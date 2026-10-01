"""Immutable D04 issued output original in the same transaction as joint adoption."""

from __future__ import annotations

from dataclasses import asdict, fields
import json
import sqlite3

from ..domains.d04.affect import _decode_feeling, _decode_mood
from ..domains.d04.joint_state_output_v1 import (
    JointStateAxisOutputV1, JointStateOutputMemberV1,
    JointStateOutputOriginalV1, SCHEMA, AUTHORED_SCHEMA,
    joint_checkpoint_payload_v1, joint_state_payload_v1,
)
from ..domains.d04.root import decode_numeric_checkpoint
from ..domains.d04.authored_lineage_v3 import (
    decode_authored_feeling_state_v1, decode_authored_mood_state_v1,
    decode_authored_numeric_checkpoint_v2,
)
from ..domains.d04.source_head import D04SourceHeadRead, _qualified_head
from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch
from ..memory_types import SourceRecord, access_key, validate_access
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


class D04JointOutputOriginalHold(ValueError):
    """The issued D04 output or its committed graph writes differ."""


def install_d04_joint_output_original_store_v1(db: sqlite3.Connection) -> None:
    if type(db) is not sqlite3.Connection or db.in_transaction:
        raise D04JointOutputOriginalHold("output schema installs before graph transaction")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS graph_d04_joint_output_originals_v1 (
            bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
            evidence_digest TEXT NOT NULL, original_json TEXT NOT NULL,
            original_digest TEXT NOT NULL, write_set_digest TEXT NOT NULL,
            PRIMARY KEY(bot,persona,operation_id),
            FOREIGN KEY(bot,persona,operation_id)
              REFERENCES graph_d04_joint_advances_v2(bot,persona,operation_id));
        CREATE TRIGGER IF NOT EXISTS graph_d04_joint_output_no_update_v1
          BEFORE UPDATE ON graph_d04_joint_output_originals_v1
          BEGIN SELECT RAISE(ABORT, 'D04 joint output original is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS graph_d04_joint_output_no_delete_v1
          BEFORE DELETE ON graph_d04_joint_output_originals_v1
          BEGIN SELECT RAISE(ABORT, 'D04 joint output original is immutable'); END;
        CREATE TABLE IF NOT EXISTS graph_d04_joint_output_closures_v1 (
            bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
            evidence_digest TEXT NOT NULL, closure_json TEXT NOT NULL,
            closure_digest TEXT NOT NULL,
            PRIMARY KEY(bot,persona,operation_id),
            FOREIGN KEY(bot,persona,operation_id)
              REFERENCES graph_d04_joint_output_originals_v1(bot,persona,operation_id));
        CREATE TRIGGER IF NOT EXISTS graph_d04_joint_output_closure_no_update_v1
          BEFORE UPDATE ON graph_d04_joint_output_closures_v1
          BEGIN SELECT RAISE(ABORT, 'D04 joint output closure is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS graph_d04_joint_output_closure_no_delete_v1
          BEFORE DELETE ON graph_d04_joint_output_closures_v1
          BEGIN SELECT RAISE(ABORT, 'D04 joint output closure is immutable'); END;
    """)


def _content_digest(original: JointStateOutputOriginalV1) -> str:
    return canonical_digest({field.name: getattr(original, field.name)
                             for field in fields(original)
                             if field.name not in {"original_digest", "status"}})


def record_d04_joint_output_original_v1(
        db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
        evidence_digest: str, original: JointStateOutputOriginalV1) -> None:
    """Persist only after W01's current preflight and all graph writes succeed."""
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise D04JointOutputOriginalHold("output original needs graph transaction")
    if (type(original) is not JointStateOutputOriginalV1
            or original.namespace != namespace or original.operation_id != operation_id
            or original.original_digest != _content_digest(original)):
        raise D04JointOutputOriginalHold("issued output identity differs")
    joint = db.execute(
        "SELECT evidence_digest FROM graph_d04_joint_advances_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if joint != (evidence_digest,):
        raise D04JointOutputOriginalHold("committed joint evidence differs")
    rows = []
    for member in original.members:
        rows.append((member.checkpoint_ref,
                     member.predecessor_checkpoint_revision + 1,
                     joint_checkpoint_payload_v1(member.next_checkpoint)))
        rows.append((member.predecessor_state_ref,
                     member.predecessor_state_revision + 1,
                     joint_state_payload_v1(member.next_state)))
    rows = tuple(sorted(rows, key=lambda item: item[0]))
    if canonical_digest(rows) != original.write_set_digest:
        raise D04JointOutputOriginalHold("issued output write set differs")
    for ref, revision, value in rows:
        key = AtomKey.from_token(ref)
        if NamespaceId.from_key(key) != namespace:
            raise D04JointOutputOriginalHold("issued output crosses namespace")
        current = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?", (ref,),
        ).fetchone()
        if (current is None or current[0] != revision or current[2] != 1
                or canonical_serialize(json.loads(current[1]))
                   != canonical_serialize(value)):
            raise D04JointOutputOriginalHold("committed output graph value differs")
    encoded = canonical_serialize(asdict(original))
    prior = db.execute(
        "SELECT evidence_digest,original_json,original_digest,write_set_digest "
        "FROM graph_d04_joint_output_originals_v1 WHERE bot=? AND persona=? "
        "AND operation_id=?", namespace.as_tuple + (operation_id,),
    ).fetchone()
    expected = (evidence_digest, encoded, original.original_digest,
                original.write_set_digest)
    if prior is not None:
        if prior != expected:
            raise D04JointOutputOriginalHold("output original replay differs")
        return
    db.execute(
        "INSERT INTO graph_d04_joint_output_originals_v1 VALUES(?,?,?,?,?,?,?)",
        namespace.as_tuple + (operation_id, *expected),
    )


def read_d04_joint_output_original_v1(
        db: sqlite3.Connection, namespace: NamespaceId,
        operation_id: str) -> JointStateOutputOriginalV1 | None:
    """Read the committed typed original; the caller must also check current graph."""
    row = db.execute(
        "SELECT evidence_digest,original_json,original_digest,write_set_digest "
        "FROM graph_d04_joint_output_originals_v1 WHERE bot=? AND persona=? "
        "AND operation_id=?", namespace.as_tuple + (operation_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        raw = json.loads(row[1])
        if type(raw) is not dict or canonical_serialize(raw) != row[1]:
            raise ValueError("noncanonical output original")
        if raw.get("schema") not in {SCHEMA, AUTHORED_SCHEMA}:
            raise ValueError("joint output original schema differs")
        raw["namespace"] = NamespaceId(**raw["namespace"])
        raw["member_refs"] = tuple(raw["member_refs"])
        raw["axis_ids"] = tuple(raw["axis_ids"])
        raw["family_transcripts"] = tuple(tuple(item)
                                           for item in raw["family_transcripts"])
        members = []
        authored = raw["schema"] == AUTHORED_SCHEMA
        for member in raw["members"]:
            item = dict(member)
            item["next_checkpoint"] = (
                decode_authored_numeric_checkpoint_v2({
                    "schema": "d04.numeric_checkpoint.v2", **item["next_checkpoint"],
                }) if authored else decode_numeric_checkpoint({
                    "schema": "d04.numeric_checkpoint.v1", **item["next_checkpoint"],
                }))
            state_type = item["next_checkpoint"].block.kind
            if authored:
                item["next_state"] = (
                    decode_authored_feeling_state_v1({
                        "schema": "d04.authored_feeling_state.v1", **item["next_state"],
                    }) if state_type == "feeling"
                    else decode_authored_mood_state_v1({
                        "schema": "d04.authored_mood_state.v1", **item["next_state"],
                    }))
            else:
                item["next_state"] = (_decode_feeling(item["next_state"])
                                      if state_type == "feeling"
                                      else _decode_mood(item["next_state"]))
            item["axes"] = tuple(JointStateAxisOutputV1(**axis)
                                 for axis in item["axes"])
            members.append(JointStateOutputMemberV1(**item))
        raw["members"] = tuple(members)
        original = JointStateOutputOriginalV1(**raw)
        joint = db.execute(
            "SELECT evidence_digest FROM graph_d04_joint_advances_v2 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (operation_id,),
        ).fetchone()
        if (original.namespace != namespace or original.operation_id != operation_id
                or original.original_digest != row[2]
                or original.write_set_digest != row[3]
                or _content_digest(original) != row[2]
                or canonical_serialize(asdict(original)) != row[1]
                or joint != (row[0],)):
            raise ValueError("committed output original identity differs")
        return original
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise D04JointOutputOriginalHold("committed output original is invalid") from exc


def record_d04_joint_output_closure_v1(
        db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
        evidence_digest: str, component_digest: str,
        audience: tuple[str, ...], purpose: str,
        rows: tuple[tuple[str, int, bool, str], ...]) -> None:
    """Seal the trusted prewrite non-output read set without source contents."""
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise D04JointOutputOriginalHold("output closure needs graph transaction")
    original = read_d04_joint_output_original_v1(db, namespace, operation_id)
    if (original is None or original.component_digest != component_digest
            or type(audience) is not tuple or not audience
            or type(purpose) is not str or not purpose
            or type(rows) is not tuple or not rows
            or tuple(ref for ref, _, _, _ in rows)
               != tuple(sorted(set(ref for ref, _, _, _ in rows)))
            or any(type(ref) is not str or type(revision) is not int
                   or type(valid) is not bool or type(digest) is not str
                   or len(digest) != 64 or revision < 0
                   or (revision == 0 and valid)
                   for ref, revision, valid, digest in rows)):
        raise D04JointOutputOriginalHold("output source closure differs")
    joint = db.execute(
        "SELECT evidence_digest FROM graph_d04_joint_advances_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if joint != (evidence_digest,):
        raise D04JointOutputOriginalHold("output closure joint evidence differs")
    body = {"schema": "d04.joint-output-closure.v1",
            "component_digest": component_digest,
            "audience": audience, "purpose": purpose, "rows": rows}
    encoded = canonical_serialize(body)
    expected = (evidence_digest, encoded, canonical_digest(body))
    prior = db.execute(
        "SELECT evidence_digest,closure_json,closure_digest "
        "FROM graph_d04_joint_output_closures_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if prior is not None:
        if prior != expected:
            raise D04JointOutputOriginalHold("output closure replay differs")
        return
    db.execute(
        "INSERT INTO graph_d04_joint_output_closures_v1 VALUES(?,?,?,?,?,?)",
        namespace.as_tuple + (operation_id, *expected),
    )


def read_d04_joint_output_closure_v1(
        db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
        evidence_digest: str, component_digest: str,
) -> tuple[tuple[str, ...], str, tuple[tuple[str, int, bool, str], ...]]:
    """Return only an immutable closure bound to the adopted output original."""
    row = db.execute(
        "SELECT evidence_digest,closure_json,closure_digest "
        "FROM graph_d04_joint_output_closures_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if row is None or row[0] != evidence_digest:
        raise D04JointOutputOriginalHold("joint output source closure is absent")
    try:
        body = json.loads(row[1])
        if (type(body) is not dict
                or set(body) != {"schema", "component_digest", "audience", "purpose", "rows"}
                or body["schema"] != "d04.joint-output-closure.v1"
                or body["component_digest"] != component_digest
                or canonical_serialize(body) != row[1]
                or canonical_digest(body) != row[2]):
            raise ValueError("closure identity differs")
        audience = tuple(body["audience"])
        rows = tuple(tuple(item) for item in body["rows"])
        if (not audience or not all(type(item) is str and item for item in audience)
                or type(body["purpose"]) is not str or not body["purpose"]
                or not rows or any(len(item) != 4 for item in rows)
                or tuple(item[0] for item in rows)
                   != tuple(sorted(set(item[0] for item in rows)))):
            raise ValueError("closure rows differ")
        return audience, body["purpose"], rows
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise D04JointOutputOriginalHold("joint output source closure is invalid") from exc


def read_current_d04_joint_output_source_closure_v1(
        db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
        evidence_digest: str, component_digest: str, graph_epoch: int,
) -> GraphSnapshot:
    """Recheck the sealed complete non-output read set and D06 qualifications."""
    audience, purpose, rows = read_d04_joint_output_closure_v1(
        db, namespace, operation_id, evidence_digest, component_digest)
    atoms = {}
    for ref, revision, valid, digest in rows:
        key = AtomKey.from_token(ref)
        if NamespaceId.from_key(key) != namespace:
            raise D04JointOutputOriginalHold("joint closure crosses namespace")
        current = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?", (ref,),
        ).fetchone()
        if revision == 0:
            if (current is not None or valid is not False
                    or digest != canonical_digest({})):
                raise D04JointOutputOriginalHold("joint negative read changed")
            atoms[key] = GraphAtom(key, 0, {}, False)
        else:
            if (current is None or current[0] != revision
                    or bool(current[2]) != valid):
                raise D04JointOutputOriginalHold("joint source read changed")
            value = json.loads(current[1])
            if (canonical_serialize(value) != current[1]
                    or canonical_digest(value) != digest):
                raise D04JointOutputOriginalHold("joint source value changed")
            atoms[key] = GraphAtom(key, revision, value, valid)
    sources = tuple(atom for atom in atoms.values()
                    if atom.key.type_name == "memory.source")
    if not sources:
        raise D04JointOutputOriginalHold("joint source closure is empty")
    snapshot = GraphSnapshot(
        tuple(atoms.values()), (NamespaceEpoch(*namespace.as_tuple, graph_epoch),))
    qualification = D04SourceHeadRead(
        snapshot, namespace, audience, purpose, None, False, False, True)
    for source_atom in sources:
        source_id = source_atom.key.owner.subject
        if not source_atom.valid or source_id is None:
            raise D04JointOutputOriginalHold("joint source was revoked")
        access = atoms.get(access_key(*namespace.as_tuple, source_id))
        correction = atoms.get(source_correction_head_key(namespace, source_id))
        if (access is None or correction is None
                or correction.revision != 0 or correction.valid):
            raise D04JointOutputOriginalHold("joint source access or correction changed")
        source = SourceRecord.from_dict(source_atom.value)
        validate_access(access.value)
        if source.parent_source_ids:
            raise D04JointOutputOriginalHold("joint source ancestor closure differs")
        qualified, reason = _qualified_head(source_atom.key.token, atoms, qualification)
        if qualified is None:
            raise D04JointOutputOriginalHold(
                f"joint source qualification changed: {reason}")
    return snapshot
