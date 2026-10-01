"""W01 transaction companion for a jointly verified D04 product advance.

The DTO is evidence, not authority. W01 must call ``preflight`` with its own
local verifier while holding the final Authority graph write transaction, then
write every graph member and ledger item, and call ``record`` in that *same*
transaction. Neither function commits, invokes FFI, or owns graph state.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import math
import re
import sqlite3
from typing import Callable

from ..domains.d04.joint_numeric_receipt import (
    D04FamilyContributionDoseV1, D04JointMemberNumericResultV1,
    D04JointNumericReceiptCandidateV1, D04NumericOutputIntervalV1,
)
from ..domains.d04.encoding_baseline_v2 import ProjectionNumericErrorV2
from ..domains.d04.numeric_coupling import REGISTERED_AXIS_IDS
from ..domains.d04.numeric_drive import (
    SourcedNumericDrive, decode_sourced_numeric_drive, sourced_numeric_drive_write,
)
from ..graph_types import AtomKey
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..domains.d06 import source_correction_head_key
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CHECKPOINT = "d04.numeric_checkpoint.v1"
_AUTHORED_CHECKPOINT = "d04.numeric_checkpoint.v2"


class JointAdvanceHold(ValueError):
    """The final graph transaction cannot prove a joint product adoption."""


def _digest(value: str, name: str) -> None:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise ValueError(f"{name} needs a lowercase SHA-256 digest")


def _text(value: str, name: str) -> None:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be nonempty")


@dataclass(frozen=True, slots=True)
class ProductAdvanceMemberV2:
    checkpoint_ref: str
    predecessor_operation_id: str
    predecessor_revision: int
    predecessor_value_digest: str
    predecessor_state_ref: str
    predecessor_state_revision: int
    predecessor_state_value_digest: str
    initial_box_digest: str
    inherited_error_bound: float
    next_revision: int
    next_value_digest: str
    next_error_bound: float
    output_state_ref: str
    output_state_revision: int
    output_state_digest: str

    def __post_init__(self) -> None:
        key = AtomKey.from_token(self.checkpoint_ref)
        if key.type_name not in {_CHECKPOINT, _AUTHORED_CHECKPOINT} or key.owner.kind != "persona":
            raise ValueError("member must be a persona numeric checkpoint")
        state = AtomKey.from_token(self.output_state_ref)
        if (self.predecessor_state_ref != self.output_state_ref
                or state.owner != key.owner or state.type_name not in (
                    {"d04.authored_feeling_state.v1", "d04.authored_mood_state.v1"}
                    if key.type_name == _AUTHORED_CHECKPOINT else
                    {"d04.feeling_state.v1", "d04.mood_field.v1"})):
            raise ValueError("member output state has wrong owner or type")
        _text(self.predecessor_operation_id, "predecessor_operation_id")
        for name in ("predecessor_value_digest", "predecessor_state_value_digest",
                     "initial_box_digest",
                     "next_value_digest", "output_state_digest"):
            _digest(getattr(self, name), name)
        if (type(self.predecessor_revision) is not int or self.predecessor_revision < 1
                or type(self.next_revision) is not int
                or self.next_revision != self.predecessor_revision + 1
                or type(self.predecessor_state_revision) is not int
                or self.predecessor_state_revision < 1
                or type(self.output_state_revision) is not int
                or self.output_state_revision != self.predecessor_state_revision + 1
                or type(self.inherited_error_bound) not in (int, float)
                or not math.isfinite(self.inherited_error_bound)
                or self.inherited_error_bound < 0
                or type(self.next_error_bound) not in (int, float)
                or not math.isfinite(self.next_error_bound)
                or self.next_error_bound < 0):
            raise ValueError("member versions or inherited error are invalid")


@dataclass(frozen=True, slots=True)
class ProductAdvanceEvidenceV2:
    schema: str
    namespace: NamespaceId
    operation_id: str
    bundle_digest: str
    process_id: str
    replay_key: str
    role_start: float
    role_end: float
    members: tuple[ProductAdvanceMemberV2, ...]
    catalogue_digest: str
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    read_versions_digest: str
    snapshot_stamp_digest: str
    time_mapping_digest: str
    closure_digest: str
    source_closure_digest: str
    absent_reads_digest: str
    asset_digest: str
    native_manifest_sha256: str
    native_sha256: str
    numeric_input_digest: str
    full_transcript_digest: str
    family_loo_transcripts: tuple[tuple[str, str], ...]
    output_write_set_digest: str
    contribution_consumption_digest: str

    def __post_init__(self) -> None:
        checkpoint_types = {AtomKey.from_token(item.checkpoint_ref).type_name
                            for item in self.members}
        if len(checkpoint_types) != 1:
            raise ValueError("joint product evidence mixes checkpoint lineages")
        authored = checkpoint_types == {_AUTHORED_CHECKPOINT}
        if self.schema != ("d11.product_advance_evidence.v3" if authored else
                           "d11.product_advance_evidence.v2"):
            raise ValueError("unknown joint product evidence schema")
        if type(self.namespace) is not NamespaceId:
            raise TypeError("namespace must be NamespaceId")
        for name in ("operation_id", "process_id", "replay_key", "graph_incarnation"):
            _text(getattr(self, name), name)
        for name in ("bundle_digest", "catalogue_digest", "read_versions_digest",
                     "snapshot_stamp_digest", "time_mapping_digest", "closure_digest",
                     "source_closure_digest", "absent_reads_digest", "asset_digest",
                     "native_manifest_sha256", "native_sha256", "numeric_input_digest",
                     "full_transcript_digest", "output_write_set_digest",
                     "contribution_consumption_digest"):
            _digest(getattr(self, name), name)
        if (type(self.role_start) not in (int, float) or not math.isfinite(self.role_start)
                or type(self.role_end) not in (int, float) or not math.isfinite(self.role_end)
                or self.role_end <= self.role_start):
            raise ValueError("joint interval must be finite and positive")
        for name in ("graph_revision", "graph_epoch", "access_epoch", "delete_epoch"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be nonnegative")
        if (type(self.members) is not tuple or len(self.members) < 2
                or any(type(m) is not ProductAdvanceMemberV2 for m in self.members)):
            raise ValueError("joint evidence needs at least two typed members")
        refs = tuple(m.checkpoint_ref for m in self.members)
        if refs != tuple(sorted(set(refs))):
            raise ValueError("joint members must be unique and ordered")
        if any(NamespaceId.from_key(AtomKey.from_token(ref)) != self.namespace for ref in refs):
            raise ValueError("joint member crosses namespace")
        if (type(self.family_loo_transcripts) is not tuple
                or not self.family_loo_transcripts
                or tuple(f for f, _ in self.family_loo_transcripts)
                   != tuple(sorted(set(f for f, _ in self.family_loo_transcripts)))):
            raise ValueError("LOO families must be complete, unique and ordered")
        for family, digest in self.family_loo_transcripts:
            _text(family, "family")
            _digest(digest, "family transcript")

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class JointAdvancePreflight:
    evidence_digest: str
    connection_id: int


@dataclass(frozen=True, slots=True)
class JointNumericOriginalPreflightV1:
    evidence_digest: str
    numeric_receipt_digest: str
    verification_digest: str
    verification: JointNumericOriginalVerificationV1
    connection_id: int


@dataclass(frozen=True, slots=True)
class JointNumericOriginalVerificationV1:
    """Output of W01's installed replay, never accepted from the candidate."""

    policy_id: str
    policy_version: str
    policy_digest: str
    readout_id: str
    readout_version: str
    readout_sha256: str
    math_transcript_sha256: str
    numeric_error: ProjectionNumericErrorV2

    def __post_init__(self) -> None:
        for name in ("policy_id", "policy_version", "readout_id", "readout_version"):
            _text(getattr(self, name), name)
        for name in ("policy_digest", "readout_sha256", "math_transcript_sha256"):
            _digest(getattr(self, name), name)
        if type(self.numeric_error) is not ProjectionNumericErrorV2:
            raise TypeError("installed replay must provide a typed numeric error")


@dataclass(frozen=True, slots=True)
class JointNumericOriginalV1:
    """W01-readable original for one member of an adopted joint operation."""

    original_ref: str
    original_revision: int
    adoption_operation_id: str
    adoption_receipt_digest: str
    receipt: D04JointNumericReceiptCandidateV1
    verification: JointNumericOriginalVerificationV1
    status: str = "w01_verified_durable_joint_numeric_original_v1"


def install_joint_advance_store_v2(db: sqlite3.Connection) -> None:
    """Provision receipt and per-member interval index before the write transaction."""
    if type(db) is not sqlite3.Connection or db.in_transaction:
        raise JointAdvanceHold("install V2 schema outside W01 graph transaction")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS graph_d04_joint_advances_v2 (
            bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
            process_id TEXT NOT NULL, replay_key TEXT NOT NULL,
            role_start REAL NOT NULL, role_end REAL NOT NULL,
            evidence_json TEXT NOT NULL, evidence_digest TEXT NOT NULL,
            bundle_digest TEXT NOT NULL,
            PRIMARY KEY(bot,persona,operation_id),
            UNIQUE(bot,persona,process_id,replay_key),
            FOREIGN KEY(bot,persona,operation_id)
              REFERENCES graph_bundle_operations(bot,persona,operation_id));
        CREATE TABLE IF NOT EXISTS graph_d04_joint_advance_members_v2 (
            bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
            checkpoint_ref TEXT NOT NULL, process_id TEXT NOT NULL,
            role_start REAL NOT NULL, role_end REAL NOT NULL,
            PRIMARY KEY(bot,persona,operation_id,checkpoint_ref),
            FOREIGN KEY(bot,persona,operation_id)
              REFERENCES graph_d04_joint_advances_v2(bot,persona,operation_id));
        CREATE INDEX IF NOT EXISTS graph_d04_joint_member_interval_v2
          ON graph_d04_joint_advance_members_v2
             (bot,persona,checkpoint_ref,role_start,role_end);
        CREATE TABLE IF NOT EXISTS graph_d04_joint_numeric_originals_v1 (
            bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
            evidence_digest TEXT NOT NULL, numeric_receipt_json TEXT NOT NULL,
            numeric_receipt_digest TEXT NOT NULL, verification_json TEXT NOT NULL,
            verification_digest TEXT NOT NULL,
            PRIMARY KEY(bot,persona,operation_id),
            FOREIGN KEY(bot,persona,operation_id)
              REFERENCES graph_d04_joint_advances_v2(bot,persona,operation_id));
        CREATE TRIGGER IF NOT EXISTS graph_d04_joint_receipt_no_update_v2
          BEFORE UPDATE ON graph_d04_joint_advances_v2
          BEGIN SELECT RAISE(ABORT, 'joint receipt is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS graph_d04_joint_receipt_no_delete_v2
          BEFORE DELETE ON graph_d04_joint_advances_v2
          BEGIN SELECT RAISE(ABORT, 'joint receipt is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS graph_d04_joint_member_no_update_v2
          BEFORE UPDATE ON graph_d04_joint_advance_members_v2
          BEGIN SELECT RAISE(ABORT, 'joint member is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS graph_d04_joint_member_no_delete_v2
          BEFORE DELETE ON graph_d04_joint_advance_members_v2
          BEGIN SELECT RAISE(ABORT, 'joint member is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS graph_d04_joint_numeric_original_no_update_v1
          BEFORE UPDATE ON graph_d04_joint_numeric_originals_v1
          BEGIN SELECT RAISE(ABORT, 'joint numeric original is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS graph_d04_joint_numeric_original_no_delete_v1
          BEFORE DELETE ON graph_d04_joint_numeric_originals_v1
          BEGIN SELECT RAISE(ABORT, 'joint numeric original is immutable'); END;
    """)


def _transaction(db: sqlite3.Connection) -> None:
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise JointAdvanceHold("joint adoption needs W01's existing graph transaction")


def _schema(db: sqlite3.Connection) -> None:
    names = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
        "('graph_d04_joint_advances_v2','graph_d04_joint_advance_members_v2',"
        "'graph_product_advances')")}
    required = {"graph_d04_joint_advances_v2", "graph_d04_joint_advance_members_v2",
                "graph_product_advances"}
    if names != required:
        raise JointAdvanceHold("committed-member V2 or root/V1 predecessor schema is absent: "
                               + ", ".join(sorted(required - names)))


def _event_root_schema(db: sqlite3.Connection, evidence: ProductAdvanceEvidenceV2) -> None:
    if (evidence.schema == "d11.product_advance_evidence.v2"
            and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                           "AND name='graph_d04_root_originals_v1'").fetchone() is None):
        raise JointAdvanceHold("event-derived V2 root predecessor schema is absent")


def _numeric_schema(db: sqlite3.Connection) -> None:
    names = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
        "('graph_d04_joint_numeric_originals_v1','graph_history')")}
    if names != {"graph_d04_joint_numeric_originals_v1", "graph_history"}:
        raise JointAdvanceHold("durable numeric original or graph history schema is absent")


def _legacy_gap(db: sqlite3.Connection, evidence: ProductAdvanceEvidenceV2) -> None:
    # V1 stores feeling/mood, not the stable numeric checkpoint member set.
    if db.execute("SELECT 1 FROM graph_product_advances WHERE bot=? AND persona=? "
                  "LIMIT 1", evidence.namespace.as_tuple).fetchone():
        raise JointAdvanceHold(
            "V1 committed product advances lack numeric checkpoint member IDs; "
            "per-member predecessor and overlap cannot be proven")


def _existing(db: sqlite3.Connection, evidence: ProductAdvanceEvidenceV2) -> str | None:
    row = db.execute(
        "SELECT evidence_digest FROM graph_d04_joint_advances_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        evidence.namespace.as_tuple + (evidence.operation_id,),
    ).fetchone()
    if row is not None:
        if row[0] != evidence.digest:
            raise JointAdvanceHold("operation ID already has different joint evidence")
        if read_joint_advance_v2(db, evidence.namespace, evidence.operation_id) != evidence:
            raise JointAdvanceHold("committed joint replay receipt differs")
        return "duplicate"
    if db.execute(
        "SELECT 1 FROM graph_d04_joint_advances_v2 WHERE bot=? AND persona=? "
        "AND process_id=? AND replay_key=? LIMIT 1",
        evidence.namespace.as_tuple + (evidence.process_id, evidence.replay_key),
    ).fetchone():
        raise JointAdvanceHold("joint replay key already belongs to another operation")
    return None


def _overlap(db: sqlite3.Connection, evidence: ProductAdvanceEvidenceV2) -> None:
    for member in evidence.members:
        if db.execute(
            "SELECT 1 FROM graph_d04_joint_advance_members_v2 "
            "WHERE bot=? AND persona=? AND checkpoint_ref=? "
            "AND role_start<? AND role_end>? LIMIT 1",
            evidence.namespace.as_tuple + (member.checkpoint_ref,
                                           evidence.role_end, evidence.role_start),
        ).fetchone():
            raise JointAdvanceHold("joint member interval overlaps a committed advance")


def preflight_joint_advance_v2(
    db: sqlite3.Connection, evidence: ProductAdvanceEvidenceV2, *,
    trusted_local_verifier: Callable[[sqlite3.Connection, ProductAdvanceEvidenceV2], bool] | None,
) -> JointAdvancePreflight | str:
    """CAS all predecessors and require W01's independent closure/certificate verifier.

    The verifier must re-read the complete component, D06 source/access lineage,
    installed assets and native transcripts. A candidate-supplied bool or proof
    is not an issuer. W01 owns this callback and the fenced SQLite connection.
    """
    _transaction(db)
    if type(evidence) is not ProductAdvanceEvidenceV2:
        raise TypeError("joint evidence must be typed V2")
    _schema(db)
    _event_root_schema(db, evidence)
    _legacy_gap(db, evidence)
    replay = _existing(db, evidence)
    if replay:
        return replay
    _overlap(db, evidence)
    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                       evidence.namespace.as_tuple).fetchone()
    authority = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", evidence.namespace.as_tuple).fetchone()
    recovery = db.execute(
        "SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
        "WHERE bot=? AND persona=?", evidence.namespace.as_tuple).fetchone()
    try:
        incarnation = json.loads(recovery[0])["graph_incarnation"] if recovery else None
    except (TypeError, ValueError, KeyError) as exc:
        raise JointAdvanceHold("joint graph recovery identity is invalid") from exc
    if epoch != (evidence.graph_epoch,) or authority != (
            evidence.access_epoch, evidence.delete_epoch) or recovery is None \
            or recovery[1] != evidence.graph_revision \
            or incarnation != evidence.graph_incarnation:
        raise JointAdvanceHold("joint graph or authority epoch changed")
    for member in evidence.members:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                         (member.checkpoint_ref,)).fetchone()
        if (row is None or row[0] != member.predecessor_revision or row[2] != 1
                or canonical_digest(json.loads(row[1])) != member.predecessor_value_digest):
            raise JointAdvanceHold("joint member predecessor CAS failed")
        state = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                           (member.predecessor_state_ref,)).fetchone()
        if (state is None or state[0] != member.predecessor_state_revision
                or state[2] != 1 or canonical_digest(json.loads(state[1]))
                != member.predecessor_state_value_digest):
            raise JointAdvanceHold("joint member state predecessor CAS failed")
        prior = db.execute(
            "SELECT evidence_json FROM graph_d04_joint_advances_v2 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            evidence.namespace.as_tuple + (member.predecessor_operation_id,),
        ).fetchone()
        if prior is None:
            if evidence.schema == "d11.product_advance_evidence.v3":
                from ..domains.d04.authored_lineage_v3 import decode_authored_numeric_checkpoint_v2
                from .d04_root_original_store_v3 import read_d04_root_original_v3

                try:
                    original = read_d04_root_original_v3(
                        db, namespace=evidence.namespace,
                        operation_id=member.predecessor_operation_id)
                    rows = {ref: (revision, value) for ref, revision, value in
                            json.loads(original.output_json)["rows"]}
                    checkpoint_value = rows[member.checkpoint_ref]
                    state_value = rows[member.predecessor_state_ref]
                    checkpoint = decode_authored_numeric_checkpoint_v2(
                        checkpoint_value[1])
                    if (checkpoint_value[0] != member.predecessor_revision
                            or state_value[0] != member.predecessor_state_revision
                            or canonical_digest(checkpoint_value[1])
                               != member.predecessor_value_digest
                            or canonical_digest(state_value[1])
                               != member.predecessor_state_value_digest
                            or checkpoint.graph_state.ref != member.predecessor_state_ref
                            or checkpoint.graph_state.revision
                               != member.predecessor_state_revision
                            or checkpoint.certificate_digest != member.initial_box_digest
                            or checkpoint.numeric_error_bound
                               != member.inherited_error_bound):
                        raise ValueError("authored root member differs")
                except (KeyError, IndexError, TypeError, ValueError) as exc:
                    raise JointAdvanceHold("V3 authored root predecessor differs") from exc
            else:
                root = db.execute(
                    "SELECT 1 FROM graph_d04_root_originals_v1 WHERE bot=? AND persona=? "
                    "AND operation_id=? LIMIT 1",
                    evidence.namespace.as_tuple + (member.predecessor_operation_id,),
                ).fetchone()
                if root is None:
                    raise JointAdvanceHold("member has no committed joint or root predecessor")
        else:
            parent = json.loads(prior[0])
            matches = [item for item in parent["members"]
                       if item["checkpoint_ref"] == member.checkpoint_ref]
            if (len(matches) != 1 or matches[0]["next_revision"] != member.predecessor_revision
                    or matches[0]["next_value_digest"] != member.predecessor_value_digest
                    or matches[0]["output_state_ref"] != member.predecessor_state_ref
                    or matches[0]["output_state_revision"] != member.predecessor_state_revision
                    or matches[0]["output_state_digest"] != member.predecessor_state_value_digest
                    or matches[0]["next_error_bound"] != member.inherited_error_bound
                    or parent["role_end"] != evidence.role_start):
                raise JointAdvanceHold("joint member predecessor chain differs")
    if trusted_local_verifier is None or not callable(trusted_local_verifier):
        raise JointAdvanceHold("W01 trusted joint issuer verification is unavailable")
    if trusted_local_verifier(db, evidence) is not True:
        raise JointAdvanceHold("W01 trusted joint issuer rejected closure or certificates")
    return JointAdvancePreflight(evidence.digest, id(db))


def record_joint_advance_v2(
    db: sqlite3.Connection, evidence: ProductAdvanceEvidenceV2, *,
    preflight: JointAdvancePreflight,
) -> str:
    """Persist a re-readable receipt after all member writes, before W01 commits."""
    _transaction(db)
    if type(evidence) is not ProductAdvanceEvidenceV2:
        raise TypeError("joint evidence must be typed V2")
    _schema(db)
    _event_root_schema(db, evidence)
    _legacy_gap(db, evidence)
    replay = _existing(db, evidence)
    if replay:
        return replay
    if (type(preflight) is not JointAdvancePreflight
            or preflight.evidence_digest != evidence.digest
            or preflight.connection_id != id(db)):
        raise JointAdvanceHold("same-transaction trusted preflight is absent")
    _overlap(db, evidence)
    operation = db.execute(
        "SELECT digest,activity_id FROM graph_bundle_operations WHERE bot=? AND persona=? "
        "AND operation_id=?", evidence.namespace.as_tuple + (evidence.operation_id,),
    ).fetchone()
    if operation is None or operation[0] != evidence.bundle_digest:
        raise JointAdvanceHold("joint bundle operation receipt is absent or differs")
    event = db.execute(
        "SELECT revisions FROM graph_events WHERE bot=? AND persona=? AND session=? "
        "AND event_id=?", evidence.namespace.as_tuple +
        (operation[1], evidence.operation_id),
    ).fetchone()
    if event is None:
        raise JointAdvanceHold("joint graph event is absent")
    try:
        writes = {tuple(item) for item in json.loads(event[0])}
    except (TypeError, ValueError) as exc:
        raise JointAdvanceHold("joint graph event write versions are malformed") from exc
    required = {(m.checkpoint_ref, m.next_revision) for m in evidence.members}
    required.update((m.output_state_ref, m.output_state_revision) for m in evidence.members)
    if not required.issubset(writes):
        raise JointAdvanceHold("joint graph event omits a member write")
    for member in evidence.members:
        for ref, revision, digest in (
            (member.checkpoint_ref, member.next_revision, member.next_value_digest),
            (member.output_state_ref, member.output_state_revision,
             member.output_state_digest),
        ):
            row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                             (ref,)).fetchone()
            if (row is None or row[0] != revision or row[2] != 1
                    or canonical_digest(json.loads(row[1])) != digest):
                raise JointAdvanceHold("joint committed member write set differs")
    data = canonical_serialize(asdict(evidence))
    db.execute(
        "INSERT INTO graph_d04_joint_advances_v2 "
        "(bot,persona,operation_id,process_id,replay_key,role_start,role_end,"
        "evidence_json,evidence_digest,bundle_digest) VALUES(?,?,?,?,?,?,?,?,?,?)",
        evidence.namespace.as_tuple + (
            evidence.operation_id, evidence.process_id, evidence.replay_key,
            evidence.role_start, evidence.role_end, data, evidence.digest,
            evidence.bundle_digest),
    )
    db.executemany(
        "INSERT INTO graph_d04_joint_advance_members_v2 "
        "(bot,persona,operation_id,checkpoint_ref,process_id,role_start,role_end) "
        "VALUES(?,?,?,?,?,?,?)",
        (evidence.namespace.as_tuple + (evidence.operation_id, m.checkpoint_ref,
                                        evidence.process_id, evidence.role_start,
                                        evidence.role_end) for m in evidence.members),
    )
    return "recorded_pending_transaction_commit"


def read_joint_advance_v2(db: sqlite3.Connection, namespace: NamespaceId,
                          operation_id: str) -> ProductAdvanceEvidenceV2 | None:
    """Reconstruct and check a committed receipt using any SQLite connection."""
    _schema(db)
    row = db.execute(
        "SELECT evidence_json,evidence_digest,bundle_digest FROM graph_d04_joint_advances_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        raw = json.loads(row[0])
        if canonical_serialize(raw) != row[0]:
            raise ValueError("noncanonical")
        raw["namespace"] = NamespaceId(**raw["namespace"])
        raw["members"] = tuple(ProductAdvanceMemberV2(**item) for item in raw["members"])
        raw["family_loo_transcripts"] = tuple(tuple(item) for item in raw["family_loo_transcripts"])
        evidence = ProductAdvanceEvidenceV2(**raw)
        _event_root_schema(db, evidence)
        indexed = db.execute(
            "SELECT checkpoint_ref,process_id,role_start,role_end "
            "FROM graph_d04_joint_advance_members_v2 WHERE bot=? AND persona=? "
            "AND operation_id=? ORDER BY checkpoint_ref",
            namespace.as_tuple + (operation_id,),
        ).fetchall()
        expected = [(m.checkpoint_ref, evidence.process_id, evidence.role_start,
                     evidence.role_end) for m in evidence.members]
        operation = db.execute(
            "SELECT digest FROM graph_bundle_operations WHERE bot=? AND persona=? "
            "AND operation_id=?", namespace.as_tuple + (operation_id,),
        ).fetchone()
        if (evidence.namespace != namespace or evidence.operation_id != operation_id
                or evidence.digest != row[1] or evidence.bundle_digest != row[2]
                or indexed != expected or operation != (evidence.bundle_digest,)):
            raise ValueError("receipt or committed member index differs")
        return evidence
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise JointAdvanceHold("committed joint receipt is malformed") from exc


def _numeric_candidate(evidence: ProductAdvanceEvidenceV2,
                       receipt: D04JointNumericReceiptCandidateV1) -> None:
    """Structural binding only; W01's local verifier must replay the math."""
    if type(receipt) is not D04JointNumericReceiptCandidateV1:
        raise JointAdvanceHold("typed full joint numeric candidate is required")
    content = {field.name: getattr(receipt, field.name)
               for field in fields(receipt)
               if field.name not in {"receipt_digest", "status"}}
    if (receipt.receipt_digest != canonical_digest(content)
            or receipt.status != "unsigned_hold_for_w01_atomic_joint_adoption"
            or receipt.namespace != evidence.namespace
            or receipt.member_refs != tuple(m.checkpoint_ref for m in evidence.members)
            or tuple(m.checkpoint_ref for m in receipt.members) != receipt.member_refs
            or receipt.graph_incarnation != evidence.graph_incarnation
            or receipt.graph_revision != evidence.graph_revision
            or receipt.graph_epoch != evidence.graph_epoch
            or receipt.access_epoch != evidence.access_epoch
            or receipt.delete_epoch != evidence.delete_epoch
            or (receipt.role_start, receipt.role_end)
               != (evidence.role_start, evidence.role_end)
            or receipt.native_manifest_sha256 != evidence.native_manifest_sha256
            or receipt.native_sha256 != evidence.native_sha256
            or receipt.native_abi_version != 2
            or receipt.full_transcript_sha256 != evidence.full_transcript_digest
            or receipt.family_transcripts != evidence.family_loo_transcripts):
        raise JointAdvanceHold("numeric original identity differs from joint advance")
    families = tuple(family for family, _ in receipt.family_transcripts)
    for member in receipt.members:
        if (type(member) is not D04JointMemberNumericResultV1
                or len(member.full) != 24
                or tuple(item.axis_id for item in member.full) != REGISTERED_AXIS_IDS
                or tuple(item.family_id for item in member.families) != families):
            raise JointAdvanceHold("numeric original omits a member, axis or family")
        outputs = tuple(item.output_id for item in member.full)
        if len(set(outputs)) != 24:
            raise JointAdvanceHold("numeric original output IDs are ambiguous")
        for family in member.families:
            if (type(family) is not D04FamilyContributionDoseV1
                    or not family.source_refs
                    or family.source_refs != tuple(sorted(set(family.source_refs)))):
                raise JointAdvanceHold("numeric original family sources are ambiguous")
            for branch in (family.without_family, family.contribution_doses):
                if (len(branch) != 24
                        or tuple((item.axis_id, item.output_id) for item in branch)
                           != tuple((axis, output) for axis, output in
                                    zip(REGISTERED_AXIS_IDS, outputs))):
                    raise JointAdvanceHold("numeric original family branch is incomplete")
        for interval in (*member.full, *(item for family in member.families
                                         for branch in (family.without_family,
                                                        family.contribution_doses)
                                         for item in branch)):
            if (type(interval) is not D04NumericOutputIntervalV1
                    or type(interval.lower) is not float
                    or type(interval.upper) is not float
                    or not math.isfinite(interval.lower)
                    or not math.isfinite(interval.upper)
                    or interval.lower > interval.upper):
                raise JointAdvanceHold("numeric original has invalid interval")
    if (type(receipt.source_versions) is not tuple
            or not receipt.source_versions
            or any(type(row) is not tuple or len(row) != 7
                   or type(row[1]) is not int or row[1] < 1
                   or type(row[3]) is not int or row[3] < 1
                   or type(row[5]) is not int or row[5] < 1
                   or any(type(row[index]) is not str or not row[index]
                          for index in (0, 2, 4, 6))
                   for row in receipt.source_versions)):
        raise JointAdvanceHold("numeric original source versions are malformed")
    family_sources = {
        family: tuple(sorted({row[2] for row in receipt.source_versions
                              if row[6] == family}))
        for family in families
    }
    if (len({row[0] for row in receipt.source_versions})
            != len(receipt.source_versions)
            or any(not source_refs for source_refs in family_sources.values())
            or any(tuple((family.family_id, family.source_refs)
                         for family in member.families)
                   != tuple(family_sources.items()) for member in receipt.members)):
        raise JointAdvanceHold("numeric original source family coverage differs")


def _decode_numeric_candidate(encoded: str) -> D04JointNumericReceiptCandidateV1:
    def exact(cls: type, raw: object):
        if type(raw) is not dict or set(raw) != set(cls.__dataclass_fields__):
            raise ValueError("numeric original fields differ")
        return cls(**raw)

    raw = json.loads(encoded)
    if type(raw) is not dict or canonical_serialize(raw) != encoded:
        raise ValueError("numeric original JSON is noncanonical")
    if set(raw) != set(D04JointNumericReceiptCandidateV1.__dataclass_fields__):
        raise ValueError("numeric original candidate fields differ")
    raw["namespace"] = exact(NamespaceId, raw["namespace"])
    raw["source_versions"] = tuple(tuple(item) for item in raw["source_versions"])
    raw["member_refs"] = tuple(raw["member_refs"])
    raw["family_transcripts"] = tuple(tuple(item) for item in raw["family_transcripts"])
    members = []
    for item in raw["members"]:
        item = dict(item)
        item["full"] = tuple(exact(D04NumericOutputIntervalV1, value)
                             for value in item["full"])
        families = []
        for family in item["families"]:
            family = dict(family)
            family["source_refs"] = tuple(family["source_refs"])
            for key in ("without_family", "contribution_doses"):
                family[key] = tuple(exact(D04NumericOutputIntervalV1, value)
                                    for value in family[key])
            families.append(exact(D04FamilyContributionDoseV1, family))
        item["families"] = tuple(families)
        members.append(exact(D04JointMemberNumericResultV1, item))
    raw["members"] = tuple(members)
    return exact(D04JointNumericReceiptCandidateV1, raw)


def _current_numeric_sources(
    db: sqlite3.Connection, evidence: ProductAdvanceEvidenceV2,
    receipt: D04JointNumericReceiptCandidateV1,
    expected_drives: tuple[SourcedNumericDrive, ...],
) -> None:
    """Bind each family to the current D06 provenance root and exact graph rows."""
    _transaction(db)
    expected = {sourced_numeric_drive_write(drive).key.token: drive
                for drive in expected_drives}
    if len(expected) != len(expected_drives):
        raise JointAdvanceHold("replay drive identities are ambiguous")
    for drive_ref, drive_revision, source_ref, source_revision, access_ref, access_revision, family in (
            receipt.source_versions):
        try:
            source_address = AtomKey.from_token(source_ref)
            source_id = source_address.owner.subject
            if (source_id is None
                    or source_address != source_key(*evidence.namespace.as_tuple, source_id)
                    or AtomKey.from_token(access_ref)
                       != access_key(*evidence.namespace.as_tuple, source_id)):
                raise ValueError("source identity differs")
            rows = tuple(db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?", (ref,),
            ).fetchone() for ref in (drive_ref, source_ref, access_ref))
            if any(row is None or row[2] != 1 for row in rows):
                raise ValueError("source row is unavailable")
            if tuple(row[0] for row in rows) != (
                    drive_revision, source_revision, access_revision):
                raise ValueError("source version differs")
            values = tuple(json.loads(row[1]) for row in rows)
            if any(canonical_serialize(value) != row[1]
                   for value, row in zip(values, rows)):
                raise ValueError("source row is noncanonical")
            drive = decode_sourced_numeric_drive(values[0])
            source = SourceRecord.from_dict(values[1])
            validate_access(values[2])
            if (expected.get(drive_ref) != drive
                    or drive.source_ref != source_ref or drive.access_ref != access_ref
                    or drive.source_revision != source_revision
                    or drive.access_revision != access_revision
                    or source.source_id != source_id
                    or source.parent_source_ids
                    or source.provenance_root != family
                    or values[2]["source_id"] != source_id
                    or values[2]["status"] != "active"):
                raise ValueError("drive or family differs from source original")
            correction = db.execute(
                "SELECT revision,valid FROM graph_atoms WHERE token=?",
                (source_correction_head_key(evidence.namespace, source_id).token,),
            ).fetchone()
            if correction is not None and correction != (0, 0):
                raise ValueError("source correction head is present")
        except (TypeError, ValueError, KeyError, IndexError) as exc:
            raise JointAdvanceHold("numeric source family proof differs") from exc


def verification_from_installed_joint_replay_v1(
    db: sqlite3.Connection,
    evidence: ProductAdvanceEvidenceV2,
    receipt: D04JointNumericReceiptCandidateV1,
    replay: object,
    *, current_component: object,
) -> JointNumericOriginalVerificationV1:
    """Compare W01's lock-free installed ABI2 replay to the final joint premise.

    W01 must pass the complete component it re-read under its Owner write fence.
    This function checks the installed numerical original; it cannot authenticate
    the caller's Authority lease or graph reader.
    """
    from ..domains.d04.trusted_joint_replay import (
        D04InstalledJointNumericReplayV1, _numeric_error_from_replay,
        is_package_bound_joint_numeric_replay_v1,
    )

    _transaction(db)
    _numeric_candidate(evidence, receipt)
    if (type(replay) is not D04InstalledJointNumericReplayV1
            or not is_package_bound_joint_numeric_replay_v1(replay)):
        raise JointAdvanceHold("installed joint replay result is unavailable")
    if (current_component != replay.component
            or replay.component.candidate_digest != receipt.component_digest
            or replay.component.read_values_digest != receipt.read_values_digest
            or len({item.source_ref for item in replay.families})
               != len(replay.families)
            or {(item.source_ref, item.family_id) for item in replay.families}
               != {(row[2], row[6]) for row in receipt.source_versions}):
        raise JointAdvanceHold("current complete component differs from installed replay")
    _current_numeric_sources(db, evidence, receipt, replay.drives)
    math_result = replay.math_result
    policy = replay.policy
    readout = replay.readout
    if (replay.status != "installed_replay_pending_w01_atomic_adoption"
            or replay.candidate != receipt
            or math_result.component_digest != receipt.component_digest
            or math_result.member_refs != receipt.member_refs
            or math_result.full_transcript_sha256 != receipt.full_transcript_sha256
            or math_result.family_transcripts != receipt.family_transcripts
            or math_result.transcript_sha256 != receipt.math_transcript_sha256
            or math_result.full_step is None
            or len(math_result.full_step.previous) != 24 * len(receipt.member_refs)
            or policy.readout_id != readout.readout_id
            or policy.readout_version != readout.readout_version
            or policy.readout_sha256 != readout.asset_sha256):
        raise JointAdvanceHold("installed ABI2 replay differs from joint evidence")
    try:
        expected_error = _numeric_error_from_replay(
            receipt, math_result, policy, readout.rows,
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise JointAdvanceHold("installed numeric error replay failed") from exc
    if replay.numeric_error != expected_error:
        raise JointAdvanceHold("installed numeric error differs from replay")
    return JointNumericOriginalVerificationV1(
        policy.policy_id, policy.version, canonical_digest(asdict(policy)),
        readout.readout_id, readout.readout_version, readout.asset_sha256,
        math_result.transcript_sha256, expected_error,
    )


def preflight_joint_numeric_original_v1(
    db: sqlite3.Connection, evidence: ProductAdvanceEvidenceV2,
    receipt: D04JointNumericReceiptCandidateV1, *,
    joint_preflight: JointAdvancePreflight,
    trusted_local_numeric_verifier: Callable[
        [sqlite3.Connection, ProductAdvanceEvidenceV2,
         D04JointNumericReceiptCandidateV1], JointNumericOriginalVerificationV1] | None,
) -> JointNumericOriginalPreflightV1:
    """W01 must re-read and replay installed ABI2 math before graph writes."""
    _transaction(db)
    _numeric_schema(db)
    _numeric_candidate(evidence, receipt)
    if (type(joint_preflight) is not JointAdvancePreflight
            or joint_preflight.connection_id != id(db)
            or joint_preflight.evidence_digest != evidence.digest):
        raise JointAdvanceHold("numeric original lacks joint trusted preflight")
    if (trusted_local_numeric_verifier is None
            or not callable(trusted_local_numeric_verifier)):
        raise JointAdvanceHold("W01 trusted numeric replay issuer is unavailable")
    verification = trusted_local_numeric_verifier(db, evidence, receipt)
    if (type(verification) is not JointNumericOriginalVerificationV1
            or verification.math_transcript_sha256 != receipt.math_transcript_sha256):
        raise JointAdvanceHold("W01 trusted numeric replay rejected original")
    return JointNumericOriginalPreflightV1(
        evidence.digest, receipt.receipt_digest,
        canonical_digest(asdict(verification)), verification, id(db),
    )


def _numeric_history(db: sqlite3.Connection,
                     evidence: ProductAdvanceEvidenceV2) -> None:
    operation = db.execute(
        "SELECT activity_id FROM graph_bundle_operations WHERE bot=? AND persona=? "
        "AND operation_id=?", evidence.namespace.as_tuple + (evidence.operation_id,),
    ).fetchone()
    if operation is None:
        raise JointAdvanceHold("numeric original has no graph operation")
    for member in evidence.members:
        for ref, revision, digest in (
            (member.checkpoint_ref, member.next_revision, member.next_value_digest),
            (member.output_state_ref, member.output_state_revision,
             member.output_state_digest),
        ):
            row = db.execute(
                "SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
                "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
                (ref, revision, *evidence.namespace.as_tuple, operation[0],
                 evidence.operation_id),
            ).fetchone()
            try:
                valid = row is not None and row[1] == 1
                matches = valid and canonical_digest(json.loads(row[0])) == digest
            except (TypeError, ValueError):
                matches = False
            if not matches:
                raise JointAdvanceHold("numeric original graph history differs")


def record_joint_numeric_original_v1(
    db: sqlite3.Connection, evidence: ProductAdvanceEvidenceV2,
    receipt: D04JointNumericReceiptCandidateV1, *,
    preflight: JointNumericOriginalPreflightV1,
) -> str:
    """Write the complete 24-axis original after joint writes, before W01 commit."""
    _transaction(db)
    _numeric_schema(db)
    _numeric_candidate(evidence, receipt)
    if (type(preflight) is not JointNumericOriginalPreflightV1
            or preflight.connection_id != id(db)
            or preflight.evidence_digest != evidence.digest
            or preflight.numeric_receipt_digest != receipt.receipt_digest
            or type(preflight.verification) is not JointNumericOriginalVerificationV1
            or preflight.verification_digest
               != canonical_digest(asdict(preflight.verification))
            or preflight.verification.math_transcript_sha256
               != receipt.math_transcript_sha256):
        raise JointAdvanceHold("same-transaction numeric replay preflight is absent")
    if read_joint_advance_v2(db, evidence.namespace, evidence.operation_id) != evidence:
        raise JointAdvanceHold("numeric original needs the same joint advance")
    _numeric_history(db, evidence)
    encoded = canonical_serialize(asdict(receipt))
    verification_json = canonical_serialize(asdict(preflight.verification))
    previous = db.execute(
        "SELECT evidence_digest,numeric_receipt_json,numeric_receipt_digest,"
        "verification_json,verification_digest "
        "FROM graph_d04_joint_numeric_originals_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        evidence.namespace.as_tuple + (evidence.operation_id,),
    ).fetchone()
    expected = (evidence.digest, encoded, receipt.receipt_digest,
                verification_json, preflight.verification_digest)
    if previous is not None:
        if previous != expected:
            raise JointAdvanceHold("numeric original operation retry differs")
        return "duplicate"
    db.execute(
        "INSERT INTO graph_d04_joint_numeric_originals_v1 "
        "(bot,persona,operation_id,evidence_digest,numeric_receipt_json,"
        "numeric_receipt_digest,verification_json,verification_digest) "
        "VALUES(?,?,?,?,?,?,?,?)",
        evidence.namespace.as_tuple + (evidence.operation_id, *expected),
    )
    return "recorded_pending_transaction_commit"


def read_current_joint_numeric_original_v1(
    db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
    original_ref: str, *, expected_graph_incarnation: str,
    expected_graph_revision: int, expected_graph_epoch: int,
    expected_access_epoch: int, expected_delete_epoch: int,
    expected_policy_digest: str, expected_readout_sha256: str,
    trusted_current_verifier: Callable[
        [sqlite3.Connection, ProductAdvanceEvidenceV2,
         D04JointNumericReceiptCandidateV1,
         JointNumericOriginalVerificationV1], bool] | None,
) -> JointNumericOriginalV1:
    """W01-only current Owner-fenced read; callback verifies live closure/assets."""
    _transaction(db)
    _numeric_schema(db)
    evidence = read_joint_advance_v2(db, namespace, operation_id)
    if evidence is None:
        raise JointAdvanceHold("adopted joint advance is absent")
    row = db.execute(
        "SELECT evidence_digest,numeric_receipt_json,numeric_receipt_digest,"
        "verification_json,verification_digest "
        "FROM graph_d04_joint_numeric_originals_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if row is None or row[0] != evidence.digest:
        raise JointAdvanceHold("adopted numeric original is absent or differs")
    try:
        receipt = _decode_numeric_candidate(row[1])
        raw_verification = json.loads(row[3])
        if (type(raw_verification) is not dict
                or canonical_serialize(raw_verification) != row[3]
                or set(raw_verification)
                   != set(JointNumericOriginalVerificationV1.__dataclass_fields__)):
            raise ValueError("numeric verification fields differ")
        raw_error = raw_verification["numeric_error"]
        if (type(raw_error) is not dict
                or set(raw_error) != set(ProjectionNumericErrorV2.__dataclass_fields__)):
            raise ValueError("numeric error fields differ")
        raw_verification["numeric_error"] = ProjectionNumericErrorV2(**raw_error)
        verification = JointNumericOriginalVerificationV1(**raw_verification)
    except (TypeError, ValueError, KeyError, IndexError) as exc:
        raise JointAdvanceHold("adopted numeric original is malformed") from exc
    _numeric_candidate(evidence, receipt)
    if (row[2] != receipt.receipt_digest
            or row[4] != canonical_digest(asdict(verification))
            or verification.math_transcript_sha256 != receipt.math_transcript_sha256
            or verification.policy_digest != expected_policy_digest
            or verification.readout_sha256 != expected_readout_sha256):
        raise JointAdvanceHold("adopted numeric original digest differs")
    member = next((item for item in evidence.members
                   if item.checkpoint_ref == original_ref), None)
    if member is None:
        raise JointAdvanceHold("numeric original member ref is absent")
    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                       namespace.as_tuple).fetchone()
    authority = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    recovery = db.execute(
        "SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    try:
        incarnation = json.loads(recovery[0])["graph_incarnation"] if recovery else None
    except (TypeError, ValueError, KeyError) as exc:
        raise JointAdvanceHold("current graph recovery identity is invalid") from exc
    if (epoch != (expected_graph_epoch,)
            or authority != (expected_access_epoch, expected_delete_epoch)
            or recovery is None or recovery[1] != expected_graph_revision
            or incarnation != expected_graph_incarnation
            or incarnation != evidence.graph_incarnation):
        raise JointAdvanceHold("current numeric original graph or rights epoch differs")
    _numeric_history(db, evidence)
    for item in evidence.members:
        for ref, revision, digest in (
            (item.checkpoint_ref, item.next_revision, item.next_value_digest),
            (item.output_state_ref, item.output_state_revision,
             item.output_state_digest),
        ):
            current = db.execute("SELECT revision,value,valid FROM graph_atoms "
                                 "WHERE token=?", (ref,)).fetchone()
            try:
                matches = (current is not None and current[0] == revision
                           and current[2] == 1
                           and canonical_digest(json.loads(current[1])) == digest)
            except (TypeError, ValueError):
                matches = False
            if not matches:
                raise JointAdvanceHold("numeric original member is no longer current")
    for drive_ref, _, source_ref, source_revision, access_ref, access_revision, _ in (
            receipt.source_versions):
        for ref, revision in ((source_ref, source_revision),
                              (access_ref, access_revision)):
            current = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?",
                                 (ref,)).fetchone()
            if current != (revision, 1):
                raise JointAdvanceHold("numeric original source or access is no longer current")
        if not drive_ref:
            raise JointAdvanceHold("numeric original drive ref is invalid")
    if trusted_current_verifier is None or not callable(trusted_current_verifier):
        raise JointAdvanceHold("W01 current Owner proof and installed replay are unavailable")
    if trusted_current_verifier(db, evidence, receipt, verification) is not True:
        raise JointAdvanceHold("W01 current Owner proof or installed replay rejected original")
    return JointNumericOriginalV1(original_ref, member.next_revision,
                                  operation_id, evidence.digest, receipt,
                                  verification)


__all__ = ["JointAdvanceHold", "ProductAdvanceMemberV2", "ProductAdvanceEvidenceV2",
           "JointAdvancePreflight", "install_joint_advance_store_v2",
           "preflight_joint_advance_v2", "record_joint_advance_v2", "read_joint_advance_v2",
           "JointNumericOriginalVerificationV1", "JointNumericOriginalPreflightV1",
           "JointNumericOriginalV1",
           "verification_from_installed_joint_replay_v1",
           "preflight_joint_numeric_original_v1", "record_joint_numeric_original_v1",
           "read_current_joint_numeric_original_v1"]
