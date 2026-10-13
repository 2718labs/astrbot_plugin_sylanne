"""W01-only immutable C04 encoding baseline record in a graph transaction.

The helper preserves a W01-authenticated historical read and D04's conditional
proof. It cannot decide whether the read set is complete, issue a projection,
grant Owner permission, or commit SQLite. W01 must provision the table before
its transaction and verify the encoding-time closure and installed assets.
"""

from __future__ import annotations


from dataclasses import asdict, dataclass, fields
import json
import math
import sqlite3

from ..contracts import canonical_json
from ..domains.d04.c04_projection_issuer_v3 import (
    D04EncodingBaselineProofV3, conditional_encoding_baseline_contract_v3,
)
from ..domains.d04.encoding_baseline_v2 import ExactGraphRefV2, ProjectionNumericErrorV2
from ..domains.d04.encoding_salience_v2 import D04EncodingSalienceProjectionV2
from ..domains.d04.interval_projection_v2 import (
    D04AxisProjectionIntervalV2, D04ProjectionMemberBindingV2,
    D04AuthoredProjectionMemberBindingV3,
)
from ..graph_types import AtomKey, GraphVersion, NamespaceEpoch
from ..runtime_contracts import (
    CommitReceipt, NamespaceId, canonical_digest, canonical_serialize,
)
from .c04_v3_contracts import (
    D04EncodingBaselineOriginalV3, D04EncodingBaselineAuthoredOriginalV3, decode_v3, encode_v3)
from .d04_joint_advance_v2 import (
    JointNumericOriginalV1, JointNumericOriginalVerificationV1,
    _decode_numeric_candidate,
)
from .d04_joint_output_original_store_v1 import read_d04_joint_output_original_v1


class C04EncodingBaselineStoreHold(ValueError):
    """The historical graph, joint original, record, or retry differs."""


@dataclass(frozen=True, slots=True)
class C04EncodingBaselineStoreRecordV3:
    original: D04EncodingBaselineOriginalV3
    proof: D04EncodingBaselineProofV3
    joint_operation_id: str
    encoding_receipt: CommitReceipt
    joint_receipt: CommitReceipt
    historical_closure_digest: str
    read_versions: tuple[GraphVersion, ...]
    record_digest: str
    status: str = "w01_transaction_read_uncommitted_until_outer_commit"


def _transaction(db: sqlite3.Connection) -> None:
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise C04EncodingBaselineStoreHold("W01 Owner graph transaction is required")


def _sha(value: object, name: str) -> str:
    if (type(value) is not str or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise C04EncodingBaselineStoreHold(f"{name} needs a bare SHA-256")
    return value


def install_c04_encoding_baseline_store_v3(db: sqlite3.Connection) -> None:
    """W01 schema hook, strictly outside a graph transaction."""
    if type(db) is not sqlite3.Connection or db.in_transaction:
        raise C04EncodingBaselineStoreHold("provision baseline table before transaction")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS graph_c04_encoding_baselines_v3 (
            bot TEXT NOT NULL, persona TEXT NOT NULL,
            encoding_operation_id TEXT NOT NULL, source_ref TEXT NOT NULL,
            joint_operation_id TEXT NOT NULL,
            original_json TEXT NOT NULL, original_digest TEXT NOT NULL,
            proof_json TEXT NOT NULL, proof_digest TEXT NOT NULL,
            as_known_at_json TEXT NOT NULL,
            historical_closure_digest TEXT NOT NULL,
            read_versions_json TEXT NOT NULL, read_versions_digest TEXT NOT NULL,
            encoding_receipt_digest TEXT NOT NULL,
            joint_receipt_digest TEXT NOT NULL,
            numeric_original_ref TEXT NOT NULL,
            numeric_original_revision INTEGER NOT NULL,
            record_digest TEXT NOT NULL,
            PRIMARY KEY(bot,persona,encoding_operation_id,source_ref),
            FOREIGN KEY(bot,persona,encoding_operation_id)
              REFERENCES graph_bundle_operations(bot,persona,operation_id),
            FOREIGN KEY(bot,persona,joint_operation_id)
              REFERENCES graph_d04_joint_advances_v2(bot,persona,operation_id));
        CREATE TRIGGER IF NOT EXISTS graph_c04_encoding_baseline_no_update_v3
          BEFORE UPDATE ON graph_c04_encoding_baselines_v3
          BEGIN SELECT RAISE(ABORT, 'C04 encoding baseline is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS graph_c04_encoding_baseline_no_delete_v3
          BEFORE DELETE ON graph_c04_encoding_baselines_v3
          BEGIN SELECT RAISE(ABORT, 'C04 encoding baseline is immutable'); END;
    """)


def _versions(encoded: str) -> tuple[GraphVersion, ...]:
    raw = json.loads(encoded)
    if type(raw) is not list or canonical_json(raw) != encoded:
        raise ValueError("graph version wire differs")
    result = tuple(GraphVersion(AtomKey.from_token(ref), revision)
                   for ref, revision in raw)
    if len({item.key for item in result}) != len(result):
        raise ValueError("duplicate graph read key")
    return result


def _receipt(db: sqlite3.Connection, namespace: NamespaceId,
             operation_id: str) -> CommitReceipt:
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    row = _producer_original_point_v3(db, table='graph_bundle_operations', columns=('digest', 'activity_id', 'effect_id', 'commit_seq', 'receipt_json'), key_columns=('bot', 'persona', 'operation_id'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2]))(namespace.as_tuple + (operation_id,)), legacy_reader=lambda: db.execute(
        "SELECT digest,activity_id,effect_id,commit_seq,receipt_json "
        "FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone())
    if row is None:
        raise C04EncodingBaselineStoreHold("graph CommitReceipt is absent")
    event = _producer_original_point_v3(db, table='graph_events', columns=('reads', 'revisions', 'epoch_revision', 'invalidated'), key_columns=('bot', 'persona', 'session', 'event_id'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2],_producer_params_v3[3]))(namespace.as_tuple + (row[1], operation_id)), legacy_reader=lambda: db.execute(
        "SELECT reads,revisions,epoch_revision,invalidated FROM graph_events "
        "WHERE bot=? AND persona=? AND session=? AND event_id=?",
        namespace.as_tuple + (row[1], operation_id),
    ).fetchone())
    if event is None:
        raise C04EncodingBaselineStoreHold("graph event is absent")
    try:
        body = json.loads(row[4])
        if (type(body) is dict and set(body)=={"schema","stage","graph_receipt_digest"}
                and body["schema"]=="d04.installed_graph_stage.v3"):
            from ..graph_types import GraphReceipt
            actual_graph = GraphReceipt("committed", _versions(event[1]), _versions(event[3]),
                NamespaceEpoch(*namespace.as_tuple,event[2]))
            if (canonical_json(body)!=row[4] or body["graph_receipt_digest"]!=canonical_digest(actual_graph)
                    or body["stage"]!="d04.appraisal_adopted.v3" or not operation_id.startswith("d04-adopt:")
                    or not any(item.key.type_name=="d04.appraisal_bundle.v1" for item in actual_graph.revisions)):

                raise ValueError("actual D04 installed stage receipt differs")
            body={"ledger_refs":[],"outbox_refs":[]}
        elif canonical_json(body) != row[4]:
            raise ValueError("graph receipt JSON differs")
        if (type(body) is not dict
                or type(body["ledger_refs"]) is not list
                or type(body["outbox_refs"]) is not list):
            raise ValueError("graph receipt JSON differs")
        return CommitReceipt(
            "committed", operation_id, row[0], row[1], row[2], row[3],
            _versions(event[0]), _versions(event[1]),
            (NamespaceEpoch(*namespace.as_tuple, event[2]),),
            tuple(body["ledger_refs"]), tuple(body["outbox_refs"]),
        )
    except (TypeError, ValueError, KeyError, IndexError) as exc:
        raise C04EncodingBaselineStoreHold("graph CommitReceipt is malformed") from exc


def _historical_reads(db: sqlite3.Connection,
                      original: D04EncodingBaselineOriginalV3,
                      receipt: CommitReceipt) -> None:
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    required = (original.source, original.perspective,
                *original.interpretations,
                *(item.feeling for item in original.members),
                *(item.checkpoint for item in original.members))
    versions = set(receipt.read_versions)
    if (len({item.ref for item in required}) != len(required)
            or any(GraphVersion(AtomKey.from_token(item.ref), item.revision)
                   not in versions for item in required)):
        raise C04EncodingBaselineStoreHold("encoding exact originals are not graph reads")
    for item in required:
        row = _producer_original_point_v3(db, table='graph_history', columns=('value', 'valid'), key_columns=('token', 'revision'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1]))((item.ref, item.revision)), legacy_reader=lambda: db.execute(
            "SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
            (item.ref, item.revision),
        ).fetchone())
        if row is None or row[1] != 1:
            raise C04EncodingBaselineStoreHold("encoding historical graph row is absent")
        try:
            value = json.loads(row[0])
            if canonical_json(value) != row[0]:
                raise ValueError("history is noncanonical")
        except (TypeError, ValueError) as exc:
            raise C04EncodingBaselineStoreHold("encoding historical graph row differs") from exc


def _exact(cls: type, raw: object) -> object:
    if type(raw) is not dict or set(raw) != set(cls.__dataclass_fields__):
        raise ValueError("conditional D04 proof fields differ")
    return cls(**raw)


def _decode_member_bindings(raw: object) -> tuple:
    """Closed ref-pair discrimination preserves the existing untagged proof wire."""
    if type(raw) is not list or not raw:
        raise ValueError("conditional member bindings are absent")
    kinds = {
        ("d04.numeric_checkpoint.v1", "d04.feeling_state.v1"): D04ProjectionMemberBindingV2,
        ("d04.numeric_checkpoint.v2", "d04.authored_feeling_state.v1"): D04AuthoredProjectionMemberBindingV3,
    }
    result = []
    for item in raw:
        if type(item) is not dict or set(item) != set(D04ProjectionMemberBindingV2.__dataclass_fields__):
            raise ValueError("conditional member binding fields differ")
        pair = (AtomKey.from_token(item["checkpoint_ref"]).type_name,
                AtomKey.from_token(item["feeling_ref"]).type_name)
        kind = kinds.get(pair)
        if kind is None:
            raise ValueError("conditional member reference lineage differs")
        result.append(_exact(kind, item))
    refs = tuple(item.checkpoint_ref for item in result)
    if len({type(item) for item in result}) != 1 or refs != tuple(sorted(set(refs))):
        raise ValueError("conditional member bindings are mixed or unordered")
    return tuple(result)


def _decode_proof(encoded: str) -> D04EncodingBaselineProofV3:
    raw = json.loads(encoded)
    if type(raw) is not dict or canonical_serialize(raw) != encoded:
        raise ValueError("conditional proof is noncanonical")
    if set(raw) != set(D04EncodingBaselineProofV3.__dataclass_fields__):
        raise ValueError("conditional proof fields differ")
    raw["namespace"] = _exact(NamespaceId, raw["namespace"])
    for name in ("source_version", "perspective_version"):
        raw[name] = _exact(ExactGraphRefV2, raw[name])
    raw["interpretation_versions"] = tuple(_exact(ExactGraphRefV2, item)
                                           for item in raw["interpretation_versions"])
    raw["feeling_bindings"] = _decode_member_bindings(raw["feeling_bindings"])
    raw["source_drive_bindings"] = tuple(tuple(item)
                                         for item in raw["source_drive_bindings"])
    raw["numeric_error"] = _exact(ProjectionNumericErrorV2, raw["numeric_error"])
    projection = raw["projection"]
    if type(projection) is not dict or set(projection) != set(
            D04EncodingSalienceProjectionV2.__dataclass_fields__):
        raise ValueError("conditional projection fields differ")
    projection["namespace"] = _exact(NamespaceId, projection["namespace"])
    projection["member_bindings"] = _decode_member_bindings(projection["member_bindings"])
    if projection["member_bindings"] != raw["feeling_bindings"]:
        raise ValueError("conditional projection member lineage differs")
    projection["normalized_axes"] = tuple(
        _exact(D04AxisProjectionIntervalV2, item)
        for item in projection["normalized_axes"])
    for name in ("salience_interval", "tone_interval"):
        projection[name] = tuple(projection[name])
    raw["projection"] = D04EncodingSalienceProjectionV2(**projection)
    projection_body = {field.name: getattr(raw["projection"], field.name)
                       for field in fields(raw["projection"])
                       if field.name not in {
                           "proof_digest", "status", "semantic_calibration"}}
    if (raw["projection"].status
            != "conditional_requires_w01_current_adopted_output"
            or raw["projection"].semantic_calibration != "unvalidated"
            or raw["projection"].proof_digest
               != canonical_digest(projection_body)):
        raise ValueError("conditional projection digest differs")
    proof = D04EncodingBaselineProofV3(**raw)
    body = {field.name: getattr(proof, field.name)
            for field in fields(proof)
            if field.name not in {"proof_digest", "status", "semantic_calibration"}}
    if (proof.status != "conditional_requires_w01_encoding_adoption"
            or proof.semantic_calibration != "unvalidated"
            or proof.proof_digest != canonical_digest(body)
            or canonical_serialize(asdict(proof)) != encoded):
        raise ValueError("conditional proof digest differs")
    return proof


def _joint_numeric(db: sqlite3.Connection, namespace: NamespaceId,
                   operation_id: str, original_ref: str,
                   original_revision: int, receipt_digest: str,
                   expected_digest: str) -> JointNumericOriginalV1:
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .d04_series_original_v1 import require_series_adopted_original_v1
    require_series_adopted_original_v1(db, namespace, operation_id)
    row = _producer_original_point_v3(db, table='graph_d04_joint_numeric_originals_v1', columns=('numeric_receipt_json', 'numeric_receipt_digest', 'verification_json', 'verification_digest'), key_columns=('bot', 'persona', 'operation_id'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2]))(namespace.as_tuple + (operation_id,)), legacy_reader=lambda: db.execute(
        "SELECT numeric_receipt_json,numeric_receipt_digest,verification_json,"
        "verification_digest FROM graph_d04_joint_numeric_originals_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone())
    if row is None:
        raise C04EncodingBaselineStoreHold("joint numeric original is absent")
    try:
        candidate = _decode_numeric_candidate(row[0])
        verification = json.loads(row[2])
        if (type(verification) is not dict
                or canonical_serialize(verification) != row[2]
                or set(verification)
                   != set(JointNumericOriginalVerificationV1.__dataclass_fields__)
                or type(verification["numeric_error"]) is not dict):
            raise ValueError("joint numeric verification differs")
        verification["numeric_error"] = _exact(
            ProjectionNumericErrorV2, verification["numeric_error"])
        verified = JointNumericOriginalVerificationV1(**verification)
        result = JointNumericOriginalV1(
            original_ref, original_revision, operation_id, receipt_digest,
            candidate, verified,
        )
        candidate_body = {field.name: getattr(candidate, field.name)
                          for field in fields(candidate)
                          if field.name not in {"receipt_digest", "status"}}
        if (candidate.receipt_digest != row[1]
                or candidate.receipt_digest != canonical_digest(candidate_body)
                or canonical_digest(asdict(verified)) != row[3]
                or canonical_digest(asdict(result)) != expected_digest):
            raise ValueError("joint numeric original digest differs")
        return result
    except (TypeError, ValueError, KeyError, IndexError) as exc:
        raise C04EncodingBaselineStoreHold("joint numeric original is malformed") from exc


def _joint_output_digest(db: sqlite3.Connection, namespace: NamespaceId,
                         operation_id: str, expected: str) -> None:
    try:
        value = read_d04_joint_output_original_v1(db, namespace, operation_id)
        if value is None or value.original_digest != expected:
            raise ValueError("joint output original differs")
    except (TypeError, ValueError) as exc:
        raise C04EncodingBaselineStoreHold("joint output original is malformed") from exc


def _payload(original: D04EncodingBaselineOriginalV3,
             proof: D04EncodingBaselineProofV3,
             encoding_receipt: CommitReceipt, joint_receipt: CommitReceipt,
             historical_closure_digest: str,
             numeric_original: JointNumericOriginalV1) -> tuple:
    original_json = encode_v3(original)
    proof_json = canonical_serialize(asdict(proof))
    as_known_at_json = canonical_json(proof.as_known_at)
    reads_json = canonical_serialize(tuple((item.key.token, item.revision)
                                           for item in encoding_receipt.read_versions))
    encoding_digest = canonical_digest(asdict(encoding_receipt))
    joint_digest = canonical_digest(asdict(joint_receipt))
    record_digest = canonical_digest({
        "schema": "c04.encoding-baseline-store.v3",
        "original": original_json, "proof": proof_json,
        "as_known_at": as_known_at_json,
        "historical_closure": historical_closure_digest,
        "reads": reads_json,
        "encoding_receipt": encoding_digest,
        "joint_receipt": joint_digest,
        "numeric_original_ref": numeric_original.original_ref,
        "numeric_original_revision": numeric_original.original_revision,
    })
    return (proof.joint_adoption_operation_id, original_json, original.digest,
            proof_json, proof.proof_digest, as_known_at_json,
            historical_closure_digest, reads_json, canonical_digest(reads_json),
            encoding_digest, joint_digest, numeric_original.original_ref,
            numeric_original.original_revision, record_digest)


def record_c04_encoding_baseline_v3(
    db: sqlite3.Connection, *, original: D04EncodingBaselineOriginalV3,
    proof: D04EncodingBaselineProofV3,
    numeric_original: JointNumericOriginalV1,
    historical_closure_digest: str,
) -> C04EncodingBaselineStoreRecordV3:
    """W01 calls after its graph operation row exists, before outer COMMIT."""
    _transaction(db)
    if (type(original) not in (D04EncodingBaselineOriginalV3, D04EncodingBaselineAuthoredOriginalV3)
            or type(proof) is not D04EncodingBaselineProofV3
            or type(numeric_original) is not JointNumericOriginalV1):
        raise C04EncodingBaselineStoreHold("typed baseline and numeric proof required")
    _sha(historical_closure_digest, "historical closure")
    if (type(proof.as_known_at) is not float or not math.isfinite(proof.as_known_at)
            or _decode_proof(canonical_serialize(asdict(proof))) != proof
            or original.namespace != proof.namespace
            or original.source.ref != proof.source_version.ref
            or original.source.revision != proof.source_version.revision
            or original != conditional_encoding_baseline_contract_v3(
                proof, encoding_operation_id=original.encoding_operation_id,
                owner_epoch=original.owner_epoch,
                access_epoch=original.access_epoch,
                delete_epoch=original.delete_epoch)
            or numeric_original.adoption_operation_id
               != proof.joint_adoption_operation_id
            or numeric_original.adoption_receipt_digest
               != proof.joint_adoption_receipt_digest
            or canonical_digest(asdict(numeric_original))
               != proof.numeric_original_digest
            or numeric_original.original_ref not in {
                item.checkpoint_ref for item in proof.feeling_bindings}):
        raise C04EncodingBaselineStoreHold("baseline proof and graph identity differ")
    namespace = original.namespace
    encoding_receipt = _receipt(db, namespace, original.encoding_operation_id)
    joint_receipt = _receipt(db, namespace, proof.joint_adoption_operation_id)
    if canonical_digest(asdict(joint_receipt)) != proof.joint_adoption_receipt_digest:
        raise C04EncodingBaselineStoreHold("joint adoption CommitReceipt differs")
    _historical_reads(db, original, encoding_receipt)
    _joint_numeric(db, namespace, proof.joint_adoption_operation_id,
                   numeric_original.original_ref, numeric_original.original_revision,
                   proof.joint_adoption_receipt_digest,
                   proof.numeric_original_digest)
    _joint_output_digest(db, namespace, proof.joint_adoption_operation_id,
                         proof.output_original_digest)
    payload = _payload(original, proof, encoding_receipt, joint_receipt,
                       historical_closure_digest, numeric_original)
    key = namespace.as_tuple + (original.encoding_operation_id,
                                original.source.ref)
    prior = db.execute(
        "SELECT joint_operation_id,original_json,original_digest,proof_json,"
        "proof_digest,as_known_at_json,historical_closure_digest,"
        "read_versions_json,read_versions_digest,encoding_receipt_digest,"
        "joint_receipt_digest,numeric_original_ref,numeric_original_revision,"
        "record_digest FROM graph_c04_encoding_baselines_v3 "
        "WHERE bot=? AND persona=? AND encoding_operation_id=? AND source_ref=?",
        key,
    ).fetchone()
    if prior is not None:
        if prior != payload:
            raise C04EncodingBaselineStoreHold("same encoding operation/source differs")
    else:
        db.execute(
            "INSERT INTO graph_c04_encoding_baselines_v3 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            key + payload,
        )
    return C04EncodingBaselineStoreRecordV3(
        original, proof, proof.joint_adoption_operation_id,
        encoding_receipt, joint_receipt, historical_closure_digest,
        encoding_receipt.read_versions, payload[-1],
    )


def read_c04_encoding_baseline_v3(
    db: sqlite3.Connection, *, namespace: NamespaceId,
    encoding_operation_id: str, source_ref: str,
) -> C04EncodingBaselineStoreRecordV3:
    """Cold-open W01 read within its Owner fence; verify immutable history."""
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    if type(db) is sqlite3.Connection:
        _transaction(db)
    else:
        from .c04_internal_work_original_v1 import _transaction as _original_read_transaction_v4
        _original_read_transaction_v4(db,original_read=True)
    if type(namespace) is not NamespaceId:
        raise C04EncodingBaselineStoreHold("typed namespace required")
    key = namespace.as_tuple + (encoding_operation_id, source_ref)
    row = _producer_original_point_v3(db, table='graph_c04_encoding_baselines_v3', columns=('joint_operation_id', 'original_json', 'original_digest', 'proof_json', 'proof_digest', 'as_known_at_json', 'historical_closure_digest', 'read_versions_json', 'read_versions_digest', 'encoding_receipt_digest', 'joint_receipt_digest', 'numeric_original_ref', 'numeric_original_revision', 'record_digest'), key_columns=('bot', 'persona', 'encoding_operation_id', 'source_ref'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2],_producer_params_v3[3]))(key), legacy_reader=lambda: db.execute(
        "SELECT joint_operation_id,original_json,original_digest,proof_json,"
        "proof_digest,as_known_at_json,historical_closure_digest,"
        "read_versions_json,read_versions_digest,encoding_receipt_digest,"
        "joint_receipt_digest,numeric_original_ref,numeric_original_revision,"
        "record_digest FROM graph_c04_encoding_baselines_v3 "
        "WHERE bot=? AND persona=? AND encoding_operation_id=? AND source_ref=?",
        key,
    ).fetchone())
    if row is None:
        raise C04EncodingBaselineStoreHold("encoding baseline original is absent")
    try:
        discriminator = json.loads(row[1]).get("$type")
        allowed_originals = {kind.__name__: kind for kind in (
            D04EncodingBaselineOriginalV3, D04EncodingBaselineAuthoredOriginalV3)}
        if discriminator not in allowed_originals:
            raise ValueError("baseline lineage wire discriminator is unknown")
        original = decode_v3(row[1], allowed_originals[discriminator])
        proof = _decode_proof(row[3])
        _sha(row[6], "historical closure")
        encoding_receipt = _receipt(db, namespace, encoding_operation_id)
        joint_receipt = _receipt(db, namespace, row[0])
        numeric = _joint_numeric(db, namespace, row[0], row[11], row[12],
                                 row[10], proof.numeric_original_digest)
        _joint_output_digest(db, namespace, row[0], proof.output_original_digest)
        if (original.namespace != namespace
                or original.encoding_operation_id != encoding_operation_id
                or original.source.ref != source_ref
                or original.digest != row[2]
                or proof.proof_digest != row[4]
                or proof.joint_adoption_operation_id != row[0]
                or canonical_json(proof.as_known_at) != row[5]
                or canonical_digest(row[7]) != row[8]
                or _versions(row[7]) != encoding_receipt.read_versions
                or canonical_digest(asdict(encoding_receipt)) != row[9]
                or canonical_digest(asdict(joint_receipt)) != row[10]
                or original != conditional_encoding_baseline_contract_v3(
                    proof, encoding_operation_id=encoding_operation_id,
                    owner_epoch=original.owner_epoch,
                    access_epoch=original.access_epoch,
                    delete_epoch=original.delete_epoch)):
            raise ValueError("baseline record identity differs")
        _historical_reads(db, original, encoding_receipt)
        expected = _payload(original, proof, encoding_receipt, joint_receipt,
                            row[6], numeric)
        if expected != row:
            raise ValueError("baseline record digest differs")
        return C04EncodingBaselineStoreRecordV3(
            original, proof, row[0], encoding_receipt, joint_receipt,
            row[6], encoding_receipt.read_versions, row[-1],
        )
    except (TypeError, ValueError, KeyError, IndexError) as exc:
        raise C04EncodingBaselineStoreHold("encoding baseline record is malformed") from exc


__all__ = [
    "C04EncodingBaselineStoreHold", "C04EncodingBaselineStoreRecordV3",
    "install_c04_encoding_baseline_store_v3",
    "record_c04_encoding_baseline_v3", "read_c04_encoding_baseline_v3",
]
