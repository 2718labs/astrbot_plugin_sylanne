"""Immutable root-v2 original written inside W01's already fenced graph transaction.

This stores full inputs and outputs, including per-axis boxes and readout
representatives. It neither authenticates Owner/package/budget nor runs FFI.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import sqlite3

from ..domains.d04.root import (
    AuthoredRootBlockInput, AuthoredRootCandidate, AuthoredRootInput,
    RootBlockIdentity, compile_authored_root_candidate, decode_root_candidate,
    encode_root_candidate,
)
from ..domains.d04.root_projection_v2 import RootProjectionCandidateV2
from ..domains.d04.joint_state_output_v1 import JointStateAxisOutputV1
from ..domains.d04.root_projection_v2 import RootProjectionMemberCandidateV2
from ..domains.d12.authored_root import D12AuthoredRootIntentV2
from ..graph_types import AtomKey, GraphVersion
from ..native_runtime.authored_root_initial_box import AuthoredRootInitialBoxMathCandidate
from ..runtime_contracts import CommitReceipt, NamespaceId, canonical_digest, canonical_serialize
from .budget import BudgetLease
from .d04_root_adoption_contract_v2 import RootAdoptionEvidenceV2, RootAdoptionWriteV2
from .d04_root_original_store_v1 import _receipt


class D04RootAdoptionOriginalHold(ValueError):
    """Root-v2 original is absent, incomplete, or differs from the graph."""


@dataclass(frozen=True, slots=True)
class RootGraphReadOriginalV2:
    ref: str
    revision: int
    valid: bool
    value_json: str

    def __post_init__(self) -> None:
        AtomKey.from_token(self.ref)
        if type(self.revision) is not int or self.revision < 0 or type(self.valid) is not bool:
            raise ValueError("invalid root read revision or validity")
        if self.revision == 0 and (self.valid or self.value_json != "{}"):
            raise ValueError("absent root read must use empty invalid value")
        _canonical(self.value_json)


@dataclass(frozen=True, slots=True)
class RootGraphWriteOriginalV2:
    ref: str
    revision: int
    value_json: str

    def __post_init__(self) -> None:
        AtomKey.from_token(self.ref)
        if type(self.revision) is not int or self.revision != 1:
            raise ValueError("initial root write must have revision one")
        _canonical(self.value_json)


@dataclass(frozen=True, slots=True)
class D04RootAdoptionOriginalV2:
    namespace: NamespaceId
    operation_id: str
    intent_json: str
    evidence_json: str
    candidate_json: str
    initial_box_json: str
    projection_json: str
    parent_budget_json: str
    owner_session_binding_digest: str
    reads_json: str
    writes_json: str
    receipt_json: str
    original_digest: str
    status: str = "recorded_requires_current_owner_replay"


def _canonical(encoded: str) -> object:
    if type(encoded) is not str:
        raise ValueError("original JSON must be text")
    decoded = json.loads(encoded)
    if canonical_serialize(decoded) != encoded:
        raise ValueError("original JSON is not canonical")
    return decoded


def _transaction(db: sqlite3.Connection) -> None:
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise D04RootAdoptionOriginalHold("root original needs caller-owned graph transaction")


def install_d04_root_adoption_original_v2(db: sqlite3.Connection) -> None:
    """Provision before W01 opens its graph transaction."""
    if type(db) is not sqlite3.Connection or db.in_transaction:
        raise D04RootAdoptionOriginalHold("root original schema installs outside graph transaction")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS graph_d04_root_adoption_originals_v2 (
            bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
            original_json TEXT NOT NULL, original_digest TEXT NOT NULL,
            PRIMARY KEY(bot,persona,operation_id),
            FOREIGN KEY(bot,persona,operation_id)
              REFERENCES graph_bundle_operations(bot,persona,operation_id));
        CREATE TRIGGER IF NOT EXISTS graph_d04_root_adoption_no_update_v2
          BEFORE UPDATE ON graph_d04_root_adoption_originals_v2
          BEGIN SELECT RAISE(ABORT, 'D04 root adoption original is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS graph_d04_root_adoption_no_delete_v2
          BEFORE DELETE ON graph_d04_root_adoption_originals_v2
          BEGIN SELECT RAISE(ABORT, 'D04 root adoption original is immutable'); END;
    """)


def _body(value: D04RootAdoptionOriginalV2) -> dict:
    return {name: getattr(value, name) for name in (
        "namespace", "operation_id", "intent_json", "evidence_json",
        "candidate_json", "initial_box_json", "projection_json",
        "parent_budget_json", "reads_json", "writes_json", "receipt_json",
        "owner_session_binding_digest",
        "status",
    )}


def _graph_history(db: sqlite3.Connection, original: D04RootAdoptionOriginalV2,
                   receipt: CommitReceipt) -> None:
    writes = tuple(RootGraphWriteOriginalV2(**row) for row in _canonical(original.writes_json))
    if (tuple(sorted(write.ref for write in writes)) != tuple(write.ref for write in writes)
            or len(set(write.ref for write in writes)) != len(writes)
            or {GraphVersion(AtomKey.from_token(write.ref), write.revision)
                for write in writes} != set(receipt.write_versions)):
        raise D04RootAdoptionOriginalHold("root original write set differs from receipt")
    for write in writes:
        key = AtomKey.from_token(write.ref)
        if NamespaceId.from_key(key) != original.namespace:
            raise D04RootAdoptionOriginalHold("root original write crosses namespace")
        history = db.execute(
            "SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
            "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
            (write.ref, 1, *original.namespace.as_tuple,
             receipt.activity_id, original.operation_id),
        ).fetchone()
        if history != (write.value_json, 1):
            raise D04RootAdoptionOriginalHold("root graph history differs from original")


def _decode_root_input(raw: dict) -> AuthoredRootInput:
    blocks = tuple(AuthoredRootBlockInput(
        RootBlockIdentity(**item["identity"]), tuple(item["axes"]),
        tuple(item["latent_state"]), tuple(tuple(pair) for pair in item["ordered_box"]),
        item["initial_error_ref"],
    ) for item in raw["blocks"])
    return AuthoredRootInput(
        raw["candidate_id"], tuple(raw["namespace"]), raw["author_id"],
        raw["draft_id"], raw["cursor"], raw["preset_digest"],
        raw["asset_digest"], blocks,
    )


def _projection_digest(raw: dict) -> str:
    members = tuple(RootProjectionMemberCandidateV2(
        item["block_id"], item["kind"], item["checkpoint_candidate_digest"],
        item["initial_box_digest"], tuple(item["latent_state"]),
        tuple(tuple(pair) for pair in item["ordered_box"]),
        item["verified_initial_error"],
        tuple(JointStateAxisOutputV1(**axis) for axis in item["axes"]),
        item["readout_proof_digest"],
    ) for item in raw["members"])
    if tuple(item.block_id for item in members) != tuple(raw["member_block_ids"]):
        raise ValueError("root projection members differ")
    return canonical_digest({
        "schema": "d04.root-projection-candidate.v2",
        "root": raw["root_candidate_digest"],
        "initial_box": raw["initial_box_transcript_sha256"],
        "manifest": raw["native_manifest_sha256"],
        "native": raw["native_sha256"],
        "policy": raw["policy_digest"],
        "readout": raw["readout_sha256"],
        "members": members,
    })


def _validate(original: D04RootAdoptionOriginalV2, receipt: CommitReceipt) -> None:
    if original.status != "recorded_requires_current_owner_replay":
        raise D04RootAdoptionOriginalHold("root original status differs")
    body = _body(original)
    if original.original_digest != canonical_digest(body):
        raise D04RootAdoptionOriginalHold("root original digest differs")
    for field in ("intent_json", "evidence_json", "candidate_json", "initial_box_json",
                  "projection_json", "parent_budget_json", "reads_json", "writes_json",
                  "receipt_json"):
        _canonical(getattr(original, field))
    intent = _canonical(original.intent_json)
    evidence = _canonical(original.evidence_json)
    candidate = _canonical(original.candidate_json)
    initial = _canonical(original.initial_box_json)
    projection = _canonical(original.projection_json)
    budget = _canonical(original.parent_budget_json)
    decoded_candidate = decode_root_candidate(candidate)
    decoded_input = _decode_root_input(intent["root_input"])
    reads = tuple(RootGraphReadOriginalV2(**row) for row in _canonical(original.reads_json))
    writes = tuple(RootGraphWriteOriginalV2(**row) for row in _canonical(original.writes_json))
    namespace = asdict(original.namespace)
    if (intent["namespace"] != namespace or evidence["namespace"] != namespace
            or intent["operation_id"] != original.operation_id
            or evidence["operation_id"] != original.operation_id
            or receipt.operation_id != original.operation_id
            or receipt.operation_digest != evidence["bundle_digest"]
            or original.receipt_json != canonical_serialize(asdict(receipt))
            or intent["owner_actor_id"] != evidence["owner_actor"]
            or intent["owner_session_id"] != evidence["owner_session_ref"]
            or intent["candidate_digest"] != evidence["candidate_digest"]
            or intent["preset_digest"] != evidence["preset_digest"]
            or intent["asset_digest"] != evidence["asset_digest"]
            or intent["draft_ref"] != evidence["draft_head"]["ref"]
            or intent["draft_revision"] != evidence["draft_head"]["version"]
            or candidate["preset_digest"] != evidence["preset_digest"]
            or decoded_candidate.digest != evidence["candidate_digest"]
            or candidate["candidate_id"] != intent["root_input"]["candidate_id"]
            or compile_authored_root_candidate(decoded_candidate.preset, decoded_input)
               != decoded_candidate
            or decoded_input.namespace != original.namespace.as_tuple
            or decoded_input.author_id != intent["owner_actor_id"]
            or decoded_input.draft_id != (
                f"{intent['draft_ref']}@{intent['draft_revision']}:{intent['draft_digest']}")
            or initial["candidate_sha256"] != evidence["candidate_digest"]
            or initial["transcript_sha256"] != evidence["initial_transcript_digest"]
            or initial["binding_sha256"] != canonical_digest(initial["production_binding"])
            or initial["transcript_sha256"] != canonical_digest({
                "schema": "d04.authored-root-initial-box-math.v1",
                "candidate_sha256": initial["candidate_sha256"],
                "binding_sha256": initial["binding_sha256"],
                "blocks": initial["blocks"],
                "status": "conditional_math_candidate",
            })
            or projection["root_candidate_digest"] != evidence["candidate_digest"]
            or projection["projection_digest"] != evidence["output_projection_digest"]
            or _projection_digest(projection) != evidence["output_projection_digest"]
            or projection["initial_box_transcript_sha256"]
               != evidence["initial_transcript_digest"]
            or projection["native_manifest_sha256"] != evidence["native_manifest_sha256"]
            or projection["native_sha256"] != evidence["native_sha256"]
            or initial["production_binding"]["manifest_sha256"]
               != evidence["native_manifest_sha256"]
            or initial["production_binding"]["native_sha256"] != evidence["native_sha256"]
            or budget["bot_id"] != original.namespace.bot_id
            or budget["persona_id"] != original.namespace.persona_id
            or original.owner_session_binding_digest != evidence["owner_session_binding_digest"]
            or budget["lease_id"] != evidence["parent_budget_lease_ref"]
            or canonical_digest(budget) != evidence["parent_budget_original_digest"]
            or intent["draft_digest"] != evidence["draft_digest"]
            or intent["input_digest"] != evidence["root_input_digest"]
            or canonical_digest(decoded_input)
               != evidence["root_input_digest"]
            or canonical_digest(reads) != evidence["graph_read_set_digest"]
            or canonical_digest(tuple(RootAdoptionWriteV2(**item)
                                      for item in evidence["writes"]))
               != evidence["output_write_set_digest"]):
        raise D04RootAdoptionOriginalHold("root original evidence binding differs")
    read_by_ref = {item.ref: item for item in reads}
    if (len(read_by_ref) != len(reads)
            or tuple(read_by_ref) != tuple(sorted(read_by_ref))
            or any(NamespaceId.from_key(AtomKey.from_token(item.ref)) != original.namespace
                   for item in reads)
            or {GraphVersion(AtomKey.from_token(item.ref), item.revision)
                for item in reads} != set(receipt.read_versions)):
        raise D04RootAdoptionOriginalHold("root original read set differs")
    for head in (evidence["d01_head"], evidence["draft_head"]):
        read = read_by_ref.get(head["ref"])
        if read is None or read.revision != head["version"] or not read.valid:
            raise D04RootAdoptionOriginalHold("D01 or draft head omitted from root reads")
    write_by_ref = {item.ref: item for item in writes}
    if len(write_by_ref) != len(writes) or len(writes) != 2 * len(evidence["writes"]):
        raise D04RootAdoptionOriginalHold("root write set is incomplete")
    for pair in evidence["writes"]:
        for key, digest in (("checkpoint_ref", "checkpoint_value_digest"),
                            ("state_ref", "state_value_digest")):
            write = write_by_ref.get(pair[key])
            if write is None or canonical_digest(_canonical(write.value_json)) != pair[digest]:
                raise D04RootAdoptionOriginalHold("root write value differs from evidence")


def record_d04_root_adoption_original_v2(
    db: sqlite3.Connection, *, intent: D12AuthoredRootIntentV2,
    evidence: RootAdoptionEvidenceV2, candidate: AuthoredRootCandidate,
    initial_box: AuthoredRootInitialBoxMathCandidate,
    projection: RootProjectionCandidateV2, parent_budget: BudgetLease,
    reads: tuple[RootGraphReadOriginalV2, ...],
    writes: tuple[RootGraphWriteOriginalV2, ...], receipt: CommitReceipt,
    owner_session_binding_digest: str,
) -> D04RootAdoptionOriginalV2:
    """Record exact bytes after W01 commits writes inside the same open transaction."""
    _transaction(db)
    if any(type(item) is not expected for item, expected in (
        (intent, D12AuthoredRootIntentV2), (evidence, RootAdoptionEvidenceV2),
        (candidate, AuthoredRootCandidate),
        (initial_box, AuthoredRootInitialBoxMathCandidate),
        (projection, RootProjectionCandidateV2), (parent_budget, BudgetLease),
        (receipt, CommitReceipt),
    )) or type(reads) is not tuple or type(writes) is not tuple:
        raise D04RootAdoptionOriginalHold("typed root originals are required")
    if (candidate.digest != evidence.candidate_digest
            or type(owner_session_binding_digest) is not str
            or len(owner_session_binding_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in owner_session_binding_digest)):
        raise D04RootAdoptionOriginalHold("root candidate differs from evidence")
    body = dict(
        namespace=intent.namespace, operation_id=intent.operation_id,
        intent_json=canonical_serialize(asdict(intent)),
        evidence_json=canonical_serialize(asdict(evidence)),
        candidate_json=canonical_serialize(encode_root_candidate(candidate)),
        initial_box_json=canonical_serialize(asdict(initial_box)),
        projection_json=canonical_serialize(asdict(projection)),
        parent_budget_json=canonical_serialize(asdict(parent_budget)),
        owner_session_binding_digest=owner_session_binding_digest,
        reads_json=canonical_serialize(tuple(asdict(item) for item in reads)),
        writes_json=canonical_serialize(tuple(asdict(item) for item in writes)),
        receipt_json=canonical_serialize(asdict(receipt)),
        status="recorded_requires_current_owner_replay",
    )
    original = D04RootAdoptionOriginalV2(**body, original_digest=canonical_digest(body))
    saved_receipt = _receipt(db, intent.namespace, intent.operation_id)
    if saved_receipt != receipt:
        raise D04RootAdoptionOriginalHold("root graph receipt differs")
    _validate(original, receipt)
    _graph_history(db, original, receipt)
    encoded = canonical_serialize(_body(original))
    key = (*intent.namespace.as_tuple, intent.operation_id)
    prior = db.execute(
        "SELECT original_json,original_digest FROM graph_d04_root_adoption_originals_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?", key,
    ).fetchone()
    if prior is not None:
        if prior != (encoded, original.original_digest):
            raise D04RootAdoptionOriginalHold("root operation retry differs")
    else:
        db.execute("INSERT INTO graph_d04_root_adoption_originals_v2 VALUES(?,?,?,?,?)",
                   (*key, encoded, original.original_digest))
    return original


def read_d04_root_adoption_original_v2(
    db: sqlite3.Connection, *, namespace: NamespaceId, operation_id: str,
) -> D04RootAdoptionOriginalV2:
    """Read and recheck stored bytes, graph receipt and historical writes."""
    _transaction(db)
    if type(namespace) is not NamespaceId or type(operation_id) is not str or not operation_id:
        raise D04RootAdoptionOriginalHold("root original identity is required")
    row = db.execute(
        "SELECT original_json,original_digest FROM graph_d04_root_adoption_originals_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id),
    ).fetchone()
    if row is None:
        raise D04RootAdoptionOriginalHold("root adoption original is absent")
    try:
        body = _canonical(row[0])
        if type(body) is not dict or set(body) != {
            "namespace", "operation_id", "intent_json", "evidence_json",
            "candidate_json", "initial_box_json", "projection_json",
            "parent_budget_json", "owner_session_binding_digest", "reads_json",
            "writes_json", "receipt_json", "status",
        } or body["namespace"] != _canonical(canonical_serialize(namespace)) \
                or body["operation_id"] != operation_id:
            raise ValueError("root original identity differs")
        original = D04RootAdoptionOriginalV2(
            **{**body, "namespace": namespace}, original_digest=row[1])
        receipt = _receipt(db, namespace, operation_id)
        _validate(original, receipt)
        _graph_history(db, original, receipt)
        if canonical_serialize(_body(original)) != row[0]:
            raise ValueError("root original bytes differ")
        return original
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise D04RootAdoptionOriginalHold("root adoption original is invalid") from exc
