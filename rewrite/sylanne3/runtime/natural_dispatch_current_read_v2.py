"""Shared, transaction-local proof for one committed natural dispatch.

The caller pins a graph SQLite snapshot and supplies a trusted current time.
This reader makes no Authority call and grants no permission to dispatch.
"""

from __future__ import annotations

import json

from ..domains.d08 import GoalExecutionProvider
from ..domains.d09 import ClaimKind, ClaimUse
from ..domains.d09.natural_batch import (
    NATURAL_BATCH_SCHEMA_V2, validate_natural_verified_batch_value_v2,
)
from ..graph_store import GraphStore
from ..graph_types import AtomKey, GraphWrite
from ..host.identity import astrbot_namespace
from ..runtime_contracts import NamespaceId, canonical_digest
from .dispatch_admission import load_admission
from .dispatch_candidate import (
    GraphDispatchTextSegmentV1, NaturalDispatchCandidateEvidenceV2,
    NaturalDispatchCandidateRecoveryV2,
    natural_dispatch_segment_payload_ref_v2,
    validate_dispatch_candidate_writes,
)
from .first_ingress_v2 import scene_ref_for_conversation
from .natural_generation_issue_v2 import read_original_scoped_query_proof_v2
from .natural_reply_job_v2 import read_original_preparation
from .natural_scoped_query_proof_v2 import (
    NaturalScopedQueryHold, assert_natural_scoped_query_current_v2,
)


class NaturalDispatchCurrentHold(ValueError):
    """The committed identity or current graph closure is unavailable."""


def _graph_stamp(db, namespace: NamespaceId):
    row = db.execute(
        "SELECT schema,requirements_json,graph_revision "
        "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    metadata = GraphStore._decode_recovery(row, namespace)
    if metadata is None:
        raise NaturalDispatchCurrentHold("natural graph recovery metadata is absent")
    return metadata


def recover_natural_dispatch_candidate_in_transaction_v2(
        db, namespace: NamespaceId, operation_id: str,
) -> NaturalDispatchCandidateRecoveryV2 | None:
    """Rebuild four V2 writes from the original event and immutable history."""
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise NaturalDispatchCurrentHold("pinned graph transaction is required")
    row = db.execute(
        "SELECT activity_id,effect_id,receipt_json FROM "
        "graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if row is None:
        return None
    data = json.loads(row[2]).get("natural_dispatch_candidate")
    if data is None:
        return None
    if (type(data) is not dict
            or data.get("schema") != "sylanne.d11.natural_dispatch_candidate.v2"
            or data.get("status") != "natural_paid_review_current_hold"
            or type(data.get("refs")) is not list or len(data["refs"]) != 4):
        raise NaturalDispatchCurrentHold("durable natural dispatch candidate is invalid")
    event = db.execute(
        "SELECT revisions,epoch_revision,reads FROM graph_events WHERE bot=? "
        "AND persona=? AND session=? AND event_id=?",
        namespace.as_tuple + (row[0], operation_id),
    ).fetchone()
    if event is None or event[1] != data.get("graph_epoch"):
        raise NaturalDispatchCurrentHold("natural dispatch graph event is absent")
    revisions = {item.key.token: item.revision
                 for item in GraphStore._version_rows(event[0])}
    types = ("d08.action_intent.v1", "d08.action_schema.v1",
             "d08.communication_intent_grant.v1", NATURAL_BATCH_SCHEMA_V2)
    writes = []
    for position, item in enumerate(data["refs"]):
        if (type(item) is not list or len(item) != 2
                or type(item[0]) is not str or type(item[1]) is not int
                or item[1] < 1 or revisions.get(item[0]) != item[1]):
            raise NaturalDispatchCurrentHold("natural dispatch write version differs")
        key = AtomKey.from_token(item[0])
        if key.type_name != types[position]:
            raise NaturalDispatchCurrentHold("natural dispatch graph type differs")
        history = db.execute(
            "SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
            "AND event_bot=? AND event_persona=? AND event_session=? "
            "AND event_id=?",
            (item[0], item[1]) + namespace.as_tuple + (row[0], operation_id),
        ).fetchone()
        if history is None or history[1] != 1:
            raise NaturalDispatchCurrentHold("natural dispatch history is absent")
        writes.append(("d09" if position == 3 else "d08",
                       GraphWrite(key, json.loads(history[0]))))
    action = next(spec for spec in GoalExecutionProvider().register_types()
                  if spec.name == "d08.action_intent.v1").validator(
                      writes[0][1].value)
    if (action.identity.operation_id, action.identity.activity_id,
            action.identity.effect_id) != (operation_id, row[0], row[1]):
        raise NaturalDispatchCurrentHold("natural dispatch operation differs")
    evidence = validate_dispatch_candidate_writes(
        tuple(writes), namespace=namespace, identity=action.identity,
        read_versions=GraphStore._version_rows(event[2]),
        source_refs=tuple(data.get("source_refs", ())),
        access_epoch=data.get("access_epoch"),
        delete_epoch=data.get("delete_epoch"),
        query_epoch=data.get("query_epoch"),
    )
    if (type(evidence) is not NaturalDispatchCandidateEvidenceV2
            or evidence.digest != data.get("digest")):
        raise NaturalDispatchCurrentHold("natural dispatch candidate digest differs")
    metadata = _graph_stamp(db, namespace)
    if (data.get("graph_incarnation")
            != metadata.requirements.graph_incarnation
            or type(data.get("graph_revision")) is not int
            or data["graph_revision"] > metadata.graph_revision):
        raise NaturalDispatchCurrentHold("natural dispatch recovery stamp differs")
    return NaturalDispatchCandidateRecoveryV2(
        evidence, tuple((ref, revision) for ref, revision in data["refs"]),
        data["graph_epoch"], data["graph_incarnation"],
        data["graph_revision"],
    )


def read_current_natural_dispatch_segment_in_transaction_v2(
        db, namespace: NamespaceId, request, *, now_utc: float,
) -> tuple[GraphDispatchTextSegmentV1, NaturalDispatchCandidateEvidenceV2] | None:
    """Revalidate the committed batch and current scoped reads in one snapshot."""
    from ..dispatch_runtime import DispatchRequest

    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(request) is not DispatchRequest
            or request.namespace != "/".join(namespace.as_tuple)):
        raise NaturalDispatchCurrentHold("typed pinned dispatch read is required")
    row = db.execute(
        "SELECT admission_ref FROM graph_dispatch_admissions "
        "WHERE bot=? AND persona=? AND operation_id=? AND effect_id=?",
        namespace.as_tuple + (request.operation_id, request.effect_id),
    ).fetchone() if db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='graph_dispatch_admissions'"
    ).fetchone() else None
    if row is None:
        return None
    receipt = load_admission(db, namespace, row[0])
    recovered = recover_natural_dispatch_candidate_in_transaction_v2(
        db, namespace, request.operation_id)
    if receipt is None or recovered is None:
        raise NaturalDispatchCurrentHold("natural dispatch admission or batch is absent")
    admission, evidence = receipt.admission, recovered.evidence
    if (admission.request_digest != canonical_digest(request)
            or admission.candidate_digest != evidence.digest
            or admission.batch_digest != evidence.batch_digest
            or admission.segment_index != 0
            or request.segment_index != 0 or request.segment_count != 1
            or admission.payload_digest != request.payload_digest
            or admission.dispatch_generation != request.dispatch_generation
            or admission.graph_incarnation != recovered.graph_incarnation
            or receipt.graph_epoch != recovered.graph_epoch
            or request.payload_ref != natural_dispatch_segment_payload_ref_v2(
                evidence.batch_ref, 0)
            or (request.operation_id, request.effect_id,
                request.payload_digest) != (
                evidence.operation_id, evidence.effect_id,
                evidence.payload_digest)):
        raise NaturalDispatchCurrentHold("natural dispatch admission differs")
    batch_ref, batch_revision = recovered.write_versions[3]
    batch_row = db.execute(
        "SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
        "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
        (batch_ref, batch_revision) + namespace.as_tuple + (
            request.activity_id, request.operation_id),
    ).fetchone()
    if batch_row is None or batch_row[1] != 1:
        raise NaturalDispatchCurrentHold("committed natural batch is unavailable")
    batch = json.loads(batch_row[0])
    validate_natural_verified_batch_value_v2(batch)
    segment = batch["segment"]
    if (batch_ref != evidence.batch_ref
            or batch["batch_digest"] != evidence.batch_digest
            or batch["paid_review"]["receipt_digest"]
               != evidence.paid_review_digest
            or (batch["paid_review"]["generation_original_operation_id"],
                batch["paid_review"]["review_original_operation_id"])
               != (evidence.generation_original_operation_id,
                   evidence.review_original_operation_id)
            or batch["scene_id"] != admission.scene_ref
            or (batch["audience_id"],) != admission.audience
            or (segment["segment_id"], segment["payload_digest"],
                segment["effect_id"])
               != (evidence.segment_id, request.payload_digest,
                   request.effect_id)
            or segment["media_refs"]):
        raise NaturalDispatchCurrentHold(
            "natural batch scope or paid originals differ")
    barrier = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if barrier != (evidence.access_epoch, evidence.delete_epoch):
        raise NaturalDispatchCurrentHold("natural source authority barrier changed")
    for version in evidence.current_read_versions:
        atom = db.execute(
            "SELECT revision,valid FROM graph_atoms WHERE token=?",
            (version.key.token,),
        ).fetchone()
        if ((version.revision == 0 and atom is not None)
                or (version.revision > 0
                    and atom != (version.revision, 1))):
            raise NaturalDispatchCurrentHold("natural paid source read changed")
    parent_rows = db.execute(
        "SELECT parent_original_id FROM "
        "graph_natural_generation_preparations_v2 WHERE bot=? AND "
        "persona=? AND original_operation_id=?",
        namespace.as_tuple + (evidence.generation_original_operation_id,),
    ).fetchall()
    if len(parent_rows) != 1:
        raise NaturalDispatchCurrentHold("natural original scoped proof is absent")
    original = read_original_preparation(
        db, namespace, parent_rows[0][0], "generation")
    if (original is None or original.state != "terminal"
            or original.seal.original_operation_id !=
               evidence.generation_original_operation_id):
        raise NaturalDispatchCurrentHold("natural paid generation original differs")
    try:
        proof = read_original_scoped_query_proof_v2(db, original)
        assert_natural_scoped_query_current_v2(
            db, proof, now_utc=now_utc)
    except (NaturalScopedQueryHold, ValueError) as exc:
        raise NaturalDispatchCurrentHold(
            "natural social or source predicate changed") from exc
    try:
        account = json.loads(admission.account_ref)
        destination = json.loads(admission.audience[0])
    except (TypeError, ValueError) as exc:
        raise NaturalDispatchCurrentHold(
            "natural AstrBot route encoding is invalid") from exc
    if (type(account) is not list or len(account) != 3
            or type(destination) is not list or len(destination) != 2
            or any(type(item) is not str or not item
                   for item in (*account, *destination))
            or astrbot_namespace(account[0], account[2], "route-check").bot_id
               != namespace.bot_id
            or scene_ref_for_conversation(
                namespace, admission.account_ref, admission.audience[0])
               != admission.scene_ref):
        raise NaturalDispatchCurrentHold("natural AstrBot route differs")
    uses = tuple(ClaimUse(item["claim_ref"], item["start"], item["end"],
                          ClaimKind(item["asserted_as"]))
                 for item in segment["claim_uses"])
    return GraphDispatchTextSegmentV1(
        segment["body"], (), uses, account[0], account[1], account[2],
        destination[0], destination[1], admission.scene_ref,
    ), evidence


__all__ = [
    "NaturalDispatchCurrentHold",
    "read_current_natural_dispatch_segment_in_transaction_v2",
    "recover_natural_dispatch_candidate_in_transaction_v2",
]
