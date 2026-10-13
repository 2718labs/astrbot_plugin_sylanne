"""Final natural V2 claim evidence, checked inside W01's held graph transaction.

This module produces the existing immutable D11 claim value and GraphWrite.  It
does not commit either, call Authority, or authorize a platform send.  W01 must
use ``_commit_dispatch_claim_atom_in_transaction`` before its outer COMMIT.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math

from ..authority_service.reverse_handoff import (
    require_exact_authority_snapshot, require_exact_reverse_handoff_identity,
)
from ..authority_service.v2_contract import (
    AuthorityDispatchSnapshotV1, DispatchHandoffContextV1, ExecutionBindingV2,
    MutationReceiptV2, OwnerDispatchWitnessV1,
    canonical_digest as authority_digest,
)
from ..dispatch_runtime import DispatchRequest
from ..domains.d08.execution import (
    ActionSchema, ActionSchemaRecord, GoalExecutionProvider,
)
from ..domains.d08.natural_plan import natural_route_semantic_digest_v2
from ..domains.d09.natural_batch import validate_natural_verified_batch_value, natural_batch_segment_count
from ..runtime_contracts import namespace_ref
from ..graph_types import AtomKey, GraphWrite
from ..runtime_contracts import CommitReceipt, NamespaceId, canonical_digest
from .dispatch_admission import (
    DispatchAdmissionReceiptV1, _request_matches,
    check_receipts_against_specs, load_admission,
)
from .dispatch_candidate import (
    NaturalDispatchCandidateEvidenceV2, natural_dispatch_segment_payload_ref_v2,
)
from .dispatch_graph_claim import (
    DispatchGraphClaimValueV1, dispatch_claim_graph_write,
)
from .natural_scoped_query_proof_v2 import (
    NaturalScopedQueryProofV2, assert_natural_scoped_query_current_v2,
)
from .natural_generation_issue_v2 import read_original_scoped_query_proof_v2
from .natural_reply_job_v2 import read_original_preparation
from .reply_entity_route_v2 import (
    CurrentReplyEntityRouteBindingV2, ReplyEntityRouteHold,
    read_current_reply_entity_route_binding_v2,
)
from .reply_model_job import CurrentReplyRouteManifestV2


class NaturalDispatchClaimHold(RuntimeError):
    """One final natural predicate is unavailable or changed."""


def require_natural_action_uncancelled_v3(db, namespace, evidence, cancel_epoch: int) -> None:
    """Read the existing durable D08 cancellation head in the held snapshot."""
    action_key = AtomKey.from_token(evidence.action_ref)
    key = AtomKey(action_key.owner, "d08.action_cancellation.v1", action_key.name)
    row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                     (key.token, *namespace.as_tuple)).fetchone()
    if row is None or row[1] != 1:
        raise NaturalDispatchClaimHold("natural cancellation head is unavailable")
    validator = next(spec.validator for spec in GoalExecutionProvider().register_types()
                     if spec.name == key.type_name)
    state = validator(json.loads(row[0]))
    if (state.action_id != action_key.name or state.action_digest != evidence.action_digest
            or state.activity_id != action_key.owner.subject
            or state.effect_id != evidence.effect_id or state.state != "active"
            or state.cancel_epoch != cancel_epoch):
        raise NaturalDispatchClaimHold("natural reply was durably cancelled")


@dataclass(frozen=True, slots=True)
class NaturalDispatchClaimPreparedV2:
    value: DispatchGraphClaimValueV1
    write: GraphWrite


def prepare_natural_dispatch_claim_v2(
    *, db, namespace: NamespaceId, admission_receipt: DispatchAdmissionReceiptV1,
    request: DispatchRequest, evidence: NaturalDispatchCandidateEvidenceV2,
    operation: CommitReceipt, batch: dict,
    original_scope_proof: NaturalScopedQueryProofV2,
    current_route: CurrentReplyEntityRouteBindingV2,
    context: DispatchHandoffContextV1, binding: ExecutionBindingV2,
    claimed: MutationReceiptV2, witness: OwnerDispatchWitnessV1,
    authority_snapshot: AuthorityDispatchSnapshotV1,
    now_utc: float,
) -> NaturalDispatchClaimPreparedV2:
    """Recheck one original paid natural effect and prepare its unique P2 atom.

    ``batch`` must be read from the committed V2 history row by W01, never
    synthesized from a candidate. ``current_route`` is the current D03 route
    reader's result in this same transaction. The original scoped proof must
    come from the sealed paid generation preparation.
    """
    if (not getattr(db, "in_transaction", False)
            or type(namespace) is not NamespaceId
            or type(admission_receipt) is not DispatchAdmissionReceiptV1
            or type(request) is not DispatchRequest
            or type(evidence) is not NaturalDispatchCandidateEvidenceV2
            or type(operation) is not CommitReceipt
            or type(original_scope_proof) is not NaturalScopedQueryProofV2
            or type(current_route) is not CurrentReplyEntityRouteBindingV2
            or type(context) is not DispatchHandoffContextV1
            or type(binding) is not ExecutionBindingV2
            or type(claimed) is not MutationReceiptV2
            or type(witness) is not OwnerDispatchWitnessV1
            or type(authority_snapshot) is not AuthorityDispatchSnapshotV1
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        raise NaturalDispatchClaimHold("typed final natural transaction required")
    admission = admission_receipt.admission
    if load_admission(db, namespace, admission.admission_ref) != admission_receipt:
        raise NaturalDispatchClaimHold("committed natural admission differs")
    try:
        validate_natural_verified_batch_value(batch)
        require_exact_reverse_handoff_identity(
            namespace_ref(namespace), context, binding, claimed)
        require_exact_authority_snapshot(context, witness, authority_snapshot)
        admission.require_current(float(now_utc))
    except (TypeError, ValueError, RuntimeError) as exc:
        raise NaturalDispatchClaimHold("natural batch, admission or P2 changed") from exc
    permit, anchor = context.permit, authority_snapshot.anchor
    own = tuple(item for item in authority_snapshot.unresolved_effects
                if item.effect_id == request.effect_id)
    if (len(own) != 1 or own[0].phase != "claimed"
            or own[0].operation_id != request.operation_id
            or own[0].mutation_id != claimed.pending.mutation_id
            or own[0].execution_seq != anchor.execution_seq
            or own[0].append_digest != anchor.execution_digest
            or claimed.pending.expected_append_digest != anchor.execution_digest
            or witness.context_digest != authority_digest(context)
            or witness.graph_namespace != binding.graph_namespace
            or witness.authority_namespace != permit.namespace
            or witness.guard.authority_id != permit.authority_id
            or witness.guard.namespace != namespace):
        raise NaturalDispatchClaimHold("current Authority P2 or Owner witness changed")
    if (operation.status != "committed" or operation.operation_id != request.operation_id
            or operation.effect_id != request.effect_id
            or operation.activity_id != request.activity_id
            or len(operation.outbox_refs) != 1 or not operation.outbox_refs[0]
            or binding.graph_namespace != "/".join(namespace.as_tuple)
            or binding.graph_incarnation != admission.graph_incarnation
            or binding.origin.admission_ref != admission.admission_ref
            or binding.origin.payload_digest != "sha256:" + request.payload_digest
            or binding.origin.effect_id != request.effect_id
            or binding.origin.operation_id != request.operation_id
            or request.namespace != binding.graph_namespace
            or not _request_matches(admission, request)
            or admission.request_digest != canonical_digest(request)
            or admission.candidate_digest != evidence.digest
            or admission.batch_digest != evidence.batch_digest
            or (admission.operation_id, admission.effect_id, admission.activity_id)
               != (request.operation_id, request.effect_id, request.activity_id)
            or (evidence.operation_id, evidence.effect_id)
               != (request.operation_id, request.effect_id)
            or request.payload_ref != natural_dispatch_segment_payload_ref_v2(
                evidence.batch_ref, batch["segment"]["position"])
            or request.segment_index != batch["segment"]["position"]
            or request.segment_count != natural_batch_segment_count(batch)
            or request.proactive_contact):
        raise NaturalDispatchClaimHold("committed natural admission or effect differs")
    paid, segment = batch["paid_review"], batch["segment"]
    require_natural_action_uncancelled_v3(db, namespace, evidence, request.cancel_epoch)
    history = db.execute(
        "SELECT value,valid FROM graph_history WHERE token=? AND event_bot=? "
        "AND event_persona=? AND event_session=? AND event_id=?",
        (evidence.batch_ref,) + namespace.as_tuple + (
            request.activity_id, request.operation_id),
    ).fetchall()
    if (len(history) != 1 or history[0][1] != 1
            or json.loads(history[0][0]) != batch):
        raise NaturalDispatchClaimHold("committed natural V2 batch differs")
    if (batch["operation_id"] != request.operation_id
            or batch["effect_id"] != request.effect_id
            or batch["activity_id"] != request.activity_id
            or batch["batch_digest"] != evidence.batch_digest
            or batch["grant_digest"] != admission.grant_digest
            or batch["scene_id"] != admission.scene_ref
            or (batch["audience_id"],) != admission.audience
            or batch["action_id"] != AtomKey.from_token(evidence.action_ref).name
            or segment["segment_id"] != evidence.segment_id
            or segment["effect_id"] != request.effect_id
            or segment["payload_digest"] != request.payload_digest
            or segment["payload_digest"] != evidence.payload_digest
            or segment["media_refs"]
            or paid["receipt_digest"] != evidence.paid_review_digest
            or paid["generation_original_operation_id"]
               != evidence.generation_original_operation_id
            or paid["review_original_operation_id"]
               != evidence.review_original_operation_id
            or paid["generation_original_operation_id"]
               == paid["review_original_operation_id"]):
        raise NaturalDispatchClaimHold("original paid review or exact payload differs")
    parents = db.execute(
        "SELECT parent_original_id FROM graph_natural_generation_preparations_v2 "
        "WHERE bot=? AND persona=? AND original_operation_id=?",
        namespace.as_tuple + (evidence.generation_original_operation_id,),
    ).fetchall()
    if len(parents) != 1:
        raise NaturalDispatchClaimHold("paid generation original is absent")
    generation = read_original_preparation(db, namespace, parents[0][0], "generation")
    review = read_original_preparation(db, namespace, parents[0][0], "review")
    if (generation is None or review is None
            or generation.state != "terminal" or review.state != "terminal"
            or generation.seal.original_operation_id
               != evidence.generation_original_operation_id
            or review.seal.original_operation_id
               != evidence.review_original_operation_id
            or generation.seal.call_id != paid["generation_call_id"]
            or review.seal.call_id != paid["review_call_id"]
            or generation.typed_request_digest
               != paid["generation_model_call_request_digest"]
            or review.typed_request_digest
               != paid["review_model_call_request_digest"]
            or generation.seal.reservation_operation_id
               != paid["generation_reservation_operation_id"]
            or review.seal.reservation_operation_id
               != paid["review_reservation_operation_id"]
            or generation.seal.parent_budget_lease_id
               != paid["parent_budget_lease_id"]
            or review.seal.parent_budget_lease_id
               != paid["parent_budget_lease_id"]
            or review.seal.review_policy_version
               != paid["review_policy_version"]
            or review.seal.generation_original_operation_id
               != generation.seal.original_operation_id
            or review.seal.generation_call_id != generation.seal.call_id
            or review.seal.generation_output_digest
               != generation.terminal_output_digest
            or generation.seal.qualified_units_digest
               != batch["qualified_units_digest"]
            or review.seal.qualified_units_digest
               != batch["qualified_units_digest"]
            or generation.terminal_receipt_digest
               != paid["generation_terminal_receipt_digest"]
            or review.terminal_receipt_digest
               != paid["review_terminal_receipt_digest"]
            or generation.terminal_output_digest
               != paid["generation_output_digest"]
            or review.terminal_output_digest
               != paid["review_output_digest"]
            or read_original_scoped_query_proof_v2(db, generation)
               != original_scope_proof):
        raise NaturalDispatchClaimHold("sealed dual paid originals or scoped proof differ")
    epochs = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if epochs != (evidence.access_epoch, evidence.delete_epoch):
        raise NaturalDispatchClaimHold("natural D06 authority epoch changed")
    for version in evidence.current_read_versions:
        head = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?",
                          (version.key.token,)).fetchone()
        if ((version.revision == 0 and head is not None)
                or (version.revision > 0 and head != (version.revision, 1))):
            raise NaturalDispatchClaimHold("natural positive read changed")
    scope = original_scope_proof.scope
    if (scope.namespace != namespace or scope.scene_ref != batch["scene_id"]
            or scope.audience_id != batch["audience_id"]
            or current_route.namespace != namespace
            or current_route.scene_ref != scope.scene_ref
            or current_route.conversation_ref != scope.audience_id
            or current_route.target_entity_ref != scope.target_entity_ref
            or current_route.binding_version.key.token
               != scope.account_binding_ref
            or current_route.query.namespace != namespace
            or current_route.query.scope_ref != "all"
            or (current_route.valid_until_utc is not None
                and current_route.valid_until_utc <= now_utc)
            or natural_route_semantic_digest_v2(current_route)
               != batch["route_binding_digest"]):
        raise NaturalDispatchClaimHold("current natural private route differs")
    try:
        current_proof = assert_natural_scoped_query_current_v2(
            db, original_scope_proof, now_utc=float(now_utc))
    except (ValueError, RuntimeError) as exc:
        raise NaturalDispatchClaimHold("current D03/D05/D06 scoped query changed") from exc
    if current_proof != original_scope_proof:
        raise NaturalDispatchClaimHold("natural negative query changed")
    route_manifest = CurrentReplyRouteManifestV2(
        namespace, current_route.c02_operation_id, current_route.source_ref,
        current_route.platform_ref, current_route.conversation_ref,
        current_route.scene_ref, canonical_digest({
            "account_ref": current_route.platform_ref,
            "destination_ref": current_route.conversation_ref,
            "scene_ref": current_route.scene_ref,
        }),
    )
    try:
        fresh_route = read_current_reply_entity_route_binding_v2(
            db, namespace, route_manifest, current_route.query, now_utc=now_utc)
    except (ReplyEntityRouteHold, ValueError) as exc:
        raise NaturalDispatchClaimHold("natural private route query changed") from exc
    if fresh_route != current_route:
        raise NaturalDispatchClaimHold("natural private route matches changed")
    for version in (
            current_route.anchor_version, current_route.binding_version,
            current_route.arrival_event_version,
            current_route.binding_evidence_event_version,
            current_route.source_version, current_route.access_version,
            *current_route.binding_scan_versions):
        head = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?",
                          (version.key.token,)).fetchone()
        if head != (version.revision, 1):
            raise NaturalDispatchClaimHold("natural current route head changed")
    action_row = db.execute(
        "SELECT value,valid FROM graph_atoms WHERE token=?", (evidence.action_ref,),
    ).fetchone()
    schema_row = db.execute(
        "SELECT value,valid FROM graph_atoms WHERE token=?", (evidence.schema_ref,),
    ).fetchone()
    action_key = AtomKey.from_token(evidence.action_ref)
    schema_key = AtomKey.from_token(evidence.schema_ref)
    if (action_row is None or schema_row is None
            or action_row[1] != 1 or schema_row[1] != 1
            or (action_key.owner.bot, action_key.owner.persona)
               != namespace.as_tuple
            or (schema_key.owner.bot, schema_key.owner.persona)
               != namespace.as_tuple
            or action_key.owner.kind != "activity"
            or action_key.owner.subject != request.activity_id
            or schema_key.owner != action_key.owner
            or action_key.type_name != "d08.action_intent.v1"
            or schema_key.type_name != "d08.action_schema.v1"):
        raise NaturalDispatchClaimHold("current D08 communication action changed")
    validators = {spec.name: spec.validator
                  for spec in GoalExecutionProvider().register_types()}
    try:
        action = validators["d08.action_intent.v1"](json.loads(action_row[0]))
        schema_record = validators["d08.action_schema.v1"](
            json.loads(schema_row[0]))
        schema = ActionSchema(schema_record.schema_id, schema_record.action_kind,
                              schema_record.proactive,
                              schema_record.required_checks)
        check_receipts_against_specs(admission, schema.required_checks, now_utc)
    except (KeyError, TypeError, ValueError) as exc:
        raise NaturalDispatchClaimHold("current natural RequiredChecks differ") from exc
    if (type(schema_record) is not ActionSchemaRecord
            or canonical_digest(action) != evidence.action_digest
            or canonical_digest(schema_record) != evidence.schema_digest
            or ActionSchemaRecord.bind(action, schema) != schema_record
            or action.action_kind != "communication"
            or schema.action_kind != "communication" or schema.proactive
            or action.identity.operation_id != request.operation_id
            or action.identity.effect_id != request.effect_id
            or action.identity.activity_id != request.activity_id
            or action.required_checks != schema.required_checks
            or tuple(batch["required_check_refs"])
               != request.required_check_refs):
        raise NaturalDispatchClaimHold("current natural communication checks differ")
    evidence_digest = "sha256:" + canonical_digest({
        "natural_v2": True, "admission": admission_receipt,
        "operation": operation, "candidate": evidence,
        "paid_review": paid, "batch_digest": batch["batch_digest"],
        "scoped_proof": current_proof, "route": current_route,
        "authority_snapshot": authority_snapshot, "owner_witness": witness,
    })
    value = DispatchGraphClaimValueV1(
        namespace.bot_id, namespace.persona_id, binding.graph_incarnation,
        request.activity_id, request.effect_id, request.operation_id,
        context.handoff_id, admission.admission_ref, permit.namespace,
        authority_digest(permit), permit.fence_epoch, claimed.updated_revision,
        anchor.execution_seq, anchor.execution_digest,
        authority_digest(context), authority_digest(witness),
        authority_digest(binding), authority_digest(claimed), evidence_digest,
    )
    return NaturalDispatchClaimPreparedV2(value, dispatch_claim_graph_write(value))


__all__ = ("NaturalDispatchClaimHold", "NaturalDispatchClaimPreparedV2",
           "prepare_natural_dispatch_claim_v2")
