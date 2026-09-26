"""Non-authorizing D11 prerequisite for a future same-P2 graph claim.

The caller must already hold the business SQLite write transaction.  This
module reads durable admission and current D06/D11 state; it never creates a
claim or returns a platform handoff authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
import math

from ..authority_service.v2_contract import (
    ExecutionBindingV2, MutationReceiptV2,
    canonical_digest as authority_digest,
)
from ..runtime_contracts import NamespaceId
from ..runtime_contracts import CheckReceipt, QueryEpoch, canonical_digest
from ..domains.d08 import ActionIntent
from .dispatch_admission import load_request
from .dispatch_current_commitments import CurrentD08ActionConflictEvidenceV1
from .dispatch_current_projection import CurrentDispatchProjectionV1
from .dispatch_current_segment import CurrentDispatchSegmentV1
from .dispatch_current_social_checks import CurrentSocialChecksV1
from .dispatch_current_source_budget import (
    CurrentDispatchHold, read_current_source_budget,
)


@dataclass(frozen=True, slots=True)
class FinalClaimPrerequisiteHoldV1:
    """Recovery identity and checked durable subset; status is always HOLD."""

    status: str
    handoff_id: str
    admission_ref: str
    operation_id: str
    effect_id: str
    binding_digest: str
    claimed_receipt_digest: str
    candidate_digest: str
    source_proof_digest: str
    budget_reservation_digest: str
    missing_guards: tuple[str, ...]
    check_receipts: tuple[CheckReceipt, ...] = ()
    batch_digest: str = ""


@dataclass(frozen=True, slots=True)
class FinalClaimEvidenceHoldV1:
    """Correlated same-P2 facts; this object has no authorization semantics."""

    status: str
    handoff_id: str
    admission_ref: str
    operation_id: str
    effect_id: str
    binding_digest: str
    claimed_receipt_digest: str
    graph_query_epoch: QueryEpoch
    checked_kinds: tuple[str, ...]
    evidence_digest: str
    missing_guards: tuple[str, ...]


_MISSING_GUARDS = (
    "current_p2_authority_permit_and_journal_chain",
    "current_owner_role_scene_and_d03_d05_checks",
    "current_d08_execution_effect_and_cancellation",
    "current_d08_d09_required_checks_and_route",
    "current_d10_contact_and_full_d11_journal_constraints",
    "same_p2_graph_claim_and_recovery_stamp",
)


def _authority_digest(raw_digest: str) -> str:
    """Authority V2 writes `sha256:`; business D11 stores the 64 hex bytes."""
    return "sha256:" + raw_digest


def _authority_namespace(namespace: NamespaceId) -> str:
    # Imported at call time because GraphCoordinator imports this module for
    # its private prerequisite callback.
    from ..graph_coordinator import namespace_ref

    return namespace_ref(namespace)


def read_final_claim_prerequisite(
    db, namespace: NamespaceId, binding: ExecutionBindingV2,
    claimed_receipt: MutationReceiptV2, handoff_id: str, *, now_utc: float,
) -> FinalClaimPrerequisiteHoldV1:
    """Bind the original P0/claimed P2 DTOs to committed D11 rows.

    Equality of Authority DTOs is only an identity check.  Their live permit,
    journal and domain facts still require trusted current reads before a claim.
    """
    if not db.in_transaction:
        raise CurrentDispatchHold("final claim prerequisite needs a held business transaction")
    if (type(namespace) is not NamespaceId or type(binding) is not ExecutionBindingV2
            or type(claimed_receipt) is not MutationReceiptV2
            or type(handoff_id) is not str or not handoff_id
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        raise CurrentDispatchHold("final claim prerequisite identity is invalid")
    pending = claimed_receipt.pending
    prepared = pending.prepared_receipt
    if (claimed_receipt.durable_state != "committed" or pending.phase != "claimed"
            or pending.binding != binding or prepared is None
            or prepared.durable_state != "committed"
            or prepared.pending.phase != "prepared"
            or pending.permit.token != binding.permit.token
            or pending.permit.fence_epoch != binding.permit.fence_epoch
            or pending.permit.revision != binding.permit.revision + 1
            or claimed_receipt.updated_revision != binding.permit.revision + 2
            or binding.namespace != _authority_namespace(namespace)
            or binding.graph_namespace != "/".join(namespace.as_tuple)):
        raise CurrentDispatchHold("claim does not continue the original dispatch P0")
    loaded = load_request(db, namespace, binding.origin.admission_ref)
    if loaded is None:
        raise CurrentDispatchHold("durable admission and command are absent")
    receipt, request = loaded
    admission = receipt.admission
    expected_binding = (
        binding.graph_namespace, binding.graph_incarnation,
        binding.admission_receipt_digest, binding.admission_graph_version,
        binding.admission_graph_epoch, binding.admission_access_epoch,
        binding.admission_deletion_epoch, binding.action_intent_digest,
        binding.action_intent_schema_version, binding.action_schema_digest,
        binding.action_schema_version, binding.required_checks_digest,
        binding.required_checks_schema_version,
        binding.initial_check_evidence_digest, binding.utc_deadline,
        binding.clock_policy_ref, binding.clock_policy_digest,
    )
    stored_binding = (
        admission.namespace, admission.graph_incarnation,
        _authority_digest(receipt.receipt_digest),
        receipt.graph_version, receipt.graph_epoch, admission.access_epoch,
        admission.delete_epoch, _authority_digest(admission.action_intent_digest),
        admission.action_intent_schema_version,
        _authority_digest(admission.action_schema_digest),
        admission.action_schema_version,
        _authority_digest(admission.required_checks_digest),
        admission.required_checks_schema_version,
        _authority_digest(admission.initial_check_evidence_digest),
        admission.utc_deadline, admission.clock_policy_ref,
        _authority_digest(admission.clock_policy_digest),
    )
    origin = binding.origin
    expected_command = (
        binding.graph_namespace, origin.operation_id, origin.activity_id,
        origin.effect_id, origin.attempt_id, origin.payload_digest,
        origin.platform_capability_ref, origin.verified_check_refs,
        origin.dispatch_generation,
        origin.activation_generation, origin.worker_fence,
        origin.content_fence, origin.cancel_epoch,
        replace(origin.footprint, namespace=binding.graph_namespace),
        origin.proactive_contact, origin.segment_authorization_ref,
        origin.segment_manifest_digest, origin.segment_index,
        origin.segment_count, origin.contact_policy_check_ref,
    )
    stored_command = (
        request.namespace, request.operation_id, request.activity_id,
        request.effect_id, request.attempt_id,
        _authority_digest(request.payload_digest),
        request.platform_capability_ref, request.required_check_refs,
        request.dispatch_generation,
        request.activation_generation, request.worker_fence,
        request.content_fence, request.cancel_epoch, request.footprint,
        request.proactive_contact, request.segment_authorization_ref,
        (_authority_digest(request.segment_manifest_digest)
         if request.segment_manifest_digest is not None else None),
        request.segment_index,
        request.segment_count, request.contact_policy_check_ref,
    )
    if (expected_binding != stored_binding or expected_command != stored_command
            or origin.account_ref != admission.account_ref
            or origin.destination_ref != admission.destination_ref
            or origin.admission_ref != admission.admission_ref
            or origin.permit.command_digest != _authority_digest(request.command_digest)
            or origin.permit.generation != admission.dispatch_generation
            or origin.permit.effect_id != admission.effect_id
            or origin.permit.operation_id != admission.operation_id):
        raise CurrentDispatchHold("binding differs from committed dispatch admission")
    # Check the UTC deadline independently of the durable source/budget subset.
    deadline = datetime.fromisoformat(admission.utc_deadline.replace("Z", "+00:00"))
    if now_utc >= deadline.timestamp():
        raise CurrentDispatchHold("dispatch admission expired")
    current = read_current_source_budget(
        db, namespace, admission.admission_ref, now_utc=now_utc,
    )
    return FinalClaimPrerequisiteHoldV1(
        "hold", handoff_id, admission.admission_ref, admission.operation_id,
        admission.effect_id, authority_digest(binding),
        authority_digest(claimed_receipt), current.candidate_digest,
        current.source_proof_digest, current.budget_reservation_digest,
        _MISSING_GUARDS, admission.check_receipts, admission.batch_digest,
    )


def assemble_final_claim_evidence(
    namespace: NamespaceId, binding: ExecutionBindingV2,
    claimed_receipt: MutationReceiptV2,
    prerequisite: FinalClaimPrerequisiteHoldV1,
    query: QueryEpoch, intent: ActionIntent,
    projection: CurrentDispatchProjectionV1,
    social: CurrentSocialChecksV1,
    action: CurrentD08ActionConflictEvidenceV1,
    segment: CurrentDispatchSegmentV1, *, now_utc: float,
) -> FinalClaimEvidenceHoldV1:
    """Correlate current reader results after the durable prerequisite read.

    The coordinator must call the readers under one held graph write fence.
    These DTOs cannot attest that call provenance, the live Authority P2, or
    the missing Owner/host/D10 authorities. Consequently this function can
    only reject inconsistent evidence or return HOLD for a later trusted claim.
    """
    if (type(namespace) is not NamespaceId
            or type(binding) is not ExecutionBindingV2
            or type(claimed_receipt) is not MutationReceiptV2
            or type(prerequisite) is not FinalClaimPrerequisiteHoldV1
            or type(query) is not QueryEpoch
            or type(intent) is not ActionIntent
            or type(projection) is not CurrentDispatchProjectionV1
            or type(social) is not CurrentSocialChecksV1
            or type(action) is not CurrentD08ActionConflictEvidenceV1
            or type(segment) is not CurrentDispatchSegmentV1
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        raise CurrentDispatchHold("final claim needs typed current evidence")
    if (prerequisite.status != "hold"
            or prerequisite.binding_digest != authority_digest(binding)
            or prerequisite.claimed_receipt_digest != authority_digest(claimed_receipt)
            or prerequisite.admission_ref != binding.origin.admission_ref
            or prerequisite.operation_id != binding.operation_id
            or prerequisite.effect_id != binding.origin.effect_id
            or claimed_receipt.pending.binding != binding
            or claimed_receipt.pending.phase != "claimed"
            or claimed_receipt.durable_state != "committed"
            or claimed_receipt.pending.prepared_receipt is None
            or claimed_receipt.pending.prepared_receipt.durable_state != "committed"
            or binding.namespace != _authority_namespace(namespace)
            or binding.graph_namespace != "/".join(namespace.as_tuple)):
        raise CurrentDispatchHold("final claim P0/P2 or admission identity differs")
    identity = intent.identity
    if (query != QueryEpoch(namespace, "all", projection.graph_epoch)
            or projection.namespace != namespace
            or action.graph_query_epoch != QueryEpoch(namespace, "d08.conflict_graph", query.revision)
            or segment.graph_epoch != query.revision
            or segment.admission_ref != prerequisite.admission_ref
            or (segment.operation_id, segment.effect_id)
            != (prerequisite.operation_id, prerequisite.effect_id)
            or (identity.operation_id, identity.effect_id, identity.activity_id,
                identity.attempt_id) != (
                    prerequisite.operation_id, prerequisite.effect_id,
                    binding.origin.activity_id, binding.origin.attempt_id)
            or intent.action_id != action.action_id
            or (action.operation_id, action.effect_id)
            != (prerequisite.operation_id, prerequisite.effect_id)
            or "sha256:" + canonical_digest(intent) != binding.action_intent_digest
            or segment.payload_digest != binding.origin.payload_digest.removeprefix("sha256:")
            or segment.batch_digest != prerequisite.batch_digest
            or action.authority_effect.effect_id != prerequisite.effect_id
            or action.authority_effect.execution_head_seq != claimed_receipt.after_anchor.execution_seq
            or action.authority_effect.execution_head_digest != claimed_receipt.after_anchor.execution_digest):
        raise CurrentDispatchHold("final claim graph epoch or action identity differs")
    specs = intent.required_checks
    receipts = prerequisite.check_receipts
    if (not specs or len(specs) != len(receipts)
            or len({item.check_kind for item in specs}) != len(specs)
            or len({item.check_kind for item in receipts}) != len(receipts)):
        raise CurrentDispatchHold("final claim required check coverage is incomplete")
    by_kind = {item.check_kind: item for item in receipts}
    if set(by_kind) != {item.check_kind for item in specs}:
        raise CurrentDispatchHold("final claim required check kinds differ")
    for spec in specs:
        receipt = by_kind[spec.check_kind]
        if (type(receipt) is not CheckReceipt
                or (receipt.issuer, receipt.subject_ref, receipt.action_ref,
                    receipt.purpose, receipt.input_versions)
                != (spec.provider_id, spec.subject_ref, spec.action_ref,
                    spec.purpose, spec.required_input_versions)
                or receipt.result != "pass" or receipt.coverage != "full"
                or receipt.valid_until < now_utc):
            raise CurrentDispatchHold("final claim required check is stale or partial")
    missing = list(prerequisite.missing_guards)
    if projection.coverage != "full" or projection.missing_sources:
        missing.extend(projection.missing_sources or ("current_social_projection_partial",))
    if social.status != "verified" or social.verified is not True:
        missing.append("current_d03_d05_checks_unverified")
    if action.status != "hold" or action.effect_state != "unresolved":
        missing.append("current_d08_effect_unresolved_unverified")
    missing.extend(action.missing_sources)
    missing.extend(segment.missing_sources)
    # An arbitrary DTO (including a forged verified=True) cannot certify the
    # provenance of current reads or replace the final Authority/graph CAS.
    missing.extend(("trusted_current_reader_provenance",
                    "complete_current_required_check_recomputation",
                    "current_p2_authority_effect_and_owner_route",
                    "same_p2_graph_claim_and_recovery_stamp"))
    evidence_digest = canonical_digest({
        "handoff_id": prerequisite.handoff_id,
        "admission_ref": prerequisite.admission_ref,
        "binding_digest": prerequisite.binding_digest,
        "claimed_receipt_digest": prerequisite.claimed_receipt_digest,
        "query_epoch": query,
        "action_intent_digest": canonical_digest(intent),
        "check_receipts_digest": canonical_digest(receipts),
        "projection_digest": projection.digest,
        "social_status": social.status,
        "social_verified": social.verified,
        "effect_state": action.effect_state,
        "effect_head_seq": action.authority_effect.execution_head_seq,
        "effect_head_digest": action.authority_effect.execution_head_digest,
        "job_id": action.job_id,
        "job_fence": action.job_fence,
        "job_cancel_epoch": action.job_cancel_epoch,
        "action_cancellation_state": action.action_cancellation_state,
        "action_job_binding_digest": action.action_job_binding_digest,
        "job_graph_version": action.job_graph_version,
        "segment_batch_ref": segment.batch_ref,
        "segment_batch_revision": segment.batch_revision,
        "segment_batch_digest": segment.batch_digest,
        "segment_payload_digest": segment.payload_digest,
        "segment_route_digest": segment.route_digest,
        "source_proof_digest": prerequisite.source_proof_digest,
        "budget_reservation_digest": prerequisite.budget_reservation_digest,
        "checked_kinds": tuple(sorted(by_kind)),
    })
    return FinalClaimEvidenceHoldV1(
        "hold", prerequisite.handoff_id, prerequisite.admission_ref,
        prerequisite.operation_id, prerequisite.effect_id,
        prerequisite.binding_digest, prerequisite.claimed_receipt_digest,
        query, tuple(sorted(by_kind)), evidence_digest,
        tuple(dict.fromkeys(missing)),
    )


__all__ = [
    "FinalClaimPrerequisiteHoldV1", "FinalClaimEvidenceHoldV1",
    "read_final_claim_prerequisite", "assemble_final_claim_evidence",
]
