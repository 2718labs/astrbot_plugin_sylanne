"""Non-authorizing D11 prerequisite for a future same-P2 graph claim.

The caller must already hold the business SQLite write transaction.  This
module reads durable admission and current D06/D11 state; it never creates a
claim or returns a platform handoff authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import math

from ..authority_service.v2_contract import (
    ExecutionBindingV2, MutationReceiptV2,
    canonical_digest as authority_digest,
)
from ..runtime_contracts import NamespaceId
from .dispatch_admission import load_request
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
            or binding.namespace != "/".join(namespace.as_tuple)):
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
        origin.namespace, origin.operation_id, origin.activity_id,
        origin.effect_id, origin.attempt_id, origin.payload_digest,
        origin.platform_capability_ref, origin.verified_check_refs,
        origin.dispatch_generation,
        origin.activation_generation, origin.worker_fence,
        origin.content_fence, origin.cancel_epoch, origin.footprint,
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
        _MISSING_GUARDS,
    )


__all__ = ["FinalClaimPrerequisiteHoldV1", "read_final_claim_prerequisite"]
