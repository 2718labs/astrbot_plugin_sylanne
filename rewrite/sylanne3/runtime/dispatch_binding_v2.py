"""Non-authorizing projection of committed dispatch identity into Binding V2.

This module does not establish that an admission came from a trusted graph
writer, that the graph remains current, or that a dispatch fence is current.
The Authority handoff path must independently verify those facts before it
uses the returned DTO. In particular, this factory never sends platform data.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import math

from ..authority_service.v2_contract import (
    ExecutionBindingV1,
    ExecutionBindingV2,
    FencePermitV2,
)
from ..dispatch_runtime import DispatchRequest
from ..graph_coordinator import namespace_ref
from .dispatch_admission import DispatchAdmissionReceiptV1, _request_matches
from ..runtime_contracts import NamespaceId, canonical_digest
from ..runtime_journal import RecoveryConstraintFootprint


def _footprint_digest(footprint: RecoveryConstraintFootprint) -> str:
    return "sha256:" + hashlib.sha256(
        footprint._json().encode("utf-8")
    ).hexdigest()


def authority_dispatch_footprint_v2(
        namespace: NamespaceId, request: DispatchRequest,
) -> RecoveryConstraintFootprint:
    """Map a trusted business namespace to P0's opaque Authority footprint."""
    if type(namespace) is not NamespaceId or type(request) is not DispatchRequest:
        raise TypeError("typed namespace and dispatch request are required")
    if "/" in namespace.bot_id or "/" in namespace.persona_id:
        raise ValueError("slash-delimited dispatch namespace is ambiguous")
    business_namespace = "/".join(namespace.as_tuple)
    if (request.namespace != business_namespace
            or request.footprint.namespace != business_namespace):
        raise ValueError("dispatch namespace differs from trusted graph namespace")
    return replace(request.footprint, namespace=namespace_ref(namespace))


def _authority_digest(value: str) -> str:
    """Authority DTO digests are explicitly tagged; runtime digests are raw hex."""
    if type(value) is not str or len(value) != 64:
        raise ValueError("runtime digest is not canonical SHA-256 hex")
    return "sha256:" + value


def _assert_budget_matches(admission, request: DispatchRequest) -> None:
    """Check the frozen request carries the admitted lease and finite ceiling."""
    if admission.budget_reservation_operation_id != request.operation_id:
        raise ValueError("budget reservation operation differs from dispatch")
    budgets = request.footprint.budgets
    matching = [item for item in budgets
                if item.parent_budget_ref == admission.budget_parent_lease_ref]
    if len(matching) != 1:
        raise ValueError("request footprint lacks the admitted parent budget")
    # Ceiling qualification depends on currency/component units and belongs to
    # the trusted D11 ledger. This projection checks only frozen identities.
    if admission.budget_lease_ref != admission.budget_parent_lease_ref:
        reservations = [item for item in request.footprint.reservations
                        if item.reservation_ref == admission.budget_lease_ref]
        if len(reservations) != 1 or reservations[0].component_ref != request.operation_id:
            raise ValueError("request footprint lacks the admitted budget reservation")


def build_non_authorizing_execution_binding_v2(
    *,
    namespace: NamespaceId,
    admission_receipt: DispatchAdmissionReceiptV1,
    recovered_request: DispatchRequest,
    original_dispatch_permit: FencePermitV2,
    adapter_ref: str,
    now_utc: float,
) -> ExecutionBindingV2:
    """Project exact persisted identities into a V2 DTO; this grants no authority.

    A parsed receipt is deliberately accepted only as data. The caller must
    obtain the receipt and request from the graph's trusted recovery boundary,
    and the Authority must verify current graph claim and fence state later.
    """
    if type(admission_receipt) is not DispatchAdmissionReceiptV1:
        raise TypeError("a typed dispatch admission receipt is required")
    if type(recovered_request) is not DispatchRequest:
        raise TypeError("the exact recovered dispatch request is required")
    if type(original_dispatch_permit) is not FencePermitV2:
        raise TypeError("the original typed dispatch permit P0 is required")
    if type(adapter_ref) is not str or not adapter_ref:
        raise ValueError("adapter_ref is required")
    if type(now_utc) not in (int, float) or not math.isfinite(now_utc):
        raise TypeError("now_utc must be a finite timestamp")

    admission = admission_receipt.admission
    request = recovered_request
    permit = original_dispatch_permit
    authority_footprint = authority_dispatch_footprint_v2(namespace, request)
    opaque_namespace = authority_footprint.namespace
    admission.require_current(float(now_utc))

    if admission.namespace != request.namespace:
        raise ValueError("admission namespace differs from trusted graph namespace")
    if not _request_matches(admission, request):
        raise ValueError("recovered request differs from committed admission")
    if canonical_digest(request) != admission.request_digest:
        raise ValueError("recovered request digest differs from admission")
    if (request.namespace, request.activity_id, request.effect_id,
            request.attempt_id, request.operation_id,
            request.dispatch_generation, request.payload_digest) != (
            admission.namespace, admission.activity_id, admission.effect_id,
            admission.attempt_id, admission.operation_id,
            admission.dispatch_generation, admission.payload_digest):
        raise ValueError("admission and recovered request identity differ")
    if (permit.operation != "dispatch"
            or permit.namespace != opaque_namespace
            or permit.effect_id != admission.effect_id
            or permit.operation_id != admission.operation_id
            or permit.generation != request.activation_generation
            or permit.command_digest != "sha256:" + request.command_digest
            or permit.footprint_digest != _footprint_digest(authority_footprint)):
        raise ValueError("P0 does not bind the exact request and admission")
    if len(request.required_check_refs) != len(admission.check_receipts):
        raise ValueError("request check refs do not cover the admitted check set")
    if any(receipt.result != "pass" or receipt.coverage != "full"
           or receipt.valid_until < float(now_utc)
           for receipt in admission.check_receipts):
        raise ValueError("admission contains incomplete or expired check evidence")
    _assert_budget_matches(admission, request)

    origin = ExecutionBindingV1(
        permit=permit,
        namespace=opaque_namespace,
        activity_id=request.activity_id,
        effect_id=request.effect_id,
        attempt_id=request.attempt_id,
        operation_id=request.operation_id,
        dispatch_generation=request.dispatch_generation,
        activation_generation=request.activation_generation,
        admission_ref=admission.admission_ref,
        verified_check_refs=request.required_check_refs,
        payload_digest=_authority_digest(request.payload_digest),
        platform_capability_ref=request.platform_capability_ref,
        adapter_ref=adapter_ref,
        account_ref=admission.account_ref,
        destination_ref=admission.destination_ref,
        worker_fence=request.worker_fence,
        content_fence=request.content_fence,
        cancel_epoch=request.cancel_epoch,
        footprint=authority_footprint,
        proactive_contact=request.proactive_contact,
        segment_authorization_ref=request.segment_authorization_ref,
        segment_manifest_digest=(
            _authority_digest(request.segment_manifest_digest)
            if request.segment_manifest_digest is not None else None
        ),
        segment_index=request.segment_index,
        segment_count=request.segment_count,
        contact_policy_check_ref=request.contact_policy_check_ref,
    )
    return ExecutionBindingV2(
        origin=origin,
        graph_namespace=admission.namespace,
        graph_incarnation=admission.graph_incarnation,
        admission_receipt_digest=_authority_digest(admission_receipt.receipt_digest),
        admission_graph_version=admission_receipt.graph_version,
        admission_graph_epoch=admission_receipt.graph_epoch,
        admission_access_epoch=admission.access_epoch,
        admission_deletion_epoch=admission.delete_epoch,
        action_intent_digest=_authority_digest(admission.action_intent_digest),
        action_intent_schema_version=admission.action_intent_schema_version,
        action_schema_digest=_authority_digest(admission.action_schema_digest),
        action_schema_version=admission.action_schema_version,
        required_checks_digest=_authority_digest(admission.required_checks_digest),
        required_checks_schema_version=admission.required_checks_schema_version,
        initial_check_evidence_digest=_authority_digest(
            admission.initial_check_evidence_digest),
        utc_deadline=admission.utc_deadline,
        clock_policy_ref=admission.clock_policy_ref,
        clock_policy_digest=_authority_digest(admission.clock_policy_digest),
    )


__all__ = [
    "authority_dispatch_footprint_v2", "build_non_authorizing_execution_binding_v2",
]
