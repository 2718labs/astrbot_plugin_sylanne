"""Tests for the non-authorizing D11 admission-to-binding projection."""

from dataclasses import replace
from datetime import datetime, timezone
import hashlib

import pytest

from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.dispatch_runtime import DispatchRequest
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.runtime.dispatch_admission import (
    DispatchAdmissionReceiptV1,
    DispatchAdmissionV1,
)
from sylanne3.runtime.dispatch_binding_v2 import (
    authority_dispatch_footprint_v2, build_non_authorizing_execution_binding_v2,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import CheckReceipt, NamespaceId, canonical_digest
from sylanne3.runtime_journal import (
    BudgetConstraint,
    RecoveryConstraintFootprint,
)


NOW = datetime(2026, 9, 26, tzinfo=timezone.utc).timestamp()
NAMESPACE = NamespaceId("bot", "persona")


def _fixture():
    namespace = "bot/persona"
    footprint = RecoveryConstraintFootprint(
        namespace, "activity:one", "effect:one",
        communication_action="message:one",
        contact_id="contact:one",
        segment_id="segment:one",
        budgets=(BudgetConstraint("lease:parent", "0", "1", "1"),),
    )
    request = DispatchRequest(
        namespace=namespace,
        operation_id="operation:one",
        activity_id="activity:one",
        effect_id="effect:one",
        attempt_id="attempt:one",
        command_digest="a" * 64,
        payload_ref="payload:one",
        payload_digest="b" * 64,
        platform_capability_ref="platform:one",
        required_check_refs=("check:one",),
        dispatch_generation=4,
        activation_generation=3,
        worker_fence=5,
        content_fence="content:one",
        cancel_epoch=6,
        footprint=footprint,
        proactive_contact=False,
        segment_authorization_ref="segment-auth:one",
        segment_manifest_digest="9" * 64,
        segment_index=0,
        segment_count=1,
    )
    check = CheckReceipt(
        "owner", "subject:one", "action:one", "purpose:one", (),
        "full", "pass", datetime(2099, 1, 1, tzinfo=timezone.utc).timestamp(),
        "issuer:one",
    )
    admission = DispatchAdmissionV1(
        namespace=namespace,
        graph_incarnation="incarnation:one",
        activity_id=request.activity_id,
        effect_id=request.effect_id,
        attempt_id=request.attempt_id,
        operation_id=request.operation_id,
        dispatch_generation=request.dispatch_generation,
        admission_ref="admission:one",
        candidate_digest="c" * 64,
        request_digest=canonical_digest(request),
        action_intent_digest="d" * 64,
        action_intent_schema_version="intent:v1",
        action_schema_digest="e" * 64,
        action_schema_version="action:v1",
        required_checks_digest="f" * 64,
        required_checks_schema_version="checks:v1",
        grant_digest="1" * 64,
        batch_digest="2" * 64,
        segment_index=0,
        payload_digest=request.payload_digest,
        account_ref="account:one",
        destination_ref="destination:one",
        scene_ref="scene:one",
        owner_head_ref="owner:one",
        role_ref="role:one",
        binding_ref="binding:one",
        object_ref="object:one",
        action_ref="action:one",
        purpose="purpose:one",
        audience=("audience:one",),
        graph_reads=(("source:one", 1),),
        query_epoch=1,
        access_epoch=2,
        delete_epoch=3,
        check_receipts=(check,),
        budget_parent_lease_ref="lease:parent",
        budget_lease_ref="lease:parent",
        budget_reservation_operation_id=request.operation_id,
        budget_reservation_digest="3" * 64,
        budget_ceiling={"unit": 1},
        budget_currency="USD",
        budget_version=1,
        contact_reservation_ref=None,
        utc_deadline="2099-01-01T00:00:00Z",
        clock_policy_ref="clock:one",
        clock_policy_digest="4" * 64,
    )
    receipt_digest = canonical_digest({
        "admission_digest": admission.digest,
        "graph_revision": 8,
        "graph_epoch": 9,
    })
    receipt = DispatchAdmissionReceiptV1(admission, 8, 9, receipt_digest)
    opaque_namespace = namespace_ref(NAMESPACE)
    authority_footprint = authority_dispatch_footprint_v2(NAMESPACE, request)
    anchor = RestoreAnchor(
        authority_id="authority:one", namespace=opaque_namespace,
        activation_generation=request.activation_generation,
        deletion_journal_id="deletion-journal:one", deletion_seq=1,
        deletion_digest="sha256:" + "5" * 64,
        execution_journal_id="execution-journal:one", execution_seq=2,
        execution_digest="sha256:" + "6" * 64, revocation_epoch=0,
        proof="proof:one",
    )
    footprint_digest = "sha256:" + hashlib.sha256(
        authority_footprint._json().encode("utf-8")
    ).hexdigest()
    permit = FencePermitV2(
        authority_id="authority:one", namespace=opaque_namespace,
        subject="subject:one", holder="holder:one",
        generation=request.activation_generation, operation="dispatch",
        operation_id=request.operation_id, token="T" * 32,
        fence_epoch=7, revision=10, pinned_anchor=anchor,
        effect_id=request.effect_id, command_digest="sha256:" + request.command_digest,
        footprint_digest=footprint_digest,
    )
    return receipt, request, permit


def test_matching_admission_request_and_original_permit_build_v2_identity():
    receipt, request, permit = _fixture()

    binding = build_non_authorizing_execution_binding_v2(
        namespace=NAMESPACE,
        admission_receipt=receipt,
        recovered_request=request,
        original_dispatch_permit=permit,
        adapter_ref="adapter:one",
        now_utc=NOW,
    )

    assert binding.origin.permit is permit
    assert binding.origin.operation_id == request.operation_id
    assert binding.origin.dispatch_generation == request.dispatch_generation
    assert binding.admission_receipt_digest == "sha256:" + receipt.receipt_digest
    assert binding.admission_graph_version == "graph:8"
    assert binding.initial_check_evidence_digest == (
        "sha256:" + receipt.admission.initial_check_evidence_digest
    )
    assert binding.origin.namespace == namespace_ref(NAMESPACE)
    assert binding.origin.footprint == authority_dispatch_footprint_v2(
        NAMESPACE, request)
    assert replace(binding.origin.footprint, namespace=request.namespace) == request.footprint
    assert binding.graph_namespace == request.namespace


def test_stale_permit_generation_is_rejected():
    receipt, request, permit = _fixture()
    stale_anchor = replace(
        permit.pinned_anchor,
        activation_generation=permit.generation - 1,
    )
    stale = replace(
        permit, generation=permit.generation - 1, pinned_anchor=stale_anchor,
    )

    with pytest.raises(ValueError, match="P0"):
        build_non_authorizing_execution_binding_v2(
            namespace=NAMESPACE,
            admission_receipt=receipt,
            recovered_request=request,
            original_dispatch_permit=stale,
            adapter_ref="adapter:one",
            now_utc=NOW,
        )


def test_admission_for_another_effect_is_rejected_even_with_valid_receipt_digest():
    receipt, request, permit = _fixture()
    altered = replace(receipt.admission, effect_id="effect:other")
    digest = canonical_digest({
        "admission_digest": altered.digest,
        "graph_revision": receipt.graph_revision,
        "graph_epoch": receipt.graph_epoch,
    })
    wrong_admission = DispatchAdmissionReceiptV1(
        altered, receipt.graph_revision, receipt.graph_epoch, digest,
    )

    with pytest.raises(ValueError, match="request"):
        build_non_authorizing_execution_binding_v2(
            namespace=NAMESPACE,
            admission_receipt=wrong_admission,
            recovered_request=request,
            original_dispatch_permit=permit,
            adapter_ref="adapter:one",
            now_utc=NOW,
        )


def test_opaque_p0_digest_and_ambiguous_or_wrong_business_namespace_hold():
    receipt, request, permit = _fixture()
    slash_footprint_digest = "sha256:" + hashlib.sha256(
        request.footprint._json().encode("utf-8")
    ).hexdigest()
    with pytest.raises(ValueError, match="P0"):
        build_non_authorizing_execution_binding_v2(
            namespace=NAMESPACE, admission_receipt=receipt,
            recovered_request=request,
            original_dispatch_permit=replace(
                permit, footprint_digest=slash_footprint_digest),
            adapter_ref="adapter:one", now_utc=NOW,
        )
    with pytest.raises(ValueError, match="ambiguous"):
        authority_dispatch_footprint_v2(NamespaceId("bot/a", "persona"), request)
    with pytest.raises(ValueError, match="trusted graph namespace"):
        authority_dispatch_footprint_v2(NamespaceId("other", "persona"), request)
