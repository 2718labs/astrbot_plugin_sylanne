"""A resolved head is only a candidate until W01 verifies real receipts."""

from dataclasses import replace

import pytest

from rewrite.tests.alpha1.d06.test_source_correction_candidate import ADAPTER, setup
from sylanne3.domains.d06 import validate_source_correction_head
from sylanne3.domains.d06.source_correction_resolution import (
    ActualCorrectionCostV1, CorrectionJobOutboxSettlementV1,
    CurrentCorrectionSourceV1, ReevaluationReceiptRefV1,
    ResolvedSourceCorrectionHeadCandidateV1, SourceCorrectionResolutionHoldV1,
    compile_resolved_source_correction_head_v1,
    validate_resolved_source_correction_head_candidate_v1,
)


def _case():
    request, reads, envelope = setup()
    pending = ADAPTER.compile_source_correction(
        envelope, request, reads, recorded_at=5.0)
    head = pending.proposal.typed_writes[2]
    current = CurrentCorrectionSourceV1(
        head.value["source_ref"], head.value["source_revision"],
        head.value["correction_source_ref"], 1,
        head.value["access_epoch"], head.value["deletion_epoch"],
        "active", "active")
    receipts = tuple(ReevaluationReceiptRefV1(
        domain, f"{domain}-receipt-1", str(index) * 64,
        request.request_id, current.correction_source_ref)
        for index, domain in enumerate(("d04", "d05", "d07"), 1))
    cost = ActualCorrectionCostV1(
        "d02-cost-receipt-1", "4" * 64, request.request_id,
        "original-quote-1", 1, 10.0, (("cpu_ms", 2),))
    d11 = CorrectionJobOutboxSettlementV1(
        request.request_id, "job-1", "job-receipt-1", "5" * 64,
        "outbox-1", "outbox-receipt-1", "6" * 64)
    return dict(head_key=head.key, pending_head=head.value, pending_revision=1,
                current=current, reevaluations=receipts, cost=cost,
                d11=d11, now_utc=8.0)


def test_resolved_candidate_preserves_pending_barrier_until_w01_atomic_adoption():
    args = _case()
    candidate = compile_resolved_source_correction_head_v1(**args)
    assert type(candidate) is ResolvedSourceCorrectionHeadCandidateV1
    assert candidate.expected_head.revision == 1
    assert candidate.next_value["state"] == "resolved_reevaluation"
    assert candidate.next_value["source_ref"] == args["pending_head"]["source_ref"]
    assert candidate.next_value["target_refs"] == args["pending_head"]["target_refs"]
    assert candidate.next_value["resolution_proof_digest"] == candidate.proof_digest
    assert candidate.status == "requires_w01_atomic_receipt_verification"
    validate_resolved_source_correction_head_candidate_v1(
        candidate, pending_head=args["pending_head"], pending_revision=1)
    with pytest.raises(ValueError, match="fields differ"):
        validate_source_correction_head(candidate.head_key, candidate.next_value)
    assert args["pending_head"]["state"] == "pending_reevaluation"


def test_candidate_validator_rejects_tampered_next_value_or_stale_head_version():
    args = _case()
    candidate = compile_resolved_source_correction_head_v1(**args)
    tampered = replace(candidate, next_value={
        **candidate.next_value, "target_refs": []})
    with pytest.raises(ValueError, match="candidate differs"):
        validate_resolved_source_correction_head_candidate_v1(
            tampered, pending_head=args["pending_head"], pending_revision=1)
    with pytest.raises(ValueError, match="candidate differs"):
        validate_resolved_source_correction_head_candidate_v1(
            candidate, pending_head=args["pending_head"], pending_revision=2)


@pytest.mark.parametrize("change,reason", [
    ({"reevaluations": ()}, "reevaluation_receipts_incomplete"),
    ({"cost": None}, "actual_d02_cost_missing"),
    ({"d11": None}, "d11_settlement_missing"),
    ({"now_utc": 10.0}, "original_quote_expired_or_changed"),
])
def test_missing_receipt_or_expired_original_quote_holds(change, reason):
    args = _case() | change
    result = compile_resolved_source_correction_head_v1(**args)
    assert type(result) is SourceCorrectionResolutionHoldV1
    assert result.reason == reason


def test_stale_source_access_and_cross_operation_receipts_hold():
    args = _case()
    args["current"] = replace(args["current"], source_access_status="withdrawn")
    assert compile_resolved_source_correction_head_v1(
        **args).reason == "source_access_or_epoch_unavailable"
    args = _case()
    args["current"] = replace(args["current"], source_revision=2)
    assert compile_resolved_source_correction_head_v1(
        **args).reason == "current_source_identity_changed"
    args = _case()
    args["reevaluations"] = (replace(
        args["reevaluations"][0], correction_operation_id="other-correction"),
        *args["reevaluations"][1:])
    assert compile_resolved_source_correction_head_v1(
        **args).reason == "reevaluation_identity_changed"
    args = _case()
    args["d11"] = replace(args["d11"], correction_operation_id="other-correction")
    assert compile_resolved_source_correction_head_v1(
        **args).reason == "d11_settlement_identity_changed"


def test_no_implicit_zero_cost_or_deadline_extension():
    args = _case()
    with pytest.raises(ValueError, match="actual D02 settlement"):
        replace(args["cost"], actual_amounts=())
    with pytest.raises(ValueError, match="SHA-256"):
        replace(args["cost"], receipt_digest="unverified")
    expired = replace(args["cost"], quote_deadline_utc=7.0)
    args["cost"] = expired
    assert compile_resolved_source_correction_head_v1(
        **args).reason == "original_quote_expired_or_changed"
