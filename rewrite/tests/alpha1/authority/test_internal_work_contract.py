"""C04 work IDs survive retry while unknown remains an unknown cost."""

from dataclasses import replace
import hashlib

import pytest

from sylanne3.authority_service.contract import JournalHead
from sylanne3.authority_service.internal_work_contract import (
    InternalWorkBindingV1, InternalWorkTerminalProofV1,
    claim_internal_work_v1, terminal_internal_work_v1,
    validate_internal_work_terminal_proof_v1,
)
from sylanne3.contracts import canonical_json
from sylanne3.graph_types import AtomKey, Owner


NAMESPACE = "ns:sha256:" + hashlib.sha256(
    canonical_json(["bot", "persona"]).encode("utf-8")
).hexdigest()
RESERVATION = AtomKey(
    Owner("activity", "bot", "persona", "activity-1"),
    "d02.reservation.v1", "body-reservation-1",
).token


def binding() -> InternalWorkBindingV1:
    return InternalWorkBindingV1(
        namespace=NAMESPACE, activity_id="activity-1",
        operation_id="operation-1", execution_id="execution-1",
        input_digest="a" * 64,
        resource_quote_ref="resource-quote-1", resource_quote_version=3,
        resource_quote_digest="b" * 64,
        body_quote_ref="body-quote-1", body_quote_version=4,
        body_quote_digest="c" * 64,
        body_reservation_ref=RESERVATION, component_id="cpu-action",
        parent_budget_lease_ref="budget-1", activation_generation=5,
        algorithm_ref="association-v1", policy_ref="policy-v1",
    )


def test_claim_terminal_and_independent_reread_locator_bind_one_original():
    original = binding()
    claim = claim_internal_work_v1(original)
    assert claim == claim_internal_work_v1(original)
    completed = terminal_internal_work_v1(
        original, claim, status="completed", actual_cpu_ms=13,
        result_digest="d" * 64, component_receipt_ref="component-receipt-1",
        component_receipt_digest="e" * 64)
    replay = terminal_internal_work_v1(
        original, claim, status="completed", actual_cpu_ms=13,
        result_digest="d" * 64, component_receipt_ref="component-receipt-1",
        component_receipt_digest="e" * 64)
    assert completed == replay
    assert completed.terminal_digest == replay.terminal_digest
    assert not completed.component_completed  # Legacy caller ref is not trusted.
    proof = InternalWorkTerminalProofV1(
        original, claim, completed, "claim-receipt-1", "f" * 64,
        "terminal-receipt-1", "1" * 64,
        JournalHead("internal-work-journal-1", 2, "sha256:" + "2" * 64))
    validate_internal_work_terminal_proof_v1(proof, expected_binding=original)
    assert "platform" not in InternalWorkBindingV1.__dataclass_fields__
    assert "dispatch" not in InternalWorkBindingV1.__dataclass_fields__

    for changed in (
        replace(original, input_digest="3" * 64),
        replace(original, resource_quote_digest="4" * 64),
        replace(original, body_quote_version=5),
        replace(original, parent_budget_lease_ref="budget-2"),
        replace(original, activation_generation=6),
    ):
        with pytest.raises(ValueError, match="binding differs"):
            validate_internal_work_terminal_proof_v1(proof, expected_binding=changed)
    with pytest.raises(ValueError, match="body_reservation_ref"):
        replace(original, namespace="ns:sha256:" + "0" * 64)


def test_unknown_never_means_zero_and_conflicting_terminal_keeps_same_mutation_id():
    original = binding()
    claim = claim_internal_work_v1(original)
    unknown = terminal_internal_work_v1(original, claim, status="unknown")
    failed = terminal_internal_work_v1(
        original, claim, status="failed", actual_cpu_ms=0)
    assert unknown.actual_cpu_ms is None
    assert not unknown.component_completed
    assert failed.actual_cpu_ms == 0
    assert unknown.mutation_id == failed.mutation_id
    assert unknown.terminal_digest != failed.terminal_digest
    with pytest.raises(ValueError, match="unknown work"):
        terminal_internal_work_v1(original, claim, status="unknown", actual_cpu_ms=0)
    with pytest.raises(ValueError, match="unknown work"):
        terminal_internal_work_v1(
            original, claim, status="unknown", component_receipt_ref="receipt",
            component_receipt_digest="e" * 64)
    with pytest.raises(ValueError, match="result_digest"):
        terminal_internal_work_v1(
            original, claim, status="completed", actual_cpu_ms=0)
    with pytest.raises(ValueError, match="travel together"):
        terminal_internal_work_v1(
            original, claim, status="failed", actual_cpu_ms=2,
            component_receipt_ref="receipt")
    with pytest.raises(ValueError, match="original internal work claim"):
        terminal_internal_work_v1(
            replace(original, execution_id="execution-2"), claim,
            status="unknown")


def test_structural_proof_cannot_rebind_terminal_or_receipt():
    original = binding()
    claim = claim_internal_work_v1(original)
    terminal = terminal_internal_work_v1(
        original, claim, status="completed", actual_cpu_ms=7,
        result_digest="d" * 64)
    proof = InternalWorkTerminalProofV1(
        original, claim, terminal, "claim-receipt", "e" * 64,
        "terminal-receipt", "f" * 64,
        JournalHead("internal-work-journal", 2, "sha256:" + "1" * 64))
    other = replace(original, execution_id="execution-2")
    other_terminal = terminal_internal_work_v1(
        other, claim_internal_work_v1(other), status="completed",
        actual_cpu_ms=7, result_digest="d" * 64)
    with pytest.raises(ValueError, match="proof identity"):
        replace(proof, terminal=other_terminal)
    with pytest.raises(ValueError, match="SHA-256"):
        replace(proof, terminal_receipt_digest="not-a-digest")


def test_body_reservation_ref_requires_exact_canonical_d02_activity_owner():
    original = binding()
    assert original.body_reservation_ref == RESERVATION
    for invalid in (
        "body-reservation-1",
        " " + RESERVATION,
        AtomKey(Owner("activity", "other", "persona", "activity-1"),
                "d02.reservation.v1", "body-reservation-1").token,
        AtomKey(Owner("activity", "bot", "persona", "other-activity"),
                "d02.reservation.v1", "body-reservation-1").token,
        AtomKey(Owner("persona", "bot", "persona"),
                "d02.reservation.v1", "body-reservation-1").token,
        AtomKey(Owner("activity", "bot", "persona", "activity-1"),
                "d02.settlement.v1", "body-reservation-1").token,
    ):
        with pytest.raises(ValueError, match="body_reservation_ref"):
            replace(original, body_reservation_ref=invalid)
