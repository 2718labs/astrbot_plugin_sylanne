"""Contract-only examples; no test here asserts live service authorization."""

from dataclasses import FrozenInstanceError, replace
import hashlib
import json

import pytest

from sylanne3.authority_service.v2_contract import (
    ExecutionBindingV1, FencePermitV2, MutationReceiptV2, PendingMutationV2,
    PlatformObservationV1, SCHEMA,
    canonical_bytes, canonical_digest, decode_bytes, from_wire, to_wire,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_journal import (
    BudgetConstraint, QuotaOccupancy, RecoveryConstraintFootprint,
    ReservationConstraint,
)


def digest(char: str) -> str:
    return "sha256:" + char * 64


def anchor(*, execution_seq: int = 0, execution_digest: str = "genesis",
           namespace: str = "ns-a", authority_id: str = "authority-a") -> RestoreAnchor:
    return RestoreAnchor(
        authority_id=authority_id, namespace=namespace, activation_generation=2,
        deletion_journal_id="delete-a", deletion_seq=0, deletion_digest="genesis",
        execution_journal_id="execution-a", execution_seq=execution_seq,
        execution_digest=execution_digest, revocation_epoch=1, proof="opaque-proof-a",
    )


def permit(*, operation: str = "dispatch", pinned_anchor=None, **changes) -> FencePermitV2:
    fields = dict(
        authority_id="authority-a", namespace="ns-a", subject="subject-a",
        holder="holder-a", generation=2, operation=operation,
        operation_id="operation-a", token="A" * 43,
        fence_epoch=3, revision=4, pinned_anchor=pinned_anchor or anchor(),
        effect_id="effect-a" if operation == "dispatch" else None,
        command_digest=digest("a") if operation == "dispatch" else None,
        footprint_digest=digest("b") if operation == "dispatch" else None,
    )
    fields.update(changes)
    return FencePermitV2(**fields)


def pending(**changes) -> PendingMutationV2:
    fields = dict(
        permit=permit(), mutation_id="mutation-a", request_digest=digest("c"),
        phase="prepared", before_anchor=anchor(), expected_append_id="entry-a",
        expected_append_digest=digest("d"),
    )
    fields.update(changes)
    return PendingMutationV2(**fields)


def test_canonical_round_trip_and_durable_receipt() -> None:
    original = pending()
    assert canonical_digest(original) == "sha256:24ca83d7a6ddd2b0ca605c95c626c56aeecac9a4653c37388069ea29b4be87af"
    committed = MutationReceiptV2(
        pending=original, after_anchor=anchor(execution_seq=1, execution_digest=digest("d")),
        updated_revision=5, durable_state="committed",
    )
    for dto in (permit(), original, committed):
        encoded = canonical_bytes(dto)
        assert decode_bytes(encoded) == dto
        assert encoded == json.dumps(to_wire(dto), sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()
        assert canonical_digest(dto).startswith("sha256:")
        assert len(canonical_digest(dto)) == 71
    assert original.expected_execution_seq == 1
    assert original.expected_execution_journal_id == "execution-a"
    assert MutationReceiptV2(
        pending=original, after_anchor=anchor(), updated_revision=5,
        durable_state="cancelled_unappended",
    ).durable_state == "cancelled_unappended"
    with pytest.raises(FrozenInstanceError):
        original.mutation_id = "new-id"


@pytest.mark.parametrize("changes", [
    {"generation": True}, {"fence_epoch": 1.0}, {"revision": False},
    {"token": "short"}, {"operation": "unknown"},
    {"command_digest": "sha256:ABC"}, {"footprint_digest": "genesis"},
    {"effect_id": "operation-a"}, {"namespace": "ns-b"},
    {"authority_id": "authority-b"}, {"pinned_anchor": anchor(execution_seq=1)},
])
def test_fence_rejects_invalid_or_unbound_fields(changes) -> None:
    with pytest.raises(ValueError):
        permit(**changes)


def test_read_fence_forbids_dispatch_binding() -> None:
    assert permit(operation="read").effect_id is None
    with pytest.raises(ValueError):
        permit(operation="read", effect_id="effect-a")


@pytest.mark.parametrize("changes", [
    {"mutation_id": "effect-a"}, {"expected_append_id": "mutation-a"},
    {"request_digest": "NaN"}, {"expected_append_digest": "genesis"},
    {"phase": "future-phase"}, {"before_anchor": anchor(namespace="ns-b")},
    {"permit": permit(operation="read")},
])
def test_pending_rejects_conflict_or_unpinned_head(changes) -> None:
    with pytest.raises(ValueError):
        pending(**changes)


@pytest.mark.parametrize("changes", [
    {"updated_revision": True}, {"updated_revision": 6},
    {"durable_state": "unknown"},
    {"after_anchor": anchor(execution_seq=1, execution_digest=digest("e"))},
    {"after_anchor": anchor(namespace="ns-b")},
    {"after_anchor": anchor(authority_id="authority-b")},
])
def test_receipt_rejects_unrelated_or_wrong_append(changes) -> None:
    fields = dict(
        pending=pending(), after_anchor=anchor(execution_seq=1, execution_digest=digest("d")),
        updated_revision=5, durable_state="committed",
    )
    fields.update(changes)
    with pytest.raises(ValueError):
        MutationReceiptV2(**fields)


def test_receipt_rejects_cancel_after_append_and_deletion_change() -> None:
    with pytest.raises(ValueError):
        MutationReceiptV2(pending(), anchor(execution_seq=1, execution_digest=digest("d")),
                          5, "cancelled_unappended")
    altered = replace(anchor(execution_seq=1, execution_digest=digest("d")),
                      deletion_seq=1, deletion_digest=digest("e"))
    with pytest.raises(ValueError):
        MutationReceiptV2(pending(), altered, 5, "committed")


def test_wire_rejects_unknown_schema_fields_kind_and_duplicate_json_fields() -> None:
    wire = to_wire(permit())
    for edited in (
        {**wire, "schema": "sylanne3.authority.v1"},
        {**wire, "kind": "other"},
        {**wire, "extra": 1},
        {key: value for key, value in wire.items() if key != "holder"},
        {**wire, "pinned_anchor": {**wire["pinned_anchor"], "extra": 1}},
        {**wire, "pinned_anchor": {**wire["pinned_anchor"], "execution_digest": digest("A")}},
    ):
        with pytest.raises(ValueError):
            from_wire(edited)
    with pytest.raises(ValueError, match="duplicate"):
        decode_bytes(b'{"schema":"sylanne3.authority.v2","schema":"sylanne3.authority.v2"}')
    with pytest.raises(ValueError):
        decode_bytes(canonical_bytes(permit()).replace(b'"revision":4', b'"revision":NaN'))
    with pytest.raises(ValueError):
        from_wire({**to_wire(pending()), "permit": to_wire(pending())})
    assert SCHEMA == "sylanne3.authority.v2"


def binding(*, contact: bool = False, **changes) -> ExecutionBindingV1:
    footprint = RecoveryConstraintFootprint(
        namespace="ns-a", activity_id="activity-a", effect_id="effect-a",
        external_idempotency_ref="idempotency-a", external_query_ref="query-a",
        conflict_keys=("conflict-a",),
        communication_action="reply" if contact else None,
        contact_id="contact-a" if contact else None,
        segment_id="segment-a" if contact else None,
        object_gate_keys=("gate-a",) if contact else (),
        quota_occupancies=(QuotaOccupancy("bucket-a", "window-a", 1),) if contact else (),
        reservations=(ReservationConstraint("reservation-a", "component-a", "3.25"),),
        budgets=(BudgetConstraint("budget-a", "2", "1.5", "10"),),
    )
    fence = permit(footprint_digest="sha256:" + hashlib.sha256(
        footprint._json().encode()).hexdigest())
    fields = dict(
        permit=fence, namespace="ns-a", activity_id="activity-a",
        effect_id="effect-a", attempt_id="attempt-a", operation_id="operation-a",
        dispatch_generation=7, activation_generation=2, admission_ref="admission-a",
        verified_check_refs=("policy-check-a",) if contact else ("core-check-a",),
        payload_digest=digest("e"), platform_capability_ref="capability-a",
        adapter_ref="adapter-a", account_ref="account-a", destination_ref="destination-a",
        worker_fence=8, content_fence="content-fence-a", cancel_epoch=0,
        footprint=footprint, proactive_contact=contact,
        segment_authorization_ref="segment-auth-a" if contact else None,
        segment_manifest_digest=digest("f") if contact else None,
        segment_index=0 if contact else None, segment_count=2 if contact else None,
        contact_policy_check_ref="policy-check-a" if contact else None,
    )
    fields.update(changes)
    return ExecutionBindingV1(**fields)


def observation(**changes) -> PlatformObservationV1:
    fields = dict(
        binding=binding(), handoff_start_ref="handoff-a", adapter_ref="adapter-a",
        account_ref="account-a", destination_ref="destination-a",
        observation_id="observation-a", platform_request_id=None,
        platform_message_id=None, evidence_source_ref="adapter-evidence-a",
        outcome="unknown", status_code_summary=None,
        observed_at_utc="2026-09-24T01:02:03Z", time_source_ref="clock-a",
    )
    fields.update(changes)
    return PlatformObservationV1(**fields)


def test_execution_binding_and_platform_observation_round_trip() -> None:
    for dto in (binding(), binding(contact=True), observation(),
                observation(outcome="delivered", platform_request_id="request-a",
                            platform_message_id="message-a", status_code_summary="200")):
        assert decode_bytes(canonical_bytes(dto)) == dto
        assert canonical_digest(dto) == "sha256:" + hashlib.sha256(
            canonical_bytes(dto)).hexdigest()
    assert to_wire(binding(contact=True))["footprint"]["budgets"] == [["budget-a", "2", "1.5", "10"]]


@pytest.mark.parametrize("changes", [
    {"namespace": "ns-b"}, {"activity_id": "activity-b"},
    {"effect_id": "effect-b"}, {"operation_id": "operation-b"},
    {"activation_generation": 3}, {"dispatch_generation": True},
    {"payload_digest": "genesis"}, {"footprint": RecoveryConstraintFootprint(
        "ns-a", "activity-a", "effect-b")},
    {"verified_check_refs": ()}, {"verified_check_refs": ("check-a", "check-a")},
    {"permit": permit(operation="read")},
    {"segment_authorization_ref": "segment-auth-a"},
    {"proactive_contact": True},
])
def test_execution_binding_rejects_identity_and_scope_conflicts(changes) -> None:
    with pytest.raises(ValueError):
        binding(**changes)


@pytest.mark.parametrize("changes", [
    {"adapter_ref": "adapter-b"}, {"account_ref": "account-b"},
    {"destination_ref": "destination-b"}, {"outcome": "failed"},
    {"observation_id": "handoff-a"}, {"platform_request_id": ""},
    {"observed_at_utc": "2026-02-30T01:02:03Z"},
    {"time_source_ref": ""},
])
def test_platform_observation_rejects_unbound_or_invalid_evidence(changes) -> None:
    with pytest.raises(ValueError):
        observation(**changes)


def test_new_wire_rejects_unknown_and_malformed_nested_footprint() -> None:
    wire = to_wire(binding(contact=True))
    for edited in (
        {**wire, "extra": 1},
        {**wire, "footprint": {**wire["footprint"], "extra": 1}},
        {**wire, "footprint": {**wire["footprint"], "quota_occupancies": [["bucket-a", "window-a", True]]}},
        {**wire, "footprint": {**wire["footprint"], "activity_id": "activity-b"}},
        {**wire, "verified_check_refs": ("policy-check-a",)},
        {**wire, "permit": to_wire(pending())},
    ):
        with pytest.raises(ValueError):
            from_wire(edited)
    observed = to_wire(observation())
    for edited in ({**observed, "extra": 1}, {**observed, "binding": to_wire(permit())},
                   {**observed, "platform_request_id": []}):
        with pytest.raises(ValueError):
            from_wire(edited)
