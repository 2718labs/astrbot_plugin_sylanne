"""Contract-only examples; no test here asserts live service authorization."""

from dataclasses import FrozenInstanceError, replace
import json

import pytest

from sylanne3.authority_service.v2_contract import (
    FencePermitV2, MutationReceiptV2, PendingMutationV2, SCHEMA,
    canonical_bytes, canonical_digest, decode_bytes, from_wire, to_wire,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor


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
