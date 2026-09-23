"""Owner DTOs bind identities; these tests do not grant runtime authority."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json

import pytest

from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerAuthorizationReceiptV1, OwnerClaimTicketV1, OwnerPrincipalV1,
    canonical_bytes, canonical_digest, decode_bytes, from_wire, to_wire,
)
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "new-persona")
PRINCIPAL = OwnerPrincipalV1("astrbot-dashboard", "account-17", "incarnation-3")


def digest(character: str) -> str:
    return "sha256:" + character * 64


def ticket(**changes) -> OwnerClaimTicketV1:
    data = dict(
        authority_id="authority-a", installation_id="installation-a",
        namespace=NS, principal=PRINCIPAL, ticket_id="ticket-a",
        creation_operation_id="create-new-persona-a", creation_digest=digest("a"),
        policy_digest=digest("b"), challenge="C" * 43,
        expires_at_utc="2030-01-01T00:00:00Z",
    )
    data.update(changes)
    return OwnerClaimTicketV1(**data)


def guard(**changes) -> OwnerAuthorizationGuardV1:
    data = dict(
        authority_id="authority-a", installation_id="installation-a",
        namespace=NS, authorization_revision=0, authorization_head="genesis",
        minimum_revocation_revision=0, minimum_revocation_epoch=0,
    )
    data.update(changes)
    return OwnerAuthorizationGuardV1(**data)


def issue(**changes) -> OwnerAuthorizationOperationV1:
    data = dict(
        action="issue", operation_id="issue-a", authority_id="authority-a",
        installation_id="installation-a", namespace=NS, principal=PRINCIPAL,
        grant_id="grant-a", grant_digest=digest("c"),
        expected_grant_revision=0, expected_guard=guard(), ticket=ticket(),
    )
    data.update(changes)
    return OwnerAuthorizationOperationV1(**data)


def revoke(**changes) -> OwnerAuthorizationOperationV1:
    data = dict(
        action="revoke", operation_id="revoke-a", authority_id="authority-a",
        installation_id="installation-a", namespace=NS, principal=PRINCIPAL,
        grant_id="grant-a", grant_digest=digest("d"),
        expected_grant_revision=1,
        expected_guard=guard(authorization_revision=1,
                             authorization_head=digest("e")),
    )
    data.update(changes)
    return OwnerAuthorizationOperationV1(**data)


def test_owner_ticket_guard_operations_and_receipts_have_canonical_round_trip():
    claim = ticket()
    first = issue()
    issued = OwnerAuthorizationReceiptV1(
        first, "committed", "receipt-issue-a",
        guard(authorization_revision=1, authorization_head=digest("e")),
        grant_revision=1, graph_access_epoch=1,
    )
    removal = revoke()
    blocked = guard(authorization_revision=2, authorization_head=digest("f"),
                    minimum_revocation_revision=2, minimum_revocation_epoch=1,
                    pending_revoke_operation_id="revoke-a")
    pending = OwnerAuthorizationReceiptV1(
        removal, "pending", "receipt-revoke-pending-a", blocked)
    finished = OwnerAuthorizationReceiptV1(
        removal, "committed", "receipt-revoke-done-a",
        guard(authorization_revision=3, authorization_head=digest("1"),
              minimum_revocation_revision=3, minimum_revocation_epoch=1),
        grant_revision=2, graph_access_epoch=2,
    )
    for value in (PRINCIPAL, claim, guard(), first, issued, removal, blocked,
                  pending, finished):
        encoded = canonical_bytes(value)
        assert decode_bytes(encoded) == value
        assert encoded == json.dumps(to_wire(value), sort_keys=True,
                                     separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")
        assert canonical_digest(value).startswith("sha256:")
    assert first.request_digest != removal.request_digest
    assert "capabilities" not in to_wire(blocked)
    with pytest.raises(FrozenInstanceError):
        first.grant_id = "another-grant"


@pytest.mark.parametrize("change", [
    {"namespace": NamespaceId("bot", "another-persona")},
    {"principal": OwnerPrincipalV1("astrbot-dashboard", "account-18", "incarnation-3")},
    {"authority_id": "authority-b"},
    {"installation_id": "installation-b"},
])
def test_issue_rejects_ticket_cross_binding(change):
    with pytest.raises(ValueError):
        issue(ticket=ticket(**change))


def test_operation_and_receipt_reject_changed_digest_or_scope():
    original = issue()
    with pytest.raises(ValueError, match="digest"):
        replace(original, grant_digest=digest("f"))
    with pytest.raises(ValueError):
        issue(expected_guard=guard(namespace=NamespaceId("bot", "other")))
    with pytest.raises(ValueError):
        OwnerAuthorizationReceiptV1(
            original, "committed", "receipt-a",
            guard(namespace=NamespaceId("bot", "other"),
                  authorization_revision=1, authorization_head=digest("e")),
            grant_revision=1, graph_access_epoch=1,
        )
    with pytest.raises(ValueError):
        revoke(ticket=ticket())


def test_revoke_pending_requires_independent_barrier_and_commit_watermark():
    operation = revoke()
    with pytest.raises(ValueError, match="barrier"):
        OwnerAuthorizationReceiptV1(
            operation, "pending", "receipt-a",
            guard(authorization_revision=1, authorization_head=digest("e")),
        )
    with pytest.raises(ValueError, match="watermark"):
        OwnerAuthorizationReceiptV1(
            operation, "committed", "receipt-a",
            guard(authorization_revision=2, authorization_head=digest("f"),
                  minimum_revocation_revision=1),
            grant_revision=2, graph_access_epoch=2,
        )
    previously_revoked = revoke(expected_guard=guard(
        authorization_revision=1, authorization_head=digest("e"),
        minimum_revocation_revision=1, minimum_revocation_epoch=1,
    ))
    with pytest.raises(ValueError, match="guard"):
        OwnerAuthorizationReceiptV1(
            previously_revoked, "pending", "receipt-a",
            guard(authorization_revision=2, authorization_head=digest("f"),
                  minimum_revocation_revision=0, minimum_revocation_epoch=0,
                  pending_revoke_operation_id="revoke-a"),
        )


def test_wire_rejects_forged_identity_unknown_fields_and_noncanonical_json():
    value = to_wire(issue())
    changed = json.loads(json.dumps(value))
    changed["principal"]["account_incarnation"] = "incarnation-4"
    with pytest.raises(ValueError, match="ticket"):
        from_wire(changed)

    changed = json.loads(json.dumps(value))
    changed["request_digest"] = digest("0")
    with pytest.raises(ValueError, match="digest"):
        from_wire(changed)

    changed = json.loads(json.dumps(value))
    changed["admin_is_owner"] = True
    with pytest.raises(ValueError, match="fields"):
        from_wire(changed)

    encoded = canonical_bytes(ticket())
    with pytest.raises(ValueError, match="canonical"):
        decode_bytes(json.dumps(to_wire(ticket())).encode())
    with pytest.raises(ValueError, match="duplicate"):
        decode_bytes(encoded.replace(b'"ticket_id":', b'"ticket_id":"duplicate","ticket_id":'))


@pytest.mark.parametrize("changes", [
    {"challenge": "short"}, {"expires_at_utc": "2030-02-30T00:00:00Z"},
    {"creation_digest": "sha256:ABC"},
])
def test_claim_ticket_rejects_invalid_identity_material(changes):
    with pytest.raises(ValueError):
        ticket(**changes)


def test_guard_rejects_false_or_incoherent_head():
    with pytest.raises(ValueError):
        guard(authorization_revision=True)
    with pytest.raises(ValueError):
        guard(authorization_revision=1, authorization_head="genesis")
