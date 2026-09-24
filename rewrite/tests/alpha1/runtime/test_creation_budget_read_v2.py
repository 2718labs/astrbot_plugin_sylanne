"""D01 budget selection reads only an existing signed D11 lease/grant."""

from dataclasses import replace
import time

import pytest

from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, canonical_digest as owner_contract_digest,
)
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.graph_coordinator import AuthorityDenied, UnavailableGuard
from sylanne3.runtime.budget import BudgetLease, create_budget_lease, get_budget_lease
from sylanne3.runtime.issuers import BudgetLeaseGrant
from sylanne3.runtime_contracts import NamespaceId

from test_graph_v2_provisioning import _owner_issue_case


def _case(tmp_path):
    (store, authority_db, port, coordinator, policy, operation,
     pending, grant_value, bootstrap) = _owner_issue_case(
        tmp_path, return_bootstrap=True, role_types=True)
    port.pending_owner = pending
    proof = coordinator.commit_first_owner_grant_v2(
        bootstrap, namespace=policy.namespace,
        operation_id=operation.operation_id, grant_value=grant_value)
    guard = OwnerAuthorizationGuardV1(
        operation.authority_id, operation.installation_id,
        policy.namespace, 1, owner_contract_digest(proof), 0, 0)

    def guarded(*, namespace, authority_namespace, permit, **session_kwargs):
        port.outside_graph_lock()
        assert namespace == policy.namespace
        assert authority_namespace == port.anchors[namespace].namespace
        assert port.fences.validate_fence(
            permit, subject="subject", current_anchor=port.anchors[namespace]) == permit
        assert session_kwargs["owner_actor_id"] == "paired-owner"
        assert session_kwargs["owner_session_token"] == "A" * 43
        assert session_kwargs["owner_session_request"].principal == operation.principal
        return guard, permit

    port.get_current_owner_guard_for_fence = guarded
    actor = "paired-owner"
    coordinator._GraphCoordinator__owner_principal_resolver = (
        lambda current, namespace: operation.principal
        if (current, namespace) == (actor, policy.namespace) else None)
    return store, authority_db, port, coordinator, policy.namespace, operation.principal, actor


def _read(case, **changes):
    _, _, port, coordinator, namespace, principal, actor = case
    anchor = port.anchors[namespace]
    args = dict(namespace=namespace, budget_ref="lease-persona",
                actor_id=actor, principal=principal,
                owner_session_token="A" * 43,
                owner_session_request=OwnerSessionLoginRequestV1(
                    anchor.authority_id, anchor.namespace,
                    port.installation_grant.installation_id, principal,
                    "credential:owner", 1, "owner", "http://localhost"))
    args.update(changes)
    return coordinator.read_current_creation_budget_v2(**args)


def test_creation_budget_read_is_current_fenced_and_typed(tmp_path):
    case = _case(tmp_path)
    store, authority_db, port, _, namespace, *_ = case
    try:
        proof = _read(case)
        assert proof.budget.namespace == namespace
        assert proof.budget.lease_ref == "lease-persona"
        assert proof.budget.version == get_budget_lease(store._db, "lease-persona").version
        assert proof.grant_id == "grant-persona"
        assert proof.grant_version == 1
        assert proof.grant_digest.startswith("sha256:")
        assert port.finishes[-1][0] == "read"
    finally:
        store.close()
        authority_db.close()


def test_creation_budget_read_holds_on_missing_or_foreign_lease(tmp_path):
    case = _case(tmp_path)
    store, authority_db, *_ = case
    try:
        with pytest.raises(UnavailableGuard, match="absent"):
            _read(case, budget_ref="missing-lease")
        with pytest.raises(UnavailableGuard, match="metadata is absent"):
            _read(case, namespace=NamespaceId("bot", "other"))
        foreign = BudgetLease(
            "lease-foreign", None, "bot", "other", "USD",
            {"cpu_ms": 200}, {}, {}, {}, 1, "active")
        create_budget_lease(store._db, foreign, "create-foreign", "f" * 64)
        issuer = case[3]._GraphCoordinator__d11_issuer
        issuer.issue_budget_grant(store._db, BudgetLeaseGrant(
            "grant-foreign", 1, "bot", "other", "lease-foreign", "USD",
            {"cpu_ms": 100}, ("encode",), time.time() + 3600, "d11-policy"))
        with pytest.raises(UnavailableGuard, match="differs"):
            _read(case, budget_ref="lease-foreign")
    finally:
        store.close()
        authority_db.close()


def test_creation_budget_read_holds_on_lease_or_grant_change(tmp_path):
    case = _case(tmp_path)
    store, authority_db, port, _, *_ = case
    try:
        before = _read(case)
        store._db.execute(
            "UPDATE runtime_budget_leases SET version=version+1 WHERE lease_id=?",
            ("lease-persona",))
        after = _read(case)
        assert after.budget.version == before.budget.version + 1
        assert after.budget.digest != before.budget.digest
        with pytest.raises(UnavailableGuard, match="selection changed"):
            _read(case, expected=before.budget)
        store._db.execute(
            "UPDATE runtime_budget_grants SET status='revoked' WHERE lease_id=?",
            ("lease-persona",))
        with pytest.raises(UnavailableGuard, match="absent"):
            _read(case)
        assert port.finishes[-1][0] == "read"
    finally:
        store.close()
        authority_db.close()


def test_creation_budget_read_holds_on_owner_revocation(tmp_path):
    case = _case(tmp_path)
    store, authority_db, port, _, *_ = case
    original = port.get_current_owner_guard_for_fence
    port.get_current_owner_guard_for_fence = lambda **kw: (
        replace(original(**kw)[0], pending_revoke_operation_id="revoke-1"),
        kw["permit"])
    try:
        with pytest.raises(UnavailableGuard, match="Owner lease differs"):
            _read(case)
    finally:
        store.close()
        authority_db.close()


def test_creation_budget_read_requires_current_signed_session(tmp_path):
    case = _case(tmp_path)
    store, authority_db, port, *_ = case
    try:
        with pytest.raises(UnavailableGuard, match="signed creation Owner session"):
            _read(case, owner_session_token="")
        port.get_current_owner_guard_for_fence = lambda **_: (
            _ for _ in ()).throw(UnavailableGuard("signed Owner session expired"))
        with pytest.raises(UnavailableGuard, match="session expired"):
            _read(case)
    finally:
        store.close()
        authority_db.close()
