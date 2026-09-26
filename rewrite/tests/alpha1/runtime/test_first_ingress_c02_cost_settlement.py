"""C02 local work must leave an auditable, conservative D11 cost receipt."""

import json
from dataclasses import replace

import pytest

from sylanne3.host.authority_profile import AdminD06FirstIngressC02Policy
from sylanne3.runtime.budget import get_budget_lease
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.runtime.issuers import d06_first_ingress_c02_quote_id
from sylanne3.runtime.issuers import IssuerAuthorityDenied
from sylanne3.runtime.c02_cost_settlement import (
    C02CostUnavailable, apply_c02_unknown_budget_in_transaction,
    prepare_c02_unknown_cost_plan,
)
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.contracts import EventConflict

from test_first_ingress_c02_commit import c02_case


def test_c02_unknown_cost_keeps_full_ceiling_encumbered_once(c02_case):
    store, coordinator, bootstrap, namespace, policy, clock, intent, read, _ = c02_case
    c02_policy = AdminD06FirstIngressC02Policy(
        30.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource")
    before = get_budget_lease(store._db, intent.budget_lease_id)

    committed = coordinator.commit_first_ingress_c02_v1(
        bootstrap, intent, read, policy, c02_policy, clock)
    assert committed.status == "committed"

    db = store._db
    quote = json.loads(db.execute(
        "SELECT quote_json FROM runtime_resource_quotes "
        "WHERE quote_id=?",
        (d06_first_ingress_c02_quote_id(
            namespace, read.request.consumer_operation_id),),
    ).fetchone()[0])
    lease_id = quote["parent_budget_lease_ref"]
    reservation = db.execute(
        "SELECT state,actual_json FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (lease_id, read.request.consumer_operation_id),
    ).fetchone()
    assert reservation == ("unknown", None)
    lease = get_budget_lease(db, lease_id)
    assert lease.reserved.get("cpu_ms", 0) == before.reserved.get("cpu_ms", 0)
    assert lease.unconfirmed["cpu_ms"] == before.unconfirmed.get("cpu_ms", 0) + 3

    cost = json.loads(db.execute(
        "SELECT value FROM graph_atoms WHERE type_name='runtime.cost_settlement' "
        "AND bot=? AND persona=? AND subject=?",
        (*read.request.namespace.as_tuple, quote["activity_id"]),
    ).fetchone()[0])
    assert cost["cost_operation_id"] == read.request.consumer_operation_id
    assert cost["status"] == "pending_confirmation"
    assert cost["actual"] is None
    assert cost["unconfirmed"] == {"cpu_ms": 3}
    assert cost["execution_revoked"] is True
    assert db.execute(
        "SELECT COUNT(*) FROM runtime_resource_outcomes WHERE quote_id=?",
        (quote["quote_id"],),
    ).fetchone() == (1,)

    replay = coordinator.commit_first_ingress_c02_v1(
        bootstrap, intent, read, policy, c02_policy, clock)
    assert replay.status == "duplicate"
    assert db.execute(
        "SELECT COUNT(*) FROM runtime_budget_operations WHERE operation_id=? "
        "AND phase='settle'",
        (read.request.consumer_operation_id,),
    ).fetchone() == (1,)
    assert get_budget_lease(db, lease_id) == lease


def test_c02_cost_finish_lost_reply_reuses_one_charge(c02_case, monkeypatch):
    store, coordinator, bootstrap, namespace, policy, clock, intent, read, _ = c02_case
    accounting = coordinator._GraphCoordinator__accounting_maintenance_port
    original_finish = accounting.finish
    first = True

    def lost_finish_reply(request, grant):
        nonlocal first
        original_finish(request, grant)
        if first and request.operation_id.startswith("c02-cost-fence-"):
            first = False
            raise RuntimeError("lost finish reply")

    monkeypatch.setattr(accounting, "finish", lost_finish_reply)
    c02_policy = AdminD06FirstIngressC02Policy(
        30.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource")
    with pytest.raises(RuntimeError, match="lost finish reply"):
        coordinator.commit_first_ingress_c02_v1(
            bootstrap, intent, read, policy, c02_policy, clock)
    db = store._db
    assert db.execute(
        "SELECT state FROM runtime_budget_reservations WHERE operation_id=?",
        (read.request.consumer_operation_id,),
    ).fetchone() == ("unknown",)
    assert coordinator.commit_first_ingress_c02_v1(
        bootstrap, intent, read, policy, c02_policy, clock).status == "duplicate"
    assert db.execute(
        "SELECT COUNT(*) FROM runtime_budget_operations WHERE operation_id=? "
        "AND phase='settle'", (read.request.consumer_operation_id,),
    ).fetchone() == (1,)


def test_c02_cost_recovery_after_content_needs_no_live_worker_clock(
        c02_case, monkeypatch):
    store, coordinator, bootstrap, _, policy, clock, intent, read, _ = c02_case
    c02_policy = AdminD06FirstIngressC02Policy(
        30.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource")
    monkeypatch.setattr(coordinator, "_commit_first_ingress_c02_unknown_cost_v1",
                        lambda *args: None)
    assert coordinator.commit_first_ingress_c02_v1(
        bootstrap, intent, read, policy, c02_policy, clock).status == "committed"
    monkeypatch.delattr(coordinator, "_commit_first_ingress_c02_unknown_cost_v1")
    port = coordinator._GraphCoordinator__content_fence_v2

    def expired_clock(*args):
        raise AssertionError("live worker clock must not be read after completion")

    monkeypatch.setattr(port, "read_ingress_clock", expired_clock)
    assert coordinator.commit_first_ingress_c02_v1(
        bootstrap, intent, read, policy, c02_policy, clock).status == "duplicate"
    assert store._db.execute(
        "SELECT state FROM runtime_budget_reservations WHERE operation_id=?",
        (read.request.consumer_operation_id,),
    ).fetchone() == ("unknown",)


def test_c02_cost_refuses_unverified_original_write_fence(c02_case, monkeypatch):
    store, coordinator, bootstrap, namespace, policy, clock, intent, read, _ = c02_case
    c02_policy = AdminD06FirstIngressC02Policy(
        30.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource")
    monkeypatch.setattr(coordinator, "_commit_first_ingress_c02_unknown_cost_v1",
                        lambda *args: None)
    coordinator.commit_first_ingress_c02_v1(
        bootstrap, intent, read, policy, c02_policy, clock)
    monkeypatch.delattr(coordinator, "_commit_first_ingress_c02_unknown_cost_v1")
    store._db.execute(
        "UPDATE graph_bundle_fences_v2 SET finish_request_id='forged' "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, read.request.consumer_operation_id),
    )
    with pytest.raises(Exception, match="fence|receipt"):
        coordinator.commit_first_ingress_c02_v1(
            bootstrap, intent, read, policy, c02_policy, clock)
    assert store._db.execute(
        "SELECT state FROM runtime_budget_reservations WHERE operation_id=?",
        (read.request.consumer_operation_id,),
    ).fetchone() == ("reserved",)


def test_c02_unknown_cost_plan_requires_verified_completion(c02_case):
    store, coordinator, bootstrap, namespace, policy, clock, intent, read, _ = c02_case
    c02_policy = AdminD06FirstIngressC02Policy(
        30.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource")
    coordinator._commit_first_ingress_c02_unknown_cost_v1 = lambda *args: None
    coordinator.commit_first_ingress_c02_v1(
        bootstrap, intent, read, policy, c02_policy, clock)
    verified = coordinator._first_ingress_c02_duplicate_v1(
        namespace, read.request.consumer_operation_id, intent, read)
    assert verified.status == "duplicate"

    plan = prepare_c02_unknown_cost_plan(
        store._db, coordinator._GraphCoordinator__d02_issuer,
        namespace, intent, read, verified)
    assert plan.predicted_budget.receipt.status == "pending_confirmation"
    assert plan.outcome.actual is None
    assert plan.outcome.execution_revoked is True
    store._db.execute("BEGIN IMMEDIATE")
    try:
        applied = apply_c02_unknown_budget_in_transaction(
            store._db, coordinator._GraphCoordinator__d02_issuer,
            plan, intent, read, verified)
        assert applied.receipt.status == "pending_confirmation"
        assert applied.cost_write.value["unconfirmed"] == {"cpu_ms": 3}
    finally:
        store._db.rollback()


def test_committed_c02_cost_recovers_after_sqlite_reopen_without_result_body(
        c02_case, monkeypatch):
    store, coordinator, bootstrap, namespace, policy, clock, intent, read, _ = c02_case
    c02_policy = AdminD06FirstIngressC02Policy(
        30.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource")
    monkeypatch.setattr(coordinator, "_commit_first_ingress_c02_unknown_cost_v1",
                        lambda *args: None)
    assert coordinator.commit_first_ingress_c02_v1(
        bootstrap, intent, read, policy, c02_policy, clock).status == "committed"
    monkeypatch.delattr(coordinator, "_commit_first_ingress_c02_unknown_cost_v1")
    operation_id = read.request.consumer_operation_id
    assert store._db.execute(
        "SELECT state FROM runtime_budget_reservations WHERE operation_id=?",
        (operation_id,)).fetchone() == ("reserved",)
    original_quote = coordinator._GraphCoordinator__d02_issuer.original_signed_quote(
        store._db, d06_first_ingress_c02_quote_id(namespace, operation_id), 1)
    before_budget = get_budget_lease(store._db, original_quote.parent_budget_lease_ref)

    path = store._db.execute("PRAGMA database_list").fetchone()[2]
    registry = store._registry
    store.close()
    reopened = ProductionGraphStore(path, registry)
    coordinator._GraphCoordinator__store = reopened
    reopened._coordinator_capability = coordinator._GraphCoordinator__graph_capability
    authority = coordinator._GraphCoordinator__content_fence_v2
    authority.store = reopened
    accounting = coordinator._GraphCoordinator__accounting_maintenance_port
    accounting.store = reopened
    coordinator._GraphCoordinator__worker_result_fact_port = None
    authority.read_ingress_clock = lambda *_: (_ for _ in ()).throw(
        AssertionError("committed cost recovery must not read the worker clock"))
    def original_intent_lookup(request):
        assert request.namespace == namespace
        assert request.consumer_operation_id == operation_id
        assert request.job_id == read.request.job_id
        assert request.acquire_operation_id == intent.operation_id
        assert request.call_id == intent.call_id
        return intent

    coordinator._GraphCoordinator__original_c02_cost_intent_port = (
        original_intent_lookup)
    try:
        coordinator.recover_committed_first_ingress_c02_unknown_cost_v1(
            bootstrap, namespace, operation_id)
        assert reopened._db.execute(
            "SELECT state,actual_json FROM runtime_budget_reservations "
            "WHERE operation_id=?", (operation_id,)).fetchone() == ("unknown", None)
        quote = coordinator._GraphCoordinator__d02_issuer.original_signed_quote(
            reopened._db, d06_first_ingress_c02_quote_id(namespace, operation_id), 1)
        budget = get_budget_lease(reopened._db, quote.parent_budget_lease_ref)
        assert budget.unconfirmed.get("cpu_ms", 0) == (
            before_budget.unconfirmed.get("cpu_ms", 0) + 3)
        assert budget.reserved.get("cpu_ms", 0) == (
            before_budget.reserved.get("cpu_ms", 0) - 3)
        cost = json.loads(reopened._db.execute(
            "SELECT value FROM graph_atoms WHERE type_name='runtime.cost_settlement' "
            "AND bot=? AND persona=? AND subject=?",
            (*namespace.as_tuple, quote.activity_id),
        ).fetchone()[0])
        assert cost["status"] == "pending_confirmation"
        assert cost["actual"] is None
        assert cost["unconfirmed"] == {"cpu_ms": 3}
        coordinator.recover_committed_first_ingress_c02_unknown_cost_v1(
            bootstrap, namespace, operation_id)
        assert reopened._db.execute(
            "SELECT COUNT(*) FROM runtime_budget_operations WHERE operation_id=? "
            "AND phase='settle'", (operation_id,)).fetchone() == (1,)
    finally:
        reopened.close()


@pytest.mark.parametrize("mutation", (
    "authority_intent", "finish_fence", "signed_quote", "reservation",
    "observation_digest", "terminal_receipt_digest",
    "malformed_result_digest"))
def test_committed_c02_cost_recovery_holds_on_broken_original_proof(
        c02_case, monkeypatch, mutation):
    store, coordinator, bootstrap, namespace, policy, clock, intent, read, _ = c02_case
    c02_policy = AdminD06FirstIngressC02Policy(
        30.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource")
    monkeypatch.setattr(coordinator, "_commit_first_ingress_c02_unknown_cost_v1",
                        lambda *args: None)
    coordinator.commit_first_ingress_c02_v1(
        bootstrap, intent, read, policy, c02_policy, clock)
    monkeypatch.delattr(coordinator, "_commit_first_ingress_c02_unknown_cost_v1")
    operation_id = read.request.consumer_operation_id
    coordinator._GraphCoordinator__original_c02_cost_intent_port = (
        lambda request: replace(intent, provider_config_digest="d" * 64)
        if mutation == "authority_intent" else intent)
    db = store._db
    if mutation == "finish_fence":
        db.execute(
            "UPDATE graph_bundle_fences_v2 SET finish_request_digest=? "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ("sha256:" + "0" * 64, *namespace.as_tuple, operation_id))
    elif mutation == "signed_quote":
        db.execute(
            "UPDATE runtime_resource_quotes SET quote_json='{}' "
            "WHERE quote_id=?",
            (d06_first_ingress_c02_quote_id(namespace, operation_id),))
    elif mutation == "reservation":
        db.execute(
            "UPDATE runtime_budget_reservations SET ceiling_json='{}' "
            "WHERE operation_id=?", (operation_id,))
    elif mutation in {"observation_digest", "terminal_receipt_digest",
                      "malformed_result_digest"}:
        receipt = db.execute(
            "SELECT receipt_json FROM graph_bundle_operations WHERE bot=? "
            "AND persona=? AND operation_id=?",
            namespace.as_tuple + (operation_id,),
        ).fetchone()[0]
        data = json.loads(receipt)
        field = ("result_digest" if mutation == "malformed_result_digest"
                 else mutation)
        data["first_ingress_c02"][field] = (
            "malformed" if mutation == "malformed_result_digest" else "0" * 64)
        db.execute(
            "UPDATE graph_bundle_operations SET receipt_json=? "
            "WHERE bot=? AND persona=? AND operation_id=?",
            (json.dumps(data, sort_keys=True, separators=(",", ":")),
             *namespace.as_tuple, operation_id))
    expected_error = {
        "authority_intent": UnavailableGuard,
        "finish_fence": UnavailableGuard,
        "signed_quote": IssuerAuthorityDenied,
        "reservation": C02CostUnavailable,
        "observation_digest": UnavailableGuard,
        "terminal_receipt_digest": UnavailableGuard,
        "malformed_result_digest": EventConflict,
    }[mutation]
    with pytest.raises(expected_error):
        coordinator.recover_committed_first_ingress_c02_unknown_cost_v1(
            bootstrap, namespace, operation_id)
    assert db.execute(
        "SELECT state FROM runtime_budget_reservations WHERE operation_id=?",
        (operation_id,)).fetchone() == ("reserved",)
    assert db.execute(
        "SELECT COUNT(*) FROM runtime_budget_operations WHERE operation_id=? "
        "AND phase='settle'", (operation_id,)).fetchone() == (0,)
