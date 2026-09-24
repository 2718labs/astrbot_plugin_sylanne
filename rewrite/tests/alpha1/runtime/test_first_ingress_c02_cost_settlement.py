"""C02 local work must leave an auditable, conservative D11 cost receipt."""

import json

import pytest

from sylanne3.host.authority_profile import AdminD06FirstIngressC02Policy
from sylanne3.runtime.budget import get_budget_lease
from sylanne3.runtime.issuers import d06_first_ingress_c02_quote_id
from sylanne3.runtime.c02_cost_settlement import (
    apply_c02_unknown_budget_in_transaction, prepare_c02_unknown_cost_plan,
)

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
