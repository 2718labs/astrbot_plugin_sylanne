"""A reserved model job cannot start after related budget debt appears."""

from sylanne3.runtime.budget import (
    BudgetLease, create_budget_lease, reserve_budget, settle_budget_partial,
)

from test_current_model_egress_graph_verifier import (  # noqa: F401
    _case, token_ingress_system,
)


def test_existing_model_job_holds_after_child_partial_overrun(token_ingress_system):
    db, verifier, intent = _case(token_ingress_system, production=True)
    assert verifier.complete_graph_current(intent)

    child = BudgetLease(
        "egress-debt-child", intent.budget_lease_id,
        "bot", "persona", "USD",
        {"cpu_ms": 100, "output_tokens": 200},
        {}, {}, {}, 1, "active")
    create_budget_lease(db, child, "create-debt-child", "a" * 64)
    reserve_budget(db, child.lease_id, "child-model", "b" * 64,
                   {"cpu_ms": 20, "output_tokens": 100})
    db.commit()
    assert verifier.complete_graph_current(intent)

    db.execute("BEGIN IMMEDIATE")
    settle_budget_partial(
        db, child.lease_id, "child-model", "b" * 64,
        {"output_tokens": 201}, ("cpu_ms",), execution_revoked=True)
    # The pinned verifier sees the committed snapshot, never uncommitted debt.
    assert verifier.complete_graph_current(intent)
    db.execute("ROLLBACK")
    assert verifier.complete_graph_current(intent)

    db.execute("BEGIN IMMEDIATE")
    first = settle_budget_partial(
        db, child.lease_id, "child-model", "b" * 64,
        {"output_tokens": 201}, ("cpu_ms",), execution_revoked=True)
    db.execute("COMMIT")
    assert first.status == "pending_overrun"
    assert not verifier.complete_graph_current(intent)
    assert settle_budget_partial(
        db, child.lease_id, "child-model", "b" * 64,
        {"output_tokens": 201}, ("cpu_ms",), execution_revoked=True) == first
    assert not verifier.complete_graph_current(intent)
