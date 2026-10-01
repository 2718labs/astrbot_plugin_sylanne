"""Two provider calls must not share one late-cost resolution receipt."""

import sqlite3

import pytest

from sylanne3.runtime.budget import (
    BudgetConflict, BudgetLease, close_budget_lease, create_budget_lease,
    get_budget_lease, install_schema, reserve_budget, resolve_unconfirmed,
    settle_budget,
)


def test_late_cost_receipt_is_bound_to_its_original_call():
    db = sqlite3.connect(":memory:")
    try:
        install_schema(db)
        create_budget_lease(
            db, BudgetLease("parent", None, "bot", "persona", "USD",
                        {"model_microusd": 500}, {}, {}, {}, 1, "active"),
            "create-parent", "a" * 64,
        )
        create_budget_lease(
            db, BudgetLease("child", "parent", "bot", "persona", "USD",
                        {"model_microusd": 400}, {}, {}, {}, 1, "active"),
            "create-child", "b" * 64,
        )
        for call in ("call-a", "call-b"):
            reserve_budget(db, "child", call, "c" * 64,
                           {"model_microusd": 100})
            settle_budget(db, "child", call, "c" * 64, None)

        first = resolve_unconfirmed(
            db, "child", "call-a", "bill-a", "d" * 64,
            {"model_microusd": 70}, execution_revoked=True,
        )
        assert resolve_unconfirmed(
            db, "child", "call-a", "bill-a", "d" * 64,
            {"model_microusd": 70}, execution_revoked=True,
        ) == first
        with pytest.raises(BudgetConflict, match="resolution.*actual"):
            resolve_unconfirmed(
                db, "child", "call-a", "bill-a", "d" * 64,
                {"model_microusd": 80}, execution_revoked=True,
            )
        # An apparent duplicate for the second original call must not report
        # success: its 100-unit unknown upper bound is still held.
        with pytest.raises(BudgetConflict, match="resolution.*original"):
            resolve_unconfirmed(
                db, "child", "call-b", "bill-a", "d" * 64,
                {"model_microusd": 70}, execution_revoked=True,
            )
        middle = get_budget_lease(db, "child")
        assert middle.used == {"model_microusd": 70}
        assert middle.unconfirmed == {"model_microusd": 100}

        second = resolve_unconfirmed(
            db, "child", "call-b", "bill-b", "e" * 64,
            {"model_microusd": 80}, execution_revoked=True,
        )
        assert second.status == "settled"
        close_budget_lease(db, "child", "close-child", "f" * 64,
                           execution_revoked=True)
        parent = get_budget_lease(db, "parent")
        assert parent.used == {"model_microusd": 150}
        assert parent.unconfirmed == {}
        assert parent.reserved == {}
    finally:
        db.close()
