"""Independent base-unit reference for conflicting original-call bills."""

import sqlite3

import pytest

from sylanne3.runtime.budget import (
    BudgetConflict, BudgetLease, close_budget_lease, create_budget_lease,
    get_budget_lease, install_schema, reserve_budget, settle_budget,
)


def _family():
    db = sqlite3.connect(":memory:")
    install_schema(db)
    for lease_id, parent_id, limit in (("parent", None, 500),
                                       ("child", "parent", 200)):
        create_budget_lease(
            db, BudgetLease(lease_id, parent_id, "bot", "persona", "USD",
                            {"model_microusd": limit}, {}, {}, {}, 1, "active"),
            "create-" + lease_id, "a" * 64,
        )
    return db


def test_same_original_call_cannot_replay_a_different_known_bill():
    db = _family()
    try:
        reserve_budget(db, "child", "call", "b" * 64,
                       {"model_microusd": 100})
        first = settle_budget(db, "child", "call", "b" * 64,
                              {"model_microusd": 80}, execution_revoked=True)
        assert first.status == "settled"
        assert settle_budget(db, "child", "call", "b" * 64,
                             {"model_microusd": 80}, execution_revoked=True) == first

        # The independent account is charged exactly 80 base units. A second
        # provider bill for 90 cannot masquerade as the earlier 80-unit receipt.
        with pytest.raises(BudgetConflict, match="settlement.*differs"):
            settle_budget(db, "child", "call", "b" * 64,
                          {"model_microusd": 90}, execution_revoked=True)
        with pytest.raises(BudgetConflict, match="settlement.*differs"):
            settle_budget(db, "child", "call", "b" * 64,
                          {"model_microusd": 80}, execution_revoked=False)
        assert get_budget_lease(db, "child").used == {"model_microusd": 80}
        close_budget_lease(db, "child", "close", "c" * 64,
                           execution_revoked=True)
        parent = get_budget_lease(db, "parent")
        assert parent.used == {"model_microusd": 80}
        assert parent.reserved == {}
        assert parent.available("model_microusd") == 500 - 80
    finally:
        db.close()
