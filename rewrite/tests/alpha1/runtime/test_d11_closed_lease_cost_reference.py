"""Independent base-unit accounting for a late provider bill after lease close."""

import sqlite3

import pytest

from sylanne3.runtime.budget import (
    BudgetLease, BudgetUnavailable, create_budget_lease, close_budget_lease, get_budget_lease,
    install_schema, reserve_budget, resolve_partial_budget,
    resolve_unconfirmed, settle_budget, settle_budget_partial,
)


@pytest.mark.parametrize("observation", ("none", "tokens_known"))
def test_late_actual_replaces_held_ceiling_through_closed_ancestors(observation):
    db = sqlite3.connect(":memory:")
    try:
        install_schema(db)
        for lease_id, parent_id, limit in (
            ("root", None, 1000), ("branch", "root", 600),
            ("leaf", "branch", 300),
        ):
            create_budget_lease(
                db, BudgetLease(lease_id, parent_id, "bot", "persona", "USD",
                                {"model_tokens": limit, "model_microusd": limit},
                                {}, {}, {}, 1, "active"),
                "create-" + lease_id, "a" * 64,
            )
        ceiling = {"model_tokens": 200, "model_microusd": 150}
        reserve_budget(db, "leaf", "provider-call", "b" * 64, ceiling)
        if observation == "none":
            settle_budget(db, "leaf", "provider-call", "b" * 64, None)
            expected_before_used = {}
            expected_before_unknown = ceiling
        else:
            settle_budget_partial(
                db, "leaf", "provider-call", "b" * 64,
                {"model_tokens": 120}, ("model_microusd",),
                execution_revoked=True,
            )
            expected_before_used = {"model_tokens": 120}
            expected_before_unknown = {"model_microusd": 150}

        close_budget_lease(db, "leaf", "close-leaf", "c" * 64,
                           execution_revoked=True)
        close_budget_lease(db, "branch", "close-branch", "d" * 64,
                           execution_revoked=True)
        root_before = get_budget_lease(db, "root")
        assert root_before.used == expected_before_used
        assert root_before.unconfirmed == expected_before_unknown
        assert root_before.reserved == {}

        if observation == "none":
            actual = {"model_tokens": 120, "model_microusd": 170}
            first = resolve_unconfirmed(
                db, "leaf", "provider-call", "late-bill", "e" * 64,
                actual, execution_revoked=True,
            )
            repeat = resolve_unconfirmed(
                db, "leaf", "provider-call", "late-bill", "e" * 64,
                actual, execution_revoked=True,
            )
        else:
            actual = {"model_tokens": 120, "model_microusd": 170}
            first = resolve_partial_budget(
                db, "leaf", "provider-call", "late-bill", "e" * 64,
                {"model_microusd": 170}, execution_revoked=True,
            )
            repeat = resolve_partial_budget(
                db, "leaf", "provider-call", "late-bill", "e" * 64,
                {"model_microusd": 170}, execution_revoked=True,
            )
        assert first.status == "overrun"
        assert repeat == first
        # Independent ledger: release the 200/150 or 150 held upper bound;
        # book the provider's 120/170 once at every closed accounting level.
        for lease_id in ("leaf", "branch", "root"):
            ledger = get_budget_lease(db, lease_id)
            assert ledger.used == actual
            assert ledger.unconfirmed == {}
            assert ledger.reserved == {}
        assert get_budget_lease(db, "root").available("model_tokens") == 880
        assert get_budget_lease(db, "root").available("model_microusd") == 830
    finally:
        db.close()


def test_cancelled_execution_without_provider_bill_keeps_unknown_charge_held():
    db = sqlite3.connect(":memory:")
    try:
        install_schema(db)
        create_budget_lease(
            db, BudgetLease("account", None, "bot", "persona", "USD",
                            {"model_microusd": 500}, {}, {}, {}, 1, "active"),
            "create", "a" * 64,
        )
        reserve_budget(db, "account", "attempt", "b" * 64,
                       {"model_microusd": 300})
        settle_budget(db, "account", "attempt", "b" * 64, None)
        before = get_budget_lease(db, "account")
        # Revoking future execution does not prove a past provider call was free.
        with pytest.raises(BudgetUnavailable, match="actual cost remains unknown"):
            resolve_unconfirmed(db, "account", "attempt", "cancel", "c" * 64,
                                None, execution_revoked=True)
        after = get_budget_lease(db, "account")
        assert after == before
        assert after.available("model_microusd") == 200
        assert db.execute(
            "SELECT state FROM runtime_budget_reservations "
            "WHERE lease_id='account' AND operation_id='attempt'"
        ).fetchone() == ("unknown",)
        receipt = resolve_unconfirmed(
            db, "account", "attempt", "observed-bill", "d" * 64,
            {"model_microusd": 125}, execution_revoked=True,
        )
        assert receipt.status == "settled"
        assert get_budget_lease(db, "account").used == {"model_microusd": 125}
    finally:
        db.close()
