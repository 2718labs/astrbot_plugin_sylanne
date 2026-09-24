"""A child overrun blocks fresh commitments throughout its lease family."""

import sqlite3

import pytest

from sylanne3.runtime.budget import (
    BudgetLease, BudgetUnavailable, create_budget_lease, get_budget_lease,
    install_schema, reserve_budget, resolve_partial_budget,
    resolve_unconfirmed, settle_budget, settle_budget_partial,
)


def _hierarchy():
    db = sqlite3.connect(":memory:")
    install_schema(db)
    root = BudgetLease("root", None, "bot", "persona", "USD",
                       {"tokens": 1000, "money": 1000}, {}, {}, {}, 1, "active")
    child = BudgetLease("child", "root", "bot", "persona", "USD",
                        {"tokens": 100, "money": 100}, {}, {}, {}, 1, "active")
    sibling = BudgetLease("sibling", "root", "bot", "persona", "USD",
                          {"tokens": 800, "money": 800}, {}, {}, {}, 1, "active")
    grandchild = BudgetLease("grandchild", "sibling", "bot", "persona", "USD",
                             {"tokens": 300, "money": 300}, {}, {}, {}, 1, "active")
    for lease, operation in ((root, "root-create"), (child, "child-create"),
                             (sibling, "sibling-create"),
                             (grandchild, "grandchild-create")):
        create_budget_lease(db, lease, operation, "a" * 64)
    reserve_budget(db, "child", "original", "b" * 64,
                   {"tokens": 100, "money": 50})
    db.commit()
    return db


def _assert_new_commitments_blocked(db):
    for lease_id in ("root", "child", "sibling", "grandchild"):
        with pytest.raises(BudgetUnavailable, match="ancestry"):
            reserve_budget(db, lease_id, "fresh-" + lease_id, "c" * 64,
                           {"tokens": 1})
    with pytest.raises(BudgetUnavailable, match="ancestry"):
        create_budget_lease(db, BudgetLease(
            "new-sibling", "root", "bot", "persona", "USD",
            {"tokens": 50}, {}, {}, {}, 1, "active"), "new-create", "d" * 64)


def test_partial_child_overrun_blocks_existing_sibling_and_grandchild():
    db = _hierarchy()
    try:
        first = settle_budget_partial(
            db, "child", "original", "b" * 64,
            {"tokens": 200}, ("money",), execution_revoked=True)
        assert first.status == "pending_overrun"
        assert get_budget_lease(db, "child").used == {"tokens": 200}
        assert get_budget_lease(db, "child").unconfirmed == {"money": 50}
        _assert_new_commitments_blocked(db)
        assert settle_budget_partial(
            db, "child", "original", "b" * 64,
            {"tokens": 200}, ("money",), execution_revoked=True) == first
        resolved = resolve_partial_budget(
            db, "child", "original", "money-resolve", "e" * 64,
            {"money": 40}, execution_revoked=True)
        assert resolved.status == "overrun"
        assert db.execute("SELECT COUNT(*) FROM runtime_budget_debt_blocks").fetchone() == (2,)
        _assert_new_commitments_blocked(db)
    finally:
        db.close()


def test_full_unknown_resolution_and_full_actual_overrun_also_block_ancestry():
    db = _hierarchy()
    try:
        settle_budget(db, "child", "original", "b" * 64, None)
        assert resolve_unconfirmed(
            db, "child", "original", "resolve", "f" * 64,
            {"tokens": 200, "money": 40}, execution_revoked=True).status == "overrun"
        _assert_new_commitments_blocked(db)
    finally:
        db.close()


def test_overrun_block_rolls_back_with_original_settlement():
    db = _hierarchy()
    try:
        db.execute("BEGIN IMMEDIATE")
        settle_budget(db, "child", "original", "b" * 64,
                      {"tokens": 200, "money": 40}, execution_revoked=True)
        _assert_new_commitments_blocked(db)
        db.execute("ROLLBACK")
        assert db.execute("SELECT COUNT(*) FROM runtime_budget_debt_blocks").fetchone() == (0,)
        assert get_budget_lease(db, "child").reserved == {"tokens": 100, "money": 50}
        assert reserve_budget(db, "sibling", "new-work", "c" * 64,
                              {"tokens": 1}).status == "reserved"
    finally:
        db.close()


def test_schema_reopen_restores_blocks_from_existing_overrun_receipts():
    db = _hierarchy()
    try:
        settle_budget(db, "child", "original", "b" * 64,
                      {"tokens": 200, "money": 40}, execution_revoked=True)
        db.execute("DELETE FROM runtime_budget_debt_blocks")
        db.commit()
        install_schema(db)
        _assert_new_commitments_blocked(db)
    finally:
        db.close()
