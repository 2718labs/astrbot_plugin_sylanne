"""D11 root signing fails closed before any caller-authored budget reservation."""

import sqlite3

import pytest

from sylanne3.runtime.budget import install_schema
from sylanne3.runtime.d11_d04_root_freeze_v2 import (
    D11RootFreezeHold, install_d11_root_freeze_v2,
    issue_d11_root_freeze_v2, read_d11_root_freeze_v2,
)
from sylanne3.runtime.issuers import D11BudgetGrantIssuer
from sylanne3.runtime_contracts import NamespaceId


def test_absent_w01_owner_read_holds_without_reserving_or_signing() -> None:
    db = sqlite3.connect(":memory:")
    install_schema(db)
    db.commit()
    install_d11_root_freeze_v2(db)
    db.execute("BEGIN IMMEDIATE")
    issuer = D11BudgetGrantIssuer(b"test-only-signing-key".ljust(32, b"0"))
    namespace = NamespaceId("bot", "persona")
    assert read_d11_root_freeze_v2(
        db, issuer, namespace=namespace, operation_id="root-op") is None
    with pytest.raises(D11RootFreezeHold, match="superseded"):
        issue_d11_root_freeze_v2(
            db, issuer, object(), namespace=namespace,
            operation_id="root-op", parent_budget_lease_ref="lease",
        )
    assert db.execute("SELECT COUNT(*) FROM runtime_budget_reservations").fetchone() == (0,)
    assert db.execute("SELECT COUNT(*) FROM runtime_d11_d04_root_freezes_v2").fetchone() == (0,)
    db.rollback()
    db.close()
