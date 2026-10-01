"""C09 D11 facts replay a real signed C04 CPU settlement."""

import pytest

from sylanne3.runtime.c09_d11_c04_recovery_reader_v4 import (
    C09D11RecoveryHold, read_current_c04_d11_recovery_fact_v4,
)
from tests.alpha1.runtime import test_d11_c04_internal_cost as c04_fixture


def test_real_overrun_budget_fact_and_tampered_settlement_hold(tmp_path, monkeypatch):
    actual_import = c04_fixture.import_c04_cpu_terminal_v1
    observed = []

    def import_and_read(db, namespace, operation_id, proof, authority, issuer):
        original = actual_import(db, namespace, operation_id, proof, authority, issuer)
        db.execute("BEGIN IMMEDIATE")
        try:
            fact = read_current_c04_d11_recovery_fact_v4(
                db, namespace=namespace, operation_id=operation_id,
                issuer=issuer, authority=authority,
            )
            observed.append(fact)
            assert fact.upper_bound == 10
            assert fact.actual_cost == fact.settled == 23
            assert fact.pending == 0 and fact.debt == 13
            db.execute("UPDATE runtime_budget_operations SET receipt_json='{}' "
                       "WHERE operation_id=? AND phase='settle'",
                       (original.budget_operation_id,))
            with pytest.raises(C09D11RecoveryHold):
                read_current_c04_d11_recovery_fact_v4(
                    db, namespace=namespace, operation_id=operation_id,
                    issuer=issuer, authority=authority,
                )
        finally:
            db.rollback()
        return original

    monkeypatch.setattr(c04_fixture, "import_c04_cpu_terminal_v1", import_and_read)
    c04_fixture.test_signed_terminal_import_and_replay(tmp_path, "completed", 23)
    assert len(observed) == 2
    assert observed[0] == observed[1]
