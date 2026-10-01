"""Durable begin, claim, local execution and D11 settlement for D12 preview."""

import sqlite3
from dataclasses import replace

import pytest

from sylanne3.runtime.budget import BudgetLease, create_budget_lease, get_budget_lease
from sylanne3.runtime.budget import install_schema as install_budget_schema
from sylanne3.runtime.d12_preview_budget_v1 import (
    D12PreviewWorkEvidenceV1, PreviewCostConflict,
    begin_d12_preview_cost_v1, claim_d12_preview_run_v1,
    d12_preview_sandbox_namespace_v1, install_d12_preview_budget_schema_v1,
    mark_d12_preview_unknown_v1, read_d12_preview_cost_v1,
    run_d12_preview_once_v1, settle_d12_preview_cost_v1,
)
from sylanne3.runtime.issuers import BudgetLeaseGrant, D11BudgetGrantIssuer
from sylanne3.runtime.issuers import install_schema as install_issuer_schema
from sylanne3.runtime_contracts import NamespaceId


NAMESPACE = NamespaceId("bot", "persona")
OPERATION = "preview-op"
SANDBOX = d12_preview_sandbox_namespace_v1(NAMESPACE, OPERATION)
DIGEST = "a" * 64


def _case(path, *, work_kind="scheme_preview"):
    db = sqlite3.connect(path, isolation_level=None)
    issuer = D11BudgetGrantIssuer(b"d12-preview-budget-test-signing-key")
    db.execute("BEGIN IMMEDIATE")
    install_budget_schema(db)
    install_issuer_schema(db)
    install_d12_preview_budget_schema_v1(db)
    create_budget_lease(db, BudgetLease(
        "preview-lease", None, "bot", "persona", "USD",
        {"thread_cpu_ms": 100}, {}, {}, {}, 1, "active"),
        "create-preview-lease", "b" * 64)
    issuer.issue_budget_grant(db, BudgetLeaseGrant(
        "preview-grant", 1, "bot", "persona", "preview-lease", "USD",
        {"thread_cpu_ms": 100}, (work_kind,), 4_000_000_000.0,
        "preview-policy"))
    db.execute("COMMIT")
    return db, issuer


def _begin(db, issuer, **changes):
    args = dict(namespace=NAMESPACE, operation_id=OPERATION,
                sandbox_namespace=SANDBOX, compiled_digest=DIGEST,
                source_snapshot_digest=DIGEST, production_revision=7,
                budget_ref="preview-lease", ceiling_thread_cpu_ms=10,
                max_wall_ms=10,
                run_intent_digest="c" * 64, experiment_digest="d" * 64)
    args.update(changes)
    return begin_d12_preview_cost_v1(db, issuer, **args)


def _evidence():
    return D12PreviewWorkEvidenceV1(
        DIGEST, SANDBOX, DIGEST, 7, 7, (), (), ())


def _report(issuer, intent, monkeypatch, *, cpu_ns=2_100_000,
            work=_evidence, wall_ns=3_000_000):
    cpu = iter((1_000_000, 1_000_000 + cpu_ns))
    wall = iter((1_000_000, 1_000_000 + wall_ns))
    monkeypatch.setattr(
        "sylanne3.runtime.d12_preview_budget_v1.time.thread_time_ns",
        lambda: next(cpu))
    monkeypatch.setattr(
        "sylanne3.runtime.d12_preview_budget_v1.time.monotonic_ns",
        lambda: next(wall))
    return run_d12_preview_once_v1(
        issuer, intent, max_wall_ms=10, run_preview=work)


def test_durable_begin_claim_settle_and_lost_ack_replay(tmp_path, monkeypatch):
    db, issuer = _case(tmp_path / "cost.sqlite")
    db.execute("BEGIN IMMEDIATE")
    intent = _begin(db, issuer)
    assert get_budget_lease(db, "preview-lease").reserved == {"thread_cpu_ms": 10}
    db.execute("COMMIT")
    db.close()

    db = sqlite3.connect(tmp_path / "cost.sqlite", isolation_level=None)
    db.execute("BEGIN IMMEDIATE")
    assert _begin(db, issuer) == intent  # lost begin ACK
    assert claim_d12_preview_run_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION) == intent
    db.execute("COMMIT")
    db.execute("BEGIN IMMEDIATE")
    assert claim_d12_preview_run_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION) is None
    db.execute("COMMIT")

    report = _report(issuer, intent, monkeypatch)
    assert report.actual_thread_cpu_ms == 3
    db.execute("BEGIN IMMEDIATE")
    receipt = settle_d12_preview_cost_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION, report=report)
    assert receipt.status == "settled"
    assert get_budget_lease(db, "preview-lease").used == {"thread_cpu_ms": 3}
    db.execute("COMMIT")
    db.execute("BEGIN IMMEDIATE")
    assert settle_d12_preview_cost_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION,
        report=report) == receipt  # lost settle ACK
    state = read_d12_preview_cost_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION)
    assert state.report == report and state.receipt == receipt
    assert claim_d12_preview_run_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION) is None
    db.execute("COMMIT")


def test_failed_preview_keeps_measured_cost(tmp_path, monkeypatch):
    db, issuer = _case(tmp_path / "failed.sqlite")
    db.execute("BEGIN IMMEDIATE")
    intent = _begin(db, issuer)
    claim_d12_preview_run_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION)
    db.execute("COMMIT")

    def fail():
        raise RuntimeError("sandbox failed")

    report = _report(issuer, intent, monkeypatch, work=fail)
    assert report.status == "failed" and report.evidence_json is None
    db.execute("BEGIN IMMEDIATE")
    receipt = settle_d12_preview_cost_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION, report=report)
    assert receipt.status == "failed"
    assert get_budget_lease(db, "preview-lease").used == {"thread_cpu_ms": 3}
    db.execute("COMMIT")


def test_uncertain_execution_holds_ceiling_without_zero_bill(tmp_path):
    db, issuer = _case(tmp_path / "unknown.sqlite")
    db.execute("BEGIN IMMEDIATE")
    _begin(db, issuer)
    claim_d12_preview_run_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION)
    db.execute("COMMIT")
    db.close()  # lost worker/report; never claim this operation again
    db = sqlite3.connect(tmp_path / "unknown.sqlite", isolation_level=None)
    db.execute("BEGIN IMMEDIATE")
    assert claim_d12_preview_run_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION) is None
    receipt = mark_d12_preview_unknown_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION)
    assert receipt.status == "pending_confirmation"
    assert receipt.actual_thread_cpu_ms is None
    lease = get_budget_lease(db, "preview-lease")
    assert lease.used == {} and lease.unconfirmed == {"thread_cpu_ms": 10}
    db.execute("COMMIT")
    db.execute("BEGIN IMMEDIATE")
    assert mark_d12_preview_unknown_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION) == receipt
    db.execute("COMMIT")


def test_overrun_is_durable_and_conflicting_operation_rejected(tmp_path,
                                                               monkeypatch):
    db, issuer = _case(tmp_path / "overrun.sqlite")
    db.execute("BEGIN IMMEDIATE")
    intent = _begin(db, issuer, ceiling_thread_cpu_ms=1)
    claim_d12_preview_run_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION)
    db.execute("COMMIT")
    report = _report(issuer, intent, monkeypatch, cpu_ns=2_100_000)
    db.execute("BEGIN IMMEDIATE")
    receipt = settle_d12_preview_cost_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION, report=report)
    assert receipt.status == "overrun"
    assert get_budget_lease(db, "preview-lease").used == {"thread_cpu_ms": 3}
    assert read_d12_preview_cost_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION).receipt == receipt
    with pytest.raises(PreviewCostConflict):
        _begin(db, issuer, compiled_digest="e" * 64)
    db.execute("COMMIT")


def test_wrong_work_kind_is_denied_before_reservation(tmp_path):
    db, issuer = _case(tmp_path / "wrong.sqlite", work_kind="scheme_compile")
    db.execute("BEGIN IMMEDIATE")
    with pytest.raises(PermissionError, match="scheme_preview"):
        _begin(db, issuer)
    assert db.execute("SELECT COUNT(*) FROM runtime_budget_reservations").fetchone() == (0,)
    db.execute("ROLLBACK")


def test_stale_result_and_wall_deadline_keep_actual_bill(tmp_path, monkeypatch):
    db, issuer = _case(tmp_path / "stale.sqlite")
    db.execute("BEGIN IMMEDIATE")
    intent = _begin(db, issuer)
    claim_d12_preview_run_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION)
    db.execute("COMMIT")
    stale = lambda: D12PreviewWorkEvidenceV1(
        DIGEST, SANDBOX, DIGEST, 7, 8, (), (), ())
    report = _report(issuer, intent, monkeypatch, work=stale,
                     wall_ns=20_000_000)
    assert report.status == "timeout"
    assert report.actual_thread_cpu_ms == 3
    db.execute("BEGIN IMMEDIATE")
    receipt = settle_d12_preview_cost_v1(
        db, issuer, namespace=NAMESPACE, operation_id=OPERATION,
        report=report)
    assert receipt.status == "timeout"
    assert get_budget_lease(db, "preview-lease").used == {"thread_cpu_ms": 3}
    with pytest.raises(PreviewCostConflict, match="execution report"):
        settle_d12_preview_cost_v1(
            db, issuer, namespace=NAMESPACE, operation_id=OPERATION,
            report=replace(report, actual_thread_cpu_ms=0))
    db.execute("COMMIT")
