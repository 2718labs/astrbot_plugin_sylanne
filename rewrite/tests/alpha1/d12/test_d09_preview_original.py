"""D09 preview originals survive exact replay and reject changed bytes."""

import sqlite3

import pytest

from sylanne3.domains.d12.d09_preview import (
    D12D09PreviewSpecV1, d09_preview_control_digest_v1,
    run_d12_d09_preview_v1,
)
from sylanne3.domains.d12.d09_preview_original import (
    install_d09_preview_original_v1, read_d09_preview_original_v1,
    record_d09_preview_original_v1, verify_d09_preview_original_v1,
)
from sylanne3.runtime.d12_domain_scheme_compile_v1 import EXPRESSION_POLICY_FIELD

from tests.alpha1.d12.test_d09_preview_runner import NAMESPACE, _candidate


def _report():
    candidate = _candidate(19)
    spec = D12D09PreviewSpecV1(
        NAMESPACE, "preview-op", "b" * 64,
        d09_preview_control_digest_v1(None), candidate.candidate_digest,
        (EXPRESSION_POLICY_FIELD,),
    )
    return run_d12_d09_preview_v1(spec, None, candidate)


def _args(report):
    return dict(
        operation_id="preview-op", compiled_digest="b" * 64,
        preview_seal="c" * 64, cost_ref="cost:1", plan_digest="d" * 64,
        report=report,
    )


def test_immutable_d09_report_round_trip_and_exact_replay():
    db = sqlite3.connect(":memory:")
    report = _report()
    db.execute("BEGIN IMMEDIATE")
    install_d09_preview_original_v1(db)
    record_d09_preview_original_v1(db, NAMESPACE, **_args(report))
    record_d09_preview_original_v1(db, NAMESPACE, **_args(report))
    assert verify_d09_preview_original_v1(db, NAMESPACE, **_args(report))
    assert read_d09_preview_original_v1(
        db, NAMESPACE, operation_id="preview-op") == (
            "b" * 64, "c" * 64, "cost:1", "d" * 64, report)
    with pytest.raises(ValueError, match="original differs"):
        record_d09_preview_original_v1(
            db, NAMESPACE, **(_args(report) | {"preview_seal": "e" * 64}))
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        db.execute("UPDATE graph_d12_d09_preview_originals_v1 "
                   "SET cost_ref='changed' WHERE operation_id='preview-op'")
    db.execute("ROLLBACK")


def test_report_must_bind_its_operation_and_compile():
    db = sqlite3.connect(":memory:")
    db.execute("BEGIN IMMEDIATE")
    install_d09_preview_original_v1(db)
    with pytest.raises(ValueError, match="does not bind"):
        record_d09_preview_original_v1(
            db, NAMESPACE, **(_args(_report()) | {"operation_id": "wrong"}))
    db.execute("ROLLBACK")
