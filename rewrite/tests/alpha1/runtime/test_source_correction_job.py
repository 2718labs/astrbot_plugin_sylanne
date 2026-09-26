"""The D11 correction worker gate reads the real committed job and ledgers."""

from dataclasses import replace
from datetime import datetime
import json

import pytest

from sylanne3.runtime.source_correction_job import (
    SourceCorrectionJobHold, acquire_source_correction_job_in_transaction,
    plan_source_correction_job_acquire,
    read_source_correction_job_snapshot,
)
from sylanne3.runtime_contracts import FenceScope
from sylanne3.graph_types import NamespaceEpoch

from test_source_correction_commit_v2 import _case


def _committed(tmp_path):
    case, request, kwargs, *_ = _case(tmp_path)
    store, authority_db, coordinator, namespace = case
    receipt = coordinator.commit_source_correction_v1(request=request, **kwargs)
    db = store._db
    job_id = db.execute(
        "SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
        "AND operation_id=?", namespace.as_tuple + (request.operation_id,),
    ).fetchone()[0]
    deadline = db.execute("SELECT deadline_utc FROM runtime_jobs WHERE job_id=?",
                          (job_id,)).fetchone()[0]
    now = datetime.fromisoformat(deadline.replace("Z", "+00:00")).timestamp() - 5
    issuer = coordinator._GraphCoordinator__d11_issuer
    return store, authority_db, db, issuer, namespace, job_id, receipt, now, coordinator


def test_correction_acquire_preflight_freezes_real_commit_without_mutation(tmp_path):
    store, authority_db, db, issuer, namespace, job_id, receipt, now, _ = _committed(tmp_path)
    try:
        db.execute("BEGIN")
        snapshot = read_source_correction_job_snapshot(
            db, issuer, namespace, job_id, now_utc=now)
        planned = plan_source_correction_job_acquire(
            snapshot, "worker-1", now_utc=now, lease_seconds=1)
        assert snapshot.correction_source_ref == receipt.correction_source_ref
        assert snapshot.outbox_ref == receipt.reevaluation_outbox_ref
        assert planned.phase == "running" and planned.fence == 1
        running = replace(snapshot, job=planned)
        assert plan_source_correction_job_acquire(
            running, "worker-1", now_utc=now, lease_seconds=1) == planned
        with pytest.raises(SourceCorrectionJobHold):
            plan_source_correction_job_acquire(
                running, "worker-1", now_utc=now + 1, lease_seconds=1)
        assert db.execute("SELECT phase FROM runtime_jobs WHERE job_id=?",
                          (job_id,)).fetchone() == ("queued",)
        assert db.execute("SELECT phase FROM graph_bundle_outbox WHERE outbox_ref=?",
                          (snapshot.outbox_ref,)).fetchone() == ("pending",)
        db.execute("ROLLBACK")
    finally:
        store.close()
        authority_db.close()


@pytest.mark.parametrize("tamper", ["head", "reservation", "outbox", "quote"])
def test_correction_acquire_holds_on_changed_frozen_fact(tmp_path, tamper):
    store, authority_db, db, issuer, namespace, job_id, receipt, now, _ = _committed(tmp_path)
    try:
        db.execute("BEGIN IMMEDIATE")
        if tamper == "head":
            head_ref = json.loads(db.execute(
                "SELECT receipt_json FROM graph_bundle_operations WHERE "
                "bot=? AND persona=? AND operation_id=?",
                namespace.as_tuple + (receipt.operation_id,),
            ).fetchone()[0])["source_correction"]["correction_head_refs"][0]
            db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (head_ref,))
        elif tamper == "reservation":
            db.execute("UPDATE runtime_budget_reservations SET state='settled' "
                       "WHERE operation_id=?", (receipt.operation_id,))
        elif tamper == "outbox":
            db.execute("UPDATE graph_bundle_outbox SET phase='claimed' "
                       "WHERE outbox_ref=?", (receipt.reevaluation_outbox_ref,))
        else:
            quote_ref = json.loads(db.execute(
                "SELECT operator_versions_json FROM runtime_jobs WHERE job_id=?",
                (job_id,)).fetchone()[0])["resource_quote"]
            db.execute("UPDATE runtime_resource_quotes SET status='revoked' "
                       "WHERE quote_id=?", (quote_ref.rsplit(":", 1)[0],))
        with pytest.raises(SourceCorrectionJobHold):
            read_source_correction_job_snapshot(
                db, issuer, namespace, job_id, now_utc=now)
        db.execute("ROLLBACK")
    finally:
        store.close()
        authority_db.close()


def test_correction_acquire_holds_after_original_deadline(tmp_path):
    store, authority_db, db, issuer, namespace, job_id, _, now, _ = _committed(tmp_path)
    try:
        db.execute("BEGIN")
        with pytest.raises(SourceCorrectionJobHold):
            read_source_correction_job_snapshot(
                db, issuer, namespace, job_id, now_utc=now + 5)
        db.execute("ROLLBACK")
    finally:
        store.close()
        authority_db.close()


def test_correction_apply_rechecks_frozen_identity_inside_v2_write_transaction(tmp_path):
    store, authority_db, db, issuer, namespace, job_id, _, now, coordinator = (
        _committed(tmp_path))
    try:
        db.execute("BEGIN")
        snapshot = read_source_correction_job_snapshot(
            db, issuer, namespace, job_id, now_utc=now)
        db.execute("ROLLBACK")
        port = coordinator._GraphCoordinator__content_fence_v2
        anchor = port.anchors[namespace]
        permit = port.begin_fence(
            namespace=namespace, authority_namespace=anchor.namespace,
            holder="worker-1", generation=snapshot.activation_generation,
            operation="write", operation_id="correction-acquire-1",
            expected_anchor=anchor)
        scope = FenceScope(
            namespace, anchor.namespace, snapshot.activation_generation,
            "write", "correction-acquire-1", permit, anchor,
            NamespaceEpoch(*namespace.as_tuple, snapshot.graph_epoch),
            snapshot.graph_revision)
        assert port.validate_fence(scope) == permit
        with store._lock:
            db.execute("BEGIN IMMEDIATE")
            acquired = acquire_source_correction_job_in_transaction(
                db, issuer, snapshot, scope, "worker-1", now_utc=now,
                lease_seconds=1)
            assert acquired.phase == "running" and acquired.fence == 1
            assert db.execute("SELECT phase FROM graph_bundle_outbox WHERE outbox_ref=?",
                              (snapshot.outbox_ref,)).fetchone() == ("pending",)
            db.execute("ROLLBACK")
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?",
                       (snapshot.head_refs[0],))
            with pytest.raises(SourceCorrectionJobHold):
                acquire_source_correction_job_in_transaction(
                    db, issuer, snapshot, scope, "worker-1", now_utc=now,
                    lease_seconds=1)
            db.execute("ROLLBACK")
        assert db.execute("SELECT phase FROM runtime_jobs WHERE job_id=?",
                          (job_id,)).fetchone() == ("queued",)
    finally:
        store.close()
        authority_db.close()
