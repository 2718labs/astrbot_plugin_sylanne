"""Production V2 acquisition leaves a correction pending for domain reevaluation."""

import json
import time
from types import SimpleNamespace

import pytest

from sylanne3.graph_coordinator import (
    JobAcquireOutcomeUnknown, UnavailableGuard,
    source_correction_acquire_operation_id,
)
from sylanne3.runtime_contracts import AuthorityContext
from sylanne3.runtime.source_correction_job import SourceCorrectionJobHold

from test_source_correction_commit_v2 import _case


def _ready(tmp_path):
    case, request, kwargs, *_ = _case(tmp_path)
    store, authority_db, coordinator, namespace = case
    receipt = coordinator.commit_source_correction_v1(request=request, **kwargs)
    db = store._db
    (job_id,) = db.execute(
        "SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
        "AND operation_id=?", namespace.as_tuple + (request.operation_id,),
    ).fetchone()
    acquire_id = source_correction_acquire_operation_id(
        namespace, job_id, request.operation_id, "correction-worker", 1,
        "a" * 32)
    lease, capability = coordinator.grant(
        coordinator._GraphCoordinator__bootstrap,
        actor="correction-worker", issuer_domain="d11", namespace=namespace,
        domains=("d11",), activation_generation=1,
        operation_id=acquire_id)
    authority = AuthorityContext(
        "correction-worker", "d11", capability, namespace, ("activity",),
        "consolidation", ("internal",), "d11-policy", 1)
    return (store, authority_db, coordinator, namespace, receipt,
            job_id, acquire_id, authority, lease)


def test_correction_job_acquire_commits_job_only_and_replays(tmp_path):
    (store, authority_db, coordinator, namespace, receipt,
     job_id, acquire_id, authority, lease) = _ready(tmp_path)
    try:
        acquired = coordinator._acquire_source_correction_job_v1(
            authority, lease, job_id, acquire_id, lease_seconds=10)
        assert acquired.phase == "running" and acquired.fence == 1
        assert coordinator._acquire_source_correction_job_v1(
            authority, lease, job_id, acquire_id, lease_seconds=10) == acquired
        with pytest.raises(UnavailableGuard, match="HOLD"):
            coordinator._acquire_source_correction_job_v1(
                authority, lease, job_id, acquire_id, lease_seconds=9)
        db = store._db
        assert db.execute(
            "SELECT COUNT(*) FROM graph_job_acquire_receipts_v2 WHERE "
            "bot=? AND persona=? AND acquire_operation_id=?",
            namespace.as_tuple + (acquire_id,),
        ).fetchone() == (1,)
        assert db.execute(
            "SELECT phase FROM graph_bundle_outbox WHERE outbox_ref=?",
            (receipt.reevaluation_outbox_ref,),
        ).fetchone() == ("pending",)
        assert db.execute(
            "SELECT valid,json_extract(value,'$.phase') FROM graph_atoms WHERE token=?",
            (receipt.reevaluation_outbox_ref,),
        ).fetchone() == (1, "pending")
        detail = json.loads(db.execute(
            "SELECT receipt_json FROM graph_bundle_operations WHERE "
            "bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (receipt.operation_id,),
        ).fetchone()[0])["source_correction"]
        assert detail["reevaluation_status"] == "pending"
        assert json.loads(db.execute(
            "SELECT value FROM graph_atoms WHERE token=?",
            (detail["correction_head_refs"][0],),
        ).fetchone()[0])["state"] == "pending_reevaluation"
    finally:
        store.close()
        authority_db.close()


def test_correction_job_acquire_replay_holds_after_worker_lease_expires(tmp_path):
    (store, authority_db, coordinator, namespace, _,
     job_id, acquire_id, authority, lease) = _ready(tmp_path)
    try:
        coordinator._acquire_source_correction_job_v1(
            authority, lease, job_id, acquire_id, lease_seconds=10)
        port = coordinator._GraphCoordinator__content_fence_v2
        port.read_ingress_clock = lambda _: SimpleNamespace(
            utc_upper_bound_seconds=time.time() + 12,
            monotonic_after_seconds=time.monotonic())
        with pytest.raises(UnavailableGuard, match="HOLD"):
            coordinator._acquire_source_correction_job_v1(
                authority, lease, job_id, acquire_id, lease_seconds=10)
    finally:
        store.close()
        authority_db.close()


def test_correction_job_acquire_holds_after_signed_quote_revocation(tmp_path):
    (store, authority_db, coordinator, namespace, _,
     job_id, acquire_id, authority, lease) = _ready(tmp_path)
    try:
        db = store._db
        quote_ref = json.loads(db.execute(
            "SELECT operator_versions_json FROM runtime_jobs WHERE job_id=?",
            (job_id,)).fetchone()[0])["resource_quote"]
        db.execute("UPDATE runtime_resource_quotes SET status='revoked' "
                   "WHERE quote_id=?", (quote_ref.rsplit(":", 1)[0],))
        with pytest.raises(UnavailableGuard, match="HOLD"):
            coordinator._acquire_source_correction_job_v1(
                authority, lease, job_id, acquire_id, lease_seconds=10)
        assert db.execute("SELECT COUNT(*) FROM graph_job_acquire_intents_v2 "
                          "WHERE acquire_operation_id=?", (acquire_id,)).fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()


def test_correction_job_acquire_recovers_unknown_begin_without_double_job(tmp_path):
    (store, authority_db, coordinator, namespace, _,
     job_id, acquire_id, authority, lease) = _ready(tmp_path)
    try:
        port = coordinator._GraphCoordinator__content_fence_v2
        port.lose_begin_after_durable = True
        with pytest.raises(JobAcquireOutcomeUnknown):
            coordinator._acquire_source_correction_job_v1(
                authority, lease, job_id, acquire_id, lease_seconds=10)
        acquired = coordinator._acquire_source_correction_job_v1(
            authority, lease, job_id, acquire_id, lease_seconds=10)
        assert acquired.phase == "running" and acquired.fence == 1
        assert store._db.execute("SELECT COUNT(*) FROM graph_job_acquire_receipts_v2 "
                                 "WHERE acquire_operation_id=?",
                                 (acquire_id,)).fetchone() == (1,)
    finally:
        store.close()
        authority_db.close()


def test_correction_job_acquire_rechecks_head_inside_write_transaction(
        tmp_path, monkeypatch):
    (store, authority_db, coordinator, namespace, receipt,
     job_id, acquire_id, authority, lease) = _ready(tmp_path)
    try:
        port = coordinator._GraphCoordinator__content_fence_v2
        begin = port.begin_fence
        detail = json.loads(store._db.execute(
            "SELECT receipt_json FROM graph_bundle_operations WHERE "
            "bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (receipt.operation_id,),
        ).fetchone()[0])["source_correction"]

        def after_read(**kwargs):
            permit = begin(**kwargs)
            if kwargs["operation"] == "write":
                store._db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?",
                                  (detail["correction_head_refs"][0],))
            return permit

        monkeypatch.setattr(port, "begin_fence", after_read)
        with pytest.raises((SourceCorrectionJobHold, UnavailableGuard), match="HOLD"):
            coordinator._acquire_source_correction_job_v1(
                authority, lease, job_id, acquire_id, lease_seconds=10)
        assert store._db.execute("SELECT phase,fence FROM runtime_jobs WHERE job_id=?",
                                 (job_id,)).fetchone() == ("queued", 0)
        assert store._db.execute("SELECT COUNT(*) FROM graph_job_acquire_receipts_v2 "
                                 "WHERE acquire_operation_id=?",
                                 (acquire_id,)).fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()


def test_correction_job_acquire_replays_after_unknown_finish(tmp_path, monkeypatch):
    (store, authority_db, coordinator, namespace, _,
     job_id, acquire_id, authority, lease) = _ready(tmp_path)
    try:
        port = coordinator._GraphCoordinator__content_fence_v2
        finish = port.finish_fence

        def lose_write_finish(scope, *, request_id, request_digest):
            if scope.operation == "write":
                port.lose_finish_after_durable = True
            return finish(scope, request_id=request_id,
                          request_digest=request_digest)

        monkeypatch.setattr(port, "finish_fence", lose_write_finish)
        with pytest.raises(JobAcquireOutcomeUnknown):
            coordinator._acquire_source_correction_job_v1(
                authority, lease, job_id, acquire_id, lease_seconds=10)
        acquired = coordinator._acquire_source_correction_job_v1(
            authority, lease, job_id, acquire_id, lease_seconds=10)
        assert acquired.phase == "running" and acquired.fence == 1
        assert store._db.execute("SELECT COUNT(*) FROM graph_job_acquire_receipts_v2 "
                                 "WHERE acquire_operation_id=?",
                                 (acquire_id,)).fetchone() == (1,)
    finally:
        store.close()
        authority_db.close()
