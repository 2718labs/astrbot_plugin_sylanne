"""Original D11 D13 worker against the ProductionGraphStore V2 fence."""

import json
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from sylanne3.graph_coordinator import StaleRead, UnavailableGuard
from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2
from sylanne3.runtime.d13_precompression_job import D13PrecompressionHold
from sylanne3.runtime.budget import get_budget_lease
from sylanne3.runtime.jobs import get_job

from test_graph_v2_provisioning import (  # noqa: F401
    bundle_system, restart_bundle_system,
)
from test_d13_deterministic_schedule_v2 import _ready


def _scheduled(bundle_system, monkeypatch):
    store, graph, authority, lease, policy, token = _ready(
        bundle_system, monkeypatch)
    _, job = graph.schedule_d13_deterministic_precompression_v2(
        authority, lease, scene_ref="scene:test")
    return store, graph, authority, lease, policy, token, job


def _cold_worker(bundle_system, old_graph, authority, policy, tmp_path,
                 synthetic_window):
    store, graph, port, _, _, authority_db = restart_bundle_system(
        bundle_system, tmp_path)
    port.read_ingress_clock = bundle_system[3].read_ingress_clock
    graph._GraphCoordinator__scene_clock_policy = (
        old_graph._GraphCoordinator__scene_clock_policy)
    graph._GraphCoordinator__d13_precompression_policy = policy
    bootstrap = graph._GraphCoordinator__bootstrap
    graph.register_provider(
        bootstrap, "d11", SimpleNamespace(validate=lambda *_: True),
        "d11.test.v1", "c" * 64)
    lease, capability = graph.grant(
        bootstrap, actor=authority.actor, issuer_domain="d11",
        namespace=authority.namespace, domains=("d11",),
        activation_generation=1, operation_id="d13-test-schedule")
    graph.read_current_d13_conversation_window_v1 = synthetic_window
    return (store, graph, port, lease,
            replace(authority, capability_ref=capability), authority_db)


@pytest.mark.parametrize("started", [False, True])
def test_expired_original_job_revokes_and_settles_fixed_unit(
        bundle_system, monkeypatch, started):
    store, graph, authority, lease, policy, _, queued = _scheduled(
        bundle_system, monkeypatch)
    running = (graph.acquire_d13_deterministic_precompression_job_v2(
        authority, lease, queued.job_id, lease_seconds=120) if started else None)
    before = get_budget_lease(store._db, policy.lease_id)
    with pytest.raises(UnavailableGuard, match="deadline is live"):
        graph.expire_d13_deterministic_precompression_job_v2(
            authority, lease, queued.job_id)
    assert get_job(store._db, queued.job_id) == (running or queued)
    assert get_budget_lease(store._db, policy.lease_id) == before
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_d13_worker_attempts_v2 "
        "WHERE operation_id LIKE 'd13:expire:%'"
    ).fetchone() == (0,)

    port = bundle_system[3]
    clock_policy = graph._GraphCoordinator__scene_clock_policy

    def expired_clock(_policy):
        before_mono = time.monotonic()
        after_mono = time.monotonic()
        utc = time.time() + 1000
        return VerifiedIngressClockV2(
            IngressClockSampleV2(
                port.installation_grant.authority_id,
                port.installation_grant.installation_id,
                clock_policy.source_id, utc, after_mono,
                "fixture-expired-epoch", 0.001),
            before_mono, after_mono, utc + 0.001)

    monkeypatch.setattr(port, "read_ingress_clock", expired_clock)
    budget, cancelled = graph.expire_d13_deterministic_precompression_job_v2(
        authority, lease, queued.job_id)
    assert budget.status == "settled" and cancelled.phase == "cancelled"
    assert cancelled.usage == ({"d13_compute_units": 1} if started else {})
    assert get_budget_lease(store._db, policy.lease_id).reserved.get(
        "d13_compute_units", 0) == 0
    assert get_budget_lease(store._db, policy.lease_id).used.get(
        "d13_compute_units", 0) == int(started)
    assert graph.expire_d13_deterministic_precompression_job_v2(
        authority, lease, queued.job_id) == (budget, cancelled)
    assert store._db.execute(
        "SELECT state FROM runtime_budget_reservations WHERE lease_id=? "
        "AND operation_id=?", (policy.lease_id, queued.operation_id)
    ).fetchone() == ("settled",)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_atoms WHERE type_name=?",
        ("d13.compressed_turn_block.v2",)).fetchone() == (0,)
    if started:
        with pytest.raises(UnavailableGuard, match="fence differs"):
            graph.complete_d13_deterministic_precompression_job_v2(
                authority, lease, queued.job_id, fence=running.fence)


def test_worker_adopts_one_standby_and_settles_one_technical_unit(
        bundle_system, monkeypatch):
    store, graph, authority, lease, policy, _, queued = _scheduled(
        bundle_system, monkeypatch)
    running = graph.acquire_d13_deterministic_precompression_job_v2(
        authority, lease, queued.job_id, lease_seconds=120)
    assert running.phase == "running" and running.fence == 1
    assert graph.acquire_d13_deterministic_precompression_job_v2(
        authority, lease, queued.job_id, lease_seconds=120) == running
    cache, budget, completed = (
        graph.complete_d13_deterministic_precompression_job_v2(
            authority, lease, queued.job_id, fence=running.fence))
    assert cache.action == "adopt" and budget.status == "settled"
    assert completed.phase == "completed"
    assert completed.usage == {"d13_compute_units": 1}
    assert get_job(store._db, queued.job_id) == completed
    assert get_budget_lease(store._db, policy.lease_id).used[
        "d13_compute_units"] == 1
    row = store._db.execute(
        "SELECT value,revision FROM graph_atoms WHERE type_name=?",
        ("d13.compressed_turn_block.v2",)).fetchone()
    assert json.loads(row[0])["status"] == "standby" and row[1] == 1
    assert graph.complete_d13_deterministic_precompression_job_v2(
        authority, lease, queued.job_id, fence=running.fence) == (
            cache, budget, completed)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_events WHERE session='d13-precompression'"
    ).fetchone()[0] == 1


def test_worker_lost_finish_replays_only_original_atomic_receipt(
        bundle_system, monkeypatch):
    store, graph, authority, lease, policy, _, queued = _scheduled(
        bundle_system, monkeypatch)
    running = graph.acquire_d13_deterministic_precompression_job_v2(
        authority, lease, queued.job_id, lease_seconds=120)
    port = bundle_system[3]
    port.lose_finish_after_durable = True
    with pytest.raises(RuntimeError, match="finish response lost"):
        graph.complete_d13_deterministic_precompression_job_v2(
            authority, lease, queued.job_id, fence=running.fence)
    monkeypatch.setattr(graph, "_v2_graph_stamp", lambda *_: (_ for _ in ()).throw(
        AssertionError("committed replay must not require the old graph head")))
    cache, budget, completed = (
        graph.complete_d13_deterministic_precompression_job_v2(
            authority, lease, queued.job_id, fence=running.fence))
    assert cache.action == "adopt" and budget.status == "settled"
    assert completed.phase == "completed"
    assert get_budget_lease(store._db, policy.lease_id).used[
        "d13_compute_units"] == 1
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_events WHERE session='d13-precompression'"
    ).fetchone() == (1,)


def test_worker_lost_begin_response_recovers_original_active_permit(
        bundle_system, monkeypatch):
    store, graph, authority, lease, policy, _, queued = _scheduled(
        bundle_system, monkeypatch)
    running = graph.acquire_d13_deterministic_precompression_job_v2(
        authority, lease, queued.job_id, lease_seconds=120)
    bundle_system[3].lose_begin_after_durable = True
    cache, budget, completed = (
        graph.complete_d13_deterministic_precompression_job_v2(
            authority, lease, queued.job_id, fence=running.fence))
    assert cache.action == "adopt" and budget.status == "settled"
    assert completed.phase == "completed"
    assert get_budget_lease(store._db, policy.lease_id).used[
        "d13_compute_units"] == 1


@pytest.mark.parametrize("begin_state", ["active", "absent"])
def test_worker_cold_recovery_uses_original_attempt_and_current_window(
        bundle_system, monkeypatch, tmp_path, begin_state):
    store, graph, authority, lease, policy, _, queued = _scheduled(
        bundle_system, monkeypatch)
    running = graph.acquire_d13_deterministic_precompression_job_v2(
        authority, lease, queued.job_id, lease_seconds=120)
    port = bundle_system[3]
    real_get = port.get_fence_operation
    real_begin = port.begin_fence
    if begin_state == "active":
        port.lose_begin_after_durable = True
        monkeypatch.setattr(port, "get_fence_operation",
                            lambda **_: (_ for _ in ()).throw(RuntimeError("query lost")))
    else:
        monkeypatch.setattr(port, "begin_fence",
                            lambda **_: (_ for _ in ()).throw(RuntimeError("before begin")))
    with pytest.raises(UnavailableGuard, match="begin outcome"):
        graph.complete_d13_deterministic_precompression_job_v2(
            authority, lease, queued.job_id, fence=running.fence)
    monkeypatch.setattr(port, "get_fence_operation", real_get)
    monkeypatch.setattr(port, "begin_fence", real_begin)
    attempt = store._db.execute(
        "SELECT attempt_id,permit_json,receipt_json FROM "
        "graph_d13_worker_attempts_v2 WHERE operation_id LIKE 'd13:complete:%'"
    ).fetchone()
    assert attempt[1:] == (None, None)
    before = store._db.execute(
        "SELECT COUNT(*) FROM graph_d13_worker_attempts_v2"
    ).fetchone()[0]
    observed_scopes = []
    original_reader = graph.read_current_d13_conversation_window_v1

    def window_reader(*args, **kwargs):
        observed_scopes.append(kwargs.get("_worker_scope"))
        return original_reader(*args, **kwargs)

    next_store, next_graph, next_port, next_lease, next_authority, next_db = _cold_worker(
        bundle_system, graph, authority, policy, tmp_path, window_reader)
    try:
        cache, budget, completed = (
            next_graph.complete_d13_deterministic_precompression_job_v2(
                next_authority, next_lease, queued.job_id, fence=running.fence))
        assert cache.action == "adopt" and budget.status == "settled"
        assert completed.phase == "completed"
        assert len(observed_scopes) == 1
        assert observed_scopes[0] is not None
        assert observed_scopes[0].operation_id == attempt[0]
        assert next_store._db.execute(
            "SELECT COUNT(*) FROM graph_d13_worker_attempts_v2"
        ).fetchone()[0] == before
        saved = next_store._db.execute(
            "SELECT permit_json,receipt_json FROM graph_d13_worker_attempts_v2 "
            "WHERE attempt_id=?", (attempt[0],)).fetchone()
        assert saved[0] is not None and saved[1] is not None
        assert get_budget_lease(next_store._db, policy.lease_id).used[
            "d13_compute_units"] == 1
    finally:
        next_store.close()
        next_db.close()


def test_worker_recovery_rejects_mismatched_authority_permit(
        bundle_system, monkeypatch):
    store, graph, authority, lease, policy, _, queued = _scheduled(
        bundle_system, monkeypatch)
    running = graph.acquire_d13_deterministic_precompression_job_v2(
        authority, lease, queued.job_id, lease_seconds=120)
    port = bundle_system[3]
    original_get = port.get_fence_operation
    port.lose_begin_after_durable = True
    monkeypatch.setattr(port, "get_fence_operation",
                        lambda **_: (_ for _ in ()).throw(RuntimeError("query lost")))
    with pytest.raises(UnavailableGuard, match="begin outcome"):
        graph.complete_d13_deterministic_precompression_job_v2(
            authority, lease, queued.job_id, fence=running.fence)
    monkeypatch.setattr(port, "get_fence_operation", original_get)
    attempt_id = store._db.execute(
        "SELECT attempt_id FROM graph_d13_worker_attempts_v2 "
        "WHERE operation_id LIKE 'd13:complete:%'"
    ).fetchone()[0]
    anchor = port.anchors[authority.namespace]
    permit, state = original_get(
        namespace=authority.namespace, authority_namespace=anchor.namespace,
        operation_id=attempt_id)
    assert state == "active"
    monkeypatch.setattr(port, "get_fence_operation",
                        lambda **_: (replace(permit, holder="other-holder"), "active"))
    with pytest.raises(UnavailableGuard, match="permit differs"):
        graph.complete_d13_deterministic_precompression_job_v2(
            authority, lease, queued.job_id, fence=running.fence)
    assert store._db.execute(
        "SELECT permit_json,receipt_json FROM graph_d13_worker_attempts_v2 "
        "WHERE attempt_id=?", (attempt_id,)).fetchone() == (None, None)
    assert get_budget_lease(store._db, policy.lease_id).used.get(
        "d13_compute_units", 0) == 0
    monkeypatch.setattr(port, "get_fence_operation", original_get)
    cache, budget, completed = (
        graph.complete_d13_deterministic_precompression_job_v2(
            authority, lease, queued.job_id, fence=running.fence))
    assert cache.action == "adopt" and budget.status == "settled"
    assert completed.phase == "completed"


@pytest.mark.parametrize("fault", ["source", "fence", "deadline", "cache"])
def test_worker_rejects_stale_or_replayed_input_without_partial_settlement(
        bundle_system, monkeypatch, fault):
    store, graph, authority, lease, policy, token, queued = _scheduled(
        bundle_system, monkeypatch)
    running = graph.acquire_d13_deterministic_precompression_job_v2(
        authority, lease, queued.job_id, lease_seconds=120)
    if fault == "source":
        store._db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (token,))
    elif fault == "fence":
        store._db.execute("UPDATE runtime_jobs SET fence=fence+1 WHERE job_id=?",
                          (queued.job_id,))
    elif fault == "deadline":
        store._db.execute(
            "UPDATE runtime_jobs SET lease_expires_utc=? WHERE job_id=?",
            ("2000-01-01T00:00:00Z", queued.job_id))
    else:
        # Same cache identity is occupied even when its content is invalid.
        from sylanne3.domains.d13.precompression import compile_deterministic_candidate
        from sylanne3.domains.d13.provider import block_graph_value
        from sylanne3.graph_types import AtomKey, Owner
        from sylanne3.runtime.d13_precompression_job import plan_from_precompression_job_v1
        window = graph.read_current_d13_conversation_window_v1(
            authority, lease, scene_ref="scene:test", max_slots=policy.max_slots)
        block = compile_deterministic_candidate(
            window, plan_from_precompression_job_v1(running))
        key = AtomKey(Owner("persona", *authority.namespace.as_tuple),
                      "d13.compressed_turn_block.v2", block.block_ref)
        store._db.execute(
            "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,"
            "type_name,name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,1)",
            (key.token, *authority.namespace.as_tuple, "persona", None,
             "d13.compressed_turn_block.v2", block.block_ref, 1,
             json.dumps(block_graph_value(block))))
    with pytest.raises((UnavailableGuard, StaleRead, D13PrecompressionHold,
                        ValueError)):
        graph.complete_d13_deterministic_precompression_job_v2(
            authority, lease, queued.job_id, fence=running.fence)
    assert store._db.execute(
        "SELECT state FROM runtime_budget_reservations WHERE lease_id=? "
        "AND operation_id=?", (policy.lease_id, queued.operation_id)
    ).fetchone() == ("reserved",)
    assert get_budget_lease(store._db, policy.lease_id).used.get(
        "d13_compute_units", 0) == 0
    assert get_job(store._db, queued.job_id).phase == "running"
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_d13_worker_attempts_v2 "
        "WHERE operation_id LIKE 'd13:complete:%' AND receipt_json IS NOT NULL"
    ).fetchone() == (0,)
    if fault == "source":
        assert bundle_system[3].fences._db.execute(
            "SELECT COUNT(*) FROM authority_v2_fences WHERE state='active'"
        ).fetchone() == (0,)
