"""A new encoding acquire freezes the earlier committed D04 baseline."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.host.authority_profile import AdminD04EncodingBaselinePolicy
from sylanne3.runtime.encoding_call_binding import load_binding

from test_d03_self_projection_commit import projection_case, _commit
from test_first_ingress_job_acquire_v2 import (
    FixedEncodingRequestIssuer, _op, _worker,
)


def _prepare_worker(case):
    store, coordinator, bootstrap, namespace, job_id, _, _, _, clock, _ = case
    port = coordinator._GraphCoordinator__content_fence_v2
    original_clock = port.read_ingress_clock

    def paired_clock(policy):
        reading = original_clock(policy)
        reading.sample = SimpleNamespace(
            epoch="fixture-clock-epoch", source_id=clock.source_id)
        return reading

    port.read_ingress_clock = paired_clock
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator._GraphCoordinator__encoding_request_issuer = FixedEncodingRequestIssuer()
    acquire_id = _op(coordinator, job_id)
    authority, lease = _worker(
        coordinator, bootstrap, namespace, operation_id=acquire_id)
    return authority, lease, acquire_id


def test_v3_acquire_freezes_real_baseline_and_history_context(projection_case):
    case = projection_case
    store, coordinator, bootstrap, namespace, job_id, ingress_op, policy, _, clock, _ = case
    _commit(case)
    coordinator.commit_d04_encoding_baseline_v1(
        bootstrap, namespace, job_id, ingress_op, policy,
        AdminD04EncodingBaselinePolicy(
            30.0, {"cpu_ms": 2}, "baseline-snapshot", "baseline-resource"),
        clock)
    authority, lease, acquire_id = _prepare_worker(case)
    acquired = coordinator.acquire_first_ingress_encoding_job_v3(
        authority, lease, job_id, acquire_id, lease_seconds=30)
    assert coordinator.acquire_first_ingress_encoding_job_v3(
        authority, lease, job_id, acquire_id, lease_seconds=30) == acquired
    binding = load_binding(store._db, namespace, job_id)
    assert binding.request["schema"] == "sylanne.first-ingress-encoding-call.v3"
    assert binding.request["baseline"]["baseline_revision"] == 1
    current_authority = replace(authority, worker_fence=acquired.fence)
    assert coordinator.read_first_ingress_encoding_binding_v2(
        current_authority, lease, job_id, acquire_id) == binding
    prepared, draft, _ = coordinator.read_first_ingress_model_egress_preparation_v2(
        current_authority, lease, job_id, acquire_id)
    assert prepared == binding
    assert (draft.call_id, draft.request_digest, draft.worker_fence) == (
        binding.call_id, binding.model_request_digest, acquired.fence)
    context = coordinator.read_first_ingress_original_model_result_context_v1(
        current_authority, lease,
        job_id, acquire_id)
    assert context.binding_digest == binding.binding_digest


def test_v3_acquire_without_baseline_leaves_no_intent(projection_case):
    case = projection_case
    store, coordinator, _, _, job_id, *_ = case
    authority, lease, acquire_id = _prepare_worker(case)
    with pytest.raises(UnavailableGuard, match="baseline"):
        coordinator.acquire_first_ingress_encoding_job_v3(
            authority, lease, job_id, acquire_id, lease_seconds=30)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_job_acquire_intents_v2"
    ).fetchone() == (0,)


def test_v3_acquire_rejects_invalidated_committed_baseline(projection_case):
    case = projection_case
    store, coordinator, bootstrap, namespace, job_id, ingress_op, policy, _, clock, _ = case
    _commit(case)
    coordinator.commit_d04_encoding_baseline_v1(
        bootstrap, namespace, job_id, ingress_op, policy,
        AdminD04EncodingBaselinePolicy(
            30.0, {"cpu_ms": 2}, "baseline-snapshot", "baseline-resource"),
        clock)
    store._db.execute(
        "UPDATE graph_atoms SET valid=0 WHERE type_name='d04.encoding_baseline.v1'")
    store._db.commit()
    authority, lease, acquire_id = _prepare_worker(case)
    with pytest.raises(UnavailableGuard, match="baseline proof"):
        coordinator.acquire_first_ingress_encoding_job_v3(
            authority, lease, job_id, acquire_id, lease_seconds=30)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_job_acquire_intents_v2"
    ).fetchone() == (0,)


def test_v3_worker_reads_hold_when_committed_baseline_is_invalidated(projection_case):
    case = projection_case
    store, coordinator, bootstrap, namespace, job_id, ingress_op, policy, _, clock, _ = case
    _commit(case)
    coordinator.commit_d04_encoding_baseline_v1(
        bootstrap, namespace, job_id, ingress_op, policy,
        AdminD04EncodingBaselinePolicy(
            30.0, {"cpu_ms": 2}, "baseline-snapshot", "baseline-resource"),
        clock)
    authority, lease, acquire_id = _prepare_worker(case)
    acquired = coordinator.acquire_first_ingress_encoding_job_v3(
        authority, lease, job_id, acquire_id, lease_seconds=30)
    current_authority = replace(authority, worker_fence=acquired.fence)
    store._db.execute(
        "UPDATE graph_atoms SET valid=0 WHERE type_name='d04.encoding_baseline.v1'")
    store._db.commit()

    with pytest.raises(UnavailableGuard, match="baseline proof"):
        coordinator.read_first_ingress_encoding_binding_v2(
            current_authority, lease, job_id, acquire_id)
    with pytest.raises(UnavailableGuard, match="baseline proof"):
        coordinator.read_first_ingress_model_egress_preparation_v2(
            current_authority, lease, job_id, acquire_id)
    with pytest.raises(UnavailableGuard, match="baseline proof"):
        coordinator.read_first_ingress_original_model_result_context_v1(
            current_authority, lease, job_id, acquire_id)
