"""Startup discovery reads only durable, still eligible first ingress work."""

import sqlite3
from types import SimpleNamespace

import pytest

from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.host.authority_profile import (
    AdminD03ArrivalPolicy, AdminD03SelfIdentityProjectionPolicy,
    AdminD04EncodingBaselinePolicy,
)
from sylanne3.memory_types import access_key

from test_d03_self_projection_commit import projection_case, _commit
from test_first_ingress_job_acquire_v2 import _op, _worker, FixedEncodingRequestIssuer


def _baseline(case):
    _, coordinator, bootstrap, namespace, job_id, original, policy, _, clock, _ = case
    _commit(case)
    coordinator.commit_d04_encoding_baseline_v1(
        bootstrap, namespace, job_id, original, policy,
        AdminD04EncodingBaselinePolicy(30.0, {"cpu_ms": 2},
                                        "baseline-snapshot", "baseline-resource"),
        clock)


def test_unacquired_requires_baseline_and_survives_sqlite_reopen(projection_case):
    case = projection_case
    store, coordinator, bootstrap, namespace, job_id, original, *_ = case
    assert coordinator.discover_first_ingress_unacquired_v1(
        bootstrap, namespace).items == ()
    _baseline(case)
    page = coordinator.discover_first_ingress_unacquired_v1(bootstrap, namespace)
    assert len(page.items) == 1
    item = page.items[0]
    assert (item.job_id, item.original_operation_id) == (job_id, original)
    assert item.envelope.text == "hello"
    assert item.envelope.lineage.source_ref == "b" * 64
    assert page.next_after_job_id is None
    path = store._db.execute("PRAGMA database_list").fetchone()[2]
    store._db.close()
    store._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    assert coordinator.discover_first_ingress_unacquired_v1(
        bootstrap, namespace).items == (item,)


def test_unacquired_keyset_crosses_more_than_eight_hold_rows(projection_case):
    case = projection_case
    store, coordinator, bootstrap, namespace, job_id, *_ = case
    _baseline(case)
    db = store._db
    columns = [row[1] for row in db.execute("PRAGMA table_info(runtime_jobs)")]
    original = db.execute("SELECT * FROM runtime_jobs WHERE job_id=?", (job_id,)).fetchone()
    for index in range(10):
        row = list(original)
        row[columns.index("job_id")] = f"encode-0000000000000000000000{index:02d}"
        db.execute(
            "INSERT INTO runtime_jobs VALUES (" + ",".join("?" for _ in row) + ")",
            row)
    first = coordinator.discover_first_ingress_unacquired_v1(
        bootstrap, namespace, limit=8)
    assert first.items == ()
    assert first.next_after_job_id is not None
    second = coordinator.discover_first_ingress_unacquired_v1(
        bootstrap, namespace, after_job_id=first.next_after_job_id, limit=8)
    assert [item.job_id for item in second.items] == [job_id]
    assert second.next_after_job_id is None
    assert coordinator.discover_first_ingress_unacquired_v1(
        bootstrap, namespace, after_job_id=first.next_after_job_id,
        limit=8).items == second.items


@pytest.mark.parametrize("mutation", ["access", "fingerprint", "job", "acquire"])
def test_unacquired_fails_closed_on_changed_proof(projection_case, mutation):
    case = projection_case
    store, coordinator, bootstrap, namespace, job_id, original, *_ = case
    _baseline(case)
    db = store._db
    if mutation == "access":
        db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (
            access_key(*namespace.as_tuple, "b" * 64).token,))
    elif mutation == "fingerprint":
        db.execute("UPDATE graph_first_ingress_identity_v1 SET "
                   "content_fingerprint=? WHERE operation_id=?", ("0" * 64, original))
    elif mutation == "job":
        db.execute("UPDATE runtime_jobs SET cancel_epoch=1 WHERE job_id=?", (job_id,))
    else:
        coordinator._GraphCoordinator__scene_clock_policy = case[8]
        coordinator._GraphCoordinator__encoding_request_issuer = FixedEncodingRequestIssuer()
        port = coordinator._GraphCoordinator__content_fence_v2
        original_clock = port.read_ingress_clock

        def paired_clock(policy):
            reading = original_clock(policy)
            reading.sample = SimpleNamespace(
                epoch="fixture-clock-epoch", source_id=case[8].source_id)
            return reading

        port.read_ingress_clock = paired_clock
        acquire_id = _op(coordinator, job_id)
        authority, lease = _worker(
            coordinator, bootstrap, namespace, operation_id=acquire_id)
        coordinator.acquire_first_ingress_encoding_job_v3(
            authority, lease, job_id, acquire_id, lease_seconds=30)
    try:
        page = coordinator.discover_first_ingress_unacquired_v1(
            bootstrap, namespace)
    except UnavailableGuard:
        return
    assert page.items == ()
