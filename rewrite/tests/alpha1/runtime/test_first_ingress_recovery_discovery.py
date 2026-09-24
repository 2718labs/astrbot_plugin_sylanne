"""Original V3 work can be found without granting another dispatch."""

from dataclasses import asdict, replace
import json
import time
from types import SimpleNamespace

import pytest

from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (
    AtomKey, GraphCandidate, GraphVersion, GraphWrite, NamespaceEpoch, Owner,
)
from sylanne3.contracts import Event, Scope
from sylanne3.host.authority_profile import AdminD06FirstIngressC02Policy
from sylanne3.host.authority_profile import (
    AdminD03ArrivalPolicy, AdminD03SelfIdentityProjectionPolicy,
    AdminD04EncodingBaselinePolicy,
)
from sylanne3.runtime.encoding_call_binding import load_binding
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime_contracts import NamespaceId

from test_first_ingress_c02_commit import c02_case
from test_first_ingress_job_acquire_v2 import (
    ingress_system, _op, _worker, FixedEncodingRequestIssuer,
)
from test_first_ingress_v2 import ingress_system as base_ingress_system
from test_first_ingress_v2 import _ingress_inputs


def _add_second_v3_job(case):
    store, coordinator, bootstrap, namespace, policy, clock, _, _, _ = case
    host, _, encoding = _ingress_inputs(namespace)
    host = replace(
        host, message_id="second-message", text="second source",
        lineage=replace(
            host.lineage, source_ref="c" * 64))
    encoding = replace(
        encoding, quote_ceiling={"output_tokens": 128})
    coordinator.commit_first_ingress_v2(
        bootstrap, host, policy, clock, encoding)
    source_id = host.lineage.source_ref
    coordinator.commit_d03_message_arrival_v2(
        bootstrap, namespace, source_id, policy,
        AdminD03ArrivalPolicy(30.0, {"cpu_ms": 3},
                              "arrival-snapshot", "arrival-resource"), clock)
    job_id, original_op = store._db.execute(
        "SELECT job_id,operation_id FROM runtime_jobs "
        "WHERE bot_id=? AND persona_id=? AND job_id != "
        "(SELECT job_id FROM runtime_jobs ORDER BY rowid LIMIT 1)",
        namespace.as_tuple).fetchone()
    coordinator.commit_d03_self_identity_projection_v1(
        bootstrap, namespace, job_id, original_op, policy,
        AdminD03SelfIdentityProjectionPolicy(
            30.0, {"cpu_ms": 4}, "projection-snapshot",
            "projection-resource"), clock)
    coordinator.commit_d04_encoding_baseline_v1(
        bootstrap, namespace, job_id, original_op, policy,
        AdminD04EncodingBaselinePolicy(
            30.0, {"cpu_ms": 2}, "baseline-snapshot", "baseline-resource"),
        clock)
    acquire_id = _op(coordinator, job_id, nonce="b" * 32)
    authority, lease = _worker(
        coordinator, bootstrap, namespace, operation_id=acquire_id)
    coordinator.acquire_first_ingress_encoding_job_v3(
        authority, lease, job_id, acquire_id, lease_seconds=30)
    return source_id, job_id, acquire_id


def test_recovery_discovers_original_identity_and_c02_receipt(c02_case):
    store, coordinator, bootstrap, namespace, policy, clock, intent, read, _ = c02_case
    binding = load_binding(store._db, namespace, read.request.job_id)
    page = coordinator.discover_first_ingress_recovery_v1(bootstrap, namespace)
    assert len(page.items) == 1
    item = page.items[0]
    assert item.job_id == read.request.job_id
    assert item.acquire_operation_id == intent.operation_id
    assert item.binding_digest == binding.binding_digest
    assert item.call_id == intent.call_id
    assert item.model_request_digest == intent.request_digest
    assert item.job_phase == "running"
    assert item.recovery_state == "original_fence"
    assert item.c02_operation_digest is None
    exported = json.dumps(asdict(page))
    assert "event_summary" not in exported
    assert "hello" not in exported

    receipt = coordinator.commit_first_ingress_c02_v1(
        bootstrap, intent, read, policy,
        AdminD06FirstIngressC02Policy(
            30.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource"),
        clock)
    completed = coordinator.discover_first_ingress_recovery_v1(
        bootstrap, namespace).items[0]
    assert completed.job_phase == "completed"
    assert completed.recovery_state == "c02_committed"
    assert completed.c02_operation_digest == receipt.operation_digest
    assert completed.c02_commit_seq == receipt.commit_seq
    assert completed.original_worker_fence == item.original_worker_fence


def test_recovery_two_original_v3_jobs_are_discoverable(c02_case):
    _, coordinator, bootstrap, namespace, _, _, _, _, _ = c02_case
    _, job_id, _ = _add_second_v3_job(c02_case)
    page = coordinator.discover_first_ingress_recovery_v1(
        bootstrap, namespace)
    assert len(page.items) == 2
    assert job_id in {item.job_id for item in page.items}


def test_recovery_skips_committed_withdrawal_and_keeps_cursor(c02_case):
    store, coordinator, bootstrap, namespace, _, _, _, _, _ = c02_case
    _add_second_v3_job(c02_case)
    before = coordinator.discover_first_ingress_recovery_v1(
        bootstrap, namespace)
    assert len(before.items) == 2
    withdrawn, healthy = before.items
    source_id = load_binding(
        store._db, namespace, withdrawn.job_id).source_id
    access = access_key(*namespace.as_tuple, source_id)
    source = source_key(*namespace.as_tuple, source_id)
    access_revision, access_json = store._db.execute(
        "SELECT revision,value FROM graph_atoms WHERE token=?",
        (access.token,)).fetchone()
    (source_revision,) = store._db.execute(
        "SELECT revision FROM graph_atoms WHERE token=?",
        (source.token,)).fetchone()
    value = json.loads(access_json)
    value["status"] = "withdrawn"
    capability = coordinator._GraphCoordinator__graph_capability
    metadata = store.graph_recovery_metadata(
        namespace, _capability=capability)
    epoch = GraphStore.graph_epoch(store,
        *namespace.as_tuple, _capability=capability)
    candidate = GraphCandidate(
        Event(Scope(*namespace.as_tuple, "withdrawal"),
              "withdraw-access-for-recovery-test", time.time(),
              "access-withdrawal", {}),
        (GraphVersion(access, access_revision),
         GraphVersion(source, source_revision)),
        (GraphWrite(access, value, (source,)),), (epoch,))
    GraphStore.graph_commit(store, candidate, _capability=capability)
    store._db.execute("BEGIN IMMEDIATE")
    try:
        store.cas_graph_recovery_metadata(
            metadata, metadata.requirements, _capability=capability)
        store._db.execute("COMMIT")
    except BaseException:
        store._db.execute("ROLLBACK")
        raise
    first = coordinator.discover_first_ingress_recovery_v1(
        bootstrap, namespace, limit=1)
    assert first.items == ()
    assert first.next_cursor is not None
    assert source_id not in first.next_cursor
    second = coordinator.discover_first_ingress_recovery_v1(
        bootstrap, namespace, cursor=first.next_cursor, limit=1)
    assert [item.job_id for item in second.items] == [healthy.job_id]
    assert second.next_cursor is None
    assert "second source" not in json.dumps(asdict(second))


def test_recovery_does_not_skip_unproven_first_row_tamper(c02_case):
    store, coordinator, bootstrap, namespace, _, _, _, _, _ = c02_case
    _add_second_v3_job(c02_case)
    first = coordinator.discover_first_ingress_recovery_v1(
        bootstrap, namespace).items[0]
    source_id = load_binding(store._db, namespace, first.job_id).source_id
    store._db.execute(
        "UPDATE graph_atoms SET valid=0 WHERE token=?",
        (access_key(*namespace.as_tuple, source_id).token,))
    with pytest.raises(UnavailableGuard):
        coordinator.discover_first_ingress_recovery_v1(
            bootstrap, namespace, limit=1)


@pytest.mark.parametrize("mutation", ["access", "source", "job"])
def test_recovery_rejects_revoked_or_altered_original(c02_case, mutation):
    store, coordinator, bootstrap, namespace, _, _, _, _, _ = c02_case
    if mutation == "job":
        store._db.execute(
            "UPDATE runtime_jobs SET cancel_epoch=1")
    else:
        store._db.execute(
            "UPDATE graph_atoms SET valid=0 WHERE bot=? AND persona=? "
            "AND type_name=?",
            namespace.as_tuple + (
                "memory.access" if mutation == "access" else "memory.source",))
    with pytest.raises((UnavailableGuard, ValueError)):
        coordinator.discover_first_ingress_recovery_v1(bootstrap, namespace)


def test_recovery_cursor_and_namespace_are_bound(c02_case):
    _, coordinator, bootstrap, namespace, _, _, _, _, _ = c02_case
    with pytest.raises((UnavailableGuard, RuntimeError)):
        coordinator.discover_first_ingress_recovery_v1(
            bootstrap, NamespaceId(namespace.bot_id, "other"))
    with pytest.raises(UnavailableGuard, match="cursor"):
        coordinator.discover_first_ingress_recovery_v1(
            bootstrap, namespace, '{"last_acquire_operation_id":"fake"}')


def test_recovery_does_not_promote_legacy_v2_acquire(ingress_system):
    store, coordinator, bootstrap, _, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator._GraphCoordinator__encoding_request_issuer = FixedEncodingRequestIssuer()
    coordinator.commit_first_ingress_v2(
        bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    acquire_id = _op(coordinator, job_id)
    authority, lease = _worker(
        coordinator, bootstrap, policy.namespace, operation_id=acquire_id)
    coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, acquire_id, lease_seconds=30)
    assert coordinator.discover_first_ingress_recovery_v1(
        bootstrap, policy.namespace).items == ()


def test_recovery_expired_lease_is_hold(c02_case):
    _, coordinator, bootstrap, namespace, _, _, _, _, _ = c02_case
    port = coordinator._GraphCoordinator__content_fence_v2
    original = port.read_ingress_clock
    item = coordinator.discover_first_ingress_recovery_v1(
        bootstrap, namespace).items[0]
    from datetime import datetime
    expiry = datetime.fromisoformat(
        item.original_worker_lease_expires_utc.replace("Z", "+00:00")).timestamp()

    def later(policy):
        reading = original(policy)
        reading.utc_upper_bound_seconds = expiry + 1
        reading.monotonic_after_seconds = time.monotonic()
        return reading

    port.read_ingress_clock = later
    expired = coordinator.discover_first_ingress_recovery_v1(
        bootstrap, namespace).items[0]
    assert expired.recovery_state == "expired_lease_hold"
    assert expired.original_worker_fence == item.original_worker_fence


@pytest.mark.parametrize("type_name", [
    "d04.feeling_state.v1", "d04.mood_field.v1",
])
def test_production_initial_d04_state_requires_authored_root(c02_case, type_name):
    store, coordinator, _, namespace, _, _, _, _, _ = c02_case
    key = AtomKey(Owner("persona", *namespace.as_tuple), type_name, "root")
    bundle = SimpleNamespace(product_advance=None)
    snapshot = SimpleNamespace(get=lambda _: SimpleNamespace(revision=0))
    write = SimpleNamespace(key=key, value={})
    with pytest.raises(UnavailableGuard, match="authored root"):
        coordinator._check_product_advance(store._db, bundle, snapshot, (write,))
