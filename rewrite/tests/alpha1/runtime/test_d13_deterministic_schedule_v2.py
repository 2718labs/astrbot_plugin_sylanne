"""D13 scheduler with real production ledgers and V2 fence.

The source window is a synthetic issuer seam; its source CAS is exercised
against a real graph atom. This file does not certify the D11 window issuer.
"""

from dataclasses import replace
import json
import time
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.graph_coordinator import AuthorityDenied, StaleRead, UnavailableGuard
from sylanne3.host.authority_profile import AdminIngressClockPolicy
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.d13_technical_policy import AdminD13PrecompressionPolicyV1
from sylanne3.runtime_contracts import (
    AuthorityContext, CompletedTurnV1, ConversationWindowProjectionV1,
    VersionedRef,
)

from test_graph_v2_provisioning import bundle_system  # noqa: F401


def _ready(system, monkeypatch):
    store, graph, bootstrap, port, admin, d06_lease, make_bundle, _, d11, _ = system
    graph.commit_domain_bundle(make_bundle(), d06_lease)
    token, revision = store._db.execute(
        "SELECT token,revision FROM graph_atoms WHERE type_name='state'",
    ).fetchone()
    ref = VersionedRef(token, revision)
    # This narrow fixture has no D13 ingress, so install its authority epoch row.
    with store._lock:
        store._db.execute(
            "INSERT OR IGNORE INTO graph_authority_epochs"
            "(bot,persona,access_epoch,delete_epoch) VALUES(?,?,0,0)",
            admin.namespace.as_tuple,
        )
    access_epoch, delete_epoch = store._db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", admin.namespace.as_tuple,
    ).fetchone()
    now = time.time()
    message = "原始已确认发言。" + "x" * 100
    # Each closed turn needs a distinct raw/source/access identity. The old
    # fixture reused one atom for every turn, which D13 correctly rejects as
    # a retransmitted raw reference before it can create a durable job.
    seed = store._db.execute(
        "SELECT owner_kind,subject,type_name,value FROM graph_atoms WHERE token=?",
        (token,),
    ).fetchone()
    source_refs = []
    for index in range(24):
        name = f"d13-test-source-{index}"
        key = AtomKey(Owner("persona", *admin.namespace.as_tuple), "state", name)
        with store._lock:
            store._db.execute(
                "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,"
                "type_name,name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,1)",
                (key.token, *admin.namespace.as_tuple, seed[0], seed[1], seed[2],
                 name, 1, seed[3]),
            )
        source_refs.append(VersionedRef(key.token, 1))
    turns = tuple(CompletedTurnV1(
        "conversation:test", ref, index,
        source_refs[index * 3], source_refs[index * 3 + 1],
        source_refs[index * 3 + 2], "user", message,
        now - 60 + index * 0.001, "confirmed", "not_applicable")
        for index in range(8))
    dependencies = tuple(source for turn in turns for source in (
        turn.raw_ref, turn.source_ref, turn.access_ref))
    window = ConversationWindowProjectionV1(
        admin.namespace, "owner:test", "conversation:test", ref, ref,
        turns, 7, now, dependencies, (ref, *dependencies),
        access_epoch, delete_epoch, 1)
    graph.register_provider(
        bootstrap, "d11", SimpleNamespace(validate=lambda *_: True),
        "d11.test.v1", "c" * 64)
    process_lease, capability = graph.grant(
        bootstrap, actor="d13-test", issuer_domain="d11",
        namespace=admin.namespace, domains=("d11",),
        activation_generation=1, operation_id="d13-test-schedule")
    authority = AuthorityContext(
        "d13-test", "d11", capability, admin.namespace, (), "context",
        (window.conversation_ref,), "policy-1", 1)
    grant = replace(admin.root_grant, version=2,
                    allowed_work_kinds=("encode", "d13.precompress"),
                    max_ceiling={**admin.root_grant.max_ceiling,
                                 "d13_compute_units": 1})
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        store._db.execute(
            "UPDATE runtime_budget_leases SET limits_json=? WHERE lease_id=?",
            (json.dumps({"cpu_ms": 200, "d13_compute_units": 8}),
             grant.lease_id))
        d11.issue_budget_grant(store._db, grant)
        store._db.execute("COMMIT")
    line_bytes = len(f"user: {message}".encode("utf-8"))
    policy = AdminD13PrecompressionPolicyV1(
        admin.namespace, port.installation_grant.installation_id,
        grant.grant_id, grant.version, grant.lease_id,
        line_bytes * 7, {"d13_compute_units": 1}, 300, 16, "d13:cpu")
    graph._GraphCoordinator__d13_precompression_policy = policy
    clock_policy = AdminIngressClockPolicy("test-clock", 0.1, 1.0)
    graph._GraphCoordinator__scene_clock_policy = clock_policy

    def paired_clock(_policy):
        before = time.monotonic()
        utc = time.time()
        after = time.monotonic()
        return VerifiedIngressClockV2(
            IngressClockSampleV2(
                port.installation_grant.authority_id,
                port.installation_grant.installation_id,
                clock_policy.source_id, utc, after,
                "fixture-clock-epoch", 0.001),
            before, after, utc + 0.001)

    monkeypatch.setattr(port, "read_ingress_clock", paired_clock, raising=False)
    monkeypatch.setattr(graph, "read_current_d13_conversation_window_v1",
                        lambda *_args, **_kwargs: window)
    return store, graph, authority, process_lease, policy, token


def test_d13_installed_policy_is_required(bundle_system):
    _, graph, bootstrap, _, admin, *_ = bundle_system
    graph.register_provider(
        bootstrap, "d11", SimpleNamespace(validate=lambda *_: True),
        "d11.test.v1", "c" * 64)
    lease, capability = graph.grant(
        bootstrap, actor="d13-test", issuer_domain="d11",
        namespace=admin.namespace, domains=("d11",),
        activation_generation=1)
    authority = AuthorityContext(
        "d13-test", "d11", capability, admin.namespace, (), "context",
        ("conversation:test",), "policy-1", 1)
    with pytest.raises(UnavailableGuard, match="installed D13 technical"):
        graph.schedule_d13_deterministic_precompression_v2(
            authority, lease, scene_ref="scene:test")


def test_d13_original_schedule_reserves_once_and_replays_without_current_head(
        bundle_system, monkeypatch):
    store, graph, authority, lease, policy, _ = _ready(bundle_system, monkeypatch)
    first = graph.schedule_d13_deterministic_precompression_v2(
        authority, lease, scene_ref="scene:test")
    assert first is not None
    budget, job = first
    assert budget.status == "reserved"
    assert job.work_kind == "d13.precompress" and job.phase == "queued"
    assert job.operator_versions["d11_grant"] == (
        f"{policy.grant_id}:{policy.grant_version}")
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_budget_reservations WHERE lease_id=? "
        "AND operation_id=?", (policy.lease_id, job.operation_id),
    ).fetchone()[0] == 1
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_jobs WHERE job_id=?", (job.job_id,),
    ).fetchone()[0] == 1
    monkeypatch.setattr(graph, "_v2_graph_stamp", lambda *_args: (_ for _ in ()).throw(
        AssertionError("replay must not require the original graph head")))
    assert graph.schedule_d13_deterministic_precompression_v2(
        authority, lease, scene_ref="scene:test",
        original_operation_id=job.operation_id) == first
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_jobs WHERE work_kind='d13.precompress'",
    ).fetchone()[0] == 1


@pytest.mark.parametrize("fault", ["grant", "budget", "source"])
def test_d13_current_grant_budget_and_source_changes_reject_new_schedule(
        bundle_system, monkeypatch, fault):
    store, graph, authority, lease, policy, token = _ready(bundle_system, monkeypatch)
    with store._lock:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        if fault == "grant":
            downgraded = replace(
                graph._GraphCoordinator__d11_issuer.current_budget_grant(
                    db, policy.lease_id), version=3,
                allowed_work_kinds=("encode",))
            graph._GraphCoordinator__d11_issuer.issue_budget_grant(db, downgraded)
        elif fault == "budget":
            db.execute(
                "UPDATE runtime_budget_leases SET reserved_json=? WHERE lease_id=?",
                (json.dumps({"d13_compute_units": 200}), policy.lease_id))
        else:
            db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (token,))
        db.execute("COMMIT")
    with pytest.raises((UnavailableGuard, StaleRead)):
        graph.schedule_d13_deterministic_precompression_v2(
            authority, lease, scene_ref="scene:test")
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_jobs WHERE work_kind='d13.precompress'",
    ).fetchone()[0] == 0


def test_d13_lost_finish_response_replays_original_receipt_and_discovery(
        bundle_system, monkeypatch):
    store, graph, authority, lease, _, _ = _ready(bundle_system, monkeypatch)
    port = graph._GraphCoordinator__content_fence_v2
    finish = port.finish_fence
    lost = False

    def lose_finish(*args, **kwargs):
        nonlocal lost
        result = finish(*args, **kwargs)
        if not lost:
            lost = True
            raise RuntimeError("finish response lost after durable finish")
        return result

    monkeypatch.setattr(port, "finish_fence", lose_finish, raising=False)
    with pytest.raises(RuntimeError, match="finish response lost"):
        graph.schedule_d13_deterministic_precompression_v2(
            authority, lease, scene_ref="scene:test")
    metadata = replace(authority, audience=())
    items = graph.discover_d13_precompression_schedule_attempts_v2(
        metadata, lease)
    assert len(items) == 1
    assert (items[0].conversation_ref, items[0].scene_ref) == (
        "conversation:test", "scene:test")
    result = graph.recover_d13_precompression_schedule_v2(
        authority, lease, original_operation_id=items[0].original_operation_id)
    assert result[0].status == "reserved"
    assert graph.schedule_d13_deterministic_precompression_v2(
        authority, lease, scene_ref="scene:test") == result
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_jobs WHERE work_kind='d13.precompress'",
    ).fetchone()[0] == 1
    assert store._db.execute(
        "SELECT finish_confirmed FROM graph_d13_precompression_attempts_v2",
    ).fetchone() == (1,)


def test_d13_lost_begin_response_recovers_under_original_write_permit(
        bundle_system, monkeypatch):
    store, graph, authority, lease, _, _ = _ready(bundle_system, monkeypatch)
    port = graph._GraphCoordinator__content_fence_v2
    begin = port.begin_fence
    begin_ids = []
    lost = False

    def lose_begin(*args, **kwargs):
        nonlocal lost
        begin_ids.append(kwargs["operation_id"])
        result = begin(*args, **kwargs)
        if not lost:
            lost = True
            raise RuntimeError("begin response lost after durable begin")
        return result

    monkeypatch.setattr(port, "begin_fence", lose_begin, raising=False)
    with pytest.raises(RuntimeError, match="begin response lost"):
        graph.schedule_d13_deterministic_precompression_v2(
            authority, lease, scene_ref="scene:test")
    assert store._db.execute(
        "SELECT permit_json,receipt_json FROM graph_d13_precompression_attempts_v2",
    ).fetchone() == (None, None)
    previous_window = graph.read_current_d13_conversation_window_v1
    seen_scopes = []

    def scoped_window(*args, **kwargs):
        seen_scopes.append(kwargs.get("_schedule_scope"))
        return previous_window(*args, **kwargs)

    monkeypatch.setattr(graph, "read_current_d13_conversation_window_v1",
                        scoped_window)
    item, = graph.discover_d13_precompression_schedule_attempts_v2(
        replace(authority, audience=()), lease)
    result = graph.recover_d13_precompression_schedule_v2(
        authority, lease, original_operation_id=item.original_operation_id)
    assert result[0].status == "reserved" and result[1].phase == "queued"
    assert len(begin_ids) == 2 and begin_ids[0] == begin_ids[1]
    assert seen_scopes and seen_scopes[-1].operation_id == begin_ids[0]
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_budget_reservations WHERE operation_id=?",
        (item.original_operation_id,),
    ).fetchone()[0] == 1
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_jobs WHERE work_kind='d13.precompress'",
    ).fetchone()[0] == 1


def test_d13_lost_begin_then_changed_source_holds_without_second_job(
        bundle_system, monkeypatch):
    store, graph, authority, lease, _, token = _ready(bundle_system, monkeypatch)
    port = graph._GraphCoordinator__content_fence_v2
    begin = port.begin_fence
    lost = False

    def lose_begin(*args, **kwargs):
        nonlocal lost
        result = begin(*args, **kwargs)
        if not lost:
            lost = True
            raise RuntimeError("begin response lost")
        return result

    monkeypatch.setattr(port, "begin_fence", lose_begin, raising=False)
    with pytest.raises(RuntimeError, match="begin response lost"):
        graph.schedule_d13_deterministic_precompression_v2(
            authority, lease, scene_ref="scene:test")
    item, = graph.discover_d13_precompression_schedule_attempts_v2(
        replace(authority, audience=()), lease)
    with store._lock:
        store._db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (token,))
    with pytest.raises((UnavailableGuard, StaleRead)):
        graph.recover_d13_precompression_schedule_v2(
            authority, lease, original_operation_id=item.original_operation_id)
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_jobs WHERE work_kind='d13.precompress'",
    ).fetchone()[0] == 0
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_budget_reservations WHERE operation_id=?",
        (item.original_operation_id,),
    ).fetchone()[0] == 0
    row = store._db.execute(
        "SELECT attempt_id,anchor_json,rejected_json,finish_confirmed "
        "FROM graph_d13_precompression_attempts_v2",
    ).fetchone()
    assert row[2] is not None and row[3] == 1
    _, state = port.get_fence_operation(
        namespace=authority.namespace,
        authority_namespace=json.loads(row[1])["namespace"],
        operation_id=row[0])
    assert state == "finished"
    assert graph.discover_d13_precompression_schedule_attempts_v2(
        replace(authority, audience=()), lease) == ()


def test_d13_deadline_crossing_at_commit_rejects_original_write_fence(
        bundle_system, monkeypatch):
    store, graph, authority, lease, _, _ = _ready(bundle_system, monkeypatch)
    port = graph._GraphCoordinator__content_fence_v2
    clock_policy = graph._GraphCoordinator__scene_clock_policy

    def future_clock(_policy):
        before = time.monotonic()
        after = time.monotonic()
        utc = time.time() + 1000
        return VerifiedIngressClockV2(
            IngressClockSampleV2(
                port.installation_grant.authority_id,
                port.installation_grant.installation_id,
                clock_policy.source_id, utc, after,
                "fixture-future-epoch", 0.001),
            before, after, utc + 0.001)

    monkeypatch.setattr(port, "read_ingress_clock", future_clock, raising=False)
    with pytest.raises(UnavailableGuard, match="deadline elapsed"):
        graph.schedule_d13_deterministic_precompression_v2(
            authority, lease, scene_ref="scene:test")
    attempt = store._db.execute(
        "SELECT attempt_id,anchor_json,rejected_json,finish_confirmed "
        "FROM graph_d13_precompression_attempts_v2",
    ).fetchone()
    assert attempt[2] is not None and attempt[3] == 1
    _, state = port.get_fence_operation(
        namespace=authority.namespace,
        authority_namespace=json.loads(attempt[1])["namespace"],
        operation_id=attempt[0])
    assert state == "finished"
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_jobs WHERE work_kind='d13.precompress'",
    ).fetchone()[0] == 0


def test_d13_recovery_deadline_crossing_rejects_original_write_fence(
        bundle_system, monkeypatch):
    store, graph, authority, lease, _, _ = _ready(bundle_system, monkeypatch)
    port = graph._GraphCoordinator__content_fence_v2
    begin = port.begin_fence
    lost = False

    def lose_begin(*args, **kwargs):
        nonlocal lost
        result = begin(*args, **kwargs)
        if not lost:
            lost = True
            raise RuntimeError("begin response lost")
        return result

    monkeypatch.setattr(port, "begin_fence", lose_begin, raising=False)
    with pytest.raises(RuntimeError, match="begin response lost"):
        graph.schedule_d13_deterministic_precompression_v2(
            authority, lease, scene_ref="scene:test")
    item, = graph.discover_d13_precompression_schedule_attempts_v2(
        replace(authority, audience=()), lease)
    with pytest.raises(AuthorityDenied, match="original conversation audience"):
        graph.recover_d13_precompression_schedule_v2(
            replace(authority, audience=()), lease,
            original_operation_id=item.original_operation_id)
    clock_policy = graph._GraphCoordinator__scene_clock_policy

    def future_clock(_policy):
        before = time.monotonic()
        after = time.monotonic()
        utc = time.time() + 1000
        return VerifiedIngressClockV2(
            IngressClockSampleV2(
                port.installation_grant.authority_id,
                port.installation_grant.installation_id,
                clock_policy.source_id, utc, after,
                "fixture-future-recovery", 0.001),
            before, after, utc + 0.001)

    monkeypatch.setattr(port, "read_ingress_clock", future_clock, raising=False)
    with pytest.raises(UnavailableGuard, match="deadline elapsed"):
        graph.recover_d13_precompression_schedule_v2(
            authority, lease,
            original_operation_id=item.original_operation_id)
    attempt = store._db.execute(
        "SELECT attempt_id,anchor_json,rejected_json,finish_confirmed "
        "FROM graph_d13_precompression_attempts_v2",
    ).fetchone()
    assert attempt[2] is not None and attempt[3] == 1
    _, state = port.get_fence_operation(
        namespace=authority.namespace,
        authority_namespace=json.loads(attempt[1])["namespace"],
        operation_id=attempt[0])
    assert state == "finished"
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_budget_reservations WHERE operation_id=?",
        (item.original_operation_id,),
    ).fetchone()[0] == 0
