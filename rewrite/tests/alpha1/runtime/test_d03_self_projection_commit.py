"""The first self perspective is an Authority-qualified, priced graph stage."""

from dataclasses import replace

import pytest

from sylanne3.authority_service.v2_self_identity_contract import (
    AuthorityCurrentSelfIdentityV1,
)
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.domains.d04 import AffectAxis, AffectProvider, AffectScheme
from sylanne3.host.authority_profile import (
    AdminD03ArrivalPolicy, AdminD03SelfIdentityProjectionPolicy,
    AdminD04EncodingBaselinePolicy,
)

from test_first_ingress_v2 import _ingress_inputs
from test_scene_binding_v2 import _bind_scene, _scene_case


class FixtureCurrentSelf:
    """Only this test supplies the paired Authority current response."""

    def __init__(self, store, coordinator, port, policy):
        self.store, self.coordinator = store, coordinator
        self.port, self.policy = port, policy
        self.graph_revision_offset = 0
        self.self_ref = "entity:fixture-self"
        self.write_self_ref = None

    def current_self_identity(self, *, namespace, authority_namespace,
                              request_operation_id, permit):
        self.port.outside_graph_lock()
        guard, _ = self.port.get_current_owner_guard_for_fence(
            namespace=namespace, authority_namespace=authority_namespace,
            permit=permit)
        with self.store._lock:
            metadata, epoch = self.coordinator._v2_graph_stamp(namespace)
            role, _, _, _ = self.coordinator._scene_binding_state_locked(
                namespace, guard)
        return AuthorityCurrentSelfIdentityV1(
            namespace, authority_namespace, self.policy.expected_authority_id,
            self.policy.installation_id, self.policy.manifest_digest,
            metadata.requirements.activation_generation,
            metadata.requirements.graph_incarnation, role.head_id,
            metadata.graph_revision + self.graph_revision_offset, epoch.revision,
            f"persona:{namespace.persona_id}",
            self.write_self_ref if permit.operation == "write" and self.write_self_ref
            else self.self_ref,
            "self-map:fixture", 1, 0, "fixture-registration", "a" * 64,
            guard.authorization_revision, guard.authorization_head,
            guard.minimum_revocation_revision, guard.minimum_revocation_epoch,
            request_operation_id, permit,
        )


@pytest.fixture
def projection_case(tmp_path):
    d04 = AffectProvider(active_scheme=AffectScheme(
        "d04.affect.scheme.v1", "scheme-1", "operator-1",
        "parameter:fixture", "coupling:fixture",
        (AffectAxis("care", "normalized", "care"),), ()))
    case = _scene_case(
        tmp_path, enable_ingress=True, arrival_allowed=True,
        extra_specs=d04.type_specs(),
        extra_work_kinds=("d03.self_identity_projection", "d04.encoding_baseline"))
    store, authority_db, port, coordinator, namespace, _, _, policy, bootstrap = case
    coordinator.register_provider(
        bootstrap, "d04", d04, "d04.proposal.v1",
        d04.descriptor.request_schema_hash)
    _bind_scene(case)
    host, clock, encoding = _ingress_inputs(namespace)
    coordinator.commit_first_ingress_v2(
        bootstrap, host, policy, clock, encoding)
    coordinator.commit_d03_message_arrival_v2(
        bootstrap, namespace, host.lineage.source_ref, policy,
        AdminD03ArrivalPolicy(
            30.0, {"cpu_ms": 3}, "arrival-snapshot", "arrival-resource"),
        clock)
    fixture_port = FixtureCurrentSelf(store, coordinator, port, policy)
    coordinator._GraphCoordinator__self_identity_port = fixture_port
    job_id, original_operation_id = store._db.execute(
        "SELECT job_id,operation_id FROM runtime_jobs").fetchone()
    stage_policy = AdminD03SelfIdentityProjectionPolicy(
        30.0, {"cpu_ms": 4}, "projection-snapshot", "projection-resource")
    try:
        yield (store, coordinator, bootstrap, namespace, job_id,
               original_operation_id, policy, stage_policy, clock, fixture_port)
    finally:
        store.close()
        authority_db.close()


def _commit(case):
    _, coordinator, bootstrap, namespace, job_id, original_operation_id, policy, stage_policy, clock, _ = case
    return coordinator.commit_d03_self_identity_projection_v1(
        bootstrap, namespace, job_id, original_operation_id,
        policy, stage_policy, clock)


def test_first_self_projection_commits_mapping_and_perspective(projection_case):
    case = projection_case
    store, *_ = case
    receipt = _commit(case)
    assert receipt.status == "committed"
    assert _commit(case).status == "duplicate"
    with store._lock:
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name='d03.self_identity_mapping.v1' "
            "AND valid=1").fetchone() == (1,)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name='d03.self_perspective.v1' "
            "AND valid=1").fetchone() == (1,)
        assert store._db.execute(
            "SELECT state FROM runtime_budget_reservations WHERE operation_id=?",
            (receipt.operation_id,)).fetchone() == ("reserved",)


def test_stale_authority_graph_stamp_rolls_back_quote(projection_case):
    case = projection_case
    store, *_, fixture_port = case
    fixture_port.graph_revision_offset = 1
    with pytest.raises(UnavailableGuard, match="current read differs"):
        _commit(case)
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_resource_quotes WHERE quote_id LIKE 'd03-self-q-%'"
    ).fetchone() == (0,)


def test_changed_current_self_at_write_fence_cannot_price_stage(projection_case):
    case = projection_case
    store, *_, fixture_port = case
    fixture_port.write_self_ref = "entity:other-self"
    with pytest.raises(UnavailableGuard, match="current self identity changed"):
        _commit(case)
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_resource_quotes WHERE quote_id LIKE 'd03-self-q-%'"
    ).fetchone() == (0,)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_atoms WHERE type_name='d03.self_perspective.v1'"
    ).fetchone() == (0,)


def test_quote_guard_mismatch_rolls_back_signed_quote_and_graph(
        projection_case, monkeypatch):
    case = projection_case
    store, coordinator, *_ = case
    issuer = coordinator._GraphCoordinator__d11_issuer
    original = issuer.issue_d03_self_identity_projection_quote

    def changed_quote(*args, **kwargs):
        quote = original(*args, **kwargs)
        return replace(quote, quote_id="different-quote")

    monkeypatch.setattr(issuer, "issue_d03_self_identity_projection_quote", changed_quote)
    with pytest.raises(Exception, match="quote guard differs"):
        _commit(case)
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_resource_quotes WHERE quote_id LIKE 'd03-self-q-%'"
    ).fetchone() == (0,)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_atoms WHERE type_name='d03.self_perspective.v1'"
    ).fetchone() == (0,)


def test_unfinished_original_write_recovers_before_new_read_or_job_check(
        projection_case, monkeypatch):
    case = projection_case
    store, coordinator, _, _, job_id, _, _, _, _, _ = case
    port = coordinator._GraphCoordinator__content_fence_v2
    finish = port.finish_fence
    lost = {"once": True}

    def lose_original_finish(scope, **kwargs):
        if scope.operation == "write" and lost["once"]:
            lost["once"] = False
            raise RuntimeError("original finish response lost")
        return finish(scope, **kwargs)

    monkeypatch.setattr(port, "finish_fence", lose_original_finish)
    with pytest.raises(RuntimeError, match="original finish response lost"):
        _commit(case)
    store._db.execute("UPDATE runtime_jobs SET phase='running' WHERE job_id=?",
                      (job_id,))
    store._db.commit()
    begin = port.begin_fence

    def no_second_read(**kwargs):
        if kwargs["operation"] == "read":
            raise AssertionError("replay must not open a new content read")
        return begin(**kwargs)

    monkeypatch.setattr(port, "begin_fence", no_second_read)
    assert _commit(case).status == "duplicate"


def test_precommit_active_write_is_closed_without_replaying_business(
        projection_case, monkeypatch):
    case = projection_case
    store, coordinator, *_ = case
    port = coordinator._GraphCoordinator__content_fence_v2
    begin = port.begin_fence
    lost = {"once": True}

    def lose_after_begin(**kwargs):
        permit = begin(**kwargs)
        if kwargs["operation"] == "write" and lost["once"]:
            lost["once"] = False
            raise RuntimeError("process stopped after Authority begin")
        return permit

    monkeypatch.setattr(port, "begin_fence", lose_after_begin)
    with pytest.raises(RuntimeError, match="process stopped"):
        _commit(case)
    with pytest.raises(UnavailableGuard, match="no-commit fence closed"):
        _commit(case)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_atoms WHERE type_name='d03.self_perspective.v1'"
    ).fetchone() == (0,)


def test_crashed_candidate_read_recovers_before_retry(projection_case, monkeypatch):
    case = projection_case
    _, coordinator, *_ = case
    port = coordinator._GraphCoordinator__content_fence_v2
    begin = port.begin_fence
    lost = {"once": True}

    def lose_after_read_begin(**kwargs):
        permit = begin(**kwargs)
        if (kwargs["operation"] == "read"
                and kwargs["operation_id"].startswith("d03-self-read-")
                and lost["once"]):
            lost["once"] = False
            raise RuntimeError("process stopped after candidate read begin")
        return permit

    monkeypatch.setattr(port, "begin_fence", lose_after_read_begin)
    with pytest.raises(RuntimeError, match="candidate read begin"):
        _commit(case)
    assert _commit(case).status == "committed"


def test_d04_baseline_commits_only_after_real_self_stage(projection_case):
    case = projection_case
    store, coordinator, bootstrap, namespace, job_id, original_operation_id, policy, _, clock, _ = case
    baseline_policy = AdminD04EncodingBaselinePolicy(
        30.0, {"cpu_ms": 2}, "baseline-snapshot", "baseline-resource")
    with pytest.raises(UnavailableGuard, match="self perspective"):
        coordinator.commit_d04_encoding_baseline_v1(
            bootstrap, namespace, job_id, original_operation_id,
            policy, baseline_policy, clock)
    _commit(case)
    receipt = coordinator.commit_d04_encoding_baseline_v1(
        bootstrap, namespace, job_id, original_operation_id,
        policy, baseline_policy, clock)
    assert receipt.status == "committed"
    assert coordinator.commit_d04_encoding_baseline_v1(
        bootstrap, namespace, job_id, original_operation_id,
        policy, baseline_policy, clock).status == "duplicate"
    with store._lock:
        row = store._db.execute(
            "SELECT value FROM graph_atoms WHERE type_name='d04.encoding_baseline.v1' "
            "AND valid=1").fetchone()
        assert row is not None
        assert '"salience_interval":null' in row[0]
        assert '"tone_interval":null' in row[0]
        assert store._db.execute(
            "SELECT state FROM runtime_budget_reservations WHERE operation_id=?",
            (receipt.operation_id,)).fetchone() == ("reserved",)


def test_d04_unfinished_original_write_replays_after_job_changes(
        projection_case, monkeypatch):
    case = projection_case
    store, coordinator, bootstrap, namespace, job_id, original_operation_id, policy, _, clock, _ = case
    _commit(case)
    baseline_policy = AdminD04EncodingBaselinePolicy(
        30.0, {"cpu_ms": 2}, "baseline-snapshot", "baseline-resource")
    port = coordinator._GraphCoordinator__content_fence_v2
    finish = port.finish_fence
    lost = {"once": True}

    def lose_baseline_finish(scope, **kwargs):
        if scope.operation == "write" and lost["once"]:
            lost["once"] = False
            raise RuntimeError("baseline finish response lost")
        return finish(scope, **kwargs)

    monkeypatch.setattr(port, "finish_fence", lose_baseline_finish)
    with pytest.raises(RuntimeError, match="baseline finish response lost"):
        coordinator.commit_d04_encoding_baseline_v1(
            bootstrap, namespace, job_id, original_operation_id,
            policy, baseline_policy, clock)
    store._db.execute("UPDATE runtime_jobs SET phase='running' WHERE job_id=?",
                      (job_id,))
    store._db.commit()
    begin = port.begin_fence

    def no_new_read(**kwargs):
        if kwargs["operation"] == "read":
            raise AssertionError("baseline replay must not read current content")
        return begin(**kwargs)

    monkeypatch.setattr(port, "begin_fence", no_new_read)
    assert coordinator.commit_d04_encoding_baseline_v1(
        bootstrap, namespace, job_id, original_operation_id,
        policy, baseline_policy, clock).status == "duplicate"


def test_d04_current_self_replacement_blocks_baseline(projection_case):
    case = projection_case
    store, coordinator, bootstrap, namespace, job_id, original_operation_id, policy, _, clock, current_self = case
    _commit(case)
    current_self.write_self_ref = "entity:replacement-self"
    baseline_policy = AdminD04EncodingBaselinePolicy(
        30.0, {"cpu_ms": 2}, "baseline-snapshot", "baseline-resource")
    with pytest.raises(UnavailableGuard, match="current Authority self differs"):
        coordinator.commit_d04_encoding_baseline_v1(
            bootstrap, namespace, job_id, original_operation_id,
            policy, baseline_policy, clock)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_atoms WHERE type_name='d04.encoding_baseline.v1'"
    ).fetchone() == (0,)
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_resource_quotes WHERE quote_id LIKE 'd04-baseline-q-%'"
    ).fetchone() == (0,)


def test_d04_crashed_queued_read_recovers_before_retry(projection_case, monkeypatch):
    case = projection_case
    _, coordinator, bootstrap, namespace, job_id, original_operation_id, policy, _, clock, _ = case
    _commit(case)
    baseline_policy = AdminD04EncodingBaselinePolicy(
        30.0, {"cpu_ms": 2}, "baseline-snapshot", "baseline-resource")
    port = coordinator._GraphCoordinator__content_fence_v2
    begin = port.begin_fence
    lost = {"once": True}

    def lose_queued_read(**kwargs):
        permit = begin(**kwargs)
        if kwargs["operation"] == "read" and lost["once"]:
            lost["once"] = False
            raise RuntimeError("process stopped after queued read begin")
        return permit

    monkeypatch.setattr(port, "begin_fence", lose_queued_read)
    with pytest.raises(UnavailableGuard, match="v2 content authority is unavailable"):
        coordinator.commit_d04_encoding_baseline_v1(
            bootstrap, namespace, job_id, original_operation_id,
            policy, baseline_policy, clock)
    assert coordinator.commit_d04_encoding_baseline_v1(
        bootstrap, namespace, job_id, original_operation_id,
        policy, baseline_policy, clock).status == "committed"


def test_d03_no_start_intent_keeps_unknown_fence_on_hold(
        projection_case, monkeypatch):
    case = projection_case
    store, coordinator, *_ = case
    port = coordinator._GraphCoordinator__content_fence_v2
    begin = port.begin_fence
    stopped = {"once": True}

    def stop_before_write_begin(**kwargs):
        if kwargs["operation"] == "write" and stopped["once"]:
            stopped["once"] = False
            raise RuntimeError("stopped before Authority begin")
        return begin(**kwargs)

    monkeypatch.setattr(port, "begin_fence", stop_before_write_begin)
    with pytest.raises(RuntimeError, match="before Authority begin"):
        _commit(case)
    with pytest.raises(UnavailableGuard, match="cannot prove absence; HOLD"):
        _commit(case)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_d03_self_projection_intents_v1"
    ).fetchone() == (1,)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_bundle_operations "
        "WHERE operation_id LIKE 'd03-self-projection-%'"
    ).fetchone() == (0,)


def test_d04_no_start_intent_keeps_unknown_fence_on_hold(
        projection_case, monkeypatch):
    case = projection_case
    store, coordinator, bootstrap, namespace, job_id, original_operation_id, policy, _, clock, _ = case
    _commit(case)
    baseline_policy = AdminD04EncodingBaselinePolicy(
        30.0, {"cpu_ms": 2}, "baseline-snapshot", "baseline-resource")
    port = coordinator._GraphCoordinator__content_fence_v2
    begin = port.begin_fence
    stopped = {"once": True}

    def stop_before_write_begin(**kwargs):
        if kwargs["operation"] == "write" and stopped["once"]:
            stopped["once"] = False
            raise RuntimeError("stopped before Authority begin")
        return begin(**kwargs)

    monkeypatch.setattr(port, "begin_fence", stop_before_write_begin)
    with pytest.raises(RuntimeError, match="before Authority begin"):
        coordinator.commit_d04_encoding_baseline_v1(
            bootstrap, namespace, job_id, original_operation_id,
            policy, baseline_policy, clock)
    with pytest.raises(UnavailableGuard, match="cannot prove absence; HOLD"):
        coordinator.commit_d04_encoding_baseline_v1(
            bootstrap, namespace, job_id, original_operation_id,
            policy, baseline_policy, clock)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_d04_baseline_intents_v1"
    ).fetchone() == (1,)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_atoms WHERE type_name='d04.encoding_baseline.v1'"
    ).fetchone() == (0,)
