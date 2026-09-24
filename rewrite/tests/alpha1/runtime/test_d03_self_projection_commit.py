"""The first self perspective is an Authority-qualified, priced graph stage."""

from dataclasses import replace

import pytest

from sylanne3.authority_service.v2_self_identity_contract import (
    AuthorityCurrentSelfIdentityV1,
)
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.host.authority_profile import (
    AdminD03ArrivalPolicy, AdminD03SelfIdentityProjectionPolicy,
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
    case = _scene_case(
        tmp_path, enable_ingress=True, arrival_allowed=True,
        extra_work_kinds=("d03.self_identity_projection",))
    store, authority_db, port, coordinator, namespace, _, _, policy, bootstrap = case
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
