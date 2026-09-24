"""Atomic first ingress uses the signed genesis grant and one business commit."""

from dataclasses import replace
import json
import sqlite3
import time
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, canonical_digest as owner_contract_digest,
)
from sylanne3.graph_coordinator import (
    AuthorityDenied, FirstIngressOutcomeUnknown, GraphCoordinator, IngressHostFacts,
    IngressLineage, UnavailableGuard,
)
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.host.authority_profile import (
    AdminIngressClockPolicy, AdminIngressEncodingPolicy,
)
from sylanne3.runtime.issuers import build_runtime_issuers

from test_graph_v2_provisioning import AuthorityPort, _owner_issue_case
from test_scene_binding_v2 import _bind_scene, _scene_case


def _ingress_inputs(namespace):
    host = IngressHostFacts(
        namespace, "platform", "conversation", "sender", "message",
        "hello", 10.0, time.time(), "private",
        IngressLineage("b" * 64, "reported", "platform",
                       "external_report", "reported_claim", "not_applicable"))
    clock = AdminIngressClockPolicy("authority", 1.0, 1.0)
    encoding = AdminIngressEncodingPolicy(
        120.0, {"cpu_ms": 20}, "snapshot-1", "resource-1",
        "character-1")
    return host, clock, encoding


@pytest.fixture
def ingress_system(tmp_path):
    case = _scene_case(tmp_path, enable_ingress=True)
    store, authority_db, port, coordinator, namespace, _, _, policy, bootstrap = case
    _bind_scene(case)
    host, clock, encoding = _ingress_inputs(namespace)

    try:
        yield store, coordinator, bootstrap, port, policy, clock, encoding, host
    finally:
        store.close()
        authority_db.close()


def count(db, table):
    if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,)).fetchone() is None:
        return 0
    return db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_scene_identity_separates_platform_account_and_conversation():
    from sylanne3.runtime_contracts import NamespaceId

    namespace = NamespaceId("bot", "persona")
    scene = scene_ref_for_conversation(namespace, "platform", "conversation")
    assert scene.startswith("scene:conversation-v1:")
    assert scene != scene_ref_for_conversation(
        namespace, "other-platform", "conversation")
    assert scene != scene_ref_for_conversation(
        NamespaceId("other-bot", "persona"), "platform", "conversation")
    assert scene != scene_ref_for_conversation(
        namespace, "platform", "other-conversation")


def test_ingress_requires_current_d01_role(tmp_path):
    (store, authority_db, port, coordinator, policy, operation,
     pending, grant_value, bootstrap) = _owner_issue_case(
         tmp_path, first_ingress=True, role_types=True, scene_types=True,
         return_bootstrap=True)
    try:
        port.pending_owner = pending
        proof = coordinator.commit_first_owner_grant_v2(
            bootstrap, namespace=policy.namespace,
            operation_id=operation.operation_id, grant_value=grant_value)
        guard = OwnerAuthorizationGuardV1(
            "authority", "installation", policy.namespace, 1,
            owner_contract_digest(proof), 0, 0)
        port.get_current_owner_guard_for_fence = lambda **kw: (
            guard, kw["permit"])
        host, clock, encoding = _ingress_inputs(policy.namespace)
        with pytest.raises(UnavailableGuard, match="active D01 role head is absent"):
            coordinator.commit_first_ingress_v2(
                bootstrap, host, policy, clock, encoding)
        assert count(store._db, "graph_bundle_operations") == 0
        assert count(store._db, "ingress_first_observations") == 0
    finally:
        store.close()
        authority_db.close()


def test_ingress_requires_fenced_scene_binding(tmp_path):
    (store, authority_db, _port, coordinator, namespace, _principal,
     _prior, policy, bootstrap) = (
         _scene_case(tmp_path, enable_ingress=True))
    try:
        host, clock, encoding = _ingress_inputs(namespace)
        with pytest.raises(UnavailableGuard, match="current scene binding is absent"):
            coordinator.commit_first_ingress_v2(
                bootstrap, host, policy, clock, encoding)
        assert count(store._db, "graph_bundle_operations") == 0
        assert count(store._db, "ingress_first_observations") == 0
    finally:
        store.close()
        authority_db.close()


def test_ingress_rejects_revoked_scene_binding(ingress_system):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = (
        ingress_system)
    scene_ref = scene_ref_for_conversation(
        policy.namespace, host.platform_ref, host.conversation_ref)
    row = store._db.execute(
        "SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? "
        "AND owner_kind='scene' AND subject=? AND type_name='d03.role_binding'",
        policy.namespace.as_tuple + (scene_ref,),
    ).fetchone()
    value = json.loads(row[1])
    value["status"] = "revoked"
    store._db.execute(
        "UPDATE graph_atoms SET value=? WHERE token=?",
        (json.dumps(value, sort_keys=True, separators=(",", ":")), row[0]),
    )
    with pytest.raises(AuthorityDenied, match="scene does not admit"):
        coordinator.commit_first_ingress_v2(
            bootstrap, host, policy, clock, encoding)
    assert count(store._db, "graph_bundle_operations") == 0
    assert count(store._db, "ingress_first_observations") == 0


def test_ingress_scene_must_match_host_platform_account(ingress_system):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = (
        ingress_system)
    with pytest.raises(UnavailableGuard, match="current scene binding is absent"):
        coordinator.commit_first_ingress_v2(
            bootstrap, replace(host, platform_ref="other-platform"),
            policy, clock, encoding)
    assert count(store._db, "graph_bundle_operations") == 0


def test_first_ingress_commits_and_replays_exact_receipt(ingress_system):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = (
        ingress_system)
    receipt = coordinator.commit_first_ingress_v2(
        bootstrap, host, policy, clock, encoding)
    assert receipt.status == "committed"
    assert coordinator.commit_first_ingress_v2(
        bootstrap, host, policy, clock, encoding) == receipt
    assert count(store._db, "ingress_first_observations") == 1
    assert count(store._db, "graph_bundle_operations") == 1
    assert count(store._db, "runtime_resource_quotes") == 1
    assert count(store._db, "runtime_budget_grants") == 1
    assert count(store._db, "runtime_budget_reservations") == 1
    assert count(store._db, "runtime_jobs") == 1
    assert count(store._db, "graph_bundle_outbox") == 1
    assert len([item for item in port.finishes if item[0] == "write"]) == 5


def test_first_ingress_commits_identity_receipt_with_bundle(ingress_system):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = (
        ingress_system)
    committed = coordinator.commit_first_ingress_v2(
        bootstrap, host, policy, clock, encoding)
    identity = store._db.execute(
        "SELECT source_ref,platform_ref,conversation_ref,sender_ref,message_id,"
        "visibility,bundle_digest FROM graph_first_ingress_identity_v1"
    ).fetchone()
    assert identity == (
        host.lineage.source_ref, host.platform_ref, host.conversation_ref,
        host.sender_ref, host.message_id, host.visibility,
        committed.operation_digest,
    )
    assert coordinator.commit_first_ingress_v2(
        bootstrap, host, policy, clock, encoding) == committed


def test_identity_read_requires_committed_matching_original(ingress_system):
    from sylanne3.runtime.ingress_observation import read_committed_ingress_identity

    store, coordinator, bootstrap, _port, policy, clock, encoding, host = (
        ingress_system)
    assert read_committed_ingress_identity(
        store._db, host.namespace, host.lineage.source_ref) is None
    committed = coordinator.commit_first_ingress_v2(
        bootstrap, host, policy, clock, encoding)
    proof = read_committed_ingress_identity(
        store._db, host.namespace, host.lineage.source_ref)
    assert proof.bundle_digest == committed.operation_digest
    assert json.loads(proof.identity_json)["message_id"] == host.message_id
    store._db.execute(
        "UPDATE graph_first_ingress_identity_v1 SET message_id='forged'")
    with pytest.raises(Exception, match="identity"):
        read_committed_ingress_identity(
            store._db, host.namespace, host.lineage.source_ref)
    store._db.execute("DELETE FROM graph_first_ingress_identity_v1")
    assert read_committed_ingress_identity(
        store._db, host.namespace, host.lineage.source_ref) is None
    with pytest.raises(UnavailableGuard, match="business receipt differs"):
        coordinator.commit_first_ingress_v2(
            bootstrap, host, policy, clock, encoding)


def test_changed_content_does_not_reuse_first_ingress_operation(ingress_system):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = (
        ingress_system)
    coordinator.commit_first_ingress_v2(
        bootstrap, host, policy, clock, encoding)
    with pytest.raises(UnavailableGuard, match="intent identity differs"):
        coordinator.commit_first_ingress_v2(
            bootstrap, replace(host, text="changed"), policy, clock, encoding)
    assert count(store._db, "graph_bundle_operations") == 1


def test_graph_failure_rolls_back_observation_quote_and_job(ingress_system):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = (
        ingress_system)
    provider = coordinator._GraphCoordinator__providers["d06"][0]
    original = provider.validate
    provider.validate = lambda *_: (_ for _ in ()).throw(
        RuntimeError("graph validation failed"))
    try:
        with pytest.raises(RuntimeError, match="graph validation failed"):
            coordinator.commit_first_ingress_v2(
                bootstrap, host, policy, clock, encoding)
    finally:
        provider.validate = original
    assert count(store._db, "ingress_first_observations") == 0
    assert count(store._db, "runtime_resource_quotes") == 0
    assert count(store._db, "runtime_jobs") == 0
    assert count(store._db, "graph_bundle_operations") == 0
    assert count(store._db, "graph_first_ingress_rejections_v2") == 1


def test_lost_begin_reuses_original_persisted_attempt(ingress_system):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = (
        ingress_system)
    port.lose_begin_after_durable = True
    with pytest.raises(FirstIngressOutcomeUnknown,
                       match="HOLD original attempt") as held:
        coordinator.commit_first_ingress_v2(
            bootstrap, host, policy, clock, encoding)
    assert held.value.operation_id == store._db.execute(
        "SELECT operation_id FROM graph_first_ingress_intents_v2"
    ).fetchone()[0]
    original = store._db.execute(
        "SELECT fence_attempt_id FROM graph_first_ingress_intents_v2"
    ).fetchone()[0]
    assert count(store._db, "graph_bundle_operations") == 0
    receipt = coordinator.commit_first_ingress_v2(
        bootstrap, host, policy, clock, encoding)
    assert receipt.status == "committed"
    assert store._db.execute(
        "SELECT fence_attempt_id FROM graph_first_ingress_intents_v2"
    ).fetchone()[0] == original


def test_lost_finish_replays_durable_business_receipt_after_restart(
        ingress_system, tmp_path):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = (
        ingress_system)
    port.lose_finish_after_durable = True
    with pytest.raises(FirstIngressOutcomeUnknown,
                       match="finish outcome unknown; HOLD") as held:
        coordinator.commit_first_ingress_v2(
            bootstrap, host, policy, clock, encoding)
    assert held.value.operation_id == store._db.execute(
        "SELECT operation_id FROM graph_first_ingress_intents_v2"
    ).fetchone()[0]
    assert count(store._db, "graph_bundle_operations") == 1
    store.close()
    reopened = ProductionGraphStore(tmp_path / "owner-business.db", store._registry)
    authority_db = sqlite3.connect(tmp_path / "owner-authority.db", isolation_level=None)
    next_port = AuthorityPort(reopened, authority_db)
    next_port.anchors.update(port.anchors)
    next_port.read_ingress_clock = lambda _: SimpleNamespace(
        utc_upper_bound_seconds=time.time() + 0.01,
        monotonic_after_seconds=time.monotonic())
    d02, d11 = build_runtime_issuers(b"issuer-key-" * 4)
    next_bootstrap = object()
    next_coordinator = GraphCoordinator(
        reopened, next_bootstrap, holder="administrator",
        content_fence_v2=next_port, d02_issuer=d02, d11_issuer=d11)
    try:
        receipt = next_coordinator.commit_first_ingress_v2(
            next_bootstrap, host, policy, clock, encoding)
        assert receipt.status == "committed"
        assert count(reopened._db, "ingress_first_observations") == 1
        assert count(reopened._db, "graph_bundle_operations") == 1
    finally:
        reopened.close()
        authority_db.close()


def test_unknown_commit_stays_on_original_operation(ingress_system):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = (
        ingress_system)

    class LostCommitResponse:
        def __init__(self, connection):
            self.connection = connection
            self.triggered = False

        def execute(self, sql, *args):
            result = self.connection.execute(sql, *args)
            if (sql == "COMMIT" and not self.triggered
                    and self.connection.execute(
                        "SELECT COUNT(*) FROM graph_bundle_operations"
                    ).fetchone()[0]):
                self.triggered = True
                raise RuntimeError("commit response lost")
            return result

        def __getattr__(self, name):
            return getattr(self.connection, name)

    connection = store._db
    store._db = LostCommitResponse(connection)
    try:
        with pytest.raises(FirstIngressOutcomeUnknown,
                           match="commit outcome unknown; HOLD") as held:
            coordinator.commit_first_ingress_v2(
                bootstrap, host, policy, clock, encoding)
    finally:
        store._db = connection
    assert held.value.operation_id == connection.execute(
        "SELECT operation_id FROM graph_first_ingress_intents_v2"
    ).fetchone()[0]
    assert count(connection, "graph_bundle_operations") == 1
    assert count(connection, "graph_first_ingress_rejections_v2") == 0
    assert coordinator.commit_first_ingress_v2(
        bootstrap, host, policy, clock, encoding).status == "committed"


def test_unqualified_clock_holds_before_intent_or_write(ingress_system):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = (
        ingress_system)
    port.read_ingress_clock = lambda _: (_ for _ in ()).throw(
        RuntimeError("clock source unavailable"))
    with pytest.raises(UnavailableGuard, match="paired ingress clock unavailable"):
        coordinator.commit_first_ingress_v2(
            bootstrap, host, policy, clock, encoding)
    assert count(store._db, "graph_first_ingress_intents_v2") == 0
    assert count(store._db, "graph_bundle_operations") == 0
