"""Atomic first ingress uses the signed genesis grant and one business commit."""

from dataclasses import replace
import sqlite3
import time
from types import SimpleNamespace

import pytest

from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.graph_coordinator import (
    FirstIngressOutcomeUnknown, GraphCoordinator, IngressHostFacts,
    IngressLineage, UnavailableGuard,
)
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.host.authority_profile import (
    AdminIngressClockPolicy, AdminIngressEncodingPolicy,
)
from sylanne3.runtime.d11_types import (
    D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH,
    D11RuntimeProvider, graph_type_specs,
)
from sylanne3.runtime.issuers import build_runtime_issuers

from test_graph_v2_provisioning import AuthorityPort, policy_for


@pytest.fixture
def ingress_system(tmp_path):
    registry = TypeRegistry()
    for spec in D06DomainProvider.type_specs() + graph_type_specs():
        registry.register(spec)
    store = ProductionGraphStore(tmp_path / "business.db", registry)
    authority_db = sqlite3.connect(tmp_path / "authority.db", isolation_level=None)
    port = AuthorityPort(store, authority_db)
    d02, d11 = build_runtime_issuers(b"first-ingress-test-signing-key-32")
    bootstrap = object()
    coordinator = GraphCoordinator(
        store, bootstrap, holder="administrator", content_fence_v2=port,
        d02_issuer=d02, d11_issuer=d11)
    d06 = D06DomainProvider()
    coordinator.register_provider(
        bootstrap, "d06", d06, "d06.contract.v1",
        d06.descriptor.request_schema_hash)
    coordinator.register_provider(
        bootstrap, "d11", D11RuntimeProvider(),
        D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH)
    original = policy_for(store)
    policy = replace(original, root_grant=replace(
        original.root_grant,
        allowed_work_kinds=("d06.encode_source",)))
    coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona")
    source_ref = "b" * 64
    host = IngressHostFacts(
        policy.namespace, "platform", "conversation", "sender", "message",
        "hello", 10.0, time.time(), "private",
        IngressLineage(source_ref, "reported", "platform",
                       "external_report", "reported_claim", "not_applicable"))
    clock = AdminIngressClockPolicy("authority", 1.0, 1.0)
    encoding = AdminIngressEncodingPolicy(
        120.0, {"cpu_ms": 20}, "snapshot-1", "resource-1",
        "character-1")

    def read_clock(_):
        port.outside_graph_lock()
        return SimpleNamespace(
            utc_upper_bound_seconds=time.time() + 0.01,
            monotonic_after_seconds=time.monotonic())

    port.read_ingress_clock = read_clock
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
    assert len([item for item in port.finishes if item[0] == "write"]) == 2


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
    reopened = ProductionGraphStore(tmp_path / "business.db", store._registry)
    authority_db = sqlite3.connect(tmp_path / "authority.db", isolation_level=None)
    next_port = AuthorityPort(reopened, authority_db)
    next_port.anchors.update(port.anchors)
    next_port.read_ingress_clock = lambda _: SimpleNamespace(
        utc_upper_bound_seconds=time.time() + 0.01,
        monotonic_after_seconds=time.monotonic())
    d02, d11 = build_runtime_issuers(b"first-ingress-test-signing-key-32")
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
