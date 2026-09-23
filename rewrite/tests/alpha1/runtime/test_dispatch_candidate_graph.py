"""A source-HOLD dispatch candidate survives the actual graph bundle transaction."""

from dataclasses import asdict, replace
import sqlite3
import time
from types import SimpleNamespace

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.domains.d08 import ActionSchema, ActionSchemaRecord, GoalExecutionProvider
from sylanne3.domains.d09 import D09ExpressionProvider
from sylanne3.graph_coordinator import (
    BudgetAdmission, GraphCoordinator, IngressHostFacts, IngressLineage,
    RuntimeAdmission,
)
from sylanne3.graph_store import GraphStore, ProductionGraphStore
from sylanne3.graph_types import AtomKey, GraphWrite, Owner, TypeRegistry
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.host.authority_profile import (
    AdminIngressClockPolicy, AdminIngressEncodingPolicy,
)
from sylanne3.runtime.budget import BudgetLease, create_budget_lease, get_budget_lease
from sylanne3.runtime.issuers import build_runtime_issuers
from sylanne3.runtime.d11_types import (
    D11RuntimeProvider, D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH,
    graph_type_specs,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, DomainBundle, DomainProposal,
    NamespaceId, OperationIdentity, QueryEpoch, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, canonical_digest,
)

from test_dispatch_admission_preflight import _candidates
from test_graph_v2_provisioning import AuthorityPort, policy_for


class _Resources:
    def authorize_resources(self, _bundle, _db, **_kwargs):
        return True


class _Budget:
    def admit_runtime(self, _bundle, _db, **_kwargs):
        return RuntimeAdmission(BudgetAdmission("parent", 1, {"cpu_ms": 1}))


def _json(value):
    if isinstance(value, tuple):
        return [_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _json(item) for key, item in value.items()}
    return value


def _registry():
    providers = (D06DomainProvider(), GoalExecutionProvider(), D09ExpressionProvider())
    registry = TypeRegistry()
    for provider in providers:
        specs = provider.type_specs() if isinstance(provider, D06DomainProvider) else provider.register_types()
        for spec in specs:
            registry.register(spec)
    return registry, providers


def _coordinator(store, providers):
    bootstrap = object()
    coordinator = GraphCoordinator(store, bootstrap, d02_issuer=_Resources(), d11_issuer=_Budget())
    for domain, provider in zip(("d06", "d08", "d09"), providers):
        coordinator.register_provider(
            bootstrap, domain, provider,
            "d06.contract.v1" if domain == "d06" else f"{domain}.proposal.v1",
            provider.descriptor.request_schema_hash,
        )
    namespace = NamespaceId("bot", "persona")
    lease, capability = coordinator.grant(
        bootstrap, actor="host", issuer_domain="d06", namespace=namespace,
        domains=("d06", "d08", "d09"), activation_generation=1,
    )
    authority = AuthorityContext(
        "host", "d06", capability, namespace, ("event", "activity"),
        "expression", ("entity:user",), "policy-1", 1,
    )
    return coordinator, bootstrap, authority, lease


def _bundle(coordinator, authority, lease, providers, *, tamper=False,
            source_id="source-1", budget_ref="parent"):
    namespace = authority.namespace
    source = source_key("bot", "persona", source_id)
    access = access_key("bot", "persona", source_id)
    schema, intent, batch, _, _, grant = _candidates(
        source_ref=source.token, include_grant=True,
    )
    identity = replace(intent.identity, canonical_input_digest=canonical_digest({"input_refs": []}))
    intent = replace(intent, identity=identity)
    schema = ActionSchemaRecord.bind(
        intent, ActionSchema(schema.schema_id, schema.action_kind,
                             schema.proactive, schema.required_checks),
    )
    owner = Owner("activity", "bot", "persona", identity.activity_id)
    values = (
        ("d08.action_intent.v1", intent.action_id, intent),
        ("d08.action_schema.v1", schema.schema_ref, schema),
        ("d08.communication_intent_grant.v1", grant.grant_id, grant),
        ("d09.verified_segment_batch.v1", batch["batch_id"], batch),
    )
    writes = tuple(GraphWrite(AtomKey(owner, type_name, name),
                              _json(asdict(value)) if not isinstance(value, dict) else value)
                   for type_name, name, value in values)
    snapshot = coordinator.read_snapshot(
        authority, lease, (source, access) + tuple(write.key for write in writes),
    )
    guard = VersionGuard(
        snapshot.versions, (QueryEpoch(namespace, "all", snapshot.epochs[0].revision),),
        0, 0, coordinator._GraphCoordinator__store._registry.catalogue_hash,
        "scheme-1", "operator-1", "policy-1", (), (), (),
    )
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA, identity, authority, guard,
        SourceQualification((source.token,), "observed", 1.0, 2.0,
                            "external_observation", "eligible", 0.8, "not_applicable"),
        (), budget_ref, 4_102_444_800.0, 100.0, "character-1", (),
    )
    if tamper:
        invalid = dict(writes[-1].value)
        invalid["grant_digest"] = "0" * 64
        writes = writes[:-1] + (GraphWrite(writes[-1].key, invalid),)
    d08 = DomainProposal(
        "d08", "d08.proposal.v1", providers[1].descriptor.request_schema_hash,
        envelope, writes[:3], DependencySet(), (), (),
    )
    d09 = DomainProposal(
        "d09", "d09.proposal.v1", providers[2].descriptor.request_schema_hash,
        envelope, writes[3:], DependencySet(), (), (),
    )
    return DomainBundle(envelope, (d08, d09), (), (), (), (), (), (), ())


def _ready(tmp_path):
    registry, providers = _registry()
    store = GraphStore(tmp_path / "candidate.db", registry)
    coordinator, bootstrap, authority, lease = _coordinator(store, providers)
    for kind, version in (("scheme", "scheme-1"), ("operator", "operator-1"),
                          ("policy", "policy-1"), ("activation", 1)):
        coordinator.set_guard_version(bootstrap, authority.namespace, kind, "current", version)
    with store._lock:
        create_budget_lease(store._db, BudgetLease(
            "parent", None, "bot", "persona", "USD", {"cpu_ms": 10}, {}, {}, {},
            1, "active",
        ), "install-parent", "0" * 64)
    MemoryRepository(store, "bot", "persona").ingest(
        Event(Scope("bot", "persona", "session"), "source-ingress", 1.0, "ingress", {}),
        SourceRecord("source-1", "Hello", "alice", "observed", "confirmed",
                     1.0, 2.0, "family-1", ("entity:user",), ("expression",)),
    )
    return store, coordinator, authority, lease, providers, registry


def test_candidate_commit_is_source_hold_and_recovers_after_reopen(tmp_path):
    store, coordinator, authority, lease, providers, registry = _ready(tmp_path)
    bundle = _bundle(coordinator, authority, lease, providers)
    committed = coordinator.commit_domain_bundle(bundle, lease)
    assert committed.status == "committed"
    duplicate = coordinator.commit_domain_bundle(bundle, lease)
    assert duplicate.status == "duplicate"
    recovery = coordinator.get_dispatch_candidate_evidence(
        authority, lease, bundle.envelope.identity.operation_id)
    assert recovery.evidence.status == "source_hold"
    assert len(recovery.write_versions) == 4
    assert recovery.evidence.source_read_versions[0][1] == 1
    store.close()

    reopened = GraphStore(tmp_path / "candidate.db", registry)
    second, _, second_authority, second_lease = _coordinator(reopened, providers)
    restored = second.get_dispatch_candidate_evidence(
        second_authority, second_lease, bundle.envelope.identity.operation_id)
    assert restored == recovery
    reopened.close()


def test_tampered_grant_digest_rolls_back_entire_candidate(tmp_path):
    store, coordinator, authority, lease, providers, _ = _ready(tmp_path)
    bundle = _bundle(coordinator, authority, lease, providers, tamper=True)
    with pytest.raises(ValueError):
        coordinator.commit_domain_bundle(bundle, lease)
    assert coordinator.get_dispatch_candidate_evidence(
        authority, lease, bundle.envelope.identity.operation_id) is None
    with store._lock:
        assert store._db.execute("SELECT 1 FROM graph_bundle_operations").fetchone() is None
        assert store._db.execute("SELECT 1 FROM runtime_budget_reservations").fetchone() is None
    store.close()


def test_receipt_insert_failure_rolls_back_graph_and_budget(tmp_path):
    store, coordinator, authority, lease, providers, _ = _ready(tmp_path)
    bundle = _bundle(coordinator, authority, lease, providers)
    with store._lock:
        store._db.execute(
            "CREATE TRIGGER fail_candidate_receipt BEFORE INSERT ON graph_bundle_operations "
            "BEGIN SELECT RAISE(ABORT, 'injected candidate receipt failure'); END"
        )
    with pytest.raises(Exception, match="injected candidate receipt failure"):
        coordinator.commit_domain_bundle(bundle, lease)
    with store._lock:
        for table in ("graph_bundle_operations", "runtime_budget_reservations"):
            assert store._db.execute(f"SELECT 1 FROM {table}").fetchone() is None
        assert store._db.execute(
            "SELECT 1 FROM graph_events WHERE event_id=?",
            (bundle.envelope.identity.operation_id,),
        ).fetchone() is None
        assert store._db.execute(
            "SELECT 1 FROM graph_atoms WHERE owner_kind='activity'"
        ).fetchone() is None
    assert coordinator.get_dispatch_candidate_evidence(
        authority, lease, bundle.envelope.identity.operation_id) is None
    store.close()


def test_v2_fenced_candidate_commit_and_cold_recovery(tmp_path):
    registry, providers = _registry()
    for spec in graph_type_specs():
        registry.register(spec)
    store = ProductionGraphStore(tmp_path / "business.db", registry)
    authority_db = sqlite3.connect(tmp_path / "authority.db", isolation_level=None)
    port = AuthorityPort(store, authority_db)
    d02, d11 = build_runtime_issuers(b"candidate-v2-signing-key-32bytes")
    bootstrap = object()
    coordinator = GraphCoordinator(
        store, bootstrap, holder="administrator", content_fence_v2=port,
        d02_issuer=d02, d11_issuer=d11,
    )
    policy = policy_for(store)
    policy = replace(policy, root_grant=replace(
        policy.root_grant, allowed_work_kinds=("d06.encode_source",)))
    coordinator.provision_namespace_v2(bootstrap, policy, operation_id="install-persona")
    for domain, provider in zip(("d06", "d08", "d09"), providers):
        coordinator.register_provider(
            bootstrap, domain, provider,
            "d06.contract.v1" if domain == "d06" else f"{domain}.proposal.v1",
            provider.descriptor.request_schema_hash,
        )
    coordinator.register_provider(
        bootstrap, "d11", D11RuntimeProvider(),
        D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH,
    )
    host = IngressHostFacts(
        policy.namespace, "platform", "conversation", "sender", "message",
        "Hello", 10.0, time.time(), "private",
        IngressLineage("b" * 64, "reported", "platform",
                       "external_report", "reported_claim", "not_applicable"),
    )
    clock = AdminIngressClockPolicy("authority", 1.0, 1.0)
    encoding = AdminIngressEncodingPolicy(
        120.0, {"cpu_ms": 20}, "snapshot-1", "resource-1", "character-1")
    port.read_ingress_clock = lambda _: SimpleNamespace(
        utc_upper_bound_seconds=time.time() + 0.01,
        monotonic_after_seconds=time.monotonic(),
    )
    assert coordinator.commit_first_ingress_v2(
        bootstrap, host, policy, clock, encoding).status == "committed"
    source_row = store._db.execute(
        "SELECT subject FROM graph_atoms WHERE type_name='memory.source'"
    ).fetchone()
    assert source_row is not None
    d11.admit_runtime = lambda _bundle, db, **_kwargs: RuntimeAdmission(
        BudgetAdmission("lease-persona", get_budget_lease(db, "lease-persona").version,
                        {"cpu_ms": 1}))
    d02.authorize_resources = lambda _bundle, _db, **_kwargs: True
    lease, capability = coordinator.grant(
        bootstrap, actor="host", issuer_domain="d06", namespace=policy.namespace,
        domains=("d06", "d08", "d09"), activation_generation=1,
        operation_id="operation:one",
    )
    authority = AuthorityContext(
        "host", "d06", capability, policy.namespace, ("event", "activity"),
        "context", ("conversation",), "policy-1", 1,
    )
    bundle = _bundle(coordinator, authority, lease, providers,
                     source_id=source_row[0], budget_ref="lease-persona")
    try:
        assert coordinator.commit_domain_bundle(bundle, lease).status == "committed"
        assert coordinator.commit_domain_bundle(bundle, lease).status == "duplicate"
        first = coordinator.get_dispatch_candidate_evidence(
            authority, lease, bundle.envelope.identity.operation_id)
        assert first.evidence.status == "source_hold"
        assert first.graph_incarnation == coordinator._v2_graph_stamp(
            policy.namespace)[0].requirements.graph_incarnation
        assert first.graph_revision == 2
        store.close()

        reopened = ProductionGraphStore(tmp_path / "business.db", registry)
        next_port = AuthorityPort(reopened, authority_db)
        next_port.anchors.update(port.anchors)
        next_bootstrap = object()
        next_coordinator = GraphCoordinator(
            reopened, next_bootstrap, holder="administrator",
            content_fence_v2=next_port, d02_issuer=d02, d11_issuer=d11,
        )
        for domain, provider in zip(("d06", "d08", "d09"), providers):
            next_coordinator.register_provider(
                next_bootstrap, domain, provider,
                "d06.contract.v1" if domain == "d06" else f"{domain}.proposal.v1",
                provider.descriptor.request_schema_hash,
            )
        next_lease, next_ref = next_coordinator.grant(
            next_bootstrap, actor="host", issuer_domain="d06",
            namespace=policy.namespace, domains=("d06", "d08", "d09"),
            activation_generation=1, operation_id="operation:one",
        )
        next_authority = replace(authority, capability_ref=next_ref)
        assert next_coordinator.get_dispatch_candidate_evidence(
            next_authority, next_lease, bundle.envelope.identity.operation_id) == first
        reopened.close()
    finally:
        store.close()
        authority_db.close()
