"""Controlled graph transaction check for the post-C02 commit façade.

The resource issuers here are local SDK controls.  This test proves atomic
graph persistence and operation replay, not installed dispatch admission.
"""

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.domains.d08 import ActionCancellationState, ActionSchema, ActionSchemaRecord, GoalExecutionProvider
from sylanne3.domains.d09 import D09ExpressionProvider
from sylanne3.graph_coordinator import BudgetAdmission, GraphCoordinator, RuntimeAdmission
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphWrite, Owner, TypeRegistry
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.budget import BudgetLease, create_budget_lease
from sylanne3.runtime.post_c02_domain_commit import commit_prepared_domain_bundle_v1
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, DomainBundle, DomainProposal,
    NamespaceId, OperationIdentity, QueryEpoch, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, canonical_digest, canonical_serialize,
)

from test_dispatch_admission_preflight import _candidates


class _ControlledResources:
    def authorize_resources(self, _bundle, _db, **_kwargs):
        return True


class _ControlledBudget:
    def admit_runtime(self, _bundle, _db, **_kwargs):
        return RuntimeAdmission(BudgetAdmission("parent", 1, {"cpu_ms": 1}))


def _case(path):
    providers = (D06DomainProvider(), GoalExecutionProvider(), D09ExpressionProvider())
    registry = TypeRegistry()
    for provider in providers:
        specs = (provider.type_specs() if isinstance(provider, D06DomainProvider)
                 else provider.register_types())
        for spec in specs:
            registry.register(spec)
    store = GraphStore(path, registry)
    bootstrap = object()
    graph = GraphCoordinator(
        store, bootstrap, d02_issuer=_ControlledResources(),
        d11_issuer=_ControlledBudget())
    for domain, provider in zip(("d06", "d08", "d09"), providers):
        graph.register_provider(
            bootstrap, domain, provider,
            "d06.contract.v1" if domain == "d06" else f"{domain}.proposal.v1",
            provider.descriptor.request_schema_hash)
    namespace = NamespaceId("bot", "persona")
    for kind, version in (("scheme", "scheme-1"), ("operator", "operator-1"),
                          ("policy", "policy-1"), ("activation", 1)):
        graph.set_guard_version(bootstrap, namespace, kind, "current", version)
    with store._lock:
        create_budget_lease(store._db, BudgetLease(
            "parent", None, "bot", "persona", "USD", {"cpu_ms": 10},
            {}, {}, {}, 1, "active"), "install-parent", "0" * 64)
    MemoryRepository(store, "bot", "persona").ingest(
        Event(Scope("bot", "persona", "session"), "source-ingress", 1.0, "ingress", {}),
        SourceRecord("source-1", "Hello", "alice", "observed", "confirmed",
                     1.0, 2.0, "family-1", ("entity:user",), ("expression",)))
    lease, capability = graph.grant(
        bootstrap, actor="host", issuer_domain="d06", namespace=namespace,
        domains=("d06", "d08", "d09"), activation_generation=1,
        operation_id="operation:one")
    authority = AuthorityContext(
        "host", "d06", capability, namespace, ("event", "activity"),
        "expression", ("entity:user",), "policy-1", 1)
    return store, graph, authority, lease, providers


def _bundle(graph, authority, lease, providers):
    namespace = authority.namespace
    source = source_key(*namespace.as_tuple, "source-1")
    access = access_key(*namespace.as_tuple, "source-1")
    schema, intent, batch, _, _, grant = _candidates(
        source_ref=source.token, include_grant=True)
    identity = replace(intent.identity, canonical_input_digest=canonical_digest({"input_refs": []}))
    intent = replace(intent, identity=identity)
    schema = ActionSchemaRecord.bind(intent, ActionSchema(
        schema.schema_id, schema.action_kind, False, schema.required_checks))
    owner = Owner("activity", *namespace.as_tuple, identity.activity_id)
    cancellation = ActionCancellationState.for_action(
        intent, state="active", actor=authority.actor,
        source_refs=(source.token,), operation_id=identity.operation_id)
    values = (
        ("d08.action_intent.v1", intent.action_id, intent),
        ("d08.action_schema.v1", schema.schema_ref, schema),
        ("d08.action_cancellation.v1", intent.action_id, cancellation),
        ("d08.communication_intent_grant.v1", grant.grant_id, grant),
        ("d09.verified_segment_batch.v1", batch["batch_id"], batch),
    )
    writes = tuple(GraphWrite(
        AtomKey(owner, kind, name),
        value if isinstance(value, dict) else json.loads(canonical_serialize(asdict(value))))
        for kind, name, value in values)
    snapshot = graph.read_snapshot(
        authority, lease, (source, access) + tuple(write.key for write in writes))
    guard = VersionGuard(
        snapshot.versions,
        (QueryEpoch(namespace, "all", snapshot.epochs[0].revision),),
        0, 0, graph._GraphCoordinator__store._registry.catalogue_hash,
        "scheme-1", "operator-1", "policy-1", (), (), ())
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA, identity, authority, guard,
        SourceQualification((source.token,), "observed", 1.0, 2.0,
                            "external_observation", "eligible", 0.8, "not_applicable"),
        (), "parent", 4_102_444_800.0, 100.0, "character-1", ())
    d08 = DomainProposal(
        "d08", "d08.proposal.v1", providers[1].descriptor.request_schema_hash,
        envelope, writes[:4], DependencySet(), (), ())
    d09 = DomainProposal(
        "d09", "d09.proposal.v1", providers[2].descriptor.request_schema_hash,
        envelope, writes[4:], DependencySet(), (), ())
    return DomainBundle(envelope, (d08, d09), (), (), (), (), (), (), ())


def test_controlled_graph_persists_d08_d09_and_replays_one_operation(tmp_path):
    path = tmp_path / "reply.db"
    store, graph, authority, lease, providers = _case(path)
    bundle = _bundle(graph, authority, lease, providers)
    first = commit_prepared_domain_bundle_v1(graph, authority, lease, bundle)
    second = commit_prepared_domain_bundle_v1(graph, authority, lease, bundle)
    assert first.status == "committed"
    assert second.operation_id == first.operation_id
    assert {item.key.type_name for item in first.write_versions} >= {
        "d08.action_intent.v1", "d08.communication_intent_grant.v1",
        "d09.verified_segment_batch.v1"}
    with store._lock:
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_bundle_operations WHERE operation_id=?",
            (first.operation_id,)).fetchone()[0] == 1
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
            "('d08.action_intent.v1', 'd09.verified_segment_batch.v1')",
        ).fetchone()[0] == 2
    registry = store._registry
    store.close()
    reopened = GraphStore(path, registry)
    bootstrap = object()
    second_graph = GraphCoordinator(
        reopened, bootstrap, d02_issuer=_ControlledResources(),
        d11_issuer=_ControlledBudget())
    for domain, provider in zip(("d06", "d08", "d09"), providers):
        second_graph.register_provider(
            bootstrap, domain, provider,
            "d06.contract.v1" if domain == "d06" else f"{domain}.proposal.v1",
            provider.descriptor.request_schema_hash)
    second_lease, second_capability = second_graph.grant(
        bootstrap, actor="host", issuer_domain="d06", namespace=authority.namespace,
        domains=("d06", "d08", "d09"), activation_generation=1,
        operation_id="operation:one")
    second_authority = replace(authority, capability_ref=second_capability)
    replayed = commit_prepared_domain_bundle_v1(
        second_graph, second_authority, second_lease, bundle)
    assert replayed.operation_id == first.operation_id
    with reopened._lock:
        assert reopened._db.execute(
            "SELECT COUNT(*) FROM graph_bundle_operations WHERE operation_id=?",
            (first.operation_id,)).fetchone()[0] == 1
    reopened.close()


def test_changed_bundle_replay_rejected_before_graph_write(tmp_path):
    store, graph, authority, lease, providers = _case(tmp_path / "reply.db")
    bundle = _bundle(graph, authority, lease, providers)
    commit_prepared_domain_bundle_v1(graph, authority, lease, bundle)
    changed = replace(bundle, idempotency_keys=("changed",))
    with pytest.raises(ValueError, match="changed its frozen bundle"):
        commit_prepared_domain_bundle_v1(graph, authority, lease, changed)
    store.close()
