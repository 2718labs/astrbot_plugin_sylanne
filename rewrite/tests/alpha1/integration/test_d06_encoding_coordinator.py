"""C02 v1 fixture: proof-bound D06 encoding through the D02/D11 coordinator path."""

import pytest

from sylanne3.contracts import Event, Scope, StaleRead
from sylanne3.domains.d03.context import ContextProvider
from sylanne3.domains.d04 import AffectProvider
from sylanne3.domains.d06 import (
    D06DomainAdapter, D06DomainProvider, EncodingContext, SourceAdmission,
)
from sylanne3.domains.d06.pipeline import D06MemoryPipeline
from sylanne3.domains.d07 import D07DomainProvider
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry, TypeSpec
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.budget import BudgetLease, create_budget_lease, get_budget_lease
from sylanne3.runtime.d11_types import (
    D11RuntimeProvider, D11_PROPOSAL_SCHEMA,
    job_graph_write, runtime_job_key,
)
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, IssuerAuthorityDenied, ResourceQuote, build_runtime_issuers,
    install_schema as install_issuer_schema,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, DomainBundle, DomainProposal,
    NamespaceId, OperationIdentity, QueryEpoch, RUNTIME_SCHEMA,
    VersionGuard, VersionedRef, canonical_digest,
)


class EncodingHarness:
    def __init__(self, root):
        self.namespace = NamespaceId("bot", "persona")
        self.registry = TypeRegistry()
        self.d06 = D06DomainProvider()
        self.d11_provider = D11RuntimeProvider()
        for provider in (self.d06, self.d11_provider):
            for spec in provider.type_specs():
                self.registry.register(spec)
        # Committed context is a v1 fixture. These types are not product D03/D04/D07 admission.
        for name, owner in (
            ("d03.world_event", "event"), ("d03.role_binding", "scene"),
            ("d04.feeling_state.v1", "persona"), ("d07.belief_revision.v1", "persona"),
        ):
            self.registry.register(TypeSpec(
                name, (owner,), "state", lambda _: None,
                writer_domain=name[:3], schema_hash="a" * 64,
            ))
        self.store = GraphStore(root / "graph.db", self.registry)
        self.repository = MemoryRepository(self.store, "bot", "persona")
        self.adapter = D06DomainAdapter(self.namespace)
        self.pipeline = D06MemoryPipeline(self.adapter, self.repository)
        self.d02, self.d11 = build_runtime_issuers(b"c02-integration-signer" * 2)
        with self.store._lock:
            install_issuer_schema(self.store._db)
            create_budget_lease(self.store._db, BudgetLease(
                "parent", None, "bot", "persona", "USD",
                {"cpu_ms": 10}, {}, {}, {}, 1, "active",
            ), "install-parent", "0" * 64)
        self.bootstrap = object()
        self.coordinator = GraphCoordinator(
            self.store, self.bootstrap, d02_issuer=self.d02, d11_issuer=self.d11,
        )
        for domain, provider, schema in (
            ("d06", self.d06, "d06.contract.v1"),
            ("d11", self.d11_provider, D11_PROPOSAL_SCHEMA),
            ("d03", ContextProvider(), "d03.proposal.v1"),
            ("d04", AffectProvider(), "d04.proposal.v1"),
            ("d07", D07DomainProvider(), "d07.proposal.v1"),
        ):
            self.coordinator.register_provider(
                self.bootstrap, domain, provider, schema,
                provider.descriptor.request_schema_hash,
            )
        self.lease, capability = self.coordinator.grant(
            self.bootstrap, actor="host", issuer_domain="d06",
            namespace=self.namespace, domains=("d03", "d04", "d06", "d07", "d11"),
            activation_generation=1,
        )
        self.authority = AuthorityContext(
            "host", "d06", capability, self.namespace,
            ("event", "scene", "persona", "activity"),
            "context", ("owner",), "policy-1", 1,
        )
        for kind, ref, version in (
            ("scheme", "current", "scheme-1"),
            ("operator", "current", "operator-1"),
            ("policy", "current", "policy-1"),
            ("activation", "current", 1),
            ("resource_lease", "quote-c02", 1),
        ):
            self.coordinator.set_guard_version(
                self.bootstrap, self.namespace, kind, ref, version,
            )
        self.source = source_key("bot", "persona", "source-1")
        self.access = access_key("bot", "persona", "source-1")
        self.event = AtomKey(Owner("event", "bot", "persona", "world-1"), "d03.world_event", "current")
        self.perspective = AtomKey(Owner("scene", "bot", "persona", "scene-1"), "d03.role_binding", "current")
        self.feeling = AtomKey(Owner("persona", "bot", "persona"), "d04.feeling_state.v1", "current")
        self.interpretation = AtomKey(Owner("persona", "bot", "persona"), "d07.belief_revision.v1", "current")
        self.repository.ingest(
            Event(Scope("bot", "persona", "session"), "ingress", 1.0, "ingress", {}),
            SourceRecord("source-1", "A reported promise", "alice", "reported",
                         "reported", None, 2.0, "family-1", ("owner",), ("context",)),
        )
        context_keys = (self.event, self.perspective, self.feeling, self.interpretation)
        self.store.graph_commit(GraphCandidate(
            Event(Scope("bot", "persona", "session"), "context", 3.0, "context", {}),
            tuple(GraphVersion(key, 0) for key in context_keys),
            tuple(GraphWrite(key, {"fixture": True}) for key in context_keys),
        ))

    def close(self):
        self.store.close()

    def bundle(self):
        context_keys = (self.event, self.perspective, self.feeling, self.interpretation)
        context = EncodingContext(
            self.event.token, self.perspective.token, (self.feeling.token,),
            (self.interpretation.token,), (("promise", 0.9),),
            tuple((key.token, 1) for key in (self.source, *context_keys)),
        )
        prepared = self.pipeline.prepare_encoding(
            "source-1", context, audience="owner", purpose="context",
        )
        episode_id = prepared.proposal.episode.episode_id
        trace_id = prepared.proposal.trace.trace_id
        from sylanne3.memory_types import episode_key, subjective_trace_key
        episode = episode_key("bot", "persona", episode_id)
        trace = subjective_trace_key("bot", "persona", trace_id)
        job = runtime_job_key("bot", "persona", "activity-c02", "job-c02")
        snapshot = self.coordinator.read_snapshot(
            self.authority, self.lease,
            (self.source, self.access, *context_keys, episode, trace, job),
        )
        inputs = (self.source.token,)
        envelope = CommandEnvelope(
            RUNTIME_SCHEMA,
            OperationIdentity("activity-c02", None, "attempt-c02", "encode",
                              "operation-c02", canonical_digest({"input_refs": list(inputs)})),
            self.authority,
            VersionGuard(
                snapshot.versions,
                (QueryEpoch(self.namespace, "all", snapshot.epochs[0].revision),),
                0, 0, self.registry.catalogue_hash,
                "scheme-1", "operator-1", "policy-1", (), (),
                (VersionedRef("quote-c02", 1),),
            ),
            self.adapter.admit_source(SourceAdmission(
                "source-1", "A reported promise", "alice", "reported", "reported",
                "reported_claim", "not_applicable", None, 2.0, "family-1",
                ("owner",), ("context",),
            )).qualification,
            inputs, "parent", 4_102_444_800.0, 100.0, "character-1",
            ("source-1",),
        )
        d06 = self.adapter.compile_encoding(envelope, prepared)
        with self.store._lock:
            self.d02.issue_quote(self.store._db, ResourceQuote(
                "quote-c02", 1, "bot", "persona", "activity-c02", "operation-c02",
                None, "parent", "encode", "snapshot-c02", envelope.deadline_utc,
                "resource-c02", job.token, (), (), {"cpu_ms": 2}, None,
                4_102_444_900.0,
            ))
            self.d11.issue_budget_grant(self.store._db, BudgetLeaseGrant(
                "grant-c02", 1, "bot", "persona", "parent", "USD",
                {"cpu_ms": 3}, ("encode",), 4_102_445_000.0, "policy-1",
            ))
            durable_job = self.d11.job_for(envelope, self.store._db)
        d11 = DomainProposal(
            "d11", D11_PROPOSAL_SCHEMA,
            self.d11_provider.descriptor.request_schema_hash, envelope,
            (job_graph_write(durable_job),),
            DependencySet(), (), (),
        )
        return DomainBundle(
            envelope, (d06, d11), (), (), (), (), (), (job.token,), (),
        ), (episode, trace, job)


@pytest.fixture
def encoding(tmp_path):
    harness = EncodingHarness(tmp_path)
    try:
        yield harness
    finally:
        harness.close()


def test_c02_signed_budget_and_job_admit_episode_and_trace_atomically(encoding):
    bundle, keys = encoding.bundle()
    receipt = encoding.coordinator.commit_domain_bundle(bundle, encoding.lease)
    assert receipt.status == "committed"
    assert {item.key for item in receipt.write_versions} == set(keys)
    episode, trace, job = (encoding.store.graph_snapshot((key,)).atoms[0] for key in keys)
    assert episode.valid and trace.valid and job.valid
    assert trace.value["episode_ref"] == episode.key.token
    with encoding.store._lock:
        assert get_budget_lease(encoding.store._db, "parent").reserved == {"cpu_ms": 2}
        assert encoding.store._db.execute("SELECT COUNT(*) FROM runtime_jobs").fetchone()[0] == 1


def test_c02_withdrawn_source_rejects_prepared_bundle_without_spending(encoding):
    bundle, keys = encoding.bundle()
    encoding.repository.set_access(
        Event(Scope("bot", "persona", "session"), "withdraw", 4.0, "withdraw", {}),
        "source-1", audiences=("owner",), purposes=("context",),
        status="withdrawn", recorded_at=4.0,
    )
    with pytest.raises(StaleRead):
        encoding.coordinator.commit_domain_bundle(bundle, encoding.lease)
    assert all(not atom.valid for atom in encoding.store.graph_snapshot(keys).atoms)
    with encoding.store._lock:
        assert get_budget_lease(encoding.store._db, "parent").reserved == {}
        assert encoding.store._db.execute("SELECT COUNT(*) FROM runtime_jobs").fetchone()[0] == 0


def test_c02_changed_policy_version_rejects_prepared_bundle_without_spending(encoding):
    bundle, keys = encoding.bundle()
    encoding.coordinator.set_guard_version(
        encoding.bootstrap, encoding.namespace, "policy", "current", "policy-2",
    )
    with pytest.raises(StaleRead):
        encoding.coordinator.commit_domain_bundle(bundle, encoding.lease)
    assert all(not atom.valid for atom in encoding.store.graph_snapshot(keys).atoms)
    with encoding.store._lock:
        assert get_budget_lease(encoding.store._db, "parent").reserved == {}
        assert encoding.store._db.execute("SELECT COUNT(*) FROM runtime_jobs").fetchone()[0] == 0


def test_c02_revoked_signed_resource_quote_rejects_job_and_budget(encoding):
    bundle, keys = encoding.bundle()
    with encoding.store._lock:
        encoding.store._db.execute(
            "UPDATE runtime_resource_quotes SET status='revoked' "
            "WHERE quote_id='quote-c02' AND version=1"
        )
    with pytest.raises(IssuerAuthorityDenied, match="qualified D02 resource quote"):
        encoding.coordinator.commit_domain_bundle(bundle, encoding.lease)
    assert all(not atom.valid for atom in encoding.store.graph_snapshot(keys).atoms)
    with encoding.store._lock:
        assert get_budget_lease(encoding.store._db, "parent").reserved == {}
        assert encoding.store._db.execute("SELECT COUNT(*) FROM runtime_jobs").fetchone()[0] == 0
