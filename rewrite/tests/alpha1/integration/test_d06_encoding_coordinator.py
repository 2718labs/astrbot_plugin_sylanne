"""Typed unit graph fixture for proof-bound D06 encoding through D02/D11."""

from dataclasses import asdict

import pytest

from sylanne3.contracts import Event, Scope, StaleRead
from sylanne3.domains.d03.context import ContextProvider, WorldEvent
from sylanne3.domains.d03.self_perspective import (
    SelfIdentityMapping, SelfPerspective, self_mapping_key,
    self_perspective_id, self_perspective_key,
)
from sylanne3.domains.d04 import AffectProvider
from sylanne3.domains.d04.encoding_baseline import decode_encoding_baseline
from sylanne3.domains.d06 import (
    D06DomainAdapter, D06DomainProvider, EncodingContext, SourceAdmission,
)
from sylanne3.domains.d06.pipeline import D06MemoryPipeline
from sylanne3.domains.d07 import D07DomainProvider
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry, TypeSpec
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import (
    SourceRecord, access_key, episode_key, source_key, subjective_trace_v2_key,
)
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
        self.d03_provider = ContextProvider()
        self.d04_provider = AffectProvider()
        for provider in (self.d06, self.d11_provider):
            for spec in provider.type_specs():
                self.registry.register(spec)
        for spec in self.d03_provider.type_specs():
            if spec.name in {
                "d03.world_event", "d03.self_identity_mapping.v1",
                "d03.self_perspective.v1",
            }:
                self.registry.register(spec)
        for spec in self.d04_provider.type_specs():
            if spec.name == "d04.encoding_baseline.v1":
                self.registry.register(spec)
        for name, owner in (
            ("d04.feeling_state.v1", "persona"),
            ("d07.belief_revision.v1", "persona"),
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
            ("d03", self.d03_provider, "d03.proposal.v1"),
            ("d04", self.d04_provider, "d04.proposal.v1"),
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
            ("activity", "event", "persona"),
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
        self.scene_ref = "scene:1"
        self.event = AtomKey(Owner("event", "bot", "persona", "world:1"), "d03.world_event", "current")
        self.mapping = self_mapping_key(self.namespace)
        self.perspective = self_perspective_key(
            self.namespace, self_perspective_id(
                self.namespace, self.scene_ref, self.event.token,
            ),
        )
        self.feeling = AtomKey(Owner("persona", "bot", "persona"), "d04.feeling_state.v1", "current")
        self.interpretation = AtomKey(Owner("persona", "bot", "persona"), "d07.belief_revision.v1", "current")
        self.baseline = AtomKey(self.source.owner, "d04.encoding_baseline.v1", "baseline-c02")
        self.repository.ingest(
            Event(Scope("bot", "persona", "session"), "ingress", 1.0, "ingress", {}),
            SourceRecord("source-1", "A reported promise", "alice", "reported",
                         "reported", None, 2.0, "family-1", ("owner",), ("context",)),
        )
        context_keys = (self.event, self.mapping, self.perspective, self.feeling, self.interpretation)
        world_event = WorldEvent(
            "world:1", "message_received",
            (("entity:account:1", "sender_account"),), None, None, 2.0,
            self.scene_ref, (self.source.token,), "host_observed",
        )
        identity_mapping = SelfIdentityMapping(
            "self-map:integration", "persona:persona", "entity:self",
            "authority:self-identity:unit-fixture", "head-1", "incarnation-1", "active",
        )
        self_perspective = SelfPerspective(
            self.perspective.name, "persona:persona", "entity:self", self.scene_ref,
            self.mapping.token, self.event.token, "head-1",
        )
        self.store.graph_commit(GraphCandidate(
            Event(Scope("bot", "persona", "session"), "context", 3.0, "context", {}),
            tuple(GraphVersion(key, 0) for key in context_keys),
            (
                GraphWrite(self.event, {
                    **asdict(world_event),
                    "participant_roles": [list(item) for item in world_event.participant_roles],
                    "source_refs": list(world_event.source_refs),
                }),
                GraphWrite(self.mapping, asdict(identity_mapping)),
                GraphWrite(self.perspective, asdict(self_perspective)),
                GraphWrite(self.feeling, {"fixture": True}),
                GraphWrite(self.interpretation, {"fixture": True}),
            ),
        ))
        baseline_value = {
            "baseline_id": self.baseline.name,
            "source_refs": [self.source.token],
            "perspective_ref": self.perspective.token,
            "then_feeling_versions": [{"ref": self.feeling.token, "revision": 1}],
            "interpretation_versions": [{"ref": self.interpretation.token, "revision": 1}],
            "as_known_at": 2.0,
            "projection_policy_ref": "projection-policy:coordinator-unit-fixture",
            "projection_policy_version": "policy-1",
            "basis_version": "scheme-1",
            "parameter_version": "params-1",
            "salience_interval": None,
            "tone_interval": None,
            "unknown_reasons": [
                "salience_interval:numeric_projection_uncertified",
                "tone_interval:numeric_projection_uncertified",
            ],
        }
        decode_encoding_baseline(baseline_value).verify_committed_refs(
            self.store.graph_snapshot((self.source, *context_keys)),
        )
        self.store.graph_commit(GraphCandidate(
            Event(Scope("bot", "persona", "session"), "baseline", 3.5, "baseline", {}),
            (GraphVersion(self.baseline, 0),),
            (GraphWrite(self.baseline, baseline_value),),
        ))

    def close(self):
        self.store.close()

    def bundle(self):
        context_keys = (self.event, self.mapping, self.perspective, self.feeling, self.interpretation)
        context = EncodingContext(
            self.event.token, self.perspective.token, (self.feeling.token,),
            (self.interpretation.token,), (("promise", 0.9),),
            tuple((key.token, 1) for key in (self.source, *context_keys, self.baseline)),
        )
        prepared = self.pipeline.prepare_encoding(
            "source-1", context, audience="owner", purpose="context",
        )
        episode_id = prepared.proposal.episode.episode_id
        trace_id = prepared.proposal.trace.trace_id
        episode = episode_key("bot", "persona", episode_id)
        trace = subjective_trace_v2_key("bot", "persona", trace_id)
        job = runtime_job_key("bot", "persona", "activity-c02", "job-c02")
        snapshot = self.coordinator.read_snapshot(
            self.authority, self.lease,
            (self.source, self.access, *context_keys, self.baseline, episode, trace, job),
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
        d06 = self.adapter.compile_encoding_v2(
            envelope, prepared, encoding_baseline_ref=self.baseline.token,
        )
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
