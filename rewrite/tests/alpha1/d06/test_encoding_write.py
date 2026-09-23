import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sylanne3.contracts import Event, Scope, StaleRead
from sylanne3.domains.d06 import (
    D06DomainAdapter, D06DomainProvider, EncodingContext, SourceAdmission,
)
from sylanne3.domains.d06.pipeline import D06MemoryPipeline
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (
    AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry, TypeSpec,
)
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import (
    SourceRecord, access_key, register_memory_types, source_key,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    RUNTIME_SCHEMA, VersionGuard, canonical_digest,
)


class EncodingWriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.registry = TypeRegistry()
        register_memory_types(self.registry)
        for name, owner in (
            ("d03.world_event", "event"), ("d03.role_binding", "scene"),
            ("d04.feeling_state.v1", "persona"), ("d07.belief_revision.v1", "persona"),
        ):
            self.registry.register(TypeSpec(name, (owner,), "state", lambda _: None))
        self.store = GraphStore(Path(self.tmp.name) / "memory.db", self.registry)
        self.addCleanup(self.store.close)
        self.namespace = NamespaceId("bot", "persona")
        self.adapter = D06DomainAdapter(self.namespace)
        self.pipeline = D06MemoryPipeline(
            self.adapter, MemoryRepository(self.store, "bot", "persona")
        )
        self.sequence = 0
        self.scope = Scope("bot", "persona", "session")
        self.source = source_key("bot", "persona", "source-1")
        self.access = access_key("bot", "persona", "source-1")
        self.event_ref = AtomKey(Owner("event", "bot", "persona", "world-1"), "d03.world_event", "current")
        self.perspective = AtomKey(Owner("scene", "bot", "persona", "scene-1"), "d03.role_binding", "current")
        self.feeling = AtomKey(Owner("persona", "bot", "persona"), "d04.feeling_state.v1", "current")
        self.interpretation = AtomKey(Owner("persona", "bot", "persona"), "d07.belief_revision.v1", "current")

    def event(self, kind):
        self.sequence += 1
        return Event(self.scope, f"{self.sequence}-{kind}", self.sequence, kind, {})

    def seed(self):
        self.pipeline.repository.ingest(
            self.event("source"),
            SourceRecord("source-1", "A reported promise", "alice", "reported", "reported",
                         None, 2.0, "family-1", ("owner",), ("context",)),
        )
        refs = (self.event_ref, self.perspective, self.feeling, self.interpretation)
        self.store.graph_commit(GraphCandidate(
            self.event("context"), tuple(GraphVersion(key, 0) for key in refs),
            tuple(GraphWrite(key, {"committed": True}) for key in refs),
        ))
        context = EncodingContext(
            self.event_ref.token, self.perspective.token, (self.feeling.token,),
            (self.interpretation.token,), (("promise", 0.9), ("weather", 0.2)),
            tuple((key.token, 1) for key in (self.source, *refs)),
        )
        prepared = self.pipeline.prepare_encoding(
            "source-1", context, audience="owner", purpose="context",
        )
        return prepared

    def envelope(self, prepared, *, missing=()):
        episode = prepared.proposal.episode.episode_id
        trace = prepared.proposal.trace.trace_id
        from sylanne3.memory_types import episode_key, subjective_trace_key
        reads = tuple(version for version in (
            *prepared.proof_versions,
            *(GraphVersion(key, 1) for key in
              (self.event_ref, self.perspective, self.feeling, self.interpretation)),
            GraphVersion(episode_key("bot", "persona", episode), 0),
            GraphVersion(subjective_trace_key("bot", "persona", trace), 0),
        ) if version.key not in missing)
        admission = self.adapter.admit_source(SourceAdmission(
            "source-1", "A reported promise", "alice", "reported", "reported",
            "reported_claim", "not_applicable", None, 2.0, "family-1",
            ("owner",), ("context",),
        ))
        input_refs = (self.source.token,)
        return CommandEnvelope(
            RUNTIME_SCHEMA,
            OperationIdentity("encoding-1", None, "attempt-1", "encode",
                              "operation-1", canonical_digest({"input_refs": list(input_refs)})),
            AuthorityContext("worker", "d06", "capability-1", self.namespace,
                             ("event",), "context", ("owner",), "policy-1", 1),
            VersionGuard(reads, (), 1, 1, "catalogue-1", "scheme-1", "operator-1",
                         "policy-1", (), (), ()),
            admission.qualification, input_refs, "budget-1", 100.0, 10.0,
            "interval-1", ("source-1",),
        )

    def test_committed_proofs_compile_separate_episode_and_subjective_trace(self):
        prepared = self.seed()
        envelope = self.envelope(prepared)
        proposal = self.adapter.compile_encoding(envelope, prepared)
        D06DomainProvider().validate(proposal)
        episode, trace = proposal.typed_writes
        self.assertEqual(episode.value["source_refs"], [self.source.token])
        self.assertEqual(episode.value["event_ref"], self.event_ref.token)
        self.assertEqual(trace.value["episode_ref"], episode.key.token)
        self.assertEqual(trace.value["then_feeling_refs"], [self.feeling.token])
        self.assertEqual(trace.value["interpretation_refs"], [self.interpretation.token])
        self.assertEqual(trace.value["detail_weights"], [["promise", 0.9], ["weather", 0.2]])
        self.assertEqual(episode.dependencies, ())
        self.assertIn(GraphVersion(self.access, 1), proposal.dependencies.historical_provenance)
        receipt = self.store.graph_commit(GraphCandidate(
            self.event("encoding"), envelope.version_guard.read_versions, proposal.typed_writes,
        ))
        self.assertEqual(receipt.status, "committed")

    def test_missing_committed_context_or_access_proof_is_rejected(self):
        prepared = self.seed()
        with self.assertRaisesRegex(ValueError, "committed read proof"):
            self.adapter.compile_encoding(
                self.envelope(prepared, missing=(self.feeling,)), prepared,
            )
        with self.assertRaisesRegex(ValueError, "source proof differs"):
            self.adapter.compile_encoding(
                self.envelope(prepared, missing=(self.access,)), prepared,
            )

    def test_candidate_is_not_written_by_preparation_or_compilation(self):
        prepared = self.seed()
        proposal = self.adapter.compile_encoding(self.envelope(prepared), prepared)
        snapshot = self.store.graph_snapshot(tuple(write.key for write in proposal.typed_writes))
        self.assertTrue(all(atom.revision == 0 and not atom.valid for atom in snapshot.atoms))

    def test_access_withdrawal_after_preparation_stales_the_write(self):
        prepared = self.seed()
        envelope = self.envelope(prepared)
        proposal = self.adapter.compile_encoding(envelope, prepared)
        self.pipeline.repository.set_access(
            self.event("withdraw"), "source-1", audiences=("owner",),
            purposes=("context",), status="withdrawn", recorded_at=3.0,
        )
        with self.assertRaises(StaleRead):
            self.store.graph_commit(GraphCandidate(
                self.event("stale-encoding"), envelope.version_guard.read_versions,
                proposal.typed_writes,
            ))

    def test_provider_rejects_a_trace_detached_from_its_episode(self):
        prepared = self.seed()
        proposal = self.adapter.compile_encoding(self.envelope(prepared), prepared)
        episode, trace = proposal.typed_writes
        detached = GraphWrite(
            trace.key, {**trace.value, "episode_ref": episode.value["event_ref"]},
        )
        with self.assertRaisesRegex(ValueError, "episode_ref"):
            D06DomainProvider().validate(replace(proposal, typed_writes=(episode, detached)))


if __name__ == "__main__":
    unittest.main()
