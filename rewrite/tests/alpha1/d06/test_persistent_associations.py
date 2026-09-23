import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06 import D06DomainAdapter, D06DomainProvider
from sylanne3.domains.d06.pipeline import D06MemoryPipeline
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import GraphCandidate, GraphVersion, TypeRegistry
from sylanne3.memory_association import ActivationPolicy, PersistentAssociationReader
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import SourceRecord, association_key, register_memory_types, source_key
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    RUNTIME_SCHEMA, SourceQualification, VersionGuard, canonical_digest,
    DependencySet,
)


class PersistentAssociationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        registry = TypeRegistry()
        register_memory_types(registry)
        self.store = GraphStore(Path(self.temp.name) / "associations.db", registry)
        self.addCleanup(self.store.close)
        self.repo = MemoryRepository(self.store, "bot", "persona")
        self.adapter = D06DomainAdapter(NamespaceId("bot", "persona"))
        self.pipeline = D06MemoryPipeline(self.adapter, self.repo)
        self.seq = 0
        for source_id in ("a", "b", "basis"):
            self.repo.ingest(self._event(f"source-{source_id}"), SourceRecord(
                source_id, f"original {source_id}", "user", "reported", "reported",
                None, float(self.seq), f"family-{source_id}", ("owner",), ("context",),
            ))

    def _event(self, kind):
        self.seq += 1
        return Event(Scope("bot", "persona", "session"), f"{self.seq}-{kind}",
                     self.seq, kind, {})

    def _envelope(self, prepared, association_id):
        key = association_key("bot", "persona", "a", association_id)
        reads = (*prepared.proof_versions, GraphVersion(key, 0))
        refs = tuple(source_key("bot", "persona", name).token
                     for name in ("a", "b", "basis"))
        input_refs = refs
        return CommandEnvelope(
            RUNTIME_SCHEMA,
            OperationIdentity("activity", None, "attempt", "associate", "operation",
                              canonical_digest({"input_refs": list(input_refs)})),
            AuthorityContext("worker", "d06", "capability", NamespaceId("bot", "persona"),
                             ("event",), "context", ("owner",), "policy", 1),
            VersionGuard(reads, (), 1, 1, "catalogue", "scheme", "operator", "policy",
                         (), (), ()),
            SourceQualification(refs, "reported", None, 3.0, "external_report",
                                "eligible", 0.5, "not_applicable"),
            input_refs, "budget", 100.0, 10.0, "interval", ("source-a",),
        )

    def _compile(self, prepared):
        association_id = self.adapter.association_identity(
            "a", "b", ("basis",), kind="subjective_meaning",
            context_tags=("rain",), content_reality="subjective",
        ).name
        return self.adapter.compile_association(
            self._envelope(prepared, association_id), prepared,
            kind="subjective_meaning", weight=0.8,
            context_tags=("rain",), content_reality="subjective",
        )

    def test_persistent_edge_is_separate_from_source_and_traversal_is_bounded(self):
        prepared = self.pipeline.prepare_association(
            "a", "b", ("basis",), audience="owner", purpose="context",
        )
        proposal = self._compile(prepared)
        D06DomainProvider().validate(proposal)
        write = proposal.typed_writes[0]
        self.assertEqual(write.value["content_reality"], "subjective")
        self.assertEqual(write.value["basis_source_refs"], [source_key("bot", "persona", "basis").token])
        self.store.graph_commit(GraphCandidate(
            self._event("association"), proposal.envelope.version_guard.read_versions,
            proposal.typed_writes,
        ))
        policy = ActivationPolicy(0.5, 0.4, 8, 8, 1e-6)
        reader = PersistentAssociationReader(self.repo)
        rain = reader.traverse("a", policy, audience="owner", purpose="context",
                               context_tags=("rain",))
        clear = reader.traverse("a", policy, audience="owner", purpose="context",
                                context_tags=("clear",))
        target = source_key("bot", "persona", "b").token
        self.assertGreater(dict(rain.activation.activations)[target], 0)
        self.assertNotIn(target, dict(clear.activation.activations))
        self.assertNotIn(target, clear.source_refs)
        self.assertEqual(rain.coverage, "bounded_complete")
        self.assertEqual(rain.edge_refs, (write.key.token,))
        capped = reader.traverse(
            "a", ActivationPolicy(0.5, 0.4, 8, 1, 1e-6),
            audience="owner", purpose="context", context_tags=("rain",),
        )
        self.assertEqual(capped.coverage, "partial")
        self.assertNotIn(target, dict(capped.activation.activations))
        closure = reader.collect_deletion_refs("basis")
        self.assertEqual(closure.association_refs, (write.key.token,))
        self.assertEqual(closure.coverage, "complete")
        self.assertEqual(self.repo.read_source("a", audience="owner", purpose="context").text,
                         "original a")

        self.repo.set_access(self._event("withdraw"), "basis", audiences=("owner",),
                             purposes=("context",), status="withdrawn", recorded_at=5.0)
        after = reader.traverse("a", policy, audience="owner", purpose="context",
                                context_tags=("rain",))
        self.assertNotIn(target, dict(after.activation.activations))

    def test_missing_access_and_unproven_association_are_rejected(self):
        prepared = self.pipeline.prepare_association(
            "a", "b", ("basis",), audience="owner", purpose="context",
        )
        proposal = self._compile(prepared)
        with self.assertRaisesRegex(ValueError, "lacks qualified source, access"):
            D06DomainProvider().validate(replace(proposal, dependencies=DependencySet()))
        self.repo.set_access(self._event("withdraw"), "basis", audiences=("owner",),
                             purposes=("context",), status="withdrawn", recorded_at=5.0)
        with self.assertRaises(PermissionError):
            self.pipeline.prepare_association("a", "b", ("basis",),
                                              audience="owner", purpose="context")


if __name__ == "__main__":
    unittest.main()
