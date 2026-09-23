import tempfile
import unittest
from pathlib import Path

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06 import D06DomainAdapter, EncodingContext, RecallIntent, TriggerKind
from sylanne3.domains.d06.pipeline import D06MemoryPipeline, SearchPlan
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_retrieval import MemoryQuery
from sylanne3.memory_types import SourceRecord, register_memory_types
from sylanne3.runtime_contracts import NamespaceId


class D06MemoryPipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        registry = TypeRegistry()
        register_memory_types(registry)
        self.store = GraphStore(Path(self.tmp.name) / "memory.db", registry)
        self.addCleanup(self.store.close)
        self.repository = MemoryRepository(self.store, "bot", "persona")
        self.domain = D06DomainAdapter(NamespaceId("bot", "persona"))
        self.pipeline = D06MemoryPipeline(self.domain, self.repository)
        self.scope = Scope("bot", "persona", "session")
        self.sequence = 0

    def event(self, kind):
        self.sequence += 1
        return Event(self.scope, f"{self.sequence}-{kind}", self.sequence, kind, {})

    def ingest(self, source_id="source-1"):
        return self.repository.ingest(
            self.event("ingest"),
            SourceRecord(
                source_id, "Project Aurora was promised for Friday", "alice",
                "observed", "confirmed", 1.0, 2.0, "family-aurora",
                ("owner",), ("context",),
            ),
        )

    def test_committed_authorized_source_can_feed_encoding_and_retrieval_candidates(self):
        self.ingest()
        prepared = self.pipeline.prepare_encoding(
            "source-1",
            EncodingContext(
                "event-aurora", "perspective@1", ("feeling@1",),
                ("interpretation@1",), (("promised", 0.9),), (("source-1", 1),),
            ),
            audience="owner", purpose="context",
        )
        self.assertEqual(prepared.status, "candidate")
        self.assertEqual(prepared.proposal.episode.source_refs, ("source-1",))
        self.assertGreaterEqual(len(prepared.proof_versions), 2)

        qualification = self.domain.qualify_recall(RecallIntent(
            "ask-aurora", TriggerKind.EXPLICIT_PAST_REQUEST, "when was Aurora promised?"
        ))
        outcome = self.pipeline.retrieve_candidates(
            qualification, "set-aurora",
            (SearchPlan("lexical", MemoryQuery("source", terms=("aurora",)), 0.8),),
            audience="owner", purpose="context", access_epoch=7, delete_epoch=11,
        )
        self.assertEqual(outcome.status, "candidate")
        self.assertEqual(tuple(item.content_ref for item in outcome.candidates.items), ("source-1",))
        self.assertEqual((outcome.candidates.access_epoch, outcome.candidates.delete_epoch), (7, 11))
        self.assertEqual(outcome.candidates.coverage, "complete")
        self.assertNotEqual(outcome.status, "recalled")

    def test_withdrawn_source_cannot_be_encoded_or_returned_as_a_candidate(self):
        self.ingest()
        self.repository.set_access(
            self.event("withdraw"), "source-1", audiences=("owner",),
            purposes=("context",), status="withdrawn", recorded_at=3.0,
        )
        with self.assertRaisesRegex(PermissionError, "unavailable"):
            self.pipeline.prepare_encoding(
                "source-1",
                EncodingContext("event", "perspective@1", (), (), (), ()),
                audience="owner", purpose="context",
            )
        qualification = self.domain.qualify_recall(RecallIntent(
            "ask", TriggerKind.EXPLICIT_PAST_REQUEST, "Aurora?"
        ))
        outcome = self.pipeline.retrieve_candidates(
            qualification, "set-withdrawn",
            (SearchPlan("exact", MemoryQuery("source", ids=("source-1",)), 1.0),),
            audience="owner", purpose="context", access_epoch=8, delete_epoch=12,
        )
        self.assertEqual(outcome.status, "candidate")
        self.assertEqual(outcome.candidates.items, ())

    def test_unqualified_greeting_does_not_touch_history_or_accept_missing_epochs(self):
        greeting = self.domain.qualify_recall(RecallIntent("hello", greeting_only=True))
        outcome = self.pipeline.retrieve_candidates(
            greeting, "set-greeting", (), audience="owner", purpose="context",
            access_epoch=0, delete_epoch=0,
        )
        self.assertEqual(outcome.status, "not_requested")
        self.assertIsNone(outcome.candidates)

        mandatory = self.domain.qualify_recall(RecallIntent(
            "ask", TriggerKind.EXPLICIT_PAST_REQUEST, "history"
        ))
        with self.assertRaisesRegex(ValueError, "access_epoch"):
            self.pipeline.retrieve_candidates(
                mandatory, "set", (), audience="owner", purpose="context",
                access_epoch=-1, delete_epoch=0,
            )

    def test_encoding_rejects_context_that_does_not_bind_the_committed_source_revision(self):
        self.ingest()
        with self.assertRaisesRegex(ValueError, "committed source revision"):
            self.pipeline.prepare_encoding(
                "source-1",
                EncodingContext(
                    "event", "perspective@1", (), (), (), (("source-1", 999),),
                ),
                audience="owner", purpose="context",
            )


if __name__ == "__main__":
    unittest.main()
