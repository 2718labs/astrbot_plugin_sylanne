import tempfile
import unittest
import json
from pathlib import Path

from sylanne3.contracts import Event, Scope, StaleRead
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, Owner, TypeRegistry
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_retrieval import MemoryQuery, MemoryRetriever
from sylanne3.memory_types import (
    InterpretationRecord,
    SourceRecord,
    register_memory_types,
)


class MemoryRetrievalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        registry = TypeRegistry()
        register_memory_types(registry)
        self.store = GraphStore(Path(self.tmp.name) / "memory.db", registry)
        self.addCleanup(self.store.close)
        self.repository = MemoryRepository(self.store, "bot", "persona")
        self.retriever = MemoryRetriever(self.repository)
        self.scope = Scope("bot", "persona", "session")
        self.sequence = 0

    def event(self, label):
        self.sequence += 1
        return Event(self.scope, f"{self.sequence}-{label}", self.sequence, label, {})

    @staticmethod
    def source(
        source_id,
        text,
        *,
        speaker_id="alice",
        provenance_root=None,
        audiences=("public",),
        purposes=("expression",),
        parent_source_ids=(),
        source_kind="observed",
        assertion_status="confirmed",
        recorded_at=1,
    ):
        return SourceRecord(
            source_id,
            text,
            speaker_id,
            source_kind,
            assertion_status,
            recorded_at,
            recorded_at,
            provenance_root or f"root-{source_id}",
            audiences,
            purposes,
            parent_source_ids,
            "unknown",
        )

    def ingest(self, source):
        return self.repository.ingest(self.event(f"ingest-{source.source_id}"), source)

    def test_query_is_an_exact_bounded_predicate(self):
        with self.assertRaises(ValueError):
            MemoryQuery("source")
        with self.assertRaises(ValueError):
            MemoryQuery("other", ids=("s",))
        with self.assertRaises(ValueError):
            MemoryQuery("source", ids=("s", "s"))
        with self.assertRaises(ValueError):
            MemoryQuery("source", terms=("x" * 257,))

        query = MemoryQuery("source", ids=("s",), terms=("BLUE",), subject_id="alice")
        self.assertEqual(query.terms, ("BLUE",))

    def test_source_search_combines_filters_and_never_returns_private_content(self):
        self.ingest(self.source("matching", "A blue notebook", provenance_root="family-a"))
        self.ingest(self.source("wrong-speaker", "A blue notebook", speaker_id="bob"))
        self.ingest(
            self.source(
                "private",
                "A blue private secret",
                audiences=("owner",),
                purposes=("context",),
            )
        )

        batch = self.retriever.search(
            MemoryQuery("source", terms=("BLUE", "note"), subject_id="alice"),
            audience="public",
            purpose="expression",
        )

        self.assertTrue(batch.complete)
        self.assertEqual([hit.record.source_id for hit in batch.hits], ["matching"])
        hit = batch.hits[0]
        self.assertEqual(hit.sources, (hit.record,))
        self.assertEqual(hit.provenance_roots, ("family-a",))
        self.assertGreaterEqual(len(hit.proof_versions), 2)
        self.assertEqual(batch.epoch, self.store.graph_epoch("bot", "persona"))

    def test_known_id_is_a_point_query_not_a_namespace_scan(self):
        for index in range(20):
            self.ingest(self.source(f"early-{index:02}", "unrelated"))
        self.ingest(self.source("zz-target", "needle"))

        batch = self.retriever.search(
            MemoryQuery("source", ids=("zz-target",)),
            audience="public",
            purpose="expression",
            max_candidates=1,
            page_size=1,
            max_pages=1,
        )

        self.assertTrue(batch.complete)
        self.assertEqual(batch.candidate_count, 1)
        self.assertEqual([hit.record.source_id for hit in batch.hits], ["zz-target"])

    def test_interpretation_hit_carries_authorized_sources_and_valid_time(self):
        self.ingest(self.source("s1", "first observation", provenance_root="family"))
        self.ingest(self.source("s2", "second report", provenance_root="family",
                                source_kind="reported", assertion_status="reported"))
        record = InterpretationRecord(
            "i1", ("s1", "s2"), "bridge", "Deck deadline is Friday",
            "reported", 10, 5, 20,
        )
        self.repository.interpret(self.event("interpret-i1"), record)

        active = self.retriever.search(
            MemoryQuery("interpretation", terms=("DEADLINE",), subject_id="bridge"),
            audience="public",
            purpose="expression",
            valid_at=10,
        )
        ended = self.retriever.search(
            MemoryQuery("interpretation", ids=("i1",)),
            audience="public",
            purpose="expression",
            valid_at=20,
        )

        self.assertEqual(len(active.hits), 1)
        hit = active.hits[0]
        self.assertEqual(tuple(source.source_id for source in hit.sources), ("s1", "s2"))
        self.assertEqual(hit.provenance_roots, ("family",))
        self.assertEqual(ended.hits, ())
        self.assertTrue(ended.complete)

    def test_page_and_node_budgets_return_honest_continuations(self):
        for source_id in ("a", "b", "c"):
            self.ingest(self.source(source_id, source_id))

        first = self.retriever.search(
            MemoryQuery("source", terms=("a",)),
            audience="public",
            purpose="expression",
            page_size=1,
            max_pages=1,
        )
        self.assertFalse(first.complete)
        self.assertIsNotNone(first.continuation)
        second = self.retriever.search(
            MemoryQuery("source", terms=("b",)),
            audience="public",
            purpose="expression",
            page_size=1,
            max_pages=1,
            after=first.continuation,
            expected_epoch=first.epoch,
        )
        self.assertEqual([hit.record.source_id for hit in second.hits], ["b"])

        exhausted = self.retriever.search(
            MemoryQuery("source", ids=("a",)),
            audience="public",
            purpose="expression",
            max_nodes=1,
        )
        self.assertFalse(exhausted.complete)
        self.assertEqual(exhausted.hits, ())
        self.assertEqual(exhausted.node_count, 1)
        self.assertIsNone(exhausted.continuation)

    def test_missing_ids_are_counted_and_can_finish(self):
        batch = self.retriever.search(
            MemoryQuery("source", ids=("missing",)),
            audience="public",
            purpose="expression",
            max_candidates=1,
        )
        self.assertTrue(batch.complete)
        self.assertEqual(batch.candidate_count, 1)
        self.assertEqual(batch.hits, ())

    def test_expected_epoch_rejects_a_changed_namespace(self):
        old_epoch = self.store.graph_epoch("bot", "persona")
        self.ingest(self.source("new", "new"))
        with self.assertRaises(StaleRead):
            self.retriever.search(
                MemoryQuery("source", ids=("new",)),
                audience="public",
                purpose="expression",
                expected_epoch=old_epoch,
            )

    def test_final_epoch_recheck_rejects_write_after_evidence_read(self):
        self.ingest(self.source("target", "target"))
        outer = self

        class WriteAfterReadRepository(MemoryRepository):
            wrote = False

            def read_source_evidence(self, source_id, **kwargs):
                result = super().read_source_evidence(source_id, **kwargs)
                if not self.wrote:
                    self.wrote = True
                    self.ingest(
                        outer.event("intervening"),
                        outer.source("intervening", "intervening", recorded_at=20),
                    )
                return result

        racing = MemoryRetriever(WriteAfterReadRepository(self.store, "bot", "persona"))
        with self.assertRaises(StaleRead):
            racing.search(
                MemoryQuery("source", ids=("target",)),
                audience="public",
                purpose="expression",
            )

    def test_times_are_validated_even_when_no_candidate_matches(self):
        for keyword, value in (("as_known_at", True), ("valid_at", -1), ("valid_at", float("inf"))):
            with self.subTest(keyword=keyword, value=value):
                with self.assertRaises(ValueError):
                    self.retriever.search(
                        MemoryQuery("source", ids=("missing",)),
                        audience="public",
                        purpose="expression",
                        **{keyword: value},
                    )

    def test_cursor_and_payload_identity_must_match_the_indexed_key(self):
        malformed_cursor = AtomKey(
            Owner("event", "bot", "persona", "s"), "memory.source", "wrong-name"
        )
        with self.assertRaises(ValueError):
            self.retriever.search(
                MemoryQuery("source", ids=("s",)),
                audience="public",
                purpose="expression",
                after=malformed_cursor,
            )

        self.ingest(self.source("s", "text"))
        key = AtomKey(Owner("event", "bot", "persona", "s"), "memory.source", "record")
        corrupted = self.source("other", "text").to_dict()
        self.store._db.execute(
            "UPDATE graph_atoms SET value=? WHERE token=?",
            (json.dumps(corrupted, sort_keys=True, separators=(",", ":")), key.token),
        )
        with self.assertRaises(ValueError):
            self.retriever.search(
                MemoryQuery("source", ids=("s",)),
                audience="public",
                purpose="expression",
            )

    def test_withdrawn_ancestor_removes_descendant_from_retrieval(self):
        self.ingest(self.source("parent", "parent"))
        self.ingest(self.source("child", "child", parent_source_ids=("parent",)))
        before = self.retriever.search(
            MemoryQuery("source", ids=("child",)),
            audience="public",
            purpose="expression",
        )
        self.assertEqual(len(before.hits), 1)

        self.repository.set_access(
            self.event("withdraw-parent"),
            "parent",
            audiences=("public",),
            purposes=("expression",),
            status="withdrawn",
            recorded_at=10,
        )
        after = self.retriever.search(
            MemoryQuery("source", ids=("child",)),
            audience="public",
            purpose="expression",
        )
        self.assertEqual(after.hits, ())


if __name__ == "__main__":
    unittest.main()
