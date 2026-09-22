import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sylanne3.contracts import Event, Scope, StaleRead
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.memory_recall import MemoryRecall
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_retrieval import MemoryQuery, MemoryRetriever
from sylanne3.memory_types import InterpretationRecord, SourceRecord, register_memory_types
from sylanne3.recall_policy import Action, Budget, RecallRequest, Trigger


class MemoryRecallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        registry = TypeRegistry()
        register_memory_types(registry)
        self.store = GraphStore(Path(self.temp.name) / "recall.db", registry)
        self.repository = MemoryRepository(self.store, "bot", "persona")
        self.retriever = MemoryRetriever(self.repository)
        self.recall = MemoryRecall(self.retriever)
        self._event_number = 0

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def event(self):
        self._event_number += 1
        return Event(
            Scope("bot", "persona", "session"),
            f"event-{self._event_number}",
            float(self._event_number),
            "recall-test",
            {},
        )

    def source(self, source_id, text, *, source_kind="observed", root=None):
        record = SourceRecord(
            source_id=source_id,
            text=text,
            speaker_id="speaker",
            source_kind=source_kind,
            assertion_status="reported" if source_kind == "reported" else "confirmed",
            occurred_at=1.0,
            recorded_at=float(self._event_number + 1),
            provenance_root=root or f"root-{source_id}",
            audiences=("public",),
            purposes=("expression",),
        )
        self.repository.ingest(self.event(), record)
        return record

    def request(self, *, trigger=Trigger.EXPLICIT_HISTORY, gaps=("detail",),
                checks=(), budget=Budget(6, 32, 64, 2)):
        return RecallRequest("request", trigger, gaps, checks, budget, 5.0)

    def run_recall(self, request, queries, *, working_ids=()):
        return self.recall.run(
            request,
            queries,
            audience="public",
            purpose="expression",
            working_ids=working_ids,
        )

    def test_empty_working_set_does_not_search_and_light_search_accounts_scans(self):
        self.source("unrelated", "other text")

        outcome = self.run_recall(
            self.request(),
            {"detail": MemoryQuery("source", terms=("missing",))},
        )

        self.assertEqual(outcome.plan.action, Action.INSUFFICIENT)
        self.assertEqual(len(outcome.batches), 1)
        coverage = outcome.batches[0]
        self.assertEqual(coverage.action, Action.LIGHT_SEARCH)
        self.assertEqual(coverage.gap, "detail")
        self.assertEqual(coverage.batch.hits, ())
        self.assertGreaterEqual(outcome.usage.candidates, 1)
        self.assertEqual(outcome.usage.candidates, coverage.batch.candidate_count)
        self.assertEqual(outcome.usage.nodes, coverage.batch.node_count)
        self.assertEqual(outcome.usage.model_calls, 0)

    def test_working_ids_are_an_exact_intersection_and_fill_only_the_named_gap(self):
        self.source("cold", "shared phrase")
        self.source("hot", "shared phrase")

        outcome = self.run_recall(
            self.request(gaps=("who", "when")),
            {
                "who": MemoryQuery("source", ids=("cold", "hot"), terms=("shared",)),
                "when": MemoryQuery("source", ids=("cold",), terms=("shared",)),
            },
            working_ids=("hot",),
        )

        self.assertEqual(outcome.batches[0].action, Action.WORKING_SET)
        self.assertEqual(outcome.batches[0].gap, "who")
        self.assertEqual(
            tuple(hit.record.source_id for hit in outcome.batches[0].batch.hits),
            ("hot",),
        )
        hot_evidence = next(
            item for item in outcome.plan.evidence if item.source_id == "hot"
        )
        self.assertEqual(hot_evidence.fills, ("who",))

    def test_mandatory_checks_stay_unresolved_without_lexical_search(self):
        self.source("correction", "the relevant source version is corrected")

        outcome = self.run_recall(
            self.request(trigger=Trigger.CORRECTION),
            {"detail": MemoryQuery("source", terms=("corrected",))},
        )

        self.assertEqual(outcome.plan.action, Action.INSUFFICIENT)
        self.assertIn("relevant_source_version", outcome.plan.missing_checks)
        self.assertEqual(outcome.batches, ())
        self.assertEqual(outcome.usage.candidates, 0)

    def test_interpretation_evidence_activates_real_sources_and_external_roots_only(self):
        observed = self.source("observed", "sensor record", root="root-observed")
        internal = self.source(
            "internal", "private synthesis", source_kind="internal", root="root-internal"
        )
        interpretation = InterpretationRecord(
            interpretation_id="interpretation",
            source_ids=(observed.source_id, internal.source_id),
            subject_id="subject",
            claim="bridge state is stable",
            status="confirmed",
            valid_from=1.0,
            recorded_at=10.0,
        )
        self.repository.interpret(self.event(), interpretation)

        outcome = self.run_recall(
            self.request(),
            {"detail": MemoryQuery("interpretation", ids=("interpretation",))},
        )

        self.assertEqual(outcome.plan.action, Action.READY)
        self.assertEqual(
            set(outcome.plan.activated_source_ids), {"observed", "internal"}
        )
        self.assertEqual(outcome.plan.external_evidence_families, ("root-observed",))
        self.assertFalse(outcome.plan.action_authorized)

    def test_final_epoch_recheck_rejects_a_write_after_search(self):
        self.source("wanted", "wanted detail")

        class MutatingRetriever(MemoryRetriever):
            def __init__(inner_self, repository, owner):
                super().__init__(repository)
                inner_self.owner = owner
                inner_self.changed = False

            def search(inner_self, *args, **kwargs):
                batch = super().search(*args, **kwargs)
                if not inner_self.changed:
                    inner_self.changed = True
                    inner_self.owner.source("late", "late write")
                return batch

        recall = MemoryRecall(MutatingRetriever(self.repository, self))
        with self.assertRaises(StaleRead):
            recall.run(
                self.request(),
                {"detail": MemoryQuery("source", ids=("wanted",))},
                audience="public",
                purpose="expression",
            )

    def test_query_names_must_be_declared_gaps_and_working_ids_are_strict(self):
        with self.assertRaisesRegex(ValueError, "declared gap"):
            self.run_recall(
                self.request(),
                {"other": MemoryQuery("source", ids=("x",))},
            )
        with self.assertRaises((TypeError, ValueError)):
            self.run_recall(
                self.request(),
                {"detail": MemoryQuery("source", ids=("x",))},
                working_ids=("x", "x"),
            )

    def test_hit_stops_followup_batches_even_when_coverage_is_incomplete(self):
        self.source("wanted", "wanted detail")

        class IncompleteHitRetriever(MemoryRetriever):
            def __init__(inner_self, repository):
                super().__init__(repository)
                inner_self.calls = 0

            def search(inner_self, *args, **kwargs):
                inner_self.calls += 1
                batch = super().search(*args, **kwargs)
                if inner_self.calls == 1:
                    return replace(
                        batch,
                        complete=False,
                        continuation=batch.hits[-1].key,
                    )
                return batch

        retriever = IncompleteHitRetriever(self.repository)
        outcome = MemoryRecall(retriever).run(
            self.request(budget=Budget(4, 64, 64, 0)),
            {"detail": MemoryQuery("source", ids=("wanted",))},
            audience="public",
            purpose="expression",
        )

        self.assertEqual(outcome.plan.action, Action.READY)
        self.assertEqual(retriever.calls, 1)
        self.assertFalse(outcome.batches[0].batch.complete)

    def test_large_total_budget_is_clamped_per_retriever_call(self):
        for number in range(10):
            self.source(f"source-{number:02d}", "unrelated")

        class RecordingRetriever(MemoryRetriever):
            def __init__(inner_self, repository):
                super().__init__(repository)
                inner_self.limits = []

            def search(inner_self, *args, **kwargs):
                inner_self.limits.append((kwargs["max_candidates"], kwargs["max_nodes"]))
                return super().search(*args, **kwargs)

        retriever = RecordingRetriever(self.repository)
        outcome = MemoryRecall(retriever).run(
            self.request(budget=Budget(4, 5000, 5000, 0)),
            {"detail": MemoryQuery("source", terms=("absent",))},
            audience="public",
            purpose="expression",
        )

        self.assertEqual(outcome.plan.action, Action.INSUFFICIENT)
        self.assertTrue(all(c <= 4096 and n <= 4096 for c, n in retriever.limits))

    def test_timeout_after_a_completed_batch_prevents_another_database_read(self):
        self.source("one", "unrelated")
        clock = FakeClock(0.0)

        class AdvancingRetriever(MemoryRetriever):
            def __init__(inner_self, repository):
                super().__init__(repository)
                inner_self.calls = 0

            def search(inner_self, *args, **kwargs):
                inner_self.calls += 1
                batch = super().search(*args, **kwargs)
                clock.now = 2.0
                return batch

        retriever = AdvancingRetriever(self.repository)
        request = RecallRequest(
            "request", Trigger.EXPLICIT_HISTORY, ("one", "two"), (),
            Budget(5, 32, 32, 0), 1.0,
        )
        outcome = MemoryRecall(retriever, clock=clock).run(
            request,
            {
                "one": MemoryQuery("source", terms=("missing-one",)),
                "two": MemoryQuery("source", terms=("missing-two",)),
            },
            audience="public",
            purpose="expression",
        )

        self.assertEqual(outcome.plan.action, Action.INSUFFICIENT)
        self.assertEqual(retriever.calls, 1)
        self.assertEqual(len(outcome.batches), 1)

    def test_initial_epoch_read_is_inside_the_request_deadline(self):
        clock = FakeClock(0.0)
        graph_epoch = self.store.graph_epoch

        def consuming_epoch(bot, persona):
            epoch = graph_epoch(bot, persona)
            clock.now = 2.0
            return epoch

        self.store.graph_epoch = consuming_epoch
        request = RecallRequest(
            "request", Trigger.EXPLICIT_HISTORY, ("detail",), (),
            Budget(5, 32, 32, 0), 1.0,
        )
        outcome = MemoryRecall(self.retriever, clock=clock).run(
            request,
            {"detail": MemoryQuery("source", ids=("missing",))},
            audience="public",
            purpose="expression",
        )

        self.assertEqual(outcome.plan.action, Action.INSUFFICIENT)
        self.assertEqual(outcome.batches, ())
        self.assertEqual(outcome.usage, Budget(0, 0, 0, 0))

    def test_time_filters_are_validated_even_when_no_query_runs(self):
        with self.assertRaisesRegex(ValueError, "as_known_at"):
            self.recall.run(
                self.request(trigger=Trigger.CORRECTION),
                {"detail": MemoryQuery("source", ids=("missing",))},
                audience="public",
                purpose="expression",
                as_known_at=-1,
            )


class FakeClock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


if __name__ == "__main__":
    unittest.main()
