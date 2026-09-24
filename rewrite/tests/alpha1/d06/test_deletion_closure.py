import unittest
import tempfile
from pathlib import Path

from sylanne3.domains.d06 import D06DomainAdapter, D06DomainProvider, ErasureRequest
from sylanne3.domains.d06.deletion_read import read_deletion_closure_candidate
from sylanne3.contracts import Event, Scope
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry, TypeSpec
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import SourceRecord, association_key, episode_key, register_memory_types, source_key, subjective_trace_key
from sylanne3.runtime_contracts import NamespaceId


class DeletionClosureTests(unittest.TestCase):
    def setUp(self):
        self.namespace = NamespaceId("bot", "persona")
        self.domain = D06DomainAdapter(self.namespace)
        self.root = source_key("bot", "persona", "source-1")

    def _key(self, type_name, name):
        return AtomKey(Owner("event", "bot", "persona", "source-1"), type_name, name)

    def test_closure_candidate_preserves_relation_kinds_and_before_epochs(self):
        current = self._key("memory.interpretation", "current")
        historical = self._key("d06.recollection.v1", "history")
        association = self._key("memory.association", "edge")
        cache = self._key("memory.cache", "projection")
        request = ErasureRequest(
            "erase-1", (self.root.token,), "all_derived", 7, 11,
        )

        closure = self.domain.prepare_deletion_closure(
            request,
            current_dependency_refs=(current.token,),
            historical_source_refs=(historical.token,),
            association_refs=(association.token,),
            graph_cache_refs=(cache.token,),
        )

        self.assertEqual(closure.namespace, self.namespace)
        self.assertEqual(closure.root_refs, (self.root.token,))
        self.assertEqual(closure.current_dependency_refs, (current.token,))
        self.assertEqual(closure.historical_source_refs, (historical.token,))
        self.assertEqual(closure.association_refs, (association.token,))
        self.assertEqual(closure.graph_cache_refs, (cache.token,))
        self.assertEqual(closure.access_epoch_before, 7)
        self.assertEqual(closure.delete_epoch_before, 11)
        self.assertEqual(closure.status, "proposal_requires_authority_v2")
        self.assertNotIn("barrier_installed", closure.__dict__)
        self.assertNotIn("accepted", closure.__dict__)
        self.assertNotIn("issuer", closure.__dict__)

    def test_cross_namespace_or_noncanonical_closure_ref_is_rejected(self):
        request = ErasureRequest(
            "erase-1", (self.root.token,), "all_derived", 7, 11,
        )
        foreign = source_key("bot", "other-persona", "source-1")
        with self.assertRaisesRegex(ValueError, "cross namespace"):
            self.domain.prepare_deletion_closure(
                request, historical_source_refs=(foreign.token,),
            )
        with self.assertRaisesRegex(ValueError, "canonical graph atom"):
            self.domain.prepare_deletion_closure(
                request, association_refs=("caller-digest-is-not-evidence",),
            )

    def test_erasure_plan_remains_pending_without_authority_evidence(self):
        request = ErasureRequest(
            "erase-1", (self.root.token,), "all_derived", 7, 11,
        )
        plan = self.domain.plan_erasure(request)
        self.assertEqual(plan.status, "pending_runtime_authority")
        self.assertNotIn(plan.status, {"accepted", "closed", "barrier_installed"})

    def test_graph_read_finds_source_descendants_episode_trace_and_association_across_pages(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        if True:
            registry = TypeRegistry()
            register_memory_types(registry)
            recollection_spec = next(
                spec for spec in D06DomainProvider.type_specs()
                if spec.name == "d06.recollection.v1"
            )
            registry.register(recollection_spec)
            registry.register(TypeSpec("d03.world_event", ("event",), "state", lambda _: None))
            store = GraphStore(Path(tmp.name) / "memory.db", registry)
            self.addCleanup(store.close)
            repository = MemoryRepository(store, "bot", "persona")
            scope = Scope("bot", "persona", "session")
            def source(source_id, parents=()):
                return SourceRecord(source_id, source_id, "speaker", "reported", "reported",
                                    None, 1.0, "family", ("owner",), ("context",), parents)
            repository.ingest(Event(scope, "root", 1, "ingest", {}), source("source-1"))
            repository.ingest(Event(scope, "child", 2, "ingest", {}), source("child-1", ("source-1",)))
            repository.ingest(Event(scope, "grandchild", 3, "ingest", {}), source("grandchild-1", ("child-1",)))
            repository.ingest(Event(scope, "other", 4, "ingest", {}), source("other-1"))
            child = source_key("bot", "persona", "child-1")
            grandchild = source_key("bot", "persona", "grandchild-1")
            other = source_key("bot", "persona", "other-1")
            episode = episode_key("bot", "persona", "episode-1")
            trace = subjective_trace_key("bot", "persona", "trace-1")
            association = association_key("bot", "persona", "other-1", "association-1")
            interpretation = AtomKey(
                Owner("event", "bot", "persona", "interpretation-1"),
                "memory.interpretation", "current",
            )
            recollection = AtomKey(
                Owner("activity", "bot", "persona", "activity-1"),
                "d06.recollection.v1", "current",
            )
            event_ref = AtomKey(Owner("event", "bot", "persona", "event-1"), "d03.world_event", "current")
            perspective = AtomKey(Owner("scene", "bot", "persona", "scene-1"), "d03.role_binding", "current")
            writes = (
                GraphWrite(episode, {"episode_id": "episode-1", "source_refs": [grandchild.token],
                                     "event_ref": event_ref.token}),
                GraphWrite(trace, {"trace_id": "trace-1", "episode_ref": episode.token,
                                   "perspective_ref": perspective.token, "then_feeling_refs": [],
                                   "interpretation_refs": [], "detail_weights": []}),
                GraphWrite(association, {"association_id": "association-1",
                                         "source_ref": other.token, "target_ref": child.token,
                                         "kind": "similarity", "weight": 0.5,
                                         "context_tags": [], "basis_source_refs": [other.token],
                                         "content_reality": "reported"}),
                GraphWrite(interpretation, {
                    "interpretation_id": "interpretation-1", "source_ids": ["grandchild-1"],
                    "subject_id": "self", "claim": "claim", "status": "confirmed",
                    "valid_from": 1.0, "recorded_at": 1.0, "valid_to": None,
                }),
                GraphWrite(recollection, {
                    "recollection_id": "recollection-1", "activity_id": "activity-1",
                    "selection_ref": "selection-1", "candidate_set_id": "candidate-1",
                    "content_refs": [grandchild.token], "activity_basis_refs": [grandchild.token],
                    "now_interpretation_refs": [interpretation.token],
                    "feeling_experience_refs": [grandchild.token], "self_understanding_refs": [],
                    "provenance_eligibility": [], "focus_epoch": 1,
                    "access_epoch": 1, "delete_epoch": 1,
                }),
            )
            store.graph_commit(GraphCandidate(
                Event(scope, "derived", 5, "derived", {}),
                tuple(GraphVersion(write.key, 0) for write in writes), writes,
            ))
            request = ErasureRequest("erase-1", (self.root.token,), "all_derived", 1, 1)
            result = read_deletion_closure_candidate(repository, request, page_limit=1)
            self.assertTrue(result.scan_complete)
            self.assertEqual(result.status, "hold")
            self.assertEqual(result.source_descendant_refs, tuple(sorted((child.token, grandchild.token))))
            self.assertEqual(result.episode_refs, (episode.token,))
            self.assertEqual(result.trace_refs, (trace.token,))
            self.assertEqual(result.association_refs, (association.token,))
            self.assertEqual(result.interpretation_refs, (interpretation.token,))
            self.assertEqual(result.recollection_refs, (recollection.token,))
            self.assertIn("current_reverse_dependency_snapshot", result.missing_facets)
            self.assertIn("historical_graph_values", result.missing_facets)
            self.assertIn("current_episode_refs", result.covered_facets)
            self.assertFalse(any("dependency" in item for item in result.covered_facets))
            self.assertFalse(hasattr(result, "request_authorized"))
            missing_target_request = ErasureRequest(
                "erase-missing", (source_key("bot", "persona", "absent").token,),
                "all_derived", 1, 1,
            )
            missing_target = read_deletion_closure_candidate(
                repository, missing_target_request, page_limit=1,
            )
            self.assertIn("target_unavailable", missing_target.missing_facets)
            self.assertEqual(missing_target.status, "hold")
            partial = read_deletion_closure_candidate(repository, request, page_limit=1, max_pages=2)
            self.assertFalse(partial.scan_complete)
            self.assertEqual(partial.status, "partial_hold")
            self.assertIsNotNone(partial.next_after)

            original_query = store.graph_query
            query_count = 0
            def query_with_interpage_write(*args, **kwargs):
                nonlocal query_count
                page = original_query(*args, **kwargs)
                query_count += 1
                if query_count == 1:
                    changed_key = AtomKey(
                        Owner("event", "bot", "persona", "drift"),
                        "d03.world_event", "current",
                    )
                    store.graph_commit(GraphCandidate(
                        Event(scope, "drift", 6, "test", {}),
                        (GraphVersion(changed_key, 0),),
                        (GraphWrite(changed_key, {}),),
                    ))
                return page
            store.graph_query = query_with_interpage_write
            drifted = read_deletion_closure_candidate(repository, request, page_limit=1)
            self.assertFalse(drifted.scan_complete)
            self.assertEqual(drifted.status, "partial_hold")
            self.assertIn("namespace_changed", drifted.missing_facets)


if __name__ == "__main__":
    unittest.main()
