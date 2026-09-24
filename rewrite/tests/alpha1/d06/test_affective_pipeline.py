import tempfile
import unittest
from pathlib import Path

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d04 import AffectAxis, AffectCoupling, AffectProvider, AffectScheme, FeelingState, MoodField
from sylanne3.domains.d06 import D06DomainAdapter, RecallIntent, RecollectionContext, SelectionTicket, TriggerKind
from sylanne3.domains.d06.pipeline import D06MemoryPipeline, SearchPlan
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphWrite, Owner, TypeRegistry
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_reconstruction import DetailCue
from sylanne3.memory_retrieval import MemoryQuery
from sylanne3.memory_types import (
    SourceRecord, episode_key, register_memory_types, source_key,
    subjective_trace_key, subjective_trace_v2_key,
)
from sylanne3.runtime_contracts import NamespaceId, SourceQualification


class AffectivePipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scheme = AffectScheme(
            "d04.affect.scheme.v1", "scheme-1", "operator-1", "parameters-1",
            "coupling-1", (AffectAxis("warmth", "normalized", "warmth"),), (),
        )
        self.coupling = AffectCoupling("recall", "coupling-1", "warmth", "warmth", 0, 0.5, 0.5)
        registry = TypeRegistry()
        register_memory_types(registry)
        for spec in AffectProvider(active_scheme=self.scheme).type_specs():
            registry.register(spec)
        self.store = GraphStore(Path(self.tmp.name) / "memory.db", registry)
        self.addCleanup(self.store.close)
        self.repository = MemoryRepository(self.store, "bot", "persona")
        self.pipeline = D06MemoryPipeline(D06DomainAdapter(NamespaceId("bot", "persona")), self.repository)
        self.scope = Scope("bot", "persona", "session")
        self.mood_key = AtomKey(Owner("persona", "bot", "persona"), "d04.mood_field.v1", "current")
        self.source = SourceRecord("message-1", "I waited a long time", "user", "reported",
                                   "reported", 1.0, 2.0, "family-1", ("owner",), ("context",))
        self.repository.ingest(Event(self.scope, "ingest", 1, "ingest", {}), self.source)
        self.qualification = self.pipeline.adapter.qualify_recall(
            RecallIntent("ask", TriggerKind.EXPLICIT_PAST_REQUEST, "what happened?"))
        self.refresh()

    def refresh(self):
        self.outcome = self.pipeline.retrieve_candidates(
            self.qualification, "set", (SearchPlan("exact", MemoryQuery("source", ids=("message-1",)), 1),),
            audience="owner", purpose="context", access_epoch=1, delete_epoch=1,
        )
        self.ticket = SelectionTicket("ticket", "activity", "set",
                                      (self.outcome.candidates.items[0].candidate_id,), 1)

    def mood(self, warmth, event_id):
        mood = MoodField("mood-1", "scheme-1", (("warmth", warmth),),
                         (source_key("bot", "persona", "message-1").token,),
                         "parameters-1", "coupling-1", 2.0)
        snapshot = self.store.graph_snapshot((self.mood_key,))
        self.store.graph_commit(GraphCandidate(
            Event(self.scope, event_id, 2, "mood", {}), snapshot.versions,
            (GraphWrite(self.mood_key, {**mood.__dict__, "coordinates": [["warmth", warmth]],
                                        "source_refs": list(mood.source_refs)}),), snapshot.epochs,
        ))
        result = self.store.graph_snapshot((self.mood_key,))
        self.refresh()
        return result

    def prepare(self, snapshot, *, encoding_trace_id=None):
        return self.pipeline.prepare_affective_recollection(
            self.outcome, self.ticket, RecollectionContext((), (), ()),
            audience="owner", purpose="context", mood_snapshot=snapshot,
            mood_key=self.mood_key, scheme=self.scheme, coupling=self.coupling,
            source_qualification=SourceQualification(
                (source_key("bot", "persona", "message-1").token,), "reported", 1.0, 2.0,
                "external_report", "eligible", 0.6, "not_applicable"),
            base_salience=(0.4, 0.6), base_tone=(-0.1, 0.1),
            detail_cues=(DetailCue("waiting", (0, 8), 0.65),), temporal_focus=True,
            encoding_trace_id=encoding_trace_id,
            encoding_trace_version=2,
        )

    def test_mood_changes_subjective_candidate_without_changing_literal_source(self):
        warm = self.prepare(self.mood(0.8, "warm"))
        guarded = self.prepare(self.mood(-0.8, "guarded"))
        self.assertEqual(warm.source_fields, guarded.source_fields)
        self.assertNotEqual(warm.subjective_tone, guarded.subjective_tone)
        self.assertNotEqual(warm.subjective_weight, guarded.subjective_weight)
        self.assertEqual(warm.status, "candidate_hold")

    def test_committed_then_feeling_stays_separate_from_current_mood_and_source(self):
        source_ref = source_key("bot", "persona", "message-1").token
        feeling = AtomKey(Owner("persona", "bot", "persona"),
                          "d04.feeling_state.v1", "then")
        episode = episode_key("bot", "persona", "episode-then")
        trace = subjective_trace_v2_key("bot", "persona", "trace-then")
        event = AtomKey(Owner("event", "bot", "persona", "event-then"),
                        "d03.world_event", "current")
        baseline = AtomKey(Owner("event", "bot", "persona", "event-then"),
                           "d04.encoding_baseline.v1", "record")
        perspective = AtomKey(Owner("scene", "bot", "persona", "scene-then"),
                              "d03.role_binding", "current")
        state = FeelingState(
            "process:then", source_ref, "scheme-1", "operator-1",
            (("warmth", 0.2),), ("meaning:then",), ("interpretation:then",),
            (), (source_ref,), "parameters-1", "coupling-1", 2.0,
        )
        prior = self.store.graph_snapshot((feeling, episode, trace, baseline))
        self.store.graph_commit(GraphCandidate(
            Event(self.scope, "encoding-then", 2, "encoding", {}), prior.versions,
            (GraphWrite(feeling, {
                **state.__dict__,
                "coordinates": [list(item) for item in state.coordinates],
                "meaning_refs": list(state.meaning_refs),
                "interpretation_refs": list(state.interpretation_refs),
                "active_driver_refs": list(state.active_driver_refs),
                "historical_source_refs": list(state.historical_source_refs),
            }),
             GraphWrite(episode, {"episode_id": "episode-then", "source_refs": [source_ref],
                                  "event_ref": event.token}),
             GraphWrite(trace, {"trace_id": "trace-then", "episode_ref": episode.token,
                                "perspective_ref": perspective.token,
                                "then_feeling_refs": [feeling.token],
                                "interpretation_refs": [], "detail_weights": [],
                                "encoding_baseline_ref": baseline.token}),
             GraphWrite(baseline, {
                 "baseline_id": "baseline-then", "source_refs": [source_ref],
                 "perspective_ref": perspective.token,
                 "then_feeling_versions": [{"ref": feeling.token, "revision": 1}],
                 "interpretation_versions": [], "as_known_at": None,
                 "projection_policy_ref": "policy-unresolved",
                 "projection_policy_version": "policy-v1", "basis_version": "scheme-1",
                 "parameter_version": "parameters-1", "salience_interval": None,
                 "tone_interval": None,
                 "unknown_reasons": ["salience_interval:unknown", "tone_interval:unknown"],
             })),
            prior.epochs,
        ))
        warm = self.prepare(self.mood(0.8, "warm"), encoding_trace_id="trace-then")
        guarded = self.prepare(self.mood(-0.8, "guarded"), encoding_trace_id="trace-then")
        self.assertEqual(warm.source_fields, guarded.source_fields)
        self.assertEqual(warm.then_feeling_refs, (feeling.token,))
        self.assertEqual(warm.then_feeling_refs, guarded.then_feeling_refs)
        self.assertEqual(warm.then_feeling_status, "baseline_versioned_refs")
        self.assertEqual(warm.encoding_trace_ref, trace.token)
        self.assertNotEqual(warm.subjective_tone, guarded.subjective_tone)
        self.assertIn(feeling, (version.key for version in warm.read_versions))
        self.assertIn(trace, (version.key for version in guarded.read_versions))
        self.assertNotEqual(
            next(version.revision for version in warm.read_versions if version.key == self.mood_key),
            next(version.revision for version in guarded.read_versions if version.key == self.mood_key),
        )
        current = self.store.graph_snapshot((feeling,))
        self.store.graph_commit(GraphCandidate(
            Event(self.scope, "feeling-update", 3, "feeling", {}), current.versions,
            (GraphWrite(feeling, {
                **current.get(feeling).value, "cursor": 3.0, "revision": 2,
            }),), current.epochs,
        ))
        with self.assertRaisesRegex(RuntimeError, "encoding source, access, or trace changed"):
            self.prepare(self.mood(0.2, "after-feeling-update"), encoding_trace_id="trace-then")

    def test_withdrawal_and_stale_mood_stop_preparation(self):
        old_mood = self.mood(0.8, "warm")
        self.mood(-0.8, "guarded")
        with self.assertRaisesRegex(RuntimeError, "epochs differ"):
            self.prepare(old_mood)
        current_mood = self.store.graph_snapshot((self.mood_key,))
        self.repository.set_access(
            Event(self.scope, "withdraw", 3, "withdraw", {}), "message-1",
            audiences=("owner",), purposes=("context",), status="withdrawn", recorded_at=3,
        )
        with self.assertRaisesRegex(PermissionError, "no longer accessible"):
            self.prepare(current_mood)

    def test_ticket_must_select_a_source_in_the_retrieved_set(self):
        snapshot = self.mood(0.5, "warm")
        self.ticket = SelectionTicket("other", "activity", "set", ("absent",), 1)
        with self.assertRaisesRegex(ValueError, "does not select"):
            self.prepare(snapshot)

    def test_committed_encoding_evidence_tracks_source_access_without_fabricating_baseline(self):
        episode = episode_key("bot", "persona", "episode-1")
        trace = subjective_trace_key("bot", "persona", "trace-1")
        feeling = AtomKey(Owner("persona", "bot", "persona"), "d04.feeling_state.v1", "current")
        event = AtomKey(Owner("event", "bot", "persona", "event-1"), "d03.world_event", "current")
        perspective = AtomKey(Owner("scene", "bot", "persona", "scene-1"), "d03.role_binding", "current")
        prior = self.store.graph_snapshot((episode, trace))
        self.store.graph_commit(GraphCandidate(
            Event(self.scope, "encoding", 2, "encoding", {}), prior.versions, (
                GraphWrite(episode, {"episode_id": "episode-1", "source_refs": [
                    source_key("bot", "persona", "message-1").token], "event_ref": event.token}),
                GraphWrite(trace, {"trace_id": "trace-1", "episode_ref": episode.token,
                                   "perspective_ref": perspective.token,
                                   "then_feeling_refs": [feeling.token],
                                   "interpretation_refs": [], "detail_weights": [["waiting", 0.8]]}),
            ), prior.epochs,
        ))
        evidence = self.pipeline.read_committed_encoding(
            "message-1", "trace-1", audience="owner", purpose="context")
        self.assertEqual(evidence.then_feeling_refs, (feeling.token,))
        self.assertEqual(evidence.detail_weights, (("waiting", 0.8),))
        self.assertFalse(hasattr(evidence, "base_salience"))
        self.repository.set_access(
            Event(self.scope, "withdraw", 3, "withdraw", {}), "message-1",
            audiences=("owner",), purposes=("context",), status="withdrawn", recorded_at=3,
        )
        with self.assertRaisesRegex(PermissionError, "unavailable"):
            self.pipeline.read_committed_encoding(
                "message-1", "trace-1", audience="owner", purpose="context")

    def test_v2_trace_reports_baseline_reference_without_claiming_numeric_value(self):
        episode = episode_key("bot", "persona", "episode-2")
        trace = subjective_trace_v2_key("bot", "persona", "trace-2")
        baseline = AtomKey(Owner("event", "bot", "persona", "event-2"),
                           "d04.encoding_baseline.v1", "record")
        event = AtomKey(Owner("event", "bot", "persona", "event-2"), "d03.world_event", "current")
        perspective = AtomKey(Owner("scene", "bot", "persona", "scene-2"), "d03.role_binding", "current")
        prior = self.store.graph_snapshot((episode, trace))
        self.store.graph_commit(GraphCandidate(
            Event(self.scope, "encoding-v2", 2, "encoding", {}), prior.versions, (
                GraphWrite(episode, {"episode_id": "episode-2", "source_refs": [
                    source_key("bot", "persona", "message-1").token], "event_ref": event.token}),
                GraphWrite(trace, {"trace_id": "trace-2", "episode_ref": episode.token,
                                   "perspective_ref": perspective.token,
                                   "then_feeling_refs": [], "interpretation_refs": [],
                                   "detail_weights": [["waiting", 0.8]],
                                   "encoding_baseline_ref": baseline.token}),
            ), prior.epochs,
        ))
        with self.assertRaisesRegex(ValueError, "baseline is unavailable"):
            self.pipeline.read_committed_encoding(
                "message-1", "trace-2", audience="owner", purpose="context", trace_version=2)

        baseline_value = {
            "baseline_id": "baseline-2",
            "source_refs": [source_key("bot", "persona", "message-1").token],
            "perspective_ref": perspective.token,
            "then_feeling_versions": [], "interpretation_versions": [],
            "as_known_at": None, "projection_policy_ref": "policy-unresolved",
            "projection_policy_version": "policy-v1", "basis_version": "scheme-1",
            "parameter_version": "parameters-1", "salience_interval": None,
            "tone_interval": None,
            "unknown_reasons": ["salience_interval:unknown", "tone_interval:unknown"],
        }
        prior = self.store.graph_snapshot((baseline,))
        self.store.graph_commit(GraphCandidate(
            Event(self.scope, "baseline-v2", 3, "baseline", {}), prior.versions,
            (GraphWrite(baseline, baseline_value),), prior.epochs,
        ))
        evidence = self.pipeline.read_committed_encoding(
            "message-1", "trace-2", audience="owner", purpose="context", trace_version=2)
        self.assertEqual(evidence.encoding_baseline_ref, baseline.token)
        self.assertIn(baseline, (version.key for version in evidence.proof_versions))
        self.assertFalse(hasattr(evidence, "base_salience"))
        self.repository.set_access(
            Event(self.scope, "withdraw-v2", 4, "withdraw", {}), "message-1",
            audiences=("owner",), purposes=("context",), status="withdrawn", recorded_at=4,
        )
        with self.assertRaisesRegex(PermissionError, "source is unavailable"):
            self.pipeline.read_committed_encoding(
                "message-1", "trace-2", audience="owner", purpose="context", trace_version=2)

    def test_v2_rejects_baseline_for_another_source(self):
        episode = episode_key("bot", "persona", "episode-3")
        trace = subjective_trace_v2_key("bot", "persona", "trace-3")
        baseline = AtomKey(Owner("event", "bot", "persona", "event-3"),
                           "d04.encoding_baseline.v1", "record")
        event = AtomKey(Owner("event", "bot", "persona", "event-3"), "d03.world_event", "current")
        perspective = AtomKey(Owner("scene", "bot", "persona", "scene-3"), "d03.role_binding", "current")
        wrong_source = source_key("bot", "persona", "other-message").token
        prior = self.store.graph_snapshot((episode, trace, baseline))
        self.store.graph_commit(GraphCandidate(
            Event(self.scope, "encoding-other-source", 2, "encoding", {}), prior.versions, (
                GraphWrite(episode, {"episode_id": "episode-3", "source_refs": [
                    source_key("bot", "persona", "message-1").token], "event_ref": event.token}),
                GraphWrite(trace, {"trace_id": "trace-3", "episode_ref": episode.token,
                                   "perspective_ref": perspective.token,
                                   "then_feeling_refs": [], "interpretation_refs": [],
                                   "detail_weights": [], "encoding_baseline_ref": baseline.token}),
                GraphWrite(baseline, {
                    "baseline_id": "baseline-3", "source_refs": [wrong_source],
                    "perspective_ref": perspective.token,
                    "then_feeling_versions": [], "interpretation_versions": [],
                    "as_known_at": None, "projection_policy_ref": "policy-unresolved",
                    "projection_policy_version": "policy-v1", "basis_version": "scheme-1",
                    "parameter_version": "parameters-1", "salience_interval": None,
                    "tone_interval": None,
                    "unknown_reasons": ["salience_interval:unknown", "tone_interval:unknown"],
                }),
            ), prior.epochs,
        ))
        with self.assertRaisesRegex(ValueError, "does not qualify this source"):
            self.pipeline.read_committed_encoding(
                "message-1", "trace-3", audience="owner", purpose="context", trace_version=2)


if __name__ == "__main__":
    unittest.main()
