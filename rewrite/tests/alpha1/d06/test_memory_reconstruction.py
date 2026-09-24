import unittest
from dataclasses import replace

from sylanne3.domains.d04 import AffectAxis, AffectCoupling, AffectScheme, MoodField
from sylanne3.domains.d06 import CandidateItem, CandidateSet, RecollectionProposal, SelectionTicket
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner
from sylanne3.memory_recollection_view import prepare_affective_recollection_view
from sylanne3.memory_reconstruction import DetailCue, reconstruct_recollection_candidate
from sylanne3.memory_retrieval import MemoryHit
from sylanne3.memory_types import SourceRecord, source_key
from sylanne3.runtime_contracts import SourceQualification


class ReconstructionTests(unittest.TestCase):
    def setUp(self):
        self.source = SourceRecord(
            "message-1", "我等了很久，但不知道他是否看见消息。", "user", "reported",
            "reported", 4.0, 5.0, "family-1", ("owner",), ("context",),
        )
        self.key = source_key("bot", "persona", self.source.source_id)
        self.hit = MemoryHit(
            self.key, self.source, (GraphVersion(self.key, 2),),
            ("family-1",), (self.source,),
        )
        self.ticket = SelectionTicket("ticket", "activity", "set", ("item",), 1)
        self.candidates = CandidateSet(
            "set", (CandidateItem("item", self.source.source_id, "family-1", "exact",
                                  ("context",), 0.8, "reported_claim"),),
            "complete", access_epoch=1, delete_epoch=1,
        )
        self.proposal = RecollectionProposal(
            "recollection", "activity", "ticket", ("message-1",),
            ("ticket", "set"), ("d07-interpretation-1",), ("d04-experience-1",),
            ("d01-self-1",), ("reported_claim",),
        )
        self.mood_key = AtomKey(Owner("persona", "bot", "persona"),
                                "d04.mood_field.v1", "current")
        self.scheme = AffectScheme(
            "d04.affect.scheme.v1", "scheme-1", "operator-1", "parameters-1",
            "coupling-1", (AffectAxis("warmth", "normalized", "warmth"),), (),
        )
        self.coupling = AffectCoupling("recall", "coupling-1", "warmth", "warmth",
                                       0.0, 0.5, 0.5)
        self.qualification = SourceQualification(
            (self.key.token, "mood-source"), "reported", 4.0, 5.0,
            "external_report", "eligible", 0.6, "not_applicable",
        )

    def _view(self, warmth, *, qualification=None):
        mood = MoodField("mood-1", "scheme-1", (("warmth", warmth),),
                         ("mood-source",), "parameters-1", "coupling-1", 5.0)
        snapshot = GraphSnapshot((GraphAtom(self.mood_key, 3, {
            **mood.__dict__, "coordinates": [list(item) for item in mood.coordinates],
            "source_refs": list(mood.source_refs),
        }),), (NamespaceEpoch("bot", "persona", 7),))
        return prepare_affective_recollection_view(
            ticket=self.ticket, candidates=self.candidates, hit=self.hit,
            mood_snapshot=snapshot, mood_key=self.mood_key, scheme=self.scheme,
            coupling=self.coupling, source_qualification=qualification or self.qualification,
            base_salience=(0.4, 0.6), base_tone=(-0.1, 0.1), purpose="context",
        )

    def test_same_source_changes_retrieval_and_subjective_duration_with_mood(self):
        cues = (DetailCue("waiting", (0, 6), 0.65),)
        warm = reconstruct_recollection_candidate(
            proposal=self.proposal, view=self._view(0.8), detail_cues=cues,
            then_meaning_refs=("then-meaning-1",), temporal_focus=True,
        )
        guarded = reconstruct_recollection_candidate(
            proposal=self.proposal, view=self._view(-0.8), detail_cues=cues,
            then_meaning_refs=("then-meaning-1",), temporal_focus=True,
        )
        self.assertEqual(warm.source_fields, guarded.source_fields)
        self.assertEqual(warm.source_fields[0].assertion_status, "reported")
        self.assertEqual(warm.subjective_details[0].state, "retrieved")
        self.assertEqual(guarded.subjective_details[0].state, "blurred")
        self.assertEqual(warm.subjective_details[0].recalled_text, self.source.text[:6])
        self.assertIsNone(guarded.subjective_details[0].recalled_text)
        self.assertIsNone(warm.subjective_duration_delta)
        self.assertIsInstance(warm.subjective_duration_interval_v1, tuple)
        self.assertIsInstance(guarded.subjective_duration_interval_v1, tuple)
        self.assertNotEqual(warm.subjective_weight, guarded.subjective_weight)
        self.assertEqual(warm.then_meaning_refs, guarded.then_meaning_refs)
        self.assertEqual(warm.status, "candidate_hold")

    def test_threshold_crossing_is_uncertain_without_recalled_text(self):
        view = self._view(0.8)
        result = reconstruct_recollection_candidate(
            proposal=self.proposal, view=view,
            detail_cues=(
                DetailCue("retrieved-threshold", (0, 6), 0.55),
                DetailCue("unavailable-threshold", (0, 6), 0.10),
            ),
        )
        retrieved_boundary, unavailable_boundary = result.subjective_details
        self.assertEqual(retrieved_boundary.state, "uncertain")
        self.assertAlmostEqual(retrieved_boundary.subjective_accessibility[0], 0.60)
        self.assertAlmostEqual(retrieved_boundary.subjective_accessibility[1], 0.70)
        self.assertIsNone(retrieved_boundary.recalled_text)
        self.assertEqual(unavailable_boundary.state, "uncertain")
        self.assertAlmostEqual(unavailable_boundary.subjective_accessibility[0], 0.15)
        self.assertAlmostEqual(unavailable_boundary.subjective_accessibility[1], 0.25)
        self.assertIsNone(unavailable_boundary.recalled_text)

    def test_narrow_accessibility_interval_has_stable_state_and_duration_range(self):
        view = replace(
            self._view(0.8), subjective_salience=(0.70, 0.72),
            base_salience=(0.50, 0.52), subjective_tone=(0.20, 0.22),
        )
        result = reconstruct_recollection_candidate(
            proposal=self.proposal, view=view,
            detail_cues=(DetailCue("stable-retrieval", (0, 6), 0.70),),
            temporal_focus=True,
        )
        detail = result.subjective_details[0]
        self.assertEqual(detail.state, "retrieved")
        self.assertEqual(detail.recalled_text, self.source.text[:6])
        self.assertAlmostEqual(result.subjective_duration_interval_v1[0], -0.1584)
        self.assertAlmostEqual(result.subjective_duration_interval_v1[1], -0.14)
        self.assertIsNone(result.subjective_duration_delta)

    def test_inference_stays_inferred_and_never_becomes_a_source_fact(self):
        cues = (
            DetailCue("unavailable", (0, 3), 0.0),
            DetailCue("attribution", interpretation_ref="d07-interpretation-1"),
        )
        first = reconstruct_recollection_candidate(
            proposal=self.proposal, view=self._view(0.8), detail_cues=cues,
        )
        repeat = reconstruct_recollection_candidate(
            proposal=self.proposal, view=self._view(0.8), detail_cues=cues,
        )
        self.assertEqual(first, repeat)
        self.assertEqual([item.state for item in first.subjective_details],
                         ["unavailable", "inferred"])
        self.assertEqual(len(first.source_fields), 1)
        self.assertIsNone(first.subjective_details[1].recalled_text)
        self.assertIsNone(first.subjective_duration_delta)
        with self.assertRaisesRegex(ValueError, "D07 interpretation"):
            reconstruct_recollection_candidate(
                proposal=self.proposal, view=self._view(0.8),
                detail_cues=(DetailCue("invented", interpretation_ref="fake-quote"),),
            )

    def test_source_limits_and_selection_remain_binding(self):
        with self.assertRaisesRegex(ValueError, "lacks qualification"):
            self._view(0.8, qualification=SourceQualification(
                (self.key.token,), "reported", 4.0, 5.0,
                "external_report", "eligible", 0.6, "not_applicable",
            ))
        view = self._view(0.8)
        with self.assertRaisesRegex(ValueError, "exceeds the qualified source"):
            reconstruct_recollection_candidate(
                proposal=self.proposal, view=view,
                detail_cues=(DetailCue("invented", (0, len(view.source_text) + 1), 1.0),),
            )
        wrong_proposal = RecollectionProposal(
            "recollection", "activity", "ticket", ("another-source",),
            ("ticket", "set"), (), (), (), ("reported_claim",),
        )
        with self.assertRaisesRegex(ValueError, "does not select this source"):
            reconstruct_recollection_candidate(
                proposal=wrong_proposal, view=view, detail_cues=(),
            )


if __name__ == "__main__":
    unittest.main()
