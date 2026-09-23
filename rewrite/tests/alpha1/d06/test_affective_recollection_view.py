import unittest

from sylanne3.domains.d04 import AffectAxis, AffectCoupling, AffectScheme, MoodField
from sylanne3.domains.d06 import CandidateItem, CandidateSet, SelectionTicket
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner
from sylanne3.memory_recollection_view import prepare_affective_recollection_view
from sylanne3.memory_retrieval import MemoryHit
from sylanne3.memory_types import SourceRecord, source_key
from sylanne3.runtime_contracts import SourceQualification


class AffectiveRecollectionViewTests(unittest.TestCase):
    def setUp(self):
        self.source = SourceRecord(
            "message-1", "我周五说过会来。", "user", "reported", "reported",
            4.0, 5.0, "family-1", ("owner",), ("context",),
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
        self.mood_key = AtomKey(Owner("persona", "bot", "persona"),
                                "d04.mood_field.v1", "current")
        self.scheme = AffectScheme(
            "d04.affect.scheme.v1", "scheme-1", "operator-1", "parameters-1",
            "coupling-1", (AffectAxis("warmth", "normalized", "warmth"),), (),
        )
        self.coupling = AffectCoupling("recall", "coupling-1", "warmth", "warmth",
                                       0.0, 0.25, 0.5)
        self.qualification = SourceQualification(
            (self.key.token, "mood-source"), "reported", 4.0, 5.0,
            "external_report", "eligible", 0.6, "not_applicable",
        )

    def _snapshot(self, warmth):
        mood = MoodField("mood-1", "scheme-1", (("warmth", warmth),),
                         ("mood-source",), "parameters-1", "coupling-1", 5.0)
        payload = {**mood.__dict__, "coordinates": [list(item) for item in mood.coordinates],
                   "source_refs": list(mood.source_refs)}
        return GraphSnapshot((GraphAtom(self.mood_key, 3, payload),),
                             (NamespaceEpoch("bot", "persona", 7),))

    def _view(self, warmth, **changes):
        kwargs = dict(
            ticket=self.ticket, candidates=self.candidates, hit=self.hit,
            mood_snapshot=self._snapshot(warmth), mood_key=self.mood_key,
            scheme=self.scheme, coupling=self.coupling,
            source_qualification=self.qualification,
            base_salience=(0.3, 0.4), base_tone=(-0.1, 0.0), purpose="context",
        )
        kwargs.update(changes)
        return prepare_affective_recollection_view(**kwargs)

    def test_same_source_different_mood_changes_subjective_view_only(self):
        warm = self._view(0.6)
        guarded = self._view(-0.6)
        self.assertEqual(warm.source_text, guarded.source_text)
        self.assertEqual(warm.source_kind, guarded.source_kind)
        self.assertEqual(warm.assertion_status, guarded.assertion_status)
        self.assertNotEqual(warm.subjective_tone, guarded.subjective_tone)
        self.assertNotEqual(warm.subjective_salience, guarded.subjective_salience)
        self.assertEqual(warm.status, "candidate")
        self.assertEqual({v.key for v in warm.read_versions}, {self.key, self.mood_key})

    def test_unqualified_or_other_persona_mood_cannot_color_source(self):
        qualification = SourceQualification(
            (self.key.token,), "reported", 4.0, 5.0,
            "external_report", "eligible", 0.6, "not_applicable",
        )
        with self.assertRaisesRegex(ValueError, "lacks qualification"):
            self._view(0.6, source_qualification=qualification)
        other_key = AtomKey(Owner("persona", "bot", "other"),
                            "d04.mood_field.v1", "current")
        with self.assertRaisesRegex(ValueError, "cross namespaces"):
            self._view(0.6, mood_key=other_key)

    def test_unselected_source_and_incompatible_scheme_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "selected source"):
            self._view(0.6, candidates=CandidateSet(
                "set", (CandidateItem("item", "different", "family-1", "exact",
                                      ("context",), 0.8, "reported_claim"),), "complete",
            ))
        incompatible = AffectScheme(
            "d04.affect.scheme.v1", "scheme-2", "operator-1", "parameters-1",
            "coupling-1", (AffectAxis("warmth", "normalized", "warmth"),), (),
        )
        with self.assertRaisesRegex(ValueError, "active affect scheme"):
            self._view(0.6, scheme=incompatible)


if __name__ == "__main__":
    unittest.main()
