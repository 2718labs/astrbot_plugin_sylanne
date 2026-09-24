"""Directional affect remains a source-bound, candidate-only calculation."""

import unittest

from sylanne3.domains.d04.memory_modulation import (
    AffectIntervalPremise,
    DirectionalMemoryPolicy,
    SourceDetail,
    project_detail_accessibility,
)


SOURCE = "我看见你画的桥了，配色很喜欢。今晚我尽量细看，但不保证能看完。"
SOURCE_REF = "memory.source:bridge-painting"
SCHEME = "d04-affect-scheme:v1"
POLICY = "bridge-meaning-direction:v1"


def _detail(text: str, meaning_axis: str) -> SourceDetail:
    start = SOURCE.index(text)
    return SourceDetail(SOURCE_REF, SOURCE, start, start + len(text), meaning_axis, (0.4, 0.5))


class DirectionalMemoryCandidateTests(unittest.TestCase):
    def test_equal_magnitude_opposite_sign_changes_only_registered_source_detail(self) -> None:
        praise = _detail("配色很喜欢", "appreciation")
        limit = _detail("不保证能看完", "completion_limit")
        policy = DirectionalMemoryPolicy(SCHEME, POLICY, (("valence", "appreciation", 0.2),))
        disabled = DirectionalMemoryPolicy(SCHEME, "direction-disabled:v1", ())

        for stage in ("encoding", "recollection"):
            with self.subTest(stage=stage):
                positive = AffectIntervalPremise("d04.readout:positive", stage, SCHEME, POLICY, "valence", (0.5, 0.6))
                negative = AffectIntervalPremise("d04.readout:negative", stage, SCHEME, POLICY, "valence", (-0.6, -0.5))
                plus = project_detail_accessibility(praise, positive, policy)
                minus = project_detail_accessibility(praise, negative, policy)
                self.assertGreater(plus.accessibility_interval[0], minus.accessibility_interval[1])
                self.assertEqual(plus.policy_version, POLICY)
                self.assertEqual(plus.scheme_version, SCHEME)
                self.assertEqual(plus.stage, stage)
                self.assertEqual(plus.source_ref, SOURCE_REF)
                self.assertEqual((plus.start, plus.end), (praise.start, praise.end))

                # The source says nothing about a promise to finish tonight.
                self.assertEqual(praise.text, "配色很喜欢")
                self.assertEqual(limit.text, "不保证能看完")
                self.assertEqual(praise.source_text, SOURCE)
                self.assertEqual(project_detail_accessibility(limit, positive, policy).accessibility_interval,
                                 project_detail_accessibility(limit, negative, policy).accessibility_interval)
                disabled_positive = AffectIntervalPremise(positive.readout_ref, stage, SCHEME, disabled.policy_version,
                                                          "valence", positive.value_interval)
                disabled_negative = AffectIntervalPremise(negative.readout_ref, stage, SCHEME, disabled.policy_version,
                                                          "valence", negative.value_interval)
                self.assertEqual(project_detail_accessibility(praise, disabled_positive, disabled).accessibility_interval,
                                 project_detail_accessibility(praise, disabled_negative, disabled).accessibility_interval)

    def test_uncertainty_and_version_mismatch(self) -> None:
        detail = _detail("配色很喜欢", "appreciation")
        policy = DirectionalMemoryPolicy(SCHEME, POLICY, (("valence", "appreciation", -0.5),))
        uncertain = AffectIntervalPremise("d04.readout:uncertain", "recollection", SCHEME, POLICY, "valence", (-0.3, 0.4))
        interval = project_detail_accessibility(detail, uncertain, policy).accessibility_interval
        self.assertLessEqual(interval[0], 0.2)
        self.assertGreaterEqual(interval[1], 0.65)
        wrong_scheme = AffectIntervalPremise("d04.readout:other", "recollection", "other-scheme", POLICY, "valence", (0.5, 0.6))
        with self.assertRaisesRegex(ValueError, "scheme or policy version"):
            project_detail_accessibility(detail, wrong_scheme, policy)
        wrong_policy = AffectIntervalPremise("d04.readout:other", "recollection", SCHEME, "other-policy", "valence", (0.5, 0.6))
        with self.assertRaisesRegex(ValueError, "scheme or policy version"):
            project_detail_accessibility(detail, wrong_policy, policy)


if __name__ == "__main__":
    unittest.main()
