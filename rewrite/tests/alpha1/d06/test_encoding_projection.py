import unittest
from dataclasses import replace
from fractions import Fraction

from sylanne3.domains.d04.encoding_baseline import EncodingBaseline
from sylanne3.domains.d06.encoding_projection import (
    EncodingAffectIntervals,
    EncodingProjectionPolicyV1,
    project_committed_baseline_candidate,
    project_encoding_candidate,
)
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.memory_types import SourceRecord, source_key
from sylanne3.model_broker.first_ingress_encoding import parse_first_ingress_encoding_result


class EncodingProjectionTests(unittest.TestCase):
    def setUp(self):
        self.source = SourceRecord(
            "message-1", "I waited for you, but I do not know if you saw it.",
            "user", "reported", "reported", 1.0, 2.0, "family-1",
            ("owner",), ("context",),
        )
        self.model = parse_first_ingress_encoding_result({
            "text": ('{"event_summary":"A wait was reported",'
                     '"quoted_details":[{"quote":"I waited","salience":0.5}],'
                     '"possible_meanings":["perhaps neglected"],'
                     '"possible_feelings":["hurt"]}'),
        }, self.source)
        self.policy = EncodingProjectionPolicyV1(
            "policy:encoding-affect", "v1", 0.4, 0.2,
        )

    def test_same_source_and_model_result_change_only_subjective_intervals(self):
        original_text = self.source.text
        quiet = project_encoding_candidate(
            self.source, self.model,
            EncodingAffectIntervals((0.2, 0.3), (-0.2, 0.1)), self.policy,
        )
        intense = project_encoding_candidate(
            self.source, self.model,
            EncodingAffectIntervals((0.7, 0.8), (0.6, 0.7)), self.policy,
        )
        self.assertEqual(self.source.text, original_text)
        self.assertEqual(quiet.model_candidate, intense.model_candidate)
        self.assertEqual(quiet.details[0].quote, "I waited")
        self.assertEqual(quiet.details[0].model_salience, 0.5)
        self.assertAlmostEqual(quiet.details[0].subjective_weight_interval[0], 0.38)
        self.assertAlmostEqual(quiet.details[0].affective_strength_interval[0], 0.04)
        self.assertEqual(quiet.assertion_status, "reported")
        self.assertEqual(intense.assertion_status, "reported")
        self.assertLess(quiet.details[0].subjective_weight_interval[1],
                        intense.details[0].subjective_weight_interval[0])
        self.assertLess(quiet.details[0].affective_strength_interval[1],
                        intense.details[0].affective_strength_interval[0])
        self.assertEqual(quiet.status, "candidate_hold")
        self.assertEqual(quiet.readout_provenance, "supplied_counterfactual")

    def test_unqualified_d04_baseline_cannot_become_a_certified_projection(self):
        source_ref = source_key("bot", "persona", self.source.source_id).token
        baseline_ref = AtomKey(Owner("event", "bot", "persona", "world-1"),
                               "d04.encoding_baseline.v1", "record").token
        perspective = AtomKey(Owner("scene", "bot", "persona", "scene-1"),
                              "d03.role_binding", "current").token
        baseline = EncodingBaseline(
            "baseline-1", (source_ref,), perspective, (), (), None,
            self.policy.policy_ref, self.policy.policy_version,
            "scheme-1", "parameters-1", None, None,
            ("salience_interval:unknown", "tone_interval:unknown"),
        )
        with self.assertRaisesRegex(ValueError, "HOLD"):
            project_committed_baseline_candidate(
                self.source, self.model, baseline, baseline_ref, 1, self.policy,
            )
        with self.assertRaisesRegex(ValueError, "verified projection issuer"):
            replace(baseline, salience_interval=(0.2, 0.3),
                    tone_interval=(-0.2, 0.1), unknown_reasons=())

    def test_quote_and_policy_inputs_remain_bounded(self):
        with self.assertRaisesRegex(ValueError, "exact source span"):
            project_encoding_candidate(
                self.source,
                replace(self.model, quoted_details=(("invented quote", 0.9),)),
                EncodingAffectIntervals((0.3, 0.5), (-0.1, 0.1)), self.policy,
            )
        with self.assertRaisesRegex(ValueError, "ordered"):
            EncodingAffectIntervals((0.7, 0.2), (0.0, 0.2))
        with self.assertRaisesRegex(ValueError, "finite"):
            EncodingProjectionPolicyV1("policy:p", "v1", float("nan"), 0.2)

    def test_outward_rounding_encloses_exact_float_input_expression(self):
        model = replace(self.model, quoted_details=(("I waited", 0.1),))
        affect = EncodingAffectIntervals((0.5, 0.5), (1.0, 1.0))
        for gain, naive_is_above in ((0.2, True), (0.4, False)):
            with self.subTest(gain=gain):
                policy = EncodingProjectionPolicyV1("policy:rounding", "v1", 0.0, gain)
                detail = project_encoding_candidate(
                    self.source, model, affect, policy,
                ).details[0]
                exact_weight = Fraction.from_float(0.1) + Fraction.from_float(gain)
                naive = Fraction.from_float(0.1 + gain)
                self.assertEqual(naive > exact_weight, naive_is_above)
                low, high = detail.subjective_weight_interval
                self.assertLessEqual(Fraction.from_float(low), exact_weight)
                self.assertGreaterEqual(Fraction.from_float(high), exact_weight)
                self.assertLess(low, high)
                exact_strength = Fraction.from_float(0.1) * Fraction.from_float(gain)
                strength_low, strength_high = detail.affective_strength_interval
                self.assertLessEqual(Fraction.from_float(strength_low), exact_strength)
                self.assertGreaterEqual(Fraction.from_float(strength_high), exact_strength)


if __name__ == "__main__":
    unittest.main()
