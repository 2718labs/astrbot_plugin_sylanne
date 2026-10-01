import unittest

from sylanne3.domains.d02 import (
    BodyDomain, BodyProfile, BodyState, BodyPassiveRates, WorkComponent,
)
from sylanne3.runtime_contracts import NamespaceId


class BodyDynamicsTests(unittest.TestCase):
    def setUp(self):
        self.domain = BodyDomain()
        self.profile = BodyProfile(
            "body:base", NamespaceId("bot", "persona"), 1,
            ("energy", "fatigue:thinking", "load"), ("thinking",),
        )
        self.state = BodyState("body:base", 1, 0.2, {"thinking": 0.7}, 0.6, 10.0)

    def test_passive_interval_recovers_energy_without_erasing_fatigue_or_inventing_activity(self):
        rates = BodyPassiveRates(energy_recovery=0.2,
                                 fatigue_recovery={"thinking": 0.1}, load_recovery=0.05)
        whole = self.domain.advance_passive_body(self.state, rates, from_cursor=10.0,
                                                 to_cursor=14.0)
        first = self.domain.advance_passive_body(self.state, rates, from_cursor=10.0,
                                                 to_cursor=12.0)
        split = self.domain.advance_passive_body(first, rates, from_cursor=12.0,
                                                 to_cursor=14.0)
        self.assertGreater(whole.energy, self.state.energy)
        self.assertLess(whole.fatigue["thinking"], self.state.fatigue["thinking"])
        self.assertLess(whole.load, self.state.load)
        self.assertGreater(whole.fatigue["thinking"], 0.0)
        self.assertAlmostEqual(whole.energy, split.energy)
        self.assertAlmostEqual(whole.fatigue["thinking"], split.fatigue["thinking"])
        self.assertAlmostEqual(whole.load, split.load)
        self.assertEqual((whole.cursor, whole.version), (14.0, 2))
        with self.assertRaisesRegex(ValueError, "cursor"):
            self.domain.advance_passive_body(self.state, rates, from_cursor=9.0,
                                             to_cursor=14.0)

    def test_actual_work_effect_follows_one_settlement_without_double_energy_debit(self):
        quote = self.domain.quote_work(
            self.profile, self.state, "activity:one", "thinking", 1.0,
            (WorkComponent("thinking", "work", fixed_cost=0.1),), valid_until=20.0,
        )
        reservation = self.domain.reserve_work(
            self.state, (), quote, "reservation:one", "effect:one",
        )
        settled = self.domain.settle_component(
            self.state, reservation, "thinking", actual_cost=0.1,
            component_receipt="segment:one",
        )
        affected = self.domain.apply_settled_work_effect(
            settled, work_kind="thinking", fatigue_increase=0.15, load_increase=0.1,
        )
        self.assertAlmostEqual(affected.state.energy, 0.1)
        self.assertAlmostEqual(affected.state.fatigue["thinking"], 0.85)
        self.assertAlmostEqual(affected.state.load, 0.7)
        self.assertEqual(affected.state.version, settled.state.version)
        duplicate = self.domain.settle_component(
            affected.state, affected.reservation, "thinking", actual_cost=0.1,
            component_receipt="segment:one",
        )
        unchanged = self.domain.apply_settled_work_effect(
            duplicate, work_kind="thinking", fatigue_increase=0.15, load_increase=0.1,
        )
        self.assertEqual(unchanged.state, affected.state)


if __name__ == "__main__":
    unittest.main()
