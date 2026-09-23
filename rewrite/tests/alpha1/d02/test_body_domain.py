import unittest

from sylanne3.domains.d02 import (
    BodyDomain,
    BodyProfile,
    BodyState,
    WorkComponent,
)
from sylanne3.graph_types import AtomKey, Owner, TypeRegistry
from sylanne3.runtime_contracts import NamespaceId


def profile():
    return BodyProfile(
        profile_id="body:base",
        namespace=NamespaceId("bot", "persona"),
        version=1,
        applicable_axes=("energy", "fatigue:thinking", "load"),
        work_kinds=("thinking",),
    )


def state(energy=0.8):
    return BodyState(profile_id="body:base", version=1, energy=energy, fatigue={"thinking": 0.1}, load=0.2, cursor=0.0)


class BodyDomainTests(unittest.TestCase):
    def test_type_specs_validate_every_persistent_shape_and_owner(self):
        domain = BodyDomain()
        specs = domain.type_specs()
        self.assertEqual(tuple(spec.name for spec in specs), domain.register_types())
        self.assertTrue(all(spec.writer_domain == "d02" for spec in specs))
        registry = TypeRegistry()
        for spec in specs:
            registry.register(spec)

        profile_write = domain.profile_write(profile())
        state_write = domain.state_write(NamespaceId("bot", "persona"), state())
        quote = domain.quote_work(
            profile(), state(), "activity:one", "thinking", 1.0,
            (WorkComponent("work", "duration", duration_rate=0.1),), valid_until=20.0,
        )
        reservation = domain.reserve_work(state(), (), quote, "reservation:one", "effect:one")
        settled = domain.settle_component(
            state(), reservation, "work", actual_cost=0.05, component_receipt="segment:1"
        )
        reservation_write = domain.reservation_write(
            NamespaceId("bot", "persona"), "activity:one", reservation
        )
        settlement_write = domain.settlement_write(
            NamespaceId("bot", "persona"), "activity:one", "settlement:one", settled
        )
        for write in (profile_write, state_write, reservation_write, settlement_write):
            with self.subTest(type_name=write.key.type_name):
                registry.validate(write.key, write.value)
                with self.assertRaises(ValueError):
                    registry.validate(write.key, {**write.value, "untracked_balance": 1})
        with self.assertRaises(ValueError):
            registry.validate(
                AtomKey(Owner("activity", "bot", "persona", "activity:one"),
                        "d02.body_state.v1", "body:base"),
                state_write.value,
            )

    def test_quote_has_no_side_effect_and_rejects_duplicate_cost_coverage(self):
        domain = BodyDomain()
        quote = domain.quote_work(
            profile(), state(), "activity:one", "thinking", 10.0,
            (WorkComponent("start", "start", fixed_cost=0.1), WorkComponent("work", "duration", duration_rate=0.02)),
            valid_until=20.0,
        )
        self.assertEqual(state().energy, 0.8)
        self.assertAlmostEqual(quote.max_energy_cost, 0.3)
        with self.assertRaises(ValueError):
            domain.quote_work(profile(), state(), "activity:one", "thinking", 1.0,
                              (WorkComponent("a", "same", fixed_cost=0.1), WorkComponent("b", "same", fixed_cost=0.1)),
                              valid_until=20.0)

    def test_reservations_prevent_concurrent_overcommit_without_spending_energy(self):
        domain = BodyDomain()
        quote = domain.quote_work(profile(), state(), "activity:one", "thinking", 10.0,
                                  (WorkComponent("work", "duration", duration_rate=0.05),), valid_until=20.0)
        reservation = domain.reserve_work(state(), (), quote, "reservation:one", "effect:one")
        self.assertAlmostEqual(state().energy, 0.8)
        self.assertAlmostEqual(domain.balance(state(), (reservation,)).available, 0.3)
        with self.assertRaises(ValueError):
            domain.reserve_work(state(), (reservation,), quote, "reservation:two", "effect:two")

    def test_component_settlement_is_idempotent_and_only_actual_labor_reduces_energy(self):
        domain = BodyDomain()
        quote = domain.quote_work(profile(), state(), "activity:one", "thinking", 5.0,
                                  (WorkComponent("work", "duration", duration_rate=0.1),), valid_until=20.0)
        reservation = domain.reserve_work(state(), (), quote, "reservation:one", "effect:one")
        settled = domain.settle_component(state(), reservation, "work", actual_cost=0.2, component_receipt="segment:1")
        self.assertAlmostEqual(settled.state.energy, 0.6)
        duplicate = domain.settle_component(settled.state, settled.reservation, "work", actual_cost=0.2, component_receipt="segment:1")
        self.assertTrue(duplicate.duplicate)
        self.assertAlmostEqual(duplicate.state.energy, 0.6)

    def test_unknown_cancellation_keeps_reservation_and_analytic_advance_is_split_invariant(self):
        domain = BodyDomain()
        quote = domain.quote_work(profile(), state(), "activity:one", "thinking", 5.0,
                                  (WorkComponent("work", "duration", duration_rate=0.1),), valid_until=20.0)
        reservation = domain.reserve_work(state(), (), quote, "reservation:one", "effect:one")
        pending = domain.release_or_cancel(reservation, execution_known=False)
        self.assertEqual(pending.status, "pending_confirmation")
        self.assertGreater(pending.reservation.remaining_cost, 0)
        one = domain.advance_scalar(0.2, 0.1, 0.4, 3.0)
        two = domain.advance_scalar(domain.advance_scalar(0.2, 0.1, 0.4, 1.0), 0.1, 0.4, 2.0)
        self.assertAlmostEqual(one, two)


if __name__ == "__main__":
    unittest.main()
