import unittest

from sylanne3.domains.d02 import BodyDomain, BodyProfile, BodyState, WorkComponent
from sylanne3.domains.d02.current_ledger import read_current_resource_ledger
from sylanne3.graph_store import GraphPage
from sylanne3.graph_types import GraphAtom, GraphSnapshot, NamespaceEpoch
from sylanne3.runtime_contracts import NamespaceId


class _Coordinator:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def query(self, authority, lease, **kwargs):
        self.calls.append(kwargs)
        return self.pages.pop(0)


class CurrentResourceLedgerTests(unittest.TestCase):
    def setUp(self):
        self.namespace = NamespaceId("bot", "persona")
        self.profile = BodyProfile("body:base", self.namespace, 1,
                                   ("energy", "fatigue:thinking", "load"), ("thinking",))
        self.state = BodyState("body:base", 1, 0.8, {"thinking": 0.1}, 0.2, 0.0)
        self.domain = BodyDomain()
        self.quote = self.domain.quote_work(
            self.profile, self.state, "activity:one", "thinking", 5.0,
            (WorkComponent("work", "duration", duration_rate=0.1),), valid_until=20.0,
        )
        self.reservation = self.domain.reserve_work(
            self.state, (), self.quote, "reservation:one", "effect:one",
        )
        self.state_atom = GraphAtom(self.domain.state_write(self.namespace, self.state).key,
                                    1, self.domain.state_write(self.namespace, self.state).value)
        reservation_write = self.domain.reservation_write(
            self.namespace, "activity:one", self.reservation,
        )
        self.reservation_atom = GraphAtom(reservation_write.key, 1, reservation_write.value)

    def _page(self, atoms, epoch=4):
        return GraphPage(GraphSnapshot(tuple(atoms), (NamespaceEpoch("bot", "persona", epoch),)), None)

    def test_committed_reservation_blocks_new_work_and_preserves_versions(self):
        coordinator = _Coordinator([
            self._page((self.state_atom,)), self._page((self.reservation_atom,)),
        ])
        ledger = read_current_resource_ledger(
            self.namespace, coordinator, authority=object(), lease=object(),
            profile_id="body:base",
        )
        self.assertEqual(ledger.graph_epoch, 4)
        self.assertEqual({ref.key for ref in ledger.read_versions},
                         {self.state_atom.key, self.reservation_atom.key})
        self.assertEqual(coordinator.calls[1]["expected_epoch"], NamespaceEpoch("bot", "persona", 4))
        admission = ledger.admit_new_work("effect:two", self.quote.max_energy_cost)
        self.assertEqual((admission.status, admission.reason),
                         ("deferred", "insufficient_unencumbered_energy"))
        self.assertEqual(admission.query_epoch.revision, 4)
        self.assertEqual(admission.read_versions, ledger.read_versions)

    def test_existing_effect_cannot_be_reused_and_reserved_segment_checks_own_remaining_cost(self):
        coordinator = _Coordinator([
            self._page((self.state_atom,)), self._page((self.reservation_atom,)),
        ])
        ledger = read_current_resource_ledger(
            self.namespace, coordinator, authority=object(), lease=object(),
            profile_id="body:base",
        )
        self.assertEqual(ledger.admit_new_work("effect:one", 0.01).reason,
                         "effect_already_reserved")
        self.assertEqual(ledger.admit_reserved_work(
            "reservation:one", "effect:wrong", 0.1,
        ).reason, "reservation_effect_mismatch")
        self.assertEqual(ledger.admit_reserved_work(
            "reservation:one", "effect:one", 0.6,
        ).reason, "reservation_limit")
        approved = ledger.admit_reserved_work("reservation:one", "effect:one", 0.2)
        self.assertEqual(approved.status, "clear")
        self.assertEqual(approved.reservation_ref, self.reservation_atom.key)
        self.assertEqual(approved.query_epoch.namespace, self.namespace)

    def test_inactive_effect_remains_in_idempotency_inventory_without_consuming_energy(self):
        from dataclasses import replace
        released = replace(self.reservation, remaining_cost=0.0, status="released")
        released_atom = GraphAtom(self.reservation_atom.key, 2,
                                  self.domain.reservation_write(
                                      self.namespace, "activity:one", released,
                                  ).value)
        ledger = read_current_resource_ledger(
            self.namespace, _Coordinator([
                self._page((self.state_atom,)), self._page((released_atom,)),
            ]), authority=object(), lease=object(), profile_id="body:base",
        )
        self.assertEqual(ledger.admit_new_work("effect:one", 0.1).reason,
                         "effect_already_reserved")
        self.assertEqual(ledger.admit_new_work("effect:two", 0.1).status, "clear")
        self.assertEqual(ledger.read_versions[-1].revision, 2)

    def test_cross_epoch_or_foreign_reservation_cannot_qualify_resource_read(self):
        changed = _Coordinator([
            self._page((self.state_atom,)), self._page((self.reservation_atom,), epoch=5),
        ])
        with self.assertRaisesRegex(ValueError, "epoch"):
            read_current_resource_ledger(
                self.namespace, changed, authority=object(), lease=object(),
                profile_id="body:base",
            )
        foreign = GraphAtom(
            self.domain.reservation_write(NamespaceId("bot", "other"), "activity:one",
                                          self.reservation).key,
            1, self.domain.reservation_write(NamespaceId("bot", "other"), "activity:one",
                                             self.reservation).value,
        )
        mixed = _Coordinator([self._page((self.state_atom,)), self._page((foreign,))])
        with self.assertRaisesRegex(ValueError, "namespace"):
            read_current_resource_ledger(
                self.namespace, mixed, authority=object(), lease=object(),
                profile_id="body:base",
            )


if __name__ == "__main__":
    unittest.main()
