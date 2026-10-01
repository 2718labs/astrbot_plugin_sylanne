"""A real graph restart retains unknown encumbrance and component identity."""

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d02 import BodyDomain, BodyProfile, BodyState, WorkComponent
from sylanne3.domains.d02.current_ledger import read_current_resource_ledger
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import GraphCandidate, GraphVersion, TypeRegistry
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "persona")


class _ReadPort:
    def __init__(self, store):
        self.store = store

    def query(self, authority, lease, **kwargs):
        return self.store.graph_query(*NS.as_tuple, **kwargs)


def _ledger(store):
    return read_current_resource_ledger(
        NS, _ReadPort(store), authority=object(), lease=object(), profile_id="body",
    )


def _commit(store, event_id, writes):
    keys = tuple(write.key for write in writes)
    snap = store.graph_snapshot(keys)
    receipt = store.graph_commit(GraphCandidate(
        Event(Scope(*NS.as_tuple, "session"), event_id, 1.0, event_id, {}),
        tuple(GraphVersion(key, snap.get(key).revision if snap.get(key) else 0)
              for key in keys),
        tuple(writes), snap.epochs,
    ))
    assert receipt.status == "committed"


def test_restart_keeps_pending_cost_and_settled_component_once(tmp_path):
    domain = BodyDomain()
    profile = BodyProfile("body", NS, 1, ("energy", "fatigue:thinking", "load"),
                          ("thinking",))
    state = BodyState("body", 1, 0.8, {"thinking": 0.1}, 0.2, 0.0)
    quote = domain.quote_work(profile, state, "activity", "thinking", 5.0,
                              (WorkComponent("work", "duration", duration_rate=0.1),),
                              valid_until=20.0)
    reserved = domain.reserve_work(state, (), quote, "reservation", "effect")
    unknown = domain.release_or_cancel(reserved, execution_known=False).reservation
    registry = TypeRegistry()
    for spec in domain.type_specs():
        registry.register(spec)
    db = tmp_path / "body.db"
    store = GraphStore(db, registry)
    try:
        _commit(store, "reserve-unknown", (
            domain.state_write(NS, state), domain.reservation_write(NS, "activity", unknown),
        ))
    finally:
        store.close()

    store = GraphStore(db, registry)
    try:
        ledger = _ledger(store)
        balance = ledger.balance
        assert (balance.gross_energy, balance.encumbered,
                balance.available, balance.shortfall,
                balance.unknown_encumbered) == pytest.approx((0.8, 0.5, 0.3, 0.0, 0.5))
        assert ledger.admit_new_work("effect", 0.01).reason == "effect_already_reserved"
        assert ledger.admit_new_work("other-effect", 0.31).reason == "insufficient_unencumbered_energy"
        assert ledger.admit_reserved_work("reservation", "effect", 0.1).reason == "receipt_unknown"
        assert len(ledger.read_versions) == 2

        settled = domain.settle_component(
            state, unknown, "work", actual_cost=0.2, component_receipt="receipt:original",
        )
        _commit(store, "settle-known", (
            domain.state_write(NS, settled.state),
            domain.reservation_write(NS, "activity", settled.reservation),
            domain.settlement_write(NS, "activity", "settlement", settled),
        ))
    finally:
        store.close()

    store = GraphStore(db, registry)
    try:
        ledger = _ledger(store)
        assert ledger.state.energy == pytest.approx(0.6)
        assert ledger.state.version == 2
        assert ledger.reservations[0].settled_components == ("work|receipt:original",)
        assert ledger.admit_new_work("effect", 0.01).reason == "effect_already_reserved"
        replay = domain.settle_component(
            ledger.state, ledger.reservations[0], "work", actual_cost=0.2,
            component_receipt="receipt:original",
        )
        assert replay.duplicate and replay.state.energy == pytest.approx(0.6)
        with pytest.raises(ValueError, match="another receipt"):
            domain.settle_component(
                ledger.state, ledger.reservations[0], "work", actual_cost=0.2,
                component_receipt="receipt:forged-retry",
            )
    finally:
        store.close()
