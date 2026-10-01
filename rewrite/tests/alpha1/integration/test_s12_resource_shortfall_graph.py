"""S12 slice: persisted D02 reservations survive a degraded body balance.

The graph writes are controlled setup. The current ledger reads through the
real GraphCoordinator and rejects new work using persisted graph versions.
"""

from dataclasses import replace

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d02 import BodyDomain, BodyProfile, BodyState, WorkComponent
from sylanne3.domains.d02.current_ledger import read_current_resource_ledger
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import GraphCandidate, GraphVersion, GraphWrite, TypeRegistry
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId


ROLE = NamespaceId("bot", "persona")


def _open_graph(path, registry, domain):
    store = GraphStore(path, registry)
    bootstrap = object()
    coordinator = GraphCoordinator(store, bootstrap)
    coordinator.register_provider(
        bootstrap, "d02", domain, "d02.proposal.v1",
        domain.descriptor.request_schema_hash)
    lease, ref = coordinator.grant(
        bootstrap, actor="body-worker", issuer_domain="d02", namespace=ROLE,
        domains=("d02",), activation_generation=1)
    authority = AuthorityContext(
        "body-worker", "d02", ref, ROLE, ("persona", "activity"),
        "check", ("internal",), "policy", 1)
    return store, coordinator, authority, lease


def _commit_fixture(store, name, versions, writes):
    return store.graph_commit(GraphCandidate(
        Event(Scope("bot", "persona", "session"), name, 1.0, name, {}),
        tuple(GraphVersion(key, revision) for key, revision in versions),
        tuple(GraphWrite(write.key, write.value) for write in writes),
    ))


def test_unknown_reservation_shortfall_survives_graph_restart(tmp_path):
    domain = BodyDomain()
    registry = TypeRegistry()
    for spec in domain.type_specs():
        registry.register(spec)
    profile = BodyProfile(
        "body:base", ROLE, 1,
        ("energy", "fatigue:thinking", "load"), ("thinking",))
    initial = BodyState("body:base", 1, 0.8, {"thinking": 0.1}, 0.2, 0.0)
    quote = domain.quote_work(
        profile, initial, "activity:one", "thinking", 5.0,
        (WorkComponent("work", "duration", duration_rate=0.1),),
        valid_until=20.0)
    reservation = domain.reserve_work(
        initial, (), quote, "reservation:one", "effect:one")
    state_write = domain.state_write(ROLE, initial)
    reserved_write = domain.reservation_write(ROLE, "activity:one", reservation)
    path = tmp_path / "business.db"
    store, coordinator, authority, lease = _open_graph(path, registry, domain)
    try:
        _commit_fixture(store, "initial-body", (
            (state_write.key, 0), (reserved_write.key, 0)),
            (state_write, reserved_write))
        before = read_current_resource_ledger(
            ROLE, coordinator, authority=authority, lease=lease,
            profile_id="body:base")
        assert before.admit_new_work("effect:two", 0.1).status == "clear"

        # Unknown cancellation preserves the existing effect's reservation.
        pending = domain.release_or_cancel(
            reservation, execution_known=False).reservation
        degraded = replace(initial, version=2, energy=0.2)
        degraded_write = domain.state_write(ROLE, degraded)
        pending_write = domain.reservation_write(
            ROLE, "activity:one", pending)
        _commit_fixture(store, "degraded-unknown", (
            (state_write.key, 1), (reserved_write.key, 1)),
            (degraded_write, pending_write))
    finally:
        store.close()

    reopened, current, authority, lease = _open_graph(path, registry, domain)
    try:
        ledger = read_current_resource_ledger(
            ROLE, current, authority=authority, lease=lease,
            profile_id="body:base")
        assert len(ledger.reservations) == 1
        assert ledger.reservations[0].effect_id == "effect:one"
        assert ledger.reservations[0].status == "pending_confirmation"
        assert {ref.revision for ref in ledger.read_versions} == {2}
        admission = ledger.admit_new_work("effect:two", 0.1)
        assert (admission.status, admission.reason) == (
            "deferred", "reservation_shortfall")
        assert (admission.balance.gross_energy,
                admission.balance.encumbered,
                admission.balance.available,
                round(admission.balance.shortfall, 6)) == (0.2, 0.5, 0.0, 0.3)
        assert ledger.admit_reserved_work(
            "reservation:one", "effect:one", 0.1).status == "deferred"
        assert admission.query_epoch.revision == ledger.graph_epoch
        assert admission.read_versions == ledger.read_versions
    finally:
        reopened.close()
