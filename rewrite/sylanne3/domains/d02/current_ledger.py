"""Read D02's current resource ledger through the authorized graph coordinator.

The resulting admission is a candidate.  Its graph epoch and read versions
must be checked again by the coordinator when an action is committed.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphVersion, NamespaceEpoch
from ...runtime_contracts import NamespaceId, QueryEpoch
from . import (BodyDomain, BodyReservation, BodyState, ResourceAdmission, ResourceBalance,
               _nonnegative, _reservation, _validate_body_state)


@dataclass(frozen=True)
class CurrentWorkAdmission:
    """D02's read-only decision plus the graph guards needed by D11."""

    admission: ResourceAdmission
    effect_id: str
    reservation_ref: AtomKey | None
    read_versions: tuple[GraphVersion, ...]
    query_epoch: QueryEpoch

    @property
    def status(self) -> str:
        return self.admission.status

    @property
    def reason(self) -> str | None:
        return self.admission.reason

    @property
    def balance(self) -> ResourceBalance:
        return self.admission.balance


@dataclass(frozen=True)
class CurrentResourceLedger:
    namespace: NamespaceId
    state: BodyState
    reservations: tuple[BodyReservation, ...]
    read_versions: tuple[GraphVersion, ...]
    graph_epoch: int

    @property
    def balance(self):
        """Five-part current balance; unknown receipts remain encumbered."""
        return BodyDomain.balance(self.state, self.reservations)

    @property
    def query_epoch(self) -> QueryEpoch:
        return QueryEpoch(self.namespace, "d02.resource_ledger", self.graph_epoch)

    def _candidate(self, admission: ResourceAdmission, effect_id: str,
                   reservation_ref: AtomKey | None = None) -> CurrentWorkAdmission:
        return CurrentWorkAdmission(admission, effect_id, reservation_ref,
                                    self.read_versions, self.query_epoch)

    def admit_new_work(self, effect_id: str, cost: float) -> CurrentWorkAdmission:
        """Check a new effect against all current and historical reservations."""
        if not isinstance(effect_id, str) or not effect_id:
            raise ValueError("effect_id is required")
        cost = _nonnegative(cost, "cost")
        if any(item.effect_id == effect_id for item in self.reservations):
            balance = BodyDomain.balance(self.state, self.reservations)
            return self._candidate(ResourceAdmission(balance, "stale", "effect_already_reserved"),
                                   effect_id)
        return self._candidate(BodyDomain.check_work_start(
            self.state, self.reservations, additional_cost=cost,
        ), effect_id)

    def admit_reserved_work(self, reservation_id: str, effect_id: str,
                            cost_upper: float) -> CurrentWorkAdmission:
        """Check a new segment against its original effect and unused bound."""
        if not isinstance(reservation_id, str) or not reservation_id:
            raise ValueError("reservation_id is required")
        if not isinstance(effect_id, str) or not effect_id:
            raise ValueError("effect_id is required")
        cost_upper = _nonnegative(cost_upper, "cost_upper")
        admission = BodyDomain.check_work_start(
            self.state, self.reservations, reservation_id=reservation_id,
        )
        selected = tuple(item for item in self.reservations
                         if item.reservation_id == reservation_id)
        reservation_ref = next((ref.key for ref in self.read_versions
                                if ref.key.type_name == "d02.reservation.v1"
                                and ref.key.name == reservation_id), None)
        if admission.status == "clear" and selected:
            if selected[0].effect_id != effect_id:
                admission = ResourceAdmission(admission.balance, "stale",
                                              "reservation_effect_mismatch")
            elif cost_upper > selected[0].remaining_cost + 1e-12:
                admission = ResourceAdmission(admission.balance, "deferred",
                                              "reservation_limit")
        return self._candidate(admission, effect_id, reservation_ref)


def read_current_resource_ledger(
    namespace: NamespaceId, coordinator: object, *,
    authority: object, lease: object, profile_id: str,
) -> CurrentResourceLedger:
    """Read state and every active activity reservation at one namespace epoch."""
    if not isinstance(namespace, NamespaceId) or not isinstance(profile_id, str) or not profile_id:
        raise ValueError("namespace and profile_id are required")
    if not callable(getattr(coordinator, "query", None)):
        raise TypeError("authorized graph coordinator query is required")

    epoch: NamespaceEpoch | None = None

    def read_type(type_name: str, owner_kind: str):
        nonlocal epoch
        atoms = []
        after = None
        while True:
            page = coordinator.query(
                authority, lease, type_names=(type_name,), owner_kind=owner_kind,
                after=after, expected_epoch=epoch, limit=512,
            )
            if len(page.snapshot.epochs) != 1:
                raise ValueError("resource query requires one namespace epoch")
            current = page.snapshot.epochs[0]
            if (current.bot, current.persona) != namespace.as_tuple:
                raise ValueError("resource query crossed namespace")
            if epoch is None:
                epoch = current
            elif current != epoch:
                raise ValueError("resource query changed epoch")
            for atom in page.snapshot.atoms:
                if (atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple:
                    raise ValueError("resource atom crossed namespace")
                if atom.key.owner.kind != owner_kind or atom.key.type_name != type_name or not atom.valid:
                    raise ValueError("resource query returned an invalid graph atom")
                atoms.append(atom)
            if page.next_after is None:
                return tuple(atoms)
            if not atoms or page.next_after != atoms[-1].key or page.next_after == after:
                raise ValueError("resource query pagination is invalid")
            after = page.next_after

    states = read_type("d02.body_state.v1", "persona")
    reservations = read_type("d02.reservation.v1", "activity")
    selected = tuple(atom for atom in states if atom.key.name == profile_id)
    if len(selected) != 1:
        raise ValueError("current body state is missing or ambiguous")
    state_atom = selected[0]
    _validate_body_state(state_atom.value)
    state = BodyState(**state_atom.value)
    if state.profile_id != profile_id or state.version != state_atom.revision:
        raise ValueError("current body state version differs from graph")
    inventory = []
    for atom in reservations:
        reservation = _reservation(atom.value)
        if atom.key.name != reservation.reservation_id:
            raise ValueError("reservation identity differs from graph")
        inventory.append(reservation)
    if len({item.reservation_id for item in inventory}) != len(inventory):
        raise ValueError("current resource ledger contains duplicate reservations")
    if len({item.effect_id for item in inventory}) != len(inventory):
        raise ValueError("current resource ledger contains duplicate effects")
    assert epoch is not None
    return CurrentResourceLedger(
        namespace, state, tuple(inventory),
        tuple(GraphVersion(atom.key, atom.revision)
              for atom in (state_atom, *reservations)),
        epoch.revision,
    )
