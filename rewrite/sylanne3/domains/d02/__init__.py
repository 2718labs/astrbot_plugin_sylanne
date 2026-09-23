"""D02 resource and artificial-body domain semantics.

The objects here are candidate calculations only.  D11 must atomically commit
reservations and settlements with the rest of a domain bundle.
"""

from dataclasses import asdict, dataclass, fields, replace
import math

from ...graph_types import AtomKey, GraphWrite, Owner, TypeSpec

from ...runtime_contracts import (
    CommandEnvelope,
    DependencySet,
    DomainProposal,
    NamespaceId,
    ProviderDescriptor,
    RUNTIME_SCHEMA,
    schema_hash,
)


def _identifier(value: object, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a nonempty string")


def _unit(value: object, name: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be a finite number in [0, 1]")
    return float(value)


def _nonnegative(value: object, name: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0.0:
        raise ValueError(f"{name} must be a finite nonnegative number")
    return float(value)


def _exact_payload(value: object, expected: set[str], label: str) -> dict:
    if type(value) is not dict:
        raise TypeError(f"{label} must be an object")
    if set(value) != expected:
        raise ValueError(
            f"{label} fields must match exactly; "
            f"missing={sorted(expected - set(value))!r}, extra={sorted(set(value) - expected)!r}"
        )
    return dict(value)


def _json_value(value: object) -> object:
    if type(value) is dict:
        return {key: _json_value(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_json_value(item) for item in value]
    if type(value) is list:
        return [_json_value(item) for item in value]
    return value


def _namespace(value: object) -> NamespaceId:
    return NamespaceId(**_exact_payload(value, {"bot_id", "persona_id"}, "namespace"))


@dataclass(frozen=True)
class BodyProfile:
    profile_id: str
    namespace: NamespaceId
    version: int
    applicable_axes: tuple[str, ...]
    work_kinds: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.profile_id, "profile_id")
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("version must be a positive exact integer")
        axes, kinds = tuple(self.applicable_axes), tuple(self.work_kinds)
        if not axes or not kinds or len(set(axes)) != len(axes) or len(set(kinds)) != len(kinds):
            raise ValueError("axes and work kinds must be nonempty and unique")
        if any(not isinstance(item, str) or not item for item in axes + kinds):
            raise ValueError("axes and work kinds must contain valid strings")
        object.__setattr__(self, "applicable_axes", axes)
        object.__setattr__(self, "work_kinds", kinds)


@dataclass(frozen=True)
class BodyState:
    profile_id: str
    version: int
    energy: float
    fatigue: dict[str, float]
    load: float
    cursor: float

    def __post_init__(self) -> None:
        _identifier(self.profile_id, "profile_id")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("version must be a positive exact integer")
        _unit(self.energy, "energy")
        _unit(self.load, "load")
        _nonnegative(self.cursor, "cursor")
        fatigue = dict(self.fatigue)
        if not fatigue:
            raise ValueError("fatigue must not be empty")
        for kind, value in fatigue.items():
            _identifier(kind, "fatigue work kind")
            _unit(value, "fatigue value")
        object.__setattr__(self, "fatigue", fatigue)


@dataclass(frozen=True)
class WorkComponent:
    component_id: str
    cost_category: str
    fixed_cost: float = 0.0
    duration_rate: float = 0.0

    def __post_init__(self) -> None:
        _identifier(self.component_id, "component_id")
        _identifier(self.cost_category, "cost_category")
        _nonnegative(self.fixed_cost, "fixed_cost")
        _nonnegative(self.duration_rate, "duration_rate")
        if self.fixed_cost == 0 and self.duration_rate == 0:
            raise ValueError("a component must carry a nonzero quoted cost")


@dataclass(frozen=True)
class BodyQuote:
    quote_id: str
    profile_id: str
    state_version: int
    activity_id: str
    work_kind: str
    duration_upper: float
    components: tuple[WorkComponent, ...]
    max_energy_cost: float
    valid_until: float


@dataclass(frozen=True)
class BodyReservation:
    reservation_id: str
    quote_id: str
    effect_id: str
    reserved_cost: float
    remaining_cost: float
    settled_components: tuple[str, ...] = ()
    status: str = "reserved"

    def __post_init__(self) -> None:
        for name in ("reservation_id", "quote_id", "effect_id"):
            _identifier(getattr(self, name), name)
        reserved = _nonnegative(self.reserved_cost, "reserved_cost")
        remaining = _nonnegative(self.remaining_cost, "remaining_cost")
        if remaining > reserved + 1e-12:
            raise ValueError("remaining_cost cannot exceed reserved_cost")
        settled = tuple(self.settled_components)
        if len(set(settled)) != len(settled):
            raise ValueError("settled_components must be unique")
        for item in settled:
            _identifier(item, "settled component")
        if self.status not in {"reserved", "pending_confirmation", "overrun", "settled", "released"}:
            raise ValueError("unknown reservation status")
        object.__setattr__(self, "settled_components", settled)


@dataclass(frozen=True)
class ResourceBalance:
    gross_energy: float
    encumbered: float
    available: float
    shortfall: float


@dataclass(frozen=True)
class BodyProjection:
    profile_id: str
    state_version: int
    available_energy: float
    fatigue: tuple[tuple[str, float], ...]
    load: float
    diagnostic_available: bool


@dataclass(frozen=True)
class SettlementResult:
    state: BodyState
    reservation: BodyReservation
    duplicate: bool
    overrun: float


@dataclass(frozen=True)
class CancellationResult:
    reservation: BodyReservation
    status: str


def _validate_body_profile(value: object) -> None:
    data = _exact_payload(value, {field.name for field in fields(BodyProfile)}, "body profile")
    data["namespace"] = _namespace(data["namespace"])
    for name in ("applicable_axes", "work_kinds"):
        if type(data[name]) is not list:
            raise TypeError(f"{name} must be a JSON array")
        data[name] = tuple(data[name])
    BodyProfile(**data)


def _validate_body_state(value: object) -> None:
    BodyState(**_exact_payload(value, {field.name for field in fields(BodyState)}, "body state"))


def _reservation(value: object) -> BodyReservation:
    data = _exact_payload(value, {field.name for field in fields(BodyReservation)}, "body reservation")
    if type(data["settled_components"]) is not list:
        raise TypeError("settled_components must be a JSON array")
    data["settled_components"] = tuple(data["settled_components"])
    return BodyReservation(**data)


def _validate_reservation(value: object) -> None:
    _reservation(value)


def _validate_settlement(value: object) -> None:
    data = _exact_payload(value, {field.name for field in fields(SettlementResult)}, "settlement")
    data["state"] = BodyState(**_exact_payload(
        data["state"], {field.name for field in fields(BodyState)}, "settlement state"
    ))
    data["reservation"] = _reservation(data["reservation"])
    if type(data["duplicate"]) is not bool:
        raise TypeError("duplicate must be bool")
    _nonnegative(data["overrun"], "overrun")
    SettlementResult(**data)


class BodyDomain:
    """Pure D02 quote/reserve/settle calculations with no hidden resource store."""

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider_id="d02.body", contract_version=RUNTIME_SCHEMA,
            request_schema_hash=schema_hash({"domain": "d02", "proposal": 1}),
            response_schema_hash=schema_hash({"domain": "d02", "resource": 1}),
            owner_capabilities=("persona", "activity"), supported_modalities=("structured",),
            supported_purposes=("context", "expression", "consolidation", "audit"),
            supported_platforms=("runtime",), timeout_mode="bounded", cancellation_mode="cooperative",
            idempotency_mode="operation_id", cost_reporting_mode="role_resource_only",
            health_capabilities=("validate",), recovery_capabilities=("reconcile_reservation",),
        )

    def type_specs(self) -> tuple[TypeSpec, ...]:
        layouts = (
            ("d02.body_profile.v1", ("persona",), "state", _validate_body_profile, BodyProfile),
            ("d02.body_state.v1", ("persona",), "state", _validate_body_state, BodyState),
            ("d02.reservation.v1", ("activity",), "state", _validate_reservation, BodyReservation),
            ("d02.settlement.v1", ("activity",), "state", _validate_settlement, SettlementResult),
        )
        return tuple(TypeSpec(
            name,
            owners,
            storage,
            validator,
            writer_domain="d02",
            schema_hash=schema_hash({
                "type": name,
                "schema_version": 1,
                "owner_kinds": sorted(owners),
                "storage_role": storage,
                "fields": [field.name for field in fields(value_type)],
            }),
        ) for name, owners, storage, validator, value_type in layouts)

    def register_types(self) -> tuple[str, ...]:
        return tuple(spec.name for spec in self.type_specs())

    @staticmethod
    def profile_write(profile: BodyProfile) -> GraphWrite:
        if not isinstance(profile, BodyProfile):
            raise TypeError("profile must be BodyProfile")
        return GraphWrite(
            AtomKey(Owner("persona", profile.namespace.bot_id, profile.namespace.persona_id),
                    "d02.body_profile.v1", profile.profile_id),
            _json_value(asdict(profile)),
        )

    @staticmethod
    def state_write(namespace: NamespaceId, state: BodyState) -> GraphWrite:
        if not isinstance(namespace, NamespaceId) or not isinstance(state, BodyState):
            raise TypeError("namespace and state must be D02 values")
        return GraphWrite(
            AtomKey(Owner("persona", namespace.bot_id, namespace.persona_id),
                    "d02.body_state.v1", state.profile_id),
            _json_value(asdict(state)),
        )

    @staticmethod
    def reservation_write(
        namespace: NamespaceId, activity_id: str, reservation: BodyReservation
    ) -> GraphWrite:
        if not isinstance(namespace, NamespaceId) or not isinstance(reservation, BodyReservation):
            raise TypeError("namespace and reservation must be D02 values")
        _identifier(activity_id, "activity_id")
        return GraphWrite(
            AtomKey(Owner("activity", namespace.bot_id, namespace.persona_id, activity_id),
                    "d02.reservation.v1", reservation.reservation_id),
            _json_value(asdict(reservation)),
        )

    @staticmethod
    def settlement_write(
        namespace: NamespaceId, activity_id: str, settlement_id: str,
        settlement: SettlementResult,
    ) -> GraphWrite:
        if not isinstance(namespace, NamespaceId) or not isinstance(settlement, SettlementResult):
            raise TypeError("namespace and settlement must be D02 values")
        _identifier(activity_id, "activity_id")
        _identifier(settlement_id, "settlement_id")
        return GraphWrite(
            AtomKey(Owner("activity", namespace.bot_id, namespace.persona_id, activity_id),
                    "d02.settlement.v1", settlement_id),
            _json_value(asdict(settlement)),
        )

    @staticmethod
    def compile_scheme(draft: BodyProfile, snapshot: object = None) -> BodyProfile:
        if not isinstance(draft, BodyProfile):
            raise TypeError("draft must be BodyProfile")
        return draft

    @staticmethod
    def project(query: BodyState, snapshot: object = None) -> BodyProjection:
        if not isinstance(query, BodyState):
            raise TypeError("query must be BodyState")
        # This is a resource projection, not a claim that the character has
        # direct diagnostic introspection.  Audience filtering is D06/D11 work.
        return BodyProjection(
            query.profile_id, query.version, query.energy,
            tuple(sorted(query.fatigue.items())), query.load, diagnostic_available=False,
        )

    def proposal_for(
        self, envelope: CommandEnvelope, contribution_keys: tuple[str, ...] = (), *,
        requires_settlement: bool = False,
        typed_writes: tuple[GraphWrite, ...] = (),
        dependencies: DependencySet | None = None,
    ) -> DomainProposal:
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        return DomainProposal(
            domain="d02", proposal_schema="d02.proposal.v1",
            proposal_schema_hash=schema_hash({"domain": "d02", "proposal": 1}), envelope=envelope,
            typed_writes=typed_writes, dependencies=dependencies or DependencySet(), contribution_keys=contribution_keys,
            required_bundle_parts=("d02_settlement",) if requires_settlement else (),
        )

    def validate(self, proposal: DomainProposal, snapshot: object = None) -> DomainProposal:
        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if proposal.domain != "d02" or proposal.proposal_schema != "d02.proposal.v1":
            raise ValueError("proposal is not a D02 body proposal")
        if proposal.proposal_schema_hash != self.descriptor.request_schema_hash:
            raise ValueError("D02 proposal schema hash is not recognized")
        specs = {spec.name: spec for spec in self.type_specs()}
        for write in proposal.typed_writes:
            spec = specs.get(write.key.type_name)
            if spec is None or write.key.owner.kind not in spec.owner_kinds:
                raise ValueError("D02 proposal contains an unauthorized graph type or owner")
            spec.validator(write.value)
        return proposal

    def quote_work(
        self,
        profile: BodyProfile,
        state: BodyState,
        activity_id: str,
        work_kind: str,
        duration_upper: float,
        components: tuple[WorkComponent, ...],
        *,
        valid_until: float,
    ) -> BodyQuote:
        if not isinstance(profile, BodyProfile) or not isinstance(state, BodyState):
            raise TypeError("profile and state must be D02 values")
        if state.profile_id != profile.profile_id:
            raise ValueError("state does not belong to profile")
        _identifier(activity_id, "activity_id")
        if work_kind not in profile.work_kinds:
            raise ValueError("work kind is not configured by profile")
        duration_upper = _nonnegative(duration_upper, "duration_upper")
        valid_until = _nonnegative(valid_until, "valid_until")
        if valid_until <= state.cursor:
            raise ValueError("quote must outlive the current cursor")
        components = tuple(components)
        if not components or any(not isinstance(item, WorkComponent) for item in components):
            raise ValueError("components must contain WorkComponent values")
        if len({item.component_id for item in components}) != len(components):
            raise ValueError("component IDs must be unique")
        if len({item.cost_category for item in components}) != len(components):
            raise ValueError("cost categories must not overlap")
        total = sum(item.fixed_cost + item.duration_rate * duration_upper for item in components)
        if total > 1.0 + 1e-12:
            raise ValueError("quote's energy bound exceeds the domain capacity")
        return BodyQuote(
            quote_id=f"quote:{activity_id}:{state.version}", profile_id=profile.profile_id,
            state_version=state.version, activity_id=activity_id, work_kind=work_kind,
            duration_upper=duration_upper, components=components, max_energy_cost=total,
            valid_until=valid_until,
        )

    @staticmethod
    def balance(state: BodyState, reservations: tuple[BodyReservation, ...]) -> ResourceBalance:
        if not isinstance(state, BodyState):
            raise TypeError("state must be BodyState")
        active = tuple(reservations)
        if any(not isinstance(item, BodyReservation) for item in active):
            raise TypeError("reservations must contain BodyReservation values")
        encumbered = sum(item.remaining_cost for item in active if item.status in {"reserved", "pending_confirmation"})
        return ResourceBalance(state.energy, encumbered, max(0.0, state.energy - encumbered), max(0.0, encumbered - state.energy))

    def reserve_work(
        self, state: BodyState, reservations: tuple[BodyReservation, ...], quote: BodyQuote,
        reservation_id: str, effect_id: str,
    ) -> BodyReservation:
        if not isinstance(quote, BodyQuote):
            raise TypeError("quote must be BodyQuote")
        _identifier(reservation_id, "reservation_id")
        _identifier(effect_id, "effect_id")
        if quote.state_version != state.version:
            raise ValueError("quote is stale")
        if any(item.reservation_id == reservation_id or item.effect_id == effect_id for item in reservations):
            raise ValueError("reservation or effect already exists")
        if self.balance(state, reservations).available + 1e-12 < quote.max_energy_cost:
            raise ValueError("insufficient unencumbered energy")
        return BodyReservation(reservation_id, quote.quote_id, effect_id, quote.max_energy_cost, quote.max_energy_cost)

    def settle_component(
        self, state: BodyState, reservation: BodyReservation, component_id: str,
        *, actual_cost: float, component_receipt: str,
    ) -> SettlementResult:
        if not isinstance(state, BodyState) or not isinstance(reservation, BodyReservation):
            raise TypeError("state and reservation must be D02 values")
        _identifier(component_id, "component_id")
        _identifier(component_receipt, "component_receipt")
        actual_cost = _nonnegative(actual_cost, "actual_cost")
        settlement_key = f"{component_id}|{component_receipt}"
        if settlement_key in reservation.settled_components:
            return SettlementResult(state, reservation, True, 0.0)
        overrun = max(0.0, actual_cost - reservation.remaining_cost)
        charged = min(state.energy, actual_cost)
        next_state = replace(state, version=state.version + 1, energy=max(0.0, state.energy - charged))
        next_reservation = replace(
            reservation,
            remaining_cost=max(0.0, reservation.remaining_cost - actual_cost),
            settled_components=reservation.settled_components + (settlement_key,),
            status="overrun" if overrun else ("settled" if reservation.remaining_cost <= actual_cost else "reserved"),
        )
        return SettlementResult(next_state, next_reservation, False, overrun)

    @staticmethod
    def release_or_cancel(reservation: BodyReservation, *, execution_known: bool) -> CancellationResult:
        if not isinstance(reservation, BodyReservation):
            raise TypeError("reservation must be BodyReservation")
        if not execution_known:
            return CancellationResult(replace(reservation, status="pending_confirmation"), "pending_confirmation")
        return CancellationResult(replace(reservation, remaining_cost=0.0, status="released"), "released")

    @staticmethod
    def advance_scalar(value: float, a: float, b: float, dt: float) -> float:
        value = _unit(value, "value")
        a, b, dt = _nonnegative(a, "a"), _nonnegative(b, "b"), _nonnegative(dt, "dt")
        rate = a + b
        if rate == 0.0:
            return value
        equilibrium = a / rate
        return equilibrium + (value - equilibrium) * math.exp(-rate * dt)

    @staticmethod
    def invalidate(refs: tuple[object, ...]) -> tuple[object, ...]:
        return tuple(refs)

    @staticmethod
    def cleanup(plan: object) -> tuple[str, object]:
        return "deferred_to_runtime_deletion_coordinator", plan
