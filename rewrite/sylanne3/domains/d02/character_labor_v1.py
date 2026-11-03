"""D02 character-labor pricing and chronological resource arithmetic.

These are calculations over D11-authenticated intervals. They issue no recipe,
clock, Source permission or execution authority.
"""
from dataclasses import dataclass, replace
import math

from ...runtime_contracts import NamespaceId, canonical_digest
from ...graph_types import AtomKey, Owner, TypeSpec
from . import BodyDomain, BodyState, BodyReservation, BodyPassiveRates


def _name(value):
    if type(value) is not str or not value or '|' in value:
        raise ValueError('character labor needs a stable nonempty identity')


def _number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError('character labor values must be finite and nonnegative')
    return float(value)


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('character labor requires an exact original commitment')


@dataclass(frozen=True, slots=True)
class CharacterLaborChannelV1:
    channel_id: str
    exclusive: bool
    compatible_channels: tuple[str, ...]

    def __post_init__(self):
        _name(self.channel_id)
        if type(self.exclusive) is not bool or type(self.compatible_channels) is not tuple:
            raise ValueError('explicit labor channel exclusivity and compatibility required')
        if len(set(self.compatible_channels)) != len(self.compatible_channels):
            raise ValueError('duplicate compatible labor channel')
        for channel in self.compatible_channels:
            _name(channel)


@dataclass(frozen=True, slots=True)
class CharacterLaborFixedComponentV1:
    component_id: str
    cost_category: str
    energy_cost: float
    trigger: str = 'terminal_completed'

    def __post_init__(self):
        _name(self.component_id); _name(self.cost_category)
        if _number(self.energy_cost) <= 0 or self.trigger != 'terminal_completed':
            raise ValueError('fixed labor impulse requires its actual completed component')


@dataclass(frozen=True, slots=True)
class CharacterLaborDurationComponentV1:
    component_id: str
    cost_category: str
    channel_id: str
    energy_drain_rate: float
    fatigue_rates: tuple[tuple[str, float], ...]
    load_rate: float

    def __post_init__(self):
        for name in (self.component_id, self.cost_category, self.channel_id):
            _name(name)
        _number(self.energy_drain_rate); _number(self.load_rate)
        if (type(self.fatigue_rates) is not tuple or tuple(sorted(self.fatigue_rates)) != self.fatigue_rates
                or len(dict(self.fatigue_rates)) != len(self.fatigue_rates)):
            raise ValueError('labor fatigue dimensions must be distinct and ordered')
        for axis, rate in self.fatigue_rates:
            _name(axis); _number(rate)
        if not any((self.energy_drain_rate, self.load_rate, *(r for _, r in self.fatigue_rates))):
            raise ValueError('a continuous labor component must have an explicit effect')


@dataclass(frozen=True, slots=True)
class CharacterLaborPolicyV1:
    policy_ref: str
    revision: int
    namespace: NamespaceId
    profile_id: str
    recipe_ref: str
    recipe_revision: int
    recipe_digest: str
    work_kind: str
    reality: str
    fixed_components: tuple[CharacterLaborFixedComponentV1, ...]
    duration_components: tuple[CharacterLaborDurationComponentV1, ...]
    channels: tuple[CharacterLaborChannelV1, ...]
    duration_upper: float
    recovery_compatible: bool
    valid_until_utc: float
    accept_local_write_wait: bool
    executor_protocol: str = 'source_note_nonpreemptible_segment.v1'
    schema: str = 'd02.character-labor-policy.v1'

    def __post_init__(self):
        for value in (self.policy_ref, self.profile_id, self.recipe_ref, self.work_kind):
            _name(value)
        _digest(self.recipe_digest)
        if (type(self.namespace) is not NamespaceId or type(self.revision) is not int or self.revision < 1
                or type(self.recipe_revision) is not int or self.recipe_revision < 1
                or self.reality not in {'real_execution', 'role_simulation'}
                or type(self.recovery_compatible) is not bool
                or type(self.accept_local_write_wait) is not bool or not self.accept_local_write_wait
                or self.executor_protocol != 'source_note_nonpreemptible_segment.v1'
                or self.schema != 'd02.character-labor-policy.v1'
                or _number(self.duration_upper) <= 0 or _number(self.valid_until_utc) <= 0):
            raise ValueError('explicit current labor policy and finite execution protocol required')
        for values, cls in ((self.fixed_components, CharacterLaborFixedComponentV1),
                (self.duration_components, CharacterLaborDurationComponentV1), (self.channels, CharacterLaborChannelV1)):
            if type(values) is not tuple or len(values) > 16 or any(type(v) is not cls for v in values):
                raise ValueError('labor policy exceeds the existing finite component/channel inventory')
        if not self.duration_components or not self.channels or len(self.fixed_components) + len(self.duration_components) > 16:
            raise ValueError('labor policy needs actual continuous components and channels')
        components = (*self.fixed_components, *self.duration_components)
        if (len({c.component_id for c in components}) != len(components)
                or len({c.cost_category for c in components}) != len(components)
                or len({c.channel_id for c in self.channels}) != len(self.channels)):
            raise ValueError('fixed and duration labor cost categories must be disjoint')
        channels = {c.channel_id: c for c in self.channels}
        if tuple(channels) != ('main_focus',) or not channels['main_focus'].exclusive:
            raise ValueError('the installed nonpreemptible protocol requires exclusive main focus')
        for component in self.duration_components:
            if component.channel_id not in channels:
                raise ValueError('labor component has no quoted channel')
        for channel in self.channels:
            if not set(channel.compatible_channels) <= set(channels):
                raise ValueError('labor channel compatibility references another policy')
            for other in channel.compatible_channels:
                if channel.channel_id not in channels[other].compatible_channels:
                    raise ValueError('labor channel compatibility must be reciprocal')
        if AtomKey.from_token(self.recipe_ref).type_name != 'd10.activity_recipe.v1':
            raise ValueError('labor policy requires the actual registered activity recipe')


@dataclass(frozen=True, slots=True)
class CharacterLaborQuoteV1:
    quote_ref: str
    namespace: NamespaceId
    policy_ref: str
    policy_revision: int
    policy_digest: str
    profile_id: str
    state_version: int
    activity_id: str
    effect_id: str
    parent_budget_lease_ref: str
    technical_quote_ref: str
    technical_quote_version: int
    technical_quote_digest: str
    clock_mapping_ref: str
    clock_mapping_version: int
    clock_original_digest: str
    duration_upper: float
    max_energy_cost: float
    valid_until_utc: float
    schema: str = 'd02.character-labor-quote.v1'

    def __post_init__(self):
        for value in (self.quote_ref, self.policy_ref, self.profile_id, self.activity_id, self.effect_id,
                self.parent_budget_lease_ref, self.technical_quote_ref, self.clock_mapping_ref):
            _name(value)
        for value in (self.policy_digest, self.technical_quote_digest, self.clock_original_digest):
            _digest(value)
        if (type(self.namespace) is not NamespaceId or self.schema != 'd02.character-labor-quote.v1'
                or any(type(v) is not int or v < 1 for v in (self.policy_revision, self.state_version,
                    self.technical_quote_version, self.clock_mapping_version))
                or _number(self.duration_upper) <= 0):
            raise ValueError('actual labor quote identities and original versions required')
        _number(self.max_energy_cost); _number(self.valid_until_utc)


def reserve_character_labor_v1(state, reservations, quote, *, reservation_id, now_utc):
    if type(state) is not BodyState or type(quote) is not CharacterLaborQuoteV1:
        raise TypeError('actual D02 state and explicit character labor quote required')
    _name(reservation_id)
    if ((state.profile_id, state.version) != (quote.profile_id, quote.state_version)
            or _number(now_utc) >= quote.valid_until_utc):
        raise ValueError('labor quote is stale or expired')
    if any(r.reservation_id == reservation_id or r.effect_id == quote.effect_id for r in reservations):
        raise ValueError('labor must be the first unique Body reservation of this actual effect')
    if BodyDomain.check_work_start(state, reservations, additional_cost=quote.max_energy_cost).status != 'clear':
        raise ValueError('labor cannot borrow future recovery or another reservation')
    return BodyReservation(reservation_id, quote.quote_ref, quote.effect_id,
        quote.max_energy_cost, quote.max_energy_cost)


def _positive_ratio(numerators, denominators):
    """Combine finite factors without an overflowing/underflowing intermediate."""
    if any(value == 0 for value in numerators):
        return 0.0
    mantissa, exponent = 1.0, 0
    for value in numerators:
        part, shift = math.frexp(value)
        mantissa *= part; exponent += shift
        mantissa, shift = math.frexp(mantissa); exponent += shift
    for value in denominators:
        part, shift = math.frexp(value)
        mantissa /= part; exponent -= shift
        mantissa, shift = math.frexp(mantissa); exponent += shift
    try:
        result = math.ldexp(mantissa, exponent)
    except OverflowError as exc:
        raise ArithmeticError('actual labor cost is outside the finite accounting range') from exc
    if not math.isfinite(result):
        raise ArithmeticError('actual labor cost is outside the finite accounting range')
    return result


def integrate_character_energy_v1(energy, recovery_rate, drain_rates, duration):
    """One analytic E update; costs only consume reserved commitments."""
    if type(energy) not in (int, float) or not math.isfinite(energy) or not 0 <= energy <= 1:
        raise ValueError('labor integration needs bounded actual energy')
    a, dt = _number(recovery_rate), _number(duration)
    rates = tuple(_number(value) for value in drain_rates)
    if len(rates) > 16:
        raise ValueError('labor rate inventory exceeds the unchanged component bound')
    scale = max((a, *rates))
    if dt == 0 or scale == 0:
        return float(energy), tuple(0.0 for _ in rates)
    normalized = math.fsum((a / scale, *(b / scale for b in rates)))
    equilibrium = (a / scale) / normalized
    z = (scale * dt) * normalized
    u = -math.expm1(-z)
    if z == 0:
        psi = 0.0
    elif z < 1e-3:
        psi = z * (0.5 + z * (-1/6 + z * (1/24 + z * (-1/120 + z/720))))
    elif math.isinf(z):
        psi = 1.0
    else:
        psi = 1.0 - u / z
    next_energy = float(energy) * math.exp(-z) + equilibrium * u
    costs = tuple(math.fsum((
        _positive_ratio((b, float(energy), u), (scale, normalized)),
        _positive_ratio((b, a, dt, psi), (scale, normalized)))) for b in rates)
    if any(not math.isfinite(value) or value < 0 for value in costs):
        raise ArithmeticError('actual labor costs require finite nonnegative originals')
    return next_energy, costs


def union_character_intervals_v1(intervals):
    merged = []
    for start, end in sorted(intervals):
        start, end = _number(start), _number(end)
        if end <= start:
            raise ValueError('actual character labor interval must advance')
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return tuple(merged)


def advance_character_axes_v1(state, passive, duration_components, *, from_cursor, to_cursor, recovery_compatible):
    if type(state) is not BodyState or type(passive) is not BodyPassiveRates:
        raise TypeError('actual Body state and registered passive interval required')
    start, end = _number(from_cursor), _number(to_cursor)
    if start != state.cursor or end <= start:
        raise ValueError('labor resource cursor must be contiguous')
    if type(recovery_compatible) is not bool or len(duration_components) > 16:
        raise ValueError('explicit bounded labor/recovery compatibility required')
    dt = end - start
    if any(type(c) is not CharacterLaborDurationComponentV1 or not set(dict(c.fatigue_rates)) <= set(state.fatigue)
            for c in duration_components):
        raise ValueError('labor rates must name actual Body fatigue axes')
    if set(passive.fatigue_recovery) != set(state.fatigue):
        raise ValueError('passive history must cover the actual fatigue axes')
    energy, costs = integrate_character_energy_v1(state.energy,
        passive.energy_recovery if recovery_compatible else 0.0,
        tuple(c.energy_drain_rate for c in duration_components), dt)
    fatigue = {}
    for axis, value in state.fatigue.items():
        incoming = tuple(dict(c.fatigue_rates).get(axis, 0.0) for c in duration_components)
        outgoing = passive.fatigue_recovery[axis] if recovery_compatible else 0.0
        fatigue[axis] = _advance_rates_v1(value, incoming, (outgoing,), dt)
    load = _advance_rates_v1(state.load, tuple(c.load_rate for c in duration_components),
        (passive.load_recovery if recovery_compatible else 0.0,), dt)
    return replace(state, version=state.version + 1, energy=energy, fatigue=fatigue, load=load, cursor=end), costs


def _advance_rates_v1(value, incoming, outgoing, duration):
    scale = max((*incoming, *outgoing))
    if scale == 0 or duration == 0:
        return value
    normalized_a = math.fsum(a / scale for a in incoming)
    normalized = math.fsum((normalized_a, *(b / scale for b in outgoing)))
    z = (scale * duration) * normalized
    return value * math.exp(-z) + (normalized_a / normalized) * -math.expm1(-z)


def consume_character_labor_cost_v1(reservation, *, component_id, segment_id, original_digest, actual_cost):
    """E has already advanced analytically: never subtract this cost again."""
    if type(reservation) is not BodyReservation:
        raise TypeError('actual unique Body reservation required')
    for value in (component_id, segment_id):
        _name(value)
    _digest(original_digest)
    cost = _number(actual_cost)
    identity = 'character-labor:' + canonical_digest((component_id, segment_id))
    key = identity + '|' + original_digest
    if key in reservation.settled_components:
        return reservation, True, 0.0
    if any(saved.startswith(identity + '|') for saved in reservation.settled_components):
        raise ValueError('same character segment/component has conflicting original evidence')
    if reservation.status in {'released', 'settled', 'overrun'}:
        raise ValueError('character labor cannot consume a closed reservation')
    overrun = max(0.0, cost - reservation.remaining_cost)
    return replace(reservation, remaining_cost=max(0.0, reservation.remaining_cost - cost),
        settled_components=(*reservation.settled_components, key),
        status='overrun' if overrun else 'reserved'), False, overrun


@dataclass(frozen=True, slots=True)
class CharacterLaborRebuildHeadV1:
    profile_id: str
    revision: int
    body_state_version: int
    body_state_digest: str
    checkpoint_ref: str
    checkpoint_revision: int
    checkpoint_digest: str
    checkpoint_cursor: float
    processed_cursor: float
    target_cursor: float
    source_epoch: int
    deletion_epoch: int
    originals_root: str
    status: str
    continuation_ref: str | None
    schema: str = 'd02.character-labor-rebuild-head.v1'

    def __post_init__(self):
        for value in (self.profile_id, self.checkpoint_ref):
            _name(value)
        for value in (self.checkpoint_digest, self.originals_root, self.body_state_digest):
            _digest(value)
        if (self.schema != 'd02.character-labor-rebuild-head.v1'
                or type(self.body_state_version) is not int or self.body_state_version < 1
                or type(self.revision) is not int or self.revision < 1
                or type(self.checkpoint_revision) is not int or self.checkpoint_revision < 1
                or any(type(v) is not int or v < 0 for v in (self.source_epoch, self.deletion_epoch))
                or self.status not in {'current', 'pending_confirmation', 'rebuilding', 'unavailable'}
                or not 0 <= _number(self.checkpoint_cursor) <= _number(self.processed_cursor) <= _number(self.target_cursor)):
            raise ValueError('actual ordered labor rebuild cursor/original epoch required')
        if self.continuation_ref is not None:
            _name(self.continuation_ref)
        if self.status == 'current' and (self.processed_cursor != self.target_cursor or self.continuation_ref is not None):
            raise ValueError('partial labor reconstruction cannot expose a spendable cursor')


@dataclass(frozen=True, slots=True)
class CharacterLaborCorrectionRevisionV1:
    profile_id: str
    revision: int
    checkpoint_ref: str
    checkpoint_revision: int
    checkpoint_digest: str
    prior_body_version: int
    new_body_version: int
    from_cursor: float
    to_cursor: float
    originals_root: str
    source_epoch: int
    deletion_epoch: int
    trigger_original_ref: str
    schema: str = 'd02.character-labor-correction-revision.v1'

    def __post_init__(self):
        for value in (self.profile_id, self.checkpoint_ref, self.trigger_original_ref):
            _name(value)
        for value in (self.checkpoint_digest, self.originals_root):
            _digest(value)
        if (self.schema != 'd02.character-labor-correction-revision.v1'
                or any(type(v) is not int or v < 1 for v in
                    (self.revision, self.checkpoint_revision, self.prior_body_version, self.new_body_version))
                or self.new_body_version != self.prior_body_version + 1
                or any(type(v) is not int or v < 0 for v in (self.source_epoch, self.deletion_epoch))
                or _number(self.to_cursor) < _number(self.from_cursor)):
            raise ValueError('labor correction must bind one actual Body CAS without replaying the action')


RESOURCE_REBUILD_TYPE = 'd02.character_labor_rebuild_head.v1'
LABOR_CORRECTION_TYPE = 'd02.character_labor_correction_revision.v1'


def character_labor_rebuild_key_v1(namespace, profile_id):
    return AtomKey(Owner('persona', *namespace.as_tuple), RESOURCE_REBUILD_TYPE, profile_id)


def character_labor_correction_key_v1(namespace, profile_id, revision):
    return AtomKey(Owner('persona', *namespace.as_tuple), LABOR_CORRECTION_TYPE,
        profile_id + ':' + str(revision))


def character_labor_type_specs_v1():
    from ...runtime_contracts import schema_hash
    from dataclasses import fields
    def validator(cls):
        def validate(value):
            if type(value) is not dict or set(value) != {f.name for f in fields(cls)}:
                raise ValueError('exact D02 character labor derived metadata fields required')
            cls(**value)
        return validate
    return tuple(TypeSpec(name, ('persona',), role, validator(cls), writer_domain='d02',
        immutable=role == 'source', schema_hash=schema_hash({
            'type': name, 'schema': cls.__dataclass_fields__['schema'].default,
            'fields': [f.name for f in fields(cls)], 'writer_domain': 'd02'}))
        for name, role, cls in (
            (RESOURCE_REBUILD_TYPE, 'state', CharacterLaborRebuildHeadV1),
            (LABOR_CORRECTION_TYPE, 'source', CharacterLaborCorrectionRevisionV1)))


def character_labor_policy_from_wire_v1(raw):
    from dataclasses import fields
    if type(raw) is not dict or set(raw) != {f.name for f in fields(CharacterLaborPolicyV1)}:
        raise ValueError('closed character labor policy fields required')
    value = dict(raw)
    value['namespace'] = NamespaceId(**value['namespace'])
    value['fixed_components'] = tuple(CharacterLaborFixedComponentV1(**v) for v in value['fixed_components'])
    value['duration_components'] = tuple(CharacterLaborDurationComponentV1(**dict(v,
        fatigue_rates=tuple(tuple(pair) for pair in v['fatigue_rates']))) for v in value['duration_components'])
    value['channels'] = tuple(CharacterLaborChannelV1(**dict(v,
        compatible_channels=tuple(v['compatible_channels']))) for v in value['channels'])
    return CharacterLaborPolicyV1(**value)


def character_labor_quote_from_wire_v1(raw):
    from dataclasses import fields
    if type(raw) is not dict or set(raw) != {f.name for f in fields(CharacterLaborQuoteV1)}:
        raise ValueError('closed character labor quote fields required')
    return CharacterLaborQuoteV1(**dict(raw, namespace=NamespaceId(**raw['namespace'])))
