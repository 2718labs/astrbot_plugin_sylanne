"""Bounded D10 offline interval candidate from a current D11 clock read.

The coordinator owns the trusted read and the eventual graph transaction.
Selecting an interval never creates an experience, artifact, or execution fact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Callable

from ...runtime.clock import CharacterClockMapping
from ...runtime.restore_anchor import RestoreAnchor
from ...runtime_contracts import NamespaceId, VersionedRef, canonical_digest
from ...graph_types import AtomKey
from ...memory_types import access_key


def _utc(value: str) -> datetime:
    if type(value) is not str:
        raise ValueError("UTC instant required")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("UTC instant required") from exc
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        raise ValueError("explicit UTC instant required")
    return result.astimezone(timezone.utc)


def _stamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _decimal_seconds(value: timedelta) -> Decimal:
    return (Decimal(value.days) * Decimal(86400)
            + Decimal(value.seconds)
            + Decimal(value.microseconds) / Decimal(1_000_000))


@dataclass(frozen=True, slots=True)
class OfflineIntervalReadSet:
    """W01 verifies these heads while holding its recovery/read barrier.

    ``source_versions`` includes the simulation recipe, checkpoint, permissions,
    and any state used by the integrator. A caller-created read set is not proof.
    """

    namespace: NamespaceId
    mapping: CharacterClockMapping
    checkpoint_ref: str
    checkpoint_end_utc: str
    source_versions: tuple[VersionedRef, ...]
    restore_anchor: RestoreAnchor
    coverage: str

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId or type(self.mapping) is not CharacterClockMapping:
            raise TypeError("typed namespace and D11 mapping required")
        if type(self.checkpoint_ref) is not str or not self.checkpoint_ref:
            raise ValueError("checkpoint ref required")
        _utc(self.checkpoint_end_utc)
        if (type(self.source_versions) is not tuple or not self.source_versions
                or any(type(item) is not VersionedRef for item in self.source_versions)
                or len({item.ref for item in self.source_versions}) != len(self.source_versions)):
            raise ValueError("complete, unique source versions required")
        if type(self.restore_anchor) is not RestoreAnchor:
            raise TypeError("independent restore anchor required")
        if self.coverage not in {"full", "partial", "none"}:
            raise ValueError("invalid read coverage")


@dataclass(frozen=True, slots=True)
class OfflineSimulationSliceCandidate:
    status: str
    reason: str | None
    namespace: NamespaceId
    checkpoint_ref: str
    mapping_id: str
    mapping_version: int
    start_utc: str | None
    end_utc: str | None
    unprocessed_from_utc: str
    unprocessed_until_utc: str
    character_start: Decimal | None
    character_end: Decimal | None
    source_versions: tuple[VersionedRef, ...]
    restore_anchor: RestoreAnchor


def plan_offline_simulation_slice(
    read_set: OfflineIntervalReadSet, *, requested_until_utc: str,
    trusted_now_utc: str, boundary_utc: str | None,
    read_verifier: Callable[[OfflineIntervalReadSet], bool] | None,
) -> OfflineSimulationSliceCandidate:
    """Select at most 24 hours of already permitted continuous simulation.

    W01's verifier must prove the current D11 mapping row, all source/access
    versions, and the independent deletion/execution restore head in one read
    barrier. A time value or issuer_domain label alone never proves that read.
    The caller must later integrate and atomically commit a versioned checkpoint.
    """
    if type(read_set) is not OfflineIntervalReadSet:
        raise TypeError("typed offline read set required")
    requested, now = _utc(requested_until_utc), _utc(trusted_now_utc)
    boundary = _utc(boundary_utc) if boundary_utc is not None else None
    start = _utc(read_set.checkpoint_end_utc)
    anchor = read_set.restore_anchor
    from ...graph_coordinator import namespace_ref
    if anchor.namespace != namespace_ref(read_set.namespace):
        raise ValueError("restore anchor namespace differs")
    if requested > now:
        raise ValueError("requested interval exceeds trusted current time")

    def deferred(reason: str) -> OfflineSimulationSliceCandidate:
        return OfflineSimulationSliceCandidate(
            "deferred", reason, read_set.namespace, read_set.checkpoint_ref,
            read_set.mapping.mapping_id, read_set.mapping.version,
            None, None, _stamp(start), _stamp(requested), None, None,
            read_set.source_versions, anchor,
        )

    if read_set.coverage != "full" or read_verifier is None:
        return deferred("current_read_unavailable")
    try:
        verified = read_verifier(read_set) is True
    except Exception:
        verified = False
    if not verified:
        return deferred("current_read_unverified")
    valid_start = _utc(read_set.mapping.valid_from_utc)
    valid_end = _utc(read_set.mapping.valid_until_utc)
    if start < valid_start or start >= valid_end:
        return deferred("mapping_outside_checkpoint")
    if boundary is not None and boundary <= start:
        return deferred("decision_boundary")
    end = min(requested, now, valid_end, start + timedelta(hours=24))
    if boundary is not None:
        end = min(end, boundary)
    if end <= start:
        return deferred("no_permitted_interval")
    return OfflineSimulationSliceCandidate(
        "candidate", None, read_set.namespace, read_set.checkpoint_ref,
        read_set.mapping.mapping_id, read_set.mapping.version,
        _stamp(start), _stamp(end), _stamp(end), _stamp(requested),
        read_set.mapping.character_at(_stamp(start)),
        read_set.mapping.character_at(_stamp(end)),
        read_set.source_versions, anchor,
    )


@dataclass(frozen=True, slots=True)
class OfflineTickRecipeV1:
    """Tick-only simulation: no real work, artifact, message or tool effect."""

    recipe_id: str
    version: int
    schedule_ref: VersionedRef
    cadence_seconds: int
    max_ticks_per_slice: int
    world_kind: str = "role_simulation"
    cadence_origin_utc: str | None = None

    def __post_init__(self) -> None:
        if (type(self.recipe_id) is not str or not self.recipe_id
                or type(self.version) is not int or self.version < 1
                or type(self.schedule_ref) is not VersionedRef
                or type(self.cadence_seconds) is not int or self.cadence_seconds < 60
                or type(self.max_ticks_per_slice) is not int
                or not 1 <= self.max_ticks_per_slice <= 32
                or self.world_kind != "role_simulation"):
            raise ValueError("bounded offline simulation recipe required")
        if self.cadence_origin_utc is not None:
            if _stamp(_utc(self.cadence_origin_utc)) != self.cadence_origin_utc:
                raise ValueError("offline cadence origin must use canonical UTC")


def offline_tick_recipe_to_wire_v1(recipe: OfflineTickRecipeV1) -> dict:
    """Keep the original six-field wire exactly when no origin is registered."""
    if type(recipe) is not OfflineTickRecipeV1:
        raise TypeError("exact offline tick recipe required")
    raw = {
        "recipe_id": recipe.recipe_id, "version": recipe.version,
        "schedule_ref": {"ref": recipe.schedule_ref.ref, "version": recipe.schedule_ref.version},
        "cadence_seconds": recipe.cadence_seconds,
        "max_ticks_per_slice": recipe.max_ticks_per_slice, "world_kind": recipe.world_kind,
    }
    if recipe.cadence_origin_utc is not None:
        raw["cadence_origin_utc"] = recipe.cadence_origin_utc
    return raw


def decode_offline_tick_recipe_v1(raw: dict) -> OfflineTickRecipeV1:
    keys = {"recipe_id", "version", "schedule_ref", "cadence_seconds", "max_ticks_per_slice", "world_kind"}
    if (type(raw) is not dict or set(raw) not in (keys, keys | {"cadence_origin_utc"})
            or ("cadence_origin_utc" in raw and type(raw["cadence_origin_utc"]) is not str)
            or type(raw["schedule_ref"]) is not dict or set(raw["schedule_ref"]) != {"ref", "version"}
            or type(raw["schedule_ref"]["ref"]) is not str
            or type(raw["schedule_ref"]["version"]) is not int
            or raw["schedule_ref"]["version"] < 1):
        raise ValueError("offline recipe wire must be an exact registered variant")
    value = OfflineTickRecipeV1(**{**raw, "schedule_ref": VersionedRef(**raw["schedule_ref"])})
    if offline_tick_recipe_to_wire_v1(value) != raw:
        raise ValueError("offline recipe wire does not round-trip exactly")
    return value


@dataclass(frozen=True, slots=True)
class OfflineObservedTickV1:
    scheduled_at_utc: str
    occurrence_ref: VersionedRef
    source_ref: VersionedRef
    access_ref: VersionedRef
    kind: str
    result: str

    def __post_init__(self) -> None:
        _utc(self.scheduled_at_utc)
        if any(type(getattr(self, name)) is not VersionedRef for name in (
            "occurrence_ref", "source_ref", "access_ref",
        )):
            raise TypeError("tick requires versioned occurrence, source and access")
        if self.kind not in {"role_simulation", "external_tool", "user_message", "decision"}:
            raise ValueError("unknown offline tick kind")
        if self.result not in {"observed", "unknown"}:
            raise ValueError("offline tick result must distinguish unknown")


@dataclass(frozen=True, slots=True)
class OfflineTickComputationV1:
    occurrence_ref: VersionedRef
    character_at: Decimal
    computed_at_utc: str

    def __post_init__(self):
        if (type(self.occurrence_ref) is not VersionedRef or type(self.character_at) is not Decimal
                or not self.character_at.is_finite()):
            raise TypeError("offline computation must bind its actual finite clock result")
        _utc(self.computed_at_utc)


def scheduled_offline_ticks_v1(recipe, *, start_utc, until_utc):
    """One bounded page of expected identities, independent of stored results."""
    if type(recipe) is not OfflineTickRecipeV1:
        raise TypeError("exact registered offline recipe required")
    start, end = _utc(start_utc), _utc(until_utc)
    end = min(end, start + timedelta(hours=24))
    cadence = timedelta(seconds=recipe.cadence_seconds)
    cursor = start
    if recipe.cadence_origin_utc is not None:
        origin = _utc(recipe.cadence_origin_utc)
        offset = start - origin
        elapsed_us = (offset.days * 86400 + offset.seconds) * 1_000_000 + offset.microseconds
        cursor = origin + cadence * max(0, -(-elapsed_us // (recipe.cadence_seconds * 1_000_000)))
    result = []
    while cursor < end and len(result) < recipe.max_ticks_per_slice:
        result.append(_stamp(cursor))
        cursor += cadence
    return tuple(result)


@dataclass(frozen=True, slots=True)
class OfflineTickReadSetV1:
    interval: OfflineSimulationSliceCandidate
    recipe: OfflineTickRecipeV1
    ticks: tuple[OfflineObservedTickV1, ...]
    coverage: str
    computations: tuple[OfflineTickComputationV1, ...] = field(default=(), kw_only=True)

    def __post_init__(self) -> None:
        if (type(self.interval) is not OfflineSimulationSliceCandidate
                or type(self.recipe) is not OfflineTickRecipeV1
                or type(self.ticks) is not tuple
                or any(type(tick) is not OfflineObservedTickV1 for tick in self.ticks)
                or self.coverage not in {"full", "partial", "none"}):
            raise TypeError("typed offline interval, recipe and ticks required")
        times = tuple(_utc(tick.scheduled_at_utc) for tick in self.ticks)
        if times != tuple(sorted(set(times))):
            raise ValueError("observed ticks must be ordered and unique")
        refs = tuple(tick.occurrence_ref for tick in self.ticks)
        if len(set(refs)) != len(refs):
            raise ValueError("observed occurrence refs must be unique")
        computation_refs = tuple(item.occurrence_ref for item in self.computations)
        if (type(self.computations) is not tuple
                or any(type(item) is not OfflineTickComputationV1 for item in self.computations)
                or len(set(computation_refs)) != len(computation_refs)
                or set(computation_refs) - set(refs)
                or self.recipe.cadence_origin_utc is not None and set(computation_refs) != set(refs)):
            raise ValueError("registered offline ticks need an exact one-to-one actual computation join")
        for tick in self.ticks:
            source = AtomKey.from_token(tick.source_ref.ref)
            if (source.type_name != "memory.source" or source.owner.kind != "event"
                    or (source.owner.bot, source.owner.persona) != self.interval.namespace.as_tuple
                    or tick.access_ref.ref != access_key(
                        *self.interval.namespace.as_tuple, source.owner.subject).token):
                raise ValueError("tick must bind same-namespace D06 source and access")


@dataclass(frozen=True, slots=True)
class OfflineSimulatedOccurrenceV1:
    occurrence_id: str
    scheduled_at_utc: str
    character_at: Decimal
    computed_at_utc: str
    recipe_ref: VersionedRef
    schedule_ref: VersionedRef
    occurrence_ref: VersionedRef
    source_ref: VersionedRef
    access_ref: VersionedRef
    world_kind: str = "role_simulation"
    actuality: str = "computed_at_recovery"


@dataclass(frozen=True, slots=True)
class OfflineTickAdvanceCandidateV1:
    status: str
    reason: str | None
    outputs: tuple[OfflineSimulatedOccurrenceV1, ...]
    processed_from_utc: str
    processed_until_utc: str
    unprocessed_from_utc: str
    unprocessed_until_utc: str
    checkpoint_ref: str
    source_versions: tuple[VersionedRef, ...]
    restore_anchor: RestoreAnchor


def advance_observed_offline_ticks_v1(
    read: OfflineTickReadSetV1, *, trusted_now_utc: str,
    read_verifier: Callable[[OfflineTickReadSetV1], bool] | None,
) -> OfflineTickAdvanceCandidateV1:
    """Advance a contiguous prefix of real occurrence receipts, at most 32.

    A missing tick, unknown result or non-simulation boundary stops the prefix.
    Outputs are source-backed *simulation candidates*, never real artifacts,
    tool completions, past thoughts or platform messages. W01 rechecks and
    atomically adopts the cursor/interval union before any D06 experience use.
    """
    if type(read) is not OfflineTickReadSetV1:
        raise TypeError("typed offline tick read required")
    now = _utc(trusted_now_utc)
    interval = read.interval
    if (interval.status != "candidate" or interval.start_utc is None
            or interval.end_utc is None or interval.character_start is None
            or interval.character_end is None):
        raise ValueError("a qualified offline interval candidate is required")
    start, end = _utc(interval.start_utc), _utc(interval.end_utc)
    if end > now or end <= start or end - start > timedelta(hours=24):
        raise ValueError("offline interval exceeds trusted bounded time")
    if read.recipe.schedule_ref not in interval.source_versions or VersionedRef(
        read.recipe.recipe_id, read.recipe.version) not in interval.source_versions:
        raise ValueError("recipe and schedule versions are absent from interval")
    if any(not start <= _utc(tick.scheduled_at_utc) < end for tick in read.ticks):
        raise ValueError("observed tick lies outside frozen interval")
    if any(ref not in interval.source_versions for tick in read.ticks
           for ref in (tick.occurrence_ref, tick.source_ref, tick.access_ref)):
        raise ValueError("tick source closure is absent from interval")

    def stop(reason: str, cursor: datetime,
             outputs: tuple[OfflineSimulatedOccurrenceV1, ...] = ()) -> OfflineTickAdvanceCandidateV1:
        return OfflineTickAdvanceCandidateV1(
            "candidate" if outputs else "deferred", reason, outputs,
            _stamp(start), _stamp(cursor), _stamp(cursor),
            interval.unprocessed_until_utc,
            interval.checkpoint_ref, interval.source_versions,
            interval.restore_anchor,
        )

    if read.coverage != "full" or read_verifier is None:
        return stop("current_read_unavailable", start)
    try:
        verified = read_verifier(read) is True
    except Exception:
        verified = False
    if not verified:
        return stop("current_read_unverified", start)

    cadence = timedelta(seconds=read.recipe.cadence_seconds)
    cursor = start
    if read.recipe.cadence_origin_utc is not None:
        origin = _utc(read.recipe.cadence_origin_utc)
        offset = start - origin
        elapsed_us = (offset.days * 86400 + offset.seconds) * 1_000_000 + offset.microseconds
        cadence_us = read.recipe.cadence_seconds * 1_000_000
        cursor = origin + cadence * max(0, -(-elapsed_us // cadence_us))
        if any((_utc(tick.scheduled_at_utc) - origin) % cadence != timedelta(0)
               or _utc(tick.scheduled_at_utc) < origin for tick in read.ticks):
            raise ValueError("observed tick is outside its registered cadence grid")
        if cursor >= end:
            return stop("no_scheduled_tick", start)
    ticks = {_utc(tick.scheduled_at_utc): tick for tick in read.ticks}
    computations = {item.occurrence_ref: item for item in read.computations}
    outputs: list[OfflineSimulatedOccurrenceV1] = []
    while cursor < end and len(outputs) < read.recipe.max_ticks_per_slice:
        tick = ticks.get(cursor)
        if tick is None:
            return stop("missing_tick", cursor if outputs else start, tuple(outputs))
        if tick.kind != "role_simulation" or tick.result != "observed":
            return stop("external_or_unknown_boundary", cursor, tuple(outputs))
        identity = canonical_digest({
            "recipe": read.recipe.recipe_id, "recipe_version": read.recipe.version,
            "schedule": read.recipe.schedule_ref,
            "occurrence": tick.occurrence_ref,
        })
        computation = computations.get(tick.occurrence_ref)
        if computation is not None and not cursor <= _utc(computation.computed_at_utc) <= now:
            raise ValueError("offline actual computation time is outside its original due/current observation")
        outputs.append(OfflineSimulatedOccurrenceV1(
            "offline-sim:" + identity, _stamp(cursor),
            computation.character_at if computation is not None else interval.character_start + (
                interval.character_end - interval.character_start
            ) * _decimal_seconds(cursor - start) / _decimal_seconds(end - start),
            computation.computed_at_utc if computation is not None else _stamp(now), VersionedRef(read.recipe.recipe_id, read.recipe.version),
            read.recipe.schedule_ref, tick.occurrence_ref,
            tick.source_ref, tick.access_ref,
        ))
        cursor = min(cursor + cadence, end)
    return stop("slice_complete" if cursor == end else "tick_budget", cursor,
                tuple(outputs))


__all__ = [
    "OfflineIntervalReadSet", "OfflineSimulationSliceCandidate",
    "plan_offline_simulation_slice", "OfflineTickRecipeV1",
    "offline_tick_recipe_to_wire_v1", "decode_offline_tick_recipe_v1",
    "OfflineObservedTickV1", "OfflineTickReadSetV1",
    "OfflineTickComputationV1", "scheduled_offline_ticks_v1",
    "OfflineSimulatedOccurrenceV1", "OfflineTickAdvanceCandidateV1",
    "advance_observed_offline_ticks_v1",
]
