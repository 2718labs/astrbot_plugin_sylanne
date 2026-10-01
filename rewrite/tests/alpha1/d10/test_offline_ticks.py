"""S09 tick-only simulation stops at gaps and never invents external results."""

from dataclasses import replace
from decimal import Decimal

import pytest

from sylanne3.domains.d10 import (
    OfflineObservedTickV1, OfflineTickReadSetV1, OfflineTickRecipeV1,
    advance_observed_offline_ticks_v1, plan_offline_simulation_slice,
)
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.clock import CharacterClockMapping
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import NamespaceId, VersionedRef
from sylanne3.domains.d10 import OfflineIntervalReadSet


def _tick(hour: int, *, kind="role_simulation", result="observed"):
    name = f"tick:{hour}"
    return OfflineObservedTickV1(
        f"2026-09-21T{hour:02d}:00:00Z", VersionedRef(f"occurrence:{name}", 1),
        VersionedRef(source_key("bot", "persona", name).token, 2),
        VersionedRef(access_key("bot", "persona", name).token, 3),
        kind, result,
    )


def _read(ticks=None, *, max_ticks=8,
          requested_until_utc="2026-09-22T00:00:00Z"):
    namespace = NamespaceId("bot", "persona")
    ticks = (_tick(0), _tick(8), _tick(16)) if ticks is None else ticks
    recipe = OfflineTickRecipeV1(
        "recipe:one", 2, VersionedRef("schedule:one", 4), 8 * 3600,
        max_ticks,
    )
    versions = (
        VersionedRef("recipe:one", 2), recipe.schedule_ref,
        VersionedRef("checkpoint:one", 3),
        *(ref for tick in ticks for ref in (
            tick.occurrence_ref, tick.source_ref, tick.access_ref)),
    )
    mapping = CharacterClockMapping(
        "clock:one", 1, "2026-09-20T00:00:00Z", Decimal("0"),
        Decimal("2"), "2026-09-20T00:00:00Z", "2026-09-25T00:00:00Z",
        "policy:one", "d11",
    )
    anchor = RestoreAnchor(
        "authority", namespace_ref(namespace), 3, "deletion", 4,
        "deletion-head", "execution", 5, "execution-head", 2, "proof",
    )
    source = OfflineIntervalReadSet(
        namespace, mapping, "checkpoint:one", "2026-09-21T00:00:00Z",
        versions, anchor, "full",
    )
    interval = plan_offline_simulation_slice(
        source, requested_until_utc=requested_until_utc,
        trusted_now_utc=requested_until_utc, boundary_utc=None,
        read_verifier=lambda observed: observed is source,
    )
    return OfflineTickReadSetV1(interval, recipe, ticks, "full")


def _advance(read, *, trusted_now_utc="2026-09-22T00:00:00Z"):
    return advance_observed_offline_ticks_v1(
        read, trusted_now_utc=trusted_now_utc,
        read_verifier=lambda observed: observed is read,
    )


def test_three_observed_schedule_points_make_only_source_backed_simulation_candidates():
    read = _read()
    result = _advance(read)
    assert result.status == "candidate"
    assert result.reason == "slice_complete"
    assert result.processed_until_utc == "2026-09-22T00:00:00Z"
    assert len(result.outputs) == 3
    assert tuple(item.character_at for item in result.outputs) == (
        Decimal("172800"), Decimal("230400"), Decimal("288000"),
    )
    for output, tick in zip(result.outputs, read.ticks):
        assert output.world_kind == "role_simulation"
        assert output.actuality == "computed_at_recovery"
        assert output.source_ref == tick.source_ref
        assert output.occurrence_ref == tick.occurrence_ref
        assert not hasattr(output, "artifact_ref")
        assert not hasattr(output, "tool_receipt_ref")
    assert _advance(read).outputs == result.outputs


def test_missing_middle_tick_stops_before_later_tick_without_gap_fill():
    read = _read((_tick(0), _tick(16)))
    result = _advance(read)
    assert result.reason == "missing_tick"
    assert len(result.outputs) == 1
    assert result.processed_until_utc == result.unprocessed_from_utc == "2026-09-21T08:00:00Z"
    assert result.unprocessed_until_utc == "2026-09-22T00:00:00Z"


def test_one_day_slice_preserves_later_requested_days_as_unprocessed():
    read = _read(requested_until_utc="2026-09-23T12:00:00Z")
    result = _advance(read, trusted_now_utc="2026-09-23T12:00:00Z")
    assert result.processed_until_utc == "2026-09-22T00:00:00Z"
    assert result.unprocessed_from_utc == "2026-09-22T00:00:00Z"
    assert result.unprocessed_until_utc == "2026-09-23T12:00:00Z"


@pytest.mark.parametrize("tick", [
    _tick(8, kind="external_tool"),
    _tick(8, kind="user_message"),
    _tick(8, result="unknown"),
])
def test_external_or_unknown_tick_is_a_boundary_not_a_completed_result(tick):
    read = _read((_tick(0), tick, _tick(16)))
    result = _advance(read)
    assert result.reason == "external_or_unknown_boundary"
    assert len(result.outputs) == 1
    assert result.unprocessed_from_utc == "2026-09-21T08:00:00Z"


def test_tick_budget_and_unverified_source_keep_replay_bounded():
    read = _read(max_ticks=2)
    result = _advance(read)
    assert result.reason == "tick_budget"
    assert len(result.outputs) == 2
    assert result.unprocessed_from_utc == "2026-09-21T16:00:00Z"
    assert advance_observed_offline_ticks_v1(
        read, trusted_now_utc="2026-09-22T00:00:00Z", read_verifier=None,
    ).status == "deferred"
    assert advance_observed_offline_ticks_v1(
        replace(read, coverage="partial"), trusted_now_utc="2026-09-22T00:00:00Z",
        read_verifier=lambda _: True,
    ).outputs == ()
    with pytest.raises(ValueError, match="source closure"):
        _advance(replace(read, interval=replace(
            read.interval, source_versions=(VersionedRef("recipe:one", 2),
                                            VersionedRef("schedule:one", 4)),
        )))


def test_tick_source_must_be_a_same_namespace_d06_access_pair():
    read = _read()
    wrong = replace(read.ticks[0], access_ref=VersionedRef(
        access_key("other", "persona", "tick:0").token, 3,
    ))
    with pytest.raises(ValueError, match="same-namespace D06"):
        replace(read, ticks=(wrong, *read.ticks[1:]))
