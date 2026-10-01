"""D10 may select a bounded simulation slice, never backfill an experience."""

from dataclasses import replace
from decimal import Decimal

import pytest

from sylanne3.domains.d10 import OfflineIntervalReadSet, plan_offline_simulation_slice
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.runtime.clock import CharacterClockMapping
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import NamespaceId, VersionedRef


NS = NamespaceId("bot", "persona")


def _read_set():
    mapping = CharacterClockMapping(
        "clock:one", 1, "2026-09-20T00:00:00Z", Decimal("0"), Decimal("2"),
        "2026-09-20T00:00:00Z", "2026-09-25T00:00:00Z", "policy:one", "d11",
    )
    anchor = RestoreAnchor(
        "authority", namespace_ref(NS), 3, "deletion", 4, "deletion-head",
        "execution", 5, "execution-head", 2, "proof",
    )
    return OfflineIntervalReadSet(
        NS, mapping, "checkpoint:one", "2026-09-21T00:00:00Z",
        (VersionedRef("recipe:one", 2), VersionedRef("checkpoint:one", 3),
         VersionedRef("access:one", 4)), anchor, "full",
    )


def _plan(read_set, **overrides):
    args = dict(requested_until_utc="2026-09-23T12:00:00Z",
                trusted_now_utc="2026-09-23T12:00:00Z", boundary_utc=None,
                read_verifier=lambda current: current is read_set)
    args.update(overrides)
    return plan_offline_simulation_slice(read_set, **args)


def test_selects_one_day_then_stops_at_decision_boundary():
    current = _read_set()
    first = _plan(current)
    assert (first.status, first.start_utc, first.end_utc) == (
        "candidate", "2026-09-21T00:00:00Z", "2026-09-22T00:00:00Z")
    assert (first.unprocessed_from_utc, first.unprocessed_until_utc) == (
        "2026-09-22T00:00:00Z", "2026-09-23T12:00:00Z")
    assert (first.character_start, first.character_end) == (
        Decimal("172800"), Decimal("345600"))
    assert not hasattr(first, "artifact_ref")

    bounded = _plan(current, boundary_utc="2026-09-21T03:00:00Z")
    assert bounded.end_utc == "2026-09-21T03:00:00Z"
    assert bounded.character_end == Decimal("194400")
    assert _plan(current, boundary_utc=current.checkpoint_end_utc).reason == "decision_boundary"


def test_unverified_or_partial_reads_never_select_a_slice():
    current = _read_set()
    assert _plan(current, read_verifier=None).status == "deferred"
    assert _plan(current, read_verifier=lambda _: False).reason == "current_read_unverified"
    partial = replace(current, coverage="partial")
    assert _plan(partial, read_verifier=lambda _: True).reason == "current_read_unavailable"
    assert _plan(current, read_verifier=lambda _: 1).reason == "current_read_unverified"


def test_trusted_time_mapping_and_restore_namespace_are_bounded():
    current = _read_set()
    with pytest.raises(ValueError, match="trusted current time"):
        _plan(current, trusted_now_utc="2026-09-22T00:00:00Z")
    with pytest.raises(ValueError, match="restore anchor namespace"):
        _plan(replace(current, restore_anchor=replace(current.restore_anchor,
                      namespace="other")), read_verifier=lambda _: True)
    expired = replace(current, checkpoint_end_utc="2026-09-25T00:00:00Z")
    assert _plan(expired, trusted_now_utc="2026-09-26T00:00:00Z",
                 requested_until_utc="2026-09-26T00:00:00Z",
                 read_verifier=lambda _: True).reason == "mapping_outside_checkpoint"
