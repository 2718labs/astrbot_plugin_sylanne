"""A source cannot silently borrow another source's 24D D04 state."""

from __future__ import annotations

from dataclasses import replace

import pytest

from sylanne3.native_runtime.d04_block_instances import (
    D04BlockCheckpoint,
    D04BlockIdentity,
    D04BlockInstance,
    D04DriveSegment,
    D04SourceHead,
    assemble_d04_engineering_blocks,
)


def _instance(source: str, *, checkpoint: D04BlockCheckpoint | None = None) -> D04BlockInstance:
    identity = D04BlockIdentity("role:1", "object:friend", "meaning:welcome", source)
    return D04BlockInstance(
        identity, "graph:7", "access:3", "clock:5", checkpoint,
        (D04DriveSegment(f"drive:{source}", 10.0, 10.25, (0.25,) * 24),),
    )


def _checkpoint(value: float) -> D04BlockCheckpoint:
    return D04BlockCheckpoint("checkpoint:4", 10.0, (value,) * 24, 0.01)


def _assemble(instances: tuple[D04BlockInstance, ...], heads: dict[D04BlockIdentity, D04SourceHead]):
    return assemble_d04_engineering_blocks(
        instances, heads, role_clock_mapping_ref="clock:5", role_start=10.0,
        role_end=10.25, iteration_guesses={item.identity: item.checkpoint.latent
                                           for item in instances if item.checkpoint is not None},
        max_iterations=16, tolerance=1e-8,
    )


def test_distinct_sources_keep_distinct_latent_drive_and_versions() -> None:
    first, second = _instance("source:a", checkpoint=_checkpoint(1.0)), _instance(
        "source:b", checkpoint=_checkpoint(2.0),
    )
    heads = {item.identity: D04SourceHead("graph:7", "access:3", True)
             for item in (first, second)}
    assembly = _assemble((first, second), heads)
    assert assembly.schema == "d04.block-assembly.engineering-candidate.v1"
    assert assembly.held == ()
    assert len(assembly.prepared) == 2
    assert [item.instance.identity.source_ref for item in assembly.prepared] == [
        "source:a", "source:b",
    ]
    assert [item.math_input.previous[0] for item in assembly.prepared] == [1.0, 2.0]
    assert all(item.math_input.h == 0.25 and len(item.math_input.previous) == 24
               for item in assembly.prepared)
    assert all(item.instance.role_clock_mapping_ref == "clock:5" for item in assembly.prepared)


def test_revoked_source_only_holds_its_own_block() -> None:
    first, second = _instance("source:a", checkpoint=_checkpoint(1.0)), _instance(
        "source:b", checkpoint=_checkpoint(2.0),
    )
    assembly = _assemble(
        (first, second),
        {first.identity: D04SourceHead("graph:7", "access:4", False),
         second.identity: D04SourceHead("graph:7", "access:3", True)},
    )
    assert [(item.identity.source_ref, item.reason) for item in assembly.held] == [
        ("source:a", "source_unqualified"),
    ]
    assert [item.instance.identity.source_ref for item in assembly.prepared] == ["source:b"]
    assert assembly.prepared[0].math_input.previous == (2.0,) * 24


def test_missing_initial_condition_and_exact_drive_interval_remain_held() -> None:
    unknown = _instance("source:unknown")
    interrupted = _instance("source:interrupted", checkpoint=_checkpoint(1.0))
    interrupted = D04BlockInstance(
        interrupted.identity, interrupted.graph_source_version, interrupted.access_version,
        interrupted.role_clock_mapping_ref, interrupted.checkpoint,
        (D04DriveSegment("drive:old", 10.0, 10.125, (0.25,) * 24),),
    )
    heads = {item.identity: D04SourceHead("graph:7", "access:3", True)
             for item in (unknown, interrupted)}
    assembly = _assemble((unknown, interrupted), heads)
    assert assembly.prepared == ()
    assert [(item.identity.source_ref, item.reason) for item in assembly.held] == [
        ("source:unknown", "initial_condition_unknown"),
        ("source:interrupted", "drive_interval_unavailable"),
    ]


def test_ambiguous_identity_and_invalid_latent_are_not_assembled() -> None:
    first = _instance("source:a", checkpoint=_checkpoint(1.0))
    head = {first.identity: D04SourceHead("graph:7", "access:3", True)}
    with pytest.raises(ValueError, match="duplicate D04 block identity"):
        _assemble((first, first), head)
    invalid = _instance("source:invalid", checkpoint=_checkpoint(5.0))
    with pytest.raises(ValueError, match="latent vector"):
        _assemble((invalid,), {invalid.identity: D04SourceHead("graph:7", "access:3", True)})


@pytest.mark.parametrize("extra", (
    D04DriveSegment("drive:wide", 9.0, 11.0, (0.5,) * 24),
    D04DriveSegment("drive:source:a", 10.25, 10.5, (0.5,) * 24),
    D04DriveSegment("drive:empty", 10.5, 10.5, (0.5,) * 24),
    D04DriveSegment("drive:nan-time", float("nan"), 11.0, (0.5,) * 24),
    D04DriveSegment("drive:inf-time", 10.5, float("inf"), (0.5,) * 24),
    D04DriveSegment("drive:inf-dose", 10.5, 11.0, (float("inf"),) * 24),
    D04DriveSegment("drive:short", 10.5, 11.0, (0.5,) * 23),
))
def test_invalid_other_drive_segment_cannot_hide_behind_exact_match(
    extra: D04DriveSegment,
) -> None:
    clean = _instance("source:a", checkpoint=_checkpoint(1.0))
    invalid = replace(clean, drive_segments=clean.drive_segments + (extra,))
    other = _instance("source:b", checkpoint=_checkpoint(2.0))
    heads = {item.identity: D04SourceHead("graph:7", "access:3", True)
             for item in (invalid, other)}
    assembly = _assemble((invalid, other), heads)
    assert [(item.identity.source_ref, item.reason) for item in assembly.held] == [
        ("source:a", "drive_schedule_invalid"),
    ]
    assert [item.instance.identity.source_ref for item in assembly.prepared] == ["source:b"]


def test_adjacent_distinct_drive_segments_are_valid() -> None:
    first = _instance("source:a", checkpoint=_checkpoint(1.0))
    first = replace(first, drive_segments=first.drive_segments + (
        D04DriveSegment("drive:next", 10.25, 10.5, (0.5,) * 24),
    ))
    assembly = _assemble((first,), {first.identity: D04SourceHead("graph:7", "access:3", True)})
    assert len(assembly.prepared) == 1
    assert assembly.held == ()
