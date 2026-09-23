"""Per-source instances of the unadmitted D04 engineering operator.

The caller supplies an observed graph/source snapshot and role clock mapping.
This module only assembles conditional math inputs; it cannot authenticate the
snapshot, certify numerics, or authorize an emotion state write.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Mapping

from .d04_engineering_scheme import DIMENSION, D04EngineeringCandidate, build_d04_engineering_candidate
from .fixed_block_transcript import FixedBlockStep


@dataclass(frozen=True, slots=True)
class D04BlockIdentity:
    role_ref: str
    object_ref: str
    meaning_ref: str
    source_ref: str


@dataclass(frozen=True, slots=True)
class D04SourceHead:
    graph_source_version: str
    access_version: str
    usable: bool


@dataclass(frozen=True, slots=True)
class D04BlockCheckpoint:
    checkpoint_ref: str
    role_time: float
    latent: tuple[float, ...]
    inherited_error: float


@dataclass(frozen=True, slots=True)
class D04DriveSegment:
    drive_ref: str
    role_start: float
    role_end: float
    drive: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class D04BlockInstance:
    identity: D04BlockIdentity
    graph_source_version: str
    access_version: str
    role_clock_mapping_ref: str
    checkpoint: D04BlockCheckpoint | None
    drive_segments: tuple[D04DriveSegment, ...]


@dataclass(frozen=True, slots=True)
class D04PreparedBlockCandidate:
    instance: D04BlockInstance
    drive_segment: D04DriveSegment
    operator: D04EngineeringCandidate
    math_input: FixedBlockStep


@dataclass(frozen=True, slots=True)
class D04HeldBlock:
    identity: D04BlockIdentity
    reason: str


@dataclass(frozen=True, slots=True)
class D04BlockAssemblyCandidate:
    prepared: tuple[D04PreparedBlockCandidate, ...]
    held: tuple[D04HeldBlock, ...]
    schema: str = "d04.block-assembly.engineering-candidate.v1"


def _drive_schedule_valid(segments: tuple[D04DriveSegment, ...]) -> bool:
    if len({segment.drive_ref for segment in segments}) != len(segments):
        return False
    for segment in segments:
        if (not segment.drive_ref or not math.isfinite(segment.role_start)
                or not math.isfinite(segment.role_end)
                or segment.role_end <= segment.role_start
                or len(segment.drive) != DIMENSION
                or any(not math.isfinite(value) for value in segment.drive)):
            return False
    ordered = sorted(segments, key=lambda segment: segment.role_start)
    return all(left.role_end <= right.role_start
               for left, right in zip(ordered, ordered[1:]))


def assemble_d04_engineering_blocks(
    instances: tuple[D04BlockInstance, ...],
    observed_heads: Mapping[D04BlockIdentity, D04SourceHead],
    *,
    role_clock_mapping_ref: str,
    role_start: float,
    role_end: float,
    iteration_guesses: Mapping[D04BlockIdentity, tuple[float, ...]],
    max_iterations: int,
    tolerance: float,
) -> D04BlockAssemblyCandidate:
    """Prepare one exact drive interval per independent source block.

    A missing initial condition, source head, or exact interval remains held.
    Adjacent intervals are assembled separately so a dose cannot be replayed
    through a broad overlapping segment.
    """
    if not (role_clock_mapping_ref and math.isfinite(role_start)
            and math.isfinite(role_end) and role_end > role_start):
        raise ValueError("role clock mapping and positive interval are required")
    identities = [instance.identity for instance in instances]
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate D04 block identity")

    operator = build_d04_engineering_candidate()
    prepared: list[D04PreparedBlockCandidate] = []
    held: list[D04HeldBlock] = []
    for instance in instances:
        identity = instance.identity
        head = observed_heads.get(identity)
        checkpoint = instance.checkpoint
        segments = [segment for segment in instance.drive_segments
                    if segment.role_start == role_start and segment.role_end == role_end]
        reason: str | None = None
        if not _drive_schedule_valid(instance.drive_segments):
            reason = "drive_schedule_invalid"
        elif (head is None or not head.usable
                or head.graph_source_version != instance.graph_source_version
                or head.access_version != instance.access_version):
            reason = "source_unqualified"
        elif instance.role_clock_mapping_ref != role_clock_mapping_ref:
            reason = "clock_mapping_mismatch"
        elif checkpoint is None:
            reason = "initial_condition_unknown"
        elif checkpoint.role_time != role_start:
            reason = "checkpoint_time_mismatch"
        elif len(segments) != 1:
            reason = "drive_interval_unavailable"
        elif identity not in iteration_guesses:
            reason = "iteration_guess_unavailable"
        if reason is not None:
            held.append(D04HeldBlock(identity, reason))
            continue

        assert checkpoint is not None
        segment = segments[0]
        guess = iteration_guesses[identity]
        if (len(checkpoint.latent) != DIMENSION or len(segment.drive) != DIMENSION
                or len(guess) != DIMENSION or not checkpoint.checkpoint_ref
                or not segment.drive_ref):
            raise ValueError("D04 block requires complete 24D checkpoint and drive")
        operator.project_latent(checkpoint.latent)
        operator.project_latent(guess)
        step = FixedBlockStep(
            operator.k, operator.r, operator.j, operator.a, operator.alpha,
            checkpoint.latent, segment.drive, guess, role_end - role_start,
            checkpoint.inherited_error, max_iterations, tolerance,
        )
        prepared.append(D04PreparedBlockCandidate(instance, segment, operator, step))
    return D04BlockAssemblyCandidate(tuple(prepared), tuple(held))
