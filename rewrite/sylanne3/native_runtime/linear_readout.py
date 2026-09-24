"""Conditional linear readout enclosure for a package-bound ABI2 trajectory.

This is mathematical error propagation only. It cannot authenticate the
initial error, source graph, semantic readout, or D04 product admission.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from fractions import Fraction
import math

from .abi2 import ABI2ResultError, ABI2_FIXED_BLOCK_INTERVAL_V1
from .fixed_block_transcript import (
    FixedBlockContinuation,
    FixedBlockTrajectoryMathTranscript,
    _digest,
    _same_fixed_model,
    _same_float_bits,
)
from .loader import ABI2NativeLibrary, NativeLoadBinding


MAX_READOUT_DIMENSION = 256


@dataclass(frozen=True, slots=True)
class FixedBlockLinearReadoutMathTranscript:
    """Finite outward enclosure of c·z from a conditional Euclidean state ball."""

    coefficients: tuple[float, ...]
    lower: float
    upper: float
    source_trajectory_sha256: str
    production_binding: NativeLoadBinding
    transcript_sha256: str


def _outward_binary64(value: Fraction, *, lower: bool) -> float:
    try:
        rounded = float(value)
    except OverflowError as exc:
        raise ABI2ResultError("linear readout interval exceeds finite binary64") from exc
    if not math.isfinite(rounded):
        raise ABI2ResultError("linear readout interval exceeds finite binary64")
    exact_rounded = Fraction.from_float(rounded)
    if lower and exact_rounded > value:
        rounded = math.nextafter(rounded, -math.inf)
    elif not lower and exact_rounded < value:
        rounded = math.nextafter(rounded, math.inf)
    if not math.isfinite(rounded):
        raise ABI2ResultError("linear readout interval exceeds finite binary64")
    return rounded


def _require_consistent_trajectory(
    trajectory: FixedBlockTrajectoryMathTranscript, binding: NativeLoadBinding,
) -> None:
    steps = trajectory.steps
    if not steps or trajectory.production_binding != binding:
        raise ABI2ResultError("linear readout trajectory belongs to a different native package")
    if (trajectory.initial_error != steps[0].input.previous_error
            or trajectory.final_error != steps[-1].bounds.trajectory_error):
        raise ABI2ResultError("linear readout trajectory error is inconsistent")
    for index, step in enumerate(steps):
        if (step.bounds.status != 0
                or step.bounds.certificate_flags != ABI2_FIXED_BLOCK_INTERVAL_V1
                or not math.isfinite(step.bounds.trajectory_error)
                or step.bounds.trajectory_error < 0
                or step.production_binding != binding
                or step.input_sha256 != step.input.digest()
                or step.output_sha256 != _digest(step.output)
                or step.transcript_sha256 != _digest({
                    "schema": "abi2.fixed-block-math-transcript.v1",
                    "input_sha256": step.input_sha256,
                    "output_sha256": step.output_sha256,
                    "manifest_sha256": binding.manifest_sha256,
                    "native_sha256": binding.native_sha256,
                    "bounds": {field.name: getattr(step.bounds, field.name)
                               for field in fields(step.bounds)},
                })):
            raise ABI2ResultError("linear readout step transcript digest is inconsistent")
        if index and (
            not _same_float_bits(step.input.previous, steps[index - 1].output)
            or step.input.previous_error != steps[index - 1].bounds.trajectory_error
            or not _same_fixed_model(steps[0].input, FixedBlockContinuation.from_step(step.input))
        ):
            raise ABI2ResultError("linear readout trajectory chain is inconsistent")
    if trajectory.transcript_sha256 != _digest({
        "schema": "abi2.fixed-block-trajectory-math-transcript.v1",
        "initial_error": trajectory.initial_error,
        "final_error": trajectory.final_error,
        "production_binding": {field.name: getattr(binding, field.name) for field in fields(binding)},
        "steps": [step.transcript_sha256 for step in steps],
    }):
        raise ABI2ResultError("linear readout trajectory digest is inconsistent")


def run_fixed_block_linear_readout_math(
    handle: ABI2NativeLibrary,
    trajectory: FixedBlockTrajectoryMathTranscript,
    coefficients: tuple[float, ...],
) -> FixedBlockLinearReadoutMathTranscript:
    """Enclose the final linear readout using exact binary64 rational inputs.

    For ||z-y||₂ <= e, each coordinate error is at most e. Therefore
    c·z lies in c·y ± e||c||₁. Fraction computes both endpoints exactly from
    the recorded binary64 values; the returned endpoints round outward once.
    """
    if not isinstance(handle, ABI2NativeLibrary) or handle.production_binding is None:
        raise ABI2ResultError("linear readout requires a package-bound ABI2 handle")
    if not handle.capabilities.supports_fixed_block_interval_math_v1:
        raise ABI2ResultError("native fixed-block interval math capability is absent")
    if not isinstance(trajectory, FixedBlockTrajectoryMathTranscript):
        raise TypeError("linear readout requires a fixed-block trajectory transcript")
    binding = handle.production_binding
    _require_consistent_trajectory(trajectory, binding)
    final = trajectory.steps[-1]
    try:
        weights = tuple(float(value) for value in coefficients)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("linear readout coefficients must be finite binary64 values") from exc
    if not 1 <= len(weights) <= MAX_READOUT_DIMENSION or len(weights) != len(final.output):
        raise ValueError("linear readout dimension is unsupported or mismatched")
    if not all(math.isfinite(value) for value in weights):
        raise ValueError("linear readout coefficients must be finite binary64 values")
    if not math.isfinite(trajectory.final_error) or trajectory.final_error < 0:
        raise ABI2ResultError("linear readout requires a finite nonnegative state error")

    exact_point = sum(
        (Fraction.from_float(weight) * Fraction.from_float(value)
         for weight, value in zip(weights, final.output)), Fraction()
    )
    exact_radius = Fraction.from_float(trajectory.final_error) * sum(
        (abs(Fraction.from_float(weight)) for weight in weights), Fraction()
    )
    lower = _outward_binary64(exact_point - exact_radius, lower=True)
    upper = _outward_binary64(exact_point + exact_radius, lower=False)
    transcript_sha256 = _digest({
        "schema": "abi2.fixed-block-linear-readout-math.v1",
        "source_trajectory_sha256": trajectory.transcript_sha256,
        "coefficients": weights,
        "lower": lower,
        "upper": upper,
        "production_binding": {field.name: getattr(binding, field.name) for field in fields(binding)},
    })
    return FixedBlockLinearReadoutMathTranscript(
        weights, lower, upper, trajectory.transcript_sha256, binding, transcript_sha256,
    )
