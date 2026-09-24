"""Native-verified initial box feeding a package-bound fixed-block trajectory.

The interval box is an external premise. ABI2 proves the radius around the
supplied nominal state; D11 must separately establish the box's source.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, fields, replace
import math
import struct
from typing import Sequence

from .abi2 import ABI2ResultError
from .fixed_block_transcript import (
    FixedBlockContinuation,
    FixedBlockStep,
    FixedBlockTrajectoryMathTranscript,
    _digest,
    run_fixed_block_trajectory_math,
)
from .loader import ABI2NativeLibrary, NativeLoadBinding
from .linear_readout import (
    FixedBlockLinearReadoutMathTranscript,
    run_fixed_block_linear_readout_math,
)


@dataclass(frozen=True, slots=True)
class FixedBlockBoxTrajectoryMathTranscript:
    """Complete box-to-trajectory numerical chain, without source authority."""

    lower: tuple[float, ...]
    upper: tuple[float, ...]
    verified_initial_error: float
    trajectory: FixedBlockTrajectoryMathTranscript
    production_binding: NativeLoadBinding
    initial_box_sha256: str
    transcript_sha256: str


@dataclass(frozen=True, slots=True)
class FixedBlockBoxLinearReadoutMathTranscript:
    """Rechecked initial box, native trajectory, and conditional linear readout."""

    box_trajectory: FixedBlockBoxTrajectoryMathTranscript
    readout: FixedBlockLinearReadoutMathTranscript
    transcript_sha256: str


def _native_initial_radius(
    handle: ABI2NativeLibrary,
    nominal: tuple[float, ...],
    lo: tuple[float, ...],
    hi: tuple[float, ...],
) -> float:
    n = len(nominal)
    if n == 0 or n > handle.capabilities.max_dimension or len(lo) != n or len(hi) != n:
        raise ValueError("initial-box dimensions must match the native state")
    if any(not math.isfinite(value) for value in nominal + lo + hi):
        raise ValueError("initial-box values must be finite")
    nominal_buffer = (ctypes.c_double * n)(*nominal)
    lower_buffer = (ctypes.c_double * n)(*lo)
    upper_buffer = (ctypes.c_double * n)(*hi)
    output = (ctypes.c_double * 1)()
    status = handle._initial_box(n, nominal_buffer, lower_buffer, upper_buffer, output, 1)
    if status != 0:
        raise ABI2ResultError(f"native initial-box verification failed: {status}")
    radius = float(output[0])
    if not math.isfinite(radius) or radius < 0:
        raise ABI2ResultError("native initial-box radius is invalid")
    return radius


def _box_digest(
    nominal: tuple[float, ...], lo: tuple[float, ...], hi: tuple[float, ...],
    radius: float, binding: NativeLoadBinding,
) -> str:
    return _digest({
        "schema": "abi2.initial-box-math.v1",
        "nominal": nominal,
        "lower": lo,
        "upper": hi,
        "verified_error": radius,
        "production_binding": {field.name: getattr(binding, field.name) for field in fields(binding)},
    })


def _chain_digest(box_sha256: str, trajectory_sha256: str,
                  binding: NativeLoadBinding) -> str:
    return _digest({
        "schema": "abi2.box-trajectory-math.v1",
        "initial_box_sha256": box_sha256,
        "trajectory_sha256": trajectory_sha256,
        "production_binding": {field.name: getattr(binding, field.name) for field in fields(binding)},
    })


def run_fixed_block_box_trajectory_math(
    handle: ABI2NativeLibrary,
    first: FixedBlockStep,
    continuations: Sequence[FixedBlockContinuation],
    *,
    lower: tuple[float, ...],
    upper: tuple[float, ...],
) -> FixedBlockBoxTrajectoryMathTranscript:
    """Compute an initial radius in native interval arithmetic, then advance.

    ``first.previous_error`` must be zero as a placeholder; the native radius
    replaces it. The caller must prove that the actual initial state lies in
    the supplied box before using this conditional certificate downstream.
    """
    if not isinstance(handle, ABI2NativeLibrary) or handle.production_binding is None:
        raise ABI2ResultError("initial box requires a package-bound ABI2 handle")
    if not handle.capabilities.supports_initial_box_math_v1 or handle._initial_box is None:
        raise ABI2ResultError("native initial-box math capability is absent")
    if not isinstance(first, FixedBlockStep):
        raise TypeError("first must be an immutable FixedBlockStep")
    if first.previous_error != 0.0:
        raise ValueError("initial-box trajectory must derive, not supply, previous error")
    try:
        lo = tuple(float(value) for value in lower)
        hi = tuple(float(value) for value in upper)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("initial-box endpoints must be binary64 values") from exc
    n = len(first.previous)
    if len(lo) != n or len(hi) != n or n > handle.capabilities.max_dimension:
        raise ValueError("initial-box dimensions must match the native state")
    if any(not math.isfinite(value) for value in lo + hi):
        raise ValueError("initial-box endpoints must be finite")
    radius = _native_initial_radius(handle, first.previous, lo, hi)

    binding = handle.production_binding
    trajectory = run_fixed_block_trajectory_math(
        handle, replace(first, previous_error=radius), continuations,
    )
    initial_box_sha256 = _box_digest(first.previous, lo, hi, radius, binding)
    transcript_sha256 = _chain_digest(initial_box_sha256, trajectory.transcript_sha256, binding)
    return FixedBlockBoxTrajectoryMathTranscript(
        lo, hi, radius, trajectory, binding, initial_box_sha256, transcript_sha256,
    )


def run_fixed_block_box_linear_readout_math(
    handle: ABI2NativeLibrary,
    boxed: FixedBlockBoxTrajectoryMathTranscript,
    coefficients: tuple[float, ...],
) -> FixedBlockBoxLinearReadoutMathTranscript:
    """Recheck both native premises before issuing a conditional readout."""
    if not isinstance(handle, ABI2NativeLibrary) or handle.production_binding is None:
        raise ABI2ResultError("initial-box readout requires a package-bound ABI2 handle")
    if not handle.capabilities.supports_initial_box_math_v1 or handle._initial_box is None:
        raise ABI2ResultError("native initial-box math capability is absent")
    if not isinstance(boxed, FixedBlockBoxTrajectoryMathTranscript):
        raise TypeError("initial-box readout requires a box trajectory transcript")
    binding = handle.production_binding
    trajectory = boxed.trajectory
    if boxed.production_binding != binding or not trajectory.steps:
        raise ABI2ResultError("initial-box readout belongs to a different package")
    nominal = trajectory.steps[0].input.previous
    radius = _native_initial_radius(handle, nominal, boxed.lower, boxed.upper)
    if (struct.pack("!d", radius) != struct.pack("!d", boxed.verified_initial_error)
            or struct.pack("!d", radius) != struct.pack("!d", trajectory.initial_error)
            or boxed.initial_box_sha256 != _box_digest(
                nominal, boxed.lower, boxed.upper, radius, binding,
            )
            or boxed.transcript_sha256 != _chain_digest(
                boxed.initial_box_sha256, trajectory.transcript_sha256, binding,
            )):
        raise ABI2ResultError("initial-box native radius or chain digest is inconsistent")
    readout = run_fixed_block_linear_readout_math(handle, trajectory, coefficients)
    digest = _digest({
        "schema": "abi2.box-linear-readout-math.v1",
        "box_trajectory_sha256": boxed.transcript_sha256,
        "readout_sha256": readout.transcript_sha256,
        "production_binding": {field.name: getattr(binding, field.name) for field in fields(binding)},
    })
    return FixedBlockBoxLinearReadoutMathTranscript(boxed, readout, digest)
