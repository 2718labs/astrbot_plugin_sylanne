"""Immutable transcript of one package-bound ABI2 fixed-block *math* call.

This is conditional numerical evidence only. It is not a product issuer or a
D04 adoption authorization.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, fields
import hashlib
import json
import math
import struct
from typing import Sequence

from .abi2 import (
    ABI2CSR,
    ABI2ResultError,
    ABI2StepInput,
    ABI2StepResult,
    ABI_VERSION,
    NativeReportedFixedBlockIntervalBounds,
    parse_fixed_block_interval_result,
)
from .loader import ABI2NativeLibrary, NativeLoadBinding


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class FixedBlockCSR:
    rows: int
    cols: int
    offsets: tuple[int, ...]
    indices: tuple[int, ...]
    values: tuple[float, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "offsets", tuple(self.offsets))
        object.__setattr__(self, "indices", tuple(self.indices))
        object.__setattr__(self, "values", tuple(float(value) for value in self.values))
        if type(self.rows) is not int or type(self.cols) is not int or not 0 <= self.rows <= 65_536 or not 0 <= self.cols <= 65_536:
            raise ValueError("CSR dimensions are outside ABI2 bounds")
        if len(self.offsets) != self.rows + 1 or len(self.indices) != len(self.values):
            raise ValueError("CSR buffers do not match dimensions")
        if len(self.values) > 2_000_000 or self.offsets[0] != 0 or self.offsets[-1] != len(self.values):
            raise ValueError("CSR offsets do not match values")
        if any(type(i) is not int or i < 0 or i > 0xFFFFFFFF for i in self.offsets + self.indices):
            raise ValueError("CSR index is outside ABI2 bounds")
        if any(a > b for a, b in zip(self.offsets, self.offsets[1:])):
            raise ValueError("CSR offsets are not monotone")
        if any(i >= self.cols for i in self.indices):
            raise ValueError("CSR column is outside matrix")
        if any(not math.isfinite(value) for value in self.values):
            raise ValueError("CSR values must be finite")


@dataclass(frozen=True, slots=True)
class FixedBlockStep:
    k: FixedBlockCSR
    r: FixedBlockCSR
    j: FixedBlockCSR
    a: FixedBlockCSR
    alpha: tuple[float, ...]
    previous: tuple[float, ...]
    drive: tuple[float, ...]
    iterate: tuple[float, ...]
    h: float
    previous_error: float
    max_iterations: int
    tolerance: float
    boundary_eta: float = 0.0

    def __post_init__(self) -> None:
        for name in ("alpha", "previous", "drive", "iterate"):
            object.__setattr__(self, name, tuple(float(value) for value in getattr(self, name)))
        for name in ("h", "previous_error", "tolerance", "boundary_eta"):
            object.__setattr__(self, name, float(getattr(self, name)))
        n = len(self.previous)
        if not 1 <= n <= 65_536 or any((m.rows, m.cols) != (n, n) for m in (self.k, self.r, self.j)):
            raise ValueError("fixed-block square matrices must match state dimension")
        if self.a.cols != n or len(self.alpha) != self.a.rows:
            raise ValueError("fixed-block A/alpha dimensions do not match")
        if len(self.drive) != n or len(self.iterate) != n:
            raise ValueError("fixed-block vectors do not match state dimension")
        if not all(math.isfinite(x) for x in self.alpha + self.previous + self.drive + self.iterate):
            raise ValueError("fixed-block vectors must be finite")
        if any(x < 0 for x in self.alpha):
            raise ValueError("fixed-block alpha must be nonnegative")
        if not (math.isfinite(self.h) and self.h > 0 and math.isfinite(self.tolerance) and self.tolerance > 0):
            raise ValueError("fixed-block step size and tolerance must be positive")
        if not (math.isfinite(self.previous_error) and self.previous_error >= 0):
            raise ValueError("fixed-block previous error must be nonnegative")
        if self.boundary_eta != 0.0:
            raise ValueError("complete fixed block requires zero boundary eta")
        if type(self.max_iterations) is not int or not 1 <= self.max_iterations <= 256:
            raise ValueError("fixed-block iteration count is outside ABI2 bounds")

    def digest(self) -> str:
        def matrix(m: FixedBlockCSR) -> dict[str, object]:
            return dict(rows=m.rows, cols=m.cols, nnz=len(m.values),
                        offsets=m.offsets, indices=m.indices, values=m.values)

        return _digest({
            "struct_size": ctypes.sizeof(ABI2StepInput),
            "abi_version": ABI_VERSION,
            "n": len(self.previous),
            "k": matrix(self.k), "r": matrix(self.r), "j": matrix(self.j), "a": matrix(self.a),
            "alpha": self.alpha, "previous": self.previous, "drive": self.drive,
            "iterate": self.iterate, "h": self.h, "previous_error": self.previous_error,
            "max_iterations": self.max_iterations, "tolerance": self.tolerance,
            "boundary_eta": self.boundary_eta,
        })


@dataclass(frozen=True, slots=True)
class FixedBlockMathTranscript:
    """Actual ABI2 call values and native-reported bounds; never a product receipt."""

    input: FixedBlockStep
    output: tuple[float, ...]
    bounds: NativeReportedFixedBlockIntervalBounds
    production_binding: NativeLoadBinding
    input_sha256: str
    output_sha256: str
    transcript_sha256: str


@dataclass(frozen=True, slots=True)
class FixedBlockContinuation:
    """Next step settings and complete model, without caller-supplied chain state.

    The trajectory runner supplies ``previous``, ``iterate`` and
    ``previous_error`` from the preceding native result. A changed model is
    rejected before the next native call; parameter switches need their own
    mathematical mapping certificate.
    """

    k: FixedBlockCSR
    r: FixedBlockCSR
    j: FixedBlockCSR
    a: FixedBlockCSR
    alpha: tuple[float, ...]
    drive: tuple[float, ...]
    h: float
    max_iterations: int
    tolerance: float

    def __post_init__(self) -> None:
        n = self.k.rows
        zero = (0.0,) * n
        # Reuse the ABI2 input gate, including finite values and dimensions.
        checked = FixedBlockStep(
            self.k, self.r, self.j, self.a, self.alpha, zero, self.drive,
            zero, self.h, 0.0, self.max_iterations, self.tolerance,
        )
        object.__setattr__(self, "alpha", checked.alpha)
        object.__setattr__(self, "drive", checked.drive)
        object.__setattr__(self, "h", checked.h)
        object.__setattr__(self, "tolerance", checked.tolerance)

    @classmethod
    def from_step(cls, step: FixedBlockStep, *, h: float | None = None,
                  max_iterations: int | None = None,
                  tolerance: float | None = None) -> FixedBlockContinuation:
        return cls(
            step.k, step.r, step.j, step.a, step.alpha, step.drive,
            step.h if h is None else h,
            step.max_iterations if max_iterations is None else max_iterations,
            step.tolerance if tolerance is None else tolerance,
        )


@dataclass(frozen=True, slots=True)
class FixedBlockTrajectoryMathTranscript:
    """Conditional fixed-model numerical chain from a supplied initial error.

    The initial error is a caller assertion; neither this transcript nor ABI2
    establish its external provenance or D04 product eligibility.
    """

    steps: tuple[FixedBlockMathTranscript, ...]
    initial_error: float
    final_error: float
    production_binding: NativeLoadBinding
    transcript_sha256: str


def _same_float_bits(lhs: tuple[float, ...], rhs: tuple[float, ...]) -> bool:
    return len(lhs) == len(rhs) and all(
        struct.pack("!d", left) == struct.pack("!d", right)
        for left, right in zip(lhs, rhs)
    )


def _same_csr_bits(lhs: FixedBlockCSR, rhs: FixedBlockCSR) -> bool:
    return (
        lhs.rows == rhs.rows and lhs.cols == rhs.cols
        and lhs.offsets == rhs.offsets and lhs.indices == rhs.indices
        and _same_float_bits(lhs.values, rhs.values)
    )


def _same_fixed_model(first: FixedBlockStep, next_step: FixedBlockContinuation) -> bool:
    return (
        all(_same_csr_bits(getattr(first, name), getattr(next_step, name))
            for name in ("k", "r", "j", "a"))
        and _same_float_bits(first.alpha, next_step.alpha)
        and _same_float_bits(first.drive, next_step.drive)
    )


def run_fixed_block_trajectory_math(
    handle: ABI2NativeLibrary,
    first: FixedBlockStep,
    continuations: Sequence[FixedBlockContinuation],
) -> FixedBlockTrajectoryMathTranscript:
    """Run at most 1025 package-bound steps with an unchanged complete model.

    Each native call receives the exact preceding output as its state and the
    preceding outward interval upper bound as its inherited error. The first
    step's ``previous_error`` remains a conditional caller-supplied premise.
    """
    if not isinstance(first, FixedBlockStep):
        raise TypeError("first must be an immutable FixedBlockStep")
    if not isinstance(continuations, Sequence) or not 1 <= len(continuations) <= 1024:
        raise ValueError("fixed trajectory requires 1 to 1024 continuations")
    planned = tuple(continuations)
    if any(not isinstance(step, FixedBlockContinuation) for step in planned):
        raise TypeError("continuations must be immutable FixedBlockContinuation values")
    if any(not _same_fixed_model(first, step) for step in planned):
        raise ABI2ResultError("fixed trajectory parameter or drive switch requires a separate certificate")

    recorded = [run_fixed_block_math(handle, first)]
    for continuation in planned:
        previous = recorded[-1]
        step = FixedBlockStep(
            continuation.k, continuation.r, continuation.j, continuation.a,
            continuation.alpha, previous.output, continuation.drive,
            previous.output, continuation.h, previous.bounds.trajectory_error,
            continuation.max_iterations, continuation.tolerance,
        )
        recorded.append(run_fixed_block_math(handle, step))

    steps = tuple(recorded)
    binding = steps[0].production_binding
    digest = _digest({
        "schema": "abi2.fixed-block-trajectory-math-transcript.v1",
        "initial_error": first.previous_error,
        "final_error": steps[-1].bounds.trajectory_error,
        "production_binding": {field.name: getattr(binding, field.name) for field in fields(binding)},
        "steps": [step.transcript_sha256 for step in steps],
    })
    return FixedBlockTrajectoryMathTranscript(
        steps, first.previous_error, steps[-1].bounds.trajectory_error,
        binding, digest,
    )


def run_fixed_block_math(handle: ABI2NativeLibrary, block: FixedBlockStep) -> FixedBlockMathTranscript:
    """Run an owned fixed block through a verified-package handle synchronously."""
    if not isinstance(handle, ABI2NativeLibrary) or handle.production_binding is None:
        raise ABI2ResultError("fixed-block math requires a package-bound ABI2 handle")
    if not handle.capabilities.supports_fixed_block_interval_math_v1:
        raise ABI2ResultError("native fixed-block math capability is absent")
    if not isinstance(block, FixedBlockStep):
        raise TypeError("block must be an immutable FixedBlockStep")
    n = len(block.previous)
    if n > handle.capabilities.max_dimension:
        raise ValueError("fixed block exceeds native maximum dimension")

    # All arrays stay owned and live until the synchronous C call returns.
    keepalive: list[object] = []

    def csr(value: FixedBlockCSR) -> ABI2CSR:
        offsets = (ctypes.c_uint32 * len(value.offsets))(*value.offsets)
        indices = (ctypes.c_uint32 * len(value.indices))(*value.indices)
        values = (ctypes.c_double * len(value.values))(*value.values)
        keepalive.extend((offsets, indices, values))
        return ABI2CSR(value.rows, value.cols, len(value.values), offsets, indices, values)

    def vector(values: tuple[float, ...]) -> ctypes.Array[ctypes.c_double]:
        owned = (ctypes.c_double * len(values))(*values)
        keepalive.append(owned)
        return owned

    alpha = vector(block.alpha)
    previous = vector(block.previous)
    drive = vector(block.drive)
    iterate = vector(block.iterate)
    request = ABI2StepInput(
        ctypes.sizeof(ABI2StepInput), ABI_VERSION, n,
        csr(block.k), csr(block.r), csr(block.j), csr(block.a),
        alpha, previous, drive, iterate,
        block.h, block.previous_error, block.max_iterations, block.tolerance, block.boundary_eta,
    )
    output_buffer = (ctypes.c_double * n)()
    raw = ABI2StepResult()
    status = handle._step(ctypes.byref(request), output_buffer, n, ctypes.byref(raw))
    if status != raw.status:
        raise ABI2ResultError("ABI2 return status disagrees with result status")
    bounds = parse_fixed_block_interval_result(raw)
    output = tuple(output_buffer)
    if not all(math.isfinite(value) for value in output):
        raise ABI2ResultError("ABI2 fixed-block output is non-finite")
    input_sha256 = block.digest()
    output_sha256 = _digest(output)
    binding = handle.production_binding
    transcript_sha256 = _digest({
        "schema": "abi2.fixed-block-math-transcript.v1",
        "input_sha256": input_sha256,
        "output_sha256": output_sha256,
        "manifest_sha256": binding.manifest_sha256,
        "native_sha256": binding.native_sha256,
        "bounds": {field.name: getattr(bounds, field.name) for field in fields(bounds)},
    })
    return FixedBlockMathTranscript(
        block, output, bounds, binding, input_sha256, output_sha256, transcript_sha256
    )
