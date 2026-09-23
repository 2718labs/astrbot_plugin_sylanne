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
