"""Conditional source-removal readout intervals for one complete ABI2 joint block.

The supplied joint matrices, source rows and initial box are premises. Native
ABI2 certifies each resulting fixed-block solve, but cannot attest that W01
enumerated the current graph SCC or that a source is causally independent.
No result here is a D04 product credential or a historical source deletion.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from fractions import Fraction
import math

from .abi2 import ABI2ResultError
from .fixed_block_transcript import FixedBlockStep, _digest, _same_float_bits, run_fixed_block_math
from .initial_box_trajectory import _native_initial_radius
from .linear_readout import _outward_binary64, MAX_READOUT_DIMENSION
from .loader import ABI2NativeLibrary


class D04JointCounterfactualHold(ValueError):
    """The proposed frozen joint calculation is incomplete or inconsistent."""


@dataclass(frozen=True, slots=True)
class D04JointSourceDrive:
    source_ref: str
    drive: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class D04SourceRemovalInterval:
    source_ref: str
    lower: float
    upper: float
    counterfactual_input_sha256: str
    counterfactual_transcript_sha256: str


@dataclass(frozen=True, slots=True)
class D04JointCounterfactualMathCandidate:
    full_input_sha256: str
    full_transcript_sha256: str
    initial_error: float
    source_intervals: tuple[D04SourceRemovalInterval, ...]
    transcript_sha256: str
    status: str = "unsigned_hold_for_w01_fenced_joint_scc_and_source_adoption"


def _sum_drives(rows: tuple[D04JointSourceDrive, ...], n: int) -> tuple[float, ...]:
    try:
        total = tuple(float(sum((Fraction.from_float(float(row.drive[index])) for row in rows),
                                Fraction())) for index in range(n))
    except OverflowError as exc:
        raise D04JointCounterfactualHold("source drive sum overflows binary64") from exc
    if any(not math.isfinite(value) for value in total):
        raise D04JointCounterfactualHold("source drive sum is not finite")
    return total


def _readout_interval(output: tuple[float, ...], error: float,
                      weights: tuple[float, ...]) -> tuple[Fraction, Fraction]:
    if not math.isfinite(error) or error < 0:
        raise ABI2ResultError("joint branch has no finite certified trajectory error")
    center = sum((Fraction.from_float(float(weight)) * Fraction.from_float(value)
                  for weight, value in zip(weights, output)), Fraction())
    # The ABI2 bound is Euclidean. Its per-coordinate implication gives the
    # conservative L1 coefficient radius, matching linear_readout.py.
    radius = Fraction.from_float(error) * sum(
        (abs(Fraction.from_float(float(weight))) for weight in weights), Fraction())
    return center - radius, center + radius


def run_d04_joint_source_removal_math(
    handle: ABI2NativeLibrary,
    *, joint: FixedBlockStep,
    source_drives: tuple[D04JointSourceDrive, ...],
    initial_lower: tuple[float, ...],
    initial_upper: tuple[float, ...],
    readout: tuple[float, ...],
) -> D04JointCounterfactualMathCandidate:
    """Run full and leave-one-source-out branches on the same frozen joint block.

    Every branch uses the same matrices, nominal previous state, verified
    initial-box radius, step size and readout. Only its complete drive changes.
    Source identity, graph closure, and box provenance remain W01 premises.
    """
    if (type(joint) is not FixedBlockStep or type(source_drives) is not tuple
            or len(source_drives) < 2 or type(initial_lower) is not tuple
            or type(initial_upper) is not tuple or type(readout) is not tuple):
        raise D04JointCounterfactualHold("joint source removal needs typed mixed inputs")
    n = len(joint.previous)
    if not 2 <= n <= MAX_READOUT_DIMENSION or joint.previous_error != 0.0:
        raise D04JointCounterfactualHold("joint block needs at least two members and a native initial box")
    if (len(initial_lower) != n or len(initial_upper) != n
            or len(readout) != n or any(type(value) not in (int, float)
                                        or not math.isfinite(value) for value in readout)):
        raise D04JointCounterfactualHold("joint initial box or readout dimension differs")
    refs = set()
    for row in source_drives:
        if (type(row) is not D04JointSourceDrive or type(row.source_ref) is not str
                or not row.source_ref or row.source_ref in refs
                or type(row.drive) is not tuple or len(row.drive) != n
                or any(type(value) not in (int, float) or not math.isfinite(value)
                       for value in row.drive)):
            raise D04JointCounterfactualHold("joint source drive is incomplete or repeated")
        refs.add(row.source_ref)
    canonical = tuple(sorted(source_drives, key=lambda row: row.source_ref))
    weights = tuple(float(value) for value in readout)
    if not _same_float_bits(joint.drive, _sum_drives(canonical, n)):
        raise D04JointCounterfactualHold("aggregate drive is not the exact source sum")
    if (not isinstance(handle, ABI2NativeLibrary) or handle.production_binding is None
            or not handle.capabilities.supports_fixed_block_interval_math_v1
            or not handle.capabilities.supports_initial_box_math_v1):
        raise ABI2ResultError("joint counterfactual requires package-bound ABI2 interval and box math")
    lower = tuple(float(value) for value in initial_lower)
    upper = tuple(float(value) for value in initial_upper)
    if any(not math.isfinite(value) for value in lower + upper):
        raise D04JointCounterfactualHold("joint initial box is not finite")
    radius = _native_initial_radius(handle, joint.previous, lower, upper)
    base = replace(joint, previous_error=radius, iterate=joint.previous)
    full = run_fixed_block_math(handle, base)
    full_lo, full_hi = _readout_interval(
        full.output, full.bounds.trajectory_error, weights,
    )
    intervals = []
    for removed in canonical:
        remaining = tuple(row for row in canonical if row.source_ref != removed.source_ref)
        branch = run_fixed_block_math(handle, replace(base, drive=_sum_drives(remaining, n)))
        branch_lo, branch_hi = _readout_interval(
            branch.output, branch.bounds.trajectory_error, weights,
        )
        # Readout(full) - readout(without source), with exact rational endpoint
        # subtraction before the one outward binary64 rounding.
        intervals.append(D04SourceRemovalInterval(
            removed.source_ref,
            _outward_binary64(full_lo - branch_hi, lower=True),
            _outward_binary64(full_hi - branch_lo, lower=False),
            branch.input_sha256, branch.transcript_sha256,
        ))
    digest = _digest({
        "schema": "d04.conditional-joint-source-removal-math.v1",
        "initial_box": (lower, upper), "initial_error": radius,
        "full": full.transcript_sha256,
        "sources": tuple((row.source_ref, row.drive) for row in canonical),
        "readout": weights,
        "intervals": tuple((row.source_ref, row.lower, row.upper,
                            row.counterfactual_transcript_sha256) for row in intervals),
    })
    return D04JointCounterfactualMathCandidate(
        full.input_sha256, full.transcript_sha256, radius, tuple(intervals), digest,
    )


__all__ = ["D04JointCounterfactualHold", "D04JointSourceDrive",
           "D04SourceRemovalInterval", "D04JointCounterfactualMathCandidate",
           "run_d04_joint_source_removal_math"]
