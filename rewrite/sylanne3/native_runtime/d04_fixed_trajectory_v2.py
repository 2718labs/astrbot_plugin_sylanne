"""Complete fixed-model D04 trajectories, with a pinned finite step policy.

Each step is an actual ABI2 call. Exact binary64 durations cover the original
role interval; neither the last step nor a locally recomputed hash can stand
in for the complete chain. Compact encoding retains every native output/bound.
"""
from __future__ import annotations

from dataclasses import dataclass, fields, replace
from contextlib import contextmanager
from contextvars import ContextVar
from time import thread_time_ns
import threading
from fractions import Fraction
import math

from .fixed_block_transcript import (
    FixedBlockStep, FixedBlockMathTranscript, FixedBlockTrajectoryMathTranscript,
    _digest, _same_float_bits, run_fixed_block_math,
    _FixedBlockInputEncoder, _run_fixed_block_math_with_input_encoder,
)

SCHEMA = "d04.fixed-trajectory-plan.v2"
COMPACT_SCHEMA = "abi2.fixed-block-trajectory-compact.v2"
MAX_STEP = 1.0 / 64.0
MAX_STEPS = 4096
MAX_NATIVE_CALLS = 8192


_CPU_SCOPE = ContextVar("d04_trajectory_cpu_v2", default=None)


class D04TrajectoryBudgetExceeded(ValueError):
    """Measured claimed work stopped; this never authorizes executing it again."""


@contextmanager
def bounded_d04_native_cpu_v2(cpu_ceiling_ms):
    if type(cpu_ceiling_ms) is not int or cpu_ceiling_ms <= 0 or _CPU_SCOPE.get() is not None:
        raise ValueError("one actual positive D04 CPU budget scope required")
    token = _CPU_SCOPE.set((threading.get_ident(), thread_time_ns() + cpu_ceiling_ms * 1_000_000))
    try:
        yield
        _require_cpu_v2()
    finally:
        _CPU_SCOPE.reset(token)


def _require_cpu_v2():
    current = _CPU_SCOPE.get()
    if current is not None and (threading.get_ident() != current[0] or thread_time_ns() >= current[1]):
        raise D04TrajectoryBudgetExceeded("D04 claimed trajectory exhausted actual thread CPU; retain cost, do not rerun")


def fixed_d04_step_plan_v2(role_start, role_end):
    plan = exact_d04_series_step_plan_v1(role_start, role_end, family_count=1)
    if plan.total_step_count > MAX_STEPS:
        raise ValueError("D04 complete interval exceeds the pinned trajectory step budget")
    return (MAX_STEP,) * plan.full_step_count + plan.tail_steps


@dataclass(frozen=True, slots=True)
class D04ExactSeriesStepPlanV1:
    role_start: float
    role_end: float
    full_step_count: int
    tail_steps: tuple[float, ...]
    family_count: int
    chunk_step_limit: int
    schema: str = "d04.exact-series-step-plan.v1"

    @property
    def total_step_count(self):
        return self.full_step_count + len(self.tail_steps)

    @property
    def digest(self):
        return _digest({"schema": self.schema, "role_start_binary64": self.role_start.hex(),
            "role_end_binary64": self.role_end.hex(), "full_step_count": self.full_step_count,
            "tail_steps_binary64": tuple(value.hex() for value in self.tail_steps),
            "family_count": self.family_count, "chunk_step_limit": self.chunk_step_limit})

    def chunk(self, start_step_index):
        if type(start_step_index) is not int or not 0 <= start_step_index < self.total_step_count:
            raise ValueError("series chunk must start at an actual absolute step index")
        end = min(start_step_index + self.chunk_step_limit, self.total_step_count)
        full_end = min(end, self.full_step_count)
        regular = (MAX_STEP,) * max(0, full_end - start_step_index)
        tail = self.tail_steps[max(0, start_step_index - self.full_step_count):max(0, end - self.full_step_count)]
        return regular + tail


def exact_d04_series_step_plan_v1(role_start, role_end, *, family_count):
    """Compact exact original h sequence; slicing never rounds role endpoints."""
    if (type(role_start) is not float or type(role_end) is not float
            or not math.isfinite(role_start) or not math.isfinite(role_end) or role_end <= role_start):
        raise ValueError("finite increasing D04 role interval required")
    remaining = Fraction.from_float(role_end) - Fraction.from_float(role_start)
    maximum = Fraction.from_float(MAX_STEP)
    if type(family_count) is not int or family_count < 1:
        raise ValueError("series requires its actual positive whole-family inventory")
    chunk_step_limit = min(512, MAX_STEPS, MAX_NATIVE_CALLS // (1 + family_count))
    if chunk_step_limit < 1:
        raise ValueError("whole-family inventory exceeds one bounded native work unit")
    full_step_count, remaining = divmod(remaining, maximum)
    tail = []
    while remaining:
        exact = remaining
        step = float(exact)
        if Fraction.from_float(step) > exact:
            step = math.nextafter(step, 0.0)
        if step <= 0 or not math.isfinite(step):
            raise ValueError("D04 role interval cannot be exactly covered in binary64")
        tail.append(step)
        remaining -= Fraction.from_float(step)
    return D04ExactSeriesStepPlanV1(role_start, role_end, full_step_count, tuple(tail), family_count, chunk_step_limit)


def trajectory_digest_v2(steps, initial_error, final_error, binding):
    return _digest({"schema": "abi2.fixed-block-trajectory-math-transcript.v1",
        "initial_error": initial_error, "final_error": final_error,
        "production_binding": {field.name: getattr(binding, field.name) for field in fields(binding)},
        "steps": [step.transcript_sha256 for step in steps]})


def run_d04_fixed_trajectory_v2(handle, first, step_plan):
    if (type(first) is not FixedBlockStep or type(step_plan) is not tuple
            or not 1 <= len(step_plan) <= MAX_STEPS or first.h != step_plan[0]):
        raise ValueError("D04 exact bounded trajectory plan required")
    recorded = []
    step = first
    input_encoder = _FixedBlockInputEncoder(first)
    for h in step_plan:
        if recorded:
            prior = recorded[-1]
            step = replace(first, previous=prior.output, iterate=prior.output, h=h,
                previous_error=prior.bounds.trajectory_error)
        _require_cpu_v2()
        recorded.append(_run_fixed_block_math_with_input_encoder(handle, step, input_encoder))
        _require_cpu_v2()
    steps = tuple(recorded)
    final_error = steps[-1].bounds.trajectory_error
    return FixedBlockTrajectoryMathTranscript(steps, first.previous_error, final_error,
        steps[0].production_binding, trajectory_digest_v2(steps, first.previous_error, final_error,
                                                         steps[0].production_binding))


def verify_d04_fixed_trajectory_v2(value, *, first=None, step_plan=None):
    """Pure structural/native commitment verification; authenticate separately."""
    if type(value) is not FixedBlockTrajectoryMathTranscript or not 1 <= len(value.steps) <= MAX_STEPS:
        raise ValueError("complete D04 fixed trajectory required")
    base = value.steps[0].input
    if first is not None and base != first:
        raise ValueError("D04 trajectory first model differs")
    if step_plan is not None and tuple(step.input.h for step in value.steps) != step_plan:
        raise ValueError("D04 trajectory does not cover its exact full role interval")
    if (value.initial_error != base.previous_error
            or value.final_error != value.steps[-1].bounds.trajectory_error
            or value.production_binding != value.steps[0].production_binding):
        raise ValueError("D04 trajectory endpoint errors differ")
    prior = None
    input_encoder = _FixedBlockInputEncoder(base)
    for step in value.steps:
        expected = base if prior is None else replace(base, previous=prior.output, iterate=prior.output,
            h=step.input.h, previous_error=prior.bounds.trajectory_error)
        if (type(step) is not FixedBlockMathTranscript or step.input != expected
                or not 0 < step.input.h <= MAX_STEP or step.production_binding != value.production_binding
                or step.input_sha256 != input_encoder.digest(step.input)
                or step.input_sha256 != input_encoder.digest(expected)
                or step.output_sha256 != _digest(step.output)
                or not _same_float_bits(step.input.previous, expected.previous)
                or not _same_float_bits(step.input.iterate, expected.iterate)
                or not _same_float_bits((step.input.previous_error,), (expected.previous_error,))
                or step.transcript_sha256 != _digest({"schema": "abi2.fixed-block-math-transcript.v1",
                    "input_sha256": step.input_sha256, "output_sha256": step.output_sha256,
                    "manifest_sha256": step.production_binding.manifest_sha256,
                    "native_sha256": step.production_binding.native_sha256,
                    "bounds": {field.name: getattr(step.bounds, field.name) for field in fields(step.bounds)}})):
            raise ValueError("D04 trajectory loses native model/state/error continuity")
        bounds = step.bounds
        if (bounds.status != 0 or bounds.certificate_flags != 1 or bounds.boundary_eta != 0
                or not 0 <= bounds.iterations <= step.input.max_iterations
                or any(not math.isfinite(getattr(bounds, name)) or getattr(bounds, name) < 0
                    for name in ("residual", "iteration_error", "time_defect", "trajectory_error",
                                 "energy_balance_defect", "q_upper", "boundary_eta"))
                or bounds.q_upper > 0.8 or not all(math.isfinite(x) for x in step.output)
                or len(step.output) != len(base.previous)):
            raise ValueError("D04 trajectory native interval certificate differs")
        prior = step
    if value.transcript_sha256 != trajectory_digest_v2(value.steps, value.initial_error, value.final_error, value.production_binding):
        raise ValueError("D04 trajectory complete commitment differs")
    return value


def compact_d04_fixed_trajectory_v2(value):
    verify_d04_fixed_trajectory_v2(value)
    return _compact_d04_fixed_trajectory_payload_v2(value)


def _compact_d04_fixed_trajectory_payload_v2(value):
    """Encode exact bits; qualification belongs to the trajectory reader/verifier."""
    from ..runtime.d04_semantic_mapping_v3 import evidence_payload_v3 as payload
    return {"schema": COMPACT_SCHEMA, "first_input": payload(value.steps[0].input),
        "initial_error": payload(value.initial_error), "final_error": payload(value.final_error),
        "production_binding": payload(value.production_binding), "transcript_sha256": value.transcript_sha256,
        "steps": [{"h": payload(step.input.h), "output": payload(step.output), "bounds": payload(step.bounds),
            "input_sha256": step.input_sha256, "output_sha256": step.output_sha256,
            "transcript_sha256": step.transcript_sha256} for step in value.steps]}


def decode_compact_d04_fixed_trajectory_v2(raw, typed):
    """Called only by the closed DTO codec after exact-bit primitive decoding."""
    return verify_d04_fixed_trajectory_v2(_decode_compact_d04_fixed_trajectory_payload_v2(raw, typed))


def _decode_compact_d04_fixed_trajectory_payload_v2(raw, typed):
    """Reconstruct exact structure; a complete final verifier must qualify it."""
    from .abi2 import NativeReportedFixedBlockIntervalBounds
    from .loader import NativeLoadBinding
    if (type(raw) is not dict or set(raw) != {"schema", "first_input", "initial_error", "final_error",
            "production_binding", "transcript_sha256", "steps"} or raw["schema"] != COMPACT_SCHEMA
            or type(raw["steps"]) is not list or not 1 <= len(raw["steps"]) <= MAX_STEPS):
        raise ValueError("D04 compact trajectory shape differs")
    first = typed(FixedBlockStep, raw["first_input"])
    binding = typed(NativeLoadBinding, raw["production_binding"])
    steps = []
    for item in raw["steps"]:
        if type(item) is not dict or set(item) != {"h", "output", "bounds", "input_sha256", "output_sha256", "transcript_sha256"}:
            raise ValueError("D04 compact trajectory native step fields differ")
        h = typed(float, item["h"])
        step = first if not steps else replace(first, h=h, previous=steps[-1].output, iterate=steps[-1].output,
            previous_error=steps[-1].bounds.trajectory_error)
        if step.h != h:
            raise ValueError("D04 compact first step differs")
        steps.append(FixedBlockMathTranscript(step, typed(tuple[float, ...], item["output"]),
            typed(NativeReportedFixedBlockIntervalBounds, item["bounds"]), binding,
            *(typed(str, item[name]) for name in ("input_sha256", "output_sha256", "transcript_sha256"))))
    value = FixedBlockTrajectoryMathTranscript(tuple(steps), typed(float, raw["initial_error"]),
        typed(float, raw["final_error"]), binding, typed(str, raw["transcript_sha256"]))
    return value
