"""Permanent offline timing/guard boundaries and exact compact-step equivalence.

No native FFI, Authority RPC, model provider or platform sender runs here.
"""
from datetime import datetime, timezone
from fractions import Fraction
import logging
import math
from types import SimpleNamespace

import pytest

from sylanne3.native_runtime.d04_fixed_trajectory_v2 import (
    MAX_STEP, exact_d04_series_step_plan_v1, fixed_d04_step_plan_v2,
)
from sylanne3.runtime.d04_installed_stage_fence_v3 import _D04PhaseTimingsV1
from sylanne3.runtime.d04_series_execution_v1 import _require_d04_series_cpu_deadline_v1


def _guard_inputs():
    deadline = datetime(2030, 1, 1, tzinfo=timezone.utc).timestamp()
    return deadline, dict(
        grant=SimpleNamespace(grant_id="grant-1", version=1, valid_until_utc=deadline + 3000,
            max_ceiling={"cpu_ms": 600000}),
        lease=SimpleNamespace(state="active"), policy=SimpleNamespace(grant_id="grant-1", grant_version=1),
        base=SimpleNamespace(cpu_ceiling_ms=100000, deadline_utc="2030-01-01T00:00:00Z"))


def test_fixed_root_deadline_rejects_fresh_parent_at_exact_boundary():
    deadline, args = _guard_inputs()
    _require_d04_series_cpu_deadline_v1(**args, now=math.nextafter(deadline, -math.inf))
    with pytest.raises(ValueError, match="fixed deadline"):
        _require_d04_series_cpu_deadline_v1(**args, now=deadline)
    with pytest.raises(ValueError, match="fixed deadline"):
        _require_d04_series_cpu_deadline_v1(**args, now=deadline + 36.097988)
    assert args["grant"].valid_until_utc > deadline + 36.097988
    assert args["base"].deadline_utc == "2030-01-01T00:00:00Z"


@pytest.mark.parametrize("target,field,bad", [("grant", "grant_id", "other-grant"),
    ("grant", "version", 2), ("grant", "valid_until_utc", 0), ("lease", "state", "closed"),
    ("grant", "max_ceiling", {"cpu_ms": 99999})])
def test_parent_guard_still_rejects_identity_expiry_state_or_ceiling_before_root_deadline(target, field, bad):
    deadline, args = _guard_inputs()
    setattr(args[target], field, bad)
    with pytest.raises(ValueError, match="current parent CPU authority"):
        _require_d04_series_cpu_deadline_v1(**args, now=deadline - 1)


@pytest.mark.parametrize("start,end,families", [(0.0, 0.1, 1), (7.0, 15.02, 1), (3.1, 3.3, 7)])
def test_small_compact_chunks_preserve_exact_original_binary64_step_sequence(start, end, families):
    compact = exact_d04_series_step_plan_v1(start, end, family_count=families)
    slices = []
    index = 0
    while index < compact.total_step_count:
        chunk = compact.chunk(index)
        assert 1 <= len(chunk) <= compact.chunk_step_limit <= 512
        slices.extend(chunk)
        index += len(chunk)
    assert tuple(slices) == fixed_d04_step_plan_v2(start, end)
    assert sum(map(Fraction.from_float, slices), Fraction()) == Fraction.from_float(end) - Fraction.from_float(start)
    assert all(0 < step <= MAX_STEP for step in slices)
    assert index == compact.full_step_count + len(compact.tail_steps)
    with pytest.raises(ValueError, match="actual absolute step"):
        compact.chunk(index)


def test_timing_uses_monotonic_wall_and_only_bound_paired_clock(caplog, monkeypatch):
    current = [10.0]
    monkeypatch.setattr("sylanne3.runtime.d04_installed_stage_fence_v3.time.monotonic", lambda: current[0])
    timings = _D04PhaseTimingsV1("fixture-root", deadline_utc="2030-01-01T00:00:00Z")
    caplog.set_level(logging.INFO, logger="sylanne3.runtime.d04_installed_stage_fence_v3")
    with timings.measure("prepare_inspect", chunk_start=0):
        current[0] = 11.0
    assert "trusted_utc_upper_start=None" in caplog.records[-1].getMessage()
    assert "trusted_utc_upper_end=None" in caplog.records[-1].getMessage()
    timings.bind_clock(SimpleNamespace(utc_upper_bound_seconds=100.0, monotonic_after_seconds=11.0))
    with timings.measure("sql_transaction", chunk_start=0):
        current[0] = 13.0
    record = caplog.records[-1]
    assert timings.seconds["sql_transaction"] == 2.0 and timings.counts["sql_transaction"] == 1
    assert record.args[6] >= 100.0 and record.args[7] >= 102.0
    assert "wall_seconds=2.000000000" in record.getMessage()
    assert not hasattr(timings, "actual_cpu_ms")


def test_diagnostics_preserve_rejection_and_use_finite_phase_labels(caplog):
    timings = _D04PhaseTimingsV1("fixture-root")
    caplog.set_level(logging.INFO, logger="sylanne3.runtime.d04_installed_stage_fence_v3")
    with pytest.raises(ValueError, match="original refusal"):
        with timings.measure("stage_callback"):
            raise ValueError("original refusal")
    assert "outcome=ValueError" in caplog.records[-1].getMessage()
    assert timings.counts["stage_callback"] == 1
    count = len(timings.counts)
    with pytest.raises(ValueError, match="finite D04 timing phase"):
        with timings.measure("caller-arbitrary-label"):
            pass
    assert len(timings.counts) == count


@pytest.mark.parametrize("start,end,families", [(0.0, float('nan'), 1), (0.0, float('inf'), 1),
    (1.0, 1.0, 1), (0.0, 1.0, 0), (0.0, 1.0, True)])
def test_compact_plan_rejects_nonfinite_interval_or_invalid_whole_family_inventory(start, end, families):
    with pytest.raises(ValueError):
        exact_d04_series_step_plan_v1(start, end, family_count=families)
