"""Independent high-precision checks of the conditional D04 tanh enclosure."""

from __future__ import annotations

from decimal import Decimal, localcontext
import math

import pytest

from sylanne3.native_runtime.tanh_interval import (
    conditional_tanh_interval_math,
    conditional_tanh_intervals_24d_math,
)


def _reference_tanh(value: Decimal) -> Decimal:
    exponential = (2 * value).exp()
    return (exponential - 1) / (exponential + 1)


def test_endpoints_and_z_two_nonlinear_counterexample() -> None:
    assert conditional_tanh_interval_math(0.0, 0.0) == (0.0, 0.0)
    with localcontext() as context:
        context.prec = 110
        for center in (0.1, 2.0, 4.0):
            lower, upper = conditional_tanh_interval_math(center, 0.0)
            reference = _reference_tanh(Decimal.from_float(center))
            assert Decimal.from_float(lower) <= reference <= Decimal.from_float(upper)
            assert upper - lower <= 2 * math.ulp(upper)
    lower, upper = conditional_tanh_interval_math(2.0, 0.0)
    assert lower < 1.0 and upper < 1.0  # A linear c·z readout would return 2.


def test_nonzero_error_and_binary64_outward_rounding() -> None:
    y, e = 2.0, 0.1
    lower, upper = conditional_tanh_interval_math(y, e)
    with localcontext() as context:
        context.prec = 110
        center, radius = Decimal.from_float(y), Decimal.from_float(e)
        assert Decimal.from_float(lower) <= _reference_tanh(center - radius)
        assert Decimal.from_float(upper) >= _reference_tanh(center + radius)
    assert lower < math.tanh(y - e) < math.tanh(y + e) < upper


def test_rejects_uncertainty_crossing_domain_or_nonbinary64_input() -> None:
    for y, e in ((0.0, 0.1), (4.0, 0.1), (float("nan"), 0.0),
                 (2.0, float("inf")), (2.0, -0.1), (2, 0.0)):
        with pytest.raises(ValueError):
            conditional_tanh_interval_math(y, e)


def test_24d_uses_supplied_joint_error_as_marginal_bound() -> None:
    centers = (2.0,) * 24
    result = conditional_tanh_intervals_24d_math(centers, 0.1)
    assert len(result) == 24
    assert result == (conditional_tanh_interval_math(2.0, 0.1),) * 24
    with pytest.raises(ValueError):
        conditional_tanh_intervals_24d_math(centers[:-1], 0.1)
    with pytest.raises(ValueError):
        conditional_tanh_intervals_24d_math((0.0,) + centers[1:], 0.1)
