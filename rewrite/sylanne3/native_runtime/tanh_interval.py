"""Conditional, rational enclosure of the positive D04 tanh readout.

These functions only propagate a supplied state error. They do not certify
that error, a source graph, a native trajectory, or product admission.
"""

from __future__ import annotations

from fractions import Fraction
import math


_TAYLOR_DEGREE = 64
_DOMAIN_UPPER = Fraction(4)


def _exp_positive_bounds(t: Fraction) -> tuple[Fraction, Fraction]:
    """Enclose exp(t) for 0 <= t <= 8 with exact rational arithmetic.

    The degree-64 positive Taylor sum is a lower bound. After its first
    omitted term a_65, consecutive term ratios are at most t/66 <= 8/66.
    Thus the whole omitted tail is at most a_65 / (1 - t/66).
    """
    term = total = Fraction(1)
    for degree in range(1, _TAYLOR_DEGREE + 1):
        term *= t / degree
        total += term
    first_omitted = term * t / (_TAYLOR_DEGREE + 1)
    tail_upper = first_omitted / (1 - t / (_TAYLOR_DEGREE + 2))
    return total, total + tail_upper


def _tanh_from_exp(exp_value: Fraction) -> Fraction:
    return (exp_value - 1) / (exp_value + 1)


def _outward_binary64(value: Fraction, *, lower: bool) -> float:
    rounded = float(value)
    exact_rounded = Fraction.from_float(rounded)
    if lower and exact_rounded > value:
        rounded = math.nextafter(rounded, -math.inf)
    elif not lower and exact_rounded < value:
        rounded = math.nextafter(rounded, math.inf)
    return rounded


def _exact_state_interval(y: float, e: float) -> tuple[Fraction, Fraction]:
    if type(y) is not float or not math.isfinite(y):
        raise ValueError("tanh center must be a finite binary64 value")
    if type(e) is not float or not math.isfinite(e) or e < 0:
        raise ValueError("state error must be a finite nonnegative binary64 value")
    center = Fraction.from_float(y)
    radius = Fraction.from_float(e)
    low, high = center - radius, center + radius
    if low < 0 or high > _DOMAIN_UPPER:
        raise ValueError("entire state interval must lie in [0, 4]")
    return low, high


def conditional_tanh_interval_math(y: float, e: float) -> tuple[float, float]:
    """Enclose tanh(z) when |z-y| <= e and the entire interval is in [0, 4].

    The input floats are treated as their exact binary64 rational values.
    Since exp and (E-1)/(E+1) increase on this domain, the lower endpoint
    uses the lower Taylor sum at y-e and the upper endpoint uses the upper
    Taylor bound at y+e. Only the final rational bounds round to binary64.
    """
    low, high = _exact_state_interval(y, e)
    return conditional_tanh_interval_endpoints_math(low, high)


def conditional_tanh_interval_endpoints_math(low: Fraction, high: Fraction) -> tuple[float, float]:
    """Conditional readout on independently proved exact rational endpoints."""
    if type(low) is not Fraction or type(high) is not Fraction or not 0 <= low <= high <= _DOMAIN_UPPER:
        raise ValueError("tanh interval endpoints must be exact and inside [0, 4]")
    lower_exp, _ = _exp_positive_bounds(2 * low)
    _, upper_exp = _exp_positive_bounds(2 * high)
    return (
        _outward_binary64(_tanh_from_exp(lower_exp), lower=True),
        _outward_binary64(_tanh_from_exp(upper_exp), lower=False),
    )


def conditional_tanh_intervals_24d_math(
    centers: tuple[float, ...], state_error_2norm: float,
) -> tuple[tuple[float, float], ...]:
    """Return 24 marginal intervals from an already certified joint L2 ball.

    The caller must supply a bound on the *whole* state error ||z-y||_2.
    Each coordinate then has |z_i-y_i| <= state_error_2norm. The returned
    marginal intervals do not assert that every combination of endpoints
    belongs to the joint ball, nor do they certify the supplied bound.
    """
    if not isinstance(centers, tuple) or len(centers) != 24:
        raise ValueError("tanh readout requires a tuple of exactly 24 centers")
    return tuple(conditional_tanh_interval_math(y, state_error_2norm)
                 for y in centers)
