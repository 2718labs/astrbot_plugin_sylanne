"""Conditional C·tanh(z) math for a loaded D04 readout candidate.

This propagates a caller-supplied joint state error through the loaded matrix.
It does not authenticate that error, the installation, a graph source, a native
trajectory, or product admission.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import math

from .d04_tanh_readout_asset import D04LoadedTanhReadoutAsset, TRANSFORM
from .tanh_interval import _outward_binary64, conditional_tanh_intervals_24d_math


@dataclass(frozen=True, slots=True)
class D04ConditionalTanhOutputInterval:
    output_id: str
    axis_id: str
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class D04ConditionalTanhReadoutMath:
    asset_sha256: str
    readout_id: str
    state_centers: tuple[float, ...]
    state_error_2norm: float
    tanh_marginals: tuple[tuple[float, float], ...]
    outputs: tuple[D04ConditionalTanhOutputInterval, ...]
    status: str = "conditional_math_only"


def run_d04_conditional_tanh_readout_math(
    asset: D04LoadedTanhReadoutAsset,
    state_centers: tuple[float, ...],
    state_error_2norm: float,
) -> D04ConditionalTanhReadoutMath:
    """Enclose each row of C·tanh(z), given ||z-state_centers||₂ <= error.

    Each nonnegative row weight preserves the direction of its coordinate
    interval. Products and sums of the recorded binary64 weights and tanh
    marginal endpoints are exact Fractions; only each final output endpoint
    rounds outward to binary64. The result contains marginal output bounds,
    not a claim that all row extremes occur at one state in the joint ball.
    """
    if type(asset) is not D04LoadedTanhReadoutAsset or len(asset.rows) != 24:
        raise ValueError("D04 conditional readout requires a loaded 24-row asset")
    for row in asset.rows:
        weights = row.coefficients
        if (row.transform != TRANSFORM or len(weights) != 24
                or any(type(weight) is not float or not math.isfinite(weight)
                       or not 0 <= weight <= 1.0e6 for weight in weights)):
            raise ValueError("D04 conditional readout requires finite nonnegative 24D rows")

    marginals = conditional_tanh_intervals_24d_math(state_centers, state_error_2norm)
    outputs = []
    for row in asset.rows:
        exact_weights = tuple(Fraction.from_float(weight) for weight in row.coefficients)
        exact_lower = sum((weight * Fraction.from_float(interval[0])
                           for weight, interval in zip(exact_weights, marginals)), Fraction())
        exact_upper = sum((weight * Fraction.from_float(interval[1])
                           for weight, interval in zip(exact_weights, marginals)), Fraction())
        outputs.append(D04ConditionalTanhOutputInterval(
            row.output_id, row.axis_id,
            _outward_binary64(exact_lower, lower=True),
            _outward_binary64(exact_upper, lower=False),
        ))
    return D04ConditionalTanhReadoutMath(
        asset.asset_sha256, asset.readout_id, state_centers, state_error_2norm,
        marginals, tuple(outputs),
    )
