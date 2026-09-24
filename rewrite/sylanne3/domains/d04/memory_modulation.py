"""Candidate-only directional affect projection for source-bound memory details.

These intervals are calculation premises, not verified encoding baselines or
committed D06 memories. An issuer must separately qualify any product use.
"""

from __future__ import annotations

from dataclasses import dataclass
import math


def _interval(value: tuple[float, float], name: str, lower: float, upper: float) -> tuple[float, float]:
    if (type(value) is not tuple or len(value) != 2
            or any(type(x) not in (int, float) or not math.isfinite(x) for x in value)
            or not lower <= value[0] <= value[1] <= upper):
        raise ValueError(f"{name} must be an ordered finite interval in [{lower}, {upper}]")
    return float(value[0]), float(value[1])


def _id(value: str, name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


@dataclass(frozen=True)
class SourceDetail:
    source_ref: str
    source_text: str
    start: int
    end: int
    meaning_axis: str
    accessibility_interval: tuple[float, float]

    def __post_init__(self) -> None:
        _id(self.source_ref, "source_ref")
        _id(self.source_text, "source_text")
        _id(self.meaning_axis, "meaning_axis")
        if (type(self.start) is not int or type(self.end) is not int
                or not 0 <= self.start < self.end <= len(self.source_text)):
            raise ValueError("detail span must lie within the source text")
        object.__setattr__(self, "accessibility_interval", _interval(
            self.accessibility_interval, "accessibility_interval", 0.0, 1.0,
        ))

    @property
    def text(self) -> str:
        return self.source_text[self.start:self.end]


@dataclass(frozen=True)
class AffectIntervalPremise:
    readout_ref: str
    stage: str
    scheme_version: str
    policy_version: str
    axis_id: str
    value_interval: tuple[float, float]

    def __post_init__(self) -> None:
        for name in ("readout_ref", "scheme_version", "policy_version", "axis_id"):
            _id(getattr(self, name), name)
        if self.stage not in ("encoding", "recollection"):
            raise ValueError("stage must be encoding or recollection")
        object.__setattr__(self, "value_interval", _interval(
            self.value_interval, "value_interval", -1.0, 1.0,
        ))


@dataclass(frozen=True)
class DirectionalMemoryPolicy:
    scheme_version: str
    policy_version: str
    # Each registered coefficient links an affect axis to a source meaning axis.
    coefficients: tuple[tuple[str, str, float], ...]

    def __post_init__(self) -> None:
        _id(self.scheme_version, "scheme_version")
        _id(self.policy_version, "policy_version")
        if type(self.coefficients) is not tuple:
            raise ValueError("coefficients must be a frozen tuple")
        keys: set[tuple[str, str]] = set()
        for item in self.coefficients:
            if type(item) is not tuple or len(item) != 3:
                raise ValueError("coefficient must be (affect axis, meaning axis, gain)")
            axis, meaning, gain = item
            key = (_id(axis, "affect axis"), _id(meaning, "meaning axis"))
            if key in keys or type(gain) not in (int, float) or not math.isfinite(gain) or abs(gain) > 1:
                raise ValueError("coefficient keys must be unique and gains finite in [-1, 1]")
            keys.add(key)


@dataclass(frozen=True)
class DetailAccessibilityCandidate:
    source_ref: str
    start: int
    end: int
    meaning_axis: str
    readout_ref: str
    stage: str
    scheme_version: str
    policy_version: str
    affect_axis: str
    affect_interval: tuple[float, float]
    base_interval: tuple[float, float]
    accessibility_interval: tuple[float, float]


def project_detail_accessibility(
    detail: SourceDetail,
    premise: AffectIntervalPremise,
    policy: DirectionalMemoryPolicy,
) -> DetailAccessibilityCandidate:
    """Bound base accessibility plus a registered signed directional shift."""
    if not isinstance(detail, SourceDetail) or not isinstance(premise, AffectIntervalPremise) or not isinstance(policy, DirectionalMemoryPolicy):
        raise TypeError("projection requires D04 detail, interval premise, and frozen policy")
    if premise.scheme_version != policy.scheme_version or premise.policy_version != policy.policy_version:
        raise ValueError("affect scheme or policy version differs from directional policy")
    gain = next((gain for axis, meaning, gain in policy.coefficients
                 if axis == premise.axis_id and meaning == detail.meaning_axis), 0.0)
    low, high = detail.accessibility_interval
    if gain:
        shifts = (gain * premise.value_interval[0], gain * premise.value_interval[1])
        # Round each arithmetic step outward before clipping to [0, 1].
        lower_shift = math.nextafter(min(shifts), -math.inf)
        upper_shift = math.nextafter(max(shifts), math.inf)
        low = max(0.0, math.nextafter(low + lower_shift, -math.inf))
        high = min(1.0, math.nextafter(high + upper_shift, math.inf))
    return DetailAccessibilityCandidate(
        source_ref=detail.source_ref, start=detail.start, end=detail.end,
        meaning_axis=detail.meaning_axis, readout_ref=premise.readout_ref,
        stage=premise.stage, scheme_version=policy.scheme_version,
        policy_version=policy.policy_version, affect_axis=premise.axis_id,
        affect_interval=premise.value_interval,
        base_interval=detail.accessibility_interval,
        accessibility_interval=(low, high),
    )
