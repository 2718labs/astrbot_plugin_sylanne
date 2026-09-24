"""Versioned, non-authoritative affect projection for first-ingress details.

The model extracts literal quotes and candidate meanings from source-only input.
D04 owns the encoding-time affect readout. This pure D06 operator combines them
without changing source bytes, fact eligibility, or C02 admission status.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ...graph_types import AtomKey
from ...memory_types import SourceRecord
from ...model_broker.first_ingress_encoding import FirstIngressEncodingCandidate
from ..d04.encoding_baseline import EncodingBaseline


def _bounded(value: object, lower: float, upper: float, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not lower <= value <= upper:
        raise ValueError(f"{label} must be finite and within [{lower}, {upper}]")
    return float(value)


def _interval(value: object, lower: float, upper: float, label: str) -> tuple[float, float]:
    if type(value) is not tuple or len(value) != 2:
        raise ValueError(f"{label} must be an interval")
    low = _bounded(value[0], lower, upper, label)
    high = _bounded(value[1], lower, upper, label)
    if low > high:
        raise ValueError(f"{label} must be ordered")
    return low, high


def _clip(value: float) -> float:
    return min(1.0, max(0.0, value))


@dataclass(frozen=True)
class EncodingProjectionPolicyV1:
    policy_ref: str
    policy_version: str
    salience_gain: float
    tone_magnitude_gain: float
    neutral_salience: float = 0.5
    schema: str = "d06.encoding_projection_policy.v1"

    def __post_init__(self) -> None:
        if (type(self.policy_ref) is not str or not self.policy_ref
                or type(self.policy_version) is not str or not self.policy_version
                or self.schema != "d06.encoding_projection_policy.v1"):
            raise ValueError("versioned encoding projection policy is required")
        for name in ("salience_gain", "tone_magnitude_gain", "neutral_salience"):
            object.__setattr__(self, name, _bounded(getattr(self, name), 0.0, 1.0, name))


@dataclass(frozen=True)
class EncodingAffectIntervals:
    """A numerical candidate; constructing it does not certify D04 provenance."""

    salience: tuple[float, float]
    tone: tuple[float, float]

    def __post_init__(self) -> None:
        object.__setattr__(self, "salience", _interval(self.salience, 0.0, 1.0, "salience"))
        object.__setattr__(self, "tone", _interval(self.tone, -1.0, 1.0, "tone"))


@dataclass(frozen=True)
class ProjectedEncodingDetail:
    quote: str
    model_salience: float
    subjective_weight_interval: tuple[float, float]
    affective_strength_interval: tuple[float, float]


@dataclass(frozen=True)
class EncodingProjectionCandidateV1:
    source_id: str
    source_kind: str
    assertion_status: str
    model_candidate: FirstIngressEncodingCandidate
    affect_intervals: EncodingAffectIntervals
    policy: EncodingProjectionPolicyV1
    details: tuple[ProjectedEncodingDetail, ...]
    baseline_ref: str | None = None
    baseline_revision: int | None = None
    readout_provenance: str = "supplied_counterfactual"
    status: str = "candidate_hold"
    schema: str = "d06.encoding_projection_candidate.v1"

    def __post_init__(self) -> None:
        if (self.schema != "d06.encoding_projection_candidate.v1"
                or self.status != "candidate_hold"
                or self.readout_provenance not in {
                    "supplied_counterfactual", "baseline_claim_requires_W01_verification",
                }
                or (self.baseline_ref is None) != (self.baseline_revision is None)):
            raise ValueError("encoding projection must remain a versioned HOLD candidate")


def project_encoding_candidate(
    source: SourceRecord,
    model_candidate: FirstIngressEncodingCandidate,
    affect: EncodingAffectIntervals,
    policy: EncodingProjectionPolicyV1,
) -> EncodingProjectionCandidateV1:
    """Apply one replayable policy without promoting model or mood to facts."""
    if (type(source) is not SourceRecord
            or type(model_candidate) is not FirstIngressEncodingCandidate
            or type(affect) is not EncodingAffectIntervals
            or type(policy) is not EncodingProjectionPolicyV1):
        raise TypeError("source, model candidate, affect intervals, and policy are required")
    if model_candidate.source_id != source.source_id or model_candidate.status != "candidate":
        raise ValueError("model candidate differs from the source")
    salience_low, salience_high = affect.salience
    tone_low, tone_high = affect.tone
    magnitude_low = 0.0 if tone_low <= 0 <= tone_high else min(abs(tone_low), abs(tone_high))
    magnitude_high = max(abs(tone_low), abs(tone_high))
    details = []
    for quote, raw_weight in model_candidate.quoted_details:
        if type(quote) is not str or not quote or quote not in source.text:
            raise ValueError("model quote must remain an exact source span")
        weight = _bounded(raw_weight, 0.0, 1.0, "model salience")
        projected = (
            _clip(weight + policy.salience_gain * (salience_low - policy.neutral_salience)
                  + policy.tone_magnitude_gain * magnitude_low),
            _clip(weight + policy.salience_gain * (salience_high - policy.neutral_salience)
                  + policy.tone_magnitude_gain * magnitude_high),
        )
        strength = (
            _clip(weight * (policy.salience_gain * salience_low
                            + policy.tone_magnitude_gain * magnitude_low)),
            _clip(weight * (policy.salience_gain * salience_high
                            + policy.tone_magnitude_gain * magnitude_high)),
        )
        details.append(ProjectedEncodingDetail(quote, weight, projected, strength))
    return EncodingProjectionCandidateV1(
        source.source_id,
        source.source_kind, source.assertion_status, model_candidate, affect,
        policy, tuple(details),
    )


def project_committed_baseline_candidate(
    source: SourceRecord,
    model_candidate: FirstIngressEncodingCandidate,
    baseline: EncodingBaseline,
    baseline_ref: str,
    baseline_revision: int,
    policy: EncodingProjectionPolicyV1,
) -> EncodingProjectionCandidateV1:
    """Fail closed until D04 admits known intervals; W01 still owns trust/CAS."""
    if type(baseline) is not EncodingBaseline:
        raise TypeError("D04 encoding baseline is required")
    if (type(baseline_ref) is not str
            or type(baseline_revision) is not int or baseline_revision < 1):
        raise ValueError("committed baseline key and revision are required")
    key = AtomKey.from_token(baseline_ref)
    source_namespace = AtomKey.from_token(baseline.source_refs[0]).owner
    if (key.type_name != "d04.encoding_baseline.v1"
            or (key.owner.bot, key.owner.persona) !=
            (source_namespace.bot, source_namespace.persona)):
        raise ValueError("D04 baseline reference has the wrong graph type")
    if (baseline.projection_policy_ref != policy.policy_ref
            or baseline.projection_policy_version != policy.policy_version):
        raise ValueError("projection policy differs from D04 baseline")
    if baseline.salience_interval is None or baseline.tone_interval is None:
        raise ValueError("D04 certified encoding affect intervals are unavailable; HOLD")
    if not any(AtomKey.from_token(ref).owner.subject == source.source_id
               for ref in baseline.source_refs):
        raise ValueError("D04 baseline does not cover the model source")
    projected = project_encoding_candidate(
        source, model_candidate,
        EncodingAffectIntervals(baseline.salience_interval, baseline.tone_interval),
        policy,
    )
    return EncodingProjectionCandidateV1(
        projected.source_id, projected.source_kind, projected.assertion_status,
        projected.model_candidate, projected.affect_intervals, projected.policy,
        projected.details, baseline_ref, baseline_revision,
        "baseline_claim_requires_W01_verification",
    )
