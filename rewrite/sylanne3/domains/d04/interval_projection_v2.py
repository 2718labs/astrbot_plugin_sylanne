"""Unsigned D04 interval projection from a complete joint numeric receipt.

The fixed readout supplies numeric axes, not psychological calibration. W01
must authenticate the package, current graph/adoption, and any mood evidence
before an issuer may use this candidate as a known encoding projection.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from fractions import Fraction
import math

from ...graph_types import AtomKey, GraphVersion
from ...native_runtime.d04_tanh_readout_asset import D04LoadedTanhReadoutAsset
from ...native_runtime.tanh_interval import _outward_binary64
from ...runtime_contracts import NamespaceId, canonical_digest
from .joint_numeric_receipt import (
    D04JointNumericReceiptCandidateV1, D04NumericOutputIntervalV1,
)
from .numeric_coupling import REGISTERED_AXIS_IDS


class D04IntervalProjectionHold(ValueError):
    """An interval or identity cannot support the declared projection."""


@dataclass(frozen=True, slots=True)
class D04IntervalProjectionPolicyV2:
    policy_id: str
    readout_id: str
    readout_version: str
    readout_sha256: str
    max_axis_width: float
    max_projection_width: float
    mood_salience_gain: float = 0.0
    mood_tone_gain: float = 0.0
    block_selection: str = "all_baseline_then_feeling_versions"
    aggregation: str = "mean_abs_24b_gain_loss_contrast_6b"
    stage_contract: str = "encoding_baseline_then_recollection_current_mood"
    version: str = "d04.interval-projection.v2"
    semantic_calibration: str = "unvalidated"

    def __post_init__(self) -> None:
        if (not all(type(value) is str and value for value in (
                self.policy_id, self.readout_id, self.readout_version))
                or type(self.readout_sha256) is not str
                or len(self.readout_sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.readout_sha256)
                or self.block_selection != "all_baseline_then_feeling_versions"
                or self.aggregation != "mean_abs_24b_gain_loss_contrast_6b"
                or self.stage_contract != "encoding_baseline_then_recollection_current_mood"
                or self.version != "d04.interval-projection.v2"
                or self.semantic_calibration != "unvalidated"):
            raise D04IntervalProjectionHold("projection policy identity differs")
        for name, limit in (("max_axis_width", 2.0),
                            ("max_projection_width", 1.0)):
            value = getattr(self, name)
            if type(value) is not float or not math.isfinite(value) or not 0 < value <= limit:
                raise D04IntervalProjectionHold(f"{name} is outside its declared range")
        for name in ("mood_salience_gain", "mood_tone_gain"):
            value = getattr(self, name)
            if type(value) is not float or not math.isfinite(value) or abs(value) > 1:
                raise D04IntervalProjectionHold(f"{name} is outside [-1, 1]")


@dataclass(frozen=True, slots=True)
class D04VerifiedMoodIntervalPremiseV2:
    """W01-supplied premise; constructing this DTO cannot authenticate it."""

    namespace: NamespaceId
    checkpoint_ref: str
    numeric_receipt_digest: str
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    role_start: float
    role_end: float
    salience_interval: tuple[float, float]
    tone_interval: tuple[float, float]
    status: str = "conditional_w01_verified_mood_interval"


@dataclass(frozen=True, slots=True)
class D04ProjectionMemberBindingV2:
    """A W01-checked checkpoint-to-committed-feeling correspondence."""

    checkpoint_ref: str
    checkpoint_revision: int
    feeling_ref: str
    feeling_revision: int

    def __post_init__(self) -> None:
        try:
            checkpoint = AtomKey.from_token(self.checkpoint_ref)
            feeling = AtomKey.from_token(self.feeling_ref)
        except (TypeError, ValueError) as exc:
            raise D04IntervalProjectionHold("member binding has invalid graph refs") from exc
        if (checkpoint.type_name != "d04.numeric_checkpoint.v1"
                or feeling.type_name != "d04.feeling_state.v1"
                or checkpoint.owner != feeling.owner
                or checkpoint.owner.kind != "persona"
                or type(self.checkpoint_revision) is not int
                or self.checkpoint_revision < 1
                or type(self.feeling_revision) is not int
                or self.feeling_revision < 1):
            raise D04IntervalProjectionHold("member binding has invalid type or revision")


@dataclass(frozen=True, slots=True)
class D04AuthoredProjectionMemberBindingV3:
    """Exact authored checkpoint/Feeling pair; no legacy type relaxation."""

    checkpoint_ref: str
    checkpoint_revision: int
    feeling_ref: str
    feeling_revision: int

    def __post_init__(self) -> None:
        try:
            checkpoint = AtomKey.from_token(self.checkpoint_ref)
            feeling = AtomKey.from_token(self.feeling_ref)
        except (TypeError, ValueError) as exc:
            raise D04IntervalProjectionHold("authored member binding has invalid refs") from exc
        if (checkpoint.type_name != "d04.numeric_checkpoint.v2"
                or feeling.type_name != "d04.authored_feeling_state.v1"
                or checkpoint.owner != feeling.owner
                or checkpoint.owner.kind != "persona"
                or type(self.checkpoint_revision) is not int
                or self.checkpoint_revision < 1
                or type(self.feeling_revision) is not int
                or self.feeling_revision < 1):
            raise D04IntervalProjectionHold("authored member binding has invalid type or revision")


@dataclass(frozen=True, slots=True)
class D04AxisProjectionIntervalV2:
    checkpoint_ref: str
    axis_id: str
    output_id: str
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class D04IntervalProjectionCandidateV2:
    namespace: NamespaceId
    member_bindings: tuple[D04ProjectionMemberBindingV2, ...]
    then_feeling_versions: tuple[GraphVersion, ...]
    numeric_receipt_digest: str
    component_digest: str
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    role_start: float
    role_end: float
    readout_id: str
    readout_version: str
    readout_sha256: str
    policy_id: str
    policy_version: str
    policy_digest: str
    normalized_axes: tuple[D04AxisProjectionIntervalV2, ...]
    salience_interval: tuple[float, float]
    tone_interval: tuple[float, float]
    proof_digest: str
    stage: str = "encoding_baseline"
    semantic_calibration: str = "unvalidated"
    status: str = "unsigned_hold_for_w01_projection_issuer"

    def __post_init__(self) -> None:
        if (self.stage != "encoding_baseline"
                or self.semantic_calibration != "unvalidated"
                or self.status != "unsigned_hold_for_w01_projection_issuer"):
            raise D04IntervalProjectionHold("candidate cannot grant a known projection")


@dataclass(frozen=True, slots=True)
class D04VerifiedBaselineIntervalPremiseV2:
    """W01-verified encoding baseline; this DTO alone is no credential."""

    namespace: NamespaceId
    baseline_receipt_ref: str
    baseline_receipt_revision: int
    baseline_receipt_digest: str
    projection_proof_digest: str
    policy_digest: str
    readout_sha256: str
    salience_interval: tuple[float, float]
    tone_interval: tuple[float, float]
    status: str = "conditional_w01_verified_encoding_baseline"


@dataclass(frozen=True, slots=True)
class D04RecollectionConditioningCandidateV2:
    namespace: NamespaceId
    baseline_receipt_ref: str
    baseline_receipt_revision: int
    baseline_receipt_digest: str
    baseline_projection_proof_digest: str
    mood_checkpoint_ref: str
    mood_numeric_receipt_digest: str
    mood_graph_incarnation: str
    mood_graph_revision: int
    mood_graph_epoch: int
    mood_access_epoch: int
    mood_delete_epoch: int
    policy_digest: str
    readout_sha256: str
    salience_interval: tuple[float, float]
    tone_interval: tuple[float, float]
    proof_digest: str
    stage: str = "recollection_current_mood_conditioned"
    semantic_calibration: str = "unvalidated"
    status: str = "unsigned_hold_for_w01_recollection_issuer"

    def __post_init__(self) -> None:
        if (self.stage != "recollection_current_mood_conditioned"
                or self.semantic_calibration != "unvalidated"
                or self.status != "unsigned_hold_for_w01_recollection_issuer"):
            raise D04IntervalProjectionHold("candidate cannot grant a recollection projection")


def _fraction(value: float) -> Fraction:
    if type(value) is not float or not math.isfinite(value):
        raise D04IntervalProjectionHold("projection needs finite binary64 intervals")
    return Fraction.from_float(value)


def _interval(value: tuple[float, float], low: int, high: int) -> tuple[Fraction, Fraction]:
    if type(value) is not tuple or len(value) != 2:
        raise D04IntervalProjectionHold("mood interval is not a pair")
    a, b = (_fraction(item) for item in value)
    if not low <= a <= b <= high:
        raise D04IntervalProjectionHold("mood interval exceeds its declared range")
    return a, b


def _clamp(value: Fraction, low: int, high: int) -> Fraction:
    return min(Fraction(high), max(Fraction(low), value))


def _float_interval(low: Fraction, high: Fraction) -> tuple[float, float]:
    try:
        return (_outward_binary64(low, lower=True),
                _outward_binary64(high, lower=False))
    except (OverflowError, ValueError) as exc:
        raise D04IntervalProjectionHold("projected interval overflows binary64") from exc


def _add_scaled(base: tuple[Fraction, Fraction],
                other: tuple[Fraction, Fraction], gain: float) -> tuple[Fraction, Fraction]:
    scale = _fraction(gain)
    a, b = (scale * item for item in other)
    return base[0] + min(a, b), base[1] + max(a, b)


def _receipt_digest(receipt: D04JointNumericReceiptCandidateV1) -> str:
    return canonical_digest({item.name: getattr(receipt, item.name)
                             for item in fields(receipt)
                             if item.name not in {"receipt_digest", "status"}})


def project_joint_interval_candidate_v2(
    *, receipt: D04JointNumericReceiptCandidateV1,
    asset: D04LoadedTanhReadoutAsset,
    policy: D04IntervalProjectionPolicyV2,
    member_bindings: tuple[D04ProjectionMemberBindingV2, ...],
    then_feeling_versions: tuple[GraphVersion, ...],
) -> D04IntervalProjectionCandidateV2:
    """Use exact binary64 rationals and round outward only at output bounds.

    Salience is the mean absolute normalized axis output across all 24B rows.
    Tone is gain-engagement minus loss-response over all 6B rows. These are
    narrowly declared numeric features and have unvalidated semantics. Mood
    belongs to recall-time conditioning and never changes this encoding base.
    """
    if (type(receipt) is not D04JointNumericReceiptCandidateV1
            or type(asset) is not D04LoadedTanhReadoutAsset
            or type(policy) is not D04IntervalProjectionPolicyV2
            or type(member_bindings) is not tuple or not member_bindings
            or type(then_feeling_versions) is not tuple or not then_feeling_versions
            or any(type(item) is not D04ProjectionMemberBindingV2
                   for item in member_bindings)
            or any(type(item) is not GraphVersion for item in then_feeling_versions)):
        raise D04IntervalProjectionHold("projection needs typed joint inputs")
    selected_refs = tuple(item.checkpoint_ref for item in member_bindings)
    selected_feelings = tuple(GraphVersion(
        AtomKey.from_token(item.feeling_ref), item.feeling_revision,
    ) for item in member_bindings)
    if (selected_refs != tuple(sorted(set(selected_refs)))
            or selected_feelings != then_feeling_versions
            or len({item.key for item in selected_feelings}) != len(selected_feelings)
            or any(item.revision < 1 for item in selected_feelings)
            or any((item.key.owner.bot, item.key.owner.persona)
                   != receipt.namespace.as_tuple for item in selected_feelings)):
        raise D04IntervalProjectionHold("selected members omit or reorder baseline feelings")
    if (receipt.status != "unsigned_hold_for_w01_atomic_joint_adoption"
            or receipt.receipt_digest != _receipt_digest(receipt)
            or any(ref not in receipt.member_refs for ref in selected_refs)
            or tuple(item.checkpoint_ref for item in receipt.members) != receipt.member_refs
            or len(receipt.members) != len(receipt.member_refs)
            or asset.status != "asset_loaded_candidate"
            or asset.axis_ids != REGISTERED_AXIS_IDS
            or len(asset.rows) != len(REGISTERED_AXIS_IDS)
            or asset.readout_id != policy.readout_id
            or asset.readout_version != policy.readout_version
            or asset.asset_sha256 != policy.readout_sha256):
        raise D04IntervalProjectionHold("joint receipt or readout identity differs")
    normalized: list[tuple[Fraction, Fraction]] = []
    axis_rows = []
    members = {item.checkpoint_ref: item for item in receipt.members}
    for binding in member_bindings:
        member = members[binding.checkpoint_ref]
        if len(member.full) != len(REGISTERED_AXIS_IDS):
            raise D04IntervalProjectionHold("joint member lacks complete readout")
        for axis, row, output in zip(REGISTERED_AXIS_IDS, asset.rows, member.full):
            if (type(output) is not D04NumericOutputIntervalV1
                    or row.axis_id != axis or output.axis_id != axis
                    or row.output_id != output.output_id
                    or type(row.coefficients) is not tuple
                    or len(row.coefficients) != len(REGISTERED_AXIS_IDS)):
                raise D04IntervalProjectionHold("readout row or output axis differs")
            weights = tuple(_fraction(weight) for weight in row.coefficients)
            if any(weight < 0 for weight in weights):
                raise D04IntervalProjectionHold("readout row is not monotone")
            norm = sum(weights, Fraction())
            if norm <= 0:
                raise D04IntervalProjectionHold("readout row has zero L1 norm")
            lower, upper = _fraction(output.lower) / norm, _fraction(output.upper) / norm
            if lower > upper or upper - lower > _fraction(policy.max_axis_width):
                raise D04IntervalProjectionHold("readout axis interval is too wide")
            lower, upper = _clamp(lower, -1, 1), _clamp(upper, -1, 1)
            normalized.append((lower, upper))
            rounded = _float_interval(lower, upper)
            axis_rows.append(D04AxisProjectionIntervalV2(
                binding.checkpoint_ref, axis, row.output_id, *rounded,
            ))
    absolute = tuple((Fraction(0) if low <= 0 <= high else min(abs(low), abs(high)),
                      max(abs(low), abs(high))) for low, high in normalized)
    count = len(absolute)
    salience = (sum((low for low, _ in absolute), Fraction()) / count,
                sum((high for _, high in absolute), Fraction()) / count)
    gain = tuple(item for index, item in enumerate(normalized)
                 if index % 24 in (0, 1, 2))
    loss = tuple(item for index, item in enumerate(normalized)
                 if index % 24 in (3, 4, 5))
    contrast_denominator = 6 * len(member_bindings)
    tone = ((sum((low for low, _ in gain), Fraction())
             - sum((high for _, high in loss), Fraction())) / contrast_denominator,
            (sum((high for _, high in gain), Fraction())
             - sum((low for low, _ in loss), Fraction())) / contrast_denominator)
    width = _fraction(policy.max_projection_width)
    if salience[1] - salience[0] > width or tone[1] - tone[0] > width:
        raise D04IntervalProjectionHold("projected interval is too wide")
    salience = _float_interval(*(_clamp(value, 0, 1) for value in salience))
    tone = _float_interval(*(_clamp(value, -1, 1) for value in tone))
    result = dict(
        namespace=receipt.namespace, member_bindings=member_bindings,
        then_feeling_versions=then_feeling_versions,
        numeric_receipt_digest=receipt.receipt_digest,
        component_digest=receipt.component_digest,
        graph_incarnation=receipt.graph_incarnation,
        graph_revision=receipt.graph_revision, graph_epoch=receipt.graph_epoch,
        access_epoch=receipt.access_epoch, delete_epoch=receipt.delete_epoch,
        role_start=receipt.role_start, role_end=receipt.role_end,
        readout_id=asset.readout_id, readout_version=asset.readout_version,
        readout_sha256=asset.asset_sha256, policy_id=policy.policy_id,
        policy_version=policy.version, policy_digest=canonical_digest(asdict(policy)),
        normalized_axes=tuple(axis_rows),
        salience_interval=salience, tone_interval=tone,
    )
    return D04IntervalProjectionCandidateV2(
        **result, proof_digest=canonical_digest(result),
    )


def condition_verified_baseline_for_recollection_v2(
    *, baseline: D04VerifiedBaselineIntervalPremiseV2,
    mood: D04VerifiedMoodIntervalPremiseV2,
    policy: D04IntervalProjectionPolicyV2,
) -> D04RecollectionConditioningCandidateV2:
    """Apply the current verified mood interval after encoding has finished."""
    if (type(baseline) is not D04VerifiedBaselineIntervalPremiseV2
            or type(mood) is not D04VerifiedMoodIntervalPremiseV2
            or type(policy) is not D04IntervalProjectionPolicyV2):
        raise D04IntervalProjectionHold("recollection needs typed verified premises")
    policy_digest = canonical_digest(asdict(policy))
    digests = (baseline.baseline_receipt_digest, baseline.projection_proof_digest,
               mood.numeric_receipt_digest)
    if (baseline.status != "conditional_w01_verified_encoding_baseline"
            or mood.status != "conditional_w01_verified_mood_interval"
            or type(baseline.namespace) is not NamespaceId
            or mood.namespace != baseline.namespace
            or type(baseline.baseline_receipt_ref) is not str
            or not baseline.baseline_receipt_ref
            or type(baseline.baseline_receipt_revision) is not int
            or baseline.baseline_receipt_revision < 1
            or type(mood.checkpoint_ref) is not str or not mood.checkpoint_ref
            or baseline.policy_digest != policy_digest
            or baseline.readout_sha256 != policy.readout_sha256
            or any(type(value) is not str or len(value) != 64
                   or any(c not in "0123456789abcdef" for c in value)
                   for value in digests)):
        raise D04IntervalProjectionHold("verified baseline or current mood identity differs")
    salience = _add_scaled(
        _interval(baseline.salience_interval, 0, 1),
        _interval(mood.salience_interval, 0, 1), policy.mood_salience_gain,
    )
    tone = _add_scaled(
        _interval(baseline.tone_interval, -1, 1),
        _interval(mood.tone_interval, -1, 1), policy.mood_tone_gain,
    )
    width = _fraction(policy.max_projection_width)
    if salience[1] - salience[0] > width or tone[1] - tone[0] > width:
        raise D04IntervalProjectionHold("recollection interval is too wide")
    salience = _float_interval(*(_clamp(value, 0, 1) for value in salience))
    tone = _float_interval(*(_clamp(value, -1, 1) for value in tone))
    result = dict(
        namespace=baseline.namespace,
        baseline_receipt_ref=baseline.baseline_receipt_ref,
        baseline_receipt_revision=baseline.baseline_receipt_revision,
        baseline_receipt_digest=baseline.baseline_receipt_digest,
        baseline_projection_proof_digest=baseline.projection_proof_digest,
        mood_checkpoint_ref=mood.checkpoint_ref,
        mood_numeric_receipt_digest=mood.numeric_receipt_digest,
        mood_graph_incarnation=mood.graph_incarnation,
        mood_graph_revision=mood.graph_revision,
        mood_graph_epoch=mood.graph_epoch,
        mood_access_epoch=mood.access_epoch, mood_delete_epoch=mood.delete_epoch,
        policy_digest=policy_digest, readout_sha256=policy.readout_sha256,
        salience_interval=salience, tone_interval=tone,
    )
    return D04RecollectionConditioningCandidateV2(
        **result, proof_digest=canonical_digest(result),
    )


__all__ = [
    "D04IntervalProjectionHold", "D04IntervalProjectionPolicyV2",
    "D04VerifiedMoodIntervalPremiseV2", "D04ProjectionMemberBindingV2",
    "D04AuthoredProjectionMemberBindingV3",
    "D04VerifiedBaselineIntervalPremiseV2",
    "D04RecollectionConditioningCandidateV2",
    "D04AxisProjectionIntervalV2",
    "D04IntervalProjectionCandidateV2", "project_joint_interval_candidate_v2",
    "condition_verified_baseline_for_recollection_v2",
]
