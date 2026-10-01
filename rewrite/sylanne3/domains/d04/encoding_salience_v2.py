"""Conditional encoding-time salience/tone from an adopted D04 joint output.

The numeric features have the fixed, unvalidated meaning declared by the
installed interval policy. This pure module does not authenticate adoption,
the live Owner fence, source rights, or an installed package; W01 must provide
and verify those premises before a result can be committed or used by C04.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from fractions import Fraction
import math
import struct

from ...graph_types import AtomKey
from ...native_runtime.d04_tanh_readout_asset import D04LoadedTanhReadoutAsset, TRANSFORM
from ...runtime_contracts import NamespaceId, canonical_digest
from .affect import FeelingState
from .authored_lineage_v3 import AuthoredFeelingStateV1
from .interval_projection_v2 import (
    D04AxisProjectionIntervalV2, D04IntervalProjectionPolicyV2,
    D04ProjectionMemberBindingV2, D04AuthoredProjectionMemberBindingV3, _float_interval,
)
from .joint_state_output_v1 import (
    JointStateAxisOutputV1, JointStateOutputOriginalV1,
)
from .numeric_coupling import REGISTERED_AXIS_IDS


class D04EncodingSalienceHold(ValueError):
    """The authenticated numeric premises do not determine a bounded feature."""


@dataclass(frozen=True, slots=True)
class D04EncodingSalienceProjectionV2:
    namespace: NamespaceId
    output_original_digest: str
    output_write_set_digest: str
    component_digest: str
    native_manifest_sha256: str
    full_transcript_sha256: str
    readout_sha256: str
    policy_id: str
    policy_version: str
    policy_digest: str
    member_bindings: tuple[D04ProjectionMemberBindingV2 | D04AuthoredProjectionMemberBindingV3, ...]
    normalized_axes: tuple[D04AxisProjectionIntervalV2, ...]
    salience_interval: tuple[float, float]
    tone_interval: tuple[float, float]
    proof_digest: str
    semantic_calibration: str = "unvalidated"
    status: str = "conditional_requires_w01_current_adopted_output"


def _fraction(value: float) -> Fraction:
    if type(value) is not float or not math.isfinite(value):
        raise D04EncodingSalienceHold("certified axis bound is not finite binary64")
    return Fraction.from_float(value)


def _bits(value: float) -> bytes:
    return struct.pack("!d", value)


def _verify_readout(asset: D04LoadedTanhReadoutAsset,
                    policy: D04IntervalProjectionPolicyV2) -> None:
    if (type(asset) is not D04LoadedTanhReadoutAsset
            or asset.status != "asset_loaded_candidate"
            or asset.readout_id != policy.readout_id
            or asset.readout_version != policy.readout_version
            or asset.asset_sha256 != policy.readout_sha256
            or asset.axis_ids != REGISTERED_AXIS_IDS
            or len(asset.rows) != 24):
        raise D04EncodingSalienceHold("installed readout identity differs")
    for index, row in enumerate(asset.rows):
        if (row.axis_id != REGISTERED_AXIS_IDS[index]
                or row.output_version != asset.readout_version
                or row.transform != TRANSFORM
                or len(row.coefficients) != 24
                or tuple(_bits(weight) for weight in row.coefficients)
                   != tuple(_bits(1.0 if pos == index else 0.0)
                            for pos in range(24))):
            raise D04EncodingSalienceHold("readout is not exact identity tanh")


def project_encoding_salience_from_joint_output_v2(
    *, output_original: JointStateOutputOriginalV1,
    asset: D04LoadedTanhReadoutAsset,
    policy: D04IntervalProjectionPolicyV2,
    member_bindings: tuple[D04ProjectionMemberBindingV2 | D04AuthoredProjectionMemberBindingV3, ...],
) -> D04EncodingSalienceProjectionV2:
    """Derive features from certified full-output axes, never caller intervals.

    W01 must check that ``output_original`` is its current durable, Owner-fenced
    original and that ``member_bindings`` are all encoding baseline feelings.
    """
    if (type(output_original) is not JointStateOutputOriginalV1
            or type(policy) is not D04IntervalProjectionPolicyV2
            or type(member_bindings) is not tuple or not member_bindings
            or any(type(item) is not (
                       D04AuthoredProjectionMemberBindingV3
                       if output_original.schema == "d04.joint-state-output.v2"
                       else D04ProjectionMemberBindingV2)
                   for item in member_bindings)):
        raise D04EncodingSalienceHold("typed joint output and feeling set are required")
    original_fields = {field.name: getattr(output_original, field.name)
                       for field in fields(output_original)
                       if field.name not in {"original_digest", "status"}}
    if (output_original.schema not in {"d04.joint-state-output.v1", "d04.joint-state-output.v2"}
            or output_original.status != "issued_pending_w01_atomic_joint_adoption"
            or canonical_digest(original_fields) != output_original.original_digest
            or output_original.axis_ids != REGISTERED_AXIS_IDS
            or output_original.readout_id != policy.readout_id
            or output_original.readout_version != policy.readout_version
            or output_original.readout_sha256 != policy.readout_sha256
            or output_original.native_abi_version != 2
            or output_original.native_manifest_sha256 == ""
            or type(output_original.namespace) is not NamespaceId
            or tuple(item.checkpoint_ref for item in output_original.members)
               != output_original.member_refs):
        raise D04EncodingSalienceHold("joint output original identity differs")
    _verify_readout(asset, policy)
    refs = tuple(item.checkpoint_ref for item in member_bindings)
    if refs != tuple(sorted(set(refs))):
        raise D04EncodingSalienceHold("feeling members are missing or reordered")
    members = {item.checkpoint_ref: item for item in output_original.members}
    normalized: list[tuple[Fraction, Fraction]] = []
    axes: list[D04AxisProjectionIntervalV2] = []
    width = _fraction(policy.max_axis_width)
    for binding in member_bindings:
        member = members.get(binding.checkpoint_ref)
        if (member is None or member.kind != "feeling"
                or type(member.next_state) is not (
                    AuthoredFeelingStateV1 if output_original.schema == "d04.joint-state-output.v2"
                    else FeelingState)
                or binding.checkpoint_revision
                   != member.predecessor_checkpoint_revision + 1
                or binding.feeling_ref != member.predecessor_state_ref
                or binding.feeling_revision
                   != member.predecessor_state_revision + 1
                or AtomKey.from_token(binding.feeling_ref).owner
                   != AtomKey.from_token(binding.checkpoint_ref).owner
                or NamespaceId.from_key(AtomKey.from_token(binding.feeling_ref))
                   != output_original.namespace
                or tuple(axis for axis, _ in member.next_state.coordinates)
                   != REGISTERED_AXIS_IDS
                or len(member.axes) != 24):
            raise D04EncodingSalienceHold("selected feeling is not a joint output member")
        for axis_id, row, interval in zip(
                REGISTERED_AXIS_IDS, asset.rows, member.axes):
            if (type(interval) is not JointStateAxisOutputV1
                    or interval.axis_id != axis_id
                    or interval.output_id != row.output_id):
                raise D04EncodingSalienceHold("certified output axis differs")
            low, high = _fraction(interval.certified_lower), _fraction(interval.certified_upper)
            representative = _fraction(interval.representative)
            error = _fraction(interval.representative_error)
            if (not -1 <= low <= representative <= high <= 1
                    or high - low > width
                    or error < max(representative - low, high - representative)
                    or _bits(interval.representative)
                       != _bits(dict(member.next_state.coordinates)[axis_id])):
                raise D04EncodingSalienceHold("certified axis interval or state differs")
            normalized.append((low, high))
            axes.append(D04AxisProjectionIntervalV2(
                binding.checkpoint_ref, axis_id, row.output_id,
                interval.certified_lower, interval.certified_upper,
            ))
    count = len(normalized)
    absolute = tuple((Fraction(0) if low <= 0 <= high else min(abs(low), abs(high)),
                      max(abs(low), abs(high))) for low, high in normalized)
    salience = (sum((low for low, _ in absolute), Fraction()) / count,
                sum((high for _, high in absolute), Fraction()) / count)
    gain = tuple(pair for index, pair in enumerate(normalized)
                 if index % 24 in (0, 1, 2))
    loss = tuple(pair for index, pair in enumerate(normalized)
                 if index % 24 in (3, 4, 5))
    denominator = 6 * len(member_bindings)
    tone = ((sum((low for low, _ in gain), Fraction())
             - sum((high for _, high in loss), Fraction())) / denominator,
            (sum((high for _, high in gain), Fraction())
             - sum((low for low, _ in loss), Fraction())) / denominator)
    projection_width = _fraction(policy.max_projection_width)
    if (salience[1] - salience[0] > projection_width
            or tone[1] - tone[0] > projection_width):
        raise D04EncodingSalienceHold("projected feature interval is too wide")
    salience = _float_interval(max(Fraction(0), salience[0]),
                               min(Fraction(1), salience[1]))
    tone = _float_interval(max(Fraction(-1), tone[0]),
                           min(Fraction(1), tone[1]))
    payload = dict(
        namespace=output_original.namespace,
        output_original_digest=output_original.original_digest,
        output_write_set_digest=output_original.write_set_digest,
        component_digest=output_original.component_digest,
        native_manifest_sha256=output_original.native_manifest_sha256,
        full_transcript_sha256=output_original.full_transcript_sha256,
        readout_sha256=asset.asset_sha256,
        policy_id=policy.policy_id, policy_version=policy.version,
        policy_digest=canonical_digest(asdict(policy)),
        member_bindings=member_bindings, normalized_axes=tuple(axes),
        salience_interval=salience, tone_interval=tone,
    )
    return D04EncodingSalienceProjectionV2(
        **payload, proof_digest=canonical_digest(payload),
    )


def verify_encoding_salience_from_joint_output_v2(
    projection: D04EncodingSalienceProjectionV2, *,
    output_original: JointStateOutputOriginalV1,
    asset: D04LoadedTanhReadoutAsset,
    policy: D04IntervalProjectionPolicyV2,
    member_bindings: tuple[D04ProjectionMemberBindingV2 | D04AuthoredProjectionMemberBindingV3, ...],
) -> bool:
    """Pure exact rederivation; adoption and package trust remain W01's duty."""
    if type(projection) is not D04EncodingSalienceProjectionV2:
        return False
    try:
        expected = project_encoding_salience_from_joint_output_v2(
            output_original=output_original, asset=asset, policy=policy,
            member_bindings=member_bindings,
        )
    except (TypeError, ValueError, KeyError, OverflowError):
        return False
    return projection == expected


__all__ = [
    "D04EncodingSalienceHold", "D04EncodingSalienceProjectionV2",
    "project_encoding_salience_from_joint_output_v2",
    "verify_encoding_salience_from_joint_output_v2",
]
