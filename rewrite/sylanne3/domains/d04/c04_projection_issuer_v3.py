"""Pure two-stage D04 C04 projection over W01-authenticated joint originals.

These values are conditional arithmetic proofs. Constructing or recomputing
one never authenticates a historical graph read or grants C04 adoption.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from fractions import Fraction
import math
import struct

from ...graph_types import AtomKey
from ...native_runtime.d04_tanh_readout_asset import D04LoadedTanhReadoutAsset
from ...native_runtime.tanh_interval import _outward_binary64
from ...runtime.d04_joint_advance_v2 import JointNumericOriginalV1
from ...runtime_contracts import NamespaceId, canonical_digest
from .affect import FeelingState, MoodField
from .authored_lineage_v3 import AuthoredFeelingStateV1, AuthoredMoodStateV1
from .encoding_baseline_v2 import ExactGraphRefV2, ProjectionNumericErrorV2
from .encoding_salience_v2 import (
    D04EncodingSalienceProjectionV2,
    _bits, _fraction, _verify_readout,
    project_encoding_salience_from_joint_output_v2,
)
from .interval_projection_v2 import (
    D04IntervalProjectionPolicyV2, D04ProjectionMemberBindingV2,
    D04AuthoredProjectionMemberBindingV3,
    _add_scaled, _clamp, _float_interval, _interval,
)
from .joint_state_output_v1 import (
    JointStateAxisOutputV1, JointStateOutputMemberV1, JointStateOutputOriginalV1,
)
from .numeric_coupling import REGISTERED_AXIS_IDS
from .numeric_drive import SourcedNumericDrive, sourced_numeric_drive_write


class D04C04ProjectionHold(ValueError):
    """A required installed, historical or numerical premise is unknown."""


@dataclass(frozen=True, slots=True)
class D04EncodingBaselineProofV3:
    baseline_id: str
    namespace: NamespaceId
    source_version: ExactGraphRefV2
    perspective_version: ExactGraphRefV2
    interpretation_versions: tuple[ExactGraphRefV2, ...]
    as_known_at: float
    feeling_bindings: tuple[D04ProjectionMemberBindingV2 | D04AuthoredProjectionMemberBindingV3, ...]
    source_drive_bindings: tuple[tuple[str, int, str], ...]
    joint_adoption_operation_id: str
    joint_adoption_receipt_digest: str
    numeric_original_digest: str
    output_original_digest: str
    output_write_set_digest: str
    numeric_receipt_digest: str
    native_manifest_sha256: str
    native_sha256: str
    full_transcript_sha256: str
    policy_digest: str
    readout_sha256: str
    numeric_error: ProjectionNumericErrorV2
    projection: D04EncodingSalienceProjectionV2
    proof_digest: str
    semantic_calibration: str = "unvalidated"
    status: str = "conditional_requires_w01_encoding_adoption"


@dataclass(frozen=True, slots=True)
class D04CurrentConditionedProjectionV3:
    namespace: NamespaceId
    source_version: ExactGraphRefV2
    baseline_id: str
    baseline_proof_digest: str
    baseline_receipt_ref: str
    baseline_receipt_revision: int
    baseline_receipt_digest: str
    mood_ref: str
    mood_revision: int
    mood_checkpoint_ref: str
    mood_checkpoint_revision: int
    mood_joint_adoption_operation_id: str
    mood_joint_adoption_receipt_digest: str
    mood_numeric_original_digest: str
    mood_output_original_digest: str
    mood_native_sha256: str
    mood_numeric_receipt_digest: str
    mood_numeric_error: ProjectionNumericErrorV2
    policy_digest: str
    readout_sha256: str
    base_salience_interval: tuple[float, float]
    base_tone_interval: tuple[float, float]
    mood_salience_interval: tuple[float, float]
    mood_tone_interval: tuple[float, float]
    conditioned_salience_interval: tuple[float, float]
    conditioned_tone_interval: tuple[float, float]
    conditioned_salience_error: float
    conditioned_tone_error: float
    proof_digest: str
    semantic_calibration: str = "unvalidated"
    evidence_weight_delta: float = 0.0
    scope: str = "subjective_association_only"
    status: str = "conditional_requires_w01_current_adoption"


def _receipt_content_digest(value: object) -> str:
    return canonical_digest({field.name: getattr(value, field.name)
                             for field in fields(value)
                             if field.name not in {"receipt_digest", "status"}})


def _original_content_digest(value: JointStateOutputOriginalV1) -> str:
    return canonical_digest({field.name: getattr(value, field.name)
                             for field in fields(value)
                             if field.name not in {"original_digest", "status"}})


def _joint_pair(output: JointStateOutputOriginalV1,
                numeric: JointNumericOriginalV1,
                policy: D04IntervalProjectionPolicyV2,
                asset: D04LoadedTanhReadoutAsset) -> None:
    if (type(output) is not JointStateOutputOriginalV1
            or type(numeric) is not JointNumericOriginalV1
            or type(policy) is not D04IntervalProjectionPolicyV2
            or type(numeric.verification.numeric_error) is not ProjectionNumericErrorV2
            or output.status != "issued_pending_w01_atomic_joint_adoption"
            or numeric.status != "w01_verified_durable_joint_numeric_original_v1"
            or output.original_digest != _original_content_digest(output)
            or numeric.receipt.receipt_digest != _receipt_content_digest(numeric.receipt)
            or output.namespace != numeric.receipt.namespace
            or output.operation_id != numeric.adoption_operation_id
            or numeric.original_ref not in output.member_refs
            or output.member_refs != numeric.receipt.member_refs
            or output.component_digest != numeric.receipt.component_digest
            or output.full_transcript_sha256
               != numeric.receipt.full_transcript_sha256
            or output.math_transcript_sha256
               != numeric.receipt.math_transcript_sha256
            or output.native_manifest_sha256
               != numeric.receipt.native_manifest_sha256
            or output.native_sha256 != numeric.receipt.native_sha256
            or output.native_abi_version != numeric.receipt.native_abi_version
            or numeric.verification.math_transcript_sha256
               != numeric.receipt.math_transcript_sha256
            or numeric.verification.policy_id != policy.policy_id
            or numeric.verification.policy_version != policy.version
            or numeric.verification.policy_digest != canonical_digest(asdict(policy))
            or numeric.verification.readout_id != asset.readout_id
            or numeric.verification.readout_version != asset.readout_version
            or numeric.verification.readout_sha256 != asset.asset_sha256
            or output.readout_sha256 != asset.asset_sha256):
        raise D04C04ProjectionHold("adopted output/numeric original pair differs")
    _verify_readout(asset, policy)


def _source_feeling_bindings(
    output: JointStateOutputOriginalV1,
    numeric: JointNumericOriginalV1,
    source: ExactGraphRefV2,
    drives: tuple[SourcedNumericDrive, ...],
) -> tuple[tuple[D04ProjectionMemberBindingV2 | D04AuthoredProjectionMemberBindingV3, ...],
           tuple[tuple[str, int, str], ...]]:
    if (source.key.type_name != "memory.source" or source.key.owner.kind != "event"
            or source.key.name != "record"
            or NamespaceId.from_key(source.key) != output.namespace):
        raise D04C04ProjectionHold("source is not an exact namespace source")
    drive_rows = numeric.receipt.source_versions
    if (not drive_rows or len({row[0] for row in drive_rows}) != len(drive_rows)
            or any(len(row) != 7 for row in drive_rows)
            or type(drives) is not tuple
            or len(drives) != len(drive_rows)
            or any(type(item) is not SourcedNumericDrive for item in drives)):
        raise D04C04ProjectionHold("joint source/drive index is incomplete")
    receipt_rows = {row[0]: row for row in drive_rows}
    members = {item.checkpoint_ref: item for item in output.members}
    seen = set()
    drive_members = {}
    selected = []
    target_drives = []
    for drive in drives:
        token = sourced_numeric_drive_write(drive).key.token
        row = receipt_rows.get(token)
        member = members.get(drive.checkpoint_ref)
        if (row is None or token in seen or member is None
                or (drive.drive_version, drive.source_ref, drive.source_revision,
                    drive.access_ref, drive.access_revision) != row[1:6]
                or drive.checkpoint_revision
                   != member.predecessor_checkpoint_revision):
            raise D04C04ProjectionHold("drive is not bound to exact joint member")
        seen.add(token)
        drive_members[token] = drive.checkpoint_ref
        state = member.next_state
        if type(state) in (FeelingState, AuthoredFeelingStateV1):
            if token not in state.active_driver_refs:
                raise D04C04ProjectionHold("Feeling lacks joint source drive")
        elif type(state) in (MoodField, AuthoredMoodStateV1):
            if drive.source_ref not in state.source_refs:
                raise D04C04ProjectionHold("Mood lacks joint source")
        else:
            raise D04C04ProjectionHold("joint output has unknown state type")
        if drive.source_ref != source.ref:
            continue
        if drive.source_revision != source.revision:
            raise D04C04ProjectionHold("source revision differs from joint drives")
        target_drives.append((token, drive.drive_version, drive.checkpoint_ref))
        if type(state) in (FeelingState, AuthoredFeelingStateV1):
            if (source.ref not in state.historical_source_refs
                    or member.kind != "feeling"):
                raise D04C04ProjectionHold("source/Feeling history differs")
            binding_type = (D04AuthoredProjectionMemberBindingV3
                            if type(state) is AuthoredFeelingStateV1
                            else D04ProjectionMemberBindingV2)
            selected.append(binding_type(
                member.checkpoint_ref, member.predecessor_checkpoint_revision + 1,
                member.predecessor_state_ref, member.predecessor_state_revision + 1,
            ))
    if seen != set(receipt_rows) or not target_drives:
        raise D04C04ProjectionHold("source revision differs from joint drives")
    for member in output.members:
        if type(member.next_state) in (FeelingState, AuthoredFeelingStateV1) and any(
                drive_members.get(token) != member.checkpoint_ref
                for token in member.next_state.active_driver_refs):
            raise D04C04ProjectionHold("Feeling contains an unbound joint drive")
    selected = tuple(sorted(set(selected), key=lambda item: item.checkpoint_ref))
    if (not selected or numeric.original_ref not in {
            item.checkpoint_ref for item in selected}
            or tuple(item.checkpoint_ref for item in selected)
               != tuple(sorted(item.checkpoint_ref for item in selected))):
        raise D04C04ProjectionHold("source has no complete ordered Feeling set")
    return selected, tuple(sorted(target_drives))


def _selected_numeric_error(
    source: ExactGraphRefV2,
    projection: D04EncodingSalienceProjectionV2,
    inherited: ProjectionNumericErrorV2,
) -> ProjectionNumericErrorV2:
    """Preserve state errors; recompute subset readout widths from original axes."""
    axes = projection.normalized_axes
    count = len(projection.member_bindings)
    if len(axes) != 24 * count:
        raise D04C04ProjectionHold("selected numerical axes are incomplete")
    salience = sum((_fraction(axis.upper) - _fraction(axis.lower)
                    for axis in axes), Fraction()) / (24 * count)
    tone = sum((_fraction(axis.upper) - _fraction(axis.lower)
                for index, axis in enumerate(axes) if index % 24 < 6),
               Fraction()) / (6 * count)
    salience_bound = _outward_binary64(salience, lower=False)
    tone_bound = _outward_binary64(tone, lower=False)
    proof = canonical_digest({
        "schema": "d04.c04-source-specific-numeric-error.v3",
        "source": (source.ref, source.revision),
        "projection": projection.proof_digest,
        "joint_numeric_proof": inherited.numeric_proof_digest,
        "inherited": inherited.inherited_state_error_2norm,
        "solve": inherited.solve_state_error_2norm,
        "salience_readout": salience_bound,
        "tone_readout": tone_bound,
    })
    return ProjectionNumericErrorV2(
        inherited.inherited_state_error_2norm,
        inherited.solve_state_error_2norm,
        salience_bound, tone_bound, proof,
    )


def issue_encoding_baseline_proof_v3(
    *, joint_operation_id: str, baseline_id: str,
    source_version: ExactGraphRefV2,
    perspective_version: ExactGraphRefV2,
    interpretation_versions: tuple[ExactGraphRefV2, ...],
    as_known_at: float,
    output_original: JointStateOutputOriginalV1,
    numeric_original: JointNumericOriginalV1,
    drives: tuple[SourcedNumericDrive, ...],
    asset: D04LoadedTanhReadoutAsset,
    policy: D04IntervalProjectionPolicyV2,
) -> D04EncodingBaselineProofV3:
    """Derive a historical source-specific Feeling baseline for W01 adoption."""
    if (type(joint_operation_id) is not str or not joint_operation_id
            or type(baseline_id) is not str or not baseline_id
            or type(source_version) is not ExactGraphRefV2
            or type(perspective_version) is not ExactGraphRefV2
            or type(interpretation_versions) is not tuple
            or any(type(item) is not ExactGraphRefV2
                   for item in interpretation_versions)
            or len({item.ref for item in interpretation_versions})
               != len(interpretation_versions)
            or tuple(item.ref for item in interpretation_versions)
               != tuple(sorted(item.ref for item in interpretation_versions))
            or type(as_known_at) not in (int, float)
            or not math.isfinite(as_known_at)):
        raise D04C04ProjectionHold("encoding source/context versions are incomplete")
    _joint_pair(output_original, numeric_original, policy, asset)
    if (output_original.operation_id != joint_operation_id
            or numeric_original.adoption_operation_id != joint_operation_id):
        raise D04C04ProjectionHold("explicit encoding joint operation differs")
    for version in (perspective_version, *interpretation_versions):
        if NamespaceId.from_key(version.key) != output_original.namespace:
            raise D04C04ProjectionHold("encoding context crosses namespace")
    bindings, source_drives = _source_feeling_bindings(
        output_original, numeric_original, source_version, drives,
    )
    projection = project_encoding_salience_from_joint_output_v2(
        output_original=output_original, asset=asset, policy=policy,
        member_bindings=bindings,
    )
    numeric_error = _selected_numeric_error(
        source_version, projection, numeric_original.verification.numeric_error,
    )
    payload = dict(
        baseline_id=baseline_id, namespace=output_original.namespace,
        source_version=source_version, perspective_version=perspective_version,
        interpretation_versions=interpretation_versions,
        as_known_at=float(as_known_at), feeling_bindings=bindings,
        source_drive_bindings=source_drives,
        joint_adoption_operation_id=numeric_original.adoption_operation_id,
        joint_adoption_receipt_digest=numeric_original.adoption_receipt_digest,
        numeric_original_digest=canonical_digest(asdict(numeric_original)),
        output_original_digest=output_original.original_digest,
        output_write_set_digest=output_original.write_set_digest,
        numeric_receipt_digest=numeric_original.receipt.receipt_digest,
        native_manifest_sha256=output_original.native_manifest_sha256,
        native_sha256=output_original.native_sha256,
        full_transcript_sha256=output_original.full_transcript_sha256,
        policy_digest=canonical_digest(asdict(policy)),
        readout_sha256=asset.asset_sha256,
        numeric_error=numeric_error,
        projection=projection,
    )
    return D04EncodingBaselineProofV3(
        **payload, proof_digest=canonical_digest(payload),
    )


def verify_encoding_baseline_proof_v3(
    proof: D04EncodingBaselineProofV3, *,
    joint_operation_id: str,
    output_original: JointStateOutputOriginalV1,
    numeric_original: JointNumericOriginalV1,
    drives: tuple[SourcedNumericDrive, ...],
    asset: D04LoadedTanhReadoutAsset,
    policy: D04IntervalProjectionPolicyV2,
) -> bool:
    """Recompute exact conditional baseline fields from W01's pinned inputs."""
    if type(proof) is not D04EncodingBaselineProofV3:
        return False
    try:
        expected = issue_encoding_baseline_proof_v3(
            joint_operation_id=joint_operation_id,
            baseline_id=proof.baseline_id, source_version=proof.source_version,
            perspective_version=proof.perspective_version,
            interpretation_versions=proof.interpretation_versions,
            as_known_at=proof.as_known_at, output_original=output_original,
            numeric_original=numeric_original, drives=drives,
            asset=asset, policy=policy,
        )
    except (TypeError, ValueError, KeyError, OverflowError):
        return False
    return proof == expected


def _mood_features(member: JointStateOutputMemberV1,
                   asset: D04LoadedTanhReadoutAsset,
                   policy: D04IntervalProjectionPolicyV2,
                   ) -> tuple[tuple[float, float], tuple[float, float]]:
    state = member.next_state
    if (member.kind != "mood" or type(state) not in (MoodField, AuthoredMoodStateV1)
            or len(member.axes) != 24
            or tuple(axis for axis, _ in state.coordinates)
               != REGISTERED_AXIS_IDS):
        raise D04C04ProjectionHold("current Mood output is incomplete")
    intervals = []
    for axis, row, output, (_, coordinate) in zip(
            REGISTERED_AXIS_IDS, asset.rows, member.axes, state.coordinates):
        if (type(output) is not JointStateAxisOutputV1
                or output.axis_id != axis or output.output_id != row.output_id
                or _bits(output.representative) != _bits(coordinate)):
            raise D04C04ProjectionHold("Mood output axis differs")
        low, high = _fraction(output.certified_lower), _fraction(output.certified_upper)
        representative = _fraction(output.representative)
        error = _fraction(output.representative_error)
        if (not -1 <= low <= representative <= high <= 1
                or high - low > _fraction(policy.max_axis_width)
                or error < max(representative - low, high - representative)):
            raise D04C04ProjectionHold("Mood certified interval differs")
        intervals.append((low, high))
    absolute = tuple((Fraction(0) if low <= 0 <= high else min(abs(low), abs(high)),
                      max(abs(low), abs(high))) for low, high in intervals)
    salience = (sum((low for low, _ in absolute), Fraction()) / 24,
                sum((high for _, high in absolute), Fraction()) / 24)
    tone = ((sum(intervals[index][0] for index in (0, 1, 2))
             - sum(intervals[index][1] for index in (3, 4, 5))) / 6,
            (sum(intervals[index][1] for index in (0, 1, 2))
             - sum(intervals[index][0] for index in (3, 4, 5))) / 6)
    width = _fraction(policy.max_projection_width)
    if salience[1] - salience[0] > width or tone[1] - tone[0] > width:
        raise D04C04ProjectionHold("Mood projection interval is too wide")
    return _float_interval(*salience), _float_interval(*tone)


def issue_current_conditioned_projection_v3(
    *, mood_joint_operation_id: str,
    baseline: D04EncodingBaselineProofV3,
    baseline_receipt_ref: str, baseline_receipt_revision: int,
    baseline_receipt_digest: str,
    mood_ref: str, mood_revision: int,
    mood_output_original: JointStateOutputOriginalV1,
    mood_numeric_original: JointNumericOriginalV1,
    asset: D04LoadedTanhReadoutAsset,
    policy: D04IntervalProjectionPolicyV2,
) -> D04CurrentConditionedProjectionV3:
    """Condition an immutable encoding feature on one current certified Mood."""
    if (type(mood_joint_operation_id) is not str or not mood_joint_operation_id
            or type(baseline) is not D04EncodingBaselineProofV3
            or baseline.status != "conditional_requires_w01_encoding_adoption"
            or baseline.semantic_calibration != "unvalidated"
            or baseline.proof_digest != canonical_digest({
                field.name: getattr(baseline, field.name)
                for field in fields(baseline)
                if field.name not in {"proof_digest", "status", "semantic_calibration"}})
            or type(baseline_receipt_ref) is not str or not baseline_receipt_ref
            or type(baseline_receipt_revision) is not int
            or baseline_receipt_revision < 1
            or type(baseline_receipt_digest) is not str
            or len(baseline_receipt_digest) != 64
            or any(c not in "0123456789abcdef" for c in baseline_receipt_digest)
            or type(mood_ref) is not str
            or type(mood_revision) is not int or mood_revision < 1):
        raise D04C04ProjectionHold("adopted encoding baseline premise is absent")
    _joint_pair(mood_output_original, mood_numeric_original, policy, asset)
    if (mood_output_original.operation_id != mood_joint_operation_id
            or mood_numeric_original.adoption_operation_id
               != mood_joint_operation_id):
        raise D04C04ProjectionHold("explicit current Mood joint operation differs")
    if (baseline.namespace != mood_output_original.namespace
            or baseline.policy_digest != canonical_digest(asdict(policy))
            or baseline.readout_sha256 != asset.asset_sha256):
        raise D04C04ProjectionHold("current Mood and historical policy differ")
    moods = tuple(member for member in mood_output_original.members
                  if member.predecessor_state_ref == mood_ref)
    if (len(moods) != 1
            or mood_numeric_original.original_ref != moods[0].checkpoint_ref
            or moods[0].predecessor_state_revision + 1 != mood_revision
            or AtomKey.from_token(mood_ref).type_name != (
                "d04.authored_mood_state.v1" if type(moods[0].next_state) is AuthoredMoodStateV1
                else "d04.mood_field.v1")
            or NamespaceId.from_key(AtomKey.from_token(mood_ref))
               != baseline.namespace):
        raise D04C04ProjectionHold("current Mood ref is not adopted output member")
    mood_salience, mood_tone = _mood_features(moods[0], asset, policy)
    original_mood_error = mood_numeric_original.verification.numeric_error
    mood_salience_error = _outward_binary64(
        _fraction(mood_salience[1]) - _fraction(mood_salience[0]), lower=False,
    )
    mood_tone_error = _outward_binary64(
        _fraction(mood_tone[1]) - _fraction(mood_tone[0]), lower=False,
    )
    mood_numeric_error = ProjectionNumericErrorV2(
        original_mood_error.inherited_state_error_2norm,
        original_mood_error.solve_state_error_2norm,
        mood_salience_error, mood_tone_error,
        canonical_digest({
            "schema": "d04.c04-mood-specific-numeric-error.v3",
            "mood": (mood_ref, mood_revision),
            "joint_numeric_proof": original_mood_error.numeric_proof_digest,
            "output_original": mood_output_original.original_digest,
            "salience_readout": mood_salience_error,
            "tone_readout": mood_tone_error,
        }),
    )
    salience = _add_scaled(
        _interval(baseline.projection.salience_interval, 0, 1),
        _interval(mood_salience, 0, 1), policy.mood_salience_gain,
    )
    tone = _add_scaled(
        _interval(baseline.projection.tone_interval, -1, 1),
        _interval(mood_tone, -1, 1), policy.mood_tone_gain,
    )
    width = _fraction(policy.max_projection_width)
    if salience[1] - salience[0] > width or tone[1] - tone[0] > width:
        raise D04C04ProjectionHold("conditioned interval is too wide")
    salience = _float_interval(*(_clamp(value, 0, 1) for value in salience))
    tone = _float_interval(*(_clamp(value, -1, 1) for value in tone))
    salience_error = _outward_binary64(
        _fraction(salience[1]) - _fraction(salience[0]), lower=False,
    )
    tone_error = _outward_binary64(
        _fraction(tone[1]) - _fraction(tone[0]), lower=False,
    )
    payload = dict(
        namespace=baseline.namespace, source_version=baseline.source_version,
        baseline_id=baseline.baseline_id,
        baseline_proof_digest=baseline.proof_digest,
        baseline_receipt_ref=baseline_receipt_ref,
        baseline_receipt_revision=baseline_receipt_revision,
        baseline_receipt_digest=baseline_receipt_digest,
        mood_ref=mood_ref, mood_revision=mood_revision,
        mood_checkpoint_ref=moods[0].checkpoint_ref,
        mood_checkpoint_revision=moods[0].predecessor_checkpoint_revision + 1,
        mood_joint_adoption_operation_id=mood_numeric_original.adoption_operation_id,
        mood_joint_adoption_receipt_digest=mood_numeric_original.adoption_receipt_digest,
        mood_numeric_original_digest=canonical_digest(asdict(mood_numeric_original)),
        mood_output_original_digest=mood_output_original.original_digest,
        mood_native_sha256=mood_output_original.native_sha256,
        mood_numeric_receipt_digest=mood_numeric_original.receipt.receipt_digest,
        mood_numeric_error=mood_numeric_error,
        policy_digest=baseline.policy_digest,
        readout_sha256=baseline.readout_sha256,
        base_salience_interval=baseline.projection.salience_interval,
        base_tone_interval=baseline.projection.tone_interval,
        mood_salience_interval=mood_salience, mood_tone_interval=mood_tone,
        conditioned_salience_interval=salience,
        conditioned_tone_interval=tone,
        conditioned_salience_error=salience_error,
        conditioned_tone_error=tone_error,
    )
    return D04CurrentConditionedProjectionV3(
        **payload, proof_digest=canonical_digest(payload),
    )


def verify_current_conditioned_projection_v3(
    projection: D04CurrentConditionedProjectionV3, *,
    mood_joint_operation_id: str,
    baseline: D04EncodingBaselineProofV3,
    mood_output_original: JointStateOutputOriginalV1,
    mood_numeric_original: JointNumericOriginalV1,
    asset: D04LoadedTanhReadoutAsset,
    policy: D04IntervalProjectionPolicyV2,
) -> bool:
    """Exact current arithmetic rederivation; W01 authenticates both epochs."""
    if type(projection) is not D04CurrentConditionedProjectionV3:
        return False
    try:
        expected = issue_current_conditioned_projection_v3(
            mood_joint_operation_id=mood_joint_operation_id,
            baseline=baseline,
            baseline_receipt_ref=projection.baseline_receipt_ref,
            baseline_receipt_revision=projection.baseline_receipt_revision,
            baseline_receipt_digest=projection.baseline_receipt_digest,
            mood_ref=projection.mood_ref, mood_revision=projection.mood_revision,
            mood_output_original=mood_output_original,
            mood_numeric_original=mood_numeric_original,
            asset=asset, policy=policy,
        )
    except (TypeError, ValueError, KeyError, OverflowError):
        return False
    return projection == expected


def _v3_digest(value: str) -> str:
    if (type(value) is not str or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise D04C04ProjectionHold("D04 original digest is not a bare SHA-256")
    return "sha256:" + value


def _v3_numeric_error(value: ProjectionNumericErrorV2) -> object:
    from ...runtime.c04_v3_contracts import ProjectionNumericErrorV3

    if type(value) is not ProjectionNumericErrorV2:
        raise D04C04ProjectionHold("verified numeric error decomposition is absent")
    return ProjectionNumericErrorV3(
        value.inherited_state_error_2norm, value.solve_state_error_2norm,
        value.salience_readout_error, value.tone_readout_error,
        _v3_digest(value.numeric_proof_digest),
    )


def conditional_encoding_baseline_contract_v3(
    proof: D04EncodingBaselineProofV3, *,
    encoding_operation_id: str, owner_epoch: int,
    access_epoch: int, delete_epoch: int,
) -> object:
    """Map a conditional D04 proof to W00 wire; W01 alone can adopt it.

    Epochs and the historical source/meaning/interpretation closure must come
    from W01's encoding-time read. This converter does not authenticate them.
    """
    from ...runtime.c04_v3_contracts import (
        D04EncodingBaselineOriginalV3, ExactRefV3,
        D04EncodingBaselineAuthoredOriginalV3,
        ProjectionMemberV3, ProjectionMemberAuthoredV3, canonical_v3_digest,
    )

    if (type(proof) is not D04EncodingBaselineProofV3
            or proof.status != "conditional_requires_w01_encoding_adoption"
            or proof.semantic_calibration != "unvalidated"):
        raise D04C04ProjectionHold("conditional encoding proof is absent")
    if (not proof.feeling_bindings or len({type(item) for item in proof.feeling_bindings}) != 1
            or type(proof.feeling_bindings[0]) not in
               (D04ProjectionMemberBindingV2, D04AuthoredProjectionMemberBindingV3)
            or proof.projection.member_bindings != proof.feeling_bindings):
        raise D04C04ProjectionHold("conditional encoding member lineage differs")
    authored = type(proof.feeling_bindings[0]) is D04AuthoredProjectionMemberBindingV3
    member_type = ProjectionMemberAuthoredV3 if authored else ProjectionMemberV3
    original_type = D04EncodingBaselineAuthoredOriginalV3 if authored else D04EncodingBaselineOriginalV3
    members = tuple(sorted((member_type(
        ExactRefV3(item.feeling_ref, item.feeling_revision),
        ExactRefV3(item.checkpoint_ref, item.checkpoint_revision),
    ) for item in proof.feeling_bindings), key=lambda item: item.feeling.ref))
    return original_type(
        namespace=proof.namespace, encoding_operation_id=encoding_operation_id,
        source=ExactRefV3(proof.source_version.ref, proof.source_version.revision),
        perspective=ExactRefV3(proof.perspective_version.ref,
                               proof.perspective_version.revision),
        interpretations=tuple(ExactRefV3(item.ref, item.revision)
                              for item in proof.interpretation_versions),
        members=members, member_set_digest=canonical_v3_digest(members),
        joint_adoption_receipt_digest=_v3_digest(proof.joint_adoption_receipt_digest),
        joint_numeric_original_digest=_v3_digest(proof.numeric_original_digest),
        joint_output_original_digest=_v3_digest(proof.output_original_digest),
        policy_digest=_v3_digest(proof.policy_digest),
        readout_sha256=proof.readout_sha256,
        native_manifest_sha256=proof.native_manifest_sha256,
        native_sha256=proof.native_sha256,
        owner_epoch=owner_epoch, access_epoch=access_epoch,
        delete_epoch=delete_epoch,
        salience_interval=proof.projection.salience_interval,
        tone_interval=proof.projection.tone_interval,
        numeric_error=_v3_numeric_error(proof.numeric_error),
        proof_digest=_v3_digest(proof.proof_digest),
    )


def conditional_current_salience_contract_v3(
    projection: D04CurrentConditionedProjectionV3, *,
    baseline_contract: object, operation_id: str,
    source_closure_digest: str, audience: str, purpose: str,
    owner_epoch: int, access_epoch: int, delete_epoch: int,
) -> object:
    """Map current arithmetic to W00 wire; W01 validates and stores it."""
    from ...runtime.c04_v3_contracts import (
        D04CurrentConditionedSalienceOriginalV3,
        D04CurrentSalienceConditionAuthoredV3,
        D04EncodingBaselineOriginalV3, D04EncodingBaselineAuthoredOriginalV3, ExactRefV3,
    )

    if (type(projection) is not D04CurrentConditionedProjectionV3
            or projection.status != "conditional_requires_w01_current_adoption"
            or projection.semantic_calibration != "unvalidated"
            or type(baseline_contract) not in (D04EncodingBaselineOriginalV3, D04EncodingBaselineAuthoredOriginalV3)
            or baseline_contract.namespace != projection.namespace
            or baseline_contract.source.ref != projection.source_version.ref
            or baseline_contract.source.revision != projection.source_version.revision
            or baseline_contract.salience_interval
               != projection.base_salience_interval
            or baseline_contract.tone_interval != projection.base_tone_interval
            or baseline_contract.proof_digest
               != _v3_digest(projection.baseline_proof_digest)):
        raise D04C04ProjectionHold("current projection or baseline wire differs")
    condition_type = (D04CurrentSalienceConditionAuthoredV3
                      if type(baseline_contract) is D04EncodingBaselineAuthoredOriginalV3
                      else D04CurrentConditionedSalienceOriginalV3)
    return condition_type(
        namespace=projection.namespace, operation_id=operation_id,
        source_ref=projection.source_version.ref,
        baseline_digest=baseline_contract.digest,
        current_mood=ExactRefV3(projection.mood_ref, projection.mood_revision),
        current_checkpoint=ExactRefV3(projection.mood_checkpoint_ref,
                                       projection.mood_checkpoint_revision),
        current_joint_adoption_receipt_digest=_v3_digest(
            projection.mood_joint_adoption_receipt_digest),
        current_joint_numeric_original_digest=_v3_digest(
            projection.mood_numeric_original_digest),
        current_joint_output_original_digest=_v3_digest(
            projection.mood_output_original_digest),
        source_closure_digest=_v3_digest(source_closure_digest),
        audience=audience, purpose=purpose,
        owner_epoch=owner_epoch, access_epoch=access_epoch,
        delete_epoch=delete_epoch,
        policy_digest=_v3_digest(projection.policy_digest),
        readout_sha256=projection.readout_sha256,
        native_sha256=projection.mood_native_sha256,
        base_salience_interval=projection.base_salience_interval,
        conditioned_salience_interval=projection.conditioned_salience_interval,
        base_tone_interval=projection.base_tone_interval,
        conditioned_tone_interval=projection.conditioned_tone_interval,
        numeric_error=_v3_numeric_error(projection.mood_numeric_error),
        baseline_proof_digest=_v3_digest(projection.baseline_proof_digest),
        conditioning_proof_digest=_v3_digest(projection.proof_digest),
    )


__all__ = [
    "D04C04ProjectionHold", "D04EncodingBaselineProofV3",
    "D04CurrentConditionedProjectionV3",
    "issue_encoding_baseline_proof_v3", "verify_encoding_baseline_proof_v3",
    "issue_current_conditioned_projection_v3",
    "verify_current_conditioned_projection_v3",
    "conditional_encoding_baseline_contract_v3",
    "conditional_current_salience_contract_v3",
]
