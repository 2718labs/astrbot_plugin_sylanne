"""Conditional D04 V2 graph writes derived from one installed joint ABI2 replay.

The issuer never accepts caller-supplied next coordinates or errors. W01 must
authenticate the frozen predecessor/source graph, use a formal policy binding,
and atomically compare and store these writes under its current Owner fence.
Semantic calibration remains unvalidated.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields, replace
from fractions import Fraction
import math
import struct
from typing import TYPE_CHECKING

from ...graph_types import AtomKey
from ...native_runtime.d04_tanh_readout_asset import TRANSFORM
from ...native_runtime.fixed_block_transcript import _digest, _same_float_bits
from ...native_runtime.tanh_interval import _outward_binary64
from ...runtime_contracts import NamespaceId, canonical_digest
from .affect import FeelingState, MoodField
from .encoding_baseline import CommittedRef
from .numeric_coupling import REGISTERED_AXIS_IDS
from .numeric_drive import sourced_numeric_drive_write
from .root import NumericCheckpoint, encode_numeric_checkpoint
from .trusted_joint_replay import (
    D04InstalledJointNumericReplayV1, is_package_bound_joint_numeric_replay_v1,
)

if TYPE_CHECKING:
    from .authored_lineage_v3 import (
        AuthoredFeelingStateV1, AuthoredMoodStateV1, AuthoredNumericCheckpointV2,
    )


SCHEMA = "d04.joint-state-output.v1"
AUTHORED_SCHEMA = "d04.joint-state-output.v2"
POLICY_SCHEMA = "d04.joint-state-output-policy.v1"
POLICY_VERSION = "d04.joint-state-output.v1"
ALGORITHM_ID = "abi2-full-output.identity-tanh24.rational-midpoint-rne.v1"


class JointStateOutputHold(ValueError):
    """An installed replay cannot derive a complete, bounded graph write set."""


def _finite(value: object, name: str) -> float:
    if type(value) is not float or not math.isfinite(value):
        raise ValueError(f"{name} must be finite binary64")
    return value


def _bits(value: float) -> str:
    return struct.pack("!d", value).hex()


@dataclass(frozen=True, slots=True)
class JointStateOutputPolicyV1:
    algorithm_id: str
    axis_ids: tuple[str, ...]
    latent_lower: float
    latent_upper: float
    max_readout_interval_width: float
    policy_id: str
    readout_id: str
    readout_sha256: str
    readout_version: str
    schema: str
    semantic_calibration: str
    version: str

    def __post_init__(self) -> None:
        if (self.schema != POLICY_SCHEMA or self.version != POLICY_VERSION
                or self.algorithm_id != ALGORITHM_ID
                or self.axis_ids != REGISTERED_AXIS_IDS
                or type(self.policy_id) is not str or not self.policy_id
                or type(self.readout_id) is not str or not self.readout_id
                or type(self.readout_version) is not str or not self.readout_version
                or type(self.readout_sha256) is not str
                or len(self.readout_sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.readout_sha256)
                or self.semantic_calibration != "unvalidated"
                or _finite(self.latent_lower, "latent_lower") != 0.0
                or _finite(self.latent_upper, "latent_upper") != 4.0
                or not 0 < _finite(self.max_readout_interval_width,
                                   "max_readout_interval_width") <= 2.0):
            raise ValueError("joint state output policy identity or bounds differ")

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class JointStatePredecessorV1:
    checkpoint_ref: str
    checkpoint_revision: int
    checkpoint: NumericCheckpoint | AuthoredNumericCheckpointV2
    state_ref: str
    state_revision: int
    state: FeelingState | MoodField | AuthoredFeelingStateV1 | AuthoredMoodStateV1
    predecessor_receipt_digest: str


@dataclass(frozen=True, slots=True)
class JointStateFrozenPredecessorsV1:
    namespace: NamespaceId
    operation_id: str
    members: tuple[JointStatePredecessorV1, ...]


@dataclass(frozen=True, slots=True)
class JointStateAxisOutputV1:
    axis_id: str
    output_id: str
    certified_lower: float
    certified_upper: float
    representative: float
    representative_error: float


@dataclass(frozen=True, slots=True)
class JointStateOutputMemberV1:
    checkpoint_ref: str
    predecessor_checkpoint_revision: int
    predecessor_checkpoint_digest: str
    predecessor_state_ref: str
    predecessor_state_revision: int
    predecessor_state_digest: str
    kind: str
    next_checkpoint: NumericCheckpoint | AuthoredNumericCheckpointV2
    next_state: FeelingState | MoodField | AuthoredFeelingStateV1 | AuthoredMoodStateV1
    axes: tuple[JointStateAxisOutputV1, ...]
    native_trajectory_error_2norm: float


@dataclass(frozen=True, slots=True)
class JointStateOutputOriginalV1:
    schema: str
    namespace: NamespaceId
    operation_id: str
    component_digest: str
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    role_start: float
    role_end: float
    member_refs: tuple[str, ...]
    axis_ids: tuple[str, ...]
    full_transcript_sha256: str
    family_transcripts: tuple[tuple[str, str], ...]
    math_transcript_sha256: str
    full_output_sha256: str
    native_manifest_sha256: str
    native_sha256: str
    native_abi_version: int
    policy_id: str
    policy_version: str
    policy_digest: str
    policy_sha256: str
    readout_id: str
    readout_version: str
    readout_sha256: str
    native_trajectory_error_2norm: float
    members: tuple[JointStateOutputMemberV1, ...]
    write_set_digest: str
    binary64_bits_digest: str
    original_digest: str
    status: str = "issued_pending_w01_atomic_joint_adoption"


def _predecessors(replay: D04InstalledJointNumericReplayV1,
                  frozen: JointStateFrozenPredecessorsV1) -> None:
    from .authored_lineage_v3 import (
        AuthoredFeelingStateV1, AuthoredMoodStateV1, AuthoredNumericCheckpointV2,
        validate_authored_joint_predecessor_v3,
    )
    refs = replay.candidate.member_refs
    authored = replay.component.root_original_digest is not None
    if (type(frozen) is not JointStateFrozenPredecessorsV1
            or frozen.namespace != replay.component.namespace
            or type(frozen.operation_id) is not str or not frozen.operation_id
            or type(frozen.members) is not tuple
            or len(frozen.members) != len(refs)
            or any(type(item) is not JointStatePredecessorV1
                   for item in frozen.members)):
        raise JointStateOutputHold("frozen predecessor member set differs")
    if (tuple(item.checkpoint_ref for item in frozen.members) != refs
            or tuple(item.checkpoint for item in frozen.members)
               != replay.checkpoints):
        raise JointStateOutputHold("frozen predecessor member set differs")
    for item, block in zip(frozen.members, replay.component.block_drives):
        try:
            checkpoint_ref = AtomKey.from_token(item.checkpoint_ref)
            state_ref = AtomKey.from_token(item.state_ref)
            state = item.state
            cp = item.checkpoint
            if (type(item) is not JointStatePredecessorV1
                    or type(cp) is not (AuthoredNumericCheckpointV2 if authored
                                        else NumericCheckpoint)
                    or checkpoint_ref.type_name != ("d04.numeric_checkpoint.v2" if authored
                                                       else "d04.numeric_checkpoint.v1")
                    or checkpoint_ref.owner.kind != "persona"
                    or NamespaceId.from_key(checkpoint_ref) != frozen.namespace
                    or checkpoint_ref.name != cp.block.block_id
                    or item.checkpoint_revision != block.checkpoint_version.revision
                    or item.state_ref != cp.graph_state.ref
                    or item.state_revision != cp.graph_state.revision
                    or item.state_revision != block.graph_state_version.revision
                    or state_ref.owner != checkpoint_ref.owner
                    or state_ref.name != cp.block.block_id
                    or state_ref.type_name != (
                        "d04.authored_feeling_state.v1" if authored and cp.block.kind == "feeling"
                        else "d04.authored_mood_state.v1" if authored
                        else "d04.feeling_state.v1" if cp.block.kind == "feeling"
                        else "d04.mood_field.v1")
                    or type(state) is not (
                        AuthoredFeelingStateV1 if authored and cp.block.kind == "feeling"
                        else AuthoredMoodStateV1 if authored
                        else FeelingState if cp.block.kind == "feeling" else MoodField)
                    or state.revision != item.state_revision
                    or state.cursor != cp.cursor
                    or cp.cursor != replay.component.role_start
                    or cp.axes != REGISTERED_AXIS_IDS
                    or type(item.predecessor_receipt_digest) is not str
                    or len(item.predecessor_receipt_digest) != 64
                    or any(c not in "0123456789abcdef"
                           for c in item.predecessor_receipt_digest)):
                raise ValueError("predecessor graph identity differs")
            if type(state) is FeelingState:
                if (state.target_ref != cp.block.object_ref
                        or cp.block.meaning_ref not in state.meaning_refs):
                    raise ValueError("feeling target or meaning differs")
            if authored:
                validate_authored_joint_predecessor_v3(cp, state, item.checkpoint_revision)
                if item.predecessor_receipt_digest != block.predecessor_receipt_digest:
                    raise ValueError("authored predecessor commit receipt differs")
        except (TypeError, ValueError, AttributeError) as exc:
            raise JointStateOutputHold("frozen predecessor is incomplete") from exc


def _full_transcript(replay: D04InstalledJointNumericReplayV1) -> tuple[tuple[float, ...], float]:
    from ...native_runtime.d04_fixed_trajectory_v2 import verify_d04_fixed_trajectory_v2, fixed_d04_step_plan_v2
    result = replay.math_result
    transcript = result.full_transcript
    try:
        verify_d04_fixed_trajectory_v2(transcript, first=result.full_step,
            step_plan=fixed_d04_step_plan_v2(replay.component.role_start, replay.component.role_end))
    except (ValueError, TypeError) as exc:
        raise JointStateOutputHold("actual complete ABI2 trajectory is unavailable") from exc
    binding = transcript.production_binding
    if (result.trajectory_schema != "d04.joint-product-fixed-trajectory.v2"
            or transcript.transcript_sha256 != result.full_transcript_sha256
            or transcript.output_sha256 != _digest(transcript.output)
            or binding.manifest_sha256 != replay.candidate.native_manifest_sha256
            or binding.native_sha256 != replay.candidate.native_sha256
            or binding.abi_version != replay.candidate.native_abi_version
            or len(transcript.output) != 24 * len(replay.candidate.member_refs)):
        raise JointStateOutputHold("complete ABI2 trajectory identity differs")
    for index, member in enumerate(result.members):
        center = transcript.output[index * 24:(index + 1) * 24]
        if (member.checkpoint_ref != replay.candidate.member_refs[index]
                or not _same_float_bits(member.full.state_centers, center)
                or _bits(member.full.state_error_2norm) != _bits(transcript.final_error)):
            raise JointStateOutputHold("full readout is not derived from the complete ABI2 trajectory")
    return transcript.output, transcript.final_error


def _identity_readout(replay: D04InstalledJointNumericReplayV1,
                      policy: JointStateOutputPolicyV1) -> None:
    asset = replay.readout
    if (asset.readout_id != policy.readout_id
            or asset.readout_version != policy.readout_version
            or asset.asset_sha256 != policy.readout_sha256
            or asset.axis_ids != REGISTERED_AXIS_IDS
            or len(asset.rows) != 24):
        raise JointStateOutputHold("installed readout identity differs")
    zero, one = _bits(0.0), _bits(1.0)
    for index, row in enumerate(asset.rows):
        if (row.axis_id != REGISTERED_AXIS_IDS[index]
                or row.output_version != asset.readout_version
                or row.transform != TRANSFORM
                or len(row.coefficients) != 24
                or tuple(_bits(weight) for weight in row.coefficients)
                   != tuple(one if pos == index else zero for pos in range(24))):
            raise JointStateOutputHold("readout must be exact identity tanh")


def _axis_output(axis: str, output_id: str, lower: float, upper: float,
                 width_limit: float) -> JointStateAxisOutputV1:
    low, high = _finite(lower, "readout lower"), _finite(upper, "readout upper")
    if (low > high
            or Fraction.from_float(high) - Fraction.from_float(low)
               > Fraction.from_float(width_limit)
            or low < -1.0 or high > 1.0):
        raise JointStateOutputHold("certified readout interval exceeds policy")
    midpoint = float((Fraction.from_float(low) + Fraction.from_float(high)) / 2)
    if not low <= midpoint <= high:
        raise JointStateOutputHold("rounded representative escapes interval")
    error = max(Fraction.from_float(midpoint) - Fraction.from_float(low),
                Fraction.from_float(high) - Fraction.from_float(midpoint))
    return JointStateAxisOutputV1(
        axis, output_id, low, high, midpoint,
        _outward_binary64(error, lower=False),
    )


def _latent_box(values: tuple[float, ...], error: float,
                policy: JointStateOutputPolicyV1) -> tuple[tuple[tuple[float, float], ...], float]:
    radius = Fraction.from_float(_finite(error, "native trajectory error"))
    boxes = []
    squared = Fraction()
    for value in values:
        center = Fraction.from_float(_finite(value, "ABI2 output"))
        lower = _outward_binary64(center - radius, lower=True)
        upper = _outward_binary64(center + radius, lower=False)
        if (lower < policy.latent_lower or upper > policy.latent_upper
                or not lower <= value <= upper):
            raise JointStateOutputHold("ABI2 latent box leaves [0, 4]")
        boxes.append((lower, upper))
        deviation = max(center - Fraction.from_float(lower),
                        Fraction.from_float(upper) - center)
        squared += deviation * deviation
    try:
        scalar = math.sqrt(float(squared))
    except OverflowError as exc:
        raise JointStateOutputHold("latent box norm overflows binary64") from exc
    if not math.isfinite(scalar):
        raise JointStateOutputHold("latent box norm overflows binary64")
    while Fraction.from_float(scalar) ** 2 < squared:
        scalar = math.nextafter(scalar, math.inf)
    return tuple(boxes), scalar


def joint_checkpoint_payload_v1(value: NumericCheckpoint | AuthoredNumericCheckpointV2) -> dict:
    from .authored_lineage_v3 import (
        AuthoredNumericCheckpointV2, encode_authored_numeric_checkpoint_v2,
    )
    if type(value) is AuthoredNumericCheckpointV2:
        return encode_authored_numeric_checkpoint_v2(value)
    if type(value) is NumericCheckpoint:
        return encode_numeric_checkpoint(value)
    raise TypeError("joint checkpoint must be a typed D04 checkpoint")


def joint_state_payload_v1(
    value: FeelingState | MoodField | AuthoredFeelingStateV1 | AuthoredMoodStateV1,
) -> dict:
    from .authored_lineage_v3 import (
        AuthoredFeelingStateV1, AuthoredMoodStateV1,
        encode_authored_feeling_state_v1, encode_authored_mood_state_v1,
    )
    if type(value) is AuthoredFeelingStateV1:
        return encode_authored_feeling_state_v1(value)
    if type(value) is AuthoredMoodStateV1:
        return encode_authored_mood_state_v1(value)
    if type(value) in (FeelingState, MoodField):
        return asdict(value)
    raise TypeError("joint state must be a typed D04 state")


def _write_set(members: tuple[JointStateOutputMemberV1, ...]) -> tuple[tuple[str, int, dict], ...]:
    rows = []
    for item in members:
        rows.append((item.checkpoint_ref, item.predecessor_checkpoint_revision + 1,
                     joint_checkpoint_payload_v1(item.next_checkpoint)))
        rows.append((item.predecessor_state_ref, item.predecessor_state_revision + 1,
                     joint_state_payload_v1(item.next_state)))
    return tuple(sorted(rows, key=lambda row: row[0]))


def issue_joint_state_outputs_v1(
    installed_replay: D04InstalledJointNumericReplayV1,
    frozen_predecessors: JointStateFrozenPredecessorsV1,
    installed_policy: object,
) -> JointStateOutputOriginalV1:
    """Authenticate policy bytes, then derive writes outside W01's graph lock."""
    from ...host.installed_d04_output_policy import (
        InstalledD04OutputPolicyBindingV1, load_installed_d04_output_policy_v1,
    )

    if (not is_package_bound_joint_numeric_replay_v1(installed_replay)
            or type(installed_policy) is not InstalledD04OutputPolicyBindingV1
            or not (installed_policy.build_mode == "formal-alpha1"
                    or installed_policy.build_mode in {"backend-alpha1-candidate", "snapshot-alpha1-test"}
                    and installed_policy.runtime_scope == "backend-production-acceptance"
                    or installed_policy.build_mode == "alpha2-candidate"
                    and installed_policy.runtime_scope == "backend-local-alpha2-acceptance"
                    or installed_policy.build_mode == "beta1-candidate"
                    and installed_policy.runtime_scope == "backend-beta1-server-test")
            or type(installed_policy.policy) is not JointStateOutputPolicyV1):
        raise JointStateOutputHold("formal installed replay and output policy are required")
    policy = installed_policy.policy
    if installed_policy.manifest_sha256 != installed_replay.candidate.native_manifest_sha256:
        raise JointStateOutputHold("installed policy identity differs")
    try:
        current_binding = load_installed_d04_output_policy_v1(
            installed_replay.package_root,
            installed_replay.candidate.native_manifest_sha256,
            require_formal=False, require_backend_runtime=True,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise JointStateOutputHold("installed output policy is unavailable") from exc
    if current_binding != installed_policy:
        raise JointStateOutputHold("installed output policy bytes changed")
    return _derive_joint_state_outputs_v1(
        installed_replay, frozen_predecessors, policy,
        installed_policy.policy_sha256,
    )


def _derive_joint_state_outputs_v1(
    installed_replay: D04InstalledJointNumericReplayV1,
    frozen_predecessors: JointStateFrozenPredecessorsV1,
    policy: JointStateOutputPolicyV1,
    policy_sha256: str,
) -> JointStateOutputOriginalV1:
    """Pure deterministic derivation; caller must authenticate policy/Owner."""
    from .authored_lineage_v3 import AuthoredFeelingStateV1, AuthoredMoodStateV1
    _identity_readout(installed_replay, policy)
    _predecessors(installed_replay, frozen_predecessors)
    output, native_error = _full_transcript(installed_replay)
    authored = installed_replay.component.root_original_digest is not None
    candidate = installed_replay.candidate
    math_result = installed_replay.math_result
    members = []
    for index, (prior, math_member) in enumerate(zip(
            frozen_predecessors.members, math_result.members)):
        values = output[index * 24:(index + 1) * 24]
        boxes, scalar_error = _latent_box(values, native_error, policy)
        if (len(math_member.full.outputs) != 24
                or math_member.full.asset_sha256 != policy.readout_sha256
                or math_member.full.readout_id != policy.readout_id):
            raise JointStateOutputHold("member full readout is incomplete")
        axes = []
        for axis, row, interval in zip(REGISTERED_AXIS_IDS,
                                       installed_replay.readout.rows,
                                       math_member.full.outputs):
            if (row.axis_id != axis or interval.axis_id != axis
                    or row.output_id != interval.output_id):
                raise JointStateOutputHold("member output axes differ")
            axes.append(_axis_output(axis, row.output_id, interval.lower,
                                     interval.upper,
                                     policy.max_readout_interval_width))
        axis_outputs = tuple(axes)
        coordinates = tuple((item.axis_id, item.representative)
                            for item in axis_outputs)
        drive_rows = tuple(drive for drive in installed_replay.drives
                           if drive.checkpoint_ref == prior.checkpoint_ref)
        driver_refs = tuple(sorted(sourced_numeric_drive_write(drive).key.token
                                   for drive in drive_rows))
        current_sources = {drive.source_ref for drive in drive_rows}
        if not driver_refs:
            raise JointStateOutputHold("member current drive closure is empty")
        readout_digest = canonical_digest(axis_outputs)
        if type(prior.state) is AuthoredFeelingStateV1:
            next_state = replace(
                prior.state, coordinates=coordinates, active_driver_refs=driver_refs,
                readout_proof_digest=readout_digest,
                historical_source_refs=tuple(sorted(
                    set(prior.state.historical_source_refs) | current_sources)),
                cursor=candidate.role_end, revision=prior.state_revision + 1,
                status="authored_joint_continuation",
            )
        elif type(prior.state) is AuthoredMoodStateV1:
            next_state = replace(
                prior.state, coordinates=coordinates, active_driver_refs=driver_refs,
                readout_proof_digest=readout_digest,
                source_refs=tuple(sorted(set(prior.state.source_refs) | current_sources)),
                cursor=candidate.role_end, revision=prior.state_revision + 1,
                status="authored_joint_continuation",
            )
        elif type(prior.state) is FeelingState:
            next_state = replace(
                prior.state, coordinates=coordinates,
                active_driver_refs=driver_refs,
                historical_source_refs=tuple(sorted(
                    set(prior.state.historical_source_refs) | current_sources)),
                cursor=candidate.role_end, revision=prior.state_revision + 1,
            )
        else:
            next_state = replace(
                prior.state, coordinates=coordinates,
                source_refs=tuple(sorted(set(prior.state.source_refs)
                                         | current_sources)),
                cursor=candidate.role_end, revision=prior.state_revision + 1,
            )
        certificate_digest = canonical_digest({
            "schema": SCHEMA, "member": prior.checkpoint_ref,
            "full_transcript": candidate.full_transcript_sha256,
            "native_error": native_error, "latent": values,
            "box": boxes, "scalar_error": scalar_error,
            "policy": policy.digest,
        })
        common_checkpoint = dict(
            latent_state=values, certified_box=boxes,
            numeric_error_bound=scalar_error,
            certificate_digest=certificate_digest, cursor=candidate.role_end,
            graph_state=CommittedRef(prior.state_ref, prior.state_revision + 1),
            readout_proof_digest=readout_digest,
            commit_operation_id=frozen_predecessors.operation_id,
            predecessor_receipt_digest=prior.predecessor_receipt_digest,
        )
        if authored:
            next_checkpoint = replace(
                prior.checkpoint, **common_checkpoint,
                status="trusted_joint_advance",
            )
        else:
            next_checkpoint = replace(
                prior.checkpoint, **common_checkpoint,
                certificate_source="trusted_abi2",
                predecessor_kind=("root" if prior.checkpoint.predecessor_kind == "none"
                                  else "advance"),
            )
        members.append(JointStateOutputMemberV1(
            prior.checkpoint_ref, prior.checkpoint_revision,
            canonical_digest(joint_checkpoint_payload_v1(prior.checkpoint)),
            prior.state_ref, prior.state_revision,
            canonical_digest(joint_state_payload_v1(prior.state)),
            prior.checkpoint.block.kind, next_checkpoint, next_state,
            axis_outputs, native_error,
        ))
    members = tuple(members)
    write_set = _write_set(members)
    float_bits = []
    for member in members:
        float_bits.extend(_bits(value) for value in member.next_checkpoint.latent_state)
        float_bits.extend(_bits(bound) for box in member.next_checkpoint.certified_box
                          for bound in box)
        float_bits.append(_bits(member.next_checkpoint.numeric_error_bound))
        float_bits.append(_bits(member.native_trajectory_error_2norm))
        for axis in member.axes:
            float_bits.extend(_bits(value) for value in (
                axis.certified_lower, axis.certified_upper, axis.representative,
                axis.representative_error,
            ))
    fields_data = dict(
        schema=AUTHORED_SCHEMA if authored else SCHEMA, namespace=candidate.namespace,
        operation_id=frozen_predecessors.operation_id,
        component_digest=candidate.component_digest,
        graph_incarnation=candidate.graph_incarnation,
        graph_revision=candidate.graph_revision, graph_epoch=candidate.graph_epoch,
        access_epoch=candidate.access_epoch, delete_epoch=candidate.delete_epoch,
        role_start=candidate.role_start, role_end=candidate.role_end,
        member_refs=candidate.member_refs, axis_ids=REGISTERED_AXIS_IDS,
        full_transcript_sha256=candidate.full_transcript_sha256,
        family_transcripts=candidate.family_transcripts,
        math_transcript_sha256=candidate.math_transcript_sha256,
        full_output_sha256=math_result.full_transcript.output_sha256,
        native_manifest_sha256=candidate.native_manifest_sha256,
        native_sha256=candidate.native_sha256,
        native_abi_version=candidate.native_abi_version,
        policy_id=policy.policy_id, policy_version=policy.version,
        policy_digest=policy.digest,
        policy_sha256=policy_sha256,
        readout_id=policy.readout_id,
        readout_version=policy.readout_version,
        readout_sha256=policy.readout_sha256,
        native_trajectory_error_2norm=native_error,
        members=members, write_set_digest=canonical_digest(write_set),
        binary64_bits_digest=canonical_digest(tuple(float_bits)),
    )
    return JointStateOutputOriginalV1(
        **fields_data, original_digest=canonical_digest(fields_data),
    )


def verify_current_joint_state_output_original_v1(
    original: JointStateOutputOriginalV1,
    installed_replay: D04InstalledJointNumericReplayV1,
    frozen_predecessors: JointStateFrozenPredecessorsV1,
    installed_policy: object,
) -> bool:
    """W01's lock-local arithmetic comparison; W01 supplies its pinned inputs."""
    from ...host.installed_d04_output_policy import InstalledD04OutputPolicyBindingV1

    if (type(original) is not JointStateOutputOriginalV1
            or not is_package_bound_joint_numeric_replay_v1(installed_replay)
            or type(installed_policy) is not InstalledD04OutputPolicyBindingV1
            or installed_policy.runtime_scope not in {"formal-alpha1", "backend-production-acceptance", "backend-local-alpha2-acceptance", "backend-beta1-server-test"}
            or type(installed_policy.policy) is not JointStateOutputPolicyV1
            or installed_policy.manifest_sha256
               != installed_replay.candidate.native_manifest_sha256):
        return False
    try:
        expected = _derive_joint_state_outputs_v1(
            installed_replay, frozen_predecessors, installed_policy.policy,
            installed_policy.policy_sha256,
        )
    except (TypeError, ValueError, OverflowError):
        return False
    return original == expected


__all__ = [
    "JointStateOutputHold", "JointStateOutputPolicyV1",
    "JointStatePredecessorV1", "JointStateFrozenPredecessorsV1",
    "JointStateAxisOutputV1", "JointStateOutputMemberV1",
    "JointStateOutputOriginalV1", "issue_joint_state_outputs_v1",
    "verify_current_joint_state_output_original_v1",
]
