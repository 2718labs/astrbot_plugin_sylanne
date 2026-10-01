"""Conditional normalized projection for an authored D04 root.

This does not adopt a root, authenticate installed package bytes, or create a
Feeling/Mood graph state. W01 must replay the initial-box proof against its
installed ABI2 handle and atomically bind the projected state to its root
checkpoint and durable output original. Legacy V1 roots remain unchanged.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from fractions import Fraction
import math
import struct

from ...native_runtime.authored_root_initial_box import AuthoredRootInitialBoxMathCandidate
from ...native_runtime.d04_tanh_readout_asset import D04LoadedTanhReadoutAsset, TRANSFORM
from ...native_runtime.loader import NativeLoadBinding
from ...native_runtime.tanh_asset_readout import run_d04_conditional_tanh_readout_math
from ...runtime_contracts import canonical_digest
from .joint_state_output_v1 import (
    JointStateAxisOutputV1, JointStateOutputPolicyV1, _axis_output,
)
from .numeric_coupling import REGISTERED_AXIS_IDS
from .root import AuthoredRootCandidate, encode_root_checkpoint_candidate


class RootProjectionHold(ValueError):
    """The initial box cannot support this fixed normalized root projection."""


@dataclass(frozen=True, slots=True)
class RootProjectionMemberCandidateV2:
    block_id: str
    kind: str
    checkpoint_candidate_digest: str
    initial_box_digest: str
    latent_state: tuple[float, ...]
    ordered_box: tuple[tuple[float, float], ...]
    verified_initial_error: float
    axes: tuple[JointStateAxisOutputV1, ...]
    readout_proof_digest: str

    @property
    def coordinates(self) -> tuple[tuple[str, float], ...]:
        return tuple((axis.axis_id, axis.representative) for axis in self.axes)


@dataclass(frozen=True, slots=True)
class RootProjectionCandidateV2:
    root_candidate_digest: str
    initial_box_transcript_sha256: str
    native_manifest_sha256: str
    native_sha256: str
    native_abi_version: int
    policy_digest: str
    readout_sha256: str
    member_block_ids: tuple[str, ...]
    members: tuple[RootProjectionMemberCandidateV2, ...]
    projection_digest: str
    semantic_calibration: str = "unvalidated"
    status: str = "candidate_hold_for_w01_root_adoption"

    def __post_init__(self) -> None:
        if (self.semantic_calibration != "unvalidated"
                or self.status != "candidate_hold_for_w01_root_adoption"
                or not self.members
                or self.member_block_ids != tuple(member.block_id for member in self.members)):
            raise ValueError("root projection cannot grant product adoption")


def _bits(value: float) -> bytes:
    return struct.pack("!d", value)


def _identity_asset(asset: D04LoadedTanhReadoutAsset,
                    policy: JointStateOutputPolicyV1) -> None:
    if (asset.axis_ids != REGISTERED_AXIS_IDS or len(asset.rows) != 24
            or asset.readout_id != policy.readout_id
            or asset.readout_version != policy.readout_version
            or asset.asset_sha256 != policy.readout_sha256):
        raise RootProjectionHold("root readout differs from fixed output policy")
    zero, one = _bits(0.0), _bits(1.0)
    for index, row in enumerate(asset.rows):
        if (row.axis_id != REGISTERED_AXIS_IDS[index]
                or row.output_version != policy.readout_version
                or row.transform != TRANSFORM
                or len(row.coefficients) != 24
                or tuple(_bits(weight) for weight in row.coefficients)
                   != tuple(one if column == index else zero for column in range(24))):
            raise RootProjectionHold("root projection requires exact identity tanh")


def _covers_box(centers: tuple[float, ...], box: tuple[tuple[float, float], ...],
                radius: float) -> bool:
    if type(radius) is not float or not math.isfinite(radius) or radius < 0:
        return False
    squared = sum((max(Fraction.from_float(center) - Fraction.from_float(low),
                       Fraction.from_float(high) - Fraction.from_float(center)) ** 2
                   for center, (low, high) in zip(centers, box)), Fraction())
    return Fraction.from_float(radius) ** 2 >= squared


def project_authored_root_candidate_v2(
    root: AuthoredRootCandidate,
    initial_box_math: AuthoredRootInitialBoxMathCandidate,
    readout: D04LoadedTanhReadoutAsset,
    policy: JointStateOutputPolicyV1,
) -> RootProjectionCandidateV2:
    """Derive one held normalized projection per exact root block and box."""
    if (type(root) is not AuthoredRootCandidate
            or type(initial_box_math) is not AuthoredRootInitialBoxMathCandidate
            or type(readout) is not D04LoadedTanhReadoutAsset
            or type(policy) is not JointStateOutputPolicyV1):
        raise TypeError("root projection needs typed root, math, readout and policy")
    binding = initial_box_math.production_binding
    if (root.status != "candidate"
            or root.preset.axes != REGISTERED_AXIS_IDS
            or root.preset.assets.readout_sha256 != readout.asset_sha256
            or root.preset.assets.readout_version != readout.readout_version
            or root.digest != initial_box_math.candidate_sha256
            or initial_box_math.status != "conditional_math_candidate"
            or len(initial_box_math.blocks) != len(root.checkpoints)
            or type(binding) is not NativeLoadBinding
            or binding.abi_version != 2
            or initial_box_math.binding_sha256 != canonical_digest(asdict(binding))
            or initial_box_math.transcript_sha256 != canonical_digest({
                "schema": "d04.authored-root-initial-box-math.v1",
                "candidate_sha256": root.digest,
                "binding_sha256": initial_box_math.binding_sha256,
                "blocks": [asdict(block) for block in initial_box_math.blocks],
                "status": "conditional_math_candidate",
            })):
        raise RootProjectionHold("root initial-box math or installed identity differs")
    _identity_asset(readout, policy)
    members = []
    for checkpoint, block_math in zip(root.checkpoints, initial_box_math.blocks):
        checkpoint_digest = canonical_digest(encode_root_checkpoint_candidate(checkpoint))
        if (checkpoint_digest != block_math.checkpoint_sha256
                or not _covers_box(checkpoint.latent_state, checkpoint.ordered_box,
                                   block_math.verified_initial_error)):
            raise RootProjectionHold("root block initial box proof is incomplete")
        try:
            math_result = run_d04_conditional_tanh_readout_math(
                readout, checkpoint.latent_state, block_math.verified_initial_error,
            )
        except (ValueError, OverflowError) as exc:
            raise RootProjectionHold("root normalized readout failed") from exc
        if (math_result.asset_sha256 != policy.readout_sha256
                or len(math_result.outputs) != len(REGISTERED_AXIS_IDS)):
            raise RootProjectionHold("root normalized readout is incomplete")
        axes = []
        for axis, row, output in zip(REGISTERED_AXIS_IDS, readout.rows,
                                     math_result.outputs):
            if axis != row.axis_id or axis != output.axis_id or row.output_id != output.output_id:
                raise RootProjectionHold("root readout axis order differs")
            try:
                axes.append(_axis_output(
                    axis, row.output_id, output.lower, output.upper,
                    policy.max_readout_interval_width,
                ))
            except (ValueError, OverflowError) as exc:
                raise RootProjectionHold("root readout interval exceeds policy") from exc
        outputs = tuple(axes)
        members.append(RootProjectionMemberCandidateV2(
            checkpoint.block_id, checkpoint.block.kind,
            checkpoint_digest, block_math.initial_box_sha256,
            checkpoint.latent_state, checkpoint.ordered_box,
            block_math.verified_initial_error, outputs, canonical_digest(outputs),
        ))
    members = tuple(members)
    data = {
        "schema": "d04.root-projection-candidate.v2",
        "root": root.digest,
        "initial_box": initial_box_math.transcript_sha256,
        "manifest": binding.manifest_sha256,
        "native": binding.native_sha256,
        "policy": policy.digest,
        "readout": readout.asset_sha256,
        "members": members,
    }
    return RootProjectionCandidateV2(
        root.digest, initial_box_math.transcript_sha256,
        binding.manifest_sha256, binding.native_sha256, binding.abi_version,
        policy.digest, readout.asset_sha256,
        tuple(member.block_id for member in members), members,
        canonical_digest(data),
    )


__all__ = [
    "RootProjectionHold", "RootProjectionMemberCandidateV2",
    "RootProjectionCandidateV2", "project_authored_root_candidate_v2",
]
