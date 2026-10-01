"""Once-only root math and purely deterministic durable proof verification.

Neither function grants an execution right or authenticates an original.
The installed caller must obtain the dedicated Authority root claim before
execution, and authenticate its terminal/artifact before final adoption.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import math

from ...native_runtime.initial_box_trajectory import _box_digest, _native_initial_radius
from ...native_runtime.loader import ABI2NativeLibrary, NativeLoadBinding
from ...native_runtime.d04_tanh_readout_asset import D04LoadedTanhReadoutAsset
from ...runtime_contracts import canonical_digest
from .authored_lineage_v3 import (
    AuthoredRootCandidateV3, AuthoredInitialBoxProofV3, AuthoredInitialBoxBlockProofV3, AuthoredRootWritesCandidateV3,
    _covers_box, issue_authored_root_writes_v3,
)
from .joint_state_output_v1 import JointStateOutputPolicyV1


SCHEMA = "d04.authored-root-math-artifact.v3"


@dataclass(frozen=True, slots=True)
class AuthoredRootMathArtifactV3:
    candidate_digest: str
    operation_id: str
    initial_box_proof: AuthoredInitialBoxProofV3
    output: AuthoredRootWritesCandidateV3
    artifact_digest: str
    schema: str = SCHEMA


def _payload(candidate_digest, operation_id, proof, output):
    from ...runtime.d04_semantic_mapping_v3 import evidence_payload_v3
    return {"schema": SCHEMA, "candidate_digest": candidate_digest, "operation_id": operation_id,
        "initial_box_proof": evidence_payload_v3(proof), "output": evidence_payload_v3(output)}


def execute_authored_root_math_once_v3(handle, candidate, readout, output_policy, operation_id):
    """One native initial-box pass; caller measures this complete synchronous call."""
    if (not isinstance(handle, ABI2NativeLibrary) or type(candidate) is not AuthoredRootCandidateV3
            or type(readout) is not D04LoadedTanhReadoutAsset or type(output_policy) is not JointStateOutputPolicyV1):
        raise TypeError("installed authored root execution inputs required")
    from ...native_runtime.d04_fixed_trajectory_v2 import _require_cpu_v2
    binding = handle.production_binding
    if (type(binding) is not NativeLoadBinding or binding.abi_version != 2
            or not handle.capabilities.supports_initial_box_math_v1 or handle._initial_box is None):
        raise ValueError("actual package-bound root initial-box capability required")
    blocks = []
    for checkpoint in candidate.checkpoints:
        lower = tuple(pair[0] for pair in checkpoint.ordered_box)
        upper = tuple(pair[1] for pair in checkpoint.ordered_box)
        _require_cpu_v2()
        radius = _native_initial_radius(handle, checkpoint.latent_state, lower, upper)
        _require_cpu_v2()
        blocks.append(AuthoredInitialBoxBlockProofV3(canonical_digest(asdict(checkpoint)),
            _box_digest(checkpoint.latent_state, lower, upper, radius, binding), radius))
    fields = dict(candidate_digest=candidate.digest, production_binding=binding,
        binding_digest=canonical_digest(asdict(binding)), blocks=tuple(blocks),
        status="conditional_native_math_pending_w01_replay")
    proof = AuthoredInitialBoxProofV3(**fields, proof_digest=canonical_digest(fields))
    output = issue_authored_root_writes_v3(candidate, proof, readout, output_policy, operation_id)
    body = _payload(candidate.digest, operation_id, proof, output)
    return AuthoredRootMathArtifactV3(candidate.digest, operation_id, proof, output, canonical_digest(body))


def verify_authored_root_math_artifact_v3(candidate, artifact, expected_native_binding,
                                        readout, output_policy, operation_id):
    """Verify terminal-authenticated values without loading/calling native code.

    The exact rational enclosure is checked independently. Native origin comes
    from the caller's actual root terminal, not from this DTO or its own hash.
    """
    from ...runtime.d04_semantic_mapping_v3 import evidence_payload_v3
    if (type(candidate) is not AuthoredRootCandidateV3 or type(artifact) is not AuthoredRootMathArtifactV3
            or type(expected_native_binding) is not NativeLoadBinding
            or type(readout) is not D04LoadedTanhReadoutAsset or type(output_policy) is not JointStateOutputPolicyV1
            or artifact.schema != SCHEMA or artifact.candidate_digest != candidate.digest
            or artifact.operation_id != operation_id or expected_native_binding.abi_version != 2):
        raise ValueError("authored root artifact identities differ")
    proof = artifact.initial_box_proof
    if type(proof) is not AuthoredInitialBoxProofV3 or type(artifact.output) is not AuthoredRootWritesCandidateV3:
        raise ValueError("authored root artifact DTOs differ")
    proof_body = dict(candidate_digest=proof.candidate_digest, production_binding=proof.production_binding,
        binding_digest=proof.binding_digest, blocks=proof.blocks, status=proof.status)
    if (proof.candidate_digest != candidate.digest or proof.production_binding != expected_native_binding
            or proof.binding_digest != canonical_digest(asdict(expected_native_binding))
            or proof.proof_digest != canonical_digest(proof_body)
            or proof.status != "conditional_native_math_pending_w01_replay"
            or len(proof.blocks) != len(candidate.checkpoints)
            or artifact.artifact_digest != canonical_digest(_payload(candidate.digest, operation_id, proof, artifact.output))):
        raise ValueError("authored root complete native proof differs")
    seen = set()
    for checkpoint, block in zip(candidate.checkpoints, proof.blocks):
        expected_checkpoint = canonical_digest(asdict(checkpoint))
        radius = block.verified_initial_error
        lower, upper = tuple(pair[0] for pair in checkpoint.ordered_box), tuple(pair[1] for pair in checkpoint.ordered_box)
        if (block.checkpoint_digest != expected_checkpoint or expected_checkpoint in seen
                or type(radius) not in (int, float) or not math.isfinite(radius) or radius < 0
                or not _covers_box(checkpoint.latent_state, checkpoint.ordered_box, radius)
                or block.initial_box_digest != _box_digest(checkpoint.latent_state, lower, upper,
                    radius, expected_native_binding)):
            raise ValueError("authored root block radius or exact input commitment differs")
        seen.add(expected_checkpoint)
    output = issue_authored_root_writes_v3(candidate, proof, readout, output_policy, operation_id)
    if evidence_payload_v3(output) != evidence_payload_v3(artifact.output):
        raise ValueError("authored root deterministic readout/write set differs")
    return output


def encode_authored_root_math_artifact_v3(artifact):
    if type(artifact) is not AuthoredRootMathArtifactV3:
        raise TypeError("typed authored root artifact required")
    body = _payload(artifact.candidate_digest, artifact.operation_id, artifact.initial_box_proof, artifact.output)
    if artifact.schema != SCHEMA or canonical_digest(body) != artifact.artifact_digest:
        raise ValueError("authored root artifact commitment differs")
    return {**body, "artifact_digest": artifact.artifact_digest}


def decode_authored_root_math_artifact_v3(raw):
    from ...runtime.d04_numeric_artifact_v3 import _json, decode_numeric_dto_v3
    value = _json(raw)
    if (set(value) != {"schema", "candidate_digest", "operation_id", "initial_box_proof", "output", "artifact_digest"}
            or value["schema"] != SCHEMA
            or canonical_digest({key: item for key, item in value.items() if key != "artifact_digest"}) != value["artifact_digest"]):
        raise ValueError("authored root artifact wire differs")
    artifact = AuthoredRootMathArtifactV3(value["candidate_digest"], value["operation_id"],
        decode_numeric_dto_v3(AuthoredInitialBoxProofV3, value["initial_box_proof"]),
        decode_numeric_dto_v3(AuthoredRootWritesCandidateV3, value["output"]), value["artifact_digest"])
    if encode_authored_root_math_artifact_v3(artifact) != value:
        raise ValueError("authored root artifact round trip differs")
    return artifact


__all__ = ("AuthoredRootMathArtifactV3", "execute_authored_root_math_once_v3",
    "verify_authored_root_math_artifact_v3", "encode_authored_root_math_artifact_v3",
    "decode_authored_root_math_artifact_v3")
