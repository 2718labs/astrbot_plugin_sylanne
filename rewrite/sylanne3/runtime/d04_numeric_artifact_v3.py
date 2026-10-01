"""Strict durable D04 full/LOO artifacts. Decoding never grants execution.

The codec has a closed set of trusted Python DTO definitions. External data
cannot name a class, import a module, install a decoder or register a replay.
Every binary64 value uses the same exact-bit representation as frozen inputs.
"""
from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from decimal import Decimal
from fractions import Fraction
import json
import math
import struct
import sys
import types
from typing import get_args, get_origin, get_type_hints, Union

from ..authority_service.d04_numeric_contract_v3 import D04NumericClaimV3, D04NumericMeasurementV3
from ..domains.d04.affect import FeelingState, MoodField
from ..domains.d04.authored_lineage_v3 import (
    AuthoredFeelingStateV1, AuthoredMoodStateV1, AuthoredNumericCheckpointV2, RootAuthoredFacetV3,
    AuthoredRootCandidateV3, RootCheckpointCandidateV3, AuthoredInitialBoxBlockProofV3,
    AuthoredInitialBoxProofV3, AuthoredRootWriteMemberV3, AuthoredRootWritesCandidateV3,
)
from ..domains.d04.encoding_baseline import CommittedRef
from ..domains.d04.joint_state_output_v1 import (
    JointStateAxisOutputV1, JointStateFrozenPredecessorsV1, JointStateOutputMemberV1,
    JointStateOutputOriginalV1, JointStatePredecessorV1,
)
from ..domains.d04.numeric_coupling import NumericCoupling
from ..domains.d04.numeric_drive import SourcedNumericDrive
from ..domains.d04.root import NumericCheckpoint, RootAssetBindings, RootBlockIdentity, AuthoredRootPreset, RootBlockTemplate
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch
from ..native_runtime.abi2 import NativeReportedFixedBlockIntervalBounds
from ..native_runtime.d04_joint_product_math import D04FamilyAssignment, D04JointMemberReadout, D04JointProductMathCandidate
from ..native_runtime.fixed_block_transcript import FixedBlockCSR, FixedBlockMathTranscript, FixedBlockTrajectoryMathTranscript, FixedBlockStep
from ..native_runtime.loader import NativeLoadBinding
from ..native_runtime.tanh_asset_readout import D04ConditionalTanhOutputInterval, D04ConditionalTanhReadoutMath
from ..runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity, QueryEpoch,
    SourceQualification, VersionGuard, VersionedRef, canonical_digest, canonical_serialize,
)
from .d04_appraisal_driver_v3 import D04GraphReadV3
from .d04_current_joint_replay_input_v2 import D04CurrentJointReplayInputV2
from .d04_joint_product_assembly_v3 import D04InstalledJointProductV3, D04JointProductPreparationV3
from .d04_numeric_cost_v3 import D04NumericPreparedV3
from .d04_numeric_policy_v3 import AdminD04JointNumericPolicyV3
from .d04_semantic_mapping_v3 import D04JointEvidenceInputsV3, D04RoleClockOriginalV3, evidence_payload_v3
from .joint_numeric_component import JointBlockDrives, JointNumericComponentCandidate


SCHEMA = "d04.numeric-artifact.v4"
ARTIFACT_KIND = "numeric_artifact"
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_TYPES = frozenset((NamespaceId, QueryEpoch, VersionedRef, OperationIdentity, AuthorityContext,
    VersionGuard, SourceQualification, CommandEnvelope, GraphVersion, NamespaceEpoch,
    CommittedRef, RootAssetBindings, RootBlockIdentity, NumericCheckpoint,
    RootAuthoredFacetV3, AuthoredNumericCheckpointV2, AuthoredFeelingStateV1, AuthoredMoodStateV1,
    AuthoredRootCandidateV3, RootCheckpointCandidateV3, AuthoredRootPreset, RootBlockTemplate,
    AuthoredInitialBoxBlockProofV3, AuthoredInitialBoxProofV3, AuthoredRootWriteMemberV3, AuthoredRootWritesCandidateV3,
    FeelingState, MoodField, NumericCoupling, SourcedNumericDrive, JointBlockDrives,
    JointNumericComponentCandidate, D04FamilyAssignment, D04JointMemberReadout, D04JointProductMathCandidate,
    FixedBlockCSR, FixedBlockStep, FixedBlockMathTranscript, FixedBlockTrajectoryMathTranscript, NativeReportedFixedBlockIntervalBounds,
    NativeLoadBinding, D04ConditionalTanhReadoutMath, D04ConditionalTanhOutputInterval,
    JointStatePredecessorV1, JointStateFrozenPredecessorsV1, JointStateAxisOutputV1,
    JointStateOutputMemberV1, JointStateOutputOriginalV1, D04GraphReadV3, D04RoleClockOriginalV3,
    D04JointEvidenceInputsV3, AdminD04JointNumericPolicyV3))
_NAMES = {value.__name__: value for value in _TYPES}
_HINTS = {}


class D04NumericArtifactHold(ValueError):
    """Artifact bytes or independently authenticated native evidence differ."""


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise D04NumericArtifactHold("numeric artifact has duplicate fields")
        value[key] = item
    return value


def _json(raw):
    if type(raw) is str:
        if len(raw.encode("utf-8")) > MAX_ARTIFACT_BYTES:
            raise D04NumericArtifactHold("numeric artifact exceeds installed bound")
        value = json.loads(raw, object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(D04NumericArtifactHold("nonfinite artifact")))
        if canonical_serialize(value) != raw:
            raise D04NumericArtifactHold("numeric artifact is not canonical")
        return value
    if type(raw) is not dict:
        raise D04NumericArtifactHold("numeric artifact object required")
    return _json(canonical_serialize(raw))


def _unpack(raw, depth=0):
    if depth > 64:
        raise D04NumericArtifactHold("numeric artifact nesting exceeds bound")
    if type(raw) is dict:
        if "$type" in raw:
            raise D04NumericArtifactHold("external class discriminators are forbidden")
        if set(raw) == {"binary64_be"}:
            value = raw["binary64_be"]
            if type(value) is not str or len(value) != 16 or any(c not in "0123456789abcdef" for c in value):
                raise D04NumericArtifactHold("invalid binary64 evidence")
            number = struct.unpack(">d", bytes.fromhex(value))[0]
            if not math.isfinite(number):
                raise D04NumericArtifactHold("nonfinite binary64 evidence")
            return number
        if set(raw) == {"decimal"}:
            number = Decimal(raw["decimal"])
            if not number.is_finite() or str(number) != raw["decimal"]:
                raise D04NumericArtifactHold("noncanonical decimal evidence")
            return number
        if set(raw) == {"rational"}:
            pair = raw["rational"]
            if type(pair) is not list or len(pair) != 2 or any(type(v) is not int for v in pair) or pair[1] <= 0:
                raise D04NumericArtifactHold("invalid rational evidence")
            value = Fraction(*pair)
            if [value.numerator, value.denominator] != pair:
                raise D04NumericArtifactHold("noncanonical rational evidence")
            return value
        return {key: _unpack(value, depth + 1) for key, value in raw.items()}
    if type(raw) is list:
        if len(raw) > 2_000_000:
            raise D04NumericArtifactHold("numeric artifact array exceeds bound")
        return [_unpack(value, depth + 1) for value in raw]
    if raw is None or type(raw) in {str, bool, int}:
        return raw
    # Untagged JSON floats would lose the exact encoding contract.
    raise D04NumericArtifactHold("unsupported or untagged numeric artifact value")


def _typed(kind, raw):
    origin, args = get_origin(kind), get_args(kind)
    if origin in (types.UnionType, Union):
        matches = []
        for option in args:
            try:
                matches.append(_typed(option, raw))
            except (TypeError, ValueError, KeyError):
                pass
        if len(matches) != 1:
            raise D04NumericArtifactHold("numeric DTO variant is absent or ambiguous")
        return matches[0]
    if kind is type(None):
        if raw is not None:
            raise D04NumericArtifactHold("unexpected numeric DTO value")
        return None
    if kind is AtomKey:
        if type(raw) is not str:
            raise D04NumericArtifactHold("numeric graph key must be a canonical token")
        value = AtomKey.from_token(raw)
        if value.token != raw:
            raise D04NumericArtifactHold("numeric graph key is not canonical")
        return value
    if kind in (str, int, bool):
        if type(raw) is not kind:
            raise D04NumericArtifactHold("numeric DTO primitive type differs")
        return raw
    if kind is float:
        if type(raw) not in (float, int) or not math.isfinite(raw):
            raise D04NumericArtifactHold("finite numeric DTO scalar required")
        return raw
    if origin is tuple:
        if type(raw) is not list:
            raise D04NumericArtifactHold("numeric DTO tuple requires an array")
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_typed(args[0], value) for value in raw)
        if len(raw) != len(args):
            raise D04NumericArtifactHold("numeric DTO tuple length differs")
        return tuple(_typed(child, value) for child, value in zip(args, raw))
    if kind is FixedBlockTrajectoryMathTranscript:
        from ..native_runtime.d04_fixed_trajectory_v2 import decode_compact_d04_fixed_trajectory_v2
        return decode_compact_d04_fixed_trajectory_v2(raw, _typed)
    if kind in _TYPES and is_dataclass(kind):
        names = {field.name for field in fields(kind)}
        if type(raw) is not dict or set(raw) != names:
            raise D04NumericArtifactHold("numeric DTO fields differ: " + kind.__name__)
        if kind not in _HINTS:
            # These annotations are trusted installed source, never input text.
            _HINTS[kind] = get_type_hints(kind, globalns=vars(sys.modules[kind.__module__]), localns=_NAMES)
        return kind(**{name: _typed(_HINTS[kind][name], raw[name]) for name in names})
    raise D04NumericArtifactHold("unregistered numeric DTO field type")


def numeric_artifact_payload_v3(value):
    """Exact-bit DTO serializer with one bounded, complete fixed-model chain codec."""
    if isinstance(value, AtomKey):
        return value.token
    if type(value) is FixedBlockTrajectoryMathTranscript:
        from ..native_runtime.d04_fixed_trajectory_v2 import compact_d04_fixed_trajectory_v2
        return compact_d04_fixed_trajectory_v2(value)
    if is_dataclass(value):
        return {field.name: numeric_artifact_payload_v3(getattr(value, field.name)) for field in fields(value)}
    if type(value) in (tuple, list):
        return [numeric_artifact_payload_v3(item) for item in value]
    return evidence_payload_v3(value)


def decode_numeric_dto_v3(kind, raw):
    """Decode only a fixed installed DTO type; this returns no trusted witness."""
    if kind not in _TYPES:
        raise D04NumericArtifactHold("numeric DTO type is not installed")
    value = _typed(kind, _unpack(raw))
    if numeric_artifact_payload_v3(value) != raw:
        raise D04NumericArtifactHold("numeric DTO canonical round trip differs")
    return value


@dataclass(frozen=True, slots=True)
class DecodedD04NumericInputV3:
    preparation: D04JointProductPreparationV3
    evidence_inputs: D04JointEvidenceInputsV3
    numeric_policy: AdminD04JointNumericPolicyV3
    holder: str
    worker_fence: int


def decode_d04_numeric_prepared_input_v3(prepared):
    if type(prepared) is not D04NumericPreparedV3:
        raise D04NumericArtifactHold("actual typed numeric preparation required")
    raw = _json(prepared.input_payload_json)
    if (set(raw) != {"schema", "read_rows", "installed_identity", "mapping_original_refs", "numeric_request",
                    "evidence_inputs", "command_envelope", "worker_original", "numeric_policy"}
            or raw["schema"] != "d04.numeric-frozen-work-input.v3"
            or canonical_digest(raw) != prepared.binding.input_digest):
        raise D04NumericArtifactHold("numeric frozen input shape or identity differs")
    request = raw["numeric_request"]
    if type(request) is not dict or set(request) != {"component", "checkpoints", "drives", "families",
            "predecessors", "max_iterations", "tolerance", "clock"}:
        raise D04NumericArtifactHold("numeric frozen recipe fields differ")
    component = decode_numeric_dto_v3(JointNumericComponentCandidate, request["component"])
    authored = component.root_original_digest is not None
    checkpoints = tuple(decode_numeric_dto_v3(AuthoredNumericCheckpointV2 if authored else NumericCheckpoint, row)
                        for row in request["checkpoints"])
    drives = tuple(decode_numeric_dto_v3(SourcedNumericDrive, row) for row in request["drives"])
    families = tuple(decode_numeric_dto_v3(D04FamilyAssignment, row) for row in request["families"])
    predecessors = decode_numeric_dto_v3(JointStateFrozenPredecessorsV1, request["predecessors"])
    evidence = decode_numeric_dto_v3(D04JointEvidenceInputsV3, raw["evidence_inputs"])
    envelope = decode_numeric_dto_v3(CommandEnvelope, raw["command_envelope"])
    numeric_policy = decode_numeric_dto_v3(AdminD04JointNumericPolicyV3, raw["numeric_policy"])
    read_rows = tuple(decode_numeric_dto_v3(D04GraphReadV3, row) for row in raw["read_rows"])
    if (read_rows != evidence.read_rows or len({row.ref for row in read_rows}) != len(read_rows)
            or evidence.namespace != prepared.binding.namespace or component.namespace != prepared.binding.namespace
            or evidence.component_digest != component.candidate_digest or evidence.member_refs != component.checkpoint_refs
            or envelope.authority.namespace != prepared.binding.namespace
            or envelope.identity.operation_id != prepared.binding.operation_id
            or envelope.identity.activity_id != prepared.binding.activity_id
            or envelope.authority.activation_generation != prepared.binding.activation_generation
            or envelope.parent_budget_lease_ref != prepared.binding.parent_budget_lease_ref
            or predecessors.namespace != prepared.binding.namespace or predecessors.operation_id != prepared.binding.operation_id
            or evidence_payload_v3(evidence.clock) != request["clock"]):
        raise D04NumericArtifactHold("numeric frozen current/evidence/predecessor identities differ")
    identity = raw["installed_identity"]
    expected_identity = {name: getattr(prepared.binding, name) for name in (
        "installation_id", "owner_grant_ref", "owner_grant_revision", "owner_grant_digest", "algorithm_id",
        "algorithm_build_digest", "native_manifest_sha256", "native_sha256", "output_policy_digest")}
    if (identity != expected_identity or numeric_policy.namespace != prepared.binding.namespace
            or numeric_policy.installation_id != prepared.binding.installation_id
            or numeric_policy.lease_id != prepared.binding.parent_budget_lease_ref
            or numeric_policy.cpu_ceiling_ms != prepared.binding.cpu_ceiling_ms
            or request["max_iterations"] != numeric_policy.max_iterations
            or request["tolerance"] != evidence_payload_v3(numeric_policy.tolerance)):
        raise D04NumericArtifactHold("numeric frozen installed/limit identity differs")
    snapshot = GraphSnapshot(tuple(GraphAtom(AtomKey.from_token(row.ref), row.revision, json.loads(row.value_json), row.valid)
                                   for row in read_rows),
        (NamespaceEpoch(*prepared.binding.namespace.as_tuple, component.query_epoch.revision),))
    versions = {row.key.token: row.revision for row in snapshot.versions}
    if any(versions.get(version.key.token) != version.revision for version in component.read_versions):
        raise D04NumericArtifactHold("numeric frozen component read coverage differs")
    if (snapshot.versions != envelope.version_guard.read_versions
            or envelope.version_guard.query_epochs != (component.query_epoch,)
            or (envelope.version_guard.access_epoch, envelope.version_guard.delete_epoch) !=
                (component.access_epoch, component.delete_epoch)):
        raise D04NumericArtifactHold("numeric frozen envelope snapshot differs")
    worker = raw["worker_original"]
    if (type(worker) is not dict or set(worker) != {"holder", "fence", "cancel_epoch", "lease_expires_utc", "deadline_utc"}
            or type(worker["holder"]) is not str or not worker["holder"]
            or type(worker["fence"]) is not int or worker["fence"] < 1 or worker["cancel_epoch"] != 0
            or worker["fence"] != envelope.authority.worker_fence
            or worker["deadline_utc"] != prepared.binding.deadline_utc):
        raise D04NumericArtifactHold("numeric frozen running worker differs")
    current = D04CurrentJointReplayInputV2(component, checkpoints, drives, families)
    return DecodedD04NumericInputV3(D04JointProductPreparationV3(envelope, current, predecessors, snapshot),
        evidence, numeric_policy, worker["holder"], worker["fence"])


@dataclass(frozen=True, slots=True)
class UntrustedD04NumericArtifactV3:
    prepared_digest: str
    binding_digest: str
    input_digest: str
    claim_id: str
    math_result: D04JointProductMathCandidate
    output: JointStateOutputOriginalV1
    artifact_digest: str


def decode_d04_numeric_artifact_v3(raw):
    value = _json(raw)
    expected = {"schema", "prepared_digest", "binding_digest", "input_digest", "claim_id", "math_result", "output", "artifact_digest"}
    if (set(value) != expected or value["schema"] != SCHEMA
            or canonical_digest({k: v for k, v in value.items() if k != "artifact_digest"}) != value["artifact_digest"]):
        raise D04NumericArtifactHold("numeric artifact fields or digest differ")
    return UntrustedD04NumericArtifactV3(value["prepared_digest"], value["binding_digest"], value["input_digest"],
        value["claim_id"], decode_numeric_dto_v3(D04JointProductMathCandidate, value["math_result"]),
        decode_numeric_dto_v3(JointStateOutputOriginalV1, value["output"]), value["artifact_digest"])


def encode_d04_numeric_artifact_v3(prepared, claim, product):
    from ..domains.d04.trusted_joint_replay import is_package_bound_joint_numeric_replay_v1
    if (type(prepared) is not D04NumericPreparedV3 or type(claim) is not D04NumericClaimV3
            or type(product) is not D04InstalledJointProductV3 or not is_package_bound_joint_numeric_replay_v1(product.replay)
            or claim.binding_digest != prepared.binding.digest
            or product.preparation != decode_d04_numeric_prepared_input_v3(prepared).preparation):
        raise D04NumericArtifactHold("actual installed measured product and original preparation required")
    value = {"schema": SCHEMA, "prepared_digest": prepared.digest, "binding_digest": prepared.binding.digest,
        "input_digest": prepared.binding.input_digest, "claim_id": claim.claim_id,
        "math_result": numeric_artifact_payload_v3(product.replay.math_result), "output": evidence_payload_v3(product.output)}
    value["artifact_digest"] = canonical_digest(value)
    decode_d04_numeric_artifact_v3(value)
    return value


def verify_d04_numeric_artifact_commitments_v3(prepared, claim, measurement, raw):
    """Compare strict bodies to measurement; caller must authenticate originals."""
    if (type(prepared) is not D04NumericPreparedV3 or type(claim) is not D04NumericClaimV3
            or type(measurement) is not D04NumericMeasurementV3 or measurement.status != "completed"
            or claim.binding_digest != prepared.binding.digest or measurement.binding_digest != prepared.binding.digest
            or measurement.claim_id != claim.claim_id):
        raise D04NumericArtifactHold("numeric artifact lacks exact completed measurement")
    value = decode_d04_numeric_artifact_v3(raw)
    result = value.math_result
    if ((value.prepared_digest, value.binding_digest, value.input_digest, value.claim_id) !=
            (prepared.digest, prepared.binding.digest, prepared.binding.input_digest, claim.claim_id)
            or result.full_transcript_sha256 != measurement.full_transcript_digest
            or result.family_transcripts != measurement.family_loo_transcripts
            or tuple(family for family, _ in result.family_transcripts) != prepared.binding.family_roots
            or value.output.original_digest != measurement.output_original_digest
            or value.output.full_transcript_sha256 != result.full_transcript_sha256
            or value.output.family_transcripts != result.family_transcripts
            or result.full_transcript is None
            or result.full_transcript.transcript_sha256 != result.full_transcript_sha256
            or tuple((family, transcript.transcript_sha256) for family, transcript in result.family_transcript_originals)
               != result.family_transcripts):
        raise D04NumericArtifactHold("numeric artifact differs from authenticated measurement commitments")
    from ..native_runtime.fixed_block_transcript import _digest
    from ..native_runtime.d04_fixed_trajectory_v2 import verify_d04_fixed_trajectory_v2, fixed_d04_step_plan_v2, MAX_NATIVE_CALLS
    decoded = decode_d04_numeric_prepared_input_v3(prepared)
    component = decoded.preparation.current.component
    plan = fixed_d04_step_plan_v2(component.role_start, component.role_end)
    chains = (result.full_transcript, *(entry[1] for entry in result.family_transcript_originals))
    if result.trajectory_schema != "d04.joint-product-fixed-trajectory.v2" or len(plan) * len(chains) > MAX_NATIVE_CALLS:
        raise D04NumericArtifactHold("numeric complete trajectory policy differs")
    for chain in chains:
        verify_d04_fixed_trajectory_v2(chain, step_plan=plan)
    for transcript in (step for chain in chains for step in chain.steps):
        native = transcript.production_binding
        if (native.manifest_sha256 != prepared.binding.native_manifest_sha256
                or native.native_sha256 != prepared.binding.native_sha256 or native.abi_version != 2
                or transcript.input_sha256 != transcript.input.digest()
                or transcript.output_sha256 != _digest(transcript.output)
                or transcript.transcript_sha256 != _digest({
                    "schema": "abi2.fixed-block-math-transcript.v1",
                    "input_sha256": transcript.input_sha256, "output_sha256": transcript.output_sha256,
                    "manifest_sha256": native.manifest_sha256, "native_sha256": native.native_sha256,
                    "bounds": {field.name: getattr(transcript.bounds, field.name) for field in fields(transcript.bounds)}})):
            raise D04NumericArtifactHold("numeric artifact native transcript bytes differ from measured commitment")
    output_body = {field.name: getattr(value.output, field.name) for field in fields(value.output)
                   if field.name not in {"original_digest", "status"}}
    if (value.output.namespace != prepared.binding.namespace or value.output.operation_id != prepared.binding.operation_id
            or value.output.native_manifest_sha256 != prepared.binding.native_manifest_sha256
            or value.output.native_sha256 != prepared.binding.native_sha256
            or value.output.policy_digest != prepared.binding.output_policy_digest
            or value.output.full_output_sha256 != result.full_transcript.output_sha256
            or value.output.original_digest != canonical_digest(output_body)):
        raise D04NumericArtifactHold("numeric artifact output bytes differ from measured commitment")
    return value
