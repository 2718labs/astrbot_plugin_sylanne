"""D04 behaviour projection from a conditional, source-bound numeric readout.

This is the domain half of C06. A caller-created checkpoint, source head or
loaded asset cannot establish a current Authority fence or product adoption.
The projection therefore remains a candidate until D11 issues that credential.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from fractions import Fraction
import math
import struct
from typing import TYPE_CHECKING

from ...native_runtime.d04_tanh_readout_asset import D04LoadedTanhReadoutAsset
from ...native_runtime.d04_block_instances import D04BlockIdentity, D04BlockInstance
from ...native_runtime.tanh_asset_readout import (
    D04ConditionalTanhReadoutMath, run_d04_conditional_tanh_readout_math,
)
from ...native_runtime.d04_joint_product_math import (
    D04FamilyAssignment, D04JointProductMathCandidate,
)
from ...native_runtime.tanh_interval import _outward_binary64
from ...graph_types import AtomKey, GraphSnapshot
from ...memory_types import SourceRecord, source_key
from ...runtime_contracts import NamespaceId, canonical_digest
from ..d06 import source_correction_head_key
from .affect import AffectScheme, FeelingState, MoodField, _decode_feeling, _decode_mood
from .numeric_coupling import REGISTERED_AXIS_IDS, SCHEME_VERSION
from .root import NumericCheckpoint, decode_numeric_checkpoint, encode_numeric_checkpoint
from .source_head import D04SourceHeadRead, derive_d04_source_heads

if TYPE_CHECKING:
    from .joint_state_output_v1 import JointStateOutputOriginalV1


_TENDENCIES = {
    "gain_engagement": "approach",
    "loss_response": "pause",
    "affiliative_approach": "care",
    "boundary_protection": "protect_boundary",
    "agency_mobilization": "seek_clarification",
    "low_control_response": "seek_support",
    "self_congruence": "share",
    "self_discrepancy": "reflect",
}
_POLICY_VERSION = "d04.behaviour-projection.v1"


class D04ReadoutHold(ValueError):
    """The domain cannot safely form even a conditional behaviour candidate."""


@dataclass(frozen=True, slots=True)
class AffectiveTendencyCandidate:
    target_ref: str
    meaning_ref: str
    source_ref: str
    tendency: str
    layer: str
    axis_id: str
    output_id: str
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class AffectiveReadoutCandidate:
    checkpoint_ref: str
    checkpoint_revision: int
    graph_state_ref: str
    graph_state_revision: int
    cursor: float
    source_ref: str
    source_head_digest: str
    access_head_digest: str
    audience: tuple[str, ...]
    purpose: str
    asset_sha256: str
    proof_digest: str
    tendencies: tuple[AffectiveTendencyCandidate, ...]
    policy_version: str = _POLICY_VERSION
    status: str = "hold_for_d11_product_admission"


@dataclass(frozen=True, slots=True)
class D04MixedTendencyV2:
    """A whole feeling output; no individual source owns this value."""

    axis_id: str
    output_id: str
    tendency: str
    layer: str
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class D04FamilyIntervalEffectV2:
    """Full minus without-family for this interval, not historical causality."""

    family_id: str
    axis_id: str
    output_id: str
    lower: float
    upper: float
    semantics: str = "current_interval_drive_effect_given_committed_initial_state"


@dataclass(frozen=True, slots=True)
class D04MixedReadoutCandidateV2:
    checkpoint_ref: str
    checkpoint_revision: int
    target_ref: str
    meaning_ref: str
    historical_source_refs: tuple[str, ...]
    interpretation_refs: tuple[str, ...]
    active_driver_refs: tuple[str, ...]
    family_sources: tuple[tuple[str, tuple[str, ...]], ...]
    member_refs: tuple[str, ...]
    full_transcript_sha256: str
    family_transcripts: tuple[tuple[str, str], ...]
    math_transcript_sha256: str
    overall: tuple[D04MixedTendencyV2, ...]
    interval_effects: tuple[D04FamilyIntervalEffectV2, ...]
    proof_digest: str
    policy_version: str = "d04.mixed-readout.v2"
    status: str = "unsigned_hold_for_w01_current_joint_adoption_and_d12_original"

    def __post_init__(self) -> None:
        if (self.policy_version != "d04.mixed-readout.v2"
                or self.status != "unsigned_hold_for_w01_current_joint_adoption_and_d12_original"
                or any(item.semantics != "current_interval_drive_effect_given_committed_initial_state"
                       for item in self.interval_effects)):
            raise ValueError("mixed readout candidate cannot grant product adoption")


def project_mixed_affect_candidate_v2(
    *, checkpoint: NumericCheckpoint, checkpoint_ref: str,
    checkpoint_revision: int, scheme: AffectScheme,
    source_read: D04SourceHeadRead, asset: D04LoadedTanhReadoutAsset,
    joint_math: D04JointProductMathCandidate,
    families: tuple[D04FamilyAssignment, ...],
) -> D04MixedReadoutCandidateV2:
    """Project certified conditional branch math as an unsigned mixed premise.

    Source-family assignments and graph completeness remain W01/D06 premises.
    This function does not adopt a certificate or confer product authority.
    """
    if (type(checkpoint) is not NumericCheckpoint or type(scheme) is not AffectScheme
            or type(source_read) is not D04SourceHeadRead
            or type(asset) is not D04LoadedTanhReadoutAsset
            or type(joint_math) is not D04JointProductMathCandidate
            or type(families) is not tuple):
        raise TypeError("mixed readout needs typed conditional joint inputs")
    if (type(checkpoint_ref) is not str or type(checkpoint_revision) is not int
            or checkpoint_revision < 1 or checkpoint.block.kind != "feeling"
            or source_read.namespace != NamespaceId(*checkpoint.namespace)
            or len(source_read.snapshot.epochs) != 1
            or checkpoint.assets.readout_sha256 != asset.asset_sha256
            or checkpoint.axes != REGISTERED_AXIS_IDS
            or tuple(axis.axis_id for axis in scheme.axes) != checkpoint.axes
            or checkpoint.assets.scheme_version != scheme.scheme_version
            or checkpoint.assets.operator_version != scheme.operator_version
            or checkpoint.assets.parameter_version != scheme.parameter_version
            or checkpoint.assets.coupling_version != scheme.coupling_version):
        raise D04ReadoutHold("mixed checkpoint, Scheme or readout asset differs")
    key = AtomKey.from_token(checkpoint_ref)
    if (key.type_name != "d04.numeric_checkpoint.v1" or key.name != checkpoint.block.block_id
            or (key.owner.bot, key.owner.persona) != checkpoint.namespace):
        raise D04ReadoutHold("mixed checkpoint identity differs")
    state_atom = source_read.snapshot.get(AtomKey.from_token(checkpoint.graph_state.ref))
    if state_atom is None or not state_atom.valid:
        raise D04ReadoutHold("mixed feeling state is unavailable")
    try:
        feeling = _decode_feeling(state_atom.value)
        lineage = _complete_state_sources(
            checkpoint, key, checkpoint_revision,
            source_key(*checkpoint.namespace, checkpoint.block.authored_source_id).token,
            source_read,
        )
    except (TypeError, ValueError) as exc:
        raise D04ReadoutHold("mixed feeling lineage is incomplete") from exc
    closure = derive_d04_source_heads(tuple(D04BlockInstance(
        D04BlockIdentity(checkpoint.graph_state.ref, checkpoint.block.object_ref,
                         checkpoint.block.meaning_ref, ref), "", "", "", None, (),
    ) for ref in lineage), source_read)
    if closure.held or len(closure.heads) != len(lineage):
        raise D04ReadoutHold("mixed historical source access is incomplete")
    if (len(joint_math.member_refs) < 2
            or checkpoint_ref not in joint_math.member_refs
            or joint_math.member_refs != tuple(sorted(set(joint_math.member_refs)))
            or len(joint_math.members) != len(joint_math.member_refs)
            or tuple(member.checkpoint_ref for member in joint_math.members)
               != joint_math.member_refs
            or joint_math.status != "conditional_math_hold_for_fenced_graph_and_joint_adoption"
            or not joint_math.full_transcript_sha256
            or not joint_math.transcript_sha256):
        raise D04ReadoutHold("joint math member or full transcript is incomplete")
    member = next(item for item in joint_math.members
                  if item.checkpoint_ref == checkpoint_ref)
    full = member.full
    if (full.asset_sha256 != asset.asset_sha256
            or full.readout_id != asset.readout_id
            or full.state_centers != checkpoint.latent_state
            or full.state_error_2norm < _inherited_radius(checkpoint)
            or run_d04_conditional_tanh_readout_math(
                asset, full.state_centers, full.state_error_2norm) != full
            or len(full.outputs) != len(REGISTERED_AXIS_IDS)):
        raise D04ReadoutHold("mixed full readout differs from checkpoint or installed asset")
    family_ids = tuple(sorted({item.family_id for item in families
                               if type(item) is D04FamilyAssignment}))
    if (len(families) == 0 or len({item.source_ref for item in families}) != len(families)
            or any(type(item) is not D04FamilyAssignment
                   or item.source_ref not in lineage or not item.family_id for item in families)
            or tuple(family for family, _ in joint_math.family_transcripts) != family_ids
            or tuple(family for family, _ in member.without_family) != family_ids
            or tuple(family for family, _ in member.effects) != family_ids
            or any(not transcript for _, transcript in joint_math.family_transcripts)):
        raise D04ReadoutHold("joint family assignment or branch transcripts differ")
    overall = []
    for axis, row, output in zip(REGISTERED_AXIS_IDS, asset.rows, full.outputs):
        mechanism, layer = axis.split(":", 1)
        if (row.axis_id != axis or output.axis_id != axis
                or output.output_id != row.output_id
                or not math.isfinite(output.lower) or not math.isfinite(output.upper)
                or output.lower > output.upper):
            raise D04ReadoutHold("mixed whole feeling output is invalid")
        overall.append(D04MixedTendencyV2(
            axis, row.output_id, _TENDENCIES[mechanism], layer,
            output.lower, output.upper,
        ))
    effects = []
    for (family, without), (_, intervals) in zip(member.without_family, member.effects):
        if (without.asset_sha256 != asset.asset_sha256
                or without.readout_id != asset.readout_id
                or run_d04_conditional_tanh_readout_math(
                    asset, without.state_centers, without.state_error_2norm) != without
                or len(intervals) != len(overall)):
            raise D04ReadoutHold("mixed without-family readout is invalid")
        for whole, absent, interval in zip(full.outputs, without.outputs, intervals):
            low = _outward_binary64(
                Fraction.from_float(whole.lower) - Fraction.from_float(absent.upper),
                lower=True,
            )
            high = _outward_binary64(
                Fraction.from_float(whole.upper) - Fraction.from_float(absent.lower),
                lower=False,
            )
            if interval != (low, high) or absent.axis_id != whole.axis_id:
                raise D04ReadoutHold("mixed family effect differs from full-minus-without")
            effects.append(D04FamilyIntervalEffectV2(
                family, whole.axis_id, whole.output_id, low, high,
            ))
    family_sources = tuple((family, tuple(sorted(item.source_ref for item in families
                                                   if item.family_id == family)))
                           for family in family_ids)
    proof = canonical_digest({
        "policy": "d04.mixed-readout.v2",
        "checkpoint": (checkpoint_ref, checkpoint_revision),
        "state": (checkpoint.graph_state.ref, checkpoint.graph_state.revision),
        "lineage": lineage,
        "source_heads": tuple(sorted((identity.source_ref, head.graph_source_version,
                                       head.access_version)
                                      for identity, head in closure.heads.items())),
        "audience": source_read.audience,
        "purpose": source_read.purpose,
        "graph_epoch": source_read.snapshot.epochs[0].revision,
        "interpretations": feeling.interpretation_refs,
        "drivers": feeling.active_driver_refs,
        "families": family_sources,
        "joint": (joint_math.component_digest, joint_math.transcript_sha256,
                  joint_math.full_transcript_sha256, joint_math.family_transcripts),
        "outputs": tuple((item.axis_id, item.lower, item.upper) for item in overall),
        "effects": tuple((item.family_id, item.axis_id, item.lower, item.upper)
                         for item in effects),
        "asset": asset.asset_sha256,
    })
    return D04MixedReadoutCandidateV2(
        checkpoint_ref, checkpoint_revision, checkpoint.block.object_ref,
        checkpoint.block.meaning_ref, lineage, feeling.interpretation_refs,
        feeling.active_driver_refs, family_sources, joint_math.member_refs,
        joint_math.full_transcript_sha256, joint_math.family_transcripts,
        joint_math.transcript_sha256, tuple(overall), tuple(effects), proof,
    )


def _inherited_radius(checkpoint: NumericCheckpoint) -> float:
    """Conservatively enclose the 2-norm from a committed coordinate box."""
    # NumericCheckpoint validates that this scalar covers every coordinate's
    # certified box. Outward rounding retains that invariant for the 2-norm.
    if checkpoint.numeric_error_bound == 0:
        return 0.0
    dimension = math.nextafter(math.sqrt(len(checkpoint.latent_state)), math.inf)
    bound = math.nextafter(checkpoint.numeric_error_bound, math.inf)
    radius = math.nextafter(dimension * bound, math.inf)
    if not math.isfinite(radius):
        raise D04ReadoutHold("inherited checkpoint error is not finite")
    return radius


def check_joint_output_against_snapshot_v2(
    original: JointStateOutputOriginalV1, snapshot: GraphSnapshot,
) -> None:
    """Check all V2 output graph values against a supplied joint original.

    This is a pure consistency check. Only W01 can establish that ``original``
    was durably adopted and that ``snapshot`` is a current Authority-fenced read.
    It does not issue a product readout or relax the legacy V1 root contract.
    """
    from .joint_state_output_v1 import JointStateOutputOriginalV1, SCHEMA as OUTPUT_SCHEMA

    if type(original) is not JointStateOutputOriginalV1 or type(snapshot) is not GraphSnapshot:
        raise TypeError("V2 output check needs a typed original and graph snapshot")
    if (original.schema != OUTPUT_SCHEMA
            or original.status != "issued_pending_w01_atomic_joint_adoption"
            or original.axis_ids != REGISTERED_AXIS_IDS
            or not original.members
            or original.member_refs != tuple(sorted(set(original.member_refs)))
            or original.member_refs != tuple(member.checkpoint_ref
                                             for member in original.members)):
        raise D04ReadoutHold("joint output member set is incomplete")
    body = {item.name: getattr(original, item.name) for item in fields(original)
            if item.name not in {"original_digest", "status"}}
    if canonical_digest(body) != original.original_digest:
        raise D04ReadoutHold("joint output original digest differs")
    write_rows = []
    float_bits = []
    for member in original.members:
        checkpoint_key = AtomKey.from_token(member.checkpoint_ref)
        state_key = AtomKey.from_token(member.predecessor_state_ref)
        checkpoint_atom = snapshot.get(checkpoint_key)
        state_atom = snapshot.get(state_key)
        if (checkpoint_atom is None or state_atom is None
                or not checkpoint_atom.valid or not state_atom.valid
                or NamespaceId.from_key(checkpoint_key) != original.namespace
                or state_key.owner != checkpoint_key.owner
                or member.next_checkpoint.namespace != original.namespace.as_tuple
                or checkpoint_atom.revision != member.predecessor_checkpoint_revision + 1
                or state_atom.revision != member.predecessor_state_revision + 1
                or member.next_checkpoint.graph_state.ref != state_key.token
                or member.next_checkpoint.graph_state.revision != state_atom.revision
                or member.next_checkpoint.commit_operation_id != original.operation_id
                or member.next_checkpoint.cursor != original.role_end
                or member.next_state.cursor != original.role_end
                or member.kind not in {"feeling", "mood"}
                or member.kind != member.next_checkpoint.block.kind
                or member.native_trajectory_error_2norm
                   != original.native_trajectory_error_2norm
                or len(member.axes) != len(REGISTERED_AXIS_IDS)
                or tuple(item.axis_id for item in member.axes) != REGISTERED_AXIS_IDS):
            raise D04ReadoutHold("joint output member graph identity differs")
        try:
            committed_checkpoint = decode_numeric_checkpoint(checkpoint_atom.value)
            committed_state = (_decode_feeling(state_atom.value)
                               if member.kind == "feeling" else _decode_mood(state_atom.value))
        except (TypeError, ValueError, KeyError) as exc:
            raise D04ReadoutHold("joint output graph value is invalid") from exc
        if (type(member.next_state) is not (FeelingState if member.kind == "feeling" else MoodField)
                or committed_checkpoint != member.next_checkpoint
                or committed_state != member.next_state
                or canonical_digest(checkpoint_atom.value)
                   != canonical_digest(encode_numeric_checkpoint(member.next_checkpoint))
                or canonical_digest(state_atom.value) != canonical_digest(asdict(member.next_state))
                or member.next_checkpoint.readout_proof_digest != canonical_digest(member.axes)
                or tuple(axis for axis, _ in committed_state.coordinates)
                   != REGISTERED_AXIS_IDS):
            raise D04ReadoutHold("joint output graph value differs from original")
        for (axis, value), proof in zip(committed_state.coordinates, member.axes):
            if (axis != proof.axis_id
                    or struct.pack("!d", value) != struct.pack("!d", proof.representative)
                    or not proof.certified_lower <= value <= proof.certified_upper):
                raise D04ReadoutHold("joint output representative differs from original")
        write_rows.extend(((checkpoint_key.token, checkpoint_atom.revision,
                            encode_numeric_checkpoint(member.next_checkpoint)),
                           (state_key.token, state_atom.revision, asdict(member.next_state))))
        float_bits.extend(struct.pack("!d", value).hex()
                          for value in member.next_checkpoint.latent_state)
        float_bits.extend(struct.pack("!d", bound).hex()
                          for box in member.next_checkpoint.certified_box for bound in box)
        float_bits.append(struct.pack("!d", member.next_checkpoint.numeric_error_bound).hex())
        float_bits.append(struct.pack("!d", member.native_trajectory_error_2norm).hex())
        for proof in member.axes:
            float_bits.extend(struct.pack("!d", value).hex() for value in (
                proof.certified_lower, proof.certified_upper,
                proof.representative, proof.representative_error,
            ))
    if (canonical_digest(tuple(sorted(write_rows, key=lambda row: row[0])))
            != original.write_set_digest
            or canonical_digest(tuple(float_bits)) != original.binary64_bits_digest):
        raise D04ReadoutHold("joint output write set or float bits differ")


def _complete_state_sources(checkpoint: NumericCheckpoint, checkpoint_key: AtomKey,
                            checkpoint_revision: int, source_ref: str,
                            read: D04SourceHeadRead) -> tuple[str, ...]:
    """Check supplied graph values and every historical source/correction head.

    Completeness of the *database query* remains D11's responsibility. These
    checks reject malformed or internally incomplete callback inputs.
    """
    snapshot = read.snapshot
    checkpoint_atom = snapshot.get(checkpoint_key)
    state_key = AtomKey.from_token(checkpoint.graph_state.ref)
    state_atom = snapshot.get(state_key)
    if (checkpoint_atom is None or not checkpoint_atom.valid
            or checkpoint_atom.revision != checkpoint_revision
            or state_atom is None or not state_atom.valid
            or state_atom.revision != checkpoint.graph_state.revision):
        raise D04ReadoutHold("checkpoint or feeling graph state is absent or stale")
    try:
        committed = decode_numeric_checkpoint(checkpoint_atom.value)
        feeling = _decode_feeling(state_atom.value)
    except (TypeError, ValueError) as exc:
        raise D04ReadoutHold("checkpoint or feeling graph value is invalid") from exc
    if (committed != checkpoint or feeling.revision != state_atom.revision
            or feeling.process_id != checkpoint.block.block_id
            or feeling.target_ref != checkpoint.block.object_ref
            or checkpoint.block.meaning_ref not in feeling.meaning_refs
            or feeling.cursor != checkpoint.cursor
            or feeling.basis_version != checkpoint.assets.scheme_version
            or feeling.operator_version != checkpoint.assets.operator_version
            or feeling.parameter_version != checkpoint.assets.parameter_version
            or feeling.coupling_version != checkpoint.assets.coupling_version):
        raise D04ReadoutHold("checkpoint and current feeling state differ")
    if (tuple(axis for axis, _ in feeling.coordinates) != checkpoint.axes
            or any(struct.pack("!d", value) != struct.pack("!d", expected)
                   for (_, value), expected in zip(
                       feeling.coordinates, checkpoint.latent_state))):
        raise D04ReadoutHold("checkpoint and feeling 24D coordinates differ")
    refs = feeling.historical_source_refs
    authored = source_key(*checkpoint.namespace, checkpoint.block.authored_source_id).token
    if (not refs or len(refs) > 256 or source_ref not in refs or authored not in refs):
        raise D04ReadoutHold("feeling historical source closure is incomplete")
    atoms = {atom.key: atom for atom in snapshot.atoms}
    pending = list(refs)
    visited: set[str] = set()
    while pending:
        ref = pending.pop()
        if ref in visited:
            continue
        visited.add(ref)
        if len(visited) > 256:
            raise D04ReadoutHold("feeling source ancestry exceeds bound")
        try:
            key = AtomKey.from_token(ref)
            source = atoms[key]
            record = SourceRecord.from_dict(source.value)
            head = atoms[source_correction_head_key(read.namespace, key.owner.subject)]
        except (KeyError, TypeError, ValueError) as exc:
            raise D04ReadoutHold("feeling source or correction head is incomplete") from exc
        if (key != source_key(*checkpoint.namespace, key.owner.subject or "")
                or not source.valid or source.revision < 1
                or head.revision != 0 or head.valid):
            raise D04ReadoutHold("feeling source is corrected or unavailable")
        pending.extend(source_key(*checkpoint.namespace, parent).token
                       for parent in record.parent_source_ids)
    return refs


def project_conditional_affect_behaviour(
    *, checkpoint: NumericCheckpoint, checkpoint_ref: str,
    checkpoint_revision: int, source_ref: str, scheme: AffectScheme,
    source_read: D04SourceHeadRead,
    asset: D04LoadedTanhReadoutAsset,
    math_readout: D04ConditionalTanhReadoutMath,
) -> AffectiveReadoutCandidate:
    """Check numerical/semantic alignment and keep every opposing tendency.

    The caller must later obtain D11's current graph, Authority, source-closure,
    asset-installation and adoption proof. This function never issues it.
    """
    if (type(checkpoint) is not NumericCheckpoint or type(scheme) is not AffectScheme
            or type(source_read) is not D04SourceHeadRead
            or type(asset) is not D04LoadedTanhReadoutAsset
            or type(math_readout) is not D04ConditionalTanhReadoutMath):
        raise TypeError("D04 behaviour projection needs typed checkpoint, scheme and readout")
    if (type(checkpoint_ref) is not str or not checkpoint_ref
            or type(source_ref) is not str or not source_ref
            or type(checkpoint_revision) is not int or checkpoint_revision < 1):
        raise D04ReadoutHold("checkpoint and source graph identities are required")
    try:
        checkpoint_key = AtomKey.from_token(checkpoint_ref)
        source_atom_key = AtomKey.from_token(source_ref)
    except (TypeError, ValueError) as exc:
        raise D04ReadoutHold("checkpoint or source graph ref is invalid") from exc
    if (checkpoint_key.type_name != "d04.numeric_checkpoint.v1"
            or checkpoint_key.owner.kind != "persona"
            or checkpoint_key.name != checkpoint.block.block_id
            or (checkpoint_key.owner.bot, checkpoint_key.owner.persona) != checkpoint.namespace
            or source_atom_key != source_key(*checkpoint.namespace,
                                              source_atom_key.owner.subject or "")):
        raise D04ReadoutHold("checkpoint or source graph ref crosses the block namespace")
    if checkpoint.block.kind != "feeling":
        raise D04ReadoutHold("a role mood cannot be attributed to an object")
    if source_read.namespace != NamespaceId(*checkpoint.namespace):
        raise D04ReadoutHold("source read namespace differs from checkpoint")
    identity = D04BlockIdentity(
        checkpoint.graph_state.ref, checkpoint.block.object_ref,
        checkpoint.block.meaning_ref, source_ref,
    )
    source_heads = derive_d04_source_heads(
        (D04BlockInstance(identity, "", "", "", None, ()),), source_read,
    )
    head = source_heads.heads.get(identity)
    if head is None or not head.usable:
        raise D04ReadoutHold("current source closure is unavailable: "
                             + source_heads.held.get(identity, "unknown"))
    all_sources = _complete_state_sources(
        checkpoint, checkpoint_key, checkpoint_revision, source_ref, source_read,
    )
    closure = derive_d04_source_heads(tuple(D04BlockInstance(
        D04BlockIdentity(checkpoint.graph_state.ref, checkpoint.block.object_ref,
                         checkpoint.block.meaning_ref, ref),
        "", "", "", None, (),
    ) for ref in all_sources), source_read)
    if closure.held or len(closure.heads) != len(all_sources):
        raise D04ReadoutHold("feeling historical source access is incomplete")
    if (checkpoint.axes != REGISTERED_AXIS_IDS
            or tuple(axis.axis_id for axis in scheme.axes) != REGISTERED_AXIS_IDS
            or scheme.scheme_version != SCHEME_VERSION
            or checkpoint.assets.scheme_version != scheme.scheme_version
            or checkpoint.assets.operator_version != scheme.operator_version
            or checkpoint.assets.parameter_version != scheme.parameter_version
            or checkpoint.assets.coupling_version != scheme.coupling_version
            or checkpoint.assets.readout_version != asset.readout_version
            or checkpoint.assets.readout_sha256 != asset.asset_sha256
            or asset.scheme_version != scheme.scheme_version
            or asset.axis_ids != checkpoint.axes):
        raise D04ReadoutHold("active Scheme, checkpoint and readout asset differ")
    if not asset.readout_id or len(asset.rows) != len(REGISTERED_AXIS_IDS):
        raise D04ReadoutHold("installed readout identity or rows are incomplete")
    if any(row.axis_id != axis or row.output_version != asset.readout_version
           for row, axis in zip(asset.rows, REGISTERED_AXIS_IDS)):
        raise D04ReadoutHold("readout rows differ from ordered Scheme axes")
    if (math_readout.asset_sha256 != asset.asset_sha256
            or math_readout.readout_id != asset.readout_id
            or math_readout.state_centers != checkpoint.latent_state):
        raise D04ReadoutHold("conditional math differs from checkpoint or installed readout")
    radius = _inherited_radius(checkpoint)
    if math_readout.state_error_2norm < radius:
        raise D04ReadoutHold("conditional math omits inherited checkpoint error")
    expected = run_d04_conditional_tanh_readout_math(
        asset, checkpoint.latent_state, math_readout.state_error_2norm,
    )
    if expected != math_readout:
        raise D04ReadoutHold("conditional readout intervals failed independent replay")
    tendencies = []
    for axis, row, output in zip(REGISTERED_AXIS_IDS, asset.rows, math_readout.outputs):
        mechanism, layer = axis.split(":", 1)
        if (output.axis_id != axis or output.output_id != row.output_id
                or not math.isfinite(output.lower) or not math.isfinite(output.upper)
                or output.lower > output.upper):
            raise D04ReadoutHold("readout output does not match registered behaviour axis")
        tendencies.append(AffectiveTendencyCandidate(
            checkpoint.block.object_ref, checkpoint.block.meaning_ref, source_ref,
            _TENDENCIES[mechanism], layer, axis, output.output_id,
            output.lower, output.upper,
        ))
    digest = canonical_digest({
        "policy": _POLICY_VERSION, "checkpoint": (checkpoint_ref, checkpoint_revision),
        "state": (checkpoint.graph_state.ref, checkpoint.graph_state.revision),
        "checkpoint_certificate": checkpoint.certificate_digest,
        "source": (source_ref, tuple(sorted(
            (item.source_ref, value.graph_source_version, value.access_version)
            for item, value in closure.heads.items()))),
        "audience": source_read.audience, "purpose": source_read.purpose,
        "graph_epoch": source_read.snapshot.epochs[0].revision,
        "readout_asset": asset.asset_sha256,
        "readout_proof": checkpoint.readout_proof_digest,
        "math": tuple((row.output_id, row.lower, row.upper)
                      for row in math_readout.outputs),
    })
    return AffectiveReadoutCandidate(
        checkpoint_ref, checkpoint_revision, checkpoint.graph_state.ref,
        checkpoint.graph_state.revision, checkpoint.cursor, source_ref,
        head.graph_source_version, head.access_version,
        source_read.audience, source_read.purpose,
        asset.asset_sha256, digest, tuple(tendencies),
    )


__all__ = ["AffectiveReadoutCandidate", "AffectiveTendencyCandidate",
           "D04FamilyIntervalEffectV2", "D04MixedReadoutCandidateV2",
           "D04MixedTendencyV2", "D04ReadoutHold",
           "project_conditional_affect_behaviour", "project_mixed_affect_candidate_v2"]
