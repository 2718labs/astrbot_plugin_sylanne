"""Structured memory grouping for a genuinely adopted internal experience.

This lane records source-backed event/episode identity. An unobserved feeling,
subjective trace or salience estimate remains absent and explicitly pending.
The concrete W01 composite witness remains the only adoption authority.
"""
from dataclasses import dataclass

from ...graph_types import AtomKey, GraphWrite, Owner
from ...memory_types import SourceRecord, access_key, episode_key, validate_episode
from ...runtime_contracts import DependencySet, DomainProposal, canonical_digest
from ...runtime.domain_production_contracts_v1 import CurrentOperationFrameV1, StagedDomainOperationV1, ProductionOriginalRefV1
from ..d01.production_operations_v1 import current_frame_guard_v1, plain_v1, stage_result_v1
from ..d03.context import ContextProvider, WorldEvent
from . import D06DomainProvider


@dataclass(frozen=True, slots=True)
class EncodeCurrentStructuredExperienceRequestV1:
    causal_operation_id: str
    source_ref: str

    def __post_init__(self):
        if type(self.causal_operation_id) is not str or not 1 <= len(self.causal_operation_id) <= 2048:
            raise ValueError("structured experience needs an actual causal operation")
        if AtomKey.from_token(self.source_ref).type_name != "memory.source":
            raise ValueError("structured experience needs an actual D06 source")


def structured_experience_output_keys_v1(namespace, source_ref):
    source = AtomKey.from_token(source_ref)
    if (source.owner.bot, source.owner.persona) != namespace.as_tuple or source.type_name != "memory.source":
        raise ValueError("structured experience source crossed namespace")
    suffix = canonical_digest((namespace, source_ref))[:48]
    event_id, episode_id = "world:d10-experience:" + suffix, "episode:d10-experience:" + suffix
    return (AtomKey(Owner("event", *namespace.as_tuple, event_id), "d03.world_event", "current"),
        episode_key(*namespace.as_tuple, episode_id))


@dataclass(frozen=True, slots=True)
class StructuredExperienceInputsV1:
    source: SourceRecord
    world_event: WorldEvent
    causal_original: ProductionOriginalRefV1
    self_identity_original: ProductionOriginalRefV1
    self_mapping_ref: str
    perspective_ref: str
    duplicate: bool


@dataclass(frozen=True, slots=True)
class StructuredExperienceBundleV1:
    envelope: object
    memory_stage: StagedDomainOperationV1
    context_proposal: DomainProposal
    episode_refs: tuple[str, ...]
    member_domains: tuple[str, ...] = ("d03", "d06")
    bundle_kind: str = "d06.structured_internal_experience.v1"

    def __post_init__(self):
        if (self.bundle_kind != "d06.structured_internal_experience.v1" or self.member_domains != ("d03", "d06")
                or self.memory_stage.domain != "d06" or self.memory_stage.operation_kind != "encode_structured_experience"
                or self.context_proposal.domain != "d03" or not self.episode_refs
                or self.context_proposal.envelope != self.envelope
                or any(proposal.envelope != self.envelope for proposal in self.memory_stage.proposals)):
            raise ValueError("structured experience requires its exact two separately issued domain members")


def validate_structured_experience_proposal_v1(proposal, snapshot):
    """Pure shape check; W01 independently verifies actual causal originals."""
    if (proposal.domain != "d06" or proposal.envelope.identity.phase != "encode_structured_experience"
            or len(proposal.typed_writes) != 1 or proposal.typed_writes[0].key.type_name != "memory.episode.v1"):
        raise ValueError("structured experience proposal has another phase or writer")
    write = proposal.typed_writes[0]
    validate_episode(write.value)
    refs = write.value["source_refs"]
    if len(refs) != 1 or tuple(refs) != proposal.envelope.source_qualification.source_refs:
        raise ValueError("structured episode must bind its one genuinely qualified experience root")
    source = AtomKey.from_token(refs[0])
    ns = proposal.envelope.authority.namespace
    event, episode = structured_experience_output_keys_v1(ns, source.token)
    if write.key != episode or write.value["event_ref"] != event.token:
        raise ValueError("structured episode identity differs from the exact source")
    reads = {version.key: version.revision for version in proposal.envelope.version_guard.read_versions}
    required = {source, access_key(*ns.as_tuple, source.owner.subject), event, episode}
    if (not required <= set(reads) or reads[event] != 0 or reads[episode] != 0
            or reads[source] < 1 or reads[access_key(*ns.as_tuple, source.owner.subject)] < 1
            or set(write.dependencies) != required - {episode}):
        raise ValueError("structured episode lacks complete real source/access and output absence reads")
    atom = snapshot.get(source) if snapshot is not None else None
    if atom is None or not atom.valid or atom.revision != reads[source]:
        raise ValueError("structured episode source is not in its actual current snapshot")
    record = SourceRecord.from_dict(atom.value)
    if record.source_kind not in {"internal", "simulated"} or not record.source_id.startswith(
            ("d10-life-experience:", "d10-offline-experience:")):
        raise ValueError("structured lane accepts only actual D10 internal/simulated experience kinds")
    return proposal


def compile_current_structured_experience_v1(frame, request, inputs):
    if (type(frame) is not CurrentOperationFrameV1 or type(request) is not EncodeCurrentStructuredExperienceRequestV1
            or type(inputs) is not StructuredExperienceInputsV1):
        raise TypeError("structured memory needs exact current frame/request/inputs")
    current_frame_guard_v1(frame)
    ns = frame.envelope.authority.namespace
    event_key, memory_key = structured_experience_output_keys_v1(ns, request.source_ref)
    episode = {"episode_id": memory_key.owner.subject, "source_refs": [request.source_ref], "event_ref": event_key.token}
    event_write = GraphWrite(event_key, plain_v1(inputs.world_event),
        (AtomKey.from_token(request.source_ref), AtomKey.from_token(inputs.self_mapping_ref), AtomKey.from_token(inputs.perspective_ref)))
    episode_write = GraphWrite(memory_key, episode,
        (AtomKey.from_token(request.source_ref), access_key(*ns.as_tuple, inputs.source.source_id), event_key))
    provider = D06DomainProvider()
    stage = stage_result_v1(frame, "d06", "encode_structured_experience", request,
        writes=() if inputs.duplicate else (episode_write,),
        provenance={"source": inputs.source, "world_event": inputs.world_event,
            "causal_original": inputs.causal_original, "self_identity_original": inputs.self_identity_original,
            "self_mapping_ref": inputs.self_mapping_ref, "perspective_ref": inputs.perspective_ref,
            "episode_ref": memory_key.token, "encoding_status": "encoding_pending", "duplicate": inputs.duplicate},
        coverage="partial", missing=("actual_d04_then_feeling_and_d06_subjective_trace_encoding",),
        continuation="structured-encoding:" + canonical_digest((ns, request.source_ref))[:48],
        proposal_schema="d06.contract.v1", proposal_hash=provider.descriptor.request_schema_hash)
    context = ContextProvider()
    writes = () if inputs.duplicate else (event_write,)
    dependencies = {key for write in writes for key in write.dependencies}
    proposal = DomainProposal("d03", "d03.proposal.v1", context.descriptor.request_schema_hash, frame.envelope, writes,
        DependencySet(current_invalidation=tuple(version for version in frame.snapshot.versions if version.key in dependencies)), (), ())
    context.validate(proposal, frame.snapshot)
    for memory in stage.proposals:
        provider.validate(memory, frame.snapshot)
    if inputs.duplicate:
        return stage
    return StructuredExperienceBundleV1(frame.envelope, stage, proposal, (memory_key.token,))


def verify_d06_structured_experience_stage_v1(stage):
    primary = stage.memory_stage if type(stage) is StructuredExperienceBundleV1 else stage
    if (type(primary) is not StagedDomainOperationV1 or primary.domain != "d06"
            or primary.operation_kind != "encode_structured_experience"
            or any(write.key.type_name != "memory.episode.v1" for proposal in primary.proposals for write in proposal.typed_writes)):
        raise ValueError("unregistered structured memory stage")
    return stage
