"""Read-only D06 preparation over the shared persistent-memory graph.

This module deliberately stops at candidates.  Source ingestion and every
write still go through the shared coordinator; a successful query or encoding
preparation is never an assertion that a memory episode or recollection took
place.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import math
from typing import Mapping

from ...graph_types import GraphVersion, NamespaceEpoch, Owner
from ...memory_repository import MemoryRepository
from ...memory_retrieval import MemoryBatch, MemoryQuery, MemoryRetriever
from ...memory_retrieval import MemoryHit
from ...memory_recollection_view import prepare_affective_recollection_view
from ...memory_reconstruction import DetailCue, RecollectionReconstruction, reconstruct_recollection_candidate
from ...memory_types import source_key
from ...model_broker.broker import CallReceipt
from ...model_broker.first_ingress_encoding import parse_first_ingress_encoding_result
from ...model_broker.first_ingress_encoding import build_first_ingress_encoding_payload
from ...authority_service.v2_model_result_read_contract import ModelResultReadV1
from ...authority_service.v2_model_result_read_contract import ModelResultReadRequestV1
from ...authority_service.v2_worker_model_result_contract import WorkerModelResultReadV1
from ...memory_types import SourceRecord
from ...runtime.encoding_call_binding import EncodingCallBinding, binding_to_json
from ..d04.encoding_baseline import EncodingBaseline
from ...runtime_contracts import canonical_digest
from ...memory_types import access_key
from ...memory_types import episode_key, subjective_trace_key, subjective_trace_v2_key
from ...memory_types import validate_episode, validate_subjective_trace, validate_subjective_trace_v2
from ...runtime_contracts import CommandEnvelope, DependencySet, DomainBundle, DomainProposal, NamespaceId, SourceQualification
from ...graph_types import AtomKey, GraphSnapshot
from ..d04 import AffectCoupling, AffectProvider, AffectScheme, MoodField
from . import (
    CandidateSet,
    D06DomainAdapter,
    EncodingContext,
    EncodingProposal,
    RecallQualification,
    RetrievalChannel,
    RecollectionContext,
    SelectionTicket,
)


def _epoch(value: object, label: str) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _unique_versions(batches: tuple[MemoryBatch, ...]) -> tuple[GraphVersion, ...]:
    versions: list[GraphVersion] = []
    seen = set()
    for batch in batches:
        for hit in batch.hits:
            for version in hit.proof_versions:
                if version.key not in seen:
                    seen.add(version.key)
                    versions.append(version)
    return tuple(versions)


@dataclass(frozen=True)
class SearchPlan:
    """One bounded, structural retrieval channel.

    ``query`` remains an exact predicate.  This type intentionally has no
    semantic-model field: vector/model retrieval needs a separately admitted
    provider and must not be silently treated as source evidence.
    """

    name: str
    query: MemoryQuery
    activation: float

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name.strip():
            raise ValueError("name must be a nonempty string")
        if not isinstance(self.query, MemoryQuery):
            raise TypeError("query must be MemoryQuery")
        if (type(self.activation) not in (int, float)
                or isinstance(self.activation, bool)
                or not math.isfinite(self.activation)):
            raise ValueError("activation must be a finite number from 0 to 1")
        if not 0.0 <= float(self.activation) <= 1.0:
            raise ValueError("activation must be a finite number from 0 to 1")


@dataclass(frozen=True)
class PreparedEncoding:
    """A source-verified C02 candidate, with the exact proof it read."""

    source_ref: str
    proposal: EncodingProposal
    proof_versions: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch
    status: str = "candidate"


@dataclass(frozen=True)
class PreparedFirstIngressEncoding:
    """Untrusted result plus a receipt claim; C02 admission remains on HOLD."""

    prepared: PreparedEncoding
    encoding_baseline_ref: str
    receipt_claim: CallReceipt
    result_digest: str
    possible_meanings: tuple[str, ...]
    possible_feelings: tuple[str, ...]
    status: str = "candidate_hold"
    authority_observation_digest: str | None = None
    authority_operation_id: str | None = None
    consumer_operation_id: str | None = None


@dataclass(frozen=True)
class HeldFirstIngressC02:
    """Compiled D06 material awaiting fresh D11 Authority and fence admission."""

    proposal: DomainProposal
    source_ref: str
    encoding_baseline_ref: str
    call_id: str
    request_digest: str
    observation_digest: str
    result_digest: str
    authority_operation_id: str
    possible_meanings: tuple[str, ...]
    possible_feelings: tuple[str, ...]
    status: str = "candidate_hold"


def validate_first_encoding_authority_result(
    read: ModelResultReadV1 | WorkerModelResultReadV1,
    frozen_request: Mapping[str, object],
    original_source: SourceRecord, *, source_revision: int, access_revision: int,
    binding: EncodingCallBinding | None = None,
) -> Mapping[str, object]:
    """Bind original Authority result bytes to the frozen first-ingress input.

    This checks content and identity, but a constructible DTO is not an
    authorization token. The caller must obtain ``read`` from the Authority
    service and the final adopter must repeat its source/job/fence checks.
    """
    if type(read) not in {ModelResultReadV1, WorkerModelResultReadV1} or type(original_source) is not SourceRecord:
        raise TypeError("typed Authority read and original source are required")
    if type(frozen_request) is not dict:
        raise TypeError("frozen encoding request must be an object")
    if (type(source_revision) is not int or source_revision < 1
            or type(access_revision) is not int or access_revision < 1):
        raise ValueError("committed source and access revisions are required")
    payload, template_digest = build_first_ingress_encoding_payload(original_source)
    if (frozen_request.get("source_id") != original_source.source_id
            or frozen_request.get("payload") != payload
            or frozen_request.get("prompt_template_digest") != template_digest):
        raise ValueError("frozen request differs from original source")
    schema = frozen_request.get("schema")
    if (schema not in {"sylanne.first-ingress-encoding-call.v2",
                       "sylanne.first-ingress-encoding-call.v3"}
            or frozen_request.get("work_kind") != "d06.encode_source"
            or type(frozen_request.get("worker_fence")) is not int
            or frozen_request["worker_fence"] < 1):
        raise ValueError("production encoding request and worker fence required")
    if (frozen_request.get("source_revision") != source_revision
            or frozen_request.get("access_revision") != access_revision):
        raise ValueError("current source and access revisions differ")
    if schema == "sylanne.first-ingress-encoding-call.v3":
        # V3 pins a committed D04 baseline into the original request. Validate
        # that the complete identity, namespace, graph reference, and all
        # source/access/baseline versions match the frozen guard. The live
        # coordinator still proves that identity against committed graph state.
        try:
            from ...runtime.encoding_call_binding import CommittedEncodingBaselineV1
            from ...graph_types import AtomKey
            from ...runtime_contracts import NamespaceId

            namespace = NamespaceId(*frozen_request["namespace"])
            baseline = CommittedEncodingBaselineV1(**frozen_request["baseline"])
            baseline_key = AtomKey.from_token(baseline.baseline_ref)
            if baseline_key.type_name != "d04.encoding_baseline.v1":
                raise ValueError("baseline type differs")
            guard = frozen_request["envelope"]["version_guard"]
            versions = guard["read_versions"]
            expected = {
                source_key(*namespace.as_tuple, original_source.source_id).token:
                    source_revision,
                access_key(*namespace.as_tuple, original_source.source_id).token:
                    access_revision,
                baseline_key.token: baseline.baseline_revision,
            }
            seen: dict[str, int] = {}
            for item in versions:
                key_data = item["key"]
                key = AtomKey.from_token(key_data["token"])
                if (key.token in seen or NamespaceId.from_key(key) != namespace
                        or type(item["revision"]) is not int or item["revision"] < 1):
                    raise ValueError("version guard contains duplicate or foreign references")
                seen[key.token] = item["revision"]
            if any(seen.get(ref) != revision for ref, revision in expected.items()):
                raise ValueError("committed baseline or source proof differs")
            if len(frozen_request["baseline"]) != len(CommittedEncodingBaselineV1.__dataclass_fields__):
                raise ValueError("baseline proof fields differ")
            digest = canonical_digest({
                "envelope": frozen_request["envelope"],
                "call_id": frozen_request["call_id"],
                "provider_id": frozen_request["provider_id"],
                "model_id": frozen_request["model_id"],
                "purpose": frozen_request["envelope"]["authority"]["purpose"],
                "required_capabilities": frozen_request["required_capabilities"],
                "privacy_tier": frozen_request["privacy_tier"],
                "template": frozen_request["prompt_template_digest"],
                "payload": frozen_request["payload"],
                "timeout_seconds": frozen_request["timeout_seconds"],
                "max_output_tokens": frozen_request["max_output_tokens"],
            })
            if digest != frozen_request.get("model_request_digest"):
                raise ValueError("model request digest differs")
            if (type(binding) is not EncodingCallBinding
                    or dict(binding.request) != dict(frozen_request)
                    or binding.namespace != namespace
                    or binding.source_id != original_source.source_id
                    or binding.source_revision != source_revision
                    or binding.access_revision != access_revision
                    or binding.call_id != frozen_request["call_id"]
                    or binding.model_request_digest != digest
                    or canonical_digest(dict(frozen_request)) != binding.binding_digest):
                raise ValueError("V3 frozen binding object is required")
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("V3 committed baseline proof or binding differs") from exc
    elif "baseline" in frozen_request:
        raise ValueError("legacy V2 request cannot claim a D04 baseline")
    observation = read.observation
    call_id = read.call_id if type(read) is ModelResultReadV1 else read.request.call_id
    if call_id != frozen_request.get("call_id"):
        raise ValueError("original call identity differs")
    if observation.request_digest != frozen_request.get("model_request_digest"):
        raise ValueError("original request digest differs")
    result = observation.result
    if type(result) is not dict:
        raise ValueError("completed original result is unavailable")
    parse_first_ingress_encoding_result(result, original_source)
    return result


@dataclass(frozen=True)
class RetrievalOutcome:
    """Candidate material plus the frozen proof set; never a recall receipt."""

    status: str
    candidates: CandidateSet | None
    proof_versions: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch | None
    batches: tuple[MemoryBatch, ...]


@dataclass(frozen=True)
class PreparedAssociation:
    source_ref: str
    target_ref: str
    basis_source_refs: tuple[str, ...]
    proof_versions: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch
    status: str = "candidate"


@dataclass(frozen=True)
class CommittedEncodingEvidence:
    """C02 references; historical revisions are baseline identity, not current CAS."""

    source_ref: str
    episode_ref: str
    trace_ref: str
    encoding_baseline_ref: str | None
    then_feeling_refs: tuple[str, ...]
    then_feeling_versions: tuple[GraphVersion, ...]
    detail_weights: tuple[tuple[str, float], ...]
    proof_versions: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch


class D06MemoryPipeline:
    """Connect committed source evidence to D06-only encoding/query candidates."""

    def __init__(self, adapter: D06DomainAdapter, repository: MemoryRepository):
        if not isinstance(adapter, D06DomainAdapter):
            raise TypeError("adapter must be D06DomainAdapter")
        if not isinstance(repository, MemoryRepository):
            raise TypeError("repository must be MemoryRepository")
        if (repository.bot, repository.persona) != adapter.namespace.as_tuple:
            raise ValueError("repository namespace differs from D06 adapter")
        self.adapter = adapter
        self.repository = repository
        self.retriever = MemoryRetriever(repository)

    def read_committed_encoding(
        self, source_ref: str, trace_id: str, *, audience: str, purpose: str,
        trace_version: int = 1,
    ) -> CommittedEncodingEvidence:
        """Read one persisted trace tied to a source still accessible now."""
        if trace_version not in (1, 2):
            raise ValueError("trace_version must be 1 or 2")
        namespace = self.adapter.namespace.as_tuple
        source, source_proof = self.repository.read_source_evidence(
            source_ref, audience=audience, purpose=purpose,
        )
        if source is None:
            raise PermissionError("encoding source is unavailable")
        trace_key = (subjective_trace_key if trace_version == 1 else subjective_trace_v2_key)(
            *namespace, trace_id,
        )
        trace_snapshot = self.repository.store.graph_snapshot((trace_key,))
        trace = trace_snapshot.get(trace_key)
        if trace is None or not trace.valid:
            raise ValueError("committed subjective trace is unavailable")
        (validate_subjective_trace if trace_version == 1 else validate_subjective_trace_v2)(
            trace.value,
        )
        if trace.value["trace_id"] != trace_id:
            raise ValueError("subjective trace identity differs from key")
        episode_ref = AtomKey.from_token(trace.value["episode_ref"])
        if (episode_ref.owner.bot, episode_ref.owner.persona) != namespace:
            raise ValueError("subjective trace crosses namespace")
        episode_snapshot = self.repository.store.graph_snapshot((episode_ref,))
        episode = episode_snapshot.get(episode_ref)
        if episode is None or not episode.valid:
            raise ValueError("committed memory episode is unavailable")
        validate_episode(episode.value)
        if episode_ref != episode_key(*namespace, episode.value["episode_id"]):
            raise ValueError("memory episode identity differs from key")
        if source_key(*namespace, source_ref).token not in episode.value["source_refs"]:
            raise ValueError("memory episode does not contain this source")
        baseline_snapshot = None
        baseline_key = None
        then_feeling_versions: tuple[GraphVersion, ...] = ()
        source_proofs = [source_proof]
        if trace_version == 2:
            baseline_key = AtomKey.from_token(trace.value["encoding_baseline_ref"])
            spec = self.repository.store._registry.spec(baseline_key.type_name)
            if spec.writer_domain != "d04" or not spec.immutable:
                raise ValueError("encoding baseline requires the registered immutable D04 type")
            baseline_snapshot = self.repository.store.graph_snapshot((baseline_key,))
            baseline = baseline_snapshot.get(baseline_key)
            if baseline is None or not baseline.valid or baseline.revision == 0:
                raise ValueError("committed D04 encoding baseline is unavailable")
            decoded = spec.validator(baseline.value)
            if source_key(*namespace, source_ref).token not in decoded.source_refs:
                raise ValueError("encoding baseline does not qualify this source")
            then_feeling_versions = tuple(
                GraphVersion(AtomKey.from_token(item.ref), item.revision)
                for item in decoded.then_feeling_versions
            )
            if tuple(version.key.token for version in then_feeling_versions) != tuple(
                trace.value["then_feeling_refs"]
            ):
                raise ValueError("encoding trace differs from D04 then-feeling versions")
            for baseline_source in decoded.source_refs:
                linked = AtomKey.from_token(baseline_source)
                record, proof = self.repository.read_source_evidence(
                    linked.owner.subject, audience=audience, purpose=purpose,
                )
                if record is None or proof.epochs != source_proof.epochs:
                    raise PermissionError("encoding baseline source is unavailable")
                source_proofs.append(proof)
        current = self.repository.store.graph_snapshot(tuple(dict.fromkeys(
            (*[version.key for proof in source_proofs for version in proof.versions],
             trace_key, episode_ref,
             *((baseline_key,) if baseline_key is not None else ()))
        )))
        if (current.epochs != source_proof.epochs or
                current.get(trace_key) != trace or current.get(episode_ref) != episode or
                (baseline_key is not None and
                 current.get(baseline_key) != baseline_snapshot.get(baseline_key)) or
                any(current.get(version.key) is None or
                    current.get(version.key).revision != version.revision or
                    not current.get(version.key).valid
                    for proof in source_proofs for version in proof.versions)):
            raise RuntimeError("encoding source, access, or trace changed during read")
        return CommittedEncodingEvidence(
            source_ref, episode_ref.token, trace_key.token,
            trace.value.get("encoding_baseline_ref"),
            tuple(trace.value["then_feeling_refs"]),
            then_feeling_versions,
            tuple((detail, weight) for detail, weight in trace.value["detail_weights"]),
            tuple(dict.fromkeys((*(version for proof in source_proofs for version in proof.versions),
                                  *episode_snapshot.versions,
                                  *trace_snapshot.versions,
                                  *(baseline_snapshot.versions if baseline_snapshot is not None else ())))),
            source_proof.epochs[0],
        )

    def prepare_affective_recollection(
        self,
        outcome: RetrievalOutcome,
        ticket: SelectionTicket,
        context: RecollectionContext,
        *,
        audience: str,
        purpose: str,
        mood_snapshot: GraphSnapshot,
        mood_key: AtomKey,
        scheme: AffectScheme,
        coupling: AffectCoupling,
        source_qualification: SourceQualification,
        base_salience: tuple[float, float],
        base_tone: tuple[float, float],
        detail_cues: tuple[DetailCue, ...],
        then_meaning_refs: tuple[str, ...] = (),
        temporal_focus: bool = False,
        encoding_trace_id: str | None = None,
        encoding_trace_version: int = 2,
    ) -> RecollectionReconstruction:
        """Prepare one selected source as a mood-shaped C04 candidate.

        The source and access are read again after retrieval. A final graph
        snapshot checks the mood and every read version before returning.
        Actual recollection and experience submission belong to C04/D11.
        A versioned C02 trace can identify the then-feeling references, but
        caller-supplied base intervals remain unqualified projection inputs.
        This method never turns them into a D04-certified encoding baseline.
        The immutable baseline identifies historical feeling revisions; this
        candidate does not claim the corresponding history rows remain available.
        """
        if outcome.status != "candidate" or outcome.candidates is None or outcome.epoch is None:
            raise ValueError("a qualified D06 retrieval outcome is required")
        if len(ticket.selected_candidate_ids) != 1:
            raise ValueError("one D07 selected candidate is required")
        if (mood_snapshot.epochs != (outcome.epoch,) or
                (outcome.epoch.bot, outcome.epoch.persona) != self.adapter.namespace.as_tuple):
            raise RuntimeError("D06 retrieval and D04 mood epochs differ")
        selected = next((item for item in outcome.candidates.items
                         if item.candidate_id == ticket.selected_candidate_ids[0]), None)
        if selected is None:
            raise ValueError("D07 ticket does not select a D06 candidate")
        if encoding_trace_id is not None and encoding_trace_version != 2:
            raise ValueError("then-feeling comparison requires a versioned D04 baseline")
        encoding = (self.read_committed_encoding(
            selected.content_ref, encoding_trace_id,
            audience=audience, purpose=purpose,
            trace_version=encoding_trace_version,
        ) if encoding_trace_id is not None else None)
        if encoding is not None and encoding.epoch != outcome.epoch:
            raise RuntimeError("committed encoding and D06 retrieval epochs differ")
        hit = next((hit for batch in outcome.batches for hit in batch.hits
                    if isinstance(hit, MemoryHit) and hit.key == source_key(
                        *self.adapter.namespace.as_tuple, selected.content_ref)), None)
        if hit is None:
            raise ValueError("selected source has no retrieval proof")
        current_source, source_proof = self.repository.read_source_evidence(
            selected.content_ref, audience=audience, purpose=purpose,
        )
        if current_source is None:
            raise PermissionError("selected source is no longer accessible")
        if source_proof.epochs != (outcome.epoch,) or current_source != hit.record:
            raise RuntimeError("selected source changed after retrieval")
        proof_by_key = {version.key: version for version in source_proof.versions}
        if any(proof_by_key.get(version.key) != version for version in hit.proof_versions):
            raise RuntimeError("selected source or access proof changed after retrieval")

        view = prepare_affective_recollection_view(
            ticket=ticket, candidates=outcome.candidates, hit=hit,
            mood_snapshot=mood_snapshot, mood_key=mood_key,
            scheme=scheme, coupling=coupling,
            source_qualification=source_qualification,
            base_salience=base_salience, base_tone=base_tone, purpose=purpose,
        )
        proposal = self.adapter.prepare_recollection(ticket, outcome.candidates, context)
        result = reconstruct_recollection_candidate(
            proposal=proposal, view=view, detail_cues=detail_cues,
            then_meaning_refs=then_meaning_refs, temporal_focus=temporal_focus,
        )
        if encoding is not None:
            feeling_keys = tuple(version.key for version in encoding.then_feeling_versions)
            if any(key.type_name != "d04.feeling_state.v1"
                   or key.owner.kind != "persona"
                   or (key.owner.bot, key.owner.persona) != self.adapter.namespace.as_tuple
                   for key in feeling_keys):
                raise ValueError("committed encoding has invalid D04 then-feeling refs")
            result = replace(
                result, encoding_trace_ref=encoding.trace_ref,
                then_feeling_refs=encoding.then_feeling_refs,
                then_feeling_versions=encoding.then_feeling_versions,
                then_feeling_status="baseline_ref_history_unverified",
                read_versions=tuple(dict.fromkeys((
                    *result.read_versions, *encoding.proof_versions,
                ))),
            )
        current = self.repository.store.graph_snapshot(
            tuple(dict.fromkeys((
                *proof_by_key, mood_key,
                *(version.key for version in result.read_versions),
            )))
        )
        if (current.epochs != (outcome.epoch,) or
                current.get(mood_key) != mood_snapshot.get(mood_key) or any(
            current.get(version.key) is None or
            current.get(version.key).revision != version.revision or
            not current.get(version.key).valid
            for version in (*source_proof.versions, *result.read_versions)
        )):
            raise RuntimeError("recollection source, access, or mood changed during preparation")
        return result

    def assemble_affective_recollection_bundle(
        self,
        envelope: CommandEnvelope,
        outcome: RetrievalOutcome,
        ticket: SelectionTicket,
        reconstruction: RecollectionReconstruction,
        *,
        mood_snapshot: GraphSnapshot,
        mood_key: AtomKey,
        scheme: AffectScheme,
        coupling: AffectCoupling,
        base_salience: tuple[float, float],
        base_tone: tuple[float, float],
        affect_provider: AffectProvider,
        experience_id: str,
        supporting_proposals: tuple[DomainProposal, ...],
        choice_ref: str,
        d02_settlement_ref: str,
        d11_cost_settlement_ref: str,
        persistent_job_ref: str,
        outbox_ref: str,
    ) -> DomainBundle:
        """Join a prepared source/mood candidate to D04 and the five-domain C04 bundle.

        Base intervals remain caller projections, not a certified C02 baseline.
        D11 owns the final locked version check and commit receipt.
        """
        candidates = outcome.candidates
        if (outcome.status != "candidate" or candidates is None or outcome.epoch is None
                or reconstruction.status != "candidate_hold"
                or reconstruction.epoch != outcome.epoch
                or mood_snapshot.epochs != (outcome.epoch,)
                or envelope.identity.activity_id != ticket.activity_id
                or envelope.authority.namespace != self.adapter.namespace):
            raise ValueError("C04 reconstruction, selection, mood, and envelope must share one activity and epoch")
        context = RecollectionContext(
            reconstruction.now_interpretation_refs,
            reconstruction.feeling_experience_refs,
            reconstruction.self_understanding_refs,
        )
        expected = self.adapter.prepare_recollection(ticket, candidates, context)
        if len(expected.content_refs) != 1:
            raise ValueError("C04 affective join requires one selected source")
        selected_source = source_key(*self.adapter.namespace.as_tuple, expected.content_refs[0])
        experience_key = AtomKey(
            Owner("activity", *self.adapter.namespace.as_tuple, ticket.activity_id),
            "d04.recollection_experience.v1", experience_id,
        )
        if (reconstruction.recollection_id != expected.recollection_id
                or reconstruction.source_ref != selected_source.token
                or context.feeling_experience_refs != (experience_key.token,)
                or reconstruction.mood_ref != mood_key.token
                or reconstruction.coupling_version != coupling.version):
            raise ValueError("C04 prepared reconstruction differs from the selected source or experience")
        guarded = set(envelope.version_guard.read_versions)
        if (not reconstruction.read_versions
                or not set(reconstruction.read_versions) <= guarded
                or not any(v.key == selected_source and v.revision > 0
                           for v in reconstruction.read_versions)
                or not any(v.key == mood_key and v.revision > 0
                           for v in reconstruction.read_versions)):
            raise ValueError("C04 envelope lacks the source or mood reconstruction versions")
        mood_atom = mood_snapshot.get(mood_key)
        if (mood_atom is None or not mood_atom.valid
                or GraphVersion(mood_key, mood_atom.revision) not in reconstruction.read_versions):
            raise ValueError("C04 mood snapshot differs from the prepared reconstruction")
        mood_spec = next(spec for spec in affect_provider.type_specs()
                         if spec.name == "d04.mood_field.v1")
        mood = mood_spec.validator(mood_atom.value)
        if (not isinstance(mood, MoodField)
                or (mood.basis_version, mood.parameter_version, mood.coupling_version)
                != (scheme.scheme_version, scheme.parameter_version, scheme.coupling_version)
                or coupling.version != scheme.coupling_version
                or not {selected_source.token, *mood.source_refs}
                <= set(envelope.source_qualification.source_refs)):
            raise ValueError("C04 mood or its source qualification differs from the active scheme")
        influence = affect_provider.condition_recollection(
            memory_ref=selected_source.token,
            memory_source_refs=(selected_source.token,),
            base_salience_interval=base_salience,
            base_tone_interval=base_tone,
            mood=mood,
            coupling=coupling,
        )
        if (influence.salience_interval != reconstruction.subjective_weight
                or influence.tone_interval != reconstruction.subjective_tone
                or influence.evidence_weight_delta != 0.0):
            raise ValueError("C04 D04 experience differs from the mood-shaped reconstruction")
        recollection_ref = AtomKey(
            Owner("activity", *self.adapter.namespace.as_tuple, ticket.activity_id),
            "d06.recollection.v1", reconstruction.recollection_id,
        ).token
        d04 = affect_provider.propose_recollection_experience(
            envelope, experience_id=experience_id, recollection_ref=recollection_ref,
            influence=influence, mood=mood, coupling=coupling,
            source_versions=reconstruction.read_versions,
            dependencies=DependencySet(),
        )
        bundle = self.adapter.assemble_recollection_bundle(
            envelope, ticket, candidates, context,
            supporting_proposals=(*supporting_proposals, d04),
            choice_ref=choice_ref,
            d02_settlement_ref=d02_settlement_ref,
            d11_cost_settlement_ref=d11_cost_settlement_ref,
            persistent_job_ref=persistent_job_ref,
            outbox_ref=outbox_ref,
        )
        d04_proposal = next(item for item in bundle.proposals if item.domain == "d04")
        experience_write = next(
            write for write in d04_proposal.typed_writes
            if write.key.token in context.feeling_experience_refs
        )
        projection_write = self.adapter.recollection_projection_write(
            reconstruction, experience_write,
        )
        d06_proposal = next(item for item in bundle.proposals if item.domain == "d06")
        updated_d06 = replace(
            d06_proposal,
            typed_writes=(*d06_proposal.typed_writes, projection_write),
        )
        return replace(
            bundle,
            proposals=tuple(updated_d06 if item is d06_proposal else item
                            for item in bundle.proposals),
        )

    def read_recollection_projection(
        self, snapshot: GraphSnapshot, projection_ref: str,
    ) -> dict:
        """Expose metadata from a supplied snapshot as HOLD; no authority or literal read is implied."""
        from . import _RECOLLECTION_PROJECTION_TYPE, _validate_recollection_projection

        if not isinstance(snapshot, GraphSnapshot):
            raise TypeError("a coordinator-supplied GraphSnapshot is required")
        key = AtomKey.from_token(projection_ref)
        if (key.type_name != _RECOLLECTION_PROJECTION_TYPE
                or (key.owner.bot, key.owner.persona) != self.adapter.namespace.as_tuple):
            raise ValueError("projection_ref must reference a D06 recollection projection")
        atom = snapshot.get(key)
        if atom is None or not atom.valid:
            raise ValueError("recollection projection is unavailable")
        _validate_recollection_projection(atom.value)
        value = dict(atom.value)
        value["details"] = [dict(detail) for detail in value["details"]]
        value["projection_ref"] = key.token
        value["projection_revision"] = atom.revision
        value["read_status"] = "hold_unverified_access_and_d04_experience"
        return value

    def prepare_association(
        self,
        source_id: str,
        target_id: str,
        basis_source_ids: tuple[str, ...],
        *,
        audience: str,
        purpose: str,
    ) -> PreparedAssociation:
        """Read all edge sources through current access before graph compilation."""
        if type(basis_source_ids) is not tuple or not basis_source_ids:
            raise ValueError("association needs at least one basis source")
        if source_id == target_id:
            raise ValueError("association endpoints must differ")
        ids = tuple(dict.fromkeys((source_id, target_id, *basis_source_ids)))
        if len(ids) > 10 or any(type(item) is not str or not item for item in ids):
            raise ValueError("association source IDs must be bounded nonempty strings")
        proofs: list[GraphVersion] = []
        epoch = None
        namespace = self.adapter.namespace.as_tuple
        for source_id_to_read in ids:
            source, proof = self.repository.read_source_evidence(
                source_id_to_read, audience=audience, purpose=purpose,
            )
            if source is None:
                raise PermissionError("association source is unavailable")
            current_epoch = proof.epochs[0]
            if epoch is not None and current_epoch != epoch:
                raise RuntimeError("association namespace changed during source reads")
            epoch = current_epoch
            for key in (source_key(*namespace, source_id_to_read),
                        access_key(*namespace, source_id_to_read)):
                if not any(version.key == key and version.revision > 0 for version in proof.versions):
                    raise RuntimeError("association source lacks committed access proof")
            proofs.extend(proof.versions)
        if self.repository.store.graph_epoch(*namespace) != epoch:
            raise RuntimeError("association namespace changed during preparation")
        unique = {version.key: version for version in proofs}
        if len(unique) != len(proofs) and any(
            unique[version.key] != version for version in proofs
        ):
            raise RuntimeError("association source proof changed during preparation")
        return PreparedAssociation(
            source_id, target_id, basis_source_ids, tuple(unique.values()), epoch,
        )

    def prepare_encoding(
        self,
        source_ref: str,
        context: EncodingContext,
        *,
        audience: str,
        purpose: str,
        expected_epoch: NamespaceEpoch | None = None,
    ) -> PreparedEncoding:
        """Prepare C02 only from currently authorized, committed source bytes."""

        if expected_epoch is not None:
            if not isinstance(expected_epoch, NamespaceEpoch):
                raise TypeError("expected_epoch must be NamespaceEpoch or None")
            if (expected_epoch.bot, expected_epoch.persona) != self.adapter.namespace.as_tuple:
                raise ValueError("expected_epoch crosses D06 namespace")
        source, proof = self.repository.read_source_evidence(
            source_ref, audience=audience, purpose=purpose
        )
        if source is None:
            raise PermissionError("source is unavailable for encoding")
        epoch = proof.epochs[0]
        if expected_epoch is not None and epoch != expected_epoch:
            raise RuntimeError("source namespace changed before encoding preparation")
        if self.repository.store.graph_epoch(*self.adapter.namespace.as_tuple) != epoch:
            raise RuntimeError("source namespace changed during encoding preparation")
        source_version = next(
            (version for version in proof.versions
             if version.key == source_key(*self.adapter.namespace.as_tuple, source_ref)),
            None,
        )
        if source_version is None:
            raise RuntimeError("source read proof does not contain the requested source")
        if not any(
            (ref, source_version.revision) in context.read_versions
            for ref in (source_ref, source_version.key.token)
        ):
            raise ValueError("encoding context must bind the committed source revision")
        proposal = self.adapter.prepare_encoding(source.source_id, context)
        return PreparedEncoding(source.source_id, proposal, proof.versions, epoch)

    def prepare_first_ingress_encoding(
        self,
        source_ref: str,
        result: Mapping[str, object],
        receipt: CallReceipt,
        context: EncodingContext,
        *,
        encoding_baseline_ref: str,
        audience: str,
        purpose: str,
    ) -> PreparedFirstIngressEncoding:
        """Ground model suggestions without asserting their Authority provenance.

        A CallReceipt is constructible and does not bind result bytes. The
        returned PreparedEncoding is held until D11 supplies a trusted result
        observation that binds the result digest to the same operation/call.
        Model meanings and feelings never become D04 experience evidence.
        """
        if (not isinstance(receipt, CallReceipt) or receipt.status != "completed"
                or receipt.result_qualification != "eligible"
                or not receipt.egress_start_ref or not receipt.egress_finish_ref):
            raise ValueError("completed model receipt claim is required")
        if not isinstance(context, EncodingContext):
            raise TypeError("context must be EncodingContext")
        source, proof = self.repository.read_source_evidence(
            source_ref, audience=audience, purpose=purpose,
        )
        if source is None:
            raise PermissionError("source is unavailable for encoding")
        candidate = parse_first_ingress_encoding_result(result, source)
        try:
            baseline_key = AtomKey.from_token(encoding_baseline_ref)
        except (TypeError, ValueError) as exc:
            raise ValueError("committed D04 baseline reference is required") from exc
        if (baseline_key.type_name != "d04.encoding_baseline.v1"
                or NamespaceId.from_key(baseline_key) != self.adapter.namespace):
            raise ValueError("committed D04 baseline must use this namespace")
        spec = self.repository.store._registry.spec(baseline_key.type_name)
        if spec.writer_domain != "d04" or not spec.immutable:
            raise ValueError("registered immutable D04 baseline is required")
        baseline_atom = self.repository.store.graph_snapshot((baseline_key,)).get(baseline_key)
        if baseline_atom is None or not baseline_atom.valid or baseline_atom.revision < 1:
            raise ValueError("committed D04 baseline is unavailable")
        baseline = spec.validator(baseline_atom.value)
        if not isinstance(baseline, EncodingBaseline):
            raise ValueError("committed D04 baseline is invalid")
        perspective_key = AtomKey.from_token(baseline.perspective_ref)
        if perspective_key.type_name != "d03.self_perspective.v1":
            raise ValueError("first-ingress C02 requires a committed D03 self perspective")
        source_key_ref = source_key(*self.adapter.namespace.as_tuple, source_ref)
        if (source_key_ref.token not in baseline.source_refs
                or baseline.perspective_ref != context.perspective_ref
                or tuple(item.ref for item in baseline.then_feeling_versions) != context.then_feeling_refs
                or tuple(item.ref for item in baseline.interpretation_versions) != context.interpretation_refs):
            raise ValueError("D04 baseline differs from encoding context")
        read_versions = dict(context.read_versions)
        if (len(read_versions) != len(context.read_versions)
                or read_versions.get(baseline_key.token) != baseline_atom.revision
                or any(read_versions.get(item.ref) != item.revision for item in (
                    *baseline.then_feeling_versions, *baseline.interpretation_versions,
                ))):
            raise ValueError("D04 baseline and context lack matching committed read versions")
        context_versions = {}
        for ref, revision in context.read_versions:
            key = AtomKey.from_token(ref)
            if NamespaceId.from_key(key) != self.adapter.namespace:
                raise ValueError("encoding context crosses namespace")
            context_versions[key] = revision
        keys = tuple(dict.fromkeys((*map(AtomKey.from_token, (
            *baseline.source_refs, baseline.perspective_ref,
            *(item.ref for item in baseline.then_feeling_versions),
            *(item.ref for item in baseline.interpretation_versions),
            baseline_key.token,
        )), *(version.key for version in proof.versions),
            *context_versions)))
        snapshot = self.repository.store.graph_snapshot(keys)
        baseline.verify_committed_refs(snapshot)
        perspective_atom = snapshot.get(perspective_key)
        if (perspective_atom is None
                or perspective_atom.value.get("arrival_event_ref") != context.event_ref):
            raise ValueError("encoding event differs from D03 self perspective arrival")
        if (snapshot.epochs != proof.epochs or snapshot.get(baseline_key) != baseline_atom
                or any(snapshot.get(key) is None or not snapshot.get(key).valid
                       or snapshot.get(key).revision != revision
                       for key, revision in context_versions.items())
                or any(snapshot.get(version.key) is None
                       or snapshot.get(version.key).revision != version.revision
                       or not snapshot.get(version.key).valid for version in proof.versions)):
            raise RuntimeError("source, access, or D04 baseline changed during encoding")
        grounded = replace(context, detail_weights=candidate.quoted_details)
        prepared = self.prepare_encoding(
            source_ref, grounded, audience=audience, purpose=purpose,
            expected_epoch=proof.epochs[0],
        )
        prepared = replace(prepared, status="candidate_hold")
        return PreparedFirstIngressEncoding(
            prepared, baseline_key.token, receipt, canonical_digest(dict(result)),
            candidate.possible_meanings, candidate.possible_feelings,
        )

    def prepare_authority_first_ingress_encoding(
        self, read_request: ModelResultReadRequestV1, read: ModelResultReadV1,
        binding: EncodingCallBinding, original_source: SourceRecord,
        context: EncodingContext, *, encoding_baseline_ref: str,
        audience: str, purpose: str,
    ) -> PreparedFirstIngressEncoding:
        """Consume a completed original read as a held D06 candidate only.

        The read DTO is data, not a durable adoption permit. D11 must obtain it
        from the live Authority service and repeat source, worker/cancel and
        graph validation at final adoption. This method does no graph write.
        """
        if (type(read_request) is not ModelResultReadRequestV1
                or type(read) is not ModelResultReadV1
                or type(binding) is not EncodingCallBinding
                or type(original_source) is not SourceRecord):
            raise TypeError("typed original Authority read, binding and source required")
        if (read_request.namespace != self.adapter.namespace
                or binding.namespace != self.adapter.namespace
                or read_request.call_id != read.call_id
                or read_request.source_purpose != purpose
                or read_request.audience != (audience,)
                or read.observation.authority_id != read_request.authority_id
                or read.observation.namespace != read_request.authority_namespace):
            raise ValueError("Authority read, binding or source scope differs")
        return self._prepare_bound_first_ingress_result(
            read, binding, original_source, context,
            encoding_baseline_ref=encoding_baseline_ref,
            audience=audience, purpose=purpose,
        )

    def prepare_worker_first_ingress_encoding(
        self, read: WorkerModelResultReadV1, binding: EncodingCallBinding,
        original_source: SourceRecord, context: EncodingContext, *,
        encoding_baseline_ref: str, audience: str, purpose: str,
    ) -> PreparedFirstIngressEncoding:
        """Prepare a worker's original completed result as held D06 material."""
        if (type(read) is not WorkerModelResultReadV1
                or type(binding) is not EncodingCallBinding
                or type(original_source) is not SourceRecord):
            raise TypeError("typed worker result, binding and source required")
        request = read.request
        frozen = binding.request
        frozen_authority = frozen.get("envelope", {}).get("authority", {})
        if (request.namespace != self.adapter.namespace
                or binding.namespace != self.adapter.namespace
                or request.job_id != binding.job_id
                or request.original_operation_id != binding.budget_reservation_operation_id
                or request.acquire_operation_id != frozen.get("acquire_operation_id")
                or request.call_id != binding.call_id
                or request.binding_digest != binding.binding_digest
                or request.model_request_digest != binding.model_request_digest
                or read.observation.operation_id != request.acquire_operation_id
                or read.observation.subject != frozen_authority.get("actor")
                or frozen_authority.get("audience") != [audience]
                or frozen_authority.get("purpose") != purpose):
            raise ValueError("worker original result and frozen encoding scope differ")
        return self._prepare_bound_first_ingress_result(
            read, binding, original_source, context,
            encoding_baseline_ref=encoding_baseline_ref,
            audience=audience, purpose=purpose,
            consumer_operation_id=request.consumer_operation_id,
        )

    def _prepare_bound_first_ingress_result(
        self, read: ModelResultReadV1 | WorkerModelResultReadV1,
        binding: EncodingCallBinding, original_source: SourceRecord,
        context: EncodingContext, *, encoding_baseline_ref: str,
        audience: str, purpose: str, consumer_operation_id: str | None = None,
    ) -> PreparedFirstIngressEncoding:
        binding_to_json(binding)  # Checks the frozen request's internal digest.
        if binding.source_id != original_source.source_id:
            raise ValueError("original source differs from encoding binding")
        source, proof = self.repository.read_source_evidence(
            original_source.source_id, audience=audience, purpose=purpose,
        )
        if source is None:
            raise PermissionError("original source is unavailable")
        if source != original_source:
            raise ValueError("current source differs from original source")
        versions = {item.key: item.revision for item in proof.versions}
        namespace = self.adapter.namespace.as_tuple
        result = validate_first_encoding_authority_result(
            read, binding.request, original_source,
            source_revision=versions.get(source_key(*namespace, source.source_id), 0),
            access_revision=versions.get(access_key(*namespace, source.source_id), 0),
            binding=binding,
        )
        call_id = read.call_id if type(read) is ModelResultReadV1 else read.request.call_id
        if (binding.call_id != call_id
                or binding.model_request_digest != read.observation.request_digest
                or read.terminal_receipt.observation_digest != read.observation.digest):
            raise ValueError("original Authority result identity differs")
        # The legacy preparation routine accepts a receipt claim. It performs
        # the D04 baseline and graph checks, then returns candidate_hold. This
        # derived claim is never promoted into a graph admission credential.
        claim = CallReceipt(
            "completed", read.observation.operation_id,
            read.observation.operation_id, call_id,
            read.observation.request_digest, "authority-original", "authority-original",
            read.observation.provider_call_ref,
            dict(read.observation.usage), dict(read.observation.cost),
            "confirmed", "eligible", False,
            read.terminal_receipt.admission_id,
            read.terminal_receipt.finish_digest,
        )
        prepared = self.prepare_first_ingress_encoding(
            source.source_id, result, claim, context,
            encoding_baseline_ref=encoding_baseline_ref,
            audience=audience, purpose=purpose,
        )
        if (prepared.prepared.epoch != proof.epochs[0]
                or any(item not in prepared.prepared.proof_versions
                       for item in proof.versions)):
            raise RuntimeError("original source or access changed during preparation")
        return replace(
            prepared, authority_observation_digest=read.observation.digest,
            authority_operation_id=read.observation.operation_id,
            consumer_operation_id=consumer_operation_id,
        )

    def compile_first_ingress_c02_v2(
        self, envelope, held: PreparedFirstIngressEncoding,
        read: ModelResultReadV1 | WorkerModelResultReadV1, *,
        audience: str, purpose: str,
    ) -> HeldFirstIngressC02:
        """Recheck a held model candidate and compile C02 without granting adoption.

        The returned wrapper is deliberately not a DomainProposal. D11 must
        repeat the live Authority read and source/worker/cancel checks before
        it may use the enclosed proposal in a coordinated graph transaction.
        """
        if (type(held) is not PreparedFirstIngressEncoding
                or held.status != "candidate_hold"
                or held.prepared.status != "candidate_hold"
                or type(read) not in {ModelResultReadV1, WorkerModelResultReadV1}):
            raise TypeError("held first-ingress candidate and original read required")
        if type(envelope) is not CommandEnvelope:
            raise TypeError("typed C02 envelope required")
        call_id = read.call_id if type(read) is ModelResultReadV1 else read.request.call_id
        if (held.authority_observation_digest != read.observation.digest
                or held.authority_operation_id != read.observation.operation_id
                or held.receipt_claim.call_id != call_id
                or held.receipt_claim.call_digest != read.observation.request_digest):
            raise ValueError("original Authority result identity differs")
        if type(read) is WorkerModelResultReadV1 and (
                held.consumer_operation_id != read.request.consumer_operation_id
                or envelope.identity.operation_id != read.request.consumer_operation_id
                or envelope.authority.namespace != read.request.namespace):
            raise ValueError("worker result consumer operation differs from C02 envelope")
        result = read.observation.result
        if (type(result) is not dict
                or canonical_digest(result) != held.result_digest):
            raise ValueError("original Authority result digest differs")
        if (envelope.authority.purpose != purpose
                or envelope.authority.audience != (audience,)):
            raise ValueError("C02 envelope source access scope differs")
        trace = held.prepared.proposal.trace
        proposal = held.prepared.proposal
        context = EncodingContext(
            proposal.episode.event_ref, trace.perspective_ref,
            trace.then_feeling_refs, trace.interpretation_refs,
            trace.detail_weights, proposal.read_versions,
        )
        fresh = self.prepare_first_ingress_encoding(
            held.prepared.source_ref, result, held.receipt_claim, context,
            encoding_baseline_ref=held.encoding_baseline_ref,
            audience=audience, purpose=purpose,
        )
        if (fresh.prepared != held.prepared
                or fresh.result_digest != held.result_digest
                or fresh.possible_meanings != held.possible_meanings
                or fresh.possible_feelings != held.possible_feelings):
            raise RuntimeError("held encoding or committed baseline changed")
        compiled = self.adapter.compile_encoding_v2(
            envelope, replace(fresh.prepared, status="candidate"),
            encoding_baseline_ref=held.encoding_baseline_ref,
        )
        return HeldFirstIngressC02(
            compiled, held.prepared.source_ref, held.encoding_baseline_ref,
            call_id, read.observation.request_digest,
            read.observation.digest, held.result_digest,
            read.observation.operation_id,
            held.possible_meanings, held.possible_feelings,
        )

    def retrieve_candidates(
        self,
        qualification: RecallQualification,
        candidate_set_id: str,
        plans: tuple[SearchPlan, ...],
        *,
        audience: str,
        purpose: str,
        access_epoch: int,
        delete_epoch: int,
        as_known_at: float | None = None,
        valid_at: float | None = None,
        expected_epoch: NamespaceEpoch | None = None,
    ) -> RetrievalOutcome:
        """Run only qualified bounded searches and return authorization-bound candidates."""

        if not isinstance(qualification, RecallQualification):
            raise TypeError("qualification must be RecallQualification")
        if type(plans) is not tuple or any(not isinstance(plan, SearchPlan) for plan in plans):
            raise TypeError("plans must be a tuple of SearchPlan")
        if len(plans) > 5:
            raise ValueError("at most five structural search plans are allowed")
        _epoch(access_epoch, "access_epoch")
        _epoch(delete_epoch, "delete_epoch")
        if qualification.mode in {"no_history_search", "working_set_only"}:
            return RetrievalOutcome("not_requested", None, (), None, ())
        if qualification.mode not in {"mandatory", "optional_association"}:
            raise ValueError("unknown recall qualification mode")
        if not plans:
            raise ValueError("qualified history retrieval requires at least one search plan")

        batches: list[MemoryBatch] = []
        for plan in plans:
            batch = self.retriever.search(
                plan.query,
                audience=audience,
                purpose=purpose,
                as_known_at=as_known_at,
                valid_at=valid_at,
                max_candidates=32,
                max_nodes=128,
                page_size=32,
                max_pages=1,
                expected_epoch=expected_epoch,
            )
            batches.append(batch)
            expected_epoch = batch.epoch

        batch_tuple = tuple(batches)
        candidates = self.adapter.assemble_candidates(
            candidate_set_id,
            tuple(RetrievalChannel(plan.name, batch, plan.activation)
                  for plan, batch in zip(plans, batch_tuple, strict=True)),
            purpose=purpose,
            max_candidates=64,
            access_epoch=access_epoch,
            delete_epoch=delete_epoch,
        )
        return RetrievalOutcome(
            "candidate",
            candidates,
            _unique_versions(batch_tuple),
            batch_tuple[0].epoch,
            batch_tuple,
        )
