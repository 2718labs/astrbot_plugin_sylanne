"""Typed D06/D07 C04 preparation from one W01-fenced graph snapshot.

This layer has no store handle or commit permission. W01 supplies a current,
authorized C03 outcome and a complete graph snapshot, then adopts the returned
read versions in a five-domain C04 bundle. Its result is never a recall receipt.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_recollection_view import prepare_affective_recollection_view
from ...memory_reconstruction import (
    DetailCue, RecollectionReconstruction, reconstruct_recollection_candidate,
)
from ...memory_retrieval import MemoryHit
from ...memory_types import (
    SourceRecord, access_key, source_key, validate_access, validate_episode,
    validate_subjective_trace_v2,
)
from ...runtime_contracts import (
    CommandEnvelope, DependencySet, DomainBundle, DomainProposal,
    SourceQualification,
)
from ..d04 import AffectCoupling, AffectProvider, AffectScheme
from ..d03.context import ContextProvider
from ..d07 import CurrentInterpretationCandidate, D07DomainProvider, RecollectionHandoff
from . import (
    D06DomainAdapter, D06DomainProvider, RecallIntent, RecallQualification,
    RecollectionContext,
)
from . import source_correction_head_key
from .pipeline import RetrievalOutcome


@dataclass(frozen=True, slots=True)
class PreparedMandatoryRecollection:
    qualification: RecallQualification
    outcome: RetrievalOutcome
    handoff: RecollectionHandoff
    reconstruction: RecollectionReconstruction
    read_versions: tuple[GraphVersion, ...]
    event_ref: str
    episode_ref: str
    source_qualification: SourceQualification
    audience: str
    purpose: str
    status: str = "candidate_hold"


def prepare_mandatory_recollection_candidate(
    *, adapter: D06DomainAdapter, cognition: D07DomainProvider,
    intent: RecallIntent, outcome: RetrievalOutcome, snapshot: GraphSnapshot,
    activity_id: str, focus_epoch: int, audience: str, purpose: str,
    mood_key: AtomKey, scheme: AffectScheme, coupling: AffectCoupling,
    source_qualification: SourceQualification,
    base_salience: tuple[float, float], base_tone: tuple[float, float],
    detail_cues: tuple[DetailCue, ...], context: RecollectionContext,
    encoding_trace_ref: str,
) -> PreparedMandatoryRecollection:
    """Select one source and reconstruct it without creating a new event.

    W01 must authenticate the snapshot, C03 outcome, focus lease, Authority
    fence, receipt issuers, and final CAS. All source ancestors, access heads,
    correction-head absence proofs, mood, and C02 trace must be in the supplied
    snapshot. An incomplete read fails closed.
    """
    if (not isinstance(adapter, D06DomainAdapter)
            or not isinstance(cognition, D07DomainProvider)
            or not isinstance(outcome, RetrievalOutcome)
            or not isinstance(snapshot, GraphSnapshot)
            or not isinstance(context, RecollectionContext)):
        raise TypeError("typed D06/D07 outcome, context, and graph snapshot are required")
    qualification = adapter.qualify_recall(intent)
    if qualification.mode != "mandatory":
        raise ValueError("this C04 path requires a mandatory history trigger")
    if outcome.qualification != qualification:
        raise ValueError("C03 outcome is not bound to this mandatory trigger")
    if (outcome.status != "candidate" or outcome.candidates is None
            or outcome.epoch is None or snapshot.epochs != (outcome.epoch,)
            or (outcome.epoch.bot, outcome.epoch.persona) != adapter.namespace.as_tuple
            or any((atom.key.owner.bot, atom.key.owner.persona)
                   != adapter.namespace.as_tuple for atom in snapshot.atoms)):
        raise ValueError("current C03 result and W01 snapshot differ")
    hits = tuple(hit for batch in outcome.batches for hit in batch.hits
                 if isinstance(hit, MemoryHit) and isinstance(hit.record, SourceRecord))
    source_ids = {hit.record.source_id for hit in hits}
    eligible = tuple(item.candidate_id for item in outcome.candidates.items
                     if item.content_ref in source_ids)
    handoff = cognition.select_bounded_recollection(
        activity_id=activity_id, focus_epoch=focus_epoch,
        candidates=outcome.candidates, purpose=purpose,
        eligible_candidate_ids=eligible,
    )
    selected = next(item for item in outcome.candidates.items
                    if item.candidate_id == handoff.selection_ticket.selected_candidate_ids[0])
    matching = tuple(hit for hit in hits if hit.record.source_id == selected.content_ref)
    if not matching or any(hit != matching[0] for hit in matching[1:]):
        raise ValueError("selected source has no unique C03 proof")
    hit = matching[0]
    if hit.key != source_key(*adapter.namespace.as_tuple, selected.content_ref):
        raise ValueError("selected hit is not the current source address")
    record = hit.record
    expected_family = "derived" if record.source_kind == "internal" else record.source_kind
    expected_reality = {
        "observed": "external_observation", "reported": "external_report",
        "authored": "authored_content", "internal": "inference",
        "simulated": "simulation",
    }[record.source_kind]
    expected_eligibility = {
        "confirmed": "eligible", "reported": "qualified",
        "disputed": "ineligible", "unknown": "ineligible",
    }[record.assertion_status]
    if (hit.key.token not in source_qualification.source_refs
            or source_qualification.source_family != expected_family
            or source_qualification.content_reality != expected_reality
            or source_qualification.evidence_eligibility != expected_eligibility
            or source_qualification.occurred_at != record.occurred_at
            or source_qualification.learned_at != record.recorded_at):
        raise ValueError("recall source qualification differs from committed source")
    records = {record.source_id: record for record in hit.sources}
    if (len(records) != len(hit.sources) or records.get(selected.content_ref) != hit.record
            or any(not set(record.parent_source_ids) <= set(records)
                   for record in records.values())):
        raise ValueError("C03 source lineage is incomplete")
    proofs = set(hit.proof_versions)
    head_proofs: list[GraphVersion] = []
    for record in hit.sources:
        source = source_key(*adapter.namespace.as_tuple, record.source_id)
        access = access_key(*adapter.namespace.as_tuple, record.source_id)
        head = source_correction_head_key(adapter.namespace, record.source_id)
        source_atom, access_atom, head_atom = (snapshot.get(key)
                                               for key in (source, access, head))
        if (source_atom is None or access_atom is None or head_atom is None
                or not source_atom.valid or not access_atom.valid
                or source_atom.revision < 1 or access_atom.revision < 1
                or GraphVersion(source, source_atom.revision) not in proofs
                or GraphVersion(access, access_atom.revision) not in proofs
                or SourceRecord.from_dict(source_atom.value) != record):
            raise ValueError("current source or access differs from C03 proof")
        validate_access(access_atom.value)
        if (access_atom.value["source_id"] != record.source_id
                or access_atom.value["status"] != "active"
                or audience not in record.audiences
                or audience not in access_atom.value["audiences"]
                or purpose not in record.purposes
                or purpose not in access_atom.value["purposes"]):
            raise PermissionError("current source access is unavailable")
        if head_atom.revision != 0 or head_atom.valid:
            raise ValueError("source correction requires a new recollection")
        head_proofs.append(GraphVersion(head, 0))
    for proof in hit.proof_versions:
        atom = snapshot.get(proof.key)
        if (atom is None or atom.revision != proof.revision
                or not atom.valid or proof.revision < 1):
            raise ValueError("C03 proof is not current in the W01 snapshot")

    trace_key = AtomKey.from_token(encoding_trace_ref)
    if (trace_key.type_name != "memory.subjective_trace.v2"
            or (trace_key.owner.bot, trace_key.owner.persona)
            != adapter.namespace.as_tuple):
        raise ValueError("C02 requires a same-namespace subjective trace v2")
    trace_atom = snapshot.get(trace_key)
    if trace_atom is None or not trace_atom.valid or trace_atom.revision < 1:
        raise ValueError("committed C02 subjective trace is unavailable")
    validate_subjective_trace_v2(trace_atom.value)
    if trace_atom.value["trace_id"] != trace_key.owner.subject:
        raise ValueError("C02 subjective trace identity differs")
    episode_key = AtomKey.from_token(trace_atom.value["episode_ref"])
    baseline_key = AtomKey.from_token(trace_atom.value["encoding_baseline_ref"])
    episode_atom, baseline_atom = snapshot.get(episode_key), snapshot.get(baseline_key)
    if (episode_atom is None or baseline_atom is None
            or not episode_atom.valid or not baseline_atom.valid
            or episode_atom.revision < 1 or baseline_atom.revision < 1):
        raise ValueError("committed C02 episode or D04 baseline is unavailable")
    validate_episode(episode_atom.value)
    if (episode_atom.value["episode_id"] != episode_key.owner.subject
            or hit.key.token not in episode_atom.value["source_refs"]):
        raise ValueError("C02 episode does not contain the selected source")
    event_key = AtomKey.from_token(episode_atom.value["event_ref"])
    event_atom = snapshot.get(event_key)
    if (event_key.type_name != "d03.world_event"
            or (event_key.owner.bot, event_key.owner.persona)
            != adapter.namespace.as_tuple
            or event_atom is None or not event_atom.valid or event_atom.revision < 1):
        raise ValueError("C02 episode lacks its committed D03 event")
    event_spec = next(spec for spec in ContextProvider().type_specs()
                      if spec.name == "d03.world_event")
    event_spec.validator(event_atom.value)
    if hit.key.token not in event_atom.value["source_refs"]:
        raise ValueError("D03 event does not trace to the selected source")
    baseline_spec = next(spec for spec in AffectProvider(active_scheme=scheme).type_specs()
                         if spec.name == "d04.encoding_baseline.v1")
    baseline = baseline_spec.validator(baseline_atom.value)
    qualified_sources = {source_key(*adapter.namespace.as_tuple, source_id).token
                         for source_id in records}
    if any(not set(refs) <= qualified_sources for refs in (
            episode_atom.value["source_refs"], event_atom.value["source_refs"],
            baseline.source_refs)):
        raise PermissionError("C02 recollection references a source outside the C03 proof")
    if (hit.key.token not in baseline.source_refs
            or trace_atom.value["perspective_ref"] != baseline.perspective_ref
            or tuple(item.ref for item in baseline.then_feeling_versions)
            != tuple(trace_atom.value["then_feeling_refs"])):
        raise ValueError("C02 trace differs from its committed D04 baseline")
    baseline.verify_committed_refs(snapshot)
    if ((baseline.salience_interval is not None
         and baseline.salience_interval != base_salience)
            or (baseline.tone_interval is not None
                and baseline.tone_interval != base_tone)):
        raise ValueError("reconstruction base differs from committed C02 baseline")
    encoded_weights = dict(trace_atom.value["detail_weights"])
    if any(cue.interpretation_ref is None
           and encoded_weights.get(cue.detail_id) != cue.accessibility
           for cue in detail_cues):
        raise ValueError("detail cue differs from committed subjective trace")

    view = prepare_affective_recollection_view(
        ticket=handoff.selection_ticket, candidates=outcome.candidates, hit=hit,
        mood_snapshot=snapshot, mood_key=mood_key, scheme=scheme,
        coupling=coupling, source_qualification=source_qualification,
        base_salience=base_salience, base_tone=base_tone, purpose=purpose,
    )
    proposal = adapter.prepare_recollection(
        handoff.selection_ticket, outcome.candidates, context,
    )
    reconstruction = reconstruct_recollection_candidate(
        proposal=proposal, view=view, detail_cues=detail_cues,
        then_meaning_refs=tuple(trace_atom.value["interpretation_refs"]),
    )
    trace_proofs = (GraphVersion(trace_key, trace_atom.revision),
                    GraphVersion(episode_key, episode_atom.revision),
                    GraphVersion(baseline_key, baseline_atom.revision),
                    GraphVersion(event_key, event_atom.revision),
                    GraphVersion(AtomKey.from_token(baseline.perspective_ref),
                                 snapshot.get(AtomKey.from_token(baseline.perspective_ref)).revision))
    read_versions = tuple(dict.fromkeys((
        *reconstruction.read_versions, *head_proofs, *trace_proofs,
    )))
    reconstruction = replace(
        reconstruction, encoding_trace_ref=trace_key.token,
        then_feeling_refs=tuple(trace_atom.value["then_feeling_refs"]),
        then_feeling_versions=tuple(
            GraphVersion(AtomKey.from_token(item.ref), item.revision)
            for item in baseline.then_feeling_versions
        ),
        then_feeling_status="baseline_ref_history_unverified",
        read_versions=read_versions,
    )
    return PreparedMandatoryRecollection(
        qualification, outcome, handoff, reconstruction, read_versions,
        event_key.token, episode_key.token, source_qualification, audience, purpose,
    )


def assemble_prepared_mandatory_recollection_bundle(
    *, prepared: PreparedMandatoryRecollection, snapshot: GraphSnapshot,
    envelope: CommandEnvelope, adapter: D06DomainAdapter,
    cognition: D07DomainProvider, interpretation: CurrentInterpretationCandidate,
    affect_proposal: DomainProposal, resource_proposal: DomainProposal,
    runtime_proposal: DomainProposal, d02_settlement_ref: str,
    d11_cost_settlement_ref: str, persistent_job_ref: str, outbox_ref: str,
) -> DomainBundle:
    """Assemble five domain candidates; W01 alone may validate and commit them.

    The original D03 event and C02 episode are guarded reads. Each new
    activity writes only its own selection, interpretation, feeling, recall,
    projection, and required runtime receipts.
    """
    if (not isinstance(prepared, PreparedMandatoryRecollection)
            or prepared.status != "candidate_hold"
            or not isinstance(snapshot, GraphSnapshot)
            or not isinstance(envelope, CommandEnvelope)
            or not isinstance(adapter, D06DomainAdapter)
            or not isinstance(cognition, D07DomainProvider)):
        raise TypeError("typed C04 preparation, snapshot, envelope, and providers required")
    recollection = prepared.reconstruction
    ticket = prepared.handoff.selection_ticket
    if (envelope.authority.namespace != adapter.namespace
            or envelope.identity.activity_id != ticket.activity_id
            or envelope.authority.purpose != prepared.purpose
            or prepared.audience not in envelope.authority.audience
            or envelope.source_qualification != prepared.source_qualification
            or snapshot.epochs != (recollection.epoch,)
            or not set(prepared.read_versions) <= set(snapshot.versions)
            or not set(prepared.read_versions) <= set(envelope.version_guard.read_versions)):
        raise ValueError("C04 envelope or current snapshot differs from prepared recall")
    if (GraphVersion(AtomKey.from_token(prepared.event_ref),
                     snapshot.get(AtomKey.from_token(prepared.event_ref)).revision)
            not in prepared.read_versions
            or GraphVersion(AtomKey.from_token(prepared.episode_ref),
                            snapshot.get(AtomKey.from_token(prepared.episode_ref)).revision)
            not in prepared.read_versions):
        raise ValueError("C04 lacks the original event and episode proofs")
    source = AtomKey.from_token(recollection.source_ref)
    access = access_key(*adapter.namespace.as_tuple, source.owner.subject)
    head = source_correction_head_key(adapter.namespace, source.owner.subject)
    access_atom, head_atom = snapshot.get(access), snapshot.get(head)
    if (access_atom is None or not access_atom.valid
            or access_atom.value.get("status") != "active"
            or head_atom is None or head_atom.revision != 0 or head_atom.valid):
        raise ValueError("C04 source access or correction head changed")
    if (recollection.activity_id != ticket.activity_id
            or interpretation.activity_id != ticket.activity_id
            or recollection.now_interpretation_refs != (
                cognition.current_interpretation_write(
                    envelope, interpretation, source_dependencies=(source,),
                ).key.token,
            )):
        raise ValueError("C04 current interpretation differs from prepared recall")
    choice = cognition.recollection_support_proposal(
        envelope, prepared.handoff, interpretation, source_dependencies=(source,),
    )
    if (affect_proposal.domain != "d04" or affect_proposal.envelope != envelope):
        raise ValueError("C04 needs its matching D04 feeling proposal")
    experiences = tuple(write for write in affect_proposal.typed_writes
                        if write.key.type_name == "d04.recollection_experience.v1")
    if (len(experiences) != 1
            or recollection.feeling_experience_refs != (experiences[0].key.token,)):
        raise ValueError("C04 needs one D04 experience for this activity")
    projection = adapter.recollection_projection_write(recollection, experiences[0])
    bundle = adapter.assemble_recollection_bundle(
        envelope, ticket, prepared.outcome.candidates,
        RecollectionContext(recollection.now_interpretation_refs,
                            recollection.feeling_experience_refs,
                            recollection.self_understanding_refs),
        supporting_proposals=(choice, affect_proposal, resource_proposal,
                              runtime_proposal),
        choice_ref=choice.typed_writes[0].key.token,
        d02_settlement_ref=d02_settlement_ref,
        d11_cost_settlement_ref=d11_cost_settlement_ref,
        persistent_job_ref=persistent_job_ref, outbox_ref=outbox_ref,
    )
    d06 = bundle.proposals[0]
    provenance = tuple(dict.fromkeys((
        *d06.dependencies.historical_provenance,
        *(version for version in prepared.read_versions if version.revision > 0),
    )))
    d06 = replace(
        d06,
        typed_writes=(*d06.typed_writes, projection),
        dependencies=DependencySet(historical_provenance=provenance),
    )
    D06DomainProvider().validate(d06)
    result = replace(bundle, proposals=(d06, *bundle.proposals[1:]))
    if any(write.key.type_name == "d03.world_event"
           for proposal in result.proposals for write in proposal.typed_writes):
        raise ValueError("C04 cannot write a second external event")
    return result


__all__ = [
    "PreparedMandatoryRecollection", "prepare_mandatory_recollection_candidate",
    "assemble_prepared_mandatory_recollection_bundle",
]
