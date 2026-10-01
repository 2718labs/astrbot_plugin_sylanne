"""Join a fenced current-memory candidate to the real C04 domain bundle.

Only W01 can issue the resource originals and atomically commit the returned
bundle. Preparing this value does not record an experienced recollection.
"""

from __future__ import annotations

from dataclasses import replace

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, Owner
from ...memory_types import source_key
from ...runtime_contracts import CommandEnvelope, DependencySet, DomainBundle, DomainProposal
from ..d04 import AffectCoupling, AffectProvider, AffectScheme, MoodField
from . import CandidateSet, D06DomainAdapter, RecollectionContext, SelectionTicket, _stable_id
from .current_recollection_bridge import CurrentC04SourceCandidateV1


def current_c04_projection_key_v1(
    candidate: CurrentC04SourceCandidateV1, *, experience_id: str,
) -> AtomKey:
    """Give W01 the deterministic absence-read key before it seals the envelope."""
    if (type(candidate) is not CurrentC04SourceCandidateV1
            or type(experience_id) is not str or not experience_id):
        raise TypeError("projection key needs a typed candidate and experience ID")
    reconstruction = candidate.reconstruction
    source = AtomKey.from_token(reconstruction.source_ref)
    mood = AtomKey.from_token(reconstruction.mood_ref)
    versions = {version.key: version.revision for version in candidate.read_versions}
    if (source not in versions or versions[source] < 1
            or mood not in versions or versions[mood] < 1):
        raise ValueError("projection key needs source and mood read versions")
    namespace = (source.owner.bot, source.owner.persona)
    experience = AtomKey(Owner("activity", *namespace, reconstruction.activity_id),
                         "d04.recollection_experience.v1", experience_id)
    projection_id = _stable_id("projection", (
        reconstruction.recollection_id, experience.token,
        versions[source], versions[mood], reconstruction.coupling_version,
    ))
    return AtomKey(Owner("activity", *namespace, reconstruction.activity_id),
                   "d06.recollection_projection.v1", projection_id)


def assemble_current_c04_bundle_v1(
    candidate: CurrentC04SourceCandidateV1, *,
    envelope: CommandEnvelope,
    ticket: SelectionTicket,
    candidates: CandidateSet,
    mood_snapshot: GraphSnapshot,
    mood_key: AtomKey,
    scheme: AffectScheme,
    coupling: AffectCoupling,
    affect_provider: AffectProvider,
    experience_id: str,
    supporting_proposals: tuple[DomainProposal, ...],
    choice_ref: str,
    d02_settlement_ref: str,
    d11_cost_settlement_ref: str,
    persistent_job_ref: str,
    outbox_ref: str,
) -> DomainBundle:
    """Return a version-bound five-domain C04 candidate for W01 adoption.

    `supporting_proposals` are the original D07, D02, and D11 proposals for
    this exact envelope. Their resource and budget receipts are checked by
    W01's issuers at commit, never synthesized by D06.
    """
    if (type(candidate) is not CurrentC04SourceCandidateV1
            or candidate.status != "candidate_hold_w01_atomic_c04"
            or type(envelope) is not CommandEnvelope
            or not isinstance(ticket, SelectionTicket)
            or not isinstance(candidates, CandidateSet)
            or type(mood_snapshot) is not GraphSnapshot
            or not isinstance(mood_key, AtomKey)
            or not isinstance(scheme, AffectScheme)
            or not isinstance(coupling, AffectCoupling)
            or not isinstance(affect_provider, AffectProvider)
            or type(experience_id) is not str or not experience_id):
        raise TypeError("current C04 requires typed candidate, operation, and affect inputs")
    namespace = envelope.authority.namespace
    proposal = candidate.proposal
    reconstruction = candidate.reconstruction
    view = candidate.view
    if (envelope.identity.activity_id != ticket.activity_id
            or proposal.activity_id != ticket.activity_id
            or reconstruction.activity_id != ticket.activity_id
            or proposal.recollection_id != reconstruction.recollection_id
            or proposal.selection_ref != ticket.ticket_id
            or ticket.candidate_set_id != candidates.candidate_set_id
            or proposal.activity_basis_refs != (ticket.ticket_id, candidates.candidate_set_id)
            or len(proposal.content_refs) != 1
            or len(ticket.selected_candidate_ids) != 1
            or candidate.graph_epoch != reconstruction.epoch
            or candidate.graph_epoch != view.epoch
            or mood_snapshot.epochs != (candidate.graph_epoch,)
            or (candidate.graph_epoch.bot, candidate.graph_epoch.persona) != namespace.as_tuple
            or candidate.access_epoch != envelope.version_guard.access_epoch
            or candidate.deletion_epoch != envelope.version_guard.delete_epoch
            or candidate.query_epoch not in envelope.version_guard.query_epochs
            or envelope.source_qualification.source_refs != tuple(
                dict.fromkeys(envelope.source_qualification.source_refs))):
        raise ValueError("current C04 selection, operation, or graph fence differs")
    context = RecollectionContext(
        proposal.now_interpretation_refs,
        proposal.feeling_experience_refs,
        proposal.self_understanding_refs,
    )
    adapter = D06DomainAdapter(namespace)
    if adapter.prepare_recollection(ticket, candidates, context) != proposal:
        raise ValueError("current C04 source selection differs from candidate")
    source = source_key(*namespace.as_tuple, proposal.content_refs[0])
    experience = AtomKey(Owner("activity", *namespace.as_tuple, ticket.activity_id),
                         "d04.recollection_experience.v1", experience_id)
    if (view.source_ref != source.token or reconstruction.source_ref != source.token
            or reconstruction.mood_ref != mood_key.token
            or view.mood_ref != mood_key.token
            or reconstruction.coupling_version != coupling.version
            or view.coupling_version != coupling.version
            or context.feeling_experience_refs != (experience.token,)
            or reconstruction.now_interpretation_refs != context.now_interpretation_refs
            or reconstruction.feeling_experience_refs != context.feeling_experience_refs
            or reconstruction.self_understanding_refs != context.self_understanding_refs
            or reconstruction.subjective_weight != view.subjective_salience
            or reconstruction.subjective_tone != view.subjective_tone):
        raise ValueError("current C04 reconstruction differs from selected source or feeling")
    reads = envelope.version_guard.read_versions
    if (candidate.focus_read_versions
            and (not set(candidate.focus_read_versions) <= set(candidate.read_versions)
                 or {"d07.focus.v1", "d07.attention_ticket.v1"}
                 - {version.key.type_name for version in candidate.focus_read_versions})):
        raise ValueError("current C04 focus proof is incomplete")
    if (len({version.key for version in reads}) != len(reads)
            or not candidate.read_versions
            or not set(candidate.read_versions) <= set(reads)
            or not set(reconstruction.read_versions) <= set(candidate.read_versions)):
        raise ValueError("current C04 envelope lacks candidate read closure")
    mood_atom = mood_snapshot.get(mood_key)
    if (mood_atom is None or not mood_atom.valid
            or GraphVersion(mood_key, mood_atom.revision) not in candidate.read_versions
            or not any(version.key == source and version.revision > 0
                       for version in candidate.read_versions)):
        raise ValueError("current C04 mood or source read proof differs")
    mood_spec = next(spec for spec in affect_provider.type_specs()
                     if spec.name == "d04.mood_field.v1")
    mood = mood_spec.validator(mood_atom.value)
    if (not isinstance(mood, MoodField)
            or (mood.basis_version, mood.parameter_version, mood.coupling_version)
            != (scheme.scheme_version, scheme.parameter_version, scheme.coupling_version)
            or coupling.version != scheme.coupling_version
            or not {source.token, *mood.source_refs}
            <= set(envelope.source_qualification.source_refs)):
        raise ValueError("current C04 mood is outside its source or scheme fence")
    influence = affect_provider.condition_recollection(
        memory_ref=source.token,
        memory_source_refs=(source.token,),
        base_salience_interval=view.base_salience,
        base_tone_interval=view.base_tone,
        mood=mood, coupling=coupling,
    )
    if (influence.salience_interval != view.subjective_salience
            or influence.tone_interval != view.subjective_tone
            or influence.evidence_weight_delta != 0.0):
        raise ValueError("current C04 feeling differs from D04 mood computation")
    recollection_ref = AtomKey(
        Owner("activity", *namespace.as_tuple, ticket.activity_id),
        "d06.recollection.v1", proposal.recollection_id,
    ).token
    d04 = affect_provider.propose_recollection_experience(
        envelope, experience_id=experience_id, recollection_ref=recollection_ref,
        influence=influence, mood=mood, coupling=coupling,
        source_versions=tuple(version for version in candidate.read_versions
                              if version.revision > 0),
        dependencies=DependencySet(),
    )
    bundle = adapter.assemble_recollection_bundle(
        envelope, ticket, candidates, context,
        supporting_proposals=(*supporting_proposals, d04),
        choice_ref=choice_ref,
        d02_settlement_ref=d02_settlement_ref,
        d11_cost_settlement_ref=d11_cost_settlement_ref,
        persistent_job_ref=persistent_job_ref,
        outbox_ref=outbox_ref,
    )
    projection = adapter.recollection_projection_write(
        reconstruction, d04.typed_writes[0],
    )
    expected_projection = current_c04_projection_key_v1(
        candidate, experience_id=experience_id,
    )
    if (projection.key != expected_projection
            or GraphVersion(projection.key, 0) not in reads):
        raise ValueError("current C04 projection requires an absent-key read")
    d06 = next(item for item in bundle.proposals if item.domain == "d06")
    updated_d06 = replace(d06, typed_writes=(*d06.typed_writes, projection))
    return replace(bundle, proposals=tuple(updated_d06 if item is d06 else item
                                           for item in bundle.proposals))


__all__ = ["assemble_current_c04_bundle_v1", "current_c04_projection_key_v1"]
