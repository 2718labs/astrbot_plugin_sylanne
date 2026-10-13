"""Turn a signed C04 result into D06 candidates for D07's final choice.

This conversion preserves the installed algorithm's per-source Mood score.
It cannot qualify an external fact or create a graph write by itself.
"""

from __future__ import annotations

from dataclasses import replace

from ..domains.d06 import (
    CandidateItem, CandidateSet, D06DomainAdapter, RecollectionContext,
    RecollectionProposal,
)
from ..domains.d07 import D07DomainProvider, RecollectionHandoff
from ..graph_types import AtomKey, GraphVersion, NamespaceEpoch
from ..memory_recollection_view import AffectiveRecollectionView
from ..memory_reconstruction import (
    RecollectionReconstruction, reconstruct_recollection_candidate,
)
from ..memory_types import SourceRecord
from .c04_v3_contracts import AssociationWorkInputV3, AssociationWorkResultV3


def candidate_set_from_c04_result_v3(
    work: AssociationWorkInputV3, result: AssociationWorkResultV3,
) -> CandidateSet:
    """Use only source records and rankings present in the frozen work/result."""
    result.validate_input(work)
    reads = {item.ref: item for item in work.reads}
    items = []
    for ranked in result.candidates:
        head = reads.get(ranked.source_ref)
        if head is None or not head.valid or head.value is None:
            raise ValueError("ranked C04 source lacks its frozen graph original")
        source = SourceRecord.from_dict(head.value)
        if (ranked.score > 1 or work.purpose not in source.purposes
                or work.audience not in source.audiences):
            raise ValueError("ranked C04 source lacks bounded current eligibility")
        from .c04_direct_seed_v4 import AssociationWorkInputV4, c04_candidate_origin_v4
        origin = c04_candidate_origin_v4(work, ranked.source_ref) if type(work) is AssociationWorkInputV4 else "c04_current_association_v3"
        items.append(CandidateItem(
            source.source_id, source.source_id, source.provenance_root,
            origin, (work.purpose,), ranked.score,
            "subjective_association_only",
        ))
    return CandidateSet(
        "c04-result:" + result.result_digest, tuple(items),
        "partial" if result.truncated else "complete",
        result.result_digest if result.truncated else None,
        work.access_epoch, work.delete_epoch,
    )


def select_c04_result_v3(
    work: AssociationWorkInputV3, result: AssociationWorkResultV3,
    *, focus_epoch: int,
) -> tuple[CandidateSet, RecollectionHandoff]:
    """Ask D07 to select one actually ranked, eligible C04 source."""
    candidates = candidate_set_from_c04_result_v3(work, result)
    handoff = D07DomainProvider.select_bounded_recollection(
        activity_id=work.activity_id, focus_epoch=focus_epoch,
        candidates=candidates, purpose=work.purpose,
        eligible_candidate_ids=tuple(item.candidate_id for item in candidates.items),
        max_considered=work.budget.max_candidates,
    )
    return candidates, handoff


def reconstruct_c04_result_v3(
    work: AssociationWorkInputV3, result: AssociationWorkResultV3,
    *, candidates: CandidateSet, handoff: RecollectionHandoff,
    adapter: D06DomainAdapter, context: RecollectionContext,
) -> tuple[RecollectionProposal, RecollectionReconstruction]:
    """Project the selected source's certified V3 intervals into D06 memory."""
    expected_candidates = candidate_set_from_c04_result_v3(work, result)
    if (type(candidates) is not CandidateSet
            or candidates != expected_candidates
            or type(handoff) is not RecollectionHandoff
            or type(adapter) is not D06DomainAdapter
            or adapter.namespace != work.namespace
            or type(context) is not RecollectionContext):
        raise ValueError("D06 C04 result, selection or context differs")
    _expected_candidates, expected_handoff = select_c04_result_v3(
        work, result, focus_epoch=work.selection_ticket.focus_epoch)
    if handoff != expected_handoff:
        raise ValueError("D07 C04 handoff differs from its frozen result choice")
    for ref in (*context.now_interpretation_refs,
                *context.feeling_experience_refs,
                *context.self_understanding_refs):
        key = AtomKey.from_token(ref)
        if (key.owner.bot, key.owner.persona) != work.namespace.as_tuple:
            raise ValueError("D06 C04 context crosses namespace")
    selected = handoff.selection_ticket.selected_candidate_ids
    if len(selected) != 1 or selected[0] not in {
            item.candidate_id for item in candidates.items}:
        raise ValueError("D07 did not select one signed C04 result candidate")
    source_id = selected[0]
    source_ref = next(item.content_ref for item in candidates.items
                      if item.candidate_id == source_id)
    source_key = AtomKey.from_token(next(
        ranked.source_ref for ranked in result.candidates
        if AtomKey.from_token(ranked.source_ref).owner.subject == source_ref))
    target = next(item for item in work.targets
                  if item.source_ref == source_key.token)
    heads = {item.ref: item for item in work.reads}
    source_head = heads[source_key.token]
    mood_head = heads[work.mood_ref]
    if (not source_head.valid or not mood_head.valid
            or source_head.value is None or mood_head.value is None):
        raise ValueError("selected source or Mood lacks a frozen graph read")
    source = SourceRecord.from_dict(source_head.value)
    from .c04_d04_state_codec_v3 import decode_c04_mood_v3
    coupling_version = decode_c04_mood_v3(work.mood_ref, mood_head.value).coupling_version
    if type(coupling_version) is not str or not coupling_version:
        raise ValueError("current Mood lacks its exact coupling version")
    proposal = adapter.prepare_recollection(
        handoff.selection_ticket, candidates, context)
    view = AffectiveRecollectionView(
        source_key.token, source.text, source.source_kind,
        source.assertion_status,
        target.condition.conditioned_salience_interval,
        target.condition.conditioned_tone_interval,
        target.baseline.salience_interval, target.baseline.tone_interval,
        work.mood_ref, coupling_version,
        tuple(sorted({
            *(GraphVersion(AtomKey.from_token(head.ref), head.revision)
              for head in work.reads),
            GraphVersion(AtomKey.from_token(target.condition.current_checkpoint.ref),
                         target.condition.current_checkpoint.revision),
        }, key=lambda version: version.key.token)),
        NamespaceEpoch(*work.namespace.as_tuple, work.graph_epoch),
    )
    reconstruction = reconstruct_recollection_candidate(
        proposal=proposal, view=view, detail_cues=(),
        then_meaning_refs=tuple(item.ref for item in target.baseline.interpretations),
    )
    reconstruction = replace(
        reconstruction,
        then_feeling_refs=tuple(member.feeling.ref
                                for member in target.baseline.members),
        then_feeling_versions=tuple(GraphVersion(
            AtomKey.from_token(member.feeling.ref), member.feeling.revision)
            for member in target.baseline.members),
        then_feeling_status="v3_certified_encoding_baseline",
    )
    return proposal, reconstruction


__all__ = ["candidate_set_from_c04_result_v3", "select_c04_result_v3",
           "reconstruct_c04_result_v3"]
