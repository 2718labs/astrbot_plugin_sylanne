"""Bind a current D06 source page to one D04-conditioned C04 candidate.

This is the D06 handoff to W01's atomic C04 bundle. A candidate, even when its
two mood projections differ, is not a committed RecollectionExperience.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, NamespaceEpoch
from ...memory_recollection_view import (
    AffectiveRecollectionView, prepare_affective_recollection_view,
)
from ...memory_reconstruction import (
    DetailCue, RecollectionReconstruction, reconstruct_recollection_candidate,
)
from ...memory_retrieval import MemoryHit
from ...memory_types import source_key
from ...runtime_contracts import NamespaceId, QueryEpoch, SourceQualification
from ..d04 import AffectCoupling, AffectScheme
from . import CandidateSet, D06DomainAdapter, RecollectionContext, RecollectionProposal, SelectionTicket
from .current_memory_evidence import CurrentMemoryEvidencePageV1


@dataclass(frozen=True, slots=True)
class CurrentC04SourceCandidateV1:
    proposal: RecollectionProposal
    view: AffectiveRecollectionView
    reconstruction: RecollectionReconstruction
    read_versions: tuple[GraphVersion, ...]
    graph_epoch: NamespaceEpoch
    query_epoch: QueryEpoch
    access_epoch: int
    deletion_epoch: int
    status: str = "candidate_hold_w01_atomic_c04"
    focus_read_versions: tuple[GraphVersion, ...] = ()


def prepare_current_c04_source_candidate_v1(
    evidence_page: CurrentMemoryEvidencePageV1, *, namespace: NamespaceId,
    ticket: SelectionTicket, candidates: CandidateSet,
    context: RecollectionContext, mood_snapshot: GraphSnapshot,
    mood_key: AtomKey, scheme: AffectScheme, coupling: AffectCoupling,
    source_qualification: SourceQualification,
    base_salience: tuple[float, float], base_tone: tuple[float, float],
    detail_cues: tuple[DetailCue, ...] = (),
) -> CurrentC04SourceCandidateV1:
    """Prepare one version-closed selected source without issuing experience."""
    if (type(evidence_page) is not CurrentMemoryEvidencePageV1
            or type(namespace) is not NamespaceId
            or not isinstance(ticket, SelectionTicket)
            or not isinstance(candidates, CandidateSet)
            or not isinstance(context, RecollectionContext)
            or type(mood_snapshot) is not GraphSnapshot
            or mood_snapshot.epochs != (evidence_page.graph_epoch,)
            or (evidence_page.graph_epoch.bot,
                evidence_page.graph_epoch.persona) != namespace.as_tuple):
        raise ValueError("current C04 source and mood need one graph epoch")
    if (candidates.access_epoch != evidence_page.access_epoch
            or candidates.delete_epoch != evidence_page.deletion_epoch
            or len(ticket.selected_candidate_ids) != 1):
        raise ValueError("C04 selection or access/deletion epoch differs")
    selected_id = ticket.selected_candidate_ids[0]
    selected = next((item for item in candidates.items
                     if item.candidate_id == selected_id), None)
    if selected is None:
        raise ValueError("C04 selection lacks a candidate")
    selected_ref = source_key(*namespace.as_tuple, selected.content_ref).token
    matching = tuple(item for item in evidence_page.candidates
                     if item.source_ref == selected_ref)
    if len(matching) != 1:
        raise PermissionError("C04 selected source is not currently qualified")
    evidence = matching[0]
    if evidence.source_ref not in source_qualification.source_refs:
        raise ValueError("C04 source qualification lacks selected source")
    expected_family = {"observed": "observed", "reported": "reported",
                       "authored": "authored", "simulated": "simulated",
                       "internal": "derived"}[evidence.source_kind]
    expected_reality = {"observed": "external_observation",
                        "reported": "external_report",
                        "authored": "authored_content", "simulated": "simulation",
                        "internal": "inference"}[evidence.source_kind]
    if (source_qualification.source_family != expected_family
            or source_qualification.content_reality != expected_reality
            or source_qualification.occurred_at != evidence.occurred_at
            or source_qualification.learned_at != evidence.learned_at
            or (source_qualification.evidence_eligibility == "eligible"
                and (evidence.source_kind != "observed"
                     or evidence.assertion_status != "confirmed"))):
        raise ValueError("C04 source qualification changes provenance or time")
    if (evidence.record.source_id != selected.content_ref
            or evidence.record.text != evidence.text
            or evidence.record.source_kind != evidence.source_kind
            or evidence.record.assertion_status != evidence.assertion_status):
        raise ValueError("C04 source evidence differs from selected record")
    if any(version not in evidence_page.read_versions
           for version in evidence.read_versions):
        raise ValueError("C04 source closure lacks a current read version")
    hit = MemoryHit(
        AtomKey.from_token(evidence.source_ref), evidence.record,
        evidence.read_versions, (evidence.provenance_root,), (evidence.record,),
    )
    view = prepare_affective_recollection_view(
        ticket=ticket, candidates=candidates, hit=hit,
        mood_snapshot=mood_snapshot, mood_key=mood_key,
        scheme=scheme, coupling=coupling,
        source_qualification=source_qualification,
        base_salience=base_salience, base_tone=base_tone,
        purpose=evidence.purpose,
    )
    proposal = D06DomainAdapter(namespace).prepare_recollection(
        ticket, candidates, context,
    )
    reconstruction = reconstruct_recollection_candidate(
        proposal=proposal, view=view, detail_cues=detail_cues,
    )
    versions = tuple(sorted(set(view.read_versions),
                            key=lambda item: item.key.token))
    if any(version not in versions for version in evidence.read_versions):
        raise ValueError("C04 lost an ancestor source/access/correction version")
    return CurrentC04SourceCandidateV1(
        proposal, view, reconstruction, versions, evidence_page.graph_epoch,
        evidence_page.query_coverage.query_epoch,
        evidence_page.access_epoch, evidence_page.deletion_epoch,
    )


__all__ = ["CurrentC04SourceCandidateV1", "prepare_current_c04_source_candidate_v1"]
