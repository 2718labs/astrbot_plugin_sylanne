"""Read-only D04 impact decision for a committed D06 source correction.

This does not mutate a feeling, retract a historical experience, or grant a
numeric certificate. W01 must prove the snapshot is complete and current,
then atomically fence affected current readouts before scheduling recompute.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import SourceRecord
from ..d06 import validate_source_correction_head
from .affect import (
    _decode_appraisal, _decode_feeling, _decode_mood,
    _decode_recollection_experience,
)


@dataclass(frozen=True, slots=True)
class D04SourceReevaluationCandidate:
    old_source: GraphVersion
    correction_source: GraphVersion
    correction_head: GraphVersion
    learned_at: float
    suppressed_contribution_keys: tuple[str, ...]
    affected_appraisal_refs: tuple[str, ...]
    blocked_current_feeling_refs: tuple[str, ...]
    blocked_current_mood_refs: tuple[str, ...]
    blocked_current_recollection_refs: tuple[str, ...]
    preserved_historical_feeling_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]
    required_recomputations: tuple[str, ...] = (
        "appraisal", "mechanism_drive", "feeling_readout", "mood_readout",
        "recollection_readout",
    )
    status: str = "proposal_requires_w01_current_snapshot_and_atomic_fence"


def compile_d04_source_reevaluation(
    snapshot: GraphSnapshot, *, correction_head_ref: str,
) -> D04SourceReevaluationCandidate:
    """Derive affected current D04 views from supplied graph atoms.

    A GraphSnapshot alone does not prove a complete authoritative read. W01
    must compare the listed revisions and graph epoch under its read fence,
    prove query coverage, and block these views before any old drive is reused.
    """
    if type(snapshot) is not GraphSnapshot:
        raise TypeError("source reevaluation requires GraphSnapshot")
    head_key = AtomKey.from_token(correction_head_ref)
    if (head_key.type_name != "d06.source_correction_head.v1"
            or head_key.owner.kind != "event" or head_key.name != "current"):
        raise ValueError("correction head ref differs from D06 contract")
    namespace = (head_key.owner.bot, head_key.owner.persona)
    if (len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace
            or snapshot.epochs[0].revision < 1):
        raise ValueError("correction snapshot lacks one matching namespace epoch")
    atoms = {atom.key: atom for atom in snapshot.atoms}
    if len(atoms) != len(snapshot.atoms) or any(
        (key.owner.bot, key.owner.persona) != namespace for key in atoms
    ):
        raise ValueError("correction snapshot contains duplicate or cross-namespace atoms")
    head = atoms.get(head_key)
    if head is None or not head.valid or head.revision < 1:
        raise ValueError("current D06 correction head is absent")
    validate_source_correction_head(head.key, head.value)
    old_key = AtomKey.from_token(head.value["source_ref"])
    new_key = AtomKey.from_token(head.value["correction_source_ref"])
    old = atoms.get(old_key)
    new = atoms.get(new_key)
    if (old is None or new is None or not old.valid or not new.valid
            or old.revision != head.value["source_revision"] or new.revision < 1):
        raise ValueError("D06 source versions differ from correction head")
    old_record = SourceRecord.from_dict(old.value)
    new_record = SourceRecord.from_dict(new.value)
    if (old_record.source_id != old_key.owner.subject
            or new_record.source_id != new_key.owner.subject
            or old_record.source_id not in new_record.parent_source_ids
            or new_record.provenance_root != "owner.correction.v1"
            or new_record.source_kind != "reported"):
        raise ValueError("correction source provenance differs from D06 contract")

    affected_appraisals: list[str] = []
    contributions: set[str] = set()
    feelings: list[str] = []
    moods: list[str] = []
    recollections: list[str] = []
    selected: dict[AtomKey, GraphVersion] = {
        item.key: GraphVersion(item.key, item.revision) for item in (head, old, new)
    }
    targets = set(head.value["target_refs"])
    for atom in snapshot.atoms:
        if not atom.valid or atom.revision < 1:
            continue
        kind = atom.key.type_name
        if kind == "d04.appraisal_bundle.v1":
            appraisal = _decode_appraisal(atom.value)
            if (old_key.token in appraisal.source_refs
                    or targets.intersection(appraisal.competing_interpretation_refs)
                    or any(facet.interpretation_ref in targets
                           for facet in appraisal.meaning_facets)):
                affected_appraisals.append(atom.key.token)
                contributions.add(appraisal.contribution_key)
                selected[atom.key] = GraphVersion(atom.key, atom.revision)
    affected_mood_ids: set[str] = set()
    for atom in snapshot.atoms:
        if not atom.valid or atom.revision < 1:
            continue
        kind = atom.key.type_name
        if kind == "d04.feeling_state.v1":
            feeling = _decode_feeling(atom.value)
            if (contributions.intersection(feeling.active_driver_refs)
                    or old_key.token in feeling.historical_source_refs
                    or targets.intersection(feeling.interpretation_refs)):
                feelings.append(atom.key.token)
                selected[atom.key] = GraphVersion(atom.key, atom.revision)
        elif kind == "d04.mood_field.v1":
            mood = _decode_mood(atom.value)
            if old_key.token in mood.source_refs:
                moods.append(atom.key.token)
                affected_mood_ids.add(mood.mood_id)
                selected[atom.key] = GraphVersion(atom.key, atom.revision)
    for atom in snapshot.atoms:
        if (not atom.valid or atom.revision < 1
                or atom.key.type_name != "d04.recollection_experience.v1"):
            continue
        experience = _decode_recollection_experience(atom.value)
        if (old_key.token in experience.memory_source_refs
                or old_key.token in experience.mood_source_refs
                or experience.mood_ref in affected_mood_ids):
            recollections.append(atom.key.token)
            selected[atom.key] = GraphVersion(atom.key, atom.revision)
    return D04SourceReevaluationCandidate(
        GraphVersion(old.key, old.revision), GraphVersion(new.key, new.revision),
        GraphVersion(head.key, head.revision), new_record.recorded_at,
        tuple(sorted(contributions)), tuple(sorted(affected_appraisals)),
        tuple(sorted(feelings)), tuple(sorted(moods)), tuple(sorted(recollections)),
        tuple(sorted(feelings)), tuple(selected[key] for key in sorted(selected, key=lambda key: key.token)),
    )


__all__ = ["D04SourceReevaluationCandidate", "compile_d04_source_reevaluation"]
