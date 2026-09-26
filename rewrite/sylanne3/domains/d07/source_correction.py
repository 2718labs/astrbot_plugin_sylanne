"""Held D07 interpretation and belief reevaluation after D06 correction."""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import InterpretationRecord, SourceRecord
from ..d06 import validate_source_correction_head
from . import (
    BeliefRevision, CurrentInterpretationCandidate, _graph_validator,
)


@dataclass(frozen=True, slots=True)
class D07SourceReevaluationCandidate:
    old_source: GraphVersion
    correction_source: GraphVersion
    correction_head: GraphVersion
    retracted_interpretation_refs: tuple[str, ...]
    historical_belief_refs: tuple[str, ...]
    blocked_current_interpretation_refs: tuple[str, ...]
    question_keys_requiring_reevaluation: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]
    correction_evidence_status: str = "reported_claim_only"
    status: str = "proposal_requires_new_interpretation_evidence_and_w01_adoption"


def compile_d07_source_reevaluation(
    snapshot: GraphSnapshot, *, correction_head_ref: str,
) -> D07SourceReevaluationCandidate:
    """Inspect original source and invalidated beliefs without creating replacements."""
    if type(snapshot) is not GraphSnapshot:
        raise TypeError("D07 source reevaluation requires GraphSnapshot")
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
    old, new = atoms.get(old_key), atoms.get(new_key)
    if (old is None or new is None or not old.valid or not new.valid
            or old.revision != head.value["source_revision"] or new.revision < 1):
        raise ValueError("D06 source versions differ from correction head")
    original = SourceRecord.from_dict(old.value)
    correction = SourceRecord.from_dict(new.value)
    if (original.source_id != old_key.owner.subject
            or correction.source_id != new_key.owner.subject
            or original.source_id not in correction.parent_source_ids
            or correction.provenance_root != "owner.correction.v1"
            or correction.source_kind != "reported"
            or correction.assertion_status != "reported"):
        raise ValueError("correction source cannot claim independent observation")
    selected = {atom.key: GraphVersion(atom.key, atom.revision) for atom in (head, old, new)}
    targets = set(head.value["target_refs"])
    retracted: list[str] = []
    for ref in sorted(targets):
        key = AtomKey.from_token(ref)
        atom = atoms.get(key)
        if atom is None or not atom.valid or atom.revision < 1:
            raise ValueError("correction target interpretation is absent")
        record = InterpretationRecord.from_dict(atom.value)
        if (record.interpretation_id != key.owner.subject
                or record.status != "retracted"
                or original.source_id not in record.source_ids):
            raise ValueError("correction target is not a retracted old interpretation")
        retracted.append(ref)
        selected[key] = GraphVersion(key, atom.revision)
    belief_validator = _graph_validator(
        "d07.belief_revision.v1", BeliefRevision,
        ("eligibility", "source_refs", "source_families", "invalidation_refs"),
    )
    interpretation_validator = _graph_validator(
        "d07.current_interpretation.v1", CurrentInterpretationCandidate,
        ("source_refs", "source_families", "meaningful_unknowns"),
    )
    affected = {old_key.token, *targets}
    historical_beliefs: list[str] = []
    current_interpretations: list[str] = []
    questions: set[str] = set()
    for atom in snapshot.atoms:
        if not atom.valid or atom.revision < 1:
            continue
        if atom.key.type_name == "d07.belief_revision.v1":
            belief_validator(atom.value)
            value = atom.value
            if not affected.intersection(value["source_refs"]):
                continue
            if (atom.key.owner.kind != "persona" or atom.key.name != value["belief_id"]
                    or value["current"] or not value["historical"]
                    or value["invalidation_kind"] != "correction"
                    or new_key.token not in value["invalidation_refs"]
                    or not targets.issubset(value["invalidation_refs"])):
                raise ValueError("old dependent belief lacks committed correction invalidation")
            historical_beliefs.append(atom.key.token)
            questions.add(value["question_key"])
            selected[atom.key] = GraphVersion(atom.key, atom.revision)
        elif atom.key.type_name == "d07.current_interpretation.v1":
            interpretation_validator(atom.value)
            value = atom.value
            if affected.intersection(value["source_refs"]):
                current_interpretations.append(atom.key.token)
                questions.add(value["question_key"])
                selected[atom.key] = GraphVersion(atom.key, atom.revision)
    if not historical_beliefs:
        raise ValueError("correction snapshot lacks an invalidated dependent belief")
    return D07SourceReevaluationCandidate(
        GraphVersion(old.key, old.revision), GraphVersion(new.key, new.revision),
        GraphVersion(head.key, head.revision), tuple(retracted),
        tuple(sorted(historical_beliefs)), tuple(sorted(current_interpretations)),
        tuple(sorted(questions)),
        tuple(selected[key] for key in sorted(selected, key=lambda key: key.token)),
    )


__all__ = ["D07SourceReevaluationCandidate", "compile_d07_source_reevaluation"]
