"""Held D05 relationship and boundary impact from a D06 source correction."""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import SourceRecord
from ..d06 import validate_source_correction_head
from .relationship import (BoundaryRule, RelationshipContribution, _tuple_payload,
    decode_relationship_projection_payload_v1, decode_relationship_contribution_payload_v1)


@dataclass(frozen=True, slots=True)
class D05SourceReevaluationCandidate:
    old_source: GraphVersion
    correction_source: GraphVersion
    correction_head: GraphVersion
    affected_current_rule_refs: tuple[str, ...]
    affected_contribution_refs: tuple[str, ...]
    blocked_projection_refs: tuple[str, ...]
    boundary_scopes_requiring_recheck: tuple[tuple[str, str, str, str, str | None], ...]
    preserved_historical_rule_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]
    status: str = "proposal_requires_w01_current_snapshot_and_boundary_hold"


def compile_d05_source_reevaluation(
    snapshot: GraphSnapshot, *, correction_head_ref: str,
) -> D05SourceReevaluationCandidate:
    """Inspect supplied current atoms; W01 still must prove complete fenced scope."""
    if type(snapshot) is not GraphSnapshot:
        raise TypeError("D05 source reevaluation requires GraphSnapshot")
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
            or correction.source_kind != "reported"):
        raise ValueError("correction source provenance differs from D06 contract")
    affected = {old_key.token, *head.value["target_refs"]}
    selected = {
        atom.key: GraphVersion(atom.key, atom.revision) for atom in (head, old, new)
    }
    current_rules: list[str] = []
    historical_rules: list[str] = []
    contributions: list[str] = []
    scopes: set[tuple[str, str, str, str, str | None]] = set()
    relations: set[tuple[str, str]] = set()
    for atom in snapshot.atoms:
        if atom.revision < 1:
            continue
        if atom.key.type_name == "d05.boundary_rule":
            rule = BoundaryRule(**_tuple_payload(
                atom.value, "source_refs", "communicated_refs", "acknowledged_refs", "exception_refs"))
            if atom.key.owner.kind != "relation" or atom.key.owner.subject != rule.target_entity_ref:
                raise ValueError("D05 boundary rule graph owner differs")
            if affected.intersection(rule.source_refs):
                historical_rules.append(atom.key.token)
                selected[atom.key] = GraphVersion(atom.key, atom.revision)
                if atom.valid and rule.status == "active":
                    current_rules.append(atom.key.token)
                    scopes.add((rule.subject_persona_ref, rule.target_entity_ref,
                                rule.action_kind, rule.audience_scope, rule.scene_ref))
        elif atom.key.type_name == "d05.contribution":
            item = decode_relationship_contribution_payload_v1(atom.value)
            if (atom.key.owner.kind != "relation" or atom.key.owner.subject != item.subject_entity_ref
                    or atom.key.name != item.key):
                raise ValueError("D05 contribution graph identity differs")
            if affected.intersection(item.source_refs):
                contributions.append(atom.key.token)
                relations.add((item.subject_entity_ref, item.target_dimension))
                selected[atom.key] = GraphVersion(atom.key, atom.revision)
    projections: list[str] = []
    for atom in snapshot.atoms:
        if (atom.revision < 1
                or atom.key.type_name != "d05.relationship_projection"):
            continue
        value = decode_relationship_projection_payload_v1(atom.value)
        if (atom.key.owner.kind != "relation" or type(value) is not dict
                or atom.key.owner.subject != value["subject_entity_ref"]):
            raise ValueError("D05 relationship projection graph identity differs")
        if (value["subject_entity_ref"], value["dimension"]) in relations:
            projections.append(atom.key.token)
            selected[atom.key] = GraphVersion(atom.key, atom.revision)
    return D05SourceReevaluationCandidate(
        GraphVersion(old.key, old.revision), GraphVersion(new.key, new.revision),
        GraphVersion(head.key, head.revision), tuple(sorted(current_rules)),
        tuple(sorted(contributions)), tuple(sorted(projections)),
        tuple(sorted(scopes, key=repr)), tuple(sorted(historical_rules)),
        tuple(selected[key] for key in sorted(selected, key=lambda key: key.token)),
    )


__all__ = ["D05SourceReevaluationCandidate", "compile_d05_source_reevaluation"]
