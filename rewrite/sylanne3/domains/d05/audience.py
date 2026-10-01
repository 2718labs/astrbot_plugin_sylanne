"""Audience qualification for one committed D05 relationship contribution.

This is a candidate over a supplied current graph snapshot.  W01/D11 owns the
fenced read and must recheck the source/access versions at use time.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import NamespaceId
from .relationship import RelationshipContribution, _tuple_payload


@dataclass(frozen=True)
class RelationshipAudienceQualification:
    status: str
    contribution_key: str | None
    read_versions: tuple[GraphVersion, ...]
    graph_epoch: int | None


def qualify_contribution_for_audience(
    snapshot: GraphSnapshot, contribution_key: str, *, namespace: NamespaceId,
    audience: str, purpose: str,
) -> RelationshipAudienceQualification:
    """Require every source of one contribution to permit this exact audience."""
    if not isinstance(snapshot, GraphSnapshot) or not isinstance(namespace, NamespaceId):
        raise TypeError("current graph snapshot and namespace are required")
    if not isinstance(contribution_key, str) or not contribution_key.startswith("contribution:"):
        raise ValueError("contribution key is required")
    if not isinstance(audience, str) or not audience:
        raise ValueError("audience is required")
    if not isinstance(purpose, str) or not purpose:
        raise ValueError("purpose is required")
    epoch = snapshot.epochs[0] if len(snapshot.epochs) == 1 else None
    unavailable = RelationshipAudienceQualification(
        "unavailable", None, (), epoch.revision if epoch is not None else None,
    )
    if (epoch is None or (epoch.bot, epoch.persona) != namespace.as_tuple):
        return unavailable
    if len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms):
        return unavailable
    candidates = tuple(atom for atom in snapshot.atoms
                       if atom.key.type_name == "d05.contribution"
                       and atom.key.name == contribution_key)
    if len(candidates) != 1:
        return unavailable
    atom = candidates[0]
    if (not atom.valid or atom.revision < 1 or atom.key.owner.kind != "relation"
            or (atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple):
        return unavailable
    try:
        contribution = RelationshipContribution(**_tuple_payload(atom.value, "source_refs"))
        if (contribution.owner_persona_ref != f"persona:{namespace.persona_id}"
                or contribution.subject_entity_ref != atom.key.owner.subject
                or contribution.key != contribution_key):
            return unavailable
        versions = [GraphVersion(atom.key, atom.revision)]
        for source_ref in contribution.source_refs:
            key = AtomKey.from_token(source_ref)
            if (key.type_name != "memory.source" or key.owner.kind != "event"
                    or (key.owner.bot, key.owner.persona) != namespace.as_tuple
                    or key != source_key(*namespace.as_tuple, key.owner.subject or "")):
                return unavailable
            source_atom = snapshot.get(key)
            access_atom = snapshot.get(access_key(*namespace.as_tuple, key.owner.subject or ""))
            if (source_atom is None or access_atom is None
                    or not source_atom.valid or not access_atom.valid
                    or source_atom.revision < 1 or access_atom.revision < 1):
                return unavailable
            source = SourceRecord.from_dict(source_atom.value)
            validate_access(access_atom.value)
            if (source.source_id != key.owner.subject
                    or access_atom.value["source_id"] != source.source_id
                    or access_atom.value["status"] != "active"
                    or audience not in source.audiences
                    or audience not in access_atom.value["audiences"]
                    or purpose not in source.purposes
                    or purpose not in access_atom.value["purposes"]):
                return unavailable
            versions.extend((GraphVersion(source_atom.key, source_atom.revision),
                             GraphVersion(access_atom.key, access_atom.revision)))
    except (KeyError, TypeError, ValueError):
        return unavailable
    return RelationshipAudienceQualification("eligible", contribution_key,
                                             tuple(versions), epoch.revision)
