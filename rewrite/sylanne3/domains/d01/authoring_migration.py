"""An authored persona edit has its own graph candidate, never a growth credit.

W01 must authenticate the Owner guard and D12 edit operation, then CAS every
read version under the same current graph epoch. No Authority is minted here.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from ...graph_types import GraphSnapshot, GraphVersion, GraphWrite, owner_grant_key
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import NamespaceId
from ..d06 import source_correction_head_key
from . import ContinuityRecord, PersonaDomain, PersonaPlan, PersonaRevision


@dataclass(frozen=True, slots=True)
class PersonaAuthoringMigrationCandidateV1:
    previous_head: str
    new_head: str
    administrative_source_ref: str
    revision: PersonaRevision
    typed_writes: tuple[GraphWrite, ...]
    read_versions: tuple[GraphVersion, ...]
    graph_epoch: int
    status: str = "candidate_requires_w01_owner_and_current_graph_adoption"


def compile_persona_authoring_migration(
    snapshot: GraphSnapshot, *, namespace: NamespaceId,
    current_guard: OwnerAuthorizationGuardV1, edited_plan: PersonaPlan,
    administrative_source_id: str,
) -> PersonaAuthoringMigrationCandidateV1:
    """One-block D12 edit; do not write a growth contribution or infer learning."""
    domain = PersonaDomain()
    active = domain.resolve_active_role(
        snapshot, namespace=namespace, current_guard=current_guard,
    )
    if (len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)
            or any((atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple
                   for atom in snapshot.atoms)):
        raise ValueError("administrative edit snapshot is ambiguous or crosses namespace")
    previous = active.plan
    if (type(edited_plan) is not PersonaPlan or edited_plan.namespace != namespace
            or edited_plan.plan_id != previous.plan_id
            or edited_plan.version != previous.version + 1
            or edited_plan.authored is not True
            or edited_plan.values != previous.values):
        raise ValueError("authored edit must advance one version of the same role plan")
    before = {block.block_id: block for block in previous.blocks}
    after = {block.block_id: block for block in edited_plan.blocks}
    changed = tuple(key for key in before if before[key] != after.get(key))
    if set(before) != set(after) or len(changed) != 1:
        raise ValueError("narrow authored migration must change exactly one existing block")
    source_key_value = source_key(*namespace.as_tuple, administrative_source_id)
    access_key_value = access_key(*namespace.as_tuple, administrative_source_id)
    head_key = source_correction_head_key(namespace, administrative_source_id)
    source_atom, access_atom, head_atom = (
        snapshot.get(source_key_value), snapshot.get(access_key_value), snapshot.get(head_key)
    )
    if (source_atom is None or access_atom is None or head_atom is None
            or not source_atom.valid or not access_atom.valid or head_atom.valid
            or source_atom.revision < 1 or access_atom.revision < 1
            or head_atom.revision != 0):
        raise ValueError("administrative edit source closure is unavailable")
    source = SourceRecord.from_dict(source_atom.value)
    validate_access(access_atom.value)
    access = access_atom.value
    if (source.source_id != administrative_source_id
            or source.source_kind != "authored" or source.assertion_status != "confirmed"
            or source.provenance_root != "administrative_edit"
            or source.parent_source_ids or "consolidation" not in source.purposes
            or "owner" not in source.audiences
            or access["source_id"] != administrative_source_id
            or access["status"] != "active"
            or "consolidation" not in access["purposes"]
            or "owner" not in access["audiences"]):
        raise ValueError("source is not a qualified administrative edit")
    revision = PersonaRevision(
        f"administrative_edit:{administrative_source_id}:{edited_plan.version}",
        previous.head_id, edited_plan.head_id, edited_plan.blocks,
        ContinuityRecord(
            previous.head_id,
            tuple(block.block_id for block in previous.blocks if block.block_id != changed[0]),
            changed[0], ("administrative_edit",),
        ),
    )
    grant = snapshot.get(owner_grant_key(*namespace.as_tuple))
    assert grant is not None  # resolve_active_role already checked the exact grant
    writes = (domain.plan_write(edited_plan), domain.revision_write(namespace, revision),
              domain.activation_write(edited_plan, grant, current_guard))
    revision_atom = snapshot.get(writes[1].key)
    if revision_atom is not None and revision_atom.valid:
        raise ValueError("administrative edit revision identity already exists")
    reads = active.read_versions + (
        GraphVersion(source_key_value, source_atom.revision),
        GraphVersion(access_key_value, access_atom.revision),
        GraphVersion(head_key, 0),
        GraphVersion(writes[1].key, revision_atom.revision if revision_atom else 0),
    )
    return PersonaAuthoringMigrationCandidateV1(
        previous.head_id, edited_plan.head_id, source_key_value.token,
        revision, writes, reads, active.graph_epoch,
    )


__all__ = ["PersonaAuthoringMigrationCandidateV1", "compile_persona_authoring_migration"]
