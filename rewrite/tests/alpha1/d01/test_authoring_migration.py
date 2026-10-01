"""An administrative edit advances the plan without impersonating growth."""

from dataclasses import replace

import pytest

from sylanne3.domains.d01 import PersonaBlock, PersonaDomain
from sylanne3.domains.d01.authoring_migration import compile_persona_authoring_migration
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_types import GraphAtom
from sylanne3.memory_types import SourceRecord, access_key, source_key

from rewrite.tests.alpha1.d01.test_role_activation import NAMESPACE, _guard, _plan, _snapshot


def _case():
    source_id = "edit:one"
    source = SourceRecord(
        source_id, "owner edited one character setting", "owner", "authored",
        "confirmed", 1.0, 2.0, "administrative_edit", ("owner",),
        ("consolidation",), (), "unknown",
    )
    source_key_value = source_key(*NAMESPACE.as_tuple, source_id)
    access_key_value = access_key(*NAMESPACE.as_tuple, source_id)
    head_key = source_correction_head_key(NAMESPACE, source_id)
    base = _snapshot()
    snapshot = replace(base, atoms=base.atoms + (
        GraphAtom(source_key_value, 1, source.to_dict()),
        GraphAtom(access_key_value, 1, {
            "source_id": source_id, "audiences": ["owner"],
            "purposes": ["consolidation"], "status": "active", "recorded_at": 2.0,
        }),
        GraphAtom(head_key, 0, {}, False),
    ))
    edited = replace(_plan(), version=2, blocks=(
        PersonaBlock("identity", "semantic_identity", "authored and revised", "read_only"),
    ))
    return snapshot, edited, source_key_value, access_key_value, head_key


def _compile(snapshot, edited):
    return compile_persona_authoring_migration(
        snapshot, namespace=NAMESPACE, current_guard=_guard(),
        edited_plan=edited, administrative_source_id="edit:one",
    )


def test_authored_migration_has_distinct_provenance_and_current_graph_guards():
    snapshot, edited, source, access, head = _case()
    candidate = _compile(snapshot, edited)
    assert (candidate.previous_head, candidate.new_head) == ("chosen@1", "chosen@2")
    assert candidate.revision.continuity.source_families == ("administrative_edit",)
    assert {write.key.type_name for write in candidate.typed_writes} == {
        "d01.persona_plan.v1", "d01.persona_revision.v1", "d01.persona_activation.v1",
    }
    assert candidate.typed_writes[0].value["authored"] is True
    assert all(write.key.type_name != "d01.growth_contribution.v1"
               for write in candidate.typed_writes)
    assert {source, access, head} <= {version.key for version in candidate.read_versions}
    assert next(version.revision for version in candidate.read_versions
                if version.key == head) == 0
    assert candidate.graph_epoch == 3


def test_growth_cannot_be_faked_by_edit_or_corrected_source():
    snapshot, edited, source, access, head = _case()
    with pytest.raises(ValueError, match="one version"):
        _compile(snapshot, replace(edited, version=3))
    with pytest.raises(ValueError, match="one version"):
        _compile(snapshot, replace(edited, authored=False))
    old = snapshot.get(source)
    forged = replace(snapshot, atoms=tuple(
        replace(atom, value={**old.value, "source_kind": "observed"})
        if atom.key == source else atom for atom in snapshot.atoms
    ))
    with pytest.raises(ValueError, match="qualified administrative"):
        _compile(forged, edited)
    corrected = replace(snapshot, atoms=tuple(
        replace(atom, valid=True, revision=1) if atom.key == head else atom
        for atom in snapshot.atoms
    ))
    with pytest.raises(ValueError, match="closure"):
        _compile(corrected, edited)
    revoked = replace(snapshot, atoms=tuple(
        replace(atom, value={**atom.value, "status": "withdrawn"})
        if atom.key == access else atom for atom in snapshot.atoms
    ))
    with pytest.raises(ValueError, match="qualified administrative"):
        _compile(revoked, edited)
