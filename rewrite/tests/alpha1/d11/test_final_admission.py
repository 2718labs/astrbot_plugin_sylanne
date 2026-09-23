"""Final D11 inspection must reject a grant revoked after candidate creation."""

from dataclasses import replace

from sylanne3.domains.d11 import assess_final_admission
from sylanne3.domains.d08 import ActionIntent, GoalPredicate, RequiredCheckSpec
from sylanne3.graph_types import GraphAtom, GraphSnapshot, NamespaceEpoch
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.dispatch_candidate import DispatchCandidateEvidenceV1
from sylanne3.runtime_contracts import (
    NamespaceId, OperationIdentity, VersionedRef, canonical_digest,
)


def _source(source_id: str, parents: tuple[str, ...] = ()) -> tuple[GraphAtom, GraphAtom]:
    source = SourceRecord(
        source_id, "remembered fact", "speaker", "reported", "reported",
        1.0, 2.0, "family", ("entity:alice",), ("expression",), parents,
    )
    return (
        GraphAtom(source_key("bot", "persona", source_id), 1, source.to_dict()),
        GraphAtom(access_key("bot", "persona", source_id), 1, {
            "source_id": source_id, "audiences": ["entity:alice"],
            "purposes": ["expression"], "status": "active", "recorded_at": 2.0,
        }),
    )


def _case():
    atoms = _source("child", ("parent",)) + _source("parent")
    source_ref = atoms[0].key.token
    spec = RequiredCheckSpec(
        "source_grant", "d06.source_grant", "persona:persona", "action:send",
        "respond", source_ref,
        tuple(VersionedRef(atom.key.token, atom.revision) for atom in atoms),
    )
    intent = ActionIntent(
        "action:send", 1, "goal:send", (), "entity:alice", "message", "respond",
        "reversible", "0" * 64,
        OperationIdentity("activity:send", "effect:send", "attempt:1", "prepare",
                          "operation:send", canonical_digest({"input": source_ref})),
        "schema:send", (spec,),
        GoalPredicate("communicated", "d11.delivery", (), 0.0, None),
        ("message:alice",), None, (source_ref,),
    )
    proof = [(atom.key.token, atom.revision, canonical_digest(atom.value))
             for atom in atoms]
    candidate = DispatchCandidateEvidenceV1(
        intent.identity.operation_id, "action_ref", "schema_ref", "grant_ref",
        "batch_ref", canonical_digest(intent), "schema_digest", "grant_digest",
        "batch_digest", intent.source_refs,
        ((atoms[0].key.token, 1),), ((atoms[1].key.token, 1),),
        1, 1, 7, "source_qualified", ("entity:alice",),
        tuple((ref, revision) for ref, revision, _ in proof), canonical_digest(proof),
    )
    snapshot = GraphSnapshot(atoms, (NamespaceEpoch("bot", "persona", 8),))
    return candidate, intent, snapshot


def _assess(candidate, intent, snapshot):
    return assess_final_admission(
        candidate, intent, snapshot, namespace=NamespaceId("bot", "persona"),
        audience=("entity:alice",), batch_audience=("entity:alice",),
        current_barrier_confirmed=True, owner_guard=None, role_binding=None,
        now_utc=5.0,
    )


def test_candidate_is_still_hold_without_atomic_final_claim_port():
    candidate, intent, snapshot = _case()
    result = _assess(candidate, intent, snapshot)
    assert result.status == "hold"
    assert "source.current_versions" not in result.missing
    assert "source.current_content" not in result.missing
    assert "source.current_ancestry_access" not in result.missing
    assert "graph.atomic_final_claim_port" in result.missing


def test_parent_access_revoked_between_candidate_and_final_read():
    candidate, intent, snapshot = _case()
    old_access = snapshot.atoms[3]
    revoked = replace(old_access, revision=2,
                      value={**old_access.value, "status": "withdrawn"})
    current = replace(snapshot, atoms=(*snapshot.atoms[:3], revoked),
                      epochs=(NamespaceEpoch("bot", "persona", 9),))
    result = _assess(candidate, intent, current)
    assert result.status == "hold"
    assert "source.current_versions" in result.missing


def test_same_revision_content_change_and_removed_ancestor_fail_closed():
    candidate, intent, snapshot = _case()
    old_access = snapshot.atoms[3]
    changed = replace(old_access, value={**old_access.value, "status": "withdrawn"})
    assert "source.current_content" in _assess(
        candidate, intent, replace(snapshot, atoms=(*snapshot.atoms[:3], changed)),
    ).missing
    assert "source.current_versions" in _assess(
        candidate, intent, replace(snapshot, atoms=snapshot.atoms[:2]),
    ).missing
