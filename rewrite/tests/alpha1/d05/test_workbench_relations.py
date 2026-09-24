import pytest

from sylanne3.domain_registry import discover_domain_registry
from sylanne3.domains.d05 import RelationshipProvider
from sylanne3.graph_coordinator import CompleteProjectionSnapshotV1, _COMPLETE_PROJECTION_SEAL
from sylanne3.graph_types import AtomKey, NamespaceEpoch, Owner
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId
from sylanne3.workbench_api.domain_registry import (
    CurrentDomainViewRegistry, ProjectionContextV1, ProjectionContextV2,
)


def context(*, audience="owner"):
    authority = AuthorityContext(
        "actor", "d12", "capability", NamespaceId("bot", "persona"),
        ("relation",), "context", (audience,), "policy", 3,
    )
    proof = CompleteProjectionSnapshotV1(
        authority.namespace, NamespaceEpoch("bot", "persona", 1),
        authority.activation_generation, "relations", ("d05.relationship_projection",),
        "relation", audience, "context", _seal=_COMPLETE_PROJECTION_SEAL,
    )
    return ProjectionContextV2(authority, audience, "context", proof)


def atom(subject="entity:alice", dimension="trust:work", status="unknown", *, persona="persona"):
    key = AtomKey(Owner("relation", "bot", persona, subject),
                  "d05.relationship_projection", dimension)
    return {"key": key.token, "type": key.type_name, "name": key.name,
            "revision": 1,
            "value": {"subject_entity_ref": subject, "dimension": dimension,
                      "status": status}}


def test_relations_contract_projects_only_committed_subjective_statuses():
    registry = CurrentDomainViewRegistry(discover_domain_registry)
    ctx = context()
    assert registry.view_types(ctx.authority)["relations"] == ("d05.relationship_projection",)
    result = registry.project_workbench(
        ctx.authority, "relations", (atom("entity:bob", status="unavailable"), atom()),
        audience=ctx.audience, purpose=ctx.purpose, snapshot_proof=ctx.snapshot_proof,
    )
    assert result == {"relations": [
        {"subject_entity_ref": "entity:alice", "dimensions": [
            {"dimension": "trust:work", "status": "unknown"}]},
        {"subject_entity_ref": "entity:bob", "dimensions": [
            {"dimension": "trust:work", "status": "unavailable"}]},
    ], "coverage": "complete"}
    assert RelationshipProvider.project_workbench("relations", (), context=ctx) == {
        "relations": [], "coverage": "complete"}


def test_relations_requires_complete_proof_and_exact_graph_owner():
    ctx = context()
    with pytest.raises(ValueError, match="unsupported D05 workbench projection context"):
        RelationshipProvider.project_workbench(
            "relations", (atom(),),
            context=ProjectionContextV1(ctx.authority, ctx.audience, ctx.purpose),
        )
    with pytest.raises(ValueError, match="graph scope"):
        RelationshipProvider.project_workbench("relations", (atom(persona="other"),), context=ctx)
    wrong_subject = atom()
    wrong_subject["value"] = {**wrong_subject["value"], "subject_entity_ref": "entity:bob"}
    with pytest.raises(ValueError, match="graph Owner"):
        RelationshipProvider.project_workbench("relations", (wrong_subject,), context=ctx)


def test_relations_does_not_accept_boundary_or_contribution_atoms():
    ctx = context()
    boundary = atom()
    boundary["type"] = "d05.boundary_rule"
    with pytest.raises(ValueError, match="graph scope"):
        RelationshipProvider.project_workbench("relations", (boundary,), context=ctx)
    with pytest.raises(ValueError, match="duplicate relationship dimension"):
        RelationshipProvider.project_workbench("relations", (atom(), atom()), context=ctx)
    with pytest.raises(ValueError, match="public status token"):
        RelationshipProvider.project_workbench(
            "relations", (atom(status="private source words"),), context=ctx,
        )
