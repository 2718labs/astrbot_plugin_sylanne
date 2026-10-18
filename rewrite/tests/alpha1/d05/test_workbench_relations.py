import pytest

from sylanne3.domain_registry import discover_domain_registry
from sylanne3.domains.d05 import RelationshipProvider
from sylanne3.domains.d05.relationship import RELATIONSHIP_WORKBENCH_TYPES_V2
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
        authority.activation_generation, "relations", RELATIONSHIP_WORKBENCH_TYPES_V2,
        "relation", audience, "context", _seal=_COMPLETE_PROJECTION_SEAL,
    )
    return ProjectionContextV2(authority, audience, "context", proof)


def atom(subject="entity:alice", dimension="trust:work", status="unknown", *, persona="persona", qualification="unknown"):
    key = AtomKey(Owner("relation", "bot", persona, subject),
                  "d05.relationship_projection", dimension)
    return {"key": key.token, "type": key.type_name, "name": key.name,
            "revision": 1,
            "value": {"subject_entity_ref": subject, "dimension": dimension,
                      "status": status, "schema_version": 2,
                      "source_qualification": "unavailable" if status == "held_source_correction" else qualification,
                      "estimate": "unknown", "influence_status": "not_evaluated"}}


def test_relations_contract_projects_only_committed_subjective_statuses():
    registry = CurrentDomainViewRegistry(discover_domain_registry)
    ctx = context()
    assert registry.view_types(ctx.authority)["relations"] == RELATIONSHIP_WORKBENCH_TYPES_V2
    result = registry.project_workbench(
        ctx.authority, "relations", (atom("entity:bob", status="unavailable"), atom()),
        audience=ctx.audience, purpose=ctx.purpose, snapshot_proof=ctx.snapshot_proof,
    )
    assert result["coverage"] == "complete"
    assert [item["subject_entity_ref"] for item in result["relations"]] == ["entity:alice", "entity:bob"]
    assert [item["dimensions"][0]["availability"] for item in result["relations"]] == ["unknown", "unavailable"]
    assert all(item["dimensions"][0]["estimate"] == "unknown" for item in result["relations"])
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
    unavailable = RelationshipProvider.project_workbench("relations", (atom(status="private source words"),), context=ctx)
    diagnostic = unavailable["relations"][0]["dimensions"][0]
    assert diagnostic["availability"] == "unavailable"
    assert diagnostic["diagnostic_error"] == "unregistered_legacy_relationship_state"
    assert "private source words" not in str(diagnostic)


@pytest.mark.parametrize("internal,public", [
    ("source_qualified", "available"),
    ("held_source_correction", "blocked_rebuild"),
    ("unknown", "unknown"), ("available", "available"),
    ("unavailable", "unavailable"), ("stale", "stale"),
    ("blocked_rebuild", "blocked_rebuild"), ("rebuilt", "rebuilt"),
    ("sanitized", "sanitized"), ("reset", "reset"),
])
def test_production_statuses_use_the_same_finite_validator_and_public_mapping(internal, public):
    ctx = context()
    projection = atom(status=internal, qualification="qualified")
    spec = next(spec for spec in RelationshipProvider().type_specs()
                if spec.name == "d05.relationship_projection")
    spec.validator(projection["value"])
    result = RelationshipProvider.project_workbench("relations", (projection,), context=ctx)
    dimension = result["relations"][0]["dimensions"][0]
    assert dimension["status"] == dimension["availability"] == public
    assert dimension["estimate"] == "unknown"
    assert "trust" not in dimension and "repair_complete" not in dimension
    with pytest.raises(ValueError, match="public status token"):
        spec.validator({**projection["value"], "status": "unregistered_private_state"})


def test_legacy_exact_codec_does_not_grant_qualification_or_fabricate_activity():
    from dataclasses import asdict
    from sylanne3.domains.d05.relationship import (
        decode_relationship_contribution_payload_v1, translate_relationship_contribution_v2,
        decode_relationship_projection_payload_v1, translate_relationship_projection_v2,
        relationship_projection_public_v2,
    )
    old = {"owner_persona_ref": "persona:persona", "canonical_event_or_family_ref": "family:one",
        "subject_entity_ref": "entity:alice", "target_dimension": "trust:work", "semantics": "recollection",
        "contribution_revision": 2, "source_refs": ["source:one"]}
    prior = decode_relationship_contribution_payload_v1(old)
    legacy_key = AtomKey(Owner("relation", "bot", "persona", "entity:alice"), "d05.contribution", prior.key)
    converted = translate_relationship_contribution_v2(old, legacy_alias_keys=(legacy_key.token,))
    assert converted.schema_version == 2 and converted.kind == "internal_recollection"
    assert converted.recollection_activity_ref is None and converted.identity_status == "legacy_unresolved"
    assert converted.key == prior.key and converted.contribution_revision == prior.contribution_revision
    assert translate_relationship_contribution_v2(asdict(converted)) == converted
    with pytest.raises(ValueError, match="exact schema"):
        decode_relationship_contribution_payload_v1({**old, "invented_delta": 0.5})
    old_projection = {"subject_entity_ref": "entity:alice", "dimension": "trust:work", "status": "pending_bounded_reevaluation"}
    assert decode_relationship_projection_payload_v1(old_projection) == old_projection
    projected = translate_relationship_projection_v2(old_projection)
    assert projected["source_qualification"] == "unknown" and projected["influence_status"] == "unapplied_pending"
    assert relationship_projection_public_v2(projected)["availability"] == "unavailable"
    unknown = {**old_projection, "status": "private legacy status text"}
    public = relationship_projection_public_v2(unknown)
    assert public["availability"] == "unavailable" and public["diagnostic_error"] == "unregistered_legacy_relationship_state"
    assert "private legacy status text" not in str(public)
    with pytest.raises(ValueError, match="exact shape"):
        decode_relationship_projection_payload_v1({**old_projection, "unregistered_field": True})


def test_schema_migration_preserves_invalid_legacy_head_and_consumption_alias():
    """Pure synthetic codec fixture; no Authority/C04 receipt or upgrade PASS."""
    from sylanne3.domains.d05.relationship import decode_relationship_contribution_payload_v1, translate_d05_current_heads_v2
    from sylanne3.graph_types import GraphAtom, GraphSnapshot
    from sylanne3.memory_types import SourceRecord, source_key, access_key
    from sylanne3.domains.d06 import source_correction_head_key
    ns = NamespaceId("bot", "persona")
    source = source_key(*ns.as_tuple, "one")
    old = {"owner_persona_ref": "persona:persona", "canonical_event_or_family_ref": "family:one",
        "subject_entity_ref": "entity:alice", "target_dimension": "trust:work", "semantics": "recollection",
        "contribution_revision": 2, "source_refs": [source.token]}
    prior = decode_relationship_contribution_payload_v1(old)
    key = AtomKey(Owner("relation", *ns.as_tuple, "entity:alice"), "d05.contribution", prior.key)
    snapshot = GraphSnapshot((GraphAtom(key, 3, old, False),
        GraphAtom(source, 1, SourceRecord("one", "synthetic codec material", "alice", "observed", "confirmed",
            1.0, 2.0, "family:one", ("owner",), ("audit",)).to_dict()),
        GraphAtom(access_key(*ns.as_tuple, "one"), 1, {"source_id": "one", "audiences": ["owner"],
            "purposes": ["audit"], "status": "active", "recorded_at": 2.0}),
        GraphAtom(source_correction_head_key(ns, "one"), 0, {}, False)), (NamespaceEpoch(*ns.as_tuple, 3),))
    args = {"legacy_consumed_keys": (key.token,),
        "source_catalogue_hash": "6a05fc901a3c45696faaab63746a6bf795db79282c6be7fdc8bffb6c228a71d1"}
    plan = translate_d05_current_heads_v2(snapshot, ns, (key.token,), **args)
    assert plan.current_validity == ((key.token, False),)
    assert plan.aliases == ((key.token, key.token, True),)
    assert plan.writes[0].value["identity_status"] == "legacy_unresolved"
    assert plan.writes[0].value["recollection_activity_ref"] is None
    assert plan == translate_d05_current_heads_v2(snapshot, ns, (key.token,), **args)
    with pytest.raises(ValueError, match="catalogue"):
        translate_d05_current_heads_v2(snapshot, ns, (key.token,), source_catalogue_hash="f" * 64)


@pytest.mark.parametrize("now,status", [(None,"unknown"),(10.0,"available"),(20.0,"stale")])
def test_current_v2_estimate_uses_scoped_context_digest_and_real_time_boundary(now,status):
    from dataclasses import replace
    from sylanne3.domains.d05.relationship_revision_v2 import (
        RelationshipScopeV2, DimensionEstimateV2, ESTIMATE_TYPE,
    )
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.graph_types import GraphVersion
    from sylanne3.runtime_contracts import canonical_digest

    ctx=replace(context(),trusted_now_utc=now)
    subject=AtomKey(Owner("persona","bot","persona"),"d03.entity_anchor","entity:alice")
    scope=RelationshipScopeV2(ctx.authority.namespace,GraphVersion(subject,2),None,
        "work","installed:private-work-context","trust","dimension-schema:1")
    current=DimensionEstimateV2(scope,0.25,0.6,"partial",(),(),(),(),(),
        "checkpoint:1",(),(),0.0,"policy:1","a"*64,(),1.0,20.0,(),"current")
    key=scope.key(ESTIMATE_TYPE)
    row={"key":key.token,"type":ESTIMATE_TYPE,"name":key.name,"revision":1,"value":plain_v1(current)}
    result=RelationshipProvider.project_workbench("relations",(row,),context=ctx)
    dimension=result["relations"][0]["dimensions"][0]
    assert dimension["context_id"]==canonical_digest((scope.relationship_domain,scope.context_ref))[:32]
    assert dimension["availability"]==status
    assert dimension["estimate"]==(0.25 if status=="available" else"unknown")
    assert scope.context_ref not in repr(result)


@pytest.mark.parametrize("source_purposes,access_purposes,status,correction,expected",[
    (("audit",),("audit",),"active",0,True),
    (("consolidation",),("audit",),"active",0,False),
    (("audit",),("context",),"active",0,False),
    (("audit",),("audit",),"withdrawn",0,False),
    (("audit",),("audit",),"active",1,False),
])
def test_catalogue_migration_requires_audit_on_source_and_access(source_purposes,access_purposes,status,correction,expected):
    from sylanne3.domains.d05.relationship import _migration_source_qualification_v2
    from sylanne3.graph_types import GraphAtom,GraphSnapshot
    from sylanne3.memory_types import SourceRecord,source_key,access_key
    from sylanne3.domains.d06 import source_correction_head_key
    ns=NamespaceId("bot","persona");source=source_key(*ns.as_tuple,"one")
    record=SourceRecord("one","audit-only fixture","alice","observed","confirmed",1.0,2.0,
        "family:one",("owner",),source_purposes)
    snapshot=GraphSnapshot((GraphAtom(source,1,record.to_dict()),
        GraphAtom(access_key(*ns.as_tuple,"one"),1,{"source_id":"one","audiences":["owner"],
            "purposes":list(access_purposes),"status":status,"recorded_at":2.0}),
        GraphAtom(source_correction_head_key(ns,"one"),correction,{},False)),(NamespaceEpoch(*ns.as_tuple,3),))
    qualified,reads=_migration_source_qualification_v2(snapshot,ns,(source.token,))
    assert qualified is expected
    assert set(reads)=={source,access_key(*ns.as_tuple,"one"),source_correction_head_key(ns,"one")}
