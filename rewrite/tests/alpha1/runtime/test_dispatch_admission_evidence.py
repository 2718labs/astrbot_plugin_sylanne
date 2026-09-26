"""D11 fact reads use actual graph rows and a held budget reservation."""

from dataclasses import asdict, replace
import json
import sqlite3

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.domains.d08 import ActionSchema, ActionSchemaRecord
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, D09ExpressionProvider, ExpressionClaim, SegmentCandidate,
)
from sylanne3.graph_coordinator import budget_operation_digest
from sylanne3.graph_types import AtomKey, GraphWrite, Owner
from sylanne3.runtime.budget import (
    BudgetLease, create_budget_lease, install_schema, reserve_budget,
)
from sylanne3.runtime.dispatch_admission_evidence import read_current_admission_facts
from sylanne3.runtime.dispatch_candidate import (
    qualify_dispatch_candidate_sources, validate_dispatch_candidate_writes,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, DomainBundle,
    DomainProposal, NamespaceId, QueryEpoch, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, VersionedRef, canonical_digest,
)

from test_dispatch_admission_preflight import _candidates
from test_dispatch_source_qualification import _case as _source_case


def _case():
    candidate_source, _, snapshot = _source_case()
    source_ref = candidate_source.source_refs[0]
    _, intent, _, _, _, grant = _candidates(
        source_ref=source_ref, include_grant=True,
    )
    identity = replace(
        intent.identity,
        canonical_input_digest=canonical_digest({"input_refs": []}),
    )
    pinned = tuple(VersionedRef(atom.key.token, atom.revision)
                   for atom in snapshot.atoms)
    specs = tuple(
        replace(spec, criteria_version=source_ref,
                required_input_versions=pinned)
        if spec.check_kind == "source_grant" else spec
        for spec in intent.required_checks
    )
    intent = replace(intent, identity=identity, required_checks=specs)
    schema = ActionSchemaRecord.bind(
        intent, ActionSchema("schema:one", "message", False, specs),
    )
    check_refs = tuple("check:" + canonical_digest({
        "kind": spec.check_kind, "provider": spec.provider_id,
        "subject": spec.subject_ref, "action": spec.action_ref,
        "purpose": spec.purpose, "criteria_version": spec.criteria_version,
        "input_versions": spec.required_input_versions,
    }) for spec in specs)
    grant = replace(
        grant, required_check_refs=check_refs,
        segment_grants=tuple(replace(segment, required_check_refs=check_refs)
                             for segment in grant.segment_grants),
    )
    use = ClaimUse("claim:one", 0, 5, ClaimKind.EXTERNAL_FACT)
    expression = D09ExpressionProvider()
    claims = (ExpressionClaim(
        "claim:one", "Hello", ClaimKind.EXTERNAL_FACT, (source_ref,),
        ("entity:user",), ("expression",), "disclosure:one",
    ),)
    blueprint = expression.prepare_blueprint(
        grant, "scene:one", 1, claims, now=1.0,
    ).blueprint
    assert blueprint is not None
    batch = expression.build_verified_batch_v1(
        grant, blueprint,
        (SegmentCandidate("segment:one", "effect:one", "Hello", (use,),
                          ("answer",), (), 0.0),), now=1.0,
    )
    namespace = NamespaceId("bot", "persona")
    owner = Owner("activity", "bot", "persona", identity.activity_id)
    values = (
        ("d08", "d08.action_intent.v1", intent.action_id, intent),
        ("d08", "d08.action_schema.v1", schema.schema_ref, schema),
        ("d08", "d08.communication_intent_grant.v1", grant.grant_id, grant),
        ("d09", "d09.verified_segment_batch.v1", batch["batch_id"], batch),
    )
    linked = tuple((domain, GraphWrite(
        AtomKey(owner, type_name, name),
        json.loads(json.dumps(asdict(value))) if not isinstance(value, dict)
        else value,
    )) for domain, type_name, name, value in values)
    authority = AuthorityContext(
        "host", "d06", "capability:one", namespace, ("activity",),
        "expression", ("entity:user",), "policy:one", 1,
    )
    guard = VersionGuard(
        snapshot.versions, (QueryEpoch(namespace, "all", 7),), 0, 0,
        "catalogue:one", "scheme:one", "operator:one", "policy:one",
        (), (), (),
    )
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA, identity, authority, guard,
        SourceQualification((source_ref,), "observed", 1.0, 2.0,
                            "external_observation", "eligible", 0.8,
                            "not_applicable"),
        (), "parent", 100.0, 100.0, "character:one", (),
    )
    proposals = tuple(DomainProposal(
        domain, f"{domain}.proposal.v1", "0" * 64,
        envelope, tuple(write for owner_domain, write in linked
                        if owner_domain == domain),
        DependencySet(), (), (),
    ) for domain in ("d08", "d09"))
    bundle = DomainBundle(envelope, proposals, (), (), (), (), (), (), ())
    candidate = validate_dispatch_candidate_writes(
        linked, namespace=namespace, identity=identity,
        read_versions=snapshot.versions,
        source_refs=(source_ref,), access_epoch=0, delete_epoch=0,
        query_epoch=7,
    )
    assert candidate is not None
    candidate = qualify_dispatch_candidate_sources(
        candidate, intent, snapshot, audience=authority.audience,
        batch_audiences=tuple(batch["audiences"]),
        current_barrier_confirmed=True, valid_until=batch["valid_until"],
    )
    assert candidate.status == "source_qualified"

    db = sqlite3.connect(":memory:", isolation_level=None)
    db.executescript("""
        CREATE TABLE graph_epochs(bot TEXT,persona TEXT,revision INTEGER);
        CREATE TABLE graph_atoms(token TEXT PRIMARY KEY,bot TEXT,persona TEXT,
                                 type_name TEXT,revision INTEGER,value TEXT,valid INTEGER);
        CREATE TABLE graph_authority_epochs(bot TEXT,persona TEXT,
                                             access_epoch INTEGER,delete_epoch INTEGER);
    """)
    db.execute("INSERT INTO graph_epochs VALUES('bot','persona',7)")
    for atom in snapshot.atoms:
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,1)", (
            atom.key.token, "bot", "persona", atom.key.type_name,
            atom.revision, canonical_json(atom.value),
        ))
    install_schema(db)
    create_budget_lease(
        db, BudgetLease("parent", None, "bot", "persona", "USD",
                        {"cpu_ms": 10}, {}, {}, {}, 1, "active"),
        "install-parent", "0" * 64,
    )
    return db, bundle, snapshot, candidate


def _reserve(db, bundle):
    envelope = bundle.envelope
    digest = budget_operation_digest(envelope, "parent", {"cpu_ms": 1})
    reserve_budget(db, "parent", envelope.identity.operation_id,
                   digest, {"cpu_ms": 1})
    return digest


def test_current_candidate_facts_stay_hold_after_real_reservation():
    db, bundle, snapshot, candidate = _case()
    try:
        db.execute("BEGIN IMMEDIATE")
        with pytest.raises(ValueError, match="reservation is absent"):
            read_current_admission_facts(
                db, bundle, snapshot, candidate, now_utc=2.0,
            )
        digest = _reserve(db, bundle)
        facts = read_current_admission_facts(
            db, bundle, snapshot, candidate, now_utc=2.0,
        )
        assert facts.status == "hold"
        assert facts.candidate_digest == candidate.digest
        assert facts.reservation_digest == digest
        assert facts.budget_ceiling == {"cpu_ms": 1}
        assert facts.d08_graph_facts.status == "hold"
        assert "d11.signed_grant_and_journal_fence" in facts.missing_sources
    finally:
        db.close()


def test_changed_graph_source_is_rejected_even_at_same_revision():
    db, bundle, snapshot, candidate = _case()
    try:
        db.execute("BEGIN IMMEDIATE")
        _reserve(db, bundle)
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                   ('{"changed":true}', candidate.source_refs[0]))
        with pytest.raises(ValueError, match="graph read changed"):
            read_current_admission_facts(
                db, bundle, snapshot, candidate, now_utc=2.0,
            )
    finally:
        db.close()
