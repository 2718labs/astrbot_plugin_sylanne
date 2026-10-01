"""Natural V2 social checks fail closed and read actual staged SQLite rows."""

import json
import sqlite3
from dataclasses import asdict, replace

import pytest

from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner, TypeRegistry,
)
from sylanne3.graph_store import GraphStore
from sylanne3.contracts import canonical_json
from sylanne3.domains.d03.context import AccountBinding, ContextProvider, RoleBinding
from sylanne3.domains.d05.relationship import BoundaryRule
from sylanne3.domains.d08.execution import ActionSchema, ActionSchemaRecord, RequiredCheckSpec
from sylanne3.domains.d08.natural_plan import natural_route_semantic_digest_v2
from sylanne3.domains.d09 import ClaimKind, ClaimUse, ExpressionClaim, SegmentCandidate, segment_payload_digest
from sylanne3.domains.d09.natural_batch import prepare_natural_verified_batch_proposal_v2
from sylanne3.domains.d09.natural_reply import NaturalFinalActionCandidateV2, NaturalFinalActionMaterialV2
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.natural_scoped_query_proof_v2 import NaturalPrivateScopeV2, read_natural_scoped_query_proof_v2
from sylanne3.runtime.reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.runtime_contracts import FenceScope, NamespaceId, QueryEpoch, VersionedRef, NaturalReplyPaidReviewReceiptV2, canonical_digest
from test_natural_final_admission_v2 import _case as natural_admission_case
from sylanne3.runtime.natural_prebatch_receipts_v2 import (
    _current_atom, issue_natural_pregrant_social_receipts_v2,
    issue_natural_prebatch_social_receipts_v2,
)


def test_staged_atom_must_equal_current_sqlite_value_and_revision():
    key = AtomKey(Owner("persona", "bot", "persona"), "d03.role_binding", "role:one")
    atom = GraphAtom(key, 2, {"policy": "private"})
    snapshot = GraphSnapshot((atom,), (NamespaceEpoch("bot", "persona", 2),))
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE graph_atoms (token TEXT, bot TEXT, persona TEXT, revision INTEGER, value TEXT, valid INTEGER)")
    db.execute("INSERT INTO graph_atoms VALUES (?,?,?,?,?,?)",
               (key.token, "bot", "persona", 2, json.dumps(atom.value), 1))
    assert _current_atom(db, snapshot, key) == atom
    db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
               (json.dumps({"policy": "public"}), key.token))
    with pytest.raises(ValueError, match="differs"):
        _current_atom(db, snapshot, key)
    db.close()


def test_untyped_or_unstaged_call_cannot_mint_social_receipts():
    db = sqlite3.connect(":memory:")
    result = issue_natural_prebatch_social_receipts_v2(
        db, None, None, None, None, None, None, None, None, None, None,
        now_utc=1.0, valid_until_utc=2.0)
    assert result.status == "hold"
    assert result.role_receipt is None and result.boundary_receipt is None
    assert not result.positive_reads and not result.negative_queries
    db.close()


def test_graphstore_staged_e_plus_one_issues_current_social_candidates(tmp_path):
    """The full current D03/D05 scan and both providers run on staged SQLite."""
    namespace = NamespaceId("bot", "persona")
    audience, scene, target = "conversation:private", "scene:private", "entity:account"
    graph = GraphStore(tmp_path / "natural-social.sqlite", TypeRegistry())
    db = graph._db
    source = source_key(*namespace.as_tuple, "source:question")
    access = access_key(*namespace.as_tuple, "source:question")
    account = AccountBinding("account:sender", "platform", "sender", target,
                             "verification:one", 0.0, None)
    account_key = AtomKey(Owner("persona", *namespace.as_tuple),
                          "d03.account_binding", account.account_id)
    role = RoleBinding("binding:private", "persona:persona", "friend", target,
                       None, scene, "private", "private", (), 0.0, None, 1,
                       (source.token,), 1, "active")
    role_key = AtomKey(Owner("scene", *namespace.as_tuple, scene),
                       "d03.role_binding", role.role_binding_id)
    rule = BoundaryRule("boundary:private", "persona:persona", target,
                        "communication", audience, scene, "allow",
                        "self_internal", (source.token,), (), (), 0.0, None,
                        1, "actor", (), "active")
    rule_key = AtomKey(Owner("relation", *namespace.as_tuple, target),
                       "d05.boundary_rule", rule.rule_id)
    record = SourceRecord("source:question", "Hello", "sender", "reported",
                          "reported", None, 1.0, "source:question", (audience,),
                          ("expression",))
    base_candidate, _, _ = natural_admission_case()
    base_intent = base_candidate.action_intent
    claim = ExpressionClaim("claim:hello", "Hello", ClaimKind.REPORTED_CLAIM,
                            (source.token,), (audience,), ("expression",), source.token)
    use = ClaimUse(claim.claim_id, 0, 5, ClaimKind.REPORTED_CLAIM)
    segment = SegmentCandidate("segment:hello", base_intent.identity.effect_id,
                               "Hello", (use,), ("reply",), (), 0.0)
    payload_digest = segment_payload_digest(segment.body, (), segment.claim_uses)
    paid = NaturalReplyPaidReviewReceiptV2(
        namespace, "original:gen", "call:gen", "1" * 64, "2" * 64,
        "3" * 64, "original:review", "call:review", "4" * 64,
        "5" * 64, "6" * 64, "lease:root", "reservation:gen",
        "reservation:review", "7" * 64, "policy:v1", "pass", "8" * 64)
    source_version = GraphVersion(source, 1)
    account_version = GraphVersion(account_key, 1)
    route = CurrentReplyEntityRouteBindingV2(
        namespace, "c02:reply", source.token, "platform", "sender",
        audience, scene, target, account.account_id, source_version,
        account_version, source_version, source_version, source_version,
        GraphVersion(access, 1), (account_version,),
        QueryEpoch(namespace, "all", 0), None, "a" * 64)
    route_digest = natural_route_semantic_digest_v2(route)
    material = NaturalFinalActionMaterialV2(
        base_intent.identity.activity_id, base_intent.identity.operation_id,
        base_intent.identity.effect_id, "c02:reply", VersionedRef(source.token, 1),
        scene, audience, VersionedRef(role_key.token, 1),
        VersionedRef(account_key.token, 1), VersionedRef(source.token, 1),
        VersionedRef(access.token, 1), route_digest, ("reply",),
        ("paraphrase",), paid.qualified_units_digest, (claim,), segment,
        payload_digest, (source_version, GraphVersion(role_key, 1),
                         account_version), paid)
    final = NaturalFinalActionCandidateV2(
        "candidate_hold_w01_final_admission", material, ("d11_admission",))
    role_criteria = AtomKey(Owner("persona", *namespace.as_tuple),
                            "d03.role_criteria", "current")
    boundary_criteria = AtomKey(Owner("persona", *namespace.as_tuple),
                                "d05.boundary_criteria", "current")
    specs = list(base_intent.required_checks)
    specs[0] = RequiredCheckSpec(
        "role_binding", "d03.role_binding", "persona:persona",
        base_intent.action_id, "expression", role_criteria.token,
        (VersionedRef(role_criteria.token, 1),
         VersionedRef("d03.role_binding", 1), VersionedRef(role.role_binding_id, 1)))
    specs[1] = RequiredCheckSpec(
        "boundary", "d05.boundary", "persona:persona",
        base_intent.action_id, "expression", boundary_criteria.token,
        (VersionedRef(boundary_criteria.token, 1),
         VersionedRef("d05.boundary", 1), VersionedRef(rule.rule_id, 1)))
    intent = replace(base_intent, target_ref=target,
                     action_kind="communication", source_refs=(source.token,),
                     required_checks=tuple(specs))
    schema = ActionSchema(intent.schema_id, "communication", False, intent.required_checks)
    schema_record = ActionSchemaRecord.bind(intent, schema)
    segment_grant = replace(base_candidate.communication_grant.segment_grants[0],
                            segment_id=segment.segment_id,
                            payload_digest=payload_digest)
    grant = replace(base_candidate.communication_grant,
                    target_ref=target, audiences=(audience,),
                    required_slots=("reply",),
                    segment_grants=(segment_grant,), route_binding_digest=route_digest)
    candidate = replace(base_candidate, action_intent=intent,
                        communication_grant=grant)
    batch = prepare_natural_verified_batch_proposal_v2(final, grant)
    assert batch.write is not None, batch.missing
    context = ContextProvider()
    context.compile_scheme({"schema": "d03.context.scheme.v1",
                            "roles": ("friend",), "norms": ()}, None)
    anchor = RestoreAnchor("authority", "namespace", 1, "deletion", 0,
                           "genesis", "execution", 0, "genesis", 0, "proof")
    permit = FencePermitV2("authority", "namespace", "subject", "holder", 1,
                           "write", intent.identity.operation_id, "x" * 32,
                           1, 1, anchor)
    scope = FenceScope(namespace, "namespace", 1, "write",
                       intent.identity.operation_id, permit, anchor,
                       NamespaceEpoch(*namespace.as_tuple, 0), 0)

    def stage(key, value):
        db.execute("INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,type_name,name,revision,value,valid) "
                   "VALUES(?,?,?,?,?,?,?,?,?,1)",
                   (key.token, *namespace.as_tuple, key.owner.kind, key.owner.subject,
                    key.type_name, key.name, 1,
                    canonical_json(json.loads(json.dumps(value)))))

    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO graph_epochs(bot,persona,revision) VALUES(?,?,1)",
                   namespace.as_tuple)
        for key, value in (
            (source, record.to_dict()),
            (access, {"source_id": record.source_id, "audiences": [audience],
                      "purposes": ["expression"], "status": "active",
                      "recorded_at": 1.0}),
            (account_key, asdict(account)), (role_key, asdict(role)),
            (rule_key, asdict(rule)), (role_criteria, {"policy": "current"}),
            (boundary_criteria, {"policy": "current"}),
            (AtomKey(Owner("activity", *namespace.as_tuple,
                           intent.identity.activity_id), "d08.action_intent.v1",
                     intent.action_id), asdict(intent)),
            (AtomKey(Owner("activity", *namespace.as_tuple,
                           intent.identity.activity_id), "d08.action_schema.v1",
                     schema_record.schema_ref), asdict(schema_record)),
        ):
            stage(key, value)
        rows = db.execute("SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=?",
                          namespace.as_tuple).fetchall()
        snapshot = GraphSnapshot(tuple(GraphAtom(AtomKey.from_token(token), revision,
                                                 json.loads(value))
                                       for token, revision, value in rows),
                                 (NamespaceEpoch(*namespace.as_tuple, 1),))
        original = read_natural_scoped_query_proof_v2(
            db, NaturalPrivateScopeV2(namespace, "platform", "sender", target,
                                      scene, audience, account_key.token,
                                      role_key.token, (source.token,)), now_utc=2.0)
        first = issue_natural_pregrant_social_receipts_v2(
            db, snapshot, QueryEpoch(namespace, "all", 1), final, intent,
            schema, route, original, context, scope,
            now_utc=2.0, valid_until_utc=grant.valid_until)
        assert first.status == "checks_candidate", first.missing
        assert first.batch_digest is None
        assert (first.role_receipt.result, first.boundary_receipt.result) == ("pass", "pass")
        evidence = issue_natural_prebatch_social_receipts_v2(
            db, snapshot, QueryEpoch(namespace, "all", 1), final, candidate,
            schema, batch.write, route, original, context, scope,
            now_utc=2.0, valid_until_utc=grant.valid_until)
        assert evidence.status == "checks_candidate", evidence.missing
        assert evidence.role_receipt.result == "pass"
        assert evidence.boundary_receipt.result == "pass"
        assert GraphVersion(role_key, 1) in evidence.positive_reads
        assert GraphVersion(rule_key, 1) in evidence.positive_reads
        assert replace(evidence, batch_digest=None) == first
        for field in ("role_matches", "account_matches"):
            prior = getattr(original, field)
            object.__setattr__(original, field, ())
            malformed = issue_natural_pregrant_social_receipts_v2(
                db, snapshot, QueryEpoch(namespace, "all", 1), final, intent,
                schema, route, original, context, scope,
                now_utc=2.0, valid_until_utc=grant.valid_until)
            assert malformed.status == "hold" and malformed.role_receipt is None
            object.__setattr__(original, field, prior)
    finally:
        db.rollback()
        graph.close()
