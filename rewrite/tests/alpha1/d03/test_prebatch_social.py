"""Pre-batch D03/D05 checks use the staged graph and original ingress route."""

from dataclasses import asdict, replace
import json
import sqlite3

from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.domains.d03 import AccountBinding, ContextProvider, EntityAnchor, RoleBinding, WorldEvent
from sylanne3.domains.d03.prebatch_social import (
    issue_prebatch_private_social_v1, match_prebatch_batch_v1,
)
from sylanne3.domains.d05 import BoundaryRule
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.domains.d08 import ActionSchema, ActionSchemaRecord
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, D09ExpressionProvider, ExpressionClaim,
    SegmentCandidate, SourceReplyExpressionV1, segment_payload_digest,
)
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner
from sylanne3.host.identity import astrbot_namespace
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.runtime.reply_model_job import CurrentReplyRouteManifestV2
from sylanne3.runtime.reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    FenceScope, NamespaceId, QueryEpoch, VersionedRef, canonical_digest,
)

from rewrite.tests.alpha1.runtime.test_dispatch_admission_preflight import _candidates


def _case(*, boundary_effect="allow", boundary_audience=None):
    account = json.dumps(["platform", "account", "self"], separators=(",", ":"))
    destination = json.dumps(["private", "user"], separators=(",", ":"))
    sender_ref = json.dumps(["platform", "user"], separators=(",", ":"))
    namespace = NamespaceId(
        astrbot_namespace("platform", "self", "selected").bot_id, "persona")
    scene = scene_ref_for_conversation(namespace, account, destination)
    source = source_key(*namespace.as_tuple, "source-one")
    suffix = canonical_digest({"namespace": namespace.as_tuple,
                               "platform_ref": account, "sender_ref": sender_ref})
    entity_id = "entity:account-v1:" + suffix
    account_id = "account:v1:" + suffix
    _, intent, _, _, _, grant = _candidates(
        source_ref=source.token, include_grant=True)
    intent = replace(intent, target_ref=entity_id)
    role = RoleBinding(
        "binding:one", "persona:persona", "friend", entity_id, None,
        scene, "direct", "private", (), 0.0, None, 1,
        (source.token,), 2, "active")
    boundary = BoundaryRule(
        "boundary:one", "persona:persona", entity_id, "message",
        boundary_audience or destination, scene, boundary_effect,
        "self_internal", (source.token,), (), (), 0.0, None, 1,
        "actor", (), "active")
    specs = list(intent.required_checks)
    specs[0] = replace(
        specs[0], criteria_version=source.token,
        required_input_versions=(
            VersionedRef(source.token, 1),
            VersionedRef("d03.role_binding", 5),
            VersionedRef(role.role_binding_id, role.binding_version)))
    specs[1] = replace(
        specs[1], criteria_version=source.token,
        required_input_versions=(
            VersionedRef(source.token, 1),
            VersionedRef("d05.boundary", 5),
            VersionedRef(boundary.rule_id, boundary.scope_version)))
    intent = replace(intent, required_checks=tuple(specs))
    schema = ActionSchemaRecord.bind(
        intent, ActionSchema(intent.schema_id, "message", False,
                             intent.required_checks))
    use = ClaimUse("claim:one", 0, 5, ClaimKind.REPORTED_CLAIM)
    provenance = canonical_digest("original-authority-read")
    segment = SegmentCandidate(
        "segment:" + provenance, "effect:one", "Hello", (use,),
        ("answer",), (), 0.0)
    payload_digest = segment_payload_digest("Hello", (), (use,))
    expression = SourceReplyExpressionV1(
        (ExpressionClaim("claim:one", "Hello", ClaimKind.REPORTED_CLAIM,
                         (source.token,), (destination,), ("expression",),
                         source.token),),
        (segment,), payload_digest, provenance, "a" * 64, "b" * 64)
    route = CurrentReplyRouteManifestV2(
        namespace, "c02-operation", source.token, account, destination,
        scene, canonical_digest({"account_ref": account,
                                 "destination_ref": destination,
                                 "scene_ref": scene}))
    db = sqlite3.connect(":memory:", isolation_level=None)
    db.executescript("""
        CREATE TABLE graph_epochs(bot TEXT,persona TEXT,revision INTEGER);
        CREATE TABLE graph_atoms(token TEXT,bot TEXT,persona TEXT,
            type_name TEXT,revision INTEGER,value TEXT,valid INTEGER);
        CREATE TABLE graph_first_ingress_identity_v1(
            bot TEXT,persona TEXT,source_ref TEXT,platform_ref TEXT,
            conversation_ref TEXT,sender_ref TEXT,message_id TEXT,visibility TEXT);
    """)
    db.execute("INSERT INTO graph_epochs VALUES(?,?,?)", (*namespace.as_tuple, 5))
    db.execute("INSERT INTO graph_first_ingress_identity_v1 VALUES(?,?,?,?,?,?,?,?)",
               (*namespace.as_tuple, "source-one", account, destination,
                sender_ref, "message-one", "private"))
    owner = Owner("activity", *namespace.as_tuple, intent.identity.activity_id)
    role_key = AtomKey(Owner("scene", *namespace.as_tuple, scene),
                       "d03.role_binding", role.role_binding_id)
    boundary_key = AtomKey(Owner("relation", *namespace.as_tuple, entity_id),
                           "d05.boundary_rule", boundary.rule_id)
    anchor_key = AtomKey(Owner("persona", *namespace.as_tuple),
                         "d03.entity_anchor", entity_id)
    binding_key = AtomKey(Owner("persona", *namespace.as_tuple),
                          "d03.account_binding", account_id)
    event_id = "world:message-arrival-v1:" + canonical_digest({
        "namespace": namespace.as_tuple, "platform_ref": account,
        "conversation_ref": destination, "message_id": "message-one",
        "source_id": "source-one",
    })
    event_key = AtomKey(Owner("event", *namespace.as_tuple, event_id),
                        "d03.world_event", "current")
    anchor = EntityAnchor(entity_id, "account", "persona:persona",
                          (source.token,), "active")
    binding = AccountBinding(account_id, account, sender_ref, entity_id,
                             event_key.token, 1.0, None)
    event = WorldEvent(event_id, "message_received",
                       ((entity_id, "sender_account"),), 1.0, 1.0, 1.0,
                       scene, (source.token,), "host_observed")
    rows = (
        (source, 1, {"source_id": "source-one"}),
        (access_key(*namespace.as_tuple, "source-one"), 1,
         {"source_id": "source-one", "status": "active"}),
        (AtomKey(owner, "d08.action_intent.v1", intent.action_id), 1, asdict(intent)),
        (AtomKey(owner, "d08.action_schema.v1", schema.schema_ref), 1, asdict(schema)),
        (role_key, role.binding_version, asdict(role)),
        (boundary_key, boundary.scope_version, asdict(boundary)),
        (anchor_key, 1, asdict(anchor)),
        (binding_key, 1, asdict(binding)),
        (event_key, 1, asdict(event)),
    )
    atoms = []
    for key, revision, value in rows:
        decoded = json.loads(json.dumps(value))
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
            key.token, *namespace.as_tuple, key.type_name, revision,
            json.dumps(decoded), 1))
        atoms.append(GraphAtom(key, revision, decoded, True))
    snapshot = GraphSnapshot(tuple(atoms), (NamespaceEpoch(*namespace.as_tuple, 5),))
    query = QueryEpoch(namespace, "all", 5)
    context = ContextProvider()
    context.compile_scheme({"schema": "d03.context.scheme.v1",
                            "roles": ("friend",), "norms": ()}, None)
    anchor = RestoreAnchor(
        "authority", "authority-namespace", 1, "deletion", 0,
        "genesis", "execution", 0, "genesis", 0, "proof")
    permit = FencePermitV2(
        "authority", "authority-namespace", "subject", "holder", 1,
        "write", "write-attempt-one", "t" * 32, 1, 1, anchor)
    scope = FenceScope(
        namespace, "authority-namespace", 1, "write",
        "write-attempt-one", permit, anchor,
        NamespaceEpoch(*namespace.as_tuple, 4), 1)
    db.execute("BEGIN IMMEDIATE")
    route_binding = CurrentReplyEntityRouteBindingV2(
        namespace, route.c02_operation_id, source.token, account, sender_ref,
        destination, scene, entity_id, account_id,
        GraphVersion(anchor_key, 1), GraphVersion(binding_key, 1),
        GraphVersion(event_key, 1), GraphVersion(event_key, 1),
        GraphVersion(source, 1),
        GraphVersion(access_key(*namespace.as_tuple, "source-one"), 1),
        (GraphVersion(binding_key, 1),), QueryEpoch(namespace, "all", 4),
        None, canonical_digest("trusted binding fixture"),
    )
    return (db, snapshot, query, intent, schema, expression, route, context,
            scope, route_binding, grant)


def _issue(case):
    db, snapshot, query, intent, schema, expression, route, context, scope, route_binding, _ = case
    return issue_prebatch_private_social_v1(
        db, snapshot, query, intent, schema, expression,
        route=route, route_binding=route_binding,
        context=context, scope=scope, now_utc=2.0)


def test_staged_action_and_original_route_issue_bounded_social_candidates():
    case = _case()
    db = case[0]
    try:
        result = _issue(case)
        assert result.status == "checks_candidate" and result.missing == ()
        assert result.role_receipt.result == result.boundary_receipt.result == "pass"
        assert result.negative_query == case[2]
        assert len(result.positive_reads) == len(case[1].atoms)
        assert result.manifest.scene_ref == case[6].scene_ref
        assert result.manifest.audience == (case[6].conversation_ref,)
        assert result.manifest.target_ref == case[-2].target_entity_ref
        assert result.manifest.target_ref != case[6].conversation_ref
        assert result.role_receipt.result == "pass"
        assert case[-2].binding_version in result.positive_reads
        assert "d03.account_binding:all_valid:unique_current_sender" in result.negative_predicates
        assert _issue(case) == result
    finally:
        db.close()


def test_route_change_or_missing_full_read_holds_before_d09_batch():
    case = _case()
    db = case[0]
    try:
        changed_route = replace(case[6], conversation_ref='["private","other"]')
        assert issue_prebatch_private_social_v1(
            db, case[1], case[2], case[3], case[4], case[5],
            route=changed_route, route_binding=case[-2],
            context=case[7], scope=case[8],
            now_utc=2.0).status == "hold"
        omitted = replace(case[1], atoms=case[1].atoms[:-1])
        assert issue_prebatch_private_social_v1(
            db, omitted, case[2], case[3], case[4], case[5],
            route=case[6], route_binding=case[-2],
            context=case[7], scope=case[8],
            now_utc=2.0).status == "hold"
    finally:
        db.close()


def test_boundary_denial_and_audience_mismatch_hold():
    for kwargs in ({"boundary_effect": "deny"},
                   {"boundary_audience": "another-audience"}):
        case = _case(**kwargs)
        try:
            result = _issue(case)
            assert result.status == "hold"
            assert any(part.startswith("d05.") for part in result.missing)
        finally:
            case[0].close()


def test_untrusted_or_stale_account_route_holds_before_social_checks():
    case = _case()
    db, snapshot, query, intent, schema, expression, route, context, scope, binding, _ = case
    try:
        for changed in (
            replace(binding, target_entity_ref="entity:person"),
            replace(binding, sender_ref='["platform","other"]'),
            replace(binding, query=QueryEpoch(scope.namespace, "all", 3)),
            replace(binding, binding_scan_versions=()),
            replace(binding, binding_version=GraphVersion(binding.binding_version.key, 2)),
        ):
            result = issue_prebatch_private_social_v1(
                db, snapshot, query, intent, schema, expression,
                route=route, route_binding=changed,
                context=context, scope=scope, now_utc=2.0)
            assert result.status == "hold"
            assert "social.current_graph_provider_read_unavailable" in result.missing
        wrong_target = replace(intent, target_ref=route.conversation_ref)
        wrong_schema = ActionSchemaRecord.bind(
            wrong_target, ActionSchema(wrong_target.schema_id, "message", False,
                                       wrong_target.required_checks))
        result = issue_prebatch_private_social_v1(
            db, snapshot, query, wrong_target, wrong_schema, expression,
            route=route, route_binding=binding,
            context=context, scope=scope, now_utc=2.0)
        assert result.status == "hold"
    finally:
        db.close()


def test_prebatch_receipt_cannot_match_a_batch_with_different_route_or_payload():
    case = _case()
    db = case[0]
    try:
        result = _issue(case)
        assert result.status == "checks_candidate"
        grant = case[-1]
        expression = case[5]
        audience = case[6].conversation_ref
        bound_grant = replace(
            grant, target_ref=case[3].target_ref, audiences=(audience,),
            allowed_claim_kinds=(ClaimKind.REPORTED_CLAIM.value,),
            segment_grants=(replace(
                grant.segment_grants[0],
                segment_id=expression.segments[0].segment_id,
                effect_id=expression.segments[0].effect_id,
                payload_digest=expression.payload_digest),))
        provider = D09ExpressionProvider()
        blueprint = provider.prepare_blueprint(
            bound_grant, case[6].scene_ref, 1, expression.claims,
            now=2.0).blueprint
        assert blueprint is not None
        batch = provider.build_verified_batch_v1(
            bound_grant, blueprint, expression.segments, now=2.0)
        assert match_prebatch_batch_v1(result, batch)
        altered = {**batch, "scene_ref": "scene:wrong"}
        assert not match_prebatch_batch_v1(result, altered)
    finally:
        db.close()


def test_later_unrelated_rows_do_not_change_social_closure_but_correction_does():
    case = _case()
    db, snapshot, query, intent, schema, expression, route, context, scope, route_binding, _ = case
    try:
        before = _issue(case)
        owner = Owner("activity", *scope.namespace.as_tuple,
                      intent.identity.activity_id)
        unrelated = AtomKey(owner, "runtime.job", "later-job")
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
            unrelated.token, *scope.namespace.as_tuple, unrelated.type_name,
            1, '{"phase":"queued"}', 1))
        expanded = replace(snapshot, atoms=snapshot.atoms + (
            GraphAtom(unrelated, 1, {"phase": "queued"}, True),))
        after = issue_prebatch_private_social_v1(
            db, expanded, query, intent, schema, expression,
            route=route, route_binding=route_binding,
            context=context, scope=scope, now_utc=2.0)
        assert after == before
        head = source_correction_head_key(scope.namespace, "source-one")
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
            head.token, *scope.namespace.as_tuple, head.type_name,
            1, "{}", 1))
        corrected = replace(expanded, atoms=expanded.atoms + (
            GraphAtom(head, 1, {}, True),))
        blocked = issue_prebatch_private_social_v1(
            db, corrected, query, intent, schema, expression,
            route=route, route_binding=route_binding,
            context=context, scope=scope, now_utc=2.0)
        assert blocked.status == "hold"
        assert any("source_pending_reevaluation" in item
                   or "correction_head_unavailable" in item
                   for item in blocked.missing)
    finally:
        db.close()
