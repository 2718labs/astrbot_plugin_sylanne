"""One typed assembly and one exact quote/ref mismatch; neither is admission."""

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.domains.d08 import (
    BASE_REQUIRED_PROVIDERS, ActionCancellationState, ActionIntent,
    ActionSchema, ActionSchemaRecord, CommunicationGrantRequest,
    CommunicationSegmentSpec, Goal, GoalPredicate, GoalExecutionProvider,
    RequiredCheckRegistry, RequiredCheckSpec,
)
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, ExpressionClaim, SegmentCandidate,
    SourceReplyExpressionV1, segment_payload_digest,
)
from sylanne3.graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from sylanne3.memory_types import source_key
from sylanne3.runtime.d11_types import validate_d11_writes
from sylanne3.runtime.issuers import BudgetLeaseGrant, ResourceQuote
from sylanne3.runtime.jobs import PersistentJob
from sylanne3.runtime.post_c02_reply_action_v2 import PostC02ReplyActionCandidateV2
from sylanne3.runtime.post_c02_reply_bundle_v2 import (
    post_c02_dispatch_runtime_refs_v2,
    prepare_post_c02_reply_bundle_candidate_v2,
)
from sylanne3.runtime.reply_model_job import CurrentReplyRouteManifestV2
from sylanne3.runtime.reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2
from sylanne3.runtime_contracts import (
    AuthorityContext, CheckReceipt, CommandEnvelope, DependencySet,
    DomainProposal, NamespaceId, OperationIdentity, QueryEpoch, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, VersionedRef, canonical_digest,
)


def _inputs():
    ns = NamespaceId("bot", "persona")
    source = source_key(*ns.as_tuple, "inbound")
    audience = '["private","user"]'
    identity = OperationIdentity(
        "activity:reply", "effect:reply", "attempt:reply", "prepare",
        "post-c02-reply:one", canonical_digest({"input_refs": [source.token]}))
    authority = AuthorityContext(
        "administrator", "d11", "capability", ns, ("activity",),
        "expression", (audience,), "policy", 1)
    activity = Owner("activity", *ns.as_tuple, identity.activity_id)
    goal_id, action_id, schema_id = "goal:one", "action:one", "schema:one"
    goal_key = AtomKey(activity, "d08.goal.v1", goal_id)
    action_key = AtomKey(activity, "d08.action_intent.v1", action_id)
    cancel_key = AtomKey(activity, "d08.action_cancellation.v1", action_id)
    criteria = tuple(RequiredCheckSpec(
        kind, provider, "persona:persona", action_id, "expression",
        "criteria:" + kind, (VersionedRef("criteria:" + kind, 1),))
        for kind, provider in BASE_REQUIRED_PROVIDERS)
    predicate = GoalPredicate("communicated", "d11.delivery", (), 1.0, 50.0)
    goal = Goal(goal_id, 1, "active", predicate, (source.token,), (), None, (), ())
    target_entity_ref = "entity:account-v1:" + "e" * 64
    intent = ActionIntent(
        action_id, 1, goal_id, (), target_entity_ref, "message", "expression",
        "limited", "a" * 64, identity, schema_id, criteria, predicate,
        (identity.effect_id,), None, (source.token,))
    schema = ActionSchema(schema_id, "message", False, criteria)
    schema_record = ActionSchemaRecord.bind(intent, schema)
    schema_key = AtomKey(activity, "d08.action_schema.v1", schema_record.schema_ref)
    guard = VersionGuard(
        (GraphVersion(source, 1), *(GraphVersion(key, 0) for key in
                                    (goal_key, action_key, schema_key, cancel_key))),
        (QueryEpoch(ns, "all", 1),), 0, 0, "catalogue", "scheme",
        "operator", "policy", (), (), (VersionedRef("quote-1", 1),))
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA, identity, authority, guard,
        SourceQualification((source.token,), "reported", 1.0, 2.0,
                            "external_report", "eligible", .8, "not_applicable"),
        (source.token,), "lease-1", 50.0, 50.0, "interval", ("c02:one",))
    route = CurrentReplyRouteManifestV2(
        ns, "c02:one", source.token, '["platform","name","bot"]',
        audience, "scene:private", canonical_digest({
            "account_ref": '["platform","name","bot"]',
            "destination_ref": audience, "scene_ref": "scene:private"}))
    route_binding = CurrentReplyEntityRouteBindingV2(
        ns, "c02:one", source.token, route.platform_ref, "sender:one",
        audience, route.scene_ref, target_entity_ref, "account:v1:one",
        GraphVersion(source, 1), GraphVersion(source, 1),
        GraphVersion(source, 1), GraphVersion(source, 1),
        GraphVersion(source, 1), GraphVersion(source, 1),
        (), QueryEpoch(ns, "all", 2), None, "f" * 64)
    claim = ExpressionClaim(
        "claim:one", "Hello", ClaimKind.REPORTED_CLAIM, (source.token,),
        (audience,), ("expression",), source.token)
    use = ClaimUse(claim.claim_id, 0, 5, ClaimKind.REPORTED_CLAIM)
    segment = SegmentCandidate(
        "segment:one", "effect:segment", "Hello", (use,), ("answer",), (), 0.0)
    payload_digest = segment_payload_digest("Hello", (), (use,))
    expression = SourceReplyExpressionV1(
        (claim,), (segment,), payload_digest, "b" * 64, "c" * 64, "d" * 64)
    communication = CommunicationGrantRequest(
        "communication:one", "contact:one", 1, (audience,), ("answer",),
        (ClaimKind.REPORTED_CLAIM.value,), (),
        (CommunicationSegmentSpec("segment:one", "effect:segment", 0,
                                  payload_digest, 5, (), None),), 0)
    action = PostC02ReplyActionCandidateV2(
        "candidate", (), goal, intent, schema, communication)
    cancellation = ActionCancellationState.for_action(
        intent, state="active", actor="administrator",
        source_refs=(source.token,), operation_id=identity.operation_id)
    writes = tuple(GraphWrite(key, json.loads(json.dumps(asdict(value))))
                   for key, value in ((goal_key, goal), (action_key, intent),
                                      (schema_key, schema_record),
                                      (cancel_key, cancellation)))
    d08 = GoalExecutionProvider()
    staged = DomainProposal(
        "d08", "d08.proposal.v1", d08.descriptor.request_schema_hash,
        envelope, writes, DependencySet(), (), ())
    checks = tuple(CheckReceipt(
        spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
        spec.required_input_versions, "full", "pass", 40.0,
        spec.provider_id) for spec in criteria)
    registry = RequiredCheckRegistry()
    registry.register(schema)
    decision = registry.qualify(intent, checks, now=10.0)
    assert decision.status == "qualified"
    pre_frozen_grant = registry._freeze_communication_grant_checked(
        intent, decision, communication,
        route_binding_digest=canonical_digest(route_binding))
    budget_grant = BudgetLeaseGrant(
        "grant-1", 1, *ns.as_tuple, "lease-1", "USD", {"cpu_ms": 10},
        ("message",), 100.0, "policy")
    job_ref, outbox_ref, _ = post_c02_dispatch_runtime_refs_v2(ns, identity)
    quote = ResourceQuote(
        "quote-1", 1, *ns.as_tuple, identity.activity_id,
        identity.operation_id, identity.effect_id, "lease-1", "message",
        "snapshot-1", 50.0, "resource-1", job_ref, (outbox_ref,), (),
        {"cpu_ms": 1}, None, 100.0)
    job = PersistentJob(
        AtomKey.from_token(job_ref).name, identity.operation_id,
        identity.activity_id, identity.effect_id, *ns.as_tuple, "snapshot-1",
        "waiting", "message", {},
        {"kind": "post_c02_reply_host_takeover", "operation_id": identity.operation_id},
        "1970-01-01T00:00:50Z", "lease-1", "resource-1",
        {"resource_quote": "quote-1:1"}, None, None, 0, 0, {}, None)
    return dict(envelope=envelope, action=action, staged_d08=staged,
                checks=checks, expression=expression, route=route,
                route_binding=route_binding,
                pre_frozen_grant=pre_frozen_grant,
                quote=quote, budget_grant=budget_grant,
                pre_reserved_job=job, now_utc=10.0, conversation_epoch=1)


def test_typed_private_reply_bundle_is_only_a_candidate():
    candidate = prepare_post_c02_reply_bundle_candidate_v2(**_inputs())
    assert candidate.status == "candidate"
    assert candidate.bundle.persistent_job_refs == (candidate.job_ref,)
    assert candidate.bundle.outbox_refs == (candidate.outbox_ref,)
    assert candidate.bundle.proposals[0].typed_writes[-1].key.type_name == \
        "d08.communication_intent_grant.v1"
    assert len(candidate.batch["segments"]) == 1
    assert candidate.grant.target_ref == "entity:account-v1:" + "e" * 64
    assert candidate.batch["audiences"] == [candidate.bundle.envelope.authority.audience[0]]
    assert candidate.bundle.proposals[2].typed_writes[1].key.token == candidate.outbox_ref
    assert validate_d11_writes(
        candidate.bundle.proposals[2].typed_writes,
        candidate.bundle.envelope.authority.namespace,
        operation_id=candidate.bundle.envelope.identity.operation_id,
        activity_id=candidate.bundle.envelope.identity.activity_id,
        effect_id=candidate.bundle.envelope.identity.effect_id)
    assert all(item.envelope == candidate.bundle.envelope
               for item in candidate.bundle.proposals)


def test_quote_must_bind_the_exact_prequoted_outbox():
    inputs = _inputs()
    inputs["quote"] = replace(inputs["quote"], outbox_refs=("other-ref",))
    with pytest.raises(ValueError, match="signed quote"):
        prepare_post_c02_reply_bundle_candidate_v2(**inputs)


def test_entity_target_cannot_be_replaced_by_json_delivery_route():
    inputs = _inputs()
    inputs["route_binding"] = replace(
        inputs["route_binding"], target_entity_ref=inputs["route"].conversation_ref)
    with pytest.raises(ValueError, match="staged passive reply identity or route"):
        prepare_post_c02_reply_bundle_candidate_v2(**inputs)
