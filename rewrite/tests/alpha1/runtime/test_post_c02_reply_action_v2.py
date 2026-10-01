"""The pure issuer cannot turn caller evidence into a send decision."""

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.domains.d07 import AttentionTicket, FocusState, attention_ticket_key
from sylanne3.domains.d08 import ActionCancellationState, ActionSchemaRecord
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, ExpressionClaim, SegmentCandidate,
    SourceReplyExpressionV1, segment_payload_digest,
)
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner
from sylanne3.host.post_c02_reply_driver import post_c02_reply_operation_id
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.issuers import BudgetLeaseGrant, ResourceQuote
from sylanne3.runtime.reply_model_job import CurrentReplyRouteManifestV2
from sylanne3.runtime.reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, CommitReceipt, NamespaceId,
    OperationIdentity, QueryEpoch, RUNTIME_SCHEMA, SourceQualification,
    VersionGuard, VersionedRef, canonical_digest,
)

from sylanne3.runtime.post_c02_reply_action_v2 import (
    CurrentReplyCheckVersionV2, CurrentReplyCheckVersionsV2,
    PostC02ReplyActionCandidateV2, issue_post_c02_reply_action_v2,
    post_c02_reply_action_ids_v2,
    prepare_post_c02_reply_action_provisional_v2,
)


def test_untyped_inputs_hold_without_any_action_or_communication():
    candidate = issue_post_c02_reply_action_v2(
        envelope=object(), c02_receipt=object(), route=object(),
        route_binding=object(),
        source_ref="source:untrusted", snapshot=object(), query=object(),
        attention=object(), focus=object(), budget_grant=object(),
        resource_quote=object(), expression=object(), anchor=object(),
        now_utc=1.0,
    )
    assert candidate == PostC02ReplyActionCandidateV2(
        "hold", ("reply.typed_current_inputs",))
    assert candidate.goal is None and candidate.intent is None
    assert candidate.schema is None and candidate.communication is None


def test_caller_cannot_supply_a_check_receipt_or_prebuilt_bundle():
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        issue_post_c02_reply_action_v2(checks=(), bundle=object())


def test_staging_ids_are_stable_for_original_c02_and_source():
    first = post_c02_reply_action_ids_v2("c02:original", "source:one")
    assert first == post_c02_reply_action_ids_v2("c02:original", "source:one")
    assert len(set(first)) == 3
    assert first != post_c02_reply_action_ids_v2("c02:original", "source:two")


def test_typed_provisional_then_actual_e_plus_one_reissues_same_candidate():
    """Synthetic typed closure exercises composition, never production admission."""
    ns = NamespaceId("bot", "persona")
    source = source_key(*ns.as_tuple, "source-1")
    access = access_key(*ns.as_tuple, "source-1")
    audience = '["private","user"]'
    platform_ref = '["platform","name","bot"]'
    sender_ref = "sender-1"
    account_digest = canonical_digest({
        "namespace": ns.as_tuple, "platform_ref": platform_ref,
        "sender_ref": sender_ref})
    target_entity_ref = "entity:account-v1:" + account_digest
    account_id = "account:v1:" + account_digest
    record = SourceRecord(
        "source-1", "Hello", sender_ref, "reported", "reported",
        1.0, 2.0, "root:message", (audience,), ("expression",))
    ticket = AttentionTicket(
        "ticket:one", "question:one", None, source.token, "interaction",
        .8, .8, .5, .5, .5, .1, .1, .1, 0.0, 1, 100.0,
        True, True, (), (source.token,))
    ticket_key = attention_ticket_key(ns, ticket.ticket_id)
    focus = FocusState("persona", 1, ticket_key.token, (), "new_message")
    focus_key = AtomKey(Owner("persona", *ns.as_tuple), "d07.focus.v1", "persona")
    role_criterion = AtomKey(Owner("persona", *ns.as_tuple),
                             "d03.role_binding.criteria.v1", "current")
    boundary_criterion = AtomKey(Owner("persona", *ns.as_tuple),
                                 "d05.boundary.criteria.v1", "current")
    route_anchor = AtomKey(Owner("persona", *ns.as_tuple),
                           "d03.entity_anchor", target_entity_ref)
    route_account = AtomKey(Owner("persona", *ns.as_tuple),
                            "d03.account_binding", account_id)
    route_arrival = AtomKey(Owner("event", *ns.as_tuple, "arrival-event"),
                            "d03.world_event", "current")
    route_evidence = AtomKey(Owner("event", *ns.as_tuple, "binding-event"),
                             "d03.world_event", "current")
    atoms = (
        GraphAtom(source, 1, record.to_dict()),
        GraphAtom(access, 1, {"source_id": "source-1", "audiences": [audience],
                              "purposes": ["expression"], "status": "active",
                              "recorded_at": 2.0}),
        GraphAtom(ticket_key, 1, {"schema": "d07.attention_ticket.v1",
                                  **asdict(ticket), "cancel_refs": [],
                                  "source_refs": [source.token]}),
        GraphAtom(focus_key, 1, {"schema": "d07.focus.v1", **asdict(focus),
                                 "auxiliary_ticket_refs": []}),
        GraphAtom(role_criterion, 1, {"criterion": "current"}),
        GraphAtom(boundary_criterion, 1, {"criterion": "current"}),
        GraphAtom(route_anchor, 1, {"entity_id": target_entity_ref,
                                   "kind": "account", "status": "active"}),
        GraphAtom(route_account, 1, {"account_id": account_id,
                                    "entity_id": target_entity_ref,
                                    "platform_namespace": platform_ref,
                                    "platform_identifier": sender_ref}),
        GraphAtom(route_arrival, 1, {"kind": "message_received"}),
        GraphAtom(route_evidence, 1, {"kind": "message_received"}),
    )
    before = GraphSnapshot(atoms, (NamespaceEpoch(*ns.as_tuple, 5),))
    query = QueryEpoch(ns, "all", 6)
    c02_id = "c02:original"
    operation_id = post_c02_reply_operation_id(c02_id, source.token)
    goal_id, action_id, schema_id = post_c02_reply_action_ids_v2(c02_id, source.token)
    input_refs = (source.token,)
    identity = OperationIdentity(
        "activity:reply", "effect:reply", "attempt:reply", "prepare",
        operation_id, canonical_digest({"input_refs": list(input_refs)}))
    authority = AuthorityContext(
        "administrator", "d11", "capability", ns, ("activity",),
        "expression", (audience,), "policy", 1)
    guard = VersionGuard(
        before.versions, (QueryEpoch(ns, "all", 5),), 0, 0,
        "catalogue", "scheme", "operator", "policy", (), (), ())
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA, identity, authority, guard,
        SourceQualification((source.token,), "reported", 1.0, 2.0,
                            "external_report", "eligible", .8, "not_applicable"),
        input_refs, "lease-1", 50.0, 50.0, "interval", (c02_id,))
    event = Owner("event", *ns.as_tuple, "c02-event")
    c02 = CommitReceipt(
        "committed", c02_id, "a" * 64, "activity:c02", None, 1, (),
        (GraphVersion(AtomKey(event, "memory.episode.v1", "record"), 1),
         GraphVersion(AtomKey(event, "memory.subjective_trace.v2", "record"), 1)),
        (), (), ())
    route = CurrentReplyRouteManifestV2(
        ns, c02_id, source.token, platform_ref,
        audience, "scene:private", canonical_digest({
            "account_ref": platform_ref,
            "destination_ref": audience, "scene_ref": "scene:private"}))
    route_binding = CurrentReplyEntityRouteBindingV2(
        ns, c02_id, source.token, platform_ref, sender_ref, audience,
        route.scene_ref, target_entity_ref, account_id,
        GraphVersion(route_anchor, 1), GraphVersion(route_account, 1),
        GraphVersion(route_arrival, 1), GraphVersion(route_evidence, 1),
        GraphVersion(source, 1), GraphVersion(access, 1),
        (GraphVersion(route_account, 1),), QueryEpoch(ns, "all", 5),
        100.0, canonical_digest({"account_id": account_id}))
    claim = ExpressionClaim(
        "claim:one", "Hello", ClaimKind.REPORTED_CLAIM, (source.token,),
        (audience,), ("expression",), source.token)
    use = ClaimUse(claim.claim_id, 0, 5, ClaimKind.REPORTED_CLAIM)
    segment = SegmentCandidate(
        "segment:one", "effect:segment", "Hello", (use,), ("answer",), (), 0.0)
    expression = SourceReplyExpressionV1(
        (claim,), (segment,), segment_payload_digest("Hello", (), (use,)),
        "b" * 64, "c" * 64, "d" * 64)
    grant = BudgetLeaseGrant(
        "grant-1", 1, *ns.as_tuple, "lease-1", "USD", {"cpu_ms": 10},
        ("message",), 100.0, "policy")
    quote = ResourceQuote(
        "quote-1", 1, *ns.as_tuple, identity.activity_id, operation_id,
        identity.effect_id, grant.lease_id, "message", "snapshot-1",
        50.0, "resource-1", None, (), (), {"cpu_ms": 1}, None, 100.0)
    anchor = RestoreAnchor(
        "authority", "namespace", 1, "deletion", 0, "genesis",
        "execution", 2, "head", 0, "proof")
    reservation_digest = "e" * 64
    specs = (
        CurrentReplyCheckVersionV2(
            "role_binding", role_criterion.token,
            (VersionedRef(role_criterion.token, 1),
             VersionedRef("d03.role_binding", 6))),
        CurrentReplyCheckVersionV2(
            "boundary", boundary_criterion.token,
            (VersionedRef(boundary_criterion.token, 1),
             VersionedRef("d05.boundary", 6))),
        CurrentReplyCheckVersionV2(
            "source_grant", source.token,
            (VersionedRef(source.token, 1), VersionedRef(access.token, 1))),
        CurrentReplyCheckVersionV2(
            "commitment_conflict", "d08.commitment_conflict.criteria.v1",
            tuple(VersionedRef(ref, version) for ref, version in (
                ("d08.commitment_conflict.criteria.v1", 1),
                (goal_id, 1), ("commitments-query:persona:persona", 6),
                (f"execution-epoch:{action_id}", 2),
                (f"cancellation-epoch:{action_id}", 1)))),
        CurrentReplyCheckVersionV2(
            "dispatch_budget", "d02.resource_quote:quote-1",
            (VersionedRef("d02.resource_quote:quote-1", 1),
             VersionedRef("d11.budget.grant:lease-1", 1),
             VersionedRef("d11.budget.lease:lease-1", 1),
             VersionedRef(f"d11.budget.reservation:lease-1:{operation_id}:"
                          f"{reservation_digest}", 1))),
    )
    versions = CurrentReplyCheckVersionsV2(
        ns, query, source.token, quote.quote_id, quote.version,
        grant.grant_id, grant.version, reservation_digest, specs)
    common = dict(
        envelope=envelope, c02_receipt=c02, route=route,
        route_binding=route_binding,
        source_ref=source.token, attention=ticket, focus=focus,
        budget_grant=grant, resource_quote=quote, expression=expression,
        anchor=anchor, now_utc=10.0)
    provisional = prepare_post_c02_reply_action_provisional_v2(
        **common, snapshot=before, expected_query=query,
        projected_check_inputs=versions)
    assert provisional.status == "provisional", provisional.missing
    activity = Owner("activity", *ns.as_tuple, identity.activity_id)
    schema_record = ActionSchemaRecord.bind(provisional.intent, provisional.schema)
    staged = (
        GraphAtom(AtomKey(activity, "d08.goal.v1", goal_id), 1,
                  {"schema": "d08.goal.v1",
                   **json.loads(json.dumps(asdict(provisional.goal)))}),
        GraphAtom(AtomKey(activity, "d08.action_intent.v1", action_id), 1,
                  {"schema": "d08.action_intent.v1",
                   **json.loads(json.dumps(asdict(provisional.intent)))}),
        GraphAtom(AtomKey(activity, "d08.action_schema.v1",
                          schema_record.schema_ref),
                  1, {"schema": "d08.action_schema.v1",
                      **json.loads(json.dumps(asdict(schema_record)))}),
        GraphAtom(AtomKey(activity, "d08.action_cancellation.v1", action_id),
                  1, {"schema": "d08.action_cancellation.v1",
                      **json.loads(json.dumps(asdict(ActionCancellationState.for_action(
                          provisional.intent, state="active", actor="administrator",
                          source_refs=(source.token,), operation_id=operation_id))))}),
    )
    actual = GraphSnapshot(atoms + staged, (NamespaceEpoch(*ns.as_tuple, 6),))
    candidate = issue_post_c02_reply_action_v2(
        **common, snapshot=actual, query=query, check_inputs=versions)
    assert candidate.status == "candidate", candidate.missing
    assert replace(provisional, status="candidate") == candidate
    assert candidate.intent.purpose == "expression"
    assert candidate.intent.target_ref == target_entity_ref
    assert candidate.intent.target_ref != route.conversation_ref
    assert candidate.schema.proactive is False
    assert candidate.communication.audiences == (audience,)
    assert len(candidate.communication.segment_specs) == 1
    wrong_route = issue_post_c02_reply_action_v2(
        **{**common, "route_binding": replace(
            route_binding, target_entity_ref=audience)},
        snapshot=actual, query=query, check_inputs=versions)
    assert wrong_route.status == "hold"
    assert wrong_route.intent is None
