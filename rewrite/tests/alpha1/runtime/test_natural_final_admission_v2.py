"""Natural final staging must not become an independent send permit."""

from dataclasses import replace

from sylanne3.domains.d08.execution import (
    ActionIntent, ActionSchema, BASE_REQUIRED_PROVIDERS,
    CommunicationGrantRequest, CommunicationIntentGrant,
    CommunicationSegmentSpec, GoalPredicate, RequiredCheckSpec, SegmentGrant,
)
from sylanne3.domains.d08.natural_final import NaturalFinalCommunicationCandidateV2
from sylanne3.domains.d08.natural_plan import natural_route_semantic_digest_v2
from sylanne3.domains.d09 import ClaimKind, ClaimUse, ExpressionClaim, SegmentCandidate
from sylanne3.domains.d09.natural_reply import (
    NaturalFinalActionCandidateV2, NaturalFinalActionMaterialV2,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.memory_types import source_key
from sylanne3.runtime.issuers import BudgetLeaseGrant, ResourceQuote
from sylanne3.runtime.natural_final_admission_v2 import (
    inspect_natural_final_admission_v2,
    prepare_natural_final_action_stage_v2,
)
from sylanne3.runtime.post_c02_reply_action_v2 import (
    CurrentReplyCheckVersionV2, CurrentReplyCheckVersionsV2,
)
from sylanne3.runtime.reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    AuthorityContext, CheckReceipt, CommandEnvelope, NamespaceId,
    NaturalReplyPaidReviewReceiptV2, OperationIdentity, QueryEpoch,
    RUNTIME_SCHEMA, SourceQualification, VersionGuard, VersionedRef,
    canonical_digest,
)


def _case():
    criteria = VersionedRef("criteria:v1", 1)
    specs = tuple(RequiredCheckSpec(
        kind, provider, "action:reply", "action:reply", "expression",
        criteria.ref, (criteria,),
    ) for kind, provider in BASE_REQUIRED_PROVIDERS)
    schema = ActionSchema("schema:reply", "communication", False, specs)
    intent = ActionIntent(
        "action:reply", 1, "goal:reply", (), "entity:private",
        "communication", "expression", "limited", "1" * 64,
        OperationIdentity("activity:reply", "effect:reply", "attempt:reply",
                          "prepare", "operation:reply", "2" * 64),
        schema.schema_id, specs,
        GoalPredicate("communicated", "d11", (), 0.0, None),
        ("effect:reply",), None, ("source:reply",),
    )
    checks = tuple(CheckReceipt(
        spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
        spec.required_input_versions, "full", "pass", 100.0,
        spec.provider_id,
    ) for spec in specs)
    refs = tuple("check:" + canonical_digest({
        "kind": spec.check_kind, "provider": spec.provider_id,
        "subject": spec.subject_ref, "action": spec.action_ref,
        "purpose": spec.purpose, "criteria_version": spec.criteria_version,
        "input_versions": spec.required_input_versions,
    }) for spec in specs)
    segment = SegmentGrant("segment:reply", "effect:reply", 0, "3" * 64,
                           32, (), None, refs, 100.0, 0)
    request = CommunicationGrantRequest(
        "communication:reply", "contact:private", 1, ("audience:private",),
        ("reply",), ("rhetoric",), (),
        (CommunicationSegmentSpec(segment.segment_id, segment.effect_id, 0,
                                  segment.payload_digest, 32, (), None),), 0,
    )
    grant = CommunicationIntentGrant(
        "communication-grant:reply", request.communication_action_id,
        request.contact_id, 1, "action-ref:reply", intent.action_id, 1,
        intent.target_ref, request.audiences, "expression",
        request.required_slots, request.allowed_claim_kinds, (), (segment,),
        canonical_digest(checks), refs, 100.0, 0,
        route_binding_digest="4" * 64,
    )
    return (NaturalFinalCommunicationCandidateV2(
        "candidate_hold_w01_final_admission", intent, request, grant,
        ("d11_final_admission",)), schema, checks)


def test_complete_local_checks_still_hold_for_atomic_admission():
    candidate, schema, checks = _case()
    stage = inspect_natural_final_admission_v2(
        candidate, schema, checks, now_utc=10.0)
    assert stage.status == "hold"
    assert stage.action_digest == canonical_digest(candidate.action_intent)
    assert stage.grant_digest == canonical_digest(candidate.communication_grant)
    assert stage.checks_digest == canonical_digest(checks)
    assert "d11_natural_final_bundle_admission" in stage.missing


def test_stale_checks_and_changed_payload_cannot_reach_staged_evidence():
    candidate, schema, checks = _case()
    stale = inspect_natural_final_admission_v2(
        candidate, schema, checks, now_utc=101.0)
    assert stale.status == "hold" and stale.action_digest is None
    grant = candidate.communication_grant
    changed = replace(candidate, communication_grant=replace(
        grant, segment_grants=(replace(grant.segment_grants[0],
                                        payload_digest="5" * 64),)))
    mismatch = inspect_natural_final_admission_v2(
        changed, schema, checks, now_utc=10.0)
    assert mismatch.missing == ("final_action_or_payload_grant_mismatch",)


def test_model_style_pass_and_missing_fifth_check_are_rejected():
    candidate, schema, checks = _case()
    asserted = replace(candidate, status="pass")
    assert inspect_natural_final_admission_v2(
        asserted, schema, checks, now_utc=10.0).action_digest is None
    assert inspect_natural_final_admission_v2(
        candidate, schema, checks[:-1], now_utc=10.0).missing == (
            "five_current_required_checks_absent",)


def test_natural_action_stages_four_graph_writes_but_no_check_pass():
    namespace = NamespaceId("bot", "persona")
    source = source_key(*namespace.as_tuple, "reply")
    source_version = GraphVersion(source, 1)
    audience = '["private","user"]'
    route = CurrentReplyEntityRouteBindingV2(
        namespace, "c02:reply", source.token, "platform:private",
        "sender:user", audience, "scene:private", "entity:private",
        "account:private", source_version, source_version, source_version,
        source_version, source_version, source_version, (),
        QueryEpoch(namespace, "all", 1), 100.0, "a" * 64,
    )
    identity = OperationIdentity(
        "activity:reply", "effect:reply", "attempt:reply", "prepare",
        "operation:reply", canonical_digest({"input_refs": [source.token]}))
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA, identity,
        AuthorityContext("administrator", "d11", "capability", namespace,
                         ("activity",), "expression", (audience,), "policy", 1),
        VersionGuard((source_version,), (QueryEpoch(namespace, "all", 1),),
                     0, 0, "catalogue", "scheme", "operator", "policy",
                     (), (), ()),
        SourceQualification((source.token,), "reported", 1.0, 2.0,
                            "external_report", "eligible", .8,
                            "not_applicable"),
        (source.token,), "lease:root", 50.0, 50.0, "interval", ("c02:reply",),
    )
    claim = ExpressionClaim("claim:hello", "Hello", ClaimKind.REPORTED_CLAIM,
                            (source.token,), (audience,), ("expression",),
                            source.token)
    segment = SegmentCandidate(
        "segment:hello", "effect:reply", "Hello",
        (ClaimUse("claim:hello", 0, 5, ClaimKind.REPORTED_CLAIM),),
        ("reply",), (), 0.0)
    paid = NaturalReplyPaidReviewReceiptV2(
        namespace, "original:gen", "call:gen", "1" * 64, "2" * 64,
        "3" * 64, "original:review", "call:review", "4" * 64,
        "5" * 64, "6" * 64, "lease:root", "reservation:gen",
        "reservation:review", "7" * 64, "policy:v1", "pass", "8" * 64)
    material = NaturalFinalActionMaterialV2(
        identity.activity_id, identity.operation_id, identity.effect_id,
        "c02:reply", VersionedRef(source.token, 1), "scene:private",
        audience, VersionedRef(source.token, 1), VersionedRef(source.token, 1),
        VersionedRef(source.token, 1), VersionedRef(source.token, 1),
        natural_route_semantic_digest_v2(route), ("reply",),
        ("paraphrase",), paid.qualified_units_digest, (claim,), segment,
        "9" * 64, (source_version,), paid,
    )
    final = NaturalFinalActionCandidateV2(
        "candidate_hold_w01_final_admission", material, ("d11_admission",))
    grant = BudgetLeaseGrant(
        "grant:root", 1, *namespace.as_tuple, "lease:root", "USD",
        {"cpu_ms": 10}, ("message",), 100.0, "policy")
    quote = ResourceQuote(
        "quote:reply", 1, *namespace.as_tuple, identity.activity_id,
        identity.operation_id, identity.effect_id, grant.lease_id,
        "message", "snapshot:reply", 50.0, "resource:reply", None,
        (), (), {"cpu_ms": 1}, None, 100.0)
    anchor = RestoreAnchor(
        "authority", "namespace", 1, "deletion", 0, "genesis",
        "execution", 2, "head", 0, "proof")
    kinds = BASE_REQUIRED_PROVIDERS
    sets = tuple(CurrentReplyCheckVersionV2(
        kind, "criteria:" + kind,
        (VersionedRef("criteria:" + kind, 1),)) for kind, _ in kinds)
    versions = CurrentReplyCheckVersionsV2(
        namespace, QueryEpoch(namespace, "all", 1), source.token,
        quote.quote_id, quote.version, grant.grant_id, grant.version,
        "c" * 64, sets)
    args = dict(envelope=envelope, final=final,
                current_check_versions=versions, route_binding=route,
                quote=quote, grant=grant, anchor=anchor, now_utc=10.0)
    staged = prepare_natural_final_action_stage_v2(**args)
    assert staged.status == "candidate_hold_w01_current_five_checks", staged.missing
    assert {write.key.type_name for write in staged.proposal.typed_writes} == {
        "d08.goal.v1", "d08.action_intent.v1", "d08.action_schema.v1",
        "d08.action_cancellation.v1"}
    assert staged.intent.parameters_digest != material.payload_digest
    assert staged.intent.identity.effect_id == material.final_effect_id
    assert prepare_natural_final_action_stage_v2(
        **{**args, "route_binding": replace(route,
            target_entity_ref="entity:changed")}).status == "hold"
