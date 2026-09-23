"""Admission preflight compares real candidates but cannot authorize delivery."""

from copy import deepcopy
from dataclasses import replace

from sylanne3.dispatch_runtime import DispatchRequest
from sylanne3.domains.d08 import (
    ActionIntent, ActionSchema, ActionSchemaRecord, CommunicationIntentGrant,
    GoalPredicate, RequiredCheckSpec, SegmentGrant,
)
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, D09ExpressionProvider, ExpressionClaim,
    SegmentCandidate, segment_payload_digest,
)
from sylanne3.runtime.dispatch_admission_preflight import (
    preflight_dispatch_admission,
)
from sylanne3.runtime_contracts import (
    CheckReceipt, OperationIdentity, VersionedRef, canonical_digest,
)
from sylanne3.runtime_journal import BudgetConstraint, RecoveryConstraintFootprint


def _candidates(*, source_ref="source:one", include_grant=False):
    providers = (
        ("role_binding", "d03.role_binding"),
        ("boundary", "d05.boundary"),
        ("source_grant", "d06.source_grant"),
        ("commitment_conflict", "d08.commitment_conflict"),
        ("dispatch_budget", "d11.dispatch_budget"),
    )
    specs = tuple(RequiredCheckSpec(
        kind, provider, "persona:persona", "action:one", "expression",
        f"criteria:{kind}", (VersionedRef(f"criteria:{kind}", 1),),
    ) for kind, provider in providers)
    identity = OperationIdentity(
        "activity:one", "effect:one", "attempt:one", "prepare",
        "operation:one", canonical_digest("input"),
    )
    intent = ActionIntent(
        "action:one", 1, "goal:one", (), "entity:user", "message",
        "expression", "reversible", canonical_digest("params"), identity,
        "schema:one", specs, GoalPredicate("communicated", "delivery", (), 0.0, None),
        ("message:entity:user",), None, (source_ref,),
    )
    schema = ActionSchemaRecord.bind(intent, ActionSchema("schema:one", "message", False, specs))
    refs = tuple("check:" + canonical_digest({
        "kind": item.check_kind, "provider": item.provider_id,
        "subject": item.subject_ref, "action": item.action_ref,
        "purpose": item.purpose, "criteria_version": item.criteria_version,
        "input_versions": item.required_input_versions,
    }) for item in specs)
    use = ClaimUse("claim:one", 0, 5, ClaimKind.EXTERNAL_FACT)
    payload = segment_payload_digest("Hello", (), (use,))
    grant = CommunicationIntentGrant(
        "communication-grant:" + "1" * 64, "communication:one", "contact:one", 1,
        "action:one", "action:one", 1, "entity:user", ("entity:user",),
        "expression", ("answer",), (ClaimKind.EXTERNAL_FACT.value,), (),
        (SegmentGrant("segment:one", "effect:one", 0, payload, 100, (), None,
                      refs, 100.0, 2),),
        "2" * 64, refs, 100.0, 2,
    )
    provider = D09ExpressionProvider()
    claims = (ExpressionClaim(
        "claim:one", "Hello", ClaimKind.EXTERNAL_FACT, (source_ref,),
        ("entity:user",), ("expression",), "disclosure:one",
    ),)
    blueprint = provider.prepare_blueprint(grant, "scene:one", 1, claims, now=1.0).blueprint
    assert blueprint is not None
    batch = provider.build_verified_batch_v1(
        grant, blueprint,
        (SegmentCandidate("segment:one", "effect:one", "Hello", (use,),
                          ("answer",), (), 0.0),), now=1.0,
    )
    request = DispatchRequest(
        "bot/persona", identity.operation_id, identity.activity_id,
        identity.effect_id, identity.attempt_id, canonical_digest("command"),
        "payload:one", payload, "platform:test", refs, 1, 1, 1,
        "content:one", 2,
        RecoveryConstraintFootprint(
            "bot/persona", identity.activity_id, identity.effect_id,
            communication_action="communication:one", contact_id="contact:one",
            segment_id="segment:one",
            budgets=(BudgetConstraint("parent:one", "0", "1", "1"),),
        ),
        False, grant.segment_authorization_ref("segment:one"),
        grant.segment_manifest_digest, 0, 1,
    )
    receipts = tuple(CheckReceipt(
        item.check_kind, item.subject_ref, item.action_ref, item.purpose,
        item.required_input_versions, "full", "pass", 100.0, item.provider_id,
    ) for item in specs)
    result = (schema, intent, batch, request, receipts)
    return result + (grant,) if include_grant else result


def test_matching_candidates_still_hold_on_source_and_business_graph() -> None:
    values = _candidates()
    result = preflight_dispatch_admission(
        *values, now_utc=2.0, trusted_check_verifier=lambda _spec, _receipt: True,
    )
    assert result.status == "hold"
    assert result.missing == (
        "d09.source_qualification", "dispatch.command_provenance",
        "graph.current_admission",
    )
    assert result.candidate_digest == preflight_dispatch_admission(
        *values, now_utc=2.0, trusted_check_verifier=lambda _spec, _receipt: True,
    ).candidate_digest


def test_missing_or_unverified_receipt_and_spec_hashes_cannot_pass() -> None:
    schema, intent, batch, request, receipts = _candidates()
    missing = preflight_dispatch_admission(
        schema, intent, batch, request, receipts[:-1], now_utc=2.0,
    )
    assert "check:dispatch_budget:cardinality" in missing.missing
    assert "checks.trusted_verifier" in missing.missing
    unverified = preflight_dispatch_admission(
        schema, intent, batch, request, receipts, now_utc=2.0,
        trusted_check_verifier=lambda _spec, _receipt: False,
    )
    assert "check:dispatch_budget:unverified" in unverified.missing
    wrong = preflight_dispatch_admission(
        schema, intent, batch, request,
        (replace(receipts[0], result="unknown"),) + receipts[1:], now_utc=2.0,
        trusted_check_verifier=lambda _spec, _receipt: True,
    )
    assert "check:role_binding:result" in wrong.missing


def test_changed_effect_manifest_or_payload_is_reported() -> None:
    schema, intent, batch, request, receipts = _candidates()
    wrong = replace(request, payload_digest=canonical_digest("other"),
                    segment_manifest_digest=canonical_digest("other"))
    result = preflight_dispatch_admission(
        schema, intent, batch, wrong, receipts, now_utc=2.0,
        trusted_check_verifier=lambda _spec, _receipt: True,
    )
    assert "dispatch.segment_identity" in result.missing
    assert "dispatch.segment_manifest" in result.missing
    altered = deepcopy(batch)
    altered["segments"][0]["body"] = "Tampered"
    try:
        preflight_dispatch_admission(
            schema, intent, altered, request, receipts, now_utc=2.0,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("tampered D09 batch must fail validation")


def test_changed_frozen_schema_and_missing_budget_are_reported() -> None:
    schema, intent, batch, request, receipts = _candidates()
    changed_intent = replace(intent, target_ref="entity:other")
    no_budget = replace(request, footprint=replace(request.footprint, budgets=()))
    result = preflight_dispatch_admission(
        schema, changed_intent, batch, no_budget, receipts, now_utc=2.0,
        trusted_check_verifier=lambda _spec, _receipt: True,
    )
    assert "d08.frozen_schema" in result.missing
    assert "dispatch.budget_footprint" in result.missing
