"""Natural paid batch is a separate content record and remains HOLD."""

from dataclasses import replace

import pytest

from sylanne3.domains.d08.execution import (
    CommunicationIntentGrant, SegmentGrant,
)
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, D09ExpressionProvider, ExpressionClaim,
    NATURAL_BATCH_SCHEMA_V2, SegmentCandidate, segment_payload_digest,
    prepare_natural_verified_batch_proposal_v2,
    validate_natural_verified_batch_value_v2,
)
from sylanne3.domains.d09.natural_reply import (
    NaturalFinalActionCandidateV2, NaturalFinalActionMaterialV2,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.runtime_contracts import (
    NamespaceId, NaturalReplyPaidReviewReceiptV2, VersionedRef,
    canonical_digest,
)


def _case():
    namespace = NamespaceId("bot", "persona")
    source_key = AtomKey(Owner("persona", "bot", "persona"),
                         "d06.source_record.v1", "source:reply")
    source = VersionedRef(source_key.token, 1)
    scene = VersionedRef(AtomKey(Owner("scene", "bot", "persona", "scene:private"),
                                 "d09.topic_thread.v1", "scene:private").token, 1)
    audience = VersionedRef(AtomKey(Owner("persona", "bot", "persona"),
                                    "d09.conversation_track.v1", "audience:private").token, 1)
    body = "Hello."
    claim = ExpressionClaim("claim:hello", body, ClaimKind.RHETORIC, (),
                            ("audience:private",), ("expression",), source.ref)
    use = ClaimUse(claim.claim_id, 0, len(body), claim.kind)
    segment = SegmentCandidate("segment:hello", "effect:reply", body,
                               (use,), ("reply",), (), 0.0)
    payload = segment_payload_digest(body, (), (use,))
    paid = NaturalReplyPaidReviewReceiptV2(
        namespace, "original:gen", "call:gen", "a" * 64, "b" * 64,
        "c" * 64, "original:review", "call:review", "d" * 64,
        "e" * 64, "f" * 64, "budget:root", "reserve:gen",
        "reserve:review", "1" * 64, "policy:v1", "pass", "2" * 64,
    )
    material = NaturalFinalActionMaterialV2(
        "activity:reply", "operation:reply", "effect:reply",
        "operation:c02", source, "scene:private", "audience:private",
        scene, audience, scene, scene, "3" * 64, ("reply",),
        ("paraphrase",), paid.qualified_units_digest, (claim,), segment,
        payload, (GraphVersion(source_key, 1),), paid,
    )
    refs = ("check:" + "4" * 64,)
    grant_segment = SegmentGrant("segment:hello", "effect:reply", 0,
                                 payload, len(body), (), None, refs, 100.0, 0)
    grant = CommunicationIntentGrant(
        "communication-grant:reply", "communication:reply", "contact:private",
        1, "action-ref:reply", "action:reply", 1, "entity:private",
        ("audience:private",), "expression", ("reply",), ("rhetoric",), (),
        (grant_segment,), "5" * 64, refs, 100.0, 0,
        route_binding_digest=material.route_binding_digest,
    )
    return NaturalFinalActionCandidateV2(
        "candidate_hold_w01_final_admission", material, ("d11_admission",)), grant


def test_natural_batch_keeps_both_original_paid_identities_and_body():
    final, grant = _case()
    proposal = prepare_natural_verified_batch_proposal_v2(final, grant)
    assert proposal.status == "candidate_hold_w01_final_admission"
    assert proposal.write.key.type_name == NATURAL_BATCH_SCHEMA_V2
    value = proposal.write.value
    assert value["segment"]["body"] == "Hello."
    assert value["paid_review"]["generation_original_operation_id"] == "original:gen"
    assert value["paid_review"]["review_original_operation_id"] == "original:review"
    assert value["segment"]["effect_id"] == final.material.final_effect_id
    assert D09ExpressionProvider.register_types()
    validate_natural_verified_batch_value_v2(value)
    assert "d11_final_admission" in proposal.missing


def test_natural_batch_rejects_payload_change_and_collapsed_paid_ids():
    final, grant = _case()
    changed = replace(final, material=replace(
        final.material, segment=replace(final.material.segment, body="Bye.")))
    assert prepare_natural_verified_batch_proposal_v2(changed, grant).write is None
    value = prepare_natural_verified_batch_proposal_v2(final, grant).write.value
    value["paid_review"]["review_original_operation_id"] = "original:gen"
    value["batch_digest"] = canonical_digest({
        key: part for key, part in value.items() if key != "batch_digest"})
    with pytest.raises(ValueError, match="distinct paid originals"):
        validate_natural_verified_batch_value_v2(value)


def test_semantic_bubbles_preserve_paid_originals_and_have_distinct_stable_effects():
    from sylanne3.domains.d09.natural_reply import (
        NATURAL_REPLY_OUTPUT_SCHEMA_V3, select_natural_final_segment_v3,
    )
    from sylanne3.domains.d09.natural_batch import (
        NATURAL_BATCH_SCHEMA_V3, prepare_natural_verified_batch_proposal_v3,
        validate_natural_verified_batch_value_v3,
    )
    from rewrite.tests.alpha1.d09.test_natural_reply import _case as expression_case
    final, grant = _case()
    plan, _, _ = expression_case()
    plan = replace(plan, final_operation_id=final.material.final_operation_id,
                   final_effect_id=final.material.final_effect_id)
    body = "Hello. Good day."
    spans = ((0, 6), (7, 16))
    output = {"schema": NATURAL_REPLY_OUTPUT_SCHEMA_V3, "body": body,
              "units": [{"start": start, "end": end, "kind": "rhetoric",
                         "basis_ids": ["basis:hello"], "speech_act": "paraphrase",
                         "promise_grant_id": None, "slot_ids": ["reply"]}
                        for start, end in spans],
              "semantic_segments": [{"start": 0, "end": 7}, {"start": 7, "end": 16}]}
    claims = tuple(ExpressionClaim("natural-unit:" + canonical_digest({
        "output": canonical_digest(output), "index": index, "basis": ["basis:hello"]}),
        body[start:end], ClaimKind.RHETORIC, (), (final.material.audience_id,),
        ("expression",), final.material.source_ref.ref)
        for index, (start, end) in enumerate(spans))
    uses = tuple(ClaimUse(claim.claim_id, start, end, claim.kind)
                 for claim, (start, end) in zip(claims, spans))
    material = replace(final.material, claims=claims,
                       segment=replace(final.material.segment, body=body, claim_uses=uses),
                       paid_receipt=replace(final.material.paid_receipt,
                                            generation_output_digest=canonical_digest(output)))
    full = replace(final, material=material)
    values = []
    for index in range(2):
        selected = select_natural_final_segment_v3(full, plan=plan,
                                                  generation_output=output, segment_index=index)
        segment = selected.material.segment
        scoped_grant = replace(grant, segment_grants=(replace(
            grant.segment_grants[0], segment_id=segment.segment_id, effect_id=segment.effect_id,
            payload_digest=selected.material.payload_digest, max_chars=len(segment.body)),))
        proposal = prepare_natural_verified_batch_proposal_v3(
            selected, scoped_grant, plan=plan, generation_output=output, segment_index=index)
        assert proposal.write.key.type_name == NATURAL_BATCH_SCHEMA_V3
        value = proposal.write.value
        assert value["paid_review"]["generation_original_operation_id"] == "original:gen"
        assert value["segment"]["position"] == 0
        assert value["semantic_manifest"]["selected_index"] == index
        assert value["semantic_manifest"]["generation_output"] == output
        validate_natural_verified_batch_value_v3(value)
        values.append(value)
    assert values[0]["effect_id"] != values[1]["effect_id"]
    assert values[0]["operation_id"] != values[1]["operation_id"]
    changed = {**values[1], "segment": {**values[1]["segment"], "body": "Changed."}}
    changed["batch_digest"] = canonical_digest({key: part for key, part in changed.items() if key != "batch_digest"})
    with pytest.raises(ValueError, match="selected semantic bubble"):
        validate_natural_verified_batch_value_v3(changed)
