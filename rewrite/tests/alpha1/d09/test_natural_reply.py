"""Language-v2 natural wording stops at independent semantic-review HOLD."""

from dataclasses import replace
import sqlite3
import pytest

from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.domains.d06.qualified_expression import (
    QualifiedExpressionRequest, SourceTextSpan, prepare_qualified_expression_unit,
)
from sylanne3.domains.d09 import (
    ClaimKind, NaturalExpressionPlanV2, QualifiedExpressionUnitV2,
    D09ExpressionPolicyV1,
    NaturalReviewCandidateV2, prepare_natural_final_action_candidate_v2,
    mechanically_verify_natural_reply_v2,
    verify_current_qualified_natural_reply_v2,
    assess_untrusted_natural_review_v2,
)
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner,
)
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import NamespaceId, VersionedRef
from sylanne3.runtime_contracts import (
    NaturalReplyGenerationOriginalSealV2, NaturalReplyReviewOriginalSealV2,
    NaturalReplyPaidReviewReceiptV2,
    canonical_digest,
)
from sylanne3.domains.d08.natural_plan import AdoptedNaturalPlanV2
from sylanne3.domains.d08.natural_final import (
    natural_final_action_parameters_digest_v2,
    prepare_natural_final_communication_candidate_v2,
)
from sylanne3.domains.d08.execution import (
    ActionIntent, ActionSchema, GoalPredicate, RequiredCheckSpec,
    BASE_REQUIRED_PROVIDERS,
)
from sylanne3.runtime_contracts import OperationIdentity
from sylanne3.runtime.d12_domain_scheme_compile_v1 import (
    D12ExpressionPolicyCandidateV1, EXPRESSION_POLICY_FIELD,
    compile_d12_domain_scheme_candidate_v1,
)
from sylanne3.runtime.d12_compiled_candidate_store_v1 import (
    install_d12_compiled_candidate_store_v1,
    record_d12_domain_candidate_v1, verify_d12_domain_candidate_v1,
)
from sylanne3.domains.d12.scheme_command import D12DomainCompileRejectionV1
from sylanne3.model_broker.natural_review import (
    NaturalReviewInstallationV1, freeze_natural_reply_review_v1,
    parse_natural_reply_review_output_v1,
)


def _case():
    namespace = NamespaceId("bot", "persona")
    source = source_key("bot", "persona", "door")
    access = access_key("bot", "persona", "door")
    correction = source_correction_head_key(namespace, "door")
    plan = AtomKey(Owner("activity", "bot", "persona", "activity:reply"),
                   "d08.natural_expression_plan.v2", "plan:reply")
    scene = AtomKey(Owner("scene", "bot", "persona", "scene:private"),
                    "d09.topic_thread.v1", "scene:private")
    audience = AtomKey(Owner("persona", "bot", "persona"),
                       "d09.conversation_track.v1", "conversation:private")
    unit = QualifiedExpressionUnitV2(
        "basis:door", ClaimKind.REPORTED_CLAIM, "The door opened.",
        None, (VersionedRef(source.token, 1),),
        (VersionedRef(access.token, 2),), (VersionedRef(correction.token, 0),),
        audience.token, "expression", 150.0,
        speaker_id="speaker:user", content_reality="external_report",
        qualification_digest="a" * 64, source_kind="user_message",
        assertion_status="reported", d06_claim_kind="attributed_report",
        attribution_required=True, polarity_status="positive",
        source_excerpt="The door opened.", evidence_span=(0, 16),
    )
    expression = NaturalExpressionPlanV2(
        namespace, VersionedRef(plan.token, 1), VersionedRef(scene.token, 1),
        VersionedRef(audience.token, 1), ("answer",), ("paraphrase", "direct_quote"),
        (), (unit,), 140.0,
        "activity:reply", "operation:reply", "effect:reply",
        "scene:private", audience.token,
    )
    reads = (GraphVersion(plan, 1), GraphVersion(scene, 1),
             GraphVersion(audience, 1), GraphVersion(source, 1),
             GraphVersion(access, 2), GraphVersion(correction, 0))
    output = {
        "schema": "sylanne.d09.context_reply_output.v2",
        "body": "The door was opened.",
        "units": [{"start": 0, "end": 20, "kind": "reported_claim",
                   "basis_ids": ["basis:door"], "speech_act": "paraphrase",
                   "promise_grant_id": None, "slot_ids": ["answer"]}],
    }
    return expression, reads, output


def test_natural_paraphrase_mechanical_pass_still_requires_paid_semantic_review():
    plan, reads, output = _case()
    result = mechanically_verify_natural_reply_v2(output, plan=plan,
                                                   current_reads=reads, now_utc=110.0)
    assert result.status == "mechanical_verified_semantic_hold"
    assert result.segment.body == "The door was opened."
    assert result.segment.effect_id == plan.final_effect_id
    assert result.source_refs == (plan.units[0].source_refs[0].ref,)
    assert result.missing == (
        "current_qualification_recompute", "independent_paid_semantic_review",
    )


@pytest.mark.parametrize(("first_items", "last_item"), (
    ("- First report.\n", "- Second report."),
    ("1. First report.\n", "2. Second report."),
    ("- First report.\n  Nested detail.\n", "- Second report."),
    ("- First report.\n\n", "- Second report."),
))
def test_semantic_bubbles_keep_a_complete_list_across_qualified_claims(first_items, last_item):
    from sylanne3.domains.d09.natural_reply import natural_semantic_ranges_v3

    plan, reads, old = _case()
    split, list_end = len(first_items), len(first_items + last_item)
    body = first_items + last_item + "\n\nAfterward, the report ended."
    output = {"schema": "sylanne.d09.context_reply_output.v3", "body": body,
        "units": [{**old["units"][0], "start": start, "end": end}
                  for start, end in ((0, split), (split, list_end), (list_end, len(body)))],
        "semantic_segments": [{"start": 0, "end": list_end},
                              {"start": list_end, "end": len(body)}]}
    # Both current references and individual claim boundaries are valid. A
    # complete list may be followed by another bubble, still requiring C6.
    result = mechanically_verify_natural_reply_v2(
        output, plan=plan, current_reads=reads, now_utc=110.0)
    assert result.status == "mechanical_verified_semantic_hold"
    assert "independent_paid_semantic_review" in result.missing
    output["semantic_segments"] = [{"start": 0, "end": split},
                                   {"start": split, "end": len(body)}]
    with pytest.raises(ValueError, match="semantic boundary splits a Markdown list block"):
        natural_semantic_ranges_v3(output)
    refused = mechanically_verify_natural_reply_v2(
        output, plan=plan, current_reads=reads, now_utc=110.0)
    assert refused.status == "hold"
    assert refused.missing == ("output_semantic_manifest",)


def test_d09_typed_visible_limit_compiles_and_changes_natural_reply_eligibility():
    plan, reads, output = _case()
    assert len(output["body"]) == 20
    payload = {
        "policy_ref": "policy:d09:short", "policy_version": "1",
        "max_visible_chars": 19, "schema": "d09.expression_policy.v1",
    }
    fields = ((EXPRESSION_POLICY_FIELD, payload, "administrative_edit"),)
    draft_digest = "d" * 64
    candidate = compile_d12_domain_scheme_candidate_v1(
        namespace=plan.namespace, draft_digest=draft_digest, domain="d09",
        fields=fields,
        field_input_digest=canonical_digest((draft_digest, "d09", fields)),
    )
    assert type(candidate) is D12ExpressionPolicyCandidateV1
    assert candidate.status == "typed_candidate_not_persisted"
    assert candidate.policy == D09ExpressionPolicyV1(**payload)
    with sqlite3.connect(":memory:") as db:
        db.execute("BEGIN")
        install_d12_compiled_candidate_store_v1(db)
        receipt = record_d12_domain_candidate_v1(db, plan.namespace, candidate)
        assert verify_d12_domain_candidate_v1(db, plan.namespace, candidate, receipt)
        assert not verify_d12_domain_candidate_v1(
            db, plan.namespace, candidate,
            replace(receipt, candidate_ref="d12-domain-candidate:wrong"),
        )
    assert mechanically_verify_natural_reply_v2(
        output, plan=plan, current_reads=reads, now_utc=110.0,
    ).status == "mechanical_verified_semantic_hold"
    assert mechanically_verify_natural_reply_v2(
        output, plan=plan, current_reads=reads, now_utc=110.0,
        expression_policy=candidate.policy,
    ).missing == ("expression_policy_max_visible_chars",)
    assert mechanically_verify_natural_reply_v2(
        output, plan=plan, current_reads=reads, now_utc=110.0,
        expression_policy=D09ExpressionPolicyV1(**(payload | {"max_visible_chars": 20})),
    ).status == "mechanical_verified_semantic_hold"
    for changed in (payload | {"max_visible_chars": True},
                    payload | {"max_visible_chars": 0},
                    payload | {"max_visible_chars": 2049},
                    payload | {"extra": 1}):
        fields = ((EXPRESSION_POLICY_FIELD, changed, "administrative_edit"),)
        rejected = compile_d12_domain_scheme_candidate_v1(
            namespace=plan.namespace, draft_digest=draft_digest, domain="d09",
            fields=fields,
            field_input_digest=canonical_digest((draft_digest, "d09", fields)),
        )
        assert type(rejected) is D12DomainCompileRejectionV1
        assert rejected.diagnostics[0].code == "invalid_expression_policy"


def test_natural_reply_cannot_claim_semantic_truth_from_coverage_or_stale_source():
    plan, reads, output = _case()
    altered = dict(output, body="The door was locked.")
    # Character coverage alone cannot establish semantic truth.
    assert mechanically_verify_natural_reply_v2(
        altered, plan=plan, current_reads=reads, now_utc=110.0,
    ).status == "mechanical_verified_semantic_hold"
    stale = tuple(replace(row, revision=3) if row.key.type_name == "memory.access"
                  else row for row in reads)
    assert mechanically_verify_natural_reply_v2(
        output, plan=plan, current_reads=stale, now_utc=110.0,
    ).missing == ("qualified_source_changed",)
    quoted = dict(output, units=[dict(output["units"][0], speech_act="direct_quote")])
    assert mechanically_verify_natural_reply_v2(
        quoted, plan=plan, current_reads=reads, now_utc=110.0,
    ).missing == ("quote_mismatch",)


def test_exact_excerpt_that_reverses_source_context_still_semantic_review_hold():
    plan, reads, _ = _case()
    # Qualified text may be an exact excerpt of “他说已付款，但实际没有”.
    # Its exact bytes alone cannot authorize the implied payment fact.
    plan = replace(plan, units=(replace(
        plan.units[0], qualified_text="已付款", direct_quote=True,
        source_excerpt="他说已付款，但实际没有", evidence_span=(0, 11),
        direct_quote_span=(2, 5), negation_cue_span=(7, 9),
    ),))
    output = {
        "schema": "sylanne.d09.context_reply_output.v2", "body": "已付款",
        "units": [{"start": 0, "end": 3, "kind": "reported_claim",
                   "basis_ids": ["basis:door"], "speech_act": "direct_quote",
                   "promise_grant_id": None, "slot_ids": ["answer"]}],
    }
    result = mechanically_verify_natural_reply_v2(
        output, plan=plan, current_reads=reads, now_utc=110.0,
    )
    assert result.status == "mechanical_verified_semantic_hold"
    assert result.missing == (
        "current_qualification_recompute", "independent_paid_semantic_review",
    )


def _current_case():
    plan, _, output = _case()
    namespace = plan.namespace
    source = source_key(*namespace.as_tuple, "door")
    access = access_key(*namespace.as_tuple, "door")
    correction = source_correction_head_key(namespace, "door")
    text = "The door opened."
    record = SourceRecord(
        "door", text, "speaker:user", "reported", "reported", 3.0, 4.0,
        "family", (plan.audience_ref.ref,), ("expression",), (),
    )
    atoms = (
        GraphAtom(source, 1, record.to_dict()),
        GraphAtom(access, 2, {"source_id": "door",
                              "audiences": [plan.audience_ref.ref],
                              "purposes": ["expression"], "status": "active",
                              "recorded_at": 4.0}),
        GraphAtom(correction, 0, {}, False),
        GraphAtom(AtomKey.from_token(plan.plan_ref.ref), 1, {}),
        GraphAtom(AtomKey.from_token(plan.scene_ref.ref), 1, {}),
        GraphAtom(AtomKey.from_token(plan.audience_ref.ref), 1, {}),
    )
    snapshot = GraphSnapshot(atoms, (NamespaceEpoch(*namespace.as_tuple, 5),))
    candidate = prepare_qualified_expression_unit(
        snapshot, namespace=namespace,
        request=QualifiedExpressionRequest(
            source.token, "attributed_report", SourceTextSpan(0, len(text)),
        ),
        audiences=(plan.audience_ref.ref,), access_epoch=2,
        deletion_epoch=0, valid_until=140.0,
    )
    unit = replace(
        plan.units[0], source_refs=tuple(
            VersionedRef(ref, next(row.revision for row in candidate.read_versions
                                   if row.key.token == ref))
            for ref in candidate.lineage_source_refs
        ),
        access_refs=tuple(VersionedRef(row.key.token, row.revision)
                          for row in candidate.read_versions
                          if row.key.type_name == "memory.access"),
        correction_refs=tuple(VersionedRef(row.key.token, row.revision)
                              for row in candidate.read_versions
                              if row.key.type_name == "d06.source_correction_head.v1"),
        qualification_digest=candidate.qualification_digest,
        expires_at_utc=candidate.valid_until,
        qualified_text=candidate.source_excerpt,
        speaker_id=candidate.speaker_id, occurred_at=candidate.occurred_at,
        learned_at=candidate.learned_at, source_kind=candidate.source_kind,
        assertion_status=candidate.assertion_status,
        attribution_required=candidate.attribution_required,
        polarity_status=candidate.polarity_status,
        source_excerpt=candidate.source_excerpt,
        evidence_span=(candidate.evidence_span.start, candidate.evidence_span.end),
    )
    plan = replace(plan, units=(unit,))
    reads = tuple(GraphVersion(atom.key, atom.revision) for atom in atoms)
    return plan, snapshot, (candidate,), reads, output


def test_current_d06_recompute_retains_semantic_hold_and_blocks_revocation():
    plan, snapshot, candidates, reads, output = _current_case()
    result = verify_current_qualified_natural_reply_v2(
        output, plan=plan, current_snapshot=snapshot,
        d06_candidates=candidates, current_reads=reads,
        access_epoch=2, deletion_epoch=0, now_utc=10.0,
    )
    assert result.status == "current_qualification_verified_semantic_hold"
    assert result.missing == ("independent_paid_semantic_review",)
    capped = verify_current_qualified_natural_reply_v2(
        output, plan=plan, current_snapshot=snapshot,
        d06_candidates=candidates, current_reads=reads,
        access_epoch=2, deletion_epoch=0, now_utc=10.0,
        expression_policy=D09ExpressionPolicyV1(
            "policy:d09:short", "1", len(output["body"]) - 1,
        ),
    )
    assert capped.missing == ("expression_policy_max_visible_chars",)
    assert assess_untrusted_natural_review_v2(result, None, None).status == "hold"
    revoked = replace(snapshot, atoms=tuple(
        replace(atom, value={**atom.value, "status": "revoked"})
        if atom.key.type_name == "memory.access" else atom
        for atom in snapshot.atoms
    ))
    assert verify_current_qualified_natural_reply_v2(
        output, plan=plan, current_snapshot=revoked,
        d06_candidates=candidates, current_reads=reads,
        access_epoch=2, deletion_epoch=0, now_utc=10.0,
    ).missing == ("d06_qualification_recompute_failed",)
    assert verify_current_qualified_natural_reply_v2(
        output, plan=plan, current_snapshot=snapshot,
        d06_candidates=candidates, current_reads=reads,
        access_epoch=2, deletion_epoch=1, now_utc=10.0,
    ).missing == ("d06_qualification_recompute_failed",)


def test_untrusted_nested_basis_and_slot_ids_are_bounded_holds():
    plan, reads, output = _case()
    for changed in ({"basis_ids": [["basis:door"]]},
                    {"slot_ids": [{"slot": "answer"}]}):
        malformed = dict(output, units=[dict(output["units"][0], **changed)])
        result = mechanically_verify_natural_reply_v2(
            malformed, plan=plan, current_reads=reads, now_utc=110.0,
        )
        assert result.status == "hold"
        assert result.missing == ("unit_scope",)


def test_negation_shift_model_pass_is_only_untrusted_review_candidate_and_old_draft_holds():
    plan, snapshot, candidates, reads, output = _current_case()
    output = dict(output, body="The door never opened.", units=[
        dict(output["units"][0], end=len("The door never opened."))
    ])
    mechanical = verify_current_qualified_natural_reply_v2(
        output, plan=plan, current_snapshot=snapshot,
        d06_candidates=candidates, current_reads=reads,
        access_epoch=2, deletion_epoch=0, now_utc=10.0,
    )
    assert mechanical.status == "current_qualification_verified_semantic_hold"
    generation = NaturalReplyGenerationOriginalSealV2(
        namespace=plan.namespace, c02_operation_id="c02", source_ref="source",
        installation_id="generation-installation", provider_config_digest="a" * 64,
        job_id="generation-job", original_operation_id="generation-original",
        acquire_operation_id="generation-acquire", call_id="generation-call",
        frozen_input_digest="b" * 64,
        qualified_units_digest=canonical_digest(plan.units),
        model_request_digest="c" * 64, original_graph_guard_digest="d" * 64,
        parent_budget_lease_id="budget", reservation_operation_id="reserve",
    )
    frozen = freeze_natural_reply_review_v1(
        generation, output, plan.units, (), "policy:1",
            NaturalReviewInstallationV1("review-installation", "provider:review",
                                        "e" * 64, "review-model"),
    )
    review = NaturalReplyReviewOriginalSealV2(
        namespace=plan.namespace, installation_id="review-installation",
        provider_config_digest="e" * 64, job_id="review-job",
        original_operation_id="review-original",
        acquire_operation_id="review-acquire", call_id="review-call",
        generation_original_operation_id="generation-original",
        generation_call_id="generation-call",
        generation_frozen_input_digest=generation.frozen_input_digest,
        generation_output_digest=frozen.generation_output_digest,
        qualified_units_digest=frozen.qualified_units_digest,
        review_frozen_input_digest=frozen.digest,
        model_request_digest=frozen.wire_digest,
        original_graph_guard_digest="f" * 64,
        parent_budget_lease_id="budget", reservation_operation_id="review-reserve",
        review_policy_version="policy:1",
    )
    parsed = parse_natural_reply_review_output_v1(
        '{"schema":"sylanne.d09.natural_review_output.v1","verdict":"pass","issues":[]}',
        frozen, generation, review,
    )
    assessed = assess_untrusted_natural_review_v2(mechanical, frozen, parsed)
    assert assessed.status == "untrusted_semantic_pass_authority_hold"
    assert "paid_review_authority_receipt" in assessed.missing
    old = replace(frozen, generation_output_digest="0" * 64)
    assert assess_untrusted_natural_review_v2(mechanical, old, parsed).missing == (
        "review_bound_to_old_generation_or_basis",
    )


def test_opaque_promise_grant_stays_hold_even_when_listed():
    plan, reads, output = _case()
    grant = VersionedRef(AtomKey.from_token(plan.plan_ref.ref).token, 1)
    plan = replace(plan, promise_grants=(grant,),
                   allowed_speech_acts=("promise", "paraphrase"))
    output = dict(output, units=[dict(output["units"][0],
                                 speech_act="promise", promise_grant_id=grant.ref)])
    assert mechanically_verify_natural_reply_v2(
        output, plan=plan, current_reads=reads, now_utc=110.0,
    ).missing == ("promise_scope_unavailable",)


def test_paraphrase_label_cannot_hide_a_future_commitment():
    plan, reads, output = _case()
    body = "I will open the door tomorrow."
    disguised = dict(output, body=body, units=[
        dict(output["units"][0], end=len(body), speech_act="paraphrase")])
    assert mechanically_verify_natural_reply_v2(
        disguised, plan=plan, current_reads=reads, now_utc=110.0,
    ).missing == ("possible_unscoped_commitment",)


def test_final_natural_material_requires_verified_paid_originals_and_current_scope():
    plan, snapshot, candidates, reads, output = _current_case()
    source = plan.units[0].source_refs[0]
    adopted = AdoptedNaturalPlanV2(
        schema="d08.natural_expression_plan.v2",
        plan_id=AtomKey.from_token(plan.plan_ref.ref).name,
        c02_operation_id="operation:c02", source_ref=source,
        final_activity_id=plan.final_activity_id,
        final_operation_id=plan.final_operation_id,
        final_effect_id=plan.final_effect_id,
        focus_ref=plan.scene_ref, ticket_ref=plan.scene_ref,
        preparation_evidence_digest="a" * 64,
        route_binding_digest="b" * 64,
        parent_budget_lease_id="budget:root", budget_grant_version=1,
        budget_grant_digest="c" * 64,
        generation_reservation_id="reservation:generation",
        review_reservation_id="reservation:review",
        generation_ceiling=(("tokens", 100),),
        review_ceiling=(("tokens", 50),),
        scene_id=plan.scene_id, audience_id=plan.audience_id,
        scene_ref=plan.scene_ref, audience_ref=plan.audience_ref,
        required_slots=plan.required_slots,
        allowed_speech_acts=plan.allowed_speech_acts,
        promise_grants=(), qualified_units_digest=canonical_digest(plan.units),
        d06_qualification_digests=(candidates[0].qualification_digest,),
        qualification_refs=(), qualified_read_versions=reads[1:],
        valid_until_utc=plan.valid_until_utc,
    )
    review = NaturalReviewCandidateV2(
        "untrusted_semantic_pass_authority_hold", canonical_digest(output),
        "d" * 64, "policy:v1", (),
    )
    paid = NaturalReplyPaidReviewReceiptV2(
        plan.namespace, "original:generation", "call:generation", "e" * 64,
        "f" * 64, canonical_digest(output), "original:review", "call:review",
        "1" * 64, "2" * 64, review.review_output_digest, "budget:root",
        adopted.generation_reservation_id, adopted.review_reservation_id,
        adopted.qualified_units_digest, review.review_policy_version,
        "pass", "3" * 64,
    )

    def assemble(**changes):
        args = dict(plan=plan, adopted=adopted, generation_output=output,
                    review=review, paid_receipt=paid, current_snapshot=snapshot,
                    d06_candidates=candidates, current_reads=reads,
                    access_epoch=2, deletion_epoch=0, now_utc=10.0,
                    paid_verifier=None)
        args.update(changes)
        return prepare_natural_final_action_candidate_v2(**args)

    assert assemble().missing == ("authority_paid_receipt_required_hold",)

    class VerifiedOriginals:
        def verify_current_paid_review_v2(self, receipt, **kwargs):
            return (receipt == paid and kwargs["generation_output"] == output
                    and kwargs["adopted"] == adopted)

    result = assemble(paid_verifier=VerifiedOriginals())
    assert result.status == "candidate_hold_w01_final_admission"
    assert result.material.segment.effect_id == plan.final_effect_id
    assert result.material.paid_receipt == paid
    assert result.material.route_binding_digest == adopted.route_binding_digest
    assert "payload_bound_communication_grant" in result.missing
    assert assemble(paid_verifier=VerifiedOriginals(),
                    paid_receipt=replace(paid, review_terminal_receipt_digest="4" * 64)
                    ).status == "hold"
    assert assemble(paid_verifier=VerifiedOriginals(),
                    review=replace(review, generation_output_digest="5" * 64)
                    ).status == "hold"
    changed_output = dict(output, body="The door was locked.")
    assert assemble(paid_verifier=VerifiedOriginals(),
                    generation_output=changed_output).status == "hold"
    assert assemble(paid_verifier=VerifiedOriginals(),
                    adopted=replace(adopted, route_binding_digest="6" * 64)
                    ).status == "hold"

    action_id = "action:reply"
    action_ref = AtomKey(Owner("activity", "bot", "persona",
                               plan.final_activity_id),
                         "d08.action_intent.v1", action_id).token
    checks = tuple(RequiredCheckSpec(
        kind, provider, action_id, action_id, "expression",
        plan.plan_ref.ref, (plan.plan_ref,),
    ) for kind, provider in BASE_REQUIRED_PROVIDERS)
    schema = ActionSchema("schema:natural-reply", "communication", False, checks)
    intent = ActionIntent(
        action_id, 1, "goal:reply", (), plan.audience_id,
        "communication", "expression", "limited",
        natural_final_action_parameters_digest_v2(result.material),
        OperationIdentity(plan.final_activity_id, plan.final_effect_id,
                          "attempt:reply", "prepare", plan.final_operation_id,
                          "9" * 64),
        schema.schema_id, checks,
        GoalPredicate("communicated", "d11", (), 0.0, None),
        (plan.final_effect_id,), None, (source.ref,),
    )

    def final_mapping(**changes):
        args = dict(
            final=result, plan=plan, adopted=adopted, intent=intent,
            intent_ref=action_ref, schema=schema, contact_id="contact:private",
            communication_action_id="communication:reply",
            grant_id="communication-grant:reply", batch_revision=1,
            cancellation_epoch=0,
            required_check_refs=tuple("check:" + kind for kind, _ in BASE_REQUIRED_PROVIDERS),
            qualification_receipt_digest="8" * 64, valid_until=100.0,
        )
        args.update(changes)
        return prepare_natural_final_communication_candidate_v2(**args)

    mapped = final_mapping()
    assert mapped.status == "candidate_hold_w01_final_admission"
    assert mapped.communication_grant.segment_grants[0].payload_digest == result.material.payload_digest
    assert mapped.communication_grant.segment_grants[0].effect_id == plan.final_effect_id
    assert "d11_final_admission" in mapped.missing
    assert final_mapping(final=replace(result, material=replace(
        result.material, segment=replace(result.material.segment,
                                         body="The door was locked.")))).status == "hold"
    assert final_mapping(final=replace(result, material=replace(
        result.material, current_reads=(reads[0],)))).status == "hold"
    assert final_mapping(intent=replace(intent, identity=replace(
        intent.identity, effect_id="effect:wrong"))).status == "hold"
