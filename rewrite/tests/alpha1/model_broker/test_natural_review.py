"""Independent review wire is frozen and parses only an untrusted candidate."""

import json

import pytest

from sylanne3.runtime_contracts import (
    NamespaceId, NaturalReplyGenerationOriginalSealV2,
    NaturalReplyReviewOriginalSealV2, canonical_digest,
)
from sylanne3.model_broker.natural_review import (
    OUTPUT_SCHEMA, NaturalReviewInstallationV1,
    freeze_natural_reply_review_v1, parse_natural_reply_review_output_v1,
)
from rewrite.tests.alpha1.d09.test_natural_reply import _case


def _frozen_and_seals(output=None):
    plan, _, original = _case()
    generation_output = output or original
    generation = NaturalReplyGenerationOriginalSealV2(
        NamespaceId("bot", "persona"), "c02:one", "source:one", "install:review",
        "a" * 64, "generation-job", "generation-original", "generation-acquire",
        "generation-call", "b" * 64, canonical_digest(plan.units), "c" * 64,
        "d" * 64, "parent-budget", "generation-reservation",
    )
    installation = NaturalReviewInstallationV1(
        "install:review", "provider:review", "a" * 64, "review-model",
    )
    frozen = freeze_natural_reply_review_v1(
        generation, generation_output, plan.units, (), "policy:natural-review:1",
        installation,
    )
    review = NaturalReplyReviewOriginalSealV2(
        generation.namespace, installation.installation_id,
        installation.provider_config_digest, "review-job", "review-original",
        "review-acquire", "review-call", generation.original_operation_id,
        generation.call_id, generation.frozen_input_digest,
        frozen.generation_output_digest, generation.qualified_units_digest,
        frozen.digest, frozen.wire_digest, "e" * 64,
        generation.parent_budget_lease_id, "review-reservation",
        frozen.review_policy_version,
    )
    return generation, frozen, review


def _pass_text():
    return json.dumps({"schema": OUTPUT_SCHEMA, "verdict": "pass", "issues": []})


def test_review_freeze_is_bound_to_generation_output_and_same_qualified_basis():
    generation, frozen, review = _frozen_and_seals()
    parsed = parse_natural_reply_review_output_v1(
        _pass_text(), frozen, generation, review,
    )
    assert parsed.generation_frozen_input_digest == generation.frozen_input_digest
    assert parsed.generation_output_digest == frozen.generation_output_digest
    assert parsed.verdict == "pass"
    assert parsed.status == "untrusted_review_candidate"
    assert not hasattr(parsed, "authority_result_read")


def test_provider_identity_is_explicit_in_exact_wire_and_changes_wire_digest():
    generation, frozen, _ = _frozen_and_seals()
    wire = json.loads(frozen.canonical_wire)
    assert wire["provider_id"] == "provider:review"
    plan, _, output = _case()
    alternate = NaturalReviewInstallationV1(
        "install:review", "provider:other", "a" * 64, "review-model",
    )
    other = freeze_natural_reply_review_v1(
        generation, output, plan.units, (), "policy:natural-review:1", alternate,
    )
    assert json.loads(other.canonical_wire)["provider_id"] == "provider:other"
    assert other.wire_digest != frozen.wire_digest


def test_review_installation_requires_provider_id():
    with pytest.raises(ValueError, match="installation identity"):
        NaturalReviewInstallationV1("install:review", "", "a" * 64, "review-model")


def test_replaced_generation_output_digest_does_not_bind_to_review_seal():
    generation, frozen, review = _frozen_and_seals()
    replaced = NaturalReplyReviewOriginalSealV2(
        review.namespace, review.installation_id, review.provider_config_digest,
        review.job_id, review.original_operation_id, review.acquire_operation_id,
        review.call_id, review.generation_original_operation_id,
        review.generation_call_id, review.generation_frozen_input_digest,
        "f" * 64, review.qualified_units_digest, review.review_frozen_input_digest,
        review.model_request_digest, review.original_graph_guard_digest,
        review.parent_budget_lease_id, review.reservation_operation_id,
        review.review_policy_version,
    )
    with pytest.raises(ValueError, match="not bound"):
        parse_natural_reply_review_output_v1(_pass_text(), frozen, generation, replaced)


@pytest.mark.parametrize("payload", [
    {"schema": OUTPUT_SCHEMA, "verdict": "pass", "issues": [], "paid": True},
    {"schema": OUTPUT_SCHEMA, "verdict": "pass", "issues": [], "authority": "verified"},
])
def test_review_parser_rejects_extra_authority_or_payment_claims(payload):
    generation, frozen, review = _frozen_and_seals()
    with pytest.raises(ValueError, match="shape"):
        parse_natural_reply_review_output_v1(
            json.dumps(payload), frozen, generation, review,
        )


def test_syntactic_pass_is_only_candidate_and_verdict_issue_pair_is_closed():
    generation, frozen, review = _frozen_and_seals()
    candidate = parse_natural_reply_review_output_v1(
        _pass_text(), frozen, generation, review,
    )
    assert candidate.verdict == "pass"
    assert candidate.status == "untrusted_review_candidate"
    with pytest.raises(ValueError, match="disagree"):
        parse_natural_reply_review_output_v1(
            json.dumps({"schema": OUTPUT_SCHEMA, "verdict": "pass", "issues": [
                {"code": "negation_shift", "location": "/body"},
            ]}), frozen, generation, review,
        )


def test_promise_speech_act_is_forced_to_hold_without_typed_grant_scope():
    generation, _, _ = _frozen_and_seals()
    plan, _, output = _case()
    output["units"][0]["speech_act"] = "promise"
    installation = NaturalReviewInstallationV1(
        "install:review", "provider:review", "a" * 64, "review-model",
    )
    frozen = freeze_natural_reply_review_v1(
        generation, output, plan.units, ("grant:opaque",),
        "policy:natural-review:1", installation,
    )
    review = NaturalReplyReviewOriginalSealV2(
        generation.namespace, installation.installation_id,
        installation.provider_config_digest, "review-job", "review-original",
        "review-acquire", "review-call", generation.original_operation_id,
        generation.call_id, generation.frozen_input_digest,
        frozen.generation_output_digest, generation.qualified_units_digest,
        frozen.digest, frozen.wire_digest, "e" * 64,
        generation.parent_budget_lease_id, "review-reservation",
        frozen.review_policy_version,
    )
    candidate = parse_natural_reply_review_output_v1(
        _pass_text(), frozen, generation, review,
    )
    assert candidate.verdict == "hold"
    assert candidate.issues == (("commitment_out_of_scope", "/units"),)
