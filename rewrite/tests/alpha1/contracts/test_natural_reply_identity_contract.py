"""Generation and review have distinct immutable pre-call identities."""

from dataclasses import replace

import pytest

from sylanne3.runtime_contracts import (
    NATURAL_REPLY_GENERATION_WORKFLOW_V2,
    NATURAL_REPLY_REVIEW_WORKFLOW_V1,
    NamespaceId,
    NaturalReplyGenerationOriginalSealV2,
    NaturalReplyPaidReviewReceiptV2,
    NaturalReplyReviewOriginalSealV2,
    canonical_digest,
)


def _generation() -> NaturalReplyGenerationOriginalSealV2:
    return NaturalReplyGenerationOriginalSealV2(
        NamespaceId("bot", "persona"), "c02:one", "source:one",
        "installation", "a" * 64, "generate-job", "generate-original",
        "generate-acquire", "generate-call", "b" * 64, "c" * 64,
        "d" * 64, "e" * 64, "parent-budget", "generation-reservation",
    )


def test_generation_and_review_are_distinct_pre_call_seals():
    generation = _generation()
    review = NaturalReplyReviewOriginalSealV2(
        generation.namespace, generation.installation_id,
        generation.provider_config_digest, "review-job", "review-original",
        "review-acquire", "review-call", generation.original_operation_id,
        generation.call_id, generation.frozen_input_digest, "f" * 64,
        generation.qualified_units_digest, "0" * 64, "1" * 64,
        "2" * 64, generation.parent_budget_lease_id,
        "review-reservation", "semantic-review-policy-1",
    )
    assert generation.template_version == NATURAL_REPLY_GENERATION_WORKFLOW_V2
    assert review.template_version == NATURAL_REPLY_REVIEW_WORKFLOW_V1
    assert review.generation_original_operation_id == generation.original_operation_id
    assert review.generation_call_id == generation.call_id
    assert review.parent_budget_lease_id == generation.parent_budget_lease_id
    assert canonical_digest(generation) != canonical_digest(review)
    assert not hasattr(generation, "terminal_receipt")
    assert not hasattr(review, "review_verdict")


def test_review_cannot_reuse_generation_call_or_forge_digest():
    generation = _generation()
    with pytest.raises(ValueError, match="identities must differ"):
        NaturalReplyReviewOriginalSealV2(
            generation.namespace, generation.installation_id,
            generation.provider_config_digest, "review-job", "review-original",
            "review-acquire", generation.call_id,
            generation.original_operation_id, generation.call_id,
            generation.frozen_input_digest, "f" * 64,
            generation.qualified_units_digest, "0" * 64, "1" * 64,
            "2" * 64, generation.parent_budget_lease_id,
            "review-reservation", "semantic-review-policy-1",
        )
    with pytest.raises(ValueError, match="qualified_units_digest"):
        replace(generation, qualified_units_digest="untrusted")


def test_v1_context_reply_template_is_not_natural_generation():
    with pytest.raises(ValueError, match="unknown natural generation"):
        replace(_generation(), template_version="sylanne.d09.context_reply.v1")


def test_paid_review_receipt_keeps_both_typed_calls_and_outputs_distinct():
    receipt = NaturalReplyPaidReviewReceiptV2(
        NamespaceId("bot", "persona"), "generation-original", "generation-call",
        "a" * 64, "b" * 64, "c" * 64,
        "review-original", "review-call", "d" * 64, "e" * 64, "f" * 64,
        "parent-budget", "generation-reservation", "review-reservation",
        "0" * 64, "policy:natural-review:1", "pass", "1" * 64,
    )
    assert receipt.generation_output_digest != receipt.review_output_digest
    assert not hasattr(receipt, "send_grant")
    with pytest.raises(ValueError, match="identities must differ"):
        replace(receipt, review_original_operation_id="generation-original")
