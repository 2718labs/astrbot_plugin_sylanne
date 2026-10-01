"""Generation, D09 and independent review agree on one frozen basis."""

import json

import pytest

from rewrite.tests.alpha1.d09.test_natural_reply import _case
from sylanne3.model_broker.context_reply import ContextReplyPartV1
from sylanne3.model_broker.natural_reply import (
    NaturalReplyInputV2, NaturalReplyInstallationV2,
    freeze_natural_reply_request_v2, parse_natural_reply_output_v2,
)
from sylanne3.model_broker.natural_review import (
    NaturalReviewInstallationV1, OUTPUT_SCHEMA,
    freeze_natural_reply_review_v1, parse_natural_reply_review_output_v1,
)
from sylanne3.domains.d09 import mechanically_verify_natural_reply_v2
from sylanne3.runtime_contracts import (
    NaturalReplyGenerationOriginalSealV2, NaturalReplyReviewOriginalSealV2,
    VersionedRef, canonical_digest,
)


def test_generation_mechanical_and_review_share_exact_basis_and_output():
    plan, reads, output = _case()
    question = ContextReplyPartV1(
        "question", plan.scene_ref,
        VersionedRef(plan.audience_id, plan.audience_ref.version), 140.0,
        "What happened to the door?",
    )
    frozen_generation = freeze_natural_reply_request_v2(
        NaturalReplyInputV2(question, plan, (), 100.0, 130.0),
        NaturalReplyInstallationV2("install:one", "a" * 64,
                                   "provider:one", "model:one", 512),
    )
    parsed_generation = parse_natural_reply_output_v2(
        json.dumps(output), frozen_generation,
    )
    assert parsed_generation.status == "untrusted_content_candidate"
    assert parsed_generation.qualified_units_digest == canonical_digest(plan.units)
    mechanical = mechanically_verify_natural_reply_v2(
        parsed_generation.d09_payload(), plan=plan,
        current_reads=reads, now_utc=110.0,
    )
    assert mechanical.status == "mechanical_verified_semantic_hold"
    assert mechanical.output_digest == parsed_generation.output_digest

    generation_seal = NaturalReplyGenerationOriginalSealV2(
        plan.namespace, "c02:one", "source:one", "install:one", "a" * 64,
        "generation-job", "generation-original", "generation-acquire",
        "generation-call", frozen_generation.frozen_input_digest,
        frozen_generation.qualified_units_digest,
        frozen_generation.model_request_digest, "b" * 64,
        "parent-budget", "generation-reservation",
    )
    frozen_review = freeze_natural_reply_review_v1(
        generation_seal, parsed_generation.d09_payload(), plan.units, (),
        "policy:natural-review:1",
        NaturalReviewInstallationV1("install:one", "provider:one", "a" * 64,
                                    "review-model"),
    )
    review_seal = NaturalReplyReviewOriginalSealV2(
        plan.namespace, "install:one", "a" * 64, "review-job",
        "review-original", "review-acquire", "review-call",
        generation_seal.original_operation_id, generation_seal.call_id,
        generation_seal.frozen_input_digest, parsed_generation.output_digest,
        generation_seal.qualified_units_digest, frozen_review.digest,
        frozen_review.wire_digest, "c" * 64,
        generation_seal.parent_budget_lease_id, "review-reservation",
        frozen_review.review_policy_version,
    )
    candidate = parse_natural_reply_review_output_v1(
        json.dumps({"schema": OUTPUT_SCHEMA, "verdict": "pass", "issues": []}),
        frozen_review, generation_seal, review_seal,
    )
    assert candidate.generation_output_digest == mechanical.output_digest
    assert candidate.status == "untrusted_review_candidate"

    tampered = dict(output, body="The door was locked.")
    with pytest.raises(ValueError, match="not bound"):
        changed_review = freeze_natural_reply_review_v1(
            generation_seal, tampered, plan.units, (),
            "policy:natural-review:1", frozen_review.installation,
        )
        parse_natural_reply_review_output_v1(
            json.dumps({"schema": OUTPUT_SCHEMA, "verdict": "pass", "issues": []}),
            changed_review, generation_seal, review_seal,
        )
