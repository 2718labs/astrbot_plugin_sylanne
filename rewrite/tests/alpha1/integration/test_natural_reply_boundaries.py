"""Generation, D09 and independent review agree on one frozen basis.

These are codec/basis contracts, including unsigned seal fixtures. They do not
issue Authority originals, record paid calls or qualify an installed P2 sender.
"""

from dataclasses import asdict
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


def _semantic_basis_case(bubble_count):
    from sylanne3.model_broker.natural_reply_history_v3 import D13NaturalHistorySelectionV1
    from sylanne3.model_broker.natural_reply_history_v4 import (
        INPUT_SCHEMA_V5, NaturalReplyInputV4, freeze_natural_reply_request_v4,
    )
    from sylanne3.model_broker.natural_reply import OUTPUT_SCHEMA_V3

    plan, reads, legacy_output = _case()
    question = ContextReplyPartV1("question", plan.scene_ref, plan.audience_ref,
                                 140.0, "What happened to the door?")
    selection = D13NaturalHistorySelectionV1(
        "a" * 64, 0, (), (), (), (plan.scene_ref, plan.audience_ref),
        plan.scene_ref, plan.audience_ref, plan.audience_id, 140.0, 0, 0, 1,
        None, (), canonical_digest({"stable_history": (), "recent_history": (),
                                   "detail_history": (), "coverage": (), "gaps": ()}),
        "policy:history", "b" * 64)
    generation = freeze_natural_reply_request_v4(
        NaturalReplyInputV4(question, plan, (), (), selection, (),
                            100.0, 130.0, INPUT_SCHEMA_V5),
        NaturalReplyInstallationV2("install:one", "a" * 64,
                                   "provider:one", "model:one", 512))
    # Every range contains a complete attributed unit. No punctuation splitting
    # or later qualifier is used to make a codec fixture appear prefix-safe.
    phrase = "You reported that the door opened."
    ranges = tuple((index * (len(phrase) + 1),
                    (index + 1) * (len(phrase) + 1) - (index == bubble_count - 1))
                   for index in range(bubble_count))
    output = {"schema": OUTPUT_SCHEMA_V3, "body": "\n".join([phrase] * bubble_count),
        "units": [{**legacy_output["units"][0], "start": start,
                   "end": start + len(phrase)} for start, _ in ranges],
        "semantic_segments": [{"start": start, "end": end} for start, end in ranges]}
    # This unsigned DTO only freezes the codec's parent identity. It is never
    # passed to an installed reader or represented as a paid receipt.
    generation_seal = NaturalReplyGenerationOriginalSealV2(
        plan.namespace, "c02:one", "source:one", "install:one", "a" * 64,
        "generation-job", "generation-original", "generation-acquire",
        "generation-call", generation.frozen_input_digest,
        generation.qualified_units_digest, generation.model_request_digest, "b" * 64,
        "parent-budget", "generation-reservation")
    review = freeze_natural_reply_review_v1(
        generation_seal, output, plan.units, (), "policy:natural-review:1",
        NaturalReviewInstallationV1("install:one", "provider:one", "a" * 64, "review-model"))
    review_seal = NaturalReplyReviewOriginalSealV2(
        plan.namespace, "install:one", "a" * 64, "review-job", "review-original",
        "review-acquire", "review-call", generation_seal.original_operation_id,
        generation_seal.call_id, generation_seal.frozen_input_digest,
        canonical_digest(output), generation_seal.qualified_units_digest,
        review.digest, review.wire_digest, "c" * 64,
        generation_seal.parent_budget_lease_id, "review-reservation", review.review_policy_version)
    return plan, reads, generation, output, ranges, generation_seal, review, review_seal


@pytest.mark.parametrize("bubble_count", (1, 2, 3, 4))
def test_v5_generation_d09_and_v2_review_bind_one_complete_semantic_manifest(bubble_count):
    from sylanne3.model_broker.natural_reply_history_v4 import (
        FROZEN_SCHEMA_V5, TEMPLATE_VERSION_V5, parse_natural_reply_output_v4,
        thaw_natural_reply_request_v4,
    )
    from sylanne3.model_broker.natural_review import (
        OUTPUT_SCHEMA_V2, REVIEW_TEMPLATE_VERSION_V2,
    )
    from sylanne3.domains.d09.natural_reply import (
        natural_segment_identity_v3, natural_semantic_ranges_v3,
    )

    plan, reads, generation, output, ranges, seal, review, review_seal = _semantic_basis_case(bubble_count)
    assert generation.schema == FROZEN_SCHEMA_V5
    assert json.loads(generation.messages[2].content)["schema"] == TEMPLATE_VERSION_V5
    cold_generation = thaw_natural_reply_request_v4(json.loads(json.dumps(asdict(generation))))
    parsed = parse_natural_reply_output_v4(json.dumps(output), cold_generation)
    mechanical = mechanically_verify_natural_reply_v2(
        parsed.d09_payload(), plan=plan, current_reads=reads, now_utc=110.0)
    assert mechanical.status == "mechanical_verified_semantic_hold"
    assert parsed.output_digest == mechanical.output_digest == review.generation_output_digest
    assert natural_semantic_ranges_v3(parsed.d09_payload()) == ranges
    review_input = json.loads(review.canonical_input)
    assert review_input["template_version"] == REVIEW_TEMPLATE_VERSION_V2
    assert review_input["body"] == output["body"]
    assert review_input["semantic_segments"] == output["semantic_segments"]
    verdict = parse_natural_reply_review_output_v1(json.dumps({
        "schema": OUTPUT_SCHEMA_V2, "verdict": "pass", "issues": [], "prefix_safe": True}),
        review, seal, review_seal)
    assert verdict.verdict == "pass" and verdict.status == "untrusted_review_candidate"
    assert verdict.generation_output_digest == parsed.output_digest
    identities = tuple(natural_segment_identity_v3(plan, output, index)
                       for index in range(bubble_count))
    assert len(set(identities)) == bubble_count
    assert identities[0][:2] == (plan.final_operation_id, plan.final_effect_id)
    # Reopening the actual frozen codec preserves parent and child identities;
    # this says nothing about resend permission or confirmed delivery.
    cold_output = parse_natural_reply_output_v4(json.dumps(parsed.d09_payload()), cold_generation)
    assert identities == tuple(natural_segment_identity_v3(plan, cold_output.d09_payload(), index)
                               for index in range(bubble_count))


def test_review_v2_unsafe_prefix_cannot_promote_or_replace_the_complete_manifest():
    from sylanne3.model_broker.natural_review import OUTPUT_SCHEMA_V2

    _, _, _, output, _, seal, review, review_seal = _semantic_basis_case(2)
    unsafe = {"schema": OUTPUT_SCHEMA_V2, "verdict": "pass", "issues": [], "prefix_safe": False}
    rejected = parse_natural_reply_review_output_v1(json.dumps(unsafe), review, seal, review_seal)
    assert rejected.verdict == "hold"
    assert rejected.issues == (("other_semantic_risk", "/semantic_segments"),)
    assert rejected.generation_output_digest == canonical_digest(output)
    assert rejected.status == "untrusted_review_candidate"
    without_prefix = {key: value for key, value in unsafe.items() if key != "prefix_safe"}
    with pytest.raises(ValueError, match="shape"):
        parse_natural_reply_review_output_v1(json.dumps(without_prefix), review, seal, review_seal)
    changed = {**output, "semantic_segments": [{"start": 0, "end": len(output["body"])}]}
    plan, _, _ = _case()
    changed_review = freeze_natural_reply_review_v1(
        seal, changed, plan.units, (), review.review_policy_version, review.installation)
    with pytest.raises(ValueError, match="not bound"):
        parse_natural_reply_review_output_v1(json.dumps({**unsafe, "prefix_safe": True}),
                                            changed_review, seal, review_seal)
