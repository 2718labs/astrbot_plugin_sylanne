"""Current review accepts same-version originals and rejects mixed seal pairs."""
from dataclasses import fields
import pytest
from test_natural_review import _frozen_and_seals, _pass_text
from rewrite.tests.alpha1.d09.test_natural_reply import _case
from sylanne3.model_broker.natural_review import freeze_natural_reply_review_v1, parse_natural_reply_review_output_v1
from sylanne3.runtime_contracts import NaturalReplyReviewOriginalSealV2, canonical_digest
from sylanne3.runtime.natural_original_v3 import NaturalReplyGenerationOriginalSealV3, NaturalReplyReviewOriginalSealV3
from sylanne3.runtime.natural_original_v4 import NaturalReplyGenerationOriginalSealV4, NaturalReplyReviewOriginalSealV4


def case(version):
    old_generation, old_frozen, old_review = _frozen_and_seals()
    generation_type, review_type = ((NaturalReplyGenerationOriginalSealV3, NaturalReplyReviewOriginalSealV3)
        if version == 3 else (NaturalReplyGenerationOriginalSealV4, NaturalReplyReviewOriginalSealV4))
    values = {f.name: getattr(old_generation, f.name) for f in fields(old_generation) if f.name not in {"schema", "template_version"}}
    values.update(original_operation_id=f"generation-original-v{version}", call_id=f"generation-call-v{version}",
                  frozen_input_digest=canonical_digest({"independent_fixture_generation": version}))
    generation = generation_type(**values)
    plan, _, output = _case()
    frozen = freeze_natural_reply_review_v1(generation, output, plan.units, (), old_frozen.review_policy_version, old_frozen.installation)
    values = {f.name: getattr(old_review, f.name) for f in fields(old_review) if f.name not in {"schema", "template_version"}}
    values.update(generation_original_operation_id=generation.original_operation_id, generation_call_id=generation.call_id,
        generation_frozen_input_digest=generation.frozen_input_digest, generation_output_digest=frozen.generation_output_digest,
        review_frozen_input_digest=frozen.digest, model_request_digest=frozen.wire_digest)
    return generation, frozen, review_type(**values), values


@pytest.mark.parametrize("version", [3, 4])
def test_review_retains_same_version_generation_and_original_identity(version):
    generation, frozen, review, _ = case(version)
    result = parse_natural_reply_review_output_v1(_pass_text(), frozen, generation, review)
    assert result.status == "untrusted_review_candidate"
    assert review.generation_frozen_input_digest == generation.frozen_input_digest
    assert generation.schema.endswith(f".v{version}") and review.schema.endswith(f".v{version}")


@pytest.mark.parametrize("version", [3, 4])
def test_review_cannot_mix_new_generation_with_legacy_review_seal(version):
    generation, frozen, _, values = case(version)
    with pytest.raises(TypeError, match="typed frozen review"):
        parse_natural_reply_review_output_v1(_pass_text(), frozen, generation, NaturalReplyReviewOriginalSealV2(**values))
