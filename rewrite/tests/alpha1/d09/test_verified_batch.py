"""A D09 graph batch must be reproducible from frozen D08 and expression inputs."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from rewrite.sylanne3.domains.d08 import CommunicationIntentGrant, SegmentGrant
from rewrite.sylanne3.domains.d09 import (
    ClaimKind,
    ClaimUse,
    D09ExpressionProvider,
    ExpressionClaim,
    SegmentCandidate,
    segment_payload_digest,
)
from rewrite.sylanne3.runtime_contracts import canonical_digest


def _inputs():
    first_use = ClaimUse("claim:one", 0, 5, ClaimKind.EXTERNAL_FACT)
    second_use = ClaimUse("claim:two", 0, 6, ClaimKind.REPORTED_CLAIM)
    checks = ("check:source", "check:budget")
    grants = (
        SegmentGrant("segment:one", "effect:one", 0, segment_payload_digest("First", (), (first_use,)),
                     100, (), None, checks, 100.0, 2),
        SegmentGrant("segment:two", "effect:two", 1, segment_payload_digest("Second", (), (second_use,)),
                     100, (), "segment:one", checks, 100.0, 2),
    )
    intent = CommunicationIntentGrant(
        "communication-grant:" + "1" * 64, "communication:one", "contact:one", 1,
        "intent:one", "action:one", 1, "entity:one", ("entity:one",), "expression",
        ("answer",), (ClaimKind.EXTERNAL_FACT.value, ClaimKind.REPORTED_CLAIM.value),
        (), grants, "2" * 64, checks, 100.0, 2,
    )
    claims = (
        ExpressionClaim("claim:one", "First", ClaimKind.EXTERNAL_FACT, ("source:first",),
                        ("entity:one",), ("expression",), "disclosure:one"),
        ExpressionClaim("claim:two", "Second", ClaimKind.REPORTED_CLAIM, ("source:second",),
                        ("entity:one",), ("expression",), "disclosure:two"),
    )
    candidates = (
        SegmentCandidate("segment:one", "effect:one", "First", (first_use,), ("answer",), (), 0.0),
        SegmentCandidate("segment:two", "effect:two", "Second", (second_use,), (), (), 0.0),
    )
    provider = D09ExpressionProvider()
    blueprint = provider.prepare_blueprint(intent, "scene:one", 3, claims, now=1.0).blueprint
    assert blueprint is not None
    return intent, blueprint, candidates


def test_batch_freezes_full_finite_payload_and_remains_source_hold() -> None:
    intent, blueprint, candidates = _inputs()
    provider = D09ExpressionProvider()
    value = provider.build_verified_batch_v1(intent, blueprint, candidates, now=1.0)
    spec = next(spec for spec in provider.register_types() if spec.name == "d09.verified_segment_batch.v1")
    assert spec.writer_domain == "d09" and spec.owner_kinds == ("activity",)
    assert spec.immutable and spec.schema_version == 1 and spec.schema_hash
    spec.validator(value)
    assert value["qualification"] == "content_verified_source_hold"
    assert value["grant_manifest_digest"] == intent.segment_manifest_digest
    assert value["scene_ref"] == "scene:one" and value["audiences"] == ["entity:one"]
    assert [segment["body"] for segment in value["segments"]] == ["First", "Second"]
    assert value["segments"][1]["prerequisite_segment_ref"] == "segment:one"
    assert value["segments"][1]["source_refs"] == ["source:second"]
    rechecked = provider.recompute_verified_batch_v1(
        value, intent=intent, blueprint=blueprint, candidates=candidates, now=1.0,
    )
    assert rechecked.status == "content_verified_source_hold"
    assert rechecked.missing == ("current_d08_grant_provenance", "current_source_reads")
    assert rechecked.value == value


def test_recompute_rejects_body_claim_span_and_manifest_tampering_even_with_new_batch_digest() -> None:
    intent, blueprint, candidates = _inputs()
    provider = D09ExpressionProvider()
    original = provider.build_verified_batch_v1(intent, blueprint, candidates, now=1.0)
    for change in ("body", "claim", "span", "omitted"):
        value = deepcopy(original)
        if change == "body":
            value["segments"][0]["body"] = "Other"
        elif change == "claim":
            value["claims"][0]["text"] = "Other"
        elif change == "span":
            value["segments"][0]["claim_uses"][0]["end"] = 4
        else:
            value["segments"].pop()
        value["batch_digest"] = canonical_digest({key: item for key, item in value.items() if key != "batch_digest"})
        with pytest.raises(ValueError):
            provider.recompute_verified_batch_v1(
                value, intent=intent, blueprint=blueprint, candidates=candidates, now=1.0,
            )


def test_changed_candidate_or_grant_cannot_reuse_batch_and_retry_is_stable() -> None:
    intent, blueprint, candidates = _inputs()
    provider = D09ExpressionProvider()
    value = provider.build_verified_batch_v1(intent, blueprint, candidates, now=1.0)
    assert provider.build_verified_batch_v1(intent, blueprint, candidates, now=1.0) == value
    with pytest.raises(ValueError, match="finite segment verification failed"):
        provider.build_verified_batch_v1(intent, blueprint, candidates[:1], now=1.0)
    with pytest.raises(ValueError, match="verified batch differs"):
        provider.recompute_verified_batch_v1(
            value, intent=replace(intent, contact_id="contact:changed"),
            blueprint=blueprint, candidates=candidates, now=1.0,
        )
    missing = provider.recompute_verified_batch_v1(
        value, intent=None, blueprint=blueprint, candidates=candidates, now=1.0,
    )
    assert missing.status == "hold" and missing.missing == ("current_d08_grant",)


def test_verified_batch_type_spec_rejects_self_declared_qualification_and_missing_payload() -> None:
    intent, blueprint, candidates = _inputs()
    provider = D09ExpressionProvider()
    spec = next(spec for spec in provider.register_types() if spec.name == "d09.verified_segment_batch.v1")
    value = provider.build_verified_batch_v1(intent, blueprint, candidates, now=1.0)
    altered = deepcopy(value)
    altered["qualification"] = "admitted"
    altered["batch_digest"] = canonical_digest({key: item for key, item in altered.items() if key != "batch_digest"})
    with pytest.raises(ValueError, match="source qualification"):
        spec.validator(altered)
    altered = deepcopy(value)
    del altered["segments"][0]["body"]
    altered["batch_digest"] = canonical_digest({key: item for key, item in altered.items() if key != "batch_digest"})
    with pytest.raises(ValueError, match="segment fields"):
        spec.validator(altered)


def test_visible_emoji_requires_claim_mapping_even_when_d08_digest_matches() -> None:
    intent, _, candidates = _inputs()
    body = "First 👍"
    uses = candidates[0].claim_uses
    changed_first = replace(candidates[0], body=body)
    changed_grant = replace(
        intent.segment_grants[0], payload_digest=segment_payload_digest(body, (), uses),
    )
    intent = replace(intent, segment_grants=(changed_grant, intent.segment_grants[1]))
    provider = D09ExpressionProvider()
    claims = (
        ExpressionClaim("claim:one", "First", ClaimKind.EXTERNAL_FACT, ("source:first",),
                        ("entity:one",), ("expression",), "disclosure:one"),
        ExpressionClaim("claim:two", "Second", ClaimKind.REPORTED_CLAIM, ("source:second",),
                        ("entity:one",), ("expression",), "disclosure:two"),
    )
    blueprint = provider.prepare_blueprint(intent, "scene:one", 3, claims, now=1.0).blueprint
    assert blueprint is not None
    staged = provider.verify_and_stage(blueprint, (changed_first, candidates[1]))
    assert staged.status == "rejected" and "unmapped_content" in staged.failures


def test_serialized_batch_rechecks_each_used_claim_audience() -> None:
    intent, blueprint, candidates = _inputs()
    provider = D09ExpressionProvider()
    spec = next(spec for spec in provider.register_types() if spec.name == "d09.verified_segment_batch.v1")
    value = provider.build_verified_batch_v1(intent, blueprint, candidates, now=1.0)
    altered = deepcopy(value)
    altered["claims"][0]["allowed_audiences"] = ["entity:private"]
    altered["batch_digest"] = canonical_digest({
        key: item for key, item in altered.items() if key != "batch_digest"
    })
    with pytest.raises(ValueError, match="audience scope"):
        spec.validator(altered)

    altered = deepcopy(value)
    altered["segments"][0]["body"] = "First 👍"
    altered["segments"][0]["payload_digest"] = segment_payload_digest(
        "First 👍", (), candidates[0].claim_uses,
    )
    altered["batch_digest"] = canonical_digest({
        key: item for key, item in altered.items() if key != "batch_digest"
    })
    with pytest.raises(ValueError, match="unmapped content"):
        spec.validator(altered)
