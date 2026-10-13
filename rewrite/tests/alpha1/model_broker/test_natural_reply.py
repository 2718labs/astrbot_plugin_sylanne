import json
from dataclasses import replace

import pytest

from sylanne3.domains.d09 import ClaimKind
from sylanne3.domains.d09.natural_reply import (
    NaturalExpressionPlanV2, QualifiedExpressionUnitV2,
)
from sylanne3.model_broker.context_reply import ContextReplyPartV1
from sylanne3.model_broker.natural_reply import (
    INPUT_SCHEMA, OUTPUT_SCHEMA, NaturalReplyInputV2,
    NaturalReplyInstallationV2, freeze_natural_reply_request_v2,
    parse_natural_reply_output_v2,
)
from sylanne3.runtime_contracts import NamespaceId, VersionedRef, canonical_digest


def frozen(*, history_text="Earlier chat", source_version=2):
    audience = VersionedRef("audience:private", 4)
    unit = QualifiedExpressionUnitV2(
        "basis:one", ClaimKind.REPORTED_CLAIM, "The door may be open.",
        VersionedRef("qualification:one", 2),
        (VersionedRef("source:one", source_version),),
        (VersionedRef("access:one", 3),),
        (VersionedRef("correction:one", 0),),
        audience.ref, "expression", 150.0,
        speaker_id="user:one", content_reality="external_report",
        uncertainty="reported_only", semantic_constraints=("retain_negation",),
        polarity_status="uncertain", source_excerpt="The door may be open.",
    )
    plan = NaturalExpressionPlanV2(
        NamespaceId("bot", "persona"), VersionedRef("plan:one", 2),
        VersionedRef("proof:scene-private", 5),
        VersionedRef("proof:audience-private", 4),
        ("answer",), ("paraphrase", "promise"),
        (VersionedRef("grant:promise", 1),), (unit,), 140.0,
        "activity:one", "operation:one", "effect:one",
        "scene:private", audience.ref,
    )
    question = ContextReplyPartV1(
        "question", VersionedRef("question:current", 1), audience,
        140.0, "Is the door open?",
    )
    d13_ref = VersionedRef(json.dumps(
        ["scene", "bot", "persona", "short", "d13.compressed_turn_block.v2", "one"],
        separators=(",", ":")), 2)
    history = ContextReplyPartV1(
        "d13_history", d13_ref, audience, 140.0, history_text,
        (VersionedRef("source:old", 1),),
    )
    input = NaturalReplyInputV2(question, plan, (history,), 100.0, 130.0)
    installation = NaturalReplyInstallationV2("installation:one", "a" * 64,
                                               "provider", "model", 512)
    return freeze_natural_reply_request_v2(input, installation)


def output(body="You said the door might be open."):
    return {"schema": OUTPUT_SCHEMA, "body": body, "units": [{
        "start": 0, "end": len(body), "kind": "reported_claim",
        "basis_ids": ["basis:one"], "speech_act": "paraphrase",
        "promise_grant_id": None, "slot_ids": ["answer"],
    }]}


def test_semantic_v3_template_is_explicit_and_legacy_wire_rejects_it():
    from dataclasses import asdict
    from sylanne3.model_broker.natural_reply_history_v4 import (
        INPUT_SCHEMA_V5, FROZEN_SCHEMA_V5, NaturalReplyInputV4,
        freeze_natural_reply_request_v4, thaw_natural_reply_request_v4,
        parse_natural_reply_output_v4,
    )
    from sylanne3.model_broker.natural_reply_history_v3 import D13NaturalHistorySelectionV1
    from sylanne3.domains.d09.natural_reply import (
        NATURAL_REPLY_OUTPUT_SCHEMA_V3, natural_semantic_ranges_v3,
    )
    legacy = frozen()
    plan = legacy.input.plan
    selection = D13NaturalHistorySelectionV1(
        "a" * 64, 0, (), (), (), (plan.scene_ref, plan.audience_ref),
        plan.scene_ref, plan.audience_ref, plan.audience_id, 140.0, 0, 0, 1, None, (),
        canonical_digest({"stable_history": (), "recent_history": (), "detail_history": (),
                          "coverage": (), "gaps": ()}), "policy:history", "b" * 64)
    current_input = NaturalReplyInputV4(
        replace(legacy.input.question, audience_ref=plan.audience_ref), plan, (), (),
        selection, (), 100.0, 130.0, INPUT_SCHEMA_V5)
    current = freeze_natural_reply_request_v4(current_input, legacy.installation)
    assert current.schema == FROZEN_SCHEMA_V5
    assert thaw_natural_reply_request_v4(asdict(current)) == current
    reply = output()
    reply.update(schema=NATURAL_REPLY_OUTPUT_SCHEMA_V3,
                 semantic_segments=[{"start": 0, "end": len(reply["body"])}])
    with pytest.raises(ValueError, match="shape"):
        parse_natural_reply_output_v2(json.dumps(reply), legacy)
    legacy_history = freeze_natural_reply_request_v4(
        replace(current_input, schema="sylanne.d09.context_reply_input.v4"), legacy.installation)
    with pytest.raises(ValueError, match="shape"):
        parse_natural_reply_output_v4(json.dumps(reply), legacy_history)
    parsed = parse_natural_reply_output_v4(json.dumps(reply), current)
    assert parsed.output_digest == canonical_digest(reply)
    assert natural_semantic_ranges_v3(reply) == ((0, len(reply["body"])),)
    assert current.model_request_digest != legacy.model_request_digest


def test_semantic_manifest_rejects_a_qualifier_or_code_split_and_over_four_bubbles():
    from sylanne3.domains.d09.natural_reply import (
        NATURAL_REPLY_OUTPUT_SCHEMA_V3, natural_semantic_ranges_v3,
    )
    reply = output("You said it might be open.")
    reply.update(schema=NATURAL_REPLY_OUTPUT_SCHEMA_V3,
                 semantic_segments=[{"start": 0, "end": 12}, {"start": 12, "end": len(reply["body"])}])
    with pytest.raises(ValueError, match="qualified claim"):
        natural_semantic_ranges_v3(reply)
    reply = {"schema": NATURAL_REPLY_OUTPUT_SCHEMA_V3,
             "body": "```py\nx = 1\n```", "units": [],
             "semantic_segments": [{"start": 0, "end": 6}, {"start": 6, "end": 15}]}
    with pytest.raises(ValueError, match="fenced code"):
        natural_semantic_ranges_v3(reply)
    reply = {"schema": NATURAL_REPLY_OUTPUT_SCHEMA_V3, "body": "12345", "units": [],
             "semantic_segments": [{"start": i, "end": i + 1} for i in range(5)]}
    with pytest.raises(ValueError, match="finite"):
        natural_semantic_ranges_v3(reply)


def test_three_message_wire_keeps_qualified_limits_and_stable_prefix():
    request = frozen()
    assert [item.role for item in request.messages] == ["system", "user", "user"]
    assert request.canonical_wire.startswith(request.stable_prefix_wire)
    assert INPUT_SCHEMA in request.messages[1].content
    assert "Earlier chat" in request.messages[1].content
    assert "Is the door open?" not in request.messages[1].content
    dynamic = json.loads(request.messages[2].content)
    assert dynamic["question"]["text"] == "Is the door open?"
    assert dynamic["expression_plan"]["final_effect_id"] == "effect:one"
    assert dynamic["expression_plan"]["audience_id"] == request.input.plan.audience_id
    assert dynamic["qualified_units"][0]["source_refs"][0]["version"] == 2
    assert dynamic["qualified_units"][0]["access_refs"][0]["version"] == 3
    assert dynamic["qualified_units"][0]["correction_refs"][0]["version"] == 0
    assert dynamic["qualified_units"][0]["semantic_constraints"] == ["retain_negation"]
    assert request.qualified_units_digest == canonical_digest(request.input.plan.units)
    assert frozen(history_text="Different chat").stable_prefix_digest != request.stable_prefix_digest
    changed = frozen(source_version=3)
    assert changed.stable_prefix_digest == request.stable_prefix_digest
    assert changed.frozen_input_digest != request.frozen_input_digest
    assert changed.qualified_units_digest != request.qualified_units_digest
    changed_provider = freeze_natural_reply_request_v2(
        request.input, replace(request.installation, provider_id="other-provider"),
    )
    assert changed_provider.model_request_digest != request.model_request_digest


def test_parser_returns_untrusted_candidate_and_empty_hold():
    request = frozen()
    candidate = parse_natural_reply_output_v2(json.dumps(output()), request)
    assert candidate.status == "untrusted_content_candidate"
    assert candidate.d09_payload() == output()
    assert candidate.frozen_input_digest == request.frozen_input_digest
    assert candidate.qualified_units_digest == request.qualified_units_digest
    empty = parse_natural_reply_output_v2(
        json.dumps({"schema": OUTPUT_SCHEMA, "body": "", "units": []}), request)
    assert empty.status == "no_reply_hold"
    with pytest.raises(ValueError):
        empty.d09_payload()


@pytest.mark.parametrize("invalid", [
    lambda data: {**data, "body": "Not " + data["body"]},
    lambda data: {**data, "units": [dict(data["units"][0], basis_ids=["basis:other"])]},
    lambda data: {**data, "units": [dict(data["units"][0], slot_ids=[])]},
    lambda data: {**data, "units": [dict(data["units"][0], speech_act="promise")]},
    lambda data: {**data, "units": [dict(data["units"][0], kind="external_fact")]},
])
def test_parser_rejects_structural_scope_or_coverage_changes(invalid):
    with pytest.raises(ValueError):
        parse_natural_reply_output_v2(json.dumps(invalid(output())), frozen())


def test_parser_rejects_duplicate_json_keys_and_modified_frozen_wire():
    request = frozen()
    with pytest.raises(ValueError):
        parse_natural_reply_output_v2(
            '{"schema":"' + OUTPUT_SCHEMA + '","body":"a","body":"b","units":[]}',
            request)
    with pytest.raises(ValueError):
        parse_natural_reply_output_v2(json.dumps(output()),
                                      replace(request, canonical_wire="altered"))


def test_parser_rejects_nested_basis_and_slot_values_as_invalid_output():
    request = frozen()
    for field, nested in (("basis_ids", [["basis:one"]]),
                          ("slot_ids", [{"slot": "answer"}])):
        candidate = output()
        candidate["units"][0][field] = nested
        with pytest.raises(ValueError):
            parse_natural_reply_output_v2(json.dumps(candidate), request)


def _frozen_v4_with_details(text="Earlier exact detail"):
    from sylanne3.model_broker.natural_reply_history_v3 import D13NaturalHistorySelectionV1
    from sylanne3.model_broker.natural_reply_history_v4 import (
        D13NaturalDetailPartV1, NaturalReplyInputV4, freeze_natural_reply_request_v4,
    )
    base = frozen()
    audience = base.input.plan.audience_ref
    stable = (replace(base.input.stable_history[0], audience_ref=audience),)
    source = stable[0].dependencies[0]
    details = (D13NaturalDetailPartV1(0, source, "user:one", text, 140.0),)
    selection = D13NaturalHistorySelectionV1(
        "a" * 64, 0, ((0, 0),), (), (source,),
        (base.input.plan.scene_ref, audience, source, stable[0].ref),
        base.input.plan.scene_ref, audience, base.input.plan.audience_id,
        140.0, 1, 1, 1, stable[0].ref, (),
        canonical_digest({"stable_history": stable, "recent_history": (),
            "detail_history": details, "coverage": ((0, 0),), "gaps": ()}),
        "test:installed-selection", "b" * 64,
    )
    return freeze_natural_reply_request_v4(NaturalReplyInputV4(
        replace(base.input.question, audience_ref=audience), base.input.plan,
        stable, (), selection, details, 100.0, 130.0), base.installation)


def test_v4_detail_values_are_dynamic_and_old_v2_wire_remains_unchanged():
    from sylanne3.model_broker.natural_reply_history_v4 import TEMPLATE_VERSION
    old = frozen()
    first = _frozen_v4_with_details()
    second = _frozen_v4_with_details("Another selected exact detail")
    assert first.stable_prefix_digest == second.stable_prefix_digest
    assert first.canonical_wire != second.canonical_wire
    stable, dynamic = (json.loads(first.messages[i].content) for i in (1, 2))
    assert stable["schema"] == TEMPLATE_VERSION
    assert "detail_history" not in stable
    assert dynamic["detail_history"][0]["text"] == "Earlier exact detail"
    assert set(dynamic["detail_history"][0]) == {
        "sequence", "source_ref", "speaker_ref", "text", "expires_at_utc"}
    assert frozen() == old


def test_v4_codec_and_detail_tamper_checks():
    from dataclasses import asdict
    from sylanne3.model_broker.natural_reply_history_v4 import (
        thaw_natural_reply_request_v4, parse_natural_reply_output_v4,
    )
    from sylanne3.runtime_contracts import canonical_serialize
    request = _frozen_v4_with_details()
    serialized = json.loads(canonical_serialize(asdict(request)))
    assert thaw_natural_reply_request_v4(serialized) == request
    serialized["input"]["detail_history"][0]["text"] = "forged"
    with pytest.raises(ValueError):
        thaw_natural_reply_request_v4(serialized)
    candidate = parse_natural_reply_output_v4(json.dumps(output()), request)
    assert candidate.status == "untrusted_content_candidate"
