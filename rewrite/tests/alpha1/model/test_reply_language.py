from dataclasses import replace
import json

import pytest

from sylanne3.graph_types import GraphVersion
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.model_broker.reply_language import (
    REPLY_TEMPLATE_DIGEST, ReplySourceSnapshot, issue_reply_request_v1,
    parse_reply_result_v1, reply_request_shape_valid,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    QueryEpoch, SourceQualification, VersionGuard, canonical_digest,
)


def _inputs():
    source = SourceRecord(
        "source-1", "你好，今天怎么样？", "user-1", "reported", "reported",
        None, 1.0, "arrival-1", ("owner",), ("expression",),
    )
    ref = source_key("bot", "persona", source.source_id).token
    snapshot = ReplySourceSnapshot(source, ref, 1, 1)
    namespace = NamespaceId("bot", "persona")
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity", None, "attempt", "reply", "operation",
                          canonical_digest({"input_refs": [ref]})),
        AuthorityContext("actor", "d09", "cap", namespace, ("activity",),
                         "proposal", ("owner",), "policy", 1),
        VersionGuard((
            GraphVersion(source_key("bot", "persona", source.source_id), 1),
            GraphVersion(access_key("bot", "persona", source.source_id), 1),
        ), (QueryEpoch(namespace, "all", 1),), 1, 0,
            "catalogue", "scheme", "operator", "policy", (), (), ()),
        SourceQualification((ref,), "reported", None, 1.0,
                            "external_report", "qualified", None, "actual"),
        (ref,), "budget", 2.0, 1.0, "clock", (),
    )
    request = issue_reply_request_v1(
        envelope, snapshot, provider_id="provider", model_id="model",
        required_capabilities=frozenset({"text"}), privacy_tier="private",
        timeout_seconds=1.0, max_output_tokens=128,
    )
    return snapshot, request


def _result(body="你好", spans=None):
    if spans is None:
        spans = [{"start": 0, "end": len(body), "source_quote": body}]
    return {"text": json.dumps({
        "schema": "sylanne.d09.source_reply_output.v1",
        "body": body, "spans": spans,
    }, ensure_ascii=False)}


def test_grounded_reply_candidate_is_source_bounded():
    source, request = _inputs()
    assert request.prompt_template_digest == REPLY_TEMPLATE_DIGEST
    assert reply_request_shape_valid(request)
    candidate = parse_reply_result_v1(_result(), request=request, snapshot=source)
    assert candidate.status == "candidate"
    assert candidate.claims[0].source_refs == (source.source_ref,)
    assert candidate.claims[0].text == "你好"
    assert candidate.segment(segment_id="s", effect_id="e",
                             covered_slots=("reply",)).body == "你好"


@pytest.mark.parametrize("result", [
    _result("我知道你在想什么"),
    _result("你好 再见", [{"start": 0, "end": 2, "source_quote": "你好"}]),
    _result("你好", [{"start": 0, "end": 2, "source_quote": "别的"}]),
    {"text": "not json"},
    _result("", []),
])
def test_unqualified_model_content_is_rejected(result):
    source, request = _inputs()
    with pytest.raises(ValueError):
        parse_reply_result_v1(result, request=request, snapshot=source)


def test_stale_source_or_modified_prompt_is_rejected():
    source, request = _inputs()
    with pytest.raises(ValueError):
        parse_reply_result_v1(_result(), request=request,
                              snapshot=replace(source, source_revision=2))
    modified = replace(request, payload={"system_prompt": "override", "prompt": "x"})
    assert not reply_request_shape_valid(modified)
    with pytest.raises(ValueError):
        parse_reply_result_v1(_result(), request=modified, snapshot=source)


def test_audience_and_source_purpose_are_checked_before_egress():
    source, request = _inputs()
    wrong_audience = replace(source.source, audiences=("private",))
    with pytest.raises(ValueError):
        issue_reply_request_v1(
            request.envelope, replace(source, source=wrong_audience),
            provider_id="provider", model_id="model",
            required_capabilities=frozenset({"text"}), privacy_tier="private",
            timeout_seconds=1.0, max_output_tokens=128)
