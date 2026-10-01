"""Context text is only a D09 content candidate, never final admission."""

from dataclasses import replace

import pytest

from sylanne3.domains.d09 import (
    CONTEXT_REPLY_OUTPUT_SCHEMA, ClaimKind, issue_context_reply_expression_v1,
)
from sylanne3.model_broker.context_reply import (
    ContextReplyInputV1, ContextReplyInstallationV1, ContextReplyPartV1,
    freeze_context_reply_request_v1,
)
from sylanne3.runtime_contracts import NamespaceId, VersionedRef


def _case():
    audience = VersionedRef("entity:alice", 2)
    kwargs = {"audience_ref": audience, "expires_at_utc": 150.0}
    current = ContextReplyInputV1(
        NamespaceId("bot", "persona"), VersionedRef("scene:private", 3),
        audience, "conversation:one", 2, 1, 4, 100.0, 140.0,
        ContextReplyPartV1("question", VersionedRef("turn:question", 1),
                           text="What happened?", **kwargs),
        (ContextReplyPartV1(
            "d06_evidence", VersionedRef("source:door", 7),
            text="The door opened.", access_ref=VersionedRef("access:door", 5),
            **kwargs,
        ),),
        history=(ContextReplyPartV1(
            "d13_history", VersionedRef("d13:block:one", 1),
            text="Someone said the window broke.",
            dependencies=(VersionedRef("source:older", 1),), **kwargs,
        ),),
    )
    installed = ContextReplyInstallationV1(
        "installation:one", "a" * 64, "provider:one", "model:one", 128,
    )
    frozen = freeze_context_reply_request_v1(current, installed)
    result = {
        "schema": CONTEXT_REPLY_OUTPUT_SCHEMA,
        "body": "The door opened.",
        "spans": [{
            "start": 0, "end": 16, "source_ref": "source:door",
            "source_revision": 7, "access_ref": "access:door",
            "access_revision": 5, "source_quote": "The door opened.",
        }],
    }
    return current, frozen, result


def _issue(current, frozen, result):
    return issue_context_reply_expression_v1(
        result, frozen_request=frozen, current_input=current,
        scene_ref="scene:private", covered_slots=("answer",),
        max_chars=200, now_utc=110.0,
    )


def test_exact_d06_quote_is_only_a_content_verified_hold_candidate():
    current, frozen, result = _case()
    reviewed = _issue(current, frozen, result)
    assert reviewed.status == "content_verified_source_hold"
    assert len(reviewed.claims) == len(reviewed.segments) == 1
    assert reviewed.claims[0].kind is ClaimKind.REPORTED_CLAIM
    assert reviewed.claims[0].source_refs == ("source:door",)
    assert reviewed.segments[0].body == result["body"]
    assert reviewed.input_digest == frozen.digest
    assert reviewed.payload_digest is not None


@pytest.mark.parametrize("source,quote", [
    ("d13:block:one", "Someone said the window broke."),
    ("source:door", "The window broke."),
])
def test_d13_or_unsupported_natural_claim_stays_hold(source, quote):
    current, frozen, result = _case()
    result["body"] = quote
    result["spans"][0].update(start=0, end=len(quote), source_ref=source,
                               source_quote=quote)
    reviewed = _issue(current, frozen, result)
    assert reviewed.status == "hold"
    assert reviewed.claims == reviewed.segments == ()
    assert reviewed.missing == ("d06_exact_source:0",)


def test_stale_access_or_input_and_unmapped_body_cannot_qualify():
    current, frozen, result = _case()
    changed = replace(current, evidence=(replace(
        current.evidence[0], access_ref=VersionedRef("access:door", 6)),))
    with pytest.raises(ValueError, match="changed or expired"):
        _issue(changed, frozen, result)
    result["spans"][0]["access_revision"] = 6
    assert _issue(current, frozen, result).status == "hold"
    result["body"] = "The door opened. Also I am sad."
    with pytest.raises(ValueError, match="unmapped content"):
        _issue(current, frozen, result)
