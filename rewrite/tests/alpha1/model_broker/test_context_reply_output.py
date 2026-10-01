"""A parsed context reply is bound to one input, but grants no send authority."""

import json

import pytest

from rewrite.tests.alpha1.contracts.test_context_reply_contract import (
    INSTALLATION, example_input, part, ref,
)
from sylanne3.model_broker.context_reply import (
    OUTPUT_SCHEMA, freeze_context_reply_request_v1,
    parse_context_reply_output_v1,
)


def _output(**changes):
    payload = {
        "schema": OUTPUT_SCHEMA,
        "body": "The door opened.",
        "spans": [{
            "start": 0, "end": 16, "source_ref": "source:1",
            "source_revision": 1, "access_ref": "access:1",
            "access_revision": 2, "source_quote": "The door opened.",
        }],
    }
    return payload | changes


def test_parsed_output_retains_frozen_digest_without_claiming_paid_result():
    frozen = freeze_context_reply_request_v1(example_input(), INSTALLATION)
    parsed = parse_context_reply_output_v1(json.dumps(_output()), frozen)
    assert parsed.frozen_input_digest == frozen.digest
    assert parsed.d09_payload() == _output()
    assert not hasattr(parsed, "authority_result_read")
    assert not hasattr(parsed, "actual_input_tokens")


def test_empty_model_refusal_is_explicit_no_reply_hold():
    frozen = freeze_context_reply_request_v1(example_input(), INSTALLATION)
    parsed = parse_context_reply_output_v1(
        json.dumps({"schema": OUTPUT_SCHEMA, "body": "", "spans": []}), frozen)
    assert parsed.status == "no_reply_hold"
    assert parsed.frozen_input_digest == frozen.digest
    with pytest.raises(ValueError, match="no-reply"):
        parsed.d09_payload()


@pytest.mark.parametrize("payload", [
    _output(body="The door opened. And she was happy."),
    _output(spans=[_output()["spans"][0] | {"source_revision": True}]),
    _output(spans=[_output()["spans"][0] | {"source_quote": "different"}]),
    _output(spans=[_output()["spans"][0] | {"extra": "bad"}]),
])
def test_unmapped_or_malformed_spans_are_rejected(payload):
    frozen = freeze_context_reply_request_v1(example_input(), INSTALLATION)
    with pytest.raises(ValueError):
        parse_context_reply_output_v1(json.dumps(payload), frozen)


def test_duplicate_json_field_is_rejected():
    frozen = freeze_context_reply_request_v1(example_input(), INSTALLATION)
    text = json.dumps(_output()).replace('"body":', '"body": "hidden", "body":', 1)
    with pytest.raises(ValueError, match="repeats"):
        parse_context_reply_output_v1(text, frozen)


def test_stable_prefix_is_exact_wire_bytes_before_dynamic_tail():
    base = example_input()
    original = freeze_context_reply_request_v1(base, INSTALLATION)
    changed = freeze_context_reply_request_v1(
        example_input(
            question=part("question", "turn:current", "What happened next?"),
            history=(part("d13_history", "d13:raw:2", "Recent raw turn.",
                          dependencies=(ref("source:older"),)),),
        ), INSTALLATION)
    assert original.stable_prefix_wire == changed.stable_prefix_wire
    assert original.stable_prefix_digest == changed.stable_prefix_digest
    assert original.digest != changed.digest
    assert original.canonical_wire.startswith(original.stable_prefix_wire)
    assert changed.canonical_wire.startswith(changed.stable_prefix_wire)

    block_ref = '["persona","bot","persona",null,"d13.compressed_turn_block.v2","block-1"]'
    stable = part("d13_history", block_ref, "Older frozen block.",
                  dependencies=(ref("source:older"),))
    with_block = freeze_context_reply_request_v1(
        example_input(stable_history=(stable,)), INSTALLATION)
    assert with_block.stable_prefix_wire != original.stable_prefix_wire
    assert with_block.stable_prefix_digest != original.stable_prefix_digest
    with pytest.raises(ValueError, match="stable history"):
        example_input(stable_history=(part(
            "d13_history", "d13:raw:2", "raw cannot be stable",
            dependencies=(ref("source:older"),)),))
