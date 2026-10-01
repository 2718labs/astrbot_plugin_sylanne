"""D13 model wire freeze and untrusted extractive-candidate boundary."""

from dataclasses import replace
import hashlib
import json

import pytest

from sylanne3.model_broker.d13_precompression import (
    D13ExactTokenCountV1,
    D13PrecompressionInstallationV1,
    compile_untrusted_d13_candidate_v1,
    d13_model_request_shape_valid_v1,
    freeze_d13_precompression_request_v1,
    gate_d13_exact_token_count_v1,
    issue_unadmitted_d13_model_request_v1,
    parse_d13_precompression_output_v1,
)
from sylanne3.model_broker.broker import ModelCallRequest
from sylanne3.model_broker.natural_reply import NaturalReplyInstallationV2
from sylanne3.domains.d13.precompression import plan_precompression
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, CompletedTurnV1,
    ConversationWindowProjectionV1, NamespaceId, OperationIdentity,
    SourceQualification, VersionGuard, VersionedRef, canonical_digest,
)


def _ref(name, version=1):
    return VersionedRef(name, version)


def _window(now=100_000):
    scene, audience = _ref("scene"), _ref("audience")
    turns = tuple(CompletedTurnV1(
        "conversation", audience, sequence, _ref(f"raw:{sequence}"),
        _ref(f"source:{sequence}"), _ref(f"access:{sequence}"),
        f"speaker:{sequence % 2}", "Hello there. " + chr(97 + sequence) * 120,
        now - 100 + sequence, "confirmed", "not_applicable",
    ) for sequence in range(8))
    dependencies = tuple(
        ref for turn in turns for ref in (turn.raw_ref, turn.source_ref, turn.access_ref)
    )
    return ConversationWindowProjectionV1(
        NamespaceId("bot", "persona"), "owner", "conversation", scene, audience,
        turns, 7, now, dependencies, (scene, audience, *dependencies), 2, 3, 4,
    )


def _planned():
    window = _window()
    plan = plan_precompression(
        window, 1000, background_capacity=True, outstanding_candidate=False,
    )
    assert plan is not None
    installation = D13PrecompressionInstallationV1(
        "installation:main", "provider:conversation", "model:conversation", "a" * 64, 1024,
    )
    return window, plan, installation


def _output(plan):
    return json.dumps({
        "schema": "d13.extractive_model_output.v1",
        "turns": [
            {"sequence": sequence, "beat": "Hello there.", "details": []}
            for sequence in range(plan.first_sequence, plan.last_sequence + 1)
        ],
    })


def _envelope(window, plan):
    refs = ("d13:source",)
    return CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity", None, "attempt", "d13.precompress",
                          plan.job_ref, canonical_digest({"input_refs": list(refs)})),
        AuthorityContext("worker", "d13", "cap", window.namespace,
                         ("persona",), "proposal", ("owner",), "policy", 1, 1),
        VersionGuard((), (), window.access_epoch, window.delete_epoch,
                     "catalogue", "scheme", "operator", "policy", (), (), ()),
        SourceQualification((), "reported", None, 1.0,
                            "external_report", "qualified", None, "actual"),
        refs, "budget", float(window.trusted_utc + 100), 1.0, "clock", (),
    )


def test_freeze_contains_exact_source_closure_ttl_and_wire_digest():
    window, plan, installation = _planned()
    frozen = freeze_d13_precompression_request_v1(window, plan, installation)
    assert frozen.digest == canonical_digest(json.loads(frozen.canonical_input))
    assert frozen.wire_digest == hashlib.sha256(
        frozen.canonical_wire.encode("utf-8")
    ).hexdigest()
    assert frozen.turns[0].source_ref.ref == f"source:{plan.first_sequence}"
    assert all(ref in window.read_set for ref in plan.source_dependencies)
    assert f"{plan.expires_at_utc}" in frozen.canonical_input
    assert window.turns[plan.first_sequence].text in frozen.canonical_input
    assert "raw:0" not in frozen.canonical_input
    for bound_identity in (installation.installation_id, installation.provider_id,
                           installation.model_id, installation.provider_config_digest):
        assert bound_identity in frozen.canonical_wire


def test_optional_natural_workflow_installation_cannot_be_used_as_main_identity():
    window, plan, _ = _planned()
    optional_natural_workflow = NaturalReplyInstallationV2(
        "installation:natural", "b" * 64, "provider:other", "model:other", 512,
    )
    with pytest.raises(TypeError, match="main-conversation"):
        freeze_d13_precompression_request_v1(window, plan, optional_natural_workflow)


def test_parsed_output_only_becomes_w14_compiled_candidate():
    window, plan, installation = _planned()
    frozen = freeze_d13_precompression_request_v1(window, plan, installation)
    untrusted = parse_d13_precompression_output_v1(_output(plan), frozen)
    block = compile_untrusted_d13_candidate_v1(frozen, untrusted)
    assert block.status == "candidate"
    assert block.job_ref == plan.job_ref
    assert block.turns[0].raw_ref == window.turns[plan.first_sequence].raw_ref
    assert not hasattr(untrusted, "paid_call_receipt")
    assert not hasattr(untrusted, "activated")
    assert not hasattr(untrusted, "cache_hit")
    assert not hasattr(untrusted, "token_budget")


@pytest.mark.parametrize("mutate", [
    lambda value: value | {"activated": True},
    lambda value: value | {"paid": True},
    lambda value: value | {"status": "standby"},
])
def test_parser_rejects_forged_authority_activation_or_payment_fields(mutate):
    _, plan, installation = _planned()
    frozen = freeze_d13_precompression_request_v1(_window(), plan, installation)
    payload = json.loads(_output(plan))
    with pytest.raises(ValueError, match="shape"):
        parse_d13_precompression_output_v1(json.dumps(mutate(payload)), frozen)


def test_wrong_turn_order_and_cross_wire_candidate_are_rejected():
    window, plan, installation = _planned()
    frozen = freeze_d13_precompression_request_v1(window, plan, installation)
    payload = json.loads(_output(plan))
    payload["turns"][0]["sequence"] += 1
    with pytest.raises(ValueError, match="shape or order"):
        parse_d13_precompression_output_v1(json.dumps(payload), frozen)

    candidate = parse_d13_precompression_output_v1(_output(plan), frozen)
    other = freeze_d13_precompression_request_v1(
        window, plan, replace(installation, model_id="other:model"),
    )
    with pytest.raises(ValueError, match="not bound"):
        compile_untrusted_d13_candidate_v1(other, candidate)


def test_source_mutation_cannot_be_frozen_against_stale_plan():
    window, plan, installation = _planned()
    changed_turn = replace(window.turns[plan.first_sequence], text="changed source text")
    changed_window = replace(
        window,
        turns=tuple(changed_turn if turn.sequence == changed_turn.sequence else turn
                    for turn in window.turns),
    )
    with pytest.raises(ValueError, match="stale, incomplete"):
        freeze_d13_precompression_request_v1(changed_window, plan, installation)


def test_optional_background_token_count_stays_unknown_and_rejects_mismatched_evidence():
    window, plan, installation = _planned()
    frozen = freeze_d13_precompression_request_v1(window, plan, installation)
    # Latest background contract permits a separately signed bounded quote.
    # This shape gate grants no budget or model-egress authority.
    unknown = gate_d13_exact_token_count_v1(frozen, None)
    assert (unknown.status, unknown.exact_input_tokens, unknown.reason) == ("ready", None, None)

    message_digest = hashlib.sha256(frozen.messages_wire.encode("utf-8")).hexdigest()
    valid = D13ExactTokenCountV1(
        installation.provider_id, installation.model_id,
        installation.provider_config_digest, message_digest, frozen.wire_digest, 900,
        "tokenizer:provider-exact-v1",
    )
    ready = gate_d13_exact_token_count_v1(frozen, valid)
    assert (ready.status, ready.exact_input_tokens, ready.reason) == ("ready", 900, None)

    for mismatched in (
        replace(valid, quality="estimated"),
        replace(valid, provider_id="other:provider"),
        replace(valid, provider_config_digest="b" * 64),
        replace(valid, messages_digest="c" * 64),
        replace(valid, wire_digest="d" * 64),
    ):
        assert gate_d13_exact_token_count_v1(frozen, mismatched).status == "hold"


def test_unadmitted_model_request_binds_template_main_installation_and_full_wire():
    window, plan, installation = _planned()
    frozen = freeze_d13_precompression_request_v1(window, plan, installation)
    request = issue_unadmitted_d13_model_request_v1(
        _envelope(window, plan), frozen, call_id="d13-call", timeout_seconds=20,
        privacy_tier="private",
    )
    assert type(request) is ModelCallRequest
    assert d13_model_request_shape_valid_v1(request, frozen)
    assert not d13_model_request_shape_valid_v1(
        replace(request, payload={**request.payload, "prompt": "different"}), frozen)
    assert not d13_model_request_shape_valid_v1(
        replace(request, provider_id="other-provider"), frozen)
    assert not d13_model_request_shape_valid_v1(
        request, replace(frozen, canonical_wire="different"))
    assert not d13_model_request_shape_valid_v1(
        request, replace(frozen, template_version="other-template"))
    with pytest.raises(ValueError, match="job scope"):
        issue_unadmitted_d13_model_request_v1(
            replace(_envelope(window, plan),
                    identity=replace(_envelope(window, plan).identity,
                                     phase="reply")),
            frozen, call_id="d13-call", timeout_seconds=20,
            privacy_tier="private",
        )


def test_changed_correction_or_deletion_read_closure_changes_frozen_identity():
    window, plan, installation = _planned()
    original = freeze_d13_precompression_request_v1(window, plan, installation)
    # Window read_set is the local current-read closure; this added ref stands
    # for a changed correction/deletion head returned by the authoritative reader.
    changed_window = replace(
        window, read_set=(*window.read_set, _ref("correction-or-delete-head", 9)),
    )
    changed = freeze_d13_precompression_request_v1(changed_window, plan, installation)
    assert original.read_closure_digest != changed.read_closure_digest
    assert original.digest != changed.digest
    assert original.wire_digest != changed.wire_digest
