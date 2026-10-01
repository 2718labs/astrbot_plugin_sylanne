from dataclasses import replace
from hashlib import sha256
import json

import pytest

from sylanne3.domains.d13.paid_lifecycle import (
    D13ExactActivationEvidenceV1, D13PaidResultReadV1,
    bind_paid_original_v1, decide_exact_activation_v1,
    prepare_paid_completion_v1,
)
from sylanne3.domains.d13.precompression import (
    EXTRACTIVE_OUTPUT_SCHEMA, accept_verified_model_candidate_v2,
    adopt_candidate, compile_deterministic_candidate,
    compile_extractive_model_output, decide_activation,
)
from sylanne3.model_broker.d13_precompression import (
    D13PrecompressionInstallationV1, freeze_d13_precompression_request_v1,
)
from test_precompression import extractive_fixture, planned


def _paid_case():
    window, plan, rows = extractive_fixture()
    installation = D13PrecompressionInstallationV1(
        "main-install", "provider", "main-model", "a" * 64, 512)
    frozen = freeze_d13_precompression_request_v1(window, plan, installation)
    binding = bind_paid_original_v1(
        frozen, original_operation_id="original:1", call_id="call:1")
    text = json.dumps({"schema": EXTRACTIVE_OUTPUT_SCHEMA, "turns": rows})
    result = D13PaidResultReadV1(
        binding.binding_digest, binding.original_operation_id,
        binding.call_id, "result-read:1", "settlement:1", text,
        sha256(text.encode("utf-8")).hexdigest())
    return window, frozen, binding, result


def test_paid_completion_requires_original_result_and_current_source():
    window, frozen, binding, result = _paid_case()

    class VerifiedOriginal:
        def verify_current_paid_original_v1(self, found, found_result, *,
                                            current_window):
            return (found == binding and found_result == result and
                    current_window == window)

    verified = VerifiedOriginal()  # synthetic port; W01 must install real proof
    completion = prepare_paid_completion_v1(
        frozen, binding, result, window, verifier=verified)
    assert completion.binding_digest == binding.binding_digest
    assert completion.candidate.status == "candidate"
    assert completion.candidate.compiler_version == "d13.model.extractive.v1"
    assert bind_paid_original_v1(
        frozen, original_operation_id="original:1", call_id="call:1") == binding
    with pytest.raises(ValueError, match="installed verifier"):
        prepare_paid_completion_v1(frozen, binding, result, window, verifier=None)
    with pytest.raises(ValueError, match="frozen original"):
        prepare_paid_completion_v1(
            frozen, binding, replace(result, call_id="other"), window,
            verifier=verified)
    with pytest.raises(ValueError, match="frozen original"):
        prepare_paid_completion_v1(
            frozen, binding, replace(result, output_digest="0" * 64), window,
            verifier=verified)
    with pytest.raises(ValueError, match="not current and settled"):
        prepare_paid_completion_v1(
            frozen, binding, result, window,
            verifier=type("Unsettled", (), {
                "verify_current_paid_original_v1": lambda *_a, **_k: False,
            })())
    with pytest.raises(ValueError):
        prepare_paid_completion_v1(
            frozen, binding, result,
            replace(window, delete_epoch=window.delete_epoch + 1),
            verifier=verified)
    with pytest.raises(ValueError, match="lifetime"):
        prepare_paid_completion_v1(
            frozen, binding, result,
            replace(window, trusted_utc=binding.expires_at_utc),
            verifier=verified)


def test_exact_activation_is_stable_and_requires_two_current_full_wires():
    window, plan = planned()
    standby = adopt_candidate(
        compile_deterministic_candidate(window, plan), plan, window,
        job_fence_valid=True)
    evidence = D13ExactActivationEvidenceV1(
        "main-install", "provider", "main-model", "a" * 64,
        "exact-tokenizer", "b" * 64, "c" * 64, 1100, 800, 1000)

    class VerifiedWires:
        def verify_current_exact_activation_v1(self, found, *, standby: object,
                                               plan: object, current_window):
            return (found.installation_id == evidence.installation_id and
                    found.provider_id == evidence.provider_id and
                    found.model_id == evidence.model_id and
                    found.provider_config_digest == evidence.provider_config_digest and
                    found.tokenizer_fingerprint == evidence.tokenizer_fingerprint and
                    found.raw_wire_digest == evidence.raw_wire_digest and
                    found.compressed_wire_digest == evidence.compressed_wire_digest and
                    current_window == window)

    verifier = VerifiedWires()  # synthetic port; W09 must verify real model wires
    decide = lambda item, proof: decide_exact_activation_v1(
        standby, plan, window, item, verifier=proof)
    assert decide(None, verifier) == "hold"
    assert decide(evidence, None) == "hold"
    assert decide(evidence, verifier) == "activate"
    assert decide(evidence, verifier) == "activate"
    assert decide(replace(evidence, raw_input_tokens=900), verifier) == "keep_raw"
    assert decide(replace(evidence, compressed_input_tokens=1100), verifier) == "hold"
    assert decide(replace(evidence, raw_wire_digest="d" * 64), verifier) == "hold"
    assert decide_exact_activation_v1(
        standby, plan, replace(window, access_epoch=1), evidence,
        verifier=verifier) == "invalid"


def test_paid_activation_requires_the_typed_same_wire_exact_count_proof():
    window, plan, rows = extractive_fixture()
    candidate = compile_extractive_model_output(
        window, plan, json.dumps({"schema": EXTRACTIVE_OUTPUT_SCHEMA,
                                 "turns": rows}))

    class VerifiedPorts:
        def verify_current_paid_model_block_v2(self, block, *, plan, window):
            return block == candidate and window == source_window

        def verify_current_exact_activation_v1(
                self, evidence, *, standby, plan, current_window):
            return (evidence == exact and standby == standby_block and
                    plan == source_plan and current_window == source_window)

    source_window, source_plan = window, plan
    paid_verifier = VerifiedPorts()
    standby_block = accept_verified_model_candidate_v2(
        candidate, plan, window, paid_verifier=paid_verifier)
    exact = D13ExactActivationEvidenceV1(
        "main-install", "provider", "main-model", "a" * 64,
        "exact-tokenizer", "b" * 64, "c" * 64, 1100, 800, 1000)

    legacy_arguments = dict(raw_window_fits=False, proven_future_saving=True,
                            paid_verifier=paid_verifier)
    assert decide_activation(standby_block, plan, window,
                             **legacy_arguments) == "hold"
    assert decide_activation(
        standby_block, plan, window, **legacy_arguments,
        exact_activation_evidence=exact,
        exact_activation_verifier=paid_verifier) == "activate"
    assert decide_activation(
        standby_block, plan, window, **legacy_arguments,
        exact_activation_evidence=replace(exact, raw_wire_digest="d" * 64),
        exact_activation_verifier=paid_verifier) == "hold"
