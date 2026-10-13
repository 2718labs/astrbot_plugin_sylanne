"""Signed billing boundaries and legacy bytes; no admission or provider call."""
from dataclasses import replace
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sylanne3.model_broker.broker import ProviderResponse
from sylanne3.model_broker.provider_billing_receipt_v1 import (
    ProviderBillingPolicyV1, ProviderBillingReceiptV1,
    provider_billing_receipt_signing_bytes_v1,
    provider_billing_request_metadata_v1, verify_provider_billing_receipt_v1,
)
from sylanne3.authority_service.v2_model_egress_contract import (
    HostObservedModelCompletionV2, host_model_completion_from_wire_v2,
    host_model_completion_to_wire_v2, model_observation_from_wire_v1,
    model_observation_to_wire_v1,
)
from sylanne3.runtime_contracts import NamespaceId
from rewrite.tests.alpha1.model_broker.test_broker import request
from rewrite.tests.alpha1.authority.test_v2_model_egress_store import intent


def _case(*, amount=7, output=4):
    call = request()
    key = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    policy = ProviderBillingPolicyV1(NamespaceId("bot", "persona"), "billing-install",
        "e" * 64, call.provider_id, call.model_id, "d" * 64, "fixture-billing", 1,
        public.hex(), "fixture_simulated_charge")
    receipt = ProviderBillingReceiptV1(policy.contract_digest, policy.evidence_kind,
        policy.installation_id, policy.manifest_digest, policy.provider_id, policy.model_id,
        policy.provider_config_digest, call.call_id, call.digest, "remote-billing", "bill-1",
        12, output, 2, amount, "0" * 128)
    receipt = replace(receipt, signature_hex=key.sign(provider_billing_receipt_signing_bytes_v1(receipt)).hex())
    return call, key, policy, receipt


def _verify(call, policy, receipt):
    return verify_provider_billing_receipt_v1(policy, request=call,
        provider_call_ref="remote-billing", response_model=call.model_id,
        usage={"input_tokens": 12, "output_tokens": 4, "cached_input_tokens": 2},
        raw=receipt.to_wire())


def test_signed_final_charge_survives_the_complete_observation_wire():
    call, _, policy, receipt = _case()
    assert _verify(call, policy, receipt) == receipt
    assert provider_billing_request_metadata_v1(policy, call) == {"metadata": {
        "sylanne_call_id": call.call_id, "sylanne_request_digest": call.digest,
        "sylanne_billing_contract": policy.contract_digest}}
    response = ProviderResponse("completed", {"text": "isolated sample"}, receipt.usage,
        {"model_microusd": 7}, receipt.provider_call_ref, receipt.encoded)
    report = HostObservedModelCompletionV2("a" * 64, "b" * 64, call.call_id, call.digest,
        call.provider_id, call.model_id, policy.provider_config_digest,
        '{"text":"isolated sample"}', tuple(sorted(response.usage.items())),
        tuple(sorted(response.cost.items())), response.provider_call_ref, response.billing_receipt_json)
    original = intent(call_id=call.call_id, request_digest=call.digest,
        provider_id=call.provider_id, model_id=call.model_id,
        provider_config_digest=policy.provider_config_digest)
    observed = report.observation_for(original)
    assert host_model_completion_from_wire_v2(host_model_completion_to_wire_v2(report)) == report
    assert model_observation_from_wire_v1(model_observation_to_wire_v1(observed)) == observed
    assert observed.billing_receipt_json == receipt.encoded
    assert dict(observed.cost) == {"model_microusd": 7}
    assert json.loads(observed.billing_receipt_json)["evidence_kind"] == "fixture_simulated_charge"


def test_signed_other_call_or_usage_and_wrong_key_cannot_supply_money():
    call, key, policy, receipt = _case()
    assert _verify(call, policy, receipt) == receipt
    for candidate in (replace(receipt, call_id="other-call"), replace(receipt, input_tokens=13)):
        signed = replace(candidate, signature_hex=key.sign(provider_billing_receipt_signing_bytes_v1(candidate)).hex())
        with pytest.raises(ValueError, match="actual request, response or usage"):
            _verify(call, policy, signed)
    wrong_key = Ed25519PrivateKey.from_private_bytes(bytes([8]) * 32)
    wrong = replace(receipt, signature_hex=wrong_key.sign(provider_billing_receipt_signing_bytes_v1(receipt)).hex())
    with pytest.raises(ValueError, match="signature is invalid"):
        _verify(call, policy, wrong)
    assert _verify(call, policy, receipt) == receipt


def test_known_zero_is_preserved_and_unconfigured_legacy_digest_is_identical():
    call, _, policy, receipt = _case(amount=0, output=0)
    verified = verify_provider_billing_receipt_v1(policy, request=call,
        provider_call_ref=receipt.provider_call_ref, response_model=call.model_id,
        usage=receipt.usage, raw=receipt.to_wire())
    response = ProviderResponse("completed", {"text": "sample"}, verified.usage,
        {"model_microusd": 0}, verified.provider_call_ref, verified.encoded)
    assert response.cost == {"model_microusd": 0} and response.usage["output_tokens"] == 0
    legacy = HostObservedModelCompletionV2("a" * 64, "b" * 64, "legacy-call", "c" * 64,
        "provider", "model", "d" * 64, '{"text":"sample"}', (("output_tokens", 1),), (), "remote")
    # Frozen legacy eleven-field report bytes, before the billing extension.
    expected = "79f06f7ca2b39257348663424fc90f5447c057ac758bd66a31acdef923a35031"
    wire = host_model_completion_to_wire_v2(legacy)
    assert "billing_receipt_json" not in wire
    assert host_model_completion_from_wire_v2(wire) == legacy and legacy.digest == expected
    assert provider_billing_request_metadata_v1(None, call) == {}
    unknown = ProviderResponse("completed", {"text": "sample"}, {"output_tokens": 1}, {}, "remote")
    assert unknown.cost == {} and unknown.billing_receipt_json is None
