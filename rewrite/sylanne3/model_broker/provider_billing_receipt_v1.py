"""A pinned provider's signed final charge; never a price estimate or grant."""
from dataclasses import asdict, dataclass, fields
import json
import re

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


EXTENSION_KEY = "sylanne_billing_receipt_v1"
SIGNING_DOMAIN = b"sylanne.provider-billing-receipt.v1\0"
MAX_RECEIPT_BYTES = 16384
EVIDENCE_KINDS = frozenset({"provider_final_charge", "fixture_simulated_charge"})


def _text(value, name):
    if type(value) is not str or not 1 <= len(value) <= 256:
        raise ValueError("invalid provider billing " + name)


def _hex(value, size):
    if type(value) is not str or re.fullmatch("[0-9a-f]{" + str(size) + "}", value) is None:
        raise ValueError("invalid provider billing commitment or key")


def _quantity(value):
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ValueError("invalid final provider billing amount")


@dataclass(frozen=True, slots=True)
class ProviderBillingPolicyV1:
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    provider_id: str
    model_id: str
    provider_config_digest: str
    contract_id: str
    contract_version: int
    provider_ed25519_public_key_hex: str
    evidence_kind: str
    currency: str = "USD"
    unit: str = "model_microusd"
    schema: str = "sylanne.provider-billing-policy.v1"

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId
                or self.schema != "sylanne.provider-billing-policy.v1"
                or type(self.contract_version) is not int or self.contract_version != 1
                or self.evidence_kind not in EVIDENCE_KINDS
                or (self.currency, self.unit) != ("USD", "model_microusd")):
            raise ValueError("unsupported installed provider billing contract")
        for name in ("installation_id", "provider_id", "model_id", "contract_id"):
            _text(getattr(self, name), name)
        for name in ("manifest_digest", "provider_config_digest", "provider_ed25519_public_key_hex"):
            _hex(getattr(self, name), 64)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.provider_ed25519_public_key_hex))

    @property
    def contract_digest(self):
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class ProviderBillingReceiptV1:
    contract_digest: str
    evidence_kind: str
    installation_id: str
    manifest_digest: str
    provider_id: str
    model_id: str
    provider_config_digest: str
    call_id: str
    request_digest: str
    provider_call_ref: str
    receipt_id: str
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int | None
    final_charged_amount: int
    signature_hex: str
    charge_status: str = "final"
    currency: str = "USD"
    unit: str = "model_microusd"
    schema: str = "sylanne.provider-billing-receipt.v1"

    def __post_init__(self):
        if (self.schema != "sylanne.provider-billing-receipt.v1"
                or self.evidence_kind not in EVIDENCE_KINDS
                or (self.charge_status, self.currency, self.unit) != ("final", "USD", "model_microusd")):
            raise ValueError("provider billing requires an explicit final charge")
        for name in ("installation_id", "provider_id", "model_id", "call_id", "provider_call_ref", "receipt_id"):
            _text(getattr(self, name), name)
        for name in ("contract_digest", "manifest_digest", "provider_config_digest", "request_digest"):
            _hex(getattr(self, name), 64)
        _hex(self.signature_hex, 128)
        for value in (self.input_tokens, self.output_tokens, self.final_charged_amount):
            _quantity(value)
        if self.cached_input_tokens is not None:
            _quantity(self.cached_input_tokens)
            if self.cached_input_tokens > self.input_tokens:
                raise ValueError("provider billing cached usage exceeds measured input")
        if len(canonical_serialize(asdict(self)).encode("utf-8")) > MAX_RECEIPT_BYTES:
            raise ValueError("provider billing receipt exceeds its fixed metadata bound")

    @property
    def usage(self):
        result = {"input_tokens": self.input_tokens, "output_tokens": self.output_tokens}
        if self.cached_input_tokens is not None:
            result["cached_input_tokens"] = self.cached_input_tokens
        return result

    def to_wire(self):
        return asdict(self)

    @property
    def encoded(self):
        return canonical_serialize(self.to_wire())


def provider_billing_policy_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(ProviderBillingPolicyV1)}:
        raise ValueError("exact provider billing policy fields required")
    data = dict(raw)
    if type(data["namespace"]) is not dict or set(data["namespace"]) != {"bot_id", "persona_id"}:
        raise ValueError("exact provider billing namespace required")
    data["namespace"] = NamespaceId(**data["namespace"])
    return ProviderBillingPolicyV1(**data)


def provider_billing_receipt_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(ProviderBillingReceiptV1)}:
        raise ValueError("exact provider billing receipt fields required")
    return ProviderBillingReceiptV1(**raw)


def provider_billing_receipt_from_json_v1(encoded):
    if type(encoded) is not str or len(encoded.encode("utf-8")) > MAX_RECEIPT_BYTES:
        raise ValueError("bounded provider billing receipt JSON required")
    receipt = provider_billing_receipt_from_wire_v1(json.loads(encoded))
    if receipt.encoded != encoded:
        raise ValueError("canonical provider billing receipt JSON required")
    return receipt


def provider_billing_receipt_signing_bytes_v1(receipt):
    payload = receipt.to_wire()
    payload.pop("signature_hex")
    return SIGNING_DOMAIN + canonical_serialize(payload).encode("utf-8")


def require_installed_provider_billing_policy_v1(policy, bundle, workflow):
    installation = bundle.installation_policy
    if (type(policy) is not ProviderBillingPolicyV1
            or bundle.provider_billing_policy_v1 is not policy
            or (policy.namespace, policy.installation_id, policy.manifest_digest,
                policy.provider_id, policy.model_id, policy.provider_config_digest) !=
               (installation.namespace, installation.installation_id, installation.manifest_digest,
                workflow.provider_id, workflow.model_id, workflow.provider_config_digest)):
        raise ValueError("provider billing contract differs from the actual installed selection")
    return policy


def provider_billing_request_metadata_v1(policy, request):
    if policy is None:
        return {}
    if (request.provider_id, request.model_id) != (policy.provider_id, policy.model_id):
        raise ValueError("provider billing request selection differs")
    return {"metadata": {"sylanne_call_id": request.call_id,
        "sylanne_request_digest": request.digest, "sylanne_billing_contract": policy.contract_digest}}


def verify_provider_billing_receipt_v1(policy, *, request, provider_call_ref, response_model, usage, raw):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    receipt = provider_billing_receipt_from_wire_v1(raw)
    if ((receipt.contract_digest, receipt.evidence_kind, receipt.installation_id,
            receipt.manifest_digest, receipt.provider_id, receipt.model_id, receipt.provider_config_digest,
            receipt.call_id, receipt.request_digest, receipt.provider_call_ref) !=
           (policy.contract_digest, policy.evidence_kind, policy.installation_id,
            policy.manifest_digest, policy.provider_id, policy.model_id, policy.provider_config_digest,
            request.call_id, request.digest, provider_call_ref)
            or (request.provider_id, request.model_id, response_model) !=
                (policy.provider_id, policy.model_id, policy.model_id)
            or receipt.usage != usage):
        raise ValueError("provider billing receipt differs from the actual request, response or usage")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(policy.provider_ed25519_public_key_hex)).verify(
            bytes.fromhex(receipt.signature_hex), provider_billing_receipt_signing_bytes_v1(receipt))
    except InvalidSignature as error:
        raise ValueError("provider billing signature is invalid") from error
    return receipt
