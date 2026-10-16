"""Closed original-effect accounting facts; none authorizes another send."""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import math

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime.restore_anchor import RestoreAnchor
from .v2_contract import ExecutionBindingV2, MutationReceiptV2, FencePermitV2

POLICY_SCHEMA = "d02.contact-effect-pricing.v1"
MEASUREMENT_SCHEMA = "d11.contact-sender-measurement.v1"
ORIGIN_SCHEMA = "d11.contact-effect-budget-origin.v1"
FACT_SCHEMA = "authority.contact-effect-cost-fact.v1"
REQUEST_SCHEMA = "authority.contact-effect-accounting-request.v1"
GRANT_SCHEMA = "authority.contact-effect-accounting-grant.v1"
MEASUREMENT_SIGN = "authority.contact-effect-sender-measurement.v1"
ORIGIN_SIGN = "d11.contact-effect-budget-origin.v1"
SETTLEMENT_SIGN = "d11.contact-effect-settlement-original.v1"
POLICY_ALGORITHM = "astrbot.onebot.call-action-invocation.v1"


def _text(value):
    if type(value) is not str or not 1 <= len(value.encode("utf-8")) <= 4096:
        raise ValueError("bounded Contact accounting identity required")


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("exact Contact accounting SHA256 required")


def _time(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("finite Contact accounting time required")


def _amounts(value):
    if (type(value) is not tuple or not 1 <= len(value) <= 16
            or value != tuple(sorted(value)) or len({name for name, _ in value}) != len(value)):
        raise ValueError("bounded unique Contact accounting dimensions required")
    for name, amount in value:
        _text(name)
        if len(name) > 64 or type(amount) is not int or not 0 <= amount <= 10**12:
            raise ValueError("Contact accounting unit quantity differs")


@dataclass(frozen=True, slots=True)
class ContactEffectPricingPolicyV1:
    policy_ref: str
    version: int
    adapter_ref: str
    unit_cost: tuple[tuple[str, int], ...]
    valid_from_utc: float
    valid_until_utc: float
    algorithm: str = POLICY_ALGORITHM
    schema: str = POLICY_SCHEMA

    def __post_init__(self):
        _text(self.policy_ref); _text(self.adapter_ref); _amounts(self.unit_cost)
        if len(self.policy_ref) > 128:
            raise ValueError("installed Contact pricing policy identifier exceeds the D02 bound")
        _time(self.valid_from_utc); _time(self.valid_until_utc)
        if set(dict(self.unit_cost)) & {"input_tokens", "output_tokens", "model_tokens", "model_microusd", "cpu_ms", "thread_cpu_ms"}:
            raise ValueError("invocation pricing cannot fabricate model or measured CPU usage")
        if (self.schema != POLICY_SCHEMA or self.algorithm != POLICY_ALGORITHM
                or type(self.version) is not int or self.version < 1
                or self.adapter_ref != "astrbot:onebot:call_action"
                or self.valid_from_utc >= self.valid_until_utc):
            raise ValueError("exact installed Contact invocation pricing policy required")

    @property
    def digest(self): return canonical_digest(to_wire(self))


@dataclass(frozen=True, slots=True)
class ContactEffectBudgetOriginV1:
    namespace: NamespaceId
    installation_id: str
    authority_namespace: str
    operation_id: str
    activity_id: str
    effect_id: str
    attempt_id: str
    admission_ref: str
    admission_receipt_digest: str
    request_digest: str
    quote_id: str
    quote_version: int
    quote_digest: str
    parent_budget_lease_ref: str
    reservation_operation_id: str
    reservation_digest: str
    ceiling: tuple[tuple[str, int], ...]
    job_ref: str
    outbox_ref: str
    original_deadline_utc: float
    pricing_policy: ContactEffectPricingPolicyV1 | None
    schema: str = ORIGIN_SCHEMA

    def __post_init__(self):
        if self.schema != ORIGIN_SCHEMA or type(self.namespace) is not NamespaceId:
            raise ValueError("exact Contact budget origin required")
        for name in ("installation_id", "authority_namespace", "operation_id", "activity_id", "effect_id",
                "attempt_id", "admission_ref", "quote_id", "parent_budget_lease_ref", "reservation_operation_id", "job_ref", "outbox_ref"):
            _text(getattr(self, name))
        for name in ("admission_receipt_digest", "request_digest", "quote_digest", "reservation_digest"):
            _digest(getattr(self, name))
        _amounts(self.ceiling); _time(self.original_deadline_utc)
        if type(self.quote_version) is not int or self.quote_version < 1:
            raise ValueError("original quote version required")
        if self.pricing_policy is not None and type(self.pricing_policy) is not ContactEffectPricingPolicyV1:
            raise TypeError("actual installed Contact pricing policy required")

    @property
    def digest(self): return canonical_digest(to_wire(self))


@dataclass(frozen=True, slots=True)
class SignedContactEffectBudgetOriginV1:
    origin: ContactEffectBudgetOriginV1
    signature: str
    schema: str = "d11.signed-contact-effect-budget-origin.v1"

    def __post_init__(self):
        if type(self.origin) is not ContactEffectBudgetOriginV1 or self.schema != "d11.signed-contact-effect-budget-origin.v1":
            raise ValueError("signed actual Contact budget origin required")
        _text(self.signature)


@dataclass(frozen=True, slots=True)
class ContactSenderMeasurementV1:
    namespace: NamespaceId
    installation_id: str
    operation_id: str
    activity_id: str
    effect_id: str
    attempt_id: str
    handoff_id: str
    admission_ref: str
    binding_digest: str
    claim_digest: str
    start_digest: str
    adapter_ref: str
    policy_digest: str
    measurement_id: str
    invocation_count: int
    observation_id: str
    observation_outcome: str
    observed_at_utc: str
    schema: str = MEASUREMENT_SCHEMA

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or self.schema != MEASUREMENT_SCHEMA
                or self.invocation_count != 1 or type(self.invocation_count) is not int
                or self.observation_outcome not in {"accepted", "unknown"}):
            raise ValueError("one actual Sender invocation measurement required")
        for name in ("installation_id", "operation_id", "activity_id", "effect_id", "attempt_id", "handoff_id",
                "admission_ref", "adapter_ref", "measurement_id", "observation_id", "observed_at_utc"):
            _text(getattr(self, name))
        for name in ("binding_digest", "claim_digest", "start_digest", "policy_digest"):
            _digest(getattr(self, name))
        if self.adapter_ref != "astrbot:onebot:call_action":
            raise ValueError("unregistered measured Sender adapter")

    @property
    def digest(self): return canonical_digest(to_wire(self))


@dataclass(frozen=True, slots=True)
class ContactEffectMeasurementReceiptV1:
    measurement: ContactSenderMeasurementV1
    policy: ContactEffectPricingPolicyV1
    authority_id: str
    authority_namespace: str
    subject: str
    handoff_original_digest: str
    receipt_digest: str
    signature: str
    schema: str = "authority.contact-effect-measurement-receipt.v1"

    def __post_init__(self):
        if (type(self.measurement) is not ContactSenderMeasurementV1 or type(self.policy) is not ContactEffectPricingPolicyV1
                or self.measurement.policy_digest != self.policy.digest
                or self.schema != "authority.contact-effect-measurement-receipt.v1"):
            raise ValueError("actual Contact measurement/pricing receipt required")
        _text(self.authority_id); _text(self.authority_namespace); _text(self.subject)
        _digest(self.handoff_original_digest); _digest(self.receipt_digest); _text(self.signature)

    def material(self):
        return {name: value for name, value in to_wire(self).items() if name not in {"receipt_digest", "signature"}}


@dataclass(frozen=True, slots=True)
class ContactEffectCostFactV1:
    origin: SignedContactEffectBudgetOriginV1
    observed_mutation_id: str
    observed_receipt_digest: str
    binding_digest: str
    handoff_id: str
    observation_digest: str
    observation_outcome: str
    measurement: ContactEffectMeasurementReceiptV1 | None
    handoff_replay_only: bool
    schema: str = FACT_SCHEMA

    def __post_init__(self):
        if (self.schema != FACT_SCHEMA or type(self.origin) is not SignedContactEffectBudgetOriginV1
                or self.measurement is not None and type(self.measurement) is not ContactEffectMeasurementReceiptV1
                or self.observation_outcome not in {"accepted", "unknown", "delivered", "failed"}
                or self.handoff_replay_only is not True):
            raise ValueError("actual observed original Contact effect cost fact required")
        _text(self.observed_mutation_id); _text(self.handoff_id)
        for value in (self.observed_receipt_digest, self.binding_digest, self.observation_digest): _digest(value)
        if self.measurement is not None:
            m, o = self.measurement.measurement, self.origin.origin
            if (m.namespace, m.installation_id, m.operation_id, m.effect_id, m.admission_ref,
                    m.binding_digest, m.handoff_id, m.policy_digest) != (
                    o.namespace, o.installation_id, o.operation_id, o.effect_id, o.admission_ref,
                    self.binding_digest, self.handoff_id,
                    "" if o.pricing_policy is None else o.pricing_policy.digest):
                raise ValueError("Contact measurement belongs to another original once handoff or price")

    @property
    def digest(self): return canonical_digest(to_wire(self))


@dataclass(frozen=True, slots=True)
class ContactEffectAccountingRequestV1:
    operation_id: str
    origin: SignedContactEffectBudgetOriginV1
    observed_mutation_id: str
    measurement_receipt_digest: str | None
    expected_anchor: RestoreAnchor
    schema: str = REQUEST_SCHEMA

    def __post_init__(self):
        _text(self.operation_id); _text(self.observed_mutation_id)
        if (self.schema != REQUEST_SCHEMA or type(self.origin) is not SignedContactEffectBudgetOriginV1
                or type(self.expected_anchor) is not RestoreAnchor
                or self.expected_anchor.namespace != self.origin.origin.authority_namespace
                or self.operation_id == self.origin.origin.operation_id):
            raise ValueError("exact Contact effect-accounting request required")
        if self.measurement_receipt_digest is not None: _digest(self.measurement_receipt_digest)


@dataclass(frozen=True, slots=True)
class ContactEffectAccountingGrantV1:
    permit: FencePermitV2
    origin_digest: str
    fact_digest: str
    effect_id: str
    schema: str = GRANT_SCHEMA

    def __post_init__(self):
        if self.schema != GRANT_SCHEMA or type(self.permit) is not FencePermitV2 or self.permit.operation != "accounting":
            raise ValueError("actual Contact accounting maintenance permit required")
        _digest(self.origin_digest); _digest(self.fact_digest); _text(self.effect_id)


def measurement_quantities_v1(fact):
    """Price only the explicitly installed measured event; ceilings are not usage."""
    if type(fact) is not ContactEffectCostFactV1:
        raise TypeError("actual Contact cost fact required")
    ceiling = dict(fact.origin.origin.ceiling)
    if fact.measurement is None:
        return {}, tuple(sorted(ceiling))
    policy = fact.measurement.policy
    if policy != fact.origin.origin.pricing_policy or policy.algorithm != POLICY_ALGORITHM:
        raise ValueError("original installed Contact measurement policy changed")
    known = {name: amount * fact.measurement.measurement.invocation_count for name, amount in policy.unit_cost}
    if not set(known) <= set(ceiling):
        raise ValueError("Contact pricing names an unreserved dimension")
    return known, tuple(sorted(set(ceiling) - set(known)))


def to_wire(value):
    from .v2_contract import to_wire as authority_wire
    if type(value) in {ExecutionBindingV2, MutationReceiptV2, FencePermitV2}:
        return authority_wire(value)
    if type(value) is NamespaceId: return asdict(value)
    if type(value) is RestoreAnchor: return asdict(value)
    if type(value) in _TYPES:
        return {field.name: to_wire(getattr(value, field.name)) for field in fields(value)}
    if type(value) is tuple: return [to_wire(item) for item in value]
    if value is None or type(value) in {str, int, float, bool}: return value
    raise TypeError("unregistered Contact accounting wire value")


_TYPES = frozenset({ContactEffectPricingPolicyV1, ContactEffectBudgetOriginV1, SignedContactEffectBudgetOriginV1,
    ContactSenderMeasurementV1, ContactEffectMeasurementReceiptV1, ContactEffectCostFactV1,
    ContactEffectAccountingRequestV1, ContactEffectAccountingGrantV1})
_NESTED = {
    SignedContactEffectBudgetOriginV1: {"origin": ContactEffectBudgetOriginV1},
    ContactEffectBudgetOriginV1: {"pricing_policy": ContactEffectPricingPolicyV1},
    ContactEffectMeasurementReceiptV1: {"measurement": ContactSenderMeasurementV1, "policy": ContactEffectPricingPolicyV1},
    ContactEffectCostFactV1: {"origin": SignedContactEffectBudgetOriginV1, "measurement": ContactEffectMeasurementReceiptV1},
    ContactEffectAccountingRequestV1: {"origin": SignedContactEffectBudgetOriginV1},
}


def from_wire(raw, cls):
    from .v2_contract import from_wire as authority_read
    if cls not in _TYPES or type(raw) is not dict or set(raw) != {f.name for f in fields(cls)}:
        raise ValueError("Contact accounting exact wire fields differ")
    value = dict(raw)
    for name, nested in _NESTED.get(cls, {}).items():
        if value[name] is not None: value[name] = from_wire(value[name], nested)
    if "namespace" in value: value["namespace"] = NamespaceId(**value["namespace"])
    for name in ("ceiling", "unit_cost"):
        if name in value:
            if type(value[name]) is not list: raise ValueError("canonical accounting quantity array required")
            value[name] = tuple(tuple(item) for item in value[name])
    for name in ("binding", "observed_receipt", "permit"):
        if name in value: value[name] = authority_read(value[name])
    if "expected_anchor" in value: value["expected_anchor"] = RestoreAnchor(**value["expected_anchor"])
    result = cls(**value)
    if to_wire(result) != raw: raise ValueError("noncanonical Contact accounting wire")
    return result


def encoded_v1(value):
    wire = canonical_serialize(to_wire(value))
    if len(wire.encode("utf-8")) > 65536:
        raise ValueError("Contact accounting metadata exceeds its original transport bound")
    return wire
