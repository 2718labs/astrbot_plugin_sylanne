"""D13's pure paid-compression lifecycle; W01/W09 own every authority port.

These values are durable identities and deterministic decisions, not proof that
an API call, settlement, current graph read, or cache transition occurred.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol

from ...model_broker.d13_precompression import (
    FrozenD13PrecompressionRequestV1,
    UntrustedD13PrecompressionOutputV1,
    freeze_d13_precompression_request_v1,
    parse_d13_precompression_output_v1,
)
from ...runtime_contracts import (
    CompressedTurnBlockV2, ConversationWindowProjectionV1, canonical_digest,
)
from .precompression import (
    PrecompressionPlan, compile_extractive_model_output, decide_activation,
)


@dataclass(frozen=True, slots=True)
class D13PaidOriginalBindingV1:
    """Persist with W01's original job before any paid acquire or dispatch."""

    job_ref: str
    original_operation_id: str
    call_id: str
    frozen_input_digest: str
    wire_digest: str
    read_closure_digest: str
    installation_id: str
    provider_id: str
    model_id: str
    provider_config_digest: str
    expires_at_utc: float
    binding_digest: str


def _paid_original_binding_value_v1(frozen,*,original_operation_id,call_id):
    return dict(
        job_ref=frozen.plan.job_ref, original_operation_id=original_operation_id,
        call_id=call_id, frozen_input_digest=frozen.digest,
        wire_digest=frozen.wire_digest,
        read_closure_digest=frozen.read_closure_digest,
        installation_id=frozen.installation.installation_id,
        provider_id=frozen.installation.provider_id,
        model_id=frozen.installation.model_id,
        provider_config_digest=frozen.installation.provider_config_digest,
        expires_at_utc=frozen.plan.expires_at_utc,
    )


def bind_paid_original_v1(
    frozen: FrozenD13PrecompressionRequestV1, *,
    original_operation_id: str, call_id: str,
) -> D13PaidOriginalBindingV1:
    """Give one frozen request one repeatable original operation and call ID."""
    if (type(frozen) is not FrozenD13PrecompressionRequestV1 or
            type(original_operation_id) is not str or not original_operation_id or
            type(call_id) is not str or not call_id):
        raise ValueError("frozen request and original operation/call required")
    if frozen != freeze_d13_precompression_request_v1(
            frozen.window, frozen.plan, frozen.installation):
        raise ValueError("D13 frozen request was modified")
    fields=_paid_original_binding_value_v1(frozen,original_operation_id=original_operation_id,call_id=call_id)
    return D13PaidOriginalBindingV1(
        **fields, binding_digest=canonical_digest({
            "schema": "d13.paid_original_binding.v1", **fields,
        }),
    )


@dataclass(frozen=True, slots=True)
class D13PaidResultReadV1:
    """Result bytes and durable references; only W01 can verify their origin."""

    binding_digest: str
    original_operation_id: str
    call_id: str
    result_read_ref: str
    settlement_ref: str
    model_text: str
    output_digest: str


class D13PaidOriginalVerifierV1(Protocol):
    """Installed W01 port: original call, settled cost, fence and current read."""

    def verify_current_paid_original_v1(
        self, binding: D13PaidOriginalBindingV1,
        result: D13PaidResultReadV1, *,
        current_window: ConversationWindowProjectionV1,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class D13PaidCompletionV1:
    binding_digest: str
    output_digest: str
    candidate: CompressedTurnBlockV2


def prepare_paid_completion_v1(
    frozen: FrozenD13PrecompressionRequestV1,
    binding: D13PaidOriginalBindingV1,
    result: D13PaidResultReadV1,
    current_window: ConversationWindowProjectionV1, *,
    verifier: D13PaidOriginalVerifierV1 | None,
) -> D13PaidCompletionV1:
    """Validate one settled original's bytes into an unadopted extractive block.

    W01 still CASes the running job and absent cache row after this pure check.
    A caller-created verifier does not substitute for W01's installed port.
    """
    if (type(binding) is not D13PaidOriginalBindingV1 or
            type(result) is not D13PaidResultReadV1 or
            type(current_window) is not ConversationWindowProjectionV1 or
            verifier is None):
        raise ValueError("original paid result and installed verifier required")
    expected = bind_paid_original_v1(
        frozen, original_operation_id=binding.original_operation_id,
        call_id=binding.call_id)
    if (binding != expected or result.binding_digest != binding.binding_digest or
            result.original_operation_id != binding.original_operation_id or
            result.call_id != binding.call_id or
            type(result.result_read_ref) is not str or not result.result_read_ref or
            type(result.settlement_ref) is not str or not result.settlement_ref or
            type(result.model_text) is not str or
            result.output_digest != sha256(result.model_text.encode("utf-8")).hexdigest()):
        raise ValueError("paid result differs from frozen original")
    original = frozen.window
    if (current_window.trusted_utc < original.trusted_utc or
            current_window.trusted_utc >= binding.expires_at_utc or
            (current_window.namespace, current_window.owner_ref,
             current_window.conversation_ref, current_window.scene_ref,
             current_window.audience_ref) !=
            (original.namespace, original.owner_ref, original.conversation_ref,
             original.scene_ref, original.audience_ref)):
        raise ValueError("current D13 scope or lifetime differs")
    # The broker checks output shape against frozen turns; the domain compiler
    # rechecks exact excerpts, order and the *current* source/epoch closure.
    parsed: UntrustedD13PrecompressionOutputV1 = (
        parse_d13_precompression_output_v1(result.model_text, frozen))
    if parsed.output_digest != result.output_digest:
        raise ValueError("paid result bytes changed")
    candidate = compile_extractive_model_output(
        current_window, frozen.plan, result.model_text)
    if verifier.verify_current_paid_original_v1(
            binding, result, current_window=current_window) is not True:
        raise ValueError("original paid result is not current and settled")
    return D13PaidCompletionV1(binding.binding_digest, result.output_digest,
                               candidate)


@dataclass(frozen=True, slots=True)
class D13ExactActivationEvidenceV1:
    """W09's two complete main-model wires, excluding predicted cache savings."""

    installation_id: str
    provider_id: str
    model_id: str
    provider_config_digest: str
    tokenizer_fingerprint: str
    raw_wire_digest: str
    compressed_wire_digest: str
    raw_input_tokens: int
    compressed_input_tokens: int
    available_input_tokens: int


class D13ExactActivationVerifierV1(Protocol):
    """Installed W09/W01 port for two current, complete, same-model wires."""

    def verify_current_exact_activation_v1(
        self, evidence: D13ExactActivationEvidenceV1, *,
        standby: CompressedTurnBlockV2, plan: PrecompressionPlan,
        current_window: ConversationWindowProjectionV1,
    ) -> bool: ...


def decide_exact_activation_v1(
    standby: CompressedTurnBlockV2, plan: PrecompressionPlan,
    current_window: ConversationWindowProjectionV1,
    evidence: D13ExactActivationEvidenceV1 | None, *,
    verifier: D13ExactActivationVerifierV1 | None,
    paid_verifier: object = None,
) -> str:
    """Repeatable HOLD/invalid/keep_raw/activate; no speculative cost claim."""
    source = decide_activation(
        standby, plan, current_window, raw_window_fits=True,
        proven_future_saving=False, paid_verifier=paid_verifier)
    if source == "invalid":
        return "invalid"
    if type(evidence) is not D13ExactActivationEvidenceV1 or verifier is None:
        return "hold"
    verify_wires = getattr(verifier, "verify_current_exact_activation_v1", None)
    if (any(type(value) is not str or not value for value in (
                evidence.installation_id, evidence.provider_id, evidence.model_id,
                evidence.tokenizer_fingerprint)) or
            any(type(value) is not str or len(value) != 64 or
                any(char not in "0123456789abcdef" for char in value)
                for value in (evidence.provider_config_digest,
                              evidence.raw_wire_digest,
                              evidence.compressed_wire_digest)) or
            any(type(value) is not int or value <= 0 for value in (
                evidence.raw_input_tokens, evidence.compressed_input_tokens,
                evidence.available_input_tokens)) or
            evidence.raw_wire_digest == evidence.compressed_wire_digest or
            not callable(verify_wires)):
        return "hold"
    try:
        wires_current = verify_wires(
            evidence, standby=standby, plan=plan,
            current_window=current_window)
    except Exception:
        return "hold"
    if wires_current is not True:
        return "hold"
    if evidence.raw_input_tokens <= evidence.available_input_tokens:
        return "keep_raw"
    return ("activate" if evidence.compressed_input_tokens <=
            evidence.available_input_tokens else "hold")


@dataclass(frozen=True, slots=True)
class D13BoundedActivationEvidenceV1:
    """Installed policy candidate for two complete same-model request wires.

    Bounds are separate from ExactV1. UTF-8 size and caller fit flags do not
    satisfy this contract; the installed verifier must reproduce its policy.
    """

    installation_id: str
    provider_id: str
    model_id: str
    provider_config_digest: str
    wire_format_policy_id: str
    wire_format_policy_version: int
    wire_format_policy_fingerprint: str
    token_bound_policy_id: str
    token_bound_policy_version: int
    token_bound_policy_fingerprint: str
    raw_wire_digest: str
    compressed_wire_digest: str
    raw_lower_tokens: int
    raw_upper_tokens: int
    compressed_lower_tokens: int
    compressed_upper_tokens: int
    capacity_input_tokens: int
    context_limit_tokens: int
    output_reserve_tokens: int
    tool_reserve_tokens: int
    current_window_digest: str
    current_read_set_digest: str
    standby_digest: str
    policy_allows_conservative_switch: bool
    schema: str = "d13.bounded_activation_evidence.v1"

    def __post_init__(self) -> None:
        if self.schema != "d13.bounded_activation_evidence.v1":
            raise ValueError("unknown D13 bounded activation evidence")
        for name in ("installation_id", "provider_id", "model_id",
                     "wire_format_policy_id", "token_bound_policy_id"):
            if type(getattr(self, name)) is not str or not getattr(self, name).strip():
                raise ValueError("installed full-wire policy identity required")
        for name in ("provider_config_digest", "wire_format_policy_fingerprint",
                     "token_bound_policy_fingerprint", "raw_wire_digest", "compressed_wire_digest",
                     "current_window_digest", "current_read_set_digest", "standby_digest"):
            value = getattr(self, name)
            if (type(value) is not str or len(value) != 64 or
                    any(char not in "0123456789abcdef" for char in value)):
                raise ValueError("D13 bounded evidence requires SHA-256 bindings")
        for name in ("wire_format_policy_version", "token_bound_policy_version",
                     "capacity_input_tokens", "context_limit_tokens"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError("D13 installed policy version and capacity must be positive integers")
        for name in ("raw_lower_tokens", "raw_upper_tokens", "compressed_lower_tokens",
                     "compressed_upper_tokens", "output_reserve_tokens", "tool_reserve_tokens"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError("D13 bounds and reserves must be exact nonnegative integers")
        if (self.raw_lower_tokens > self.raw_upper_tokens or
                self.compressed_lower_tokens > self.compressed_upper_tokens or
                self.capacity_input_tokens != self.context_limit_tokens -
                self.output_reserve_tokens - self.tool_reserve_tokens or
                self.raw_wire_digest == self.compressed_wire_digest or
                type(self.policy_allows_conservative_switch) is not bool):
            raise ValueError("D13 bounded wire interval or context reserve differs")


@dataclass(frozen=True, slots=True)
class D13BoundedActivationVerifiedReceiptV1:
    """Installed verifier's current wire, source, policy and worst-cost read."""

    evidence_digest: str
    current_window_digest: str
    current_read_set_digest: str
    standby_digest: str
    raw_wire_digest: str
    compressed_wire_digest: str
    wire_format_policy_fingerprint: str
    token_bound_policy_fingerprint: str
    foreground_budget_ref: str
    foreground_reservation_ref: str
    foreground_budget_receipt_digest: str
    required_model_tokens: int
    reserved_model_tokens: int
    required_model_microusd: int
    reserved_model_microusd: int
    trusted_utc: float

    def __post_init__(self) -> None:
        for name in ("evidence_digest", "current_window_digest", "current_read_set_digest",
                     "standby_digest", "raw_wire_digest", "compressed_wire_digest",
                     "wire_format_policy_fingerprint", "token_bound_policy_fingerprint",
                     "foreground_budget_receipt_digest"):
            value = getattr(self, name)
            if (type(value) is not str or len(value) != 64 or
                    any(char not in "0123456789abcdef" for char in value)):
                raise ValueError("D13 bounded verified receipt requires exact digest bindings")
        for name in ("foreground_budget_ref", "foreground_reservation_ref"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError("D13 bounded receipt requires original foreground budget read")
        for name in ("required_model_tokens", "reserved_model_tokens",
                     "required_model_microusd", "reserved_model_microusd"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError("D13 foreground worst-cost counters must be integers")
        import math
        if type(self.trusted_utc) not in (int, float) or not math.isfinite(self.trusted_utc):
            raise ValueError("D13 bounded receipt requires current trusted time")


class D13BoundedActivationVerifierV1(Protocol):
    def verify_current_bounded_activation_v1(
        self, evidence: D13BoundedActivationEvidenceV1, *,
        standby: CompressedTurnBlockV2, plan: PrecompressionPlan,
        current_window: ConversationWindowProjectionV1,
    ) -> D13BoundedActivationVerifiedReceiptV1 | None: ...


@dataclass(frozen=True, slots=True)
class D13BoundedActivationDecisionV1:
    decision: str
    reason: str
    verified_receipt: D13BoundedActivationVerifiedReceiptV1 | None


def decide_bounded_activation_v1(
    standby: CompressedTurnBlockV2, plan: PrecompressionPlan,
    current_window: ConversationWindowProjectionV1,
    evidence: D13BoundedActivationEvidenceV1 | None, *,
    verifier: D13BoundedActivationVerifierV1 | None,
    paid_verifier: object = None,
) -> D13BoundedActivationDecisionV1:
    """Apply the frozen safe-bound decision without claiming measured savings."""
    source = decide_activation(standby, plan, current_window, raw_window_fits=True,
                               proven_future_saving=False, paid_verifier=paid_verifier)
    if source == "invalid":
        return D13BoundedActivationDecisionV1("invalid", "current_paid_source_invalid", None)
    if type(evidence) is not D13BoundedActivationEvidenceV1 or verifier is None:
        return D13BoundedActivationDecisionV1("hold", "installed_bounded_wire_proof_required", None)
    if (evidence.current_window_digest != canonical_digest(current_window) or
            evidence.current_read_set_digest != canonical_digest(current_window.read_set) or
            evidence.standby_digest != canonical_digest(standby)):
        return D13BoundedActivationDecisionV1("hold", "bounded_wire_source_binding_changed", None)
    try:
        receipt = verifier.verify_current_bounded_activation_v1(
            evidence, standby=standby, plan=plan, current_window=current_window)
    except Exception:
        receipt = None
    if (type(receipt) is not D13BoundedActivationVerifiedReceiptV1 or
            receipt.evidence_digest != canonical_digest(evidence) or
            receipt.current_window_digest != evidence.current_window_digest or
            receipt.current_read_set_digest != evidence.current_read_set_digest or
            receipt.standby_digest != evidence.standby_digest or
            receipt.raw_wire_digest != evidence.raw_wire_digest or
            receipt.compressed_wire_digest != evidence.compressed_wire_digest or
            receipt.wire_format_policy_fingerprint != evidence.wire_format_policy_fingerprint or
            receipt.token_bound_policy_fingerprint != evidence.token_bound_policy_fingerprint or
            receipt.trusted_utc != current_window.trusted_utc or
            receipt.required_model_tokens < evidence.compressed_upper_tokens +
            evidence.output_reserve_tokens + evidence.tool_reserve_tokens or
            receipt.required_model_tokens > receipt.reserved_model_tokens or
            receipt.required_model_microusd > receipt.reserved_model_microusd):
        return D13BoundedActivationDecisionV1("hold", "current_bounded_wire_or_foreground_budget_unverified", None)
    if evidence.raw_upper_tokens <= evidence.capacity_input_tokens:
        return D13BoundedActivationDecisionV1("keep_raw", "raw_fit_certified", receipt)
    if evidence.compressed_upper_tokens > evidence.capacity_input_tokens:
        return D13BoundedActivationDecisionV1("hold", "compressed_fit_not_certified", receipt)
    if evidence.raw_lower_tokens > evidence.capacity_input_tokens:
        return D13BoundedActivationDecisionV1("activate", "proven_pressure", receipt)
    if evidence.policy_allows_conservative_switch:
        return D13BoundedActivationDecisionV1(
            "activate", "raw_fit_unproven_compressed_fit_certified", receipt)
    return D13BoundedActivationDecisionV1("hold", "installed_policy_disallows_conservative_switch", receipt)
