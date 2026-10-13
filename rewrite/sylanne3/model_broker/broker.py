"""Purpose-gated model calling with honest cost and unknown-result receipts.

The broker has no graph or budget-database writes.  The host must reserve and
settle its W01 budget lease from the returned receipt under the operation's
existing identity; this module must never reset or manufacture a budget.
"""

from __future__ import annotations

import asyncio
from dataclasses import InitVar, dataclass
from hashlib import sha256
import json
from typing import Any, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..runtime_contracts import CommandEnvelope, OperationIdentity, canonical_digest


class ProviderUnavailable(RuntimeError): pass
class ProviderTimeout(TimeoutError): pass
class ProviderUnknown(RuntimeError): pass


@dataclass(frozen=True)
class EgressStartReceipt:
    """Trusted authority's durable decision for one exact outward call.

    ``started`` means source/grant/deletion/activation checks and the handoff
    start were serialized under the shared content fence.  The broker cannot
    create this authority from a chat request or provider response.
    """

    status: str  # started | denied | unavailable | unknown
    operation_id: str
    call_id: str
    request_digest: str
    source_refs: tuple[str, ...]
    access_epoch: int
    delete_epoch: int
    activation_generation: int
    start_ref: str | None

    def __post_init__(self) -> None:
        if self.status not in {"started", "denied", "unavailable", "unknown"}:
            raise ValueError("unknown egress start status")
        _text(self.operation_id, "operation_id")
        _text(self.call_id, "call_id")
        if (len(self.request_digest) != 64
                or any(char not in "0123456789abcdef" for char in self.request_digest)):
            raise ValueError("request_digest must be SHA-256")
        if type(self.source_refs) is not tuple or any(
            not isinstance(ref, str) or not ref for ref in self.source_refs
        ):
            raise ValueError("source_refs must be a tuple of nonempty references")
        for name in ("access_epoch", "delete_epoch", "activation_generation"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative exact integer")
        if self.status == "started":
            _text(self.start_ref, "start_ref")
        elif self.start_ref is not None:
            raise ValueError("non-started egress cannot carry a start reference")


@dataclass(frozen=True)
class EgressFinishReceipt:
    """Authority confirmation that one durable egress handoff has ended.

    A ``finished`` receipt is an authority observation that the provider's
    outcome was independently resolved (including an explicit no-dispatch
    proof).  It is not an acknowledgement manufactured by the broker.  In
    particular, an RPC timeout while finishing leaves the original permit open:
    deletion and migration remain blocked until the authority recovers it
    independently.
    """

    status: str  # finished | unavailable | unknown
    operation_id: str
    call_id: str
    request_digest: str
    start_ref: str
    outcome_digest: str
    finish_ref: str | None

    def __post_init__(self) -> None:
        if self.status not in {"finished", "unavailable", "unknown"}:
            raise ValueError("unknown egress finish status")
        for name in ("operation_id", "call_id", "start_ref"):
            _text(getattr(self, name), name)
        for name in ("request_digest", "outcome_digest"):
            value = getattr(self, name)
            if (len(value) != 64
                    or any(char not in "0123456789abcdef" for char in value)):
                raise ValueError(f"{name} must be SHA-256")
        if self.status == "finished":
            _text(self.finish_ref, "finish_ref")
        elif self.finish_ref is not None:
            raise ValueError("unfinished egress cannot carry a finish reference")


class ModelEgressAuthority(Protocol):
    async def execute_call(
        self, request: "ModelCallRequest", request_digest: str
    ) -> "AuthorityExecutionResult": ...


def _text(value: object, name: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ValueError(f"{name} must be a nonempty bounded string")
    return value


def _amounts(value: Mapping[str, int] | None, name: str) -> dict[str, int]:
    if value is None: return {}
    if not isinstance(value, Mapping) or len(value) > 32:
        raise ValueError(f"{name} must be a bounded amount object")
    result: dict[str, int] = {}
    for key, amount in value.items():
        _text(key, name)
        if type(amount) is not int or amount < 0:
            raise ValueError(f"{name} amounts must be nonnegative exact integers")
        if amount: result[key] = amount
    return result


@dataclass(frozen=True)
class ModelProviderDescriptor:
    provider_id: str
    adapter_version: str
    model_id: str
    capabilities: frozenset[str]
    purposes: frozenset[str]
    privacy_tiers: frozenset[str]
    credential_ref: str
    cost_reporting: str
    timeout_cancellable: bool
    supports_idempotency: bool
    is_test_double: bool = False

    def __post_init__(self) -> None:
        for name in ("provider_id", "adapter_version", "model_id", "credential_ref"):
            _text(getattr(self, name), name)
        for name in ("capabilities", "purposes", "privacy_tiers"):
            items = getattr(self, name)
            if not isinstance(items, frozenset) or not items or any(not isinstance(item, str) or not item for item in items):
                raise ValueError(f"{name} must be a nonempty frozen string set")
        if self.cost_reporting not in {"reported", "estimated", "unknown"}:
            raise ValueError("cost_reporting must be reported, estimated, or unknown")


@dataclass(frozen=True)
class ModelCallRequest:
    envelope: CommandEnvelope
    call_id: str
    provider_id: str
    model_id: str
    required_capabilities: frozenset[str]
    privacy_tier: str
    prompt_template_digest: str
    payload: Mapping[str, Any]
    timeout_seconds: float
    max_output_tokens: int
    _prepared_payload_eof_v3: InitVar[object] = None

    def __post_init__(self, _prepared_payload_eof_v3=None) -> None:
        if not isinstance(self.envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        _text(self.call_id, "call_id")
        _text(self.provider_id, "provider_id"); _text(self.model_id, "model_id")
        if not isinstance(self.required_capabilities, frozenset) or any(not isinstance(v, str) or not v for v in self.required_capabilities):
            raise ValueError("required_capabilities must be a frozen string set")
        _text(self.privacy_tier, "privacy_tier")
        if not isinstance(self.prompt_template_digest, str) or len(self.prompt_template_digest) != 64 or any(c not in "0123456789abcdef" for c in self.prompt_template_digest):
            raise ValueError("prompt_template_digest must be a SHA-256 digest")
        if not isinstance(self.payload, Mapping): raise TypeError("payload must be an object")
        if _prepared_payload_eof_v3 is None:
            try: json.dumps(dict(self.payload), sort_keys=True, allow_nan=False)
            except (TypeError, ValueError) as exc: raise ValueError("payload must be JSON-safe") from exc
        else:
            from ..authority_service.d13_paid_block_verifier_v1 import (
                PreparedD13PaidRequestEOFV3,require_prepared_d13_paid_payload_eof_v3)
            if type(_prepared_payload_eof_v3)is PreparedD13PaidRequestEOFV3:
                require_prepared_d13_paid_payload_eof_v3(_prepared_payload_eof_v3,self)
            else:
                from ..runtime.dispatch_initial_source_read_v3 import require_prepared_model_payload_eof_v3
                require_prepared_model_payload_eof_v3(_prepared_payload_eof_v3,self)
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(self.timeout_seconds, bool) or not 0 < self.timeout_seconds <= 300:
            raise ValueError("timeout_seconds must be in (0,300]")
        if type(self.max_output_tokens) is not int or self.max_output_tokens < 1:
            raise ValueError("max_output_tokens must be a positive integer")
        if self.envelope.identity.operation_id == self.call_id:
            raise ValueError("call_id must be distinct from operation_id")

    @property
    def identity(self) -> OperationIdentity: return self.envelope.identity

    @property
    def digest(self) -> str:
        from ..authority_service.d13_paid_block_verifier_v1 import prepared_d13_paid_request_digest_v3
        prepared=prepared_d13_paid_request_digest_v3(self)
        if prepared is not None:return prepared
        from ..authority_service.current_authority_graph_read_v3 import prepared_authority_model_request_digest_v3
        prepared=prepared_authority_model_request_digest_v3(self)
        if prepared is not None:return prepared
        return canonical_digest({"envelope": self.envelope, "call_id": self.call_id,
                                 "provider_id": self.provider_id, "model_id": self.model_id,
                                 "purpose": self.envelope.authority.purpose,
                                 "required_capabilities": sorted(self.required_capabilities),
                                 "privacy_tier": self.privacy_tier,
                                 "template": self.prompt_template_digest, "payload": dict(self.payload),
                                 "timeout_seconds": float(self.timeout_seconds),
                                 "max_output_tokens": self.max_output_tokens})


@dataclass(frozen=True)
class ProviderResponse:
    status: str  # completed | not_dispatched | unknown
    result: Mapping[str, Any] | None
    usage: Mapping[str, int] | None
    cost: Mapping[str, int] | None
    provider_call_ref: str | None
    billing_receipt_json: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"completed", "not_dispatched", "unknown"}: raise ValueError("invalid provider response status")
        if self.result is not None:
            if not isinstance(self.result, Mapping): raise TypeError("result must be an object")
            try: json.dumps(dict(self.result), sort_keys=True, allow_nan=False)
            except (TypeError, ValueError) as exc: raise ValueError("result must be JSON-safe") from exc
        original_usage, original_cost = self.usage, self.cost
        object.__setattr__(self, "usage", _amounts(self.usage, "usage"))
        object.__setattr__(self, "cost", _amounts(self.cost, "cost"))
        if self.billing_receipt_json is not None:
            from .provider_billing_receipt_v1 import provider_billing_receipt_from_json_v1
            receipt = provider_billing_receipt_from_json_v1(self.billing_receipt_json)
            if (self.status != "completed" or receipt.provider_call_ref != self.provider_call_ref
                    or receipt.usage != dict(original_usage)
                    or dict(original_cost) != {"model_microusd": receipt.final_charged_amount}):
                raise ValueError("provider billing original differs from the completed response")
            # A signed final zero is a known measurement, not a missing amount.
            object.__setattr__(self, "usage", receipt.usage)
            object.__setattr__(self, "cost", {"model_microusd": receipt.final_charged_amount})
        if self.provider_call_ref is not None: _text(self.provider_call_ref, "provider_call_ref")
        if self.status == "completed" and self.result is None: raise ValueError("completed response requires a result")
        if self.status == "not_dispatched" and (self.result is not None or self.usage or self.cost):
            raise ValueError("not_dispatched cannot carry a result or incurred usage")
        if self.status == "unknown" and self.result is not None:
            raise ValueError("unknown result cannot be eligible content")


@dataclass(frozen=True)
class CallReceipt:
    status: str  # completed/cancelled/timed_out/unknown/unavailable/denied/failed
    operation_id: str
    attempt_id: str
    call_id: str
    call_digest: str
    provider_id: str
    model_id: str
    provider_call_ref: str | None
    usage: Mapping[str, int]
    cost: Mapping[str, int]
    cost_status: str  # confirmed/estimated/unconfirmed/not_charged
    result_qualification: str  # eligible/unavailable/unknown
    cancellation_requested: bool
    egress_start_ref: str | None = None
    egress_finish_ref: str | None = None


@dataclass(frozen=True)
class AuthorityExecutionResult:
    """Authority-owned attempt and durable observation; never a host provider reply."""

    receipt: CallReceipt
    result: Mapping[str, Any] | None
    finish: EgressFinishReceipt | None


class ModelProvider(Protocol):
    @property
    def descriptor(self) -> ModelProviderDescriptor: ...
    async def invoke(self, request: ModelCallRequest, cancellation: asyncio.Event) -> ProviderResponse: ...
    async def cancel(self, request: ModelCallRequest) -> bool: ...


@dataclass(frozen=True)
class VerifiedHttpConfiguration:
    """Non-secret provider connection metadata attested by the host configuration."""

    endpoint: str
    credential_ref: str
    configuration_attested: bool

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, str) or not self.endpoint.startswith("https://"):
            raise ValueError("provider endpoint must be an HTTPS URL")
        _text(self.credential_ref, "credential_ref")


class VerifiedHttpProvider:
    """Generic JSON provider adapter; it holds no credential and never retries.

    The credential resolver and configuration attestation are supplied by W09.
    Without both, this adapter raises ``ProviderUnavailable`` before network
    activity.  The standard-library request is intentionally non-cancellable;
    callers preserve unknown status on timeout instead of retrying it.
    """

    def __init__(self, descriptor: ModelProviderDescriptor, configuration: VerifiedHttpConfiguration | None,
                 credential_resolver: callable | None = None) -> None:
        self._descriptor, self._configuration, self._credential_resolver = descriptor, configuration, credential_resolver
        if descriptor.is_test_double: raise ValueError("HTTP production adapter cannot use a test descriptor")
        if descriptor.timeout_cancellable:
            raise ValueError("generic HTTP adapter cannot claim cancellation support")

    @property
    def descriptor(self) -> ModelProviderDescriptor: return self._descriptor

    def _credential(self) -> str:
        if self._configuration is None or not self._configuration.configuration_attested or self._credential_resolver is None:
            raise ProviderUnavailable("provider configuration or credential attestation is unavailable")
        if self._configuration.credential_ref != self._descriptor.credential_ref:
            raise ProviderUnavailable("credential reference does not match provider descriptor")
        secret = self._credential_resolver(self._configuration.credential_ref)
        if not isinstance(secret, str) or not secret:
            raise ProviderUnavailable("provider credential is unavailable")
        return secret

    async def invoke(self, request: ModelCallRequest, cancellation: asyncio.Event) -> ProviderResponse:
        if cancellation.is_set(): return ProviderResponse("not_dispatched", None, {}, {}, None)
        secret = self._credential()
        payload = json.dumps({"model": request.model_id, "call_id": request.call_id,
                               "operation_id": request.identity.operation_id,
                               "max_output_tokens": request.max_output_tokens,
                               "payload": dict(request.payload)}, separators=(",", ":"), allow_nan=False).encode("utf-8")
        try:
            raw = await asyncio.to_thread(self._post, payload, secret, request.timeout_seconds)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            # A failed HTTP exchange may have reached the provider; do not claim no dispatch.
            raise ProviderUnknown("provider exchange has unknown outcome") from exc
        try:
            body = json.loads(raw)
            return ProviderResponse(body["status"], body.get("result"), body.get("usage"), body.get("cost"), body.get("provider_call_ref"))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ProviderUnknown("provider response cannot be verified") from exc

    def _post(self, payload: bytes, secret: str, timeout: float) -> str:
        assert self._configuration is not None
        request = Request(self._configuration.endpoint, data=payload, method="POST",
                          headers={"Content-Type": "application/json", "Accept": "application/json",
                                   "Authorization": f"Bearer {secret}"})
        with urlopen(request, timeout=timeout) as response:  # nosec B310: endpoint requires host attestation
            return response.read(1_048_576).decode("utf-8")

    async def cancel(self, request: ModelCallRequest) -> bool:
        return False


class ModelBroker:
    def __init__(self, providers: Mapping[str, ModelProvider], *, production: bool = True,
                 egress_authority: ModelEgressAuthority | None = None) -> None:
        self._providers = dict(providers)
        self._production = production
        self._egress_authority = egress_authority

    async def call(self, request: ModelCallRequest, *, cancellation: asyncio.Event | None = None) -> tuple[CallReceipt, Mapping[str, Any] | None]:
        if not isinstance(request, ModelCallRequest):
            raise TypeError("request must be ModelCallRequest")
        cancelled = cancellation or asyncio.Event()
        if cancelled.is_set():
            return self._receipt(request, "cancelled", None, {}, {}, "not_charged", "unavailable", True), None
        if self._production:
            return await self._call_production(request)
        provider = self._providers.get(request.provider_id)
        if provider is None:
            return self._receipt(request, "unavailable", None, {}, {}, "not_charged", "unavailable", False), None
        descriptor = provider.descriptor
        if descriptor.provider_id != request.provider_id or descriptor.model_id != request.model_id:
            return self._receipt(request, "unavailable", None, {}, {}, "not_charged", "unavailable", False), None
        if (not request.required_capabilities <= descriptor.capabilities
                or request.privacy_tier not in descriptor.privacy_tiers
                or request.envelope.authority.purpose not in descriptor.purposes):
            return self._receipt(request, "denied", None, {}, {}, "not_charged", "unavailable", False), None
        try:
            response = await asyncio.wait_for(provider.invoke(request, cancelled), timeout=request.timeout_seconds)
        except asyncio.CancelledError:
            await self._request_cancel(provider, request)
            raise
        except TimeoutError:
            was_cancelled = await self._request_cancel(provider, request)
            return self._receipt(request, "timed_out", None, {}, {}, "unconfirmed", "unknown", was_cancelled), None
        except ProviderUnavailable:
            return self._receipt(request, "unavailable", None, {}, {}, "not_charged", "unavailable", False), None
        except ProviderUnknown:
            return self._unknown(request)
        except Exception:
            return self._receipt(request, "failed", None, {}, {}, "unconfirmed", "unknown", False), None
        if not isinstance(response, ProviderResponse):
            return self._unknown(request)
        if cancelled.is_set():
            was_cancelled = await self._request_cancel(provider, request)
            return self._receipt(request, "cancelled", response.provider_call_ref, response.usage,
                                 response.cost, self._cost_status(descriptor, response, unknown=True),
                                 "unknown", was_cancelled), None
        if response.status == "not_dispatched":
            return self._receipt(request, "failed", response.provider_call_ref, {}, {},
                                 "not_charged", "unavailable", False), None
        if response.status == "unknown":
            return self._receipt(request, "unknown", response.provider_call_ref, response.usage,
                                 response.cost, self._cost_status(descriptor, response, unknown=True),
                                 "unknown", False), None
        return self._receipt(request, "completed", response.provider_call_ref, response.usage,
                             response.cost, self._cost_status(descriptor, response),
                             "eligible", False), response.result

    async def _call_production(
        self, request: ModelCallRequest
    ) -> tuple[CallReceipt, Mapping[str, Any] | None]:
        executor = getattr(self._egress_authority, "execute_call", None)
        if not callable(executor):
            return self._receipt(request, "unavailable", None, {}, {}, "not_charged", "unavailable", False), None
        try:
            execution = await executor(request, request.digest)
        except (Exception, asyncio.CancelledError):
            # An attempt may already have reached the network. Only the authority
            # can recover and settle it; the broker must not retry locally.
            return self._unknown(request)
        if not isinstance(execution, AuthorityExecutionResult):
            return self._unknown(request)
        receipt = execution.receipt
        if not isinstance(receipt, CallReceipt) or (
            receipt.operation_id != request.identity.operation_id
            or receipt.attempt_id != request.identity.attempt_id
            or receipt.call_id != request.call_id
            or receipt.call_digest != request.digest
            or receipt.provider_id != request.provider_id
            or receipt.model_id != request.model_id
        ):
            return self._unknown(request)
        if receipt.result_qualification != "eligible":
            if execution.result is not None:
                return self._unknown(request)
            return receipt, None
        finish, result = execution.finish, execution.result
        try:
            if (receipt.status != "completed"
                    or not receipt.egress_start_ref or not receipt.egress_finish_ref
                    or not isinstance(finish, EgressFinishReceipt)
                    or finish.status != "finished"
                    or finish.operation_id != receipt.operation_id
                    or finish.call_id != receipt.call_id
                    or finish.request_digest != receipt.call_digest
                    or finish.start_ref != receipt.egress_start_ref
                    or finish.finish_ref != receipt.egress_finish_ref
                    or not isinstance(result, Mapping)):
                return self._unknown(request)
            result_dict = dict(result)
            json.dumps(result_dict, sort_keys=True, allow_nan=False)
            outcome_digest = canonical_digest({
                "request_digest": request.digest,
                "status": "completed",
                "provider_call_ref": receipt.provider_call_ref,
                "usage": dict(receipt.usage),
                "cost": dict(receipt.cost),
                "result_digest": canonical_digest(result_dict),
            })
            if finish.outcome_digest != outcome_digest:
                return self._unknown(request)
        except (TypeError, ValueError):
            return self._unknown(request)
        return receipt, result_dict

    @staticmethod
    def _unknown(request: ModelCallRequest) -> tuple[CallReceipt, None]:
        return ModelBroker._receipt(request, "unknown", None, {}, {}, "unconfirmed", "unknown", False), None

    @staticmethod
    async def _request_cancel(provider: ModelProvider, request: ModelCallRequest) -> bool:
        try: return bool(await provider.cancel(request))
        except Exception: return False

    @staticmethod
    def _cost_status(descriptor: ModelProviderDescriptor, response: ProviderResponse, *, unknown: bool = False) -> str:
        if unknown or descriptor.cost_reporting == "unknown" or not response.cost: return "unconfirmed"
        return "confirmed" if descriptor.cost_reporting == "reported" else "estimated"

    @staticmethod
    def _receipt(request: ModelCallRequest, status: str, provider_call_ref: str | None, usage: Mapping[str, int],
                 cost: Mapping[str, int], cost_status: str, result_qualification: str,
                 cancellation_requested: bool, egress_start_ref: str | None = None,
                 egress_finish_ref: str | None = None) -> CallReceipt:
        return CallReceipt(status, request.identity.operation_id, request.identity.attempt_id, request.call_id,
                           request.digest, request.provider_id, request.model_id, provider_call_ref,
                           dict(usage), dict(cost), cost_status, result_qualification,
                           cancellation_requested, egress_start_ref, egress_finish_ref)
