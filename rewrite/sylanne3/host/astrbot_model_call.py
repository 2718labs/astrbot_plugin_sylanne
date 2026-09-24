"""Local one-attempt AstrBot call mechanics for a future Authority executor.

The UMO is supplied by trusted host composition. This adapter rechecks its
current chat-provider selection before each call. The existing Broker invoke
port has no admission proof and therefore never sends. A lost outcome remains
unknown; this process-local registry is not durable Authority observation.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import Future
from dataclasses import dataclass, field
import re
import secrets
from threading import Lock

from astrbot.api.star import Context
from astrbot.core.provider.entities import ProviderMeta, ProviderType
from astrbot.core.provider.sources.openai_source import ProviderOpenAIOfficial
from openai import AsyncAzureOpenAI, AsyncOpenAI
from openai.types.chat.chat_completion import ChatCompletion

from ..runtime_contracts import canonical_digest
from ..model_broker.broker import (
    ModelCallRequest, ModelProviderDescriptor, ProviderResponse,
)
from ..model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST,
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
)
from .authority_profile import (
    AdminIngressEncodingPolicy, AdminIngressModelPolicy, AdminModelWorkflowV2,
    AdminInstallationBundle, installed_model_config_ref,
)
from ..installation_policy import AdminInstallationPolicy


@dataclass
class _CallEntry:
    digest: str
    admission_id: str
    host_incarnation: str
    provider_config_digest: str
    binding: tuple[object, ...]
    terminal: Future[ProviderResponse] = field(default_factory=Future)
    task: asyncio.Task[ProviderResponse] | None = None


# Process-local dispatch memory. An unresolved entry is intentionally retained:
# a stopped host loop provides no evidence that its provider call did not run.
_call_lock = Lock()
_calls: dict[str, _CallEntry] = {}
_admissions: dict[str, str] = {}
_HOST_INCARNATION = secrets.token_hex(32)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class LocalModelAdmission:
    """Executor-supplied local start identity; not an Authority credential."""

    admission_id: str
    host_incarnation: str
    call_id: str
    request_digest: str
    provider_config_digest: str

    def __post_init__(self) -> None:
        if (not all(type(value) is str and value for value in (
                self.admission_id, self.host_incarnation, self.call_id,
                self.request_digest, self.provider_config_digest))
                or _SHA256.fullmatch(self.admission_id) is None
                or _SHA256.fullmatch(self.host_incarnation) is None
                or _SHA256.fullmatch(self.request_digest) is None
                or _SHA256.fullmatch(self.provider_config_digest) is None):
            raise ValueError("invalid local model admission identity")


class AstrBotModelProvider:
    """Bound to one trusted UMO and one exact configured provider/model."""

    def __init__(
        self, *, context: Context, host_loop: asyncio.AbstractEventLoop,
        trusted_umo: str, descriptor: ModelProviderDescriptor,
        admin_model: AdminIngressModelPolicy | AdminModelWorkflowV2,
        installation_bundle: AdminInstallationBundle,
    ) -> None:
        if (not isinstance(context, Context)
                or not isinstance(host_loop, asyncio.AbstractEventLoop)
                or type(trusted_umo) is not str or not trusted_umo
                or type(descriptor) is not ModelProviderDescriptor
                or descriptor.is_test_double or descriptor.timeout_cancellable
                or descriptor.supports_idempotency
                or descriptor.cost_reporting != "unknown"):
            raise ValueError("trusted non-retrying AstrBot model binding is required")
        if (type(admin_model) not in (AdminIngressModelPolicy, AdminModelWorkflowV2)
                or admin_model.provider_id != descriptor.provider_id
                or admin_model.model_id != descriptor.model_id
                or admin_model.provider_config_ref != installed_model_config_ref(
                    descriptor.provider_id, descriptor.model_id,
                    admin_model.provider_config_digest)
                or type(installation_bundle) is not AdminInstallationBundle):
            raise ValueError("exact administrator model configuration is required")
        workflows = installation_bundle.model_workflows
        if type(admin_model) is AdminIngressModelPolicy:
            installed = admin_model is installation_bundle.ingress_model
        else:
            installed = (workflows is not None and
                         (admin_model is workflows.encode
                          or admin_model is workflows.reply))
        if not installed:
            raise ValueError("model selection is absent from installed administrator snapshot")
        self._context = context
        self._host_loop = host_loop
        self._trusted_umo = trusted_umo
        self._descriptor = descriptor
        self._admin_model = admin_model
        self._installation_bundle = installation_bundle
        self._binding = (context, host_loop, trusted_umo,
                         descriptor.provider_id, descriptor.model_id,
                         admin_model.provider_config_ref,
                         (admin_model.work_kind, admin_model.template_version)
                         if type(admin_model) is AdminModelWorkflowV2 else "legacy")

    @property
    def host_incarnation(self) -> str:
        return _HOST_INCARNATION

    def _same_binding(self, entry: _CallEntry) -> bool:
        return (entry.binding[0] is self._context
                and entry.binding[1] is self._host_loop
                and entry.binding[2:] == self._binding[2:])

    @property
    def descriptor(self) -> ModelProviderDescriptor:
        return self._descriptor

    def _request_allowed(self, request: ModelCallRequest) -> bool:
        """Recheck the installed scope and exact request before host dispatch."""
        model = self._admin_model
        bundle = self._installation_bundle
        policy = bundle.installation_policy
        encoding = bundle.ingress_encoding
        authority = request.envelope.authority
        descriptor = self._descriptor
        if type(model) is AdminModelWorkflowV2:
            workflows = bundle.model_workflows
            if (workflows is None
                    or (model is not workflows.encode
                        and model is not workflows.reply)
                    or type(policy) is not AdminInstallationPolicy
                    or policy.namespace != authority.namespace
                    or model.work_kind not in policy.root_grant.allowed_work_kinds
                    or request.provider_id != model.provider_id
                    or request.model_id != model.model_id
                    or descriptor.capabilities != frozenset({"text"})
                    or not request.required_capabilities
                    or not request.required_capabilities <= descriptor.capabilities
                    or not request.required_capabilities <= set(model.required_capabilities)
                    or descriptor.purposes != frozenset({model.purpose})
                    or authority.purpose != model.purpose
                    or not authority.audience
                    or not set(authority.audience) <= set(model.audiences)
                    or descriptor.privacy_tiers != frozenset({model.privacy_tier})
                    or request.privacy_tier != model.privacy_tier
                    or request.timeout_seconds > model.timeout_seconds
                    or request.max_output_tokens > model.max_output_tokens):
                return False
            for dimension, amount in model.quote_ceiling.items():
                if (amount > policy.root_lease.limits.get(dimension, 0)
                        or amount > policy.root_grant.max_ceiling.get(dimension, 0)):
                    return False
            if model is workflows.encode:
                return (type(encoding) is AdminIngressEncodingPolicy
                        and all(amount <= encoding.quote_ceiling.get(dimension, 0)
                                for dimension, amount in model.quote_ceiling.items())
                        and model.template_version
                        == FIRST_INGRESS_ENCODING_TEMPLATE_VERSION
                        and request.prompt_template_digest
                        == FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST)
            # No trusted D09 reply template registry is installed in this slice.
            return False
        if (model is not bundle.ingress_model
                or type(policy) is not AdminInstallationPolicy
                or type(encoding) is not AdminIngressEncodingPolicy
                or policy.namespace != authority.namespace
                or descriptor.capabilities != frozenset({"text"})
                or not set(model.required_capabilities) <= {"text"}
                or not request.required_capabilities
                or not request.required_capabilities <= descriptor.capabilities
                or not request.required_capabilities <= set(model.required_capabilities)
                or not descriptor.purposes <= set(model.allowed_purposes)
                or authority.purpose not in descriptor.purposes
                or authority.purpose not in model.allowed_purposes
                or not authority.audience
                or not set(authority.audience) <= set(model.allowed_audiences)
                or not descriptor.privacy_tiers <= set(model.allowed_privacy_tiers)
                or request.privacy_tier != model.privacy_tier
                or request.privacy_tier not in descriptor.privacy_tiers
                or request.privacy_tier not in model.allowed_privacy_tiers
                or "reply" not in policy.root_grant.allowed_work_kinds):
            return False
        output = model.max_output_tokens
        return (encoding.quote_ceiling.get("output_tokens", 0) >= output
                and policy.root_lease.limits.get("output_tokens", 0) >= output
                and policy.root_grant.max_ceiling.get("output_tokens", 0) >= output
                and request.max_output_tokens <= output)

    def _matches_live_provider(self, provider: object) -> bool:
        if type(provider) is not ProviderOpenAIOfficial:
            return False
        installed = self._context.get_all_providers()
        meta = provider.meta()
        if (type(installed) is not list
                or sum(item is provider for item in installed) != 1
                or not isinstance(meta, ProviderMeta)
                or meta.provider_type is not ProviderType.CHAT_COMPLETION
                or meta.id != self._descriptor.provider_id
                or meta.model != self._descriptor.model_id
                or provider.get_model() != meta.model
                or self._context.get_provider_by_id(meta.id) is not provider
                or type(provider.provider_config) is not dict
                or "api_version" in provider.provider_config
                or not isinstance(provider.client, AsyncOpenAI)
                or isinstance(provider.client, AsyncAzureOpenAI)):
            return False
        digest = canonical_digest(provider.provider_config)
        return (digest == self._admin_model.provider_config_digest
                and installed_model_config_ref(meta.id, meta.model, digest)
                == self._admin_model.provider_config_ref)

    async def _selected_provider(self):
        """Read AstrBot's current UMO selection on its owning host loop."""
        async_selector = getattr(self._context, "get_using_provider_async", None)
        if callable(async_selector):
            return await async_selector(self._trusted_umo)
        selector = getattr(self._context, "get_using_provider", None)
        if callable(selector):
            return selector(self._trusted_umo)
        raise RuntimeError("AstrBot chat provider selection is unavailable")

    async def _invoke_on_host(self, request: ModelCallRequest) -> ProviderResponse:
        try:
            provider = await self._selected_provider()
            if not self._matches_live_provider(provider):
                return ProviderResponse("not_dispatched", None, {}, {}, None)
        except asyncio.CancelledError:
            return ProviderResponse("not_dispatched", None, {}, {}, None)
        except Exception:
            return ProviderResponse("not_dispatched", None, {}, {}, None)
        payload = request.payload
        if (set(payload) not in ({"prompt"}, {"prompt", "system_prompt"})
                or type(payload.get("prompt")) is not str or not payload["prompt"]
                or ("system_prompt" in payload
                    and type(payload["system_prompt"]) is not str)):
            return ProviderResponse("not_dispatched", None, {}, {}, None)
        try:
            selected_client = provider.client
            client = selected_client.with_options(
                max_retries=0, timeout=request.timeout_seconds,
            )
            messages = []
            if payload.get("system_prompt"):
                messages.append({"role": "system", "content": payload["system_prompt"]})
            messages.append({"role": "user", "content": payload["prompt"]})
            # No network operation has begun. Re-read the selected provider and
            # its live configuration immediately before creating the call.
            try:
                selected = await self._selected_provider()
                if (selected is not provider
                        or not self._matches_live_provider(provider)
                        or provider.client is not selected_client
                        or not self._request_allowed(request)):
                    return ProviderResponse("not_dispatched", None, {}, {}, None)
            except asyncio.CancelledError:
                return ProviderResponse("not_dispatched", None, {}, {}, None)
            except Exception:
                return ProviderResponse("not_dispatched", None, {}, {}, None)
            # Selection hooks may request host shutdown without suspending the
            # coroutine. Check the pending cancellation before the SDK call.
            if asyncio.current_task().cancelling():
                try:
                    await asyncio.sleep(0)
                except asyncio.CancelledError:
                    return ProviderResponse("not_dispatched", None, {}, {}, None)
                return ProviderResponse("not_dispatched", None, {}, {}, None)
            response = await client.chat.completions.create(
                model=self._descriptor.model_id,
                messages=messages, stream=False,
                max_completion_tokens=request.max_output_tokens,
            )
            if (not isinstance(response, ChatCompletion)
                    or len(response.choices) != 1
                    or response.choices[0].finish_reason != "stop"):
                return ProviderResponse("unknown", None, {}, {}, None)
            message = response.choices[0].message
            if (message.role != "assistant" or type(message.content) is not str
                    or message.refusal is not None
                    or message.tool_calls or message.function_call):
                return ProviderResponse("unknown", None, {}, {}, None)
            usage = response.usage
            if usage is None:
                amounts = {}
            elif all(type(value) is int and value >= 0 for value in (
                    usage.prompt_tokens, usage.completion_tokens, usage.total_tokens)):
                cached = (usage.prompt_tokens_details.cached_tokens
                          if usage.prompt_tokens_details is not None else None)
                if cached is not None and (type(cached) is not int or cached < 0):
                    return ProviderResponse("unknown", None, {}, {}, None)
                amounts = {
                    "input_tokens": usage.prompt_tokens,
                    "output_tokens": usage.completion_tokens,
                }
                if cached is not None:
                    amounts["cached_input_tokens"] = cached
            else:
                return ProviderResponse("unknown", None, {}, {}, None)
            call_ref = response.id if type(response.id) is str and response.id else None
            return ProviderResponse("completed", {"text": message.content}, amounts, {}, call_ref)
        except asyncio.CancelledError:
            return ProviderResponse("unknown", None, {}, {}, None)
        except Exception:
            return ProviderResponse("unknown", None, {}, {}, None)

    def terminal_response(self, call_id: str, request_digest: str,
                          admission_id: str) -> ProviderResponse | None:
        """Read an exact call's terminal response; None means absent or unresolved.

        The host executor must retain this bound adapter. This process-local
        observation is neither durable recovery nor proof of remote cancellation.
        """
        with _call_lock:
            entry = _calls.get(call_id)
            if entry is None:
                return None
            if (entry.digest != request_digest or entry.admission_id != admission_id
                    or entry.host_incarnation != self.host_incarnation
                    or entry.provider_config_digest != self._admin_model.provider_config_digest
                    or not self._same_binding(entry)):
                raise ValueError("call_id belongs to a different request or binding")
            if not entry.terminal.done():
                return None
            return entry.terminal.result()

    def _launch_on_host(self, entry: _CallEntry,
                        request: ModelCallRequest) -> None:
        coroutine = self._invoke_on_host(request)
        try:
            task = asyncio.create_task(coroutine)
        except RuntimeError:
            coroutine.close()
            entry.terminal.set_result(
                ProviderResponse("not_dispatched", None, {}, {}, None))
            return
        entry.task = task

        def finish(done: asyncio.Task[ProviderResponse]) -> None:
            try:
                response = done.result()
            except asyncio.CancelledError:
                # The host's shutdown/cancellation did not settle remote egress.
                return
            except Exception:
                response = ProviderResponse("unknown", None, {}, {}, None)
            entry.task = None
            entry.terminal.set_result(response)

        task.add_done_callback(finish)

    async def invoke(self, request: ModelCallRequest,
                     cancellation: asyncio.Event) -> ProviderResponse:
        """The old Broker port has no Authority admission or recovery identity."""
        return ProviderResponse("unknown", None, {}, {}, None)

    async def invoke_admitted(self, request: ModelCallRequest,
                              admission: LocalModelAdmission,
                              cancellation: asyncio.Event) -> ProviderResponse:
        """Exercise one local start claim; a future executor must prove its provenance.

        A process restart loses this registry. No durable replay or remote-stop
        guarantee follows from this method or from a finished asyncio task.
        """
        if type(request) is not ModelCallRequest:
            return ProviderResponse("not_dispatched", None, {}, {}, None)
        if (type(admission) is not LocalModelAdmission
                or admission.host_incarnation != self.host_incarnation
                or admission.call_id != request.call_id
                or admission.request_digest != request.digest
                or admission.provider_config_digest != self._admin_model.provider_config_digest):
            raise ValueError("model admission differs from local request or configuration")
        with _call_lock:
            entry = _calls.get(request.call_id)
            if entry is not None:
                if (entry.digest != request.digest
                        or entry.admission_id != admission.admission_id
                        or entry.host_incarnation != admission.host_incarnation
                        or entry.provider_config_digest != admission.provider_config_digest
                        or not self._same_binding(entry)):
                    raise ValueError("call_id belongs to a different request or binding")
                first = False
            else:
                old_call = _admissions.get(admission.admission_id)
                if old_call is not None and old_call != request.call_id:
                    raise ValueError("model admission already belongs to another call")
                entry = _CallEntry(
                    request.digest, admission.admission_id, admission.host_incarnation,
                    admission.provider_config_digest, self._binding)
                _calls[request.call_id] = entry
                _admissions[admission.admission_id] = request.call_id
                first = True
        if first:
            if (request.provider_id != self._descriptor.provider_id
                    or request.model_id != self._descriptor.model_id
                    or request.timeout_seconds > self._admin_model.timeout_seconds
                    or request.max_output_tokens > self._admin_model.max_output_tokens
                    or not self._request_allowed(request)
                    or cancellation.is_set() or not self._host_loop.is_running()):
                entry.terminal.set_result(
                    ProviderResponse("not_dispatched", None, {}, {}, None))
            else:
                try:
                    self._host_loop.call_soon_threadsafe(
                        self._launch_on_host, entry, request)
                except RuntimeError:
                    # The callback was not accepted, so no provider task exists.
                    entry.terminal.set_result(
                        ProviderResponse("not_dispatched", None, {}, {}, None))
        # A cancelled waiter must never cancel the one accepted provider task.
        return await asyncio.shield(asyncio.wrap_future(entry.terminal))

    async def cancel(self, request: ModelCallRequest) -> bool:
        """No host cancellation proof: preserve Broker's unknown outcome."""
        return False


__all__ = ("AstrBotModelProvider", "LocalModelAdmission")
