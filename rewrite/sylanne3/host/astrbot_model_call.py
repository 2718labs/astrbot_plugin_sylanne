"""One AstrBot chat call behind ModelBroker's egress and receipt boundary.

The UMO is supplied by trusted host composition. This adapter rechecks its
current chat-provider selection before each call; it does not grant egress or
infer a conversation from model payload. A lost outcome remains unknown.
"""

from __future__ import annotations

import asyncio

from astrbot.api.star import Context
from astrbot.core.provider.entities import ProviderMeta, ProviderType
from astrbot.core.provider.sources.openai_source import ProviderOpenAIOfficial
from openai import AsyncAzureOpenAI, AsyncOpenAI
from openai.types.chat.chat_completion import ChatCompletion

from ..model_broker.broker import (
    ModelCallRequest, ModelProviderDescriptor, ProviderResponse,
)


class AstrBotModelProvider:
    """Bound to one trusted UMO and one exact configured provider/model."""

    def __init__(
        self, *, context: Context, host_loop: asyncio.AbstractEventLoop,
        trusted_umo: str, descriptor: ModelProviderDescriptor,
    ) -> None:
        if (not isinstance(context, Context)
                or not isinstance(host_loop, asyncio.AbstractEventLoop)
                or type(trusted_umo) is not str or not trusted_umo
                or type(descriptor) is not ModelProviderDescriptor
                or descriptor.is_test_double or descriptor.timeout_cancellable
                or descriptor.supports_idempotency
                or descriptor.cost_reporting != "unknown"):
            raise ValueError("trusted non-retrying AstrBot model binding is required")
        self._context = context
        self._host_loop = host_loop
        self._trusted_umo = trusted_umo
        self._descriptor = descriptor

    @property
    def descriptor(self) -> ModelProviderDescriptor:
        return self._descriptor

    async def _invoke_on_host(self, request: ModelCallRequest) -> ProviderResponse:
        try:
            provider = await self._context.get_using_provider_async(self._trusted_umo)
            if type(provider) is not ProviderOpenAIOfficial:
                return ProviderResponse("not_dispatched", None, {}, {}, None)
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
            client = provider.client.with_options(
                max_retries=0, timeout=request.timeout_seconds,
            )
            messages = []
            if payload.get("system_prompt"):
                messages.append({"role": "system", "content": payload["system_prompt"]})
            messages.append({"role": "user", "content": payload["prompt"]})
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

    async def invoke(self, request: ModelCallRequest,
                     cancellation: asyncio.Event) -> ProviderResponse:
        if (type(request) is not ModelCallRequest
                or request.provider_id != self._descriptor.provider_id
                or request.model_id != self._descriptor.model_id):
            return ProviderResponse("not_dispatched", None, {}, {}, None)
        if cancellation.is_set() or not self._host_loop.is_running():
            return ProviderResponse("not_dispatched", None, {}, {}, None)
        if asyncio.get_running_loop() is self._host_loop:
            task = asyncio.create_task(self._invoke_on_host(request))
            return await asyncio.shield(task)
        coroutine = self._invoke_on_host(request)
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, self._host_loop)
        except RuntimeError:
            coroutine.close()
            return ProviderResponse("not_dispatched", None, {}, {}, None)
        # Broker timeout/cancellation must not imply that AstrBot stopped egress.
        return await asyncio.shield(asyncio.wrap_future(future))

    async def cancel(self, request: ModelCallRequest) -> bool:
        """No host cancellation proof: preserve Broker's unknown outcome."""
        return False


__all__ = ("AstrBotModelProvider",)
