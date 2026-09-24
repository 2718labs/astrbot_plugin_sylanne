"""Read the currently installed AstrBot chat provider without invoking it.

This is an installation-level availability receipt. It says nothing about the
provider selected for a conversation, remote health, or a successful model call.
"""

from __future__ import annotations

import asyncio

from astrbot.api.star import Context
from astrbot.core.provider.entities import ProviderMeta, ProviderType
from astrbot.core.provider.provider import Provider
from astrbot.core.provider.sources.openai_source import ProviderOpenAIOfficial
from openai import AsyncAzureOpenAI, AsyncOpenAI

from .authority_profile import AdminIngressModelPolicy, installed_model_config_ref
from ..runtime_contracts import NamespaceId, canonical_digest
from ..workbench_api.d01_onboarding import VerifiedModelCapability


_SCHEMA = "sylanne.astrbot.installed-model.v1"


def model_capability_ref(provider_id: str, model: str) -> str:
    """Canonical selector for one configured provider and its current model."""
    if (type(provider_id) is not str or not provider_id
            or type(model) is not str or not model):
        raise ValueError("provider ID and model must be nonempty strings")
    return "astrbot-model:" + canonical_digest({
        "schema": _SCHEMA, "provider_id": provider_id, "model": model,
    })


class InstalledModelCapabilityPort:
    """Resolve a content-addressed selector on the running AstrBot host loop."""

    def __init__(self, *, context: Context, host_loop: asyncio.AbstractEventLoop,
                 installed_namespace: NamespaceId,
                 timeout_seconds: float = 2.0) -> None:
        if (not isinstance(context, Context)
                or not isinstance(host_loop, asyncio.AbstractEventLoop)
                or type(installed_namespace) is not NamespaceId
                or not 0 < timeout_seconds <= 10):
            raise ValueError("installed model bridge needs a current AstrBot host")
        self._context = context
        self._host_loop = host_loop
        self._installed_namespace = installed_namespace
        self._timeout_seconds = timeout_seconds

    async def _verify_on_host_loop(
        self, namespace: NamespaceId, capability_ref: str,
    ) -> VerifiedModelCapability | None:
        context = self._context
        try:
            installed = context.get_all_providers()
            if type(installed) is not list:
                return None
            matches = []
            for provider in installed:
                if not isinstance(provider, Provider):
                    continue
                meta = provider.meta()
                if (not isinstance(meta, ProviderMeta)
                        or meta.provider_type is not ProviderType.CHAT_COMPLETION
                        or type(meta.id) is not str or not meta.id
                        or type(meta.model) is not str or not meta.model
                        or type(meta.type) is not str or not meta.type
                        or provider.get_model() != meta.model):
                    return None
                if model_capability_ref(meta.id, meta.model) == capability_ref:
                    matches.append((provider, meta))
            if len(matches) != 1:
                return None
            provider, meta = matches[0]
            if context.get_provider_by_id(meta.id) is not provider:
                return None
            payload = {
                "schema": _SCHEMA, "provider_id": meta.id,
                "adapter_type": meta.type, "provider_type": meta.provider_type.value,
                "model": meta.model,
            }
            digest = canonical_digest(payload)
            # Content-derived stable integer, not an AstrBot monotonic version.
            revision = int(digest[:15], 16) + 1
            return VerifiedModelCapability(
                namespace, capability_ref,
                "astrbot-provider:" + canonical_digest({
                    "schema": _SCHEMA, "provider_id": meta.id,
                    "adapter_type": meta.type,
                }),
                revision, "sha256:" + digest,
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            return None

    def verify(self, namespace: NamespaceId,
               capability_ref: str) -> VerifiedModelCapability | None:
        if (type(namespace) is not NamespaceId
                or namespace != self._installed_namespace
                or type(capability_ref) is not str
                or not capability_ref.startswith("astrbot-model:")
                or len(capability_ref) != len("astrbot-model:") + 64
                or any(ch not in "0123456789abcdef" for ch in capability_ref[14:])):
            return None
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._host_loop or not self._host_loop.is_running():
            return None
        coro = self._verify_on_host_loop(namespace, capability_ref)
        try:
            future = asyncio.run_coroutine_threadsafe(coro, self._host_loop)
        except RuntimeError:
            coro.close()
            return None
        try:
            return future.result(timeout=self._timeout_seconds)
        except Exception:
            future.cancel()
            return None

    def resolve_current_model_capability(
        self, *, namespace: NamespaceId, capability_ref: str,
    ) -> VerifiedModelCapability | None:
        return self.verify(namespace, capability_ref)

    async def _verify_admin_config_on_host_loop(
        self, selection: AdminIngressModelPolicy,
    ) -> bool:
        """Check installed adapter/config identity, not capability or policy fitness."""
        try:
            providers = self._context.get_all_providers()
            if type(providers) is not list:
                return False
            matches = [provider for provider in providers
                       if type(provider) is ProviderOpenAIOfficial
                       and isinstance(provider.meta(), ProviderMeta)
                       and provider.meta().id == selection.provider_id]
            if len(matches) != 1:
                return False
            provider = matches[0]
            meta = provider.meta()
            config_digest = canonical_digest(provider.provider_config)
            return (
                meta.provider_type is ProviderType.CHAT_COMPLETION
                and meta.model == selection.model_id
                and provider.get_model() == selection.model_id
                and self._context.get_provider_by_id(selection.provider_id) is provider
                and type(provider.provider_config) is dict
                and "api_version" not in provider.provider_config
                and config_digest == selection.provider_config_digest
                and installed_model_config_ref(
                    meta.id, meta.model, config_digest) == selection.provider_config_ref
                and isinstance(provider.client, AsyncOpenAI)
                and not isinstance(provider.client, AsyncAzureOpenAI)
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            return False

    def verify_admin_config(
        self, namespace: NamespaceId, selection: AdminIngressModelPolicy,
    ) -> bool:
        if (type(namespace) is not NamespaceId
                or namespace != self._installed_namespace
                or type(selection) is not AdminIngressModelPolicy
                or not self._host_loop.is_running()):
            return False
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._host_loop:
            return False
        coro = self._verify_admin_config_on_host_loop(selection)
        try:
            future = asyncio.run_coroutine_threadsafe(coro, self._host_loop)
        except RuntimeError:
            coro.close()
            return False
        try:
            return future.result(timeout=self._timeout_seconds)
        except Exception:
            future.cancel()
            return False

    def verify_admin_selection(
        self, namespace: NamespaceId, selection: AdminIngressModelPolicy,
    ) -> bool:
        """Full selection remains HOLD without host capability/privacy/limit proof."""
        return False


__all__ = ("InstalledModelCapabilityPort", "model_capability_ref")
