"""AstrBot SDK-backed installed model receipt; no model calls are made."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
import unittest

from astrbot.api.star import Context
from astrbot.core.provider.entities import ProviderMeta, ProviderType
from astrbot.core.provider.provider import Provider

from sylanne3.host.installed_model_capability import (
    InstalledModelCapabilityPort, model_capability_ref,
)
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.workbench_api.d01_onboarding import VerifiedModelCapability


class InstalledChatProvider(Provider):
    def __init__(self, provider_id="provider-1", model="model-1"):
        self.provider_id = provider_id
        self.model_name = model

    def meta(self):
        return ProviderMeta(
            self.provider_id, self.model_name, "openai_chat_completion",
            ProviderType.CHAT_COMPLETION,
        )

    def get_current_key(self):
        raise AssertionError("capability check must not read credentials")

    def set_key(self, key):
        raise AssertionError("capability check must not change credentials")

    async def get_models(self):
        raise AssertionError("capability check must not call remote model catalogue")

    async def text_chat(self, *args, **kwargs):
        raise AssertionError("capability check must not call model")


class InstalledModelCapabilityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.provider = InstalledChatProvider()
        self.manager = SimpleNamespace(
            provider_insts=[self.provider], inst_map={"provider-1": self.provider},
        )
        self.context = Context(
            asyncio.Queue(), {}, None, self.manager, None, None,
            None, None, None, None, None,
        )
        self.namespace = NamespaceId("bot", "persona")
        self.port = InstalledModelCapabilityPort(
            context=self.context, host_loop=asyncio.get_running_loop(),
            installed_namespace=self.namespace,
        )
        self.ref = model_capability_ref("provider-1", "model-1")

    async def test_current_installed_chat_model_is_content_stable(self):
        first = await asyncio.to_thread(self.port.verify, self.namespace, self.ref)
        second = await asyncio.to_thread(self.port.verify, self.namespace, self.ref)
        self.assertIsInstance(first, VerifiedModelCapability)
        self.assertEqual(first, second)
        self.assertEqual(first, await asyncio.to_thread(
            self.port.resolve_current_model_capability,
            namespace=self.namespace, capability_ref=self.ref))
        self.assertEqual(first.capability_ref, self.ref)
        self.assertGreater(first.revision, 0)
        self.assertTrue(first.digest.startswith("sha256:"))
        self.assertIsNone(self.port.verify(self.namespace, self.ref))
        self.assertIsNone(await asyncio.to_thread(
            self.port.verify, NamespaceId("other-bot", "persona"), self.ref))

    async def test_removed_changed_or_duplicate_provider_holds(self):
        self.provider.model_name = "model-2"
        self.assertIsNone(await asyncio.to_thread(
            self.port.verify, self.namespace, self.ref))
        self.provider.model_name = "model-1"
        self.manager.inst_map.clear()
        self.assertIsNone(await asyncio.to_thread(
            self.port.verify, self.namespace, self.ref))
        self.manager.inst_map["provider-1"] = self.provider
        self.manager.provider_insts.append(InstalledChatProvider())
        self.assertIsNone(await asyncio.to_thread(
            self.port.verify, self.namespace, self.ref))

    async def test_non_chat_or_malformed_selection_holds(self):
        self.provider.meta = lambda: ProviderMeta(
            "provider-1", "model-1", "embedding", ProviderType.EMBEDDING,
        )
        self.assertIsNone(await asyncio.to_thread(
            self.port.verify, self.namespace, self.ref))
        self.assertIsNone(await asyncio.to_thread(
            self.port.verify, self.namespace, "astrbot-model:bad"))
        with self.assertRaises(ValueError):
            model_capability_ref("", "model-1")


if __name__ == "__main__":
    unittest.main()
