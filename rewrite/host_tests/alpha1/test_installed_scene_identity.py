"""The worker bridge resolves only current installed host candidates."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

from astrbot.api.star import Context
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_platform_adapter import AiocqhttpAdapter

from sylanne3.host.current_scene import CurrentHostScene
from sylanne3.host.identity import astrbot_namespace
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.host.installed_scene_identity import InstalledSceneIdentityPort
from sylanne3.host.scene_candidates import SceneCandidateCatalog


UMO = "platform-1:FriendMessage:123456"


class Conversations:
    current = "conversation-1"

    async def get_curr_conversation_id(self, umo):
        assert umo == UMO
        return self.current

    async def get_conversation(self, umo, conversation_id, create_if_not_exists=False):
        assert umo == UMO and create_if_not_exists is False
        return SimpleNamespace(persona_id="persona-1") if conversation_id == self.current else None


class Personas:
    selected = "persona-1"

    async def resolve_selected_persona(self, **kwargs):
        assert kwargs["umo"] == UMO
        return self.selected, {}, None, False


class InstalledSceneIdentityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter = AiocqhttpAdapter(
            {"id": "platform-1", "ws_reverse_host": "127.0.0.1", "ws_reverse_port": 6199},
            {}, asyncio.Queue())
        self.adapter.bot.call_action = AsyncMock(return_value={"user_id": "bot-1"})
        self.context = Context(
            asyncio.Queue(), {}, None, None,
            SimpleNamespace(platform_insts=[self.adapter]), None, None, None,
            SimpleNamespace(get_conf=lambda umo: {}), None, None)
        self.conversations = Conversations()
        self.personas = Personas()
        self.context.conversation_manager = self.conversations
        self.context.persona_manager = self.personas
        self.namespace = astrbot_namespace("platform-1", "bot-1", "persona-1")
        self.catalog = SceneCandidateCatalog()
        self.port = InstalledSceneIdentityPort(
            context=self.context, host_loop=asyncio.get_running_loop(),
            candidates=self.catalog)
        self.ingress = HostIngressEnvelope(
            self.namespace, '["platform-1","aiocqhttp","bot-1"]',
            '["platform-1:FriendMessage:123456","conversation-1"]',
            '["platform-1","user-1"]', "message-1", "test", 1.0, 2.0,
            "private", SourceLineage("a" * 64, "reported", "onebot",
                                     "external_report", "reported_claim"))
        self.observed = self.catalog.observe(self.ingress)
        assert self.observed is not None

    async def test_current_candidate_returns_only_current_host_identity(self):
        result = await asyncio.to_thread(
            self.port.verify, self.namespace, self.observed.scene_ref, "private")
        self.assertEqual(result, CurrentHostScene(
            self.namespace, self.observed.platform_ref,
            self.observed.conversation_ref, "private", self.observed.scene_ref))
        self.assertEqual(self.adapter.bot.call_action.await_count, 1)
        self.adapter.bot.call_action.assert_awaited_with("get_login_info", self_id="bot-1")
        self.assertEqual(self.port.verify(self.namespace, self.observed.scene_ref, "private"), None)

    async def test_absent_or_mismatched_candidate_holds_before_host_call(self):
        self.catalog.clear()
        self.assertIsNone(await asyncio.to_thread(
            self.port.verify, self.namespace, self.observed.scene_ref, "private"))
        self.assertEqual(self.adapter.bot.call_action.await_count, 0)
        self.catalog.observe(self.ingress)
        self.assertIsNone(await asyncio.to_thread(
            self.port.verify, self.namespace, self.observed.scene_ref, "group"))
        self.assertIsNone(await asyncio.to_thread(
            self.port.verify, self.namespace, "scene:conversation-v1:" + "0" * 64,
            "private"))
        self.assertIsNone(await asyncio.to_thread(
            self.port.verify, astrbot_namespace("platform-2", "bot-1", "persona-1"),
            self.observed.scene_ref, "private"))
        self.assertEqual(self.adapter.bot.call_action.await_count, 0)

    async def test_changed_host_conversation_persona_or_account_holds(self):
        self.conversations.current = "conversation-2"
        self.assertIsNone(await asyncio.to_thread(
            self.port.verify, self.namespace, self.observed.scene_ref, "private"))
        self.conversations.current = "conversation-1"
        self.personas.selected = "persona-2"
        self.assertIsNone(await asyncio.to_thread(
            self.port.verify, self.namespace, self.observed.scene_ref, "private"))
        self.personas.selected = "persona-1"
        self.adapter.bot.call_action.return_value = {"user_id": "bot-2"}
        self.assertIsNone(await asyncio.to_thread(
            self.port.verify, self.namespace, self.observed.scene_ref, "private"))
