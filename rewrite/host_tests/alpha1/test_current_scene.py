"""Current host scene checks use the controlled AstrBot 4.28.1 SDK seam."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, call

from astrbot.api.star import Context
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_platform_adapter import AiocqhttpAdapter

from sylanne3.host.current_scene import CurrentHostScene, verify_current_host_scene
from sylanne3.host.identity import astrbot_namespace
from sylanne3.host.scene_candidates import ObservedSceneCandidate
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation


PLATFORM_ID = "platform-1"
SELF_ID = "bot-1"
UMO = "platform-1:FriendMessage:123456"


def _canonical(*parts: str) -> str:
    return json.dumps(parts, ensure_ascii=True, separators=(",", ":"))


class Conversations:
    def __init__(self):
        self.current = "conversation-1"
        self.after_read = None
        self.present = True
        self.calls = 0

    async def get_curr_conversation_id(self, umo):
        assert umo == UMO
        self.calls += 1
        if self.calls == 2 and self.after_read is not None:
            self.current = self.after_read
        return self.current

    async def get_conversation(self, umo, conversation_id, create_if_not_exists=False):
        assert umo == UMO and conversation_id == "conversation-1"
        assert create_if_not_exists is False
        return SimpleNamespace(persona_id="persona-1") if self.present else None


class Personas:
    def __init__(self):
        self.selected = "persona-1"

    async def resolve_selected_persona(self, **kwargs):
        assert kwargs["umo"] == UMO
        assert kwargs["conversation_persona_id"] == "persona-1"
        assert kwargs["platform_name"] == "aiocqhttp"
        return self.selected, {}, None, False


class CurrentSceneTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter = AiocqhttpAdapter(
            {"id": PLATFORM_ID, "ws_reverse_host": "127.0.0.1", "ws_reverse_port": 6199},
            {}, asyncio.Queue())
        self.adapter.bot.call_action = AsyncMock(return_value={"user_id": SELF_ID})
        self.conversations = Conversations()
        self.personas = Personas()
        self.context = Context(
            asyncio.Queue(), {}, None, None,
            SimpleNamespace(platform_insts=[self.adapter]), None, None, None,
            SimpleNamespace(get_conf=lambda umo: {}), None, None,
        )
        self.context.conversation_manager = self.conversations
        self.context.persona_manager = self.personas
        namespace = astrbot_namespace(PLATFORM_ID, SELF_ID, "persona-1")
        platform_ref = _canonical(PLATFORM_ID, "aiocqhttp", SELF_ID)
        conversation_ref = _canonical(UMO, "conversation-1")
        self.candidate = ObservedSceneCandidate(
            namespace, platform_ref, conversation_ref, "private",
            scene_ref_for_conversation(namespace, platform_ref, conversation_ref))

    async def test_current_scene_rechecks_account_conversation_persona_without_send(self):
        result = await verify_current_host_scene(self.context, self.candidate)
        self.assertEqual(result, CurrentHostScene(
            self.candidate.namespace, self.candidate.platform_ref,
            self.candidate.conversation_ref, "private", self.candidate.scene_ref))
        self.adapter.bot.call_action.assert_has_awaits([
            call("get_login_info", self_id=SELF_ID)])
        self.assertEqual(self.adapter.bot.call_action.await_count, 1)
        self.assertEqual(self.conversations.calls, 2)

    async def test_conversation_or_persona_switch_holds(self):
        self.conversations.after_read = "conversation-2"
        self.assertIsNone(await verify_current_host_scene(self.context, self.candidate))
        self.conversations = Conversations()
        self.context.conversation_manager = self.conversations
        self.personas.selected = "persona-2"
        self.assertIsNone(await verify_current_host_scene(self.context, self.candidate))

    async def test_wrong_account_visibility_scene_or_platform_holds(self):
        self.adapter.bot.call_action.return_value = {"user_id": "another-bot"}
        self.assertIsNone(await verify_current_host_scene(self.context, self.candidate))
        self.adapter.bot.call_action.return_value = {"user_id": SELF_ID}
        self.assertIsNone(await verify_current_host_scene(
            self.context, replace(self.candidate, scene_ref="scene:conversation-v1:" + "0" * 64)))
        self.assertIsNone(await verify_current_host_scene(
            self.context, replace(self.candidate, visibility="group")))
        self.context.platform_manager.platform_insts.append(self.adapter)
        self.assertIsNone(await verify_current_host_scene(self.context, self.candidate))

    async def test_missing_conversation_or_noncanonical_refs_hold(self):
        self.conversations.present = False
        self.assertIsNone(await verify_current_host_scene(self.context, self.candidate))
        self.assertIsNone(await verify_current_host_scene(
            self.context, replace(self.candidate, platform_ref='["platform-1", "aiocqhttp", "bot-1"]')))
        self.assertIsNone(await verify_current_host_scene(
            self.context, replace(self.candidate, conversation_ref="[]")))
