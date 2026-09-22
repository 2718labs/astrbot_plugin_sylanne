from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path

from astrbot.api.event import AstrMessageEvent, MessageChain
from astrbot.api.platform import (
    AstrBotMessage,
    MessageMember,
    MessageType,
    PlatformMetadata,
)
from astrbot.api.provider import LLMResponse, Provider
from astrbot.api.star import Context, Star, StarTools
from astrbot.core.provider.entities import ProviderMeta
from astrbot.core.star.filter.command import CommandFilter
from astrbot.core.star.star_handler import star_handlers_registry

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_default_plugin_root = REPOSITORY_ROOT
if "class Sylanne3Plugin" not in (REPOSITORY_ROOT / "main.py").read_text(
    encoding="utf-8"
):
    _default_plugin_root = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = Path(
    os.environ.get("SYLANNE3_PLUGIN_ROOT", _default_plugin_root)
).resolve()
PLUGIN_MODULE = "data.plugins.sylanne3_acceptance.main"


def load_plugin_module():
    """Load the root entry point with the namespace shape used by AstrBot."""
    paths = {
        "data": PLUGIN_ROOT,
        "data.plugins": PLUGIN_ROOT,
        "data.plugins.sylanne3_acceptance": PLUGIN_ROOT,
    }
    for name, path in paths.items():
        package = sys.modules.get(name)
        if package is None:
            package = types.ModuleType(name)
            package.__package__ = name
            sys.modules[name] = package
        package.__path__ = [str(path)]
    sys.modules.pop(PLUGIN_MODULE, None)
    return importlib.import_module(PLUGIN_MODULE)


class ControlledProvider(Provider):
    def __init__(self, response: str = '{"appraisal":"support","evidence":"谢谢你"}'):
        super().__init__({"type": "controlled", "id": "provider-1", "key": [""]}, {})
        self.response = response
        self.calls: list[dict] = []
        self.entered: asyncio.Event | None = None
        self.release: asyncio.Event | None = None

    def meta(self):
        return ProviderMeta("provider-1", "controlled", "controlled")

    def get_current_key(self) -> str:
        return ""

    def set_key(self, key: str) -> None:
        return None

    async def get_models(self) -> list[str]:
        return ["controlled"]

    async def text_chat(self, **kwargs) -> LLMResponse:
        self.calls.append(kwargs)
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            await self.release.wait()
        return LLMResponse("assistant", result_chain=MessageChain().message(self.response))


class ControlledProviderManager:
    def __init__(self, provider: ControlledProvider):
        self.provider = provider

    async def get_using_provider_async(self, *, provider_type, umo):
        return self.provider

    async def get_provider_by_id(self, provider_id: str):
        return self.provider if provider_id == "provider-1" else None


class Conversation:
    def __init__(self, cid: str, persona_id: str):
        self.cid = cid
        self.persona_id = persona_id


class ControlledConversationManager:
    def __init__(self):
        self.current: dict[str, str] = {}
        self.conversations: dict[tuple[str, str], Conversation] = {}

    def select(self, umo: str, cid: str, persona_id: str):
        self.current[umo] = cid
        self.conversations[(umo, cid)] = Conversation(cid, persona_id)

    async def get_curr_conversation_id(self, umo: str):
        return self.current.get(umo)

    async def get_conversation(self, umo: str, cid: str, create_if_not_exists: bool = False):
        if create_if_not_exists:
            raise AssertionError("adapter must fail closed instead of creating host conversations")
        return self.conversations.get((umo, cid))


class ControlledPersonaManager:
    def __init__(self):
        self.calls: list[dict] = []

    async def resolve_selected_persona(self, **kwargs):
        self.calls.append(kwargs)
        persona_id = kwargs["conversation_persona_id"]
        return persona_id, {"name": persona_id, "prompt": ""}, None, False


class ControlledConfigManager:
    def get_conf(self, umo: str):
        return {"umo": umo, "controlled": True}


def make_context(provider, conversations, personas):
    return Context(
        asyncio.Queue(),
        {},
        None,
        ControlledProviderManager(provider),
        None,
        conversations,
        None,
        personas,
        ControlledConfigManager(),
        None,
        None,
    )


class ControlledEvent(AstrMessageEvent):
    def __init__(
        self,
        text: str,
        message_id: str,
        *,
        sender: str = "sender-1",
        bot: str = "bot-1",
        session: str = "session-1",
        platform_id: str = "adapter-1",
        timestamp: int = 10,
    ):
        message = AstrBotMessage()
        message.type = MessageType.FRIEND_MESSAGE
        message.self_id = bot
        message.session_id = session
        message.message_id = message_id
        message.sender = MessageMember(sender, "Sender")
        message.message = []
        message.message_str = text
        message.raw_message = {"controlled": True}
        message.timestamp = timestamp
        metadata = PlatformMetadata("controlled", "controlled test adapter", platform_id)
        super().__init__(text, message, metadata, session)
        self.is_at_or_wake_command = True
        self.sent: list[MessageChain] = []

    async def send(self, message: MessageChain) -> None:
        if not isinstance(message, MessageChain):
            raise TypeError("adapter must send an AstrBot MessageChain")
        self.sent.append(message)
        self._has_send_oper = True


class AstrBotAdapterTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_plugin_module()
        cls.Plugin = cls.module.Sylanne3Plugin
        if not issubclass(cls.Plugin, Star):
            raise AssertionError("entry point must expose an actual AstrBot Star subclass")

    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous_cwd = Path.cwd()
        os.chdir(self.temp.name)
        self.original_data_dir = StarTools.__dict__["get_data_dir"]
        controlled_data = Path(self.temp.name) / "data" / "plugin_data"
        StarTools.get_data_dir = classmethod(
            lambda cls, plugin_name=None: controlled_data / (plugin_name or "unknown")
        )
        self.provider = ControlledProvider()
        self.conversations = ControlledConversationManager()
        self.personas = ControlledPersonaManager()
        self.context = make_context(self.provider, self.conversations, self.personas)
        self.plugins = []

    async def asyncTearDown(self):
        for plugin in reversed(self.plugins):
            await plugin.terminate()
        StarTools.get_data_dir = self.original_data_dir
        os.chdir(self.previous_cwd)
        self.temp.cleanup()

    async def plugin(self, **config):
        values = {"enabled": True, "capacity": 2, "timeout": 5}
        values.update(config)
        plugin = self.Plugin(self.context, values)
        self.plugins.append(plugin)
        await plugin.initialize()
        return plugin

    def event(self, text="sylanne3 谢谢你", message_id="message-1", **kwargs):
        event = ControlledEvent(text, message_id, **kwargs)
        self.conversations.select(event.unified_msg_origin, "cid-1", "persona-1")
        return event

    def command_handler(self):
        handlers = [
            handler
            for handler in star_handlers_registry
            if handler.handler_module_path == PLUGIN_MODULE and handler.handler_name == "sylanne3"
        ]
        self.assertEqual(len(handlers), 1)
        command_filters = [item for item in handlers[0].event_filters if isinstance(item, CommandFilter)]
        self.assertEqual(len(command_filters), 1)
        return handlers[0], command_filters[0]

    async def invoke(self, plugin, event):
        handler, command_filter = self.command_handler()
        self.assertTrue(command_filter.filter(event, {}))
        await handler.handler(plugin, event)

    async def test_disabled_by_default_stops_default_llm_without_provider_call(self):
        plugin = self.Plugin(self.context, {})
        self.plugins.append(plugin)
        await plugin.initialize()
        event = self.event()
        await self.invoke(plugin, event)
        self.assertTrue(event.is_stopped())
        self.assertEqual(self.provider.calls, [])

    async def test_actual_command_filter_preserves_multiword_text_and_sends_one_action(self):
        plugin = await self.plugin()
        event = self.event("sylanne3 谢谢你  真的谢谢", "multiword")
        await self.invoke(plugin, event)
        self.assertTrue(event.is_stopped())
        self.assertEqual(len(self.provider.calls), 1)
        self.assertIn(
            json.dumps("谢谢你  真的谢谢", ensure_ascii=True),
            self.provider.calls[0]["prompt"],
        )
        self.assertEqual(len(event.sent), 1)
        self.assertTrue(event.sent[0].get_plain_text())
        database = await asyncio.to_thread(
            lambda: plugin._app.store._db.execute("PRAGMA database_list").fetchone()[2]
        )
        self.assertTrue(await asyncio.to_thread(Path(database).is_file))

    async def test_invalid_json_has_no_reaction_and_no_send(self):
        self.provider.response = "not JSON"
        plugin = await self.plugin()
        event = self.event(message_id="invalid")
        await self.invoke(plugin, event)
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(event.sent, [])
        scope, _ = await plugin._resolve_scope(event)
        reaction = plugin._app.store.snapshot(scope, ("reaction",)).get("reaction")
        self.assertEqual(reaction.revision, 0)

    async def test_identity_isolates_bot_sender_persona_and_conversation(self):
        plugin = await self.plugin()
        first = self.event(message_id="one", bot="bot-a", sender="sender-a")
        first_scope, first_ingress = await plugin._resolve_scope(first)
        second = ControlledEvent("sylanne3 谢谢你", "two", bot="bot-b", sender="sender-b")
        self.conversations.select(second.unified_msg_origin, "cid-2", "persona-2")
        second_scope, second_ingress = await plugin._resolve_scope(second)
        self.assertNotEqual(first_scope, second_scope)
        self.assertNotEqual(first_ingress, second_ingress)
        self.assertIn("bot-a", first_scope.bot)
        self.assertEqual(first_scope.persona, "persona-1")
        self.assertIn("cid-1", first_scope.session)
        self.assertIn("sender-a", first_ingress.session)

    async def test_duplicate_survives_restart_without_second_model_or_send(self):
        plugin = await self.plugin()
        first = self.event(message_id="restart")
        await self.invoke(plugin, first)
        await plugin.terminate()
        self.plugins.remove(plugin)
        restarted = await self.plugin()
        replay = self.event(message_id="restart")
        await self.invoke(restarted, replay)
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(len(first.sent), 1)
        self.assertEqual(replay.sent, [])

    async def test_same_message_after_owner_switch_is_not_reproposed_but_new_message_is_isolated(self):
        plugin = await self.plugin()
        first = self.event(message_id="stable-host-id")
        await self.invoke(plugin, first)
        self.conversations.select(first.unified_msg_origin, "cid-2", "persona-2")
        replay = ControlledEvent("sylanne3 谢谢你", "stable-host-id")
        await self.invoke(plugin, replay)
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(replay.sent, [])
        fresh = ControlledEvent("sylanne3 谢谢你", "new-host-id")
        await self.invoke(plugin, fresh)
        self.assertEqual(len(self.provider.calls), 2)
        self.assertEqual(len(fresh.sent), 1)

    async def test_owner_change_during_provider_call_blocks_transport(self):
        self.provider.entered = asyncio.Event()
        self.provider.release = asyncio.Event()
        plugin = await self.plugin()
        event = self.event(message_id="ownership-race")
        task = asyncio.create_task(self.invoke(plugin, event))
        await asyncio.wait_for(self.provider.entered.wait(), 2)
        self.conversations.select(event.unified_msg_origin, "cid-2", "persona-2")
        self.provider.release.set()
        await asyncio.wait_for(task, 2)
        self.assertEqual(event.sent, [])

    async def test_terminate_cancels_and_joins_inflight_handler(self):
        self.provider.entered = asyncio.Event()
        self.provider.release = asyncio.Event()
        plugin = await self.plugin(timeout=30)
        event = self.event(message_id="shutdown")
        task = asyncio.create_task(self.invoke(plugin, event))
        await asyncio.wait_for(self.provider.entered.wait(), 2)
        await asyncio.wait_for(plugin.terminate(), 2)
        self.plugins.remove(plugin)
        self.assertTrue(task.done())
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(event.sent, [])

    async def test_terminate_during_resource_initialization_cannot_publish_late_application(self):
        entered = threading.Event()
        release = threading.Event()
        original = self.module._open_resources

        def blocked(data_dir=None):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("resource initialization release timed out")
            return original(data_dir)

        self.module._open_resources = blocked
        plugin = self.Plugin(
            self.context, {"enabled": True, "capacity": 2, "timeout": 5}
        )
        self.plugins.append(plugin)
        initialize = asyncio.create_task(plugin.initialize())
        self.assertTrue(await asyncio.to_thread(entered.wait, 2))
        terminate = asyncio.create_task(plugin.terminate())
        await asyncio.sleep(0)
        release.set()
        try:
            await asyncio.wait_for(initialize, 2)
            await asyncio.wait_for(terminate, 2)
        finally:
            self.module._open_resources = original
        self.assertIsNone(plugin._app)
        self.assertTrue(plugin._closing)


if __name__ == "__main__":
    unittest.main()
