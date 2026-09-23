"""Pinned AstrBot SDK checks for the production Sylanne entry point."""

from __future__ import annotations

import asyncio
import importlib
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import AsyncMock, patch

from astrbot.api.star import Context, Star
from astrbot.core.star.filter.event_message_type import EventMessageTypeFilter
from astrbot.core.star.star_handler import star_handlers_registry

ROOT = Path(os.environ.get("SYLANNE3_PLUGIN_ROOT", Path(__file__).resolve().parents[2])).resolve()
MODULE = "data.plugins.sylanne3_acceptance.main"


def load_plugin_module():
    for name in ("data", "data.plugins", "data.plugins.sylanne3_acceptance"):
        package = sys.modules.get(name)
        if package is None:
            package = types.ModuleType(name)
            package.__package__ = name
            sys.modules[name] = package
        package.__path__ = [str(ROOT)]
    sys.modules.pop(MODULE, None)
    return importlib.import_module(MODULE)


class ControlledEvent:
    def __init__(self):
        self.stopped = False

    def stop_event(self):
        self.stopped = True


class AstrBotAdapterTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_plugin_module()
        cls.Plugin = cls.module.Sylanne3Plugin
        if not issubclass(cls.Plugin, Star):
            raise AssertionError("root entry must expose an AstrBot Star subclass")

    def setUp(self):
        context = Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None)
        self.plugin = self.Plugin(context, {})

    async def test_production_ingress_is_registered_with_astrbot_sdk(self):
        handlers = [
            item for item in star_handlers_registry
            if item.handler_module_path == MODULE and item.handler_name == "ingress"
        ]
        self.assertEqual(len(handlers), 1)
        self.assertTrue(any(isinstance(item, EventMessageTypeFilter) for item in handlers[0].event_filters))

    async def test_disabled_default_does_not_claim_ingress(self):
        await self.plugin.initialize()
        self.assertEqual(self.plugin.runtime_health.status, "limited")
        self.assertEqual(self.plugin.runtime_health.missing_capabilities, ("disabled",))
        event = ControlledEvent()
        await self.plugin.ingress(event)
        self.assertFalse(event.stopped)
        await self.plugin.terminate()
        self.assertEqual(self.plugin.runtime_health.status, "stopped")

    async def test_invalid_configuration_blocks_startup(self):
        plugin = self.Plugin(self.plugin.context, {"enabled": "yes"})
        await plugin.initialize()
        self.assertEqual(plugin.runtime_health.status, "blocked")
        self.assertIn("configuration", plugin.runtime_health.missing_capabilities)
        event = ControlledEvent()
        await plugin.ingress(event)
        self.assertFalse(event.stopped)

    async def test_missing_administrator_profile_requires_enrollment(self):
        plugin = self.Plugin(self.plugin.context, {"enabled": True})
        with patch.object(self.module, "build_admin_authority_transport", side_effect=FileNotFoundError):
            await plugin.initialize()
        self.assertEqual(plugin.runtime_health.status, "enrollment_required")
        event = ControlledEvent()
        await plugin.ingress(event)
        self.assertFalse(event.stopped)

    async def test_ready_ingress_claims_only_accepted_runtime_receipts(self):
        runtime = types.SimpleNamespace(handle_ingress=AsyncMock())
        self.plugin._runtime = runtime
        self.plugin.runtime_health = self.module.RuntimeHealth("ready")
        event = ControlledEvent()
        with patch.object(self.module, "build_astrbot_ingress", new_callable=AsyncMock) as build:
            build.return_value = object()
            runtime.handle_ingress.return_value = types.SimpleNamespace(status="accepted")
            await self.plugin.ingress(event)
            self.assertTrue(event.stopped)
            runtime.handle_ingress.assert_awaited_once_with(build.return_value)

            runtime.handle_ingress.return_value = types.SimpleNamespace(status="rejected")
            rejected = ControlledEvent()
            await self.plugin.ingress(rejected)
            self.assertFalse(rejected.stopped)

            build.side_effect = self.module.AstrBotIngressError("invalid host identity")
            malformed = ControlledEvent()
            await self.plugin.ingress(malformed)
            self.assertFalse(malformed.stopped)


if __name__ == "__main__":
    unittest.main()
