"""Single-attempt AstrBot/OpenAI SDK calls through a local HTTP transport."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import threading
import unittest

from astrbot.api.star import Context
from astrbot.core.provider.entities import ProviderType
from astrbot.core.provider.sources.openai_source import ProviderOpenAIOfficial
import httpx
from openai import AsyncOpenAI

from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.host.astrbot_model_call import AstrBotModelProvider
from sylanne3.host.authority_profile import (
    AdminIngressModelPolicy, installed_model_config_ref,
)
from sylanne3.model_broker.broker import ModelCallRequest, ModelProviderDescriptor
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    QueryEpoch, SourceQualification, VersionGuard, canonical_digest,
)


UMO = "platform-1:FriendMessage:123456"


class Manager:
    def __init__(self, provider):
        self.provider_insts = [provider]
        self.inst_map = {"provider-1": provider}
        self.selected = provider
        self.seen_umo = []
        self.on_selection = None

    async def get_using_provider_async(self, *, provider_type, umo):
        assert provider_type is ProviderType.CHAT_COMPLETION
        self.seen_umo.append(umo)
        if self.on_selection is not None:
            self.on_selection(len(self.seen_umo))
        return self.selected


def call_request():
    namespace = NamespaceId("bot", "persona")
    key = AtomKey(Owner("persona", "bot", "persona"), "state", "model")
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity", None, "attempt", "propose", "operation",
                          canonical_digest({"input_refs": ["input"]})),
        AuthorityContext("actor", "d07", "cap", namespace, ("persona",),
                         "proposal", ("owner",), "policy", 1),
        VersionGuard((GraphVersion(key, 0),), (QueryEpoch(namespace, "all", 0),),
                     0, 0, "catalogue", "scheme", "operator", "policy", (), (), ()),
        SourceQualification(("source",), "reported", None, 1.0,
                            "external_report", "qualified", None, "actual"),
        ("input",), "budget", 2.0, 1.0, "clock", (),
    )
    return ModelCallRequest(
        envelope, "call", "provider-1", "model-1", frozenset({"text"}),
        "private", "a" * 64, {"prompt": "say hello"}, 0.2, 64,
    )


def successful_completion():
    return {
        "id": "remote-1", "object": "chat.completion", "created": 1,
        "model": "model-1", "choices": [{
            "index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": "hello"},
        }],
        "usage": {
            "prompt_tokens": 3, "completion_tokens": 3, "total_tokens": 6,
            "prompt_tokens_details": {"cached_tokens": 1},
        },
    }


class AstrBotModelCallTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.host_thread = threading.get_ident()
        self.requests = []
        self.status = 200
        self.transport_error = None
        self.completion = successful_completion()

        def respond(request):
            self.requests.append((threading.get_ident(), request))
            if self.transport_error is not None:
                raise self.transport_error
            if self.status != 200:
                return httpx.Response(self.status, json={"error": {"message": "test error"}})
            return httpx.Response(200, json=self.completion)

        self.http_client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
        self.shared_client = AsyncOpenAI(
            api_key="test-only", base_url="https://mock.invalid/v1",
            http_client=self.http_client, max_retries=2,
        )
        self.provider = object.__new__(ProviderOpenAIOfficial)
        self.provider.provider_config = {
            "id": "provider-1", "type": "openai_chat_completion", "model": "model-1",
        }
        self.provider.model_name = "model-1"
        self.provider.client = self.shared_client
        self.manager = Manager(self.provider)
        self.context = Context(
            asyncio.Queue(), {}, None, self.manager, None, None,
            None, None, None, None, None,
        )
        self.descriptor = ModelProviderDescriptor(
            "provider-1", "astrbot-4.28.1", "model-1",
            frozenset({"text"}), frozenset({"proposal"}),
            frozenset({"private"}), "credential:astrbot-installed",
            "unknown", False, False,
        )
        config_digest = canonical_digest(self.provider.provider_config)
        self.admin_model = AdminIngressModelPolicy(
            "provider-1", "model-1",
            installed_model_config_ref("provider-1", "model-1", config_digest),
            config_digest, 0.2, 64, ("text",), "private",
        )
        self.adapter = AstrBotModelProvider(
            context=self.context, host_loop=asyncio.get_running_loop(),
            trusted_umo=UMO, descriptor=self.descriptor,
            admin_model=self.admin_model,
        )

    async def asyncTearDown(self):
        await self.shared_client.close()

    async def invoke_on_worker(self, request=None):
        request = request or call_request()
        return await asyncio.to_thread(
            lambda: asyncio.run(self.adapter.invoke(request, asyncio.Event())))

    async def test_one_http_request_on_host_loop_with_usage(self):
        response = await self.invoke_on_worker()
        self.assertEqual(response.status, "completed")
        self.assertEqual(response.result, {"text": "hello"})
        self.assertEqual(response.usage, {
            "input_tokens": 3, "cached_input_tokens": 1, "output_tokens": 3,
        })
        self.assertEqual(response.provider_call_ref, "remote-1")
        self.assertEqual(self.manager.seen_umo, [UMO, UMO])
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.requests[0][0], self.host_thread)
        self.assertIn(b'"max_completion_tokens":64', self.requests[0][1].content)
        self.assertEqual(self.shared_client.max_retries, 2)

    async def test_500_429_and_timeout_each_make_one_request(self):
        for status in (500, 429):
            with self.subTest(status=status):
                self.requests.clear()
                self.status = status
                response = await self.invoke_on_worker()
                self.assertEqual(response.status, "unknown")
                self.assertEqual(len(self.requests), 1)
        self.requests.clear()
        self.status = 200
        self.transport_error = httpx.ReadTimeout("lost response")
        response = await self.invoke_on_worker()
        self.assertEqual(response.status, "unknown")
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.shared_client.max_retries, 2)

    async def test_selection_change_and_unsupported_provider_never_request(self):
        self.provider.model_name = "model-2"
        self.assertEqual((await self.invoke_on_worker()).status, "not_dispatched")
        self.provider.model_name = "model-1"
        self.manager.selected = None
        self.assertEqual((await self.invoke_on_worker()).status, "not_dispatched")
        self.manager.selected = self.provider
        self.provider.provider_config["api_version"] = "2025-01-01"
        self.assertEqual((await self.invoke_on_worker()).status, "not_dispatched")
        self.provider.provider_config.pop("api_version")
        self.assertEqual((await self.invoke_on_worker(
            replace(call_request(), payload={"prompt": "hello", "unexpected": True})
        )).status, "not_dispatched")
        self.assertEqual(self.requests, [])

    async def test_installed_config_drift_has_no_network_dispatch(self):
        self.provider.provider_config["temperature"] = 0.25
        response = await self.invoke_on_worker()
        self.assertEqual(response.status, "not_dispatched")
        self.assertEqual(self.requests, [])
        self.provider.provider_config.pop("temperature")
        self.assertEqual((await self.invoke_on_worker()).status, "completed")
        self.assertEqual(len(self.requests), 1)

    async def test_config_drift_after_first_selection_still_has_no_dispatch(self):
        def change_on_second_selection(number):
            if number == 2:
                self.provider.provider_config["temperature"] = 0.25

        self.manager.on_selection = change_on_second_selection
        response = await self.invoke_on_worker()
        self.assertEqual(response.status, "not_dispatched")
        self.assertEqual(self.manager.seen_umo, [UMO, UMO])
        self.assertEqual(self.requests, [])

    async def test_client_replacement_after_first_selection_has_no_dispatch(self):
        def replace_on_second_selection(number):
            if number == 2:
                self.provider.client = object.__new__(AsyncOpenAI)

        self.manager.on_selection = replace_on_second_selection
        response = await self.invoke_on_worker()
        self.assertEqual(response.status, "not_dispatched")
        self.assertEqual(self.requests, [])

    async def test_admin_timeout_and_token_ceilings_hold_before_dispatch(self):
        for request in (
            replace(call_request(), timeout_seconds=0.3),
            replace(call_request(), max_output_tokens=65),
        ):
            with self.subTest(request=request):
                self.assertEqual((await self.invoke_on_worker(request)).status,
                                 "not_dispatched")
        self.assertEqual(self.manager.seen_umo, [])
        self.assertEqual(self.requests, [])

    async def test_ambiguous_completion_is_unknown(self):
        self.completion["choices"] = [{
            "index": 0, "finish_reason": "tool_calls",
            "message": {"role": "assistant", "content": None, "tool_calls": []},
        }]
        self.assertEqual((await self.invoke_on_worker()).status, "unknown")
        self.assertEqual(len(self.requests), 1)


if __name__ == "__main__":
    unittest.main()
