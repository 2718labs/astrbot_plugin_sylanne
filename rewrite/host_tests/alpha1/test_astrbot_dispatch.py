"""Pinned AstrBot SDK route checks; no live platform is contacted."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, call

from astrbot.api.star import Context
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_platform_adapter import AiocqhttpAdapter

from sylanne3.dispatch_runtime import (
    DispatchBlocked, DispatchRequest, DispatchUnavailable, HandoffStartReceipt,
    HandoffUncertain,
)
from sylanne3.domains.d09 import ClaimKind, ClaimUse, segment_payload_digest
from sylanne3.host.astrbot_dispatch import (
    AstrBotTextPlatformCapability, GraphTextPayloadResolver, ResolvedTextPayload,
)
from sylanne3.host.identity import astrbot_namespace
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.runtime_journal import RecoveryConstraintFootprint


TEXT = "你好，世界"
PAYLOAD = TEXT.encode("utf-8")
UMO = "platform-1:FriendMessage:123456"
NAMESPACE_ID = astrbot_namespace("platform-1", "bot-1", "persona-1")
NAMESPACE = "/".join(NAMESPACE_ID.as_tuple)
PLATFORM_REF = json.dumps(["platform-1", "aiocqhttp", "bot-1"], separators=(",", ":"))
CONVERSATION_REF = json.dumps([UMO, "conversation-1"], separators=(",", ":"))
SCENE_REF = scene_ref_for_conversation(NAMESPACE_ID, PLATFORM_REF, CONVERSATION_REF)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _request() -> DispatchRequest:
    return DispatchRequest(
        namespace=NAMESPACE, operation_id="operation-1", activity_id="activity-1",
        effect_id="effect-1", attempt_id="attempt-1", command_digest=_digest(b"command"),
        payload_ref="payload-1", payload_digest=segment_payload_digest(TEXT, (), ()),
        platform_capability_ref="capability-1", required_check_refs=("check-1",),
        dispatch_generation=1, activation_generation=1, worker_fence=1,
        content_fence="fence-1", cancel_epoch=0,
        footprint=RecoveryConstraintFootprint(NAMESPACE, "activity-1", "effect-1"),
        proactive_contact=False,
    )


def _start() -> HandoffStartReceipt:
    return HandoffStartReceipt(
        "start-1", "permit-1", "operation-1", "effect-1", "capability-1",
        1, 1, 1, "fence-1", 0, False, None, None, None, None,
    )


class Resolver:
    def __init__(self):
        self.result = ResolvedTextPayload(
            PAYLOAD, (), (), NAMESPACE, "platform-1", "aiocqhttp", "bot-1",
            UMO, "conversation-1", SCENE_REF,
        )

    def resolve(self, request: DispatchRequest) -> ResolvedTextPayload:
        if request.payload_ref != "payload-1":
            raise KeyError(request.payload_ref)
        return self.result


def test_graph_resolver_passes_complete_command_to_fenced_reader() -> None:
    class Coordinator:
        def get_dispatch_text_segment(self, authority, lease, request):
            assert (authority, lease, request) == ("authority", "lease", command)
            return SimpleNamespace(body=TEXT, media_refs=(), claim_uses=(),
                                   platform_id="platform-1", platform_name="aiocqhttp",
                                   self_id="bot-1", umo=UMO, conversation_id="conversation-1",
                                   scene_ref=SCENE_REF)

    command = _request()
    resolved = GraphTextPayloadResolver(Coordinator(), "authority", "lease").resolve(command)
    assert resolved.payload == PAYLOAD and resolved.umo == UMO and resolved.scene_ref == SCENE_REF


class AstrBotTextDispatchTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.platform = AiocqhttpAdapter(
            {"id": "platform-1", "ws_reverse_host": "127.0.0.1", "ws_reverse_port": 6199},
            {}, asyncio.Queue(),
        )
        self.platform.bot.call_action = AsyncMock(side_effect=lambda action, **kwargs:
            {"user_id": "bot-1"} if action == "get_login_info" else {"message_id": 1})
        self.conversations = SimpleNamespace(
            get_curr_conversation_id=AsyncMock(return_value="conversation-1"),
            get_conversation=AsyncMock(return_value=SimpleNamespace(persona_id="persona-1")),
        )
        self.personas = SimpleNamespace(
            resolve_selected_persona=AsyncMock(return_value=("persona-1", {}, None, False)),
        )
        self.context = Context(
            asyncio.Queue(), {}, None, None,
            SimpleNamespace(platform_insts=[self.platform]), self.conversations, None, self.personas,
            SimpleNamespace(get_conf=lambda umo: {}), None, None,
        )
        self.resolver = Resolver()
        self.capability = AstrBotTextPlatformCapability(
            self.context, self.loop, self.resolver, capability_ref="capability-1",
            namespace=NAMESPACE, platform_id="platform-1", self_id="bot-1",
            timeout_seconds=0.05,
        )

    async def test_private_handoff_revalidates_and_routes_to_bound_account(self) -> None:
        result = await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.assertEqual(result.status, "handed_off")
        self.assertIsNone(result.provider_request_ref)
        self.platform.bot.call_action.assert_has_awaits([
            call("get_login_info", self_id="bot-1"),
            call("send_private_msg", self_id="bot-1", user_id=123456,
                 message=[{"type": "text", "data": {"text": TEXT}}]),
        ])
        with self.assertRaises(HandoffUncertain):
            await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.assertEqual(self.platform.bot.call_action.await_count, 2)
        self.assertFalse(self.capability.descriptor.supports_query)

    async def test_digest_and_routing_fail_before_send(self) -> None:
        self.resolver.result = replace(self.resolver.result, payload=b"changed")
        with self.assertRaises(DispatchBlocked):
            await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.resolver.result = replace(self.resolver.result, payload=PAYLOAD,
                                       claim_uses=(ClaimUse("claim:1", 0, 2, ClaimKind.RHETORIC),))
        with self.assertRaises(DispatchBlocked):
            await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.resolver.result = replace(self.resolver.result, claim_uses=(), media_refs=("media:1",))
        with self.assertRaises(DispatchBlocked):
            await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.resolver.result = replace(self.resolver.result, media_refs=(), claim_uses=[])  # type: ignore[arg-type]
        with self.assertRaises(DispatchBlocked):
            await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.resolver.result = replace(self.resolver.result, payload=PAYLOAD, umo="other:FriendMessage:123456")
        with self.assertRaises(DispatchBlocked):
            await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.resolver.result = replace(self.resolver.result, umo=UMO, self_id="wrong-bot")
        with self.assertRaises(DispatchBlocked):
            await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.platform.bot.call_action.assert_not_awaited()

    async def test_claim_qualified_text_uses_d09_digest_and_sends_original_body(self) -> None:
        use = ClaimUse("claim:1", 0, len(TEXT), ClaimKind.RHETORIC)
        self.resolver.result = replace(self.resolver.result, claim_uses=(use,))
        request = replace(_request(), payload_digest=segment_payload_digest(TEXT, (), (use,)))
        result = await asyncio.to_thread(self.capability.handoff, request, _start())
        self.assertEqual(result.status, "handed_off")
        self.assertEqual(self.platform.bot.call_action.await_args_list[-1].kwargs["message"][0]["data"]["text"], TEXT)

    async def test_group_handoff_routes_to_original_group_with_explicit_account(self) -> None:
        group_umo = "platform-1:GroupMessage:456789"
        group_ref = json.dumps([group_umo, "conversation-1"], separators=(",", ":"))
        self.resolver.result = replace(
            self.resolver.result, umo=group_umo,
            scene_ref=scene_ref_for_conversation(NAMESPACE_ID, PLATFORM_REF, group_ref),
        )
        result = await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.assertEqual(result.status, "handed_off")
        self.platform.bot.call_action.assert_has_awaits([
            call("get_login_info", self_id="bot-1"),
            call("send_group_msg", self_id="bot-1", group_id=456789,
                 message=[{"type": "text", "data": {"text": TEXT}}]),
        ])

    async def test_non_message_or_non_numeric_onebot_route_is_blocked_before_account_probe(self) -> None:
        for umo in ("platform-1:OtherMessage:123456", "platform-1:FriendMessage:not-a-qq"):
            self.resolver.result = replace(self.resolver.result, umo=umo)
            with self.subTest(umo=umo), self.assertRaises(DispatchBlocked):
                await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.platform.bot.call_action.assert_not_awaited()

    async def test_wrong_current_account_blocks_before_send(self) -> None:
        self.platform.bot.call_action.side_effect = lambda action, **kwargs: {"user_id": "other-bot"}
        result = await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.assertEqual(result.status, "failed")
        self.platform.bot.call_action.assert_awaited_once_with("get_login_info", self_id="bot-1")

    async def test_changed_conversation_or_persona_blocks_before_send(self) -> None:
        self.conversations.get_curr_conversation_id.return_value = "conversation-2"
        result = await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.assertEqual(result.status, "failed")
        self.platform.bot.call_action.assert_awaited_once_with("get_login_info", self_id="bot-1")

        self.platform.bot.call_action.reset_mock()
        self.conversations.get_curr_conversation_id.return_value = "conversation-1"
        self.personas.resolve_selected_persona.return_value = ("persona-2", {}, None, False)
        second = replace(_request(), operation_id="operation-2")
        second_start = replace(_start(), operation_id="operation-2")
        result = await asyncio.to_thread(self.capability.handoff, second, second_start)
        self.assertEqual(result.status, "failed")
        self.platform.bot.call_action.assert_awaited_once_with("get_login_info", self_id="bot-1")

    async def test_missing_or_invalid_send_receipt_is_unknown_without_retry(self) -> None:
        for index, receipt in enumerate((None, {}, {"message_id": 0}, {"message_id": True})):
            self.platform.bot.call_action.reset_mock()
            self.platform.bot.call_action.side_effect = lambda action, **kwargs: (
                {"user_id": "bot-1"} if action == "get_login_info" else receipt
            )
            request = replace(_request(), operation_id=f"operation-receipt-{index}")
            start = replace(_start(), operation_id=request.operation_id)
            with self.subTest(receipt=receipt), self.assertRaises(HandoffUncertain):
                await asyncio.to_thread(self.capability.handoff, request, start)
            self.assertEqual(self.platform.bot.call_action.await_count, 2)
            with self.assertRaises(HandoffUncertain):
                await asyncio.to_thread(self.capability.handoff, request, start)
            self.assertEqual(self.platform.bot.call_action.await_count, 2)

    async def test_reconnected_adapter_revalidates_account_for_each_operation(self) -> None:
        first = self.platform
        await asyncio.to_thread(self.capability.handoff, _request(), _start())
        replacement = AiocqhttpAdapter(
            {"id": "platform-1", "ws_reverse_host": "127.0.0.1", "ws_reverse_port": 6199},
            {}, asyncio.Queue(),
        )
        replacement.bot.call_action = AsyncMock(side_effect=lambda action, **kwargs:
            {"user_id": "bot-1"} if action == "get_login_info" else {"message_id": 2})
        self.context.platform_manager.platform_insts = [replacement]
        second = replace(_request(), operation_id="operation-2")
        second_start = replace(_start(), operation_id="operation-2")
        result = await asyncio.to_thread(self.capability.handoff, second, second_start)
        self.assertEqual(result.status, "handed_off")
        first.bot.call_action.assert_any_await("get_login_info", self_id="bot-1")
        replacement.bot.call_action.assert_any_await("get_login_info", self_id="bot-1")
        self.assertEqual(first.bot.call_action.await_count, 2)
        self.assertEqual(replacement.bot.call_action.await_count, 2)

    async def test_no_matching_platform_is_failed(self) -> None:
        self.context.platform_manager.platform_insts = []
        result = await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.assertEqual(result.status, "failed")
        self.assertIsNone(result.provider_request_ref)

    async def test_unsupported_or_duplicate_adapter_does_not_send(self) -> None:
        self.context.platform_manager.platform_insts = [SimpleNamespace(
            meta=lambda: SimpleNamespace(id="platform-1", name="other"),
        )]
        result = await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.assertEqual(result.status, "failed")
        self.platform.bot.call_action.assert_not_awaited()

        self.context.platform_manager.platform_insts = [self.platform, self.platform]
        second = replace(_request(), operation_id="operation-2")
        second_start = replace(_start(), operation_id="operation-2")
        result = await asyncio.to_thread(self.capability.handoff, second, second_start)
        self.assertEqual(result.status, "failed")
        self.platform.bot.call_action.assert_not_awaited()

    async def test_adapter_exception_and_timeout_are_unknown_without_retry(self) -> None:
        async def failing_send(action, **kwargs):
            if action == "get_login_info":
                return {"user_id": "bot-1"}
            raise RuntimeError("provider unavailable")

        self.platform.bot.call_action.side_effect = failing_send
        with self.assertRaises(HandoffUncertain):
            await asyncio.to_thread(self.capability.handoff, _request(), _start())
        with self.assertRaises(HandoffUncertain):
            await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.assertEqual(self.platform.bot.call_action.await_count, 2)

        self.platform.bot.call_action.reset_mock(side_effect=True)
        started = asyncio.Event()
        release = asyncio.Event()

        async def pending_send(action, **kwargs):
            if action == "get_login_info":
                return {"user_id": "bot-1"}
            started.set()
            await release.wait()

        self.platform.bot.call_action.side_effect = pending_send
        second = replace(_request(), operation_id="operation-2")
        second_start = replace(_start(), operation_id="operation-2")
        task = asyncio.create_task(asyncio.to_thread(self.capability.handoff, second, second_start))
        await asyncio.wait_for(started.wait(), timeout=1)
        with self.assertRaises(HandoffUncertain):
            await task
        release.set()
        await asyncio.sleep(0)
        with self.assertRaises(HandoffUncertain):
            await asyncio.to_thread(self.capability.handoff, second, second_start)
        self.assertEqual(self.platform.bot.call_action.await_count, 2)

    async def test_host_loop_cannot_synchronously_wait_on_itself(self) -> None:
        with self.assertRaises(DispatchUnavailable):
            self.capability.handoff(_request(), _start())
        self.platform.bot.call_action.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
