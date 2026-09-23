"""Pinned AstrBot SDK route checks; no live platform is contacted."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

from astrbot.api.star import Context
from astrbot.core.platform.message_session import MessageSession

from sylanne3.dispatch_runtime import (
    DispatchBlocked, DispatchRequest, DispatchUnavailable, HandoffStartReceipt,
    HandoffUncertain,
)
from sylanne3.host.astrbot_dispatch import AstrBotTextPlatformCapability, ResolvedTextPayload
from sylanne3.runtime_journal import RecoveryConstraintFootprint


TEXT = "你好，世界"
PAYLOAD = TEXT.encode("utf-8")
UMO = "platform-1:FriendMessage:123456"


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _request() -> DispatchRequest:
    return DispatchRequest(
        namespace="namespace-1", operation_id="operation-1", activity_id="activity-1",
        effect_id="effect-1", attempt_id="attempt-1", command_digest=_digest(b"command"),
        payload_ref="payload-1", payload_digest=_digest(PAYLOAD),
        platform_capability_ref="capability-1", required_check_refs=("check-1",),
        dispatch_generation=1, activation_generation=1, worker_fence=1,
        content_fence="fence-1", cancel_epoch=0,
        footprint=RecoveryConstraintFootprint("namespace-1", "activity-1", "effect-1"),
        proactive_contact=False,
    )


def _start() -> HandoffStartReceipt:
    return HandoffStartReceipt(
        "start-1", "permit-1", "operation-1", "effect-1", "capability-1",
        1, 1, 1, "fence-1", 0, False, None, None, None, None,
    )


class Resolver:
    def __init__(self):
        self.result = ResolvedTextPayload(PAYLOAD, "namespace-1", "platform-1", "bot-1", UMO)

    def resolve(self, payload_ref: str) -> ResolvedTextPayload:
        if payload_ref != "payload-1":
            raise KeyError(payload_ref)
        return self.result


class AstrBotTextDispatchTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.platform = SimpleNamespace(
            meta=lambda: SimpleNamespace(id="platform-1", name="aiocqhttp"),
            send_by_session=AsyncMock(return_value=None),
        )
        self.context = Context(
            asyncio.Queue(), {}, None, None,
            SimpleNamespace(platform_insts=[self.platform]), None, None, None,
            SimpleNamespace(get_conf=lambda umo: {}), None, None,
        )
        self.resolver = Resolver()
        self.capability = AstrBotTextPlatformCapability(
            self.context, self.loop, self.resolver, capability_ref="capability-1",
            namespace="namespace-1", platform_id="platform-1", self_id="bot-1",
            timeout_seconds=0.05,
        )

    async def test_real_sdk_message_chain_and_worker_handoff(self) -> None:
        result = await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.assertEqual(result.status, "handed_off")
        self.assertIsNone(result.provider_request_ref)
        session, chain = self.platform.send_by_session.await_args.args
        self.assertIsInstance(session, MessageSession)
        self.assertEqual(str(session), UMO)
        self.assertEqual(len(chain.chain), 1)
        self.assertEqual(chain.chain[0].text, TEXT)
        self.assertFalse(self.capability.descriptor.supports_query)

    async def test_digest_and_routing_fail_before_send(self) -> None:
        self.resolver.result = replace(self.resolver.result, payload=b"changed")
        with self.assertRaises(DispatchBlocked):
            await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.resolver.result = replace(self.resolver.result, payload=PAYLOAD, umo="other:FriendMessage:123456")
        with self.assertRaises(DispatchBlocked):
            await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.resolver.result = replace(self.resolver.result, umo=UMO, self_id="wrong-bot")
        with self.assertRaises(DispatchBlocked):
            await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.platform.send_by_session.assert_not_awaited()

    async def test_no_matching_platform_is_failed(self) -> None:
        self.context.platform_manager.platform_insts = []
        result = await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.assertEqual(result.status, "failed")
        self.assertIsNone(result.provider_request_ref)

    async def test_adapter_exception_and_timeout_are_unknown_without_retry(self) -> None:
        self.platform.send_by_session.side_effect = RuntimeError("provider unavailable")
        with self.assertRaises(HandoffUncertain):
            await asyncio.to_thread(self.capability.handoff, _request(), _start())
        with self.assertRaises(HandoffUncertain):
            await asyncio.to_thread(self.capability.handoff, _request(), _start())
        self.platform.send_by_session.assert_awaited_once()

        self.platform.send_by_session.reset_mock(side_effect=True)
        started = asyncio.Event()
        release = asyncio.Event()

        async def pending_send(*args):
            started.set()
            await release.wait()

        self.platform.send_by_session.side_effect = pending_send
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
        self.platform.send_by_session.assert_awaited_once()

    async def test_host_loop_cannot_synchronously_wait_on_itself(self) -> None:
        with self.assertRaises(DispatchUnavailable):
            self.capability.handoff(_request(), _start())
        self.platform.send_by_session.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
