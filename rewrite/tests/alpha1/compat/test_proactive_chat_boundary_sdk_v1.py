"""Offline compatibility prerequisites against real AstrBot SDK interfaces.

These tests intentionally exercise Context.send_message with a minimal in-memory
platform implementation; no peer private method, real adapter, registry mutation,
network, model, database, or caller-supplied ownership flag is involved. Passing
proves SDK boundary semantics, NOT exclusive ownership or integrated sender safety.
"""
import asyncio
from types import SimpleNamespace

import pytest

from astrbot.api.star import Context
from astrbot.core.message.components import Plain, Record
from astrbot.core.message.message_event_result import MessageChain
from astrbot.core.platform.message_session import MessageSession


class OfflinePlatform:
    def __init__(self, platform_id="platform-1", error=None):
        self.platform_id = platform_id
        self.error = error
        self.calls = []

    def meta(self):
        return SimpleNamespace(id=self.platform_id, name="aiocqhttp")

    async def send_by_session(self, session, chain):
        self.calls.append((session, chain))
        if self.error is not None:
            raise self.error
        # Real Context ignores the platform's result. This is not delivery proof.
        return None


def context_for(*platforms):
    return SimpleNamespace(
        platform_manager=SimpleNamespace(platform_insts=list(platforms)),
        get_config=lambda **kwargs: {},
    )


@pytest.mark.parametrize("umo", [
    "platform-1:FriendMessage:123", "platform-1:GroupMessage:123",
    "platform-2:FriendMessage:123",
])
def test_session_identity_preserves_platform_type_and_target(umo):
    assert str(MessageSession.from_str(umo)) == umo


@pytest.mark.parametrize("umo", ["123", "platform-1:friend:123", "platform-1::123"])
def test_invalid_standard_session_refuses_before_platform_call(umo):
    platform = OfflinePlatform()
    with pytest.raises(ValueError):
        asyncio.run(Context.send_message(context_for(platform), umo, MessageChain()))
    assert platform.calls == []


def test_context_true_is_platform_match_not_delivery_receipt():
    platform = OfflinePlatform()
    chain = MessageChain([Plain(text="synthetic offline fixture")])
    result = asyncio.run(Context.send_message(
        context_for(platform), "platform-1:FriendMessage:123", chain))
    assert result is True
    assert len(platform.calls) == 1
    assert platform.calls[0][1] is chain
    # No hook registry, event, delivery receipt or ownership service was supplied.
    # The real SDK sends anyway: decorating is not a universal send interception.


def test_missing_platform_returns_false_without_send():
    platform = OfflinePlatform("other-platform")
    assert asyncio.run(Context.send_message(
        context_for(platform), "platform-1:FriendMessage:123", MessageChain())) is False
    assert platform.calls == []


def test_media_only_chain_reaches_standard_interface_intact():
    platform = OfflinePlatform()
    voice = Record(file="offline-unopened-voice-fixture")
    chain = MessageChain([voice])
    assert asyncio.run(Context.send_message(
        context_for(platform), "platform-1:FriendMessage:123", chain)) is True
    assert platform.calls[0][1].chain == [voice]
    assert platform.calls[0][1].chain[0] is voice


def test_uncertain_adapter_exception_propagates_without_sdk_retry():
    platform = OfflinePlatform(error=TimeoutError("synthetic uncertain outcome"))
    with pytest.raises(TimeoutError, match="synthetic uncertain"):
        asyncio.run(Context.send_message(
            context_for(platform), "platform-1:FriendMessage:123", MessageChain()))
    assert len(platform.calls) == 1


def test_duplicate_platform_identity_is_not_rejected_by_standard_send():
    first, second = OfflinePlatform(), OfflinePlatform()
    assert asyncio.run(Context.send_message(
        context_for(first, second), "platform-1:FriendMessage:123", MessageChain())) is True
    assert len(first.calls) == 1 and second.calls == []
    # Sylanne must retain its stricter unique-current-adapter check.


def test_standard_session_parser_does_not_validate_onebot_target():
    assert MessageSession.from_str("platform-1:FriendMessage:123::agent:x").session_id == "123::agent:x"
    assert MessageSession.from_str("platform-1:FriendMessage:１２３").session_id == "１２３"
    # Sylanne must retain exact original UMO plus ASCII numeric OneBot target checks.
