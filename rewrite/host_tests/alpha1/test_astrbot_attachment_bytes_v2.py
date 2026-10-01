"""Staged media byte verification; product ingress remains closed."""

import base64
import hashlib
from types import SimpleNamespace

import pytest
from astrbot.api.event import AstrMessageEvent
from astrbot.api.message_components import File, Image, Plain
from astrbot.api.platform import AstrBotMessage, MessageMember, MessageType, PlatformMetadata

from sylanne3.host.astrbot import (
    AstrBotIngressError, build_astrbot_ingress, resolve_astrbot_attachment_bytes,
)
from sylanne3.domains.d06.attachment_contract_v2 import MAX_ATTACHMENT_BYTES
from sylanne3.host.authority_profile import AdminD06PrivateReplySourcePolicy
from sylanne3.host.d06_ingress import source_admission_from_host
from sylanne3.host.v2_ingress_adapter import VerifiedMediaIngressV2, ingress_host_facts


PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/"
    "lZkAAAAASUVORK5CYII="
)


def test_embedded_image_bytes_are_bounded_ordered_and_hashed():
    result = resolve_astrbot_attachment_bytes((Plain("caption"), Image.fromBytes(PNG_1X1)))
    assert len(result) == 1
    assert (result[0].order, result[0].media_kind, result[0].mime_type) == (
        0, "image", "image/png",
    )
    assert result[0].content == PNG_1X1
    assert result[0].sha256 == hashlib.sha256(PNG_1X1).hexdigest()


def test_url_only_media_is_not_claimed_as_read():
    with pytest.raises(AstrBotIngressError, match="URL-only"):
        resolve_astrbot_attachment_bytes((Image.fromURL("https://example.invalid/a.png"),))


def test_embedded_image_bytes_take_precedence_over_remote_url():
    component = Image(
        file="base64://" + base64.b64encode(PNG_1X1).decode("ascii"),
        url="https://example.invalid/preview.png",
    )
    assert resolve_astrbot_attachment_bytes((component,))[0].content == PNG_1X1


def test_local_file_read_is_capped_and_requires_trusted_root(tmp_path):
    path = tmp_path / "attachment.bin"
    path.write_bytes(b"x" * (MAX_ATTACHMENT_BYTES + 1))
    component = File("attachment.bin", file=str(path))
    with pytest.raises(AstrBotIngressError, match="trusted roots"):
        resolve_astrbot_attachment_bytes((component,))
    with pytest.raises(AstrBotIngressError, match="byte limit"):
        resolve_astrbot_attachment_bytes((component,), trusted_roots=(tmp_path,))


class _Event(AstrMessageEvent):
    def __init__(self, components):
        message = AstrBotMessage()
        message.type = MessageType.FRIEND_MESSAGE
        message.self_id = "bot-1"
        message.session_id = "session-1"
        message.message_id = "message-1"
        message.sender = MessageMember("sender-1", "Sender")
        message.message = components
        message.message_str = "host placeholder"
        message.raw_message = {}
        message.timestamp = 10
        super().__init__(
            "host placeholder", message,
            PlatformMetadata("controlled", "controlled", "adapter-1"),
            "session-1",
        )


class _Context:
    conversation_manager = SimpleNamespace(
        get_curr_conversation_id=None, get_conversation=None,
    )
    persona_manager = SimpleNamespace(resolve_selected_persona=None)

    def __init__(self):
        async def conversation_id(_):
            return "conversation-1"

        async def conversation(*_, **__):
            return SimpleNamespace(persona_id="persona-1")

        async def persona(**_):
            return "persona-1", {}, None, False

        self.conversation_manager = SimpleNamespace(
            get_curr_conversation_id=conversation_id, get_conversation=conversation,
        )
        self.persona_manager = SimpleNamespace(resolve_selected_persona=persona)

    def get_config(self, _):
        return {}


@pytest.mark.asyncio
async def test_captioned_media_builds_source_bound_installed_ingress():
    envelope = await build_astrbot_ingress(
        _Event([Plain("caption"), Image.fromBytes(PNG_1X1)]), _Context(),
    )
    assert envelope.text == "caption"
    media = ingress_host_facts(envelope)
    assert isinstance(media, VerifiedMediaIngressV2)
    assert media.host.lineage.source_ref == envelope.lineage.source_ref
    assert media.source_admission_v2.source.source_id == envelope.lineage.source_ref
    assert media.source_admission_v2.attachments == envelope.attachments
    assert media.source_admission_v2.content_fingerprint
    assert media.source_admission_v2.source.purposes == ("context", "consolidation")
    with pytest.raises(ValueError, match="atomic D06 v2"):
        source_admission_from_host(envelope)


@pytest.mark.asyncio
async def test_captioned_private_media_carries_installed_expression_policy():
    envelope = await build_astrbot_ingress(
        _Event([Plain("caption"), Image.fromBytes(PNG_1X1)]), _Context(),
    )
    policy = AdminD06PrivateReplySourcePolicy(1, "private_conversation", True)
    media = ingress_host_facts(envelope, reply_source_policy=policy)
    assert isinstance(media, VerifiedMediaIngressV2)
    assert media.source_admission_v2.source.purposes == (
        "context", "consolidation", "expression",
    )
    assert media.source_admission_v2.source == source_admission_from_host(
        envelope, policy, allow_verified_media_v2=True,
    )


@pytest.mark.asyncio
async def test_media_without_plain_caption_holds_even_if_host_has_placeholder():
    with pytest.raises(AstrBotIngressError, match="captioned text"):
        await build_astrbot_ingress(_Event([Image.fromBytes(PNG_1X1)]), _Context())
