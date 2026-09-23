from __future__ import annotations

import json
import hashlib
import time

from astrbot.api.event import AstrMessageEvent
from astrbot.api.message_components import Plain
from astrbot.api.platform import MessageType

from ..runtime_contracts import NamespaceId
from .ingress import HostIngressEnvelope, SourceLineage


class AstrBotIngressError(ValueError):
    pass


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value == "[%None]":
        raise AstrBotIngressError(f"missing {label}")
    return value


def _canonical(*values: str) -> str:
    return json.dumps(values, ensure_ascii=True, separators=(",", ":"))


async def build_astrbot_ingress(event: AstrMessageEvent, context) -> HostIngressEnvelope:
    if not isinstance(event, AstrMessageEvent):
        raise TypeError("event must be AstrMessageEvent")
    umo = _id(event.unified_msg_origin, "unified message origin")
    platform_id = _id(event.get_platform_id(), "platform id")
    self_id = _id(event.get_self_id(), "self id")
    sender_id = _id(event.get_sender_id(), "sender id")
    platform_name = _id(event.get_platform_name(), "platform name")
    conversation_id = _id(
        await context.conversation_manager.get_curr_conversation_id(umo),
        "conversation id",
    )
    conversation = await context.conversation_manager.get_conversation(
        umo, conversation_id, create_if_not_exists=False
    )
    if conversation is None:
        raise AstrBotIngressError("conversation is absent")
    selected = await context.persona_manager.resolve_selected_persona(
        umo=umo,
        conversation_persona_id=getattr(conversation, "persona_id", None),
        platform_name=platform_name,
        provider_settings=context.get_config(umo),
    )
    persona_id = _id(selected[0], "effective persona id")
    if await context.conversation_manager.get_curr_conversation_id(umo) != conversation_id:
        raise AstrBotIngressError("conversation ownership changed")
    message = event.message_obj
    message_id = _id(getattr(message, "message_id", None), "message id")
    occurred_at = getattr(message, "timestamp", None)
    if isinstance(occurred_at, bool) or not isinstance(occurred_at, (int, float)):
        raise AstrBotIngressError("source timestamp is invalid")
    components = tuple(getattr(message, "message", ()) or ())
    if any(not isinstance(component, Plain) for component in components):
        raise AstrBotIngressError("media ingress is unavailable until source-bound attachment support exists")
    text = event.get_message_str()
    if not isinstance(text, str) or not text:
        raise AstrBotIngressError("empty or non-text ingress is unavailable")
    message_type = getattr(message, "type", None)
    visibility = (
        "private" if message_type == MessageType.FRIEND_MESSAGE else
        "group" if message_type == MessageType.GROUP_MESSAGE else "other"
    )
    learned_at = time.time()
    known_occurred_at = float(occurred_at)
    if not known_occurred_at > 0 or known_occurred_at > learned_at:
        known_occurred_at = None
    namespace = NamespaceId(_canonical(platform_id, self_id), persona_id)
    platform_ref = _canonical(platform_id, platform_name, self_id)
    conversation_ref = _canonical(umo, conversation_id)
    sender_ref = _canonical(platform_id, sender_id)
    source_identity = _canonical(
        namespace.bot_id, namespace.persona_id, platform_ref,
        conversation_ref, sender_ref, message_id,
    )
    lineage = SourceLineage(
        source_ref=hashlib.sha256(source_identity.encode("utf-8")).hexdigest(),
        source_kind="reported",
        provenance_family=platform_ref,
        content_reality="external_report",
        evidence_eligibility="reported_claim",
    )
    return HostIngressEnvelope(
        namespace=namespace,
        platform_ref=platform_ref,
        conversation_ref=conversation_ref,
        sender_ref=sender_ref,
        message_id=message_id,
        text=text,
        occurred_at=known_occurred_at,
        learned_at=learned_at,
        visibility=visibility,
        lineage=lineage,
    )
