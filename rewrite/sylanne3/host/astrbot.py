from __future__ import annotations

import json
import hashlib
import base64
import binascii
from pathlib import Path
import time
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

from astrbot.api.event import AstrMessageEvent
from astrbot.api.message_components import File, Image, Plain, Record, Video
from astrbot.api.platform import MessageType
from astrbot.core.utils.astrbot_path import get_astrbot_temp_path

from ..domains.d06.attachment_contract_v2 import (
    MAX_ATTACHMENT_BYTES, MAX_ATTACHMENTS, SourceAttachmentV2,
)
from .identity import astrbot_namespace
from .ingress import HostIngressEnvelope, SourceLineage


class AstrBotIngressError(ValueError):
    pass


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value == "[%None]":
        raise AstrBotIngressError(f"missing {label}")
    return value


def _canonical(*values: str) -> str:
    return json.dumps(values, ensure_ascii=True, separators=(",", ":"))


def _media_mime(data: bytes, kind: str) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        mime = "image/png"
    elif data.startswith(b"\xff\xd8\xff"):
        mime = "image/jpeg"
    elif data.startswith((b"GIF87a", b"GIF89a")):
        mime = "image/gif"
    elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        mime = "image/webp"
    elif data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        mime = "audio/wav"
    elif data.startswith(b"OggS"):
        mime = "audio/ogg"
    elif data.startswith(b"fLaC"):
        mime = "audio/flac"
    elif data.startswith(b"ID3") or data[:1] == b"\xff" and data[1:2] in (b"\xfb", b"\xf3", b"\xf2"):
        mime = "audio/mpeg"
    elif data[4:8] == b"ftyp":
        mime = "video/mp4"
    elif data.startswith(b"\x1a\x45\xdf\xa3"):
        mime = "video/webm"
    else:
        mime = "application/octet-stream"
    if kind != "file" and not mime.startswith(kind + "/"):
        raise AstrBotIngressError("media bytes do not match the component kind")
    return mime


def _verified_media_bytes(source: str, trusted_roots: tuple[Path, ...]) -> bytes:
    if source.startswith("base64://"):
        encoded = source[len("base64://"):]
    elif source.startswith("data:"):
        header, marker, encoded = source.partition(",")
        if not marker or not header.endswith(";base64"):
            raise AstrBotIngressError("unsupported media data URI")
    else:
        encoded = None
    if encoded is not None:
        if len(encoded) > ((MAX_ATTACHMENT_BYTES + 2) // 3) * 4 + 4:
            raise AstrBotIngressError("media attachment exceeds byte limit")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AstrBotIngressError("invalid media base64") from exc
    else:
        parsed = urlsplit(source)
        if parsed.scheme in {"http", "https"}:
            raise AstrBotIngressError("URL-only media has no verified bytes")
        if parsed.scheme == "file":
            path = Path(url2pathname(unquote(parsed.path)))
        elif parsed.scheme and not (len(parsed.scheme) == 1 and source[1:3] in {":\\", ":/"}):
            raise AstrBotIngressError("unsupported media source")
        else:
            path = Path(source)
        path = path.resolve()
        if not any(path.is_relative_to(root.resolve()) for root in trusted_roots):
            raise AstrBotIngressError("media path is outside trusted roots")
        if not path.is_file() or path.stat().st_size > MAX_ATTACHMENT_BYTES:
            raise AstrBotIngressError("media attachment is absent or exceeds byte limit")
        with path.open("rb") as handle:
            data = handle.read(MAX_ATTACHMENT_BYTES + 1)
    if not data or len(data) > MAX_ATTACHMENT_BYTES:
        raise AstrBotIngressError("media attachment is absent or exceeds byte limit")
    return data


def resolve_astrbot_attachment_bytes(
    components: tuple[object, ...], *, trusted_roots: tuple[Path, ...] = (),
) -> tuple[SourceAttachmentV2, ...]:
    """Verify bounded embedded/local bytes; this does not authorize ingress.

    Remote URLs are deliberately not fetched. The caller must provide trusted
    local roots for path-backed components and still needs an atomic D06 v2
    graph/blob commit before these values may enter the product path.
    """
    attachments: list[SourceAttachmentV2] = []
    for component in components:
        if isinstance(component, Plain):
            continue
        if len(attachments) >= MAX_ATTACHMENTS:
            raise AstrBotIngressError("too many media attachments")
        if isinstance(component, Image):
            kind, source = "image", component.file or component.url
        elif isinstance(component, Record):
            kind, source = "audio", component.file or component.url or component.path
        elif isinstance(component, Video):
            kind, source = "video", component.file or component.url or component.path
        elif isinstance(component, File):
            kind, source = "file", component.file_
        else:
            raise AstrBotIngressError("unsupported message component")
        if not isinstance(source, str) or not source:
            raise AstrBotIngressError("media component has no verified byte source")
        data = _verified_media_bytes(source, trusted_roots)
        attachments.append(SourceAttachmentV2(
            len(attachments), kind, _media_mime(data, kind), data,
            hashlib.sha256(data).hexdigest(),
        ))
    return tuple(attachments)


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
    attachments = (
        resolve_astrbot_attachment_bytes(
            components, trusted_roots=(Path(get_astrbot_temp_path()),),
        ) if any(not isinstance(component, Plain) for component in components)
        else ()
    )
    text = (
        "".join(component.text for component in components if isinstance(component, Plain))
        if attachments else event.get_message_str()
    )
    if not isinstance(text, str) or not text:
        raise AstrBotIngressError("captioned text is required for ingress")
    if attachments and not text.strip():
        raise AstrBotIngressError("captioned text is required for media ingress")
    message_type = getattr(message, "type", None)
    visibility = (
        "private" if message_type == MessageType.FRIEND_MESSAGE else
        "group" if message_type == MessageType.GROUP_MESSAGE else "other"
    )
    learned_at = time.time()
    known_occurred_at = float(occurred_at)
    if not known_occurred_at > 0 or known_occurred_at > learned_at:
        known_occurred_at = None
    namespace = astrbot_namespace(platform_id, self_id, persona_id)
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
        attachments=attachments,
    )
