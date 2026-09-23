"""Read-only current AstrBot scene proof for a recent Owner candidate.

This checks host identity at observation time. It does not authorize a D03
binding, create conversations, or grant a platform send capability.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from astrbot.api.platform import MessageType
from astrbot.core.platform.message_session import MessageSession
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_platform_adapter import AiocqhttpAdapter

from ..runtime.first_ingress_v2 import scene_ref_for_conversation
from ..runtime_contracts import NamespaceId
from .identity import astrbot_namespace
from .scene_candidates import ObservedSceneCandidate


@dataclass(frozen=True, slots=True)
class CurrentHostScene:
    """Current host identity only; no D03 configuration or send authority."""

    namespace: NamespaceId
    platform_ref: str
    conversation_ref: str
    visibility: str
    scene_ref: str


def _canonical_tuple(value: str, length: int) -> tuple[str, ...] | None:
    try:
        items = json.loads(value)
    except (TypeError, ValueError):
        return None
    if (type(items) is not list or len(items) != length
            or any(type(item) is not str or not item or item == "[%None]"
                   for item in items)
            or json.dumps(items, ensure_ascii=True, separators=(",", ":")) != value):
        return None
    return tuple(items)


async def verify_current_host_scene(
    context: Any, candidate: ObservedSceneCandidate,
) -> CurrentHostScene | None:
    """Recheck one observed scene on the active AstrBot event loop.

    A None result means HOLD. The caller must separately establish D03 policy,
    Owner command authorization, and graph admission before a binding write.
    """
    if type(candidate) is not ObservedSceneCandidate:
        return None
    platform = _canonical_tuple(candidate.platform_ref, 3)
    conversation_ref = _canonical_tuple(candidate.conversation_ref, 2)
    if platform is None or conversation_ref is None:
        return None
    platform_id, platform_name, self_id = platform
    umo, conversation_id = conversation_ref
    try:
        session = MessageSession.from_str(umo)
    except (ValueError, TypeError, IndexError):
        return None
    visibility = {
        MessageType.FRIEND_MESSAGE: "private",
        MessageType.GROUP_MESSAGE: "group",
    }.get(session.message_type)
    if (platform_name != "aiocqhttp" or visibility != candidate.visibility
            or session.platform_id != platform_id
            or not session.session_id.isascii() or not session.session_id.isdigit()
            or scene_ref_for_conversation(
                candidate.namespace, candidate.platform_ref,
                candidate.conversation_ref) != candidate.scene_ref):
        return None

    try:
        matching = [
            adapter for adapter in context.platform_manager.platform_insts
            if adapter.meta().id == platform_id
        ]
        if len(matching) != 1:
            return None
        adapter = context.get_platform_inst(platform_id)
        if (adapter is not matching[0] or not isinstance(adapter, AiocqhttpAdapter)
                or adapter.meta().name != "aiocqhttp"):
            return None
        login = await adapter.bot.call_action("get_login_info", self_id=self_id)
        if not isinstance(login, dict) or str(login.get("user_id")) != self_id:
            return None
        current_id = await context.conversation_manager.get_curr_conversation_id(umo)
        if current_id != conversation_id:
            return None
        conversation = await context.conversation_manager.get_conversation(
            umo, conversation_id, create_if_not_exists=False)
        if conversation is None:
            return None
        selected = await context.persona_manager.resolve_selected_persona(
            umo=umo,
            conversation_persona_id=getattr(conversation, "persona_id", None),
            platform_name=platform_name,
            provider_settings=context.get_config(umo),
        )
        if (not isinstance(selected, (tuple, list)) or not selected
                or type(selected[0]) is not str or not selected[0]
                or astrbot_namespace(platform_id, self_id, selected[0])
                != candidate.namespace):
            return None
        if (await context.conversation_manager.get_curr_conversation_id(umo)
                != conversation_id or context.get_platform_inst(platform_id) is not adapter):
            return None
    except Exception:
        # AstrBot can withdraw a platform, account or conversation during any await.
        return None
    return CurrentHostScene(
        candidate.namespace, candidate.platform_ref, candidate.conversation_ref,
        candidate.visibility, candidate.scene_ref)


__all__ = ("CurrentHostScene", "verify_current_host_scene")
