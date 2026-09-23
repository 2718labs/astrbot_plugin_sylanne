"""Stable, content-free AstrBot namespace identifiers."""

from __future__ import annotations

from ..runtime_contracts import NamespaceId, canonical_digest


_SCHEMA = "sylanne.astrbot.namespace.v1"


def _host_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value == "[%None]":
        raise ValueError(f"{label} must be a nonempty string")
    return value


def astrbot_namespace(
    platform_id: str, self_id: str, selected_persona_id: str,
) -> NamespaceId:
    """Bind a selected AstrBot persona to one platform account."""

    platform_id = _host_id(platform_id, "platform_id")
    self_id = _host_id(self_id, "self_id")
    selected_persona_id = _host_id(selected_persona_id, "selected_persona_id")
    bot_id = "astrbot-bot:" + canonical_digest({
        "schema": _SCHEMA,
        "platform_id": platform_id,
        "self_id": self_id,
    })
    persona_id = "astrbot-persona:" + canonical_digest({
        "schema": _SCHEMA,
        "persona_id": selected_persona_id,
    })
    return NamespaceId(bot_id, persona_id)
