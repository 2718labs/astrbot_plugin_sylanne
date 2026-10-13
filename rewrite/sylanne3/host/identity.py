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


def astrbot_namespace_from_configuration_v1(value) -> NamespaceId:
    """Exact initial configuration; actual SDK/Host observation remains independent."""
    if (type(value) is not dict or set(value) != {
            "schema", "platform_id", "self_id", "selected_persona_id"}
            or value["schema"] != "sylanne.astrbot.installed-namespace.v1"):
        raise ValueError("exact configured AstrBot namespace identity required")
    for name in ("platform_id", "self_id", "selected_persona_id"):
        if type(value[name]) is not str:
            raise ValueError("configured AstrBot identity values must be strings")
    return astrbot_namespace(value["platform_id"], value["self_id"], value["selected_persona_id"])
