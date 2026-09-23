"""AstrBot 4.28.1 host entry for the Sylanne 3 production runtime."""
from __future__ import annotations

import asyncio
from pathlib import Path

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, StarTools

from .rewrite.sylanne3.host import (
    AstrBotIngressError,
    AuthorityClient,
    AuthoritySelection,
    build_astrbot_ingress,
)
from .rewrite.sylanne3.host.authority_profile import (
    AuthorityProfileUnavailable,
    build_admin_authority_transport,
)
from .rewrite.sylanne3.runtime_context import RuntimeContext, RuntimeHealth


PLUGIN_NAME = "astrbot_plugin_sylanne"
PACKAGE_ROOT = Path(__file__).resolve().parent


def _settings(config: object) -> tuple[bool, AuthoritySelection]:
    values = config if isinstance(config, dict) else {}
    enabled = values.get("enabled", False)
    if type(enabled) is not bool:
        raise ValueError("enabled must be boolean")
    profile = values.get("authority_profile", "default")
    return enabled, AuthoritySelection(profile)


class Sylanne3Plugin(Star):
    """Full-runtime host. Incomplete authority or domain sets remain blocked."""

    def __init__(self, context: Context, config: dict | None = None) -> None:
        super().__init__(context, config)
        try:
            self._enabled, self._authority_selection = _settings(config)
            self._config_valid = True
        except ValueError:
            self._enabled = False
            self._config_valid = False
        self._runtime: RuntimeContext | None = None
        self.runtime_health = RuntimeHealth("limited", ("not_started",))

    async def initialize(self) -> None:
        if not self._config_valid:
            self.runtime_health = RuntimeHealth("blocked", ("configuration",))
            logger.error("Sylanne 3 startup rejected: invalid configuration")
            return
        if not self._enabled:
            self.runtime_health = RuntimeHealth("limited", ("disabled",))
            logger.info("Sylanne 3 is disabled")
            return
        data_dir = await asyncio.to_thread(
            lambda: Path(StarTools.get_data_dir(PLUGIN_NAME)).resolve()
        )
        try:
            transport = await asyncio.to_thread(
                build_admin_authority_transport,
                self._authority_selection.profile_id,
            )
        except FileNotFoundError:
            self.runtime_health = RuntimeHealth(
                "enrollment_required", ("authority_profile",),
                "administrator Authority profile is not installed",
            )
            logger.info("Sylanne 3 requires administrator authority enrollment")
            return
        except AuthorityProfileUnavailable:
            self.runtime_health = RuntimeHealth(
                "blocked", ("authority_profile_verification",),
                "administrator Authority profile verification is unavailable",
            )
            logger.error("Sylanne 3 startup blocked: Authority profile verification unavailable")
            return
        except (OSError, ValueError):
            self.runtime_health = RuntimeHealth(
                "blocked", ("authority_profile_integrity",),
                "administrator Authority profile is invalid or unsafe",
            )
            logger.error("Sylanne 3 startup blocked: Authority profile invalid or unsafe")
            return
        authority = AuthorityClient(
            self._authority_selection,
            package_root=PACKAGE_ROOT,
            data_dir=data_dir,
            transport=transport,
        )
        authority_status = await authority.status()
        # A capability grant contains only authenticated facts. Production
        # RuntimeDependencies still require local adapters and a real ingress
        # handler, none of which may be synthesized by this plugin.
        if authority_status.state == "paired":
            await authority.capability_grant()
        self._runtime = RuntimeContext(
            data_dir,
            package_root=PACKAGE_ROOT,
            dependencies=None,
            authority_state=authority_status.state,
        )
        self.runtime_health = await self._runtime.start()
        if self.runtime_health.status == "enrollment_required":
            logger.info("Sylanne 3 requires administrator authority enrollment")
        elif self.runtime_health.status != "ready":
            logger.error(
                "Sylanne 3 startup blocked: missing=%s detail=%s",
                ",".join(self.runtime_health.missing_capabilities),
                self.runtime_health.detail,
            )

    async def terminate(self) -> None:
        if self._runtime is not None:
            self.runtime_health = await self._runtime.stop()
            self._runtime = None
        else:
            self.runtime_health = RuntimeHealth("stopped")

    @filter.event_message_type(filter.EventMessageType.ALL)
    async def ingress(self, event: AstrMessageEvent) -> None:
        runtime = self._runtime
        if runtime is None or self.runtime_health.status != "ready":
            return
        try:
            envelope = await build_astrbot_ingress(event, self.context)
            receipt = await runtime.handle_ingress(envelope)
        except AstrBotIngressError:
            logger.warning("Sylanne 3 ingress rejected: invalid host identity or ownership")
            return
        except Exception:
            logger.exception("Sylanne 3 ingress failed")
            return
        if receipt.status in {"accepted", "duplicate", "deferred"}:
            event.stop_event()


__all__ = ("Sylanne3Plugin",)
