"""AstrBot 4.28.1 host entry for the Sylanne 3 production runtime."""
from __future__ import annotations

import asyncio
from pathlib import Path

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, StarTools

from .rewrite.sylanne3.host import (
    AstrBotIngressError,
    AuthoritySelection,
    assemble_v2_installation,
    build_astrbot_ingress,
)
from .rewrite.sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
from .rewrite.sylanne3.host.authority_profile import AuthorityProfileUnavailable
from .rewrite.sylanne3.host.workbench_mount import WorkbenchHostMount
from .rewrite.sylanne3.runtime_context import RuntimeContext, RuntimeHealth
from .rewrite.sylanne3.runtime_contracts import canonical_digest


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
        self._workbench = WorkbenchHostMount()
        self._workbench.register(context)

    async def initialize(self) -> None:
        if not self._config_valid:
            self.runtime_health = RuntimeHealth("blocked", ("configuration",))
            logger.error("Sylanne 3 startup rejected: invalid configuration")
            return
        if not self._enabled:
            self.runtime_health = RuntimeHealth("limited", ("disabled",))
            logger.info("Sylanne 3 is disabled")
            return
        try:
            data_dir = await asyncio.to_thread(
                lambda: Path(StarTools.get_data_dir(PLUGIN_NAME)).resolve()
            )
        except Exception:
            self.runtime_health = RuntimeHealth("blocked", ("data_dir",))
            logger.error("Sylanne 3 startup blocked: data directory unavailable")
            return
        try:
            installation = await assemble_v2_installation(
                self._authority_selection.profile_id,
                package_root=PACKAGE_ROOT, data_dir=data_dir,
            )
        except FileNotFoundError:
            self.runtime_health = RuntimeHealth(
                "enrollment_required", ("authority_profile",),
            )
            logger.info("Sylanne 3 requires administrator authority enrollment")
            return
        except AuthorityProfileUnavailable:
            self.runtime_health = RuntimeHealth(
                "blocked", ("authority_profile_verification",),
            )
            logger.error("Sylanne 3 startup blocked: Authority profile verification unavailable")
            return
        except (OSError, ValueError):
            self.runtime_health = RuntimeHealth(
                "blocked", ("authority_profile_integrity",),
            )
            logger.error("Sylanne 3 startup blocked: Authority profile invalid or unsafe")
            return
        except Exception:
            self.runtime_health = RuntimeHealth("blocked", ("installation_verification",))
            logger.error("Sylanne 3 startup blocked: installation verification failed")
            return
        try:
            verified = await asyncio.to_thread(
                load_verified_affect_scheme,
                PACKAGE_ROOT,
                installation.installation_policy.manifest_digest,
                available_cpu_features=installation.available_cpu_features,
            )
        except Exception:
            self.runtime_health = RuntimeHealth("blocked", ("affect_scheme_verification",))
            logger.error("Sylanne 3 startup blocked: D04 scheme verification failed")
            return
        try:
            self._runtime = RuntimeContext(
                data_dir, package_root=PACKAGE_ROOT, dependencies=None,
                domains=verified.registry,
            )
            health = await self._runtime.start_v2(installation)
        except Exception:
            self.runtime_health = RuntimeHealth("blocked", ("runtime_bootstrap",))
            logger.error("Sylanne 3 startup blocked: v2 graph bootstrap failed")
            return
        if health.status == "limited" and health.missing_capabilities == ("namespace_activation",):
            try:
                operation_id = (
                    "namespace-provision:"
                    + canonical_digest(installation.installation_policy.digest_payload())
                )
                await self._runtime.provision_installed_namespace(operation_id)
            except Exception:
                failed = self._runtime.health
                self.runtime_health = (
                    failed if failed.status == "blocked"
                    else RuntimeHealth("blocked", ("namespace_activation",))
                )
                logger.error("Sylanne 3 startup blocked: namespace provisioning failed")
                return
            health = self._runtime.health
        if health.status == "limited":
            self.runtime_health = health
        else:
            self.runtime_health = RuntimeHealth(
                "blocked", health.missing_capabilities or ("runtime_bootstrap",),
            )
            logger.error("Sylanne 3 startup blocked: v2 graph unavailable")

    async def terminate(self) -> None:
        self._workbench.close()
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
