"""AstrBot 4.28.1 host entry for the Sylanne 3 production runtime."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Callable

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, StarTools

from .rewrite.sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from .rewrite.sylanne3.host import (
    AstrBotIngressError,
    AuthoritySelection,
    assemble_v2_installation,
    build_astrbot_ingress,
)
from .rewrite.sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
from .rewrite.sylanne3.host.context_scheme_asset import load_verified_context_scheme
from .rewrite.sylanne3.host.authority_profile import AuthorityProfileUnavailable
from .rewrite.sylanne3.host.installed_scene_identity import InstalledSceneIdentityPort
from .rewrite.sylanne3.host.installed_model_capability import InstalledModelCapabilityPort
from .rewrite.sylanne3.host.scene_candidates import ObservedSceneCandidate, SceneCandidateCatalog
from .rewrite.sylanne3.host.workbench_mount import WorkbenchHostMount
from .rewrite.sylanne3.runtime_context import RuntimeContext, RuntimeHealth
from .rewrite.sylanne3.runtime_contracts import NamespaceId, canonical_digest
from .rewrite.sylanne3.workbench_api.current_onboarding import CurrentOnboardingResolver
from .rewrite.sylanne3.workbench_api.d01_onboarding import CurrentD01OnboardingResolver
from .rewrite.sylanne3.workbench_api.d03_onboarding import CurrentD03OnboardingResolver
from .rewrite.sylanne3.workbench_api.http_transport import CurrentOwnerPairingPort
from .rewrite.sylanne3.workbench_api.onboarding import OnboardingPolicyResolver
from .rewrite.sylanne3.workbench_api.local_creation_catalogue import LocalCreationCatalogue
from .rewrite.sylanne3.workbench_api.owner_grant import CurrentOwnerGrantPort


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

    def __init__(self, context: Context, config: dict | None = None, *,
                 workbench_pairing: CurrentOwnerPairingPort | None = None,
                 workbench_owner_grants: CurrentOwnerGrantPort | None = None,
                 workbench_onboarding: OnboardingPolicyResolver | None = None,
                 workbench_origin: str | None = None,
                 owner_principal_resolver: Callable[[str, NamespaceId], OwnerPrincipalV1 | None] | None = None) -> None:
        super().__init__(context, config)
        try:
            self._enabled, self._authority_selection = _settings(config)
            self._config_valid = True
        except ValueError:
            self._enabled = False
            self._config_valid = False
        self._runtime: RuntimeContext | None = None
        self._installed_namespace: NamespaceId | None = None
        self._scene_candidates = SceneCandidateCatalog()
        self.runtime_health = RuntimeHealth("limited", ("not_started",))
        self._workbench = WorkbenchHostMount(
            self._installation_status, self.observed_scene_candidates)
        self._workbench.register(context)
        self._workbench_dependencies = (
            workbench_pairing, workbench_owner_grants,
            workbench_onboarding, workbench_origin,
        )
        self._owner_principal_resolver = owner_principal_resolver

    def _installation_status(self) -> tuple[str, str]:
        health = self.runtime_health
        return health.status, (health.missing_capabilities[0]
                               if health.missing_capabilities else "none")

    def observed_scene_candidates(self, namespace: NamespaceId) -> tuple[ObservedSceneCandidate, ...]:
        """Server-side observations only; an Owner route must still authenticate."""
        if (not self._enabled or self._runtime is None
                or self._installed_namespace != namespace
                or self.runtime_health.status not in {"limited", "ready"}):
            return ()
        return self._scene_candidates.for_namespace(namespace)

    def lookup_observed_scene_candidate(
        self, *, namespace: NamespaceId, platform_ref: str,
        conversation_ref: str, visibility: str, scene_ref: str,
    ) -> ObservedSceneCandidate | None:
        """Require exact host identity; this lookup does not authorize binding."""
        if (not self._enabled or self._runtime is None
                or self._installed_namespace != namespace
                or self.runtime_health.status not in {"limited", "ready"}):
            return None
        return self._scene_candidates.get_exact(
            namespace=namespace, platform_ref=platform_ref,
            conversation_ref=conversation_ref, visibility=visibility,
            scene_ref=scene_ref,
        )

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
            context_scheme = await asyncio.to_thread(
                load_verified_context_scheme,
                PACKAGE_ROOT,
                installation.installation_policy.manifest_digest,
                available_cpu_features=installation.available_cpu_features,
            )
            provider = verified.registry.registrations["d03"].provider
            compile_scheme = getattr(provider, "compile_scheme", None)
            if not callable(compile_scheme):
                raise TypeError("installed D03 provider is unavailable")
            compiled = compile_scheme(context_scheme.draft(), None)
            if compiled != {
                "schema": "d03.context.scheme.v1",
                "roles": ("scene_participant",), "norms": (),
            }:
                raise ValueError("installed D03 scheme did not compile to neutral policy")
        except Exception:
            self.runtime_health = RuntimeHealth("blocked", ("context_scheme_verification",))
            logger.error("Sylanne 3 startup blocked: D03 scheme verification failed")
            return
        scene_port = InstalledSceneIdentityPort(
            context=self.context, host_loop=asyncio.get_running_loop(),
            candidates=self._scene_candidates,
        )
        try:
            self._runtime = RuntimeContext(
                data_dir, package_root=PACKAGE_ROOT, dependencies=None,
                domains=verified.registry,
                owner_principal_resolver=self._owner_principal_resolver,
                scene_identity_port=scene_port,
            )
            health = await self._runtime.start_v2(installation)
            self._installed_namespace = installation.installation_policy.namespace
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
                await self._runtime.refresh_capabilities()
            except Exception:
                failed = self._runtime.health
                self.runtime_health = (
                    failed if failed.status == "blocked"
                    else RuntimeHealth("blocked", ("namespace_activation",))
                )
                logger.error("Sylanne 3 startup blocked: namespace provisioning failed")
                return
            health = self._runtime.health
        pairing, grants, onboarding, origin = self._workbench_dependencies
        origin = origin or installation.workbench_origin
        if onboarding is None and pairing is None and grants is None and origin is not None:
            try:
                owner_ports = self._runtime.installed_owner_onboarding_ports()
                model_port = InstalledModelCapabilityPort(
                    context=self.context, host_loop=asyncio.get_running_loop(),
                    installed_namespace=installation.installation_policy.namespace,
                )
                onboarding = CurrentOnboardingResolver(
                    d01=CurrentD01OnboardingResolver(
                        namespaces=owner_ports, owners=owner_ports,
                        catalogue=LocalCreationCatalogue(
                            package_root=PACKAGE_ROOT,
                            expected_manifest_digest=installation.installation_policy.manifest_digest,
                            model_checker=model_port, budget_checker=owner_ports,
                        ),
                    ),
                    d03=CurrentD03OnboardingResolver(
                        namespaces=owner_ports, owners=owner_ports, scenes=scene_port,
                    ),
                )
            except Exception:
                logger.error("Sylanne D03 onboarding authority could not be attached")
        if onboarding is not None and origin is not None:
            try:
                transport = self._runtime.workbench_transport(
                    pairing=pairing, owner_grants=grants,
                    onboarding=onboarding, origin=origin)
                owner_sessions = self._runtime.workbench_owner_sessions
                if owner_sessions is not None:
                    self._workbench.attach_owner_sessions(owner_sessions)
                self._workbench.attach_transport(transport)
            except Exception:
                logger.error("Sylanne D12 workbench pairing could not be attached")
        if health.status == "limited":
            self.runtime_health = health
        else:
            self.runtime_health = RuntimeHealth(
                "blocked", health.missing_capabilities or ("runtime_bootstrap",),
            )
            logger.error("Sylanne 3 startup blocked: v2 graph unavailable")

    async def terminate(self) -> None:
        self._workbench.close()
        self._scene_candidates.clear()
        self._installed_namespace = None
        if self._runtime is not None:
            self.runtime_health = await self._runtime.stop()
            self._runtime = None
        else:
            self.runtime_health = RuntimeHealth("stopped")

    @filter.event_message_type(filter.EventMessageType.ALL)
    async def ingress(self, event: AstrMessageEvent) -> None:
        runtime = self._runtime
        if (not self._enabled or runtime is None
                or self.runtime_health.status not in {"limited", "ready"}
                or (self.runtime_health.status == "limited" and (
                    self._installed_namespace is None
                    or self.runtime_health.missing_capabilities == ("not_started",)))):
            return
        ready = self.runtime_health.status == "ready"
        v2_ingress_qualified = (
            self.runtime_health.status == "limited"
            and getattr(runtime, "v2_ingress_qualified", False) is True
        )
        try:
            envelope = await build_astrbot_ingress(event, self.context)
            if envelope.namespace == self._installed_namespace:
                self._scene_candidates.observe(envelope)
            if not ready and not (
                v2_ingress_qualified and envelope.namespace == self._installed_namespace
            ):
                return
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
