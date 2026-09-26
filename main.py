"""AstrBot 4.28.1 host entry for the Sylanne 3 production runtime."""
from __future__ import annotations

import asyncio
from pathlib import Path
import tempfile
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
from .rewrite.sylanne3.host.authority_profile import (
    AdminIngressModelPolicy, AdminInstallationBundle, AdminModelWorkflowsV2,
    AuthorityProfileUnavailable,
)
from .rewrite.sylanne3.host.v2_installation import V2InstallationAssembly
from .rewrite.sylanne3.host.installed_scene_identity import InstalledSceneIdentityPort
from .rewrite.sylanne3.host.installed_model_capability import InstalledModelCapabilityPort
from .rewrite.sylanne3.host.first_ingress_c02_driver import (
    installed_first_ingress_c02_pairing_ready_v1,
    original_acquired_handoff_v1,
    original_unacquired_handoff_v1,
    run_installed_first_ingress_c02_v1,
)
from .rewrite.sylanne3.host.ingress import IngressReceipt
from .rewrite.sylanne3.installation_policy import AdminInstallationPolicy
from .rewrite.sylanne3.host.scene_candidates import ObservedSceneCandidate, SceneCandidateCatalog
from .rewrite.sylanne3.host.workbench_mount import WorkbenchHostMount
from .rewrite.sylanne3.runtime_context import (
    FirstIngressPreEncodingStagesV1, RuntimeContext, RuntimeHealth,
)
from .rewrite.sylanne3.runtime.first_ingress_recovery import FirstIngressRecoveryItemV1
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


def _installed_model_port(
    context: Context, host_loop: asyncio.AbstractEventLoop,
    installation: object,
) -> InstalledModelCapabilityPort | None:
    """Keep the selected model tied to the exact administrator snapshot."""
    if type(installation) is not V2InstallationAssembly:
        return None
    bundle = installation.admin_bundle
    has_v2_workflows = (
        type(bundle) is AdminInstallationBundle
        and type(bundle.model_workflows) is AdminModelWorkflowsV2
        and bundle.ingress_model is None
    )
    if (type(bundle) is not AdminInstallationBundle
            or installation.installation_policy is not bundle.installation_policy
            or installation.ingress_encoding is not bundle.ingress_encoding
            or installation.ingress_model is not bundle.ingress_model
            or type(bundle.installation_policy) is not AdminInstallationPolicy
            or (not has_v2_workflows
                and type(bundle.ingress_model) is not AdminIngressModelPolicy)):
        return None
    return InstalledModelCapabilityPort(
        context=context, host_loop=host_loop,
        installed_namespace=bundle.installation_policy.namespace,
        installation_bundle=bundle,
    )


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
        self._v2_installation: V2InstallationAssembly | None = None
        self._encoding_tasks: set[asyncio.Task] = set()
        self._encoding_inflight: set[tuple[str, str, str, str]] = set()
        self._encoding_pending: asyncio.Queue = asyncio.Queue(maxsize=8)
        self._encoding_waiters: set[asyncio.Task] = set()
        self._recovery_scan_task: asyncio.Task | None = None
        self._encoding_stopping = False
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
            model_port = _installed_model_port(
                self.context, asyncio.get_running_loop(), installation)
        except (AttributeError, TypeError, ValueError):
            model_port = None
            logger.warning("Sylanne 3 installed model selection cannot be checked; HOLD")
        # A UMO exists only for a verified event. Keep provider construction
        # behind the future Authority executor; selection alone permits no call.
        try:
            self._runtime = RuntimeContext(
                data_dir, package_root=PACKAGE_ROOT, dependencies=None,
                domains=verified.registry,
                owner_principal_resolver=self._owner_principal_resolver,
                scene_identity_port=scene_port,
                **({"model_selection_port": model_port} if model_port is not None else {}),
            )
            health = await self._runtime.start_v2(installation)
            self._v2_installation = installation
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
                if model_port is None:
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
        if health.status in {"limited", "ready"}:
            self.runtime_health = health
            self._recovery_scan_task = asyncio.create_task(
                self._run_startup_c02_recovery_v1())
        else:
            self.runtime_health = RuntimeHealth(
                "blocked", health.missing_capabilities or ("runtime_bootstrap",),
            )
            logger.error("Sylanne 3 startup blocked: v2 graph unavailable")

    async def terminate(self) -> None:
        self._encoding_stopping = True
        self._workbench.close()
        self._scene_candidates.clear()
        self._installed_namespace = None
        if self._recovery_scan_task is not None:
            self._recovery_scan_task.cancel()
            await asyncio.gather(self._recovery_scan_task, return_exceptions=True)
            self._recovery_scan_task = None
        for task in self._encoding_waiters:
            task.cancel()
        if self._encoding_waiters:
            await asyncio.gather(*self._encoding_waiters, return_exceptions=True)
        if self._encoding_tasks:
            for task in self._encoding_tasks:
                task.cancel()
            await asyncio.gather(*self._encoding_tasks, return_exceptions=True)
            self._encoding_tasks.clear()
        queued = self._encoding_pending.qsize()
        while not self._encoding_pending.empty():
            self._encoding_pending.get_nowait()
        if queued:
            logger.warning("Sylanne 3 first encoding interrupted with %d queued handoffs; HOLD",
                           queued)
        self._encoding_inflight.clear()
        self._v2_installation = None
        if self._runtime is not None:
            self.runtime_health = await self._runtime.stop()
            self._runtime = None
        else:
            self.runtime_health = RuntimeHealth("stopped")

    async def _run_first_ingress_c02(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        trusted_umo: str, envelope, receipt: IngressReceipt,
        original_recovery: FirstIngressRecoveryItemV1 | None = None,
    ) -> None:
        try:
            committed = await run_installed_first_ingress_c02_v1(
                runtime, installation, context=self.context,
                trusted_umo=trusted_umo, envelope=envelope, receipt=receipt,
                original_recovery=original_recovery,
            )
            if committed is None:
                logger.warning("Sylanne 3 first encoding C02 remains HOLD")
            else:
                logger.info("Sylanne 3 first encoding C02 committed; reply HOLD")
        except asyncio.CancelledError:
            logger.warning("Sylanne 3 first encoding interrupted; original call HOLD")
            raise
        except Exception:
            logger.exception("Sylanne 3 first encoding C02 failed; original call HOLD")

    async def _drive_first_ingress_c02_queue(self) -> None:
        try:
            while not self._encoding_pending.empty() and not self._encoding_stopping:
                key, runtime, installation, trusted_umo, envelope, receipt = (
                    self._encoding_pending.get_nowait())
                try:
                    await self._run_first_ingress_c02(
                        runtime, installation, trusted_umo, envelope, receipt)
                finally:
                    self._encoding_inflight.discard(key)
        finally:
            self._encoding_tasks.discard(asyncio.current_task())
            if not self._encoding_pending.empty() and not self._encoding_stopping:
                self._encoding_tasks.add(asyncio.create_task(
                    self._drive_first_ingress_c02_queue()))

    async def _restore_unacquired_first_ingress_c02_v1(self) -> None:
        runtime = self._runtime
        installation = self._v2_installation
        try:
            if (self._encoding_stopping or runtime is None or installation is None
                    or getattr(runtime, "v2_ingress_qualified", False) is not True
                    or not await runtime.first_ingress_c02_accounting_installed_v1()
                    or not await installed_first_ingress_c02_pairing_ready_v1(
                        installation)):
                return
            attempted: set[tuple[str, str]] = set()
            # A second pass catches lower-key jobs committed during the scan.
            # Each job is attempted at most once by this startup scan; a HOLD
            # needs a later explicit wake or restart, never a hot retry loop.
            for _ in range(2):
                after_job_id = None
                while not self._encoding_stopping:
                    page = await runtime.discover_first_ingress_unacquired_v1(
                        after_job_id=after_job_id, limit=8)
                    if page is None:
                        logger.warning(
                            "Sylanne 3 unacquired first encoding discovery unavailable; HOLD")
                        return
                    for item in page.items:
                        identity = (item.job_id, item.original_operation_id)
                        if identity in attempted:
                            continue
                        attempted.add(identity)
                        handoff = original_unacquired_handoff_v1(item, installation)
                        if handoff is None:
                            logger.warning(
                                "Sylanne 3 unacquired first encoding identity invalid; HOLD")
                            continue
                        trusted_umo, envelope, receipt = handoff
                        await self._queue_first_ingress_c02(
                            runtime, installation, trusted_umo, envelope, receipt,
                            item.job_id)
                    after_job_id = page.next_after_job_id
                    if after_job_id is None:
                        break
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Sylanne 3 unacquired first encoding scan failed; HOLD")

    async def _run_startup_c02_recovery_v1(self) -> None:
        # C02 cost discovery uses graph-stamped V1 cursors. Finish that scan
        # before an unacquired job's V3 acquire can advance the graph stamp.
        await self._restore_committed_first_ingress_c02_cost_v1()
        if not self._encoding_stopping:
            await self._restore_acquired_first_ingress_c02_v1()
        if not self._encoding_stopping:
            await self._restore_unacquired_first_ingress_c02_v1()

    async def _restore_acquired_first_ingress_c02_v1(self) -> None:
        runtime = self._runtime
        installation = self._v2_installation
        try:
            if (self._encoding_stopping or runtime is None or installation is None
                    or getattr(runtime, "v2_ingress_qualified", False) is not True
                    or not await runtime.first_ingress_c02_accounting_installed_v1()
                    or not await installed_first_ingress_c02_pairing_ready_v1(
                        installation)):
                return
            # Collect both classes before writes invalidate the V1 cursor.
            # A sealed pending C02 must never enter the original result-read path.
            with tempfile.SpooledTemporaryFile(
                    max_size=131_072, mode="w+t", encoding="ascii") as ids, \
                    tempfile.SpooledTemporaryFile(
                        max_size=131_072, mode="w+t", encoding="ascii") as pending_ids:
                cursor = None
                seen_cursors = set()
                while not self._encoding_stopping:
                    page = await runtime.discover_committed_first_ingress_c02_cost_v1(
                        cursor=cursor, limit=50)
                    if page is None:
                        logger.warning(
                            "Sylanne 3 acquired first encoding discovery unavailable; HOLD")
                        return
                    for item in page.items:
                        if item.recovery_state == "original_fence":
                            operation_id = item.acquire_operation_id
                            if (len(operation_id) > 128
                                    or "\n" in operation_id or "\r" in operation_id):
                                logger.warning(
                                    "Sylanne 3 acquired first encoding identity invalid; HOLD")
                                return
                            ids.write(operation_id + "\n")
                        elif item.recovery_state == "c02_pending_hold":
                            operation_id = item.consumer_operation_id
                            if (type(operation_id) is not str or not operation_id
                                    or len(operation_id) > 512
                                    or "\n" in operation_id or "\r" in operation_id):
                                logger.warning(
                                    "Sylanne 3 pending C02 identity invalid; HOLD")
                                return
                            pending_ids.write(operation_id + "\n")
                    cursor = page.next_cursor
                    if cursor is None:
                        break
                    if cursor in seen_cursors:
                        logger.warning(
                            "Sylanne 3 acquired first encoding cursor repeated; HOLD")
                        return
                    seen_cursors.add(cursor)
                pending_ids.seek(0)
                for line in pending_ids:
                    if self._encoding_stopping:
                        return
                    committed = await runtime.recover_pending_first_ingress_c02_v1(
                        line.rstrip("\n"))
                    if committed is None:
                        logger.warning("Sylanne 3 pending C02 remains HOLD")
                    else:
                        if not await runtime.recover_committed_first_ingress_c02_unknown_cost_v1(
                                committed.operation_id):
                            logger.warning(
                                "Sylanne 3 pending C02 committed but cost remains HOLD")
                        else:
                            logger.info(
                                "Sylanne 3 pending C02 and cost recovered; reply HOLD")
                ids.seek(0)
                for line in ids:
                    if self._encoding_stopping:
                        return
                    handoff = await runtime.read_first_ingress_acquired_handoff_v1(
                        line.rstrip("\n"))
                    if handoff is None:
                        logger.warning(
                            "Sylanne 3 acquired first encoding recheck unavailable; HOLD")
                        continue
                    item, envelope = handoff
                    original = original_acquired_handoff_v1(
                        item, envelope, installation)
                    if original is None:
                        logger.warning(
                            "Sylanne 3 acquired first encoding host identity invalid; HOLD")
                        continue
                    trusted_umo, envelope, receipt = original
                    await self._run_first_ingress_c02(
                        runtime, installation, trusted_umo, envelope, receipt,
                        original_recovery=item)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Sylanne 3 acquired first encoding scan failed; HOLD")

    async def _restore_committed_first_ingress_c02_cost_v1(self) -> None:
        runtime = self._runtime
        installation = self._v2_installation
        try:
            if (self._encoding_stopping or runtime is None or installation is None
                    or getattr(runtime, "v2_ingress_qualified", False) is not True
                    or not await runtime.first_ingress_c02_accounting_installed_v1(
                        require_worker_result=False)
                    or not await installed_first_ingress_c02_pairing_ready_v1(
                        installation)):
                return
            # Finish a content-free discovery snapshot before any cost write
            # changes the graph stamp and invalidates its V1 cursor.
            with tempfile.SpooledTemporaryFile(
                    max_size=131_072, mode="w+t", encoding="ascii") as ids:
                cursor = None
                seen_cursors = set()
                while not self._encoding_stopping:
                    page = await runtime.discover_committed_first_ingress_c02_cost_v1(
                        cursor=cursor, limit=50)
                    if page is None:
                        logger.warning("Sylanne 3 committed C02 cost discovery unavailable; HOLD")
                        return
                    for item in page.items:
                        if item.recovery_state == "c02_committed":
                            operation_id = item.consumer_operation_id
                            if (type(operation_id) is not str or not operation_id
                                    or len(operation_id) > 512
                                    or "\n" in operation_id or "\r" in operation_id):
                                logger.warning("Sylanne 3 C02 cost identity invalid; HOLD")
                                return
                            ids.write(operation_id + "\n")
                    cursor = page.next_cursor
                    if cursor is None:
                        break
                    if cursor in seen_cursors:
                        logger.warning("Sylanne 3 C02 cost discovery cursor repeated; HOLD")
                        return
                    seen_cursors.add(cursor)
                ids.seek(0)
                for line in ids:
                    if self._encoding_stopping:
                        return
                    if not await runtime.recover_committed_first_ingress_c02_unknown_cost_v1(
                            line.rstrip("\n")):
                        logger.warning("Sylanne 3 committed C02 cost remains HOLD")
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Sylanne 3 committed C02 cost scan failed; HOLD")

    async def _schedule_first_ingress_c02(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        trusted_umo: str, envelope, receipt: IngressReceipt,
        stages: FirstIngressPreEncodingStagesV1,
    ) -> None:
        if (type(stages) is not FirstIngressPreEncodingStagesV1
                or stages.namespace != envelope.namespace
                or stages.ingress_operation_id != receipt.operation_id):
            logger.warning("Sylanne 3 first encoding handoff identity unavailable; HOLD")
            return
        await self._queue_first_ingress_c02(
            runtime, installation, trusted_umo, envelope, receipt,
            stages.job_id)

    async def _queue_first_ingress_c02(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        trusted_umo: str, envelope, receipt: IngressReceipt, job_id: str,
    ) -> None:
        if (self._encoding_stopping or self._runtime is not runtime
                or self._v2_installation is not installation
                or type(trusted_umo) is not str or not trusted_umo
                or type(job_id) is not str or not job_id
                or receipt.status != "accepted"):
            logger.warning("Sylanne 3 first encoding handoff identity unavailable; HOLD")
            return
        key = (*envelope.namespace.as_tuple, job_id, receipt.operation_id)
        if key in self._encoding_inflight:
            return
        self._encoding_inflight.add(key)
        current = asyncio.current_task()
        self._encoding_waiters.add(current)
        try:
            await self._encoding_pending.put((
                key, runtime, installation, trusted_umo, envelope, receipt))
        except asyncio.CancelledError:
            self._encoding_inflight.discard(key)
            logger.warning("Sylanne 3 first encoding handoff interrupted before queueing; HOLD")
            raise
        finally:
            self._encoding_waiters.discard(current)
        if self._encoding_stopping:
            logger.warning("Sylanne 3 first encoding handoff interrupted during shutdown; HOLD")
            return
        if not self._encoding_tasks:
            self._encoding_tasks.add(asyncio.create_task(
                self._drive_first_ingress_c02_queue()))

    @filter.event_message_type(filter.EventMessageType.ALL)
    async def ingress(self, event: AstrMessageEvent) -> None:
        runtime = self._runtime
        if (not self._enabled or runtime is None or self._encoding_stopping
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
        # Ingress receipts describe the durable D06 observation, not a reply.
        # Until runtime egress completes a host response, let AstrBot continue
        # processing every event, including duplicate and deferred ingress.
        if receipt.status == "deferred":
            logger.warning("Sylanne 3 ingress outcome pending confirmation")
        elif receipt.status == "accepted" and self._v2_installation is not None:
            stages = await runtime.commit_first_ingress_pre_encoding_stages_v1(
                envelope, receipt)
            if stages is None:
                logger.warning("Sylanne 3 first encoding awaits D03/D04 stages; HOLD")
            else:
                if not await runtime.first_ingress_c02_accounting_installed_v1():
                    logger.info("Sylanne 3 first encoding baseline committed; C02 accounting HOLD")
                else:
                    await self._schedule_first_ingress_c02(
                        runtime, self._v2_installation,
                        event.unified_msg_origin, envelope, receipt, stages)


__all__ = ("Sylanne3Plugin",)
