"""AstrBot 4.28.1 host entry for the Sylanne 3 production runtime."""
from __future__ import annotations

import asyncio
from datetime import datetime
import json
from pathlib import Path
import secrets
import tempfile
import time
from typing import Callable

from ._runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(Path(__file__).resolve().parent)

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, StarTools

from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.host import (
    AstrBotIngressError,
    AuthoritySelection,
    assemble_v2_installation,
    build_astrbot_ingress,
)
from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
from sylanne3.host.context_scheme_asset import load_verified_context_scheme
from sylanne3.host.authority_profile import (
    AdminIngressModelPolicy, AdminInstallationBundle, AdminModelWorkflowsV2,
    AdminPrivateReplyDispatchPolicy,
    AuthorityProfileUnavailable,
)
from sylanne3.host.v2_installation import V2InstallationAssembly
from sylanne3.host.final_handoff_pairing import TrustedFinalHandoffBindingV1
from sylanne3.host.reverse_handoff import HostReverseGraphClaimServer
from sylanne3.host.installed_scene_identity import InstalledSceneIdentityPort
from sylanne3.host.installed_model_capability import InstalledModelCapabilityPort
from sylanne3.host.first_ingress_c02_driver import (
    installed_first_ingress_c02_pairing_ready_v1,
    original_acquired_handoff_v1,
    original_unacquired_handoff_v1,
    run_installed_first_ingress_c02_v2,
    run_installed_pending_first_ingress_c02_v2,
    run_installed_committed_first_ingress_c02_cost_v2,
)
from sylanne3.host.ingress import IngressReceipt
from sylanne3.host.installed_reply_model_driver import (
    run_installed_post_c02_reply_model_v1,
)
from sylanne3.host.installed_d13_paid_driver import (
    run_installed_d13_paid_precompression_v1,
)
from sylanne3.host.natural_reply_dispatch_driver import (
    NaturalReplyDispatchResultV2,
)
from sylanne3.host.reply_takeover import rendezvous_private_reply_v1
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.host.scene_candidates import ObservedSceneCandidate, SceneCandidateCatalog
from sylanne3.host.workbench_mount import WorkbenchHostMount
from sylanne3.host.legacy_data_preflight import inspect_native_data_dir_v1
from sylanne3.runtime_context import (
    FirstIngressPreEncodingStagesV1, RuntimeContext, RuntimeHealth,
)
from sylanne3.runtime.first_ingress_recovery import FirstIngressRecoveryItemV1
from sylanne3.runtime.reply_model_job import (
    ReplyModelQueuedPreparationV1, ReplyModelRecoveryItemV1,
    ReplyModelRecoveryPageV1,
)
from sylanne3.runtime.natural_reply_job_v2 import SavedNaturalPreparationV2
from sylanne3.runtime.d13_technical_policy import D13ScheduleRecoveryItemV2
from sylanne3.memory_types import source_key
from sylanne3.runtime_contracts import NamespaceId, canonical_digest
from sylanne3.workbench_api.current_onboarding import CurrentOnboardingResolver
from sylanne3.workbench_api.d01_onboarding import CurrentD01OnboardingResolver
from sylanne3.workbench_api.d03_onboarding import CurrentD03OnboardingResolver
from sylanne3.workbench_api.http_transport import CurrentOwnerPairingPort
from sylanne3.workbench_api.onboarding import OnboardingPolicyResolver
from sylanne3.workbench_api.local_creation_catalogue import LocalCreationCatalogue
from sylanne3.workbench_api.owner_grant import CurrentOwnerGrantPort


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
        self._reply_tasks: dict[asyncio.Task, str] = {}
        self._reply_attempted_jobs: set[str] = set()
        self._natural_backlog: dict[
            str, tuple[RuntimeContext, V2InstallationAssembly,
                       SavedNaturalPreparationV2, str]] = {}
        self._natural_stage_scan_after: str | None = None
        self._natural_stage_scan_pending = False
        self._natural_stage_scan_running = False
        self._natural_stage_scan_task: asyncio.Task | None = None
        self._released_attention_scan_after: str | None = None
        self._released_attention_scan_pending = False
        self._released_attention_scan_running = False
        self._released_attention_scan_task: asyncio.Task | None = None
        self._reply_backlog_waiting = False
        self._reply_drain_task: asyncio.Task | None = None
        self._d13_pending_jobs: dict[str, str] = {}
        self._d13_pending_expiries: dict[str, str] = {}
        self._d13_deadline_wakes: dict[str, asyncio.TimerHandle] = {}
        self._d13_pending_schedules: dict[str, tuple[object, str]] = {}
        self._d13_scan_needed = False
        self._d13_attempted_jobs: set[str] = set()
        self._d13_drain_task: asyncio.Task | None = None
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
        self._final_handoff_server: HostReverseGraphClaimServer | None = None
        self._final_handoff_listener: asyncio.AbstractServer | None = None
        self._final_claim_writer: Callable | None = None

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
        data_preflight = await asyncio.to_thread(inspect_native_data_dir_v1, data_dir)
        if data_preflight.status == "migration_required":
            self.runtime_health = RuntimeHealth("blocked", ("migration_required",))
            logger.error("Sylanne 3 startup blocked: unmigrated or unsafe plugin data")
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
        reverse_binding = installation.reverse_handoff
        if (health.status in {"limited", "ready"}
                and type(reverse_binding) is TrustedFinalHandoffBindingV1):
            try:
                verified, writer = await self._runtime.install_final_handoff_pairing_v1(
                    installation, reverse_binding,
                    host_context=self.context, host_loop=asyncio.get_running_loop(),
                    candidates=self._scene_candidates)
                server = HostReverseGraphClaimServer(verified.binding.profile)
                await self._runtime.install_first_owner_reverse_v1(server, installation)
                listener = await server.start(
                    verified.binding.listen_host, verified.binding.port)
                self._final_handoff_server = server
                self._final_handoff_listener = listener
                self._final_claim_writer = writer
            except Exception:
                await self._runtime.uninstall_final_handoff_pairing_v1()
                logger.warning("Sylanne 3 final handoff pairing unavailable; dispatch HOLD")
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
            await self._runtime.resume_pending_d07_v1()
            self._runtime.resume_pending_domain_followups_v1(installation)
        else:
            self.runtime_health = RuntimeHealth(
                "blocked", health.missing_capabilities or ("runtime_bootstrap",),
            )
            logger.error("Sylanne 3 startup blocked: v2 graph unavailable")

    async def terminate(self) -> None:
        self._encoding_stopping = True
        # A started handoff keeps its reverse listener and graph worker until
        # its bounded send/observation decision ends. Remaining tasks are
        # cancelled below; Authority's durable start bars a later resend.
        dispatching = tuple(
            task for task, label in self._reply_tasks.items()
            if label.startswith("dispatch:") and not task.done())
        if dispatching:
            await asyncio.wait(dispatching, timeout=5.0)
        if self._final_handoff_listener is not None:
            self._final_handoff_listener.close()
            await self._final_handoff_listener.wait_closed()
            self._final_handoff_listener = None
        self._final_handoff_server = None
        self._final_claim_writer = None
        self._workbench.close()
        self._scene_candidates.clear()
        self._installed_namespace = None
        if self._recovery_scan_task is not None:
            self._recovery_scan_task.cancel()
            await asyncio.gather(self._recovery_scan_task, return_exceptions=True)
            self._recovery_scan_task = None
        if self._reply_drain_task is not None:
            self._reply_drain_task.cancel()
            await asyncio.gather(self._reply_drain_task, return_exceptions=True)
            self._reply_drain_task = None
        if self._natural_stage_scan_task is not None:
            self._natural_stage_scan_task.cancel()
            await asyncio.gather(self._natural_stage_scan_task,
                                 return_exceptions=True)
            self._natural_stage_scan_task = None
        if self._released_attention_scan_task is not None:
            self._released_attention_scan_task.cancel()
            await asyncio.gather(self._released_attention_scan_task,
                                 return_exceptions=True)
            self._released_attention_scan_task = None
        if self._d13_drain_task is not None:
            self._d13_drain_task.cancel()
            await asyncio.gather(self._d13_drain_task, return_exceptions=True)
            self._d13_drain_task = None
        for handle in self._d13_deadline_wakes.values():
            handle.cancel()
        self._d13_deadline_wakes.clear()
        self._d13_pending_jobs.clear()
        self._d13_pending_expiries.clear()
        self._d13_pending_schedules.clear()
        self._d13_scan_needed = False
        self._d13_attempted_jobs.clear()
        for task in self._encoding_waiters:
            task.cancel()
        if self._encoding_waiters:
            await asyncio.gather(*self._encoding_waiters, return_exceptions=True)
        if self._encoding_tasks:
            for task in self._encoding_tasks:
                task.cancel()
            await asyncio.gather(*self._encoding_tasks, return_exceptions=True)
            self._encoding_tasks.clear()
        if self._reply_tasks:
            tasks = tuple(self._reply_tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self._reply_tasks.clear()
        self._reply_attempted_jobs.clear()
        self._natural_backlog.clear()
        self._natural_stage_scan_after = None
        self._natural_stage_scan_pending = False
        self._natural_stage_scan_running = False
        self._released_attention_scan_after = None
        self._released_attention_scan_pending = False
        self._released_attention_scan_running = False
        self._reply_backlog_waiting = False
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

    def _natural_reply_ready_v2(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
    ) -> bool:
        ready = getattr(runtime, "natural_reply_product_ready_v2", None)
        if not callable(ready):
            return False
        try:
            return ready(
                installation, server=getattr(self, "_final_handoff_server", None),
                listener=getattr(self, "_final_handoff_listener", None),
                candidates=getattr(self, "_scene_candidates", None),
                context=self.context) is True
        except Exception:
            return False

    async def _prepare_new_post_c02_natural_v2(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        c02_operation_id: str, *, source_ref: str | None = None,
        trusted_umo: str | None = None,
    ) -> None:
        """Create a new paid original only with the complete natural path installed."""
        if not self._natural_reply_ready_v2(runtime, installation):
            logger.warning("Sylanne 3 natural reply product unavailable; new C02 HOLD")
            return
        if source_ref is None:
            read_source = getattr(runtime, "read_original_c02_source_ref_v2", None)
            if not callable(read_source):
                logger.warning("Sylanne 3 original C02 source read unavailable; HOLD")
                return
            source_ref = await read_source(c02_operation_id)
        if type(source_ref) is not str or not source_ref:
            logger.warning("Sylanne 3 original C02 source unavailable; HOLD")
            return
        try:
            appraisal = await runtime.run_post_c02_appraisal_v3(installation, context=self.context,
                trusted_umo=trusted_umo, c02_operation_id=c02_operation_id, source_ref=source_ref)
            if appraisal.get("status") not in {"adopted", "no_supported_meaning", "not_configured"}:
                logger.info("Sylanne 3 D04 appraisal original status: %s", appraisal.get("status"))
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Sylanne 3 D04 original appraisal remains pending")
        saved = await runtime.prepare_post_c02_natural_generation_v2(
            installation=installation,
            server=getattr(self, "_final_handoff_server", None),
            listener=getattr(self, "_final_handoff_listener", None),
            candidates=getattr(self, "_scene_candidates", None),
            context=self.context, c02_operation_id=c02_operation_id,
            source_ref=source_ref)
        if (type(saved) is not SavedNaturalPreparationV2
                or saved.stage != "generation"
                or saved.seal.c02_operation_id != c02_operation_id
                or saved.seal.source_ref != source_ref):
            logger.warning("Sylanne 3 natural original prepare remains HOLD")
            return
        try:
            audience = json.loads(saved.frozen.input.plan.audience_id)
        except (AttributeError, TypeError, ValueError):
            audience = None
        if (type(audience) is not list or len(audience) != 2
                or any(type(value) is not str or not value for value in audience)
                or trusted_umo is not None and audience[0] != trusted_umo):
            logger.warning("Sylanne 3 natural original audience unavailable; HOLD")
            return
        self._schedule_post_c02_natural_v2(
            runtime, installation, saved, audience[0])

    def _schedule_post_c02_natural_v2(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        saved: SavedNaturalPreparationV2, trusted_umo: str,
    ) -> None:
        if (self._encoding_stopping or self._runtime is not runtime
                or self._v2_installation is not installation
                or not self._natural_reply_ready_v2(runtime, installation)
                or type(saved) is not SavedNaturalPreparationV2
                or saved.stage != "generation"
                or saved.state not in {"queued", "acquired", "terminal"}
                or type(trusted_umo) is not str or not trusted_umo):
            logger.warning("Sylanne 3 natural original cannot be scheduled; HOLD")
            return
        job_id = saved.seal.job_id
        if job_id in self._reply_attempted_jobs:
            return
        if len(self._reply_tasks) >= 8:
            if job_id not in self._natural_backlog:
                if len(self._natural_backlog) >= 256:
                    # The original is already durable. Resume the bounded
                    # discovery scan when a worker frees capacity.
                    self._natural_stage_scan_after = None
                    self._natural_stage_scan_pending = True
                    logger.warning("Sylanne 3 natural backlog full; original job HOLD")
                    return
                self._natural_backlog[job_id] = (
                    runtime, installation, saved, trusted_umo)
            return
        self._natural_backlog.pop(job_id, None)

        async def continue_original() -> None:
            try:
                outcome = await runtime.run_installed_natural_reply_v2(
                    installation, context=self.context, trusted_umo=trusted_umo,
                    saved=saved, server=self._final_handoff_server,
                    candidates=self._scene_candidates,
                    listener=self._final_handoff_listener)
                if outcome is None:
                    logger.warning("Sylanne 3 natural original remains HOLD")
                elif type(outcome) is NaturalReplyDispatchResultV2:
                    if outcome.status == "unknown":
                        logger.warning("Sylanne 3 natural effect outcome unknown; reconcile original")
                    elif outcome.status == "hold":
                        logger.warning("Sylanne 3 natural effect remains HOLD: %s",
                                       outcome.reason)
                    elif outcome.status == "accepted":
                        logger.info("Sylanne 3 natural platform adapter accepted; delivery unobserved")
                        if outcome.original is not None:
                            await self._complete_accepted_natural_attention_v2(
                                runtime, installation, outcome.original.operation_id)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Sylanne 3 natural original failed; HOLD")
            finally:
                if not self._encoding_stopping:
                    runtime.queue_post_c02_numeric_v3(installation,
                        c02_operation_id=saved.seal.c02_operation_id,
                        source_ref=saved.seal.source_ref)

        task = asyncio.create_task(continue_original())
        self._reply_tasks[task] = "natural:" + job_id
        self._reply_attempted_jobs.add(job_id)
        def finished_natural(finished: asyncio.Task) -> None:
            self._reply_tasks.pop(finished, None)
            if not self._encoding_stopping:
                self._drain_natural_backlog_v2()

        task.add_done_callback(finished_natural)

    def _drain_natural_backlog_v2(self) -> None:
        while (self._natural_backlog and len(self._reply_tasks) < 8
               and not self._encoding_stopping):
            job_id = next(iter(self._natural_backlog))
            item = self._natural_backlog.pop(job_id)
            self._schedule_post_c02_natural_v2(*item)
        self._resume_natural_stage_scan_v2()
        self._resume_released_attention_scan_v2()
        if not self._reply_tasks and not self._natural_backlog:
            runtime = getattr(self, "_runtime", None)
            installation = getattr(self, "_v2_installation", None)
            if runtime is not None and installation is not None:
                runtime.resume_pending_d04_numeric_v3(installation)

    def _resume_natural_stage_scan_v2(self) -> None:
        runtime = getattr(self, "_runtime", None)
        installation = getattr(self, "_v2_installation", None)
        if (not getattr(self, "_natural_stage_scan_pending", False)
                or getattr(self, "_natural_stage_scan_running", False)
                or getattr(self, "_natural_stage_scan_task", None) is not None
                or self._encoding_stopping
                or len(self._natural_backlog) >= 256
                or runtime is None or installation is None
                or not self._natural_reply_ready_v2(runtime, installation)):
            return
        task = asyncio.create_task(self._restore_pending_natural_stages_v2())
        self._natural_stage_scan_task = task

        def finished_scan(finished: asyncio.Task) -> None:
            if self._natural_stage_scan_task is finished:
                self._natural_stage_scan_task = None
            if not self._encoding_stopping:
                self._resume_natural_stage_scan_v2()

        task.add_done_callback(finished_scan)

    def _resume_released_attention_scan_v2(self) -> None:
        runtime = getattr(self, "_runtime", None)
        installation = getattr(self, "_v2_installation", None)
        if (not getattr(self, "_released_attention_scan_pending", False)
                or getattr(self, "_released_attention_scan_running", False)
                or getattr(self, "_released_attention_scan_task", None) is not None
                or self._encoding_stopping
                or len(self._natural_backlog) >= 256
                or runtime is None or installation is None
                or not self._natural_reply_ready_v2(runtime, installation)):
            return
        task = asyncio.create_task(self._restore_released_attention_v2())
        self._released_attention_scan_task = task

        def finished_scan(finished: asyncio.Task) -> None:
            if self._released_attention_scan_task is finished:
                self._released_attention_scan_task = None
            if not self._encoding_stopping:
                self._resume_released_attention_scan_v2()

        task.add_done_callback(finished_scan)

    async def _complete_accepted_natural_attention_v2(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        final_operation_id: str,
    ) -> None:
        result = await runtime.complete_observed_natural_attention_v2(
            installation, final_operation_id=final_operation_id,
            server=getattr(self, "_final_handoff_server", None),
            listener=getattr(self, "_final_handoff_listener", None),
            candidates=getattr(self, "_scene_candidates", None),
            context=self.context)
        if result is None:
            logger.warning("Sylanne 3 accepted natural focus completion HOLD")
            return
        self._released_attention_scan_pending = True
        self._resume_released_attention_scan_v2()

    async def _run_first_ingress_c02(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        trusted_umo: str, envelope, receipt: IngressReceipt,
        original_recovery: FirstIngressRecoveryItemV1 | None = None,
        handler_invocation_id: str | None = None,
        handler_deadline_utc: float | None = None,
    ) -> None:
        try:
            committed = await run_installed_first_ingress_c02_v2(
                runtime, installation, context=self.context,
                trusted_umo=trusted_umo, envelope=envelope, receipt=receipt,
                original_recovery=original_recovery,
            )
            if committed is None:
                logger.warning("Sylanne 3 first encoding C02 remains HOLD")
            else:
                inbound_turn = None
                try:
                    inbound_turn = await runtime.commit_confirmed_d13_inbound_turn_v1(
                        ingress_operation_id=receipt.operation_id,
                        c02_operation_id=committed.operation_id,
                        envelope=envelope)
                    if inbound_turn is None:
                        logger.warning("Sylanne 3 confirmed D13 inbound turn remains HOLD")
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("Sylanne 3 confirmed D13 inbound turn failed; HOLD")
                settled = await run_installed_committed_first_ingress_c02_cost_v2(
                    runtime, installation, committed.operation_id)
                if settled is not True:
                    logger.warning("Sylanne 3 C02 committed but cost remains HOLD")
                    return
                source_ref = source_key(
                    *envelope.namespace.as_tuple, envelope.lineage.source_ref).token
                attention = await runtime.commit_post_c02_attention_v1(
                    c02_operation_id=committed.operation_id, source_ref=source_ref)
                if attention is None or attention.status not in {"committed", "duplicate"}:
                    logger.warning("Sylanne 3 settled C02 attention remains HOLD")
                    return
                if inbound_turn is not None:
                    self._queue_d13_schedule_v2(
                        runtime, installation, receipt.operation_id, envelope,
                        trusted_umo=trusted_umo)
                await self._prepare_new_post_c02_natural_v2(
                    runtime, installation, committed.operation_id,
                    source_ref=source_ref, trusted_umo=trusted_umo)
        except asyncio.CancelledError:
            logger.warning("Sylanne 3 first encoding interrupted; original call HOLD")
            raise
        except Exception:
            logger.exception("Sylanne 3 first encoding C02 failed; original call HOLD")

    async def _continue_post_c02_reply_model_v1(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        queued: ReplyModelQueuedPreparationV1, trusted_umo: str,
        *, handler_invocation_id: str | None = None,
        handler_deadline_utc: float | None = None,
    ) -> None:
        progress = await run_installed_post_c02_reply_model_v1(
            runtime, installation, context=self.context,
            trusted_umo=trusted_umo, queued=queued)
        if progress is None or progress.run.terminal.terminal is None:
            logger.warning("Sylanne 3 reply model attempt unresolved; HOLD")
        elif progress.cost is None:
            logger.warning("Sylanne 3 reply model cost remains HOLD")
        elif progress.candidate is None:
            logger.warning("Sylanne 3 reply model result adoption remains HOLD")
        else:
            if (handler_invocation_id is None or handler_deadline_utc is None
                    or time.time() >= handler_deadline_utc):
                logger.info("Sylanne 3 reply candidate has no live original handler; HOLD")
                return
            assembled = await runtime.assemble_post_c02_reply_v2(
                progress, handler_invocation_id=handler_invocation_id,
                handler_deadline_utc=handler_deadline_utc)
            if assembled is None or assembled.status not in {"committed", "duplicate"}:
                logger.warning("Sylanne 3 post-C02 reply assembly remains HOLD")
            else:
                logger.info("Sylanne 3 reply admission sealed; awaiting original handler")

    def _queue_d13_schedule_v2(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        ingress_operation_id: str, envelope, *, trusted_umo: str,
    ) -> None:
        if (self._encoding_stopping or self._runtime is not runtime
                or self._v2_installation is not installation
                or type(ingress_operation_id) is not str or not ingress_operation_id
                or type(trusted_umo) is not str or not trusted_umo
                or getattr(envelope, "namespace", None) !=
                   installation.installation_policy.namespace):
            logger.warning("Sylanne 3 D13 schedule binding invalid; HOLD")
            return
        if (ingress_operation_id not in self._d13_pending_schedules
                and len(self._d13_pending_schedules) + len(self._d13_pending_jobs) >= 256):
            logger.warning("Sylanne 3 D13 optional schedule backlog bounded; HOLD")
            return
        self._d13_pending_schedules.setdefault(
            ingress_operation_id, (envelope, trusted_umo))
        self._start_d13_drain_v2(runtime, installation)

    def _queue_d13_precompression_v2(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        job_id: str, conversation_ref: str, *, start_drain: bool = True,
    ) -> None:
        """Queue an optional original job without delaying foreground work."""
        if (self._encoding_stopping or self._runtime is not runtime
                or self._v2_installation is not installation
                or type(job_id) is not str or not job_id
                or type(conversation_ref) is not str or not conversation_ref):
            logger.warning("Sylanne 3 D13 original job binding invalid; HOLD")
            return
        if job_id not in self._d13_pending_jobs and len(self._d13_pending_jobs) >= 256:
            logger.warning("Sylanne 3 D13 optional worker backlog bounded; HOLD")
            return
        prior = self._d13_pending_jobs.setdefault(job_id, conversation_ref)
        if prior != conversation_ref:
            logger.warning("Sylanne 3 D13 original conversation changed; HOLD")
            return
        if start_drain:
            self._start_d13_drain_v2(runtime, installation)

    def _start_d13_drain_v2(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
    ) -> None:
        if self._d13_drain_task is None or self._d13_drain_task.done():
            self._d13_drain_task = asyncio.create_task(
                self._drain_d13_precompression_v2(runtime, installation))

    def _wake_d13_expiry_v2(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        job_id: str, conversation_ref: str,
    ) -> None:
        self._d13_deadline_wakes.pop(job_id, None)
        if (self._encoding_stopping or self._runtime is not runtime
                or self._v2_installation is not installation):
            return
        self._d13_pending_expiries[job_id] = conversation_ref
        self._start_d13_drain_v2(runtime, installation)

    async def _arm_d13_expiry_v2(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        job_id: str, conversation_ref: str,
    ) -> None:
        """Wake once at the saved job deadline; never rerun its worker."""
        if job_id in self._d13_deadline_wakes or len(self._d13_deadline_wakes) >= 256:
            return
        recovered = await runtime.recover_d13_precompression_schedule_v2(
            original_operation_id=job_id, conversation_ref=conversation_ref)
        if recovered is None:
            return
        _, job = recovered
        if (job.job_id != job_id or job.operation_id != job_id
                or job.continuation.get("conversation_ref") != conversation_ref
                or job.phase not in {"queued", "running"}):
            return
        try:
            deadline = datetime.fromisoformat(
                job.deadline_utc.replace("Z", "+00:00")).timestamp()
        except (AttributeError, ValueError, OverflowError):
            return
        delay = deadline - time.time() + 1.0
        if not 0 < delay <= 72 * 3600 + 1:
            return
        if (self._encoding_stopping or self._runtime is not runtime
                or self._v2_installation is not installation):
            return
        self._d13_deadline_wakes[job_id] = asyncio.get_running_loop().call_later(
            delay, self._wake_d13_expiry_v2, runtime, installation,
            job_id, conversation_ref)

    async def _drain_d13_precompression_v2(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
    ) -> None:
        """Run one bounded background consumer over committed D13 inputs."""
        try:
            while (self._d13_pending_jobs or self._d13_pending_expiries
                   or self._d13_pending_schedules
                   or self._d13_scan_needed) and not self._encoding_stopping:
                if (self._runtime is not runtime
                        or self._v2_installation is not installation):
                    return
                if self._d13_scan_needed:
                    self._d13_scan_needed = False
                    await self._restore_d13_original_schedules_v2()
                    continue
                if self._d13_pending_expiries:
                    job_id, conversation_ref = next(iter(self._d13_pending_expiries.items()))
                    self._d13_pending_expiries.pop(job_id)
                    expired = await runtime.expire_d13_deterministic_precompression_job_v2(
                        job_id=job_id, conversation_ref=conversation_ref)
                    if expired is None:
                        logger.warning("Sylanne 3 D13 deadline expiry %s remains HOLD", job_id)
                    continue
                if self._d13_pending_schedules:
                    operation_id, (envelope, trusted_umo) = next(
                        iter(self._d13_pending_schedules.items()))
                    self._d13_pending_schedules.pop(operation_id)
                    try:
                        paid = await run_installed_d13_paid_precompression_v1(
                            runtime, installation, context=self.context,
                            trusted_umo=trusted_umo, envelope=envelope,
                            ingress_operation_id=operation_id)
                        if paid is not None:
                            if paid.status != "standby":
                                logger.warning(
                                    "Sylanne 3 D13 paid original remains HOLD")
                            continue
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        logger.exception("Sylanne 3 D13 paid original attempt failed; HOLD")
                    try:
                        scheduled = await runtime.schedule_d13_deterministic_precompression_v2(
                            ingress_operation_id=operation_id, envelope=envelope)
                        if scheduled is not None:
                            _, original_job = scheduled
                            self._d13_pending_jobs.setdefault(
                                original_job.job_id, envelope.conversation_ref)
                        else:
                            logger.warning("Sylanne 3 D13 original schedule remains HOLD")
                            self._d13_scan_needed = True
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        logger.exception("Sylanne 3 D13 original schedule failed; HOLD")
                    continue
                job_id, conversation_ref = next(iter(self._d13_pending_jobs.items()))
                self._d13_pending_jobs.pop(job_id)
                if job_id in self._d13_attempted_jobs:
                    continue
                self._d13_attempted_jobs.add(job_id)
                completed = await runtime.consume_d13_deterministic_precompression_job_v2(
                    job_id=job_id, conversation_ref=conversation_ref)
                if completed is None:
                    expired = await runtime.expire_d13_deterministic_precompression_job_v2(
                        job_id=job_id, conversation_ref=conversation_ref)
                    if expired is None:
                        logger.warning(
                            "Sylanne 3 D13 precompression original job %s remains HOLD",
                            job_id)
                        await self._arm_d13_expiry_v2(
                            runtime, installation, job_id, conversation_ref)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Sylanne 3 optional D13 worker failed; HOLD")
        finally:
            if self._d13_drain_task is asyncio.current_task():
                self._d13_drain_task = None
            if ((self._d13_pending_jobs or self._d13_pending_expiries
                 or self._d13_pending_schedules
                 or self._d13_scan_needed)
                    and not self._encoding_stopping
                    and self._runtime is runtime
                    and self._v2_installation is installation):
                self._d13_drain_task = asyncio.create_task(
                    self._drain_d13_precompression_v2(runtime, installation))

    def _schedule_post_c02_reply_model_v1(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        queued: ReplyModelQueuedPreparationV1, trusted_umo: str,
        *, handler_invocation_id: str | None = None,
        handler_deadline_utc: float | None = None,
    ) -> None:
        """Bound live egress without occupying the serial C02 encoding queue."""
        if (self._encoding_stopping or self._runtime is not runtime
                or self._v2_installation is not installation
                or type(queued) is not ReplyModelQueuedPreparationV1
                or queued.original_operation_id != queued.job.operation_id
                or type(queued.job.job_id) is not str or not queued.job.job_id
                or type(trusted_umo) is not str or not trusted_umo):
            logger.warning("Sylanne 3 reply model original job invalid; HOLD")
            return
        if queued.job.job_id in self._reply_attempted_jobs:
            return
        if len(self._reply_tasks) >= 8:
            self._reply_backlog_waiting = True
            logger.warning("Sylanne 3 reply model worker busy; original job HOLD")
            return

        async def continue_original() -> None:
            try:
                handler_kwargs = (
                    {"handler_invocation_id": handler_invocation_id,
                     "handler_deadline_utc": handler_deadline_utc}
                    if handler_invocation_id is not None else {}
                )
                await self._continue_post_c02_reply_model_v1(
                    runtime, installation, queued, trusted_umo,
                    **handler_kwargs)
            except asyncio.CancelledError:
                logger.warning("Sylanne 3 reply model job %s interrupted; HOLD",
                               queued.job.job_id)
                raise
            except Exception:
                logger.exception("Sylanne 3 reply model original job failed; HOLD")

        task = asyncio.create_task(continue_original())
        self._reply_tasks[task] = queued.job.job_id
        self._reply_attempted_jobs.add(queued.job.job_id)

        def finished_reply(finished: asyncio.Task) -> None:
            self._reply_tasks.pop(finished, None)
            if self._reply_backlog_waiting and not self._encoding_stopping:
                self._start_reply_backlog_drain_v1()
            if not self._encoding_stopping:
                self._drain_natural_backlog_v2()

        task.add_done_callback(finished_reply)

    def _reserve_private_reply_dispatch_v1(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        ingress_operation_id: str, handler_invocation_id: str,
    ) -> asyncio.Future[bool] | None:
        """Reserve a bounded egress slot before the handler can stop AstrBot."""
        server = getattr(self, "_final_handoff_server", None)
        if (self._encoding_stopping or self._runtime is not runtime
                or self._v2_installation is not installation
                or server is None
                or getattr(self, "_final_handoff_listener", None) is None
                or getattr(self, "_final_claim_writer", None) is None
                or len(self._reply_tasks) >= 8
                or any(label.startswith("dispatch:")
                       for label in self._reply_tasks.values())):
            return None
        decision = asyncio.get_running_loop().create_future()

        async def continue_owned() -> None:
            if not await decision:
                return
            try:
                result = await runtime.dispatch_owned_private_reply_v1(
                    ingress_operation_id=ingress_operation_id,
                    handler_invocation_id=handler_invocation_id,
                    server=server, host_context=self.context,
                    candidates=self._scene_candidates)
                if result is None or result.status == "hold":
                    logger.warning("Sylanne 3 original private reply dispatch HOLD")
                elif result.status == "accepted":
                    logger.info("Sylanne 3 original OneBot reply accepted; delivery unobserved")
                else:
                    logger.warning("Sylanne 3 original OneBot reply outcome unknown")
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Sylanne 3 original private reply dispatch failed; HOLD")

        task = asyncio.create_task(continue_owned())
        self._reply_tasks[task] = "dispatch:" + ingress_operation_id
        def finished_dispatch(finished: asyncio.Task) -> None:
            self._reply_tasks.pop(finished, None)
            if not self._encoding_stopping:
                self._drain_natural_backlog_v2()

        task.add_done_callback(finished_dispatch)
        return decision

    def _start_reply_backlog_drain_v1(self) -> None:
        """Re-read durable originals once a bounded live egress slot opens."""
        if (self._encoding_stopping or not self._reply_backlog_waiting
                or self._reply_drain_task is not None
                and not self._reply_drain_task.done()):
            return

        async def drain() -> None:
            self._reply_backlog_waiting = False
            await self._restore_pending_post_c02_reply_models_v1(
                schedule_only=True)

        task = asyncio.create_task(drain())
        self._reply_drain_task = task

        def finished_drain(finished: asyncio.Task) -> None:
            if self._reply_drain_task is finished:
                self._reply_drain_task = None

        task.add_done_callback(finished_drain)

    async def _drive_first_ingress_c02_queue(self) -> None:
        try:
            while not self._encoding_pending.empty() and not self._encoding_stopping:
                pending = self._encoding_pending.get_nowait()
                if len(pending) == 6:
                    (key, runtime, installation, trusted_umo,
                     envelope, receipt) = pending
                    handler_invocation_id = handler_deadline_utc = None
                else:
                    (key, runtime, installation, trusted_umo, envelope, receipt,
                     handler_invocation_id, handler_deadline_utc) = pending
                try:
                    handler_kwargs = (
                        {"handler_invocation_id": handler_invocation_id,
                         "handler_deadline_utc": handler_deadline_utc}
                        if handler_invocation_id is not None else {}
                    )
                    await self._run_first_ingress_c02(
                        runtime, installation, trusted_umo, envelope, receipt,
                        **handler_kwargs)
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
        # Reconcile any original D13 write fence before other graph reads.
        # Consumption remains queued until the reply recovery scan has ended.
        await self._restore_d13_original_schedules_v2(start_drain=False)
        # C02 cost discovery uses graph-stamped V1 cursors. Finish that scan
        # before an unacquired job's V3 acquire can advance the graph stamp.
        await self._restore_committed_first_ingress_c02_cost_v1()
        if not self._encoding_stopping:
            await self._restore_acquired_first_ingress_c02_v1()
        if not self._encoding_stopping:
            await self._restore_unacquired_first_ingress_c02_v1()
        if not self._encoding_stopping:
            await self._restore_pending_post_c02_reply_models_v1()
        if not self._encoding_stopping:
            await self._restore_pending_natural_stages_v2()
        if not self._encoding_stopping:
            await self._restore_pending_natural_dispatch_v2()
        if not self._encoding_stopping:
            self._released_attention_scan_pending = True
            await self._restore_released_attention_v2()
        if not self._encoding_stopping and self._d13_pending_jobs:
            runtime = self._runtime
            installation = self._v2_installation
            if runtime is not None and installation is not None:
                self._start_d13_drain_v2(runtime, installation)

    async def _restore_pending_natural_stages_v2(self) -> None:
        """Resume sealed original stages without creating another paid identity."""
        runtime, installation = self._runtime, self._v2_installation
        if self._encoding_stopping or runtime is None or installation is None:
            return
        cost_cursor = None
        while not self._encoding_stopping:
            try:
                costs = await runtime.reconcile_natural_original_costs_v3(
                    installation, after=cost_cursor, limit=32)
            except Exception:
                logger.exception("Sylanne 3 original natural accounting recovery HOLD")
                break
            if costs is None or costs["next_after"] is None:
                break
            cost_cursor = costs["next_after"]
            await asyncio.sleep(0)
        if not self._natural_reply_ready_v2(runtime, installation):
            return
        if getattr(self, "_natural_stage_scan_running", False):
            return
        self._natural_stage_scan_running = True
        server = getattr(self, "_final_handoff_server", None)
        listener = getattr(self, "_final_handoff_listener", None)
        candidates = getattr(self, "_scene_candidates", None)
        cursor = getattr(self, "_natural_stage_scan_after", None)
        try:
            while not self._encoding_stopping:
                page = await runtime.discover_pending_natural_stages_v2(
                    installation, server=server, listener=listener,
                    candidates=candidates, context=self.context,
                    after=cursor, limit=32)
                if page is None or len(page.items) > 32:
                    logger.warning("Sylanne 3 natural original discovery HOLD")
                    self._natural_stage_scan_pending = False
                    return
                for item in page.items:
                    parent, source = item.parent_original_id, item.source_ref
                    if (type(parent) is not str or not parent
                            or type(source) is not str or not source
                            or (cursor is not None and parent <= cursor)):
                        logger.warning("Sylanne 3 natural original identity HOLD")
                        self._natural_stage_scan_pending = False
                        return
                    if (len(self._reply_tasks) >= 8
                            and len(self._natural_backlog) >= 256):
                        self._natural_stage_scan_after = cursor
                        self._natural_stage_scan_pending = True
                        return
                    progress = await runtime.read_installed_natural_original_progress_v2(
                        parent)
                    saved = await runtime.read_installed_natural_stage_preparation_v2(
                        parent, "generation")
                    if (progress is None or progress.generation is None
                            or type(saved) is not SavedNaturalPreparationV2
                            or saved.stage != "generation"
                            or saved.seal.c02_operation_id != parent
                            or saved.seal.source_ref != source
                            or progress.generation.original_operation_id !=
                               saved.seal.original_operation_id):
                        logger.warning("Sylanne 3 natural original recheck HOLD")
                    else:
                        try:
                            audience = json.loads(saved.frozen.input.plan.audience_id)
                        except (AttributeError, TypeError, ValueError):
                            audience = None
                        if (type(audience) is not list or len(audience) != 2
                                or any(type(value) is not str or not value
                                       for value in audience)):
                            logger.warning("Sylanne 3 natural original audience HOLD")
                        else:
                            self._schedule_post_c02_natural_v2(
                                runtime, installation, saved, audience[0])
                    cursor = parent
                next_after = page.next_after
                if next_after is None:
                    self._natural_stage_scan_after = None
                    self._natural_stage_scan_pending = False
                    return
                if not page.items or next_after != cursor:
                    logger.warning("Sylanne 3 natural original cursor repeated; HOLD")
                    self._natural_stage_scan_pending = False
                    return
                self._natural_stage_scan_after = cursor
                self._natural_stage_scan_pending = True
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Sylanne 3 natural original recovery failed; HOLD")
            self._natural_stage_scan_pending = False
        finally:
            self._natural_stage_scan_running = False
            self._resume_natural_stage_scan_v2()

    async def _restore_pending_natural_dispatch_v2(self) -> None:
        """Resume only committed natural effects discovered by W01's graph read."""
        runtime, installation = self._runtime, self._v2_installation
        if (self._encoding_stopping or runtime is None or installation is None
                or not self._natural_reply_ready_v2(runtime, installation)):
            return
        server = getattr(self, "_final_handoff_server", None)
        listener = getattr(self, "_final_handoff_listener", None)
        candidates = getattr(self, "_scene_candidates", None)
        seen: set[str] = set()
        cursor = None
        original_ids: list[str] = []
        try:
            for _ in range(32):
                page = await runtime.discover_pending_natural_dispatch_v2(
                    installation, server=server, listener=listener,
                    candidates=candidates, context=self.context,
                    after=cursor, limit=32)
                if page is None or len(page.items) > 32:
                    logger.warning("Sylanne 3 natural dispatch discovery HOLD")
                    return
                for item in page.items:
                    operation_id = item.operation_id
                    if (type(operation_id) is not str or not operation_id
                            or operation_id in seen):
                        logger.warning("Sylanne 3 natural dispatch identity HOLD")
                        return
                    seen.add(operation_id)
                    original_ids.append(operation_id)
                next_after = page.next_after
                if next_after is None:
                    break
                if next_after == cursor:
                    logger.warning("Sylanne 3 natural dispatch cursor repeated; HOLD")
                    return
                cursor = next_after
            else:
                logger.warning("Sylanne 3 natural dispatch page limit reached; HOLD")
                return
            for operation_id in original_ids:
                if self._encoding_stopping:
                    return
                completed = await runtime.complete_observed_natural_attention_v2(
                    installation, final_operation_id=operation_id,
                    context=self.context, server=server, listener=listener,
                    candidates=candidates)
                if completed is not None:
                    self._released_attention_scan_pending = True
                result = await runtime.dispatch_committed_natural_reply_v2(
                    installation, operation_id=operation_id,
                    context=self.context, server=server, listener=listener,
                    candidates=candidates)
                if result is None:
                    logger.warning("Sylanne 3 natural effect %s remains HOLD",
                                   operation_id)
                elif result.status == "accepted":
                    await self._complete_accepted_natural_attention_v2(
                        runtime, installation, operation_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Sylanne 3 natural dispatch recovery failed; HOLD")

    async def _restore_released_attention_v2(self) -> None:
        """Resume accepted-focus releases by their original committed C02 IDs."""
        runtime, installation = self._runtime, self._v2_installation
        if (self._encoding_stopping or runtime is None or installation is None
                or self._released_attention_scan_running
                or not self._natural_reply_ready_v2(runtime, installation)):
            return
        self._released_attention_scan_running = True
        cursor = self._released_attention_scan_after
        server = getattr(self, "_final_handoff_server", None)
        listener = getattr(self, "_final_handoff_listener", None)
        candidates = getattr(self, "_scene_candidates", None)
        try:
            while not self._encoding_stopping:
                if len(self._reply_tasks) >= 8 and len(self._natural_backlog) >= 256:
                    self._released_attention_scan_after = cursor
                    self._released_attention_scan_pending = True
                    return
                page = await runtime.discover_released_attention_v2(
                    installation, server=server, listener=listener,
                    candidates=candidates, context=self.context,
                    after=cursor, limit=32)
                if page is None or len(page.items) > 32:
                    logger.warning("Sylanne 3 released attention discovery HOLD")
                    self._released_attention_scan_pending = False
                    return
                for item in page.items:
                    if len(self._reply_tasks) >= 8 and len(self._natural_backlog) >= 256:
                        self._released_attention_scan_after = cursor
                        self._released_attention_scan_pending = True
                        return
                    c02_id = item.c02_operation_id
                    progress = await runtime.read_installed_natural_original_progress_v2(
                        c02_id)
                    if progress is None:
                        logger.warning("Sylanne 3 released C02 progress HOLD")
                        self._released_attention_scan_pending = False
                        return
                    if progress.generation is None:
                        source_ref = await runtime.read_original_c02_source_ref_v2(
                            c02_id)
                        if not source_ref:
                            logger.warning("Sylanne 3 released C02 source HOLD")
                            self._released_attention_scan_pending = False
                            return
                        await self._prepare_new_post_c02_natural_v2(
                            runtime, installation, c02_id, source_ref=source_ref)
                        progress = await runtime.read_installed_natural_original_progress_v2(
                            c02_id)
                        if progress is None or progress.generation is None:
                            logger.warning("Sylanne 3 released natural prepare HOLD")
                            self._released_attention_scan_pending = False
                            return
                    cursor = c02_id
                if page.next_after is None:
                    self._released_attention_scan_after = None
                    self._released_attention_scan_pending = False
                    return
                if not page.items or page.next_after != cursor:
                    logger.warning("Sylanne 3 released attention cursor HOLD")
                    self._released_attention_scan_pending = False
                    return
                self._released_attention_scan_after = cursor
                self._released_attention_scan_pending = True
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Sylanne 3 released attention recovery failed; HOLD")
            self._released_attention_scan_pending = False
        finally:
            self._released_attention_scan_running = False

    async def _restore_d13_original_schedules_v2(
        self, *, start_drain: bool = True,
    ) -> None:
        runtime = self._runtime
        installation = self._v2_installation
        if (self._encoding_stopping or runtime is None or installation is None
                or getattr(runtime, "v2_ingress_qualified", False) is not True):
            return
        try:
            items = await runtime.discover_d13_precompression_schedule_attempts_v2()
            if (type(items) is not tuple or len(items) > 64
                    or any(type(item) is not D13ScheduleRecoveryItemV2
                           for item in items)):
                logger.warning("Sylanne 3 D13 original schedule discovery HOLD")
                return
            seen: set[str] = set()
            for item in items:
                if self._encoding_stopping:
                    return
                if item.original_operation_id in seen:
                    logger.warning("Sylanne 3 D13 recovery identity repeated; HOLD")
                    return
                seen.add(item.original_operation_id)
                recovered = await runtime.recover_d13_precompression_schedule_v2(
                    original_operation_id=item.original_operation_id,
                    conversation_ref=item.conversation_ref)
                if recovered is None:
                    logger.warning("Sylanne 3 D13 original schedule %s recovery HOLD",
                                   item.original_operation_id)
                    continue
                _, job = recovered
                if (job.operation_id != item.original_operation_id
                        or job.continuation.get("conversation_ref") !=
                           item.conversation_ref):
                    logger.warning("Sylanne 3 D13 recovered original binding differs; HOLD")
                    continue
                if job.phase in {"queued", "running"}:
                    self._queue_d13_precompression_v2(
                        runtime, installation, job.job_id, item.conversation_ref,
                        start_drain=start_drain)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Sylanne 3 D13 original schedule recovery failed; HOLD")

    async def _restore_pending_post_c02_reply_models_v1(
        self, *, schedule_only: bool = False,
    ) -> None:
        """Snapshot at most 256 current job identities before any model call."""
        runtime = self._runtime
        installation = self._v2_installation
        if (self._encoding_stopping or runtime is None or installation is None
                or getattr(runtime, "v2_ingress_qualified", False) is not True):
            return
        pending: list[tuple[ReplyModelQueuedPreparationV1, str]] = []
        seen_jobs: set[str] = set()
        seen_cursors: set[str] = set()
        cursor = None
        stamp = None
        held = 0
        truncated = False
        try:
            for _ in range(32):
                if self._encoding_stopping:
                    return
                page = await runtime.discover_pending_post_c02_reply_model_jobs_v1(
                    cursor=cursor, limit=8)
                if (type(page) is not ReplyModelRecoveryPageV1
                        or page.namespace != installation.installation_policy.namespace
                        or page.installation_id !=
                           installation.installation_grant.installation_id
                        or len(page.items) > 8):
                    logger.warning("Sylanne 3 reply recovery page unavailable; HOLD")
                    return
                current_stamp = (page.graph_incarnation,
                                 page.graph_revision, page.graph_epoch)
                if stamp is not None and current_stamp != stamp:
                    logger.warning("Sylanne 3 reply recovery graph changed; HOLD")
                    return
                stamp = current_stamp
                for item in page.items:
                    if type(item) is not ReplyModelRecoveryItemV1:
                        logger.warning("Sylanne 3 reply recovery item invalid; HOLD")
                        return
                    if item.job_id in seen_jobs:
                        logger.warning("Sylanne 3 reply recovery identity repeated; HOLD")
                        return
                    seen_jobs.add(item.job_id)
                    if item.hold_reason is not None:
                        held += 1
                        continue
                    queued = item.preparation
                    if (type(queued) is not ReplyModelQueuedPreparationV1
                            or queued.job.job_id != item.job_id
                            or type(item.conversation_ref) is not str):
                        logger.warning("Sylanne 3 reply recovery binding invalid; HOLD")
                        return
                    try:
                        audience = json.loads(item.conversation_ref)
                    except (TypeError, ValueError):
                        logger.warning("Sylanne 3 reply recovery audience invalid; HOLD")
                        return
                    if (type(audience) is not list or len(audience) != 2
                            or any(type(value) is not str or not value
                                   for value in audience)):
                        logger.warning("Sylanne 3 reply recovery audience invalid; HOLD")
                        return
                    pending.append((queued, audience[0]))
                cursor = page.next_cursor
                if cursor is None:
                    break
                if (type(cursor) is not str or not cursor
                        or cursor in seen_cursors):
                    logger.warning("Sylanne 3 reply recovery cursor invalid; HOLD")
                    return
                seen_cursors.add(cursor)
            else:
                truncated = True
            if held or truncated:
                logger.warning(
                    "Sylanne 3 reply recovery has %d held jobs; backlog=%s",
                    held, "bounded" if truncated else "none")
            for queued, trusted_umo in pending:
                if (self._encoding_stopping or self._runtime is not runtime
                        or self._v2_installation is not installation):
                    return
                if queued.job.job_id in self._reply_attempted_jobs:
                    continue
                if schedule_only:
                    self._schedule_post_c02_reply_model_v1(
                        runtime, installation, queued, trusted_umo)
                    if self._reply_backlog_waiting:
                        break
                else:
                    self._reply_attempted_jobs.add(queued.job.job_id)
                    await self._continue_post_c02_reply_model_v1(
                        runtime, installation, queued, trusted_umo)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Sylanne 3 reply recovery scan failed; HOLD")

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
                    outcome = await run_installed_pending_first_ingress_c02_v2(
                        runtime, installation, line.rstrip("\n"))
                    if outcome is None:
                        logger.warning("Sylanne 3 pending C02 remains HOLD")
                    else:
                        committed, settled = outcome
                        if not settled:
                            logger.warning(
                                "Sylanne 3 pending C02 committed but cost remains HOLD")
                        else:
                            attention = await runtime.commit_post_c02_attention_v1(
                                c02_operation_id=committed.operation_id)
                            if attention is None or attention.status not in {
                                    "committed", "duplicate"}:
                                logger.warning(
                                    "Sylanne 3 recovered C02 attention remains HOLD")
                            else:
                                await self._prepare_new_post_c02_natural_v2(
                                    runtime, installation, committed.operation_id)
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
                    operation_id = line.rstrip("\n")
                    terminal = await run_installed_committed_first_ingress_c02_cost_v2(
                        runtime, installation, operation_id)
                    if terminal is False:
                        settled = await runtime.recover_committed_first_ingress_c02_unknown_cost_v1(
                            operation_id)
                    else:
                        settled = terminal is True
                    if not settled:
                        logger.warning("Sylanne 3 committed C02 cost remains HOLD")
                    else:
                        attention = await runtime.commit_post_c02_attention_v1(
                            c02_operation_id=operation_id)
                        if attention is None or attention.status not in {
                                "committed", "duplicate"}:
                            logger.warning(
                                "Sylanne 3 settled C02 attention remains HOLD")
                        else:
                            await self._prepare_new_post_c02_natural_v2(
                                runtime, installation, operation_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Sylanne 3 committed C02 cost scan failed; HOLD")

    async def _schedule_first_ingress_c02(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        trusted_umo: str, envelope, receipt: IngressReceipt,
        stages: FirstIngressPreEncodingStagesV1,
        *, handler_invocation_id: str | None = None,
        handler_deadline_utc: float | None = None,
    ) -> bool:
        if (type(stages) is not FirstIngressPreEncodingStagesV1
                or stages.namespace != envelope.namespace
                or stages.ingress_operation_id != receipt.operation_id):
            logger.warning("Sylanne 3 first encoding handoff identity unavailable; HOLD")
            return False
        return await self._queue_first_ingress_c02(
            runtime, installation, trusted_umo, envelope, receipt,
            stages.job_id, handler_invocation_id=handler_invocation_id,
            handler_deadline_utc=handler_deadline_utc)

    async def _queue_first_ingress_c02(
        self, runtime: RuntimeContext, installation: V2InstallationAssembly,
        trusted_umo: str, envelope, receipt: IngressReceipt, job_id: str,
        *, handler_invocation_id: str | None = None,
        handler_deadline_utc: float | None = None,
    ) -> bool:
        if (self._encoding_stopping or self._runtime is not runtime
                or self._v2_installation is not installation
                or type(trusted_umo) is not str or not trusted_umo
                or type(job_id) is not str or not job_id
                or receipt.status != "accepted"):
            logger.warning("Sylanne 3 first encoding handoff identity unavailable; HOLD")
            return False
        key = (*envelope.namespace.as_tuple, job_id, receipt.operation_id)
        if key in self._encoding_inflight:
            return False
        self._encoding_inflight.add(key)
        current = asyncio.current_task()
        self._encoding_waiters.add(current)
        try:
            await self._encoding_pending.put((
                key, runtime, installation, trusted_umo, envelope, receipt,
                handler_invocation_id, handler_deadline_utc))
        except asyncio.CancelledError:
            self._encoding_inflight.discard(key)
            logger.warning("Sylanne 3 first encoding handoff interrupted before queueing; HOLD")
            raise
        finally:
            self._encoding_waiters.discard(current)
        if self._encoding_stopping:
            logger.warning("Sylanne 3 first encoding handoff interrupted during shutdown; HOLD")
            return False
        if not self._encoding_tasks:
            self._encoding_tasks.add(asyncio.create_task(
                self._drive_first_ingress_c02_queue()))
        return True

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
            installation = self._v2_installation
            bundle = getattr(installation, "admin_bundle", None)
            private_policy = (
                bundle.private_reply_dispatch
                if (type(bundle) is AdminInstallationBundle
                    and bundle.installation_policy is installation.installation_policy
                    and type(bundle.private_reply_dispatch)
                    is AdminPrivateReplyDispatchPolicy
                    and envelope.visibility == "private"
                    and envelope.namespace == installation.installation_policy.namespace)
                else None
            )
            handler_invocation_id = None
            handler_deadline_utc = None
            deadline_monotonic = None
            handler_nonce = None
            takeover_port = None
            dispatch_decision = None
            if private_policy is not None:
                wait = private_policy.host_takeover_wait_seconds
                loop = asyncio.get_running_loop()
                deadline_monotonic = loop.time() + wait
                handler_deadline_utc = time.time() + wait
                handler_invocation_id = "handler:" + secrets.token_hex(16)
                handler_nonce = secrets.token_hex(32)
                try:
                    takeover_port = runtime.reply_takeover_port_v1(
                        envelope, receipt, deadline_monotonic=deadline_monotonic)
                    dispatch_decision = self._reserve_private_reply_dispatch_v1(
                        runtime, installation, receipt.operation_id,
                        handler_invocation_id)
                except (RuntimeError, TypeError, ValueError):
                    logger.warning("Sylanne 3 installed private reply takeover unavailable; HOLD")
                    takeover_port = None
                    handler_invocation_id = None
                    handler_deadline_utc = None
                if takeover_port is not None and dispatch_decision is None:
                    # No reserved sender slot or paired reverse listener: keep
                    # the default host reply before any stop_event opportunity.
                    try:
                        await takeover_port.close_host_default_v1(
                            ingress_operation_id=receipt.operation_id,
                            handler_invocation_id=handler_invocation_id)
                    except Exception:
                        logger.warning("Sylanne 3 host-default close unavailable; no takeover")
                    takeover_port = None
                    handler_invocation_id = None
                    handler_deadline_utc = None

            async def continue_accepted() -> bool:
                stages = await runtime.commit_first_ingress_pre_encoding_stages_v1(
                    envelope, receipt)
                if stages is None:
                    logger.warning("Sylanne 3 first encoding awaits D03/D04 stages; HOLD")
                    return False
                if not await runtime.first_ingress_c02_accounting_installed_v1():
                    logger.info("Sylanne 3 first encoding baseline committed; C02 accounting HOLD")
                    return False
                return await self._schedule_first_ingress_c02(
                    runtime, installation, event.unified_msg_origin,
                    envelope, receipt, stages,
                    handler_invocation_id=handler_invocation_id,
                    handler_deadline_utc=handler_deadline_utc)

            queued_for_handler = False
            try:
                if takeover_port is None:
                    queued_for_handler = await continue_accepted()
                else:
                    async with asyncio.timeout_at(deadline_monotonic):
                        queued_for_handler = await continue_accepted()
            except TimeoutError:
                logger.warning("Sylanne 3 private reply handler work exceeded installed wait")
            except Exception:
                logger.exception("Sylanne 3 accepted ingress continuation failed; HOLD")
            finally:
                try:
                    if takeover_port is not None:
                        try:
                            # Failed pre-encoding or queueing has no live reply
                            # worker to await; persist host default immediately.
                            wait_deadline = (deadline_monotonic if queued_for_handler
                                             else asyncio.get_running_loop().time())
                            takeover = await rendezvous_private_reply_v1(
                                event=event, envelope=envelope,
                                ingress_receipt=receipt,
                                installation_id=installation.installation_grant.installation_id,
                                handler_invocation_id=handler_invocation_id,
                                handler_nonce=handler_nonce, port=takeover_port,
                                deadline_monotonic=wait_deadline,
                                close_timeout_seconds=min(1.0, wait),
                                activation_timeout_seconds=min(5.0, wait),
                                suppression_registry=runtime.reply_suppression_registry,
                                handler_deadline_utc=handler_deadline_utc,
                            )
                            if dispatch_decision is not None and not dispatch_decision.done():
                                dispatch_decision.set_result(
                                    takeover.status == "sylanne_owned")
                        except Exception:
                            logger.exception("Sylanne 3 private reply rendezvous failed; HOLD")
                finally:
                    if dispatch_decision is not None and not dispatch_decision.done():
                        dispatch_decision.set_result(False)


__all__ = ("Sylanne3Plugin",)
