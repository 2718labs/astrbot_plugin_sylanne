from __future__ import annotations

import asyncio
from .host.model_workflows_v3 import AdminModelWorkflowsV3
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
import hashlib
import hmac
import inspect
import math
from pathlib import Path
from typing import TYPE_CHECKING, AsyncIterator, Awaitable, Callable, Protocol

from .authority_service.v2_owner_contract import OwnerActorBindingV1, OwnerPrincipalV1
from .contracts import StaleRead, canonical_json
from .domain_registry import DomainRegistry, discover_domain_registry
from .domains.d01 import ActiveRoleQualification
from .domains.d03.context import ContextProvider, RoleBinding
from .graph_coordinator import (
    D13InboundTurnReceiptV1, FirstIngressOutcomeUnknown, GraphCoordinator,
    D07ObservedFocusCompletionV2, D07ReleasedAttentionPageV2,
    NaturalOriginalProgressV2,
    NaturalPendingDispatchPageV2,
    NaturalPendingOriginalPageV2,
    IngressClockSample,
    IngressIssuancePolicy, UnavailableGuard,
    first_ingress_encoding_acquire_operation_id, namespace_ref,
)
from .graph_store import ProductionGraphStore
from .graph_worker import GraphWorker
from .host.ingress import HostIngressEnvelope, IngressReceipt
from .host.legacy_data_preflight import inspect_native_data_dir_v1
from .host.reply_suppression import HostReplySuppressionRegistryV1
from .host.reply_suppression import HostReplySuppressionEvidenceV1
from .host.reply_takeover import HostReplyTakeoverReadyV1
from .host.authority_profile import (
    AdminD03ArrivalPolicy, AdminD03SelfIdentityProjectionPolicy,
    AdminD04EncodingBaselinePolicy, AdminD06FirstIngressC02Policy,
    AdminIngressClockPolicy, AdminIngressEncodingPolicy,
    AdminIngressModelPolicy, AdminInstallationBundle, AdminModelWorkflowsV2,
    AdminModelWorkflowV2,
    AdminD07AttentionPolicy,
    AdminPrivateReplyDispatchPolicy,
)
from .host.v2_ingress_adapter import VerifiedMediaIngressV2, ingress_host_facts
from .host.installed_package import verify_installed_backend_runtime_v1
from .host.model_egress_executor import (
    FrozenEncodingEgressResult, HostModelEgressExecutor,
)
from .host.installed_model_capability import InstalledModelCapabilityPort
from .host.installation_grant_identity import same_installed_grant_identity_v2
from .host.installed_d04_root_resources import InstalledD04RootResources
from .host.accounting_maintenance_port import InstalledAccountingMaintenancePort
from .host.authority_client import AuthorityClient, AuthoritySelection
from .host.model_terminal_cost_port import InstalledModelTerminalCostPort
from .host.natural_generation_output_port import InstalledNaturalGenerationOutputPortV2
from .host.natural_generation_content_port import InstalledNaturalGenerationContentPortV2
from .host.natural_review_output_port import InstalledNaturalReviewOutputPortV2
from .host.natural_paid_review_port import InstalledNaturalPaidReviewPortV2
from .host.original_c02_cost_intent_port import InstalledOriginalC02CostIntentPort
from .host.self_identity_current_port import InstalledCurrentSelfIdentityPort
from .host.worker_result_read_fact_port import InstalledWorkerResultReadFactPort
from .host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from .host.first_ingress_result import OriginalFirstIngressRead
from .host.worker_result_identity import first_ingress_worker_result_request_v1
from .authority_service.v2_model_egress_contract import ModelEgressIntentV1
from .authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, WorkerModelResultReadV1,
)
from .authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from .host.v2_installation import V2InstallationAssembly
from .host.v2_fence_port import V2FenceOutcomeUnknown, V2FencePort
from .host.final_handoff_pairing import (
    TrustedFinalHandoffBindingV1, VerifiedFinalHandoffPairingV1,
    verify_final_handoff_pairing_v1,
)
from .installation_policy import AdminInstallationPolicy
from .model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION, issue_first_ingress_encoding_request_v2,
)
from .model_broker.d13_precompression import D13PrecompressionInstallationV1
from .runtime.issuers import (
    D02ResourceIssuer, D11BudgetGrantIssuer, D11BudgetJobIssuer,
)
from .runtime.d13_technical_policy import (
    AdminD13PrecompressionPolicyV1, D13ScheduleRecoveryItemV2,
)
from .runtime.d13_precompression_job import D13CacheCommitReceiptV1
from .runtime.d12_current_d07_policy_v1 import D12CurrentD07PolicyReadV1
from .runtime.budget import BudgetReceipt
from .runtime.jobs import PersistentJob
from .runtime.installed_dispatch_admission_issuer import InstalledDispatchAdmissionIssuer
from .runtime.first_ingress_v2 import ingress_ids, scene_ref_for_conversation
from .runtime.post_c02_domain_commit import commit_post_c02_reply_bundle_v1
from .host.post_c02_reply_driver import (
    PostC02ReplyCandidate, post_c02_reply_operation_id,
)
from .host.installed_reply_model_driver import (
    FrozenReplyModelPreparationV1, InstalledReplyModelRunV1,
    InstalledReplyProgressV1, reply_model_operation_id_v1,
)
from .host.post_c02_attention_driver import (
    post_c02_attention_operation_id, prepare_post_c02_attention_v1,
)
from .runtime.first_ingress_v2 import trusted_upper
from .runtime.reply_model_job import (
    ReplyModelQueuedPreparationV1, ReplyModelRecoveryPageV1,
)
from .runtime.context_reply_job_v2 import (
    SavedContextReplyPreparationV2, context_reply_job_ids_v2,
)
from .runtime.natural_reply_job_v2 import SavedNaturalPreparationV2
from .model_broker.broker import ModelCallRequest
from .authority_service.v2_context_reply_result_contract import (
    ContextReplyResultReadRequestV1,
)
from .authority_service.v2_model_egress_contract import ModelTerminalReceiptV2
from .authority_service.v2_reply_worker_model_result_contract import (
    ReplyWorkerModelResultReadRequestV1,
)
from .runtime.model_cost_settlement import OriginalModelCostCommitV1
from .runtime.first_ingress_unacquired import FirstIngressUnacquiredPageV1
from .runtime.first_ingress_recovery import (
    FirstIngressRecoveryItemV1, FirstIngressRecoveryPageV1,
)
from .runtime.original_model_result_context import OriginalModelResultContextV1
from .runtime.restore_anchor import ExecutionJournalPort
from .runtime_contracts import (
    AuthorityContext, CommitReceipt, DomainBundle, InstallationGrantV2, NamespaceId,
    SourceQualification, canonical_digest,
)
from .workbench_api.async_service import AsyncGraphWorkbenchService
from .workbench_api.domain_registry import CurrentDomainViewRegistry
from .workbench_api.http_transport import (
    BoundCsrfTokens, CurrentOwnerDashboardSessions, CurrentOwnerPairingPort,
    TransportConfig, WorkbenchHttpTransport,
)
from .workbench_api.onboarding import OnboardingPolicyResolver
from .workbench_api.owner_grant import (
    CurrentOwnerGrantPort, DurableOwnerGrantResolver, GraphCurrentOwnerGrantPort,
)
from .workbench_api.owner_session_resolver import BoundOwnerSessions
from .workbench_api.installed_owner_ports import InstalledOwnerOnboardingPorts

if TYPE_CHECKING:
    from .host.current_scene import CurrentHostScene
    from .host.reverse_handoff import HostReverseGraphClaimServer


class SceneIdentityPort(Protocol):
    def verify(self, namespace: NamespaceId, scene_ref: str,
               visibility: str) -> CurrentHostScene | None: ...


@dataclass(frozen=True)
class RuntimeHealth:
    status: str
    missing_capabilities: tuple[str, ...] = ()
    detail: str = ""


@dataclass(frozen=True, slots=True)
class _InstalledNaturalReplyReadinessReceiptV2:
    """One installation's graph, Authority readers, model and P2 bindings."""

    installation: V2InstallationAssembly
    bundle: AdminInstallationBundle
    policy: AdminInstallationPolicy
    grant: InstallationGrantV2
    client_grant: InstallationGrantV2
    worker: GraphWorker
    coordinator: GraphCoordinator
    fence_port: V2FencePort
    cost_transport: MtlsAuthorityTransport
    authority_client: AuthorityClient
    model_selection_port: object
    owner_loop: asyncio.AbstractEventLoop
    natural_ports: tuple[Callable, Callable, Callable, Callable]
    verified_handoff: VerifiedFinalHandoffPairingV1 | None = None
    p2_writer: object | None = None
    p2_context: object | None = None
    p2_candidates: object | None = None


@dataclass(frozen=True)
class FirstIngressPreEncodingStagesV1:
    namespace: NamespaceId
    ingress_operation_id: str
    job_id: str
    d03_receipt: CommitReceipt
    d04_receipt: CommitReceipt


@dataclass(frozen=True)
class AcquiredFirstIngressEncodingV2:
    """One live D11 lease shared by egress, cost and result consumption."""

    authority: AuthorityContext
    lease: object
    job_id: str
    acquire_operation_id: str


@dataclass(frozen=True)
class AcquiredPostC02ReplyModelV1:
    """The original durable reply worker lease; no model result is implied."""

    authority: AuthorityContext
    lease: object
    c02_operation_id: str
    source_ref: str
    acquire_operation_id: str


@dataclass(frozen=True)
class AcquiredPostC02ContextReplyModelV2:
    """Original V2 paid-call binding under the live D11 worker lease."""

    authority: AuthorityContext
    lease: object
    saved: SavedContextReplyPreparationV2
    job: PersistentJob
    call: ModelCallRequest


@dataclass(frozen=True)
class PreparedFirstIngressWorkerResultV1:
    """Original facts and worker-read body under the live D11 worker scope."""

    egress: FrozenEncodingEgressResult
    result_context: OriginalModelResultContextV1
    read_request: WorkerModelResultReadRequestV1
    result_read: WorkerModelResultReadV1


@dataclass(frozen=True)
class RuntimeDependencies:
    authority_attestation_ref: str
    package_manifest_sha256: str
    deletion_journal: object
    migration_authority: object
    restore_authority: object
    execution_journal_port: ExecutionJournalPort
    snapshot_requirements: Callable
    holder: str
    content_fence: Callable
    closure_verifier: Callable
    d02_issuer: object
    d11_issuer: object
    model_egress_authority: object
    ingress_policy: Callable[[NamespaceId, str], IngressIssuancePolicy]
    ingress_clock: Callable[[], IngressClockSample]
    ingress_handler_factory: Callable[
        [GraphCoordinator, object],
        Callable[[HostIngressEnvelope, GraphCoordinator], Awaitable[IngressReceipt]],
    ]

    def missing(self) -> tuple[str, ...]:
        missing = []
        if not isinstance(self.authority_attestation_ref, str) or not self.authority_attestation_ref:
            missing.append("authority_attestation_ref")
        digest = self.package_manifest_sha256
        if not isinstance(digest, str) or len(digest) != 64 or any(
            ch not in "0123456789abcdef" for ch in digest
        ):
            missing.append("package_manifest_sha256")
        for name in ("deletion_journal", "migration_authority", "restore_authority"):
            if getattr(self, name) is None:
                missing.append(name)
        if not callable(getattr(self.d02_issuer, "authorize_resources", None)):
            missing.append("d02_issuer")
        if not callable(getattr(self.d11_issuer, "admit_runtime", None)):
            missing.append("d11_issuer")
        if not callable(getattr(self.model_egress_authority, "execute_call", None)):
            missing.append("model_egress_authority")
        if not callable(getattr(self.execution_journal_port, "verify_current_chain", None)):
            missing.append("execution_journal_port")
        if not isinstance(self.holder, str) or not self.holder:
            missing.append("holder")
        for name in (
            "snapshot_requirements", "content_fence", "closure_verifier",
            "ingress_policy", "ingress_clock", "ingress_handler_factory",
        ):
            if not callable(getattr(self, name)):
                missing.append(name)
        return tuple(missing)


class InstalledReplyTakeoverRuntimePortV1:
    """One live ingress handler's bounded view of W01 ownership decisions."""

    def __init__(self, runtime: RuntimeContext, envelope: HostIngressEnvelope,
                 receipt: IngressReceipt, deadline_monotonic: float) -> None:
        if (type(envelope) is not HostIngressEnvelope
                or type(receipt) is not IngressReceipt
                or receipt.status != "accepted" or envelope.visibility != "private"
                or type(deadline_monotonic) not in (int, float)
                or not math.isfinite(deadline_monotonic)):
            raise ValueError("current private ingress handler is required")
        self._runtime = runtime
        self._envelope = envelope
        self._receipt = receipt
        self._deadline_monotonic = deadline_monotonic

    async def wait_for_durable_admission_v1(
        self, *, ingress_operation_id: str, handler_invocation_id: str,
    ) -> HostReplyTakeoverReadyV1 | None:
        if ingress_operation_id != self._receipt.operation_id:
            raise ValueError("reply ingress identity differs")
        loop = asyncio.get_running_loop()
        while loop.time() < self._deadline_monotonic:
            ready = await self._runtime._call_reply_ownership_v1(
                self._envelope, self._receipt, handler_invocation_id,
                "wait")
            if ready is not None:
                if type(ready) is not HostReplyTakeoverReadyV1:
                    raise RuntimeError("durable reply admission has no typed ready hint")
                return ready
            await asyncio.sleep(min(0.05, max(0.0, self._deadline_monotonic - loop.time())))
        return None

    async def close_host_default_v1(
        self, *, ingress_operation_id: str, handler_invocation_id: str,
    ) -> object:
        if ingress_operation_id != self._receipt.operation_id:
            raise ValueError("reply ingress identity differs")
        return await self._runtime._call_reply_ownership_v1(
            self._envelope, self._receipt, handler_invocation_id, "close")

    async def activate_reply_ownership_v1(
        self, *, ready: HostReplyTakeoverReadyV1,
        evidence: HostReplySuppressionEvidenceV1,
    ) -> object:
        if (type(ready) is not HostReplyTakeoverReadyV1
                or ready.ingress_operation_id != self._receipt.operation_id):
            raise ValueError("reply takeover ready hint differs")
        return await self._runtime._call_reply_ownership_v1(
            self._envelope, self._receipt,
            evidence.handler_invocation_id, "activate",
            ready=ready, evidence=evidence)

    async def recover_reply_ownership_v1(
        self, *, ingress_operation_id: str, handler_invocation_id: str,
    ) -> object:
        if ingress_operation_id != self._receipt.operation_id:
            raise ValueError("reply ingress identity differs")
        return await self._runtime._call_reply_ownership_v1(
            self._envelope, self._receipt, handler_invocation_id, "recover")


def _installed_body_quote_authority_v1(
    installation: V2InstallationAssembly,
) -> object | None:
    """Derive the C04 signer only from the paired, prepared admin profile."""
    bundle = installation.admin_bundle
    policy = installation.installation_policy
    if (type(bundle) is not AdminInstallationBundle
            or bundle.installation_policy != policy
            or bundle.d02_signing_key != installation.d02_signing_key
            or type(bundle.tls_profile) is not AuthorityTlsProfile
            or bundle.tls_profile.prepared_ssl_context is None
            or bundle.tls_profile.expected_authority_id != policy.expected_authority_id):
        return None
    from .domains.d02.body_quote_original import D02BodyQuoteAuthority
    key = hmac.digest(
        bundle.d02_signing_key,
        b"sylanne3.d02.body_quote_original.v1\0"
        + policy.installation_id.encode("utf-8"), "sha256")
    return D02BodyQuoteAuthority(key)


def _installed_c04_cpu_quote_authority_v1(
    installation: V2InstallationAssembly,
) -> object | None:
    """Bind C04 CPU quote policy to the prepared installation's D11 key."""
    bundle = installation.admin_bundle
    policy = installation.installation_policy
    if (type(bundle) is not AdminInstallationBundle
            or bundle.installation_policy != policy
            or bundle.d11_signing_key != installation.d11_signing_key
            or type(bundle.tls_profile) is not AuthorityTlsProfile
            or bundle.tls_profile.prepared_ssl_context is None
            or bundle.tls_profile.expected_authority_id != policy.expected_authority_id):
        return None
    from .runtime.c04_cpu_quote_policy import C04InternalCpuQuotePolicyAuthorityV1
    key = hmac.digest(
        bundle.d11_signing_key,
        b"sylanne3.c04.internal_cpu_quote_policy.v1\0"
        + policy.installation_id.encode("utf-8"), "sha256")
    return C04InternalCpuQuotePolicyAuthorityV1(key)


class RuntimeContext:
    """Own the production graph bootstrap and expose one bounded host ingress."""

    def __init__(
        self,
        data_dir: Path,
        *,
        package_root: Path | None = None,
        dependencies: RuntimeDependencies | None,
        domains: DomainRegistry | None = None,
        authority_state: str = "unavailable",
        owner_principal_resolver: Callable[[str, NamespaceId], OwnerPrincipalV1 | None] | None = None,
        scene_identity_port: SceneIdentityPort | None = None,
        model_selection_port: object | None = None,
    ) -> None:
        if owner_principal_resolver is not None and not callable(owner_principal_resolver):
            raise TypeError("owner_principal_resolver must be callable")
        if scene_identity_port is not None and not callable(getattr(scene_identity_port, "verify", None)):
            raise TypeError("scene_identity_port must verify current scenes")
        self._data_dir = Path(data_dir)
        self._package_root = (
            Path(package_root).resolve()
            if package_root is not None
            else Path(__file__).resolve().parents[2]
        )
        self._dependencies = dependencies
        self._authority_state = authority_state
        self._domains = domains or discover_domain_registry()
        self._owner_principal_resolver = owner_principal_resolver
        self._scene_identity_port = scene_identity_port
        self._reply_suppression_registry = HostReplySuppressionRegistryV1()
        if model_selection_port is not None and (
                not callable(getattr(model_selection_port, "verify_admin_config", None))
                or not callable(getattr(model_selection_port, "verify_admin_selection", None))):
            raise TypeError("model_selection_port must verify installed selection")
        self._model_selection_port = model_selection_port
        self._store: ProductionGraphStore | None = None
        self._coordinator: GraphCoordinator | None = None
        self._worker: GraphWorker | None = None
        self._v2_coordinator: GraphCoordinator | None = None
        self._v2_bootstrap: object | None = None
        self._v2_port: V2FencePort | None = None
        self._final_claim_lease: object | None = None
        self._final_claim_authority: AuthorityContext | None = None
        self._final_claim_writer: Callable | None = None
        self._v2_policy: AdminInstallationPolicy | None = None
        self._v2_installation_grant: InstallationGrantV2 | None = None
        self._v2_model_bundle: AdminInstallationBundle | None = None
        self._v2_available_cpu_features: frozenset[str] | None = None
        self._v2_cost_transport: MtlsAuthorityTransport | None = None
        self._v2_authority_client: AuthorityClient | None = None
        self._v2_authority_loop: asyncio.AbstractEventLoop | None = None
        self._v2_authority_client_grant: InstallationGrantV2 | None = None
        self._v2_owner_actor: Callable[[OwnerPrincipalV1, NamespaceId], str | None] | None = None
        self._workbench_owner_sessions: BoundOwnerSessions | None = None
        self._v2_d12_backend_port = None
        self._v2_package_maintenance_port = None
        self._v2_d07_execution_service = None
        self._domain_followup_task = None
        self._domain_followup_stopping = False
        self._domain_followup_rescan_requested = False
        self._host_lifecycle_observer = None
        self._host_lifecycle_startup_task = None
        self._host_lifecycle_startup_receipt = None
        self._host_lifecycle_last_status = None
        self._offline_recovery_task = None
        self._offline_recovery_stopping = False
        self._offline_recovery_last_status = None
        self._lifecycle_bootstrap_original = None
        self._v2_provision: Callable | None = None
        self._v2_ingress: Callable | None = None
        self._v2_role_probe: Callable | None = None
        self._v2_scene_probe: Callable | None = None
        self._v2_namespace: NamespaceId | None = None
        self._v2_missing_ingress_policies: tuple[str, ...] = ()
        self._v2_installed_model_selected = False
        self._v2_installed_model_config_matched = False
        self._v2_natural_generation_output_bound = False
        self._v2_natural_generation_content_bound = False
        self._v2_natural_review_output_bound = False
        self._v2_natural_paid_review_current_bound = False
        self._v2_natural_readiness_receipt: (
            _InstalledNaturalReplyReadinessReceiptV2 | None) = None
        self._v2_namespace_provisioned = False
        self._ingress_handler: Callable[
            [HostIngressEnvelope, GraphCoordinator], Awaitable[IngressReceipt]
        ] | None = None
        self._lock = asyncio.Lock()
        self._d04_numeric_tasks: dict[str, asyncio.Task] = {}
        self._d04_numeric_attempted: set[str] = set()
        self._d04_numeric_semaphore = asyncio.Semaphore(1)
        self._d04_numeric_stopping = False
        self._d04_numeric_scan_task: asyncio.Task | None = None
        self._d04_numeric_scan_after: str | None = None
        self._d04_numeric_last_status: dict[str, object] | None = None
        self.health = RuntimeHealth("limited", ("not_started",))

    async def start_v2(
        self,
        installation: V2InstallationAssembly,
        *,
        capacity: int = 8,
    ) -> RuntimeHealth:
        """Own a v2 graph worker; pairing alone never admits a namespace."""
        async with self._lock:
            if "v2_fence_recovery" in self.health.missing_capabilities:
                return self.health
            if self._worker is not None:
                return self.health
            self._d04_numeric_stopping = False
            self._domain_followup_stopping = False
            self._domain_followup_rescan_requested = False
            self._d04_numeric_attempted.clear()
            if self._store is not None:
                return self.health
            if not self._domains.complete:
                self.health = RuntimeHealth("blocked", ("domain_registry",))
                return self.health
            if type(installation) is not V2InstallationAssembly:
                self.health = RuntimeHealth("blocked", ("v2_installation",))
                return self.health
            installation_grant = installation.installation_grant
            policy = installation.installation_policy
            if (type(policy) is not AdminInstallationPolicy
                    or type(installation_grant) is not InstallationGrantV2
                    or not installation.package_root.is_absolute()
                    or not installation.data_dir.is_absolute()
                    or installation.package_root != self._package_root
                    or installation.data_dir != self._data_dir
                    or installation_grant.authority_id != policy.expected_authority_id
                    or installation_grant.installation_id != policy.installation_id
                    or installation_grant.administrator_holder != policy.administrator_holder
                    or installation_grant.manifest_digest != policy.manifest_digest):
                self.health = RuntimeHealth("blocked", ("v2_installation",))
                return self.health
            if isinstance(self._domains, DomainRegistry):
                scheme = self._domains.active_affect_scheme
                if (scheme is None or policy.scheme_version != scheme.scheme_version
                        or policy.operator_version != scheme.operator_version):
                    self.health = RuntimeHealth("blocked", ("affect_scheme",))
                    return self.health
            package = await asyncio.to_thread(
                verify_installed_backend_runtime_v1,
                self._package_root,
                policy.manifest_digest,
                available_cpu_features=installation.available_cpu_features,
            )
            if not package.verified or package.runtime_scope not in {"formal-alpha1", "backend-production-acceptance"}:
                self.health = RuntimeHealth(
                    "blocked", ("installed_package",),
                    package.reason if not package.verified else "formal-alpha1 package required",
                )
                return self.health

            try:
                from .host.d12_linux_bootstrap_v1 import complete_linux_lifecycle_bootstrap_v1
                self._lifecycle_bootstrap_original = await asyncio.to_thread(
                    complete_linux_lifecycle_bootstrap_v1, installation, self._domains)
            except (OSError, TypeError, ValueError, RuntimeError):
                self.health = RuntimeHealth("blocked", ("lifecycle_bootstrap",),
                    "resumed installation requires its independent original bootstrap readiness")
                return self.health

            if inspect_native_data_dir_v1(self._data_dir).status == "migration_required":
                self.health = RuntimeHealth("blocked", ("migration_required",),
                                            "unmigrated plugin data needs explicit migration proof")
                return self.health
            self._data_dir.mkdir(parents=True, exist_ok=True)

            cost_transport = None
            terminal_cost_port = None
            d04_appraisal_result_port = None
            accounting_port = None
            self_identity_port = None
            worker_result_fact_port = None
            original_c02_cost_intent_port = None
            natural_generation_output_port = None
            natural_generation_content_port = None
            natural_review_output_port = None
            natural_paid_review_current_port = None
            natural_authority_client = None
            natural_client_grant = None
            natural_owner_loop = None
            bundle = installation.admin_bundle
            if (type(bundle) is AdminInstallationBundle
                    and type(bundle.tls_profile) is AuthorityTlsProfile):
                try:
                    cost_transport = MtlsAuthorityTransport({
                        bundle.tls_profile.profile_id: bundle.tls_profile})
                    client = AuthorityClient(
                        AuthoritySelection(bundle.tls_profile.profile_id),
                        package_root=installation.package_root,
                        data_dir=installation.data_dir,
                        transport=cost_transport)
                    status = await client.status_v2()
                    client_grant = await client.installation_grant_v2()
                    if (status.state != "paired"
                            or not same_installed_grant_identity_v2(
                                installation_grant, client_grant)
                            or client._v2_handshake is None
                            or client_grant.channel_binding_sha256 !=
                               client._v2_handshake.channel_binding_sha256):
                        raise RuntimeError("installed accounting observer is unpaired")
                    loop = asyncio.get_running_loop()
                    natural_authority_client = client
                    natural_client_grant = client_grant
                    natural_owner_loop = loop
                    terminal_cost_port = InstalledModelTerminalCostPort(
                        client=client, bundle=bundle,
                        grant=client_grant, owner_loop=loop)
                    from .host.d04_appraisal_result_port_v3 import InstalledD04AppraisalResultPortV3
                    d04_appraisal_result_port = InstalledD04AppraisalResultPortV3(client=client, bundle=bundle,
                        grant=client_grant, owner_loop=loop)
                    accounting_port = InstalledAccountingMaintenancePort(
                        client=client, bundle=bundle,
                        grant=client_grant, owner_loop=loop)
                    self_identity_port = InstalledCurrentSelfIdentityPort(
                        client=client, bundle=bundle,
                        grant=client_grant, owner_loop=loop)
                    worker_result_fact_port = InstalledWorkerResultReadFactPort(
                        client=client, bundle=bundle,
                        grant=client_grant, owner_loop=loop)
                    original_c02_cost_intent_port = InstalledOriginalC02CostIntentPort(
                        client=client, bundle=bundle,
                        grant=client_grant, owner_loop=loop)
                    workflows = bundle.model_workflows
                    if (bundle.installation_policy == policy
                            and type(workflows) in (AdminModelWorkflowsV2, AdminModelWorkflowsV3)
                            and type(workflows.natural_generation)
                            is AdminModelWorkflowV2
                            and type(workflows.natural_review)
                            is AdminModelWorkflowV2):
                        try:
                            natural_generation_output_port = (
                                InstalledNaturalGenerationOutputPortV2(
                                    client=client, bundle=bundle,
                                    grant=client_grant, owner_loop=loop)
                                .read_original_natural_generation_output_v2)
                        except (TypeError, ValueError, RuntimeError):
                            natural_generation_output_port = None
                        try:
                            natural_generation_content_port = (
                                InstalledNaturalGenerationContentPortV2(
                                    client=client, bundle=bundle,
                                    grant=client_grant, owner_loop=loop)
                                .read_current_natural_generation_content_v2)
                        except (TypeError, ValueError, RuntimeError):
                            natural_generation_content_port = None
                        try:
                            natural_review_output_port = (
                                InstalledNaturalReviewOutputPortV2(
                                    client=client, bundle=bundle,
                                    grant=client_grant, owner_loop=loop)
                                .read_original_natural_review_output_v2)
                        except (TypeError, ValueError, RuntimeError):
                            natural_review_output_port = None
                        try:
                            natural_paid_review_current_port = (
                                InstalledNaturalPaidReviewPortV2(
                                    client=client, bundle=bundle,
                                    grant=client_grant, owner_loop=loop)
                                .read_current_natural_paid_review_v2)
                        except (TypeError, ValueError, RuntimeError):
                            natural_paid_review_current_port = None
                except Exception:
                    if cost_transport is not None:
                        await cost_transport.close()
                    cost_transport = None
                    terminal_cost_port = accounting_port = None
                    self_identity_port = worker_result_fact_port = None
                    original_c02_cost_intent_port = None
                    natural_generation_output_port = None
                    natural_generation_content_port = None
                    natural_review_output_port = None
                    natural_paid_review_current_port = None
                    natural_authority_client = None
                    natural_client_grant = None
                    natural_owner_loop = None
            model_authority_hold = (
                type(bundle) is AdminInstallationBundle
                and cost_transport is None)
            d04_output_policy = None
            c04_build_digest = None
            c04_authority_port = None
            try:
                from .host.installed_d04_output_policy import load_installed_d04_output_policy_v1
                from .host.installed_d06_build import verify_d06_algorithm_build, ALGORITHM_ID_V3
                from .runtime.c04_authority_port_v3 import InstalledC04AuthorityPortV3
                d04_output_policy = await asyncio.to_thread(
                    load_installed_d04_output_policy_v1,
                    installation.package_root, policy.manifest_digest,
                    require_formal=False, require_backend_runtime=True)
                verified_c04 = await asyncio.to_thread(
                    verify_d06_algorithm_build, installation.package_root,
                    policy.manifest_digest, require_formal=False, require_backend_runtime=True, algorithm_id=ALGORITHM_ID_V3)
                c04_build_digest = verified_c04["build_digest"].removeprefix("sha256:")
                if natural_authority_client is not None and natural_owner_loop is not None:
                    c04_authority_port = InstalledC04AuthorityPortV3(
                        client=natural_authority_client, bundle=bundle,
                        grant=natural_client_grant, owner_loop=natural_owner_loop)
            except (OSError, TypeError, ValueError, RuntimeError, KeyError):
                # The other qualified domains may start. D04/C04 public ports
                # still require these exact installed dependencies themselves.
                d04_output_policy = None
                c04_build_digest = None
                c04_authority_port = None

            from .host.installed_package_history_v1 import build_installed_host_d04_history_v1
            try:
                d04_history = await asyncio.to_thread(build_installed_host_d04_history_v1, installation)
            except (OSError, ValueError, TypeError, RuntimeError):
                if cost_transport is not None:
                    await cost_transport.close()
                self.health = RuntimeHealth("blocked", ("qualified_package_history",),
                    "selected package history qualification is unavailable")
                return self.health

            def make_store():
                if installation.storage_admission is not None:
                    installation.storage_admission.require_current_process_v1()
                return ProductionGraphStore(
                    (installation.storage_admission.graph_path if installation.storage_admission is not None
                     else self._data_dir / "sylanne3.sqlite3"), self._domains.type_registry,
                )

            provision = None
            ingress = None
            owner_runtime = None
            d12_backend_port = None
            package_maintenance_port = None
            model_config_matched = False
            model_selected = False
            encoding_request_issuer = None
            natural_ports_bound = False
            natural_model_selection_ready = False

            def make_coordinator(store, port):
                nonlocal provision, ingress, owner_runtime, model_config_matched, model_selected
                nonlocal encoding_request_issuer, natural_ports_bound
                nonlocal natural_model_selection_ready, d12_backend_port, package_maintenance_port
                if not same_installed_grant_identity_v2(
                        installation_grant, port.installation_grant):
                    raise RuntimeError("v2 port installation grant changed")
                bootstrap = object()
                reader = getattr(port, "current_owner_actor_binding", None)
                inverse_reader = getattr(port, "current_owner_principal_binding", None)
                current_binding_available = (
                    callable(reader) and callable(inverse_reader)
                    and policy.authority_namespace == namespace_ref(policy.namespace)
                )

                def matching_binding(binding, namespace):
                    return (type(binding) is OwnerActorBindingV1
                            and binding.namespace == namespace == policy.namespace
                            and binding.authority_id == installation_grant.authority_id
                            and binding.installation_id == installation_grant.installation_id)

                def current_principal(actor_id, namespace):
                    if (not current_binding_available or namespace != policy.namespace
                            or type(actor_id) is not str or not actor_id):
                        return None
                    binding = reader(
                        namespace=namespace, authority_namespace=policy.authority_namespace,
                        actor_id=actor_id)
                    return (binding.principal if matching_binding(binding, namespace)
                            and binding.actor_id == actor_id else None)

                def current_actor(principal, namespace):
                    if (not current_binding_available or namespace != policy.namespace
                            or type(principal) is not OwnerPrincipalV1):
                        return None
                    binding = inverse_reader(
                        namespace=namespace, authority_namespace=policy.authority_namespace,
                        principal=principal)
                    return (binding.actor_id if matching_binding(binding, namespace)
                            and binding.principal == principal else None)

                d02_issuer = D02ResourceIssuer(installation.d02_signing_key)
                body_quote_authority = _installed_body_quote_authority_v1(installation)
                c04_cpu_quote_authority = _installed_c04_cpu_quote_authority_v1(installation)
                d11_job_issuer = D11BudgetJobIssuer(
                    d02_issuer, installation.d11_signing_key)
                d03_registration = self._domains.registrations.get("d03")
                d03_provider = (d03_registration.provider
                                if d03_registration is not None else None)
                dispatch_admission_issuer = (
                    InstalledDispatchAdmissionIssuer(
                        context=d03_provider,
                        d11_issuer=D11BudgetGrantIssuer(installation.d11_signing_key),
                        d02_issuer=d02_issuer)
                    if (type(port) is V2FencePort
                        and type(installation.ingress_clock) is AdminIngressClockPolicy
                        and type(d03_provider) is ContextProvider)
                    else None)
                if (type(installation.ingress_model) is AdminIngressModelPolicy
                        and self._model_selection_port is not None):
                    try:
                        model_config_matched = (
                            self._model_selection_port.verify_admin_config(
                                policy.namespace, installation.ingress_model) is True)
                        model_selected = (
                            self._model_selection_port.verify_admin_selection(
                                policy.namespace, installation.ingress_model) is True)
                    except Exception:
                        model_config_matched = False
                        model_selected = False
                workflows = (bundle.model_workflows
                             if type(bundle) is AdminInstallationBundle else None)
                workflow = (workflows.encode
                            if type(workflows) in (AdminModelWorkflowsV2, AdminModelWorkflowsV3) else None)
                if (type(workflow) is AdminModelWorkflowV2
                        and bundle.installation_policy == policy
                        and bundle.ingress_encoding == installation.ingress_encoding
                        and bundle.ingress_model is None
                        and installation.ingress_model is None
                        and workflow.work_kind == "d06.encode_source"
                        and workflow.purpose == "consolidation"
                        and workflow.template_version == FIRST_INGRESS_ENCODING_TEMPLATE_VERSION
                        and type(installation.ingress_encoding) is AdminIngressEncodingPolicy
                        and set(workflow.required_capabilities) <= {"text"}
                        and all(amount <= installation.ingress_encoding.quote_ceiling.get(dimension, 0)
                                and amount <= policy.root_lease.limits.get(dimension, 0)
                                and amount <= policy.root_grant.max_ceiling.get(dimension, 0)
                                for dimension, amount in workflow.quote_ceiling.items())
                        and self._model_selection_port is not None):
                    def current_selection():
                        try:
                            return (self._model_selection_port.verify_admin_config(
                                policy.namespace, workflow) is True
                                and self._model_selection_port.verify_admin_selection(
                                    policy.namespace, workflow) is True)
                        except Exception:
                            return False

                    if current_selection():
                        def encoding_request_issuer(context):
                            if (context.authority.namespace != policy.namespace
                                    or context.authority.purpose != workflow.purpose
                                    or not set(context.authority.audience).issubset(
                                        workflow.audiences)
                                    or not current_selection()):
                                raise UnavailableGuard(
                                    "current installed encoding selection or scope unavailable; HOLD")
                            return issue_first_ingress_encoding_request_v2(
                                context, provider_id=workflow.provider_id,
                                model_id=workflow.model_id,
                                provider_config_ref=workflow.provider_config_ref,
                                provider_config_digest=workflow.provider_config_digest,
                                required_capabilities=frozenset(workflow.required_capabilities),
                                privacy_tier=workflow.privacy_tier,
                                timeout_seconds=workflow.timeout_seconds,
                                max_output_tokens=workflow.max_output_tokens,
                            )
                coordinator = GraphCoordinator(
                    store, bootstrap, holder=installation_grant.administrator_holder,
                    content_fence_v2=port,
                    d02_issuer=d02_issuer,
                    d11_issuer=d11_job_issuer,
                    body_quote_authority=body_quote_authority,
                    c04_cpu_quote_authority=c04_cpu_quote_authority,
                    c04_algorithm_build_digest=c04_build_digest,
                    c04_authority_port_v3=c04_authority_port,
                    d04_installed_joint_assembly=installation,
                    d04_installed_joint_output_policy=d04_output_policy,
                    d04_appraisal_result_port=d04_appraisal_result_port,
                    owner_principal_resolver=(self._owner_principal_resolver
                                              if self._owner_principal_resolver is not None
                                              else current_principal if current_binding_available
                                              else None),
                    scene_identity_port=self._scene_identity_port,
                    scene_clock_policy=installation.ingress_clock,
                    dispatch_clock_policy=installation.ingress_clock,
                    dispatch_admission_issuer=dispatch_admission_issuer,
                    reply_suppression_ack_verifier=(
                        self._reply_suppression_registry.verify_and_consume),
                    encoding_request_issuer=encoding_request_issuer,
                    model_terminal_cost_port=terminal_cost_port,
                    natural_generation_output_port=natural_generation_output_port,
                    natural_generation_content_port=natural_generation_content_port,
                    natural_review_output_port=natural_review_output_port,
                    natural_paid_review_current_port=natural_paid_review_current_port,
                    accounting_maintenance_port=accounting_port,
                    self_identity_port=self_identity_port,
                    worker_result_fact_port=worker_result_fact_port,
                    original_c02_cost_intent_port=original_c02_cost_intent_port,
                    d13_precompression_policy=(
                        bundle.d13_precompression
                        if type(bundle) is AdminInstallationBundle
                        and bundle.installation_policy == policy
                        and type(bundle.d13_precompression)
                        is AdminD13PrecompressionPolicyV1
                        else None),
                    d13_paid_precompression_policy=(
                        bundle.d13_paid_precompression
                        if type(bundle) is AdminInstallationBundle
                        and bundle.installation_policy == policy
                        else None),
                    life_d04_before_capture_policy=(
                        bundle.life_d04_before_capture_policy
                        if type(bundle) is AdminInstallationBundle
                        and bundle.installation_policy == policy
                        else None),
                )
                for registration in self._domains.registrations.values():
                    coordinator.register_provider(
                        bootstrap, registration.domain, registration.provider,
                        registration.proposal_schema,
                        registration.proposal_schema_hash,
                    )
                from .host.installed_d04_semantic_mapping_v3 import InstalledD04SemanticMappingReaderV3
                coordinator._GraphCoordinator__d04_historical_compatibility_v1 = d04_history
                coordinator._GraphCoordinator__d04_semantic_mapping_reader = InstalledD04SemanticMappingReaderV3(
                    coordinator, installation.package_root, policy.manifest_digest,
                    available_cpu_features=installation.available_cpu_features, historical_compatibility=d04_history)
                from .runtime.d12_installed_services_v1 import install_d12_services_v1
                d12_backend_port = install_d12_services_v1(coordinator, bootstrap=bootstrap)
                if bundle.model_workflows.contact_generation is not None:
                    if type(bundle.model_workflows) is AdminModelWorkflowsV3:
                        coordinator.install_contact_model_runtime_v2(bootstrap, bundle)
                    else:
                        coordinator.install_contact_model_runtime_v1(bootstrap, bundle)
                if bundle.package_selection is not None:
                    from .host.d12_package_workbench_port_v2 import InstalledD12PackageWorkbenchPortV2
                    package_maintenance_port = InstalledD12PackageWorkbenchPortV2(
                        coordinator=coordinator, bootstrap=bootstrap, authority_port=port)
                selection = self._model_selection_port
                if (type(selection) is InstalledModelCapabilityPort
                        and type(bundle) is AdminInstallationBundle
                        and type(bundle.model_workflows) in (AdminModelWorkflowsV2, AdminModelWorkflowsV3)
                        and selection._installation_bundle is bundle
                        and selection._installed_namespace == policy.namespace
                        and selection._host_loop is natural_owner_loop
                        and natural_owner_loop is not None
                        and natural_owner_loop.is_running()):
                    try:
                        natural_model_selection_ready = all(
                            selection.verify_admin_selection(
                                policy.namespace, workflow) is True
                            for workflow in (
                                bundle.model_workflows.natural_generation,
                                bundle.model_workflows.natural_review)
                        )
                    except Exception:
                        natural_model_selection_ready = False
                bind_natural = getattr(
                    port, "bind_natural_paid_consumers_v2", None)
                if (callable(bind_natural)
                        and type(bundle) is AdminInstallationBundle
                        and all(callable(bound) for bound in (
                            natural_generation_output_port,
                            natural_generation_content_port,
                            natural_review_output_port,
                            natural_paid_review_current_port))):
                    try:
                        natural_ports_bound = bind_natural(
                            coordinator, bundle, installation_grant) is True
                    except Exception:
                        natural_ports_bound = False
                provision = lambda graph, operation_id: graph.provision_namespace_v2(
                    bootstrap, policy, operation_id=operation_id,
                )
                if (type(installation.ingress_clock) is AdminIngressClockPolicy
                        and type(installation.ingress_encoding) is AdminIngressEncodingPolicy):
                    def ingress(graph, host):
                        media_source = None
                        if isinstance(host, VerifiedMediaIngressV2):
                            media_source = host.source_admission_v2
                            host = host.host
                        first = graph.commit_first_ingress_v2(
                            bootstrap, host, policy,
                            installation.ingress_clock, installation.ingress_encoding,
                            installation.admin_bundle.d06_private_reply_source
                            if type(installation.admin_bundle) is AdminInstallationBundle
                            else None,
                            **({"source_admission_v2": media_source}
                               if media_source is not None else {}),
                        )
                        if (first.status in {"committed", "duplicate"}
                                and type(installation.d03_arrival) is AdminD03ArrivalPolicy):
                            arrival = graph.commit_d03_message_arrival_v2(
                                bootstrap, host.namespace, host.lineage.source_ref,
                                policy, installation.d03_arrival,
                                installation.ingress_clock,
                            )
                            if arrival.status not in {"committed", "duplicate"}:
                                return arrival
                        return first
                owner_runtime = (
                    coordinator, bootstrap, port, policy, current_actor
                    if current_binding_available else None
                )
                return coordinator

            try:
                self._worker = await GraphWorker.start(
                    make_store, make_coordinator,
                    fence_port_factory=installation.fence_port_factory, capacity=capacity,
                )
            except Exception:
                if cost_transport is not None:
                    await cost_transport.close()
                self.health = RuntimeHealth(
                    "blocked", ("graph_worker",), "v2 graph worker could not initialize",
                )
                return self.health
            self._v2_d12_backend_port = d12_backend_port
            self._v2_package_maintenance_port = package_maintenance_port
            self._v2_provision = provision
            self._v2_ingress = ingress
            self._v2_installed_model_config_matched = model_config_matched
            # Selection is an installation diagnostic, never an egress permit.
            self._v2_installed_model_selected = model_selected
            self._v2_namespace = policy.namespace
            if owner_runtime is not None:
                (self._v2_coordinator, self._v2_bootstrap, port,
                 self._v2_policy, self._v2_owner_actor) = owner_runtime
                self._v2_port = port if isinstance(port, V2FencePort) else None
            self._v2_installation_grant = installation_grant
            self._v2_model_bundle = installation.admin_bundle
            self._v2_available_cpu_features = installation.available_cpu_features
            self._v2_cost_transport = cost_transport
            self._v2_authority_client = natural_authority_client
            self._v2_authority_client_grant = natural_client_grant
            self._v2_authority_loop = natural_owner_loop
            if (type(bundle) is AdminInstallationBundle and type(bundle.model_workflows) in (AdminModelWorkflowsV2, AdminModelWorkflowsV3)
                    and bundle.model_workflows.d07_cognition is not None
                    and type(natural_authority_client) is AuthorityClient
                    and natural_owner_loop is asyncio.get_running_loop()):
                from .runtime.d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
                selected_context = (self._model_selection_port._context
                    if type(self._model_selection_port) is InstalledModelCapabilityPort else None)
                def install_d07(graph):
                    service = InstalledD07ExecutionServiceV1(graph=graph, bootstrap=self._v2_bootstrap,
                        bundle=bundle, installation=installation, worker=self._worker,
                        authority_client=natural_authority_client, client_grant=natural_client_grant,
                        context=selected_context, owner_loop=natural_owner_loop)
                    graph._GraphCoordinator__d07_execution_service_v1 = service
                    graph._GraphCoordinator__body_quote_authority = service.body_authority
                    return service
                self._v2_d07_execution_service = await self._worker.call(install_d07)
            owner_loop = asyncio.get_running_loop()
            def install_followup_wake(graph):
                graph._GraphCoordinator__domain_followup_wake_v1 = lambda: owner_loop.call_soon_threadsafe(
                    self.resume_pending_domain_followups_v1, installation)
                graph._GraphCoordinator__host_lifecycle_wake_v1 = lambda: owner_loop.call_soon_threadsafe(
                    self.resume_host_lifecycle_observation_v1)
                graph._GraphCoordinator__offline_recovery_wake_v1 = lambda: owner_loop.call_soon_threadsafe(
                    self.resume_offline_recovery_v1)
            await self._worker.call(install_followup_wake)
            from .runtime.d11_host_lifecycle_v1 import InstalledHostLifecycleObserverV1
            self._host_lifecycle_observer = InstalledHostLifecycleObserverV1(self)
            self._host_lifecycle_startup_receipt = None
            self._offline_recovery_stopping = False
            self._v2_natural_generation_output_bound = (
                natural_generation_output_port is not None)
            self._v2_natural_generation_content_bound = (
                natural_generation_content_port is not None)
            self._v2_natural_review_output_bound = (
                natural_review_output_port is not None)
            self._v2_natural_paid_review_current_bound = (
                natural_paid_review_current_port is not None)
            if (natural_ports_bound and natural_model_selection_ready
                    and type(self._worker) is GraphWorker
                    and type(self._v2_coordinator) is GraphCoordinator
                    and type(self._v2_port) is V2FencePort
                    and type(cost_transport) is MtlsAuthorityTransport
                    and type(natural_authority_client) is AuthorityClient
                    and type(natural_client_grant) is InstallationGrantV2
                    and natural_owner_loop is asyncio.get_running_loop()
                    and type(self._model_selection_port)
                       is InstalledModelCapabilityPort):
                self._v2_natural_readiness_receipt = (
                    _InstalledNaturalReplyReadinessReceiptV2(
                        installation, bundle, policy, installation_grant,
                        natural_client_grant,
                        self._worker, self._v2_coordinator, self._v2_port,
                        cost_transport, natural_authority_client,
                        self._model_selection_port, natural_owner_loop,
                        (natural_generation_output_port,
                         natural_generation_content_port,
                         natural_review_output_port,
                         natural_paid_review_current_port)))
            self._v2_role_probe = lambda graph: graph.read_active_role_v2(
                namespace=policy.namespace,
            )
            self._v2_scene_probe = lambda graph, scene_ref: graph.read_active_scene_v2(
                namespace=policy.namespace, scene_ref=scene_ref,
            )
            self._v2_missing_ingress_policies = tuple(
                name for name, configured, expected in (
                    ("ingress_clock", installation.ingress_clock, AdminIngressClockPolicy),
                    ("ingress_encoding", installation.ingress_encoding, AdminIngressEncodingPolicy),
                ) if type(configured) is not expected
            )
            detail = "v2 graph worker started; namespace admission is pending"
            if model_authority_hold:
                detail += "; model egress and C02 HOLD: paired Authority TLS unavailable"
            self.health = RuntimeHealth(
                "limited", ("namespace_activation",), detail,
            )
            return self.health

    async def install_first_owner_reverse_v1(self, server, installation):
        """Bind only the fixed Authority-initiated first Owner Graph commit."""
        from .host.first_owner_reverse_v1 import InstalledFirstOwnerGraphCommitV1
        from .host.reverse_handoff import HostReverseGraphClaimServer
        if (type(server) is not HostReverseGraphClaimServer
                or type(installation) is not V2InstallationAssembly
                or self._worker is None or self._v2_bootstrap is None
                or not self._v2_namespace_provisioned
                or installation.admin_bundle is not self._v2_model_bundle
                or installation.installation_policy is not self._v2_policy):
            raise UnavailableGuard("actual first Owner reverse installation unavailable")
        service = InstalledFirstOwnerGraphCommitV1(namespace=self._v2_namespace,
            worker=self._worker, bootstrap=self._v2_bootstrap, installation=installation)
        server.install_first_owner_v1(service)
        return service

    async def install_final_handoff_pairing_v1(
        self, installation: V2InstallationAssembly,
        binding: TrustedFinalHandoffBindingV1,
        *, host_context: object, host_loop: asyncio.AbstractEventLoop,
        candidates: object,
    ) -> tuple[VerifiedFinalHandoffPairingV1, Callable]:
        """Install P2 only after an authenticated Authority/local TLS comparison."""
        from .host.installed_dispatch_route import InstalledDispatchRoutePort
        from .host.scene_candidates import SceneCandidateCatalog

        async with self._lock:
            policy = self._v2_policy
            grant = self._v2_installation_grant
            port = self._v2_port
            worker = self._worker
            bootstrap = self._v2_bootstrap
            if (type(installation) is not V2InstallationAssembly
                    or type(binding) is not TrustedFinalHandoffBindingV1
                    or type(candidates) is not SceneCandidateCatalog
                    or not isinstance(host_loop, asyncio.AbstractEventLoop)
                    or worker is None or bootstrap is None or port is None
                    or policy is None or grant is None
                    or not self._v2_namespace_provisioned
                    or installation.installation_policy != policy
                    or installation.installation_grant != grant
                    or installation.reverse_handoff is not binding):
                raise RuntimeError("installed final handoff prerequisites unavailable; HOLD")
            if self._final_claim_writer is not None:
                raise RuntimeError("final handoff pairing is already installed")

            def install(graph):
                authenticated = port.read_final_handoff_pairing_v1(
                    namespace=policy.authority_namespace,
                    installation_id=grant.installation_id)
                verified = verify_final_handoff_pairing_v1(
                    authenticated, installation, binding)
                anchor = port.current_anchor(
                    namespace=policy.namespace,
                    authority_namespace=policy.authority_namespace)
                lease, ref = graph.grant(
                    bootstrap, actor=grant.administrator_holder,
                    issuer_domain="d11", namespace=policy.namespace,
                    domains=("d03", "d05", "d06", "d07", "d08", "d09", "d11"),
                    activation_generation=anchor.activation_generation)
                try:
                    authority = AuthorityContext(
                        grant.administrator_holder, "d11", ref, policy.namespace,
                        ("activity",),
                        "expression", ("internal",), policy.root_grant.policy_ref,
                        anchor.activation_generation)
                    route = InstalledDispatchRoutePort(
                        context=host_context, host_loop=host_loop,
                        candidates=candidates, coordinator=graph,
                        authority=authority, lease=lease,
                        policy=policy, grant=grant)
                    writer = graph.register_dispatch_final_claim_writer_v1(
                        bootstrap, route_port=route, issuer_id=verified.issuer_id)
                except BaseException:
                    graph.release_authority_lease(bootstrap, lease)
                    raise
                return verified, lease, authority, writer

            verified, lease, authority, writer = await worker.call(install)
            self._final_claim_lease = lease
            self._final_claim_authority = authority
            self._final_claim_writer = writer
            natural = self._v2_natural_readiness_receipt
            route = getattr(writer, "route_port", None)
            if (type(natural) is _InstalledNaturalReplyReadinessReceiptV2
                    and natural.installation is installation
                    and natural.worker is worker
                    and natural.coordinator is self._v2_coordinator
                    and natural.fence_port is port
                    and natural.policy is policy
                    and natural.grant == grant
                    and natural.owner_loop is host_loop
                    and type(verified) is VerifiedFinalHandoffPairingV1
                    and verified.binding is binding
                    and getattr(writer, "graph", None)
                       is self._v2_coordinator
                    and getattr(writer, "port", None) is port
                    and getattr(writer, "issuer_id", None)
                       == verified.issuer_id
                    and type(route) is InstalledDispatchRoutePort
                    and route._context is host_context
                    and route._host_loop is host_loop
                    and route._candidates is candidates
                    and route._coordinator is self._v2_coordinator
                    and route._authority is authority
                    and route._lease is lease
                    and route._namespace == policy.namespace
                    and natural.model_selection_port._context is host_context):
                self._v2_natural_readiness_receipt = replace(
                    natural, verified_handoff=verified, p2_writer=writer,
                    p2_context=host_context, p2_candidates=candidates)
            return verified, writer

    async def uninstall_final_handoff_pairing_v1(self) -> None:
        async with self._lock:
            lease, self._final_claim_lease = self._final_claim_lease, None
            self._final_claim_authority = None
            self._final_claim_writer = None
            natural = self._v2_natural_readiness_receipt
            if type(natural) is _InstalledNaturalReplyReadinessReceiptV2:
                self._v2_natural_readiness_receipt = replace(
                    natural, verified_handoff=None, p2_writer=None,
                    p2_context=None, p2_candidates=None)
            if lease is not None and self._worker is not None and self._v2_bootstrap is not None:
                await self._worker.call(lambda graph: graph.release_authority_lease(
                    self._v2_bootstrap, lease))

    async def dispatch_owned_private_reply_v1(
        self, *, ingress_operation_id: str, handler_invocation_id: str,
        server: HostReverseGraphClaimServer, host_context: object,
        candidates: object,
    ):
        """Continue only the installed original after the handler's takeover.

        The driver rereads durable SYLANNE_OWNED and the sealed original; this
        entry never accepts a caller-provided ownership or send credential.
        """
        from .host.private_reply_dispatch_driver import (
            InstalledPrivateReplyContinuationV1, PrivateReplyDispatchDriver,
        )
        from .host.installed_dispatch_route import InstalledDispatchRoutePort
        from .host.reverse_handoff import HostReverseGraphClaimServer
        from .host.scene_candidates import SceneCandidateCatalog

        async with self._lock:
            worker = self._worker
            authority = self._final_claim_authority
            lease = self._final_claim_lease
            paired_writer = self._final_claim_writer
            port = self._v2_port
            policy = self._v2_policy
            grant = self._v2_installation_grant
            bundle = self._v2_model_bundle
            bootstrap = self._v2_bootstrap
            if (worker is None or authority is None or lease is None
                    or paired_writer is None or bootstrap is None
                    or port is None or policy is None
                    or grant is None or type(bundle) is not AdminInstallationBundle
                    or type(bundle.ingress_clock) is not AdminIngressClockPolicy
                    or type(server) is not HostReverseGraphClaimServer
                    or type(candidates) is not SceneCandidateCatalog
                    or server.profile.namespace != policy.authority_namespace
                    or server.profile.installation_id != grant.installation_id
                    or self.health.status not in {"limited", "ready"}):
                return None
            host_loop = asyncio.get_running_loop()

        def install_original(graph):
            scoped, scoped_lease, ownership = (
                graph.grant_owned_reply_dispatch_scope_v1(
                    bootstrap, bundle,
                    ingress_operation_id=ingress_operation_id,
                    handler_invocation_id=handler_invocation_id))
            try:
                route = InstalledDispatchRoutePort(
                    context=host_context, host_loop=host_loop,
                    candidates=candidates, coordinator=graph,
                    authority=scoped, lease=scoped_lease,
                    policy=policy, grant=grant)
                writer = graph.register_dispatch_final_claim_writer_v1(
                    bootstrap, route_port=route,
                    issuer_id=paired_writer.issuer_id)
                return scoped, scoped_lease, ownership, writer
            except BaseException:
                graph.release_authority_lease(bootstrap, scoped_lease)
                raise

        scoped, scoped_lease, _ownership, writer = await worker.call(
            install_original)
        try:
            continuation = InstalledPrivateReplyContinuationV1(
                worker=worker, authority=scoped, lease=scoped_lease,
                fence_port=port, policy=policy, grant=grant,
                server=server, claim_writer=writer,
                context=host_context, candidates=candidates,
                clock_policy=bundle.ingress_clock,
                adapter_ref="astrbot:onebot:call_action")
            driver = PrivateReplyDispatchDriver(
                worker, scoped, scoped_lease, continuation)
            return await driver.run_once(
                ingress_operation_id=ingress_operation_id,
                handler_invocation_id=handler_invocation_id)
        finally:
            await worker.call(lambda graph: graph.release_authority_lease(
                bootstrap, scoped_lease))

    async def provision_installed_namespace(self, operation_id: str):
        """Provision the installed administrator namespace on its graph worker."""
        async with self._lock:
            if self._worker is None or self._v2_provision is None:
                raise RuntimeError("v2 graph worker is unavailable")
            try:
                receipt = await self._worker.call(self._v2_provision, operation_id)
            except V2FenceOutcomeUnknown as exc:
                self.health = RuntimeHealth(
                    "blocked", ("v2_fence_recovery",), str(exc),
                )
                raise
            except UnavailableGuard as exc:
                self.health = RuntimeHealth(
                    "blocked", ("namespace_activation",), str(exc),
                )
                raise
            except Exception:
                self.health = RuntimeHealth(
                    "blocked", ("namespace_activation",),
                    "installed namespace provisioning failed",
                )
                raise
            self._v2_namespace_provisioned = True
            # Provisioning creates the namespace, not its Owner, active role,
            # or D03 scene binding. First dialogue cannot be admitted yet.
            missing = ["owner_guard", "active_role", "scene_binding", "dispatch"]
            if self._v2_ingress is None:
                missing.insert(0, "product_ingress")
            detail = (
                "installed namespace provisioned; trusted Owner, active role, "
                "scene binding, and dispatch remain pending"
            )
            if self._v2_missing_ingress_policies:
                detail += "; ingress requires " + ", ".join(self._v2_missing_ingress_policies)
            if (type(self._v2_model_bundle) is AdminInstallationBundle
                    and self._v2_cost_transport is None):
                detail += "; model egress and C02 HOLD: paired Authority TLS unavailable"
            self.health = RuntimeHealth(
                "limited", tuple(missing), detail,
            )
            return receipt

    async def run_post_c02_appraisal_v3(self, installation, *, context, trusted_umo, c02_operation_id, source_ref):
        from .host.installed_d04_appraisal_driver_v3 import run_installed_post_c02_appraisal_v3
        return await run_installed_post_c02_appraisal_v3(self, installation, context=context, trusted_umo=trusted_umo,
            c02_operation_id=c02_operation_id, source_ref=source_ref)

    async def run_installed_contact_model_v1(self, installation, *, context, trusted_umo, contact_id, phase):
        from .host.installed_contact_model_driver_v1 import run_installed_contact_model_v1
        return await run_installed_contact_model_v1(self, installation, context=context,
            trusted_umo=trusted_umo, contact_id=contact_id, phase=phase)

    async def run_installed_contact_model_v2(self, installation, *, context, trusted_umo, contact_id, phase):
        from .host.installed_contact_model_driver_v2 import run_installed_contact_model_v2
        return await run_installed_contact_model_v2(self, installation, context=context,
            trusted_umo=trusted_umo, contact_id=contact_id, phase=phase)

    async def dispatch_committed_contact_v3(self, installation, *, operation_id,
            context, server, listener, candidates):
        """Read the actual single Contact original through installed gates.

        The registered Contact writer currently refuses before P0. The final
        write's six checks cannot substitute for a current P2 qualification.
        """
        from .host.contact_dispatch_driver_v3 import (
            ContactDispatchDriverV3, ContactDispatchResultV3,
            InstalledContactContinuationV3,
        )
        from .host.installed_dispatch_route import InstalledDispatchRoutePort
        from .host.reverse_handoff import HostReverseGraphClaimServer
        from .host.scene_candidates import SceneCandidateCatalog
        from .host.v2_fence_port import V2FencePort
        if (type(installation) is not V2InstallationAssembly
                or installation.admin_bundle is not self._v2_model_bundle
                or installation.installation_policy is not self._v2_policy
                or installation.installation_grant != self._v2_installation_grant
                or installation.data_dir != self._data_dir
                or type(self._worker) is not GraphWorker
                or type(self._v2_port) is not V2FencePort
                or self._v2_bootstrap is None or not self._v2_namespace_provisioned
                or self._final_claim_writer is None
                or type(server) is not HostReverseGraphClaimServer
                or type(candidates) is not SceneCandidateCatalog
                or not isinstance(listener, asyncio.AbstractServer) or not listener.is_serving()
                or installation.reverse_handoff is None
                or server.profile is not installation.reverse_handoff.profile
                or self.health.status not in {'limited', 'ready'}
                or type(operation_id) is not str or not operation_id):
            return ContactDispatchResultV3('hold', 'qualified installed Contact handoff unavailable')
        worker, port, bootstrap = self._worker, self._v2_port, self._v2_bootstrap
        policy, grant, bundle = (installation.installation_policy,
            installation.installation_grant, installation.admin_bundle)
        host_loop = asyncio.get_running_loop()
        def install(graph):
            pairing = port.read_final_handoff_pairing_v1(
                namespace=policy.authority_namespace, installation_id=grant.installation_id)
            verified = verify_final_handoff_pairing_v1(pairing, installation, installation.reverse_handoff)
            anchor = port.current_anchor(namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(bootstrap, actor=grant.administrator_holder,
                issuer_domain='d11', namespace=policy.namespace,
                domains=('d03', 'd05', 'd06', 'd08', 'd09', 'd10', 'd11'),
                activation_generation=anchor.activation_generation, operation_id=operation_id)
            try:
                authority = AuthorityContext(grant.administrator_holder, 'd11', capability,
                    policy.namespace, ('activity',), 'expression', ('internal',),
                    policy.root_grant.policy_ref, anchor.activation_generation)
                route = InstalledDispatchRoutePort(context=context, host_loop=host_loop,
                    candidates=candidates, coordinator=graph, authority=authority, lease=lease,
                    policy=policy, grant=grant)
                writer = graph.register_contact_dispatch_final_claim_writer_v3(bootstrap,
                    route_port=route, issuer_id=verified.issuer_id)
                return authority, lease, writer
            except BaseException:
                graph.release_authority_lease(bootstrap, lease)
                raise
        try:
            authority, lease, writer = await worker.call(install)
        except Exception as exc:
            return ContactDispatchResultV3('hold', str(exc))
        try:
            continuation = InstalledContactContinuationV3(worker=worker, authority=authority,
                lease=lease, fence_port=port, policy=policy, grant=grant, server=server,
                claim_writer=writer, context=context, candidates=candidates,
                clock_policy=bundle.ingress_clock)
            return await ContactDispatchDriverV3(worker, authority, lease, continuation).run_once(
                operation_id=operation_id)
        finally:
            await worker.call(lambda graph: graph.release_authority_lease(bootstrap, lease))

    def queue_post_c02_numeric_v3(self, installation, *, c02_operation_id, source_ref):
        """Wake one bounded stage from its already adopted appraisal original."""
        if (self._d04_numeric_stopping or self._worker is None
                or installation is not getattr(self._v2_natural_readiness_receipt, "installation", None)
                or installation.admin_bundle.d04_joint_numeric is None
                or installation.admin_bundle.d04_semantic_drive is None
                or c02_operation_id in self._d04_numeric_tasks
                or c02_operation_id in self._d04_numeric_attempted):
            return False
        if len(self._d04_numeric_tasks) >= 8:
            # The input remains in the actual committed appraisal ledger;
            # bounded discovery resumes it when the current stage finishes.
            return False
        async def run():
            from .host.installed_d04_numeric_driver_v3 import run_installed_post_c02_numeric_v3
            async with self._d04_numeric_semaphore:
                if self._d04_numeric_stopping:
                    return
                try:
                    result = await run_installed_post_c02_numeric_v3(self, installation,
                        c02_operation_id=c02_operation_id, source_ref=source_ref)
                    self._d04_numeric_last_status = dict(result)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self._d04_numeric_last_status = {"status": "hold", "error_code": type(exc).__name__,
                        "c02_operation_id": c02_operation_id}
        task = asyncio.create_task(run())
        self._d04_numeric_tasks[c02_operation_id] = task
        def done(_task):
            self._d04_numeric_tasks.pop(c02_operation_id, None)
            if len(self._d04_numeric_attempted) >= 4096:
                self._d04_numeric_attempted.clear()
            self._d04_numeric_attempted.add(c02_operation_id)
            if not self._d04_numeric_stopping:
                self.resume_pending_d04_numeric_v3(installation)
        task.add_done_callback(done)
        return True

    def resume_pending_d04_numeric_v3(self, installation):
        if (self._d04_numeric_stopping or self._worker is None
                or self._d04_numeric_scan_task is not None and not self._d04_numeric_scan_task.done()
                or installation is not getattr(self._v2_natural_readiness_receipt, "installation", None)
                or installation.admin_bundle.d04_joint_numeric is None):
            return
        async def scan():
            from .runtime.d04_numeric_discovery_v3 import discover_pending_d04_numeric_v3
            try:
                page = await self._worker.call(lambda graph: discover_pending_d04_numeric_v3(
                    graph, self._v2_bootstrap, installation.admin_bundle,
                    after=self._d04_numeric_scan_after, limit=32))
                self._d04_numeric_scan_after = page["next_after"]
                for item in page["items"]:
                    self.queue_post_c02_numeric_v3(installation, **item)
            except Exception as exc:
                self._d04_numeric_last_status = {"status": "recovery_discovery_hold", "error_code": type(exc).__name__}
                return
            finally:
                self._d04_numeric_scan_task = None
            if (self._d04_numeric_scan_after is not None and not self._d04_numeric_stopping
                    and len(self._d04_numeric_tasks) < 8):
                # Continue the actual stable cursor even when this page had
                # only completed/held originals; no new ingress is required.
                asyncio.get_running_loop().call_soon(self.resume_pending_d04_numeric_v3, installation)
        self._d04_numeric_scan_task = asyncio.create_task(scan())

    def resume_pending_domain_followups_v1(self, installation):
        if self._domain_followup_stopping or self._worker is None:
            return
        if self._domain_followup_task is not None and not self._domain_followup_task.done():
            self._domain_followup_rescan_requested = True
            return
        self._domain_followup_rescan_requested = False
        async def consume():
            cursor = ""
            try:
                while not self._domain_followup_stopping:
                    def page(graph):
                        graph._admin(self._v2_bootstrap)
                        store = graph._GraphCoordinator__store
                        with store._lock:
                            return tuple(row[0] for row in store._db.execute(
                                "SELECT dedupe_key FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? "
                                "AND state IN ('pending','waiting') AND dedupe_key>? ORDER BY dedupe_key LIMIT 32",
                                (*installation.installation_policy.namespace.as_tuple, cursor)))
                    keys = await self._worker.call(page)
                    if not keys:
                        break
                    for key in keys:
                        if self._domain_followup_stopping:
                            break
                        try:
                            await self._worker.call(lambda graph, selected=key: graph.consume_current_domain_followup_v1(
                                self._v2_bootstrap, installation.admin_bundle, dedupe_key=selected))
                        except Exception as exc:
                            self._domain_followup_last_hold = type(exc).__name__
                        cursor = key
                        await asyncio.sleep(0)
                    if len(keys) < 32:
                        break
            finally:
                self._domain_followup_task = None
                if self._domain_followup_rescan_requested and not self._domain_followup_stopping:
                    asyncio.get_running_loop().call_soon(self.resume_pending_domain_followups_v1, installation)
        self._domain_followup_task = asyncio.create_task(consume())

    def resume_host_lifecycle_observation_v1(self):
        """Record a paired runtime boundary only when actual Owner rights exist."""
        if (self._worker is None or self._host_lifecycle_observer is None
                or self._host_lifecycle_startup_receipt is not None
                or self.health.status not in {"limited", "ready"}
                or not self._v2_namespace_provisioned
                or self._host_lifecycle_startup_task is not None and not self._host_lifecycle_startup_task.done()):
            return
        async def record():
            try:
                from .runtime.d10_offline_recovery_driver_v1 import close_pre_reconnect_offline_page_v1
                cursor = ""
                while not self._offline_recovery_stopping:
                    closed = await self._worker.call(lambda graph, selected=cursor:
                        close_pre_reconnect_offline_page_v1(self, graph, after_ref=selected))
                    self._offline_recovery_last_status = closed
                    if closed["status"] == "held":
                        self._host_lifecycle_last_status = closed
                        return
                    if closed["status"] == "closed":
                        break
                    cursor = closed["after_ref"]
                    await asyncio.sleep(0)
                if self._offline_recovery_stopping:
                    return
                observation = self._host_lifecycle_observer.capture_startup_v1()
                from .runtime.d11_host_lifecycle_driver_v1 import record_current_host_lifecycle_v1
                result = await self._worker.call(lambda graph: record_current_host_lifecycle_v1(
                    graph, self._v2_bootstrap, self._v2_model_bundle,
                    observer=self._host_lifecycle_observer, observation=observation))
                self._host_lifecycle_last_status = result
                if result.get("schema") == "sylanne.domain-production-receipt.v1" and result.get("coverage") == "complete":
                    self._host_lifecycle_startup_receipt = result
                    self.resume_offline_recovery_v1()
            except Exception as exc:
                self._host_lifecycle_last_status = {"status": "held", "error_code": type(exc).__name__}
            finally:
                self._host_lifecycle_startup_task = None
        self._host_lifecycle_startup_task = asyncio.create_task(record())

    def resume_offline_recovery_v1(self):
        """Advance genuine registered downtime one claimed tick at a time."""
        if (self._worker is None or self._offline_recovery_stopping
                or self.health.status not in {"ready", "limited"}
                or self._host_lifecycle_startup_receipt is None
                or self._offline_recovery_task is not None and not self._offline_recovery_task.done()):
            return
        async def recover():
            try:
                from .runtime.d10_offline_recovery_driver_v1 import recover_current_offline_tick_v1
                while not self._offline_recovery_stopping and self.health.status in {"ready", "limited"}:
                    result = await self._worker.call(lambda graph: recover_current_offline_tick_v1(self, graph))
                    self._offline_recovery_last_status = result
                    if result["status"] != "progressed":
                        break
                    await asyncio.sleep(0)
            except Exception as exc:
                self._offline_recovery_last_status = {"status": "held", "error_code": type(exc).__name__}
            finally:
                self._offline_recovery_task = None
        self._offline_recovery_task = asyncio.create_task(recover())

    async def resume_pending_d07_v1(self):
        service = self._v2_d07_execution_service
        if service is None or self._worker is None:
            return
        await service.resume_pending_jobs_v1()

    async def prepare_current_c04_work_v3(self, authority, lease, **request):
        if self._worker is None or self._v2_coordinator is None:
            raise UnavailableGuard("installed C04 graph worker is unavailable")
        return await self._worker.call(lambda graph: graph.prepare_internal_work_v3(authority, lease, **request))

    async def advance_current_c04_work_v3(self, authority, lease, operation_id, *, holder, lease_seconds=300):
        if self._worker is None or self._v2_coordinator is None:
            raise UnavailableGuard("installed C04 graph worker is unavailable")
        return await self._worker.call(lambda graph: graph.advance_current_c04_product_v3(
            authority, lease, operation_id, holder=holder, lease_seconds=lease_seconds))

    async def refresh_capabilities(self, *, scene_ref: str | None = None) -> RuntimeHealth:
        """Probe current Owner, role and optional exact scene on the graph worker.

        The result is diagnostic only. A later ingress must obtain fresh
        Owner, role and scene proofs inside its own fenced operation.
        """
        async with self._lock:
            if (self._worker is None or not self._v2_namespace_provisioned
                    or self._v2_role_probe is None or self.health.status == "blocked"):
                return self.health
            if scene_ref is not None and (
                    not isinstance(scene_ref, str) or not scene_ref.startswith("scene:")
                    or len(scene_ref) == len("scene:")):
                raise ValueError("scene_ref must identify a scene")
            try:
                if scene_ref is None:
                    role = await self._worker.call(self._v2_role_probe)
                    scene = None
                else:
                    role, scene = await self._worker.call(self._v2_scene_probe, scene_ref)
                if (type(role) is not ActiveRoleQualification
                        or role.namespace != self._v2_namespace):
                    raise ValueError("current role probe returned an invalid qualification")
                if scene_ref is not None and (
                        type(scene) is not RoleBinding or scene.scene_ref != scene_ref
                        or scene.subject_persona_ref != f"persona:{self._v2_namespace.persona_id}"):
                    raise ValueError("current scene probe returned an invalid binding")
            except V2FenceOutcomeUnknown as exc:
                self.health = RuntimeHealth(
                    "blocked", ("v2_fence_recovery",), str(exc),
                )
                return self.health
            except (UnavailableGuard, StaleRead, ValueError):
                owner_role = ("owner_guard", "active_role")
                scene_ready = False
            else:
                owner_role = ()
                scene_ready = scene_ref is not None
            missing = list(owner_role) + ["scene_binding", "dispatch"]
            if self._v2_ingress is None:
                missing.insert(0, "product_ingress")
            if owner_role:
                detail = "trusted Owner and active role remain unavailable"
            elif scene_ready:
                detail = (
                    "current scene binding record exists; message-time eligibility "
                    "and dispatch remain pending"
                )
            else:
                detail = "current Owner and role checked; scene-specific proof and dispatch remain pending"
            if (type(self._v2_model_bundle) is AdminInstallationBundle
                    and self._v2_cost_transport is None):
                detail += "; model egress and C02 HOLD: paired Authority TLS unavailable"
            self.health = RuntimeHealth(
                "limited", tuple(missing), detail,
            )
            if not owner_role:
                self.resume_host_lifecycle_observation_v1()
            return self.health

    @property
    def v2_installed_model_selected(self) -> bool:
        """Installed selection eligibility only; model egress remains fenced/HOLD."""
        return self._v2_installed_model_selected

    @property
    def v2_installed_model_config_matched(self) -> bool:
        """Startup match of exact installed adapter, model and config identity."""
        return self._v2_installed_model_config_matched

    @property
    def v2_ingress_qualified(self) -> bool:
        """Only the installed v2 ingress path is eligible for a graph attempt."""
        policy = self._v2_policy
        grant = self._v2_installation_grant
        return (
            self.health.status in {"limited", "ready"}
            and self._worker is not None
            and self._v2_namespace_provisioned
            and type(policy) is AdminInstallationPolicy
            and type(grant) is InstallationGrantV2
            and self._v2_namespace == policy.namespace
            and grant.authority_id == policy.expected_authority_id
            and grant.installation_id == policy.installation_id
            and grant.administrator_holder == policy.administrator_holder
            and grant.manifest_digest == policy.manifest_digest
            and not self._v2_missing_ingress_policies
            and callable(self._v2_ingress)
        )

    @property
    def workbench_owner_sessions(self) -> BoundOwnerSessions | None:
        return self._workbench_owner_sessions

    @property
    def reply_suppression_registry(self) -> HostReplySuppressionRegistryV1:
        """The installed handler-local proof issuer paired with this graph."""
        return self._reply_suppression_registry

    def reply_takeover_port_v1(
        self, envelope: HostIngressEnvelope, receipt: IngressReceipt,
        *, deadline_monotonic: float,
    ) -> InstalledReplyTakeoverRuntimePortV1:
        policy = self._v2_policy
        bundle = self._v2_model_bundle
        if (type(policy) is not AdminInstallationPolicy
                or type(bundle) is not AdminInstallationBundle
                or type(bundle.private_reply_dispatch)
                   is not AdminPrivateReplyDispatchPolicy
                or envelope.namespace != policy.namespace
                or self._worker is None or self._v2_port is None
                or self._v2_bootstrap is None):
            raise RuntimeError("installed private reply takeover is unavailable")
        return InstalledReplyTakeoverRuntimePortV1(
            self, envelope, receipt, deadline_monotonic)

    def installed_owner_onboarding_ports(self) -> InstalledOwnerOnboardingPorts:
        """Expose only the installed, live V2 Owner facts for onboarding."""
        if (self._worker is None or not self._v2_namespace_provisioned
                or self._v2_policy is None or self._v2_port is None
                or self._v2_coordinator is None or self._v2_bootstrap is None):
            raise RuntimeError("installed Owner onboarding authority is unavailable")
        return InstalledOwnerOnboardingPorts(
            policy=self._v2_policy, authority=self._v2_port,
            coordinator=self._v2_coordinator, bootstrap=self._v2_bootstrap,
        )

    def workbench_transport(self, *, pairing: CurrentOwnerPairingPort | None = None,
                            owner_grants: CurrentOwnerGrantPort | None = None,
                            onboarding: OnboardingPolicyResolver,
                            origin: str) -> WorkbenchHttpTransport:
        """Compose D12 from the installed V2 port or explicit trusted ports."""
        if self._worker is None or not self._v2_namespace_provisioned:
            raise RuntimeError("v2 graph namespace is unavailable")
        if (pairing is None) != (owner_grants is None):
            raise TypeError("Owner pairing and grant ports must be supplied together")
        if pairing is None:
            policy = self._v2_policy
            port = self._v2_port
            grant = self._v2_installation_grant
            if (not isinstance(policy, AdminInstallationPolicy)
                    or not isinstance(port, V2FencePort)
                    or not isinstance(grant, InstallationGrantV2)
                    or not isinstance(self._v2_coordinator, GraphCoordinator)
                    or self._v2_bootstrap is None
                    or self._v2_owner_actor is None
                    or policy.namespace != self._v2_namespace
                    or policy.authority_namespace != namespace_ref(policy.namespace)
                    or grant.authority_id != policy.expected_authority_id
                    or grant.installation_id != policy.installation_id
                    or not isinstance(origin, str) or not origin.startswith("https://")):
                raise RuntimeError("installed Owner workbench authority is unavailable")
            pairing = BoundOwnerSessions(
                authority=port, worker=self._worker, bootstrap=self._v2_bootstrap,
                owner_actor=self._v2_owner_actor, namespace=policy.namespace,
                authority_id=policy.expected_authority_id,
                installation_id=policy.installation_id, origin=origin,
                operation_status_port=(self._v2_d12_backend_port.operation_status_port
                    if self._v2_d12_backend_port is not None else None),
                package_maintenance_port=self._v2_package_maintenance_port)
            owner_grants = GraphCurrentOwnerGrantPort(
                self._v2_coordinator, self._v2_bootstrap,
                namespace=policy.namespace, activation_generation=1,
                domains=tuple(sorted(self._domains.registrations)),
            )
        if not callable(getattr(owner_grants, "resolve_current_owner", None)):
            raise TypeError("current W01 Owner grant port is required")
        if (not callable(getattr(onboarding, "resolve_create_character", None))
                or not callable(getattr(onboarding, "resolve_bind_scene", None))):
            raise TypeError("trusted onboarding policy resolver is required")
        sessions = CurrentOwnerDashboardSessions(pairing)
        bundle = self._v2_model_bundle
        support_export_root = self._data_dir / "support_exports"
        support_export_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        service = AsyncGraphWorkbenchService(
            self._worker, DurableOwnerGrantResolver(owner_grants),
            CurrentDomainViewRegistry(lambda: self._domains), onboarding,
            self._v2_policy,
            bundle.d06_source_correction if bundle is not None else None,
            scheme_port=self._v2_coordinator,
            d04_root_resource_resolver=InstalledD04RootResources(
                namespace=self._v2_policy.namespace,
                package_root=self._package_root,
                trusted_manifest_sha256=self._v2_policy.manifest_digest,
                read_current_dedicated_lease=(
                    self._v2_coordinator.read_current_d04_root_budget_lease_v3),
                available_cpu_features=self._v2_available_cpu_features),
            support_export_root=support_export_root,
            authority_client=self._v2_authority_client,
            authority_bundle=bundle,
            authority_grant=self._v2_authority_client_grant,
            authority_loop=self._v2_authority_loop,
            backend_operation_port=self._v2_d12_backend_port,
            package_maintenance_port=self._v2_package_maintenance_port)
        transport = WorkbenchHttpTransport(
            service, sessions, BoundCsrfTokens(),
            TransportConfig(origin, self._package_root / "resources" / "workbench"))
        self._workbench_owner_sessions = (
            pairing if isinstance(pairing, BoundOwnerSessions) else None)
        return transport

    async def start(self) -> RuntimeHealth:
        async with self._lock:
            if "v2_fence_recovery" in self.health.missing_capabilities:
                return self.health
            if self._worker is not None:
                return self.health
            if self.health.status == "ready":
                return self.health
            missing_capabilities = []
            details = []
            if not self._domains.complete:
                detail = "; ".join(
                    f"{domain}: {reason}" for domain, reason in self._domains.unavailable.items()
                )
                missing_capabilities.append("domain_registry")
                details.append(detail)
            if self._dependencies is None:
                missing_capabilities.extend(
                    (
                        "external_runtime_authorities", "content_fence",
                        "ingress_policy", "ingress_clock", "ingress_handler_factory",
                    )
                )
                details.append(
                    "installation-level authorities require an administrator-paired "
                    "Sylanne Authority; AstrBot chat configuration is not a trust root"
                )
            if missing_capabilities:
                self.health = RuntimeHealth(
                    "enrollment_required"
                    if (
                        self._domains.complete
                        and self._dependencies is None
                        and self._authority_state == "enrollment_required"
                    )
                    else "blocked",
                    tuple(missing_capabilities),
                    "; ".join(details),
                )
                return self.health
            assert self._dependencies is not None
            missing = self._dependencies.missing()
            if missing:
                self.health = RuntimeHealth("blocked", missing, "runtime dependency set is incomplete")
                return self.health
            manifest_path = self._package_root / "release-manifest.json"
            if not manifest_path.is_file() or manifest_path.is_symlink():
                self.health = RuntimeHealth(
                    "blocked", ("package_manifest",),
                    "trusted release-manifest.json is missing or unsafe",
                )
                return self.health
            manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            if not hmac.compare_digest(
                manifest_digest, self._dependencies.package_manifest_sha256
            ):
                self.health = RuntimeHealth(
                    "blocked", ("package_manifest",),
                    "installer authority attestation does not match this package manifest",
                )
                return self.health
            if inspect_native_data_dir_v1(self._data_dir).status == "migration_required":
                self.health = RuntimeHealth("blocked", ("migration_required",),
                                            "unmigrated plugin data needs explicit migration proof")
                return self.health
            self._data_dir.mkdir(parents=True, exist_ok=True)
            store = await asyncio.to_thread(
                ProductionGraphStore,
                self._data_dir / "sylanne3.sqlite3",
                self._domains.type_registry,
            )
            bootstrap = object()
            try:
                coordinator = GraphCoordinator(
                    store,
                    bootstrap,
                    deletion_journal=self._dependencies.deletion_journal,
                    migration_authority=self._dependencies.migration_authority,
                    restore_authority=self._dependencies.restore_authority,
                    execution_journal_port=self._dependencies.execution_journal_port,
                    snapshot_requirements=self._dependencies.snapshot_requirements,
                    holder=self._dependencies.holder,
                    content_fence=self._dependencies.content_fence,
                    closure_verifier=self._dependencies.closure_verifier,
                    d02_issuer=self._dependencies.d02_issuer,
                    d11_issuer=self._dependencies.d11_issuer,
                    ingress_policy=self._dependencies.ingress_policy,
                    ingress_clock=self._dependencies.ingress_clock,
                )
                for registration in self._domains.registrations.values():
                    coordinator.register_provider(
                        bootstrap,
                        registration.domain,
                        registration.provider,
                        registration.proposal_schema,
                        registration.proposal_schema_hash,
                    )
                try:
                    handler = self._dependencies.ingress_handler_factory(coordinator, bootstrap)
                except Exception:
                    self.health = RuntimeHealth(
                        "blocked", ("ingress_handler",),
                        "trusted ingress factory could not initialize",
                    )
                    await asyncio.to_thread(store.close)
                    return self.health
                if not callable(handler) or not (
                    inspect.iscoroutinefunction(handler)
                    or inspect.iscoroutinefunction(getattr(handler, "__call__", None))
                ):
                    self.health = RuntimeHealth(
                        "blocked", ("ingress_handler",),
                        "trusted ingress factory did not return an async handler",
                    )
                    await asyncio.to_thread(store.close)
                    return self.health
            except BaseException:
                await asyncio.to_thread(store.close)
                raise
            self._store = store
            self._coordinator = coordinator
            self._ingress_handler = handler
            self.health = RuntimeHealth("ready")
            return self.health

    async def execute_first_ingress_encoding_v2(
        self, authority: AuthorityContext, lease: object,
        job_id: str, acquire_operation_id: str, *,
        executor: HostModelEgressExecutor,
    ) -> FrozenEncodingEgressResult | None:
        """Read original graph and Authority facts, then attempt the fenced call.

        The worker's read is the only request source. The separate Authority
        admission rechecks its current graph, budget and model configuration.
        An unresolved return is a HOLD under the original operation identity.
        """
        if (type(executor) is not HostModelEgressExecutor
                or type(authority) is not AuthorityContext
                or self._worker is None
                or self._v2_cost_transport is None
                or not self._v2_namespace_provisioned
                or authority.namespace != self._v2_namespace
                or executor._bundle is not self._v2_model_bundle
                or executor._grant != self._v2_installation_grant
                or executor._bundle.installation_policy != self._v2_policy):
            return None
        try:
            binding, draft, expected_anchor = await self._worker.call(
                lambda graph, auth, bound_lease, job, acquire: (
                    graph.read_first_ingress_model_egress_preparation_v2(
                        auth, bound_lease, job, acquire)),
                authority, lease, job_id, acquire_operation_id,
            )
        except Exception:
            return None
        if binding.request.get("schema") != "sylanne.first-ingress-encoding-call.v3":
            return None
        return await executor.execute_frozen_encoding_once(
            binding=binding, draft=draft, expected_anchor=expected_anchor)

    async def commit_first_ingress_pre_encoding_stages_v1(
        self, envelope: HostIngressEnvelope, receipt: IngressReceipt,
    ) -> FirstIngressPreEncodingStagesV1 | None:
        """Commit D03 then D04 for the original accepted C01 job.

        W01 obtains its own current Authority receipts and write fences. A
        missing policy, unresolved stage, or unverifiable receipt stays HOLD.
        This method does not acquire the job or call the model.
        """
        bundle = self._v2_model_bundle
        policy = self._v2_policy
        if (type(envelope) is not HostIngressEnvelope
                or type(receipt) is not IngressReceipt
                or receipt.status != "accepted"
                or self._worker is None or self._v2_bootstrap is None
                or not self._v2_namespace_provisioned
                or type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or bundle.installation_policy != policy
                or envelope.namespace != policy.namespace
                or type(bundle.ingress_clock) is not AdminIngressClockPolicy
                or type(bundle.d03_self_identity_projection)
                   is not AdminD03SelfIdentityProjectionPolicy
                or type(bundle.d04_encoding_baseline)
                   is not AdminD04EncodingBaselinePolicy):
            return None
        _, _, ingress_id, job_id, _, _ = ingress_ids(
            envelope.lineage.source_ref)
        if receipt.operation_id != ingress_id:
            return None

        def committed_stage(value, prefix, required_types):
            return (type(value) is CommitReceipt
                    and value.status in {"committed", "duplicate"}
                    and value.operation_id.startswith(prefix)
                    and {version.key.type_name for version in value.write_versions}
                    >= required_types
                    and all(NamespaceId.from_key(version.key) == policy.namespace
                            for version in value.write_versions))

        try:
            d03 = await self._worker.call(
                lambda graph: graph.commit_d03_self_identity_projection_v1(
                    self._v2_bootstrap, policy.namespace, job_id, ingress_id,
                    policy, bundle.d03_self_identity_projection,
                    bundle.ingress_clock))
            if not committed_stage(
                    d03, "d03-self-projection-",
                    {"d03.self_identity_mapping.v1", "d03.self_perspective.v1"}):
                return None
            d04 = await self._worker.call(
                lambda graph: graph.commit_d04_encoding_baseline_v1(
                    self._v2_bootstrap, policy.namespace, job_id, ingress_id,
                    policy, bundle.d04_encoding_baseline,
                    bundle.ingress_clock))
        except Exception:
            return None
        if not committed_stage(d04, "d04-baseline-", {"d04.encoding_baseline.v1"}):
            return None
        return FirstIngressPreEncodingStagesV1(
            policy.namespace, ingress_id, job_id, d03, d04)

    async def read_first_ingress_encoding_for_owner_v2(
        self, authority: AuthorityContext, lease: object,
        job_id: str, acquire_operation_id: str, *,
        intent: ModelEgressIntentV1,
        owner_actor_id: str,
        owner_session_request: OwnerSessionLoginRequestV1,
        owner_session_token: str,
        executor: HostModelEgressExecutor,
    ) -> OriginalFirstIngressRead | None:
        """Use the current job fence before an Owner-qualified original read.

        The graph worker returns only the original preparation. Both Authority
        queries run afterward on the host loop, outside the graph lock.
        """
        if (type(executor) is not HostModelEgressExecutor
                or type(authority) is not AuthorityContext
                or self._worker is None
                or not self._v2_namespace_provisioned
                or authority.namespace != self._v2_namespace
                or executor._bundle is not self._v2_model_bundle
                or executor._grant != self._v2_installation_grant
                or executor._bundle.installation_policy != self._v2_policy):
            return None
        try:
            binding, draft, expected_anchor = await self._worker.call(
                lambda graph, auth, bound_lease, job, acquire: (
                    graph.read_first_ingress_model_egress_preparation_v2(
                        auth, bound_lease, job, acquire)),
                authority, lease, job_id, acquire_operation_id)
        except Exception:
            return None
        return await executor.read_original_for_owner(
            binding=binding, draft=draft, expected_anchor=expected_anchor,
            intent=intent, owner_actor_id=owner_actor_id,
            owner_session_request=owner_session_request,
            owner_session_token=owner_session_token)

    async def commit_first_ingress_model_cost_v1(
        self, result: FrozenEncodingEgressResult,
    ):
        """Settle only the original observed call through W01's cost transaction.

        An unresolved fence or lost graph response is HOLD. Re-entry with the
        same intent uses W01's persisted call ID and fence attempt; it never
        re-admits the model and never implies D06 candidate adoption.
        """
        if (type(result) is not FrozenEncodingEgressResult
                or result.terminal is None
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_namespace is None
                or self._v2_cost_transport is None):
            return None
        intent = result.intent
        namespace = self._v2_namespace
        policy = self._v2_policy
        if (type(intent) is not ModelEgressIntentV1
                or policy is None
                or (intent.authority_id, intent.namespace) !=
                   (policy.expected_authority_id, policy.authority_namespace)
                or result.terminal.call_id != intent.call_id
                or result.terminal.request_digest != intent.request_digest):
            return None
        quote_id = "ingress-q-" + hashlib.sha256(canonical_json([
            *namespace.as_tuple, intent.budget_reservation_operation_id,
        ]).encode()).hexdigest()[:40]
        try:
            return await self._worker.call(
                lambda graph: graph.commit_first_ingress_model_cost_v1(
                    self._v2_bootstrap, namespace, intent,
                    quote_id=quote_id, quote_version=1))
        except Exception:
            return None

    @asynccontextmanager
    async def acquired_first_ingress_encoding_v2(
        self, envelope: HostIngressEnvelope, receipt: IngressReceipt, *,
        executor: HostModelEgressExecutor,
        original_recovery: FirstIngressRecoveryItemV1 | None = None,
    ) -> AsyncIterator[AcquiredFirstIngressEncodingV2 | None]:
        """Acquire only baseline-backed V3 work and keep its D11 lease alive.

        The caller may settle the original cost and read its result context
        before leaving this scope. No model call occurs merely by acquiring it.
        """
        if (type(envelope) is not HostIngressEnvelope
                or type(receipt) is not IngressReceipt
                or receipt.status != "accepted"
                or self._worker is None
                or self._v2_cost_transport is None
                or self._v2_policy is None
                or self._v2_port is None
                or self._v2_bootstrap is None
                or self._v2_installation_grant is None
                or self._v2_model_bundle is None
                or self._v2_model_bundle.model_workflows is None
                or envelope.namespace != self._v2_namespace):
            yield None
            return
        _, _, ingress_operation_id, job_id, _, _ = ingress_ids(
            envelope.lineage.source_ref)
        if receipt.operation_id != ingress_operation_id:
            yield None
            return
        if original_recovery is not None and (
                type(original_recovery) is not FirstIngressRecoveryItemV1
                or original_recovery.recovery_state != "original_fence"
                or original_recovery.namespace != envelope.namespace
                or original_recovery.installation_id
                   != self._v2_installation_grant.installation_id
                or original_recovery.job_id != job_id
                or original_recovery.original_operation_id
                   != ingress_operation_id
                or original_recovery.original_worker_actor
                   != self._v2_installation_grant.subject):
            yield None
            return
        workflow = self._v2_model_bundle.model_workflows.encode
        if (type(workflow) is not AdminModelWorkflowV2
                or envelope.conversation_ref not in workflow.audiences):
            yield None
            return
        policy = self._v2_policy
        port = self._v2_port
        bootstrap = self._v2_bootstrap
        actor = self._v2_installation_grant.subject
        lease_seconds = min(3600, math.ceil(workflow.timeout_seconds) + 120)

        def acquire(graph: GraphCoordinator):
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            generation = anchor.activation_generation
            attempt_nonce = hashlib.sha256(
                ("sylanne.first-ingress-encoding-first-attempt.v1:"
                 + self._v2_installation_grant.installation_id + ":"
                 + job_id).encode("utf-8")
            ).hexdigest()[:32]
            acquire_id = first_ingress_encoding_acquire_operation_id(
                policy.namespace, job_id, ingress_operation_id,
                actor, generation, attempt_nonce)
            if original_recovery is not None:
                acquire_id = original_recovery.acquire_operation_id
            lease, capability_ref = graph.grant(
                bootstrap, actor=actor, issuer_domain="d11",
                namespace=policy.namespace, domains=("d11",),
                activation_generation=generation,
                operation_id=acquire_id)
            try:
                authority = AuthorityContext(
                    actor, "d11", capability_ref, policy.namespace,
                    ("activity",), workflow.purpose,
                    (envelope.conversation_ref,), workflow.provider_config_ref,
                    generation)
                job = graph.acquire_first_ingress_encoding_job_v3(
                    authority, lease, job_id, acquire_id,
                    lease_seconds=lease_seconds)
                if original_recovery is not None and (
                        job.fence != original_recovery.original_worker_fence
                        or job.lease_expires_utc !=
                           original_recovery.original_worker_lease_expires_utc):
                    raise UnavailableGuard("original worker lease differs; HOLD")
            except BaseException:
                graph.release_authority_lease(bootstrap, lease)
                raise
            return (AuthorityContext(
                actor, "d11", capability_ref, policy.namespace,
                ("activity",), workflow.purpose,
                (envelope.conversation_ref,), workflow.provider_config_ref,
                generation, job.fence), lease, acquire_id)

        try:
            authority, lease, acquire_id = await self._worker.call(acquire)
        except Exception:
            yield None
            return
        try:
            yield AcquiredFirstIngressEncodingV2(
                authority, lease, job_id, acquire_id)
        finally:
            await self._worker.call(
                lambda graph: graph.release_authority_lease(bootstrap, lease))

    async def read_first_ingress_original_model_result_context_v1(
        self, acquired: AcquiredFirstIngressEncodingV2,
    ) -> OriginalModelResultContextV1 | None:
        """Read W01's historical identity while the same worker lease is live."""
        if (type(acquired) is not AcquiredFirstIngressEncodingV2
                or self._worker is None
                or acquired.authority.namespace != self._v2_namespace):
            return None
        try:
            return await self._worker.call(
                lambda graph: graph.read_first_ingress_original_model_result_context_v1(
                    acquired.authority, acquired.lease, acquired.job_id,
                    acquired.acquire_operation_id))
        except Exception:
            return None

    @asynccontextmanager
    async def prepared_first_ingress_worker_result_v1(
        self, envelope: HostIngressEnvelope, receipt: IngressReceipt, *,
        executor: HostModelEgressExecutor,
        original_recovery: FirstIngressRecoveryItemV1 | None = None,
    ) -> AsyncIterator[PreparedFirstIngressWorkerResultV1 | None]:
        """Hold the one worker lease through egress, accounting and result read.

        The worker result is fetched before releasing this same D11 lease.
        D06 candidate preparation and adoption remain separate gates.
        This scope is not scheduled until the upstream D04 baseline is committed.
        """
        async with self.acquired_first_ingress_encoding_v2(
                envelope, receipt, executor=executor,
                original_recovery=original_recovery) as acquired:
            if acquired is None:
                yield None
                return
            if original_recovery is None:
                egress = await self.execute_first_ingress_encoding_v2(
                    acquired.authority, acquired.lease, acquired.job_id,
                    acquired.acquire_operation_id, executor=executor)
            else:
                original_context = (
                    await self.read_first_ingress_original_model_result_context_v1(
                        acquired))
                egress = (None if original_context is None else
                    await executor.recover_observed_frozen_encoding(
                        context=original_context, original=original_recovery))
            if (type(egress) is not FrozenEncodingEgressResult
                    or egress.terminal is None):
                yield None
                return
            cost = await self.commit_first_ingress_model_cost_v1(egress)
            if (cost is None or getattr(cost, "status", None)
                    not in {"committed", "duplicate"}
                    or getattr(cost, "call_id", None) != egress.intent.call_id):
                yield None
                return
            context = await self.read_first_ingress_original_model_result_context_v1(
                acquired)
            if (type(context) is not OriginalModelResultContextV1
                    or context.namespace != acquired.authority.namespace
                    or (context.authority_id, context.authority_namespace,
                        context.installation_id, context.job_id,
                        context.acquire_operation_id, context.call_id,
                        context.original_operation_id, context.model_request_digest,
                        context.worker_actor,
                        context.worker_fence) != (
                        egress.intent.authority_id, egress.intent.namespace,
                        self._v2_installation_grant.installation_id,
                        acquired.job_id, acquired.acquire_operation_id,
                        egress.intent.call_id,
                        egress.intent.budget_reservation_operation_id,
                        egress.intent.request_digest,
                        egress.intent.subject, egress.intent.worker_fence)
                    or canonical_digest(context.anchor) != egress.intent.anchor_digest
                    or (context.worker_actor, context.worker_fence,
                        context.source_id, context.source_revision,
                        context.access_revision) != (
                        acquired.authority.actor, acquired.authority.worker_fence,
                        egress.intent.source_refs[0],
                        egress.intent.source_revisions[0][1],
                        egress.intent.access_revisions[0][1])):
                yield None
                return
            read_request = first_ingress_worker_result_request_v1(context)
            if original_recovery is not None:
                read_request = await executor.select_original_worker_read_attempt(
                    read_request)
                if type(read_request) is not WorkerModelResultReadRequestV1:
                    yield None
                    return
            result_read = await executor.read_original_for_worker(
                read_request=read_request, intent=egress.intent,
                terminal=egress.terminal)
            if type(result_read) is not WorkerModelResultReadV1:
                yield None
                return
            try:
                result_read.require_original_intent(egress.intent)
            except ValueError:
                yield None
                return
            if (result_read.request != read_request
                    or result_read.terminal_receipt != egress.terminal
                    or result_read.observation.digest
                       != egress.terminal.observation_digest):
                yield None
                return
            yield PreparedFirstIngressWorkerResultV1(
                egress, context, read_request, result_read)

    async def commit_first_ingress_c02_v2(
        self, envelope: HostIngressEnvelope, receipt: IngressReceipt, *,
        executor: HostModelEgressExecutor,
        original_recovery: FirstIngressRecoveryItemV1 | None = None,
    ) -> CommitReceipt | None:
        """Commit C02 while the original V3 worker lease and read remain live."""
        bundle = self._v2_model_bundle
        policy = self._v2_policy
        if (type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or bundle.installation_policy != policy
                or type(bundle.d06_first_ingress_c02)
                   is not AdminD06FirstIngressC02Policy
                or type(bundle.ingress_clock) is not AdminIngressClockPolicy
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_cost_transport is None):
            return None
        async with self.prepared_first_ingress_worker_result_v1(
                envelope, receipt, executor=executor,
                original_recovery=original_recovery) as prepared:
            if prepared is None:
                return None
            try:
                committed = await self._worker.call(
                    lambda graph: graph.commit_first_ingress_c02_v2(
                        self._v2_bootstrap, prepared.egress.intent,
                        prepared.result_read, policy,
                        bundle.d06_first_ingress_c02, bundle.ingress_clock))
            except Exception:
                return None
            if (type(committed) is not CommitReceipt
                    or committed.status not in {"committed", "duplicate"}
                    or committed.operation_id !=
                       prepared.read_request.consumer_operation_id
                    or not {"memory.episode.v1", "memory.subjective_trace.v2"}
                           <= {version.key.type_name
                               for version in committed.write_versions}
                    or any(NamespaceId.from_key(version.key) != policy.namespace
                           for version in committed.write_versions)):
                return None
            return committed

    async def commit_first_ingress_c02_v1(
        self, envelope: HostIngressEnvelope, receipt: IngressReceipt, *,
        executor: HostModelEgressExecutor,
        original_recovery: FirstIngressRecoveryItemV1 | None = None,
    ) -> CommitReceipt | None:
        """Compatibility entry; installed host always takes the v2 first seal."""
        return await self.commit_first_ingress_c02_v2(
            envelope, receipt, executor=executor,
            original_recovery=original_recovery)

    async def commit_confirmed_d13_inbound_turn_v1(
        self, *, ingress_operation_id: str, c02_operation_id: str,
        envelope: HostIngressEnvelope,
    ) -> D13InboundTurnReceiptV1 | None:
        """Record the original confirmed inbound turn under installed authority."""
        policy = self._v2_policy
        grant = self._v2_installation_grant
        port = self._v2_port
        worker = self._worker
        bootstrap = self._v2_bootstrap
        if (type(ingress_operation_id) is not str or not ingress_operation_id
                or type(c02_operation_id) is not str or not c02_operation_id
                or type(envelope) is not HostIngressEnvelope
                or type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or port is None or worker is None or bootstrap is None
                or not self._v2_namespace_provisioned
                or envelope.namespace != policy.namespace
                or policy.namespace != self._v2_namespace
                or (ingress_ids(envelope.lineage.source_ref)[2]
                    != ingress_operation_id)):
            return None

        def commit(graph: GraphCoordinator) -> D13InboundTurnReceiptV1:
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.subject, issuer_domain="d09",
                namespace=policy.namespace, domains=("d09",),
                activation_generation=anchor.activation_generation,
                operation_id=ingress_operation_id)
            try:
                authority = AuthorityContext(
                    grant.subject, "d09", capability, policy.namespace,
                    ("scene",), "context", (envelope.conversation_ref,),
                    policy.root_grant.policy_ref,
                    anchor.activation_generation)
                return graph.commit_confirmed_d13_inbound_turn_v1(
                    authority, lease,
                    ingress_operation_id=ingress_operation_id,
                    c02_operation_id=c02_operation_id)
            finally:
                graph.release_authority_lease(bootstrap, lease)

        try:
            return await worker.call(commit)
        except Exception:
            return None

    def installed_d13_main_model_v1(self) -> D13PrecompressionInstallationV1 | None:
        """Copy the installed main conversation model identity for D13.

        This is configuration identity only. D13's exact pre-call token gate
        and original paid-job fence still decide whether a call may run.
        """
        bundle, policy = self._v2_model_bundle, self._v2_policy
        if (type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or bundle.installation_policy != policy
                or type(bundle.model_workflows) not in (AdminModelWorkflowsV2, AdminModelWorkflowsV3)
                or type(bundle.model_workflows.reply) is not AdminModelWorkflowV2):
            return None
        main = bundle.model_workflows.reply
        return D13PrecompressionInstallationV1(
            policy.installation_id, main.provider_id, main.model_id,
            main.provider_config_digest, main.max_output_tokens)

    async def run_installed_d13_paid_precompression_v1(
        self, envelope: HostIngressEnvelope, ingress_operation_id: str, *,
        executor: HostModelEgressExecutor,
    ):
        """Execute or recover one installed original paid D13 background job."""
        from .runtime.d13_paid_product_v1 import run_installed_d13_paid_runtime_v1
        return await run_installed_d13_paid_runtime_v1(
            self, envelope, ingress_operation_id, executor=executor)

    async def schedule_d13_deterministic_precompression_v2(
        self, *, ingress_operation_id: str,
        envelope: HostIngressEnvelope,
    ) -> tuple | None:
        """Optionally queue installed D13 technical work for this trusted scene."""
        policy = self._v2_policy
        bundle = self._v2_model_bundle
        grant = self._v2_installation_grant
        port = self._v2_port
        worker = self._worker
        bootstrap = self._v2_bootstrap
        if (type(ingress_operation_id) is not str or not ingress_operation_id
                or type(envelope) is not HostIngressEnvelope
                or type(policy) is not AdminInstallationPolicy
                or type(bundle) is not AdminInstallationBundle
                or bundle.installation_policy != policy
                or type(bundle.d13_precompression)
                   is not AdminD13PrecompressionPolicyV1
                or type(grant) is not InstallationGrantV2
                or port is None or worker is None or bootstrap is None
                or not self._v2_namespace_provisioned
                or envelope.namespace != policy.namespace
                or policy.namespace != self._v2_namespace
                or ingress_ids(envelope.lineage.source_ref)[2]
                   != ingress_operation_id):
            return None
        scene_ref = scene_ref_for_conversation(
            policy.namespace, envelope.platform_ref, envelope.conversation_ref)

        def schedule(graph: GraphCoordinator) -> tuple | None:
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.subject, issuer_domain="d11",
                namespace=policy.namespace, domains=("d11",),
                activation_generation=anchor.activation_generation,
                operation_id=ingress_operation_id)
            try:
                authority = AuthorityContext(
                    grant.subject, "d11", capability, policy.namespace,
                    ("scene",), "context", (envelope.conversation_ref,),
                    policy.root_grant.policy_ref,
                    anchor.activation_generation)
                return graph.schedule_d13_deterministic_precompression_v2(
                    authority, lease, scene_ref=scene_ref)
            finally:
                graph.release_authority_lease(bootstrap, lease)

        try:
            return await worker.call(schedule)
        except Exception:
            return None

    async def consume_d13_deterministic_precompression_job_v2(
        self, *, job_id: str, conversation_ref: str,
        lease_seconds: int = 30,
    ) -> tuple[D13CacheCommitReceiptV1, BudgetReceipt, PersistentJob] | None:
        """Consume one scheduled original D13 job with one installed D11 holder."""
        policy = self._v2_policy
        bundle = self._v2_model_bundle
        grant = self._v2_installation_grant
        port = self._v2_port
        worker = self._worker
        bootstrap = self._v2_bootstrap
        if (type(job_id) is not str or not job_id
                or type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600
                or type(conversation_ref) is not str or not conversation_ref
                or type(policy) is not AdminInstallationPolicy
                or type(bundle) is not AdminInstallationBundle
                or bundle.installation_policy != policy
                or type(bundle.d13_precompression)
                   is not AdminD13PrecompressionPolicyV1
                or type(grant) is not InstallationGrantV2
                or port is None or worker is None or bootstrap is None
                or not self._v2_namespace_provisioned
                or policy.namespace != self._v2_namespace):
            return None

        def consume(graph: GraphCoordinator):
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.subject, issuer_domain="d11",
                namespace=policy.namespace, domains=("d11",),
                activation_generation=anchor.activation_generation,
                operation_id=job_id)
            try:
                authority = AuthorityContext(
                    grant.subject, "d11", capability, policy.namespace,
                    ("scene",), "context", (conversation_ref,),
                    policy.root_grant.policy_ref,
                    anchor.activation_generation)
                running = graph.acquire_d13_deterministic_precompression_job_v2(
                    authority, lease, job_id, lease_seconds=lease_seconds)
                if type(running) is not PersistentJob or running.job_id != job_id:
                    raise UnavailableGuard("D13 acquired original job differs; HOLD")
                result = graph.complete_d13_deterministic_precompression_job_v2(
                    authority, lease, job_id, fence=running.fence)
                if (type(result) is not tuple or len(result) != 3
                        or type(result[0]) is not D13CacheCommitReceiptV1
                        or type(result[1]) is not BudgetReceipt
                        or type(result[2]) is not PersistentJob
                        or result[2].job_id != job_id):
                    raise UnavailableGuard("D13 completion receipt differs; HOLD")
                return result
            finally:
                graph.release_authority_lease(bootstrap, lease)

        try:
            return await worker.call(consume)
        except Exception:
            return None

    async def expire_d13_deterministic_precompression_job_v2(
        self, *, job_id: str, conversation_ref: str,
    ) -> tuple[BudgetReceipt, PersistentJob] | None:
        """Reconcile one expired original job through the installed V2 fence."""
        policy = self._v2_policy
        bundle = self._v2_model_bundle
        grant = self._v2_installation_grant
        port = self._v2_port
        worker = self._worker
        bootstrap = self._v2_bootstrap
        if (type(job_id) is not str or not job_id
                or type(conversation_ref) is not str or not conversation_ref
                or type(policy) is not AdminInstallationPolicy
                or type(bundle) is not AdminInstallationBundle
                or bundle.installation_policy != policy
                or type(bundle.d13_precompression)
                   is not AdminD13PrecompressionPolicyV1
                or type(grant) is not InstallationGrantV2
                or port is None or worker is None or bootstrap is None
                or not self._v2_namespace_provisioned
                or policy.namespace != self._v2_namespace):
            return None

        def expire(graph: GraphCoordinator):
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.subject, issuer_domain="d11",
                namespace=policy.namespace, domains=("d11",),
                activation_generation=anchor.activation_generation,
                operation_id=job_id)
            try:
                authority = AuthorityContext(
                    grant.subject, "d11", capability, policy.namespace,
                    ("scene",), "context", (conversation_ref,),
                    policy.root_grant.policy_ref,
                    anchor.activation_generation)
                result = graph.expire_d13_deterministic_precompression_job_v2(
                    authority, lease, job_id)
                if (type(result) is not tuple or len(result) != 2
                        or type(result[0]) is not BudgetReceipt
                        or type(result[1]) is not PersistentJob
                        or result[1].job_id != job_id
                        or result[1].phase != "cancelled"):
                    raise UnavailableGuard("D13 expiry receipt differs; HOLD")
                return result
            finally:
                graph.release_authority_lease(bootstrap, lease)

        try:
            return await worker.call(expire)
        except Exception:
            return None

    async def discover_d13_precompression_schedule_attempts_v2(
        self,
    ) -> tuple[D13ScheduleRecoveryItemV2, ...] | None:
        """Discover installed original D13 identities without assuming a scene."""
        return await self._read_d13_schedule_recovery_v2(None, None)

    async def recover_d13_precompression_schedule_v2(
        self, *, original_operation_id: str, conversation_ref: str,
    ) -> tuple[BudgetReceipt, PersistentJob] | None:
        """Reconcile one original D13 receipt using its saved conversation."""
        if (type(original_operation_id) is not str or not original_operation_id
                or type(conversation_ref) is not str or not conversation_ref):
            return None
        return await self._read_d13_schedule_recovery_v2(
            original_operation_id, conversation_ref)

    async def _read_d13_schedule_recovery_v2(
        self, original_operation_id: str | None, conversation_ref: str | None,
    ):
        policy = self._v2_policy
        bundle = self._v2_model_bundle
        grant = self._v2_installation_grant
        port = self._v2_port
        worker = self._worker
        bootstrap = self._v2_bootstrap
        if (type(policy) is not AdminInstallationPolicy
                or type(bundle) is not AdminInstallationBundle
                or bundle.installation_policy != policy
                or type(bundle.d13_precompression)
                   is not AdminD13PrecompressionPolicyV1
                or type(grant) is not InstallationGrantV2
                or port is None or worker is None or bootstrap is None
                or not self._v2_namespace_provisioned
                or policy.namespace != self._v2_namespace):
            return None

        def read(graph: GraphCoordinator):
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.subject, issuer_domain="d11",
                namespace=policy.namespace, domains=("d11",),
                activation_generation=anchor.activation_generation,
                operation_id=original_operation_id or "d13:schedule-discovery")
            try:
                authority = AuthorityContext(
                    grant.subject, "d11", capability, policy.namespace,
                    ("scene",), "context",
                    (conversation_ref,) if conversation_ref is not None else (),
                    policy.root_grant.policy_ref,
                    anchor.activation_generation)
                if original_operation_id is None:
                    result = graph.discover_d13_precompression_schedule_attempts_v2(
                        authority, lease)
                    if (type(result) is not tuple or len(result) > 256
                            or any(type(item) is not D13ScheduleRecoveryItemV2
                                   for item in result)):
                        raise UnavailableGuard("D13 recovery identities differ; HOLD")
                else:
                    result = graph.recover_d13_precompression_schedule_v2(
                        authority, lease,
                        original_operation_id=original_operation_id)
                    if (type(result) is not tuple or len(result) != 2
                            or type(result[0]) is not BudgetReceipt
                            or type(result[1]) is not PersistentJob
                            or result[1].operation_id != original_operation_id
                            or result[1].continuation.get("conversation_ref") !=
                               conversation_ref):
                        raise UnavailableGuard("D13 original recovery receipt differs; HOLD")
                return result
            finally:
                graph.release_authority_lease(bootstrap, lease)

        try:
            return await worker.call(read)
        except Exception:
            return None

    async def commit_post_c02_attention_v1(
        self, *, c02_operation_id: str, source_ref: str | None = None,
    ) -> CommitReceipt | None:
        """Commit a current D07 ticket before the post-C02 model job."""
        bundle = self._v2_model_bundle
        policy = self._v2_policy
        if (self._worker is None or self._v2_bootstrap is None
                or self._v2_port is None or self._v2_installation_grant is None
                or type(bundle) is not AdminInstallationBundle
                or type(bundle.d07_attention) is not AdminD07AttentionPolicy
                or type(policy) is not AdminInstallationPolicy
                or bundle.installation_policy != policy):
            return None
        bootstrap = self._v2_bootstrap
        actor = self._v2_installation_grant.subject
        def commit(graph: GraphCoordinator) -> CommitReceipt | None:
            (c02, snapshot, qualification, conversation_ref, guard, anchor,
             clock, active_policy, current_competitor) = graph.read_post_c02_attention_inputs_v1(
                bootstrap, policy.namespace, c02_operation_id, source_ref, bundle)
            if type(active_policy) is not D12CurrentD07PolicyReadV1:
                raise UnavailableGuard("current D07 attention policy is unavailable; HOLD")
            exact_source_ref = qualification.source_refs[0]
            operation_id = post_c02_attention_operation_id(
                c02_operation_id, exact_source_ref)
            lease, capability = graph.grant(
                bootstrap, actor=actor, issuer_domain="d11",
                namespace=policy.namespace, domains=("d07",),
                activation_generation=anchor.activation_generation,
                operation_id=operation_id)
            try:
                authority = AuthorityContext(
                    actor, "d11", capability, policy.namespace,
                    ("persona",), "expression", (conversation_ref,),
                    policy.root_grant.policy_ref, anchor.activation_generation)
                recorded = graph.get_operation(authority, lease, operation_id)
                if recorded is not None:
                    decision = graph.read_post_c02_attention_decision_v2(
                        bootstrap, policy.namespace, c02_operation_id, bundle)
                    return (recorded if decision is not None
                            and decision.attention_operation_id == operation_id
                            and decision.bundle_digest == recorded.operation_digest
                            and not decision.inbound_deferred else None)
                now = trusted_upper(clock)
                uncertainty = (2 * bundle.ingress_clock.max_utc_error_seconds
                               + bundle.ingress_clock.max_round_trip_seconds)
                lifetime = bundle.d07_attention.deadline_after_seconds - uncertainty
                if lifetime <= 0:
                    return None
                candidate = prepare_post_c02_attention_v1(
                    c02_receipt=c02, source_ref=exact_source_ref, snapshot=snapshot,
                    qualification=qualification, authority=authority,
                    guard=guard, parent_budget_lease_ref=policy.root_grant.lease_id,
                    conversation_ref=conversation_ref, now_utc=now,
                    monotonic_deadline=clock.monotonic_after_seconds + lifetime,
                    ticket_lifetime_seconds=lifetime,
                    current_policy=active_policy.policy,
                    active_head_ref=active_policy.active_head_ref,
                    current_competitor=current_competitor)
                committed = graph.commit_post_c02_attention_v1(
                    candidate.bundle, lease, bundle)
                decision = graph.read_post_c02_attention_decision_v2(
                    bootstrap, policy.namespace, c02_operation_id, bundle)
                if (decision is None
                        or decision.attention_operation_id != operation_id
                        or decision.bundle_digest != committed.operation_digest
                        or decision.inbound_deferred != candidate.inbound_deferred):
                    raise UnavailableGuard("durable D07 attention decision differs; HOLD")
                return committed if not decision.inbound_deferred else None
            finally:
                graph.release_authority_lease(bootstrap, lease)

        return await self._worker.call(commit)

    async def read_original_c02_source_ref_v2(
        self, c02_operation_id: str,
    ) -> str | None:
        """Read one sealed C02 source via W01's current fenced graph port."""
        bundle, policy = self._v2_model_bundle, self._v2_policy
        if (type(c02_operation_id) is not str or not c02_operation_id
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_port is None or not self._v2_namespace_provisioned
                or type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or bundle.installation_policy is not policy):
            return None
        try:
            result = await self._worker.call(lambda graph:
                graph.read_post_c02_attention_inputs_v1(
                    self._v2_bootstrap, policy.namespace,
                    c02_operation_id, None, bundle))
        except Exception:
            return None
        if (type(result) is not tuple or len(result) != 9
                or type(result[0]) is not CommitReceipt
                or result[0].operation_id != c02_operation_id
                or result[0].status not in {"committed", "duplicate"}
                or type(result[2]) is not SourceQualification
                or len(result[2].source_refs) != 1
                or type(result[7]) is not D12CurrentD07PolicyReadV1):
            return None
        source_ref = result[2].source_refs[0]
        return source_ref if type(source_ref) is str and source_ref else None

    async def read_installed_natural_original_progress_v2(
        self, c02_operation_id: str,
    ) -> NaturalOriginalProgressV2 | None:
        """Read W01's content-free paid/final state under a fresh d11 lease."""
        bundle, policy, grant = (
            self._v2_model_bundle, self._v2_policy,
            self._v2_installation_grant)
        if (type(c02_operation_id) is not str or not c02_operation_id
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_port is None or not self._v2_namespace_provisioned
                or type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or bundle.installation_policy is not policy):
            return None
        bootstrap, port = self._v2_bootstrap, self._v2_port
        operation_id = "natural-progress-read-" + canonical_digest({
            "namespace": policy.namespace.as_tuple,
            "c02_operation_id": c02_operation_id,
        })[:48]

        def read(graph: GraphCoordinator):
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.subject, issuer_domain="d11",
                namespace=policy.namespace, domains=("d11",),
                activation_generation=anchor.activation_generation,
                operation_id=operation_id)
            try:
                authority = AuthorityContext(
                    grant.subject, "d11", capability, policy.namespace,
                    ("activity",), "proposal", ("internal",),
                    policy.root_grant.policy_ref,
                    anchor.activation_generation)
                return graph.read_natural_original_progress_v2(
                    authority, lease, c02_operation_id, bundle)
            finally:
                graph.release_authority_lease(bootstrap, lease)

        try:
            progress = await self._worker.call(read)
        except Exception:
            return None
        return (progress if type(progress) is NaturalOriginalProgressV2
                and progress.namespace == policy.namespace
                and progress.parent_original_id == c02_operation_id
                else None)

    async def read_installed_natural_stage_preparation_v2(
        self, c02_operation_id: str, stage: str,
    ) -> SavedNaturalPreparationV2 | None:
        """Reopen W01's original Saved row; never synthesize terminal state."""
        if stage not in {"generation", "review"}:
            return None
        progress = await self.read_installed_natural_original_progress_v2(
            c02_operation_id)
        if type(progress) is not NaturalOriginalProgressV2:
            return None
        status = progress.generation if stage == "generation" else progress.review
        if status is None:
            return None
        policy, grant, bundle = (
            self._v2_policy, self._v2_installation_grant,
            self._v2_model_bundle)
        bootstrap, port = self._v2_bootstrap, self._v2_port
        operation_id = "natural-stage-read-" + canonical_digest({
            "namespace": policy.namespace.as_tuple,
            "c02_operation_id": c02_operation_id,
            "stage": stage,
        })[:48]

        def read(graph: GraphCoordinator):
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.subject, issuer_domain="d11",
                namespace=policy.namespace, domains=("d11",),
                activation_generation=anchor.activation_generation,
                operation_id=operation_id)
            try:
                authority = AuthorityContext(
                    grant.subject, "d11", capability, policy.namespace,
                    ("activity",), "proposal", ("internal",),
                    policy.root_grant.policy_ref,
                    anchor.activation_generation)
                return graph.read_natural_original_stage_preparation_v2(
                    authority, lease, c02_operation_id, stage, bundle)
            finally:
                graph.release_authority_lease(bootstrap, lease)

        try:
            saved = await self._worker.call(read)
        except Exception:
            return None
        if (type(saved) is not SavedNaturalPreparationV2
                or saved.stage != stage or saved.state != status.state
                or saved.parent_original_id != c02_operation_id
                or saved.seal.namespace != policy.namespace
                or saved.seal.installation_id != policy.installation_id
                or (saved.seal.job_id, saved.seal.original_operation_id,
                    saved.seal.acquire_operation_id, saved.seal.call_id,
                    saved.typed_request_digest,
                    saved.terminal_receipt_digest,
                    saved.terminal_output_digest) !=
                   (status.job_id, status.original_operation_id,
                    status.acquire_operation_id, status.call_id,
                    status.typed_request_digest,
                    status.terminal_receipt_digest,
                    status.terminal_output_digest)):
            return None
        return saved

    def natural_reply_product_ready_v2(
        self, installation: V2InstallationAssembly, *,
        server: object, listener: object, candidates: object, context: object,
    ) -> bool:
        """Require the complete installed paid-to-P2 path before a new job.

        This is an admission preflight, not a permit to send. W01 repeats its
        current graph and Authority checks at every paid and final boundary.
        """
        from astrbot.api.star import Context
        from .host.installed_dispatch_route import InstalledDispatchRoutePort
        from .host.reverse_handoff import HostReverseGraphClaimServer
        from .host.scene_candidates import SceneCandidateCatalog

        if (type(installation) is not V2InstallationAssembly
                or installation.admin_bundle is not self._v2_model_bundle
                or installation.installation_policy is not self._v2_policy
                or installation.installation_grant != self._v2_installation_grant
                or installation.data_dir != self._data_dir
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_port is None or self._v2_cost_transport is None
                or not self._v2_namespace_provisioned
                or self.health.status not in {"limited", "ready"}
                or not all((self._v2_natural_generation_output_bound,
                            self._v2_natural_generation_content_bound,
                            self._v2_natural_review_output_bound,
                            self._v2_natural_paid_review_current_bound))
                or self._final_claim_writer is None
                or self._final_claim_authority is None
                or self._final_claim_lease is None
                or type(server) is not HostReverseGraphClaimServer
                or type(candidates) is not SceneCandidateCatalog
                or not isinstance(context, Context)
                or not isinstance(listener, asyncio.AbstractServer)
                or not listener.is_serving()):
            return False
        bundle, policy, grant = (
            installation.admin_bundle, installation.installation_policy,
            installation.installation_grant)
        binding = installation.reverse_handoff
        natural = self._v2_natural_readiness_receipt
        if type(natural) is not _InstalledNaturalReplyReadinessReceiptV2:
            return False
        try:
            owner_loop = asyncio.get_running_loop()
        except RuntimeError:
            return False
        writer = self._final_claim_writer
        route = getattr(writer, "route_port", None)
        verified = natural.verified_handoff
        if (type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or type(binding) is not TrustedFinalHandoffBindingV1
                or natural.installation is not installation
                or natural.bundle is not bundle
                or natural.policy is not policy
                or natural.grant != grant
                or not same_installed_grant_identity_v2(
                    grant, natural.client_grant)
                or natural.worker is not self._worker
                or natural.coordinator is not self._v2_coordinator
                or natural.fence_port is not self._v2_port
                or natural.cost_transport is not self._v2_cost_transport
                or natural.owner_loop is not owner_loop
                or natural.model_selection_port is not self._model_selection_port
                or type(self._model_selection_port)
                   is not InstalledModelCapabilityPort
                or self._model_selection_port._installation_bundle is not bundle
                or self._model_selection_port._installed_namespace
                   != policy.namespace
                or self._model_selection_port._host_loop is not owner_loop
                or self._model_selection_port._context is not context
                or self._v2_namespace != policy.namespace
                or type(self._v2_port) is not V2FencePort
                or type(self._worker) is not GraphWorker
                or type(self._v2_coordinator) is not GraphCoordinator
                or type(self._v2_cost_transport) is not MtlsAuthorityTransport
                or type(natural.authority_client) is not AuthorityClient
                or natural.authority_client._transport
                   is not self._v2_cost_transport
                or natural.authority_client._selection.profile_id
                   != bundle.tls_profile.profile_id
                or natural.authority_client._v2_handshake is None
                or natural.client_grant.channel_binding_sha256 !=
                   natural.authority_client._v2_handshake.channel_binding_sha256
                or type(verified) is not VerifiedFinalHandoffPairingV1
                or verified.binding is not binding
                or natural.p2_writer is not writer
                or natural.p2_context is not context
                or natural.p2_candidates is not candidates
                or getattr(writer, "graph", None) is not self._v2_coordinator
                or getattr(writer, "port", None) is not self._v2_port
                or getattr(writer, "issuer_id", None) != verified.issuer_id
                or type(route) is not InstalledDispatchRoutePort
                or route._context is not context
                or route._host_loop is not owner_loop
                or route._candidates is not candidates
                or route._coordinator is not self._v2_coordinator
                or route._authority is not self._final_claim_authority
                or route._lease is not self._final_claim_lease
                or route._namespace != policy.namespace
                or server.profile is not binding.profile
                or server.profile.namespace != policy.authority_namespace
                or server.profile.installation_id != grant.installation_id
                or bundle.installation_policy is not policy
                or type(bundle.model_workflows) not in (AdminModelWorkflowsV2, AdminModelWorkflowsV3)
                or type(bundle.model_workflows.natural_generation)
                   is not AdminModelWorkflowV2
                or type(bundle.model_workflows.natural_review)
                   is not AdminModelWorkflowV2
                or type(bundle.private_reply_dispatch)
                   is not AdminPrivateReplyDispatchPolicy
                or type(bundle.ingress_clock) is not AdminIngressClockPolicy
                or not callable(getattr(
                    RuntimeContext, "_run_installed_natural_chain_stages_v2",
                    None))):
            return False
        natural_specs = (
            (InstalledNaturalGenerationOutputPortV2,
             "read_original_natural_generation_output_v2"),
            (InstalledNaturalGenerationContentPortV2,
             "read_current_natural_generation_content_v2"),
            (InstalledNaturalReviewOutputPortV2,
             "read_original_natural_review_output_v2"),
            (InstalledNaturalPaidReviewPortV2,
             "read_current_natural_paid_review_v2"),
        )
        if len(natural.natural_ports) != len(natural_specs):
            return False
        for method, (kind, name) in zip(
                natural.natural_ports, natural_specs, strict=True):
            owner = getattr(method, "__self__", None)
            if (type(owner) is not kind
                    or getattr(method, "__func__", None)
                       is not getattr(kind, name)
                    or owner._bundle is not bundle
                    or owner._grant != natural.client_grant
                    or owner._client is not natural.authority_client
                    or owner._loop is not owner_loop):
                return False
        required_graph = (
            "commit_post_c02_natural_final_v2",
            "_recover_committed_natural_final_v2",
            "register_natural_dispatch_final_claim_writer_v2",
            "discover_pending_post_c02_natural_dispatch_v2",
            "discover_pending_post_c02_natural_stages_v2",
            "read_natural_original_progress_v2",
            "read_natural_original_stage_preparation_v2",
            "read_committed_natural_dispatch_v2",
            "get_natural_dispatch_text_segment_v2",
        )
        if any(not callable(getattr(GraphCoordinator, name, None))
               for name in required_graph):
            return False
        if (not callable(getattr(GraphCoordinator, "reconcile_natural_original_costs_v3", None))
                or not callable(getattr(RuntimeContext, "reconcile_natural_original_costs_v3", None))):
            return False
        generation_ready = getattr(
            self._v2_port, "natural_paid_consumer_ready_v2", None)
        review_ready = getattr(
            self._v2_port, "natural_review_paid_consumer_ready_v2", None)
        if not callable(generation_ready) or not callable(review_ready):
            return False
        try:
            return (generation_ready(
                namespace=policy.namespace,
                template_version=bundle.model_workflows.
                    natural_generation.template_version,
                installation_id=policy.installation_id,
                provider_id=bundle.model_workflows.
                    natural_generation.provider_id,
                model_id=bundle.model_workflows.
                    natural_generation.model_id,
                provider_config_digest=bundle.model_workflows.
                    natural_generation.provider_config_digest) is True
                and review_ready(
                    namespace=policy.namespace,
                    template_version=bundle.model_workflows.
                        natural_review.template_version,
                    installation_id=policy.installation_id,
                    provider_id=bundle.model_workflows.
                        natural_review.provider_id,
                    model_id=bundle.model_workflows.
                        natural_review.model_id,
                    provider_config_digest=bundle.model_workflows.
                        natural_review.provider_config_digest) is True)
        except Exception:
            return False

    async def prepare_post_c02_natural_generation_v2(
        self, *, installation: V2InstallationAssembly,
        server: object, listener: object, candidates: object,
        context: object, c02_operation_id: str, source_ref: str,
    ) -> SavedNaturalPreparationV2 | None:
        """Seal a new paid job only with the entire natural product installed."""
        bundle, policy = self._v2_model_bundle, self._v2_policy
        if (not self.natural_reply_product_ready_v2(
                installation, server=server, listener=listener,
                candidates=candidates, context=context)
                or self._worker is None or self._v2_bootstrap is None
                or not self._v2_namespace_provisioned
                or not self._v2_natural_generation_output_bound
                or type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or bundle.installation_policy is not policy
                or type(bundle.model_workflows) not in (AdminModelWorkflowsV2, AdminModelWorkflowsV3)
                or type(bundle.model_workflows.natural_generation)
                   is not AdminModelWorkflowV2
                or type(bundle.model_workflows.natural_review)
                   is not AdminModelWorkflowV2
                or type(c02_operation_id) is not str or not c02_operation_id
                or type(source_ref) is not str or not source_ref):
            return None
        try:
            saved = await self._worker.call(lambda graph:
                graph.prepare_post_c02_natural_generation_v2(
                    self._v2_bootstrap, policy.namespace,
                    c02_operation_id, source_ref, bundle))
            return (saved if type(saved) is SavedNaturalPreparationV2
                    and saved.stage == "generation"
                    and saved.seal.c02_operation_id == c02_operation_id
                    and saved.seal.source_ref == source_ref
                    and saved.seal.installation_id == policy.installation_id
                    else None)
        except Exception:
            return None

    async def run_installed_post_c02_natural_generation_v2(
        self, installation: V2InstallationAssembly, *, context,
        trusted_umo: str, saved: SavedNaturalPreparationV2,
    ):
        """Continue the sealed generation through its installed paid terminal."""
        if (not self._v2_natural_generation_output_bound
                or type(installation) is not V2InstallationAssembly
                or installation.admin_bundle is not self._v2_model_bundle
                or installation.installation_policy is not self._v2_policy
                or installation.installation_grant !=
                   self._v2_installation_grant):
            return None
        from .host.installed_natural_reply_driver import (
            run_installed_post_c02_natural_generation_v2,
        )

        return await run_installed_post_c02_natural_generation_v2(
            self, installation, context=context,
            trusted_umo=trusted_umo, saved=saved)

    async def run_installed_natural_reply_v2(
        self, installation: V2InstallationAssembly, *, context,
        trusted_umo: str, saved: SavedNaturalPreparationV2,
        server: object, candidates: object, listener: object = None,
    ):
        """Resume one original through review, final admission and P2.

        The full runner is installed only after W01's atomic final/claim and
        recovery interfaces exist. Until then this entry never acquires a
        generation call or initiates provider egress.
        """
        if (not self.natural_reply_product_ready_v2(
                installation, server=server, listener=listener,
                candidates=candidates, context=context)
                or type(saved) is not SavedNaturalPreparationV2
                or saved.stage != "generation"
                or saved.seal.namespace != installation.installation_policy.namespace
                or type(trusted_umo) is not str or not trusted_umo):
            return None
        return await self._run_installed_natural_chain_stages_v2(
            installation, context=context, trusted_umo=trusted_umo,
            saved=saved, server=server, listener=listener,
            candidates=candidates)

    async def _run_installed_natural_chain_stages_v2(
        self, installation: V2InstallationAssembly, *, context,
        trusted_umo: str, saved: SavedNaturalPreparationV2,
        server: object, listener: object, candidates: object,
    ):
        """Resume original paid stages, admit final once, then recover P2."""
        from .host.installed_natural_reply_driver import (
            InstalledNaturalGenerationProgressV2,
            run_installed_post_c02_natural_generation_v2,
        )
        from .host.installed_natural_review_driver import (
            InstalledNaturalReviewProgressV2,
            run_installed_post_c02_natural_review_v2,
        )

        c02_id = saved.seal.c02_operation_id
        progress = await self.read_installed_natural_original_progress_v2(c02_id)
        if (type(progress) is not NaturalOriginalProgressV2
                or progress.generation is None
                or progress.generation.original_operation_id !=
                   saved.seal.original_operation_id):
            return None
        final_id = saved.frozen.input.plan.final_operation_id
        if progress.final_operation_id is not None:
            if progress.final_operation_id != final_id:
                return None
            return await self.dispatch_committed_natural_reply_v2(
                installation, operation_id=final_id, context=context,
                server=server, listener=listener, candidates=candidates)

        generation_saved = await self.read_installed_natural_stage_preparation_v2(
            c02_id, "generation")
        if (type(generation_saved) is not SavedNaturalPreparationV2
                or generation_saved.seal != saved.seal
                or generation_saved.frozen != saved.frozen):
            return None
        generated = await run_installed_post_c02_natural_generation_v2(
            self, installation, context=context, trusted_umo=trusted_umo,
            saved=generation_saved)
        if (type(generated) is not InstalledNaturalGenerationProgressV2
                or generated.status != "review_content_hold"):
            return None
        generation_saved = await self.read_installed_natural_stage_preparation_v2(
            c02_id, "generation")
        if (type(generation_saved) is not SavedNaturalPreparationV2
                or generation_saved.state != "terminal"
                or generation_saved.seal != saved.seal):
            return None
        review_saved = await self.read_installed_natural_stage_preparation_v2(
            c02_id, "review")
        if review_saved is None:
            review_saved = await self._prepare_installed_natural_review_v2(
                installation, generation_saved)
        if (type(review_saved) is not SavedNaturalPreparationV2
                or review_saved.stage != "review"
                or review_saved.parent_original_id != c02_id):
            return None
        reviewed = await run_installed_post_c02_natural_review_v2(
            self, installation, context=context,
            trusted_umo=trusted_umo, generation_saved=generation_saved,
            review_saved=review_saved)
        if (type(reviewed) is not InstalledNaturalReviewProgressV2
                or reviewed.status != "paid_review_current_hold"):
            return None
        final = await self._commit_installed_natural_final_v2(
            installation, generation_saved)
        if (type(final) is not CommitReceipt
                or final.operation_id != final_id
                or final.status not in {"committed", "duplicate"}):
            return None
        return await self.dispatch_committed_natural_reply_v2(
            installation, operation_id=final_id, context=context,
            server=server, listener=listener, candidates=candidates)

    async def _commit_installed_natural_final_v2(
        self, installation: V2InstallationAssembly,
        saved: SavedNaturalPreparationV2,
    ) -> CommitReceipt | None:
        """Let W01 alone read both paid originals and atomically admit P2."""
        if (type(installation) is not V2InstallationAssembly
                or type(saved) is not SavedNaturalPreparationV2
                or saved.stage != "generation"
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_port is None
                or installation.admin_bundle is not self._v2_model_bundle
                or installation.installation_policy is not self._v2_policy
                or installation.installation_grant != self._v2_installation_grant):
            return None
        policy, grant, bundle = (
            installation.installation_policy,
            installation.installation_grant,
            installation.admin_bundle)
        plan = saved.frozen.input.plan
        from .domains.d08.natural_plan import natural_final_effect_id_v2

        if (type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or type(bundle) is not AdminInstallationBundle
                or saved.seal.namespace != policy.namespace
                or saved.seal.installation_id != policy.installation_id
                or plan.namespace != policy.namespace
                or plan.final_operation_id != post_c02_reply_operation_id(
                    saved.seal.c02_operation_id, saved.seal.source_ref)
                or plan.final_effect_id != natural_final_effect_id_v2(
                    policy.namespace, saved.seal.c02_operation_id,
                    saved.seal.source_ref)
                or not callable(getattr(
                    GraphCoordinator, "commit_post_c02_natural_final_v2", None))):
            return None
        port, bootstrap = self._v2_port, self._v2_bootstrap

        def commit(graph: GraphCoordinator) -> CommitReceipt:
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.administrator_holder,
                issuer_domain="d11", namespace=policy.namespace,
                domains=("d08", "d09", "d11"),
                activation_generation=anchor.activation_generation,
                operation_id=plan.final_operation_id)
            try:
                authority = AuthorityContext(
                    grant.administrator_holder, "d11", capability,
                    policy.namespace, ("activity",), "expression",
                    (plan.audience_id,), policy.root_grant.policy_ref,
                    anchor.activation_generation)
                return graph.commit_post_c02_natural_final_v2(
                    authority, lease, saved.seal.c02_operation_id, bundle)
            finally:
                graph.release_authority_lease(bootstrap, lease)

        try:
            receipt = await self._worker.call(commit)
        except Exception:
            return None
        return (receipt if type(receipt) is CommitReceipt
                and receipt.status in {"committed", "duplicate"}
                and receipt.operation_id == plan.final_operation_id
                and receipt.effect_id == plan.final_effect_id
                and len(receipt.outbox_refs) == 1
                else None)

    async def _prepare_installed_natural_review_v2(
        self, installation: V2InstallationAssembly,
        generation_saved: SavedNaturalPreparationV2,
    ) -> SavedNaturalPreparationV2 | None:
        """Let W01 read current Authority generation text into an independent job."""
        if (type(installation) is not V2InstallationAssembly
                or type(generation_saved) is not SavedNaturalPreparationV2
                or generation_saved.stage != "generation"
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_port is None
                or installation.admin_bundle is not self._v2_model_bundle
                or installation.installation_policy is not self._v2_policy
                or installation.installation_grant != self._v2_installation_grant):
            return None
        policy, grant, bundle = (
            installation.installation_policy,
            installation.installation_grant,
            installation.admin_bundle)
        if (type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or type(bundle) is not AdminInstallationBundle
                or type(bundle.model_workflows) not in (AdminModelWorkflowsV2, AdminModelWorkflowsV3)
                or type(bundle.model_workflows.natural_review)
                   is not AdminModelWorkflowV2
                or generation_saved.seal.namespace != policy.namespace
                or generation_saved.seal.installation_id != policy.installation_id):
            return None
        workflow, bootstrap, port = (
            bundle.model_workflows.natural_review,
            self._v2_bootstrap, self._v2_port)
        operation_id = "natural-review-prepare-" + canonical_digest({
            "namespace": policy.namespace.as_tuple,
            "c02_operation_id": generation_saved.seal.c02_operation_id,
        })[:48]

        def prepare(graph: GraphCoordinator):
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.subject, issuer_domain="d11",
                namespace=policy.namespace, domains=("d11",),
                activation_generation=anchor.activation_generation,
                operation_id=operation_id)
            try:
                authority = AuthorityContext(
                    grant.subject, "d11", capability, policy.namespace,
                    ("activity",), workflow.purpose,
                    (generation_saved.frozen.input.plan.audience_id,),
                    workflow.provider_config_ref,
                    anchor.activation_generation)
                return graph.prepare_post_c02_natural_review_v2(
                    authority, lease,
                    generation_saved.seal.c02_operation_id, bundle)
            finally:
                graph.release_authority_lease(bootstrap, lease)

        try:
            review = await self._worker.call(prepare)
        except Exception:
            return None
        return (review if type(review) is SavedNaturalPreparationV2
                and review.stage == "review"
                and review.parent_original_id ==
                    generation_saved.seal.c02_operation_id
                and review.seal.namespace == policy.namespace
                and review.seal.installation_id == policy.installation_id
                and review.seal.generation_original_operation_id ==
                    generation_saved.seal.original_operation_id
                else None)

    async def dispatch_committed_natural_reply_v2(
        self, installation: V2InstallationAssembly, *,
        operation_id: str, context: object, server: object,
        listener: object, candidates: object,
    ):
        """Recover an admitted original before attempting the P2 handoff."""
        from .host.installed_dispatch_route import InstalledDispatchRoutePort
        from .host.natural_reply_dispatch_driver import (
            InstalledNaturalReplyContinuationV2, NaturalReplyDispatchDriverV2,
        )

        if (not self.natural_reply_product_ready_v2(
                installation, server=server, listener=listener,
                candidates=candidates, context=context)
                or type(operation_id) is not str or not operation_id):
            return None
        worker, bootstrap, port = (
            self._worker, self._v2_bootstrap, self._v2_port)
        policy, grant, bundle = (
            installation.installation_policy,
            installation.installation_grant, installation.admin_bundle)
        issuer_id = getattr(self._final_claim_writer, "issuer_id", None)
        if type(issuer_id) is not str or not issuer_id:
            return None
        host_loop = asyncio.get_running_loop()

        def install_original(graph: GraphCoordinator):
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.administrator_holder,
                issuer_domain="d11", namespace=policy.namespace,
                domains=("d08", "d09", "d11"),
                activation_generation=anchor.activation_generation,
                operation_id=operation_id)
            try:
                authority = AuthorityContext(
                    grant.administrator_holder, "d11", capability,
                    policy.namespace, ("activity",), "expression",
                    ("internal",), policy.root_grant.policy_ref,
                    anchor.activation_generation)
                route = InstalledDispatchRoutePort(
                    context=context, host_loop=host_loop,
                    candidates=candidates, coordinator=graph,
                    authority=authority, lease=lease,
                    policy=policy, grant=grant)
                writer = graph.register_natural_dispatch_final_claim_writer_v2(
                    bootstrap, route_port=route, issuer_id=issuer_id)
                if not callable(getattr(writer,
                                        "prepare_natural_for_handoff", None)):
                    raise RuntimeError("natural final claim writer unavailable")
                return authority, lease, writer
            except BaseException:
                graph.release_authority_lease(bootstrap, lease)
                raise

        try:
            authority, lease, writer = await worker.call(install_original)
        except Exception:
            return None
        try:
            continuation = InstalledNaturalReplyContinuationV2(
                worker=worker, authority=authority, lease=lease,
                fence_port=port, policy=policy, grant=grant,
                server=server, natural_claim_writer=writer,
                context=context, candidates=candidates,
                clock_policy=bundle.ingress_clock,
                adapter_ref="astrbot:onebot:call_action")
            driver = NaturalReplyDispatchDriverV2(
                worker, authority, lease, continuation)
            result = await driver.run_once(operation_id=operation_id)
            if result.original is not None:
                try:
                    await worker.call(lambda graph: graph.record_natural_outbound_observation_v1(
                        bootstrap, policy.namespace, operation_id))
                except Exception:
                    result = replace(result, reason=result.reason + "; outbound history reconciliation pending")
            return result
        except Exception:
            return None
        finally:
            await worker.call(lambda graph:
                graph.release_authority_lease(bootstrap, lease))

    async def discover_pending_natural_dispatch_v2(
        self, installation: V2InstallationAssembly, *,
        server: object, listener: object, candidates: object,
        context: object, after: str | None = None, limit: int = 32,
    ) -> NaturalPendingDispatchPageV2 | None:
        """Page original committed outbox IDs; each still needs P2 recovery."""
        if (not self.natural_reply_product_ready_v2(
                installation, server=server, listener=listener,
                candidates=candidates, context=context)
                or after is not None and (
                    type(after) is not str or not after)
                or type(limit) is not int or not 1 <= limit <= 64):
            return None
        policy, grant = (
            installation.installation_policy,
            installation.installation_grant)
        bootstrap, port = self._v2_bootstrap, self._v2_port
        operation_id = "natural-dispatch-scan-" + canonical_digest({
            "namespace": policy.namespace.as_tuple, "after": after,
        })[:48]

        def read(graph: GraphCoordinator):
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.administrator_holder,
                issuer_domain="d11", namespace=policy.namespace,
                domains=("d08", "d09", "d11"),
                activation_generation=anchor.activation_generation,
                operation_id=operation_id)
            try:
                authority = AuthorityContext(
                    grant.administrator_holder, "d11", capability,
                    policy.namespace, ("activity",), "expression",
                    ("internal",), policy.root_grant.policy_ref,
                    anchor.activation_generation)
                return graph.discover_pending_post_c02_natural_dispatch_v2(
                    authority, lease, after=after, limit=limit)
            finally:
                graph.release_authority_lease(bootstrap, lease)

        try:
            page = await self._worker.call(read)
        except Exception:
            return None
        return (page if type(page) is NaturalPendingDispatchPageV2
                and page.namespace == policy.namespace
                and len(page.items) <= limit else None)

    async def reconcile_natural_original_costs_v3(self, installation, *, after=None, limit=32):
        """Historical expense recovery is independent of reply/content readiness."""
        if (type(installation) is not V2InstallationAssembly or self._worker is None
                or self._v2_bootstrap is None or self._v2_policy is not installation.installation_policy
                or self._v2_model_bundle is not installation.admin_bundle
                or self._v2_installation_grant != installation.installation_grant):
            return None
        policy = installation.installation_policy
        return await self._worker.call(lambda graph:
            graph.reconcile_natural_original_costs_v3(self._v2_bootstrap,
                namespace=policy.namespace, installation_id=policy.installation_id,
                after=after, limit=limit))

    async def discover_pending_natural_stages_v2(
        self, installation: V2InstallationAssembly, *,
        server: object, listener: object, candidates: object,
        context: object, after: str | None = None, limit: int = 32,
    ) -> NaturalPendingOriginalPageV2 | None:
        """Find unfinished original IDs; current stage reads gate each resume."""
        if (not self.natural_reply_product_ready_v2(
                installation, server=server, listener=listener,
                candidates=candidates, context=context)
                or after is not None and (
                    type(after) is not str or not after)
                or type(limit) is not int or not 1 <= limit <= 64):
            return None
        policy, grant, bundle = (
            installation.installation_policy,
            installation.installation_grant, installation.admin_bundle)
        bootstrap, port = self._v2_bootstrap, self._v2_port
        operation_id = "natural-original-scan-" + canonical_digest({
            "namespace": policy.namespace.as_tuple, "after": after,
        })[:48]

        def read(graph: GraphCoordinator):
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.subject, issuer_domain="d11",
                namespace=policy.namespace, domains=("d11",),
                activation_generation=anchor.activation_generation,
                operation_id=operation_id)
            try:
                authority = AuthorityContext(
                    grant.subject, "d11", capability, policy.namespace,
                    ("activity",), "proposal", ("internal",),
                    policy.root_grant.policy_ref,
                    anchor.activation_generation)
                return graph.discover_pending_post_c02_natural_stages_v2(
                    authority, lease, after=after, limit=limit,
                    installed_bundle=bundle)
            finally:
                graph.release_authority_lease(bootstrap, lease)

        try:
            page = await self._worker.call(read)
        except Exception:
            return None
        return (page if type(page) is NaturalPendingOriginalPageV2
                and page.namespace == policy.namespace
                and len(page.items) <= limit else None)

    async def discover_released_attention_v2(
        self, installation: V2InstallationAssembly, *,
        server: object, listener: object, candidates: object,
        context: object, after: str | None = None, limit: int = 32,
    ) -> D07ReleasedAttentionPageV2 | None:
        """Discover promoted original C02 IDs for bounded natural recovery."""
        if (not self.natural_reply_product_ready_v2(
                installation, server=server, listener=listener,
                candidates=candidates, context=context)
                or self._worker is None or self._v2_bootstrap is None
                or after is not None and (type(after) is not str or not after)
                or type(limit) is not int or not 1 <= limit <= 64):
            return None
        policy = installation.installation_policy
        try:
            page = await self._worker.call(lambda graph:
                graph.discover_released_post_c02_attention_v2(
                    self._v2_bootstrap, policy.namespace,
                    installation.admin_bundle, after=after, limit=limit))
        except Exception:
            return None
        return (page if type(page) is D07ReleasedAttentionPageV2
                and page.namespace == policy.namespace
                and len(page.items) <= limit else None)

    async def complete_observed_natural_attention_v2(
        self, installation: V2InstallationAssembly, *,
        final_operation_id: str, server: object, listener: object,
        candidates: object, context: object,
    ) -> D07ObservedFocusCompletionV2 | None:
        """Replay Graph focus CAS using its own pinned accepted observation."""
        if (not self.natural_reply_product_ready_v2(
                installation, server=server, listener=listener,
                candidates=candidates, context=context)
                or self._worker is None or self._v2_bootstrap is None
                or type(final_operation_id) is not str or not final_operation_id):
            return None
        try:
            result = await self._worker.call(lambda graph:
                graph.complete_observed_natural_attention_v2(
                    self._v2_bootstrap,
                    installation.installation_policy.namespace,
                    final_operation_id))
        except Exception:
            return None
        return (result if type(result) is D07ObservedFocusCompletionV2
                and result.final_operation_id == final_operation_id
                and result.status == "committed" else None)

    async def prepare_post_c02_context_reply_model_job_v2(
        self, *, c02_operation_id: str, source_ref: str,
        attention_receipt: CommitReceipt,
    ) -> SavedContextReplyPreparationV2 | None:
        """Queue V2 only when the installed paid consumer readiness gate is true."""
        bundle = self._v2_model_bundle
        policy = self._v2_policy
        if (self._worker is None or self._v2_bootstrap is None
                or not self._v2_namespace_provisioned
                or type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or bundle.installation_policy != policy
                or bundle.model_workflows is None
                or bundle.model_workflows.context_reply is None
                or type(attention_receipt) is not CommitReceipt
                or attention_receipt.status not in {"committed", "duplicate"}
                or attention_receipt.operation_id !=
                   post_c02_attention_operation_id(c02_operation_id, source_ref)):
            return None
        try:
            saved = await self._worker.call(
                lambda graph: graph.prepare_post_c02_context_reply_model_job_v2(
                    self._v2_bootstrap, policy.namespace, c02_operation_id,
                    source_ref, bundle))
            return saved if type(saved) is SavedContextReplyPreparationV2 else None
        except Exception:
            return None

    @asynccontextmanager
    async def acquired_post_c02_context_reply_model_v2(
        self, saved: SavedContextReplyPreparationV2,
    ) -> AsyncIterator[AcquiredPostC02ContextReplyModelV2 | None]:
        """Keep the V2 original D11 lease through egress and settlement."""
        bundle, policy, grant = (
            self._v2_model_bundle, self._v2_policy, self._v2_installation_grant)
        if (type(saved) is not SavedContextReplyPreparationV2
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_port is None or not self._v2_namespace_provisioned
                or type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or bundle.installation_policy != policy
                or saved.seal.namespace != policy.namespace
                or saved.seal.installation_id != policy.installation_id
                or bundle.model_workflows is None
                or type(bundle.model_workflows.context_reply) is not AdminModelWorkflowV2):
            yield None
            return
        workflow = bundle.model_workflows.context_reply
        bootstrap, port = self._v2_bootstrap, self._v2_port
        seal = saved.seal
        lease_seconds = min(3600, math.ceil(workflow.timeout_seconds) + 120)

        def acquire(graph: GraphCoordinator):
            _, _, qualification, audience, _, _, _, _, _ = (
                graph.read_post_c02_attention_inputs_v1(
                    bootstrap, policy.namespace, seal.c02_operation_id,
                    seal.source_ref, bundle))
            if (seal.source_ref not in qualification.source_refs
                    or audience not in workflow.audiences):
                raise UnavailableGuard("context reply source or audience changed; HOLD")
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=policy.administrator_holder, issuer_domain="d11",
                namespace=policy.namespace, domains=("d11",),
                activation_generation=anchor.activation_generation,
                operation_id=seal.acquire_operation_id)
            try:
                authority = AuthorityContext(
                    policy.administrator_holder, "d11", capability, policy.namespace,
                    ("activity",), workflow.purpose, (audience,),
                    workflow.provider_config_ref, anchor.activation_generation)
                job, call = graph.acquire_post_c02_context_reply_model_job_v2(
                    authority, lease, seal.c02_operation_id, seal.source_ref,
                    bundle, lease_seconds=lease_seconds)
                if (job.job_id != seal.job_id or call.call_id != seal.call_id):
                    raise UnavailableGuard("context reply original binding differs; HOLD")
                return AcquiredPostC02ContextReplyModelV2(
                    replace(authority, worker_fence=job.fence),
                    lease, saved, job, call)
            except BaseException:
                graph.release_authority_lease(bootstrap, lease)
                raise

        try:
            acquired = await self._worker.call(acquire)
        except Exception:
            yield None
            return
        try:
            yield acquired
        finally:
            await self._worker.call(lambda graph:
                                    graph.release_authority_lease(
                                        bootstrap, acquired.lease))

    async def read_post_c02_context_reply_model_egress_v2(
        self, acquired: AcquiredPostC02ContextReplyModelV2,
    ) -> tuple | None:
        bundle = self._v2_model_bundle
        if (type(acquired) is not AcquiredPostC02ContextReplyModelV2
                or self._worker is None or not self._v2_namespace_provisioned
                or type(bundle) is not AdminInstallationBundle
                or bundle.installation_policy != self._v2_policy):
            return None
        seal = acquired.saved.seal
        try:
            prepared = await self._worker.call(
                lambda graph: graph.read_post_c02_context_reply_model_egress_preparation_v2(
                    acquired.authority, acquired.lease,
                    seal.c02_operation_id, seal.source_ref, bundle))
            return prepared if prepared[0] == acquired.call else None
        except Exception:
            return None

    async def settle_post_c02_context_reply_model_v2(
        self, acquired: AcquiredPostC02ContextReplyModelV2,
        intent: ModelEgressIntentV1, terminal: ModelTerminalReceiptV2,
    ) -> tuple[OriginalModelCostCommitV1, ContextReplyResultReadRequestV1] | None:
        """Commit original paid cost, close its job, then read only its selector."""
        bundle, policy, grant = (
            self._v2_model_bundle, self._v2_policy, self._v2_installation_grant)
        if (type(acquired) is not AcquiredPostC02ContextReplyModelV2
                or type(intent) is not ModelEgressIntentV1
                or type(terminal) is not ModelTerminalReceiptV2
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_port is None or not self._v2_namespace_provisioned
                or type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or bundle.installation_policy != policy
                or acquired.saved.seal.namespace != policy.namespace
                or acquired.authority.actor != policy.administrator_holder
                or intent.subject != policy.administrator_holder
                or intent.call_id != acquired.call.call_id
                or intent.request_digest != acquired.call.digest
                or terminal.call_id != intent.call_id
                or terminal.request_digest != intent.request_digest):
            return None
        seal = acquired.saved.seal
        quote_id = "context-reply-quote:" + seal.job_id.split(":")[-1]
        try:
            cost = await self._worker.call(
                lambda graph: graph.commit_context_reply_model_cost_v2(
                    self._v2_bootstrap, policy.namespace, intent,
                    quote_id=quote_id, quote_version=1))
            if (type(cost) is not OriginalModelCostCommitV1
                    or cost.status not in {"committed", "duplicate"}):
                return None
        except Exception:
            return None

        def complete(graph: GraphCoordinator):
            anchor = self._v2_port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            operation_id = "context-reply-terminal-" + canonical_digest({
                "namespace": policy.namespace.as_tuple,
                "original_operation_id": seal.original_operation_id,
            })[:48]
            lease, capability = graph.grant(
                self._v2_bootstrap, actor=policy.administrator_holder, issuer_domain="d11",
                namespace=policy.namespace, domains=("d11",),
                activation_generation=anchor.activation_generation,
                operation_id=operation_id)
            try:
                authority = AuthorityContext(
                    policy.administrator_holder, "d11", capability, policy.namespace,
                    ("activity",), "proposal",
                    acquired.authority.audience,
                    acquired.authority.provider_policy_ref,
                    anchor.activation_generation)
                graph.complete_post_c02_context_reply_model_job_v2(
                    authority, lease, seal.c02_operation_id,
                    seal.source_ref, intent)
                return graph.read_post_c02_context_reply_model_result_request_v2(
                    authority, lease, seal.c02_operation_id,
                    seal.source_ref, bundle)
            finally:
                graph.release_authority_lease(self._v2_bootstrap, lease)

        try:
            request = await self._worker.call(complete)
            return (cost, request) if type(request) is ContextReplyResultReadRequestV1 else None
        except Exception:
            return None

    async def prepare_post_c02_reply_model_job_v1(
        self, *, c02_operation_id: str,
        attention_receipt: CommitReceipt,
        source_ref: str | None = None,
    ) -> ReplyModelQueuedPreparationV1 | None:
        """Queue the original signed reply model job after durable D07 selection."""
        bundle = self._v2_model_bundle
        policy = self._v2_policy
        if (self._worker is None or self._v2_bootstrap is None
                or not self._v2_namespace_provisioned
                or type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or bundle.installation_policy != policy
                or bundle.model_workflows is None
                or bundle.model_workflows.reply is None
                or type(attention_receipt) is not CommitReceipt
                or attention_receipt.status not in {"committed", "duplicate"}
                or {"d07.attention_ticket.v1", "d07.focus.v1"}
                   != {item.key.type_name for item in attention_receipt.write_versions}):
            return None

        def prepare(graph: GraphCoordinator) -> ReplyModelQueuedPreparationV1 | None:
            c02, _, qualification, _, _, _, _, _, _ = (
                graph.read_post_c02_attention_inputs_v1(
                    self._v2_bootstrap, policy.namespace, c02_operation_id,
                    source_ref, bundle))
            exact_source = qualification.source_refs[0]
            if (c02.operation_id != c02_operation_id
                    or attention_receipt.operation_id !=
                       post_c02_attention_operation_id(
                           c02_operation_id, exact_source)):
                return None
            return graph.prepare_post_c02_reply_model_job_v1(
                self._v2_bootstrap, policy.namespace, c02_operation_id,
                exact_source, bundle)

        try:
            return await self._worker.call(prepare)
        except Exception:
            return None

    @asynccontextmanager
    async def acquired_post_c02_reply_model_v1(
        self, *, c02_operation_id: str, source_ref: str,
    ) -> AsyncIterator[AcquiredPostC02ReplyModelV1 | None]:
        """Keep the original D11 worker lease alive across reply model egress."""
        bundle = self._v2_model_bundle
        policy = self._v2_policy
        grant = self._v2_installation_grant
        if (self._worker is None or self._v2_bootstrap is None
                or self._v2_port is None or not self._v2_namespace_provisioned
                or type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or bundle.installation_policy != policy
                or bundle.model_workflows is None
                or type(c02_operation_id) is not str or not c02_operation_id
                or type(source_ref) is not str or not source_ref):
            yield None
            return
        workflow = bundle.model_workflows.reply
        if (type(workflow) is not AdminModelWorkflowV2
                or workflow.work_kind != "reply"
                or workflow.purpose != "proposal"):
            yield None
            return
        bootstrap = self._v2_bootstrap
        port = self._v2_port
        actor = grant.subject
        acquire_id = reply_model_operation_id_v1(c02_operation_id, source_ref)
        lease_seconds = min(3600, math.ceil(workflow.timeout_seconds) + 120)

        def acquire(graph: GraphCoordinator) -> AcquiredPostC02ReplyModelV1:
            _, _, qualification, conversation_ref, _, _, _, _, _ = (
                graph.read_post_c02_attention_inputs_v1(
                    bootstrap, policy.namespace, c02_operation_id,
                    source_ref, bundle))
            if (qualification.source_refs != (source_ref,)
                    or conversation_ref not in workflow.audiences):
                raise UnavailableGuard("reply source or audience changed; HOLD")
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=actor, issuer_domain="d11",
                namespace=policy.namespace, domains=("d11",),
                activation_generation=anchor.activation_generation,
                operation_id=acquire_id)
            try:
                authority = AuthorityContext(
                    actor, "d11", capability, policy.namespace,
                    ("activity",), workflow.purpose,
                    (conversation_ref,), workflow.provider_config_ref,
                    anchor.activation_generation)
                job = graph.acquire_post_c02_reply_model_job_v1(
                    authority, lease, c02_operation_id, source_ref, bundle,
                    lease_seconds=lease_seconds)
                return AcquiredPostC02ReplyModelV1(
                    AuthorityContext(
                        actor, "d11", capability, policy.namespace,
                        ("activity",), workflow.purpose,
                        (conversation_ref,), workflow.provider_config_ref,
                        anchor.activation_generation, job.fence),
                    lease, c02_operation_id, source_ref, acquire_id)
            except BaseException:
                graph.release_authority_lease(bootstrap, lease)
                raise

        try:
            acquired = await self._worker.call(acquire)
        except Exception:
            yield None
            return
        try:
            yield acquired
        finally:
            await self._worker.call(lambda graph:
                                    graph.release_authority_lease(
                                        bootstrap, acquired.lease))

    async def read_post_c02_reply_model_egress_v1(
        self, acquired: AcquiredPostC02ReplyModelV1,
    ) -> tuple | None:
        """Read the graph-frozen source, job, draft and Authority anchor."""
        bundle = self._v2_model_bundle
        if (type(acquired) is not AcquiredPostC02ReplyModelV1
                or self._worker is None or not self._v2_namespace_provisioned
                or type(bundle) is not AdminInstallationBundle
                or bundle.installation_policy != self._v2_policy
                or acquired.authority.namespace != self._v2_policy.namespace
                or acquired.acquire_operation_id != reply_model_operation_id_v1(
                    acquired.c02_operation_id, acquired.source_ref)):
            return None
        try:
            return await self._worker.call(
                lambda graph: graph.read_post_c02_reply_model_egress_preparation_v1(
                    acquired.authority, acquired.lease,
                    acquired.c02_operation_id, acquired.source_ref, bundle))
        except Exception:
            return None

    async def read_post_c02_reply_model_result_request_v1(
        self, acquired: AcquiredPostC02ReplyModelV1,
    ) -> ReplyWorkerModelResultReadRequestV1 | None:
        """Get the original reply-scoped result selector from current graph truth."""
        bundle = self._v2_model_bundle
        if (type(acquired) is not AcquiredPostC02ReplyModelV1
                or self._worker is None or not self._v2_namespace_provisioned
                or type(bundle) is not AdminInstallationBundle
                or bundle.installation_policy != self._v2_policy
                or acquired.authority.namespace != self._v2_policy.namespace):
            return None
        try:
            request = await self._worker.call(
                lambda graph: graph.read_post_c02_reply_model_result_request_v1(
                    acquired.authority, acquired.lease,
                    acquired.c02_operation_id, acquired.source_ref, bundle))
            return (request if type(request) is ReplyWorkerModelResultReadRequestV1
                    else None)
        except Exception:
            return None

    async def discover_pending_post_c02_reply_model_jobs_v1(
        self, *, cursor: str | None = None, limit: int = 8,
    ) -> ReplyModelRecoveryPageV1 | None:
        """Read a bounded current recovery page without acquiring or sending."""
        bundle = self._v2_model_bundle
        policy = self._v2_policy
        if (self._worker is None or self._v2_bootstrap is None
                or not self._v2_namespace_provisioned
                or type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or bundle.installation_policy != policy
                or type(limit) is not int or not 1 <= limit <= 8
                or cursor is not None and (
                    type(cursor) is not str or not cursor or len(cursor) > 128)):
            return None
        try:
            page = await self._worker.call(
                lambda graph: graph.discover_pending_post_c02_reply_model_jobs_v1(
                    self._v2_bootstrap, policy.namespace,
                    cursor=cursor, limit=limit, installed_bundle=bundle))
            return (page if type(page) is ReplyModelRecoveryPageV1
                    and page.namespace == policy.namespace
                    and page.installation_id == policy.installation_id
                    else None)
        except Exception:
            return None

    async def commit_post_c02_reply_model_cost_v1(
        self, queued: ReplyModelQueuedPreparationV1,
        intent: ModelEgressIntentV1,
        terminal: ModelTerminalReceiptV2,
    ) -> OriginalModelCostCommitV1 | None:
        """Settle the original observed call with W01's signed reply quote."""
        policy = self._v2_policy
        if (type(queued) is not ReplyModelQueuedPreparationV1
                or type(intent) is not ModelEgressIntentV1
                or type(terminal) is not ModelTerminalReceiptV2
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_cost_transport is None
                or not self._v2_namespace_provisioned
                or type(policy) is not AdminInstallationPolicy
                or (intent.authority_id, intent.namespace) !=
                   (policy.expected_authority_id, policy.authority_namespace)
                or intent.job_id != queued.job.job_id
                or intent.budget_reservation_operation_id !=
                   queued.original_operation_id
                or intent.budget_lease_id != queued.quote.parent_budget_lease_ref
                or (queued.quote.bot_id, queued.quote.persona_id) !=
                   policy.namespace.as_tuple
                or (terminal.call_id, terminal.request_digest) !=
                   (intent.call_id, intent.request_digest)):
            return None
        try:
            cost = await self._worker.call(
                lambda graph: graph.commit_post_c02_reply_model_cost_v1(
                    self._v2_bootstrap, policy.namespace, intent,
                    quote_id=queued.quote.quote_id,
                    quote_version=queued.quote.version))
            return (cost if type(cost) is OriginalModelCostCommitV1
                    and cost.status == "committed"
                    and cost.call_id == intent.call_id
                    and (cost.quote_id, cost.quote_version) ==
                        (queued.quote.quote_id, queued.quote.version)
                    else None)
        except Exception:
            return None

    async def _call_reply_ownership_v1(
        self, envelope: HostIngressEnvelope, receipt: IngressReceipt,
        handler_invocation_id: str, action: str, *,
        ready: HostReplyTakeoverReadyV1 | None = None,
        evidence: HostReplySuppressionEvidenceV1 | None = None,
    ) -> object:
        policy = self._v2_policy
        grant = self._v2_installation_grant
        worker = self._worker
        bootstrap = self._v2_bootstrap
        port = self._v2_port
        if (type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or worker is None or bootstrap is None or port is None
                or type(envelope) is not HostIngressEnvelope
                or envelope.namespace != policy.namespace
                or envelope.visibility != "private"
                or type(receipt) is not IngressReceipt
                or receipt.status != "accepted"
                or type(handler_invocation_id) is not str
                or not handler_invocation_id
                or action not in {"wait", "close", "activate", "recover"}):
            raise RuntimeError("installed reply ownership context is unavailable")

        def call(graph: GraphCoordinator) -> object:
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.subject, issuer_domain="d11",
                namespace=policy.namespace, domains=("d08", "d09", "d11"),
                activation_generation=anchor.activation_generation,
                operation_id=receipt.operation_id)
            try:
                authority = AuthorityContext(
                    grant.subject, "d11", capability, policy.namespace,
                    ("activity",), "expression", (envelope.conversation_ref,),
                    policy.root_grant.policy_ref,
                    anchor.activation_generation)
                if action == "wait":
                    return graph.wait_for_durable_admission_v1(
                        authority, lease,
                        ingress_operation_id=receipt.operation_id,
                        handler_invocation_id=handler_invocation_id)
                if action == "close":
                    return graph.close_host_default_v1(
                        authority, lease,
                        ingress_operation_id=receipt.operation_id,
                        handler_invocation_id=handler_invocation_id)
                if action == "recover":
                    return graph.read_reply_ownership_v1(
                        authority, lease,
                        ingress_operation_id=receipt.operation_id,
                        handler_invocation_id=handler_invocation_id)
                if (type(ready) is not HostReplyTakeoverReadyV1
                        or type(evidence) is not HostReplySuppressionEvidenceV1):
                    raise RuntimeError("original handler stop evidence is unavailable")
                activate = getattr(graph, "activate_reply_ownership_v1", None)
                if not callable(activate):
                    raise RuntimeError("durable reply ownership activation is unavailable")
                return activate(authority, lease, ready=ready, evidence=evidence)
            finally:
                graph.release_authority_lease(bootstrap, lease)

        return await worker.call(call)

    async def assemble_post_c02_reply_v2(
        self, progress: InstalledReplyProgressV1, *,
        handler_invocation_id: str, handler_deadline_utc: float,
    ) -> CommitReceipt | None:
        """Ask W01 to seal a paid reply under a D08/D09/D11 activity lease.

        W01 alone reads current graph/Authority facts, stages checks and signs
        the message quote. A commit here remains pending host ownership and
        does not allow platform dispatch.
        """
        bundle = self._v2_model_bundle
        policy = self._v2_policy
        grant = self._v2_installation_grant
        if (type(progress) is not InstalledReplyProgressV1
                or type(progress.run) is not InstalledReplyModelRunV1
                or type(progress.run.preparation)
                   is not FrozenReplyModelPreparationV1
                or type(progress.cost) is not OriginalModelCostCommitV1
                or progress.cost.status != "committed"
                or progress.candidate is None or progress.result_read is None
                or type(bundle) is not AdminInstallationBundle
                or type(bundle.private_reply_dispatch)
                   is not AdminPrivateReplyDispatchPolicy
                or type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or bundle.installation_policy != policy
                or grant.installation_id != policy.installation_id
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_port is None or not self._v2_namespace_provisioned
                or type(handler_invocation_id) is not str
                or not handler_invocation_id or len(handler_invocation_id) > 255
                or type(handler_deadline_utc) not in (int, float)
                or not math.isfinite(handler_deadline_utc)
                or handler_deadline_utc <= 0):
            return None
        preparation = progress.run.preparation
        if (preparation.envelope.authority.namespace != policy.namespace
                or len(preparation.envelope.authority.audience) != 1
                or progress.cost.call_id != preparation.intent.call_id
                or progress.result_read.request.c02_operation_id
                   != preparation.c02_receipt.operation_id
                or progress.result_read.request.source_ref
                   != preparation.source.source_ref):
            return None
        c02_operation_id = preparation.c02_receipt.operation_id
        source_ref = preparation.source.source_ref
        operation_id = post_c02_reply_operation_id(c02_operation_id, source_ref)
        actor = grant.subject
        bootstrap = self._v2_bootstrap
        port = self._v2_port

        def assemble(graph: GraphCoordinator) -> CommitReceipt:
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=actor, issuer_domain="d11",
                namespace=policy.namespace,
                domains=("d08", "d09", "d11"),
                activation_generation=anchor.activation_generation,
                operation_id=operation_id)
            try:
                authority = AuthorityContext(
                    actor, "d11", capability, policy.namespace,
                    ("activity",),
                    "expression", preparation.envelope.authority.audience,
                    policy.root_grant.policy_ref,
                    anchor.activation_generation)
                return graph.assemble_post_c02_reply_v2(
                    authority, lease, progress, bundle,
                    handler_invocation_id=handler_invocation_id,
                    handler_deadline_utc=handler_deadline_utc)
            finally:
                graph.release_authority_lease(bootstrap, lease)

        try:
            receipt = await self._worker.call(assemble)
        except Exception:
            return None
        return (receipt if type(receipt) is CommitReceipt
                and receipt.status in {"committed", "duplicate"}
                and receipt.operation_id == operation_id else None)

    async def commit_prepared_post_c02_reply_v1(
        self, *, c02_operation_id: str, source_ref: str,
        audience: tuple[str, ...],
        prepare: Callable[[GraphCoordinator, AuthorityContext, object, CommitReceipt],
                          tuple[PostC02ReplyCandidate, DomainBundle]],
    ) -> CommitReceipt | None:
        """Commit a graph-read, finite reply candidate under one installed lease.

        ``prepare`` runs on the graph worker after a durable duplicate check.
        It must use current graph/domain reads and an already settled reply
        result; no model call is made by this method.  A missing result or
        provider is a HOLD at the caller's orchestration boundary.
        """
        if (self._worker is None or self._v2_bootstrap is None
                or self._v2_port is None or self._v2_policy is None
                or self._v2_installation_grant is None
                or not callable(prepare) or not audience):
            return None
        policy = self._v2_policy
        port = self._v2_port
        bootstrap = self._v2_bootstrap
        actor = self._v2_installation_grant.subject
        operation_id = post_c02_reply_operation_id(c02_operation_id, source_ref)

        def commit(graph: GraphCoordinator) -> CommitReceipt | None:
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=actor, issuer_domain="d11",
                namespace=policy.namespace,
                domains=("d03", "d05", "d06", "d07", "d08", "d09", "d11"),
                activation_generation=anchor.activation_generation,
                operation_id=operation_id)
            try:
                authority = AuthorityContext(
                    actor, "d11", capability, policy.namespace,
                    ("event", "persona", "relation", "scene", "activity"),
                    "expression", audience,
                    policy.root_grant.policy_ref,
                    anchor.activation_generation)
                c02 = graph.get_operation(authority, lease, c02_operation_id)
                if (c02 is None or c02.status not in {"committed", "duplicate"}
                        or not {"memory.episode.v1", "memory.subjective_trace.v2"}
                           <= {item.key.type_name for item in c02.write_versions}):
                    return None
                recorded = graph.get_operation(authority, lease, operation_id)
                if recorded is not None:
                    return recorded
                episodes = tuple(item for item in c02.write_versions
                                 if item.key.type_name == "memory.episode.v1")
                if len(episodes) != 1:
                    return None
                episode = graph.read_snapshot(
                    authority, lease, (episodes[0].key,)).get(episodes[0].key)
                if (episode is None or not episode.valid
                        or episode.revision != episodes[0].revision
                        or source_ref not in episode.value.get("source_refs", ())):
                    return None
                candidate, bundle = prepare(graph, authority, lease, c02)
                return commit_post_c02_reply_bundle_v1(
                    graph, authority, lease,
                    c02_operation_id=c02_operation_id, source_ref=source_ref,
                    candidate=candidate, bundle=bundle)
            finally:
                graph.release_authority_lease(bootstrap, lease)

        return await self._worker.call(commit)

    async def first_ingress_c02_accounting_installed_v1(
        self, *, require_worker_result: bool = True,
    ) -> bool:
        """Admit automatic handoff only with W01's installed cost continuation."""
        bundle = self._v2_model_bundle
        if (type(require_worker_result) is not bool
                or self._worker is None or not self._v2_namespace_provisioned
                or self._v2_cost_transport is None
                or type(bundle) is not AdminInstallationBundle
                or bundle.installation_policy != self._v2_policy
                or type(bundle.d06_first_ingress_c02)
                   is not AdminD06FirstIngressC02Policy
                or type(bundle.ingress_clock) is not AdminIngressClockPolicy):
            return False
        try:
            return (await self._worker.call(
                lambda graph: graph.first_ingress_c02_accounting_installed_v1()
                if require_worker_result else
                graph.first_ingress_c02_accounting_installed_v1(
                    require_worker_result=False)
            )) is True
        except Exception:
            return False

    async def discover_first_ingress_unacquired_v1(
        self, *, after_job_id: str | None = None, limit: int = 8,
    ) -> FirstIngressUnacquiredPageV1 | None:
        """Read one installed startup page; absence of the graph API is HOLD.

        The graph owns content-fence, D06 access, stage, and queued-job checks.
        This wrapper never reads private tables or upgrades a hint to a permit.
        """
        if (type(limit) is not int or not 1 <= limit <= 8
                or after_job_id is not None and (
                    type(after_job_id) is not str or not after_job_id)
                or self._worker is None or self._v2_bootstrap is None
                or not self._v2_namespace_provisioned
                or type(self._v2_policy) is not AdminInstallationPolicy
                or self._v2_installation_grant is None
                or self._v2_policy.namespace != self._v2_namespace):
            return None
        namespace = self._v2_namespace
        bootstrap = self._v2_bootstrap
        try:
            page = await self._worker.call(
                lambda graph: graph.discover_first_ingress_unacquired_v1(
                    bootstrap, namespace, after_job_id=after_job_id,
                    limit=limit))
        except Exception:
            return None
        if (type(page) is not FirstIngressUnacquiredPageV1
                or page.namespace != namespace
                or page.installation_id
                   != self._v2_installation_grant.installation_id
                or len(page.items) > limit
                or any(item.job_id <= (after_job_id or "")
                       for item in page.items)
                or any(left.job_id >= right.job_id for left, right in zip(
                    page.items, page.items[1:]))
                or page.next_after_job_id is not None and (
                    page.next_after_job_id <= (after_job_id or "")
                    or page.items and
                    page.next_after_job_id < page.items[-1].job_id)):
            return None
        return page

    async def recover_committed_first_ingress_c02_unknown_cost_v1(
        self, operation_id: str,
    ) -> bool:
        """Settle only a graph-proven committed C02 with the original intent."""
        if (type(operation_id) is not str or not operation_id
                or self._worker is None or self._v2_bootstrap is None
                or not self._v2_namespace_provisioned
                or self._v2_namespace is None):
            return False
        try:
            await self._worker.call(
                lambda graph: graph.recover_committed_first_ingress_c02_unknown_cost_v1(
                    self._v2_bootstrap, self._v2_namespace, operation_id))
        except Exception:
            return False
        return True

    async def recover_pending_first_ingress_c02_v1(
        self, consumer_operation_id: str,
    ) -> CommitReceipt | None:
        """Resume one sealed C02 candidate without model dispatch or result read."""
        bundle = self._v2_model_bundle
        policy = self._v2_policy
        grant = self._v2_installation_grant
        if (type(consumer_operation_id) is not str or not consumer_operation_id
                or self._worker is None or self._v2_bootstrap is None
                or not self._v2_namespace_provisioned
                or type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or bundle.installation_policy != policy
                or policy.namespace != self._v2_namespace
                or grant.installation_id != policy.installation_id
                or type(bundle.d06_first_ingress_c02)
                   is not AdminD06FirstIngressC02Policy
                or type(bundle.ingress_clock) is not AdminIngressClockPolicy
                or self._v2_cost_transport is None):
            return None
        try:
            receipt = await self._worker.call(
                lambda graph: graph.recover_pending_first_ingress_c02_v1(
                    self._v2_bootstrap, policy.namespace, consumer_operation_id,
                    policy, bundle.d06_first_ingress_c02,
                    bundle.ingress_clock))
        except Exception:
            return None
        if (type(receipt) is not CommitReceipt
                or receipt.status not in {"committed", "duplicate"}
                or receipt.operation_id != consumer_operation_id
                or not {"memory.episode.v1", "memory.subjective_trace.v2"}
                       <= {version.key.type_name
                           for version in receipt.write_versions}
                or any(NamespaceId.from_key(version.key) != policy.namespace
                       for version in receipt.write_versions)):
            return None
        return receipt

    async def read_pending_first_ingress_c02_terminal_request_v2(
        self, consumer_operation_id: str,
    ):
        """Obtain the first-sealed attempt ID on the graph worker thread."""
        if (type(consumer_operation_id) is not str or not consumer_operation_id
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_namespace is None or not self._v2_namespace_provisioned
                or self._v2_cost_transport is None):
            return None
        try:
            return await self._worker.call(
                lambda graph: graph.read_pending_first_ingress_c02_terminal_request_v2(
                    self._v2_bootstrap, self._v2_namespace, consumer_operation_id))
        except Exception:
            return None

    async def claim_pending_first_ingress_c02_terminal_read_v2(
        self, consumer_operation_id: str, request,
    ) -> bool | None:
        """Persist one read attempt before the host issues its body RPC."""
        from .authority_service.v2_terminal_c02_recovery_contract import (
            TerminalRecoveryReadRequestV1,
        )

        if (type(consumer_operation_id) is not str or not consumer_operation_id
                or type(request) is not TerminalRecoveryReadRequestV1
                or request.consumer_operation_id != consumer_operation_id
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_namespace is None or not self._v2_namespace_provisioned
                or self._v2_cost_transport is None):
            return None
        try:
            claimed = await self._worker.call(
                lambda graph: graph.claim_pending_first_ingress_c02_terminal_read_v2(
                    self._v2_bootstrap, self._v2_namespace,
                    consumer_operation_id, request))
            return claimed if type(claimed) is bool else None
        except Exception:
            return None

    async def recover_pending_first_ingress_c02_v2_pinned(
        self, consumer_operation_id: str, pinned_query, pinned_read,
    ) -> CommitReceipt | None:
        """Complete v2 recovery synchronously on the graph worker thread."""
        from .host.terminal_c02_recovery_query import PinnedTerminalC02RecoveryQueryV1
        from .runtime.c02_terminal_job import _PinnedTerminalRead

        bundle = self._v2_model_bundle
        policy = self._v2_policy
        if (type(consumer_operation_id) is not str or not consumer_operation_id
                or type(pinned_query) is not PinnedTerminalC02RecoveryQueryV1
                or type(pinned_read) is not _PinnedTerminalRead
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_namespace is None or not self._v2_namespace_provisioned
                or self._v2_cost_transport is None
                or type(bundle) is not AdminInstallationBundle
                or type(policy) is not AdminInstallationPolicy
                or type(bundle.d06_first_ingress_c02)
                   is not AdminD06FirstIngressC02Policy
                or type(bundle.ingress_clock) is not AdminIngressClockPolicy):
            return None
        try:
            receipt = await self._worker.call(
                lambda graph: graph.recover_pending_first_ingress_c02_v2_pinned(
                    self._v2_bootstrap, policy.namespace, consumer_operation_id,
                    policy, bundle.d06_first_ingress_c02, bundle.ingress_clock,
                    pinned_query, pinned_read))
        except Exception:
            return None
        if (type(receipt) is not CommitReceipt
                or receipt.status not in {"committed", "duplicate"}
                or receipt.operation_id != consumer_operation_id
                or not {"memory.episode.v1", "memory.subjective_trace.v2"}
                   <= {version.key.type_name for version in receipt.write_versions}):
            return None
        return receipt

    async def read_committed_first_ingress_c02_terminal_request_v2(
        self, consumer_operation_id: str,
    ):
        """Classify a committed terminal v2 cost without a body read."""
        if (type(consumer_operation_id) is not str or not consumer_operation_id
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_namespace is None or not self._v2_namespace_provisioned
                or self._v2_cost_transport is None):
            return None
        try:
            return await self._worker.call(
                lambda graph: graph.read_committed_first_ingress_c02_terminal_request_v2(
                    self._v2_bootstrap, self._v2_namespace, consumer_operation_id))
        except Exception:
            return None

    async def recover_committed_first_ingress_c02_unknown_cost_v2_pinned(
        self, consumer_operation_id: str, pinned_read,
    ) -> bool:
        from .runtime.c02_terminal_job import _PinnedTerminalRead

        if (type(consumer_operation_id) is not str or not consumer_operation_id
                or type(pinned_read) is not _PinnedTerminalRead
                or self._worker is None or self._v2_bootstrap is None
                or self._v2_namespace is None or not self._v2_namespace_provisioned
                or self._v2_cost_transport is None):
            return False
        try:
            await self._worker.call(
                lambda graph: graph.recover_committed_first_ingress_c02_unknown_cost_v2_pinned(
                    self._v2_bootstrap, self._v2_namespace,
                    consumer_operation_id, pinned_read))
        except Exception:
            return False
        return True

    async def discover_committed_first_ingress_c02_cost_v1(
        self, *, cursor: str | None = None, limit: int = 50,
    ) -> FirstIngressRecoveryPageV1 | None:
        """Read content-free V3 identities before any startup cost writes."""
        if (type(limit) is not int or not 1 <= limit <= 50
                or cursor is not None and (type(cursor) is not str or not cursor)
                or self._worker is None or self._v2_bootstrap is None
                or not self._v2_namespace_provisioned
                or self._v2_namespace is None
                or self._v2_installation_grant is None):
            return None
        try:
            page = await self._worker.call(
                lambda graph: graph.discover_first_ingress_recovery_v1(
                    self._v2_bootstrap, self._v2_namespace,
                    cursor=cursor, limit=limit))
        except Exception:
            return None
        if (type(page) is not FirstIngressRecoveryPageV1
                or page.namespace != self._v2_namespace
                or page.installation_id
                   != self._v2_installation_grant.installation_id
                or len(page.items) > limit
                or page.next_cursor == cursor):
            return None
        return page

    async def read_first_ingress_acquired_handoff_v1(
        self, acquire_operation_id: str,
    ) -> tuple[FirstIngressRecoveryItemV1, HostIngressEnvelope] | None:
        """Requalify an original running V3 job before host recovery."""
        if (type(acquire_operation_id) is not str
                or not acquire_operation_id
                or self._worker is None or self._v2_bootstrap is None
                or not self._v2_namespace_provisioned
                or self._v2_namespace is None
                or self._v2_installation_grant is None):
            return None
        try:
            item, envelope = await self._worker.call(
                lambda graph: graph.read_first_ingress_acquired_handoff_v1(
                    self._v2_bootstrap, self._v2_namespace,
                    acquire_operation_id))
        except Exception:
            return None
        if (type(item) is not FirstIngressRecoveryItemV1
                or item.recovery_state != "original_fence"
                or item.acquire_operation_id != acquire_operation_id
                or item.namespace != self._v2_namespace
                or item.installation_id
                   != self._v2_installation_grant.installation_id
                or type(envelope) is not HostIngressEnvelope
                or envelope.namespace != item.namespace):
            return None
        return item, envelope

    async def run_committed_first_ingress_encoding_v2(
        self, envelope: HostIngressEnvelope, receipt: IngressReceipt, *,
        executor: HostModelEgressExecutor,
    ) -> FrozenEncodingEgressResult | None:
        """Retired half-flow: release-before-cost would strand the original call."""
        return None

    async def handle_ingress(self, envelope: HostIngressEnvelope) -> IngressReceipt:
        if not isinstance(envelope, HostIngressEnvelope):
            raise TypeError("envelope must be HostIngressEnvelope")
        if self._worker is not None:
            if not self.v2_ingress_qualified:
                return IngressReceipt("unavailable")
            try:
                bundle = self._v2_model_bundle
                reply_source_policy = (
                    bundle.d06_private_reply_source
                    if type(bundle) is AdminInstallationBundle else None
                )
                receipt = await self._worker.call(
                    self._v2_ingress,
                    ingress_host_facts(
                        envelope, reply_source_policy=reply_source_policy,
                    ),
                )
            except FirstIngressOutcomeUnknown as exc:
                return IngressReceipt("deferred", exc.operation_id)
            if receipt.status == "committed":
                return IngressReceipt("accepted", receipt.operation_id)
            if receipt.status == "duplicate":
                return IngressReceipt("duplicate", receipt.operation_id)
            if receipt.status == "pending_confirmation":
                return IngressReceipt("deferred", receipt.operation_id)
            if receipt.status == "rejected":
                return IngressReceipt("rejected")
            return IngressReceipt("unavailable")
        if self.health.status != "ready" or self._coordinator is None or self._ingress_handler is None:
            return IngressReceipt("unavailable")
        receipt = await self._ingress_handler(envelope, self._coordinator)
        if not isinstance(receipt, IngressReceipt):
            raise TypeError("ingress handler returned an invalid receipt")
        return receipt

    async def stop(self) -> RuntimeHealth:
        async with self._lock:
            if "v2_fence_recovery" in self.health.missing_capabilities:
                return self.health
            if self._host_lifecycle_startup_task is not None:
                await self._host_lifecycle_startup_task
            self.health = RuntimeHealth("draining")
            self._offline_recovery_stopping = True
            if self._offline_recovery_task is not None:
                await self._offline_recovery_task
            d07 = self._v2_d07_execution_service
            if d07 is not None:
                await d07.close_v1()
                self._v2_d07_execution_service = None
            self._domain_followup_stopping = True
            if self._domain_followup_task is not None:
                await self._domain_followup_task
            self._d04_numeric_stopping = True
            pending_numeric = tuple(self._d04_numeric_tasks.values())
            if self._d04_numeric_scan_task is not None:
                pending_numeric += (self._d04_numeric_scan_task,)
            if pending_numeric:
                await asyncio.gather(*pending_numeric, return_exceptions=True)
            from .host.installed_d04_numeric_driver_v3 import close_installed_d04_math_v3
            await close_installed_d04_math_v3(self)
            if (self._host_lifecycle_observer is not None and self._worker is not None
                    and self._host_lifecycle_startup_receipt is not None):
                try:
                    observation = self._host_lifecycle_observer.capture_drained_shutdown_v1()
                    from .runtime.d11_host_lifecycle_driver_v1 import record_current_host_lifecycle_v1
                    self._host_lifecycle_last_status = await self._worker.call(
                        lambda graph: record_current_host_lifecycle_v1(graph, self._v2_bootstrap,
                            self._v2_model_bundle, observer=self._host_lifecycle_observer,
                            observation=observation))
                except Exception as exc:
                    self._host_lifecycle_last_status = {"status": "held", "error_code": type(exc).__name__}
            self._host_lifecycle_observer = None
            if (self._final_claim_lease is not None and self._worker is not None
                    and self._v2_bootstrap is not None):
                lease = self._final_claim_lease
                bootstrap = self._v2_bootstrap
                await self._worker.call(
                    lambda graph: graph.release_authority_lease(bootstrap, lease))
            self._final_claim_lease = None
            self._final_claim_authority = None
            self._final_claim_writer = None
            worker, self._worker = self._worker, None
            self._v2_provision = None
            self._v2_ingress = None
            self._v2_coordinator = None
            self._v2_bootstrap = None
            self._v2_port = None
            self._v2_policy = None
            self._v2_installation_grant = None
            self._v2_model_bundle = None
            self._v2_available_cpu_features = None
            self._v2_authority_client = None
            self._v2_authority_client_grant = None
            self._v2_authority_loop = None
            self._v2_natural_generation_output_bound = False
            self._v2_natural_generation_content_bound = False
            self._v2_natural_review_output_bound = False
            self._v2_natural_paid_review_current_bound = False
            self._v2_natural_readiness_receipt = None
            cost_transport, self._v2_cost_transport = self._v2_cost_transport, None
            self._v2_owner_actor = None
            self._v2_d12_backend_port = None
            self._v2_package_maintenance_port = None
            self._workbench_owner_sessions = None
            self._v2_role_probe = None
            self._v2_scene_probe = None
            self._v2_namespace = None
            self._v2_missing_ingress_policies = ()
            self._v2_namespace_provisioned = False
            store, self._store = self._store, None
            self._coordinator = None
            self._ingress_handler = None
            if worker is not None:
                try:
                    await worker.close()
                except V2FenceOutcomeUnknown:
                    if cost_transport is not None:
                        await cost_transport.close()
                    self.health = RuntimeHealth(
                        "blocked", ("v2_fence_recovery",),
                        "v2 Authority fence outcome is unresolved",
                    )
                    raise
            if cost_transport is not None:
                await cost_transport.close()
            if store is not None:
                await asyncio.to_thread(store.close)
            self.health = RuntimeHealth("stopped")
            return self.health


__all__ = (
    "AcquiredFirstIngressEncodingV2", "PreparedFirstIngressWorkerResultV1",
    "RuntimeContext", "RuntimeDependencies", "RuntimeHealth",
)
