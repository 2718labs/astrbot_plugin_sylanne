from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
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
from .domains.d03.context import RoleBinding
from .graph_coordinator import (
    FirstIngressOutcomeUnknown, GraphCoordinator, IngressClockSample,
    IngressIssuancePolicy, UnavailableGuard,
    first_ingress_encoding_acquire_operation_id, namespace_ref,
)
from .graph_store import ProductionGraphStore
from .graph_worker import GraphWorker
from .host.ingress import HostIngressEnvelope, IngressReceipt
from .host.authority_profile import (
    AdminD03ArrivalPolicy, AdminD03SelfIdentityProjectionPolicy,
    AdminD04EncodingBaselinePolicy, AdminD06FirstIngressC02Policy,
    AdminIngressClockPolicy, AdminIngressEncodingPolicy,
    AdminIngressModelPolicy, AdminInstallationBundle, AdminModelWorkflowsV2,
    AdminModelWorkflowV2,
)
from .host.v2_ingress_adapter import ingress_host_facts
from .host.installed_package import verify_installed_package
from .host.model_egress_executor import (
    FrozenEncodingEgressResult, HostModelEgressExecutor,
)
from .host.accounting_maintenance_port import InstalledAccountingMaintenancePort
from .host.authority_client import AuthorityClient, AuthoritySelection
from .host.model_terminal_cost_port import InstalledModelTerminalCostPort
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
from .installation_policy import AdminInstallationPolicy
from .model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION, issue_first_ingress_encoding_request_v2,
)
from .runtime.issuers import D02ResourceIssuer, D11BudgetJobIssuer
from .runtime.first_ingress_v2 import ingress_ids
from .runtime.post_c02_domain_commit import commit_post_c02_reply_bundle_v1
from .host.post_c02_reply_driver import (
    PostC02ReplyCandidate, post_c02_reply_operation_id,
)
from .runtime.first_ingress_unacquired import FirstIngressUnacquiredPageV1
from .runtime.first_ingress_recovery import (
    FirstIngressRecoveryItemV1, FirstIngressRecoveryPageV1,
)
from .runtime.original_model_result_context import OriginalModelResultContextV1
from .runtime.restore_anchor import ExecutionJournalPort
from .runtime_contracts import (
    AuthorityContext, CommitReceipt, DomainBundle, InstallationGrantV2, NamespaceId,
    canonical_digest,
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


class SceneIdentityPort(Protocol):
    def verify(self, namespace: NamespaceId, scene_ref: str,
               visibility: str) -> CurrentHostScene | None: ...


@dataclass(frozen=True)
class RuntimeHealth:
    status: str
    missing_capabilities: tuple[str, ...] = ()
    detail: str = ""


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
        self._v2_policy: AdminInstallationPolicy | None = None
        self._v2_installation_grant: InstallationGrantV2 | None = None
        self._v2_model_bundle: AdminInstallationBundle | None = None
        self._v2_cost_transport: MtlsAuthorityTransport | None = None
        self._v2_owner_actor: Callable[[OwnerPrincipalV1, NamespaceId], str | None] | None = None
        self._workbench_owner_sessions: BoundOwnerSessions | None = None
        self._v2_provision: Callable | None = None
        self._v2_ingress: Callable | None = None
        self._v2_role_probe: Callable | None = None
        self._v2_scene_probe: Callable | None = None
        self._v2_namespace: NamespaceId | None = None
        self._v2_missing_ingress_policies: tuple[str, ...] = ()
        self._v2_installed_model_selected = False
        self._v2_installed_model_config_matched = False
        self._v2_namespace_provisioned = False
        self._ingress_handler: Callable[
            [HostIngressEnvelope, GraphCoordinator], Awaitable[IngressReceipt]
        ] | None = None
        self._lock = asyncio.Lock()
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
                verify_installed_package,
                self._package_root,
                policy.manifest_digest,
                available_cpu_features=installation.available_cpu_features,
            )
            if not package.verified or package.build_mode != "formal-alpha1":
                self.health = RuntimeHealth(
                    "blocked", ("installed_package",),
                    package.reason if not package.verified else "formal-alpha1 package required",
                )
                return self.health

            self._data_dir.mkdir(parents=True, exist_ok=True)

            cost_transport = None
            terminal_cost_port = None
            accounting_port = None
            self_identity_port = None
            worker_result_fact_port = None
            original_c02_cost_intent_port = None
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
                    if (status.state != "paired"
                            or await client.installation_grant_v2() != installation_grant):
                        raise RuntimeError("installed accounting observer is unpaired")
                    loop = asyncio.get_running_loop()
                    terminal_cost_port = InstalledModelTerminalCostPort(
                        client=client, bundle=bundle,
                        grant=installation_grant, owner_loop=loop)
                    accounting_port = InstalledAccountingMaintenancePort(
                        client=client, bundle=bundle,
                        grant=installation_grant, owner_loop=loop)
                    self_identity_port = InstalledCurrentSelfIdentityPort(
                        client=client, bundle=bundle,
                        grant=installation_grant, owner_loop=loop)
                    worker_result_fact_port = InstalledWorkerResultReadFactPort(
                        client=client, bundle=bundle,
                        grant=installation_grant, owner_loop=loop)
                    original_c02_cost_intent_port = InstalledOriginalC02CostIntentPort(
                        client=client, bundle=bundle,
                        grant=installation_grant, owner_loop=loop)
                except Exception:
                    if cost_transport is not None:
                        await cost_transport.close()
                    cost_transport = None
                    terminal_cost_port = accounting_port = None
                    self_identity_port = worker_result_fact_port = None
                    original_c02_cost_intent_port = None
            model_authority_hold = (
                type(bundle) is AdminInstallationBundle
                and cost_transport is None)

            def make_store():
                return ProductionGraphStore(
                    self._data_dir / "sylanne3.sqlite3", self._domains.type_registry,
                )

            provision = None
            ingress = None
            owner_runtime = None
            model_config_matched = False
            model_selected = False
            encoding_request_issuer = None

            def make_coordinator(store, port):
                nonlocal provision, ingress, owner_runtime, model_config_matched, model_selected
                nonlocal encoding_request_issuer
                if port.installation_grant != installation_grant:
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
                bundle = installation.admin_bundle
                workflows = (bundle.model_workflows
                             if type(bundle) is AdminInstallationBundle else None)
                workflow = (workflows.encode
                            if type(workflows) is AdminModelWorkflowsV2 else None)
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
                    d11_issuer=D11BudgetJobIssuer(
                        d02_issuer, installation.d11_signing_key),
                    owner_principal_resolver=(self._owner_principal_resolver
                                              if self._owner_principal_resolver is not None
                                              else current_principal if current_binding_available
                                              else None),
                    scene_identity_port=self._scene_identity_port,
                    scene_clock_policy=installation.ingress_clock,
                    dispatch_clock_policy=installation.ingress_clock,
                    encoding_request_issuer=encoding_request_issuer,
                    model_terminal_cost_port=terminal_cost_port,
                    accounting_maintenance_port=accounting_port,
                    self_identity_port=self_identity_port,
                    worker_result_fact_port=worker_result_fact_port,
                    original_c02_cost_intent_port=original_c02_cost_intent_port,
                )
                for registration in self._domains.registrations.values():
                    coordinator.register_provider(
                        bootstrap, registration.domain, registration.provider,
                        registration.proposal_schema,
                        registration.proposal_schema_hash,
                    )
                provision = lambda graph, operation_id: graph.provision_namespace_v2(
                    bootstrap, policy, operation_id=operation_id,
                )
                if (type(installation.ingress_clock) is AdminIngressClockPolicy
                        and type(installation.ingress_encoding) is AdminIngressEncodingPolicy):
                    def ingress(graph, host):
                        first = graph.commit_first_ingress_v2(
                            bootstrap, host, policy,
                            installation.ingress_clock, installation.ingress_encoding,
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
            self._v2_cost_transport = cost_transport
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
                installation_id=policy.installation_id, origin=origin)
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
        service = AsyncGraphWorkbenchService(
            self._worker, DurableOwnerGrantResolver(owner_grants),
            CurrentDomainViewRegistry(lambda: self._domains), onboarding,
            self._v2_policy,
            bundle.d06_source_correction if bundle is not None else None)
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
                receipt = await self._worker.call(self._v2_ingress, ingress_host_facts(envelope))
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
            self.health = RuntimeHealth("draining")
            worker, self._worker = self._worker, None
            self._v2_provision = None
            self._v2_ingress = None
            self._v2_coordinator = None
            self._v2_bootstrap = None
            self._v2_port = None
            self._v2_policy = None
            self._v2_installation_grant = None
            self._v2_model_bundle = None
            cost_transport, self._v2_cost_transport = self._v2_cost_transport, None
            self._v2_owner_actor = None
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
