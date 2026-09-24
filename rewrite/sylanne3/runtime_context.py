from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import inspect
from pathlib import Path
from typing import TYPE_CHECKING, Awaitable, Callable, Protocol

from .authority_service.v2_owner_contract import OwnerActorBindingV1, OwnerPrincipalV1
from .contracts import StaleRead
from .domain_registry import DomainRegistry, discover_domain_registry
from .domains.d01 import ActiveRoleQualification
from .domains.d03.context import RoleBinding
from .graph_coordinator import (
    FirstIngressOutcomeUnknown, GraphCoordinator, IngressClockSample,
    IngressIssuancePolicy, UnavailableGuard, namespace_ref,
)
from .graph_store import ProductionGraphStore
from .graph_worker import GraphWorker
from .host.ingress import HostIngressEnvelope, IngressReceipt
from .host.authority_profile import (
    AdminIngressClockPolicy, AdminIngressEncodingPolicy, AdminIngressModelPolicy,
)
from .host.v2_ingress_adapter import ingress_host_facts
from .host.installed_package import verify_installed_package
from .host.v2_installation import V2InstallationAssembly
from .host.v2_fence_port import V2FenceOutcomeUnknown, V2FencePort
from .installation_policy import AdminInstallationPolicy
from .runtime.issuers import D02ResourceIssuer, D11BudgetJobIssuer
from .runtime.restore_anchor import ExecutionJournalPort
from .runtime_contracts import InstallationGrantV2, NamespaceId
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
        if model_selection_port is not None and not callable(
                getattr(model_selection_port, "verify_admin_selection", None)):
            raise TypeError("model_selection_port must verify administrator selections")
        self._model_selection_port = model_selection_port
        self._store: ProductionGraphStore | None = None
        self._coordinator: GraphCoordinator | None = None
        self._worker: GraphWorker | None = None
        self._v2_coordinator: GraphCoordinator | None = None
        self._v2_bootstrap: object | None = None
        self._v2_port: V2FencePort | None = None
        self._v2_policy: AdminInstallationPolicy | None = None
        self._v2_installation_grant: InstallationGrantV2 | None = None
        self._v2_owner_actor: Callable[[OwnerPrincipalV1, NamespaceId], str | None] | None = None
        self._workbench_owner_sessions: BoundOwnerSessions | None = None
        self._v2_provision: Callable | None = None
        self._v2_ingress: Callable | None = None
        self._v2_role_probe: Callable | None = None
        self._v2_scene_probe: Callable | None = None
        self._v2_namespace: NamespaceId | None = None
        self._v2_missing_ingress_policies: tuple[str, ...] = ()
        self._v2_installed_model_selected = False
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

            def make_store():
                return ProductionGraphStore(
                    self._data_dir / "sylanne3.sqlite3", self._domains.type_registry,
                )

            provision = None
            ingress = None
            owner_runtime = None
            model_selected = False

            def make_coordinator(store, port):
                nonlocal provision, ingress, owner_runtime, model_selected
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
                        model_selected = (
                            self._model_selection_port.verify_admin_selection(
                                policy.namespace, installation.ingress_model) is True)
                    except Exception:
                        model_selected = False
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
                        return graph.commit_first_ingress_v2(
                            bootstrap, host, policy,
                            installation.ingress_clock, installation.ingress_encoding,
                        )
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
                self.health = RuntimeHealth(
                    "blocked", ("graph_worker",), "v2 graph worker could not initialize",
                )
                return self.health
            self._v2_provision = provision
            self._v2_ingress = ingress
            self._v2_installed_model_selected = model_selected
            self._v2_namespace = policy.namespace
            if owner_runtime is not None:
                (self._v2_coordinator, self._v2_bootstrap, port,
                 self._v2_policy, self._v2_owner_actor) = owner_runtime
                self._v2_port = port if isinstance(port, V2FencePort) else None
                self._v2_installation_grant = installation_grant
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
            self.health = RuntimeHealth(
                "limited", ("namespace_activation",),
                "v2 graph worker started; namespace admission is pending",
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
            self.health = RuntimeHealth(
                "limited", tuple(missing), detail,
            )
            return self.health

    @property
    def v2_installed_model_selected(self) -> bool:
        """Startup host check only; model request issuance is not yet enabled."""
        return self._v2_installed_model_selected

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
        service = AsyncGraphWorkbenchService(
            self._worker, DurableOwnerGrantResolver(owner_grants),
            CurrentDomainViewRegistry(lambda: self._domains), onboarding)
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
                    self.health = RuntimeHealth(
                        "blocked", ("v2_fence_recovery",),
                        "v2 Authority fence outcome is unresolved",
                    )
                    raise
            if store is not None:
                await asyncio.to_thread(store.close)
            self.health = RuntimeHealth("stopped")
            return self.health


__all__ = ("RuntimeContext", "RuntimeDependencies", "RuntimeHealth")
