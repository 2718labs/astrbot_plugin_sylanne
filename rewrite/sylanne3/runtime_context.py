from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import inspect
from pathlib import Path
from typing import Awaitable, Callable

from .domain_registry import DomainRegistry, discover_domain_registry
from .graph_coordinator import GraphCoordinator, IngressClockSample, IngressIssuancePolicy
from .graph_store import ProductionGraphStore
from .host.ingress import HostIngressEnvelope, IngressReceipt
from .runtime.restore_anchor import ExecutionJournalPort
from .runtime_contracts import NamespaceId


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
        if not callable(getattr(self.model_egress_authority, "begin_handoff", None)):
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
    ) -> None:
        self._data_dir = Path(data_dir)
        self._package_root = (
            Path(package_root).resolve()
            if package_root is not None
            else Path(__file__).resolve().parents[2]
        )
        self._dependencies = dependencies
        self._authority_state = authority_state
        self._domains = domains or discover_domain_registry()
        self._store: ProductionGraphStore | None = None
        self._coordinator: GraphCoordinator | None = None
        self._ingress_handler: Callable[
            [HostIngressEnvelope, GraphCoordinator], Awaitable[IngressReceipt]
        ] | None = None
        self._lock = asyncio.Lock()
        self.health = RuntimeHealth("limited", ("not_started",))

    async def start(self) -> RuntimeHealth:
        async with self._lock:
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
        if self.health.status != "ready" or self._coordinator is None or self._ingress_handler is None:
            return IngressReceipt("unavailable")
        receipt = await self._ingress_handler(envelope, self._coordinator)
        if not isinstance(receipt, IngressReceipt):
            raise TypeError("ingress handler returned an invalid receipt")
        return receipt

    async def stop(self) -> RuntimeHealth:
        async with self._lock:
            self.health = RuntimeHealth("draining")
            store, self._store = self._store, None
            self._coordinator = None
            self._ingress_handler = None
            if store is not None:
                await asyncio.to_thread(store.close)
            self.health = RuntimeHealth("stopped")
            return self.health


__all__ = ("RuntimeContext", "RuntimeDependencies", "RuntimeHealth")
