"""Concrete cold-process C09 assembly over the daemon's exact current bundle.

The administrator supplies typed installation assets, never per-request
callbacks or caller-created cleanup receipts. No old process hot-swap exists.
"""
from __future__ import annotations

from pathlib import Path

from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import SURFACES
from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
from .c09_surface_cleanup_v1 import InstalledC09SurfaceCleanupV1
from .c09_close_apply_v1 import InstalledC09CloseApplyV1
from .c09_graph_application_v1 import InstalledC09GraphApplicationV1
from .erasure_closure_inventory import AuthorityErasureClosureInventory
from ..graph_coordinator import GraphCoordinator, namespace_ref
from ..graph_store import ProductionGraphStore
from ..graph_types import TypeRegistry
from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2
from ..runtime_contracts import NamespaceId
from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
from ..runtime.issuers import D02ResourceIssuer


class _LocalInstalledFencePortV1:
    """Actual local Authority service calls; no synthesized permits or ACKs."""
    def __init__(self, service, credential, subject, namespace):
        self.service, self.credential, self.subject, self.namespace = service, credential, subject, namespace

    def _scope(self, namespace, authority_namespace):
        if namespace != self.namespace or authority_namespace != self.service.namespace:
            raise AuthorityUnavailable("installed maintenance graph namespace differs")

    def current_anchor(self, *, namespace, authority_namespace):
        self._scope(namespace, authority_namespace)
        return self.service.current_anchor(credential=self.credential, subject=self.subject)

    def begin_fence(self, *, namespace, authority_namespace, holder, generation,
                    operation, operation_id, expected_anchor, **effect):
        self._scope(namespace, authority_namespace)
        if generation != expected_anchor.activation_generation:
            raise AuthorityUnavailable("installed local fence generation differs")
        return self.service.begin_fence(credential=self.credential, subject=self.subject,
            holder=holder, operation=operation, operation_id=operation_id,
            expected_anchor=expected_anchor, **effect)

    def validate_fence(self, scope):
        self._scope(scope.namespace, scope.authority_namespace)
        return self.service.validate_fence(credential=self.credential,
            subject=self.subject, permit=scope.permit)

    def finish_fence(self, scope, *, request_id, request_digest):
        self._scope(scope.namespace, scope.authority_namespace)
        return self.service.finish_fence(credential=self.credential, subject=self.subject,
            permit=scope.permit, request_id=request_id, request_digest=request_digest)


class InstalledC09MaintenanceFactoryV1:
    """Bind all four current stores, recovery readers and twelve actual cleaners.

    Provider prompt caches and nonempty backups require their independently
    installed provider/backup cleaner. A sanitized Graph hash cannot prove
    those external surfaces empty. Missing support remains a specific HOLD.
    """
    def __init__(self, *, namespace, peer, registry, resource_issuer,
            body_authority, inventory_manifest, target_directory,
            provider_cache_cleanup, controlled_backup_cleanup=None, controlled_backup_registry=None,
            budget_job_issuer=None):
        if (type(namespace) is not NamespaceId or type(registry) is not TypeRegistry
                or type(resource_issuer) is not D02ResourceIssuer
                or type(body_authority) is not D02BodyQuoteAuthority
                or type(inventory_manifest) is not InstallationFilesystemManifestV2
                or inventory_manifest.namespace != namespace_ref(namespace)
                or type(peer) is not tuple or len(peer) != 2):
            raise AuthorityUnavailable("typed installed C09 factory assets required")
        from ..runtime.issuers import D11BudgetJobIssuer
        if budget_job_issuer is not None and (type(budget_job_issuer) is not D11BudgetJobIssuer
                or budget_job_issuer.resource_issuer is not resource_issuer):
            raise AuthorityUnavailable("C09 Life requires the actual same-installation D11/D02 issuers")
        for service in (provider_cache_cleanup, controlled_backup_cleanup):
            if service is not None and any(not callable(getattr(service, name, None))
                    for name in ("clean_installed_surface_v1", "reread_installed_surface_v1")):
                raise AuthorityUnavailable("installed surface cleaner and independent reader required")
        if provider_cache_cleanup is None:
            raise AuthorityUnavailable("installed provider cache disposition service required")
        if controlled_backup_registry is not None:
            from .d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2
            if (type(controlled_backup_registry) is not InstalledPackageSupervisorJournalV2
                    or controlled_backup_cleanup is not None):
                raise AuthorityUnavailable("one exact installed managed-backup registry is required")
        self.namespace, self.peer, self.registry = namespace, peer, registry
        self.resource_issuer, self.body_authority = resource_issuer, body_authority
        self.budget_job_issuer = budget_job_issuer
        self.inventory, self.target_directory = inventory_manifest, Path(target_directory)
        self.provider_cache_cleanup = provider_cache_cleanup
        self.controlled_backup_cleanup = controlled_backup_cleanup
        self.controlled_backup_registry = controlled_backup_registry

    def __call__(self, *, daemon, control, gate):
        namespace = namespace_ref(self.namespace)
        installed = daemon.config.installations_v2.get(self.peer)
        if (installed is None or installed.installation_id != control.installation_id
                or self.inventory.installation_id != control.installation_id
                or self.inventory.authority_id != control.authority_id
                or daemon.config.namespace_bindings_v2.get((*self.peer, self.namespace)) != namespace):
            raise AuthorityUnavailable("C09 factory differs from installed daemon identity")
        erasure = daemon.server._current_erasure_prepares.get((namespace, control.installation_id))
        accepted = daemon.server._current_accepted_erasure_reads.get((namespace, control.installation_id))
        if erasure is None or accepted is None:
            raise AuthorityUnavailable("C09 current Owner erasure services unavailable")
        service = daemon.server._v2_fences[namespace]
        recovery = erasure._recovery
        scoped = recovery.scoped_store
        closure = AuthorityErasureClosureInventory(scoped=scoped, installation_id=control.installation_id)
        credential = daemon.config.local_administrator_credential("c09_maintenance", namespace)
        subject = "mtls:sha256:" + self.peer[0]
        graph = ProductionGraphStore(daemon.config.graph_db, self.registry)
        try:
            bootstrap = object()
            coordinator = GraphCoordinator(graph, bootstrap,
                holder=installed.administrator_holder,
                content_fence_v2=_LocalInstalledFencePortV1(service, credential, subject, self.namespace))
            application = InstalledC09GraphApplicationV1(control=control, core=daemon.core,
                scoped=scoped, coordinator=coordinator, bootstrap=bootstrap,
                namespace=self.namespace, subject=subject, credential=credential)
            close_apply = InstalledC09CloseApplyV1(control=control, service=service,
                recovery=recovery, graph_application=application, subject=subject, credential=credential)
            cleaners = {surface: InstalledC09SurfaceCleanupV1(control=control, gate=gate,
                inventory_manifest=self.inventory, surface=surface, registry=self.registry)
                for surface in SURFACES - {"model_prompt_caches"}}
            cleaners["model_prompt_caches"] = self.provider_cache_cleanup
            if self.controlled_backup_cleanup is not None:
                cleaners["controlled_backups"] = self.controlled_backup_cleanup
            elif self.controlled_backup_registry is not None:
                from .d12_managed_backup_cleanup_v2 import InstalledD12ManagedBackupCleanupV2
                cleaners["controlled_backups"] = InstalledD12ManagedBackupCleanupV2(control=control, gate=gate,
                    inventory_manifest=self.inventory, supervisor_journal=self.controlled_backup_registry)
            internal = dict(daemon.core._execution_redaction_c04_services.get(namespace, {}))
            daemon.core.install_current_c09_recovery_readers_v4(closure=closure, graph=graph,
                namespace_id=self.namespace, resource_issuer=self.resource_issuer,
                body_authority=self.body_authority, internal_services=internal,
                budget_job_issuer=self.budget_job_issuer)
            result = InstalledC09MaintenanceV1(control=control, gate=gate, core=daemon.core,
                closure=closure, graph=graph, namespace_id=self.namespace,
                accepted_service=accepted, inventory_manifest=self.inventory,
                target_directory=self.target_directory, subject=subject, credential=credential,
                service_handles=(graph,), surface_services=cleaners, close_apply_service=close_apply)
            return result
        except BaseException:
            graph.close()
            raise
