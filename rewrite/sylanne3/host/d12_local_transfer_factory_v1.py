"""Real local paired-Authority transfer assembly with isolated target import.

The administrator supplies both management identities and fixed target lease
registrations. The browser cannot create a peer, target directory or verifier.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from threading import RLock

from ..authority_service.d12_target_registry_v1 import InstalledD12TargetRegistryV1
from ..authority_service.installed_migration_graph_proofs import InstalledSourceGraphProofV1
from ..authority_service.installed_migration_reconciliation_v1 import InstalledMigrationReconciliationV1
from ..authority_service.installed_migration_target_verifier import InstalledMigrationTargetVerifierV1
from ..graph_store import GraphStore
from ..runtime.d12_installed_transfer_registry_v1 import InstalledD12TransferRegistryV1
from ..runtime.graph_migration_transfer_verifier_v2 import InstalledGraphMigrationTransferVerifierV2
from ..runtime.graph_migration_snapshot_v1 import _schema_digest, _catalogue_digest
from .workbench_lifecycle_port_v1 import InstalledCurrentTransferPortV1


def install_d12_isolated_target_schema_v1(*, graph_db, registry, schema_fence_port, holder):
    """Installer-only schema construction, before a target lease is registered.

    The normal installed constructors provide the current schema. No DDL is
    taken from the source DB or request, and no target content lease is issued.
    The resulting schema-only coordinator is discarded before runtime import.
    """
    from ..graph_store import ProductionGraphStore
    from ..graph_coordinator import GraphCoordinator
    from ..runtime.d12_installed_graph_schema_v1 import install_d12_installed_graph_schema_v1
    from ..runtime.issuers import install_schema
    from ..runtime.graph_migration_snapshot_v1 import _install_import_receipt_schema
    path = Path(graph_db)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("fixed administrator target Graph path required")
    graph = ProductionGraphStore(path, registry)
    try:
        GraphCoordinator(graph, object(), holder=holder, content_fence_v2=schema_fence_port)
        with graph._lock:
            install_schema(graph._db)
            _install_import_receipt_schema(graph._db)
            graph._db.execute("BEGIN IMMEDIATE")
            try:
                install_d12_installed_graph_schema_v1(graph._db)
                graph._db.execute("COMMIT")
            except BaseException:
                if graph._db.in_transaction:
                    graph._db.execute("ROLLBACK")
                raise
    finally:
        graph.close()


class InstalledD12IsolatedTargetFactoryV1:
    def __init__(self, *, source_store, migration, target_registry, credential, subject):
        if type(target_registry) is not InstalledD12TargetRegistryV1:
            raise TypeError("actual administrator target reservation registry required")
        self.source, self.migration, self.registry = source_store, migration, target_registry
        self.credential, self.subject = credential, subject
        self._opened = {}
        self._lock = RLock()

    def open_isolated_target_v1(self, *, plan, permit, source_requirements, target_lease_ref):
        item = self.registry.claim_target_for_transfer_v1(lease_ref=target_lease_ref, plan=plan)
        anchor = permit.pinned_anchor
        requirements = replace(source_requirements,
            authority_id=anchor.authority_id, authority_namespace=anchor.namespace,
            activation_generation=anchor.activation_generation,
            deletion_journal_id=anchor.deletion_journal_id, deletion_seq=anchor.deletion_seq,
            deletion_digest=anchor.deletion_digest, execution_journal_id=anchor.execution_journal_id,
            execution_seq=anchor.execution_seq, execution_digest=anchor.execution_digest,
            revocation_epoch=anchor.revocation_epoch, graph_incarnation=item.graph_incarnation)
        if (permit.installation_id != item.installation_id or permit.holder != item.holder
                or permit.kind != "target_recovery" or requirements.namespace != item.namespace_id):
            raise PermissionError("target reservation differs from actual recovery permit")
        with self._lock:
            existing = self._opened.get(plan.transfer_id)
            if existing is not None:
                if existing[2] != requirements:
                    raise PermissionError("original target requirements changed")
                return existing
            verifier = InstalledGraphMigrationTransferVerifierV2(authority=self.migration,
                credential=self.credential, subject=self.subject,
                target_installation_id=item.installation_id, target_requirements=requirements)
            target = GraphStore(Path(item.graph_db), self.source._registry,
                                migration_transfer_verifier=verifier)
            try:
                with target._lock:
                    if (_schema_digest(target._db), _catalogue_digest(target._db)) != (
                            item.schema_digest, item.catalogue_digest):
                        raise PermissionError("target installed schema/catalogue changed")
                capability = object()
                target._coordinator_capability = capability
                result = (target, capability, requirements)
                self._opened[plan.transfer_id] = result
                return result
            except BaseException:
                target.close()
                raise

    def close(self):
        with self._lock:
            for target, _, _ in self._opened.values():
                target.close()
            self._opened.clear()


def install_local_d12_transfer_port_v1(*, source_store, source_graph_db,
        source_recovery_capability, migration, manifests, target_registry,
        source_credential, source_subject, target_credential, target_subject,
        model_store=None):
    """Assemble the real frozen contract; no peer is installed implicitly."""
    source_store._require_recovery_capability(source_recovery_capability)
    targets = {item.target_ref for item in manifests}
    if len(targets) != 1:
        raise ValueError("one exact administrator-paired target is required")
    target = target_registry.read_current_target_lease_v1(target_ref=next(iter(targets)))
    proof = migration._source_verifier
    if (type(proof) is not InstalledSourceGraphProofV1
            or proof._path != Path(source_graph_db).resolve(strict=True)
            or proof._namespace != migration.namespace):
        raise PermissionError("migration source verifier must pin this exact source Graph")
    reconciliation = InstalledMigrationReconciliationV1(authority=migration,
        credential=target_credential, subject=target_subject, model_store=model_store)
    holder = InstalledMigrationTargetVerifierV1(authority=migration,
        credential=target_credential, subject=target_subject,
        source_graph_db=Path(source_graph_db), target_graph_db=Path(target.graph_db),
        reconciliation_reader=reconciliation, target_lease_registry=target_registry)
    migration.install_target_recovery_holder(holder)
    factory = InstalledD12IsolatedTargetFactoryV1(source_store=source_store,
        migration=migration, target_registry=target_registry,
        credential=target_credential, subject=target_subject)
    registry = InstalledD12TransferRegistryV1(source_store=source_store,
        manifests=manifests, target_registry=target_registry)
    return InstalledCurrentTransferPortV1(registry=registry, source_store=source_store,
        source_recovery_capability=source_recovery_capability, migration=migration,
        credential=source_credential, source_subject=source_subject,
        target_credential=target_credential, target_subject=target_subject,
        target_factory=factory, target_lease_reader=target_registry,
        reconciliation_reader=reconciliation)


__all__ = ("InstalledD12IsolatedTargetFactoryV1", "install_local_d12_transfer_port_v1")
