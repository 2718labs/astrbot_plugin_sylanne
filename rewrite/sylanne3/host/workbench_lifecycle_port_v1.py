"""Installable D12 lifecycle facade and actual two-graph migration bridge."""
from __future__ import annotations

from ..authority_service.v2_migration_contract import SourceSnapshotReceiptV2, TargetRecoveryReceiptV2
from ..authority_service.v2_migration_service import AuthorityV2MigrationService
from ..graph_store import GraphStore
from ..runtime.graph_migration_snapshot_v1 import (
    FORMAT, seal_source_namespace_in_tx, import_snapshot_into_isolated_target_in_tx,
    read_target_import_receipt,
)
from ..runtime.graph_migration_transfer_verifier_v2 import InstalledGraphMigrationTransferVerifierV2
from ..runtime.lifecycle_operations_v1 import LifecycleOperationsV1, ResolvedTransferPlanV1
from ..runtime_contracts import SnapshotRequirementsV2


class InstalledCurrentTransferPortV1:
    """Admin-paired source/target graphs, one Authority, real import and lease read.

registry.resolve_current_transfer_plan_v1(owner,input_data) returns the typed
current ResolvedTransferPlanV1, including the current source anchor and both
paired installation identities. registry.validate_current_transfer_execution_v1
rechecks selected scope/rights/deletion/epochs and target lease under the W01
Owner fence. target_factory.open_isolated_target_v1(plan,permit,requirements)
returns (GraphStore, recovery_capability) pinned to an empty installed target;
it must install the exact schema/catalogue and the supplied migration verifier.
All providers are constructor dependencies; request JSON cannot install them.
"""
    def __init__(self, *, registry, source_store: GraphStore,
                 source_recovery_capability, migration: AuthorityV2MigrationService,
                 credential, target_factory, target_lease_reader,
                 reconciliation_reader, artifact_transfer_port=None,
                 source_subject=None, target_credential=None, target_subject=None):
        if not isinstance(source_store, GraphStore) or type(migration) is not AuthorityV2MigrationService:
            raise TypeError("installed source graph and v2 Authority service required")
        self.registry, self.source = registry, source_store
        self.source_capability = source_recovery_capability
        self.migration, self.credential = migration, credential
        self.source_subject = source_subject
        self.target_credential, self.target_subject = target_credential, target_subject
        self.target_factory, self.target_lease_reader = target_factory, target_lease_reader
        self.reconciliation_reader = reconciliation_reader
        self.artifact_transfer_port = artifact_transfer_port

    def require_installed_transfer_v1(self, input_data):
        from ..runtime.lifecycle_operations_v1 import D12PrerequisiteUnavailable
        self.migration_identity_v1("source")
        self.migration_identity_v1("target")
        if input_data.get("mode", "relocate") != "relocate" and self.artifact_transfer_port is None:
            raise D12PrerequisiteUnavailable("installed_authorized_artifact_transfer_port_unavailable")

    def bind_owner_access_v1(self, access):
        self.registry.bind_owner_access_v1(access)

    def current_resolution_scope_v1(self, input_data):
        return self.registry.current_resolution_scope_v1(input_data)

    def migration_identity_v1(self, role):
        credential, subject = ((self.credential, self.source_subject) if role == "source"
            else (self.target_credential, self.target_subject))
        if credential is None or not subject:
            raise LookupError("installed paired migration management identity unavailable")
        return credential, subject

    def resolve_current_transfer_plan_v1(self, *, owner, input_data):
        resolved = self.registry.resolve_current_transfer_plan_v1(owner=owner, input_data=input_data)
        if type(resolved) is not ResolvedTransferPlanV1:
            raise TypeError("current installed registry resolution required")
        if resolved.payload.authority_namespace != self.migration.namespace:
            raise PermissionError("registry selected another installed Authority")
        return resolved

    def validate_current_transfer_execution_v1(self, **kwargs):
        return self.registry.validate_current_transfer_execution_v1(**kwargs)

    def resolve_installed_migration_service_v1(self, *, plan, owner):
        if (plan.namespace != self.migration.namespace or plan.namespace_id != owner.namespace):
            raise PermissionError("paired migration namespace differs")
        return self.migration, self.credential

    def _source_snapshot(self, plan, permit):
        recovered = self.migration.recover_transfer(credential=self.credential,
            subject=self.migration_identity_v1("source")[1], transfer_id=plan.transfer_id)
        if recovered.history.plan != plan or recovered.history.source_permit != permit:
            raise PermissionError("current original source permit differs")
        self.source._require_recovery_capability(self.source_capability)
        with self.source._lock:
            self.source._ensure_open()
            if self.source._db.in_transaction:
                raise RuntimeError("source seal needs an independent graph transaction")
            self.source._db.execute("BEGIN IMMEDIATE")
            try:
                row = self.source._db.execute("SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                    plan.namespace_id.as_tuple).fetchone()
                metadata = GraphStore._decode_recovery(row, plan.namespace_id)
                if metadata is None:
                    raise LookupError("installed current source graph stamp absent")
                if self.source._db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_migration_import_receipts_v1'").fetchone() is None:
                    raise LookupError("install migration import schema before source freeze")
                snapshot = seal_source_namespace_in_tx(self.source, plan.namespace_id,
                    transfer_id=plan.transfer_id, source_installation_id=plan.source_installation_id,
                    permit_token=permit.token, expected=metadata, _capability=self.source_capability)
                # Sealing is read-only. Roll back incidental schema preparation;
                # installation must already have registered the import schema.
                self.source._db.execute("ROLLBACK")
                return snapshot
            except BaseException:
                if self.source._db.in_transaction:
                    self.source._db.execute("ROLLBACK")
                raise

    def read_current_source_snapshot_v2(self, *, plan, permit):
        snapshot = self._source_snapshot(plan, permit)
        req = snapshot.source_metadata.requirements
        return SourceSnapshotReceiptV2(plan.transfer_id, plan.namespace,
            plan.source_installation_id, permit.token, snapshot.digest, FORMAT,
            req.graph_incarnation, snapshot.source_metadata.graph_revision,
            snapshot.graph_epoch, req, snapshot.closure_digest)

    def recover_current_target_graph_v2(self, *, plan, permit, source_snapshot, target_lease_ref):
        status = self.migration.recover_transfer(credential=self.migration_identity_v1("target")[0],
            subject=self.migration_identity_v1("target")[1], transfer_id=plan.transfer_id)
        if (status.history.plan != plan or status.history.target_permit != permit
                or status.history.source_snapshot != source_snapshot):
            raise PermissionError("current original target permit/snapshot differs")
        snapshot = self._source_snapshot(plan, status.history.source_permit)
        if snapshot.digest != source_snapshot.snapshot_digest:
            raise PermissionError("durable source snapshot changed")
        # The factory persists this incarnation under the original transfer ID;
        # retry must reopen its same graph and return the same requirements.
        target, capability, requirements = self.target_factory.open_isolated_target_v1(
            plan=plan, permit=permit, source_requirements=source_snapshot.requirements,
            target_lease_ref=target_lease_ref)
        if not isinstance(target, GraphStore) or type(requirements) is not SnapshotRequirementsV2:
            raise TypeError("installed isolated target and requirements required")
        if (requirements.namespace != plan.namespace_id or requirements.authority_namespace != plan.namespace
                or requirements.activation_generation != permit.generation
                or requirements.graph_incarnation == source_snapshot.graph_incarnation):
            raise PermissionError("target recovery stamp differs")
        verifier = target._migration_transfer_verifier
        if type(verifier) is not InstalledGraphMigrationTransferVerifierV2:
            raise PermissionError("installed current graph transfer verifier required")
        existing = read_target_import_receipt(target, plan.namespace_id, plan.transfer_id,
                                              _capability=capability)
        if existing is None:
            handle = verifier.prepare(permit)
            with target._lock:
                if target._db.in_transaction:
                    raise RuntimeError("isolated target import requires own transaction")
                target._db.execute("BEGIN IMMEDIATE")
                try:
                    imported = import_snapshot_into_isolated_target_in_tx(target, snapshot,
                        requirements, handle, _capability=capability)
                    target._db.execute("COMMIT")
                except BaseException:
                    target._db.execute("ROLLBACK")
                    raise
                finally:
                    verifier.discard(handle)
        else:
            imported = existing
        if (imported.snapshot_digest != snapshot.digest or imported.target_graph_incarnation != requirements.graph_incarnation
                or imported.target_activation_generation != permit.generation):
            raise PermissionError("original target import differs")
        with target._lock:
            target._db.execute("BEGIN")
            try:
                original = self.reconciliation_reader.read_current_constraints_v1(
                    target_db=target._db, plan=plan, permit=permit)
            finally:
                target._db.execute("ROLLBACK")
        return TargetRecoveryReceiptV2(plan.transfer_id, plan.namespace, plan.target_installation_id,
            permit.token, snapshot.digest, permit.generation, requirements.graph_incarnation,
            imported.graph_commit_digest, requirements, original.original_digest)

    def read_current_target_lease_digest_v1(self, **kwargs):
        return self.target_lease_reader.read_current_target_lease_digest_v1(**kwargs)

    def execute_current_artifact_transfer_v1(self, **kwargs):
        if self.artifact_transfer_port is None:
            raise LookupError("installed authorized backup/share/import port unavailable")
        return self.artifact_transfer_port.execute_current_artifact_transfer_v1(**kwargs)


class WorkbenchLifecyclePortV1:
    """Single D12 backend port with optional independently owned C06/C10 ports."""
    def __init__(self, *, lifecycle: LifecycleOperationsV1, experiment_port=None, support_export_port=None):
        if type(lifecycle) is not LifecycleOperationsV1:
            raise TypeError("installed lifecycle producers required")
        self.lifecycle = lifecycle
        self.experiment_port, self.support_export_port = experiment_port, support_export_port

    def prepare_current_transfer_v1(self, *args, **kwargs):
        return self.lifecycle.prepare_current_transfer_v1(*args, **kwargs)

    def read_current_transfer_expected_epochs_v1(self, *args, **kwargs):
        return self.owner_access.read_current_transfer_expected_epochs_v1(*args, **kwargs)

    def execute_current_transfer_v1(self, *args, **kwargs):
        return self.lifecycle.execute_current_transfer_v1(*args, **kwargs)

    def read_current_installation_lifecycle_v1(self, authority, lease):
        reader = getattr(self.lifecycle.lifecycle_control_port,
                         "read_current_installation_lifecycle_v1", None)
        if not callable(reader):
            from ..runtime.lifecycle_operations_v1 import D12PrerequisiteUnavailable
            raise D12PrerequisiteUnavailable("installed_whole_host_controller_unavailable")
        return reader(authority, lease)

    def commit_current_control_v1(self, *args, **kwargs):
        return self.lifecycle.commit_current_control_v1(*args, **kwargs)

    def run_current_experiment_v1(self, *args, **kwargs):
        if self.experiment_port is None:
            raise LookupError("installed isolated experiment runner unavailable")
        return self.experiment_port.run_current_experiment_v1(*args, **kwargs)

    def export_current_support_v1(self, *args, **kwargs):
        if self.support_export_port is None:
            raise LookupError("installed authorized support export unavailable")
        return self.support_export_port.export_current_support_v1(*args, **kwargs)

    def read_current_backend_operation_original_v1(self, authority, lease, *, original_ref):
        if original_ref.startswith(("d12original:", "d12authority:")):
            return self.lifecycle.read_current_backend_operation_original_v1(authority, lease, original_ref=original_ref)
        # Other producers own their opaque reference prefixes. Registry dispatch
        # must be unique; no failure falls back to an ordinary content read.
        matches = [port for port in (self.experiment_port, self.support_export_port)
                   if port is not None and port.owns_original_ref_v1(original_ref)]
        if len(matches) != 1:
            raise LookupError("backend original has no unique installed reader")
        return matches[0].read_current_backend_operation_original_v1(authority, lease, original_ref=original_ref)


__all__ = ("InstalledCurrentTransferPortV1", "WorkbenchLifecyclePortV1")
