"""Installed D12 command admission on W01's real Owner transaction.

Only the installation factory can construct this adapter. Workbench input is
intent; the process lease, signed session, grant and Authority permit are reread
by GraphCoordinator before the callback may observe or change business rows.
"""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import asdict, dataclass
import json

from ..contracts import Event, Scope
from ..graph_store import GraphStore, ProductionGraphStore
from ..graph_types import GraphCandidate, GraphVersion, owner_grant_key
from ..runtime_contracts import canonical_digest, canonical_serialize
from .d11_types import job_graph_write
from .jobs import get_job
from .lifecycle_operations_v1 import (
    LifecycleOperationsV1, LifecycleOriginalStoreV1, OwnerOperationBindingV1,
    decode_original, digest, D12PrerequisiteUnavailable,
)


@dataclass(frozen=True, slots=True)
class D12CurrentCommandFrameV1:
    owner: OwnerOperationBindingV1
    metadata: object
    epoch: object
    authority_scope: object
    trusted_now_utc: float


class InstalledD12OwnerAccessV1:
    def __init__(self, coordinator, *, bootstrap, store, operation_status_port=None):
        coordinator._admin(bootstrap)
        if (not isinstance(coordinator._GraphCoordinator__store, ProductionGraphStore)
                or coordinator._GraphCoordinator__content_fence_v2 is None
                or store.db is not coordinator._GraphCoordinator__store._db
                or store.lock is not coordinator._GraphCoordinator__store._lock):
            raise TypeError("D12 requires the installed production Graph and Authority")
        self.coordinator, self.store = coordinator, store
        self.operation_status_port = operation_status_port
        self._frame = ContextVar("d12_installed_command_frame", default=None)

    @staticmethod
    def owner_binding(authority, owner):
        return OwnerOperationBindingV1(authority.namespace, authority.actor,
            authority.activation_generation, owner_grant_key(*authority.namespace.as_tuple).token,
            owner.grant_revision, owner.grant_digest,
            "owner-authority:" + owner.authorization_head,
            digest({"authorization_head": owner.authorization_head,
                    "authorization_revision": owner.authorization_revision,
                    "revocation_epoch": owner.revocation_epoch,
                    "principal": asdict(owner.principal)}))

    def current_frame(self):
        frame = self._frame.get()
        if frame is None or not self.store.db.in_transaction:
            raise PermissionError("D12 current frame is only available inside W01 commit")
        return frame

    def execute_current_owner_command_v1(self, authority, lease, *, operation_id,
                                         request_digest, capability, commit, domains=(),job_cancel_request=None):
        if job_cancel_request is not None:
            from .current_owner_job_cancel_v3 import prepare_current_job_cancel_v3
            if capability!="workbench.control":raise PermissionError("D12 cancel requires current Owner control")
            return prepare_current_job_cancel_v3(self,authority,lease,operation_id=operation_id,
                request_digest=request_digest,command=job_cancel_request,commit=commit,domains=domains)
        return self._execute_current_owner_command_v3(authority,lease,operation_id=operation_id,
            request_digest=request_digest,capability=capability,commit=commit,domains=domains)

    def _execute_prepared_cancel_v3(self,reader,capsule):
        if reader.cancel_access is not self or capsule.reader is not reader:
            raise PermissionError("D12 cancel capsule crossed installed producer")
        return self._execute_current_owner_command_v3(reader.authority,reader.lease,operation_id=reader.operation_id,
            request_digest=reader.request_digest,capability="workbench.control",commit=reader.cancel_commit,
            domains=reader.cancel_domains,job_cancel_prepare=capsule)

    def _execute_current_owner_command_v3(self,authority,lease,*,operation_id,request_digest,capability,commit,
            domains,job_cancel_prepare=None):
        c = self.coordinator
        def current_commit(db, metadata, epoch, now, owner, scope):
            if db is not self.store.db or not db.in_transaction:
                raise RuntimeError("D12 callback requires the existing W01 transaction")
            binding = self.owner_binding(authority, owner)
            token = self._frame.set(D12CurrentCommandFrameV1(binding, metadata, epoch, scope, now))
            try:
                original = commit(binding)
                # Job control updates the same graph projection used by current
                # worker admission. Runtime cancellation alone is insufficient.
                if original.kind == "control" and original.result.control == "cancel_job":
                    job = get_job(db, original.result.object_ref.removeprefix("job:"))
                    write = job_graph_write(job)
                    if job_cancel_prepare is None:
                        raise PermissionError("D12 cancel requires its actual exact job Source preparation")
                    from .current_owner_job_cancel_v3 import current_cancel_projection_v3
                    projection=current_cancel_projection_v3(db,job.job_id)
                    row=(projection.revision,canonical_serialize(projection.value))
                    from ..contracts import canonical_json
                    if row is None or row[1] != canonical_json(write.value):
                        candidate = GraphCandidate(Event(
                            Scope(*authority.namespace.as_tuple, job.activity_id),
                            "d12-control-" + operation_id, now, "d12.job_cancel.v1",
                            {"operation_id": operation_id, "request_digest": request_digest}),
                            (GraphVersion(write.key, row[0] if row else 0),), (write,), (epoch,))
                        GraphStore._graph_commit_in_transaction(c._GraphCoordinator__store, candidate,
                            _capability=c._GraphCoordinator__graph_capability)
                        c._GraphCoordinator__store.cas_graph_recovery_metadata(metadata,
                            metadata.requirements, _capability=c._GraphCoordinator__graph_capability)
                return json.loads(canonical_serialize(asdict(original)))
            finally:
                self._frame.reset(token)
        result = c._owner_domain_write_v3(authority, lease,
            operation_id=operation_id, request_digest=request_digest,
            domains=domains,
            capability=capability, commit=current_commit,job_cancel_prepare=job_cancel_prepare)
        return decode_original(result)

    def read_current_backend_operation_original_v1(self, authority, lease, *, original_ref):
        c = self.coordinator
        c._authorize(lease, authority, frozenset(), owner_read=True)
        owner = c._GraphCoordinator__owner_leases.get(lease)
        proof = c._GraphCoordinator__owner_session_proofs.get(lease)
        if owner is None or proof is None:
            raise PermissionError("D12 status requires the authenticated Owner lease")
        if self.operation_status_port is not None and self.operation_status_port.owns_original_ref_v1(original_ref):
            return self.operation_status_port.read_current_backend_operation_original_v1(
                authority, lease, original_ref=original_ref)
        def read():
            original = self.store.original(authority.namespace, original_ref)
            binding = self.owner_binding(authority, owner)
            if (original.owner_grant_ref, original.owner_grant_revision,
                    original.owner_grant_digest, original.activation_generation) != (
                    binding.grant_ref, binding.grant_revision, binding.grant_digest,
                    binding.activation_generation):
                raise PermissionError("D12 original belongs to a different Owner grant")
            return original
        return c._read_v2(authority, read, owner_binding=owner, owner_session_proof=proof)

    def read_current_transfer_expected_epochs_v1(self, authority, lease, *, original_ref):
        c = self.coordinator
        c._authorize(lease, authority, frozenset(), owner_read=True)
        owner = c._GraphCoordinator__owner_leases.get(lease)
        proof = c._GraphCoordinator__owner_session_proofs.get(lease)
        if owner is None or proof is None:
            raise PermissionError("signed Owner transfer preview required")
        def read():
            original = self.store.original(authority.namespace, original_ref)
            if (original.kind != "transfer_plan" or original.owner_grant_digest != owner.grant_digest
                    or original.activation_generation != authority.activation_generation):
                raise PermissionError("current transfer preview Owner differs")
            plan_digest, plan = self.store.plan(authority.namespace, original.plan_ref)
            metadata, _ = c._v2_graph_stamp(authority.namespace)
            epochs = self.store.db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
                "WHERE bot=? AND persona=?", authority.namespace.as_tuple).fetchone()
            if (metadata.graph_revision != plan["graph_revision"]
                    or epochs != (plan["access_epoch"], plan["delete_epoch"])):
                from ..contracts import StaleRead
                raise StaleRead("current transfer preview source epochs changed")
            return {"schema": "d12.transfer_preview.v1", "original_ref": original_ref,
                "target_lease_ref": plan.get("target_lease_ref"), "current_epochs": {
                    "schema": "d12.transfer_expected_epochs.v1", "plan_digest": plan_digest,
                    "graph_revision": plan["graph_revision"], "access_epoch": plan["access_epoch"],
                    "delete_epoch": plan["delete_epoch"], "activation_generation": original.activation_generation}}
        return c._read_v2(authority, read, owner_binding=owner, owner_session_proof=proof)


class UnpairedTransferPortV1:
    """No target is inferred from browser selectors or source installation."""
    def require_installed_transfer_v1(self, input_data):
        raise D12PrerequisiteUnavailable("installed_transfer_pairing_unavailable")

    def resolve_current_transfer_plan_v1(self, **_):
        raise D12PrerequisiteUnavailable("installed_transfer_pairing_unavailable")


def install_d12_services_v1(coordinator, *, bootstrap, transfer_port=None,
                            operation_status_port=None, domain_controls=(),
                            lifecycle_control_port=None):
    """Install concrete D12 admission and durable controls before exposing W09.

    A transfer port must be independently administrator-paired. Its absence
    holds transfer only; authenticated job control remains available.
    """
    from ..host.workbench_lifecycle_port_v1 import WorkbenchLifecyclePortV1
    coordinator._admin(bootstrap)
    graph = coordinator._GraphCoordinator__store
    store = LifecycleOriginalStoreV1(db=graph._db, lock=graph._lock)
    store.install_schema()
    if operation_status_port is None:
        from ..host.d12_operation_status_port_v1 import InstalledD12OperationStatusPortV1
        operation_status_port = InstalledD12OperationStatusPortV1(coordinator=coordinator,
            bootstrap=bootstrap, authority_port=coordinator._GraphCoordinator__content_fence_v2)
    access = InstalledD12OwnerAccessV1(coordinator, bootstrap=bootstrap, store=store,
        operation_status_port=operation_status_port)
    if transfer_port is not None:
        transfer_port.bind_owner_access_v1(access)
    if lifecycle_control_port is None:
        from ..host.d12_installation_control_port_v1 import InstalledD12InstallationControlPortV1
        lifecycle_control_port = InstalledD12InstallationControlPortV1(coordinator=coordinator,
            bootstrap=bootstrap, authority_port=coordinator._GraphCoordinator__content_fence_v2)
    lifecycle = LifecycleOperationsV1(store=store, owner_command_fence=None,
        owner_status_fence=None, transfer_port=transfer_port or UnpairedTransferPortV1(),
        domain_controls=domain_controls, lifecycle_control_port=lifecycle_control_port,
        command_executor=access.execute_current_owner_command_v1,
        status_reader=access.read_current_backend_operation_original_v1)
    lifecycle.operation_status_port = operation_status_port
    binder = getattr(lifecycle_control_port, "bind_lifecycle_v1", None)
    if callable(binder):
        binder(lifecycle)
    result = WorkbenchLifecyclePortV1(lifecycle=lifecycle)
    result.operation_status_port = operation_status_port
    result.owner_access = access
    return result


__all__ = ("D12CurrentCommandFrameV1", "InstalledD12OwnerAccessV1", "install_d12_services_v1")
