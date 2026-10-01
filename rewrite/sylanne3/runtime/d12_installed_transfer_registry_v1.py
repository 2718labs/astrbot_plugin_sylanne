"""Typed administrator artifact catalogue for complete-namespace relocation.

V1 intentionally cannot reinterpret a browser reference as a filesystem path,
accept a caller-built MigrationPlan, or claim that a full database is a redacted
share artifact. Other transfer modes require their own installed artifact port.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
import re

from ..authority_service.d12_target_registry_v1 import (
    D12TargetLeaseOriginalV1, InstalledD12TargetRegistryV1,
)
from ..authority_service.v2_migration_contract import MigrationPlanV2
from ..contracts import StaleRead
from ..domains.d12.backend_operation_contracts_v1 import D12TransferPlanPayloadV1
from ..runtime_contracts import NamespaceId, canonical_digest
from .graph_migration_snapshot_v1 import _schema_digest, _catalogue_digest, _inventory
from .lifecycle_operations_v1 import ResolvedTransferPlanV1, digest


@dataclass(frozen=True, slots=True)
class InstalledD12TransferManifestV1:
    manifest_ref: str
    namespace: NamespaceId
    authority_namespace: str
    source_installation_id: str
    source_holder: str
    target_ref: str
    scope_selection: tuple[str, ...]
    source_schema_digest: str
    source_catalogue_digest: str
    policy_ref: str
    policy_digest: str
    loss_coverage: tuple[str, ...] = ()
    schema: str = "d12.installed_relocation_manifest.v1"

    def __post_init__(self):
        if (self.schema != "d12.installed_relocation_manifest.v1"
                or type(self.namespace) is not NamespaceId
                or self.scope_selection != ("namespace:" + "/".join(self.namespace.as_tuple),)):
            raise ValueError("V1 relocation requires the explicit complete namespace selection")
        for value in (self.manifest_ref, self.authority_namespace, self.source_installation_id,
                      self.source_holder, self.target_ref, self.policy_ref):
            if type(value) is not str or not value or len(value) > 256:
                raise ValueError("bounded installed relocation identity required")
        if self.loss_coverage:
            raise ValueError("complete namespace relocation cannot silently authorize content loss")
        for value in (self.source_schema_digest, self.source_catalogue_digest, self.policy_digest):
            if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
                raise ValueError("installed transfer digests must be exact SHA256")


class InstalledD12TransferRegistryV1:
    def __init__(self, *, source_store, manifests, target_registry):
        if type(target_registry) is not InstalledD12TargetRegistryV1:
            raise TypeError("actual target pairing/reservation registry required")
        self.source, self.targets = source_store, target_registry
        self.manifests = {item.manifest_ref: item for item in manifests}
        if len(self.manifests) != len(manifests) or any(type(item) is not InstalledD12TransferManifestV1 for item in manifests):
            raise ValueError("unique typed installed transfer manifests required")
        self._access = None
        self._target = ContextVar("d12_current_paired_target", default=None)

    def bind_owner_access_v1(self, access):
        if self._access is not None or access.store.db is not self.source._db:
            raise ValueError("transfer registry must bind exactly once to its installed Graph")
        self._access = access

    @contextmanager
    def current_resolution_scope_v1(self, input_data):
        # Core/current pairing I/O finishes before W01 acquires its Graph lock.
        if "target" in input_data:
            target = self.targets.read_current_target_lease_v1(target_ref=input_data["target"])
        else:
            target = self.targets.read_current_target_lease_v1(lease_ref=input_data["target_lease_ref"])
        token = self._target.set(target)
        try:
            yield
        finally:
            self._target.reset(token)

    def _current(self, owner):
        if self._access is None:
            raise LookupError("installed D12 current Owner adapter unavailable")
        frame = self._access.current_frame()
        if frame.owner != owner:
            raise PermissionError("transfer registry Owner differs from W01 fence")
        target = self._target.get()
        if type(target) is not D12TargetLeaseOriginalV1:
            raise LookupError("current target reservation was not independently read")
        return frame, target

    def resolve_current_transfer_plan_v1(self, *, owner, input_data):
        if set(input_data) != {"mode", "target", "manifest_ref", "scope_selection"}:
            raise ValueError("transfer request fields differ")
        if input_data["mode"] != "relocate":
            raise LookupError("installed_authorized_artifact_transfer_port_unavailable")
        manifest = self.manifests.get(input_data["manifest_ref"])
        frame, target = self._current(owner)
        if (manifest is None or manifest.namespace != owner.namespace
                or tuple(input_data["scope_selection"]) != manifest.scope_selection
                or input_data["target"] != manifest.target_ref
                or target.target_ref != manifest.target_ref
                or target.authority_namespace != manifest.authority_namespace
                or target.namespace_id != owner.namespace
                or target.installation_id == manifest.source_installation_id):
            raise PermissionError("transfer intent has no exact installed manifest and paired target")
        metadata = frame.metadata
        req = metadata.requirements
        scope = frame.authority_scope
        if (req.authority_namespace != manifest.authority_namespace
                or scope.permit.holder != manifest.source_holder
                or req.activation_generation != owner.activation_generation):
            raise StaleRead("installed source identity or generation changed")
        db = self.source._db
        schema, catalogue = _schema_digest(db), _catalogue_digest(db)
        if (schema, catalogue) != (manifest.source_schema_digest, manifest.source_catalogue_digest):
            raise StaleRead("source schema/catalogue differs from installed transfer manifest")
        if (schema, catalogue) != (target.schema_digest, target.catalogue_digest):
            raise StaleRead("target schema/catalogue cannot import this namespace")
        # This is the closed migration inventory, including all source access,
        # deletion barriers, original jobs and unknown fee occupancies. An
        # unclassified table or cross-namespace row raises; no loss is guessed.
        _inventory(db, owner.namespace)
        epochs = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
                            owner.namespace.as_tuple).fetchone()
        if epochs is None:
            raise StaleRead("current source permission/deletion epochs unavailable")
        scope_digest = digest({"namespace": owner.namespace, "scope_selection": manifest.scope_selection,
            "mode": "relocate", "audience": "same_owner", "policy": manifest.policy_digest})
        payload = D12TransferPlanPayloadV1("relocate", manifest.manifest_ref, digest(manifest), scope_digest,
            manifest.source_installation_id, target.installation_id, manifest.authority_namespace,
            req, manifest.loss_coverage)
        transfer_id = "d12-transfer-" + canonical_digest((manifest, owner, scope.pinned_anchor,
            target.original_digest, metadata.graph_revision, epochs))[:48]
        plan = MigrationPlanV2(transfer_id, manifest.authority_namespace, owner.namespace,
            manifest.source_holder, manifest.source_installation_id, target.holder,
            target.installation_id, scope.pinned_anchor)
        return ResolvedTransferPlanV1(payload, plan, target.authority_namespace,
            metadata.graph_revision, epochs[0], epochs[1], manifest.policy_ref, manifest.policy_digest, target.lease_ref)

    def validate_current_transfer_execution_v1(self, *, owner, plan, expected_epochs, target_lease_ref):
        frame, target = self._current(owner)
        payload = plan["payload"]
        manifest = self.manifests.get(payload["manifest_ref"])
        epochs = self.source._db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", owner.namespace.as_tuple).fetchone()
        if (manifest is None or digest(manifest) != payload["manifest_digest"]
                or target.lease_ref != target_lease_ref or target.target_ref != manifest.target_ref
                or target.installation_id != payload["target_installation_id"]
                or target.authority_namespace != payload["authority_namespace"]
                or frame.metadata.graph_revision != expected_epochs["graph_revision"]
                or epochs != (expected_epochs["access_epoch"], expected_epochs["delete_epoch"])
                or frame.metadata.requirements.activation_generation != expected_epochs["activation_generation"]
                or plan["migration_plan"]["before_anchor"] != asdict(frame.authority_scope.pinned_anchor)):
            raise StaleRead("current source epochs, manifest, paired target or Authority anchor changed")
        _inventory(self.source._db, owner.namespace)
        return target.original_digest


__all__ = ("InstalledD12TransferManifestV1", "InstalledD12TransferRegistryV1")
