"""D12 consumes current durable backend originals; it never issues authority.

Producers persist the original and its typed result under their own authority.
The workbench rereads it through the same current Owner fence before exposing
it. Digests bind bytes and identities; they do not replace that fenced read.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from datetime import datetime, timedelta
from typing import Mapping
import re
from uuid import UUID

from ...runtime_contracts import NamespaceId, SnapshotRequirementsV2, canonical_digest

SCHEMA = "d12.backend_operation_original.v1"
STATES = frozenset({"accepted", "running", "completed", "partial", "stale",
                    "rejected", "unavailable", "cancel_requested", "cancelled",
                    "pending_confirmation"})
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _text(value: object, name: str) -> None:
    if type(value) is not str or not 1 <= len(value) <= 4096 or not value.strip():
        raise ValueError(f"{name} must be a bounded reference")


def _digest(value: object, name: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a SHA-256 digest")


def _strings(value: object, name: str) -> None:
    if type(value) is not tuple or len(value) > 128 or len(set(value)) != len(value):
        raise ValueError(f"{name} must be bounded unique strings")
    for item in value:
        _text(item, name)


@dataclass(frozen=True, slots=True)
class D12TransferPlanPayloadV1:
    mode: str
    manifest_ref: str
    manifest_digest: str
    scope_digest: str
    source_installation_id: str
    target_installation_id: str
    authority_namespace: str
    snapshot_requirements: SnapshotRequirementsV2
    loss_coverage: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.mode not in {"backup", "share", "relocate", "import"}:
            raise ValueError("unknown transfer mode")
        for name in ("manifest_ref", "source_installation_id", "target_installation_id",
                     "authority_namespace"):
            _text(getattr(self, name), name)
        for name in ("manifest_digest", "scope_digest"):
            _digest(getattr(self, name), name)
        if (type(self.snapshot_requirements) is not SnapshotRequirementsV2
                or self.snapshot_requirements.authority_namespace != self.authority_namespace):
            raise ValueError("transfer snapshot requirements differ")
        _strings(self.loss_coverage, "loss_coverage")


@dataclass(frozen=True, slots=True)
class D12TransferExecutionPayloadV1:
    transfer_id: str
    stage: str
    authority_namespace: str
    current_authority_head_digest: str
    target_lease_digest: str
    source_revoked: bool
    target_activated: bool

    def __post_init__(self) -> None:
        for name in ("transfer_id", "stage", "authority_namespace"):
            _text(getattr(self, name), name)
        for name in ("current_authority_head_digest", "target_lease_digest"):
            _digest(getattr(self, name), name)
        if type(self.source_revoked) is not bool or type(self.target_activated) is not bool:
            raise ValueError("transfer activation observations must be exact booleans")
        if self.target_activated and not self.source_revoked:
            raise ValueError("target activation requires durable source revocation")


@dataclass(frozen=True, slots=True)
class D12ControlPayloadV1:
    object_ref: str
    control: str
    effective_version: int
    domain_receipt_refs: tuple[str, ...]
    cancellation_confirmed: bool

    def __post_init__(self) -> None:
        _text(self.object_ref, "object_ref")
        _text(self.control, "control")
        if type(self.effective_version) is not int or self.effective_version < 0:
            raise ValueError("control effective version must be nonnegative")
        _strings(self.domain_receipt_refs, "domain_receipt_refs")
        if type(self.cancellation_confirmed) is not bool:
            raise ValueError("control cancellation observation must be boolean")


@dataclass(frozen=True, slots=True)
class D12MaintenancePayloadV1:
    release_manifest_ref: str
    release_manifest_digest: str
    migration_plan_ref: str
    target_capability: str
    stage: str
    active_installation_digest: str
    stage_receipt_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("release_manifest_ref", "migration_plan_ref", "target_capability", "stage"):
            _text(getattr(self, name), name)
        for name in ("release_manifest_digest", "active_installation_digest"):
            _digest(getattr(self, name), name)
        _strings(self.stage_receipt_refs, "stage_receipt_refs")


@dataclass(frozen=True, slots=True)
class D12ExperimentPayloadV1:
    experiment: str
    sandbox_namespace: NamespaceId
    retention_policy_ref: str
    isolation_original_ref: str
    actual_cost_receipt_ref: str
    report_ref: str
    report_digest: str

    def __post_init__(self) -> None:
        for name in ("experiment", "retention_policy_ref", "isolation_original_ref",
                     "actual_cost_receipt_ref", "report_ref"):
            _text(getattr(self, name), name)
        if type(self.sandbox_namespace) is not NamespaceId:
            raise ValueError("experiment sandbox namespace required")
        _digest(self.report_digest, "report_digest")


@dataclass(frozen=True, slots=True)
class D12SupportExportPayloadV1:
    allowed_data: tuple[str, ...]
    retention_policy_ref: str
    artifact_ref: str
    payload_digest: str
    redaction_original_ref: str
    access_epoch: int
    delete_epoch: int
    scope_digest: str
    expires_at_utc: str
    coverage: tuple[str, ...]

    def __post_init__(self) -> None:
        _strings(self.allowed_data, "allowed_data")
        if not self.allowed_data:
            raise ValueError("support export requires explicitly allowed data")
        for name in ("retention_policy_ref", "artifact_ref", "redaction_original_ref"):
            _text(getattr(self, name), name)
        for name in ("payload_digest", "scope_digest"):
            _digest(getattr(self, name), name)
        if any(type(getattr(self, name)) is not int or getattr(self, name) < 0
               for name in ("access_epoch", "delete_epoch")):
            raise ValueError("support export requires exact source epochs")
        expiry = datetime.fromisoformat(self.expires_at_utc)
        if expiry.tzinfo is None or expiry.utcoffset() != timedelta(0):
            raise ValueError("support artifact expiry must be UTC")
        _strings(self.coverage, "coverage")


_PAYLOADS = {"transfer_plan": D12TransferPlanPayloadV1,
             "transfer_execution": D12TransferExecutionPayloadV1,
             "control": D12ControlPayloadV1, "maintenance": D12MaintenancePayloadV1,
             "experiment": D12ExperimentPayloadV1, "support_export": D12SupportExportPayloadV1}


@dataclass(frozen=True, slots=True)
class D12BackendOperationOriginalV1:
    schema: str
    kind: str
    namespace: NamespaceId
    operation_id: str
    request_digest: str
    plan_ref: str | None
    plan_digest: str | None
    activation_generation: int
    owner_grant_ref: str
    owner_grant_revision: int
    owner_grant_digest: str
    authority_refs: tuple[tuple[str, str, str], ...]
    state: str
    coverage: tuple[str, ...]
    missing_inputs: tuple[str, ...]
    result: object
    result_digest: str
    original_ref: str
    original_digest: str

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or self.kind not in _PAYLOADS or self.state not in STATES:
            raise ValueError("unknown D12 backend original version, kind or state")
        if type(self.namespace) is not NamespaceId or type(self.result) is not _PAYLOADS[self.kind]:
            raise ValueError("backend original requires its typed namespace and payload")
        parsed = UUID(self.operation_id)
        if parsed.version != 4 or str(parsed) != self.operation_id:
            raise ValueError("backend operation id must be canonical UUID4")
        for name in ("request_digest", "owner_grant_digest", "result_digest", "original_digest"):
            _digest(getattr(self, name), name)
        for name in ("owner_grant_ref", "original_ref"):
            _text(getattr(self, name), name)
        if (type(self.activation_generation) is not int or self.activation_generation < 1
                or type(self.owner_grant_revision) is not int or self.owner_grant_revision < 1):
            raise ValueError("backend original requires current Owner versions")
        if (self.plan_ref is None) != (self.plan_digest is None):
            raise ValueError("backend plan identity must be complete")
        if self.plan_ref is not None:
            _text(self.plan_ref, "plan_ref")
            _digest(self.plan_digest, "plan_digest")
        if self.kind in {"transfer_plan", "transfer_execution", "maintenance"} and self.plan_ref is None:
            raise ValueError("backend operation requires its durable plan")
        if type(self.authority_refs) is not tuple or not 1 <= len(self.authority_refs) <= 128:
            raise ValueError("backend original requires bounded authority originals")
        for item in self.authority_refs:
            if type(item) is not tuple or len(item) != 3:
                raise ValueError("authority original reference shape differs")
            _text(item[0], "authority kind")
            _text(item[1], "authority reference")
            _digest(item[2], "authority original digest")
        _strings(self.coverage, "coverage")
        _strings(self.missing_inputs, "missing_inputs")
        if self.state == "completed" and self.missing_inputs:
            raise ValueError("completed operation cannot have missing inputs")
        if self.kind == "experiment" and self.result.sandbox_namespace == self.namespace:
            raise ValueError("experiment cannot use the production namespace")
        if self.result_digest != "sha256:" + canonical_digest(self.result):
            raise ValueError("backend typed result digest differs")
        if self.original_digest != backend_original_digest_v1(self):
            raise ValueError("backend original digest differs")

    def to_wire(self) -> dict[str, object]:
        return asdict(self)


def backend_original_digest_v1(original: object) -> str:
    """Canonical original bytes, excluding the digest that identifies them."""
    return "sha256:" + canonical_digest({
        field.name: original[field.name] if isinstance(original, Mapping) else getattr(original, field.name)
        for field in fields(D12BackendOperationOriginalV1)
        if field.name != "original_digest"
    })


__all__ = ("SCHEMA", "STATES", "D12BackendOperationOriginalV1",
           "D12TransferPlanPayloadV1", "D12TransferExecutionPayloadV1",
           "D12ControlPayloadV1", "D12MaintenancePayloadV1", "D12ExperimentPayloadV1", "D12SupportExportPayloadV1",
           "backend_original_digest_v1")
