"""Content-free contracts for a v2-only Authority transfer.

These shapes carry identity, never proof that a graph snapshot or recovery is
current. The installed Authority service must verify both receipts independently.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import (NamespaceId, NamespaceRuntimeState,
                                 SnapshotRequirementsV2)
from .contract import identifier
from .v2_owner_contract import OwnerMigrationHeadV1


_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,256}$")
_PHASES = ("begun", "revoked", "target_prepared", "activated")


def _digest(value: str, name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


@dataclass(frozen=True, slots=True)
class MigrationPlanV2:
    transfer_id: str
    namespace: str
    namespace_id: NamespaceId
    source_holder: str
    source_installation_id: str
    target_holder: str
    target_installation_id: str
    before_anchor: RestoreAnchor

    def __post_init__(self) -> None:
        for name in ("transfer_id", "namespace", "source_holder",
                     "source_installation_id", "target_holder",
                     "target_installation_id"):
            identifier(getattr(self, name), name)
        if (type(self.namespace_id) is not NamespaceId
                or type(self.before_anchor) is not RestoreAnchor
                or self.before_anchor.namespace != self.namespace
                or self.before_anchor.activation_generation < 1
                or self.source_holder == self.target_holder
                or self.source_installation_id == self.target_installation_id):
            raise ValueError("migration plan identity or current anchor differs")


@dataclass(frozen=True, slots=True)
class MigrationPermitV2:
    transfer_id: str
    namespace: str
    kind: str  # source_snapshot | target_recovery
    holder: str
    installation_id: str
    generation: int
    token: str
    pinned_anchor: RestoreAnchor

    def __post_init__(self) -> None:
        for name in ("transfer_id", "namespace", "holder", "installation_id"):
            identifier(getattr(self, name), name)
        if (self.kind not in {"source_snapshot", "target_recovery"}
                or type(self.generation) is not int or self.generation < 1
                or type(self.token) is not str or _TOKEN.fullmatch(self.token) is None
                or type(self.pinned_anchor) is not RestoreAnchor
                or self.pinned_anchor.namespace != self.namespace
                or self.pinned_anchor.activation_generation != self.generation):
            raise ValueError("invalid migration permit")


@dataclass(frozen=True, slots=True)
class SourceSnapshotReceiptV2:
    transfer_id: str
    namespace: str
    source_installation_id: str
    permit_token: str
    snapshot_digest: str
    snapshot_format: str
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    requirements: SnapshotRequirementsV2
    closure_digest: str

    def __post_init__(self) -> None:
        for name in ("transfer_id", "namespace", "source_installation_id",
                     "snapshot_format", "graph_incarnation"):
            identifier(getattr(self, name), name)
        if (type(self.permit_token) is not str
                or _TOKEN.fullmatch(self.permit_token) is None
                or type(self.graph_revision) is not int or self.graph_revision < 0
                or type(self.graph_epoch) is not int or self.graph_epoch < 0
                or type(self.requirements) is not SnapshotRequirementsV2
                or self.requirements.authority_namespace != self.namespace
                or self.requirements.graph_incarnation != self.graph_incarnation):
            raise ValueError("invalid source snapshot receipt")
        _digest(self.snapshot_digest, "snapshot_digest")
        _digest(self.closure_digest, "closure_digest")


@dataclass(frozen=True, slots=True)
class TargetRecoveryReceiptV2:
    transfer_id: str
    namespace: str
    target_installation_id: str
    permit_token: str
    snapshot_digest: str
    target_generation: int
    new_graph_incarnation: str
    graph_commit_digest: str
    current_requirements: SnapshotRequirementsV2
    unknown_constraints_digest: str

    def __post_init__(self) -> None:
        for name in ("transfer_id", "namespace", "target_installation_id",
                     "new_graph_incarnation"):
            identifier(getattr(self, name), name)
        if (type(self.permit_token) is not str
                or _TOKEN.fullmatch(self.permit_token) is None
                or type(self.target_generation) is not int
                or self.target_generation < 3
                or type(self.current_requirements) is not SnapshotRequirementsV2
                or self.current_requirements.authority_namespace != self.namespace
                or self.current_requirements.graph_incarnation
                   != self.new_graph_incarnation
                or self.current_requirements.activation_generation
                   != self.target_generation):
            raise ValueError("invalid target recovery receipt")
        for name in ("snapshot_digest", "graph_commit_digest",
                     "unknown_constraints_digest"):
            _digest(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class MigrationStageReceiptV2:
    transfer_id: str
    phase: str
    request_id: str
    request_digest: str
    after_anchor: RestoreAnchor
    permit: MigrationPermitV2 | None = None

    def __post_init__(self) -> None:
        identifier(self.transfer_id, "transfer_id")
        identifier(self.request_id, "request_id")
        if (self.phase not in _PHASES
                or type(self.after_anchor) is not RestoreAnchor
                or (self.permit is not None
                    and (type(self.permit) is not MigrationPermitV2
                         or self.permit.transfer_id != self.transfer_id
                         or self.permit.pinned_anchor != self.after_anchor))):
            raise ValueError("invalid migration stage receipt")
        _digest(self.request_digest, "request_digest")


@dataclass(frozen=True, slots=True)
class MigrationStatusV2:
    plan: MigrationPlanV2
    phase: str
    current_anchor: RestoreAnchor
    receipts: tuple[MigrationStageReceiptV2, ...]
    source_permit: MigrationPermitV2
    target_permit: MigrationPermitV2 | None
    source_snapshot: SourceSnapshotReceiptV2 | None
    target_recovery: TargetRecoveryReceiptV2 | None

    def __post_init__(self) -> None:
        if (type(self.plan) is not MigrationPlanV2 or self.phase not in _PHASES
                or type(self.current_anchor) is not RestoreAnchor
                or type(self.source_permit) is not MigrationPermitV2
                or self.source_permit.transfer_id != self.plan.transfer_id
                or self.current_anchor.namespace != self.plan.namespace
                or any(type(item) is not MigrationStageReceiptV2
                       for item in self.receipts)):
            raise ValueError("invalid migration status")


@dataclass(frozen=True, slots=True)
class MigrationCurrentNamespaceV2:
    """Fresh Authority observation; an isolated state carries no usable anchor."""

    namespace: str
    holder: str | None
    generation: int
    phase: str
    transfer_id: str | None
    target: str | None
    state: NamespaceRuntimeState
    anchor: RestoreAnchor | None
    blockers: tuple[str, ...]

    def __post_init__(self) -> None:
        identifier(self.namespace, "namespace")
        for name in ("holder", "transfer_id", "target"):
            value = getattr(self, name)
            if value is not None:
                identifier(value, name)
        if (type(self.generation) is not int or self.generation < 0
                or self.phase not in {"active", "recovering", "revoked"}
                or type(self.state) is not NamespaceRuntimeState
                or (self.anchor is not None and (
                    type(self.anchor) is not RestoreAnchor
                    or self.anchor.namespace != self.namespace
                    or self.anchor.activation_generation != self.generation))
                or (self.state is NamespaceRuntimeState.QUARANTINED
                    and self.anchor is not None)
                or type(self.blockers) is not tuple
                or any(type(item) is not str for item in self.blockers)):
            raise ValueError("invalid current migration namespace state")


@dataclass(frozen=True, slots=True)
class MigrationRecoveryV2:
    """Immutable transfer history plus independently observed current state."""

    history: MigrationStatusV2
    current: MigrationCurrentNamespaceV2
    owner_head: OwnerMigrationHeadV1 | None = None

    def __post_init__(self) -> None:
        if (type(self.history) is not MigrationStatusV2
                or type(self.current) is not MigrationCurrentNamespaceV2
                or self.history.plan.namespace != self.current.namespace
                or (self.owner_head is not None and (
                    type(self.owner_head) is not OwnerMigrationHeadV1
                    or self.owner_head.authority_namespace
                       != self.history.plan.namespace
                    or self.owner_head.guard.namespace
                       != self.history.plan.namespace_id))):
            raise ValueError("migration recovery namespace differs")


__all__ = [
    "MigrationPlanV2", "MigrationPermitV2", "MigrationStageReceiptV2",
    "MigrationStatusV2", "MigrationCurrentNamespaceV2", "MigrationRecoveryV2",
    "SourceSnapshotReceiptV2", "TargetRecoveryReceiptV2",
]
