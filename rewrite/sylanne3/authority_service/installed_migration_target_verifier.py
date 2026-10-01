"""Pinned, read-only target migration proof; missing originals remain HOLD.

The source graph is the durable snapshot original. Both graph paths and the
Authority recovery identity are installed, never supplied by a migration RPC.
An installed reconciliation reader independently rereads effects/model/CPU and
retained job/budget/Body originals. Unknown constraints retain their identity
and occupancy; a final in-transaction reread guards Authority activation.
"""

from __future__ import annotations

from contextlib import closing, contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from pathlib import Path
import sqlite3
from typing import Iterator

from ..graph_store import (
    GraphStore, _assert_migration_owner_head_in_transaction,
)
from ..runtime.graph_migration_snapshot_v1 import (
    FORMAT, _DEFERRED, _catalogue_digest, _hash, _inventory,
    _read_import_receipt_locked, _schema_digest,
)
from ..runtime_contracts import NamespaceRuntimeState
from .contract import AuthorityUnavailable
from .v2_migration_contract import (
    MigrationPermitV2, MigrationPlanV2, TargetRecoveryReceiptV2,
)
from .v2_migration_service import AuthorityV2MigrationService


@dataclass(frozen=True, slots=True)
class TargetGraphHeldProofV1:
    """Exact proof yielded only while the target SQLite writer lock is held."""

    transfer_id: str
    target_installation_id: str
    permit_token: str
    snapshot_digest: str
    graph_commit_digest: str
    target_generation: int
    new_graph_incarnation: str
    reconciliation_digest: str | None = None


class InstalledMigrationTargetVerifierV1:
    """Recheck two persistent graphs and Authority before target activation.

    Independent heads, current Owner, complete source/target equality and actual
    reconciliation originals all gate activation; missing providers fail closed.
    """

    def __init__(
        self, *, authority: AuthorityV2MigrationService,
        credential: object, subject: str,
        source_graph_db: Path, target_graph_db: Path,
        reconciliation_reader=None, target_lease_registry=None,
    ) -> None:
        source, target = Path(source_graph_db), Path(target_graph_db)
        if (type(authority) is not AuthorityV2MigrationService
                or type(subject) is not str or not subject
                or not source.is_absolute() or not target.is_absolute()
                or source == target):
            raise ValueError("installed migration target identity is required")
        self._authority = authority
        self._credential = credential
        self._subject = subject
        self._source = source.resolve(strict=False)
        self._target = target.resolve(strict=False)
        from .installed_migration_reconciliation_v1 import InstalledMigrationReconciliationV1
        if (reconciliation_reader is not None and
                (type(reconciliation_reader) is not InstalledMigrationReconciliationV1 or
                 reconciliation_reader.authority is not authority)):
            raise ValueError("same Authority current reconciliation reader required")
        from .d12_target_registry_v1 import InstalledD12TargetRegistryV1
        if (target_lease_registry is not None and (
                type(target_lease_registry) is not InstalledD12TargetRegistryV1
                or target_lease_registry.core is not authority.core)):
            raise ValueError("target lease registry must belong to the same Authority Core")
        self._target_lease_registry = target_lease_registry
        self._reconciliation = reconciliation_reader
        self._held_reconciliation = ContextVar("migration_target_reconciliation", default=None)

    @staticmethod
    def _read(db_path: Path) -> sqlite3.Connection:
        if not db_path.is_file():
            raise FileNotFoundError(db_path)
        db = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True,
                             isolation_level=None)
        db.execute("BEGIN")
        return db

    @contextmanager
    def _target_writer_lock(self) -> Iterator[sqlite3.Connection]:
        """Acquire a real SQLite writer lock without changing target rows."""
        if not self._target.is_file():
            raise AuthorityUnavailable("installed target graph is absent; HOLD")
        try:
            db = sqlite3.connect(self._target.as_uri() + "?mode=rw", uri=True,
                                 isolation_level=None, timeout=5.0)
            with closing(db):
                db.execute("BEGIN IMMEDIATE")
                try:
                    yield db
                finally:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
        except sqlite3.Error as exc:
            raise AuthorityUnavailable("target graph write fence unavailable; HOLD") from exc

    def _require_reconciled_constraints(self, target_db, receipt, plan, permit):
        if self._reconciliation is None:
            raise AuthorityUnavailable("installed current reconciliation reader is absent; HOLD")
        original = self._reconciliation.read_current_constraints_v1(
            target_db=target_db, plan=plan, permit=permit)
        if original.original_digest != receipt.unknown_constraints_digest:
            raise AuthorityUnavailable("current original reconciliation digest differs; HOLD")
        return original

    def require_current_reconciliation_in_tx(self, db, held: TargetGraphHeldProofV1,
                                             execution_head, deletion_head):
        """Called by activate_target inside its final frozen-head Core CAS.

        This rechecks live Authority originals while the same target writer
        lock remains held. No second graph connection or content read fallback.
        """
        context = self._held_reconciliation.get()
        if context is None or self._reconciliation is None:
            raise AuthorityUnavailable("target reconciliation hold is absent")
        target_db, receipt, plan, permit = context
        if self._target_lease_registry is not None:
            self._target_lease_registry.require_current_target_lease_in_tx_v1(
                db, plan=plan, permit=permit, held=held)
        current = self._reconciliation.read_constraints_in_authority_tx_v1(
            db=db, target_db=target_db, plan=plan, permit=permit,
            deletion_head=deletion_head, execution_head=execution_head)
        if current.original_digest != held.reconciliation_digest or current.original_digest != receipt.unknown_constraints_digest:
            raise AuthorityUnavailable("reconciliation changed before target activation CAS")

    @contextmanager
    def hold(self, receipt: TargetRecoveryReceiptV2,
             plan: MigrationPlanV2,
             permit: MigrationPermitV2) -> Iterator[TargetGraphHeldProofV1]:
        """Hold a same-host SQLite write fence through the caller's Core CAS.

        The caller must enter this context before verification and leave it
        only after the Authority transaction commits or aborts. A WAL read
        transaction is insufficient: BEGIN IMMEDIATE prevents every competing
        SQLite writer to this pinned target file, including maintenance paths.
        This context never mutates the graph; ROLLBACK releases the fence.
        """
        with self._target_writer_lock() as target_db:
            if not self._verify_persisted_graph_and_heads(receipt, plan, permit):
                raise AuthorityUnavailable("target graph proof is unavailable; HOLD")
            # TargetRecoveryReceiptV2 carries only a claimed digest for the
            # deferred external effects and costs. This gate cannot be
            # satisfied by an installer-supplied boolean.
            reconciliation = self._require_reconciled_constraints(target_db, receipt, plan, permit)
            token = self._held_reconciliation.set((target_db, receipt, plan, permit))
            try:
                yield TargetGraphHeldProofV1(
                    receipt.transfer_id, receipt.target_installation_id,
                    receipt.permit_token, receipt.snapshot_digest,
                    receipt.graph_commit_digest, receipt.target_generation,
                    receipt.new_graph_incarnation, reconciliation.original_digest)
            finally:
                self._held_reconciliation.reset(token)

    def __call__(self, receipt: TargetRecoveryReceiptV2,
                 plan: MigrationPlanV2, permit: MigrationPermitV2) -> bool:
        try:
            with self.hold(receipt, plan, permit):
                return True
        except Exception:
            return False

    def _verify_persisted_graph_and_heads(
            self, receipt: TargetRecoveryReceiptV2,
            plan: MigrationPlanV2, permit: MigrationPermitV2) -> bool:
        if (type(receipt) is not TargetRecoveryReceiptV2
                or type(plan) is not MigrationPlanV2
                or type(permit) is not MigrationPermitV2
                or plan.namespace != self._authority.namespace
                or receipt.transfer_id != plan.transfer_id
                or receipt.namespace != plan.namespace
                or receipt.target_installation_id != plan.target_installation_id
                or receipt.permit_token != permit.token
                or receipt.target_generation != permit.generation
                or receipt.new_graph_incarnation
                   != receipt.current_requirements.graph_incarnation
                or permit.kind != "target_recovery"
                or permit.transfer_id != plan.transfer_id
                or permit.namespace != plan.namespace
                or permit.holder != plan.target_holder
                or permit.installation_id != plan.target_installation_id):
            return False
        try:
            recovery = self._authority.recover_transfer(
                credential=self._credential, subject=self._subject,
                transfer_id=plan.transfer_id)
            status, current = recovery.history, recovery.current
            source = status.source_snapshot
            if (status.plan != plan or status.phase != "target_prepared"
                    or status.target_permit != permit
                    or status.target_recovery is not None
                    or source is None or source.snapshot_format != FORMAT
                    or source.source_installation_id
                       != plan.source_installation_id
                    or source.permit_token != status.source_permit.token
                    or source.requirements.namespace != plan.namespace_id
                    or current.state is not NamespaceRuntimeState.RECOVERING
                    or current.phase != "recovering"
                    or current.holder != plan.target_holder
                    or current.transfer_id != plan.transfer_id
                    or current.target != plan.target_holder
                    or current.generation != permit.generation
                    or current.blockers != ("activation_unsettled",)
                    or current.anchor != status.current_anchor
                    or current.anchor != permit.pinned_anchor
                    or receipt.snapshot_digest != source.snapshot_digest
                    or receipt.current_requirements.namespace
                       != plan.namespace_id
                    or receipt.current_requirements.activation_generation
                       != permit.generation
                    or receipt.current_requirements.authority_id
                       != current.anchor.authority_id
                    or receipt.current_requirements.authority_namespace
                       != current.anchor.namespace
                    or (receipt.current_requirements.deletion_journal_id,
                        receipt.current_requirements.deletion_seq,
                        receipt.current_requirements.deletion_digest,
                        receipt.current_requirements.execution_journal_id,
                        receipt.current_requirements.execution_seq,
                        receipt.current_requirements.execution_digest,
                        receipt.current_requirements.revocation_epoch)
                       != (current.anchor.deletion_journal_id,
                           current.anchor.deletion_seq,
                           current.anchor.deletion_digest,
                           current.anchor.execution_journal_id,
                           current.anchor.execution_seq,
                           current.anchor.execution_digest,
                           current.anchor.revocation_epoch)):
                return False
            with closing(self._read(self._source)) as source_db, closing(
                    self._read(self._target)) as target_db:
                namespace = plan.namespace_id
                source_row = source_db.execute(
                    "SELECT schema,requirements_json,graph_revision "
                    "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                    namespace.as_tuple).fetchone()
                source_metadata = GraphStore._decode_recovery(
                    source_row, namespace)
                if (source_metadata is None
                        or source_metadata.requirements != source.requirements
                        or source_metadata.graph_revision != source.graph_revision):
                    return False
                source_epoch_row = source_db.execute(
                    "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                    namespace.as_tuple).fetchone()
                source_epoch = source_epoch_row[0] if source_epoch_row else 0
                source_schema = _schema_digest(source_db)
                source_catalogue = _catalogue_digest(source_db)
                source_tables = _inventory(source_db, namespace)
                source_import_rows = next(
                    rows for name, _, rows in source_tables
                    if name == "graph_migration_import_receipts_v1")
                if any(row[2] == plan.transfer_id for row in source_import_rows):
                    return False
                snapshot_digest = _hash((
                    FORMAT, plan.transfer_id, namespace.as_tuple,
                    plan.source_installation_id, status.source_permit.token,
                    asdict(source_metadata), source_epoch, source_schema,
                    source_catalogue, source_tables, _DEFERRED))
                if (source_epoch != source.graph_epoch
                        or snapshot_digest != source.snapshot_digest
                        or _hash((source_schema, source_catalogue,
                                  source_tables)) != source.closure_digest):
                    return False
                target_import = _read_import_receipt_locked(
                    target_db, namespace, plan.transfer_id)
                if (target_import is None
                        or target_import.snapshot_digest != snapshot_digest
                        or target_import.closure_digest != source.closure_digest
                        or target_import.source_graph_revision
                           != source.graph_revision
                        or target_import.source_graph_incarnation
                           != source.graph_incarnation
                        or target_import.target_graph_incarnation
                           != receipt.new_graph_incarnation
                        or target_import.target_activation_generation
                           != receipt.target_generation
                        or target_import.graph_epoch != source_epoch
                        or target_import.graph_commit_digest
                           != receipt.graph_commit_digest):
                    return False
                target_row = target_db.execute(
                    "SELECT schema,requirements_json,graph_revision "
                    "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                    namespace.as_tuple).fetchone()
                target_metadata = GraphStore._decode_recovery(
                    target_row, namespace)
                if (target_metadata is None
                        or target_metadata.requirements
                           != receipt.current_requirements
                        or target_metadata.graph_revision
                           != target_import.target_graph_revision
                        or _schema_digest(target_db) != source_schema
                        or _catalogue_digest(target_db) != source_catalogue):
                    return False
                _assert_migration_owner_head_in_transaction(
                    target_db, namespace, recovery.owner_head)
                target_tables = _inventory(target_db, namespace)
                target_import_rows = next(
                    rows for name, _, rows in target_tables
                    if name == "graph_migration_import_receipts_v1")
                current_import_rows = tuple(row for row in target_import_rows if row[2] == plan.transfer_id)
                retained_import_rows = tuple(row for row in target_import_rows if row[2] != plan.transfer_id)
                if (len(current_import_rows) != 1
                        or retained_import_rows != source_import_rows):
                    return False
                excluded = {"graph_recovery_metadata_v2",
                            "graph_migration_import_receipts_v1"}
                if tuple(item for item in target_tables if item[0] not in excluded) \
                        != tuple(item for item in source_tables
                                 if item[0] not in excluded):
                    return False
            return True
        except Exception:
            return False


__all__ = ["InstalledMigrationTargetVerifierV1", "TargetGraphHeldProofV1"]
