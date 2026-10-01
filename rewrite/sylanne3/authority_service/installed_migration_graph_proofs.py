"""Read-only source graph proof for an administrator-pinned local migration.

The Authority callback never accepts a path or snapshot body from RPC.  It
recomputes the namespace snapshot from the installed graph database after the
source permit has frozen the namespace.  Target activation remains unavailable
until a durable, service-owned snapshot original and an independently defined
unknown-constraints proof can be checked against the imported target.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import sqlite3

from ..graph_store import GraphStore
from ..runtime.graph_migration_snapshot_v1 import (
    FORMAT, _DEFERRED, _catalogue_digest, _hash, _inventory,
    _schema_digest,
)
from ..runtime_contracts import NamespaceId
from .v2_migration_contract import (
    MigrationPermitV2, MigrationPlanV2, SourceSnapshotReceiptV2,
    TargetRecoveryReceiptV2,
)


class InstalledSourceGraphProofV1:
    """Recompute a source snapshot using one fixed graph path and installation."""

    def __init__(self, *, graph_db: Path, namespace: str,
                 namespace_id: NamespaceId, installation_id: str) -> None:
        path = Path(graph_db)
        if (not path.is_absolute() or not path.is_file()
                or type(namespace) is not str or not namespace
                or type(namespace_id) is not NamespaceId
                or type(installation_id) is not str or not installation_id):
            raise ValueError("installed source graph identity is required")
        self._path = path.resolve(strict=True)
        self._namespace = namespace
        self._namespace_id = namespace_id
        self._installation_id = installation_id

    def __call__(self, receipt: SourceSnapshotReceiptV2,
                 plan: MigrationPlanV2, permit: MigrationPermitV2) -> bool:
        if (type(receipt) is not SourceSnapshotReceiptV2
                or type(plan) is not MigrationPlanV2
                or type(permit) is not MigrationPermitV2
                or plan.namespace != self._namespace
                or plan.namespace_id != self._namespace_id
                or plan.source_installation_id != self._installation_id
                or (permit.transfer_id, permit.namespace, permit.kind,
                    permit.holder, permit.installation_id)
                   != (plan.transfer_id, plan.namespace, "source_snapshot",
                       plan.source_holder, self._installation_id)
                or permit.pinned_anchor.namespace != plan.namespace
                or (receipt.transfer_id, receipt.namespace,
                    receipt.source_installation_id, receipt.permit_token,
                    receipt.snapshot_format)
                   != (plan.transfer_id, plan.namespace, self._installation_id,
                       permit.token, FORMAT)):
            return False
        # mode=ro cannot create a missing database. A SQLite read transaction
        # gives the inventory, schema, catalogue and graph stamp one view.
        if not self._path.is_file():
            return False
        try:
            db = sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True,
                                 isolation_level=None)
            try:
                db.execute("BEGIN")
                row = db.execute(
                    "SELECT schema,requirements_json,graph_revision "
                    "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                    self._namespace_id.as_tuple).fetchone()
                metadata = GraphStore._decode_recovery(row, self._namespace_id)
                if metadata is None or metadata.requirements != receipt.requirements:
                    return False
                epoch_row = db.execute(
                    "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                    self._namespace_id.as_tuple).fetchone()
                epoch = epoch_row[0] if epoch_row else 0
                tables = _inventory(db, self._namespace_id)
                schema = _schema_digest(db)
                catalogue = _catalogue_digest(db)
                payload = (
                    FORMAT, plan.transfer_id, self._namespace_id.as_tuple,
                    self._installation_id, permit.token, asdict(metadata),
                    epoch, schema, catalogue, tables, _DEFERRED,
                )
                digest = _hash(payload)
                closure = _hash((schema, catalogue, tables))
                return (
                    receipt.requirements.namespace == self._namespace_id
                    and receipt.requirements.authority_namespace == plan.namespace
                    and receipt.requirements.graph_incarnation
                        == receipt.graph_incarnation
                    and receipt.graph_revision == metadata.graph_revision
                    and receipt.graph_epoch == epoch
                    and receipt.snapshot_digest == digest
                    and receipt.closure_digest == closure
                )
            finally:
                db.close()
        except (OSError, sqlite3.Error, ValueError, TypeError, KeyError):
            return False


class InstalledTargetGraphProofHoldV1:
    """Explicit HOLD until W01 supplies durable source and target originals."""

    def __call__(self, receipt: TargetRecoveryReceiptV2,
                 plan: MigrationPlanV2, permit: MigrationPermitV2) -> bool:
        return False


__all__ = ["InstalledSourceGraphProofV1", "InstalledTargetGraphProofHoldV1"]
