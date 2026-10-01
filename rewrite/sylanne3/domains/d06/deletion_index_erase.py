"""D06 sidecar erasure primitive for a W01-fenced, verified deletion scope.

The caller owns installed-path identity, the W01 deletion fence, and the graph
epoch. This primitive does not authorize deletion or attest to other stores.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3

from ...graph_types import NamespaceEpoch
from ...runtime_contracts import NamespaceId, canonical_digest
from .deletion_index_inventory import (
    _canonical_source_ref, read_d06_index_deletion_inventory_v1,
)


_RECEIPT_DDL = """CREATE TABLE IF NOT EXISTS d06_index_erasure_receipts (
    operation_id TEXT PRIMARY KEY,
    bot TEXT NOT NULL, persona TEXT NOT NULL, graph_epoch INTEGER NOT NULL,
    request_digest TEXT NOT NULL, before_digest TEXT NOT NULL,
    erased_rows INTEGER NOT NULL, tombstoned_refs INTEGER NOT NULL,
    receipt_digest TEXT NOT NULL
)"""


@dataclass(frozen=True, slots=True)
class D06IndexErasureReceiptV1:
    operation_id: str
    namespace: NamespaceId
    graph_epoch: NamespaceEpoch
    request_digest: str
    before_digest: str
    erased_rows: int
    tombstoned_refs: int
    receipt_digest: str
    status: str = "d06_projection_rows_erased"


def erase_d06_projection_index_v1(
    installed_sidecar_path: str | Path, namespace: NamespaceId, *,
    graph_epoch: NamespaceEpoch, source_refs: tuple[str, ...],
    operation_id: str, expected_inventory_digest: str,
) -> D06IndexErasureReceiptV1:
    """Erase exact source rows in every generation and retain deletion blocks.

    Only W01 may supply these arguments after its authority checks and while
    holding its deletion fence. The expected inventory digest binds the plan
    to a prior complete D06 observation; SQLite then rejects a changed state.
    This receipt covers the projection only, not WAL, free pages, or backups.
    """
    if (type(namespace) is not NamespaceId or type(graph_epoch) is not NamespaceEpoch
            or (graph_epoch.bot, graph_epoch.persona) != namespace.as_tuple
            or graph_epoch.revision < 1):
        raise ValueError("D06 erasure namespace and graph epoch differ")
    if (type(source_refs) is not tuple or not source_refs
            or len(set(source_refs)) != len(source_refs)
            or any(type(ref) is not str or not _canonical_source_ref(ref, namespace)
                   for ref in source_refs)):
        raise ValueError("D06 erasure requires unique canonical source refs")
    if type(operation_id) is not str or not operation_id:
        raise ValueError("D06 erasure operation identity is required")
    if (type(expected_inventory_digest) is not str
            or len(expected_inventory_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in expected_inventory_digest)):
        raise ValueError("D06 erasure needs a complete inventory digest")

    path = Path(installed_sidecar_path).resolve(strict=True)
    if not path.is_file():
        raise FileNotFoundError("installed D06 sidecar is unavailable")
    refs = tuple(sorted(source_refs))
    request_digest = canonical_digest({
        "schema": "d06-index-erasure.v1", "operation_id": operation_id,
        "namespace": namespace.as_tuple, "graph_epoch": graph_epoch.revision,
        "source_refs": refs,
    })
    db = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, isolation_level=None)
    try:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        try:
            # The inventory validates schema and receipt continuity. Its read
            # transaction runs while this connection excludes sidecar writers.
            inventory = read_d06_index_deletion_inventory_v1(
                path, namespace, graph_epoch=graph_epoch,
            )
            if not inventory.scan_complete or inventory.sidecar_digest is None:
                raise ValueError("D06 erasure inventory is incomplete")
            db.execute(_RECEIPT_DDL)
            prior = db.execute(
                "SELECT bot,persona,graph_epoch,request_digest,before_digest,"
                "erased_rows,tombstoned_refs,receipt_digest "
                "FROM d06_index_erasure_receipts WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if prior is not None:
                if prior[:4] != (*namespace.as_tuple, graph_epoch.revision, request_digest):
                    raise ValueError("D06 erasure operation replay conflicts")
                for ref in refs:
                    if db.execute(
                        "SELECT 1 FROM d06_index_sources WHERE bot=? AND persona=? "
                        "AND source_ref=? LIMIT 1", (*namespace.as_tuple, ref),
                    ).fetchone() is not None or db.execute(
                        "SELECT reason FROM d06_index_source_blocks WHERE bot=? "
                        "AND persona=? AND source_ref=?", (*namespace.as_tuple, ref),
                    ).fetchone() != ("deletion",):
                        raise ValueError("D06 erasure replay finds resurrected source")
                receipt = D06IndexErasureReceiptV1(
                    operation_id, namespace, graph_epoch, request_digest,
                    prior[4], prior[5], prior[6], prior[7],
                )
                if receipt.receipt_digest != _receipt_digest(receipt):
                    raise ValueError("D06 erasure receipt is corrupt")
                db.execute("COMMIT")
                return receipt

            if inventory.sidecar_digest != expected_inventory_digest:
                raise ValueError("D06 erasure inventory changed")
            active = [watermark for _, watermark, flag in inventory.generation_watermarks
                      if flag]
            if len(active) != 1 or active[0] != graph_epoch.revision:
                raise ValueError("D06 active generation does not cover graph epoch")
            erased = 0
            for ref in refs:
                cursor = db.execute(
                    "DELETE FROM d06_index_sources WHERE bot=? AND persona=? "
                    "AND source_ref=?", (*namespace.as_tuple, ref),
                )
                erased += cursor.rowcount
                db.execute(
                    "INSERT INTO d06_index_source_blocks "
                    "(bot,persona,source_ref,first_epoch,reason) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(bot,persona,source_ref) DO UPDATE SET reason='deletion'",
                    (*namespace.as_tuple, ref, graph_epoch.revision, "deletion"),
                )
            receipt = D06IndexErasureReceiptV1(
                operation_id, namespace, graph_epoch, request_digest,
                inventory.sidecar_digest, erased, len(refs), "",
            )
            receipt = D06IndexErasureReceiptV1(
                operation_id, namespace, graph_epoch, request_digest,
                inventory.sidecar_digest, erased, len(refs), _receipt_digest(receipt),
            )
            db.execute(
                "INSERT INTO d06_index_erasure_receipts VALUES(?,?,?,?,?,?,?,?,?)",
                (operation_id, *namespace.as_tuple, graph_epoch.revision,
                 request_digest, inventory.sidecar_digest, erased, len(refs),
                 receipt.receipt_digest),
            )
            db.execute("COMMIT")
            return receipt
        except BaseException:
            db.execute("ROLLBACK")
            raise
    finally:
        db.close()


def _receipt_digest(receipt: D06IndexErasureReceiptV1) -> str:
    return canonical_digest({
        "schema": "d06-index-erasure-receipt.v1",
        "operation_id": receipt.operation_id,
        "namespace": receipt.namespace.as_tuple,
        "graph_epoch": receipt.graph_epoch.revision,
        "request_digest": receipt.request_digest,
        "before_digest": receipt.before_digest,
        "erased_rows": receipt.erased_rows,
        "tombstoned_refs": receipt.tombstoned_refs,
    })


__all__ = ["D06IndexErasureReceiptV1", "erase_d06_projection_index_v1"]
