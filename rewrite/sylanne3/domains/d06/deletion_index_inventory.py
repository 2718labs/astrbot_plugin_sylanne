"""Bounded observation of one D06 projection sidecar for deletion planning.

The path is not an installed-path attestation. This read does not share W01's
Authority fence or graph transaction, so its result never closes the index
facet or authorizes deletion by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3

from ...graph_types import AtomKey, NamespaceEpoch
from ...memory_types import source_key
from ...runtime_contracts import NamespaceId, canonical_digest


_TABLES = (
    "d06_index_generations", "d06_index_receipts",
    "d06_index_sources", "d06_index_source_blocks",
)


@dataclass(frozen=True, slots=True)
class D06IndexDeletionInventoryV1:
    namespace: NamespaceId
    graph_epoch: NamespaceEpoch
    sidecar_path: str
    generation_watermarks: tuple[tuple[str, int, bool], ...]
    receipt_epochs: tuple[tuple[str, int, str], ...]
    active_source_refs: tuple[str, ...]
    inactive_source_refs: tuple[str, ...]
    blocked_source_refs: tuple[str, ...]
    all_source_refs: tuple[str, ...]
    sidecar_digest: str | None
    scan_complete: bool
    status: str


def _canonical_source_ref(ref: str, namespace: NamespaceId) -> bool:
    try:
        key = AtomKey.from_token(ref)
        return key == source_key(*namespace.as_tuple, key.owner.subject)
    except (TypeError, ValueError):
        return False


def read_d06_index_deletion_inventory_v1(
    path: str | Path, namespace: NamespaceId, *,
    graph_epoch: NamespaceEpoch, max_rows_per_table: int = 4096,
) -> D06IndexDeletionInventoryV1:
    """Observe all current and retained sidecar rows in one read transaction.

    The caller must separately prove that this path is the installed D06 index
    and coordinate the sidecar snapshot with the current deletion fence. Even a
    complete matching-watermark observation therefore remains on HOLD.
    """
    if (type(namespace) is not NamespaceId or type(graph_epoch) is not NamespaceEpoch
            or (graph_epoch.bot, graph_epoch.persona) != namespace.as_tuple):
        raise ValueError("D06 index inventory namespace and graph epoch differ")
    if type(max_rows_per_table) is not int or not 1 <= max_rows_per_table <= 4096:
        raise ValueError("D06 index inventory row bound must be from 1 to 4096")
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise FileNotFoundError("D06 projection sidecar is unavailable")
    db = sqlite3.connect(resolved.as_uri() + "?mode=ro", uri=True, isolation_level=None)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        if not set(_TABLES) <= tables:
            raise ValueError("D06 projection sidecar schema is incomplete")

        scope = namespace.as_tuple
        limit = max_rows_per_table + 1
        generations = db.execute(
            "SELECT generation_id,watermark,active FROM d06_index_generations "
            "WHERE bot=? AND persona=? ORDER BY generation_id LIMIT ?",
            (*scope, limit),
        ).fetchall()
        receipts = db.execute(
            "SELECT generation_id,epoch,digest FROM d06_index_receipts "
            "WHERE bot=? AND persona=? ORDER BY generation_id,epoch LIMIT ?",
            (*scope, limit),
        ).fetchall()
        sources = db.execute(
            "SELECT generation_id,source_ref,source_revision,access_revision "
            "FROM d06_index_sources WHERE bot=? AND persona=? "
            "ORDER BY generation_id,source_ref LIMIT ?",
            (*scope, limit),
        ).fetchall()
        blocks = db.execute(
            "SELECT source_ref,first_epoch,reason FROM d06_index_source_blocks "
            "WHERE bot=? AND persona=? ORDER BY source_ref LIMIT ?",
            (*scope, limit),
        ).fetchall()
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise
    finally:
        db.close()

    if any(len(rows) > max_rows_per_table for rows in (
            generations, receipts, sources, blocks)):
        return D06IndexDeletionInventoryV1(
            namespace, graph_epoch, str(resolved), (), (), (), (), (), (),
            None, False, "partial_hold_row_bound",
        )

    generation_map = {}
    active = []
    for generation, watermark, flag in generations:
        if (type(generation) is not str or not generation
                or type(watermark) is not int or watermark < 0
                or flag not in (0, 1)):
            raise ValueError("D06 projection generation is invalid")
        generation_map[generation] = watermark
        if flag == 1:
            active.append(generation)
    if len(active) > 1:
        raise ValueError("D06 projection has multiple active generations")
    for generation, watermark in generation_map.items():
        epochs = [epoch for name, epoch, _ in receipts if name == generation]
        if (len(epochs) != watermark
                or any(epoch != ordinal for ordinal, epoch in enumerate(epochs, 1))):
            raise ValueError("D06 projection receipt continuity differs from watermark")
    if any(name not in generation_map or type(epoch) is not int or epoch < 1
           or type(digest) is not str or len(digest) != 64
           or any(ch not in "0123456789abcdef" for ch in digest)
           for name, epoch, digest in receipts):
        raise ValueError("D06 projection receipt is invalid")

    active_refs, inactive_refs = set(), set()
    for generation, ref, source_revision, access_revision in sources:
        if (generation not in generation_map
                or not _canonical_source_ref(ref, namespace)
                or type(source_revision) is not int or source_revision < 1
                or type(access_revision) is not int or access_revision < 1):
            raise ValueError("D06 projection source row is invalid")
        (active_refs if generation in active else inactive_refs).add(ref)
    blocked_refs = set()
    for ref, first_epoch, reason in blocks:
        if (not _canonical_source_ref(ref, namespace)
                or type(first_epoch) is not int or first_epoch < 1
                or reason not in {"correction", "revocation", "deletion"}):
            raise ValueError("D06 projection source block is invalid")
        blocked_refs.add(ref)

    active_watermark = generation_map[active[0]] if active else None
    status = ("observed_hold_unbound" if active_watermark == graph_epoch.revision
              else "observed_hold_no_active_generation" if active_watermark is None
              else "observed_hold_epoch_mismatch")
    return D06IndexDeletionInventoryV1(
        namespace, graph_epoch, str(resolved),
        tuple((name, watermark, bool(flag)) for name, watermark, flag in generations),
        tuple(receipts), tuple(sorted(active_refs)), tuple(sorted(inactive_refs)),
        tuple(sorted(blocked_refs)),
        tuple(sorted(active_refs | inactive_refs | blocked_refs)),
        canonical_digest({
            "namespace": scope, "generations": generations,
            "receipts": receipts, "sources": sources, "blocks": blocks,
        }), True, status,
    )


__all__ = ["D06IndexDeletionInventoryV1", "read_d06_index_deletion_inventory_v1"]
