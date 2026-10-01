"""Read-only D06 sidecar seal and target rebuild gate for namespace moves.

The source projection is disposable address data. This contract never copies
source rows, accepts a deletion barrier, or activates a target namespace.
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
class ProjectionNamespaceSealV1:
    namespace: NamespaceId
    active_generation: str | None
    active_watermark: int | None
    generation_count: int
    source_count: int
    block_count: int
    content_digest: str
    status: str = "sealed_projection_rebuild_only"


@dataclass(frozen=True, slots=True)
class TargetProjectionRebuildV1:
    namespace: NamespaceId
    source_projection_digest: str
    target_graph_epoch: NamespaceEpoch
    new_generation_id: str
    status: str = "hold_w01_target_graph_replay_and_authority"


def _open_existing_readonly(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise FileNotFoundError("D06 projection file is unavailable")
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    db.execute("PRAGMA query_only=ON")
    db.execute("BEGIN")
    tables = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    if not set(_TABLES) <= tables:
        db.close()
        raise ValueError("D06 projection schema is incomplete")
    return db


def seal_projection_namespace_v1(
    path: str | Path, namespace: NamespaceId,
) -> ProjectionNamespaceSealV1:
    """Fingerprint every D06 sidecar row for one namespace, without writes."""
    if type(namespace) is not NamespaceId:
        raise TypeError("projection seal needs a typed namespace")
    db = _open_existing_readonly(Path(path))
    try:
        scope = namespace.as_tuple
        generations = db.execute(
            "SELECT generation_id,watermark,active FROM d06_index_generations "
            "WHERE bot=? AND persona=? ORDER BY generation_id", scope,
        ).fetchall()
        receipts = db.execute(
            "SELECT generation_id,epoch,digest FROM d06_index_receipts "
            "WHERE bot=? AND persona=? ORDER BY generation_id,epoch", scope,
        ).fetchall()
        sources = db.execute(
            "SELECT generation_id,source_ref,source_revision,access_revision "
            "FROM d06_index_sources WHERE bot=? AND persona=? "
            "ORDER BY generation_id,source_ref", scope,
        ).fetchall()
        blocks = db.execute(
            "SELECT source_ref,first_epoch,reason FROM d06_index_source_blocks "
            "WHERE bot=? AND persona=? ORDER BY source_ref", scope,
        ).fetchall()
        generation_map = {name: watermark for name, watermark, _ in generations}
        active = [(name, watermark) for name, watermark, flag in generations if flag == 1]
        if len(active) > 1 or any(flag not in (0, 1) or watermark < 0
                                  for _, watermark, flag in generations):
            raise ValueError("D06 projection generation state is invalid")
        for name, watermark in generation_map.items():
            epochs = [epoch for generation, epoch, _ in receipts if generation == name]
            if (len(epochs) != watermark
                    or (epochs and (epochs[0] != 1 or epochs[-1] != watermark))):
                raise ValueError("D06 projection receipts do not cover watermark")
        if any(generation not in generation_map or epoch < 1 or not digest
               for generation, epoch, digest in receipts):
            raise ValueError("D06 projection receipt is invalid")
        for generation, ref, source_revision, access_revision in sources:
            key = AtomKey.from_token(ref)
            if (generation not in generation_map
                    or key != source_key(*scope, key.owner.subject)
                    or source_revision < 1 or access_revision < 1):
                raise ValueError("D06 projection source row is invalid")
        for ref, first_epoch, reason in blocks:
            key = AtomKey.from_token(ref)
            if (key != source_key(*scope, key.owner.subject)
                    or first_epoch < 1
                    or reason not in {"correction", "revocation", "deletion"}):
                raise ValueError("D06 projection block row is invalid")
        digest = canonical_digest({
            "namespace": scope, "generations": generations,
            "receipts": receipts, "sources": sources, "blocks": blocks,
        })
        return ProjectionNamespaceSealV1(
            namespace, active[0][0] if active else None,
            active[0][1] if active else None, len(generations),
            len(sources), len(blocks), digest,
        )
    finally:
        db.close()


def inspect_target_projection_rebuild_v1(
    seal: ProjectionNamespaceSealV1, *, target_path: str | Path,
    target_graph_epoch: NamespaceEpoch, new_generation_id: str,
    source_path: str | Path,
) -> TargetProjectionRebuildV1:
    """Reject copied target state; W01 must replay the target authoritative graph."""
    if (type(seal) is not ProjectionNamespaceSealV1
            or seal.status != "sealed_projection_rebuild_only"
            or type(target_graph_epoch) is not NamespaceEpoch
            or (target_graph_epoch.bot, target_graph_epoch.persona)
            != seal.namespace.as_tuple
            or type(new_generation_id) is not str or not new_generation_id):
        raise ValueError("target rebuild needs a sealed namespace and graph epoch")
    target, source = Path(target_path).resolve(), Path(source_path).resolve()
    if target == source:
        raise ValueError("target projection cannot reuse the source sidecar")
    if target.is_file():
        db = _open_existing_readonly(target)
        try:
            for table in _TABLES:
                if db.execute(
                    f"SELECT 1 FROM {table} WHERE bot=? AND persona=? LIMIT 1",
                    seal.namespace.as_tuple,
                ).fetchone() is not None:
                    raise ValueError("target namespace already has D06 projection state")
        finally:
            db.close()
    return TargetProjectionRebuildV1(
        seal.namespace, seal.content_digest, target_graph_epoch,
        new_generation_id,
    )


__all__ = [
    "ProjectionNamespaceSealV1", "TargetProjectionRebuildV1",
    "seal_projection_namespace_v1", "inspect_target_projection_rebuild_v1",
]
