"""Bounded SQL input for D06 under an existing W01 Authority read fence.

The caller owns the SQLite transaction and Authority fence. This helper does
not begin/commit, authorize, disclose results, or certify a cross-page negative
query. It returns raw graph values only to the coordinator's D06 projector.
"""

from __future__ import annotations

import json
import sqlite3

from ..domains.d06 import source_correction_head_key
from ..domains.d06.current_memory_evidence import CurrentMemoryQueryCoverageV1
from ..graph_types import AtomKey, GraphAtom, GraphPage, GraphSnapshot, NamespaceEpoch
from ..memory_types import SourceRecord, access_key, source_key
from ..runtime_contracts import NamespaceId, QueryEpoch


def read_current_memory_evidence_page_v1(
    db: sqlite3.Connection, namespace: NamespaceId, *,
    type_filter: str = "memory.source", after: AtomKey | None = None,
    limit: int = 32, audience: str, purpose: str,
    graph_epoch: NamespaceEpoch, access_epoch: int, delete_epoch: int,
) -> tuple[GraphPage, GraphSnapshot, CurrentMemoryQueryCoverageV1]:
    """Read one source page and its ancestry in the caller's live transaction."""
    if (not isinstance(db, sqlite3.Connection) or not db.in_transaction):
        raise ValueError("D06 current memory read requires caller-owned SQLite transaction")
    if (type(namespace) is not NamespaceId or type_filter != "memory.source"
            or type(graph_epoch) is not NamespaceEpoch
            or (graph_epoch.bot, graph_epoch.persona) != namespace.as_tuple
            or type(access_epoch) is not int or access_epoch < 0
            or type(delete_epoch) is not int or delete_epoch < 0
            or type(limit) is not int or not 1 <= limit <= 64
            or type(audience) is not str or not audience or audience == "*"
            or type(purpose) is not str or not purpose or purpose == "*"):
        raise ValueError("D06 current memory read scope or bounds are invalid")
    if after is not None and (
        type(after) is not AtomKey
        or after != source_key(*namespace.as_tuple, after.owner.subject)
    ):
        raise ValueError("D06 memory cursor is not a source in this namespace")
    epoch_row = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    barriers = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if (epoch_row is None or epoch_row[0] != graph_epoch.revision
            or barriers != (access_epoch, delete_epoch)):
        raise ValueError("D06 current memory graph or access/delete barrier changed")

    rows = db.execute(
        "SELECT token,revision,value,valid FROM graph_atoms "
        "WHERE bot=? AND persona=? AND owner_kind='event' "
        "AND type_name='memory.source' AND name='record' AND valid=1 "
        "AND token>? ORDER BY token LIMIT ?",
        (*namespace.as_tuple, after.token if after is not None else "", limit + 1),
    ).fetchall()
    roots = tuple(GraphAtom(AtomKey.from_token(token), revision,
                            json.loads(value), bool(valid))
                  for token, revision, value, valid in rows[:limit])
    has_more = len(rows) > limit
    cursor = roots[-1].key if has_more else None
    page = GraphPage(GraphSnapshot(roots, (graph_epoch,)), cursor)

    closure: dict[AtomKey, GraphAtom] = {}

    def read_key(key: AtomKey) -> GraphAtom:
        if key not in closure:
            if len(closure) >= 4096:
                raise ValueError("D06 current memory ancestry exceeds read bound")
            row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
                "AND bot=? AND persona=?", (key.token, *namespace.as_tuple),
            ).fetchone()
            closure[key] = (GraphAtom(key, row[0], json.loads(row[1]), bool(row[2]))
                            if row is not None else GraphAtom(key, 0, {}, False))
        return closure[key]

    pending = [root.key.owner.subject for root in roots]
    seen: set[str] = set()
    while pending:
        source_id = pending.pop()
        if source_id in seen:
            continue
        seen.add(source_id)
        if len(seen) > 4096:
            raise ValueError("D06 current memory ancestry exceeds read bound")
        source = read_key(source_key(*namespace.as_tuple, source_id))
        read_key(access_key(*namespace.as_tuple, source_id))
        read_key(source_correction_head_key(namespace, source_id))
        if source.revision > 0 and source.valid:
            record = SourceRecord.from_dict(source.value)
            if record.source_id != source_id:
                raise ValueError("D06 current memory source identity differs")
            pending.extend(record.parent_source_ids)

    coverage = CurrentMemoryQueryCoverageV1(
        "partial" if after is not None or has_more else "verified_complete",
        QueryEpoch(namespace, "memory.source", graph_epoch.revision),
        cursor.token if cursor is not None else None,
    )
    return (page, GraphSnapshot(tuple(closure[key] for key in sorted(
        closure, key=lambda item: item.token)), (graph_epoch,)), coverage)


__all__ = ["read_current_memory_evidence_page_v1",
           "CurrentMemoryQueryCoverageV1"]
