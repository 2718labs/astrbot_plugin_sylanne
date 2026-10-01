"""Durable D06 candidate projection with crash-safe graph-epoch watermarks.

This sidecar stores only source addresses and versions. It grants no source
access and cannot certify a negative memory query. W01 must supply consecutive
committed graph event pages and a current fenced epoch; consumers still re-read
each candidate through the authoritative graph and access barrier.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3

from ...graph_types import AtomKey, NamespaceEpoch
from ...memory_types import source_key
from ...runtime_contracts import NamespaceId, canonical_digest


@dataclass(frozen=True, slots=True)
class SourceIndexMutation:
    source_ref: str
    source_revision: int
    access_revision: int
    present: bool
    terminal_invalidation: str | None = None

    def __post_init__(self) -> None:
        key = AtomKey.from_token(self.source_ref)
        if key != source_key(key.owner.bot, key.owner.persona,
                             key.owner.subject):
            raise ValueError("index mutation needs a canonical source ref")
        if (type(self.source_revision) is not int or self.source_revision < 0
                or type(self.access_revision) is not int or self.access_revision < 0
                or type(self.present) is not bool):
            raise ValueError("index mutation versions or presence are invalid")
        if self.present and (self.source_revision == 0 or self.access_revision == 0):
            raise ValueError("present source needs source and access versions")
        if (self.terminal_invalidation not in (None, "correction", "revocation", "deletion")
                or (self.present and self.terminal_invalidation is not None)):
            raise ValueError("terminal invalidation needs an absent source and known reason")


@dataclass(frozen=True, slots=True)
class SourceIndexEpochPage:
    namespace: NamespaceId
    epoch: int
    mutations: tuple[SourceIndexMutation, ...]

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId or type(self.epoch) is not int or self.epoch < 1:
            raise ValueError("index page needs a namespace and positive epoch")
        if type(self.mutations) is not tuple or any(
            type(item) is not SourceIndexMutation for item in self.mutations
        ):
            raise TypeError("index page mutations must be typed")
        refs = [item.source_ref for item in self.mutations]
        if len(refs) != len(set(refs)):
            raise ValueError("index page repeats a source")
        if any(NamespaceId.from_key(AtomKey.from_token(ref)) != self.namespace
               for ref in refs):
            raise ValueError("index page crosses namespace")

    @property
    def digest(self) -> str:
        return canonical_digest({
            "namespace": self.namespace.as_tuple,
            "epoch": self.epoch,
            "mutations": [
                (item.source_ref, item.source_revision,
                 item.access_revision, item.present, item.terminal_invalidation)
                for item in self.mutations
            ],
        })


@dataclass(frozen=True, slots=True)
class SourceIndexPage:
    status: str
    generation_id: str | None
    watermark: int | None
    candidates: tuple[SourceIndexMutation, ...]
    next_after: str | None
    page_complete: bool


class DurableSourceProjectionIndex:
    """D06-owned sidecar; a projection, never the graph or access authority."""

    def __init__(self, path: str | Path):
        self._db = sqlite3.connect(path, isolation_level=None)
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS d06_index_generations (
                bot TEXT NOT NULL, persona TEXT NOT NULL, generation_id TEXT NOT NULL,
                watermark INTEGER NOT NULL CHECK(watermark >= 0),
                active INTEGER NOT NULL CHECK(active IN (0,1)),
                PRIMARY KEY(bot, persona, generation_id));
            CREATE UNIQUE INDEX IF NOT EXISTS d06_one_active_generation
                ON d06_index_generations(bot, persona) WHERE active=1;
            CREATE TABLE IF NOT EXISTS d06_index_receipts (
                bot TEXT NOT NULL, persona TEXT NOT NULL, generation_id TEXT NOT NULL,
                epoch INTEGER NOT NULL, digest TEXT NOT NULL,
                PRIMARY KEY(bot, persona, generation_id, epoch),
                FOREIGN KEY(bot, persona, generation_id) REFERENCES
                    d06_index_generations(bot, persona, generation_id));
            CREATE TABLE IF NOT EXISTS d06_index_sources (
                bot TEXT NOT NULL, persona TEXT NOT NULL, generation_id TEXT NOT NULL,
                source_ref TEXT NOT NULL, source_revision INTEGER NOT NULL,
                access_revision INTEGER NOT NULL,
                PRIMARY KEY(bot, persona, generation_id, source_ref),
                FOREIGN KEY(bot, persona, generation_id) REFERENCES
                    d06_index_generations(bot, persona, generation_id));
            CREATE TABLE IF NOT EXISTS d06_index_source_blocks (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                source_ref TEXT NOT NULL, first_epoch INTEGER NOT NULL,
                reason TEXT NOT NULL,
                PRIMARY KEY(bot, persona, source_ref));
        """)

    def close(self) -> None:
        self._db.close()

    def begin_generation(self, namespace: NamespaceId, generation_id: str) -> None:
        if type(namespace) is not NamespaceId or type(generation_id) is not str or not generation_id:
            raise ValueError("index generation identity is required")
        self._db.execute(
            "INSERT OR IGNORE INTO d06_index_generations VALUES(?,?,?,0,0)",
            (*namespace.as_tuple, generation_id),
        )

    def apply_page(self, generation_id: str, page: SourceIndexEpochPage) -> int:
        """Commit page mutations and its watermark in one SQLite transaction."""
        if type(page) is not SourceIndexEpochPage or type(generation_id) is not str or not generation_id:
            raise TypeError("typed D06 index page and generation are required")
        key = (*page.namespace.as_tuple, generation_id)
        db = self._db
        db.execute("BEGIN IMMEDIATE")
        try:
            row = db.execute(
                "SELECT watermark FROM d06_index_generations "
                "WHERE bot=? AND persona=? AND generation_id=?", key,
            ).fetchone()
            if row is None:
                raise ValueError("unknown D06 index generation")
            watermark = row[0]
            if page.epoch <= watermark:
                prior = db.execute(
                    "SELECT digest FROM d06_index_receipts WHERE bot=? AND persona=? "
                    "AND generation_id=? AND epoch=?", (*key, page.epoch),
                ).fetchone()
                if prior is None or prior[0] != page.digest:
                    raise ValueError("index page replay conflicts with committed receipt")
                db.execute("COMMIT")
                return watermark
            if page.epoch != watermark + 1:
                raise ValueError("index page would skip a committed graph epoch")
            for item in page.mutations:
                if item.terminal_invalidation is not None:
                    db.execute(
                        "INSERT OR IGNORE INTO d06_index_source_blocks "
                        "VALUES(?,?,?,?,?)",
                        (*page.namespace.as_tuple, item.source_ref,
                         page.epoch, item.terminal_invalidation),
                    )
                if item.present:
                    blocked = db.execute(
                        "SELECT 1 FROM d06_index_source_blocks WHERE bot=? "
                        "AND persona=? AND source_ref=?",
                        (*page.namespace.as_tuple, item.source_ref),
                    ).fetchone()
                    if blocked is None:
                        db.execute(
                            "INSERT INTO d06_index_sources VALUES(?,?,?,?,?,?) "
                            "ON CONFLICT(bot,persona,generation_id,source_ref) DO UPDATE SET "
                            "source_revision=excluded.source_revision, "
                            "access_revision=excluded.access_revision",
                            (*key, item.source_ref, item.source_revision,
                             item.access_revision),
                        )
                    else:
                        db.execute(
                            "DELETE FROM d06_index_sources WHERE bot=? AND persona=? "
                            "AND generation_id=? AND source_ref=?",
                            (*key, item.source_ref),
                        )
                else:
                    db.execute(
                        "DELETE FROM d06_index_sources WHERE bot=? AND persona=? "
                        "AND generation_id=? AND source_ref=?",
                        (*key, item.source_ref),
                    )
            db.execute(
                "INSERT INTO d06_index_receipts VALUES(?,?,?,?,?)",
                (*key, page.epoch, page.digest),
            )
            db.execute(
                "UPDATE d06_index_generations SET watermark=? "
                "WHERE bot=? AND persona=? AND generation_id=?",
                (page.epoch, *key),
            )
            db.execute("COMMIT")
            return page.epoch
        except BaseException:
            db.execute("ROLLBACK")
            raise

    def activate(self, namespace: NamespaceId, generation_id: str,
                 current_epoch: NamespaceEpoch) -> None:
        """Switch coverage only when the candidate projection has caught up."""
        if (type(namespace) is not NamespaceId
                or type(current_epoch) is not NamespaceEpoch
                or (current_epoch.bot, current_epoch.persona) != namespace.as_tuple):
            raise ValueError("activation epoch crosses namespace")
        key = (*namespace.as_tuple, generation_id)
        db = self._db
        db.execute("BEGIN IMMEDIATE")
        try:
            row = db.execute(
                "SELECT watermark FROM d06_index_generations WHERE bot=? "
                "AND persona=? AND generation_id=?", key,
            ).fetchone()
            if row is None or row[0] != current_epoch.revision:
                raise ValueError("index generation has not reached current graph epoch")
            db.execute(
                "UPDATE d06_index_generations SET active=0 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            )
            db.execute(
                "UPDATE d06_index_generations SET active=1 WHERE bot=? AND persona=? "
                "AND generation_id=?", key,
            )
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise

    def candidate_page(self, namespace: NamespaceId, *, current_epoch: NamespaceEpoch,
                       after: str | None = None, limit: int = 32) -> SourceIndexPage:
        """Only current projection addresses are exposed; graph recheck is required."""
        if (type(namespace) is not NamespaceId or type(current_epoch) is not NamespaceEpoch
                or (current_epoch.bot, current_epoch.persona) != namespace.as_tuple
                or type(limit) is not int or not 1 <= limit <= 64):
            raise ValueError("index page scope or limit is invalid")
        if after is not None:
            key = AtomKey.from_token(after)
            if key != source_key(*namespace.as_tuple, key.owner.subject):
                raise ValueError("index cursor crosses source namespace")
        row = self._db.execute(
            "SELECT generation_id,watermark FROM d06_index_generations "
            "WHERE bot=? AND persona=? AND active=1", namespace.as_tuple,
        ).fetchone()
        if row is None:
            return SourceIndexPage("unavailable", None, None, (), None, False)
        generation_id, watermark = row
        if watermark != current_epoch.revision:
            return SourceIndexPage("partial_watermark_lag", generation_id,
                                   watermark, (), None, False)
        rows = self._db.execute(
            "SELECT source_ref,source_revision,access_revision FROM d06_index_sources "
            "WHERE bot=? AND persona=? AND generation_id=? AND source_ref>? "
            "AND NOT EXISTS (SELECT 1 FROM d06_index_source_blocks AS blocked "
            "WHERE blocked.bot=d06_index_sources.bot "
            "AND blocked.persona=d06_index_sources.persona "
            "AND blocked.source_ref=d06_index_sources.source_ref) "
            "ORDER BY source_ref LIMIT ?",
            (*namespace.as_tuple, generation_id, after or "", limit + 1),
        ).fetchall()
        more = len(rows) > limit
        items = tuple(SourceIndexMutation(ref, source_revision, access_revision, True)
                      for ref, source_revision, access_revision in rows[:limit])
        return SourceIndexPage("projection_current", generation_id, watermark,
                               items, items[-1].source_ref if more else None,
                               not more)


__all__ = ["SourceIndexMutation", "SourceIndexEpochPage", "SourceIndexPage",
           "DurableSourceProjectionIndex"]
