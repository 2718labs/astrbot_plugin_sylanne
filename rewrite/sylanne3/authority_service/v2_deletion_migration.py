"""Stopped-service, same-file v1 deletion prefix to v2-tail migration.

The Authority blocker commits first. Each later stage is retryable after a
crash and never rolls the log back to v1. This module does not append a v2
deletion event and cannot establish old-process or file-handle exclusion.
"""

from __future__ import annotations

import json

from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .v2_deletion_guard import (
    AuthorityV2DeletionGuard, _PREFIX_TRIGGERS, _TAIL_TRIGGERS,
    _V2_META_DDL, _V2_TAIL_DDL,
)
from .v2_execution_journal import AuthorityV2ExecutionJournal
from .v2_fence_store import AuthorityV2FenceStore


_KEY = "deletion_v2_migration"
_SCHEMA = "sylanne3.deletion-migration.v1"


class AuthorityV2DeletionMigration:
    def __init__(self, *, core: AuthorityServiceCore,
                 fences: AuthorityV2FenceStore,
                 deletion: AuthorityV2DeletionGuard,
                 execution: AuthorityV2ExecutionJournal,
                 namespace: str):
        identifier(namespace, "namespace")
        if (type(core) is not AuthorityServiceCore
                or type(fences) is not AuthorityV2FenceStore
                or type(deletion) is not AuthorityV2DeletionGuard
                or type(execution) is not AuthorityV2ExecutionJournal
                or core._db is not fences._db or core._lock is not fences._lock
                or execution.namespace != namespace):
            raise AuthorityUnavailable("deletion migration requires one service DB/lock")
        self.core, self.fences = core, fences
        self.deletion, self.execution = deletion, execution
        self.namespace = namespace

    @staticmethod
    def _read_marker(db):
        row = db.execute("SELECT value FROM authority_meta WHERE key=?", (_KEY,)).fetchone()
        if row is None:
            return None
        try:
            marker = json.loads(row[0])
        except (TypeError, ValueError) as exc:
            raise AuthorityUnavailable("malformed deletion migration marker") from exc
        if (type(marker) is not dict or set(marker) != {
                "schema", "namespace", "authority_id", "journal_id", "cut_seq",
                "cut_digest", "stage"} or marker["schema"] != _SCHEMA
                or marker["stage"] not in ("blocked", "complete")
                or type(marker["cut_seq"]) is not int or marker["cut_seq"] < 0):
            raise AuthorityUnavailable("unknown deletion migration marker")
        return marker

    def _require_mode_and_idle(self, db):
        if db.execute("SELECT value FROM authority_meta WHERE key='service_mode'").fetchone() != ("v2-only",):
            raise AuthorityUnavailable("deletion migration requires v2-only seal")
        self.fences._check_schema(db)
        namespaces = tuple(row[0] for row in db.execute(
            "SELECT namespace FROM authority_namespaces"))
        if namespaces != (self.namespace,):
            raise AuthorityUnavailable("multi-namespace deletion migration is not implemented")
        if db.execute("SELECT 1 FROM authority_permits LIMIT 1").fetchone():
            raise AuthorityUnavailable("legacy permit blocks deletion migration")
        if db.execute("SELECT 1 FROM authority_v2_fences WHERE state='active' LIMIT 1").fetchone():
            raise AuthorityUnavailable("active v2 fence blocks deletion migration")
        if db.execute("SELECT 1 FROM authority_v2_mutations WHERE state='pending' LIMIT 1").fetchone():
            raise AuthorityUnavailable("pending v2 mutation blocks deletion migration")

    def begin_block(self, *, credential) -> dict:
        """First durable Authority commit; no journal lock nests inside it."""
        self.core._require(credential, "migrate_deletion", self.namespace)
        with self.core._tx() as db:
            self._require_mode_and_idle(db)
            row = self.core._row(db, self.namespace)
            if row[2] != "active" or row[0] is None or row[9] != "clear":
                raise AuthorityUnavailable("unsettled namespace blocks deletion migration")
            marker = self._read_marker(db)
            if marker is None:
                marker = {
                    "schema": _SCHEMA, "namespace": self.namespace,
                    "authority_id": self.core._id(db),
                    "journal_id": row[6], "cut_seq": row[7],
                    "cut_digest": row[8], "stage": "blocked",
                }
                db.execute("INSERT INTO authority_meta(key,value) VALUES(?,?)", (
                    _KEY, json.dumps(marker, sort_keys=True, separators=(",", ":"))))
            elif (marker["namespace"] != self.namespace
                  or marker["authority_id"] != self.core._id(db)):
                raise AuthorityUnavailable("deletion migration identity changed")
            return marker

    def migrate_journal(self, *, credential) -> None:
        """One FULL-synced transaction in the original deletion SQLite file."""
        self.core._require(credential, "migrate_deletion", self.namespace)
        with self.core._tx() as db:
            marker = self._read_marker(db)
            if marker is None or marker["stage"] != "blocked":
                raise AuthorityUnavailable("durable Authority migration blocker is absent")
        with self.deletion.freeze_writes():
            head = self.deletion.verified_head()
            if (head.journal_id, head.seq, head.digest) != (
                    marker["journal_id"], marker["cut_seq"], marker["cut_digest"]):
                raise AuthorityUnavailable("old deletion head changed after migration blocker")
            kind = self.deletion.schema_kind()
            if kind == "v2":
                metadata = self.deletion._check_schema()[2]
                if (metadata["namespace"] != self.namespace
                        or (int(metadata["cut_seq"]), metadata["cut_digest"]) !=
                        (marker["cut_seq"], marker["cut_digest"])):
                    raise AuthorityUnavailable("v2 deletion cutpoint differs from Authority")
                return
            db = self.deletion._db
            # Old update/delete triggers are replaced under the same writer txn.
            for name in ("deletion_events_immutable_update",
                         "deletion_events_immutable_delete"):
                db.execute(f"DROP TRIGGER {name}")
            for ddl in _PREFIX_TRIGGERS.values():
                db.execute(ddl)
            db.execute(_V2_META_DDL)
            db.execute(_V2_TAIL_DDL)
            for ddl in _TAIL_TRIGGERS.values():
                db.execute(ddl)
            db.executemany("INSERT INTO authority_deletion_v2_meta(key,value) VALUES(?,?)", (
                ("schema_version", "1"), ("journal_id", marker["journal_id"]),
                ("namespace", self.namespace), ("cut_seq", str(marker["cut_seq"])),
                ("cut_digest", marker["cut_digest"]),
            ))
            if self.deletion.schema_kind() != "v2" or self.deletion.verified_head() != head:
                raise AuthorityUnavailable("v2 deletion prefix migration did not verify")

    def complete(self, *, credential) -> None:
        """Final deletion→execution→Authority CAS after same-file migration."""
        self.core._require(credential, "migrate_deletion", self.namespace)
        with self.deletion.freeze_writes():
            if self.deletion.schema_kind() != "v2":
                raise AuthorityUnavailable("v2 deletion journal migration is incomplete")
            deletion_head = self.deletion.verified_head()
            metadata = self.deletion._check_schema()[2]
            with self.execution.freeze_writes():
                execution_head = self.execution.verified_head()
                with self.core._tx() as db:
                    self._require_mode_and_idle(db)
                    marker = self._read_marker(db)
                    if marker is None or marker["namespace"] != self.namespace:
                        raise AuthorityUnavailable("Authority migration blocker is absent")
                    row = self.core._row(db, self.namespace)
                    if (marker["stage"] not in ("blocked", "complete")
                            or marker["authority_id"] != self.core._id(db)
                            or metadata["namespace"] != self.namespace
                            or (metadata["journal_id"], int(metadata["cut_seq"]),
                                metadata["cut_digest"]) !=
                               (marker["journal_id"], marker["cut_seq"], marker["cut_digest"])
                            or row[6:9] != (deletion_head.journal_id, deletion_head.seq,
                                               deletion_head.digest)
                            or row[10:13] != (execution_head.journal_id,
                                                execution_head.seq, execution_head.digest)):
                        raise AuthorityUnavailable("deletion migration final anchor differs")
                    if marker["stage"] == "complete":
                        return
                    marker["stage"] = "complete"
                    db.execute("UPDATE authority_meta SET value=? WHERE key=?", (
                        json.dumps(marker, sort_keys=True, separators=(",", ":")), _KEY))

    def run(self, *, credential) -> None:
        marker = self.begin_block(credential=credential)
        if marker["stage"] == "complete":
            self.complete(credential=credential)
            return
        self.migrate_journal(credential=credential)
        self.complete(credential=credential)


__all__ = ["AuthorityV2DeletionMigration"]
