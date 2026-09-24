"""Crash-resumable, stopped-service upgrade of the same-file deletion tail.

The existing Authority deletion migration marker is set to an unknown stage
while this upgrade runs. Every current v2 service entrance rejects that stage.
The operator must separately exclude old processes and DDL-capable writers.
"""

from __future__ import annotations

import json

from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .v2_deletion_guard import (
    AuthorityV2DeletionGuard, _PREFIX_TRIGGERS, _TAIL_TRIGGERS, _TAIL_TRIGGERS_V2,
    _V2_TAIL_DDL_V2,
)
from .v2_execution_journal import AuthorityV2ExecutionJournal
from .v2_fence_store import AuthorityV2FenceStore


_KEY = "deletion_v2_tail_migration"
_OLD_KEY = "deletion_v2_migration"
_SCHEMA = "sylanne3.deletion-tail-migration.v2"
_PREFIX_DDL = {
    ("table", "deletion_meta"):
        "CREATE TABLE deletion_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    ("table", "deletion_events"): """CREATE TABLE deletion_events (
                seq INTEGER PRIMARY KEY, namespace TEXT NOT NULL, operation_id TEXT NOT NULL,
                roots_json TEXT NOT NULL, epoch INTEGER NOT NULL, policy_ref TEXT NOT NULL,
                phase TEXT NOT NULL CHECK(phase IN ('pending','accepted','closed')),
                prev_digest TEXT NOT NULL, chain_digest TEXT NOT NULL)""",
    ("index", "deletion_intent_once"):
        "CREATE UNIQUE INDEX deletion_intent_once ON deletion_events(operation_id)\n                WHERE phase='pending'",
    **{("trigger", name): ddl for name, ddl in _PREFIX_TRIGGERS.items()},
}


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class AuthorityV2DeletionTailMigration:
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
            raise AuthorityUnavailable("tail migration requires one service DB and namespace")
        self.core, self.fences = core, fences
        self.deletion, self.execution = deletion, execution
        self.namespace = namespace

    @staticmethod
    def _marker(db, key):
        row = db.execute("SELECT value FROM authority_meta WHERE key=?", (key,)).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row[0])
        except (TypeError, ValueError) as exc:
            raise AuthorityUnavailable("malformed deletion migration marker") from exc
        if type(value) is not dict:
            raise AuthorityUnavailable("malformed deletion migration marker")
        return value

    def _read_markers(self, db):
        old = self._marker(db, _OLD_KEY)
        target = self._marker(db, _KEY)
        if (old is None or set(old) != {"schema", "namespace", "authority_id",
                "journal_id", "cut_seq", "cut_digest", "stage"}
                or old["schema"] != "sylanne3.deletion-migration.v1"
                or old["stage"] not in ("complete", "tail-blocked")
                or old["namespace"] != self.namespace):
            raise AuthorityUnavailable("completed prefix migration is required")
        if target is not None and (set(target) != {"schema", "namespace", "authority_id",
                "journal_id", "before_seq", "before_digest", "target_version", "stage"}
                or target["schema"] != _SCHEMA or target["namespace"] != self.namespace
                or target["authority_id"] != old["authority_id"]
                or target["journal_id"] != old["journal_id"]
                or target["target_version"] != 2
                or target["stage"] not in ("blocked", "complete")
                or type(target["before_seq"]) is not int or target["before_seq"] < 0):
            raise AuthorityUnavailable("unknown deletion tail migration marker")
        if ((old["stage"] == "tail-blocked") !=
                (target is not None and target["stage"] == "blocked")):
            raise AuthorityUnavailable("deletion tail migration blockers disagree")
        return old, target

    def begin_block(self, *, credential):
        """Commit the v2 entry blocker before touching the journal file."""
        self.core._require(credential, "migrate_deletion", self.namespace)
        with self.core._tx() as db:
            if db.execute("SELECT value FROM authority_meta WHERE key='service_mode'").fetchone() != ("v2-only",):
                raise AuthorityUnavailable("tail migration requires v2-only mode")
            self.fences._check_schema(db)
            old, target = self._read_markers(db)
            if target is not None:
                return target
            if (tuple(row[0] for row in db.execute("SELECT namespace FROM authority_namespaces"))
                    != (self.namespace,)):
                raise AuthorityUnavailable("tail migration requires one namespace")
            if db.execute("SELECT 1 FROM authority_permits LIMIT 1").fetchone():
                raise AuthorityUnavailable("legacy permit blocks tail migration")
            if db.execute("SELECT 1 FROM authority_v2_fences WHERE state='active' OR pending IS NOT NULL LIMIT 1").fetchone():
                raise AuthorityUnavailable("active fence blocks tail migration")
            if db.execute("SELECT 1 FROM authority_v2_mutations WHERE state='pending' LIMIT 1").fetchone():
                raise AuthorityUnavailable("pending mutation blocks tail migration")
            row = self.core._row(db, self.namespace)
            if row[2] != "active" or row[0] is None or row[9] != "clear":
                raise AuthorityUnavailable("unsettled namespace blocks tail migration")
            if (old["authority_id"], old["journal_id"]) != (self.core._id(db), row[6]):
                raise AuthorityUnavailable("prefix migration identity differs")
            target = dict(schema=_SCHEMA, namespace=self.namespace,
                          authority_id=old["authority_id"], journal_id=row[6],
                          before_seq=row[7], before_digest=row[8],
                          target_version=2, stage="blocked")
            old["stage"] = "tail-blocked"
            db.execute("UPDATE authority_meta SET value=? WHERE key=?", (_encoded(old), _OLD_KEY))
            db.execute("INSERT INTO authority_meta(key,value) VALUES(?,?)", (_KEY, _encoded(target)))
            return target

    def migrate_journal(self, *, credential):
        """Replace only an empty schema-1 tail in one FULL WAL transaction."""
        self.core._require(credential, "migrate_deletion", self.namespace)
        with self.core._tx() as db:
            _, marker = self._read_markers(db)
            if marker is None or marker["stage"] != "blocked":
                raise AuthorityUnavailable("durable tail blocker is absent")
        with self.deletion.freeze_writes():
            objects = {(kind, name): ddl for kind, name, ddl in self.deletion._db.execute(
                "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
            if any(objects.get(key) != ddl for key, ddl in _PREFIX_DDL.items()):
                raise AuthorityUnavailable("deletion historical prefix DDL differs")
            head = self.deletion.verified_head()
            if (head.journal_id, head.seq, head.digest) != (
                    marker["journal_id"], marker["before_seq"], marker["before_digest"]):
                raise AuthorityUnavailable("deletion head changed after tail blocker")
            version = self.deletion.schema_version()
            metadata = self.deletion._check_schema()[2]
            if (metadata["namespace"] != self.namespace
                    or int(metadata["cut_seq"]) != marker["before_seq"]
                    or metadata["cut_digest"] != marker["before_digest"]):
                raise AuthorityUnavailable("tail cut or namespace differs from blocker")
            if version == 2:
                return
            if (self.deletion._db.execute(
                        "SELECT 1 FROM authority_deletion_v2_tail LIMIT 1").fetchone()):
                raise AuthorityUnavailable("tail upgrade requires exact cut and empty old tail")
            log = self.deletion._db
            for name in _TAIL_TRIGGERS:
                log.execute(f"DROP TRIGGER {name}")
            log.execute("DROP TABLE authority_deletion_v2_tail")
            log.execute(_V2_TAIL_DDL_V2)
            for ddl in _TAIL_TRIGGERS_V2.values():
                log.execute(ddl)
            log.execute("UPDATE authority_deletion_v2_meta SET value='2' WHERE key='schema_version'")
            if self.deletion.schema_version() != 2 or self.deletion.verified_head() != head:
                raise AuthorityUnavailable("upgraded tail failed verification")

    def complete(self, *, credential):
        """Finish only after both journals and Authority agree on the head."""
        self.core._require(credential, "migrate_deletion", self.namespace)
        with self.deletion.freeze_writes():
            if self.deletion.schema_version() != 2:
                raise AuthorityUnavailable("schema-2 tail is absent")
            deletion_head = self.deletion.verified_head()
            metadata = self.deletion._check_schema()[2]
            if (metadata["namespace"] != self.namespace
                    or int(metadata["cut_seq"]) != deletion_head.seq
                    or metadata["cut_digest"] != deletion_head.digest):
                raise AuthorityUnavailable("schema-2 tail cut or namespace differs")
            with self.execution.freeze_writes():
                execution_head = self.execution.verified_head()
                with self.core._tx() as db:
                    old, marker = self._read_markers(db)
                    if marker is None or (old["authority_id"] != self.core._id(db)
                            or marker["authority_id"] != self.core._id(db)
                            or (deletion_head.journal_id, deletion_head.seq,
                                deletion_head.digest) != (marker["journal_id"],
                                                         marker["before_seq"],
                                                         marker["before_digest"])):
                        raise AuthorityUnavailable("tail migration identity or head differs")
                    row = self.core._row(db, self.namespace)
                    if (row[6:9] != (deletion_head.journal_id, deletion_head.seq,
                                      deletion_head.digest)
                            or row[10:13] != (execution_head.journal_id,
                                               execution_head.seq, execution_head.digest)):
                        raise AuthorityUnavailable("Authority anchor differs at tail completion")
                    if marker["stage"] == "complete":
                        return
                    old["stage"] = "complete"
                    marker["stage"] = "complete"
                    db.execute("UPDATE authority_meta SET value=? WHERE key=?",
                               (_encoded(old), _OLD_KEY))
                    db.execute("UPDATE authority_meta SET value=? WHERE key=?",
                               (_encoded(marker), _KEY))

    def run(self, *, credential):
        marker = self.begin_block(credential=credential)
        if marker["stage"] == "blocked":
            self.migrate_journal(credential=credential)
        self.complete(credential=credential)


__all__ = ["AuthorityV2DeletionTailMigration"]
