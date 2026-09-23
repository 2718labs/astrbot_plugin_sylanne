"""Service-owned, single-namespace v2 execution append substrate.

Only an installer-owned service may construct this object or call append_once.
PendingMutationV2 is a shape and identity record, not authorization: this
module cannot authenticate a subject, verify a footprint, or commit an
Authority head. The service must first persist the matching pending fence.

One SQLite file is one v2 journal and one namespace. Legacy/mixed schemas are
rejected. With WAL and synchronous=FULL, a successful SQLite commit syncs the
append before append_once returns. The chain detects accidental alteration;
freshness against a fully rewritten file still requires the external Authority.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
import threading

from .contract import AuthorityUnavailable, JournalHead, identifier
from .v2_contract import (
    PendingMutationV2, canonical_bytes, decode_bytes, to_wire,
)


_VERSION = "1"
_META_DDL = "CREATE TABLE authority_v2_execution_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT"
_ENTRY_DDL = """CREATE TABLE authority_v2_execution_entries(
    seq INTEGER PRIMARY KEY CHECK(seq > 0),
    mutation_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL,
    append_id TEXT NOT NULL UNIQUE,
    pending BLOB NOT NULL,
    previous_digest TEXT NOT NULL,
    chain_digest TEXT NOT NULL
) STRICT"""
_UPDATE_DDL = """CREATE TRIGGER authority_v2_execution_no_update
BEFORE UPDATE ON authority_v2_execution_entries
BEGIN SELECT RAISE(ABORT,'append-only'); END"""
_DELETE_DDL = """CREATE TRIGGER authority_v2_execution_no_delete
BEFORE DELETE ON authority_v2_execution_entries
BEGIN SELECT RAISE(ABORT,'append-only'); END"""
_OBJECTS = {
    ("table", "authority_v2_execution_meta"): _META_DDL,
    ("table", "authority_v2_execution_entries"): _ENTRY_DDL,
    ("trigger", "authority_v2_execution_no_update"): _UPDATE_DDL,
    ("trigger", "authority_v2_execution_no_delete"): _DELETE_DDL,
}


@dataclass(frozen=True, slots=True)
class VerifiedAppendV2:
    journal_id: str
    namespace: str
    seq: int
    mutation_id: str
    request_digest: str
    append_id: str
    chain_digest: str


@dataclass(frozen=True, slots=True)
class ExpectedAppendInspectionV2:
    """0, 1, or >1 rows after the pending before-head; never a commit decision."""

    following_count: int
    first_append: VerifiedAppendV2 | None
    verified_head: JournalHead


class AuthorityV2ExecutionJournal:
    def __init__(self, path, *, namespace: str, journal_id: str, create: bool = False):
        identifier(namespace, "namespace")
        identifier(journal_id, "journal_id")
        self.path = Path(path)
        if not create and not self.path.is_file():
            raise AuthorityUnavailable("v2 execution journal is absent")
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.namespace = namespace
        self.journal_id = journal_id
        self._lock = threading.RLock()
        self._guard_owner: int | None = None
        self._db = sqlite3.connect(self.path, isolation_level=None,
                                   check_same_thread=False, timeout=5)
        try:
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA busy_timeout=5000")
            mode = self._db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            self._db.execute("PRAGMA synchronous=FULL")
            if (mode.lower() != "wal"
                    or self._db.execute("PRAGMA synchronous").fetchone()[0] < 2):
                raise AuthorityUnavailable("v2 execution journal lacks FULL WAL durability")
            with self._transaction():
                existing = self._objects()
                if not existing:
                    if not create:
                        raise AuthorityUnavailable("v2 execution schema is absent")
                    for ddl in _OBJECTS.values():
                        self._db.execute(ddl)
                    self._db.executemany(
                        "INSERT INTO authority_v2_execution_meta(key,value) VALUES(?,?)",
                        (("schema_version", _VERSION), ("namespace", namespace),
                         ("journal_id", journal_id)),
                    )
                self._check_schema()
                self._scan_locked()
        except BaseException:
            self._db.close()
            self._db = None
            raise

    def _objects(self) -> dict[tuple[str, str], str]:
        return {(kind, name): ddl for kind, name, ddl in self._db.execute(
            "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}

    def _check_schema(self) -> None:
        if self._objects() != _OBJECTS:
            raise AuthorityUnavailable("legacy, mixed or malformed v2 execution schema")
        meta = dict(self._db.execute("SELECT key,value FROM authority_v2_execution_meta"))
        if meta != {"schema_version": _VERSION, "namespace": self.namespace,
                    "journal_id": self.journal_id}:
            raise AuthorityUnavailable("v2 execution schema/version/namespace mismatch")

    @contextmanager
    def _transaction(self):
        with self._lock:
            if self._db is None or self._db.in_transaction:
                raise AuthorityUnavailable("v2 execution journal transaction unavailable")
            try:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    yield
                    self._db.execute("COMMIT")
                except BaseException:
                    self._db.execute("ROLLBACK")
                    raise
            except sqlite3.Error as exc:
                raise AuthorityUnavailable("v2 execution journal SQLite failure") from exc

    @contextmanager
    def freeze_writes(self):
        """Hold the sole writer across inspect_expected and an Authority CAS.

        The caller must release this guard before waiting for a graph lock or
        invoking any business callback. No append may run inside this guard.
        """
        with self._transaction():
            self._guard_owner = threading.get_ident()
            try:
                self._check_schema()
                yield self
            finally:
                self._guard_owner = None

    @staticmethod
    def _material(pending: PendingMutationV2, seq: int, previous: str,
                  journal_id: str) -> bytes:
        shape = to_wire(pending)
        shape.pop("expected_append_digest")  # The digest cannot contain itself.
        return json.dumps({
            "journal_id": journal_id, "seq": seq,
            "previous_digest": previous, "pending": shape,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8")

    @classmethod
    def expected_digest(cls, pending: PendingMutationV2) -> str:
        """Preview a chain digest; this neither authorizes nor appends."""
        if type(pending) is not PendingMutationV2:
            raise TypeError("PendingMutationV2 required")
        return "sha256:" + hashlib.sha256(cls._material(
            pending, pending.expected_execution_seq,
            pending.before_anchor.execution_digest,
            pending.expected_execution_journal_id,
        )).hexdigest()

    def _require_pending(self, pending: PendingMutationV2) -> None:
        if type(pending) is not PendingMutationV2:
            raise AuthorityUnavailable("PendingMutationV2 required")
        if (pending.permit.namespace != self.namespace
                or pending.expected_execution_journal_id != self.journal_id):
            raise AuthorityUnavailable("pending namespace or journal mismatch")
        if pending.expected_append_digest != self.expected_digest(pending):
            raise AuthorityUnavailable("pending expected digest does not match canonical append")

    @staticmethod
    def _append_from_row(row, journal_id: str, namespace: str) -> VerifiedAppendV2:
        return VerifiedAppendV2(journal_id, namespace, row[0], row[1], row[2],
                                row[3], row[6])

    def _scan_locked(self) -> tuple[JournalHead, list[tuple]]:
        previous = "genesis"
        rows = list(self._db.execute(
            "SELECT seq,mutation_id,request_digest,append_id,pending,previous_digest,chain_digest "
            "FROM authority_v2_execution_entries ORDER BY seq"))
        for expected_seq, row in enumerate(rows, 1):
            seq, mutation_id, request_digest, append_id, encoded, prev, digest = row
            try:
                pending = decode_bytes(encoded)
            except (TypeError, ValueError, UnicodeError) as exc:
                raise AuthorityUnavailable("malformed persisted execution pending") from exc
            if (type(pending) is not PendingMutationV2
                    or encoded != canonical_bytes(pending)
                    or seq != expected_seq or prev != previous
                    or (mutation_id, request_digest, append_id) != (
                        pending.mutation_id, pending.request_digest,
                        pending.expected_append_id)
                    or pending.permit.namespace != self.namespace
                    or pending.expected_execution_journal_id != self.journal_id
                    or pending.before_anchor.execution_seq != seq - 1
                    or pending.before_anchor.execution_digest != previous
                    or pending.expected_append_digest != digest
                    or self.expected_digest(pending) != digest):
                raise AuthorityUnavailable("v2 execution chain or entry identity is invalid")
            previous = digest
        return JournalHead(self.journal_id, len(rows), previous), rows

    def verified_head(self) -> JournalHead:
        """Recompute the full chain; a current Authority anchor remains required."""
        if self._guard_owner == threading.get_ident():
            self._check_schema()
            return self._scan_locked()[0]
        with self._transaction():
            self._check_schema()
            return self._scan_locked()[0]

    def inspect_expected(self, pending: PendingMutationV2) -> ExpectedAppendInspectionV2:
        """Inspect while freeze_writes is held; never repair or append here."""
        if self._guard_owner != threading.get_ident():
            raise AuthorityUnavailable("inspect_expected requires frozen journal writer")
        self._check_schema()
        self._require_pending(pending)
        head, rows = self._scan_locked()
        before = pending.before_anchor
        if (before.execution_seq > head.seq
                or (before.execution_seq and rows[before.execution_seq - 1][6]
                    != before.execution_digest)
                or (before.execution_seq == 0 and before.execution_digest != "genesis")):
            raise AuthorityUnavailable("pending before-head is absent or differs")
        following = head.seq - before.execution_seq
        first = None
        if following:
            row = rows[before.execution_seq]
            if row[4] != canonical_bytes(pending):
                raise AuthorityUnavailable("first append differs from pending mutation")
            first = self._append_from_row(row, self.journal_id, self.namespace)
        return ExpectedAppendInspectionV2(following, first, head)

    def _append_locked(self, pending: PendingMutationV2) -> VerifiedAppendV2:
        self._require_pending(pending)
        self._check_schema()
        head, _ = self._scan_locked()
        existing = self._db.execute(
            "SELECT seq,mutation_id,request_digest,append_id,pending,previous_digest,chain_digest "
            "FROM authority_v2_execution_entries WHERE mutation_id=?",
            (pending.mutation_id,),
        ).fetchone()
        if existing is not None:
            if (existing[4] != canonical_bytes(pending) or existing[0] != head.seq
                    or existing[5] != pending.before_anchor.execution_digest):
                raise AuthorityUnavailable("mutation ID reused or append no longer current")
            return self._append_from_row(existing, self.journal_id, self.namespace)
        if (head.seq != pending.before_anchor.execution_seq
                or head.digest != pending.before_anchor.execution_digest):
            raise AuthorityUnavailable("execution before-head differs")
        try:
            self._db.execute(
                "INSERT INTO authority_v2_execution_entries "
                "(seq,mutation_id,request_digest,append_id,pending,previous_digest,chain_digest) "
                "VALUES(?,?,?,?,?,?,?)",
                (pending.expected_execution_seq, pending.mutation_id,
                 pending.request_digest, pending.expected_append_id,
                 canonical_bytes(pending), head.digest,
                 pending.expected_append_digest),
            )
        except sqlite3.IntegrityError as exc:
            raise AuthorityUnavailable("append ID or sequence already bound") from exc
        return VerifiedAppendV2(
            self.journal_id, self.namespace, pending.expected_execution_seq,
            pending.mutation_id, pending.request_digest,
            pending.expected_append_id, pending.expected_append_digest,
        )

    def append_once_guarded(self, pending: PendingMutationV2) -> VerifiedAppendV2:
        """Service-internal append after Authority pending check under freeze_writes."""
        if self._guard_owner != threading.get_ident():
            raise AuthorityUnavailable("guarded append requires frozen journal writer")
        return self._append_locked(pending)

    def append_once(self, pending: PendingMutationV2) -> VerifiedAppendV2:
        """Journal-only append; callers must have persisted Authority pending."""
        with self._transaction():
            return self._append_locked(pending)

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None


__all__ = ["AuthorityV2ExecutionJournal", "ExpectedAppendInspectionV2",
           "VerifiedAppendV2"]
