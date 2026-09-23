"""Independent, append-only deletion evidence and conservative access barrier.

The database belongs outside ordinary business backup/restore. SQLite FULL
sync makes an intent durable before its caller may acknowledge it. A pending
intent blocks its entire namespace because this layer cannot prove D06's
derived-content closure. The host must serialize this barrier with business
reads and dispatch; this primitive alone is not a production admission gate.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import uuid


class DeletionBlocked(RuntimeError):
    pass


class DeletionConflict(ValueError):
    pass


class DeletionJournalUnavailable(RuntimeError):
    pass


def _id(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256 or any(
        ord(c) < 33 or ord(c) > 126 for c in value
    ):
        raise ValueError(f"{label} must be a bounded content-free identifier")
    return value


def _uint(value: int, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a nonnegative exact integer")
    return value


def _canonical(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True)
class DeletionIntent:
    namespace: str
    seq: int
    operation_id: str
    closure_roots: tuple[str, ...]
    epoch: int
    policy_ref: str
    phase: str


@dataclass(frozen=True)
class DeletionHead:
    journal_id: str
    seq: int
    chain_digest: str


class DeletionJournal:
    """Durable intent first; pending/accepted/closed all retain a read barrier.

    ``accepted`` requires an injected business-barrier callback to return True
    after installing the graph-side shield. A callback failure leaves pending.
    Phase ``closed`` records physical cleanup completion, never resurrection.
    """

    def __init__(self, path, *, create: bool = False):
        self.path = Path(path)
        if not self.path.exists() and not create:
            raise DeletionJournalUnavailable("missing independent deletion journal")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS deletion_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS deletion_events (
                seq INTEGER PRIMARY KEY, namespace TEXT NOT NULL, operation_id TEXT NOT NULL,
                roots_json TEXT NOT NULL, epoch INTEGER NOT NULL, policy_ref TEXT NOT NULL,
                phase TEXT NOT NULL CHECK(phase IN ('pending','accepted','closed')),
                prev_digest TEXT NOT NULL, chain_digest TEXT NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS deletion_intent_once ON deletion_events(operation_id)
                WHERE phase='pending';
            CREATE TRIGGER IF NOT EXISTS deletion_events_immutable_update
                BEFORE UPDATE ON deletion_events BEGIN SELECT RAISE(ABORT,'append-only'); END;
            CREATE TRIGGER IF NOT EXISTS deletion_events_immutable_delete
                BEFORE DELETE ON deletion_events BEGIN SELECT RAISE(ABORT,'append-only'); END;
        """)
        self._db.execute("INSERT OR IGNORE INTO deletion_meta VALUES('journal_id',?)", (str(uuid.uuid4()),))

    def _ensure_open(self):
        if self._db is None:
            raise DeletionJournalUnavailable("deletion journal is closed")

    @staticmethod
    def _decode(row):
        return DeletionIntent(row[1], row[0], row[2], tuple(json.loads(row[3])),
                              row[4], row[5], row[6])

    def _append(self, namespace, operation_id, roots, epoch, policy_ref, phase):
        prior = self._db.execute(
            "SELECT seq,chain_digest FROM deletion_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        seq = 1 if prior is None else prior[0] + 1
        previous = "genesis" if prior is None else prior[1]
        body = dict(seq=seq, namespace=namespace, operation_id=operation_id,
                    roots=list(roots), epoch=epoch, policy_ref=policy_ref,
                    phase=phase, previous=previous)
        digest = "sha256:" + hashlib.sha256(_canonical(body).encode()).hexdigest()
        self._db.execute("INSERT INTO deletion_events VALUES(?,?,?,?,?,?,?,?,?)",
                         (seq, namespace, operation_id, _canonical(list(roots)), epoch,
                          policy_ref, phase, previous, digest))
        return DeletionIntent(namespace, seq, operation_id, roots, epoch, policy_ref, phase)

    def append_intent(self, *, namespace: str, operation_id: str,
                      closure_roots: tuple[str, ...], epoch: int, policy_ref: str):
        _id(namespace, "namespace")
        _id(operation_id, "operation_id")
        _id(policy_ref, "policy_ref")
        _uint(epoch, "epoch")
        if (not isinstance(closure_roots, tuple) or not closure_roots
                or len(set(closure_roots)) != len(closure_roots)):
            raise ValueError("closure_roots must be a nonempty unique tuple")
        for root in closure_roots:
            _id(root, "closure_root")
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                previous = self._db.execute(
                    "SELECT seq,namespace,operation_id,roots_json,epoch,policy_ref,phase "
                    "FROM deletion_events WHERE operation_id=? AND phase='pending'",
                    (operation_id,)).fetchone()
                if previous:
                    existing = self._decode(previous)
                    if (existing.namespace, existing.closure_roots, existing.epoch,
                            existing.policy_ref) != (namespace, closure_roots, epoch, policy_ref):
                        raise DeletionConflict("operation_id is bound to a different deletion")
                    self._db.execute("COMMIT")
                    return existing
                row = self._db.execute(
                    "SELECT MAX(epoch) FROM deletion_events WHERE namespace=? AND phase='pending'",
                    (namespace,)).fetchone()
                if row[0] is not None and epoch <= row[0]:
                    raise DeletionConflict("deletion epoch must increase")
                result = self._append(namespace, operation_id, closure_roots, epoch,
                                      policy_ref, "pending")
                self._db.execute("COMMIT")
                return result
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def advance(self, operation_id: str, phase: str, *, business_barrier=None,
                cleanup_verifier=None):
        _id(operation_id, "operation_id")
        if phase not in ("accepted", "closed"):
            raise ValueError("invalid deletion phase")
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT seq,namespace,operation_id,roots_json,epoch,policy_ref,phase "
                    "FROM deletion_events WHERE operation_id=? ORDER BY seq DESC LIMIT 1",
                    (operation_id,)).fetchone()
                if row is None:
                    raise KeyError(operation_id)
                prior = self._decode(row)
                if prior.phase == phase:
                    self._db.execute("COMMIT")
                    return prior
                if (prior.phase, phase) not in (("pending", "accepted"), ("accepted", "closed")):
                    raise DeletionConflict("invalid phase transition")
                if phase == "accepted" and (business_barrier is None or
                                            business_barrier(prior) is not True):
                    raise DeletionBlocked("business read/outbound shield is not confirmed")
                if phase == "closed" and (cleanup_verifier is None or
                                          cleanup_verifier(prior) is not True):
                    raise DeletionBlocked("cleanup facets are not confirmed")
                result = self._append(prior.namespace, operation_id, prior.closure_roots,
                                      prior.epoch, prior.policy_ref, phase)
                self._db.execute("COMMIT")
                return result
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def assert_access(self, namespace: str, *, content_refs: tuple[str, ...] | None = None,
                      closure_verifier=None):
        """Pending blocks namespace; accepted closures require D06 disjointness.

        The injected verifier must check *every* requested content reference
        against the complete D06 closure including derived/cached forms. Without
        it, this primitive blocks the whole namespace rather than guessing.
        """
        _id(namespace, "namespace")
        with self._lock:
            self._ensure_open()
            rows = self._db.execute(
                "SELECT e.seq,e.namespace,e.operation_id,e.roots_json,e.epoch,e.policy_ref,e.phase "
                "FROM deletion_events e JOIN (SELECT operation_id,MAX(seq) seq "
                "FROM deletion_events WHERE namespace=? GROUP BY operation_id) latest "
                "ON e.seq=latest.seq", (namespace,)).fetchall()
            if any(row[6] == "pending" for row in rows):
                raise DeletionBlocked("namespace has a pending deletion intent")
            if rows:
                if (not isinstance(content_refs, tuple) or not content_refs
                        or closure_verifier is None):
                    raise DeletionBlocked("complete deletion closure is not verified")
                for ref in content_refs:
                    _id(ref, "content_ref")
                for row in rows:
                    try:
                        allowed = closure_verifier(self._decode(row), content_refs)
                    except Exception as exc:
                        raise DeletionBlocked("deletion closure verifier unavailable") from exc
                    if allowed is not True:
                        raise DeletionBlocked("content may be in a deletion closure")

    def latest_head(self) -> DeletionHead:
        with self._lock:
            self._ensure_open()
            jid = self._db.execute(
                "SELECT value FROM deletion_meta WHERE key='journal_id'").fetchone()[0]
            row = self._db.execute(
                "SELECT seq,chain_digest FROM deletion_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            return DeletionHead(jid, row[0], row[1]) if row else DeletionHead(jid, 0, "genesis")

    def verify_chain(self, expected: DeletionHead) -> bool:
        with self._lock:
            self._ensure_open()
            if self.latest_head() != expected:
                return False
            previous = "genesis"
            next_seq = 1
            for row in self._db.execute(
                "SELECT seq,namespace,operation_id,roots_json,epoch,policy_ref,phase,"
                "prev_digest,chain_digest FROM deletion_events ORDER BY seq"
            ):
                seq, ns, op, roots, epoch, policy, phase, prev, digest = row
                if seq != next_seq or prev != previous:
                    return False
                body = dict(seq=seq, namespace=ns, operation_id=op,
                            roots=json.loads(roots), epoch=epoch, policy_ref=policy,
                            phase=phase, previous=previous)
                candidate = "sha256:" + hashlib.sha256(_canonical(body).encode()).hexdigest()
                if candidate != digest:
                    return False
                previous, next_seq = digest, next_seq + 1
            return next_seq - 1 == expected.seq and previous == expected.chain_digest

    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
