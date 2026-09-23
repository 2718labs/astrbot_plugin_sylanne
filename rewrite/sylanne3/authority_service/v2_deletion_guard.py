"""Service-side writer freeze and verified v1-prefix/v2-tail deletion reader.

This does not issue deletion decisions or invoke graph callbacks. A separate
SQLite BEGIN IMMEDIATE on the *same file* waits for in-flight append/advance
and excludes another writer until the Authority transaction has committed.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
import threading

from .contract import AuthorityUnavailable, JournalHead


_V2_META_DDL = "CREATE TABLE authority_deletion_v2_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT"
_V2_TAIL_DDL = """CREATE TABLE authority_deletion_v2_tail(
    seq INTEGER PRIMARY KEY CHECK(seq > 0), mutation_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL, namespace TEXT NOT NULL,
    operation_id TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('pending','accepted','closed')),
    subject TEXT NOT NULL, holder TEXT NOT NULL, token_digest TEXT NOT NULL,
    fence_epoch INTEGER NOT NULL, revision INTEGER NOT NULL,
    before_seq INTEGER NOT NULL, before_digest TEXT NOT NULL,
    evidence_digest TEXT NOT NULL, roots_json TEXT NOT NULL,
    epoch INTEGER NOT NULL, policy_ref TEXT NOT NULL,
    prev_digest TEXT NOT NULL, chain_digest TEXT NOT NULL
) STRICT"""
_PREFIX_TRIGGERS = {
    "deletion_events_immutable_insert": "CREATE TRIGGER deletion_events_immutable_insert BEFORE INSERT ON deletion_events BEGIN SELECT RAISE(ABORT,'v2 historical prefix'); END",
    "deletion_events_immutable_update": "CREATE TRIGGER deletion_events_immutable_update BEFORE UPDATE ON deletion_events BEGIN SELECT RAISE(ABORT,'v2 historical prefix'); END",
    "deletion_events_immutable_delete": "CREATE TRIGGER deletion_events_immutable_delete BEFORE DELETE ON deletion_events BEGIN SELECT RAISE(ABORT,'v2 historical prefix'); END",
}
_TAIL_TRIGGERS = {
    "authority_deletion_v2_no_insert": "CREATE TRIGGER authority_deletion_v2_no_insert BEFORE INSERT ON authority_deletion_v2_tail BEGIN SELECT RAISE(ABORT,'v2 deletion append disabled'); END",
    "authority_deletion_v2_no_update": "CREATE TRIGGER authority_deletion_v2_no_update BEFORE UPDATE ON authority_deletion_v2_tail BEGIN SELECT RAISE(ABORT,'append-only'); END",
    "authority_deletion_v2_no_delete": "CREATE TRIGGER authority_deletion_v2_no_delete BEFORE DELETE ON authority_deletion_v2_tail BEGIN SELECT RAISE(ABORT,'append-only'); END",
}


class AuthorityV2DeletionGuard:
    def __init__(self, path):
        self.path = Path(path)
        if not self.path.is_file():
            raise AuthorityUnavailable("independent deletion journal is absent")
        self._lock = threading.RLock()
        self._db = sqlite3.connect(f"file:{self.path.as_posix()}?mode=rw", uri=True,
                                   isolation_level=None, check_same_thread=False)
        try:
            self._db.execute("PRAGMA busy_timeout=5000")
            if self._db.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                raise AuthorityUnavailable("deletion journal is not WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            if self._db.execute("PRAGMA synchronous").fetchone()[0] < 2:
                raise AuthorityUnavailable("deletion journal is not FULL synchronous")
            with self.freeze_writes():
                self.verified_head()
        except BaseException:
            self._db.close()
            self._db = None
            raise

    def _check_schema(self):
        objects = {(kind, name): ddl for kind, name, ddl in self._db.execute(
            "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
        legacy = {
            ("table", "deletion_meta"), ("table", "deletion_events"),
            ("index", "deletion_intent_once"),
            ("trigger", "deletion_events_immutable_update"),
            ("trigger", "deletion_events_immutable_delete"),
        }
        v2 = legacy | {
            ("table", "authority_deletion_v2_meta"),
            ("table", "authority_deletion_v2_tail"),
            ("trigger", "deletion_events_immutable_insert"),
            ("trigger", "authority_deletion_v2_no_insert"),
            ("trigger", "authority_deletion_v2_no_update"),
            ("trigger", "authority_deletion_v2_no_delete"),
        }
        if set(objects) not in (legacy, v2):
            raise AuthorityUnavailable("malformed or mixed deletion journal schema")
        columns = tuple(row[1] for row in self._db.execute(
            "PRAGMA table_info(deletion_events)"))
        if columns != ("seq", "namespace", "operation_id", "roots_json", "epoch",
                       "policy_ref", "phase", "prev_digest", "chain_digest"):
            raise AuthorityUnavailable("malformed deletion journal events")
        meta = tuple(self._db.execute("SELECT key,value FROM deletion_meta"))
        if len(meta) != 1 or meta[0][0] != "journal_id" or not meta[0][1]:
            raise AuthorityUnavailable("malformed deletion journal identity")
        if set(objects) == legacy:
            return "legacy", meta[0][1], None
        expected_sql = {
            ("table", "authority_deletion_v2_meta"): _V2_META_DDL,
            ("table", "authority_deletion_v2_tail"): _V2_TAIL_DDL,
            **{("trigger", name): ddl for name, ddl in
               {**_PREFIX_TRIGGERS, **_TAIL_TRIGGERS}.items()},
        }
        if any(objects[key] != ddl for key, ddl in expected_sql.items()):
            raise AuthorityUnavailable("unsafe v2 deletion schema migration")
        values = dict(self._db.execute("SELECT key,value FROM authority_deletion_v2_meta"))
        if (set(values) != {"schema_version", "journal_id", "namespace", "cut_seq", "cut_digest"}
                or values["schema_version"] != "1" or values["journal_id"] != meta[0][1]
                or not values["namespace"]):
            raise AuthorityUnavailable("unknown v2 deletion metadata")
        try:
            cut_seq = int(values["cut_seq"])
        except ValueError as exc:
            raise AuthorityUnavailable("invalid v2 deletion cut sequence") from exc
        if cut_seq < 0 or str(cut_seq) != values["cut_seq"]:
            raise AuthorityUnavailable("invalid v2 deletion cut sequence")
        return "v2", meta[0][1], values

    def schema_kind(self) -> str:
        if self._db is None or not self._db.in_transaction:
            raise AuthorityUnavailable("deletion schema query requires writer guard")
        return self._check_schema()[0]

    @contextmanager
    def freeze_writes(self):
        with self._lock:
            if self._db is None or self._db.in_transaction:
                raise AuthorityUnavailable("deletion writer guard unavailable")
            try:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    self._check_schema()
                    yield self
                    self._db.execute("COMMIT")
                except BaseException:
                    self._db.execute("ROLLBACK")
                    raise
            except sqlite3.Error as exc:
                raise AuthorityUnavailable("deletion writer guard SQLite failure") from exc

    def verified_head(self) -> JournalHead:
        """Scan the full chain on the writer-frozen connection."""
        if self._db is None or not self._db.in_transaction:
            raise AuthorityUnavailable("deletion chain requires writer guard")
        kind, journal_id, metadata = self._check_schema()
        previous = "genesis"
        seq = 0
        try:
            for row in self._db.execute(
                "SELECT seq,namespace,operation_id,roots_json,epoch,policy_ref,phase,"
                "prev_digest,chain_digest FROM deletion_events ORDER BY seq"):
                number, namespace, operation, roots_json, epoch, policy, phase, prior, digest = row
                if (type(number) is not int or number != seq + 1 or prior != previous
                        or phase not in ("pending", "accepted", "closed")
                        or type(epoch) is not int or epoch < 0):
                    raise AuthorityUnavailable("deletion journal chain is discontinuous")
                roots = json.loads(roots_json)
                if type(roots) is not list or not roots or any(type(x) is not str for x in roots):
                    raise AuthorityUnavailable("deletion journal roots are malformed")
                body = dict(seq=number, namespace=namespace, operation_id=operation,
                            roots=roots, epoch=epoch, policy_ref=policy,
                            phase=phase, previous=previous)
                encoded = json.dumps(body, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()
                calculated = "sha256:" + hashlib.sha256(encoded).hexdigest()
                if digest != calculated:
                    raise AuthorityUnavailable("deletion journal chain digest mismatch")
                previous, seq = digest, number
        except (TypeError, ValueError, UnicodeError, sqlite3.Error) as exc:
            raise AuthorityUnavailable("malformed deletion journal chain") from exc
        if kind == "v2":
            if (seq, previous) != (int(metadata["cut_seq"]), metadata["cut_digest"]):
                raise AuthorityUnavailable("v2 deletion historical cut differs")
            try:
                for row in self._db.execute(
                    "SELECT seq,mutation_id,request_digest,namespace,operation_id,phase,"
                    "subject,holder,token_digest,fence_epoch,revision,before_seq,before_digest,"
                    "evidence_digest,roots_json,epoch,policy_ref,prev_digest,chain_digest "
                    "FROM authority_deletion_v2_tail ORDER BY seq"):
                    (number, mutation_id, request_digest, namespace, operation, phase,
                     subject, holder, token_digest, fence_epoch, revision, before_seq,
                     before_digest, evidence_digest, roots_json, epoch, policy, prior,
                     digest) = row
                    if (type(number) is not int or number != seq + 1
                            or prior != previous or before_seq != seq
                            or before_digest != previous or namespace != metadata["namespace"]
                            or phase not in ("pending", "accepted", "closed")):
                        raise AuthorityUnavailable("v2 deletion tail is discontinuous")
                    roots = json.loads(roots_json)
                    if type(roots) is not list or not roots:
                        raise AuthorityUnavailable("v2 deletion roots are malformed")
                    body = dict(seq=number, mutation_id=mutation_id,
                                request_digest=request_digest, namespace=namespace,
                                operation_id=operation, phase=phase, subject=subject,
                                holder=holder, token_digest=token_digest,
                                fence_epoch=fence_epoch, revision=revision,
                                before_seq=before_seq, before_digest=before_digest,
                                evidence_digest=evidence_digest, roots=roots,
                                epoch=epoch, policy_ref=policy, previous=prior)
                    calculated = "sha256:" + hashlib.sha256(json.dumps(
                        body, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True).encode()).hexdigest()
                    if digest != calculated:
                        raise AuthorityUnavailable("v2 deletion tail digest mismatch")
                    previous, seq = digest, number
            except (TypeError, ValueError, UnicodeError, sqlite3.Error) as exc:
                raise AuthorityUnavailable("malformed v2 deletion tail") from exc
        return JournalHead(journal_id, seq, previous)

    def latest_phases(self) -> dict[tuple[str, str], str]:
        """Verified latest phase for every historical and future operation."""
        if self._db is None or not self._db.in_transaction:
            raise AuthorityUnavailable("deletion history query requires writer guard")
        self.verified_head()
        phases: dict[tuple[str, str], str] = {}
        for namespace, operation, phase in self._db.execute(
                "SELECT namespace,operation_id,phase FROM deletion_events ORDER BY seq"):
            key = (namespace, operation)
            prior = phases.get(key)
            if (prior, phase) not in ((None, "pending"), ("pending", "accepted"),
                                      ("accepted", "closed")):
                raise AuthorityUnavailable("invalid historical deletion phase transition")
            phases[key] = phase
        if self.schema_kind() == "v2":
            for namespace, operation, phase in self._db.execute(
                    "SELECT namespace,operation_id,phase FROM authority_deletion_v2_tail ORDER BY seq"):
                key = (namespace, operation)
                prior = phases.get(key)
                if (prior, phase) not in ((None, "pending"), ("pending", "accepted"),
                                          ("accepted", "closed")):
                    raise AuthorityUnavailable("invalid v2 deletion phase transition")
                phases[key] = phase
        return phases

    def has_deletion_history(self, namespace: str) -> bool:
        """Conservatively retain all closures, including physically closed ones."""
        return any(ns == namespace for ns, _ in self.latest_phases())

    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None


__all__ = ["AuthorityV2DeletionGuard"]
