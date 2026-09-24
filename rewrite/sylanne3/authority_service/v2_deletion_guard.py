"""Service-side writer freeze and verified v1-prefix/v2-tail deletion reader.

This does not issue deletion decisions or invoke graph callbacks. A separate
SQLite BEGIN IMMEDIATE on the *same file* waits for in-flight append/advance
and excludes another writer until the Authority transaction has committed.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
import threading

from .contract import AuthorityUnavailable, JournalHead
from .v2_contract import DeletionPendingV1, canonical_bytes, canonical_digest


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
_V2_TAIL_DDL_V2 = """CREATE TABLE authority_deletion_v2_tail(
    seq INTEGER PRIMARY KEY CHECK(seq > 0),
    schema TEXT NOT NULL CHECK(schema='sylanne3.deletion-tail.v2'),
    kind TEXT NOT NULL CHECK(kind='deletion'),
    append_id TEXT NOT NULL UNIQUE, mutation_id TEXT NOT NULL UNIQUE,
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
_TAIL_TRIGGERS_V2 = {
    "authority_deletion_v2_guarded_insert": "CREATE TRIGGER authority_deletion_v2_guarded_insert BEFORE INSERT ON authority_deletion_v2_tail BEGIN SELECT CASE WHEN authority_deletion_v2_append_allowed() != 1 THEN RAISE(ABORT,'v2 deletion append requires service guard') END; END",
    "authority_deletion_v2_no_update": _TAIL_TRIGGERS["authority_deletion_v2_no_update"],
    "authority_deletion_v2_no_delete": _TAIL_TRIGGERS["authority_deletion_v2_no_delete"],
}


@dataclass(frozen=True, slots=True)
class VerifiedDeletionAppendV2:
    seq: int
    append_id: str
    mutation_id: str
    digest: str


class AuthorityV2DeletionGuard:
    def __init__(self, path):
        self.path = Path(path)
        if not self.path.is_file():
            raise AuthorityUnavailable("independent deletion journal is absent")
        self._lock = threading.RLock()
        self._db = sqlite3.connect(f"file:{self.path.as_posix()}?mode=rw", uri=True,
                                   isolation_level=None, check_same_thread=False)
        # Schema 2 denies inserts on every connection until a future service
        # append implementation explicitly owns this connection's write guard.
        self._append_allowed = False
        self._db.create_function("authority_deletion_v2_append_allowed", 0,
                                 lambda: int(self._append_allowed))
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
        v2_schema2 = (v2 - {("trigger", "authority_deletion_v2_no_insert")}
                      | {("trigger", "authority_deletion_v2_guarded_insert")})
        if set(objects) not in (legacy, v2, v2_schema2):
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
        schema2 = set(objects) == v2_schema2
        expected_sql = {
            ("table", "authority_deletion_v2_meta"): _V2_META_DDL,
            ("table", "authority_deletion_v2_tail"): (_V2_TAIL_DDL_V2 if schema2 else _V2_TAIL_DDL),
            **{("trigger", name): ddl for name, ddl in
               {**_PREFIX_TRIGGERS, **(_TAIL_TRIGGERS_V2 if schema2 else _TAIL_TRIGGERS)}.items()},
        }
        if any(objects[key] != ddl for key, ddl in expected_sql.items()):
            raise AuthorityUnavailable("unsafe v2 deletion schema migration")
        values = dict(self._db.execute("SELECT key,value FROM authority_deletion_v2_meta"))
        if (set(values) != {"schema_version", "journal_id", "namespace", "cut_seq", "cut_digest"}
                or values["schema_version"] != ("2" if schema2 else "1")
                or values["journal_id"] != meta[0][1]
                or not values["namespace"]):
            raise AuthorityUnavailable("unknown v2 deletion metadata")
        try:
            cut_seq = int(values["cut_seq"])
        except ValueError as exc:
            raise AuthorityUnavailable("invalid v2 deletion cut sequence") from exc
        if cut_seq < 0 or str(cut_seq) != values["cut_seq"]:
            raise AuthorityUnavailable("invalid v2 deletion cut sequence")
        return "v2", meta[0][1], values

    def schema_version(self) -> int:
        if self._db is None or not self._db.in_transaction:
            raise AuthorityUnavailable("deletion schema query requires writer guard")
        kind, _, metadata = self._check_schema()
        if kind != "v2":
            raise AuthorityUnavailable("deletion journal has no v2 tail")
        return int(metadata["schema_version"])

    def require_target_schema_locked(self, authority_db, *, authority_id: str,
                                     namespace: str, journal_id: str) -> None:
        """Bind Authority's completed target marker to the guarded log schema."""
        if (self._db is None or not self._db.in_transaction
                or not authority_db.in_transaction):
            raise AuthorityUnavailable("deletion and Authority transactions required")
        kind, observed_journal_id, metadata = self._check_schema()
        version = int(metadata["schema_version"]) if kind == "v2" else None
        row = authority_db.execute(
            "SELECT value FROM authority_meta WHERE key='deletion_v2_tail_migration'").fetchone()
        if row is None:
            if version == 2:
                raise AuthorityUnavailable("schema-2 deletion tail lacks durable target marker")
            return
        try:
            marker = json.loads(row[0])
        except (TypeError, ValueError) as exc:
            raise AuthorityUnavailable("malformed deletion tail migration marker") from exc
        if (type(marker) is not dict or set(marker) != {
                "schema", "namespace", "authority_id", "journal_id", "before_seq",
                "before_digest", "target_version", "stage"}
                or marker["schema"] != "sylanne3.deletion-tail-migration.v2"
                or marker["target_version"] != 2 or marker["stage"] != "complete"
                or (marker["authority_id"], marker["namespace"], marker["journal_id"])
                   != (authority_id, namespace, journal_id)
                or observed_journal_id != journal_id or version != 2
                or metadata["namespace"] != namespace
                or type(marker["before_seq"]) is not int
                or marker["before_seq"] != int(metadata["cut_seq"])
                or marker["before_digest"] != metadata["cut_digest"]):
            raise AuthorityUnavailable("deletion schema rollback or migration mismatch")

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
                version = int(metadata["schema_version"])
                extra = "schema,kind,append_id," if version == 2 else ""
                for row in self._db.execute(
                    "SELECT seq," + extra + "mutation_id,request_digest,namespace,operation_id,phase,"
                    "subject,holder,token_digest,fence_epoch,revision,before_seq,before_digest,"
                    "evidence_digest,roots_json,epoch,policy_ref,prev_digest,chain_digest "
                    "FROM authority_deletion_v2_tail ORDER BY seq"):
                    if version == 2:
                        number, schema, event_kind, append_id, *rest = row
                        row = (number, *rest)
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
                    if version == 2:
                        if (schema != "sylanne3.deletion-tail.v2" or event_kind != "deletion"
                                or type(append_id) is not str or not append_id):
                            raise AuthorityUnavailable("v2 deletion tail event identity is malformed")
                        body.update(schema=schema, kind=event_kind, append_id=append_id)
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

    @staticmethod
    def _pending_body(pending: DeletionPendingV1) -> dict:
        if type(pending) is not DeletionPendingV1:
            raise AuthorityUnavailable("typed deletion pending is required")
        permit = pending.permit
        before = pending.before_anchor
        return dict(
            seq=pending.expected_deletion_seq,
            schema="sylanne3.deletion-tail.v2", kind="deletion",
            append_id=pending.expected_append_id,
            mutation_id=pending.mutation_id,
            request_digest=pending.request_digest,
            namespace=permit.namespace,
            operation_id=pending.deletion_operation_id,
            phase=pending.target_phase,
            subject=permit.subject, holder=permit.holder,
            token_digest="sha256:" + hashlib.sha256(permit.token.encode()).hexdigest(),
            fence_epoch=permit.fence_epoch, revision=permit.revision,
            before_seq=before.deletion_seq, before_digest=before.deletion_digest,
            evidence_digest=canonical_digest(pending.evidence),
            roots=list(pending.closure_roots), epoch=pending.deletion_epoch,
            policy_ref=pending.policy_ref, previous=before.deletion_digest,
        )

    @classmethod
    def expected_digest(cls, pending: DeletionPendingV1) -> str:
        body = cls._pending_body(pending)
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def _require_persisted_pending(self, pending, *, core, fences) -> None:
        """Read the live Authority ledger under deletion→Authority lock order."""
        from .v2_fence_store import AuthorityV2FenceStore
        from .core import AuthorityServiceCore

        if (type(pending) is not DeletionPendingV1
                or type(fences) is not AuthorityV2FenceStore
                or type(core) is not AuthorityServiceCore
                or core._db is not fences._db or core._lock is not fences._lock
                or self._db is None or not self._db.in_transaction
                or self.schema_version() != 2):
            raise AuthorityUnavailable("schema-2 guarded deletion pending is required")
        _, journal_id, metadata = self._check_schema()
        permit = pending.permit
        before = pending.before_anchor
        if (permit.namespace != metadata["namespace"]
                or pending.before_anchor.deletion_journal_id != journal_id
                or pending.expected_append_digest != self.expected_digest(pending)):
            raise AuthorityUnavailable("deletion append identity or digest differs")
        with fences._tx() as db:
            fences._check_schema(db)
            fences._require_no_migration(db)
            self.require_target_schema_locked(
                db, authority_id=core._id(db), namespace=permit.namespace,
                journal_id=journal_id)
            namespace_row = core._row(db, permit.namespace)
            if (core._id(db) != permit.authority_id
                    or core._anchor(db, permit.namespace, namespace_row) != before
                    or namespace_row[0] != permit.holder
                    or namespace_row[2] != "active" or namespace_row[9] != "clear"):
                raise AuthorityUnavailable("Authority deletion owner or anchor differs")
            row = fences._row(db, permit.operation_id)
            mutation = fences.mutation_locked(db, pending.mutation_id)
            if (row is None or row[6] != "active"
                    or fences._permit(row) != permit
                    or row[10] != canonical_bytes(pending)
                    or mutation is None or mutation[4] != "pending"
                    or mutation[9] != "deletion"):
                raise AuthorityUnavailable("deletion pending is not durably owned")
            kind, saved, receipt, updated = fences._decode_mutation_row(mutation)
            if (kind != "deletion" or saved != pending
                    or receipt is not None or updated is not None):
                raise AuthorityUnavailable("deletion ledger differs from requested append")

    def _inspect_pending_locked(self, pending: DeletionPendingV1):
        """Classify 0/1/>1 rows after full chain verification."""
        head = self.verified_head()
        before = pending.before_anchor
        if head.journal_id != before.deletion_journal_id:
            raise AuthorityUnavailable("deletion journal identity differs")
        if (head.seq, head.digest) == (before.deletion_seq, before.deletion_digest):
            return None
        if (head.seq, head.digest) != (pending.expected_deletion_seq,
                                       pending.expected_append_digest):
            raise AuthorityUnavailable("extra or mismatched deletion append; quarantine")
        row = self._db.execute(
            "SELECT schema,kind,append_id,mutation_id,request_digest,namespace,"
            "operation_id,phase,subject,holder,token_digest,fence_epoch,revision,"
            "before_seq,before_digest,evidence_digest,roots_json,epoch,policy_ref,"
            "prev_digest,chain_digest FROM authority_deletion_v2_tail WHERE seq=?",
            (pending.expected_deletion_seq,)).fetchone()
        body = self._pending_body(pending)
        expected = (
            body["schema"], body["kind"], body["append_id"], body["mutation_id"],
            body["request_digest"], body["namespace"], body["operation_id"],
            body["phase"], body["subject"], body["holder"], body["token_digest"],
            body["fence_epoch"], body["revision"], body["before_seq"],
            body["before_digest"], body["evidence_digest"],
            json.dumps(body["roots"], separators=(",", ":"), ensure_ascii=True),
            body["epoch"], body["policy_ref"], body["previous"],
            pending.expected_append_digest)
        if row != expected:
            raise AuthorityUnavailable("deletion append fields differ; quarantine")
        return VerifiedDeletionAppendV2(
            pending.expected_deletion_seq, pending.expected_append_id,
            pending.mutation_id, pending.expected_append_digest)

    def inspect_pending(self, pending: DeletionPendingV1, *, core, fences):
        with self.freeze_writes():
            self._require_persisted_pending(pending, core=core, fences=fences)
            return self._inspect_pending_locked(pending)

    def append_pending(self, pending: DeletionPendingV1, *, core, fences):
        """One FULL-WAL append; Authority pending must already be durable."""
        with self.freeze_writes():
            self._require_persisted_pending(pending, core=core, fences=fences)
            existing = self._inspect_pending_locked(pending)
            if existing is not None:
                return existing
            body = self._pending_body(pending)
            self._append_allowed = True
            try:
                self._db.execute(
                    "INSERT INTO authority_deletion_v2_tail VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (body["seq"], body["schema"], body["kind"], body["append_id"],
                     body["mutation_id"], body["request_digest"], body["namespace"],
                     body["operation_id"], body["phase"], body["subject"],
                     body["holder"], body["token_digest"], body["fence_epoch"],
                     body["revision"], body["before_seq"], body["before_digest"],
                     body["evidence_digest"],
                     json.dumps(body["roots"], separators=(",", ":"), ensure_ascii=True),
                     body["epoch"], body["policy_ref"], body["previous"],
                     pending.expected_append_digest))
            finally:
                self._append_allowed = False
            return self._inspect_pending_locked(pending)

    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None


__all__ = ["AuthorityV2DeletionGuard"]
