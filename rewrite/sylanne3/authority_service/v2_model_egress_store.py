"""Authority-local passive egress ledger; never executes or authorizes a send."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import json
import sqlite3
import threading

from .contract import AuthorityUnavailable, identifier
from .v2_model_egress_contract import ModelEgressIntentV1, ModelEgressRecoveryV1


_DDL = """CREATE TABLE authority_model_egress_v1(
    call_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL,
    namespace TEXT NOT NULL, subject TEXT NOT NULL,
    identity_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('prepared','dispatch_started','observed','unknown')),
    observation_digest TEXT,
    CHECK((state IN ('prepared','dispatch_started') AND observation_digest IS NULL)
       OR (state IN ('observed','unknown') AND observation_digest IS NOT NULL))
)"""


def _encoded(intent: ModelEgressIntentV1) -> str:
    return json.dumps(asdict(intent), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _decoded(value: str) -> ModelEgressIntentV1:
    data = json.loads(value)
    if type(data) is not dict or set(data) != set(ModelEgressIntentV1.__dataclass_fields__):
        raise ValueError("egress identity fields changed")
    data["source_refs"] = tuple(data["source_refs"])
    data["source_revisions"] = tuple(tuple(item) for item in data["source_revisions"])
    data["access_revisions"] = tuple(tuple(item) for item in data["access_revisions"])
    data["budget_ceiling"] = tuple(tuple(item) for item in data["budget_ceiling"])
    result = ModelEgressIntentV1(**data)
    if _encoded(result) != value:
        raise ValueError("noncanonical egress identity")
    return result


class AuthorityV2ModelEgressStore:
    """Transactionally records identity and a one-way send marker.

    `record_dispatch_started` is an internal persistence primitive for a future
    executor. It must be called only after independent current graph and fence
    checks. No production service currently exposes that executor.
    """

    def __init__(self, connection: sqlite3.Connection, *, create: bool = False,
                 lock: threading.RLock | None = None):
        if type(connection) is not sqlite3.Connection or connection.isolation_level is not None:
            raise AuthorityUnavailable("model egress needs an autocommit Authority SQLite connection")
        path = connection.execute("PRAGMA database_list").fetchone()[2]
        synchronous = connection.execute("PRAGMA synchronous").fetchone()[0]
        journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
        if not path or synchronous < 2 or journal.lower() in {"off", "memory"}:
            raise AuthorityUnavailable("model egress requires durable Authority SQLite settings")
        self._db = connection
        self._lock = lock if lock is not None else threading.RLock()
        with self._tx() as db:
            existing = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='authority_model_egress_v1'"
            ).fetchone()
            if existing is None:
                if not create:
                    raise AuthorityUnavailable("model egress schema is absent")
                db.execute(_DDL)
            elif existing != (_DDL,):
                raise AuthorityUnavailable("unknown model egress schema")

    @contextmanager
    def _tx(self):
        with self._lock:
            if self._db.in_transaction:
                raise AuthorityUnavailable("model egress connection already has a transaction")
            try:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    yield self._db
                    self._db.execute("COMMIT")
                except BaseException:
                    self._db.execute("ROLLBACK")
                    raise
            except sqlite3.Error as exc:
                raise AuthorityUnavailable("model egress SQLite transaction failed") from exc

    @staticmethod
    def _read(db, call_id: str) -> ModelEgressRecoveryV1 | None:
        row = db.execute(
            "SELECT call_id,operation_id,namespace,subject,identity_json,state,observation_digest "
            "FROM authority_model_egress_v1 WHERE call_id=?", (call_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            intent = _decoded(row[4])
            if row[:4] != (intent.call_id, intent.operation_id, intent.namespace, intent.subject):
                raise ValueError("persisted egress identity mismatch")
            return ModelEgressRecoveryV1(intent, row[5], row[6])
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityUnavailable("persisted model egress record is invalid") from exc

    def prepare(self, intent: ModelEgressIntentV1) -> ModelEgressRecoveryV1:
        if type(intent) is not ModelEgressIntentV1:
            raise AuthorityUnavailable("typed model egress intent required")
        with self._tx() as db:
            old = self._read(db, intent.call_id)
            if old is not None:
                if old.intent != intent:
                    raise AuthorityUnavailable("model call ID reused with different identity")
                return old
            db.execute(
                "INSERT INTO authority_model_egress_v1 "
                "(call_id,operation_id,namespace,subject,identity_json,state) "
                "VALUES(?,?,?,?,?,'prepared')",
                (intent.call_id, intent.operation_id, intent.namespace,
                 intent.subject, _encoded(intent)),
            )
            return ModelEgressRecoveryV1(intent, "prepared")

    def read(self, call_id: str, *, subject: str, namespace: str) -> ModelEgressRecoveryV1:
        identifier(call_id, "call_id")
        identifier(subject, "subject")
        identifier(namespace, "namespace")
        with self._tx() as db:
            record = self._read(db, call_id)
            if record is None or (record.intent.subject, record.intent.namespace) != (subject, namespace):
                raise AuthorityUnavailable("model egress unavailable for subject or namespace")
            return record

    def _transition(self, intent: ModelEgressIntentV1, state: str,
                    observation_digest: str | None = None) -> ModelEgressRecoveryV1:
        target = ModelEgressRecoveryV1(intent, state, observation_digest)
        with self._tx() as db:
            old = self._read(db, intent.call_id)
            if old is None or old.intent != intent:
                raise AuthorityUnavailable("model egress identity changed or absent")
            expected = "prepared" if state == "dispatch_started" else "dispatch_started"
            if old.state != expected:
                raise AuthorityUnavailable("model egress transition cannot repeat or reverse")
            updated = db.execute(
                "UPDATE authority_model_egress_v1 SET state=?,observation_digest=? "
                "WHERE call_id=? AND state=? AND identity_json=?",
                (state, observation_digest, intent.call_id, expected, _encoded(intent)),
            )
            if updated.rowcount != 1:
                raise AuthorityUnavailable("model egress transition lost its exact identity")
            return target

    def record_dispatch_started(self, intent: ModelEgressIntentV1) -> ModelEgressRecoveryV1:
        """Commit before any future send; no second caller can cross this boundary."""
        return self._transition(intent, "dispatch_started")

    def record_observed(self, intent: ModelEgressIntentV1, *,
                        observation_digest: str) -> ModelEgressRecoveryV1:
        return self._transition(intent, "observed", observation_digest)

    def record_unknown(self, intent: ModelEgressIntentV1, *,
                       observation_digest: str) -> ModelEgressRecoveryV1:
        return self._transition(intent, "unknown", observation_digest)


__all__ = ["AuthorityV2ModelEgressStore"]
