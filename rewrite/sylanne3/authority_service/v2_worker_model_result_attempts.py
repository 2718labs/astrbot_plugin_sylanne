"""Durable, content-free identity binding for worker result read attempts.

This ledger does not grant a read or replace Authority fences. Its locked calls
join the service's existing Authority SQLite transaction after fresh checks.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import json
import sqlite3
import threading

from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2
from .v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, from_wire, to_wire,
)
from .v2_reply_worker_model_result_contract import (
    ReplyWorkerModelResultReadRequestV1,
    SCHEMA as REPLY_READ_SCHEMA,
    from_wire as reply_from_wire, to_wire as reply_to_wire,
)
from ..runtime_contracts import canonical_digest, canonical_serialize


_DDL = """CREATE TABLE authority_worker_result_read_attempts_v1(
    read_attempt_id TEXT PRIMARY KEY,
    consumer_operation_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    permit_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','finished')),
    result_digest TEXT,
    CHECK((state='active' AND result_digest IS NULL)
       OR (state='finished' AND result_digest IS NOT NULL))
)"""


@dataclass(frozen=True, slots=True)
class WorkerModelResultReadAttemptV1:
    request: WorkerModelResultReadRequestV1 | ReplyWorkerModelResultReadRequestV1
    permit_digest: str
    state: str
    result_digest: str | None


class AuthorityV2WorkerModelResultAttempts:
    """Stores stable consumer attempt identity in the Authority database."""

    def __init__(self, connection: sqlite3.Connection, *, create: bool = False,
                 lock: threading.RLock | None = None):
        if type(connection) is not sqlite3.Connection or connection.isolation_level is not None:
            raise AuthorityUnavailable("worker result attempts need an autocommit Authority connection")
        path = connection.execute("PRAGMA database_list").fetchone()[2]
        synchronous = connection.execute("PRAGMA synchronous").fetchone()[0]
        journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
        if not path or synchronous < 2 or journal.lower() in {"off", "memory"}:
            raise AuthorityUnavailable("worker result attempts require durable Authority SQLite")
        self._db = connection
        self._lock = lock if lock is not None else threading.RLock()
        with self._tx() as db:
            row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' "
                             "AND name='authority_worker_result_read_attempts_v1'").fetchone()
            if row is None:
                if not create:
                    raise AuthorityUnavailable("worker result attempt schema is absent")
                db.execute(_DDL)
            elif row != (_DDL,):
                raise AuthorityUnavailable("unknown worker result attempt schema")

    @contextmanager
    def _tx(self):
        with self._lock:
            if self._db.in_transaction:
                raise AuthorityUnavailable("Authority connection already has a transaction")
            try:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    yield self._db
                    self._db.execute("COMMIT")
                except BaseException:
                    self._db.execute("ROLLBACK")
                    raise
            except sqlite3.Error as exc:
                raise AuthorityUnavailable("worker result attempt transaction failed") from exc

    def _require_tx(self, db: sqlite3.Connection) -> None:
        if db is not self._db or not db.in_transaction:
            raise AuthorityUnavailable("same Authority transaction required")

    def _read_locked(self, db, attempt_id: str):
        row = db.execute(
            "SELECT consumer_operation_id,request_json,request_digest,permit_digest,state,result_digest "
            "FROM authority_worker_result_read_attempts_v1 WHERE read_attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            raw = json.loads(row[1])
            if type(raw) is not dict:
                raise ValueError("worker read request is malformed")
            if raw.get("schema") == REPLY_READ_SCHEMA:
                request = reply_from_wire(raw, ReplyWorkerModelResultReadRequestV1)
                encoded = reply_to_wire(request)
            else:
                request = from_wire(raw, WorkerModelResultReadRequestV1)
                encoded = to_wire(request)
            if (request.read_attempt_id != attempt_id
                    or request.consumer_operation_id != row[0]
                    or request.digest != row[2]
                    or row[1] != canonical_serialize(encoded)
                    or type(row[3]) is not str or len(row[3]) != 64
                    or any(c not in "0123456789abcdef" for c in row[3])
                    or row[4] not in {"active", "finished"}
                    or (row[4] == "active") != (row[5] is None)):
                raise ValueError("attempt identity differs")
            if row[5] is not None and (type(row[5]) is not str or len(row[5]) != 64
                                       or any(c not in "0123456789abcdef" for c in row[5])):
                raise ValueError("invalid stored result digest")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityUnavailable("worker result attempt record differs") from exc
        return WorkerModelResultReadAttemptV1(request, row[3], row[4], row[5])

    @staticmethod
    def _permit_digest(request: WorkerModelResultReadRequestV1 |
                       ReplyWorkerModelResultReadRequestV1,
                       permit: FencePermitV2) -> str:
        if (type(permit) is not FencePermitV2 or permit.operation != "read"
                or (permit.authority_id, permit.namespace, permit.operation_id) !=
                   (request.authority_id, request.authority_namespace,
                    request.read_attempt_id)):
            raise AuthorityUnavailable("worker read attempt requires its original read fence")
        return canonical_digest(asdict(permit))

    def read(self, request: WorkerModelResultReadRequestV1 |
             ReplyWorkerModelResultReadRequestV1):
        if type(request) not in {WorkerModelResultReadRequestV1,
                                ReplyWorkerModelResultReadRequestV1}:
            raise TypeError("typed worker read request required")
        with self._tx() as db:
            record = self._read_locked(db, request.read_attempt_id)
            if record is not None and record.request != request:
                raise AuthorityUnavailable("worker read attempt identity conflict")
            return record

    def begin(self, request: WorkerModelResultReadRequestV1 |
              ReplyWorkerModelResultReadRequestV1, *, permit: FencePermitV2):
        with self._tx() as db:
            return self.begin_locked(db, request, permit=permit)

    def begin_locked(self, db: sqlite3.Connection,
                     request: WorkerModelResultReadRequestV1 |
                     ReplyWorkerModelResultReadRequestV1,
                     *, permit: FencePermitV2):
        """Bind an attempt; service must revalidate current eligibility first."""
        self._require_tx(db)
        if type(request) not in {WorkerModelResultReadRequestV1,
                                ReplyWorkerModelResultReadRequestV1}:
            raise TypeError("typed worker read request required")
        permit_digest = self._permit_digest(request, permit)
        record = self._read_locked(db, request.read_attempt_id)
        if record is not None:
            if record.request != request or record.permit_digest != permit_digest:
                raise AuthorityUnavailable("worker read attempt identity conflict")
            if record.state == "finished":
                raise AuthorityUnavailable("finished worker read attempt cannot reopen")
            return record
        db.execute(
            "INSERT INTO authority_worker_result_read_attempts_v1 "
            "(read_attempt_id,consumer_operation_id,request_json,request_digest,permit_digest,state,result_digest) "
            "VALUES(?,?,?,?,?,'active',NULL)",
            (request.read_attempt_id, request.consumer_operation_id,
             canonical_serialize(
                 reply_to_wire(request) if type(request) is ReplyWorkerModelResultReadRequestV1
                 else to_wire(request)), request.digest, permit_digest),
        )
        return WorkerModelResultReadAttemptV1(request, permit_digest, "active", None)

    def finish(self, request: WorkerModelResultReadRequestV1 |
               ReplyWorkerModelResultReadRequestV1, *, permit: FencePermitV2,
               result_digest: str):
        with self._tx() as db:
            return self.finish_locked(db, request, permit=permit,
                                      result_digest=result_digest)

    def finish_locked(self, db: sqlite3.Connection,
                      request: WorkerModelResultReadRequestV1 |
                      ReplyWorkerModelResultReadRequestV1,
                      *, permit: FencePermitV2, result_digest: str):
        """Close only the exact active attempt; stores a digest, never the body."""
        self._require_tx(db)
        if type(request) not in {WorkerModelResultReadRequestV1,
                                ReplyWorkerModelResultReadRequestV1}:
            raise TypeError("typed worker read request required")
        permit_digest = self._permit_digest(request, permit)
        if (type(result_digest) is not str or len(result_digest) != 64
                or any(c not in "0123456789abcdef" for c in result_digest)):
            raise ValueError("invalid worker result digest")
        record = self._read_locked(db, request.read_attempt_id)
        if (record is None or record.request != request
                or record.permit_digest != permit_digest):
            raise AuthorityUnavailable("worker read attempt identity conflict")
        if record.state == "finished":
            if record.result_digest == result_digest:
                return result_digest
            raise AuthorityUnavailable("worker read result digest conflict")
        changed = db.execute(
            "UPDATE authority_worker_result_read_attempts_v1 "
            "SET state='finished',result_digest=? "
            "WHERE read_attempt_id=? AND state='active' AND request_digest=?",
            (result_digest, request.read_attempt_id, request.digest),
        ).rowcount
        if changed != 1:
            raise AuthorityUnavailable("worker read attempt finish lost CAS")
        return result_digest


__all__ = ("AuthorityV2WorkerModelResultAttempts", "WorkerModelResultReadAttemptV1")
