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
    WorkerModelResultReadRequestV1, SCHEMA as MODEL_READ_SCHEMA, from_wire, to_wire,
)
from .v2_reply_worker_model_result_contract import (
    ReplyWorkerModelResultReadRequestV1,
    SCHEMA as REPLY_READ_SCHEMA,
    from_wire as reply_from_wire, to_wire as reply_to_wire,
)
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.d11_artifact_draft_contract_v1 import DraftObservationReadRequestV1, draft_from_wire_v1, draft_to_wire_v1
from .d11_artifact_draft_model_v1 import (ArtifactDraftModelResultReadRequestV1,
    artifact_draft_model_result_from_wire_v1,artifact_draft_model_result_to_wire_v1)


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
    request: WorkerModelResultReadRequestV1 | ReplyWorkerModelResultReadRequestV1 | DraftObservationReadRequestV1 | ArtifactDraftModelResultReadRequestV1
    permit_digest: str
    state: str
    result_digest: str | None


READ_ATTEMPT_COLUMNS_V1 = (
    "read_attempt_id", "consumer_operation_id", "request_json",
    "request_digest", "permit_digest", "state", "result_digest",
)


def require_worker_result_read_attempt_schema_v1(db: sqlite3.Connection) -> None:
    """Recognize the installed table without creating or migrating it."""
    if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                  ("authority_worker_result_read_attempts_v1",)).fetchone() != (_DDL,):
        raise AuthorityUnavailable("unknown worker result attempt schema")


def validate_worker_result_read_attempt_row_v1(
    columns: tuple[str, ...], row: tuple,
) -> WorkerModelResultReadAttemptV1:
    """Decode only the four registered request variants and their exact row."""
    if columns != READ_ATTEMPT_COLUMNS_V1 or len(row) != len(columns):
        raise AuthorityUnavailable("worker result attempt columns differ")
    try:
        raw = json.loads(row[2])
        if type(raw) is not dict:
            raise ValueError("worker read request is malformed")
        if raw.get("schema") == "d11.artifact-draft-model-result-read.v1":
            request=artifact_draft_model_result_from_wire_v1(raw,ArtifactDraftModelResultReadRequestV1)
            encoded=artifact_draft_model_result_to_wire_v1(request)
        elif raw.get("schema") == "d11.draft-observation-read-request.v1":
            request = draft_from_wire_v1(raw, DraftObservationReadRequestV1)
            encoded = draft_to_wire_v1(request)
        elif raw.get("schema") == REPLY_READ_SCHEMA:
            request = reply_from_wire(raw, ReplyWorkerModelResultReadRequestV1)
            encoded = reply_to_wire(request)
        elif raw.get("schema") == MODEL_READ_SCHEMA:
            request = from_wire(raw, WorkerModelResultReadRequestV1)
            encoded = to_wire(request)
        else:
            raise ValueError("unregistered worker read request schema")
        if (request.read_attempt_id != row[0]
                or request.consumer_operation_id != row[1]
                or request.digest != row[3]
                or row[2] != canonical_serialize(encoded)
                or type(row[4]) is not str or len(row[4]) != 64
                or any(c not in "0123456789abcdef" for c in row[4])
                or row[5] not in {"active", "finished"}
                or (row[5] == "active") != (row[6] is None)):
            raise ValueError("attempt identity differs")
        if row[6] is not None and (type(row[6]) is not str or len(row[6]) != 64
                                  or any(c not in "0123456789abcdef" for c in row[6])):
            raise ValueError("invalid stored result digest")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AuthorityUnavailable("worker result attempt record differs") from exc
    return WorkerModelResultReadAttemptV1(request, row[4], row[5], row[6])


def require_worker_result_read_attempt_fence_v1(
    db: sqlite3.Connection, *, attempt: WorkerModelResultReadAttemptV1,
    authority_id: str, authority_namespace: str, installation_id: str,
) -> FencePermitV2:
    """Join a current cohort attempt to its real frozen Core read fence.

    This verifies originals for C09 classification; it grants neither a read
    nor retention and does not recover a result body or its cost from a digest.
    """
    from .v2_fence_store import AuthorityV2FenceStore
    from .v2_contract import canonical_bytes
    request = attempt.request
    if (request.authority_id, request.authority_namespace, request.installation_id) != (
            authority_id, authority_namespace, installation_id):
        raise AuthorityUnavailable("worker result attempt cohort differs")
    fence_row = AuthorityV2FenceStore._row(db, request.read_attempt_id)
    if fence_row is None:
        raise AuthorityUnavailable("worker result attempt original read fence absent")
    permit = AuthorityV2FenceStore._permit(fence_row)
    if (permit.operation != "read" or permit.authority_id != authority_id
            or permit.namespace != authority_namespace
            or permit.operation_id != request.read_attempt_id
            or canonical_bytes(permit) != fence_row[7]
            or canonical_digest(asdict(permit)) != attempt.permit_digest
            or fence_row[6] not in {"active", "finished"}
            or fence_row[10] is not None):
        raise AuthorityUnavailable("worker result attempt original permit differs")
    if type(request) is DraftObservationReadRequestV1:
        if (request.request.current_read_permit_ref != permit.operation_id
                or request.request.current_read_permit_digest != attempt.permit_digest
                or attempt.state != fence_row[6]
                or attempt.state == "finished" and (
                    fence_row[8] != request.read_attempt_id + ":observed"
                    or fence_row[9] != "sha256:" + attempt.result_digest)):
            raise AuthorityUnavailable("draft observation attempt/fence result differs")
    elif type(request) is ArtifactDraftModelResultReadRequestV1:
        if (attempt.state!=fence_row[6] or attempt.state=="finished" and
                (fence_row[8]!=request.read_attempt_id+":delivered" or fence_row[9]!="sha256:"+attempt.result_digest)):
            raise AuthorityUnavailable("C4 actual result-read attempt/fence finish differs")
    return permit


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
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                      ("authority_c09_consumed_execution_v1",)).fetchone() is not None:
            if db.execute("SELECT 1 FROM authority_c09_consumed_execution_v1 "
                          "WHERE kind='worker_result_read_attempt' AND item_id=? LIMIT 1",
                          (attempt_id,)).fetchone() is not None:
                raise AuthorityUnavailable("C09 retired worker read attempt cannot reopen")
        row = db.execute(
            "SELECT read_attempt_id,consumer_operation_id,request_json,request_digest,permit_digest,state,result_digest "
            "FROM authority_worker_result_read_attempts_v1 WHERE read_attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if row is None:
            return None
        return validate_worker_result_read_attempt_row_v1(READ_ATTEMPT_COLUMNS_V1, row)

    @staticmethod
    def _permit_digest(request: WorkerModelResultReadRequestV1 |
                       ReplyWorkerModelResultReadRequestV1 | DraftObservationReadRequestV1,
                       permit: FencePermitV2) -> str:
        if (type(permit) is not FencePermitV2 or permit.operation != "read"
                or (permit.authority_id, permit.namespace, permit.operation_id) !=
                   (request.authority_id, request.authority_namespace,
                    request.read_attempt_id)):
            raise AuthorityUnavailable("worker read attempt requires its original read fence")
        return canonical_digest(asdict(permit))

    def read(self, request: WorkerModelResultReadRequestV1 |
             ReplyWorkerModelResultReadRequestV1 | DraftObservationReadRequestV1):
        if type(request) not in {WorkerModelResultReadRequestV1,
                                ReplyWorkerModelResultReadRequestV1, DraftObservationReadRequestV1,ArtifactDraftModelResultReadRequestV1}:
            raise TypeError("typed worker read request required")
        with self._tx() as db:
            record = self._read_locked(db, request.read_attempt_id)
            if record is not None and record.request != request:
                raise AuthorityUnavailable("worker read attempt identity conflict")
            return record

    def begin(self, request: WorkerModelResultReadRequestV1 |
              ReplyWorkerModelResultReadRequestV1 | DraftObservationReadRequestV1, *, permit: FencePermitV2):
        with self._tx() as db:
            return self.begin_locked(db, request, permit=permit)

    def begin_locked(self, db: sqlite3.Connection,
                     request: WorkerModelResultReadRequestV1 |
                     ReplyWorkerModelResultReadRequestV1 | DraftObservationReadRequestV1,
                     *, permit: FencePermitV2):
        """Bind an attempt; service must revalidate current eligibility first."""
        self._require_tx(db)
        if type(request) not in {WorkerModelResultReadRequestV1,
                                ReplyWorkerModelResultReadRequestV1, DraftObservationReadRequestV1,ArtifactDraftModelResultReadRequestV1}:
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
                artifact_draft_model_result_to_wire_v1(request) if type(request) is ArtifactDraftModelResultReadRequestV1 else
                draft_to_wire_v1(request) if type(request) is DraftObservationReadRequestV1 else
                 reply_to_wire(request) if type(request) is ReplyWorkerModelResultReadRequestV1
                 else to_wire(request)), request.digest, permit_digest),
        )
        return WorkerModelResultReadAttemptV1(request, permit_digest, "active", None)

    def finish(self, request: WorkerModelResultReadRequestV1 |
               ReplyWorkerModelResultReadRequestV1 | DraftObservationReadRequestV1, *, permit: FencePermitV2,
               result_digest: str):
        with self._tx() as db:
            return self.finish_locked(db, request, permit=permit,
                                      result_digest=result_digest)

    def finish_locked(self, db: sqlite3.Connection,
                      request: WorkerModelResultReadRequestV1 |
                      ReplyWorkerModelResultReadRequestV1 | DraftObservationReadRequestV1,
                      *, permit: FencePermitV2, result_digest: str):
        """Close only the exact active attempt; stores a digest, never the body."""
        self._require_tx(db)
        if type(request) not in {WorkerModelResultReadRequestV1,
                                ReplyWorkerModelResultReadRequestV1, DraftObservationReadRequestV1,ArtifactDraftModelResultReadRequestV1}:
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


__all__ = ("AuthorityV2WorkerModelResultAttempts", "WorkerModelResultReadAttemptV1",
           "READ_ATTEMPT_COLUMNS_V1", "require_worker_result_read_attempt_schema_v1",
           "validate_worker_result_read_attempt_row_v1", "require_worker_result_read_attempt_fence_v1")
