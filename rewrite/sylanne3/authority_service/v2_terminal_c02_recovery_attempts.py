"""Durable, content-free terminal C02 recovery read attempts.

The future Authority read service must run current graph, fence and transport
checks before invoking these locked methods. This ledger never reads bodies.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import json
import sqlite3
import threading

from ..runtime.first_ingress_c02_identity import first_ingress_c02_consumer_operation_id_v1
from ..runtime_contracts import canonical_digest, canonical_serialize
from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2
from .v2_terminal_c02_recovery_contract import (
    TerminalRecoveryReadAttemptV1, TerminalRecoveryReadFactV1,
    TerminalRecoveryReadRequestV1, from_wire, to_wire,
)


_DDL = """CREATE TABLE authority_terminal_c02_read_attempts_v1(
    read_attempt_id TEXT PRIMARY KEY,
    consumer_operation_id TEXT NOT NULL UNIQUE,
    request_json TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    permit_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','finished')),
    result_digest TEXT,
    handoff_digest TEXT,
    CHECK((state='active' AND result_digest IS NULL AND handoff_digest IS NULL)
       OR (state='finished' AND result_digest IS NOT NULL AND handoff_digest IS NOT NULL))
)"""


class AuthorityV2TerminalC02RecoveryAttempts:
    """One immutable attempt identity per business C02 operation."""

    def __init__(self, connection: sqlite3.Connection, *, create: bool = False,
                 lock: threading.RLock | None = None):
        if type(connection) is not sqlite3.Connection or connection.isolation_level is not None:
            raise AuthorityUnavailable("terminal C02 attempts need an autocommit Authority connection")
        path = connection.execute("PRAGMA database_list").fetchone()[2]
        synchronous = connection.execute("PRAGMA synchronous").fetchone()[0]
        journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
        if not path or synchronous < 2 or journal.lower() in {"off", "memory"}:
            raise AuthorityUnavailable("terminal C02 attempts require durable Authority SQLite")
        self._db = connection
        self._lock = lock if lock is not None else threading.RLock()
        with self._tx() as db:
            row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' "
                             "AND name='authority_terminal_c02_read_attempts_v1'").fetchone()
            if row is None:
                if not create:
                    raise AuthorityUnavailable("terminal C02 attempt schema is absent")
                db.execute(_DDL)
            elif row != (_DDL,):
                raise AuthorityUnavailable("unknown terminal C02 attempt schema")

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
                raise AuthorityUnavailable("terminal C02 attempt transaction failed") from exc

    def _require_tx(self, db: sqlite3.Connection) -> None:
        if db is not self._db or not db.in_transaction:
            raise AuthorityUnavailable("same Authority transaction required")

    @staticmethod
    def _stable_operation(request: TerminalRecoveryReadRequestV1) -> str:
        key = request.original_key
        return first_ingress_c02_consumer_operation_id_v1(
            namespace=key.namespace, authority_id=key.authority_id,
            authority_namespace=key.authority_namespace,
            installation_id=key.installation_id, job_id=key.job_id,
            acquire_operation_id=key.acquire_operation_id,
            original_operation_id=key.original_operation_id,
            call_id=key.call_id, binding_digest=key.binding_digest,
            model_request_digest=key.model_request_digest,
        )

    @staticmethod
    def _permit_digest(request: TerminalRecoveryReadRequestV1,
                       permit: FencePermitV2) -> str:
        key = request.original_key
        if (type(permit) is not FencePermitV2 or permit.operation != "read"
                or (permit.authority_id, permit.namespace, permit.operation_id)
                != (key.authority_id, key.authority_namespace,
                    request.read_attempt_id)
                or permit.generation != permit.pinned_anchor.activation_generation):
            raise AuthorityUnavailable("terminal C02 attempt requires its current read fence")
        return canonical_digest(asdict(permit))

    def _read_locked(self, db: sqlite3.Connection, attempt_id: str):
        self._require_tx(db)
        row = db.execute(
            "SELECT consumer_operation_id,request_json,request_digest,permit_digest,"
            "state,result_digest,handoff_digest FROM authority_terminal_c02_read_attempts_v1 "
            "WHERE read_attempt_id=?", (attempt_id,),
        ).fetchone()
        if row is None:
            return None, None
        try:
            request = from_wire(json.loads(row[1]), TerminalRecoveryReadRequestV1)
            if (request.read_attempt_id != attempt_id
                    or request.consumer_operation_id != row[0]
                    or request.consumer_operation_id != self._stable_operation(request)
                    or request.digest != row[2]
                    or row[1] != canonical_serialize(to_wire(request))
                    or row[4] not in {"active", "finished"}):
                raise ValueError("terminal C02 attempt identity differs")
            attempt = TerminalRecoveryReadAttemptV1(request, row[3], row[4], row[5])
            if row[4] == "active":
                if row[6] is not None:
                    raise ValueError("active terminal C02 handoff differs")
                return attempt, None
            fact = TerminalRecoveryReadFactV1(request, row[3], row[5], row[6])
            return attempt, fact
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityUnavailable("terminal C02 attempt record differs") from exc

    def read(self, request: TerminalRecoveryReadRequestV1):
        """Query an exact attempt after restart; returns no provider content."""
        if type(request) is not TerminalRecoveryReadRequestV1:
            raise TypeError("typed terminal C02 read request required")
        with self._tx() as db:
            attempt, fact = self._read_locked(db, request.read_attempt_id)
            if attempt is not None and attempt.request != request:
                raise AuthorityUnavailable("terminal C02 read attempt identity conflict")
            return attempt, fact

    def begin_locked(self, db: sqlite3.Connection, request: TerminalRecoveryReadRequestV1,
                     *, permit: FencePermitV2):
        """Bind a checked read fence; caller must first prove current eligibility."""
        self._require_tx(db)
        if type(request) is not TerminalRecoveryReadRequestV1:
            raise TypeError("typed terminal C02 read request required")
        permit_digest = self._permit_digest(request, permit)
        if request.consumer_operation_id != self._stable_operation(request):
            raise AuthorityUnavailable("terminal C02 business operation differs")
        existing = db.execute(
            "SELECT read_attempt_id FROM authority_terminal_c02_read_attempts_v1 "
            "WHERE consumer_operation_id=?", (request.consumer_operation_id,),
        ).fetchone()
        if existing is not None and existing[0] != request.read_attempt_id:
            raise AuthorityUnavailable("terminal C02 operation already has a read attempt")
        attempt, _ = self._read_locked(db, request.read_attempt_id)
        if attempt is not None:
            if attempt.request != request or attempt.permit_digest != permit_digest:
                raise AuthorityUnavailable("terminal C02 read attempt identity conflict")
            if attempt.state == "finished":
                raise AuthorityUnavailable("finished terminal C02 handoff cannot reopen")
            return attempt
        db.execute(
            "INSERT INTO authority_terminal_c02_read_attempts_v1 "
            "(read_attempt_id,consumer_operation_id,request_json,request_digest,"
            "permit_digest,state,result_digest,handoff_digest) "
            "VALUES(?,?,?,?,?,'active',NULL,NULL)",
            (request.read_attempt_id, request.consumer_operation_id,
             canonical_serialize(to_wire(request)), request.digest, permit_digest),
        )
        return TerminalRecoveryReadAttemptV1(request, permit_digest, "active", None)

    def finish_locked(self, db: sqlite3.Connection, request: TerminalRecoveryReadRequestV1,
                      *, permit: FencePermitV2, handoff_digest: str):
        """Record a trusted transport completion in the Authority transaction.

        The future service must verify the original body, drain its response,
        and finish the read fence in this same transaction before calling here.
        """
        self._require_tx(db)
        if type(request) is not TerminalRecoveryReadRequestV1:
            raise TypeError("typed terminal C02 read request required")
        permit_digest = self._permit_digest(request, permit)
        result_digest = request.original_key.stable_result_digest
        fact = TerminalRecoveryReadFactV1(
            request, permit_digest, result_digest, handoff_digest,
        )
        attempt, prior = self._read_locked(db, request.read_attempt_id)
        if (attempt is None or attempt.request != request
                or attempt.permit_digest != permit_digest):
            raise AuthorityUnavailable("terminal C02 read attempt identity conflict")
        if prior is not None:
            if prior == fact:
                return fact
            raise AuthorityUnavailable("terminal C02 handoff digest conflict")
        changed = db.execute(
            "UPDATE authority_terminal_c02_read_attempts_v1 "
            "SET state='finished',result_digest=?,handoff_digest=? "
            "WHERE read_attempt_id=? AND state='active' AND request_digest=?",
            (result_digest, handoff_digest, request.read_attempt_id, request.digest),
        ).rowcount
        if changed != 1:
            raise AuthorityUnavailable("terminal C02 handoff finish lost CAS")
        return fact


__all__ = ("AuthorityV2TerminalC02RecoveryAttempts",)
