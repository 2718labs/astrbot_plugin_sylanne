"""Durable first-owner ticket and issue-pending records in Authority SQLite.

This is an Authority-side storage slice, not an owner grant issuer. The caller
must install independent first-creation and claimant verifiers. No callback is
provided here, and no permission becomes active when an issue is reserved.
The graph remains the sole business grant store.
"""

from __future__ import annotations

from datetime import datetime, timezone
import sqlite3
from time import monotonic
from typing import Callable

from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerAuthorizationReceiptV1, OwnerClaimTicketV1, canonical_bytes,
    decode_bytes,
)
from ..graph_coordinator import namespace_ref


_TICKETS = """CREATE TABLE authority_owner_claim_tickets_v1 (
    authority_namespace TEXT PRIMARY KEY,
    ticket_id TEXT NOT NULL UNIQUE,
    ticket_bytes BLOB NOT NULL,
    issue_operation_id TEXT UNIQUE
) STRICT"""
_PENDING = """CREATE TABLE authority_owner_issue_pending_v1 (
    operation_id TEXT PRIMARY KEY,
    authority_namespace TEXT NOT NULL UNIQUE,
    ticket_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL,
    operation_bytes BLOB NOT NULL,
    receipt_bytes BLOB NOT NULL,
    FOREIGN KEY(authority_namespace)
        REFERENCES authority_owner_claim_tickets_v1(authority_namespace),
    FOREIGN KEY(ticket_id)
        REFERENCES authority_owner_claim_tickets_v1(ticket_id)
) STRICT"""
_COLUMNS = {
    "authority_owner_claim_tickets_v1": (
        "authority_namespace", "ticket_id", "ticket_bytes", "issue_operation_id"),
    "authority_owner_issue_pending_v1": (
        "operation_id", "authority_namespace", "ticket_id", "request_digest",
        "operation_bytes", "receipt_bytes"),
}


class AuthorityV2OwnerTicketStore:
    """One-use claim registration and pending issue, with no grant commit API."""

    def __init__(self, core: AuthorityServiceCore, *,
                 utc_clock: Callable[[], datetime] | None = None,
                 first_claim_verifier: Callable[[object, OwnerClaimTicketV1, str], bool] | None = None,
                 claimant_verifier: Callable[[object, OwnerAuthorizationOperationV1], bool] | None = None,
                 create: bool = False) -> None:
        if type(core) is not AuthorityServiceCore:
            raise TypeError("owner tickets require the independent Authority core")
        self._core = core
        self._utc_clock = utc_clock
        self._first_claim_verifier = first_claim_verifier
        self._claimant_verifier = claimant_verifier
        with core._tx() as db:
            self._require_mode(db)
            present = self._present(db)
            if not present:
                if not create:
                    raise AuthorityUnavailable("owner ticket schema is absent")
                db.execute(_TICKETS)
                db.execute(_PENDING)
            elif present != set(_COLUMNS):
                raise AuthorityUnavailable("partial owner ticket schema")
            self._check_schema(db)

    @staticmethod
    def _present(db: sqlite3.Connection) -> set[str]:
        return {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name IN (?, ?)", tuple(_COLUMNS))}

    @staticmethod
    def _checked_pending(db: sqlite3.Connection, authority_namespace: str,
                         operation_id: str) -> tuple[OwnerAuthorizationOperationV1,
                                                     OwnerAuthorizationReceiptV1] | None:
        row = db.execute(
            "SELECT p.operation_id,p.authority_namespace,p.ticket_id,p.request_digest,"
            "p.operation_bytes,p.receipt_bytes,t.authority_namespace,t.ticket_id,"
            "t.ticket_bytes,t.issue_operation_id "
            "FROM authority_owner_issue_pending_v1 AS p "
            "LEFT JOIN authority_owner_claim_tickets_v1 AS t "
            "ON t.authority_namespace=p.authority_namespace AND t.ticket_id=p.ticket_id "
            "WHERE p.operation_id=?", (operation_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            operation = decode_bytes(row[4])
            receipt = decode_bytes(row[5])
            ticket = decode_bytes(row[8])
        except (TypeError, ValueError) as exc:
            raise AuthorityUnavailable("stored owner issue pending state differs") from exc
        if (type(operation) is not OwnerAuthorizationOperationV1
                or type(receipt) is not OwnerAuthorizationReceiptV1
                or type(ticket) is not OwnerClaimTicketV1
                or operation.action != "issue" or operation.ticket != ticket
                or row[0] != operation_id or row[0] != operation.operation_id
                or row[1] != authority_namespace
                or row[1] != namespace_ref(operation.namespace)
                or row[1] != namespace_ref(ticket.namespace)
                or row[2] != ticket.ticket_id or row[3] != operation.request_digest
                or row[4] != canonical_bytes(operation)
                or row[5] != canonical_bytes(receipt)
                or row[6] != row[1] or row[7] != row[2]
                or row[8] != canonical_bytes(ticket)
                or row[9] != operation_id
                or receipt.operation != operation or receipt.phase != "pending"
                or receipt.guard != operation.expected_guard
                or receipt.receipt_ref != "owner-issue-pending:"
                + operation.request_digest.removeprefix("sha256:")[:48]):
            raise AuthorityUnavailable("stored owner issue pending state differs")
        return operation, receipt

    @staticmethod
    def _check_schema(db: sqlite3.Connection) -> None:
        for name, columns in _COLUMNS.items():
            actual = tuple(row[1] for row in db.execute(f"PRAGMA table_info({name})"))
            ddl = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (name,),
            ).fetchone()
            expected = _TICKETS if name == "authority_owner_claim_tickets_v1" else _PENDING
            if actual != columns or ddl != (expected,):
                raise AuthorityUnavailable("owner ticket schema differs")

    @staticmethod
    def _require_mode(db: sqlite3.Connection) -> None:
        if db.execute(
                "SELECT value FROM authority_meta WHERE key='service_mode'"
        ).fetchone() != ("v2-only",):
            raise AuthorityUnavailable("owner claim requires v2-only Authority")
        AuthorityServiceCore._require_no_deletion_migration(db)

    def _bound_namespace(self, db: sqlite3.Connection, ticket: OwnerClaimTicketV1,
                         authority_namespace: str) -> None:
        if namespace_ref(ticket.namespace) != authority_namespace:
            raise AuthorityUnavailable("owner ticket namespace binding differs")
        if self._core._id(db) != ticket.authority_id:
            raise AuthorityUnavailable("owner ticket Authority identity differs")
        row = self._core._row(db, authority_namespace)
        if (row[0] is None or row[1] < 1 or row[2] != "active"
                or row[3] is not None or row[9] != "clear"):
            raise AuthorityUnavailable("owner ticket namespace is not active")

    def _now(self) -> datetime:
        if not callable(self._utc_clock):
            raise AuthorityUnavailable("trusted owner claim clock is unavailable")
        try:
            now = self._utc_clock()
        except Exception as exc:
            raise AuthorityUnavailable("trusted owner claim clock failed") from exc
        if (type(now) is not datetime or now.tzinfo is None
                or now.utcoffset() is None or now.utcoffset().total_seconds() != 0):
            raise AuthorityUnavailable("owner claim clock must provide UTC")
        return now

    @staticmethod
    def _expires(ticket: OwnerClaimTicketV1) -> datetime:
        return datetime.strptime(ticket.expires_at_utc, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)

    @staticmethod
    def _verified(callback, *args) -> None:
        if not callable(callback):
            raise AuthorityUnavailable("trusted owner claim verifier is unavailable")
        try:
            accepted = callback(*args)
        except Exception as exc:
            raise AuthorityUnavailable("owner claim verification failed") from exc
        if accepted is not True:
            raise AuthorityUnavailable("owner claim verification denied")

    def register_ticket(self, *, credential: object, authority_namespace: str,
                        ticket: OwnerClaimTicketV1) -> OwnerClaimTicketV1:
        """Register exactly one original creation binding; never infer owner."""
        identifier(authority_namespace, "authority_namespace")
        if type(ticket) is not OwnerClaimTicketV1:
            raise TypeError("owner claim ticket is required")
        self._core._require(credential, "owner_pair", authority_namespace)
        encoded = canonical_bytes(ticket)
        with self._core._tx() as db:
            self._require_mode(db)
            self._bound_namespace(db, ticket, authority_namespace)
            prior = db.execute(
                "SELECT authority_namespace,ticket_bytes FROM authority_owner_claim_tickets_v1 "
                "WHERE ticket_id=? OR authority_namespace=?",
                (ticket.ticket_id, authority_namespace),
            ).fetchall()
            if prior:
                if len(prior) != 1 or prior[0] != (authority_namespace, encoded):
                    raise AuthorityUnavailable("original owner claim binding differs")
                return ticket

        if self._now() >= self._expires(ticket):
            raise AuthorityUnavailable("owner claim ticket has expired")
        # W01 freshness and administrator pairing are external trust decisions.
        # The callback runs before the Authority SQLite lock and is absent in
        # the product until a real first-creation verifier is installed.
        self._verified(self._first_claim_verifier, credential, ticket,
                       authority_namespace)
        sampled_at = monotonic()
        remaining = (self._expires(ticket) - self._now()).total_seconds()
        if remaining <= 0:
            raise AuthorityUnavailable("owner claim ticket has expired")
        with self._core._tx() as db:
            self._require_mode(db)
            self._bound_namespace(db, ticket, authority_namespace)
            prior = db.execute(
                "SELECT authority_namespace,ticket_bytes FROM authority_owner_claim_tickets_v1 "
                "WHERE ticket_id=? OR authority_namespace=?",
                (ticket.ticket_id, authority_namespace),
            ).fetchall()
            if prior:
                if len(prior) != 1 or prior[0] != (authority_namespace, encoded):
                    raise AuthorityUnavailable("original owner claim binding differs")
                return ticket
            if monotonic() - sampled_at >= remaining:
                raise AuthorityUnavailable("owner claim ticket has expired")
            db.execute(
                "INSERT INTO authority_owner_claim_tickets_v1"
                "(authority_namespace,ticket_id,ticket_bytes) VALUES(?,?,?)",
                (authority_namespace, ticket.ticket_id, encoded),
            )
            if monotonic() - sampled_at >= remaining:
                raise AuthorityUnavailable("owner claim ticket has expired")
        return ticket

    def reserve_issue(self, *, credential: object, authority_namespace: str,
                      operation: OwnerAuthorizationOperationV1) -> OwnerAuthorizationReceiptV1:
        """Consume a registered ticket once and retain an inert pending issue."""
        identifier(authority_namespace, "authority_namespace")
        if type(operation) is not OwnerAuthorizationOperationV1 or operation.action != "issue":
            raise TypeError("first owner issue operation is required")
        self._core._require(credential, "owner_claim", authority_namespace)
        # This callback must authenticate the full stable principal and proof
        # of the independently paired challenge; no dashboard role is enough.
        self._verified(self._claimant_verifier, credential, operation)
        ticket = operation.ticket
        assert ticket is not None
        with self._core._tx() as db:
            self._require_mode(db)
            self._bound_namespace(db, ticket, authority_namespace)
            prior = self._checked_pending(db, authority_namespace, operation.operation_id)
            if prior is not None:
                if prior[0] != operation:
                    raise AuthorityUnavailable("owner issue operation replay differs")
                return prior[1]

        sampled_at = monotonic()
        now = self._now()
        remaining = (self._expires(ticket) - now).total_seconds()
        if remaining <= 0:
            raise AuthorityUnavailable("owner claim ticket has expired")
        with self._core._tx() as db:
            self._require_mode(db)
            self._bound_namespace(db, ticket, authority_namespace)
            prior = self._checked_pending(db, authority_namespace, operation.operation_id)
            if prior is not None:
                if prior[0] != operation:
                    raise AuthorityUnavailable("owner issue operation replay differs")
                return prior[1]
            saved = db.execute(
                "SELECT ticket_bytes,issue_operation_id FROM authority_owner_claim_tickets_v1 "
                "WHERE authority_namespace=? AND ticket_id=?",
                (authority_namespace, ticket.ticket_id),
            ).fetchone()
            if saved is None or saved[0] != canonical_bytes(ticket) or saved[1] is not None:
                raise AuthorityUnavailable("owner claim ticket is absent or already consumed")
            expected = operation.expected_guard
            if (expected != OwnerAuthorizationGuardV1(
                    ticket.authority_id, ticket.installation_id, ticket.namespace,
                    0, "genesis", 0, 0)):
                raise AuthorityUnavailable("first owner issue guard is not genesis")
            receipt = OwnerAuthorizationReceiptV1(
                operation, "pending", "owner-issue-pending:" +
                operation.request_digest.removeprefix("sha256:")[:48], expected)
            if monotonic() - sampled_at >= remaining:
                raise AuthorityUnavailable("owner claim ticket has expired")
            db.execute(
                "INSERT INTO authority_owner_issue_pending_v1"
                "(operation_id,authority_namespace,ticket_id,request_digest,"
                "operation_bytes,receipt_bytes) VALUES(?,?,?,?,?,?)",
                (operation.operation_id, authority_namespace, ticket.ticket_id,
                 operation.request_digest, canonical_bytes(operation),
                 canonical_bytes(receipt)),
            )
            updated = db.execute(
                "UPDATE authority_owner_claim_tickets_v1 SET issue_operation_id=? "
                "WHERE authority_namespace=? AND ticket_id=? AND issue_operation_id IS NULL",
                (operation.operation_id, authority_namespace, ticket.ticket_id),
            ).rowcount
            if updated != 1:
                raise AuthorityUnavailable("owner ticket consumption raced")
            if monotonic() - sampled_at >= remaining:
                raise AuthorityUnavailable("owner claim ticket has expired")
            return receipt

    def get_pending(self, *, credential: object, authority_namespace: str,
                    operation_id: str) -> OwnerAuthorizationReceiptV1 | None:
        """Query the original pending receipt after restart; never mint access."""
        identifier(authority_namespace, "authority_namespace")
        identifier(operation_id, "operation_id")
        self._core._require(credential, "owner_claim", authority_namespace)
        with self._core._tx() as db:
            self._require_mode(db)
            pending = self._checked_pending(db, authority_namespace, operation_id)
        if pending is None:
            return None
        operation, receipt = pending
        self._verified(self._claimant_verifier, credential, operation)
        return receipt


__all__ = ("AuthorityV2OwnerTicketStore",)
