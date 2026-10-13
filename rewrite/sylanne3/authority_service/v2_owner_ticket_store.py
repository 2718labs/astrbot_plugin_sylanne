"""Durable first-owner ticket and issue-pending records in Authority SQLite.

The caller must install independent first-creation, claimant, and current-graph
verifiers. No callback is provided here. Pending never grants permission.
The graph remains the sole business grant store.
"""

from __future__ import annotations

from datetime import datetime, timezone
import sqlite3
from time import monotonic
from typing import Callable

from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .v2_fence_store import AuthorityV2FenceStore
from .v2_contract import (
    DispatchHandoffContextV1, ExecutionBindingV2, FencePermitV2,
    OwnerDispatchWitnessV1, canonical_bytes as fence_canonical_bytes,
    canonical_digest as fence_canonical_digest,
)
from .v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerAuthorizationReceiptV1, OwnerClaimTicketV1, OwnerGraphCommitProofV1,
    OwnerMigrationHeadV1,
    canonical_bytes, canonical_digest,
    decode_bytes,
)
from .v2_owner_session import AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1
from ..runtime_contracts import namespace_ref


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
_COMMITTED = """CREATE TABLE authority_owner_issue_committed_v1 (
    authority_namespace TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL UNIQUE,
    proof_bytes BLOB NOT NULL,
    receipt_bytes BLOB NOT NULL,
    guard_bytes BLOB NOT NULL,
    FOREIGN KEY(operation_id)
        REFERENCES authority_owner_issue_pending_v1(operation_id)
) STRICT"""
_HEAD = """CREATE TABLE authority_owner_authorization_heads_v1 (
    authority_namespace TEXT PRIMARY KEY,
    issue_operation_id TEXT NOT NULL UNIQUE,
    current_operation_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    state TEXT NOT NULL CHECK(state IN ('active','revoked')),
    guard_bytes BLOB NOT NULL,
    FOREIGN KEY(issue_operation_id)
        REFERENCES authority_owner_issue_committed_v1(operation_id)
) STRICT"""
_REVOKE_PENDING = """CREATE TABLE authority_owner_revoke_pending_v1 (
    operation_id TEXT PRIMARY KEY,
    authority_namespace TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL,
    operation_bytes BLOB NOT NULL,
    receipt_bytes BLOB NOT NULL,
    FOREIGN KEY(authority_namespace)
        REFERENCES authority_owner_authorization_heads_v1(authority_namespace)
) STRICT"""
_REVOKE_COMMITTED = """CREATE TABLE authority_owner_revoke_committed_v1 (
    operation_id TEXT PRIMARY KEY,
    authority_namespace TEXT NOT NULL UNIQUE,
    proof_bytes BLOB NOT NULL,
    receipt_bytes BLOB NOT NULL,
    guard_bytes BLOB NOT NULL,
    FOREIGN KEY(operation_id)
        REFERENCES authority_owner_revoke_pending_v1(operation_id)
) STRICT"""
_COLUMNS = {
    "authority_owner_claim_tickets_v1": (
        "authority_namespace", "ticket_id", "ticket_bytes", "issue_operation_id"),
    "authority_owner_issue_pending_v1": (
        "operation_id", "authority_namespace", "ticket_id", "request_digest",
        "operation_bytes", "receipt_bytes"),
    "authority_owner_issue_committed_v1": (
        "authority_namespace", "operation_id", "proof_bytes", "receipt_bytes",
        "guard_bytes"),
    "authority_owner_authorization_heads_v1": (
        "authority_namespace", "issue_operation_id", "current_operation_id",
        "revision", "state", "guard_bytes"),
    "authority_owner_revoke_pending_v1": (
        "operation_id", "authority_namespace", "request_digest",
        "operation_bytes", "receipt_bytes"),
    "authority_owner_revoke_committed_v1": (
        "operation_id", "authority_namespace", "proof_bytes", "receipt_bytes",
        "guard_bytes"),
}
_ISSUE_TABLES = set(_COLUMNS) - {
    "authority_owner_revoke_pending_v1", "authority_owner_revoke_committed_v1"}


class OwnerAuthorizationBarrier(AuthorityUnavailable):
    """A verified pending/revoked Owner head denies this content handoff."""


class AuthorityV2OwnerTicketStore:
    """One-use claim and graph-verified first-issue receipts."""

    def __init__(self, core: AuthorityServiceCore, *,
                 utc_clock: Callable[[], datetime] | None = None,
                 first_claim_verifier: Callable[[object, OwnerClaimTicketV1, str], bool] | None = None,
                 claimant_verifier: Callable[[object, OwnerAuthorizationOperationV1], bool] | None = None,
                 graph_commit_verifier: Callable[[OwnerAuthorizationOperationV1,
                                                 OwnerGraphCommitProofV1], bool] | None = None,
                 revoke_graph_commit_verifier: Callable[[OwnerAuthorizationOperationV1,
                                                        OwnerGraphCommitProofV1], bool] | None = None,
                 owner_sessions: AuthorityV2OwnerSessionStore | None = None,
                 creation_pairing_source: object | None = None,
                 create: bool = False) -> None:
        if type(core) is not AuthorityServiceCore:
            raise TypeError("owner tickets require the independent Authority core")
        self._core = core
        self._utc_clock = utc_clock
        self._first_claim_verifier = first_claim_verifier
        self._claimant_verifier = claimant_verifier
        self._graph_commit_verifier = graph_commit_verifier
        self._revoke_graph_commit_verifier = revoke_graph_commit_verifier
        if owner_sessions is not None and (
                type(owner_sessions) is not AuthorityV2OwnerSessionStore
                or owner_sessions._core is not core):
            raise TypeError("Owner sessions must use the same Authority core")
        self._owner_sessions = owner_sessions
        if creation_pairing_source is not None:
            from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource
            if (type(creation_pairing_source) is not AuthorityOwnerPairingSource
                    or creation_pairing_source._core is not core):
                raise TypeError("creation pairing requires this Authority core")
        self._creation_pairing_source = creation_pairing_source
        with core._tx() as db:
            self._require_mode(db)
            present = self._present(db)
            if not present:
                if not create:
                    raise AuthorityUnavailable("owner ticket schema is absent")
                db.execute(_TICKETS)
                db.execute(_PENDING)
                db.execute(_COMMITTED)
                db.execute(_HEAD)
                db.execute(_REVOKE_PENDING)
                db.execute(_REVOKE_COMMITTED)
            elif present == _ISSUE_TABLES - {
                    "authority_owner_issue_committed_v1",
                    "authority_owner_authorization_heads_v1"} and create:
                # Explicit, additive upgrade preserves already consumed tickets.
                self._check_schema(db, old={"authority_owner_issue_committed_v1",
                                            "authority_owner_authorization_heads_v1"})
                db.execute(_COMMITTED)
                db.execute(_HEAD)
            elif present == _ISSUE_TABLES - {"authority_owner_authorization_heads_v1"} and create:
                # An already committed first issue becomes the initial current
                # head without changing its immutable historical receipt.
                self._check_schema(db, old={"authority_owner_authorization_heads_v1"})
                db.execute(_HEAD)
                for namespace, operation_id in db.execute(
                        "SELECT authority_namespace,operation_id "
                        "FROM authority_owner_issue_committed_v1"):
                    committed = self._checked_committed(db, namespace, operation_id)
                    assert committed is not None
                    db.execute(
                        "INSERT INTO authority_owner_authorization_heads_v1"
                        "(authority_namespace,issue_operation_id,current_operation_id,"
                        "revision,state,guard_bytes) VALUES(?,?,?,?,?,?)",
                        (namespace, operation_id, operation_id, 1, "active",
                         canonical_bytes(committed[1].guard)),
                    )
            elif present == _ISSUE_TABLES and create:
                self._check_schema(db, old={"authority_owner_revoke_pending_v1",
                                            "authority_owner_revoke_committed_v1"})
                db.execute(_REVOKE_PENDING)
                db.execute(_REVOKE_COMMITTED)
            elif present != set(_COLUMNS):
                raise AuthorityUnavailable("partial owner ticket schema")
            if create and present in (
                    _ISSUE_TABLES - {"authority_owner_issue_committed_v1",
                                     "authority_owner_authorization_heads_v1"},
                    _ISSUE_TABLES - {"authority_owner_authorization_heads_v1"}):
                db.execute(_REVOKE_PENDING)
                db.execute(_REVOKE_COMMITTED)
            self._check_schema(db)
            if create:
                from .v3_owner_paid_guard_observation import install_owner_paid_guard_observations_v3
                install_owner_paid_guard_observations_v3(db)

    @staticmethod
    def _present(db: sqlite3.Connection) -> set[str]:
        return {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name IN (?, ?, ?, ?, ?, ?)", tuple(_COLUMNS))}

    @staticmethod
    def _checked_committed(db: sqlite3.Connection, authority_namespace: str,
                           operation_id: str) -> tuple[OwnerGraphCommitProofV1,
                                                       OwnerAuthorizationReceiptV1] | None:
        row = db.execute(
            "SELECT authority_namespace,operation_id,proof_bytes,receipt_bytes,guard_bytes "
            "FROM authority_owner_issue_committed_v1 "
            "WHERE authority_namespace=? OR operation_id=?",
            (authority_namespace, operation_id),
        ).fetchall()
        if not row:
            return None
        if len(row) != 1 or row[0][0:2] != (authority_namespace, operation_id):
            raise AuthorityUnavailable("committed owner issue identity differs")
        saved = row[0]
        pending = AuthorityV2OwnerTicketStore._checked_pending(
            db, authority_namespace, operation_id)
        if pending is None:
            raise AuthorityUnavailable("committed owner issue lacks pending origin")
        operation = pending[0]
        try:
            proof, receipt, guard = (decode_bytes(saved[2]), decode_bytes(saved[3]),
                                     decode_bytes(saved[4]))
        except (TypeError, ValueError) as exc:
            raise AuthorityUnavailable("stored owner issue commit differs") from exc
        if (type(proof) is not OwnerGraphCommitProofV1
                or type(receipt) is not OwnerAuthorizationReceiptV1
                or type(guard) is not OwnerAuthorizationGuardV1
                or saved[2] != canonical_bytes(proof)
                or saved[3] != canonical_bytes(receipt)
                or saved[4] != canonical_bytes(guard)
                or receipt.operation != operation or receipt.phase != "committed"
                or receipt.guard != guard or proof.namespace != operation.namespace
                or proof.operation_id != operation_id
                or proof.request_digest != operation.request_digest
                or proof.grant_id != operation.grant_id
                or proof.grant_digest != operation.grant_digest
                or proof.grant_revision != 1
                or receipt.grant_revision != proof.grant_revision
                or receipt.graph_access_epoch != proof.graph_access_epoch
                or guard != OwnerAuthorizationGuardV1(
                    operation.authority_id, operation.installation_id,
                    operation.namespace, 1, canonical_digest(proof), 0, 0)
                or receipt.receipt_ref != "owner-issue-committed:" +
                    proof.graph_receipt_digest.removeprefix("sha256:")[:48]):
            raise AuthorityUnavailable("stored owner issue commit differs")
        return proof, receipt

    @staticmethod
    def _checked_current_head(db: sqlite3.Connection, authority_namespace: str
                              ) -> OwnerAuthorizationGuardV1 | None:
        row = db.execute(
            "SELECT issue_operation_id,current_operation_id,revision,state,guard_bytes "
            "FROM authority_owner_authorization_heads_v1 WHERE authority_namespace=?",
            (authority_namespace,),
        ).fetchone()
        if row is None:
            if db.execute(
                "SELECT 1 FROM authority_owner_issue_committed_v1 "
                "WHERE authority_namespace=?", (authority_namespace,),
            ).fetchone():
                raise AuthorityUnavailable("committed owner issue lacks current head")
            return None
        committed = AuthorityV2OwnerTicketStore._checked_committed(
            db, authority_namespace, row[0])
        if committed is None:
            raise AuthorityUnavailable("owner current head lacks issue origin")
        try:
            guard = decode_bytes(row[4])
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityUnavailable("owner current head differs") from exc
        issue_guard = committed[1].guard
        if (type(guard) is not OwnerAuthorizationGuardV1
                or row[4] != canonical_bytes(guard)
                or guard.authorization_revision != row[2]):
            raise AuthorityUnavailable("owner current head differs")
        if row[1:4] == (row[0], 1, "active") and guard == issue_guard:
            if db.execute(
                    "SELECT 1 FROM authority_owner_revoke_pending_v1 "
                    "WHERE authority_namespace=?", (authority_namespace,)).fetchone():
                raise AuthorityUnavailable("owner revoke ledger lacks a barrier")
            return guard
        revoke = AuthorityV2OwnerTicketStore._checked_revoke_pending(
            db, authority_namespace, row[1])
        if revoke is None:
            raise AuthorityUnavailable("owner current head lacks revoke origin")
        operation, pending_receipt = revoke
        if operation.expected_guard != issue_guard or row[0] == row[1]:
            raise AuthorityUnavailable("owner revoke origin differs from issue")
        saved_commit = AuthorityV2OwnerTicketStore._checked_revoke_committed(
            db, authority_namespace, row[1])
        if row[2:4] == (1, "active"):
            if saved_commit is not None or guard != pending_receipt.guard:
                raise AuthorityUnavailable("owner pending revoke barrier differs")
        elif row[2:4] == (2, "revoked"):
            if saved_commit is None or guard != saved_commit[1].guard:
                raise AuthorityUnavailable("owner committed revoke head differs")
        else:
            raise AuthorityUnavailable("unsupported owner authorization transition")
        return guard

    @staticmethod
    def _checked_revoke_pending(db: sqlite3.Connection, authority_namespace: str,
                                operation_id: str) -> tuple[OwnerAuthorizationOperationV1,
                                                            OwnerAuthorizationReceiptV1] | None:
        rows = db.execute(
            "SELECT operation_id,authority_namespace,request_digest,operation_bytes,"
            "receipt_bytes FROM authority_owner_revoke_pending_v1 "
            "WHERE operation_id=? OR authority_namespace=?",
            (operation_id, authority_namespace)).fetchall()
        if not rows:
            return None
        if len(rows) != 1 or rows[0][0:2] != (operation_id, authority_namespace):
            raise AuthorityUnavailable("owner revoke pending identity differs")
        saved = rows[0]
        try:
            operation, receipt = decode_bytes(saved[3]), decode_bytes(saved[4])
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityUnavailable("stored owner revoke pending differs") from exc
        issue_row = db.execute(
            "SELECT issue_operation_id FROM authority_owner_authorization_heads_v1 "
            "WHERE authority_namespace=?", (authority_namespace,)).fetchone()
        issue = (AuthorityV2OwnerTicketStore._checked_committed(
            db, authority_namespace, issue_row[0]) if issue_row else None)
        issue_pending = (AuthorityV2OwnerTicketStore._checked_pending(
            db, authority_namespace, issue_row[0]) if issue_row else None)
        if (type(operation) is not OwnerAuthorizationOperationV1
                or type(receipt) is not OwnerAuthorizationReceiptV1
                or issue is None or issue_pending is None
                or operation.action != "revoke" or operation.ticket is not None
                or operation.expected_grant_revision != 1
                or operation.expected_guard != issue[1].guard
                or operation.authority_id != issue_pending[0].authority_id
                or operation.installation_id != issue_pending[0].installation_id
                or operation.namespace != issue_pending[0].namespace
                or operation.principal != issue_pending[0].principal
                or operation.grant_id != issue_pending[0].grant_id
                or operation.operation_id == issue_row[0]
                or saved[2] != operation.request_digest
                or saved[3] != canonical_bytes(operation)
                or saved[4] != canonical_bytes(receipt)
                or receipt.operation != operation or receipt.phase != "pending"
                or receipt.guard != OwnerAuthorizationGuardV1(
                    operation.authority_id, operation.installation_id,
                    operation.namespace, 1, issue[1].guard.authorization_head,
                    0, 0, operation.operation_id)
                or receipt.receipt_ref != "owner-revoke-pending:"
                    + operation.request_digest.removeprefix("sha256:")[:48]):
            raise AuthorityUnavailable("stored owner revoke pending differs")
        return operation, receipt

    @staticmethod
    def _checked_revoke_committed(db: sqlite3.Connection, authority_namespace: str,
                                  operation_id: str) -> tuple[OwnerGraphCommitProofV1,
                                                              OwnerAuthorizationReceiptV1] | None:
        rows = db.execute(
            "SELECT operation_id,authority_namespace,proof_bytes,receipt_bytes,guard_bytes "
            "FROM authority_owner_revoke_committed_v1 "
            "WHERE operation_id=? OR authority_namespace=?",
            (operation_id, authority_namespace)).fetchall()
        if not rows:
            return None
        if len(rows) != 1 or rows[0][0:2] != (operation_id, authority_namespace):
            raise AuthorityUnavailable("owner revoke committed identity differs")
        saved = rows[0]
        pending = AuthorityV2OwnerTicketStore._checked_revoke_pending(
            db, authority_namespace, operation_id)
        if pending is None:
            raise AuthorityUnavailable("owner revoke commit lacks pending origin")
        operation = pending[0]
        try:
            proof, receipt, guard = map(decode_bytes, saved[2:5])
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityUnavailable("stored owner revoke commit differs") from exc
        if (type(proof) is not OwnerGraphCommitProofV1
                or type(receipt) is not OwnerAuthorizationReceiptV1
                or type(guard) is not OwnerAuthorizationGuardV1
                or saved[2] != canonical_bytes(proof)
                or saved[3] != canonical_bytes(receipt)
                or saved[4] != canonical_bytes(guard)
                or proof.namespace != operation.namespace
                or proof.operation_id != operation_id
                or proof.request_digest != operation.request_digest
                or proof.grant_id != operation.grant_id
                or proof.grant_digest != operation.grant_digest
                or proof.grant_revision != 2 or proof.graph_access_epoch < 2
                or receipt.operation != operation or receipt.phase != "committed"
                or receipt.grant_revision != 2
                or receipt.graph_access_epoch != proof.graph_access_epoch
                or receipt.guard != guard
                or guard != OwnerAuthorizationGuardV1(
                    operation.authority_id, operation.installation_id,
                    operation.namespace, 2, canonical_digest(proof), 2,
                    proof.graph_access_epoch)
                or receipt.receipt_ref != "owner-revoke-committed:"
                    + proof.graph_receipt_digest.removeprefix("sha256:")[:48]):
            raise AuthorityUnavailable("stored owner revoke commit differs")
        return proof, receipt

    def current_dispatch_witness_in_tx(
            self, db: sqlite3.Connection, *, context: DispatchHandoffContextV1,
            binding: ExecutionBindingV2, installation_id: str,
    ) -> OwnerDispatchWitnessV1:
        """Snapshot the committed, active Owner grant in the caller's Core tx."""
        if db is not self._core._db or not db.in_transaction:
            raise AuthorityUnavailable("Owner dispatch witness needs Authority transaction")
        if (type(context) is not DispatchHandoffContextV1
                or type(binding) is not ExecutionBindingV2):
            raise TypeError("Owner dispatch witness requires exact P2 identity")
        identifier(installation_id, "installation_id")
        self._require_mode(db)
        authority_namespace = context.permit.namespace
        guard = self._checked_current_head(db, authority_namespace)
        if guard is not None and (
                guard.pending_revoke_operation_id is not None
                or guard.minimum_revocation_revision >= guard.authorization_revision):
            raise OwnerAuthorizationBarrier("current Owner authorization is barred")
        if (guard is None or guard.authority_id != context.permit.authority_id
                or guard.installation_id != installation_id
                or namespace_ref(guard.namespace) != authority_namespace
                or binding.graph_namespace != "/".join(guard.namespace.as_tuple)
                or guard.minimum_revocation_epoch > 0
                or "/" in guard.namespace.bot_id
                or "/" in guard.namespace.persona_id):
            raise AuthorityUnavailable("current Owner authorization is unavailable")
        head = db.execute(
            "SELECT issue_operation_id FROM authority_owner_authorization_heads_v1 "
            "WHERE authority_namespace=?", (authority_namespace,),
        ).fetchone()
        if head is None:
            raise AuthorityUnavailable("current Owner grant origin is unavailable")
        pending = self._checked_pending(db, authority_namespace, head[0])
        committed = self._checked_committed(db, authority_namespace, head[0])
        if pending is None or committed is None:
            raise AuthorityUnavailable("current Owner grant is not committed")
        operation = pending[0]
        proof = committed[0]
        if (operation.action != "issue" or operation.authority_id != guard.authority_id
                or operation.installation_id != installation_id
                or operation.namespace != guard.namespace
                or proof.graph_incarnation != binding.graph_incarnation
                or proof.graph_epoch > binding.admission_graph_epoch
                or proof.graph_access_epoch > binding.admission_access_epoch):
            raise AuthorityUnavailable("current Owner grant differs from dispatch graph")
        return OwnerDispatchWitnessV1(
            context_digest=fence_canonical_digest(context),
            authority_namespace=authority_namespace,
            graph_namespace=binding.graph_namespace, guard=guard,
            issue_operation_id=operation.operation_id,
            grant_id=operation.grant_id, grant_digest=operation.grant_digest)

    def current_migration_head_in_tx(
            self, db: sqlite3.Connection, *, authority_namespace: str,
    ) -> OwnerMigrationHeadV1 | None:
        """Freeze the current Owner ledger head in a caller-held Core transaction."""
        identifier(authority_namespace, "authority_namespace")
        if db is not self._core._db or not db.in_transaction:
            raise AuthorityUnavailable("Owner migration head needs Authority transaction")
        return read_owner_migration_head_in_tx_v1(db, authority_namespace=authority_namespace)

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
    def _check_schema(db: sqlite3.Connection, *, old: set[str] | None = None) -> None:
        for name, columns in _COLUMNS.items():
            if old and name in old:
                continue
            actual = tuple(row[1] for row in db.execute(f"PRAGMA table_info({name})"))
            ddl = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (name,),
            ).fetchone()
            expected = {"authority_owner_claim_tickets_v1": _TICKETS,
                        "authority_owner_issue_pending_v1": _PENDING,
                        "authority_owner_issue_committed_v1": _COMMITTED,
                        "authority_owner_authorization_heads_v1": _HEAD,
                        "authority_owner_revoke_pending_v1": _REVOKE_PENDING,
                        "authority_owner_revoke_committed_v1": _REVOKE_COMMITTED}[name]
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

    def _require_owner_session(
        self, db: sqlite3.Connection, authority_namespace: str,
        operation: OwnerAuthorizationOperationV1 | None,
        session_token: str | None, session_request: OwnerSessionLoginRequestV1 | None,
    ) -> None:
        sessions = self._owner_sessions
        if sessions is None:
            if session_token is not None or session_request is not None:
                raise AuthorityUnavailable("Owner session service is unavailable")
            return
        if (session_token is None or type(session_request) is not OwnerSessionLoginRequestV1
                or session_request.authority_namespace != authority_namespace
                or session_request.audience != "sylanne-owner-console"
                or (operation is not None and (
                    session_request.authority_id != operation.authority_id
                    or session_request.installation_id != operation.installation_id
                    or session_request.principal != operation.principal
                    or authority_namespace != namespace_ref(operation.namespace)))):
            raise AuthorityUnavailable("Owner session differs from issue operation")
        sessions.require_current_in_tx(db, token=session_token, request=session_request)

    def _require_revoke_session(
        self, db: sqlite3.Connection, authority_namespace: str,
        operation: OwnerAuthorizationOperationV1 | None,
        session_token: str | None, session_request: OwnerSessionLoginRequestV1 | None,
    ) -> None:
        """Check an Owner-audience session against the immutable issue identity."""
        sessions = self._owner_sessions
        if (type(sessions) is not AuthorityV2OwnerSessionStore
                or type(session_token) is not str or not session_token
                or type(session_request) is not OwnerSessionLoginRequestV1
                or session_request.audience != "owner"
                or session_request.authority_namespace != authority_namespace):
            raise AuthorityUnavailable("current Owner revoke session is unavailable")
        if operation is None:
            row = db.execute(
                "SELECT issue_operation_id FROM authority_owner_authorization_heads_v1 "
                "WHERE authority_namespace=?", (authority_namespace,)).fetchone()
            original = (self._checked_pending(db, authority_namespace, row[0])
                        if row else None)
            if original is None:
                raise AuthorityUnavailable("Owner revoke session lacks issue identity")
            operation = original[0]
        if (session_request.authority_id != operation.authority_id
                or session_request.installation_id != operation.installation_id
                or session_request.principal != operation.principal
                or namespace_ref(operation.namespace) != authority_namespace):
            raise AuthorityUnavailable("Owner revoke session identity differs")
        sessions.require_current_in_tx(
            db, token=session_token, request=session_request)

    def _require_creation_pairing(self, db: sqlite3.Connection,
                                  credential: object, authority_namespace: str,
                                  ticket: OwnerClaimTicketV1) -> None:
        source = self._creation_pairing_source
        if source is None:
            return
        from .mtls_server import MtlsPeerCredential
        if type(credential) is not MtlsPeerCredential:
            raise AuthorityUnavailable("Owner creation pairing requires an mTLS peer")
        source.require_current_creation_pairing_in_tx(
            db, authority_namespace=authority_namespace, ticket=ticket,
            client_certificate_sha256=credential.certificate_sha256)

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
            self._require_creation_pairing(db, credential, authority_namespace, ticket)
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
            self._require_creation_pairing(db, credential, authority_namespace, ticket)
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
                      operation: OwnerAuthorizationOperationV1,
                      session_token: str | None = None,
                      session_request: OwnerSessionLoginRequestV1 | None = None,
                      ) -> OwnerAuthorizationReceiptV1:
        """Consume a registered ticket once and retain an inert pending issue."""
        identifier(authority_namespace, "authority_namespace")
        if type(operation) is not OwnerAuthorizationOperationV1 or operation.action != "issue":
            raise TypeError("first owner issue operation is required")
        self._core._require(credential, "owner_claim", authority_namespace)
        if self._owner_sessions is None:
            # Historical proof mode authenticates a paired claimant externally.
            self._verified(self._claimant_verifier, credential, operation)
        ticket = operation.ticket
        assert ticket is not None
        with self._core._tx() as db:
            self._require_mode(db)
            self._require_owner_session(db, authority_namespace, operation,
                                        session_token, session_request)
            self._require_creation_pairing(db, credential, authority_namespace, ticket)
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
            self._require_owner_session(db, authority_namespace, operation,
                                        session_token, session_request)
            self._require_creation_pairing(db, credential, authority_namespace, ticket)
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
                    operation_id: str, session_token: str | None = None,
                    session_request: OwnerSessionLoginRequestV1 | None = None,
                    ) -> OwnerAuthorizationReceiptV1 | None:
        """Query the original pending receipt after restart; never mint access."""
        identifier(authority_namespace, "authority_namespace")
        identifier(operation_id, "operation_id")
        self._core._require(credential, "owner_claim", authority_namespace)
        with self._core._tx() as db:
            self._require_mode(db)
            pending = self._checked_pending(db, authority_namespace, operation_id)
            self._require_owner_session(db, authority_namespace,
                                        pending[0] if pending is not None else None,
                                        session_token, session_request)
        if pending is None:
            return None
        operation, receipt = pending
        if self._owner_sessions is None:
            self._verified(self._claimant_verifier, credential, operation)
        return receipt

    def get_pending_for_graph_write(
        self, *, credential: object, authority_namespace: str,
        operation_id: str, installation_id: str, subject: str,
        permit: FencePermitV2,
    ) -> OwnerAuthorizationReceiptV1 | None:
        """Read one uncommitted pending issue under this caller's live write fence.

        The service must first validate the permit against its current journals.
        This transaction independently checks that the exact permit is still the
        active durable fence before reading the original pending record.
        """
        identifier(authority_namespace, "authority_namespace")
        identifier(operation_id, "operation_id")
        identifier(installation_id, "installation_id")
        identifier(subject, "subject")
        if (type(permit) is not FencePermitV2 or permit.operation != "write"
                or permit.namespace != authority_namespace
                or permit.subject != subject):
            raise AuthorityUnavailable("owner graph read requires an exact write fence")
        self._core._require(credential, "write", authority_namespace, permit.holder)
        with self._core._tx() as db:
            self._require_mode(db)
            AuthorityV2FenceStore._check_schema(db)
            AuthorityV2FenceStore._require_no_migration(db)
            row = AuthorityV2FenceStore._row(db, permit.operation_id)
            if (row is None or row[1] != authority_namespace or row[2] != subject
                    or row[3] != permit.token or row[6] != "active"
                    or row[7] != fence_canonical_bytes(permit) or row[10] is not None
                    or AuthorityV2FenceStore._permit(row) != permit
                    or permit.authority_id != self._core._id(db)):
                raise AuthorityUnavailable("owner graph write fence is no longer current")
            pending = self._checked_pending(db, authority_namespace, operation_id)
            if pending is None:
                return None
            operation, receipt = pending
            if (operation.authority_id != permit.authority_id
                    or operation.installation_id != installation_id
                    or db.execute(
                        "SELECT 1 FROM authority_owner_issue_committed_v1 "
                        "WHERE authority_namespace=? OR operation_id=?",
                        (authority_namespace, operation_id),
                    ).fetchone() is not None):
                raise AuthorityUnavailable("owner pending issue is not eligible for graph read")
            return receipt

    def _owner_commit_snapshot(self, db: sqlite3.Connection,
                               authority_namespace: str) -> tuple[int, tuple]:
        """Capture the Authority barrier while no graph write can be in flight."""
        AuthorityV2FenceStore._check_schema(db)
        AuthorityV2FenceStore._require_no_migration(db)
        if db.execute(
            "SELECT 1 FROM authority_v2_fences WHERE namespace=? "
            "AND (state='active' OR pending IS NOT NULL) LIMIT 1",
            (authority_namespace,),
        ).fetchone() or db.execute(
            "SELECT 1 FROM authority_v2_mutations WHERE namespace=? "
            "AND state='pending' LIMIT 1", (authority_namespace,),
        ).fetchone():
            raise AuthorityUnavailable("live v2 fence blocks owner commit")
        epoch = db.execute(
            "SELECT last_epoch FROM authority_v2_epochs WHERE namespace=?",
            (authority_namespace,),
        ).fetchone()
        return (epoch[0] if epoch is not None else 0,
                self._core._row(db, authority_namespace))

    def read_committed_issue(self, *, credential, authority_namespace, operation,
                             session_token=None, session_request=None):
        """Read the exact already-issued original; never grant or write anew."""
        if type(operation) is not OwnerAuthorizationOperationV1 or operation.action != 'issue':
            raise TypeError('exact first Owner issue operation required')
        self._core._require(credential, 'owner_claim', authority_namespace)
        with self._core._tx() as db:
            self._require_mode(db)
            self._require_owner_session(db,authority_namespace,operation,session_token,session_request)
            self._require_creation_pairing(db,credential,authority_namespace,operation.ticket)
            pending=self._checked_pending(db,authority_namespace,operation.operation_id)
            if pending is None:return None
            if pending[0]!=operation:raise AuthorityUnavailable('committed Owner replay operation differs')
            original=self._checked_committed(db,authority_namespace,operation.operation_id)
            if original is None:return None
            proof,receipt=original
            if (receipt.operation!=operation or receipt.phase!='committed'
                    or proof.operation_id!=operation.operation_id or proof.grant_digest!=operation.grant_digest):
                raise AuthorityUnavailable('committed Owner original differs')
            return receipt

    def finalize_issue(self, *, credential: object, authority_namespace: str,
                       operation: OwnerAuthorizationOperationV1,
                       proof: OwnerGraphCommitProofV1,
                       session_token: str | None = None,
                       session_request: OwnerSessionLoginRequestV1 | None = None,
                       ) -> OwnerAuthorizationReceiptV1:
        """Record one graph-verified issue after an exact durable pending claim."""
        identifier(authority_namespace, "authority_namespace")
        if type(operation) is not OwnerAuthorizationOperationV1 or operation.action != "issue":
            raise TypeError("first owner issue operation is required")
        if type(proof) is not OwnerGraphCommitProofV1:
            raise TypeError("canonical graph commit proof is required")
        self._core._require(credential, "owner_claim", authority_namespace)
        if self._owner_sessions is None:
            self._verified(self._claimant_verifier, credential, operation)
        if not callable(self._graph_commit_verifier):
            raise AuthorityUnavailable("trusted graph commit verifier is unavailable")
        if (namespace_ref(operation.namespace) != authority_namespace
                or proof.namespace != operation.namespace
                or proof.operation_id != operation.operation_id
                or proof.request_digest != operation.request_digest
                or proof.grant_id != operation.grant_id
                or proof.grant_digest != operation.grant_digest
                or proof.grant_revision != 1):
            raise AuthorityUnavailable("owner graph proof differs from pending issue")
        with self._core._tx() as db:
            self._require_mode(db)
            self._require_owner_session(db, authority_namespace, operation,
                                        session_token, session_request)
            ticket = operation.ticket
            assert ticket is not None
            self._require_creation_pairing(db, credential, authority_namespace, ticket)
            pending = self._checked_pending(db, authority_namespace,
                                            operation.operation_id)
            if pending is None or pending[0] != operation:
                raise AuthorityUnavailable("exact pending owner issue is absent")
            committed = self._checked_committed(db, authority_namespace,
                                                operation.operation_id)
            if committed is not None:
                if committed[0] != proof:
                    raise AuthorityUnavailable("owner issue commit replay differs")
                return committed[1]
            ticket = operation.ticket
            assert ticket is not None
            self._bound_namespace(db, ticket, authority_namespace)
            before = self._owner_commit_snapshot(db, authority_namespace)
        # A trusted service-side verifier must check the CURRENT graph stamp and
        # independently durable graph receipt. A new graph write requires a new
        # Authority fence epoch; never call graph under Core lock.
        self._verified(self._graph_commit_verifier, operation, proof)
        guard = OwnerAuthorizationGuardV1(
            operation.authority_id, operation.installation_id,
            operation.namespace, 1, canonical_digest(proof), 0, 0)
        receipt = OwnerAuthorizationReceiptV1(
            operation, "committed", "owner-issue-committed:" +
            proof.graph_receipt_digest.removeprefix("sha256:")[:48], guard,
            proof.grant_revision, proof.graph_access_epoch)
        with self._core._tx() as db:
            self._require_mode(db)
            self._require_owner_session(db, authority_namespace, operation,
                                        session_token, session_request)
            ticket = operation.ticket
            assert ticket is not None
            self._require_creation_pairing(db, credential, authority_namespace, ticket)
            self._bound_namespace(db, ticket, authority_namespace)
            pending = self._checked_pending(db, authority_namespace,
                                            operation.operation_id)
            if pending is None or pending[0] != operation:
                raise AuthorityUnavailable("exact pending owner issue is absent")
            committed = self._checked_committed(db, authority_namespace,
                                                operation.operation_id)
            if committed is not None:
                if committed[0] != proof:
                    raise AuthorityUnavailable("owner issue commit replay differs")
                return committed[1]
            if self._owner_commit_snapshot(db, authority_namespace) != before:
                raise AuthorityUnavailable("owner graph proof crossed Authority state change")
            # Absence of a row is genesis. UNIQUE namespace and operation keys
            # make this an atomic genesis -> revision 1 compare-and-set.
            inserted = db.execute(
                "INSERT INTO authority_owner_issue_committed_v1"
                "(authority_namespace,operation_id,proof_bytes,receipt_bytes,guard_bytes) "
                "SELECT ?,?,?,?,? WHERE NOT EXISTS "
                "(SELECT 1 FROM authority_owner_issue_committed_v1 "
                "WHERE authority_namespace=? OR operation_id=?)",
                (authority_namespace, operation.operation_id,
                 canonical_bytes(proof), canonical_bytes(receipt),
                 canonical_bytes(guard), authority_namespace,
                 operation.operation_id),
            ).rowcount
            if inserted != 1:
                raise AuthorityUnavailable("owner authorization genesis CAS failed")
            head_inserted = db.execute(
                "INSERT INTO authority_owner_authorization_heads_v1"
                "(authority_namespace,issue_operation_id,current_operation_id,"
                "revision,state,guard_bytes) SELECT ?,?,?,1,'active',? WHERE NOT EXISTS "
                "(SELECT 1 FROM authority_owner_authorization_heads_v1 "
                "WHERE authority_namespace=?)",
                (authority_namespace, operation.operation_id, operation.operation_id,
                 canonical_bytes(guard), authority_namespace),
            ).rowcount
            if head_inserted != 1:
                raise AuthorityUnavailable("owner current head genesis CAS failed")
            return receipt

    def get_current_guard(self, *, credential: object,
                          authority_namespace: str, installation_id: str,
                          subject: str, permit: FencePermitV2,
                          owner_actor_id: str | None = None,
                          owner_session_token: str | None = None,
                          owner_session_request: OwnerSessionLoginRequestV1 | None = None,
                          ) -> OwnerAuthorizationGuardV1 | None:
        """Read only the current control head under a live read/write fence.

        The service validates the journal-current permit before this call.
        This transaction rechecks the durable permit and Authority anchor so a
        finish or head change between those steps cannot yield a stale guard.
        A graph consumer still revalidates both control and graph at use time.
        """
        identifier(authority_namespace, "authority_namespace")
        identifier(installation_id, "installation_id")
        identifier(subject, "subject")
        signed = any(value is not None for value in (
            owner_actor_id, owner_session_token, owner_session_request))
        if signed and (type(owner_actor_id) is not str or not owner_actor_id
                       or type(owner_session_token) is not str or not owner_session_token
                       or type(owner_session_request) is not OwnerSessionLoginRequestV1):
            raise AuthorityUnavailable("Owner actor and session fields must be paired")
        if (type(permit) is not FencePermitV2
                or permit.operation not in {"read", "write"}
                or permit.namespace != authority_namespace
                or permit.subject != subject):
            raise AuthorityUnavailable("owner guard read requires exact read/write fence")
        self._core._require(credential, "owner_guard_read", authority_namespace,
                            permit.holder)
        with self._core._tx() as db:
            self._require_mode(db)
            AuthorityV2FenceStore._check_schema(db)
            AuthorityV2FenceStore._require_no_migration(db)
            namespace_row = self._core._row(db, authority_namespace)
            if (namespace_row[0] != permit.holder
                    or namespace_row[1] != permit.generation
                    or namespace_row[2] != "active"
                    or namespace_row[3] is not None
                    or namespace_row[9] != "clear"
                    or self._core._anchor(db, authority_namespace, namespace_row)
                    != permit.pinned_anchor):
                raise AuthorityUnavailable("owner guard Authority anchor is no longer current")
            row = AuthorityV2FenceStore._row(db, permit.operation_id)
            if (row is None or row[1] != authority_namespace
                    or row[2] != subject or row[3] != permit.token
                    or row[6] != "active" or row[7] != fence_canonical_bytes(permit)
                    or row[10] is not None
                    or AuthorityV2FenceStore._permit(row) != permit
                    or permit.authority_id != self._core._id(db)
                    or db.execute(
                        "SELECT 1 FROM authority_v2_mutations "
                        "WHERE namespace=? AND state='pending' LIMIT 1",
                        (authority_namespace,),
                    ).fetchone() is not None):
                raise AuthorityUnavailable("owner guard fence is no longer current")
            guard = self._checked_current_head(db, authority_namespace)
            if guard is not None and (
                    guard.authority_id != permit.authority_id
                    or guard.installation_id != installation_id
                    or namespace_ref(guard.namespace) != authority_namespace):
                raise AuthorityUnavailable("owner guard installation identity differs")
            if signed:
                request = owner_session_request
                sessions = self._owner_sessions
                source = (sessions._current_pairing_source
                          if sessions is not None else None)
                from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource

                if (guard is None
                        or type(sessions) is not AuthorityV2OwnerSessionStore
                        or type(source) is not AuthorityOwnerPairingSource
                        or source._core is not self._core
                        or request.audience != "owner"
                        or request.authority_id != permit.authority_id
                        or request.authority_namespace != authority_namespace
                        or request.installation_id != installation_id
                        or guard.authority_id != request.authority_id
                        or guard.installation_id != request.installation_id):
                    raise AuthorityUnavailable("Owner session guard identity differs")
                sessions.require_current_in_tx(
                    db, token=owner_session_token, request=request)
                source.require_current_actor_in_tx(
                    db, authority_namespace=authority_namespace,
                    installation_id=installation_id, actor_id=owner_actor_id,
                    principal=request.principal)
                row = db.execute(
                    "SELECT issue_operation_id FROM authority_owner_authorization_heads_v1 "
                    "WHERE authority_namespace=?", (authority_namespace,)).fetchone()
                pending = (self._checked_pending(db, authority_namespace, row[0])
                           if row is not None else None)
                if pending is None or pending[0].principal != request.principal:
                    raise AuthorityUnavailable("Owner session differs from current grant")
            return guard

    def observe_paid_guard_for_fence_v3(self, *, credential: object,
            authority_namespace: str, installation_id: str, subject: str,
            permit: FencePermitV2, business_operation_id: str,
            request_digest: str, phase: str):
        """Persist an actual guard observation in the same live Core fence transaction."""
        from .v3_owner_paid_guard_observation import _record_owner_paid_guard_observation_v3
        identifier(authority_namespace, 'authority_namespace')
        identifier(installation_id, 'installation_id')
        identifier(subject, 'subject')
        identifier(business_operation_id, 'business_operation_id')
        if (type(permit) is not FencePermitV2 or permit.operation!='write'
                or permit.namespace!=authority_namespace or permit.subject!=subject
                or phase not in {'schedule','acquire'}):
            raise AuthorityUnavailable('paid Owner observation requires exact named write fence')
        self._core._require(credential, 'owner_guard_read', authority_namespace, permit.holder)
        with self._core._tx() as db:
            self._require_mode(db)
            self._check_schema(db)
            AuthorityV2FenceStore._check_schema(db)
            AuthorityV2FenceStore._require_no_migration(db)
            namespace_row=self._core._row(db,authority_namespace)
            if (namespace_row[0]!=permit.holder or namespace_row[1]!=permit.generation
                    or namespace_row[2]!='active' or namespace_row[3] is not None
                    or namespace_row[9]!='clear'
                    or self._core._anchor(db,authority_namespace,namespace_row)!=permit.pinned_anchor):
                raise AuthorityUnavailable('paid Owner observation Authority anchor is no longer current')
            row=AuthorityV2FenceStore._row(db,permit.operation_id)
            if (row is None or row[1]!=authority_namespace or row[2]!=subject or row[3]!=permit.token
                    or row[6]!='active' or row[7]!=fence_canonical_bytes(permit) or row[10] is not None
                    or AuthorityV2FenceStore._permit(row)!=permit or permit.authority_id!=self._core._id(db)
                    or db.execute("SELECT 1 FROM authority_v2_mutations WHERE namespace=? AND state='pending' LIMIT 1",
                        (authority_namespace,)).fetchone() is not None):
                raise AuthorityUnavailable('paid Owner observation fence is no longer current')
            guard=self._checked_current_head(db,authority_namespace)
            if (guard is None or guard.authority_id!=permit.authority_id
                    or guard.installation_id!=installation_id
                    or namespace_ref(guard.namespace)!=authority_namespace
                    or guard.authorization_revision!=1 or guard.pending_revoke_operation_id is not None
                    or guard.minimum_revocation_revision!=0 or guard.minimum_revocation_epoch!=0):
                raise OwnerAuthorizationBarrier('paid Owner guard is not the active original issue')
            head=db.execute('SELECT authority_namespace,issue_operation_id,current_operation_id,revision,state,guard_bytes '
                'FROM authority_owner_authorization_heads_v1 WHERE authority_namespace=?',(authority_namespace,)).fetchone()
            return _record_owner_paid_guard_observation_v3(db,authority_namespace=authority_namespace,
                business_operation_id=business_operation_id,request_digest=request_digest,phase=phase,
                guard=guard,permit=permit,head=head)

    def reserve_revoke(self, *, credential: object, authority_namespace: str,
                       operation: OwnerAuthorizationOperationV1,
                       session_token: str | None = None,
                       session_request: OwnerSessionLoginRequestV1 | None = None,
                       ) -> OwnerAuthorizationReceiptV1:
        """Durably block Owner-backed content before the graph changes."""
        identifier(authority_namespace, "authority_namespace")
        if (type(operation) is not OwnerAuthorizationOperationV1
                or operation.action != "revoke"):
            raise TypeError("Owner revoke operation is required")
        self._core._require(credential, "owner_authorization_revoke", authority_namespace)
        with self._core._tx() as db:
            self._require_mode(db)
            if session_token is not None or session_request is not None:
                self._require_revoke_session(db, authority_namespace, operation,
                                             session_token, session_request)
            guard = self._checked_current_head(db, authority_namespace)
            saved = self._checked_revoke_pending(db, authority_namespace,
                                                 operation.operation_id)
            if saved is not None:
                committed = self._checked_revoke_committed(
                    db, authority_namespace, operation.operation_id)
                if (saved[0] != operation or guard != (
                        committed[1].guard if committed is not None
                        else saved[1].guard)):
                    raise AuthorityUnavailable("Owner revoke replay differs")
                return saved[1]
            if (namespace_ref(operation.namespace) != authority_namespace
                    or self._core._id(db) != operation.authority_id
                    or guard is None or guard != operation.expected_guard
                    or guard.authorization_revision != 1
                    or guard.pending_revoke_operation_id is not None
                    or operation.expected_grant_revision != 1):
                raise AuthorityUnavailable("current Owner issue head differs from revoke")
            issue_row = db.execute(
                "SELECT issue_operation_id FROM authority_owner_authorization_heads_v1 "
                "WHERE authority_namespace=?", (authority_namespace,)).fetchone()
            issue = self._checked_pending(db, authority_namespace, issue_row[0])
            if (issue is None or operation.principal != issue[0].principal
                    or operation.grant_id != issue[0].grant_id
                    or operation.installation_id != issue[0].installation_id
                    or operation.operation_id == issue[0].operation_id):
                raise AuthorityUnavailable("Owner revoke differs from issued grant")
            namespace_row = self._core._row(db, authority_namespace)
            if (namespace_row[0] is None or namespace_row[1] < 1
                    or namespace_row[2] != "active" or namespace_row[3] is not None
                    or namespace_row[9] != "clear"):
                raise AuthorityUnavailable("Owner revoke namespace is unavailable")
            AuthorityV2FenceStore._check_schema(db)
            AuthorityV2FenceStore._require_no_migration(db)
            live = db.execute(
                "SELECT operation_id FROM authority_v2_fences "
                "WHERE namespace=? AND state='active'", (authority_namespace,)
            ).fetchone()
            if live is not None:
                fence_row = AuthorityV2FenceStore._row(db, live[0])
                if (fence_row is None or fence_row[6] != "active"
                        or AuthorityV2FenceStore._permit(fence_row).operation
                        != "dispatch"):
                    raise AuthorityUnavailable("non-dispatch fence blocks Owner revoke")
            elif db.execute(
                    "SELECT 1 FROM authority_v2_mutations WHERE namespace=? "
                    "AND state='pending' LIMIT 1", (authority_namespace,)
            ).fetchone():
                raise AuthorityUnavailable("pending mutation blocks Owner revoke")
            pending_guard = OwnerAuthorizationGuardV1(
                operation.authority_id, operation.installation_id,
                operation.namespace, 1, guard.authorization_head,
                guard.minimum_revocation_revision,
                guard.minimum_revocation_epoch, operation.operation_id)
            receipt = OwnerAuthorizationReceiptV1(
                operation, "pending", "owner-revoke-pending:"
                + operation.request_digest.removeprefix("sha256:")[:48],
                pending_guard)
            db.execute(
                "INSERT INTO authority_owner_revoke_pending_v1"
                "(operation_id,authority_namespace,request_digest,operation_bytes,"
                "receipt_bytes) VALUES(?,?,?,?,?)",
                (operation.operation_id, authority_namespace,
                 operation.request_digest, canonical_bytes(operation),
                 canonical_bytes(receipt)))
            changed = db.execute(
                "UPDATE authority_owner_authorization_heads_v1 "
                "SET current_operation_id=?,guard_bytes=? "
                "WHERE authority_namespace=? AND issue_operation_id=? "
                "AND current_operation_id=? AND revision=1 AND state='active' "
                "AND guard_bytes=?",
                (operation.operation_id, canonical_bytes(pending_guard),
                 authority_namespace, issue[0].operation_id,
                 issue[0].operation_id, canonical_bytes(guard))).rowcount
            if changed != 1:
                raise AuthorityUnavailable("Owner revoke barrier CAS failed")
            return receipt

    def get_revoke_pending(self, *, credential: object,
                           authority_namespace: str, operation_id: str,
                           session_token: str | None = None,
                           session_request: OwnerSessionLoginRequestV1 | None = None,
                           ) -> OwnerAuthorizationReceiptV1 | None:
        identifier(authority_namespace, "authority_namespace")
        identifier(operation_id, "operation_id")
        self._core._require(credential, "owner_authorization_revoke", authority_namespace)
        with self._core._tx() as db:
            self._require_mode(db)
            saved = self._checked_revoke_pending(db, authority_namespace, operation_id)
            if session_token is not None or session_request is not None:
                self._require_revoke_session(db, authority_namespace,
                                             saved[0] if saved else None,
                                             session_token, session_request)
            if saved is None:
                return None
            guard = self._checked_current_head(db, authority_namespace)
            if guard != saved[1].guard:
                if self._checked_revoke_committed(db, authority_namespace,
                                                  operation_id) is None:
                    raise AuthorityUnavailable("Owner revoke pending barrier differs")
            return saved[1]

    def get_revoke_pending_for_graph_write(
            self, *, credential: object, authority_namespace: str,
            operation_id: str, installation_id: str, subject: str,
            permit: FencePermitV2) -> OwnerAuthorizationReceiptV1 | None:
        """Give the graph worker only the current durable pending barrier."""
        identifier(authority_namespace, "authority_namespace")
        identifier(operation_id, "operation_id")
        identifier(installation_id, "installation_id")
        identifier(subject, "subject")
        if (type(permit) is not FencePermitV2 or permit.operation != "write"
                or permit.namespace != authority_namespace
                or permit.subject != subject):
            raise AuthorityUnavailable("Owner revoke graph read needs exact write fence")
        self._core._require(credential, "write", authority_namespace, permit.holder)
        with self._core._tx() as db:
            self._require_mode(db)
            AuthorityV2FenceStore._check_schema(db)
            AuthorityV2FenceStore._require_no_migration(db)
            row = AuthorityV2FenceStore._row(db, permit.operation_id)
            if (row is None or row[1] != authority_namespace or row[2] != subject
                    or row[3] != permit.token or row[6] != "active"
                    or row[7] != fence_canonical_bytes(permit)
                    or row[10] is not None
                    or AuthorityV2FenceStore._permit(row) != permit
                    or permit.authority_id != self._core._id(db)):
                raise AuthorityUnavailable("Owner revoke graph write fence is stale")
            saved = self._checked_revoke_pending(db, authority_namespace, operation_id)
            if saved is None:
                return None
            guard = self._checked_current_head(db, authority_namespace)
            if (saved[0].installation_id != installation_id
                    or guard != saved[1].guard
                    or self._checked_revoke_committed(
                        db, authority_namespace, operation_id) is not None):
                raise AuthorityUnavailable("Owner revoke is not pending for graph write")
            return saved[1]

    def finalize_revoke(self, *, credential: object, authority_namespace: str,
                        operation: OwnerAuthorizationOperationV1,
                        proof: OwnerGraphCommitProofV1,
                        session_token: str | None = None,
                        session_request: OwnerSessionLoginRequestV1 | None = None,
                        ) -> OwnerAuthorizationReceiptV1:
        """Advance to revoked rev2 only after independent current graph proof."""
        identifier(authority_namespace, "authority_namespace")
        if (type(operation) is not OwnerAuthorizationOperationV1
                or operation.action != "revoke"
                or type(proof) is not OwnerGraphCommitProofV1):
            raise TypeError("exact Owner revoke operation and graph proof are required")
        self._core._require(credential, "owner_authorization_revoke", authority_namespace)
        if (namespace_ref(operation.namespace) != authority_namespace
                or proof.namespace != operation.namespace
                or proof.operation_id != operation.operation_id
                or proof.request_digest != operation.request_digest
                or proof.grant_id != operation.grant_id
                or proof.grant_digest != operation.grant_digest
                or proof.grant_revision != 2 or proof.graph_access_epoch < 2):
            raise AuthorityUnavailable("Owner revoke graph proof identity differs")
        with self._core._tx() as db:
            self._require_mode(db)
            if session_token is not None or session_request is not None:
                self._require_revoke_session(db, authority_namespace, operation,
                                             session_token, session_request)
            saved = self._checked_revoke_pending(db, authority_namespace,
                                                 operation.operation_id)
            if saved is None or saved[0] != operation:
                raise AuthorityUnavailable("exact pending Owner revoke is absent")
            committed = self._checked_revoke_committed(
                db, authority_namespace, operation.operation_id)
            if committed is not None:
                if committed[0] != proof:
                    raise AuthorityUnavailable("Owner revoke commit replay differs")
                if self._checked_current_head(db, authority_namespace) != committed[1].guard:
                    raise AuthorityUnavailable("Owner revoke committed head differs")
                return committed[1]
            if self._checked_current_head(db, authority_namespace) != saved[1].guard:
                raise AuthorityUnavailable("pending Owner revoke barrier differs")
            before = self._revoke_commit_snapshot(db, authority_namespace)
        self._verified(self._revoke_graph_commit_verifier, operation, proof)
        guard = OwnerAuthorizationGuardV1(
            operation.authority_id, operation.installation_id,
            operation.namespace, 2, canonical_digest(proof), 2,
            proof.graph_access_epoch)
        receipt = OwnerAuthorizationReceiptV1(
            operation, "committed", "owner-revoke-committed:"
            + proof.graph_receipt_digest.removeprefix("sha256:")[:48],
            guard, 2, proof.graph_access_epoch)
        with self._core._tx() as db:
            self._require_mode(db)
            saved = self._checked_revoke_pending(db, authority_namespace,
                                                 operation.operation_id)
            if saved is None or saved[0] != operation:
                raise AuthorityUnavailable("pending Owner revoke changed")
            committed = self._checked_revoke_committed(
                db, authority_namespace, operation.operation_id)
            if committed is not None:
                if committed[0] != proof:
                    raise AuthorityUnavailable("Owner revoke commit replay differs")
                return committed[1]
            if (self._checked_current_head(db, authority_namespace) != saved[1].guard
                    or self._revoke_commit_snapshot(db, authority_namespace) != before):
                raise AuthorityUnavailable("Owner revoke graph proof crossed Authority change")
            db.execute(
                "INSERT INTO authority_owner_revoke_committed_v1"
                "(operation_id,authority_namespace,proof_bytes,receipt_bytes,guard_bytes) "
                "VALUES(?,?,?,?,?)",
                (operation.operation_id, authority_namespace,
                 canonical_bytes(proof), canonical_bytes(receipt), canonical_bytes(guard)))
            changed = db.execute(
                "UPDATE authority_owner_authorization_heads_v1 "
                "SET revision=2,state='revoked',guard_bytes=? "
                "WHERE authority_namespace=? AND current_operation_id=? "
                "AND revision=1 AND state='active' AND guard_bytes=?",
                (canonical_bytes(guard), authority_namespace, operation.operation_id,
                 canonical_bytes(saved[1].guard))).rowcount
            if changed != 1:
                raise AuthorityUnavailable("Owner revoke rev2 CAS failed")
            return receipt

    def _revoke_commit_snapshot(self, db: sqlite3.Connection,
                                authority_namespace: str) -> tuple[int, tuple]:
        AuthorityV2FenceStore._check_schema(db)
        AuthorityV2FenceStore._require_no_migration(db)
        epoch = db.execute(
            "SELECT last_epoch FROM authority_v2_epochs WHERE namespace=?",
            (authority_namespace,)).fetchone()
        row = self._core._row(db, authority_namespace)
        if (row[0] is None or row[2] != "active"
                or row[3] is not None or row[9] != "clear"):
            raise AuthorityUnavailable("Owner revoke namespace is unavailable")
        return (epoch[0] if epoch else 0, row)

    def get_revoke_committed(self, *, credential: object,
                             authority_namespace: str, operation_id: str,
                             session_token: str | None = None,
                             session_request: OwnerSessionLoginRequestV1 | None = None,
                             ) -> OwnerAuthorizationReceiptV1 | None:
        identifier(authority_namespace, "authority_namespace")
        identifier(operation_id, "operation_id")
        self._core._require(credential, "owner_authorization_revoke", authority_namespace)
        with self._core._tx() as db:
            self._require_mode(db)
            saved = self._checked_revoke_pending(db, authority_namespace, operation_id)
            if session_token is not None or session_request is not None:
                self._require_revoke_session(db, authority_namespace,
                                             saved[0] if saved else None,
                                             session_token, session_request)
            committed = self._checked_revoke_committed(
                db, authority_namespace, operation_id)
            if committed is None:
                return None
            if self._checked_current_head(db, authority_namespace) != committed[1].guard:
                raise AuthorityUnavailable("Owner revoke committed head differs")
            return committed[1]


__all__ = ("AuthorityV2OwnerTicketStore", "OwnerAuthorizationBarrier")


def read_owner_migration_head_in_tx_v1(db, *, authority_namespace):
    identifier(authority_namespace, "authority_namespace")
    if not db.in_transaction:
        raise AuthorityUnavailable("Owner migration head needs pinned Authority transaction")
    AuthorityV2OwnerTicketStore._require_mode(db)
    guard = AuthorityV2OwnerTicketStore._checked_current_head(db, authority_namespace)
    if guard is None:
        if db.execute(
                "SELECT 1 FROM authority_owner_issue_pending_v1 "
                "WHERE authority_namespace=?", (authority_namespace,)
        ).fetchone():
            raise AuthorityUnavailable("uncommitted Owner issue blocks migration")
        return None
    if guard.pending_revoke_operation_id is not None:
        raise AuthorityUnavailable("pending Owner revoke blocks migration")
    row = db.execute(
        "SELECT issue_operation_id,current_operation_id,state "
        "FROM authority_owner_authorization_heads_v1 WHERE authority_namespace=?",
        (authority_namespace,)).fetchone()
    if row is None:
        raise AuthorityUnavailable("Owner migration head is absent")
    issue = AuthorityV2OwnerTicketStore._checked_pending(db, authority_namespace, row[0])
    committed_issue = AuthorityV2OwnerTicketStore._checked_committed(db, authority_namespace, row[0])
    if issue is None or committed_issue is None:
        raise AuthorityUnavailable("Owner migration issue origin differs")
    if row[2] == "active":
        return OwnerMigrationHeadV1(
            authority_namespace, guard, "active", issue[0],
            committed_issue[0], None, None, 1,
            committed_issue[0].grant_digest,
            committed_issue[0].graph_access_epoch)
    if row[2] != "revoked":
        raise AuthorityUnavailable("Owner migration state differs")
    revoke = AuthorityV2OwnerTicketStore._checked_revoke_pending(db, authority_namespace, row[1])
    committed_revoke = AuthorityV2OwnerTicketStore._checked_revoke_committed(
        db, authority_namespace, row[1])
    if revoke is None or committed_revoke is None:
        raise AuthorityUnavailable("Owner migration revoke origin differs")
    return OwnerMigrationHeadV1(
        authority_namespace, guard, "revoked", issue[0],
        committed_issue[0], revoke[0], committed_revoke[0], 2,
        committed_revoke[0].grant_digest,
        committed_revoke[0].graph_access_epoch)
