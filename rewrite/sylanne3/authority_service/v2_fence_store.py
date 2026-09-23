"""B1 durable exclusive fences inside the authority service's own SQLite DB.

The caller supplies an *already authenticated* subject and the service-current
RestoreAnchor. This store does not authenticate callers, attest anchors, or
verify a journal or a dispatch footprint. The service must do those checks before calling it, and must
not expose this connection or these methods to a plugin. It owns no parallel
activation or journal truth. One store instance owns one injected autocommit
connection; separate instances may use separate connections to the same DB.

No timeout, disconnect, or restart releases a fence. Pending mutations remain
blocked until a later, independently verified recovery implementation resolves
them; this B1 module does not append to or inspect the execution journal.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import json
import secrets
import sqlite3
import threading
import uuid

from ..runtime.restore_anchor import RestoreAnchor
from .contract import AuthorityUnavailable, identifier
from .v2_contract import (
    DeletionEvidenceV1, DeletionMutationReceiptV1, DeletionPendingV1,
    FencePermitV2, MutationReceiptV2,
    PendingMutationV2, SCHEMA, canonical_bytes, decode_bytes,
)


_VERSION = "3"
_META_DDL = "CREATE TABLE authority_v2_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
_EPOCH_DDL = "CREATE TABLE authority_v2_epochs(namespace TEXT PRIMARY KEY, last_epoch INTEGER NOT NULL CHECK(last_epoch >= 0))"
_FENCE_DDL = """CREATE TABLE authority_v2_fences(
                    operation_id TEXT PRIMARY KEY, namespace TEXT NOT NULL,
                    subject TEXT NOT NULL, token TEXT NOT NULL UNIQUE,
                    fence_epoch INTEGER NOT NULL CHECK(fence_epoch > 0),
                    revision INTEGER NOT NULL CHECK(revision >= 0),
                    state TEXT NOT NULL CHECK(state IN ('active','finished')),
                    permit BLOB NOT NULL, finish_request_id TEXT,
                    finish_request_digest TEXT, pending BLOB,
                    CHECK((state='active' AND finish_request_id IS NULL AND finish_request_digest IS NULL)
                       OR (state='finished' AND finish_request_id IS NOT NULL AND finish_request_digest IS NOT NULL)),
                    FOREIGN KEY(namespace) REFERENCES authority_v2_epochs(namespace))"""
_INDEX_DDL = "CREATE UNIQUE INDEX authority_v2_one_active ON authority_v2_fences(namespace) WHERE state='active'"
_MUTATION_DDL_V2 = """CREATE TABLE authority_v2_mutations(
    mutation_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL,
    namespace TEXT NOT NULL, subject TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','committed','cancelled_unappended')),
    conflict_keys_json TEXT NOT NULL, pending BLOB NOT NULL,
    receipt BLOB, updated_permit BLOB,
    CHECK((state='pending' AND receipt IS NULL AND updated_permit IS NULL)
       OR (state!='pending' AND receipt IS NOT NULL AND updated_permit IS NOT NULL))
)"""
_MUTATION_DDL = """CREATE TABLE authority_v2_mutations(
    mutation_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL,
    namespace TEXT NOT NULL, subject TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','committed','cancelled_unappended')),
    conflict_keys_json TEXT NOT NULL, pending BLOB NOT NULL,
    receipt BLOB, updated_permit BLOB,
    mutation_kind TEXT NOT NULL CHECK(mutation_kind IN ('execution','deletion')),
    deletion_evidence BLOB,
    CHECK((mutation_kind='execution' AND deletion_evidence IS NULL)
       OR (mutation_kind='deletion' AND deletion_evidence IS NOT NULL
           AND state!='cancelled_unappended')),
    CHECK((state='pending' AND receipt IS NULL AND updated_permit IS NULL)
       OR (state!='pending' AND receipt IS NOT NULL AND updated_permit IS NOT NULL))
)"""
_TABLES = {
    "authority_v2_meta": ("key", "value"),
    "authority_v2_epochs": ("namespace", "last_epoch"),
    "authority_v2_fences": (
        "operation_id", "namespace", "subject", "token", "fence_epoch",
        "revision", "state", "permit", "finish_request_id",
        "finish_request_digest", "pending",
    ),
    "authority_v2_mutations": (
        "mutation_id", "operation_id", "namespace", "subject",
        "request_digest", "state", "conflict_keys_json", "pending",
        "receipt", "updated_permit", "mutation_kind", "deletion_evidence",
    ),
}
_TABLES_V2 = {**_TABLES, "authority_v2_mutations":
              _TABLES["authority_v2_mutations"][:10]}


class AuthorityV2FenceStore:
    """Transactional storage primitive; caller owns authorization and journal checks."""

    def __init__(self, connection: sqlite3.Connection, *, create: bool = False,
                 lock: threading.RLock | None = None):
        if type(connection) is not sqlite3.Connection or connection.isolation_level is not None:
            raise AuthorityUnavailable("v2 fence requires an injected autocommit SQLite connection")
        db_path = connection.execute("PRAGMA database_list").fetchone()[2]
        synchronous = connection.execute("PRAGMA synchronous").fetchone()[0]
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        if (not db_path or synchronous < 2
                or journal_mode.lower() in {"off", "memory"}):
            raise AuthorityUnavailable("v2 fence requires durable service SQLite settings")
        self._db = connection
        self._lock = lock if lock is not None else threading.RLock()
        with self._tx() as db:
            present = self._v2_tables(db)
            if not present:
                if not create:
                    raise AuthorityUnavailable("v2 fence schema is absent")
                db.execute(_META_DDL)
                db.execute(_EPOCH_DDL)
                db.execute(_FENCE_DDL)
                db.execute(_INDEX_DDL)
                db.execute(_MUTATION_DDL)
                db.execute("INSERT INTO authority_v2_meta(key,value) VALUES('schema_version',?)", (_VERSION,))
            elif present != set(_TABLES):
                raise AuthorityUnavailable("partial or unknown v2 fence schema")
            self._check_schema(db)

    @staticmethod
    def _v2_tables(db: sqlite3.Connection) -> set[str]:
        return {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'authority_v2_%'")}

    @staticmethod
    def _check_schema(db: sqlite3.Connection) -> None:
        AuthorityV2FenceStore._check_schema_version(db, _VERSION)

    @staticmethod
    def _check_schema_version(db: sqlite3.Connection, version: str) -> None:
        if version not in ("2", "3"):
            raise AuthorityUnavailable("unknown v2 fence schema version")
        tables = _TABLES if version == "3" else _TABLES_V2
        objects = {(kind, name) for kind, name in db.execute(
            "SELECT type,name FROM sqlite_master WHERE name LIKE 'authority_v2_%'")}
        expected_objects = {("table", table) for table in tables} | {
            ("index", "authority_v2_one_active")}
        if objects != expected_objects:
            raise AuthorityUnavailable("unknown v2 fence schema object")
        expected_ddl = {
            "authority_v2_meta": _META_DDL,
            "authority_v2_epochs": _EPOCH_DDL,
            "authority_v2_fences": _FENCE_DDL,
            "authority_v2_mutations": (_MUTATION_DDL if version == "3"
                                        else _MUTATION_DDL_V2),
        }
        for table, expected in tables.items():
            columns = tuple(row[1] for row in db.execute(f"PRAGMA table_info({table})"))
            if columns != expected:
                raise AuthorityUnavailable("malformed v2 fence schema")
            stored_ddl = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            if stored_ddl != (expected_ddl[table],):
                raise AuthorityUnavailable("unsafe v2 fence schema migration")
        row = db.execute("SELECT value FROM authority_v2_meta WHERE key='schema_version'").fetchone()
        if row != (version,) or db.execute("SELECT count(*) FROM authority_v2_meta").fetchone()[0] != 1:
            raise AuthorityUnavailable("unknown v2 fence schema version")
        index = db.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name='authority_v2_one_active'").fetchone()
        if index != (_INDEX_DDL,):
            raise AuthorityUnavailable("v2 exclusive index is absent or unsafe")

    @staticmethod
    def upgrade_schema_2_to_3(connection: sqlite3.Connection, *,
                              lock: threading.RLock | None = None) -> None:
        """Explicit, atomic old-execution-row preserving upgrade; no live fences."""
        if type(connection) is not sqlite3.Connection or connection.isolation_level is not None:
            raise AuthorityUnavailable("schema upgrade requires service autocommit connection")
        if (not connection.execute("PRAGMA database_list").fetchone()[2]
                or connection.execute("PRAGMA synchronous").fetchone()[0] < 2):
            raise AuthorityUnavailable("schema upgrade requires durable service SQLite")
        with (lock if lock is not None else threading.RLock()):
            if connection.in_transaction:
                raise AuthorityUnavailable("schema upgrade requires no open transaction")
            connection.execute("BEGIN IMMEDIATE")
            try:
                AuthorityV2FenceStore._check_schema_version(connection, "2")
                if connection.execute("SELECT 1 FROM authority_v2_fences WHERE state='active' OR pending IS NOT NULL LIMIT 1").fetchone():
                    raise AuthorityUnavailable("live fence blocks v2 schema upgrade")
                if connection.execute("SELECT 1 FROM authority_v2_mutations WHERE state='pending' LIMIT 1").fetchone():
                    raise AuthorityUnavailable("pending mutation blocks v2 schema upgrade")
                rows = tuple(connection.execute(
                    "SELECT mutation_id,operation_id,namespace,subject,request_digest,"
                    "state,conflict_keys_json,pending,receipt,updated_permit "
                    "FROM authority_v2_mutations ORDER BY mutation_id"))
                for row in rows:
                    try:
                        pending = decode_bytes(row[7])
                        receipt = decode_bytes(row[8])
                        updated = decode_bytes(row[9])
                        keys = json.loads(row[6])
                    except (TypeError, ValueError, UnicodeError) as exc:
                        raise AuthorityUnavailable("old execution mutation is malformed") from exc
                    if (type(pending) is not PendingMutationV2
                            or type(receipt) is not MutationReceiptV2
                            or type(updated) is not FencePermitV2
                            or row[:5] != (pending.mutation_id, pending.permit.operation_id,
                                           pending.permit.namespace, pending.permit.subject,
                                           pending.request_digest)
                            or row[5] != receipt.durable_state
                            or receipt.pending != pending
                            or updated != replace(pending.permit,
                                                  revision=receipt.updated_revision,
                                                  pinned_anchor=receipt.after_anchor)
                            or row[7] != canonical_bytes(pending)
                            or row[8] != canonical_bytes(receipt)
                            or row[9] != canonical_bytes(updated)
                            or (keys is not None and type(keys) is not list)):
                        raise AuthorityUnavailable("old execution mutation identity changed")
                connection.execute("DROP TABLE authority_v2_mutations")
                connection.execute(_MUTATION_DDL)
                connection.executemany(
                    "INSERT INTO authority_v2_mutations VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
                    (row + ("execution",) for row in rows),
                )
                connection.execute("UPDATE authority_v2_meta SET value='3' WHERE key='schema_version'")
                AuthorityV2FenceStore._check_schema_version(connection, "3")
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _require_no_migration(db: sqlite3.Connection) -> None:
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_meta'").fetchone() is None:
            return  # Isolated storage tests have no Core; never a service entry.
        row = db.execute("SELECT value FROM authority_meta WHERE key='deletion_v2_migration'").fetchone()
        if row is None:
            return  # Pre-migration service prototype only.
        try:
            marker = json.loads(row[0])
        except (TypeError, ValueError) as exc:
            raise AuthorityUnavailable("malformed deletion migration blocker") from exc
        if (type(marker) is not dict
                or marker.get("schema") != "sylanne3.deletion-migration.v1"
                or marker.get("stage") != "complete"):
            raise AuthorityUnavailable("deletion migration blocks v2 fence entry")

    @contextmanager
    def _tx(self):
        with self._lock:
            if self._db.in_transaction:
                raise AuthorityUnavailable("v2 fence connection has an open transaction")
            try:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    yield self._db
                    self._db.execute("COMMIT")
                except BaseException:
                    self._db.execute("ROLLBACK")
                    raise
            except sqlite3.Error as exc:
                raise AuthorityUnavailable("v2 fence SQLite transaction failed") from exc

    @staticmethod
    def _require_anchor(anchor: RestoreAnchor, namespace: str) -> None:
        if type(anchor) is not RestoreAnchor or anchor.namespace != namespace:
            raise AuthorityUnavailable("service-current anchor namespace mismatch")

    @staticmethod
    def _permit(row) -> FencePermitV2:
        try:
            permit = decode_bytes(row[7])
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityUnavailable("malformed persisted v2 permit") from exc
        if (type(permit) is not FencePermitV2 or
                (permit.operation_id, permit.namespace, permit.subject, permit.token,
                 permit.fence_epoch, permit.revision) != row[:6]):
            raise AuthorityUnavailable("persisted v2 permit identity mismatch")
        return permit

    @staticmethod
    def _row(db, operation_id: str):
        return db.execute("SELECT operation_id,namespace,subject,token,fence_epoch,revision,state,permit,finish_request_id,finish_request_digest,pending FROM authority_v2_fences WHERE operation_id=?", (operation_id,)).fetchone()

    def begin_fence(self, *, subject: str, holder: str, operation: str,
                    current_anchor: RestoreAnchor, operation_id: str | None = None,
                    effect_id: str | None = None, command_digest: str | None = None,
                    footprint_digest: str | None = None) -> FencePermitV2:
        """Issue a service-generated token; same active operation ID is retryable."""
        identifier(subject, "subject")
        identifier(holder, "holder")
        operation_id = identifier(str(uuid.uuid4()) if operation_id is None else operation_id,
                                  "operation_id")
        if type(current_anchor) is not RestoreAnchor:
            raise AuthorityUnavailable("service-current anchor is required")
        self._require_anchor(current_anchor, current_anchor.namespace)
        namespace = current_anchor.namespace
        with self._tx() as db:
            self._check_schema(db)
            return self.begin_fence_locked(
                db, subject=subject, holder=holder, operation=operation,
                current_anchor=current_anchor, operation_id=operation_id,
                effect_id=effect_id, command_digest=command_digest,
                footprint_digest=footprint_digest)

    def begin_fence_locked(self, db: sqlite3.Connection, *, subject: str,
                           holder: str, operation: str,
                           current_anchor: RestoreAnchor, operation_id: str,
                           effect_id: str | None = None,
                           command_digest: str | None = None,
                           footprint_digest: str | None = None) -> FencePermitV2:
        """Storage step inside the caller's already-held Authority transaction."""
        identifier(subject, "subject")
        identifier(holder, "holder")
        identifier(operation_id, "operation_id")
        self._require_anchor(current_anchor, current_anchor.namespace)
        namespace = current_anchor.namespace
        self._check_schema(db)
        self._require_no_migration(db)
        old = self._row(db, operation_id)
        if old is not None:
            saved = self._permit(old)
            if (old[6] != "active" or saved.subject != subject or saved.holder != holder
                    or saved.operation != operation or saved.pinned_anchor != current_anchor
                    or saved.effect_id != effect_id or saved.command_digest != command_digest
                    or saved.footprint_digest != footprint_digest):
                raise AuthorityUnavailable("operation ID reused with different identity or completed fence")
            return saved
        if db.execute("SELECT 1 FROM authority_v2_fences WHERE namespace=? AND state='active'", (namespace,)).fetchone():
            raise AuthorityUnavailable("namespace already has an active v2 fence")
        last = db.execute("SELECT last_epoch FROM authority_v2_epochs WHERE namespace=?", (namespace,)).fetchone()
        epoch = (last[0] if last else 0) + 1
        permit = FencePermitV2(
            authority_id=current_anchor.authority_id, namespace=namespace,
            subject=subject, holder=holder, generation=current_anchor.activation_generation,
            operation=operation, operation_id=operation_id,
            token=secrets.token_urlsafe(48), fence_epoch=epoch, revision=0,
            pinned_anchor=current_anchor, effect_id=effect_id,
            command_digest=command_digest, footprint_digest=footprint_digest,
            schema=SCHEMA,
        )
        db.execute("INSERT INTO authority_v2_epochs(namespace,last_epoch) VALUES(?,?) ON CONFLICT(namespace) DO UPDATE SET last_epoch=excluded.last_epoch", (namespace, epoch))
        db.execute("INSERT INTO authority_v2_fences(operation_id,namespace,subject,token,fence_epoch,revision,state,permit) VALUES(?,?,?,?,?,?,'active',?)", (
            operation_id, namespace, subject, permit.token, epoch, 0, canonical_bytes(permit)))
        return permit

    def validate_fence(self, permit: FencePermitV2, *, subject: str,
                       current_anchor: RestoreAnchor) -> FencePermitV2:
        """Check exact active permit and current service head inside an immediate tx."""
        with self._tx() as db:
            return self.validate_fence_locked(
                db, permit, subject=subject, current_anchor=current_anchor)

    def validate_fence_locked(self, db: sqlite3.Connection, permit: FencePermitV2,
                              *, subject: str,
                              current_anchor: RestoreAnchor) -> FencePermitV2:
        """Same validation within the service's journal-frozen Authority txn."""
        if type(permit) is not FencePermitV2:
            raise AuthorityUnavailable("invalid v2 fence permit")
        identifier(subject, "subject")
        self._require_anchor(current_anchor, permit.namespace)
        self._check_schema(db)
        self._require_no_migration(db)
        row = self._row(db, permit.operation_id)
        if row is None or row[6] != "active":
            raise AuthorityUnavailable("v2 fence is absent or finished")
        saved = self._permit(row)
        if saved != permit or saved.subject != subject or saved.pinned_anchor != current_anchor:
            raise AuthorityUnavailable("v2 fence identity, revision or anchor mismatch")
        if row[10] is not None:
            raise AuthorityUnavailable("v2 fence has a pending mutation")
        return saved

    def get_operation(self, operation_id: str, *, subject: str,
                      namespace: str) -> tuple[FencePermitV2, str, PendingMutationV2 | DeletionPendingV1 | None]:
        """Read durable state after caller has reauthenticated the same subject."""
        identifier(operation_id, "operation_id")
        identifier(subject, "subject")
        identifier(namespace, "namespace")
        with self._tx() as db:
            self._check_schema(db)
            self._require_no_migration(db)
            row = self._row(db, operation_id)
            if row is None or row[1] != namespace or row[2] != subject:
                raise AuthorityUnavailable("operation unavailable for subject or namespace")
            permit = self._permit(row)
            pending = None
            if row[10] is not None:
                if row[6] != "active":
                    raise AuthorityUnavailable("finished fence retains pending mutation")
                try:
                    pending = decode_bytes(row[10])
                except (TypeError, ValueError, UnicodeError) as exc:
                    raise AuthorityUnavailable("malformed pending mutation") from exc
                if (type(pending) not in (PendingMutationV2, DeletionPendingV1)
                        or pending.permit != permit):
                    raise AuthorityUnavailable("pending mutation owner mismatch")
                mutation = self.mutation_locked(db, pending.mutation_id)
                kind, saved_pending, _, _ = self._decode_mutation_row(mutation)
                if (saved_pending != pending or mutation[4] != "pending"
                        or kind != ("execution" if type(pending) is PendingMutationV2
                                    else "deletion")):
                    raise AuthorityUnavailable("pending mutation ledger differs from fence")
            elif db.execute("SELECT 1 FROM authority_v2_mutations WHERE operation_id=? AND state='pending' LIMIT 1",
                            (operation_id,)).fetchone():
                raise AuthorityUnavailable("pending mutation ledger lacks fence marker")
            return permit, row[6], pending

    def record_pending(self, pending: PendingMutationV2, *, subject: str,
                       current_anchor: RestoreAnchor,
                       conflict_keys: tuple[str, ...] | None = None) -> PendingMutationV2:
        """Persist a prepare marker only; journal append/recovery is future work."""
        with self._tx() as db:
            self._check_schema(db)
            self._require_no_migration(db)
            return self.record_pending_locked(
                db, pending, subject=subject, current_anchor=current_anchor,
                conflict_keys=conflict_keys)

    def record_pending_locked(self, db: sqlite3.Connection,
                              pending: PendingMutationV2, *, subject: str,
                              current_anchor: RestoreAnchor,
                              conflict_keys: tuple[str, ...] | None = None,
                              ) -> PendingMutationV2:
        """Same operation inside the service's already open Authority txn."""
        if type(pending) is not PendingMutationV2:
            raise AuthorityUnavailable("invalid pending mutation")
        self._require_no_migration(db)
        permit = pending.permit
        identifier(subject, "subject")
        self._require_anchor(current_anchor, permit.namespace)
        if conflict_keys is not None:
            if (type(conflict_keys) is not tuple or len(conflict_keys) > 64
                    or len(set(conflict_keys)) != len(conflict_keys)):
                raise AuthorityUnavailable("invalid verified conflict keys")
            for key in conflict_keys:
                identifier(key, "conflict key")
            conflict_keys = tuple(sorted(conflict_keys))
        keys_json = json.dumps(conflict_keys, separators=(",", ":"))
        row = self._row(db, permit.operation_id)
        if row is None or row[6] != "active":
            raise AuthorityUnavailable("pending mutation has no active fence")
        saved = self._permit(row)
        if saved != permit or saved.subject != subject or saved.pinned_anchor != current_anchor:
            raise AuthorityUnavailable("pending mutation fence identity or anchor mismatch")
        prior = db.execute("SELECT operation_id,namespace,subject,request_digest,state,conflict_keys_json,pending,mutation_kind,deletion_evidence FROM authority_v2_mutations WHERE mutation_id=?", (pending.mutation_id,)).fetchone()
        if prior is not None:
            if prior != (permit.operation_id, permit.namespace, subject,
                         pending.request_digest, "pending", keys_json,
                         canonical_bytes(pending), "execution", None) or row[10] != canonical_bytes(pending):
                raise AuthorityUnavailable("mutation ID reused with different identity or digest")
            return pending
        if row[10] is not None:
            raise AuthorityUnavailable("fence already has another pending mutation")
        db.execute("INSERT INTO authority_v2_mutations(mutation_id,operation_id,namespace,subject,request_digest,state,conflict_keys_json,pending,mutation_kind,deletion_evidence) VALUES(?,?,?,?,?,'pending',?,?,'execution',NULL)", (
            pending.mutation_id, permit.operation_id, permit.namespace, subject,
            pending.request_digest, keys_json, canonical_bytes(pending)))
        db.execute("UPDATE authority_v2_fences SET pending=? WHERE operation_id=?", (
            canonical_bytes(pending), permit.operation_id))
        return pending

    @staticmethod
    def mutation_locked(db: sqlite3.Connection, mutation_id: str):
        identifier(mutation_id, "mutation_id")
        return db.execute("SELECT operation_id,namespace,subject,request_digest,state,conflict_keys_json,pending,receipt,updated_permit,mutation_kind,deletion_evidence FROM authority_v2_mutations WHERE mutation_id=?", (mutation_id,)).fetchone()

    @staticmethod
    def _decode_mutation_row(row):
        if row is None or len(row) != 11:
            raise AuthorityUnavailable("mutation row is absent or malformed")
        try:
            pending = decode_bytes(row[6])
            if row[9] == "execution":
                keys = json.loads(row[5])
                if (type(pending) is not PendingMutationV2 or row[10] is not None
                        or (keys is not None and type(keys) is not list)):
                    raise ValueError("execution mutation kind or evidence mismatch")
            elif row[9] == "deletion":
                evidence = decode_bytes(row[10])
                if (type(pending) is not DeletionPendingV1
                        or type(evidence) is not DeletionEvidenceV1
                        or pending.evidence != evidence
                        or row[10] != canonical_bytes(evidence)
                        or row[5] != "null"):
                    raise ValueError("deletion mutation kind or evidence mismatch")
            else:
                raise ValueError("unknown mutation kind")
            if (row[:4] != (pending.permit.operation_id, pending.permit.namespace,
                            pending.permit.subject, pending.request_digest)
                    or row[6] != canonical_bytes(pending)):
                raise ValueError("mutation identity mismatch")
            if row[4] == "pending":
                if row[7] is not None or row[8] is not None:
                    raise ValueError("pending mutation has result")
                return row[9], pending, None, None
            receipt, updated = decode_bytes(row[7]), decode_bytes(row[8])
            expected_receipt = (MutationReceiptV2 if row[9] == "execution"
                                else DeletionMutationReceiptV1)
            if (type(receipt) is not expected_receipt
                    or type(updated) is not FencePermitV2
                    or receipt.pending != pending or receipt.durable_state != row[4]
                    or updated != replace(pending.permit,
                                          revision=receipt.updated_revision,
                                          pinned_anchor=receipt.after_anchor)
                    or row[7] != canonical_bytes(receipt)
                    or row[8] != canonical_bytes(updated)):
                raise ValueError("mutation result identity mismatch")
            return row[9], pending, receipt, updated
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityUnavailable("persisted mutation kind, evidence or result is invalid") from exc

    def get_mutation(self, mutation_id: str, *, subject: str, namespace: str):
        """Strict kind-aware internal result read; no deletion write capability."""
        identifier(subject, "subject")
        identifier(namespace, "namespace")
        with self._tx() as db:
            self._check_schema(db)
            self._require_no_migration(db)
            row = self.mutation_locked(db, mutation_id)
            if row is None or row[1:3] != (namespace, subject):
                raise AuthorityUnavailable("mutation unavailable for subject or namespace")
            return self._decode_mutation_row(row)

    def finish_mutation_locked(self, db: sqlite3.Connection,
                               receipt: MutationReceiptV2, *, subject: str,
                               ) -> FencePermitV2:
        """Persist receipt and new permit in the caller's Authority CAS txn."""
        if type(receipt) is not MutationReceiptV2:
            raise AuthorityUnavailable("invalid mutation receipt")
        self._require_no_migration(db)
        pending = receipt.pending
        permit = pending.permit
        row = self._row(db, permit.operation_id)
        mutation = self.mutation_locked(db, pending.mutation_id)
        if (row is None or row[6] != "active" or row[10] != canonical_bytes(pending)
                or self._permit(row) != permit or mutation is None
                or mutation[:5] != (permit.operation_id, permit.namespace, subject,
                                    pending.request_digest, "pending")
                or mutation[6] != canonical_bytes(pending)
                or mutation[9:] != ("execution", None)):
            raise AuthorityUnavailable("pending mutation no longer owns fence")
        updated = replace(permit, revision=receipt.updated_revision,
                          pinned_anchor=receipt.after_anchor)
        db.execute("UPDATE authority_v2_fences SET revision=?,permit=?,pending=NULL WHERE operation_id=?", (
            updated.revision, canonical_bytes(updated), permit.operation_id))
        db.execute("UPDATE authority_v2_mutations SET state=?,receipt=?,updated_permit=? WHERE mutation_id=?", (
            receipt.durable_state, canonical_bytes(receipt),
            canonical_bytes(updated), pending.mutation_id))
        return updated

    def finish_fence(self, permit: FencePermitV2, *, subject: str,
                     current_anchor: RestoreAnchor, request_id: str,
                     request_digest: str) -> None:
        """Finish exactly once; same request identity is idempotent after restart."""
        with self._tx() as db:
            self.finish_fence_locked(
                db, permit, subject=subject, current_anchor=current_anchor,
                request_id=request_id, request_digest=request_digest)

    def finish_fence_locked(self, db: sqlite3.Connection, permit: FencePermitV2,
                            *, subject: str, current_anchor: RestoreAnchor,
                            request_id: str, request_digest: str) -> None:
        """Finish within the caller's already-held Authority transaction."""
        if type(permit) is not FencePermitV2:
            raise AuthorityUnavailable("invalid v2 fence permit")
        identifier(subject, "subject")
        identifier(request_id, "request_id")
        # Reuse strict DTO digest validation without accepting a caller token.
        if (type(request_digest) is not str or len(request_digest) != 71
                or not request_digest.startswith("sha256:")
                or any(c not in "0123456789abcdef" for c in request_digest[7:])):
            raise ValueError("invalid finish request digest")
        self._require_anchor(current_anchor, permit.namespace)
        self._check_schema(db)
        self._require_no_migration(db)
        row = self._row(db, permit.operation_id)
        if row is None:
            raise AuthorityUnavailable("v2 fence is absent")
        saved = self._permit(row)
        if saved != permit or saved.subject != subject:
            raise AuthorityUnavailable("v2 fence identity or revision mismatch")
        if row[6] == "finished":
            if (row[8], row[9]) == (request_id, request_digest):
                return
            raise AuthorityUnavailable("finish request identity or digest conflict")
        if row[6] != "active":
            raise AuthorityUnavailable("unknown v2 fence state")
        self._require_anchor(current_anchor, permit.namespace)
        if saved.pinned_anchor != current_anchor:
            raise AuthorityUnavailable("v2 fence anchor mismatch")
        if row[10] is not None:
            raise AuthorityUnavailable("pending mutation blocks fence finish")
        db.execute("UPDATE authority_v2_fences SET state='finished',finish_request_id=?,finish_request_digest=? WHERE operation_id=?", (request_id, request_digest, permit.operation_id))


__all__ = ["AuthorityV2FenceStore"]
