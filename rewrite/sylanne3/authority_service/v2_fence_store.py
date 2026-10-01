"""B1 durable exclusive fences inside the authority service's own SQLite DB.

The caller supplies an *already authenticated* subject and the service-current
RestoreAnchor. This store does not authenticate callers, attest anchors, or
verify a journal or attest a dispatch footprint's issuer. It does verify the
canonical footprint bytes against the permit and request digest. The service
must verify the issuer before calling it and must not expose this connection
or these methods to a plugin. It owns no parallel
activation or journal truth. One store instance owns one injected autocommit
connection; separate instances may use separate connections to the same DB.

No timeout, disconnect, or restart releases a fence. Pending mutations remain
blocked until a later, independently verified recovery implementation resolves
them; this B1 module does not append to or inspect the execution journal.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, replace
import hashlib
import json
import secrets
import sqlite3
import threading
import uuid

from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import canonical_digest
from ..runtime_journal import RecoveryConstraintFootprint
from .contract import AuthorityUnavailable, identifier
from .local_bridge import constraint_keys_from_footprint
from .v2_contract import (
    DeletionEvidenceV1, DeletionMutationReceiptV1, DeletionPendingV1,
    FencePermitV2, FenceNeverBegunReceiptV2, MutationReceiptV2,
    PendingMutationV2, SCHEMA, canonical_bytes, decode_bytes, to_wire,
)


_VERSION = "5"
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
_MUTATION_DDL_V3 = """CREATE TABLE authority_v2_mutations(
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
_MUTATION_DDL = """CREATE TABLE authority_v2_mutations(
    mutation_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL,
    namespace TEXT NOT NULL, subject TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','committed','cancelled_unappended')),
    conflict_keys_json TEXT NOT NULL, pending BLOB NOT NULL,
    receipt BLOB, updated_permit BLOB,
    mutation_kind TEXT NOT NULL CHECK(mutation_kind IN ('execution','deletion')),
    deletion_evidence BLOB, footprint BLOB,
    CHECK((mutation_kind='execution' AND deletion_evidence IS NULL AND footprint IS NOT NULL)
       OR (mutation_kind='deletion' AND deletion_evidence IS NOT NULL
           AND footprint IS NULL AND state!='cancelled_unappended')),
    CHECK((state='pending' AND receipt IS NULL AND updated_permit IS NULL)
       OR (state!='pending' AND receipt IS NOT NULL AND updated_permit IS NOT NULL))
)"""
_NEVER_BEGUN_DDL = """CREATE TABLE authority_v2_never_begun(
    operation_id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL, receipt BLOB NOT NULL
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
        "footprint",
    ),
    "authority_v2_never_begun": (
        "operation_id", "request_id", "request_digest", "receipt",
    ),
}
_TABLES_V4 = {key: value for key, value in _TABLES.items()
              if key != "authority_v2_never_begun"}
_TABLES_V2 = {**_TABLES_V4, "authority_v2_mutations":
              _TABLES["authority_v2_mutations"][:10]}
_TABLES_V3 = {**_TABLES_V4, "authority_v2_mutations":
              _TABLES["authority_v2_mutations"][:12]}


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
                db.execute(_NEVER_BEGUN_DDL)
                db.execute("INSERT INTO authority_v2_meta(key,value) VALUES('schema_version',?)", (_VERSION,))
            elif present == set(_TABLES_V4):
                # V4->V5 only adds an empty tombstone table; perform it under
                # the same immediate transaction after validating the old DDL.
                self._check_schema_version(db, "4")
                db.execute(_NEVER_BEGUN_DDL)
                db.execute("UPDATE authority_v2_meta SET value='5' "
                           "WHERE key='schema_version'")
            elif present != set(_TABLES):
                raise AuthorityUnavailable("partial or unknown v2 fence schema")
            self._check_schema(db)

    @staticmethod
    def _v2_tables(db: sqlite3.Connection) -> set[str]:
        return {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'authority_v2_%'")}

    @staticmethod
    def require_idle_owner_write_in_tx(db: sqlite3.Connection,
                                       authority_namespace: str) -> None:
        """Serialize Owner session/key changes with an active content write."""
        if not AuthorityV2FenceStore._v2_tables(db):
            return
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
            raise AuthorityUnavailable("Owner session/key change waits for v2 namespace work")

    @staticmethod
    def require_idle_migration_in_tx(db: sqlite3.Connection,
                                     namespace: str) -> None:
        """No ordinary or pending work may cross the source freeze boundary."""
        AuthorityV2FenceStore._check_schema(db)
        AuthorityV2FenceStore._require_no_migration(db)
        if db.execute(
                "SELECT 1 FROM authority_v2_fences WHERE namespace=? "
                "AND (state='active' OR pending IS NOT NULL) LIMIT 1",
                (namespace,)).fetchone() or db.execute(
                "SELECT 1 FROM authority_v2_mutations WHERE namespace=? "
                "AND state='pending' LIMIT 1", (namespace,)).fetchone():
            raise AuthorityUnavailable("v2 namespace has active or pending work")

    @staticmethod
    def _check_schema(db: sqlite3.Connection) -> None:
        AuthorityV2FenceStore._check_schema_version(db, _VERSION)

    @staticmethod
    def _check_schema_version(db: sqlite3.Connection, version: str) -> None:
        if version not in ("2", "3", "4", "5"):
            raise AuthorityUnavailable("unknown v2 fence schema version")
        try:
            row = db.execute(
                "SELECT value FROM authority_v2_meta WHERE key='schema_version'").fetchone()
            count = db.execute("SELECT count(*) FROM authority_v2_meta").fetchone()[0]
        except sqlite3.Error as exc:
            raise AuthorityUnavailable("malformed v2 fence schema") from exc
        if row != (version,) or count != 1:
            raise AuthorityUnavailable("v2 fence schema version requires explicit migration")
        tables = {"2": _TABLES_V2, "3": _TABLES_V3,
                  "4": _TABLES_V4, "5": _TABLES}[version]
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
            "authority_v2_mutations": {
                "2": _MUTATION_DDL_V2, "3": _MUTATION_DDL_V3,
                "4": _MUTATION_DDL, "5": _MUTATION_DDL,
            }[version],
            "authority_v2_never_begun": _NEVER_BEGUN_DDL,
        }
        for table, expected in tables.items():
            columns = tuple(row[1] for row in db.execute(f"PRAGMA table_info({table})"))
            if columns != expected:
                raise AuthorityUnavailable("malformed v2 fence schema")
            stored_ddl = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            if stored_ddl != (expected_ddl[table],):
                raise AuthorityUnavailable("unsafe v2 fence schema migration")
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
                connection.execute(_MUTATION_DDL_V3)
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
    def upgrade_schema_3_to_4(connection: sqlite3.Connection, *,
                              lock: threading.RLock | None = None) -> None:
        """Explicit empty-ledger upgrade; old execution rows lack recoverable limits."""
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
                AuthorityV2FenceStore._check_schema_version(connection, "3")
                if connection.execute(
                        "SELECT 1 FROM authority_v2_fences WHERE state='active' "
                        "OR pending IS NOT NULL LIMIT 1").fetchone():
                    raise AuthorityUnavailable("live fence blocks footprint schema upgrade")
                if connection.execute(
                        "SELECT 1 FROM authority_v2_mutations LIMIT 1").fetchone():
                    raise AuthorityUnavailable(
                        "old mutation lacks a complete recovery footprint; HOLD")
                if connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' "
                        "AND name='authority_namespaces'").fetchone():
                    if connection.execute(
                            "SELECT 1 FROM authority_namespaces WHERE execution_seq>0 "
                            "LIMIT 1").fetchone():
                        raise AuthorityUnavailable(
                            "old execution history lacks recovery footprints; HOLD")
                connection.execute("DROP TABLE authority_v2_mutations")
                connection.execute(_MUTATION_DDL)
                connection.execute(
                    "UPDATE authority_v2_meta SET value='4' WHERE key='schema_version'")
                AuthorityV2FenceStore._check_schema_version(connection, "4")
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    @staticmethod
    def upgrade_schema_4_to_5(connection: sqlite3.Connection, *,
                              lock: threading.RLock | None = None) -> None:
        """Add a durable operation-ID tombstone in an explicit schema upgrade."""
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
                AuthorityV2FenceStore._check_schema_version(connection, "4")
                connection.execute(_NEVER_BEGUN_DDL)
                connection.execute(
                    "UPDATE authority_v2_meta SET value='5' WHERE key='schema_version'")
                AuthorityV2FenceStore._check_schema_version(connection, "5")
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _canonical_footprint(pending: PendingMutationV2,
                             footprint: RecoveryConstraintFootprint) -> bytes:
        if type(footprint) is not RecoveryConstraintFootprint:
            raise AuthorityUnavailable("complete recovery footprint required")
        raw = footprint._json().encode("utf-8")
        request = json.dumps({
            "permit": to_wire(pending.permit), "mutation_id": pending.mutation_id,
            "footprint": json.loads(raw), "phase": "prepared",
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if (footprint.namespace != pending.permit.namespace
                or footprint.effect_id != pending.permit.effect_id
                or pending.permit.footprint_digest !=
                    "sha256:" + hashlib.sha256(raw).hexdigest()
                or pending.request_digest !=
                    "sha256:" + hashlib.sha256(request).hexdigest()):
            raise AuthorityUnavailable("recovery footprint identity or digest mismatch")
        return raw

    @staticmethod
    def _decode_footprint(pending: PendingMutationV2,
                          encoded: bytes) -> RecoveryConstraintFootprint:
        try:
            footprint = RecoveryConstraintFootprint._from_json(encoded.decode("utf-8"))
            if encoded != AuthorityV2FenceStore._canonical_footprint(pending, footprint):
                raise ValueError("noncanonical footprint")
            return footprint
        except (AttributeError, TypeError, ValueError, KeyError, UnicodeError) as exc:
            raise AuthorityUnavailable("persisted recovery footprint is invalid") from exc

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

    def reject_unbegun_content_fence_locked(
        self, db: sqlite3.Connection, *, subject: str, installation_id: str,
        holder: str, generation: int, operation_id: str,
        current_anchor: RestoreAnchor, request_id: str, request_digest: str,
    ) -> FenceNeverBegunReceiptV2:
        """Atomically reserve a never-issued operation ID, or replay its exact proof."""
        self._check_schema(db)
        self._require_no_migration(db)
        receipt = FenceNeverBegunReceiptV2(
            authority_id=current_anchor.authority_id,
            namespace=current_anchor.namespace, subject=subject,
            installation_id=installation_id, holder=holder,
            generation=generation, operation_id=operation_id,
            pinned_anchor=current_anchor, request_id=request_id,
            request_digest=request_digest,
        )
        # Operation IDs are global in this store. A foreign namespace or subject
        # must never be reported as absent to this caller.
        if self._row(db, operation_id) is not None:
            raise AuthorityUnavailable("operation ID already has a fence")
        if db.execute(
                "SELECT 1 FROM authority_v2_mutations WHERE operation_id=? LIMIT 1",
                (operation_id,)).fetchone():
            raise AuthorityUnavailable("operation has mutation history")
        old = db.execute(
            "SELECT request_id,request_digest,receipt FROM authority_v2_never_begun "
            "WHERE operation_id=?", (operation_id,)).fetchone()
        if old is not None:
            try:
                saved = decode_bytes(old[2])
            except (TypeError, ValueError, UnicodeError) as exc:
                raise AuthorityUnavailable("malformed never-begun receipt") from exc
            if (type(saved) is not FenceNeverBegunReceiptV2
                    or old != (saved.request_id, saved.request_digest,
                               canonical_bytes(saved))
                    or saved != receipt):
                raise AuthorityUnavailable("never-begun operation identity differs")
            return saved
        if db.execute(
                "SELECT 1 FROM authority_v2_never_begun WHERE request_id=?",
                (request_id,)).fetchone():
            raise AuthorityUnavailable("never-begun request ID was reused")
        db.execute(
            "INSERT INTO authority_v2_never_begun"
            "(operation_id,request_id,request_digest,receipt) VALUES(?,?,?,?)",
            (operation_id, request_id, request_digest, canonical_bytes(receipt)))
        return receipt

    def begin_fence(self, *, subject: str, holder: str, operation: str,
                    current_anchor: RestoreAnchor, operation_id: str | None = None,
                    effect_id: str | None = None, command_digest: str | None = None,
                    footprint_digest: str | None = None) -> FencePermitV2:
        """Issue a service-generated token; same active operation ID is retryable."""
        if operation in {"model_egress", "accounting"}:
            raise AuthorityUnavailable(
                "special fence requires atomic typed service preparation")
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
        if operation in {"migrate", "recovery"}:
            raise AuthorityUnavailable("migration permits require the dedicated management service")
        if operation == "accounting" and (effect_id is not None or footprint_digest is not None
                                          or type(command_digest) is not str):
            raise AuthorityUnavailable("typed accounting binding digest required")
        self._require_anchor(current_anchor, current_anchor.namespace)
        namespace = current_anchor.namespace
        self._check_schema(db)
        self._require_no_migration(db)
        if db.execute(
                "SELECT 1 FROM authority_v2_never_begun WHERE operation_id=?",
                (operation_id,)).fetchone():
            raise AuthorityUnavailable("operation ID was durably rejected before begin")
        old = self._row(db, operation_id)
        if old is not None:
            saved = self._permit(old)
            if (old[6] != "active" or saved.subject != subject or saved.holder != holder
                    or saved.operation != operation or saved.pinned_anchor != current_anchor
                    or saved.effect_id != effect_id or saved.command_digest != command_digest
                    or saved.footprint_digest != footprint_digest):
                raise AuthorityUnavailable("operation ID reused with different identity or completed fence")
            return saved
        from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
        require_lifecycle_admission_in_tx_v1(db, namespace,
            action="accounting" if operation == "accounting" else "new_" + operation,
            original_claimed=operation == "accounting")
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
                       footprint: RecoveryConstraintFootprint | None = None,
                       conflict_keys: tuple[str, ...] | None = None) -> PendingMutationV2:
        """Persist the full recovery footprint with the prepare marker."""
        with self._tx() as db:
            self._check_schema(db)
            self._require_no_migration(db)
            return self.record_pending_locked(
                db, pending, subject=subject, current_anchor=current_anchor,
                footprint=footprint, conflict_keys=conflict_keys)

    def record_pending_locked(self, db: sqlite3.Connection,
                              pending: PendingMutationV2, *, subject: str,
                              current_anchor: RestoreAnchor,
                              footprint: RecoveryConstraintFootprint | None = None,
                              conflict_keys: tuple[str, ...] | None = None,
                              ) -> PendingMutationV2:
        """Same operation inside the service's already open Authority txn."""
        if type(pending) is not PendingMutationV2:
            raise AuthorityUnavailable("invalid pending mutation")
        self._require_no_migration(db)
        permit = pending.permit
        identifier(subject, "subject")
        self._require_anchor(current_anchor, permit.namespace)
        raw_footprint = self._canonical_footprint(pending, footprint)
        expected_keys = constraint_keys_from_footprint(footprint)
        if conflict_keys is not None:
            if type(conflict_keys) is not tuple or len(conflict_keys) > 64:
                raise AuthorityUnavailable("invalid verified conflict keys")
            if tuple(sorted(conflict_keys)) != expected_keys:
                raise AuthorityUnavailable("verified conflict keys differ from recovery footprint")
        conflict_keys = expected_keys
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
        prior = db.execute("SELECT operation_id,namespace,subject,request_digest,state,conflict_keys_json,pending,mutation_kind,deletion_evidence,footprint FROM authority_v2_mutations WHERE mutation_id=?", (pending.mutation_id,)).fetchone()
        if prior is not None:
            if prior != (permit.operation_id, permit.namespace, subject,
                         pending.request_digest, "pending", keys_json,
                         canonical_bytes(pending), "execution", None,
                         raw_footprint) or row[10] != canonical_bytes(pending):
                raise AuthorityUnavailable("mutation ID reused with different identity or digest")
            return pending
        if row[10] is not None:
            raise AuthorityUnavailable("fence already has another pending mutation")
        db.execute("INSERT INTO authority_v2_mutations(mutation_id,operation_id,namespace,subject,request_digest,state,conflict_keys_json,pending,mutation_kind,deletion_evidence,footprint) VALUES(?,?,?,?,?,'pending',?,?,'execution',NULL,?)", (
            pending.mutation_id, permit.operation_id, permit.namespace, subject,
            pending.request_digest, keys_json, canonical_bytes(pending),
            raw_footprint))
        db.execute("UPDATE authority_v2_fences SET pending=? WHERE operation_id=?", (
            canonical_bytes(pending), permit.operation_id))
        return pending

    @staticmethod
    def mutation_locked(db: sqlite3.Connection, mutation_id: str):
        identifier(mutation_id, "mutation_id")
        return db.execute("SELECT operation_id,namespace,subject,request_digest,state,conflict_keys_json,pending,receipt,updated_permit,mutation_kind,deletion_evidence,footprint FROM authority_v2_mutations WHERE mutation_id=?", (mutation_id,)).fetchone()

    @classmethod
    def verify_current_deletion_bridge_locked(
            cls, db: sqlite3.Connection, *, core, receipt,
            original_permit: FencePermitV2, current_anchor: RestoreAnchor,
            current_permit: FencePermitV2) -> None:
        """Authenticate the installed storage transition for one accepted deletion."""
        from .c09_originals_archive_v1 import read_current_deletion_continuation_v1_locked

        if (core is None or getattr(core, "_db", None) is not db
                or not db.in_transaction
                or type(receipt) is not DeletionMutationReceiptV1
                or receipt.pending.target_phase != "accepted"):
            raise AuthorityUnavailable("installed accepted deletion bridge required")
        namespace = receipt.pending.permit.namespace
        operation_id = receipt.pending.deletion_operation_id
        transition = read_current_deletion_continuation_v1_locked(
            db, namespace=namespace, operation_id=operation_id)
        if transition is None:
            raise AuthorityUnavailable("accepted deletion storage transition is absent")
        authenticated = core.verify_c09_deletion_transition_v1(
            namespace=namespace, operation_id=operation_id,
            transition=transition, db=db)
        if (authenticated != transition
                or transition["accepted_receipt_digest"] != canonical_digest(receipt)
                or transition["original_fence_permit_digest"] != canonical_digest(original_permit)
                or transition["before_anchor"] != asdict(receipt.after_anchor)
                or transition["after_anchor"] != asdict(current_anchor)
                or transition["continuation_permit"] != asdict(current_permit)):
            raise AuthorityUnavailable("accepted deletion bridge differs from originals")

    @classmethod
    def require_prior_deletion_transition_locked(cls, db: sqlite3.Connection,
                                                 pending: DeletionPendingV1, *, core=None) -> None:
        """Bind a later phase to the one committed original, without a side table."""
        if type(pending) is not DeletionPendingV1:
            raise AuthorityUnavailable("typed deletion transition required")
        if pending.source_phase == "absent":
            return
        if pending.evidence.deletion_epoch != pending.deletion_epoch:
            raise AuthorityUnavailable("graph barrier deletion epoch differs from request")
        matches = []
        for row in db.execute(
                "SELECT operation_id,namespace,subject,request_digest,state,"
                "conflict_keys_json,pending,receipt,updated_permit,mutation_kind,"
                "deletion_evidence,footprint FROM authority_v2_mutations "
                "WHERE namespace=? AND mutation_kind='deletion' AND state='committed'",
                (pending.permit.namespace,)):
            kind, prior, receipt, updated = cls._decode_mutation_row(row)
            if (kind == "deletion"
                    and prior.deletion_operation_id == pending.deletion_operation_id
                    and prior.target_phase == pending.source_phase):
                matches.append((prior, receipt, updated))
        if len(matches) != 1:
            raise AuthorityUnavailable("unique prior deletion phase receipt required")
        prior, receipt, updated = matches[0]
        bridged_storage = False
        if receipt.after_anchor != pending.before_anchor or updated != pending.permit:
            if pending.source_phase != "accepted":
                raise AuthorityUnavailable("deletion phase anchor differs from prior original")
            cls.verify_current_deletion_bridge_locked(
                db, core=core, receipt=receipt, original_permit=updated,
                current_anchor=pending.before_anchor, current_permit=pending.permit)
            bridged_storage = True
        if (prior.permit.operation_id != pending.permit.operation_id
                or prior.permit.subject != pending.permit.subject
                or prior.permit.holder != pending.permit.holder
                or prior.permit.generation != pending.permit.generation
                or prior.request_digest != pending.request_digest
                or prior.closure_roots != pending.closure_roots
                or prior.deletion_epoch != pending.deletion_epoch
                or prior.policy_ref != pending.policy_ref):
            raise AuthorityUnavailable("deletion phase differs from prior original")
        if pending.source_phase == "accepted" and (
                prior.evidence.graph_version != pending.evidence.graph_version
                or prior.evidence.incarnation != pending.evidence.incarnation
                or prior.evidence.access_epoch != pending.evidence.access_epoch
                or prior.evidence.barrier_scope_digest
                   != pending.evidence.barrier_scope_digest):
            # A real selected C09 transition may change only the physical
            # Graph incarnation. All original barrier scope/version/epochs
            # remain exact, and the signed old→new certificate qualifies it.
            if not bridged_storage:
                raise AuthorityUnavailable("cleanup differs from accepted graph barrier")
            context = core.require_current_storage_generation_locked(db,
                namespace=pending.permit.namespace, action="maintenance")
            prepared = context.prepared_original
            certificate = None if prepared is None else prepared["graph_certificate_original"]
            if (certificate is None or prepared["operation_id"] != pending.deletion_operation_id
                    or prepared["accepted_receipt_digest"] != canonical_digest(receipt)
                    or certificate["accepted_receipt_digest"] != canonical_digest(receipt)
                    or (certificate["authority_id"], certificate["namespace"], certificate["operation_id"]) !=
                       (pending.permit.authority_id, pending.permit.namespace, pending.deletion_operation_id)
                    or certificate["old_incarnation"] != prior.evidence.incarnation
                    or certificate["new_incarnation"] != pending.evidence.incarnation
                    or prior.evidence.graph_version != "graph-epoch-" + str(certificate["old_graph_epoch"])
                    or certificate["old_access_epoch"] != prior.evidence.access_epoch
                    or prior.evidence.graph_version != pending.evidence.graph_version
                    or prior.evidence.access_epoch != pending.evidence.access_epoch
                    or prior.evidence.barrier_scope_digest != pending.evidence.barrier_scope_digest
                    or pending.evidence.barrier_scope_digest != "sha256:" + certificate["source_closure_digest"]
                    or pending.evidence.deletion_epoch != prior.evidence.deletion_epoch):
                raise AuthorityUnavailable("C09 cleanup does not follow the exact authenticated old Graph barrier")

    def record_deletion_pending_locked(self, db: sqlite3.Connection,
                                       pending: DeletionPendingV1, *, subject: str,
                                       current_anchor: RestoreAnchor, core=None) -> DeletionPendingV1:
        """Durably prepare one typed phase under the caller's Authority lock.

        The caller must first verify the phase-specific Owner/graph/cleanup
        original. This storage primitive does not make that trust decision.
        """
        if type(pending) is not DeletionPendingV1:
            raise AuthorityUnavailable("typed deletion pending required")
        identifier(subject, "subject")
        self._check_schema(db)
        self._require_no_migration(db)
        permit = pending.permit
        self._require_anchor(current_anchor, permit.namespace)
        if (permit.subject != subject or permit.pinned_anchor != current_anchor
                or pending.before_anchor != current_anchor):
            raise AuthorityUnavailable("deletion preparation anchor or subject differs")
        live = db.execute(
            "SELECT holder,generation,phase,transfer_id,target,revocation_epoch,"
            "deletion_journal_id,deletion_seq,deletion_digest,deletion_phase,"
            "execution_journal_id,execution_seq,execution_digest,anchor_nonce "
            "FROM authority_namespaces WHERE namespace=?",
            (permit.namespace,)).fetchone()
        expected_phase = {"absent": "clear", "pending": "pending",
                          "accepted": "accepted"}.get(pending.source_phase)
        if (live is None or expected_phase is None
                or live[0:5] != (permit.holder, permit.generation, "active", None, None)
                or live[5:9] != (current_anchor.revocation_epoch,
                                  current_anchor.deletion_journal_id,
                                  current_anchor.deletion_seq,
                                  current_anchor.deletion_digest)
                or live[9] != expected_phase
                or live[10:14] != (current_anchor.execution_journal_id,
                                    current_anchor.execution_seq,
                                    current_anchor.execution_digest,
                                    current_anchor.proof)):
            raise AuthorityUnavailable("live deletion phase or anchor differs")
        if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='authority_scoped_erasure_v2'").fetchone():
            from .v2_scoped_erasure_store import AuthorityV2ScopedErasureStore

            marker = AuthorityV2ScopedErasureStore._marker(db)
            if (marker is None or marker["stage"] != "complete"
                    or marker["namespace"] != permit.namespace
                    or not AuthorityV2ScopedErasureStore._table(db)):
                raise AuthorityUnavailable("scoped deletion migration is incomplete")
            scoped = db.execute(
                "SELECT active_operation_id,aggregate_phase,active_epoch "
                "FROM authority_scoped_erasure_v2 WHERE namespace=?",
                (permit.namespace,)).fetchone()
            if (scoped is None
                    or scoped != (
                        pending.deletion_operation_id,
                        "accepted" if pending.source_phase == "accepted"
                        else "pending", pending.deletion_epoch)):
                raise AuthorityUnavailable("scoped deletion reservation differs")
        row = self._row(db, permit.operation_id)
        if (row is None or row[6] != "active" or self._permit(row) != permit):
            raise AuthorityUnavailable("deletion preparation has no active fence")
        self.require_prior_deletion_transition_locked(db, pending, core=core)
        prior = self.mutation_locked(db, pending.mutation_id)
        if prior is not None:
            kind, saved, receipt, updated = self._decode_mutation_row(prior)
            if (kind != "deletion" or saved != pending or receipt is not None
                    or updated is not None or row[10] != canonical_bytes(pending)):
                raise AuthorityUnavailable("deletion mutation ID reused")
            return pending
        if row[10] is not None:
            raise AuthorityUnavailable("fence already has a pending mutation")
        db.execute(
            "INSERT INTO authority_v2_mutations(mutation_id,operation_id,namespace,"
            "subject,request_digest,state,conflict_keys_json,pending,mutation_kind,"
            "deletion_evidence,footprint) VALUES(?,?,?,?,?,'pending','null',?,'deletion',?,NULL)",
            (pending.mutation_id, permit.operation_id, permit.namespace, subject,
             pending.request_digest, canonical_bytes(pending),
             canonical_bytes(pending.evidence)))
        if db.execute(
                "UPDATE authority_v2_fences SET pending=? WHERE operation_id=? "
                "AND state='active' AND pending IS NULL",
                (canonical_bytes(pending), permit.operation_id)).rowcount != 1:
            raise AuthorityUnavailable("deletion preparation fence CAS failed")
        return pending

    @staticmethod
    def _decode_mutation_row(row):
        if row is None or len(row) != 12:
            raise AuthorityUnavailable("mutation row is absent or malformed")
        try:
            pending = decode_bytes(row[6])
            if row[9] == "execution":
                keys = json.loads(row[5])
                if (type(pending) is not PendingMutationV2 or row[10] is not None
                        or type(keys) is not list):
                    raise ValueError("execution mutation kind or evidence mismatch")
                footprint = AuthorityV2FenceStore._decode_footprint(pending, row[11])
                if (row[11] != footprint._json().encode("utf-8")
                        or tuple(keys) != constraint_keys_from_footprint(footprint)):
                    raise ValueError("execution recovery limits differ from conflict keys")
            elif row[9] == "deletion":
                evidence = decode_bytes(row[10])
                if (type(pending) is not DeletionPendingV1
                        or type(evidence) is not DeletionEvidenceV1
                        or pending.evidence != evidence
                        or row[10] != canonical_bytes(evidence)
                        or row[5] != "null" or row[11] is not None):
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
        except (TypeError, ValueError, UnicodeError, AuthorityUnavailable) as exc:
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

    def get_recovery_footprint(self, mutation_id: str, *, subject: str,
                               namespace: str) -> RecoveryConstraintFootprint:
        """Return exact Authority-persisted limits after subject and ledger checks."""
        identifier(subject, "subject")
        identifier(namespace, "namespace")
        with self._tx() as db:
            self._check_schema(db)
            self._require_no_migration(db)
            row = self.mutation_locked(db, mutation_id)
            if row is None or row[1:3] != (namespace, subject):
                raise AuthorityUnavailable("mutation unavailable for subject or namespace")
            kind, pending, _, _ = self._decode_mutation_row(row)
            if kind != "execution":
                raise AuthorityUnavailable("mutation has no execution recovery footprint")
            return self._decode_footprint(pending, row[11])

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
                or mutation[9] != "execution" or mutation[10] is not None):
            raise AuthorityUnavailable("pending mutation no longer owns fence")
        self._decode_mutation_row(mutation)
        updated = replace(permit, revision=receipt.updated_revision,
                          pinned_anchor=receipt.after_anchor)
        db.execute("UPDATE authority_v2_fences SET revision=?,permit=?,pending=NULL WHERE operation_id=?", (
            updated.revision, canonical_bytes(updated), permit.operation_id))
        db.execute("UPDATE authority_v2_mutations SET state=?,receipt=?,updated_permit=? WHERE mutation_id=?", (
            receipt.durable_state, canonical_bytes(receipt),
            canonical_bytes(updated), pending.mutation_id))
        return updated

    def finish_deletion_mutation_locked(
            self, db: sqlite3.Connection, receipt: DeletionMutationReceiptV1,
            *, subject: str) -> FencePermitV2:
        """Store one original deletion result in the Authority CAS transaction."""
        if type(receipt) is not DeletionMutationReceiptV1:
            raise AuthorityUnavailable("typed deletion receipt required")
        self._check_schema(db)
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
                or mutation[9] != "deletion"
                or mutation[10] != canonical_bytes(pending.evidence)
                or mutation[11] is not None):
            raise AuthorityUnavailable("deletion pending no longer owns fence")
        kind, saved, prior, updated = self._decode_mutation_row(mutation)
        if kind != "deletion" or saved != pending or prior is not None or updated is not None:
            raise AuthorityUnavailable("deletion pending record differs")
        updated = replace(permit, revision=receipt.updated_revision,
                          pinned_anchor=receipt.after_anchor)
        changed_fence = db.execute(
            "UPDATE authority_v2_fences SET revision=?,permit=?,pending=NULL "
            "WHERE operation_id=? AND state='active' AND revision=? AND pending=?",
            (updated.revision, canonical_bytes(updated), permit.operation_id,
             permit.revision, canonical_bytes(pending))).rowcount
        changed_mutation = db.execute(
            "UPDATE authority_v2_mutations SET state='committed',receipt=?,updated_permit=? "
            "WHERE mutation_id=? AND state='pending' AND pending=? AND mutation_kind='deletion'",
            (canonical_bytes(receipt), canonical_bytes(updated), pending.mutation_id,
             canonical_bytes(pending))).rowcount
        if (changed_fence, changed_mutation) != (1, 1):
            raise AuthorityUnavailable("deletion result CAS failed")
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
        if permit.operation == "model_egress":
            raise AuthorityUnavailable(
                "model_egress requires typed durable observation before finish; HOLD")
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

    def finish_observed_model_egress_locked(self, db: sqlite3.Connection,
                                            permit: FencePermitV2, *, intent,
                                            current_anchor: RestoreAnchor) -> None:
        """Close only the original typed model fence with its complete durable observation."""
        self.finish_terminal_model_egress_locked(
            db, permit, intent=intent, current_anchor=current_anchor,
            status="completed")

    @staticmethod
    def model_terminal_finish_digest(intent, permit: FencePermitV2,
                                     status: str,
                                     observation_digest: str | None = None) -> str:
        if status == "not_dispatched" and observation_digest is None:
            return "sha256:" + canonical_digest({
                "status": status, "call_id": intent.call_id,
                "operation_id": intent.operation_id, "token": permit.token})
        if status in {"completed", "unknown"} and observation_digest is not None:
            return "sha256:" + observation_digest
        raise AuthorityUnavailable("invalid model egress terminal digest")

    def finish_terminal_model_egress_locked(self, db: sqlite3.Connection,
                                            permit: FencePermitV2, *, intent,
                                            current_anchor: RestoreAnchor,
                                            status: str) -> None:
        """Atomically close a typed model fence after its terminal ledger state exists."""
        from .v2_model_egress_contract import ModelEgressIntentV1
        from .v2_model_egress_store import AuthorityV2ModelEgressStore
        if (db is not self._db or not db.in_transaction
                or type(permit) is not FencePermitV2
                or type(intent) is not ModelEgressIntentV1
                or permit.operation != "model_egress"):
            raise AuthorityUnavailable("typed active model fence transaction required")
        self._require_anchor(current_anchor, permit.namespace)
        self._check_schema(db)
        self._require_no_migration(db)
        row = self._row(db, permit.operation_id)
        if row is None:
            raise AuthorityUnavailable("typed model fence is absent")
        saved = self._permit(row)
        if (saved != permit or permit.pinned_anchor != current_anchor
                or (intent.authority_id, intent.namespace, intent.subject,
                    intent.operation_id, intent.fence_token, intent.fence_epoch,
                    intent.fence_revision, intent.anchor_digest) !=
                   (permit.authority_id, permit.namespace, permit.subject,
                    permit.operation_id, permit.token, permit.fence_epoch,
                    permit.revision, canonical_digest(asdict(permit.pinned_anchor)))):
            raise AuthorityUnavailable("typed model fence identity or anchor mismatch")
        binding = db.execute(
            "SELECT operation_id,token FROM authority_model_egress_bindings_v1 WHERE call_id=?",
            (intent.call_id,),
        ).fetchone()
        if binding != (intent.operation_id, intent.fence_token):
            raise AuthorityUnavailable("typed model fence lacks atomic call binding")
        if status not in {"completed", "unknown", "not_dispatched"}:
            raise AuthorityUnavailable("invalid model egress terminal status")
        # The strict read rechecks canonical body, digest, and original identity.
        recovery = AuthorityV2ModelEgressStore._read(db, intent.call_id)
        expected_state = {"completed": "observed", "unknown": "unknown",
                          "not_dispatched": "prepared"}[status]
        if recovery is None or recovery.intent != intent or recovery.state != expected_state:
            raise AuthorityUnavailable("complete original provider observation or unsent state is absent")
        if status == "not_dispatched":
            finish_digest = self.model_terminal_finish_digest(intent, permit, status)
        else:
            if recovery.content_erased:
                raise AuthorityUnavailable("complete original provider observation is absent")
            AuthorityV2ModelEgressStore._read_observation_locked(db, intent)
            finish_digest = self.model_terminal_finish_digest(
                intent, permit, status, recovery.observation_digest)
        if row[6] == "finished":
            if (row[8], row[9]) == (intent.call_id, finish_digest):
                return
            raise AuthorityUnavailable("typed model finish identity conflict")
        if row[6] != "active" or row[10] is not None:
            raise AuthorityUnavailable("typed model fence is not finishable")
        updated = db.execute(
            "UPDATE authority_v2_fences SET state='finished',finish_request_id=?,finish_request_digest=? "
            "WHERE operation_id=? AND state='active' AND token=? AND revision=? AND pending IS NULL",
            (intent.call_id, finish_digest, permit.operation_id, permit.token, permit.revision),
        )
        if updated.rowcount != 1:
            raise AuthorityUnavailable("typed model fence finish lost CAS")


__all__ = ["AuthorityV2FenceStore"]
