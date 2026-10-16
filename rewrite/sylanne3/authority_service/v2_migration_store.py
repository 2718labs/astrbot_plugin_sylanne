"""Durable v2 migration ledger inside the existing Authority SQLite file.

This is a passive storage primitive. It cannot authenticate an administrator,
verify graph receipts, or advance a namespace without the migration service.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
import hashlib
import json
import sqlite3
import threading

from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2
from .contract import AuthorityUnavailable, identifier
from .v2_migration_contract import (
    MigrationPermitV2, MigrationPlanV2, MigrationStageReceiptV2,
    MigrationStatusV2, SourceSnapshotReceiptV2, TargetRecoveryReceiptV2,
)


_META_DDL = "CREATE TABLE authority_migration_v2_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT"
_PLAN_DDL = """CREATE TABLE authority_migration_v2_plans(
    transfer_id TEXT PRIMARY KEY, namespace TEXT NOT NULL,
    plan_json TEXT NOT NULL, phase TEXT NOT NULL
        CHECK(phase IN ('begun','revoked','target_prepared','activated')),
    current_anchor_json TEXT NOT NULL, source_permit_json TEXT NOT NULL,
    target_permit_json TEXT, source_snapshot_json TEXT, target_recovery_json TEXT,
    FOREIGN KEY(namespace) REFERENCES authority_namespaces(namespace)
) STRICT"""
_LIVE_DDL = "CREATE UNIQUE INDEX authority_migration_v2_one_live ON authority_migration_v2_plans(namespace) WHERE phase!='activated'"
_RECEIPT_DDL = """CREATE TABLE authority_migration_v2_receipts(
    transfer_id TEXT NOT NULL, phase TEXT NOT NULL,
    stage_index INTEGER NOT NULL CHECK(stage_index BETWEEN 1 AND 4),
    request_id TEXT NOT NULL UNIQUE, request_digest TEXT NOT NULL,
    receipt_digest TEXT NOT NULL, receipt_json TEXT NOT NULL,
    PRIMARY KEY(transfer_id,phase),
    FOREIGN KEY(transfer_id) REFERENCES authority_migration_v2_plans(transfer_id)
) STRICT"""
_RECEIPT_NO_UPDATE_DDL = """CREATE TRIGGER authority_migration_v2_receipts_no_update
BEFORE UPDATE ON authority_migration_v2_receipts
BEGIN SELECT RAISE(ABORT,'append-only migration receipt'); END"""
_RECEIPT_NO_DELETE_DDL = """CREATE TRIGGER authority_migration_v2_receipts_no_delete
BEFORE DELETE ON authority_migration_v2_receipts
BEGIN SELECT RAISE(ABORT,'append-only migration receipt'); END"""
_OBJECTS = {
    ("table", "authority_migration_v2_meta"): _META_DDL,
    ("table", "authority_migration_v2_plans"): _PLAN_DDL,
    ("index", "authority_migration_v2_one_live"): _LIVE_DDL,
    ("table", "authority_migration_v2_receipts"): _RECEIPT_DDL,
    ("trigger", "authority_migration_v2_receipts_no_update"):
        _RECEIPT_NO_UPDATE_DDL,
    ("trigger", "authority_migration_v2_receipts_no_delete"):
        _RECEIPT_NO_DELETE_DDL,
}
_STAGES = {"begun": 1, "revoked": 2, "target_prepared": 3, "activated": 4}


def _encode(value) -> str:
    return json.dumps(
        asdict(value) if is_dataclass(value) else value,
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False)


def _receipt_digest(raw: str) -> str:
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _checked_receipt(raw: str, digest: str) -> MigrationStageReceiptV2:
    if digest != _receipt_digest(raw):
        raise AuthorityUnavailable("stored migration receipt digest differs")
    return _decode(raw, MigrationStageReceiptV2)


def _requirements(value: dict) -> SnapshotRequirementsV2:
    return SnapshotRequirementsV2(**{
        **value, "namespace": NamespaceId(**value["namespace"]),
    })


def _decode(raw: str, kind):
    try:
        data = json.loads(raw)
        if kind is MigrationPlanV2:
            result = kind(**{
                **data, "namespace_id": NamespaceId(**data["namespace_id"]),
                "before_anchor": RestoreAnchor(**data["before_anchor"]),
            })
        elif kind is MigrationPermitV2:
            result = kind(**{
                **data, "pinned_anchor": RestoreAnchor(**data["pinned_anchor"]),
            })
        elif kind is SourceSnapshotReceiptV2:
            result = kind(**{
                **data, "requirements": _requirements(data["requirements"]),
            })
        elif kind is TargetRecoveryReceiptV2:
            result = kind(**{
                **data, "current_requirements": _requirements(
                    data["current_requirements"]),
            })
        elif kind is MigrationStageReceiptV2:
            result = kind(**{
                **data, "after_anchor": RestoreAnchor(**data["after_anchor"]),
                "permit": (_decode(_encode(data["permit"]), MigrationPermitV2)
                           if data["permit"] is not None else None),
            })
        elif kind is RestoreAnchor:
            result = kind(**data)
        else:
            raise TypeError("unknown migration DTO")
        if _encode(result) != raw:
            raise ValueError("noncanonical migration DTO")
        return result
    except (TypeError, ValueError, KeyError, UnicodeError) as exc:
        raise AuthorityUnavailable("persisted migration DTO is invalid") from exc


class AuthorityV2MigrationStore:
    """One ledger in the Core DB; all transition methods require its transaction."""

    def __init__(self, connection: sqlite3.Connection, *, lock: threading.RLock,
                 create: bool = False):
        if (type(connection) is not sqlite3.Connection
                or connection.isolation_level is not None
                or not connection.execute("PRAGMA database_list").fetchone()[2]
                or connection.execute("PRAGMA synchronous").fetchone()[0] < 2
                or connection.execute("PRAGMA journal_mode").fetchone()[0].lower()
                   in {"off", "memory"}):
            raise AuthorityUnavailable("migration ledger needs durable Authority SQLite")
        self._db, self._lock = connection, lock
        with self._tx() as db:
            present = self._objects(db)
            if not present:
                if not create:
                    raise AuthorityUnavailable("v2 migration schema is absent")
                for ddl in _OBJECTS.values():
                    db.execute(ddl)
                db.execute("INSERT INTO authority_migration_v2_meta VALUES('version','2')")
            self.check_schema_locked(db)
            from .migration_snapshot_certificate_members_v1 import install_migration_snapshot_certificate_members_schema_v1
            install_migration_snapshot_certificate_members_schema_v1(db, create=create)

    @staticmethod
    def _objects(db):
        return {(kind, name): sql for kind, name, sql in db.execute(
            "SELECT type,name,sql FROM sqlite_master "
            "WHERE name LIKE 'authority_migration_v2_%'")}

    @classmethod
    def check_schema_locked(cls, db):
        if (cls._objects(db) != _OBJECTS
                or tuple(db.execute("SELECT key,value FROM authority_migration_v2_meta"))
                   != (("version", "2"),)):
            raise AuthorityUnavailable("unknown or malformed v2 migration schema")

    @contextmanager
    def _tx(self):
        with self._lock:
            if self._db.in_transaction:
                raise AuthorityUnavailable("migration store connection is busy")
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    @classmethod
    def status_locked(cls, db, transfer_id: str) -> MigrationStatusV2 | None:
        identifier(transfer_id, "transfer_id")
        cls.check_schema_locked(db)
        row = db.execute(
            "SELECT namespace,plan_json,phase,current_anchor_json,"
            "source_permit_json,target_permit_json,source_snapshot_json,"
            "target_recovery_json FROM authority_migration_v2_plans "
            "WHERE transfer_id=?", (transfer_id,)).fetchone()
        if row is None:
            return None
        plan = _decode(row[1], MigrationPlanV2)
        anchor = _decode(row[3], RestoreAnchor)
        source_permit = _decode(row[4], MigrationPermitV2)
        target_permit = (_decode(row[5], MigrationPermitV2)
                         if row[5] is not None else None)
        source_snapshot = (_decode(row[6], SourceSnapshotReceiptV2)
                           if row[6] is not None else None)
        target_recovery = (_decode(row[7], TargetRecoveryReceiptV2)
                           if row[7] is not None else None)
        receipt_rows = tuple(db.execute(
            "SELECT phase,stage_index,request_id,request_digest,"
            "receipt_digest,receipt_json "
            "FROM authority_migration_v2_receipts WHERE transfer_id=? "
            "ORDER BY stage_index", (transfer_id,)))
        receipts = tuple(_checked_receipt(item[5], item[4])
                         for item in receipt_rows)
        if (row[0] != plan.namespace or plan.transfer_id != transfer_id
                or source_permit.transfer_id != transfer_id
                or source_permit.kind != "source_snapshot"
                or source_permit.holder != plan.source_holder
                or source_permit.installation_id != plan.source_installation_id
                or source_permit.generation
                   != plan.before_anchor.activation_generation
                or (target_permit is not None and (
                    target_permit.kind != "target_recovery"
                    or target_permit.holder != plan.target_holder
                    or target_permit.installation_id != plan.target_installation_id
                    or target_permit.generation
                       != plan.before_anchor.activation_generation + 2))
                or (source_snapshot is not None and (
                    source_snapshot.transfer_id != transfer_id
                    or source_snapshot.permit_token != source_permit.token
                    or source_snapshot.source_installation_id
                       != plan.source_installation_id))
                or (target_recovery is not None and (
                    target_permit is None or source_snapshot is None
                    or target_recovery.transfer_id != transfer_id
                    or target_recovery.permit_token != target_permit.token
                    or target_recovery.snapshot_digest
                       != source_snapshot.snapshot_digest))
                or len(receipts) != _STAGES[row[2]]
                or any(_STAGES[receipt.phase] != index
                       for index, receipt in enumerate(receipts, 1))
                or any((item[0], item[1], item[2], item[3])
                       != (receipt.phase, index, receipt.request_id,
                           receipt.request_digest)
                       for index, (item, receipt) in enumerate(
                           zip(receipt_rows, receipts), 1))
                or receipts[-1].after_anchor != anchor
                or (source_snapshot is None) != (row[2] == "begun")
                or (target_permit is None) != (row[2] in {"begun", "revoked"})
                or (target_recovery is None) != (row[2] != "activated")):
            raise AuthorityUnavailable("migration ledger state is inconsistent")
        return MigrationStatusV2(plan, row[2], anchor, receipts,
                                 source_permit, target_permit,
                                 source_snapshot, target_recovery)

    @classmethod
    def replay_locked(cls, db, transfer_id: str, phase: str,
                      request_id: str, request_digest: str
                      ) -> MigrationStageReceiptV2 | None:
        cls.check_schema_locked(db)
        saved = db.execute(
            "SELECT request_id,request_digest,receipt_digest,receipt_json "
            "FROM authority_migration_v2_receipts WHERE transfer_id=? AND phase=?",
            (transfer_id, phase)).fetchone()
        if saved is not None:
            receipt = _checked_receipt(saved[3], saved[2])
            if (saved[:2] != (request_id, request_digest)
                    or (receipt.transfer_id, receipt.phase,
                        receipt.request_id, receipt.request_digest)
                       != (transfer_id, phase, request_id, request_digest)):
                raise AuthorityUnavailable("migration phase request differs")
            return receipt
        if db.execute(
                "SELECT 1 FROM authority_migration_v2_receipts WHERE request_id=?",
                (request_id,)).fetchone():
            raise AuthorityUnavailable("migration request ID reused")
        return None

    @classmethod
    def _save_receipt(cls, db, receipt: MigrationStageReceiptV2):
        encoded = _encode(receipt)
        db.execute(
            "INSERT INTO authority_migration_v2_receipts VALUES(?,?,?,?,?,?,?)",
            (receipt.transfer_id, receipt.phase, _STAGES[receipt.phase],
             receipt.request_id, receipt.request_digest,
             _receipt_digest(encoded), encoded))

    @classmethod
    def begin_locked(cls, db, plan: MigrationPlanV2,
                     permit: MigrationPermitV2,
                     receipt: MigrationStageReceiptV2):
        cls.check_schema_locked(db)
        if db.execute(
                "SELECT 1 FROM authority_migration_v2_plans "
                "WHERE namespace=? AND phase!='activated' LIMIT 1",
                (plan.namespace,)).fetchone():
            raise AuthorityUnavailable("namespace already has a live transfer")
        db.execute(
            "INSERT INTO authority_migration_v2_plans VALUES(?,?,?,?,?,?,?,?,?)",
            (plan.transfer_id, plan.namespace, _encode(plan), "begun",
             _encode(receipt.after_anchor), _encode(permit), None, None, None))
        cls._save_receipt(db, receipt)

    @classmethod
    def advance_locked(cls, db, *, transfer_id: str, old_phase: str,
                       receipt: MigrationStageReceiptV2,
                       source_snapshot: SourceSnapshotReceiptV2 | None = None,
                       target_permit: MigrationPermitV2 | None = None,
                       target_recovery: TargetRecoveryReceiptV2 | None = None):
        cls.check_schema_locked(db)
        if (old_phase, receipt.phase) not in {
                ("begun", "revoked"), ("revoked", "target_prepared"),
                ("target_prepared", "activated")}:
            raise AuthorityUnavailable("invalid migration transition")
        changed = db.execute(
            "UPDATE authority_migration_v2_plans SET phase=?,current_anchor_json=?,"
            "source_snapshot_json=COALESCE(?,source_snapshot_json),"
            "target_permit_json=COALESCE(?,target_permit_json),"
            "target_recovery_json=COALESCE(?,target_recovery_json) "
            "WHERE transfer_id=? AND phase=?",
            (receipt.phase, _encode(receipt.after_anchor),
             _encode(source_snapshot) if source_snapshot is not None else None,
             _encode(target_permit) if target_permit is not None else None,
             _encode(target_recovery) if target_recovery is not None else None,
             transfer_id, old_phase)).rowcount
        if changed != 1:
            raise AuthorityUnavailable("migration stage CAS failed")
        cls._save_receipt(db, receipt)


__all__ = ["AuthorityV2MigrationStore"]
