"""Durable write epoch for the Authority side of final P2 admission.

SQLite triggers cover every persistent user table in the Authority database,
including stores with their own transaction helpers and other connections.
The schema cookie catches DDL between the two P2 checks. A missing or altered
trigger is repaired only before taking a snapshot; malformed objects fail
closed. This global epoch deliberately makes unrelated namespace writes cause
a conservative retry.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import sqlite3

from .contract import AuthorityUnavailable


_TABLE = "authority_dispatch_admission_epoch_v1"
_DDL = ("CREATE TABLE authority_dispatch_admission_epoch_v1 "
        "(id INTEGER PRIMARY KEY CHECK(id=1), "
        "epoch INTEGER NOT NULL CHECK(epoch>=0)) STRICT")
_UPDATE_GUARD = ("CREATE TRIGGER authority_dispatch_epoch_no_decrease_v1 "
                 "BEFORE UPDATE ON authority_dispatch_admission_epoch_v1 "
                 "WHEN NEW.epoch<=OLD.epoch "
                 "BEGIN SELECT RAISE(ABORT,'admission epoch must advance'); END")
_DELETE_GUARD = ("CREATE TRIGGER authority_dispatch_epoch_no_delete_v1 "
                 "BEFORE DELETE ON authority_dispatch_admission_epoch_v1 "
                 "BEGIN SELECT RAISE(ABORT,'admission epoch is durable'); END")


@dataclass(frozen=True, slots=True)
class AuthorityAdmissionStampV1:
    epoch: int
    schema_version: int


def _object_sql(db: sqlite3.Connection, kind: str, name: str) -> str | None:
    row = db.execute(
        "SELECT sql FROM sqlite_master WHERE type=? AND name=?", (kind, name)
    ).fetchone()
    return None if row is None else row[0]


def _require_trigger(db: sqlite3.Connection, name: str, ddl: str) -> None:
    stored = _object_sql(db, "trigger", name)
    if stored is None:
        db.execute(ddl)
    elif stored != ddl:
        raise AuthorityUnavailable("Authority admission trigger differs")


def current_admission_stamp_in_tx(db: sqlite3.Connection) -> AuthorityAdmissionStampV1:
    """Install missing coverage while holding the caller's IMMEDIATE tx.

    The caller compares this exact stamp before and after the graph callback.
    The post-callback transaction must perform its other current checks before
    inserting a handoff start, since that insertion advances this epoch.
    """
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise AuthorityUnavailable("Authority admission epoch needs Core transaction")
    stored = _object_sql(db, "table", _TABLE)
    if stored is None:
        db.execute(_DDL)
        db.execute(f"INSERT INTO {_TABLE}(id,epoch) VALUES(1,0)")
    elif stored != _DDL:
        raise AuthorityUnavailable("Authority admission epoch schema differs")
    _require_trigger(db, "authority_dispatch_epoch_no_decrease_v1", _UPDATE_GUARD)
    _require_trigger(db, "authority_dispatch_epoch_no_delete_v1", _DELETE_GUARD)
    tables = tuple(row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' AND name<>? ORDER BY name", (_TABLE,)))
    for table in tables:
        quoted = '"' + table.replace('"', '""') + '"'
        digest = hashlib.sha256(table.encode("utf-8")).hexdigest()[:24]
        for action in ("INSERT", "UPDATE", "DELETE"):
            name = f"authority_dispatch_epoch_{action.lower()}_{digest}_v1"
            ddl = (f"CREATE TRIGGER {name} AFTER {action} ON {quoted} "
                   "BEGIN UPDATE authority_dispatch_admission_epoch_v1 "
                   "SET epoch=epoch+1 WHERE id=1; END")
            _require_trigger(db, name, ddl)
    row = db.execute(f"SELECT id,epoch FROM {_TABLE}").fetchall()
    if len(row) != 1 or row[0][0] != 1 or type(row[0][1]) is not int:
        raise AuthorityUnavailable("Authority admission epoch row differs")
    schema_version = db.execute("PRAGMA schema_version").fetchone()[0]
    return AuthorityAdmissionStampV1(row[0][1], schema_version)


__all__ = ("AuthorityAdmissionStampV1", "current_admission_stamp_in_tx")
