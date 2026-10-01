"""Exact operation-keyed immutable C09 original archive and continuations."""
from __future__ import annotations

import json
import sqlite3

from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import canonical, digest

ARCHIVE_DDL = """CREATE TABLE authority_c09_originals_archive_v1(
 namespace TEXT NOT NULL, operation_id TEXT NOT NULL, original_kind TEXT NOT NULL,
 original_digest TEXT NOT NULL, original_json TEXT NOT NULL,
 maintenance_generation INTEGER NOT NULL CHECK(maintenance_generation>=0),
 PRIMARY KEY(namespace,operation_id,original_kind)) STRICT"""
CONTINUATION_DDL = """CREATE TABLE authority_c09_deletion_continuations_v1(
 namespace TEXT NOT NULL, operation_id TEXT NOT NULL,
 transition_json TEXT NOT NULL, transition_digest TEXT NOT NULL,
 PRIMARY KEY(namespace,operation_id)) STRICT"""
BINDINGS_DDL = """CREATE TABLE authority_c09_recovery_bindings_v1(
 namespace TEXT NOT NULL, operation_id TEXT NOT NULL,
 bindings_json TEXT NOT NULL, bindings_digest TEXT NOT NULL,
 PRIMARY KEY(namespace,operation_id)) STRICT"""
SOURCE_SEAL_DDL = """CREATE TABLE authority_c09_execution_source_seals_v4(
 namespace TEXT NOT NULL, operation_id TEXT NOT NULL,
 seal_json TEXT NOT NULL, seal_digest TEXT NOT NULL,
 PRIMARY KEY(namespace,operation_id)) STRICT"""
SOURCE_PIN_DDL = """CREATE TABLE authority_c09_execution_source_pins_v4(
 namespace TEXT NOT NULL, operation_id TEXT NOT NULL,
 pin_json TEXT NOT NULL, pin_digest TEXT NOT NULL,
 PRIMARY KEY(namespace,operation_id)) STRICT"""
FACT_FRAME_DDL = """CREATE TABLE authority_c09_recovery_fact_frames_v4(
 namespace TEXT NOT NULL, operation_id TEXT NOT NULL,
 facts_json TEXT NOT NULL, facts_digest TEXT NOT NULL,
 PRIMARY KEY(namespace,operation_id)) STRICT"""

SINGLETONS = {
    "authority_execution_redaction_seals_v3": ("seal", "seal_json", "seal_digest"),
    "authority_execution_redaction_sidecar_pins_v3": ("sidecar_pin", "pin_json", "pin_digest"),
    "authority_execution_redaction_switches_v3": ("switch", "switch_json", "switch_digest"),
    "authority_execution_recovery_facts_pins_v4": ("facts_pin", "pin_json", "pin_digest"),
    "authority_execution_recovery_facts_v4": ("facts", "facts_json", "facts_digest"),
    "authority_c09_graph_rebase_issues_v1": ("graph_issue", "issue_json", "issue_digest"),
}


def install_c09_archive_schema_v1(db):
    for ddl in (ARCHIVE_DDL, CONTINUATION_DDL, BINDINGS_DDL, SOURCE_SEAL_DDL, SOURCE_PIN_DDL, FACT_FRAME_DDL):
        name = ddl.split("(", 1)[0].rsplit(" ", 1)[-1]
        db.execute(ddl.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
        if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() != (ddl,):
            raise AuthorityUnavailable("C09 archive schema differs: " + name)
        for action in ("UPDATE", "DELETE"):
            db.execute(f"CREATE TRIGGER IF NOT EXISTS {name}_no_{action.lower()} BEFORE {action} ON {name} BEGIN SELECT RAISE(ABORT,'C09 immutable lineage'); END")


def archive_exact_original_v1(db, *, namespace, operation_id, original_kind,
                              original_digest, original_json, maintenance_generation):
    """Preserve the stored bytes, including old serialization and old digest."""
    row = db.execute("SELECT original_digest,original_json,maintenance_generation FROM authority_c09_originals_archive_v1 WHERE namespace=? AND operation_id=? AND original_kind=?", (namespace, operation_id, original_kind)).fetchone()
    value = (original_digest, original_json, maintenance_generation)
    if row is not None:
        if row != value:
            raise AuthorityUnavailable("C09 archive original conflict")
        return
    db.execute("INSERT INTO authority_c09_originals_archive_v1 VALUES(?,?,?,?,?,?)", (
        namespace, operation_id, original_kind, *value))


def read_archived_original_v1(db, *, namespace, operation_id, original_kind):
    row = db.execute("SELECT original_digest,original_json,maintenance_generation FROM authority_c09_originals_archive_v1 WHERE namespace=? AND operation_id=? AND original_kind=?", (namespace, operation_id, original_kind)).fetchone()
    if row is None:
        return None
    return dict(original_digest=row[0], original_json=row[1], maintenance_generation=row[2])


def read_current_deletion_continuation_v1_locked(db, *, namespace, operation_id):
    row = db.execute("SELECT transition_json,transition_digest FROM authority_c09_deletion_continuations_v1 WHERE namespace=? AND operation_id=?", (namespace, operation_id)).fetchone()
    if row is None:
        return None
    original = json.loads(row[0])
    if (original.get("namespace"), original.get("operation_id")) != (namespace, operation_id) or original.get("transition_digest") != row[1] or digest({k:v for k,v in original.items() if k != "transition_digest"}) != row[1]:
        raise AuthorityUnavailable("C09 continuation commitment differs")
    return original
