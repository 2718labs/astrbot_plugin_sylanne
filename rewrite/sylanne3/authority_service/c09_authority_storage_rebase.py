"""Build C09's fresh Core and journal files from frozen installed originals.

This module produces a candidate.  The installer owns the writer freeze, Core
signature checks, durable SWITCHED anchor, handle replacement, and cleanup.
No source SQLite file is modified and no SQLite backup is used.
"""

from __future__ import annotations

from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2

from dataclasses import dataclass
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
from typing import Any

from .contract import AuthorityUnavailable, identifier
from .c09_originals_archive_v1 import (
    SINGLETONS, install_c09_archive_schema_v1, archive_exact_original_v1,
)
from .c09_owner_pairing_rows_v1 import (
    SCHEMAS as _OWNER_PAIRING_SCHEMAS, verify_owner_pairing_schema_v1,
    validate_owner_pairing_row_v1,
)
from .installer_genesis_v1 import DDL as _INSTALLER_GENESIS_TABLES, validate_installer_genesis_row_v1
from .d12_package_maintenance_authority_v2 import DDL as _PACKAGE_CORE_SCHEMAS
from .d12_package_core_rows_v2 import validate_d12_package_core_row_v2
from .c09_model_budget_original_v1 import (
    TABLE as _MODEL_BUDGET_TABLE, MODEL_TABLES, read_model_budget_originals_v1,
    validate_c09_model_budget_row_v1, model_unit_fact_v4,
)
from ..runtime.c09_d07_execution_v1 import TIMING_TABLE as _D07_TIMING_TABLE, validate_d07_schema_v1, validate_d07_timing_row_v1
from .d10_contact_policy_service_v1 import TABLE as _CONTACT_POLICY_TABLE, DDL as _CONTACT_POLICY_DDL
from .c09_contact_finish_original_v1 import TABLE as _CONTACT_FINISH_TABLE, validate_contact_finish_row_v1
from .c09_contact_frame_authentication_v1 import (
    TABLE as _CONTACT_FRAME_AUTH_TABLE, validate_contact_frame_authentication_row_v1,
)
from .c09_life_completed_archive_v1 import (
    TABLE as _LIFE_COMPLETED_ARCHIVE_TABLE, validate_life_archive_row_v1,
    require_completed_life_archive_schema_v1,
)


_KNOWN_CORE_TABLES = frozenset({
    "authority_meta", "authority_namespaces", "authority_transfers",
    "authority_natural_disposition_originals_v1",
    "authority_permits", "authority_effects", "authority_events",
    "authority_v2_meta", "authority_v2_epochs", "authority_v2_fences",
    "authority_v2_mutations", "authority_v2_never_begun",
    "authority_installation_management_v1", "authority_installation_management_grants_v1",
    "authority_installation_management_events_v1", "authority_installation_management_receipts_v1",
    "authority_erasure_surface_registry_v1",
    "authority_erasure_cleanup_runs_v1",
    "authority_erasure_execution_inventory_v1",
    "authority_execution_redaction_seals_v3",
    "authority_execution_redaction_sidecar_pins_v3",
    "authority_execution_redaction_switches_v3",
    "authority_execution_recovery_facts_pins_v4",
    "authority_execution_recovery_facts_v4",
    "authority_c09_graph_rebase_issues_v1",
    "authority_migration_pairings_v1",
    "authority_d12_operation_originals_v1", "authority_d12_target_leases_v1",
    "authority_d12_target_owner_admissions_v1",
    "authority_d12_lifecycle_heads_v1", "authority_d12_lifecycle_operations_v1",
    "authority_d12_lifecycle_receipts_v1", "authority_d12_lifecycle_bootstraps_v1",
    "authority_graph_catalogue_upgrades_v1",
    "authority_dispatch_admission_epoch_v1",
    "authority_execution_handoff_starts_v1",
    "authority_execution_handoff_graph_receipts_v1",
    "authority_natural_final_observations_v4",
    "authority_migration_v2_meta", "authority_migration_v2_plans",
    "authority_migration_v2_receipts",
    "authority_model_egress_v1", "authority_model_egress_bindings_v1",
    "authority_model_egress_observations_v1",
    "authority_model_egress_observation_status_v1",
    "authority_model_admissions_v2", "authority_model_original_identity_v2",
    "authority_owner_credentials_v1", "authority_owner_enrollments_v1",
    "authority_owner_proof_challenges_v1",
    "authority_owner_login_challenges_v1", "authority_owner_sessions_v1",
    "authority_owner_session_principals_v1",
    "authority_owner_session_revoked_keys_v1",
    "authority_owner_claim_tickets_v1", "authority_owner_issue_pending_v1",
    "authority_owner_issue_committed_v1",
    "authority_owner_authorization_heads_v1",
    "authority_owner_revoke_pending_v1",
    "authority_owner_revoke_committed_v1",
    "authority_scoped_erasure_v2",
    "authority_self_identity_heads_v1", "authority_self_identity_operations_v1",
    "authority_terminal_c02_read_attempts_v1",
    "authority_worker_result_read_attempts_v1",
    "authority_c09_consumed_execution_v1", "authority_c09_unresolved_effects_v1",
    "authority_c09_originals_archive_v1", "authority_c09_deletion_continuations_v1",
    "authority_c09_recovery_bindings_v1", "authority_c09_execution_source_seals_v4",
    "authority_c09_execution_source_pins_v4", "authority_c09_recovery_fact_frames_v4",
}) | frozenset(_OWNER_PAIRING_SCHEMAS) | frozenset(_INSTALLER_GENESIS_TABLES) | frozenset(_PACKAGE_CORE_SCHEMAS) | {_MODEL_BUDGET_TABLE, _D07_TIMING_TABLE, _CONTACT_POLICY_TABLE, _CONTACT_FINISH_TABLE, _CONTACT_FRAME_AUTH_TABLE, _LIFE_COMPLETED_ARCHIVE_TABLE}
_KNOWN_DELETION_TABLES = frozenset({
    "deletion_meta", "deletion_events", "authority_deletion_v2_meta",
    "authority_deletion_v2_tail",
})
_LEDGER_DDL = """CREATE TABLE authority_c09_consumed_execution_v1(
    namespace TEXT NOT NULL, kind TEXT NOT NULL, item_id TEXT NOT NULL,
    operation_id TEXT NOT NULL, original_commitment TEXT NOT NULL,
    facts_pin_digest TEXT NOT NULL,
    PRIMARY KEY(namespace,kind,item_id)) STRICT"""
_EFFECT_DDL = """CREATE TABLE authority_c09_unresolved_effects_v1(
    namespace TEXT NOT NULL, effect_id TEXT NOT NULL,
    operation_id TEXT NOT NULL, mutation_id TEXT NOT NULL,
    phase TEXT NOT NULL, execution_seq INTEGER NOT NULL,
    append_digest TEXT NOT NULL, footprint_commitment TEXT NOT NULL,
    conflict_keys_digest TEXT NOT NULL,
    PRIMARY KEY(namespace,effect_id)) STRICT"""


@dataclass(frozen=True, slots=True)
class RebasedFileV1:
    source_path: str
    source_identity: tuple[int, int, int, int]
    source_files_sha256: str
    target_path: str
    target_identity: tuple[int, int, int, int]
    target_sha256: str
    source_data_root: str
    target_data_root: str
    cold_read_digest: str


@dataclass(frozen=True, slots=True)
class RowDispositionV1:
    table_name: str
    row_key_digest: str
    original_commitment: str
    disposition: str
    new_commitment: str | None


@dataclass(frozen=True, slots=True)
class AuthorityStorageRebaseCandidateV1:
    authority_id: str
    namespace: str
    operation_id: str
    facts_pin_digest: str
    graph_issue_digest: str
    old_execution_journal_id: str
    old_execution_seq: int
    old_execution_digest: str
    new_execution_journal_id: str
    core: RebasedFileV1
    execution: RebasedFileV1
    deletion: RebasedFileV1
    changed_rows: tuple[RowDispositionV1, ...]
    inventory_digest: str
    candidate_digest: str


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


def _cell(value: Any) -> Any:
    if value is None:
        return ["null"]
    if type(value) is bytes:
        return ["blob", value.hex()]
    if type(value) is str:
        return ["text", value]
    if type(value) is int:
        return ["integer", value]
    if type(value) is float:
        return ["real", value.hex()]
    raise AuthorityUnavailable(f"unsupported SQLite cell type: {type(value).__name__}")


def _row_commitment(table: str, columns: tuple[str, ...], row: tuple) -> str:
    return _digest((table, columns, tuple(_cell(value) for value in row)))


def _identity(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    if not path.is_file():
        raise AuthorityUnavailable(f"C09 source is not a regular file: {path}")
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def _file_sha(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _files_sha(path: Path) -> str:
    parts = []
    for suffix in ("", "-wal", "-shm"):
        member = Path(str(path) + suffix)
        if member.exists():
            parts.append((suffix, _identity(member), _file_sha(member)))
    return _digest(parts)


def _db_path(db: sqlite3.Connection) -> Path:
    row = db.execute("PRAGMA database_list").fetchone()
    if row is None or not row[2]:
        raise AuthorityUnavailable("C09 candidate requires installed file-backed SQLite")
    return Path(row[2]).resolve(strict=True)


def _objects(db: sqlite3.Connection) -> tuple[tuple[str, str, str, str], ...]:
    result = tuple(db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"))
    if any(kind not in ("table", "index", "trigger") or sql is None
           for kind, _name, _table, sql in result):
        raise AuthorityUnavailable("unsupported C09 SQLite schema object")
    return result


def _tables(db: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(sorted(row[1] for row in _objects(db) if row[0] == "table"))


def _columns(db: sqlite3.Connection, table: str) -> tuple[str, ...]:
    # Names come exclusively from sqlite_master, then are checked as identifiers.
    if not table.replace("_", "").isalnum():
        raise AuthorityUnavailable(f"unsafe C09 table name: {table}")
    return tuple(row[1] for row in db.execute(f'PRAGMA table_info("{table}")'))


def _rows(db: sqlite3.Connection, table: str) -> tuple[tuple, ...]:
    return tuple(tuple(row) for row in db.execute(f'SELECT * FROM "{table}"'))


def _root(db: sqlite3.Connection) -> str:
    return _digest(tuple((table, _columns(db, table), tuple(sorted(
        _row_commitment(table, _columns(db, table), row)
        for row in _rows(db, table)))) for table in _tables(db)))


def _fresh_connection(path: Path) -> sqlite3.Connection:
    path = path.resolve(strict=False)
    if not path.parent.is_dir() or path.exists():
        raise AuthorityUnavailable(f"C09 target must be a new file: {path}")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(descriptor)
    db = sqlite3.connect(path, isolation_level=None)
    db.execute("PRAGMA foreign_keys=OFF")
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("PRAGMA synchronous=FULL")
    return db


def _insert_rows(db: sqlite3.Connection, table: str,
                 rows: tuple[tuple, ...]) -> None:
    if rows:
        count = len(rows[0])
        db.executemany(f'INSERT INTO "{table}" VALUES({",".join("?" for _ in range(count))})',
                       rows)


def _build_file(source: sqlite3.Connection, target: Path,
                expected_tables: frozenset[str], transform, *, control=None,
                operation_id=None, role=None) -> tuple[RebasedFileV1,
                                                                       tuple[RowDispositionV1, ...]]:
    source_path = _db_path(source)
    source_identity = _identity(source_path)
    source_files_sha = _files_sha(source_path)
    objects = _objects(source)
    observed = set(_tables(source))
    if not observed.issubset(expected_tables):
        raise AuthorityUnavailable(
            "unclassified C09 installed table(s): " +
            ", ".join(sorted(observed - expected_tables)))
    if observed & set(_OWNER_PAIRING_SCHEMAS):
        verify_owner_pairing_schema_v1(source)
    for table in observed & set(_PACKAGE_CORE_SCHEMAS):
        if source.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() != (_PACKAGE_CORE_SCHEMAS[table],):
            raise AuthorityUnavailable("C09 installed package Core schema differs")
    if observed & set(_PACKAGE_CORE_SCHEMAS):
        from .d12_package_maintenance_authority_v2 import validate_package_authority_schema_v2
        validate_package_authority_schema_v2(source)
    if "authority_natural_disposition_originals_v1" in observed:
        _require_natural_disposition_original_inventory_v1(source)
    if "authority_graph_catalogue_upgrades_v1" in observed:
        from .graph_catalogue_upgrade_v1 import validate_catalogue_upgrade_core_schema_v1
        validate_catalogue_upgrade_core_schema_v1(source)
    if "authority_worker_result_read_attempts_v1" in observed:
        from .v2_worker_model_result_attempts import (
            require_worker_result_read_attempt_schema_v1,
            validate_worker_result_read_attempt_row_v1,
            require_worker_result_read_attempt_fence_v1)
        require_worker_result_read_attempt_schema_v1(source)
        table = "authority_worker_result_read_attempts_v1"
        for row in _rows(source, table):
            attempt = validate_worker_result_read_attempt_row_v1(_columns(source, table), row)
            if attempt.request.authority_namespace == transform.namespace:
                require_worker_result_read_attempt_fence_v1(
                    source, attempt=attempt, authority_id=transform.authority_id,
                    authority_namespace=transform.namespace,
                    installation_id=transform.installation_id)
                from .d11_artifact_draft_model_v1 import ArtifactDraftModelResultReadRequestV1
                if type(attempt.request) is ArtifactDraftModelResultReadRequestV1:
                    _require_c4_read_attempt_core_original_v1(source,attempt)
    if observed & set(MODEL_TABLES):
        from .v2_model_egress_store import (_DDL, _BINDING_DDL, _OBSERVATION_DDL, _OBSERVATION_STATUS_DDL,
            _ADMISSION_DDL, _ORIGINAL_IDENTITY_DDL, _JOB_INDEX_DDL)
        schemas = dict(zip(MODEL_TABLES, (_DDL, _BINDING_DDL, _OBSERVATION_DDL, _OBSERVATION_STATUS_DDL,
            _ADMISSION_DDL, _ORIGINAL_IDENTITY_DDL)))
        for table, sql in schemas.items():
            if source.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() != (sql,):
                raise AuthorityUnavailable("C09 exact model Core schema is unavailable")
        if source.execute("SELECT sql FROM sqlite_master WHERE name='authority_model_egress_one_job'").fetchone() != (_JOB_INDEX_DDL,):
            raise AuthorityUnavailable("C09 model once-job index differs")
    if _D07_TIMING_TABLE in observed:
        validate_d07_schema_v1(source)
    if _CONTACT_POLICY_TABLE in observed:
        from .c09_contact_policy_rows_v1 import require_contact_policy_schema_v1
        require_contact_policy_schema_v1(source)
    if _CONTACT_FINISH_TABLE in observed:
        from .c09_contact_finish_original_v1 import require_contact_finish_archive_schema_v1
        require_contact_finish_archive_schema_v1(source)
    if _CONTACT_FRAME_AUTH_TABLE in observed:
        from .c09_contact_frame_authentication_v1 import require_contact_frame_authentication_schema_v1
        require_contact_frame_authentication_schema_v1(source)
    if _LIFE_COMPLETED_ARCHIVE_TABLE in observed:
        require_completed_life_archive_schema_v1(source)
    if any(table not in observed for table in transform.required_tables):
        raise AuthorityUnavailable(
            "required C09 installed table(s) absent: " +
            ", ".join(sorted(set(transform.required_tables) - observed)))
    source_root = _root(source)
    target = target.resolve(strict=False)
    recomputed = False
    if control is None:
        db = _fresh_connection(target)
    else:
        from .c09_build_originals_v1 import open_registered_candidate_v1
        db, recomputed = open_registered_candidate_v1(control=control,
            operation_id=operation_id, role=role, target=target, source_root=source_root)
        db.execute("PRAGMA foreign_keys=OFF")
    changed: list[RowDispositionV1] = []
    try:
        db.execute("BEGIN IMMEDIATE")
        for kind, _name, _table, sql in objects:
            if kind == "table":
                if hasattr(transform,"schema_sql"):
                    sql = transform.schema_sql(_name,sql)
                db.execute(sql)
        for table in sorted(observed):
            columns = _columns(source, table)
            old_rows = _rows(source, table)
            new_rows, dispositions = transform(table, columns, old_rows)
            changed.extend(dispositions)
            _insert_rows(db, table, new_rows)
        transform.finish(db)
        for kind, _name, _table, sql in objects:
            if kind in ("index", "trigger"):
                existing = db.execute("SELECT sql FROM sqlite_master WHERE type=? AND name=?",(kind,_name)).fetchone()
                if existing is None:
                    db.execute(sql)
                elif existing != (sql,):
                    raise AuthorityUnavailable("C09 duplicate schema object differs: " + _name)
        if "sqlite_sequence" in {row[0] for row in source.execute(
                "SELECT name FROM sqlite_master WHERE name='sqlite_sequence'")}:
            sequences = tuple(source.execute("SELECT name,seq FROM sqlite_sequence"))
            if sequences:
                db.executemany("INSERT OR REPLACE INTO sqlite_sequence(name,seq) VALUES(?,?)",
                               sequences)
        db.execute(f"PRAGMA user_version={source.execute('PRAGMA user_version').fetchone()[0]}")
        db.execute(f"PRAGMA application_id={source.execute('PRAGMA application_id').fetchone()[0]}")
        if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise AuthorityUnavailable(f"C09 candidate foreign key check failed: {target}")
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise AuthorityUnavailable(f"C09 candidate integrity check failed: {target}")
        db.execute("COMMIT")
        target_root = _root(db)
        if recomputed:
            from .c09_build_originals_v1 import verify_recomputed_candidate_v1
            verify_recomputed_candidate_v1(db, target)
        elif db.execute("PRAGMA journal_mode=WAL").fetchall() != [("wal",)]:
            raise AuthorityUnavailable("C09 current candidate must retain installed WAL policy")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        db.close()
        raise
    db.close()
    with closing(sqlite3.connect(target, isolation_level=None)) as checkpoint_db:
        checkpoint_db.execute("PRAGMA synchronous=FULL")
        checkpoint = checkpoint_db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()[0]
        if checkpoint[0] != 0:
            raise AuthorityUnavailable("C09 candidate WAL checkpoint blocked")
    if any(Path(str(target) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise AuthorityUnavailable("C09 closed candidate has residual sidecars")
    with closing(sqlite3.connect(target.as_uri() + "?mode=ro&immutable=1", uri=True)) as cold:
        cold.execute("BEGIN")
        cold_root = _root(cold)
    if cold_root != target_root:
        raise AuthorityUnavailable(f"C09 candidate cold read differs: {target}")
    if _identity(source_path) != source_identity or _files_sha(source_path) != source_files_sha:
        raise AuthorityUnavailable(f"C09 frozen source changed while building: {source_path}")
    return (RebasedFileV1(str(source_path), source_identity, source_files_sha,
                          str(target), _identity(target), _file_sha(target),
                          source_root, target_root, _digest((str(target), cold_root))),
            tuple(changed))


def _require_natural_disposition_original_inventory_v1(source):
    """The same-Core signed metadata family has explicit retirement, never an exemption."""
    import hmac
    from .natural_disposition_maintenance_v1 import (ORIGINAL_TABLE, ORIGINAL_COLUMNS, ORIGINAL_DDL,
        ORIGINAL_TRIGGER_DDLS, SIGNING_KEY_PREFIX, core_original_from_wire_v1)
    from ..runtime_contracts import canonical_digest, canonical_serialize
    reference = sqlite3.connect(":memory:")
    try:
        reference.execute(ORIGINAL_DDL)
        for ddl in ORIGINAL_TRIGGER_DDLS:
            reference.execute(ddl)
        for db in (source, reference):
            if _columns(db, ORIGINAL_TABLE) != ORIGINAL_COLUMNS:
                raise AuthorityUnavailable("C09 natural disposition Core columns differ")
        actual = tuple(source.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? ORDER BY type,name", (ORIGINAL_TABLE,)))
        wanted = tuple(reference.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? ORDER BY type,name", (ORIGINAL_TABLE,)))
        if actual != wanted:
            raise AuthorityUnavailable("C09 natural disposition immutable Core schema differs")
    finally:
        reference.close()
    originals = {}
    for row in _rows(source, ORIGINAL_TABLE):
        value = core_original_from_wire_v1(json.loads(row[5]))
        if (canonical_serialize(value.to_wire()) != row[5]
                or row[:5] != (value.authority_namespace, value.installation_id, value.kind, value.operation_id, value.original_ref)
                or row[6:] != (value.payload_digest, value.signature)):
            raise AuthorityUnavailable("C09 natural disposition original columns/commitment differ")
        key = source.execute("SELECT value FROM authority_meta WHERE key=?",
            (SIGNING_KEY_PREFIX + canonical_digest((value.authority_namespace, value.installation_id)),)).fetchone()
        if key is None or len(key[0]) != 64 or any(c not in "0123456789abcdef" for c in key[0]):
            raise AuthorityUnavailable("C09 natural disposition actual Core signing material missing")
        material = {k:v for k,v in value.to_wire().items() if k != "signature"}
        expected = hmac.new(bytes.fromhex(key[0]), b"sylanne.natural-disposition-original.v1\0" +
            canonical_serialize(material).encode("utf-8"), sha256).hexdigest()
        if not hmac.compare_digest(expected, value.signature):
            raise AuthorityUnavailable("C09 natural disposition original lost its private Core signature")
        originals[value.original_ref] = value
    for value in originals.values():
        if value.kind == "rejected_no_commit":
            from .natural_disposition_maintenance_v1 import validate_original_terminal_fence_in_tx_v1
            validate_original_terminal_fence_in_tx_v1(source, value)
            if value.payload["state"] == "proven_no_preparation_no_graph_commit":
                continue
        if value.kind.endswith("_committed") or value.kind == "rejected_no_commit":
            parent = originals.get(value.payload["prepared_original_ref"])
            if (parent is None or parent.digest != value.payload["prepared_original_digest"]
                    or (parent.authority_namespace, parent.installation_id, parent.operation_id, parent.parent_original_id) !=
                       (value.authority_namespace, value.installation_id, value.operation_id, value.parent_original_id)
                    or not parent.kind.endswith("_prepared")):
                raise AuthorityUnavailable("C09 natural disposition confirmation lost its actual prepared original")
    return True


def _change(table: str, columns: tuple[str, ...], old: tuple,
            disposition: str, new: tuple | None = None) -> RowDispositionV1:
    key = _digest((table, tuple(_cell(value) for value in old[:2])))
    return RowDispositionV1(
        table, key, _row_commitment(table, columns, old), disposition,
        None if new is None else _row_commitment(table, columns, new))


def _need_columns(table: str, columns: tuple[str, ...], names: tuple[str, ...]) -> None:
    if any(name not in columns for name in names):
        raise AuthorityUnavailable(
            f"C09 installed {table} missing columns: " +
            ", ".join(name for name in names if name not in columns))


def _require_c4_read_attempt_core_original_v1(source,attempt):
    """Bind the closed fourth variant to its real original model call metadata."""
    from .v2_model_egress_store import AuthorityV2ModelEgressStore
    from .d11_artifact_draft_model_v1 import ArtifactDraftModelResultReadRequestV1
    request=attempt.request
    if type(request) is not ArtifactDraftModelResultReadRequestV1:
        raise AuthorityUnavailable("C09 C4 read-attempt classification needs exact request")
    record=AuthorityV2ModelEgressStore._read(source,request.call_id)
    if record is None or (record.intent.authority_id,record.intent.namespace,record.intent.job_id,
            record.intent.acquire_operation_id,record.intent.binding_digest,record.intent.request_digest)!= (
            request.authority_id,request.authority_namespace,request.job_id,request.acquire_operation_id,
            request.binding_digest,request.model_request_digest):
        raise AuthorityUnavailable("C09 C4 read-attempt crossed original model call/acquire/request")
    identity=source.execute("SELECT installation_id FROM authority_model_original_identity_v2 WHERE call_id=?",
        (request.call_id,)).fetchone()
    if identity!=(request.installation_id,):raise AuthorityUnavailable("C09 C4 read-attempt crossed installed model original")



def _owner_stop_reply_core_dispositions_v1(core_db,*,control,operation_id,issue,mirror):
    """Join immutable stop groups to the selected Graph and its certified target."""
    from dataclasses import asdict
    from ..runtime.c09_foreground_attempt_v1 import _selected_context_v1
    from ..runtime.c09_graph_rebase_candidate_v1 import graph_source_files_fingerprint_v1,_row_digest
    from .c09_graph_rebase_issue_v1 import verify_graph_rebase_issue_signature_v1
    from .owner_stop_reply_v1 import (PLAN_SCHEMA,decode_owner_stop_reply_plan_v1,
        validate_owner_stop_reply_core_row_v1,owner_reply_cycle_retirement_commitment_v1)
    from ..runtime.owner_stop_reply_v1 import read_original_owner_reply_cycle_identity_v1
    from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..runtime.jobs import get_job
    from ..runtime.d11_types import job_graph_write
    from ..runtime.foreground_cycle_v1 import ForegroundResponsibilityV1
    from ..runtime.domain_production_original_codec_v1 import decode_typed_production_value_v1
    from ..runtime_contracts import canonical_digest,canonical_serialize
    from ..graph_types import AtomKey
    table="authority_d12_operation_originals_v1"
    if core_db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() is None:return {}
    selected=[]
    for row in core_db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE namespace=?",(issue.namespace,)):
        plan=json.loads(row[7])
        if plan.get("schema")==PLAN_SCHEMA:
            validate_owner_stop_reply_core_row_v1(row);selected.append((tuple(row),plan))
    if not selected:return {}
    context,intent,members=_selected_context_v1(control,operation_id)
    source=Path(members["graph"]["resolved_path"]);target=Path(intent["details"]["targets"]["graph"])
    verify_graph_rebase_issue_signature_v1(issue,control._key)
    if (_identity(target)!=mirror.final_file_identity or _file_sha(target)!=mirror.final_file_sha256
            or Path(core_db.execute("PRAGMA database_list").fetchone()[2]).resolve(strict=True)!=Path(members["core"]["resolved_path"])
            or issue.source_path!=str(source) or issue.target_path!=str(target)
            or issue.certificate_digest!=mirror.certificate.certificate_digest or issue.authority_id!=control.authority_id
            or issue.operation_id!=operation_id or issue.source_files_fingerprint!=graph_source_files_fingerprint_v1(source)):
        raise AuthorityUnavailable("C09 stop groups are outside the real selected Core/Graph certified source")
    manifests={m.table_name:{r.row_key_digest:r for r in m.rows} for m in mirror.certificate.table_manifests}
    groups={}
    for row,plan in selected:groups.setdefault(row[1],[]).append((row,plan))
    result={}
    with closing(sqlite3.connect(source.as_uri()+"?mode=ro",uri=True)) as graph,closing(sqlite3.connect(target.as_uri()+"?mode=ro",uri=True)) as candidate:
        graph.execute("PRAGMA query_only=ON");graph.execute("BEGIN")
        candidate.execute("PRAGMA query_only=ON");candidate.execute("BEGIN")
        def disposition(table,row):
            info=tuple(graph.execute("PRAGMA table_info("+table+")"));columns=tuple(x[1] for x in info)
            primary=tuple(x[1] for x in sorted((x for x in info if x[5]),key=lambda x:x[5]))
            if row is None or not primary:raise AuthorityUnavailable("C09 stop lineage source row absent: "+table)
            key=tuple(row[columns.index(name)] for name in primary)
            proof=manifests.get(table,{}).get(canonical_digest((table,key)))
            if proof is None or proof.old_commitment!=_row_digest(row) or proof.disposition not in {"preserved_exact","derived_removed"}:
                raise AuthorityUnavailable("C09 stop lineage has no exact certified row disposition: "+table)
            actual=candidate.execute("SELECT * FROM "+table+" WHERE "+" AND ".join(name+"=?" for name in primary),key).fetchone()
            if (proof.disposition=="preserved_exact" and (actual!=row or proof.new_commitment!=proof.old_commitment)
                    or proof.disposition=="derived_removed" and actual is not None):
                raise AuthorityUnavailable("C09 stop lineage candidate disagrees with its real certified closure")
            return proof.disposition
        for stop_operation,group in groups.items():
            base,plan=group[0];request,_=decode_owner_stop_reply_plan_v1(plan)
            if request.installation_id!=control.installation_id:
                raise AuthorityUnavailable("C09 stop original crossed its actual installed cohort")
            if any(row[4:]!=base[4:] or other!=plan for row,other in group):
                raise AuthorityUnavailable("C09 initial/derived StopReply group changed its original plan/Owner scope")
            identity,cycle=read_original_owner_reply_cycle_identity_v1(graph,namespace=request.namespace,request=request)
            if asdict(identity)!=plan["scope"]:
                raise AuthorityUnavailable("C09 stop plan has no exact actual historical cycle/create/C02 identity")
            ns=request.namespace.as_tuple;states=[]
            states.append(disposition("runtime_jobs",graph.execute("SELECT * FROM runtime_jobs WHERE job_id=?",(cycle.job_id,)).fetchone()))
            states.append(disposition("graph_atoms",graph.execute("SELECT * FROM graph_atoms WHERE token=?",(request.cycle_job_ref,)).fetchone()))
            create=read_adopted_domain_operation_v1(graph,request.namespace,cycle.operation_id)
            states.append(disposition("graph_domain_production_originals_v1",graph.execute("SELECT * FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND operation_id=?",(*ns,cycle.operation_id)).fetchone()))
            for producer in (cycle.operation_id,request.c02_operation_id):
                states.append(disposition("graph_bundle_operations",graph.execute("SELECT * FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",(*ns,producer)).fetchone()))
            if identity.responsibility_ref is not None:
                responsibility=decode_typed_production_value_v1(create["payload"]["provenance"]["foreground_responsibility"],ForegroundResponsibilityV1)
                kind="foreground_post_c02_cause" if responsibility.mode=="bounded_causal_window_v1" else "draft_root_capability"
                states.append(disposition("graph_d11_life_originals_v1",graph.execute("SELECT * FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind=? AND original_ref=?",(*ns,kind,responsibility.cause_original_ref)).fetchone()))
            for job_ref,original_ref,original_digest in plan["child_originals"]:
                child=get_job(graph,AtomKey.from_token(job_ref).name)
                if job_graph_write(child).key.token!=job_ref or (child.bot_id,child.persona_id)!=ns:
                    raise AuthorityUnavailable("C09 stop child locator is not its actual same-namespace job")
                states.append(disposition("runtime_jobs",graph.execute("SELECT * FROM runtime_jobs WHERE job_id=?",(child.job_id,)).fetchone()))
                states.append(disposition("graph_atoms",graph.execute("SELECT * FROM graph_atoms WHERE token=?",(job_ref,)).fetchone()))
                carrier=_owner_stop_reply_child_carrier_v1(graph,request.namespace,cycle,child,original_ref,original_digest)
                for family,row in carrier:states.append(disposition(family,row))
            for row,_ in group:
                from ..runtime.lifecycle_operations_v1 import decode_original
                original=decode_original(json.loads(row[3]))
                for ref in original.result.domain_receipt_refs:
                    rows=graph.execute("SELECT * FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND domain='d11' AND substr(original_digest,1,48)=? LIMIT 2",(*ns,ref.removeprefix("d11-current:"))).fetchall()
                    if len(rows)!=1:raise AuthorityUnavailable("C09 derived stop lost its actual Graph projection original")
                    projection=read_adopted_domain_operation_v1(graph,request.namespace,rows[0][2])
                    if projection["operation_kind"]!="owner_stop_reply_v1" or projection["payload"]["provenance"]["cycle_identity"]!=plan["scope"]:
                        raise AuthorityUnavailable("C09 derived stop projection belongs to another actual control scope")
                    states.append(disposition("graph_domain_production_originals_v1",rows[0]))
            state="derived_removed" if "derived_removed" in states else "preserved_exact"
            commitment=owner_reply_cycle_retirement_commitment_v1(base[0],request.cycle_job_ref,stop_operation)
            for row,_ in group:result[row[:3]]=(row,state,AtomKey.from_token(request.cycle_job_ref).name,commitment)
    if _identity(target)!=mirror.final_file_identity or _file_sha(target)!=mirror.final_file_sha256:
        raise AuthorityUnavailable("C09 stop lineage certified candidate changed during the actual source/target join")
    control.verify_member_v1(members["graph"],prepared=False);context.require_current("maintenance")
    return result


def _owner_stop_reply_child_carrier_v1(db,namespace,cycle,job,original_ref,original_digest):
    """Closed immutable metadata carriers; no caller-selected table or codec."""
    from ..runtime_contracts import canonical_digest
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..runtime.d11_types import job_graph_write
    ns=namespace.as_tuple
    from ..runtime.foreground_cycle_v1 import foreground_cycle_from_wire_v1
    continuation=foreground_cycle_from_wire_v1(cycle.continuation)
    if job.work_kind in {"artifact_draft_v1","d10.life.source_note.v1","d10.life.artifact_draft.v1"}:
        kind="c4_prepared" if job.work_kind=="artifact_draft_v1" else "prepared"
        row=db.execute("SELECT * FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind=? AND original_ref=?",(*ns,kind,original_ref)).fetchone()
        if row is None or row[6]!=original_digest:raise AuthorityUnavailable("C09 stop child lost its actual Life/C4 signed metadata carrier")
        if kind=="c4_prepared":
            from ..runtime.d11_artifact_draft_model_v1 import decode_artifact_draft_original_v1
            binding=decode_artifact_draft_original_v1(kind,json.loads(row[5]))
            if binding.selector.cycle_job_ref!=job_graph_write(cycle).key.token or binding.selector.c02_operation_id!=continuation.c02_operation_id:
                raise AuthorityUnavailable("C09 C4 child belongs to another original reply cycle")
        else:
            from ..runtime.d11_life_contract_v1 import D11LifeExecutionBindingV1,life_from_wire_v1
            encoded=db.execute("SELECT json_extract(payload_json,'$.binding') FROM graph_d11_life_originals_v1 "
                "WHERE bot=? AND persona=? AND kind='prepared' AND original_ref=?",(*ns,original_ref)).fetchone()
            binding=life_from_wire_v1(json.loads(encoded[0]),D11LifeExecutionBindingV1)
            if binding.activity_id!=cycle.activity_id:raise AuthorityUnavailable("C09 Life child belongs to another original reply activity")
        if (binding.job_id,binding.operation_id,binding.activity_id)!=(job.job_id,job.operation_id,job.activity_id):
            raise AuthorityUnavailable("C09 stop Life/C4 child crossed its immutable producer")
        return (("graph_d11_life_originals_v1",row),)
    if job.work_kind=="d04.appraisal":
        from ..runtime.d04_appraisal_driver_v3 import read_current_d04_appraisal_original_v3
        from ..runtime.d04_product_pipeline_v3 import ids
        if ids(namespace,continuation.c02_operation_id)["job"]!=job.job_id:
            raise AuthorityUnavailable("C09 C2 child belongs to another immutable C02")
        value=read_current_d04_appraisal_original_v3(db,namespace,job.job_id)
        row=db.execute("SELECT * FROM graph_d04_originals_v3 WHERE bot=? AND persona=? AND kind='appraisal' AND original_ref=?",(*ns,original_ref)).fetchone()
        if value is None or row is None or value.digest!=original_digest or value.job_id!=job.job_id or value.operation_id!=job.operation_id:
            raise AuthorityUnavailable("C09 stop C2 child lost actual appraisal metadata")
        return (("graph_d04_originals_v3",row),)
    if job.work_kind in {"natural_generation","natural_review"}:
        from ..runtime.foreground_cycle_v1 import _read_reply_natural_metadata_v1
        from ..runtime.natural_reply_job_v2 import _table
        stage=job.work_kind.removeprefix("natural_");table=_table(stage)
        value=_read_reply_natural_metadata_v1(db,namespace,continuation.c02_operation_id,stage)
        if value is None:raise AuthorityUnavailable("C09 stop natural child original absent")
        seal=value[0]
        if ((seal.original_operation_id,seal.job_id,canonical_digest(plain_v1(seal)))!=(original_ref,job.job_id,original_digest)
                or job.operation_id!=original_ref or seal.parent_budget_lease_id!=continuation.call_plan.protected_reply_lease_ref):
            raise AuthorityUnavailable("C09 stop natural child lost immutable sealed identity")
        row=db.execute("SELECT * FROM "+table+" WHERE bot=? AND persona=? AND job_id=?",(*ns,job.job_id)).fetchone()
        operation=db.execute("SELECT * FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",(*ns,job.operation_id)).fetchone()
        return ((table,row),("graph_bundle_operations",operation))
    if job.work_kind=="message":
        from ..runtime.foreground_cycle_v1 import _read_reply_natural_metadata_v1,_read_reply_message_metadata_v1
        generation=_read_reply_natural_metadata_v1(db,namespace,continuation.c02_operation_id,"generation")
        review=_read_reply_natural_metadata_v1(db,namespace,continuation.c02_operation_id,"review")
        if generation is None or review is None:raise AuthorityUnavailable("C09 stopped message lacks actual natural parent seals")
        messages=_read_reply_message_metadata_v1(db,namespace=namespace,generation_seal=generation[0],review_seal=review[0])
        found=tuple(value for value in messages if value[0].job_id==job.job_id)
        if len(found)!=1 or (found[0][1],found[0][2])!=(original_ref,original_digest):
            raise AuthorityUnavailable("C09 stop message child lost its actual immutable batch metadata")
        row=db.execute("SELECT * FROM graph_atoms WHERE token=?",(original_ref,)).fetchone()
        operation=db.execute("SELECT * FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",(*ns,job.operation_id)).fetchone()
        return (("graph_atoms",row),("graph_bundle_operations",operation))
    raise AuthorityUnavailable("C09 StopReply child metadata family has no registered codec")


class _CoreTransform:
    required_tables = (
        "authority_meta", "authority_namespaces", "authority_effects",
        "authority_v2_meta", "authority_v2_fences", "authority_v2_mutations",
        "authority_execution_recovery_facts_pins_v4",
        "authority_execution_recovery_facts_v4",
        "authority_c09_graph_rebase_issues_v1",
    )

    def __init__(self, *, namespace: str, operation_id: str,
                 authority_id: str, pin_digest: str,
                 new_journal_id: str, old_journal_id: str, new_anchor_nonce: str,
                 continuation_permit_token: str,
                 old_seq: int, old_digest: str, facts,
                 execution_rows: tuple[tuple, ...], bindings=None,
                 accepted_receipt=None, old_manifest_digest=None,
                 maintenance_generation=1, installation_id=None,current_originals=None):
        self.namespace = namespace
        self.operation_id = operation_id
        self.authority_id = authority_id
        self.pin_digest = pin_digest
        self.new_journal_id = new_journal_id
        if (type(new_anchor_nonce) is not str or len(new_anchor_nonce) != 64
                or any(ch not in "0123456789abcdef" for ch in new_anchor_nonce)):
            raise AuthorityUnavailable("C09 planned anchor nonce invalid")
        self.new_anchor_nonce = new_anchor_nonce
        self.continuation_permit_token = continuation_permit_token
        self.old_journal_id = old_journal_id
        self.old_seq = old_seq
        self.old_digest = old_digest
        self.facts = facts
        self.execution_rows = execution_rows
        self.consumed: dict[tuple[str, str], tuple[str, str]] = {}
        self.effects: dict[str, tuple] = {}
        self.namespace_seen = False
        self.bindings = bindings
        self.accepted_receipt = accepted_receipt
        self.old_manifest_digest = old_manifest_digest
        self.maintenance_generation = maintenance_generation
        self.installation_id = installation_id
        self.archive_rows = []
        self.transition = None
        self.current_anchor = None
        self.current_fence = None
        self.prior_ledger = {}
        self.current_originals = {} if current_originals is None else current_originals
        self.model_originals = self.current_originals.get("model_budget_originals", ())
        self.model_by_call = {original.call_id: original for original in self.model_originals}
        self.foreground_fences = self.current_originals.get("foreground_fences", {})
        self.owner_reply_stops = self.current_originals.get("owner_reply_stops", {})

    def _consume(self, kind: str, item_id: str, operation_id: str,
                 original_commitment: str) -> None:
        identifier(item_id, "consumed item_id")
        identifier(operation_id, "consumed operation_id")
        key = kind, item_id
        if key in self.consumed and self.consumed[key] != (
                operation_id, original_commitment):
            raise AuthorityUnavailable(f"C09 consumed identity conflicts: {kind}/{item_id}")
        self.consumed[key] = (operation_id, original_commitment)

    def _check_unsupported(self, table: str, columns: tuple[str, ...],
                           rows: tuple[tuple, ...]) -> None:
        if "namespace" not in columns:
            return
        namespace_index = columns.index("namespace")
        if any(row[namespace_index] == self.namespace for row in rows):
            raise AuthorityUnavailable(
                f"C09 V4 facts do not cover installed {table} rows in namespace "
                f"{self.namespace}")

    def __call__(self, table: str, columns: tuple[str, ...],
                 rows: tuple[tuple, ...]) -> tuple[tuple[tuple, ...],
                                                 tuple[RowDispositionV1, ...]]:
        changes: list[RowDispositionV1] = []
        if table == "authority_natural_disposition_originals_v1":
            from .natural_disposition_maintenance_v1 import ORIGINAL_COLUMNS, core_original_from_wire_v1
            if columns != ORIGINAL_COLUMNS:
                raise AuthorityUnavailable("C09 natural disposition original inventory columns differ")
            output = []
            for old in rows:
                value = core_original_from_wire_v1(json.loads(old[5]))
                if value.authority_namespace != self.namespace:
                    output.append(old)
                    continue
                # C09 retires this source-dependent roster evidence. Original
                # admission, UNKNOWN, execution and fee families have their own
                # existing retained-fact contracts and are never cleared here.
                self._consume("natural_disposition_original_v1", value.original_ref,
                    value.operation_id, value.digest)
                changes.append(_change(table, columns, old, "derived_removed"))
            return tuple(output), tuple(changes)
        if table == "authority_worker_result_read_attempts_v1":
            from .v2_worker_model_result_attempts import (
                validate_worker_result_read_attempt_row_v1)
            output = []
            for old in rows:
                attempt = validate_worker_result_read_attempt_row_v1(columns, old)
                request = attempt.request
                if request.authority_namespace != self.namespace:
                    output.append(old)
                    continue
                self._consume("worker_result_read_attempt", request.read_attempt_id,
                    request.consumer_operation_id, _row_commitment(table, columns, old))
                changes.append(_change(table, columns, old, "payload_erased_retained_facts"))
            return tuple(output), tuple(changes)
        if table == _CONTACT_POLICY_TABLE:
            from .c09_contact_policy_rows_v1 import validate_contact_policy_core_row_v1
            for row in rows:
                validate_contact_policy_core_row_v1(columns, row)
            return rows, ()
        if table == _D07_TIMING_TABLE:
            for row in rows:
                validate_d07_timing_row_v1(columns, row)
            return rows, ()
        if table == _MODEL_BUDGET_TABLE:
            for row in rows:
                validate_c09_model_budget_row_v1(columns, row)
            return rows, ()
        if table == _CONTACT_FINISH_TABLE:
            for row in rows:
                validate_contact_finish_row_v1(columns, row)
            return rows, ()
        if table == _CONTACT_FRAME_AUTH_TABLE:
            for row in rows:
                validate_contact_frame_authentication_row_v1(columns, row)
            # Authentication alone does not authorize disposal. Preserve the
            # original until an exact private disposition verifies the chain.
            return rows, ()
        if table == _LIFE_COMPLETED_ARCHIVE_TABLE:
            for row in rows:
                validate_life_archive_row_v1(columns, row)
            # Minimal retained associations are not anonymous data. No later
            # disposal is implied by recognizing their exact immutable schema.
            return rows, ()
        if table in MODEL_TABLES:
            from .c09_model_budget_original_v1 import validate_model_core_row_v1
            output = []
            for old in rows:
                call = validate_model_core_row_v1(table, columns, old)
                original = self.model_by_call.get(call)
                if original is None:
                    # Other namespaces and prior consumed metadata remain
                    # passive audit; no payload may survive a current call.
                    if table == "authority_model_egress_observations_v1" and any(
                            key == ("model_call", call) for key in self.prior_ledger):
                        raise AuthorityUnavailable("C09 historical model body survived its prior retirement")
                    output.append(old)
                    continue
                commitment = _row_commitment(table, columns, old)
                for kind, item in (("model_call", call), ("model_operation", original.model_operation_id),
                        ("model_job", original.job_id), ("model_acquire", original.acquire_operation_id),
                        ("model_admission", original.admission_id_or_none)):
                    if item is not None:
                        self._consume(kind, item, original.model_operation_id, original.original_digest)
                if table == "authority_model_egress_observations_v1":
                    changes.append(_change(table, columns, old, "payload_erased_retained_facts"))
                    continue
                if table == "authority_model_egress_observation_status_v1":
                    updated = (*old[:-1], 1)
                    output.append(updated)
                    if updated != old:
                        changes.append(_change(table, columns, old, "payload_erased_retained_facts", updated))
                    continue
                output.append(old)
            return tuple(output), tuple(changes)
        if table in _PACKAGE_CORE_SCHEMAS:
            for row in rows:
                validate_d12_package_core_row_v2(table, columns, row)
                if (table == "authority_d12_package_heads_v2" and row[0] == self.namespace
                        and row[4] not in {"active", "rollback_complete"}):
                    raise AuthorityUnavailable("C09 unfinished package operation remains authoritative")
            # Completed package records retain immutable audit identity only;
            # their typed readers cannot qualify a copied installation.
            return rows, ()
        if table in _INSTALLER_GENESIS_TABLES:
            for row in rows:
                validate_installer_genesis_row_v1(table, columns, row)
            return rows, ()
        if table in _OWNER_PAIRING_SCHEMAS:
            for row in rows:
                validate_owner_pairing_row_v1(table, columns, row, authority_id=self.authority_id)
            # Keep administrator identity, key pairing and active/revoked
            # revisions exactly. A content erasure is not an Owner re-pairing.
            return rows, ()
        if table in {"authority_d12_operation_originals_v1", "authority_d12_target_leases_v1",
                     "authority_d12_target_owner_admissions_v1", "authority_d12_lifecycle_heads_v1",
                     "authority_d12_lifecycle_operations_v1", "authority_d12_lifecycle_receipts_v1",
                     "authority_d12_lifecycle_bootstraps_v1", "authority_graph_catalogue_upgrades_v1"}:
            from .d12_c09_core_rows_v1 import validate_d12_core_row_v1
            output = []
            for old in rows:
                namespace, kind, item_id, operation_id = validate_d12_core_row_v1(table, columns, old)
                if namespace != self.namespace:
                    output.append(old)
                    continue
                if table=="authority_d12_operation_originals_v1":
                    from .owner_stop_reply_v1 import PLAN_SCHEMA
                    if json.loads(old[7]).get("schema")==PLAN_SCHEMA:
                        proof=self.owner_reply_stops.get(old[:3])
                        if proof is None or proof[0]!=old:raise AuthorityUnavailable("C09 actual StopReply group/closure is unconfirmed")
                        if proof[1]=="preserved_exact":
                            output.append(old);continue
                        if proof[1]!="derived_removed":raise AuthorityUnavailable("C09 unregistered StopReply group disposition")
                        self._consume("owner_reply_cycle_stop_v1",proof[2],old[1],proof[3])
                self._consume(kind, item_id, operation_id or self.operation_id,
                              _row_commitment(table, columns, old))
                if table == "authority_d12_operation_originals_v1":
                    self._consume("d12_source_original", old[8], old[1], _digest((old[0],old[1],old[8])))
                if table == "authority_d12_lifecycle_heads_v1":
                    if old[2] != "active":
                        raise AuthorityUnavailable("C09 cannot cross unfinished/paused installation lifecycle")
                    from ..runtime.lifecycle_operations_v1 import digest as lifecycle_digest
                    rebuilt=(old[0],old[1],"active",old[3]+1,None,
                        lifecycle_digest((old[0],old[1],"active",old[3]+1,"c09_rebase",self.operation_id,self.pin_digest)),None)
                    output.append(rebuilt)
                    changes.append(_change(table,columns,old,"rebuilt_from_surviving_sources",rebuilt))
                    continue
                # Old source/target epochs, pairing or location never become
                # current in the new cohort just because the row is metadata.
                changes.append(_change(table, columns, old, "payload_erased_retained_facts"))
            return tuple(output), tuple(changes)
        if table == "authority_namespaces":
            _need_columns(table, columns, ("namespace", "execution_journal_id",
                                           "execution_seq", "execution_digest"))
            output = []
            for old in rows:
                if old[columns.index("namespace")] != self.namespace:
                    output.append(old)
                    continue
                if self.namespace_seen:
                    raise AuthorityUnavailable("duplicate C09 namespace row")
                self.namespace_seen = True
                if (old[columns.index("execution_journal_id")],
                    old[columns.index("execution_seq")],
                    old[columns.index("execution_digest")]) != (
                        self.old_journal_id, self.old_seq, self.old_digest):
                    raise AuthorityUnavailable("C09 Core old execution head differs from pin")
                new = list(old)
                for name, value in (("execution_journal_id", self.new_journal_id),
                                    ("execution_seq", 0),
                                    ("execution_digest", "genesis"),
                                    ("revocation_epoch", old[columns.index("revocation_epoch")]+1),
                                    ("anchor_nonce", self.new_anchor_nonce)):
                    new[columns.index(name)] = value
                new = tuple(new)
                from ..runtime.restore_anchor import RestoreAnchor
                get = lambda name: new[columns.index(name)]
                self.current_anchor = RestoreAnchor(self.authority_id, self.namespace,
                    get("generation"), get("deletion_journal_id"), get("deletion_seq"),
                    get("deletion_digest"), get("execution_journal_id"), get("execution_seq"),
                    get("execution_digest"), get("revocation_epoch"), get("anchor_nonce"))
                changes.append(_change(table, columns, old, "rebuilt_from_surviving_sources", new))
                output.append(new)
            return tuple(output), tuple(changes)
        if table in ("authority_v2_fences", "authority_v2_mutations"):
            _need_columns(table, columns, ("namespace", "operation_id", "state"))
            if table == "authority_v2_mutations":
                _need_columns(table, columns, ("mutation_id", "mutation_kind", "pending"))
            else:
                _need_columns(table, columns, ("permit",))
            output = []
            for old in rows:
                if old[columns.index("namespace")] != self.namespace:
                    output.append(old)
                    continue
                op = old[columns.index("operation_id")]
                if table == "authority_v2_fences" and op.startswith("foreground-domain-"):
                    verified = self.foreground_fences.get(op)
                    if verified is None or tuple(old) != verified[0]:
                        raise AuthorityUnavailable("C09 foreground actual finished fence/Graph disposition is unconfirmed; HOLD")
                    if verified[1] == "preserved_exact":
                        # A surviving Graph receipt needs this real immutable finish
                        # on the next C09; it cannot be replaced by a guessed DTO.
                        output.append(old)
                        continue
                    if verified[1] != "derived_removed":
                        raise AuthorityUnavailable("C09 foreground fence disposition is unregistered")
                if table == "authority_v2_mutations" and old[columns.index("mutation_kind")] == "deletion":
                    # Historical pending/accepted/closed originals remain byte exact.
                    output.append(old)
                    continue
                if table == "authority_v2_fences":
                    from .v2_contract import decode_bytes
                    permit = decode_bytes(old[columns.index("permit")])
                    if permit.operation == "delete":
                        output.append(old)
                        if old[columns.index("state")] == "active":
                            if self.accepted_receipt is None or permit.operation_id != self.accepted_receipt.pending.permit.operation_id:
                                raise AuthorityUnavailable("C09 unrelated active deletion fence")
                            self.current_fence = (columns, old, permit)
                        continue
                if old[columns.index("state")] == "pending":
                    raise AuthorityUnavailable(f"C09 unappended execution obligation: {old[0]}")
                if table == "authority_v2_fences" and old[columns.index("state")] == "active":
                    # A prepared dispatch may never reacquire its old capability.
                    if old[columns.index("pending")] is not None:
                        raise AuthorityUnavailable("C09 live dispatch must drain before rebase")
                kind = "mutation" if table == "authority_v2_mutations" else "fence"
                item = old[columns.index("mutation_id")] if kind == "mutation" else op
                commitment = _row_commitment(table, columns, old)
                self._consume(kind, item, op, commitment)
                changes.append(_change(table, columns, old, "payload_erased_retained_facts"))
            return tuple(output), tuple(changes)
        if table == "authority_c09_consumed_execution_v1":
            for old in rows:
                if old[0] == self.namespace:
                    self._consume(old[1], old[2], old[3], old[4])
                    self.prior_ledger[(old[1],old[2])] = old
            return rows, ()
        if table in SINGLETONS:
            kind, json_column, digest_column = SINGLETONS[table]
            for old in rows:
                if old[columns.index("namespace")] == self.namespace:
                    raw = old[columns.index(json_column)]
                    original = json.loads(raw)
                    self.archive_rows.append((old[columns.index("operation_id")], kind,
                        original[digest_column], raw))
            if table == "authority_execution_redaction_seals_v3":
                expected = self.current_originals.get(table)
                scoped_rows = tuple(row for row in rows if row[columns.index("namespace")] == self.namespace)
                if not scoped_rows:
                    # Modern source preparation records only its genuine V4
                    # immutable source original. Never plant a compatibility
                    # PREPARED marker into the fresh target merely to retire it.
                    return rows, ()
                if expected is None or scoped_rows != (expected,):
                    raise AuthorityUnavailable("C09 retirement requires the exact current source PREPARED original")
                from .c09_recovery_frame_v4 import C09ExecutionSourceSealV4
                raw = json.loads(expected[2]); raw["suffix_row_commitments"] = tuple(raw["suffix_row_commitments"])
                if raw.get("schema") != "sylanne3.c09.execution_source_seal.v4":
                    raise AuthorityUnavailable("C09 legacy PREPARED marker has no installed retirement codec")
                seal = C09ExecutionSourceSealV4(**raw)
                if (seal.authority_id, seal.namespace, seal.operation_id, seal.execution_journal_id, seal.execution_seq,
                        seal.execution_digest) != (self.authority_id, self.namespace, self.operation_id,
                        self.old_journal_id, self.old_seq, self.old_digest):
                    raise AuthorityUnavailable("C09 retired PREPARED source cut differs")
                output = tuple(row for row in rows if row[columns.index("namespace")] != self.namespace)
                return output, tuple(_change(table, columns, row, "payload_erased_retained_facts") for row in scoped_rows)
            replacement = self.current_originals.get(table)
            if replacement is not None:
                output = tuple(row for row in rows if row[columns.index("namespace")] != self.namespace)+(replacement,)
                changed = tuple(_change(table,columns,row,"payload_erased_retained_facts",replacement) for row in rows if row[columns.index("namespace")] == self.namespace)
                return output,changed
            # Empty sidecar/switch current slots; archived originals remain immutable.
            if table in {"authority_execution_redaction_sidecar_pins_v3","authority_execution_redaction_switches_v3"}:
                output = tuple(row for row in rows if row[columns.index("namespace")] != self.namespace)
                return output,tuple(_change(table,columns,row,"payload_erased_retained_facts") for row in rows if row[columns.index("namespace")] == self.namespace)
            return rows, ()
        if table == "authority_v2_never_begun":
            from .v2_contract import FenceNeverBegunReceiptV2, canonical_bytes, decode_bytes

            _need_columns(table, columns, ("operation_id", "request_id", "receipt"))
            output = []
            for old in rows:
                try:
                    receipt = decode_bytes(old[columns.index("receipt")])
                    if (type(receipt) is not FenceNeverBegunReceiptV2
                            or canonical_bytes(receipt) != old[columns.index("receipt")]
                            or (receipt.operation_id, receipt.request_id) !=
                               (old[columns.index("operation_id")],
                                old[columns.index("request_id")])):
                        raise ValueError("typed receipt identity differs")
                except (TypeError, ValueError, UnicodeError) as exc:
                    raise AuthorityUnavailable(
                        f"C09 cannot classify {table} operation {old[0]}") from exc
                if receipt.namespace != self.namespace:
                    output.append(old)
                    continue
                commitment = _row_commitment(table, columns, old)
                self._consume("never_begun_operation", receipt.operation_id,
                              receipt.operation_id, commitment)
                self._consume("never_begun_request", receipt.request_id,
                              receipt.operation_id, commitment)
                changes.append(_change(table, columns, old, "payload_erased_retained_facts"))
            return tuple(output), tuple(changes)
        if table == "authority_execution_handoff_starts_v1":
            self._check_unsupported(table, columns, rows)
        if table == "authority_execution_handoff_graph_receipts_v1":
            # No namespace column: a prior target handoff is already a HOLD.
            pass
        if table == "authority_effects":
            _need_columns(table, columns, ("namespace", "effect_id", "state",
                                           "conflict_keys_json", "execution_seq"))
            for row in rows:
                if row[columns.index("namespace")] == self.namespace:
                    effect_id = row[columns.index("effect_id")]
                    if effect_id in self.effects:
                        raise AuthorityUnavailable("duplicate C09 effect identity")
                    self.effects[effect_id] = row
        return rows, ()

    def finish(self, db: sqlite3.Connection) -> None:
        from ..runtime_contracts import canonical_digest
        from .v2_contract import PendingMutationV2, decode_bytes

        if not self.namespace_seen:
            raise AuthorityUnavailable("C09 target namespace absent from Core")
        facts_by_id = {fact.execution_id: fact for fact in self.facts.executions}
        bindings_by_id = {} if self.bindings is None else {
            item.execution_id:item for item in self.bindings.execution_bindings}
        unknown_by_id = {fact.execution_id: fact for fact in self.facts.unknown_facts}
        latest: dict[str, tuple[tuple, PendingMutationV2]] = {}
        for row in self.execution_rows:
            _seq, mutation_id, _request, append_id, encoded, _prior, _digest_value = row
            from .d04_numeric_journal_v3 import ENTRY_PREFIX
            numeric = encoded.startswith(ENTRY_PREFIX)
            from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3
            authored_root = encoded.startswith(ROOT_ENTRY_PREFIX_V3)
            series = encoded.startswith(b'{"d04_series_original":')
            life = encoded.startswith(b'{"d11_life_original":')
            offline_tick = encoded.startswith(b'{"d11_offline_tick_original":')
            if authored_root:
                from .d04_root_execution_contract_v3 import D04RootExecutionBindingV3, root_execution_from_wire_v3
                binding = root_execution_from_wire_v3(json.loads(encoded)["d04_root_execution_original"]["binding"], D04RootExecutionBindingV3)
                if binding.authority_namespace != self.namespace:
                    raise AuthorityUnavailable("C09 authored-root namespace differs")
                business_operation, execution_id = binding.operation_id, binding.execution_id
            elif numeric:
                from .d04_numeric_contract_v3 import D04NumericBindingV3, from_wire as numeric_from_wire
                binding = numeric_from_wire(json.loads(encoded)["d04_numeric_original"]["binding"], D04NumericBindingV3)
                if binding.authority_namespace != self.namespace:
                    raise AuthorityUnavailable("C09 numeric namespace differs")
                business_operation, execution_id = binding.operation_id, binding.execution_id
            elif series:
                from .d04_series_contract_v1 import D04SeriesChunkBindingV1, from_wire as series_from_wire
                binding = series_from_wire(json.loads(encoded)["d04_series_original"]["binding"], D04SeriesChunkBindingV1).numeric
                if binding.authority_namespace != self.namespace:
                    raise AuthorityUnavailable("C09 series namespace differs")
                business_operation, execution_id = binding.operation_id, binding.execution_id
            elif life:
                from ..runtime.d11_life_contract_v1 import D11LifeExecutionBindingV1, life_from_wire_v1
                binding = life_from_wire_v1(json.loads(encoded)["d11_life_original"]["binding"], D11LifeExecutionBindingV1)
                if binding.authority_namespace != self.namespace:
                    raise AuthorityUnavailable("C09 Life namespace differs")
                business_operation, execution_id = binding.operation_id, binding.execution_id
            elif offline_tick:
                from .d11_offline_tick_contract_v1 import D11OfflineTickBindingV1, offline_tick_from_wire_v1
                binding = offline_tick_from_wire_v1(json.loads(encoded)["d11_offline_tick_original"]["binding"], D11OfflineTickBindingV1)
                if binding.authority_namespace != self.namespace:
                    raise AuthorityUnavailable("C09 offline namespace differs")
                business_operation, execution_id = binding.operation_id, binding.execution_id
            elif encoded.startswith(b'{"binding":'):
                from .internal_work_contract import InternalWorkBindingV1
                binding = InternalWorkBindingV1(**json.loads(encoded)["binding"])
                business_operation = binding.operation_id
                execution_id = binding.execution_id
            else:
                try:
                    pending = decode_bytes(encoded)
                except (TypeError, ValueError, UnicodeError) as exc:
                    raise AuthorityUnavailable(f"C09 execution row {row[0]} cannot decode") from exc
                if type(pending) is not PendingMutationV2 or pending.permit.namespace != self.namespace:
                    raise AuthorityUnavailable(f"C09 execution row {row[0]} identity differs")
                business_operation = pending.permit.operation_id
                execution_id = pending.permit.effect_id
                if execution_id is None or execution_id not in facts_by_id:
                    raise AuthorityUnavailable(f"C09 execution row {row[0]} lacks V4 fact")
                latest[execution_id] = row, pending
            self._consume("journal_mutation", mutation_id, business_operation,
                _row_commitment("authority_v2_execution_entries",
                    ("seq", "mutation_id", "request_digest", "append_id", "pending",
                     "previous_digest", "chain_digest"), row))
            self._consume("journal_append", append_id, business_operation, sha256(encoded).hexdigest())
            self._consume("execution_id", execution_id, business_operation,
                          facts_by_id[execution_id].input_commitment)
            if numeric or authored_root or series or offline_tick or life or encoded.startswith(b'{"binding":'):
                self._consume("internal_operation",business_operation,business_operation,
                              binding.digest if numeric or authored_root or series or offline_tick or life else binding.binding_digest)
        for fact in self.facts.executions:
            binding = bindings_by_id.get(fact.execution_id)
            if binding is None:
                if ("execution_id",fact.execution_id) not in self.consumed:
                    raise AuthorityUnavailable("C09 business operation binding absent: " + fact.execution_id)
            else:
                self._consume("execution_id", fact.execution_id, binding.business_operation_id,
                              fact.input_commitment)
        for original in self.model_originals:
            fact = facts_by_id.get(original.call_id)
            binding = bindings_by_id.get(original.call_id)
            expected_units = tuple(sorted(model_unit_fact_v4(original, unit).settlement_id
                for unit in original.units if unit.actual_or_none is not None))
            if (fact is None or binding is None or binding.execution_kind != "model"
                    or fact.signature_commitment != original.original_digest
                    or fact.input_commitment != original.request_digest
                    or original.original_digest not in binding.source_row_commitments
                    or binding.d11_settlement_ids != expected_units
                    or binding.originating_journal_id != original.originating_journal_id):
                raise AuthorityUnavailable("C09 model original is not bound to the authenticated recovery frame")
        if not set(latest).issubset(self.effects):
            raise AuthorityUnavailable("C09 effect index and old journal differ")
        if "authority_c09_consumed_execution_v1" not in _tables(db):
            db.execute(_LEDGER_DDL)
        if "authority_c09_unresolved_effects_v1" not in _tables(db):
            db.execute(_EFFECT_DDL)
        install_c09_archive_schema_v1(db)
        for operation_id, kind, commitment, original_json in self.archive_rows:
            prior = db.execute("SELECT 1 FROM authority_c09_originals_archive_v1 WHERE namespace=? AND operation_id=? AND original_kind=?", (self.namespace,operation_id,kind)).fetchone()
            if prior is None:
                archive_exact_original_v1(db, namespace=self.namespace, operation_id=operation_id,
                    original_kind=kind, original_digest=commitment, original_json=original_json,
                    maintenance_generation=self.maintenance_generation if operation_id == self.operation_id else self.maintenance_generation-1)
        for (kind, item_id), (operation_id, commitment) in sorted(self.consumed.items()):
            if (kind,item_id) in self.prior_ledger:
                continue
            db.execute(
                "INSERT INTO authority_c09_consumed_execution_v1 VALUES(?,?,?,?,?,?)",
                (self.namespace, kind, item_id, operation_id, commitment,
                 self.pin_digest))
        for effect_id, old in sorted(self.effects.items()):
            if old[2] != "unresolved":
                continue
            if effect_id not in latest:
                prior = db.execute("SELECT operation_id,footprint_commitment FROM authority_c09_unresolved_effects_v1 WHERE namespace=? AND effect_id=?", (self.namespace,effect_id)).fetchone()
                unknown = unknown_by_id.get(effect_id)
                if prior is None or unknown is None or prior != (unknown.footprint.operation_id,canonical_digest(unknown.footprint)):
                    raise AuthorityUnavailable("C09 unresolved historical effect lacks original footprint: " + effect_id)
                continue
            row, pending = latest[effect_id]
            unknown = unknown_by_id.get(effect_id)
            if unknown is None or pending.phase not in ("claimed", "observed"):
                raise AuthorityUnavailable(
                    f"C09 unresolved effect {effect_id} lacks unknown V4 fact")
            if old[4] != row[0] or pending.permit.operation_id != unknown.footprint.operation_id:
                raise AuthorityUnavailable(f"C09 effect {effect_id} old sequence differs")
            db.execute(
                "INSERT INTO authority_c09_unresolved_effects_v1 VALUES(?,?,?,?,?,?,?,?,?)",
                (self.namespace, effect_id, pending.permit.operation_id,
                 pending.mutation_id, pending.phase, row[0], row[6],
                 canonical_digest(unknown.footprint), _digest(old[3])))
        if self.bindings is not None:
            from dataclasses import asdict
            from ..runtime_contracts import canonical_serialize
            db.execute("INSERT INTO authority_c09_recovery_bindings_v1 VALUES(?,?,?,?)", (
                self.namespace,self.operation_id,canonical_serialize(asdict(self.bindings)),self.bindings.bindings_digest))
        if self.current_fence is not None:
            from dataclasses import asdict, replace
            from .v2_contract import canonical_bytes
            from .c09_storage_control_v1 import digest, canonical
            columns, old, permit = self.current_fence
            if self.current_anchor is None or self.accepted_receipt.after_anchor.execution_journal_id != self.old_journal_id:
                raise AuthorityUnavailable("C09 accepted anchor cannot transfer")
            continuation = replace(permit, token=self.continuation_permit_token,
                fence_epoch=permit.fence_epoch+1, revision=permit.revision+1,
                pinned_anchor=self.current_anchor)
            # Historical mutation updated_permit and receipt blobs stay unchanged.
            db.execute("UPDATE authority_v2_fences SET token=?,fence_epoch=?,revision=?,permit=? WHERE operation_id=?", (
                continuation.token,continuation.fence_epoch,continuation.revision,
                canonical_bytes(continuation),continuation.operation_id))
            db.execute("UPDATE authority_v2_epochs SET last_epoch=? WHERE namespace=?", (continuation.fence_epoch,self.namespace))
            body = dict(authority_id=self.authority_id, installation_id=self.installation_id,
                namespace=self.namespace, operation_id=self.operation_id,
                old_manifest_digest=self.old_manifest_digest, maintenance_generation=self.maintenance_generation,
                accepted_receipt_digest=canonical_digest(self.accepted_receipt),
                original_fence_permit_digest=canonical_digest(permit),
                before_anchor=asdict(self.accepted_receipt.after_anchor), after_anchor=asdict(self.current_anchor),
                continuation_permit=asdict(continuation))
            self.transition = {**body, "transition_digest":digest(body)}
            db.execute("INSERT INTO authority_c09_deletion_continuations_v1 VALUES(?,?,?,?)", (
                self.namespace,self.operation_id,canonical(self.transition),self.transition["transition_digest"]))


class _ExecutionTransform:
    required_tables = ("authority_v2_execution_meta", "authority_v2_execution_entries")

    def __init__(self, *, namespace: str, authority_id: str, operation_id: str,
                 old_journal_id: str, old_seq: int, old_digest: str,
                 new_journal_id: str, pin_digest: str, issue_digest: str,
                 new_core_path: Path):
        self.namespace = namespace
        self.authority_id = authority_id
        self.operation_id = operation_id
        self.old_journal_id = old_journal_id
        self.old_seq = old_seq
        self.old_digest = old_digest
        self.new_journal_id = new_journal_id
        self.pin_digest = pin_digest
        self.issue_digest = issue_digest
        self.new_core_path = new_core_path

    def __call__(self, table: str, columns: tuple[str, ...], rows: tuple[tuple, ...]):
        if table == "authority_v2_execution_redacted_prefix_v4":
            return (), tuple(_change(table,columns,row,"payload_erased_retained_facts") for row in rows)
        if table == "authority_v2_execution_entries":
            return (), tuple(_change(table, columns, row,
                                     "payload_erased_retained_facts") for row in rows)
        if table != "authority_v2_execution_meta":
            raise AuthorityUnavailable(f"unclassified execution table: {table}")
        if columns != ("key", "value"):
            raise AuthorityUnavailable("execution metadata shape differs")
        original = dict(rows)
        if (original.get("namespace") != self.namespace
                or original.get("journal_id") != self.old_journal_id
                or original.get("schema_version") not in ("1", "2", "4")):
            raise AuthorityUnavailable("source execution metadata differs from pin")
        from .v2_execution_journal import _CORE_SEAL_SOURCE_SCHEMA

        original["schema_version"] = "4"
        original["journal_id"] = self.new_journal_id
        original["core_redaction_source"] = json.dumps({
            "schema": _CORE_SEAL_SOURCE_SCHEMA,
            "core_path": str(self.new_core_path),
            "authority_id": self.authority_id,
            "namespace": self.namespace,
            "journal_id": self.new_journal_id,
        }, sort_keys=True, separators=(",", ":"))
        new_rows = tuple(sorted(original.items()))
        changes = tuple(_change(table, columns, row,
                                "rebuilt_from_surviving_sources",
                                (row[0], original[row[0]]))
                        for row in rows if original[row[0]] != row[1])
        return new_rows, changes

    def schema_sql(self,table,sql):
        if table == "authority_v2_execution_redacted_prefix_v4":
            from .v2_execution_journal import _PREFIX_DDL_V4
            return _PREFIX_DDL_V4
        return sql

    def finish(self, db: sqlite3.Connection) -> None:
        from .v2_execution_journal import _OBJECTS_V4, _OBJECTS

        for key, ddl in _OBJECTS_V4.items():
            if key not in _OBJECTS:
                if db.execute("SELECT 1 FROM sqlite_master WHERE type=? AND name=?",key).fetchone() is None:
                    db.execute(ddl)
        db.execute(
            "INSERT INTO authority_v2_execution_redacted_prefix_v4 VALUES(1,?,?,?,?,?,?,?,?,?)",
            (self.authority_id, self.namespace, self.operation_id,
             self.old_journal_id, self.old_seq, self.old_digest,
             self.pin_digest, self.issue_digest, self.new_journal_id))


class _DeletionTransform:
    required_tables = ("deletion_meta", "deletion_events")

    def __call__(self, table: str, columns: tuple[str, ...], rows: tuple[tuple, ...]):
        # The deletion chain is structural accepted-scope evidence and stays exact.
        return rows, ()

    def finish(self, db: sqlite3.Connection) -> None:
        pass


def build_installed_authority_storage_rebase_candidate_v1(
        *,core,closure,maintenance,operation_id,subject,credential,graph_mirror,targets):
    """Build from server-read originals and INTENT targets; never caller rows."""
    from dataclasses import asdict
    from ..runtime_contracts import canonical_digest,canonical_serialize
    from ..runtime.c09_graph_rebase_candidate_v1 import GraphRebaseMirrorV1
    from .c09_source_prepare_v4 import read_installed_source_bundle_v4
    from .c09_graph_rebase_issue_v1 import read_graph_rebase_issue_v1_locked
    from .c09_recovery_resolver_v4 import InstalledSanitizedRecoveryResolverV4
    if type(graph_mirror) is not GraphRebaseMirrorV1 or maintenance.core is not core or maintenance.closure is not closure:
        raise AuthorityUnavailable("installed C09 paired builder required")
    intent = maintenance.control.read_operation_event_v1(operation_id,"INTENT")
    if dict(targets) != intent["details"]["targets"]:
        raise AuthorityUnavailable("C09 builder targets differ from installed INTENT")
    bundle = read_installed_source_bundle_v4(core=core,closure=closure,
        credential=credential,subject=subject,operation_id=operation_id)
    with closure.deletion.freeze_writes():
        with closure.execution._transaction():
            with core._tx() as db:
                result, bindings, transition, issue = build_authority_storage_rebase_connections_v1(
                    core_db=db, execution_db=closure.execution._db, deletion_db=closure.deletion._db,
                    execution_reader=closure.execution, control=maintenance.control,
                    namespace=closure.namespace, installation_id=closure.installation_id,
                    inventory_manifest=maintenance.inventory_manifest, operation_id=operation_id,
                    graph_mirror=graph_mirror, targets=targets, bundle=bundle)
    maintenance._candidate_originals[operation_id] = dict(bundle=bundle, bindings=bindings,
        transition=transition, candidate=result, issue=issue)
    return result


def build_authority_storage_rebase_connections_v1(*, core_db, execution_db, deletion_db,
        execution_reader, control, namespace, installation_id, inventory_manifest,
        operation_id, graph_mirror, targets, bundle):
    """Build the three candidates directly from the actual frozen source connections."""
    from dataclasses import asdict
    from ..runtime_contracts import canonical_digest, canonical_serialize
    from ..runtime.c09_graph_rebase_candidate_v1 import GraphRebaseMirrorV1
    from .c09_graph_rebase_issue_v1 import read_graph_rebase_issue_original_v1
    from .c09_recovery_resolver_v4 import InstalledSanitizedRecoveryResolverV4
    from .c09_storage_control_v1 import C09StorageControlV1
    from .c09_storage_maintenance_v1 import (
        read_recovery_bindings_connection_v1, read_rebased_file_from_control_v1,
        retain_rebased_file_in_control_v1)
    if (type(control) is not C09StorageControlV1 or type(graph_mirror) is not GraphRebaseMirrorV1
            or not all(db.in_transaction for db in (core_db, execution_db, deletion_db))):
        raise AuthorityUnavailable("C09 candidate needs real frozen connections and installed control")
    control.lease.require_held()
    intent = control.read_operation_event_v1(operation_id, "INTENT")
    if dict(targets) != intent["details"]["targets"]:
        raise AuthorityUnavailable("C09 builder targets differ from installed INTENT")
    context = control.read_verified_current_storage_v1()
    seal,pin,frame = bundle["seal"],bundle["pin"],bundle["facts"]
    merged = InstalledSanitizedRecoveryResolverV4(storage_reader=control).read_merged_facts_v4()
    families = {}
    for name,key in (("executions","execution_id"),("d02_facts","quote_id"),
            ("d11_facts","settlement_id"),("unknown_facts","execution_id"),("graph_facts","operation_id")):
        values = {getattr(item,key):item for item in getattr(merged,name)}
        for item in getattr(frame,name):
            identity = getattr(item,key)
            if identity in values and values[identity] != item:
                raise AuthorityUnavailable("C09 current suffix reused consumed identity")
            values[identity] = item
        families[name] = tuple(item for _,item in sorted(values.items()))
    facts = _MergedRecoveryFactsV1(**families)
    bindings = read_recovery_bindings_connection_v1(control=control, core_db=core_db,
        execution_reader=execution_reader, namespace=namespace, bundle=bundle)
    issue = read_graph_rebase_issue_original_v1(core_db,namespace,operation_id=operation_id)
    if issue is None or issue.issue_digest != graph_mirror.core_issue_digest:
        raise AuthorityUnavailable("C09 graph mirror issue differs")
    saved_plan = control.read_build_original_v1(operation_id=operation_id, kind="authority_build_plan")
    if saved_plan is None:
        saved_plan = control.record_build_original_v1(operation_id=operation_id,
            kind="authority_build_plan", details={"new_execution_journal_id": "c09-execution-" + __import__('secrets').token_hex(16),
                "facts_pin_digest": pin.pin_digest, "graph_issue_digest": issue.issue_digest,
                "new_anchor_nonce": __import__('secrets').token_hex(32),
                "continuation_permit_token": __import__('secrets').token_hex(32)})
    if (saved_plan["details"]["facts_pin_digest"] != pin.pin_digest
            or saved_plan["details"]["graph_issue_digest"] != issue.issue_digest):
        raise AuthorityUnavailable("C09 durable build plan originals differ")
    fresh_id = saved_plan["details"]["new_execution_journal_id"]
    current_originals = {
        "authority_execution_redaction_seals_v3":(namespace,operation_id,canonical_serialize(asdict(seal))),
        "authority_execution_recovery_facts_pins_v4":(namespace,operation_id,canonical_serialize(asdict(pin))),
        "authority_execution_recovery_facts_v4":(namespace,operation_id,canonical_serialize(asdict(frame))),
        "authority_c09_graph_rebase_issues_v1":(namespace,operation_id,canonical_serialize(asdict(issue))),
    }
    current_originals["model_budget_originals"] = read_model_budget_originals_v1(core_db, namespace=namespace, operation_id=operation_id, meter=current_c09_sql_meter_v2())
    from ..runtime.c09_foreground_attempt_v1 import foreground_core_dispositions_v1
    current_originals["foreground_fences"] = foreground_core_dispositions_v1(core_db,
        control=control, operation_id=operation_id, issue=issue, mirror=graph_mirror)
    current_originals["owner_reply_stops"]=_owner_stop_reply_core_dispositions_v1(core_db,
        control=control,operation_id=operation_id,issue=issue,mirror=graph_mirror)
    transform = _CoreTransform(namespace=namespace,operation_id=operation_id,
        authority_id=seal.authority_id,pin_digest=pin.pin_digest,new_journal_id=fresh_id,
        new_anchor_nonce=saved_plan["details"]["new_anchor_nonce"],
        continuation_permit_token=saved_plan["details"]["continuation_permit_token"],
        old_journal_id=pin.old_journal_id,old_seq=pin.old_seq,old_digest=pin.old_digest,
        facts=facts,execution_rows=bundle["rows"],bindings=bindings,
        accepted_receipt=bundle["accepted_receipt"],old_manifest_digest=context.manifest_digest,
        maintenance_generation=context.storage_generation+1,installation_id=installation_id,
        current_originals=current_originals)
    completed_core = read_rebased_file_from_control_v1(control, operation_id=operation_id, role="core")
    if completed_core is None:
        core_file,core_rows = _build_file(core_db,Path(targets["core"]),_KNOWN_CORE_TABLES,transform,
            control=control, operation_id=operation_id, role="core")
        transition = transform.transition
        retain_rebased_file_in_control_v1(control, operation_id=operation_id, role="core",
            file=core_file, rows=core_rows, transition=transition)
    else:
        core_file, core_rows, transition = completed_core
        _require_completed_source_v1(core_db, core_file)
    completed_execution = read_rebased_file_from_control_v1(control, operation_id=operation_id, role="execution")
    if completed_execution is None:
        execution_file,execution_rows = _build_file(execution_db,Path(targets["execution"]),
            frozenset({"authority_v2_execution_meta","authority_v2_execution_entries","authority_v2_execution_redacted_prefix_v4"}),
            _ExecutionTransform(namespace=namespace,authority_id=seal.authority_id,
                operation_id=operation_id,old_journal_id=pin.old_journal_id,old_seq=pin.old_seq,
                old_digest=pin.old_digest,new_journal_id=fresh_id,pin_digest=pin.pin_digest,
                issue_digest=issue.issue_digest,new_core_path=Path(targets["core"])),
            control=control, operation_id=operation_id, role="execution")
        retain_rebased_file_in_control_v1(control, operation_id=operation_id, role="execution",
            file=execution_file, rows=execution_rows)
    else:
        execution_file, execution_rows, _ = completed_execution
        _require_completed_source_v1(execution_db, execution_file)
    completed_deletion = read_rebased_file_from_control_v1(control, operation_id=operation_id, role="deletion")
    if completed_deletion is None:
        deletion_file,deletion_rows = _build_file(deletion_db,Path(targets["deletion"]),
            _KNOWN_DELETION_TABLES,_DeletionTransform(), control=control,
            operation_id=operation_id, role="deletion")
        retain_rebased_file_in_control_v1(control, operation_id=operation_id, role="deletion",
            file=deletion_file, rows=deletion_rows)
    else:
        deletion_file, deletion_rows, _ = completed_deletion
        _require_completed_source_v1(deletion_db, deletion_file)
    changed = tuple(sorted((*core_rows,*execution_rows,*deletion_rows),key=lambda r:(r.table_name,r.row_key_digest)))
    body = (seal.authority_id,namespace,operation_id,pin.pin_digest,issue.issue_digest,
        pin.old_journal_id,pin.old_seq,pin.old_digest,fresh_id,core_file,execution_file,deletion_file,
        changed,inventory_manifest.manifest_digest)
    result = AuthorityStorageRebaseCandidateV1(*body,canonical_digest(body))
    control.record_build_original_v1(operation_id=operation_id, kind="storage_candidate",
        details={"candidate": asdict(result), "transition": transition,
            "bindings_digest": bindings.bindings_digest, "issue_digest": issue.issue_digest})
    return result, bindings, transition, issue


@dataclass(frozen=True, slots=True)
class _MergedRecoveryFactsV1:
    executions: tuple
    d02_facts: tuple
    d11_facts: tuple
    unknown_facts: tuple
    graph_facts: tuple


def _require_completed_source_v1(db, original):
    path = _db_path(db)
    if (str(path) != original.source_path or _identity(path) != original.source_identity
            or _files_sha(path) != original.source_files_sha256 or _root(db) != original.source_data_root):
        raise AuthorityUnavailable("completed C09 candidate source snapshot changed")
