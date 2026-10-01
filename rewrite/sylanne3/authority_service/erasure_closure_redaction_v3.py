"""Core-owned PREPARED seal for a future execution-journal redaction.

This is a migration blocker and old-row commitment, not a cleanup receipt.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import quote

from .contract import AuthorityUnavailable, identifier


_SCHEMA = "sylanne3.authority.execution_redaction_seal.v3"
_TABLE = "authority_execution_redaction_seals_v3"
_DDL = f"""CREATE TABLE {_TABLE}(
    namespace TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE,
    seal_json TEXT NOT NULL) STRICT"""
_PIN_TABLE = "authority_execution_redaction_sidecar_pins_v3"
_PIN_DDL = f"""CREATE TABLE {_PIN_TABLE}(
    namespace TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE,
    pin_json TEXT NOT NULL) STRICT"""
_SWITCH_TABLE = "authority_execution_redaction_switches_v3"
_SWITCH_DDL = f"""CREATE TABLE {_SWITCH_TABLE}(
    namespace TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE,
    switch_json TEXT NOT NULL) STRICT"""
_HEX = re.compile(r"[0-9a-f]{64}\Z")


def _canonical_digest(value) -> str:
    from ..runtime_contracts import canonical_digest

    return canonical_digest(value)


def _canonical_serialize(value) -> str:
    from ..runtime_contracts import canonical_serialize

    return canonical_serialize(value)


def _digest(value: str, name: str) -> None:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


@dataclass(frozen=True, slots=True)
class ExecutionRowCommitmentV3:
    seq: int
    mutation_id: str
    request_digest: str
    append_id: str
    previous_digest: str
    chain_digest: str
    body_digest: str
    body_bytes: int
    entry_kind: str
    terminal_status: str | None
    actual_cpu_ms: int | None

    def __post_init__(self) -> None:
        if type(self.seq) is not int or self.seq < 1:
            raise ValueError("redaction row sequence is invalid")
        for name in ("mutation_id", "append_id"):
            identifier(getattr(self, name), name)
        for name in ("request_digest", "chain_digest", "body_digest"):
            value = getattr(self, name)
            if name == "request_digest" and type(value) is str and _HEX.fullmatch(value):
                continue  # Internal-work claim/terminal content digest.
            if type(value) is not str or not value.startswith("sha256:"):
                raise ValueError(f"invalid {name}")
            _digest(value.removeprefix("sha256:"), name)
        if self.previous_digest != "genesis":
            if not self.previous_digest.startswith("sha256:"):
                raise ValueError("invalid prior execution digest")
            _digest(self.previous_digest.removeprefix("sha256:"), "previous_digest")
        if type(self.body_bytes) is not int or self.body_bytes < 1:
            raise ValueError("empty execution body cannot be sealed")
        if self.entry_kind not in {
                "mutation_prepared", "mutation_claimed", "mutation_observed",
                "internal_claim", "internal_terminal", "numeric_claim", "numeric_terminal",
                "series_claim", "series_terminal", "life_claim", "life_terminal", "offline_tick_claim", "offline_tick_terminal", "authored_root_claim", "authored_root_terminal"}:
            raise ValueError("unknown execution row kind")
        if self.entry_kind in {"internal_terminal", "numeric_terminal", "series_terminal", "life_terminal", "offline_tick_terminal", "authored_root_terminal"}:
            allowed = {"completed", "failed", "unknown"} if self.entry_kind != "series_terminal" else {
                "chunk_completed", "failed", "unknown"}
            if self.terminal_status not in allowed:
                raise ValueError("internal terminal status is invalid")
            if self.terminal_status == "unknown":
                if self.actual_cpu_ms is not None:
                    raise ValueError("unknown work cannot claim zero cost")
            elif type(self.actual_cpu_ms) is not int or self.actual_cpu_ms < 0:
                raise ValueError("observed work requires measured cost")
        elif self.terminal_status is not None or self.actual_cpu_ms is not None:
            raise ValueError("only terminals can carry execution cost")


@dataclass(frozen=True, slots=True)
class ExecutionRedactionPreparedV3:
    authority_id: str
    namespace: str
    installation_id: str
    operation_id: str
    accepted_receipt_digest: str
    cleanup_run_digest: str
    inventory_receipt_digest: str
    registry_digest: str
    execution_journal_id: str
    execution_seq: int
    execution_digest: str
    rows: tuple[ExecutionRowCommitmentV3, ...]
    seal_digest: str
    stage: str = "prepared"
    schema: str = _SCHEMA

    def __post_init__(self) -> None:
        for name in ("authority_id", "namespace", "installation_id",
                     "operation_id", "execution_journal_id"):
            identifier(getattr(self, name), name)
        for name in ("accepted_receipt_digest", "cleanup_run_digest",
                     "inventory_receipt_digest", "registry_digest", "seal_digest"):
            _digest(getattr(self, name), name)
        if (self.schema != _SCHEMA or self.stage != "prepared"
                or type(self.execution_seq) is not int or self.execution_seq < 1
                or type(self.rows) is not tuple or len(self.rows) != self.execution_seq
                or any(type(row) is not ExecutionRowCommitmentV3
                       for row in self.rows)):
            raise ValueError("PREPARED seal requires a non-empty full execution chain")
        previous = "genesis"
        for expected, row in enumerate(self.rows, 1):
            if row.seq != expected or row.previous_digest != previous:
                raise ValueError("execution row commitments are not an ordered chain")
            previous = row.chain_digest
        if self.execution_digest != previous:
            raise ValueError("sealed execution head differs from row commitments")
        if self.seal_digest != _canonical_digest((
                self.schema, self.authority_id, self.namespace,
                self.installation_id, self.operation_id,
                self.accepted_receipt_digest, self.cleanup_run_digest,
                self.inventory_receipt_digest, self.registry_digest,
                self.execution_journal_id, self.execution_seq,
                self.execution_digest, self.rows, self.stage)):
            raise ValueError("PREPARED seal digest differs")


@dataclass(frozen=True, slots=True)
class ExecutionRedactionSidecarPinV3:
    authority_id: str
    namespace: str
    operation_id: str
    seal_digest: str
    sidecar_path: str
    certificate_digest: str
    sanitized_head_digest: str
    row_count: int
    pin_digest: str
    stage: str = "sidecar_pinned_hold"
    schema: str = "sylanne3.authority.execution_redaction_sidecar_pin.v3"

    def __post_init__(self) -> None:
        for name in ("authority_id", "namespace", "operation_id"):
            identifier(getattr(self, name), name)
        for name in ("seal_digest", "certificate_digest",
                     "sanitized_head_digest", "pin_digest"):
            _digest(getattr(self, name), name)
        if (type(self.sidecar_path) is not str
                or not Path(self.sidecar_path).is_absolute()
                or str(Path(self.sidecar_path).resolve()) != self.sidecar_path
                or type(self.row_count) is not int or self.row_count < 1
                or self.stage != "sidecar_pinned_hold"
                or self.schema !=
                   "sylanne3.authority.execution_redaction_sidecar_pin.v3"):
            raise ValueError("sidecar pin shape differs")
        if self.pin_digest != _canonical_digest((
                self.schema, self.authority_id, self.namespace,
                self.operation_id, self.seal_digest, self.sidecar_path,
                self.certificate_digest, self.sanitized_head_digest,
                self.row_count, self.stage)):
            raise ValueError("sidecar pin digest differs")


@dataclass(frozen=True, slots=True)
class ExecutionRedactionSwitchV3:
    authority_id: str
    namespace: str
    operation_id: str
    seal_digest: str
    pin_digest: str
    certificate_digest: str
    old_journal_id: str
    old_seq: int
    old_digest: str
    new_journal_id: str
    new_seq: int
    new_digest: str
    facts_digest: str
    signed_terminal_digests: tuple[str, ...]
    before_anchor_digest: str
    after_anchor_digest: str
    switch_digest: str
    stage: str = "identity_switched_hold"
    schema: str = "sylanne3.authority.execution_redaction_switch.v3"

    def __post_init__(self) -> None:
        for name in ("authority_id", "namespace", "operation_id",
                     "old_journal_id", "new_journal_id"):
            identifier(getattr(self, name), name)
        for name in ("seal_digest", "pin_digest", "certificate_digest",
                     "facts_digest", "before_anchor_digest", "after_anchor_digest",
                     "switch_digest"):
            _digest(getattr(self, name), name)
        if (self.stage != "identity_switched_hold" or
                self.schema != "sylanne3.authority.execution_redaction_switch.v3"
                or type(self.old_seq) is not int or self.old_seq < 1
                or self.new_seq != self.old_seq
                or type(self.signed_terminal_digests) is not tuple):
            raise ValueError("execution redaction switch shape differs")
        for value in self.signed_terminal_digests:
            _digest(value, "signed_terminal_digest")
        for name in ("old_digest", "new_digest"):
            value = getattr(self, name)
            if type(value) is not str or not value.startswith("sha256:"):
                raise ValueError("execution redaction switch head differs")
            _digest(value.removeprefix("sha256:"), name)
        if self.switch_digest != _canonical_digest((
                self.schema, self.authority_id, self.namespace,
                self.operation_id, self.seal_digest, self.pin_digest,
                self.certificate_digest, self.old_journal_id, self.old_seq,
                self.old_digest, self.new_journal_id, self.new_seq,
                self.new_digest, self.facts_digest,
                self.signed_terminal_digests, self.before_anchor_digest,
                self.after_anchor_digest, self.stage)):
            raise ValueError("execution redaction switch commitment differs")


def execution_row_commitment_v3(journal, row) -> ExecutionRowCommitmentV3:
    """Project a fully scanned old row to content-free migration material."""
    encoded = row[4]
    from .d04_series_journal_v1 import ENTRY_PREFIX as SERIES_PREFIX, decode_series_row_v1
    from .d04_numeric_journal_v3 import ENTRY_PREFIX, decode_numeric_row_v3
    from .d11_life_journal_v1 import ENTRY_PREFIX as LIFE_PREFIX, decode_life_row_v1
    from .d11_offline_tick_journal_v1 import ENTRY_PREFIX as OFFLINE_PREFIX, decode_offline_tick_row_v1
    from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3, decode_root_execution_row_v3
    if encoded.startswith(LIFE_PREFIX) or encoded.startswith(OFFLINE_PREFIX):
        family,decoder=("life",decode_life_row_v1) if encoded.startswith(LIFE_PREFIX) else ("offline_tick",decode_offline_tick_row_v1)
        _binding,_claim,terminal=decoder(journal,row)
        kind=family+("_claim" if terminal is None else "_terminal")
        status=None if terminal is None else terminal.status
        cost=None if terminal is None else terminal.actual_cpu_ms
    elif encoded.startswith(ROOT_ENTRY_PREFIX_V3):
        _binding,_claim,measurement=decode_root_execution_row_v3(journal,row)
        kind="authored_root_claim" if measurement is None else "authored_root_terminal"
        status=None if measurement is None else measurement.status
        cost=None if measurement is None else measurement.actual_cpu_ms
    elif encoded.startswith(SERIES_PREFIX):
        _binding, _claim, measurement = decode_series_row_v1(journal, row)
        kind = "series_claim" if measurement is None else "series_terminal"
        status = None if measurement is None else measurement.status
        cost = None if measurement is None else measurement.actual_cpu_ms
    elif encoded.startswith(ENTRY_PREFIX):
        _binding, _claim, measurement = decode_numeric_row_v3(journal, row)
        kind = "numeric_claim" if measurement is None else "numeric_terminal"
        status = None if measurement is None else measurement.status
        cost = None if measurement is None else measurement.actual_cpu_ms
    elif encoded.startswith(b'{"binding":'):
        _binding, _claim, terminal = journal._decode_internal_row(row)
        kind = "internal_claim" if terminal is None else "internal_terminal"
        status = None if terminal is None else terminal.status
        cost = None if terminal is None else terminal.actual_cpu_ms
    else:
        from .v2_contract import PendingMutationV2, decode_bytes

        pending = decode_bytes(encoded)
        if type(pending) is not PendingMutationV2:
            raise AuthorityUnavailable("execution seal row is not a typed pending")
        kind = "mutation_" + pending.phase
        status = cost = None
    return ExecutionRowCommitmentV3(
        row[0], row[1], row[2], row[3], row[5], row[6],
        "sha256:" + hashlib.sha256(encoded).hexdigest(), len(encoded),
        kind, status, cost)


def install_execution_redaction_schema(db: sqlite3.Connection) -> None:
    for table, ddl, message in (
            (_TABLE, _DDL, "execution redaction seal immutable"),
            (_PIN_TABLE, _PIN_DDL, "execution redaction pin immutable"),
            (_SWITCH_TABLE, _SWITCH_DDL, "execution redaction switch immutable")):
        db.execute(ddl.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
        for action in ("UPDATE", "DELETE"):
            db.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_{action.lower()}_immutable "
                f"BEFORE {action} ON {table} "
                f"BEGIN SELECT RAISE(ABORT,'{message}'); END")
    require_execution_redaction_schema(db)


def require_execution_redaction_schema(db: sqlite3.Connection) -> None:
    for table, ddl, columns, message in (
            (_TABLE, _DDL, ("namespace", "operation_id", "seal_json"),
             "execution redaction seal immutable"),
            (_PIN_TABLE, _PIN_DDL, ("namespace", "operation_id", "pin_json"),
             "execution redaction pin immutable"),
            (_SWITCH_TABLE, _SWITCH_DDL,
             ("namespace", "operation_id", "switch_json"),
             "execution redaction switch immutable")):
        found_columns = tuple(
            row[1] for row in db.execute(f"PRAGMA table_info({table})"))
        found_ddl = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (table,)).fetchone()
        triggers = {row[0]: row[1] for row in db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?",
            (table,))}
        immutable_names = {
            f"{table}_update_immutable", f"{table}_delete_immutable"}
        # Final dispatch admission instruments all Core tables with a paired
        # epoch trigger set. Accept only that exact installed set and SQL;
        # rejecting every extra trigger would break legitimate Owner handoff.
        digest = hashlib.sha256(table.encode("utf-8")).hexdigest()[:24]
        epoch_triggers = {
            f"authority_dispatch_epoch_{action.lower()}_{digest}_v1":
            f"CREATE TRIGGER authority_dispatch_epoch_{action.lower()}_{digest}_v1 "
            f"AFTER {action} ON \"{table}\" "
            "BEGIN UPDATE authority_dispatch_admission_epoch_v1 "
            "SET epoch=epoch+1 WHERE id=1; END"
            for action in ("INSERT", "UPDATE", "DELETE")}
        extras = set(triggers) - immutable_names
        if (found_ddl != (ddl,) or found_columns != columns
                or extras not in (set(), set(epoch_triggers))
                or any(triggers.get(name) != sql
                       for name, sql in epoch_triggers.items()
                       if name in extras)
                or any(f"RAISE(ABORT,'{message}')" not in triggers.get(name, "")
                       for name in immutable_names)):
            raise AuthorityUnavailable("execution redaction Core schema differs")


def read_execution_redaction_pin_locked(
        db: sqlite3.Connection, namespace: str,
) -> ExecutionRedactionSidecarPinV3 | None:
    require_execution_redaction_schema(db)
    row = db.execute(
        f"SELECT operation_id,pin_json FROM {_PIN_TABLE} WHERE namespace=?",
        (namespace,)).fetchone()
    if row is None:
        return None
    try:
        pin = ExecutionRedactionSidecarPinV3(**json.loads(row[1]))
    except (TypeError, ValueError, KeyError) as exc:
        raise AuthorityUnavailable("execution redaction sidecar pin malformed") from exc
    if (pin.namespace != namespace or pin.operation_id != row[0]
            or _canonical_serialize(asdict(pin)) != row[1]):
        raise AuthorityUnavailable("execution redaction sidecar pin differs")
    return pin


def read_execution_redaction_switch_locked(
        db: sqlite3.Connection, namespace: str,
) -> ExecutionRedactionSwitchV3 | None:
    require_execution_redaction_schema(db)
    row = db.execute(
        f"SELECT operation_id,switch_json FROM {_SWITCH_TABLE} WHERE namespace=?",
        (namespace,)).fetchone()
    if row is None:
        return None
    try:
        shape = json.loads(row[1])
        shape["signed_terminal_digests"] = tuple(
            shape["signed_terminal_digests"])
        switch = ExecutionRedactionSwitchV3(**shape)
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthorityUnavailable("execution redaction switch malformed") from exc
    if (switch.namespace != namespace or switch.operation_id != row[0]
            or _canonical_serialize(asdict(switch)) != row[1]):
        raise AuthorityUnavailable("execution redaction switch differs")
    return switch


def read_execution_redaction_seal_locked(
        db: sqlite3.Connection, namespace: str,
) -> ExecutionRedactionPreparedV3 | None:
    require_execution_redaction_schema(db)
    row = db.execute(
        f"SELECT operation_id,seal_json FROM {_TABLE} WHERE namespace=?",
        (namespace,)).fetchone()
    if row is None:
        return None
    try:
        shape = json.loads(row[1])
        if shape.get("schema") == "sylanne3.c09.execution_source_seal.v4":
            from .c09_recovery_frame_v4 import C09ExecutionSourceSealV4
            shape["suffix_row_commitments"] = tuple(shape["suffix_row_commitments"])
            seal = C09ExecutionSourceSealV4(**shape)
        else:
            shape["rows"] = tuple(ExecutionRowCommitmentV3(**item) for item in shape["rows"])
            seal = ExecutionRedactionPreparedV3(**shape)
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthorityUnavailable("execution redaction seal original malformed") from exc
    if (row[0] != seal.operation_id or namespace != seal.namespace
            or _canonical_serialize(asdict(seal)) != row[1]):
        raise AuthorityUnavailable("execution redaction seal original differs")
    return seal


def require_no_execution_redaction_locked(
        db: sqlite3.Connection, namespace: str | None = None,
) -> None:
    require_execution_redaction_schema(db)
    if namespace is None:
        blocked = db.execute(f"SELECT 1 FROM {_TABLE} LIMIT 1").fetchone()
    else:
        blocked = db.execute(
            f"SELECT 1 FROM {_TABLE} WHERE namespace=?", (namespace,)).fetchone()
    if blocked is not None:
        raise AuthorityUnavailable("PREPARED execution redaction blocks old v2 entry")


def require_no_execution_redaction_at_path(
        core_path: Path, *, namespace: str, authority_id: str,
) -> None:
    """Independent old-journal gate; it never creates a missing Core file."""
    if not core_path.is_file():
        raise AuthorityUnavailable("execution redaction Core seal source is absent")
    uri = "file:" + quote(core_path.as_posix(), safe="/:") + "?mode=ro"
    try:
        db = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            db.execute("PRAGMA query_only=ON")
            current = db.execute(
                "SELECT value FROM authority_meta WHERE key='authority_id'").fetchone()
            if current != (authority_id,):
                raise AuthorityUnavailable("execution redaction Core identity differs")
            require_no_execution_redaction_locked(db, namespace)
        finally:
            db.close()
    except sqlite3.Error as exc:
        raise AuthorityUnavailable("execution redaction Core seal source unavailable") from exc


def read_execution_redaction_seal_at_path(
        core_path: Path, *, namespace: str, authority_id: str,
) -> ExecutionRedactionPreparedV3:
    """Read the original PREPARED seal without opening an ordinary V2 port."""
    if not core_path.is_file():
        raise AuthorityUnavailable("execution redaction Core seal source is absent")
    uri = "file:" + quote(core_path.as_posix(), safe="/:") + "?mode=ro"
    try:
        db = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            db.execute("PRAGMA query_only=ON")
            identity = db.execute(
                "SELECT value FROM authority_meta WHERE key='authority_id'"
            ).fetchone()
            if identity != (authority_id,):
                raise AuthorityUnavailable("execution redaction Core identity differs")
            seal = read_execution_redaction_seal_locked(db, namespace)
            if seal is None or seal.authority_id != authority_id:
                raise AuthorityUnavailable("PREPARED execution seal is absent")
            return seal
        finally:
            db.close()
    except sqlite3.Error as exc:
        raise AuthorityUnavailable("execution redaction Core seal unavailable") from exc


__all__ = ["ExecutionRowCommitmentV3", "ExecutionRedactionPreparedV3",
           "ExecutionRedactionSidecarPinV3", "read_execution_redaction_pin_locked",
           "execution_row_commitment_v3", "install_execution_redaction_schema",
           "read_execution_redaction_seal_locked", "require_no_execution_redaction_locked",
           "require_no_execution_redaction_at_path",
           "read_execution_redaction_seal_at_path"]
