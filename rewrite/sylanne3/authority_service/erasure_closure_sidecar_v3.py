"""Installer-owned sanitized execution sidecar, pinned to Core PREPARED.

The old journal and Core execution head remain untouched. A pinned sidecar is
only a recoverable migration candidate; it is not a cleanup-complete receipt.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import quote

from ..runtime_contracts import canonical_digest, canonical_serialize
from .contract import AuthorityUnavailable, JournalHead, identifier
from .erasure_closure_inventory import (
    AuthorityErasureClosureInventory, CleanupRunV2, _TABLES,
)
from .erasure_closure_redaction_v3 import (
    ExecutionRedactionPreparedV3, ExecutionRedactionSidecarPinV3,
    ExecutionRedactionSwitchV3, read_execution_redaction_pin_locked,
    read_execution_redaction_seal_locked, read_execution_redaction_switch_locked,
)
from .v2_contract import PendingMutationV2, decode_bytes
from .v2_execution_journal import AuthorityV2ExecutionJournal


_ROW_SCHEMA = "sylanne3.authority.execution_sanitized_row.v3"
_CERT_SCHEMA = "sylanne3.authority.execution_sidecar_certificate.v3"
_TABLE_ROWS = "authority_execution_sanitized_rows_v3"
_TABLE_CERT = "authority_execution_sidecar_certificate_v3"
_ROW_DDL = f"""CREATE TABLE {_TABLE_ROWS}(
    seq INTEGER PRIMARY KEY CHECK(seq > 0), row_json TEXT NOT NULL) STRICT"""
_CERT_DDL = f"""CREATE TABLE {_TABLE_CERT}(
    id INTEGER PRIMARY KEY CHECK(id = 1), certificate_json TEXT NOT NULL) STRICT"""
_HEX = re.compile(r"[0-9a-f]{64}\Z")


def _hex(value: str, name: str) -> None:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


@dataclass(frozen=True, slots=True)
class SanitizedExecutionRowV3:
    seq: int
    mutation_id: str
    append_id: str
    entry_kind: str
    old_body_digest: str
    old_chain_digest: str
    operation_id: str
    effect_id: str | None
    binding_digest: str | None
    claim_mutation_id: str | None
    terminal_status: str | None
    actual_cpu_ms: int | None
    result_digest: str | None
    unknown_constraint: str
    previous_sanitized_digest: str
    sanitized_digest: str
    schema: str = _ROW_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != _ROW_SCHEMA or type(self.seq) is not int or self.seq < 1:
            raise ValueError("sanitized execution row schema or sequence differs")
        for name in ("mutation_id", "append_id", "operation_id"):
            identifier(getattr(self, name), name)
        for name in ("effect_id", "claim_mutation_id"):
            value = getattr(self, name)
            if value is not None:
                identifier(value, name)
        for name in ("old_body_digest", "old_chain_digest"):
            value = getattr(self, name)
            if type(value) is not str or not value.startswith("sha256:"):
                raise ValueError("sanitized row old commitment differs")
            _hex(value.removeprefix("sha256:"), name)
        for name in ("binding_digest", "result_digest"):
            value = getattr(self, name)
            if value is not None:
                _hex(value, name)
        if (self.entry_kind not in {
                "mutation_prepared", "mutation_claimed", "mutation_observed",
                "internal_claim", "internal_terminal"}
                or self.unknown_constraint not in {
                    "none", "prepared_unresolved", "claim_unobserved",
                    "internal_claim_open", "terminal_unknown"}):
            raise ValueError("sanitized row state differs")
        if self.entry_kind.startswith("internal_"):
            if self.effect_id is not None or self.binding_digest is None:
                raise ValueError("internal work binding cannot be an effect")
        elif (self.binding_digest is not None
              or self.claim_mutation_id is not None
              or self.terminal_status is not None
              or self.actual_cpu_ms is not None
              or self.result_digest is not None):
            raise ValueError("mutation row cannot claim internal cost")
        if self.entry_kind == "internal_terminal":
            if self.terminal_status not in {"completed", "failed", "unknown"}:
                raise ValueError("terminal status differs")
            if self.terminal_status == "unknown":
                if (self.actual_cpu_ms is not None
                        or self.result_digest is not None
                        or self.unknown_constraint != "terminal_unknown"):
                    raise ValueError("unknown cost cannot become zero")
            elif type(self.actual_cpu_ms) is not int or self.actual_cpu_ms < 0:
                raise ValueError("measured terminal cost required")
        elif (self.terminal_status is not None or self.actual_cpu_ms is not None
              or self.result_digest is not None):
            raise ValueError("only terminal rows carry status and cost")
        if self.previous_sanitized_digest != "genesis":
            _hex(self.previous_sanitized_digest, "previous_sanitized_digest")
        _hex(self.sanitized_digest, "sanitized_digest")
        if self.sanitized_digest != canonical_digest((
                self.schema, self.seq, self.mutation_id, self.append_id,
                self.entry_kind, self.old_body_digest, self.old_chain_digest,
                self.operation_id, self.effect_id, self.binding_digest,
                self.claim_mutation_id, self.terminal_status,
                self.actual_cpu_ms, self.result_digest,
                self.unknown_constraint, self.previous_sanitized_digest)):
            raise ValueError("sanitized execution row digest differs")


@dataclass(frozen=True, slots=True)
class ExecutionSidecarCertificateV3:
    authority_id: str
    namespace: str
    operation_id: str
    seal_digest: str
    old_journal_id: str
    old_seq: int
    old_digest: str
    row_count: int
    rows_digest: str
    sanitized_head_digest: str
    unresolved_mutation_ids: tuple[str, ...]
    certificate_digest: str
    status: str = "sidecar_only_hold"
    schema: str = _CERT_SCHEMA

    def __post_init__(self) -> None:
        for name in ("authority_id", "namespace", "operation_id",
                     "old_journal_id"):
            identifier(getattr(self, name), name)
        if (self.schema != _CERT_SCHEMA or self.status != "sidecar_only_hold"
                or type(self.old_seq) is not int or self.old_seq < 1
                or type(self.row_count) is not int or self.row_count != self.old_seq
                or type(self.unresolved_mutation_ids) is not tuple
                or self.unresolved_mutation_ids
                   != tuple(sorted(set(self.unresolved_mutation_ids)))):
            raise ValueError("sidecar certificate shape differs")
        for name in ("seal_digest", "rows_digest", "sanitized_head_digest",
                     "certificate_digest"):
            _hex(getattr(self, name), name)
        if not self.old_digest.startswith("sha256:"):
            raise ValueError("old execution head digest differs")
        _hex(self.old_digest.removeprefix("sha256:"), "old_digest")
        if self.certificate_digest != canonical_digest((
                self.schema, self.authority_id, self.namespace,
                self.operation_id, self.seal_digest,
                self.old_journal_id, self.old_seq, self.old_digest,
                self.row_count, self.rows_digest,
                self.sanitized_head_digest,
                self.unresolved_mutation_ids, self.status)):
            raise ValueError("sidecar certificate commitment differs")


@dataclass(frozen=True, slots=True)
class ExecutionSidecarRecoveryStateV3:
    seal: ExecutionRedactionPreparedV3
    certificate: ExecutionSidecarCertificateV3 | None
    pin: ExecutionRedactionSidecarPinV3 | None
    stage: str
    switch: ExecutionRedactionSwitchV3 | None = None

    def __post_init__(self) -> None:
        if self.stage not in {
                "prepared_only_hold", "sidecar_unpinned_hold",
                "sidecar_pinned_hold", "identity_switched_hold"}:
            raise ValueError("unknown execution redaction recovery stage")
        if ((self.stage == "prepared_only_hold"
             and (self.certificate is not None or self.pin is not None))
                or (self.stage == "sidecar_unpinned_hold"
                    and (self.certificate is None or self.pin is not None))
                or (self.stage in {"sidecar_pinned_hold",
                                       "identity_switched_hold"}
                    and (self.certificate is None or self.pin is None))
                or (self.stage == "identity_switched_hold"
                    and self.switch is None)
                or (self.stage != "identity_switched_hold"
                    and self.switch is not None)):
            raise ValueError("sidecar recovery stage lacks its durable originals")


def redaction_facts_digest_v3(
        rows: tuple[SanitizedExecutionRowV3, ...],
        effects: tuple[tuple, ...]) -> str:
    """Bind effect consumption and terminal/unknown facts without old bodies."""
    return canonical_digest((
        "sylanne3.authority.execution_redaction_facts.v3",
        tuple((row.seq, row.entry_kind, row.operation_id,
               row.effect_id, row.binding_digest, row.claim_mutation_id,
               row.terminal_status, row.actual_cpu_ms, row.result_digest,
               row.unknown_constraint, row.old_body_digest)
              for row in rows), effects))


def sidecar_path_v3(old_path: Path, seal: ExecutionRedactionPreparedV3) -> Path:
    return Path(str(Path(old_path).resolve())
                + f".{seal.seal_digest[:24]}.sanitized-v3.sqlite")


def _row_from_old(journal: AuthorityV2ExecutionJournal, raw,
                  commitment, *, open_internal: set[str],
                  unobserved_effects: set[tuple[str, str | None]],
                  previous: str) -> SanitizedExecutionRowV3:
    encoded = raw[4]
    if commitment.entry_kind.startswith("internal_"):
        binding, claim, terminal = journal._decode_internal_row(raw)
        operation_id = binding.operation_id
        effect_id = None
        binding_digest = binding.binding_digest
        claim_id = claim.mutation_id
        status = None if terminal is None else terminal.status
        cost = None if terminal is None else terminal.actual_cpu_ms
        result_digest = None if terminal is None else terminal.result_digest
        constraint = (
            "internal_claim_open" if terminal is None
            and binding_digest in open_internal else
            "terminal_unknown" if terminal is not None
            and terminal.status == "unknown" else "none")
    else:
        pending = decode_bytes(encoded)
        if type(pending) is not PendingMutationV2:
            raise AuthorityUnavailable("old execution mutation body differs")
        operation_id = pending.permit.operation_id
        effect_id = pending.permit.effect_id
        binding_digest = claim_id = status = cost = result_digest = None
        key = (operation_id, effect_id)
        constraint = (
            "prepared_unresolved" if pending.phase == "prepared"
            and key in unobserved_effects else
            "claim_unobserved" if pending.phase == "claimed"
            and key in unobserved_effects else "none")
    shape = (raw[0], raw[1], raw[3], commitment.entry_kind,
             commitment.body_digest, commitment.chain_digest,
             operation_id, effect_id, binding_digest, claim_id,
             status, cost, result_digest, constraint, previous)
    return SanitizedExecutionRowV3(
        *shape, canonical_digest((_ROW_SCHEMA, *shape)))


def _sanitize(journal: AuthorityV2ExecutionJournal,
              seal: ExecutionRedactionPreparedV3, old_rows: tuple[tuple, ...]
              ) -> tuple[SanitizedExecutionRowV3, ...]:
    if len(old_rows) != len(seal.rows):
        raise AuthorityUnavailable("sealed old execution row count differs")
    open_internal: set[str] = set()
    pending_effects: set[tuple[str, str | None]] = set()
    observed_effects: set[tuple[str, str | None]] = set()
    for raw, commitment in zip(old_rows, seal.rows, strict=True):
        if commitment.entry_kind.startswith("internal_"):
            binding, _, terminal = journal._decode_internal_row(raw)
            if terminal is None:
                open_internal.add(binding.binding_digest)
            else:
                open_internal.discard(binding.binding_digest)
        else:
            pending = decode_bytes(raw[4])
            key = (pending.permit.operation_id, pending.permit.effect_id)
            pending_effects.add(key)
            if pending.phase == "observed":
                observed_effects.add(key)
    unobserved = pending_effects - observed_effects
    previous = "genesis"
    sanitized = []
    for raw, commitment in zip(old_rows, seal.rows, strict=True):
        row = _row_from_old(
            journal, raw, commitment, open_internal=open_internal,
            unobserved_effects=unobserved, previous=previous)
        sanitized.append(row)
        previous = row.sanitized_digest
    return tuple(sanitized)


def _certificate(seal: ExecutionRedactionPreparedV3,
                 rows: tuple[SanitizedExecutionRowV3, ...]
                 ) -> ExecutionSidecarCertificateV3:
    unresolved = tuple(sorted(
        row.mutation_id for row in rows
        if row.unknown_constraint != "none"))
    shape = (seal.authority_id, seal.namespace, seal.operation_id,
             seal.seal_digest, seal.execution_journal_id,
             seal.execution_seq, seal.execution_digest, len(rows),
             canonical_digest(rows), rows[-1].sanitized_digest, unresolved)
    return ExecutionSidecarCertificateV3(
        *shape, canonical_digest((_CERT_SCHEMA, *shape, "sidecar_only_hold")))


def _install_sidecar_schema(db: sqlite3.Connection) -> None:
    for table, ddl in ((_TABLE_ROWS, _ROW_DDL), (_TABLE_CERT, _CERT_DDL)):
        db.execute(ddl)
        for action in ("UPDATE", "DELETE"):
            db.execute(
                f"CREATE TRIGGER {table}_{action.lower()}_immutable "
                f"BEFORE {action} ON {table} "
                "BEGIN SELECT RAISE(ABORT,'execution sidecar immutable'); END")


def _require_sidecar_schema(db: sqlite3.Connection) -> None:
    expected = {
        ("table", _TABLE_ROWS): _ROW_DDL,
        ("table", _TABLE_CERT): _CERT_DDL,
    }
    for table in (_TABLE_ROWS, _TABLE_CERT):
        for action in ("UPDATE", "DELETE"):
            expected[("trigger", f"{table}_{action.lower()}_immutable")] = (
                f"CREATE TRIGGER {table}_{action.lower()}_immutable "
                f"BEFORE {action} ON {table} "
                "BEGIN SELECT RAISE(ABORT,'execution sidecar immutable'); END")
    found = {(kind, name): ddl for kind, name, ddl in db.execute(
        "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
    if found != expected:
        raise AuthorityUnavailable("execution sidecar schema differs")


def _read_sidecar(path: Path, seal: ExecutionRedactionPreparedV3
                  ) -> tuple[tuple[SanitizedExecutionRowV3, ...],
                             ExecutionSidecarCertificateV3]:
    if not path.is_file():
        raise AuthorityUnavailable("sanitized execution sidecar is absent")
    uri = "file:" + quote(path.as_posix(), safe="/:") + "?mode=ro"
    try:
        db = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            db.execute("PRAGMA query_only=ON")
            _require_sidecar_schema(db)
            raw = tuple(db.execute(
                f"SELECT seq,row_json FROM {_TABLE_ROWS} ORDER BY seq"))
            rows = []
            for expected, (seq, encoded) in enumerate(raw, 1):
                row = SanitizedExecutionRowV3(**json.loads(encoded))
                if (seq != expected or row.seq != expected
                        or canonical_serialize(asdict(row)) != encoded
                        or row.old_body_digest != seal.rows[expected - 1].body_digest
                        or row.old_chain_digest != seal.rows[expected - 1].chain_digest
                        or row.entry_kind != seal.rows[expected - 1].entry_kind
                        or row.mutation_id != seal.rows[expected - 1].mutation_id
                        or row.append_id != seal.rows[expected - 1].append_id
                        or row.previous_sanitized_digest != (
                            "genesis" if expected == 1 else rows[-1].sanitized_digest)):
                    raise AuthorityUnavailable("sanitized row differs from Core seal")
                rows.append(row)
            cert_row = db.execute(
                f"SELECT certificate_json FROM {_TABLE_CERT} WHERE id=1").fetchone()
            if cert_row is None or len(rows) != seal.execution_seq:
                raise AuthorityUnavailable("complete sidecar certificate absent")
            value = json.loads(cert_row[0])
            value["unresolved_mutation_ids"] = tuple(
                value["unresolved_mutation_ids"])
            cert = ExecutionSidecarCertificateV3(**value)
            if (canonical_serialize(asdict(cert)) != cert_row[0]
                    or cert != _certificate(seal, tuple(rows))
                    or db.execute(
                        f"SELECT count(*) FROM {_TABLE_CERT}").fetchone() != (1,)):
                raise AuthorityUnavailable("sidecar certificate differs")
            return tuple(rows), cert
        finally:
            db.close()
    except (sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        raise AuthorityUnavailable("sanitized execution sidecar is malformed") from exc


def _write_or_verify_sidecar(
        path: Path, seal: ExecutionRedactionPreparedV3,
        rows: tuple[SanitizedExecutionRowV3, ...],
        cert: ExecutionSidecarCertificateV3) -> None:
    if path.exists():
        stored_rows, stored_cert = _read_sidecar(path, seal)
        if stored_rows != rows or stored_cert != cert:
            raise AuthorityUnavailable("existing sanitized sidecar differs")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        db = sqlite3.connect(path, isolation_level=None, timeout=5)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            if db.execute("PRAGMA synchronous").fetchone()[0] < 2:
                raise AuthorityUnavailable("sidecar lacks FULL durability")
            db.execute("BEGIN IMMEDIATE")
            try:
                _install_sidecar_schema(db)
                db.executemany(
                    f"INSERT INTO {_TABLE_ROWS} VALUES(?,?)",
                    ((row.seq, canonical_serialize(asdict(row)))
                     for row in rows))
                db.execute(
                    f"INSERT INTO {_TABLE_CERT} VALUES(1,?)",
                    (canonical_serialize(asdict(cert)),))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        finally:
            db.close()
    except sqlite3.Error as exc:
        raise AuthorityUnavailable("sanitized sidecar write failed") from exc
    if _read_sidecar(path, seal) != (rows, cert):
        raise AuthorityUnavailable("sanitized sidecar cold reread differs")


def read_execution_sidecar_recovery_v3(
        *, core, credential, namespace: str, operation_id: str,
        old_journal_path: Path) -> ExecutionSidecarRecoveryStateV3:
    """Cold recovery needs only Core and the installed old-journal path."""
    from .core import AuthorityServiceCore

    if type(core) is not AuthorityServiceCore:
        raise AuthorityUnavailable("installed Core required for sidecar recovery")
    identifier(namespace, "namespace")
    identifier(operation_id, "operation_id")
    core._require(credential, "execution_redaction_install", namespace)
    with core._tx() as db:
        seal = read_execution_redaction_seal_locked(db, namespace)
        pin = read_execution_redaction_pin_locked(db, namespace)
        switch = read_execution_redaction_switch_locked(db, namespace)
        if seal is None or seal.operation_id != operation_id:
            raise AuthorityUnavailable("matching PREPARED Core seal required")
        current = core._row(db, namespace)
        head = core._head(current, "execution")
        if switch is None:
            if head != JournalHead(seal.execution_journal_id,
                                   seal.execution_seq,
                                   seal.execution_digest):
                raise AuthorityUnavailable("Core execution head differs from PREPARED")
        elif (head != JournalHead(switch.new_journal_id,
                                 switch.new_seq, switch.new_digest)
              or switch.authority_id != core._id(db)
              or switch.seal_digest != seal.seal_digest
              or pin is None or switch.pin_digest != pin.pin_digest
              or switch.before_anchor_digest == switch.after_anchor_digest
              or switch.after_anchor_digest != canonical_digest(
                  asdict(core._anchor(db, namespace, current)))):
            raise AuthorityUnavailable("Core V3 switch identity differs")
        effects = tuple(db.execute(
            "SELECT effect_id,state,conflict_keys_json,execution_seq "
            "FROM authority_effects WHERE namespace=? ORDER BY effect_id",
            (namespace,)))
    path = sidecar_path_v3(old_journal_path, seal)
    if not path.exists():
        if pin is not None:
            raise AuthorityUnavailable("Core-pinned sanitized sidecar is absent")
        return ExecutionSidecarRecoveryStateV3(
            seal, None, None, "prepared_only_hold")
    _, cert = _read_sidecar(path, seal)
    if pin is None:
        return ExecutionSidecarRecoveryStateV3(
            seal, cert, None, "sidecar_unpinned_hold")
    if ((pin.authority_id, pin.namespace, pin.operation_id,
         pin.seal_digest, pin.sidecar_path, pin.certificate_digest,
         pin.sanitized_head_digest, pin.row_count) != (
            seal.authority_id, namespace, operation_id,
            seal.seal_digest, str(path.resolve()),
            cert.certificate_digest, cert.sanitized_head_digest,
            cert.row_count)):
        raise AuthorityUnavailable("Core sidecar pin differs")
    if switch is not None:
        rows, cert = _read_sidecar(path, seal)
        expected_signed = tuple(
            row.request_digest for row in seal.rows
            if row.entry_kind == "internal_terminal"
            and row.terminal_status != "unknown")
        if ((switch.certificate_digest, switch.old_journal_id,
             switch.old_seq, switch.old_digest, switch.new_seq,
             switch.new_digest, switch.signed_terminal_digests,
             switch.facts_digest) !=
            (cert.certificate_digest, seal.execution_journal_id,
             seal.execution_seq, seal.execution_digest, len(rows),
             "sha256:" + cert.sanitized_head_digest, expected_signed,
             redaction_facts_digest_v3(rows, effects))):
            raise AuthorityUnavailable("V3 switch facts differ from pinned sidecar")
        return ExecutionSidecarRecoveryStateV3(
            seal, cert, pin, "identity_switched_hold", switch)
    return ExecutionSidecarRecoveryStateV3(
        seal, cert, pin, "sidecar_pinned_hold")


class AuthorityExecutionRedactionSidecarV3:
    """Installer-only PREPARED→sidecar-pinned HOLD transition."""

    def __init__(self, closure: AuthorityErasureClosureInventory):
        if type(closure) is not AuthorityErasureClosureInventory:
            raise AuthorityUnavailable("paired C09 closure service required")
        self.closure = closure
        self.core = closure.core
        self.namespace = closure.namespace

    def build_and_pin(self, *, credential, subject: str,
                      operation_id: str) -> ExecutionSidecarRecoveryStateV3:
        identifier(subject, "subject")
        identifier(operation_id, "operation_id")
        self.core._require(
            credential, "execution_redaction_install", self.namespace)
        self.closure.qualify_current_registry_location_v1(
            credential=credential,subject=subject,operation_id=operation_id)
        with self.core._tx() as db:
            seal = read_execution_redaction_seal_locked(db, self.namespace)
            if seal is None or seal.operation_id != operation_id:
                raise AuthorityUnavailable("matching PREPARED Core seal required")
        old = AuthorityV2ExecutionJournal.open_prepared_redaction_v3(
            self.closure.execution.path, namespace=self.namespace,
            journal_id=seal.execution_journal_id, core=self.core,
            credential=credential)
        try:
            with self.closure.deletion.freeze_writes():
                with old.freeze_prepared_redaction_v3() as raw:
                    rows = _sanitize(old, seal, raw)
                    cert = _certificate(seal, rows)
                    path = sidecar_path_v3(old.path, seal)
                    _write_or_verify_sidecar(path, seal, rows, cert)
                    with self.core._tx() as db:
                        current = read_execution_redaction_seal_locked(
                            db, self.namespace)
                        if current != seal:
                            raise AuthorityUnavailable("Core PREPARED seal changed")
                        run = self.closure._read_record(
                            db, _TABLES[1], operation_id, CleanupRunV2)
                        if run is None:
                            raise AuthorityUnavailable("cleanup run original absent")
                        self.closure._registry_locked(db)
                        self.closure._accepted_locked(db, run, subject)
                        head = self.core._head(
                            self.core._row(db, self.namespace), "execution")
                        if head != JournalHead(
                                seal.execution_journal_id, seal.execution_seq,
                                seal.execution_digest):
                            raise AuthorityUnavailable(
                                "Core execution head changed before sidecar pin")
                        reread_rows, reread_cert = _read_sidecar(path, seal)
                        if reread_rows != rows or reread_cert != cert:
                            raise AuthorityUnavailable("sidecar independent reread differs")
                        shape = (seal.authority_id, self.namespace,
                                 operation_id, seal.seal_digest,
                                 str(path.resolve()), cert.certificate_digest,
                                 cert.sanitized_head_digest, len(rows))
                        pin = ExecutionRedactionSidecarPinV3(
                            *shape, canonical_digest((
                                "sylanne3.authority.execution_redaction_sidecar_pin.v3",
                                *shape, "sidecar_pinned_hold")))
                        prior = read_execution_redaction_pin_locked(
                            db, self.namespace)
                        if prior is not None:
                            if prior != pin:
                                raise AuthorityUnavailable("sidecar pin replay differs")
                        else:
                            db.execute(
                                "INSERT INTO authority_execution_redaction_sidecar_pins_v3 "
                                "(namespace,operation_id,pin_json) VALUES(?,?,?)",
                                (self.namespace, operation_id,
                                 canonical_serialize(asdict(pin))))
                        return ExecutionSidecarRecoveryStateV3(
                            seal, cert, pin, "sidecar_pinned_hold")
        finally:
            old.close()

    def read_recovery_state(self, *, credential,
                            operation_id: str) -> ExecutionSidecarRecoveryStateV3:
        return read_execution_sidecar_recovery_v3(
            core=self.core, credential=credential, namespace=self.namespace,
            operation_id=operation_id,
            old_journal_path=self.closure.execution.path)


__all__ = ["SanitizedExecutionRowV3", "ExecutionSidecarCertificateV3",
           "ExecutionSidecarRecoveryStateV3", "AuthorityExecutionRedactionSidecarV3",
           "sidecar_path_v3", "read_execution_sidecar_recovery_v3",
           "redaction_facts_digest_v3"]
