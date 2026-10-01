"""Immutable Core pin for complete V4 recovery facts before physical rebase.

This pin is a prerequisite for a future maintenance switch, never a cleanup
receipt. The complete facts remain with trusted original readers until that
switch independently rereads them.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import sqlite3

from .contract import AuthorityUnavailable, identifier


_TABLE = "authority_execution_recovery_facts_pins_v4"
_DDL = f"""CREATE TABLE {_TABLE}(
    namespace TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE,
    pin_json TEXT NOT NULL) STRICT"""
_SCHEMA = "sylanne3.authority.execution_recovery_facts_pin.v4"
_FACTS_TABLE = "authority_execution_recovery_facts_v4"
_FACTS_DDL = f"""CREATE TABLE {_FACTS_TABLE}(
    namespace TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE,
    facts_json TEXT NOT NULL) STRICT"""


def _digest(value: str, name: str) -> None:
    if (type(value) is not str or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)):
        raise ValueError(f"invalid {name}")


def _canonical_digest(value) -> str:
    from ..runtime_contracts import canonical_digest

    return canonical_digest(value)


def _canonical_serialize(value) -> str:
    from ..runtime_contracts import canonical_serialize

    return canonical_serialize(value)


@dataclass(frozen=True, slots=True)
class ExecutionRecoveryFactsPinV4:
    authority_id: str
    installation_id: str
    namespace: str
    operation_id: str
    seal_digest: str
    old_journal_id: str
    old_seq: int
    old_digest: str
    verifier_commitment: str
    facts_digest: str
    pin_digest: str
    stage: str = "prepared_facts_pinned_hold"
    schema: str = _SCHEMA

    def __post_init__(self) -> None:
        for name in ("authority_id", "installation_id", "namespace",
                     "operation_id", "old_journal_id"):
            identifier(getattr(self, name), name)
        for name in ("seal_digest", "verifier_commitment", "facts_digest",
                     "pin_digest"):
            _digest(getattr(self, name), name)
        if (type(self.old_seq) is not int or self.old_seq < 1
                or type(self.old_digest) is not str
                or not self.old_digest.startswith("sha256:")
                or self.stage != "prepared_facts_pinned_hold"
                or self.schema != _SCHEMA):
            raise ValueError("V4 recovery facts pin shape differs")
        _digest(self.old_digest.removeprefix("sha256:"), "old_digest")
        if self.pin_digest != _canonical_digest((
                self.schema, self.authority_id, self.installation_id,
                self.namespace, self.operation_id, self.seal_digest,
                self.old_journal_id, self.old_seq, self.old_digest,
                self.verifier_commitment, self.facts_digest, self.stage)):
            raise ValueError("V4 recovery facts pin commitment differs")


def make_execution_recovery_facts_pin_v4(*, seal, facts) -> ExecutionRecoveryFactsPinV4:
    shape = (facts.authority_id, facts.installation_id, facts.namespace,
             facts.operation_id, seal.seal_digest, seal.execution_journal_id,
             seal.execution_seq, seal.execution_digest,
             facts.verifier_commitment, facts.facts_digest)
    return ExecutionRecoveryFactsPinV4(
        *shape, _canonical_digest((_SCHEMA, *shape,
                                   "prepared_facts_pinned_hold")))


def install_execution_recovery_pin_schema_v4(db: sqlite3.Connection) -> None:
    db.execute(_DDL.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
    db.execute(_FACTS_DDL.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
    for table in (_TABLE, _FACTS_TABLE):
        marker = ("V4 recovery facts pin immutable" if table == _TABLE
                  else "V4 recovery facts immutable")
        for action in ("UPDATE", "DELETE"):
            db.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_{action.lower()}_immutable "
                f"BEFORE {action} ON {table} "
                f"BEGIN SELECT RAISE(ABORT,'{marker}'); END")
    require_execution_recovery_pin_schema_v4(db)


def require_execution_recovery_pin_schema_v4(db: sqlite3.Connection) -> None:
    for table, expected, columns, marker in (
            (_TABLE, _DDL, ("namespace", "operation_id", "pin_json"),
             "V4 recovery facts pin immutable"),
            (_FACTS_TABLE, _FACTS_DDL,
             ("namespace", "operation_id", "facts_json"),
             "V4 recovery facts immutable")):
        ddl = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (table,)).fetchone()
        triggers = {row[0]: row[1] for row in db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?",
            (table,))}
        if (ddl != (expected,) or tuple(row[1] for row in db.execute(
                f"PRAGMA table_info({table})")) != columns
                or any(f"RAISE(ABORT,'{marker}')" not in
                       triggers.get(f"{table}_{action}_immutable", "")
                       for action in ("update", "delete"))):
            raise AuthorityUnavailable("V4 recovery facts Core schema differs")


def read_execution_recovery_facts_v4_locked(db: sqlite3.Connection,
                                             namespace: str, operation_id: str | None = None):
    """Cold-read exact content-free facts committed with the Core pin."""
    from ..runtime.c09_storage_rebase_contract_v1 import (
        SanitizedD02FactV4, SanitizedD11FactV4, SanitizedExecutionFactV4,
        SanitizedGraphFactV4, SanitizedRecoveryFactsV4, SanitizedUnknownFactV4,
    )
    from ..runtime_journal import (
        BudgetConstraint, QuotaOccupancy, RecoveryConstraintFootprint,
        ReservationConstraint,
    )

    require_execution_recovery_pin_schema_v4(db)
    row = db.execute(
        f"SELECT operation_id,facts_json FROM {_FACTS_TABLE} WHERE namespace=?",
        (namespace,)).fetchone()
    if operation_id is not None and (row is None or row[0] != operation_id):
        from .c09_originals_archive_v1 import read_archived_original_v1
        archived = read_archived_original_v1(db,namespace=namespace,operation_id=operation_id,original_kind="facts")
        frame = db.execute("SELECT operation_id,facts_json FROM authority_c09_recovery_fact_frames_v4 WHERE namespace=? AND operation_id=?", (namespace,operation_id)).fetchone()
        row = frame if frame is not None else (None if archived is None else (operation_id,archived["original_json"]))
    if row is None:
        return None
    try:
        raw = json.loads(row[1])
        raw["executions"] = tuple(SanitizedExecutionFactV4(**item)
                                  for item in raw["executions"])
        raw["d02_facts"] = tuple(SanitizedD02FactV4(**item)
                                 for item in raw["d02_facts"])
        raw["d11_facts"] = tuple(SanitizedD11FactV4(**item)
                                 for item in raw["d11_facts"])
        unknown = []
        for item in raw["unknown_facts"]:
            footprint = item["footprint"]
            footprint["conflict_keys"] = tuple(footprint["conflict_keys"])
            footprint["object_gate_keys"] = tuple(footprint["object_gate_keys"])
            footprint["quota_occupancies"] = tuple(
                QuotaOccupancy(**value)
                for value in footprint["quota_occupancies"])
            footprint["reservations"] = tuple(
                ReservationConstraint(**value)
                for value in footprint["reservations"])
            footprint["budgets"] = tuple(
                BudgetConstraint(**value) for value in footprint["budgets"])
            item["footprint"] = RecoveryConstraintFootprint(**footprint)
            item["cost_pending"] = tuple(tuple(value)
                                         for value in item["cost_pending"])
            unknown.append(SanitizedUnknownFactV4(**item))
        raw["unknown_facts"] = tuple(unknown)
        raw["graph_facts"] = tuple(SanitizedGraphFactV4(**item)
                                   for item in raw["graph_facts"])
        if raw.get("schema") == "sylanne3.c09.recovery_fact_frame.v4":
            from .c09_recovery_frame_v4 import C09RecoveryFactFrameV4
            raw["prior_fact_frame_digests"] = tuple(raw["prior_fact_frame_digests"])
            facts = C09RecoveryFactFrameV4(**raw)
        else:
            facts = SanitizedRecoveryFactsV4(**raw)
    except (TypeError, ValueError, KeyError) as exc:
        raise AuthorityUnavailable("V4 recovery facts malformed") from exc
    pin = read_execution_recovery_facts_pin_v4_locked(db, namespace, operation_id=row[0])
    if (pin is None or facts.namespace != namespace
            or facts.operation_id != row[0]
            or facts.facts_digest != pin.facts_digest
            or _canonical_serialize(asdict(facts)) != row[1]):
        raise AuthorityUnavailable("V4 recovery facts differ from immutable pin")
    return facts


def read_execution_recovery_facts_pin_v4_locked(
        db: sqlite3.Connection, namespace: str, operation_id: str | None = None,
) -> ExecutionRecoveryFactsPinV4 | None:
    require_execution_recovery_pin_schema_v4(db)
    row = db.execute(
        f"SELECT operation_id,pin_json FROM {_TABLE} WHERE namespace=?",
        (namespace,)).fetchone()
    if operation_id is not None and (row is None or row[0] != operation_id):
        from .c09_originals_archive_v1 import read_archived_original_v1
        archived = read_archived_original_v1(db,namespace=namespace,operation_id=operation_id,original_kind="facts_pin")
        frame = db.execute("SELECT operation_id,pin_json FROM authority_c09_execution_source_pins_v4 WHERE namespace=? AND operation_id=?", (namespace,operation_id)).fetchone()
        row = frame if frame is not None else (None if archived is None else (operation_id,archived["original_json"]))
    if row is None:
        return None
    try:
        raw = json.loads(row[1])
        if raw.get("schema") == "sylanne3.c09.execution_source_pin.v4":
            from .c09_recovery_frame_v4 import C09ExecutionSourcePinV4
            pin = C09ExecutionSourcePinV4(**raw)
        else:
            pin = ExecutionRecoveryFactsPinV4(**raw)
    except (TypeError, ValueError, KeyError) as exc:
        raise AuthorityUnavailable("V4 recovery facts pin malformed") from exc
    if (pin.namespace != namespace or pin.operation_id != row[0]
            or _canonical_serialize(asdict(pin)) != row[1]):
        raise AuthorityUnavailable("V4 recovery facts pin original differs")
    return pin


def read_consumed_execution_fact_v4_locked(
        db: sqlite3.Connection, namespace: str, execution_id: str):
    """Read a pinned execution right without recovering erased payload bytes."""
    identifier(execution_id, "execution_id")
    facts = read_execution_recovery_facts_v4_locked(db, namespace)
    if facts is None:
        return None
    found = tuple(item for item in facts.executions
                  if item.execution_id == execution_id)
    if len(found) > 1:
        raise AuthorityUnavailable("duplicate V4 execution right")
    if not found:
        return None
    execution = found[0]
    unknown = tuple(item for item in facts.unknown_facts
                    if item.execution_id == execution_id)
    if ((execution.status == "unknown") != (len(unknown) == 1)
            or len(unknown) > 1):
        raise AuthorityUnavailable("V4 unknown obligation differs")
    return execution, (unknown[0] if unknown else None)


__all__ = ["ExecutionRecoveryFactsPinV4", "make_execution_recovery_facts_pin_v4",
           "install_execution_recovery_pin_schema_v4",
           "read_execution_recovery_facts_pin_v4_locked",
           "read_execution_recovery_facts_v4_locked",
           "read_consumed_execution_fact_v4_locked"]
