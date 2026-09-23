"""Durable, append-only evidence written before external execution.

This journal is deliberately independent from the business graph database.  It
records only stable recovery identities and constraints; it is not an outbox,
does not contain a replayable command, and grants no dispatch authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import threading
import uuid


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@#=+-]{0,255}\Z")
_PHASES = frozenset({
    "claimed",
    "handed_off",
    "acknowledged",
    "delivered",
    "failed",
    "unknown",
})
_RESOLVED_PHASES = frozenset({"confirmed_not_dispatched", "constraints_released"})


class EffectConflict(ValueError):
    """The effect identity was already bound to different immutable data."""


class WatermarkUnavailable(RuntimeError):
    """The journal cannot prove it is complete through the required sequence."""


class SettlementAuthorityRequired(RuntimeError):
    """An independent domain authority did not verify constraint release."""


def _identifier(value, label, *, optional=False):
    if optional and value is None:
        return
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} must be a stable, content-free identifier")


def _identifier_tuple(value, label):
    if not isinstance(value, tuple):
        raise TypeError(f"{label} must be a tuple")
    for item in value:
        _identifier(item, label)
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must not contain duplicates")


def _amount(value, label, *, optional=False):
    if optional and value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a decimal string or None")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"{label} must be a finite nonnegative decimal") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ValueError(f"{label} must be a finite nonnegative decimal")
    return format(parsed, "f")


@dataclass(frozen=True)
class QuotaOccupancy:
    bucket_key: str
    window_key: str
    occupied: int

    def __post_init__(self):
        _identifier(self.bucket_key, "bucket_key")
        _identifier(self.window_key, "window_key")
        if type(self.occupied) is not int or self.occupied < 1:
            raise ValueError("occupied must be a positive integer")


@dataclass(frozen=True)
class ReservationConstraint:
    reservation_ref: str
    component_ref: str
    upper_bound: str | None

    def __post_init__(self):
        _identifier(self.reservation_ref, "reservation_ref")
        _identifier(self.component_ref, "component_ref")
        object.__setattr__(
            self, "upper_bound", _amount(self.upper_bound, "upper_bound", optional=True))


@dataclass(frozen=True)
class BudgetConstraint:
    parent_budget_ref: str
    used_amount: str
    pending_amount: str | None
    upper_bound: str | None

    def __post_init__(self):
        _identifier(self.parent_budget_ref, "parent_budget_ref")
        object.__setattr__(self, "used_amount", _amount(self.used_amount, "used_amount"))
        object.__setattr__(
            self, "pending_amount", _amount(
                self.pending_amount, "pending_amount", optional=True))
        object.__setattr__(
            self, "upper_bound", _amount(self.upper_bound, "upper_bound", optional=True))


@dataclass(frozen=True)
class RecoveryConstraintFootprint:
    namespace: str
    activity_id: str
    effect_id: str
    external_idempotency_ref: str | None = None
    external_query_ref: str | None = None
    conflict_keys: tuple[str, ...] = ()
    communication_action: str | None = None
    contact_id: str | None = None
    segment_id: str | None = None
    object_gate_keys: tuple[str, ...] = ()
    quota_occupancies: tuple[QuotaOccupancy, ...] = ()
    reservations: tuple[ReservationConstraint, ...] = ()
    budgets: tuple[BudgetConstraint, ...] = ()

    def __post_init__(self):
        for label in ("namespace", "activity_id", "effect_id"):
            _identifier(getattr(self, label), label)
        for label in ("external_idempotency_ref", "external_query_ref",
                      "communication_action", "contact_id", "segment_id"):
            _identifier(getattr(self, label), label, optional=True)
        _identifier_tuple(self.conflict_keys, "conflict_keys")
        _identifier_tuple(self.object_gate_keys, "object_gate_keys")
        for label, values, item_type in (
            ("quota_occupancies", self.quota_occupancies, QuotaOccupancy),
            ("reservations", self.reservations, ReservationConstraint),
            ("budgets", self.budgets, BudgetConstraint),
        ):
            if not isinstance(values, tuple) or not all(
                    isinstance(item, item_type) for item in values):
                raise TypeError(f"{label} must be a tuple of {item_type.__name__}")
        if (self.communication_action is None) != (self.contact_id is None):
            raise ValueError("communication_action and contact_id must be present together")
        if self.segment_id is not None and self.contact_id is None:
            raise ValueError("segment_id requires a contact identity")
        if ((self.object_gate_keys or self.quota_occupancies)
                and self.contact_id is None):
            raise ValueError("contact quota and object gates require a contact identity")

    def _json(self):
        value = {
            "namespace": self.namespace,
            "activity_id": self.activity_id,
            "effect_id": self.effect_id,
            "external_idempotency_ref": self.external_idempotency_ref,
            "external_query_ref": self.external_query_ref,
            "conflict_keys": list(self.conflict_keys),
            "communication_action": self.communication_action,
            "contact_id": self.contact_id,
            "segment_id": self.segment_id,
            "object_gate_keys": list(self.object_gate_keys),
            "quota_occupancies": [
                [item.bucket_key, item.window_key, item.occupied]
                for item in self.quota_occupancies
            ],
            "reservations": [
                [item.reservation_ref, item.component_ref, item.upper_bound]
                for item in self.reservations
            ],
            "budgets": [
                [item.parent_budget_ref, item.used_amount, item.pending_amount,
                 item.upper_bound]
                for item in self.budgets
            ],
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    @classmethod
    def _from_json(cls, raw):
        value = json.loads(raw)
        return cls(
            namespace=value["namespace"],
            activity_id=value["activity_id"],
            effect_id=value["effect_id"],
            external_idempotency_ref=value["external_idempotency_ref"],
            external_query_ref=value["external_query_ref"],
            conflict_keys=tuple(value["conflict_keys"]),
            communication_action=value["communication_action"],
            contact_id=value["contact_id"],
            segment_id=value["segment_id"],
            object_gate_keys=tuple(value["object_gate_keys"]),
            quota_occupancies=tuple(QuotaOccupancy(*item)
                                    for item in value["quota_occupancies"]),
            reservations=tuple(ReservationConstraint(*item)
                               for item in value["reservations"]),
            budgets=tuple(BudgetConstraint(*item) for item in value["budgets"]),
        )


@dataclass(frozen=True)
class JournalEntry:
    execution_seq: int
    effect_id: str
    command_digest: str
    dispatch_generation: int
    activation_generation: int
    admission_ref: str
    phase: str
    observation_ref: str | None


@dataclass(frozen=True)
class PendingConstraint:
    effect_id: str
    command_digest: str
    latest_execution_seq: int
    latest_phase: str
    footprint: RecoveryConstraintFootprint


@dataclass(frozen=True)
class JournalWatermark:
    """A local anchor candidate; insufficient by itself to prove no rollback."""

    journal_id: str
    execution_seq: int
    chain_digest: str


@dataclass(frozen=True)
class TrustedRestoreAnchor:
    """A journal head attested by an independent current restore authority."""

    journal_id: str
    execution_seq: int
    chain_digest: str
    authority_ref: str

    def __post_init__(self):
        _identifier(self.journal_id, "journal_id")
        if type(self.execution_seq) is not int or self.execution_seq < 1:
            raise ValueError("execution_seq must be a positive integer")
        _identifier(self.chain_digest, "chain_digest")
        _identifier(self.authority_ref, "authority_ref")


@dataclass(frozen=True)
class SettlementAuthority:
    namespace: str
    effect_id: str
    decision: str
    settlement_ref: str

    def __post_init__(self):
        _identifier(self.namespace, "namespace")
        _identifier(self.effect_id, "effect_id")
        if self.decision not in _RESOLVED_PHASES:
            raise ValueError("settlement decision must prove no dispatch or release")
        _identifier(self.settlement_ref, "settlement_ref")


class ExecutionJournal:
    """SQLite execution evidence store with no business-database dependency."""

    def __init__(self, path, *, restore_anchor_verifier=None,
                 settlement_verifier=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._restore_anchor_verifier = restore_anchor_verifier
        self._settlement_verifier = settlement_verifier
        self._db = sqlite3.connect(
            self.path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._create_schema()

    def _create_schema(self):
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS execution_metadata (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS execution_effects (
                effect_id TEXT PRIMARY KEY,
                command_digest TEXT NOT NULL,
                dispatch_generation INTEGER NOT NULL,
                activation_generation INTEGER NOT NULL,
                admission_ref TEXT NOT NULL,
                footprint_json TEXT NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS execution_entries (
                execution_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                effect_id TEXT NOT NULL REFERENCES execution_effects(effect_id),
                phase TEXT NOT NULL,
                observation_ref TEXT,
                chain_digest TEXT NOT NULL
            ) STRICT;
            CREATE TRIGGER IF NOT EXISTS execution_metadata_no_update
                BEFORE UPDATE ON execution_metadata BEGIN
                SELECT RAISE(ABORT, 'execution metadata is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS execution_metadata_no_delete
                BEFORE DELETE ON execution_metadata BEGIN
                SELECT RAISE(ABORT, 'execution metadata is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS execution_effects_no_update
                BEFORE UPDATE ON execution_effects BEGIN
                SELECT RAISE(ABORT, 'execution effects are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS execution_effects_no_delete
                BEFORE DELETE ON execution_effects BEGIN
                SELECT RAISE(ABORT, 'execution effects are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS execution_entries_no_update
                BEFORE UPDATE ON execution_entries BEGIN
                SELECT RAISE(ABORT, 'execution entries are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS execution_entries_no_delete
                BEFORE DELETE ON execution_entries BEGIN
                SELECT RAISE(ABORT, 'execution entries are append-only'); END;
        """)
        self._db.execute(
            "INSERT OR IGNORE INTO execution_metadata(name,value) VALUES('journal_id',?)",
            (str(uuid.uuid4()),),
        )

    def _ensure_open(self):
        if self._db is None:
            raise RuntimeError("execution journal is closed")

    @staticmethod
    def _generation(value, label):
        if type(value) is not int or value < 0:
            raise ValueError(f"{label} must be a nonnegative integer")

    @staticmethod
    def _entry(row):
        return JournalEntry(*row)

    def _append_entry_locked(self, effect_id, phase, observation_ref, effect):
        prior = self._db.execute(
            "SELECT chain_digest FROM execution_entries "
            "ORDER BY execution_seq DESC LIMIT 1").fetchone()
        material = json.dumps({
            "previous": prior[0] if prior else None,
            "effect_id": effect_id,
            "command_digest": effect[0],
            "dispatch_generation": effect[1],
            "activation_generation": effect[2],
            "admission_ref": effect[3],
            "phase": phase,
            "observation_ref": observation_ref,
        }, sort_keys=True, separators=(",", ":"))
        chain_digest = "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()
        cursor = self._db.execute(
            "INSERT INTO execution_entries(effect_id,phase,observation_ref,chain_digest) "
            "VALUES(?,?,?,?)", (effect_id, phase, observation_ref, chain_digest),
        )
        return cursor.lastrowid

    def prepare(self, *, effect_id, command_digest, dispatch_generation,
                activation_generation, admission_ref, footprint):
        for value, label in ((effect_id, "effect_id"),
                             (command_digest, "command_digest"),
                             (admission_ref, "admission_ref")):
            _identifier(value, label)
        self._generation(dispatch_generation, "dispatch_generation")
        self._generation(activation_generation, "activation_generation")
        if not isinstance(footprint, RecoveryConstraintFootprint):
            raise TypeError("footprint must be RecoveryConstraintFootprint")
        if footprint.effect_id != effect_id:
            raise ValueError("footprint effect_id does not match effect_id")
        encoded = footprint._json()
        binding = (command_digest, dispatch_generation, activation_generation,
                   admission_ref, encoded)
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                existing = self._db.execute(
                    "SELECT command_digest,dispatch_generation,activation_generation,"
                    "admission_ref,footprint_json FROM execution_effects WHERE effect_id=?",
                    (effect_id,),
                ).fetchone()
                if existing is not None:
                    if tuple(existing) != binding:
                        raise EffectConflict("effect_id is bound to different execution data")
                    row = self._db.execute(
                        "SELECT e.execution_seq,x.effect_id,x.command_digest,"
                        "x.dispatch_generation,x.activation_generation,x.admission_ref,"
                        "e.phase,e.observation_ref FROM execution_entries e "
                        "JOIN execution_effects x USING(effect_id) "
                        "WHERE e.effect_id=? AND e.phase='prepared' "
                        "ORDER BY e.execution_seq LIMIT 1", (effect_id,),
                    ).fetchone()
                    self._db.execute("COMMIT")
                    return self._entry(row)
                self._db.execute(
                    "INSERT INTO execution_effects VALUES(?,?,?,?,?,?)",
                    (effect_id,) + binding,
                )
                sequence = self._append_entry_locked(
                    effect_id, "prepared", None,
                    (command_digest, dispatch_generation, activation_generation,
                     admission_ref))
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return JournalEntry(sequence, effect_id, command_digest,
                            dispatch_generation, activation_generation,
                            admission_ref, "prepared", None)

    def observe(self, effect_id, command_digest, phase, observation_ref):
        _identifier(effect_id, "effect_id")
        _identifier(command_digest, "command_digest")
        if phase not in _PHASES:
            raise ValueError("unsupported execution phase")
        _identifier(observation_ref, "observation_ref")
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                effect = self._db.execute(
                    "SELECT command_digest,dispatch_generation,activation_generation,"
                    "admission_ref FROM execution_effects WHERE effect_id=?",
                    (effect_id,),
                ).fetchone()
                if effect is None:
                    raise KeyError(effect_id)
                if effect[0] != command_digest:
                    raise EffectConflict("effect_id is bound to a different command digest")
                prior = self._db.execute(
                    "SELECT phase FROM execution_entries WHERE effect_id=? "
                    "ORDER BY execution_seq DESC LIMIT 1", (effect_id,),
                ).fetchone()[0]
                if prior in _RESOLVED_PHASES:
                    raise EffectConflict("resolved constraints cannot receive new observations")
                sequence = self._append_entry_locked(
                    effect_id, phase, observation_ref, effect)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return JournalEntry(sequence, effect_id, effect[0], effect[1], effect[2],
                            effect[3], phase, observation_ref)

    def release_constraints(self, effect_id, command_digest, settlement):
        if not isinstance(settlement, SettlementAuthority):
            raise TypeError("settlement must be SettlementAuthority")
        verifier = self._settlement_verifier
        if verifier is None or not verifier(settlement):
            raise SettlementAuthorityRequired(
                "constraint release requires an independently verified settlement")
        _identifier(effect_id, "effect_id")
        _identifier(command_digest, "command_digest")
        if settlement.effect_id != effect_id:
            raise EffectConflict("settlement effect does not match")
        with self._lock:
            self._ensure_open()
            row = self._db.execute(
                "SELECT footprint_json FROM execution_effects WHERE effect_id=?",
                (effect_id,),
            ).fetchone()
            if row is None:
                raise KeyError(effect_id)
            footprint = RecoveryConstraintFootprint._from_json(row[0])
            if footprint.namespace != settlement.namespace:
                raise EffectConflict("settlement namespace does not match")
        return self._observe_resolved(
            effect_id, command_digest, settlement.decision,
            settlement.settlement_ref)

    def _observe_resolved(self, effect_id, command_digest, phase, observation_ref):
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                effect = self._db.execute(
                    "SELECT command_digest,dispatch_generation,activation_generation,"
                    "admission_ref FROM execution_effects WHERE effect_id=?",
                    (effect_id,),
                ).fetchone()
                if effect is None:
                    raise KeyError(effect_id)
                if effect[0] != command_digest:
                    raise EffectConflict("effect_id is bound to a different command digest")
                prior = self._db.execute(
                    "SELECT phase FROM execution_entries WHERE effect_id=? "
                    "ORDER BY execution_seq DESC LIMIT 1", (effect_id,),
                ).fetchone()[0]
                if prior in _RESOLVED_PHASES:
                    raise EffectConflict("constraints are already resolved")
                sequence = self._append_entry_locked(
                    effect_id, phase, observation_ref, effect)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return JournalEntry(sequence, effect_id, effect[0], effect[1], effect[2],
                            effect[3], phase, observation_ref)

    def latest_execution_seq(self):
        with self._lock:
            self._ensure_open()
            row = self._db.execute(
                "SELECT COALESCE(MAX(execution_seq),0) FROM execution_entries").fetchone()
            return row[0]

    def latest_watermark(self):
        """Return a local candidate that an independent authority must attest."""
        with self._lock:
            self._ensure_open()
            journal_id = self._db.execute(
                "SELECT value FROM execution_metadata WHERE name='journal_id'"
            ).fetchone()[0]
            row = self._db.execute(
                "SELECT execution_seq,chain_digest FROM execution_entries "
                "ORDER BY execution_seq DESC LIMIT 1").fetchone()
            return JournalWatermark(journal_id, *row) if row else None

    def unresolved_constraints(self, *, minimum_execution_seq, restore_anchor):
        if type(minimum_execution_seq) is not int or minimum_execution_seq < 0:
            raise ValueError("minimum_execution_seq must be a nonnegative integer")
        verifier = self._restore_anchor_verifier
        if (not isinstance(restore_anchor, TrustedRestoreAnchor)
                or verifier is None or not verifier(restore_anchor)):
            raise WatermarkUnavailable(
                "an independently trusted current restore anchor is required")
        with self._lock:
            self._ensure_open()
            journal_id = self._db.execute(
                "SELECT value FROM execution_metadata WHERE name='journal_id'"
            ).fetchone()[0]
            latest = self._db.execute(
                "SELECT execution_seq,chain_digest FROM execution_entries "
                "ORDER BY execution_seq DESC LIMIT 1").fetchone()
            if (latest is None or restore_anchor.journal_id != journal_id
                    or restore_anchor.execution_seq < minimum_execution_seq
                    or (restore_anchor.execution_seq, restore_anchor.chain_digest)
                    != tuple(latest)):
                raise WatermarkUnavailable(
                    "trusted restore anchor does not match the current journal head")
            rows = self._db.execute("""
                SELECT x.effect_id,x.command_digest,e.execution_seq,e.phase,
                       x.footprint_json
                FROM execution_effects x
                JOIN execution_entries e ON e.execution_seq=(
                    SELECT MAX(last.execution_seq) FROM execution_entries last
                    WHERE last.effect_id=x.effect_id)
                WHERE e.phase NOT IN ('confirmed_not_dispatched','constraints_released')
                ORDER BY e.execution_seq,x.effect_id
            """).fetchall()
        return tuple(PendingConstraint(
            row[0], row[1], row[2], row[3],
            RecoveryConstraintFootprint._from_json(row[4])) for row in rows)

    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None


__all__ = (
    "BudgetConstraint",
    "EffectConflict",
    "ExecutionJournal",
    "JournalEntry",
    "PendingConstraint",
    "QuotaOccupancy",
    "RecoveryConstraintFootprint",
    "JournalWatermark",
    "ReservationConstraint",
    "SettlementAuthority",
    "SettlementAuthorityRequired",
    "TrustedRestoreAnchor",
    "WatermarkUnavailable",
)
