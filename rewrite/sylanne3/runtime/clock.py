"""Versioned character-time mappings and restart-safe deadline rebuilding."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import json
import math
import re


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_ABS_CHARACTER_TIME = Decimal("1e18")
MAX_RATE = Decimal("1000000")


class ClockConflict(RuntimeError):
    pass


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def _digest(value: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError("digest must be 64 lowercase hex characters")
    return value


def _utc(value: str, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 35:
        raise ValueError(f"invalid {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid {field}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include an offset")
    return parsed.astimezone(timezone.utc)


def _decimal(value, field: str, *, positive: bool = False,
             limit: Decimal = MAX_ABS_CHARACTER_TIME) -> Decimal:
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"invalid {field}") from exc
    if not result.is_finite() or abs(result) > limit or (positive and result <= 0):
        raise ValueError(f"{field} is outside the supported finite range")
    return result


@dataclass(frozen=True)
class CharacterClockMapping:
    mapping_id: str
    version: int
    wall_origin_utc: str
    character_origin: Decimal
    rate: Decimal
    valid_from_utc: str
    valid_until_utc: str
    policy_ref: str
    issuer_domain: str

    def __post_init__(self) -> None:
        _identifier(self.mapping_id, "mapping_id")
        _identifier(self.policy_ref, "policy_ref")
        _identifier(self.issuer_domain, "issuer_domain")
        if self.issuer_domain != "d11":
            raise ValueError("only D11 may issue a character clock mapping")
        if not isinstance(self.version, int) or self.version < 1:
            raise ValueError("clock version must be positive")
        origin = _utc(self.wall_origin_utc, "wall_origin_utc")
        valid_from = _utc(self.valid_from_utc, "valid_from_utc")
        valid_until = _utc(self.valid_until_utc, "valid_until_utc")
        if valid_until <= valid_from or not valid_from <= origin <= valid_until:
            raise ValueError("clock validity interval must contain its origin")
        object.__setattr__(self, "character_origin",
                           _decimal(self.character_origin, "character_origin"))
        object.__setattr__(self, "rate",
                           _decimal(self.rate, "rate", positive=True, limit=MAX_RATE))

    def character_at(self, wall_utc: str) -> Decimal:
        wall = _utc(wall_utc, "wall_utc")
        start = _utc(self.valid_from_utc, "valid_from_utc")
        end = _utc(self.valid_until_utc, "valid_until_utc")
        if not start <= wall <= end:
            raise ValueError("wall time is outside the mapping validity interval")
        delta = wall - _utc(self.wall_origin_utc, "wall_origin_utc")
        seconds = (Decimal(delta.days) * Decimal(86400)
                   + Decimal(delta.seconds)
                   + Decimal(delta.microseconds) / Decimal(1_000_000))
        result = self.character_origin + self.rate * seconds
        return _decimal(result, "mapped character time")


@dataclass(frozen=True)
class PersistentDeadline:
    deadline_id: str
    deadline_utc: str
    floating_rule: str | None
    timezone_name: str
    policy_ref: str

    def __post_init__(self) -> None:
        _identifier(self.deadline_id, "deadline_id")
        _utc(self.deadline_utc, "deadline_utc")
        _identifier(self.timezone_name, "timezone_name")
        _identifier(self.policy_ref, "policy_ref")
        if self.floating_rule is not None and (
                not isinstance(self.floating_rule, str)
                or not 1 <= len(self.floating_rule) <= 256):
            raise ValueError("invalid floating deadline rule")


@dataclass(frozen=True)
class RebuiltDeadline:
    deadline_id: str
    status: str
    monotonic_deadline: float | None
    remaining_seconds: float | None
    reason: str | None

    def __post_init__(self) -> None:
        if self.status not in {"armed", "expired", "deferred"}:
            raise ValueError("invalid rebuilt deadline status")


def install_schema(db) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_character_clocks(
            mapping_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            wall_origin_utc TEXT NOT NULL,
            character_origin TEXT NOT NULL,
            rate TEXT NOT NULL,
            valid_from_utc TEXT NOT NULL,
            valid_until_utc TEXT NOT NULL,
            policy_ref TEXT NOT NULL,
            issuer_domain TEXT NOT NULL,
            PRIMARY KEY(mapping_id,version)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_clock_operations(
            operation_id TEXT PRIMARY KEY,
            digest TEXT NOT NULL,
            mapping_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            mapping_json TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_deadlines(
            deadline_id TEXT PRIMARY KEY,
            deadline_utc TEXT NOT NULL,
            floating_rule TEXT,
            timezone_name TEXT NOT NULL,
            policy_ref TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_deadline_operations(
            operation_id TEXT PRIMARY KEY,
            digest TEXT NOT NULL,
            deadline_id TEXT NOT NULL,
            deadline_json TEXT NOT NULL
        )
    """)


def _mapping_dict(mapping: CharacterClockMapping) -> dict[str, object]:
    return {
        "mapping_id": mapping.mapping_id, "version": mapping.version,
        "wall_origin_utc": mapping.wall_origin_utc,
        "character_origin": str(mapping.character_origin), "rate": str(mapping.rate),
        "valid_from_utc": mapping.valid_from_utc,
        "valid_until_utc": mapping.valid_until_utc,
        "policy_ref": mapping.policy_ref, "issuer_domain": mapping.issuer_domain,
    }


def _mapping_from_dict(value) -> CharacterClockMapping:
    return CharacterClockMapping(**value)


def issue_clock_mapping(db, mapping: CharacterClockMapping,
                        operation_id: str, digest: str) -> CharacterClockMapping:
    if not isinstance(mapping, CharacterClockMapping):
        raise TypeError("mapping must be CharacterClockMapping")
    _identifier(operation_id, "operation_id")
    _digest(digest)
    prior = db.execute(
        "SELECT digest,mapping_id,version,mapping_json FROM runtime_clock_operations "
        "WHERE operation_id=?", (operation_id,),
    ).fetchone()
    if prior is not None:
        if (prior[0], prior[1], prior[2]) != (
                digest, mapping.mapping_id, mapping.version):
            raise ClockConflict("operation identity was reused with different input")
        return _mapping_from_dict(json.loads(prior[3]))
    versions = db.execute(
        "SELECT max(version) FROM runtime_character_clocks WHERE mapping_id=?",
        (mapping.mapping_id,),
    ).fetchone()[0]
    if versions is not None and mapping.version != versions + 1:
        raise ClockConflict("clock mapping versions must be consecutive")
    if versions is None and mapping.version != 1:
        raise ClockConflict("first clock mapping version must be 1")
    value = _mapping_dict(mapping)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    db.execute(
        "INSERT INTO runtime_character_clocks(mapping_id,version,wall_origin_utc,"
        "character_origin,rate,valid_from_utc,valid_until_utc,policy_ref,issuer_domain) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (mapping.mapping_id, mapping.version, mapping.wall_origin_utc,
         str(mapping.character_origin), str(mapping.rate), mapping.valid_from_utc,
         mapping.valid_until_utc, mapping.policy_ref, mapping.issuer_domain),
    )
    db.execute(
        "INSERT INTO runtime_clock_operations(operation_id,digest,mapping_id,version,"
        "mapping_json) VALUES(?,?,?,?,?)",
        (operation_id, digest, mapping.mapping_id, mapping.version, encoded),
    )
    return mapping


def get_clock_mapping(db, mapping_id: str,
                      version: int | None = None) -> CharacterClockMapping:
    _identifier(mapping_id, "mapping_id")
    if version is None:
        row = db.execute(
            "SELECT mapping_id,version,wall_origin_utc,character_origin,rate,"
            "valid_from_utc,valid_until_utc,policy_ref,issuer_domain FROM "
            "runtime_character_clocks WHERE mapping_id=? ORDER BY version DESC LIMIT 1",
            (mapping_id,),
        ).fetchone()
    else:
        if not isinstance(version, int) or version < 1:
            raise ValueError("clock version must be positive")
        row = db.execute(
            "SELECT mapping_id,version,wall_origin_utc,character_origin,rate,"
            "valid_from_utc,valid_until_utc,policy_ref,issuer_domain FROM "
            "runtime_character_clocks WHERE mapping_id=? AND version=?",
            (mapping_id, version),
        ).fetchone()
    if row is None:
        raise ClockConflict("clock mapping does not exist")
    return CharacterClockMapping(row[0], row[1], row[2], Decimal(row[3]),
                                 Decimal(row[4]), row[5], row[6], row[7], row[8])


def _deadline_dict(deadline: PersistentDeadline) -> dict[str, object]:
    return {
        "deadline_id": deadline.deadline_id,
        "deadline_utc": deadline.deadline_utc,
        "floating_rule": deadline.floating_rule,
        "timezone_name": deadline.timezone_name,
        "policy_ref": deadline.policy_ref,
    }


def put_deadline(db, deadline: PersistentDeadline,
                 operation_id: str, digest: str) -> PersistentDeadline:
    if not isinstance(deadline, PersistentDeadline):
        raise TypeError("deadline must be PersistentDeadline")
    _identifier(operation_id, "operation_id")
    _digest(digest)
    prior = db.execute(
        "SELECT digest,deadline_id,deadline_json FROM runtime_deadline_operations "
        "WHERE operation_id=?", (operation_id,),
    ).fetchone()
    if prior is not None:
        if prior[0] != digest or prior[1] != deadline.deadline_id:
            raise ClockConflict("operation identity was reused with different input")
        return PersistentDeadline(**json.loads(prior[2]))
    if db.execute("SELECT 1 FROM runtime_deadlines WHERE deadline_id=?",
                  (deadline.deadline_id,)).fetchone() is not None:
        raise ClockConflict("deadline ID already exists")
    encoded = json.dumps(_deadline_dict(deadline), sort_keys=True,
                         separators=(",", ":"))
    db.execute(
        "INSERT INTO runtime_deadlines(deadline_id,deadline_utc,floating_rule,"
        "timezone_name,policy_ref) VALUES(?,?,?,?,?)",
        (deadline.deadline_id, deadline.deadline_utc, deadline.floating_rule,
         deadline.timezone_name, deadline.policy_ref),
    )
    db.execute(
        "INSERT INTO runtime_deadline_operations(operation_id,digest,deadline_id,"
        "deadline_json) VALUES(?,?,?,?)",
        (operation_id, digest, deadline.deadline_id, encoded),
    )
    return deadline


def get_deadline(db, deadline_id: str) -> PersistentDeadline:
    _identifier(deadline_id, "deadline_id")
    row = db.execute(
        "SELECT deadline_id,deadline_utc,floating_rule,timezone_name,policy_ref "
        "FROM runtime_deadlines WHERE deadline_id=?", (deadline_id,),
    ).fetchone()
    if row is None:
        raise ClockConflict("deadline does not exist")
    return PersistentDeadline(row[0], row[1], row[2], row[3], row[4])


def rebuild_deadline(deadline: PersistentDeadline, *, wall_now_utc: str,
                     monotonic_now: float, clock_trusted: bool) -> RebuiltDeadline:
    if not isinstance(deadline, PersistentDeadline):
        raise TypeError("deadline must be PersistentDeadline")
    if isinstance(monotonic_now, bool) or not isinstance(monotonic_now, (int, float)) or not math.isfinite(monotonic_now):
        raise ValueError("monotonic_now must be finite")
    if not isinstance(clock_trusted, bool):
        raise ValueError("clock_trusted must be boolean")
    if not clock_trusted:
        return RebuiltDeadline(deadline.deadline_id, "deferred", None, None,
                               "wall_clock_untrusted")
    now = _utc(wall_now_utc, "wall_now_utc")
    target = _utc(deadline.deadline_utc, "deadline_utc")
    remaining = (target - now).total_seconds()
    if remaining <= 0:
        return RebuiltDeadline(deadline.deadline_id, "expired", float(monotonic_now),
                               0.0, None)
    return RebuiltDeadline(deadline.deadline_id, "armed",
                           float(monotonic_now) + remaining, remaining, None)


__all__ = [
    "CharacterClockMapping", "ClockConflict", "PersistentDeadline",
    "RebuiltDeadline", "get_clock_mapping", "get_deadline", "install_schema",
    "issue_clock_mapping", "put_deadline", "rebuild_deadline",
]
