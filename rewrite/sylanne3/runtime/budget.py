"""Transaction-scoped budget leases for the alpha1 runtime.

The functions in this module deliberately never commit or roll back.  The
GraphCoordinator owns the SQLite transaction so a budget change can be made
atomic with the business bundle that consumes it.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Mapping


MAX_DIMENSIONS = 32
MAX_QUANTITY = 9_000_000_000_000_000
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class BudgetError(RuntimeError):
    pass


class BudgetConflict(BudgetError):
    pass


class BudgetUnavailable(BudgetError):
    pass


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def _digest(value: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError("digest must be 64 lowercase hex characters")
    return value


def _amounts(value: Mapping[str, int] | None, *, allow_empty: bool = True) -> dict[str, int]:
    if value is None:
        value = {}
    if not isinstance(value, Mapping) or len(value) > MAX_DIMENSIONS:
        raise ValueError("budget amounts have too many dimensions")
    result: dict[str, int] = {}
    for dimension, amount in value.items():
        _identifier(dimension, "budget dimension")
        if isinstance(amount, bool) or not isinstance(amount, int):
            raise ValueError("budget quantities must be integer base units")
        if amount < 0 or amount > MAX_QUANTITY:
            raise ValueError("budget quantity is outside the supported range")
        if amount:
            result[dimension] = amount
    if not allow_empty and not result:
        raise ValueError("budget amounts cannot be empty")
    return result


def _json(value: Mapping[str, int]) -> str:
    return json.dumps(dict(sorted(value.items())), separators=(",", ":"), ensure_ascii=True)


def _plus(left: Mapping[str, int], right: Mapping[str, int]) -> dict[str, int]:
    result = dict(left)
    for key, value in right.items():
        total = result.get(key, 0) + value
        if total > MAX_QUANTITY:
            raise BudgetUnavailable("budget counter overflow")
        if total:
            result[key] = total
    return result


def _minus(left: Mapping[str, int], right: Mapping[str, int]) -> dict[str, int]:
    result = dict(left)
    for key, value in right.items():
        remaining = result.get(key, 0) - value
        if remaining < 0:
            raise BudgetConflict("budget counter would become negative")
        if remaining:
            result[key] = remaining
        else:
            result.pop(key, None)
    return result


@dataclass(frozen=True)
class BudgetLease:
    lease_id: str
    parent_id: str | None
    bot_id: str
    persona_id: str
    currency: str
    limits: Mapping[str, int]
    used: Mapping[str, int]
    reserved: Mapping[str, int]
    unconfirmed: Mapping[str, int]
    version: int
    state: str

    def __post_init__(self) -> None:
        _identifier(self.lease_id, "lease_id")
        if self.parent_id is not None:
            _identifier(self.parent_id, "parent_id")
            if self.parent_id == self.lease_id:
                raise ValueError("a budget lease cannot parent itself")
        _identifier(self.bot_id, "bot_id")
        _identifier(self.persona_id, "persona_id")
        if not _CURRENCY.fullmatch(self.currency):
            raise ValueError("currency must be an ISO-style uppercase code")
        limits = _amounts(self.limits, allow_empty=False)
        used = _amounts(self.used)
        reserved = _amounts(self.reserved)
        unconfirmed = _amounts(self.unconfirmed)
        if not isinstance(self.version, int) or self.version < 1:
            raise ValueError("budget version must be positive")
        if self.state not in {"active", "closed", "blocked"}:
            raise ValueError("invalid budget state")
        for dimension in set(used) | set(reserved) | set(unconfirmed):
            if dimension not in limits:
                raise ValueError("budget counter has no declared limit")
            if used.get(dimension, 0) + reserved.get(dimension, 0) + unconfirmed.get(dimension, 0) > limits[dimension]:
                raise ValueError("budget counters exceed the lease limit")
        object.__setattr__(self, "limits", limits)
        object.__setattr__(self, "used", used)
        object.__setattr__(self, "reserved", reserved)
        object.__setattr__(self, "unconfirmed", unconfirmed)

    def available(self, dimension: str) -> int:
        return max(0, self.limits.get(dimension, 0) - self.used.get(dimension, 0)
                   - self.reserved.get(dimension, 0)
                   - self.unconfirmed.get(dimension, 0))


@dataclass(frozen=True)
class BudgetReceipt:
    status: str
    operation_id: str
    digest: str
    lease_id: str
    version: int
    used: Mapping[str, int]
    reserved: Mapping[str, int]
    unconfirmed: Mapping[str, int]

    def __post_init__(self) -> None:
        if self.status not in {"created", "reserved", "settled", "pending_confirmation", "closed", "duplicate"}:
            raise ValueError("invalid budget receipt status")
        _identifier(self.operation_id, "operation_id")
        _digest(self.digest)
        _identifier(self.lease_id, "lease_id")
        _amounts(self.used)
        _amounts(self.reserved)
        _amounts(self.unconfirmed)


@dataclass(frozen=True)
class BudgetReservation:
    lease_id: str
    operation_id: str
    digest: str
    ceiling: Mapping[str, int]
    state: str = "reserved"

    def __post_init__(self) -> None:
        _identifier(self.lease_id, "lease_id")
        _identifier(self.operation_id, "operation_id")
        _digest(self.digest)
        object.__setattr__(self, "ceiling", _amounts(self.ceiling, allow_empty=False))
        if self.state != "reserved":
            raise BudgetConflict("budget reservation is no longer settleable")


@dataclass(frozen=True)
class BudgetPrediction:
    receipt: BudgetReceipt
    receipt_json_sha256: str


def install_schema(db) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_budget_leases(
            lease_id TEXT PRIMARY KEY,
            parent_id TEXT,
            bot_id TEXT NOT NULL,
            persona_id TEXT NOT NULL,
            currency TEXT NOT NULL,
            limits_json TEXT NOT NULL,
            used_json TEXT NOT NULL,
            reserved_json TEXT NOT NULL,
            unconfirmed_json TEXT NOT NULL,
            version INTEGER NOT NULL,
            state TEXT NOT NULL,
            FOREIGN KEY(parent_id) REFERENCES runtime_budget_leases(lease_id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_budget_reservations(
            lease_id TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            digest TEXT NOT NULL,
            ceiling_json TEXT NOT NULL,
            state TEXT NOT NULL,
            actual_json TEXT,
            PRIMARY KEY(lease_id, operation_id),
            FOREIGN KEY(lease_id) REFERENCES runtime_budget_leases(lease_id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_budget_operations(
            bot_id TEXT NOT NULL,
            persona_id TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            phase TEXT NOT NULL,
            digest TEXT NOT NULL,
            lease_id TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            PRIMARY KEY(bot_id, persona_id, operation_id, phase)
        )
    """)


def _lease_from_row(row) -> BudgetLease:
    if row is None:
        raise BudgetUnavailable("budget lease does not exist")
    return BudgetLease(
        row[0], row[1], row[2], row[3], row[4], json.loads(row[5]),
        json.loads(row[6]), json.loads(row[7]), json.loads(row[8]), row[9], row[10],
    )


def get_budget_lease(db, lease_id: str) -> BudgetLease:
    _identifier(lease_id, "lease_id")
    return _lease_from_row(db.execute(
        "SELECT lease_id,parent_id,bot_id,persona_id,currency,limits_json,used_json,"
        "reserved_json,unconfirmed_json,version,state FROM runtime_budget_leases "
        "WHERE lease_id=?", (lease_id,),
    ).fetchone())


def _save_lease(db, lease: BudgetLease) -> None:
    changed = db.execute(
        "UPDATE runtime_budget_leases SET used_json=?,reserved_json=?,unconfirmed_json=?,"
        "version=?,state=? WHERE lease_id=?",
        (_json(lease.used), _json(lease.reserved), _json(lease.unconfirmed),
         lease.version, lease.state, lease.lease_id),
    ).rowcount
    if changed != 1:
        raise BudgetUnavailable("budget lease disappeared")


def _receipt(lease: BudgetLease, status: str, operation_id: str, digest: str) -> BudgetReceipt:
    return BudgetReceipt(status, operation_id, digest, lease.lease_id, lease.version,
                         lease.used, lease.reserved, lease.unconfirmed)


def _receipt_json(receipt: BudgetReceipt) -> str:
    return json.dumps({
        "status": receipt.status, "operation_id": receipt.operation_id,
        "digest": receipt.digest, "lease_id": receipt.lease_id,
        "version": receipt.version, "used": receipt.used,
        "reserved": receipt.reserved, "unconfirmed": receipt.unconfirmed,
    }, sort_keys=True, separators=(",", ":"))


def _receipt_from_json(value: str) -> BudgetReceipt:
    return BudgetReceipt(**json.loads(value))


def _reserve_transition(lease: BudgetLease, ceiling: Mapping[str, int]) -> BudgetLease:
    if lease.state != "active":
        raise BudgetUnavailable("budget lease is inactive")
    for dimension, amount in ceiling.items():
        if amount > lease.available(dimension):
            raise BudgetUnavailable("budget ceiling exceeds availability")
    return BudgetLease(
        lease.lease_id, lease.parent_id, lease.bot_id, lease.persona_id,
        lease.currency, lease.limits, lease.used, _plus(lease.reserved, ceiling),
        lease.unconfirmed, lease.version + 1, lease.state,
    )


def _settle_transition(
    lease: BudgetLease, ceiling: Mapping[str, int], actual: Mapping[str, int] | None,
    execution_revoked: bool,
) -> tuple[BudgetLease, str, str | None, str]:
    if actual is None:
        used = lease.used
        unconfirmed = _plus(lease.unconfirmed, ceiling)
        status = "pending_confirmation"
        actual_json = None
        reservation_state = "unknown"
    else:
        charged = _amounts(actual)
        for dimension, amount in charged.items():
            if amount > ceiling.get(dimension, 0):
                raise BudgetUnavailable("actual cost exceeds reserved ceiling")
        if charged != ceiling and not execution_revoked:
            raise BudgetUnavailable("unused reserved budget requires revoked execution authority")
        used = _plus(lease.used, charged)
        unconfirmed = lease.unconfirmed
        status = "settled"
        actual_json = _json(charged)
        reservation_state = "settled"
    updated = BudgetLease(
        lease.lease_id, lease.parent_id, lease.bot_id, lease.persona_id,
        lease.currency, lease.limits, used, _minus(lease.reserved, ceiling),
        unconfirmed, lease.version + 1, lease.state,
    )
    return updated, status, actual_json, reservation_state


def predict_budget_settlement(
    lease: BudgetLease, operation_id: str, digest: str,
    ceiling: Mapping[str, int], actual: Mapping[str, int] | None,
    *, reservation: BudgetReservation | None = None,
    inline_reserve: bool = False, execution_revoked: bool = False,
) -> BudgetPrediction:
    """Predict a fresh reserve/settle path from trusted, versioned input snapshots.

    This performs no I/O and does not authenticate the snapshot or replace the
    transaction's operation identity, issuer, and lease-version checks.
    """
    if not isinstance(lease, BudgetLease):
        raise TypeError("lease must be BudgetLease")
    _identifier(operation_id, "operation_id")
    _digest(digest)
    if not isinstance(execution_revoked, bool):
        raise ValueError("execution_revoked must be boolean")
    requested = _amounts(ceiling, allow_empty=False)
    if inline_reserve:
        if reservation is not None:
            raise ValueError("inline reserve cannot reuse a reservation")
        lease = _reserve_transition(lease, requested)
    else:
        if not isinstance(reservation, BudgetReservation):
            raise BudgetConflict("no matching budget reservation")
        if (reservation.lease_id, reservation.operation_id, reservation.digest, reservation.ceiling) != (
            lease.lease_id, operation_id, digest, requested,
        ):
            raise BudgetConflict("budget reservation differs from the requested settlement")
    updated, status, _, _ = _settle_transition(lease, requested, actual, execution_revoked)
    receipt = _receipt(updated, status, operation_id, digest)
    return BudgetPrediction(receipt, hashlib.sha256(_receipt_json(receipt).encode("utf-8")).hexdigest())


def _prior(db, lease: BudgetLease, operation_id: str, phase: str,
           digest: str) -> BudgetReceipt | None:
    row = db.execute(
        "SELECT digest,lease_id,receipt_json FROM runtime_budget_operations WHERE "
        "bot_id=? AND persona_id=? AND operation_id=? AND phase=?",
        (lease.bot_id, lease.persona_id, operation_id, phase),
    ).fetchone()
    if row is None:
        return None
    if row[0] != digest or row[1] != lease.lease_id:
        raise BudgetConflict("operation identity was reused with different input")
    return _receipt_from_json(row[2])


def _record(db, lease: BudgetLease, operation_id: str, phase: str,
            digest: str, receipt: BudgetReceipt) -> None:
    db.execute(
        "INSERT INTO runtime_budget_operations(bot_id,persona_id,operation_id,phase,"
        "digest,lease_id,receipt_json) VALUES(?,?,?,?,?,?,?)",
        (lease.bot_id, lease.persona_id, operation_id, phase, digest,
         lease.lease_id, _receipt_json(receipt)),
    )


def create_budget_lease(db, lease: BudgetLease, operation_id: str,
                        digest: str) -> BudgetReceipt:
    if not isinstance(lease, BudgetLease):
        raise TypeError("lease must be BudgetLease")
    _identifier(operation_id, "operation_id")
    _digest(digest)
    existing_op = db.execute(
        "SELECT digest,lease_id,receipt_json FROM runtime_budget_operations WHERE "
        "bot_id=? AND persona_id=? AND operation_id=? AND phase='create'",
        (lease.bot_id, lease.persona_id, operation_id),
    ).fetchone()
    if existing_op is not None:
        if existing_op[0] != digest or existing_op[1] != lease.lease_id:
            raise BudgetConflict("operation identity was reused with different input")
        return _receipt_from_json(existing_op[2])
    if db.execute("SELECT 1 FROM runtime_budget_leases WHERE lease_id=?",
                  (lease.lease_id,)).fetchone() is not None:
        raise BudgetConflict("lease ID already exists")
    if lease.used or lease.reserved or lease.unconfirmed or lease.version != 1 or lease.state != "active":
        raise ValueError("new budget lease must start active and unused at version 1")
    if lease.parent_id is not None:
        parent = get_budget_lease(db, lease.parent_id)
        if (parent.bot_id, parent.persona_id, parent.currency) != (
                lease.bot_id, lease.persona_id, lease.currency):
            raise BudgetConflict("child lease must share parent namespace and currency")
        if parent.state != "active":
            raise BudgetUnavailable("parent budget lease is inactive")
        for dimension, amount in lease.limits.items():
            if amount > parent.available(dimension):
                raise BudgetUnavailable("child lease exceeds parent availability")
        parent = BudgetLease(
            parent.lease_id, parent.parent_id, parent.bot_id, parent.persona_id,
            parent.currency, parent.limits, parent.used,
            _plus(parent.reserved, lease.limits), parent.unconfirmed,
            parent.version + 1, parent.state,
        )
        _save_lease(db, parent)
    db.execute(
        "INSERT INTO runtime_budget_leases(lease_id,parent_id,bot_id,persona_id,currency,"
        "limits_json,used_json,reserved_json,unconfirmed_json,version,state) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (lease.lease_id, lease.parent_id, lease.bot_id, lease.persona_id,
         lease.currency, _json(lease.limits), _json(lease.used),
         _json(lease.reserved), _json(lease.unconfirmed), lease.version, lease.state),
    )
    receipt = _receipt(lease, "created", operation_id, digest)
    _record(db, lease, operation_id, "create", digest, receipt)
    return receipt


def reserve_budget(db, lease_id: str, operation_id: str, digest: str,
                   ceiling: Mapping[str, int]) -> BudgetReceipt:
    _identifier(operation_id, "operation_id")
    _digest(digest)
    requested = _amounts(ceiling, allow_empty=False)
    lease = get_budget_lease(db, lease_id)
    prior = _prior(db, lease, operation_id, "reserve", digest)
    if prior is not None:
        return prior
    updated = _reserve_transition(lease, requested)
    _save_lease(db, updated)
    db.execute(
        "INSERT INTO runtime_budget_reservations(lease_id,operation_id,digest,ceiling_json,"
        "state,actual_json) VALUES(?,?,?,?, 'reserved', NULL)",
        (lease_id, operation_id, digest, _json(requested)),
    )
    receipt = _receipt(updated, "reserved", operation_id, digest)
    _record(db, updated, operation_id, "reserve", digest, receipt)
    return receipt


def settle_budget(db, lease_id: str, operation_id: str, digest: str,
                  actual: Mapping[str, int] | None, *,
                  execution_revoked: bool = False) -> BudgetReceipt:
    _identifier(operation_id, "operation_id")
    _digest(digest)
    if not isinstance(execution_revoked, bool):
        raise ValueError("execution_revoked must be boolean")
    lease = get_budget_lease(db, lease_id)
    prior = _prior(db, lease, operation_id, "settle", digest)
    if prior is not None:
        return prior
    row = db.execute(
        "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (lease_id, operation_id),
    ).fetchone()
    if row is None or row[0] != digest:
        raise BudgetConflict("no matching budget reservation")
    if row[2] != "reserved":
        raise BudgetConflict("budget reservation is no longer settleable")
    ceiling = _amounts(json.loads(row[1]), allow_empty=False)
    updated, status, actual_json, reservation_state = _settle_transition(
        lease, ceiling, actual, execution_revoked,
    )
    _save_lease(db, updated)
    db.execute(
        "UPDATE runtime_budget_reservations SET state=?,actual_json=? "
        "WHERE lease_id=? AND operation_id=?",
        (reservation_state, actual_json, lease_id, operation_id),
    )
    receipt = _receipt(updated, status, operation_id, digest)
    _record(db, updated, operation_id, "settle", digest, receipt)
    return receipt


def resolve_unconfirmed(db, lease_id: str, original_operation_id: str,
                        resolution_operation_id: str, digest: str,
                        actual: Mapping[str, int] | None,
                        *, execution_revoked: bool) -> BudgetReceipt:
    _identifier(original_operation_id, "original_operation_id")
    _identifier(resolution_operation_id, "resolution_operation_id")
    _digest(digest)
    lease = get_budget_lease(db, lease_id)
    prior = _prior(db, lease, resolution_operation_id, "resolve", digest)
    if prior is not None:
        return prior
    row = db.execute(
        "SELECT ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (lease_id, original_operation_id),
    ).fetchone()
    if row is None or row[1] != "unknown":
        raise BudgetConflict("reservation is not awaiting confirmation")
    ceiling = _amounts(json.loads(row[0]), allow_empty=False)
    charged = _amounts(actual)
    for dimension, amount in charged.items():
        if amount > ceiling.get(dimension, 0):
            raise BudgetUnavailable("resolved cost exceeds held ceiling")
    if charged != ceiling and not execution_revoked:
        raise BudgetUnavailable("unused unknown ceiling requires revoked execution authority")
    updated = BudgetLease(
        lease.lease_id, lease.parent_id, lease.bot_id, lease.persona_id,
        lease.currency, lease.limits, _plus(lease.used, charged), lease.reserved,
        _minus(lease.unconfirmed, ceiling), lease.version + 1, lease.state,
    )
    _save_lease(db, updated)
    db.execute(
        "UPDATE runtime_budget_reservations SET state='settled',actual_json=? "
        "WHERE lease_id=? AND operation_id=?",
        (_json(charged), lease_id, original_operation_id),
    )
    receipt = _receipt(updated, "settled", resolution_operation_id, digest)
    _record(db, updated, resolution_operation_id, "resolve", digest, receipt)
    return receipt


def close_budget_lease(db, lease_id: str, operation_id: str, digest: str,
                       *, execution_revoked: bool) -> BudgetReceipt:
    """Close a child lease and settle its counters into its parent.

    Releasing any unused part of the parent's encumbrance requires proof that
    the child can no longer execute.  Active reservations must first become a
    known charge or an unconfirmed ceiling; closing never erases them.
    """
    _identifier(operation_id, "operation_id")
    _digest(digest)
    if not isinstance(execution_revoked, bool):
        raise ValueError("execution_revoked must be boolean")
    lease = get_budget_lease(db, lease_id)
    prior = _prior(db, lease, operation_id, "close", digest)
    if prior is not None:
        return prior
    if lease.parent_id is None:
        raise BudgetConflict("root budget lease cannot be closed into a parent")
    if lease.state != "active":
        raise BudgetConflict("budget lease is not active")
    if lease.reserved:
        raise BudgetUnavailable("active reservations must be resolved before close")
    unused = {
        dimension: limit - lease.used.get(dimension, 0)
        - lease.unconfirmed.get(dimension, 0)
        for dimension, limit in lease.limits.items()
        if limit - lease.used.get(dimension, 0)
        - lease.unconfirmed.get(dimension, 0) > 0
    }
    if unused and not execution_revoked:
        raise BudgetUnavailable(
            "unused child budget can be released only after execution is revoked"
        )
    parent = get_budget_lease(db, lease.parent_id)
    if parent.state != "active":
        raise BudgetUnavailable("parent budget lease is inactive")
    parent_updated = BudgetLease(
        parent.lease_id, parent.parent_id, parent.bot_id, parent.persona_id,
        parent.currency, parent.limits, _plus(parent.used, lease.used),
        _minus(parent.reserved, lease.limits),
        _plus(parent.unconfirmed, lease.unconfirmed), parent.version + 1,
        parent.state,
    )
    child_updated = BudgetLease(
        lease.lease_id, lease.parent_id, lease.bot_id, lease.persona_id,
        lease.currency, lease.limits, lease.used, lease.reserved,
        lease.unconfirmed, lease.version + 1, "closed",
    )
    _save_lease(db, parent_updated)
    _save_lease(db, child_updated)
    receipt = _receipt(child_updated, "closed", operation_id, digest)
    _record(db, child_updated, operation_id, "close", digest, receipt)
    return receipt


__all__ = [
    "BudgetConflict", "BudgetError", "BudgetLease", "BudgetPrediction",
    "BudgetReceipt", "BudgetReservation",
    "BudgetUnavailable", "close_budget_lease", "create_budget_lease", "get_budget_lease",
    "install_schema", "predict_budget_settlement", "reserve_budget",
    "resolve_unconfirmed", "settle_budget",
]
