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
            # A provider can report more than its quoted ceiling. The actual
            # debt remains in used; availability clamps to zero below.
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
        if self.status not in {"created", "reserved", "settled", "overrun", "pending_confirmation", "pending_overrun", "closed", "duplicate", "cancelled_unstarted"}:
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
            resolution_binding_json TEXT,
            PRIMARY KEY(bot_id, persona_id, operation_id, phase)
        )
    """)
    # Older local stores may predate the explicit original-call binding.
    # Their unbound resolution receipts remain held for manual reconciliation.
    columns = {row[1] for row in db.execute("PRAGMA table_info(runtime_budget_operations)")}
    if "resolution_binding_json" not in columns:
        db.execute("ALTER TABLE runtime_budget_operations "
                   "ADD COLUMN resolution_binding_json TEXT")
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_budget_debt_blocks(
            lease_id TEXT NOT NULL,
            cause_lease_id TEXT NOT NULL,
            cause_operation_id TEXT NOT NULL,
            PRIMARY KEY(lease_id,cause_lease_id,cause_operation_id),
            FOREIGN KEY(lease_id) REFERENCES runtime_budget_leases(lease_id)
        )
    """)
    # Preserve admission safety when opening an older store that already
    # contains an overrun. The original reservation remains the debt evidence.
    for lease_id, operation_id in db.execute(
            "SELECT lease_id,operation_id FROM runtime_budget_reservations "
            "WHERE state IN ('overrun','partial_overrun')"):
        _record_debt_block(db, lease_id, operation_id)


def _lease_from_row(row) -> BudgetLease:
    from .domain_background_read_v3 import background_json_loads_v3
    if row is None:
        raise BudgetUnavailable("budget lease does not exist")
    return BudgetLease(
        row[0], row[1], row[2], row[3], row[4], background_json_loads_v3(row[5]),
        background_json_loads_v3(row[6]), background_json_loads_v3(row[7]), background_json_loads_v3(row[8]), row[9], row[10],
    )


def get_budget_lease(db, lease_id: str) -> BudgetLease:
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    _identifier(lease_id, "lease_id")
    from ..authority_service.foreground_mesh_source_read_v3 import read_bound_foreground_mesh_budget_v3
    mesh, lease = read_bound_foreground_mesh_budget_v3(db,lease_id)
    if mesh:
        return lease
    from .current_life_numeric_accounting_v3 import numeric_accounting_current_point_v3,_LEASE_COLUMNS
    numeric,row=numeric_accounting_current_point_v3(db,table='runtime_budget_leases',columns=_LEASE_COLUMNS,
        key_columns=('lease_id',),key=(lease_id,))
    if numeric:return _lease_from_row(row)
    from ..authority_service.life_numeric_source_read_v3 import read_bound_numeric_model_budget_lease_v3
    numeric,lease=read_bound_numeric_model_budget_lease_v3(db,lease_id)
    if numeric:return lease
    from .current_life_numeric_read_v3 import read_bound_numeric_host_lease_v3
    numeric,lease=read_bound_numeric_host_lease_v3(db,lease_id)
    if numeric:return lease
    from .contact_domain_source_work_v3 import contact_domain_budget_lease_v3
    contact,row = contact_domain_budget_lease_v3(db,lease_id)
    if contact:
        return _lease_from_row(row)
    from ..authority_service.model_reply_scope_observation_v3 import model_reply_scope_point_v3
    row=model_reply_scope_point_v3(db,table='runtime_budget_leases',
        columns=('lease_id','parent_id','bot_id','persona_id','currency','limits_json','used_json',
            'reserved_json','unconfirmed_json','version','state'),
        key_columns=('lease_id',),key=(lease_id,),legacy_reader=lambda:_artifact_receipt_sql_v1(db,
            "SELECT lease_id,parent_id,bot_id,persona_id,currency,limits_json,used_json,"
            "reserved_json,unconfirmed_json,version,state FROM runtime_budget_leases "
            "WHERE lease_id=?", (lease_id,)).fetchone())
    return _lease_from_row(row)


def _lease_ancestry(db, lease_id: str):
    """Include self and every parent; a cycle is invalid budget authority."""
    seen = set()
    current = lease_id
    while current is not None:
        if current in seen:
            raise BudgetConflict("budget lease ancestry has a cycle")
        seen.add(current)
        lease = get_budget_lease(db, current)
        yield lease
        current = lease.parent_id


def _record_debt_block(db, lease_id: str, operation_id: str) -> None:
    for ancestor in _lease_ancestry(db, lease_id):
        db.execute(
            "INSERT OR IGNORE INTO runtime_budget_debt_blocks"
            "(lease_id,cause_lease_id,cause_operation_id) VALUES(?,?,?)",
            (ancestor.lease_id, lease_id, operation_id),
        )


def _propagate_closed_resolution(
    db, lease: BudgetLease, held_ceiling: Mapping[str, int],
    actual: Mapping[str, int],
) -> None:
    """Replace a transferred unknown ceiling with its bill in closed ancestry.

    Closing a child moves its used and unconfirmed counters into its parent.
    Each subsequently closed parent moves those counters upward again. A late
    provider receipt must update those ledgers as well as the original child.
    """
    seen = {lease.lease_id}
    current = lease
    while current.state == "closed":
        if current.parent_id is None or current.parent_id in seen:
            raise BudgetConflict("closed budget ancestry is invalid")
        seen.add(current.parent_id)
        parent = get_budget_lease(db, current.parent_id)
        updated = BudgetLease(
            parent.lease_id, parent.parent_id, parent.bot_id, parent.persona_id,
            parent.currency, parent.limits, _plus(parent.used, actual),
            parent.reserved, _minus(parent.unconfirmed, held_ceiling),
            parent.version + 1, parent.state,
        )
        _save_lease(db, updated)
        current = parent


def _assert_no_ancestor_debt(db, lease_id: str) -> None:
    for ancestor in _lease_ancestry(db, lease_id):
        if db.execute(
                "SELECT 1 FROM runtime_budget_debt_blocks "
                "WHERE lease_id=? LIMIT 1", (ancestor.lease_id,),
        ).fetchone() is not None:
            raise BudgetUnavailable("budget ancestry has unresolved overrun debt")


def require_budget_family_admissible(db, lease_id: str) -> None:
    """Read-only dispatch gate, evaluated in the caller's pinned DB snapshot."""
    _assert_no_ancestor_debt(db, lease_id)


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
        if any(dimension not in lease.limits for dimension in charged):
            raise BudgetUnavailable("actual cost uses an undeclared lease dimension")
        if any(charged.get(dimension, 0) < amount
               for dimension, amount in ceiling.items()) and not execution_revoked:
            raise BudgetUnavailable("unused reserved budget requires revoked execution authority")
        used = _plus(lease.used, charged)
        unconfirmed = lease.unconfirmed
        status = ("overrun" if any(amount > ceiling.get(dimension, 0)
                                   for dimension, amount in charged.items())
                  else "settled")
        actual_json = _json(charged)
        reservation_state = status
    updated = BudgetLease(
        lease.lease_id, lease.parent_id, lease.bot_id, lease.persona_id,
        lease.currency, lease.limits, used, _minus(lease.reserved, ceiling),
        unconfirmed, lease.version + 1, lease.state,
    )
    return updated, status, actual_json, reservation_state


def _partial_transition(
    lease: BudgetLease, ceiling: Mapping[str, int],
    known_actual: Mapping[str, int], unknown_dimensions: tuple[str, ...],
    execution_revoked: bool,
) -> tuple[BudgetLease, str, str, str]:
    """Account known dimensions now and retain only unknown upper bounds."""
    if (type(unknown_dimensions) is not tuple or not unknown_dimensions
            or len(set(unknown_dimensions)) != len(unknown_dimensions)
            or not set(unknown_dimensions) <= set(ceiling)
            or set(known_actual) | set(unknown_dimensions) != set(ceiling)
            or set(known_actual) & set(unknown_dimensions)):
        raise BudgetConflict("partial cost must partition the original ceiling")
    charged = _amounts(known_actual)
    if any(dimension not in lease.limits for dimension in known_actual):
        raise BudgetUnavailable("partial cost uses an undeclared lease dimension")
    if (not execution_revoked and any(
            known_actual[dimension] < ceiling[dimension]
            for dimension in known_actual)):
        raise BudgetUnavailable("unused known ceiling requires revoked execution authority")
    unknown_ceiling = {dimension: ceiling[dimension]
                       for dimension in unknown_dimensions}
    overrun = any(known_actual[dimension] > ceiling[dimension]
                  for dimension in known_actual)
    updated = BudgetLease(
        lease.lease_id, lease.parent_id, lease.bot_id, lease.persona_id,
        lease.currency, lease.limits, _plus(lease.used, charged),
        _minus(lease.reserved, ceiling),
        _plus(lease.unconfirmed, unknown_ceiling), lease.version + 1, lease.state,
    )
    return (updated, "pending_overrun" if overrun else "pending_confirmation",
            json.dumps(dict(sorted(known_actual.items())), separators=(",", ":")),
            "partial_overrun" if overrun else "partial_unknown")


def predict_budget_partial_settlement(
    lease: BudgetLease, operation_id: str, digest: str,
    ceiling: Mapping[str, int], known_actual: Mapping[str, int],
    unknown_dimensions: tuple[str, ...], *, reservation: BudgetReservation,
    execution_revoked: bool,
) -> BudgetPrediction:
    """Pure prediction for a fresh, partially observed original reservation."""
    requested = _amounts(ceiling, allow_empty=False)
    if (type(reservation) is not BudgetReservation
            or (reservation.lease_id, reservation.operation_id,
                reservation.digest, reservation.ceiling)
            != (lease.lease_id, operation_id, digest, requested)):
        raise BudgetConflict("partial budget reservation differs")
    updated, status, _, _ = _partial_transition(
        lease, requested, known_actual, unknown_dimensions, execution_revoked)
    receipt = _receipt(updated, status, operation_id, digest)
    return BudgetPrediction(
        receipt, hashlib.sha256(_receipt_json(receipt).encode("utf-8")).hexdigest())


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


def _resolution_binding(original_operation_id: str, actual: Mapping[str, int],
                        execution_revoked: bool) -> str:
    if not isinstance(execution_revoked, bool):
        raise ValueError("execution_revoked must be boolean")
    _amounts(actual)
    return json.dumps({
        "original_operation_id": original_operation_id,
        "actual": dict(sorted(actual.items())),
        "execution_revoked": execution_revoked,
    }, sort_keys=True, separators=(",", ":"))


def _settlement_binding(actual: Mapping[str, int] | None,
                        execution_revoked: bool) -> str:
    if not isinstance(execution_revoked, bool):
        raise ValueError("execution_revoked must be boolean")
    if actual is not None:
        _amounts(actual)
    return json.dumps({
        "actual": None if actual is None else dict(sorted(actual.items())),
        "execution_revoked": execution_revoked,
    }, sort_keys=True, separators=(",", ":"))


def _numeric_accounting_budget_point_v3(db,*,table,columns,key_columns,key,legacy_reader):
    from .current_life_numeric_accounting_v3 import numeric_accounting_current_point_v3
    handled,row=numeric_accounting_current_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    return row if handled else legacy_reader()


def _prior(db, lease: BudgetLease, operation_id: str, phase: str,
           digest: str, *, resolution_binding: str | None = None) -> BudgetReceipt | None:
    row = _numeric_accounting_budget_point_v3(db,table='runtime_budget_operations',columns=('digest','lease_id','receipt_json','resolution_binding_json'),
        key_columns=('bot_id','persona_id','operation_id','phase'),key=(lease.bot_id,lease.persona_id,operation_id,phase),legacy_reader=lambda:db.execute(
        "SELECT digest,lease_id,receipt_json,resolution_binding_json "
        "FROM runtime_budget_operations WHERE "
        "bot_id=? AND persona_id=? AND operation_id=? AND phase=?",
        (lease.bot_id, lease.persona_id, operation_id, phase),
    ).fetchone())
    if row is None:
        return None
    if row[0] != digest or row[1] != lease.lease_id:
        raise BudgetConflict("operation identity was reused with different input")
    if phase == "resolve" and row[3] != resolution_binding:
        raise BudgetConflict("resolution original call or actual cost differs")
    if phase == "settle" and resolution_binding is not None and row[3] != resolution_binding:
        raise BudgetConflict("settlement actual cost or revocation differs")
    return _receipt_from_json(row[2])


def _record(db, lease: BudgetLease, operation_id: str, phase: str,
            digest: str, receipt: BudgetReceipt, *,
            resolution_binding: str | None = None) -> None:
    db.execute(
        "INSERT INTO runtime_budget_operations(bot_id,persona_id,operation_id,phase,"
        "digest,lease_id,receipt_json,resolution_binding_json) VALUES(?,?,?,?,?,?,?,?)",
        (lease.bot_id, lease.persona_id, operation_id, phase, digest,
         lease.lease_id, _receipt_json(receipt), resolution_binding),
    )
    from .current_life_numeric_accounting_v3 import numeric_accounting_budget_transition_v3
    numeric_accounting_budget_transition_v3(db,lease,operation_id,phase,digest,receipt)


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
        _assert_no_ancestor_debt(db, lease.parent_id)
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
    _assert_no_ancestor_debt(db, lease_id)
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
    binding = _settlement_binding(actual, execution_revoked)
    lease = get_budget_lease(db, lease_id)
    prior = _prior(db, lease, operation_id, "settle", digest,
                   resolution_binding=binding)
    if prior is not None:
        return prior
    row = _numeric_accounting_budget_point_v3(db,table='runtime_budget_reservations',columns=('digest','ceiling_json','state'),
        key_columns=('lease_id','operation_id'),key=(lease_id,operation_id),legacy_reader=lambda:db.execute(
        "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (lease_id, operation_id),
    ).fetchone())
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
    _record(db, updated, operation_id, "settle", digest, receipt,
            resolution_binding=binding)
    if status == "overrun":
        _record_debt_block(db, lease_id, operation_id)
    return receipt


def cancel_unstarted_offline_reservation_v1(db, *, witness) -> BudgetReceipt:
    """Release a never-started D11 reserve after actual permanent claim retirement.

    An active child still encumbers its full allocation in its parent. Only
    closing that child transfers its counters and releases the allocation;
    cancelling this child reservation must not release the parent twice.
    """
    from .d11_offline_unstarted_cancellation_v1 import require_offline_cancellation_witness_v1
    gate = require_offline_cancellation_witness_v1(db, witness)
    binding = gate.binding
    lease = get_budget_lease(db, binding.parent_budget_lease_ref)
    proof_binding = json.dumps({"schema": "d11.unstarted-reservation-cancellation-binding.v1",
        "binding_digest": binding.digest, "accounting_original_digest": gate.accounting_original_digest,
        "claim_gate_id": gate.claim_gate_id, "no_future_claim_digest": gate.no_future_claim_digest,
        "cancellation_gate_digest": gate.digest, "ceiling": {"thread_cpu_ms": binding.cpu_ceiling_ms}},
        sort_keys=True, separators=(",", ":"))
    prior = db.execute("SELECT digest,lease_id,receipt_json,resolution_binding_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='cancel_unstarted'",
        (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    if prior is not None:
        if prior[:2] != (binding.reservation_digest, lease.lease_id) or prior[3] != proof_binding:
            raise BudgetConflict("offline cancellation replay changed its no-future-claim original")
        receipt = _receipt_from_json(prior[2])
        if receipt.status != "cancelled_unstarted":
            raise BudgetConflict("offline cancellation original has another status")
        return receipt
    ceiling = {"thread_cpu_ms": binding.cpu_ceiling_ms}
    row = db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (lease.lease_id, binding.reservation_operation_id)).fetchone()
    if (row != (binding.reservation_digest, _json(ceiling), "reserved", None)
            or (lease.bot_id, lease.persona_id) != binding.namespace.as_tuple or lease.state == "closed"
            or db.execute("SELECT 1 FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? "
                "AND phase IN ('settle','resolve')", (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone() is not None):
        raise BudgetConflict("offline cancellation has no exact unstarted reserved ceiling")
    updated = BudgetLease(lease.lease_id, lease.parent_id, lease.bot_id, lease.persona_id, lease.currency,
        lease.limits, lease.used, _minus(lease.reserved, ceiling), lease.unconfirmed, lease.version + 1, lease.state)
    _save_lease(db, updated)
    db.execute("UPDATE runtime_budget_reservations SET state='cancelled_unstarted' WHERE lease_id=? AND operation_id=?",
        (lease.lease_id, binding.reservation_operation_id))
    receipt = _receipt(updated, "cancelled_unstarted", binding.reservation_operation_id, binding.reservation_digest)
    _record(db, updated, binding.reservation_operation_id, "cancel_unstarted", binding.reservation_digest, receipt,
        resolution_binding=proof_binding)
    return receipt


def settle_budget_partial(
    db, lease_id: str, operation_id: str, digest: str,
    known_actual: Mapping[str, int], unknown_dimensions: tuple[str, ...], *,
    execution_revoked: bool,
) -> BudgetReceipt:
    """Settle measured dimensions while holding each unmeasured upper bound."""
    _identifier(operation_id, "operation_id")
    _digest(digest)
    lease = get_budget_lease(db, lease_id)
    prior = _prior(db, lease, operation_id, "settle", digest)
    if prior is not None:
        row = _numeric_accounting_budget_point_v3(db,table='runtime_budget_reservations',columns=('ceiling_json','actual_json','state'),
        key_columns=('lease_id','operation_id'),key=(lease_id,operation_id),legacy_reader=lambda:db.execute(
            "SELECT ceiling_json,actual_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?", (lease_id, operation_id),
        ).fetchone())
        if (row is None or prior.status not in {
                "pending_confirmation", "pending_overrun"}
                or row[2] not in {"partial_unknown", "partial_overrun",
                                   "settled", "overrun"}
                or set(unknown_dimensions) != set(json.loads(row[0])) - set(known_actual)
                or any(json.loads(row[1]).get(key) != value
                       for key, value in known_actual.items())):
            raise BudgetConflict("replayed partial cost differs from original")
        return prior
    row = _numeric_accounting_budget_point_v3(db,table='runtime_budget_reservations',columns=('digest','ceiling_json','state'),
        key_columns=('lease_id','operation_id'),key=(lease_id,operation_id),legacy_reader=lambda:db.execute(
        "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (lease_id, operation_id),
    ).fetchone())
    if row is None or row[0] != digest or row[2] != "reserved":
        raise BudgetConflict("no settleable original budget reservation")
    ceiling = _amounts(json.loads(row[1]), allow_empty=False)
    updated, status, actual_json, reservation_state = _partial_transition(
        lease, ceiling, known_actual, unknown_dimensions, execution_revoked)
    _save_lease(db, updated)
    db.execute(
        "UPDATE runtime_budget_reservations SET state=?,actual_json=? "
        "WHERE lease_id=? AND operation_id=?",
        (reservation_state, actual_json, lease_id, operation_id),
    )
    receipt = _receipt(updated, status, operation_id, digest)
    _record(db, updated, operation_id, "settle", digest, receipt)
    if status == "pending_overrun":
        _record_debt_block(db, lease_id, operation_id)
    return receipt


def resolve_partial_budget(
    db, lease_id: str, original_operation_id: str,
    resolution_operation_id: str, digest: str,
    newly_known_actual: Mapping[str, int], *, execution_revoked: bool,
) -> BudgetReceipt:
    """Resolve only previously unknown dimensions; never charge known ones twice."""
    _identifier(original_operation_id, "original_operation_id")
    _identifier(resolution_operation_id, "resolution_operation_id")
    _digest(digest)
    binding = _resolution_binding(
        original_operation_id, newly_known_actual, execution_revoked)
    lease = get_budget_lease(db, lease_id)
    prior = _prior(db, lease, resolution_operation_id, "resolve", digest,
                   resolution_binding=binding)
    if prior is not None:
        return prior
    row = db.execute(
        "SELECT ceiling_json,state,actual_json FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (lease_id, original_operation_id),
    ).fetchone()
    if row is None or row[1] not in {"partial_unknown", "partial_overrun"}:
        raise BudgetConflict("reservation is not partially unconfirmed")
    ceiling = _amounts(json.loads(row[0]), allow_empty=False)
    known = json.loads(row[2])
    unknown = set(ceiling) - set(known)
    if set(newly_known_actual) != unknown:
        raise BudgetConflict("resolution may name only unknown dimensions")
    charged = _amounts(newly_known_actual)
    if (not execution_revoked and any(
            newly_known_actual[dimension] < ceiling[dimension]
            for dimension in unknown)):
        raise BudgetUnavailable("unused unknown ceiling requires revoked execution authority")
    status = ("overrun" if row[1] == "partial_overrun" or any(
        newly_known_actual[dimension] > ceiling[dimension]
        for dimension in unknown) else "settled")
    updated = BudgetLease(
        lease.lease_id, lease.parent_id, lease.bot_id, lease.persona_id,
        lease.currency, lease.limits, _plus(lease.used, charged), lease.reserved,
        _minus(lease.unconfirmed, {
            dimension: ceiling[dimension] for dimension in unknown}),
        lease.version + 1, lease.state,
    )
    _save_lease(db, updated)
    _propagate_closed_resolution(
        db, lease, {dimension: ceiling[dimension] for dimension in unknown},
        charged,
    )
    db.execute(
        "UPDATE runtime_budget_reservations SET state=?,actual_json=? "
        "WHERE lease_id=? AND operation_id=?",
        (status, json.dumps(dict(sorted({**known, **newly_known_actual}.items())),
                            separators=(",", ":")), lease_id, original_operation_id),
    )
    receipt = _receipt(updated, status, resolution_operation_id, digest)
    _record(db, updated, resolution_operation_id, "resolve", digest, receipt,
            resolution_binding=binding)
    if status == "overrun":
        _record_debt_block(db, lease_id, original_operation_id)
    return receipt


def resolve_unconfirmed(db, lease_id: str, original_operation_id: str,
                        resolution_operation_id: str, digest: str,
                        actual: Mapping[str, int] | None,
                        *, execution_revoked: bool) -> BudgetReceipt:
    _identifier(original_operation_id, "original_operation_id")
    _identifier(resolution_operation_id, "resolution_operation_id")
    _digest(digest)
    if actual is None:
        raise BudgetUnavailable("actual cost remains unknown")
    binding = _resolution_binding(original_operation_id, actual, execution_revoked)
    lease = get_budget_lease(db, lease_id)
    prior = _prior(db, lease, resolution_operation_id, "resolve", digest,
                   resolution_binding=binding)
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
    if any(dimension not in lease.limits for dimension in charged):
        raise BudgetUnavailable("resolved cost uses an undeclared lease dimension")
    if any(charged.get(dimension, 0) < amount
           for dimension, amount in ceiling.items()) and not execution_revoked:
        raise BudgetUnavailable("unused unknown ceiling requires revoked execution authority")
    status = ("overrun" if any(amount > ceiling.get(dimension, 0)
                               for dimension, amount in charged.items())
              else "settled")
    updated = BudgetLease(
        lease.lease_id, lease.parent_id, lease.bot_id, lease.persona_id,
        lease.currency, lease.limits, _plus(lease.used, charged), lease.reserved,
        _minus(lease.unconfirmed, ceiling), lease.version + 1, lease.state,
    )
    _save_lease(db, updated)
    _propagate_closed_resolution(db, lease, ceiling, charged)
    db.execute(
        "UPDATE runtime_budget_reservations SET state=?,actual_json=? "
        "WHERE lease_id=? AND operation_id=?",
        (status, _json(charged), lease_id, original_operation_id),
    )
    receipt = _receipt(updated, status, resolution_operation_id, digest)
    _record(db, updated, resolution_operation_id, "resolve", digest, receipt,
            resolution_binding=binding)
    if status == "overrun":
        _record_debt_block(db, lease_id, original_operation_id)
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
    "install_schema", "predict_budget_partial_settlement",
    "predict_budget_settlement", "require_budget_family_admissible",
    "reserve_budget", "resolve_partial_budget",
    "resolve_unconfirmed", "settle_budget", "settle_budget_partial",
    "cancel_unstarted_offline_reservation_v1",
]
