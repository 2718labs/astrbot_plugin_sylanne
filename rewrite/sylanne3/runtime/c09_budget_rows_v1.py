"""Closed content-free ledger rows for this installation's budget units."""
from dataclasses import fields
import json

from .budget import BudgetLease, BudgetReceipt, BudgetReservation, _identifier, _digest, install_schema as install_budget_schema
from ..runtime_contracts import canonical_serialize, canonical_digest

TABLES = frozenset({"runtime_budget_leases", "runtime_budget_reservations", "runtime_budget_operations", "runtime_budget_debt_blocks"})
UNITS = frozenset({"cpu_ms", "thread_cpu_ms", "input_tokens", "output_tokens", "model_tokens", "model_microusd"})
CAPABILITY_DIGEST_V1 = canonical_digest(("sylanne3.c09.closed-budget-units.v1", tuple(sorted(UNITS))))
COLUMNS = {
    "runtime_budget_leases": ("lease_id", "parent_id", "bot_id", "persona_id", "currency", "limits_json", "used_json", "reserved_json", "unconfirmed_json", "version", "state"),
    "runtime_budget_reservations": ("lease_id", "operation_id", "digest", "ceiling_json", "state", "actual_json"),
    "runtime_budget_operations": ("bot_id", "persona_id", "operation_id", "phase", "digest", "lease_id", "receipt_json", "resolution_binding_json"),
    "runtime_budget_debt_blocks": ("lease_id", "cause_lease_id", "cause_operation_id"),
}


def _json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("budget original has duplicate fields")
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite budget original")))
    if canonical_serialize(value) != raw:
        raise ValueError("budget original JSON differs from fixed canonical wire")
    return value


def _amounts(raw):
    if type(raw) is not dict or not set(raw) <= UNITS or any(type(value) is not int or value < 0 for value in raw.values()):
        raise ValueError("unclassified installed budget unit/amount")
    return raw


def validate_c09_budget_row_v1(table, columns, row):
    if table not in COLUMNS or tuple(columns) != COLUMNS[table] or len(row) != len(columns):
        raise ValueError("budget installed fixed row columns differ")
    if table == "runtime_budget_leases":
        amounts = tuple(_amounts(_json(raw)) for raw in row[5:9])
        BudgetLease(*row[:5], *amounts, *row[9:])
        if type(row[9]) is not int or row[9] < 1:
            raise ValueError("budget passive lease version must be an exact positive int")
    elif table == "runtime_budget_reservations":
        ceiling = _amounts(_json(row[3]))
        # BudgetReservation is a live settleable DTO. A persisted terminal
        # audit row must never be reconstituted as spending permission.
        _identifier(row[0], "budget lease"); _identifier(row[1], "budget operation"); _digest(row[2])
        if not ceiling or any(amount < 1 for amount in ceiling.values()):
            raise ValueError("budget original reservation ceiling differs")
        if row[4] not in {"reserved", "unknown", "partial_unknown", "partial_overrun", "settled", "overrun", "cancelled_unstarted"}:
            raise ValueError("budget reservation has unknown accounting state")
        actual = None if row[5] is None else _amounts(_json(row[5]))
        if ((row[4] in {"reserved", "unknown", "cancelled_unstarted"}) != (actual is None)
                or actual is not None and not set(actual) <= set(ceiling)):
            raise ValueError("budget reservation state/actual partition differs")
        if actual is not None:
            overrun = any(amount > ceiling[unit] for unit, amount in actual.items())
            if (overrun != (row[4] in {"overrun", "partial_overrun"})
                    or row[4] in {"partial_unknown", "partial_overrun"} and not set(ceiling) - set(actual)):
                raise ValueError("budget persisted reservation terminal conservation/state differs")
    elif table == "runtime_budget_operations":
        raw = _json(row[6])
        if type(raw) is not dict or set(raw) != {field.name for field in fields(BudgetReceipt)}:
            raise ValueError("budget immutable receipt fields differ")
        for name in ("used", "reserved", "unconfirmed"):
            _amounts(raw[name])
        receipt = BudgetReceipt(**raw)
        phases = {"create": {"created"}, "reserve": {"reserved"}, "settle": {"settled", "overrun", "pending_confirmation", "pending_overrun"},
            "resolve": {"settled", "overrun"}, "close": {"closed"}, "cancel_unstarted": {"cancelled_unstarted"}}
        if ((receipt.operation_id, receipt.digest, receipt.lease_id) != (row[2], row[4], row[5])
                or row[3] not in phases or receipt.status not in phases[row[3]]
                or type(receipt.version) is not int or receipt.version < 1):
            raise ValueError("budget immutable operation/receipt identity differs")
        if row[3] == "cancel_unstarted":
            if row[7] is None:
                raise ValueError("unstarted cancellation lacks its durable no-future-claim binding")
            binding = _json(row[7])
            if (type(binding) is not dict or set(binding) != {"schema", "binding_digest", "accounting_original_digest",
                    "claim_gate_id", "no_future_claim_digest", "cancellation_gate_digest", "ceiling"}
                    or binding["schema"] != "d11.unstarted-reservation-cancellation-binding.v1"):
                raise ValueError("unstarted cancellation proof binding differs")
            for name in ("binding_digest", "accounting_original_digest", "no_future_claim_digest", "cancellation_gate_digest"):
                _digest(binding[name])
            _identifier(binding["claim_gate_id"], "original offline claim gate")
            if not _amounts(binding["ceiling"]) or any(amount < 1 for amount in binding["ceiling"].values()):
                raise ValueError("unstarted cancellation must release its original positive ceiling")
        elif row[7] is not None:
            binding = _json(row[7])
            expected = {"actual", "execution_revoked"} if row[3] == "settle" else {"original_operation_id", "actual", "execution_revoked"}
            if type(binding) is not dict or set(binding) != expected or row[3] not in {"settle", "resolve"}:
                raise ValueError("budget resolution binding fields differ")
            if row[3] == "resolve":
                _identifier(binding["original_operation_id"], "original budget operation")
            if binding["actual"] is not None:
                _amounts(binding["actual"])
            elif row[3] == "resolve":
                raise ValueError("budget resolution cannot invent an unknown actual")
            if type(binding["execution_revoked"]) is not bool:
                raise ValueError("budget resolution binding phase differs")
    else:
        for value in row:
            _identifier(value, "budget debt identity")
    return row


def validate_c09_budget_schema_v1(db):
    from contextlib import closing
    import sqlite3
    with closing(sqlite3.connect(":memory:", isolation_level=None)) as expected:
        install_budget_schema(expected)
        for table in TABLES:
            actual = tuple(db.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name", (table,)))
            desired = tuple(expected.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name", (table,)))
            if actual != desired:
                raise ValueError("budget installed immutable schema differs")
