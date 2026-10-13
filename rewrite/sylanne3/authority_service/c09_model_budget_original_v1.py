"""Fixed, content-free per-unit model obligations from real frozen originals."""
from dataclasses import asdict, dataclass, fields
import json

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest, canonical_serialize

_MODEL_PROVIDER_SCOPE_ISSUER_V3 = object()

TABLE = "authority_c09_model_budget_originals_v1"
DDL = f"CREATE TABLE {TABLE}(namespace TEXT NOT NULL,operation_id TEXT NOT NULL,call_id TEXT NOT NULL,original_json TEXT NOT NULL,original_digest TEXT NOT NULL,PRIMARY KEY(namespace,operation_id,call_id))"
UNITS = frozenset({"input_tokens", "output_tokens", "model_tokens", "model_microusd"})
MODEL_TABLES = (
    "authority_model_egress_v1", "authority_model_egress_bindings_v1", "authority_model_egress_observations_v1",
    "authority_model_egress_observation_status_v1", "authority_model_admissions_v2", "authority_model_original_identity_v2",
)
MODEL_COLUMNS = {
    "authority_model_egress_v1": ("call_id", "operation_id", "namespace", "subject", "identity_json", "state", "observation_digest"),
    "authority_model_egress_bindings_v1": ("call_id", "operation_id", "token"),
    "authority_model_egress_observations_v1": ("call_id", "observation_json", "observation_digest"),
    "authority_model_egress_observation_status_v1": ("call_id", "observation_digest", "status", "usage_json", "cost_json", "content_erased"),
    "authority_model_admissions_v2": ("call_id", "admission_id", "admission_json", "report_digest", "receipt_json"),
    "authority_model_original_identity_v2": ("call_id", "authority_id", "installation_id", "namespace", "job_id", "acquire_operation_id", "operation_id", "request_digest", "binding_digest"),
}


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AuthorityUnavailable("C09 model original duplicate field")
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(AuthorityUnavailable("C09 model original nonfinite value")))
    if canonical_serialize(result) != raw:
        raise AuthorityUnavailable("C09 model original noncanonical JSON")
    return result


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


@dataclass(frozen=True, slots=True)
class C09ModelUnitObligationV1:
    unit: str
    ceiling: int
    actual_or_none: int | None
    settled: int
    pending_known: int
    debt: int
    unknown_upper_bound: int
    settlement_id_or_none: str | None

    def __post_init__(self):
        if (self.unit not in UNITS or any(type(getattr(self, name)) is not int or getattr(self, name) < 0
                for name in ("ceiling", "settled", "pending_known", "debt", "unknown_upper_bound"))
                or self.ceiling < 1):
            raise AuthorityUnavailable("C09 model obligation fixed unit/amount differs")
        if self.actual_or_none is None:
            if (self.settled or self.pending_known or self.debt or self.unknown_upper_bound != self.ceiling):
                raise AuthorityUnavailable("C09 unknown model amount cannot be zero actual")
        elif (type(self.actual_or_none) is not int or self.actual_or_none < 0
                or self.settled + self.pending_known != self.actual_or_none
                or self.debt != max(0, self.actual_or_none - self.ceiling) or self.unknown_upper_bound):
            raise AuthorityUnavailable("C09 known model amount conservation differs")
        if self.settlement_id_or_none is not None and (type(self.settlement_id_or_none) is not str or not self.settlement_id_or_none):
            raise AuthorityUnavailable("C09 model settlement identity differs")


@dataclass(frozen=True, slots=True)
class C09ModelBudgetOriginalV1:
    authority_id: str
    installation_id: str
    namespace: str
    operation_id: str
    call_id: str
    model_operation_id: str
    job_id: str
    acquire_operation_id: str
    admission_id_or_none: str | None
    request_digest: str
    binding_digest: str
    provider_id: str
    provider_query_ref_or_none: str | None
    provider_state: str
    dispatch_generation: int
    originating_journal_id: str
    original_execution_seq: int
    original_execution_digest: str
    parent_budget_id: str
    reservation_operation_id: str
    reservation_digest: str
    reservation_state: str
    quote_id: str
    quote_version: int
    quote_digest: str
    observation_digest_or_none: str | None
    terminal_digest_or_none: str | None
    source_row_commitments: tuple[str, ...]
    units: tuple[C09ModelUnitObligationV1, ...]
    original_digest: str
    schema: str = "sylanne3.c09.model-budget-original.v1"

    def __post_init__(self):
        for name in ("authority_id", "installation_id", "namespace", "operation_id", "call_id", "model_operation_id",
                "job_id", "acquire_operation_id", "provider_id", "originating_journal_id", "parent_budget_id", "reservation_operation_id", "quote_id"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise AuthorityUnavailable("C09 model obligation identity absent")
        if (self.schema != "sylanne3.c09.model-budget-original.v1"
                or self.provider_state not in {"prepared", "dispatch_started", "observed", "unknown"}
                or self.reservation_state not in {"reserved", "settled", "overrun", "unknown", "partial_unknown", "partial_overrun"}
                or type(self.dispatch_generation) is not int or self.dispatch_generation < 1
                or type(self.original_execution_seq) is not int or self.original_execution_seq < 0
                or type(self.quote_version) is not int or self.quote_version < 1
                or self.original_execution_seq == 0 and self.original_execution_digest != "genesis"
                or self.original_execution_seq > 0 and not _digest(self.original_execution_digest.removeprefix("sha256:"))):
            raise AuthorityUnavailable("C09 model obligation fixed state/head differs")
        for name in ("request_digest", "binding_digest", "reservation_digest", "quote_digest", "original_digest"):
            if not _digest(getattr(self, name)):
                raise AuthorityUnavailable("C09 model obligation commitment differs")
        for value in (self.observation_digest_or_none, self.terminal_digest_or_none):
            if value is not None and not _digest(value):
                raise AuthorityUnavailable("C09 model original terminal commitment differs")
        if self.provider_query_ref_or_none is not None and (
                type(self.provider_query_ref_or_none) is not str or not self.provider_query_ref_or_none
                or len(self.provider_query_ref_or_none) > 256
                or self.observation_digest_or_none is None):
            raise AuthorityUnavailable("C09 model passive provider query identity differs")
        if (type(self.source_row_commitments) is not tuple or not self.source_row_commitments
                or self.source_row_commitments != tuple(sorted(set(self.source_row_commitments)))
                or not all(_digest(item) for item in self.source_row_commitments)
                or type(self.units) is not tuple or not self.units
                or not all(type(item) is C09ModelUnitObligationV1 for item in self.units)
                or tuple(item.unit for item in self.units) != tuple(sorted({item.unit for item in self.units}))):
            raise AuthorityUnavailable("C09 model exact original/unit inventory differs")
        if self.provider_state in {"prepared", "dispatch_started"} and (self.observation_digest_or_none or self.terminal_digest_or_none):
            raise AuthorityUnavailable("C09 model unobserved state has fabricated terminal")
        if canonical_digest(tuple(getattr(self, f.name) for f in fields(self) if f.name != "original_digest")) != self.original_digest:
            raise AuthorityUnavailable("C09 model obligation original digest differs")


def model_budget_original_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(C09ModelBudgetOriginalV1)}:
        raise AuthorityUnavailable("C09 model original fields differ")
    value = dict(raw)
    value["source_row_commitments"] = tuple(value["source_row_commitments"])
    value["units"] = tuple(C09ModelUnitObligationV1(**item) for item in value["units"])
    return C09ModelBudgetOriginalV1(**value)


def install_c09_model_budget_schema_v1(db):
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone()
    if row is None:
        db.execute(DDL)
    elif row != (DDL,):
        raise AuthorityUnavailable("C09 model fixed original schema differs")
    for action in ("UPDATE", "DELETE"):
        name = TABLE + "_no_" + action.lower()
        sql = f"CREATE TRIGGER {name} BEFORE {action} ON {TABLE} BEGIN SELECT RAISE(ABORT,'C09 model obligation immutable'); END"
        row = db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone()
        if row is None:
            db.execute(sql)
        elif row != (sql,):
            raise AuthorityUnavailable("C09 model immutable original trigger differs")


def validate_c09_model_budget_row_v1(columns, row):
    if tuple(columns) != ("namespace", "operation_id", "call_id", "original_json", "original_digest"):
        raise AuthorityUnavailable("C09 model original columns differ")
    result = model_budget_original_from_wire_v1(_json(row[3]))
    if row[:3] != (result.namespace, result.operation_id, result.call_id) or row[4] != result.original_digest:
        raise AuthorityUnavailable("C09 model original row identity differs")
    return result


def validate_model_core_row_v1(table, columns, row):
    from .v2_model_egress_store import _decoded, _decoded_observation
    from .v2_model_egress_contract import ModelAdmissionV2, ModelTerminalReceiptV2
    if table not in MODEL_COLUMNS or tuple(columns) != MODEL_COLUMNS[table] or len(row) != len(columns):
        raise AuthorityUnavailable("C09 model Core row columns differ")
    if type(row[0]) is not str or not row[0]:
        raise AuthorityUnavailable("C09 model call identity absent")
    if table == "authority_model_egress_v1":
        intent = _decoded(row[4])
        if (row[:4] != (intent.call_id, intent.operation_id, intent.namespace, intent.subject)
                or row[5] not in {"prepared", "dispatch_started", "observed", "unknown"}
                or ((row[5] in {"observed", "unknown"}) != (row[6] is not None))
                or row[6] is not None and not _digest(row[6])):
            raise AuthorityUnavailable("C09 model intent/state row differs")
    elif table == "authority_model_egress_observations_v1":
        observation = _decoded_observation(row[1])
        if (row[0], row[2]) != (observation.call_id, observation.digest):
            raise AuthorityUnavailable("C09 model original response commitment differs")
    elif table == "authority_model_egress_observation_status_v1":
        if (not _digest(row[1]) or row[2] not in {"completed", "unknown"}
                or type(row[5]) is not int or row[5] not in {0, 1}):
            raise AuthorityUnavailable("C09 model usage status differs")
        for encoded in row[3:5]:
            amounts = _json(encoded)
            if (type(amounts) is not list or amounts != sorted(amounts)
                    or len({item[0] for item in amounts}) != len(amounts)):
                raise AuthorityUnavailable("C09 model fixed usage vector differs")
            for item in amounts:
                if (type(item) is not list or len(item) != 2 or item[0] not in UNITS | {"cached_input_tokens"}
                        or type(item[1]) is not int or item[1] < 0):
                    raise AuthorityUnavailable("C09 model usage vector unit/amount differs")
    elif table == "authority_model_admissions_v2":
        admission = ModelAdmissionV2(**_json(row[2]))
        if row[:2] != (admission.call_id, admission.admission_id) or (row[3] is None) != (row[4] is None):
            raise AuthorityUnavailable("C09 model actual admission row differs")
        if row[4] is not None:
            terminal = ModelTerminalReceiptV2(**_json(row[4]))
            if (terminal.call_id, terminal.admission_id, terminal.report_digest, terminal.request_digest,
                    terminal.installation_id, terminal.host_incarnation) != (
                    row[0], row[1], row[3], admission.request_digest, admission.installation_id, admission.host_incarnation):
                raise AuthorityUnavailable("C09 model terminal/admission row differs")
    elif table == "authority_model_original_identity_v2":
        if any(type(value) is not str or not value for value in row) or not all(_digest(value) for value in row[-2:]):
            raise AuthorityUnavailable("C09 model original identity row differs")
    else:
        from .v2_contract import _TOKEN
        if type(row[1]) is not str or not row[1] or type(row[2]) is not str or not _TOKEN.fullmatch(row[2]):
            raise AuthorityUnavailable("C09 model passive fence audit binding differs")
    return row[0]


def read_model_audit_metadata_v1(db, call_id):
    """Passive audit only; never return response bytes or an active permit."""
    from .v2_model_egress_store import _decoded
    from .v2_model_egress_contract import ModelEgressRecoveryV1
    row = db.execute("SELECT * FROM authority_model_egress_v1 WHERE call_id=?", (call_id,)).fetchone()
    if row is None:
        return None
    validate_model_core_row_v1("authority_model_egress_v1", MODEL_COLUMNS["authority_model_egress_v1"], row)
    intent = _decoded(row[4])
    status = db.execute("SELECT * FROM authority_model_egress_observation_status_v1 WHERE call_id=?", (call_id,)).fetchone()
    if row[5] in {"observed", "unknown"}:
        if status is None:
            raise AuthorityUnavailable("C09 model audit usage original absent")
        validate_model_core_row_v1("authority_model_egress_observation_status_v1", MODEL_COLUMNS["authority_model_egress_observation_status_v1"], status)
        if status[1:3] != (row[6], "completed" if row[5] == "observed" else "unknown"):
            raise AuthorityUnavailable("C09 model audit state/observation differs")
        return ModelEgressRecoveryV1(intent, row[5], row[6], tuple(tuple(item) for item in _json(status[3])),
            tuple(tuple(item) for item in _json(status[4])), bool(status[5]))
    if status is not None:
        raise AuthorityUnavailable("C09 unobserved model audit has fabricated usage")
    return ModelEgressRecoveryV1(intent, row[5])


def read_authenticated_model_budget_original_in_tx_v1(db, *, namespace, call_id, context):
    """Core-only join after the caller qualified current applied context outside SQL.

    This function never invokes Graph, an applied reader or an RPC. The short
    protected control-pointer read rechecks the already minted exact context.
    """
    from pathlib import Path
    from .c09_storage_control_v1 import VerifiedStorageOpenContextV1
    from .erasure_recovery_pin_v4 import read_execution_recovery_facts_v4_locked, read_execution_recovery_facts_pin_v4_locked
    from .c09_recovery_resolver_v4 import read_recovery_bindings_v1_locked
    if (not db.in_transaction or type(context) is not VerifiedStorageOpenContextV1
            or context.stage != "RELEASED" or context.prepared_original is None
            or context._capability is not context._reader._capability):
        raise AuthorityUnavailable("C09 current qualified model accounting context required")
    member = next(item for item in context.manifest["members"] if item["role"] == "core")
    path = db.execute("PRAGMA database_list").fetchone()[2]
    if Path(path).resolve() != Path(member["resolved_path"]).resolve():
        raise AuthorityUnavailable("C09 model accounting Core is not selected current storage")
    originals = {}
    with context._reader._db() as control:
        pointer = context._reader._current(control)
        if (pointer["pointer_version"], pointer["current_manifest_digest"], pointer["stage"]) != (
                context.pointer_version, context.manifest_digest, "RELEASED"):
            raise AuthorityUnavailable("C09 model accounting context pointer expired")
        for (encoded,) in control.execute("SELECT prepared_original_json FROM c09_storage_operations_v1 WHERE installation_id=? AND generation<=? ORDER BY generation",
                (context._reader.installation_id, context.storage_generation)):
            original = json.loads(encoded); context._reader.verify_original_v1(original, "prepared_digest")
            if original["namespace"] == namespace:
                originals[original["operation_id"]] = original
    columns = tuple(item[1] for item in db.execute(f"PRAGMA table_info({TABLE})"))
    rows = db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND call_id=?", (namespace, call_id)).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise AuthorityUnavailable("C09 model accounting consumed call appears in multiple original frames")
    model = validate_c09_model_budget_row_v1(columns, rows[0])
    original = originals.get(model.operation_id)
    facts = read_execution_recovery_facts_v4_locked(db, namespace, operation_id=model.operation_id)
    pin = read_execution_recovery_facts_pin_v4_locked(db, namespace, operation_id=model.operation_id)
    bindings = read_recovery_bindings_v1_locked(db, namespace=namespace, operation_id=model.operation_id)
    if (original is None or facts is None or pin is None or bindings is None
            or original["facts_digest"] != facts.facts_digest or original["facts_pin_original"] != asdict(pin)
            or original["recovery_bindings_digest"] != bindings.bindings_digest):
        raise AuthorityUnavailable("C09 model accounting original is outside authenticated storage frames")
    matches = tuple(item for item in bindings.execution_bindings if item.execution_id == call_id)
    executions = tuple(item for item in facts.executions if item.execution_id == call_id)
    units = tuple(model_unit_fact_v4(model, item) for item in model.units if item.actual_or_none is not None)
    if (len(matches) != 1 or len(executions) != 1 or matches[0].execution_kind != "model"
            or executions[0].signature_commitment != model.original_digest
            or executions[0].input_commitment != model.request_digest
            or matches[0].business_operation_id != model.model_operation_id
            or matches[0].source_row_commitments != tuple(sorted({*model.source_row_commitments, model.original_digest}))
            or matches[0].d11_settlement_ids != tuple(sorted(item.settlement_id for item in units))
            or any(item not in facts.d11_facts for item in units)):
        raise AuthorityUnavailable("C09 model accounting original/facts/business binding differs")
    for kind, identity in (("model_call", call_id), ("model_operation", model.model_operation_id),
            ("model_job", model.job_id), ("model_acquire", model.acquire_operation_id), ("model_admission", model.admission_id_or_none)):
        if identity is not None and db.execute("SELECT original_commitment,facts_pin_digest FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind=? AND item_id=?",
                (namespace, kind, identity)).fetchone() != (model.original_digest, pin.pin_digest):
            raise AuthorityUnavailable("C09 model accounting irreversible consumed key differs")
    if db.execute("SELECT 1 FROM authority_model_egress_observations_v1 WHERE call_id=?", (call_id,)).fetchone():
        raise AuthorityUnavailable("C09 model consumed response body still survives")
    return model


def _model_compat_reader_v1(db, meter):
    """Borrow the installed quantum; no compatibility call creates a budget."""
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2, C09PagedCaptureHold
    from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
    if meter is not current_c09_sql_meter_v2():
        raise AuthorityUnavailable("C09 legacy model reader crossed its actual reserved quantum")
    reader = _BoundedReadConnectionV2(db, meter)
    retained = 0
    def preread(size):
        nonlocal retained
        # Bodies, decoded values and canonical copies share this actual arena.
        meter.require_available(size * 7)
        retained += size * 8
        if retained > meter.budget.reserved_arena_bytes:
            raise C09PagedCaptureHold("C09 legacy model inventory needs the sealed V2 stream")
    reader._natural_preflight_v3 = preread
    return reader


def _complete_model_keys_v1(reader, *, table, where, args, columns, order, meter):
    """A single complete compatibility page, with the tail observed before bodies."""
    from time import monotonic_ns
    from ..runtime.c09_paged_sql_v2 import C09PagedCaptureHold
    keys = []
    cursor = reader.execute(f"SELECT {columns} FROM {table} WHERE {where} ORDER BY {order} LIMIT ?",
        (*args, meter.budget.max_records + 1))
    for key in cursor:
        if len(keys) == meter.budget.max_records:
            raise C09PagedCaptureHold("C09 legacy model inventory exceeds one complete page; use sealed V2")
        if monotonic_ns() - meter.started_ns > meter.budget.max_local_ns:
            raise C09PagedCaptureHold("C09 legacy model inventory exceeded its actual reserved duration")
        keys.append(key)
    return tuple(keys)


def read_model_budget_originals_v1(db, *, namespace, operation_id, meter):
    """Return the whole V1 frame only when its EOF fits the caller's real quantum."""
    from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2
    with legacy_cell_read_transaction_v2(db):
        reader = _model_compat_reader_v1(db, meter)
        columns = tuple(item[1] for item in reader.execute(f"PRAGMA table_info({TABLE})"))
        keys = _complete_model_keys_v1(reader, table=TABLE,
            where="namespace=? AND operation_id=?", args=(namespace, operation_id),
            columns="call_id", order="call_id COLLATE BINARY", meter=meter)
        return tuple(validate_c09_model_budget_row_v1(columns, reader.execute(
            f"SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=? AND call_id=?",
            (namespace, operation_id, key[0])).fetchone()) for key in keys)


def read_model_budget_original_v1(db, *, namespace, operation_id, call_id, meter):
    """Exact archived call; historical frame authentication belongs to the caller."""
    from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2
    with legacy_cell_read_transaction_v2(db):
        reader = _model_compat_reader_v1(db, meter)
        columns = tuple(item[1] for item in reader.execute(f"PRAGMA table_info({TABLE})"))
        row = reader.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=? AND call_id=?",
            (namespace, operation_id, call_id)).fetchone()
        return None if row is None else validate_c09_model_budget_row_v1(columns, row)


def model_unit_fact_v4(original, unit):
    from ..runtime.c09_storage_rebase_contract_v1 import SanitizedD11FactV4
    if unit.actual_or_none is None:
        raise AuthorityUnavailable("C09 unknown model amount has no actual-cost fact")
    identity = "model-unit:" + canonical_digest((unit.unit, original.call_id, original.parent_budget_id,
        original.reservation_operation_id, unit.settlement_id_or_none))[:48]
    return SanitizedD11FactV4(identity, original.parent_budget_id, original.reservation_operation_id,
        unit.ceiling, unit.actual_or_none, unit.settled, unit.pending_known, unit.debt, unit.unit)


def require_model_budget_release_safe_v1(db, *, namespace, meter):
    from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2
    with legacy_cell_read_transaction_v2(db):
        reader = _model_compat_reader_v1(db, meter)
        columns = tuple(item[1] for item in reader.execute(f"PRAGMA table_info({TABLE})"))
        keys = _complete_model_keys_v1(reader, table=TABLE, where="namespace=?", args=(namespace,),
            columns="operation_id,call_id", order="operation_id COLLATE BINARY,call_id COLLATE BINARY", meter=meter)
        for operation, call in keys:
            row = reader.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=? AND call_id=?",
                (namespace, operation, call)).fetchone()
            original = validate_c09_model_budget_row_v1(columns, row)
            if (original.provider_state != "observed" or original.reservation_state not in {"settled", "overrun"}
                    or any(unit.actual_or_none is None or unit.pending_known or unit.unknown_upper_bound for unit in original.units)):
                raise AuthorityUnavailable("C09 model pending/unknown budget has no installed sanitized settlement consumer")


def require_model_identities_unconsumed_in_tx_v1(db, *, namespace, call_id, operation_id, job_id=None,
        acquire_operation_id=None, admission_id=None):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_c09_consumed_execution_v1'").fetchone():
        return
    for kind, value in (("model_call", call_id), ("model_operation", operation_id), ("model_job", job_id),
                        ("model_acquire", acquire_operation_id), ("model_admission", admission_id)):
        if value is not None and db.execute("SELECT 1 FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind=? AND item_id=?",
                (namespace, kind, value)).fetchone():
            raise AuthorityUnavailable("already_consumed:" + kind + ":" + value)


def read_frozen_model_budget_original_v2(*, core_db, business, namespace_id, seal,
        resource_issuer, call_id, budget_job_issuer=None, _natural_proof=None, _provider_scope_sink=None):
    """Read one complete actual Core/Graph obligation without mutating either source.

    The caller owns the genuine installed freeze and bounded database reads.
    A missing or already-consumed call returns None; historical facts require
    their independently authenticated pin and are never reconstructed here.
    """
    from .v2_model_egress_store import AuthorityV2ModelEgressStore, _decoded_observation
    from .v2_model_egress_contract import ModelAdmissionV2, ModelTerminalReceiptV2
    from .v2_fence_store import AuthorityV2FenceStore
    from ..runtime.issuers import _decode_quote
    from ..runtime.jobs import get_job
    from ..runtime.budget import BudgetReceipt, get_budget_lease
    from ..runtime.d11_types import RuntimeCostSettlement, _strict_payload
    from ..runtime.model_cost_settlement import original_model_cost_operation_id_v1
    from ..graph_types import AtomKey
    if not core_db.in_transaction or not business.in_transaction:
        raise AuthorityUnavailable("C09 real frozen Core/Graph snapshots required")
    present = core_db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_model_egress_v1'").fetchone()
    if present is None:
        return None
    def commitment(db, table, row):
        columns = tuple(item[1] for item in db.execute(f"PRAGMA table_info({table})"))
        material = tuple({"blob_sha256": __import__('hashlib').sha256(value).hexdigest(), "size": len(value)}
                         if type(value) is bytes else value for value in row)
        return canonical_digest((table, columns, material))
    ledger = core_db.execute("SELECT * FROM authority_model_egress_v1 WHERE namespace=? AND call_id=?",
        (seal.namespace, call_id)).fetchone()
    if ledger is None:
        return None
    call = ledger[0]
    if core_db.execute("SELECT 1 FROM sqlite_master WHERE name='authority_c09_consumed_execution_v1'").fetchone() and core_db.execute(
            "SELECT 1 FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind='model_call' AND item_id=?", (seal.namespace, call)).fetchone():
        return None
    record = AuthorityV2ModelEgressStore._read(core_db, call)
    intent = record.intent
    fence_row = AuthorityV2FenceStore._row(core_db, intent.operation_id)
    if fence_row is None:
        raise AuthorityUnavailable("C09 real model original fence absent")
    permit = AuthorityV2FenceStore._permit(fence_row)
    if (intent.authority_id != seal.authority_id or intent.namespace != seal.namespace
            or intent.acquire_operation_id is None or intent.binding_digest is None
            or permit.operation != "model_egress" or permit.operation_id != intent.operation_id
            or (permit.subject, permit.namespace, permit.authority_id, permit.token, permit.fence_epoch, permit.revision,
                permit.generation, canonical_digest(asdict(permit.pinned_anchor))) !=
               (intent.subject, intent.namespace, intent.authority_id, intent.fence_token, intent.fence_epoch,
                intent.fence_revision, intent.authority_activation_generation, intent.anchor_digest)
            or permit.pinned_anchor.execution_journal_id != seal.execution_journal_id
            or permit.pinned_anchor.execution_seq != intent.authority_execution_seq
            or intent.authority_execution_seq > seal.execution_seq):
        raise AuthorityUnavailable("C09 model independent anchor/original identity differs")
    rows = {"authority_model_egress_v1": ledger, "authority_v2_fences": fence_row}
    binding = core_db.execute("SELECT * FROM authority_model_egress_bindings_v1 WHERE call_id=?", (call,)).fetchone()
    identity = core_db.execute("SELECT * FROM authority_model_original_identity_v2 WHERE call_id=?", (call,)).fetchone()
    if (binding != (call, intent.operation_id, intent.fence_token) or identity is None
            or identity[:2] != (call, seal.authority_id)
            or identity[3:] != (seal.namespace, intent.job_id, intent.acquire_operation_id, intent.operation_id,
                               intent.request_digest, intent.binding_digest)):
        raise AuthorityUnavailable("C09 model original binding row differs")
    installation = identity[2]
    rows["authority_model_egress_bindings_v1"], rows["authority_model_original_identity_v2"] = binding, identity
    admission_row = core_db.execute("SELECT * FROM authority_model_admissions_v2 WHERE call_id=?", (call,)).fetchone()
    admission = terminal = None
    if admission_row is not None:
        admission = ModelAdmissionV2(**_json(admission_row[2]))
        if (admission_row[:2] != (call, admission.admission_id)
                or (admission.authority_id, admission.namespace, admission.subject, admission.operation_id,
                    admission.call_id, admission.request_digest, admission.provider_config_digest, admission.installation_id) !=
                   (intent.authority_id, intent.namespace, intent.subject, intent.operation_id, call,
                    intent.request_digest, intent.provider_config_digest, installation)):
            raise AuthorityUnavailable("C09 real model admission differs")
        if admission_row[4] is not None:
            terminal = ModelTerminalReceiptV2(**_json(admission_row[4]))
            if (terminal.report_digest != admission_row[3] or (terminal.admission_id, terminal.call_id,
                    terminal.request_digest, terminal.observation_digest, terminal.installation_id,
                    terminal.host_incarnation) != (admission.admission_id, call, intent.request_digest,
                    record.observation_digest, installation, admission.host_incarnation)):
                raise AuthorityUnavailable("C09 actual model terminal/report binding differs")
        elif admission_row[3] is not None:
            raise AuthorityUnavailable("C09 model report lacks actual terminal")
        rows["authority_model_admissions_v2"] = admission_row
    if record.state != "prepared" and admission is None:
        raise AuthorityUnavailable("C09 legacy model send has no real admission original")
    provider_query_ref = None
    if record.state in {"observed", "unknown"}:
        status = core_db.execute("SELECT * FROM authority_model_egress_observation_status_v1 WHERE call_id=?", (call,)).fetchone()
        observation_row = core_db.execute("SELECT * FROM authority_model_egress_observations_v1 WHERE call_id=?", (call,)).fetchone()
        if observation_row is not None:
            observation = _decoded_observation(observation_row[1])
            if (observation.digest != record.observation_digest or observation_row[2] != observation.digest
                    or (observation.call_id, observation.operation_id, observation.namespace, observation.request_digest,
                        observation.usage, observation.cost) != (call, intent.operation_id, intent.namespace,
                        intent.request_digest, record.usage, record.cost)):
                raise AuthorityUnavailable("C09 model body/original observation differs")
            rows["authority_model_egress_observations_v1"] = observation_row
            provider_query_ref = observation.provider_call_ref
        rows["authority_model_egress_observation_status_v1"] = status
        if record.state == "observed" and terminal is None:
            raise AuthorityUnavailable("C09 model completion lacks original terminal")
    if fence_row[6] == "finished":
        status = {"prepared": "not_dispatched", "observed": "completed", "unknown": "unknown"}.get(record.state)
        expected = None if status is None else AuthorityV2FenceStore.model_terminal_finish_digest(intent, permit, status, record.observation_digest)
        if fence_row[8:11] != (call, expected, None) or terminal is not None and terminal.finish_digest != expected:
            raise AuthorityUnavailable("C09 model actual terminal fence differs")
    elif fence_row[6] != "active" or record.state in {"observed", "unknown"}:
        raise AuthorityUnavailable("C09 model original fence state differs")
    job = get_job(business, intent.job_id)
    if (job.bot_id, job.persona_id, job.budget_ref, job.fence) != (*namespace_id.as_tuple, intent.budget_lease_id, intent.worker_fence):
        raise AuthorityUnavailable("C09 actual model job/worker/budget differs")
    quote_rows = business.execute("SELECT quote_id,version,quote_json FROM runtime_resource_quotes WHERE "
        "json_extract(quote_json,'$.operation_id')=? AND json_extract(quote_json,'$.parent_budget_lease_ref')=? LIMIT 2",
        (intent.budget_reservation_operation_id, intent.budget_lease_id)).fetchall()
    if len(quote_rows) != 1:
        raise AuthorityUnavailable("C09 unique original signed model quote absent")
    quote = resource_issuer.original_signed_quote(business, quote_rows[0][0], quote_rows[0][1])
    if (quote != _decode_quote(quote_rows[0][2]) or (quote.bot_id, quote.persona_id) != namespace_id.as_tuple
            or dict(quote.ceiling) != dict(intent.budget_ceiling) or quote.work_kind != job.work_kind
            or quote.graph_job_ref != __import__('sylanne3.runtime.d11_types', fromlist=['runtime_job_key']).runtime_job_key(
                *namespace_id.as_tuple, job.activity_id, job.job_id).token):
        raise AuthorityUnavailable("C09 actual D02 signed model quote differs")
    ceiling = dict(intent.budget_ceiling)
    if not set(ceiling) <= UNITS:
        raise AuthorityUnavailable("C09 model installed cost unit is unsupported")
    reservation = business.execute("SELECT * FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (intent.budget_lease_id, intent.budget_reservation_operation_id)).fetchone()
    reserve = business.execute("SELECT * FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*namespace_id.as_tuple, intent.budget_reservation_operation_id)).fetchone()
    if (reservation is None or reservation[2] != intent.budget_reservation_digest or _json(reservation[3]) != ceiling
            or reserve is None or reserve[4:6] != (intent.budget_reservation_digest, intent.budget_lease_id)):
        raise AuthorityUnavailable("C09 real model reservation/reserve receipt differs")
    reserve_receipt = BudgetReceipt(**_json(reserve[6]))
    if (reserve_receipt.operation_id, reserve_receipt.digest, reserve_receipt.lease_id, reserve_receipt.status) != (
            intent.budget_reservation_operation_id, intent.budget_reservation_digest, intent.budget_lease_id, "reserved"):
        raise AuthorityUnavailable("C09 model original reserve receipt identity differs")
    lease = get_budget_lease(business, intent.budget_lease_id)
    if (lease.bot_id, lease.persona_id) != namespace_id.as_tuple:
        raise AuthorityUnavailable("C09 model original budget crosses namespace")
    source_commitments = [commitment(core_db, table, row) for table, row in rows.items()]
    for table, row in (("runtime_jobs", business.execute("SELECT * FROM runtime_jobs WHERE job_id=?", (job.job_id,)).fetchone()),
            ("runtime_budget_reservations", reservation), ("runtime_budget_operations", reserve),
            ("runtime_budget_leases", business.execute("SELECT * FROM runtime_budget_leases WHERE lease_id=?", (lease.lease_id,)).fetchone()),
            ("runtime_resource_quotes", business.execute("SELECT * FROM runtime_resource_quotes WHERE quote_id=? AND version=?", (quote.quote_id, quote.version)).fetchone())):
        source_commitments.append(commitment(business, table, row))
    if job.work_kind in {"natural_generation","natural_review"}:
        from .c09_natural_model_original_v3 import NaturalModelFrozenProofV3
        if type(_natural_proof) is not NaturalModelFrozenProofV3:
            raise AuthorityUnavailable("C09 natural model requires complete installed pre-mirror Graph proof")
        source_commitments.extend(_natural_proof.require_for(core=core_db,business=business,seal=seal,
            namespace_id=namespace_id,intent=intent,job=job,installation=installation,terminal=terminal))
    else:
        # Generic acquire, or the exact D04 appraisal driver acquire variant.
        acquire = business.execute("SELECT * FROM graph_job_acquire_intents_v2 WHERE bot=? AND persona=? AND acquire_operation_id=?",
            (*namespace_id.as_tuple, intent.acquire_operation_id)).fetchone()
        if acquire is not None:
            receipt = business.execute("SELECT * FROM graph_job_acquire_receipts_v2 WHERE bot=? AND persona=? AND acquire_operation_id=?",
                (*namespace_id.as_tuple, intent.acquire_operation_id)).fetchone()
            if acquire[4] != job.job_id or receipt is None or receipt[3] != acquire[3]:
                raise AuthorityUnavailable("C09 model real Graph acquire pair differs")
            source_commitments.extend((commitment(business, "graph_job_acquire_intents_v2", acquire), commitment(business, "graph_job_acquire_receipts_v2", receipt)))
        elif job.work_kind == "d04.appraisal":
            from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
            from ..runtime.c09_d04_originals_v3 import validate_d04_original_payload_v3
            prepared = read_d04_original_v3(business, namespace_id, "appraisal", job.job_id)
            original_call = read_d04_original_v3(business, namespace_id, "appraisal_call", job.job_id)
            if prepared is None or original_call is None or canonical_digest(original_call[0]) != canonical_digest(asdict(intent)):
                raise AuthorityUnavailable("C09 actual D04 appraisal acquire original absent")
            validate_d04_original_payload_v3("appraisal", prepared[0])
            if (prepared[0]["call_id"], prepared[0]["quote_id"], prepared[0]["quote_version"], prepared[0]["reservation_digest"]) != (
                    call, quote.quote_id, quote.version, intent.budget_reservation_digest):
                raise AuthorityUnavailable("C09 D04 appraisal accounting acquire differs")
            source_commitments.extend((prepared[1], original_call[1]))
        elif job.work_kind == "artifact_draft_v1":
            from ..runtime.issuers import D11BudgetJobIssuer
            from ..runtime.d11_life_preparation_v1 import _read as read_c4,TABLE as C4_TABLE
            from ..model_broker.artifact_draft_v1 import artifact_draft_from_wire_v1,ArtifactDraftTaskSelectorV1,artifact_draft_model_ids_v1
            from ..runtime.c09_life_originals_v1 import validate_c4_life_original_row_v1
            from ..runtime.natural_reply_job_v2 import _request_from_wire
            from .v2_model_egress_wire import to_wire
            if type(budget_job_issuer) is not D11BudgetJobIssuer or budget_job_issuer.resource_issuer is not resource_issuer:
                raise AuthorityUnavailable("C09 C4 needs the actual same installed original issuer; HOLD")
            if set(job.continuation)!={"schema","selector","prepared_digest"} or job.continuation["schema"]!="d11.artifact-draft-model-job.v1":
                raise AuthorityUnavailable("C09 C4 once job descriptor is not its closed variant")
            selector=artifact_draft_from_wire_v1(job.continuation["selector"],ArtifactDraftTaskSelectorV1)
            ids=artifact_draft_model_ids_v1(selector)
            carriers={}
            for kind,ref in (("c4_prepared",ids["job"]),("c4_frozen",ids["frozen"]),("c4_request",ids["request"]),("c4_call",ids["call"])):
                original=read_c4(business,issuer=budget_job_issuer,namespace=namespace_id,kind=kind,ref=ref)
                if original is None:raise AuthorityUnavailable("C09 C4 actual signed predecessor absent: "+kind)
                value=validate_c4_life_original_row_v1(kind,namespace=namespace_id,original_ref=ref,
                    producing_operation_id=original[1],raw=original[0])
                carriers[kind]=value
                row=business.execute("SELECT * FROM "+C4_TABLE+" WHERE bot=? AND persona=? AND kind=? AND original_ref=?",
                    (*namespace_id.as_tuple,kind,ref)).fetchone()
                source_commitments.append(commitment(business,C4_TABLE,row))
            prepared,frozen,acquired,original_call=(carriers[k] for k in ("c4_prepared","c4_frozen","c4_request","c4_call"))
            model_request=_request_from_wire(acquired.request_json)
            from ..runtime.c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
            cycle=get_job(business,AtomKey.from_token(selector.cycle_job_ref).name)
            responsibility=read_original_foreground_responsibility_for_c09_v1(business,namespace=namespace_id,job=cycle,issuer=budget_job_issuer)
            if responsibility is not None and (
                    (responsibility.c02_operation_id,responsibility.source_ref,responsibility.parent_budget_lease_ref)!=
                    (selector.c02_operation_id,frozen.task_source_ref,prepared.parent_budget_lease_ref)
                    or responsibility.root_registration_ref is not None and
                       (responsibility.root_registration_ref,responsibility.root_registration_digest)!=
                       (selector.root_registration_ref,frozen.root_registration_digest)):
                raise AuthorityUnavailable("C09 C4 crossed its immutable actual foreground responsibility")
            if (selector.namespace!=namespace_id or prepared.selector!=selector or prepared.digest!=intent.binding_digest
                    or frozen.digest!=prepared.frozen_digest or acquired.prepared_digest!=prepared.digest
                    or model_request.digest!=intent.request_digest or dict(model_request.payload)!=frozen.wire
                    or to_wire(original_call)!=to_wire(intent)
                    or (prepared.call_id,prepared.job_id,prepared.acquire_operation_id,prepared.quote_id,prepared.quote_digest,
                        prepared.reservation_digest,prepared.worker_subject,prepared.parent_budget_lease_ref)!=
                       (call,job.job_id,intent.acquire_operation_id,quote.quote_id,canonical_digest(quote),
                        intent.budget_reservation_digest,intent.subject,intent.budget_lease_id)
                    or job.continuation["prepared_digest"]!=prepared.digest):
                raise AuthorityUnavailable("C09 C4 real Core call/acquire/complete frozen input differs")
            if reservation[4]!="reserved":
                paid=read_c4(business,issuer=budget_job_issuer,namespace=namespace_id,kind="c4_paid",ref=ids["paid"])
                if paid is None or terminal is None:raise AuthorityUnavailable("C09 C4 settled cost requires actual paid/terminal originals")
                actual_paid=validate_c4_life_original_row_v1("c4_paid",namespace=namespace_id,original_ref=ids["paid"],
                    producing_operation_id=paid[1],raw=paid[0])
                if actual_paid.terminal_receipt_digest!=canonical_digest(asdict(terminal)):
                    raise AuthorityUnavailable("C09 C4 paid fact crossed original Core terminal")
                source_commitments.append(commitment(business,C4_TABLE,business.execute("SELECT * FROM "+C4_TABLE+
                    " WHERE bot=? AND persona=? AND kind='c4_paid' AND original_ref=?",(*namespace_id.as_tuple,ids["paid"])).fetchone()))
            returned=read_c4(business,issuer=budget_job_issuer,namespace=namespace_id,kind="c4_result",ref=ids["result"])
            if returned is not None:
                result_value=validate_c4_life_original_row_v1("c4_result",namespace=namespace_id,original_ref=ids["result"],
                    producing_operation_id=returned[1],raw=returned[0])
                if (terminal is None or result_value.terminal_receipt!=terminal or result_value.observation.digest!=record.observation_digest
                        or result_value.request.binding_digest!=prepared.digest or result_value.request.model_request_digest!=intent.request_digest):
                    raise AuthorityUnavailable("C09 C4 paired result differs from real Core terminal/body")
                from .v2_worker_model_result_attempts import (READ_ATTEMPT_COLUMNS_V1,validate_worker_result_read_attempt_row_v1,
                    require_worker_result_read_attempt_fence_v1)
                attempt=core_db.execute("SELECT * FROM authority_worker_result_read_attempts_v1 WHERE read_attempt_id=?",
                    (result_value.request.read_attempt_id,)).fetchone()
                if attempt is None:raise AuthorityUnavailable("C09 C4 real result read attempt absent")
                read_attempt=validate_worker_result_read_attempt_row_v1(READ_ATTEMPT_COLUMNS_V1,attempt)
                require_worker_result_read_attempt_fence_v1(core_db,attempt=read_attempt,authority_id=seal.authority_id,
                    authority_namespace=seal.namespace,installation_id=installation)
                from .d11_artifact_draft_model_v1 import artifact_draft_model_result_to_wire_v1
                if (read_attempt.request!=result_value.request or read_attempt.state!="finished"
                        or read_attempt.result_digest!=canonical_digest(artifact_draft_model_result_to_wire_v1(result_value))):
                    raise AuthorityUnavailable("C09 C4 result body has no actual finished delivered-read original")
                source_commitments.extend((commitment(core_db,"authority_worker_result_read_attempts_v1",attempt),
                    commitment(business,C4_TABLE,business.execute("SELECT * FROM "+C4_TABLE+
                        " WHERE bot=? AND persona=? AND kind='c4_result' AND original_ref=?",(*namespace_id.as_tuple,ids["result"])).fetchone())))
        elif job.work_kind == "d06.encode_internal_life_content":
            # This authenticates one completed acquire against real Core
            # originals. It does not close the three-table disposal inventory.
            from ..runtime.issuers import D11BudgetJobIssuer
            from ..runtime.internal_life_completed_original_v1 import read_completed_internal_life_original_v1
            if (type(budget_job_issuer) is not D11BudgetJobIssuer
                    or budget_job_issuer.resource_issuer is not resource_issuer):
                raise AuthorityUnavailable("C09 completed Life acquire needs the installed same D11 issuer; HOLD")
            try:
                life = read_completed_internal_life_original_v1(business,
                    namespace=namespace_id, issuer=budget_job_issuer, job_id=job.job_id)
            except (ValueError, TypeError, KeyError) as exc:
                raise AuthorityUnavailable("C09 completed Life signed acquire/history is unavailable; HOLD") from exc
            if (record.state != "observed" or terminal is None
                    or life.intent != intent or life.job != job
                    or life.delivered.terminal_receipt != terminal
                    or life.delivered.observation.digest != record.observation_digest
                    or (life.prepared.call_id, life.prepared.acquire_operation_id,
                        life.prepared.quote_id, life.prepared.quote_version,
                        life.prepared.reservation_digest) !=
                       (call, intent.acquire_operation_id, quote.quote_id,
                        quote.version, intent.budget_reservation_digest)
                    or reservation[4] != "settled"):
                raise AuthorityUnavailable("C09 completed Life differs from actual Core terminal/accounting; HOLD")
            from ..runtime.internal_life_paid_result_v2 import read_life_paid_original_v2
            from .internal_life_model_result_contract_v2 import (
                InternalLifeModelResultReadRequestV2, internal_life_result_from_wire_v2)
            try:
                request_original = read_life_paid_original_v2(business, namespace_id,
                    budget_job_issuer, "read_attempt", life.delivered.request.read_attempt_id)
                if (request_original is None or internal_life_result_from_wire_v2(
                        request_original, InternalLifeModelResultReadRequestV2) != life.delivered.request):
                    raise ValueError("Life paid request differs")
            except (ValueError, TypeError, KeyError) as exc:
                raise AuthorityUnavailable("C09 completed Life paid request original differs; HOLD") from exc
            # Commit exactly the authenticated carrier rows. These opaque
            # hashes are evidence inputs, never a replacement for full inventory.
            life_rows = (
                ("graph_internal_life_content_originals_v1", "original_ref", "prepared", job.job_id),
                ("graph_internal_life_content_originals_v1", "original_ref", "prepare_commit", job.job_id),
                *(("graph_internal_life_worker_originals_v2", "job_id", kind, job.job_id)
                  for kind in ("binding", "request", "acquire_commit", "call")),
                ("graph_internal_life_paid_originals_v2", "original_ref", "read_attempt", life.delivered.request.read_attempt_id),
                ("graph_internal_life_paid_originals_v2", "original_ref", "result", job.job_id),
                ("graph_internal_life_paid_originals_v2", "original_ref", "adoption_commit", job.job_id),
            )
            for table, ref_column, kind, ref in life_rows:
                row = business.execute(f"SELECT * FROM {table} WHERE bot=? AND persona=? AND kind=? AND {ref_column}=?",
                    (*namespace_id.as_tuple, kind, ref)).fetchone()
                if row is None:
                    raise AuthorityUnavailable("C09 completed Life authenticated carrier is missing; HOLD")
                source_commitments.append(commitment(business, table, row))
        else:
            raise AuthorityUnavailable("C09 model Graph acquire codec is unavailable")
    known = {}
    if record.state == "observed":
        usage, money = dict(record.usage), dict(record.cost)
        for unit in ceiling:
            if unit in {"input_tokens", "output_tokens"} and unit in usage:
                known[unit] = usage[unit]
            elif unit == "model_tokens" and {"input_tokens", "output_tokens"} <= set(usage):
                known[unit] = usage["input_tokens"] + usage["output_tokens"]
            elif unit == "model_microusd" and unit in money:
                known[unit] = money[unit]
    settled = {} if reservation[5] is None else _json(reservation[5])
    state = reservation[4]
    if state in {"settled", "overrun"} and (set(known) != set(ceiling) or any(settled.get(unit, 0) != amount for unit, amount in known.items())):
        raise AuthorityUnavailable("C09 settled model budget has no exact actual vector")
    if state in {"unknown", "partial_unknown", "partial_overrun"} and any(unit not in known or known[unit] != amount for unit, amount in settled.items()):
        raise AuthorityUnavailable("C09 partial model budget differs from observed vector")
    if state == "reserved" and reservation[5] is not None:
        raise AuthorityUnavailable("C09 reserved model budget has fabricated actual")
    cost_id = original_model_cost_operation_id_v1(namespace_id, call)
    cost_row = business.execute("SELECT token,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND type_name='runtime.cost_settlement' AND json_extract(value,'$.settlement_id')=?",
        (*namespace_id.as_tuple, cost_id)).fetchone()
    if state != "reserved":
        if cost_row is None or cost_row[2] != 1:
            raise AuthorityUnavailable("C09 model actual settled-cost Graph original absent")
        cost = _strict_payload(_json(cost_row[1]), RuntimeCostSettlement)
        if (cost.budget_phase=="settle" and cost.status in {"pending_confirmation","pending_overrun"}
                and state in {"settled","overrun"}):
            raise AuthorityUnavailable("C09 independently resolved model cost needs its separate resolution originals; HOLD")
        if (cost.settlement_id, cost.lease_id, cost.cost_operation_id, dict(cost.ceiling), cost.actual) != (
                cost_id, intent.budget_lease_id, intent.budget_reservation_operation_id, ceiling,
                settled if reservation[5] is not None else None):
            raise AuthorityUnavailable("C09 actual model cost original vector differs")
        source_commitments.append(canonical_digest((cost_row[0], cost_row[1], cost_row[2])))
        if job.work_kind in {"natural_generation","natural_review"}:
            from ..runtime.model_cost_settlement import OriginalModelCostCommitV1
            settle_row = business.execute("SELECT * FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
                "AND operation_id=? AND phase='settle'",
                (*namespace_id.as_tuple,intent.budget_reservation_operation_id)).fetchone()
            if settle_row is None or settle_row[4:6]!=(intent.budget_reservation_digest,intent.budget_lease_id):
                raise AuthorityUnavailable("C09 natural cost lacks original settle operation")
            settle_receipt = BudgetReceipt(**_json(settle_row[6]))
            if ((settle_receipt.operation_id,settle_receipt.digest,settle_receipt.lease_id)!=
                    (intent.budget_reservation_operation_id,intent.budget_reservation_digest,intent.budget_lease_id)
                    or settle_receipt.status not in {"settled","overrun","pending_confirmation","pending_overrun"}
                    or type(settle_receipt.version) is not int or not 1<=settle_receipt.version<=lease.version):
                raise AuthorityUnavailable("C09 natural original settle receipt differs")
            if ((cost.bot_id,cost.persona_id,cost.activity_id,cost.effect_id,
                    cost.bundle_operation_id,cost.currency,cost.budget_phase,
                    cost.budget_operation_id,cost.prior_unknown_ref,cost.status,
                    cost.budget_receipt_digest,cost.execution_revoked)!=
                    (*namespace_id.as_tuple,quote.activity_id,quote.effect_id,cost_id,
                    lease.currency,"settle",intent.budget_reservation_operation_id,None,
                    settle_receipt.status,canonical_digest(asdict(settle_receipt)),True)):
                raise AuthorityUnavailable("C09 natural cost projection differs from original settle receipt")
            operation = business.execute("SELECT * FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                (*namespace_id.as_tuple,cost_id)).fetchone()
            if operation is None:
                raise AuthorityUnavailable("C09 natural cost lacks actual Graph commit original")
            detail = _json(operation[7])
            committed = OriginalModelCostCommitV1(**detail["original_model_cost"])
            if ((committed.status,committed.operation_id,committed.call_id,committed.quote_id,
                    committed.quote_version,committed.cost_ref,committed.budget_receipt_digest,committed.commit_seq)!=
                    ("committed",cost_id,call,quote.quote_id,quote.version,cost_row[0],
                    canonical_digest(asdict(settle_receipt)),operation[6])
                    or terminal is None or committed.terminal_receipt_digest!=canonical_digest(asdict(terminal))
                    or (operation[4],operation[5])!=(quote.activity_id,quote.effect_id)
                    or type(committed.commit_seq) is not int or committed.commit_seq<1):
                raise AuthorityUnavailable("C09 natural settle/terminal/Graph cost identity differs")
            if ((detail.get("original_intent_digest"),detail.get("terminal_receipt_digest"),
                    detail.get("quote_id"),detail.get("quote_version"),detail.get("work_kind"))!=
                    (canonical_digest(asdict(intent)),canonical_digest(asdict(terminal)),
                    quote.quote_id,quote.version,job.work_kind)
                    or committed.schema!="sylanne.d11.original-model-cost-commit.v1"
                    or type(committed.graph_revision) is not int or committed.graph_revision<1
                    or type(committed.graph_epoch) is not int or committed.graph_epoch<1):
                raise AuthorityUnavailable("C09 natural outer cost receipt identity differs")
            event = business.execute("SELECT * FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
                (*namespace_id.as_tuple,operation[4],cost_id)).fetchone()
            history = business.execute("SELECT * FROM graph_history WHERE token=? AND revision=1",
                (committed.cost_ref,)).fetchone()
            if (event is None or event[9]!=committed.graph_epoch
                    or _json(event[7])!=[[committed.cost_ref,1]]
                    or history is None or history[0:4]!=(committed.cost_ref,1,cost_row[1],1)
                    or history[5:9]!=(*namespace_id.as_tuple,quote.activity_id,cost_id)):
                raise AuthorityUnavailable("C09 natural cost lacks its actual birth history/event")
            source_commitments.extend((commitment(business,"runtime_budget_operations",settle_row),
                commitment(business,"graph_bundle_operations",operation),
                commitment(business,"graph_events",event),commitment(business,"graph_history",history)))
    units = tuple(C09ModelUnitObligationV1(unit, amount, known.get(unit),
        0 if state == "reserved" or unit not in known else settled.get(unit, 0),
        known.get(unit, 0) if state == "reserved" else 0, max(0, known.get(unit, 0) - amount),
        amount if unit not in known else 0, None if state == "reserved" else cost_id)
        for unit, amount in sorted(ceiling.items()))
    body = dict(authority_id=seal.authority_id, installation_id=installation, namespace=seal.namespace,
        operation_id=seal.operation_id, call_id=call, model_operation_id=intent.operation_id, job_id=intent.job_id,
        acquire_operation_id=intent.acquire_operation_id, admission_id_or_none=None if admission is None else admission.admission_id,
        request_digest=intent.request_digest, binding_digest=intent.binding_digest, provider_id=intent.provider_id,
        provider_query_ref_or_none=provider_query_ref,
        provider_state=record.state, dispatch_generation=intent.authority_activation_generation,
        originating_journal_id=permit.pinned_anchor.execution_journal_id, original_execution_seq=permit.pinned_anchor.execution_seq,
        original_execution_digest=permit.pinned_anchor.execution_digest, parent_budget_id=lease.lease_id,
        reservation_operation_id=intent.budget_reservation_operation_id, reservation_digest=intent.budget_reservation_digest,
        reservation_state=state, quote_id=quote.quote_id, quote_version=quote.version, quote_digest=canonical_digest(quote),
        observation_digest_or_none=record.observation_digest, terminal_digest_or_none=None if terminal is None else canonical_digest(terminal),
        source_row_commitments=tuple(sorted(set(source_commitments))), units=units, schema="sylanne3.c09.model-budget-original.v1")
    original = C09ModelBudgetOriginalV1(**body, original_digest=canonical_digest(tuple(body[f.name] for f in fields(C09ModelBudgetOriginalV1) if f.name != "original_digest")))
    if _provider_scope_sink is not None:
        from .c09_provider_scope_v3 import issue_verified_model_provider_scope_v3
        proof = issue_verified_model_provider_scope_v3(token=_MODEL_PROVIDER_SCOPE_ISSUER_V3,core_db=core_db,business=business,seal=seal,original=original,
            intent=intent,source_ledger_commitment=commitment(core_db,'authority_model_egress_v1',ledger))
        _provider_scope_sink.retain_verified_provider_scope_v3(proof,original,core=core_db,graph=business)
    return original


def capture_frozen_model_budget_originals_v1(*, core_db, business, namespace_id, seal, resource_issuer,
        meter, require_existing=False, budget_job_issuer=None):
    """Complete one-quantum V1 compatibility; V2 owns larger actual inventories."""
    if not core_db.in_transaction or not business.in_transaction:
        raise AuthorityUnavailable("C09 real frozen Core/Graph snapshots required")
    core = _model_compat_reader_v1(core_db, meter)
    graph = _model_compat_reader_v1(business, meter)
    if core.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_model_egress_v1'").fetchone() is None:
        return ()
    calls = _complete_model_keys_v1(core, table="authority_model_egress_v1",
        where="namespace=?", args=(seal.namespace,), columns="call_id", order="call_id COLLATE BINARY", meter=meter)
    if not require_existing:
        install_c09_model_budget_schema_v1(core_db)
    result = []
    for (call,) in calls:
        original = read_frozen_model_budget_original_v2(core_db=core, business=graph,
            namespace_id=namespace_id, seal=seal, resource_issuer=resource_issuer,
            call_id=call, budget_job_issuer=budget_job_issuer)
        if original is None:
            continue
        encoded = canonical_serialize(asdict(original))
        old = core.execute(f"SELECT original_json,original_digest FROM {TABLE} WHERE namespace=? AND operation_id=? AND call_id=?",
            (seal.namespace, seal.operation_id, call)).fetchone()
        if old is None:
            if require_existing:
                raise AuthorityUnavailable("completed Core candidate forbids new model budget originals")
            meter.write_row(core_db, TABLE, ("namespace", "operation_id", "call_id", "original_json", "original_digest"),
                (seal.namespace, seal.operation_id, call, encoded, original.original_digest))
        elif old != (encoded, original.original_digest):
            raise AuthorityUnavailable("C09 frozen model original changed during repeated facts read")
        result.append(original)
    from time import monotonic_ns
    from ..runtime.c09_paged_sql_v2 import C09PagedCaptureHold
    if monotonic_ns() - meter.started_ns > meter.budget.max_local_ns:
        raise C09PagedCaptureHold("C09 legacy model capture exceeded its actual reserved duration")
    return tuple(result)
