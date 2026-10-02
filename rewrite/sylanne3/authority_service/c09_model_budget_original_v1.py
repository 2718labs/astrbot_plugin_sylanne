"""Fixed, content-free per-unit model obligations from real frozen originals."""
from dataclasses import asdict, dataclass, fields
import json

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest, canonical_serialize

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


def read_model_budget_originals_v1(db, *, namespace, operation_id):
    columns = tuple(item[1] for item in db.execute(f"PRAGMA table_info({TABLE})"))
    return tuple(validate_c09_model_budget_row_v1(columns, row) for row in db.execute(
        f"SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=? ORDER BY call_id", (namespace, operation_id)))


def model_unit_fact_v4(original, unit):
    from ..runtime.c09_storage_rebase_contract_v1 import SanitizedD11FactV4
    if unit.actual_or_none is None:
        raise AuthorityUnavailable("C09 unknown model amount has no actual-cost fact")
    identity = "model-unit:" + canonical_digest((unit.unit, original.call_id, original.parent_budget_id,
        original.reservation_operation_id, unit.settlement_id_or_none))[:48]
    return SanitizedD11FactV4(identity, original.parent_budget_id, original.reservation_operation_id,
        unit.ceiling, unit.actual_or_none, unit.settled, unit.pending_known, unit.debt, unit.unit)


def require_model_budget_release_safe_v1(db, *, namespace):
    columns = tuple(item[1] for item in db.execute(f"PRAGMA table_info({TABLE})"))
    for row in db.execute(f"SELECT * FROM {TABLE} WHERE namespace=?", (namespace,)):
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


def capture_frozen_model_budget_originals_v1(*, core_db, business, namespace_id, seal, resource_issuer,
        require_existing=False, budget_job_issuer=None):
    """Read real Core/Graph joins in the installed frozen transaction.

    No dedicated model execution append is invented. Its original fence pins
    the real independent execution head, while its send CAS/admission is Core.
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
        return ()
    if not require_existing:
        install_c09_model_budget_schema_v1(core_db)
    result = []
    def commitment(db, table, row):
        columns = tuple(item[1] for item in db.execute(f"PRAGMA table_info({table})"))
        material = tuple({"blob_sha256": __import__('hashlib').sha256(value).hexdigest(), "size": len(value)}
                         if type(value) is bytes else value for value in row)
        return canonical_digest((table, columns, material))
    for ledger in core_db.execute("SELECT * FROM authority_model_egress_v1 WHERE namespace=? ORDER BY call_id", (seal.namespace,)).fetchall():
        call = ledger[0]
        if core_db.execute("SELECT 1 FROM sqlite_master WHERE name='authority_c09_consumed_execution_v1'").fetchone() and core_db.execute(
                "SELECT 1 FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind='model_call' AND item_id=?", (seal.namespace, call)).fetchone():
            continue
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
            "json_extract(quote_json,'$.operation_id')=? AND json_extract(quote_json,'$.parent_budget_lease_ref')=?",
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
            if (cost.settlement_id, cost.lease_id, cost.cost_operation_id, dict(cost.ceiling), cost.actual) != (
                    cost_id, intent.budget_lease_id, intent.budget_reservation_operation_id, ceiling,
                    settled if reservation[5] is not None else None):
                raise AuthorityUnavailable("C09 actual model cost original vector differs")
            source_commitments.append(canonical_digest((cost_row[0], cost_row[1], cost_row[2])))
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
        encoded = canonical_serialize(asdict(original))
        old = core_db.execute(f"SELECT original_json,original_digest FROM {TABLE} WHERE namespace=? AND operation_id=? AND call_id=?",
            (seal.namespace, seal.operation_id, call)).fetchone()
        if old is None:
            if require_existing:
                raise AuthorityUnavailable("completed Core candidate forbids new model budget originals")
            core_db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?)", (seal.namespace, seal.operation_id, call, encoded, original.original_digest))
        elif old != (encoded, original.original_digest):
            raise AuthorityUnavailable("C09 frozen model original changed during repeated facts read")
        result.append(original)
    return tuple(result)
