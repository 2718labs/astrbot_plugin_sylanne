"""Content-free CPU originals survive removal of a numeric input/artifact body.

The wire decoder is closed. Historical callers additionally reverify the
installed D02 signature and exact durable reservation; none of these reads
qualifies source access, native execution, or a mathematical adoption.
"""
from dataclasses import asdict, dataclass, fields
import json
from ..authority_service.d04_numeric_contract_v3 import D04NumericBindingV3, WORK_KIND, from_wire
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest, canonical_serialize
from .d04_appraisal_driver_v3 import record_d04_original_in_transaction_v3, read_d04_original_v3

JOB_IDENTITY_FIELDS = frozenset(("job_id", "operation_id", "activity_id", "effect_id", "bot_id", "persona_id",
    "work_kind", "budget_ref", "resource_ref", "operator_versions", "deadline_utc", "lease_holder",
    "lease_expires_utc", "fence", "cancel_epoch"))


@dataclass(frozen=True, slots=True)
class D04NumericAccountingPreparedV3:
    binding: D04NumericBindingV3
    prepared_digest: str
    quote_payload_json: str
    reserve_receipt_json: str
    job_identity_json: str
    schema: str = "d04.numeric-accounting-prepared.v3"

    @property
    def digest(self):
        return canonical_digest(asdict(self))


def _json(text, names, *, typed=None):
    if type(text) is not str:
        raise ValueError("numeric accounting original JSON text required")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("numeric accounting original has duplicate fields")
            result[key] = value
        return result
    raw = json.loads(text, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite numeric accounting original")))
    if type(raw) is not dict or canonical_serialize(raw) != text:
        raise ValueError("numeric accounting original fixed fields or canonical bytes differ")
    expected = set(names)
    if typed is not None:
        if set(raw) != expected | {"$type"} or raw["$type"] != typed.__module__ + "." + typed.__qualname__:
            raise ValueError("numeric accounting original fixed type discriminator differs")
        raw = {name: item for name, item in raw.items() if name != "$type"}
    elif set(raw) != expected:
        raise ValueError("numeric accounting original fixed fields or canonical bytes differ")
    return raw


def decode_numeric_accounting_prepared_payload_v3(raw):
    from .budget import BudgetReceipt
    from .issuers import ResourceQuote, _decode_quote
    from .jobs import _identifier, _utc
    if type(raw) is not dict or set(raw) != set(D04NumericAccountingPreparedV3.__dataclass_fields__):
        raise ValueError("numeric accounting original fields differ")
    binding = from_wire(raw["binding"], D04NumericBindingV3)
    value = D04NumericAccountingPreparedV3(**{**raw, "binding": binding})
    if (value.schema != "d04.numeric-accounting-prepared.v3"
            or type(value.prepared_digest) is not str or len(value.prepared_digest) != 64
            or any(c not in "0123456789abcdef" for c in value.prepared_digest)):
        raise ValueError("numeric accounting original schema/commitment differs")
    quote_raw = _json(value.quote_payload_json, (field.name for field in fields(ResourceQuote)), typed=ResourceQuote)
    quote = _decode_quote(canonical_serialize(quote_raw))
    reserve = BudgetReceipt(**_json(value.reserve_receipt_json, (field.name for field in fields(BudgetReceipt))))
    job = _json(value.job_identity_json, JOB_IDENTITY_FIELDS)
    for name in ("job_id", "operation_id", "activity_id", "bot_id", "persona_id", "work_kind", "budget_ref", "resource_ref"):
        _identifier(job[name], name)
    if job["effect_id"] is not None:
        _identifier(job["effect_id"], "effect_id")
    if job["lease_holder"] is not None:
        _identifier(job["lease_holder"], "lease_holder")
    if _utc(job["deadline_utc"], "deadline_utc") is None:
        raise ValueError("numeric accounting original deadline is absent")
    _utc(job["lease_expires_utc"], "lease_expires_utc")
    if ((job["lease_holder"] is None) != (job["lease_expires_utc"] is None)
            or any(type(job[name]) is not int or job[name] < 0 for name in ("fence", "cancel_epoch"))):
        raise ValueError("numeric accounting original worker identity differs")
    versions = job["operator_versions"]
    if versions != {"algorithm": binding.algorithm_build_digest,
            "resource_quote": binding.quote_id + ":" + str(binding.quote_version)}:
        raise ValueError("numeric accounting original fixed operator versions differ")
    expected_job = (binding.job_id, binding.operation_id, binding.activity_id, None,
        binding.namespace.bot_id, binding.namespace.persona_id, WORK_KIND, binding.parent_budget_lease_ref,
        binding.algorithm_id, binding.deadline_utc)
    if tuple(job[name] for name in ("job_id", "operation_id", "activity_id", "effect_id", "bot_id", "persona_id",
            "work_kind", "budget_ref", "resource_ref", "deadline_utc")) != expected_job:
        raise ValueError("numeric accounting job identity differs from binding")
    graph_job = AtomKey.from_token(quote.graph_job_ref)
    if ((quote.quote_id, quote.version, canonical_digest(quote), quote.bot_id, quote.persona_id,
            quote.operation_id, quote.activity_id, quote.effect_id, quote.parent_budget_lease_ref, quote.work_kind,
            quote.resource_ref) != (binding.quote_id, binding.quote_version, binding.quote_digest,
            binding.namespace.bot_id, binding.namespace.persona_id, binding.operation_id, binding.activity_id,
            None, binding.parent_budget_lease_ref, WORK_KIND, binding.algorithm_id)
            or dict(quote.ceiling) != {"cpu_ms": binding.cpu_ceiling_ms}
            or quote.job_continuation is not None or quote.outbox_refs or quote.d02_settlement_refs
            or quote.required_worker_fence is not None or graph_job.type_name != "runtime.job"
            or (graph_job.owner.bot, graph_job.owner.persona, graph_job.owner.subject, graph_job.name) !=
               (binding.namespace.bot_id, binding.namespace.persona_id, binding.activity_id, binding.job_id)
            or (reserve.status, reserve.operation_id, reserve.digest, reserve.lease_id) !=
               ("reserved", binding.reservation_operation_id, binding.reservation_digest, binding.parent_budget_lease_ref)):
        raise ValueError("numeric accounting quote/reservation differs from binding")
    return value


def record_numeric_accounting_prepared_v3(db, prepared):
    job = json.loads(prepared.job_payload_json)
    identity = {name: job[name] for name in JOB_IDENTITY_FIELDS}
    original = D04NumericAccountingPreparedV3(prepared.binding, prepared.digest,
        prepared.quote_payload_json, prepared.reserve_receipt_json, canonical_serialize(identity))
    decode_numeric_accounting_prepared_payload_v3(json.loads(canonical_serialize(asdict(original))))
    record_d04_original_in_transaction_v3(db, prepared.binding.namespace, "numeric_accounting_prepared",
        prepared.binding.operation_id, asdict(original))
    return original


def read_numeric_accounting_prepared_v3(db, namespace, operation_id, *, issuer=None):
    saved = read_d04_original_v3(db, namespace, "numeric_accounting_prepared", operation_id)
    if saved is None:
        return None
    raw, digest = saved
    value = decode_numeric_accounting_prepared_payload_v3(raw)
    if value.binding.namespace != namespace or value.binding.operation_id != operation_id or value.digest != digest:
        raise ValueError("numeric accounting original identity differs")
    if issuer is not None:
        from .issuers import D02ResourceIssuer
        if type(issuer) is not D02ResourceIssuer:
            raise ValueError("numeric accounting original requires installed D02 verifier")
        binding = value.binding
        quote = issuer.original_signed_quote(db, binding.quote_id, binding.quote_version)
        reserve = db.execute("SELECT receipt_json,digest,lease_id FROM runtime_budget_operations "
            "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
            (*namespace.as_tuple, binding.reservation_operation_id)).fetchone()
        if (canonical_serialize(quote) != value.quote_payload_json or canonical_digest(quote) != binding.quote_digest
                or reserve != (value.reserve_receipt_json, binding.reservation_digest, binding.parent_budget_lease_ref)):
            raise ValueError("numeric accounting signed quote/durable reservation differs")
    return value
