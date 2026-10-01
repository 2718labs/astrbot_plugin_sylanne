"""Content-free signed accounting original for an actually prepared CPU tick.

It survives removal of raw Graph input bodies. It preserves the accepted cost
contract and never authorizes recomputation or simulated-source production.
"""
from dataclasses import dataclass
import json

from ..domains.d01.production_operations_v1 import plain_v1
from ..runtime_contracts import canonical_digest, canonical_serialize
from .budget import BudgetLease, BudgetReceipt
from .d11_offline_originals_v1 import TABLE, SIGN_KIND, WORK_KIND, ALGORITHM_ID, D11OfflineTickBindingV1, _digest
from .d10_offline_tick_execution_v1 import _decode_json
from .issuers import BudgetLeaseGrant, ResourceQuote


@dataclass(frozen=True, slots=True)
class D11OfflineAccountingPreparedV1:
    binding: D11OfflineTickBindingV1
    accounting_original_ref: str
    prepare_operation_id: str
    prepared_digest: str
    quote_json: str
    signed_grant_json: str
    signed_grant_signature: str
    parent_budget_json: str
    reserve_receipt_json: str
    schema: str = "d11.offline-content-free-accounting-prepared.v1"

    def __post_init__(self):
        if self.schema != "d11.offline-content-free-accounting-prepared.v1" or type(self.binding) is not D11OfflineTickBindingV1:
            raise ValueError("exact content-free offline accounting schema required")
        binding = self.binding
        _digest(self.prepared_digest)
        _digest(self.signed_grant_signature)
        if (self.accounting_original_ref != offline_accounting_original_ref_v1(binding)
                or self.prepare_operation_id != "d11-offline-tick-prepare:" + binding.operation_id):
            raise ValueError("offline accounting preparation has another actual identity")
        quote = _decode_json(self.quote_json, ResourceQuote)
        grant = _decode_json(self.signed_grant_json, BudgetLeaseGrant)
        parent = _decode_json(self.parent_budget_json, BudgetLease)
        reserve = _decode_json(self.reserve_receipt_json, BudgetReceipt)
        if ((quote.quote_id, quote.version, quote.activity_id, quote.operation_id, quote.effect_id, quote.parent_budget_lease_ref,
                quote.work_kind, quote.resource_ref, quote.required_worker_fence, quote.ceiling) !=
                (binding.quote_id, binding.quote_version, binding.activity_id, binding.operation_id, None, binding.parent_budget_lease_ref,
                WORK_KIND, ALGORITHM_ID, binding.job_fence, {"thread_cpu_ms": binding.cpu_ceiling_ms})
                or canonical_digest(quote) != binding.quote_digest or quote.outbox_refs or quote.d02_settlement_refs
                or quote.job_continuation is not None or parent.lease_id != binding.parent_budget_lease_ref
                or (grant.bot_id, grant.persona_id, grant.lease_id, grant.currency) !=
                    (*binding.namespace.as_tuple, parent.lease_id, parent.currency)
                or WORK_KIND not in grant.allowed_work_kinds or grant.max_ceiling.get("thread_cpu_ms", 0) < binding.cpu_ceiling_ms
                or (reserve.operation_id, reserve.lease_id, reserve.digest, reserve.status) !=
                    (binding.reservation_operation_id, binding.parent_budget_lease_ref, binding.reservation_digest, "reserved")):
            raise ValueError("offline accounting exact signed quote/grant/reserve contract differs")


def offline_accounting_original_ref_v1(binding):
    return "d11-offline-accounting:" + canonical_digest((binding.namespace, binding.execution_id, binding.digest))[:48]


def record_offline_accounting_prepared_after_cas_v1(db, *, issuer, prepared):
    if prepared.requirements_json is None:
        raise ValueError("accounting original must follow the genuine final preparation CAS")
    actual = db.execute("SELECT producing_operation_id,payload_json,payload_digest FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind='prepared_tick' AND original_ref=?",
        (*prepared.binding.namespace.as_tuple, prepared.binding.prepared_original_ref)).fetchone()
    if actual != (prepared.prepare_operation_id, canonical_serialize(plain_v1(prepared)), prepared.digest):
        raise ValueError("accounting preparation projection must come from the actual same-SQL signed prepared row")
    value = D11OfflineAccountingPreparedV1(prepared.binding, offline_accounting_original_ref_v1(prepared.binding),
        prepared.prepare_operation_id, prepared.digest, prepared.quote_json, prepared.signed_grant_json,
        prepared.signed_grant_signature, prepared.parent_budget_json, prepared.reserve_receipt_json)
    wire, digest = canonical_serialize(plain_v1(value)), canonical_digest(plain_v1(value))
    ns = value.binding.namespace
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((ns, "accounting_prepared", value.accounting_original_ref, digest)))
    expected = (value.prepare_operation_id, wire, digest, signature)
    prior = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind='accounting_prepared' AND original_ref=?", (*ns.as_tuple, value.accounting_original_ref)).fetchone()
    if prior is not None and prior != expected:
        raise ValueError("offline content-free accounting original replay changed")
    if prior is None:
        db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?)", (*ns.as_tuple, "accounting_prepared", value.accounting_original_ref, *expected))
    return value


def read_offline_accounting_prepared_v1(db, *, binding, issuer, resource_issuer):
    ref = offline_accounting_original_ref_v1(binding)
    row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind='accounting_prepared' AND original_ref=?", (*binding.namespace.as_tuple, ref)).fetchone()
    if row is None:
        return None
    value = _decode_json(row[1], D11OfflineAccountingPreparedV1)
    digest = canonical_digest(plain_v1(value))
    issuer._signer.verify(SIGN_KIND, canonical_serialize((binding.namespace, "accounting_prepared", ref, digest)), row[3])
    if value.binding != binding or digest != row[2] or value.prepare_operation_id != row[0]:
        raise ValueError("actual signed offline accounting original identity differs")
    from .domain_production_read_plans_v1 import _committed
    _committed(db, binding.namespace, value.prepare_operation_id)
    if canonical_serialize(plain_v1(resource_issuer.original_signed_quote(db, binding.quote_id, binding.quote_version))) != value.quote_json:
        raise ValueError("offline accounting actual signed quote differs")
    grant = _decode_json(value.signed_grant_json, BudgetLeaseGrant)
    signed, signature = issuer.signed_budget_grant_at_version(db, grant.lease_id, grant.version)
    if signed != grant or signature != value.signed_grant_signature:
        raise ValueError("offline accounting actual signed grant differs")
    reserve = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    reservation = db.execute("SELECT digest,ceiling_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (binding.parent_budget_lease_ref, binding.reservation_operation_id)).fetchone()
    if reserve != (value.reserve_receipt_json,) or reservation != (binding.reservation_digest, canonical_serialize({"thread_cpu_ms": binding.cpu_ceiling_ms})):
        raise ValueError("offline accounting actual original reserve differs")
    return value
