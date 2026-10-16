"""Content-free signed accounting original for an actually prepared CPU tick.

It survives removal of raw Graph input bodies. It preserves the accepted cost
contract and never authorizes recomputation or simulated-source production.
"""
from .d11_life_contract_v1 import LIFE_BINDING_TYPES, LIFE_CLAIM_TYPES, LIFE_TERMINAL_TYPES
from dataclasses import dataclass
import json

from ..domains.d01.production_operations_v1 import plain_v1
from ..runtime_contracts import canonical_digest, canonical_serialize
from .budget import BudgetLease, BudgetReceipt
from .d11_life_preparation_v1 import TABLE, SIGN_KIND
from .d11_life_contract_v1 import WORK_KIND, ALGORITHM_ID, D11LifeExecutionBindingV1, life_work_kind_v1
from .d11_offline_originals_v1 import _digest
from .d10_offline_tick_execution_v1 import _decode_json
from .issuers import BudgetLeaseGrant, ResourceQuote


@dataclass(frozen=True, slots=True)
class D11LifeAccountingPreparedV1:
    binding: D11LifeExecutionBindingV1
    accounting_original_ref: str
    prepare_operation_id: str
    prepared_digest: str
    quote_json: str
    signed_grant_json: str
    signed_grant_signature: str
    parent_budget_json: str
    reserve_receipt_json: str
    schema: str = "d11.life-content-free-accounting-prepared.v1"

    def __post_init__(self):
        if self.schema != "d11.life-content-free-accounting-prepared.v1" or type(self.binding) not in LIFE_BINDING_TYPES:
            raise ValueError("exact content-free life accounting schema required")
        binding = self.binding
        work_kind = life_work_kind_v1(binding)
        _digest(self.prepared_digest)
        _digest(self.signed_grant_signature)
        if (self.accounting_original_ref != life_accounting_original_ref_v1(binding)
                or self.prepare_operation_id != binding.prepare_operation_id):
            raise ValueError("life accounting preparation has another actual identity")
        quote = _decode_json(self.quote_json, ResourceQuote)
        grant = _decode_json(self.signed_grant_json, BudgetLeaseGrant)
        parent = _decode_json(self.parent_budget_json, BudgetLease)
        reserve = _decode_json(self.reserve_receipt_json, BudgetReceipt)
        if ((quote.quote_id, quote.version, quote.activity_id, quote.operation_id, quote.effect_id, quote.parent_budget_lease_ref,
                quote.work_kind, quote.resource_ref, quote.required_worker_fence, quote.ceiling) !=
                (binding.quote_id, binding.quote_version, binding.activity_id, binding.prepare_operation_id, binding.effect_id, binding.parent_budget_lease_ref,
                work_kind, binding.algorithm_id, binding.job_fence, {"thread_cpu_ms": binding.cpu_ceiling_ms})
                or canonical_digest(quote) != binding.quote_digest or quote.outbox_refs or quote.d02_settlement_refs
                or quote.job_continuation is not None or parent.lease_id != binding.parent_budget_lease_ref
                or (grant.bot_id, grant.persona_id, grant.lease_id, grant.currency) !=
                    (*binding.namespace.as_tuple, parent.lease_id, parent.currency)
                or work_kind not in grant.allowed_work_kinds or grant.max_ceiling.get("thread_cpu_ms", 0) < binding.cpu_ceiling_ms
                or (reserve.operation_id, reserve.lease_id, reserve.digest, reserve.status) !=
                    (binding.reservation_operation_id, binding.parent_budget_lease_ref, binding.reservation_digest, "reserved")):
            raise ValueError("life accounting exact signed quote/grant/reserve contract differs")


def life_accounting_original_ref_v1(binding):
    return "d11-life-accounting:" + canonical_digest((binding.namespace, binding.execution_id, binding.digest))[:48]


def record_life_accounting_prepared_after_cas_v1(db, *, issuer, prepared):
    if prepared.requirements_json is None:
        raise ValueError("accounting original must follow the genuine final preparation CAS")
    actual = db.execute("SELECT producing_operation_id,payload_json,payload_digest FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind='prepared' AND original_ref=?",
        (*prepared.binding.namespace.as_tuple, prepared.binding.prepared_original_ref)).fetchone()
    if actual != (prepared.prepare_operation_id, canonical_serialize(plain_v1(prepared)), prepared.digest):
        raise ValueError("accounting preparation projection must come from the actual same-SQL signed prepared row")
    value = D11LifeAccountingPreparedV1(prepared.binding, life_accounting_original_ref_v1(prepared.binding),
        prepared.prepare_operation_id, prepared.digest, prepared.quote_json, prepared.signed_grant_json,
        prepared.signed_grant_signature, prepared.parent_budget_json, prepared.reserve_receipt_json)
    wire, digest = canonical_serialize(plain_v1(value)), canonical_digest(plain_v1(value))
    ns = value.binding.namespace
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((ns, "accounting_prepared", value.accounting_original_ref, digest)))
    expected = (value.prepare_operation_id, wire, digest, signature)
    prior = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind='accounting_prepared' AND original_ref=?", (*ns.as_tuple, value.accounting_original_ref)).fetchone()
    if prior is not None and prior != expected:
        raise ValueError("life content-free accounting original replay changed")
    if prior is None:
        db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?)", (*ns.as_tuple, "accounting_prepared", value.accounting_original_ref, *expected))
    return value


def read_life_accounting_prepared_v1(db, *, binding, issuer, resource_issuer):
    ref = life_accounting_original_ref_v1(binding)
    from .current_life_numeric_native_read_v3 import read_bound_native_numeric_point_v3
    handled,row=read_bound_native_numeric_point_v3(db,table='graph_d11_life_originals_v1',columns=('producing_operation_id', 'payload_json', 'payload_digest', 'signature'),
        key_columns=('bot', 'persona', 'kind', 'original_ref'),key=(*binding.namespace.as_tuple,'accounting_prepared',ref))
    if not handled:
        from ..authority_service.life_model_original_family_read_v3 import read_bound_life_model_body_point_v3
        handled,row=read_bound_life_model_body_point_v3(db,table='graph_d11_life_originals_v1',columns=('producing_operation_id', 'payload_json', 'payload_digest', 'signature'),
        key_columns=('bot', 'persona', 'kind', 'original_ref'),key=(*binding.namespace.as_tuple,'accounting_prepared',ref))
    if not handled:
        row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind='accounting_prepared' AND original_ref=?", (*binding.namespace.as_tuple, ref)).fetchone()
    if row is None:
        return None
    value = _decode_json(row[1], D11LifeAccountingPreparedV1)
    digest = canonical_digest(plain_v1(value))
    issuer._signer.verify(SIGN_KIND, canonical_serialize((binding.namespace, "accounting_prepared", ref, digest)), row[3])
    if value.binding != binding or digest != row[2] or value.prepare_operation_id != row[0]:
        raise ValueError("actual signed life accounting original identity differs")
    from .domain_production_read_plans_v1 import _committed
    _committed(db, binding.namespace, value.prepare_operation_id)
    if canonical_serialize(plain_v1(resource_issuer.original_signed_quote(db, binding.quote_id, binding.quote_version))) != value.quote_json:
        raise ValueError("life accounting actual signed quote differs")
    grant = _decode_json(value.signed_grant_json, BudgetLeaseGrant)
    signed, signature = issuer.signed_budget_grant_at_version(db, grant.lease_id, grant.version)
    if signed != grant or signature != value.signed_grant_signature:
        raise ValueError("life accounting actual signed grant differs")
    from .current_life_numeric_native_read_v3 import read_bound_native_numeric_point_v3
    handled,reserve=read_bound_native_numeric_point_v3(db,table='runtime_budget_operations',columns=('receipt_json',),
        key_columns=('bot_id', 'persona_id', 'operation_id', 'phase'),key=(*binding.namespace.as_tuple,binding.reservation_operation_id,'reserve'))
    if not handled:
        from ..authority_service.life_model_original_family_read_v3 import read_bound_life_model_body_point_v3
        handled,reserve=read_bound_life_model_body_point_v3(db,table='runtime_budget_operations',columns=('receipt_json',),
        key_columns=('bot_id', 'persona_id', 'operation_id', 'phase'),key=(*binding.namespace.as_tuple,binding.reservation_operation_id,'reserve'))
    if not handled:
        reserve = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    from .current_life_numeric_native_read_v3 import read_bound_native_numeric_point_v3
    handled,reservation=read_bound_native_numeric_point_v3(db,table='runtime_budget_reservations',columns=('digest', 'ceiling_json'),
        key_columns=('lease_id', 'operation_id'),key=(binding.parent_budget_lease_ref,binding.reservation_operation_id))
    if not handled:
        from ..authority_service.life_model_original_family_read_v3 import read_bound_life_model_body_point_v3
        handled,reservation=read_bound_life_model_body_point_v3(db,table='runtime_budget_reservations',columns=('digest', 'ceiling_json'),
        key_columns=('lease_id', 'operation_id'),key=(binding.parent_budget_lease_ref,binding.reservation_operation_id))
    if not handled:
        reservation = db.execute("SELECT digest,ceiling_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (binding.parent_budget_lease_ref, binding.reservation_operation_id)).fetchone()
    if reserve != (value.reserve_receipt_json,) or reservation != (binding.reservation_digest, canonical_serialize({"thread_cpu_ms": binding.cpu_ceiling_ms})):
        raise ValueError("life accounting actual original reserve differs")
    return value
