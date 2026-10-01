"""Strict retained authored-root CPU identity without coordinates or Owner tokens."""
from dataclasses import fields

from ..authority_service.d04_root_execution_contract_v3 import D04RootExecutionBindingV3, root_execution_from_wire_v3
from ..runtime_contracts import canonical_digest, canonical_serialize
from .budget import BudgetLease, BudgetReceipt
from .issuers import ResourceQuote, BudgetLeaseGrant, _decode_quote, _decode_grant, D02ResourceIssuer, D11BudgetGrantIssuer
from .d04_numeric_accounting_prepared_v3 import _json
from .d04_appraisal_driver_v3 import read_d04_original_v3
from .d11_d04_root_freeze_v3 import ROOT_WORK_KIND_V3

FIELDS = frozenset(("schema", "binding", "prepared_digest", "quote_payload_json", "reserve_receipt_json",
    "parent_budget_original_json", "signed_grant_payload_json", "signed_grant_signature"))
SCHEMA = "d04.authored-root-accounting-prepared.v3"


def decode_root_accounting_prepared_payload_v3(raw):
    """Return only typed fixed accounting fields; never decode a math candidate."""
    if type(raw) is not dict or set(raw) != FIELDS or raw["schema"] != SCHEMA:
        raise ValueError("root accounting original fixed fields/schema differ")
    binding = root_execution_from_wire_v3(raw["binding"], D04RootExecutionBindingV3)
    for name in ("prepared_digest", "signed_grant_signature"):
        value = raw[name]
        if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("root accounting original commitment/signature differs")
    quote_raw = _json(raw["quote_payload_json"], (f.name for f in fields(ResourceQuote)), typed=ResourceQuote)
    quote = _decode_quote(canonical_serialize(quote_raw))
    reserve = BudgetReceipt(**_json(raw["reserve_receipt_json"], (f.name for f in fields(BudgetReceipt))))
    budget = BudgetLease(**_json(raw["parent_budget_original_json"], (f.name for f in fields(BudgetLease))))
    grant_raw = _json(raw["signed_grant_payload_json"], (f.name for f in fields(BudgetLeaseGrant)))
    grant = _decode_grant(canonical_serialize(grant_raw))
    from .d04_root_execution_v3 import root_execution_ids_v3
    identity = root_execution_ids_v3(binding.namespace, binding.operation_id)
    if ((quote.quote_id, quote.version, canonical_digest(quote), quote.bot_id, quote.persona_id,
            quote.operation_id, quote.activity_id, quote.effect_id, quote.parent_budget_lease_ref,
            quote.work_kind, quote.resource_ref, quote.graph_job_ref) !=
            (binding.quote_id, binding.quote_version, binding.quote_digest, *binding.namespace.as_tuple,
             binding.operation_id, identity["activity"], None, binding.parent_budget_lease_ref,
             ROOT_WORK_KIND_V3, binding.algorithm_id, None)
            or quote.outbox_refs or quote.d02_settlement_refs or quote.required_worker_fence is not None
            or quote.job_continuation is not None or dict(quote.ceiling) != {binding.cpu_dimension: binding.cpu_ceiling_ms}
            or (reserve.status, reserve.operation_id, reserve.digest, reserve.lease_id) !=
               ("reserved", binding.reservation_operation_id, binding.reservation_digest, binding.parent_budget_lease_ref)
            or (grant.bot_id, grant.persona_id, grant.lease_id, grant.currency) !=
               (*binding.namespace.as_tuple, binding.parent_budget_lease_ref, budget.currency)
            or grant.allowed_work_kinds != (ROOT_WORK_KIND_V3,)
            or dict(grant.max_ceiling) != {binding.cpu_dimension: binding.cpu_ceiling_ms}
            or (budget.bot_id, budget.persona_id, budget.lease_id) != (*binding.namespace.as_tuple, binding.parent_budget_lease_ref)
            or set(budget.limits) != {binding.cpu_dimension}
            or budget.state != "active"):
        raise ValueError("root accounting fixed CPU identity/amount differs")
    return binding, quote, reserve, budget, grant


def read_root_accounting_prepared_v3(db, namespace, operation_id, *, resource_issuer, budget_issuer):
    """Verify original D02/D11 signatures and durable reserve without source reads."""
    if type(resource_issuer) is not D02ResourceIssuer or not isinstance(budget_issuer, D11BudgetGrantIssuer):
        raise ValueError("root accounting requires its actual installed D02/D11 verifiers")
    saved = read_d04_original_v3(db, namespace, "root_accounting_prepared", operation_id)
    if saved is None:
        return None
    raw, committed = saved
    binding, quote, reserve, budget, grant = decode_root_accounting_prepared_payload_v3(raw)
    if binding.namespace != namespace or binding.operation_id != operation_id or canonical_digest(raw) != committed:
        raise ValueError("root accounting original row identity differs")
    actual_quote = resource_issuer.original_signed_quote(db, binding.quote_id, binding.quote_version)
    actual_grant, signature = budget_issuer.signed_budget_grant_at_version(db, grant.lease_id, grant.version)
    signed = db.execute("SELECT grant_json,signature FROM runtime_budget_grants WHERE lease_id=? AND version=?",
        (grant.lease_id, grant.version)).fetchone()
    reservation = db.execute("SELECT receipt_json,digest,lease_id FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    if (actual_quote != quote or canonical_serialize(actual_quote) != raw["quote_payload_json"]
            or actual_grant != grant or signature != raw["signed_grant_signature"]
            or signed != (raw["signed_grant_payload_json"], raw["signed_grant_signature"])
            or reservation != (raw["reserve_receipt_json"], binding.reservation_digest, binding.parent_budget_lease_ref)):
        raise ValueError("root accounting actual signed quote/grant/reservation differs")
    return raw, committed
