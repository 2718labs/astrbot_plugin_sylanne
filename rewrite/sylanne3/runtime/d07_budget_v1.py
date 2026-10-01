"""Explicit Owner allocation of a bounded D07 child from the existing parent."""
from __future__ import annotations

from dataclasses import asdict

from ..runtime_contracts import canonical_digest
from .budget import BudgetLease, create_budget_lease, get_budget_lease, require_budget_family_admissible, close_budget_lease
from .issuers import BudgetLeaseGrant
from .d07_execution_v1 import record_d07_original_in_transaction_v1, read_d07_original_v1
from .d07_current_behavior_v1 import _json


def allocate_current_d07_cognition_budget_v1(graph, authority, lease, *, operation_id, parent_budget_lease_ref, ceiling):
    service = getattr(graph, "_GraphCoordinator__d07_execution_service_v1", None)
    if service is None or service.graph is not graph:
        raise ValueError("D07 child allocation requires actual installed cognition service")
    workflow = service._configured()
    if (type(ceiling) is not dict or not ceiling or any(type(k) is not str or type(v) is not int or v <= 0 for k, v in ceiling.items())
            or set(ceiling) != set(workflow.quote_ceiling)):
        raise ValueError("D07 child allocation requires explicit exact workflow cost dimensions")
    namespace = authority.namespace
    request_digest = canonical_digest(("d07.owner-child-budget.v1", namespace, operation_id, parent_budget_lease_ref, ceiling))
    child_id = "d07-budget:" + canonical_digest((namespace, operation_id))[:48]
    def commit(db, metadata, epoch, now, owner, scope):
        parent = get_budget_lease(db, parent_budget_lease_ref)
        issuer = service.d11_issuer
        grant = issuer.current_budget_grant(db, parent_budget_lease_ref)
        require_budget_family_admissible(db, parent.lease_id)
        if (parent.parent_id is not None or parent.state != "active" or (parent.bot_id, parent.persona_id) != namespace.as_tuple
                or parent.lease_id != service.bundle.installation_policy.root_lease.lease_id
                or grant.lease_id != parent.lease_id or grant.valid_until_utc <= now
                or "d07.cognition" not in grant.allowed_work_kinds
                or any(v > grant.max_ceiling.get(k, 0) for k, v in ceiling.items())):
            raise ValueError("D07 actual signed installed parent does not cover child allocation")
        child = BudgetLease(child_id, parent.lease_id, *namespace.as_tuple, parent.currency, ceiling, {}, {}, {}, 1, "active")
        receipt = create_budget_lease(db, child, "d07-allocate:" + operation_id, request_digest)
        child_grant = BudgetLeaseGrant("d07-grant:" + canonical_digest((namespace, operation_id))[:48], 1,
            *namespace.as_tuple, child_id, parent.currency, ceiling, ("d07.cognition",), grant.valid_until_utc,
            "d07-owner-child-budget.v1")
        signature = issuer.issue_budget_grant(db, child_grant)
        result = _json({"schema": "d07.actual-child-budget.v1", "namespace": asdict(namespace), "operation_id": operation_id,
            "lease_id": child_id, "parent_id": parent.lease_id, "grant": asdict(child_grant),
            "grant_digest": canonical_digest(child_grant), "signature_digest": canonical_digest(signature),
            "creation_receipt": asdict(receipt)})
        record_d07_original_in_transaction_v1(db, issuer, namespace, "budget_allocation", child_id, result)
        return result
    return graph._owner_domain_write_v3(authority, lease, operation_id=operation_id, request_digest=request_digest,
        domains=("d07", "d11"), capability="workbench.create", commit=commit)


def close_actual_d07_child_after_adoption_v1(db, *, prepared, issuer):
    lease = get_budget_lease(db, db.execute("SELECT budget_ref FROM runtime_jobs WHERE job_id=?", (prepared.job_id,)).fetchone()[0])
    if lease.parent_id is None or prepared.work_kind != "simulation":
        return None
    prior = read_d07_original_v1(db, issuer, prepared.namespace, "budget_closed", lease.lease_id)
    if prior is not None:
        return prior[0]
    if not db.in_transaction or lease.reserved:
        raise ValueError("D07 child cannot close while actual execution is unresolved")
    rows = db.execute("SELECT job_id,phase FROM runtime_jobs WHERE budget_ref=? ORDER BY job_id LIMIT 17", (lease.lease_id,)).fetchall()
    if len(rows) > 16 or any(phase not in {"completed", "failed", "cancelled"} for _, phase in rows):
        raise ValueError("D07 child budget still has live or unknown jobs")
    original = read_d07_original_v1(db, issuer, prepared.namespace, "execution", "d07-terminal:" + prepared.call_id)
    if original is None:
        raise ValueError("D07 child release needs actual original consumed/completed claim")
    operation = "d07-close-budget:" + canonical_digest((prepared.namespace, lease.lease_id, prepared.call_id))[:48]
    digest = canonical_digest((operation, prepared.digest, original[1], lease.lease_id))
    receipt = close_budget_lease(db, lease.lease_id, operation, digest, execution_revoked=True)
    result = {"schema": "d07.actual-child-budget-close.v1", "namespace": asdict(prepared.namespace),
        "lease_id": lease.lease_id, "parent_id": lease.parent_id, "operation_id": operation,
        "prepared_digest": prepared.digest, "execution_original_digest": original[1], "close_receipt": asdict(receipt)}
    record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "budget_closed", lease.lease_id, result)
    return result
