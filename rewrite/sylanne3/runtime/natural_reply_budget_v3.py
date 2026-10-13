"""Natural reply budget consumers over the existing signed D11 lease family.

The installed root remains pinned. New foreground work uses Goal's actual
cycle/child resolver; historical reads retain the original signed budget.
These functions issue no grant, allocation, reservation or settlement.
"""
from __future__ import annotations

import json

from ..domains.d08.natural_plan import decode_natural_plan_v2
from ..graph_types import AtomKey
from ..host.authority_profile import AdminInstallationBundle
from ..runtime_contracts import NamespaceId, canonical_digest
from .budget import get_budget_lease, require_budget_family_admissible
from .issuers import BudgetLeaseGrant, D11BudgetJobIssuer
from .natural_reply_job_v2 import SavedNaturalPreparationV2, read_original_preparation

FOREGROUND_WORK_KIND = "d11.foreground_cycle.v1"
REPLY_WORK_KINDS = frozenset({"natural_generation", "natural_review", "message"})


def _require_installed_root(db, namespace, installed_bundle, grant):
    policy = installed_bundle.installation_policy
    lease = get_budget_lease(db, grant.lease_id)
    if (policy.namespace != namespace or grant != policy.root_grant
            or lease.parent_id is not None
            or lease.lease_id != policy.root_lease.lease_id
            or (lease.bot_id, lease.persona_id) != namespace.as_tuple
            or lease.currency != policy.root_lease.currency
            or lease.limits != policy.root_lease.limits):
        raise ValueError("natural installed root budget pin differs")
    return lease, grant


def _require_installed_transaction(db, namespace, issuer, installed_bundle):
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(issuer) is not D11BudgetJobIssuer
            or type(installed_bundle) is not AdminInstallationBundle):
        raise ValueError("natural budget requires its installed issuer and pinned Graph transaction")


def _current_installed_root(db, namespace, issuer, installed_bundle):
    _require_installed_transaction(db, namespace, issuer, installed_bundle)
    grant = issuer.current_budget_grant(db, installed_bundle.installation_policy.root_lease.lease_id)
    return _require_installed_root(db, namespace, installed_bundle, grant)


def resolve_natural_reply_budget_for_new_admission_v3(db, *, namespace,
        c02_operation_id, source_ref, issuer, installed_bundle, now_utc):
    root, root_grant = _current_installed_root(db, namespace, issuer, installed_bundle)
    if FOREGROUND_WORK_KIND not in root_grant.allowed_work_kinds:
        return root, root_grant
    from .foreground_call_plan_v1 import resolve_current_foreground_reply_budget_v1
    lease, grant = resolve_current_foreground_reply_budget_v1(db, namespace=namespace,
        c02_operation_id=c02_operation_id, source_ref=source_ref, issuer=issuer,
        installed_bundle=installed_bundle, now_utc=now_utc)
    if (type(grant) is not BudgetLeaseGrant or lease.lease_id == root.lease_id
            or lease.parent_id != root.lease_id or grant.lease_id != lease.lease_id
            or (lease.bot_id, lease.persona_id) != namespace.as_tuple
            or (grant.bot_id, grant.persona_id) != namespace.as_tuple
            or lease.currency != root.currency or grant.currency != root_grant.currency
            or lease.state != "active" or grant.valid_until_utc <= now_utc
            or grant.valid_until_utc > root_grant.valid_until_utc
            or not REPLY_WORK_KINDS <= set(grant.allowed_work_kinds)
            or not REPLY_WORK_KINDS <= set(root_grant.allowed_work_kinds)
            or any(amount > root_grant.max_ceiling.get(name, 0)
                   for name, amount in grant.max_ceiling.items())):
        raise ValueError("natural reply needs the actual signed child including message permission")
    require_budget_family_admissible(db, lease.lease_id)
    return lease, grant


def read_natural_reply_original_budget_v3(db, *, namespace, c02_operation_id,
        source_ref, issuer, installed_bundle, original_preparation):
    """Read exact old signed provenance. This is not a new-work admission."""
    _require_installed_transaction(db, namespace, issuer, installed_bundle)
    policy = installed_bundle.installation_policy
    root_grant, _root_signature = issuer.signed_budget_grant_at_version(
        db, policy.root_lease.lease_id, policy.root_grant.version)
    _require_installed_root(db, namespace, installed_bundle, root_grant)
    if (type(original_preparation) is not SavedNaturalPreparationV2
            or original_preparation.stage != "generation"
            or original_preparation.seal.namespace != namespace
            or original_preparation.seal.c02_operation_id != c02_operation_id
            or original_preparation.seal.source_ref != source_ref
            or read_original_preparation(db, namespace, c02_operation_id, "generation") != original_preparation):
        raise ValueError("natural original budget lacks its actual sealed generation")
    frozen = original_preparation.frozen
    key = AtomKey.from_token(frozen.input.plan.plan_ref.ref)
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                     (key.token, *namespace.as_tuple)).fetchone()
    if row is None or row[0] != frozen.input.plan.plan_ref.version or row[2] != 1:
        raise ValueError("natural original adopted plan is unavailable")
    adopted = decode_natural_plan_v2(json.loads(row[1]))
    lease_id = original_preparation.seal.parent_budget_lease_id
    if (adopted.c02_operation_id != c02_operation_id or adopted.source_ref.ref != source_ref
            or adopted.parent_budget_lease_id != lease_id):
        raise ValueError("natural original plan and sealed budget differ")
    grant, _signature = issuer.signed_budget_grant_at_version(db, lease_id, adopted.budget_grant_version)
    lease = get_budget_lease(db, lease_id)
    if (canonical_digest(grant) != adopted.budget_grant_digest
            or (grant.bot_id, grant.persona_id) != namespace.as_tuple
            or (lease.bot_id, lease.persona_id) != namespace.as_tuple):
        raise ValueError("natural original signed budget provenance differs")
    return lease, grant


def resolve_natural_reply_budget_for_original_admission_v3(db, *, namespace,
        c02_operation_id, source_ref, issuer, installed_bundle, now_utc, original_preparation):
    """New review/message work must still qualify its exact original budget."""
    old_lease, old_grant = read_natural_reply_original_budget_v3(db, namespace=namespace,
        c02_operation_id=c02_operation_id, source_ref=source_ref, issuer=issuer,
        installed_bundle=installed_bundle, original_preparation=original_preparation)
    lease, grant = resolve_natural_reply_budget_for_new_admission_v3(db, namespace=namespace,
        c02_operation_id=c02_operation_id, source_ref=source_ref, issuer=issuer,
        installed_bundle=installed_bundle, now_utc=now_utc)
    if lease.lease_id != old_lease.lease_id or grant != old_grant:
        raise ValueError("new natural work cannot replace or re-sign its original budget")
    if lease.state != "active" or grant.valid_until_utc <= now_utc:
        raise ValueError("natural original budget is no longer eligible for new work")
    require_budget_family_admissible(db, lease.lease_id)
    return lease, grant
