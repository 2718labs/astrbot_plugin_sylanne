"""Bounded Owner project next-step and ledger observation; never execution authority."""
from datetime import datetime, timezone
import json

from ..domains.d10.project_checkpoint_v1 import (CHECKPOINT_TYPE, decode_project_checkpoint_type_v1,
    project_checkpoint_key_v1)
from ..runtime_contracts import canonical_digest
from .budget import BudgetUnavailable, get_budget_lease
from .c09_budget_rows_v1 import UNITS
from .d08_project_control_v1 import project_control_basis_v1, project_control_context_v1
from .issuers import IssuerAuthorityDenied


def _budget_observation(db, *, namespace, original, issuer, now_utc, missing):
    # This is the verified project-producing W01 original, not an Owner-selected lease.
    lease_ref = original['payload']['parent_budget']
    if lease_ref is None:
        missing.append('project_original_budget_origin_missing')
        return None
    try:
        lease = get_budget_lease(db, lease_ref)
        grant = issuer.current_budget_grant(db, lease_ref)
    except (BudgetUnavailable, IssuerAuthorityDenied):
        missing.append('project_original_current_budget_unavailable')
        return None
    if ((lease.bot_id, lease.persona_id) != namespace.as_tuple
            or (grant.bot_id, grant.persona_id) != namespace.as_tuple
            or grant.lease_id != lease.lease_id or grant.currency != lease.currency):
        raise PermissionError('project original budget crossed its current namespace/currency')
    children = db.execute('SELECT limits_json FROM runtime_budget_leases '
        "WHERE parent_id=? AND state!='closed' ORDER BY lease_id LIMIT 129", (lease_ref,)).fetchall()
    allocation_complete = len(children) <= 128
    allocated = {}
    if allocation_complete:
        for (raw,) in children:
            for dimension, amount in json.loads(raw).items():
                allocated[dimension] = allocated.get(dimension, 0) + amount
    else:
        missing.append('parent_pool_child_allocation_window_incomplete')
    rows = []
    for dimension, limit in sorted(lease.limits.items()):
        unit = dimension if dimension in UNITS and (dimension != 'model_microusd' or lease.currency == 'USD') else None
        if unit is None:
            missing.append('budget_unit_unavailable:' + dimension)
        rows.append({'dimension': dimension, 'unit': unit, 'limit': limit,
            'grant_ceiling': grant.max_ceiling.get(dimension), 'spent': lease.used.get(dimension, 0),
            'reserved': lease.reserved.get(dimension, 0), 'unconfirmed': lease.unconfirmed.get(dimension, 0),
            'allocated': allocated.get(dimension, 0) if allocation_complete else None,
            'remaining': lease.available(dimension)})
    qualification = 'not_evaluated'
    if lease.state != 'active' or now_utc >= grant.valid_until_utc:
        qualification = 'hold'
        missing.append('current_budget_or_grant_inactive_or_expired')
    elif lease.unconfirmed or any(row['unit'] is None for row in rows) or not allocation_complete:
        qualification = 'unknown'
    return {'scope': 'shared_parent_pool', 'lease_ref': lease.lease_id, 'lease_version': lease.version,
        'state': lease.state, 'currency': lease.currency, 'grant_ref': grant.grant_id, 'grant_version': grant.version,
        'grant_expires_utc': datetime.fromtimestamp(grant.valid_until_utc, timezone.utc).isoformat().replace('+00:00', 'Z'),
        'qualification_state': qualification, 'allocation_coverage': 'complete' if allocation_complete else 'partial',
        'dimensions': rows}


def project_control_context_v2(db, *, namespace, project_ref, owner_binding, issuer, now_utc, graph_revision):
    """Only inside the existing Graph Owner/Source/C09 read fence and transaction."""
    context, audiences = project_control_context_v1(db, namespace=namespace, project_ref=project_ref,
        owner_binding=owner_binding, issuer=issuer, now_utc=now_utc, graph_revision=graph_revision)
    original, _, plan_atom, plan, _ = project_control_basis_v1(db, namespace=namespace, project_ref=project_ref)
    missing, checkpoint, next_step = [], None, None
    key = project_checkpoint_key_v1(namespace, project_ref)
    row = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
        (*namespace.as_tuple, key.token)).fetchone()
    if row is None or row[2] != 1:
        missing.append('current_project_checkpoint_missing')
    else:
        current = decode_project_checkpoint_type_v1(CHECKPOINT_TYPE, json.loads(row[1]))
        if current.project_ref != project_ref:
            raise ValueError('checkpoint differs from its actual project key')
        basis_current = current.plan_ref == plan_atom.key.token and current.plan_revision == plan_atom.revision
        checkpoint = {'checkpoint_ref': key.token, 'revision': row[0], 'plan_revision': current.plan_revision,
            'state': current.state, 'basis_status': 'current' if basis_current else 'stale',
            'wait_reason': None if current.wait_condition is None else current.wait_condition.event_kind}
        if not basis_current:
            missing.append('checkpoint_plan_basis_stale_requires_reevaluation')
        elif current.next_step is not None:
            node = next((node for node in plan.nodes if node.node_id == current.next_step), None)
            if node is None:
                missing.append('checkpoint_next_step_not_in_current_plan')
            else:
                next_step = {'node_ref': node.node_id, 'action_kind': node.action_kind,
                    'depends_on': list(node.depends_on), 'wait_condition': node.wait_condition}
    pending = sorted({ref for node in plan.nodes for ref in node.pending_original_effects})
    context.pop('context_digest')
    context.update(schema='d12.project-control-context.v2', checkpoint=checkpoint, next_step=next_step,
        pending_effects={'refs': pending[:32], 'total_count': len(pending), 'truncated': len(pending) > 32},
        budget=_budget_observation(db, namespace=namespace, original=original, issuer=issuer, now_utc=now_utc, missing=missing),
        missing=missing)
    context['context_digest'] = canonical_digest(context)
    return context, audiences
