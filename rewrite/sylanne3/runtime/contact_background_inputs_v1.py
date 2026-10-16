"""Derive Contact background scope from authenticated installed originals."""
from dataclasses import asdict
from .contact_original_read_v3 import contact_original_point_v3
import json

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest
from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2, require_contact_inventory_current_v2
from .contact_model_preparation_v2 import read_paid_contact_batch_original_v2
from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
from .contact_paid_original_v2 import require_contact_original_v2
from .budget import get_budget_lease, require_budget_family_admissible


def read_contact_background_inputs_v1(db, *, namespace, contact_id, operation_id, request_digest,
        dedupe_key, issuer, now, owner_actor):
    from ..authority_service.contact_model_graph_v2 import require_contact_scope_current_v2
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError('Contact background inputs require one pinned original snapshot')
    plan, expression, raw, plan_digest = read_adopted_contact_plan_v2(db, namespace=namespace,
        contact_id=contact_id, issuer=issuer)
    saved = read_adopted_domain_operation_v1(db, namespace, operation_id)
    if saved is None:
        require_contact_inventory_current_v2(db, namespace, raw)
        require_contact_scope_current_v2(db, plan, expression, now=now)
    elif saved['operation_kind'] != 'prepare_contact_dispatch_v3':
        raise ValueError('Contact background final identity belongs to another operation')
    pair = read_paid_contact_batch_original_v2(db, namespace=namespace, contact_id=contact_id,
        issuer=issuer, resource_issuer=issuer._d02)
    if pair is None:
        raise ValueError('Contact background requires both actual paid passing phases')
    content = read_contact_reviewed_content_original_v2(db, namespace=namespace, contact_id=contact_id,
        issuer=issuer, resource_issuer=issuer._d02)
    first = content.segments[0]
    parent = issuer.current_budget_grant(db, plan.parent_budget_lease_id)
    budget = get_budget_lease(db, parent.lease_id)
    require_budget_family_admissible(db, parent.lease_id)
    expected = canonical_digest(('sylanne.domain-production-command.v1', namespace, owner_actor,
        'prepare_contact_dispatch_v3', PrepareCurrentContactDispatchRequestV3(contact_id, 0), operation_id,
        plan.activity_id, plan.audience_id, parent.lease_id))
    event = contact_original_point_v3(db,table='graph_domain_production_outbox_v1',
        columns=('causal_operation_id','event_kind','original_ref','original_digest','state'),
        key_columns=('bot','persona','dedupe_key'),key=(*namespace.as_tuple,dedupe_key),
        legacy_reader=lambda: db.execute('SELECT causal_operation_id,event_kind,original_ref,original_digest,state FROM '
            'graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?',
            (*namespace.as_tuple,dedupe_key)).fetchone())
    causal = None if event is None else read_adopted_domain_operation_v1(db, namespace, event[0])
    if (request_digest != expected or first.operation_id != operation_id or causal is None
            or event[1] != 'qualified_contact_opportunity_requires_action'
            or event[4] not in {'pending', 'waiting', 'completed'}
            or causal['operation_kind'] != 'prepare_contact'
            or causal['payload']['request']['opportunity_ref'] != plan.opportunity_ref.ref
            or event[3] != causal['original_digest'] or budget.state != 'active'
            or parent.version != plan.budget_grant_version or canonical_digest(parent) != plan.budget_grant_digest
            or not now < min(plan.valid_until_utc, content.valid_until, parent.valid_until_utc)):
        raise ValueError('Contact background exact cause/first command/current finite parent differs')
    phases = []
    results = []
    from ..authority_service.contact_model_result_contract_v2 import ContactModelResultReadV2, contact_result_from_wire_v2
    for prepared, frozen, candidate, paid in pair[2:]:
        terminal, terminal_digest = require_contact_original_v2(db, issuer, namespace, 'terminal', prepared.job_id)
        result_raw, result_digest = require_contact_original_v2(db, issuer, namespace, 'result', prepared.job_id)
        result = contact_result_from_wire_v2(result_raw, ContactModelResultReadV2)
        phases.append({'phase': prepared.phase, 'job_id': prepared.job_id, 'prepared_digest': prepared.digest,
            'terminal_digest': terminal_digest, 'cost_digest': canonical_digest(paid),
            'result_digest': result_digest, 'call_id': prepared.call_id})
        results.append(result)
    metadata = contact_original_point_v3(db,table='graph_recovery_metadata_v2',
        columns=('requirements_json','graph_revision'),key_columns=('bot','persona'),key=namespace.as_tuple,
        legacy_reader=lambda: db.execute('SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 '
            'WHERE bot=? AND persona=?',namespace.as_tuple).fetchone())
    epoch = db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?', namespace.as_tuple).fetchone()
    requirements = json.loads(metadata[0])
    terms = {'namespace': asdict(namespace), 'contact_id': contact_id, 'operation_id': operation_id,
        'request_digest': request_digest, 'dedupe_key': dedupe_key, 'causal_operation_id': event[0],
        'causal_original_ref': event[2], 'causal_original_digest': event[3], 'plan_ref': expression.plan_ref.ref,
        'plan_revision': expression.plan_ref.version, 'plan_original_digest': plan_digest,
        'generation': requirements['activation_generation'], 'graph_incarnation': requirements['graph_incarnation'],
        'graph_revision': metadata[1], 'graph_epoch': epoch[0], 'phases': phases,
        'reviewed_content_digest': content.digest, 'first_effect_id': first.segment.effect_id,
        'budget_lease_ref': parent.lease_id, 'grant_id': parent.grant_id, 'grant_version': parent.version,
        'grant_digest': canonical_digest(parent), 'deadline_utc': min(plan.valid_until_utc, content.valid_until, parent.valid_until_utc),
        'source_refs': sorted({v.key.token for v in content.read_versions if v.key.type_name == 'memory.source'})}
    return terms, results, plan, content


_INPUT_FIELDS = {'namespace','contact_id','operation_id','request_digest','dedupe_key','causal_operation_id',
    'causal_original_ref','causal_original_digest','plan_ref','plan_revision','plan_original_digest','generation',
    'graph_incarnation','graph_revision','graph_epoch','phases','reviewed_content_digest','first_effect_id',
    'budget_lease_ref','grant_id','grant_version','grant_digest','deadline_utc','source_refs'}


def validate_background_inputs_v1(raw):
    from math import isfinite
    if (type(raw) is not dict or set(raw) != _INPUT_FIELDS
            or type(raw['namespace']) is not dict or set(raw['namespace']) != {'bot_id','persona_id'}
            or type(raw['phases']) is not list or len(raw['phases']) != 2
            or [p['phase'] for p in raw['phases']] != ['contact_generation','contact_review']
            or any(set(p) != {'phase','job_id','prepared_digest','terminal_digest','cost_digest','result_digest','call_id'} for p in raw['phases'])
            or type(raw['deadline_utc']) not in {int,float} or not isfinite(raw['deadline_utc'])
            or type(raw['source_refs']) is not list or raw['source_refs'] != sorted(set(raw['source_refs']))
            or any(type(raw[k]) is not int or raw[k] < 0 for k in ('graph_revision','graph_epoch','generation','plan_revision','grant_version'))):
        raise ValueError('Contact background derived input closed schema differs')
    for key in ('request_digest','causal_original_digest','plan_original_digest','reviewed_content_digest','grant_digest'):
        if type(raw[key]) is not str or len(raw[key]) != 64 or any(c not in '0123456789abcdef' for c in raw[key]):
            raise ValueError('Contact background derived commitment differs')
    ns = NamespaceId(**raw['namespace'])
    for ref in raw['source_refs']:
        key = AtomKey.from_token(ref)
        if key.type_name != 'memory.source' or NamespaceId.from_key(key) != ns:
            raise ValueError('Contact background source closure crossed its namespace')
    return raw
