"""Closed storage inventory codecs for installed domain stage originals/outbox.

These decoders validate retained bytes, never confer current source or execution
permission. Stage originals are content-bearing; deletion uses all actual read
keys plus explicitly decoded provenance roots.
"""
from dataclasses import fields
import json
import math

from ..graph_types import AtomKey
from ..runtime_contracts import AuthorityContext, OperationIdentity, NamespaceId, canonical_digest, canonical_serialize
from .domain_production_contracts_v1 import ProductionOwnerGuardV1, ProductionPolicyRefV1, ProductionOriginalRefV1
from .domain_production_originals_v1 import _receipt
from .domain_production_registry_v1 import installed_operation_v1

ORIGINAL_COLUMNS = ('bot','persona','operation_id','domain','operation_kind','request_digest','original_digest',
    'original_payload_json','read_versions_json','bundle_digest','receipt_json','receipt_digest')
OUTBOX_COLUMNS = ('bot','persona','dedupe_key','causal_operation_id','receiver_domain','event_kind',
    'original_ref','original_digest','state','consumer_operation_id','receipt_json')
_PAYLOAD_FIELDS = {'schema','request','namespace','identity','authority','parent_budget','now_utc','owner_guard',
    'policy_refs','read_versions','query_coverage','observed_originals','provenance','writes','coverage',
    'missing_inputs','continuation_ref'}
_EVENTS = {
    'action_outcome_observed_requires_current_life_qualification':'d10',
 'values_evaluated':'d08', 'persona_growth_requires_commitment_reevaluation':'d08',
 'persona_growth_requires_life_reevaluation':'d10', 'body_effect_settled':'d10',
 'relationship_changed_requires_action_recheck':'d08','boundary_changed_requires_action_recheck':'d08',
 'boundary_changed_requires_contact_recheck':'d10','source_correction_requires_boundary_recheck':'d08',
 'source_correction_requires_contact_recheck':'d10','bilateral_commitment_established':'d10',
 'joint_plan_adopted_requires_activity_qualification':'d10','joint_plan_adopted_requires_next_node_action':'d08',
 'actual_life_outcome_available_for_growth':'d01','qualified_contact_opportunity_requires_action':'d08',
 'actual_internal_experience_requires_encoding':'d06','actual_offline_simulation_experiences_require_encoding':'d06',
 'cognitive_execution_requires_current_adoption':'d07',
}


def _text(value):
    if type(value) is not str or not 1 <= len(value) <= 4096:
        raise ValueError('domain storage locator is invalid')
    return value


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('domain storage commitment is invalid')
    return value


def _key(ref, namespace):
    key=AtomKey.from_token(ref)
    if NamespaceId.from_key(key)!=namespace:
        raise ValueError('domain storage Graph locator crossed namespace')
    return key


def _version(raw, namespace):
    if type(raw) is not dict or set(raw)!={'key','revision'} or type(raw['revision']) is not int or raw['revision']<0:
        raise ValueError('domain storage Graph version differs')
    return _key(raw['key'],namespace),raw['revision']


def decode_domain_production_original_row_v1(row, namespace, *, registry):
    if (type(namespace) is not NamespaceId or len(row)!=len(ORIGINAL_COLUMNS)
            or tuple(row[:2])!=namespace.as_tuple):
        raise ValueError('domain stage row namespace/schema differs')
    data=dict(zip(ORIGINAL_COLUMNS,row,strict=True));kind=data['operation_kind'];domain=data['domain']
    operation=installed_operation_v1(kind)
    if operation.domain!=domain:
        raise ValueError('domain stage row kind is not installed')
    for field in ('request_digest','original_digest','bundle_digest','receipt_digest'):_digest(data[field])
    value=json.loads(data['original_payload_json'])
    if (type(value) is not dict or set(value)!=_PAYLOAD_FIELDS
            or canonical_serialize(value)!=data['original_payload_json'] or canonical_digest(value)!=data['original_digest']
            or value['schema']!=domain+'.current-'+kind+'.v1' or value['namespace']!={'bot_id':namespace.bot_id,'persona_id':namespace.persona_id}):
        raise ValueError('domain stage original exact bytes/schema differ')
    from ..workbench_api.domain_operations_v1 import decode_request_v1
    decode_request_v1(kind,value['request'])
    identity=value['identity'];authority=value['authority']
    if (type(identity) is not dict or set(identity)!={f.name for f in fields(OperationIdentity)}
            or identity['operation_id']!=data['operation_id'] or type(authority) is not dict
            or set(authority)!={f.name for f in fields(AuthorityContext)} or authority['namespace']!=value['namespace']
            or type(value['now_utc']) not in (float,int) or not math.isfinite(value['now_utc'])
            or type(value['read_versions']) is not list or len(value['read_versions'])>1024):
        raise ValueError('domain stage identity/authority/read envelope differs')
    versions=tuple(_version(v,namespace) for v in value['read_versions'])
    if len({key for key,_ in versions})!=len(versions):raise ValueError('domain stage repeats read key')
    reads=json.loads(data['read_versions_json'])
    if (canonical_serialize(reads)!=data['read_versions_json']
            or reads!=[[key.token,revision] for key,revision in versions]):
        raise ValueError('domain stage erasure read closure differs')
    owner=value['owner_guard']
    if type(owner) is not dict or set(owner)!={f.name for f in fields(ProductionOwnerGuardV1)}:
        raise ValueError('domain stage Owner original differs')
    ProductionOwnerGuardV1(**owner);_key(owner['grant_ref'],namespace)
    if type(value['policy_refs']) is not list or len(value['policy_refs'])>128:raise ValueError('domain policy inventory bound differs')
    for policy in value['policy_refs']:ProductionPolicyRefV1(**policy)
    if type(value['observed_originals']) is not list or len(value['observed_originals'])>128:raise ValueError('domain original inventory bound differs')
    for original in value['observed_originals']:
        if type(original) is not dict or set(original)!={f.name for f in fields(ProductionOriginalRefV1)}:
            raise ValueError('domain original locator schema differs')
        _text(original['kind']);_text(original['original_ref']);_digest(original['original_digest'])
        if type(original['read_versions']) is not list or len(original['read_versions'])>1024:raise ValueError('domain original read bound differs')
        for version in original['read_versions']:_version(version,namespace)
    if type(value['query_coverage']) is not list or len(value['query_coverage'])>64:raise ValueError('domain query inventory bound differs')
    for page in value['query_coverage']:
        if type(page) is not dict or set(page)!={'epoch','type_id','row_versions','complete','continuation_ref'}:
            raise ValueError('domain query page schema differs')
        if (page['epoch'].get('namespace')!=value['namespace'] or type(page['complete']) is not bool
                or page['complete']!=(page['continuation_ref'] is None) or len(page['row_versions'])>128):
            raise ValueError('domain query scope/coverage differs')
        registry.spec(page['type_id'])
        for version in page['row_versions']:_version(version,namespace)
    if type(value['writes']) is not list or len(value['writes'])>64:raise ValueError('domain output bound differs')
    keys={key for key,_ in versions}
    for write in value['writes']:
        if type(write) is not dict or set(write)!={'key','value','dependencies'}:raise ValueError('domain Graph write schema differs')
        key=_key(write['key'],namespace);spec=registry.spec(key.type_name)
        if key not in keys or spec.writer_domain!=domain or key.owner.kind not in spec.owner_kinds:
            raise ValueError('domain output is outside exact writer/read closure')
        spec.validator(write['value'])
        for ref in write['dependencies']:
            if _key(ref,namespace) not in keys:raise ValueError('domain output dependency omitted')
    from .domain_production_erasure_v1 import validate_domain_stage_provenance_v1
    if kind.startswith('input:'):
        provenance=value['provenance']
        expected={'producer_kind','input_request_digest'}
        if kind == 'input:set_contact_policy' and 'owner_contact_policy_original' in provenance:
            expected.add('owner_contact_policy_original')
            from ..authority_service.d10_contact_policy_service_v1 import contact_policy_original_from_wire_v1
            policy_original=contact_policy_original_from_wire_v1(provenance['owner_contact_policy_original'])
            if (policy_original.namespace != namespace or policy_original.action != 'issue'
                    or canonical_digest(policy_original.policy) != canonical_digest(value['request']['policy'])):
                raise ValueError('contact-policy approval differs from its actual input adoption')
            qualified=tuple(original for original in value['observed_originals']
                if original['original_ref']==policy_original.original_ref)
            if (len(qualified)!=1 or qualified[0]['kind']!='d10.owner_contact_policy'
                    or qualified[0]['original_digest']!=policy_original.digest):
                raise ValueError('contact-policy mirror lost its actual Authority original reference')
        if (type(provenance) is not dict or set(provenance)!=expected
                or provenance['producer_kind']!=kind[len('input:'):]
                or provenance['input_request_digest']!=canonical_digest(value['request'])):
            raise ValueError('domain input producer provenance differs')
        extra=()
    elif domain == 'd07':
        from .d07_behavior_stage_codec_v1 import validate_d07_behavior_provenance_v1
        extra=validate_d07_behavior_provenance_v1(kind,value['provenance'])
    else:
        extra=validate_domain_stage_provenance_v1(domain,kind,value['provenance'])
    for ref in extra:_key(ref,namespace)
    if value['coverage'] not in {'complete','partial','deferred','waiting_for_original'}:
        raise ValueError('domain stage coverage is invalid')
    if type(value['missing_inputs']) is not list or any(type(v) is not str or not v for v in value['missing_inputs']):
        raise ValueError('domain stage missing input labels differ')
    receipt_raw=json.loads(data['receipt_json']);receipt=_receipt(receipt_raw)
    if (canonical_serialize(receipt_raw)!=data['receipt_json'] or canonical_digest(receipt)!=data['receipt_digest']
            or receipt.operation_id!=data['operation_id'] or receipt.operation_digest!=data['bundle_digest']):
        raise ValueError('domain stage actual receipt commitment differs')
    return {'content_bearing':True,'graph_refs':tuple(sorted({key.token for key in keys}|set(extra))),
        'operation_id':data['operation_id'],'domain':domain,'operation_kind':kind,'original_digest':data['original_digest']}


def decode_domain_production_outbox_row_v1(row, namespace, *, db=None):
    if len(row)!=len(OUTBOX_COLUMNS) or tuple(row[:2])!=namespace.as_tuple:
        raise ValueError('domain followup outbox row schema/namespace differs')
    data=dict(zip(OUTBOX_COLUMNS,row,strict=True))
    if _EVENTS.get(data['event_kind']) != data['receiver_domain']:
        from .d07_behavior_stage_codec_v1 import decode_d07_followup_event_v1
        decode_d07_followup_event_v1(data['event_kind'], data['receiver_domain'])
    if data['state'] not in {'pending','waiting','completed','retired'}:
        raise ValueError('unregistered domain followup event/state')
    for field in ('causal_operation_id','original_ref'):_text(data[field])
    _digest(data['original_digest']);_digest(data['dedupe_key'])
    if data['dedupe_key']!=canonical_digest((namespace,data['causal_operation_id'],data['receiver_domain'],data['event_kind'])):
        raise ValueError('domain followup exact once identity differs')
    if data['state']=='pending' and (data['consumer_operation_id'] is not None or data['receipt_json'] is not None):
        raise ValueError('unconsumed followup claims a consumer receipt')
    if data['receipt_json'] is not None:
        value=json.loads(data['receipt_json'])
        expected={'schema','resolver_version','dedupe_key','causal_operation_id','causal_original_digest','trigger_original_digest',
            'manifest_digest','state','observed_epoch','completed_commands','missing_originals',
            'continuation_ref','consumer_operation_id'}
        if (type(value) is not dict or set(value)!=expected or canonical_serialize(value)!=data['receipt_json']
                or value['schema']!='sylanne.domain-followup-disposition.v1'
                or value['resolver_version']!='sylanne.domain-followup-resolver.v1'
                or any(value[name]!=data[name] for name in ('dedupe_key','causal_operation_id','state','consumer_operation_id'))
                or value['trigger_original_digest']!=data['original_digest']
                or type(value['observed_epoch']) is not int or value['observed_epoch']<0
                or type(value['completed_commands']) is not list or len(value['completed_commands'])>16
                or type(value['missing_originals']) is not list or len(value['missing_originals'])>128):
            raise ValueError('domain followup disposition exact fields differ')
        _digest(value['manifest_digest']);_digest(value['causal_original_digest'])
        for missing in value['missing_originals']:_text(missing)
        if value['continuation_ref'] is not None:_text(value['continuation_ref'])
        if db is None:raise ValueError('domain followup disposition requires actual durable receipt joins')
        causal=db.execute('SELECT original_digest FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND operation_id=?',
            (*namespace.as_tuple,data['causal_operation_id'])).fetchone()
        if causal!=(value['causal_original_digest'],):raise ValueError('followup causal adoption changed')
        seen=set()
        for item in value['completed_commands']:
            if type(item) is not dict or set(item)!={'command_digest','operation_id','receipt_digest'}:
                raise ValueError('domain followup completed command fields differ')
            _digest(item['command_digest']);_digest(item['receipt_digest']);_text(item['operation_id'])
            if item['command_digest'] in seen:raise ValueError('domain followup command repeats')
            seen.add(item['command_digest'])
            actual=db.execute('SELECT receipt_digest FROM graph_domain_production_originals_v1 '
                'WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,item['operation_id'])).fetchone()
            if actual!=(item['receipt_digest'],):raise ValueError('domain followup lost its actual adopted receipt')
        actual=db.execute('SELECT receipt_json FROM graph_owner_domain_attempts_v3 '
            'WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,data['consumer_operation_id'])).fetchone()
        if actual is None or actual[0] is None:raise ValueError('domain followup current disposition original missing')
        saved=json.loads(actual[0])
        if saved!=value and saved.get('followup_disposition')!=value:
            raise ValueError('domain followup differs from actual atomic Owner receipt')
    return {'content_bearing':False,'causal_operation_id':data['causal_operation_id'],
        'original_ref':data['original_ref'],'original_digest':data['original_digest']}
