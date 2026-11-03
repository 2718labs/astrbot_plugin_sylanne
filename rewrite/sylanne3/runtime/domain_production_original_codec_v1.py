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
 'ordinary_continuity_basis_available_for_screen':'d01',
 'ordinary_continuity_deep_required':'d01',
 'ordinary_continuity_assessment_available':'d01',
 'ordinary_continuity_attention_available_for_service':'d07',
 'ordinary_continuity_cognition_adopted_v1':'d01',
 'single_event_growth_review_required_v1':'d01',
 'd01.single_event_review_case_registered_v1':'d07',
 'single_event_review_attention_available_for_service':'d07',
 'single_event_review_cognition_adopted_v1':'d01',
 'commitment_terms_accepted_requires_current_performance_qualification':'d08',
 'commitment_fulfilled_requires_current_plan_reevaluation':'d08',
 'conditioned_simulation_committed_v1':'d07',
 'conditioned_observed_outcome_committed_v1':'d07',
 'conditioned_calibration_resolution_committed_v1':'d01',
 'conditioned_method_review_committed_v1':'d01',
 'conditioned_conditions_committed_v1':'d07',
 'conditioned_life_phase_committed_v1':'d10',
 'conditioned_self_candidate_available':'d01',
 'conditioned_self_adopted_requires_choice_recheck':'d08',
 'conditioned_self_adopted_requires_life_projection':'d10',
 'conditioned_life_strategy_projected':'d10',
 'prediction_registered':'d07',
 'general_growth_intent_available_for_future_trial':'d01',
 'general_growth_trial_start_available_for_observation':'d01',
 'general_growth_trial_completed_for_adoption':'d01',
 'general_growth_action_outcome_available':'d01',
 'owner_source_note_task_submitted_v1':'d11',
 'artifact_draft_phase_content_adopted':'d11',
 'artifact_draft_phase_model_queued':'d11',
 'artifact_phase_action_proposal_available':'d11',
 'artifact_draft_phase_structurally_verified':'d11',
 'actual_artifact_phase_assessment_available':'d11',
 'foreground_cycle_ready':'d11',
 'artifact_draft_root_registered':'d11',
 'artifact_task_wait_registered':'d11',
 'artifact_task_amendment_adopted':'d10',
 'foreground_post_c02_cause_available':'d11',
 'artifact_draft_model_queued':'d11',
 'artifact_draft_content_adopted':'d11',
 'artifact_goal_plan_available':'d10',
 'artifact_project_definition_available':'d03',
 'artifact_project_context_available':'d08',
 'artifact_action_proposal_available':'d11',
 'personal_plan_revision_available':'d10',
 'personal_step_requires_current_final_admission':'d11',
 'personal_step_wait_condition_required':'d11',
 'project_continuation_updated':'d08',
 'actual_project_result_available':'d07',
 'general_growth_attention_available_for_service':'d07',
 'project_checkpoint_wait_registered':'d11',
    'action_outcome_observed_requires_current_life_qualification':'d10',
 'values_evaluated':'d08', 'persona_growth_requires_commitment_reevaluation':'d08',
 'persona_growth_requires_life_reevaluation':'d10', 'body_effect_settled':'d10',
 'relationship_changed_requires_action_recheck':'d08','boundary_changed_requires_action_recheck':'d08',
 'boundary_changed_requires_contact_recheck':'d10','source_correction_requires_boundary_recheck':'d08',
 'source_correction_requires_contact_recheck':'d10','bilateral_commitment_established':'d10',
 'joint_plan_adopted_requires_activity_qualification':'d10','joint_plan_adopted_requires_next_node_action':'d08','joint_node_observation_requires_node_recheck':'d08','joint_external_semantic_question_requires_fair_cognition':'d07',
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
    from .domain_production_registry_v1 import _FOREGROUND_OPERATIONS, _PERSONAL_OPERATIONS, _ARTIFACT_OPERATIONS, _POSTCONDITION_OPERATIONS
    if kind in _FOREGROUND_OPERATIONS or kind in _PERSONAL_OPERATIONS or kind in _ARTIFACT_OPERATIONS or kind in _POSTCONDITION_OPERATIONS or kind in {"register_artifact_draft_root", "owner_stop_reply_v1", "adopt_owner_artifact_project_context_v1", "register_general_growth_attention_v1"}:
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        decode_typed_production_value_v1(value['request'], operation.request_type)
    else:
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
        from ..domains.d03.world_history_v1 import WORLD_OPERATIONS
        mesh_companion = kind in WORLD_OPERATIONS and spec.writer_domain=="d11" and key.type_name=="d11.semantic_tick.v1"
        if key not in keys or spec.writer_domain!=domain and not mesh_companion or key.owner.kind not in spec.owner_kinds:
            raise ValueError('domain output is outside exact writer/read closure')
        if key.type_name == 'd05.contribution':
            from ..domains.d05.relationship import decode_relationship_contribution_payload_v1
            decode_relationship_contribution_payload_v1(write['value'])
        elif key.type_name == 'd05.relationship_projection':
            from ..domains.d05.relationship import decode_relationship_projection_payload_v1
            decode_relationship_projection_payload_v1(write['value'])
        else:
            spec.validator(write['value'])
        for ref in write['dependencies']:
            if _key(ref,namespace) not in keys:raise ValueError('domain output dependency omitted')
    if (kind in {'freeze_general_growth_intent_v1','register_general_growth_trial_start_v1',
            'derive_general_growth_trial_v1','adopt_general_growth_v1'}
            and value['coverage']=='complete' and value['provenance']=={}):
        raise ValueError('complete General growth original lacks actual verified provenance')
    from .domain_production_erasure_v1 import validate_domain_stage_provenance_v1
    if kind in _POSTCONDITION_OPERATIONS:
        extra=validate_domain_stage_provenance_v1(domain,kind,value['provenance'])
    elif kind.startswith('input:'):
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
    elif domain == 'd07' and kind=='register_single_event_review_attention_v1':
        from .d07_single_event_review_v1 import validate_single_event_review_registration_provenance_v1
        extra=validate_single_event_review_registration_provenance_v1(value['provenance']) if value['coverage']=='complete' else ()
    elif domain == 'd07' and kind=='register_ordinary_continuity_attention_v1':
        from .d07_ordinary_continuity_attention_v1 import validate_ordinary_continuity_registration_provenance_v1
        extra=validate_ordinary_continuity_registration_provenance_v1(value['provenance']) if value['coverage']=='complete' else ()
    elif domain == 'd07' and kind=='register_general_growth_attention_v1':
        from .d07_general_growth_attention_v1 import validate_general_growth_registration_provenance_v1
        extra=validate_general_growth_registration_provenance_v1(value['provenance']) if value['coverage']=='complete' else ()
    elif domain == 'd07' and kind in {'serve_concern','advance_reflection','run_simulation'}:
        from .d07_behavior_stage_codec_v1 import validate_d07_behavior_provenance_v1
        extra=validate_d07_behavior_provenance_v1(kind,value['provenance'])
    else:
        extra=validate_domain_stage_provenance_v1(domain,kind,value['provenance'])
    from .habit_census_provenance_v1 import validate_habit_census_payload_v1
    validate_habit_census_payload_v1(value)
    for ref in extra:_key(ref,namespace)
    if value['coverage'] not in {'complete','partial','deferred','waiting_for_original'}:
        raise ValueError('domain stage coverage is invalid')
    if type(value['missing_inputs']) is not list or any(type(v) is not str or not v for v in value['missing_inputs']):
        raise ValueError('domain stage missing input labels differ')
    receipt_raw=json.loads(data['receipt_json']);receipt=_receipt(receipt_raw)
    if (canonical_serialize(receipt_raw)!=data['receipt_json'] or canonical_digest(receipt)!=data['receipt_digest']
            or receipt.operation_id!=data['operation_id'] or receipt.operation_digest!=data['bundle_digest']):
        raise ValueError('domain stage actual receipt commitment differs')
    return {'content_bearing':kind != 'owner_stop_reply_v1','graph_refs':tuple(sorted({key.token for key in keys}|set(extra))),
        'operation_id':data['operation_id'],'domain':domain,'operation_kind':kind,'original_digest':data['original_digest']}



def _ordinary_service_command_receipt_v1(db,namespace,data,value,item):
    """Join the committed Serve invocation; this does not assert model completion."""
    from .d07_execution_v1 import d07_execution_ids_v1
    if(data['event_kind'] not in {'ordinary_continuity_attention_available_for_service','single_event_review_attention_available_for_service'}
            or data['receiver_domain']!='d07'):
        return None
    op=item['operation_id']
    row=db.execute('SELECT receipt_json FROM graph_owner_domain_attempts_v3 '
        'WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,op)).fetchone()
    if row is None or row[0]is None:raise ValueError('ordinary service command lacks its actual Owner preparation receipt')
    result=json.loads(row[0]);job=d07_execution_ids_v1(namespace,op,'concern')['job']
    if(canonical_serialize(result)!=row[0] or result.get('schema')!='sylanne.domain-production-receipt.v1'
            or result.get('domain')!='d07'or result.get('operation_kind')!='serve_concern'
            or result.get('operation_id')!=op or result.get('original_ref')!='d07-prepared:'+op
            or result.get('coverage')!='deferred' or result.get('continuation_ref')!=job
            or result.get('missing_inputs')!=['actual_d07_original_execution']
            or result.get('job_states')!=[[job,'queued']]):
        raise ValueError('ordinary service handoff changed its exact native prepared/job result')
    receipt=_receipt(result['receipt'])
    if(receipt.status!='committed'or receipt.operation_id!=result.get('prepare_operation_id')
            or receipt.activity_id!=result.get('activity_id') or canonical_digest(receipt)!=item['receipt_digest']
            or result.get('receipt_digest')!=item['receipt_digest']):
        raise ValueError('ordinary service handoff is not the actual preparation Graph receipt')
    native=db.execute('SELECT payload_digest,signature FROM graph_d07_execution_originals_v1 '
        'WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
        (*namespace.as_tuple,'prepare_commit',job)).fetchone()
    prepared=db.execute('SELECT payload_digest,signature FROM graph_d07_execution_originals_v1 '
        'WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
        (*namespace.as_tuple,'prepared',job)).fetchone()
    actual=db.execute('SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations '
        'WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,receipt.operation_id)).fetchone()
    if(native is None or prepared is None or native[0]!=result.get('original_digest')
           
            or actual!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)):
        raise ValueError('ordinary service handoff lost its actual signed native originals/preparation bundle')
    prior=result.get('followup_disposition')
    if(type(prior)is not dict or prior.get('dedupe_key')!=data['dedupe_key']
            or prior.get('causal_operation_id')!=data['causal_operation_id']
            or prior.get('causal_original_digest')!=value['causal_original_digest']
            or prior.get('trigger_original_digest')!=data['original_digest']
            or prior.get('state')!='waiting'or prior.get('continuation_ref')!=job
            or prior.get('completed_commands')!=[item]):
        raise ValueError('ordinary service handoff lacks the actual atomic waiting disposition')
    from .d11_types import runtime_job_key
    job_key=runtime_job_key(*namespace.as_tuple,receipt.activity_id,job)
    if not any(v.key==job_key and v.revision>0 for v in receipt.write_versions):
        raise ValueError('ordinary service job is not an actual preparation receipt write')
    # These are dependency locators. The C09 caller must authenticate the frozen
    # native rows through the official typed reader and actual issuer.
    dependencies=(
        ('graph_d07_execution_originals_v1',(*namespace.as_tuple,'prepared',job),prepared[0]),
        ('graph_d07_execution_originals_v1',(*namespace.as_tuple,'prepare_commit',job),native[0]))
    if data['event_kind']=='single_event_review_attention_available_for_service' and data['state']=='completed':
        from .d07_single_event_review_v1 import (single_event_review_adoption_original_ref_v1,
            single_event_review_cardinality_rejection_ref_v1)
        terminals=[]
        for kind,ref in (('single_event_review_adoption_v1',single_event_review_adoption_original_ref_v1(namespace,job)),
                ('single_event_review_cardinality_rejected_v1',single_event_review_cardinality_rejection_ref_v1(namespace,job))):
            header=db.execute('SELECT payload_digest FROM graph_d07_execution_originals_v1 '
                'WHERE bot=? AND persona=? AND kind=? AND original_ref=?',(*namespace.as_tuple,kind,ref)).fetchone()
            if header is not None:terminals.append(('graph_d07_execution_originals_v1',(*namespace.as_tuple,kind,ref),header[0]))
        if len(terminals)!=1:
            raise ValueError('completed review service requires its unique actual signed adoption/rejection dependency')
        dependencies=(*dependencies,*terminals)
    return dependencies,job_key.token


def decode_domain_production_outbox_row_v1(row, namespace, *, db=None):
    if len(row)!=len(OUTBOX_COLUMNS) or tuple(row[:2])!=namespace.as_tuple:
        raise ValueError('domain followup outbox row schema/namespace differs')
    data=dict(zip(OUTBOX_COLUMNS,row,strict=True))
    native_causal=[];native_commands=[];native_jobs=[];native_preparations=[]
    native_kind={'ordinary_continuity_attention_available_for_service':'ordinary_continuity_attention_v1',
        'ordinary_continuity_cognition_adopted_v1':'ordinary_continuity_adoption_v1',
        'single_event_review_attention_available_for_service':'single_event_review_attention_v1',
        'single_event_review_cognition_adopted_v1':'single_event_review_adoption_v1'}.get(data['event_kind'])
    if native_kind is not None:
        native_causal.append(('graph_d07_execution_originals_v1',
            (*namespace.as_tuple,native_kind,data['original_ref']),data['original_digest']))
    if data['event_kind']=='d01.single_event_review_case_registered_v1':
        native_causal.append(('graph_d01_production_inputs_v1',
            (*namespace.as_tuple,data['original_ref']),data['original_digest']))
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
        if type(value) is dict and value.get('schema') == 'd11.artifact-draft-wake-disposition.v1':
            if canonical_serialize(value) != data['receipt_json']:
                raise ValueError('C4 self disposition bytes are noncanonical')
            from .foreground_cycle_v1 import validate_artifact_draft_wake_disposition_v1
            validate_artifact_draft_wake_disposition_v1(db, namespace=namespace, row_data=data, value=value)
            return {'content_bearing': False, 'causal_operation_id': data['causal_operation_id'],
                'original_ref': data['original_ref'], 'original_digest':data['original_digest'],'native_causal_dependencies':(),
                'native_command_dependencies':(),'native_job_graph_refs':(),'native_preparation_operations':()}
        if type(value) is dict and value.get('schema')=='d11.artifact-task-wait-consumed.v1':
            if canonical_serialize(value)!=data['receipt_json']:raise ValueError('task wait disposition bytes changed')
            from .artifact_task_wait_consumer_v1 import validate_task_wait_disposition_v1
            validate_task_wait_disposition_v1(db,namespace=namespace,row_data=data,value=value)
            return {'content_bearing':False,'causal_operation_id':data['causal_operation_id'],
                'original_ref':data['original_ref'],'original_digest':data['original_digest'],'native_causal_dependencies':(),
                'native_command_dependencies':(),'native_job_graph_refs':(),'native_preparation_operations':()}
        if type(value) is dict and value.get('schema') == 'd11.owner-source-note-submit-consumed.v1':
            if canonical_serialize(value) != data['receipt_json']:
                raise ValueError('Owner task submit disposition bytes are noncanonical')
            from .owner_source_note_task_driver_v1 import validate_owner_task_submit_disposition_v1
            validate_owner_task_submit_disposition_v1(db,namespace=namespace,row_data=data,value=value)
            return {'content_bearing':False,'causal_operation_id':data['causal_operation_id'],
                'original_ref':data['original_ref'],'original_digest':data['original_digest'],'native_causal_dependencies':(),
                'native_command_dependencies':(),'native_job_graph_refs':(),'native_preparation_operations':()}
        expected={'schema','resolver_version','dedupe_key','causal_operation_id','causal_original_digest','trigger_original_digest',
            'manifest_digest','state','observed_epoch','completed_commands','missing_originals',
            'continuation_ref','consumer_operation_id'}
        from .domain_production_followups_v1 import _NATIVE_ATTENTION_JOB_SCHEMA_V1
        observed_job=type(value)is dict and value.get("schema")==_NATIVE_ATTENTION_JOB_SCHEMA_V1
        if observed_job:expected=expected|{"job_preparation"}
        if (type(value) is not dict or set(value)!=expected or canonical_serialize(value)!=data['receipt_json']
                or value['schema']not in {'sylanne.domain-followup-disposition.v1',_NATIVE_ATTENTION_JOB_SCHEMA_V1}
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
        if observed_job:
            dependencies,job_ref,preparation_op=_native_attention_observed_job_receipt_v1(db,namespace,data,value)
            native_commands.extend(dependencies);native_jobs.append(job_ref);native_preparations.append(preparation_op)
        seen=set()
        for item in value['completed_commands']:
            if type(item) is not dict or set(item)!={'command_digest','operation_id','receipt_digest'}:
                raise ValueError('domain followup completed command fields differ')
            _digest(item['command_digest']);_digest(item['receipt_digest']);_text(item['operation_id'])
            if item['command_digest'] in seen:raise ValueError('domain followup command repeats')
            seen.add(item['command_digest'])
            native=_ordinary_service_command_receipt_v1(db,namespace,data,value,item)
            if native is not None:
                native_commands.extend(native[0]);native_jobs.append(native[1])
            else:
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
        'original_ref':data['original_ref'],'original_digest':data['original_digest'],
        'native_causal_dependencies':tuple(native_causal),
        'native_command_dependencies':tuple(native_commands),'native_job_graph_refs':tuple(native_jobs),
        'native_preparation_operations':tuple(native_preparations)}

def _native_attention_observed_job_receipt_v1(db,namespace,data,value):
    from .domain_production_followups_v1 import (
        _NATIVE_ATTENTION_SERVICE_EVENTS_V1,validate_native_attention_job_preparation_v1)
    if data["event_kind"]not in _NATIVE_ATTENTION_SERVICE_EVENTS_V1 or data["receiver_domain"]!="d07":
        raise ValueError("native observed-job disposition has another event")
    p=validate_native_attention_job_preparation_v1(value["job_preparation"],namespace)
    from .domain_production_followups_v1 import native_attention_job_observer_operation_v1
    if (value["state"]not in {"waiting","completed"}
            or value["consumer_operation_id"]!=native_attention_job_observer_operation_v1(
                namespace,data["dedupe_key"],p,value["observed_epoch"])):
        raise ValueError("observed job metadata is not its exact actual observer operation")
    family="single_event_review"if data["event_kind"]=="single_event_review_attention_available_for_service"else"ordinary_continuity"
    if (p["family"]!=family or value["completed_commands"]
            or value["state"]=="waiting"and (value["continuation_ref"]!=p["job_id"]or value["missing_originals"]!=["actual_d07_original_execution"])
            or value["state"]=="completed"and (value["continuation_ref"]is not None or value["missing_originals"])):
        raise ValueError("native observed-job disposition changed its immutable family/cursor")
    actual=db.execute("SELECT receipt_json FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple,p["operation_id"])).fetchone()
    if actual is None or actual[0]is None:raise ValueError("observed Owner preparation lacks its actual saved receipt")
    result=json.loads(actual[0])
    if (canonical_serialize(result)!=actual[0]or result.get("schema")!="sylanne.domain-production-receipt.v1"
            or result.get("domain")!="d07"or result.get("operation_kind")!="serve_concern"
            or result.get("operation_id")!=p["operation_id"]or result.get("activity_id")!=p["activity_id"]
            or result.get("prepare_operation_id")!=p["prepare_operation_id"]
            or result.get("original_ref")!="d07-prepared:"+p["operation_id"]
            or result.get("original_digest")!=p["prepare_commit_original"]["original_digest"]
            or result.get("receipt_digest")!=p["prepare_receipt_digest"]
            or result.get("coverage")!="deferred"or result.get("continuation_ref")!=p["job_id"]
            or result.get("missing_inputs")!=["actual_d07_original_execution"]
            or result.get("job_states")!=[[p["job_id"],"queued"]]):
        raise ValueError("observed Owner preparation is not the actual original job handoff")
    receipt=_receipt(result["receipt"])
    if (receipt.status!="committed"or receipt.operation_id!=p["prepare_operation_id"]
            or canonical_digest(receipt)!=p["prepare_receipt_digest"]
            or not any(v.key.token==p["job_ref"]and v.revision==p["job_revision"]for v in receipt.write_versions)):
        raise ValueError("observed Owner job lacks its actual preparation receipt birth")
    ledger=db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",(*namespace.as_tuple,p["prepare_operation_id"])).fetchone()
    if ledger!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
        raise ValueError("observed Owner prepare receipt differs from actual W01 ledger")
    dependencies=[]
    for name,kind in (("prepared_original","prepared"),("prepare_commit_original","prepare_commit")):
        header=db.execute("SELECT payload_digest,signature FROM graph_d07_execution_originals_v1 "
            "WHERE bot=? AND persona=? AND kind=? AND original_ref=?",(*namespace.as_tuple,kind,p["job_id"])).fetchone()
        if header is None or header[0]!=p[name]["original_digest"]:
            raise ValueError("observed Owner job changed its exact immutable native original")
        dependencies.append(("graph_d07_execution_originals_v1",(*namespace.as_tuple,kind,p["job_id"]),header[0]))
    if value["state"]=="completed":
        if family=="single_event_review":
            from .d07_single_event_review_v1 import (
                single_event_review_adoption_original_ref_v1,single_event_review_cardinality_rejection_ref_v1)
            variants=(("single_event_review_adoption_v1",single_event_review_adoption_original_ref_v1(namespace,p["job_id"])),
                ("single_event_review_cardinality_rejected_v1",single_event_review_cardinality_rejection_ref_v1(namespace,p["job_id"])))
        else:
            from .d07_ordinary_continuity_cognition_v1 import ordinary_continuity_adoption_original_ref_v1
            variants=(("ordinary_continuity_adoption_v1",ordinary_continuity_adoption_original_ref_v1(namespace,p["job_id"])),)
        terminals=[]
        for kind,ref in variants:
            header=db.execute("SELECT payload_digest FROM graph_d07_execution_originals_v1 "
                "WHERE bot=? AND persona=? AND kind=? AND original_ref=?",(*namespace.as_tuple,kind,ref)).fetchone()
            if header is not None:terminals.append(("graph_d07_execution_originals_v1",(*namespace.as_tuple,kind,ref),header[0]))
        if len(terminals)!=1:raise ValueError("observed job completion lacks its unique actual adopted/rejected native dependency")
        dependencies.extend(terminals)
    return tuple(dependencies),p["job_ref"],p["operation_id"]

