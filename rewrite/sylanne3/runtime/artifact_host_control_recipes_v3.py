"""Fixed same-Work Artifact control locator recipes; no table-wide Body grants."""
from dataclasses import replace
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_serialize
from .domain_background_read_v3 import BackgroundReadNeededV3
from .source_correction_read_v3 import _heap

_LIFE='graph_d11_life_originals_v1'
_D07='graph_d07_execution_originals_v1'
_INPUT='graph_d10_production_inputs_v1'
_GRAPH_COLUMNS=frozenset({'token','revision','value','valid','type_name','event_id','event_bot','event_persona','event_session','dependencies'})
_JOB_COLUMNS=frozenset({'job_id','operation_id','activity_id','effect_id','bot_id','persona_id','snapshot_ref',
    'phase','work_kind','continuation_json','wake_condition_json','deadline_utc','budget_ref','resource_ref',
    'operator_versions_json','lease_holder','lease_expires_utc','fence','cancel_epoch','usage_json','result_ref'})
_LIFE_COLUMNS=frozenset({'bot','persona','kind','original_ref','producing_operation_id','payload_json','payload_digest','signature'})
_D07_COLUMNS=_LIFE_COLUMNS-{'producing_operation_id'}
_DOMAIN_COLUMNS=frozenset({'bot','persona','operation_id','domain','operation_kind','request_digest','original_digest',
    'original_payload_json','read_versions_json','bundle_digest','receipt_json','receipt_digest'})
_BUNDLE_COLUMNS=frozenset({'bot','persona','operation_id','digest','activity_id','effect_id','commit_seq','receipt_json'})
_VERSION_FIELDS=frozenset({'source_head','task_source_head','content_source_head','goal_head','plan_head','self_mapping_head'})
_VERSION_ARRAYS=frozenset({'source_read_versions','read_versions','actor_heads','source_heads'})
_GRAPH_FIELDS={'source_ref':{'memory.source'},'task_source_ref':{'memory.source'},'goal_ref':{'d08.goal.v1'},
    'plan_ref':{'d08.personal_plan.v1'},'project_ref':{'d10.life_project.v1'},
    'recipe_ref':{'d10.activity_recipe.v1'},'decision_ref':{'d08.decision_record.v2'},
    'interpretation_ref':{'d07.current_interpretation.v1'}}
_LIFE_FIELDS={'root_registration_ref':'draft_root_capability','objective_ref':'artifact_task_objective',
    'task_scope_ref':'artifact_task_scope','approval_original_ref':'artifact_standing_predecision_approval',
    'extent_original_ref':'artifact_task_text_extent','postcondition_contract_ref':'artifact_phase_postcondition_contract',
    'contract_ref':'artifact_phase_postcondition_contract','policy_ref':'artifact_phase_postcondition_policy',
    'content_adoption_ref':'c4_phase_adopted','prev_verified_original_ref':'c4_phase_verified',
    'verified_original_ref':'c4_phase_verified','readback_original_ref':'adopted_life',
    'file_result_ref':'adopted_life','activity_scope_ref':'activity_scope','prepared_original_ref':'prepared',
    'authorization_original_ref':'source_note_task_authorization'}
_LOCATOR_FIELDS=frozenset({'schema','namespace','selector','task','request','source_ref','task_source_ref',
    'source_refs','supporting_refs','source_head','task_source_head','content_source_head','source_heads',
    'source_read_versions','read_versions','read_rows','post_read_rows','actor_heads','goal_head','plan_head',
    'owner_guard','actor_ref','current_self_ref','current_self_digest','root_registration_ref','root_registration_digest',
    'c02_operation_id','installation_id','manifest_digest','operation_id','producing_operation_id',
    'registration_operation_id','prepare_operation_id','acquire_operation_id','adoption_operation_id',
    'job_id','call_id','quote_id','parent_budget_lease_ref','parent_grant_id','parent_grant_version','parent_grant_digest',
    'prepared_digest','frozen_ref','frozen_digest','request_digest','payload_digest','result_ref',
    'content_adoption_ref','content_adoption_digest','prev_verified_original_ref','prev_verified_original_digest',
    'verified_original_ref','verified_original_digest','readback_original_ref','readback_original_digest',
    'extent_original_ref','extent_original_digest','postcondition_contract_ref','postcondition_contract_digest',
    'contract_ref','contract_digest','policy_ref','policy_digest','objective_ref','objective_digest',
    'task_scope_ref','task_scope_digest','approval_original_ref','approval_original_digest','activity_scope_ref',
    'activity_scope_digest','authorization_original_ref','authorization_original_digest','goal_ref','plan_ref',
    'project_ref','recipe_ref','decision_ref','content','task_source','prior_content','target',
    'paid_original_ref','paid_original_digest','result_original_ref','result_original_digest','original_deadline_utc',
    'source_value_digest','prepared_original_ref','prepared_original_digest','terminal','write_commitments',
    'observation_basis_ref','observation_basis_digest','semantic_question_ref','semantic_question_digest'})

def _actual(state):
    from .artifact_host_control_metadata_v3 import control_state_for_dispatch_v3
    if control_state_for_dispatch_v3(state.reader)is not state or not state.source_complete:
        raise AuthorityUnavailable('Artifact recipe requires its actual completed same-Work Source qualification')
    return state

def _qualified_roots(state,roots):
    values=tuple(dict.fromkeys(roots))
    if not values:raise AuthorityUnavailable('Artifact original has no declared qualified Source roots')
    if any(AtomKey.from_token(ref)not in state.source_versions for ref in values):
        raise AuthorityUnavailable('Artifact original declares a Source outside the original qualified roots')
    return values

def _put(state,table,keys,key,column,family,roots,parent,field):
    identity=(table,tuple(keys),tuple(key),column)
    value={'family':family,'source_roots':tuple(roots),'parent':parent,'field':tuple(field)}
    previous=state.derived_refs_v3.get(identity)
    if previous is not None and previous['family']!=family:
        raise AuthorityUnavailable('Artifact actual locator has conflicting fixed family recipes')
    state.derived_refs_v3[identity]=value

def _graph(state,ref,roots,parent,field,revision=None,types=None):
    key=AtomKey.from_token(ref)
    if NamespaceId.from_key(key)!=state.reader.namespace or types is not None and key.type_name not in types:
        raise AuthorityUnavailable('Artifact declared Graph locator changed its exact namespace/type')
    if key.type_name=='memory.source':
        if key not in state.source_versions:raise AuthorityUnavailable('Artifact Source Body is not in actual ALL closure')
        if revision is not None and state.source_versions[key]!=revision:
            raise AuthorityUnavailable('Artifact historical Source version lacks its exact current qualified head')
    ns=state.reader.namespace.as_tuple
    for keys,actual in((('token',),(ref,)),(('token','bot','persona'),(ref,*ns))):
        for column in _GRAPH_COLUMNS:_put(state,'graph_atoms',keys,actual,column,'graph_head',roots,parent,field)
    if revision is not None and type(revision)is int and revision>0:
        for column in _GRAPH_COLUMNS:_put(state,'graph_history',('token','revision'),(ref,revision),column,
            'graph_history',roots,parent,field)

def _life(state,kind,ref,roots,parent,field,*,digest=None):
    if not ref:return
    key=(*state.reader.namespace.as_tuple,kind,ref)
    for column in _LIFE_COLUMNS:_put(state,_LIFE,('bot','persona','kind','original_ref'),key,column,
        'signed_original',roots,parent,field)
    previous=state.recipe_originals_v3.get((_LIFE,kind,ref))
    if previous is not None:
        old=previous.get('digest')
        if old is not None and digest is not None and old!=digest:
            raise AuthorityUnavailable('Artifact signed parents disagree on one actual child digest')
        if digest is None:digest=old
    state.recipe_originals_v3[_LIFE,kind,ref]={'roots':tuple(roots),'parent':parent,'field':tuple(field),'digest':digest}

def _operation(state,operation,roots,parent,field,activity=None):
    if not operation:return
    ns=state.reader.namespace.as_tuple
    for column in _DOMAIN_COLUMNS:_put(state,'graph_domain_production_originals_v1',('bot','persona','operation_id'),
        (*ns,operation),column,'domain_original',roots,parent,field)
    for column in _BUNDLE_COLUMNS:_put(state,'graph_bundle_operations',('bot','persona','operation_id'),
        (*ns,operation),column,'domain_original',roots,parent,field)
    from .domain_production_originals_v1 import PHYSICAL_TABLE
    for entry in state.verified_metadata_v3.values():
        layout=entry.get('physical_layout')
        if entry.get('operation_id')!=operation or layout is None or layout[0]!=PHYSICAL_TABLE:continue
        if layout[1]!='original_payload_cell_id' or entry['header'][:2]!=('d06','admit_owner_material_source_v1'):
            raise AuthorityUnavailable('Artifact recipe has an unregistered actual physical Domain producer')
        qualified=_qualified_roots(state,entry['source_roots'])
        columns=(_DOMAIN_COLUMNS-{'original_payload_json'})|{'original_payload_cell_id','prepared_digest'}
        for column in columns:
            _put(state,PHYSICAL_TABLE,('bot','persona','operation_id'),(*ns,operation),column,'domain_original',
                qualified,('actual_positive_domain_producer',operation,entry['payload_digest'],layout[2]),(column,))
    if activity is not None:
        for column in('reads','revisions','epoch_revision'):
            _put(state,'graph_events',('bot','persona','session','event_id'),(*ns,activity,operation),
                column,'domain_original',roots,parent,field)

def _job(state,job_id,activity,roots,parent,field):
    for column in _JOB_COLUMNS:_put(state,'runtime_jobs',('job_id',),(job_id,),column,'job_metadata',roots,parent,field)
    from .d11_types import runtime_job_key
    _graph(state,runtime_job_key(*state.reader.namespace.as_tuple,activity,job_id).token,roots,parent,field,types={'runtime.job'})

def _phase(state,selector,roots,parent):
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2,artifact_draft_phase_original_ref_v2
    from .artifact_phase_postconditions_v1 import artifact_phase_postcondition_contract_ref_v1,artifact_phase_assessment_original_ref_v1
    from .foreground_cycle_v1 import foreground_cycle_ids_v1
    ids=artifact_draft_model_ids_v2(selector);activity=foreground_cycle_ids_v1(state.reader.namespace,selector.task.c02_operation_id)[0]
    for suffix,ref in(('prepared',ids['job']),('frozen',ids['frozen']),('request',ids['request']),
            ('call',ids['call']),('paid',ids['paid']),('result',ids['result']),('adopted',ids['adopt']),
            ('verified',artifact_draft_phase_original_ref_v2(selector)+':verified')):
        _life(state,'c4_phase_'+suffix,ref,roots,parent,('phase_ids',suffix))
    _life(state,'artifact_phase_postcondition_contract',artifact_phase_postcondition_contract_ref_v1(selector),
        roots,parent,('phase_contract',))
    if not selector.generation:
        _life(state,'artifact_phase_assessment',artifact_phase_assessment_original_ref_v1(selector),roots,parent,('phase_assessment',))
    if not selector.generation:
        from .foreground_artifact_observation_plan_v3 import artifact_observation_ids_v1
        condition={'sample_check':'tone','check':'task_semantics'}.get(selector.phase_kind)
        if condition is not None:
            observation=artifact_observation_ids_v1(selector,condition)
            _life(state,'artifact_phase_observation_basis_v1',observation['basis'],roots,parent,('observation_basis',))
            _d07(state,observation,roots,parent)
    _job(state,ids['job'],activity,roots,parent,('phase_job',))
    for name in('prepare','acquire','adopt'):_operation(state,ids[name],roots,parent,('phase_ids',name),activity)
    state.recipe_quotes_v3.add((ids['quote'],1))

def _declared(state,value,roots,parent):
    """Only declared typed locator positions; arbitrary strings never become keys."""
    for name,types in _GRAPH_FIELDS.items():
        ref=value.get(name)
        if type(ref)is str and ref.startswith('['):_graph(state,ref,roots,parent,(name,),types=types)
    for name in _VERSION_FIELDS:
        item=value.get(name)
        if type(item)is dict and set(item)>={'key','revision'}:
            _graph(state,item['key'],roots,parent,(name,),item['revision'])
    for name in _VERSION_ARRAYS:
        for item in value.get(name,()):
            if type(item)is dict and set(item)>={'key','revision'}:_graph(state,item['key'],roots,parent,(name,),item['revision'])
            elif type(item)is list and len(item)==2 and type(item[0])is dict and set(item[0])>={'key','revision'}:
                _graph(state,item[0]['key'],roots,parent,(name,),item[0]['revision'])
    for name,kind in _LIFE_FIELDS.items():
        ref=value.get(name)
        if type(ref)is str and ref:
            digest=value.get(name.removesuffix('_ref')+'_digest')
            _life(state,kind,ref,roots,parent,(name,),digest=digest)
    phase=type(value.get('selector'))is dict and value['selector'].get('schema')=='d11.artifact-draft-phase-selector.v2'
    prefix='c4_phase_'if phase else'c4_'
    for name,suffix in(('paid_original_ref','paid'),('result_original_ref','result'),('frozen_ref','frozen')):
        if type(value.get(name))is str:
            _life(state,prefix+suffix,value[name],roots,parent,(name,),
                digest=value.get(name.removesuffix('_ref')+'_digest'))
    for name in('operation_id','producing_operation_id','registration_operation_id','prepare_operation_id',
            'acquire_operation_id','adoption_operation_id'):
        if type(value.get(name))is str:_operation(state,value[name],roots,parent,(name,))
    for name in('selector','task','request'):
        child=value.get(name)
        if type(child)is dict:
            if name=='selector':
                from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2,artifact_draft_from_wire_v2
                if child.get('schema')=='d11.artifact-draft-phase-selector.v2':
                    _phase(state,artifact_draft_from_wire_v2(child,ArtifactDraftPhaseSelectorV2),roots,parent)
            _declared(state,child,roots,parent)
    for name in('content','task_source','prior_content','target','terminal'):
        child=value.get(name)
        if type(child)is dict:_declared_embedded(state,child,roots,parent,(name,))

def _declared_embedded(state,value,roots,parent,path):
    if set(value)>={'ref','revision'}:
        _graph(state,value['ref'],roots,parent,path,value['revision'])
    if 'source_head'in value and type(value['source_head'])is dict:
        head=value['source_head']
        if set(head)>={'ref','version'}:_graph(state,head['ref'],roots,parent,(*path,'source_head'),head['version'])
    for name,kind in _LIFE_FIELDS.items():
        if type(value.get(name))is str:_life(state,kind,value[name],roots,parent,(*path,name),
            digest=value.get(name.removesuffix('_ref')+'_digest'))
    for name in('content','binding','payload'):
        child=value.get(name)
        if type(child)is dict:_declared_embedded(state,child,roots,parent,(*path,name))

def _d07(state,ids,roots,parent):
    from ..runtime_contracts import canonical_digest
    prepare='d07-prepare:'+ids['operation']
    acquire='d07-acquire:'+canonical_digest((state.reader.namespace,ids['operation']))[:48]
    refs=(('semantic_question',ids['question']),('prepared',ids['job']),('prepare_commit',ids['job']),
        ('request',ids['job']),('call',ids['call']),('result','d07-result:'+ids['call']),
        ('execution','d07-terminal:'+ids['call']))
    for kind,ref in refs:
        key=(*state.reader.namespace.as_tuple,kind,ref)
        for column in _D07_COLUMNS:
            _put(state,_D07,('bot','persona','kind','original_ref'),key,column,'signed_original',roots,parent,('d07_ids',kind))
        producer=(None if kind=='semantic_question'else prepare if kind in{'prepared','prepare_commit'}else acquire)
        state.recipe_originals_v3[_D07,kind,ref]={'roots':tuple(roots),'parent':parent,
            'field':('d07_ids',kind),'digest':None,'parent_producer':producer,
            'basis_ref':ids['basis'],'job_id':ids['job'],'operation_id':ids['operation']}
    _operation(state,prepare,roots,parent,('observation_prepare',))
    _operation(state,acquire,roots,parent,('observation_acquire',))



def _index(state):
    _actual(state)
    roots=_qualified_roots(state,state.current_roots);r=state.reader;ns=r.namespace.as_tuple
    from .foreground_cycle_v1 import foreground_cycle_ids_v1
    activity,cycle=foreground_cycle_ids_v1(r.namespace,r.selector.c02_operation_id)
    _job(state,cycle,activity,roots,('selector',),('c02_cycle',))
    from ..domains.d03.self_perspective import self_mapping_key
    _graph(state,self_mapping_key(r.namespace).token,roots,('current_self',),('mapping',))
    _graph(state,owner_grant_key(*ns).token,roots,('current_owner',),('grant',))
    for key,revision in state.source_versions.items():_graph(state,key.token,roots,('actual_source_closure',),('readset',),revision)
    for column in('access_epoch','delete_epoch'):
        _put(state,'graph_authority_epochs',('bot','persona'),ns,column,'graph_head',roots,('source_epochs',),(column,))
    seed=state.seed
    if seed is not None:
        _operation(state,r.selector.c02_operation_id,roots,('actual_c02',),('operation',),seed.business[1])
        _operation(state,seed.ingress_op,roots,('actual_ingress',),('operation',))
        if seed.cycle is not None:
            _operation(state,seed.cycle[1],roots,('actual_cycle',),('create',),seed.cycle[2])
            for column in ('request_digest','receipt_json'):
                _put(state,'graph_owner_domain_attempts_v3',('bot','persona','operation_id'),
                    (*ns,seed.cycle[1]),column,'domain_original',roots,('actual_cycle',),('saved_receipt',))
        if state.profile=='post_commit_read':
            selector=r.selector
            _operation(state,selector.operation_id,roots,('actual_post_commit',),('operation',),
                state.post_commit_metadata.producer.receipt.activity_id)
            for column in ('request_digest','receipt_json'):
                _put(state,'graph_owner_domain_attempts_v3',('bot','persona','operation_id'),
                    (*ns,selector.operation_id),column,'domain_original',roots,('actual_post_commit',),('saved_receipt',))
        for column in('schema','bundle_digest','seal_json','evidence_json','quote_json','bundle_json'):
            _put(state,'graph_first_ingress_c02_committed_seals_v2',('bot','persona','operation_id'),
                (*ns,r.selector.c02_operation_id),column,'domain_original',roots,('actual_c02',),(column,))
        for column in('source_ref','platform_ref','conversation_ref','sender_ref','message_id','visibility','identity_json',
                'content_fingerprint','learned_at','bundle_digest'):
            _put(state,'graph_first_ingress_identity_v1',('bot','persona','operation_id'),(*ns,seed.ingress_op),column,
                'domain_original',roots,('actual_ingress',),(column,))
        for column in('content_fingerprint','learned_at','bundle_digest'):
            _put(state,'ingress_first_observations',('bot','persona','operation_id'),(*ns,seed.ingress_op),column,
                'domain_original',roots,('actual_ingress',),(column,))
        _put(state,'graph_first_ingress_intents_v2',('bot','persona','operation_id'),(*ns,seed.ingress_op),
            'identity_json','domain_original',roots,('actual_ingress',),('identity',))
        lease=seed.budget.lease
        for column in('lease_id','parent_id','bot_id','persona_id','currency','limits_json','used_json',
                'reserved_json','unconfirmed_json','version','state'):
            _put(state,'runtime_budget_leases',('lease_id',),(lease,),column,'budget_original',roots,('actual_root',),(column,))
        for column in('grant_json','signature','lease_id','version','status'):
            _put(state,'runtime_budget_grants',('lease_id','version'),(lease,seed.budget.header[1]),column,
                'budget_original',roots,('actual_root',),(column,))
        from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
        _life(state,'c1_task_intent',c1_task_intent_ref_v1(r.namespace,r.selector.c02_operation_id),roots,
            ('actual_c02',),('c1_task_intent',))
        if seed.root is not None:
            from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
            _life(state,'draft_root_capability',seed.root.registration_ref,roots,('actual_root',),('root',))
            _life(state,'artifact_task_scope',task_scope_ref_v1(seed.root.registration_ref),roots,('actual_root',),('task_scope',))
    locator=state.semantic_locators
    if locator is not None and locator.group is not None:
        from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2
        group=locator.group;phases=artifact_draft_phase_sequence_v2(group.selector.method_ref)
        for index in range(group.selector.phase_index+1):
            prior=group.completed_phase_originals[index-1]if index else(None,None)
            selector=replace(group.selector,phase_index=index,phase_kind=phases[index],
                prev_phase_original_ref=prior[0],prev_phase_original_digest=prior[1])
            _phase(state,selector,roots,('actual_phase_group',))
    for parent,entry in tuple(state.verified_metadata_v3.items()):
        inherited=_qualified_roots(state,entry['source_roots'])
        value=entry['projection']
        if parent[0]==_LIFE:
            _life(state,parent[1],parent[2],inherited,parent,('verified_metadata',),digest=entry['payload_digest'])
        _declared(state,value,inherited,parent)
        if parent[0]=='graph_domain_production_originals_v1':
            for name in('draft_root_capability','artifact_task_scope','artifact_task_objective',
                    'foreground_responsibility','responsibility'):
                child=value.get('provenance',{}).get(name)
                if type(child)is dict:_declared(state,child,inherited,parent)
        if entry.get('operation_id'):_operation(state,entry['operation_id'],inherited,parent,('actual_producer',))
        for name in('read_versions','write_versions'):
            for version in entry.get(name,()):
                _graph(state,version.key.token,inherited,parent,(name,),version.revision)
    metadata=state.draft_metadata
    if metadata is not None and metadata.task is not None:
        from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v1
        task=metadata.task;ids=artifact_draft_model_ids_v1(task)
        for kind,slot in (('c4_prepared','job'),('c4_frozen','frozen'),('c4_request','request'),
                ('c4_call','call'),('c4_paid','paid'),('c4_result','result'),('c4_adopted','adopt')):
            _life(state,kind,ids[slot],roots,('actual_legacy_task',task.digest),(slot,))
        _job(state,ids['job'],activity,roots,('actual_legacy_task',task.digest),('model_job',))
        for slot in ('prepare','acquire','adopt'):
            _operation(state,ids[slot],roots,('actual_legacy_task',task.digest),(slot,),activity)
        from .artifact_continuation_originals_v1 import artifact_continuation_operation_id_v1
        _operation(state,artifact_continuation_operation_id_v1(task),roots,('actual_legacy_task',task.digest),('selected_once',))
        continuation=metadata.continuation
        if continuation is not None and continuation.complete:
            for ref,(header,projection,digest,history)in continuation.graph_rows.items():
                _graph(state,ref,roots,('actual_legacy_census',ref,digest),('actual_head',),header['revision'])
                if history is not None:_graph(state,ref,roots,('actual_legacy_census',ref,digest),('actual_history',),history[0])
            for(kind,ref),(header,projection)in continuation.life_rows.items():
                _life(state,kind,ref,roots,('actual_legacy_signed',kind,ref),('metadata_eof',),digest=header[1])
        _life(state,'plan','artifact-draft-final-plan:'+task.digest[:40],roots,('actual_legacy_task',task.digest),('final_plan',))
        _life(state,'prepared','artifact-draft-life-prepare:'+task.digest[:40],roots,('actual_legacy_task',task.digest),('final_prepare',))
        for entry in state.verified_metadata_v3.values():
            value=entry['projection']
            if type(value)is not dict:continue
            for ref_field,version_field in (('resource_quote_ref','resource_quote_version'),('body_quote_ref','body_quote_version')):
                if type(value.get(ref_field))is str and type(value.get(version_field))is int:
                    state.recipe_quotes_v3.add((value[ref_field],value[version_field]))
        from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v1
        from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1,artifact_draft_action_keys_v1
        from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
        controls=artifact_goal_plan_keys_v1(r.namespace,c02_operation_id=task.c02_operation_id,root_registration_ref=task.root_registration_ref)
        for key in controls:_graph(state,key.token,roots,('actual_legacy_task',task.digest),('fixed_controls',))
        action=artifact_draft_action_keys_v1(r.namespace,c02_operation_id=task.c02_operation_id,root_registration_ref=task.root_registration_ref)[0]
        _graph(state,action.token,roots,('actual_legacy_task',task.digest),('fixed_action',))
        _graph(state,project_checkpoint_key_v1(r.namespace,controls[2].token).token,roots,('actual_legacy_task',task.digest),('checkpoint',))
        from .d03_life_project_context_v1 import life_project_context_keys_v1
        projects=(controls[2].token,)
        if continuation is not None:projects+=tuple(ref for ref in continuation.graph_rows if AtomKey.from_token(ref).type_name=='d10.life_project.v1')
        for project in dict.fromkeys(projects):
            for key in life_project_context_keys_v1(r.namespace,project):_graph(state,key.token,roots,('actual_legacy_task',task.digest),('project_context',))
        state.recipe_quotes_v3.add((ids['quote'],1))
        if metadata.prepared is not None:
            from ..runtime_contracts import canonical_digest
            dedupe=canonical_digest((r.namespace,metadata.prepared.operation_id,'d11','artifact_draft_model_queued'))
            _put(state,'graph_domain_production_outbox_v1',('bot','persona','dedupe_key'),(*ns,dedupe),
                'state','domain_original',roots,('actual_legacy_task',task.digest),('queued_once',))
    from .artifact_host_ingress_recall_metadata_v3 import index_ingress_control_points_v3
    index_ingress_control_points_v3(state,roots)
    completed=state.completed_stage_metadata_v3
    if completed is not None:
        if not completed.complete:raise AuthorityUnavailable('Artifact predecessor directory lacks actual complete EOF')
        for producer in completed.records:
            operation=producer.operation
            _operation(state,operation,roots,('actual_completed_predecessor',),('operation',),producer.receipt.activity_id)
            for column in ('request_digest','receipt_json'):
                _put(state,'graph_owner_domain_attempts_v3',('bot','persona','operation_id'),
                    (*ns,operation),column,'domain_original',roots,('actual_completed_predecessor',),('saved_receipt',))
    _completed_c1_binding_v3(state,roots)
    for quote in state.recipe_quotes_v3:
        for column in('quote_id','version','quote_json','signature'):
            _put(state,'runtime_resource_quotes',('quote_id','version'),quote,column,'budget_original',roots,
                ('actual_prepared',),('quote',))

def _original_metadata(state,table,kind,ref):
    from .artifact_host_ingress_recall_metadata_v3 import read_ingress_control_signed_metadata_v3
    handled,entry=read_ingress_control_signed_metadata_v3(state,table,kind,ref)
    if handled:return entry
    identity=(table,kind,ref)
    proof=state.recipe_originals_v3.get(identity)
    if proof is None:raise AuthorityUnavailable('Artifact signed Original has no actual declared parent locator')
    entry=state.verified_metadata_v3.get(identity)
    if entry is None:
        task=state.recipe_metadata_tasks_v3.get(identity)
        if task is None or not task.complete:
            raise BackgroundReadNeededV3(('artifact_control_recipe_metadata',table,kind,ref))
        if task.absent:return None
        entry=state.verified_metadata_v3[identity]
    expected=proof.get('digest')
    if expected is not None and entry['payload_digest']!=expected:
        raise AuthorityUnavailable('Artifact actual child EOF differs from its current declared parent digest')
    _qualified_roots(state,entry['source_roots'])
    return entry

def artifact_control_point_recipe_v3(state,table,columns,key_columns,key):
    _index(state);columns,key_columns,key=tuple(columns),tuple(key_columns),tuple(key)
    if table in(_LIFE,_D07):
        if key_columns!=('bot','persona','kind','original_ref')or key[:2]!=state.reader.namespace.as_tuple:
            raise AuthorityUnavailable('Artifact signed point crossed actual namespace/PK')
        _original_metadata(state,table,key[2],key[3])
    recipe=[]
    for column in columns:
        proof=state.derived_refs_v3.get((table,key_columns,key,column))
        if proof is None:raise AuthorityUnavailable('Artifact point has no exact declared column/PK lineage')
        recipe.append((column,proof['family']))
    return tuple(recipe)

def artifact_control_attachment_recipe_v3(state,table,key_columns,key,column,family):
    _index(state)
    proof=state.derived_refs_v3.get((table,tuple(key_columns),tuple(key),column))
    if proof is None or proof['family']!=family:
        raise AuthorityUnavailable('Artifact Body attachment has no exact actual declared locator family')
    if table in(_LIFE,_D07):_original_metadata(state,table,key[2],key[3])
    return _qualified_roots(state,proof['source_roots'])

def artifact_control_signed_recipe_v3(state,kind,ref,profile):
    if profile not in {'control_target_mode','control_phase_status'}:
        raise AuthorityUnavailable('Artifact signed projection is not an exact control profile')
    _index(state)
    if profile=='control_target_mode'and kind!='c4_phase_frozen':
        raise AuthorityUnavailable('Artifact target-mode projection is only its actual frozen phase Original')
    if profile=='control_phase_status'and kind not in{
            'c4_phase_request','c4_phase_call','c4_phase_paid','c4_phase_result','c4_phase_adopted'}:
        raise AuthorityUnavailable('Artifact phase status has no such actual signed Original kind')
    if(_LIFE,kind,ref)not in state.recipe_originals_v3:
        raise AuthorityUnavailable('Artifact signed status lost its exact current phase/once locator')

def artifact_control_locator_paths_v3(table,kind,path):
    if table not in {_LIFE,_D07,_INPUT}:raise AuthorityUnavailable('Artifact locator metadata has no exact signed table family')
    if not path:return True
    field=path[0]
    if field not in _LOCATOR_FIELDS:return False
    if field in {'source_refs','supporting_refs'}:return len(path)<=2
    if field in {'read_rows','post_read_rows'}:
        return len(path)<=2 or len(path)==3 and path[2]in {'ref','revision','valid'}
    if field in {'request','terminal'}:
        if len(path)>1 and path[1]in {'payload','request_json','result_json','frozen_json','observation'}:
            if field=='request':return False
            return len(path)<=2 or len(path)==3 and path[2]in {'status','readback'}
    if field=='content':
        if len(path)<=1:return True
        if path[1]in {'content_digest','content_length','source_refs','schema'}:return True
        return path[1]=='content'and(len(path)<=2 or len(path)==3 and path[2]in {'ref','revision','digest','schema'})
    if field=='target':return len(path)<=1 or path[1]in {'root_registration_ref','root_registration_digest','activity_id'}
    return not any(part in {'text','question','proposition','body','result_json','request_json','frozen_json','value_json'}for part in path)



class ArtifactControlRecipeMetadataTaskV3:
    """Whole signed locator EOF. It does not thaw a Source or frozen request."""
    def __init__(self,state,table,kind,ref):
        _index(state);proof=state.recipe_originals_v3.get((table,kind,ref))
        if proof is None:raise AuthorityUnavailable('Artifact locator metadata lacks an actual declared parent')
        if table not in {_LIFE,_D07}:raise AuthorityUnavailable('Artifact locator metadata has no exact signature recipe')
        self.state,self.table,self.kind,self.ref=state,table,kind,ref
        self.proof=proof;self.header=self.column=self.value=None
        self.complete=False;self.absent=False
    def advance(self,meter):
        from .artifact_host_control_metadata_v3 import _ControlColumnV3
        from .d11_life_preparation_v1 import SIGN_KIND as LIFE_SIGN
        from .d07_execution_v1 import SIGN_KIND as D07_SIGN
        s=self.state;r=s.reader;s.require_current_v3(meter)
        columns=(('producing_operation_id','payload_digest','signature')if self.table==_LIFE else('payload_digest','signature'))
        row=meter.read_fixed_row(r.db,self.table,columns,'bot=? AND persona=? AND kind=? AND original_ref=?',
            (*r.namespace.as_tuple,self.kind,self.ref))
        if self.header is None:
            if row is None:self.absent=True;self.complete=True;return True
            self.header=tuple(row)
            expected=self.proof.get('digest')
            digest=self.header[-2]
            if expected is not None and digest!=expected:
                raise AuthorityUnavailable('Artifact child signed digest differs from actual declared parent')
            self.column=_ControlColumnV3(s,('control_recipe_locator',self.table,self.kind),
                table=self.table,column='payload_json',key_columns=('bot','persona','kind','original_ref'),
                key=(*r.namespace.as_tuple,self.kind,self.ref))
            return False
        if tuple(row or())!=self.header:raise AuthorityUnavailable('Artifact signed locator header changed during EOF')
        if not self.column.advance(meter):return False
        digest,signature=self.header[-2:]
        if self.column.sha256!=digest:raise AuthorityUnavailable('Artifact locator whole canonical EOF differs from signed parent')
        r.graph._GraphCoordinator__d11_issuer._signer.verify(LIFE_SIGN if self.table==_LIFE else D07_SIGN,
            canonical_serialize((r.namespace,self.kind,self.ref,digest)),signature)
        self.value=self.column.require_v3(r)
        namespace=self.value.get('namespace')
        if namespace is not None and namespace!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}:
            raise AuthorityUnavailable('Artifact signed locator metadata crossed actual namespace')
        _require_locator_scope_v3(s,self.value,self.proof)
        if self.table==_LIFE:producer=self.header[0]
        else:
            producer=self.proof.get('parent_producer')
            if self.kind=='semantic_question':
                basis=s.verified_metadata_v3.get((_LIFE,'artifact_phase_observation_basis_v1',self.proof['basis_ref']))
                if basis is None:
                    _original_metadata(s,_LIFE,'artifact_phase_observation_basis_v1',self.proof['basis_ref'])
                    raise AuthorityUnavailable('Artifact semantic question lost actual observation basis metadata')
                producer=basis['projection']['registration_operation_id']
            if self.kind=='prepared'and self.value.get('prepare_operation_id')!=producer:
                raise AuthorityUnavailable('Artifact D07 prepared metadata changed actual preparation producer')
            if self.kind=='prepare_commit'and self.value.get('prepare_operation_id')!=producer:
                raise AuthorityUnavailable('Artifact D07 prepare commitment changed actual W01 producer')
        bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
            'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,producer))
        if bundle is None or type(bundle[3])is not int or bundle[3]<1:
            raise AuthorityUnavailable('Artifact locator has no actual positive W01 parent producer')
        roots=_qualified_roots(s,self.proof['roots'])
        _require_locator_sources_v3(s,self.value)
        s.verified_metadata_v3[self.table,self.kind,self.ref]={'projection':self.value,'header':self.header,
            'payload_digest':digest,'operation_id':producer,'source_roots':roots,'selector':None,
            'producer_header':tuple(bundle),'parent':self.proof['parent'],'field':self.proof['field']}
        self.complete=True;return True

def _require_locator_scope_v3(state,value,proof):
    """A child may only refine the actual task/cue named by its signed parent."""
    selector=value.get('selector')
    if selector is None:
        request=value.get('request')
        if type(request)is dict:selector=request.get('selector')or request.get('task')
    if type(selector)is dict:
        task=selector.get('task',selector)
        namespace=task.get('namespace')
        if namespace is not None and namespace!={'bot_id':state.reader.namespace.bot_id,'persona_id':state.reader.namespace.persona_id}:
            raise AuthorityUnavailable('Artifact locator nested task crossed actual namespace')
        if task.get('c02_operation_id')is not None:
            root=None if state.seed is None else state.seed.root
            if(task['c02_operation_id']!=state.reader.selector.c02_operation_id
                    or root is not None and task.get('root_registration_ref')!=root.registration_ref):
                raise AuthorityUnavailable('Artifact locator child changed actual C02/Root task')
    if value.get('c02_operation_id')is not None and value['c02_operation_id']!=state.reader.selector.c02_operation_id:
        raise AuthorityUnavailable('Artifact locator child changed actual C02')
    if value.get('installation_id')is not None and value['installation_id']!=state.reader.bundle.installation_policy.installation_id:
        raise AuthorityUnavailable('Artifact locator child changed actual installation')
    if value.get('manifest_digest')is not None and value['manifest_digest']!=state.reader.bundle.installation_policy.manifest_digest:
        raise AuthorityUnavailable('Artifact locator child changed actual installed manifest')

def _require_locator_sources_v3(state,value):
    refs=list(value.get('source_refs',()))+list(value.get('supporting_refs',()))
    for name in('source_ref','task_source_ref'):
        ref=value.get(name)
        if type(ref)is str and ref.startswith('['):refs.append(ref)
    for name in('source_head','task_source_head','content_source_head'):
        head=value.get(name)
        if type(head)is dict and 'key'in head:refs.append(head['key'])
    for name in('read_rows','post_read_rows'):
        for row in value.get(name,()):
            key=AtomKey.from_token(row['ref'])
            if key.type_name=='memory.source':refs.append(key.token)
    for ref in refs:
        key=AtomKey.from_token(ref)
        if key.type_name!='memory.source'or NamespaceId.from_key(key)!=state.reader.namespace or key not in state.source_versions:
            raise AuthorityUnavailable('Artifact child Original has an unqualified actual Source root')



def _completed_c1_binding_v3(state,roots):
    """Actual signed C1 Body refs; historical refs require this census lineage."""
    from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1,C1ArtifactTaskIntentOriginalV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..authority_service.v2_worker_model_result_contract import WorkerModelResultReadV1,from_wire
    from .domain_background_read_v3 import background_json_loads_v3
    import json
    r=state.reader;current=c1_task_intent_ref_v1(r.namespace,r.selector.c02_operation_id)
    metadata=state.draft_metadata
    historical={}if metadata is None or metadata.continuation is None else metadata.continuation.life_rows
    for request,point in tuple(r.points.items()):
        table,columns,keys,key=request
        if(table!=_LIFE or keys!=('bot','persona','kind','original_ref')
                or key[:3]!=(*r.namespace.as_tuple,'c1_task_intent')or not point.complete):continue
        ref=key[3];entry=state.verified_metadata_v3.get((_LIFE,'c1_task_intent',ref))
        if entry is None:continue
        if ref!=current and('c1_task_intent',ref)not in historical:continue
        column=point.values.get('payload_json')
        if column is None or not column.complete:continue
        if column.sha256!=entry['payload_digest']:
            raise AuthorityUnavailable('Artifact C1 Body differs from actual signed metadata EOF')
        value=decode_typed_production_value_v1(background_json_loads_v3(column),C1ArtifactTaskIntentOriginalV1)
        if(value.namespace!=r.namespace or ref!=c1_task_intent_ref_v1(r.namespace,value.c02_operation_id)
                or AtomKey.from_token(value.source_ref)not in state.source_versions):
            raise AuthorityUnavailable('Artifact C1 data ref changed its actual qualified Source/C02/namespace')
        if ref==current:
            if value.source_ref!=r.selector.source_ref:raise AuthorityUnavailable('Current C1 Body changed actual cue')
        else:
            header,projection=historical['c1_task_intent',ref]
            if(header[0]!=value.c02_operation_id or header[1]!=entry['payload_digest']
                    or projection['c02_operation_id']!=value.c02_operation_id or projection['source_ref']!=value.source_ref):
                raise AuthorityUnavailable('Historical C1 lacks actual same-census producer/Source lineage')
        worker=from_wire(json.loads(value.worker_read_json),WorkerModelResultReadV1)
        job=worker.request.job_id
        names=('source_id','source_revision','access_revision','budget_lease_id','budget_reservation_operation_id',
            'binding_digest','model_request_digest','call_id','request_json')
        qualified=_qualified_roots(state,entry['source_roots'])
        for name in names:
            _put(state,'runtime_encoding_call_bindings_v1',('bot','persona','job_id'),
                (*r.namespace.as_tuple,job),name,'domain_original',qualified,(_LIFE,'c1_task_intent',ref),
                ('worker_read_json','request','job_id'))
