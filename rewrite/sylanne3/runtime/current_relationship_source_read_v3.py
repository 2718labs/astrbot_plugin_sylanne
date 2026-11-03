"""Exact D05 production Owner Source Work on the common bounded kernel."""
from types import SimpleNamespace
from weakref import WeakKeyDictionary
import json
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
from ..domains.d01.production_operations_v1 import plain_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1,ProductionPolicyRefV1
from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1,production_read_plan_v1
from ..domains.d05.relationship_revision_v2 import PROFILE_TYPE,ESTIMATE_TYPE,CHECKPOINT_TYPE,CONTRIBUTION_TYPE,EXPECTATION_TYPE,RECIPROCITY_TYPE,REPAIR_TYPE
OPERATIONS=frozenset({'initialize_relationship_prior_v2','revise_boundary','input:register_boundary_intent','adopt_relationship_revision_v2','adopt_relationship_contribution','reevaluate_relationship'})
_STATES=WeakKeyDictionary()
_WRITES=WeakKeyDictionary()
_CORRECTION_ISSUER=object()
_CORRECTION_CONTEXTS=WeakKeyDictionary()
_CONTRIBUTION_FACTS=WeakKeyDictionary()
_CONTRIBUTION_TYPES=('d03.entity_anchor','d03.account_binding','d05.contribution','d05.relationship_projection')
_CONTRIBUTION_FIELDS={
    'd03.entity_anchor':('entity_id','status','creation_evidence_refs'),
    'd03.account_binding':('platform_namespace','platform_identifier','entity_id','valid_from','valid_until','verification_ref'),
    'd05.contribution':('subject_entity_ref','target_dimension','semantics','identity_status','source_refs','schema_version'),
    'd05.relationship_projection':('subject_entity_ref','dimension','status'),
}
_REEVALUATION_TYPES=('d05.boundary_rule','d05.contribution','d05.relationship_projection')
_REEVALUATION_FIELDS={'d05.boundary_rule':('source_refs','status'),'d05.contribution':('source_refs','subject_entity_ref','target_dimension'),'d05.relationship_projection':('subject_entity_ref','dimension')}
_HEAD_PATHS=tuple((name,)for name in ('source_refs','creation_evidence_refs'))
_POLICY_PATHS=(('namespace',),('policy_ref',),('revision',),('schema_version',),('policy_source_refs',),('dimension_rules','*','authored_prior_source_ref'))
_NUMERIC_TYPES=(PROFILE_TYPE,ESTIMATE_TYPE,CONTRIBUTION_TYPE,CHECKPOINT_TYPE,EXPECTATION_TYPE,RECIPROCITY_TYPE,REPAIR_TYPE,'d03.entity_anchor','d03.account_binding','d05.contribution','d05.relationship_projection')
_NUMERIC_HEAD_NAMES=('source_refs','historical_source_refs','memory_source_refs','mood_source_refs','creation_evidence_refs','snapshot_refs','content_refs','evaluation_interpretation_ref','trigger_original_ref','checkpoint_ref','support_refs','counter_refs','interpretation_refs','affect_refs','initialization_original_ref','contribution_refs','observation_refs','scope')
_INTENT_PATHS=(('boundary_ref',),('next_rule','source_refs'),('next_rule','target_entity_ref'),('acceptance_interpretation_refs',),('outbound_receipt_refs',))

def required_domains_v3(kind):
    if kind=='reevaluate_relationship':return frozenset({'d01','d05','d06','d11'})
    if kind=='adopt_relationship_contribution':return frozenset({'d01','d03','d04','d05','d06','d07','d11'})
    if kind=='adopt_relationship_revision_v2':return frozenset({'d01','d03','d04','d05','d06','d07','d08','d11'})
    return frozenset({'d01','d03','d05','d06','d11'})if kind=='initialize_relationship_prior_v2'else frozenset({'d01','d03','d05','d06','d07','d08','d11'})

def _identity(r):return(r.graph,r.work,r.operation,r.fence,r.namespace,r.selection_digest,r.graph_stamp,r.request,r.operation_id,r.authority,r.owner_binding)

def register_relationship_source_v3(r):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    from .domain_production_registry_v1 import installed_operation_v1
    require_current_beta1_source_work_v3(r)
    if r.operation_kind not in OPERATIONS or type(r.request)is not installed_operation_v1(r.operation_kind).request_type or r in _STATES:
        raise AuthorityUnavailable('D05 Source requires its exact once-issued typed Owner command')
    _STATES[r]=SimpleNamespace(identity=_identity(r),tasks={},selected=set(),keys=set(),roots=set(),originals=set(),
        producers=set(),outbounds={},policy_header=None,policy_schema=None,permission=None,metadata_complete=False,
        numeric_prepared=None,numeric_interpretation_ref=None,numeric_adopted_digest=None,numeric_prepared_digest=None,
        numeric_budget_tasks={},numeric_d07={},output_phase='unplanned',output_previous_plan=None,output_keys=(),
        source_caps={},historical_versions=set(),numeric_candidate=None,numeric_extra_types=set(),control_originals=None,metadata_keys=set(),trigger_key_planned=False,legacy_selector=None,legacy_selectors=set(),legacy_operations=set(),legacy_matches={},correction_context=None,reevaluation_rows={},reevaluation_selected={},reevaluation_affected=None,simulation_operations={},simulation_originals={},simulation_original_refs={},contribution_rows={},contribution_selected={},contribution_route=None,contribution_r_roots=set(),contribution_p_roots=set(),contribution_identity_groups={},contribution_legacy_roots=set())

def require_relationship_source_v3(r):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(r);state=_STATES.get(r)
    if state is None or state.identity[:-1]!=_identity(r)[:-1] or state.permission is not None and state.identity[-1]is not r.owner_binding:
        raise AuthorityUnavailable('D05 Source changed actual Work/Owner/selection')
    return state

def _active(db):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    return r if r is not None and r.operation_kind in OPERATIONS else None

def pin_relationship_owner_v3(r):
    state=require_relationship_source_v3(r);r.general_owner_entry.require_for_v3(r);state.identity=_identity(r)

def _metadata(r,identity):
    from .current_method_learning_read_v3 import _need_method_input
    state=require_relationship_source_v3(r);state.selected.add(identity);task=state.tasks.get(identity)
    if task is None or not task.complete:_need_method_input(r,('relationship_metadata',identity))
    with runtime_storage_quantum_v3(r.db)as meter:task.require_header_v3(meter)
    return task.result

class _OutboundLocatorV3:
    def __init__(self,r,identity):self.reader,self.identity=r,identity;self.complete=False;self.result=None
    def require_header_v3(self,meter):
        r=self.reader;ref=self.identity[1]
        rows=r.db.execute('SELECT final_operation_id,observation_digest,source_ref,slot_ref,batch_ref,original_digest FROM graph_d13_outbound_observations_v1 WHERE bot=? AND persona=? AND (source_ref=? OR observation_digest=? OR final_operation_id=?) LIMIT 3',(*r.namespace.as_tuple,ref,ref,ref)).fetchall();meter.charge_read(8192)
        if rows!=[self.result]:raise AuthorityUnavailable('D05 outbound original locator changed')
        return self.result
    def advance(self,meter):
        r=self.reader;r.require_current(meter=meter);state=require_relationship_source_v3(r);ref=self.identity[1]
        rows=r.db.execute('SELECT final_operation_id,observation_digest,source_ref,slot_ref,batch_ref,original_digest FROM graph_d13_outbound_observations_v1 WHERE bot=? AND persona=? AND (source_ref=? OR observation_digest=? OR final_operation_id=?) LIMIT 3',(*r.namespace.as_tuple,ref,ref,ref)).fetchall();meter.charge_read(8192)
        if len(rows)!=1:raise MissingProductionOriginalV1('unique_current_boundary_outbound_observation:'+ref)
        self.result=rows[0];state.outbounds[ref]=self.result;self.complete=True;return True

def create_relationship_metadata_task_v3(r,identity):
    state=require_relationship_source_v3(r)
    if identity not in state.selected:raise AuthorityUnavailable('D05 metadata was not selected by its actual recipe')
    task=state.tasks.get(identity)
    if task is None:
        from .current_beta1_source_read_v3 import create_current_beta1_metadata_task_v3
        task=_ContributionAncestryMetadataV3(r,identity)if identity[0]=='contribution_ancestors'else _OutboundLocatorV3(r,identity)if identity[0]=='outbound'else _LegacyCatalogueV3(r,identity)if identity[0]=='legacy_catalogue'else create_current_beta1_metadata_task_v3(r,identity)
        state.tasks[identity]=task
    return task

def relationship_metadata_spec_v3(r,identity):
    state=require_relationship_source_v3(r)
    if identity not in state.selected:raise AuthorityUnavailable('D05 metadata has no actual selected locator')
    if identity[0]=='relationship_budget':
        from .relationship_call_plan_budget_v3 import relationship_call_plan_budget_metadata_spec_v3
        return relationship_call_plan_budget_metadata_spec_v3(r,identity)
    kind,ref=identity
    if kind=='head':
        key=AtomKey.from_token(ref)
        if key not in state.keys|state.metadata_keys or NamespaceId.from_key(key)!=r.namespace:raise AuthorityUnavailable('D05 metadata head crossed selection')
        paths=tuple((name,)for name in _CONTRIBUTION_FIELDS[key.type_name])if r.operation_kind=='adopt_relationship_contribution'and key.type_name in _CONTRIBUTION_FIELDS else tuple((name,)for name in ('schema','branch_id','snapshot_refs','content_reality','evidence_eligibility'))if r.operation_kind=='adopt_relationship_contribution'and r.request.semantics=='simulation'and ref==r.request.trigger_original_ref else ((),)if r.operation_kind=='reevaluate_relationship'and key.token==r.request.correction_head_ref else tuple((name,)for name in _REEVALUATION_FIELDS[key.type_name])if r.operation_kind=='reevaluate_relationship'and key.type_name in _REEVALUATION_FIELDS else tuple((name,)for name in _NUMERIC_HEAD_NAMES)if r.operation_kind in {'adopt_relationship_revision_v2','adopt_relationship_contribution'}else _HEAD_PATHS
        return('graph_atoms','value',('token','bot','persona'),(ref,*r.namespace.as_tuple),('revision','valid','value_cell_id'),paths,None)
    if kind=='simulation_history':
        token=ref
        if r.operation_kind!='adopt_relationship_contribution'or r.request.semantics!='simulation'or token!=r.request.trigger_original_ref:
            raise AuthorityUnavailable('D05 simulation history has no actual typed branch selector')
        return('graph_history','value',('token','revision'),(token,r.heads[token][0]),
            ('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),
            tuple((name,)for name in ('schema','branch_id','snapshot_refs','content_reality','evidence_eligibility')),None)
    if kind in {'simulation_original','simulation_reads','simulation_receipt'}:
        if ref not in state.simulation_operations:raise AuthorityUnavailable('D05 simulation producer lacks actual branch history')
        column={'simulation_original':'original_payload_json','simulation_reads':'read_versions_json','simulation_receipt':'receipt_json'}[kind]
        paths=(('schema',),('namespace',),('identity','operation_id'),('identity','activity_id'),('identity','effect_id'),
            ('provenance','schema'),('provenance','work_kind'),('provenance','input_digest'),('provenance','status'),
            ('provenance','execution','work_kind'),('provenance','execution','input_digest'),('provenance','execution','source_refs'),
            ('provenance','behavior','request','snapshot_refs'),('provenance','behavior','simulation_result','activity_id'),
            ('provenance','behavior','simulation_result','branches','*','branch_id'),
            ('provenance','behavior','simulation_result','branches','*','snapshot_refs'))if kind=='simulation_original'else((),)
        return('graph_domain_production_originals_v1',column,('bot','persona','operation_id'),(*r.namespace.as_tuple,ref),
            ('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest'),paths,None)
    if kind in {'legacy_original','legacy_reads'}:
        if ref not in state.legacy_operations:raise AuthorityUnavailable('D05 legacy metadata lacks actual catalogue selection')
        column='original_payload_json'if kind=='legacy_original'else'read_versions_json'
        paths=(('namespace',),('identity','operation_id'),('provenance','trigger','original_ref'),('provenance','contribution','canonical_event_or_family_ref'),('provenance','contribution','subject_entity_ref'),('provenance','contribution','target_dimension'),('provenance','contribution','semantics'))if kind=='legacy_original'else((),)
        return('graph_domain_production_originals_v1',column,('bot','persona','operation_id'),(*r.namespace.as_tuple,ref),('domain','operation_kind','original_digest','bundle_digest','receipt_digest'),paths,None)
    if kind=='numeric_d07':
        original_kind,original_ref=ref
        if r.operation_kind!='adopt_relationship_revision_v2'or (original_kind,original_ref)not in state.numeric_d07:
            raise AuthorityUnavailable('D05 numeric original was not selected by its signed actual chain')
        names=('schema','interpretation_ref','interpretation_revision','interpretation_value_digest','prepared_digest','actual_result_digest','adoption_operation_id','graph_receipt_digest','question_scope')if original_kind=='adopted'else('schema','namespace','job_id','call_id','operation_id','activity_id','work_kind','purpose','audience','read_rows','cycle_ref','semantic_question_ref','c02_operation_id')
        return('graph_d07_execution_originals_v1','payload_json',('bot','persona','kind','original_ref'),(*r.namespace.as_tuple,original_kind,original_ref),('payload_digest','signature'),tuple((name,)for name in names),None)
    if kind in {'policy_locator','policy'}:
        header=state.policy_header
        if header is None or ref!=r.request.policy_ref:raise AuthorityUnavailable('D05 policy locator crossed actual request')
        sign=None if kind=='policy_locator'else'd11.d05-production-policy.v2'if state.policy_schema==2 else'd11.d05-production-policy.v1'
        return('graph_d05_production_policies_v1','payload_json',('bot','persona','policy_ref','revision'),(*r.namespace.as_tuple,ref,header[0]),('revision','payload_digest','signature'),_POLICY_PATHS,sign)
    if kind=='intent':
        if r.operation_kind!='revise_boundary'or ref!=r.request.intent_original_ref:raise AuthorityUnavailable('D05 intent locator crossed actual request')
        return('graph_d05_boundary_intents_v1','payload_json',('bot','persona','original_ref'),(*r.namespace.as_tuple,ref),('producing_operation_id','payload_digest','signature'),_INTENT_PATHS,'d11.d05-boundary-intent.v1')
    raise AuthorityUnavailable('unregistered D05 metadata kind')

def retain_relationship_metadata_path_v3(task,path):
    if task.identity[0]=='numeric_d07'and path and path[0]=='read_rows':
        return len(path)<3 or type(path[1])is int and path[2]in {'ref','revision','valid'}
    normalized=tuple('*'if type(part)is int else part for part in path)
    return not path or any(selected[:len(normalized)]==normalized or normalized[:len(selected)]==selected for selected in task.paths)

def finish_relationship_metadata_v3(task,value):
    r=task.reader;state=require_relationship_source_v3(r)
    if task.identity[0]=='relationship_budget':
        from .relationship_call_plan_budget_v3 import finish_relationship_call_plan_budget_metadata_v3
        return finish_relationship_call_plan_budget_metadata_v3(task,value)
    kind,ref=task.identity
    if kind in {'simulation_original','simulation_reads','simulation_receipt'}:
        if task.metadata[:2]!=('d07','run_simulation'):raise AuthorityUnavailable('D05 branch was not adopted by the actual D07 producer')
        if kind=='simulation_original':
            if value.get('schema')!='d07.current-run_simulation.v1'or value.get('namespace')!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}or value.get('identity',{}).get('operation_id')!=ref:
                raise AuthorityUnavailable('D05 simulation producer metadata changed its actual identity')
        elif kind=='simulation_receipt':
            from .domain_production_originals_v1 import _receipt
            if canonical_digest(_receipt(value))!=task.metadata[5]:raise AuthorityUnavailable('D05 actual simulation typed receipt digest differs after whole EOF')
    elif kind=='legacy_original':
        if(task.metadata[:2]!=('d05','adopt_relationship_contribution')or value.get('namespace')!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}or value.get('identity',{}).get('operation_id')!=ref):
            raise AuthorityUnavailable('D05 legacy catalogue changed its actual producer identity')
    elif kind=='numeric_d07':
        from .d07_execution_v1 import SIGN_KIND
        original_kind,original_ref=ref
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,canonical_serialize((r.namespace,original_kind,original_ref,task.metadata[0])),task.metadata[1])
        if original_kind=='adopted':
            if value.get('schema')!='d07.actual-cognition-adoption.v1'or value.get('interpretation_ref')!=r.request.interpretation_ref:
                raise AuthorityUnavailable('D05 numeric metadata is not its actual D07 adoption')
            state.producers.add(('',value['adoption_operation_id']))
        elif value.get('schema')!='d07.relationship-prepared.v2'or value.get('namespace')!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}or value.get('job_id')!=original_ref:
            raise AuthorityUnavailable('D05 numeric metadata is not its exact named C3 preparation')
        state.numeric_d07[ref]=(task.metadata,value)
    elif kind in {'policy_locator','policy'}:
        if(value.get('namespace')!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}or value.get('policy_ref')!=ref or value.get('revision')!=state.policy_header[0]):
            raise AuthorityUnavailable('D05 installed policy metadata changed exact namespace/version')
        if kind=='policy_locator':state.policy_schema=value.get('schema_version',1)
    elif kind=='intent':state.producers.add(('',task.metadata[0]))
    return value

def _roots(value):
    from ..authority_service.habit_authority_source_read_v3 import _source_refs_v3
    result=_source_refs_v3(value)
    if type(value)is dict:
        result.update(value.get('policy_source_refs',()))
        for rule in value.get('dimension_rules',()):
            if rule.get('authored_prior_source_ref')is not None:result.add(rule['authored_prior_source_ref'])
    return result

def read_plan_relationship_source_v3(db,*,namespace,activity_id,operation_kind,request,operation_id=None):
    r=_active(db)
    if r is None or r.namespace!=namespace or r.request!=request or r.operation_kind!=operation_kind:raise AuthorityUnavailable('D05 plan requires its exact Source Work')
    if operation_kind=='reevaluate_relationship':return _read_plan_relationship_reevaluation_v3(r)
    if operation_kind=='adopt_relationship_contribution':return _read_plan_relationship_contribution_v3(r)
    state=require_relationship_source_v3(r);keys={owner_grant_key(*namespace.as_tuple)}
    fixed=('d03.entity_anchor','d03.account_binding','d05.boundary_rule')
    if operation_kind=='initialize_relationship_prior_v2':
        scope=request.scope;fixed=(PROFILE_TYPE,ESTIMATE_TYPE,CHECKPOINT_TYPE)
        keys.update((scope.subject_head.key,scope.key(ESTIMATE_TYPE),scope.key(PROFILE_TYPE),scope.key(CHECKPOINT_TYPE,r.operation_id)))
        if scope.context_head is not None:keys.add(scope.context_head.key)
    elif operation_kind=='adopt_relationship_revision_v2':
        fixed=(*_NUMERIC_TYPES,*sorted(state.numeric_extra_types));keys.add(AtomKey.from_token(request.interpretation_ref));state.originals.add(request.interpretation_ref)
        _numeric_preparation_metadata_v3(r)
        keys.update(state.keys)
    elif operation_kind=='revise_boundary':
        keys.add(AtomKey.from_token(request.boundary_ref));intent=_metadata(r,('intent',request.intent_original_ref))
        if intent is None:raise MissingProductionOriginalV1('actual_boundary_intent_original')
        state.originals.add(request.intent_original_ref);state.roots.update(intent['next_rule']['source_refs'])
        state.originals.update(intent['acceptance_interpretation_refs']);state.originals.update(intent['outbound_receipt_refs'])
        keys.update(AtomKey.from_token(ref)for ref in intent['acceptance_interpretation_refs'])
        for ref in intent['outbound_receipt_refs']:state.roots.add(_metadata(r,('outbound',ref))[2])
    else:
        intent=request.intent;keys.add(AtomKey.from_token(intent.boundary_ref));state.roots.update(intent.next_rule.source_refs)
        state.originals.update((*intent.acceptance_interpretation_refs,*intent.outbound_receipt_refs))
        keys.update(AtomKey.from_token(ref)for ref in intent.acceptance_interpretation_refs)
        for ref in intent.outbound_receipt_refs:state.roots.add(_metadata(r,('outbound',ref))[2])
    if operation_kind!='input:register_boundary_intent':
        with runtime_storage_quantum_v3(db)as meter:
            header=_runtime_bounded_fixed_row_v3(db,meter,'graph_d05_production_policies_v1',('revision','payload_digest','signature'),
                'bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC',(*namespace.as_tuple,request.policy_ref))
        if header is None:raise MissingProductionOriginalV1('installed_relationship_policy:'+request.policy_ref)
        if state.policy_header is not None and state.policy_header!=header:raise AuthorityUnavailable('D05 selected policy revision changed')
        state.policy_header=header
        _metadata(r,('policy_locator',request.policy_ref));policy=_metadata(r,('policy',request.policy_ref));state.roots.update(_roots(policy));state.originals.add(request.policy_ref)
        if operation_kind=='initialize_relationship_prior_v2':
            for rule in policy.get('dimension_rules',()):
                if rule.get('authored_prior_source_ref')is not None:state.originals.add(rule['authored_prior_source_ref'])
    state.keys.update(keys);state.keys.update(AtomKey.from_token(token)for token in r.heads if AtomKey.from_token(token).type_name in fixed)
    visited=set()
    while (state.keys|state.metadata_keys)-visited:
        for key in tuple(sorted((state.keys|state.metadata_keys)-visited,key=lambda key:key.token)):
            visited.add(key)
            if key.type_name=='runtime.owner_grant.v1'or key.type_name=='memory.source':continue
            if key.token not in r.heads:continue
            metadata=_metadata(r,('head',key.token))
            if metadata is not None:
                state.roots.update(_roots(metadata))
                if operation_kind=='adopt_relationship_revision_v2':
                    _numeric_head_closure_v3(r,key,metadata,metadata_only=key not in state.keys)
                for ref in (()if key not in state.keys else metadata.get('creation_evidence_refs',())):
                    atom=AtomKey.from_token(ref)
                    if atom.type_name!='memory.source':state.keys.add(atom);state.originals.add(ref)
    for key in keys:
        if key.type_name=='memory.source':state.roots.add(key.token)
    if any(NamespaceId.from_key(AtomKey.from_token(ref))!=namespace or AtomKey.from_token(ref).type_name!='memory.source'for ref in state.roots):raise AuthorityUnavailable('D05 metadata crossed Source namespace')
    state.metadata_complete=True
    return production_read_plan_v1(fixed,tuple(sorted(state.keys,key=lambda key:key.token)),tuple(sorted(state.roots)),tuple(sorted(state.originals)))

def relationship_source_groups_v3(r,roots):
    state=require_relationship_source_v3(r)
    if not state.metadata_complete or set(roots)!=state.roots or r.selected_envelope.authority.purpose!='context':raise AuthorityUnavailable('D05 Source groups changed actual complete current recipe')
    if r.operation_kind=='adopt_relationship_contribution':
        groups=[]
        if state.contribution_r_roots:groups.append(('context',(r.audience_ref,),tuple(sorted(state.contribution_r_roots))))
        if state.contribution_p_roots:groups.append(('context',('owner',),tuple(sorted(state.contribution_p_roots))))
        return tuple(groups)
    return (('context',(r.audience_ref,),tuple(sorted(roots))),)

def require_relationship_sources_v3(r,roots):
    from .current_beta1_source_read_v3 import qualify_current_beta1_source_groups_v3
    state=require_relationship_source_v3(r);state.permission=qualify_current_beta1_source_groups_v3(r,roots);state.source_caps[state.permission]=True;return state.permission

def relationship_point_v3(db,table,columns,key_columns,key):
    from .current_method_learning_read_v3 import _need_method_input
    r=_active(db)
    if r is None:return False,None
    request=(table,tuple(columns),tuple(key_columns),tuple(key));require_relationship_point_v3(r,request)
    task=r.points.get(request)
    if task is None or not task.complete:_need_method_input(r,('point',request))
    with runtime_storage_quantum_v3(db)as meter:row=task.require_row_v3(meter)
    if row is None:return True,None
    from .current_method_learning_read_v3 import MethodJSONColumnV3
    return True,tuple(value.wire if type(value)is MethodJSONColumnV3 else value for value in row)

def require_relationship_body_v3(r,table,key):
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    state=require_relationship_source_v3(r)
    if require_beta1_source_control_point_v3(r,(table,('revision','value','valid'),('token','bot','persona'),tuple(key))):return
    if table=='runtime_budget_grants'and r.budget_task is not None and tuple(key)==tuple(r.budget_task.metadata[:2])and key[0]==r.parent_budget_lease_ref:return
    if state.permission is None:raise AuthorityUnavailable('D05 protected Body requires complete actual Source ALL')
    state.permission.require_for_v3(r)
    if table in {'graph_first_ingress_identity_v1','graph_first_ingress_intents_v2'}:
        if key[-1]not in _relationship_ingress_operations_v3(r):raise AuthorityUnavailable('D05 ingress Body lacks an actual qualified Source identity')
        return
    if table=='graph_d07_execution_originals_v1':
        if tuple(key[-2:])not in state.numeric_d07:raise AuthorityUnavailable('D05 numeric Body is outside actual signed chain')
        return
    if table in {'graph_atoms','graph_history'}:
        atom=AtomKey.from_token(key[0])
        if atom not in r.selected_plan.exact_keys and atom.token not in state.permission.source_refs:raise AuthorityUnavailable('D05 Body outside actual exact graph closure')
        if table=='graph_history':
            expected=r.heads.get(atom.token)
            if expected is None or key[1]!=expected[0]:raise AuthorityUnavailable('D05 historical Body is outside its exact selected current revision')
    elif table=='graph_events':
        if tuple(key[-2:])not in state.producers:raise AuthorityUnavailable('D05 graph event not derived from actual selected history')
    elif table=='graph_bundle_operations':
        if key[-1]not in {op for session,op in state.producers}:raise AuthorityUnavailable('D05 bundle not from actual selected producer')
    elif table=='graph_domain_production_originals_v1':
        if key[-1]not in state.legacy_operations and key[-1]not in state.simulation_operations:raise AuthorityUnavailable('D05 producer Body lacks its actual selected history')
    elif table=='graph_d05_production_policies_v1':
        if tuple(key[-2:])!=(r.request.policy_ref,state.policy_header[0]):raise AuthorityUnavailable('D05 selected another installed policy')
    elif table=='graph_d05_boundary_intents_v1':
        if r.operation_kind!='revise_boundary'or key[-1]!=r.request.intent_original_ref:raise AuthorityUnavailable('D05 selected another boundary intent')
    elif table=='graph_d13_outbound_observations_v1':
        if tuple(key[-2:])not in {(row[0],row[1])for row in state.outbounds.values()}:raise AuthorityUnavailable('D05 selected another adopted outbound observation')
    else:raise AuthorityUnavailable('D05 has no protected Body shape for this table')

def require_relationship_point_v3(r,request):
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    state=require_relationship_source_v3(r);table,columns,key_columns,key=request
    if require_beta1_source_control_point_v3(r,request):return
    ingress_shapes={
        ('graph_first_ingress_identity_v1',('source_ref','platform_ref','conversation_ref','sender_ref','message_id','visibility','identity_json','content_fingerprint','learned_at','bundle_digest')),
        ('graph_first_ingress_intents_v2',('identity_json',)),
        ('ingress_first_observations',('content_fingerprint','learned_at','bundle_digest')),
        ('graph_bundle_operations',('digest',))}
    if(table,columns)in ingress_shapes:
        if(key_columns!=('bot','persona','operation_id')or tuple(key[:2])!=r.namespace.as_tuple
                or key[-1]not in _relationship_ingress_operations_v3(r)):
            raise AuthorityUnavailable('D05 ingress point crossed its actual Source-qualified Host identity')
        return
    graph=(table=='graph_atoms'and key_columns==('token','bot','persona')and columns==('revision','value','valid')or table=='graph_history'and key_columns==('token','revision')and set(columns)<={'event_id','event_session','event_bot','event_persona','value','valid'})
    shapes={('graph_events',('revisions',),('bot','persona','session','event_id')),
        ('graph_events',('reads','revisions'),('bot','persona','session','event_id')),
        ('graph_bundle_operations',('digest','activity_id','effect_id','commit_seq','receipt_json'),('bot','persona','operation_id')),
        ('graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),('bot','persona','operation_id')),
        ('graph_domain_production_originals_v1',('domain','operation_kind','request_digest','original_digest','original_payload_json','read_versions_json','bundle_digest','receipt_json','receipt_digest'),('bot','persona','operation_id')),
        ('graph_d07_execution_originals_v1',('payload_json','payload_digest','signature'),('bot','persona','kind','original_ref')),
        ('graph_bundle_operations',('digest','receipt_json','commit_seq'),('bot','persona','operation_id')),
        ('graph_d05_production_policies_v1',('payload_json','payload_digest','signature'),('bot','persona','policy_ref','revision')),
        ('graph_d05_boundary_intents_v1',('producing_operation_id','payload_json','payload_digest','signature'),('bot','persona','original_ref')),
        ('graph_d13_outbound_observations_v1',('observation_json','original_json'),('bot','persona','final_operation_id','observation_digest'))}
    if not graph and request[:3]not in shapes:raise AuthorityUnavailable('D05 point shape is not registered')
    if table in {'graph_atoms','graph_history'}:
        if NamespaceId.from_key(AtomKey.from_token(key[0]))!=r.namespace:raise AuthorityUnavailable('D05 point crossed graph namespace')
    elif tuple(key[:2])!=r.namespace.as_tuple:raise AuthorityUnavailable('D05 point crossed namespace')
    require_relationship_body_v3(r,table,key)

def read_relationship_policy_v3(db,read,policy_ref,issuer):
    r=_active(db)
    if r is None:return None
    state=require_relationship_source_v3(r);header=state.policy_header
    own,row=relationship_point_v3(db,'graph_d05_production_policies_v1',('payload_json','payload_digest','signature'),('bot','persona','policy_ref','revision'),(*r.namespace.as_tuple,policy_ref,header[0]))
    if row is None:raise MissingProductionOriginalV1('signed_relationship_policy:'+policy_ref)
    raw=json.loads(row[0]);kind='d11.d05-production-policy.v2'if raw.get('schema_version')==2 else'd11.d05-production-policy.v1';issuer._signer.verify(kind,row[0],row[2])
    if (canonical_digest(raw),row[1],row[2])!=(header[1],header[1],header[2]):raise AuthorityUnavailable('D05 signed Body differs from fully authenticated metadata EOF')
    from .d05_production_operations_v1 import InstalledRelationshipPolicyV1
    from ..domains.d05.relationship_revision_v2 import InstalledRelationshipPolicyV2
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    policy=decode_typed_production_value_v1(raw,InstalledRelationshipPolicyV2 if raw.get('schema_version')==2 else InstalledRelationshipPolicyV1)
    if read is not None:
        pins=tuple(item for item in read.frame.installed_policy_refs if item.policy_ref==policy_ref)
        if len(pins)!=1 or (pins[0].revision,pins[0].policy_digest)!=(header[0],header[1]):raise AuthorityUnavailable('D05 policy differs from actual frame policy pin')
        if type(policy)is InstalledRelationshipPolicyV2:
            if r.operation_kind=='adopt_relationship_contribution':_require_contribution_policy_sources_v3(db,read,policy.policy_source_refs)
            else:read.source_family(db,policy.policy_source_refs)
    return policy,ProductionOriginalRefV1('d05.installed_policy',policy_ref,row[1])

class RelationshipDomainReadV3(CurrentDomainReadV1):
    def source_family(self,db,roots,*,purpose=None,audience=None,allow_corrected=False):
        r=_active(db)
        if r.operation_kind=='adopt_relationship_contribution':
            state=require_relationship_source_v3(r);state.permission.require_for_v3(r)
            if allow_corrected or purpose not in {None,'context'}:raise AuthorityUnavailable('new contribution cannot borrow historical Source permission')
            chosen=audience or r.audience_ref
            from .current_beta1_source_read_v3 import require_beta1_source_member_v3
            for ref in roots:require_beta1_source_member_v3(r,ref,'context',(chosen,))
            return super().source_family(db,roots,purpose='context',audience=chosen)
        if r.operation_kind=='reevaluate_relationship':
            state=require_relationship_source_v3(r);state.permission.require_for_v3(r)
            if purpose not in {None,'context'}or audience not in {None,'owner'}or r.audience_ref!='owner':
                raise AuthorityUnavailable('relationship correction context cannot become another Source grant')
            if not set(roots)<=set(state.permission.source_refs)or state.correction_context is None:
                raise AuthorityUnavailable('relationship correction context lacks actual complete Source membership')
            state.correction_context.require_current_v3(r)
            return super().source_family(db,roots,purpose='context',audience='owner',allow_corrected=True)
        if allow_corrected:raise AuthorityUnavailable('D05 historical context requires its exact reevaluation Work')
        return super().source_family(db,roots,purpose=purpose,audience=audience)
    def actor_entity(self,db,source_ref,*,expected_entity):
        r=_active(db)
        if r.operation_kind=='adopt_relationship_contribution':
            return read_current_relationship_contribution_actor_v3(db,self,source_ref,expected_entity=expected_entity)
        return super().actor_entity(db,source_ref,expected_entity=expected_entity)
    def committed_operation(self,db,operation_id):
        r=_active(db);state=require_relationship_source_v3(r)
        if operation_id not in {producer for session,producer in state.producers}:
            selected=tuple(point for point in r.points.values()if point.complete and point.table=='graph_history'
                and point.small is not None and point.small.get('event_id')==operation_id
                and AtomKey.from_token(point.key[0])in r.selected_plan.exact_keys)
            with runtime_storage_quantum_v3(db)as meter:
                for point in selected:point.require_row_v3(meter)
                if not selected:
                    for key in r.selected_plan.exact_keys:
                        head=r.heads.get(key.token)
                        if head is None:continue
                        origin=_runtime_bounded_fixed_row_v3(db,meter,'graph_history',('event_session','event_id'),
                            'token=? AND revision=? AND event_bot=? AND event_persona=?',(key.token,head[0],*r.namespace.as_tuple))
                        if origin is not None and origin[1]==operation_id:state.producers.add(origin)
            if not selected and operation_id not in {op for session,op in state.producers}:
                raise AuthorityUnavailable('D05 producer was not derived from actual selected current history')
            state.producers.add(('',operation_id))
        own,row=relationship_point_v3(db,'graph_bundle_operations',('digest','receipt_json','commit_seq'),('bot','persona','operation_id'),(*r.namespace.as_tuple,operation_id))
        if row is None or row[2]<1 or json.loads(row[1]).get('commit_seq')!=row[2]:raise MissingProductionOriginalV1('actual_committed_producing_operation')
        return row
    def adopted_outbound_observation(self,db,ref):
        r=_active(db);state=require_relationship_source_v3(r);locator=state.outbounds.get(ref)
        if locator is None:raise AuthorityUnavailable('D05 outbound was not selected before Source qualification')
        own,row=relationship_point_v3(db,'graph_d13_outbound_observations_v1',('observation_json','original_json'),('bot','persona','final_operation_id','observation_digest'),(*r.namespace.as_tuple,locator[0],locator[1]))
        from ..authority_service.v2_contract import MutationReceiptV2,from_wire
        observed=from_wire(json.loads(row[0]));original=json.loads(row[1])
        if(type(observed)is not MutationReceiptV2 or observed.durable_state!='committed'or observed.pending.phase!='observed'or canonical_digest(observed)!=locator[1]or canonical_digest(original)!=locator[5]
            or original['observation_digest']!=locator[1]or original['source_ref']!=locator[2]or original['slot_ref']!=locator[3]or original['batch_ref']!=locator[4]
            or observed.pending.platform_observation.binding.origin.operation_id!=locator[0]):raise AuthorityUnavailable('D05 actual outbound adoption original differs')
        own,history=relationship_point_v3(db,'graph_history',('event_id','valid'),('token','revision'),(locator[2],1))
        if history!=(original['operation_id'],1):raise AuthorityUnavailable('D05 outward Source lacks same W01 observation adoption')
        self.source_family(db,(locator[2],));return observed,self.original(ref)

def relationship_domain_read_v3(db,frame):return RelationshipDomainReadV3(frame)if _active(db)is not None else CurrentDomainReadV1(frame)

def _graph_original_v3(r,ref):
    from .current_method_learning_read_v3 import method_graph_head_v3
    state=require_relationship_source_v3(r);key=AtomKey.from_token(ref);atom=method_graph_head_v3(r.db,r.namespace,key)
    if not atom.valid:raise MissingProductionOriginalV1('current_d05_original:'+ref)
    own,history=relationship_point_v3(r.db,'graph_history',('value','valid','event_bot','event_persona','event_session','event_id'),('token','revision'),(ref,atom.revision))
    if history is None or json.loads(history[0])!=atom.value or history[1:4]!=(1,*r.namespace.as_tuple):raise AuthorityUnavailable('D05 graph Original lost exact current history')
    state.producers.add((history[4],history[5]))
    own,event=relationship_point_v3(r.db,'graph_events',('revisions',),('bot','persona','session','event_id'),(*r.namespace.as_tuple,history[4],history[5]))
    if event is None or [ref,atom.revision]not in json.loads(event[0]):raise AuthorityUnavailable('D05 graph Original absent from actual event writes')
    if key.type_name=='d07.simulation_branch.v1'and r.operation_kind=='adopt_relationship_contribution'and r.request.semantics=='simulation':
        return read_committed_simulation_branch_original_v3(r.db,r.namespace,ref)
    if key.type_name=='d06.recollection.v1':
        from .domain_production_read_plans_v1 import read_committed_recollection_original_v1
        return read_committed_recollection_original_v1(r.db,r.namespace,ref)[0]
    if key.type_name=='d07.current_interpretation.v1':
        own,bundle=relationship_point_v3(r.db,'graph_bundle_operations',('digest','receipt_json','commit_seq'),('bot','persona','operation_id'),(*r.namespace.as_tuple,history[5]))
        if bundle is None or bundle[2]<1:raise AuthorityUnavailable('D05 semantic Original has no actual committed producer')
    return ProductionOriginalRefV1(key.type_name,ref,canonical_digest(atom.value),(GraphVersion(key,atom.revision),))

def read_bound_relationship_originals_v3(db,*,namespace,plan,installed_readers):
    r=_active(db)
    if r is None:return False,None
    if namespace!=r.namespace or plan!=r.selected_plan:raise AuthorityUnavailable('D05 originals crossed actual selected plan')
    state=require_relationship_source_v3(r);result=[]
    for ref in plan.required_original_refs:
        if state.policy_header is not None and ref==r.request.policy_ref:
            result.append(read_relationship_policy_v3(db,None,ref,installed_readers.issuer)[1])
        elif ref in state.simulation_original_refs.values():
            op=next(op for op,original_ref in state.simulation_original_refs.items()if original_ref==ref)
            read_committed_simulation_branch_original_v3(db,namespace,state.simulation_operations[op])
            saved=state.simulation_originals[op]
            # Match the existing immutable historical adoption projection:
            # pre-CAS producer reads remain historical, not current heads.
            result.append(ProductionOriginalRefV1('d07.current-run_simulation',ref,saved['original_digest']))
        elif ref in state.outbounds:
            locator=state.outbounds[ref]
            # The same exact adopted observation is also rechecked by its actual
            # boundary consumer before any bilateral result can be written.
            own,row=relationship_point_v3(db,'graph_d13_outbound_observations_v1',('observation_json','original_json'),('bot','persona','final_operation_id','observation_digest'),(*namespace.as_tuple,locator[0],locator[1]))
            from ..authority_service.v2_contract import from_wire
            if canonical_digest(from_wire(json.loads(row[0])))!=locator[1]or canonical_digest(json.loads(row[1]))!=locator[5]:raise AuthorityUnavailable('D05 outbound Original digest differs')
            result.append(ProductionOriginalRefV1('d11.outbound_observation',ref,locator[1]))
        elif r.operation_kind=='revise_boundary'and ref==r.request.intent_original_ref:
            own,row=relationship_point_v3(db,'graph_d05_boundary_intents_v1',('producing_operation_id','payload_json','payload_digest','signature'),('bot','persona','original_ref'),(*namespace.as_tuple,ref))
            installed_readers.issuer._signer.verify('d11.d05-boundary-intent.v1',row[1],row[3])
            if canonical_digest(json.loads(row[1]))!=row[2]:raise AuthorityUnavailable('D05 boundary Original digest differs')
            result.append(ProductionOriginalRefV1('d05.boundary_intent',ref,row[2]))
        else:result.append(_graph_original_v3(r,ref))
    return True,tuple(result)

def read_bound_relationship_policies_v3(db,*,namespace,plan):
    r=_active(db)
    if r is None:return False,None
    state=require_relationship_source_v3(r)
    if namespace!=r.namespace or plan!=r.selected_plan:raise AuthorityUnavailable('D05 policy pins crossed actual selected plan')
    return True,()if state.policy_header is None else(ProductionPolicyRefV1(r.request.policy_ref,state.policy_header[0],state.policy_header[1]),)

def register_relationship_write_v3(inputs,scope,current_owner):
    r=inputs.owner;state=require_relationship_source_v3(r)
    if not r.inputs_sealed:return
    from .current_method_learning_read_v3 import _method_active
    if not r.read_finished or not r.business_started or scope.operation!='write'or scope is r.fence.scope or current_owner!=r.owner_binding or inputs.plan!=r.selected_plan or _method_active(r.db)is not r or state.permission is None:
        raise AuthorityUnavailable('D05 WRITE requires exact actual sealed Source/Owner inputs')
    _WRITES[r]=(inputs,scope,current_owner,state.identity,state.permission)

def require_relationship_write_v3(r):
    state=require_relationship_source_v3(r);saved=_WRITES.get(r)
    if saved is None or saved[0].owner is not r or saved[2]!=r.owner_binding or saved[3:]!=(state.identity,state.permission)or not r.business_started:raise AuthorityUnavailable('D05 Source lost actual same-Work WRITE binding')
    return saved

def release_relationship_source_v3(r):
    state=_STATES.pop(r,None);_WRITES.pop(r,None);_CORRECTION_CONTEXTS.pop(r,None);_CONTRIBUTION_FACTS.pop(r,None)
    if state is not None:
        for task in tuple(state.numeric_budget_tasks.values()):task.release_v3()
        state.tasks.clear();state.selected.clear();state.keys.clear();state.roots.clear();state.originals.clear();state.producers.clear();state.outbounds.clear();state.numeric_budget_tasks.clear();state.numeric_d07.clear();state.metadata_keys.clear();state.legacy_operations.clear();state.legacy_matches.clear();state.legacy_selectors.clear();state.source_caps.clear();state.numeric_prepared=None;state.numeric_candidate=None;state.permission=None;state.correction_context=None;state.reevaluation_rows.clear();state.reevaluation_selected.clear();state.simulation_operations.clear();state.simulation_originals.clear();state.simulation_original_refs.clear();state.contribution_rows.clear();state.contribution_selected.clear();state.contribution_identity_groups.clear();state.contribution_r_roots.clear();state.contribution_p_roots.clear();state.contribution_legacy_roots.clear()


def record_boundary_input_after_commit_v3(db,*,frame,staged_input,actual_receipt,installed_readers):
    """Record the existing signed Original from the actual same-commit input."""
    r=_active(db);state=None if r is None else _STATES.get(r)
    if(state is None or r.operation_kind!='input:register_boundary_intent'or r.operation_id!=actual_receipt.operation_id
            or staged_input.request!=r.request or staged_input.stage.operation_id!=actual_receipt.operation_id
            or state.permission is None or state.identity!=_identity(r)or not db.in_transaction):
        raise AuthorityUnavailable('D05 boundary Original requires actual same-Work staged input and committed receipt')
    # The Graph CAS has advanced its epoch. Reuse only the actual completed
    # prior Source readset; recheck every unchanged Source control head here.
    if not set(state.permission.versions)<=set(actual_receipt.read_versions):raise AuthorityUnavailable('boundary input receipt lost its actual complete Source readset')
    for version in state.permission.versions:
        row=db.execute('SELECT revision FROM graph_atoms WHERE token=? AND bot=? AND persona=?',(version.key.token,*r.namespace.as_tuple)).fetchone()
        if (0 if row is None else row[0])!=version.revision:raise AuthorityUnavailable('boundary input Source control changed within its actual commit')
    request=r.request;raw=plain_v1(request.intent);encoded=canonical_serialize(raw);digest=canonical_digest(raw)
    signature=installed_readers.issuer._signer.sign('d11.d05-boundary-intent.v1',encoded)
    old=db.execute('SELECT producing_operation_id,payload_digest,signature FROM graph_d05_boundary_intents_v1 WHERE bot=? AND persona=? AND original_ref=?',(*r.namespace.as_tuple,request.original_ref)).fetchone()
    expected=(r.operation_id,digest,signature)
    if old is not None and old!=expected:raise AuthorityUnavailable('boundary Original conflicts with its actual immutable input')
    if old is None:
        db.execute('INSERT INTO graph_d05_boundary_intents_v1 VALUES(?,?,?,?,?,?,?,?)',(*r.namespace.as_tuple,request.original_ref,r.operation_id,encoded,digest,signature,canonical_serialize(request.intent.next_rule.source_refs)))
    return (ProductionOriginalRefV1('d05.boundary_intent',request.original_ref,digest),)


def require_current_relationship_numeric_reader_v3(reader):
    from .current_method_learning_read_v3 import _MethodLearningReadV3
    from .d05_relationship_revision_v2 import AdoptCurrentRelationshipRevisionRequestV2
    state=require_relationship_source_v3(reader)
    if(type(reader)is not _MethodLearningReadV3 or reader.operation_kind!='adopt_relationship_revision_v2'
            or type(reader.request)is not AdoptCurrentRelationshipRevisionRequestV2 or state.permission is None):
        raise AuthorityUnavailable('relationship numeric budget requires exact actual Source-qualified typed Work')
    state.permission.require_for_v3(reader)
    return state


def _numeric_preparation_metadata_v3(r):
    state=require_relationship_source_v3(r);ref=r.request.interpretation_ref
    state.numeric_d07.setdefault(('adopted',ref),None)
    adopted=_metadata(r,('numeric_d07',('adopted',ref)))
    if adopted is None:raise MissingProductionOriginalV1('actual_relationship_D07_adoption')
    with runtime_storage_quantum_v3(r.db)as meter:
        rows=r.db.execute("SELECT original_ref FROM graph_d07_execution_originals_v1 WHERE bot=? AND persona=? AND kind='prepared' AND payload_digest=? LIMIT 2",(*r.namespace.as_tuple,adopted['prepared_digest'])).fetchall();meter.charge_read(4096)
    if len(rows)!=1:raise MissingProductionOriginalV1('unique_relationship_D07_preparation_original')
    job=rows[0][0];state.numeric_d07.setdefault(('prepared',job),None)
    prepared=_metadata(r,('numeric_d07',('prepared',job)))
    if prepared is None:raise MissingProductionOriginalV1('actual_relationship_D07_preparation')
    if state.tasks[('numeric_d07',('prepared',job))].metadata[0]!=adopted['prepared_digest']:
        raise AuthorityUnavailable('D05 signed adoption preparation digest differs')
    state.numeric_interpretation_ref=ref;state.numeric_adopted_digest=state.tasks[('numeric_d07',('adopted',ref))].metadata[0]
    state.numeric_prepared_digest=adopted['prepared_digest']
    state.numeric_d07.setdefault(('result','d07-result:'+prepared['call_id']),None);state.numeric_d07.setdefault(('call',job),None)
    for row in prepared['read_rows']:
        key=AtomKey.from_token(row['ref'])
        if NamespaceId.from_key(key)!=r.namespace:raise AuthorityUnavailable('D05 prepared content locator crossed namespace')
        state.metadata_keys.add(key)
        if key.type_name=='memory.source':state.roots.add(key.token)
    state.keys.add(decode_typed_production_value_v3(prepared['cycle_ref'],GraphVersion).key)


def decode_typed_production_value_v3(value,cls):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(value,cls)


def _numeric_head_closure_v3(r,key,value,*,metadata_only=False):
    state=require_relationship_source_v3(r)
    for name in ('historical_source_refs','memory_source_refs','mood_source_refs'):
        state.roots.update(value.get(name,()))
    if key.type_name=='d06.recollection.v1':
        from ..memory_types import source_key
        state.roots.update(source_key(*r.namespace.as_tuple,ref).token for ref in value.get('content_refs',()))
    refs=[]
    for name in ('snapshot_refs','source_refs','creation_evidence_refs','support_refs','counter_refs','interpretation_refs','affect_refs','contribution_refs'):
        refs.extend(value.get(name,()))
    for name in ('evaluation_interpretation_ref','trigger_original_ref','checkpoint_ref','initialization_original_ref'):
        if value.get(name)is not None:refs.append(value[name])
    if not metadata_only:
        for observation_ref in value.get('observation_refs',()):
            locator=_metadata(r,('outbound',observation_ref));state.roots.add(locator[2]);state.originals.add(observation_ref)
    if metadata_only:refs=[ref for name in ('snapshot_refs','source_refs','creation_evidence_refs')for ref in value.get(name,())]
    for ref in refs:
        atom=AtomKey.from_token(ref)
        if NamespaceId.from_key(atom)!=r.namespace:raise AuthorityUnavailable('D05 numeric dependency crossed namespace')
        (state.metadata_keys if metadata_only else state.keys).add(atom)
        if atom.type_name=='memory.source':state.roots.add(ref)
        elif atom.type_name=='d07.current_interpretation.v1':state.originals.add(ref)
    scope=value.get('scope')
    if scope is not None and not metadata_only:
        from ..domains.d05.relationship_revision_v2 import RelationshipScopeV2
        actual=decode_typed_production_value_v3(scope,RelationshipScopeV2)
        state.keys.add(actual.subject_head.key)
        if actual.context_head is not None:state.keys.add(actual.context_head.key)


def _discover_numeric_candidate_v3(r,candidate):
    state=require_current_relationship_numeric_reader_v3(r);scope=candidate.scope
    if scope.namespace!=r.namespace:raise AuthorityUnavailable('D05 numeric candidate crossed its actual namespace')
    state.keys.update((scope.subject_head.key,scope.key(ESTIMATE_TYPE),scope.key(PROFILE_TYPE,'profile')))
    if scope.context_head is not None:state.keys.add(scope.context_head.key)
    refs=[candidate.trigger_original_ref,*candidate.support_refs,*candidate.counter_refs,*candidate.interpretation_refs,*candidate.affect_refs]
    originals=[candidate.trigger_original_ref,*candidate.interpretation_refs]
    if candidate.reassessment_interpretation_ref is not None:
        refs.append(candidate.reassessment_interpretation_ref);originals.append(candidate.reassessment_interpretation_ref)
        state.keys.update(v.key for v in candidate.reassessment_basis_versions)
    expectation,reciprocity,repair=candidate.expectation,candidate.reciprocity,candidate.repair
    if expectation is not None:
        refs.extend(expectation.negotiated_interpretation_refs);originals.extend(expectation.negotiated_interpretation_refs)
        if expectation.commitment_ref is not None:refs.append(expectation.commitment_ref)
    if reciprocity is not None:refs.extend(reciprocity.visible_sample_refs)
    if repair is not None:
        refs.extend((*repair.proposal_interpretation_refs,*repair.response_interpretation_refs,*repair.practice_progress_refs,*repair.reevaluated_estimate_refs,*repair.contact_basis_refs))
        originals.extend((*repair.proposal_interpretation_refs,*repair.response_interpretation_refs))
        if repair.communication_original_ref is not None:
            outbound=_metadata(r,('outbound',repair.communication_original_ref));state.roots.add(outbound[2]);state.originals.add(repair.communication_original_ref)
        if repair.communication_action_ref is not None:refs.append(repair.communication_action_ref)
        if repair.practice_progress_refs or repair.communication_action_ref:state.numeric_extra_types.add('d08.action_intent.v1')
    state.keys.update(AtomKey.from_token(ref)for ref in refs);state.originals.update(originals);state.roots.update(candidate.source_refs)


def require_relationship_output_requalification_v3(r):
    state=require_relationship_source_v3(r);previous=state.output_previous_plan
    from .d05_relationship_revision_v2 import AdoptCurrentRelationshipRevisionRequestV2
    from ..domains.d05.production_operations_v1 import AdoptCurrentRelationshipContributionRequestV1
    expected={'adopt_relationship_revision_v2':AdoptCurrentRelationshipRevisionRequestV2,'adopt_relationship_contribution':AdoptCurrentRelationshipContributionRequestV1}
    if(r.operation_kind not in expected or type(r.request)is not expected[r.operation_kind]
            or state.output_phase!='requalifying'or previous is None or r.read_finished or r.inputs_sealed or r.business_started
            or r.fence.scope.operation!='read'or state.identity!=_identity(r)
            or not set(previous.exact_keys)<=set(r.selected_plan.exact_keys)
            or not set(previous.source_roots)<=set(r.selected_plan.source_roots)
            or not set(state.output_keys)<=set(r.selected_plan.exact_keys)):
        raise AuthorityUnavailable('D05 Source renewal escaped its exact unsealed typed output metadata phase')
    return state


def _renew_numeric_plan_v3(r,next_phase):
    state=require_relationship_source_v3(r)
    previous=r.selected_plan
    plan=read_plan_relationship_source_v3(r.db,namespace=r.namespace,activity_id=r.activity_id,
        operation_kind=r.operation_kind,request=r.request,operation_id=r.operation_id)
    from .domain_production_contracts_v1 import CurrentOperationFrameV1
    if len(plan.exact_keys)>CurrentOperationFrameV1(*r.frame_fields).limits.max_graph_heads:
        raise MissingProductionOriginalV1('bounded_relationship_complete_output_metadata_closure')
    state.output_previous_plan=previous;state.output_next_phase=next_phase;r.selected_plan=plan;state.output_phase='requalifying'
    from .current_beta1_source_read_v3 import reset_current_beta1_source_permission_v3
    reset_current_beta1_source_permission_v3(r);state.permission=None


def _numeric_output_keys_v3(r,frame):
    from .d05_relationship_revision_v2 import _candidate,_validate_ancillary
    read=RelationshipDomainReadV3(frame)
    result=_candidate(r.db,read,r.request,r.installed_readers)
    candidate,_,_,_,_,_,identity,*_=result
    _validate_ancillary(r.db,read,candidate)
    scope=candidate.scope
    keys=[scope.key(ESTIMATE_TYPE),scope.key(PROFILE_TYPE,'profile'),scope.key(CONTRIBUTION_TYPE,(candidate.contribution_kind,identity))]
    if candidate.initial_estimate is not None:
        keys.append(scope.key(CHECKPOINT_TYPE,candidate.reassessment_interpretation_ref or r.request.interpretation_ref))
    for value,kind in ((candidate.expectation,EXPECTATION_TYPE),(candidate.reciprocity,RECIPROCITY_TYPE),(candidate.repair,REPAIR_TYPE)):
        if value is not None:
            suffix=value.expectation_ref if kind==EXPECTATION_TYPE else value.pattern_ref if kind==RECIPROCITY_TYPE else(value.dispute_ref,value.action_kind)
            keys.append(scope.key(kind,suffix))
    # Rebuild writes each existing contribution in this exact dimension. Their
    # authenticated heads were selected by the original fixed family census.
    from .current_method_learning_read_v3 import method_domain_inventory_v3
    from ..domains.d05.relationship_revision_v2 import RelationshipScopeV2
    for atom in method_domain_inventory_v3(r.db,r.namespace,CONTRIBUTION_TYPE):
        if atom.valid and decode_typed_production_value_v3(atom.value['scope'],RelationshipScopeV2).scope_id==scope.scope_id:keys.append(atom.key)
    return tuple(sorted(set(keys),key=lambda key:key.token))


def _contribution_output_keys_v3(r):
    from .current_method_learning_read_v3 import method_graph_head_v3
    from .d05_production_operations_v1 import _relationship_trigger_sources_v1,_relationship_canonical_identity_v1
    from ..domains.d05.relationship import RelationshipContribution,CONTRIBUTION_KINDS_V2
    from ..graph_types import Owner
    state=require_relationship_source_v3(r);state.permission.require_for_v3(r)
    trigger=method_graph_head_v3(r.db,r.namespace,AtomKey.from_token(r.request.trigger_original_ref))
    roots=_relationship_trigger_sources_v1(r.namespace,trigger.key,trigger.value)
    if not roots:raise MissingProductionOriginalV1('actual_relationship_trigger_content_sources')
    source=state.permission.records[roots[0]]
    identity,aliases=_relationship_canonical_identity_v1(r.db,r.namespace,r.request,roots,source)
    item=RelationshipContribution('persona:'+r.namespace.persona_id,identity,r.request.subject_entity_ref,
        r.request.dimension,r.request.semantics,1,roots,schema_version=2,kind=CONTRIBUTION_KINDS_V2[r.request.semantics],
        recollection_activity_ref=trigger.key.token if r.request.semantics=='recollection'else None,
        identity_status='resolved',legacy_alias_keys=aliases)
    owner=Owner('relation',*r.namespace.as_tuple,r.request.subject_entity_ref)
    return tuple(sorted((AtomKey(owner,'d05.contribution',item.key),AtomKey(owner,'d05.relationship_projection',r.request.dimension)),key=lambda key:key.token))


def _augment_contribution_output_plan_v3(r):
    from ..domains.d05.production_operations_v1 import AdoptCurrentRelationshipContributionRequestV1
    from ..domains.d05.relationship import RelationshipContribution
    from ..graph_types import Owner
    from .current_method_learning_read_v3 import method_graph_head_v3
    from .d05_production_operations_v1 import _relationship_trigger_sources_v1
    state=require_relationship_source_v3(r)
    if type(r.request)is not AdoptCurrentRelationshipContributionRequestV1 or r.read_finished or r.inputs_sealed or r.business_started or r.frame_fields is None or r.fence.scope.operation!='read':
        raise AuthorityUnavailable('D05 contribution output planning requires its exact unsealed Source Work')
    if state.output_phase=='complete':return False
    if state.output_phase=='unplanned':
        state.permission.require_for_v3(r)
        if r.request.semantics=='recollection':
            trigger=method_graph_head_v3(r.db,r.namespace,AtomKey.from_token(r.request.trigger_original_ref))
            roots=_relationship_trigger_sources_v1(r.namespace,trigger.key,trigger.value)
            if not roots:raise MissingProductionOriginalV1('actual_relationship_trigger_content_sources')
            source=state.permission.records[roots[0]]
            legacy=RelationshipContribution('persona:'+r.namespace.persona_id,source.provenance_root,r.request.subject_entity_ref,r.request.dimension,r.request.semantics,1,roots)
            state.keys.add(AtomKey(Owner('relation',*r.namespace.as_tuple,r.request.subject_entity_ref),'d05.contribution',legacy.key))
            state.legacy_selector=(source.provenance_root,r.request.subject_entity_ref,r.request.dimension)
            state.legacy_selectors.add(state.legacy_selector);state.output_phase='legacy_metadata'
        else:state.output_phase='outputs'
    if state.output_phase=='legacy_metadata':
        selector=state.legacy_selector;matches=_metadata(r,('legacy_catalogue',selector));state.legacy_matches[selector]=matches
        for operation_id,trigger_ref in matches:
            state.keys.add(AtomKey.from_token(trigger_ref));state.originals.add(trigger_ref);state.producers.add(('',operation_id))
        state.output_phase='trigger_metadata'
    if state.output_phase=='trigger_metadata':_renew_numeric_plan_v3(r,'outputs')
    if state.output_phase=='requalifying':
        require_relationship_sources_v3(r,r.selected_plan.source_roots);_refresh_relationship_originals_v3(r)
        state.output_phase=state.output_next_phase;return True
    if state.output_phase=='outputs':
        state.output_keys=_contribution_output_keys_v3(r);state.keys.update(state.output_keys);state.output_phase='output_metadata'
    if state.output_phase=='output_metadata':_renew_numeric_plan_v3(r,'checking')
    if state.output_phase=='requalifying':
        require_relationship_sources_v3(r,r.selected_plan.source_roots);_refresh_relationship_originals_v3(r)
        state.output_phase=state.output_next_phase;return True
    if state.output_phase!='checking'or _contribution_output_keys_v3(r)!=state.output_keys:
        raise AuthorityUnavailable('D05 contribution canonical output keys changed after complete Source renewal')
    state.output_phase='complete';return False


def augment_current_relationship_output_plan_v3(r):
    if r.operation_kind=='adopt_relationship_contribution':return _augment_contribution_output_plan_v3(r)
    state=require_relationship_source_v3(r)
    if state.output_phase not in {'dependency_metadata','legacy_metadata','trigger_metadata','output_metadata','requalifying'}:
        require_current_relationship_numeric_reader_v3(r)
    from .domain_production_contracts_v1 import CurrentOperationFrameV1
    from .d05_relationship_revision_v2 import _decode_candidate
    from .current_method_learning_read_v3 import method_graph_head_v3
    if r.read_finished or r.inputs_sealed or r.business_started or r.frame_fields is None or r.fence.scope.operation!='read':
        raise AuthorityUnavailable('D05 output planning requires its actual original unsealed READ frame')
    if state.output_phase=='complete':return False
    if state.output_phase=='unplanned':
        atom=method_graph_head_v3(r.db,r.namespace,AtomKey.from_token(r.request.interpretation_ref))
        candidate=_decode_candidate(atom.value);state.numeric_candidate=candidate
        _discover_numeric_candidate_v3(r,candidate);state.output_phase='dependency_metadata'
    if state.output_phase=='dependency_metadata':_renew_numeric_plan_v3(r,'outputs')
    if state.output_phase=='requalifying':
        require_relationship_sources_v3(r,r.selected_plan.source_roots)
        _refresh_relationship_originals_v3(r)
        state.output_phase=state.output_next_phase
        return True
    if state.output_phase=='outputs'and not state.trigger_key_planned:
        candidate=state.numeric_candidate
        if candidate.contribution_kind!='administrative_edit':
            trigger=method_graph_head_v3(r.db,r.namespace,AtomKey.from_token(candidate.trigger_original_ref))
            from .d05_production_operations_v1 import _relationship_trigger_sources_v1
            roots=_relationship_trigger_sources_v1(r.namespace,trigger.key,trigger.value)
            if not roots:raise MissingProductionOriginalV1('actual_relationship_trigger_content_sources')
            source=state.permission.records[roots[0]]
            from ..domains.d05.relationship import RelationshipContribution
            from ..graph_types import Owner
            semantics={'external_interaction':'external_observation','internal_recollection':'recollection','simulated_trial':'simulation'}[candidate.contribution_kind]
            legacy=RelationshipContribution('persona:'+r.namespace.persona_id,source.provenance_root,candidate.scope.subject_entity_ref,candidate.scope.dimension,semantics,1,roots)
            state.keys.add(AtomKey(Owner('relation',*r.namespace.as_tuple,candidate.scope.subject_entity_ref),'d05.contribution',legacy.key))
        state.trigger_key_planned=True;state.output_phase='legacy_metadata'
    if state.output_phase=='legacy_metadata':
        candidate=state.numeric_candidate
        if candidate.contribution_kind=='internal_recollection':
            if state.legacy_selector is None:
                trigger=method_graph_head_v3(r.db,r.namespace,AtomKey.from_token(candidate.trigger_original_ref))
                from .d05_production_operations_v1 import _relationship_trigger_sources_v1
                source=state.permission.records[_relationship_trigger_sources_v1(r.namespace,trigger.key,trigger.value)[0]]
                state.legacy_selector=(source.provenance_root,candidate.scope.subject_entity_ref,candidate.scope.dimension)
                state.legacy_selectors.add(state.legacy_selector)
            selector=state.legacy_selector
            matches=_metadata(r,('legacy_catalogue',selector));state.legacy_matches[selector]=matches
            for operation_id,trigger_ref in matches:
                state.keys.add(AtomKey.from_token(trigger_ref));state.originals.add(trigger_ref);state.producers.add(('',operation_id))
        state.output_phase='trigger_metadata'
    if state.output_phase=='trigger_metadata':
        _renew_numeric_plan_v3(r,'outputs')
        require_relationship_sources_v3(r,r.selected_plan.source_roots)
        state.output_phase='outputs'
        return True
    if state.output_phase=='outputs':
        from .d07_execution_v1 import read_prepared_d07_execution_v1
        prepared_ref=next(ref for kind,ref in state.numeric_d07 if kind=='prepared')
        prepared=read_prepared_d07_execution_v1(r.db,r.installed_readers.issuer,r.namespace,prepared_ref)
        if prepared is None or prepared.digest!=state.numeric_prepared_digest:raise AuthorityUnavailable('D05 numeric prepared Body differs from actual signed metadata')
        if state.numeric_prepared is None:state.numeric_prepared=prepared
        elif state.numeric_prepared!=prepared:raise AuthorityUnavailable('D05 numeric actual prepared EOF changed during its same Work')
        keys=_numeric_output_keys_v3(r,CurrentOperationFrameV1(*r.frame_fields))
        if len(keys)>CurrentOperationFrameV1(*r.frame_fields).limits.max_writes:raise MissingProductionOriginalV1('bounded_relationship_actual_output_keys')
        state.output_keys=keys;state.keys.update(keys);state.output_phase='output_metadata'
    if state.output_phase=='output_metadata':_renew_numeric_plan_v3(r,'checking')
    if state.output_phase=='requalifying':
        require_relationship_sources_v3(r,r.selected_plan.source_roots)
        _refresh_relationship_originals_v3(r)
        state.output_phase=state.output_next_phase
        return True
    if state.output_phase!='checking':raise AuthorityUnavailable('D05 numeric output phase differs')
    if _numeric_output_keys_v3(r,CurrentOperationFrameV1(*r.frame_fields))!=state.output_keys:
        raise AuthorityUnavailable('D05 pure output keys changed after actual metadata and complete Source renewal')
    state.output_phase='complete'
    return False


class _LegacyCatalogueV3:
    """Whole original metadata EOF census; no JSON SQL predicate or Body grant."""
    def __init__(self,r,identity):
        self.reader,self.identity=r,identity;self.cursor='';self.pending=None;self.column=None;self.matches=[];self.complete=False;self.result=None;self.phase='next'
        if identity[1]not in require_relationship_source_v3(r).legacy_selectors or require_relationship_source_v3(r).output_phase!='legacy_metadata':raise AuthorityUnavailable('D05 legacy census lacks actual Source-derived identity selector')
    def require_header_v3(self,meter):
        self.reader.require_current(meter=meter);return self.result
    def advance(self,meter):
        r=self.reader;r.require_current(meter=meter);state=require_relationship_source_v3(r)
        from .current_beta1_source_read_v3 import create_current_beta1_metadata_task_v3
        if self.phase=='next':
            row=_runtime_bounded_fixed_row_v3(r.db,meter,'graph_domain_production_originals_v1',('operation_id',),
                "bot=? AND persona=? AND domain='d05' AND operation_kind='adopt_relationship_contribution' AND operation_id>? ORDER BY operation_id",(*r.namespace.as_tuple,self.cursor))
            if row is None:self.complete=True;self.result=tuple(self.matches);return True
            self.pending=row[0];state.legacy_operations.add(row[0]);identity=('legacy_original',row[0]);state.selected.add(identity)
            self.column=create_current_beta1_metadata_task_v3(r,identity);self.phase='original';return False
        if not self.column.complete:self.column.advance(meter);return False
        self.column.require_header_v3(meter)
        if self.phase=='original':
            value=self.column.result;contribution=value['provenance']['contribution']
            matched=(contribution['canonical_event_or_family_ref'],contribution['subject_entity_ref'],contribution['target_dimension'])==self.identity[1]and contribution['semantics']=='recollection'
            if matched:
                self.matches.append((self.pending,value['provenance']['trigger']['original_ref']))
                identity=('legacy_reads',self.pending);state.selected.add(identity);self.column=create_current_beta1_metadata_task_v3(r,identity);self.phase='reads';return False
            state.legacy_operations.discard(self.pending)
        else:
            for token,revision in self.column.result:
                key=AtomKey.from_token(token)
                if NamespaceId.from_key(key)!=r.namespace:raise AuthorityUnavailable('D05 legacy readset crossed namespace')
                if key.type_name=='memory.source':
                    if r.operation_kind=='adopt_relationship_contribution':state.contribution_legacy_roots.add(token)
                    else:state.roots.add(token)
        self.cursor=self.pending;self.pending=self.column=None;self.phase='next';return False


def read_relationship_recollection_identity_v3(db,namespace,request,roots,source):
    r=_active(db)
    if r is None:return False,None
    state=require_relationship_source_v3(r)
    if r.operation_kind=='adopt_relationship_contribution':
        from ..domains.d05.production_operations_v1 import AdoptCurrentRelationshipContributionRequestV1
        if type(r.request)is not AdoptCurrentRelationshipContributionRequestV1 or request!=r.request or state.permission is None:raise AuthorityUnavailable('D05 recollection identity requires its actual typed Source Work')
        state.permission.require_for_v3(r)
    else:require_current_relationship_numeric_reader_v3(r)
    from .domain_production_read_plans_v1 import read_committed_recollection_original_v1
    _,identity=read_committed_recollection_original_v1(db,namespace,request.trigger_original_ref)
    selector=(source.provenance_root,request.subject_entity_ref,request.dimension)
    if selector not in state.legacy_matches:raise AuthorityUnavailable('D05 legacy canonical identity lacks complete selected metadata census')
    from ..domains.d05.relationship import RelationshipContribution
    from ..graph_types import Owner
    legacy=RelationshipContribution('persona:'+namespace.persona_id,source.provenance_root,request.subject_entity_ref,request.dimension,request.semantics,1,roots)
    legacy_key=AtomKey(Owner('relation',*namespace.as_tuple,request.subject_entity_ref),'d05.contribution',legacy.key)
    if legacy_key.token not in r.heads:return True,(identity,())
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    identities=set()
    for operation_id,trigger_ref in state.legacy_matches[selector]:
        saved=read_adopted_domain_operation_v1(db,namespace,operation_id)
        contribution=saved['payload']['provenance']['contribution']
        if(saved['domain'],saved['operation_kind'])!=('d05','adopt_relationship_contribution')or(saved['payload']['provenance']['trigger']['original_ref']!=trigger_ref
                or (contribution['canonical_event_or_family_ref'],contribution['subject_entity_ref'],contribution['target_dimension'])!=selector
                or contribution['semantics']!='recollection'):
            raise AuthorityUnavailable('D05 legacy complete original differs from its whole metadata census')
        _,actual=read_committed_recollection_original_v1(db,namespace,trigger_ref);identities.add(actual)
    return True,((source.provenance_root if len(identities)==1 else identity),(legacy_key.token,))if identity in identities else(identity,())


def _refresh_relationship_originals_v3(r):
    state=require_relationship_source_v3(r)
    from .domain_production_read_plans_v1 import read_current_domain_original_refs_v1,read_current_domain_policy_refs_v1
    if state.control_originals is None:state.control_originals=r.observed_originals
    business=read_current_domain_original_refs_v1(r.db,namespace=r.namespace,plan=r.selected_plan,installed_readers=r.installed_readers)
    r.observed_originals=tuple({item.original_ref:item for item in (*state.control_originals,*business)}.values())
    r.installed_policy_refs=read_current_domain_policy_refs_v1(r.db,namespace=r.namespace,plan=r.selected_plan,installed_readers=r.installed_readers)


def prepare_current_relationship_source_dependencies_v3(r):
    """Prepare actual Original EOF and policy pins before this same Work seals."""
    state=require_relationship_source_v3(r)
    if r.operation_kind in {'adopt_relationship_revision_v2','adopt_relationship_contribution'}and state.output_phase in {'dependency_metadata','legacy_metadata','trigger_metadata','output_metadata','requalifying'}:
        return augment_current_relationship_output_plan_v3(r)
    require_relationship_sources_v3(r,r.selected_plan.source_roots)
    if r.installed_readers is None:
        from .domain_production_registry_v1 import installed_operation_v1,installed_readers_for_operation_v1
        r.installed_readers=installed_readers_for_operation_v1(r.graph,installed_operation_v1(r.operation_kind),
            scope=r.fence.scope,owner_guard=r.owner_guard,owner_binding=r.owner_binding,
            execution_reader=r.graph._GraphCoordinator__d07_execution_service_v1)
    _refresh_relationship_originals_v3(r)
    return False


def _relationship_ingress_operations_v3(r):
    state=require_relationship_source_v3(r)
    if state.permission is None:raise AuthorityUnavailable('D05 Host identity requires actual complete Source ALL')
    state.permission.require_for_v3(r)
    from .first_ingress_v2 import ingress_ids
    return {ingress_ids(record.source_id)[2]for record in state.permission.records.values()
        if len(record.source_id)==64 and set(record.source_id)<=set('0123456789abcdef')}


class CurrentRelationshipCorrectionContextV3:
    """One actual reevaluation's corrected Source context, never an execution grant."""
    def __init__(self,issuer,r,head_value,head_task,old_source,new_source):
        if issuer is not _CORRECTION_ISSUER:raise AuthorityUnavailable('private relationship correction issuer required')
        self.reader=r;self.head_value=head_value;self.head_metadata=head_task.metadata
        self.head_digest=head_task.column.canonical_digest
        self.old_source,self.new_source=old_source,new_source
        self.identity=(_identity(r),self.head_metadata,self.head_digest,canonical_digest(head_value),
            old_source.header,old_source.sha256,new_source.header,new_source.sha256)
        _CORRECTION_CONTEXTS[r]=(self,self.identity)
    def require_current_v3(self,r):
        state=require_relationship_source_v3(r);r.require_current()
        if(r is not self.reader or state.correction_context is not self
                or _CORRECTION_CONTEXTS.get(r)!=(self,self.identity)
                or self.identity[0]!=_identity(r)or canonical_digest(self.head_value)!=self.identity[3]
                or r.operation_kind!='reevaluate_relationship'or r.audience_ref!='owner'):
            raise AuthorityUnavailable('relationship corrected context changed actual Owner/Work/selection')
        with runtime_storage_quantum_v3(r.db)as meter:
            task=state.tasks[('head',r.request.correction_head_ref)];task.require_header_v3(meter)
            self.old_source.require_v1(r,meter);self.new_source.require_v1(r,meter)
            if(task.metadata,task.column.canonical_digest,self.old_source.header,self.old_source.sha256,self.new_source.header,self.new_source.sha256)!=(
                self.head_metadata,self.head_digest,*self.identity[4:]):
                raise AuthorityUnavailable('relationship correction full metadata EOF changed')
        return self
    def permits_v3(self,r,ref,purpose,audience,head):
        self.require_current_v3(r)
        if ref!=self.head_value['source_ref']:return False
        if(purpose!='context'or audience!='owner'or head.key.token!=r.request.correction_head_ref
                or not head.valid or head.revision!=self.head_metadata[0]or head.value!=self.head_value):
            raise AuthorityUnavailable('relationship corrected Source lacks its exact current correction original')
        return True


def prepare_relationship_correction_context_v3(r):
    from ..domains.d05.production_operations_v1 import ReevaluateCurrentRelationshipRequestV1
    from ..domains.d06 import validate_source_correction_head
    from .current_beta1_source_read_v3 import _SOURCE_TASKS,_SOURCE_PENDING
    from .current_method_learning_read_v3 import _need_method_input
    from .dispatch_initial_source_read_v3 import _SourceMetadataRecordV3
    state=require_relationship_source_v3(r)
    if r.operation_kind!='reevaluate_relationship'or type(r.request)is not ReevaluateCurrentRelationshipRequestV1:
        raise AuthorityUnavailable('relationship correction qualifier requires exact registered request')
    if state.correction_context is not None:return state.correction_context.require_current_v3(r)
    if r.read_finished or r.inputs_sealed or r.business_started or r.audience_ref!='owner':
        raise AuthorityUnavailable('relationship correction context must be prepared by actual Owner READ')
    r.general_owner_entry.require_for_v3(r)
    value=_metadata(r,('head',r.request.correction_head_ref));key=AtomKey.from_token(r.request.correction_head_ref)
    validate_source_correction_head(key,value);task=state.tasks[('head',key.token)]
    if task.metadata[0]<1 or not task.metadata[1]:raise MissingProductionOriginalV1('actual_current_relationship_correction_head')
    sources=[]
    for ref in(value['source_ref'],value['correction_source_ref']):
        leaf=_SOURCE_TASKS.get(r,{}).get(ref)
        if leaf is None or not leaf.complete:
            _SOURCE_PENDING.setdefault(r,set()).add(ref);_need_method_input(r,('beta1_source_metadata',ref))
        with runtime_storage_quantum_v3(r.db)as meter:leaf.require_v1(r,meter)
        sources.append(leaf)
    old,new=sources;original,correction=(_SourceMetadataRecordV3(leaf.metadata)for leaf in sources)
    if(old.revision!=value['source_revision']or not old.valid or not new.valid or new.revision<1
            or original.source_id!=AtomKey.from_token(value['source_ref']).owner.subject
            or correction.source_id!=AtomKey.from_token(value['correction_source_ref']).owner.subject
            or original.source_id not in correction.parent_source_ids
            or correction.provenance_root!='owner.correction.v1'or correction.source_kind!='reported'):
        raise AuthorityUnavailable('relationship correction Source metadata differs from actual D06 original')
    proof=CurrentRelationshipCorrectionContextV3(_CORRECTION_ISSUER,r,value,task,old,new)
    state.correction_context=proof
    return proof.require_current_v3(r)


def qualify_relationship_corrected_context_v3(r,ref,source,access,head,*,purpose,audience):
    state=require_relationship_source_v3(r);proof=state.correction_context
    if proof is None or not proof.permits_v3(r,ref,purpose,audience,head):return None
    if source is not proof.old_source:raise AuthorityUnavailable('relationship corrected Source changed actual inspection original')
    from ..domains.d07.qualified_attention_read import _qualify_source_acl_values_v3
    return _qualify_source_acl_values_v3(r.namespace,ref,source,access,audience=audience,purpose=purpose,metadata_only=True)


def _reevaluation_selection_v3(r,head,rows):
    affected={head['source_ref'],*head['target_refs']};selected={kind:[]for kind in _REEVALUATION_TYPES};relations=set()
    for key,value in rows.items():
        names=_REEVALUATION_FIELDS[key.type_name]
        if set(value)!=set(names):raise AuthorityUnavailable('relationship reevaluation selector metadata is incomplete')
        if key.type_name in {'d05.boundary_rule','d05.contribution'}:
            refs=value['source_refs']
            if type(refs)is not list or any(type(ref)is not str for ref in refs):raise AuthorityUnavailable('relationship reevaluation Source selector differs')
            if affected.intersection(refs):
                selected[key.type_name].append(key)
                if key.type_name=='d05.contribution':relations.add((value['subject_entity_ref'],value['target_dimension']))
    for key,value in rows.items():
        if key.type_name=='d05.relationship_projection'and(value['subject_entity_ref'],value['dimension'])in relations:
            selected[key.type_name].append(key)
    return {kind:tuple(sorted(keys,key=lambda key:key.token))for kind,keys in selected.items()}


def _read_plan_relationship_reevaluation_v3(r):
    state=require_relationship_source_v3(r);key=AtomKey.from_token(r.request.correction_head_ref)
    state.metadata_keys.add(key);head=_metadata(r,('head',key.token))
    from ..domains.d06 import validate_source_correction_head
    validate_source_correction_head(key,head)
    rows={}
    for token in sorted(r.heads):
        atom=AtomKey.from_token(token)
        if atom.type_name in _REEVALUATION_TYPES:
            state.metadata_keys.add(atom);rows[atom]=_metadata(r,('head',token))
    selected=_reevaluation_selection_v3(r,head,rows)
    if state.reevaluation_rows and(state.reevaluation_rows!=rows or state.reevaluation_selected!=selected):
        raise AuthorityUnavailable('relationship reevaluation metadata selection changed')
    if not state.reevaluation_rows:r.operation.retain(4096+128*len(rows))
    state.reevaluation_rows=rows;state.reevaluation_selected=selected;state.reevaluation_affected=(head['source_ref'],tuple(head['target_refs']))
    state.keys.update((owner_grant_key(*r.namespace.as_tuple),key,AtomKey.from_token(head['source_ref']),AtomKey.from_token(head['correction_source_ref'])))
    state.roots.add(head['correction_source_ref'])
    for keys in selected.values():
        for atom in keys:
            state.keys.add(atom);state.roots.update(_roots(rows[atom]))
    if any(NamespaceId.from_key(AtomKey.from_token(ref))!=r.namespace or AtomKey.from_token(ref).type_name!='memory.source'for ref in state.roots):
        raise AuthorityUnavailable('relationship reevaluation Source metadata crossed its namespace')
    state.metadata_complete=True
    return production_read_plan_v1(_REEVALUATION_TYPES,tuple(sorted(state.keys,key=lambda key:key.token)),tuple(sorted(state.roots)),())


def current_relationship_metadata_inventory_v3(prepared,type_id):
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3
    if type(prepared)is not PreparedMethodDomainInputsV3:return None
    r=prepared.owner
    types=_CONTRIBUTION_TYPES if r.operation_kind=='adopt_relationship_contribution'else _REEVALUATION_TYPES if r.operation_kind=='reevaluate_relationship'else ()
    if type_id not in types:return None
    state=require_relationship_source_v3(r);r.require_current()
    rows=state.contribution_rows if r.operation_kind=='adopt_relationship_contribution'else state.reevaluation_rows
    if not state.metadata_complete or state.permission is None:raise AuthorityUnavailable('relationship metadata inventory requires actual complete Source Work')
    state.permission.require_for_v3(r)
    with runtime_storage_quantum_v3(r.db)as meter:
        for key in rows:state.tasks[('head',key.token)].require_header_v3(meter)
    return tuple(GraphVersion(key,r.heads[key.token][0])for key in sorted(rows,key=lambda key:key.token)if key.type_name==type_id)


def compose_relationship_metadata_cas_v3(db,read_versions,limits):
    r=_active(db)
    if r is None or r.operation_kind not in {'reevaluate_relationship','adopt_relationship_contribution'}:return read_versions
    state=require_relationship_source_v3(r);state.permission.require_for_v3(r)
    if r.operation_kind=='reevaluate_relationship':state.correction_context.require_current_v3(r)
    rows=state.contribution_rows if r.operation_kind=='adopt_relationship_contribution'else state.reevaluation_rows
    versions={version.key:version for version in read_versions}
    extra=(*state.permission.versions,*(GraphVersion(key,r.heads[key.token][0])for key in rows))
    for version in extra:
        prior=versions.get(version.key)
        if prior is not None and prior!=version:raise AuthorityUnavailable('relationship metadata CAS has conflicting actual revisions')
        versions[version.key]=version
    if len(versions)>limits.max_graph_heads:raise MissingProductionOriginalV1('bounded_relationship_actual_metadata_cas')
    return tuple(sorted(versions.values(),key=lambda version:version.key.token))


def read_current_relationship_reevaluation_inventory_v3(db,frame,type_id):
    r=_active(db);state=require_relationship_source_v3(r)
    if r.operation_kind!='reevaluate_relationship'or type_id not in _REEVALUATION_TYPES:raise AuthorityUnavailable('exact relationship reevaluation inventory required')
    state.permission.require_for_v3(r);state.correction_context.require_current_v3(r)
    head=state.correction_context.head_value
    if((head['source_ref'],tuple(head['target_refs']))!=state.reevaluation_affected
            or _reevaluation_selection_v3(r,head,state.reevaluation_rows)!=state.reevaluation_selected):
        raise AuthorityUnavailable('relationship reevaluation changed its sealed metadata predicate inputs')
    pages=tuple(page for page in frame.query_coverage if page.type_id==type_id)
    expected=tuple(GraphVersion(key,r.heads[key.token][0])for key in sorted(state.reevaluation_rows,key=lambda key:key.token)if key.type_name==type_id)
    if len(pages)!=1 or not pages[0].complete or pages[0].row_versions!=expected or pages[0].epoch.revision!=frame.snapshot.epochs[0].revision:
        raise AuthorityUnavailable('relationship reevaluation lacks complete current metadata query coverage')
    read=RelationshipDomainReadV3(frame);atoms=[]
    for key in state.reevaluation_selected[type_id]:
        atom=read.head(db,key,required=False);value={name:atom.value[name]for name in _REEVALUATION_FIELDS[type_id]}
        if value!=state.reevaluation_rows[key]or(atom.revision,int(atom.valid))!=r.heads[key.token][:2]:
            raise AuthorityUnavailable('relationship selected Body differs from its actual metadata predicate')
        atoms.append(atom)
    return tuple(atoms)



def _plan_relationship_simulation_original_v3(r):
    state=require_relationship_source_v3(r);ref=r.request.trigger_original_ref;key=AtomKey.from_token(ref)
    if key.type_name!='d07.simulation_branch.v1'or key.token not in r.heads:
        raise MissingProductionOriginalV1('actual_adopted_simulation_branch')
    branch=_metadata(r,('head',ref));history=_metadata(r,('simulation_history',ref))
    current=state.tasks[('head',ref)];prior=state.tasks[('simulation_history',ref)]
    if(current.metadata[0]<1 or not current.metadata[1]or prior.metadata[:4]!=(1,*r.namespace.as_tuple,key.owner.subject)
            or current.column.canonical_digest!=prior.column.canonical_digest or branch!=history):
        raise AuthorityUnavailable('D05 simulation branch lost exact current same-activity history EOF')
    op=prior.metadata[4];state.simulation_operations[op]=ref;state.producers.add((key.owner.subject,op))
    original=_metadata(r,('simulation_original',op));reads=_metadata(r,('simulation_reads',op));receipt=_metadata(r,('simulation_receipt',op))
    producer_ref='d07-current:'+state.tasks[('simulation_original',op)].metadata[3][:48]
    state.simulation_original_refs[op]=producer_ref;state.originals.add(producer_ref)
    provenance=original['provenance'];execution=provenance.get('execution');identity=original['identity']
    if(identity['activity_id']!=key.owner.subject or provenance.get('schema')!='d07.actual-behavior-provenance.v1'
            or provenance.get('work_kind')!='simulation'or provenance.get('status')!='staged'
            or execution is None or execution.get('work_kind')!='simulation'or execution.get('input_digest')!=provenance.get('input_digest')
            or branch.get('schema')!='d07.simulation_branch.v1'or branch.get('branch_id')!=key.name
            or branch.get('content_reality')!='simulated'or branch.get('evidence_eligibility')!='none'):
        raise AuthorityUnavailable('D05 simulation requires its actual completed hypothetical producer')
    version=GraphVersion(key,current.metadata[0])
    from .domain_production_originals_v1 import _receipt
    actual_receipt=_receipt(receipt)
    if(actual_receipt.operation_id!=op or actual_receipt.activity_id!=identity['activity_id']
            or actual_receipt.effect_id!=identity['effect_id']or actual_receipt.operation_digest!=state.tasks[('simulation_original',op)].metadata[4]
            or version not in actual_receipt.write_versions):
        raise AuthorityUnavailable('D05 simulation branch is absent from its exact producer receipt')
    refs=set(branch['snapshot_refs'])|set(provenance['behavior']['request']['snapshot_refs'])|set(execution['source_refs'])
    read_versions={}
    for token,revision in reads:
        atom=AtomKey.from_token(token)
        if NamespaceId.from_key(atom)!=r.namespace or atom in read_versions:raise AuthorityUnavailable('D05 simulation original reads crossed namespace or repeated a head')
        read_versions[atom]=revision
    if any(read_versions.get(AtomKey.from_token(token),0)<1 for token in refs):
        raise AuthorityUnavailable('D05 simulation producer lacks its actual Source read versions')
    if any(AtomKey.from_token(token).type_name!='memory.source'or NamespaceId.from_key(AtomKey.from_token(token))!=r.namespace for token in refs):
        raise AuthorityUnavailable('D05 simulation producer sources are not its actual namespace roots')
    state.roots.update(refs)


def read_committed_simulation_branch_original_v3(db,namespace,ref):
    r=_active(db)
    if r is None or r.operation_kind!='adopt_relationship_contribution'or r.request.semantics!='simulation'or ref!=r.request.trigger_original_ref or namespace!=r.namespace:
        raise AuthorityUnavailable('simulation branch consumer requires its exact actual relationship Source Work')
    state=require_relationship_source_v3(r);state.permission.require_for_v3(r)
    from .current_method_learning_read_v3 import method_graph_head_v3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d07_behavior_stage_codec_v1 import validate_d07_behavior_provenance_v1
    key=AtomKey.from_token(ref);atom=method_graph_head_v3(db,namespace,key)
    history=state.tasks[('simulation_history',ref)];op=history.metadata[4]
    with runtime_storage_quantum_v3(db)as meter:
        for identity in(('head',ref),('simulation_history',ref),('simulation_original',op),('simulation_reads',op),('simulation_receipt',op)):
            state.tasks[identity].require_header_v3(meter)
    if not atom.valid or atom.revision!=r.heads[ref][0]or canonical_digest(atom.value)!=history.column.canonical_digest:
        raise AuthorityUnavailable('D05 actual simulation branch Body differs from fully selected metadata EOF')
    saved=read_adopted_domain_operation_v1(db,namespace,op)
    if saved is None:raise MissingProductionOriginalV1('actual_committed_simulation_domain_original')
    metadata=state.tasks[('simulation_original',op)].metadata;payload=saved['payload'];provenance=payload['provenance']
    if((saved['domain'],saved['operation_kind'],saved['request_digest'],saved['original_digest'],saved['receipt'].operation_digest,canonical_digest(saved['receipt']))!=metadata
            or saved['receipt'].activity_id!=key.owner.subject or GraphVersion(key,atom.revision)not in saved['receipt'].write_versions
            or payload.get('schema')!='d07.current-run_simulation.v1'):
        raise AuthorityUnavailable('D05 actual simulation original differs from its authenticated metadata and receipt')
    validate_d07_behavior_provenance_v1('run_simulation',provenance)
    if provenance['status']!='staged'or provenance['work_kind']!='simulation'or provenance['execution']is None:
        raise AuthorityUnavailable('D05 simulation has no actual completed execution original')
    behavior=provenance['behavior'];result=behavior['simulation_result'];execution=provenance['execution']
    branches=tuple(branch for branch in result['branches']if branch['branch_id']==key.name)
    writes=tuple(write for write in payload['writes']if write['key']==plain_v1(key))
    if(len(branches)!=1 or len(writes)!=1 or {'schema':key.type_name,**branches[0]}!=atom.value or writes[0]['value']!=atom.value
            or result['activity_id']!=key.owner.subject or behavior['request']['activity_id']!=key.owner.subject
            or execution['source_refs']!=behavior['request']['snapshot_refs']or execution['input_digest']!=provenance['input_digest']):
        raise AuthorityUnavailable('D05 actual simulation branch differs from its full original result and input')
    own,event=relationship_point_v3(db,'graph_events',('reads','revisions'),('bot','persona','session','event_id'),(*namespace.as_tuple,key.owner.subject,op))
    actual_reads=tuple((v.key.token,v.revision)for v in saved['read_versions'])
    if event is None:raise AuthorityUnavailable('D05 actual simulation producer lost its W01 event')
    event_reads=tuple(tuple(value)for value in json.loads(event[0]))
    if([ref,atom.revision]not in json.loads(event[1])or len(event_reads)!=len(actual_reads)or set(event_reads)!=set(actual_reads)
            or canonical_digest(actual_reads)!=state.tasks[('simulation_reads',op)].column.canonical_digest):
        raise AuthorityUnavailable('D05 actual simulation producer lost its complete W01 event/readset')
    state.simulation_originals[op]=saved
    return ProductionOriginalRefV1('d07.adopted_simulation',ref,canonical_digest(atom.value),(GraphVersion(key,atom.revision),))



def _contribution_source_metadata_v3(r,ref):
    from .current_beta1_source_read_v3 import _SOURCE_TASKS,_SOURCE_PENDING
    from .current_method_learning_read_v3 import _need_method_input
    leaf=_SOURCE_TASKS.get(r,{}).get(ref)
    if leaf is None or not leaf.complete:
        _SOURCE_PENDING.setdefault(r,set()).add(ref);_need_method_input(r,('beta1_source_metadata',ref))
    with runtime_storage_quantum_v3(r.db)as meter:leaf.require_v1(r,meter)
    return leaf


class _ContributionAncestryMetadataV3:
    """Bounded inspection-parent selector; this task issues no Source rights."""
    def __init__(self,r,identity):
        state=require_relationship_source_v3(r)
        if r.operation_kind!='adopt_relationship_contribution'or identity not in state.selected:
            raise AuthorityUnavailable('contribution ancestry metadata lacks its actual typed recipe')
        self.reader,self.identity=r,identity;self.pending=list(identity[1]);self.seen=set()
        self.current=self.leaf=None;self.complete=False;self.result=None
    def require_header_v3(self,meter):
        r=self.reader;r.require_current(meter=meter)
        if(require_relationship_source_v3(r).tasks.get(self.identity)is not self or not self.complete
                or self.result!=frozenset(self.seen)):
            raise AuthorityUnavailable('contribution ancestry metadata changed its complete same-Work selector')
        return self.result
    def advance(self,meter):
        r=self.reader;r.require_current(meter=meter)
        if self.complete:self.require_header_v3(meter);return True
        from .current_beta1_source_read_v3 import _SOURCE_PENDING,create_current_beta1_source_metadata_task_v3
        from .dispatch_initial_source_read_v3 import _SourceMetadataRecordV3
        from ..memory_types import source_key
        if self.leaf is not None:
            if not self.leaf.complete:self.leaf.advance(meter);return False
            self.leaf.require_v1(r,meter);record=_SourceMetadataRecordV3(self.leaf.metadata)
            if AtomKey.from_token(self.current)!=source_key(*r.namespace.as_tuple,record.source_id):
                raise AuthorityUnavailable('relationship Source selector crossed namespace')
            parents=tuple(source_key(*r.namespace.as_tuple,parent).token for parent in record.parent_source_ids)
            self.seen.add(self.current);self.pending.extend(parents)
            r.operation.retain(256+sum(len(ref)*2 for ref in(self.current,*parents)))
            self.current=self.leaf=None;return False
        if not self.pending:self.complete=True;self.result=frozenset(self.seen);return True
        ref=self.pending.pop()
        if ref in self.seen:return False
        if len(self.seen)>=256:raise MissingProductionOriginalV1('bounded_relationship_source_metadata_ancestry')
        _SOURCE_PENDING.setdefault(r,set()).add(ref)
        self.current=ref;self.leaf=create_current_beta1_source_metadata_task_v3(r,ref)
        return False


def _contribution_metadata_ancestry_v3(r,roots):
    return _metadata(r,('contribution_ancestors',tuple(sorted(roots))))


def _contribution_policy_metadata_v3(r):
    state=require_relationship_source_v3(r)
    with runtime_storage_quantum_v3(r.db)as meter:
        header=_runtime_bounded_fixed_row_v3(r.db,meter,'graph_d05_production_policies_v1',('revision','payload_digest','signature'),
            'bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC',(*r.namespace.as_tuple,r.request.policy_ref))
    if header is None:raise MissingProductionOriginalV1('installed_relationship_policy:'+r.request.policy_ref)
    if state.policy_header is not None and state.policy_header!=header:raise AuthorityUnavailable('D05 selected policy revision changed')
    state.policy_header=header;_metadata(r,('policy_locator',r.request.policy_ref))
    policy=_metadata(r,('policy',r.request.policy_ref));state.originals.add(r.request.policy_ref)
    return _roots(policy)


def _read_plan_relationship_contribution_v3(r):
    from ..graph_types import Owner
    from .d05_production_operations_v1 import _relationship_trigger_sources_v1
    state=require_relationship_source_v3(r);request=r.request;trigger=AtomKey.from_token(request.trigger_original_ref)
    owner=Owner('relation',*r.namespace.as_tuple,request.subject_entity_ref)
    state.keys.update((owner_grant_key(*r.namespace.as_tuple),trigger,AtomKey(owner,'d05.relationship_projection',request.dimension)))
    state.originals.add(request.trigger_original_ref)
    rows={}
    for token in sorted(r.heads):
        key=AtomKey.from_token(token)
        if key.type_name in _CONTRIBUTION_TYPES:
            state.metadata_keys.add(key);rows[key]=_metadata(r,('head',token))
    if state.contribution_rows and state.contribution_rows!=rows:raise AuthorityUnavailable('contribution complete metadata census changed')
    if not state.contribution_rows:r.operation.retain(4096+128*len(rows))
    state.contribution_rows=rows
    if trigger.type_name=='memory.source':roots={trigger.token}
    else:
        value=_metadata(r,('head',trigger.token));roots=set(_relationship_trigger_sources_v1(r.namespace,trigger,value))
    if not roots:raise MissingProductionOriginalV1('actual_relationship_trigger_content_sources')
    roots.update(state.contribution_legacy_roots)
    for key in state.output_keys:
        if key.type_name=='d05.contribution'and key in rows:roots.update(rows[key]['source_refs'])
    if request.semantics=='simulation':
        state.roots=set(roots);_plan_relationship_simulation_original_v3(r);roots.update(state.roots)
    identity_refs=set(_contribution_policy_metadata_v3(r));entities=[];accounts=[]
    for key,value in rows.items():
        names=_CONTRIBUTION_FIELDS[key.type_name]
        required=set(names)-({'identity_status','schema_version'}if key.type_name=='d05.contribution'else set())
        if not required<=set(value):raise AuthorityUnavailable('contribution selector metadata is incomplete')
        if key.type_name=='d03.entity_anchor'and value['entity_id']==request.subject_entity_ref and value['status']=='active'and r.heads[key.token][1]:
            entities.append(key);identity_refs.update(value['creation_evidence_refs'])
    if len(entities)!=1:raise MissingProductionOriginalV1('unique_current_d03_relationship_entity')
    route=None
    if trigger.type_name=='memory.source':
        from .dispatch_initial_source_read_v3 import _SourceMetadataRecordV3
        from .first_ingress_v2 import ingress_ids
        source=_SourceMetadataRecordV3(_contribution_source_metadata_v3(r,trigger.token).metadata)
        operation=ingress_ids(source.source_id)[2]
        with runtime_storage_quantum_v3(r.db)as meter:
            route=_runtime_bounded_fixed_row_v3(r.db,meter,'graph_first_ingress_identity_v1',('source_ref','platform_ref','sender_ref'),
                'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,operation))
        if route is None or route[0]!=trigger.token or route[2]!=source.speaker_id:raise MissingProductionOriginalV1('original_inbound_host_actor_identity')
        for key,value in rows.items():
            if(key.type_name=='d03.account_binding'and r.heads[key.token][1]and value['platform_namespace']==route[1]
                    and value['platform_identifier']==route[2]and value['entity_id']==request.subject_entity_ref
                    and value['valid_from']<=r.initial_now_utc and(value['valid_until']is None or r.initial_now_utc<=value['valid_until'])):
                accounts.append(key)
                identity_refs.update(_roots({'creation_evidence_refs':[value['verification_ref']]}))
        if len(accounts)!=1:raise MissingProductionOriginalV1('exact_current_d03_inbound_actor_binding')
    if state.contribution_route is not None and state.contribution_route!=route:raise AuthorityUnavailable('contribution actual Host route changed')
    state.contribution_route=route;state.contribution_selected={'d03.entity_anchor':tuple(entities),'d03.account_binding':tuple(accounts)}
    state.keys.update((*entities,*accounts))
    for key in tuple(state.keys):
        if key.type_name=='d06.recollection.v1'and key!=trigger and key.token in r.heads:
            value=_metadata(r,('head',key.token));roots.update(_relationship_trigger_sources_v1(r.namespace,key,value))
    ancestors=_contribution_metadata_ancestry_v3(r,roots)
    groups={ref:state.contribution_identity_groups.get(ref,('context',(r.audience_ref,))if ref in ancestors else('context',('owner',)))for ref in identity_refs}
    if any(AtomKey.from_token(ref).type_name!='memory.source'or NamespaceId.from_key(AtomKey.from_token(ref))!=r.namespace for ref in groups):
        raise AuthorityUnavailable('contribution identity Source provenance crossed namespace')
    private={ref for ref,group in groups.items()if group==('context',('owner',))and(ref not in ancestors or ref in state.contribution_p_roots)}
    state.contribution_identity_groups=groups;state.contribution_r_roots=set(roots);state.contribution_p_roots=private
    state.roots=set(roots)|private
    if len(state.roots)>32:raise MissingProductionOriginalV1('source_root_budget_exceeded(required_count='+str(len(state.roots))+',limit=32)')
    state.metadata_complete=True
    return production_read_plan_v1(_CONTRIBUTION_TYPES,tuple(sorted(state.keys,key=lambda key:key.token)),tuple(sorted(state.roots)),tuple(sorted(state.originals)))


def _require_contribution_policy_sources_v3(db,read,refs):
    r=_active(db);state=require_relationship_source_v3(r);state.permission.require_for_v3(r)
    if not refs:raise MissingProductionOriginalV1('bounded_source_roots')
    from .current_beta1_source_read_v3 import require_beta1_source_member_v3
    grouped={}
    for ref in refs:
        group=state.contribution_identity_groups.get(ref)
        if group is None:raise AuthorityUnavailable('identity Source lacks its sealed contribution group')
        require_beta1_source_member_v3(r,ref,*group);grouped.setdefault(group,[]).append(ref)
    for(purpose,audiences),roots in grouped.items():read.source_family(db,tuple(roots),purpose=purpose,audience=audiences[0])


def _contribution_selected_body_v3(db,read,type_id):
    r=_active(db);state=require_relationship_source_v3(r);state.permission.require_for_v3(r);atoms=[]
    for key in state.contribution_selected[type_id]:
        atom=read.head(db,key,required=True)
        expected=state.contribution_rows[key];value={name:atom.value[name]for name in _CONTRIBUTION_FIELDS[type_id]}
        if value!=expected or(atom.revision,int(atom.valid))!=r.heads[key.token][:2]:raise AuthorityUnavailable('contribution selected Body differs from metadata selector')
        atoms.append(atom)
    return tuple(atoms)


def read_current_relationship_contribution_entity_v3(db,read,entity):
    r=_active(db)
    if r is None or r.operation_kind!='adopt_relationship_contribution':return None
    if entity!=r.request.subject_entity_ref:raise AuthorityUnavailable('contribution entity crossed its actual request')
    atoms=_contribution_selected_body_v3(db,read,'d03.entity_anchor')
    if len(atoms)!=1 or atoms[0].value['entity_id']!=entity or atoms[0].value['status']!='active':raise MissingProductionOriginalV1('unique_current_d03_relationship_entity')
    atom=atoms[0];_require_contribution_policy_sources_v3(db,read,tuple(atom.value['creation_evidence_refs']))
    return ProductionOriginalRefV1('d03.entity',atom.key.token,canonical_digest(atom.value),(GraphVersion(atom.key,atom.revision),))


def read_current_relationship_contribution_actor_v3(db,read,source_ref,*,expected_entity):
    r=_active(db);state=require_relationship_source_v3(r)
    if source_ref!=r.request.trigger_original_ref or expected_entity!=r.request.subject_entity_ref:raise AuthorityUnavailable('contribution actor crossed actual inbound request')
    record=read.source_family(db,(source_ref,))[source_ref]
    from .ingress_observation import read_committed_ingress_identity
    ingress=read_committed_ingress_identity(db,r.namespace,record.source_id)
    if ingress is None:raise MissingProductionOriginalV1('original_inbound_host_actor_identity')
    identity=json.loads(ingress.identity_json);route=state.contribution_route
    if route!=(source_ref,identity['platform_ref'],identity['sender_ref'])or record.speaker_id!=identity['sender_ref']:
        raise AuthorityUnavailable('contribution actual Host actor differs from metadata route')
    accounts=_contribution_selected_body_v3(db,read,'d03.account_binding');entities=_contribution_selected_body_v3(db,read,'d03.entity_anchor')
    if len(accounts)!=1 or len(entities)!=1:raise MissingProductionOriginalV1('exact_current_d03_inbound_actor_binding')
    account=accounts[0];value=account.value
    if(value['entity_id']!=expected_entity or value['platform_namespace']!=identity['platform_ref']or value['platform_identifier']!=identity['sender_ref']
            or value['valid_from']>read.frame.now_utc or value['valid_until']is not None and read.frame.now_utc>value['valid_until']):
        raise AuthorityUnavailable('contribution actor does not satisfy actual D03 binding predicate')
    refs=_roots({'creation_evidence_refs':[value['verification_ref']]})
    if refs:_require_contribution_policy_sources_v3(db,read,tuple(sorted(refs)))
    return account,entities[0]


def read_current_relationship_contribution_facts_v3(db,frame):
    from ..domains.d05.production_operations_v1 import CurrentRelationshipContributionFactsV1
    r=_active(db);state=require_relationship_source_v3(r);state.permission.require_for_v3(r)
    if r.operation_kind!='adopt_relationship_contribution':return None
    rows=state.contribution_rows;versions=tuple(GraphVersion(key,r.heads[key.token][0])for key in sorted(rows,key=lambda key:key.token))
    for type_id in _CONTRIBUTION_TYPES:
        expected=tuple(version for version in versions if version.key.type_name==type_id)
        pages=tuple(page for page in frame.query_coverage if page.type_id==type_id)
        if len(pages)!=1 or not pages[0].complete or pages[0].row_versions!=expected or pages[0].epoch.revision!=frame.snapshot.epochs[0].revision:
            raise AuthorityUnavailable('contribution metadata facts lack complete current query coverage')
    with runtime_storage_quantum_v3(db)as meter:
        for key in rows:state.tasks[('head',key.token)].require_header_v3(meter)
    from ..graph_types import Owner
    owner=Owner('relation',*r.namespace.as_tuple,r.request.subject_entity_ref)
    related=tuple(key for key,value in rows.items()if key.type_name=='d05.contribution'and key.owner==owner
        and value['subject_entity_ref']==r.request.subject_entity_ref and value['target_dimension']==r.request.dimension)
    valid=tuple(sorted((key for key in related if r.heads[key.token][1]),key=lambda key:key.token))
    projection=AtomKey(owner,'d05.relationship_projection',r.request.dimension)
    status=rows[projection]['status']if projection in rows else None
    metadata=tuple((GraphVersion(key,r.heads[key.token][0]),state.tasks[('head',key.token)].column.canonical_digest)for key in sorted(related,key=lambda key:key.token))
    root=canonical_digest(tuple((key.token,r.heads[key.token][:2],state.tasks[('head',key.token)].column.canonical_digest)for key in sorted(rows,key=lambda key:key.token)))
    facts=CurrentRelationshipContributionFactsV1(r.namespace,r.request.subject_entity_ref,r.request.dimension,frame.query_coverage[0].epoch,
        versions,root,metadata,valid,any(rows[key]['semantics']in {'recollection','simulation'}for key in valid),
        any(rows[key].get('identity_status','legacy_unresolved')=='legacy_unresolved'for key in valid),
        GraphVersion(projection,r.heads[projection.token][0]if projection.token in r.heads else 0),status,tuple(r.selected_plan.source_roots))
    _CONTRIBUTION_FACTS[r]=(facts,frame,_identity(r),state.permission,canonical_digest(facts))
    return facts


def require_current_relationship_contribution_facts_v3(db,frame,facts):
    r=_active(db);state=require_relationship_source_v3(r);state.permission.require_for_v3(r)
    if _CONTRIBUTION_FACTS.get(r)!=(facts,frame,_identity(r),state.permission,canonical_digest(facts))or facts is not _CONTRIBUTION_FACTS[r][0]:
        raise AuthorityUnavailable('contribution facts were not issued by this actual same-frame Source Work')
    return facts
