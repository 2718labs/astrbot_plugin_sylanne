"""Owner selection of real prospective inputs before a managed Window is adopted.

The browser selects existing LongPlan, JointPlan/node and input/role references.
All Root, build, phase, Action and budget commitments are read from real signed
Originals. The second ordinary worker call freezes the resulting exact command.
"""
from dataclasses import dataclass
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,Owner,GraphVersion,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .joint_window_command_v1 import FreezeJointWindowNodeCommandRequestV1

@dataclass(frozen=True,slots=True)
class JointCommandSelectionV1:
    long_plan_ref:str
    joint_plan_ref:str
    node_id:str
    executor_kind:str
    input_original_ref:str
    role_ref:str|None
    def __post_init__(self):
        if self.executor_kind not in {'draft_file','contact'}or not self.node_id or not self.input_original_ref:raise ValueError('Choose one existing prospective input and accepted Joint node')
        for ref,kind in((self.long_plan_ref,'d08.long_term_plan.v1'),(self.joint_plan_ref,'d08.joint_plan.v1')):
            if AtomKey.from_token(ref).type_name!=kind:raise ValueError('Actual LongPlan and JointPlan references required')
        if self.executor_kind=='draft_file'and(self.role_ref is None or AtomKey.from_token(self.role_ref).type_name!='d03.role_binding'):
            raise ValueError('Artifact selection requires its real current role')
        if self.executor_kind=='contact'and self.role_ref is not None:raise ValueError('Contact role/route comes from its actual signed prospective birth')

@dataclass(frozen=True,slots=True)
class JointCommandSelectionResultV1:
    selection:JointCommandSelectionV1
    request:FreezeJointWindowNodeCommandRequestV1
    activity_id:str
    source_purpose_groups:tuple


def prepare_joint_command_selection_v1(graph,authority,lease,selection):
    from .beta1_owner_state_read_v3 import Beta1OwnerStateRequestV1,prepare_owner_state_read_v3
    from .named_joint_node_descriptor_v3 import _PROFILES
    if type(selection)is not JointCommandSelectionV1:raise TypeError('Exact Owner prospective selection required')
    work=prepare_owner_state_read_v3(graph,authority,lease,request=Beta1OwnerStateRequestV1('long_window',(selection.long_plan_ref,)))
    reader=work.state
    if 'workbench.create'not in reader.owner_binding.capabilities:raise AuthorityUnavailable('Prospective command selection needs current signed Owner read/create')
    _PROFILES[reader]={'identity':(graph,work,reader.operation,reader.fence,reader.request,authority,lease),
        'builder':selection,'window_ref':selection.long_plan_ref,'plan_ref':selection.joint_plan_ref,
        'command_ref':None,'node_id':selection.node_id,'node':None,'metadata':{},'groups':(),
        'extra_heads':set(),'note_ops':{},'originals':{},'producer_ids':set()}
    return work


def _original(p,role,table,ref,kind,paths,*,signature='d11.life-original.v1'):
    key=(table,ref)
    prior=p['originals'].get(role)
    value=(table,ref,kind,tuple(paths),signature)
    if prior is not None and prior!=value:raise AuthorityUnavailable('Selected command changed its actual original lineage')
    p['originals'][role]=value
    return ('named_build_original',role)


def joint_selection_metadata_spec_v1(reader,p,identity):
    kind,ref=identity
    if kind=='named_build_head'and ref in {p['window_ref'],p['plan_ref'],*p['extra_heads']}:
        paths=tuple((name,)for name in('source_refs','state','node_drafts','nodes','entity_id','target_entity_ref'))
        paths+=(('continuation','source_ref'),('continuation','call_plan','phase_group','selector','decision_ref'),('continuation','call_plan','phase_group','selector','plan_ref'))
        return('graph_atoms','value',('token','bot','persona'),(ref,*reader.namespace.as_tuple),('revision','valid','value_cell_id'),paths,None)
    if kind!='named_build_original'or ref not in p['originals']:raise AuthorityUnavailable('Prospective metadata is outside the exact selected originals')
    table,original,original_kind,paths,signature=p['originals'][ref]
    if table=='graph_contact_prospective_originals_v1':
        return(table,'payload_json',('bot','persona','original_ref'),(*reader.namespace.as_tuple,original),
            ('contact_id','birth_operation_id','payload_digest','signature'),paths,None)
    if table=='graph_d11_life_originals_v1':
        return(table,'payload_json',('bot','persona','kind','original_ref'),(*reader.namespace.as_tuple,original_kind,original),
            ('producing_operation_id','payload_digest','signature'),paths,signature)
    if table=='graph_d10_production_inputs_v1':
        return(table,'payload_json',('bot','persona','original_ref'),(*reader.namespace.as_tuple,original),
            ('kind','producing_operation_id','payload_digest','signature'),paths,signature)
    raise AuthorityUnavailable('Prospective original table is not registered')


def finish_joint_selection_metadata_v1(task,value,p):
    if value is None:raise AuthorityUnavailable('Selected prospective Original or current Head was deleted')
    kind,role=task.identity
    if kind=='named_build_head':
        if task.reader.heads.get(role)!=task.metadata or task.metadata[0]<1 or task.metadata[1]!=1:raise AuthorityUnavailable('Prospective selected Head changed during complete EOF')
    else:
        table,ref,expected,_,_=p['originals'][role]
        if table=='graph_contact_prospective_originals_v1':
            ns=task.reader.namespace
            task.reader.graph._GraphCoordinator__d11_issuer._signer.verify('d10.contact-prospective-original.v1',
                canonical_serialize((ns,task.metadata[0],task.metadata[1],task.metadata[2])),task.metadata[3])
            if(value['namespace']!={'bot_id':ns.bot_id,'persona_id':ns.persona_id}or(value['contact_id'],value['birth_operation_id'])!=task.metadata[:2]):
                raise AuthorityUnavailable('Prospective Contact original HMAC identity differs')
            p['producer_ids'].add(task.metadata[1])
        else:
            if table=='graph_d10_production_inputs_v1'and task.metadata[0]!=expected:raise AuthorityUnavailable('Selected prospective input kind differs')
            p['producer_ids'].add(task.metadata[0 if table=='graph_d11_life_originals_v1'else 1])
    p['metadata'][(kind,role)]=(value,task.column.canonical_digest,task.metadata)
    return True,value


def joint_selection_plan_v1(reader,p):
    from .beta1_owner_state_read_v3 import _metadata,require_owner_state_reader_v3
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    state=require_owner_state_reader_v3(reader);choice=p['builder'];ns=reader.namespace
    roots=set();context=set();purpose='consolidation'if choice.executor_kind=='draft_file'else 'expression'
    long_plan=_metadata(reader,('named_build_head',choice.long_plan_ref));joint=_metadata(reader,('named_build_head',choice.joint_plan_ref))
    if long_plan['state']in {'paused','stopped','closed'}:raise AuthorityUnavailable('Current LongPlan denies new prospective command selection')
    nodes=tuple(node for node in joint['nodes']if node['node_id']==choice.node_id)
    if len(nodes)!=1:raise AuthorityUnavailable('Select one actual accepted JointPlan node')
    p['node']=nodes[0];context.update(long_plan['source_refs']);context.update(joint['source_refs'])
    if choice.executor_kind=='draft_file':
        scope_paths=tuple((name,)for name in('schema','namespace','c02_operation_id','source_ref','objective_ref','objective_digest'))+(('root','registration_ref'),)
        scope=_metadata(reader,_original(p,'input','graph_d11_life_originals_v1',choice.input_original_ref,'artifact_task_scope',scope_paths))
        if not scope['objective_ref']:raise AuthorityUnavailable('Selected Artifact scope has no actual admitted objective')
        objective_paths=tuple((name,)for name in('namespace','source_ref','goal_ref','project_ref','recipe_ref','plan_ref','installation_id','manifest_digest'))
        objective=_metadata(reader,_original(p,'objective','graph_d11_life_originals_v1',scope['objective_ref'],'artifact_task_objective',objective_paths))
        roots.update((scope['source_ref'],objective['source_ref']))
        p['extra_heads'].update((objective['goal_ref'],objective['project_ref'],objective['recipe_ref'],objective['plan_ref'],choice.role_ref))
        role=_metadata(reader,('named_build_head',choice.role_ref));context.update(role['source_refs'])
        entity=AtomKey(Owner('persona',*ns.as_tuple),'d03.entity_anchor',role['target_entity_ref']).token
        p['entity_ref']=entity;p['extra_heads'].add(entity)
        from .foreground_cycle_v1 import foreground_cycle_ids_v1
        from .d11_types import runtime_job_key
        activity,job=foreground_cycle_ids_v1(ns,scope['c02_operation_id']);p['activity_id']=activity
        cycle=runtime_job_key(*ns.as_tuple,activity,job).token;p['cycle_ref']=cycle;p['extra_heads'].add(cycle)
        job_metadata=_metadata(reader,('named_build_head',cycle))
        group=job_metadata.get('continuation',{}).get('call_plan',{}).get('phase_group')
        if group is not None:
            selector=group['selector'];p['extra_heads'].update((selector['decision_ref'],selector['plan_ref']))
    else:
        birth_paths=tuple((name,)for name in('schema','namespace','contact_id','birth_operation_id','joint_preparation','deadline_utc'))
        birth=_metadata(reader,_original(p,'input','graph_contact_prospective_originals_v1',choice.input_original_ref,'contact_prospective',birth_paths,signature=None))
        from .joint_contact_preparation_v1 import JointContactPreparationOriginalV1
        from dataclasses import fields
        prep_paths=tuple((f.name,)for f in fields(JointContactPreparationOriginalV1))
        preparation=_metadata(reader,_original(p,'preparation','graph_d10_production_inputs_v1',birth['joint_preparation']['ref'],'joint_contact_preparation_v1',prep_paths,signature='d11.d10-production-input.v1'))
        declared=preparation['request']
        if(declared['joint_plan_ref'],declared['joint_plan_revision'],declared['node_id'])!=(choice.joint_plan_ref,reader.heads[choice.joint_plan_ref][0],choice.node_id):
            raise AuthorityUnavailable('Actual Contact preparation selected another JointPlan node/revision')
        roots.update(preparation['source_refs']);p['contact_groups']=tuple((ref,tuple(groups))for ref,groups in preparation['source_purpose_groups'])
    for ref in tuple(p['extra_heads']):
        key=AtomKey.from_token(ref)
        if NamespaceId.from_key(key)!=ns:raise AuthorityUnavailable('Prospective selected controls crossed current namespace')
        value=_metadata(reader,('named_build_head',ref))
        target=context if key.type_name in {'d03.entity_anchor','d03.role_binding'}else roots
        target.update(value.get('source_refs',()))
    for ref in(choice.long_plan_ref,choice.joint_plan_ref,*p['extra_heads']):
        head=reader.heads[ref]
        with runtime_storage_quantum_v3(reader.db)as meter:
            row=_beta1_metadata_row_v3(reader,meter,'graph_history',('event_bot','event_persona','event_id','valid'),'token=? AND revision=?',(ref,head[0]))
        if row is None or tuple(row[:2])!=ns.as_tuple or row[3]!=1:raise AuthorityUnavailable('Prospective selected Head has no positive producing history')
        state.histories[ref]=row[2];state.producers.add(row[2])
    state.producers.update(p['producer_ids'])
    groups={('context','owner'):set(context)|set(roots)}
    # Owner selection is a local read. Executor groups retain each actual original audience.
    if choice.executor_kind=='contact':
        audiences=tuple(preparation['audience'])
        for ref,purposes in p['contact_groups']:
            for use in purposes:
                for audience in audiences:groups.setdefault((use,audience),set()).add(ref)
        for audience in audiences:groups.setdefault(('context',audience),set()).update(context)
    else:
        # Current Joint Plan acceptance gives the actual party scope; the actual
        # admitted objective Source remains the original private conversation.
        from .first_ingress_v2 import ingress_ids
        source_id=AtomKey.from_token(scope['source_ref']).owner.subject
        op=ingress_ids(source_id)[2]
        with runtime_storage_quantum_v3(reader.db)as meter:
            original=_beta1_metadata_row_v3(reader,meter,'graph_first_ingress_identity_v1',('conversation_ref',),
                'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,op))
        if original is None:raise AuthorityUnavailable('Artifact scope has no actual original ingress audience')
        audiences=(original[0],);p['audiences']=audiences
        for audience in audiences:
            groups.setdefault(('context',audience),set()).update(context)
            groups.setdefault((purpose,audience),set()).update(roots)
    p['groups']=tuple((use,(audience,),tuple(sorted(values)))for(use,audience),values in sorted(groups.items())if values)
    state.roots={ref for _,_,values in p['groups']for ref in values};state.metadata_complete=True
    return ProductionReadPlanV1((),tuple(AtomKey.from_token(ref)for ref in(choice.long_plan_ref,choice.joint_plan_ref,*sorted(p['extra_heads'])))+(owner_grant_key(*ns.as_tuple),),tuple(sorted(state.roots)),())


def joint_selection_point_v1(reader,p,request):
    table,columns,keys,key=request
    for original_table,ref,kind,_,_ in p['originals'].values():
        if table!=original_table:continue
        if table=='graph_d11_life_originals_v1'and tuple(columns)==('producing_operation_id','payload_json','payload_digest','signature')and tuple(keys)==('bot','persona','kind','original_ref')and tuple(key)==(*reader.namespace.as_tuple,kind,ref):return True
        if table=='graph_d10_production_inputs_v1'and tuple(columns)==('kind','producing_operation_id','payload_json','payload_digest','signature')and tuple(keys)==('bot','persona','original_ref')and tuple(key)==(*reader.namespace.as_tuple,ref):return True
        if table=='graph_contact_prospective_originals_v1'and tuple(columns)==('contact_id','birth_operation_id','payload_json','payload_digest','signature')and tuple(keys)==('bot','persona','original_ref')and tuple(key)==(*reader.namespace.as_tuple,ref):return True
    return False


def joint_selection_body_v1(reader,p,table,key):
    for selected_table,ref,kind,_,_ in p['originals'].values():
        expected=(*reader.namespace.as_tuple,kind,ref)if table=='graph_d11_life_originals_v1'else(*reader.namespace.as_tuple,ref)
        if selected_table==table and tuple(key)==expected:return True
    return False


def _selected_original(reader,p,role):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_background_read_v3 import background_json_loads_v3,background_json_digest_v3
    table,ref,kind,_,_=p['originals'][role];ns=reader.namespace
    if table=='graph_d11_life_originals_v1':columns=('producing_operation_id','payload_json','payload_digest','signature');keys=('bot','persona','kind','original_ref');key=(*ns.as_tuple,kind,ref);offset=0
    elif table=='graph_d10_production_inputs_v1':columns=('kind','producing_operation_id','payload_json','payload_digest','signature');keys=('bot','persona','original_ref');key=(*ns.as_tuple,ref);offset=1
    else:columns=('contact_id','birth_operation_id','payload_json','payload_digest','signature');keys=('bot','persona','original_ref');key=(*ns.as_tuple,ref);offset=1
    row=_producer_original_point_v3(reader.db,table=table,columns=columns,key_columns=keys,key=key,legacy_reader=lambda:None)
    if row is None:raise AuthorityUnavailable('Selected original disappeared after Source ALL')
    raw=background_json_loads_v3(row[offset+1]);digest=background_json_digest_v3(row[offset+1],raw)
    if digest!=row[offset+2]or digest!=p['metadata'][('named_build_original',role)][1]:raise AuthorityUnavailable('Selected original protected Body differs from its verified whole EOF')
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    actual=read_adopted_domain_operation_v1(reader.db,ns,row[offset])
    if actual is None or actual['receipt'].status!='committed':raise AuthorityUnavailable('Selected original has no actual positive W01 producer')
    return raw,digest


def joint_selection_projection_v1(reader,p):
    from .current_method_learning_read_v3 import method_graph_head_v3
    from .beta1_owner_state_read_v3 import _verify_current_original
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .joint_node_execution_v1 import RegisterJointNodeExecutionBindingRequestV1,ArtifactJointExecutorV1,ContactJointExecutorV1,JointContactProspectiveBindingV1
    from ..domains.d08.execution import _decode_goal,_decode_intent,ActionSchema,ActionSchemaRecord,_check_spec
    from ..domains.d01.production_operations_v1 import plain_v1
    choice=p['builder'];ns=reader.namespace
    for ref in(choice.long_plan_ref,choice.joint_plan_ref,*p['extra_heads']):
        atom=method_graph_head_v3(reader.db,ns,AtomKey.from_token(ref))
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        from .beta1_owner_state_read_v3 import require_owner_state_reader_v3
        actual=read_adopted_domain_operation_v1(reader.db,ns,require_owner_state_reader_v3(reader).histories[ref])
        if actual is None or actual['receipt'].status!='committed'or GraphVersion(atom.key,atom.revision)not in actual['receipt'].write_versions:
            raise AuthorityUnavailable('Selected prospective control has no actual current positive COMMIT')
        if canonical_digest(atom.value)!=p['metadata'][('named_build_head',ref)][1]:raise AuthorityUnavailable('Selected prospective control Body changed after metadata EOF')
        writes=tuple(w for w in actual['payload']['writes']if w['key']==ref)
        if len(writes)!=1 or canonical_digest(writes[0]['value'])!=canonical_digest(atom.value):raise AuthorityUnavailable('Selected prospective control differs from its actual committed write')
    input_raw,input_digest=_selected_original(reader,p,'input')
    node=p['node'];plan=method_graph_head_v3(reader.db,ns,AtomKey.from_token(choice.joint_plan_ref))
    if choice.executor_kind=='draft_file':
        from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV1,ArtifactTaskObjectiveV1,_decode as task_decode
        from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1,artifact_joint_schema_contract_digest_v1
        from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
        from .foreground_call_plan_v1 import ForegroundCallPlanV2
        from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
        scope=task_decode(input_raw,IngressArtifactTaskScopeOriginalV1)
        objective_raw,objective_digest=_selected_original(reader,p,'objective');objective=task_decode(objective_raw,ArtifactTaskObjectiveV1)
        job=method_graph_head_v3(reader.db,ns,AtomKey.from_token(p['cycle_ref']))
        continuation=foreground_cycle_from_wire_v1(job.value['continuation'])
        phase=continuation.call_plan.phase_group.selector if type(continuation.call_plan)is ForegroundCallPlanV2 and continuation.call_plan.phase_group is not None else None
        policy=reader.graph._GraphCoordinator__d04_installed_joint_assembly.installation_policy
        parent=reader.graph._GraphCoordinator__d11_issuer.current_budget_grant(reader.db,continuation.call_plan.parent_budget_lease_ref)
        build=read_installed_d11_life_build_v1(reader.graph._GraphCoordinator__d04_installed_joint_assembly.package_root,policy.manifest_digest,recipe_id='artifact_draft_v1')
        entity=method_graph_head_v3(reader.db,ns,AtomKey.from_token(p['entity_ref']));goal=_decode_goal(method_graph_head_v3(reader.db,ns,AtomKey.from_token(objective.goal_ref)).value)
        sources={scope.source_ref,objective.source_ref}
        for ref in(objective.goal_ref,objective.project_ref,objective.recipe_ref):sources.update(method_graph_head_v3(reader.db,ns,AtomKey.from_token(ref)).value.get('source_refs',()))
        binding=JointArtifactProspectiveBindingV1(namespace=ns,node_id=choice.node_id,plan_ref=choice.joint_plan_ref,plan_revision=plan.revision,
            owner_ref='persona:'+ns.persona_id,action_kind='artifact_draft_v1',objective_ref=scope.objective_ref,objective_digest=objective_digest,
            task_scope_ref=choice.input_original_ref,task_scope_digest=input_digest,project_ref=objective.project_ref,recipe_ref=objective.recipe_ref,
            goal_ref=objective.goal_ref,goal_id=goal.goal_id,target_ref=entity.value['entity_id'],target_entity_ref=entity.key.token,role_ref=choice.role_ref,
            source_refs=tuple(sorted(sources)),success_predicate=goal.satisfaction_predicate,
            executor=ArtifactJointExecutorV1(scope.c02_operation_id,scope.source_ref,scope.root.registration_ref,phase),
            parent_budget_lease_ref=parent.lease_id,parent_grant_id=parent.grant_id,parent_grant_version=parent.version,parent_grant_digest=canonical_digest(parent),
            original_deadline_utc=goal.satisfaction_predicate.valid_until,purpose='consolidation',audience=p['audiences'],installation_id=policy.installation_id,
            manifest_digest=policy.manifest_digest,algorithm_build_digest=build['algorithm_build_digest'],postcondition_build_digest=build['postcondition_build_digest'],schema_contract_digest=artifact_joint_schema_contract_digest_v1())
        activity=p['activity_id'];groups=(('consolidation',binding.audience,binding.source_refs),)
    else:
        preparation_raw,_=_selected_original(reader,p,'preparation')
        from .joint_contact_preparation_v1 import JointContactPreparationOriginalV1
        prep=decode_typed_production_value_v1(preparation_raw,JointContactPreparationOriginalV1)
        action=_decode_intent(input_raw['candidate']['action']);schema_raw=input_raw['candidate']['schema']
        schema=ActionSchema(schema_raw['schema_id'],schema_raw['action_kind'],schema_raw['proactive'],tuple(_check_spec(v)for v in schema_raw['required_checks']))
        record=ActionSchemaRecord.bind(action,schema);owner=Owner('activity',*ns.as_tuple,action.identity.activity_id)
        terms=input_raw['terms'];activity=action.identity.activity_id
        binding=JointContactProspectiveBindingV1(namespace=ns,node_id=choice.node_id,plan_ref=choice.joint_plan_ref,plan_revision=plan.revision,
            owner_ref='persona:'+ns.persona_id,action_kind=action.action_kind,action_ref=AtomKey(owner,'d08.action_intent.v1',action.action_id).token,
            action_revision=1,action_digest=canonical_digest(input_raw['candidate']['action']),action_schema_ref=AtomKey(owner,'d08.action_schema.v1',record.schema_ref).token,
            action_schema_revision=1,action_schema_digest=canonical_digest(plain_v1(record)),project_ref=None,recipe_ref=None,goal_ref=None,goal_id=action.goal_ref,
            target_ref=action.target_ref,target_entity_ref=action.target_ref,role_ref=None,source_refs=prep.source_refs,progress_ref=None,
            success_predicate=action.success_predicate,executor=ContactJointExecutorV1(prep.request.qualified_contact_dedupe_key,prep.request.prepare_contact_operation_id),
            parent_budget_lease_ref=terms['budget_lease_ref'],parent_grant_id=terms['grant_id'],parent_grant_version=terms['grant_version'],parent_grant_digest=terms['grant_digest'],
            original_deadline_utc=input_raw['deadline_utc'],purpose='expression',audience=prep.audience,contact_id=input_raw['contact_id'],
            prospective_original_ref=choice.input_original_ref,prospective_original_digest=input_digest,refresh_rule=input_raw['refresh_rule'])
        groups=tuple((use,binding.audience,tuple(ref for ref,purposes in prep.source_purpose_groups if use in purposes))for use in('context','expression')if any(use in values for _,values in prep.source_purpose_groups))
    if(binding.node_id,binding.owner_ref,binding.action_kind,plain_v1(binding.success_predicate))!=(node['node_id'],node['owner_ref'],node['action_kind'],node['success_predicate']):
        raise AuthorityUnavailable('Actual prospective executor changed accepted JointPlan responsibility')
    return JointCommandSelectionResultV1(choice,FreezeJointWindowNodeCommandRequestV1(RegisterJointNodeExecutionBindingRequestV1(binding)),activity,groups)
