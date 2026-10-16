"""Private inert Window-node command descriptor on the existing Owner Source READ.

Only an exact server-issued profile selects the command frozen before Window
adoption. The descriptor is requalified by the later independent named Work.
"""
from weakref import WeakKeyDictionary
from dataclasses import dataclass
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .joint_window_command_v1 import joint_window_command_ref_v1,KIND,OPERATION,JointWindowNodeCommandOriginalV1
from .joint_window_management_v1 import ManagedWindowArgumentV1

_PROFILES=WeakKeyDictionary()
@dataclass(frozen=True,slots=True)
class NamedJointNodeDescriptorV1:
    argument:ManagedWindowArgumentV1
    command:object
    frozen_original_ref:str
    frozen_original_digest:str

def descriptor_profile_v3(reader):
    profile=_PROFILES.get(reader)
    if profile is None:return None
    from .beta1_owner_state_read_v3 import require_owner_state_reader_v3
    require_owner_state_reader_v3(reader)
    if profile['identity']!=(reader.graph,reader.work,reader.operation,reader.fence,reader.request,reader.authority,reader.lease):
        raise AuthorityUnavailable('Named descriptor changed actual Owner/Source Work')
    return profile

def prepare_named_joint_descriptor_v3(graph,authority,lease,*,window_ref,node_id):
    from .beta1_owner_state_read_v3 import Beta1OwnerStateRequestV1,prepare_owner_state_read_v3
    if type(node_id)is not str or not node_id or len(node_id)>192:raise ValueError('One adopted node identity is required')
    request=Beta1OwnerStateRequestV1('long_window',(window_ref,))
    work=prepare_owner_state_read_v3(graph,authority,lease,request=request);reader=work.state
    if 'workbench.create'not in reader.owner_binding.capabilities:raise AuthorityUnavailable('Named descriptor requires actual signed Owner create and read')
    _PROFILES[reader]={'identity':(graph,work,reader.operation,reader.fence,request,authority,lease),
        'window_ref':window_ref,'node_id':node_id,'plan_ref':None,'command_ref':None,'metadata':{},'groups':(), 'node':None,'extra_heads':set(),'note_ops':{}}
    return work

def descriptor_metadata_spec_v3(reader,identity):
    p=descriptor_profile_v3(reader)
    if p is None:return None
    kind,ref=identity
    if 'builder'in p:
        from .named_joint_command_selection_v1 import joint_selection_metadata_spec_v1
        return joint_selection_metadata_spec_v1(reader,p,identity)
    if kind.startswith('named_note_'):
        return _note_descriptor_metadata_spec_v3(reader,p,kind,ref)
    if kind=='named_window'and ref==p['window_ref']or kind=='named_plan'and ref==p['plan_ref']:
        paths=(('schema',),('source_refs',),('state',),('purpose',),('audience',),('long_term_plan_ref',),('node_drafts',),('current_window_ref',))
        return('graph_atoms','value',('token','bot','persona'),(ref,*reader.namespace.as_tuple),('revision','valid','value_cell_id'),paths,None)
    if kind=='named_command'and ref==p['command_ref']:
        paths=tuple((name,)for name in('schema','namespace','executor_kind','typed_input_original_ref','typed_input_original_digest',
            'typed_request_digest','parent_grant_ref','parent_grant_digest','original_deadline_utc','source_refs','source_purpose_groups','producing_operation_id'))
        return('graph_d10_production_inputs_v1','payload_json',('bot','persona','original_ref'),(*reader.namespace.as_tuple,ref),
            ('kind','producing_operation_id','payload_digest','signature'),paths,'d11.d10-production-input.v1')
    return None

def finish_descriptor_metadata_v3(task,value):
    p=descriptor_profile_v3(task.reader)
    if p is None or not task.identity[0].startswith('named_'):return False,None
    if value is None:raise AuthorityUnavailable('Actual adopted Window/Plan/frozen command is absent or deleted')
    kind,ref=task.identity
    if 'builder'in p:
        from .named_joint_command_selection_v1 import finish_joint_selection_metadata_v1
        return finish_joint_selection_metadata_v1(task,value,p)
    if kind.startswith('named_note_'):
        return _finish_note_descriptor_metadata_v3(task,value,p)
    if kind in {'named_window','named_plan'}:
        if task.reader.heads.get(ref)!=task.metadata or task.metadata[0]<1 or task.metadata[1]!=1:
            raise AuthorityUnavailable('Named descriptor current metadata lost its census Head')
    elif(task.metadata[0]!=KIND or value['producing_operation_id']!=task.metadata[1]
            or value['schema']!='d10.joint-window-node-command.v1' or value['namespace']!={'bot_id':task.reader.namespace.bot_id,'persona_id':task.reader.namespace.persona_id}):
        raise AuthorityUnavailable('Named descriptor has no exact signed frozen command EOF')
    p['metadata'][ref]=(value,task.column.canonical_digest,task.metadata)
    return True,value

def descriptor_plan_v3(reader):
    p=descriptor_profile_v3(reader)
    if p is None:return None
    from .beta1_owner_state_read_v3 import _metadata,require_owner_state_reader_v3
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    state=require_owner_state_reader_v3(reader)
    if 'builder'in p:
        from .named_joint_command_selection_v1 import joint_selection_plan_v1
        return joint_selection_plan_v1(reader,p)
    window=_metadata(reader,('named_window',p['window_ref']))
    matches=tuple(n for n in window['node_drafts']if n['node_id']==p['node_id'])
    if len(matches)!=1 or window['state']!='preparing':raise AuthorityUnavailable('Named descriptor needs one actual preparing Window node')
    node=matches[0];p['node']=node;p['plan_ref']=window['long_term_plan_ref']
    plan=_metadata(reader,('named_plan',p['plan_ref']))
    if plan['state']in {'paused','stopped','closed'}:raise AuthorityUnavailable('Current LongPlan denies new node preparation')
    if node['executor_kind']=='source_note':return _note_descriptor_plan_v3(reader,p,window,plan,node)
    p['command_ref']=joint_window_command_ref_v1(reader.namespace,node['typed_request_digest'])
    frozen=_metadata(reader,('named_command',p['command_ref']))
    if(frozen['executor_kind'],frozen['typed_input_original_ref'],frozen['typed_input_original_digest'],frozen['typed_request_digest'],
        frozen['parent_grant_ref'],frozen['parent_grant_digest'],frozen['original_deadline_utc'])!=(node['executor_kind'],node['typed_request_ref'],
        node['typed_input_original_digest'],node['typed_request_digest'],node['parent_grant_ref'],node['parent_grant_digest'],node['original_deadline_utc']):
        raise AuthorityUnavailable('Frozen command differs from its actual adopted immutable node')
    groups={}
    def add(roots,purpose,audiences):
        for audience in audiences:groups.setdefault((purpose,audience),set()).update(roots)
    add(window['source_refs'],'context',('owner',));add(plan['source_refs'],'context',('owner',))
    add(plan['source_refs'],plan['purpose'],plan['audience']);add(node['source_refs'],node['purpose'],node['audience'])
    for purpose,audiences,roots in frozen['source_purpose_groups']:add(roots,purpose,audiences)
    p['groups']=tuple((purpose,(audience,),tuple(sorted(roots)))for(purpose,audience),roots in sorted(groups.items())if roots)
    roots={ref for _,_,values in p['groups']for ref in values}
    if not roots:raise AuthorityUnavailable('Named descriptor requires complete actual Source roots')
    for ref in roots:
        key=AtomKey.from_token(ref)
        if key.type_name!='memory.source'or NamespaceId.from_key(key)!=reader.namespace:raise AuthorityUnavailable('Descriptor Source crossed namespace/type')
    for ref in(p['window_ref'],p['plan_ref']):
        head=reader.heads[ref]
        with runtime_storage_quantum_v3(reader.db)as meter:
            row=_beta1_metadata_row_v3(reader,meter,'graph_history',('event_bot','event_persona','event_id','valid'),'token=? AND revision=?',(ref,head[0]))
        if row is None or tuple(row[:2])!=reader.namespace.as_tuple or row[3]!=1:raise AuthorityUnavailable('Descriptor Head has no actual positive current history')
        state.histories[ref]=row[2];state.producers.add(row[2])
    state.producers.add(frozen['producing_operation_id']);state.roots=roots;state.metadata_complete=True
    return ProductionReadPlanV1((),tuple(AtomKey.from_token(ref)for ref in(p['window_ref'],p['plan_ref']))+(owner_grant_key(*reader.namespace.as_tuple),),tuple(sorted(roots)),())

def descriptor_groups_v3(reader,roots):
    p=descriptor_profile_v3(reader)
    if p is None:return None
    if set(roots)!={ref for _,_,values in p['groups']for ref in values}:raise AuthorityUnavailable('Descriptor Source union changed')
    return p['groups']

def descriptor_point_v3(reader,request):
    p=descriptor_profile_v3(reader)
    if p is None:return False
    table,columns,keys,key=request
    if 'builder'in p:
        from .named_joint_command_selection_v1 import joint_selection_point_v1
        if joint_selection_point_v1(reader,p,request):
            descriptor_body_v3(reader,table,key)
            return True
    if table=='graph_atoms'and tuple(columns)==('revision','value','valid')and tuple(keys)==('token','bot','persona'):
        allowed=len(key)==3 and key[0]in {p['window_ref'],p['plan_ref'],*p['extra_heads']}and tuple(key[1:])==reader.namespace.as_tuple
    elif table=='graph_d10_production_inputs_v1':
        allowed=tuple(columns)==('kind','producing_operation_id','payload_json','payload_digest','signature','source_refs_json')and tuple(keys)==('bot','persona','original_ref')and tuple(key)==(*reader.namespace.as_tuple,p['command_ref'])
    else:return False
    if not allowed:raise AuthorityUnavailable('Named descriptor point is outside its exact selected command')
    from .beta1_owner_state_read_v3 import require_owner_state_reader_v3
    state=require_owner_state_reader_v3(reader)
    if not state.metadata_complete or state.source_permission is None:raise AuthorityUnavailable('Descriptor Body cannot precede Owner17 and Source ALL')
    state.source_permission.require_for_v3(reader)
    return True

def descriptor_projection_v3(reader):
    p=descriptor_profile_v3(reader)
    if p is None:return None
    if 'builder'in p:
        from .named_joint_command_selection_v1 import joint_selection_projection_v1
        return joint_selection_projection_v1(reader,p)
    if p['node']['executor_kind']=='source_note':return _note_descriptor_projection_v3(reader,p)
    from .beta1_owner_state_read_v3 import _verify_current_original
    from .current_method_learning_read_v3 import method_graph_head_v3
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_background_read_v3 import background_json_loads_v3,background_json_digest_v3
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..domains.d08.long_term_plan_v1 import long_term_value_from_wire_v1
    for ref in(p['window_ref'],p['plan_ref']):
        atom=method_graph_head_v3(reader.db,reader.namespace,AtomKey.from_token(ref));_verify_current_original(reader,atom)
        if canonical_digest(atom.value)!=p['metadata'][ref][1]:raise AuthorityUnavailable('Descriptor actual Body differs from metadata EOF')
    window=long_term_value_from_wire_v1('d08.joint_window.v1',method_graph_head_v3(reader.db,reader.namespace,AtomKey.from_token(p['window_ref'])).value)
    node=next(n for n in window.node_drafts if n.node_id==p['node_id'])
    row=_producer_original_point_v3(reader.db,table='graph_d10_production_inputs_v1',columns=('kind','producing_operation_id','payload_json','payload_digest','signature','source_refs_json'),
        key_columns=('bot','persona','original_ref'),key=(*reader.namespace.as_tuple,p['command_ref']),legacy_reader=lambda:None)
    if row is None or row[0]!=KIND:raise AuthorityUnavailable('Frozen command was deleted after qualification')
    raw=background_json_loads_v3(row[2]);digest=background_json_digest_v3(row[2],raw)
    if digest!=row[3]or digest!=p['metadata'][p['command_ref']][1]or tuple((row[0],row[1],row[3],row[4]))!=p['metadata'][p['command_ref']][2]:
        raise AuthorityUnavailable('Frozen command protected Body differs from its actual whole signed EOF')
    frozen=decode_typed_production_value_v1(raw,JointWindowNodeCommandOriginalV1)
    original=read_adopted_domain_operation_v1(reader.db,reader.namespace,row[1])
    from ..domains.d01.production_operations_v1 import plain_v1
    if(original is None or original['operation_kind']!=OPERATION or original['receipt'].status!='committed'
            or original['payload']['provenance']['joint_window_node_command']!=plain_v1(frozen)):
        raise AuthorityUnavailable('Frozen command lacks its exact actual positive W01 producer')
    arg=ManagedWindowArgumentV1(p['window_ref'],reader.heads[p['window_ref']][0],node.node_id,node.executor_kind,node.typed_request_ref,node.typed_input_original_digest,node.typed_request_digest)
    return NamedJointNodeDescriptorV1(arg,frozen.command,frozen.original_ref,frozen.digest)

def release_named_descriptor_v3(reader):_PROFILES.pop(reader,None)


def descriptor_body_v3(reader,table,key):
    p=descriptor_profile_v3(reader)
    if p is None:return False
    allowed=(table=='graph_atoms'and tuple(key[1:])==reader.namespace.as_tuple and key[0]in {p['window_ref'],p['plan_ref'],*p['extra_heads']}
        or table=='graph_d10_production_inputs_v1'and tuple(key)==(*reader.namespace.as_tuple,p['command_ref']))
    if not allowed and 'builder'in p:
        from .named_joint_command_selection_v1 import joint_selection_body_v1
        allowed=joint_selection_body_v1(reader,p,table,key)
    if not allowed:return False
    from .beta1_owner_state_read_v3 import require_owner_state_reader_v3
    state=require_owner_state_reader_v3(reader)
    if not state.metadata_complete or state.source_permission is None:raise AuthorityUnavailable('Named descriptor Body requires actual Owner17 and complete Source ALL')
    state.source_permission.require_for_v3(reader)
    return True


def _note_descriptor_metadata_spec_v3(reader,p,kind,ref):
    if kind=='named_note_head':
        if ref!=p['node']['typed_request_ref']:raise AuthorityUnavailable('SourceNote descriptor changed its actual Decision')
        return('graph_atoms','value',('token','bot','persona'),(ref,*reader.namespace.as_tuple),
            ('revision','valid','value_cell_id'),(('source_refs',),('chosen_action_ref',)),None)
    role={'named_note_selection':'selection','named_note_preparation':'preparation','named_note_need':'need'}.get(kind)
    if role is None or p['note_ops'].get(role)!=ref:raise AuthorityUnavailable('SourceNote original metadata escaped its actual positive lineage')
    common=(('schema',),('namespace',),('identity',),('read_versions',))
    if role=='selection':paths=common+(('provenance','prepared_candidates_operation_id'),)
    elif role=='preparation':paths=common+(('provenance','prepared_candidates','source_refs'),('provenance','prepared_candidates','need','original'))
    else:paths=common+tuple(('request',name)for name in('c02_operation_id','source_ref','job_ref','task_job_ref','authorization_original_ref'))+(('provenance','owner_source_note_need','authorization_original_digest'),)
    return('graph_domain_production_originals_v1','original_payload_json',('bot','persona','operation_id'),(*reader.namespace.as_tuple,ref),
        ('domain','operation_kind','original_digest'),paths,None)


def _finish_note_descriptor_metadata_v3(task,value,p):
    kind,ref=task.identity
    if kind=='named_note_head':
        if task.reader.heads.get(ref)!=task.metadata or task.metadata[0]<1 or task.metadata[1]!=1:raise AuthorityUnavailable('Actual SourceNote Decision metadata Head changed')
    else:
        allowed={'named_note_selection':{'select_personal_step_v2','select_current_conditioned_personal_step_v1'},
            'named_note_preparation':{'prepare_personal_candidates_v1'},
            'named_note_need':{'prepare_owner_source_note_need_v1','prepare_ingress_recall_need_v1','adopt_current_task_no_search_v1'}}[kind]
        if(task.metadata[1]not in allowed or value['identity']['phase']!=task.metadata[1]or value['identity']['operation_id']!=ref
                or value['namespace']!={'bot_id':task.reader.namespace.bot_id,'persona_id':task.reader.namespace.persona_id}):
            raise AuthorityUnavailable('SourceNote actual original metadata canonical identity differs')
    p['metadata'][ref]=(value,task.column.canonical_digest,task.metadata)
    return True,value


def _note_descriptor_plan_v3(reader,p,window,plan,node):
    from .beta1_owner_state_read_v3 import _metadata,require_owner_state_reader_v3
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    from .d08_personal_candidate_v1 import ConsumePersonalDecisionRequestV1
    state=require_owner_state_reader_v3(reader);decision_ref=node['typed_request_ref']
    p['extra_heads'].add(decision_ref)
    decision=_metadata(reader,('named_note_head',decision_ref))
    if p['metadata'][decision_ref][1]!=node['typed_input_original_digest']:raise AuthorityUnavailable('SourceNote adopted Decision digest changed')
    for ref in(p['window_ref'],p['plan_ref'],decision_ref):
        header=reader.heads.get(ref)
        if header is None or header[1]!=1:raise AuthorityUnavailable('SourceNote descriptor requires actual current Heads')
        with runtime_storage_quantum_v3(reader.db)as meter:
            history=_beta1_metadata_row_v3(reader,meter,'graph_history',('event_bot','event_persona','event_id','valid'),'token=? AND revision=?',(ref,header[0]))
        if history is None or tuple(history[:2])!=reader.namespace.as_tuple or history[3]!=1:raise AuthorityUnavailable('SourceNote selected Head lost its actual W01 history')
        state.histories[ref]=history[2];state.producers.add(history[2])
    p['note_ops']['selection']=state.histories[decision_ref]
    selected=_metadata(reader,('named_note_selection',p['note_ops']['selection']))
    preparation=selected['provenance']['prepared_candidates_operation_id'];p['note_ops']['preparation']=preparation
    prepared=_metadata(reader,('named_note_preparation',preparation));state.producers.add(preparation)
    original=prepared['provenance']['prepared_candidates']['need']['original']
    domain,kind=original['kind'].split('.current-',1)
    with runtime_storage_quantum_v3(reader.db)as meter:
        row=_beta1_metadata_row_v3(reader,meter,'graph_domain_production_originals_v1',('operation_id',),
            'bot=? AND persona=? AND domain=? AND operation_kind=? AND original_digest=?',(*reader.namespace.as_tuple,domain,kind,original['original_digest']))
    if row is None:raise AuthorityUnavailable('SourceNote actual immutable Need original was deleted')
    p['note_ops']['need']=row[0];state.producers.add(row[0])
    need=_metadata(reader,('named_note_need',row[0]))
    if original['original_digest']!=p['metadata'][row[0]][1]:raise AuthorityUnavailable('SourceNote Need metadata differs from its actual prepared original')
    command=ConsumePersonalDecisionRequestV1(decision_ref,preparation)
    if canonical_digest(command)!=node['typed_request_digest']:raise AuthorityUnavailable('SourceNote Window did not freeze this exact actual Consume command')
    p['note_command']=command;p['note_need']=need
    groups={}
    def add(roots,purpose,audiences):
        for audience in audiences:groups.setdefault((purpose,audience),set()).update(roots)
    add(window['source_refs'],'context',('owner',));add(plan['source_refs'],'context',('owner',));add(plan['source_refs'],plan['purpose'],plan['audience'])
    add(node['source_refs'],node['purpose'],node['audience'])
    roots=set(node['source_refs'])
    for value in(selected,prepared,need):
        for version in value['read_versions']:
            key=AtomKey.from_token(version['key'])
            if key.type_name=='memory.source':roots.add(key.token)
    for purpose in('context','consolidation'):add(roots,purpose,node['audience'])
    p['groups']=tuple((purpose,(audience,),tuple(sorted(roots)))for(purpose,audience),roots in sorted(groups.items())if roots)
    state.roots={ref for _,_,group in p['groups']for ref in group};state.metadata_complete=True
    keys=tuple(AtomKey.from_token(ref)for ref in(p['window_ref'],p['plan_ref'],decision_ref))+(owner_grant_key(*reader.namespace.as_tuple),)
    return ProductionReadPlanV1((),keys,tuple(sorted(state.roots)),())


def _note_descriptor_projection_v3(reader,p):
    from .beta1_owner_state_read_v3 import _verify_current_original
    from .current_method_learning_read_v3 import method_graph_head_v3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1,SourceNoteCandidateBindingV1
    from .named_joint_source_note_command_v1 import ManagedSourceNotePreparationRequestV1
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    from .domain_production_registry_v1 import installed_operation_v1
    from ..authority_service.current_owner_source_note_task_v1 import OwnerTaskActivityRequestV1,owner_task_typed_command_digest_v1
    from ..authority_service.current_foreground_activity_v1 import ForegroundActivityRequestV1,foreground_typed_command_digest_v1
    from .foreground_cycle_v1 import foreground_cycle_ids_v1
    from .d11_types import runtime_job_key
    from .ingress_observation import ingress_ids
    for ref in(p['window_ref'],p['plan_ref']):
        atom=method_graph_head_v3(reader.db,reader.namespace,AtomKey.from_token(ref));_verify_current_original(reader,atom)
        if canonical_digest(atom.value)!=p['metadata'][ref][1]:raise AuthorityUnavailable('SourceNote Window/LongPlan Body changed after metadata EOF')
    actual={}
    for role,operation in p['note_ops'].items():
        original=read_adopted_domain_operation_v1(reader.db,reader.namespace,operation)
        if original is None or original['receipt'].status!='committed'or original['original_digest']!=p['metadata'][operation][1]:
            raise AuthorityUnavailable('SourceNote command requires its actual positive immutable W01 producer')
        actual[role]=original
    decision=method_graph_head_v3(reader.db,reader.namespace,AtomKey.from_token(p['node']['typed_request_ref']))
    if(GraphVersion(decision.key,decision.revision)not in actual['selection']['receipt'].write_versions
            or canonical_digest(decision.value)!=p['node']['typed_input_original_digest']):raise AuthorityUnavailable('SourceNote Decision differs from its actual positive COMMIT')
    prepared=decode_typed_production_value_v1(actual['preparation']['payload']['provenance']['prepared_candidates'],PreparedPersonalCandidateSetV1)
    chosen=tuple(c for c in prepared.candidates if c.future_identity.action_ref==decision.value['chosen_action_ref'])
    if len(chosen)!=1 or type(chosen[0].binding)is not SourceNoteCandidateBindingV1:raise AuthorityUnavailable('SourceNote Decision has no unique actual selected SourceNote candidate')
    future=chosen[0].future_identity;node=p['node'];need=actual['need']['payload'];command=p['note_command'];ns=reader.namespace
    if(future.parent_budget_lease_ref,future.deadline_utc)!=(node['parent_grant_ref'],node['original_deadline_utc']):raise AuthorityUnavailable('SourceNote cannot replace the original selected future Root or TTL')
    if actual['need']['operation_kind']=='prepare_owner_source_note_need_v1':
        fixed=need['provenance']['owner_source_note_need'];job=AtomKey.from_token(fixed['task_job_head']['key'])
        auth_ref,auth_digest=fixed['authorization_original_ref'],fixed['authorization_original_digest']
    else:
        c02=need['request']['c02_operation_id'];activity,job_id=foreground_cycle_ids_v1(ns,c02)
        job=runtime_job_key(*ns.as_tuple,activity,job_id)
    head=reader.heads.get(job.token)
    with runtime_storage_quantum_v3(reader.db)as meter:
        current=_beta1_metadata_row_v3(reader,meter,'runtime_jobs',('bot_id','persona_id','cancel_epoch','lease_holder','fence','lease_expires_utc'),'job_id=?',(job.name,))
    if head is None or head[1]!=1 or current is None or tuple(current[:2])!=ns.as_tuple:raise AuthorityUnavailable('SourceNote original current task job is absent or retired')
    policy=reader.graph._GraphCoordinator__d04_installed_joint_assembly.installation_policy
    operation=installed_operation_v1('prepare_selected_source_note_action_v2')
    if actual['need']['operation_kind']=='prepare_owner_source_note_need_v1':
        selector=OwnerTaskActivityRequestV1(ns,policy.installation_id,auth_ref,auth_digest,future.action_operation_id,
            operation.operation_kind,owner_task_typed_command_digest_v1(operation,command),job.token,head[0],current[2])
    else:
        cue=need['request']['source_ref']
        selector=ForegroundActivityRequestV1(ns,policy.installation_id,ingress_ids(AtomKey.from_token(cue).owner.subject)[2],c02,
            cue,cue,job.token,head[0],current[2],future.activity_id,future.action_operation_id,operation.operation_kind,
            foreground_typed_command_digest_v1(operation,command),future.parent_budget_lease_ref,'consolidation',tuple(node['audience']),future.deadline_utc,
            worker_holder=current[3],worker_fence=current[4],worker_lease_expires_utc=current[5])
    arg=ManagedWindowArgumentV1(p['window_ref'],reader.heads[p['window_ref']][0],node['node_id'],'source_note',
        node['typed_request_ref'],node['typed_input_original_digest'],node['typed_request_digest'])
    return NamedJointNodeDescriptorV1(arg,ManagedSourceNotePreparationRequestV1(selector,command),
        'd08-current:'+actual['selection']['original_digest'][:48],actual['selection']['original_digest'])


def named_descriptor_retained_heap_v3(value):
    from .named_joint_command_selection_v1 import JointCommandSelectionResultV1
    if type(value)not in {NamedJointNodeDescriptorV1,JointCommandSelectionResultV1}:return None
    from dataclasses import is_dataclass,fields
    import sys
    seen=set()
    def size(v):
        if id(v)in seen:return 0
        seen.add(id(v));result=sys.getsizeof(v)
        if is_dataclass(v):return result+sum(size(getattr(v,f.name))for f in fields(v))
        if type(v)is dict:return result+sum(size(k)+size(x)for k,x in v.items())
        if type(v)in {tuple,list,set,frozenset}:return result+sum(size(x)for x in v)
        return result
    return size(value)
