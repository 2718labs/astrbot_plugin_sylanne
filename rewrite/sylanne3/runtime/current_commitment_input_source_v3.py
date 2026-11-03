"""Exact Owner aspiration/commitment inputs on the common bounded Source Work."""
from types import SimpleNamespace
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3

INPUT_OPERATIONS=frozenset({'input:create_aspiration','input:create_commitment','input:create_commitment_with_fulfillment_terms','input:register_commitment_communication'})
LIFECYCLE_OPERATIONS=frozenset({'settle_observed_action','acknowledge_bilateral'})
CANCELLATION_OPERATIONS=frozenset({'cancel_action'})
from .current_commitment_fulfillment_source_v3 import SOURCE_OPERATIONS as TERMS_SOURCE_OPERATIONS_V3
OPERATIONS=INPUT_OPERATIONS|LIFECYCLE_OPERATIONS|CANCELLATION_OPERATIONS|TERMS_SOURCE_OPERATIONS_V3
DOMAINS=frozenset({'d01','d03','d05','d06','d08','d11'})
TYPES=('d03.entity_anchor','d03.account_binding','d03.role_binding','d05.boundary_rule')
APPLICABILITY_OPERATIONS=frozenset({'input:create_commitment','input:create_commitment_with_fulfillment_terms','input:register_commitment_communication'})|TERMS_SOURCE_OPERATIONS_V3
_SELECTOR_FIELDS={
 'd03.entity_anchor':('entity_id','status','creation_evidence_refs'),
 'd03.account_binding':('platform_namespace','platform_identifier','entity_id','valid_from','valid_until','verification_ref'),
 'd03.role_binding':('subject_persona_ref','target_entity_ref','group_ref','scene_ref','status','effective_from','effective_until','source_refs'),
 'd05.boundary_rule':('subject_persona_ref','target_entity_ref','action_kind','audience_scope','scene_ref','status','valid_from','valid_until','source_refs')}

_STATES=WeakKeyDictionary()
_WRITES=WeakKeyDictionary()

def _identity(r):return(r.graph,r.work,r.operation,r.fence,r.namespace,r.selection_digest,r.graph_stamp,r.request,r.operation_id,r.authority,r.owner_binding)

def register_commitment_input_source_v3(r):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    from .domain_production_registry_v1 import installed_operation_v1
    require_current_beta1_source_work_v3(r)
    if r.operation_kind not in OPERATIONS or type(r.request)is not installed_operation_v1(r.operation_kind).request_type or r in _STATES:
        raise AuthorityUnavailable('Commitment Source profile requires its exact originating typed Owner command')
    _STATES[r]=SimpleNamespace(identity=_identity(r),tasks={},keys=set(),roots=set(),selector_dependency_refs=set(),content_source_refs=set(),applicable_keys=set(),policy_source_refs=set(),policy_audiences=(),selector_context=None,permission=None,metadata_complete=False)

def require_commitment_input_source_v3(r):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(r)
    state=_STATES.get(r)
    if state is None or state.identity[:-1]!=_identity(r)[:-1] or state.permission is not None and state.identity[-1]is not r.owner_binding:
        raise AuthorityUnavailable('Commitment Source changed its actual Work/Owner/selector')
    return state

def pin_commitment_input_owner_v3(r):
    state=require_commitment_input_source_v3(r);r.general_owner_entry.require_for_v3(r);state.identity=_identity(r)

class _MetadataColumn(DispatchOriginalJSONReadV3):
    def _emit(self,event):
        fields={'source_refs','creation_evidence_refs','reason_refs','identity','action_id','purpose','counterparty_ref'}
        if self.owner.operation_kind in APPLICABILITY_OPERATIONS:
            fields.update(name for names in _SELECTOR_FIELDS.values()for name in names)
        if self.owner.operation_kind in TERMS_SOURCE_OPERATIONS_V3:
            from .current_commitment_fulfillment_source_v3 import _METADATA_FIELDS
            fields.update(_METADATA_FIELDS)
        if self.owner.operation_kind=='cancel_action':
            fields.update({'revision','action_revision','action_digest','activity_id','attempt_id','effect_id','cancel_epoch','state','actor','operation_id'})
        if not event.path or event.path[0] in fields:super()._emit(event)

class _MetadataTask:
    def __init__(self,r,token):
        state=require_commitment_input_source_v3(r)
        if AtomKey.from_token(token)not in state.keys:raise AuthorityUnavailable('Commitment metadata key is outside its fixed selection')
        self.reader,self.token=r,token;self.header=self.column=None;self.complete=False;self.result=None
    def advance(self,meter):
        r=self.reader;r.require_current(meter=meter);require_commitment_input_source_v3(r)
        row=_runtime_bounded_fixed_row_v3(r.db,meter,'graph_atoms',('revision','valid','value_cell_id'),'token=? AND bot=? AND persona=?',(self.token,*r.namespace.as_tuple))
        if self.header is None:
            if row is None:raise AuthorityUnavailable('Commitment metadata head disappeared')
            self.header=row
            if r.operation_kind in APPLICABILITY_OPERATIONS and AtomKey.from_token(self.token).type_name in TYPES and row[1]!=1:
                # The invalid current header is its complete negative selector;
                # no retired Body is needed to classify an unrelated row.
                self.result={};self.complete=True;return True
            self.column=_MetadataColumn(r,table='graph_atoms',column='value',key_columns=('token','bot','persona'),key=(self.token,*r.namespace.as_tuple),cell_id=row[2])
            from ..authority_service.named_joint_binding_source_read_v3 import _MetadataStreamV3
            self.stream=_MetadataStreamV3(self.column,self.column.cell is None or self.column.cell.header[0]=='canonical-json.ascii.v1');self.column.parser=self.stream
            return False
        if row!=self.header:raise AuthorityUnavailable('Commitment metadata head changed before EOF')
        if not self.column.advance(meter):return False
        self.result=self.column.require_v3(r);self.complete=True;return True

def create_commitment_input_metadata_task_v3(r,token):
    state=require_commitment_input_source_v3(r)
    task=state.tasks.get(token)
    if task is None:
        if type(token)is tuple and token[0]=='policy_route':
            task=_PolicyRouteMetadataV3(r,token[1])
        elif type(token)is tuple and len(token)==3 and token[0]=='terms_head_original':
            from .current_commitment_fulfillment_source_v3 import CommitmentTermsHeadOriginalV3
            task=CommitmentTermsHeadOriginalV3(r,token[1],token[2])
        elif type(token)is tuple:
            from .current_commitment_lifecycle_source_v3 import CommitmentLifecycleMetadataV3,CommitmentLifecycleOriginalReadV3,LifecycleHeadOriginalV3
            if token==('lifecycle_locator',):task=CommitmentLifecycleMetadataV3(r)
            elif token==('lifecycle_originals',):task=CommitmentLifecycleOriginalReadV3(r)
            elif len(token)==3 and token[0]=='lifecycle_head_original':task=LifecycleHeadOriginalV3(r,token[1],token[2])
            else:raise AuthorityUnavailable('unregistered exact lifecycle original selector')
        else:task=_MetadataTask(r,token)
        state.tasks[token]=task
    return task

def commitment_input_read_plan_v3(db,*,namespace,activity_id,operation_kind,request):
    if operation_kind in TERMS_SOURCE_OPERATIONS_V3:
        from .current_commitment_fulfillment_source_v3 import terms_source_read_plan_v3
        return terms_source_read_plan_v3(db,namespace=namespace,activity_id=activity_id,operation_kind=operation_kind,request=request)
    if operation_kind in LIFECYCLE_OPERATIONS:
        from .current_commitment_lifecycle_source_v3 import lifecycle_read_plan_v3
        return lifecycle_read_plan_v3(db,namespace=namespace,activity_id=activity_id,operation_kind=operation_kind,request=request)
    from .current_method_learning_read_v3 import _method_active,_need_method_input
    from .d01_production_operations_v1 import production_read_plan_v1
    from .persona_growth_birth_v1 import augment_persona_birth_plan_v1
    from ..graph_types import Owner
    from ..domains.d08.commitment_communication_v1 import communication_scope_key_v1,communication_scope_id_v1
    r=_method_active(db)
    if r is None or r.namespace!=namespace or r.operation_kind!=operation_kind or r.request!=request:
        raise AuthorityUnavailable('Commitment plan requires its actual Owner Source Work')
    state=require_commitment_input_source_v3(r)
    if operation_kind=='input:create_aspiration':
        state.roots.update(request.aspiration.source_refs)
        if any(NamespaceId.from_key(AtomKey.from_token(ref))!=namespace or AtomKey.from_token(ref).type_name!='memory.source' for ref in state.roots):
            raise AuthorityUnavailable('Aspiration birth crossed its canonical current Source namespace')
        key=AtomKey(Owner('activity',*namespace.as_tuple,activity_id),'d08.aspiration.v1',request.aspiration.aspiration_id)
        state.metadata_complete=True
        return augment_persona_birth_plan_v1(db,namespace=namespace,operation_kind=operation_kind,
            plan=production_read_plan_v1((),tuple(sorted((owner_grant_key(*namespace.as_tuple),key),key=lambda value:value.token)),
                tuple(sorted(state.roots)),()))
    state.keys.update(AtomKey.from_token(token)for token in r.heads if AtomKey.from_token(token).type_name in TYPES)
    keys={owner_grant_key(*namespace.as_tuple)}
    if operation_kind in {'input:create_commitment','input:create_commitment_with_fulfillment_terms'}:
        keys.add(AtomKey(Owner('persona',*namespace.as_tuple),'d08.commitment.v1',request.commitment_id));state.roots.update(request.source_refs)
        if operation_kind=='input:create_commitment_with_fulfillment_terms':
            from ..domains.d08.commitment_fulfillment_v1 import terms_key_v1
            keys.add(terms_key_v1(namespace,request.commitment_id))
    else:
        selected=AtomKey.from_token(request.commitment.ref)
        from ..domains.d08.commitment_fulfillment_v1 import terms_key_v1
        terms_key=terms_key_v1(namespace,selected.name)
        with runtime_storage_quantum_v3(db)as meter:
            terms_head=_runtime_bounded_fixed_row_v3(db,meter,'graph_atoms',('revision','valid'),
                'token=? AND bot=? AND persona=?',(terms_key.token,*namespace.as_tuple))
        if terms_head is not None:
            raise AuthorityUnavailable('terms-bearing commitment requires its exact V2 structured communication producer')
        keys.add(terms_key)
        state.keys.add(selected);keys.update((selected,communication_scope_key_v1(namespace,communication_scope_id_v1(namespace,request))))
        state.roots.add(request.source_ref)
    for key in sorted(state.keys,key=lambda key:key.token):
        task=state.tasks.get(key.token)
        if task is None or not task.complete:_need_method_input(r,('commitment_input_metadata',key.token))
        from ..authority_service.habit_authority_source_read_v3 import _source_refs_v3
        if key.type_name not in TYPES:state.roots.update(_source_refs_v3(task.result))
    if operation_kind in APPLICABILITY_OPERATIONS:
        prepare_current_commitment_applicability_v3(r)
        state.content_source_refs=set(state.roots)
        state.roots.update(state.policy_source_refs)
        keys.update(state.applicable_keys)
    if len(state.roots)>32:raise AuthorityUnavailable(f'source_root_budget_exceeded(required_count={len(state.roots)},limit=32)')
    if any(NamespaceId.from_key(AtomKey.from_token(ref))!=namespace or AtomKey.from_token(ref).type_name!='memory.source'for ref in state.roots):
        raise AuthorityUnavailable('Commitment metadata crossed its canonical Source namespace')
    state.metadata_complete=True
    return augment_persona_birth_plan_v1(db,namespace=namespace,operation_kind=operation_kind,
        plan=production_read_plan_v1(TYPES,tuple(sorted(keys|{key for key in state.keys if key.type_name not in TYPES},key=lambda key:key.token)),tuple(sorted(state.roots)),()))

def commitment_input_source_groups_v3(r,roots):
    state=require_commitment_input_source_v3(r)
    if r.operation_kind in TERMS_SOURCE_OPERATIONS_V3:
        from .current_commitment_fulfillment_source_v3 import terms_source_groups_v3
        return terms_source_groups_v3(r,roots)
    if r.operation_kind in CANCELLATION_OPERATIONS:
        from .d08_action_cancellation_v1 import action_cancellation_source_groups_v1
        return action_cancellation_source_groups_v1(r,roots)
    if r.operation_kind in LIFECYCLE_OPERATIONS:
        from .current_commitment_lifecycle_source_v3 import commitment_lifecycle_source_groups_v3
        return commitment_lifecycle_source_groups_v3(r,roots)
    if not state.metadata_complete or set(roots)!=state.roots or r.authority.purpose!='expression' or r.selected_envelope.authority.purpose!='expression':
        raise AuthorityUnavailable('Commitment Source groups changed the actual complete expression plan')
    if r.operation_kind in {'input:create_commitment','input:create_commitment_with_fulfillment_terms'}:
        content=tuple(sorted(state.content_source_refs))
        return (('expression',(r.audience_ref,),content),)+(('context',state.policy_audiences,tuple(sorted(state.policy_source_refs))),)if state.policy_source_refs else (('expression',(r.audience_ref,),content),)
    return (('expression',(r.audience_ref,),tuple(sorted(roots))),)

def require_commitment_input_sources_v3(r,roots):
    from .current_beta1_source_read_v3 import qualify_current_beta1_source_groups_v3
    state=require_commitment_input_source_v3(r);state.permission=qualify_current_beta1_source_groups_v3(r,roots);return state.permission

def require_commitment_input_body_v3(r,table,key):
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    state=require_commitment_input_source_v3(r)
    if require_beta1_source_control_point_v3(r,(table,('revision','value','valid'),('token','bot','persona'),tuple(key))):return
    if table=='runtime_budget_grants'and r.budget_task is not None and tuple(key)==tuple(r.budget_task.metadata[:2])and key[0]==r.parent_budget_lease_ref:return
    if state.permission is None:raise AuthorityUnavailable('Commitment protected Body requires its actual complete Source ALL')
    state.permission.require_for_v3(r)
    from .current_beta1_source_read_v3 import require_beta1_source_member_v3
    for ref in sorted(state.policy_source_refs):
        new_policy=r.operation_kind in TERMS_SOURCE_OPERATIONS_V3 or r.operation_kind in {'input:create_commitment','input:create_commitment_with_fulfillment_terms'}
        require_beta1_source_member_v3(r,ref,'context' if new_policy else 'expression',state.policy_audiences if new_policy else(r.audience_ref,))
    if state.selector_dependency_refs:
        from .current_beta1_source_read_v3 import require_beta1_source_member_v3
        for ref in sorted(state.selector_dependency_refs):
            for purpose in (('context','expression') if r.operation_kind=='input:register_commitment_terms_communication' else ('context',) if r.operation_kind in TERMS_SOURCE_OPERATIONS_V3 else ('expression',)):
                require_beta1_source_member_v3(r,ref,purpose,(r.audience_ref,))
    if table in {'graph_first_ingress_identity_v1','graph_first_ingress_intents_v2'}:
        if key[-1] not in _commitment_ingress_operations_v3(r):
            raise AuthorityUnavailable('Commitment ingress metadata lacks its actual Source-qualified identity')
        return
    if table=='graph_atoms':
        atom=AtomKey.from_token(key[0])
        if r.operation_kind in APPLICABILITY_OPERATIONS and atom.type_name in TYPES and atom not in state.applicable_keys:
            raise AuthorityUnavailable('unrelated policy metadata cannot authorize its Body')
        if atom not in r.selected_plan.exact_keys and atom.token not in state.permission.source_refs:raise AuthorityUnavailable('Commitment Body is outside its exact current plan')
    elif table=='graph_history':
        atom=AtomKey.from_token(key[0])
        if not any(version.key==atom and version.revision==key[1]for version in state.permission.versions):raise AuthorityUnavailable('Commitment history is outside its actual current Source head')
    else:raise AuthorityUnavailable('Commitment input has no registered historical original Body')

def require_commitment_input_point_v3(r,request):
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    require_commitment_input_source_v3(r)
    table,columns,key_columns,key=request
    if (table,columns) in _COMMITMENT_INGRESS_SHAPES_V3:
        if key_columns!=('bot','persona','operation_id') or tuple(key[:2])!=r.namespace.as_tuple or key[-1]not in _commitment_ingress_operations_v3(r):
            raise AuthorityUnavailable('Commitment ingress point crossed its exact Source-qualified Host identity')
        return
    if require_beta1_source_control_point_v3(r,request):return
    shapes={('graph_atoms',('revision','value','valid'),('token','bot','persona')),
        ('graph_history',('event_id','value','valid'),('token','revision')),
        ('graph_history',('value','valid','event_id'),('token','revision'))}
    if request[:3]not in shapes or NamespaceId.from_key(AtomKey.from_token(key[0]))!=r.namespace:
        raise AuthorityUnavailable('Commitment input point is outside its exact registered current shape')
    require_commitment_input_body_v3(r,table,key)

def register_commitment_input_write_v3(inputs,scope,current_owner):
    r=inputs.owner;state=require_commitment_input_source_v3(r)
    if not r.inputs_sealed:return
    from .current_method_learning_read_v3 import _method_active
    if (not r.read_finished or not r.business_started or scope.operation!='write'or scope is r.fence.scope
            or scope.namespace!=r.namespace or current_owner!=r.owner_binding or state.permission is None
            or inputs.plan!=r.selected_plan or _method_active(r.db)is not r):
        raise AuthorityUnavailable('Commitment WRITE requires its sealed actual Source Work and fresh Owner')
    _WRITES[r]=(inputs,scope,current_owner,state.identity,state.permission)

def require_commitment_input_write_v3(r):
    state=require_commitment_input_source_v3(r);record=_WRITES.get(r)
    if record is None or record[0].owner is not r or record[2]!=r.owner_binding or record[3:]!=(state.identity,state.permission)or not r.inputs_sealed or not r.read_finished or not r.business_started:
        raise AuthorityUnavailable('Commitment input lost its actual same-Work WRITE binder')
    r.require_current();return record

def release_commitment_input_source_v3(r):
    state=_STATES.pop(r,None);_WRITES.pop(r,None)
    if state is not None:
        from .d08_commitment_fulfillment_v1 import release_actual_commitment_terms_stages_v1
        release_actual_commitment_terms_stages_v1(state)
        if r.operation_kind in CANCELLATION_OPERATIONS:
            from .d08_action_cancellation_v1 import release_current_action_cancellation_v1
            release_current_action_cancellation_v1(state)
        for task in state.tasks.values():
            release=getattr(task,'release_v1',None)
            if release is not None:release()
        state.tasks.clear();state.keys.clear();state.roots.clear();state.selector_dependency_refs.clear();state.permission=None


_COMMITMENT_INGRESS_SHAPES_V3=frozenset({
    ('graph_first_ingress_identity_v1',('source_ref','platform_ref','conversation_ref','sender_ref','message_id','visibility','identity_json','content_fingerprint','learned_at','bundle_digest')),
    ('graph_first_ingress_intents_v2',('identity_json',)),
    ('ingress_first_observations',('content_fingerprint','learned_at','bundle_digest')),
    ('graph_bundle_operations',('digest',))})


def _commitment_ingress_operations_v3(reader):
    state=require_commitment_input_source_v3(reader)
    if state.permission is None:raise AuthorityUnavailable('Commitment ingress requires actual full Source ALL first')
    state.permission.require_for_v3(reader)
    from .first_ingress_v2 import ingress_ids
    return frozenset(ingress_ids(record.source_id)[2]for record in state.permission.records.values()
        if len(record.source_id)==64 and set(record.source_id)<=set('0123456789abcdef'))


def commitment_input_ingress_point_v3(db,table,columns,key_columns,key):
    from .current_method_learning_read_v3 import _method_active,_need_method_input,MethodJSONColumnV3
    r=_method_active(db)
    if r is None or r.operation_kind not in OPERATIONS:return False,None
    request=(table,tuple(columns),tuple(key_columns),tuple(key))
    if (table,tuple(columns))not in _COMMITMENT_INGRESS_SHAPES_V3:
        raise AuthorityUnavailable('unregistered Commitment ingress metadata point')
    require_commitment_input_point_v3(r,request)
    task=r.points.get(request)
    if task is None or not task.complete:_need_method_input(r,('point',request))
    with runtime_storage_quantum_v3(db)as meter:row=task.require_row_v3(meter)
    if row is None:return True,None
    return True,tuple(value.wire if type(value)is MethodJSONColumnV3 else value for value in row)


class _PolicyRouteMetadataV3:
    def __init__(self,reader,ref):
        self.reader,self.ref=reader,ref;self.complete=False;self.result=None
    def advance(self,meter):
        import json
        from .first_ingress_v2 import ingress_ids,scene_ref_for_conversation
        from ..host.identity import astrbot_namespace
        r=self.reader;r.require_current(meter=meter);require_commitment_input_source_v3(r)
        key=AtomKey.from_token(self.ref)
        if key.type_name!='memory.source' or NamespaceId.from_key(key)!=r.namespace:
            raise AuthorityUnavailable('policy route selector is not an actual canonical Source')
        row=meter.read_fixed_row(r.db,'graph_first_ingress_identity_v1',
            ('source_ref','platform_ref','conversation_ref','sender_ref','message_id','visibility'),
            'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,ingress_ids(key.owner.subject)[2]))
        if row is None or row[0]!=key.owner.subject or row[5]!='private':
            raise AuthorityUnavailable('policy applicability requires its actual private ingress metadata')
        account,destination=json.loads(row[1]),json.loads(row[2])
        if (type(account)is not list or len(account)!=3 or type(destination)is not list or len(destination)!=2
                or any(type(x)is not str or not x for x in (*account,*destination,row[3],row[4]))
                or json.dumps(account,ensure_ascii=True,separators=(',',':'))!=row[1]
                or json.dumps(destination,ensure_ascii=True,separators=(',',':'))!=row[2]
                or astrbot_namespace(account[0],account[2],'route-check').bot_id!=r.namespace.bot_id):
            raise AuthorityUnavailable('policy applicability original ingress route differs')
        self.result=(*row[1:5],scene_ref_for_conversation(r.namespace,row[1],row[2]))
        self.complete=True;return True


def _policy_sources_v3(value):
    refs=set()
    for field in ('source_refs','creation_evidence_refs','verification_ref'):
        entries=value.get(field,())
        entries=(entries,)if type(entries)is str else entries
        for ref in entries:
            if type(ref)is not str:raise AuthorityUnavailable('policy provenance metadata is not a fixed reference tuple')
            try:key=AtomKey.from_token(ref)
            except ValueError:
                if field=='source_refs':raise
                continue
            if key.type_name=='memory.source':refs.add(ref)
    return refs


def _policy_decision_v3(kind,value,*,subject,target,route,now):
    from ..domains.d03.context import RoleBinding,RoleBindingRequest
    from ..domains.d05.relationship import BoundaryRule
    if not set(_SELECTOR_FIELDS[kind])<=set(value):
        raise AuthorityUnavailable('policy applicability metadata is incomplete')
    import math
    required_text={
      'd03.entity_anchor':('entity_id','status'),
      'd03.account_binding':('platform_namespace','platform_identifier','entity_id','verification_ref'),
      'd03.role_binding':('subject_persona_ref','status'),
      'd05.boundary_rule':('subject_persona_ref','target_entity_ref','action_kind','audience_scope','status')}[kind]
    if any(type(value[name])is not str or not value[name]for name in required_text):
        raise AuthorityUnavailable('policy selector has an unknown identity/status field')
    statuses={'d03.entity_anchor':{'active','ambiguous','retired'},'d03.role_binding':{'active','review','revoked'},'d05.boundary_rule':{'active','superseded','revoked'}}
    if kind in statuses and value['status']not in statuses[kind]:raise AuthorityUnavailable('unknown policy selector status')
    for name in ('target_entity_ref','group_ref','scene_ref'):
        if name in value and value[name]is not None and(type(value[name])is not str or not value[name]):
            raise AuthorityUnavailable('unknown nullable policy scope selector')
    for name in ('source_refs','creation_evidence_refs'):
        if name in value and(type(value[name])not in(list,tuple)or any(type(ref)is not str or not ref for ref in value[name])):
            raise AuthorityUnavailable('incomplete policy provenance selector')
    time_fields=('effective_from','effective_until')if kind=='d03.role_binding' else ('valid_from','valid_until')
    if kind!='d03.entity_anchor':
        start,end=(value[name]for name in time_fields)
        if type(start)not in (float,int)or not math.isfinite(start)or(end is not None and(type(end)not in(float,int)or not math.isfinite(end)or end<start)):
            raise AuthorityUnavailable('policy selector has incomplete current time bounds')
    if kind=='d03.entity_anchor':return value['entity_id']==target and value['status']=='active' 
    if route is None:return False
    platform,audience,sender,message,scene=route
    if kind=='d03.account_binding':
        return (value['platform_namespace']==platform and value['platform_identifier']==sender and value['entity_id']==target
            and value['valid_from']<=now and(value['valid_until']is None or now<=value['valid_until']))
    projected=SimpleNamespace(**value)
    if kind=='d03.role_binding':
        return RoleBinding.applies_to(projected,RoleBindingRequest(subject,target,None,scene,'message','expression',now,True))
    return BoundaryRule.applies_to(projected,subject_persona_ref=subject,target_entity_ref=target,
        action_kind='message',audience_scope=audience,scene_ref=scene,at_time=now)


def prepare_current_commitment_applicability_v3(reader):
    from .current_method_learning_read_v3 import _need_method_input
    state=require_commitment_input_source_v3(reader);request=reader.request;op=reader.operation_kind
    if op not in APPLICABILITY_OPERATIONS:raise AuthorityUnavailable('policy selector requires the exact Commitment Source profile')
    if op in {'input:create_commitment','input:create_commitment_with_fulfillment_terms'}:
        target=request.counterparty_ref;route_ref=None
    else:
        ref=request.current_commitment.ref if op in TERMS_SOURCE_OPERATIONS_V3 else request.commitment.ref
        metadata=state.tasks[ref].result;target=metadata['counterparty_ref']
        if op=='input:register_commitment_terms_communication' or op=='input:register_commitment_communication':route_ref=request.source_ref
        elif op=='acknowledge_commitment_terms':route_ref=request.inbound_source_ref
        else:route_ref=request.recipient_ack_source_ref
    route=None
    if route_ref is not None:
        task=state.tasks.get(('policy_route',route_ref))
        if task is None or not task.complete:_need_method_input(reader,('commitment_input_metadata',('policy_route',route_ref)))
        route=task.result
    subject='persona:'+reader.namespace.persona_id;selected=set();sources=set()
    for key in sorted(state.keys,key=lambda key:key.token):
        if key.type_name not in TYPES:continue
        task=state.tasks.get(key.token)
        if task is None or not task.complete:_need_method_input(reader,('commitment_input_metadata',key.token))
        if task.header!=reader.heads.get(key.token):raise AuthorityUnavailable('policy selector metadata changed its complete census Head')
        if task.header[1]!=1:continue
        # Facts do not reauthorize current outgoing policy.
        applicable=_policy_decision_v3(key.type_name,task.result,subject=subject,target=target,
            route=route,now=reader.initial_now_utc)
        if op in {'acknowledge_commitment_terms','settle_current_commitment_fulfillment'} and(route is None or key.type_name in {'d03.role_binding','d05.boundary_rule'}):applicable=False
        if applicable:selected.add(key);sources.update(_policy_sources_v3(task.result))
    for ref in sources:
        key=AtomKey.from_token(ref)
        if key.type_name!='memory.source' or NamespaceId.from_key(key)!=reader.namespace:
            raise AuthorityUnavailable('policy provenance left its actual namespace')
    context=(subject,target,route,reader.initial_now_utc,tuple(sorted((key.token,reader.heads[key.token])for key in state.keys if key.type_name in TYPES)))
    if state.selector_context is not None and(state.selector_context!=context or state.applicable_keys!=selected or state.policy_source_refs!=sources):
        raise AuthorityUnavailable('sealed policy applicability changed its original metadata selection')
    state.selector_context=context;state.applicable_keys=selected;state.policy_source_refs=sources;state.policy_audiences=('owner',)
    return state


def read_current_commitment_applicable_inventory_v3(db,frame,type_name):
    from .current_method_learning_read_v3 import _method_active,method_graph_head_v3
    reader=_method_active(db);state=require_commitment_input_source_v3(reader)
    if reader.operation_kind not in APPLICABILITY_OPERATIONS or type_name not in TYPES or not state.metadata_complete:
        raise AuthorityUnavailable('actual sealed Commitment applicability profile required')
    state.permission.require_for_v3(reader)
    subject,target,route,now,census=state.selector_context
    pages=tuple(page for page in frame.query_coverage if page.type_id==type_name)
    expected=tuple(GraphVersion(AtomKey.from_token(ref),head[0])for ref,head in census if AtomKey.from_token(ref).type_name==type_name)
    if len(pages)!=1 or not pages[0].complete or pages[0].row_versions!=expected or pages[0].epoch.revision!=frame.snapshot.epochs[0].revision:
        raise AuthorityUnavailable('Commitment policy census lost its complete current negative-query coverage')
    result=[]
    for ref,header in census:
        key=AtomKey.from_token(ref)
        if key.type_name!=type_name or header[1]!=1:continue
        value=state.tasks[ref].result
        applicable=_policy_decision_v3(type_name,value,subject=subject,target=target,route=route,now=frame.now_utc)
        if reader.operation_kind in {'acknowledge_commitment_terms','settle_current_commitment_fulfillment'} and(route is None or type_name in {'d03.role_binding','d05.boundary_rule'}):applicable=False
        if applicable!=(key in state.applicable_keys):raise AuthorityUnavailable('policy applicability changed before actual Body use')
        if not applicable:continue
        atom=method_graph_head_v3(db,reader.namespace,key)
        if (not atom.valid or atom.revision!=header[0] or canonical_digest({field:atom.value.get(field)for field in _SELECTOR_FIELDS[type_name]})!=canonical_digest({field:value[field]for field in _SELECTOR_FIELDS[type_name]})):
            raise AuthorityUnavailable('qualified policy Body differs from its exact applicability metadata')
        result.append(atom)
    return tuple(result)


def read_current_commitment_actor_entity_v3(db,frame,source_ref,*,expected_entity):
    from .d01_production_operations_v1 import CurrentDomainReadV1
    from ..domains.d03.prebatch_social import _private_route
    read=CurrentDomainReadV1(frame);family=read.source_family(db,(source_ref,),purpose=frame.envelope.authority.purpose)
    platform,audience,sender,message,scene=_private_route(db,frame.envelope.authority.namespace,source_ref)
    import json
    from .ingress_observation import read_committed_ingress_identity
    original=read_committed_ingress_identity(db,frame.envelope.authority.namespace,family[source_ref].source_id)
    if original is None:raise AuthorityUnavailable('actual committed Host ingress actor original required')
    identity=json.loads(original.identity_json)
    if (family[source_ref].speaker_id!=sender or identity['sender_ref']!=sender or identity['platform_ref']!=platform):
        raise AuthorityUnavailable('actual inbound Source speaker differs from original Host identity')
    accounts=tuple(atom for atom in read_current_commitment_applicable_inventory_v3(db,frame,'d03.account_binding')
        if atom.value['platform_namespace']==platform and atom.value['platform_identifier']==sender and atom.value['entity_id']==expected_entity)
    entities=read_current_commitment_applicable_inventory_v3(db,frame,'d03.entity_anchor')
    if len(accounts)!=1 or len(entities)!=1:raise AuthorityUnavailable('one actual current inbound account/entity binding required')
    return accounts[0],entities[0]


def current_commitment_applicability_metadata_inventory_v3(prepared,type_id):
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3
    if type(prepared)is not PreparedMethodDomainInputsV3 or prepared.owner.operation_kind not in APPLICABILITY_OPERATIONS or type_id not in TYPES:return None
    r=prepared.owner;state=require_commitment_input_source_v3(r)
    if not state.metadata_complete or prepared.plan!=r.selected_plan:raise AuthorityUnavailable('policy metadata inventory lost actual Source inputs')
    return tuple(GraphVersion(AtomKey.from_token(token),head[0])for token,head in sorted(r.heads.items())if AtomKey.from_token(token).type_name==type_id)


def compose_current_commitment_applicability_cas_v3(db,read_versions,limits):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    if r is None or r.operation_kind not in APPLICABILITY_OPERATIONS:return read_versions
    state=require_commitment_input_source_v3(r)
    if not state.metadata_complete:raise AuthorityUnavailable('policy CAS requires actual complete applicability metadata')
    versions={v.key:v.revision for v in read_versions}
    if state.permission is None:raise AuthorityUnavailable('policy CAS requires the actual Source ALL permission')
    state.permission.require_for_v3(r)
    for version in state.permission.versions:
        if version.key in versions and versions[version.key]!=version.revision:
            raise AuthorityUnavailable('policy Source metadata and actual Body CAS disagree')
        versions[version.key]=version.revision
    for token,header in r.heads.items():
        key=AtomKey.from_token(token)
        if key.type_name not in TYPES:continue
        if key in versions and versions[key]!=header[0]:raise AuthorityUnavailable('policy Body and census CAS disagree')
        versions[key]=header[0]
    if len(versions)>limits.max_graph_heads:raise AuthorityUnavailable('complete policy census exceeds current-head bound')
    return tuple(GraphVersion(key,revision)for key,revision in sorted(versions.items(),key=lambda pair:pair[0].token))



def current_commitment_policy_binding_v3(db,frame):
    from .current_method_learning_read_v3 import _method_active
    reader=_method_active(db);state=require_commitment_input_source_v3(reader)
    if reader.operation_kind!='input:register_commitment_terms_communication' or not state.metadata_complete or state.selector_context is None:
        raise AuthorityUnavailable('actual sealed V2 communication policy context required')
    state.permission.require_for_v3(reader)
    versions=tuple(GraphVersion(key,reader.heads[key.token][0])for key in sorted(state.applicable_keys,key=lambda key:key.token))
    from .current_beta1_source_read_v3 import require_beta1_source_member_v3
    for ref in state.policy_source_refs:require_beta1_source_member_v3(reader,ref,'context',state.policy_audiences)
    return tuple(sorted(state.policy_source_refs)),state.policy_audiences,versions


def current_commitment_policy_metadata_source_v3(prepared,ref):
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3
    if type(prepared)is not PreparedMethodDomainInputsV3 or prepared.owner.operation_kind not in APPLICABILITY_OPERATIONS:return None
    r=prepared.owner;state=require_commitment_input_source_v3(r)
    if not state.metadata_complete or state.permission is None:return None
    if(ref,'context',state.policy_audiences)not in state.permission.qualified_members:return None
    content_purpose='context' if r.operation_kind in {'acknowledge_commitment_terms','settle_current_commitment_fulfillment'} else 'expression'
    if(ref,content_purpose,(r.audience_ref,))in state.permission.qualified_members:return None
    from .current_beta1_source_read_v3 import require_beta1_source_member_v3
    return require_beta1_source_member_v3(r,ref,'context',state.policy_audiences)
