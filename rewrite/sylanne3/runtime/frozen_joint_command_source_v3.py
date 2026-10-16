"""Fixed Artifact command-freeze Source profile on World/common storage Work.

Only real Root/Scope/objective/selected-phase locators are admitted. Metadata EOF
precedes Source ALL; the original typed producer remains a separate Owner WRITE.
"""
from contextlib import contextmanager
from types import SimpleNamespace
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3,bind_runtime_storage_operation_v3
from .joint_window_command_v1 import OPERATION,FreezeJointWindowNodeCommandRequestV1
from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3

_STATES=WeakKeyDictionary()
_BRIDGES=WeakKeyDictionary()
_WRITES=WeakKeyDictionary()
DOMAINS=frozenset({'d01','d02','d03','d05','d06','d07','d08','d10','d11','d12'})
_SOURCE_FIELDS=frozenset({'source_refs','source_ref','input_source_ref','body_source_ref','creation_evidence_refs','reason_refs'})
_CONTROL_FIELDS=frozenset({'prepared_candidates_operation_id','chosen_action_ref','quote_ref','quote_digest','action_ref','candidate_ref','node_id'})


def is_frozen_joint_artifact_request_v3(request):
    return type(request)is FreezeJointWindowNodeCommandRequestV1 and type(request.command.binding)is JointArtifactProspectiveBindingV1


def _identity(r):return(r.graph,r.work,r.operation,r.fence,r.namespace,r.selection_digest,r.graph_stamp,r.request,r.operation_id,r.authority,r.owner_binding)


def register_frozen_joint_source_v3(r):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3,WORLD_SOURCE_WORK_KIND_V3
    require_current_beta1_source_work_v3(r)
    if r.operation_kind!=OPERATION or not is_frozen_joint_artifact_request_v3(r.request)or r.work.kind!=WORLD_SOURCE_WORK_KIND_V3 or r in _STATES:
        raise AuthorityUnavailable('Frozen Artifact Source profile requires its exact once-issued Owner command')
    state=SimpleNamespace(reader=r,identity=_identity(r),tasks={},roots=set(),groups=(),permission=None,
        graph_keys=set(),life_keys=set(),producers=set(),quote_keys=set(),job_ids=set(),body=None,
        d12_digests=set(),d12_compilations={},d12_tasks={},d12_candidate_refs=set())
    _STATES[r]=state
    binding=r.request.command.binding
    from .d11_life_preparation_v1 import TABLE
    for kind,ref in(('artifact_task_objective',binding.objective_ref),('artifact_task_scope',binding.task_scope_ref),('draft_root_capability',binding.executor.root_registration_ref)):
        state.life_keys.add((kind,ref))
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    from ..domains.d12.types import active_scheme_head_key
    task=artifact_draft_task_selector_v1(r.namespace,c02_operation_id=binding.executor.c02_operation_id,root_registration_ref=binding.executor.root_registration_ref)
    state.job_ids.add(AtomKey.from_token(task.cycle_job_ref).name)
    state.graph_keys.update(AtomKey.from_token(ref)for ref in(binding.goal_ref,binding.project_ref,binding.recipe_ref,binding.target_entity_ref,binding.role_ref,task.cycle_job_ref))
    state.graph_keys.update((owner_grant_key(*r.namespace.as_tuple),active_scheme_head_key(r.namespace)))
    phase=binding.executor.phase_selector
    if phase is not None:
        state.graph_keys.update((AtomKey.from_token(phase.decision_ref),AtomKey.from_token(phase.plan_ref)))
        if phase.prev_phase_original_ref is not None:state.life_keys.add(('c4_phase_verified',phase.prev_phase_original_ref))
    return state


def require_frozen_joint_source_v3(r):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(r)
    state=_STATES.get(r)
    if state is None or state.reader is not r or not is_frozen_joint_artifact_request_v3(r.request)or state.identity[:-1]!=_identity(r)[:-1]:
        raise AuthorityUnavailable('Frozen command Source profile changed its exact actual Work/selection')
    if state.permission is not None and state.identity[-1]is not r.owner_binding:raise AuthorityUnavailable('Frozen Source Owner changed after ALL')
    return state


def pin_frozen_joint_owner_v3(r):
    state=require_frozen_joint_source_v3(r)
    r.general_owner_entry.require_for_v3(r);state.identity=_identity(r)


class _MetadataColumn(DispatchOriginalJSONReadV3):
    def _emit(self,event):
        if event.kind in {'object_start','array_start'}or any(part in _SOURCE_FIELDS or part in _CONTROL_FIELDS or type(part)is str and(part.endswith('_source_head')or part.endswith('_source_ref'))for part in event.path):
            super()._emit(event)


def _refs(value):
    from ..authority_service.habit_authority_source_read_v3 import _source_refs_v3
    result=_source_refs_v3(value)
    def walk(raw,path=()):
        if type(raw)is dict:
            for key,item in raw.items():
                if type(item)is str and(key.endswith('_source_ref')or key=='key'and any(type(p)is str and p.endswith('_source_head')for p in path)):
                    token=AtomKey.from_token(item)
                    if token.type_name=='memory.source':result.add(item)
                elif type(item)in(dict,list):walk(item,(*path,key))
        elif type(raw)is list:
            for item in raw:walk(item,path)
    walk(value)
    return result


class _MetadataTask:
    def __init__(self,r,identity):
        from .d11_life_preparation_v1 import TABLE
        from .domain_production_originals_v1 import PHYSICAL_TABLE
        self.reader,self.identity=r,identity;self.column=None;self.complete=False;self.result=None;self.header=None
        state=require_frozen_joint_source_v3(r);kind=identity[0]
        if kind=='life'and tuple(identity[1:])in state.life_keys:
            self.table,self.name,self.keys,self.key=TABLE,'payload_json',('bot','persona','kind','original_ref'),(*r.namespace.as_tuple,*identity[1:])
            self.columns=('producing_operation_id','payload_digest','signature')
        elif kind=='head'and AtomKey.from_token(identity[1])in state.graph_keys:
            self.table,self.name,self.keys,self.key='graph_atoms','value',('token','bot','persona'),(identity[1],*r.namespace.as_tuple)
            self.columns=('revision','valid','value_cell_id')
        elif kind=='producer'and identity[1]in state.producers:
            self.table,self.name,self.keys,self.key='graph_domain_production_originals_v1','original_payload_json',('bot','persona','operation_id'),(*r.namespace.as_tuple,identity[1])
            self.columns=('domain','operation_kind','original_digest')
        else:raise AuthorityUnavailable('Frozen Source metadata selector is outside its actual fixed originals')
        self.where=' AND '.join(name+'=?'for name in self.keys)
    def advance(self,meter):
        r=self.reader;state=require_frozen_joint_source_v3(r);r.require_current(meter=meter)
        if self.complete:return True
        row=_runtime_bounded_fixed_row_v3(r.db,meter,self.table,self.columns,self.where,self.key)
        if self.header is None:
            if row is None and self.identity[0]=='producer':
                from .domain_production_originals_v1 import PHYSICAL_TABLE
                self.table,self.name=PHYSICAL_TABLE,'original_payload_cell_id';self.columns=(*self.columns,'original_payload_cell_id')
                row=_runtime_bounded_fixed_row_v3(r.db,meter,self.table,self.columns,self.where,self.key)
            if row is None:raise AuthorityUnavailable('Frozen Source actual immutable metadata is missing')
            self.header=row
            cell=row[2]if self.identity[0]=='head'else row[3]if self.name=='original_payload_cell_id'else None
            self.column=_MetadataColumn(r,table=self.table,column=self.name,key_columns=self.keys,key=self.key,cell_id=cell)
            from ..authority_service.named_joint_binding_source_read_v3 import _MetadataStreamV3
            self.stream=_MetadataStreamV3(self.column,self.column.cell is None or self.column.cell.header[0]=='canonical-json.ascii.v1')
            self.column.parser=self.stream
            return False
        if row!=self.header:raise AuthorityUnavailable('Frozen Source original locator changed during complete EOF')
        if not self.column.advance(meter):return False
        value=self.column.require_v3(r);digest=self.stream.semantic.hexdigest();kind=self.identity[0]
        if kind=='head':
            if self.header[:2]!=(r.heads[self.identity[1]][0],1)or self.header[2]!=r.heads[self.identity[1]][2]:raise AuthorityUnavailable('Frozen Source graph metadata differs from actual current census')
        elif kind=='life':
            from .d11_life_preparation_v1 import SIGN_KIND
            r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,canonical_serialize((r.namespace,self.identity[1],self.identity[2],digest)),self.header[2])
            if digest!=self.header[1]:raise AuthorityUnavailable('Frozen Source signed life original changed')
            state.producers.add(self.header[0])
        else:
            if digest!=self.header[2]:raise AuthorityUnavailable('Frozen Source W01 original metadata digest changed')
            pointer=value.get('provenance',{}).get('prepared_candidates_operation_id')
            if pointer is not None:state.producers.add(pointer)
        roots=_refs(value)
        if any(NamespaceId.from_key(AtomKey.from_token(ref))!=r.namespace for ref in roots):raise AuthorityUnavailable('Frozen Source metadata crossed Source namespace')
        state.roots.update(roots);self.result=value;self.complete=True
        return True


def create_frozen_joint_metadata_task_v3(r,identity):
    state=require_frozen_joint_source_v3(r)
    task=state.tasks.get(identity)
    if task is None:task=_MetadataTask(r,identity);state.tasks[identity]=task
    return task


def _metadata(r,identity):
    from .current_method_learning_read_v3 import _need_method_input
    state=require_frozen_joint_source_v3(r);task=state.tasks.get(identity)
    if task is None or not task.complete:_need_method_input(r,('frozen_joint_metadata',identity))
    return task.result


def frozen_joint_read_plan_v3(db,*,namespace,request):
    from .current_method_learning_read_v3 import _method_active
    from .d01_production_operations_v1 import production_read_plan_v1
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    r=_method_active(db);state=require_frozen_joint_source_v3(r)
    if namespace!=r.namespace or request!=r.request:raise AuthorityUnavailable('Frozen Source plan changed its original request')
    for kind,ref in sorted(state.life_keys):_metadata(r,('life',kind,ref))
    for key in sorted(state.graph_keys,key=lambda key:key.token):
        if key==owner_grant_key(*r.namespace.as_tuple):continue
        raw=_metadata(r,('head',key.token))
        if key.type_name=='d12.active_scheme_head.v1':continue
        head=r.heads[key.token]
        with runtime_storage_quantum_v3(db)as meter:
            row=_beta1_metadata_row_v3(r,meter,'graph_history',('event_bot','event_persona','event_id','valid'),'token=? AND revision=?',(key.token,head[0]))
        if row is None or row[:2]!=r.namespace.as_tuple or row[3]!=1:raise AuthorityUnavailable('Frozen Source actual selected head has no valid producer')
        # A C02-created persistent job is proved by the first-ingress receipt,
        # not a nonexistent domain-production Original row.
        if key.type_name in {'d08.decision_record.v2','d08.personal_plan.v1'}:state.producers.add(row[2])
    while True:
        pending=tuple(sorted(operation for operation in state.producers if('producer',operation)not in state.tasks or not state.tasks['producer',operation].complete))
        if not pending:break
        for operation in pending:_metadata(r,('producer',operation))
    state.roots.update(request.command.binding.source_refs)
    role_roots=set()
    for key in state.graph_keys:
        if key.type_name in {'d03.role_binding','d03.entity_anchor'}:role_roots.update(_refs(state.tasks['head',key.token].result))
    all_roots=tuple(sorted(state.roots));binding=request.command.binding
    groups=[]
    if role_roots:groups.append(('context',binding.audience,tuple(sorted(role_roots))))
    other=set(all_roots)-role_roots|set(binding.source_refs)
    if other:groups.append(('consolidation',binding.audience,tuple(sorted(other))))
    state.groups=tuple(groups)
    phase=binding.executor.phase_selector
    if phase is not None:
        decision=state.tasks['head',phase.decision_ref].result
        for identity,task in state.tasks.items():
            if identity[0]!='producer'or not task.complete:continue
            prepared=task.result.get('provenance',{}).get('prepared_candidates')
            if prepared is None:continue
            chosen=tuple(item for item in prepared['candidates']if item['future_identity']['action_ref']==decision['chosen_action_ref'])
            if len(chosen)!=1:raise AuthorityUnavailable('Frozen phase metadata lacks its actual unique selected candidate')
            if chosen[0].get('quote_ref')is not None:state.quote_keys.add((chosen[0]['quote_ref'],1))
    originals=(binding.objective_ref,binding.task_scope_ref,binding.executor.root_registration_ref,binding.executor.c02_operation_id)
    if binding.executor.phase_selector is not None and binding.executor.phase_selector.prev_phase_original_ref is not None:originals=(*originals,binding.executor.phase_selector.prev_phase_original_ref)
    return production_read_plan_v1((),tuple(sorted(state.graph_keys,key=lambda key:key.token)),all_roots,originals)


def frozen_joint_source_groups_v3(r,roots):
    state=require_frozen_joint_source_v3(r)
    if set(roots)!=state.roots:raise AuthorityUnavailable('Frozen Source roots changed after complete original EOF')
    return state.groups


def require_frozen_joint_sources_v3(r,roots):
    from .current_beta1_source_read_v3 import qualify_current_beta1_source_groups_v3
    state=require_frozen_joint_source_v3(r);state.permission=qualify_current_beta1_source_groups_v3(r,roots)
    return state.permission


def require_frozen_joint_body_v3(r,table,key):
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    state=require_frozen_joint_source_v3(r)
    if require_beta1_source_control_point_v3(r,(table,('revision','value','valid'),('token','bot','persona'),tuple(key))):return
    if table=='runtime_budget_grants'and r.budget_task is not None and tuple(key)==tuple(r.budget_task.metadata[:2])and key[0]==r.parent_budget_lease_ref:return
    if state.permission is None:raise AuthorityUnavailable('Frozen body requires completed exact Source ALL first')
    state.permission.require_for_v3(r)
    if table in {'graph_atoms','graph_history'}:
        atom=AtomKey.from_token(key[0])
        if atom not in state.graph_keys and atom.token not in state.permission.source_refs:raise AuthorityUnavailable('Frozen body is outside actual fixed graph inputs')
    elif table=='graph_d11_life_originals_v1':
        if tuple(key[-2:])not in state.life_keys:raise AuthorityUnavailable('Frozen body selected another life Original')
    elif table in {'graph_domain_production_originals_v1','graph_domain_production_originals_v3','graph_bundle_operations'}:
        if key[-1]not in state.producers and key[-1]!=r.request.command.binding.executor.c02_operation_id:raise AuthorityUnavailable('Frozen body selected another actual producer')
    elif table=='graph_d12_domain_candidates_v1':
        if key[-1]not in state.d12_candidate_refs:raise AuthorityUnavailable('Frozen body selected another compiled Context catalogue')
    elif table=='runtime_jobs':
        if key[0]not in state.job_ids:raise AuthorityUnavailable('Frozen body selected another cycle job')
    elif table=='runtime_resource_quotes':
        if tuple(key)not in state.quote_keys:raise AuthorityUnavailable('Frozen body selected another existing selected price')
    elif table in {'runtime_budget_grants','runtime_budget_leases','runtime_budget_debt_blocks'}:
        if key[0]!=r.parent_budget_lease_ref:raise AuthorityUnavailable('Frozen body selected another parent grant')
    else:raise AuthorityUnavailable('Frozen body has no fixed original shape')


def require_frozen_joint_point_v3(r,request):
    from .natural_producer_qualification_v1 import _HOST_ATTACHMENT_SHAPES_V3
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    state=require_frozen_joint_source_v3(r);table,columns,key_columns,key=request
    if len(key)!=len(key_columns):raise AuthorityUnavailable('Frozen point requires its exact full key')
    if require_beta1_source_control_point_v3(r,request):return
    d12=(table=='graph_d12_domain_candidates_v1'and key_columns==('bot','persona','candidate_ref')and columns in {('candidate_json','candidate_sha256'),('domain','field_input_digest','proposal_schema_hash','candidate_digest','candidate_json','candidate_sha256')}and key[-1]in state.d12_candidate_refs)
    if request[:3]not in _HOST_ATTACHMENT_SHAPES_V3 and not d12 and not(table in {'graph_atoms','graph_history'}and set(columns)<=({'revision','value','valid'}if table=='graph_atoms'else{'event_id','value','valid','event_bot','event_persona','event_session','dependencies'})):
        raise AuthorityUnavailable('Frozen point is not an installed exact original shape')
    if table in {'graph_atoms','graph_history'}:
        if NamespaceId.from_key(AtomKey.from_token(key[0]))!=r.namespace:raise AuthorityUnavailable('Frozen point crossed actual namespace')
    elif table not in {'runtime_budget_grants','runtime_budget_leases','runtime_budget_debt_blocks','runtime_jobs','runtime_resource_quotes'}and tuple(key[:2])!=r.namespace.as_tuple:
        raise AuthorityUnavailable('Frozen point crossed actual namespace')
    require_frozen_joint_body_v3(r,table,key)


def register_frozen_joint_write_v3(inputs,scope,current_owner):
    r=inputs.owner;state=require_frozen_joint_source_v3(r)
    if not r.inputs_sealed or not r.read_finished or scope.operation!='write'or scope.namespace!=r.namespace or current_owner is not r.owner_binding or state.permission is None:
        raise AuthorityUnavailable('Frozen WRITE requires its actual sealed same-Work Owner/Source inputs')
    _WRITES[r]=(inputs,scope,current_owner,state.identity,state.permission)


def require_frozen_joint_write_v3(r):
    state=require_frozen_joint_source_v3(r);record=_WRITES.get(r)
    if record is None or record[0].owner is not r or record[2]is not r.owner_binding or record[3:]!=(state.identity,state.permission)or not r.inputs_sealed or not r.read_finished or not r.business_started:
        raise AuthorityUnavailable('Frozen Source permission lost its actual original WRITE binder')
    r.require_current();return record


def release_frozen_joint_source_v3(r):
    state=_STATES.pop(r,None);_WRITES.pop(r,None)
    if state is not None:state.tasks.clear();state.permission=state.body=None


def _active(db):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    if r is None or r.operation_kind!=OPERATION or not is_frozen_joint_artifact_request_v3(r.request):return None
    require_frozen_joint_source_v3(r);return r


def record_frozen_joint_scheme_head_v3(db,namespace,head,revision):
    r=_active(db)
    if r is None:return
    from ..domains.d12.types import active_scheme_head_key
    state=require_frozen_joint_source_v3(r)
    if namespace!=r.namespace or state.permission is None or not 1<=revision<=r.heads[active_scheme_head_key(namespace).token][0]:
        raise AuthorityUnavailable('Frozen Context ancestry lacks its actual Source/current scheme scope')
    state.permission.require_for_v3(r);state.d12_digests.add(head.compiled_digest)


def read_frozen_joint_compilation_v3(db,namespace,digest):
    r=_active(db)
    if r is None:return False,None
    from .current_method_learning_read_v3 import _need_method_input
    state=require_frozen_joint_source_v3(r)
    if namespace!=r.namespace or digest not in state.d12_digests:raise AuthorityUnavailable('Frozen Context compilation is outside the actual selected ancestry')
    if digest not in state.d12_compilations:_need_method_input(r,('frozen_joint_d12',digest))
    return True,state.d12_compilations[digest]


class _FrozenD12Task:
    def __init__(self,r,digest):
        state=require_frozen_joint_source_v3(r)
        if state.permission is None or digest not in state.d12_digests:raise AuthorityUnavailable('Frozen Context Original requires current Source ALL and actual scheme ancestry')
        self.reader,self.digest,self.complete=r,digest,False
        self.header=self.sha=self.column=None;self.phase='header'
    def advance(self,meter):
        from .scheme_original_store_v1 import CompilationOriginalV1,_compiled,_compilation_binding,_sha
        r=self.reader;state=require_frozen_joint_source_v3(r);state.permission.require_for_v3(r)
        if self.complete:return True
        key=(*r.namespace.as_tuple,self.digest)
        if self.phase=='header':
            self.header=_runtime_bounded_fixed_row_v3(r.db,meter,'graph_d12_compilation_operations_v1',
                ('operation_id','source_input_digest','budget_receipt_digest','binding_digest'),
                'bot=? AND persona=? AND compiled_digest=? ORDER BY operation_id',key)
            row=_runtime_bounded_fixed_row_v3(r.db,meter,'graph_d12_compilation_originals_v1',('original_sha256',),
                'bot=? AND persona=? AND compiled_digest=?',key)
            if self.header is None or row is None:raise AuthorityUnavailable('Frozen Context actual compilation Original is absent')
            self.sha=row[0];self.column=_MetadataColumn(r,table='graph_d12_compilation_originals_v1',column='original_json',key_columns=('bot','persona','compiled_digest'),key=key)
            self.phase='locator';return False
        if not self.column.advance(meter):return False
        raw=self.column.require_v3(r)
        if self.phase=='locator':
            if not _refs(raw)<=set(state.permission.source_refs):raise AuthorityUnavailable('Frozen Context Original introduced an unqualified Source')
            self.column=DispatchOriginalJSONReadV3(r,table='graph_d12_compilation_originals_v1',column='original_json',key_columns=('bot','persona','compiled_digest'),key=key)
            self.phase='body';return False
        encoded=canonical_serialize(raw)
        original=CompilationOriginalV1(self.header[0],_compiled(encoded),self.header[1],self.header[2])
        if _sha(encoded)!=self.sha or original.compiled.namespace!=r.namespace or original.compiled.compiled_digest!=self.digest or _compilation_binding(original)!=self.header[3]:
            raise AuthorityUnavailable('Frozen Context exact compiled Original bytes/binding changed')
        state.d12_compilations[self.digest]=original
        state.d12_candidate_refs.update(receipt.candidate_ref for receipt in original.compiled.domain_receipts if receipt.domain=='d03')
        self.complete=True;return True


def create_frozen_joint_d12_task_v3(r,digest):
    state=require_frozen_joint_source_v3(r)
    task=state.d12_tasks.get(digest)
    if task is None:task=_FrozenD12Task(r,digest);state.d12_tasks[digest]=task
    return task
