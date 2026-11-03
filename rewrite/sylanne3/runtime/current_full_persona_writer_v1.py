"""Same-Method full Persona writer: metadata, current Source groups, exact EOF, local copy."""
from contextlib import contextmanager
from dataclasses import dataclass,asdict
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,GraphAtom,GraphSnapshot,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3

_KEY=object()
_STATES=WeakKeyDictionary()
_OWNERS=WeakKeyDictionary()
_QUALIFIED=WeakKeyDictionary()
_ADAPTERS=WeakKeyDictionary()
_METADATA=WeakKeyDictionary()
_FRAME_READSETS_V1={}
_PRODUCER_PROFILE='full_persona_writer_producer_metadata_v1'
_SIGNED_PROFILE='full_persona_writer_signed_metadata_v1'
_LIFE_PROFILE='full_persona_writer_life_metadata_v1'


def _actual_reader_v1(reader):
    from .current_method_learning_read_v3 import (require_actual_method_learning_attachment_owner_v3,
        _FULL_PERSONA_WRITER_METHOD_OPERATIONS_V1)
    from .domain_production_registry_v1 import installed_operation_v1
    r=require_actual_method_learning_attachment_owner_v3(reader,db=reader.db)
    descriptor=installed_operation_v1(r.operation_kind)
    if(r.operation_kind not in _FULL_PERSONA_WRITER_METHOD_OPERATIONS_V1
            or descriptor.domain!='d01' or type(r.request)is not descriptor.request_type
            or r.fence.scope.operation!='read' or r.fence.scope.namespace!=r.namespace):
        raise AuthorityUnavailable('full Persona writer requires its exact actual D01 Method request/READ')
    return r


def _identity_v1(reader):
    return(reader.work,reader.operation,reader.fence,reader.namespace,reader.selection_digest,
        reader.graph_stamp,reader.authority_epochs,reader.owner_binding,reader.owner_guard,
        reader.operation_kind,reader.operation_id,reader.request_digest,reader.request,
        reader.operation.deadline_utc)


class _FullPersonaWriterOriginOwnerV1:
    def __init__(self,key,state):
        if key is not _KEY:raise TypeError('private full writer metadata issuer required')
        r=_actual_reader_v1(state.reader)
        self.state,self.reader,self.db,self.namespace,self.operation=state,r,r.db,r.namespace,r.operation
        self.origin_signer=r.graph._GraphCoordinator__d11_issuer._signer
        self.origin_history,self.origin_support_readsets,self.origin_columns={},{},[]
        self.fixed_rows,self.selected_fixed={},set()
        self.selected_columns=set();self.fixed_tasks={};self.column_tasks={}
        _OWNERS[self]=state
    def require_current_v1(self):
        if _OWNERS.get(self)is not self.state or _STATES.get(self.reader)is not self.state:
            raise AuthorityUnavailable('full writer metadata owner is not the actual private Work')
        self.state.require_current_v1(self.reader);return self
    @contextmanager
    def quantum_v3(self):
        self.require_current_v1()
        with runtime_storage_quantum_v3(self.db)as meter:
            self.reader.require_current(meter=meter);yield meter
    def fixed_v1(self,table,columns,where,args):
        return read_full_persona_writer_fixed_metadata_v1(self,table,columns,where,args)
    def column_v1(self,table,column,key_columns,key,profile,*,cell_id=None,signed_header=None):
        return read_full_persona_writer_metadata_column_v1(self,table=table,column=column,
            key_columns=key_columns,key=key,profile=profile,cell_id=cell_id,signed_header=signed_header)
    def producer_v1(self,operation_id):
        from .domain_production_originals_v1 import _receipt
        row=self.fixed_v1('graph_domain_production_originals_v1',
            ('domain','operation_kind','original_digest','bundle_digest','receipt_digest'),
            'bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,operation_id))
        from .domain_production_registry_v1 import installed_operation_v1
        if row is None or installed_operation_v1(row[1]).domain!=row[0]:
            raise AuthorityUnavailable('full writer metadata has no actual registered producer')
        column=self.column_v1('graph_domain_production_originals_v1','original_payload_json',
            ('bot','persona','operation_id'),(*self.namespace.as_tuple,operation_id),_PRODUCER_PROFILE)
        receipt=_receipt(self.column_v1('graph_domain_production_originals_v1','receipt_json',
            ('bot','persona','operation_id'),(*self.namespace.as_tuple,operation_id),'activation').metadata)
        value=column.metadata
        if(column.semantic_digest!=row[2] or canonical_digest(receipt)!=row[4]
                or receipt.operation_id!=operation_id or receipt.status!='committed'
                or receipt.operation_digest!=row[3] or value['identity']['operation_id']!=operation_id
                or value['namespace']!=asdict(self.namespace) or value['coverage']!='complete'
                or value['schema']!=row[0]+'.current-'+row[1]+'.v1' or value['missing_inputs']
                or value['continuation_ref']is not None):
            raise AuthorityUnavailable('full writer producer metadata differs from its exact committed original')
        return row,column,receipt
    def signed_v1(self,ref,expected_kinds,observed):
        from .d01_ordinary_origin_read_v3 import _signed,_references
        return _signed(self,ref,_SIGNED_PROFILE,frozenset(expected_kinds),_references(observed))


def is_current_full_persona_writer_origin_owner_v1(owner):
    return type(owner)is _FullPersonaWriterOriginOwnerV1 and owner in _OWNERS


def require_current_full_persona_writer_origin_owner_v1(owner):
    if not is_current_full_persona_writer_origin_owner_v1(owner):
        raise AuthorityUnavailable('actual same-Method full writer metadata owner required')
    return owner.require_current_v1()


def read_full_persona_writer_fixed_metadata_v1(owner,table,columns,where,args):
    require_current_full_persona_writer_origin_owner_v1(owner)
    from .role_control_lineage_metadata_v4 import _TABLE_COLUMNS,_FIXED_WHERE
    extra={'graph_d01_production_inputs_v1':frozenset({'kind','producing_operation_id','payload_digest','signature'}),
        'graph_d11_life_originals_v1':frozenset({'producing_operation_id','payload_digest','signature'})}
    allowed=_TABLE_COLUMNS.get(table,extra.get(table,()))
    wheres=_FIXED_WHERE.get(table,())
    if table=='graph_d01_production_inputs_v1':wheres=('bot=? AND persona=? AND original_ref=?',)
    if table=='graph_d11_life_originals_v1':wheres=('bot=? AND persona=? AND kind=? AND original_ref=?',)
    if not columns or not set(columns)<=set(allowed) or where not in wheres:
        raise AuthorityUnavailable('full writer fixed metadata escaped its registered columns/selector')
    if table=='graph_history'and where.startswith('token=?'):
        if NamespaceId.from_key(AtomKey.from_token(args[0]))!=owner.namespace:
            raise AuthorityUnavailable('full writer fixed metadata crossed namespace')
    elif tuple(args[:2])!=owner.namespace.as_tuple:
        raise AuthorityUnavailable('full writer original selector crossed namespace')
    identity=('fixed',table,tuple(columns),where,tuple(args));owner.selected_fixed.add(identity)
    if identity not in owner.fixed_rows:_need_v1(owner,identity)
    return owner.fixed_rows[identity]


def read_full_persona_writer_metadata_column_v1(owner,*,table,column,key_columns,key,profile,cell_id=None,signed_header=None):
    require_current_full_persona_writer_origin_owner_v1(owner)
    from .role_control_lineage_metadata_v4 import _COLUMN_PROFILES
    allowed=_COLUMN_PROFILES.get((table,column),())
    if (table,column)==('graph_domain_production_originals_v1','original_payload_json'):
        allowed=(*allowed,'adoption',_PRODUCER_PROFILE)
    if table=='graph_d01_production_inputs_v1':
        allowed=(_SIGNED_PROFILE,'proposal','trial','counter','general_intent','general_start','single_event_policy','single_event_input')if column=='payload_json'else('activation',)if column=='source_refs_json'else()
        if column=='payload_json'and signed_header is None:
            raise AuthorityUnavailable('full writer signed original requires its actual header')
    if table=='graph_history':allowed=(*allowed,'revision','growth','single_event_adoption','single_event_review',_SIGNED_PROFILE)
    if(table,column)==('graph_d11_life_originals_v1','payload_json'):allowed=(_LIFE_PROFILE,)
    if profile not in allowed:raise AuthorityUnavailable('full writer metadata column has no closed profile')
    if table=='graph_history':
        if tuple(key_columns)!=('token','revision')or type(key[1])is not int or key[1]<1 or NamespaceId.from_key(AtomKey.from_token(key[0]))!=owner.namespace:
            raise AuthorityUnavailable('full writer history crossed actual positive namespace/version')
    elif tuple(key[:2])!=owner.namespace.as_tuple:
        raise AuthorityUnavailable('full writer original column crossed namespace')
    identity=('column',table,column,tuple(key_columns),tuple(key),profile,cell_id,signed_header)
    owner.selected_columns.add(identity);task=owner.column_tasks.get(identity)
    if task is None or not task.complete:_need_v1(owner,identity)
    return task.column.require_v3()


def _need_v1(owner,identity):
    from .current_method_learning_read_v3 import _need_method_input
    _need_method_input(owner.reader,('full_persona_writer_metadata_v1',identity))


class _FullWriterMetadataTaskV1:
    def __init__(self,owner,identity):
        owner.require_current_v1();self.owner,self.identity,self.complete=owner,identity,False
        if identity[0]=='fixed':
            if identity not in owner.selected_fixed:raise AuthorityUnavailable('unselected full writer fixed metadata')
            owner.fixed_tasks[identity]=self
        else:
            if identity not in owner.selected_columns:raise AuthorityUnavailable('unselected full writer original metadata')
            from .d01_ordinary_origin_read_v3 import OrdinaryOriginColumnV3
            _,table,column,key_columns,key,profile,cell_id,signed_header=identity
            self.column=OrdinaryOriginColumnV3(owner,table=table,column=column,key_columns=key_columns,
                key=key,profile=profile,cell_id=cell_id,signed_header=signed_header)
            owner.column_tasks[identity]=self
    def advance(self,meter):
        owner=self.owner;owner.require_current_v1();owner.reader.require_current(meter=meter)
        if self.complete:return True
        if self.identity[0]=='fixed':
            _,table,columns,where,args=self.identity
            row=meter.read_fixed_row(owner.db,table,columns,where,args)
            from .source_correction_read_v3 import _heap
            owner.operation.retain(_heap((self.identity,row))+1024)
            owner.fixed_rows[self.identity]=row;self.complete=True
        else:
            self.complete=self.column.advance(meter)
            if self.complete:owner.origin_columns.append(self.column)
        return self.complete


def create_current_full_persona_writer_metadata_task_v1(reader,identity):
    state=require_current_full_persona_writer_metadata_state_v1(reader);owner=state.origin
    task=(owner.fixed_tasks if identity[0]=='fixed'else owner.column_tasks).get(identity)
    return task if task is not None else _FullWriterMetadataTaskV1(owner,identity)


_METADATA_KEYS=frozenset({'schema','namespace','bot_id','persona_id','bot','persona','subject','$type','identity','operation_id','activity_id','effect_id',
    'authority','actor','issuer_domain','purpose','audience','activation_generation','owner_guard','now_utc','coverage',
    'missing_inputs','continuation_ref','read_versions','observed_originals','original_ref','original_digest','original_kind',
    'kind','request','provenance','writes','key','owner','type_name','name','revision','dependencies','token','plan_id',
    'head_id','plan_version','version','authored','blocks','block_id','plasticity','candidate','typed_writes','growth',
    'general_growth','originals','growth_proposal','growth_proposal_ref','base_head','target_block','target_block_ids',
    'expected_plan_head','expected_persona_head_id','trigger_original_ref','trial_original_refs','counterevidence_query_ref',
    'general_growth_intent_ref','input_ref','policy_ref','plasticity_policy_ref','continuity_interpretation_ref',
    'method_outcome_review_ref','method_outcome_review_digest','review_ref','trial_ref','protocol_ref','evaluation_refs',
    'conditioned_candidate_ref','conditioned_candidate_digest','conditioned_review_ref','conditioned_source_roots',
    'conditioned_original_deadline_utc','rollback','candidate_method_trials','general_required_trials','source_refs',
    'evidence_source_refs','counterevidence_source_refs','support_original_refs','scope_refs','exclusion_refs','required_trial_refs',
    'trial_start_ref','trial_start_refs','settled_outcome_refs','source_families','counterevidence_checked','change_kind',
    'evidence_reality','completed','coverage_complete','query_scope_ref','single_event_adoption','single_event_review',
    'adoption_ref','adoption_id','target_head','growth_proposal_original','policy_original','input_original','claim_digest',
    'replacement_claim_digest','policy_digest','producer_binding_digest','authorization_revision','grant_id','grant_revision',
    'principal','state','qualification','missing','runtime_identity','valid_from','valid_until','adopt_before','revision_kind',
    'previous_revision','changed_from_claim_digest','counterevidence_original_ref','continuity_original_ref',
    'protocol_id','policy_id','required_project_trials','minimum_blind_reviewers','minimum_rework_reduction_ppm',
    'maximum_time_regression_ppm','observer_policy_ref','observer_policy_digest','trial_id','gp1_interpretation_ref',
    'base_persona_head','goal_refs','status','review_id','counter_interpretation_refs','evidence_families','missing_items',
    'evaluation_id','project_ref','milestone_ref','milestone_digest','artifact_ref','artifact_version','artifact_digest',
    'baseline_milestone_ref','baseline_milestone_digest','baseline_artifact_ref','baseline_artifact_version',
    'baseline_artifact_digest','experiment_original_ref','experiment_original_digest','measurement_original_ref',
    'measurement_original_digest','terminal_provenance','binding','prepared_original_ref','prepare_operation_id',
    'execution_id','job_id','call_id','job_cancel_epoch','parent_budget_lease_ref','deadline_utc',
    'support_source_refs','activation_operation_id','activation_receipt','activation_event_digest','write_versions',
    'operation_digest','commit_seq','read_versions','invalidated_epochs','ledger_refs','outbox_refs',
    'terms','registration_operation_id','expected_persona_head','persona_head_id','target_kind','base_claim_digest'})


def full_persona_writer_metadata_retains_path_v1(profile,path):
    if profile==_LIFE_PROFILE:
        from .life_prepared_source_metadata_v3 import retain_life_prepared_locator_path_v3
        return retain_life_prepared_locator_path_v3(path)
    if profile not in {_PRODUCER_PROFILE,_SIGNED_PROFILE}:return None
    if not path:return True
    if any(part in {'claim','replacement_claim','values','literal','text','notes','rationale','proposition','adopted_claim'}for part in path):return False
    if profile==_PRODUCER_PROFILE and path[0]=='writes':
        return len(path)<3 or path[2]in {'key','dependencies'}
    if 'value'in path:return False
    if profile==_SIGNED_PROFILE:
        from .conditioned_producer_source_metadata_v3 import CONDITIONED_LOCATOR_FIELDS_V3
        if path[0]in CONDITIONED_LOCATOR_FIELDS_V3:return True
    return all(type(part)is int or part in _METADATA_KEYS for part in path)


def full_persona_writer_metadata_commits_path_v1(profile,path):
    if profile not in {_PRODUCER_PROFILE,_SIGNED_PROFILE,_LIFE_PROFILE}:return None
    if not path or path[-1]in {'claim','replacement_claim','values'}:return True
    if len(path)==3 and path[0]=='writes'and path[2]=='value':return True
    if path in {('base_head',),('successor_head',),('terms',),('request','terms')}:return True
    return path in {('writes',),('provenance','candidate','revision'),('provenance','growth','candidate','revision')}


def require_full_persona_writer_signature_column_v1(column,*,signer,kind,signature=None,verifier=None,complete=False):
    if not is_current_full_persona_writer_origin_owner_v1(column.owner)or column.profile!=_SIGNED_PROFILE:return None
    from .d01_ordinary_origin_read_v3 import OrdinaryOriginColumnV3
    from .d01_production_operations_v1 import SIGN_KIND
    owner=require_current_full_persona_writer_origin_owner_v1(column.owner)
    if(type(column)is not OrdinaryOriginColumnV3 or column.table!='graph_d01_production_inputs_v1'
            or column.column!='payload_json' or column.key_columns!=('bot','persona','original_ref')
            or column.key[:2]!=owner.namespace.as_tuple or column.signed_header is None
            or kind!=SIGN_KIND or signer is not owner.origin_signer):
        raise AuthorityUnavailable('full writer signature column differs from its exact selected actual original')
    if complete and(not column.complete or signature!=column.signed_header[3]or verifier is not column.verifier):
        raise AuthorityUnavailable('full writer signature has no complete actual original EOF')
    return column.require_v3()


class _FullPersonaWriterMetadataV1:
    def __init__(self,key,reader,request,head):
        if key is not _KEY:raise TypeError('private full writer state issuer required')
        r=_actual_reader_v1(reader)
        if request is not r.request or type(head)is not GraphVersion or NamespaceId.from_key(head.key)!=r.namespace or head.key.type_name!='d01.persona_plan.v1':
            raise AuthorityUnavailable('full writer needs its exact Method request and actual expected plan GraphVersion')
        self.reader,self.identity,self.request,self.expected_head=r,_identity_v1(r),request,head
        self.current=self.initial=self.control=None;self.history=();self.blocks=();self.targets=()
        self.groups=();self.base_roots=();self.preserved_dependencies=();self.copy_evidence=()
        self.complete=False;self.source_permission=None;self.body_admitted=False;self.qualification=None
        self.base_plan=self.bound_plan=None
        self.bound_frames=set()
        self.origin=None
    def _metadata_identity_v1(self):
        return(self.expected_head,self.current,self.initial,self.control,self.history,self.blocks,self.targets,
            self.groups,self.base_roots,self.preserved_dependencies,self.copy_evidence,self.base_plan,self.bound_plan)
    def require_current_v1(self,reader):
        if _STATES.get(reader)is not self or reader is not self.reader or _identity_v1(reader)!=self.identity:
            raise AuthorityUnavailable('full writer changed its actual Method/Owner/selection/request/deadline')
        _actual_reader_v1(reader)
        if self.complete:
            if _METADATA.get(self)!=self._metadata_identity_v1():
                raise AuthorityUnavailable('full writer private complete metadata selection changed')
            from .current_method_learning_read_v3 import require_current_full_persona_writer_role_control_v1
            actual=require_current_full_persona_writer_role_control_v1(reader,self)
            if(actual.persona_head_version!=self.current.plan_ref or actual.activation_version!=self.current.activation_ref
                    or actual.owner_grant_version!=self.control[2] or actual.head_id!=self.current.head_id):
                raise AuthorityUnavailable('full writer current control metadata changed')
        return self


def require_full_persona_writer_control_check_v1(state,reader):
    if(type(state)is not _FullPersonaWriterMetadataV1 or _STATES.get(reader)is not state
            or state.reader is not reader or state.identity!=_identity_v1(reader)
            or state.complete and _METADATA.get(state)!=state._metadata_identity_v1()):
        raise AuthorityUnavailable('full writer role-control observer is not the actual private same-Work metadata state')
    return state


def require_current_full_persona_writer_metadata_state_v1(reader):
    state=_STATES.get(reader)
    if state is None:raise AuthorityUnavailable('actual full Persona writer metadata state is unavailable')
    return state.require_current_v1(reader)


def prepare_current_full_persona_writer_metadata_v1(reader,request,head):
    state=_STATES.get(reader)
    if state is None:
        state=_FullPersonaWriterMetadataV1(_KEY,reader,request,head);_STATES[reader]=state
        state.origin=_FullPersonaWriterOriginOwnerV1(_KEY,state)
    state.require_current_v1(reader)
    if request is not state.request or head!=state.expected_head:
        raise AuthorityUnavailable('full writer preparation changed its original request/head')
    if state.complete:return state
    _prepare_metadata_v1(state)
    return state


def bind_current_full_persona_writer_read_plan_v1(reader,plan):
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    state=require_current_full_persona_writer_metadata_state_v1(reader)
    if(type(plan)is not ProductionReadPlanV1 or reader.selected_plan is not plan or state.source_permission is not None
            or state.body_admitted or state.base_plan is not None and state.base_plan is not plan):
        raise AuthorityUnavailable('full writer base read plan is not the original actual selected metadata recipe')
    state.base_plan=plan;state.bound_plan=plan;state.base_roots=tuple(plan.source_roots)
    groups=[(reader.authority.purpose,tuple(reader.authority.audience),state.base_roots)]
    for evidence in state.copy_evidence:groups.extend(evidence.groups)
    merged={}
    for purpose,audiences,roots in groups:merged.setdefault((purpose,tuple(audiences)),set()).update(roots)
    state.groups=tuple((p,a,tuple(sorted(roots)))for(p,a),roots in sorted(merged.items()))
    if len({ref for _,_,roots in state.groups for ref in roots})>32:
        raise AuthorityUnavailable('full writer actual direct Source union exceeds 32 roots')
    _METADATA[state]=state._metadata_identity_v1()
    return state


def bind_current_full_persona_writer_augmented_plan_v1(reader,base_plan,plan):
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    state=require_current_full_persona_writer_metadata_state_v1(reader)
    roots={ref for _,_,values in state.groups for ref in values}
    if(type(plan)is not ProductionReadPlanV1 or state.base_plan is not base_plan or reader.selected_plan is not plan
            or state.source_permission is not None or state.body_admitted or set(plan.source_roots)!=roots
            or plan.fixed_type_ids!=base_plan.fixed_type_ids or plan.required_original_refs!=base_plan.required_original_refs
            or set(plan.exact_keys)!={*base_plan.exact_keys,*(v.key for v in state.control)}):
        raise AuthorityUnavailable('full writer augmented read plan differs from its actual frozen base/Source/control union')
    state.bound_plan=plan;_METADATA[state]=state._metadata_identity_v1();return state


def current_full_persona_writer_base_source_roots_v1(reader):
    state=_STATES.get(reader)
    if state is None:return None
    state.require_current_v1(reader)
    if state.base_plan is None:raise AuthorityUnavailable('full writer actual base Source recipe is not bound')
    return tuple(state.base_plan.source_roots)


def _prepare_metadata_v1(state):
    from .persona_growth_birth_v1 import current_persona_birth_control_v1
    from .d01_ordinary_origin_read_v3 import _initial,_fixed
    from .d01_ordinary_origin_v3 import validate_ordinary_initial_v3
    from .role_control_lineage_metadata_v4 import _transition_v4
    r=state.reader;owner=state.origin
    control=current_persona_birth_control_v1(r.db,namespace=r.namespace)
    if control.persona_head_version!=state.expected_head:raise AuthorityUnavailable('full writer expected current plan changed')
    initial=_initial(owner);previous=validate_ordinary_initial_v3(initial)
    last={block.block_id:('initial',initial,previous)for block in previous.blocks};history=[];cursor=previous.plan_ref.revision
    while cursor<state.expected_head.revision:
        row=_fixed(owner,'graph_history',('revision','event_id'),
            'token=? AND revision>? AND revision<=? ORDER BY revision',
            (state.expected_head.key.token,cursor,state.expected_head.revision))
        if row is None:raise AuthorityUnavailable('full writer current plan has missing actual producer history')
        following,transition=_transition_v4(owner,previous,GraphVersion(state.expected_head.key,row[0]),row[1])
        before={block.block_id:block for block in previous.blocks};after={block.block_id:block for block in following.blocks}
        if set(before)!=set(after):raise AuthorityUnavailable('full writer actual history changed the initialized block census')
        for block_id,block in after.items():
            if block!=before[block_id]:last[block_id]=(transition[0],row[1],following)
        history.append((previous,following,transition));previous=following;cursor=row[0]
    if(previous.plan_ref!=control.persona_head_version or previous.activation_ref!=control.activation_version
            or previous.head_id!=control.head_id):raise AuthorityUnavailable('full writer metadata did not reach its exact current controls')
    state.initial,state.current,state.history,state.blocks=initial,previous,tuple(history),previous.blocks
    state.control=(control.activation_version,control.persona_head_version,control.owner_grant_version)
    state.base_roots=tuple(sorted(set(()if r.selected_plan is None else r.selected_plan.source_roots)))
    groups=[(r.authority.purpose,tuple(r.authority.audience),state.base_roots)];evidence=[];deps=[]
    for block in previous.blocks:
        producer=last[block.block_id]
        from .full_persona_semantic_writer_metadata_v1 import prepare_full_persona_semantic_copy_metadata_v1
        from .full_persona_method_writer_metadata_v1 import prepare_full_persona_method_copy_metadata_v1
        if block.claim_protocol in {'d01.semantic-identity-revision.v3',None}and block.kind=='semantic_identity':
            selected=prepare_full_persona_semantic_copy_metadata_v1(state,block,producer)
        elif block.claim_protocol=='d01.method-policy.v1':
            selected=prepare_full_persona_method_copy_metadata_v1(state,block,producer)
        elif block.claim_protocol in {'d01.conditioned-capability-revision.v1','d01.conditioned-strategy-revision.v1'}:
            from .current_conditioned_self_read_v3 import prepare_full_persona_conditioned_copy_metadata_v1
            selected=prepare_full_persona_conditioned_copy_metadata_v1(state,block,producer)
        elif block.claim_protocol is None:
            selected=_ordinary_copy_v1(state,block,producer)
        else:raise AuthorityUnavailable('full writer has an unregistered dedicated claim protocol')
        evidence.append(selected);groups.extend(selected.groups);deps.extend(selected.dependencies)
    merged={}
    for purpose,audiences,roots in groups:
        key=(purpose,tuple(audiences));merged.setdefault(key,set()).update(roots)
    state.groups=tuple((p,a,tuple(sorted(roots)))for(p,a),roots in sorted(merged.items()))
    roots={ref for _,_,values in state.groups for ref in values}
    if len(roots)>32:raise AuthorityUnavailable('full writer actual direct Source union exceeds the existing 32 roots')
    for ref in roots:
        key=AtomKey.from_token(ref)
        if key.type_name!='memory.source'or NamespaceId.from_key(key)!=r.namespace:
            raise AuthorityUnavailable('full writer Source groups crossed actual namespace/family')
    state.copy_evidence=tuple(evidence);state.preserved_dependencies=tuple(dict.fromkeys(deps))
    state.targets=_targets_v1(state);state.complete=True
    _METADATA[state]=state._metadata_identity_v1()
    from .source_correction_read_v3 import _heap
    r.operation.retain(_heap((state.history,state.copy_evidence,state.groups,state.preserved_dependencies))+8192)


def _ordinary_copy_v1(state,block,producer):
    if producer[0]=='initial':return issue_full_persona_copy_metadata_v1(state,block,producer,(),())
    kind,operation,_head=producer
    if kind not in {'adopt_growth','adopt_general_growth_v1','adopt_single_event_growth_v1','adopt_ordinary_deep_growth_v1'}:
        raise AuthorityUnavailable('ordinary full writer block has an unregistered actual producing transition')
    from .full_persona_method_writer_metadata_v1 import prepare_full_persona_ordinary_copy_metadata_v1
    return prepare_full_persona_ordinary_copy_metadata_v1(state,block,producer)


@dataclass(frozen=True,eq=False)
class _FullPersonaCopyMetadataV1:
    state:object
    block:object
    producer:tuple
    groups:tuple
    dependencies:tuple
    original_digest:str
    def require_v1(self,state):
        if _ADAPTERS.get(self)!=(state,self.block,self.producer,self.groups,self.dependencies,self.original_digest):
            raise AuthorityUnavailable('full writer dedicated block has no actual private metadata qualification')
        state.require_current_v1(state.reader);return self


def issue_full_persona_copy_metadata_v1(state,block,producer,groups,dependencies,original_digest=None):
    state.require_current_v1(state.reader)
    if block not in state.current.blocks:raise AuthorityUnavailable('full writer copy metadata selected a foreign current block')
    digest=canonical_digest(producer[1])if original_digest is None else original_digest
    proof=_FullPersonaCopyMetadataV1(state,block,producer,tuple(groups),tuple(dependencies),digest)
    _ADAPTERS[proof]=(state,block,producer,proof.groups,proof.dependencies,digest);return proof


def copy_metadata_from_actual_producer_v1(state,block,producer):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    kind,operation,head=producer;row,column,receipt=state.origin.producer_v1(operation)
    if row[1]!=kind or head.plan_ref not in receipt.write_versions:
        raise AuthorityUnavailable('full writer block producer has another actual plan/operation')
    writes=column.metadata['writes'];matching=[]
    for index,write in enumerate(writes):
        if decode_typed_production_value_v1(write['key'],AtomKey)==head.plan_ref.key:matching.append((index,write))
    if len(matching)!=1:raise AuthorityUnavailable('full writer producer has no unique actual plan write')
    index,write=matching[0]
    if column.commitments[('writes',index,'value')]!=head.plan_value_digest:
        raise AuthorityUnavailable('full writer producer plan write differs from its complete history commitment')
    deps=tuple(decode_typed_production_value_v1(v,AtomKey)for v in write['dependencies'])
    return issue_full_persona_copy_metadata_v1(state,block,producer,(),deps,row[2])


def _targets_v1(state):
    r=state.reader;request=r.request;owner=state.origin
    if r.operation_kind in {'assess_ordinary_continuity_v1','adopt_ordinary_deep_growth_v1'}:
        request=request.growth_request
    if r.operation_kind in {'adopt_growth','freeze_general_growth_intent_v1','register_general_growth_trial_start_v1',
            'derive_general_growth_trial_v1','adopt_general_growth_v1','assess_ordinary_continuity_v1','adopt_ordinary_deep_growth_v1'}:
        row=owner.fixed_v1('graph_d01_production_inputs_v1',('kind','producing_operation_id','payload_digest','signature'),
            'bot=? AND persona=? AND original_ref=?',(*r.namespace.as_tuple,request.growth_proposal_ref))
        if row is None or row[0]!='growth_proposal':raise AuthorityUnavailable('full writer target has no actual signed proposal')
        column=owner.column_v1('graph_d01_production_inputs_v1','payload_json',('bot','persona','original_ref'),
            (*r.namespace.as_tuple,request.growth_proposal_ref),_SIGNED_PROFILE,signed_header=row)
        if not column.signature_verified or column.semantic_digest!=row[2]:raise AuthorityUnavailable('full writer target proposal signature differs')
        value=column.metadata
        if value['base_head']!=state.current.head_id or value['target_block']not in {b.block_id for b in state.current.blocks}:
            raise AuthorityUnavailable('full writer signed target proposal has another actual current base')
        return(value['target_block'],)
    from .full_persona_semantic_writer_metadata_v1 import full_persona_single_event_target_v1
    target=full_persona_single_event_target_v1(state)
    if target is None:
        from .full_persona_method_writer_metadata_v1 import full_persona_method_target_v1
        target=full_persona_method_target_v1(state)
    return()if target is None else(target,)


@dataclass(frozen=True,eq=False)
class CurrentFullPersonaWriterQualificationV1:
    state:object
    plan:object
    plan_ref:object
    whole_value_digest:str
    preserved_dependencies:tuple


def require_current_full_persona_writer_body_v1(reader,plan_ref):
    state=require_current_full_persona_writer_metadata_state_v1(reader)
    if not state.complete or state.bound_plan is not reader.selected_plan or state.base_plan is None or plan_ref!=state.current.plan_ref:
        raise AuthorityUnavailable('full writer Body is not its exact complete current metadata plan')
    from .current_method_learning_read_v3 import require_current_full_persona_writer_source_groups_v1
    permission=require_current_full_persona_writer_source_groups_v1(reader,state.groups)
    permission.require_for_v1(reader,state.groups)
    for evidence in state.copy_evidence:evidence.require_v1(state)
    state.source_permission=permission;state.body_admitted=True
    return state


def finish_current_full_persona_writer_v1(reader,decoded_plan,EOF):
    from .current_method_learning_read_v3 import MethodJSONColumnV3
    from ..domains.d01 import PersonaPlan
    state=require_current_full_persona_writer_body_v1(reader,require_current_full_persona_writer_metadata_state_v1(reader).current.plan_ref)
    if(type(EOF)is not MethodJSONColumnV3 or EOF.owner is not reader or EOF.general_metadata_profile is not None
            or not EOF.complete or EOF.table not in {'graph_atoms','graph_history'}or EOF.column!='value'
            or EOF.key[0]!=state.current.plan_ref.key.token or type(decoded_plan)is not PersonaPlan):
        raise AuthorityUnavailable('full writer final qualification requires its actual full Method column EOF/PersonaPlan')
    EOF._actual()
    if EOF.table=='graph_history'and EOF.key!=(state.current.plan_ref.key.token,state.current.plan_ref.revision):
        raise AuthorityUnavailable('full writer historical Body selected another actual version')
    if(EOF.canonical_digest!=state.current.plan_value_digest or canonical_digest(decoded_plan)!=state.current.plan_value_digest
            or decoded_plan.head_id!=state.current.head_id or decoded_plan.namespace!=reader.namespace
            or canonical_digest(decoded_plan.values)!=state.current.values_digest):
        raise AuthorityUnavailable('full writer full Plan EOF/value/values differs from its complete metadata commitment')
    expected={b.block_id:b for b in state.current.blocks}
    if len(decoded_plan.blocks)!=len(expected):raise AuthorityUnavailable('full writer Plan changed its complete block census')
    for block in decoded_plan.blocks:
        old=expected.get(block.block_id)
        if old is None or(block.kind,block.plasticity,canonical_digest(block.claim))!=(old.kind,old.plasticity,old.claim_digest):
            raise AuthorityUnavailable('full writer selected Plan block differs from its actual metadata EOF')
    evidence_by_id={value.block.block_id:value for value in state.copy_evidence}
    for block in decoded_plan.blocks:
        evidence=evidence_by_id[block.block_id]
        if evidence.block.kind=='semantic_identity':
            from .full_persona_semantic_writer_metadata_v1 import finish_full_persona_semantic_copy_v1
            finish_full_persona_semantic_copy_v1(evidence,block.claim)
        elif evidence.block.claim_protocol=='d01.method-policy.v1':
            from .full_persona_method_writer_metadata_v1 import finish_full_persona_method_copy_v1
            finish_full_persona_method_copy_v1(evidence,block.claim)
        elif evidence.block.claim_protocol in {'d01.conditioned-capability-revision.v1','d01.conditioned-strategy-revision.v1'}:
            from .current_conditioned_self_read_v3 import finish_full_persona_conditioned_copy_v1
            finish_full_persona_conditioned_copy_v1(evidence,block.claim)
    proof=CurrentFullPersonaWriterQualificationV1(state,decoded_plan,state.current.plan_ref,state.current.plan_value_digest,state.preserved_dependencies)
    _QUALIFIED[proof]=(state,decoded_plan,proof.plan_ref,proof.whole_value_digest,proof.preserved_dependencies)
    state.qualification=proof;return proof


def current_full_persona_writer_v1(reader):
    state=require_current_full_persona_writer_metadata_state_v1(reader)
    if state.qualification is None:raise AuthorityUnavailable('actual full Persona writer qualification is unavailable')
    return state.qualification


def require_current_full_persona_writer_v1(proof,reader,frame,plan_ref,operation_kind,request):
    if(type(proof)is not CurrentFullPersonaWriterQualificationV1 or _QUALIFIED.get(proof)!=(proof.state,proof.plan,proof.plan_ref,proof.whole_value_digest,proof.preserved_dependencies)):
        raise AuthorityUnavailable('actual private full Persona writer final qualification required')
    state=require_current_full_persona_writer_body_v1(reader,plan_ref)
    from .domain_production_contracts_v1 import CurrentOperationFrameV1
    if(state is not proof.state or type(frame)is not CurrentOperationFrameV1 or frame!=CurrentOperationFrameV1(*reader.frame_fields)
            or operation_kind!=reader.operation_kind or request is not reader.request):
        raise AuthorityUnavailable('full Persona writer final consumer changed its actual frame/request/operation')
    _bind_full_persona_writer_frame_v1(proof,frame)
    return proof.plan


def _full_persona_writer_metadata_versions_v1(state,permission):
    reader=state.reader;preserved=[]
    for key in state.preserved_dependencies:
        if type(key)is not AtomKey or NamespaceId.from_key(key)!=reader.namespace:
            raise AuthorityUnavailable('full writer preserved support dependency crossed its actual namespace/type')
        reader.store._registry.spec(key.type_name)
        header=reader.heads.get(key.token)
        preserved.append(GraphVersion(key,0 if header is None else header[0]))
    return(*state.control,*permission.head_versions,*preserved)


def _bind_full_persona_writer_frame_v1(proof,frame):
    state=proof.state;permission=state.source_permission
    permission.require_for_v1(state.reader,state.groups)
    versions=tuple(frame.envelope.version_guard.read_versions)
    actual={version.key:version.revision for version in versions}
    if len(actual)!=len(versions)or len(actual)>frame.limits.max_graph_heads:
        raise AuthorityUnavailable('full writer private frame has another actual bounded metadata CAS readset')
    for version in _full_persona_writer_metadata_versions_v1(state,permission):
        if actual.get(version.key)!=version.revision:
            raise AuthorityUnavailable('full writer private frame omitted or changed an actual copy Source/control/support CAS fact')
    identity=id(frame);record=(frame,proof,state,permission,state.identity,versions)
    saved=_FRAME_READSETS_V1.get(identity)
    if saved is not None and saved!=record:
        raise AuthorityUnavailable('full writer exact frame object changed its private qualification binding')
    if saved is None:state.reader.operation.retain(1024)
    _FRAME_READSETS_V1[identity]=record;state.bound_frames.add(identity)


def current_full_persona_writer_frame_read_versions_v1(frame):
    record=_FRAME_READSETS_V1.get(id(frame))
    if record is None:return None
    actual,proof,state,permission,identity,versions=record
    if(actual is not frame or state.identity!=identity or proof.state is not state
            or state.source_permission is not permission):
        raise AuthorityUnavailable('full writer frame readset is not its exact privately bound current frame')
    require_current_full_persona_writer_v1(proof,state.reader,frame,state.current.plan_ref,
        state.reader.operation_kind,state.request)
    if _FRAME_READSETS_V1.get(id(frame))!=record:
        raise AuthorityUnavailable('full writer current frame metadata qualification changed')
    return versions


def require_bound_current_full_persona_writer_v1(db,*,frame,request):
    from .current_method_learning_read_v3 import _method_active
    reader=_method_active(db)
    if reader is None or reader.db is not db:
        raise AuthorityUnavailable('full Persona writer final consumer has no actual same-database Method binding')
    state=require_current_full_persona_writer_metadata_state_v1(reader)
    proof=current_full_persona_writer_v1(reader)
    plan=require_current_full_persona_writer_v1(proof,reader,frame,state.current.plan_ref,
        reader.operation_kind,request)
    return proof,plan


def _require_full_persona_writer_mechanical_candidate_v1(proof,candidate,request):
    from ..domains.d01 import GrowthAdoptionCandidate,PersonaPlan
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(proof)is not CurrentFullPersonaWriterQualificationV1 or proof not in _QUALIFIED:
        raise AuthorityUnavailable('actual full writer qualification required for mechanical candidate')
    state=proof.state;require_current_full_persona_writer_body_v1(state.reader,proof.plan_ref)
    if request is not state.request or type(candidate)is not GrowthAdoptionCandidate:
        raise AuthorityUnavailable('full writer mechanical candidate changed its exact actual request/type')
    writes=tuple(w for w in candidate.typed_writes if w.key.type_name=='d01.persona_plan.v1')
    if len(writes)!=1 or writes[0].key!=proof.plan_ref.key:
        raise AuthorityUnavailable('full writer mechanical candidate changed its actual current Plan key')
    plan=decode_typed_production_value_v1(writes[0].value,PersonaPlan)
    before={b.block_id:b for b in proof.plan.blocks};after={b.block_id:b for b in plan.blocks}
    if(set(before)!=set(after)or plan.namespace!=proof.plan.namespace or plan.plan_id!=proof.plan.plan_id
            or plan.version!=proof.plan.version+1 or plan.values!=proof.plan.values
            or candidate.revision.previous_head!=proof.plan.head_id or candidate.head_id!=plan.head_id
            or tuple(candidate.revision.blocks)!=tuple(plan.blocks)):
        raise AuthorityUnavailable('full writer candidate changed base, block census, values or actual revision')
    if any(after[key]!=value for key,value in before.items()if key not in state.targets):
        raise AuthorityUnavailable('full writer candidate changed an unselected preserved block')
    if not set(proof.preserved_dependencies)<=set(writes[0].dependencies):
        raise AuthorityUnavailable('full writer candidate dropped actual preserved support/delete dependencies')
    return candidate


def require_full_persona_writer_candidate_v1(proof,candidate,request):
    candidate=_require_full_persona_writer_mechanical_candidate_v1(proof,candidate,request)
    if proof.state.reader.operation_kind not in {'adopt_growth','adopt_general_growth_v1',
            'adopt_single_event_growth_v1','adopt_ordinary_deep_growth_v1','adopt_current_method_strategy_v1',
            'adopt_current_conditioned_self_v1','rollback_current_conditioned_strategy_v1'}:
        raise AuthorityUnavailable('this actual full writer operation cannot transition PersonaPlan')
    return candidate


def preserve_full_persona_writer_candidate_v1(proof,candidate,*,frame,request):
    from dataclasses import replace
    from ..domains.d01 import GrowthAdoptionCandidate
    if(type(proof)is not CurrentFullPersonaWriterQualificationV1 or proof not in _QUALIFIED
            or type(candidate)is not GrowthAdoptionCandidate):
        raise AuthorityUnavailable('mechanical dependency preservation requires the actual private full writer candidate')
    reader=proof.state.reader
    require_current_full_persona_writer_v1(proof,reader,frame,proof.plan_ref,reader.operation_kind,request)
    selected=tuple(i for i,write in enumerate(candidate.typed_writes)if write.key==proof.plan_ref.key)
    if len(selected)!=1:
        raise AuthorityUnavailable('full writer mechanical candidate has no unique actual current Plan write')
    index=selected[0];write=candidate.typed_writes[index]
    dependencies=tuple(sorted(set((*write.dependencies,*proof.preserved_dependencies)),key=lambda key:key.token))
    if dependencies!=write.dependencies:
        writes=list(candidate.typed_writes);writes[index]=replace(write,dependencies=dependencies)
        candidate=replace(candidate,typed_writes=tuple(writes))
    if reader.operation_kind=='assess_ordinary_continuity_v1':
        return _require_full_persona_writer_mechanical_candidate_v1(proof,candidate,request)
    return require_full_persona_writer_candidate_v1(proof,candidate,request)


def require_full_persona_writer_stage_v1(db,*,frame,request,stage):
    import json
    from ..domains.d01 import GrowthAdoptionCandidate
    from ..domains.d01.production_operations_v1 import plain_v1
    from .domain_production_contracts_v1 import StagedDomainOperationV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..runtime_contracts import canonical_serialize
    proof,_plan=require_bound_current_full_persona_writer_v1(db,frame=frame,request=request)
    if(type(stage)is not StagedDomainOperationV1 or stage.domain!='d01' or stage.operation_kind!='adopt_growth'
            or stage.namespace!=frame.envelope.authority.namespace
            or(stage.operation_id,stage.activity_id)!=(frame.envelope.identity.operation_id,frame.envelope.identity.activity_id)):
        raise AuthorityUnavailable('full writer stage is not this actual old growth compiler result')
    writes=tuple(write for proposal in stage.proposals for write in proposal.typed_writes)
    plans=tuple(write for write in writes if write.key.type_name=='d01.persona_plan.v1')
    if stage.coverage!='complete':
        if plans:raise AuthorityUnavailable('waiting growth stage cannot transition the qualified PersonaPlan')
        return stage
    payload=json.loads(stage.original_payload_json)
    if(canonical_serialize(payload)!=stage.original_payload_json or canonical_digest(payload)!=stage.original_digest
            or payload['schema']!='d01.current-adopt_growth.v1' or payload['coverage']!='complete'
            or payload['identity']!=plain_v1(frame.envelope.identity)
            or payload['namespace']!=plain_v1(stage.namespace) or payload['writes']!=plain_v1(writes)):
        raise AuthorityUnavailable('full writer growth stage differs from its actual complete original and typed writes')
    candidate=decode_typed_production_value_v1(payload['provenance']['candidate'],GrowthAdoptionCandidate)
    if len(plans)!=1 or candidate.typed_writes!=writes:
        raise AuthorityUnavailable('full writer actual growth stage changed its exact decoded mechanical candidate writes')
    require_full_persona_writer_candidate_v1(proof,candidate,request)
    return stage


def release_current_full_persona_writer_v1(reader):
    state=_STATES.pop(reader,None)
    if state is None:return
    from .current_conditioned_self_read_v3 import release_full_persona_conditioned_copy_metadata_v1
    release_full_persona_conditioned_copy_metadata_v1(state)
    for value in state.copy_evidence:_ADAPTERS.pop(value,None)
    if state.qualification is not None:_QUALIFIED.pop(state.qualification,None)
    for identity in state.bound_frames:_FRAME_READSETS_V1.pop(identity,None)
    state.bound_frames.clear()
    _METADATA.pop(state,None)
    owner=state.origin;_OWNERS.pop(owner,None)
    owner.column_tasks.clear();owner.fixed_tasks.clear();owner.fixed_rows.clear()
    owner.selected_columns.clear();owner.selected_fixed.clear();owner.origin_columns.clear();owner.origin_history.clear()
    state.qualification=state.source_permission=None;state.copy_evidence=();state.history=()


def compose_current_full_persona_writer_metadata_cas_v1(prepared_inputs,read_versions,limits):
    from .current_method_learning_read_v3 import(PreparedMethodDomainInputsV3,_INPUTS,
        require_current_full_persona_writer_source_groups_v1)
    if type(prepared_inputs)is not PreparedMethodDomainInputsV3:return read_versions
    reader=prepared_inputs.owner;state=_STATES.get(reader)
    if state is None:return read_versions
    state.require_current_v1(reader)
    if(_INPUTS.get(prepared_inputs)!=(reader,prepared_inputs.plan,prepared_inputs.envelope,
            prepared_inputs.read_scope,prepared_inputs.graph_stamp,prepared_inputs.owner_rights)
            or prepared_inputs.plan is not reader.selected_plan or state.bound_plan is not reader.selected_plan):
        raise AuthorityUnavailable('full writer metadata CAS left its exact prepared Method inputs/plan')
    permission=require_current_full_persona_writer_source_groups_v1(reader,state.groups)
    permission.require_for_v1(reader,state.groups)
    versions={version.key:version.revision for version in read_versions}
    for version in _full_persona_writer_metadata_versions_v1(state,permission):
        if type(version)is not GraphVersion or NamespaceId.from_key(version.key)!=reader.namespace:
            raise AuthorityUnavailable('full writer Source metadata CAS crossed actual namespace/typed versions')
        if version.key in versions and versions[version.key]!=version.revision:
            raise AuthorityUnavailable('full writer Body/control/Source metadata CAS versions disagree')
        versions[version.key]=version.revision
    if len(versions)>limits.max_graph_heads:
        raise AuthorityUnavailable('full writer complete metadata CAS exceeds the original current-head budget')
    return tuple(GraphVersion(key,revision)for key,revision in sorted(versions.items(),key=lambda row:row[0].token))
