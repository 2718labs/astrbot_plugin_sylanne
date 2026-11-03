"""One current claim for the actual automatic single-event reviewer.

This private result is neither a PersonaPlan nor a persona readout/write grant.
Metadata lineage is complete; only the authenticated adoption target is retained.
"""
from dataclasses import dataclass
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..domains.d01 import ActiveRoleHeadControlV3,_persona_block,method_policy_state_v1
from ..domains.d01.single_event_growth_v1 import SingleEventGrowthAdoptionV1,SingleEventGrowthPolicyV1
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .d01_ordinary_origin_read_v3 import OrdinaryOriginColumnV3
from .selected_persona_readout_v4 import _SelectedPlanStreamV4

_KEY=object()
_STATES=WeakKeyDictionary()
_PROOFS=WeakKeyDictionary()


def _reader(owner):
    from .d01_single_event_growth_v1 import require_single_event_review_target_metadata_work_v1
    value=require_single_event_review_target_metadata_work_v1(owner)
    if value.sealed:
        from .domain_background_read_v3 import require_current_general_growth_trial_metadata_reader_v1
        require_current_general_growth_trial_metadata_reader_v1(value)
    else:value.work._require_invocation(value.graph)
    return value


def _identity(owner):
    return(owner.work,owner.operation,owner.read_scope,owner.authority,owner.owner,owner.owner_guard,
        owner.graph_stamp,owner.selection_digest,owner.handoff,owner.operation.deadline_utc)


def _current_control(owner):
    from .persona_growth_birth_v1 import current_persona_birth_control_v1
    birth=current_persona_birth_control_v1(owner.db,namespace=owner.namespace)
    return ActiveRoleHeadControlV3(owner.namespace,birth.head_id,birth.persona_head_version.key,birth.semantic_version,
        (birth.activation_version,birth.persona_head_version,birth.owner_grant_version),
        owner.graph_stamp[1].revision,owner.owner_guard.authorization_revision)


class _TargetStateV1:
    def __init__(self,key,owner,control,adoption,adoption_version,policy):
        if key is not _KEY:raise TypeError('private review target issuer required')
        self.owner,self.identity=owner,_identity(owner)
        self.control,self.adoption,self.adoption_version,self.policy=control,adoption,adoption_version,policy
        self.lineage=self.head=self.target=None
        self.complete=False;self.body_task=self.source_permission=self.proof=None;self.adoption_metadata_task=None
    def require_current_v1(self):
        owner=_reader(self.owner)
        if _STATES.get(owner)is not self or _identity(owner)!=self.identity:
            raise AuthorityUnavailable('review target metadata changed its actual child Work/Owner/READ')
        with runtime_storage_quantum_v3(owner.db)as meter:owner.require_data_current_v3(meter)
        if _current_control(owner)!=self.control:
            raise AuthorityUnavailable('review target current activation/plan/Owner controls changed')
        return self


def prepare_current_single_event_review_target_metadata_v1(owner):
    owner=_reader(owner)
    state=_STATES.get(owner)
    if state is None:
        from .domain_background_read_v3 import require_background_followup_handoff_v3
        from .d01_single_event_growth_v1 import _single_graph_metadata_v1,_single_signed_metadata_v1,POLICY_KIND,ADOPTION_TYPE
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from .persona_growth_review_metadata_v1 import growth_metadata_head_v1
        command=require_background_followup_handoff_v3(owner.handoff,owner.graph,owner.bundle).command
        key=AtomKey.from_token(command.request.adoption_ref)
        raw=_single_graph_metadata_v1(owner.db,owner.namespace,key,'single_event_adoption',[])
        adoption=decode_typed_production_value_v1(raw,SingleEventGrowthAdoptionV1)
        version,valid=growth_metadata_head_v1(owner.db,owner.namespace,key)
        if not valid or version.revision!=1 or key.type_name!=ADOPTION_TYPE or adoption.namespace!=owner.namespace:
            raise AuthorityUnavailable('review target needs its actual first adoption')
        raw_policy=_single_signed_metadata_v1(owner.db,owner.namespace,owner.graph._GraphCoordinator__d11_issuer,
            adoption.policy_ref,POLICY_KIND,[])
        policy=decode_typed_production_value_v1(raw_policy,SingleEventGrowthPolicyV1)
        if (canonical_digest(raw_policy)!=adoption.policy_digest or policy.terms.namespace!=owner.namespace
                or policy.terms.target_block!=adoption.target_block):
            raise AuthorityUnavailable('review target differs from its actual signed adoption policy')
        state=_TargetStateV1(_KEY,owner,_current_control(owner),adoption,version,policy);_STATES[owner]=state
    state.require_current_v1()
    if state.complete:return state
    from .role_control_lineage_metadata_v4 import require_role_control_lineage_metadata_v4
    lineage=require_role_control_lineage_metadata_v4(owner,state.control)
    head=lineage.current
    target=tuple(b for b in head.blocks if b.block_id==state.adoption.target_block)
    if (len(target)!=1 or target[0].claim_digest!=state.adoption.adopted_claim_digest
            or target[0].kind!=state.policy.terms.target_kind or target[0].plasticity!='growth'):
        raise AuthorityUnavailable('review target current committed claim differs from its actual adoption')
    _require_unchanged_target(lineage,state.adoption,target[0])
    state.lineage,state.head,state.target=lineage,head,target[0]
    state.complete=True
    owner.operation.retain(4096)
    return state


def _require_unchanged_target(lineage,adoption,target):
    columns=tuple(c for c in lineage.owner.columns.values()if c.table=='graph_history'and c.column=='value'
        and c.profile=='plan'and c.complete and c.key[0]==lineage.current.plan_ref.key.token)
    ordered=sorted(columns,key=lambda c:c.key[1]);seen=False
    for column in ordered:
        raw=column.metadata
        if raw['plan_id']+'@'+str(raw['version'])==adoption.adopted_head:seen=True
        if not seen:continue
        matches=tuple((i,b)for i,b in enumerate(raw['blocks'])if b['block_id']==adoption.target_block)
        if len(matches)!=1:raise AuthorityUnavailable('review target disappeared in its actual producer lineage')
        index,block=matches[0];path=('blocks',index,'claim')
        if ((block['kind'],block['plasticity'],column.commitments[path],column.parser.claim_protocols[path])
                !=(target.kind,target.plasticity,target.claim_digest,target.claim_protocol)):
            raise AuthorityUnavailable('review target changed after its actual registered adoption')
    if not seen:raise AuthorityUnavailable('review target adoption head is missing from the complete actual lineage')


def _sources(state):
    state.require_current_v1()
    from .d01_single_event_review_case_v1 import _case_upper_v1
    now=_case_upper_v1(state.owner)
    if not state.adoption.review_not_before_utc<=now<min(state.adoption.review_due_utc,
            state.adoption.readout_valid_until_utc,state.owner.operation.deadline_utc):
        raise AuthorityUnavailable('selected review claim is outside its original review window')
    from .d01_single_event_growth_v1 import require_single_event_background_source_permission_v1
    from .persona_growth_review_metadata_v1 import growth_metadata_head_v1
    proof=require_single_event_background_source_permission_v1(state.owner)
    proof.require_v1(state.owner)
    if not set((*state.adoption.source_refs,*state.policy.source_refs))<=set(proof.refs):
        raise AuthorityUnavailable('review target lacks its actual complete support/context Source closure')
    for version in (*state.policy.terms.scope_versions,*state.policy.terms.exclusion_versions):
        current,valid=growth_metadata_head_v1(state.owner.db,state.owner.namespace,version.key)
        if current!=version or not valid:
            raise AuthorityUnavailable('review target finite scope/exclusion changed')
    state.source_permission=proof
    return proof


class _TargetColumnV1(OrdinaryOriginColumnV3):
    def __init__(self,key,state):
        if key is not _KEY:raise TypeError('private selected review column issuer required')
        _sources(state);self.state=state
        from .d01_ordinary_origin_read_v3 import _fixed
        head=state.head
        current=_fixed(state.lineage.owner,'graph_atoms',('revision','valid','value_cell_id'),
            'bot=? AND persona=? AND token=?',(*state.owner.namespace.as_tuple,head.plan_ref.key.token))
        if current is None or current[:2]!=(head.plan_ref.revision,1):
            raise AuthorityUnavailable('review selected claim left its current complete metadata head')
        self.selected_index=next(i for i,b in enumerate(head.blocks)if b.block_id==state.target.block_id)
        super().__init__(state.lineage.owner,table='graph_atoms',column='value',key_columns=('token',),
            key=(head.plan_ref.key.token,),profile='plan',cell_id=current[2])
        self.parser=_SelectedPlanStreamV4(selected_indexes=frozenset({self.selected_index}),read_values=False,
            ensure_ascii=self.cell.header[0]=='canonical-json.ascii.v1',reserve=self.reserve)
    def require_v3(self):
        super().require_v3();_sources(self.state)
        return self


@dataclass(frozen=True,eq=False)
class SingleEventReviewTargetClaimV1:
    block:object
    control:ActiveRoleHeadControlV3
    head:object
    adoption_version:GraphVersion
    read_versions:tuple
    def require_current_v1(self,owner):
        record=_PROOFS.get(self)
        if record is None or record[0].owner is not owner:
            raise AuthorityUnavailable('review target claim is not this actual child Work result')
        state,column=record
        if state.proof is not self or state.body_task is None or state.body_task.column is not column:
            raise AuthorityUnavailable('review target claim lost its actual selected EOF')
        state.require_current_v1();column.require_v3()
        if (self.control,self.head,self.adoption_version)!=(state.control,state.head,state.adoption_version):
            raise AuthorityUnavailable('review target claim control identity changed')
        return self


class _TargetBodyTaskV1:
    def __init__(self,key,state):
        if key is not _KEY:raise TypeError('private review target task issuer required')
        self.state=state;self.column=_TargetColumnV1(_KEY,state);self.complete=False
    def advance(self,meter):
        state=self.state;state.require_current_v1();state.owner.require_data_current_v3(meter)
        if self.complete:state.proof.require_current_v1(state.owner);return True
        if not self.column.advance(meter):return False
        head=state.head;column=self.column;raw=column.metadata
        if (column.semantic_digest!=head.plan_value_digest or raw['namespace']!={'bot_id':state.owner.namespace.bot_id,'persona_id':state.owner.namespace.persona_id}
                or (raw['plan_id'],raw['version'],raw['authored'])!=(head.plan_id,head.version,head.authored)
                or len(raw['blocks'])!=len(head.blocks)or column.commitments[('values',)]!=head.values_digest):
            raise AuthorityUnavailable('review selected claim EOF differs from its actual whole-plan commitment')
        selected=None
        for i,expected in enumerate(head.blocks):
            value=raw['blocks'][i];path=('blocks',i)
            if (column.fields[path]!={'block_id','kind','claim','plasticity'}
                    or(value['block_id'],value['kind'],value['plasticity'])!=(expected.block_id,expected.kind,expected.plasticity)
                    or column.commitments[path+('claim',)]!=expected.claim_digest
                    or column.parser.claim_protocols[path+('claim',)]!=expected.claim_protocol):
                raise AuthorityUnavailable('review selected block metadata differs from complete original EOF')
            if i==column.selected_index:selected=_persona_block(value)
            elif 'claim'in value:raise AuthorityUnavailable('review parser retained an unselected claim')
        if selected is None or canonical_digest(selected.claim)!=state.adoption.adopted_claim_digest:
            raise AuthorityUnavailable('review claim is not the exact actually adopted claim')
        if state.target.kind=='semantic_identity':
            from ..domains.d01.identity_v3 import decode_semantic_identity_v3
            if decode_semantic_identity_v3(selected.claim)is None:
                raise AuthorityUnavailable('review semantic claim lacks its exact registered V3 decoder')
        elif state.target.claim_protocol in {'d01.conditioned-capability-revision.v1','d01.conditioned-strategy-revision.v1'}:
            from ..domains.d01.conditioned_self_v1 import decode_conditioned_self_claim_v1
            if decode_conditioned_self_claim_v1(selected.claim)is None:
                raise AuthorityUnavailable('review conditioned claim lacks its exact registered decoder')
        elif state.target.claim_protocol=='d01.method-policy.v1':
            if method_policy_state_v1(selected.claim)is None:raise AuthorityUnavailable('review method claim has no exact registered decoder')
        elif state.target.claim_protocol is not None:
            raise AuthorityUnavailable('review target claim has an unknown dedicated protocol')
        versions=tuple(sorted({v.key:v for v in (*state.control.read_versions,state.adoption_version,
            *state.source_permission.versions,*state.policy.terms.scope_versions,*state.policy.terms.exclusion_versions)}.values(),key=lambda v:v.key.token))
        proof=SingleEventReviewTargetClaimV1(selected,state.control,head,state.adoption_version,versions)
        _PROOFS[proof]=(state,column);state.proof=proof;self.complete=True
        return True


def prepare_current_single_event_review_target_v1(owner):
    state=prepare_current_single_event_review_target_metadata_v1(owner)
    _sources(state)
    if state.proof is not None:return state.proof.require_current_v1(owner)
    from .domain_background_read_v3 import BackgroundReadNeededV3
    if owner.sealed:raise AuthorityUnavailable('review target selected EOF was not prepared before W01 WRITE')
    raise BackgroundReadNeededV3(('single_event_review_target_body_v1',
        (state.adoption_version.key.token,state.adoption.adopted_claim_digest)))


def create_current_single_event_review_target_task_v1(owner,identity):
    owner=_reader(owner);state=_STATES.get(owner)
    if state is None or not state.complete or identity!=(state.adoption_version.key.token,state.adoption.adopted_claim_digest):
        raise AuthorityUnavailable('review target Body task has no actual complete metadata selection')
    state.require_current_v1()
    if state.body_task is None:state.body_task=_TargetBodyTaskV1(_KEY,state)
    return state.body_task


def require_current_single_event_review_target_claim_v1(owner,adoption):
    state=_STATES.get(owner)
    if state is None or not state.complete or adoption!=state.adoption:
        raise AuthorityUnavailable('review target claim has no actual exact adoption metadata')
    return prepare_current_single_event_review_target_v1(owner).block


def single_event_review_adoption_retains_path_v1(path):
    if not path:return True
    if path[0]=='writes':return len(path)<3 or path[2]in {'key','dependencies'}
    if path[0]=='provenance':return len(path)==1 or path[1]=='single_event_adoption'
    return path[0]in {'schema','namespace','identity','coverage','missing_inputs','continuation_ref',
        'read_versions','now_utc','parent_budget'}


def single_event_review_adoption_commits_path_v1(path):
    return not path or len(path)==3 and path[0]=='writes'and path[2]=='value'


class _AdoptionMetadataTaskV1:
    def __init__(self,key,state):
        if key is not _KEY:raise TypeError('private adopted producer metadata issuer required')
        state.require_current_v1();self.state=state;self.complete=False;self.result=None
        operation=state.adoption.adoption_operation_id
        matches=tuple(v for v in state.lineage.transitions if v[0]=='adopt_single_event_growth_v1'and v[1]==operation)
        if len(matches)!=1 or state.adoption_version not in matches[0][6]:
            raise AuthorityUnavailable('review adopted producer is absent from the complete registered lineage')
        self.transition=matches[0]
        self.column=OrdinaryOriginColumnV3(state.lineage.owner,table='graph_domain_production_originals_v1',
            column='original_payload_json',key_columns=('bot','persona','operation_id'),
            key=(*state.owner.namespace.as_tuple,operation),profile='single_event_review_adoption_original_v1')
    def advance(self,meter):
        state=self.state;state.require_current_v1();state.owner.require_data_current_v3(meter)
        if self.complete:return True
        if not self.column.advance(meter):return False
        raw=self.column.metadata
        from .d01_single_event_growth_v1 import plain_v1
        if (self.column.semantic_digest!=self.transition[2]or raw['schema']!='d01.current-adopt_single_event_growth_v1.v1'
                or raw['namespace']!={'bot_id':state.owner.namespace.bot_id,'persona_id':state.owner.namespace.persona_id}
                or raw['identity']['operation_id']!=state.adoption.adoption_operation_id
                or raw['coverage']!='complete'or raw['missing_inputs']or raw['continuation_ref']is not None
                or raw['provenance']['single_event_adoption']!=plain_v1(state.adoption)):
            raise AuthorityUnavailable('review adopted metadata differs from its actual full EOF/producer binding')
        from .role_control_lineage_metadata_v4 import _read_metadata_column_v4
        from .domain_production_originals_v1 import _receipt
        receipt=_receipt(_read_metadata_column_v4(state.lineage.owner,'graph_domain_production_originals_v1',
            'receipt_json',('bot','persona','operation_id'),(*state.owner.namespace.as_tuple,state.adoption.adoption_operation_id),'activation').metadata)
        if (receipt.operation_id!=state.adoption.adoption_operation_id or receipt.read_versions!=self.transition[5]
                or receipt.write_versions!=self.transition[6]or state.adoption_version not in receipt.write_versions):
            raise AuthorityUnavailable('review adopted metadata changed its actual recorded receipt')
        self.result={'domain':'d01','operation_kind':'adopt_single_event_growth_v1','original_digest':self.transition[2],
            'bundle_digest':self.transition[3],'receipt':receipt,'read_versions':receipt.read_versions,
            'payload':raw,'metadata_only':True}
        self.complete=True;return True


def create_current_single_event_review_adoption_metadata_task_v1(owner,identity):
    state=prepare_current_single_event_review_target_metadata_v1(owner)
    if identity!=(state.adoption.adoption_operation_id,):
        raise AuthorityUnavailable('review adopted metadata selector is not its actual registered adoption')
    task=state.adoption_metadata_task
    if task is None:task=_AdoptionMetadataTaskV1(_KEY,state);state.adoption_metadata_task=task
    return task


def read_current_single_event_review_adoption_metadata_v1(owner,adoption):
    state=prepare_current_single_event_review_target_metadata_v1(owner)
    if adoption!=state.adoption:raise AuthorityUnavailable('review producer metadata has another actual adoption')
    task=state.adoption_metadata_task
    if task is None or not task.complete:
        from .domain_background_read_v3 import BackgroundReadNeededV3
        if owner.sealed:raise AuthorityUnavailable('review adopted producer metadata was not prepared before WRITE')
        raise BackgroundReadNeededV3(('single_event_review_adoption_metadata_v1',(adoption.adoption_operation_id,)))
    state.require_current_v1();task.column.require_v3()
    return task.result


def read_bound_single_event_review_target_original_ref_v1(db,namespace,ref):
    from .domain_background_read_v3 import _active_v3
    from .d01_single_event_growth_v1 import single_event_metadata_work_v1
    owner=_active_v3(db)
    if owner is None or owner.kind!='followup_child' or not single_event_metadata_work_v1(owner):return False,None
    state=prepare_current_single_event_review_target_metadata_v1(owner)
    matches=tuple(v for v in state.lineage.transitions if v[0]=='adopt_single_event_growth_v1'
        and v[1]==state.adoption.adoption_operation_id)
    if len(matches)!=1:raise AuthorityUnavailable('review original has no actual adoption producer lineage')
    digest=matches[0][2]
    if ref not in {state.adoption.adoption_operation_id,'d01-current:'+digest[:48]}:return False,None
    if namespace!=owner.namespace:raise AuthorityUnavailable('review adopted original crossed actual namespace')
    original=read_current_single_event_review_adoption_metadata_v1(owner,state.adoption)
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    return True,ProductionOriginalRefV1('d01.current-adopt_single_event_growth_v1',ref,original['original_digest'])


def release_current_single_event_review_target_v1(owner):
    state=_STATES.pop(owner,None)
    if state is None:return
    if state.proof is not None:_PROOFS.pop(state.proof,None)
    if state.body_task is not None:
        column=state.body_task.column
        column.parser=None;column.fragment=b''
    if state.adoption_metadata_task is not None:
        state.adoption_metadata_task.column.parser=None
        state.adoption_metadata_task.column.fragment=b''
        state.adoption_metadata_task.result=None
    state.proof=state.body_task=state.lineage=state.source_permission=state.adoption_metadata_task=None
