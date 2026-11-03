"""Exact current controls for scoped single-event ordinary readout.

Metadata discovery issues no Source permission. The existing consumer qualifies
its own Source ALL before this module reads selected D07 meaning.
"""
from dataclasses import asdict,dataclass
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import canonical_digest,NamespaceId
from ..domains.d01.single_event_growth_v1 import (SingleEventGrowthReviewV1,SingleEventGrowthReviewV2,SingleEventGrowthAdoptionV1,
    REVIEW_TYPE,REVIEW_TYPE_V2,
    single_event_adoption_key_v1,single_event_review_key_v1)

_ORIGINS=WeakKeyDictionary()
_COUNTERS=WeakKeyDictionary()
_PREPARED=WeakKeyDictionary()
_REVIEWS=WeakKeyDictionary()
_REVIEW_BY_OWNER=WeakKeyDictionary()
_REVIEW_METADATA=WeakKeyDictionary()
_D07_METADATA_KINDS=frozenset({'adopted','prepared','semantic_question','single_event_review_attention_v1',
    'request','call','paid_cost','body_cost','execution','result','single_event_review_adoption_v1'})


@dataclass(frozen=True,slots=True)
class SingleEventControlHeadV4:
    ref:str
    revision:int
    valid:bool
    cell_id:str|None


@dataclass(frozen=True,slots=True)
class SingleEventCounterHeadV4:
    ref:str
    revision:int
    valid:bool
    cell_id:str|None
    semantic_digest:str|None


@dataclass(frozen=True,slots=True)
class SingleEventReadoutControlV4:
    block_id:str
    policy_ref:str
    policy_digest:str
    input_ref:str
    input_digest:str
    adoption_ref:tuple[str,int]
    adoption_digest:str
    review_ref:tuple[str,int]
    review_digest:str
    scope_ref:tuple[str,int]
    scope_digest:str
    consumer_selector:tuple[str,int,str]
    guard_heads:tuple[SingleEventControlHeadV4,...]
    counter_census:tuple[SingleEventCounterHeadV4,...]
    counter_census_digest:str
    source_refs:tuple[str,...]
    review_not_before_utc:float
    review_due_utc:float
    readout_valid_until_utc:float
    next_boundary_utc:float
    schema:str='d01.single-event-readout-control.v4'


class _PreparedSingleEventControlsV4:
    def __init__(self,owner,origins,selected,census,rows,scope):
        self.origins,self.selected,self.census,self.rows,self.scope=origins,selected,census,rows,scope
        self.source_roots=tuple(sorted({root for item in selected for root in item[4]}))
        _PREPARED[self]=(owner,owner.operation,owner.work,owner.work.selection_digest)



def single_event_readout_metadata_retains_path_v4(profile,path):
    if profile=='single_event_readout_registration_metadata_v4':
        return not path or path[0] in {'schema','namespace','identity','coverage','now_utc'}
    if profile!='single_event_readout_case_metadata_v4':
        raise ValueError('another single-event readout metadata profile')
    if not path:return True
    from ..domains.d01.single_event_review_case_v1 import RegisteredSingleEventReviewCaseV1
    return path[0] in RegisteredSingleEventReviewCaseV1.__dataclass_fields__ and path[0] not in {
        'adopted_claim','post_adoption_evidence_values'}


def single_event_readout_metadata_commits_path_v4(profile,path):
    if profile=='single_event_readout_registration_metadata_v4':
        return not path or path==('provenance','single_event_review_case')
    if profile!='single_event_readout_case_metadata_v4':
        raise ValueError('another single-event readout metadata profile')
    return not path or path in {('adopted_claim',),('post_adoption_evidence_values',)}


def _qualified_case_metadata_v4(owner,origin,original,current):
    from .d01_ordinary_origin_read_v3 import _fixed,_column,_history,_versions,_typed
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    from ..domains.d01.single_event_review_case_v1 import CASE_KIND,CASE_SCHEMA,RegisteredSingleEventReviewCaseV1
    head,column,history=current
    review=_review_value_v4(AtomKey.from_token(original.single_event.adoption.review_ref),column.metadata)
    if review.disposition!='qualified':return None
    pending=original.single_event.review
    pending_version=GraphVersion(AtomKey.from_token(original.single_event.adoption.review_ref),1)
    if (type(review)is not SingleEventGrowthReviewV2 or type(pending)is not SingleEventGrowthReviewV2
            or head[0]!=2 or pending.disposition!='pending' or review.review_case_original is None):
        raise AuthorityUnavailable('single-event readout requires the actual Review V2 pending1 to qualified2 transition')
    immutable=('namespace','adoption_ref','adoption_operation_id','adopted_head','target_block','adopted_claim_digest',
        'review_not_before_utc','review_due_utc','readout_valid_until_utc')
    if any(getattr(review,name)!=getattr(pending,name)for name in immutable):
        raise AuthorityUnavailable('qualified2 changed the immutable fields of its actual pending1 obligation')
    member,previous=_history(owner,pending_version.key,1,'single_event_review')
    from ..domains.d01.production_operations_v1 import plain_v1
    if member.value_digest!=canonical_digest(asdict(pending)) or previous.metadata!=plain_v1(pending):
        raise AuthorityUnavailable('single-event qualified transition changed its actual pending1 original')
    ref=review.review_case_original
    if type(ref)is not ProductionOriginalRefV1 or ref.kind!='d01.'+CASE_KIND:
        raise AuthorityUnavailable('single-event qualified review lacks its exact signed Case locator')
    key=(*owner.namespace.as_tuple,ref.original_ref)
    header=_fixed(owner,'graph_d01_production_inputs_v1',
        ('kind','producing_operation_id','payload_digest','signature'),
        'bot=? AND persona=? AND original_ref=?',key)
    if header is None or header[0]!=CASE_KIND or header[2]!=ref.original_digest:
        raise AuthorityUnavailable('single-event review Case locator differs from its actual signed producer')
    case_column=_column(owner,'graph_d01_production_inputs_v1','payload_json',
        ('bot','persona','original_ref'),key,'single_event_readout_case_metadata_v4',signed_header=header)
    raw=case_column.metadata
    adoption=original.single_event.adoption
    policy_original=original.single_event.policy_original
    input_original=original.single_event.input_original
    if (case_column.fields[()]!=set(RegisteredSingleEventReviewCaseV1.__dataclass_fields__)
            or not case_column.signature_verified or case_column.semantic_digest!=ref.original_digest
            or raw['schema']!=CASE_SCHEMA or raw['namespace']!=plain_v1(owner.namespace)
            or raw['case_revision']!=1 or raw['registration_operation_id']!=header[1]
            or raw['policy_original']!=plain_v1(ProductionOriginalRefV1(
                policy_original.kind,policy_original.original_ref,policy_original.original_digest))
            or raw['input_original']!=plain_v1(ProductionOriginalRefV1(
                input_original.kind,input_original.original_ref,input_original.original_digest))
            or raw['adoption_version']!=plain_v1(original.single_event.adoption_version)
            or raw['adoption_value_digest']!=canonical_digest(asdict(adoption))
            or raw['adoption_receipt_digest']!=canonical_digest(original.receipt)
            or raw['adoption_original']!=plain_v1(ProductionOriginalRefV1(
                'd01.current-adopt_single_event_growth_v1','d01-current:'+original.original_digest[:48],original.original_digest))
            or raw['review_version']!=plain_v1(pending_version)
            or raw['review_value_digest']!=canonical_digest(asdict(pending))
            or raw['target_block']!=origin.block.block_id or raw['adopted_claim_digest']!=origin.block.claim_digest
            or case_column.commitments[('adopted_claim',)]!=origin.block.claim_digest
            or raw['scope_versions']!=plain_v1(original.single_event.policy.terms.scope_versions)
            or raw['exclusion_versions']!=plain_v1(original.single_event.policy.terms.exclusion_versions)
            or (raw['review_not_before_utc'],raw['review_due_utc'],raw['readout_valid_until_utc'])!=
                (adoption.review_not_before_utc,adoption.review_due_utc,adoption.readout_valid_until_utc)
            or not raw['review_not_before_utc']<=raw['registered_at_utc']<=review.reviewed_at_utc<raw['review_due_utc']):
        raise AuthorityUnavailable('single-event qualified Case changed its signed adoption, target, scope or original window')
    receipt=_review_receipt(owner,original,current)
    if (pending_version not in receipt.read_versions or receipt.write_versions!=(GraphVersion(pending_version.key,2),)
            or review.reviewed_at_utc is None):
        raise AuthorityUnavailable('single-event qualification did not read pending1 and atomically write qualified2')
    case_plan=_typed(raw['current_persona_head'],GraphVersion)
    if case_plan.key!=owner.head.plan_ref.key or not 1<=case_plan.revision<=owner.head.plan_ref.revision:
        raise AuthorityUnavailable('single-event Case belongs to another actual persona history')
    _,plan_column=_history(owner,case_plan.key,case_plan.revision,'plan')
    blocks=tuple((i,block)for i,block in enumerate(plan_column.metadata['blocks'])if block['block_id']==origin.block.block_id)
    if (raw['current_persona_head_id']!=plan_column.metadata['plan_id']+'@'+str(plan_column.metadata['version'])
            or len(blocks)!=1 or (blocks[0][1]['kind'],blocks[0][1]['plasticity'])!=(origin.block.kind,origin.block.plasticity)
            or plan_column.commitments[('blocks',blocks[0][0],'claim')]!=origin.block.claim_digest):
        raise AuthorityUnavailable('signed Case target is not the unchanged block in its actual historical persona head')
    _require_case_target_lineage_v4(owner,origin,case_plan)
    registered=_case_registration_receipt_v4(owner,raw,ref)
    required=(*_versions(raw['source_versions']),*_versions(raw['scope_versions']),*_versions(raw['exclusion_versions']),
        pending_version,original.single_event.adoption_version,case_plan,*_versions(raw['counter_scope_binding']['inventory_versions']))
    if not set(required)<=set(registered.read_versions):
        raise AuthorityUnavailable('single-event signed Case lost its original complete Source/control/counter readset')
    stored_roots=tuple(_column(owner,'graph_d01_production_inputs_v1','source_refs_json',
        ('bot','persona','original_ref'),key,'activation').metadata)
    # record_input's closed Case producer has no evidence_source_refs index;
    # its actual support/context roots are authenticated by the signed value.
    if stored_roots:
        raise AuthorityUnavailable('single-event signed Case changed its actual producer Source index')
    return raw,ref,review,receipt,case_column,registered



def _require_case_target_lineage_v4(owner,origin,case_plan):
    # The real ordinary issuer has already authenticated every W01 transition.
    # Reuse that complete metadata; never fetch an arbitrary historical plan.
    expected=origin.block
    for revision in range(case_plan.revision,owner.head.plan_ref.revision+1):
        saved=owner.origin_history.get((case_plan.key.token,revision))
        if saved is None:
            raise AuthorityUnavailable('single-event target has a gap in its actual complete ordinary history')
        member,column=saved
        if (member.ref!=GraphVersion(case_plan.key,revision)or not member.valid or not column.complete
                or member.value_digest!=column.semantic_digest):
            raise AuthorityUnavailable('single-event target lost its actual historical plan commitment')
        selected=tuple((i,block)for i,block in enumerate(column.metadata['blocks'])if block['block_id']==expected.block_id)
        if len(selected)!=1:
            raise AuthorityUnavailable('single-event target changed its identity during the actual persona history')
        index,block=selected[0];path=('blocks',index,'claim')
        if (block['kind'],block['plasticity'],column.commitments[path],column.parser.claim_protocols[path])!=(
                expected.kind,expected.plasticity,expected.claim_digest,expected.claim_protocol):
            raise AuthorityUnavailable('single-event target changed during an intervening registered persona transition')


def _qualified2_current_guard_versions_v4(owner,versions):
    historical_types={'d01.persona_plan.v1','d01.persona_revision.v1',
        'd01.growth_contribution.v1','d01.persona_activation.v1'}
    advancing_types={'d01.persona_plan.v1','d01.persona_activation.v1'}
    current=[]
    for version in versions:
        if version.key.type_name in historical_types and version.revision>0:
            saved=owner.origin_history.get((version.key.token,version.revision))
            if saved is None:
                raise AuthorityUnavailable('qualified2 historical role dependency is outside the actual registered lineage')
            member,column=saved
            if (member.ref!=version or not member.valid or not column.complete
                    or member.value_digest!=column.semantic_digest or NamespaceId.from_key(version.key)!=owner.namespace):
                raise AuthorityUnavailable('qualified2 historical role dependency lost its actual W01 membership')
            if version.key.type_name in advancing_types:continue
        # Immutable revision/contribution controls keep their current validity;
        # revocation/correction cannot be hidden by an unchanged target claim.
        current.append(version)
    return tuple(current)


def _case_registration_receipt_v4(owner,case,case_original):
    from .d01_ordinary_origin_read_v3 import _fixed,_column,_event
    from .domain_production_originals_v1 import _receipt
    from ..contracts import Event,Scope
    op=case['registration_operation_id'];key=(*owner.namespace.as_tuple,op)
    header=_fixed(owner,'graph_domain_production_originals_v1',
        ('domain','operation_kind','original_digest','bundle_digest','receipt_digest'),
        'bot=? AND persona=? AND operation_id=?',key)
    if header is None or header[:2]!=('d01','review_single_event_growth_v1'):
        raise AuthorityUnavailable('single-event signed Case has another actual registered W01 producer')
    receipt=_receipt(_column(owner,'graph_domain_production_originals_v1','receipt_json',
        ('bot','persona','operation_id'),key,'activation').metadata)
    bundle=_fixed(owner,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',key)
    if (canonical_digest(receipt)!=header[4] or receipt.operation_digest!=header[3]
            or receipt.operation_id!=op or receipt.write_versions
            or bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)):
        raise AuthorityUnavailable('single-event Case registration changed its actual W01 receipt')
    payload=_column(owner,'graph_domain_production_originals_v1','original_payload_json',
        ('bot','persona','operation_id'),key,'single_event_readout_registration_metadata_v4')
    if (payload.semantic_digest!=header[2] or payload.metadata['coverage']!='complete'
            or payload.metadata['identity']['operation_id']!=op
            or payload.metadata['namespace']!={'bot_id':owner.namespace.bot_id,'persona_id':owner.namespace.persona_id}
            or payload.commitments[('provenance','single_event_review_case')]!=case_original.original_digest):
        raise AuthorityUnavailable('single-event Case is not the exact original registered in its complete W01')
    actual=_event(owner,Event(Scope(*owner.namespace.as_tuple,receipt.activity_id),op,payload.metadata['now_utc'],
        'domain_bundle',{'bundle_digest':header[3]}))
    if (actual.recorded_digest!=actual.event.digest or actual.reads!=receipt.read_versions
            or actual.revisions!=receipt.write_versions):
        raise AuthorityUnavailable('single-event Case registration lost its same-event complete W01 readset')
    return receipt


def _review_value_v4(key,metadata):
    from .d01_ordinary_origin_read_v3 import _typed
    if key.type_name==REVIEW_TYPE:return _typed(metadata,SingleEventGrowthReviewV1)
    if key.type_name==REVIEW_TYPE_V2:return _typed(metadata,SingleEventGrowthReviewV2)
    raise AuthorityUnavailable('single-event readout has another explicit review type')


def retain_single_event_ordinary_origin_v4(owner,previous,adoption):
    from .d01_ordinary_origin_read_v3 import _actual
    from .d01_ordinary_origin_v3 import validate_ordinary_adoption_v3
    _actual(owner);validate_ordinary_adoption_v3(previous,adoption)
    if adoption.single_event is not None:
        _ORIGINS.setdefault(owner,{})[adoption.operation_id]=adoption


def _now(owner):
    from .d06_ordinary_readout_v3 import require_life_ordinary_origin_owner_v3
    require_life_ordinary_origin_owner_v3(owner)
    if owner.is_authority:
        from ..authority_service.current_authority_graph_read_v3 import current_authority_graph_upper_utc_v3
        return current_authority_graph_upper_utc_v3(owner.work)
    from .current_method_learning_read_v3 import actual_current_method_upper_utc_v1
    return actual_current_method_upper_utc_v1(owner.consumer)


def _life_scope(owner):
    from .d06_ordinary_readout_v3 import require_life_ordinary_origin_owner_v3
    from .d01_ordinary_origin_read_v3 import _fixed
    from .current_life_numeric_metadata_v1 import _metadata
    from .d04_life_before_original_v1 import life_d04_before_ref_v1
    from .d06_internal_life_episode_v2 import EPISODE,PROVENANCE
    from .d11_life_contract_v1 import LifeInputRefV1
    require_life_ordinary_origin_owner_v3(owner);r=owner.consumer
    if owner.is_authority:
        from ..authority_service.life_numeric_source_read_v3 import read_current_authority_numeric_life_scope_v1
        return read_current_authority_numeric_life_scope_v1(owner.db,namespace=owner.namespace,
            episode_ref=r.request.episode_ref,causal_operation_id=r.request.causal_operation_id)
    episode=AtomKey.from_token(r.request.episode_ref)
    if episode.type_name!=EPISODE or NamespaceId.from_key(episode)!=owner.namespace:
        raise AuthorityUnavailable('single-event Life selector has another actual occurrence')
    provenance,pt=_metadata(r,'graph','episode',AtomKey(episode.owner,PROVENANCE,'record').token)
    activity=provenance['event']['activity']
    if (provenance['episode']['episode_ref']!=episode.token
            or provenance['event']['causal_operation_id']!=r.request.causal_operation_id):
        raise AuthorityUnavailable('single-event Life selector changed its actual occurrence/cause')
    before,bt=_metadata(r,'life','before',life_d04_before_ref_v1(owner.namespace,activity['execution_id']))
    if before['execution_id']!=activity['execution_id'] or before['namespace']!=asdict(owner.namespace):
        raise AuthorityUnavailable('single-event Life Before has another execution')
    where='bot=? AND persona=? AND kind=? AND producing_operation_id=?'
    args=(*owner.namespace.as_tuple,'prepared',before['prepare_operation_id'])
    locator=_fixed(owner,'graph_d11_life_originals_v1',('original_ref',),where+' ORDER BY original_ref',args)
    if locator is None or _fixed(owner,'graph_d11_life_originals_v1',('original_ref',),
            where+' AND original_ref>? ORDER BY original_ref',(*args,locator[0])) is not None:
        raise AuthorityUnavailable('single-event Life selector lacks one actual prepared original')
    prepared,task=_metadata(r,'life','single_event_life_scope',locator[0])
    binding=prepared['binding']
    if (task.column.canonical_digest!=before['prepared_digest']
            or binding['namespace']!=asdict(owner.namespace) or binding['execution_id']!=before['execution_id']
            or binding['prepare_operation_id']!=before['prepare_operation_id']
            or binding['prepared_original_ref']!=locator[0]
            or prepared['prepare_operation_id']!=before['prepare_operation_id']):
        raise AuthorityUnavailable('single-event Life project is not the same authenticated prepared execution')
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    scope=decode_typed_production_value_v1(prepared['plan']['project'],LifeInputRefV1)
    matches=[row for row in prepared['read_rows']if row['ref']==scope.ref and row['revision']==scope.revision]
    if len(matches)!=1:raise AuthorityUnavailable('single-event Life project lacks its actual prepared version')
    return scope


def _current(owner,key,profile):
    from .d01_ordinary_origin_read_v3 import _fixed,_column
    head=_fixed(owner,'graph_atoms',('revision','valid','value_cell_id'),
        'token=? AND bot=? AND persona=?',(key.token,*owner.namespace.as_tuple))
    if head is None or head[1]!=1:return None
    column=_column(owner,'graph_atoms','value',('token',),(key.token,),profile,cell_id=head[2])
    history=_fixed(owner,'graph_history',('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),
        'token=? AND revision=?',(key.token,head[0]))
    if history is None or history[0]!=1 or history[1:3]!=owner.namespace.as_tuple or history[5]!=head[2]:
        raise AuthorityUnavailable('single-event current metadata lost its exact historical member')
    return head,column,history


def _counters(owner):
    from .d01_ordinary_origin_read_v3 import _fixed,_column
    from .d06_ordinary_readout_v3 import require_life_ordinary_origin_owner_v3
    require_life_ordinary_origin_owner_v3(owner)
    stamp=owner.work.graph_stamp if owner.is_authority else owner.consumer.graph_stamp
    cached=_COUNTERS.get(owner)
    if cached is not None:
        if cached[:2]!=(owner.operation,stamp):raise AuthorityUnavailable("single-event counter census left its actual snapshot")
        return cached[2:]
    rows=[];census=[];after=''
    fields={'schema','interpretation_id','activity_id','question_key','proposition','stance',
        'subjective_conviction','evidence_status','source_refs','source_families','meaningful_unknowns','current'}
    while True:
        row=_fixed(owner,'graph_atoms',('token','revision','valid','value_cell_id'),
            'bot=? AND persona=? AND type_name=? AND token>? ORDER BY token',
            (*owner.namespace.as_tuple,'d07.current_interpretation.v1',after))
        if row is None:break
        if len(census)>=128:raise AuthorityUnavailable('single-event complete counter census exceeds the actual 128-row bound')
        token,revision,valid,cell=row;after=token;digest=None
        if valid:
            column=_column(owner,'graph_atoms','value',('token',),(token,),'single_event_counter_metadata',cell_id=cell)
            if column.fields[()]!=fields or column.metadata['schema']!='d07.current_interpretation.v1':
                raise AuthorityUnavailable('single-event counter metadata has another actual registered schema')
            digest=column.semantic_digest;rows.append((token,revision,column.metadata,digest,cell))
        census.append(SingleEventCounterHeadV4(token,revision,bool(valid),cell,digest))
    result=(tuple(census),tuple(rows))
    _COUNTERS[owner]=(owner.operation,stamp,*result)
    return result


def _guard_heads(owner,versions):
    from .d01_ordinary_origin_read_v3 import _fixed
    result=[]
    for version in sorted(versions,key=lambda v:v.key.token):
        head=_fixed(owner,'graph_atoms',('revision','valid','value_cell_id'),
            'token=? AND bot=? AND persona=?',(version.key.token,*owner.namespace.as_tuple))
        if version.revision==0:
            if head is not None:return None
            result.append(SingleEventControlHeadV4(version.key.token,0,False,None))
        else:
            if head is None or head[0]!=version.revision:return None
            result.append(SingleEventControlHeadV4(version.key.token,head[0],bool(head[1]),head[2]))
    return tuple(result)


def prepare_single_event_ordinary_controls_v4(owner,origins):
    from .d01_ordinary_origin_read_v3 import _actual,_typed
    from .d06_ordinary_readout_v3 import is_life_ordinary_origin_owner_v3
    _actual(owner)
    ordinary=tuple(o for o in origins if o.origin_kind!='ordinary_single_event_growth_v1')
    changed=tuple(o for o in origins if o.origin_kind=='ordinary_single_event_growth_v1')
    if not changed:return _PreparedSingleEventControlsV4(owner,origins,(),(),(),None)
    if not is_life_ordinary_origin_owner_v3(owner):
        return _PreparedSingleEventControlsV4(owner,ordinary,(),(),(),None)
    scope=_life_scope(owner);now=_now(owner);census,rows=_counters(owner)
    selected=[];allowed=list(ordinary)
    for origin in changed:
        original=_ORIGINS.get(owner,{}).get(origin.producing_operation_id)
        if original is None:raise AuthorityUnavailable('single-event readout has no actual verified origin')
        controls=original.single_event;policy=controls.policy;value=controls.input;adoption=controls.adoption
        from ..domains.d01.identity_v3 import RuntimeIdentityRef
        guard=owner.consumer.owner_entry.head.guard if owner.is_authority else owner.consumer.owner_guard
        grant=next((a for a in owner.control_atoms if a.key==policy.owner_grant.key),None)
        if (policy.runtime_identity!=RuntimeIdentityRef.from_owner_guard(owner.namespace,guard)
                or policy.owner_binding_digest!=canonical_digest(guard) or grant is None
                or grant.revision!=policy.owner_grant.revision or canonical_digest(grant.value)!=policy.owner_grant_digest):continue
        matching=tuple(c for c in policy.scope_commitments if (c.version.key.token,c.version.revision,c.semantic_digest)==
            (scope.ref,scope.revision,scope.digest) and c.version in policy.terms.scope_versions)
        if len(matching)!=1 or not adoption.adopted_at_utc<=now<adoption.readout_valid_until_utc:continue
        current=_current(owner,AtomKey.from_token(adoption.review_ref),'single_event_review')
        if current is None:continue
        head,column,history=current;review=_review_value_v4(AtomKey.from_token(adoption.review_ref),column.metadata)
        if (review.adoption_operation_id!=adoption.adoption_operation_id or review.adopted_claim_digest!=origin.block.claim_digest
                or review.disposition in {'opposed','expired'} or now>=adoption.review_due_utc and review.disposition!='qualified'):continue
        written={v.key for v in original.receipt.write_versions}
        versions=tuple(v for v in original.receipt.read_versions if v.key not in written
            and v.key.type_name!='d07.current_interpretation.v1')
        guards=_guard_heads(owner,versions)
        if guards is None:continue
        case=_qualified_case_metadata_v4(owner,origin,original,current)
        source_roots=set(policy.source_refs)|set(value.source_refs)
        if case is not None:
            source_roots.update((*case[0]['support_source_refs'],*case[0]['context_source_refs']))
            source_roots.update(case[2].source_refs)
        question='d01.growth:'+origin.block.block_id+':core'
        from .d01_single_event_growth_v1 import single_event_review_question_v1
        continuity=single_event_review_question_v1(adoption,adoption.input_digest)
        relevant=tuple(row for row in rows if row[2]['current']is True and row[2]['question_key']in {question,continuity})
        for row in relevant:source_roots.update(row[2]['source_refs'])
        if len(source_roots)>32:raise AuthorityUnavailable('single-event readout roots exceed the existing production 32-root bound')
        selected.append((origin,original,current,guards,tuple(sorted(source_roots)),matching[0],relevant,case))
        allowed.append(origin)
    return _PreparedSingleEventControlsV4(owner,tuple(allowed),tuple(selected),census,rows,scope)



def _review_receipt(owner,original,current):
    from .d01_ordinary_origin_read_v3 import _fixed,_column,_event,_versions
    from .domain_production_originals_v1 import _receipt
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..contracts import Event,Scope
    head,column,history=current
    if head[0]==1:
        if history[4]!=original.operation_id or column.semantic_digest!=canonical_digest(asdict(original.single_event.review)):
            raise AuthorityUnavailable('single-event initial review obligation changed its actual same commit')
        return original.receipt
    op=history[4];key=(*owner.namespace.as_tuple,op)
    metadata=_fixed(owner,'graph_domain_production_originals_v1',
        ('domain','operation_kind','original_digest','bundle_digest','receipt_digest'),
        'bot=? AND persona=? AND operation_id=?',key)
    if metadata is None or metadata[:2]!=('d01','review_single_event_growth_v1'):
        raise AuthorityUnavailable('single-event current review lacks its independently registered actual producer')
    payload_column=_column(owner,'graph_domain_production_originals_v1','original_payload_json',
        ('bot','persona','operation_id'),key,'single_event_review_operation')
    payload=payload_column.metadata
    receipt=_receipt(_column(owner,'graph_domain_production_originals_v1','receipt_json',
        ('bot','persona','operation_id'),key,'activation').metadata)
    row_reads=tuple(GraphVersion(AtomKey.from_token(token),revision)for token,revision in
        _column(owner,'graph_domain_production_originals_v1','read_versions_json',('bot','persona','operation_id'),key,'activation').metadata)
    bundle=_fixed(owner,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',key)
    if (row_reads!=receipt.read_versions or payload_column.semantic_digest!=metadata[2]or canonical_digest(receipt)!=metadata[4]
            or receipt.operation_digest!=metadata[3]or receipt.operation_id!=op
            or bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)
            or payload['coverage']!='complete'or payload['identity']['operation_id']!=op
            or payload['namespace']!={'bot_id':owner.namespace.bot_id,'persona_id':owner.namespace.persona_id}
            or history[3]!=receipt.activity_id
            or payload['provenance']['single_event_review']!=column.metadata
            or payload['provenance']['single_event_adoption']!=plain_v1(original.single_event.adoption)
            or receipt.write_versions!=(GraphVersion(AtomKey.from_token(original.single_event.adoption.review_ref),head[0]),)):
        raise AuthorityUnavailable('single-event current review metadata is not its actual complete W01 original')
    actual=_event(owner,Event(Scope(*owner.namespace.as_tuple,receipt.activity_id),op,payload['now_utc'],
        'domain_bundle',{'bundle_digest':metadata[3]}))
    if (actual.recorded_digest!=actual.event.digest or actual.reads!=receipt.read_versions
            or actual.revisions!=receipt.write_versions):
        raise AuthorityUnavailable('single-event review lost the complete same-event receipt readset')
    return receipt


def _require_scope_header(owner,commitment):
    from .d01_ordinary_origin_read_v3 import _fixed
    from ..runtime_storage_v3 import begin_runtime_cell_read_v3
    key=commitment.version.key
    head=_fixed(owner,'graph_atoms',('revision','valid','value_cell_id'),
        'token=? AND bot=? AND persona=?',(key.token,*owner.namespace.as_tuple))
    if head!=(commitment.version.revision,1,commitment.cell_id):return False
    with owner.quantum_v3()as meter:
        cell=begin_runtime_cell_read_v3(owner.db,commitment.cell_id,erasure_owner_ref=key.token)
        header=cell.header
    return (header[0],header[2],header[3],header[5])==(commitment.codec_id,
        commitment.producer_operation_id,commitment.total_bytes,commitment.payload_sha256)


def _require_control_sources(owner,preparation,heads):
    from .d01_ordinary_origin_read_v3 import _actual
    from ..memory_types import access_key,validate_access
    from ..domains.d06 import source_correction_head_key
    _actual(owner)
    if _PREPARED.get(preparation)!=(owner,owner.operation,owner.work,owner.work.selection_digest):
        raise AuthorityUnavailable('single-event controls left their actual independent Source Work')
    present={h.ref:h for h in heads}
    atoms={a.key.token:a for a in owner.atoms}
    for token in preparation.source_roots:
        witness=owner.sources.get(token)
        if witness is None or not witness.valid or token not in present:
            raise AuthorityUnavailable('single-event control Source ALL has not completed before meaning Body')
        key=AtomKey.from_token(token);metadata=witness.metadata
        ak=access_key(*owner.namespace.as_tuple,key.owner.subject)
        ck=source_correction_head_key(owner.namespace,key.owner.subject)
        access=atoms.get(ak.token)
        if access is None or not access.valid or ak.token not in present or ck.token not in present or present[ck.token].revision!=0:
            raise AuthorityUnavailable('single-event control Source lacks its actual current Access/correction proof')
        validate_access(access.value)
        if ('consolidation'not in metadata['purposes']or 'consolidation'not in access.value['purposes']
                or access.value['status']!='active'or not set(owner.audience)<=set(metadata['audiences'])
                or not set(owner.audience)<=set(access.value['audiences'])):
            raise AuthorityUnavailable('single-event current control Source does not permit this actual use')
    return preparation



@dataclass(frozen=True,eq=False)
class _ActualSingleEventReadoutReviewV4:
    owner:object
    preparation:object
    original:object
    review:SingleEventGrowthReviewV2
    review_version:GraphVersion
    case_metadata:dict
    case_original:object
    producer_receipt:object
    source_refs:tuple[str,...]
    source_support_heads:tuple
    current_guard_heads:tuple
    review_head:tuple
    reviewed_at_utc:float

    def read_d07_metadata_v1(self,kind,ref):
        from .d01_ordinary_origin_read_v3 import _fixed,_column
        from .d07_execution_v1 import SIGN_KIND
        from .domain_production_contracts_v1 import ProductionOriginalRefV1
        from ..runtime_contracts import canonical_serialize
        self.require_current_v4()
        if kind not in _D07_METADATA_KINDS or type(ref)is not str or not ref:
            raise AuthorityUnavailable('historical readout has another closed D07 metadata selector')
        from .dispatch_current_inventory_v3 import _freeze_value_v3,_detach_value_v3
        cache=_REVIEW_METADATA.setdefault(self,{})
        if (kind,ref)in cache:
            metadata,original=cache[kind,ref]
            return _detach_value_v3(metadata),original
        owner=self.owner;key=(*owner.namespace.as_tuple,kind,ref)
        header=_fixed(owner,'graph_d07_execution_originals_v1',('payload_digest','signature'),
            'bot=? AND persona=? AND kind=? AND original_ref=?',key)
        if header is None:
            raise AuthorityUnavailable('historical readout lacks its actual immutable D07 original')
        column=_column(owner,'graph_d07_execution_originals_v1','payload_json',
            ('bot','persona','kind','original_ref'),key,'single_event_readout_d07_'+kind+'_v4')
        if column.semantic_digest!=header[0]:
            raise AuthorityUnavailable('historical D07 metadata changed its whole original canonical commitment')
        owner.origin_signer.verify(SIGN_KIND,canonical_serialize((owner.namespace,kind,ref,header[0])),header[1])
        original=ProductionOriginalRefV1('d07.'+kind,ref,header[0])
        from .source_correction_read_v3 import _heap
        frozen=_freeze_value_v3(column.metadata)
        owner.operation.retain(_heap((frozen,original))+512)
        cache[kind,ref]=(frozen,original)
        return _detach_value_v3(frozen),original

    def locate_d07_prepared_v1(self,digest):
        from .d01_ordinary_origin_read_v3 import _fixed
        self.require_current_v4();owner=self.owner
        where='bot=? AND persona=? AND kind=? AND payload_digest=?'
        args=(*owner.namespace.as_tuple,'prepared',digest)
        row=_fixed(owner,'graph_d07_execution_originals_v1',('original_ref',),where+' ORDER BY original_ref',args)
        if row is None or _fixed(owner,'graph_d07_execution_originals_v1',('original_ref',),
                where+' AND original_ref>? ORDER BY original_ref',(*args,row[0]))is not None:
            raise AuthorityUnavailable('historical D07 adoption lacks one exact signed Prepared identity')
        return row[0]

    def read_interpretation_metadata_v1(self):
        self.require_current_v4()
        token=self.review.continuity_interpretation_ref
        actual=_current(self.owner,AtomKey.from_token(token),'single_event_counter_metadata')
        if actual is None:
            raise AuthorityUnavailable('historical review has no actual current interpretation metadata')
        head,column,history=actual
        if column.metadata['current']is not True:
            raise AuthorityUnavailable('historical review interpretation is no longer current')
        return GraphVersion(AtomKey.from_token(token),head[0]),column.semantic_digest,column.metadata

    def require_current_v4(self):
        from .d01_ordinary_origin_read_v3 import _actual,_fixed
        owner=_actual(self.owner)
        binding=(owner,owner.operation,owner.work,owner.work.selection_digest,owner.control,owner.head,self.preparation,
            self.original,self.review,self.review_version,self.case_original,self.producer_receipt,
            self.source_refs,self.source_support_heads,self.current_guard_heads,self.review_head,
            self.reviewed_at_utc,canonical_digest(self.case_metadata))
        if _REVIEWS.get(self)!=binding:
            raise AuthorityUnavailable('historical review left its actual independent readout/selection/Source proof')
        _require_control_sources(owner,self.preparation,self.source_support_heads)
        actual=_fixed(owner,'graph_atoms',('revision','valid','value_cell_id'),
            'token=? AND bot=? AND persona=?',(self.review_version.key.token,*owner.namespace.as_tuple))
        if actual!=self.review_head:
            raise AuthorityUnavailable('historical review changed its actual qualified2 head')
        for expected in self.current_guard_heads:
            actual=_fixed(owner,'graph_atoms',('revision','valid','value_cell_id'),
                'token=? AND bot=? AND persona=?',(expected.ref,*owner.namespace.as_tuple))
            wanted=None if expected.revision==0 else(expected.revision,int(expected.valid),expected.cell_id)
            if actual!=wanted:
                raise AuthorityUnavailable('historical review changed its actual Source/scope control guard')
        census,_=_counters(owner)
        if census!=self.preparation.census:
            raise AuthorityUnavailable('historical review changed its actual complete counter census')
        if not self.original.single_event.adoption.adopted_at_utc<=_now(owner)<self.review.readout_valid_until_utc:
            raise AuthorityUnavailable('historical review cannot extend the original single-event readout window')
        return self


def require_actual_single_event_readout_review_v4(proof,*,db=None):
    if type(proof)is not _ActualSingleEventReadoutReviewV4:
        raise TypeError('actual privately issued independent readout review required')
    proof.require_current_v4()
    if db is not None and proof.owner.db is not db:
        raise AuthorityUnavailable('historical readout review crossed its actual Graph connection')
    return proof.owner


def _issue_readout_review_v4(owner,preparation,origin,original,current,case,source_support_heads):
    raw,ref,review,receipt,column,registered=case
    version=GraphVersion(AtomKey.from_token(original.single_event.adoption.review_ref),2)
    evidence=tuple(dict.fromkeys((*_case_current_guard_versions_v4(case),*receipt.read_versions)))
    required=_qualified2_current_guard_versions_v4(owner,tuple(v for v in evidence
        if v.key!=version.key and v.key.type_name!='d07.current_interpretation.v1'))
    current_guards=_guard_heads(owner,required)
    if current_guards is None:
        raise AuthorityUnavailable('historical review Case changed its actual current Source/scope controls')
    question='d01.growth:'+origin.block.block_id+':core'
    members=tuple(sorted(((GraphVersion(AtomKey.from_token(row[0]),row[1]),row[3])
        for row in preparation.rows if row[2]['current']is True and row[2]['question_key']==question),key=lambda row:row[0].key.token))
    from .d01_ordinary_origin_read_v3 import _typed
    stored=tuple(sorted(((_typed(v,GraphVersion),digest)for v,digest in raw['counter_scope_binding']['selected_members']),
        key=lambda row:row[0].key.token))
    if raw['counter_scope_binding']['question_key']!=question or members!=stored:
        raise AuthorityUnavailable('historical review Case changed its complete actual counter selection')
    current_blocks=tuple(block for block in owner.head.blocks if block.block_id==origin.block.block_id)
    if current_blocks!=(origin.block,):
        raise AuthorityUnavailable('historical Case no longer describes the unchanged current target block')
    proof=_ActualSingleEventReadoutReviewV4(owner,preparation,original,review,version,raw,ref,receipt,
        tuple(sorted(set((*raw['support_source_refs'],*raw['context_source_refs'])))),
        tuple(source_support_heads),current_guards,current[0],review.reviewed_at_utc)
    owner.operation.retain(1024+len(current_guards)*128)
    _REVIEWS[proof]=(owner,owner.operation,owner.work,owner.work.selection_digest,owner.control,owner.head,preparation,
        original,review,version,ref,receipt,proof.source_refs,proof.source_support_heads,
        proof.current_guard_heads,proof.review_head,review.reviewed_at_utc,canonical_digest(raw))
    return proof.require_current_v4()


def _case_current_guard_versions_v4(case):
    from .d01_ordinary_origin_read_v3 import _versions,_typed
    raw=case[0]
    return (*_versions(raw['source_versions']),*_versions(raw['scope_versions']),*_versions(raw['exclusion_versions']),
        _typed(raw['adoption_version'],GraphVersion))


def finish_single_event_ordinary_controls_v4(owner,preparation,source_support_heads):
    from .d01_ordinary_origin_read_v3 import _column,_typed
    from ..domains.d07 import D07DomainProvider
    _require_control_sources(owner,preparation,source_support_heads)
    if not preparation.selected:return (),preparation.origins
    now=_now(owner);controls=[];kept=[o for o in preparation.origins if o.origin_kind!='ordinary_single_event_growth_v1']
    spec=next(s for s in D07DomainProvider.type_specs()if s.name=='d07.current_interpretation.v1')
    for origin,original,current,guards,roots,scope,relevant,case in preparation.selected:
        if not _require_scope_header(owner,scope):continue
        head,review_column,history=current;review=_review_value_v4(AtomKey.from_token(original.single_event.adoption.review_ref),review_column.metadata)
        adopted=original.single_event.adoption;policy=original.single_event.policy;value=original.single_event.input
        receipt=_review_receipt(owner,original,current)
        written={v.key for v in receipt.write_versions}
        guard_versions=tuple(v for v in receipt.read_versions if v.key not in written
            and v.key.type_name!='d07.current_interpretation.v1')
        if case is not None:guard_versions=_qualified2_current_guard_versions_v4(owner,guard_versions)
        current_guards=_guard_heads(owner,guard_versions)
        if current_guards is None or not adopted.adopted_at_utc<=now<adopted.readout_valid_until_utc:continue
        if now>=adopted.review_due_utc and review.disposition!='qualified':continue
        counter_seen=False;unknown=False;opposed=False;continuity_ok=now<adopted.review_due_utc
        historical=None
        if case is not None:
            from .d07_single_event_review_v1 import require_historical_single_event_review_interpretation_v1
            review_proof=_issue_readout_review_v4(owner,preparation,origin,original,current,case,source_support_heads)
            historical=require_historical_single_event_review_interpretation_v1(review_proof)
            historical.require_current_v1(review_proof)
            if historical.interpretation_ref!=review.continuity_interpretation_ref:
                raise AuthorityUnavailable('historical qualification changed its exact adopted interpretation')
            prior_kinds={'d07.prepared','d07.semantic_question','d07.request','d07.call','d07.paid_cost',
                'd07.body_cost','d07.execution','d07.adopted','d07.result'}
            observed=set(review.observed_original_refs)
            if (review.review_case_original.original_ref not in observed
                    or any(item.original_ref not in observed for item in historical.originals if item.kind in prior_kinds)):
                raise AuthorityUnavailable('qualified2 did not consume the exact signed Case and paid C3 originals')
            continuity_ok=True
            merged={row.ref:row for row in current_guards}
            for row in review_proof.current_guard_heads:
                if row.ref in merged and merged[row.ref]!=row:
                    raise AuthorityUnavailable('historical Case conflicts with the current review control readset')
                merged[row.ref]=row
            current_guards=tuple(merged[token]for token in sorted(merged))
            _REVIEW_BY_OWNER.setdefault(owner,{})[(adopted.review_ref,2)]=(review_proof,historical)
        for token,revision,metadata,digest,cell in relevant:
            if metadata['question_key']!='d01.growth:'+origin.block.block_id+':core':continue
            # Every selected counter's Source roots were independently qualified above.
            body=_column(owner,'graph_atoms','value',('token',),(token,),'single_event_interpretation_body',cell_id=cell)
            if body.semantic_digest!=digest:raise AuthorityUnavailable('single-event selected meaning differs from its metadata EOF')
            raw=body.metadata;spec.validator(raw)
            if any(raw[name]!=metadata[name]for name in metadata):
                raise AuthorityUnavailable('single-event selected meaning changed its exact fixed metadata')
            actual=_current(owner,AtomKey.from_token(token),'single_event_counter_metadata')
            if actual is None or actual[0]!=(revision,1,cell):raise AuthorityUnavailable('single-event meaning head changed')
            from .d01_ordinary_origin_read_v3 import _fixed
            event_id=actual[2][4]
            bundle=_fixed(owner,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
                'bot=? AND persona=? AND operation_id=?',(*owner.namespace.as_tuple,event_id))
            if bundle is None:raise AuthorityUnavailable('single-event selected meaning lacks an actual W01 producer')
            if metadata['question_key']=='d01.growth:'+origin.block.block_id+':core':
                counter_seen=True
                opposed=opposed or raw['stance']=='oppose'and raw['evidence_status']=='supported'
                unknown=unknown or not raw['source_refs']or raw['stance']!='support'or raw['evidence_status']!='supported'or bool(raw['meaningful_unknowns'])
        if opposed or unknown or not counter_seen or not continuity_ok:continue
        review_version=(adopted.review_ref,head[0])
        boundary=adopted.readout_valid_until_utc if review.disposition=='qualified'else (
            adopted.review_not_before_utc if now<adopted.review_not_before_utc else adopted.review_due_utc)
        controls.append(SingleEventReadoutControlV4(origin.block.block_id,policy.terms.policy_ref,
            original.single_event.policy_original.original_digest,value.input_ref,original.single_event.input_original.original_digest,
            (original.single_event.adoption_version.key.token,1),canonical_digest(asdict(adopted)),review_version,
            review_column.semantic_digest,(scope.version.key.token,scope.version.revision),scope.semantic_digest,
            (preparation.scope.ref,preparation.scope.revision,preparation.scope.digest),current_guards,
            preparation.census,canonical_digest(tuple(asdict(row)for row in preparation.census)),roots,
            adopted.review_not_before_utc,adopted.review_due_utc,adopted.readout_valid_until_utc,boundary))
        kept.append(origin)
    return tuple(controls),tuple(kept)


def validate_single_event_controls_wire_v4(raw,namespace):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(raw)is not list:raise AuthorityUnavailable('single-event V4 controls require a closed list')
    controls=tuple(decode_typed_production_value_v1(item,SingleEventReadoutControlV4)for item in raw)
    seen=set()
    for control,item in zip(controls,raw,strict=True):
        if (control.schema!='d01.single-event-readout-control.v4'or control.block_id in seen or plain_v1(control)!=item
                or control.counter_census_digest!=canonical_digest(tuple(asdict(row)for row in control.counter_census))
                or not control.review_not_before_utc<control.review_due_utc<=control.readout_valid_until_utc
                or not control.next_boundary_utc<=control.readout_valid_until_utc):
            raise AuthorityUnavailable('single-event durable controls changed their exact original fields/window')
        seen.add(control.block_id)
        for token,revision in (control.adoption_ref,control.review_ref,control.scope_ref):
            if NamespaceId.from_key(AtomKey.from_token(token))!=namespace or revision<1:
                raise AuthorityUnavailable('single-event durable selector crossed namespace/current version')
        for row in (*control.guard_heads,*control.counter_census):
            if NamespaceId.from_key(AtomKey.from_token(row.ref))!=namespace or row.revision<0:
                raise AuthorityUnavailable('single-event durable current guard crossed namespace')
    return controls


def single_event_control_versions_v4(controls):
    versions={}
    for control in controls:
        for row in (*control.guard_heads,*control.counter_census):
            key=AtomKey.from_token(row.ref);version=GraphVersion(key,row.revision)
            if key in versions and versions[key]!=version:raise AuthorityUnavailable('single-event controls repeat a conflicting current guard')
            versions[key]=version
        for token,revision in (control.adoption_ref,control.review_ref,control.scope_ref):
            key=AtomKey.from_token(token);version=GraphVersion(key,revision)
            if key in versions and versions[key]!=version:raise AuthorityUnavailable('single-event control identity conflicts with its guard')
            versions[key]=version
    return tuple(sorted(versions.values(),key=lambda v:v.key.token))


def require_current_single_event_controls_v4(owner,controls):
    from .d01_ordinary_origin_read_v3 import _actual,_fixed
    _actual(owner)
    if not controls:return
    now=_now(owner);census,_=_counters(owner)
    for control in controls:
        if control.review_ref[1]>1:
            issued=_REVIEW_BY_OWNER.get(owner,{}).get(control.review_ref)
            if issued is not None:
                issued[0].require_current_v4();issued[1].require_current_v1(issued[0])
            else:
                actual=_current(owner,AtomKey.from_token(control.review_ref[0]),'single_event_review')
                if actual is None:
                    raise AuthorityUnavailable('single-event current review control disappeared')
                review=_review_value_v4(AtomKey.from_token(control.review_ref[0]),actual[1].metadata)
                if review.disposition in {'qualified','opposed','expired'} or now>=control.review_due_utc:
                    raise AuthorityUnavailable('single-event qualified control lacks its independently issued historical proof')
        if now>=control.next_boundary_utc or census!=control.counter_census:
            raise AuthorityUnavailable('single-event readout crossed its actual counter census/time boundary')
        for row in control.guard_heads:
            actual=_fixed(owner,'graph_atoms',('revision','valid','value_cell_id'),
                'token=? AND bot=? AND persona=?',(row.ref,*owner.namespace.as_tuple))
            expected=None if row.revision==0 else(row.revision,int(row.valid),row.cell_id)
            if actual!=expected:raise AuthorityUnavailable('single-event current trial/scope/Source guard changed')
        for token,revision in (control.adoption_ref,control.review_ref,control.scope_ref):
            actual=_fixed(owner,'graph_atoms',('revision','valid'),
                'token=? AND bot=? AND persona=?',(token,*owner.namespace.as_tuple))
            if actual!=(revision,1):raise AuthorityUnavailable('single-event actual control head changed')


def release_single_event_readout_v4(owner):
    _ORIGINS.pop(owner,None);_COUNTERS.pop(owner,None)
    _REVIEW_BY_OWNER.pop(owner,None)
    for proof in tuple(_REVIEWS):
        if proof.owner is owner:
            _REVIEW_METADATA.pop(proof,None);_REVIEWS.pop(proof,None)
    for prepared,identity in tuple(_PREPARED.items()):
        if identity[0]is owner:_PREPARED.pop(prepared,None)
