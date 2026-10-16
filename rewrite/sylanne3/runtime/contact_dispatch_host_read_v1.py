"""Installed Contact identity and fresh text reads over privately issued Works."""
from dataclasses import dataclass
from time import monotonic
from weakref import WeakKeyDictionary
import json
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import NamespaceId,canonical_digest
from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
_TEXT_WORKS=WeakKeyDictionary()

_IDENTITY_WORKS=WeakKeyDictionary()
@dataclass(frozen=True,slots=True)
class ContactDispatchIdentitySelectorV3:
    namespace:NamespaceId
    operation_id:str
    def __post_init__(self):
        if type(self.namespace)is not NamespaceId or type(self.operation_id)is not str or not self.operation_id:
            raise AuthorityUnavailable('Contact identity requires its exact namespace and actual committed operation locator')
    @property
    def stage(self):return 'dispatch_identity'

@dataclass(frozen=True,slots=True)
class _ContactDispatchIdentityCallV3:
    authority:object
    lease:object
    selector:ContactDispatchIdentitySelectorV3


@dataclass(frozen=True,slots=True)
class _ContactDispatchTextCallV1:
    installed:object
    authority:object
    lease:object
    request:object
    original:object
    segment:object

@dataclass(frozen=True,slots=True)
class ContactDispatchTextLocatorV1:
    namespace:NamespaceId
    contact_id:str
    segment_index:int
    segment_count:int
    operation_id:str
    effect_id:str
    request_digest:str
    dispatch_request_digest:str
    payload_digest:str
    whole_manifest_digest:str
    deadline_utc:float
    digest:str
    core_selector:object
    original_write_permit:object

class ContactDispatchTextLocatorReadV1:
    def __init__(self,state):
        self.state,self.row,self.task,self.complete=state,None,None,False
    def advance(self,meter):
        from .contact_continuation_v1 import TABLE,SIGN_KIND
        from .contact_dispatch_identity_metadata_v1 import _IdentityJSONEOFV1
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..runtime_contracts import canonical_serialize
        call=require_contact_dispatch_text_work_v1(self.state);state=self.state;ns=state.namespace
        if state.phase!='dispatch_text_locator' or not state.db.in_transaction:
            raise AuthorityUnavailable('Contact dispatch text locator requires its actual initial fixed metadata quantum')
        if self.row is None:
            self.row=_runtime_bounded_fixed_row_v3(state.db,meter,TABLE,('contact_id','segment_index','operation_id','effect_id','payload_digest','signature'),
                'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,call.request.operation_id))
            if self.row is None:raise AuthorityUnavailable('Contact dispatch text lacks its actual committed signed segment metadata locator')
            fields=('schema','namespace','contact_id','segment_index','segment_count','operation_id','effect_id','request_digest',
                'dispatch_request_digest','payload_digest','whole_manifest_digest','deadline_utc')
            self.task=_IdentityJSONEOFV1(state,table=TABLE,column='payload_json',where='bot=? AND persona=? AND operation_id=?',
                key=(*ns.as_tuple,call.request.operation_id),prefixes=tuple((name,)for name in fields)+
                (('core_observation','selector'),('background_invocation','scope','permit')))
        if not self.task.complete:self.task.advance(meter)
        if not self.task.complete:return
        value=self.task.value;row=self.row;request=call.request
        state.service.issuer._signer.verify(SIGN_KIND,canonical_serialize((ns,row[0],row[1],self.task.digest)),row[5])
        if (value['schema']!=SIGN_KIND or NamespaceId(**value['namespace'])!=ns or self.task.digest!=row[4]
                or row[:4]!=(request.footprint.contact_id,request.segment_index,request.operation_id,request.effect_id)
                or (value['contact_id'],value['segment_index'],value['segment_count'],value['operation_id'],value['effect_id'],value['payload_digest'],value['dispatch_request_digest'])!=
                    (request.footprint.contact_id,request.segment_index,request.segment_count,request.operation_id,request.effect_id,request.payload_digest,canonical_digest(request))):
            raise AuthorityUnavailable('Contact dispatch text fixed metadata locator differs from its actual installed request')
        from ..authority_service.v2_contract import from_wire
        permit=from_wire(value['background_invocation']['scope']['permit'])
        if request.segment_index:
            from ..authority_service.contact_continuation_contract_v1 import ContactContinuationSelectorV1,contact_continuation_from_wire_v1
            selected=contact_continuation_from_wire_v1(value['core_observation']['selector'],ContactContinuationSelectorV1)
            if (selected.namespace,selected.contact_id,selected.segment_index,selected.operation_id,selected.request_digest)!=(
                    ns,value['contact_id'],request.segment_index,request.operation_id,value['request_digest']):
                raise AuthorityUnavailable('Contact dispatch text metadata selected another actual Core continuation')
        else:selected=None
        if permit.operation!='write' or permit.namespace!=state.service.bundle.installation_policy.authority_namespace:
            raise AuthorityUnavailable('Contact dispatch text locator has another actual original WRITE namespace')
        self.result=ContactDispatchTextLocatorV1(ns,value['contact_id'],request.segment_index,request.segment_count,request.operation_id,request.effect_id,
            value['request_digest'],value['dispatch_request_digest'],value['payload_digest'],value['whole_manifest_digest'],value['deadline_utc'],self.task.digest,selected,permit)
        self.complete=True
    def release_v3(self):
        self.task,self.row=None,None

def finish_contact_dispatch_text_locator_v1(state):
    from .first_ingress_v2 import trusted_upper
    call=require_contact_dispatch_text_work_v1(state);reader=state.dispatch_text_locator
    if not reader.complete:raise AuthorityUnavailable('Contact dispatch text has no complete fixed signed metadata locator EOF')
    segment=reader.result
    now=trusted_upper(state.service.port.read_ingress_clock(state.graph._GraphCoordinator__scene_clock_policy))
    if now>=segment.deadline_utc:raise AuthorityUnavailable('Contact dispatch text cannot extend its original segment absolute TTL')
    state.operation.deadline_utc=state.work.deadline_utc=segment.deadline_utc
    state.initial_monotonic_deadline=monotonic()+(segment.deadline_utc-now)
    actual=_ContactDispatchTextCallV1(call.installed,call.authority,call.lease,call.request,call.original,segment)
    saved=_TEXT_WORKS[state];_TEXT_WORKS[state]=(actual,*saved[1:])

def require_contact_dispatch_text_work_v1(state):
    from .contact_host_stage_work_v3 import ContactHostStageReadWorkV3
    from .contact_host_source_v3 import require_contact_host_work_v3
    from .contact_dispatch_host_v3 import _INSTALLED
    if type(state)is not ContactHostStageReadWorkV3:
        raise AuthorityUnavailable('Contact dispatch text requires its actual fixed Host stage Work')
    require_contact_host_work_v3(state)
    saved=_TEXT_WORKS.get(state)
    if saved is None:raise AuthorityUnavailable('Contact dispatch text has no actual installed request issuer')
    call,service,graph,db,selector,operation,selection=saved
    if (_INSTALLED.get(id(call.installed))is not call.installed or call.installed.graph is not graph
            or state.service is not service or state.graph is not graph or state.db is not db
            or state.selector is not selector or state.operation is not operation or state.selection_digest!=selection
            or selector.stage!='dispatch_text' or selector.dispatch_request_digest!=canonical_digest(call.request)
            or selector.contact_id!=call.request.footprint.contact_id or state.namespace!=call.authority.namespace
            or state.authority is not call.authority or state.lease is not call.lease
            or graph._GraphCoordinator__owner_leases.get(call.lease)is not state.expected_owner_binding
            or graph._GraphCoordinator__owner_session_proofs.get(call.lease)is not state.owner_session_proof):
        raise AuthorityUnavailable('Contact dispatch text escaped its actual installed request/Owner lease/Source Work')
    return call

def require_current_contact_dispatch_text_owner_v1(state):
    require_contact_dispatch_text_work_v1(state)
    if state.owner_entry is None or state.owner_entry.require_for_v3(state)!=state.owner:
        raise AuthorityUnavailable('Contact dispatch text has no actual complete Owner metadata EOF')
    return state.owner

def observe_contact_dispatch_text_owner_v1(state):
    require_current_contact_dispatch_text_owner_v1(state)
    if state.db.in_transaction or state.store._lock._is_owned():
        raise AuthorityUnavailable('Contact dispatch permission observation must stay outside Graph SQL')
    return state.owner_entry.require_permission_v3(state),state.owner_entry.require_for_v3(state)

def _require_contact_dispatch_prefix_v1(state,call):
    if not call.segment.segment_index:return
    from ..host.contact_continuation_port_v1 import install_contact_continuation_port_v1
    observed,current=install_contact_continuation_port_v1(state.service.port,state.service.bundle).read_existing_contact_continuation_v1(
        call.segment.original_write_permit,call.segment.core_selector)
    if observed.selector!=call.segment.core_selector:
        raise AuthorityUnavailable('Contact dispatch current Core prefix differs from the actual signed metadata selector')
    state.dispatch_observation=observed
    state.dispatch_prefix=observed.prefix


def _require_contact_dispatch_prefix_in_read_v1(state):
    from ..authority_service.contact_effect_accounting_contract_v1 import ContactEffectAccountingRequestV1,from_wire as accounting_from_wire_v1
    call=require_contact_dispatch_text_work_v1(state)
    if not call.segment.segment_index:return
    captured=json.loads(state.dispatch_observation.inputs_json)['prefix']
    if len(state.dispatch_prefix)!=call.segment.segment_index or len(captured)!=len(state.dispatch_prefix):
        raise AuthorityUnavailable('Contact dispatch lacks every actual accepted/settled/finished prefix segment')
    for fact,raw in zip(state.dispatch_prefix,captured):
        current=state.service.port.read_current_effect(namespace=state.namespace,authority_namespace=state.scope.authority_namespace,effect_id=fact.effect_id)
        permit,status=state.service.port.get_fence_operation(namespace=state.namespace,authority_namespace=state.scope.authority_namespace,operation_id=fact.accounting_operation_id)
        request=accounting_from_wire_v1(raw['accounting_request'],ContactEffectAccountingRequestV1)
        if (current.state!='observed' or current.observation_outcome!='accepted' or current.mutation_id!=fact.observed_mutation_id
                or status!='finished' or permit.operation!='accounting' or permit.operation_id!=request.operation_id
                or permit.pinned_anchor!=request.expected_anchor or permit.subject!=state.scope.permit.subject
                or permit.holder!=state.scope.permit.holder or fact.accounting_finished is not True
                or fact.observation_outcome!='accepted' or fact.budget_status!='settled'):
            raise AuthorityUnavailable('Contact dispatch current prefix effect/accounting fence differs from its actual Core finished facts')

def open_contact_dispatch_text_authority_v1(state):
    from ..authority_service.owner_location_read_v3 import prepare_current_host_contact_dispatch_text_owner_entry_v3
    call=require_contact_dispatch_text_work_v1(state)
    if state.scope is not None:raise AuthorityUnavailable('Contact dispatch text cannot acquire another current READ')
    _require_contact_dispatch_prefix_v1(state,call)
    state.fence=state.graph._begin_read_fence_v3(call.authority,operation_id=state.operation_id,owner_session_proof=state.owner_session_proof)
    state.scope=state.read_scope=state.fence.scope
    state.owner_entry=prepare_current_host_contact_dispatch_text_owner_entry_v3(state)
    state.owner=state.owner_entry.require_for_v3(state)
    state.owner_guard=state.owner_entry.require_permission_v3(state)
    _require_contact_dispatch_prefix_in_read_v1(state)
    return call.authority

def prepare_contact_dispatch_text_work_v1(installed,graph,authority,lease,request,*,original=None):
    from ..dispatch_runtime import DispatchRequest
    from .contact_dispatch_host_v3 import _INSTALLED
    from .contact_host_stage_work_v3 import prepare_contact_host_stage_work_v3
    if (_INSTALLED.get(id(installed))is not installed or installed.graph is not graph or type(request)is not DispatchRequest
            or request.namespace!='/'.join(authority.namespace.as_tuple) or request.proactive_contact is not True
            or not 0<=request.segment_index<request.segment_count<=3):
        raise AuthorityUnavailable('Contact dispatch text requires its actual installed selected-segment request')
    graph._authorize(lease,authority,frozenset({'d08','d09','d10','d11'}),owner_read=True)
    service=graph._GraphCoordinator__contact_model_runtime_v2;service._current()
    work=prepare_contact_host_stage_work_v3(service,contact_id=request.footprint.contact_id,model_phase='contact_review',stage='dispatch_text',dispatch_request=request)
    state=work.state
    try:
        state.authority,state.lease=authority,lease
        state.expected_owner_binding=graph._GraphCoordinator__owner_leases[lease]
        state.owner_session_proof=graph._GraphCoordinator__owner_session_proofs[lease]
        state.read_scope=None;state.initial_monotonic_deadline=None
        call=_ContactDispatchTextCallV1(installed,authority,lease,request,original,None)
        _TEXT_WORKS[state]=(call,service,graph,state.db,state.selector,state.operation,state.selection_digest)
        state.issued_capabilities.append((_TEXT_WORKS,state))
        state.dispatch_text_locator=ContactDispatchTextLocatorReadV1(state)
        state.phase='dispatch_text_locator'
        def require_before_owner_v3():
            require_contact_dispatch_text_work_v1(state)
            if state.scope is None or state.read_scope is not state.scope or state.phase!='authorize':
                raise AuthorityUnavailable('Contact dispatch text Owner EOF lacks its actual initial READ and authorization phase')
            return state
        state.require_before_owner_v3=require_before_owner_v3
        def result(actual):
            if actual is not state or not state.complete:
                raise AuthorityUnavailable('Contact dispatch text result left its actual completed Work')
            return state.result
        work.map_terminal_v3('issuer',result,lambda error:(_ for _ in ()).throw(error))
        return work
    except BaseException:
        from ..runtime_storage_v3 import finish_runtime_storage_operation_v3
        state.release_payload_v3()
        finish_runtime_storage_operation_v3(state.operation)
        raise

def read_qualified_contact_dispatch_text_v1(state):
    from .contact_host_source_v3 import require_contact_host_material_scope_v3
    from .contact_p2_birth_v1 import read_contact_p2_birth_v1
    from .contact_batch_current_v3 import require_current_contact_batch_v3
    from .contact_continuation_v1 import read_contact_segment_original_v1
    from ..host.astrbot_dispatch import ResolvedTextPayload
    from .jobs import get_job
    from sys import getsizeof
    call=require_contact_dispatch_text_work_v1(state);request=call.request;db=state.db
    if state.phase!='semantic' or not db.in_transaction or state.source_material is None:
        raise AuthorityUnavailable('Contact dispatch text lacks its complete same-Work Source/Owner/current-policy frame')
    require_contact_host_material_scope_v3(state.source_material,work=state,db=db)
    prepared,frozen,plan,expression,raw=state.service._original(db,state.selector.contact_id,state.selector.model_phase)
    state.service._content(db,(prepared,frozen,plan,expression,raw),state.now_utc,state.owner_guard)
    state.prepared=prepared
    if request.segment_index:
        from .contact_continuation_p2_v1 import read_contact_continuation_p2_birth_v1
        birth=read_contact_continuation_p2_birth_v1(db,namespace=state.namespace,operation_id=request.operation_id,issuer=state.contact_issuer)
    else:birth=read_contact_p2_birth_v1(db,namespace=state.namespace,operation_id=request.operation_id)
    segment=read_contact_segment_original_v1(db,namespace=state.namespace,contact_id=request.footprint.contact_id,segment_index=request.segment_index,issuer=state.contact_issuer)
    if (segment is None or segment.digest!=call.segment.digest or segment.request_digest!=call.segment.request_digest
            or (segment.namespace,segment.contact_id,segment.segment_index,segment.operation_id,segment.effect_id)!=(state.namespace,request.footprint.contact_id,request.segment_index,request.operation_id,request.effect_id)
            or birth.request!=request or segment.admission_ref!=birth.admission.admission.admission_ref
            or call.original is not None and (call.original.request!=birth.request or call.original.admission!=birth.admission)):
        raise AuthorityUnavailable('Contact dispatch text same-Work birth/admission/segment identity changed')
    if request.segment_index:
        from ..authority_service.contact_continuation_contract_v1 import ContactContinuationObservationV1,contact_continuation_from_wire_v1
        if contact_continuation_from_wire_v1(segment.core_observation,ContactContinuationObservationV1)!=state.dispatch_observation:
            raise AuthorityUnavailable('Contact dispatch full same-Work segment differs from the authenticated current Core original')
    birth.admission.admission.require_current(state.now_utc)
    batch,proof,_=require_current_contact_batch_v3(db,namespace=state.namespace,batch_ref=birth.batch_ref,
        operation_id=segment.first_operation_id,generation=request.activation_generation,graph_incarnation=birth.admission.admission.graph_incarnation)
    policy=state.contact_policy
    if (proof.qualification.check_versions.owner_policy_ref!=policy.original_ref or proof.qualification.check_versions.owner_policy_digest!=policy.digest
            or birth.qualification.audience!=batch.content.audience_id or len(batch.content.segments)!=request.segment_count
            or batch.segment_manifest_digest!=segment.whole_manifest_digest or batch.content.digest!=segment.reviewed_content_digest or not state.now_utc<min(batch.content.valid_until,segment.deadline_utc)):
        raise AuthorityUnavailable('Contact dispatch text current signed policy/whole manifest/original deadline changed')
    from ..graph_types import AtomKey
    job=get_job(db,AtomKey.from_token(birth.job_ref).name)
    outbox=db.execute('SELECT phase FROM graph_bundle_outbox WHERE bot=? AND persona=? AND outbox_ref=?',(*state.namespace.as_tuple,birth.outbox_ref)).fetchone()
    if (job.phase!='waiting' or job.cancel_epoch!=0 or job.fence!=0 or job.operation_id!=request.operation_id
            or job.effect_id!=request.effect_id or outbox!=('pending',)):
        raise AuthorityUnavailable('Contact dispatch text has no current unconsumed job/outbox')
    selected=batch.content.segments[request.segment_index]
    if selected.segment.effect_id!=request.effect_id or selected.payload_digest!=request.payload_digest:
        raise AuthorityUnavailable('Contact dispatch text selected another signed segment/effect/payload')
    account=json.loads(birth.admission.admission.account_ref);destination=json.loads(birth.admission.admission.destination_ref)
    body=selected.segment.body
    size=sum(1 if ord(c)<128 else 2 if ord(c)<2048 else 3 if ord(c)<65536 else 4 for c in body)
    state.operation.retain(size+getsizeof(b'')+256)
    return ResolvedTextPayload(body.encode('utf-8'),(),selected.segment.claim_uses,request.namespace,*account,*destination,batch.content.scene_id)


def require_contact_dispatch_identity_work_v3(state,*,db=None):
    from .contact_host_stage_work_v3 import ContactHostStageReadWorkV3
    from .contact_host_source_v3 import require_contact_host_work_v3
    if type(state)is not ContactHostStageReadWorkV3 or type(state.selector)is not ContactDispatchIdentitySelectorV3:
        raise AuthorityUnavailable('Contact identity cannot borrow a Source/body stage or generic Owner read')
    require_contact_host_work_v3(state,db=db)
    saved=_IDENTITY_WORKS.get(state)
    if saved is None:raise AuthorityUnavailable('Contact identity has no actual committed-operation lookup issuer')
    call,service,graph,actual_db,selector,operation,selection=saved
    if (state.service is not service or state.graph is not graph or state.db is not actual_db
            or state.selector is not selector or state.operation is not operation or state.selection_digest!=selection
            or state.authority is not call.authority or state.lease is not call.lease or call.selector is not selector
            or state.namespace!=call.authority.namespace or state.operation.deadline_utc is not None
            or state.work.deadline_utc is not None or state.initial_monotonic_deadline is not None
            or graph._GraphCoordinator__owner_leases.get(call.lease)is not state.expected_owner_binding
            or graph._GraphCoordinator__owner_session_proofs.get(call.lease)is not state.owner_session_proof
            or state.phase not in {'dispatch_identity_locator','dispatch_identity_authorize','dispatch_identity_metadata','dispatch_identity_validate','dispatch_identity_complete'}):
        raise AuthorityUnavailable('Contact identity escaped its actual metadata-only Work/Owner session/request namespace')
    if state.scope is not None and (state.read_scope is not state.scope or state.scope.operation!='read'
            or state.fence.scope is not state.scope or state.graph_stamp!=(state.fence.metadata,state.fence.epoch)):
        raise AuthorityUnavailable('Contact identity changed its actual independent current READ scope')
    return state

def prepare_contact_dispatch_identity_work_v3(graph,authority,lease,operation_id):
    from .contact_host_stage_work_v3 import ContactHostStageReadWorkV3,_HOST_ISSUER
    from .contact_dispatch_identity_metadata_v1 import ContactDispatchIdentityMetadataReadV1
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from ..runtime_storage_v3 import begin_runtime_storage_operation_v3,finish_runtime_storage_operation_v3
    import secrets
    require_graph_storage_work_admission_v3(graph)
    graph._authorize(lease,authority,frozenset({'d08','d09','d10','d11'}),owner_read=True)
    service=graph._GraphCoordinator__contact_model_runtime_v2;service._current()
    selector=ContactDispatchIdentitySelectorV3(authority.namespace,operation_id)
    read_id='contact-dispatch-identity-read:'+secrets.token_hex(16)
    operation=begin_runtime_storage_operation_v3(service.store._db,read_id,None)
    state=None
    try:
        state=ContactHostStageReadWorkV3(_HOST_ISSUER,service,selector,operation)
        work=create_graph_storage_work_v3(graph,kind='contact_host_stage_read_v3',operation_id=read_id,
            selection_digest=operation.selection_digest,deadline_utc=None,state=state,operation=operation)
        state.work=work
        state.authority,state.lease=authority,lease
        state.expected_owner_binding=graph._GraphCoordinator__owner_leases[lease]
        state.owner_session_proof=graph._GraphCoordinator__owner_session_proofs[lease]
        state.read_scope=None;state.initial_monotonic_deadline=None
        state.phase='dispatch_identity_locator'
        call=_ContactDispatchIdentityCallV3(authority,lease,selector)
        _IDENTITY_WORKS[state]=(call,service,graph,state.db,selector,operation,operation.selection_digest)
        state.issued_capabilities.append((_IDENTITY_WORKS,state))
        def require_before_owner_v3():
            require_contact_dispatch_identity_work_v3(state)
            if state.scope is None or state.phase!='dispatch_identity_authorize':
                raise AuthorityUnavailable('Contact identity Owner EOF must use the actual initial READ scope')
            return state
        state.require_before_owner_v3=require_before_owner_v3
        state.dispatch_identity_recipe=ContactDispatchIdentityMetadataReadV1(state)
        def result(actual):
            if actual is not state or not state.complete:
                raise AuthorityUnavailable('Contact identity result left its actual completed metadata Work')
            return state.result
        work.map_terminal_v3('issuer',result,lambda error:(_ for _ in ()).throw(error))
        return work
    except BaseException:
        if state is not None:state.release_payload_v3()
        finish_runtime_storage_operation_v3(operation)
        raise

def advance_contact_dispatch_identity_work_v3(graph,work):
    from ..graph_worker import GraphStorageStepV3
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    from ..authority_service.owner_location_read_v3 import prepare_current_host_contact_dispatch_identity_owner_entry_v3
    state=require_contact_dispatch_identity_work_v3(work.state)
    if state.graph is not graph:raise AuthorityUnavailable('Contact identity Work belongs to another actual Graph')
    with bind_runtime_storage_operation_v3(state.operation,state.db):
        if state.phase=='dispatch_identity_authorize':
            state.fence=graph._begin_read_fence_v3(state.authority,operation_id=state.operation_id,owner_session_proof=state.owner_session_proof)
            state.scope=state.read_scope=state.fence.scope
            state.owner_entry=prepare_current_host_contact_dispatch_identity_owner_entry_v3(state)
            state.owner=state.owner_entry.require_for_v3(state)
            state.owner_guard=state.owner_entry.require_permission_v3(state)
            state.phase='dispatch_identity_metadata'
            return GraphStorageStepV3('progress')
        if state.phase=='dispatch_identity_validate':
            if state.owner_entry.require_for_v3(state)!=state.owner or state.owner_entry.require_permission_v3(state)!=state.owner_guard:
                raise AuthorityUnavailable('Contact identity actual current Owner/session changed before metadata publication')
            graph._validate_read_fence_v3(state.fence)
            state.phase='dispatch_identity_complete';state.complete=True
            return GraphStorageStepV3('complete',state)
        if state.scope is not None:state.service.port.validate_fence(state.scope)
        with state.store._lock,runtime_storage_quantum_v3(state.db)as meter:
            state.db.execute('BEGIN')
            try:
                state.require_current(meter=meter)
                if state.phase=='dispatch_identity_locator':
                    state.dispatch_identity_recipe.advance_locator_v1(meter)
                    if state.dispatch_identity_recipe.locator_complete:
                        state.phase='dispatch_identity_authorize'
                elif state.phase=='dispatch_identity_metadata':
                    if state.owner_entry.require_for_v3(state)!=state.owner:
                        raise AuthorityUnavailable('Contact identity metadata lost its actual Owner EOF')
                    state.dispatch_identity_recipe.advance_metadata_v1(meter)
                    if state.dispatch_identity_recipe.complete:
                        state.result=state.dispatch_identity_recipe.require_for_v1(state,state.db)[0]
                        state.phase='dispatch_identity_validate'
                else:raise AuthorityUnavailable('Contact identity metadata has an unknown fixed phase')
            finally:state.db.rollback()
        if state.scope is not None:state.service.port.validate_fence(state.scope)
    return GraphStorageStepV3('progress')
