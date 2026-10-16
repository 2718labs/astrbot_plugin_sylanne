"""Closed Numeric seal and paid producer Work entries; Source facts do not grant a read."""
from dataclasses import dataclass
from uuid import uuid4
from weakref import WeakKeyDictionary
from contextvars import ContextVar
import time

from ..authority_service.contract import AuthorityUnavailable
from ..graph_worker import GraphStorageStepV3, create_graph_storage_work_v3, require_graph_storage_work_admission_v3
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import begin_runtime_storage_operation_v3, bind_runtime_storage_operation_v3, finish_runtime_storage_operation_v3, runtime_storage_quantum_v3
from .dispatch_current_inventory_v3 import _freeze_value_v3, _detach_value_v3, _heap

NUMERIC_SEAL_WORK_KIND_V3 = 'current_life_numeric_model_seal_v3'
_SEALS = WeakKeyDictionary()
_OBSERVATIONS = WeakKeyDictionary()
_SEAL_APPEND = ContextVar("numeric_actual_call_seal_append_v3",default=None)
_SEAL_COLUMN_ISSUER=object()
_SEAL_COLUMNS=WeakKeyDictionary()


class _NumericModelSealObservationV3:
    def __init__(self, graph, bundle, intent, permit, stamp, value):
        self.graph, self.bundle, self.intent, self.permit, self.stamp = graph, bundle, intent, permit, stamp
        self.value = _freeze_value_v3(value)
        _OBSERVATIONS[self] = (graph, bundle, intent, permit, stamp, self.value)

    def require_v3(self, graph, bundle, intent, permit, stamp):
        if _OBSERVATIONS.get(self) != (graph, bundle, intent, permit, stamp, self.value):
            raise AuthorityUnavailable('Numeric seal observer changed its actual installed original/permission')
        return _detach_value_v3(self.value)


def _capture_numeric_model_seal_observation_v3(graph, bundle, intent, permit, stamp, host_selection_digest):
    from ..authority_service.life_numeric_source_read_v3 import NUMERIC_MODEL_SEAL_OBSERVER_METHOD_V3, NUMERIC_MODEL_SEAL_OBSERVER_SIGN_V3, NUMERIC_MODEL_SEAL_OBSERVER_SCHEMA_V3
    from ..authority_service.v2_model_egress_wire import to_wire as model_to_wire
    from ..authority_service.v2_contract import to_wire as fence_to_wire, SCHEMA
    port = graph._GraphCoordinator__content_fence_v2
    command = {'namespace':intent.namespace, 'installation_id':bundle.installation_policy.installation_id,
        'intent':model_to_wire(intent), 'permit':fence_to_wire(permit),
        'graph_stamp_digest':canonical_digest(stamp), 'clock_policy_digest':canonical_digest(bundle.ingress_clock),
        'host_selection_digest':host_selection_digest}
    async def call():
        await port._mapped(bundle.installation_policy.namespace, intent.namespace)
        handshake, grant = port._identity()
        if (grant.authority_id, grant.subject, grant.administrator_holder, grant.installation_id) != (
                permit.authority_id, permit.subject, permit.holder, command['installation_id']):
            raise AuthorityUnavailable('Numeric seal observer crossed actual Host pairing')
        result = await port._transport._content_rpc(port._request, handshake,
            NUMERIC_MODEL_SEAL_OBSERVER_METHOD_V3, command, protocol=SCHEMA)
        if set(result) != {'observation','signature','channel_binding_sha256'} or result['channel_binding_sha256'] != grant.channel_binding_sha256 or grant.channel_binding_sha256 != handshake.channel_binding_sha256:
            raise AuthorityUnavailable('Numeric seal observer authenticated response differs')
        raw = result['observation']
        graph._GraphCoordinator__d11_issuer._signer.verify(NUMERIC_MODEL_SEAL_OBSERVER_SIGN_V3,
            canonical_serialize(raw), result['signature'])
        expected = {'schema','namespace','authority_namespace','authority_id','installation_id','subject','holder',
            'intent_digest','permit','graph_stamp_digest','clock_policy_digest','current_owner_authority','principal',
            'prepared_digest','binding_digest','request_digest','episode_ref','causal_operation_id','core_selection_digest','host_selection_digest','job_digest','source_versions','owner_grant_digest','owner_permissions','current_scope_digest','original_deadline_utc'}
        if (set(raw) != expected or raw['schema'] != NUMERIC_MODEL_SEAL_OBSERVER_SCHEMA_V3
                or raw['namespace'] != list(bundle.installation_policy.namespace.as_tuple)
                or (raw['authority_namespace'],raw['authority_id'],raw['installation_id'],raw['subject'],raw['holder']) !=
                   (intent.namespace,intent.authority_id,command['installation_id'],permit.subject,permit.holder)
                or raw['intent_digest'] != canonical_digest(model_to_wire(intent)) or raw['permit'] != fence_to_wire(permit)
                or raw['graph_stamp_digest'] != command['graph_stamp_digest']
                or raw['clock_policy_digest'] != command['clock_policy_digest']
                or raw['host_selection_digest'] != host_selection_digest
                or raw['binding_digest'] != intent.binding_digest or raw['request_digest'] != intent.request_digest):
            raise AuthorityUnavailable('Numeric seal signed metadata lost exact original/model/Owner/Source binding')
        return _NumericModelSealObservationV3(graph,bundle,intent,permit,stamp,raw)
    return port._submit(port._with_session_repair(call))


from .contact_cost_metadata_v3 import _CostColumnV3


def _numeric_seal_prior_request_v3(state):
    return ('graph_d11_life_originals_v1',('producing_operation_id','payload_json','payload_digest','signature'),
        ('bot','persona','kind','original_ref'),(*state.namespace.as_tuple,'numeric_call_v1',state.intent.job_id))


class _NumericSealPriorColumnV3(_CostColumnV3):
    def __init__(self,issuer,state):
        if issuer is not _SEAL_COLUMN_ISSUER or type(self)is not _NumericSealPriorColumnV3:
            raise AuthorityUnavailable('Numeric call prior column private issuer required')
        request=_numeric_seal_prior_request_v3(state)
        _SEAL_COLUMNS[self]=(state,request)
        super().__init__(state,request)


def require_numeric_seal_prior_column_v3(column):
    if type(column)is not _NumericSealPriorColumnV3:return None
    state=column.owner
    if (type(state)is not _NumericModelSealStateV3
            or _SEALS.get(state)!=(state.graph,state.authority,state.lease,state.intent,state.permit,state.operation,state.work)
            or _SEAL_COLUMNS.get(column)!=(state,column.request)
            or column.request!=_numeric_seal_prior_request_v3(state)
            or state.observation is None or state.operation.closed
            or state.work.kind!=NUMERIC_SEAL_WORK_KIND_V3):
        raise AuthorityUnavailable('Numeric call prior requires its exact retained seal Work and fixed recipe')
    state.work._require_invocation(state.graph)
    state.observation.require_v3(state.graph,state.bundle,state.intent,state.permit,state.stamp)
    return state


class _NumericModelSealStateV3:
    def __init__(self, graph, authority, lease, bundle, intent, permit, operation):
        self.graph, self.authority, self.lease, self.bundle = graph, authority, lease, bundle
        self.intent, self.permit, self.operation = intent, permit, operation
        self.observation = None; self.stamp = None; self.work = None
        self.store,self.db=graph._GraphCoordinator__store,graph._GraphCoordinator__store._db
        self.namespace=authority.namespace;self.prior=None
    def require_current(self,*,meter):
        if _SEALS.get(self)!=(self.graph,self.authority,self.lease,self.intent,self.permit,self.operation,self.work):
            raise AuthorityUnavailable("Numeric seal prior metadata lost its real Work")
        self.work._require_invocation(self.graph);self.operation.handle.require_current(meter)
        if self.graph._v2_graph_stamp(self.namespace)!=self.stamp:
            raise AuthorityUnavailable("Numeric call prior metadata Graph stamp changed")
        return self
    def _runtime_retained_heap_bytes_v3(self):
        return _heap((self.intent,self.permit,self.stamp,None if self.observation is None else self.observation.value))


def prepare_current_life_numeric_call_seal_v3(graph, authority, lease, *, episode_ref, causal_operation_id, job_id, intent, permit):
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    from ..authority_service.v2_contract import FencePermitV2
    from .current_life_numeric_read_v3 import ReadCurrentLifeNumericModelDraftRequestV3
    from .first_ingress_v2 import trusted_upper
    require_graph_storage_work_admission_v3(graph)
    ReadCurrentLifeNumericModelDraftRequestV3(episode_ref,causal_operation_id,job_id)
    if (type(intent) is not ModelEgressIntentV1 or type(permit) is not FencePermitV2
            or intent.job_id != job_id or permit.operation != 'model_egress'
            or permit.operation_id != intent.operation_id or permit.subject != intent.subject):
        raise AuthorityUnavailable('Numeric call seal needs the actual prepared original MODEL permission')
    graph._authorize(lease,authority,frozenset({'d11'}),owner_read=True)
    owner = graph._GraphCoordinator__owner_leases.get(lease)
    session = graph._GraphCoordinator__owner_session_proofs.get(lease)
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if owner is None or session is None or assembly is None or 'workbench.create' not in owner.capabilities:
        raise AuthorityUnavailable('Numeric call seal actual current Owner/session unavailable')
    bundle = assembly.admin_bundle
    if bundle.installation_policy.namespace != authority.namespace or intent.namespace != bundle.installation_policy.authority_namespace:
        raise AuthorityUnavailable('Numeric call seal crossed actual installation/namespace')
    now = trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(bundle.ingress_clock))
    operation = begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,'numeric-call-seal:'+uuid4().hex,now+60.0)
    state = _NumericModelSealStateV3(graph,authority,lease,bundle,intent,permit,operation)
    state.episode_ref,state.causal_operation_id,state.job_id = episode_ref,causal_operation_id,job_id
    state.owner,state.session,state.monotonic_deadline = owner,session,time.monotonic()+60.0
    operation.register_retained_state_v3(state)
    work = create_graph_storage_work_v3(graph,kind=NUMERIC_SEAL_WORK_KIND_V3,operation_id=operation.operation_id,
        selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=state,operation=operation)
    state.work = work; _SEALS[state] = (graph,authority,lease,intent,permit,operation,work)
    return work


def advance_current_life_numeric_call_seal_v3(graph, work):
    from .first_ingress_v2 import trusted_upper
    from ..authority_service.d12_target_owner_admission_v1 import current_owner_authority_from_wire_v1
    from ..authority_service.v2_owner_contract import OwnerPrincipalV1
    state = work.state
    if _SEALS.get(state) != (graph,state.authority,state.lease,state.intent,state.permit,work.operation,work):
        raise AuthorityUnavailable('Numeric call seal lost its exact original Work')
    work._require_invocation(graph)
    store = graph._GraphCoordinator__store; port = graph._GraphCoordinator__content_fence_v2
    with bind_runtime_storage_operation_v3(work.operation,store._db):
        if state.observation is None:
            with store._lock,runtime_storage_quantum_v3(store._db): state.stamp = graph._v2_graph_stamp(state.authority.namespace)
            state.observation = _capture_numeric_model_seal_observation_v3(graph,state.bundle,state.intent,state.permit,state.stamp,work.selection_digest)
            original=state.observation.require_v3(graph,state.bundle,state.intent,state.permit,state.stamp)
            now=trusted_upper(port.read_ingress_clock(state.bundle.ingress_clock))
            deadline=min(work.deadline_utc,original['original_deadline_utc'])
            if now>=deadline:raise AuthorityUnavailable('Numeric model seal original deadline ended during observation')
            work.deadline_utc=work.operation.deadline_utc=deadline
            state.monotonic_deadline=min(state.monotonic_deadline,time.monotonic()+deadline-now)
            return GraphStorageStepV3('progress')
        raw = state.observation.require_v3(graph,state.bundle,state.intent,state.permit,state.stamp)
        owner = current_owner_authority_from_wire_v1(raw['current_owner_authority'])
        principal = OwnerPrincipalV1(**raw['principal'])
        now = trusted_upper(port.read_ingress_clock(state.bundle.ingress_clock))
        if ((raw['episode_ref'],raw['causal_operation_id'],raw['host_selection_digest']) !=
                (state.episode_ref,state.causal_operation_id,work.selection_digest)
                or now >= min(work.deadline_utc,raw['original_deadline_utc']) or time.monotonic() >= state.monotonic_deadline
                or graph._GraphCoordinator__owner_leases.get(state.lease) is not state.owner
                or graph._GraphCoordinator__owner_session_proofs.get(state.lease) != state.session
                or state.owner.principal != principal or state.owner.authorization_head != owner.guard.authorization_head
                or state.owner.grant_digest != raw['owner_grant_digest']
                or any(tuple(raw['owner_permissions'][name]) != tuple(getattr(state.owner,name)) for name in ('capabilities','purposes','audiences'))
                or any(raw['owner_permissions'][name] != getattr(state.owner,name) for name in ('scope','issuer_ref','grant_id','grant_revision'))):
            raise AuthorityUnavailable('Numeric call seal current Owner or original deadline changed')
        observed, status = port.get_fence_operation(namespace=state.authority.namespace,
            authority_namespace=state.intent.namespace,operation_id=state.intent.operation_id)
        from ..runtime_contracts import FenceScope
        scope = FenceScope(state.authority.namespace,state.intent.namespace,state.permit.generation,'model_egress',
            state.permit.operation_id,state.permit,state.permit.pinned_anchor,state.stamp[1],state.stamp[0].graph_revision)
        if observed != state.permit or status != 'active' or port.validate_fence(scope) != state.permit:
            raise AuthorityUnavailable('Numeric call seal original MODEL permission is no longer active')
        if state.prior is None:
            state.prior=_NumericSealPriorColumnV3(_SEAL_COLUMN_ISSUER,state)
        if not state.prior.complete:
            with store._lock,runtime_storage_quantum_v3(store._db)as meter:
                db=store._db;db.execute("BEGIN")
                try:state.prior.advance(meter)
                finally:db.rollback()
            return GraphStorageStepV3("progress")
        with store._lock,runtime_storage_quantum_v3(store._db):
            db = store._db; db.execute('BEGIN IMMEDIATE')
            append_token=_SEAL_APPEND.set(state)
            try:
                if graph._v2_graph_stamp(state.authority.namespace) != state.stamp:
                    raise AuthorityUnavailable('Numeric model admission Graph stamp changed before original seal')
                from .d06_life_numeric_paid_v1 import append_current_life_numeric_call_seal_v3
                result = append_current_life_numeric_call_seal_v3(db,namespace=state.authority.namespace,
                    issuer=graph._GraphCoordinator__d11_issuer,intent=state.intent,permit=state.permit,
                    state=state,prepared_digest=raw['prepared_digest'],binding_digest=raw['binding_digest'],request_digest=raw['request_digest'])
                db.commit()
            except BaseException:
                db.rollback(); raise
            finally:_SEAL_APPEND.reset(append_token)
        return GraphStorageStepV3('complete',result)


def read_bound_numeric_seal_point_v3(db,*,table,columns,key_columns,key):
    state=_SEAL_APPEND.get()
    if state is None:return False,None
    expected=("graph_d11_life_originals_v1",("producing_operation_id","payload_json","payload_digest","signature"),
        ("bot","persona","kind","original_ref"),(*state.namespace.as_tuple,"numeric_call_v1",state.intent.job_id))
    if db is not state.db or (table,tuple(columns),tuple(key_columns),tuple(key))!=expected or state.prior is None:
        raise AuthorityUnavailable("Numeric seal append prior escaped its fixed actual call selector")
    with runtime_storage_quantum_v3(db)as meter:row=state.prior.require_row(meter)
    if row is not None:
        import json
        from .d11_life_preparation_v1 import SIGN_KIND
        value=json.loads(row[1]);raw=state.observation.require_v3(state.graph,state.bundle,state.intent,state.permit,state.stamp)
        from ..authority_service.v2_model_egress_wire import to_wire as model_wire
        from ..authority_service.v2_contract import to_wire as permit_wire
        expected_value={"schema":"d06.internal-life-numeric-call.v1","prepared_digest":raw["prepared_digest"],
            "binding_digest":raw["binding_digest"],"request_digest":raw["request_digest"],"intent":model_wire(state.intent),"permit":permit_wire(state.permit)}
        if value!=expected_value or row[0]!=state.intent.acquire_operation_id or row[2]!=canonical_digest(value):
            raise AuthorityUnavailable("Numeric seal actual immutable prior call metadata differs")
        state.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,canonical_serialize((state.namespace,"numeric_call_v1",state.intent.job_id,row[2])),row[3])
    return True,row

def require_current_life_numeric_call_seal_v3(state,db,intent,permit):
    saved = _SEALS.get(state)
    if (saved is None or saved[0]._GraphCoordinator__store._db is not db or saved[3] is not intent
            or saved[4] is not permit or state.observation is None or not db.in_transaction):
        raise AuthorityUnavailable('Numeric call append has no real Source-qualified MODEL Work')
    state.work._require_invocation(state.graph)
    return state.observation.require_v3(state.graph,state.bundle,intent,permit,state.stamp)


def finish_current_life_numeric_call_seal_v3(graph, work, error):
    state = work.state
    _SEALS.pop(state,None)
    if state.observation is not None: _OBSERVATIONS.pop(state.observation,None)
    if state.prior is not None:_SEAL_COLUMNS.pop(state.prior,None)
    state.observation = None;state.prior=None
    work.operation.unregister_retained_state_v3(state)
    finish_runtime_storage_operation_v3(work.operation)


NUMERIC_PAID_WORK_KIND_V3 = 'current_life_numeric_paid_write_v3'
NUMERIC_SELECTOR_OPERATION_V3 = 'prepare_current_life_numeric_result_read_v3'
NUMERIC_PAID_OPERATION_V3 = 'record_current_life_numeric_paid_result_v3'
_PAID_WORKS = WeakKeyDictionary()
_PAID_SOURCES = WeakKeyDictionary()
_PAID_WRITES = WeakKeyDictionary()
_PAID_QUALIFICATIONS = WeakKeyDictionary()

@dataclass(frozen=True,slots=True)
class _NumericPaidWriteRequestV3:
    episode_ref:str
    causal_operation_id:str
    job_id:str
    attempt:int = 1
    delivery:object = None
    fact:object = None

@dataclass(frozen=True,slots=True)
class CurrentLifeNumericPaidCandidateV3:
    producing_operation_id:str
    cost_digest:str

class _NumericPaidResultV3:
    def __init__(self, reader, value, facts=None):
        self.reader,self.value = reader,value
        _PAID_QUALIFICATIONS[self] = (reader,reader.work,reader.operation,value,facts)
    def require_result_v3(self,work):
        saved=_PAID_QUALIFICATIONS.get(self)
        if saved is None or saved[1] is not work or saved[2] is not work.operation:
            raise AuthorityUnavailable('Numeric paid result changed its actual producer Work')
        return self.value if self.reader.operation_kind==NUMERIC_SELECTOR_OPERATION_V3 else self
    def qualify_candidate_v3(self,candidate):
        if type(candidate) is not CurrentLifeNumericPaidCandidateV3:
            raise TypeError('Numeric paid candidate exposes only producing operation and cost digest')
        saved = _PAID_QUALIFICATIONS.get(self)
        if saved is None or saved[0] is not self.reader or saved[3] is not self.value or saved[4] is None:
            raise AuthorityUnavailable('Numeric paid candidate lacks its actual retained producer qualification')
        p,b,model,cost = saved[4]
        from .d06_life_numeric_paid_v1 import require_life_numeric_paid_membership_v3
        from ..domains.d01.production_operations_v1 import plain_v1
        require_life_numeric_paid_membership_v3(producing_operation_id=candidate.producing_operation_id,
            prepared_digest=p.digest,binding_digest=b.digest,cost_value=plain_v1(cost),
            cost_digest=candidate.cost_digest,result_request_digest=model.digest,prepared=p,binding=b,model=model,cost=cost)
    def release_payload_v3(self):
        saved = _PAID_QUALIFICATIONS.pop(self,None)
        if saved is not None: _release_numeric_paid_reader_v3(saved[0])
        self.reader=self.value=None


def _paid_identity_v3(r):
    return (r.graph,r.runtime,r.authority,r.lease,r.fence,r.operation,r.request,r.request_digest,r.operation_kind,
        r.work,r.selection_digest,r.operation_id,r.parent_budget_lease_ref,r.session_proof)


def require_numeric_paid_write_work_v3(r):
    from .current_method_learning_read_v3 import _MethodLearningReadV3,_READERS,_NUMERIC_PAID_WRITE_OPERATIONS_V3
    from ..graph_worker import GraphStorageWorkV3
    if (type(r) is not _MethodLearningReadV3 or r not in _READERS
            or r.operation_kind not in _NUMERIC_PAID_WRITE_OPERATIONS_V3
            or _PAID_WORKS.get(r) != _paid_identity_v3(r) or type(r.work) is not GraphStorageWorkV3
            or r.work.kind != NUMERIC_PAID_WORK_KIND_V3 or r.work.state is not r or r.work.operation is not r.operation
            or r.work.coordinator is not r.graph or r.operation.closed or r.session_proof is None
            or r.fence.scope.operation != 'read' or r.runtime is not r.graph._GraphCoordinator__domain_production_runtime_v1
            or any((r.background_followup,r.background_host_lifecycle,r.background_offline))
            or 'workbench.create' not in r.owner_binding.capabilities):
        raise AuthorityUnavailable('Numeric paid writer requires its own exact actual Owner Work')
    r.work._require_invocation(r.graph)
    return r


def prepare_current_life_numeric_paid_write_v3(graph,authority,lease,*,operation_kind,episode_ref,causal_operation_id,job_id,attempt=1,delivery=None,fact=None):
    from .current_method_learning_read_v3 import begin_current_method_learning_read_v3
    from .current_life_numeric_read_v3 import ReadCurrentLifeNumericModelDraftRequestV3
    from .first_ingress_v2 import trusted_upper
    from ..authority_service.current_life_numeric_v1 import LifeNumericModelResultReadV1
    require_graph_storage_work_admission_v3(graph)
    ReadCurrentLifeNumericModelDraftRequestV3(episode_ref,causal_operation_id,job_id)
    if (operation_kind not in (NUMERIC_SELECTOR_OPERATION_V3,NUMERIC_PAID_OPERATION_V3)
            or type(attempt) is not int or not 1 <= attempt <= 64
            or operation_kind == NUMERIC_SELECTOR_OPERATION_V3 and (delivery is not None or fact is not None)
            or operation_kind == NUMERIC_PAID_OPERATION_V3 and (type(delivery) is not LifeNumericModelResultReadV1 or fact is None)):
        raise AuthorityUnavailable('Numeric paid writer requires its exact named producer arguments')
    graph._authorize(lease,authority,frozenset({'d11'}),owner_read=True)
    owner=graph._GraphCoordinator__owner_leases.get(lease);session=graph._GraphCoordinator__owner_session_proofs.get(lease)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if owner is None or session is None or assembly is None or 'workbench.create' not in owner.capabilities:
        raise AuthorityUnavailable('Numeric paid writer current installed Owner/session unavailable')
    bundle=assembly.admin_bundle;workflow=bundle.model_workflows.life_numeric
    if (bundle.installation_policy.namespace != authority.namespace or workflow is None
            or workflow.work_kind != 'd06.encode_internal_life_numeric' or workflow.purpose != 'consolidation'
            or authority.purpose not in ('context','consolidation') or not authority.audience
            or not set(authority.audience) <= set(workflow.audiences)):
        raise AuthorityUnavailable('Numeric paid writer actual installed recipe/purpose/audience differs')
    request=_NumericPaidWriteRequestV3(episode_ref,causal_operation_id,job_id,attempt,delivery,fact)
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(bundle.ingress_clock))
    operation=begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,'numeric-paid-work:'+uuid4().hex,now+60.0)
    fence=None
    try:
        with bind_runtime_storage_operation_v3(operation,graph._GraphCoordinator__store._db):
            fence=graph._begin_read_fence_v3(authority,operation_id=operation.operation_id,owner_session_proof=session)
            r=begin_current_method_learning_read_v3(graph,operation,fence,runtime=graph._GraphCoordinator__domain_production_runtime_v1,
                authority=authority,lease=lease,operation_kind=operation_kind,request=request,operation_id=operation.operation_id,
                activity_id=operation.operation_id,audience_ref=authority.audience[0],parent_budget_lease_ref=bundle.installation_policy.root_grant.lease_id,
                request_digest='sha256:'+canonical_digest((operation_kind,request)),owner_binding=owner,owner_guard=None,
                session_proof=session,initial_now_utc=now)
            r.initial_monotonic_deadline=time.monotonic()+60.0
            r.background_followup=r.background_host_lifecycle=r.background_offline=None
            r.numeric_paid_now=now;r.numeric_paid_prepared=r.numeric_paid_binding=r.numeric_paid_model=None
            r.numeric_paid_capsule=None;r.numeric_paid_result=None;r.numeric_paid_recipe=None
            r.numeric_paid_operation_id='numeric-paid:'+canonical_digest((authority.namespace,operation_kind,job_id,attempt))[:48]
        work=create_graph_storage_work_v3(graph,kind=NUMERIC_PAID_WORK_KIND_V3,operation_id=operation.operation_id,
            selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=r,operation=operation)
        r.work=work;_PAID_WORKS[r]=_paid_identity_v3(r)
        return work
    except BaseException:
        try:
            if fence is not None:graph._finish_read_fence_v3(fence)
        finally:finish_runtime_storage_operation_v3(operation)
        raise


def require_numeric_paid_source_purposes_v3(r,purposes):
    require_numeric_paid_write_work_v3(r)
    if tuple(purposes) != ('context','consolidation'):
        raise AuthorityUnavailable('Numeric paid writer Source has another registered purpose recipe')


def _prepare_numeric_paid_sources_v3(r):
    from .current_life_numeric_metadata_v1 import prepare_numeric_metadata_plan_v1,_metadata
    from .current_method_learning_read_v3 import qualify_method_source_metadata_kernel_v1
    from ..graph_types import AtomKey
    plan,expectations=prepare_numeric_metadata_plan_v1(r)
    prepared,prepared_task=_metadata(r,'life','prepared',r.request.job_id)
    binding,binding_task=_metadata(r,'life','binding',r.request.job_id)
    request,request_task=_metadata(r,'life','request',r.request.job_id)
    acquired,acquired_task=_metadata(r,'life','acquire_commit',r.request.job_id)
    from .d06_life_numeric_worker_v1 import decode_life_numeric_worker_binding_v1
    from .domain_production_originals_v1 import _receipt
    b=decode_life_numeric_worker_binding_v1(binding); receipt=_receipt(acquired['receipt'])
    if (prepared['job_id'] != r.request.job_id or b.job_id != r.request.job_id
            or b.owner_principal != r.owner_binding.principal or b.owner_actor != r.owner_binding.actor
            or b.owner_guard != r.material_owner_guard
            or b.prepared_digest != prepared_task.column.canonical_digest
            or (request['prepared_digest'],request['binding_digest'],request['request_digest']) !=
               (b.prepared_digest,b.digest,request['request_digest'])
            or (acquired['prepared_digest'],acquired['binding_digest'],acquired['request_digest']) !=
               (b.prepared_digest,b.digest,b.request_digest)
            or receipt.status != 'committed' or receipt.operation_id != b.acquire_operation_id
            or acquired['receipt_digest'] != canonical_digest(receipt)):
        raise AuthorityUnavailable('Numeric paid writer actual signed acquired originals differ')
    from datetime import datetime
    from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
    quote,quote_task=_metadata(r,'quote','quote',prepared['quote_id'])
    envelope=request_task.column.envelope_metadata
    with runtime_storage_quantum_v3(r.db) as meter:
        job=_runtime_bounded_fixed_row_v3(r.db,meter,'runtime_jobs',
            ('bot_id','persona_id','work_kind','deadline_utc','lease_expires_utc','lease_holder','fence','cancel_epoch'),'job_id=?',(r.request.job_id,))
    if (job is None or job[:2] != r.namespace.as_tuple or job[2] != 'd06.encode_internal_life_numeric'
            or job[4] is None or job[5] != b.worker_subject or job[6] != envelope['envelope']['authority']['worker_fence'] or job[7] != 0):
        raise AuthorityUnavailable('Numeric paid writer actual job/worker metadata differs')
    r.numeric_paid_job_metadata=job
    r.numeric_paid_deadline=min(r.operation.deadline_utc,b.deadline_utc,envelope['envelope']['deadline_utc'],
        *(datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()for value in job[3:5]),
        quote['valid_until_utc'],quote['deadline_utc'],r.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.installation_policy.root_grant.valid_until_utc)
    if r.numeric_paid_now >= r.numeric_paid_deadline or time.monotonic()>=r.initial_monotonic_deadline:
        raise AuthorityUnavailable('Numeric paid writer original deadline expired')
    records,versions=qualify_method_source_metadata_kernel_v1(r,plan.source_roots,purposes=('context','consolidation'))
    for ref,revision in expectations.items():
        current=versions.get(AtomKey.from_token(ref))
        if current is None or current.revision != revision:
            raise AuthorityUnavailable('Numeric paid writer Source versions differ from prepared originals')
    source=(plan,tuple(sorted(records)),tuple(versions.values()),prepared_task,binding_task,request_task,acquired_task,quote_task)
    _PAID_SOURCES[r]=source
    from ..model_broker.internal_life_numeric_v1 import InternalLifeNumericIdentityV1,internal_life_numeric_ids_v1
    identity_data=dict(prepared['frozen']['identity']);identity_data['namespace']=NamespaceId(**identity_data['namespace'])
    identity=InternalLifeNumericIdentityV1(**identity_data);ids=internal_life_numeric_ids_v1(identity)
    if ids['job'] != r.request.job_id:raise AuthorityUnavailable('Numeric paid selected job differs from actual once identity')
    from ..authority_service.current_life_numeric_v1 import life_numeric_read_attempt_id_v1
    read_attempt=life_numeric_read_attempt_id_v1(ids['adopt'],r.request.attempt) if r.operation_kind==NUMERIC_SELECTOR_OPERATION_V3 else r.request.delivery.request.read_attempt_id
    if r.operation_kind==NUMERIC_PAID_OPERATION_V3 and (r.request.delivery.request.consumer_operation_id != ids['adopt'] or r.request.delivery.request.job_id != ids['job']):
        raise AuthorityUnavailable('Numeric paid result selector escaped its exact actual once family')
    from .d11_types import runtime_job_key
    expected_job=runtime_job_key(*r.namespace.as_tuple,prepared['activity_id'],r.request.job_id)
    if len(receipt.write_versions)!=1 or receipt.write_versions[0].key!=expected_job or receipt.write_versions[0].revision<1:
        raise AuthorityUnavailable('Numeric paid acquisition receipt lost its actual selected job version')
    r.numeric_paid_acquisition=receipt
    r.numeric_paid_ids,r.numeric_paid_read_attempt=ids,read_attempt
    r.numeric_paid_recipe=(prepared,b,source)
    return source


def require_numeric_paid_body_v3(r,table,key):
    require_numeric_paid_write_work_v3(r)
    from ..graph_types import AtomKey,owner_grant_key
    from ..memory_types import access_key
    if table=='graph_atoms':
        atom=AtomKey.from_token(key[0])
        if atom==owner_grant_key(*r.namespace.as_tuple) or atom.type_name==access_key(*r.namespace.as_tuple,'metadata').type_name:return r
    if r not in _PAID_SOURCES:
        raise AuthorityUnavailable('Numeric paid protected body requires its own complete ALL Source qualification')
    if r.read_finished and r not in _PAID_WRITES:
        raise AuthorityUnavailable('Numeric paid protected body requires a fresh independent WRITE capsule')
    if table=='graph_atoms' and AtomKey.from_token(key[0]).type_name=='memory.source' and key[0] not in _PAID_SOURCES[r][1]:
        raise AuthorityUnavailable('Numeric paid Source body escaped its actual root/ancestor family')
    return r


def _paid_cost_locator_v3(r):
    from .model_cost_settlement import original_model_cost_operation_id_v1
    return original_model_cost_operation_id_v1(r.namespace,r.numeric_paid_recipe[0]['call_id'])


def _paid_cost_ref_v3(r):
    request=('graph_bundle_operations',('digest','activity_id','effect_id','commit_seq','receipt_json'),
        ('bot','persona','operation_id'),(*r.namespace.as_tuple,_paid_cost_locator_v3(r)))
    point=r.points.get(request)
    if point is None or not point.complete: return None
    value=point.values['receipt_json'].json_v3()
    return value['original_model_cost']['cost_ref']


def require_numeric_paid_point_v3(r,request):
    require_numeric_paid_write_work_v3(r)
    from ..graph_types import AtomKey
    from .d11_types import runtime_job_key
    from .current_method_learning_read_v3 import _HISTORY_COLUMNS
    from .natural_producer_qualification_v1 import _HOST_ATTACHMENT_SHAPES_V3
    table,columns,keycols,key=request;columns=tuple(columns);keycols=tuple(keycols);key=tuple(key)
    require_numeric_paid_body_v3(r,table,key)
    ns=r.namespace.as_tuple;recipe=r.numeric_paid_recipe
    if recipe is None:
        allowed=table=='graph_atoms' and columns==('revision','value','valid') and NamespaceId.from_key(AtomKey.from_token(key[0]))==r.namespace
    else:
        p,b,source=recipe;ids=r.numeric_paid_ids
        job=runtime_job_key(*ns,p['activity_id'],r.request.job_id).token
        cost_ref=_paid_cost_ref_v3(r)
        graph_refs={key.token for key in source[0].exact_keys}|{row['ref']for row in p['read_rows']}|{v.key.token for v in source[2]}|{job}
        if cost_ref is not None:graph_refs.add(cost_ref)
        if table=='graph_atoms':allowed=key[0] in graph_refs and NamespaceId.from_key(AtomKey.from_token(key[0]))==r.namespace
        elif table=='graph_history':
            revision=r.numeric_paid_acquisition.write_versions[0].revision
            allowed=columns in (_HISTORY_COLUMNS,('event_id','value','valid')) and key in {(job,revision),(cost_ref,1)}
        elif table=='runtime_jobs':allowed=key==(r.request.job_id,)
        elif table=='graph_d11_life_originals_v1':
            from .current_life_numeric_metadata_v1 import _METADATA_PLANS
            originals={task.key for task in _METADATA_PLANS[r][2] if task.identity[0]=='life'}
            originals.update(((*ns,kind,ref))for kind,ref in (('numeric_prepared_v1',r.request.job_id),
                ('numeric_binding_v1',r.request.job_id),('numeric_request_v1',r.request.job_id),('numeric_acquire_commit_v1',r.request.job_id),
                ('numeric_call_v1',r.request.job_id),('numeric_paid_v1',r.request.job_id),('numeric_read_attempt_v1',r.numeric_paid_read_attempt)))
            allowed=key in originals
        elif table=='graph_bundle_operations':allowed=key[:2]==ns and key[-1] in {ids['prepare'],ids['acquire'],_paid_cost_locator_v3(r)}
        elif table=='graph_domain_production_originals_v1':allowed=key[:2]==ns and key[-1] in {ids['prepare'],ids['acquire']}
        elif table=='runtime_resource_quotes':allowed=key==(p['quote_id'],1)
        elif table=='runtime_budget_operations':allowed=key==(*ns,ids['prepare'],'settle')
        elif table=='runtime_budget_reservations':allowed=key==(r.parent_budget_lease_ref,ids['prepare'])
        elif table=='graph_original_model_cost_attempts_v1':allowed=key==(*ns,p['call_id'])
        elif table=='graph_events':allowed=key==(*ns,p['activity_id'],_paid_cost_locator_v3(r))
        elif table=='graph_owner_domain_attempts_v3':allowed=key==(*ns,r.numeric_paid_operation_id)
        else:allowed=False
    custom={('graph_bundle_operations',('digest','activity_id','effect_id','commit_seq','receipt_json')),
        ('runtime_budget_operations',('receipt_json',)),('runtime_budget_reservations',('state','digest')),
        ('graph_original_model_cost_attempts_v1',('state','attempt_id')),('graph_events',('reads','revisions','epoch_revision')),
        ('graph_history',_HISTORY_COLUMNS),('graph_history',('event_id','value','valid')),
        ('graph_owner_domain_attempts_v3',('request_digest','attempt_id','anchor_json','graph_revision','graph_epoch','permit_json','receipt_json'))}
    if not allowed or request[:3] not in _HOST_ATTACHMENT_SHAPES_V3 and (table,columns) not in custom:
        raise AuthorityUnavailable('Numeric paid point escaped its exact producer/key/fixed-column recipe')
    return r


def read_bound_numeric_paid_point_v3(db,*,table,columns,key_columns,key):
    from .current_method_learning_read_v3 import _method_active,_NUMERIC_PAID_WRITE_OPERATIONS_V3,read_bound_method_learning_attachment_v3
    r=_method_active(db)
    if r is None or r.operation_kind not in _NUMERIC_PAID_WRITE_OPERATIONS_V3:return False,None
    request=(table,tuple(columns),tuple(key_columns),tuple(key));require_numeric_paid_point_v3(r,request)
    return read_bound_method_learning_attachment_v3(db,table=table,columns=tuple(columns),key_columns=tuple(key_columns),key=tuple(key))


def read_bound_numeric_paid_history_v3(db,token,revision,columns):
    return read_bound_numeric_paid_point_v3(db,table='graph_history',columns=tuple(columns),
        key_columns=('token','revision'),key=(token,revision))


_PAID_CAPSULES=WeakKeyDictionary()
_PAID_WRITE_AUTHORITIES=WeakKeyDictionary()
_PAID_ATTEMPT_COLUMNS=('request_digest','attempt_id','anchor_json','graph_revision','graph_epoch','permit_json','receipt_json')
_PAID_OWNER_FIELDS=('principal','actor','namespace','purpose','audience','grant_id','scope','issuer_ref','capabilities','purposes','audiences',
    'grant_digest','grant_revision','access_epoch','delete_epoch','graph_incarnation','authorization_head','authorization_revision','revocation_epoch','target_admission','storage_admission')

class _NumericPaidWriteCapsuleV3:
    def __init__(self,r,attempt):
        self.reader=r;self.attempt=attempt
        self.seal=(r.work,r.operation,r.selection_digest,r.graph_stamp,r.authority,r.lease,r.owner_binding,r.owner_guard,
            r.request,r.request_digest,r.operation.deadline_utc,_PAID_SOURCES[r],r.numeric_paid_deadline,
            r.numeric_paid_prepared,r.numeric_paid_binding,r.numeric_paid_model)
        _PAID_CAPSULES[self]=self.seal
        r.operation.retain(_heap((self.seal,attempt))+1024)
    def require_write_v3(self,graph,*,authority,lease,operation_id,request_digest,metadata,epoch,owner,guard,scope,now):
        r=require_numeric_paid_write_work_v3(self.reader)
        if (_PAID_CAPSULES.get(self)!=self.seal or self.seal[:11]!=(r.work,r.operation,r.selection_digest,r.graph_stamp,
                r.authority,r.lease,r.owner_binding,r.owner_guard,r.request,r.request_digest,r.operation.deadline_utc)
                or graph is not r.graph or authority is not r.authority or lease is not r.lease
                or operation_id!=r.numeric_paid_operation_id or request_digest!=r.request_digest
                or (metadata,epoch)!=r.graph_stamp or guard!=r.owner_guard or scope.operation!='write' or scope.namespace!=r.namespace
                or self.seal[11] != _PAID_SOURCES.get(r) or not r.read_finished or not r.inputs_sealed
                or _PAID_WRITE_AUTHORITIES.get(r,(None,None))[:2]!=(self,scope)
                or tuple(getattr(owner,name)for name in _PAID_OWNER_FIELDS)!=tuple(getattr(r.owner_binding,name)for name in _PAID_OWNER_FIELDS)
                or 'workbench.create'not in owner.capabilities):
            raise AuthorityUnavailable('Numeric paid fresh WRITE changed sealed actual Owner/Source/job/stamp/selection')
        if now>=r.numeric_paid_deadline or time.monotonic()>=r.initial_monotonic_deadline:
            raise AuthorityUnavailable('Numeric paid fresh WRITE exceeded its original deadline')
        r.numeric_paid_now=now;r.require_current()
        from .current_life_numeric_metadata_v1 import _METADATA_PLANS
        from .current_method_learning_read_v3 import _GENERAL_METHOD_SOURCE_TASKS_V1
        with runtime_storage_quantum_v3(r.db)as meter:
            for task in _METADATA_PLANS[r][2]:task.require_header_v1(meter)
            for task in _PAID_SOURCES[r][3:]:task.require_header_v1(meter)
            for task in _GENERAL_METHOD_SOURCE_TASKS_V1[r].values():task.require_v1(r,meter)
            for point in r.points.values():
                if point.table!='graph_owner_domain_attempts_v3':point.require_row_v3(meter)
        _PAID_WRITES[r]=(self,scope,owner)
        return self


def observe_current_numeric_paid_owner_write_v3(capsule,graph,authority,lease,scope,expected,session):
    r=require_numeric_paid_write_work_v3(capsule.reader)
    if (capsule not in _PAID_CAPSULES or graph is not r.graph or authority is not r.authority or lease is not r.lease
            or session!=r.session_proof or expected!=r.owner_binding or r.db.in_transaction or not r.read_finished
            or scope.operation!='write' or graph._current_owner_principal(authority.actor,r.namespace)!=expected.principal):
        raise AuthorityUnavailable('Numeric paid fresh WRITE Owner observation crossed its exact sealed Work')
    token,request=session
    current,permit=graph._GraphCoordinator__content_fence_v2.get_current_owner_authority_for_fence_v1(
        namespace=r.namespace,authority_namespace=scope.authority_namespace,permit=scope.permit,
        owner_actor_id=authority.actor,owner_session_token=token,owner_session_request=request)
    if (permit!=scope.permit or current.guard!=r.owner_guard or current.target_admission!=expected.target_admission
            or current.storage_admission!=expected.storage_admission):
        raise AuthorityUnavailable('Numeric paid fresh WRITE actual signed Owner differs from complete EOF')
    _PAID_WRITE_AUTHORITIES[r]=(capsule,scope,current)
    return current.guard,expected


def read_current_numeric_paid_attempt_v3(capsule,db):
    r=require_numeric_paid_write_work_v3(capsule.reader)
    if capsule not in _PAID_CAPSULES or db is not r.db or not r.read_finished or not r.inputs_sealed:
        raise AuthorityUnavailable('Numeric paid attempt has no exact sealed current metadata EOF')
    r.require_current()
    with runtime_storage_quantum_v3(db)as meter:
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        presence=_runtime_bounded_fixed_row_v3(db,meter,'graph_owner_domain_attempts_v3',('request_digest','attempt_id','graph_revision','graph_epoch'),
            'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,r.numeric_paid_operation_id))
    expected=None if capsule.attempt is None else (capsule.attempt[0],capsule.attempt[1],capsule.attempt[3],capsule.attempt[4])
    if presence!=expected:raise AuthorityUnavailable('Numeric paid durable attempt metadata changed after its exact EOF')
    return capsule.attempt


def replay_current_numeric_paid_original_v3(capsule,db,*,permit,state,now):
    from ..authority_service.v2_contract import to_wire
    r=require_numeric_paid_write_work_v3(capsule.reader)
    request=('graph_owner_domain_attempts_v3',_PAID_ATTEMPT_COLUMNS,('bot','persona','operation_id'),
        (*r.namespace.as_tuple,r.numeric_paid_operation_id))
    point=r.points[request];column=point.values.get('permit_json')
    if (capsule not in _PAID_CAPSULES or state!='finished' or capsule.attempt is None
            or capsule.attempt[6] is None or column is None or column.frozen!=_freeze_value_v3(to_wire(permit))
            or now>=r.numeric_paid_deadline):
        raise AuthorityUnavailable('Numeric paid original WRITE finish identity or saved metadata differs')
    return point.values['receipt_json'].json_v3()


def _commit_numeric_paid_producer_v3(r,db,metadata,epoch,now,owner,scope):
    from .d06_life_numeric_paid_v1 import prepare_life_numeric_result_selector_v1,record_life_numeric_paid_result_v1
    from ..authority_service.current_life_numeric_v1 import life_numeric_result_to_wire_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    if r not in _PAID_WRITES:raise AuthorityUnavailable('Numeric producer lacks its actual fresh WRITE capsule')
    issuer=r.graph._GraphCoordinator__d11_issuer
    if r.operation_kind==NUMERIC_SELECTOR_OPERATION_V3:
        selector=prepare_life_numeric_result_selector_v1(db,namespace=r.namespace,issuer=issuer,job_id=r.request.job_id,
            authority_id=metadata.requirements.authority_id,authority_namespace=metadata.requirements.authority_namespace,
            attempt=r.request.attempt)
        return {'schema':'numeric.current-result-selector.v3','selector':life_numeric_result_to_wire_v1(selector)}
    original=record_life_numeric_paid_result_v1(db,namespace=r.namespace,issuer=issuer,job_id=r.request.job_id,
        result_read=r.request.delivery,fact=r.request.fact)
    return {'schema':'numeric.current-paid-original.v3','original':plain_v1(original),
        'cost_operation_id':r.numeric_paid_cost.operation_id,'cost_digest':canonical_digest(r.numeric_paid_cost)}


def _prepare_numeric_paid_originals_v3(r):
    from .d06_life_numeric_worker_v1 import read_committed_life_numeric_request_v1
    from .d06_life_numeric_paid_v1 import read_life_numeric_cost_commit_v1,require_life_numeric_paid_membership_v3
    from .d11_life_preparation_v1 import _read
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    from ..authority_service.v2_model_egress_wire import from_wire
    from ..authority_service.current_life_numeric_v1 import LifeNumericModelResultReadRequestV1,life_numeric_read_attempt_id_v1,life_numeric_result_to_wire_v1
    from .current_method_learning_read_v3 import read_bound_method_learning_attachment_v3
    issuer=r.graph._GraphCoordinator__d11_issuer
    p,b,model=read_committed_life_numeric_request_v1(r.db,namespace=r.namespace,issuer=issuer,job_id=r.request.job_id)
    source=_PAID_SOURCES[r]
    if (p.digest!=source[3].column.canonical_digest or b!=r.numeric_paid_recipe[1]
            or model.digest!=_detach_value_v3(source[5].result)['request_digest'] or p.frozen.identity.episode_ref!=r.request.episode_ref
            or p.causal_operation_id!=r.request.causal_operation_id):
        raise AuthorityUnavailable('Numeric paid typed originals differ from qualified signed metadata')
    r.numeric_paid_prepared,r.numeric_paid_binding,r.numeric_paid_model=p,b,model
    if r.operation_kind==NUMERIC_PAID_OPERATION_V3:
        delivery=r.request.delivery
        saved=_read(r.db,namespace=r.namespace,issuer=issuer,kind='numeric_call_v1',ref=p.job_id)
        if saved is None:raise AuthorityUnavailable('Numeric paid actual sealed call unavailable')
        intent=from_wire(saved[0]['intent'],ModelEgressIntentV1)
        delivery.require_original(intent,p,p.frozen,b)
        selector=_read(r.db,namespace=r.namespace,issuer=issuer,kind='numeric_read_attempt_v1',ref=delivery.request.read_attempt_id)
        if selector is None or selector[0]!=life_numeric_result_to_wire_v1(delivery.request) or selector[1]!=p.acquire_operation_id:
            raise AuthorityUnavailable('Numeric paid actual result lacks its exact signed W01 selector')
        cost=read_life_numeric_cost_commit_v1(r.db,namespace=r.namespace,issuer=issuer,prepared=p,intent=intent,
            terminal=delivery.terminal_receipt,fact=r.request.fact)
        from ..domains.d01.production_operations_v1 import plain_v1
        require_life_numeric_paid_membership_v3(producing_operation_id=cost.operation_id,prepared_digest=p.digest,
            binding_digest=b.digest,cost_value=plain_v1(cost),cost_digest=canonical_digest(cost),
            result_request_digest=delivery.request.model_request_digest,prepared=p,binding=b,model=model,cost=cost)
        r.numeric_paid_cost=cost
    target='numeric_read_attempt_v1' if r.operation_kind==NUMERIC_SELECTOR_OPERATION_V3 else 'numeric_paid_v1'
    ref=r.numeric_paid_read_attempt if target=='numeric_read_attempt_v1' else p.job_id
    read_bound_method_learning_attachment_v3(r.db,table='graph_d11_life_originals_v1',
        columns=('producing_operation_id','payload_json','payload_digest','signature'),
        key_columns=('bot','persona','kind','original_ref'),key=(*r.namespace.as_tuple,target,ref))
    _,attempt=read_bound_method_learning_attachment_v3(r.db,table='graph_owner_domain_attempts_v3',columns=_PAID_ATTEMPT_COLUMNS,
        key_columns=('bot','persona','operation_id'),key=(*r.namespace.as_tuple,r.numeric_paid_operation_id))
    return _NumericPaidWriteCapsuleV3(r,attempt)


from contextlib import contextmanager

@contextmanager
def _bind_numeric_paid_write_v3(r,capsule):
    from .current_method_learning_read_v3 import _READING
    token=_READING.set(r)
    try:
        with bind_runtime_storage_operation_v3(r.operation,r.db):yield
    finally:
        _READING.reset(token);_PAID_WRITES.pop(r,None);_PAID_WRITE_AUTHORITIES.pop(r,None)


def advance_current_life_numeric_paid_write_v3(graph,work):
    from .first_ingress_v2 import trusted_upper
    from .current_method_learning_read_v3 import (_READING,_prepare_current_general_method_owner_entry_v1,
        bind_prepared_method_learning_read_v3,MethodInputNeededV3,_MethodPointReadV3,_MethodBudgetGrantReadV3,
        _GeneralMethodSourceMetadataEOFV1,_GENERAL_METHOD_SOURCE_ISSUER_V1,_GENERAL_METHOD_SOURCE_TASKS_V1)
    from .current_life_numeric_metadata_v1 import NumericMetadataTaskV1
    r=require_numeric_paid_write_work_v3(work.state)
    if r.read_finished:raise AuthorityUnavailable('Numeric paid writer advanced after its original READ terminal')
    with bind_runtime_storage_operation_v3(work.operation,r.db):
        r.numeric_paid_now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
            graph._GraphCoordinator__scene_clock_policy))
        if r.numeric_paid_now>=work.deadline_utc or time.monotonic()>=r.initial_monotonic_deadline:
            raise AuthorityUnavailable('Numeric paid writer original operation window ended')
        _prepare_current_general_method_owner_entry_v1(r);graph._validate_read_fence_v3(r.fence)
        if not r.inventory_sealed:
            with r.store._lock:r.advance()
            return GraphStorageStepV3('progress')
        if r.pending_input is not None:
            with r.store._lock,runtime_storage_quantum_v3(r.db)as meter:
                r.require_current(meter=meter);r.pending_input.advance(meter)
                if r.pending_input.complete:r.pending_input=None
            return GraphStorageStepV3('progress')
        token=_READING.set(r)
        try:
            with bind_prepared_method_learning_read_v3(r.inventory,graph,r.db),r.store._lock:
                r.db.execute('BEGIN')
                try:
                    _prepare_numeric_paid_sources_v3(r)
                    capsule=_prepare_numeric_paid_originals_v3(r)
                    r.numeric_paid_capsule=capsule;r.inputs_sealed=True
                finally:r.db.rollback()
            graph._validate_read_fence_v3(r.fence);graph._finish_read_fence_v3(r.fence);r.read_finished=True
            with _bind_numeric_paid_write_v3(r,capsule):
                result=graph._owner_domain_write_v3(r.authority,r.lease,operation_id=r.numeric_paid_operation_id,
                    request_digest=r.request_digest,domains=('d11',),capability='workbench.create',
                    commit=lambda db,metadata,epoch,now,owner,scope:_commit_numeric_paid_producer_v3(r,db,metadata,epoch,now,owner,scope),
                    numeric_paid_prepare=capsule)
            if r.operation_kind==NUMERIC_SELECTOR_OPERATION_V3:
                from ..authority_service.current_life_numeric_v1 import LifeNumericModelResultReadRequestV1,life_numeric_result_from_wire_v1
                value=life_numeric_result_from_wire_v1(result['selector'],LifeNumericModelResultReadRequestV1);facts=None
            else:
                value=result;facts=(r.numeric_paid_prepared,r.numeric_paid_binding,r.numeric_paid_model,r.numeric_paid_cost)
            r.numeric_paid_result=_NumericPaidResultV3(r,value,facts)
            r.complete=r.business_completed=True
            return GraphStorageStepV3('complete',r.numeric_paid_result)
        except MethodInputNeededV3 as needed:
            kind,actual=needed.request
            with r.store._lock,runtime_storage_quantum_v3(r.db):
                if kind=='numeric_owner_metadata':
                    identity=(kind,actual);task=r.attachments.get(identity)
                    if task is None:task=NumericMetadataTaskV1(r,actual);r.attachments[identity]=task
                elif kind=='general_method_source_metadata':
                    tasks=_GENERAL_METHOD_SOURCE_TASKS_V1.setdefault(r,{})
                    task=tasks.get(actual)
                    if task is None:task=_GeneralMethodSourceMetadataEOFV1(_GENERAL_METHOD_SOURCE_ISSUER_V1,r,actual);tasks[actual]=task
                elif kind=='point':
                    require_numeric_paid_point_v3(r,actual);task=r.points.get(actual)
                    if task is None:task=_MethodPointReadV3(r,actual);r.points[actual]=task
                elif kind=='budget_grant':
                    if actual!=r.parent_budget_lease_ref:raise AuthorityUnavailable('Numeric paid parent budget locator changed')
                    if r.budget_task is None:r.budget_task=_MethodBudgetGrantReadV3(r,actual)
                    task=r.budget_task
                else:raise AuthorityUnavailable('Numeric paid writer has no registered current original dependency')
                r.pending_input=task
            return GraphStorageStepV3('progress')
        finally:_READING.reset(token)


def _release_numeric_paid_reader_v3(r):
    from .current_method_learning_read_v3 import _release_method_registered_payloads_v3
    _PAID_WORKS.pop(r,None);_PAID_SOURCES.pop(r,None);_PAID_WRITES.pop(r,None);_PAID_WRITE_AUTHORITIES.pop(r,None)
    for capsule in tuple(_PAID_CAPSULES):
        if capsule.reader is r:_PAID_CAPSULES.pop(capsule,None)
    _release_method_registered_payloads_v3(r)
    if r.inventory is not None:r.inventory.release_payload_v3()
    r.points.clear();r.attachments.clear();r.numeric_paid_prepared=r.numeric_paid_binding=r.numeric_paid_model=None
    r.numeric_paid_capsule=r.numeric_paid_result=r.numeric_paid_recipe=None


def finish_current_life_numeric_paid_write_v3(graph,work,error):
    r=work.state
    try:
        if not r.read_finished:graph._finish_read_fence_v3(r.fence);r.read_finished=True
        if error is None:work.result_lease=work.operation
    finally:
        if error is not None:
            _release_numeric_paid_reader_v3(r);finish_runtime_storage_operation_v3(work.operation)
