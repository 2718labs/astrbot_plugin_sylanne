"""Contact preparation Source reads issued by the actual current Owner session.

Owner command purpose and Contact expression/context Source purposes are
independent. Retained READ material can only enter the separate WRITE binder.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from weakref import WeakKeyDictionary
from contextvars import ContextVar
from ..runtime_contracts import canonical_digest
from ..authority_service.contract import AuthorityUnavailable
from .contact_original_read_v3 import contact_original_point_v3

_COMMANDS = WeakKeyDictionary()
_WRITES = WeakKeyDictionary()
_CURRENT_WRITE = ContextVar('contact_owner_command_source_write_v3',default=None)

@dataclass(frozen=True,slots=True,weakref_slot=True)
class _ContactOwnerCommandSourceV3:
    service:object
    authority:object
    lease:object
    request:object
    operation_id:str
    source_request_digest:str
    owner:object
    owner_session_proof:object
    @property
    def namespace(self):return _contact_owner_request_tuple_v3(self.request)[0]
    @property
    def contact_id(self):return _contact_owner_request_tuple_v3(self.request)[1]
    @property
    def qualified_contact_dedupe_key(self):return _contact_owner_request_tuple_v3(self.request)[2]
    @property
    def prepare_contact_operation_id(self):return _contact_owner_request_tuple_v3(self.request)[3]
    @property
    def operation_kind(self):return _contact_owner_request_tuple_v3(self.request)[4]


def contact_owner_command_request_kind_v3(request):
    from .joint_window_command_v1 import FreezeJointWindowNodeCommandRequestV1
    from .joint_node_execution_v1 import JointContactProspectiveBindingV1
    if type(request)is FreezeJointWindowNodeCommandRequestV1 and type(request.command.binding)is JointContactProspectiveBindingV1:
        return "input:freeze_joint_window_node_command_v1"
    from .joint_contact_preparation_v1 import RegisterJointContactPreparationRequestV1
    from .joint_node_execution_v1 import RegisterJointNodeExecutionBindingRequestV1,JointContactProspectiveBindingV1
    if type(request)is RegisterJointContactPreparationRequestV1:return 'input:register_joint_contact_preparation_v1'
    if type(request)is RegisterJointNodeExecutionBindingRequestV1 and type(request.binding)is JointContactProspectiveBindingV1:
        return 'input:register_joint_node_execution_binding_v1'
    return None


def _contact_owner_request_tuple_v3(request):
    kind=contact_owner_command_request_kind_v3(request)
    if kind=='input:register_joint_contact_preparation_v1':
        return request.namespace,request.contact_id,request.qualified_contact_dedupe_key,request.prepare_contact_operation_id,kind
    if kind in {'input:register_joint_node_execution_binding_v1','input:freeze_joint_window_node_command_v1'}:
        binding=request.binding if kind=='input:register_joint_node_execution_binding_v1'else request.command.binding
        return binding.namespace,binding.contact_id,binding.executor.qualified_outbox_dedupe_key,binding.executor.prepare_contact_operation_id,kind
    raise TypeError('actual typed Joint Contact preparation or prospective binding input required')


def require_contact_owner_command_source_v3(command,*,state=None):
    from .contact_graph_runtime_v2 import InstalledContactModelGraphRuntimeV2
    from .joint_contact_preparation_v1 import RegisterJointContactPreparationRequestV1
    if (type(command) is not _ContactOwnerCommandSourceV3 or _COMMANDS.get(command) !=
            (command.service,command.authority,command.lease,command.request,command.operation_id,
                command.source_request_digest,command.owner,command.owner_session_proof)
            or type(command.service) is not InstalledContactModelGraphRuntimeV2
            or contact_owner_command_request_kind_v3(command.request)is None):
        raise AuthorityUnavailable('Contact Owner Source command lacks its actual installed typed issuer/session')
    command.service._current()
    graph = command.service.graph
    graph._authorize(command.lease,command.authority,frozenset({'d08','d09','d10','d11'}),owner_read=True)
    if (graph._GraphCoordinator__owner_leases.get(command.lease) is not command.owner
            or graph._GraphCoordinator__owner_session_proofs.get(command.lease) is not command.owner_session_proof
            or command.authority.namespace != command.namespace
            or command.authority.actor != command.owner.actor
            or command.authority.capability_ref!='workbench.create' or command.authority.purpose!='context'
            or command.authority.audience!=('owner',)):
        raise AuthorityUnavailable('Contact Owner source request changed its original actual session/actor')
    if state is not None:
        if (state.owner_command is not command or state.service is not command.service
                or state.selector.stage != 'joint_contact_preparation' or state.selector.contact_id != command.contact_id
                or state.selector.owner_command_digest != command.source_request_digest or state.operation.closed):
            raise AuthorityUnavailable('Contact Owner command Source Work has another request/stage/operation')
    return command


def prepare_joint_contact_owner_command_v3(graph,authority,lease,*,request,operation_id):
    from .joint_contact_preparation_v1 import RegisterJointContactPreparationRequestV1
    from .contact_graph_runtime_v2 import InstalledContactModelGraphRuntimeV2
    from .contact_host_stage_work_v3 import prepare_contact_host_stage_work_v3
    namespace,contact_id,_,_,operation_kind=_contact_owner_request_tuple_v3(request)
    if (namespace != authority.namespace
            or authority.capability_ref!='workbench.create' or authority.purpose!='context'
            or authority.audience!=('owner',)):
        raise TypeError('Joint Contact preparation requires its actual typed Owner request namespace')
    graph._authorize(lease,authority,frozenset({'d08','d09','d10','d11'}),owner_read=True)
    service = graph._GraphCoordinator__contact_model_runtime_v2
    owner,proof = graph._GraphCoordinator__owner_leases.get(lease),graph._GraphCoordinator__owner_session_proofs.get(lease)
    if type(service) is not InstalledContactModelGraphRuntimeV2 or owner is None or proof is None:
        raise AuthorityUnavailable('Joint Contact preparation requires its actual installed current Owner session')
    digest = canonical_digest(('d10.contact-owner-preparation-source.v3',authority.namespace,authority.actor,request,operation_id))
    command = _ContactOwnerCommandSourceV3(service,authority,lease,request,operation_id,digest,owner,proof)
    _COMMANDS[command] = (service,authority,lease,request,operation_id,digest,owner,proof)
    work = prepare_contact_host_stage_work_v3(service,contact_id=contact_id,model_phase='contact_review',
        stage='joint_contact_preparation',owner_command=command)
    def prepared(state):
        require_contact_owner_command_source_v3(command,state=state)
        if not state.complete or state.source_material is None:
            raise AuthorityUnavailable('Joint Contact Owner Source has not completed its current Source/body EOF')
        return state
    work.map_terminal_v3('issuer',prepared,lambda error:(_ for _ in ()).throw(error))
    return work


def observe_contact_owner_command_read_v3(state):
    require_contact_owner_command_source_v3(state.owner_command,state=state)
    if state.owner_entry is None:
        raise AuthorityUnavailable('Contact Owner READ has not completed its fixed Owner EOF')
    return state.owner_entry.observe_current_v3(state)


def _open_contact_owner_command_read_v3(state):
    command=require_contact_owner_command_source_v3(state.owner_command,state=state)
    if state.db.in_transaction or state.borrowed_scope is not None:
        raise AuthorityUnavailable('Contact Owner READ must issue outside SQL and cannot borrow WRITE')
    deadline=min(state.contact_locator.values[('plan','valid_until_utc')],state.parent_deadline,*state.job_deadlines)
    if state.operation.deadline_utc is not None:deadline=min(deadline,state.operation.deadline_utc)
    state.operation.deadline_utc=state.work.deadline_utc=float(deadline)
    state.authority=command.authority
    state.fence=state.graph._begin_read_fence_v3(command.authority,operation_id=state.operation_id)
    state.scope=state.fence.scope
    from ..authority_service.owner_location_read_v3 import prepare_current_contact_owner_source_read_entry_v3
    entry=prepare_current_contact_owner_source_read_entry_v3(state)
    state.owner_entry=entry
    state.owner_guard,state.owner=entry.require_for_v3(state)
    state.fence.observed_guard,state.fence.observed_owner=state.owner_guard,state.owner
    return command.authority


_WRITE_BIRTHS = WeakKeyDictionary()
_CURRENT_WRITE_BIRTH = ContextVar('contact_owner_source_actual_write_birth_v3',default=None)


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class _ContactOwnerSourceWriteBirthV3:
    graph:object
    runtime:object
    state:object
    command:object
    authority:object
    lease:object
    business_operation_id:str
    request_digest:str
    attempt_id:str
    scope:object
    current_authority:object
    owner:object
    owner_session_proof:object
    metadata:object
    epoch:object
    retained_operation:object
    original_deadline_utc:float
    def _identity_v3(self):
        return (self.graph,self.runtime,self.state,self.command,self.authority,self.lease,
            self.business_operation_id,self.request_digest,self.attempt_id,self.scope,
            self.current_authority,self.owner,self.owner_session_proof,self.metadata,self.epoch,
            self.retained_operation,self.original_deadline_utc)
    def _runtime_retained_heap_bytes_v3(self):
        from ..authority_service.owner_location_read_v3 import _owner_heap_size_v3,_owner_location_payload_heap_v3
        return _owner_heap_size_v3(self)+_owner_location_payload_heap_v3((self.scope,self.current_authority,
            self.owner,self.owner_session_proof,self.metadata,self.epoch,self.original_deadline_utc),set())


def _require_contact_owner_write_birth_v3(birth):
    if (type(birth)is not _ContactOwnerSourceWriteBirthV3 or _CURRENT_WRITE_BIRTH.get()is not birth
            or _WRITE_BIRTHS.get(birth)!=birth._identity_v3()):
        raise AuthorityUnavailable('Contact WRITE requires its actual Owner-domain birth')
    state=birth.state
    command=require_contact_owner_command_source_v3(birth.command,state=state)
    from .contact_host_source_v3 import require_contact_host_work_v3
    require_contact_host_work_v3(state)
    expected_digest=canonical_digest(('sylanne.domain-production-command.v1',state.namespace,command.authority.actor,
        command.operation_kind,command.request,command.operation_id,
        state.result['activity_id'],state.result['audience_ref'],state.result['parent_budget_lease_ref']))
    attempt='owner-domain-'+canonical_digest((state.namespace,command.operation_id,expected_digest))[:48]
    if (birth.graph is not state.graph or birth.runtime is not state.graph._GraphCoordinator__domain_production_runtime_v1
            or birth.runtime.graph is not state.graph or birth.authority is not command.authority
            or birth.lease is not command.lease or birth.business_operation_id!=command.operation_id
            or birth.request_digest!=expected_digest or birth.attempt_id!=attempt
            or birth.scope.operation_id!=attempt or birth.scope.permit.operation_id!=attempt
            or birth.scope.operation!='write' or birth.scope.permit.operation!='write'
            or birth.scope is state.scope or birth.scope.permit is state.scope.permit
            or birth.scope.namespace!=state.namespace or birth.scope.pinned_anchor!=birth.scope.permit.pinned_anchor
            or birth.scope.graph_revision!=birth.metadata.graph_revision or birth.scope.graph_epoch!=birth.epoch
            or birth.owner is not command.owner or birth.owner_session_proof is not command.owner_session_proof
            or birth.retained_operation is not state.operation or not state.complete or state.result is None
            or state.operation.closed or state.operation.deadline_utc is None
            or state.operation.deadline_utc>birth.original_deadline_utc
            or birth.current_authority.guard.authorization_head!=command.owner.authorization_head
            or birth.current_authority.guard.authorization_revision!=command.owner.authorization_revision):
        raise AuthorityUnavailable('Contact WRITE birth differs from its original command/attempt/Source operation')
    state.operation.refresh_retained_state_v3(birth)
    return birth


@contextmanager
def bind_contact_owner_source_write_birth_v3(issuer,graph,*,runtime,state,authority,lease,operation_id,
        request_digest,attempt_id,scope,current_authority,owner,owner_session_proof,metadata,epoch):
    from ..graph_coordinator import _CONTACT_OWNER_DOMAIN_WRITE_ISSUER_V3
    from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    command=require_contact_owner_command_source_v3(state.owner_command,state=state)
    if (issuer is not _CONTACT_OWNER_DOMAIN_WRITE_ISSUER_V3 or state.db.in_transaction
            or type(current_authority)is not D12CurrentOwnerAuthorityV1
            or _CURRENT_WRITE_BIRTH.get()is not None):
        raise AuthorityUnavailable('Contact WRITE birth must come from actual Owner-domain admission before SQL')
    birth=_ContactOwnerSourceWriteBirthV3(graph,runtime,state,command,authority,lease,operation_id,
        request_digest,attempt_id,scope,current_authority,owner,owner_session_proof,metadata,epoch,
        state.operation,state.operation.deadline_utc)
    state.operation.register_retained_state_v3(birth)
    token=None
    try:
        _WRITE_BIRTHS[birth]=birth._identity_v3()
        token=_CURRENT_WRITE_BIRTH.set(birth)
        _require_contact_owner_write_birth_v3(birth)
        yield birth
    finally:
        if token is not None:_CURRENT_WRITE_BIRTH.reset(token)
        _WRITE_BIRTHS.pop(birth,None)
        state.operation.unregister_retained_state_v3(birth)


def require_contact_owner_source_write_birth_v3(write):
    if (type(write)is not _ContactOwnerSourceWriteV3 or _CURRENT_WRITE.get()is not write
            or _WRITES.get(write)!=(write.command,write.state,write.scope,write.owner,write.guard,
                write.request_digest,write.current_policy,write.birth)):
        raise AuthorityUnavailable('Contact WRITE adapter requires its actual private fresh binder')
    birth=_require_contact_owner_write_birth_v3(write.birth)
    if (birth.state is not write.state or birth.command is not write.command
            or birth.scope is not write.scope or birth.request_digest!=write.request_digest
            or birth.owner is not write.owner or birth.current_authority.guard!=write.guard):
        raise AuthorityUnavailable('Contact fresh WRITE binder crossed another actual command birth')
    return birth


class _ContactOwnerSourceWriteV3:
    def __init__(self,command,state,scope,owner,guard,request_digest,current_policy,birth):
        self.command,self.state,self.scope,self.owner,self.guard = command,state,scope,owner,guard
        self.request_digest,self.current_policy = request_digest,current_policy
        self.birth,self.owner_entry = birth,None
        _WRITES[self] = (command,state,scope,owner,guard,request_digest,current_policy,birth)
    def require_current(self,db):
        command = require_contact_owner_command_source_v3(self.command,state=self.state)
        state = self.state
        if (_CURRENT_WRITE.get() is not self or _WRITES.get(self) !=
                (command,state,self.scope,self.owner,self.guard,self.request_digest,self.current_policy,self.birth)
                or db is not state.db or not db.in_transaction or not state.store._lock._is_owned()
                or not state.complete or self.scope.operation != 'write' or self.scope is state.scope
                or self.owner.principal != state.owner.principal or self.guard != state.owner_guard
                or self.current_policy.original.digest != state.contact_policy.digest):
            raise AuthorityUnavailable('Retained Contact Owner READ bytes have no exact separate actual WRITE')
        require_contact_owner_source_write_birth_v3(self)
        if self.owner_entry is None or self.owner_entry.require_for_v3(state,write=self)!=(self.guard,self.owner):
            raise AuthorityUnavailable('Contact WRITE lacks its complete actual Owner EOF entry')
        state.require_current_v3()
        from .contact_host_source_v3 import require_contact_host_material_scope_v3
        require_contact_host_material_scope_v3(state.source_material,work=state,db=db)
        return self


@contextmanager
def bind_contact_owner_command_write_v3(runtime,*,state,authority,lease,operation_kind,request,operation_id,
        request_digest,scope,owner,guard):
    command = require_contact_owner_command_source_v3(state.owner_command,state=state)
    if (runtime is not state.graph._GraphCoordinator__domain_production_runtime_v1
            or authority is not command.authority or lease != command.lease or request != command.request
            or operation_kind != command.operation_kind or operation_id != command.operation_id
            or not state.complete or state.db.in_transaction or scope.namespace != state.namespace
            or scope.operation != 'write' or scope.permit is state.scope.permit):
        raise AuthorityUnavailable('Joint Contact Owner WRITE cannot borrow another request or READ permit')
    if state.service.port.validate_fence(scope) != scope.permit:
        raise AuthorityUnavailable('Joint Contact Owner current WRITE permit changed')
    birth=_require_contact_owner_write_birth_v3(_CURRENT_WRITE_BIRTH.get())
    if (birth.state is not state or birth.command is not command or birth.scope is not scope
            or birth.request_digest!=request_digest or birth.current_authority.guard!=guard
            or birth.owner is not owner or owner.principal!=state.owner.principal or guard!=state.owner_guard):
        raise AuthorityUnavailable('Joint Contact actual Owner session changed before separate WRITE')
    from .d10_contact_policy_authority_v1 import read_installed_current_contact_policy_v1
    matched = [atom for atom in state.atoms if atom.valid and atom.key.type_name=='d10.contact_policy.v1'
        and atom.value['approval_ref']==state.contact_locator.values[('plan','policy_original_ref')]]
    if len(matched)!=1:
        raise AuthorityUnavailable('Joint Contact Owner WRITE has no unique actual standing-policy locator')
    with read_installed_current_contact_policy_v1(state.graph._GraphCoordinator__c04_authority_port_v3,
            scope,matched[0].value['policy_id']) as current:
        if current is None or current.original.digest != state.contact_policy.digest:
            raise AuthorityUnavailable('Joint Contact standing policy changed before Owner WRITE')
        from .first_ingress_v2 import trusted_upper
        now = trusted_upper(state.service.port.read_ingress_clock(state.service.bundle.ingress_clock))
        if now >= min(state.operation.deadline_utc,state.result['deadline_utc'],current.original.policy.window_end):
            raise AuthorityUnavailable('Joint Contact original Source operation/Plan/root/policy deadline expired')
        binding = _ContactOwnerSourceWriteV3(command,state,scope,owner,guard,request_digest,current,birth)
        token = _CURRENT_WRITE.set(binding)
        from .contact_host_source_v3 import bind_contact_host_originals_v3
        try:
            from ..authority_service.owner_location_read_v3 import prepare_current_contact_owner_source_write_entry_v3
            binding.owner_entry=prepare_current_contact_owner_source_write_entry_v3(binding)
            binding.owner_entry.require_for_v3(state,write=binding)
            with bind_contact_host_originals_v3(state):
                yield binding
        finally:
            if binding.owner_entry is not None:
                binding.owner_entry.release_v3()
                binding.owner_entry=None
            _CURRENT_WRITE.reset(token)
            _WRITES.pop(binding,None)
    state.service.port.validate_fence(scope)


def require_contact_owner_source_write_v3(state,db):
    value = _CURRENT_WRITE.get()
    if value is None or value.state is not state:
        raise AuthorityUnavailable('Contact Owner Source READ does not grant a command WRITE')
    return value.require_current(db)


def release_contact_owner_command_source_v3(state):
    command = getattr(state,'owner_command',None)
    if command is not None:
        _COMMANDS.pop(command,None)


def read_joint_contact_owner_source_inputs_v3(service,state):
    command = require_contact_owner_command_source_v3(state.owner_command,state=state)
    from .contact_host_source_v3 import require_contact_host_work_v3
    require_contact_host_work_v3(state,db=service.store._db)
    if (state.service is not service or state.phase != 'semantic' or not state.db.in_transaction
            or state.selector.stage != 'joint_contact_preparation'):
        raise AuthorityUnavailable('Joint Contact paid inputs require their actual Source-qualified Owner READ')
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2
    from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
    from .contact_background_inputs_v1 import read_contact_background_inputs_v1
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    plan,_,_,_ = read_adopted_contact_plan_v2(state.db,namespace=state.namespace,
        contact_id=command.contact_id,issuer=service.issuer)
    content = read_contact_reviewed_content_original_v2(state.db,namespace=state.namespace,
        contact_id=command.contact_id,issuer=service.issuer,resource_issuer=service.resource_issuer)
    first = content.segments[0]
    final_digest = canonical_digest(('sylanne.domain-production-command.v1',state.namespace,state.owner.actor,
        'prepare_contact_dispatch_v3',PrepareCurrentContactDispatchRequestV3(command.contact_id),
        first.operation_id,plan.activity_id,plan.audience_id,plan.parent_budget_lease_id))
    terms,_,_,_ = read_contact_background_inputs_v1(state.db,namespace=state.namespace,contact_id=command.contact_id,
        operation_id=first.operation_id,request_digest=final_digest,dedupe_key=command.qualified_contact_dedupe_key,
        issuer=service.issuer,now=state.now_utc,owner_actor=state.owner.actor)
    if terms['causal_operation_id'] != command.prepare_contact_operation_id:
        raise AuthorityUnavailable('Joint preparation changed its actual original Contact opportunity cause')
    final_attempt = contact_original_point_v3(state.db,table='graph_owner_domain_attempts_v3',columns=('attempt_id',),
        key_columns=('bot','persona','operation_id'),key=(*state.namespace.as_tuple,first.operation_id),legacy_reader=lambda:None)
    if final_attempt is not None:
        raise AuthorityUnavailable('Joint Contact preparation cannot retrofit an already-started final operation')
    result={'namespace':state.namespace,'contact_id':plan.contact_id,'activity_id':plan.activity_id,
        'audience_ref':plan.audience_id,'parent_budget_lease_ref':plan.parent_budget_lease_id,'inputs':terms,
        'deadline_utc':min(terms['deadline_utc'],state.operation.deadline_utc),
        'source_purpose_groups':list(state.source_selection.purpose_groups)}
    if command.operation_kind in {'input:register_joint_node_execution_binding_v1','input:freeze_joint_window_node_command_v1'}:
        result['binding_preparation']=_read_contact_owner_prospective_binding_inputs_v3(service,state,command,terms,plan,content)
    return result


def read_plan_joint_contact_owner_source_v3(db,*,namespace,request,activity_id):
    """The fixed Owner input CAS reads exactly the retained Contact recipe."""
    from .contact_host_source_v3 import contact_host_work_for_db_v3,require_contact_host_material_scope_v3
    from .d01_production_operations_v1 import production_read_plan_v1
    from .contact_qualification_evidence_v3 import CONTACT_FINAL_QUERY_TYPES_V3
    from ..domains.d08.contact_plan_v2 import decode_contact_plan_v2,contact_plan_keys_v2
    from ..domains.d08.contact_plan_v3 import contact_plan_keys_v3
    from ..domains.d06 import source_correction_head_key
    from ..graph_types import AtomKey,owner_grant_key
    from ..memory_types import access_key
    state=contact_host_work_for_db_v3(db)
    binding=require_contact_owner_source_write_v3(state,db)
    if (binding.command.request!=request or state.namespace!=namespace
            or state.result['namespace']!=namespace or state.result['activity_id']!=activity_id):
        raise AuthorityUnavailable('Joint Contact read recipe lost its exact native Owner request/activity')
    material=require_contact_host_material_scope_v3(state.source_material,work=state,db=db)
    plan=decode_contact_plan_v2(state.contact_locator.plan_metadata)
    terms=state.result['inputs']
    keys={owner_grant_key(*namespace.as_tuple),*contact_plan_keys_v2(plan),*contact_plan_keys_v3(plan)[1:]}
    keys.update(AtomKey.from_token(row['key']) for row in state.contact_locator.versions.values())
    for ref in material.metadata_records:
        key=AtomKey.from_token(ref)
        keys.update((key,access_key(*namespace.as_tuple,key.owner.subject),source_correction_head_key(namespace,key.owner.subject)))
    # Complete type inventories are refrozen by W01, including absent members;
    # a fresh policy/route/claim is never inferred from the earlier READ.
    return production_read_plan_v1(CONTACT_FINAL_QUERY_TYPES_V3,keys,state.source_selection.roots,
        (terms['causal_original_ref'],))


def _read_contact_owner_prospective_binding_inputs_v3(service,state,command,terms,plan,content):
    from .joint_node_execution_v1 import RegisterJointNodeExecutionBindingRequestV1,JointContactProspectiveBindingV1
    from .contact_prospective_v1 import read_contact_prospective_original_v1,contact_prospective_original_ref_v1
    from .joint_contact_preparation_v1 import read_current_joint_contact_preparation_v1
    import json
    request=command.request
    from .joint_window_command_v1 import FreezeJointWindowNodeCommandRequestV1
    if type(request)is FreezeJointWindowNodeCommandRequestV1:request=request.command
    if type(request)is not RegisterJointNodeExecutionBindingRequestV1 or type(request.binding)is not JointContactProspectiveBindingV1:
        raise TypeError('Contact Owner binding Source requires its exact registered input and prospective binding')
    binding=request.binding
    original=read_contact_prospective_original_v1(state.db,service.issuer,state.namespace,command.contact_id)
    if original is None:raise AuthorityUnavailable('Contact binding Owner READ requires its actual immutable prospective birth')
    raw=json.loads(original.payload_json)
    preparation=read_current_joint_contact_preparation_v1(state.db,namespace=state.namespace,
        original_ref=raw['joint_preparation']['ref'],issuer=service.issuer)
    declared=preparation.request
    if (preparation.digest!=raw['joint_preparation']['digest']
            or preparation.namespace!=state.namespace or preparation.owner_acl_actor!=command.owner.actor
            or (declared.contact_id,declared.prepare_contact_operation_id,declared.qualified_contact_dedupe_key)!=(
                command.contact_id,command.prepare_contact_operation_id,command.qualified_contact_dedupe_key)
            or (declared.joint_plan_ref,declared.joint_plan_revision,declared.node_id,preparation.owner_ref)!=(
                binding.plan_ref,binding.plan_revision,binding.node_id,binding.owner_ref)
            or original.digest!=binding.prospective_original_digest
            or contact_prospective_original_ref_v1(state.namespace,command.contact_id,raw['birth_operation_id'])!=binding.prospective_original_ref
            or raw['refresh_rule']!=binding.refresh_rule
            or preparation.contact_plan_original_digest!=terms['plan_original_digest']
            or preparation.reviewed_content_digest!=content.digest
            or (preparation.contact_causal_original_ref,preparation.contact_causal_original_digest)!=(
                terms['causal_original_ref'],terms['causal_original_digest'])
            or (binding.parent_budget_lease_ref,binding.parent_grant_id,binding.parent_grant_version,binding.parent_grant_digest,
                binding.original_deadline_utc)!=(terms['budget_lease_ref'],terms['grant_id'],terms['grant_version'],terms['grant_digest'],terms['deadline_utc'])
            or binding.audience!=preparation.audience or binding.purpose!=preparation.purpose
            or set(binding.source_refs)!=set(preparation.source_refs)
            or preparation.source_purpose_groups!=state.source_selection.purpose_groups
            or {key:value for key,value in raw['terms'].items()if key not in ('graph_revision','graph_epoch')}!=
                {key:value for key,value in terms.items()if key not in ('graph_revision','graph_epoch')}
            or raw['deadline_utc']!=preparation.absolute_deadline_utc
            or raw['final_operation_id']!=content.segments[0].operation_id or raw['effect_id']!=content.segments[0].segment.effect_id):
        raise AuthorityUnavailable('Contact binding Source changed original Preparation/Owner/Plan/paid content/cause/grant/deadline')
    return preparation
