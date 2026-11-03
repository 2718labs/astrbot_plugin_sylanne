"""Neutral namespace READ and retained Owner EOF for one actual D13 CPU preparation."""
from contextlib import ExitStack,contextmanager
from dataclasses import dataclass,fields
from threading import get_ident,Lock
from time import monotonic
from weakref import WeakKeyDictionary
from secrets import token_hex,token_bytes

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.d13_core_counter_contract_v1 import D13CounterCPUPrepareInstructionV1,D13CurrentFramePrepareSelectorV7,D13CoreFrameIntentHeaderV7
from ..host.d13_core_counter_port_v1 import InstalledD13CoreCounterPortV1
from ..host.v2_fence_port import FenceScope
from ..runtime_contracts import AuthorityContext,NamespaceId,canonical_digest
from ..contracts import canonical_json
from ..graph_types import AtomKey
from ..graph_worker import GraphStorageWorkV3,GraphStorageStepV3,create_graph_storage_work_v3,require_graph_storage_work_admission_v3
from ..runtime_storage_v3 import (runtime_storage_v3,begin_runtime_storage_operation_v3,
    bind_runtime_storage_operation_v3,runtime_storage_quantum_v3,finish_runtime_storage_operation_v3,
    _runtime_bounded_fixed_row_v3)
from .first_ingress_v2 import trusted_upper
from .dispatch_current_inventory_v3 import _heap

KIND='d13_counter_owner_metadata_v1'
_KEY=object()
_READERS=WeakKeyDictionary()
_PREPARED=WeakKeyDictionary()
_ISSUANCES=WeakKeyDictionary()
_WRITES=WeakKeyDictionary()
_ROUTE_ORIGINALS=WeakKeyDictionary()
_RECOVERED=WeakKeyDictionary()
_HANDOFFS={}
_HANDOFF_ISSUED=WeakKeyDictionary()


@dataclass(frozen=True,slots=True)
class _NamespaceReadFenceV1:
    scope:object
    metadata:object
    epoch:object


class D13CounterOwnerMetadataReadV1:
    def __init__(self,graph,bootstrap,bundle,instruction,operation,fence,clock,prepared_header):
        self.graph,self.bootstrap,self.bundle,self.instruction=graph,bootstrap,bundle,instruction
        self.prepared_header=prepared_header;self.replay_task=None
        self.store=graph._GraphCoordinator__store;self.db=self.store._db
        self.port=graph._GraphCoordinator__content_fence_v2
        self.namespace=instruction.namespace
        self.operation,self.fence,self.scope=operation,fence,fence.scope
        self.graph_stamp=(fence.metadata,fence.epoch)
        self.selection_digest=operation.selection_digest
        self.original_deadline=operation.deadline_utc
        self.initial_clock=clock;self.initial_monotonic=monotonic()
        self.monotonic_deadline=self.initial_monotonic+operation.deadline_utc-trusted_upper(clock)
        self.thread=get_ident();self.work=None
        self.resource_verified=False;self.grant_header=None
        self.owner_task=self.owner_entry=None
        self.current_self=self.current_owner_guard=self.owner_principal=None
        self.authority=self.owner_binding=None
        self.c02_header=self.route_header=None
        self.complete=self.read_finished=False
        self.result=None;self.phase='root'
    @property
    def closed(self):return self.operation.closed
    def identity_v1(self):
        return (self.graph,self.bootstrap,self.bundle,self.instruction,self.work,self.operation,self.fence,
            self.scope,self.graph_stamp,self.selection_digest,self.original_deadline,self.thread,self.prepared_header)
    def _runtime_retained_heap_bytes_v3(self):
        return 65536+_heap((self.instruction,self.grant_header,self.c02_header,self.route_header,
            self.current_self,self.current_owner_guard,self.owner_binding))+ (0 if self.replay_task is None else self.replay_task.retained_bytes_v1())
    def require_v1(self,meter=None,*,retained=False):
        if (_READERS.get(self)!=self.identity_v1()or get_ident()!=self.thread or self.operation.closed
                or self.work.state is not self or self.work.operation is not self.operation
                or self.work.coordinator is not self.graph or self.work.kind!=KIND
                or runtime_storage_v3(self.db)is not self.operation.handle
                or self.operation.selection_digest!=self.selection_digest
                or self.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not self.bundle
                or monotonic()>=self.monotonic_deadline
                or trusted_upper(self.initial_clock)>=self.original_deadline):
            raise AuthorityUnavailable('D13 Owner metadata lost its actual Work/selection/original lifetime')
        self.work._require_invocation(self.graph)
        if retained:
            if not self.complete or not self.read_finished or self.result not in _PREPARED:
                raise AuthorityUnavailable('D13 retained Owner requires its real completed READ EOF')
        elif self.read_finished:
            raise AuthorityUnavailable('finished D13 namespace READ cannot be revived')
        if meter is not None:
            if not self.db.in_transaction or not self.store._lock._is_owned():
                raise AuthorityUnavailable('D13 Owner metadata needs its actual Graph quantum')
            self.operation.handle.require_current(meter)
            if self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp:
                raise AuthorityUnavailable('D13 Owner metadata Graph stamp changed')
            if self.grant_header is not None:
                head=meter.read_fixed_row(self.db,'runtime_budget_grants',('version','status','signature'),
                    'lease_id=? ORDER BY version DESC',(self.bundle.installation_policy.root_grant.lease_id,))
                if head!=self.grant_header:raise AuthorityUnavailable('D13 original Root resource grant changed')
        return self
    def require_read_scope_v1(self):
        self.require_v1()
        if self.db.in_transaction or self.store._lock._is_owned():
            raise AuthorityUnavailable('D13 namespace permit validation must precede Graph SQL')
        if self.port.validate_fence(self.scope)!=self.scope.permit:
            raise AuthorityUnavailable('D13 original namespace READ permit changed')
    def root_v1(self,meter):
        from .issuers import _decode_grant
        self.require_v1(meter)
        grant=self.bundle.installation_policy.root_grant
        head=meter.read_fixed_row(self.db,'runtime_budget_grants',('version','status','signature'),
            'lease_id=? ORDER BY version DESC',(grant.lease_id,))
        if head is None or head[:2]!=(grant.version,'active'):
            raise AuthorityUnavailable('D13 Owner metadata needs the actual current installed Root grant')
        row=_runtime_bounded_fixed_row_v3(self.db,meter,'runtime_budget_grants',('grant_json',),
            'lease_id=? AND version=?',(grant.lease_id,grant.version))
        if row is None:raise AuthorityUnavailable('D13 original Root grant payload is missing')
        actual=_decode_grant(row[0])
        self.graph._GraphCoordinator__d11_issuer._signer.verify('budget-grant.v1',row[0],head[2])
        if actual!=grant or (grant.bot_id,grant.persona_id)!=self.namespace.as_tuple:
            raise AuthorityUnavailable('D13 Owner resource grant differs from its protected installation')
        self.grant_header=head;self.resource_verified=True;self.phase='owner'
    def route_v1(self,meter):
        self.require_v1(meter)
        ns=self.namespace;ins=self.instruction
        c02=_runtime_bounded_fixed_row_v3(self.db,meter,'graph_bundle_operations',
            ('digest','activity_id','effect_id','commit_seq'),
            'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,ins.c02_operation_id))
        key=AtomKey.from_token(ins.source_ref.ref)
        if NamespaceId.from_key(key)!=ns or key.type_name!='memory.source' or c02 is None:
            raise AuthorityUnavailable('D13 Owner route lacks its exact current C02/Source locator')
        columns=('operation_id','platform_ref','conversation_ref','bundle_digest','source_ref')
        route=_runtime_bounded_fixed_row_v3(self.db,meter,'graph_first_ingress_identity_v1',columns,
            'bot=? AND persona=? AND source_ref=? ORDER BY operation_id',(*ns.as_tuple,key.owner.subject))
        if route is None or not route[2]:raise AuthorityUnavailable('D13 Owner route has no actual audience')
        extra=meter.read_fixed_row(self.db,'graph_first_ingress_identity_v1',('operation_id',),
            'bot=? AND persona=? AND source_ref=? AND operation_id>? ORDER BY operation_id',
            (*ns.as_tuple,key.owner.subject,route[0]))
        if extra is not None:raise AuthorityUnavailable('D13 Owner route Source locator is ambiguous')
        self.c02_header,self.route_header=c02,route
        self.phase='qualify'
    def release_payload_v3(self):
        if _READERS.pop(self,None)is None:return
        if self.result is not None:_PREPARED.pop(self.result,None)
        for issued,record in tuple(_ISSUANCES.items()):
            if record[1]is self:_ISSUANCES.pop(issued,None)
        _WRITES.pop(self,None);_ROUTE_ORIGINALS.pop(self,None);_RECOVERED.pop(self,None)
        first=None
        if self.owner_task is not None:
            try:self.owner_task.release_v3()
            except BaseException as error:first=error
        self.owner_task=self.owner_entry=self.result=None
        self.current_self=self.current_owner_guard=self.owner_binding=self.authority=None
        self.c02_header=self.route_header=self.replay_task=self.prepared_header=None
        self.operation.unregister_retained_state_v3(self)
        if first is not None:raise first


class PreparedD13CounterOwnerMetadataV1:
    def __init__(self,key,r):
        if key is not _KEY or not r.complete or not r.read_finished:
            raise AuthorityUnavailable('D13 Owner capsule requires actual finished metadata READ')
        self.reader=r
        _PREPARED[self]=(r,r.work,r.operation,r.owner_entry,r.authority,r.owner_binding,
            r.instruction,r.c02_header,r.route_header,r.work.ticket)
    def require_result_v3(self,work):
        record=_PREPARED.get(self)
        if (record is None or record!=(self.reader,work,self.reader.operation,self.reader.owner_entry,
                self.reader.authority,self.reader.owner_binding,self.reader.instruction,
                self.reader.c02_header,self.reader.route_header,work.ticket)or work.state is not self.reader):
            raise AuthorityUnavailable('D13 Owner capsule crossed its actual producer Work')
        self.reader.require_v1(retained=True)
        return self
    @property
    def recovered_receipt_v1(self):
        self.require_result_v3(self.reader.work)
        saved=_RECOVERED.get(self.reader)
        if saved is None:return None
        if (self.reader.replay_task is not saved[0] or not saved[0].complete
                or canonical_json(saved[0].receipt)!=saved[1]):
            raise AuthorityUnavailable('D13 readonly preparation receipt lost its complete original metadata')
        with bind_runtime_storage_operation_v3(self.reader.operation,self.reader.db):
            self.reader.owner_entry.require_for_v3(self.reader)
        import json
        return json.loads(saved[1])
    def release_payload_v3(self):
        if self in _PREPARED:self.reader.release_payload_v3()


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class D13CounterOwnerIssuanceV1:
    graph:object
    authority:AuthorityContext
    owner:object
    operation_id:str
    bundle:object
    instruction:D13CounterCPUPrepareInstructionV1


def require_actual_d13_counter_owner_metadata_reader_v1(r,meter=None):
    if type(r)is not D13CounterOwnerMetadataReadV1:
        raise AuthorityUnavailable('actual D13 namespace Owner metadata reader required')
    r.require_v1(meter)
    if not r.resource_verified:raise AuthorityUnavailable('D13 Owner cannot precede actual Root grant EOF')
    return r.graph,r.port,r.bundle,r.scope


def require_actual_d13_counter_owner_retained_reader_v1(r,meter=None):
    if type(r)is not D13CounterOwnerMetadataReadV1:
        raise AuthorityUnavailable('actual retained D13 Owner reader required')
    r.require_v1(meter,retained=True)
    return r.graph,r.port,r.bundle,r.scope


def d13_counter_owner_metadata_identity_v1(r):
    if type(r)is not D13CounterOwnerMetadataReadV1 or _READERS.get(r)!=r.identity_v1():
        raise AuthorityUnavailable('D13 Owner metadata identity was not privately issued')
    return r.identity_v1()


def require_actual_d13_counter_owner_route_v1(r,*,authority,audience):
    if type(r)is not D13CounterOwnerMetadataReadV1:
        raise AuthorityUnavailable('D13 Owner route needs its actual metadata reader')
    r.require_v1(retained=r.read_finished)
    if (not r.resource_verified or _ROUTE_ORIGINALS.get(r)!=(r.instruction if r.prepared_header is None else r.prepared_header)
            or r.c02_header is None or r.route_header is None
            or authority is not r.authority or audience!=r.route_header[2]
            or authority.namespace!=r.namespace or authority.purpose!='expression' or authority.audience!=(audience,)
            or authority.actor!=r.current_self.self_entity_ref or authority.owner_scope!=('persona','activity')):
        raise AuthorityUnavailable('D13 Owner audience is not its actual C02/route-qualified authority')
    return r.c02_header,r.route_header


def create_d13_counter_owner_issuance_v1(prepared,graph,bundle,*,operation_id):
    if type(prepared)is not PreparedD13CounterOwnerMetadataV1:
        raise AuthorityUnavailable('D13 execution requires its real retained Owner metadata capsule')
    r=prepared.reader;prepared.require_result_v3(r.work)
    if (r.graph is not graph or r.bundle is not bundle or operation_id!=r.instruction.counter_operation_id+':prepare'
            or r.owner_binding is None or r.authority is None or r.prepared_header is not None):
        raise AuthorityUnavailable('D13 Owner execution issuer changed its fixed original operation')
    issued=D13CounterOwnerIssuanceV1(graph,r.authority,r.owner_binding,operation_id,bundle,r.instruction)
    _ISSUANCES[issued]=(prepared,r,r.work.ticket)
    return issued


def require_actual_d13_counter_owner_issuance_v1(issued,graph,authority,operation_id):
    record=_ISSUANCES.get(issued)if type(issued)is D13CounterOwnerIssuanceV1 else None
    if record is None:raise AuthorityUnavailable('actual Root-owned D13 execution issuer required')
    prepared,r,ticket=record
    prepared.require_result_v3(r.work)
    if (issued.graph is not graph or issued.authority is not authority or issued.operation_id!=operation_id
            or issued.bundle is not r.bundle or issued.instruction is not r.instruction or issued.owner is not r.owner_binding
            or require_graph_storage_work_admission_v3(graph)!=ticket):
        raise AuthorityUnavailable('D13 execution issuer crossed its actual Owner/Root/ticket')
    return issued.owner


def require_actual_d13_counter_owner_write_reader_v1(r,scope):
    record=_WRITES.get(r)
    if record is None or record[1]is not scope:
        raise AuthorityUnavailable('D13 Owner WRITE has no actual pending issuer observation')
    issued=record[0]
    require_actual_d13_counter_owner_issuance_v1(issued,r.graph,r.authority,issued.operation_id)
    if (scope.operation!='write' or scope.namespace!=r.namespace or scope.operation_id!=record[2][1]
            or scope.generation!=r.instruction.activation_generation or scope.pinned_anchor!=r.scope.pinned_anchor
            or scope.graph_revision!=r.graph_stamp[0].graph_revision or scope.graph_epoch!=r.graph_stamp[1]):
        raise AuthorityUnavailable('D13 Owner WRITE differs from its retained metadata basis')
    return r


def observe_current_d13_counter_owner_write_v1(issued,graph,scope):
    require_actual_d13_counter_owner_issuance_v1(issued,graph,issued.authority,issued.operation_id)
    r=_ISSUANCES[issued][1]
    if r.db.in_transaction or r.store._lock._is_owned():
        raise AuthorityUnavailable('D13 fresh Owner observations must precede Graph SQL')
    if r.port.validate_fence(scope)!=scope.permit:
        raise AuthorityUnavailable('D13 actual fresh WRITE permit differs')
    with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock:
        r.db.execute('BEGIN')
        try:
            with runtime_storage_quantum_v3(r.db)as meter:
                r.require_v1(meter,retained=True)
                attempt=_counter_write_attempt_v1(r,issued,scope,meter)
        finally:r.db.rollback()
    _WRITES[r]=(issued,scope,attempt)
    require_actual_d13_counter_owner_write_reader_v1(r,scope)
    return r.owner_entry.observe_write_v3(r,scope)


def require_current_d13_counter_owner_write_v1(issued,graph,scope,guard,owner,meter):
    require_actual_d13_counter_owner_issuance_v1(issued,graph,issued.authority,issued.operation_id)
    r=_ISSUANCES[issued][1];require_actual_d13_counter_owner_write_reader_v1(r,scope)
    with bind_runtime_storage_operation_v3(r.operation,r.db):
        r.require_v1(meter,retained=True)
        if _counter_write_attempt_v1(r,issued,scope,meter)!=_WRITES[r][2]:
            raise AuthorityUnavailable('D13 actual Owner WRITE attempt changed inside its transaction')
        return r.owner_entry.require_write_v3(r,scope,guard,owner,meter)


@contextmanager
def bind_current_d13_counter_owner_operation_v1(issued,graph):
    require_actual_d13_counter_owner_issuance_v1(issued,graph,issued.authority,issued.operation_id)
    r=_ISSUANCES[issued][1]
    with bind_runtime_storage_operation_v3(r.operation,r.db):
        yield


def _counter_write_attempt_v1(r,issued,scope,meter):
    row=meter.read_fixed_row(r.db,'graph_owner_domain_attempts_v3',
        ('request_digest','attempt_id','graph_revision','graph_epoch'),
        'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,issued.operation_id))
    expected=canonical_digest({'schema':'sylanne3.d13.counter-prepare-write.v1','instruction':issued.instruction})
    if row!=(expected,scope.operation_id,scope.graph_revision,scope.graph_epoch.revision):
        raise AuthorityUnavailable('D13 fresh WRITE is not its actual original owner-domain attempt')
    return row


def begin_current_d13_counter_owner_metadata_v1(graph,bootstrap,bundle,*,instruction):
    graph._admin(bootstrap);require_graph_storage_work_admission_v3(graph)
    if (type(instruction)is not D13CounterCPUPrepareInstructionV1
            or graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not bundle
            or instruction.namespace!=bundle.installation_policy.namespace
            or instruction.install_id!=bundle.installation_policy.installation_id):
        raise AuthorityUnavailable('actual installed Core CPU preparation instruction required')
    store=graph._GraphCoordinator__store;db=store._db;port=graph._GraphCoordinator__content_fence_v2
    if db.in_transaction or store._lock._is_owned():raise AuthorityUnavailable('D13 Owner metadata begins outside Graph SQL')
    selector=D13CurrentFramePrepareSelectorV7(instruction.install_id,instruction.authority_namespace,
        instruction.namespace,instruction.c02_operation_id,instruction.plan_ref,instruction.counter_operation_id)
    graph._recover_current_d13_counter_write_ack_v1(bootstrap,bundle,selector)
    graph._GraphCoordinator__local_module_admission.require_v1(('d13',),'prepare_current_d13_counter_cpu_v1')
    actual=InstalledD13CoreCounterPortV1(port,policy=bundle.d13_wire_policy).prepare_current_d13_frame_v7(selector)
    if actual!=instruction and type(actual)is not D13CoreFrameIntentHeaderV7:
        raise AuthorityUnavailable('D13 Owner locator differs from its actual Core instruction')
    prepared_header=actual if type(actual)is D13CoreFrameIntentHeaderV7 else None
    if prepared_header is not None:_require_replay_header_v1(instruction,prepared_header)
    clock=port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    deadline=min(instruction.expires_at_utc,bundle.installation_policy.root_grant.valid_until_utc)
    opid='d13-counter-owner:'+token_hex(16)
    operation=begin_runtime_storage_operation_v3(db,opid,deadline)
    if operation is None:raise AuthorityUnavailable('D13 Owner metadata needs actual bounded runtime storage')
    r=None;scope=None
    try:
        graph._recover_d13_counter_preparation_ack_v1(bootstrap,bundle,instruction,operation)
        clock=port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
        if trusted_upper(clock)>=deadline:raise AuthorityUnavailable('D13 Owner original deadline expired')
        with bind_runtime_storage_operation_v3(operation,db),store._lock,runtime_storage_quantum_v3(db):
            stamp=graph._v2_graph_stamp(instruction.namespace)
        metadata,epoch=stamp;target=metadata.requirements
        if target.activation_generation!=instruction.activation_generation or target.authority_namespace!=instruction.authority_namespace:
            raise AuthorityUnavailable('D13 Owner namespace installation generation changed')
        anchor=port.current_anchor(namespace=instruction.namespace,authority_namespace=target.authority_namespace)
        if not graph._anchor_matches(target,anchor):raise AuthorityUnavailable('D13 Owner current Core/Graph anchor differs')
        permit=port.begin_fence(namespace=instruction.namespace,authority_namespace=target.authority_namespace,
            holder=graph._GraphCoordinator__holder,generation=target.activation_generation,
            operation='read',operation_id=opid,expected_anchor=anchor)
        scope=FenceScope(instruction.namespace,target.authority_namespace,target.activation_generation,
            'read',opid,permit,anchor,epoch,metadata.graph_revision)
        if port.validate_fence(scope)!=permit:raise AuthorityUnavailable('D13 Owner namespace READ changed')
        r=D13CounterOwnerMetadataReadV1(graph,bootstrap,bundle,instruction,operation,
            _NamespaceReadFenceV1(scope,metadata,epoch),clock,prepared_header)
        r.work=create_graph_storage_work_v3(graph,kind=KIND,operation_id=opid,selection_digest=operation.selection_digest,
            deadline_utc=deadline,state=r,operation=operation)
        _READERS[r]=r.identity_v1();operation.register_retained_state_v3(r)
        return r.work
    except BaseException as first:
        if r is not None:
            try:r.release_payload_v3()
            except BaseException as later:first.add_note('D13 Owner factory payload cleanup failed: '+type(later).__name__)
        if scope is not None:
            try:_finish_namespace_read_v1(port,scope)
            except BaseException as later:first.add_note('D13 Owner factory READ cleanup failed: '+type(later).__name__)
        try:finish_runtime_storage_operation_v3(operation)
        except BaseException as later:first.add_note('D13 Owner factory retention cleanup failed: '+type(later).__name__)
        raise


def _finish_namespace_read_v1(port,scope):
    port.finish_fence(scope,request_id='finish:'+scope.operation_id,
        request_digest='sha256:'+canonical_digest({'operation_id':scope.operation_id,
            'permit_token':scope.permit.token,'action':'finish_read'}))


def advance_current_d13_counter_owner_metadata_v1(graph,work):
    r=work.state
    if type(r)is not D13CounterOwnerMetadataReadV1 or r.work is not work or r.graph is not graph:
        raise AuthorityUnavailable('actual D13 Owner metadata Work required')
    r.require_read_scope_v1()
    if r.phase=='owner':
        if r.owner_task is None:
            from ..authority_service.owner_location_read_v3 import create_current_host_d13_counter_owner_metadata_task_v1
            r.owner_task=create_current_host_d13_counter_owner_metadata_task_v1(r)
        elif not r.owner_task.complete:r.owner_task.advance()
        if r.owner_task.complete:
            r.owner_entry=r.owner_task.result;r.current_self=r.owner_entry.current_self
            r.current_owner_guard=r.owner_entry.current_owner_guard;r.owner_principal=r.owner_entry.owner_principal
            r.phase='route'
    elif r.phase=='qualify':
        ins=r.instruction
        selector=D13CurrentFramePrepareSelectorV7(ins.install_id,ins.authority_namespace,ins.namespace,
            ins.c02_operation_id,ins.plan_ref,ins.counter_operation_id)
        actual=InstalledD13CoreCounterPortV1(r.port,policy=r.bundle.d13_wire_policy).prepare_current_d13_frame_v7(selector)
        if actual!=(ins if r.prepared_header is None else r.prepared_header):
            raise AuthorityUnavailable('D13 route qualification changed its actual Core instruction')
        _ROUTE_ORIGINALS[r]=actual
        r.authority=AuthorityContext(r.current_self.self_entity_ref,'d13',
            'installed-d13-counter:'+r.instruction.frame_intent_id,r.namespace,('persona','activity'),
            'expression',(r.route_header[2],),r.port.installation_grant.publisher_policy_ref,
            r.instruction.activation_generation)
        r.owner_binding=r.owner_entry.qualify_route_v3(r,authority=r.authority,audience=r.route_header[2])
        if r.prepared_header is None:r.complete=True
        else:r.phase='replay'
    else:
        with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock:
            r.db.execute('BEGIN')
            try:
                with runtime_storage_quantum_v3(r.db)as meter:
                    if r.phase=='root':r.root_v1(meter)
                    elif r.phase=='route':r.route_v1(meter)
                    elif r.phase=='replay':
                        if r.replay_task is None:r.replay_task=_PreparedCounterReplayReadV1(r)
                        elif r.replay_task.advance_v1(meter):
                            _RECOVERED[r]=(r.replay_task,canonical_json(r.replay_task.receipt))
                            r.complete=True
                    else:raise AuthorityUnavailable('D13 Owner metadata phase is unregistered')
            finally:r.db.rollback()
    r.operation.refresh_retained_state_v3(r)
    r.require_read_scope_v1()
    if r.complete:
        _finish_namespace_read_v1(r.port,r.scope);r.read_finished=True
        r.result=PreparedD13CounterOwnerMetadataV1(_KEY,r)
        return GraphStorageStepV3('complete',r.result)
    return GraphStorageStepV3('progress')


def finish_current_d13_counter_owner_metadata_v1(graph,work,error):
    r=work.state
    if type(r)is not D13CounterOwnerMetadataReadV1 or r.work is not work or r.graph is not graph:
        raise AuthorityUnavailable('D13 Owner finish crossed its actual Work')
    first=error
    if not r.read_finished:
        try:_finish_namespace_read_v1(r.port,r.scope);r.read_finished=True
        except BaseException as later:
            if first is None:first=later
            elif later is not first:first.add_note('D13 Owner READ finish failed: '+type(later).__name__)
    if first is None and not r.complete:first=AuthorityUnavailable('D13 Owner cannot publish partial metadata EOF')
    if first is None:work.result_lease=r.operation;return
    try:r.release_payload_v3()
    except BaseException as later:
        if later is not first:first.add_note('D13 Owner payload cleanup failed: '+type(later).__name__)
    try:finish_runtime_storage_operation_v3(r.operation)
    except BaseException as later:
        if later is not first:first.add_note('D13 Owner retention cleanup failed: '+type(later).__name__)
    if error is None:raise first


class _D13CounterOwnerHandoffV1:
    def __init__(self,graph,parent,prepared,issued):
        self.graph,self.parent,self.prepared,self.issued=graph,parent,prepared,issued
        self.ticket,self.selection=parent.ticket,parent.selection_digest
        self.deadline=min(parent.deadline_utc,issued.instruction.expires_at_utc)
        self.locator=token_bytes(32);self.thread=get_ident();self.lock=Lock()
        self.handoff=self.child=self.holder=None
        self.started=self.closed=False;self.first_error=None
        parent.operation.register_retained_state_v3(self)
        _HANDOFFS[self.locator]=self;_HANDOFF_ISSUED[issued]=self
    def _runtime_retained_heap_bytes_v3(self):return 8192+len(self.locator)*2
    def require_v1(self,graph):
        if (_HANDOFFS.get(self.locator)is not self or self.closed or self.graph is not graph
                or get_ident()!=self.thread or self.parent.ticket!=self.ticket
                or self.parent.selection_digest!=self.selection
                or self.parent.operation is not self.prepared.reader.operation
                or self.parent.state is not self.prepared.reader or self.parent.operation.closed
                or _HANDOFF_ISSUED.get(self.issued)is not self):
            raise AuthorityUnavailable('D13 Owner handoff lost its original retained parent')
        require_actual_d13_counter_owner_issuance_v1(self.issued,graph,self.issued.authority,self.issued.operation_id)
        return self
    def remember_v1(self,error):
        with self.lock:
            if self.first_error is None:self.first_error=error
    def close_v1(self):
        with self.lock:
            if self.closed:return
            self.closed=True
            first=self.first_error;parent=self.parent;issued=self.issued;holder=self.holder
            self.holder=None
            _HANDOFFS.pop(self.locator,None);_HANDOFF_ISSUED.pop(issued,None)
        _ISSUANCES.pop(issued,None)
        actions=[('handoff metadata',lambda:parent.operation.unregister_retained_state_v3(self))]
        if holder is not None:actions.append(('original Owner payload/lease',holder.release))
        for label,action in actions:
            try:action()
            except BaseException as later:
                if first is None:first=later
                elif later is not first:first.add_note('D13 Owner '+label+' cleanup failed: '+type(later).__name__)
        self.graph=self.parent=self.prepared=self.issued=self.handoff=self.child=None
        if first is not None and first is not self.first_error:raise first


def issue_d13_counter_owner_source_handoff_v1(graph,*,parent,prepared,issued):
    from ..graph_storage_handoff_v3 import issue_graph_storage_handoff_v3
    if (type(parent)is not GraphStorageWorkV3 or parent.kind!=KIND
            or type(prepared)is not PreparedD13CounterOwnerMetadataV1
            or parent.state is not prepared.reader or not parent.terminal or parent.phase!='complete'
            or not parent._finish_called or issued in _HANDOFF_ISSUED):
        raise AuthorityUnavailable('D13 source handoff requires its actual terminal Owner metadata Work')
    parent._require_invocation(graph);prepared.require_result_v3(parent)
    require_actual_d13_counter_owner_issuance_v1(issued,graph,issued.authority,issued.operation_id)
    if _ISSUANCES[issued][0]is not prepared:raise AuthorityUnavailable('D13 Owner issuer has another capsule')
    record=_D13CounterOwnerHandoffV1(graph,parent,prepared,issued)
    try:
        if parent._request_lifetime is None:parent._request_lifetime=ExitStack()
        parent._request_lifetime.callback(record.close_v1)
        clock=graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
        record.handoff=issue_graph_storage_handoff_v3(parent,factory=_start_d13_counter_owner_child_v1,
            command=record.locator,deadline_utc=record.deadline,observed_utc=trusted_upper(clock))
        return record.handoff
    except BaseException as first:
        record.remember_v1(first);record.close_v1();raise


def require_d13_counter_owner_child_deadline_v1(issued,graph):
    record=_HANDOFF_ISSUED.get(issued)
    if record is None:raise AuthorityUnavailable('D13 counter child has no actual Owner handoff')
    record.require_v1(graph)
    if not record.started:raise AuthorityUnavailable('D13 counter child factory has not consumed its locator')
    return record.deadline


def _start_d13_counter_owner_child_v1(graph,locator):
    from ..graph_worker import _STORAGE_INVOCATION_V3
    record=_HANDOFFS.get(locator)if type(locator)is bytes else None
    if record is None or record.locator is not locator:
        raise AuthorityUnavailable('D13 Owner handoff locator is absent or consumed')
    record.require_v1(graph);invocation=_STORAGE_INVOCATION_V3.get()
    if (invocation is None or invocation.mode!='ordinary' or not invocation.initial
            or invocation.coordinator is not graph or invocation.ticket!=record.ticket):
        raise AuthorityUnavailable('D13 Owner handoff requires its same actual worker ticket')
    with record.lock:
        if record.started:raise AuthorityUnavailable('D13 Owner handoff may start only once')
        record.started=True
    try:
        child=graph._continue_current_d13_counter_cpu_source_work_v1(record.issued)
        if child is not record.child:
            raise AuthorityUnavailable('D13 counter factory did not bind its actual private FULL child')
        return child
    except BaseException as first:
        record.remember_v1(first);raise


def bind_current_d13_counter_owner_child_v1(issued,child):
    from .current_graph_full_read_v3 import require_actual_d13_counter_prepare_full_reader_v1
    record=_HANDOFF_ISSUED.get(issued)
    if record is None:raise AuthorityUnavailable('actual D13 Owner source handoff required')
    record.require_v1(child.coordinator)
    if (type(child)is not GraphStorageWorkV3 or child.kind!='current_graph_full_read_v3'
            or child.coordinator is not record.graph or child.ticket!=record.ticket or child.terminal
            or child.operation is record.parent.operation or child.deadline_utc>record.deadline
            or record.child is not None or not record.started):
        raise AuthorityUnavailable('D13 Owner handoff child changed its original ticket/deadline')
    require_actual_d13_counter_prepare_full_reader_v1(child.state)
    record.child=child
    if child._request_lifetime is None:child._request_lifetime=ExitStack()
    child._request_lifetime.callback(record.close_v1)
    return child


def _d13_owner_handoff_record_v1(handoff):
    locator=handoff.command
    record=_HANDOFFS.get(locator)if type(locator)is bytes else None
    return record if record is not None and record.handoff is handoff else None


def _d13_owner_payload_v1(callback,prepared):
    return (getattr(callback,'__self__',None)is prepared
        and getattr(callback,'__func__',None)is PreparedD13CounterOwnerMetadataV1.release_payload_v3)


def retain_d13_counter_owner_parent_holder_v1(handoff,holder,*,child=None,error=None):
    record=_d13_owner_handoff_record_v1(handoff)
    if record is None:return False
    if (holder is not record.parent.operation or holder.closed
            or not _d13_owner_payload_v1(holder._payload_release,record.prepared)):
        if error is not None:record.remember_v1(error);return False
        raise AuthorityUnavailable('D13 Owner handoff cannot retain another payload/lease')
    if error is None:
        record.require_v1(record.graph)
        if child is not record.child or child.ticket!=record.ticket:
            raise AuthorityUnavailable('D13 Owner retention has no actual bound FULL child')
    else:record.remember_v1(error)
    with record.lock:
        if record.closed or record.holder is not None:
            raise AuthorityUnavailable('D13 Owner original result ownership was already moved')
        record.holder=holder
    return True


def retain_invalid_d13_counter_owner_parent_v1(handoff,graph,call,value,error):
    from ..graph_worker import OwnedGraphStorageResultV3
    record=_d13_owner_handoff_record_v1(handoff)
    if record is None:return False
    if (record.graph is not graph or record.parent is not call.work or record.ticket!=call.ticket
            or type(value)is not OwnedGraphStorageResultV3 or value._value is not handoff
            or value._lease is not record.parent.operation
            or not (_d13_owner_payload_v1(value._release_payload,record.prepared)
                or value._release_payload is None and _d13_owner_payload_v1(value._lease._payload_release,record.prepared))):
        return False
    record.remember_v1(error)
    actual,holder=value.take_value_v3()
    if actual is not handoff:raise AuthorityUnavailable('D13 invalid handoff changed its actual ownership')
    return retain_d13_counter_owner_parent_holder_v1(handoff,holder,error=error)



def _require_replay_header_v1(ins,header):
    names=('namespace','install_id','authority_namespace','frame_intent_id','frame_intent_digest',
        'counter_operation_id','c02_operation_id','plan_ref','job_id','generation_call_id',
        'activation_generation','owner_responsibility_digest','owner_grant_digest','source_scope_digest',
        'parent_budget_lease_ref','budget_grant_digest','frozen_at_utc','expires_at_utc','prospective_plan_deadline_utc')
    if type(header)is not D13CoreFrameIntentHeaderV7 or any(getattr(header,k)!=getattr(ins,k)for k in names):
        raise AuthorityUnavailable('D13 replay Core header changed its original instruction commitments')


class _PreparedCounterProjectionV1:
    """Full canonical EOF with a closed metadata projection, never a partial Prepared DTO."""
    def __init__(self):
        from .c04_internal_work_original_v1 import C04InternalWorkPreparedV1
        from ..authority_service.internal_work_contract import InternalWorkBindingV1
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.top=frozenset(f.name for f in fields(C04InternalWorkPreparedV1))
        self.binding_fields=frozenset(f.name for f in fields(InternalWorkBindingV1))
        self.keys=set();self.binding_keys=set();self.values={};self.buffers={}
        self.last_token=None;self.pair={};self.count=0
    def emit_v1(self,event):
        path=event.path
        if event.kind=='key':
            if len(path)==1 and path[0]in self.top:self.keys.add(path[0])
            elif len(path)==2 and path[0]=='binding' and path[1]in self.binding_fields:self.binding_keys.add(path[1])
            else:raise AuthorityUnavailable('D13 prepared metadata has unregistered fields')
        elif event.kind=='object_start':
            if path not in ((),('binding',)):raise AuthorityUnavailable('D13 prepared metadata has an unregistered object')
        elif event.kind=='array_start':
            if path==('read_versions',):return
            if len(path)==2 and path[0]=='read_versions' and path[1]==self.count and self.count<1024:
                self.pair={};return
            raise AuthorityUnavailable('D13 prepared read-set grammar exceeds its original finite profile')
        elif event.kind=='array_end' and len(path)==2:
            if path[0]!='read_versions' or set(self.pair)!={0,1}:
                raise AuthorityUnavailable('D13 prepared metadata has an incomplete read-set member')
            token,revision=self.pair[0],self.pair[1]
            if (type(token)is not str or not token or type(revision)is not int or revision<0
                    or self.last_token is not None and token<=self.last_token):
                raise AuthorityUnavailable('D13 prepared read-set metadata is not exact sorted unique versions')
            self.last_token=token;self.pair={};self.count+=1
        elif event.kind=='scalar_start':
            allowed=(len(path)==1 and path[0]in self.top-{'binding','read_versions'}
                or len(path)==2 and path[0]=='binding' and path[1]in self.binding_fields
                or len(path)==3 and path[:2]==('read_versions',self.count)and path[2]in(0,1))
            if not allowed:raise AuthorityUnavailable('D13 prepared metadata scalar has another shape')
            self.buffers[path]=bytearray()
        elif event.kind=='scalar_chunk':
            target=self.buffers[path]
            if len(target)+len(event.raw)>8192:raise AuthorityUnavailable('D13 prepared metadata scalar exceeds its original bound')
            target.extend(event.raw)
        elif event.kind=='scalar_end':
            import json
            value=json.loads(self.buffers.pop(path))
            if path[0]=='read_versions':self.pair[path[2]]=value
            else:self.values[path]=value
    def finish_v1(self):
        if self.keys!=self.top or self.binding_keys!=self.binding_fields or self.buffers:
            raise AuthorityUnavailable('D13 prepared metadata EOF has missing exact fields')
        result=self.parser.finish()
        from ..authority_service.internal_work_contract import InternalWorkBindingV1
        binding=InternalWorkBindingV1(**{name:self.values[('binding',name)]for name in self.binding_fields})
        controls={name:self.values[(name,)]for name in self.top-{'binding','read_versions'}}
        if controls['schema']!='sylanne3.c04.internal_work_prepared.v1':
            raise AuthorityUnavailable('D13 replay prepared metadata has another actual schema')
        for name in ('body_profile_ref','body_state_ref','owner_grant_ref','budget_reservation_operation_id'):
            if type(controls[name])is not str or not controls[name]:raise AuthorityUnavailable('D13 prepared metadata reference is absent')
        for name in ('body_profile_revision','body_state_revision','body_reservation_revision','owner_grant_revision',
                'graph_revision','access_epoch','delete_epoch'):
            if type(controls[name])is not int or controls[name]<0:raise AuthorityUnavailable('D13 prepared metadata revision is invalid')
        return result,binding,controls


class _PreparedCounterReplayReadV1:
    def __init__(self,r):
        self.reader=r;self.phase='header';self.head=None;self.total=None
        self.offset=0;self.fragment=b'';self.projection=_PreparedCounterProjectionV1()
        self.binding=self.controls=self.receipt=None;self.complete=False
    def retained_bytes_v1(self):
        return 65536+_heap((self.head,self.fragment,self.projection.values,self.projection.buffers,
            self.projection.last_token,self.projection.pair,self.binding,self.controls,self.receipt))
    def advance_v1(self,meter):
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
        from ..contracts import canonical_json
        from ..graph_coordinator import namespace_ref
        r=self.reader;r.require_v1(meter);ins=r.instruction;ns=r.namespace
        key=(*ns.as_tuple,ins.counter_operation_id)
        if self.phase=='header':
            self.head=meter.read_fixed_row(r.db,'graph_c04_internal_work_prepared_v1',
                ('binding_digest','prepared_digest'),'bot=? AND persona=? AND operation_id=?',key)
            if self.head is None:raise AuthorityUnavailable('D13 replay has no actual C04 prepared metadata original')
            meter.require_available(1024)
            row=r.db.execute('SELECT typeof(prepared_json),length(CAST(prepared_json AS BLOB)) '
                'FROM graph_c04_internal_work_prepared_v1 WHERE bot=? AND persona=? AND operation_id=?',key).fetchone()
            meter.charge_read(32)
            if row is None or row[0]!='text' or row[1]<1:raise AuthorityUnavailable('D13 prepared metadata physical column is missing')
            self.total=row[1];self.phase='column';return False
        if self.phase=='column':
            if self.fragment:
                part=self.fragment[:1024];self.fragment=self.fragment[len(part):]
                self.projection.parser.feed(part,self.projection.emit_v1);return False
            if self.offset<self.total:
                chunk,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table='graph_c04_internal_work_prepared_v1',
                    column='prepared_json',where='bot=? AND persona=? AND operation_id=?',parameters=key,
                    start=self.offset,length=min(16384,self.total-self.offset),meter=meter)
                if (total,kind)!=(self.total,'text')or not chunk:
                    raise AuthorityUnavailable('D13 prepared metadata bytes changed before EOF')
                self.offset+=len(chunk);self.fragment=chunk;return False
            result,binding,controls=self.projection.finish_v1()
            if (result.sha256,result.byte_count)!=(self.head[1],self.total)or binding.binding_digest!=self.head[0]:
                raise AuthorityUnavailable('D13 prepared metadata canonical EOF differs from its original header')
            if ((binding.namespace,binding.operation_id,binding.activity_id,binding.execution_id,binding.input_digest,
                    binding.algorithm_ref,binding.algorithm_build_digest,binding.parent_budget_lease_ref,binding.activation_generation)
                    !=(namespace_ref(ns),ins.counter_operation_id,ins.activity_id,ins.execution_id,ins.input_digest,
                        ins.algorithm_id,ins.algorithm_build_digest,ins.parent_budget_lease_ref,ins.activation_generation)
                    or controls['owner_grant_digest']!=ins.owner_grant_digest
                    or (controls['budget_reservation_operation_id'],controls['budget_reservation_digest'])!=(
                        r.prepared_header.cpu_reservation_ref,r.prepared_header.cpu_reservation_digest)):
                raise AuthorityUnavailable('D13 replay prepared binding/control metadata changed its original instruction')
            self.binding,self.controls=binding,controls;self.phase='attempt';return False
        if self.phase=='attempt':
            row=_runtime_bounded_fixed_row_v3(r.db,meter,'graph_owner_domain_attempts_v3',
                ('request_digest','attempt_id','receipt_json'),
                'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,ins.counter_operation_id+':prepare'))
            expected=canonical_digest({'schema':'sylanne3.d13.counter-prepare-write.v1','instruction':ins})
            receipt={'schema':'sylanne3.d13.counter-cpu-preparation-receipt.v1',
                'frame_intent_id':ins.frame_intent_id,'counter_operation_id':ins.counter_operation_id,
                'instruction_digest':canonical_digest(ins),'input_digest':ins.input_digest,
                'binding_digest':self.head[0],'prepared_digest':self.head[1],'job_id':ins.job_id,'status':'prepared'}
            if row is None or row[0]!=expected or not row[1]or row[2]!=canonical_json(receipt):
                raise AuthorityUnavailable('D13 replay lacks its actual complete Owner-attempt preparation receipt')
            job=meter.read_fixed_row(r.db,'runtime_jobs',('job_id','operation_id','activity_id','effect_id','bot_id',
                'persona_id','work_kind','budget_ref'),'job_id=?',(ins.job_id,))
            if job!=(ins.job_id,ins.counter_operation_id,ins.activity_id,ins.execution_id,*ns.as_tuple,
                    ins.algorithm_id,ins.parent_budget_lease_ref):
                raise AuthorityUnavailable('D13 replay actual job metadata differs from its prepared original')
            head=meter.read_fixed_row(r.db,'graph_c04_internal_work_prepared_v1',
                ('binding_digest','prepared_digest'),'bot=? AND persona=? AND operation_id=?',key)
            if head!=self.head:raise AuthorityUnavailable('D13 prepared original changed after its full metadata EOF')
            _require_replay_header_v1(ins,r.prepared_header)
            self.receipt=receipt;self.complete=True;return True
        raise AuthorityUnavailable('D13 prepared replay metadata has an unregistered phase')


def require_d13_counter_owner_recovered_receipt_v1(work,*,instruction,receipt):
    if type(work)is not GraphStorageWorkV3 or work.kind!=KIND or not work.terminal or work.phase!='complete':
        raise AuthorityUnavailable('D13 readonly recovery requires its actual completed metadata Work')
    r=work.state
    if type(r)is not D13CounterOwnerMetadataReadV1 or r.instruction!=instruction or r.result is None:
        raise AuthorityUnavailable('D13 readonly recovery changed its original instruction')
    actual=r.result.recovered_receipt_v1
    if actual is None or actual!=receipt:raise AuthorityUnavailable('D13 readonly recovery has no verified original receipt')
    return work
