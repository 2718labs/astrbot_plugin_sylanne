"""Owner rebuild selection, UUID-bound commit metadata and cold finish."""
from contextlib import ExitStack
from secrets import token_bytes,token_hex
from threading import get_ident
from weakref import WeakKeyDictionary
import time

from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..runtime_storage_v3 import (RuntimeStorageOperationV3,_INSTALLED,runtime_storage_v3,
    begin_runtime_storage_operation_v3,finish_runtime_storage_operation_v3,
    bind_runtime_storage_operation_v3,runtime_storage_quantum_v3)
from ..graph_worker import GraphStorageWorkV3,GraphStorageStepV3,create_graph_storage_work_v3
from .dispatch_current_inventory_v3 import _heap
from .current_character_labor_adoption_v1 import _payload_heap_v1,_LocatorMetadataColumnV1
from .d02_character_labor_read_v1 import SELECT_REBUILD_KIND_V1
from .d02_character_labor_rebuild_v1 import (
    CharacterLaborRebuildSelectorV1,CharacterLaborRebuildCommandContextV1,
    consume_character_labor_rebuild_selection_v1,character_labor_rebuild_selection_view_v1,
    require_detached_character_labor_rebuild_inputs_v1)

COLD_KIND="current_character_labor_rebuild_cold_v1"
_KEY=object()
_PENDING={}
_INVOCATIONS=WeakKeyDictionary()
_COLD_OWNERS=WeakKeyDictionary()
_COLD_RESULTS=WeakKeyDictionary()
_SUBMISSIONS={}


def _owner_identity_v1(graph,authority,lease):
    graph._authorize(lease,authority,frozenset(("d02",)),owner_read=True)
    owner=graph._GraphCoordinator__owner_leases.get(lease)
    session=graph._GraphCoordinator__owner_session_proofs.get(lease)
    if owner is None or session is None or authority.issuer_domain!="d12":
        raise AuthorityUnavailable("labor rebuild needs the actual current D12 Owner/session")
    return owner,session


class CharacterLaborRebuildColdReadV1:
    def __init__(self,graph,authority,lease,bundle,operation,clock,stamp,command,
            activity_id,audience_ref,parent_budget_lease_ref):
        from .first_ingress_v2 import trusted_upper
        self.graph,self.authority,self.lease,self.bundle=graph,authority,lease,bundle
        self.store=graph._GraphCoordinator__store
        self.db,self.operation=self.store._db,operation
        self.namespace,self.issuer=authority.namespace,graph._GraphCoordinator__d11_issuer
        self.owner,self.session=_owner_identity_v1(graph,authority,lease)
        self.command_context=command
        self.mutation_operation_id,self.command_input_digest=command.mutation_operation_id,command.command_input_digest
        self.selector,self.expected_choice_digest=command.selector,command.expected_choice_digest
        self.command_scope=command.scope
        self.activity_id,self.audience_ref,self.parent_budget_lease_ref=activity_id,audience_ref,parent_budget_lease_ref
        self.selection_digest,self.graph_stamp=operation.selection_digest,stamp
        self.clock,self.deadline_utc=clock,operation.deadline_utc
        self.monotonic_deadline=time.monotonic()+operation.deadline_utc-trusted_upper(clock)
        self.thread,self.work=get_ident(),None
        self.resource_verified=False
        self.grant_header=self.grant_column=self.binding_task=None
        self.complete=False
        self.result=None

    def _identity_v1(self):
        return (self.graph,self.authority,self.lease,self.bundle,self.operation,self.work,self.owner,self.session,
            self.namespace,self.command_context,self.activity_id,self.audience_ref,self.parent_budget_lease_ref,
            self.selection_digest,self.graph_stamp,self.thread,self.deadline_utc,self.monotonic_deadline)

    def _runtime_retained_heap_bytes_v3(self):
        column=()if self.grant_column is None else (
            self.grant_column.body,self.grant_column.fragment,self.grant_column.value)
        return 16384+_payload_heap_v1((self.command_context,self.grant_header,column))

    def require_v1(self,meter=None):
        if (_COLD_OWNERS.get(self)!=self._identity_v1()or self.thread!=get_ident()
                or self.operation.closed or self.work.state is not self or self.work.operation is not self.operation
                or self.work.kind!=COLD_KIND or self.work.coordinator is not self.graph
                or runtime_storage_v3(self.db)is not self.operation.handle
                or self.operation.selection_digest!=self.selection_digest
                or time.monotonic()>=self.monotonic_deadline
                or self.graph._GraphCoordinator__owner_leases.get(self.lease)is not self.owner
                or self.graph._GraphCoordinator__owner_session_proofs.get(self.lease)is not self.session):
            raise AuthorityUnavailable("labor cold metadata lost its actual Owner/Work/Root resource selection")
        self.work._require_invocation(self.graph)
        _owner_identity_v1(self.graph,self.authority,self.lease)
        if meter is not None:
            if not self.db.in_transaction or not self.store._lock._is_owned():
                raise AuthorityUnavailable("labor cold metadata quantum needs its own actual Graph transaction")
            self.operation.handle.require_current(meter)
            if self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp:
                raise AuthorityUnavailable("labor cold metadata Graph stamp changed")
            grant=self.bundle.installation_policy.root_grant
            header=meter.read_fixed_row(self.db,"runtime_budget_grants",("version","status","signature"),
                "lease_id=? ORDER BY version DESC",(grant.lease_id,))
            if self.grant_header is not None and header!=self.grant_header:
                raise AuthorityUnavailable("labor current Root resource grant changed")
        return self

    def advance_v1(self,meter):
        self.require_v1(meter)
        grant=self.bundle.installation_policy.root_grant
        if self.grant_header is None:
            header=meter.read_fixed_row(self.db,"runtime_budget_grants",("version","status","signature"),
                "lease_id=? ORDER BY version DESC",(grant.lease_id,))
            if header is None or header[:2]!=(grant.version,"active"):
                raise AuthorityUnavailable("labor cold metadata needs the actual current active installed Root grant")
            self.grant_header=header
            return
        if not self.resource_verified:
            if self.grant_column is None:
                self.grant_column=_LocatorMetadataColumnV1(self,"runtime_budget_grants","grant_json",
                    ("lease_id","version"),(grant.lease_id,grant.version),
                    signature_kind="budget-grant.v1",signature=self.grant_header[2])
                return
            if not self.grant_column.advance(meter):return
            from .issuers import _decode_grant
            actual=_decode_grant(self.grant_column.body.decode("utf-8"))
            if actual!=grant or (grant.bot_id,grant.persona_id)!=self.namespace.as_tuple:
                raise AuthorityUnavailable("labor cold metadata Root resource original differs from protected installation")
            self.resource_verified=True
            return
        from .d02_character_labor_rebuild_v1 import (
            create_character_labor_rebuild_binding_read_v1,require_character_labor_rebuild_binding_read_v1)
        if self.binding_task is None:
            self.binding_task=create_character_labor_rebuild_binding_read_v1(self)
            return
        if self.binding_task.advance_v1(meter):
            value=require_character_labor_rebuild_binding_read_v1(self.binding_task,self,meter=meter)
            self.complete=True
            self.result=PreparedCharacterLaborRebuildColdV1(_KEY,self,value)

    def release_payload_v3(self):
        if _COLD_OWNERS.pop(self,None)is None:return
        first=None
        if self.result is not None:_COLD_RESULTS.pop(self.result,None)
        if self.binding_task is not None:
            try:self.binding_task.release_v1()
            except BaseException as error:first=error
        self.binding_task=self.grant_column=self.result=None
        self.operation.unregister_retained_state_v3(self)
        if first is not None:raise first


def require_actual_character_labor_rebuild_cold_owner_v1(owner,*,meter=None):
    if type(owner)is not CharacterLaborRebuildColdReadV1:
        raise AuthorityUnavailable("actual named Owner rebuild cold metadata Work required")
    actual=owner.require_v1(meter)
    if not actual.resource_verified:
        raise AuthorityUnavailable("labor binding metadata cannot precede actual current Root grant EOF")
    return actual


class PreparedCharacterLaborRebuildColdV1:
    def __init__(self,key,reader,value):
        if key is not _KEY or not reader.complete:
            raise AuthorityUnavailable("labor cold result requires its actual complete metadata EOF")
        self.reader,self.value=reader,value
        _COLD_RESULTS[self]=(reader,reader.work,reader.operation,reader._identity_v1(),value)

    def require_v1(self,graph,work):
        from .d02_character_labor_rebuild_v1 import require_character_labor_rebuild_binding_read_v1
        r=require_actual_character_labor_rebuild_cold_owner_v1(self.reader)
        if (_COLD_RESULTS.get(self)!=(r,work,r.operation,r._identity_v1(),self.value)
                or r.graph is not graph or r.work is not work or r.result is not self or not r.complete
                or r.db.in_transaction or r.store._lock._is_owned()):
            raise AuthorityUnavailable("labor cold result is not its actual retained terminal Work")
        with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock:
            r.db.execute("BEGIN")
            try:
                with runtime_storage_quantum_v3(r.db)as meter:
                    r.require_v1(meter)
                    value=require_character_labor_rebuild_binding_read_v1(r.binding_task,r,meter=meter)
                    if value is not self.value:raise AuthorityUnavailable("labor cold metadata proof changed")
            finally:r.db.rollback()
        return self.value

    def release_payload_v3(self):
        self.reader.release_payload_v3()


def _begin_cold_v1(graph,authority,lease,command,activity_id,audience_ref,parent_budget_lease_ref):
    from ..host.authority_profile import current_owner_metadata_installation_v3
    from .first_ingress_v2 import trusted_upper
    from .domain_production_registry_v1 import installed_operation_v1
    from ..graph_worker import require_graph_storage_work_admission_v3
    require_graph_storage_work_admission_v3(graph)
    _owner_identity_v1(graph,authority,lease)
    owner=graph._GraphCoordinator__owner_leases[lease]
    if installed_operation_v1("rebuild_character_labor_body").capability not in owner.capabilities:
        raise AuthorityUnavailable("actual Owner labor rebuild capability required")
    store=graph._GraphCoordinator__store
    bundle=current_owner_metadata_installation_v3(graph)[0]
    if authority.namespace!=bundle.installation_policy.namespace or store._db.in_transaction or store._lock._is_owned():
        raise AuthorityUnavailable("labor cold metadata needs the actual installed Owner namespace outside Graph SQL")
    clock=graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    deadline=bundle.installation_policy.root_grant.valid_until_utc
    if trusted_upper(clock)>=deadline:raise AuthorityUnavailable("labor current Root metadata resource deadline expired")
    opid="character-labor-rebuild-cold:"+canonical_digest((authority.namespace,
        command.mutation_operation_id,command.command_input_digest))[:48]
    operation=begin_runtime_storage_operation_v3(store._db,opid,deadline)
    if operation is None:raise AuthorityUnavailable("labor cold metadata requires actual bounded selected storage")
    reader=None
    try:
        with bind_runtime_storage_operation_v3(operation,store._db),store._lock:
            store._db.execute("BEGIN")
            try:stamp=graph._v2_graph_stamp(authority.namespace)
            finally:store._db.rollback()
        reader=CharacterLaborRebuildColdReadV1(graph,authority,lease,bundle,operation,clock,stamp,
            command,activity_id,audience_ref,parent_budget_lease_ref)
        reader.work=create_graph_storage_work_v3(graph,kind=COLD_KIND,operation_id=opid,
            selection_digest=operation.selection_digest,deadline_utc=deadline,state=reader,operation=operation)
        _COLD_OWNERS[reader]=reader._identity_v1()
        operation.register_retained_state_v3(reader)
        return reader.work
    except BaseException as first:
        if reader is not None:
            try:reader.release_payload_v3()
            except BaseException as later:first.add_note("labor cold metadata payload cleanup failed: "+type(later).__name__)
        try:finish_runtime_storage_operation_v3(operation)
        except BaseException as later:first.add_note("labor cold resource release failed: "+type(later).__name__)
        raise


def advance_current_character_labor_rebuild_cold_v1(graph,work):
    r=work.state
    if type(r)is not CharacterLaborRebuildColdReadV1 or r.work is not work or r.graph is not graph:raise AuthorityUnavailable("actual labor cold Work required")
    r.require_v1()
    with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock:
        if r.db.in_transaction:raise AuthorityUnavailable("labor cold Work cannot inherit Graph SQL")
        r.db.execute("BEGIN")
        try:
            with runtime_storage_quantum_v3(r.db)as meter:r.advance_v1(meter)
        finally:r.db.rollback()
    return GraphStorageStepV3("complete",r.result)if r.complete else GraphStorageStepV3("progress")


def finish_current_character_labor_rebuild_cold_v1(graph,work,error):
    r=work.state
    if type(r)is not CharacterLaborRebuildColdReadV1 or r.work is not work or r.graph is not graph:
        raise AuthorityUnavailable("actual labor cold Work finish required")
    if error is None:
        if not r.complete or type(r.result)is not PreparedCharacterLaborRebuildColdV1:
            raise AuthorityUnavailable("labor cold Work cannot publish partial metadata")
        work.result_lease=r.operation
        return
    try:r.release_payload_v3()
    except BaseException as later:error.add_note("labor cold metadata cleanup failed: "+type(later).__name__)
    try:finish_runtime_storage_operation_v3(r.operation)
    except BaseException as later:error.add_note("labor cold resource release failed: "+type(later).__name__)


class _SelectionInvocationV1:
    def __init__(self,graph,authority,lease,work,selector,expected,activity_id,audience_ref,parent,command):
        self.graph,self.authority,self.lease,self.work=graph,authority,lease,work
        self.owner,self.session=_owner_identity_v1(graph,authority,lease)
        self.ticket,self.thread=work.ticket,get_ident()
        self.selector,self.expected,self.command=selector,expected,command
        self.activity_id,self.audience_ref,self.parent_budget_lease_ref=activity_id,audience_ref,parent
        self.inputs=self.token=self.cold_result=self.child=None
        self.first_error=None;self.closed=False
        self.original_deadline=work.deadline_utc
        self.retention=RuntimeStorageOperationV3(_INSTALLED,work.operation.handle,
            work.operation_id+":selector-handoff",work.deadline_utc)
        self.works=set()
        try:self.retention.register_retained_state_v3(self)
        except BaseException as first:
            try:self.retention.release()
            except BaseException as later:first.add_note("selector reservation release failed: "+type(later).__name__)
            raise
        self.register_work_v1(work)
        if command is not None:
            key=(authority.namespace,command.mutation_operation_id)
            if key in _SUBMISSIONS:
                self.close_v1()
                raise AuthorityUnavailable("this actual Owner mutation already has an active selector invocation")
            _SUBMISSIONS[key]=self

    def register_work_v1(self,work):
        _INVOCATIONS[work]=self
        self.works.add(work)

    def _runtime_retained_heap_bytes_v3(self):
        return 16384+_payload_heap_v1((self.inputs,self.command,self.selector))+_heap(self.expected)+_heap(self.token)

    def require_v1(self,graph):
        from ..graph_worker import require_graph_storage_work_admission_v3
        if (self.closed or self.graph is not graph or self.thread!=get_ident()
                or self.retention.closed or require_graph_storage_work_admission_v3(graph)!=self.ticket
                or graph._GraphCoordinator__owner_leases.get(self.lease)is not self.owner
                or graph._GraphCoordinator__owner_session_proofs.get(self.lease)is not self.session
                or runtime_storage_v3(graph._GraphCoordinator__store._db)is not self.retention.handle):
            raise AuthorityUnavailable("labor selector lost its actual Owner/worker/physical selection")
        _owner_identity_v1(graph,self.authority,self.lease)
        return self

    def handoff_v1(self,stage):
        from ..graph_storage_handoff_v3 import issue_graph_storage_handoff_v3
        from .first_ingress_v2 import trusted_upper
        self.token=token_bytes(32);_PENDING[self.token]=(self,self.work,stage)
        self.retention.refresh_retained_state_v3(self)
        now=trusted_upper(self.graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
            self.graph._GraphCoordinator__scene_clock_policy))
        return issue_graph_storage_handoff_v3(self.work,factory=_rebuild_selected_character_labor_v1,
            command=self.token,deadline_utc=self.original_deadline,observed_utc=now)

    def cold_completed_v1(self,result):
        from .d02_character_labor_rebuild_v1 import PreparedCharacterLaborRebuildBindingV1,NoCharacterLaborRebuildBindingV1
        try:
            self.require_v1(self.graph)
            if type(result)is not PreparedCharacterLaborRebuildColdV1:
                raise AuthorityUnavailable("actual private rebuild cold terminal required")
            value=result.require_v1(self.graph,self.work)
            if type(value)is PreparedCharacterLaborRebuildBindingV1:
                if (value.binding.command!=self.command
                        or (value.binding.activity_id,value.binding.audience_ref,value.binding.parent_budget_lease_ref)
                            !=(self.activity_id,self.audience_ref,self.parent_budget_lease_ref)):
                    raise AuthorityUnavailable("same rebuild UUID belongs to another actual command scope or selected identity")
                with bind_runtime_storage_operation_v3(result.reader.operation,result.reader.db):
                    return self.graph._finish_current_character_labor_rebuild_cold_v1(result.reader,value)
            if type(value)is not NoCharacterLaborRebuildBindingV1:
                raise AuthorityUnavailable("unknown rebuild cold metadata outcome")
            value.require_current_v1(result.reader)
            self.cold_result=result
            return self.handoff_v1("select")
        except BaseException as first:
            if self.first_error is None:self.first_error=first
            raise

    def completed_v1(self,proof):
        try:
            self.require_v1(self.graph)
            self.inputs=consume_character_labor_rebuild_selection_v1(proof,graph=self.graph,work=self.work)
            require_detached_character_labor_rebuild_inputs_v1(self.inputs,graph=self.graph)
            self.retention.refresh_retained_state_v3(self)
            view=character_labor_rebuild_selection_view_v1(self.inputs)
            if self.expected is None:
                self.work.operation.retain(_heap(view)+65536)
                return view
            if (view["choice_digest"]!=self.expected
                    or (self.inputs.activity_id,self.inputs.audience_ref,self.inputs.parent_budget_lease_ref)
                        !=(self.activity_id,self.audience_ref,self.parent_budget_lease_ref)):
                raise AuthorityUnavailable("labor rebuild choice or original command identity changed")
            return self.handoff_v1("rebuild")
        except BaseException as first:
            if self.first_error is None:self.first_error=first
            raise

    def failed_v1(self,error):
        if self.first_error is None:self.first_error=error
        raise error

    def close_v1(self):
        if self.closed:return
        self.closed=True
        if self.token is not None:_PENDING.pop(self.token,None)
        for work in self.works:_INVOCATIONS.pop(work,None)
        if self.command is not None:
            key=(self.authority.namespace,self.command.mutation_operation_id)
            if _SUBMISSIONS.get(key)is self:_SUBMISSIONS.pop(key,None)
        first=self.first_error
        try:self.retention.release()
        except BaseException as later:
            if first is None:raise
            first.add_note("labor selector metadata release failed: "+type(later).__name__)
        finally:
            self.graph=self.authority=self.lease=self.work=self.owner=self.session=None
            self.inputs=self.retention=self.token=self.cold_result=self.child=self.command=None
            self.works.clear()


def _new_selector_v1(graph,authority,lease,selector,activity_id,audience_ref,parent,deadline=None):
    runtime=graph._GraphCoordinator__domain_production_runtime_v1
    operation_id="character-labor-selector:"+token_hex(16)
    return graph._prepare_current_method_operation_v3(runtime,authority,lease,
        operation_kind=SELECT_REBUILD_KIND_V1,request=selector,operation_id=operation_id,
        activity_id=activity_id,audience_ref=audience_ref,parent_budget_lease_ref=parent,
        request_digest=canonical_digest((SELECT_REBUILD_KIND_V1,selector,activity_id,audience_ref,parent)),
        read_deadline_utc=deadline)


def _rebuild_selected_character_labor_v1(graph,token):
    from ..graph_worker import _STORAGE_INVOCATION_V3,OwnedGraphStorageResultV3
    invocation,parent,stage=_PENDING.pop(token,(None,None,None))
    if invocation is None or invocation.token is not token:
        raise AuthorityUnavailable("labor rebuild needs its actual once-only selector continuation")
    child=None
    try:
        invocation.require_v1(graph)
        actual=_STORAGE_INVOCATION_V3.get()
        if (actual is None or not actual.initial or actual.mode!="ordinary"
                or actual.coordinator is not graph or actual.ticket!=invocation.ticket or invocation.work is not parent):
            raise AuthorityUnavailable("labor rebuild continuation changed its actual initial worker ticket")
        if stage=="select":
            invocation.cold_result.release_payload_v3()
            finish_runtime_storage_operation_v3(parent.operation)
            if not parent.operation.closed:raise AuthorityUnavailable("cold rebuild result retention has not closed")
            invocation.cold_result=None
            child=_new_selector_v1(graph,invocation.authority,invocation.lease,invocation.selector,
                invocation.activity_id,invocation.audience_ref,invocation.parent_budget_lease_ref,invocation.original_deadline)
            invocation.work=child
            invocation.register_work_v1(child)
            return child.map_terminal_v3("issuer",invocation.completed_v1,invocation.failed_v1)
        if stage!="rebuild":raise AuthorityUnavailable("unknown fixed labor selector continuation")
        inputs=require_detached_character_labor_rebuild_inputs_v1(invocation.inputs,graph=graph)
        store=graph._GraphCoordinator__store
        with bind_runtime_storage_operation_v3(invocation.retention,store._db),store._lock,runtime_storage_quantum_v3(store._db):
            if store._db.in_transaction or graph._v2_graph_stamp(invocation.authority.namespace)!=inputs.graph_stamp:
                raise AuthorityUnavailable("labor selected Graph changed before fresh rebuild READ")
        if inputs.selection_digest!=invocation.retention.handle.selection_digest:
            raise AuthorityUnavailable("labor rebuild changed its actual selected storage")
        q=inputs.request
        graph._authorize(invocation.lease,invocation.authority,frozenset(("d02","d08","d11")),owner_read=True)
        child=graph._GraphCoordinator__domain_production_runtime_v1.run_current(
            invocation.authority,invocation.lease,operation_kind="rebuild_character_labor_body",request=q,
            operation_id=invocation.command.mutation_operation_id,activity_id=inputs.activity_id,audience_ref=inputs.audience_ref,
            parent_budget_lease_ref=inputs.parent_budget_lease_ref,
            _read_deadline_utc=min(inputs.deadline_utc,invocation.original_deadline))
        from .current_beta1_source_read_v3 import beta1_source_work_kind_v3
        if (type(child)is not GraphStorageWorkV3 or child.coordinator is not graph
                or child.kind!=beta1_source_work_kind_v3("rebuild_character_labor_body")
                or child.ticket!=invocation.ticket or child.terminal or child.operation.closed
                or child.deadline_utc>min(inputs.deadline_utc,invocation.original_deadline)
                or child.state.request is not q):
            raise AuthorityUnavailable("rebuild is not its actual fresh same-command Source Work")
        invocation.child=child
        invocation.register_work_v1(child)
        return child
    except BaseException as first:
        if invocation.first_error is None:invocation.first_error=first
        if (type(child)is GraphStorageWorkV3 and child.coordinator is graph and child.ticket==invocation.ticket and not child.terminal):
            try:
                discarded=child._finish_and_map(graph,None,first)
                if type(discarded)is OwnedGraphStorageResultV3:discarded.release_v3()
            except BaseException as later:
                if later is not first:first.add_note("labor selector child cleanup failed: "+type(later).__name__)
        raise


def begin_character_labor_rebuild_selection_v1(graph,authority,lease,*,selector,
        activity_id,audience_ref,parent_budget_lease_ref,expected_choice_digest=None,
        mutation_operation_id=None,command_input_digest=None,command_scope=None):
    if type(selector)is not CharacterLaborRebuildSelectorV1:
        raise TypeError("exact installed labor rebuild selector required")
    command=None
    if expected_choice_digest is None:
        if any(v is not None for v in (mutation_operation_id,command_input_digest,command_scope)):
            raise AuthorityUnavailable("preview READ cannot carry a mutation command identity")
        work=_new_selector_v1(graph,authority,lease,selector,activity_id,audience_ref,parent_budget_lease_ref)
    else:
        if len(authority.audience)!=1 or authority.audience!=(audience_ref,):
            raise AuthorityUnavailable("actual Owner command audience must equal its explicit rebuild audience")
        command=CharacterLaborRebuildCommandContextV1(mutation_operation_id,"domain_rebuild_character_labor_body",
            command_scope,authority.purpose,authority.audience[0],command_input_digest,selector,expected_choice_digest)
        work=_begin_cold_v1(graph,authority,lease,command,activity_id,audience_ref,parent_budget_lease_ref)
    invocation=None
    try:
        invocation=_SelectionInvocationV1(graph,authority,lease,work,selector,expected_choice_digest,
            activity_id,audience_ref,parent_budget_lease_ref,command)
        lifetime=ExitStack();lifetime.callback(invocation.close_v1)
        if work._request_lifetime is None:work.adopt_request_lifetime_v3(lifetime)
        else:work._request_lifetime.callback(lifetime.close)
        return work.map_terminal_v3("issuer",
            invocation.completed_v1 if command is None else invocation.cold_completed_v1,invocation.failed_v1)
    except BaseException as first:
        if invocation is not None:
            try:invocation.close_v1()
            except BaseException as later:first.add_note("selector factory metadata cleanup failed: "+type(later).__name__)
        try:work._finish_and_map(graph,None,first)
        except BaseException as later:
            if later is not first:first.add_note("selector factory Work cleanup failed: "+type(later).__name__)
        raise


def require_character_labor_rebuild_selection_work_v1(work,*,graph,authority,lease,operation_id,
        command_input_digest,selector,expected_choice_digest,activity_id,audience_ref,parent_budget_lease_ref,command_scope=None):
    invocation=_INVOCATIONS.get(work)
    if (type(work)is not GraphStorageWorkV3 or invocation is None or invocation.work is not work
            or work.coordinator is not graph or work.terminal):
        raise AuthorityUnavailable("actual initial labor preview/cold submission Work required")
    invocation.require_v1(graph)
    work._require_invocation(graph,initial=True)
    command=invocation.command
    expected=(None,None,None)if command is None else (
        command.mutation_operation_id,command.command_input_digest,command.scope)
    if ((authority,lease)!=(invocation.authority,invocation.lease)
            or authority is not invocation.authority or lease is not invocation.lease
            or (operation_id,command_input_digest,command_scope)!=expected
            or (selector,expected_choice_digest,activity_id,audience_ref,parent_budget_lease_ref)
                !=(invocation.selector,invocation.expected,invocation.activity_id,invocation.audience_ref,invocation.parent_budget_lease_ref)):
        raise AuthorityUnavailable("labor Work differs from the actual outer command identity and Owner scope")
    return work


def require_character_labor_rebuild_store_receipt_operation_v1(witness):
    """Return this active selector child's actual storage accounting operation."""
    from .domain_production_commit_v1 import _ACTIVE,_ProductionCommitWitnessV1
    from ..runtime_storage_v3 import _operation
    if (type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness
            or witness.operation.operation_kind!="rebuild_character_labor_body"):
        raise AuthorityUnavailable("actual active rebuild W01 receipt-hook witness required")
    graph=witness.graph
    db=graph._GraphCoordinator__store._db
    identity=witness.frame.envelope.identity
    authority=witness.frame.envelope.authority
    invocation=_SUBMISSIONS.get((authority.namespace,identity.operation_id))
    if invocation is None:
        raise AuthorityUnavailable("rebuild receipt hook has no actual UUID-bound selector submission")
    invocation.require_v1(graph)
    inputs=require_detached_character_labor_rebuild_inputs_v1(invocation.inputs,graph=graph)
    child=invocation.child
    handle=runtime_storage_v3(db)
    if (not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or invocation.command is None
            or identity.operation_id!=invocation.command.mutation_operation_id
            or identity.activity_id!=invocation.activity_id
            or authority is not invocation.authority
            or witness.runtime is not graph._GraphCoordinator__domain_production_runtime_v1
            or witness.request is not inputs.request
            or type(child)is not GraphStorageWorkV3 or _INVOCATIONS.get(child)is not invocation
            or child.coordinator is not graph or child.ticket!=invocation.ticket
            or child.state.request is not inputs.request or child.operation.closed
            or child.operation.handle is not handle
            or handle is not invocation.retention.handle
            or child.operation.pool is not invocation.retention.pool
            or child.operation.selection_digest!=inputs.selection_digest):
        raise AuthorityUnavailable("rebuild receipt hook lost its actual fresh Source child/command/storage")
    child._require_invocation(graph)
    operation=_operation(handle)
    if operation is not child.operation:
        raise AuthorityUnavailable("rebuild receipt metadata must charge its actual bound Source operation")
    return operation


def require_current_character_labor_rebuild_binding_context_v1(witness,*,db,receipt):
    from .domain_production_commit_v1 import _ACTIVE,_ProductionCommitWitnessV1
    from ..runtime_contracts import CommitReceipt
    if (type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness
            or type(receipt)is not CommitReceipt or receipt.status!="committed"
            or witness.operation.operation_kind!="rebuild_character_labor_body"):
        raise AuthorityUnavailable("actual active rebuild W01 witness and saved receipt required")
    key=(witness.frame.envelope.authority.namespace,receipt.operation_id)
    invocation=_SUBMISSIONS.get(key)
    if invocation is None:raise AuthorityUnavailable("rebuild has no actual UUID-bound selector submission")
    invocation.require_v1(witness.graph)
    inputs=require_detached_character_labor_rebuild_inputs_v1(invocation.inputs,graph=witness.graph)
    child=invocation.child
    if (db is not witness.graph._GraphCoordinator__store._db or not db.in_transaction
            or not witness.graph._GraphCoordinator__store._lock._is_owned()
            or witness.runtime is not witness.graph._GraphCoordinator__domain_production_runtime_v1
            or witness.frame.envelope.authority is not invocation.authority
            or witness.request is not inputs.request
            or witness.frame.envelope.identity.operation_id!=invocation.command.mutation_operation_id
            or receipt.operation_id!=invocation.command.mutation_operation_id
            or type(child)is not GraphStorageWorkV3 or _INVOCATIONS.get(child)is not invocation
            or child.state.request is not inputs.request or child.operation.closed
            or child.operation.handle is not invocation.retention.handle):
        raise AuthorityUnavailable("rebuild witness lost its actual selected request/fresh child/command lineage")
    operation=require_character_labor_rebuild_store_receipt_operation_v1(witness)
    with bind_runtime_storage_operation_v3(operation,db),runtime_storage_quantum_v3(db)as meter:
        head=meter.read_fixed_row(db,"graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),
            "bot=? AND persona=? AND operation_id=?",(*key[0].as_tuple,receipt.operation_id))
        if head!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
            raise AuthorityUnavailable("rebuild binding witness does not name the actual saved W01 receipt")
    return inputs,invocation.command


def peek_current_character_labor_rebuild_binding_context_v1(witness):
    """Locate this invocation's actual context; this is not a commit proof."""
    from .domain_production_commit_v1 import _ACTIVE,_ProductionCommitWitnessV1
    if type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness:
        raise AuthorityUnavailable("active actual W01 witness required for rebuild context lookup")
    if witness.operation.operation_kind!="rebuild_character_labor_body":return None
    operation_id=witness.frame.envelope.identity.operation_id
    invocation=_SUBMISSIONS.get((witness.frame.envelope.authority.namespace,operation_id))
    if invocation is None:return None
    invocation.require_v1(witness.graph)
    if (invocation.command is None or invocation.command.mutation_operation_id!=operation_id
            or invocation.inputs is None or invocation.child is None):
        raise AuthorityUnavailable("selected rebuild submission lost its actual command or fresh Source child")
    return invocation.command
