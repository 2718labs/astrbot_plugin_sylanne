"""Independent, content-free C04/D13 historical Body accounting inputs."""
from threading import get_ident
from weakref import WeakKeyDictionary
import time

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.internal_accounting_v1 import HistoricalInternalCostRequestV1,HistoricalInternalCostGrantV1
from ..domains.d02 import BodyState,BodyReservation
from ..graph_types import AtomKey,GraphVersion,GraphReceipt
from ..runtime_storage_v3 import (runtime_storage_v3,begin_runtime_storage_operation_v3,
    bind_runtime_storage_operation_v3,runtime_storage_quantum_v3,finish_runtime_storage_operation_v3,_operation)
from ..graph_worker import GraphStorageStepV3,create_graph_storage_work_v3,require_graph_storage_work_admission_v3
from .c04_internal_work_original_v1 import C04InternalWorkPreparedV1
from .c04_body_resource_inputs_v3 import C04ResourceRowsReadV3
from .dispatch_current_inventory_v3 import _heap
from .current_character_labor_adoption_v1 import _payload_heap_v1

KIND="c04_body_accounting_inputs_v3"
_KEY=object()
_READERS=WeakKeyDictionary()
_INPUTS=WeakKeyDictionary()
_STAGES={}


def validate_body_accounting_lineage_v3(rows,*,start_revision,current_revision,kind):
    """Validate already-complete, independently qualified historical resource EOF."""
    if len(rows)!=current_revision-start_revision+1 or any(
            revision!=start_revision+i or valid!=1 or type(value)is not kind
            for i,(_,revision,valid,value)in enumerate(rows)):
        raise ValueError("original Body accounting ancestry is incomplete or invalid")
    values=tuple(value for _,_,_,value in rows)
    if kind is BodyState:
        if len({v.profile_id for v in values})!=1 or any(v.version!=row[1]for v,row in zip(values,rows,strict=True)):
            raise ValueError("historical Body state changed its original profile/revision")
    elif kind is BodyReservation:
        if len({(v.reservation_id,v.quote_id,v.effect_id,v.reserved_cost)for v in values})!=1:
            raise ValueError("historical reservation changed original accounting identity")
    else:raise TypeError("only the actual historical Body state/reservation lineage is admitted")
    return values


class C04BodyAccountingInputsV3:
    def __init__(self,key,reader):
        if key is not _KEY or not reader.complete:raise TypeError("actual complete accounting resource EOF required")
        self.reader=reader
        self.rows=tuple(reader.rows)
        self.lineages=tuple(reader.lineages)
        self.target_erased=reader.target_erased
        self.consumed=False
        _INPUTS[self]=(reader,reader.work,reader.operation,self.rows,self.lineages,self.target_erased)

    def require_v3(self,db,*,namespace,evidence,prepared):
        r=self.reader
        if (_INPUTS.get(self)!=(r,r.work,r.operation,self.rows,self.lineages,self.target_erased)
                or self.consumed or db is not r.db or not db.in_transaction
                or namespace!=r.namespace or evidence is not r.grant.evidence
                or prepared!=r.prepared or _operation(runtime_storage_v3(db))is not r.operation):
            raise AuthorityUnavailable("historical Body inputs are not this actual accounting grant/transaction")
        with runtime_storage_quantum_v3(db)as meter:r.require_current_v3(meter)
        return self

    def consume_v3(self):
        if self.consumed:raise AuthorityUnavailable("historical Body packet was already consumed")
        self.consumed=True
        return self

    def current_rows_v3(self):
        if self.target_erased:return None,None
        return self.rows[0],self.rows[1]

    def require_lineages_v3(self):
        r=self.reader
        for i,kind in enumerate((BodyState,BodyReservation)):
            validate_body_accounting_lineage_v3(self.lineages[i],start_revision=r.starts[i],
                current_revision=r.headers[r.tokens[i]][0],kind=kind)
        return self

    def release_payload_v3(self):self.reader.release_payload_v3()


class CurrentC04BodyAccountingReadV3:
    def __init__(self,graph,request,grant,prepared,operation,bundle,stamp,now):
        self.graph,self.request,self.grant,self.prepared=graph,request,grant,prepared
        self.store=graph._GraphCoordinator__store
        self.db,self.operation,self.bundle=self.store._db,operation,bundle
        self.namespace=bundle.installation_policy.namespace
        self.graph_stamp,self.selection_digest=stamp,operation.selection_digest
        self.port=graph._GraphCoordinator__c04_authority_port_v3
        self.thread,self.work=get_ident(),None
        self.resource_tokens={prepared.body_state_ref,prepared.binding.body_reservation_ref}
        self.allow_reservation_census=False
        self.tokens=(prepared.body_state_ref,prepared.binding.body_reservation_ref)
        self.starts=(prepared.body_state_revision,prepared.body_reservation_revision)
        self.rows=[];self.lineages=[]
        self.current=None;self.index=0;self.phase="root"
        self.root_header=self.root_column=None
        self.monotonic_deadline=time.monotonic()+operation.deadline_utc-now
        self.headers={}
        self.complete=False;self.target_erased=False;self.result=None

    def identity_v3(self):
        return(self.graph,self.request,self.grant,self.prepared,self.operation,self.bundle,self.work,
            self.namespace,self.selection_digest,self.graph_stamp,self.port,self.thread)

    def require_current_v3(self,meter=None):
        if (_READERS.get(self)!=self.identity_v3()or self.thread!=get_ident()or self.operation.closed
                or self.work.state is not self or self.work.operation is not self.operation
                or time.monotonic()>=self.monotonic_deadline
                or self.graph._GraphCoordinator__c04_authority_port_v3 is not self.port
                or runtime_storage_v3(self.db)is not self.operation.handle):
            raise AuthorityUnavailable("historical Body reader lost its actual accounting/selected Work")
        self.work._require_invocation(self.graph)
        if meter is not None:
            self.operation.handle.require_current(meter)
            if self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp:
                raise AuthorityUnavailable("historical Body accounting Graph changed during complete EOF")
            if self.root_header is not None:
                root=self.bundle.installation_policy.root_grant
                if meter.read_fixed_row(self.db,"runtime_budget_grants",("version","status","signature"),
                        "lease_id=? ORDER BY version DESC",(root.lease_id,))!=self.root_header:
                    raise AuthorityUnavailable("historical accounting current Root resource changed")
            for token,head in self.headers.items():
                if meter.read_fixed_row(self.db,"graph_atoms",("revision","valid","value_cell_id"),
                        "token=? AND bot=? AND persona=?",(token,*self.namespace.as_tuple))!=head:
                    raise AuthorityUnavailable("historical accounting resource head changed")
        return self

    def require_v1(self,meter=None):return self.require_current_v3(meter)

    def require_resource_reader_v3(self):
        self.require_current_v3()
        if self.phase not in {"heads","lineage"}:raise AuthorityUnavailable("historical Body reader is outside its finite phase")

    def _runtime_retained_heap_bytes_v3(self):
        return 65536+_payload_heap_v1((self.request,self.grant,self.prepared))+_heap((self.rows,self.lineages,self.headers,
            None if self.current is None else(self.current.values,self.current.reader.values),
            None if self.root_column is None else(self.root_column.body,self.root_column.fragment,self.root_column.value)))

    def advance_v3(self,meter):
        self.require_current_v3(meter)
        if self.phase=="root":
            root=self.bundle.installation_policy.root_grant
            head=meter.read_fixed_row(self.db,"runtime_budget_grants",("version","status","signature"),
                "lease_id=? ORDER BY version DESC",(root.lease_id,))
            if head is None or head[:2]!=(root.version,"active"):
                raise AuthorityUnavailable("historical accounting requires the actual current Root resource grant")
            self.root_header=head
            if self.root_column is None:
                from .current_character_labor_adoption_v1 import _LocatorMetadataColumnV1
                self.root_column=_LocatorMetadataColumnV1(self,"runtime_budget_grants","grant_json",
                    ("lease_id","version"),(root.lease_id,root.version),
                    signature_kind="budget-grant.v1",signature=head[2]);return
            if not self.root_column.advance(meter):return
            from .issuers import _decode_grant
            if _decode_grant(self.root_column.body.decode("utf-8"))!=root:
                raise AuthorityUnavailable("historical accounting Root original differs from protected installation")
            self.phase="heads";return
        token=self.tokens[self.index]
        if token not in self.headers:
            self.headers[token]=meter.read_fixed_row(self.db,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(token,*self.namespace.as_tuple))
            if self.headers[token]is None or self.headers[token][1]!=1:self.target_erased=True
            return
        if self.phase=="heads"and(self.headers[token]is None or self.headers[token][1]!=1):
            self.rows.append(None);self.index+=1
        else:
            if self.current is None:
                self.current=C04ResourceRowsReadV3(self,token=token,history=self.phase=="lineage",
                    after_revision=self.starts[self.index],before_revision=self.headers[token][0])
                return
            if not self.current.advance_v3():return
            rows=tuple(self.current.values)
            if self.phase=="heads":
                if len(rows)!=1 or rows[0][1:3]!=self.headers[token][:2]:
                    raise AuthorityUnavailable("historical accounting endpoint lacks its actual complete Body cell")
                self.rows.append(rows[0])
            else:
                self.lineages.append(rows)
            self.current=None;self.index+=1
        if self.index<2:return
        if self.phase=="heads"and not self.target_erased:
            self.phase="lineage";self.index=0;return
        self.complete=True;self.phase="complete"
        self.result=C04BodyAccountingInputsV3(_KEY,self)

    def release_payload_v3(self):
        if _READERS.pop(self,None)is None:return
        if self.result is not None:_INPUTS.pop(self.result,None)
        for key,value in tuple(_STAGES.items()):
            if value[1]is self.result:_STAGES.pop(key,None)
        self.rows.clear();self.lineages.clear();self.headers.clear()
        self.current=self.result=self.root_column=None
        self.operation.unregister_retained_state_v3(self)


def begin_c04_body_accounting_inputs_v3(graph,bootstrap,*,request,grant,prepared):
    from ..host.authority_profile import current_owner_metadata_installation_v3
    from .first_ingress_v2 import trusted_upper
    require_graph_storage_work_admission_v3(graph)
    graph._admin(bootstrap)
    port=graph._GraphCoordinator__c04_authority_port_v3
    bundle=current_owner_metadata_installation_v3(graph)[0]
    if (type(request)is not HistoricalInternalCostRequestV1 or type(grant)is not HistoricalInternalCostGrantV1
            or type(prepared)is not C04InternalWorkPreparedV1 or request.binding!=prepared.binding
            or grant.evidence.binding!=prepared.binding or grant.permit.operation_id!=request.operation_id
            or request.expected_anchor!=grant.permit.pinned_anchor
            or grant.evidence.installation_id!=bundle.installation_policy.installation_id
            or grant.permit.namespace!=bundle.installation_policy.authority_namespace or port is None):
        raise AuthorityUnavailable("historical Body resource issuer needs its actual installed accounting grant")
    store=graph._GraphCoordinator__store
    if store._db.in_transaction or store._lock._is_owned():raise AuthorityUnavailable("accounting validation must precede Graph SQL")
    port.internal_accounting(request,"validate",grant)
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    deadline=bundle.installation_policy.root_grant.valid_until_utc
    if now>=deadline:raise AuthorityUnavailable("current Root accounting metadata resource deadline expired")
    operation=begin_runtime_storage_operation_v3(store._db,"c04-body-accounting:"+request.operation_id,deadline)
    r=None
    try:
        with bind_runtime_storage_operation_v3(operation,store._db),store._lock,runtime_storage_quantum_v3(store._db):
            stamp=graph._v2_graph_stamp(bundle.installation_policy.namespace)
        r=CurrentC04BodyAccountingReadV3(graph,request,grant,prepared,operation,bundle,stamp,now)
        r.work=create_graph_storage_work_v3(graph,kind=KIND,operation_id=operation.operation_id,
            selection_digest=operation.selection_digest,deadline_utc=deadline,state=r,operation=operation)
        _READERS[r]=r.identity_v3();operation.register_retained_state_v3(r)
        return r.work
    except BaseException as first:
        if r is not None:r.release_payload_v3()
        try:finish_runtime_storage_operation_v3(operation)
        except BaseException as later:first.add_note("accounting Body resource cleanup failed: "+type(later).__name__)
        raise


def advance_c04_body_accounting_inputs_v3(graph,work):
    r=work.state
    if type(r)is not CurrentC04BodyAccountingReadV3 or r.graph is not graph or r.work is not work:
        raise AuthorityUnavailable("actual historical Body accounting Work required")
    r.require_current_v3()
    r.port.internal_accounting(r.request,"validate",r.grant)
    with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock:
        r.db.execute("BEGIN")
        try:
            with runtime_storage_quantum_v3(r.db)as meter:r.advance_v3(meter)
        finally:r.db.rollback()
    return GraphStorageStepV3("complete",r.result)if r.complete else GraphStorageStepV3("progress")


def finish_c04_body_accounting_inputs_v3(graph,work,error):
    r=work.state
    if type(r)is not CurrentC04BodyAccountingReadV3 or r.graph is not graph or r.work is not work:
        raise AuthorityUnavailable("actual historical Body accounting Work finish required")
    try:
        if error is None:
            r.port.internal_accounting(r.request,"validate",r.grant)
            work.result_lease=work.operation
    except BaseException as first:
        try:r.release_payload_v3()
        except BaseException as later:first.add_note("historical Body payload cleanup failed: "+type(later).__name__)
        try:finish_runtime_storage_operation_v3(work.operation)
        except BaseException as later:first.add_note("historical Body retention cleanup failed: "+type(later).__name__)
        raise
    if error is not None:
        try:r.release_payload_v3()
        except BaseException as later:error.add_note("historical Body payload cleanup failed: "+type(later).__name__)
        try:finish_runtime_storage_operation_v3(work.operation)
        except BaseException as later:error.add_note("historical Body retention cleanup failed: "+type(later).__name__)


def register_c04_body_accounting_stage_v3(packet,stage):
    if type(packet)is not C04BodyAccountingInputsV3 or packet not in _INPUTS or not packet.consumed:
        raise AuthorityUnavailable("actual consumed accounting Body packet required")
    _STAGES[id(stage)]=(stage,packet)
    return stage


def require_c04_body_accounting_after_cas_v3(db,stage,receipt):
    record=_STAGES.get(id(stage))
    if record is None or record[0]is not stage or type(receipt)is not GraphReceipt or receipt.status!="committed":
        raise AuthorityUnavailable("actual registered accounting stage and real committed Graph receipt required")
    packet=record[1];r=packet.reader
    if db is not r.db or not db.in_transaction or r.operation.closed:
        raise AuthorityUnavailable("accounting Body recorder crossed its actual CAS transaction")
    expected={v.key:v.revision for v in stage.reads}
    written={v.key:v.revision for v in receipt.revisions}
    with runtime_storage_quantum_v3(db)as meter:
        for write in stage.writes:
            if write.key not in expected or written.get(write.key)!=expected[write.key]+1:
                raise AuthorityUnavailable("accounting receipt does not contain the actual staged write")
            head=meter.read_fixed_row(db,"graph_atoms",("revision","valid"),"token=? AND bot=? AND persona=?",
                (write.key.token,*r.namespace.as_tuple))
            if head!=(written[write.key],1):raise AuthorityUnavailable("accounting CAS staged member is not its real current header")
    _STAGES.pop(id(stage))
    return packet
