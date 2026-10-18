"""Actual Owner StopReply metadata calls; no model, Source-body or execution capability."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from threading import get_ident
from weakref import WeakSet
import sqlite3

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest
from ..runtime_storage_v3 import (
    bind_runtime_database_from_control_v3, runtime_storage_v3,
    begin_runtime_storage_operation_v3, bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3)

_ISSUER=object()
_INVOCATIONS=WeakSet()
_READERS=WeakSet()
_BOUND=ContextVar("owner-stop-reply-metadata.v1",default=None)


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class OwnerStopReplyMetadataInvocationV1:
    service: object
    credential: object
    subject: str
    actor: str
    session_token: str | None
    session_request: object
    mode: str
    request: object
    cursor: str | None
    source_row: tuple | None
    original_permit: object
    current_owner_guard: object
    current_owner_head: object
    current_anchor: object
    active_originals_commitment: str
    registered_deadline_utc: float | None
    registered_deadline_text: str | None
    storage_context: object
    selected_graph_member: object
    storage: dict
    actual_db: object
    retained_operation: object
    selection_digest: str
    holder: str
    thread_id: int
    _issuer: object

    def __post_init__(self):
        if self._issuer is not _ISSUER:
            raise AuthorityUnavailable("actual StopReply metadata call issuer required")
        _INVOCATIONS.add(self)
        self.retained_operation.register_retained_state_v3(self)

    @property
    def namespace(self):return self.service.namespace_id
    @property
    def authority_namespace(self):return self.service.namespace
    @property
    def installation_id(self):return self.service.installation_id
    @property
    def owner_service(self):return self.service
    @property
    def status_service(self):return self.service.status_service
    @property
    def core(self):return self.service.core
    @property
    def fences(self):return self.service.fences
    @property
    def control(self):return self.service.control
    @property
    def issuer(self):return self.service.issuer
    @property
    def bundle(self):return self.service.bundle
    @property
    def principal(self):return self.session_request.principal

    def _runtime_retained_heap_bytes_v3(self):
        from ..runtime.artifact_no_dispatch_metadata_invocation_v1 import _actual_metadata_heap_v1
        return _actual_metadata_heap_v1((self.actor,self.session_token,self.session_request,
            self.mode,self.request,self.cursor,self.source_row,self.current_owner_guard,
            self.current_owner_head,self.current_anchor,self.storage),set())

    def require_current_v1(self,*,phase,graph_stamp=None):
        if (self not in _INVOCATIONS or self._issuer is not _ISSUER or get_ident()!=self.thread_id
                or phase not in {"before","after"} or self.retained_operation.closed
                or runtime_storage_v3(self.actual_db).selection_digest!=self.selection_digest
                or self.retained_operation.deadline_utc!=self.registered_deadline_utc):
            raise AuthorityUnavailable("StopReply metadata lost its actual caller/selected operation")
        if self.actual_db.in_transaction:
            if graph_stamp is not None:
                from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
                from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
                meter=current_c09_sql_meter_v2()
                revision=_runtime_bounded_fixed_row_v3(self.actual_db,meter,"graph_recovery_metadata_v2",
                    ("graph_revision",),"bot=? AND persona=?",self.namespace.as_tuple)
                epoch=_runtime_bounded_fixed_row_v3(self.actual_db,meter,"graph_epochs",
                    ("revision",),"bot=? AND persona=?",self.namespace.as_tuple)
                if (revision,epoch)!=((graph_stamp[0].graph_revision,),(graph_stamp[1].revision,)):
                    raise AuthorityUnavailable("StopReply metadata Graph stamp changed")
            return self
        self.storage_context.require_current("business")
        self.core._require(self.credential,"d12_operation_status",self.authority_namespace)
        if self.original_permit is not None:
            self.fences.validate_fence(credential=self.credential,subject=self.subject,permit=self.original_permit)
        with self.fences._frozen() as (db,deletion,execution,_):
            anchor=self.fences._current_locked(db,deletion,execution,holder=self.holder,
                require_clear=False,require_no_pending=False)
            self.require_core_v1(db,anchor=anchor)
        return self

    def require_core_v1(self,db,*,anchor):
        if (self not in _INVOCATIONS or self._issuer is not _ISSUER or get_ident()!=self.thread_id
                or self.retained_operation.closed or db is not self.core._db or not db.in_transaction):
            raise AuthorityUnavailable("StopReply metadata seal needs its actual same-Core consumer")
        if self.mode in {"projection","cause_read"}:
            session,guard=self.service._projection_owner_in_tx_v1(db,self.source_row)
            if session!=self.session_request:
                raise AuthorityUnavailable("StopReply projection initiating Owner changed")
        else:
            guard=self.service._auth(db,actor=self.actor,session_token=self.session_token,
                session_request=self.session_request)
            from .v2_owner_session import _verifier
            expiry=db.execute("SELECT expires_at_utc FROM authority_owner_sessions_v1 WHERE verifier=?",
                (_verifier(self.session_token),)).fetchone()
            if (expiry!=(self.registered_deadline_text,)
                    or self.status_service.sessions._now().timestamp()>=self.registered_deadline_utc):
                raise AuthorityUnavailable("StopReply original current session deadline expired/changed")
        if self.source_row is not None:
            actual=db.execute("SELECT * FROM authority_d12_operation_originals_v1 "
                "WHERE authority_namespace=? AND operation_id=? AND original_ref=?",self.source_row[:3]).fetchone()
            if actual!=self.source_row:
                raise AuthorityUnavailable("StopReply original metadata cause changed in its actual Core")
        head=self.status_service.tickets.current_migration_head_in_tx(db,authority_namespace=self.authority_namespace)
        if (guard!=self.current_owner_guard or head!=self.current_owner_head or anchor!=self.current_anchor
                or _active_originals_v1(self.service,db)!=self.active_originals_commitment):
            raise AuthorityUnavailable("StopReply sealed Owner/anchor/active originals changed")
        self.service._require_projection_pointer_in_tx_v1(db,self.storage_context)
        return self

    def close_v1(self):
        self.retained_operation.unregister_retained_state_v3(self)
        _INVOCATIONS.discard(self)
        finish_runtime_storage_operation_v3(self.retained_operation)
        self.actual_db.close()


def _active_originals_v1(service,db):
    rows=tuple(db.execute("SELECT operation_id,namespace,subject,token,fence_epoch,revision,state,"
        "finish_request_id,finish_request_digest,pending IS NOT NULL FROM authority_v2_fences "
        "WHERE namespace=? AND state='active' ORDER BY operation_id",(service.namespace,)))
    if len(rows)>1:
        raise AuthorityUnavailable("StopReply active fence set violates its actual unique-index contract")
    return canonical_digest(rows)


def require_owner_stop_reply_metadata_invocation_v1(invocation,*,phase,graph_stamp=None):
    if type(invocation)is not OwnerStopReplyMetadataInvocationV1:
        raise AuthorityUnavailable("actual private StopReply metadata invocation required")
    return invocation.require_current_v1(phase=phase,graph_stamp=graph_stamp)


def begin_owner_stop_reply_metadata_invocation_v1(service,*,credential,subject,actor=None,
        session_token=None,session_request=None,mode,request=None,cursor=None,source_row=None,permit=None):
    from .owner_stop_reply_v1 import InstalledOwnerStopReplyServiceV1,OwnerStopReplyRequestV1
    from .mtls_server import MtlsPeerCredential
    from .v2_contract import FencePermitV2
    from .v2_owner_session import _verifier
    from ..runtime.d11_offline_originals_v1 import _utc
    if (type(service)is not InstalledOwnerStopReplyServiceV1
            or type(credential)is not MtlsPeerCredential
            or subject!="mtls:sha256:"+credential.certificate_sha256
            or mode not in {"submit","list","list_target","status","projection","cause_read"}):
        raise AuthorityUnavailable("actual installed StopReply caller kind/peer required")
    service.core._require(credential,"d12_operation_status",service.namespace)
    if mode=="list":
        if request is not None or source_row is not None or permit is not None:
            raise AuthorityUnavailable("StopReply list has only its actual cursor")
    elif type(request)is not OwnerStopReplyRequestV1 or (
            request.namespace,request.installation_id)!=(service.namespace_id,service.installation_id):
        raise AuthorityUnavailable("StopReply metadata request crossed actual installation")
    with service.fences._frozen()as(db,deletion,execution,_):
        if mode in {"projection","cause_read"}:
            if source_row is None:
                raise AuthorityUnavailable("StopReply cause metadata needs its accepted original")
            if mode=="projection" and (type(permit)is not FencePermitV2 or permit.operation!="write"
                    or permit.operation_id!="owner-stop-projection:"+request.operation_id):
                raise AuthorityUnavailable("StopReply projection needs its actual WRITE")
            if mode=="cause_read" and permit is not None:
                raise AuthorityUnavailable("passive StopReply cause metadata cannot claim a WRITE")
            session_request,guard=service._projection_owner_in_tx_v1(db,source_row)
            actor=source_row[4]
            deadline_text=None;deadline=None
        else:
            if permit is not None:
                raise AuthorityUnavailable("session StopReply metadata cannot borrow a WRITE")
            guard=service._auth(db,actor=actor,session_token=session_token,session_request=session_request)
            expiry=db.execute("SELECT expires_at_utc FROM authority_owner_sessions_v1 WHERE verifier=?",
                (_verifier(session_token),)).fetchone()
            if expiry is None:raise AuthorityUnavailable("actual StopReply session expiry is absent")
            deadline_text=expiry[0];deadline=_utc(deadline_text).timestamp()
        head=service.status_service.tickets.current_migration_head_in_tx(db,authority_namespace=service.namespace)
        if head is None or head.state!="active" or head.guard!=guard:
            raise AuthorityUnavailable("actual current StopReply Owner head is absent")
        holder=service.core._row(db,service.namespace)[0]
        anchor=service.fences._current_locked(db,deletion,execution,holder=holder,
            require_clear=False,require_no_pending=False)
        active=_active_originals_v1(service,db)
    if permit is not None:
        service.fences._require_permit(credential=credential,subject=subject,permit=permit)
        service.fences.validate_fence(credential=credential,subject=subject,permit=permit)
        if permit.pinned_anchor!=anchor:
            raise AuthorityUnavailable("StopReply metadata WRITE changed its original anchor")
    context,storage,member=service._storage()
    db=sqlite3.connect(Path(storage["graph_path"]).as_uri()+"?mode=ro",uri=True,isolation_level=None)
    operation=None
    invocation=None
    try:
        db.execute("PRAGMA query_only=ON")
        handle=bind_runtime_database_from_control_v3(db,control=service.control,role="graph")
        if handle is None:
            raise AuthorityUnavailable("StopReply metadata requires actual installed selected storage")
        from uuid import uuid4
        operation=begin_runtime_storage_operation_v3(db,"owner-stop-metadata:"+str(uuid4()),deadline)
        invocation=OwnerStopReplyMetadataInvocationV1(service,credential,subject,actor,session_token,
            session_request,mode,request,cursor,None if source_row is None else tuple(source_row),permit,
            guard,head,anchor,active,deadline,deadline_text,context,member,storage,db,operation,
            handle.selection_digest,holder,get_ident(),_ISSUER)
        invocation.require_current_v1(phase="before")
        return invocation
    except BaseException:
        if invocation is not None:
            invocation.close_v1()
        else:
            if operation is not None:finish_runtime_storage_operation_v3(operation)
            db.close()
        raise

class OwnerStopReplyMetadataReadV1:
    """A distinct Owner control Work over the shared fixed-point/canonical EOF machinery."""
    kind="owner_stop_reply_metadata"
    legacy=False

    def __init__(self,invocation,*,owner_proof,owner_work,owner_facts):
        self.invocation=invocation
        self.proof,self.owner_work,self.facts=owner_proof,owner_work,owner_facts
        self.db,self.operation=invocation.actual_db,invocation.retained_operation
        self.namespace=invocation.namespace
        self.issuer=invocation.issuer
        self.closed=False
        self.points={};self.scans={};self.columns=set();self.column_kinds={}
        self.inner_readers={};self.inner_headers={}
        self.reserved=0;self.outputs=[]
        self.thread=get_ident()
        _READERS.add(self)

    def require_actual_v3(self):
        if (self not in _READERS or self.closed or self.thread!=get_ident()
                or self.invocation not in _INVOCATIONS or self.operation.closed
                or runtime_storage_v3(self.db).selection_digest!=self.invocation.selection_digest):
            raise AuthorityUnavailable("actual StopReply Owner metadata Work ended/changed")
        return self

    def require_data_current_v3(self,meter):
        self.require_actual_v3()
        self.facts.require_for_v3(self.proof)
        self.invocation.require_current_v1(phase="before",
            graph_stamp=(self.facts.metadata,self.facts.graph_epoch))
        runtime_storage_v3(self.db).require_current(meter)
        return self

    def reserve_heap_v3(self,*,extra=0):
        from ..runtime.source_correction_read_v3 import _heap
        amount=_heap((tuple((c.nodes,c.scalar,c.text_parts,c.text_chars,c.frozen,c.fragment)for c in self.columns),
            tuple((t.metadata,t.small,t.row)for t in self.points.values()),
            tuple((t.rows,t.after,t.candidate)for t in self.scans.values()),
            self.column_kinds,self.inner_headers,self.outputs,
            tuple((r.nodes,r.value,r.scalar,r.chars,r.buffer)for r in self.inner_readers.values())))+extra+65536
        if amount>self.reserved:
            self.operation.retain(amount-self.reserved);self.reserved=amount

    def signer_v3(self,table):
        return self.issuer.resource_issuer._signer if table=="runtime_resource_quotes"else self.issuer._signer

    @staticmethod
    def life_binding_column_v3(column):
        return (column.table=="graph_d11_life_originals_v1"and column.column=="payload_json"
            and dict(zip(column.key_columns,column.key)).get("kind")=="prepared")

    @staticmethod
    def d07_parentage_column_v3(column):
        return (column.table=="graph_d07_execution_originals_v1"and column.column=="payload_json"
            and dict(zip(column.key_columns,column.key)).get("kind")=="prepared")

    @staticmethod
    def appraisal_parentage_column_v3(column):
        return (column.table=="graph_d04_originals_v3"and column.column=="payload_json"
            and dict(zip(column.key_columns,column.key)).get("kind")=="appraisal")

    def metadata_only_column_v3(self,column):
        from ..graph_types import AtomKey
        return (self.life_binding_column_v3(column)or self.d07_parentage_column_v3(column)
            or self.appraisal_parentage_column_v3(column)
            or column.table=="graph_history"and column.column=="value"
                and AtomKey.from_token(column.key[0]).type_name
                    in {"d09.natural_verified_segment_batch.v2","d09.natural_verified_segment_batch.v3"})

    def retain_column_path_v3(self,column,path):
        if self.d07_parentage_column_v3(column):
            return not path or path[0]not in {"frozen_json","clock_mapping_json"}
        if self.appraisal_parentage_column_v3(column):
            return not path or path[0]in {"schema","namespace","operation_id","job_id","call_id","model_request_digest"}
        if self.life_binding_column_v3(column):
            prefixes=(("binding",),("prepare_operation_id",),("plan","activity_id"),("plan","effect_id"),("plan","operation_id"))
            return not path or any(path[:len(p)]==p or p[:len(path)]==path for p in prefixes)
        if self.metadata_only_column_v3(column):
            prefixes=(("schema",),("activity_id",),("operation_id",),("effect_id",),("batch_id",),
                ("paid_review","generation_original_operation_id"),("paid_review","review_original_operation_id"),
                ("paid_review","generation_call_id"),("paid_review","review_call_id"))
            return not path or any(path[:len(p)]==p or p[:len(path)]==path for p in prefixes)
        return True

    def observe_column_fragment_v3(self,column,fragment,meter):
        return None

    def observe_column_finish_v3(self,column):
        return None

    def observe_column_event_v3(self,column,event):
        if self.appraisal_parentage_column_v3(column)and event.path==("frozen_json",):
            if event.kind=="scalar_start"and event.scalar_kind=="string":
                from .model_reply_parentage_v3 import _HeaderStreamV3
                self.inner_readers[column]=_HeaderStreamV3()
            elif event.kind=="scalar_end"and event.scalar_kind=="string":
                self.inner_headers[column]=self.inner_readers.pop(column).finish_header()
        if len(event.path)==1:
            kinds=self.column_kinds.setdefault(column,{})
            if event.kind=="key":kinds[event.path[0]]=None
            elif event.kind=="scalar_start":kinds[event.path[0]]=event.scalar_kind
            elif event.kind in {"object_start","array_start"}:kinds[event.path[0]]=event.kind

    def observe_column_codepoint_v3(self,column,path,codepoint):
        if self.appraisal_parentage_column_v3(column)and path==("frozen_json",):
            self.inner_readers[column].codepoint(codepoint)

    def require_request_v3(self,request):
        from .model_reply_scope_observation_v3 import _POINT_KEYS,_POINT_COLUMNS
        from ..graph_types import AtomKey,OWNER_GRANT_TYPE
        from ..runtime_contracts import NamespaceId
        table,columns,key_columns,key=request
        if table not in _POINT_KEYS or not columns or len(key_columns)!=len(key):
            raise AuthorityUnavailable("unregistered StopReply metadata point")
        values=dict(zip(key_columns,key))
        if not set(_POINT_KEYS[table])<=set(values):
            raise AuthorityUnavailable("StopReply metadata point requires its complete immutable PK")
        if any(name in values and values[name]!=value for name,value in (
                ("bot",self.namespace.bot_id),("persona",self.namespace.persona_id),
                ("bot_id",self.namespace.bot_id),("persona_id",self.namespace.persona_id))):
            raise AuthorityUnavailable("StopReply metadata crossed its actual namespace")
        if table in {"graph_atoms","graph_history"}:
            atom=AtomKey.from_token(values["token"])
            if (self.namespace!=NamespaceId.from_key(atom)
                    or atom.type_name not in {OWNER_GRANT_TYPE,"runtime.job","runtime.cost_settlement",
                        "d09.verified_segment_batch.v1","d09.natural_verified_segment_batch.v2","d09.natural_verified_segment_batch.v3"}):
                raise AuthorityUnavailable("StopReply metadata cannot read arbitrary Graph or Source bodies")
            allowed={"revision","value","valid","event_id","event_bot","event_persona","event_session","token"}
        else:
            allowed=set(_POINT_COLUMNS.get(table,()))
            if table=="graph_events":allowed.add("reads")
        if not set(columns)<=allowed:
            raise AuthorityUnavailable("unregistered StopReply metadata columns")
        return request

    def evaluate_v1(self,callback):
        from .model_reply_scope_observation_v3 import ModelReplyScopeObservationNeededV3,_ReplyScopeMetadataScanV3
        from .owner_location_read_v3 import owner_location_read_quantum_v3
        from ..runtime.domain_background_read_v3 import _BackgroundPointReadV3
        pending=None
        while True:
            self.invocation.require_current_v1(phase="before")
            with owner_location_read_quantum_v3(self.proof)as meter:
                with bind_runtime_storage_operation_v3(self.operation,self.db):
                    self.db.execute("BEGIN")
                    token=_BOUND.set(self)
                    try:
                        self.require_data_current_v3(meter)
                        if pending is None:
                            try:result=callback(self.db)
                            except ModelReplyScopeObservationNeededV3 as needed:pending=needed.request
                            else:
                                self.outputs.append(result);self.reserve_heap_v3()
                                self.require_data_current_v3(meter)
                                return result
                        if pending is not None:
                            tasks=self.scans if pending[0]=="scan"else self.points
                            task=tasks.get(pending)
                            if task is None:
                                if pending[0]=="scan":
                                    task=_ReplyScopeMetadataScanV3(self,pending[1],pending[2])
                                else:
                                    self.require_request_v3(pending);task=_BackgroundPointReadV3(self,pending)
                                tasks[pending]=task
                            task.advance(meter);self.reserve_heap_v3()
                            if task.complete:pending=None
                    finally:
                        _BOUND.reset(token);self.db.rollback()
            self.invocation.require_current_v1(phase="after")

    def close_v1(self):
        from ..runtime.domain_background_read_v3 import _COLUMNS
        for column in self.columns:
            _COLUMNS.pop(column,None)
        self.columns.clear();self.points.clear();self.scans.clear()
        self.column_kinds.clear();self.inner_readers.clear();self.inner_headers.clear();self.outputs.clear()
        _READERS.discard(self);self.closed=True


def active_owner_stop_reply_metadata_read_v1(db=None):
    reader=_BOUND.get()
    if reader is None or db is not None and reader.db is not db:return None
    return reader.require_actual_v3()


def require_owner_stop_reply_metadata_column_owner_v1(reader,*,db):
    if type(reader)not in (OwnerStopReplyMetadataReadV1,HostOwnerStopReplyMetadataReadV1)or reader.db is not db:
        raise AuthorityUnavailable("actual originating StopReply metadata column required")
    return reader.require_actual_v3()


def read_bound_owner_stop_reply_metadata_point_v1(db,*,table,columns,key_columns,key):
    reader=active_owner_stop_reply_metadata_read_v1(db)
    if reader is None:return False,None
    from .model_reply_scope_observation_v3 import ModelReplyScopeObservationNeededV3
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    request=(table,tuple(columns),tuple(key_columns),tuple(key))
    reader.require_request_v3(request)
    task=reader.points.get(request)
    if task is None or not task.complete:raise ModelReplyScopeObservationNeededV3(request)
    meter=current_c09_sql_meter_v2()
    reader.require_data_current_v3(meter)
    return True,task.require_row_v3(meter)


def read_bound_owner_stop_reply_metadata_rows_v1(db,*,kind,parameters):
    reader=active_owner_stop_reply_metadata_read_v1(db)
    if reader is None:return False,None
    from .model_reply_scope_observation_v3 import ModelReplyScopeObservationNeededV3,_REPLY_METADATA_SCAN_KINDS_V3
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    if kind not in _REPLY_METADATA_SCAN_KINDS_V3:
        raise AuthorityUnavailable("unregistered StopReply metadata cursor")
    request=("scan",kind,tuple(parameters))
    task=reader.scans.get(request)
    if task is None or not task.complete:raise ModelReplyScopeObservationNeededV3(request)
    return True,task.require_rows_v3(current_c09_sql_meter_v2())

_SEALS=WeakSet()
_SERVICE_SEAL=ContextVar("owner-stop-reply-service-metadata.v1",default=None)


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class PreparedOwnerStopReplyMetadataV1:
    invocation:OwnerStopReplyMetadataInvocationV1
    reader:OwnerStopReplyMetadataReadV1
    result:object
    _issuer:object

    def __post_init__(self):
        if self._issuer is not _ISSUER or self.reader.invocation is not self.invocation:
            raise AuthorityUnavailable("StopReply metadata result requires its actual completed Work")
        _SEALS.add(self)

    def require_core_v1(self,service,db,*,anchor,request=None):
        if (self not in _SEALS or self._issuer is not _ISSUER or self.invocation.service is not service
                or self.reader.closed or self.invocation.request!=request):
            raise AuthorityUnavailable("StopReply consumer requires its same originating sealed metadata")
        self.invocation.require_core_v1(db,anchor=anchor)
        return self.result


@contextmanager
def prepare_owner_stop_reply_metadata_v1(service,*,credential,subject,actor=None,session_token=None,
        session_request=None,mode,request=None,cursor=None,source_row=None,permit=None,callback):
    """The installed Owner endpoint owns this call; callback is fixed product code."""
    from .owner_location_read_v3 import (create_owner_stop_reply_metadata_caller_proof_v1,
        prepare_owner_location_read_work_v3,owner_location_read_quantum_v3)
    invocation=begin_owner_stop_reply_metadata_invocation_v1(service,credential=credential,subject=subject,
        actor=actor,session_token=session_token,session_request=session_request,mode=mode,
        request=request,cursor=cursor,source_row=source_row,permit=permit)
    proof=owner_work=reader=seal=None
    try:
        proof=create_owner_stop_reply_metadata_caller_proof_v1(invocation)
        owner_work=prepare_owner_location_read_work_v3(proof)
        while True:
            with owner_location_read_quantum_v3(proof)as meter:
                result=owner_work.advance(meter=meter)
            if type(result)is dict and result.get("phase")=="owner_location_quantum_commit":
                result=owner_work.complete_reserved_quantum_v3(proof)
            if type(result)is not dict:break
        facts=result.require_for_v3(proof)
        reader=OwnerStopReplyMetadataReadV1(invocation,owner_proof=proof,owner_work=owner_work,owner_facts=facts)
        value=reader.evaluate_v1(callback)
        invocation.require_current_v1(phase="after")
        seal=PreparedOwnerStopReplyMetadataV1(invocation,reader,value,_ISSUER)
        token=_SERVICE_SEAL.set(seal)
        try:yield seal
        finally:_SERVICE_SEAL.reset(token)
    finally:
        if seal is not None:_SEALS.discard(seal)
        try:
            if reader is not None:reader.close_v1()
            if owner_work is not None:owner_work.close_v3()
        finally:
            try:
                if proof is not None:proof.release_v3()
            finally:invocation.close_v1()


def active_owner_stop_reply_service_metadata_v1(service,*,request=None,session_request=None):
    seal=_SERVICE_SEAL.get()
    if seal is None or seal.invocation.service is not service:return None
    if (seal not in _SEALS or seal.reader.closed or seal.invocation.request!=request
            or session_request is not None and seal.invocation.session_request!=session_request):
        raise AuthorityUnavailable("StopReply metadata selection differs from its actual caller seal")
    if service.core._db.in_transaction:
        db=service.core._db
        anchor=service.core._anchor(db,service.namespace,service.core._row(db,service.namespace))
        seal.require_core_v1(service,db,anchor=anchor,request=request)
    else:seal.invocation.require_current_v1(phase="after")
    return seal.result


@dataclass(frozen=True,slots=True)
class OwnerStopReplyMetadataResultV1:
    metadata_value:tuple
    projection_ref:str|None
    versions:tuple
    requirements:object
    artifact_mode:bool

_HOST_READERS=WeakSet()
_HOST_PREPARED={}


class HostOwnerStopReplyMetadataReadV1(OwnerStopReplyMetadataReadV1):
    """The actual held WRITE caller, scheduled by the installed GraphWorker."""
    def __init__(self,graph,issued,operation):
        from ..runtime.foreground_activity_issuance_v1 import require_owner_stop_projection_issuance_v1
        observed=require_owner_stop_projection_issuance_v1(issued,graph,issued.scope)
        self.graph,self.issued,self.observed=graph,issued,observed
        self.db=graph._GraphCoordinator__store._db
        self.operation=operation;self.namespace=observed.request.namespace
        self.issuer=graph._GraphCoordinator__d11_issuer
        self.selection_digest=runtime_storage_v3(self.db).selection_digest
        self.closed=False;self.sealed=False;self.complete=False;self.pending=None
        self.points={};self.scans={};self.columns=set();self.column_kinds={}
        self.inner_readers={};self.inner_headers={}
        self.reserved=0;self.outputs=[];self.thread=get_ident();self.result=None
        _HOST_READERS.add(self)

    def require_actual_v3(self):
        from ..runtime.foreground_activity_issuance_v1 import require_owner_stop_projection_issuance_v1
        if (self not in _HOST_READERS or self.closed or self.thread!=get_ident()
                or self.operation.closed or runtime_storage_v3(self.db).selection_digest!=self.selection_digest):
            raise AuthorityUnavailable("StopReply Host metadata lost its actual retained WRITE Work")
        if require_owner_stop_projection_issuance_v1(self.issued,self.graph,self.issued.scope)!=self.observed:
            raise AuthorityUnavailable("StopReply Host metadata changed its privately held observation")
        return self

    def require_data_current_v3(self,meter):
        self.require_actual_v3()
        runtime_storage_v3(self.db).require_current(meter)
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        revision=_runtime_bounded_fixed_row_v3(self.db,meter,"graph_recovery_metadata_v2",
            ("graph_revision",),"bot=? AND persona=?",self.namespace.as_tuple)
        epoch=_runtime_bounded_fixed_row_v3(self.db,meter,"graph_epochs",
            ("revision",),"bot=? AND persona=?",self.namespace.as_tuple)
        if (revision,epoch)!=((self.observed.graph_revision,),(self.observed.graph_epoch,)):
            raise AuthorityUnavailable("StopReply Host metadata fixed Graph stamp changed")
        return self

    def require_outside_v1(self):
        from ..runtime.foreground_activity_issuance_v1 import reobserve_owner_stop_projection_v1
        self.require_actual_v3()
        if self.db.in_transaction:
            raise AuthorityUnavailable("StopReply Host Owner observation must precede Graph SQL")
        if reobserve_owner_stop_projection_v1(self.issued)!=self.observed:
            raise AuthorityUnavailable("StopReply Host current Owner/WRITE changed")

    def read_algorithm_v1(self):
        from ..runtime.owner_stop_reply_v1 import read_plan_owner_stop_reply_v1
        from ..runtime.d11_types import job_graph_write
        from .model_reply_scope_observation_v3 import model_reply_scope_point_v3
        from ..runtime.domain_background_read_v3 import background_json_matches_v3
        plan=read_plan_owner_stop_reply_v1(self.db,namespace=self.namespace,
            request=self.observed.request,issuer=self.issuer)
        for job in plan.jobs:
            projection=job_graph_write(job)
            atom=model_reply_scope_point_v3(self.db,table="graph_atoms",
                columns=("revision","value","valid"),key_columns=("token",),key=(projection.key.token,),
                legacy_reader=lambda:None)
            if atom is None or atom[2]!=1 or not background_json_matches_v3(atom[1],projection.value):
                raise AuthorityUnavailable("StopReply Host metadata differs from the actual job projection")
        return plan

    def release_payload_v3(self):
        if self.closed:return
        _HOST_PREPARED.pop(id(self.issued),None)
        OwnerStopReplyMetadataReadV1.close_v1(self)
        _HOST_READERS.discard(self)


class PreparedHostOwnerStopReplyMetadataV1:
    def __init__(self,key,reader):
        if key is not _ISSUER or not reader.complete or reader.closed:
            raise AuthorityUnavailable("StopReply Host result requires actual metadata EOF")
        self.reader=reader
        _HOST_PREPARED[id(reader.issued)]=self

    def release_payload_v3(self):
        self.reader.release_payload_v3()


class HostOwnerStopReplyMetadataWorkV1:
    kind="owner_stop_projection"
    def __init__(self,key,reader):
        if key is not _ISSUER:raise TypeError("actual StopReply metadata producer required")
        self.reader=reader

    def release_payload_v3(self):self.reader.release_payload_v3()


def create_host_owner_stop_reply_metadata_work_v1(graph,issued):
    from ..graph_worker import create_graph_storage_work_v3,require_graph_storage_work_admission_v3
    require_graph_storage_work_admission_v3(graph)
    db=graph._GraphCoordinator__store._db
    operation=begin_runtime_storage_operation_v3(db,"owner-stop-metadata:"+issued.scope.operation_id,None)
    if operation is None:raise AuthorityUnavailable("StopReply Host requires actual installed selected Graph storage")
    reader=None
    try:
        reader=HostOwnerStopReplyMetadataReadV1(graph,issued,operation)
        reader.require_outside_v1()
        return create_graph_storage_work_v3(graph,kind="domain_background_read_v3",
            operation_id=operation.operation_id,selection_digest=reader.selection_digest,deadline_utc=None,
            state=HostOwnerStopReplyMetadataWorkV1(_ISSUER,reader),operation=operation)
    except BaseException:
        if reader is not None:reader.release_payload_v3()
        finish_runtime_storage_operation_v3(operation)
        raise


def advance_host_owner_stop_reply_metadata_work_v1(graph,work):
    from ..graph_worker import GraphStorageStepV3
    from .model_reply_scope_observation_v3 import ModelReplyScopeObservationNeededV3,_ReplyScopeMetadataScanV3
    from ..runtime.domain_background_read_v3 import _BackgroundPointReadV3
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    if type(work.state)is not HostOwnerStopReplyMetadataWorkV1:
        raise AuthorityUnavailable("actual StopReply Host Work required")
    reader=work.state.reader
    if reader.graph is not graph or work.operation is not reader.operation:
        raise AuthorityUnavailable("StopReply Host Work crossed its producer or physical lease")
    reader.require_outside_v1()
    with bind_runtime_storage_operation_v3(reader.operation,reader.db):
        with graph._GraphCoordinator__store._lock,runtime_storage_quantum_v3(reader.db)as meter:
            reader.db.execute("BEGIN")
            token=_BOUND.set(reader)
            try:
                reader.require_data_current_v3(meter)
                if reader.pending is None:
                    try:value=reader.read_algorithm_v1()
                    except ModelReplyScopeObservationNeededV3 as needed:reader.pending=needed.request
                    else:
                        reader.outputs.append(value);reader.reserve_heap_v3()
                        reader.complete=True
                if reader.pending is not None:
                    request=reader.pending
                    tasks=reader.scans if request[0]=="scan"else reader.points
                    task=tasks.get(request)
                    if task is None:
                        if request[0]=="scan":task=_ReplyScopeMetadataScanV3(reader,request[1],request[2])
                        else:
                            reader.require_request_v3(request);task=_BackgroundPointReadV3(reader,request)
                        tasks[request]=task
                    task.advance(meter);reader.reserve_heap_v3()
                    if task.complete:reader.pending=None
                reader.require_data_current_v3(meter)
            finally:
                _BOUND.reset(token);reader.db.rollback()
    reader.require_outside_v1()
    if reader.complete:
        reader.sealed=True;reader.result=PreparedHostOwnerStopReplyMetadataV1(_ISSUER,reader)
        return GraphStorageStepV3("complete",reader.result)
    return GraphStorageStepV3("progress")


def finish_host_owner_stop_reply_metadata_work_v1(graph,work,error):
    if type(work.state)is not HostOwnerStopReplyMetadataWorkV1 or work.state.reader.graph is not graph:
        raise AuthorityUnavailable("StopReply Host finalization lost its actual Work")
    if error is None:work.result_lease=work.operation
    else:
        work.state.release_payload_v3()
        finish_runtime_storage_operation_v3(work.operation)


@contextmanager
def bind_host_owner_stop_reply_metadata_v1(issued,db):
    prepared=_HOST_PREPARED.get(id(issued))
    if (type(prepared)is not PreparedHostOwnerStopReplyMetadataV1 or prepared.reader.issued is not issued
            or prepared.reader.db is not db or not prepared.reader.sealed or not prepared.reader.complete
            or not db.in_transaction):
        raise AuthorityUnavailable("StopReply W01 needs the same held WRITE metadata EOF")
    reader=prepared.reader.require_actual_v3()
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with bind_runtime_storage_operation_v3(reader.operation,db),runtime_storage_quantum_v3(db):
        token=_BOUND.set(reader)
        try:yield prepared
        finally:_BOUND.reset(token)
