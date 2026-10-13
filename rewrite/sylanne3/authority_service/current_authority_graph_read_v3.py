"""Authority-owned graph read lifetime; physical identity never grants a body read."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from threading import get_ident
from weakref import WeakKeyDictionary,WeakSet
import sqlite3
import math

from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2
from ..runtime_contracts import NamespaceId
from ..runtime_storage_v3 import (bind_runtime_database_from_control_v3,
    begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3,runtime_storage_quantum_v3)

_ISSUER=object()
_CONTROLLERS=WeakKeyDictionary()
_WORKS=WeakSet()
_PREPARED=WeakKeyDictionary()
_DEADLINES=WeakKeyDictionary()
_BOUND=ContextVar('sylanne_authority_graph_read_v3',default=None)


def _service_fields_v3(service,verifier):
    from .v2_model_egress_service import AuthorityV2ModelEgressService
    from .v2_natural_generation_content_service import AuthorityV2NaturalGenerationContentService
    from .v2_natural_paid_review_service import AuthorityV2NaturalPaidReviewService
    from .d13_core_counter_source_v1 import InstalledD13CounterSourceV1
    if type(service)is AuthorityV2ModelEgressService:
        if service._graph_verifier is not verifier:raise AuthorityUnavailable('actual installed model verifier differs')
        return 'model',service._fences,service._source_location,verifier._clock
    if type(service)is AuthorityV2NaturalGenerationContentService:
        if service._graph is not verifier:raise AuthorityUnavailable('actual installed generation verifier differs')
        owner=service._original
        return 'generation',owner._fences,None,service._clock
    if type(service)is AuthorityV2NaturalPaidReviewService:
        if service._graph is not verifier:raise AuthorityUnavailable('actual installed paid-review verifier differs')
        return 'review',service._generation._fences,None,service._clock
    if type(service)is InstalledD13CounterSourceV1:
        if service is not verifier:raise AuthorityUnavailable('actual installed counter source differs')
        owner=service.self_identity
        return 'counter',owner._fences,owner._source_location,service.observer.clock
    raise AuthorityUnavailable('unregistered Authority graph read service')


class InstalledAuthorityGraphReadControllerV3:
    def __init__(self,issuer,verifier,service):
        if issuer is not _ISSUER:raise TypeError('actual installed Authority read controller required')
        self.verifier,self.service=verifier,service
        self.kind,self.fences,self.location,self.clock=_service_fields_v3(service,verifier)
        self.thread=get_ident()
        self.control=None
    def require_installed_v3(self):
        if _CONTROLLERS.get(self.verifier)is not self:
            raise AuthorityUnavailable('Authority read controller changed installation or owning thread')
        kind,fences,location,clock=_service_fields_v3(self.service,self.verifier)
        if kind!=self.kind or fences is not self.fences or clock!=self.clock:
            raise AuthorityUnavailable('Authority read controller changed its actual service')
        from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
        if type(self.location)is not InstalledCurrentSourceLocationQualifierV1:
            raise AuthorityUnavailable('Authority reader needs its late-installed current Graph qualifier')
        if location is not None and location is not self.location:
            raise AuthorityUnavailable('Authority current location service changed')
        if (self.location._fences is not fences or self.location.core is not fences.core
                or self.location._control is not fences.core._c09_storage_reader_v1):
            raise AuthorityUnavailable('Authority controller crossed its actual Core/fence/Control')
        return self
    def bind_location_v3(self,location):
        from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
        if (type(location)is not InstalledCurrentSourceLocationQualifierV1
                or location._fences is not self.fences or location.core is not self.fences.core
                or self.location is not None and self.location is not location):
            raise AuthorityUnavailable('Authority reader needs its actual installed location')
        path=(self.verifier.self_identity._graph._path if self.kind=='counter' else self.verifier._path)
        if location._graph_db_path!=path:raise AuthorityUnavailable('Authority verifier differs from selected Graph path')
        self.location,self.control=location,location._control
        return self


def install_authority_graph_read_controller_v3(verifier,*,service,source_location=None):
    previous=_CONTROLLERS.get(verifier)
    if previous is None:
        previous=InstalledAuthorityGraphReadControllerV3(_ISSUER,verifier,service)
        _CONTROLLERS[verifier]=previous
    elif previous.service is not service:
        raise AuthorityUnavailable('Authority verifier already belongs to another actual service')
    location=source_location if source_location is not None else previous.location
    if location is not None:previous.bind_location_v3(location)
    return previous


def require_authority_graph_read_controller_v3(verifier):
    controller=_CONTROLLERS.get(verifier)
    if controller is None:raise AuthorityUnavailable('late-installed Authority read controller unavailable')
    return controller.require_installed_v3()


@dataclass(frozen=True,slots=True)
class _AuthorityReadScopeV3:
    namespace:NamespaceId
    permit:FencePermitV2
    operation_id:str


class AuthorityGraphReadWorkV3:
    """One actual Authority call owns its cursor, database and retention operation."""
    def __init__(self,issuer,controller,*,credential,subject,permit,namespace,request,deadline_utc):
        if issuer is not _ISSUER:raise TypeError('Authority Work requires its installed producer')
        controller.require_installed_v3()
        if (type(permit)is not FencePermitV2 or type(namespace)is not NamespaceId
                or namespace!=controller.location.namespace_id or subject!=permit.subject
                or permit.namespace!=controller.fences.namespace
                or deadline_utc is not None and (type(deadline_utc)not in(int,float)or not math.isfinite(deadline_utc))):
            raise AuthorityUnavailable('Authority Work crossed its original namespace/permit/deadline')
        self.controller,self.service=controller,controller.service
        self.credential,self.subject,self.permit=credential,subject,permit
        self.namespace,self.request,self.deadline_utc=namespace,request,(None if deadline_utc is None else float(deadline_utc))
        self.thread=get_ident();self.closed=False;self.complete=False;self.failure=None;self.issued_capabilities=[]
        self.db=self.handle=self.operation=None;self.borrowed_counter_operation=False
        self.work=self;self.state=self;self.prefinal=self
        self.scope=_AuthorityReadScopeV3(namespace,permit,permit.operation_id)
        self.fence=self
        self.phase='entry';self.attachments={};self.sources={};self.originals={};self.members={}
        self.prepared=None;self.graph_stamp=None;self.pending=None
        self.history_continuation=self.history_current_reader=self.history_current=None
        self.catalogue_reader=self.namespace_reader=self.projection=None
        self.original_reader=self.source_reader=self.source_material=self.source_selection=None
        self.parent_original_id=None;self.now_utc=None;self.producer_roots=()
        self.collection_record=None;self.collection_source_materials={};self.collection_source_reader=None
        self.collection_readers=[];self.paid_candidate_readers=[];self.source_atoms={};self.atom_json_originals={}
        self.producer_inputs=self.producer_context=self.producer_frame=None
        self.counter_call=self.counter_current_self=self.counter_owner=self.counter_location=None
        self.counter_prospective=self.counter_material_scope=self.counter_pair_reader=None
        self.counter_events=[];self.counter_event_index=0
        self.context_original_reader=self.context_original=self.context_source_selection=None
        self.context_call_reader=None
        self.context_source_reader=self.context_source_material=None;self.model_context=False
        self.c02_bundle_reader=self.c02_bundle_original=None
        self._check_permission_v3()
        control=controller.control
        from .daemon import _bootstrap_control_quantum_v3
        with _bootstrap_control_quantum_v3(control)as initial_meter:
            context=control.read_verified_current_storage_v3()
            context.require_current('business')
            core_handle=controller.fences.core._runtime_storage_v3
            if (core_handle is None or core_handle.context._reader is not control
                    or (core_handle.context.manifest_digest,core_handle.context.pointer_version)!=
                       (context.manifest_digest,context.pointer_version)):
                raise AuthorityUnavailable('Authority Core and current selected Graph differ')
            member=next(item for item in context.manifest['members']if item['role']=='graph')
            path=Path(member['resolved_path']).resolve(strict=True)
            if path!=controller.location._graph_db_path:
                raise AuthorityUnavailable('Authority reader path differs from its actual selected member')
            self.db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
            self.db.execute('PRAGMA query_only=ON')
            try:self.handle=bind_runtime_database_from_control_v3(self.db,control=control,role='graph')
            except BaseException:self.db.close();self.db=None;raise
            if controller.kind=='model'and self.deadline_utc is None:
                from datetime import datetime
                row=initial_meter.read_fixed_row(self.db,'runtime_jobs',
                    ('bot_id','persona_id','deadline_utc','lease_expires_utc'),'job_id=?',(request.job_id,))
                if row is None or row[:2]!=namespace.as_tuple or row[3]is None:
                    self.handle.close();self.db.close();self.db=None
                    raise AuthorityUnavailable('Authority model read has no actual current original worker/job deadline')
                self.deadline_utc=min(datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()for value in row[2:])
        if self.handle is None:
            self.db.close();self.db=None
            raise AuthorityUnavailable('Authority V3 Work requires its actual selected segmented Graph')
        try:
            if controller.kind=='counter':
                from .d13_core_counter_source_v1 import borrow_authority_counter_resource_lease_v3
                self.operation=borrow_authority_counter_resource_lease_v3(self);self.borrowed_counter_operation=True
            else:self.operation=begin_runtime_storage_operation_v3(self.db,permit.operation_id,self.deadline_utc)
            self.selection_digest=self.operation.selection_digest
            _WORKS.add(self)
            _DEADLINES[self]=(self.operation,self.deadline_utc,None)
        except BaseException:
            self.handle.close();self.db.close();self.db=None;raise
    def _check_permission_v3(self):
        controller=self.controller.require_installed_v3()
        if get_ident()!=self.thread or self.closed:
            raise AuthorityUnavailable('Authority read Work no longer belongs to its live call')
        if controller.fences.core._db.in_transaction:
            raise AuthorityUnavailable('Authority permission observation must precede Graph SQL')
        controller.fences.core._require(self.credential,self.permit.operation,
            controller.fences.namespace,self.permit.holder)
        controller.fences.validate_fence(credential=self.credential,subject=self.subject,permit=self.permit)
        if self.deadline_utc is not None:
            reading=controller.clock()
            now=reading.utc_seconds+reading.utc_error_seconds if controller.kind=='counter' else reading
            if type(now)not in(int,float)or not math.isfinite(now)or now>=self.deadline_utc:
                raise AuthorityUnavailable('Authority read exceeded its original contract deadline')
    def _actual(self):
        if (self not in _WORKS or self.closed or self.operation is None or self.operation.closed
                or self.state is not self or self.prefinal is not self or get_ident()!=self.thread
                or self.controller.service is not self.service
                or self.operation.selection_digest!=self.selection_digest
                or _DEADLINES.get(self)!=(self.operation,self.deadline_utc,getattr(self,'deadline_original',None))
                or not self.borrowed_counter_operation and self.operation.deadline_utc!=self.deadline_utc):
            raise AuthorityUnavailable('actual same-Authority Work and retained operation required')
        if self.borrowed_counter_operation:
            from .d13_core_counter_source_v1 import require_authority_counter_resource_borrow_v3
            require_authority_counter_resource_borrow_v3(self)
        return self
    def require_current(self,*,meter=None):
        self._actual()
        if meter is None:raise AuthorityUnavailable('Authority local read requires its actual current quantum')
        self.handle.require_current(meter)
        epoch=meter.read_fixed_row(self.db,'graph_epochs',('revision',),'bot=? AND persona=?',self.namespace.as_tuple)
        rights=meter.read_fixed_row(self.db,'graph_authority_epochs',('access_epoch','delete_epoch'),
            'bot=? AND persona=?',self.namespace.as_tuple)
        if epoch is None or rights is None:raise AuthorityUnavailable('Authority Graph scope epochs absent')
        stamp=(*epoch,*rights)
        if self.graph_stamp is None:self.graph_stamp=stamp
        elif self.graph_stamp!=stamp:raise AuthorityUnavailable('Authority Graph Source/rights scope changed while reading')
        return self
    @contextmanager
    def quantum_v3(self):
        self._check_permission_v3()
        if self.db.in_transaction:
            raise AuthorityUnavailable('Authority quantum cannot inherit a Graph transaction')
        with bind_runtime_storage_operation_v3(self.operation,self.db):
            with runtime_storage_quantum_v3(self.db)as meter:
                self.db.execute('BEGIN')
                try:
                    self.require_current(meter=meter)
                    yield meter
                    self.require_current(meter=meter)
                finally:
                    self.db.execute('ROLLBACK')
        self._check_permission_v3()
    def release_v3(self):
        if self.closed:return
        self.closed=True;_WORKS.discard(self);_DEADLINES.pop(self,None)
        for registry,original in self.issued_capabilities:registry.pop(original,None)
        self.issued_capabilities.clear()
        if self.prepared is not None:_PREPARED.pop(self.prepared,None)
        try:
            if self.producer_context is not None:self.producer_context.close()
            self.producer_context=self.producer_inputs=self.producer_frame=None
            self.pending=None;self.attachments.clear();self.sources.clear();self.originals.clear();self.members.clear()
            if self.history_continuation is not None:self.history_continuation.release_payload_v3()
            if self.history_current_reader is not None:self.history_current_reader.release_payload_v3()
            self.history_continuation=self.history_current_reader=self.history_current=None
            if self.counter_pair_reader is not None:self.counter_pair_reader.release_payload_v3()
            for reader in self.collection_readers:
                if reader.page_program is not None:reader.page_program.close()
            self.collection_readers.clear();self.paid_candidate_readers.clear()
            self.source_atoms.clear();self.atom_json_originals.clear()
            self.counter_pair_reader=self.counter_prospective=self.counter_material_scope=None
            self.catalogue_reader=self.namespace_reader=self.projection=None
            self.original_reader=self.source_reader=self.source_material=self.source_selection=None
            self.context_original_reader=self.context_original=self.context_source_selection=None
            self.context_source_reader=self.context_source_material=self.context_call_reader=None
            self.c02_bundle_reader=self.c02_bundle_original=None
            self.collection_source_reader=None;self.collection_source_materials.clear();self.collection_record=None
            if self.handle is not None:self.handle.close()
        finally:
            try:
                if self.db is not None:self.db.close()
            finally:
                if self.borrowed_counter_operation:
                    from .d13_core_counter_source_v1 import release_authority_counter_resource_borrow_v3
                    release_authority_counter_resource_borrow_v3(self)
                else:finish_runtime_storage_operation_v3(self.operation)


def require_actual_authority_graph_attachment_owner_v3(owner,*,db=None):
    if type(owner)is not AuthorityGraphReadWorkV3:raise TypeError('exact Authority attachment Work required')
    owner._actual()
    if db is not None and owner.db is not db:raise AuthorityUnavailable('Authority attachment database differs')
    return owner


class PreparedAuthorityGraphReadV3:
    def __init__(self,issuer,work):
        if issuer is not _ISSUER or type(work)is not AuthorityGraphReadWorkV3 or not work.complete:
            raise TypeError('actual complete Authority read Work required')
        work._actual();self.work,self.service,self.db=work,work.service,work.db
        self.request,self.scope,self.selection_digest=work.request,work.scope,work.selection_digest
        self.projection=work.projection
        _PREPARED[self]=(work,self.service,self.db,self.request,self.scope,self.selection_digest)
    def require_current_v3(self,*,service,db,meter):
        if (_PREPARED.get(self)!=(self.work,self.service,self.db,self.request,self.scope,self.selection_digest)
                or service is not self.service or db is not self.db or not self.work.complete
                or self.projection is not self.work.projection):
            raise AuthorityUnavailable('prepared Authority read changed service/request/selected scope')
        self.work.require_current(meter=meter)
        return self


@contextmanager
def bind_prepared_authority_graph_read_v3(prepared,*,service,db,meter):
    if type(prepared)is not PreparedAuthorityGraphReadV3:raise TypeError('exact prepared Authority read required')
    prepared.require_current_v3(service=service,db=db,meter=meter)
    token=_BOUND.set(prepared)
    try:yield prepared
    finally:_BOUND.reset(token)

_READING=ContextVar('sylanne_authority_graph_original_reading_v3',default=None)


class AuthorityGraphAttachmentRequiredV3(Exception):
    def __init__(self,request):
        self.request=request
        super().__init__('actual Authority phase requires a prepared original')


def _authority_attachment_owner_v3(db):
    prepared=_BOUND.get()
    if prepared is not None:
        if type(prepared)is not PreparedAuthorityGraphReadV3 or prepared not in _PREPARED:
            raise AuthorityUnavailable('actual issued Authority prepared-original binding required')
        owner=prepared.work
    else:owner=_READING.get()
    if owner is None:return None
    require_actual_authority_graph_attachment_owner_v3(owner,db=db)
    return owner


@contextmanager
def bind_authority_graph_original_preparation_v3(work):
    require_actual_authority_graph_attachment_owner_v3(work)
    if work.complete:raise AuthorityUnavailable('Authority original preparation already sealed')
    token=_READING.set(work)
    try:yield work
    finally:_READING.reset(token)


def read_bound_authority_graph_attachment_v3(db,*,table,columns,key_columns,key):
    owner=_authority_attachment_owner_v3(db)
    if owner is None:return False,None
    from ..runtime.natural_producer_qualification_v1 import _HOST_ATTACHMENT_SHAPES_V3
    from ..graph_types import AtomKey
    original_columns=tuple(columns);original_keys=dict(zip(key_columns,key))
    if table=='graph_atoms':
        key=(original_keys['token'],*owner.namespace.as_tuple)
        key_columns=('token','bot','persona');columns=('revision','value','valid')
    elif table=='graph_history':
        key=(original_keys['token'],original_keys['revision']);key_columns=('token','revision')
        columns=('event_id','value','valid','event_bot','event_persona','event_session','dependencies')
    request=(table,tuple(columns),tuple(key_columns),tuple(key))
    if request[:3]not in _HOST_ATTACHMENT_SHAPES_V3:
        raise AuthorityUnavailable('Authority original lacks a registered exact table/columns/PK shape')
    if table in('graph_atoms','graph_history','graph_dependencies'):
        if NamespaceId.from_key(AtomKey.from_token(key[0]))!=owner.namespace:
            raise AuthorityUnavailable('Authority original crossed its actual namespace')
    elif table=='runtime_resource_quotes':
        if tuple(key_columns)!=('quote_id','version'):raise AuthorityUnavailable('Authority quote requires its actual full PK')
    elif table=='runtime_budget_reservations':
        with runtime_storage_quantum_v3(db)as meter:
            lease=meter.read_fixed_row(db,'runtime_budget_leases',('bot_id','persona_id'),'lease_id=?',(key[0],))
        if lease!=owner.namespace.as_tuple:raise AuthorityUnavailable('Authority reservation crossed actual parent namespace')
    elif tuple(key[:2])!=owner.namespace.as_tuple:
        raise AuthorityUnavailable('Authority original crossed its actual namespace')
    attachment=owner.attachments.get(request)
    if attachment is None:
        if owner.complete:raise AuthorityUnavailable('Authority final original was not prepared by this Work')
        raise AuthorityGraphAttachmentRequiredV3(request)
    with runtime_storage_quantum_v3(db)as meter:
        row=attachment.require_row_v3(owner,meter)
    if row is None:return True,None
    if table in('graph_atoms','graph_history'):
        data=dict(zip(columns,row))
        if table=='graph_atoms':data.update(token=key[0],bot=key[1],persona=key[2])
        else:data.update(token=key[0],revision=key[1])
        if any(data.get(name)!=value for name,value in original_keys.items()):
            raise AuthorityUnavailable('Authority original current/history fullPK differs')
        return True,tuple(data[name]for name in original_columns)
    return True,row


def read_bound_authority_graph_attachment_rows_v3(db,*,table,columns,key_columns,key,order_column):
    owner=_authority_attachment_owner_v3(db)
    if owner is None:return False,None
    from ..runtime.natural_producer_qualification_v1 import _HOST_ATTACHMENT_SCANS_V3
    from ..graph_types import AtomKey
    shape=(table,tuple(columns),tuple(key_columns),order_column)
    if shape not in _HOST_ATTACHMENT_SCANS_V3:
        raise AuthorityUnavailable('Authority original family lacks a registered fixed keyset shape')
    if table=='graph_dependencies':
        if NamespaceId.from_key(AtomKey.from_token(key[0]))!=owner.namespace:
            raise AuthorityUnavailable('Authority dependency family crossed namespace')
    elif tuple(key[:2])!=owner.namespace.as_tuple:
        raise AuthorityUnavailable('Authority original family crossed namespace')
    request=(table,tuple(columns),tuple(key_columns),tuple(key),order_column)
    attachment=owner.attachments.get(request)
    if attachment is None:
        if owner.complete:raise AuthorityUnavailable('Authority final family was not prepared to actual EOF')
        raise AuthorityGraphAttachmentRequiredV3(request)
    with runtime_storage_quantum_v3(db)as meter:return True,attachment.require_row_v3(owner,meter)


def install_authority_graph_read_service_registry_v3(server,*,namespace,source_location):
    from .mtls_server import AuthorityRpcServer
    from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
    if (type(server)is not AuthorityRpcServer or type(source_location)is not InstalledCurrentSourceLocationQualifierV1
            or source_location.namespace!=namespace or server._v2_fences.get(namespace)is not source_location._fences):
        raise AuthorityUnavailable('actual late Authority service registry and installed location required')
    model=server._v2_model_egress.get(namespace)
    if model is not None:
        install_authority_graph_read_controller_v3(model._graph_verifier,service=model,source_location=source_location)
    for name in('_v2_natural_generation_content_reads','_v2_natural_paid_review_reads'):
        service=getattr(server,name).get(namespace)
        if service is not None:
            install_authority_graph_read_controller_v3(service._graph,service=service,source_location=source_location)


_AUTHORITY_C04_WIRES_V3=WeakKeyDictionary()


class PreparedAuthorityC04WireOriginalV3:
    """One complete actual Authority column, never a Host wire qualification."""
    def __init__(self,issuer,work,attachment,column):
        from ..runtime.natural_producer_qualification_v1 import _HostProducerAttachmentV3
        if (issuer is not _ISSUER or type(attachment)is not _HostProducerAttachmentV3
                or attachment.owner is not work or not attachment.complete
                or work.attachments.get(attachment.request)is not attachment):
            raise AuthorityUnavailable('actual completed Authority C04 attachment required')
        require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
        body=attachment.json_columns.get(column)
        if body is None or attachment.encoded.get(column)is None:
            raise AuthorityUnavailable('Authority C04 original column has no complete EOF')
        self.owner,self.attachment,self.column=work,attachment,column
        self.parsed_value=body.require_v3(work)
        self.wire=attachment.encoded[column]
        self.sha256,self.byte_count=body.sha256,body.byte_count
        self.column_original=(body,body.owner,body.table,body.column,body.key,body.sha256,body.byte_count,body._frozen_value)
        self.operation,self.scope=work.operation,work.scope
        _AUTHORITY_C04_WIRES_V3[self]=self._identity_v3()
    def _identity_v3(self):
        return(self.owner,self.attachment,self.column,self.parsed_value,self.wire,self.sha256,self.byte_count,
            self.column_original,self.operation,self.scope)
    def require_for_v4(self,owner):
        require_actual_authority_graph_attachment_owner_v3(owner,db=owner.db)
        if (_AUTHORITY_C04_WIRES_V3.get(self)!=self._identity_v3()or owner is not self.owner
                or owner.operation is not self.operation or owner.scope is not self.scope
                or owner.attachments.get(self.attachment.request)is not self.attachment
                or self.attachment.encoded.get(self.column)is not self.wire
                or self.attachment.json_columns.get(self.column)is not self.column_original[0]):
            raise AuthorityUnavailable('Authority C04 original changed its Work, column or scope')
        from ..runtime.dispatch_initial_source_read_v3 import _COLUMNS
        body=self.column_original[0]
        if (not body.complete or _COLUMNS.get(body)!=self.column_original[1:]
                or body.operation is not self.operation):
            raise AuthorityUnavailable('Authority C04 original lost canonical full EOF')
        return self


def actual_authority_c04_wire_original_v3(work,wire):
    require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
    from ..runtime.natural_producer_qualification_v1 import _HostProducerAttachmentV3
    matches=[(attachment,column)for attachment in work.attachments.values()
        if type(attachment)is _HostProducerAttachmentV3 and attachment.complete
        for column,value in attachment.encoded.items()if value is wire]
    if len(matches)!=1:raise AuthorityUnavailable('Authority C04 typed read must identify its unique actual column')
    attachment,column=matches[0]
    return PreparedAuthorityC04WireOriginalV3(_ISSUER,work,attachment,column)


class _AuthorityCanonicalTextReadV3:
    """Canonical embedded text is consumed once, in the owning Work's quanta."""
    def __init__(self,work,text):
        from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        if type(text)is not str:raise AuthorityUnavailable('Authority canonical original must be actual text')
        self.work,self.text=work,text
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.offset=0;self.nodes={};self.scalar=bytearray();self.value=None;self.complete=False;self.reserved=0
    def _reserve_v3(self,extra=0):
        from ..runtime.source_correction_read_v3 import _heap
        amount=_heap((self.nodes,self.scalar))+extra+65536
        if amount>self.reserved:self.work.operation.retain(amount-self.reserved);self.reserved=amount
    def _put_v3(self,path,value):
        if not path:self.value=value
        else:
            parent=self.nodes[path[:-1]]
            if type(parent)is list:parent.append(value)
            else:parent[path[-1]]=value
    def _emit_v3(self,event):
        import json
        if event.kind in('object_start','array_start'):
            self._reserve_v3(1024);value={}if event.kind=='object_start'else[]
            self.nodes[event.path]=value;self._put_v3(event.path,value)
        elif event.kind=='scalar_start':self.scalar=bytearray()
        elif event.kind=='scalar_chunk':self._reserve_v3(len(event.raw)*4+1024);self.scalar.extend(event.raw)
        elif event.kind=='scalar_end':
            self._reserve_v3(len(self.scalar)*4+1024)
            value=json.loads(self.scalar);self.scalar=bytearray();self._put_v3(event.path,value)
    def advance_v3(self,meter):
        self.work.require_current(meter=meter)
        if self.offset<len(self.text):
            end=min(self.offset+1024,len(self.text))
            fragment=self.text[self.offset:end].encode('ascii')
            meter.charge_encode(len(fragment));self._reserve_v3(len(fragment)*4+1024)
            self.parser.feed(fragment,self._emit_v3);self.offset=end;return False
        self.summary=self.parser.finish();self.complete=True
        return True


_AUTHORITY_REVIEW_CANONICAL_V3=WeakKeyDictionary()


class PreparedAuthorityReviewCanonicalV3:
    """Original review fields and all canonical carriers verified in one Work."""
    def __init__(self,issuer,work,column,generation):
        from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3,_container_bytes_v3
        if issuer is not _ISSUER or type(column)is not DispatchOriginalJSONReadV3:
            raise TypeError('actual Authority review column producer required')
        require_actual_authority_graph_attachment_owner_v3(work,db=column.db)
        if column.owner is not work or column.table!='graph_natural_review_preparations_v2'or column.column!='frozen_json':
            raise AuthorityUnavailable('Authority review canonical original crossed its actual column')
        self.work,self.column,self.generation=work,column,generation
        self.raw=column.require_v3(work)
        from ..model_broker.natural_review import FrozenNaturalReplyReviewV1
        from dataclasses import fields
        if type(self.raw)is not dict or set(self.raw)!={field.name for field in fields(FrozenNaturalReplyReviewV1)}:
            raise AuthorityUnavailable('Authority review frozen fieldset differs')
        work.operation.retain(_container_bytes_v3(self.raw)*2+65536)
        self.inner=_AuthorityCanonicalTextReadV3(work,self.raw['canonical_input'])
        self.phase='input';self.complete=False;self.comparison=None;self.result=None
        _AUTHORITY_REVIEW_CANONICAL_V3[self]=(work,column,work.operation,work.scope,generation,self.raw)
        _track_authority_capability_v3(work,_AUTHORITY_REVIEW_CANONICAL_V3,self)
    def _actual_v3(self):
        require_actual_authority_graph_attachment_owner_v3(self.work,db=self.column.db)
        if (_AUTHORITY_REVIEW_CANONICAL_V3.get(self)!=(self.work,self.column,self.work.operation,
                self.work.scope,self.generation,self.raw)or self.column.owner is not self.work):
            raise AuthorityUnavailable('Authority review canonical original lost its actual Work')
    def _comparison_v3(self,value,target=None):
        from ..runtime.natural_frozen_original_read_v3 import _CanonicalComparisonV3
        self.comparison=_CanonicalComparisonV3(value,target,operation=self.work.operation)
    def advance(self,meter):
        self._actual_v3();self.work.require_current(meter=meter)
        if self.complete:return True
        if self.phase=='input':
            if self.inner.advance_v3(meter):self.payload=self.inner.value;self.phase='fields'
            return False
        if self.phase=='fields':
            from ..model_broker.natural_review import _natural_review_value_fields_v3,NaturalReviewInstallationV1
            from ..runtime.natural_reply_job_v2 import _unit
            payload=self.payload
            if type(payload)is not dict or type(payload.get('qualified_basis'))is not list or not payload['qualified_basis']:
                raise AuthorityUnavailable('Authority review qualified basis is missing')
            self.basis=tuple(_unit(item['source_unit'])for item in payload['qualified_basis'])
            self.grants=tuple(payload['qualified_basis'][0]['promise_grant_refs'])
            if any(tuple(item['promise_grant_refs'])!=self.grants for item in payload['qualified_basis']):
                raise AuthorityUnavailable('Authority review promise grant family changed')
            output={'schema':payload.get('generation_output_schema','sylanne.d09.context_reply_output.v2'),
                'body':payload['body'],'units':payload['units']}
            from ..model_broker.natural_review import INPUT_SCHEMA_V2
            if payload.get('schema')==INPUT_SCHEMA_V2:output['semantic_segments']=payload['semantic_segments']
            self.installation=NaturalReviewInstallationV1(**self.raw['installation'])
            self.body,self.units,self.output,self.policy,self.semantic=_natural_review_value_fields_v3(
                self.generation,output,self.basis,self.grants,payload['review_policy_version'],self.installation)
            self._comparison_v3(self.basis);self.phase='basis';return False
        if self.phase=='basis':
            if not self.comparison.advance(meter):return False
            self.basis_digest='sha256:'+self.comparison.digest
            if self.basis_digest!=self.generation.qualified_units_digest:
                raise AuthorityUnavailable('Authority review actual basis differs from generation seal')
            self._comparison_v3(self.output);self.phase='output';return False
        if self.phase=='output':
            if not self.comparison.advance(meter):return False
            self.output_digest='sha256:'+self.comparison.digest
            from dataclasses import asdict
            from ..model_broker.natural_review import (NaturalReviewQualifiedUnitV1,INPUT_SCHEMA,INPUT_SCHEMA_V2,
                REVIEW_TEMPLATE_VERSION,REVIEW_TEMPLATE_VERSION_V2)
            self.expected_input={'schema':INPUT_SCHEMA_V2 if self.semantic else INPUT_SCHEMA,
                'template_version':REVIEW_TEMPLATE_VERSION_V2 if self.semantic else REVIEW_TEMPLATE_VERSION,
                'generation_frozen_input_digest':self.generation.frozen_input_digest,
                'generation_output_digest':self.output_digest,'qualified_units_digest':self.basis_digest,
                'review_policy_version':self.policy,'body':self.body,'units':[asdict(unit)for unit in self.units],
                'qualified_basis':[asdict(NaturalReviewQualifiedUnitV1(unit,self.grants))for unit in self.basis]}
            if self.semantic:
                self.expected_input['semantic_segments']=self.output['semantic_segments']
                self.expected_input['generation_output_schema']=self.output['schema']
            self._comparison_v3(self.expected_input,self.raw['canonical_input']);self.phase='input_compare';return False
        if self.phase=='input_compare':
            if not self.comparison.advance(meter):return False
            self.input_digest='sha256:'+self.comparison.digest
            from ..model_broker.natural_review import SYSTEM_MESSAGE,SYSTEM_MESSAGE_V2
            self.messages=[{'role':'system','content':SYSTEM_MESSAGE_V2 if self.semantic else SYSTEM_MESSAGE},
                {'role':'user','content':self.raw['canonical_input']}]
            self._comparison_v3(self.messages,self.raw['messages_wire']);self.phase='messages';return False
        if self.phase=='messages':
            if not self.comparison.advance(meter):return False
            self.expected_wire={'provider_id':self.installation.provider_id,'model':self.installation.model_id,
                'messages':self.messages,'max_output_tokens':self.installation.max_output_tokens}
            self._comparison_v3(self.expected_wire,self.raw['canonical_wire']);self.phase='wire';return False
        if self.phase=='wire':
            if not self.comparison.advance(meter):return False
            self.wire_digest=self.comparison.digest
            self.expected_payload_digest=self.wire_digest
            from dataclasses import asdict
            from ..model_broker.natural_review import FrozenNaturalReplyReviewV1
            self.result=FrozenNaturalReplyReviewV1(self.generation.frozen_input_digest,self.output_digest,
                self.basis_digest,self.body,self.units,self.basis,self.policy,self.installation,
                self.raw['canonical_input'],self.raw['messages_wire'],self.raw['canonical_wire'],
                self.input_digest,self.wire_digest)
            self._comparison_v3(asdict(self.result));self.phase='roundtrip';return False
        if self.phase=='roundtrip':
            if not self.comparison.advance(meter):return False
            if(self.comparison.digest,self.comparison.offset)!=(self.column.sha256,self.column.byte_count):
                raise AuthorityUnavailable('Authority review typed roundtrip differs from its original full EOF')
            self.complete=True;return True
        raise AuthorityUnavailable('unregistered Authority review canonical phase')
    def require_for_v3(self,raw):
        self._actual_v3()
        from ..runtime.dispatch_current_inventory_v3 import _freeze_value_v3
        if not self.complete or _freeze_value_v3(raw)!=self.column._frozen_value:
            raise AuthorityUnavailable('Authority review canonical proof requires complete actual roundtrip')
        return self.result


def begin_authority_review_canonical_read_v3(work,column,*,generation):
    return PreparedAuthorityReviewCanonicalV3(_ISSUER,work,column,generation)


_AUTHORITY_PAYLOAD_EOF_V3=WeakKeyDictionary()


class PreparedAuthorityNaturalPayloadEOFV3:
    """Canonical historical request material; carries no current Source grant."""
    def __init__(self,issuer,originals,raw,envelope):
        from ..runtime.dispatch_initial_source_read_v3 import require_actual_authority_natural_original_v3
        if issuer is not _ISSUER:raise TypeError('actual Authority payload EOF issuer required')
        require_actual_authority_natural_original_v3(originals)
        column=originals.columns['typed_request_wire']
        from ..runtime.dispatch_current_inventory_v3 import _freeze_value_v3
        if (_freeze_value_v3(raw)!=column._frozen_value or column.owner is not originals.owner
                or envelope.authority.namespace!=originals.owner.namespace):
            raise AuthorityUnavailable('Authority request canonical original differs from its actual column')
        self.originals,self.column,self.raw,self.envelope=originals,column,raw,envelope
        _AUTHORITY_PAYLOAD_EOF_V3[self]=(originals,column,raw,envelope,originals.owner.operation)
    def require_for_v3(self,request):
        from ..runtime.dispatch_initial_source_read_v3 import require_actual_authority_natural_original_v3
        from ..runtime.dispatch_current_inventory_v3 import _freeze_value_v3
        from ..runtime.reply_model_job import reply_request_wire_v1
        require_actual_authority_natural_original_v3(self.originals)
        if (_AUTHORITY_PAYLOAD_EOF_V3.get(self)!=(self.originals,self.column,self.raw,self.envelope,self.originals.owner.operation)
                or request.envelope!=self.envelope or request.payload is not self.raw['payload']
                or _freeze_value_v3(reply_request_wire_v1(request.envelope,request))!=self.column._frozen_value):
            raise AuthorityUnavailable('Authority typed historical request changed after complete canonical EOF')
        _retain_authority_model_digest_v3(request,self.originals.digests['typed_request'])
        _AUTHORITY_PAYLOAD_EOF_V3.pop(self,None)


def require_prepared_authority_model_payload_eof_v3(witness,request):
    if type(witness)is PreparedAuthorityContextPayloadEOFV3:
        witness.require_for_v3(request);return
    if type(witness)is not PreparedAuthorityNaturalPayloadEOFV3 or witness not in _AUTHORITY_PAYLOAD_EOF_V3:
        raise TypeError('exact Authority historical payload EOF witness required')
    witness.require_for_v3(request)


def prepare_authority_natural_payload_eof_v3(originals,raw,envelope):
    return PreparedAuthorityNaturalPayloadEOFV3(_ISSUER,originals,raw,envelope)


class AuthorityNaturalOriginalRequiredV3(Exception):
    def __init__(self,namespace,parent,stage):
        self.namespace,self.parent,self.stage=namespace,parent,stage
        super().__init__('actual Authority phase requires its saved natural original')


def read_bound_authority_natural_original_v3(db,namespace,parent,stage):
    owner=_authority_attachment_owner_v3(db)
    if owner is None:return False,None
    if namespace!=owner.namespace or stage not in('generation','review'):
        raise AuthorityUnavailable('Authority saved original crossed its actual namespace or stage')
    original=owner.originals.get((parent,stage))
    if original is None:
        if owner.complete:raise AuthorityUnavailable('Authority final saved original was not prepared')
        raise AuthorityNaturalOriginalRequiredV3(namespace,parent,stage)
    from ..runtime.dispatch_initial_source_read_v3 import require_actual_authority_natural_original_v3
    require_actual_authority_natural_original_v3(original)
    original.require_for_v3(db,namespace,parent,stage)
    return True,original


_AUTHORITY_GRAPH_VALUES_V3=WeakKeyDictionary()


class PreparedAuthorityGraphValueOriginalV3:
    """Canonical-object EOF for a normal GraphAtom constructor, without a grant."""
    def __init__(self,issuer,work,attachment,key,revision,valid,value):
        from ..graph_types import AtomKey
        from ..runtime.natural_producer_qualification_v1 import _HostProducerAttachmentV3
        from ..runtime.dispatch_initial_source_read_v3 import _COLUMNS,_container_bytes_v3
        from ..runtime.dispatch_current_inventory_v3 import _freeze_value_v3
        if (issuer is not _ISSUER or type(key)is not AtomKey or type(value)is not dict
                or type(attachment)is not _HostProducerAttachmentV3 or attachment.owner is not work
                or not attachment.complete or work.attachments.get(attachment.request)is not attachment
                or type(revision)is not int or revision<1 or type(valid)is not bool
                or NamespaceId.from_key(key)!=work.namespace):
            raise AuthorityUnavailable('actual Authority graph object column/namespace/revision required')
        require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
        if attachment.table not in('graph_atoms','graph_history')or attachment.key[0]!=key.token:
            raise AuthorityUnavailable('Authority graph canonical object crossed its actual table/PK')
        row=dict(zip(attachment.columns,attachment.row))
        actual_revision=(row['revision']if attachment.table=='graph_atoms'else attachment.key[1])
        if(actual_revision,bool(row['valid']))!=(revision,valid):
            raise AuthorityUnavailable('Authority graph canonical object differs from actual revision/validity')
        column=attachment.json_columns.get('value')
        if column is None or not column.complete or column.owner is not work:
            raise AuthorityUnavailable('Authority graph object lacks complete actual column EOF')
        work.operation.retain(_container_bytes_v3(value)+1024)
        if _freeze_value_v3(value)!=column._frozen_value:
            raise AuthorityUnavailable('Authority graph object differs from its full canonical column')
        self.work,self.attachment,self.column=work,attachment,column
        self.key,self.revision,self.valid,self.value=key,revision,valid,value
        self.column_original=_COLUMNS.get(column)
        self.metadata=attachment.metadata
        _AUTHORITY_GRAPH_VALUES_V3[self]=(work,attachment,column,key,revision,valid,value,
            self.column_original,self.metadata,work.operation,work.scope)
        _track_authority_capability_v3(work,_AUTHORITY_GRAPH_VALUES_V3,self)
    def require_value_v3(self,*,key,revision,valid,value):
        if getattr(self,'source_material',None)is not None:
            material=self.source_material;work=material.work
            if (_AUTHORITY_GRAPH_VALUES_V3.get(self)!=(work,material,self.key,self.revision,self.valid,self.value)
                    or(key,revision,valid)!=(self.key,self.revision,self.valid)or value is not self.value):
                raise AuthorityUnavailable('Authority Source graph object lost its actual canonical material')
            material.selection.require_v3(work)
            record=material.source_records[self.key.token]
            witness=material.witnesses[self.key.token].require_current_v3()
            if (set(value)!=set(witness.metadata)|{'text'}or value.get('text') is not record.text
                    or (revision,valid)!=(witness.revision,witness.valid)):
                raise AuthorityUnavailable('Authority Source graph object differs from its actual text/header EOF')
            for name,expected in witness.metadata.items():
                actual=value.get(name)
                if type(actual)is list:actual=tuple(actual)
                if actual!=expected:raise AuthorityUnavailable('Authority Source metadata differs from its actual body EOF')
            return value
        from ..runtime.dispatch_initial_source_read_v3 import _COLUMNS
        from ..runtime.dispatch_current_inventory_v3 import _freeze_value_v3
        work=require_actual_authority_graph_attachment_owner_v3(self.work,db=self.work.db)
        if (_AUTHORITY_GRAPH_VALUES_V3.get(self)!=(work,self.attachment,self.column,self.key,self.revision,
                self.valid,self.value,self.column_original,self.metadata,work.operation,work.scope)
                or(key,revision,valid)!=(self.key,self.revision,self.valid)or value is not self.value
                or self.attachment.metadata!=self.metadata or self.attachment.json_columns.get('value')is not self.column
                or _COLUMNS.get(self.column)!=self.column_original or not self.column.complete
                or _freeze_value_v3(value)!=self.column._frozen_value):
            raise AuthorityUnavailable('Authority graph object changed its exact original/Work/JSON value')
        return self.column.require_v3(work)


def require_authority_graph_atom_json_v3(original,*,key,revision,valid,value):
    if type(original)is not PreparedAuthorityGraphValueOriginalV3 or original not in _AUTHORITY_GRAPH_VALUES_V3:
        raise TypeError('exact Authority canonical graph object proof required')
    return original.require_value_v3(key=key,revision=revision,valid=valid,value=value)


def prepare_authority_graph_value_original_v3(work,*,attachment,key,revision,valid,value):
    return PreparedAuthorityGraphValueOriginalV3(_ISSUER,work,attachment,key,revision,valid,value)


from ..runtime.dispatch_current_inventory_v3 import _CurrentNamespaceInventoryKernelV3

_AUTHORITY_SOURCES_V3=WeakKeyDictionary()


class VerifiedAuthoritySourceMetadataV3:
    def __init__(self,issuer,reader,key,revision,valid,cell,header,digest,metadata,canonical_semantic_digest):
        from types import MappingProxyType
        if issuer is not _ISSUER or type(reader)is not _AuthorityNamespaceReadV3 or not reader.work.graph_stamp:
            raise TypeError('actual Authority Source canonical EOF producer required')
        reader.work._actual()
        self.source_key,self.key,self.revision,self.valid=key,key,revision,valid
        self.cell_id,self.header,self.payload_sha256=cell,tuple(header),digest
        self.canonical_semantic_digest=canonical_semantic_digest
        self.byte_count=header[3]
        self.metadata=MappingProxyType({name:tuple(value)if type(value)is list else value for name,value in metadata.items()})
        self.scope,self.graph_stamp,self.query=reader.work.scope,reader.work.graph_stamp,reader.query
        self.operation_id,self.selection_digest=reader.work.operation.operation_id,reader.work.selection_digest
        self.work=reader.work
        _AUTHORITY_SOURCES_V3[self]=self._identity_v3()
    def _identity_v3(self):
        return(self.work,self.source_key,self.revision,self.valid,self.cell_id,self.header,self.payload_sha256,
            self.metadata,self.scope,self.graph_stamp,self.query,self.operation_id,self.selection_digest,self.canonical_semantic_digest)
    def require_current_v3(self):
        if _AUTHORITY_SOURCES_V3.get(self)!=self._identity_v3():
            raise AuthorityUnavailable('actual Authority Source metadata original changed')
        self.work._actual()
        return self


class _AuthorityNamespaceReadV3(_CurrentNamespaceInventoryKernelV3):
    """Independent Authority census, with shared parsing and no Host issuance."""
    def __init__(self,work,*,catalogue,catalogue_hash):
        from ..graph_types import NamespaceEpoch
        from ..runtime.dispatch_current_inventory_v3 import _DISPATCH_TYPES
        from ..runtime.d11_types import _VALUE_TYPES
        require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
        self.work,self.db=work,work.db
        self.catalogue=catalogue
        self._initialize_storage_kernel_v3(work.operation,work,namespace=work.namespace,
            graph_stamp=(None,NamespaceEpoch(*work.namespace.as_tuple,work.graph_stamp[0])),catalogue_hash=catalogue_hash,
            projection_types=_DISPATCH_TYPES|frozenset(_VALUE_TYPES)|frozenset({'d08.natural_plan.v2'}),
            selected_tokens=frozenset(),census_schema='sylanne3.authority-namespace-census.v3',
            leaf_schema='sylanne3.authority-namespace-leaf.v3')
        self.authority_epochs=tuple(work.graph_stamp[1:])
        self.attachment=None
    def _next(self,meter):
        from ..graph_types import AtomKey
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
        from ..runtime.dispatch_current_inventory_v3 import _DispatchSourceStreamV3
        from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        row=meter.read_fixed_row(self.db,'graph_atoms',('token','revision','valid','type_name','value_cell_id'),
            'bot=? AND persona=? AND token>? ORDER BY token',(*self.namespace.as_tuple,self.cursor))
        if row is None:
            if self._epochs(meter)!=self.authority_epochs:raise AuthorityUnavailable('Authority Source rights changed before census EOF')
            self.graph_eof=True;self._graph_eof_v3();return
        token,revision,valid,type_name,cell=row;key=AtomKey.from_token(token)
        spec=self.catalogue.get(type_name)
        if (NamespaceId.from_key(key)!=self.namespace or key.type_name!=type_name or spec is None
                or key.owner.kind not in spec[0]or type(revision)is not int or revision<1 or valid not in(0,1)or cell is None):
            raise AuthorityUnavailable('Authority graph head differs from actual complete catalogue/namespace')
        self.cursor=token;self.pending=(key,revision,valid,type_name,cell)
        self.heads[token]=(revision,valid,cell)
        self.cell=begin_runtime_cell_read_v3(self.db,cell,erasure_owner_ref=token)
        codec=self.cell.header[0]
        if codec not in('canonical-json.ascii.v1','canonical-json.utf8.v1'):
            raise AuthorityUnavailable('Authority graph value has an unregistered canonical codec')
        self.parser=(_DispatchSourceStreamV3(self,key,valid,ensure_ascii=codec=='canonical-json.ascii.v1')
            if type_name=='memory.source'else C09CanonicalJSONStreamV2(ensure_ascii=codec=='canonical-json.ascii.v1'))
        self.body=None
        self.semantic_decoder=self.semantic_hash=None
        if type_name=='memory.source'and codec=='canonical-json.utf8.v1':
            import codecs
            from hashlib import sha256
            self.semantic_decoder=codecs.getincrementaldecoder('utf-8')('strict');self.semantic_hash=sha256()
    def _semantic_source_fragment_v3(self,fragment,meter,*,final=False):
        if self.semantic_decoder is None:return
        text=self.semantic_decoder.decode(fragment,final=final)
        parts=[]
        for char in text:
            point=ord(char)
            if point<127:parts.append(char)
            elif point<=65535:parts.append('\\u'+format(point,'04x'))
            else:
                point-=65536;parts.append('\\u'+format(55296+(point>>10),'04x')+'\\u'+format(56320+(point&1023),'04x'))
        encoded=''.join(parts).encode('ascii');meter.charge_encode(len(encoded));self.semantic_hash.update(encoded)
    def _cell(self,meter):
        from ..runtime_contracts import canonical_digest
        if self.offset<len(self.fragment):
            end=min(self.offset+1024,len(self.fragment));self._reserve(65536)
            fragment=self.fragment[self.offset:end]
            self.parser.feed(fragment,lambda event:None);self._semantic_source_fragment_v3(fragment,meter)
            self.offset=end;return
        fragment=self.cell.read_fragment(meter=meter)
        if fragment is not None:self.fragment,self.offset=fragment,0;return
        parsed=self.parser.finish();digest=self.cell.finish(meter=meter)
        if(parsed.byte_count,parsed.sha256)!=(self.cell.header[3],digest):
            raise AuthorityUnavailable('Authority graph canonical/header/full EOF differs')
        key,revision,valid,type_name,cell=self.pending
        self.root=canonical_digest((self.leaf_schema,self.root,key.token,revision,valid,type_name,digest,cell,tuple(self.cell.header)))
        self.count+=1
        if type_name=='memory.source'and not self.parser.erased:
            metadata=self.parser._source_metadata
            if metadata['source_id']!=key.owner.subject or key.name!='record':
                raise AuthorityUnavailable('Authority Source identity differs from actual canonical full EOF')
            self._reserve(65536)
            self._semantic_source_fragment_v3(b'',meter,final=True)
            semantic=digest if self.semantic_hash is None else self.semantic_hash.hexdigest()
            self.sources[key.token]=VerifiedAuthoritySourceMetadataV3(_ISSUER,self,key,revision,bool(valid),cell,
                self.cell.header,digest,metadata,semantic)
        elif type_name in self.projection_types:
            from ..runtime.natural_producer_qualification_v1 import _HostProducerAttachmentV3
            request=('graph_atoms',('revision','value','valid'),('token','bot','persona'),(key.token,*self.namespace.as_tuple))
            self.attachment=_HostProducerAttachmentV3(self.work,request)
        self.cell,self.parser,self.pending=None,None,None
        self.fragment,self.offset=b'',0
    def _graph_eof_v3(self):
        self.work.sources.update(self.sources)
        self.work.heads=dict(self.heads)
    def advance_v3(self,meter):
        self.work.require_current(meter=meter)
        if self.attachment is not None:
            self.attachment.advance(meter)
            if self.attachment.complete:
                self.work.attachments[self.attachment.request]=self.attachment
                _adopt_authority_atom_attachment_v3(self.work,self.attachment)
                self.attachment=None
            return
        if self.cell is None:self._next(meter)
        else:self._cell(meter)


class _AuthorityCatalogueReadV3:
    def __init__(self,work):
        self.work=work;self.phase='catalogue';self.after='';self.rows={};self.authorities={}
        self.complete=False;self.comparison=None
    def advance_v3(self,meter):
        import json
        work=self.work
        work.require_current(meter=meter)
        if self.phase=='catalogue':
            row=meter.read_fixed_row(work.db,'graph_type_catalog',('name','owner_kinds','storage_role','immutable','schema_version'),
                'name>? ORDER BY name',(self.after,))
            if row is None:self.phase='authority';self.after='';return
            self.after=row[0];owners=json.loads(row[1])
            if type(owners)is not list or not owners or any(type(owner)is not str for owner in owners):
                raise AuthorityUnavailable('Authority actual catalogue owner kinds differ')
            self.rows[row[0]]=(tuple(owners),row[2],bool(row[3]),row[4]);work.operation.retain(1024)
        elif self.phase=='authority':
            row=meter.read_fixed_row(work.db,'graph_type_authority',('name','writer_domain','schema_hash'),
                'name>? ORDER BY name',(self.after,))
            if row is None:
                if not self.rows or set(self.rows)!=set(self.authorities):
                    raise AuthorityUnavailable('Authority catalogue and writer family are not complete 1:1 EOF')
                from ..runtime.natural_frozen_original_read_v3 import _CanonicalComparisonV3
                material=[[name,list(value[0]),value[1],value[2],value[3],self.authorities[name][0]or None,
                    self.authorities[name][1]or None]for name,value in sorted(self.rows.items())]
                self.comparison=_CanonicalComparisonV3(material,operation=work.operation)
                self.phase='hash';return
            self.after=row[0];self.authorities[row[0]]=row[1:];work.operation.retain(1024)
        elif self.phase=='hash':
            if self.comparison.advance(meter):
                self.catalogue_hash=self.comparison.digest
                from ..runtime.graph_catalogue_upgrade_v1 import (TARGET_164_V1,registered_source_v1)
                if self.catalogue_hash!=TARGET_164_V1.catalogue_hash:
                    registered_source_v1(self.catalogue_hash)
                self.complete=True
        else:raise AuthorityUnavailable('unregistered Authority catalogue phase')


_AUTHORITY_PROJECTIONS_V3=WeakKeyDictionary()


class AuthorityGraphProjectionV3:
    """An explicit typed projection backed by this Authority namespace's census."""
    def __init__(self,issuer,work):
        from ..graph_types import AtomKey,GraphAtom,NamespaceEpoch
        if issuer is not _ISSUER or not work.namespace_reader.graph_eof:
            raise TypeError('actual complete Authority namespace census required')
        work._actual();self.work,self.namespace=work,work.namespace
        self.epochs=(NamespaceEpoch(*work.namespace.as_tuple,work.graph_stamp[0]),)
        self.members=work.members
        _AUTHORITY_PROJECTIONS_V3[self]=(work,work.operation,work.scope,work.selection_digest,self.epochs,self.members)
        _track_authority_capability_v3(work,_AUTHORITY_PROJECTIONS_V3,self)
    def require_current_v3(self):
        if _AUTHORITY_PROJECTIONS_V3.get(self)!=(self.work,self.work.operation,self.work.scope,
                self.work.selection_digest,self.epochs,self.members):
            raise AuthorityUnavailable('Authority typed projection lost its actual census/Work')
        self.work._actual();return self
    def get(self,key):
        self.require_current_v3()
        from ..graph_types import GraphAtom
        if NamespaceId.from_key(key)!=self.namespace:raise AuthorityUnavailable('Authority projection crossed namespace')
        if key in self.members:return self.members[key]
        if key.type_name=='memory.source':
            return require_authority_expression_source_atom_v3(self.work,key.token)
        if key.token not in self.work.heads:return GraphAtom(key,0,{},False)
        request=('graph_atoms',('revision','value','valid'),('token','bot','persona'),(key.token,*self.namespace.as_tuple))
        if self.work.complete:raise AuthorityUnavailable('Authority final requested a value outside its prepared family')
        raise AuthorityGraphAttachmentRequiredV3(request)
    @property
    def atoms(self):
        self.require_current_v3();return tuple(self.members.values())
    @property
    def versions(self):
        from ..graph_types import GraphVersion
        values=tuple(GraphVersion(atom.key,atom.revision)for atom in self.atoms)
        material=self.work.source_material
        if type(material)is PreparedAuthoritySourceMaterialV3:
            material.selection.require_v3(self.work);values=tuple(dict.fromkeys((*values,*material.rights_versions)))
        return values
    def atoms_for(self,type_names):
        return tuple(atom for atom in self.atoms if atom.key.type_name in type_names)


def require_bound_authority_graph_read_v3(db,namespace,*,prepared=None):
    actual=_BOUND.get()
    if actual is None:return None
    if type(actual)is not PreparedAuthorityGraphReadV3 or actual not in _PREPARED:
        raise AuthorityUnavailable('exact independently issued Authority read binding required')
    if actual.db is not db or actual.work.namespace!=namespace or prepared is not None and prepared is not actual:
        raise AuthorityUnavailable('Authority read binding crossed its actual DB/request/namespace')
    with runtime_storage_quantum_v3(db)as meter:
        actual.require_current_v3(service=actual.service,db=db,meter=meter)
    return actual


def authority_graph_projection_for_db_v3(db,namespace):
    owner=_authority_attachment_owner_v3(db)
    if owner is None:return None
    if owner.namespace!=namespace or getattr(owner,'projection',None)is None:
        raise AuthorityUnavailable('Authority namespace projection has not reached actual full EOF')
    return owner.projection.require_current_v3()



def _adopt_authority_atom_attachment_v3(work,attachment):
    from ..graph_types import AtomKey,GraphAtom
    if attachment.table!='graph_atoms'or attachment.row is None:return
    data=dict(zip(attachment.columns,attachment.row))
    if not {'revision','value','valid'}<=set(data):return
    key=AtomKey.from_token(attachment.key[0]);value=attachment.json_columns['value'].require_v3(work)
    original=prepare_authority_graph_value_original_v3(work,attachment=attachment,key=key,
        revision=data['revision'],valid=bool(data['valid']),value=value)
    work.members[key]=GraphAtom(key,data['revision'],value,bool(data['valid']),_canonical_original=original)


_AUTHORITY_SOURCE_SELECTIONS_V3=WeakKeyDictionary()
_AUTHORITY_SOURCE_MATERIALS_V3=WeakKeyDictionary()


class _AuthoritySourceSelectionV3:
    def __init__(self,issuer,work,root,audience,attention,producer_roots):
        if issuer is not _ISSUER:raise TypeError('actual Authority source-selection producer required')
        work._actual()
        self.work,self.root,self.audience,self.attention=work,root,audience,attention
        self.purpose='expression';self.maximum_ancestors=256
        self.roots=tuple(dict.fromkeys((root,*producer_roots)))
        _AUTHORITY_SOURCE_SELECTIONS_V3[self]=(work,root,audience,attention,self.roots,work.operation,work.scope)
        _track_authority_capability_v3(work,_AUTHORITY_SOURCE_SELECTIONS_V3,self)
    def require_v3(self,work):
        if (_AUTHORITY_SOURCE_SELECTIONS_V3.get(self)!=(self.work,self.root,self.audience,self.attention,self.roots,
                self.work.operation,self.work.scope)or work is not self.work):
            raise AuthorityUnavailable('Authority Source selection changed its actual entry/Work')
        work._actual();return self


def _resolve_authority_source_selection_v3(work,meter):
    from ..graph_types import AtomKey
    from ..memory_types import source_key
    from ..domains.d07 import _qualify_focus_attention_values_v3
    ns=work.namespace;parent=work.parent_original_id
    rows=work.db.execute('SELECT source_ref FROM graph_d07_attention_issuance_v1 WHERE bot=? AND persona=? AND c02_operation_id=? LIMIT 2',
        (*ns.as_tuple,parent)).fetchall()
    meter.charge_read(sum(len(row[0].encode('utf8'))for row in rows)+32)
    if len(rows)!=1:raise AuthorityUnavailable('Authority C02 has no unique actual D07 Source original')
    root=rows[0][0];key=AtomKey.from_token(root)
    if key!=source_key(*ns.as_tuple,key.owner.subject or ''):
        raise AuthorityUnavailable('Authority original D07 Source locator is not canonical')
    original=work.originals.get((parent,'generation'))
    if original is not None and original.saved is not None and original.saved.seal.source_ref!=root:
        raise AuthorityUnavailable('Authority generation and C02 Source originals differ')
    requested=getattr(work.request,'source_ref',None)
    if requested is not None and requested!=root:
        raise AuthorityUnavailable('Authority current read differs from actual C02 Source original')
    ingress=work.db.execute('SELECT conversation_ref FROM graph_first_ingress_identity_v1 WHERE bot=? AND persona=? AND source_ref=? LIMIT 2',
        (*ns.as_tuple,key.owner.subject)).fetchall()
    meter.charge_read(sum(len(row[0].encode('utf8'))for row in ingress)+32)
    if len(ingress)!=1:raise AuthorityUnavailable('Authority Source has no unique actual ingress audience')
    def source_metadata(source):
        witness=work.sources.get(source.token)
        if witness is None:return None
        return witness.require_current_v3()
    attention=_qualify_focus_attention_values_v3(work.projection,ns,now=work.now_utc,source_reader=source_metadata)
    if attention is None:
        raise AuthorityUnavailable('Authority current D07 focus/ticket differs from its actual C02 Source')
    if work.model_context:
        if root not in attention.ticket.source_refs or set(attention.ticket.source_refs)!=set(part.ref.ref for part in work.context_original.saved.frozen_request.input.evidence):
            raise AuthorityUnavailable('Authority ContextReply D07 Source roots differ from its actual original evidence')
    elif attention.ticket.source_refs!=(root,):
        raise AuthorityUnavailable('Authority current D07 Source differs from its actual C02 original')
    roots=tuple(work.producer_roots)
    return _AuthoritySourceSelectionV3(_ISSUER,work,root,ingress[0][0],attention,roots)


class PreparedAuthoritySourceMaterialV3:
    """Authority's independent current Source family and actual root texts."""
    def __init__(self,issuer,reader):
        from types import MappingProxyType
        if issuer is not _ISSUER or not reader.complete:
            raise TypeError('actual completed Authority Source material producer required')
        reader.selection.require_v3(reader.work)
        self.work,self.selection=reader.work,reader.selection
        self.namespace,self.operation,self.scope=reader.work.namespace,reader.work.operation,reader.work.scope
        self.source_ref,self.audiences=reader.selection.root,(reader.selection.audience,)
        self.source_records=MappingProxyType(dict(reader.records))
        self.witnesses=MappingProxyType(dict(reader.witnesses))
        self.metadata_records=MappingProxyType(dict(reader.metadata_records))
        self.rights_versions=tuple(reader.versions);self.attention_refs=frozenset(reader.attention_refs)
        self.attention=reader.selection.attention
        _AUTHORITY_SOURCE_MATERIALS_V3[self]=self._identity_v3()
    def _identity_v3(self):
        return(self.work,self.selection,self.namespace,self.operation,self.scope,self.source_ref,self.audiences,
            self.source_records,self.witnesses,self.metadata_records,self.rights_versions,self.attention_refs,self.attention)
    def require_current(self,*,db,prepared_full_read,namespace,source_ref,audiences,purpose='expression'):
        if prepared_full_read is None:
            return self.require_preparation_v3(db=db,namespace=namespace,source_ref=source_ref,
                audiences=audiences,purpose=purpose)
        if (_AUTHORITY_SOURCE_MATERIALS_V3.get(self)!=self._identity_v3()or type(prepared_full_read)is not PreparedAuthorityGraphReadV3
                or prepared_full_read.work is not self.work or db is not self.work.db or namespace!=self.namespace
                or source_ref not in self.source_records or tuple(audiences)!=self.audiences or purpose!='expression'
                or not _is_actual_authority_source_material_v3(self.work,self) or not db.in_transaction):
            raise AuthorityUnavailable('Authority Source body belongs to another request/purpose/audience/Work')
        actual=require_bound_authority_graph_read_v3(db,namespace,prepared=prepared_full_read)
        if actual is not prepared_full_read:raise AuthorityUnavailable('Authority Source body lacks its actual final binding')
        self.selection.require_v3(self.work)
        for witness in self.witnesses.values():witness.require_current_v3()
        return self
    def require_preparation_v3(self,*,db,namespace,source_ref,audiences,purpose='expression'):
        work=self.work
        if (_AUTHORITY_SOURCE_MATERIALS_V3.get(self)!=self._identity_v3()
                or _READING.get() is not work or work.complete or work.phase not in
                    ('producer_local','counter_plan','counter_material','counter_digest','history_local','history_current','history_materials','validate')
                or db is not work.db or not db.in_transaction or namespace!=self.namespace
                or source_ref not in self.source_records or tuple(audiences)!=self.audiences
                or purpose!='expression' or not _is_actual_authority_source_material_v3(work,self)):
            raise AuthorityUnavailable('Authority preparation Source is outside its actual selected family/phase/purpose')
        work._actual();self.selection.require_v3(work)
        for witness in self.witnesses.values():witness.require_current_v3()
        return self
    def source_record_for_v3(self,*,db,prepared_full_read,namespace,source_ref,audiences,purpose='expression'):
        self.require_current(db=db,prepared_full_read=prepared_full_read,namespace=namespace,source_ref=source_ref,
            audiences=audiences,purpose=purpose)
        return self.source_records[source_ref]
    def source_family_for_v3(self,*,db,prepared_full_read,namespace,source_ref,audiences):
        self.require_current(db=db,prepared_full_read=prepared_full_read,namespace=namespace,source_ref=source_ref,audiences=audiences)
        from ..memory_types import source_key,access_key
        from ..domains.d06 import source_correction_head_key
        from ..graph_types import AtomKey,GraphVersion
        pending=[source_ref];done=set();lineage=[];versions=[]
        while pending:
            ref=pending.pop()
            if ref in done:continue
            done.add(ref);lineage.append(ref);key=AtomKey.from_token(ref)
            access=access_key(*namespace.as_tuple,key.owner.subject);head=source_correction_head_key(namespace,key.owner.subject)
            versions.extend((GraphVersion(key,self.witnesses[ref].revision),GraphVersion(access,self.work.projection.get(access).revision),GraphVersion(head,0)))
            pending.extend(source_key(*namespace.as_tuple,parent).token for parent in self.metadata_records[ref].parent_source_ids)
        return tuple(lineage),tuple(sorted(versions,key=lambda row:row.key.token))


class _AuthoritySourceMaterialReadV3:
    def __init__(self,work,selection):
        selection.require_v3(work)
        self.work,self.selection=work,selection
        self.phase='rights';self.pending=[(ref,getattr(selection,'assertion_required',False))for ref in selection.roots]+([]if selection.attention is None else[(ref,True)for ref in selection.attention.ticket.source_refs])
        self.witnesses={};self.metadata_records={};self.records={};self.attention_refs=set();self.versions=[]
        self.root_position=0;self.cell=self.parser=None;self.fragment=b'';self.offset=0
        self.complete=False;self.proof=None;self.reserved=0
    def _reserve_v3(self,extra=0):
        from ..runtime.source_correction_read_v3 import _heap
        amount=_heap((self.pending,self.witnesses,self.metadata_records,self.records,self.versions,self.fragment))+extra+65536
        if self.parser is not None:amount+=self.parser._source_heap_bytes()
        if amount>self.reserved:self.work.operation.retain(amount-self.reserved);self.reserved=amount
    def advance_v3(self,meter):
        from ..graph_types import AtomKey,GraphVersion
        from ..memory_types import source_key,access_key,SourceRecord
        from ..domains.d06 import source_correction_head_key
        work=self.work;ns=work.namespace
        work.require_current(meter=meter);self.selection.require_v3(work)
        if self.phase=='rights':
            if not self.pending:
                active=set();done=set()
                def visit(ref):
                    if ref in active:raise AuthorityUnavailable('Authority Source ancestry contains a cycle')
                    if ref in done:return
                    active.add(ref)
                    for parent in self.metadata_records[ref].parent_source_ids:visit(source_key(*ns.as_tuple,parent).token)
                    active.remove(ref);done.add(ref)
                for ref in self.witnesses:visit(ref)
                self.phase='cell';return
            ref,ticket_required=self.pending.pop()
            if ref in self.witnesses:
                if ticket_required and ref not in self.attention_refs:
                    record=self.metadata_records[ref]
                    if record.assertion_status not in {'confirmed','reported'}:
                        raise AuthorityUnavailable('Authority D07 ticket Source assertion status differs')
                    self.attention_refs.add(ref)
                    self.pending.extend((source_key(*ns.as_tuple,parent).token,True)for parent in record.parent_source_ids)
                return
            if len(self.witnesses)>=self.selection.maximum_ancestors:raise AuthorityUnavailable('Authority Source ancestry exceeds the original bound')
            key=AtomKey.from_token(ref);witness=work.sources.get(ref)
            if witness is None:raise AuthorityUnavailable('Authority Source family has no complete actual metadata original')
            witness.require_current_v3()
            access=access_key(*ns.as_tuple,key.owner.subject);head=source_correction_head_key(ns,key.owner.subject)
            access_atom=work.projection.get(access);correction=work.projection.get(head)
            from ..domains.d07.qualified_attention_read import _qualify_source_node_values_v3,_qualify_source_rights_values_v3
            qualifier=_qualify_source_node_values_v3 if ticket_required else _qualify_source_rights_values_v3
            record=qualifier(ns,ref,witness,access_atom,correction,audience=self.selection.audience,purpose=self.selection.purpose,metadata_only=True)
            if record is None:raise AuthorityUnavailable('Authority Source/ancestor access/correction/purpose/audience differs')
            self.witnesses[ref]=witness;self.metadata_records[ref]=record
            if ticket_required:self.attention_refs.add(ref)
            self.versions.extend((GraphVersion(key,witness.revision),GraphVersion(access,access_atom.revision),GraphVersion(head,0)))
            self.pending.extend((source_key(*ns.as_tuple,parent).token,ticket_required)for parent in record.parent_source_ids)
            self._reserve_v3();return
        if self.phase=='cell':
            if self.root_position==len(self.selection.roots):self.phase='seal';return
            ref=self.selection.roots[self.root_position];self.witness=self.witnesses[ref]
            from ..runtime_storage_v3 import RuntimeCellReadV3
            from ..runtime.current_graph_source_material_v3 import _SourceTextJSONStreamV3
            self.cell=RuntimeCellReadV3(work.handle,self.witness.cell_id,erasure_owner_ref=ref,meter=meter)
            if tuple(self.cell.header)!=self.witness.header:raise AuthorityUnavailable('Authority Source body changed its actual complete header')
            if self.cell.header[0]not in('canonical-json.ascii.v1','canonical-json.utf8.v1'):
                raise AuthorityUnavailable('Authority Source body codec is not registered canonical JSON')
            self.parser=_SourceTextJSONStreamV3(ensure_ascii=self.cell.header[0]=='canonical-json.ascii.v1')
            self.phase='body';return
        if self.phase=='body':
            if self.offset<len(self.fragment):
                end=min(self.offset+1024,len(self.fragment));self._reserve_v3(65536)
                self.parser.feed(self.fragment[self.offset:end],lambda event:None);self.offset=end;return
            fragment=self.cell.read_fragment(meter=meter)
            if fragment is not None:self.fragment,self.offset=fragment,0;return
            self.phase='eof';return
        if self.phase=='eof':
            self._reserve_v3(self.parser._source_text_characters*4+8192)
            parsed=self.parser.finish();digest=self.cell.finish(meter=meter)
            metadata={name:tuple(value)if type(value)is list else value for name,value in self.parser._source_metadata.items()}
            if(parsed.byte_count,parsed.sha256,digest)!=(self.cell.header[3],self.witness.payload_sha256,self.witness.payload_sha256)or metadata!=dict(self.witness.metadata):
                raise AuthorityUnavailable('Authority Source body canonical/whole SHA/EOF/metadata differs')
            self.records[self.selection.roots[self.root_position]]=SourceRecord.from_dict(dict(self.parser._source_metadata,text=self.parser.text))
            self.parser=self.cell=None;self.fragment=b'';self.offset=0;self.root_position+=1;self.phase='cell';self._reserve_v3();return
        if self.phase=='seal':
            self.selection.require_v3(work);self.complete=True
            self.proof=PreparedAuthoritySourceMaterialV3(_ISSUER,self);return
        raise AuthorityUnavailable('unregistered Authority Source material phase')



def require_current_authority_graph_read_work_v3(db,namespace,*,parent_original_id,frozen=None):
    owner=_authority_attachment_owner_v3(db)
    if owner is None:return None
    if owner.namespace!=namespace or getattr(owner,'parent_original_id',None)!=parent_original_id:
        raise AuthorityUnavailable('Authority continuation crossed its actual parent/namespace/DB')
    owner._actual()
    if frozen is not None:
        original=owner.originals.get((parent_original_id,'generation'))
        if original is None or original.saved is None or original.saved.frozen is not frozen:
            raise AuthorityUnavailable('Authority continuation frozen input is not its actual prepared generation original')
    return owner


def require_authority_prepared_generation_v3(work,*,parent_original_id):
    require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
    original=work.originals.get((parent_original_id,'generation'))
    if original is None or original.saved is None:
        raise AuthorityUnavailable('Authority generation original has not completed actual canonical EOF')
    from ..runtime.dispatch_initial_source_read_v3 import require_actual_authority_natural_original_v3
    require_actual_authority_natural_original_v3(original)
    if original.owner is not work or original.meta[0]!=parent_original_id or original.stage!='generation':
        raise AuthorityUnavailable('Authority generation original belongs to another actual Work/parent')
    return original.saved


def require_authority_source_material_preparation_v3(work,*,source_ref,audiences,purpose='expression'):
    """The replay preparer borrows only this Work's already qualified Source body."""
    require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
    material=work.source_material
    if type(material)is not PreparedAuthoritySourceMaterialV3:
        raise AuthorityUnavailable('Authority Source material has not completed its actual rights/body EOF')
    return material.require_preparation_v3(db=work.db,namespace=work.namespace,source_ref=source_ref,
        audiences=audiences,purpose=purpose)


def begin_authority_graph_read_work_v3(verifier,*,credential,subject,permit,namespace,request,
        parent_original_id,now_utc,deadline_utc):
    """Borrow the original call permit; this producer never claims or finishes it."""
    controller=require_authority_graph_read_controller_v3(verifier)
    if (type(parent_original_id)is not str or not parent_original_id
            or type(now_utc)not in(int,float)or not math.isfinite(now_utc)
            or(deadline_utc is None and controller.kind not in('generation','review'))
            or(deadline_utc is not None and(type(deadline_utc)not in(int,float)or not math.isfinite(deadline_utc)
                or now_utc>=deadline_utc))):
        raise AuthorityUnavailable('Authority read needs its original parent/clock/finite deadline')
    work=AuthorityGraphReadWorkV3(_ISSUER,controller,credential=credential,subject=subject,
        permit=permit,namespace=namespace,request=request,deadline_utc=deadline_utc)
    work.parent_original_id=parent_original_id;work.now_utc=float(now_utc)
    work.catalogue_reader=_AuthorityCatalogueReadV3(work)
    work.phase='bootstrap_generation'if deadline_utc is None else'catalogue'
    return work


def _prepare_authority_attachment_v3(work,request):
    from ..runtime.natural_producer_qualification_v1 import (_HostProducerAttachmentV3,
        _HostProducerMetadataScanV3,_HOST_ATTACHMENT_SHAPES_V3,_HOST_ATTACHMENT_SCANS_V3)
    if len(request)==4:
        if request==('runtime_resource_quotes',('quote_json','signature'),('quote_id','version'),request[3]):
            return _AuthoritySignedQuoteReadV3(work,request)
        if request[:3]not in _HOST_ATTACHMENT_SHAPES_V3:
            raise AuthorityUnavailable('Authority dependency is outside the fixed original inventory')
        if request[0]=='graph_atoms':
            from ..graph_types import AtomKey
            if AtomKey.from_token(request[3][0]).type_name=='memory.source':
                raise AuthorityUnavailable('Authority Source body requires its selected rights/material producer')
        return _HostProducerAttachmentV3(work,request)
    if len(request)==5 and (request[0],request[1],request[2],request[4])in _HOST_ATTACHMENT_SCANS_V3:
        return _HostProducerMetadataScanV3(work,request)
    raise AuthorityUnavailable('Authority dependency is not a registered fixed original family')


def _advance_authority_local_materials_v3(work,meter):
    work.require_current(meter=meter)
    if work.collection_source_reader is not None:
        reader=work.collection_source_reader;reader.advance_v3(meter)
        if reader.complete:
            work.collection_source_materials[reader.selection.root]=reader.proof
            work.collection_source_reader=None
        return
    if work.pending is not None:
        attachment=work.pending;attachment.advance(meter)
        if attachment.complete:
            work.attachments[attachment.request]=attachment
            _adopt_authority_atom_attachment_v3(work,attachment);work.pending=None
        return
    if work.phase=='model_entry':
        from ..runtime.jobs import get_job
        job=get_job(work.db,work.request.job_id)
        if(job.bot_id,job.persona_id)!=work.namespace.as_tuple:
            raise AuthorityUnavailable('Authority model job changed actual namespace')
        if job.work_kind in('natural_generation','natural_review'):
            table='graph_natural_generation_preparations_v2'if job.work_kind=='natural_generation'else'graph_natural_review_preparations_v2'
            rows=work.db.execute('SELECT parent_original_id FROM '+table+' WHERE bot=? AND persona=? AND job_id=? LIMIT 2',
                (*work.namespace.as_tuple,job.job_id)).fetchall()
            meter.charge_read(sum(len(row[0].encode('utf-8'))for row in rows)+32)
            if len(rows)!=1:raise AuthorityUnavailable('Authority model lost its unique actual sealed natural parent')
            work.parent_original_id=rows[0][0];work.model_natural=True
        else:
            work.parent_original_id=job.continuation.get('c02_operation_id')
            work.model_natural=False
            work.model_reply=job.work_kind in('reply','context_reply')and type(work.parent_original_id)is str
            work.model_context=job.work_kind=='context_reply'
            if work.model_context:
                rows=work.db.execute('SELECT c02_operation_id,source_ref FROM graph_context_reply_preparations_v2 '
                    'WHERE bot=? AND persona=? AND job_id=? LIMIT 2',(*work.namespace.as_tuple,job.job_id)).fetchall()
                meter.charge_read(sum(len(value.encode('utf-8'))for row in rows for value in row)+32)
                if len(rows)!=1:raise AuthorityUnavailable('Authority ContextReply job has no unique actual original')
                work.parent_original_id=rows[0][0];work.context_locator=tuple(rows[0])
        work.phase='context_original'if work.model_context else'catalogue';return
    if work.phase=='context_original':
        if work.context_original_reader is None:work.context_original_reader=_AuthorityContextOriginalReadV3(work)
        work.context_original_reader.advance(meter)
        if work.context_original_reader.complete:
            work.context_original=work.context_original_reader;work.phase='context_call'
        return
    if work.phase=='context_call':
        if work.context_call_reader is None:work.context_call_reader=_AuthorityContextCallReadV3(work)
        work.context_call_reader.advance(meter)
        if work.context_call_reader.complete:work.phase='catalogue'
        return
    if work.phase=='catalogue':
        work.catalogue_reader.advance_v3(meter)
        if work.catalogue_reader.complete:
            work.namespace_reader=_AuthorityNamespaceReadV3(work,catalogue=work.catalogue_reader.rows,
                catalogue_hash=work.catalogue_reader.catalogue_hash)
            work.phase='namespace'
        return
    if work.phase=='namespace':
        work.namespace_reader.advance_v3(meter)
        if work.namespace_reader.graph_eof:
            work.projection=AuthorityGraphProjectionV3(_ISSUER,work)
            if work.controller.kind=='model'and not work.model_natural:
                work.phase='source_selection'if work.model_reply else'validate'
            else:work.phase='source_selection'if work.controller.kind=='counter'or(work.parent_original_id,'generation')in work.originals else'generation'
        return
    if work.phase in('bootstrap_generation','generation','review'):
        from ..runtime.dispatch_initial_source_read_v3 import (
            begin_authority_natural_saved_original_read_v3,begin_authority_natural_review_original_read_v3)
        bootstrap=work.phase=='bootstrap_generation';stage='generation'if bootstrap else work.phase
        if work.original_reader is None:
            work.original_reader=(begin_authority_natural_saved_original_read_v3(work,
                parent_original_id=work.parent_original_id)if stage=='generation'else
                begin_authority_natural_review_original_read_v3(work,parent_original_id=work.parent_original_id,
                    generation_original=work.originals[(work.parent_original_id,'generation')]))
        reader=work.original_reader;reader.advance(meter)
        if reader.complete:
            if reader.natural_values is not None:
                work.originals[(work.parent_original_id,stage)]=reader.natural_values
            work.original_reader=None
            if stage=='generation'and reader.natural_values is not None:
                frozen=reader.natural_values.saved.frozen
                if bootstrap:_pin_authority_generation_deadline_v3(work,reader.natural_values)
                work.producer_roots=tuple(dict.fromkeys(ref.ref for unit in frozen.input.plan.units for ref in unit.source_refs))
                work.phase='review'
            elif bootstrap:raise AuthorityUnavailable('Authority bootstrap has no actual saved generation deadline original')
            else:work.phase='catalogue'if work.namespace_reader is None else'source_selection'
        return
    if work.phase=='source_selection':
        work.source_selection=_resolve_authority_source_selection_v3(work,meter)
        work.source_reader=_AuthoritySourceMaterialReadV3(work,work.source_selection);work.phase='source'
        return
    if work.phase=='source':
        work.source_reader.advance_v3(meter)
        if work.source_reader.complete:
            work.source_material=work.source_reader.proof
            work.phase=('context_source'if work.model_context else'legacy_c02')if work.controller.kind=='model'and work.model_reply else'producer_local'
        return
    if work.phase=='context_source':
        if work.context_source_reader is None:
            work.context_source_selection=_AuthorityContextSourceSelectionV3(_ISSUER,work,work.context_original)
            work.context_source_reader=_AuthoritySourceMaterialReadV3(work,work.context_source_selection)
        work.context_source_reader.advance_v3(meter)
        if work.context_source_reader.complete:
            work.context_source_material=work.context_source_reader.proof;work.phase='legacy_c02'
        return
    if work.phase=='legacy_c02':
        if work.c02_bundle_reader is None:work.c02_bundle_reader=_AuthorityC02BundleReadV3(work)
        work.c02_bundle_reader.advance(meter)
        if work.c02_bundle_reader.complete:
            work.c02_bundle_original=work.c02_bundle_reader.proof;work.phase='validate'
        return
    if work.phase=='producer_local':
        from ..runtime.natural_producer_qualification_v1 import (
            frozen_natural_producer_selectors_v1,fresh_natural_producer_selectors_v1)
        original=work.originals.get((work.parent_original_id,'generation'))
        if work.controller.kind=='counter':
            selectors=fresh_natural_producer_selectors_v1(work.db,namespace=work.namespace,
                parent_original_id=work.parent_original_id,issuer=work.controller.service.observer.issuer)
            units=None
        elif original is not None:
            selectors=frozen_natural_producer_selectors_v1(work.db,namespace=work.namespace,frozen=original.saved.frozen)
            units=original.saved.frozen.input.plan.units
        else:work.phase='validate';return
        work.producer_inputs=(selectors,units);work.phase='producer_observations';return
    if work.phase=='counter_plan':
        work.controller.service._prepare_current_counter_work_v3(work,meter)
        work.phase='counter_material';return
    if work.phase=='counter_material':
        from ..runtime.installed_d13_natural_frame_v7 import begin_authority_initial_natural_history_pair_v7
        if work.counter_pair_reader is None:
            work.counter_pair_reader=begin_authority_initial_natural_history_pair_v7(work,counter_scope=work.counter_material_scope)
        work.counter_pair_reader.advance(meter=meter)
        if work.counter_pair_reader.complete:work.phase='counter_digest'
        return
    if work.phase=='counter_digest':
        if not work.counter_source_digest_reader.advance(meter):return
        from .d13_core_counter_source_v1 import D13CurrentCounterSourceV1
        from ..runtime_contracts import canonical_digest
        pair=work.counter_pair_reader.require_current_v7(work)
        work.counter_result=D13CurrentCounterSourceV1(work.counter_prospective,pair,work.counter_location,
            work.counter_current_self,work.counter_owner,canonical_digest(work.counter_owner_grant),
            work.counter_source_digest_reader.digest,work.counter_frozen_at_utc,pair.raw.input.expires_at_utc)
        work.phase='counter_events'if work.counter_call.draft is not None else'validate';return
    if work.phase=='counter_events':
        _prepare_authority_counter_event_read_v3(work,meter);return
    if work.phase=='history_local':
        original=work.originals.get((work.parent_original_id,'generation'))
        if original is None:work.phase='validate';return
        from .d13_natural_frame_verifier_v7 import (InstalledAuthorityD13NaturalFrameVerifierV7,
            begin_authority_same_batch_continuation_v7)
        issuer=getattr(work.controller.verifier,'_natural_history',None)
        if type(issuer)is not InstalledAuthorityD13NaturalFrameVerifierV7:
            raise AuthorityUnavailable('Authority segmented natural replay requires its installed V7 issuer')
        if work.history_continuation is None:
            work.history_continuation=begin_authority_same_batch_continuation_v7(work,
                frozen=original.saved.frozen,parent_original_id=work.parent_original_id)
        continuation=work.history_continuation
        continuation.advance(meter=meter)
        if continuation.complete:work.phase='history_current'
        elif continuation.phase=='observations':work.phase='history_observations'
        return
    if work.phase=='history_current':
        from ..runtime.installed_d13_natural_frame_v7 import begin_authority_current_natural_frame_v7
        original=work.originals[(work.parent_original_id,'generation')]
        if work.history_current_reader is None:
            work.history_current_reader=begin_authority_current_natural_frame_v7(work,
                issuer=work.controller.verifier._natural_history,frozen=original.saved.frozen,
                parent_original_id=work.parent_original_id,now_utc=work.now_utc,
                same_batch_prepared=work.history_continuation.prepared)
        reader=work.history_current_reader;reader.advance(meter=meter)
        if reader.complete:work.history_current=reader.prepared;work.phase='validate'
        return
    if work.phase!='validate':raise AuthorityUnavailable('unregistered Authority local preparation phase')


def advance_authority_graph_read_work_v3(work):
    """One cursor or fragment per call; Core observations never share Graph SQL."""
    require_actual_authority_graph_attachment_owner_v3(work)
    if work.failure is not None:raise work.failure
    if work.complete:return work.prepared
    try:
        if work.phase=='producer_observations':
            _observe_authority_producer_context_v3(work)
            work.phase='counter_plan'if work.controller.kind=='counter'else'history_local'
        elif work.phase=='history_observations':
            if work.db.in_transaction:raise AuthorityUnavailable('Authority observation inherited Graph SQL')
            work.history_continuation.advance(meter=None)
            work.phase='history_current'
        else:
            with work.quantum_v3()as meter:
                with bind_authority_graph_original_preparation_v3(work):
                    try:_advance_authority_local_materials_v3(work,meter)
                    except AuthorityGraphAttachmentRequiredV3 as required:
                        work.pending=_prepare_authority_attachment_v3(work,required.request)
                    except AuthorityCollectionSourceRequiredV6 as required:
                        required.selection.require_v3(work)
                        work.collection_source_reader=_AuthoritySourceMaterialReadV3(work,required.selection)
        return work
    except BaseException as error:
        if work.failure is None:work.failure=error
        raise


def require_authority_current_natural_frame_v7(work,*,issuer,frozen,parent_original_id,
        now_utc,same_batch_prepared):
    require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
    if (work.parent_original_id!=parent_original_id or work.controller.verifier._natural_history is not issuer
            or work.now_utc!=now_utc or work.history_current_reader is None):
        raise AuthorityUnavailable('Authority current frame belongs to another actual replay/clock')
    return work.history_current_reader.require_current_v7(issuer=issuer,frozen=frozen,
        parent_original_id=parent_original_id,now_utc=now_utc,same_batch_prepared=same_batch_prepared)


_AUTHORITY_COLLECTION_SELECTIONS_V6=WeakKeyDictionary()


class AuthorityCollectionSourceRequiredV6(Exception):
    def __init__(self,selection):
        self.selection=selection
        super().__init__('actual Authority record awaits its context Source rights/body EOF')


class _AuthorityCollectionSourceSelectionV6:
    def __init__(self,issuer,work,*,root,audience,binding,maximum_ancestors):
        if issuer is not _ISSUER or _READING.get()is not work or work.collection_record is None:
            raise AuthorityUnavailable('Authority context Source needs its actual current collection record')
        work._actual()
        self.work,self.root,self.audience,self.binding=work,root,audience,binding
        self.record=work.collection_record;self.roots=(root,);self.attention=None
        self.purpose='context';self.maximum_ancestors=maximum_ancestors
        _AUTHORITY_COLLECTION_SELECTIONS_V6[self]=(work,root,audience,binding,self.record,work.operation,work.scope)
        _track_authority_capability_v3(work,_AUTHORITY_COLLECTION_SELECTIONS_V6,self)
    def require_v3(self,work):
        if (_AUTHORITY_COLLECTION_SELECTIONS_V6.get(self)!=(self.work,self.root,self.audience,self.binding,
                self.record,work.operation,work.scope)or self.work is not work or work.collection_record is not self.record):
            raise AuthorityUnavailable('Authority context Source moved outside its proven current record')
        work._actual();return self


class _AuthorityRouteMetadataV6:
    def __init__(self,witness):
        self.witness=witness.require_current_v3()
        self.revision=self.witness.revision;self.metadata=self.witness.metadata
    def __getattr__(self,name):
        self.witness.require_current_v3()
        if name not in self.metadata:raise AttributeError(name)
        return self.metadata[name]


class AuthorityRouteMetadataInventoryV6:
    def __init__(self,work):
        from ..runtime_contracts import QueryEpoch
        require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
        self.record=work.collection_record
        self.expression=(self.record is None and type(work.source_material)is PreparedAuthoritySourceMaterialV3
            and work.controller.kind in('counter','model')and work.phase in('counter_plan','validate'))
        if _authority_attachment_owner_v3(work.db)is not work or self.record is None and not self.expression:
            raise AuthorityUnavailable('Authority route metadata is outside its actual current record/selected expression')
        self.work,self.namespace,self.projection=work,work.namespace,work.projection
        self.query=QueryEpoch(work.namespace,'all',work.graph_stamp[0])
    def require_current(self,db,namespace,query):
        if (db is not self.work.db or namespace!=self.namespace or query!=self.query
                or _authority_attachment_owner_v3(db)is not self.work or not db.in_transaction
                or self.record is not self.work.collection_record
                or self.expression and(type(self.work.source_material)is not PreparedAuthoritySourceMaterialV3
                    or self.work.phase not in('counter_plan','validate'))):
            raise AuthorityUnavailable('Authority route metadata crossed actual record/DB/namespace')
        self.work._actual();self.projection.require_current_v3();return self
    def source_metadata(self,db,namespace,query,key,*,require_grant=False):
        self.require_current(db,namespace,query)
        if self.expression and key.token not in self.work.source_material.witnesses:
            raise AuthorityUnavailable('Authority expression route Source is outside its actually qualified ancestry')
        witness=self.work.sources.get(key.token)
        if witness is None or not witness.valid:raise AuthorityUnavailable('Authority record Source metadata EOF absent')
        return _AuthorityRouteMetadataV6(witness)
    def atom_rows(self,db,namespace,query,type_names,columns):
        self.require_current(db,namespace,query)
        from ..graph_types import AtomKey
        if tuple(type_names)!=('d03.account_binding',)or tuple(columns)!=('token','revision','value'):
            raise AuthorityUnavailable('Authority route requested a different account-binding census family')
        result=[]
        for token,head in self.work.heads.items():
            key=AtomKey.from_token(token)
            if key.type_name=='d03.account_binding'and head[1]:
                atom=self.projection.get(key);result.append((token,atom.revision,atom.value))
        return tuple(sorted(result,key=lambda row:row[0]))


def require_authority_collection_source_v6(work,*,binding):
    from ..runtime.reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2
    require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
    record=work.collection_record
    if (type(binding)is not CurrentReplyEntityRouteBindingV2 or record is None
            or binding.namespace!=work.namespace or binding.c02_operation_id!=record['c02_operation_id']
            or binding.scene_ref!=record['scene_ref']or binding.conversation_ref!=record['conversation_ref']
            or binding.arrival_event_version.key.token!=record['slot'].value['origin_ref']):
        raise AuthorityUnavailable('Authority context Source lacks actual slot/route/C02 lineage')
    ref=binding.source_ref;witness=work.sources.get(ref)
    if witness is None or binding.source_version.revision!=witness.revision:
        raise AuthorityUnavailable('Authority record Source version differs from actual route metadata')
    material=work.collection_source_materials.get(ref)
    if material is not None and material.selection.record is record:
        material.selection.require_v3(work);return material
    selection=_AuthorityCollectionSourceSelectionV6(_ISSUER,work,root=ref,
        audience=binding.conversation_ref,binding=binding,maximum_ancestors=256)
    raise AuthorityCollectionSourceRequiredV6(selection)


def authority_collection_source_atom_v6(work,material,source_ref):
    from ..graph_types import AtomKey,GraphAtom
    require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
    if (type(material)is not PreparedAuthoritySourceMaterialV3
            or work.collection_source_materials.get(material.source_ref)is not material
            or source_ref not in material.source_records):
        raise AuthorityUnavailable('Authority window Source lacks its actual selected context material')
    material.selection.require_v3(work)
    key=AtomKey.from_token(source_ref);witness=material.witnesses[source_ref].require_current_v3()
    record=material.source_records[source_ref];value=record.to_dict()
    original=PreparedAuthorityGraphValueOriginalV3.__new__(PreparedAuthorityGraphValueOriginalV3)
    original.work,original.source_material=work,material
    original.key,original.revision,original.valid,original.value=key,witness.revision,witness.valid,value
    _AUTHORITY_GRAPH_VALUES_V3[original]=(work,material,key,witness.revision,witness.valid,value)
    _track_authority_capability_v3(work,_AUTHORITY_GRAPH_VALUES_V3,original)
    return GraphAtom(key,witness.revision,value,witness.valid,_canonical_original=original)


_AUTHORITY_JOB_COLUMNS_V3=WeakKeyDictionary()
_AUTHORITY_JOB_FIELDS_V3=('job_id','operation_id','activity_id','effect_id','bot_id','persona_id','snapshot_ref',
    'phase','work_kind','continuation_json','wake_condition_json','deadline_utc','budget_ref','resource_ref',
    'operator_versions_json','lease_holder','lease_expires_utc','fence','cancel_epoch','usage_json','result_ref')
_AUTHORITY_JOB_JSON_V3={'continuation_json':'continuation','wake_condition_json':'wake_condition',
    'operator_versions_json':'operator_versions','usage_json':'usage'}


class PreparedAuthorityJobColumnsV3:
    def __init__(self,issuer,work,attachment):
        from ..runtime.natural_producer_qualification_v1 import _HostProducerAttachmentV3
        from ..runtime.jobs import MAX_JSON_BYTES
        if (issuer is not _ISSUER or type(attachment)is not _HostProducerAttachmentV3
                or attachment.owner is not work or not attachment.complete or attachment.table!='runtime_jobs'
                or attachment.columns!=_AUTHORITY_JOB_FIELDS_V3 or attachment.row is None
                or work.attachments.get(attachment.request)is not attachment):
            raise AuthorityUnavailable('Authority job needs its actual complete fixed row/JSON originals')
        work._actual();self.work,self.attachment,self.row=work,attachment,attachment.row
        row=dict(zip(_AUTHORITY_JOB_FIELDS_V3,self.row))
        if (row['bot_id'],row['persona_id'])!=work.namespace.as_tuple:
            raise AuthorityUnavailable('Authority job crossed its actual namespace')
        self.values={}
        for column,field in _AUTHORITY_JOB_JSON_V3.items():
            proof=attachment.json_columns.get(column)
            if proof is None:
                if column!='wake_condition_json'or attachment.encoded.get(column)is not None:
                    raise AuthorityUnavailable('Authority job is missing a non-null original JSON column')
                self.values[field]=None
            else:
                if not proof.complete or proof.byte_count>MAX_JSON_BYTES:
                    raise AuthorityUnavailable('Authority original job JSON exceeds its original 64KiB bound')
                self.values[field]=proof.require_v3(work)
        _AUTHORITY_JOB_COLUMNS_V3[self]=(work,attachment,self.row,self.values,work.operation,work.scope)
        _track_authority_capability_v3(work,_AUTHORITY_JOB_COLUMNS_V3,self)
    def require_job_v3(self,job):
        work=self.work;work._actual()
        if (_AUTHORITY_JOB_COLUMNS_V3.get(self)!=(work,self.attachment,self.row,self.values,work.operation,work.scope)
                or work.attachments.get(self.attachment.request)is not self.attachment):
            raise AuthorityUnavailable('Authority job canonical row original changed its actual Work')
        row=dict(zip(_AUTHORITY_JOB_FIELDS_V3,self.row))
        for column in _AUTHORITY_JOB_FIELDS_V3:
            field=_AUTHORITY_JOB_JSON_V3.get(column,column)
            actual=getattr(job,field)
            if column in _AUTHORITY_JOB_JSON_V3:
                if actual is not self.values[field]:raise AuthorityUnavailable('Authority job JSON changed its canonical original')
            elif actual!=row[column]:raise AuthorityUnavailable('Authority job metadata changed its actual fixed row')
        return job


def require_authority_job_columns_v3(proof,job):
    if type(proof)is not PreparedAuthorityJobColumnsV3 or proof not in _AUTHORITY_JOB_COLUMNS_V3:
        raise TypeError('exact privately issued Authority job row/columns required')
    return proof.require_job_v3(job)


def read_bound_authority_job_v3(db,*,job_id):
    owner=_authority_attachment_owner_v3(db)
    if owner is None:return False,None
    request=('runtime_jobs',_AUTHORITY_JOB_FIELDS_V3,('job_id',),(job_id,))
    attachment=owner.attachments.get(request)
    if attachment is None:
        if owner.complete:raise AuthorityUnavailable('Authority final job was not read to complete row/JSON EOF')
        raise AuthorityGraphAttachmentRequiredV3(request)
    with runtime_storage_quantum_v3(db)as meter:row=attachment.require_row_v3(owner,meter)
    if row is None:
        from ..runtime.jobs import JobConflict
        raise JobConflict('job does not exist')
    proof=PreparedAuthorityJobColumnsV3(_ISSUER,owner,attachment)
    data=dict(zip(_AUTHORITY_JOB_FIELDS_V3,row))
    for column,field in _AUTHORITY_JOB_JSON_V3.items():data.pop(column);data[field]=proof.values[field]
    from ..runtime.jobs import PersistentJob
    return True,PersistentJob(**data,_canonical_columns=proof)


def _pin_authority_generation_deadline_v3(work,original):
    from ..runtime.dispatch_initial_source_read_v3 import require_actual_authority_natural_original_v3
    require_actual_authority_natural_original_v3(original)
    if (work.phase!='bootstrap_generation'or work.deadline_utc is not None
            or _DEADLINES.get(work)!=(work.operation,None,None)or original.owner is not work
            or original.stage!='generation'or original.saved is None
            or work.originals.get((work.parent_original_id,'generation'))is not original):
        raise AuthorityUnavailable('Authority original deadline can be pinned only at its first generation EOF')
    deadline=original.saved.frozen.input.expires_at_utc
    if type(deadline)not in(int,float)or not math.isfinite(deadline):
        raise AuthorityUnavailable('Authority original frozen expiry is not a finite contract deadline')
    work.deadline_utc=work.operation.deadline_utc=float(deadline);work.deadline_original=original
    _DEADLINES[work]=(work.operation,work.deadline_utc,original)
    now=work.controller.clock()
    if type(now)not in(int,float)or not math.isfinite(now)or now>=deadline:
        raise AuthorityUnavailable('Authority saved generation was already expired at complete original EOF')


_AUTHORITY_PAID_CANDIDATES_V6=WeakKeyDictionary()
_AUTHORITY_DERIVED_BLOB_V6=WeakKeyDictionary()


def _require_authority_collection_value_v6(work,selection):
    from ..runtime.d13_current_collection_v6 import PreparedAuthorityD13CollectionV6
    require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
    matches=[reader for reader in work.collection_readers if reader.complete and reader.collection is selection
        and type(reader.prepared)is PreparedAuthorityD13CollectionV6]
    if len(matches)!=1:raise AuthorityUnavailable('Authority paid materials need the actual same-Work collection original')
    matches[0].prepared.require_current_v6(work);return matches[0].prepared


class _AuthorityPaidCandidateRowsReadV6:
    def __init__(self,issuer,work,selection):
        if issuer is not _ISSUER:raise TypeError('actual fixed paid candidate census required')
        self.work,self.selection,self.collection_original=work,selection,_require_authority_collection_value_v6(work,selection)
        self.cursor=iter(work.heads);self.token=None;self.rows=[];self.complete=False
        _AUTHORITY_PAID_CANDIDATES_V6[self]=(work,selection,self.collection_original,work.operation,work.scope)
        _track_authority_capability_v3(work,_AUTHORITY_PAID_CANDIDATES_V6,self)
    def advance(self,meter):
        from ..domains.d13.derived_block_metadata_v2 import METADATA_TYPE
        from ..graph_types import AtomKey
        work=self.work;work.require_current(meter=meter);self.collection_original.require_current_v6(work)
        if self.complete:return self
        if self.token is None:
            try:self.token=next(self.cursor)
            except StopIteration:self.complete=True;self.rows=tuple(self.rows);return self
        token=self.token;key=AtomKey.from_token(token);head=work.heads[token]
        if key.type_name!=METADATA_TYPE or key.owner.kind!='persona'or not head[1]:self.token=None;return self
        atom=work.projection.get(key);value=atom.value
        expiries=value.get('turn_expiries');first=last=None
        if type(expiries)is list and expiries:
            first=expiries[0].get('sequence')if type(expiries[0])is dict else None
            last=expiries[-1].get('sequence')if type(expiries[-1])is dict else None
        lower=self.selection.pages[-1].first_sequence;upper=self.selection.window.order_watermark
        # JSON1 numbers compare numerically; non-null JSON text sorts after numbers.
        first_matches=(first is not None and(type(first)not in(int,float,bool)or first>=lower))
        last_matches=type(last)in(int,float,bool)and last<=upper
        if value.get('status')in('standby','active')and first_matches and last_matches:
            self.rows.append((token,atom.revision,value,last))
            self.rows.sort(key=lambda row:(-row[3],row[0]))
            if len(self.rows)>16:self.rows.pop()
            work.operation.retain(1024)
        self.token=None;return self
    def require_current_v6(self,work):
        if (_AUTHORITY_PAID_CANDIDATES_V6.get(self)!=(self.work,self.selection,self.collection_original,
                work.operation,work.scope)or self.work is not work or not self.complete):
            raise AuthorityUnavailable('Authority fixed paid candidates did not complete the actual filtered census EOF')
        self.collection_original.require_current_v6(work)
        return tuple(row[:3]for row in self.rows)


def begin_authority_paid_candidate_rows_read_v6(work,*,selection):
    previous=[reader for reader in work.paid_candidate_readers if reader.selection is selection]
    if previous:
        if len(previous)!=1:raise AuthorityUnavailable('Authority paid candidate continuation identity is ambiguous')
        return previous[0]
    reader=_AuthorityPaidCandidateRowsReadV6(_ISSUER,work,selection);work.paid_candidate_readers.append(reader);return reader


def require_authority_paid_candidate_rows_v6(work,*,selection):
    return begin_authority_paid_candidate_rows_read_v6(work,selection=selection).require_current_v6(work)


class _AuthorityDerivedBlobOriginalV6:
    def __init__(self,issuer,work,selection,metadata,metadata_ref):
        from ..domains.d13.derived_block_metadata_v2 import DerivedBlockMetadataV2,decode_derived_block_metadata_v2
        from ..runtime_contracts import VersionedRef
        if issuer is not _ISSUER or type(metadata)is not DerivedBlockMetadataV2 or type(metadata_ref)is not VersionedRef:
            raise TypeError('actual typed fixed-candidate derived body original required')
        reader=begin_authority_paid_candidate_rows_read_v6(work,selection=selection)
        rows=reader.require_current_v6(work)
        matches=[row for row in rows if(row[0],row[1])==(metadata_ref.ref,metadata_ref.version)]
        if len(matches)!=1 or decode_derived_block_metadata_v2(matches[0][2])!=metadata or metadata.namespace!=work.namespace:
            raise AuthorityUnavailable('Authority derived body is outside its actual filtered candidate/collection')
        self.work,self.reader,self.metadata,self.metadata_ref=work,reader,metadata,metadata_ref
        self.key=(*work.namespace.as_tuple,metadata.block_ref)
        self.sha256,self.byte_count=metadata.payload_digest,metadata.payload_length_bytes
        _AUTHORITY_DERIVED_BLOB_V6[self]=(work,reader,metadata,metadata_ref,self.key,self.sha256,self.byte_count,work.operation,work.scope)
        _track_authority_capability_v3(work,_AUTHORITY_DERIVED_BLOB_V6,self)
    def require_current_v6(self,owner,*,table,column,key_columns,key):
        if (_AUTHORITY_DERIVED_BLOB_V6.get(self)!=(self.work,self.reader,self.metadata,self.metadata_ref,
                self.key,self.sha256,self.byte_count,owner.operation,owner.scope)or owner is not self.work
                or(table,column,tuple(key_columns),tuple(key))!=('graph_d11_derived_cache_payloads_v1','payload_bytes',
                    ('bot','persona','block_ref'),self.key)):
            raise AuthorityUnavailable('Authority BLOB original crossed actual fixed table/column/PK/candidate')
        self.reader.require_current_v6(owner);return self


def begin_authority_derived_payload_read_v6(work,*,selection,metadata,metadata_ref):
    from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
    original=_AuthorityDerivedBlobOriginalV6(_ISSUER,work,selection,metadata,metadata_ref)
    return DispatchOriginalJSONReadV3(work,table='graph_d11_derived_cache_payloads_v1',column='payload_bytes',
        key_columns=('bot','persona','block_ref'),key=original.key,authority_blob_original=original)


def read_authority_graph_current_v3(work,read):
    """Drive material EOF on the original RPC thread, then repeat the original pure read."""
    require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
    if work.failure is not None:raise work.failure
    try:
        while work.phase!='validate':advance_authority_graph_read_work_v3(work)
        if work.complete and work.producer_inputs is not None:_observe_authority_producer_context_v3(work)
        while True:
            with work.quantum_v3()as meter:
                if work.complete:
                    with bind_prepared_authority_graph_read_v3(work.prepared,service=work.service,db=work.db,meter=meter):
                        return read(work.db)
                with bind_authority_graph_original_preparation_v3(work):
                    try:result=read(work.db)
                    except AuthorityGraphAttachmentRequiredV3 as required:
                        work.pending=_prepare_authority_attachment_v3(work,required.request)
                    else:
                        work.complete=True;work.prepared=PreparedAuthorityGraphReadV3(_ISSUER,work)
                        return result
            while work.pending is not None:advance_authority_graph_read_work_v3(work)
    except BaseException as error:
        if work.failure is None:work.failure=error
        raise


def finish_authority_graph_read_work_v3(work):
    if type(work)is not AuthorityGraphReadWorkV3:return
    first=work.failure
    try:work.release_v3()
    except BaseException:
        if first is None:raise


def require_authority_same_batch_hints_v7(work,*,parent_original_id,frozen):
    from ..runtime.dispatch_initial_source_read_v3 import require_actual_authority_natural_original_v3
    from ..domains.d09.natural_reply import natural_semantic_ranges_v3,natural_segment_identity_v3
    from ..domains.d09.turn_order import turn_order_key,validate_turn_order_v1
    require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
    if _READING.get()is not work or work.phase not in('history_local','history_current','validate'):
        raise AuthorityUnavailable('Authority V7 hints are outside the actual history preparation quantum')
    generation=work.originals.get((parent_original_id,'generation'))
    if generation is None:raise AuthorityUnavailable('Authority V7 generation original EOF is absent')
    require_actual_authority_natural_original_v3(generation)
    saved=generation.saved
    if saved is None or saved.frozen is not frozen or work.parent_original_id!=parent_original_id:
        raise AuthorityUnavailable('Authority V7 hints changed saved generation/frozen/parent identity')
    if saved.seal.schema!='sylanne.d09.natural_generation_seal.v7':return None
    review=work.originals.get((parent_original_id,'review'))
    if review is None:return None
    require_actual_authority_natural_original_v3(review)
    if review.saved is None or review.saved.state!='terminal':return None
    canonical=review.frozen_eof
    if type(canonical)is not PreparedAuthorityReviewCanonicalV3 or not canonical.complete:
        raise AuthorityUnavailable('Authority V7 review output canonical whole EOF is absent')
    canonical._actual_v3();output=canonical.output
    # output_digest is the original review DTO SHA field; the bare whole-output SHA is its own completed comparison.
    if canonical.output_digest!='sha256:'+saved.terminal_output_digest:
        raise AuthorityUnavailable('Authority same-batch whole paid output differs from generation terminal original')
    count=len(natural_semantic_ranges_v3(output));plan=frozen.input.plan
    order=work.projection.get(turn_order_key(work.namespace,plan.scene_id,plan.audience_id))
    if not order.valid:raise AuthorityUnavailable('Authority same-batch current order is absent')
    validate_turn_order_v1(order.value)
    suffix=order.value['high_watermark']-frozen.input.history_selection.order_watermark
    if not 0<=suffix<=count<=4:raise AuthorityUnavailable('Authority same-batch suffix exceeds the complete manifest')
    return frozen,output,tuple(natural_segment_identity_v3(plan,output,index)[:2]for index in range(suffix)),generation.columns['frozen_json'].sha256


def require_authority_expression_projection_v3(material,*,db,prepared,namespace,source_ref,audiences):
    if type(material)is not PreparedAuthoritySourceMaterialV3 or material not in _AUTHORITY_SOURCE_MATERIALS_V3:
        raise TypeError('exact independently issued Authority expression Source material required')
    material.require_current(db=db,prepared_full_read=prepared,namespace=namespace,source_ref=source_ref,
        audiences=audiences,purpose='expression')
    return material.work.projection


def authority_source_expression_kwargs_v3(db,namespace):
    work=_authority_attachment_owner_v3(db)
    if work is None:return None
    if work.namespace!=namespace or work.source_material is None:
        raise AuthorityUnavailable('Authority expression Source material is outside its actual namespace/EOF')
    prepared=_BOUND.get()
    return {'prepared_source_material':work.source_material,'prepared_full_read':prepared,'db':db}


def _observe_authority_producer_context_v3(work):
    from contextlib import ExitStack
    from ..runtime.natural_producer_qualification_v1 import observe_authority_natural_producers_v1,_bind_natural_frame
    if work.db.in_transaction or work.producer_inputs is None:
        raise AuthorityUnavailable('Authority producer observations require the actual local-input EOF outside SQL')
    work._check_permission_v3()
    if work.producer_context is not None:work.producer_context.close()
    selectors,units=work.producer_inputs;stack=ExitStack()
    try:
        observed=(None if selectors.empty else stack.enter_context(observe_authority_natural_producers_v1(
            fences=work.controller.fences,credential=work.credential,subject=work.subject,permit=work.permit,
            namespace=work.namespace,c02_operation_id=work.parent_original_id,graph_db=work.db,
            c04_ref=selectors.c04_ref,draft_result_ref=selectors.draft_result_ref,
            model_service=work.service if work.controller.kind=='model'else None,
            model_intent=work.request if work.controller.kind=='model'else None)))
        frame=stack.enter_context(_bind_natural_frame(work.db,work.namespace,work.parent_original_id,
            selectors,observed,units,scope=work.scope,phase='authority_current_v3'))
        work._check_permission_v3();work.producer_context,work.producer_frame=stack,frame
    except BaseException:stack.close();raise


_AUTHORITY_SIGNED_COLUMNS_V3=WeakKeyDictionary()


def _authority_resource_signer_v3(work):
    issuer=(work.controller.service.observer.issuer if work.controller.kind=='counter'else
        work.controller.verifier._issuer if work.controller.kind=='model'else work.controller.verifier._natural_history._issuer)
    return issuer.resource_issuer._signer


class AuthoritySignedJSONColumnV3:
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER or reader.table!='runtime_resource_quotes':
            raise TypeError('actual fixed Authority resource quote signature column required')
        self.reader,self.owner,self.table,self.column,self.key_columns,self.key=(
            reader,reader.owner,reader.table,'quote_json',reader.key_columns,reader.key)
        self.signer=_authority_resource_signer_v3(self.owner);self.signature_kind='resource-quote.v1'
        self.signature=reader.signature;self.signature_state=None;self.signature_bytes=0
        self.complete=self.signature_verified=False;self.value=None
        _AUTHORITY_SIGNED_COLUMNS_V3[self]=(reader,self.owner,self.table,self.column,self.key_columns,self.key,
            self.signer,self.signature_kind,self.signature,self.owner.operation,self.owner.scope)
        self.signature_state=self.signer.begin_original_stream_verification_v3(self.signature_kind,self)
    def _actual_v3(self):
        work=self.owner;work._actual()
        if _AUTHORITY_SIGNED_COLUMNS_V3.get(self)!=(self.reader,work,self.table,self.column,self.key_columns,self.key,
                self.signer,self.signature_kind,self.signature,work.operation,work.scope):
            raise AuthorityUnavailable('Authority quote signature column changed its actual issuer/locator')
        if self.signer is not _authority_resource_signer_v3(work):
            raise AuthorityUnavailable('Authority quote signer changed installation')
        return self
    def feed_signature_v3(self,fragment):
        self._actual_v3();self.signature_state.update(fragment);self.signature_bytes+=len(fragment)
    def finish_signature_v3(self,column):
        self._actual_v3()
        if self.reader.column is not column or column.owner is not self.owner or not column.complete:
            raise AuthorityUnavailable('Authority quote signature lacks complete actual column EOF')
        self.value=column.require_v3(self.owner);self.sha256,self.byte_count=column.sha256,column.byte_count
        if(self.value.get('bot_id'),self.value.get('persona_id'))!=self.owner.namespace.as_tuple:
            raise AuthorityUnavailable('Authority signed quote belongs to another namespace')
        self.complete=True
        self.signer.finish_original_stream_verification_v3(self.signature_kind,self.signature,self,self.signature_state)
        self.signature_verified=True
    def json_v3(self):
        self._actual_v3()
        if not self.complete or not self.signature_verified:raise AuthorityUnavailable('Authority signed quote original EOF is incomplete')
        return self.value
    def matches_v3(self,value):
        from ..runtime.dispatch_current_inventory_v3 import _freeze_value_v3
        self._actual_v3()
        return self.complete and self.signature_verified and _freeze_value_v3(value)==self.reader.column._frozen_value


def require_authority_signature_column_v3(original,*,signer,kind,signature=None,verifier=None,complete=False):
    if type(original)is not AuthoritySignedJSONColumnV3 or original not in _AUTHORITY_SIGNED_COLUMNS_V3:
        raise TypeError('exact Authority fixed signed quote column required')
    original._actual_v3()
    if(original.signer is not signer or kind!='resource-quote.v1'or original.signature_kind!=kind):
        raise AuthorityUnavailable('Authority quote signature kind/signer changed')
    if complete and(not original.complete or original.signature!=signature
            or original.signature_state is not verifier or original.signature_bytes!=original.byte_count):
        raise AuthorityUnavailable('Authority quote HMAC is not bound to actual raw-byte whole EOF')
    return original


def authority_verify_signature_v3(signer,kind,original,signature):
    require_authority_signature_column_v3(original,signer=signer,kind=kind,signature=signature,
        verifier=original.signature_state,complete=True)
    if not original.signature_verified:raise AuthorityUnavailable('Authority actual quote signature EOF has not been verified')


class _AuthoritySignedQuoteReadV3:
    def __init__(self,work,request):
        self.owner,self.request=work,request;self.table,self.columns,self.key_columns,self.key=request
        self.phase='metadata';self.complete=False;self.column=self.original=self.row=None
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
        self.owner.require_current(meter=meter)
        if self.phase=='metadata':
            self.metadata=_runtime_bounded_fixed_row_v3(self.owner.db,meter,self.table,
                (*self.key_columns,'signature'),'quote_id=? AND version=?',self.key)
            if self.metadata is None:self.complete=True;return
            self.signature=self.metadata[-1];self.original=AuthoritySignedJSONColumnV3(_ISSUER,self)
            self.column=DispatchOriginalJSONReadV3(self.owner,table=self.table,column='quote_json',
                key_columns=self.key_columns,key=self.key,authority_signature_original=self.original)
            self.phase='body';return
        if self.phase=='body':
            if not self.column.advance(meter):return
            self.original.finish_signature_v3(self.column);self.row=(self.original,self.signature);self.complete=True;return
        raise AuthorityUnavailable('unregistered fixed Authority quote phase')
    def require_row_v3(self,owner,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        if owner is not self.owner or not self.complete:raise AuthorityUnavailable('actual complete Authority quote row required')
        current=_runtime_bounded_fixed_row_v3(owner.db,meter,self.table,
            (*self.key_columns,'signature'),'quote_id=? AND version=?',self.key)
        if current!=self.metadata:raise AuthorityUnavailable('Authority quote signature/locator changed at current read')
        return self.row


def require_authority_graph_type_rows_v3(db,namespace,type_names,columns):
    """Closed current families from actual namespace HEAD EOF plus each requested body EOF."""
    work=_authority_attachment_owner_v3(db)
    if work is None:return None
    allowed=frozenset({'d03.account_binding','d03.role_binding','d05.boundary_rule'})
    if (work.namespace!=namespace or not db.in_transaction or not set(type_names)<=allowed
            or tuple(columns)not in(('token','revision','value'),('token','revision','value','valid'))
            or work.namespace_reader is None or not work.namespace_reader.graph_eof):
        raise AuthorityUnavailable('Authority current family is outside its closed actual namespace census')
    from ..graph_types import AtomKey
    result=[]
    for token,head in work.heads.items():
        key=AtomKey.from_token(token)
        if key.type_name in type_names and head[1]:
            atom=work.projection.get(key)
            data={'token':token,'revision':atom.revision,'value':atom.value,'valid':int(atom.valid)}
            result.append(tuple(data[column]for column in columns))
    return tuple(sorted(result,key=lambda row:row[0]))


def require_authority_source_metadata_v3(db,namespace,source_ref):
    work=_authority_attachment_owner_v3(db)
    if work is None:return None
    from ..graph_types import AtomKey
    key=AtomKey.from_token(source_ref)
    if work.namespace!=namespace or NamespaceId.from_key(key)!=namespace or key.type_name!='memory.source'or not db.in_transaction:
        raise AuthorityUnavailable('Authority Source metadata crossed its actual scope/namespace')
    witness=work.sources.get(source_ref)
    if witness is None or not witness.valid:raise AuthorityUnavailable('Authority Source metadata actual canonical cell EOF is absent')
    return witness.require_current_v3()


_AUTHORITY_JSON_COLUMN_CAPS_V3=WeakKeyDictionary()


class PreparedAuthorityJSONColumnV3:
    def __init__(self,issuer,work,attachment,column):
        from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3,_COLUMNS
        if(issuer is not _ISSUER or attachment.owner is not work or not attachment.complete
                or work.attachments.get(attachment.request)is not attachment
                or type(column)is not DispatchOriginalJSONReadV3 or not column.complete
                or attachment.json_columns.get(column.column)is not column or column.owner is not work):
            raise AuthorityUnavailable('actual completed Authority fixed JSON column required')
        work._actual();self.owner,self.attachment,self.column=work,attachment,column
        self.sha256,self.byte_count=column.sha256,column.byte_count
        self.original=_COLUMNS.get(column)
        _AUTHORITY_JSON_COLUMN_CAPS_V3[self]=(work,attachment,column,self.original,self.sha256,self.byte_count,work.operation,work.scope)
        _track_authority_capability_v3(work,_AUTHORITY_JSON_COLUMN_CAPS_V3,self)
    def require_v3(self,work):
        from ..runtime.dispatch_initial_source_read_v3 import _COLUMNS
        if(_AUTHORITY_JSON_COLUMN_CAPS_V3.get(self)!=(work,self.attachment,self.column,self.original,self.sha256,
                self.byte_count,work.operation,work.scope)or self.owner is not work or _COLUMNS.get(self.column)!=self.original
                or work.attachments.get(self.attachment.request)is not self.attachment):
            raise AuthorityUnavailable('Authority JSON cap changed its actual column/Work/EOF')
        work._actual();return self.column.require_v3(work)
    def matches_v3(self,value):
        from ..runtime.dispatch_current_inventory_v3 import _freeze_value_v3
        self.owner._actual()
        return _freeze_value_v3(value)==self.column._frozen_value


def require_authority_json_column_v3(db,*,table,columns,key_columns,key,column):
    work=_authority_attachment_owner_v3(db)
    if work is None:return None
    handled,row=read_bound_authority_graph_attachment_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if not handled or row is None:return None
    request=(table,tuple(columns),tuple(key_columns),tuple(key));attachment=work.attachments.get(request)
    if attachment is None or column not in attachment.json_columns:
        raise AuthorityUnavailable('Authority fixed column has no actual body EOF')
    return _authority_json_column_cap_v3(work,attachment,attachment.json_columns[column])


def begin_authority_model_graph_read_work_v3(verifier,*,model_service,credential,subject,permit,intent,now_utc):
    controller=require_authority_graph_read_controller_v3(verifier)
    if(controller.kind!='model'or controller.service is not model_service or permit is None
            or type(now_utc)not in(int,float)or not math.isfinite(now_utc)):
        raise AuthorityUnavailable('Authority model graph read requires its actual installed service/original permit')
    work=AuthorityGraphReadWorkV3(_ISSUER,controller,credential=credential,subject=subject,permit=permit,
        namespace=controller.location.namespace_id,request=intent,deadline_utc=None)
    work.now_utc=float(now_utc);work.catalogue_reader=_AuthorityCatalogueReadV3(work)
    work.model_natural=False;work.model_reply=False;work.phase='model_entry';return work


def require_authority_current_reply_attention_v3(db,namespace,*,source_ref,now_utc,epoch):
    """The actual selected Source family, rechecked with D07's pure current rule."""
    work=_authority_attachment_owner_v3(db)
    if work is None:return None
    from ..domains.d07 import _qualify_focus_attention_values_v3
    if (work.namespace!=namespace or work.projection is None or work.source_material is None
            or work.source_selection.root!=source_ref or work.projection.epochs!=(epoch,)):
        raise AuthorityUnavailable('Authority reply attention lost its actual Source selection/epoch')
    material=work.source_material
    material.require_current(db=db,prepared_full_read=work.prepared,namespace=namespace,
        source_ref=source_ref,audiences=material.audiences)
    def source_reader(key):
        witness=material.witnesses.get(key.token)
        return None if witness is None else witness.require_current_v3()
    attention=_qualify_focus_attention_values_v3(work.projection,namespace,now=now_utc,source_reader=source_reader)
    if attention is None or attention!=material.attention:
        raise AuthorityUnavailable('Authority current D07 focus/ticket/Source versions changed')
    return work.projection,attention



def require_authority_expression_source_atom_v3(work,source_ref):
    """Only the actual selected expression body's EOF may supply a Source atom."""
    from ..graph_types import AtomKey,GraphAtom
    material=work.source_material
    if type(material)is not PreparedAuthoritySourceMaterialV3 or source_ref not in material.source_records:
        material=work.context_source_material
    if type(material)is not PreparedAuthoritySourceMaterialV3 or source_ref not in material.source_records:
        raise AuthorityUnavailable('Authority Source has no actual selected expression body EOF')
    material.require_current(db=work.db,prepared_full_read=work.prepared,namespace=work.namespace,
        source_ref=source_ref,audiences=material.audiences)
    key=AtomKey.from_token(source_ref);witness=material.witnesses[source_ref].require_current_v3()
    atom=work.source_atoms.get(key)
    if atom is not None and work.atom_json_originals[key].source_material is material:
        original=work.atom_json_originals[key]
        original.require_value_v3(key=key,revision=atom.revision,valid=atom.valid,value=atom.value)
        return atom
    value=material.source_records[source_ref].to_dict()
    original=PreparedAuthorityGraphValueOriginalV3.__new__(PreparedAuthorityGraphValueOriginalV3)
    original.work,original.source_material=work,material
    original.key,original.revision,original.valid,original.value=key,witness.revision,witness.valid,value
    _AUTHORITY_GRAPH_VALUES_V3[original]=(work,material,key,witness.revision,witness.valid,value)
    _track_authority_capability_v3(work,_AUTHORITY_GRAPH_VALUES_V3,original)
    work.operation.retain(4096)
    atom=GraphAtom(key,witness.revision,value,witness.valid,_canonical_original=original)
    work.source_atoms[key]=atom;work.atom_json_originals[key]=original
    return atom


_AUTHORITY_ATOM_JSON_V3=WeakKeyDictionary()
class _AuthorityAtomJSONV3:
    def __init__(self,issuer,work,atom):
        if issuer is not _ISSUER:raise TypeError('actual Authority atom column issuer required')
        self.work,self.atom=work,atom
        _AUTHORITY_ATOM_JSON_V3[self]=(work,atom,work.operation,work.scope)
        _track_authority_capability_v3(work,_AUTHORITY_ATOM_JSON_V3,self)
    def require_v3(self,work):
        if (_AUTHORITY_ATOM_JSON_V3.get(self)!=(self.work,self.atom,self.work.operation,self.work.scope)
                or work is not self.work or work.projection.get(self.atom.key)is not self.atom):
            raise AuthorityUnavailable('Authority graph JSON differs from its actual complete current body')
        work._actual()
        if self.atom.key.type_name!='memory.source':
            request=('graph_atoms',('revision','value','valid'),('token','bot','persona'),
                (self.atom.key.token,*work.namespace.as_tuple))
            attachment=work.attachments.get(request)
            if attachment is not None:
                from ..runtime.dispatch_current_inventory_v3 import _freeze_value_v3
                column=attachment.json_columns.get('value')
                if column is None or _freeze_value_v3(self.atom.value)!=column._frozen_value:
                    raise AuthorityUnavailable('Authority current graph JSON changed its canonical original')
            else:raise AuthorityUnavailable('Authority current value lost its actual complete typed body column')
        return self.atom.value
    def matches_v3(self,value):
        return self.require_v3(self.work)==value


def authority_current_json_v3(value):
    """Decode only exact privately issued columns; the legacy JSON path is unchanged."""
    if type(value)in(PreparedAuthorityJSONColumnV3,_AuthorityAtomJSONV3):return value.require_v3(value.work if type(value)is _AuthorityAtomJSONV3 else value.owner)
    import json
    return json.loads(value)


def authority_current_json_matches_v3(original,value,*,legacy_serializer):
    if type(original)in(PreparedAuthorityJSONColumnV3,_AuthorityAtomJSONV3):return original.matches_v3(value)
    return legacy_serializer(value)==original


def read_authority_current_point_v3(db,*,table,columns,key_columns,key,legacy_reader,required_valid=False):
    """Fixed current points under the same Work; no SQL predicate or Source grant is inferred."""
    work=_authority_attachment_owner_v3(db)
    if work is None:return legacy_reader()
    from ..graph_types import AtomKey
    columns=tuple(columns);key_columns=tuple(key_columns);key=tuple(key)
    exists=columns==('1',)
    if table=='graph_atoms':
        if key_columns not in(('token',),('token','bot','persona')):
            raise AuthorityUnavailable('Authority current atom point lacks its actual full locator')
        atom_key=AtomKey.from_token(key[0])
        if NamespaceId.from_key(atom_key)!=work.namespace or len(key)==3 and key[1:]!=work.namespace.as_tuple:
            raise AuthorityUnavailable('Authority current atom point crossed namespace')
        if not set(columns)<={'1','token','revision','value','valid'}:
            raise AuthorityUnavailable('Authority current atom point requested an unprepared column')
        head=work.heads.get(key[0])
        if head is None or required_valid and not head[1]:return None
        values={'1':1,'token':key[0],'revision':head[0],'valid':int(head[1])}
        if 'value'in columns:
            atom=work.projection.get(atom_key)
            values['value']=_AuthorityAtomJSONV3(_ISSUER,work,atom)
        return tuple(values[name]for name in columns)
    actual_columns=('event_id',)if exists and table=='graph_events'else('operation_id',)if exists else columns
    handled,row=read_bound_authority_graph_attachment_v3(db,table=table,columns=actual_columns,
        key_columns=key_columns,key=key)
    if not handled:raise AuthorityUnavailable('Authority current point has no actual fixed reader')
    if row is None:return None
    if exists:return(1,)
    request=(table,actual_columns,key_columns,key);attachment=work.attachments.get(request)
    if attachment is None:raise AuthorityUnavailable('Authority current point lost its actual complete attachment')
    result=list(row)
    for i,name in enumerate(actual_columns):
        if name in attachment.json_columns:
            result[i]=_authority_json_column_cap_v3(work,attachment,attachment.json_columns[name])
    return tuple(result)



def authority_current_versions_v3(encoded):
    from ..graph_types import AtomKey,GraphVersion
    return tuple(GraphVersion(AtomKey.from_token(token),revision)for token,revision in authority_current_json_v3(encoded))


def authority_reply_attention_versions_v3(snapshot):
    """Preserve the original selected D07 closure read set rather than all namespace members."""
    if type(snapshot)is not AuthorityGraphProjectionV3:return snapshot.versions
    work=snapshot.work;material=work.source_material
    if type(material)is not PreparedAuthoritySourceMaterialV3 or material.attention is None:
        raise AuthorityUnavailable('Authority reply read set has no actual selected D07 Source closure')
    material.selection.require_v3(work)
    from ..graph_types import AtomKey,GraphVersion
    from ..memory_types import access_key
    from ..domains.d06 import source_correction_head_key
    versions=[material.attention.focus_version,material.attention.ticket_version]
    for ref in sorted(material.attention_refs):
        key=AtomKey.from_token(ref);witness=material.witnesses[ref].require_current_v3()
        access=access_key(*work.namespace.as_tuple,key.owner.subject);head=source_correction_head_key(work.namespace,key.owner.subject)
        access_atom=work.projection.get(access);correction=work.projection.get(head)
        if correction.valid or correction.revision!=0:raise AuthorityUnavailable('Authority D07 Source correction changed')
        versions.extend((GraphVersion(key,witness.revision),GraphVersion(access,access_atom.revision),GraphVersion(head,0)))
    return tuple(dict.fromkeys(versions))



def require_authority_outbound_collection_source_v6(work,*,slot,completion,batch,outbox,source_ref,original,receipt):
    """Context use derives only from this record's actual adopted delivered observation."""
    from ..authority_service.v2_contract import MutationReceiptV2,PlatformObservationV2
    from ..domains.d09.turn_order import _outbound_segment
    from ..graph_types import AtomKey
    if (type(original)is not PreparedAuthorityJSONColumnV3 or original.owner is not work
            or original.attachment.table!='graph_d13_outbound_observations_v1'
            or type(receipt)is not MutationReceiptV2):
        raise AuthorityUnavailable('Authority outbound context lacks its actual adopted original column')
    adopted=original.require_v3(work);pending=receipt.pending
    observation=None if pending is None else pending.platform_observation
    for atom in(slot,completion,batch,outbox):
        if work.projection.get(atom.key)is not atom or not atom.valid:
            raise AuthorityUnavailable('Authority outbound record changed its actual current Graph atoms')
    segment,payload_ref=_outbound_segment(batch)
    key=AtomKey.from_token(source_ref);witness=work.sources.get(source_ref)
    if (witness is None or not witness.valid or witness.metadata['source_kind']!='authored'
            or adopted.get('source_ref')!=source_ref or adopted.get('slot_ref')!=slot.key.token
            or adopted.get('batch_ref')!=batch.key.token or completion.value['source_ref']!=source_ref
            or slot.value['direction']!='outbound' or slot.value['origin_ref']!=outbox.key.token
            or outbox.key.type_name!='runtime.outbox'or outbox.value['phase']!='delivered'
            or outbox.value['payload_ref']!=payload_ref or type(segment)is not dict
            or type(observation)is not PlatformObservationV2 or pending.phase!='observed'
            or receipt.durable_state!='committed'or observation.outcome!='delivered'
            or outbox.value['effect_id']!=observation.binding.origin.effect_id
            or outbox.value['operation_id']!=observation.binding.origin.operation_id
            or '/'.join(work.namespace.as_tuple)!=observation.binding.graph_namespace):
        raise AuthorityUnavailable('Authority outbound context differs from its actual adopted delivered record')
    identity=(slot,completion,batch,outbox,original.attachment,source_ref)
    current=work.collection_record
    if current is None or current.get('outbound_identity')!=identity:
        work.collection_record={'outbound_identity':identity,'slot':slot,'completion':completion,
            'scene_ref':slot.value['scene_ref'],'conversation_ref':slot.value['conversation_ref']}
    record=work.collection_record;material=work.collection_source_materials.get(source_ref)
    if material is not None and material.selection.record is record:
        material.selection.require_v3(work);return material
    if work.complete:raise AuthorityUnavailable('Authority final outbound Source was not prepared by this Work')
    selection=_AuthorityCollectionSourceSelectionV6(_ISSUER,work,root=source_ref,
        audience=slot.value['conversation_ref'],binding=identity,maximum_ancestors=128)
    raise AuthorityCollectionSourceRequiredV6(selection)



def _track_authority_capability_v3(work,registry,original):
    if type(work)is not AuthorityGraphReadWorkV3 or work.closed or work not in _WORKS:
        raise AuthorityUnavailable('Authority private original has no actual retained issuing Work')
    work.operation.retain(128)
    work.issued_capabilities.append((registry,original))


def _authority_json_column_cap_v3(work,attachment,column):
    cache=getattr(attachment,'authority_json_caps_v3',None)
    if cache is None:cache={};attachment.authority_json_caps_v3=cache
    proof=cache.get(column.column)
    if proof is None:
        proof=PreparedAuthorityJSONColumnV3(_ISSUER,work,attachment,column);cache[column.column]=proof
    proof.require_v3(work);return proof



def _prepare_authority_counter_event_read_v3(work,meter):
    draft=work.counter_call.draft
    if draft is None:raise AuthorityUnavailable('Counter event preparation has no actual original draft')
    old=draft['graph_epoch'];new=work.counter_current_self.graph_epoch
    if new!=work.graph_stamp[0]or not 0<=new-old<=2:
        raise AuthorityUnavailable('Counter current frame has an unproven Graph epoch transition')
    if work.counter_event_index<2:
        suffix=('prepare','settle')[work.counter_event_index]
        event_id=draft['selector']['counter_operation_id']+':'+suffix
        point=read_authority_current_point_v3(work.db,table='graph_events',columns=('epoch_revision','revisions'),
            key_columns=('bot','persona','session','event_id'),
            key=(*work.namespace.as_tuple,'d13-counter-v1',event_id),legacy_reader=lambda:None)
        if point is not None and point[0]>old:
            work.counter_events.append(('d13-counter-v1',event_id,point[0],point[1]))
        work.counter_event_index+=1;return
    work.counter_events.sort(key=lambda row:row[2])
    if [row[2]for row in work.counter_events]!=list(range(old+1,new+1)):
        raise AuthorityUnavailable('another Graph operation occurred inside the original counter frame')
    work.phase='validate'



def _is_actual_authority_source_material_v3(work,material):
    return work.source_material is material or work.context_source_material is material


class _AuthorityContextFrozenReadV3:
    """Original ContextReply recipe compared one canonical fragment at a time."""
    def __init__(self,work,column):
        self.work,self.column=work,column;self.raw=column.require_v3(work)
        self.phase='fields';self.complete=False;self.comparison=None;self.result=None
    def _compare(self,value,target=None):
        from ..runtime.natural_frozen_original_read_v3 import _CanonicalComparisonV3
        self.comparison=_CanonicalComparisonV3(value,target,operation=self.work.operation)
    def advance(self,meter):
        from dataclasses import asdict,fields
        from ..model_broker.context_reply import (ContextReplyInputV1,ContextReplyInstallationV1,ContextReplyMessageV1,
            FrozenContextReplyRequestV1,INPUT_SCHEMA,SYSTEM_MESSAGE,CONTEXT_REPLY_TEMPLATE_VERSION,CONTEXT_REPLY_TEMPLATE_DIGEST)
        from ..runtime.context_reply_job_v2 import _part,_versioned
        raw=self.raw;work=self.work;work.require_current(meter=meter)
        if self.phase=='fields':
            if type(raw)is not dict or set(raw)!={field.name for field in fields(FrozenContextReplyRequestV1)}:
                raise AuthorityUnavailable('Authority ContextReply frozen fieldset differs')
            value=raw['input']
            self.input=ContextReplyInputV1(NamespaceId(**value['namespace']),_versioned(value['scene_ref']),
                _versioned(value['audience_ref']),value['conversation_ref'],value['access_epoch'],value['delete_epoch'],
                value['activation_generation'],value['frozen_at_utc'],value['expires_at_utc'],_part(value['question']),
                *(tuple(_part(part)for part in value[name])for name in('evidence','focus','required_checks','dialogue_state','history','stable_history')))
            self.installation=ContextReplyInstallationV1(**raw['installation'])
            self.messages=tuple(ContextReplyMessageV1(**item)for item in raw['messages'])
            if len(self.messages)!=3 or tuple(message.role for message in self.messages)!=('system','user','user')or self.messages[0].content!=SYSTEM_MESSAGE:
                raise AuthorityUnavailable('Authority ContextReply messages differ from original recipe')
            work.operation.retain(65536)
            self._compare({'schema':INPUT_SCHEMA,'scope':{'namespace':asdict(self.input.namespace),'scene_ref':asdict(self.input.scene_ref),
                'audience_ref':asdict(self.input.audience_ref),'conversation_ref':self.input.conversation_ref},
                'stable_history':[asdict(part)for part in self.input.stable_history]},self.messages[1].content)
            self.phase='stable';return
        if self.phase=='stable':
            if not self.comparison.advance(meter):return
            sections=[{'kind':kind,'parts':[asdict(part)for part in parts]}for kind,parts in(
                ('question',(self.input.question,)),('d06_evidence',self.input.evidence),('d07_focus',self.input.focus),
                ('required_check',self.input.required_checks),('d09_state',self.input.dialogue_state),('d13_history',self.input.history))]
            self._compare({'schema':INPUT_SCHEMA,'scope':{name:getattr(self.input,name)for name in(
                'access_epoch','delete_epoch','activation_generation','frozen_at_utc','expires_at_utc')},'sections':sections},self.messages[2].content)
            self.phase='dynamic';return
        if self.phase=='dynamic':
            if not self.comparison.advance(meter):return
            self.payload={'model':self.installation.model_id,'messages':[asdict(message)for message in self.messages],
                'max_output_tokens':self.installation.max_output_tokens}
            self._compare(self.payload,raw['canonical_wire']);self.phase='wire';return
        if self.phase=='wire':
            if not self.comparison.advance(meter):return
            if self.comparison.digest!=raw['digest']:raise AuthorityUnavailable('Authority ContextReply provider wire digest differs')
            from hashlib import sha256
            self.prefix_hash=sha256();self.prefix_offset=0;self.prefix_part=0;self.prefix_stream=None;self.phase='prefix';return
        if self.phase=='prefix':
            from ..runtime.owner_material_source_storage_v3 import CanonicalValueStreamV3
            prefix=raw['stable_prefix_wire'];parts=('header','system','comma','stable','end')
            if self.prefix_part==len(parts):
                if self.prefix_offset!=len(prefix)or not raw['canonical_wire'].startswith(prefix):
                    raise AuthorityUnavailable('Authority ContextReply prefix differs from complete provider wire')
                self._compare({'version':CONTEXT_REPLY_TEMPLATE_VERSION,'template_digest':CONTEXT_REPLY_TEMPLATE_DIGEST,
                    'installation_id':self.installation.installation_id,'provider_config_digest':self.installation.provider_config_digest,
                    'provider_id':self.installation.provider_id,'model_id':self.installation.model_id,
                    'stable_prefix_sha256':self.prefix_hash.hexdigest()})
                self.phase='prefix_digest';return
            kind=parts[self.prefix_part]
            if kind in('system','stable'):
                if self.prefix_stream is None:self.prefix_stream=CanonicalValueStreamV3(asdict(self.messages[0 if kind=='system'else 1]))
                fragment=self.prefix_stream.read_fragment(meter)
                if self.prefix_stream.complete:self.prefix_stream=None;self.prefix_part+=1
            else:
                fragment=(('{"max_output_tokens":'+str(self.installation.max_output_tokens)+',"messages":[')if kind=='header'else','if kind=='comma'else',{"content":').encode('ascii')
                meter.charge_encode(len(fragment));self.prefix_part+=1
            if fragment:
                text=fragment.decode('ascii');end=self.prefix_offset+len(text)
                if prefix[self.prefix_offset:end]!=text:raise AuthorityUnavailable('Authority ContextReply exact stable prefix changed')
                self.prefix_hash.update(fragment);self.prefix_offset=end
            return
        if self.phase=='prefix_digest':
            if not self.comparison.advance(meter):return
            if self.comparison.digest!=raw['stable_prefix_digest']:raise AuthorityUnavailable('Authority ContextReply prefix commitment differs')
            self.result=FrozenContextReplyRequestV1(self.input,self.installation,self.messages,raw['canonical_wire'],raw['stable_prefix_wire'],raw['stable_prefix_digest'],raw['digest'])
            self._compare(asdict(self.input));self.phase='input_digest';return
        if self.phase=='input_digest':
            if not self.comparison.advance(meter):return
            self.input_digest=self.comparison.digest;self._compare(asdict(self.result));self.phase='roundtrip';return
        if self.phase=='roundtrip':
            if not self.comparison.advance(meter):return
            if self.comparison.digest!=self.column.sha256 or self.comparison.offset!=self.column.byte_count:
                raise AuthorityUnavailable('Authority ContextReply typed recipe differs from complete original column EOF')
            self.complete=True;return
        raise AuthorityUnavailable('unregistered Authority ContextReply recipe phase')


class _AuthorityContextOriginalReadV3:
    def __init__(self,work):
        self.work=work;self.phase='point';self.complete=False;self.saved=None;self.frozen_reader=None
    def advance(self,meter):
        work=self.work
        if self.phase=='point':
            columns=('seal_json','frozen_request_json','read_versions_json','query_epoch_json','graph_epoch','access_epoch','delete_epoch','state')
            keys=('bot','persona','c02_operation_id','source_ref');key=(*work.namespace.as_tuple,*work.context_locator)
            self.row=read_authority_current_point_v3(work.db,table='graph_context_reply_preparations_v2',columns=columns,
                key_columns=keys,key=key,legacy_reader=lambda:None)
            if self.row is None:raise AuthorityUnavailable('Authority ContextReply original disappeared')
            self.frozen_reader=_AuthorityContextFrozenReadV3(work,self.row[1].column);self.phase='frozen';return
        if self.phase=='frozen':
            self.frozen_reader.advance(meter)
            if not self.frozen_reader.complete:return
            from ..runtime.context_reply_job_v2 import SavedContextReplyPreparationV2,context_reply_job_ids_v2
            from ..runtime_contracts import ContextReplyOriginalSealV2,QueryEpoch,context_reply_graph_guard_digest_v2
            from ..graph_types import AtomKey,GraphVersion
            seal_data=authority_current_json_v3(self.row[0]).copy();seal_data['namespace']=NamespaceId(**seal_data['namespace'])
            seal=ContextReplyOriginalSealV2(**seal_data);frozen=self.frozen_reader.result
            versions=tuple(GraphVersion(AtomKey.from_token(item['key']),item['revision'])for item in authority_current_json_v3(self.row[2]))
            query_data=authority_current_json_v3(self.row[3]).copy();query_data['namespace']=NamespaceId(**query_data['namespace']);query=QueryEpoch(**query_data)
            ids=context_reply_job_ids_v2(work.namespace,*work.context_locator)
            guard_digest=context_reply_graph_guard_digest_v2(versions,query,graph_epoch=self.row[4],access_epoch=self.row[5],
                delete_epoch=self.row[6],activation_generation=frozen.input.activation_generation)
            if (seal.namespace!=work.namespace or (seal.c02_operation_id,seal.source_ref)!=work.context_locator
                    or (seal.job_id,seal.original_operation_id,seal.acquire_operation_id,seal.call_id)!=ids
                    or seal.job_id!=work.request.job_id or seal.frozen_input_digest!=self.frozen_reader.input_digest
                    or seal.model_request_digest!=frozen.digest or seal.graph_guard_digest!=guard_digest
                    or seal.installation_id!=frozen.installation.installation_id
                    or seal.provider_config_digest!=frozen.installation.provider_config_digest or frozen.input.namespace!=work.namespace
                    or self.row[5:7]!=(frozen.input.access_epoch,frozen.input.delete_epoch)or self.row[7]not in('queued','acquired','terminal')):
                raise AuthorityUnavailable('Authority ContextReply actual original seal/binding differs')
            if not frozen.input.frozen_at_utc<=work.now_utc<frozen.input.expires_at_utc:
                raise AuthorityUnavailable('Authority ContextReply original window expired')
            deadline=min(work.deadline_utc,frozen.input.expires_at_utc)
            work.deadline_utc=work.operation.deadline_utc=deadline;work.deadline_original=self
            _DEADLINES[work]=(work.operation,deadline,self)
            self.saved=SavedContextReplyPreparationV2(seal,frozen,versions,query,*self.row[4:]);self.complete=True;return
        raise AuthorityUnavailable('unregistered Authority ContextReply original phase')


_AUTHORITY_CONTEXT_SELECTIONS_V3=WeakKeyDictionary()
class _AuthorityContextSourceSelectionV3:
    def __init__(self,issuer,work,original):
        if issuer is not _ISSUER or original is not work.context_original or not original.complete:
            raise AuthorityUnavailable('Authority ContextReply Source selection has no actual completed original')
        input=original.saved.frozen_request.input
        self.work,self.original=work,original;self.roots=tuple(part.ref.ref for part in input.evidence)
        self.root=self.roots[0];self.audience=input.audience_ref.ref;self.purpose='expression'
        self.maximum_ancestors=256;self.attention=None;self.assertion_required=True
        _AUTHORITY_CONTEXT_SELECTIONS_V3[self]=(work,original,self.roots,self.audience,work.operation,work.scope)
        _track_authority_capability_v3(work,_AUTHORITY_CONTEXT_SELECTIONS_V3,self)
    def require_v3(self,work):
        if (_AUTHORITY_CONTEXT_SELECTIONS_V3.get(self)!=(work,self.original,self.roots,self.audience,work.operation,work.scope)
                or self.work is not work or work.context_original is not self.original or not self.original.complete):
            raise AuthorityUnavailable('Authority ContextReply Source selection moved outside actual saved original')
        work._actual();return self


def require_authority_context_reply_preparation_v3(db,namespace,c02_operation_id,source_ref):
    work=_authority_attachment_owner_v3(db)
    if work is None:return False,None
    original=work.context_original
    if (not work.model_context or original is None or not original.complete or work.namespace!=namespace
            or work.context_locator!=(c02_operation_id,source_ref)):
        raise AuthorityUnavailable('Authority ContextReply consumer requested an unprepared actual original')
    for column in original.row[:4]:column.require_v3(work)
    return True,original.saved


def require_authority_context_source_material_v3(db,frozen):
    work=_authority_attachment_owner_v3(db)
    if work is None:return None
    if (not work.model_context or work.context_original is None or work.context_original.saved.frozen_request is not frozen
            or type(work.context_source_material)is not PreparedAuthoritySourceMaterialV3):
        raise AuthorityUnavailable('Authority ContextReply Source consumer lacks its actual saved original/independent material')
    material=work.context_source_material
    for ref in material.selection.roots:
        material.require_current(db=db,prepared_full_read=work.prepared,namespace=work.namespace,
            source_ref=ref,audiences=(frozen.input.audience_ref.ref,))
    return material



_AUTHORITY_MODEL_REQUEST_DIGESTS_V3={}
def _retain_authority_model_digest_v3(request,digest):
    from weakref import ref
    from ..runtime.dispatch_current_inventory_v3 import _freeze_value_v3
    from ..model_broker.broker import ModelCallRequest
    if type(request)is not ModelCallRequest or type(digest)is not str or len(digest)!=64:
        raise AuthorityUnavailable('actual complete Authority model recipe digest required')
    fields=tuple((name,getattr(request,name))for name in('envelope','call_id','provider_id','model_id',
        'required_capabilities','privacy_tier','prompt_template_digest','timeout_seconds','max_output_tokens'))
    identity=id(request);payload=_freeze_value_v3(dict(request.payload))
    _AUTHORITY_MODEL_REQUEST_DIGESTS_V3[identity]=(ref(request,lambda _: _AUTHORITY_MODEL_REQUEST_DIGESTS_V3.pop(identity,None)),fields,payload,digest)


def prepared_authority_model_request_digest_v3(request):
    item=_AUTHORITY_MODEL_REQUEST_DIGESTS_V3.get(id(request))
    if item is None:return None
    from ..runtime.dispatch_current_inventory_v3 import _freeze_value_v3
    reference,fields,payload,digest=item
    if reference()is not request or any(getattr(request,name)!=value for name,value in fields)or _freeze_value_v3(dict(request.payload))!=payload:
        raise AuthorityUnavailable('Authority model request changed its complete original recipe')
    return digest


_AUTHORITY_CONTEXT_PAYLOAD_EOF_V3=WeakKeyDictionary()
class PreparedAuthorityContextPayloadEOFV3:
    def __init__(self,issuer,reader,raw,envelope):
        from ..runtime.dispatch_current_inventory_v3 import _freeze_value_v3
        if (issuer is not _ISSUER or type(reader)is not _AuthorityContextCallReadV3 or not reader.recipe_complete
                or reader.work.context_call_reader is not reader or _freeze_value_v3(raw)!=reader.column._frozen_value):
            raise AuthorityUnavailable('Authority ContextReply request lacks its actual full column/recipe EOF')
        self.reader,self.raw,self.envelope=reader,raw,envelope
        _AUTHORITY_CONTEXT_PAYLOAD_EOF_V3[self]=(reader,raw,envelope,reader.work.operation)
        _track_authority_capability_v3(reader.work,_AUTHORITY_CONTEXT_PAYLOAD_EOF_V3,self)
    def require_for_v3(self,request):
        from ..runtime.dispatch_current_inventory_v3 import _freeze_value_v3
        from ..runtime.reply_model_job import reply_request_wire_v1
        reader=self.reader;reader.work._actual()
        if (_AUTHORITY_CONTEXT_PAYLOAD_EOF_V3.get(self)!=(reader,self.raw,self.envelope,reader.work.operation)
                or not reader.recipe_complete or request.envelope!=self.envelope or request.payload is not self.raw['payload']
                or _freeze_value_v3(reply_request_wire_v1(request.envelope,request))!=reader.column._frozen_value):
            raise AuthorityUnavailable('Authority ContextReply model request changed its complete typed recipe')
        _retain_authority_model_digest_v3(request,reader.request_digest)
        _AUTHORITY_CONTEXT_PAYLOAD_EOF_V3.pop(self,None)


class _AuthorityContextCallReadV3:
    def __init__(self,work):
        self.work=work;self.phase='point';self.complete=False;self.recipe_complete=False;self.result=None
    def advance(self,meter):
        from ..runtime.context_reply_job_v2 import SavedContextReplyCallBindingV2
        from ..runtime.natural_frozen_original_read_v3 import _CanonicalComparisonV3
        from ..runtime.natural_reply_job_v2 import _envelope_from_wire_v3
        from ..model_broker.broker import ModelCallRequest
        from ..model_broker.context_reply import CONTEXT_REPLY_TEMPLATE_DIGEST
        from ..runtime_contracts import canonical_digest
        from dataclasses import asdict
        from ..runtime.dispatch_current_inventory_v3 import _freeze_value_v3
        work=self.work;saved=work.context_original.saved;seal=saved.seal
        if self.phase=='point':
            self.row=read_authority_current_point_v3(work.db,table='graph_context_reply_call_bindings_v2',
                columns=('acquire_operation_id','call_id','worker_fence','original_seal_digest','frozen_request_digest',
                    'model_call_request_digest','model_call_request_json'),key_columns=('bot','persona','original_operation_id'),
                key=(*work.namespace.as_tuple,seal.original_operation_id),legacy_reader=lambda:None)
            if self.row is None:raise AuthorityUnavailable('Authority ContextReply has no actual original call binding')
            self.column=self.row[6].column;self.raw=self.column.require_v3(work)
            self.envelope=_envelope_from_wire_v3(self.raw)
            if _freeze_value_v3(self.raw['payload'])!=_freeze_value_v3(work.context_original.frozen_reader.payload):
                raise AuthorityUnavailable('Authority ContextReply model payload differs from full frozen wire recipe')
            raw=self.raw
            value={'envelope':self.envelope,'call_id':raw['call_id'],'provider_id':raw['provider_id'],'model_id':raw['model_id'],
                'purpose':self.envelope.authority.purpose,'required_capabilities':sorted(raw['required_capabilities']),
                'privacy_tier':raw['privacy_tier'],'template':raw['prompt_template_digest'],'payload':raw['payload'],
                'timeout_seconds':float(raw['timeout_seconds']),'max_output_tokens':raw['max_output_tokens']}
            self.digest_reader=_CanonicalComparisonV3(value,operation=work.operation);self.phase='digest';return
        if self.phase=='digest':
            if not self.digest_reader.advance(meter):return
            self.request_digest=self.digest_reader.digest;self.recipe_complete=True
            raw=self.raw;witness=PreparedAuthorityContextPayloadEOFV3(_ISSUER,self,raw,self.envelope)
            request=ModelCallRequest(self.envelope,raw['call_id'],raw['provider_id'],raw['model_id'],frozenset(raw['required_capabilities']),
                raw['privacy_tier'],raw['prompt_template_digest'],raw['payload'],raw['timeout_seconds'],raw['max_output_tokens'],
                _prepared_payload_eof_v3=witness)
            if (self.row[:2]!=(seal.acquire_operation_id,seal.call_id)or type(self.row[2])is not int or self.row[2]<1
                    or self.row[3]!=canonical_digest(asdict(seal))or self.row[4]!=saved.frozen_request.digest
                    or self.row[5]!=self.request_digest or request.call_id!=seal.call_id
                    or request.identity.operation_id!=seal.acquire_operation_id or request.prompt_template_digest!=CONTEXT_REPLY_TEMPLATE_DIGEST
                    or request.provider_id!=saved.frozen_request.installation.provider_id
                    or request.model_id!=saved.frozen_request.installation.model_id):
                raise AuthorityUnavailable('Authority ContextReply actual original call binding/paid recipe differs')
            self.result=SavedContextReplyCallBindingV2(request,self.request_digest,self.row[2]);self.complete=True;return
        raise AuthorityUnavailable('unregistered Authority ContextReply call phase')


def require_authority_context_call_binding_v3(db,saved):
    work=_authority_attachment_owner_v3(db)
    if work is None:return False,None
    reader=work.context_call_reader
    if reader is None or not reader.complete or saved is not work.context_original.saved:
        raise AuthorityUnavailable('Authority ContextReply call binding is outside its actual prepared original')
    reader.column.require_v3(work)
    return True,reader.result



_AUTHORITY_C02_BUNDLES_V3=WeakKeyDictionary()
class _PreparedAuthorityC02EnvelopeV3:
    """Complete legacy C02 typed-semantic/identity EOF; exposes only the normal envelope."""
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER or not reader.complete:
            raise AuthorityUnavailable('Authority C02 envelope requires complete typed-semantic original EOF')
        self.work,self.reader,self.envelope=reader.work,reader,reader.envelope
        _AUTHORITY_C02_BUNDLES_V3[self]=(reader,self.work,self.envelope,reader.bundle_digest,reader.column,
            tuple(reader.proposal_fingerprints),self.work.operation,self.work.scope)
        _track_authority_capability_v3(self.work,_AUTHORITY_C02_BUNDLES_V3,self)
    def require_current_v3(self,work,operation_id):
        reader=self.reader
        if (_AUTHORITY_C02_BUNDLES_V3.get(self)!=(reader,work,self.envelope,reader.bundle_digest,reader.column,
                tuple(reader.proposal_fingerprints),work.operation,work.scope)
                or self.work is not work or operation_id!=work.parent_original_id or work.c02_bundle_original is not self):
            raise AuthorityUnavailable('Authority C02 envelope changed its actual original/Work')
        reader.column.require_v3(work);work._actual();return self.envelope


class _AuthorityC02BundleReadV3:
    """Authority qualification around the shared data-only C02 stream mechanics."""
    def __init__(self,work):
        self.work=work;self.phase='point';self.complete=False;self.proof=None
        self.proposal_fingerprints=[];self.stream=None;self.kernel=None
        self.fragment=b'';self.fragment_offset=0
    def advance(self,meter):
        from ..runtime.c02_bundle_mechanical_read_v3 import C02BundleMechanicalReadV3
        from ..runtime.owner_material_source_storage_v3 import CanonicalValueStreamV3
        from ..runtime.dispatch_initial_source_read_v3 import _container_bytes_v3
        work=self.work;work.require_current(meter=meter)
        if self.phase=='point':
            keys=('bot','persona','operation_id');key=(*work.namespace.as_tuple,work.parent_original_id)
            self.archive=read_authority_current_point_v3(work.db,table='graph_first_ingress_c02_committed_seals_v2',
                columns=('schema','bundle_digest','bundle_json'),key_columns=keys,key=key,legacy_reader=lambda:None)
            self.business=read_authority_current_point_v3(work.db,table='graph_bundle_operations',
                columns=('digest','activity_id','effect_id','commit_seq'),key_columns=keys,key=key,legacy_reader=lambda:None)
            if self.archive is None or self.business is None:
                raise AuthorityUnavailable('Authority C02 typed original lacks its actual committed archive/business identity')
            self.event=read_authority_current_point_v3(work.db,table='graph_events',columns=('digest','epoch_revision'),
                key_columns=('bot','persona','session','event_id'),
                key=(*work.namespace.as_tuple,self.business[1],work.parent_original_id),legacy_reader=lambda:None)
            self.column=self.archive[2].column
            self.kernel=C02BundleMechanicalReadV3(namespace=work.namespace,operation_id=work.parent_original_id,
                archive_schema=self.archive[0],archive_digest=self.archive[1],business=self.business,
                event=self.event,operation=work.operation)
            # Existing Authority attachments materialize their qualified JSON. This
            # adapter does not grant that ability to the metadata-only Observer.
            raw=self.column.require_v3(work)
            work.operation.retain(_container_bytes_v3(raw)+65536)
            self.stream=CanonicalValueStreamV3(raw);self.phase='stream';return
        if self.phase=='stream':
            if self.fragment_offset<len(self.fragment):
                end=min(self.fragment_offset+1024,len(self.fragment))
                self.kernel.feed_v3(self.fragment[self.fragment_offset:end],meter)
                self.fragment_offset=end;return
            self.fragment=b'';self.fragment_offset=0
            if not self.stream.complete:
                fragment=self.stream.read_fragment(meter)
                if fragment is not None:self.fragment=fragment
                return
            self.envelope=self.kernel.finish_v3(sha256=self.column.sha256,byte_count=self.column.byte_count)
            self.bundle_digest=self.kernel.bundle_digest
            self.proposal_fingerprints=tuple(self.kernel.proposal_fingerprints)
            self.stream=None;self.complete=True;self.proof=_PreparedAuthorityC02EnvelopeV3(_ISSUER,self);return
        raise AuthorityUnavailable('unregistered Authority C02 typed-semantic original phase')


def require_authority_c02_bundle_envelope_v3(db,namespace,operation_id):
    work=_authority_attachment_owner_v3(db)
    if work is None:return None
    if work.namespace!=namespace or work.c02_bundle_original is None:
        raise AuthorityUnavailable('Authority C02 consumer lacks its actual full typed-semantic original EOF')
    return work.c02_bundle_original.require_current_v3(work,operation_id)
