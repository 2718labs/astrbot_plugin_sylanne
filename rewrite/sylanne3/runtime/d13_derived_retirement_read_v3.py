"""Named Host Work for expired D13 descriptors; it never opens derived/Source bodies."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import fields,is_dataclass,replace
from weakref import WeakKeyDictionary,WeakSet
import json,secrets,sys
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,owner_grant_key
from ..graph_worker import GraphStorageStepV3,create_graph_storage_work_v3,require_graph_storage_work_admission_v3
from ..runtime_contracts import canonical_digest
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3,runtime_storage_quantum_v3,runtime_storage_v3,
    begin_runtime_cell_read_v3,read_runtime_cell_origin_v3)
from ..domains.d13.derived_block_metadata_v2 import METADATA_TYPE,decode_derived_block_metadata_v2,derived_block_metadata_key_v2
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .first_ingress_v2 import trusted_upper
KIND='d13_derived_retirement_read_v3'
_ISSUER=object()
_READERS=WeakSet()
_CAPS=WeakKeyDictionary()
_WRITES=WeakKeyDictionary()
_RECOVERY_LOCATORS=WeakSet()
_BOUND=ContextVar('d13_derived_retirement_metadata_v3',default=None)
_HEADER=('codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
    'payload_sha256','ordered_segment_root','origin_scope_digest')

def _heap(value):
    result=sys.getsizeof(value)
    if type(value)is dict:result+=sum(_heap(k)+_heap(v)for k,v in value.items())
    elif type(value)in(tuple,list):result+=sum(_heap(v)for v in value)
    elif is_dataclass(value)and not isinstance(value,type):result+=sum(_heap(getattr(value,f.name))for f in fields(value))
    return result

class _CommittedRetirementWriteV3:
    def __init__(self,issuer,graph,scope,metadata,epoch,guard,operation_id,request_digest):
        if issuer is not _ISSUER:raise AuthorityUnavailable('Actual committed D13 retirement locator required')
        self.graph,self.scope,self.metadata,self.epoch=graph,scope,metadata,epoch
        self.fence_observation=guard;self.operation_id,self.request_digest=operation_id,request_digest
        _RECOVERY_LOCATORS.add(self)

class _WorkerReceiptMetadataV3:
    """Only this named retirement row; locator projects four scalar fields."""
    def __init__(self,reader,operation_id,*,full,meter):
        self.reader,self.operation_id,self.full=reader,operation_id,full
        self.key=(*reader.namespace.as_tuple,operation_id);self.where='bot=? AND persona=? AND operation_id=?'
        columns=reader.db.execute('PRAGMA table_info(graph_d13_worker_attempts_v2)').fetchall()
        meter.charge_read(sum(len(row[1].encode())+16 for row in columns))
        self.cell=None
        if any(row[1]=='receipt_json_cell_id'for row in columns):
            row=meter.read_fixed_row(reader.db,'graph_d13_worker_attempts_v2',('receipt_json_cell_id',),self.where,self.key)
            if row is None or row[0]is None:raise AuthorityUnavailable('D13 committed retirement metadata cell is absent')
            self.cell=begin_runtime_cell_read_v3(reader.db,row[0])
            self.total=self.cell.header[3];codec=self.cell.header[0]
            if codec not in('canonical-json.ascii.v1','canonical-json.utf8.v1'):raise AuthorityUnavailable('D13 retirement receipt has another actual codec')
        else:
            meter.require_available(1024)
            row=reader.db.execute('SELECT typeof(receipt_json),length(CAST(receipt_json AS BLOB)) FROM graph_d13_worker_attempts_v2 WHERE '+self.where,self.key).fetchone()
            meter.charge_read(16)
            if row is None or row[0]!='text':raise AuthorityUnavailable('D13 committed retirement metadata TEXT is absent')
            self.total=row[1];codec='canonical-json.ascii.v1'
        if not 0<self.total<=65536:raise AuthorityUnavailable('D13 closed retirement receipt exceeds its actual metadata bound')
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=codec=='canonical-json.ascii.v1')
        self.offset=0;self.fragment=b'';self.body=bytearray()if full else None
        self.buffers={};self.values={};self.complete=False;self.value=None;self.sha256=None
        reader.reserve(self.total*10 if full else 65536)
    def emit(self,event):
        if event.path not in{('schema',),('operation_id',),('metadata_ref',),('metadata_revision',)}:return
        if event.kind=='scalar_start':self.buffers[event.path]=bytearray()
        elif event.kind=='scalar_chunk':
            target=self.buffers[event.path]
            if len(target)+len(event.raw)>16384:raise AuthorityUnavailable('D13 retirement locator scalar exceeds its actual schema bound')
            target.extend(event.raw)
        elif event.kind=='scalar_end':self.values[event.path]=json.loads(self.buffers.pop(event.path))
    def advance(self,meter):
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
        if self.fragment:
            part=self.fragment[:1024];self.parser.feed(part,self.emit)
            if self.body is not None:self.body.extend(part)
            self.fragment=self.fragment[len(part):];return
        if self.cell is not None:chunk=self.cell.read_fragment(meter=meter)
        elif self.offset<self.total:
            chunk,total,kind=read_legacy_sql_cell_fragment_v2(self.reader.db,table='graph_d13_worker_attempts_v2',column='receipt_json',
                where=self.where,parameters=self.key,start=self.offset,length=min(8192,self.total-self.offset),meter=meter)
            if(total,kind)!=(self.total,'text'):raise AuthorityUnavailable('D13 retirement original metadata physical byte identity changed')
            self.offset+=len(chunk)
        else:chunk=None
        if chunk is not None:self.fragment=chunk;return
        result=self.parser.finish()
        if self.cell is not None:
            if (result.sha256,result.byte_count)!=(self.cell.finish(meter=meter),self.total):
                raise AuthorityUnavailable('D13 retirement receipt actual cell EOF differs')
        elif result.byte_count!=self.total:raise AuthorityUnavailable('D13 retirement receipt metadata TEXT EOF differs')
        self.sha256=result.sha256
        self.value=json.loads(self.body)if self.body is not None else dict(self.values)
        self.body=None;self.complete=True;self.reader.reserve()

class _MetadataCellV3:
    def __init__(self,reader,cell_id,token):
        self.reader=reader;self.cell=begin_runtime_cell_read_v3(reader.db,cell_id,erasure_owner_ref=token)
        h=self.cell.header
        if h[0]not in('canonical-json.ascii.v1','canonical-json.utf8.v1')or not 0<h[3]<=65536:
            raise AuthorityUnavailable('D13 retirement requires its actual bounded metadata cell')
        self.origin=read_runtime_cell_origin_v3(reader.db,cell_id,header=h)
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=h[0]=='canonical-json.ascii.v1')
        self.body=bytearray();self.complete=False;self.value=None
        reader.reserve(h[3]*10+65536)
    def advance(self,meter):
        fragment=self.cell.read_fragment(meter=meter)
        if fragment is not None:
            self.parser.feed(fragment,lambda event:None);self.body.extend(fragment);return
        self.cell.finish(meter=meter);self.parser.finish()
        self.value=decode_derived_block_metadata_v2(json.loads(self.body));self.body.clear();self.complete=True
        self.reader.reserve()

class _DerivedRetirementReadV3:
    def __init__(self,issuer,graph,authority,lease,policy,operation,fence,mode,args,now):
        if issuer is not _ISSUER:raise AuthorityUnavailable('Actual private D13 retirement reader required')
        self.graph,self.authority,self.lease,self.policy=graph,authority,lease,policy
        self.operation,self.fence,self.mode,self.args=operation,fence,mode,dict(args)
        self.store,self.db=graph._GraphCoordinator__store,graph._GraphCoordinator__store._db
        self.namespace,self.selection_digest=authority.namespace,operation.selection_digest
        self.graph_stamp=(fence.metadata,fence.epoch)if fence is not None else None
        self.guard=None if fence is None else fence.fence_observation
        self.borrowed=type(fence)is _CommittedRetirementWriteV3
        self.initial_now=self.now=now;self.work=None;self.phase='locator_head'if mode=='retire'else'scope';self.cursor=''
        self.locator_cursor='d13-derived-retire:';self.locator_row=None;self.locators=[]
        self.receipt_reader=self.receipt_row=self.receipt_value=self.receipt_sha256=None
        self.records=[];self.head=self.owner_head=self.epochs=None;self.current=self.original=None
        self.current_header=self.current_origin=None;self.cell=None;self.coverage=None
        self.read_finished=False;self.complete=False;self.proof=None;self.reserved=0
        _READERS.add(self);self.reserve(65536)
    def reserve(self,extra=0):
        values=(self.records,self.head,self.current,self.original,self.current_header,self.current_origin,self.locators,self.receipt_row,self.receipt_value)
        if self.receipt_reader is not None:values+=(self.receipt_reader.body,self.receipt_reader.fragment,self.receipt_reader.values,self.receipt_reader.buffers)
        if self.cell is not None:values+=(self.cell.body,self.cell.value,vars(self.cell.parser))
        amount=_heap(values)+extra+65536
        if amount>self.reserved:self.operation.retain(amount-self.reserved);self.reserved=amount
    def current_scope(self):
        from .d13_paid_product_v1 import _authorize
        _,port,policy,_,_=_authorize(self.graph,self.authority,self.lease)
        if (self not in _READERS or policy is not self.policy or self.work is None or self.work.state is not self
                or self.work.kind!=KIND or self.work.operation is not self.operation or self.operation.closed
                or runtime_storage_v3(self.db)is not self.operation.handle or self.operation.selection_digest!=self.selection_digest):
            raise AuthorityUnavailable('D13 retirement lost its actual installed Work/policy/selection')
        self.work._require_invocation(self.graph)
        self.now=trusted_upper(port.read_ingress_clock(self.graph._GraphCoordinator__scene_clock_policy))
        if self.now>=self.operation.deadline_utc:raise AuthorityUnavailable('D13 retirement original operation deadline expired')
        if self.fence is None:
            return
        if self.borrowed:
            from .d13_paid_original_read_v3 import observe_d13_paid_owner_guard_v3
            if (self.fence not in _RECOVERY_LOCATORS or self.fence.graph is not self.graph
                    or port.validate_fence(self.fence.scope)!=self.fence.scope.permit
                    or observe_d13_paid_owner_guard_v3(self.graph,self.authority,self.fence.scope)!=self.guard):
                raise AuthorityUnavailable('D13 retirement actual committed borrowed WRITE changed')
        elif not self.read_finished:self.graph._validate_read_fence_v3(self.fence)
        with self.store._lock:
            if self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp:
                raise AuthorityUnavailable('D13 retirement metadata/rights stamp changed')
    def heads(self,meter):
        epochs=meter.read_fixed_row(self.db,'graph_authority_epochs',('access_epoch','delete_epoch'),'bot=? AND persona=?',self.namespace.as_tuple)
        owner=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),'token=?',(owner_grant_key(*self.namespace.as_tuple).token,))
        if epochs is None or owner is None or owner[1]!=1:raise AuthorityUnavailable('D13 retirement actual Owner/rights metadata is absent')
        if self.epochs is None:self.epochs,self.owner_head=epochs,owner
        elif epochs!=self.epochs or owner!=self.owner_head:raise AuthorityUnavailable('D13 retirement current Owner/delete/access changed')
    def advance(self,meter):
        self.heads(meter)
        if self.phase=='locator_head':
            row=meter.read_fixed_row(self.db,'graph_d13_worker_attempts_v2',('operation_id','request_digest','attempt_id'),
                "bot=? AND persona=? AND operation_id>? AND operation_id<'d13-derived-retire;' AND receipt_json IS NOT NULL ORDER BY operation_id",
                (*self.namespace.as_tuple,self.locator_cursor))
            if row is None:self.phase='scope';return
            self.locator_row=tuple(row);self.locator_cursor=row[0]
            self.receipt_reader=_WorkerReceiptMetadataV3(self,row[0],full=False,meter=meter);self.phase='locator_scalar';return
        if self.phase=='locator_scalar':
            if not self.receipt_reader.complete:self.receipt_reader.advance(meter);return
            values=self.receipt_reader.value
            if (values.get(('schema',))=='d13.derived-retirement-result.v6'and values.get(('operation_id',))==self.locator_row[0]
                    and values.get(('metadata_ref',))==self.args['token']and values.get(('metadata_revision',))==self.args['expected_revision']+1):
                self.locators.append((self.locator_row,self.receipt_reader.sha256))
                if len(self.locators)>1:raise AuthorityUnavailable('D13 retirement committed metadata locator is not unique')
            self.receipt_reader=None;self.phase='locator_head';self.reserve();return
        if self.phase=='scope':return
        if self.phase=='head':
            if self.mode=='discover':
                row=meter.read_fixed_row(self.db,'graph_atoms',('token','revision','valid','value_cell_id'),
                    'bot=? AND persona=? AND type_name=? AND valid=1 AND token>? ORDER BY token',
                    (*self.namespace.as_tuple,METADATA_TYPE,self.cursor))
                if row is None:self.coverage='family_eof';self.seal();return
            else:
                token=self.args['token'];row=meter.read_fixed_row(self.db,'graph_atoms',('token','revision','valid','value_cell_id'),
                    'token=? AND bot=? AND persona=?',(token,*self.namespace.as_tuple))
                if row is None or row[2]!=1 or row[1]not in(self.args['expected_revision'],self.args['expected_revision']+1):
                    raise AuthorityUnavailable('D13 retirement exact original head is unavailable')
            self.head=tuple(row);self.cell=_MetadataCellV3(self,row[3],row[0]);self.phase='current';return
        if self.phase=='receipt_head':
            operation_id,digest=retirement_identity_v3(self.namespace,self.original,self.args['expected_revision'])
            row=_worker_attempt_metadata_v3(self,operation_id,meter,committed=True)
            if row is None:
                if self.head[1]!=self.args['expected_revision']:raise AuthorityUnavailable('D13 adopted retirement lacks its actual committed worker metadata')
                self.phase='receipt_body';self.seal();return
            if row[1]!=digest:raise AuthorityUnavailable('D13 retirement actual committed request digest differs')
            self.receipt_row=tuple(row);self.receipt_reader=_WorkerReceiptMetadataV3(self,operation_id,full=True,meter=meter)
            self.phase='receipt_body';return
        if self.phase=='receipt_body':
            if not self.receipt_reader.complete:self.receipt_reader.advance(meter);return
            value=self.receipt_reader.value
            if (type(value)is not dict or set(value)!={'schema','operation_id','metadata_ref','metadata_revision','graph_receipt','reclaim',
                    'legacy_v2_history_and_paid_originals','secure_erasure'}or value['schema']!='d13.derived-retirement-result.v6'
                    or value['operation_id']!=self.receipt_row[0]or value['metadata_ref']!=self.head[0]
                    or value['metadata_revision']!=self.args['expected_revision']+1
                    or value['graph_receipt']['status']!='committed'):
                raise AuthorityUnavailable('D13 retirement receipt is outside its exact closed producer result')
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            from ..graph_types import GraphReceipt,GraphVersion
            from ..runtime_contracts import NamespaceId
            receipt=decode_typed_production_value_v1(value['graph_receipt'],GraphReceipt)
            if (receipt.revisions!=(GraphVersion(AtomKey.from_token(self.head[0]),self.args['expected_revision']+1),)
                    or receipt.epoch.revision!=self.receipt_row[5]+1
                    or (receipt.epoch.bot_id,receipt.epoch.persona_id)!=self.namespace.as_tuple
                    or any(NamespaceId.from_key(v.key)!=self.namespace for v in receipt.invalidated)):
                raise AuthorityUnavailable('D13 retirement closed result is outside its actual producer revisions/namespace/epoch')
            if self.locators and self.receipt_reader.sha256!=self.locators[0][1]:
                raise AuthorityUnavailable('D13 committed retirement original metadata SHA changed after actual locator EOF')
            self.receipt_value=value;self.receipt_sha256=self.receipt_reader.sha256;self.receipt_reader=None;self.seal();return
        if self.phase in('current','original_history','retired_history'):
            if not self.cell.complete:self.cell.advance(meter);return
            value=self.cell.value
            if derived_block_metadata_key_v2(value).token!=self.head[0]or value.namespace!=self.namespace:
                raise AuthorityUnavailable('D13 retirement cell changed its exact namespace/key schema')
            if self.phase=='current':
                self.current=value;self.current_header=tuple(self.cell.cell.header);self.current_origin=self.cell.origin
                if self.mode=='discover':
                    if value.conversation_ref==self.authority.audience[0]and value.status in{'standby','active'}and value.expires_at_utc<=self.initial_now:
                        self.records.append((self.head,value,self.current_header,self.current_origin))
                    self.cursor=self.head[0];self.cell=None;self.current=None;self.current_header=self.current_origin=None
                    if len(self.records)==16:self.coverage='bounded_page';self.seal()
                    else:self.phase='head'
                    self.reserve();return
                if value.conversation_ref!=self.authority.audience[0]:raise AuthorityUnavailable('D13 retirement crossed its conversation')
                if self.head[1]==self.args['expected_revision']:
                    self.original=value
                    if value.status not in{'standby','active'}:raise AuthorityUnavailable('D13 retirement cannot create a second retirement')
                    self.seal();return
                if value.status!='retired':raise AuthorityUnavailable('D13 retirement replay changed beyond its one retired revision')
                history=meter.read_fixed_row(self.db,'graph_history',('value_cell_id','valid','event_id'),
                    'token=? AND revision=? AND event_bot=? AND event_persona=?',
                    (self.head[0],self.args['expected_revision'],*self.namespace.as_tuple))
                if history is None or history[1]!=1:raise AuthorityUnavailable('D13 retirement exact original history is absent')
                self.cell=_MetadataCellV3(self,history[0],self.head[0]);self.phase='original_history';return
            if self.phase=='original_history':
                self.original=value
                if value.status not in{'standby','active'}or self.current!=replace(value,status='retired'):
                    raise AuthorityUnavailable('D13 retirement history is outside the exact one original transition')
                operation_id,_=retirement_identity_v3(self.namespace,value,self.args['expected_revision'])
                history=meter.read_fixed_row(self.db,'graph_history',('value_cell_id','valid','event_id'),
                    'token=? AND revision=? AND event_bot=? AND event_persona=?',
                    (self.head[0],self.args['expected_revision']+1,*self.namespace.as_tuple))
                if history is None or history[1:]!=(1,operation_id):raise AuthorityUnavailable('D13 retirement adopted producer differs')
                self.cell=_MetadataCellV3(self,history[0],self.head[0]);self.phase='retired_history';return
            if value!=self.current:raise AuthorityUnavailable('D13 retirement adopted history differs from current metadata')
            self.seal();return
        raise AuthorityUnavailable('Unregistered D13 retirement metadata phase')
    def seal(self):
        if self.phase not in{'receipt_head','receipt_body'}:
            if self.mode=='retire':self.cell=None;self.phase='receipt_head';return
        if self.borrowed:
            if (self.head[1]!=self.args['expected_revision']+1
                    or retirement_identity_v3(self.namespace,self.original,self.args['expected_revision'])!=(
                        self.fence.operation_id,self.fence.request_digest)):
                raise AuthorityUnavailable('D13 retirement recovery locator differs from actual metadata/producer EOF')
        self.cell=None;self.complete=True;self.phase='complete';self.reserve();self.proof=PreparedD13DerivedRetirementV3(_ISSUER,self)

class PreparedD13DerivedRetirementV3:
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER or not reader.complete:raise AuthorityUnavailable('D13 retirement metadata requires actual EOF')
        self.reader=reader;self.used=False;_CAPS[self]=(reader,reader.work,reader.operation,reader.fence,reader.selection_digest)
    def require(self,graph,authority,lease,mode,args):
        r=self.reader
        if (_CAPS.get(self)!=(r,r.work,r.operation,r.fence,r.selection_digest)or not r.read_finished
                or r.graph is not graph or r.authority!=authority or r.lease is not lease or r.mode!=mode or r.args!=args):
            raise AuthorityUnavailable('D13 retirement requires its exact privately issued metadata Work')
        r.current_scope();return r
    def release_payload_v3(self):
        r=self.reader;_CAPS.pop(self,None);_WRITES.pop(self,None);_READERS.discard(r)
        r.records.clear();r.locators.clear();r.current=r.original=r.cell=r.receipt_reader=None
        r.current_header=r.current_origin=r.receipt_row=r.receipt_value=None
        if r.borrowed:_RECOVERY_LOCATORS.discard(r.fence)

def retirement_identity_v3(namespace,metadata,revision):
    digest=canonical_digest({'schema':'d13.derived-retirement.v6','namespace':namespace,
        'block_ref':metadata.block_ref,'revision':revision,'metadata_digest':canonical_digest(metadata)})
    return 'd13-derived-retire:'+digest[:48],digest

@contextmanager
def bind_d13_derived_retirement_v3(proof):
    if type(proof)is not PreparedD13DerivedRetirementV3 or proof not in _CAPS:raise AuthorityUnavailable('Actual D13 retirement capsule required')
    token=_BOUND.set(proof)
    try:yield proof
    finally:_BOUND.reset(token)

def bound_d13_derived_retirement_v3():return _BOUND.get()

def prepare_d13_derived_retirement_v3(graph,authority,lease,*,mode,args):
    from .d13_paid_product_v1 import _authorize
    from .d13_paid_original_read_v3 import observe_d13_paid_owner_guard_v3
    require_graph_storage_work_admission_v3(graph)
    store,port,policy,_,_=_authorize(graph,authority,lease)
    if mode not in{'retire','discover'}or (mode=='retire'and set(args)!={'token','expected_revision'})or(mode=='discover'and args):
        raise AuthorityUnavailable('D13 retirement closed selector differs')
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    operation=begin_runtime_storage_operation_v3(store._db,'d13-derived-metadata:'+secrets.token_hex(24),now+policy.deadline_after_seconds)
    fence=None
    try:
        reader=_DerivedRetirementReadV3(_ISSUER,graph,authority,lease,policy,operation,None,mode,args,now)
        work=create_graph_storage_work_v3(graph,kind=KIND,operation_id=operation.operation_id,selection_digest=operation.selection_digest,
            deadline_utc=operation.deadline_utc,state=reader,operation=operation);reader.work=work
        def completed(proof):
            with bind_runtime_storage_operation_v3(operation,store._db),bind_d13_derived_retirement_v3(proof):
                from .d13_derived_product_v6 import retire_due_d13_derived_graph_v6,discover_due_d13_derived_graph_v6
                if mode=='discover':return discover_due_d13_derived_graph_v6(graph,authority,lease)
                return retire_due_d13_derived_graph_v6(graph,authority,lease,
                    block_ref=AtomKey.from_token(args['token']).name,expected_revision=args['expected_revision'])
        return work.map_terminal_v3('issuer',completed,lambda error:(_ for _ in()).throw(error))
    except BaseException:
        try:
            if fence is not None and type(fence)is not _CommittedRetirementWriteV3:graph._finish_read_fence_v3(fence)
        finally:finish_runtime_storage_operation_v3(operation)
        raise

def advance_d13_derived_retirement_v3(graph,work):
    r=work.state
    with bind_runtime_storage_operation_v3(work.operation,r.db):
        r.current_scope()
        with r.store._lock:
            r.db.execute('BEGIN')
            try:
                with runtime_storage_quantum_v3(r.db)as meter:r.advance(meter)
            finally:r.db.rollback()
        if r.phase=='scope':_begin_d13_retirement_scope_v3(r)
        r.current_scope()
    return GraphStorageStepV3('complete',r.proof)if r.complete else GraphStorageStepV3('progress')

def finish_d13_derived_retirement_v3(graph,work,error):
    r=work.state
    try:
        if r.fence is not None and not r.borrowed:graph._finish_read_fence_v3(r.fence)
        r.read_finished=True
        if error is None:work.result_lease=work.operation
    finally:
        if error is not None or work.result_lease is None:
            if r.proof is not None:r.proof.release_payload_v3()
            _READERS.discard(r);finish_runtime_storage_operation_v3(work.operation)

def observe_d13_retirement_write_v3(graph,authority,scope,proof,operation_id,request_digest):
    from .d13_paid_original_read_v3 import observe_d13_paid_owner_guard_v3
    r=proof.require(graph,authority,proof.reader.lease,'retire',proof.reader.args)
    if not proof.used or retirement_identity_v3(r.namespace,r.original,r.args['expected_revision'])!=(operation_id,request_digest):
        raise AuthorityUnavailable('D13 retirement WRITE is outside its exact original producer identity')
    guard=observe_d13_paid_owner_guard_v3(graph,authority,scope)
    if guard!=r.guard or scope.operation!='write' or scope.namespace!=r.namespace:
        raise AuthorityUnavailable('D13 retirement fresh WRITE changed the actual original Owner')
    _WRITES[proof]=(scope,guard);return guard

def require_d13_retirement_write_in_tx_v3(graph,db,authority,scope,proof,metadata,epoch,now):
    r=proof.reader
    if (_CAPS.get(proof)!=(r,r.work,r.operation,r.fence,r.selection_digest)or _WRITES.get(proof)!=(scope,r.guard)
            or not proof.used or db is not r.db or not db.in_transaction or graph is not r.graph or authority!=r.authority
            or (metadata,epoch)!=r.graph_stamp or runtime_storage_v3(db)is not r.operation.handle
            or r.operation.closed or now>=r.operation.deadline_utc or now<r.original.expires_at_utc):
        raise AuthorityUnavailable('D13 retirement fresh WRITE lost its actual sealed metadata/current scope')
    with runtime_storage_quantum_v3(db)as meter:
        r.heads(meter)
        head=meter.read_fixed_row(db,'graph_atoms',('token','revision','valid','value_cell_id'),
            'token=? AND bot=? AND persona=?',(r.args['token'],*r.namespace.as_tuple))
        header=meter.read_fixed_row(db,'segmented_cells_v1',_HEADER,'cell_id=?',(r.head[3],))
        if head!=r.head or header!=r.current_header or read_runtime_cell_origin_v3(db,r.head[3],header=header,meter=meter)!=r.current_origin:
            raise AuthorityUnavailable('D13 retirement current cell/origin/revision differs from its actual metadata EOF')
    return r.original

def require_d13_retirement_producer_v3(graph,authority,proof,operation_id,request_digest):
    if type(proof)is not PreparedD13DerivedRetirementV3:raise AuthorityUnavailable('Actual D13 retirement capsule required')
    r=proof.require(graph,authority,proof.reader.lease,'retire',proof.reader.args)
    if not proof.used or retirement_identity_v3(r.namespace,r.original,r.args['expected_revision'])!=(operation_id,request_digest):
        raise AuthorityUnavailable('D13 retirement producer differs from its exact metadata EOF and selected original')
    return r

def _begin_d13_retirement_scope_v3(r):
    from ..authority_service.v2_contract import from_wire
    from ..runtime.restore_anchor import RestoreAnchor
    from ..graph_types import NamespaceEpoch
    from ..graph_coordinator import FenceScope
    from .d13_paid_original_read_v3 import observe_d13_paid_owner_guard_v3
    port=r.graph._GraphCoordinator__content_fence_v2
    if r.locators:
        operation_id,digest,attempt_id=r.locators[0][0]
        with r.store._lock:
            r.db.execute('BEGIN')
            try:
                with runtime_storage_quantum_v3(r.db)as meter:
                    full_row=_worker_attempt_metadata_v3(r,operation_id,meter,committed=True)
                    if full_row is None or full_row[:3]!=(operation_id,digest,attempt_id):
                        raise AuthorityUnavailable('D13 committed locator original operation tuple changed')
                    row=(full_row[3],full_row[4],full_row[5],full_row[6],full_row[7],full_row[8])
            finally:r.db.rollback()
        if row is None or any(v is None for v in row):raise AuthorityUnavailable('D13 committed locator original WRITE metadata disappeared')
        permit=from_wire(json.loads(row[3]));anchor=RestoreAnchor(**json.loads(row[0]))
        observed,state=port.get_fence_operation(namespace=r.namespace,authority_namespace=anchor.namespace,operation_id=attempt_id)
        expected='d13-worker-'+canonical_digest({'operation_id':operation_id,'request_digest':digest,'namespace':r.namespace.as_tuple})[:48]
        finish='sha256:'+canonical_digest({'action':'finish_d13_worker','operation_id':operation_id,'permit_token':permit.token})
        if (observed!=permit or state not in{'active','finished'}or permit.operation!='write' or permit.operation_id!=attempt_id
                or permit.generation!=r.authority.activation_generation or permit.namespace!=anchor.namespace
                or permit.holder!=r.graph._GraphCoordinator__holder or permit.subject!=port.installation_grant.subject
                or permit.pinned_anchor!=anchor or attempt_id!=expected or row[4:]!=('finish:'+attempt_id,finish)):
            raise AuthorityUnavailable('D13 committed locator changed its actual original WRITE/finish identity')
        if state=='active':
            with r.store._lock:metadata,epoch=r.graph._v2_graph_stamp(r.namespace)
            if (metadata.graph_revision,epoch.revision)!=(row[1]+1,row[2]+1)or not r.graph._anchor_matches(metadata.requirements,anchor):
                raise AuthorityUnavailable('D13 committed recovery is outside its exact one original COMMIT')
            scope=FenceScope(r.namespace,anchor.namespace,r.authority.activation_generation,'write',attempt_id,permit,anchor,
                NamespaceEpoch(*r.namespace.as_tuple,row[2]),row[1])
            if port.validate_fence(scope)!=permit:raise AuthorityUnavailable('D13 actual committed WRITE permit changed')
            guard=observe_d13_paid_owner_guard_v3(r.graph,r.authority,scope)
            r.fence=_CommittedRetirementWriteV3(_ISSUER,r.graph,scope,metadata,epoch,guard,operation_id,digest);r.borrowed=True
    if r.fence is None:
        r.fence=r.graph._begin_read_fence_v3(r.authority,operation_id=r.operation.operation_id,
            fence_observer=lambda scope:observe_d13_paid_owner_guard_v3(r.graph,r.authority,scope))
    r.graph_stamp=(r.fence.metadata,r.fence.epoch);r.guard=r.fence.fence_observation;r.phase='head'

def replay_d13_retirement_metadata_v3(graph,authority,proof,operation_id,request_digest):
    from ..authority_service.v2_contract import from_wire
    from ..runtime.restore_anchor import RestoreAnchor
    from ..graph_types import NamespaceEpoch
    from ..graph_coordinator import FenceScope
    r=require_d13_retirement_producer_v3(graph,authority,proof,operation_id,request_digest)
    if r.receipt_row is None:return None
    row=r.receipt_row;permit=from_wire(json.loads(row[6]));anchor=RestoreAnchor(**json.loads(row[3]))
    port=graph._GraphCoordinator__content_fence_v2
    observed,state=port.get_fence_operation(namespace=r.namespace,authority_namespace=anchor.namespace,operation_id=row[2])
    if (row[:2]!=(operation_id,request_digest)or observed!=permit or state not in{'active','finished'}or permit.pinned_anchor!=anchor):
        raise AuthorityUnavailable('D13 retirement actual original replay WRITE differs')
    if state=='active':
        scope=FenceScope(r.namespace,anchor.namespace,authority.activation_generation,'write',row[2],permit,anchor,
            NamespaceEpoch(*r.namespace.as_tuple,row[5]),row[4])
        if port.validate_fence(scope)!=permit:raise AuthorityUnavailable('D13 retirement replay permit changed')
        port.finish_fence(scope,request_id=row[7],request_digest=row[8])
    return r.receipt_value

def _worker_attempt_metadata_v3(r,operation_id,meter,*,committed):
    where='bot=? AND persona=? AND operation_id=?'+(' AND receipt_json IS NOT NULL'if committed else '')
    key=(*r.namespace.as_tuple,operation_id)
    meter.require_available(1024)
    lengths=r.db.execute('SELECT length(CAST(anchor_json AS BLOB)),length(CAST(permit_json AS BLOB)) FROM graph_d13_worker_attempts_v2 WHERE '+where,key).fetchone()
    meter.charge_read(16)
    if lengths is None:return None
    if any(v is None or v>32768 for v in lengths):raise AuthorityUnavailable('D13 original WRITE metadata exceeds its closed anchor/permit bound')
    meter.require_available(sum(lengths)+4096);r.reserve(sum(lengths)*10+65536)
    return meter.read_fixed_row(r.db,'graph_d13_worker_attempts_v2',
        ('operation_id','request_digest','attempt_id','anchor_json','pre_graph_revision','pre_graph_epoch','permit_json','finish_request_id','finish_request_digest'),where,key)
