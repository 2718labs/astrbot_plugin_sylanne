"""Actual GraphStore delta evidence; it grants no business or Source authority."""
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import GraphCandidate,GraphReceipt,OWNER_GRANT_TYPE
from ..segmented_sql_cell_v1 import CODECS
from ..runtime_contracts import FenceScope,QueryEpoch,canonical_serialize
from ..runtime_storage_v3 import runtime_storage_v3,runtime_storage_quantum_v3,_operation
from .current_graph_full_read_v3 import PreparedCurrentGraphFullReadV3

_AUXILIARY_METADATA_ONLY_TYPES_V3=frozenset({
    'd08.communication_intent_grant.v1','d09.natural_verified_segment_batch.v2',
    'd09.natural_verified_segment_batch.v3','d09.verified_segment_batch.v1','runtime.outbox'})
_PROVISIONAL_TYPES_V3=frozenset({'d08.goal.v1','d08.action_intent.v1','d08.action_schema.v1','d08.action_cancellation.v1'})
_SOURCE_AUTHORITY_TYPES_V3=frozenset({'memory.source','memory.access','d06.source_correction_head.v1',OWNER_GRANT_TYPE})
_HEADER_COLUMNS=('codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
    'payload_sha256','ordered_segment_root','origin_scope_digest')
_ORIGIN_COLUMNS=('origin_digest','selection_digest','role','authority_id','installation_id','namespace_json',
    'operation_id','event_digest','locator_json')
_ISSUER=object()
_CAPTURES=WeakKeyDictionary()
_FACTS=WeakKeyDictionary()


@dataclass(frozen=True)
class _ActualFullWriteRowV3:
    key:object
    revision:int
    valid:bool
    cell_id:str
    before_head:tuple|None
    payload_json:str|None
    seal_header:tuple
    origin_metadata:tuple|None
    metadata_only:bool


@dataclass(frozen=True,eq=False)
class _ActualFullWriteFactsV3:
    base:object
    graph:object
    store:object
    db:object
    namespace:object
    work:object
    operation:object
    writer_scope:object
    phase:str
    savepoint_name:str|None
    outer_transaction:object
    actual_event_scope:object
    actual_event_id:str
    actual_event_digest:str
    before_stamp:tuple
    after_stamp:tuple
    receipt:object
    rows:tuple
    authority_epochs:tuple
    owner_head:tuple|None
    capture:object
    auxiliary_metadata_only_types:frozenset=_AUXILIARY_METADATA_ONLY_TYPES_V3
    coverage_kind:str='base_full_eof_plus_actual_delta'
    def _identity_v3(self):
        values=tuple(getattr(self,name)for name in _ActualFullWriteFactsV3.__dataclass_fields__ if name!='rows')
        return values,tuple(tuple(getattr(row,name)for name in _ActualFullWriteRowV3.__dataclass_fields__)for row in self.rows)
    @property
    def query(self):return QueryEpoch(self.namespace,'all',self.after_stamp[1].revision)
    def require_current(self,graph,db,namespace):
        identity=_FACTS.get(self)
        if identity is None or identity!=self._identity_v3():
            raise AuthorityUnavailable('FULL actual writer facts were not issued or have been invalidated')
        capture=self.capture
        capture._actual_v3()
        if (capture._facts is not self or graph is not self.graph or db is not self.db or namespace!=self.namespace
                or not db.in_transaction or not self.store._lock._is_owned()
                or graph._v2_graph_stamp(namespace)!=self.after_stamp
                or self.phase=='provisional' and capture._savepoint_name!=self.savepoint_name
                or self.phase=='applied_transaction' and not capture._writer_active):
            raise AuthorityUnavailable('actual FULL writer/savepoint/outer transaction lifetime changed')
        with runtime_storage_quantum_v3(db)as meter:
            if capture._authority_heads_v3(meter)!=(self.authority_epochs,self.owner_head):
                raise AuthorityUnavailable('Source access/delete or Owner changed after actual FULL delta')
            for row in self.rows:
                if capture._head_v3(meter,row.key)!=(row.revision,int(row.valid),row.cell_id):
                    raise AuthorityUnavailable('actual FULL delta head differs from its writer original')
        return self


class _FullReadWriteCaptureV3:
    def __init__(self,issuer,base,graph,scope,capability,candidate,phase):
        if issuer is not _ISSUER:raise TypeError('actual GraphStore FULL capture issuer required')
        self.base,self.graph,self.store,self.db=base,graph,graph._GraphCoordinator__store,base.db
        self.namespace,self.work,self.operation=base.namespace,base.work,base.operation
        self.writer_scope,self.capability,self.candidate,self.phase=scope,capability,candidate,phase
        self.outer_transaction=object();self._savepoint_name=None;self._staged_candidate=None
        self._writer_active=False;self._facts=None;self._before_heads=None;self._before_stamp=None
        self._prepared=None;self._active_candidate=None;self.closed=False;self._used=False
        _CAPTURES[self]=(base,graph,self.store,self.db,self.namespace,self.work,self.operation,scope,capability,candidate,phase,self.outer_transaction)
    @property
    def provisional_proof(self):return self._facts if self.phase=='provisional' else None
    def _actual_v3(self):
        if self.closed or _CAPTURES.get(self)!=(self.base,self.graph,self.store,self.db,self.namespace,self.work,self.operation,
                self.writer_scope,self.capability,self.candidate,self.phase,self.outer_transaction):
            raise AuthorityUnavailable('actual originating FULL writer capture changed or ended')
        self.base._actual()
        self.store._require_recovery_capability(self.capability)
        if (self.db is not self.store._db or not self.db.in_transaction or not self.store._lock._is_owned()
                or runtime_storage_v3(self.db)is not self.operation.handle or _operation(self.operation.handle)is not self.operation):
            raise AuthorityUnavailable('actual FULL writer requires its same retained operation and transaction')
    def _head_v3(self,meter,key):
        return meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
            'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,key.token))
    def _authority_heads_v3(self,meter):
        from ..graph_types import owner_grant_key
        epochs=meter.read_fixed_row(self.db,'graph_authority_epochs',('access_epoch','delete_epoch'),
            'bot=? AND persona=?',self.namespace.as_tuple)
        owner=self._head_v3(meter,owner_grant_key(*self.namespace.as_tuple))
        return epochs,owner
    def _supported_key_v3(self,key):
        if key.owner.bot!=self.namespace.bot_id or key.owner.persona!=self.namespace.persona_id:
            raise AuthorityUnavailable('FULL writer delta crosses its original namespace')
        if (key.type_name in _SOURCE_AUTHORITY_TYPES_V3 or key.type_name not in
                self.base.projection._types|_AUXILIARY_METADATA_ONLY_TYPES_V3):
            raise AuthorityUnavailable('FULL delta affects Source/Owner or an unprepared graph type')
    def _begin_savepoint_v3(self,store,business_candidate,staged,name,capability):
        self._actual_v3()
        if (store is not self.store or business_candidate is not self.candidate or capability is not self.capability
                or self.phase!='provisional' or self._savepoint_name is not None or self._used):
            raise AuthorityUnavailable('actual Store-owned provisional FULL savepoint required')
        self._savepoint_name,self._staged_candidate=name,staged
    def _enter_writer_v3(self,store,candidate,prepared,capability):
        self._actual_v3()
        expected=self._staged_candidate if self.phase=='provisional' else self.candidate
        if (store is not self.store or capability is not self.capability or candidate is not expected or self._writer_active or self._used
                or self.phase=='provisional' and self._savepoint_name is None):
            raise AuthorityUnavailable('actual FULL capture must bind this one Store writer invocation')
        self.base.require_current(self.graph,self.db,self.namespace,required_families=self.base.prepared_families)
        self._before_stamp=self.graph._v2_graph_stamp(self.namespace)
        self._active_candidate,self._prepared,self._writer_active=candidate,prepared,True
    def _record_before_v3(self,store,namespace,prepared,invalidation_rows):
        self._actual_v3()
        if not self._writer_active or store is not self.store or tuple(namespace)!=self.namespace.as_tuple or prepared is not self._prepared[4]:
            raise AuthorityUnavailable('actual GraphStore before-head capture requires its active writer')
        from ..graph_types import AtomKey
        keys=tuple(write.key for write,_,_ in prepared)+tuple(AtomKey.from_token(token)for token,_,_ in invalidation_rows)
        for key in keys:self._supported_key_v3(key)
        self.operation.retain(1024+len(keys)*512)
        with runtime_storage_quantum_v3(self.db)as meter:
            if self._authority_heads_v3(meter)!=(self.base.authority_epochs,self.base.owner_head):
                raise AuthorityUnavailable('actual Source access/delete/Owner changed before FULL writer')
            self._before_heads=tuple((key,self._head_v3(meter,key))for key in keys)
    def _receipt_v3(self,db,receipt,original_hook):
        self._actual_v3()
        if db is not self.db or type(receipt)is not GraphReceipt or not self._writer_active:
            raise AuthorityUnavailable('actual GraphStore receipt hook required for FULL delta')
        if receipt.status=='duplicate':
            # Replay has no newly applied delta. Keep the existing current base,
            # never issue an AppliedTransaction proof from an old receipt.
            self.base.require_current(self.graph,db,self.namespace,required_families=self.base.prepared_families)
            if original_hook is not None:original_hook(db,receipt)
            return
        if self._before_heads is None:raise AuthorityUnavailable('actual FULL writer before metadata is missing')
        changed=receipt.revisions+receipt.invalidated
        before=dict(self._before_heads)
        if len(changed)!=len(before) or {item.key for item in changed}!=set(before):
            raise AuthorityUnavailable('actual FULL receipt does not cover the entire Store delta')
        for version in changed:self._supported_key_v3(version.key)
        prepared=self._prepared
        writes={write.key:payload for write,_,payload in prepared[4]}
        write_keys=set(writes);rows=[]
        self.operation.retain(2048+len(changed)*1536)
        with runtime_storage_quantum_v3(db)as meter:
            authority_heads=self._authority_heads_v3(meter)
            if authority_heads!=(self.base.authority_epochs,self.base.owner_head):
                raise AuthorityUnavailable('actual FULL writer changed Source access/delete/Owner')
            for version in changed:
                key=version.key;head=self._head_v3(meter,key)
                valid=key in write_keys
                if head is None or head[:2]!=(version.revision,int(valid)):
                    raise AuthorityUnavailable('actual FULL receipt differs from its written atom head')
                cell_id=head[2]
                header=meter.read_fixed_row(db,'segmented_cells_v1',_HEADER_COLUMNS,'cell_id=?',(cell_id,))
                if (header is None or header[1]!=key.token
                        or valid and header[0]!='canonical-json.ascii.v1' or not valid and header[0] not in CODECS):
                    raise AuthorityUnavailable('actual FULL writer cell seal/codec is absent or differs')
                origin=meter.read_fixed_row(db,'runtime_cell_origins_v3',_ORIGIN_COLUMNS,'origin_digest=?',(header[7],))
                metadata_only=key.type_name in _AUXILIARY_METADATA_ONLY_TYPES_V3 and key.type_name not in self.base.projection._types
                payload=None
                if valid:
                    authority=self.operation.handle.selected.basis.control
                    if (origin is None or origin[:3]!=(header[7],self.operation.selection_digest,'graph')
                            or origin[3:5]!=(authority.authority_id,authority.installation_id)
                            or origin[8]!=canonical_serialize(dict(table='graph_atoms',token=key.token,revision=version.revision))
                            or origin[5]!=canonical_serialize(self.namespace.as_tuple) or origin[6:8]!=(prepared[6][3],prepared[5])
                            or header[2]!=prepared[6][3]):
                        raise AuthorityUnavailable('actual FULL new cell lacks its same-event sealed writer original')
                    if not metadata_only:
                        payload=writes[key]
                        if (type(payload)is not str or len(payload.encode('utf-8'))!=header[3]
                                or sha256(payload.encode('utf-8')).hexdigest()!=header[5]):
                            raise AuthorityUnavailable('actual FULL typed delta differs from validated writer canonical bytes')
                elif before[key] is None or before[key][2]!=cell_id:
                    raise AuthorityUnavailable('actual FULL invalidation replaced its original cell')
                rows.append(_ActualFullWriteRowV3(key,version.revision,valid,cell_id,before[key],payload,tuple(header),
                    None if origin is None else tuple(origin),metadata_only))
        after=self.graph._v2_graph_stamp(self.namespace)
        if after[1]!=receipt.epoch or after==self._before_stamp:
            raise AuthorityUnavailable('actual FULL applied receipt has no matching observed graph stamp')
        event=self._active_candidate.event
        facts=_ActualFullWriteFactsV3(self.base,self.graph,self.store,db,self.namespace,self.work,self.operation,self.writer_scope,
            self.phase,self._savepoint_name,self.outer_transaction,event.scope,event.event_id,prepared[5],self._before_stamp,after,
            receipt,tuple(rows),authority_heads[0],authority_heads[1],self)
        _FACTS[facts]=facts._identity_v3()
        self._facts=facts
        if self.phase=='applied_transaction':
            from .current_graph_full_read_v3 import bind_actual_graph_full_write_v3
            try:
                if original_hook is not None:
                    with bind_actual_graph_full_write_v3(facts):original_hook(db,receipt)
            finally:self._invalidate_v3()
        elif original_hook is not None:
            raise AuthorityUnavailable('provisional FULL stage cannot run a formal receipt hook')
    @contextmanager
    def bind_provisional_v3(self):
        if self.phase!='provisional' or self._facts is None:
            raise AuthorityUnavailable('actual applied SAVEPOINT delta is required before provisional FULL reads')
        from .current_graph_full_read_v3 import bind_actual_graph_full_write_v3
        with bind_actual_graph_full_write_v3(self._facts):yield self._facts
    def _invalidate_v3(self):
        if self._facts is not None:_FACTS.pop(self._facts,None)
        self._facts=None
    def _exit_writer_v3(self):
        if self.phase=='applied_transaction':self._invalidate_v3()
        self._writer_active=False;self._used=True;self._prepared=None
    def _end_savepoint_v3(self):
        self._invalidate_v3();self._savepoint_name=self._staged_candidate=None
    def close(self):
        self._invalidate_v3();_CAPTURES.pop(self,None);self.closed=True
        self._prepared=self._before_heads=self._staged_candidate=self._active_candidate=None
        self.base=self.graph=self.store=self.db=self.work=self.operation=self.candidate=self.writer_scope=None
    def __enter__(self):return self
    def __exit__(self,*exc):self.close()


def begin_full_read_write_capture_v3(base_proof,*,graph,actual_write_scope,capability,candidate,phase):
    """After the caller's existing finalSQL business gates; no new approval."""
    if type(base_proof)is not PreparedCurrentGraphFullReadV3 or type(candidate)is not GraphCandidate:
        raise AuthorityUnavailable('actual ordinary FULL proof and real GraphStore candidate required')
    base_proof.require_current(graph,base_proof.db,base_proof.namespace,required_families=base_proof.prepared_families)
    store=graph._GraphCoordinator__store;store._require_recovery_capability(capability)
    scope=actual_write_scope
    if (type(scope)is not FenceScope or scope.operation!='write' or scope.namespace!=base_proof.namespace
            or scope.authority_namespace!=base_proof.scope.authority_namespace or scope.generation!=base_proof.scope.generation
            or (scope.graph_revision,scope.graph_epoch)!=(base_proof.graph_stamp[0].graph_revision,base_proof.graph_stamp[1])
            or phase not in('provisional','applied_transaction')
            or (candidate.event.scope.bot,candidate.event.scope.persona)!=base_proof.namespace.as_tuple
            or phase=='provisional' and candidate.epochs!=(base_proof.graph_stamp[1],)
            or phase=='applied_transaction' and candidate.epochs not in((),(base_proof.graph_stamp[1],))):
        raise AuthorityUnavailable('actual FULL capture scope/candidate belongs to another write transaction')
    if phase=='provisional' and (len(candidate.writes)!=4 or {write.key.type_name for write in candidate.writes}!=_PROVISIONAL_TYPES_V3
            or any(write.key.owner.kind!='activity' or write.key.owner.subject!=candidate.event.scope.session for write in candidate.writes)):
        raise AuthorityUnavailable('provisional FULL capture requires the actual fixed four D08 activity writes')
    capture=_FullReadWriteCaptureV3(_ISSUER,base_proof,graph,scope,capability,candidate,phase)
    for write in candidate.writes:capture._supported_key_v3(write.key)
    return capture
