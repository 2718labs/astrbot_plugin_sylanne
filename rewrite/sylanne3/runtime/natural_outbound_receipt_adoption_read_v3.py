"""Named SourceALL READ for an already observed outbound fact; no frozen input."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass,asdict
from time import monotonic, monotonic_ns
from types import SimpleNamespace
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.v2_contract import MutationReceiptV2, PlatformObservationV2
from ..authority_service.observation_refinement_contract_v3 import (
    PlatformObservationRefinementReceiptV3,observation_platform_observation_v3)
from ..graph_types import AtomKey, GraphAtom, GraphVersion,NamespaceEpoch
from ..runtime_contracts import FenceScope, canonical_digest, NamespaceId,QueryEpoch
from ..runtime_storage_v3 import (runtime_storage_v3,runtime_storage_quantum_v3,
    begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,finish_runtime_storage_operation_v3)
from ..graph_worker import (GraphStorageStepV3,create_graph_storage_work_v3,require_graph_storage_work_admission_v3)
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .natural_dispatch_locator_metadata_v1 import _FIELD_V1,_OBJECT_FIELDS_V1,_ARRAY_PATHS_V1
from .c09_canonical_json_stream_v2 import _CanonicalJSONValueBuilderV3
from .first_ingress_v2 import trusted_upper_at_v4
from .source_correction_read_v3 import _heap
KIND='natural_outbound_receipt_adoption_read_v3'
_ISSUER=object()
_READERS=WeakKeyDictionary()
_PROOFS=WeakKeyDictionary()
_REPLAYS=WeakKeyDictionary()
_BOUND=ContextVar('natural_outbound_receipt_adoption_exact_writer_v3',default=None)

class _AdoptionJSONColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self,owner,**arguments):
        super().__init__(owner,**arguments)
        self.source_original=None;self.semantic_decoder=self.semantic_hash=None
        if self.cell is not None:
            from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
            if self.cell.header[0]not in('canonical-json.ascii.v1','canonical-json.utf8.v1'):
                raise AuthorityUnavailable('outbound original has another actual JSON codec')
            self.parser=C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0]=='canonical-json.ascii.v1')
            if self.table=='graph_atoms'and AtomKey.from_token(self.key[0]).type_name=='memory.source':
                if not owner.qualified:
                    raise AuthorityUnavailable('outbound Source Body requires the actual complete Source family')
                self.source_original=owner.source_inspection_tasks[self.key[0]].result
                if self.cell.header[0]=='canonical-json.utf8.v1':
                    import codecs
                    from hashlib import sha256
                    self.semantic_decoder=codecs.getincrementaldecoder('utf-8')('strict')
                    self.semantic_hash=sha256()

    def advance(self,meter):
        if self.source_original is not None:
            self.source_original.require_v3(self.owner,meter)
            if not self.complete and self.fragment_offset<len(self.fragment)and self.semantic_decoder is not None:
                from .d13_natural_original_sources_v3 import _NaturalOriginalSourceAllReadV3
                end=min(self.fragment_offset+1024,len(self.fragment))
                _NaturalOriginalSourceAllReadV3._semantic_body_fragment_v3(self,
                    self.fragment[self.fragment_offset:end],meter)
        completed=super().advance(meter)
        if completed and self.source_original is not None:
            if self.semantic_decoder is not None:
                from .d13_natural_original_sources_v3 import _NaturalOriginalSourceAllReadV3
                _NaturalOriginalSourceAllReadV3._semantic_body_fragment_v3(self,b'',meter,final=True)
                semantic=self.semantic_hash.hexdigest()
            else:semantic=self.sha256
            from ..memory_types import SourceRecord
            from ..domains.d06.inspection_metadata_v1 import SOURCE_FIELDS
            record=SourceRecord.from_dict(self.require_v3(self.owner));data=record.to_dict()
            metadata={name:tuple(data[name])if type(data[name])is list else data[name]for name in SOURCE_FIELDS}
            original=self.source_original
            if (tuple(self.cell.header)!=original.header or self.sha256!=original.payload_sha256
                    or semantic!=original.semantic_digest or metadata!=dict(original.metadata)):
                raise AuthorityUnavailable('outbound qualified Source Body differs from inspection original')
        return completed

class _ReceiptMetadataColumnV3(_AdoptionJSONColumnV3):
    def _emit(self,event):
        if not event.path:
            if event.kind not in ('object_start','object_end'):
                raise AuthorityUnavailable('outbound receipt must be its canonical object')
            return _CanonicalJSONValueBuilderV3._emit(self,event)
        if event.path[0]==_FIELD_V1:
            if event.path==(_FIELD_V1,)and event.kind=='key':
                return _CanonicalJSONValueBuilderV3._emit(self,event)
            pattern=tuple('*'if type(value)is int else value for value in event.path[1:])
            if event.kind=='object_start'and pattern not in _OBJECT_FIELDS_V1:
                raise AuthorityUnavailable('outbound locator contains an undeclared metadata object')
            if event.kind=='array_start'and pattern not in _ARRAY_PATHS_V1:
                raise AuthorityUnavailable('outbound locator contains an undeclared metadata array')
            if event.kind=='key'and event.key not in _OBJECT_FIELDS_V1.get(pattern[:-1],()):
                raise AuthorityUnavailable('outbound locator contains an undeclared metadata field')
            return _CanonicalJSONValueBuilderV3._emit(self,event)
        if event.path[0]in('natural_dispatch_candidate','dispatch_candidate'):
            allowed=('schema','status','refs','source_refs','digest','graph_epoch','graph_incarnation',
                'graph_revision','access_epoch','delete_epoch','query_epoch','batch_digest')
            if len(event.path)>1 and event.path[1]not in allowed:return
            return _CanonicalJSONValueBuilderV3._emit(self,event)

class _SlotMetadataColumnV3:
    """One reusable metadata decode peak; unrelated slot Body is never retained."""
    def __init__(self,owner,*,table,column,key_columns,key,cell_id):
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        if(table,column,key_columns)!=('graph_atoms','value',('token',))or cell_id is None:
            raise AuthorityUnavailable('slot metadata needs its actual selected Graph cell')
        self.owner=owner;self.cell=begin_runtime_cell_read_v3(owner.db,cell_id,erasure_owner_ref=key[0])
        if self.cell.header[0]not in('canonical-json.ascii.v1','canonical-json.utf8.v1'):
            raise AuthorityUnavailable('slot metadata requires its actual registered JSON codec')
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0]=='canonical-json.ascii.v1')
        self.fragment=b'';self.scalar=bytearray();self.value={};self.complete=False
    def _emit(self,event):
        if event.path not in(('origin_ref',),('scene_ref',),('conversation_ref',),('sequence',)):return
        if event.kind=='scalar_start':self.scalar.clear()
        elif event.kind=='scalar_chunk':
            if len(self.scalar)+len(event.raw)>8192:raise AuthorityUnavailable('slot metadata scalar exceeds its fixed profile')
            self.scalar.extend(event.raw)
        elif event.kind=='scalar_end':
            import json
            self.value[event.path[0]]=json.loads(self.scalar);self.scalar.clear()
    def advance(self,meter):
        self.owner.require_current_v3(meter)
        self.owner.reserve_slot_scratch_v3(_heap((self.fragment,self.scalar,self.value))+65536)
        if self.fragment:
            part,self.fragment=self.fragment[:1024],self.fragment[1024:];self.parser.feed(part,self._emit);return False
        raw=self.cell.read_fragment(meter=meter)
        if raw is not None:self.fragment=raw;return False
        parsed=self.parser.finish()
        if(parsed.sha256,parsed.byte_count)!=(self.cell.finish(meter=meter),self.cell.header[3]):
            raise AuthorityUnavailable('actual slot metadata whole canonical EOF changed')
        self.sha256,self.byte_count=parsed.sha256,parsed.byte_count;self.complete=True;return True
    def require_v3(self,owner):
        if owner is not self.owner or not self.complete or set(self.value)!={'origin_ref','scene_ref','conversation_ref','sequence'}:
            raise AuthorityUnavailable('actual complete slot metadata EOF required')
        return self.value

@dataclass(frozen=True,slots=True)
class _QualifiedSourceMetadataV3:
    revision:int
    metadata:object
    payload_sha256:str

class _AdoptionProjectionV3:
    def __init__(self,reader):self.reader=reader
    def get(self,key):return self.reader.atoms.get(key.token)
    def atoms_for_types_v3(self,kinds):return tuple(atom for atom in self.reader.atoms.values()if atom.key.type_name in kinds)

def _actual_receipt_adoption_kind_v3(reader):
    if type(reader)is NaturalOutboundReceiptAdoptionReadV3:return KIND
    from .artifact_outbound_receipt_adoption_read_v3 import ArtifactOutboundReceiptAdoptionReadV3,KIND as ARTIFACT_KIND
    if type(reader)is ArtifactOutboundReceiptAdoptionReadV3:return ARTIFACT_KIND
    raise AuthorityUnavailable('receipt fact IO requires its exact installed named reader class')

class NaturalOutboundReceiptAdoptionReadV3:
    def __init__(self,graph,bootstrap,namespace,final_operation_id,observed):
        require_graph_storage_work_admission_v3(graph);graph._admin(bootstrap)
        if type(namespace)is not NamespaceId:raise AuthorityUnavailable('outbound fact READ needs actual namespace')
        self.graph,self.bootstrap,self.namespace=graph,bootstrap,namespace
        self.store=graph._GraphCoordinator__store;self.db=self.store._db;self.storage=runtime_storage_v3(self.db)
        if self.storage is None or self.storage.purpose!='business':raise AuthorityUnavailable('actual selected runtime storage required')
        self.port=graph._GraphCoordinator__content_fence_v2
        self.final_operation_id=self.selected_operation_id=final_operation_id
        self.scope=self.operation=self.work=None
        with self.store._lock,self.storage.quantum()as meter:
            if self.db.in_transaction:raise AuthorityUnavailable('outbound READ cannot inherit Graph transaction')
            self.graph_stamp=graph._v2_graph_stamp(namespace)
            self.bundle_header=meter.read_fixed_row(self.db,'graph_bundle_operations',('activity_id','effect_id','digest'),
                'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,final_operation_id))
        if self.bundle_header is None:raise AuthorityUnavailable('actual committed final bundle absent')
        self.selected_activity_id,self.selected_effect_id=self.bundle_header[:2]
        actual=self._current_observation_v3()
        if observed is not None and canonical_digest(observed)!=canonical_digest(actual):raise AuthorityUnavailable('caller observation differs from current Core original')
        self.observed=actual;self.observation_digest=canonical_digest(actual)
        self.reading=self.port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
        self.now_utc=trusted_upper_at_v4(self.reading,monotonic());target=self.graph_stamp[0].requirements
        anchor=self.port.current_anchor(namespace=namespace,authority_namespace=target.authority_namespace)
        if not graph._accounting_anchor_covers(target,anchor):raise AuthorityUnavailable('actual Authority anchor differs')
        profile=_actual_receipt_adoption_kind_v3(self)
        op=profile+':'+canonical_digest((namespace,final_operation_id,self.observation_digest,monotonic_ns()))[:48]
        try:
            permit=self.port.begin_fence(namespace=namespace,authority_namespace=target.authority_namespace,
                holder=graph._GraphCoordinator__holder,generation=target.activation_generation,operation='read',
                operation_id=op,expected_anchor=anchor,retain_on_unknown=True)
            self.scope=FenceScope(namespace,target.authority_namespace,target.activation_generation,'read',op,
                permit,anchor,self.graph_stamp[1],self.graph_stamp[0].graph_revision)
            if self.port.validate_fence(self.scope)!=permit:raise AuthorityUnavailable('actual fresh READ permit changed')
            self.operation=begin_runtime_storage_operation_v3(self.db,op,None)
            self.query=QueryEpoch(namespace,'all',self.graph_stamp[1].revision);self.selection_digest=self.operation.selection_digest
            self.family=None;self.candidate_metadata=self.receipt_metadata=self.locator=None
            self.scoped_proof=self.named_original=self.recovered=None
            self.sources,self.source_heads,self.access_atoms={},{},{}
            self.source_payload_sha256,self.frozen_versions={},{}
            self.pending_sources,self.column=[],None;self.qualified=self.complete=self.read_finished=False
            self.source_inspection_tasks={}
            self.atoms,self.heads,self.columns,self.history_rows={},{},{},{}
            self.queue,self.current=[],None;self.phase,self.control_after,self.slot_after='receipt_metadata','',''
            self.slot_ref=self.outbox_ref=None;self.reserved=self.slot_scratch_peak=0;self.projection=_AdoptionProjectionV3(self)
            self.proof=self.admission_originals=self.admission_task=None;self.write_observation=None;self.saved_header=None
            self.saved_natural_parent=self.saved_natural_headers=self.saved_locator_digest_stream=None
            self._advance_head_memo_v2=None
            self.receipt_column=_ReceiptMetadataColumnV3(self,table='graph_bundle_operations',column='receipt_json',
                key_columns=('bot','persona','operation_id'),key=(*namespace.as_tuple,final_operation_id))
            self.reserve_v3()
            _READERS[self]=(graph,bootstrap,namespace,final_operation_id,self.scope,self.operation,self.graph_stamp,self.observation_digest)
        except BaseException:
            try:
                if self.scope is not None:self.port.finish_fence(self.scope,request_id='finish:'+op,
                    request_digest='sha256:'+canonical_digest((op,'outbound-fact-read-closed')))
            finally:finish_runtime_storage_operation_v3(self.operation)
            raise

    def _current_observation_v3(self):
        actual=self.port.read_current_observation_receipt_v1(namespace=self.namespace,
            authority_namespace=self.graph_stamp[0].requirements.authority_namespace,effect_id=self.selected_effect_id)
        if type(actual) not in (MutationReceiptV2,PlatformObservationRefinementReceiptV3) or actual.durable_state!='committed':
            raise AuthorityUnavailable('independent committed Core observation required')
        platform=observation_platform_observation_v3(actual)
        if type(platform) is not PlatformObservationV2:raise AuthorityUnavailable('actual V2 handoff observation required')
        origin=platform.binding.origin
        if((origin.operation_id,origin.effect_id)!=(self.final_operation_id,self.selected_effect_id)
                or platform.outcome not in('accepted','unknown','delivered')):raise AuthorityUnavailable('actual final/effect/outcome differs')
        return actual

    def reserve_v3(self,extra=0):
        amount=_heap((self.atoms,self.heads,self.source_heads,self.source_payload_sha256,
            tuple(source.metadata for source in self.sources.values()),self.access_atoms,self.receipt_metadata,self.queue))+extra+65536
        if amount>self.reserved:self.operation.retain(amount-self.reserved);self.reserved=amount

    def reserve_slot_scratch_v3(self,size):
        if size>self.slot_scratch_peak:
            self.operation.retain(size-self.slot_scratch_peak);self.slot_scratch_peak=size

    def require_current_v3(self,meter=None):
        if(_READERS.get(self)!=(self.graph,self.bootstrap,self.namespace,self.final_operation_id,self.scope,self.operation,self.graph_stamp,self.observation_digest)
                or self.operation.closed or self.work is None or self.work.state is not self or self.work.operation is not self.operation
                or self.work.kind!=_actual_receipt_adoption_kind_v3(self) or runtime_storage_v3(self.db)is not self.operation.handle):raise AuthorityUnavailable('actual named Work/retention/selection changed')
        self.work._require_invocation(self.graph);self.graph._admin(self.bootstrap)
        if self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp:raise AuthorityUnavailable('current Graph/Source stamp changed')
        self.now_utc=trusted_upper_at_v4(self.reading,monotonic())
        if self.db.in_transaction:
            with runtime_storage_quantum_v3(self.db)as current:
                if meter is not None and current is not meter:raise AuthorityUnavailable('actual Graph quantum changed')
                from .graph_d13_cache_use_collection_v2 import require_current_metadata_heads_v3
                current.require_available((len(self.source_heads)+len(self.heads))*128+256)
                expected=dict(self.source_heads)
                for token,head in self.heads.items():
                    if token in expected and expected[token]!=head:
                        raise AuthorityUnavailable('current writer head cannot replace original Source EOF')
                    expected[token]=head
                self._advance_head_memo_v2=require_current_metadata_heads_v3(self.db,self.namespace,
                    expected,current,self._advance_head_memo_v2)
        return self

    def _enqueue(self,tag,table,column,keys,key,cell_id=None,kind='json'):self.queue.append((tag,table,column,keys,key,cell_id,kind))
    def _advance_queue(self,meter):
        if self.current is not None:
            tag,column,kind=self.current
            if column.advance(meter):
                value=column.require_v3(self);self.columns[tag]=(column,value)
                if kind=='atom':
                    key=AtomKey.from_token(tag[5:]);head=self.heads[key.token];self.atoms[key.token]=GraphAtom(key,head[0],value,bool(head[1]))
                self.current=None
            return False
        if not self.queue:return True
        tag,table,column,keys,key,cell_id,kind=self.queue.pop(0)
        cls=_SlotMetadataColumnV3 if kind=='slot_metadata'else _AdoptionJSONColumnV3
        self.current=(tag,cls(self,table=table,column=column,key_columns=keys,key=key,cell_id=cell_id),kind);return False
    def _value(self,tag):return self.columns[tag][1]
    def _atom(self,key,meter,*,optional=False):
        if key.token in self.heads:return
        head=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
            'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,key.token));self.heads[key.token]=head
        if head is None:
            if optional:return
            raise AuthorityUnavailable('exact current atom absent')
        if head[1]!=1:raise AuthorityUnavailable('exact current atom invalid')
        self._enqueue('atom:'+key.token,'graph_atoms','value',('token',),(key.token,),head[2],'atom')

    def _metadata(self,meter):
        raw=self.receipt_column.require_v3(self);self.receipt_metadata=raw
        natural,named=raw.get('natural_dispatch_candidate'),raw.get('dispatch_candidate')
        if(natural is None)==(named is None):raise AuthorityUnavailable('one exact supported final candidate family required')
        self.family='natural'if natural is not None else'commitment_literal';self.candidate_metadata=natural if natural is not None else named
        candidate=self.candidate_metadata
        if(type(candidate)is not dict or type(candidate.get('source_refs'))is not list or not candidate['source_refs']
                or len(candidate['source_refs'])>256 or type(candidate.get('refs'))is not list or len(candidate['refs'])!=4):raise AuthorityUnavailable('actual candidate metadata incomplete')
        origin=observation_platform_observation_v3(self.observed).binding.origin
        self.admission_ref=origin.admission_ref;self.authority=SimpleNamespace(audience=(origin.destination_ref,))
        if self.family=='natural':
            from .natural_dispatch_locator_metadata_v1 import _META_KEYS_V1,_RECIPE_KEYS_V1,_OBJECT_FIELDS_V1
            locator=raw.get(_FIELD_V1)
            if(type(locator)is not dict or set(locator)!=_OBJECT_FIELDS_V1[()]or locator['schema']!='sylanne.natural_dispatch_read_locator.v1'
                    or type(locator['metadata'])is not dict or set(locator['metadata'])!=_META_KEYS_V1):raise AuthorityUnavailable('committed metadata-only natural locator absent')
            self.locator=locator;metadata=locator['metadata'];recipe=metadata['recipe']
            if(set(recipe)!=_RECIPE_KEYS_V1 or recipe['kind']!='unsealed_producer_metadata_recipe'
                    or metadata['namespace']!={'bot_id':self.namespace.bot_id,'persona_id':self.namespace.persona_id}
                    or(metadata['operation_id'],metadata['activity_id'],metadata['effect_id'],metadata['bundle_digest'])
                        !=(self.final_operation_id,self.selected_activity_id,self.selected_effect_id,self.bundle_header[2])
                    or metadata['admission_ref']!=self.admission_ref or metadata['candidate_digest']!=candidate['digest']
                    or recipe['admission']['audience']!=[origin.destination_ref]):raise AuthorityUnavailable('natural locator differs from actual final/Core/admission route')
            parent=recipe['generation_parent_original_id'];self.parent_original_id=parent
            header=meter.read_fixed_row(self.db,'graph_natural_generation_preparations_v2',
                ('original_operation_id','state','graph_epoch','access_epoch','deletion_epoch'),
                'bot=? AND persona=? AND parent_original_id=?',(*self.namespace.as_tuple,parent))
            if header is None or header[0]!=recipe['generation_original_operation_id']or header[1]!='terminal':raise AuthorityUnavailable('actual generation metadata identity/terminal differs')
            self.generation_header=header
            self.scope_header=meter.read_fixed_row(self.db,'graph_natural_generation_scopes_v2',('original_seal_digest',),
                'bot=? AND persona=? AND parent_original_id=?',(*self.namespace.as_tuple,parent))
            if self.scope_header is None or self.scope_header[0]!=metadata['generation_seal_digest']:raise AuthorityUnavailable('scope proof differs from same sealed producer')
            for tag,column in(('seal','seal_json'),('generation_reads','read_versions_json'),('generation_queries','query_epochs_json')):
                self._enqueue(tag,'graph_natural_generation_preparations_v2',column,('bot','persona','parent_original_id'),(*self.namespace.as_tuple,parent))
            self._enqueue('scope','graph_natural_generation_scopes_v2','proof_json',('bot','persona','parent_original_id'),(*self.namespace.as_tuple,parent))
            from .owner_material_source_storage_v3 import CanonicalValueStreamV3
            self.locator_digest_stream=CanonicalValueStreamV3(metadata)
        for name in('reads','revisions'):
            self._enqueue('event_'+name,'graph_events',name,('bot','persona','session','event_id'),
                (*self.namespace.as_tuple,self.selected_activity_id,self.final_operation_id))
        event=meter.read_fixed_row(self.db,'graph_events',('epoch_revision',),'bot=? AND persona=? AND session=? AND event_id=?',
            (*self.namespace.as_tuple,self.selected_activity_id,self.final_operation_id))
        if event is None or event[0]!=candidate['graph_epoch']:raise AuthorityUnavailable('candidate has no actual same-commit event')
        if(candidate['graph_incarnation']!=self.graph_stamp[0].requirements.graph_incarnation
                or type(candidate['graph_revision'])is not int or candidate['graph_revision']>self.graph_stamp[0].graph_revision):
            raise AuthorityUnavailable('actual final candidate belongs to another Graph incarnation/revision')
        self.event_epoch=event[0];self.phase='locator_digest'if self.family=='natural'else'metadata_columns'

    def _finish_metadata(self):
        self.event_reads=tuple(GraphVersion(AtomKey.from_token(token),rev)for token,rev in self._value('event_reads'))
        self.event_revisions=tuple(GraphVersion(AtomKey.from_token(token),rev)for token,rev in self._value('event_revisions'))
        self.expression_roots=tuple(self.candidate_metadata['source_refs'])
        if self.family=='natural':
            from .natural_scoped_query_proof_v2 import natural_scoped_query_proof_from_wire_v2
            from .natural_reply_job_v2 import _seal,natural_graph_guard_digest_v2,natural_job_ids_v2
            seal=_seal('generation',self._value('seal'))
            if(canonical_digest(asdict(seal))!=self.scope_header[0]or seal.original_operation_id!=self.generation_header[0]
                    or self.columns['scope'][0].sha256!=self.locator['metadata']['scoped_proof_digest']):raise AuthorityUnavailable('actual canonical seal/scoped-proof commitment differs')
            versions=tuple(GraphVersion(AtomKey.from_token(row['key']),row['revision'])for row in self._value('generation_reads'))
            queries=tuple(QueryEpoch(NamespaceId(**row['namespace']),row['scope_ref'],row['revision'])for row in self._value('generation_queries'))
            guard=natural_graph_guard_digest_v2(self.namespace,versions,queries,graph_epoch=self.generation_header[2],
                access_epoch=self.generation_header[3],deletion_epoch=self.generation_header[4])
            ids=natural_job_ids_v2(self.namespace,self.parent_original_id,'generation')
            if(seal.namespace!=self.namespace or seal.original_graph_guard_digest!=guard
                    or(seal.job_id,seal.original_operation_id,seal.acquire_operation_id,seal.call_id,seal.reservation_operation_id)!=ids):
                raise AuthorityUnavailable('actual original metadata readset/guard/sealed producer identity differs')
            self.scoped_proof=natural_scoped_query_proof_from_wire_v2(self._value('scope'))
            if self.scoped_proof.scope.namespace!=self.namespace or self.scoped_proof.scope.audience_id!=self.authority.audience[0]:raise AuthorityUnavailable('scope differs from actual recorded destination')
            self.expression_roots=tuple(sorted(set((*self.expression_roots,*self.scoped_proof.scope.source_roots))))
        else:
            from .d08_commitment_outbound_receipt_v1 import begin_named_commitment_outbound_locator_metadata_v1
            self.named_locator=begin_named_commitment_outbound_locator_metadata_v1(self)
            if self.named_locator.audience!=self.authority.audience:raise AuthorityUnavailable('named observation route differs')
        for version in self.event_reads:
            if version.key.type_name in('memory.source','memory.access_control','d06.source_correction_head.v1'):self.frozen_versions[version.key.token]=version.revision
        self.pending_sources=list(self.expression_roots)
        from ..memory_types import source_key
        sid='outbound:'+canonical_digest((self.namespace,self.final_operation_id))[:48]
        self.authored_source_key=source_key(*self.namespace.as_tuple,sid);self.phase='authored_metadata'

    def _finish_source_all(self):
        from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
        from ..memory_types import access_key,source_key
        required,pending=set(),list(self.expression_roots)
        while pending:
            ref=pending.pop()
            if ref in required:continue
            required.add(ref);source=self.sources[ref]
            pending.extend(source_key(*self.namespace.as_tuple,parent).token for parent in source.metadata['parent_source_ids'])
        for ref in required:
            source=self.sources[ref];access=self.access_atoms[access_key(*self.namespace.as_tuple,source.metadata['source_id']).token]
            if _qualify_source_rights_values_v3(self.namespace,ref,source,access,None,
                    audience=self.authority.audience[0],purpose='expression',metadata_only=True)is None:raise AuthorityUnavailable('Source ancestor not currently expression qualified')
        self.qualified=True
        for atom in self.access_atoms.values():self.atoms[atom.key.token]=atom
        self.proof=PreparedNaturalOutboundReceiptAdoptionV3(_ISSUER,self);self.admission_task=None;self.phase='admission'

    def _recover_natural(self):
        from ..domains.d08.execution import GoalExecutionProvider
        from .dispatch_candidate import validate_dispatch_candidate_writes,NaturalDispatchCandidateRecoveryV2
        from ..graph_types import GraphWrite
        writes=[];revisions={version.key.token:version.revision for version in self.event_revisions}
        for index,(token,revision)in enumerate(self.candidate_metadata['refs']):
            if revisions.get(token)!=revision:raise AuthorityUnavailable('actual event revision list differs')
            writes.append(('d09'if index==3 else'd08',GraphWrite(AtomKey.from_token(token),self._value('history:'+token))))
        action=next(spec for spec in GoalExecutionProvider().register_types()if spec.name=='d08.action_intent.v1').validator(writes[0][1].value)
        evidence=validate_dispatch_candidate_writes(tuple(writes),namespace=self.namespace,identity=action.identity,
            read_versions=self.event_reads,source_refs=tuple(self.candidate_metadata['source_refs']),
            access_epoch=self.candidate_metadata['access_epoch'],delete_epoch=self.candidate_metadata['delete_epoch'],query_epoch=self.candidate_metadata['query_epoch'])
        if evidence.digest!=self.candidate_metadata['digest']or evidence.generation_original_operation_id!=self.generation_header[0]:raise AuthorityUnavailable('actual final/effect/scoped original association differs')
        return NaturalDispatchCandidateRecoveryV2(evidence,tuple(tuple(row)for row in self.candidate_metadata['refs']),
            self.candidate_metadata['graph_epoch'],self.candidate_metadata['graph_incarnation'],self.candidate_metadata['graph_revision'])

    def advance(self,meter):
        from .d13_paid_original_read_v3 import D13PaidOriginalReadWorkV3
        self.require_current_v3(meter)
        if self.phase=='receipt_metadata':
            if self.receipt_column.advance(meter):
                if not self._begin_saved_replay_v3(meter):self._metadata(meter)
        elif self.phase=='saved_columns':
            if self._advance_queue(meter):self._verify_saved_replay_v3(meter)
        elif self.phase=='saved_locator_digest':
            self.saved_locator_digest_stream.read_fragment(meter)
            if self.saved_locator_digest_stream.complete:
                locator=self.receipt_column.require_v3(self)[_FIELD_V1]
                if (self.saved_locator_digest_stream.hash.hexdigest(),self.saved_locator_digest_stream.offset)!=(
                        locator['metadata_sha256'],locator['metadata_byte_count']):
                    raise AuthorityUnavailable('saved natural parent locator canonical EOF differs')
                self.saved_locator_digest_stream=None;self.phase='saved_event_columns'
        elif self.phase=='saved_event_columns':
            if self._advance_queue(meter):self._verify_saved_event_v3(meter);self.phase='replay_fence'
        elif self.phase=='locator_digest':
            self.locator_digest_stream.read_fragment(meter)
            if self.locator_digest_stream.complete:
                if(self.locator_digest_stream.hash.hexdigest(),self.locator_digest_stream.offset)!=(self.locator['metadata_sha256'],self.locator['metadata_byte_count']):raise AuthorityUnavailable('complete locator metadata canonical commitment differs')
                self.locator_digest_stream=None;self.phase='metadata_columns'
        elif self.phase=='metadata_columns':
            if self._advance_queue(meter):self._finish_metadata()
        elif self.phase=='authored_metadata':
            head=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,self.authored_source_key.token))
            if head is not None:self.pending_sources.append(self.authored_source_key.token)
            if head is None:
                from ..domains.d06.inspection_metadata_v1 import inspection_key_v1
                projection=inspection_key_v1(self.authored_source_key,1)
                metadata_head=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                    'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,projection.token))
                if metadata_head is not None:
                    raise AuthorityUnavailable('new outbound Source inspection output has a conflicting actual head')
                self.heads[projection.token]=None
            self.authored_source_head=head;self.phase='sources'
        elif self.phase=='sources':
            D13PaidOriginalReadWorkV3._sources(self,meter)
            if self.phase=='originals':self._finish_source_all()
        elif self.phase=='access':D13PaidOriginalReadWorkV3._access(self,meter)
        elif self.phase=='admission':
            from .dispatch_admission_read_v3 import DispatchAdmissionReadV3
            if self.admission_task is None:self.admission_task=DispatchAdmissionReadV3(self)
            if self.admission_task.advance(meter):
                self.admission_originals=self.admission_task.result
                receipt=self.admission_originals.receipt_v3();origin=observation_platform_observation_v3(self.observed).binding.origin
                if(receipt.admission.admission_ref!=origin.admission_ref or receipt.admission.effect_id!=origin.effect_id
                        or receipt.admission.payload_digest!=origin.payload_digest.removeprefix('sha256:')
                        or receipt.admission.account_ref!=origin.account_ref or receipt.admission.destination_ref!=origin.destination_ref
                        or receipt.admission.audience!=self.authority.audience):raise AuthorityUnavailable('historical admission differs from independent actual Core binding')
                self.phase='controls'if self.family=='natural'else'named_original'
        elif self.phase=='controls':
            if self._advance_queue(meter):
                row=meter.read_fixed_row(self.db,'graph_atoms',('token','revision','valid','value_cell_id'),
                    "bot=? AND persona=? AND token>? AND type_name IN ('d03.account_binding','d03.role_binding','d05.boundary_rule') ORDER BY token",
                    (*self.namespace.as_tuple,self.control_after))
                if row is None:
                    from .natural_scoped_query_proof_v2 import assert_natural_scoped_query_current_v2
                    assert_natural_scoped_query_current_v2(self.db,self.scoped_proof,now_utc=self.now_utc,prepared_inventory=self.proof);self.phase='history'
                else:
                    self.control_after=row[0]
                    if row[2]:self._atom(AtomKey.from_token(row[0]),meter)
        elif self.phase=='history':
            for token,revision in self.candidate_metadata['refs']:
                row=meter.read_fixed_row(self.db,'graph_history',('value_cell_id','valid','event_bot','event_persona','event_session','event_id'),
                    'token=? AND revision=?',(token,revision))
                if row is None or row[1:]!=(1,*self.namespace.as_tuple,self.selected_activity_id,self.final_operation_id):raise AuthorityUnavailable('emitted member lacks actual final event/history')
                self.history_rows[(token,revision)]=row
                self._enqueue('history:'+token,'graph_history','value',('token','revision'),(token,revision),row[0])
            self.phase='history_columns'
        elif self.phase=='history_columns':
            if self._advance_queue(meter):self.recovered=self._recover_natural();self.phase='writer_atoms'
        elif self.phase=='named_original':
            from .d08_commitment_outbound_receipt_v1 import begin_named_commitment_outbound_receipt_metadata_v1
            if self.named_original is None:self.named_original=begin_named_commitment_outbound_receipt_metadata_v1(self)
            if self.named_original.advance(meter):self.recovered=self.named_original.result;self.phase='writer_atoms'
        elif self.phase=='writer_atoms':
            evidence=self.recovered.evidence;origin=observation_platform_observation_v3(self.observed).binding.origin
            admission=self.admission_originals.receipt_v3().admission
            if(evidence.effect_id!=origin.effect_id or evidence.payload_digest!=origin.payload_digest.removeprefix('sha256:')
                    or admission.candidate_digest!=evidence.digest):
                raise AuthorityUnavailable('recovered final changed actual admission/candidate/observed effect/payload')
            for token,_ in self.recovered.write_versions:self._atom(AtomKey.from_token(token),meter)
            row=meter.read_fixed_row(self.db,'graph_outbox_jobs',('outbox_ref',),
                'bot=? AND persona=? AND operation_id=? ORDER BY outbox_ref',(*self.namespace.as_tuple,self.final_operation_id))
            if row is None or meter.read_fixed_row(self.db,'graph_outbox_jobs',('outbox_ref',),
                    'bot=? AND persona=? AND operation_id=? AND outbox_ref<>? ORDER BY outbox_ref',
                    (*self.namespace.as_tuple,self.final_operation_id,row[0]))is not None:raise AuthorityUnavailable('one actual original outbox required')
            self.outbox_ref=row[0];self._atom(AtomKey.from_token(row[0]),meter);self.phase='writer_columns'
        elif self.phase=='writer_columns':
            if self._advance_queue(meter):
                batch=self.atoms[self.recovered.evidence.batch_ref]
                if self.family=='natural':scene,conversation=batch.value['scene_id'],batch.value['audience_id']
                else:scene,conversation=batch.value['scene_ref'],batch.value['audiences'][0]
                if conversation!=self.authority.audience[0]:raise AuthorityUnavailable('emitted batch changed actual recorded destination')
                from ..domains.d09.turn_order import turn_order_key
                from ..memory_types import access_key
                self.scene_ref,self.conversation_ref=scene,conversation
                self._atom(turn_order_key(self.namespace,scene,conversation),meter,optional=True)
                self._atom(AtomKey.from_token(self.atoms[self.outbox_ref].value['job_ref']),meter)
                self._atom(self.authored_source_key,meter,optional=True)
                self._atom(access_key(*self.namespace.as_tuple,self.authored_source_key.owner.subject),meter,optional=True)
                self.phase='slot_metadata'
        elif self.phase=='slot_metadata':
            if not self._advance_queue(meter):return
            previous=self.columns.pop('slot_metadata',None)
            if previous is not None:
                raw=previous[1]
                if raw.get('origin_ref')==self.outbox_ref:
                    if self.slot_ref is not None:raise AuthorityUnavailable('outbound origin has conflicting actual turn slots')
                    self.slot_ref=self.slot_after;self._atom(AtomKey.from_token(self.slot_ref),meter)
            row=meter.read_fixed_row(self.db,'graph_atoms',('token','revision','valid','value_cell_id'),
                "bot=? AND persona=? AND type_name='d09.turn_slot.v1' AND token>? ORDER BY token",(*self.namespace.as_tuple,self.slot_after))
            if row is None:self.phase='final_atoms'
            else:
                self.slot_after=row[0]
                if row[2]:self._enqueue('slot_metadata','graph_atoms','value',('token',),(row[0],),row[3],'slot_metadata')
        elif self.phase=='final_atoms':
            if not self._advance_queue(meter):return
            if self.slot_ref is not None:
                from ..domains.d09.turn_order import turn_outbound_observation_key
                slot=self.atoms[self.slot_ref]
                self._atom(turn_outbound_observation_key(self.namespace,self.scene_ref,self.conversation_ref,slot.value['sequence']),meter,optional=True)
            for version in self.recovered.evidence.current_read_versions:
                key=version.key;actual=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                    'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,key.token))
                if(version.revision==0 and actual is not None)or(version.revision>0 and(actual is None or actual[:2]!=(version.revision,1))):raise AuthorityUnavailable('actual original Source/route readset changed')
                self.heads[key.token]=actual
            self.phase='complete_columns'
        elif self.phase=='complete_columns':
            if self._advance_queue(meter):self.complete=True;self.phase='complete'
        elif self.phase!='complete':raise AuthorityUnavailable('unregistered outbound receipt adoption phase')
        self.reserve_v3()

    def _begin_saved_replay_v3(self,meter):
        table='graph_d13_outbound_observations_v1'
        present=meter.read_fixed_row(self.db,'sqlite_master',('name',),"type='table' AND name=?",(table,))
        if present is None:return False
        row=meter.read_fixed_row(self.db,table,('source_ref','slot_ref','batch_ref','original_digest'),
            'bot=? AND persona=? AND final_operation_id=? AND observation_digest=?',
            (*self.namespace.as_tuple,self.final_operation_id,self.observation_digest))
        if row is None:return False
        self.saved_header=row
        key=(*self.namespace.as_tuple,self.final_operation_id,self.observation_digest)
        for tag,column in(('saved_observation','observation_json'),('saved_original','original_json')):
            self._enqueue(tag,table,column,('bot','persona','final_operation_id','observation_digest'),key)
        self.phase='saved_columns';return True

    def _verify_saved_replay_v3(self,meter):
        from ..authority_service.v2_contract import FencePermitV2
        from ..authority_service.observation_refinement_contract_v3 import to_wire,from_wire
        observation,original=self._value('saved_observation'),self._value('saved_original')
        op='d13-outbound:'+canonical_digest((self.namespace,self.final_operation_id,self.observation_digest))[:48]
        if(self.columns['saved_observation'][0].sha256!=canonical_digest(to_wire(self.observed))
                or observation!=to_wire(self.observed)or self.columns['saved_original'][0].sha256!=self.saved_header[3]
                or canonical_digest(original)!=self.saved_header[3]
                or original.get('schema')!='d13.outbound_adoption.v1'or original.get('operation_id')!=op
                or original.get('observation_digest')!=self.observation_digest
                or(original.get('source_ref'),original.get('slot_ref'),original.get('batch_ref'))!=self.saved_header[:3]):
            raise AuthorityUnavailable('saved receipt adoption original differs from actual complete canonical/Core observation EOF')
        raw=self.receipt_column.require_v3(self)
        candidates=tuple(value for name,value in raw.items()if name in('natural_dispatch_candidate','dispatch_candidate'))
        if len(candidates)!=1 or candidates[0]['refs'][3][0]!=self.saved_header[2]:
            raise AuthorityUnavailable('saved adoption batch is not the actual committed final metadata member')
        for token in self.saved_header[:3]:
            if NamespaceId.from_key(AtomKey.from_token(token))!=self.namespace:
                raise AuthorityUnavailable('saved adoption metadata reference crossed namespace')
        permit=from_wire(original['permit'])
        if(type(permit)is not FencePermitV2 or permit.operation!='write'or permit.operation_id!=op
                or permit.namespace!=self.scope.authority_namespace
                or original['finish_digest']!='sha256:'+canonical_digest((op,permit.token,self.observation_digest))):
            raise AuthorityUnavailable('saved adoption original permit/finish identity differs')
        event=meter.read_fixed_row(self.db,'graph_events',('digest','epoch_revision'),
            'bot=? AND persona=? AND session=? AND event_id=?',(*self.namespace.as_tuple,'d13-outbound-observation',op))
        if(event is None or event[1]!=original['pre_epoch']+1
                or self.graph_stamp[0].graph_revision<original['pre_revision']+1):
            raise AuthorityUnavailable('saved adoption lacks its actual E+1 producer event')
        self.saved_event_header=event;self.saved_permit=permit;self.saved_original=original
        for name in('revisions','invalidated'):
            self._enqueue('saved_event_'+name,'graph_events',name,('bot','persona','session','event_id'),
                (*self.namespace.as_tuple,'d13-outbound-observation',op))
        from .d13_cache_use_admission_v2 import _graph_use_enabled_v2
        if 'natural_dispatch_candidate'in raw and _graph_use_enabled_v2(self.graph):
            self._prepare_saved_natural_parent_v3(meter,candidates[0])
            self.phase='saved_locator_digest'
        else:self.phase='saved_event_columns'

    def _prepare_saved_natural_parent_v3(self,meter,candidate):
        from .natural_dispatch_locator_metadata_v1 import _META_KEYS_V1,_RECIPE_KEYS_V1
        from .natural_reply_job_v2 import natural_job_ids_v2
        from .owner_material_source_storage_v3 import CanonicalValueStreamV3
        raw=self.receipt_column.require_v3(self);locator=raw.get(_FIELD_V1)
        if (type(locator)is not dict or set(locator)!=_OBJECT_FIELDS_V1[()]
                or locator['schema']!='sylanne.natural_dispatch_read_locator.v1'
                or type(locator['metadata'])is not dict or set(locator['metadata'])!=_META_KEYS_V1):
            raise AuthorityUnavailable('saved natural adoption lacks its exact committed parent locator')
        metadata=locator['metadata'];recipe=metadata['recipe']
        origin=observation_platform_observation_v3(self.observed).binding.origin
        if (type(recipe)is not dict or set(recipe)!=_RECIPE_KEYS_V1
                or recipe['kind']!='unsealed_producer_metadata_recipe'
                or metadata['namespace']!={'bot_id':self.namespace.bot_id,'persona_id':self.namespace.persona_id}
                or recipe['namespace']!=metadata['namespace']
                or (metadata['operation_id'],metadata['activity_id'],metadata['effect_id'],metadata['bundle_digest'])!=(
                    self.final_operation_id,self.selected_activity_id,self.selected_effect_id,self.bundle_header[2])
                or metadata['admission_ref']!=origin.admission_ref or metadata['candidate_digest']!=candidate['digest']
                or (metadata['graph_incarnation'],metadata['graph_revision'],metadata['graph_epoch'])!=(
                    candidate['graph_incarnation'],candidate['graph_revision'],candidate['graph_epoch'])
                or recipe['admission']['audience']!=[origin.destination_ref]
                or (recipe['committed_selection']['operation_id'],recipe['committed_selection']['activity_id'],
                    recipe['committed_selection']['effect_id'],recipe['committed_selection']['admission_ref'])!=(
                    self.final_operation_id,self.selected_activity_id,self.selected_effect_id,origin.admission_ref)):
            raise AuthorityUnavailable('saved natural parent locator differs from actual final/observed admission')
        parent=recipe['generation_parent_original_id'];ids=natural_job_ids_v2(self.namespace,parent,'generation')
        generation=self._fixed_saved_parent_v3(meter,parent)
        scope=meter.read_fixed_row(self.db,'graph_natural_generation_scopes_v2',('original_seal_digest',),
            'bot=? AND persona=? AND parent_original_id=?',(*self.namespace.as_tuple,parent))
        expected=recipe['generation_original_header'];commitments=recipe['commitments']
        if (recipe['generation_original_operation_id']!=ids[1] or recipe['generation_job_id']!=ids[0]
                or recipe['generation_c02_operation_id']!=parent
                or recipe['batch']['paid_review']['generation_original_operation_id']!=ids[1]
                or generation is None or generation[:3]!=(ids[0],ids[1],'terminal')
                or generation[3:7]!=(expected['graph_epoch'],expected['access_epoch'],expected['deletion_epoch'],expected['worker_fence'])
                or generation[7:]!=(commitments['generation_typed_request_digest'],
                    commitments['generation_terminal_receipt_digest'],commitments['generation_terminal_output_digest'])
                or scope!=(metadata['generation_seal_digest'],)):
            raise AuthorityUnavailable('saved natural parent has no exact original generation/seal terminal metadata')
        self.saved_natural_parent=(parent,ids[1]);self.saved_natural_headers=(generation,scope)
        self.saved_locator_digest_stream=CanonicalValueStreamV3(metadata)

    def _fixed_saved_parent_v3(self,meter,parent):
        return meter.read_fixed_row(self.db,'graph_natural_generation_preparations_v2',
            ('job_id','original_operation_id','state','graph_epoch','access_epoch','deletion_epoch',
             'worker_fence','typed_request_digest','terminal_receipt_digest','terminal_output_digest'),
            'bot=? AND persona=? AND parent_original_id=?',(*self.namespace.as_tuple,parent))

    def _verify_saved_event_v3(self,meter):
        from ..graph_types import GraphReceipt,NamespaceEpoch
        revisions=tuple(GraphVersion(AtomKey.from_token(token),rev)for token,rev in self._value('saved_event_revisions'))
        invalidated=tuple(GraphVersion(AtomKey.from_token(token),rev)for token,rev in self._value('saved_event_invalidated'))
        receipt=GraphReceipt('committed',revisions,invalidated,NamespaceEpoch(*self.namespace.as_tuple,self.saved_event_header[1]))
        if canonical_digest(receipt)!=self.saved_original['graph_receipt_digest']:
            raise AuthorityUnavailable('saved adoption original differs from actual producer event receipt metadata')
        for version in revisions:
            row=meter.read_fixed_row(self.db,'graph_history',('valid','event_bot','event_persona','event_session','event_id'),
                'token=? AND revision=?',(version.key.token,version.revision))
            if row!=(1,*self.namespace.as_tuple,'d13-outbound-observation',self.saved_original['operation_id']):
                raise AuthorityUnavailable('saved adoption event member lacks actual matching immutable history metadata')

    def release_payload_v3(self):
        from .d13_paid_original_read_v3 import release_d13_paid_source_inspection_v3
        release_d13_paid_source_inspection_v3(self)
        _READERS.pop(self,None)
        if self.proof is not None:_PROOFS.pop(self.proof,None);_REPLAYS.pop(self.proof,None)
        if self.admission_originals is not None:self.admission_originals.release_payload_v3()
        if self.named_original is not None:self.named_original.release_v1()
        for values in(self.atoms,self.columns,self.sources,self.source_heads,self.heads,self.access_atoms,
                self.source_payload_sha256,self.frozen_versions,self.history_rows):values.clear()
        self.queue.clear();self.pending_sources.clear()
        self.current=self.column=self.receipt_column=self.proof=None
        self.admission_task=self.admission_originals=self.named_original=self.scoped_proof=None
        self.receipt_metadata=self.candidate_metadata=self.locator=self.recovered=None

class PreparedNaturalOutboundReceiptAdoptionV3:
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER or not reader.qualified:raise AuthorityUnavailable('actual current SourceALL EOF required')
        self.reader,self.operation,self.projection,self.query=reader,reader.operation,reader.projection,reader.query
        _PROOFS[self]=(reader,reader.operation,reader.scope,reader.observation_digest)
    def require_current(self,db,namespace,query):
        r=self.reader
        if(_PROOFS.get(self)!=(r,r.operation,r.scope,r.observation_digest)or db is not r.db or namespace!=r.namespace
                or query!=r.query or not r.qualified):raise AuthorityUnavailable('exact private outbound Source READ proof required')
        r.require_current_v3();return self.projection
    def source_metadata(self,db,namespace,query,key,*,require_grant=False):
        if require_grant:raise AuthorityUnavailable('receipt-fact metadata grants no execution Source permission')
        self.require_current(db,namespace,query);r=self.reader;source=r.sources.get(key.token)
        if source is None:raise AuthorityUnavailable('Source outside actual qualified family')
        return _QualifiedSourceMetadataV3(source.revision,source.metadata,r.source_payload_sha256[key.token])
    def saved_observation_v3(self):
        self.require_current(self.reader.db,self.reader.namespace,self.reader.query)
        return self.reader.saved_header
    @property
    def recovered(self):return self.reader.recovered
    @property
    def scoped_proof(self):return self.reader.scoped_proof
    @property
    def named_original(self):return self.reader.named_original
    @property
    def read_versions(self):
        values={**self.reader.source_heads,**self.reader.heads}
        return tuple(GraphVersion(AtomKey.from_token(token),0 if head is None else head[0])for token,head in sorted(values.items()))
    def atom_v3(self,key):
        self.require_current(self.reader.db,self.reader.namespace,self.reader.query);atom=self.reader.atoms.get(key.token)
        if atom is None or not atom.valid:raise AuthorityUnavailable('Body outside exact Source-qualified adoption projection')
        return atom
    def optional_atom_v3(self,key):
        self.require_current(self.reader.db,self.reader.namespace,self.reader.query)
        if key.token not in self.reader.heads:raise AuthorityUnavailable('optional key lacks actual absence/head observation')
        return self.reader.atoms.get(key.token)
    def outbound_slots_v3(self,outbox_ref):
        if outbox_ref!=self.reader.outbox_ref:raise AuthorityUnavailable('slot census belongs to another actual outbox')
        self.require_current(self.reader.db,self.reader.namespace,self.reader.query)
        return()if self.reader.slot_ref is None else(self.atom_v3(AtomKey.from_token(self.reader.slot_ref)),)
    def release_payload_v3(self):
        self.reader.release_payload_v3()

class PreparedNaturalOutboundReceiptReplayV3:
    """Exact historical ACK recovery. It exposes no Body/projection/Source API."""
    def __init__(self,issuer,reader,state):
        if issuer is not _ISSUER or reader.phase!='replay_fence' or state not in('active','finished'):
            raise AuthorityUnavailable('actual complete metadata replay/original fence producer required')
        self.reader=reader
        _REPLAYS[self]=(reader,reader.operation,reader.scope,reader.observation_digest,reader.saved_header,
            reader.saved_permit,reader.saved_event_header,reader.columns['saved_original'][0].sha256,
            reader.saved_natural_parent,reader.saved_natural_headers)
    def _actual(self,graph,namespace,final_operation_id,observed):
        r=self.reader
        if(_REPLAYS.get(self)!=(r,r.operation,r.scope,r.observation_digest,r.saved_header,
                r.saved_permit,r.saved_event_header,r.columns['saved_original'][0].sha256,
                r.saved_natural_parent,r.saved_natural_headers)
                or graph is not r.graph or namespace!=r.namespace or final_operation_id!=r.final_operation_id
                or canonical_digest(observed)!=r.observation_digest or r.db.in_transaction):
            raise AuthorityUnavailable('exact metadata-only replay producer/retention identity differs')
        r.require_current_v3();return r
    def resume_original_ack_v3(self,graph,namespace,final_operation_id,observed):
        r=self._actual(graph,namespace,final_operation_id,observed)
        if canonical_digest(r._current_observation_v3())!=r.observation_digest:
            raise AuthorityUnavailable('metadata replay cannot substitute an older accepted Core observation')
        permit,state=r.port.get_fence_operation(namespace=namespace,authority_namespace=r.scope.authority_namespace,
            operation_id=r.saved_original['operation_id'])
        if permit!=r.saved_permit or state not in('active','finished'):
            raise AuthorityUnavailable('metadata replay original adoption fence/ACK is unknown')
        if state=='active':r.port.finish_fence(FenceScope(namespace,r.scope.authority_namespace,permit.generation,
            'write',permit.operation_id,permit,permit.pinned_anchor,
            NamespaceEpoch(*namespace.as_tuple,r.saved_original['pre_epoch']),r.saved_original['pre_revision']),
            request_id='finish:'+permit.operation_id,request_digest=r.saved_original['finish_digest'])
        return {'status':'duplicate','observation_outcome':observation_platform_observation_v3(r.observed).outcome}
    def close_natural_parent_after_ack_v3(self,graph,namespace,final_operation_id,observed):
        r=self._actual(graph,namespace,final_operation_id,observed)
        if r.saved_natural_parent is None:
            return
        permit,state=r.port.get_fence_operation(namespace=namespace,authority_namespace=r.scope.authority_namespace,
            operation_id=r.saved_original['operation_id'])
        if permit!=r.saved_permit or state!='finished':
            raise AuthorityUnavailable('natural parent cleanup requires its actual saved adoption finish ACK')
        from .d13_natural_original_use_v3 import close_graph_natural_parent_after_outbound_v3
        close_graph_natural_parent_after_outbound_v3(graph,namespace=namespace,
            generation_original_id=r.saved_natural_parent[1],permit=permit)

    def release_payload_v3(self):self.reader.release_payload_v3()

def begin_natural_outbound_receipt_adoption_read_v3(graph,bootstrap,namespace,final_operation_id,observed=None):
    r=NaturalOutboundReceiptAdoptionReadV3(graph,bootstrap,namespace,final_operation_id,observed)
    try:
        work=create_graph_storage_work_v3(graph,kind=KIND,operation_id=r.operation.operation_id,
            selection_digest=r.operation.selection_digest,deadline_utc=None,state=r,operation=r.operation)
        r.work=work;return work
    except BaseException:
        try:r.port.finish_fence(r.scope,request_id='finish:'+r.scope.operation_id,
            request_digest='sha256:'+canonical_digest((r.scope.operation_id,'outbound-fact-read-closed')))
        finally:r.release_payload_v3();finish_runtime_storage_operation_v3(r.operation)
        raise

def advance_natural_outbound_receipt_adoption_read_v3(graph,work):
    r=work.state
    if canonical_digest(r._current_observation_v3())!=r.observation_digest:raise AuthorityUnavailable('actual Core observation changed during receipt READ')
    if r.port.validate_fence(r.scope)!=r.scope.permit:raise AuthorityUnavailable('actual receipt READ permit changed')
    if r.phase=='replay_fence':
        with bind_runtime_storage_operation_v3(r.operation,r.db):
            permit,state=r.port.get_fence_operation(namespace=r.namespace,authority_namespace=r.scope.authority_namespace,
                operation_id=r.saved_original['operation_id'])
            if permit!=r.saved_permit or state not in('active','finished'):
                raise AuthorityUnavailable('actual saved adoption original fence is unknown')
            r.proof=PreparedNaturalOutboundReceiptReplayV3(_ISSUER,r,state);r.complete=True;r.phase='complete_replay'
        return GraphStorageStepV3('complete',r.proof)
    with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock:
        r.db.execute('BEGIN')
        r._advance_head_memo_v2=(r.db.total_changes,{})
        try:
            with runtime_storage_quantum_v3(r.db)as meter:r.advance(meter)
        finally:
            r._advance_head_memo_v2=None
            r.db.rollback()
    return GraphStorageStepV3('complete',r.proof)if r.complete else GraphStorageStepV3('progress')

def finish_natural_outbound_receipt_adoption_read_v3(graph,work,error):
    r=work.state;failure=error
    try:
        r.port.finish_fence(r.scope,request_id='finish:'+r.scope.operation_id,
            request_digest='sha256:'+canonical_digest((r.scope.operation_id,'outbound-fact-read-closed')))
        r.read_finished=True
    except BaseException as exc:failure=exc
    finally:
        if failure is None:work.result_lease=r.operation
        else:
            r.release_payload_v3()
            finish_runtime_storage_operation_v3(r.operation)
    if failure is not None:raise failure

def observe_natural_outbound_receipt_adoption_write_v3(proof):
    if type(proof)is not PreparedNaturalOutboundReceiptAdoptionV3:raise AuthorityUnavailable('actual private adoption proof required')
    r=proof.reader
    if r.db.in_transaction:raise AuthorityUnavailable('Core re-observation must precede Graph WRITE transaction')
    if canonical_digest(r._current_observation_v3())!=r.observation_digest:raise AuthorityUnavailable('actual Core observation changed before WRITE')
    r.write_observation=(r.observation_digest,r.graph_stamp)

@contextmanager
def bind_natural_outbound_receipt_adoption_v3(proof,graph,db,namespace,final_operation_id,observed):
    if type(proof)is not PreparedNaturalOutboundReceiptAdoptionV3:raise AuthorityUnavailable('actual named adoption proof required')
    r=proof.reader;proof.require_current(db,namespace,r.query)
    if(not r.complete or graph is not r.graph or final_operation_id!=r.final_operation_id
            or canonical_digest(observed)!=r.observation_digest or r.write_observation!=(r.observation_digest,r.graph_stamp)):
        raise AuthorityUnavailable('WRITE lacks actual complete READ/current independent Core observation')
    if r.family=='natural':
        from .natural_scoped_query_proof_v2 import assert_natural_scoped_query_current_v2
        assert_natural_scoped_query_current_v2(db,r.scoped_proof,now_utc=r.now_utc,prepared_inventory=proof)
    token=_BOUND.set(proof)
    try:yield proof
    finally:_BOUND.reset(token)

def current_bound_natural_outbound_receipt_adoption_v3(db,namespace,final_operation_id=None):
    proof=_BOUND.get()
    if proof is None:return None
    if type(proof)is not PreparedNaturalOutboundReceiptAdoptionV3:raise AuthorityUnavailable('unregistered adoption binding')
    r=proof.reader;proof.require_current(db,namespace,r.query)
    if final_operation_id is not None and final_operation_id!=r.final_operation_id:raise AuthorityUnavailable('bound final operation changed')
    return proof

def require_bound_natural_outbound_receipt_adoption_v3(graph,db,namespace,final_operation_id,observed):
    proof=current_bound_natural_outbound_receipt_adoption_v3(db,namespace,final_operation_id)
    if proof is None or proof.reader.graph is not graph or canonical_digest(observed)!=proof.reader.observation_digest:
        raise AuthorityUnavailable('fact adoption writer requires exact private receipt READ')
    return proof
