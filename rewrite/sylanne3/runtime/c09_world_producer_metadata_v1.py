"""Fixed C09 World producer metadata over the actual frozen V1 W01 original.

Only the canonical metadata projection survives each fragment. Request/value
bodies are hashed through EOF and never become a decoded World value here.
"""
from __future__ import annotations
from copy import copy
from hashlib import sha256
import codecs
import json

from ..runtime_contracts import NamespaceId,OperationIdentity,canonical_digest,canonical_serialize
from ..graph_types import AtomKey
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .c09_graph_row_codec_v2 import _C09RegisteredGraphValueV3
from .c09_paged_sql_v2 import (C09PagedCaptureHold,current_c09_sql_meter_v2,
    require_c09_reserved_meter_v3,begin_c09_row_commitment_v2,advance_c09_row_commitment_v2,
    read_legacy_sql_cell_fragment_v2,legacy_cell_read_transaction_v2,
    read_c09_table_shape_v2,require_c09_capture_member_v2)
from .domain_production_original_codec_v1 import ORIGINAL_COLUMNS,_PAYLOAD_FIELDS,_version
from .domain_production_originals_v1 import TABLE,_receipt

_KINDS=frozenset({'adopt_world_assertion_v1','relearn_world_assertion_v1'})
_KEEP=(('schema',),('namespace',),('identity',),('read_versions',),
    ('provenance','world_source_roots'),('request','assertion','source_refs'),('request','prior_erasure_ref'),
    ('coverage',),('missing_inputs',),('continuation_ref',))


class _WorldProducerMetadataFSMV1(_C09RegisteredGraphValueV3):
    def __init__(self,*,source_arena=None,**profile):
        super().__init__(source_arena=source_arena,**profile)
        self.keys={():set(),('request',):set(),('provenance',):set()}
        self.spans={};self.write_keys={};self.finished=False

    def _source_heap_bytes(self):
        from .c09_logical_source_v3 import _retained_size
        return super()._source_heap_bytes()+_retained_size((self.keys,self.spans,self.write_keys),set())+4096

    def _selected(self,path):
        if any(path[:len(prefix)]==prefix or prefix[:len(path)]==path for prefix in _KEEP):return True
        return (path==('writes',) or len(path)==2 and path[0]=='writes' and type(path[1])is int
            or len(path)>=3 and path[0]=='writes' and type(path[1])is int and path[2]in{'key','dependencies'})

    def _span_path(self,path):
        return (path in {('request',),('request','assertion'),('provenance','world_assertion')}
            or len(path)==3 and path[0]=='writes' and type(path[1])is int and path[2]=='value')

    def _emit(self,emit,kind,path,start,end,**values):
        if kind=='key' and path[:-1]in self.keys:self.keys[path[:-1]].add(values['key'])
        if kind=='key' and len(path)==3 and path[0]=='writes' and type(path[1])is int:
            self.write_keys.setdefault(path[1],set()).add(values['key'])
        if self._span_path(path):
            if kind in('object_start','array_start','scalar_start'):
                if path in self.spans:raise C09PagedCaptureHold('World producer canonical span was repeated')
                self.spans[path]={'start':start,'end':None,'hash':sha256(),'kind':kind}
            elif kind in('object_end','array_end','scalar_end'):
                self.spans[path]['end']=end
        if self._selected(path):super()._emit(emit,kind,path,start,end,**values)
        else:C09CanonicalJSONStreamV2._emit(self,emit,kind,path,start,end,**values)

    def feed(self,raw,emit):
        begin=self.byte_count
        super().feed(raw,emit)
        for span in self.spans.values():
            upper=min(self.byte_count,self.byte_count if span['end']is None else span['end'])
            lower=max(begin,span['start'])
            if upper>lower:span['hash'].update(raw[lower-begin:upper-begin])

    def copy(self):
        result=super().copy()
        result.keys={path:set(values)for path,values in self.keys.items()}
        result.spans={path:{**state,'hash':state['hash'].copy()}for path,state in self.spans.items()}
        result.write_keys={index:set(values)for index,values in self.write_keys.items()}
        result.finished=self.finished
        return result

    def finish(self):
        result=super().finish()
        if self.keys[()]!=_PAYLOAD_FIELDS:
            raise C09PagedCaptureHold('World producer original envelope field set differs')
        if self.keys[('provenance',)]!={'world_assertion','world_source_roots','semantic_mesh'}:
            raise C09PagedCaptureHold('World producer registered provenance field set differs')
        if any(span['end']is None for span in self.spans.values()):
            raise C09PagedCaptureHold('World producer metadata lacks canonical value EOF')
        self.finished=True
        return result


class C09WorldProducerMetadataCaptureV1:
    """One actual same-scope producer lookup; prefix state cannot issue proof."""
    def __init__(self,build,index):
        from .c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2,_read_frozen_source_row_metadata_v3
        if type(build)is not InstalledGraphRebaseBuildV2:
            raise TypeError('actual C09 World producer capture requires its installed Graph build')
        build.require_current();meter=current_c09_sql_meter_v2()
        self.build,self.index=build,index
        self.namespace=NamespaceId(*json.loads(build.scope.graph_namespace))
        if NamespaceId.from_key(index.input_version.key)!=self.namespace:
            raise C09PagedCaptureHold('World producer metadata lookup crossed its actual maintenance namespace')
        self.key=(*self.namespace.as_tuple,index.adoption_operation_id)
        self.shape=read_c09_table_shape_v2(build.pair.source,TABLE)
        if self.shape.columns!=ORIGINAL_COLUMNS or self.shape.primary_key_columns!=('bot','persona','operation_id'):
            raise C09PagedCaptureHold('World producer original actual physical schema differs')
        self.metadata=_read_frozen_source_row_metadata_v3(build,self.shape,self.key,meter)
        self.header=meter.read_fixed_row(build.pair.source,TABLE,
            ('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest'),
            'bot=? AND persona=? AND operation_id=?',self.key)
        if self.header is None or self.header[0]!='d03' or self.header[1]not in _KINDS:
            raise C09PagedCaptureHold('World index has no registered actual World producer original')
        for name in('original_payload_json','read_versions_json','receipt_json'):
            kind,size=self.metadata[self.shape.columns.index(name)]
            if kind!='text' or not size:
                raise C09PagedCaptureHold('World producer original fixed JSON cell is absent')
        self.row=begin_c09_row_commitment_v2(build.pair.source,self.shape,self.key,self.metadata)
        arena=build.session._source_parser_arena_v3
        self.payload=_WorldProducerMetadataFSMV1(source_arena=arena,ensure_ascii=True)
        self.aux={name:_C09RegisteredGraphValueV3(source_arena=arena,ensure_ascii=True)
            for name in('read_versions_json','receipt_json')}
        self.cell_index=0;self.offset=0;self.complete=False;self.quantum_completed=False
        self.reads=None;self.receipt=None
        self._source_arena=arena;arena.add(self)

    def _source_heap_bytes(self):
        from .c09_logical_source_v3 import _retained_size
        return 8192+_retained_size((self.index,self.key,self.metadata,self.header,self.reads,self.receipt),set())

    def _copy(self):
        self.payload._require(self._source_heap_bytes())
        result=copy(self);result.quantum_completed=False
        result.row=copy(self.row);result.row.row_hash=self.row.row_hash.copy()
        if self.row.blob_hash is not None:result.row.blob_hash=self.row.blob_hash.copy()
        if self.row.utf8 is not None:
            result.row.utf8=codecs.getincrementaldecoder('utf-8')('strict')
            result.row.utf8.setstate(self.row.utf8.getstate())
        result.payload=self.payload.copy()
        result.aux={name:parser.copy()for name,parser in self.aux.items()}
        self._source_arena.add(result);result.payload._require()
        return result

    def next_quantum(self,budget):
        meter=require_c09_reserved_meter_v3(budget);self.build.require_current()
        result=self._copy()
        with legacy_cell_read_transaction_v2(self.build.pair.source):
            if not result.row.complete:
                advance_c09_row_commitment_v2(self.build.pair.source,self.shape,budget,cursor=result.row,meter=meter)
            elif self.cell_index<3:
                name=('original_payload_json','read_versions_json','receipt_json')[self.cell_index]
                size=self.metadata[self.shape.columns.index(name)][1]
                amount=min(16384,size-self.offset)
                meter.require_available(amount*8+8192)
                raw,total,kind=read_legacy_sql_cell_fragment_v2(self.build.pair.source,table=TABLE,column=name,
                    where='bot=? AND persona=? AND operation_id=?',parameters=self.key,
                    start=self.offset,length=amount,meter=meter)
                if total!=size or kind!='text' or len(raw)!=amount:
                    raise C09PagedCaptureHold('World frozen producer metadata fragment identity changed')
                parser=result.payload if self.cell_index==0 else result.aux[name]
                parser.feed(raw,lambda event:None);result.offset+=amount
                if result.offset==size:
                    finished=parser.finish()
                    if self.cell_index==0 and finished.sha256!=self.header[3]:
                        raise C09PagedCaptureHold('World producer full canonical EOF hash differs from its original header')
                    result.cell_index+=1;result.offset=0
            elif not result.complete:result._finish_metadata(meter)
        self.build.require_current()
        return result

    def _finish_metadata(self,meter):
        from dataclasses import fields
        from .c09_graph_rebase_candidate_v2 import _actual_source_locator_v2
        payload=self.payload.value;index=self.index
        expected_request={'assertion'}if self.header[1]=='adopt_world_assertion_v1'else{'assertion','prior_erasure_ref'}
        if (not self.payload.finished or self.payload.keys[('request',)]!=expected_request
                or payload['schema']!='d03.current-'+self.header[1]+'.v1'
                or payload['namespace']!={'bot_id':self.namespace.bot_id,'persona_id':self.namespace.persona_id}
                or set(payload['identity'])!={field.name for field in fields(OperationIdentity)}
                or payload['identity']['operation_id']!=self.key[2]or payload['identity']['phase']!=self.header[1]
                or payload['coverage']!='complete' or payload['missing_inputs']!=[] or payload['continuation_ref']is not None):
            raise C09PagedCaptureHold('World producer fixed envelope/identity/coverage differs')
        OperationIdentity(**payload['identity'])
        spans=self.payload.spans
        expected_spans={('request',),('request','assertion'),('provenance','world_assertion')}
        if not expected_spans<=set(spans)or any(spans[path]['kind']!='object_start'for path in expected_spans):
            raise C09PagedCaptureHold('World producer input canonical object spans are incomplete')
        if (spans[('request','assertion')]['hash'].hexdigest()!=index.input_digest
                or spans[('provenance','world_assertion')]['hash'].hexdigest()!=index.input_digest):
            raise C09PagedCaptureHold('World producer request/input/provenance exact canonical commitments differ')
        roots=tuple(payload['provenance']['world_source_roots'])
        base_roots=tuple(payload['request']['assertion']['source_refs'])
        if (not 1<=len(roots)<=16 or roots!=tuple(sorted(set(roots)))or roots!=index.source_refs
                or not set(base_roots)<=set(roots)):
            raise C09PagedCaptureHold('World producer complete Source roots differ from its signed index')
        for ref in roots:
            key=AtomKey.from_token(ref)
            if key.type_name!='memory.source' or NamespaceId.from_key(key)!=self.namespace:
                raise C09PagedCaptureHold('World producer Source roots crossed actual namespace/type')
        self.reads=tuple(_version(value,self.namespace)for value in payload['read_versions'])
        reads_raw=self.aux['read_versions_json'].value
        if (len(self.reads)>1024 or len({key.token for key,_ in self.reads})!=len(self.reads)
                or [[key.token,revision]for key,revision in self.reads]!=reads_raw
                or not set(roots)<={key.token for key,_ in self.reads if key.type_name=='memory.source'}):
            raise C09PagedCaptureHold('World producer roots lack their actual complete W01 readset')
        receipt=_receipt(self.aux['receipt_json'].value)
        if (receipt.status!='committed' or receipt.operation_id!=self.key[2]
                or receipt.operation_digest!=self.header[4]or receipt.commit_seq!=index.known_from_sequence
                or canonical_digest(receipt)!=self.header[5]or self.header[5]!=index.adoption_receipt_digest
                or index.input_version not in receipt.write_versions):
            raise C09PagedCaptureHold('World producer receipt differs from actual index adoption/W01')
        ledger=meter.read_fixed_row(self.build.pair.source,'graph_bundle_operations',
            ('digest','activity_id','effect_id','commit_seq'),'bot=? AND persona=? AND operation_id=?',self.key)
        if ledger!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
            raise C09PagedCaptureHold('World producer actual same-W01 bundle ledger differs')
        if self.header[1]=='relearn_world_assertion_v1':
            prior=payload['request']['prior_erasure_ref']
            if (type(prior)is not dict or set(prior)!={'assertion_commitment','known_from_sequence','payload_digest'}
                    or prior['assertion_commitment']!=index.assertion_commitment
                    or prior['payload_digest']!=index.prior_erasure_digest
                    or type(prior['known_from_sequence'])is not int or prior['known_from_sequence']<1
                    or prior['known_from_sequence']>=index.known_from_sequence):
                raise C09PagedCaptureHold('World relearning producer lost its exact opaque predecessor metadata')
        writes=payload.get('writes')
        if (type(writes)is not list or len(writes)>128 or len(self.payload.write_keys)!=len(writes)
                or any(values!={'key','value','dependencies'}for values in self.payload.write_keys.values())):
            raise C09PagedCaptureHold('World producer registered output inventory differs')
        chosen=[i for i,value in enumerate(writes)if value.get('key')==index.input_version.key.token]
        if len(chosen)!=1 or writes[chosen[0]].get('dependencies')!=[]:
            raise C09PagedCaptureHold('World producer immutable input write identity/dependencies differ')
        path=('writes',chosen[0],'value')
        if path not in spans or spans[path]['kind']!='object_start' or spans[path]['hash'].hexdigest()!=index.input_digest:
            raise C09PagedCaptureHold('World producer actual immutable input output commitment differs')
        locator=_actual_source_locator_v2(self.build,self.shape,meter)
        member=meter.read_fixed_row(self.build.pair.candidate,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND primary_key_json=?',(locator.identity.stream_id,canonical_serialize(self.key)))
        if member is None or member[1]!=self.row.commitment:
            raise C09PagedCaptureHold('World producer canonical metadata is not its complete captured actual source row')
        require_c09_capture_member_v2(self.build.pair.candidate,locator.identity,member[0],self.key,member[1],meter=meter)
        self.receipt=receipt;self.payload._require();self.complete=True

    def require_for_index(self,build,index):
        build.require_current()
        if (self.build is not build or self.index!=index or not self.complete or not self.quantum_completed
                or not self.row.complete or not self.payload.finished):
            raise C09PagedCaptureHold('World index requires its exact actual complete producer metadata capture')
        return self.index.source_refs


def next_world_producer_metadata_v1(build,index,budget):
    capture=build.world_producer_capture_v1
    if capture is None or capture.index!=index:
        capture=C09WorldProducerMetadataCaptureV1(build,index)
    if capture.complete and capture.quantum_completed:
        capture.require_for_index(build,index)
        return capture,None
    return None,capture.next_quantum(budget)


def require_world_producer_metadata_v1(build,index):
    capture=build.world_producer_capture_v1
    if type(capture)is not C09WorldProducerMetadataCaptureV1:
        raise C09PagedCaptureHold('World producer complete metadata proof is absent')
    return capture.require_for_index(build,index)


def advance_world_producer_target_phase_v1(build,progress):
    from time import monotonic_ns
    from .d03_world_history_v1 import TABLE as INDEX_TABLE,COLUMNS,decode_world_revision_index_row_v1,SIGN_KIND
    from .c09_graph_rebase_candidate_v2 import _save_graph_progress_v2,_graph_step_report_v2
    from .c09_paged_sql_v2 import c09_sql_meter_quantum_v2,capture_transaction_v2
    started=monotonic_ns();next_progress=dict(progress);pending=None
    with build.session.reserve_batch()as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter),legacy_cell_read_transaction_v2(build.pair.source):
            key=tuple(progress['row_complete'])
            row=meter.read_fixed_row(build.pair.source,INDEX_TABLE,COLUMNS,
                'bot=? AND persona=? AND original_ref=?',key)
            if row is None:raise C09PagedCaptureHold('World target metadata phase lost its actual index row')
            index=decode_world_revision_index_row_v1(COLUMNS,row,namespace=NamespaceId(*key[:2]))
            build.session.get_c09_domain_original_issuer_v2()._signer.verify(SIGN_KIND,row[5],row[7])
            complete,pending=next_world_producer_metadata_v1(build,index,budget)
            if complete is not None:next_progress['scan_phase']='rows'
            with capture_transaction_v2(build.pair.candidate):
                _save_graph_progress_v2(build,'target',next_progress,meter)
    if pending is not None:
        pending.quantum_completed=True;build.world_producer_capture_v1=pending
    return _graph_step_report_v2(build,'target',meter,started)


def prepare_cold_world_producer_v1(progress,index,budget):
    complete,pending=next_world_producer_metadata_v1(progress.cold_build,index,budget)
    if pending is not None:progress.prospective_world_producer_capture_v1=pending
    return complete
