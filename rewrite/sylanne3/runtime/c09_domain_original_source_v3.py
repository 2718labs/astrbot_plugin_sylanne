"""Actual C09 Owner material original semantics without retaining its three texts."""
from __future__ import annotations
from copy import copy
from dataclasses import dataclass,fields
from hashlib import sha256
import json
from types import SimpleNamespace
from .c09_graph_row_codec_v2 import _C09RegisteredGraphValueV3,C09MemorySourceJSONStreamV3
from .c09_paged_sql_v2 import C09PagedCaptureHold,current_c09_sql_meter_v2,require_c09_reserved_meter_v3
from ..runtime_contracts import NamespaceId,AuthorityContext,OperationIdentity,canonical_digest,canonical_serialize
from ..memory_types import source_key,access_key,validate_source_metadata_v1,_SOURCE_FIELDS
from .owner_material_source_v1 import owner_material_source_id_v1,AdmitOwnerMaterialSourceRequestV1
from .domain_production_originals_v1 import PHYSICAL_TABLE,_receipt
from .domain_production_original_codec_v1 import _PAYLOAD_FIELDS,_version,_key,_digest,_text
from .domain_production_contracts_v1 import ProductionOwnerGuardV1,ProductionPolicyRefV1,ProductionOriginalRefV1

_TEXT_PATHS=(('request','text'),('provenance','source','text'),('writes',0,'value','text'))
_SOURCE_PATHS=(('provenance','source'),('writes',0,'value'))
_D06_SCHEMA='d06.current-admit_owner_material_source_v1.v1'


@dataclass(frozen=True,slots=True)
class _TextSummaryV3:
    scalar_sha256:str
    characters:int
    nonspace:bool
    atom_hit:bool


class _OwnerOriginalMetadataFSMV3(_C09RegisteredGraphValueV3):
    """Original canonical FSM plus exact registered Source grammar and text witnesses."""
    def __init__(self,*,source_arena=None,atom_pattern=None,text_paths=_TEXT_PATHS,source_paths=_SOURCE_PATHS,root_fields=_PAYLOAD_FIELDS,**profile):
        self.text_paths,self.source_paths,self.root_fields=tuple(text_paths),tuple(source_paths),set(root_fields)
        self.atom_pattern=atom_pattern;self.prefix=[];self.text_states={};self.source_spans={}
        super().__init__(source_arena=source_arena,**profile)
        self.source_grammars={path:C09MemorySourceJSONStreamV3(
            source_arena=self._source_arena,ensure_ascii=self.ensure_ascii) for path in self.source_paths}
        self.source_spans={};self.finished=False
        if atom_pattern is not None:
            self._require(len(atom_pattern)*48+16384)
            for index,char in enumerate(atom_pattern):
                matched=0 if index==0 else self.prefix[-1]
                while matched and atom_pattern[matched]!=char:matched=self.prefix[matched-1]
                if index and atom_pattern[matched]==char:matched+=1
                self.prefix.append(matched)

    def _source_heap_bytes(self):
        from .c09_logical_source_v3 import _retained_size
        return super()._source_heap_bytes()+_retained_size((self.prefix,
            self.text_states,self.source_spans,self.atom_pattern),set())+8192

    def _character(self,path,codepoint):
        state=self.text_states[path];state['characters']+=1
        if state['characters']>65536:raise ValueError('Owner material text exceeds actual Source character bound')
        char=chr(codepoint);state['nonspace']|=not char.isspace()
        if self.atom_pattern is not None and not state['hit']:
            matched=state['position']
            while matched and self.atom_pattern[matched]!=char:matched=self.prefix[matched-1]
            if self.atom_pattern[matched]==char:matched+=1
            state['hit']=matched==len(self.atom_pattern);state['position']=matched
        if path[:-1] in self.source_grammars:
            grammar=self.source_grammars[path[:-1]]
            grammar._source_text_characters=state['characters']
            grammar._source_text_nonempty=True

    def _append_decoded_codepoint(self,codepoint):
        state=self._string
        if state is None or state['mode']!='value' or state['path'] not in self.text_paths:
            return super()._append_decoded_codepoint(codepoint)
        path=state['path'];text=self.text_states[path];high=text['high']
        if high is not None:
            text['high']=None
            if 0xdc00<=codepoint<=0xdfff:
                self._character(path,0x10000+((high-0xd800)<<10)+codepoint-0xdc00);return
            self._character(path,high)
        if 0xd800<=codepoint<=0xdbff:text['high']=codepoint
        else:self._character(path,codepoint)

    def _emit(self,emit,kind,path,start,end,**values):
        if kind=='scalar_end' and path in self.text_paths:
            state=self.text_states[path]
            if state['high'] is not None:self._character(path,state['high']);state['high']=None
        if kind=='key' and len(path)==1 and values['key'] not in self.root_fields:
            raise ValueError('unregistered Owner material original root field')
        for prefix,grammar in self.source_grammars.items():
            if path[:len(prefix)]==prefix:
                relative=path[len(prefix):]
                grammar._emit(lambda event:None,kind,relative,start,end,**values)
                if kind=='object_start' and not relative:
                    self.source_spans[prefix]={'start':start,'end':None,'hash':sha256()}
                elif kind=='object_end' and not relative:self.source_spans[prefix]['end']=end
        if path in self.text_paths:
            if kind=='scalar_start':
                if values['scalar_kind']!='string':raise ValueError('Owner original text must be a JSON string')
                self.text_states[path]={'hash':sha256(),'characters':0,'nonspace':False,'hit':False,'position':0,'high':None}
            elif kind=='scalar_chunk':self.text_states[path]['hash'].update(values['raw'])
            elif kind=='scalar_end':
                state=self.text_states[path]
                if state['high'] is not None:self._character(path,state['high']);state['high']=None
                if not state['nonspace']:raise ValueError('Owner request requires nonblank original text')
                self._put(path,_TextSummaryV3(state['hash'].hexdigest(),state['characters'],state['nonspace'],state['hit']))
            return
        if path==('request',):
            if kind=='object_start':self.source_spans[path]={'start':start,'end':None,'hash':sha256()}
            elif kind=='object_end':self.source_spans[path]['end']=end
        super()._emit(emit,kind,path,start,end,**values)

    def feed(self,raw,emit):
        begin=self.byte_count
        super().feed(raw,emit)
        for span in self.source_spans.values():
            end=self.byte_count if span['end'] is None else span['end']
            lower=max(begin,span['start']);upper=min(self.byte_count,end)
            if upper>lower:span['hash'].update(raw[lower-begin:upper-begin])

    def copy(self):
        result=super().copy();result.atom_pattern=self.atom_pattern;result.prefix=list(self.prefix)
        result.text_paths=self.text_paths;result.source_paths=self.source_paths;result.root_fields=self.root_fields
        result.text_states={path:{**state,'hash':state['hash'].copy()} for path,state in self.text_states.items()}
        result.source_grammars={path:grammar.copy() for path,grammar in self.source_grammars.items()}
        result.source_spans={path:{**state,'hash':state['hash'].copy()} for path,state in self.source_spans.items()}
        result.finished=self.finished;return result

    def finish(self):
        result=super().finish()
        if type(self.value) is not dict or set(self.value)!=self.root_fields or set(self.text_states)!=set(self.text_paths):
            raise ValueError('Owner original exact registered field/text-path set differs')
        for grammar in self.source_grammars.values():
            if grammar._source_fields!=_SOURCE_FIELDS or not grammar._source_text_nonempty:
                raise ValueError('Owner original Source field/character grammar differs')
            metadata=dict(grammar._source_metadata)
            for name in ('audiences','purposes','parent_source_ids'):metadata[name]=tuple(metadata[name])
            validate_source_metadata_v1(**metadata)
        self.finished=True;return result


class C09MappedDomainOriginalCaptureV3:
    """Private actual13-column Source producer with incremental semantic qualification."""
    def __init__(self,build,shape,key,metadata,*,pattern_kind=None,pattern_ref=None):
        from .c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
        from .c09_logical_source_v3 import read_c09_logical_source_shape_v3,begin_logical_source_row_v3
        from .domain_production_registry_v1 import installed_operation_v1
        if type(build) is not InstalledGraphRebaseBuildV2 or shape.table!=PHYSICAL_TABLE:
            raise TypeError('actual registered Domain physical Source capture required')
        build.require_current();meter=current_c09_sql_meter_v2()
        self.build,self.shape,self.key,self.metadata=build,shape,tuple(key),metadata
        self.pattern_kind,self.pattern_ref=pattern_kind,pattern_ref;self.quantum_completed=False
        self.namespace=NamespaceId(*self.key[:2]);self.operation_id=self.key[2]
        if self.namespace.as_tuple!=tuple(json.loads(build.scope.graph_namespace)):raise ValueError('Domain original namespace differs')
        operation=installed_operation_v1('admit_owner_material_source_v1')
        if operation.domain!='d06' or operation.request_type is not AdmitOwnerMaterialSourceRequestV1:
            raise ValueError('actual Owner material request registration differs')
        self.scope=build.session.begin_source_physical_read_v3(build.pair,meter=meter)
        self.logical_shape=read_c09_logical_source_shape_v3(self.scope,shape.table,meter=meter)
        if self.logical_shape.physical_shape!=shape:raise ValueError('Domain physical shape changed')
        row=meter.read_fixed_row(build.pair.source,PHYSICAL_TABLE,
            ('domain','operation_kind','original_digest','original_payload_cell_id','prepared_digest','bundle_digest','receipt_digest','request_digest'),
            'bot=? AND persona=? AND operation_id=?',self.key)
        if row is None or row[:2]!=('d06','admit_owner_material_source_v1'):raise ValueError('registered Domain original row absent')
        self.identity=row;self.header=self.scope.read_cell_header_v3(row[3],meter=meter)
        self.prepared=self.scope.read_owner_source_prepared_metadata_v3(row[4],meter=meter)
        self.prepared.require_current(meter=meter)
        parser=_OwnerOriginalMetadataFSMV3(source_arena=self.scope.arena,ensure_ascii=True,
            atom_pattern=pattern_ref if pattern_kind=='atom' else None)
        self.value=SimpleNamespace(parser=parser,complete=False)
        self.aux={name:_C09RegisteredGraphValueV3(source_arena=self.scope.arena,ensure_ascii=True)
            for name in ('read_versions_json','receipt_json')}
        self.aux_finished=set();self.row=begin_logical_source_row_v3(self.scope,self.logical_shape,self.key,meter)
        self.semantic_stage='envelope';self.semantic_index=0;self.semantic_subindex=0
        self.read_refs=set();self.graph_refs=set();self.receipt=None;self.reads=None
        self.scope.arena.add(self)

    def _source_heap_bytes(self):
        from .c09_logical_source_v3 import _retained_size
        return 4096+_retained_size((self.read_refs,self.graph_refs,self.aux_finished),set())

    def _copy(self):
        self.value.parser._require(self._source_heap_bytes())
        result=copy(self);result.quantum_completed=False
        result.value=copy(self.value);result.value.parser=self.value.parser.copy()
        result.aux={name:parser.copy() for name,parser in self.aux.items()}
        result.aux_finished=set(self.aux_finished);result.read_refs=set(self.read_refs);result.graph_refs=set(self.graph_refs)
        self.scope.arena.add(result);return result

    def next_quantum(self,budget):
        meter=require_c09_reserved_meter_v3(budget);self.build.require_current();self.prepared.require_current(meter=meter)
        self.scope.require_current(meter=meter)
        result=self._copy()
        if not self.row.complete:
            result.row=self.row.advance(meter);fragment=result.row.last_logical_fragment
            if fragment is not None:
                name,raw=fragment
                if name=='original_payload_json':result.value.parser.feed(raw,lambda event:None)
                elif name in result.aux:result.aux[name].feed(raw,lambda event:None)
            eof=result.row.last_cell_eof
            if eof=='original_payload_json':
                finished=result.value.parser.finish()
                if (finished.sha256,finished.byte_count)!=(self.identity[2],self.header[4]):
                    raise ValueError('Domain original canonical whole EOF/header SHA differs')
            elif eof in result.aux:
                result.aux[eof].finish();result.aux_finished.add(eof)
        elif not result.value.complete:result._advance_semantics(meter)
        self.build.require_current();return result

    def _small_metadata(self,name):
        value=self.row.metadata[name]
        if type(value) is not str:raise ValueError('typed auxiliary metadata did not complete its registered stream')
        if len(value.encode('utf8'))>4096:raise ValueError('large auxiliary metadata requires its actual stream')
        parser=_C09RegisteredGraphValueV3(source_arena=self.scope.arena,ensure_ascii=True)
        parser.feed(value.encode('utf8'),lambda event:None);parser.finish();return parser.value

    def _advance_semantics(self,meter):
        payload=self.value.parser.value;prepared=self.prepared.metadata
        if self.semantic_stage=='envelope':
            if (self.identity[7]!=prepared['expected_outputs']['stage_request']['payload_sha256']
                    or self.identity[2]!=prepared['expected_outputs']['original']['payload_sha256']
                    or self.header[2]!=prepared['source_ref']
                    or (self.header[8]==self.prepared.prepared_digest and self.header[3]!=prepared['operation_id'])
                    or self.header[4]!=prepared['expected_outputs']['original']['total_bytes']):
                raise ValueError('Domain physical request/original prepared binding differs')
            if (not self.value.parser.finished or payload['schema']!=_D06_SCHEMA
                    or payload['namespace']!={'bot_id':self.namespace.bot_id,'persona_id':self.namespace.persona_id}
                    or payload['identity']!=prepared['envelope']['identity']
                    or payload['authority']!=prepared['envelope']['authority']
                    or payload['parent_budget']!=prepared['parent_budget_original_ref']
                    or payload['now_utc']!=prepared['original_now_utc']
                    or canonical_digest(payload['owner_guard'])!=prepared['owner_guard_digest']
                    or payload['coverage']!='complete' or payload['missing_inputs']!=[] or payload['continuation_ref'] is not None):
                raise ValueError('Domain original actual prepared envelope/Owner/Root/clock differs')
            if set(payload['identity'])!={f.name for f in fields(OperationIdentity)} or set(payload['authority'])!={f.name for f in fields(AuthorityContext)}:
                raise ValueError('Domain original typed envelope fields differ')
            OperationIdentity(**payload['identity'])
            authority=dict(payload['authority']);authority['namespace']=self.namespace;AuthorityContext(**authority)
            guard=ProductionOwnerGuardV1(**payload['owner_guard']);_key(guard.grant_ref,self.namespace)
            if set(payload['request'])!={'text'} or set(payload['provenance'])!={'source_ref','source','source_access'} or len(payload['writes'])!=2:
                raise ValueError('registered Owner material stage structure differs')
            texts=(payload['request']['text'],payload['provenance']['source']['text'],payload['writes'][0]['value']['text'])
            if any(type(value) is not _TextSummaryV3 for value in texts) or len({(value.scalar_sha256,value.characters) for value in texts})!=1:
                raise ValueError('original request/provenance/write texts differ')
            self.reads=self.aux['read_versions_json'].value if 'read_versions_json' in self.aux_finished else self._small_metadata('read_versions_json')
            receipt_raw=self.aux['receipt_json'].value if 'receipt_json' in self.aux_finished else self._small_metadata('receipt_json')
            self.receipt=_receipt(receipt_raw)
            if (canonical_digest(self.receipt)!=self.identity[6] or self.receipt.operation_id!=self.operation_id
                    or self.receipt.operation_digest!=self.identity[5]):raise ValueError('Domain original receipt identity differs')
            bundle=meter.read_fixed_row(self.build.pair.source,'graph_bundle_operations',
                ('digest','activity_id','effect_id','commit_seq'),'bot=? AND persona=? AND operation_id=?',self.key)
            if bundle!=(self.receipt.operation_digest,self.receipt.activity_id,self.receipt.effect_id,self.receipt.commit_seq):
                raise ValueError('Domain original actual same-W01 receipt join differs')
            self.semantic_stage='reads';self.semantic_index=0;return
        if self.semantic_stage=='reads':
            values=payload['read_versions'];expected=prepared['frame_snapshot_versions']
            if len(values)>1024 or len(values)!=len(expected) or len(values)!=len(self.reads):raise ValueError('original actual readset bound/count differs')
            if self.semantic_index<len(values):
                i=self.semantic_index;key,revision=_version(values[i],self.namespace)
                if values[i]!=expected[i] or self.reads[i]!=[key.token,revision] or key.token in self.read_refs:
                    raise ValueError('original actual readset key/revision/order differs')
                self.read_refs.add(key.token);self.graph_refs.add(key.token);self.semantic_index+=1;return
            self.semantic_stage='policies';self.semantic_index=0;return
        if self.semantic_stage=='policies':
            values=payload['policy_refs'];expected=prepared['policy_refs']
            if len(values)>128 or len(values)!=len(expected):raise ValueError('actual policy count differs')
            if self.semantic_index<len(values):
                value=values[self.semantic_index]
                if value!=expected[self.semantic_index]:raise ValueError('actual immutable policy binding differs')
                ProductionPolicyRefV1(**value);self.semantic_index+=1;return
            self.semantic_stage='queries';self.semantic_index=0;return
        if self.semantic_stage=='queries':
            values=payload['query_coverage'];expected=prepared['query_coverage']
            if len(values)>64 or len(values)!=len(expected):raise ValueError('actual query coverage bound/count differs')
            if self.semantic_index<len(values):
                value=values[self.semantic_index]
                if value!=expected[self.semantic_index] or set(value)!={'epoch','type_id','row_versions','complete','continuation_ref'}:
                    raise ValueError('actual query metadata differs')
                if value['epoch'].get('namespace')!=payload['namespace'] or type(value['complete']) is not bool or value['complete']!=(value['continuation_ref'] is None) or len(value['row_versions'])>128:
                    raise ValueError('actual query namespace/continuation differs')
                self.build.session._control.maintenance.graph._registry.spec(value['type_id'])
                for version in value['row_versions']:_version(version,self.namespace)
                self.semantic_index+=1;return
            self.semantic_stage='observed';self.semantic_index=0;self.semantic_subindex=0;return
        if self.semantic_stage=='observed':
            values=payload['observed_originals']
            if len(values)>128:raise ValueError('observed original count differs')
            if self.semantic_index<len(values):
                value=values[self.semantic_index]
                if set(value)!={f.name for f in fields(ProductionOriginalRefV1)} or len(value['read_versions'])>1024:
                    raise ValueError('observed original schema/bound differs')
                _digest(value['original_digest'])
                _text(value['original_ref']);_text(value['kind'])
                if self.semantic_subindex<len(value['read_versions']):
                    key,_=_version(value['read_versions'][self.semantic_subindex],self.namespace)
                    self.semantic_subindex+=1;return
                self.semantic_index+=1;self.semantic_subindex=0;return
            self.semantic_stage='source';return
        if self.semantic_stage=='source':
            source_id=owner_material_source_id_v1(self.namespace,self.operation_id)
            source=source_key(*self.namespace.as_tuple,source_id);access=access_key(*self.namespace.as_tuple,source_id)
            provenance=payload['provenance'];source_value=provenance['source'];written=payload['writes'][0]
            if (source_value!=written['value'] or provenance['source_ref']!=source.token or written['key']!=source.token
                    or written['dependencies']!=[] or source.token not in self.read_refs or access.token not in self.read_refs):
                raise ValueError('Domain original Source read/write/provenance exact identity differs')
            metadata=self.value.parser.source_grammars[('provenance','source')]._source_metadata
            if (metadata['source_id']!=source_id or metadata['speaker_id']!=payload['authority']['actor']
                    or metadata['recorded_at']!=payload['now_utc'] or metadata['source_kind']!='authored'
                    or metadata['occurred_at'] is not None or metadata['provenance_root']!='owner-material:'+source_id
                    or metadata['audiences']!=['owner'] or metadata['purposes']!=['context','consolidation']
                    or metadata['parent_source_ids']!=[] or metadata['assertion_status']!='unknown' or metadata['independence']!='unknown'):
                raise ValueError('actual Owner material Source actor/clock/rights/ancestry differs')
            access_value=provenance['source_access'];expected={'source_id':source_id,'audiences':['owner'],
                'purposes':['context','consolidation'],'status':'active','recorded_at':payload['now_utc']}
            if (access_value!=expected or payload['writes'][1]!={'key':access.token,'value':access_value,'dependencies':[source.token]}):
                raise ValueError('actual Owner material access write/provenance differs')
            from ..memory_types import validate_access
            validate_access(access_value)
            source_sha=self.value.parser.source_spans[('writes',0,'value')]['hash'].hexdigest()
            input_sha=self.value.parser.source_spans[('request',)]['hash'].hexdigest()
            if input_sha!=prepared['expected_outputs']['input']['payload_sha256']:
                raise ValueError('actual original request canonical span differs from prepared input original')
            if source_sha!=prepared['expected_outputs']['source']['payload_sha256']:
                raise ValueError('actual Source object canonical span differs from prepared output original')
            if tuple(self.row.result.descriptor['cell_bindings'][0]['source_header9'])!=self.header:
                raise ValueError('Domain original real old Source Header9 changed')
            self.graph_refs.add(source.token);self.graph_refs.add(access.token)
            self.value.complete=True;self.semantic_stage='complete';return
        raise ValueError('unknown Domain semantic stage')

    def require_complete(self,build,shape,key,metadata):
        self.prepared.require_current(meter=current_c09_sql_meter_v2())
        if (self.build is not build or self.shape!=shape or self.key!=tuple(key) or self.metadata!=metadata
                or not self.quantum_completed or not self.row.complete or not self.value.complete):
            raise C09PagedCaptureHold('actual Domain Source semantic/canonical/row/quantum EOF required')
        return self.row.result.commitment

    def require_nested_hit(self,build,shape,key,metadata,small_sql):
        self.require_complete(build,shape,key,metadata)
        from .c09_closure_index_v2 import _nested_pattern_hit
        if self.pattern_kind not in ('atom','source_id') or type(self.pattern_ref) is not str:
            raise C09PagedCaptureHold('actual closure pattern required')
        hit=_nested_pattern_hit(self.value.parser.value,self.pattern_ref,source_id=self.pattern_kind=='source_id')
        if self.pattern_kind=='atom':hit|=any(state['hit'] for state in self.value.parser.text_states.values())
        return hit


class C09ColdDomainOriginalCellV3:
    """Independent new target cell, compared with actual frozen Source fragments."""
    def __init__(self,progress,shape,key):
        from .c09_graph_rebase_candidate_v2 import GraphRebaseColdProgressV2
        if type(progress) is not GraphRebaseColdProgressV2 or shape.table!=PHYSICAL_TABLE:
            raise TypeError('actual Domain cold verifier required')
        meter=current_c09_sql_meter_v2();progress.session.require_current();progress.pair.require_current()
        self.progress,self.shape,self.key=progress,shape,tuple(key)
        self.scope=progress.session.begin_source_physical_read_v3(progress.pair,meter=meter)
        original=meter.read_fixed_row(progress.pair.source,PHYSICAL_TABLE,('original_payload_cell_id',),
            'bot=? AND persona=? AND operation_id=?',self.key)
        self.source_header=self.scope.read_cell_header_v3(original[0],meter=meter)
        namespace=NamespaceId(*self.key[:2]);owner=source_key(*namespace.as_tuple,owner_material_source_id_v1(namespace,self.key[2])).token
        target=meter.read_row(progress.read_db,shape,self.key)
        if target is None:raise C09PagedCaptureHold('Domain target physical row is absent')
        self.physical=tuple(target);cell=target[shape.columns.index('original_payload_cell_id')]
        self.header=meter.read_fixed_row(progress.read_db,'segmented_cells_v1',
            ('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
             'payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(cell,))
        layout=meter.read_fixed_row(progress.read_db,'segmented_storage_layout_v1',('storage_instance_id',),'singleton=?',(1,))
        locator={'role':'graph','family':shape.table,'primary_key':self.key,'column':'original_payload_json',
            'source_schema_digest':shape.schema_digest}
        expected=canonical_digest({'schema':'sylanne3.segmented-cell-identity.v1','instance':layout[0],
            'scope':progress.session.scope.scope_digest,'erasure_owner':owner,
            'producer':progress.session.scope.operation_id,'locator':locator})
        if (self.header is None or cell!=expected or self.header[:4]!=(cell,'canonical-json.ascii.v1',owner,progress.session.scope.operation_id)
                or self.header[8]!=progress.session.scope.scope_digest
                or (self.header[4],self.header[6])!=(self.source_header[4],self.source_header[6])):
            raise C09PagedCaptureHold('Domain target exact cell/owner/capture actor/Source canonical bytes differ')
        self.ordinal=self.offset=0;self.hash=sha256()
        self.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell));self.complete=False
        self.scope.arena.add(self)

    def _source_heap_bytes(self):
        from .c09_logical_source_v3 import _retained_size
        return 4096+_retained_size((self.physical,self.header,self.source_header),set())

    def advance(self):
        self.progress.session.require_current();self.progress.pair.require_current()
        meter=current_c09_sql_meter_v2();self.scope.require_current(meter=meter)
        if sum(value._source_heap_bytes() for value in self.scope.arena)+self._source_heap_bytes()>meter.budget.reserved_arena_bytes:
            raise C09PagedCaptureHold('Domain cold prospective state exceeds its actual shared Source arena')
        result=copy(self);result.hash=self.hash.copy();self.scope.arena.add(result)
        if self.complete:return result
        cell=self.header[0]
        if self.ordinal<self.header[5]:
            row=meter.read_fixed_row(self.progress.read_db,'segmented_cell_segments_v1',
                ('byte_offset','payload','payload_sha256'),'cell_id=? AND ordinal=?',(cell,self.ordinal))
            if row is None or row[0]!=self.offset or type(row[1]) is not bytes or not 1<=len(row[1])<=16384 or sha256(row[1]).hexdigest()!=row[2]:
                raise C09PagedCaptureHold('Domain target segment bytes/order/hash differ')
            original,total=self.scope.read_cell_fragment_v3(self.source_header[0],start=self.offset,length=len(row[1]),meter=meter)
            if original!=row[1] or total!=self.header[4]:raise C09PagedCaptureHold('Domain target segment differs from actual original Source')
            result.hash.update(row[1]);result.root=canonical_digest(('sylanne3.segmented-cell-link.v1',
                self.root,cell,self.ordinal,self.offset,len(row[1]),row[2]))
            result.ordinal+=1;result.offset+=len(row[1]);return result
        extra=meter.read_fixed_row(self.progress.read_db,'segmented_cell_segments_v1',('ordinal',),
            'cell_id=? AND ordinal>=? ORDER BY ordinal',(cell,self.ordinal))
        original,total=self.scope.read_cell_fragment_v3(self.source_header[0],start=self.offset,length=0,meter=meter)
        if (extra is not None or original or total!=self.offset
                or (self.offset,self.hash.hexdigest(),self.root)!=(self.header[4],self.header[6],self.header[7])):
            raise C09PagedCaptureHold('Domain target independent exact EOF/header/hash/root differs')
        result.complete=True;return result

def _domain_removed_v3(capture,closure,nested_hit):
    return (closure.contains_operation(capture.operation_id) or nested_hit
        or any(closure.contains_atom(ref) for ref in capture.graph_refs))


def advance_domain_original_target_v3(build,progress,shape):
    """Use actual target quantum; publish new ref/disposition/page/cursor atomically."""
    from ..segmented_sql_cell_v1 import open_c09_segmented_target_v1,VerifiedSealedCellV1
    from .c09_closure_index_v2 import C09ClosureIndexV2
    from .c09_paged_sql_v2 import (capture_transaction_v2,_load_census,_capture_data_state,
        read_capture_cursor_v2,read_c09_next_row_metadata_v2,require_c09_capture_member_v2,c09_row_commitment_v2,_wire)
    from .c09_paged_capture_contract_v2 import C09CaptureRecordV2,append_c09_page_v2
    from .c09_graph_rebase_candidate_v2 import (_source_stream_identity_v2,_actual_source_locator_v2,
        _read_graph_disposition_original_row_v3,_graph_logical_preservation_original_v3,
        GRAPH_DISPOSITION_COLUMNS_V2,GRAPH_DISPOSITION_COLUMNS_V3,_save_graph_progress_v2,_graph_step_report_v2)
    from ..authority_service.c09_authority_storage_rebase import _row_commitment
    from dataclasses import asdict
    from time import monotonic_ns
    if build.segmented_target_v3 is None:build.segmented_target_v3=open_c09_segmented_target_v1(build.session,build.pair)
    key=tuple(progress['row_complete']);target=build.segmented_target_v3;started=monotonic_ns()
    capture=build.source_row_capture_v3
    if type(capture) is not C09MappedDomainOriginalCaptureV3 or capture.key!=key:
        raise C09PagedCaptureHold('Domain target requires the actual completed same-row Source producer')
    writer=build.segmented_writer_v3;seal=build.segmented_seal_v3;next_progress=dict(progress)
    with target.quantum() as quantum:
        meter=quantum.meter;capture.require_complete(build,shape,key,capture.metadata)
        candidate=build.pair.candidate;source=build.pair.source
        closure=C09ClosureIndexV2(candidate,build.scope)
        if closure._state()[3]!='sealed':raise C09PagedCaptureHold('Domain target needs actual closure EOF')
        removed=_domain_removed_v3(capture,closure,progress.get('nested_hit',False))
        stream=_source_stream_identity_v2(build,shape,'row_dispositions')
        locator=_actual_source_locator_v2(build,shape,meter)
        member=meter.read_fixed_row(candidate,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND primary_key_json=?',(locator.identity.stream_id,canonical_serialize(key)))
        if member is None or member[1]!=capture.row.result.commitment:
            raise C09PagedCaptureHold('Domain target Source original member differs')
        require_c09_capture_member_v2(candidate,locator.identity,member[0],key,member[1],meter=meter)
        cursor=read_capture_cursor_v2(candidate,stream)
        found=read_c09_next_row_metadata_v2(source,shape,cursor.last_key)
        existing=_read_graph_disposition_original_row_v3(candidate,build.scope.scope_digest,shape.table,key,meter)
        if existing is None and (found is None or found[0]!=key):
            raise C09PagedCaptureHold('Domain target is outside actual current Source cursor')
        if not removed and seal is None:
            if writer is None:writer=target.begin_mapped_cell_copy(quantum,source_row=capture.row.result,column='original_payload_json')
            else:writer=writer.copy_progress_v3(quantum)
            if writer.phase=='write':writer.advance(quantum)
            elif writer.phase=='replay_prefix':writer.replay_prefix(quantum)
            elif writer.phase=='verify':
                value=writer.verify_and_seal(quantum)
                if type(value) is VerifiedSealedCellV1:seal=value
            else:raise C09PagedCaptureHold('Domain target writer requires actual publication recovery')
            if seal is not None:next_progress['scan_phase']='domain_publish'
            with capture_transaction_v2(candidate):_save_graph_progress_v2(build,'target',next_progress,meter)
        else:
            original=meter.read_row(source,shape,key)
            if original is None:raise C09PagedCaptureHold('Domain actual physical Source row disappeared')
            if removed:
                row=None;commitment=None;kind='derived_removed';columns=GRAPH_DISPOSITION_COLUMNS_V2;table='c09_graph_dispositions_v2'
            else:
                ref=seal.require_current(target,quantum=quantum,table=shape.table,primary_key=key,column='original_payload_json')
                values=list(original);values[shape.columns.index('original_payload_cell_id')]=ref.cell_id;row=tuple(values)
                commitment=_row_commitment(shape.table,shape.columns,row)
                kind='logical_preserved_v3';columns=GRAPH_DISPOSITION_COLUMNS_V3;table='c09_graph_dispositions_v3'
            proof=(build.scope.scope_digest,shape.table,canonical_digest((shape.table,key)),canonical_serialize(key),
                member[1],kind,commitment,locator.identity.stream_id,member[0])
            if not removed:
                header=quantum.read_header(candidate,ref.cell_id)
                proof+=_graph_logical_preservation_original_v3(build.scope.scope_digest,shape.table,key,
                    capture.row.result.descriptor,capture.header,header,commitment)
            with capture_transaction_v2(candidate):
                _load_census(candidate,stream);data=_capture_data_state(candidate,stream)
                actual=meter.read_row(candidate,shape,key)
                if existing is not None:
                    if existing!=proof or actual!=row:raise C09PagedCaptureHold('Domain committed row/disposition replay differs')
                    sealed_member=meter.read_fixed_row(candidate,'c09_capture_members_v2',('record_ordinal','commitment'),
                        'stream_id=? AND primary_key_json=?',(stream.stream_id,canonical_serialize(key)))
                    if sealed_member is None or sealed_member[1]!=c09_row_commitment_v2(proof):
                        raise C09PagedCaptureHold('Domain publication replay lost real page member')
                    require_c09_capture_member_v2(candidate,stream,sealed_member[0],key,sealed_member[1],meter=meter)
                else:
                    if actual is not None or data['eof'] is not None:raise C09PagedCaptureHold('Domain target exists without atomic disposition')
                    if row is not None:meter.write_row(candidate,shape.table,shape.columns,row)
                    meter.write_row(candidate,table,columns,proof)
                    record=C09CaptureRecordV2(key,c09_row_commitment_v2(proof));page=append_c09_page_v2(stream,cursor,(record,))
                    quantum.mutate(candidate,'INSERT INTO c09_capture_pages_v2 VALUES(?,?,?,?)',
                        (stream.stream_id,page.page_index,_wire(page),json.dumps([asdict(record)],sort_keys=True,separators=(',',':'))))
                    quantum.mutate(candidate,'INSERT INTO c09_capture_members_v2 VALUES(?,?,?,?,?,?)',
                        (stream.stream_id,cursor.record_offset+1,canonical_digest(key),canonical_serialize(key),record.commitment,page.page_index))
                    data['cursor']=asdict(page.next_cursor)
                    quantum.mutate(candidate,"UPDATE c09_capture_progress_v2 SET progress_json=? WHERE stream_id=? AND phase='data'",
                        (canonical_serialize(data),stream.stream_id))
                next_progress.update(scan_phase='patterns',pattern_kind='atom',pattern_after=None,nested_hit=False,row_complete=None)
                _save_graph_progress_v2(build,'target',next_progress,meter)
            writer=seal=capture=None
    # A failed actual reservation exit adopts none of the prospective volatile state.
    build.segmented_writer_v3=writer;build.segmented_seal_v3=seal;build.source_row_capture_v3=capture
    build.require_current();return _graph_step_report_v2(build,'target',meter,started)


def verify_cold_domain_original_v3(progress,shape,key,metadata,meter,*,verify_semantics=True):
    from .c09_closure_index_v2 import C09ClosureIndexV2
    from .c09_graph_rebase_candidate_v2 import (_advance_source_nested_match_v3,
        _actual_streamed_source_origin_v3,
        _read_graph_disposition_original_row_v3,_require_graph_logical_disposition_original_v3)
    from .c09_storage_rebase_contract_v1 import GraphRowDispositionV1
    from ..authority_service.c09_authority_storage_rebase import _row_commitment
    closure=C09ClosureIndexV2(progress.read_db,progress.session.scope)
    if closure._state()[3]!='sealed':raise C09PagedCaptureHold('Domain cold requires actual sealed closure')
    build=progress.cold_build
    if not verify_semantics and not progress.source_semantic_eof:
        raise C09PagedCaptureHold('Domain cold cannot skip independent actual Source semantics')
    hit,done,pending,_=_advance_source_nested_match_v3(build,shape,key,metadata,closure,
        progress.pattern_progress,meter.budget,meter)
    progress.prospective_source_capture_v3=pending
    if not done:return None
    capture=pending if pending is not None else build.source_row_capture_v3
    if type(capture) is not C09MappedDomainOriginalCaptureV3:
        raise C09PagedCaptureHold('Domain cold lost its actual completed typed producer')
    origin=_actual_streamed_source_origin_v3(build,shape,key,metadata,capture,meter)
    proof=_read_graph_disposition_original_row_v3(progress.read_db,progress.session.scope.scope_digest,shape.table,key,meter)
    if (proof is None or proof[4]!=origin['origin_commitment']
            or proof[7]!=origin['origin_stream_id'] or proof[8]!=origin['origin_record_ordinal']):
        raise C09PagedCaptureHold('Domain cold lost exact Source original/member/ordinal')
    removed=_domain_removed_v3(capture,closure,hit)
    if removed:
        actual=meter.read_row(progress.read_db,shape,key)
        if proof[5:7]!=('derived_removed',None) or actual is not None:
            raise C09PagedCaptureHold('Domain erased original retained target body/ref')
        result=GraphRowDispositionV1(proof[2],proof[4],proof[5],proof[6])
    else:
        reader=progress.domain_cold_cell_v3
        if reader is None or reader.shape!=shape or reader.key!=tuple(key):reader=C09ColdDomainOriginalCellV3(progress,shape,key)
        prospective=reader.advance();progress.prospective_domain_cell_v3=(prospective,)
        if not prospective.complete:return None
        original=meter.read_row(progress.pair.source,shape,key)
        values=list(original);values[shape.columns.index('original_payload_cell_id')]=prospective.header[0]
        if prospective.physical!=tuple(values) or _row_commitment(shape.table,shape.columns,tuple(values))!=proof[6]:
            raise C09PagedCaptureHold('Domain target actual13-column metadata/ref differs from frozen Source')
        result=_require_graph_logical_disposition_original_v3(build,progress.read_db,shape,key,proof,meter,target_header=prospective.header)
        progress.prospective_domain_cell_v3=(None,)
    progress.pattern_progress={'pattern_kind':'atom','pattern_after':None,'nested_hit':False}
    return result
