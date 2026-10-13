"""Actual final Graph originals; Authority/Owner historical qualification is separate."""
from hashlib import sha256
import json
import sys
from .c09_authority_storage_rebase_v2 import _D13PaidRowStreamV3,C09CanonicalJSONStreamV2,C09PagedCaptureHold


class _NaturalFinalReceiptStreamV3(C09CanonicalJSONStreamV2):
    def __init__(self,**profile):
        super().__init__(**profile);self.starts={};self.ranges={};self.payload_hash=sha256()
        self.payload_start=None;self.payload_end=None;self.scalar=bytearray();self.small={}
    def copy(self):
        result=super().copy();result.starts=dict(self.starts);result.ranges=dict(self.ranges)
        result.payload_hash=self.payload_hash.copy();result.payload_start=self.payload_start;result.payload_end=self.payload_end
        result.scalar=bytearray(self.scalar);result.small=dict(self.small);return result
    def _emit(self,emit,kind,path,start,end,**values):
        root=('natural_final_authorization_original',)
        selected=(len(path)==2 and path[:1]==root or len(path)==3 and path[:2]==root+('payload',)
            or len(path)==4 and path[:2]==root+('payload',) and path[2] in {'route','projection'})
        if selected:
            if kind in {'object_start','array_start','scalar_start'}:self.starts[path]=start
            elif kind in {'object_end','array_end','scalar_end'}:
                self.ranges[path]=(self.starts.pop(path),end)
        if path==root+('payload',):
            if kind=='object_start':self.payload_start=start
            elif kind=='object_end':self.payload_end=end
        if path in {root+('schema',),root+('original_digest',)}:
            if kind=='scalar_start':self.scalar.clear()
            elif kind=='scalar_chunk':self.scalar.extend(values['raw'])
            elif kind=='scalar_end':self.small[path[-1]]=json.loads(self.scalar);self.scalar.clear()
        super()._emit(emit,kind,path,start,end,**values)
    def feed(self,fragment,emit):
        base=self.byte_count;result=super().feed(fragment,emit)
        if self.payload_start is not None:
            left=max(base,self.payload_start);right=min(base+len(fragment),self.payload_end if self.payload_end is not None else base+len(fragment))
            if left<right:self.payload_hash.update(fragment[left-base:right-base])
        return result


class _NaturalFinalAdmissionStreamV4(C09CanonicalJSONStreamV2):
    """Canonical full admission bytes, with finite headers and array spans."""
    def __init__(self,**profile):
        super().__init__(**profile);self.starts={};self.ranges={};self.check_fields={};self.check_indices=set();self.scalar=bytearray()
    def copy(self):
        result=super().copy();result.starts=dict(self.starts);result.ranges=dict(self.ranges)
        result.check_fields={i:dict(value) for i,value in self.check_fields.items()};result.check_indices=set(self.check_indices);result.scalar=bytearray(self.scalar);return result
    def _emit(self,emit,kind,path,start,end,**values):
        check=len(path)==3 and path[0]=='check_receipts' and type(path[1]) is int
        selected=len(path)==1 or check
        if selected:
            if kind in {'object_start','array_start','scalar_start'}:self.starts[path]=start
            elif kind in {'object_end','array_end','scalar_end'}:self.ranges[path]=(self.starts.pop(path),end)
        if len(path)==2 and path[0]=='check_receipts' and kind=='object_start':self.check_indices.add(path[1])
        if check and path[2]!='input_versions':
            if kind=='scalar_start':self.scalar.clear()
            elif kind=='scalar_chunk':self.scalar.extend(values['raw'])
            elif kind=='scalar_end':self.check_fields.setdefault(path[1],{})[path[2]]=json.loads(self.scalar);self.scalar.clear()
        super()._emit(emit,kind,path,start,end,**values)


class NaturalFinalGraphOriginalReadV3(_D13PaidRowStreamV3):
    """Full row commitments and final/admission/event linkage; no live reauthorization."""
    kinds=('bundle','admission','event','owner_issue')
    payload_fields=('schema','namespace','identity','candidate_digest','bundle_digest','graph_receipt',
        'graph_receipt_commitment','admission_ref','admission_digest','admission_receipt_digest','request_digest',
        'scope','owner_guard','clock_reading','clock_policy','now_utc','current_effect','effect_snapshot','route',
        'snapshot_versions','snapshot_epochs','snapshot_commitment','query','projection','checks_digest','owner_issue_original',
        'clock_validation','clock_uses','effect_observation','budget_observation','context_catalogue','graph_barrier')
    def __init__(self,parent):
        from .c09_authority_storage_rebase_v2 import _D13OutboundAdoptionReadV3
        if (type(parent) is not _D13OutboundAdoptionReadV3 or parent.phase!='natural_final_authorization_originals'
                or parent.natural_qualification_original is None or not parent.natural_qualification_original.complete):
            raise C09PagedCaptureHold("actual final originals require completed external Source qualification stage")
        self.parent=parent;self.capture=parent.capture;self.graph=parent.graph;self.source=parent.natural_reference_facts.source
        self.origin=parent.handoff.observation.binding.origin;self.kind_index=0;self.complete=False
        self.receipt_parser=None;self.bundle_small=None;self.admission_small=None;self.admission_values=None
        self.event_small=None;self.event_values=None;self.owner_small=None;self.owner_values=None
        self.payload_values={};self.payload_index=0;self.payload_buffer=bytearray();self.payload_offset=0;self.payload_child_index=0
        self.admission_parser=None;self.admission_ranges={};self.admission_total=None;self.admission_wire_sha=None
        self.admission_field_index=0;self.admission_header={}
        self._start_row();self.capture.parser._source_arena.add(self);self.capture.parser._require_arena()
    def owned_values(self):return (self.bundle_small,self.admission_small,self.admission_values,self.event_small,
        self.event_values,self.owner_small,self.owner_values,self.payload_values,self.admission_header,self.admission_ranges)
    def _source_heap_bytes(self):
        def size(value):
            total=sys.getsizeof(value)
            if type(value) is dict:total+=sum(size(k)+size(v) for k,v in value.items())
            elif type(value) in (list,tuple,set):total+=sum(size(v) for v in value)
            return total
        parser=self.receipt_parser
        extra=0 if parser is None else size(parser.__dict__)+sum(size(getattr(parser,n)) for n in C09CanonicalJSONStreamV2.__slots__ if n!='_emit_callback')
        if isinstance(self.parser,_NaturalFinalReceiptStreamV3) and self.parser is not parser:extra+=size(self.parser.__dict__)
        if self.admission_parser is not None:extra+=size(self.admission_parser.__dict__)+sum(size(getattr(self.admission_parser,n)) for n in C09CanonicalJSONStreamV2.__slots__ if n!='_emit_callback')
        if isinstance(self.parser,_NaturalFinalAdmissionStreamV4) and self.parser is not self.admission_parser:extra+=size(self.parser.__dict__)
        return super()._source_heap_bytes()+extra+size(self.payload_buffer)
    def copy(self):
        result=super().copy();result.payload_values=dict(self.payload_values);result.payload_buffer=bytearray(self.payload_buffer)
        result.receipt_parser=None if self.receipt_parser is None else self.receipt_parser.copy()
        result.admission_parser=None if self.admission_parser is None else self.admission_parser.copy();result.admission_header=dict(self.admission_header)
        result.admission_ranges=dict(self.admission_ranges);return result
    def _start_row(self):
        self.kind=self.kinds[self.kind_index];namespace=self.parent.namespace.as_tuple
        self.phase='source';self.small=None;self.shape=None;self.disposition=None;self.target_small=None
        if self.kind=='bundle':
            self.json_columns=('receipt_json',);self.decode_names=();self.row_key=(*namespace,self.origin.operation_id)
        elif self.kind=='admission':
            self.json_columns=('admission_json','request_json');self.decode_names=self.json_columns;self.row_key=(*namespace,self.origin.admission_ref)
        elif self.kind=='event':
            self.json_columns=('reads','epoch_reads','revisions','invalidated');self.decode_names=self.json_columns
            self.row_key=(*namespace,self.origin.activity_id,self.origin.operation_id)
        else:self.json_columns=('proof_json',);self.decode_names=self.json_columns;self.row_key=namespace
        self.source_hash=sha256();self.target_hash=sha256();self.column=0;self.offset=0;self.total=None
        self.parser=None;self.buffer=bytearray();self.values={};self.json_source_bytes={}
        self.row_where=None
    def _new_source_parser(self,name):
        if self.kind=='bundle':return _NaturalFinalReceiptStreamV3(ensure_ascii=True)
        if self.kind=='admission' and name=='admission_json':return _NaturalFinalAdmissionStreamV4(ensure_ascii=True)
        return super()._new_source_parser(name)
    def _source_json_complete(self,name,parser,eof):
        if self.kind=='bundle' and name=='receipt_json':self.receipt_parser=parser
        elif self.kind=='admission' and name=='admission_json':
            self.admission_parser=parser;self.admission_ranges=dict(parser.ranges);self.admission_total=eof.byte_count;self.admission_wire_sha=eof.sha256
    def _identity(self,meter):
        from ..runtime.natural_final_authorization_original_v3 import SCHEMA_V4 as SCHEMA
        ns=self.parent.namespace.as_tuple;origin=self.origin
        if self.kind=='bundle':
            parser=self.receipt_parser
            if (parser is None or parser.small.get('schema')!=SCHEMA or parser.payload_start is None
                    or parser.payload_end is None or parser.payload_hash.hexdigest()!=parser.small.get('original_digest')):
                raise C09PagedCaptureHold("final historical authorization v3 actual original absent or digest differs; legacy cannot be backfilled")
            wrapper=('natural_final_authorization_original',)
            if {path[-1] for path in parser.ranges if len(path)==2 and path[:1]==wrapper}!={'schema','payload','original_digest'}:
                raise C09PagedCaptureHold("actual final authorization wrapper has another complete field inventory")
            root=('natural_final_authorization_original','payload')
            if {path[-1] for path in parser.ranges if len(path)==3 and path[:2]==root}!=set(self.payload_fields):
                raise C09PagedCaptureHold("actual final authorization payload has another complete field inventory")
            if (self.small['bot'],self.small['persona'],self.small['operation_id'],self.small['activity_id'],self.small['effect_id'])!=(
                    *ns,origin.operation_id,origin.activity_id,origin.effect_id):
                raise C09PagedCaptureHold("actual final bundle crossed original dispatch identity")
            self.bundle_small=self.small
        elif self.kind=='admission':self.admission_small=self.small;self.admission_values=self.values
        elif self.kind=='event':self.event_small=self.small;self.event_values=self.values
        else:self.owner_small=self.small;self.owner_values=self.values
        self.kind_index+=1
        if self.kind_index==len(self.kinds):self.phase='payload';return
        self._start_row()
    def _span_value(self,span,*,table,column,key,total,meter):
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        left,right=span
        if self.payload_offset==right-left:
            self.source.require_arena(len(self.payload_buffer)*32+65536)
            value=json.loads(self.payload_buffer);self.payload_buffer.clear();self.payload_offset=0;return True,value
        amount=min(1024,right-left-self.payload_offset);self.source.require_arena((len(self.payload_buffer)+amount)*32+32768)
        where='bot=? AND persona=? AND '+('admission_ref' if table=='graph_dispatch_admissions' else 'operation_id')+'=?'
        with legacy_cell_read_transaction_v2(self.graph.pair.source):
            raw,actual,kind=read_legacy_sql_cell_fragment_v2(self.graph.pair.source,table=table,column=column,
                where=where,parameters=key,start=left+self.payload_offset,length=amount,meter=meter)
        if kind!='text' or actual!=total or len(raw)!=amount:raise C09PagedCaptureHold('actual final field span lost its complete Source row')
        self.payload_buffer.extend(raw);self.payload_offset+=amount;return False,None
    def _read_admission_fields(self,meter):
        from dataclasses import fields
        from ..runtime.dispatch_admission import DispatchAdmissionV1
        from ..runtime_contracts import CheckReceipt
        parser=self.admission_parser;expected={field.name for field in fields(DispatchAdmissionV1)}
        actual={path[0] for path in parser.ranges if len(path)==1}
        if actual!=expected or parser.check_indices!=set(range(5)):raise C09PagedCaptureHold('actual full final admission/check field inventory differs')
        names=tuple(sorted(expected-{'graph_reads','check_receipts'}))
        if self.admission_field_index==len(names):
            checks=[];check_fields={field.name for field in fields(CheckReceipt)}
            for index in range(5):
                fields_raw=parser.check_fields.get(index,{})
                if set(fields_raw)!=check_fields-{'input_versions'} or ('check_receipts',index,'input_versions') not in parser.ranges:
                    raise C09PagedCaptureHold('actual final check scalar/array field inventory differs')
                checks.append({**fields_raw,'input_versions':None})
            self.values['admission_json']={**self.admission_header,'check_receipts':checks};self.column=1;return
        name=names[self.admission_field_index]
        done,value=self._span_value(parser.ranges[(name,)],table='graph_dispatch_admissions',column='admission_json',
            key=(*self.parent.namespace.as_tuple,self.origin.admission_ref),total=self.admission_total,meter=meter)
        if done:self.admission_header[name]=value;self.admission_field_index+=1
    def _payload(self,meter):
        if self.payload_index==len(self.payload_fields):self.phase='links';return
        name=self.payload_fields[self.payload_index];root=('natural_final_authorization_original','payload')
        if name in {'snapshot_versions','budget_observation'}:self.payload_index+=1;return
        key=(*self.parent.namespace.as_tuple,self.origin.operation_id)
        if name in {'route','projection'}:
            from dataclasses import fields
            if name=='route':
                from ..runtime.reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2 as cls
                excluded={'binding_scan_versions'}
            else:
                from ..runtime.dispatch_current_projection import CurrentDispatchProjectionV1 as cls
                excluded={'role_bindings','boundary_rules'}
            expected={field.name for field in fields(cls)}
            actual={path[-1] for path in self.receipt_parser.ranges if len(path)==4 and path[:3]==root+(name,)}
            if actual!=expected:raise C09PagedCaptureHold('actual final '+name+' complete field inventory differs')
            names=tuple(sorted(expected-excluded))
            if self.payload_child_index==len(names):self.payload_child_index=0;self.payload_index+=1;return
            field_name=names[self.payload_child_index]
            done,value=self._span_value(self.receipt_parser.ranges[root+(name,field_name)],table='graph_bundle_operations',column='receipt_json',key=key,total=self.bundle_total,meter=meter)
            if done:
                existing=dict(self.payload_values.get(name,{}));existing[field_name]=value;self.payload_values[name]=existing;self.payload_child_index+=1
        else:
            done,value=self._span_value(self.receipt_parser.ranges[root+(name,)],table='graph_bundle_operations',column='receipt_json',key=key,total=self.bundle_total,meter=meter)
            if done:self.payload_values[name]=value;self.payload_index+=1
    def _links(self,meter):
        from ..runtime.natural_final_authorization_original_v3 import SCHEMA_V4 as SCHEMA
        value=self.payload_values;ns=self.parent.namespace;origin=self.origin;small=self.admission_small
        if (value['schema']!=SCHEMA or value['namespace']!={'bot_id':ns.bot_id,'persona_id':ns.persona_id}
                or (value['identity']['operation_id'],value['identity']['activity_id'],value['identity']['effect_id'])!=(origin.operation_id,origin.activity_id,origin.effect_id)
                or value['bundle_digest']!=self.bundle_small['digest'] or value['admission_ref']!=origin.admission_ref
                or (small['operation_id'],small['effect_id'],small['admission_digest'],small['receipt_digest'])!=(
                    origin.operation_id,origin.effect_id,value['admission_digest'],value['admission_receipt_digest'])
                or value['query']['revision']!=small['graph_epoch'] or self.event_small['epoch_revision']!=small['graph_epoch']
                or value['scope']['graph_epoch']['revision']+1!=small['graph_epoch']
                or value['scope']['graph_revision']+1!=small['graph_revision']):
            raise C09PagedCaptureHold("actual final authorization business/admission/pre-post Graph links differ")
        self.complete=True
    def advance(self,meter):
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_c09_table_shape_v2
        self.source.require_current();self.capture.builder.require_current();result=self.copy()
        if result.phase=='source':
            result.small,result.shape,result.disposition=self.capture.builder.basis.read_natural_final_source_original_v3(
                result.kind,self.origin.operation_id,self.origin.activity_id,self.origin.admission_ref,meter=meter)
            result.row_where=' AND '.join(name+'=?' for name in result.shape.primary_key_columns);result.phase='source_row'
        elif result.phase=='source_row':result._row_advance(False,meter)
        elif result.phase=='target':
            with legacy_cell_read_transaction_v2(self.graph._read_db):
                shape=read_c09_table_shape_v2(self.graph._read_db,result.shape.table,meter=meter)
                if shape!=result.shape:raise C09PagedCaptureHold("actual final source/target logical schema differs")
                names=tuple(name for name in shape.columns if name not in result.json_columns)
                row=meter.read_fixed_row(self.graph._read_db,shape.table,names,result.row_where,result.row_key)
            if result.disposition.disposition=='derived_removed':
                if row is not None:raise C09PagedCaptureHold("removed final original remains in target")
                result.phase='fields'
            else:
                if row is None:raise C09PagedCaptureHold("retained final original absent in target")
                result.target_small=dict(zip(names,row,strict=True))
                if result.target_small!=result.small:raise C09PagedCaptureHold("actual final source/target small identity differs")
                result.phase='target_row'
        elif result.phase=='target_row':result._row_advance(True,meter)
        elif result.phase=='fields':
            if result.kind=='admission' and result.column==0:result._read_admission_fields(meter)
            else:result._read_fields(meter)
            if result.kind=='bundle' and result.phase=='identity':result.bundle_total=result.json_source_bytes['receipt_json']
        elif result.phase=='identity':result._identity(meter)
        elif result.phase=='payload':result._payload(meter)
        elif result.phase=='links':result._links(meter)
        else:raise C09PagedCaptureHold("unknown actual final Graph original phase")
        self.source.require_current();self.source.require_arena();return result
