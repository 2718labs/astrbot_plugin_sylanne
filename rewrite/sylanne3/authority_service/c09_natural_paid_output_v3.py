"""Actual frozen Core observations bound to natural generation and paid review."""
from copy import copy
import json
import sys
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2


class _NaturalResultTextStreamV3(C09CanonicalJSONStreamV2):
    """Canonical result object; retain only the formally bounded Python text."""
    def __init__(self, **profile):
        super().__init__(**profile)
        self.limit=32768;self.parts=[];self.pending=[];self.count=0;self.high=None;self.fields=set()
    def copy(self):
        result=super().copy();result.limit=self.limit;result.parts=list(self.parts)
        result.pending=list(self.pending);result.count=self.count;result.high=self.high;result.fields=set(self.fields)
        return result
    def _point(self,point):
        if self.count>=self.limit:raise ValueError("natural provider output exceeds original Python character limit")
        self.pending.append(chr(point));self.count+=1
    def _append_decoded_codepoint(self,point):
        state=self._string
        if state is not None and state['mode']=='value':
            if state['path']!=('text',):raise ValueError("natural provider result is not exactly text")
            if self.high is not None:
                high=self.high;self.high=None
                if 0xdc00<=point<=0xdfff:
                    self._point(0x10000+((high-0xd800)<<10)+point-0xdc00)
                    return super()._append_decoded_codepoint(point)
                self._point(high)
            if 0xd800<=point<=0xdbff:self.high=point
            else:self._point(point)
        return super()._append_decoded_codepoint(point)
    def _emit(self,emit,kind,path,start,end,**values):
        if kind=='object_start' and path:raise ValueError("natural provider result has nested object")
        if kind=='array_start':raise ValueError("natural provider result has array")
        if kind=='key':
            if path!=('text',) or values['key']!='text':raise ValueError("natural provider result has another field")
            self.fields.add(values['key'])
        if kind=='scalar_start' and (path!=('text',) or values.get('scalar_kind')!='string'):
            raise ValueError("natural provider result text has another type")
        if kind=='scalar_end' and self.high is not None:self._point(self.high);self.high=None
        super()._emit(emit,kind,path,start,end,**values)
    def flush(self,meter):
        if self.pending:
            meter.charge_encode(len(self.pending)*8)
            self.parts.append(''.join(self.pending));self.pending.clear()
    def finish(self):
        result=super().finish()
        if self.fields!={'text'}:raise ValueError("natural provider result lacks exact text field")
        return result


class NaturalPaidOutputReadV3:
    """One real Core row per call, full observation digest and formal output semantics."""
    def __init__(self,parent):
        from .c09_authority_storage_rebase_v2 import _D13OutboundAdoptionReadV3,C09PagedCaptureHold,_D13PaidEncodedStringStreamV3
        if (type(parent) is not _D13OutboundAdoptionReadV3 or parent.phase!='natural_paid_outputs'
                or parent.natural_model_stage!=2):
            raise C09PagedCaptureHold("natural paid outputs require both actual admitted model originals")
        self.parent=parent;self.capture=parent.capture;self.source=parent.natural_reference_facts.source
        self.pair=self.capture.builder.pair;self.source_original=self.pair.source_original
        self.stage=('generation','review')[parent.natural_paid_output_stage]
        self.original=parent.natural_models[self.stage].original;self.phase='row';self.total=None;self.offset=0
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=True);self.start=None;self.span=None;self.fields=set()
        self.decoder=_D13PaidEncodedStringStreamV3(ensure_ascii=True);self.result_parser=_NaturalResultTextStreamV3(ensure_ascii=True)
        self.result_parser.limit=32768 if self.stage=='generation' else 16384
        self.text=None;self.output_digest=None;self.units=();self.verdict=None;self.complete=False
        self.source.arena.add(self);self.source.require_arena()
    def _source_heap_bytes(self):
        def size(value):
            total=sys.getsizeof(value)
            if type(value) in (list,tuple,set):total+=sum(size(x) for x in value)
            elif type(value) is dict:total+=sum(size(k)+size(v) for k,v in value.items())
            else:
                from dataclasses import fields,is_dataclass
                if is_dataclass(value) and not isinstance(value,type):total+=sum(size(getattr(value,f.name)) for f in fields(value))
            return total
        streams=(self.parser,self.decoder,self.result_parser)
        total=sys.getsizeof(self.__dict__)+size(self.fields)+size(self.text)+size(self.units)+4096
        for stream in streams:
            total+=sys.getsizeof(stream)+sum(size(getattr(stream,name)) for name in C09CanonicalJSONStreamV2.__slots__ if name not in {'_emit_callback','_feeding'})
            if hasattr(stream,'__dict__'):total+=size(stream.__dict__)
        return total
    def copy(self):
        self.source.require_arena(self._source_heap_bytes());result=copy(self)
        result.fields=set(self.fields);result.parser=self.parser.copy();result.decoder=self.decoder.copy()
        result.result_parser=self.result_parser.copy();self.source.arena.add(result);return result
    def _event(self,event):
        if event.kind=='key' and len(event.path)==1:self.fields.add(event.key)
        if event.path==('result_json',):
            if event.kind=='scalar_start':
                if event.scalar_kind!='string':raise ValueError("completed natural observation lacks result JSON")
                self.start=event.start_offset
            elif event.kind=='scalar_end':self.span=(self.start,event.end_offset)
    def _read(self,start,amount,meter):
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold
        self.source.require_arena(amount*48+32768)
        with legacy_cell_read_transaction_v2(self.pair.source):
            raw,total,kind=read_legacy_sql_cell_fragment_v2(self.pair.source,table='authority_model_egress_observations_v1',
                column='observation_json',where='call_id=?',parameters=(self.original.call_id,),start=start,length=amount,meter=meter)
        if kind!='text' or total!=self.total or len(raw)!=amount:raise C09PagedCaptureHold("actual natural observation Source changed")
        return raw
    def _semantics(self,meter):
        from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold
        from ..model_broker.natural_review import _generation_output,_validate_natural_reply_review_output_payload_v1
        from ..model_broker.natural_reply import _unique_fields,_validate_expression_output_scope_v2
        from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
        parent=self.parent;paid=parent.paid_review_original.value;facts=parent.natural_reference_facts.parser
        self.source.require_arena(len(self.text)*48+65536)
        if self.stage=='generation':
            data=json.loads(self.text,object_pairs_hook=_unique_fields)
            size=c09_canonical_json_size_v3(data,exact=True);meter.require_available(size*2)
            body,units,digest,canonical=_generation_output(data);meter.charge_encode(size)
            def members(name):
                selected={path[3]:value for path,value in facts.metadata.items()
                    if len(path)==4 and path[:3]==('input','plan',name)}
                if set(selected)!=set(range(len(selected))):raise C09PagedCaptureHold("actual plan output-scope tuple has gaps")
                return tuple(selected[i] for i in range(len(selected)))
            scope_members=len(facts.metadata)+len(facts.references)+len(parent.natural_units.units)
            self.source.require_arena((scope_members+32)*512)
            basis={value[0]:value[1].value for value in parent.natural_units.units.values()}
            grants={value.ref for path,value in facts.references.items() if len(path)==4 and path[:3]==('input','plan','promise_grants')}
            status=_validate_expression_output_scope_v2(data,basis_kinds=basis,allowed_grants=grants,
                required_slots=members('required_slots'),allowed_speech_acts=members('allowed_speech_acts'))
            if (status!='untrusted_content_candidate' or digest!=parent.natural_output_conformance.output_digest
                    or digest!=paid['generation_output_digest']):
                raise C09PagedCaptureHold("actual provider generation differs from adopted complete batch and paid review")
            self.units=units;self.output_digest=digest
        else:
            generation=parent.natural_paid_outputs['generation'];frozen=parent.natural_frozens['review'].parser.metadata
            data=json.loads(self.text,object_pairs_hook=_unique_fields)
            size=c09_canonical_json_size_v3(data,exact=True);meter.require_available(size*3)
            parsed=_validate_natural_reply_review_output_payload_v1(data,semantic_batch=True,units=generation.units,
                generation_frozen_input_digest=frozen['generation_frozen_input_digest'],
                generation_output_digest=frozen['generation_output_digest'],review_frozen_input_digest=frozen['digest'])
            meter.charge_encode(size)
            if (parsed.output_digest!=paid['review_output_digest']
                    or parsed.verdict!='pass' or data.get('prefix_safe') is not True):
                raise C09PagedCaptureHold("actual provider review differs from adopted paid verdict/prefix safety")
            self.output_digest=parsed.output_digest;self.verdict=parsed.verdict
        self.text=None;self.result_parser.parts.clear();self.complete=True
    def advance(self,meter):
        from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_c09_table_shape_v2,read_legacy_sql_cell_fragment_v2
        self.source.require_current();self.capture.builder.require_current();result=self.copy()
        if self.pair is not self.capture.builder.pair or self.source_original!=self.pair.source_original:
            raise C09PagedCaptureHold("natural observation lost same frozen Core role source")
        if result.phase=='row':
            with legacy_cell_read_transaction_v2(self.pair.source):
                shape=read_c09_table_shape_v2(self.pair.source,'authority_model_egress_observations_v1',meter=meter)
                if shape.columns!=('call_id','observation_json','observation_digest') or shape.primary_key_columns!=('call_id',):
                    raise C09PagedCaptureHold("natural actual observation Core schema differs")
                row=meter.read_fixed_row(self.pair.source,shape.table,('call_id','observation_digest'),'call_id=?',(self.original.call_id,))
                _,result.total,kind=read_legacy_sql_cell_fragment_v2(self.pair.source,table=shape.table,column='observation_json',
                    where='call_id=?',parameters=(self.original.call_id,),start=0,length=0,meter=meter)
            if row!=(self.original.call_id,self.original.observation_digest_or_none) or kind!='text' or not result.total:
                raise C09PagedCaptureHold("natural actual observation row does not match sealed execution")
            result.phase='observation'
        elif result.phase=='observation':
            if result.offset==result.total:
                eof=result.parser.finish()
                required={'authority_id','namespace','subject','operation_id','call_id','request_digest','status','result_json','usage','cost','provider_call_ref'}
                if eof.sha256!=self.original.observation_digest_or_none or result.span is None or result.fields not in (required,required|{'billing_receipt_json'}):
                    raise C09PagedCaptureHold("complete natural observation differs from actual sealed digest/wire")
                result.offset=0;result.phase='result'
            else:
                amount=min(1024,result.total-result.offset);raw=result._read(result.offset,amount,meter)
                result.parser.feed(raw,result._event);result.parser._emit_callback=None;result.offset+=amount
        elif result.phase=='result':
            left,right=result.span
            if result.offset==right-left:
                result.decoder.finish();result.result_parser.finish();result.result_parser.flush(meter)
                self.source.require_arena(result.result_parser.count*8+32768);meter.charge_encode(result.result_parser.count*4)
                result.text=''.join(result.result_parser.parts);result.phase='semantics'
            else:
                amount=min(1024,right-left-result.offset);raw=result._read(left+result.offset,amount,meter)
                result.decoder.feed(raw,lambda event:None);result.decoder._emit_callback=None
                decoded=bytes(result.decoder.pending);result.decoder.pending.clear();meter.charge_encode(len(decoded))
                if decoded:result.result_parser.feed(decoded,lambda event:None);result.result_parser._emit_callback=None
                result.result_parser.flush(meter);result.offset+=amount
        elif result.phase=='semantics':result._semantics(meter)
        else:raise C09PagedCaptureHold("unknown actual natural provider output phase")
        self.source.require_current();self.source.require_arena();return result
