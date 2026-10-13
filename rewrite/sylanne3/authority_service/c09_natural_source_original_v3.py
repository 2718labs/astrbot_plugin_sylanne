"""Historical natural Source/Access originals through existing C09 epoch witnesses."""
from copy import copy
from dataclasses import fields,is_dataclass
import sys


class NaturalSourceOriginalReadV3:
    def __init__(self,parent):
        from .c09_authority_storage_rebase_v2 import _D13OutboundAdoptionReadV3,C09PagedCaptureHold
        if (type(parent) is not _D13OutboundAdoptionReadV3 or parent.phase!='natural_source_originals'
                or parent.natural_paid_output_stage!=2):
            raise C09PagedCaptureHold("actual natural Source requires both original paid outputs")
        self.parent=parent;self.capture=parent.capture;self.graph=parent.graph
        self.source=parent.natural_reference_facts.source;self.facts=parent.natural_reference_facts.parser
        self.epoch=parent.natural_acquires['generation'].acquire['graph_epoch']
        self.source.require_arena((len(self.facts.references)+16)*1024)
        self.question=self.facts.references[('input','question','ref')]
        selected={self.question}
        selected.update(value for path,value in self.facts.references.items()
            if len(path)==6 and path[:3]==('input','plan','units') and path[4] in {'source_refs','access_refs','correction_refs'})
        self.references=tuple(sorted(selected,key=lambda value:(value.ref,value.version)))
        self.index=0;self.phase='locator';self.locator=None;self.row_index=0;self.row=None;self.semantic=None
        self.sources={};self.source_texts={};self.accesses={};self.corrections=set();self.text_hash=None;self.parents=();self.parent_index=0;self.closure_index=0;self.closure_sources=();self.complete=False
        self.source.arena.add(self);self.source.require_arena()
    def _source_heap_bytes(self):
        def size(value):
            total=sys.getsizeof(value)
            if type(value) is dict:total+=sum(size(k)+size(v) for k,v in value.items())
            elif type(value) in (tuple,list,set):total+=sum(size(v) for v in value)
            elif is_dataclass(value) and not isinstance(value,type):total+=sum(size(getattr(value,f.name)) for f in fields(value))
            return total
        return sys.getsizeof(self.__dict__)+sum(size(value) for value in
            (self.references,self.locator,self.sources,self.source_texts,self.accesses,self.corrections,self.parents,self.text_hash,self.closure_sources))+4096
    def copy(self):
        self.source.require_arena(self._source_heap_bytes());result=copy(self)
        result.sources=dict(self.sources);result.source_texts=dict(self.source_texts);result.accesses=dict(self.accesses);result.corrections=set(self.corrections);self.source.arena.add(result);return result
    def _identity(self,meter):
        from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold
        from ..graph_types import AtomKey
        from ..runtime.c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3,C09MemoryAccessJSONStreamV3
        reference=self.references[self.index];meter.require_available(len(reference.ref));self.source.require_arena(len(reference.ref)*32+16384)
        key=AtomKey.from_token(reference.ref);meter.charge_encode(len(reference.ref))
        audience=self.facts.metadata[('input','plan','audience_id')]
        if self.locator.value_kind=='memory.source':
            if type(self.semantic) is not C09MemorySourceJSONStreamV3:raise C09PagedCaptureHold("actual natural Source full semantic parser absent")
            value=self.semantic._source_metadata
            if (value['source_id']!=key.owner.subject or audience not in value['audiences'] or 'expression' not in value['purposes']):
                raise C09PagedCaptureHold("natural original Source namespace/audience/purpose differs")
            if reference==self.question:
                expected=self.parent.natural_context_parts.parts[('input','question')]
                if self.text_hash!=expected[6] or self.semantic._source_text_characters!=expected[7]:
                    raise C09PagedCaptureHold("natural frozen question differs from complete original Source text")
            self.sources[reference.ref]=dict(value);self.parents=tuple(value['parent_source_ids']);self.parent_index=0;self.phase='parents'
        elif self.locator.value_kind=='memory.access':
            if type(self.semantic) is not C09MemoryAccessJSONStreamV3:raise C09PagedCaptureHold("actual natural Access full semantic parser absent")
            value=self.semantic.metadata
            if (value['source_id']!=key.owner.subject or value['status']!='active'
                    or audience not in value['audiences'] or 'expression' not in value['purposes']):
                raise C09PagedCaptureHold("natural original Access was not active for original audience/expression")
            self.accesses[reference.ref]=dict(value);self.phase='next'
        elif self.locator.value_kind=='d06.source_correction_head.v1':
            if reference.version!=0 or not self.locator.absent:
                raise C09PagedCaptureHold("natural original Source or ancestor had a correction")
            self.corrections.add(reference.ref);self.phase='next'
        else:raise C09PagedCaptureHold("natural Source inventory contains another original family")
    def _parent(self,meter):
        from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold
        from ..memory_types import source_key,access_key
        from ..domains.d06 import source_correction_head_key
        from ..runtime_contracts import VersionedRef
        if self.parent_index==len(self.parents):self.phase='next';return
        source_id=self.parents[self.parent_index];namespace=self.parent.namespace
        meter.require_available((len(source_id)+sum(map(len,namespace.as_tuple)))*48+1536)
        self.source.require_arena((len(source_id)+128)*64)
        keys=(source_key(*namespace.as_tuple,source_id),access_key(*namespace.as_tuple,source_id),source_correction_head_key(namespace,source_id))
        wanted=tuple(key.token for key in keys)
        meter.charge_encode(sum(map(len,wanted)))
        reads=self.parent.natural_requests['generation'].request_envelope.version_guard.read_versions
        additional=[]
        for key,token in zip(keys,wanted,strict=True):
            revision=next((version.revision for version in reads if version.key==key),None)
            if (type(revision) is not int or key.type_name=='d06.source_correction_head.v1' and revision!=0
                    or key.type_name!='d06.source_correction_head.v1' and revision<1):
                raise C09PagedCaptureHold("natural Source parent lacks its actual original guarded Source/Access revision")
            ref=VersionedRef(token,revision)
            if ref not in self.references:additional.append(ref)
        self.source.require_arena((len(self.references)+len(additional)+16)*256)
        self.references+=tuple(additional);self.parent_index+=1
    def _closure(self,meter):
        from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold
        from ..memory_types import access_key
        from ..domains.d06 import source_correction_head_key
        self.source.require_arena((len(self.sources)+len(self.accesses)+16)*512)
        if self.closure_index==len(self.closure_sources):self.complete=True;return
        token=self.closure_sources[self.closure_index];value=self.sources[token]
        meter.require_available((len(value['source_id'])+sum(map(len,self.parent.namespace.as_tuple))+128)*24)
        wanted=access_key(*self.parent.namespace.as_tuple,value['source_id']).token;meter.charge_encode(len(wanted))
        if wanted not in self.accesses:raise C09PagedCaptureHold("natural historical Source closure lacks matching original Access")
        correction=source_correction_head_key(self.parent.namespace,value['source_id']).token;meter.charge_encode(len(correction))
        if correction not in self.corrections:raise C09PagedCaptureHold("natural historical Source closure lacks original correction absence")
        self.closure_index+=1
    def advance(self,meter):
        from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold,_D13ContextEpochRowReadV3
        self.source.require_current();self.capture.builder.require_current();result=self.copy()
        if result.phase=='locator':
            if result.index==len(result.references):
                self.source.require_arena((len(result.sources)+16)*128)
                result.closure_sources=tuple(result.sources);result.phase='closure'
            else:
                result.locator=self.capture.builder.basis.read_d13_context_epoch_locator_v3(result.references[result.index],result.epoch,meter=meter)
                result.row_index=0;result.row=None;result.semantic=None;result.text_hash=None;result.phase='rows'
        elif result.phase=='rows':
            if result.row_index==len(result.locator.rows):result.phase='identity'
            elif result.row is None:result.row=_D13ContextEpochRowReadV3(self)
            elif not self.row.complete:result.row=self.row.advance(meter)
            else:
                if self.row.shape.table=='graph_history' and self.row.row_key==(self.locator.reference.ref,self.locator.reference.version):
                    result.semantic=self.row.semantic_parser;result.text_hash=self.row.text_hash.hexdigest()
                    if result.locator.value_kind=='memory.source':
                        result.source_texts[result.locator.reference.ref]=(result.locator.reference,self.row.text_start,
                            self.row.text_start+self.row.text_size,self.row.json_source_bytes['value'],
                            self.row.semantic_parser._source_text_characters)
                result.row_index+=1;result.row=None
        elif result.phase=='identity':result._identity(meter)
        elif result.phase=='parents':result._parent(meter)
        elif result.phase=='next':
            result.index+=1;result.locator=None;result.semantic=None;result.phase='locator'
        elif result.phase=='closure':result._closure(meter)
        else:raise C09PagedCaptureHold("unknown actual natural Source original phase")
        self.source.require_current();self.source.require_arena();return result
