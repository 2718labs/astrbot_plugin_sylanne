"""Actual historical D06 qualification, using the unchanged formal identity recipe."""
from copy import copy
from dataclasses import fields,is_dataclass
from hashlib import sha256
import json
import sys


class NaturalQualificationOriginalReadV3:
    def __init__(self,parent):
        from .c09_authority_storage_rebase_v2 import _D13OutboundAdoptionReadV3,C09PagedCaptureHold
        if (type(parent) is not _D13OutboundAdoptionReadV3 or parent.phase!='natural_qualification_originals'
                or parent.natural_source_original is None or not parent.natural_source_original.complete):
            raise C09PagedCaptureHold("natural qualifications require complete actual historical Source originals")
        self.parent=parent;self.capture=parent.capture;self.source=parent.natural_reference_facts.source
        self.original=parent.natural_source_original;self.facts=parent.natural_reference_facts.parser
        self.source.require_arena((len(self.facts.units)+16)*128)
        self.paths=tuple(sorted(self.facts.units));self.index=0;self.phase='unit';self.small=None;self.refs={};self.extra={}
        self.pending=[];self.visited=set();self.lineage=[];self.root=None;self.field_index=0;self.closure_index=0;self.closure_accesses=[];self.closure_corrections=[]
        self.text_name='source_excerpt';self.text_phase='source';self.text_parser=None;self.text_offset=0
        self.expected_text=None
        self.qualification_pieces=();self.qualification_index=0;self.qualification_offset=0
        self.qualification_literal=None;self.qualification_hash=sha256();self.verified={};self.qualification_digests=set();self.producer_paths=[];self.complete=False
        self.source.arena.add(self);self.source.require_arena()
    def _source_heap_bytes(self):
        def size(value):
            total=sys.getsizeof(value)
            if type(value) is dict:total+=sum(size(k)+size(v) for k,v in value.items())
            elif type(value) in (list,tuple,set):total+=sum(size(v) for v in value)
            elif is_dataclass(value) and not isinstance(value,type):total+=sum(size(getattr(value,f.name)) for f in fields(value))
            return total
        total=sys.getsizeof(self.__dict__)+sum(size(v) for v in (self.paths,self.small,self.refs,self.extra,self.pending,
            self.visited,self.lineage,self.root,self.expected_text,
            self.qualification_pieces,self.qualification_literal,self.verified,self.qualification_digests,self.producer_paths,self.closure_accesses,self.closure_corrections))+4096
        if self.text_parser is not None:
            from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
            total+=size(self.text_parser.__dict__)+sum(size(getattr(self.text_parser,n)) for n in C09CanonicalJSONStreamV2.__slots__ if n!='_emit_callback')
        return total
    def copy(self):
        self.source.require_arena(self._source_heap_bytes());result=copy(self)
        result.refs=dict(self.refs);result.extra=dict(self.extra);result.pending=list(self.pending)
        result.visited=set(self.visited);result.lineage=list(self.lineage);result.verified=dict(self.verified)
        result.producer_paths=list(self.producer_paths);result.qualification_digests=set(self.qualification_digests);result.closure_accesses=list(self.closure_accesses);result.closure_corrections=list(self.closure_corrections);result.qualification_hash=self.qualification_hash.copy()
        result.text_parser=None if self.text_parser is None else self.text_parser.copy();self.source.arena.add(result);return result
    def _unit(self,meter):
        from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold
        if self.index==len(self.paths):self.complete=True;return
        path=self.paths[self.index];self.source.require_arena((len(self.facts.references)+len(self.facts._unit_scalars)+16)*512)
        self.small={name:self.facts.metadata[path+(name,)] for name in self.facts._unit_scalars}
        digest=self.small['qualification_digest']
        if (type(digest) is not str or len(digest)!=64 or any(char not in '0123456789abcdef' for char in digest)
                or digest in self.qualification_digests):
            raise C09PagedCaptureHold("actual natural qualification set is incomplete or repeats original digest")
        self.qualification_digests.add(digest)
        kind=self.small['d06_claim_kind']
        if kind not in {'attributed_report','confirmed_external_fact'}:
            from ..runtime.natural_producer_qualification_v1 import C04_KIND,DRAFT_KIND
            if kind not in {C04_KIND,DRAFT_KIND}:raise C09PagedCaptureHold("natural qualification has unknown original producer kind")
            self.producer_paths.append(path);self.index+=1;return
        self.refs={}
        for name in ('source_refs','access_refs','correction_refs'):
            selected={p[5]:ref for p,ref in self.facts.references.items() if len(p)==6 and p[:5]==path+(name,)}
            if set(selected)!=set(range(len(selected))):raise C09PagedCaptureHold("actual qualification reference indices differ")
            self.refs[name]=tuple(selected[i] for i in range(len(selected)))
        if not self.refs['source_refs']:raise C09PagedCaptureHold("actual Source qualification lacks root")
        self.root=self.refs['source_refs'][0];self.extra={};self.field_index=0;self.phase='fields'
    def _field(self,meter):
        names=('evidence_span','direct_quote_span','negation_cue_span')
        if self.field_index==len(names):self.phase='scope';return
        name=names[self.field_index];left,right=self.source.evidence.projection_ranges[self.paths[self.index]+(name,)]
        self.source.require_range(left,right);size=right-left;meter.require_available(size)
        self.source.require_arena(size*32+32768)
        raw=self.source._read_fragment(left,size,meter);value=json.loads(raw)
        self.extra[name]=None if value is None else tuple(value);self.field_index+=1
    def _scope(self,meter):
        from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold
        from ..domains.d06.qualified_expression import SourceTextSpan
        from ..graph_types import AtomKey
        small=self.small;record=self.original.sources.get(self.root.ref)
        if record is None:raise C09PagedCaptureHold("actual qualification root Source original absent")
        self.source.require_arena(len(self.root.ref)*32+16384);meter.require_available(len(self.root.ref))
        key=AtomKey.from_token(self.root.ref);meter.charge_encode(len(self.root.ref))
        evidence=SourceTextSpan(*self.extra['evidence_span']);characters=self.original.source_texts[self.root.ref][4]
        for name in ('direct_quote_span','negation_cue_span'):
            value=self.extra[name]
            if value is not None:
                span=SourceTextSpan(*value)
                if not evidence.start<=span.start<span.end<=evidence.end:
                    raise C09PagedCaptureHold("actual qualification quote/negation lies outside Source evidence")
        if (evidence.end>characters or type(small['direct_quote']) is not bool
                or (self.extra['direct_quote_span'] is None)!= (small['direct_quote'] is False)):
            raise C09PagedCaptureHold("actual qualification original Source span/quote pairing differs")
        claim=small['d06_claim_kind']
        if (claim=='confirmed_external_fact' and (record['source_kind'],record['assertion_status'])!=('observed','confirmed')
                or claim=='attributed_report' and record['source_kind'] not in {'reported','observed'}):
            raise C09PagedCaptureHold("actual Source kind cannot support original claim qualification")
        expected={'speaker_id':record['speaker_id'],'occurred_at':record['occurred_at'],'learned_at':record['recorded_at'],
            'source_kind':record['source_kind'],'assertion_status':record['assertion_status'],
            'attribution_required':claim=='attributed_report',
            'polarity_status':'source_cue_unreviewed' if self.extra['negation_cue_span'] else 'unspecified_unreviewed',
            'kind':'reported_claim' if claim=='attributed_report' else 'external_fact',
            'content_reality':'external_report' if claim=='attributed_report' else 'external_observation'}
        if self.paths[self.index]+('qualification_ref',) in self.facts.references or any(small[name]!=value for name,value in expected.items()):
            raise C09PagedCaptureHold("actual qualified unit attributes differ from original Source")
        self.pending=[key.owner.subject];self.visited=set();self.lineage=[];self.phase='lineage'
    def _lineage(self,meter):
        from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold
        from ..memory_types import source_key
        if not self.pending:
            self.closure_index=0;self.closure_accesses=[];self.closure_corrections=[];self.phase='closure';return
        source_id=self.pending.pop()
        if source_id in self.visited:return
        self.visited.add(source_id)
        if len(self.visited)>256:raise C09PagedCaptureHold("D06 original qualification ancestry exceeds its formal bound")
        meter.require_available((len(source_id)+sum(map(len,self.parent.namespace.as_tuple))+128)*12)
        token=source_key(*self.parent.namespace.as_tuple,source_id).token;meter.charge_encode(len(token))
        record=self.original.sources.get(token)
        if record is None:raise C09PagedCaptureHold("actual Source qualification ancestry original missing")
        self.source.require_arena((len(record['parent_source_ids'])+len(self.pending)+16)*128)
        self.lineage.append(token);self.pending.extend(record['parent_source_ids'])
    def _closure(self,meter):
        from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold
        from ..memory_types import access_key
        from ..domains.d06 import source_correction_head_key
        self.source.require_arena((len(self.lineage)+sum(map(len,self.refs.values()))+16)*1024)
        if tuple(ref.ref for ref in self.refs['source_refs'])!=tuple(self.lineage):
            raise C09PagedCaptureHold("actual qualification Source refs differ from original D06 traversal order")
        if self.closure_index<len(self.lineage):
            token=self.lineage[self.closure_index];source_id=self.original.sources[token]['source_id'];namespace=self.parent.namespace
            upper=(len(source_id)+sum(map(len,namespace.as_tuple))+128)*24;meter.require_available(upper)
            access=access_key(*namespace.as_tuple,source_id).token;correction=source_correction_head_key(namespace,source_id).token
            meter.charge_encode(len(access)+len(correction));self.closure_accesses.append(access);self.closure_corrections.append(correction)
            self.closure_index+=1;return
        accesses=self.closure_accesses;corrections=self.closure_corrections
        if ({ref.ref for ref in self.refs['access_refs']}!=set(accesses)
                or {(ref.ref,ref.version) for ref in self.refs['correction_refs']}!={(token,0) for token in corrections}
                or any(ref not in self.original.references for group in self.refs.values() for ref in group)):
            raise C09PagedCaptureHold("actual qualification Access/correction refs differ from verified Source closure")
        self.text_name='source_excerpt';self.text_phase='source';self.text_parser=None;self.text_offset=0;self.phase='text'
    def _text(self,meter):
        from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold,_D13ClaimCodepointStreamV3
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        if self.text_parser is None:
            selected=self.extra['direct_quote_span'] if self.text_name=='qualified_text' and self.small['direct_quote'] else self.extra['evidence_span']
            self.text_parser=_D13ClaimCodepointStreamV3(selected if self.text_phase=='source' else None,ensure_ascii=True)
            self.text_offset=0;return
        if self.text_phase=='source':
            reference,left,right,total,count=self.original.source_texts[self.root.ref]
        else:
            left,right=self.source.evidence.projection_ranges[self.paths[self.index]+(self.text_name,)]
            self.source.require_range(left,right)
        if self.text_offset==right-left:
            self.text_parser.finish()
            actual=(self.text_parser.digest.hexdigest(),self.text_parser.selected_count)
            if self.text_phase=='source':
                self.expected_text=actual;self.text_phase='frozen';self.text_parser=None;return
            if actual!=self.expected_text:raise C09PagedCaptureHold("actual qualified excerpt/quote differs from original Source Python slice")
            if self.text_name=='source_excerpt':
                self.text_name='qualified_text';self.text_phase='source';self.text_parser=None
            else:self.text_parser=None;self.phase='recipe'
            return
        amount=min(1024,right-left-self.text_offset);self.source.require_arena(amount*24+16384)
        if self.text_phase=='source':
            with legacy_cell_read_transaction_v2(self.parent.graph.pair.source):
                raw,actual,kind=read_legacy_sql_cell_fragment_v2(self.parent.graph.pair.source,table='graph_history',column='value',
                    where='token=? AND revision=?',parameters=(reference.ref,reference.version),start=left+self.text_offset,length=amount,meter=meter)
            if actual!=total or kind!='text' or len(raw)!=amount:raise C09PagedCaptureHold("actual qualification Source text range changed")
        else:raw=self.source._read_fragment(left+self.text_offset,amount,meter)
        self.text_parser.feed(raw,lambda event:None);self.text_parser._emit_callback=None;self.text_offset+=amount
    def _recipe(self,meter):
        from .c09_authority_storage_rebase_v2 import _qualified_expression_identity_pieces_v3
        from ..domains.d06.qualified_expression import _qualified_expression_identity_payload_v1
        from ..memory_types import access_key
        self.source.require_arena((sum(map(len,self.refs.values()))+len(self.lineage)+32)*1024)
        record=self.original.sources[self.root.ref];namespace=self.parent.namespace;source_id=record['source_id']
        meter.require_available((len(source_id)+sum(map(len,namespace.as_tuple))+128)*12)
        access=access_key(*namespace.as_tuple,source_id).token;meter.charge_encode(len(access))
        access_revision=next(ref.version for ref in self.refs['access_refs'] if ref.ref==access)
        values=_qualified_expression_identity_payload_v1(source_ref=self.root.ref,source_revision=self.root.version,
            access_revision=access_revision,claim_kind=self.small['d06_claim_kind'],source_excerpt=None,
            evidence_span=self.extra['evidence_span'],quote_span=self.extra['direct_quote_span'],quote_text=None,
            negation_cue_span=self.extra['negation_cue_span'],source_metadata=record,audiences=(self.small['audience_ref'],),
            lineage_source_refs=self.lineage,access_epoch=self.parent.natural_requests['generation'].request_envelope.version_guard.access_epoch,
            deletion_epoch=self.parent.natural_requests['generation'].request_envelope.version_guard.delete_epoch,
            valid_until=self.small['expires_at_utc'],read_versions=sorted({(ref.ref,ref.version) for group in self.refs.values() for ref in group}))
        ranges={'source_excerpt':('frozen',self.source.evidence.projection_ranges[self.paths[self.index]+('source_excerpt',)])}
        if self.small['direct_quote']:ranges['quote_text']=('frozen',self.source.evidence.projection_ranges[self.paths[self.index]+('qualified_text',)])
        self.qualification_pieces=_qualified_expression_identity_pieces_v3(values,ranges,meter,self.source.require_arena)
        self.qualification_index=0;self.qualification_offset=0;self.qualification_literal=None;self.qualification_hash=sha256();self.phase='digest'
    def _digest(self,meter):
        from .c09_authority_storage_rebase_v2 import _advance_qualified_expression_identity_v3,C09PagedCaptureHold
        def read_range(kind,span,offset,amount,meter):
            if kind!='frozen':raise C09PagedCaptureHold("natural qualification range has another actual source kind")
            self.source.require_range(*span);return self.source._read_fragment(span[0]+offset,amount,meter)
        if _advance_qualified_expression_identity_v3(self,meter,self.source.require_arena,read_range):
            actual=self.qualification_hash.hexdigest()
            if actual!=self.small['qualification_digest']:raise C09PagedCaptureHold("actual historical D06 qualification digest differs from frozen unit")
            self.verified[self.paths[self.index]]=actual;self.index+=1;self.phase='unit'
    def advance(self,meter):
        from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold
        self.source.require_current();self.capture.builder.require_current();result=self.copy()
        if result.phase=='unit':result._unit(meter)
        elif result.phase=='fields':result._field(meter)
        elif result.phase=='scope':result._scope(meter)
        elif result.phase=='lineage':result._lineage(meter)
        elif result.phase=='closure':result._closure(meter)
        elif result.phase=='text':result._text(meter)
        elif result.phase=='recipe':result._recipe(meter)
        elif result.phase=='digest':result._digest(meter)
        else:raise C09PagedCaptureHold("unknown actual natural qualification phase")
        self.source.require_current();self.source.require_arena();return result
