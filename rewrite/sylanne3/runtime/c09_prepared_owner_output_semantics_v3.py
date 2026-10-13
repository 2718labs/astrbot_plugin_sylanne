"""Registered Owner prepared output semantics over actual Source quantum copies."""
from __future__ import annotations
from copy import copy,deepcopy
from dataclasses import asdict,fields
from weakref import WeakSet
from .c09_paged_sql_v2 import C09PagedCaptureHold
from .c09_domain_original_source_v3 import _OwnerOriginalMetadataFSMV3,_TextSummaryV3
from ..runtime_contracts import canonical_digest,_canonical_value,NamespaceId,DomainBundle,DomainProposal,DependencySet
from ..graph_types import AtomKey,GraphVersion,GraphWrite
from ..memory_types import source_key,access_key,_SOURCE_FIELDS,validate_access
from .owner_material_source_v1 import owner_material_source_id_v1,AdmitOwnerMaterialSourceRequestV1
from .domain_production_original_codec_v1 import _PAYLOAD_FIELDS,_version,_digest,_text
_SOURCES=WeakSet()

def _profile(name):
    if name=='input':return (('text',),),(),{'text'}
    if name=='http_request':return (('request','text'),),(),{'request'}
    if name=='stage_request':return (('request','text'),),(),{'request','envelope'}
    if name=='source':return (('text',),),((),),_SOURCE_FIELDS
    if name=='original':return (('request','text'),('provenance','source','text'),('writes',0,'value','text')),(('provenance','source'),('writes',0,'value')),_PAYLOAD_FIELDS
    if name=='bundle':return (('proposals',0,'typed_writes',0,'value','text'),),(('proposals',0,'typed_writes',0,'value'),),{'$type',*(field.name for field in fields(DomainBundle) if field.name not in ('product_advance','root_adoption'))}
    raise C09PagedCaptureHold('registered prepared output name required')

def _envelope(metadata):
    from ..authority_service.v2_model_egress_wire import command_envelope_from_wire_v2
    value=deepcopy(metadata['envelope'])
    for version in value['version_guard']['read_versions']:
        version['key']=asdict(AtomKey.from_token(version['key']))
    return command_envelope_from_wire_v2(value)

class PreparedOwnerOutputSemanticReadV3:
    def __init__(self,scope,prepared_digest,cell_name,*,meter):
        self.scope,self.prepared_digest,self.cell_name=scope,prepared_digest,cell_name
        self.source=scope.begin_owner_source_output_v3(prepared_digest,cell_name,meter=meter)
        texts,sources,root=_profile(cell_name)
        self.parser=_OwnerOriginalMetadataFSMV3(source_arena=scope.arena,ensure_ascii=True,
            text_paths=texts,source_paths=sources,root_fields=root)
        self.complete=False;self.quantum_completed=False;self.proof=None;self.stage='metadata';self.index=0;self.version_index=0
        _SOURCES.add(self);scope.arena.add(self)
    def _source_heap_bytes(self):return 8192
    def advance(self,meter):
        self.scope.require_current(meter=meter)
        if self not in _SOURCES or self.complete:raise C09PagedCaptureHold('actual unfinished semantic Source required')
        self.parser._require(self._source_heap_bytes())
        result=copy(self);result.parser=self.parser.copy();result.quantum_completed=False
        _SOURCES.add(result);self.scope.arena.add(result)
        if not self.source.complete:
            result.source=self.source.advance(meter)
            if result.source.last_segment is not None:result.parser.feed(result.source.last_segment[1],lambda event:None)
            return result
        proof=self.source.proof;proof.require_current(meter=meter)
        if proof.kind!='Complete':
            result.proof=proof;result.complete=True;return result
        if self.stage=='metadata':
            finished=result.parser.finish()
            if (finished.sha256,finished.byte_count)!=(proof.expected_sha256,proof.expected_total_bytes):
                raise C09PagedCaptureHold('semantic Source canonical EOF differs from actual bytes')
            result._metadata(proof);result.stage='observed' if self.cell_name=='original' else 'complete'
        elif self.stage=='observed':
            values=result.parser.value['observed_originals']
            if type(values) is not list or len(values)>128:raise C09PagedCaptureHold('Owner observed original bound differs')
            if result.index<len(values):
                value=values[result.index]
                if type(value) is not dict or set(value)!={'kind','original_ref','original_digest','read_versions'}:
                    raise C09PagedCaptureHold('Owner observed original exact shape differs')
                _text(value['kind']);_text(value['original_ref']);_digest(value['original_digest'])
                if type(value['read_versions']) is not list or len(value['read_versions'])>1024:
                    raise C09PagedCaptureHold('Owner observed readset bound differs')
                ns=NamespaceId(**proof.metadata['namespace'])
                if self.version_index<len(value['read_versions']):
                    _version(value['read_versions'][self.version_index],ns);result.version_index+=1
                else:result.index+=1;result.version_index=0
            else:result.stage='complete'
        if result.stage=='complete':result.proof=proof;result.complete=True
        return result
    def require_complete(self,*,meter):
        if self not in _SOURCES or not self.complete or not self.quantum_completed:
            raise C09PagedCaptureHold('actual semantic Source EOF and successful reservation exit required')
        self.proof.require_current(meter=meter)
        return self.proof
    def _metadata(self,proof):
        metadata=proof.metadata;value=self.parser.value;name=self.cell_name
        ns=NamespaceId(**metadata['namespace']);op=metadata['operation_id']
        sid=owner_material_source_id_v1(ns,op);source=source_key(*ns.as_tuple,sid);access=access_key(*ns.as_tuple,sid)
        texts,sources,_=_profile(name)
        for state in self.parser.text_states.values():
            if not state['nonspace']:raise C09PagedCaptureHold('actual Owner text cannot be blank')
        for path in sources:
            raw=self.parser.source_grammars[path]._source_metadata
            if (raw['source_id']!=sid or raw['speaker_id']!=metadata['envelope']['authority']['actor']
                    or raw['recorded_at']!=metadata['original_now_utc'] or raw['source_kind']!='authored'
                    or raw['assertion_status']!='unknown' or raw['occurred_at'] is not None
                    or raw['provenance_root']!='owner-material:'+sid or raw['audiences']!=['owner']
                    or raw['purposes']!=['context','consolidation'] or raw['parent_source_ids']!=[] or raw['independence']!='unknown'
                    or self.parser.source_spans[path]['hash'].hexdigest()!=metadata['expected_outputs']['source']['payload_sha256']):
                raise C09PagedCaptureHold('actual Source author/time/rights/subtree SHA differs')
        if name=='input':
            if type(value['text']) is not _TextSummaryV3:raise C09PagedCaptureHold('Owner input text grammar differs')
            return
        if name=='http_request':
            if set(value['request'])!={'text'}:raise C09PagedCaptureHold('Owner HTTP request schema differs')
            return
        envelope=_envelope(metadata);tagged=_canonical_value(envelope,set())
        if name=='stage_request':
            if (set(value['request'])!={'$type','text'} or value['request']['$type']!=AdmitOwnerMaterialSourceRequestV1.__module__+'.'+AdmitOwnerMaterialSourceRequestV1.__qualname__
                    or value['envelope']!=tagged):
                raise C09PagedCaptureHold('actual typed Owner stage request/envelope differs')
            return
        if name=='source':return
        expected_access={'source_id':sid,'audiences':['owner'],'purposes':['context','consolidation'],'status':'active','recorded_at':metadata['original_now_utc']}
        if name=='original':
            if (value['schema']!='d06.current-admit_owner_material_source_v1.v1' or value['namespace']!=metadata['namespace']
                    or value['identity']!=metadata['envelope']['identity'] or value['authority']!=metadata['envelope']['authority']
                    or value['parent_budget']!=metadata['parent_budget_original_ref'] or value['now_utc']!=metadata['original_now_utc']
                    or canonical_digest(value['owner_guard'])!=metadata['owner_guard_digest']
                    or value['read_versions']!=metadata['frame_snapshot_versions'] or value['policy_refs']!=metadata['policy_refs']
                    or value['query_coverage']!=metadata['query_coverage'] or value['coverage']!='complete'
                    or value['missing_inputs']!=[] or value['continuation_ref'] is not None or set(value['request'])!={'text'}
                    or set(value['provenance'])!={'source_ref','source','source_access'} or value['provenance']['source_ref']!=source.token
                    or value['provenance']['source_access']!=expected_access or len(value['writes'])!=2
                    or value['writes'][0]!={'key':source.token,'value':value['provenance']['source'],'dependencies':[]}
                    or value['writes'][1]!={'key':access.token,'value':expected_access,'dependencies':[source.token]}):
                raise C09PagedCaptureHold('actual Owner original metadata/writes/readset differs')
            validate_access(expected_access)
            vals=(value['request']['text'],value['provenance']['source']['text'],value['writes'][0]['value']['text'])
            if len({(text.scalar_sha256,text.characters) for text in vals})!=1:
                raise C09PagedCaptureHold('Owner original three text witnesses differ')
            if self.parser.source_spans[('request',)]['hash'].hexdigest()!=metadata['expected_outputs']['input']['payload_sha256']:
                raise C09PagedCaptureHold('Owner original exact input subtree SHA differs')
            return
        from ..domains.d06 import D06DomainProvider
        proposal=value['proposals'][0] if len(value['proposals'])==1 else None
        reads=tuple(GraphVersion(AtomKey.from_token(raw['key']),raw['revision']) for raw in metadata['frame_snapshot_versions'])
        dependencies=DependencySet(current_invalidation=tuple(version for version in reads if version.key==source),
            historical_provenance=tuple(version for version in reads if version.key.type_name=='memory.source' and version.revision>0))
        root={'$type':DomainBundle.__module__+'.'+DomainBundle.__qualname__,'envelope':tagged,
            'experience_refs':[],'choice_refs':[],'d02_settlement_refs':[],'d11_cost_settlement_refs':[],
            'idempotency_keys':[op],'persistent_job_refs':[],'outbox_refs':[]}
        if proposal is None or {key:item for key,item in value.items() if key!='proposals'}!=root:
            raise C09PagedCaptureHold('Owner bundle actual Root/sideeffects differs')
        if (set(proposal)!={'$type','domain','proposal_schema','proposal_schema_hash','envelope','typed_writes','dependencies','contribution_keys','required_bundle_parts'}
                or proposal['$type']!=DomainProposal.__module__+'.'+DomainProposal.__qualname__ or proposal['domain']!='d06'
                or proposal['proposal_schema']!='d06.proposal.v1' or proposal['proposal_schema_hash']!=D06DomainProvider().descriptor.request_schema_hash
                or proposal['envelope']!=tagged or proposal['dependencies']!=_canonical_value(dependencies,set())
                or proposal['contribution_keys']!=[] or proposal['required_bundle_parts']!=[] or len(proposal['typed_writes'])!=2):
            raise C09PagedCaptureHold('Owner bundle actual proposal/dependencies differ')
        writes=proposal['typed_writes'];kind=GraphWrite.__module__+'.'+GraphWrite.__qualname__
        if (writes[0]!={'$type':kind,'key':_canonical_value(source,set()),'value':writes[0]['value'],'dependencies':[]}
                or writes[1]!={'$type':kind,'key':_canonical_value(access,set()),'value':expected_access,'dependencies':[_canonical_value(source,set())]}):
            raise C09PagedCaptureHold('Owner bundle actual typed writes/access differ')
