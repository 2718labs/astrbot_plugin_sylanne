"""Same-Borrowed-Work C03 discovery and term search under the original finite prefix."""
from dataclasses import fields, is_dataclass, replace
from hashlib import sha256
from math import ceil
from time import monotonic
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..memory_types import SourceRecord, source_key, access_key, validate_access
from ..memory_retrieval import MemoryQuery, MemoryHit, MemoryBatch
from ..domains.d06 import D06DomainAdapter, RecallIntent, TriggerKind, RetrievalChannel, source_correction_head_key
from ..domains.d06.pipeline import SearchPlan, RetrievalOutcome
from .source_inspection_metadata_read_v3 import InspectionMetadataReadV3
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3, _COLUMNS
from .runtime_canonical_stream_v3 import RuntimeCanonicalStreamV3
_OPERATION = 'select_ingress_recall_seed_v1'
_TASKS = WeakKeyDictionary()
_RESULTS = {}
_CAPS = WeakKeyDictionary()
def _heap(value, seen=None):
    from sys import getsizeof
    if seen is None:seen=set()
    if id(value) in seen:return 0
    seen.add(id(value));size=getsizeof(value)
    if is_dataclass(value):
        return size+sum(_heap(getattr(value,field.name),seen)for field in fields(value))
    if type(value)is dict:
        return size+sum(_heap(key,seen)+_heap(item,seen)for key,item in value.items())
    if type(value)in(tuple,list,set):
        return size+sum(_heap(item,seen)for item in value)
    return size
class _InspectionV3(InspectionMetadataReadV3):
    def __init__(self, task, key):
        self.c03_task=task
        super().__init__(task.reader,key)
    def _fixed_v3(self,meter,table,columns,where,key):
        return self.c03_task.fixed(meter,table,columns,where,key)
class _JSONV3(DispatchOriginalJSONReadV3):
    def __init__(self,task,**arguments):
        self.task=task
        self._registered=False;self._growing=False
        super().__init__(task.reader,**arguments)
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        if self.cell is not None:
            if self.cell.header[0]not in('canonical-json.ascii.v1','canonical-json.utf8.v1'):
                raise AuthorityUnavailable('C03 exact JSON cell codec is not registered')
            self.parser=C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0]=='canonical-json.ascii.v1')
    def _runtime_retained_heap_bytes_v3(self):
        return 65536+self._payload_bytes+_heap((self.scalar,self.fragment))
    def _reserve(self,extra=0):
        if not self._registered:
            self.operation.register_retained_state_v3(self);self._registered=True
        if self._growing:self.operation.finish_retained_state_growth_v3(self)
        self.operation.reserve_retained_state_growth_v3(self,extra);self._growing=True
    def advance(self,meter):
        try:return super().advance(meter)
        finally:
            if self._growing:
                self.operation.finish_retained_state_growth_v3(self);self._growing=False
    def value_v3(self,owner):
        if (self.owner is not owner or self.operation.closed or not self.complete
                or _COLUMNS.get(self)!=(owner,self.table,self.column,self.key,self.sha256,self.byte_count,self._frozen_value)):
            raise AuthorityUnavailable('C03 JSON lacks actual same-Work canonical EOF')
        from .dispatch_current_inventory_v3 import _detach_value_v3
        return _detach_value_v3(self._frozen_value)
    def release_v3(self):
        if self._growing:
            self.operation.finish_retained_state_growth_v3(self);self._growing=False
        _COLUMNS.pop(self,None)
        self.nodes={};self.scalar=bytearray();self.fragment=b''
        self.value=self._frozen_value=self.parser=self.cell=None
        if self._registered:
            self.operation.unregister_retained_state_v3(self);self._registered=False
class _BodyV3(_JSONV3):
    def __init__(self,task,ref,original):
        task.require_body_v3(ref)
        self.ref,self.original=ref,original
        super().__init__(task,table='graph_atoms',column='value',key_columns=('token',),
            key=(ref,),cell_id=original.cell_id)
        if tuple(self.cell.header)!=original.header:
            raise AuthorityUnavailable('C03 Source Body differs from its actual prior inspection')
        import codecs
        self.semantic_decoder=codecs.getincrementaldecoder('utf-8')('strict')if self.cell.header[0]=='canonical-json.utf8.v1'else None
        self.semantic_hash=sha256()if self.semantic_decoder is not None else None
    def advance(self,meter):
        self.task.require_body_v3(self.ref)
        if not self.complete and self.fragment_offset<len(self.fragment)and self.semantic_decoder is not None:
            from .d13_natural_original_sources_v3 import _NaturalOriginalSourceAllReadV3
            end=min(self.fragment_offset+1024,len(self.fragment))
            _NaturalOriginalSourceAllReadV3._semantic_body_fragment_v3(self,self.fragment[self.fragment_offset:end],meter)
        done=super().advance(meter)
        if done:
            from .d13_natural_original_sources_v3 import _NaturalOriginalSourceAllReadV3
            _NaturalOriginalSourceAllReadV3._semantic_body_fragment_v3(self,b'',meter,final=True)
            semantic=self.sha256 if self.semantic_hash is None else self.semantic_hash.hexdigest()
            if self.sha256!=self.original.payload_sha256 or semantic!=self.original.semantic_digest:
                raise AuthorityUnavailable('C03 Source Body canonical/semantic EOF differs')
        return done
class C03SearchSourceTaskV3:
    def __init__(self,state):
        from .foreground_command_source_v3 import _require_state_v3,_bundle_v3
        from .d06_ingress_c03_read_v1 import SelectIngressRecallSeedRequestV1
        _require_state_v3(state);r=state.reader
        if r.operation_kind!=_OPERATION or type(r.request)is not SelectIngressRecallSeedRequestV1:
            raise AuthorityUnavailable('C03 requires its actual closed Borrowed command')
        self.state,self.reader,self.operation=state,r,r.operation
        self.bundle=_bundle_v3(r);self.policy=self.bundle.d06_recall
        self.preparation=state.preparation
        self.need,self.routing=self.preparation.need,self.preparation.routing
        q=r.request
        if (self.need is None or self.routing is None or not self.preparation.complete
                or q.c02_operation_id!=self.need.c02_operation_id or q.source_ref!=self.need.source_ref
                or q.job_ref!=self.need.cycle_job_ref or q.need_digest!=canonical_digest(self.need)
                or q.policy_digest!=self.policy.policy_digest
                or self.routing['stop_reason']!='search_required' or not self.routing['query_terms']
                or not self.routing['triggers']):
            raise AuthorityUnavailable('C03 discovery lacks its actual Need/signed adopted routing')
        self.profile=next(profile for profile in self.policy.profiles if profile.name==self.routing['mode'])
        self.query=MemoryQuery('source',terms=tuple(self.routing['query_terms']))
        self.plans=(SearchPlan('ingress_structural_v1',self.query,0.5),)
        self.began=monotonic()
        self.deadline=min(state.monotonic_deadline,self.began+self.policy.read_timeout_seconds)
        self.identity=(state,r,r.work,r.issued,r.issued.scope,r.request,r.request_digest,
            r.operation,r.selection_digest,r.graph_stamp,r.expected_rights,self.preparation,
            self.need,self.routing,self.bundle,self.policy,self.profile,self.query,self.deadline)
        self.prefix_limit=min(self.profile.max_candidates,self.profile.max_rounds*self.policy.max_candidates_per_channel)
        self.after='';self.census_count=0;self.census_hash=sha256(b'sylanne3.d06.c03-source-census.v3\0')
        self.census_eof=False;self.prefix=[];self.metadata={};self.current=None;self.inspection=self.column=None
        self.current_ref=None;self.headers={};self.current_source=None;self.current_access=None;self.current_body=None
        self.phase='census';self.next_phase=None;self.lookup_ref=None
        self.candidate_index=self.candidate_count=self.node_count=self.page_count=0
        self.processed_after=None;self.stop=None;self.pending=[];self.closure={};self.denied=False
        self.candidates=[];self.candidate_nodes=[];self.body_refs=();self.body_index=0;self.records={};self.eofs={}
        self.match_refs=();self.match_index=self.match_offset=0;self.match_tail='';self.match_found=set()
        self.folded_terms=tuple(term.casefold()for term in self.query.terms)
        self.matched=set()
        self.versions={};self.body_versions={};self.granted={};self.hits=[];self.batches=()
        self.complete=False;self.result=None;self.outcome=self.digest_stream=None
        self.row=None;self._registered=True
        _TASKS[r]=self
        self.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        return 65536+_heap((self.prefix,self.headers,self.current_source,self.current_access,self.current_body,
            tuple((key,tuple(value[0].metadata.items()),value[1],value[2],value[3])for key,value in self.metadata.items()),
            self.pending,self.closure,self.candidates,self.body_refs,self.records,self.eofs,
            self.versions,self.body_versions,self.granted,self.hits,self.outcome,self.row,self.match_tail,self.match_found))
    def actual(self,meter=None):
        from .foreground_command_source_v3 import _require_state_v3
        s=_require_state_v3(self.state);r=self.reader
        if (_TASKS.get(r)is not self or s.reader is not r or self.identity!=(s,r,r.work,r.issued,
                r.issued.scope,r.request,r.request_digest,r.operation,r.selection_digest,r.graph_stamp,
                r.expected_rights,self.preparation,self.need,self.routing,self.bundle,self.policy,self.profile,self.query,self.deadline)
                or not self.complete and monotonic()>=self.deadline):
            raise AuthorityUnavailable('C03 search left its actual Source Work/request/epoch/original deadline')
        if meter is not None:
            r.require_current(meter=meter)
            s.owner_entry.require_for_v3(r)
        return self
    def fixed(self,meter,table,columns,where,key):
        from .c09_paged_sql_v2 import _quote
        db=self.reader.db
        lengths=db.execute('SELECT '+','.join('length(CAST('+_quote(c)+' AS BLOB))'for c in columns)
            +' FROM '+_quote(table)+' WHERE '+where+' LIMIT 1',key).fetchone()
        if lengths is None:
            self.row=None;self.operation.refresh_retained_state_v3(self);return None
        amount=sum(v or 0 for v in lengths);meter.require_available(amount+256)
        if amount*12+4096>meter.budget.reserved_arena_bytes:
            raise AuthorityUnavailable('C03 fixed metadata exceeds its original reserved arena')
        self.operation.reserve_retained_state_growth_v3(self,amount*12+4096)
        try:self.row=meter.read_fixed_row(db,table,columns,where,key);return self.row
        finally:self.operation.finish_retained_state_growth_v3(self)
    def _head(self,meter,key):
        return self.fixed(meter,'graph_atoms',('revision','valid','value_cell_id'),
            'bot=? AND persona=? AND token=?',(*self.reader.namespace.as_tuple,key.token))
    def _start_metadata(self,ref,return_phase):
        self.lookup_ref=ref;self.next_phase=return_phase
        self.inspection=_InspectionV3(self,AtomKey.from_token(ref))
        self.phase='inspection'
    def _advance_metadata(self,meter):
        ns=self.reader.namespace
        if self.phase=='inspection':
            if not self.inspection.advance(meter):return
            original=self.inspection.result.require_v3(self.reader,meter)
            if not original.valid:
                raise AuthorityUnavailable('C03 candidate lost its actual valid Source projection')
            self.current_source=original
            key=access_key(*ns.as_tuple,original.key.owner.subject)
            access=self._head(meter,key)
            correction_key=source_correction_head_key(ns,original.key.owner.subject)
            correction=self._head(meter,correction_key)
            if access is None or access[1]!=1 or access[2]is None:
                raise AuthorityUnavailable('C03 Source current Access metadata is unknown')
            self.headers[self.lookup_ref]=(access,correction)
            self.column=_JSONV3(self,table='graph_atoms',column='value',key_columns=('token',),
                key=(key.token,),cell_id=access[2])
            self.phase='access';return
        if not self.column.advance(meter):return
        self.operation.reserve_retained_state_growth_v3(self,self.column._payload_bytes*2+self.column._detached_container_bytes+65536)
        try:
            access=self.column.value_v3(self.reader);validate_access(access)
            original=self.current_source;ref=self.lookup_ref
            if access['source_id']!=original.key.owner.subject:
                raise AuthorityUnavailable('C03 actual Source/Access identities differ')
            self.metadata[ref]=(original,access,self.headers[ref],self.inspection)
            self.current_access=access
        finally:self.operation.finish_retained_state_growth_v3(self)
        self.column.release_v3();self.column=None
        self.inspection=self.current_source=None
        self.phase=self.next_phase
        self.lookup_ref=None;self.next_phase=None
    def _census(self,meter):
        ns=self.reader.namespace
        row=self.fixed(meter,'graph_atoms',('token','revision','valid','value_cell_id'),
            "bot=? AND persona=? AND type_name='memory.source' AND valid=1 AND token>? ORDER BY token",
            (*ns.as_tuple,self.after))
        if row is None:
            self.census_eof=True;self.phase='prefix';return
        key=AtomKey.from_token(row[0])
        if key!=source_key(*ns.as_tuple,key.owner.subject)or row[1]<1 or row[3]is None:
            raise AuthorityUnavailable('C03 Source query census lacks its actual fixed metadata locator')
        header=self.fixed(meter,'segmented_cells_v1',
            ('codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
             'payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(row[3],))
        if header is None or header[1]!=row[0]:
            raise AuthorityUnavailable('C03 Source census fixed sealed header differs')
        encoded=canonical_serialize((row,header)).encode('ascii');meter.charge_encode(len(encoded))
        self.census_hash.update(encoded);self.census_count+=1
        if len(self.prefix)<self.prefix_limit:self.prefix.append(row[0])
        self.after=row[0]
    def _prefix(self,meter):
        if self.candidate_index>=len(self.prefix):
            if self.census_count==self.candidate_index:
                self.stop='complete'
            elif self.page_count>=self.profile.max_rounds:
                self.stop='round_budget'
            else:self.stop='candidate_budget'
            self._seal_body_cap_v3();return
        ref=self.prefix[self.candidate_index]
        self.candidate_count+=1
        self.page_count=ceil(self.candidate_count/self.policy.max_candidates_per_channel)
        self.pending=[ref];self.closure={};self.denied=False
        self.phase='closure'
    def _closure(self,meter):
        if self.pending:
            ref=self.pending.pop()
            if ref in self.closure:return
            if 2*(len(self.closure)+1)>self.profile.max_nodes-self.node_count:
                self.node_count=self.profile.max_nodes;self.stop='no_progress'if self.processed_after is None else'node_budget'
                self._seal_body_cap_v3();return
            if ref not in self.metadata:
                self.pending.append(ref);self._start_metadata(ref,'closure');return
            original,access,(ahead,correction),inspection=self.metadata[ref]
            if correction is not None:
                raise AuthorityUnavailable('C03 original candidate has an unresolved correction head')
            if not original.valid or access['source_id']!=original.key.owner.subject:
                raise AuthorityUnavailable('C03 candidate/ancestor metadata is unknown')
            purpose=self.reader.purpose;audiences=self.reader.audiences
            denied=(access['status']!='active' or purpose not in original.metadata['purposes']
                or purpose not in access['purposes'] or not set(audiences)<=set(original.metadata['audiences'])
                or not set(audiences)<=set(access['audiences']))
            self.denied=self.denied or denied
            self.closure[ref]=original
            self.pending.extend(source_key(*self.reader.namespace.as_tuple,parent).token
                for parent in original.metadata['parent_source_ids'])
            return
        ref=self.prefix[self.candidate_index]
        active,done=set(),set()
        def visit(token):
            if token in active:raise AuthorityUnavailable('C03 actual Source ancestry is cyclic')
            if token in done:return
            active.add(token)
            for parent in self.closure[token].metadata['parent_source_ids']:
                visit(source_key(*self.reader.namespace.as_tuple,parent).token)
            active.remove(token);done.add(token)
        visit(ref)
        versions=[]
        for token,original in self.closure.items():
            ahead,correction=self.metadata[token][2]
            key=original.key;akey=access_key(*self.reader.namespace.as_tuple,key.owner.subject)
            ckey=source_correction_head_key(self.reader.namespace,key.owner.subject)
            values=(GraphVersion(key,original.revision),GraphVersion(akey,ahead[0]),GraphVersion(ckey,0))
            for version in values:
                previous=self.versions.setdefault(version.key,version.revision)
                if previous!=version.revision:raise AuthorityUnavailable('C03 exact Source versions disagree within its prefix')
            self.versions[original.task.metadata_key]=1
            versions.extend(values)
        self.node_count+=2*len(self.closure)
        self.candidate_nodes.append(2*len(self.closure))
        self.candidates.append((ref,self.denied,tuple(sorted(set(versions),key=lambda row:row.key.token))))
        if not self.denied:
            for token in self.closure:self.granted[token]=self.metadata[token][0]
            for version in versions:self.body_versions[version.key]=version.revision
        self.processed_after=AtomKey.from_token(ref)
        self.candidate_index+=1;self.phase='prefix'
    def _seal_body_cap_v3(self):
        if not self.census_eof:
            raise AuthorityUnavailable('C03 Body cannot precede actual complete metadata discovery')
        owner=self.state.owner_entry.require_for_v3(self.reader)
        if self.reader.purpose not in owner.purposes or not set(self.reader.audiences)<=set(owner.audiences):
            raise AuthorityUnavailable('C03 actual Owner denies its original Source search group')
        self.body_refs=tuple(sorted(self.granted))
        _CAPS[self]=(self.identity,tuple(self.candidates),self.body_refs,
            tuple(sorted(self.body_versions.items(),key=lambda row:row[0].token)),
            self.census_count,self.census_hash.hexdigest())
        self.phase='body'
    def require_body_v3(self,ref):
        self.actual()
        if (_CAPS.get(self)!=(self.identity,tuple(self.candidates),self.body_refs,
                tuple(sorted(self.body_versions.items(),key=lambda row:row[0].token)),
                self.census_count,self.census_hash.hexdigest()) or ref not in self.granted):
            raise AuthorityUnavailable('C03 Source Body escaped its actual prefix/ancestor ALL capability')
        return self.granted[ref]
    def _body(self,meter):
        if self.body_index==len(self.body_refs):
            self.match_refs=tuple(ref for ref,denied,_ in self.candidates if not denied)
            self.phase='match';return
        ref=self.body_refs[self.body_index];original=self.require_body_v3(ref)
        if self.column is None:
            original.require_v3(self.reader,meter)
            self.column=_BodyV3(self,ref,original);return
        if not self.column.advance(meter):return
        self.operation.reserve_retained_state_growth_v3(self,self.column._payload_bytes*2+self.column._detached_container_bytes+65536)
        try:
            raw=self.column.value_v3(self.reader)
            record=SourceRecord.from_dict(raw)
            self.current_body=(raw,record)
        finally:self.operation.finish_retained_state_growth_v3(self)
        metadata={name:tuple(value)if type(value)is list else value for name,value in raw.items()if name!='text'}
        if metadata!=dict(original.metadata):
            raise AuthorityUnavailable('C03 actual full Source EOF differs from prior metadata qualification')
        original.require_v3(self.reader,meter)
        self.eofs[ref]=(original.revision,self.column.sha256,self.column.byte_count)
        if any(candidate[0]==ref and not candidate[1]for candidate in self.candidates):
            self.records[ref]=record
        self.column.release_v3();self.column=None;self.current_body=None
        self.body_index+=1
    def _match(self,meter):
        if self.match_index==len(self.match_refs):
            self.phase='assemble';return
        ref=self.match_refs[self.match_index];text=self.records[ref].text
        if self.match_offset<len(text):
            fragment=text[self.match_offset:self.match_offset+1024].casefold()
            meter.charge_encode(len(fragment)*4)
            joined=self.match_tail+fragment
            for term in self.folded_terms:
                if term in joined:self.match_found.add(term)
            width=max(map(len,self.folded_terms),default=1)-1
            self.match_tail=joined[-width:]if width else''
            self.match_offset+=1024;return
        if set(self.folded_terms)<=self.match_found:self.matched.add(ref)
        self.match_index+=1;self.match_offset=0;self.match_tail='';self.match_found.clear()
    def _assemble(self):
        self.hits=[]
        for ref,denied,versions in self.candidates:
            if denied:continue
            record=self.records[ref]
            if ref in self.matched:
                self.hits.append(MemoryHit(AtomKey.from_token(ref),record,versions,(record.provenance_root,),(record,)))
        complete=self.stop=='complete'
        continuation=None if complete else self.processed_after
        if self.page_count==0:self.page_count=1
        batch=MemoryBatch(tuple(self.hits),self.reader.graph_stamp[1],self.candidate_count,
            self.node_count,self.page_count,complete,continuation)
        batches=[];used_nodes=0
        for page in range(self.page_count):
            start=page*self.policy.max_candidates_per_channel
            end=min(start+self.policy.max_candidates_per_channel,self.candidate_count)
            processed=min(end,len(self.candidates))
            refs={row[0]for row in self.candidates[start:processed]}
            nodes=sum(self.candidate_nodes[start:processed])
            if page==self.page_count-1:nodes=self.node_count-used_nodes
            used_nodes+=nodes
            cursor=AtomKey.from_token(self.candidates[processed-1][0])if processed else None
            final=page==self.page_count-1 and complete
            batches.append(MemoryBatch(tuple(hit for hit in self.hits if hit.key.token in refs),
                self.reader.graph_stamp[1],end-start,nodes,1,final,None if final else cursor))
        self.batches=tuple(batches)
        adapter=D06DomainAdapter(self.reader.namespace)
        qualification=adapter.qualify_recall(RecallIntent(
            'ingress-c03:'+canonical_digest((self.reader.namespace,self.reader.request.c02_operation_id))[:40],
            TriggerKind(self.routing['triggers'][0]),'actual_adopted_ingress_routing'))
        candidate_id='ingress-candidates:'+canonical_digest((self.reader.namespace,
            self.reader.request.c02_operation_id,self.query))[:40]
        candidates=adapter.assemble_candidates(candidate_id,
            (RetrievalChannel(self.plans[0].name,batch,self.plans[0].activation),),
            purpose=self.reader.purpose,max_candidates=self.profile.max_candidates,
            access_epoch=self.reader.expected_rights[0],delete_epoch=self.reader.expected_rights[1])
        refs={hit.record.source_id:hit.key.token for hit in self.hits}
        candidates=replace(candidates,items=tuple(replace(item,content_ref=refs[item.content_ref])for item in candidates.items))
        versions=tuple(GraphVersion(key,revision)for key,revision in sorted(self.versions.items(),key=lambda item:item[0].token))
        self.outcome=RetrievalOutcome('candidate',candidates,versions,self.reader.graph_stamp[1],
            self.batches,qualification,'not_requested')
        matched={hit.key.token for hit in self.hits}
        self.records={ref:record for ref,record in self.records.items()if ref in matched}
        self.digest_stream=RuntimeCanonicalStreamV3(self.outcome,self.operation)
        self.phase='digest'
    def advance(self,meter):
        self.actual(meter)
        if self.complete:return True
        if self.phase in('inspection','access'):self._advance_metadata(meter)
        elif self.phase=='census':self._census(meter)
        elif self.phase=='prefix':self._prefix(meter)
        elif self.phase=='closure':self._closure(meter)
        elif self.phase=='body':self._body(meter)
        elif self.phase=='match':self._match(meter)
        elif self.phase=='assemble':self._assemble()
        elif self.phase=='digest':
            if self.digest_stream.read_fragment(meter)is None:
                self.outcome_digest=self.digest_stream.hash.hexdigest()
                self.digest_stream=None;self.phase='final_heads';self.version_position=0
        elif self.phase=='final_heads':
            values=tuple(sorted(self.versions.items(),key=lambda row:row[0].token))
            if self.version_position<len(values):
                key,revision=values[self.version_position];head=self._head(meter,key)
                if (0 if head is None else head[0])!=revision:
                    raise AuthorityUnavailable('C03 positive/negative search readset changed before completion')
                self.version_position+=1
            else:
                from .d06_ingress_c03_read_v1 import issue_ingress_c03_read_from_source_task_v3
                self.result=issue_ingress_c03_read_from_source_task_v3(self)
                _RESULTS[id(self.result)]=self
                self._merge_frame_metadata_v3();self.complete=True;self.phase='complete'
        else:raise AuthorityUnavailable('C03 has an unregistered finite Source phase')
        self.operation.refresh_retained_state_v3(self)
        return self.complete
    def _merge_frame_metadata_v3(self):
        s=self.state;m=s.metadata
        for ref,original in self.granted.items():
            s.metadata.roots.add(ref)
            s.original_root_purposes.setdefault(ref,set()).add(self.reader.purpose)
            s.expected_source_versions_v3[original.key]=original.revision
            self.reader.source_inspections[ref]=original
        self.positive_versions=tuple(sorted({version for hit in self.hits for version in hit.proof_versions},
            key=lambda row:row.key.token))
    def release_v3(self):
        from .d06_ingress_c03_read_v1 import release_ingress_c03_source_handle_v3
        if self.column is not None:self.column.release_v3();self.column=None
        if self.inspection is not None:self.inspection.release_v3();self.inspection=None
        for original,access,heads,inspection in self.metadata.values():inspection.release_v3()
        if self.result is not None:
            _RESULTS.pop(id(self.result),None);release_ingress_c03_source_handle_v3(self.result)
        _CAPS.pop(self,None);_TASKS.pop(self.reader,None)
        self.metadata.clear();self.headers.clear();self.prefix.clear();self.records.clear()
        self.candidates.clear();self.granted.clear();self.hits.clear();self.versions.clear();self.body_versions.clear()
        self.result=self.outcome=self.digest_stream=self.inspection=None
        if self._registered:self.operation.unregister_retained_state_v3(self);self._registered=False
def begin_foreground_c03_search_source_v3(state):
    if state.reader in _TASKS:raise AuthorityUnavailable('C03 actual search Work is already prepared')
    return C03SearchSourceTaskV3(state)
def require_c03_source_task_material_v3(task):
    if (type(task)is not C03SearchSourceTaskV3 or _TASKS.get(task.reader)is not task
            or task.phase!='final_heads' or not task.census_eof or task.digest_stream is not None):
        raise AuthorityUnavailable('actual complete finite C03 Source/Body EOF producer required')
    task.actual()
    return dict(graph=task.reader.graph,issued=task.reader.issued,scope=task.reader.issued.scope,
        request=task.reader.request,routing=task.routing,routing_digest=canonical_digest(task.routing),
        need=task.need,policy=task.policy,plans=task.plans,outcome=task.outcome,
        outcome_digest=task.outcome_digest,
        closure_versions=tuple(GraphVersion(key,revision)for key,revision in
            sorted(task.versions.items(),key=lambda row:row[0].token)),
        query_epoch=task.reader.graph_stamp[1],access_epoch=task.reader.expected_rights[0],
        delete_epoch=task.reader.expected_rights[1],elapsed_seconds=monotonic()-task.began,
        search_stop_reason=task.stop,search_cursor=None if task.stop=='complete'or task.processed_after is None else task.processed_after.token)
def require_prepared_ingress_c03_search_v3(reader):
    task=_TASKS.get(reader)
    if (task is None or not task.complete or task.result is None or _RESULTS.get(id(task.result))is not task):
        raise AuthorityUnavailable('C03 requires its same-Work prepared finite search')
    task.actual()
    return task.result
def require_c03_positive_versions_v3(handle):
    task=_RESULTS.get(id(handle))
    if task is None or task.result is not handle:raise AuthorityUnavailable('actual C03 search result required')
    task.actual();return task.positive_versions
def verify_actual_c03_search_versions_v3(handle,db,frame):
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    task=_RESULTS.get(id(handle))
    if (task is None or task.result is not handle or db is not task.reader.db or not db.in_transaction
            or frame.envelope.identity.operation_id!=task.reader.operation_id):
        raise AuthorityUnavailable('C03 negative readset requires its actual compiler transaction/frame')
    task.actual()
    guarded={row.key:row.revision for row in frame.envelope.version_guard.read_versions}
    if any(guarded.get(key)!=revision for key,revision in task.versions.items()):
        raise AuthorityUnavailable('C03 actual positive/negative search readset was dropped from Frame CAS')
    with runtime_storage_quantum_v3(db)as meter:
        for key,revision in task.versions.items():
            head=task._head(meter,key)
            if (0 if head is None else head[0])!=revision:
                raise AuthorityUnavailable('C03 Source/access/correction search fact changed before selection')
    return True
def read_prepared_ingress_c03_for_scope_v3(graph,issued,scope,request):
    matches=[task for reader,task in tuple(_TASKS.items())
        if reader.graph is graph and reader.issued is issued and reader.issued.scope is scope and reader.request==request]
    if len(matches)!=1:raise AuthorityUnavailable('C03 selector has no exact same-Work prepared search')
    return require_prepared_ingress_c03_search_v3(matches[0].reader)
def c03_search_versions_for_frame_v3(reader):
    handle=require_prepared_ingress_c03_search_v3(reader)
    return handle.closure_versions
