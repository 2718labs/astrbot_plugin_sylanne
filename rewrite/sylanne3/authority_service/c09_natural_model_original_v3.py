"""Bounded pre-mirror natural originals for the existing C09 facts chain."""
from __future__ import annotations
from dataclasses import asdict,fields,is_dataclass
from contextlib import contextmanager
from hashlib import sha256
import json,sys
from weakref import WeakSet
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_serialize
from ..runtime.c09_paged_sql_v2 import C09CanonicalJSONStreamV2,c09_canonical_json_size_v3,c09_sql_meter_quantum_v2
from .c09_authority_storage_rebase_v2 import (
    _D13NaturalFrozenJSONStreamV3,_D13PaidInnerObjectStreamV3,_D13PaidIdentityOriginalReadV3,_D13TypedInputCommitmentV3,
    _c09_construct_request_envelope_v3,_c09_request_digest_begin_v3,
)

_TOKEN=object()
_PROOFS=WeakSet()
_PREP=('bot','persona','parent_original_id','job_id','original_operation_id','seal_json','frozen_json',
    'read_versions_json','query_epochs_json','graph_epoch','access_epoch','deletion_epoch','state','worker_fence',
    'typed_request_digest','typed_request_wire','terminal_receipt_digest','terminal_output_digest')
_ACQUIRE=('bot','persona','acquire_operation_id','request_digest','attempt_id','anchor_json','graph_revision','graph_epoch','state')
_BUNDLE=('bot','persona','operation_id','digest','activity_id','effect_id','commit_seq','receipt_json')
_EVENT=('bot','persona','session','event_id','digest','reads','epoch_reads','revisions','invalidated','epoch_revision')
_HISTORY=('token','revision','value','valid','dependencies','event_bot','event_persona','event_session','event_id')


class _NaturalQuantumMeterV3:
    def __init__(self,parent,budget):
        if parent.max_bytes!=budget.max_bytes:raise AuthorityUnavailable('natural proof crossed actual reservation')
        self.parent=parent;self.budget=budget
    @property
    def remaining_bytes(self):return self.parent.remaining_bytes
    def charge_read(self,n):self.parent.charge_read(n)
    def charge_encode(self,n):self.parent.charge_encode(n)
    def require_available(self,n):self.parent.require_available(n)


def _heap(value,seen):
    if id(value) in seen:return 0
    seen.add(id(value));total=sys.getsizeof(value)
    if type(value) is dict:total+=sum(_heap(k,seen)+_heap(v,seen) for k,v in value.items())
    elif type(value) in (tuple,list,set):total+=sum(_heap(v,seen) for v in value)
    elif is_dataclass(value) and not isinstance(value,type):total+=sum(_heap(getattr(value,f.name),seen) for f in fields(value))
    elif isinstance(value,C09CanonicalJSONStreamV2):
        total+=sum(_heap(getattr(value,n),seen) for n in C09CanonicalJSONStreamV2.__slots__ if n!='_emit_callback')
        if type(value) is not C09CanonicalJSONStreamV2:
            total+=sum(_heap(v,seen) for k,v in value.__dict__.items() if k not in {'_source_arena','_emit_callback'})
    elif type(value) is _D13TypedInputCommitmentV3:
        total+=_heap(value.__dict__,seen)
    return total


class NaturalModelFrozenProofV3:
    __slots__=('_reader','_producer','_connections','_budget','_mode','_verification','_used','__weakref__')
    def __init__(self,token,reader,core,graph,meter,budget):
        if token is not _TOKEN or not reader.complete:raise AuthorityUnavailable('complete natural proof factory required')
        p=reader.producer
        if p._natural_model_active_v3 is not reader or p._natural_model_connections_v3!=(core,graph,meter):
            raise AuthorityUnavailable('natural proof needs actual producer current connections')
        reader.require_current()
        self._reader=reader;self._producer=p;self._connections=(core,graph,meter);self._budget=budget
        self._mode=p._readback_only;self._verification=p._verification_id;self._used=False;_PROOFS.add(self)
    def require_for(self,*,core,business,seal,namespace_id,intent,job,installation,terminal):
        p=self._producer;r=self._reader
        if (self not in _PROOFS or self._used or p._natural_model_active_v3 is not r
                or p._natural_model_connections_v3!=self._connections or self._connections[:2]!=(core,business)
                or not core.in_transaction or not business.in_transaction
                or p._natural_model_reservation_v3 is not self._budget or p._readback_only!=self._mode
                or p._verification_id!=self._verification or p.source is not seal or p.maintenance.namespace_id!=namespace_id):
            raise AuthorityUnavailable('natural proof outside actual connection/source/reservation interval')
        r.require_current();saved=r.seal;prep=r.preparation
        if ((intent.call_id,intent.job_id,intent.acquire_operation_id,intent.request_digest,intent.worker_fence,
                intent.budget_lease_id,intent.budget_reservation_operation_id,intent.binding_digest)!=
                (saved.call_id,saved.job_id,saved.acquire_operation_id,prep['typed_request_digest'],prep['worker_fence'],
                saved.parent_budget_lease_id,saved.reservation_operation_id,r.binding_digest)
                or installation!=saved.installation_id or job.work_kind!='natural_'+r.stage
                or job.operation_id!=saved.original_operation_id or job.resource_ref!=r.envelope.authority.provider_policy_ref
                or (intent.provider_id,intent.model_id,intent.provider_config_digest,intent.max_output_tokens)!=
                    (r.installation.provider_id,r.installation.model_id,r.installation.provider_config_digest,r.installation.max_output_tokens)
                or intent.namespace!=seal.namespace or intent.authority_id!=seal.authority_id
                or intent.source_refs!=r.envelope.input_refs or (intent.access_epoch,intent.delete_epoch)!=(
                    prep['access_epoch'],prep['deletion_epoch'])
                or intent.graph_epoch<r.event['epoch_revision'] or intent.graph_revision<r.acquire['graph_revision']):
            raise AuthorityUnavailable('natural Graph proof differs from actual Core/job/provider/budget identity')
        from ..runtime.d11_types import job_value
        values=(job.continuation,job.operator_versions,job.usage)
        amount=sum(c09_canonical_json_size_v3(value,exact=True) for value in values)
        self._connections[2].require_available(amount*2)
        previous_budget=r._budget;r._budget=self._budget
        try:
            r._request_arena(amount*32+65536);current=job_value(job);self._connections[2].charge_encode(amount)
        finally:r._budget=previous_budget
        sticky=('bot_id','persona_id','activity_id','operation_id','effect_id','job_id','snapshot_ref','work_kind',
            'continuation_digest','deadline_utc','parent_budget_lease_ref','resource_ref','operator_versions_digest')
        if any(getattr(current,name)!=getattr(r.running,name) for name in sticky):
            raise AuthorityUnavailable('actual current natural job changed original immutable fields')
        if prep['state']=='terminal':
            if terminal is None or r._terminal_plain_digest(terminal,self._connections[2])!=prep['terminal_receipt_digest']:
                raise AuthorityUnavailable('natural original terminal differs from actual Core receipt')
            if job.phase!='completed' or job.result_ref!=saved.call_id or job.cancel_epoch!=0:
                raise AuthorityUnavailable('terminal natural original lost completed job identity')
        self._used=True;return tuple(sorted(set(r.commitments)))


class NaturalModelGraphOriginalReaderV3:
    """Cold recovery replays only the unfinished call, never trusts saved hash offsets."""
    def __init__(self,producer,call_id,job_id,stage):
        from .c09_paged_recovery_facts_v2 import C09PagedRecoveryFactsProducerV2
        if type(producer) is not C09PagedRecoveryFactsProducerV2 or stage not in {'generation','review'}:
            raise AuthorityUnavailable('actual natural facts producer required')
        self.producer=producer;self.scope=producer.scope;self.source=producer.source;self.source_original=producer.pair.source_original
        self.mode=producer._readback_only;self.verification=producer._verification_id
        self.call_id=call_id;self.job_id=job_id;self.stage=stage;self.phase='locate';self.complete=False
        self.preparation=None;self.seal=None;self.installation=None;self.envelope=None;self.binding_digest=None
        self.frozen=None;self.inner_parser=None;self.inner_values={};self.total=None;self.offset=0
        self.buffer=bytearray();self.field_index=0;self.field_offset=0;self.wire_sha=None
        self.input_actions=();self.input_action_index=0;self.input_hash=sha256();self.input_bytes=0
        self.input_pending=bytearray();self.input_pending_base=0;self.input_pending_offset=0
        self.input_encoded_offset=0;self.input_decoded_offset=0;self.input_range_offset=0;self.input_text_complete=0
        self.input_replay_hash=sha256();self.input_expected_ranges=0;self.projection_tags={}
        self.projection_tags_consumed=0;self.projection_replacements=();self.projection_replacements_consumed=0
        self.rows=[];self.row_index=0;self.row_column=0;self.row_small=None;self.row_hash=None
        self.row_parser=None;self.row_json={};self.commitments=[]
        self.acquire=None;self.event=None;self.receipt=None;self.queued=None;self.running=None
        self.acquire_core=None;self.acquire_permit=None;self.acquire_core_total=None;self.acquire_core_offset=0
        self.plan_ref=None;self.plan_fields={};self.plan_pending=bytearray();self.plan_scalar=None
        self.original_guard=None;self.guard_reads={};self.guard_queries={};self.guard_index=0;self.guard_item=0
        self.guard_hash=sha256();self.guard_pairs=();self.query_pairs=();self.guard_open=False
        self.arena=WeakSet();self.arena.add(self);self._budget=None;self._graph=None
    _input_projection_emit=_D13PaidIdentityOriginalReadV3._input_projection_emit
    _input_projection_advance=_D13PaidIdentityOriginalReadV3._input_projection_advance
    @property
    def request_envelope(self):return self.envelope
    def require_current(self):
        p=self.producer;p.session.require_current();p.pair.require_current()
        if (p.scope is not self.scope or p.source is not self.source or p.pair.source_original!=self.source_original
                or p._readback_only!=self.mode or p._verification_id!=self.verification):
            raise AuthorityUnavailable('natural proof lost actual frozen source/readback mode')
    def _source_heap_bytes(self):
        seen=set()
        return sys.getsizeof(self.__dict__)+sum(_heap(v,seen) for k,v in self.__dict__.items()
            if k not in {'producer','scope','source','source_original','arena','_budget','_graph'})+4096
    def _request_arena(self,extra):
        if self._budget is None or sum(v._source_heap_bytes() for v in self.arena)+extra>self._budget.reserved_arena_bytes:
            raise AuthorityUnavailable('natural model original exceeds actual reserved arena')
    def _read(self,start,amount,meter):
        self._request_arena(amount*32+32768)
        raw,total,kind=self._graph.read_incremental_cell_v2(self.table,'typed_request_wire',self.where,self.key,start,amount)
        if kind!='text' or total!=self.total or len(raw)!=amount:raise AuthorityUnavailable('natural typed request source changed')
        return raw
    def _input_projection_read(self,meter):
        if self.input_pending_offset!=len(self.input_pending):raise AuthorityUnavailable('consume actual request fragment first')
        amount=min(1024,self.total-self.input_encoded_offset)
        if amount<=0:raise AuthorityUnavailable('natural request ended before projected range')
        raw=self._read(self.input_encoded_offset,amount,meter);meter.charge_encode(len(raw))
        self.input_replay_hash.update(raw);self.input_pending=bytearray(raw)
        self.input_pending_base=self.input_encoded_offset;self.input_pending_offset=0
        self.input_encoded_offset+=amount;self.input_decoded_offset=self.input_encoded_offset
    def _encoded(self,value,meter):
        amount=c09_canonical_json_size_v3(value,typed=True,exact=True);meter.require_available(amount*2);self._request_arena(amount*16+16384)
        text=canonical_serialize(value);raw=text.encode('ascii');meter.charge_encode(len(raw));return raw
    def _digest(self,value,meter):return sha256(self._encoded(value,meter)).hexdigest()
    def _terminal_plain_digest(self,value,meter):
        previous_budget=self._budget;self._budget=self.producer._natural_model_reservation_v3
        try:return self._digest(asdict(value),meter)
        finally:self._budget=previous_budget
    @staticmethod
    def _point(db,statement,args):
        row=db.execute(statement,args).fetchone()
        if row is None:raise AuthorityUnavailable('actual natural point original absent')
        return row
    def _cell(self,db,column,start,amount):
        raw,total,kind=db.read_incremental_cell_v2(self.table,column,self.where,self.key,start,amount)
        if kind!='text' or len(raw)!=amount:raise AuthorityUnavailable('natural canonical column changed')
        return raw,total
    def _seal_identity(self,raw,meter):
        from ..runtime.natural_reply_job_v2 import _seal,natural_job_ids_v2
        saved=_seal(self.stage,raw);namespace=self.producer.maintenance.namespace_id
        if set(raw)!={f.name for f in fields(saved)}:raise AuthorityUnavailable('natural seal exact fields differ')
        material={'schema':'sylanne.natural-original-identity.v2','namespace':namespace.as_tuple,
            'parent':self.preparation['parent_original_id'],'stage':self.stage}
        amount=c09_canonical_json_size_v3(material,exact=True);meter.require_available(amount*2)
        ids=natural_job_ids_v2(namespace,self.preparation['parent_original_id'],self.stage);meter.charge_encode(amount)
        if ((saved.job_id,saved.original_operation_id,saved.acquire_operation_id,saved.call_id,saved.reservation_operation_id)!=ids
                or saved.namespace!=namespace or saved.call_id!=self.call_id or saved.job_id!=self.job_id
                or saved.installation_id!=self.scope.installation_id
                or saved.original_operation_id!=self.preparation['original_operation_id']
                or self.preparation['state'] not in {'acquired','terminal'}
                or any(type(self.preparation[n]) is not int or self.preparation[n]<0
                    for n in ('graph_epoch','access_epoch','deletion_epoch'))
                or type(self.preparation['worker_fence']) is not int or self.preparation['worker_fence']<1):
            raise AuthorityUnavailable('natural seal differs from actual installation/preparation identity')
        if self.stage=='generation' and saved.c02_operation_id!=self.preparation['parent_original_id']:
            raise AuthorityUnavailable('generation seal crossed its actual C02 parent')
        self.seal=saved;self.version=int(saved.schema.rsplit('v',1)[1])
        self.frozen=_D13NaturalFrozenJSONStreamV3(self.stage,self.version,self.arena,ensure_ascii=True);self.phase='frozen_length'
    def _frozen_event(self,event):
        path=event.path
        if len(path)!=4 or path[:3]!=('input','plan','plan_ref'):return
        if path[3] not in {'ref','version'}:raise AuthorityUnavailable('actual frozen plan reference fields differ')
        if event.kind=='scalar_start':
            self.plan_scalar=path[3];self.plan_pending.clear()
        elif event.kind=='scalar_chunk':
            self._request_arena(len(event.raw)*8+16384);self.plan_pending.extend(event.raw)
        elif event.kind=='scalar_end':
            self._request_arena(len(self.plan_pending)*32+16384)
            self.plan_fields[path[3]]=json.loads(self.plan_pending);self.plan_pending.clear();self.plan_scalar=None
            if set(self.plan_fields)=={'ref','version'}:
                from ..runtime_contracts import VersionedRef
                value=VersionedRef(**self.plan_fields)
                if value.version!=1:raise AuthorityUnavailable('actual frozen adopted plan must be revision1')
                self.plan_ref=value.ref
    def _guard_advance(self,meter):
        from ..graph_types import AtomKey,GraphVersion
        from ..runtime_contracts import NamespaceId,QueryEpoch
        reads,queries=self.original_guard
        if self.phase=='guard_reads':
            if type(reads) is not list or not reads:raise AuthorityUnavailable('actual original read guard must be nonempty')
            if self.guard_index==len(reads):self.guard_index=0;self.phase='guard_queries';return
            raw=reads[self.guard_index]
            if type(raw) is not dict or set(raw)!={'key','revision'} or type(raw['key']) is not str:
                raise AuthorityUnavailable('actual original read guard exact fields differ')
            token=raw['key'];meter.require_available(len(token));self._request_arena(len(token)*32+16384)
            key=AtomKey.from_token(token);meter.charge_encode(len(token));value=GraphVersion(key,raw['revision'])
            if (key.owner.bot,key.owner.persona)!=self.seal.namespace.as_tuple or raw['key'] in self.guard_reads:
                raise AuthorityUnavailable('actual original read guard duplicates/crosses namespace')
            self.guard_reads[raw['key']]=value.revision;self.guard_index+=1
        elif self.phase=='guard_queries':
            if type(queries) is not list or not queries:raise AuthorityUnavailable('actual original query guard must be nonempty')
            if self.guard_index==len(queries):
                self.guard_pairs=tuple(sorted(self.guard_reads.items()));self.query_pairs=tuple(sorted(self.guard_queries.items()))
                self.guard_index=0;self.guard_item=0;self.phase='guard_hash';self.guard_hash.update(b'{');meter.charge_encode(1);return
            raw=queries[self.guard_index]
            if (type(raw) is not dict or set(raw)!={'namespace','scope_ref','revision'} or type(raw['namespace']) is not dict
                    or set(raw['namespace'])!={'bot_id','persona_id'}):
                raise AuthorityUnavailable('actual original query guard exact fields differ')
            value=QueryEpoch(NamespaceId(**raw['namespace']),raw['scope_ref'],raw['revision'])
            if value.namespace!=self.seal.namespace or value.scope_ref in self.guard_queries:
                raise AuthorityUnavailable('actual original query guard duplicates/crosses namespace')
            self.guard_queries[value.scope_ref]=value.revision;self.guard_index+=1
        else:
            names=('access_epoch','deletion_epoch','graph_epoch','namespace','query_epochs','read_versions','schema')
            if self.guard_index==len(names):
                self.guard_hash.update(b'}');meter.charge_encode(1)
                if self.guard_hash.hexdigest()!=self.seal.original_graph_guard_digest:
                    raise AuthorityUnavailable('actual original read/query guard digest differs from seal')
                self.phase='acquire_core';return
            name=names[self.guard_index]
            if not self.guard_open:
                raw=(b',' if self.guard_index else b'')+self._encoded(name,meter)+b':'
                meter.charge_encode(len(raw));self.guard_hash.update(raw);self.guard_open=True
                if name in {'query_epochs','read_versions'}:self.guard_hash.update(b'[');meter.charge_encode(1)
            elif name in {'query_epochs','read_versions'}:
                pairs=self.query_pairs if name=='query_epochs' else self.guard_pairs
                if self.guard_item==len(pairs):
                    self.guard_hash.update(b']');meter.charge_encode(1)
                    self.guard_item=0;self.guard_index+=1;self.guard_open=False
                else:
                    if self.guard_item:self.guard_hash.update(b',');meter.charge_encode(1)
                    self.guard_hash.update(self._encoded(pairs[self.guard_item],meter));self.guard_item+=1
            else:
                value=self.seal.namespace if name=='namespace' else 'sylanne.natural-current-guard.v2' if name=='schema' else self.preparation[name]
                self.guard_hash.update(self._encoded(value,meter));self.guard_index+=1;self.guard_open=False
    def _frozen_identity(self):
        v=self.frozen.metadata;s=self.seal;i=v['installation']
        if (i.installation_id!=s.installation_id or i.provider_config_digest!=s.provider_config_digest
                or v['qualified_units_digest']!=s.qualified_units_digest):
            raise AuthorityUnavailable('natural frozen installation/basis differs')
        if self.stage=='generation':
            if v['frozen_input_digest']!=s.frozen_input_digest or v['model_request_digest']!=s.model_request_digest:
                raise AuthorityUnavailable('actual frozen generation differs from seal')
        elif (v['generation_frozen_input_digest']!=s.generation_frozen_input_digest
                or v['generation_output_digest']!=s.generation_output_digest or v['digest']!=s.review_frozen_input_digest
                or v['wire_digest']!=s.model_request_digest or v['review_policy_version']!=s.review_policy_version):
            raise AuthorityUnavailable('actual review differs from original generation/output/policy')
        self.installation=i
    def _request_identity(self,meter):
        from ..model_broker.broker import _text
        from ..model_broker.natural_reply import TEMPLATE_DIGEST as V2
        from ..model_broker.natural_reply_history_v3 import TEMPLATE_DIGEST as V3
        from ..model_broker.natural_reply_history_v4 import TEMPLATE_DIGEST as V4,TEMPLATE_DIGEST_V5 as V5
        from ..model_broker.natural_reply_history_v6 import TEMPLATE_DIGEST as V6
        from ..model_broker.natural_reply_history_v7 import TEMPLATE_DIGEST as V7
        from ..model_broker.natural_review import REVIEW_TEMPLATE_DIGEST,REVIEW_TEMPLATE_DIGEST_V2
        v=self.inner_values;e=_c09_construct_request_envelope_v3(self,meter,self._request_arena)
        for n in ('call_id','provider_id','model_id','privacy_tier'):_text(v[n],n)
        template={2:V2,3:V3,4:V4,5:V5,6:V6,7:V7}[self.version] if self.stage=='generation' else (
            REVIEW_TEMPLATE_DIGEST_V2 if self.version>=5 else REVIEW_TEMPLATE_DIGEST)
        caps=v['required_capabilities'];timeout=v['timeout_seconds'];maximum=v['max_output_tokens']
        if (type(caps) is not list or any(type(x) is not str or not x for x in caps) or caps!=sorted(set(caps))
                or type(timeout) not in (int,float) or not 0<timeout<=300 or type(maximum) is not int
                or (v['call_id'],v['provider_id'],v['model_id'],maximum)!=(
                    self.seal.call_id,self.installation.provider_id,self.installation.model_id,self.installation.max_output_tokens)
                or v['prompt_template_digest']!=template or e.identity.phase!='natural_'+self.stage
                or e.identity.operation_id!=self.seal.acquire_operation_id
                or e.authority.namespace!=self.producer.maintenance.namespace_id or e.authority.issuer_domain!='d11'
                or e.authority.worker_fence!=self.preparation['worker_fence'] or e.parent_budget_lease_ref!=self.seal.parent_budget_lease_id
                or (e.version_guard.access_epoch,e.version_guard.delete_epoch)!=(
                    self.preparation['access_epoch'],self.preparation['deletion_epoch'])):
            raise AuthorityUnavailable('actual natural request differs from original worker/provider/budget')
        self.envelope=e;_c09_request_digest_begin_v3(self,meter,self._request_arena)
    def _begin_rows(self,meter):
        from ..runtime.d11_types import runtime_job_key
        ns=self.producer.maintenance.namespace_id.as_tuple;a=self.envelope.identity.activity_id
        amount=c09_canonical_json_size_v3(['activity',*ns,a,'runtime.job',self.job_id],exact=True)
        meter.require_available(amount);self._request_arena(amount*16+32768)
        self.job_ref=runtime_job_key(*ns,a,self.job_id).token;meter.charge_encode(len(self.job_ref))
        op=self.seal.acquire_operation_id;self.rows=[
            ('preparation',self.table,_PREP,self.where,self.key,
                {'seal_json','frozen_json','read_versions_json','query_epochs_json','typed_request_wire'},{'read_versions_json','query_epochs_json'}),
            ('acquire','graph_natural_'+self.stage+'_acquires_v2',_ACQUIRE,'bot=? AND persona=? AND acquire_operation_id=?',(*ns,op),{'anchor_json'},{'anchor_json'}),
            ('bundle','graph_bundle_operations',_BUNDLE,'bot=? AND persona=? AND operation_id=?',(*ns,op),{'receipt_json'},{'receipt_json'}),
            ('event','graph_events',_EVENT,'bot=? AND persona=? AND session=? AND event_id=?',(*ns,a,op),{'reads','epoch_reads','revisions','invalidated'},{'reads','epoch_reads','revisions'}),
            ('queued','graph_history',_HISTORY,'token=? AND revision=?',(self.job_ref,1),{'value','dependencies'},{'value','dependencies'}),
            ('running','graph_history',_HISTORY,'token=? AND revision=?',(self.job_ref,2),{'value','dependencies'},{'value','dependencies'})]
        if self.stage=='review':self.rows.append(('generation','graph_natural_generation_preparations_v2',_PREP,
            'bot=? AND persona=? AND parent_original_id=?',(*ns,self.preparation['parent_original_id']),
            {'seal_json','frozen_json','read_versions_json','query_epochs_json','typed_request_wire'},{'seal_json'}))
        self.phase='row_start';self.frozen=None;self.inner_parser=None;self.inner_values={};self.input_pending.clear()
    def _row_advance(self,graph,meter):
        kind,table,columns,where,key,large,decode=self.rows[self.row_index]
        if self.phase=='row_start':
            schema=graph.execute('PRAGMA table_info('+table+')').fetchall()
            if tuple(v[1] for v in schema)!=columns:raise AuthorityUnavailable('natural row changed registered schema')
            names=tuple(n for n in columns if n not in large)
            row=self._point(graph,'SELECT '+','.join(names)+' FROM '+table+' WHERE '+where,key)
            self.row_small=dict(zip(names,row,strict=True));self.row_json={};self.row_column=0;self.offset=0;self.total=None
            self.row_hash=sha256();header=canonical_serialize((table,columns));prefix=header[:-1]+',['
            meter.require_available(len(prefix)*3);meter.charge_encode(len(header)-1+len(prefix)*2)
            self.row_hash.update(prefix.encode('ascii'));self.phase='row_columns';return
        if self.row_column==len(columns):
            meter.require_available(2);meter.charge_encode(2);self.row_hash.update(b']]')
            self.commitments.append(self.row_hash.hexdigest());self._row_identity(kind,meter)
            self.row_index+=1;self.phase='guard_reads' if self.row_index==len(self.rows) else 'row_start';return
        name=columns[self.row_column]
        if self.total is None:
            if self.row_column:meter.charge_encode(1);self.row_hash.update(b',')
            if name not in large:self.row_hash.update(self._encoded(self.row_small[name],meter));self.row_column+=1;return
            raw,total,storage=graph.read_incremental_cell_v2(table,name,where,key,0,0)
            if storage!='text' or total<=0:raise AuthorityUnavailable('natural row canonical cell absent')
            self.total=total;self.offset=0;self.row_parser=(_D13NaturalFrozenJSONStreamV3('generation',self.version,self.arena,ensure_ascii=True)
                if kind=='generation' and name=='frozen_json' else C09CanonicalJSONStreamV2(ensure_ascii=True))
            meter.charge_encode(1);self.row_hash.update(b'"');self.buffer.clear();return
        if self.offset==self.total:
            eof=self.row_parser.finish()
            if eof.byte_count!=self.total:raise AuthorityUnavailable('natural row canonical EOF differs')
            if kind=='generation' and name=='frozen_json':
                from ..runtime.natural_reply_job_v2 import _seal
                saved=_seal('generation',self.row_json['seal_json']);meta=self.row_parser.metadata
                installation=meta['installation']
                if (meta['frozen_input_digest']!=saved.frozen_input_digest or meta['model_request_digest']!=saved.model_request_digest
                        or meta['qualified_units_digest']!=saved.qualified_units_digest
                        or installation.installation_id!=saved.installation_id
                        or installation.provider_config_digest!=saved.provider_config_digest
                        or saved.c02_operation_id!=self.preparation['parent_original_id']):
                    raise AuthorityUnavailable('review generation frozen original differs from actual generation seal')
            if name in decode:self._request_arena(len(self.buffer)*32+65536);self.row_json[name]=json.loads(self.buffer)
            self.buffer.clear();meter.charge_encode(1);self.row_hash.update(b'"')
            self.row_parser=None;self.total=None;self.offset=0;self.row_column+=1;return
        amount=min(1024,self.total-self.offset);self._request_arena(amount*32+32768)
        raw,total,storage=graph.read_incremental_cell_v2(table,name,where,key,self.offset,amount)
        if storage!='text' or total!=self.total or len(raw)!=amount or any(v>=128 for v in raw):
            raise AuthorityUnavailable('natural complete physical row JSON changed')
        meter.require_available(amount*8+32);text=canonical_serialize(raw.decode('ascii'));escaped=text[1:-1]
        encoded=escaped.encode('ascii');meter.charge_encode(len(escaped)+len(encoded));self.row_hash.update(encoded)
        self.row_parser.feed(raw,self._frozen_event if kind=='generation' and name=='frozen_json' else lambda event:None);self.row_parser._emit_callback=None
        if name in decode:self._request_arena((len(self.buffer)+amount)*2+32768);self.buffer.extend(raw);meter.charge_encode(len(raw))
        self.offset+=amount
    def _row_identity(self,kind,meter):
        from ..runtime.d11_types import RuntimeJobValue,_strict_payload
        from ..runtime.natural_reply_job_v2 import _seal
        raw=self.row_small;v=self.row_json
        if kind=='preparation':
            if raw!=self.preparation:raise AuthorityUnavailable('complete natural preparation changed')
            self.original_guard=(v['read_versions_json'],v['query_epochs_json'])
        elif kind=='acquire':
            from ..runtime.restore_anchor import RestoreAnchor
            anchor=RestoreAnchor(**v['anchor_json'])
            if (raw['state']!='committed' or raw['attempt_id']!=self.envelope.identity.attempt_id
                    or (anchor.authority_id,anchor.namespace,anchor.activation_generation)!=(
                        self.scope.authority_id,self.scope.authority_namespace,self.envelope.authority.activation_generation)):
                raise AuthorityUnavailable('natural acquire original/anchor differs')
            self.acquire=raw;self.acquire_anchor=anchor
        elif kind=='bundle':self.receipt=v['receipt_json'];self.bundle=raw
        elif kind=='event':self.event=raw;self.event_values=v
        elif kind in {'queued','running'}:
            value=_strict_payload(v['value'],RuntimeJobValue)
            if (value.job_id!=self.job_id or value.operation_id!=self.seal.original_operation_id or value.cancel_epoch!=0
                    or value.result_ref is not None or value.wake_condition_digest is not None
                    or value.parent_budget_lease_ref!=self.seal.parent_budget_lease_id
                    or value.resource_ref!=self.envelope.authority.provider_policy_ref
                    or value.work_kind!='natural_'+self.stage or raw['valid']!=1):
                raise AuthorityUnavailable('natural historical job has another identity/state')
            if kind=='queued':self.queued=value;self.queued_metadata=raw;self.queued_dependencies=v['dependencies']
            else:self.running=value;self.running_metadata=raw;self.running_dependencies=v['dependencies']
        elif kind=='generation':
            saved=_seal('generation',v['seal_json'])
            if (saved.namespace!=self.seal.namespace or saved.schema!=self.seal.schema.replace('review','generation')
                    or raw['state']!='terminal' or raw['terminal_output_digest']!=self.seal.generation_output_digest
                    or saved.original_operation_id!=self.seal.generation_original_operation_id or saved.call_id!=self.seal.generation_call_id
                    or saved.frozen_input_digest!=self.seal.generation_frozen_input_digest
                    or saved.qualified_units_digest!=self.seal.qualified_units_digest or saved.parent_budget_lease_id!=self.seal.parent_budget_lease_id):
                raise AuthorityUnavailable('review lost original same-version generation/output/budget')
    def _acquire_core_advance(self,core,meter):
        from .v2_contract import decode_bytes,canonical_bytes,FencePermitV2
        columns=('operation_id','namespace','subject','token','fence_epoch','revision','state','permit',
            'finish_request_id','finish_request_digest','pending')
        attempt=self.acquire['attempt_id']
        if self.acquire_core is None:
            shape=core.execute('PRAGMA table_info(authority_v2_fences)').fetchall()
            keys=tuple(row[1] for row in sorted(shape,key=lambda row:row[5]) if row[5]>0)
            if (tuple(row[1] for row in shape)!=columns or keys!=('operation_id',)
                    or next(row[2].upper() for row in shape if row[1]=='operation_id')!='TEXT'):
                raise AuthorityUnavailable('natural acquire Core fence changed registered full-row schema/key')
            names=tuple(n for n in columns if n!='permit')
            row=self._point(core,'SELECT '+','.join(names)+' FROM authority_v2_fences WHERE operation_id=?',(attempt,))
            self.acquire_core=dict(zip(names,row,strict=True));v=self.acquire_core
            if (v['state']!='finished' or v['pending'] is not None or v['namespace']!=self.scope.authority_namespace
                    or v['subject']!=self.producer.maintenance.subject or v['finish_request_id']!='finish:'+attempt):
                raise AuthorityUnavailable('natural original acquire Core fence identity/state differs')
            return
        if self.acquire_core_total is None:
            _,total,kind=core.read_incremental_cell_v2('authority_v2_fences','permit','operation_id=?',(attempt,),0,0)
            if kind!='blob' or total<=0:raise AuthorityUnavailable('natural original acquire Core permit absent')
            self._request_arena(total*2+16384);self.acquire_core_total=total;self.buffer.clear();return
        total=self.acquire_core_total
        if self.acquire_core_offset<total:
            amount=min(8192,total-self.acquire_core_offset);self._request_arena(amount*8+16384)
            raw,size,kind=core.read_incremental_cell_v2('authority_v2_fences','permit','operation_id=?',(attempt,),self.acquire_core_offset,amount)
            if kind!='blob' or size!=total or len(raw)!=amount:raise AuthorityUnavailable('natural acquire Core permit changed')
            self.buffer.extend(raw);self.acquire_core_offset+=amount;return
        self._request_arena(total*32+65536);meter.require_available(total*3)
        encoded=bytes(self.buffer);meter.charge_encode(len(encoded));permit=decode_bytes(encoded)
        if type(permit) is not FencePermitV2:raise AuthorityUnavailable('natural original acquire has nonformal permit')
        original=canonical_bytes(permit);meter.charge_encode(len(original)*2)
        if (encoded!=original or permit.operation!='write' or permit.operation_id!=attempt
                or permit.pinned_anchor!=self.acquire_anchor or permit.authority_id!=self.scope.authority_id
                or permit.namespace!=self.scope.authority_namespace or permit.subject!=self.producer.maintenance.subject
                or permit.generation!=self.envelope.authority.activation_generation
                or tuple(self.acquire_core[n] for n in columns[:6])!=(
                    permit.operation_id,permit.namespace,permit.subject,permit.token,permit.fence_epoch,permit.revision)):
            raise AuthorityUnavailable('natural original acquire Core permit/anchor/worker differs')
        finish='sha256:'+self._digest({'action':'finish_reply_acquire','attempt_id':attempt,'permit_token':permit.token},meter)
        if self.acquire_core['finish_request_digest']!=finish:raise AuthorityUnavailable('natural acquire Core finish digest differs')
        material=tuple({'blob_sha256':sha256(self.buffer).hexdigest(),'size':total} if n=='permit' else self.acquire_core[n] for n in columns)
        self.commitments.append(self._digest(('authority_v2_fences',columns,material),meter))
        self.acquire_permit=permit;self.buffer.clear();self.phase='graph_identity'
    def _graph_identity(self,meter):
        from datetime import datetime,timedelta,timezone
        import math
        from ..runtime.jobs import _utc,_utc_text
        ns=self.seal.namespace;r=self.receipt;j=self.running;q=self.queued;e=self.event_values
        expected={'c02_operation_id','plan_ref','job_ref','call_id','typed_request_digest','ledger_refs','outbox_refs','acquire_utc','lease_seconds','expected_fence'}
        if type(r) is dict and set(r)==expected-{'acquire_utc','lease_seconds','expected_fence'}:
            raise AuthorityUnavailable('legacy natural acquire lacks actual clock/lease preimage; cannot backfill')
        if (type(r) is not dict or set(r)!=expected or r['c02_operation_id']!=self.preparation['parent_original_id']
                or r['job_ref']!=self.job_ref or r['call_id']!=self.call_id or r['typed_request_digest']!=self.preparation['typed_request_digest']
                or self.plan_ref is None or r['plan_ref']!=self.plan_ref
                or r['ledger_refs']!=[self.job_ref] or r['outbox_refs']!=[] or self.bundle['digest']!=self.acquire['request_digest']
                or self.bundle['activity_id']!=j.activity_id or self.bundle['effect_id'] is not None
                or type(self.bundle['commit_seq']) is not int or self.bundle['commit_seq']<1):
            raise AuthorityUnavailable('natural actual acquire bundle differs')
        now=r['acquire_utc'];seconds=r['lease_seconds'];fence=r['expected_fence']
        if (type(now) not in (int,float) or not math.isfinite(now) or now<=0 or type(seconds) is not int or not 1<=seconds<=3600
                or type(fence) is not int or fence!=0 or q.phase!='queued' or q.fence!=0 or q.lease_holder is not None
                or q.lease_expires_utc is not None or j.phase!='running' or j.fence!=1
                or j.fence!=self.envelope.authority.worker_fence or j.lease_holder!=self.envelope.authority.actor):
            raise AuthorityUnavailable('natural queued/acquired original clock/worker/fence differs')
        if (j.lease_expires_utc!=_utc_text(datetime.fromtimestamp(now,timezone.utc)+timedelta(seconds=seconds))
                or now>=_utc(j.deadline_utc,'original deadline').timestamp()
                or self.envelope.deadline_utc!=min(_utc(j.deadline_utc,'original deadline').timestamp(),_utc(j.lease_expires_utc,'original lease').timestamp())):
            raise AuthorityUnavailable('natural request/worker time contract differs')
        sticky=('bot_id','persona_id','activity_id','operation_id','effect_id','job_id','snapshot_ref','work_kind','continuation_digest',
            'deadline_utc','parent_budget_lease_ref','resource_ref','operator_versions_digest','usage_digest')
        if any(getattr(j,n)!=getattr(q,n) for n in sticky):raise AuthorityUnavailable('acquire changed nonlease original job fields')
        a=self.envelope.identity.activity_id
        if (j.activity_id!=a or (j.bot_id,j.persona_id)!=ns.as_tuple or j.usage_digest!=self._digest({},meter)
                or tuple(self.running_metadata[n] for n in ('event_bot','event_persona','event_session','event_id'))!=(*ns.as_tuple,a,self.seal.acquire_operation_id)
                or tuple(self.queued_metadata[n] for n in ('event_bot','event_persona','event_session','event_id'))!=(*ns.as_tuple,a,self.seal.original_operation_id)
                or self.running_dependencies!=[[r['plan_ref'],1]] or self.queued_dependencies!=[[r['plan_ref'],1]]):
            raise AuthorityUnavailable('natural job history lost actual event/plan dependencies')
        token_bytes=sum(c09_canonical_json_size_v3([v.key.owner.kind,v.key.owner.bot,v.key.owner.persona,v.key.owner.subject,
            v.key.type_name,v.key.name],exact=True) for v in self.envelope.version_guard.read_versions)
        self._request_arena(token_bytes+len(self.envelope.version_guard.read_versions)*512+32768);wanted=set()
        for v in self.envelope.version_guard.read_versions:
            amount=c09_canonical_json_size_v3([v.key.owner.kind,v.key.owner.bot,v.key.owner.persona,v.key.owner.subject,v.key.type_name,v.key.name],exact=True)
            meter.require_available(amount);token=v.key.token;meter.charge_encode(len(token))
            if token==self.job_ref and v.revision!=2:raise AuthorityUnavailable('request lost actual running revision2')
            wanted.add((token,1 if token==self.job_ref else v.revision))
        reads=e['reads'];pre=self.acquire['graph_epoch']
        if (type(reads) is not list or any(type(v) is not list or len(v)!=2 or type(v[0]) is not str or type(v[1]) is not int for v in reads)
                or len({v[0] for v in reads})!=len(reads) or {tuple(v) for v in reads}!=wanted
                or (self.job_ref,1) not in wanted or (r['plan_ref'],1) not in wanted
                or e['revisions']!=[[self.job_ref,2]] or e['epoch_reads']!=[[*ns.as_tuple,pre]] or self.event['epoch_revision']!=pre+1
                or tuple(v.scope_ref for v in self.envelope.version_guard.query_epochs)!=('all','d03.role_binding','d05.boundary')
                or any(v.namespace!=ns or v.revision!=pre+1 for v in self.envelope.version_guard.query_epochs)):
            raise AuthorityUnavailable('natural Graph event differs from original request guard')
        digest=self._digest({'schema':'sylanne.natural-'+self.stage+'-acquire.v2','seal':asdict(self.seal),
            'actor':self.envelope.authority.actor,'lease_seconds':seconds,'expected_fence':fence},meter)
        if digest!=self.acquire['request_digest'] or self.event['digest']!=self._digest({
            'scope':{'bot':ns.bot_id,'persona':ns.persona_id,'session':a},'event_id':self.seal.acquire_operation_id,
            'occurred_at':now,'kind':'domain_bundle','payload':{'bundle_digest':digest}},meter):
            raise AuthorityUnavailable('natural acquire/event actual digest preimage differs')
        self.binding_digest=self._digest({'original_seal_digest':self._digest(asdict(self.seal),meter),
            'model_call_request_digest':self.preparation['typed_request_digest'],'worker_fence':self.preparation['worker_fence']},meter)
        self.complete=True;self.phase='complete'
    def advance(self,*,core,graph,meter,budget):
        self.require_current()
        if self.producer._natural_model_connections_v3!=(core,graph,meter):raise AuthorityUnavailable('actual producer connections required')
        self._budget=budget;self._graph=graph
        try:
            with c09_sql_meter_quantum_v2(_NaturalQuantumMeterV3(meter,budget)):
                self._request_arena(0);self._advance(core,graph,meter);self._request_arena(0)
        finally:self._budget=None;self._graph=None
    def _advance(self,core,graph,meter):
        if self.phase=='locate':
            self.table='graph_natural_'+self.stage+'_preparations_v2';self.where='bot=? AND persona=? AND job_id=?'
            self.key=(*self.producer.maintenance.namespace_id.as_tuple,self.job_id)
            names=tuple(n for n in _PREP if n not in {'seal_json','frozen_json','read_versions_json','query_epochs_json','typed_request_wire'})
            matches=graph.execute('SELECT '+','.join(names)+' FROM '+self.table+' WHERE '+self.where+' LIMIT 2',self.key).fetchall()
            if len(matches)!=1:raise AuthorityUnavailable('natural preparation locator absent or ambiguous')
            self.preparation=dict(zip(names,matches[0],strict=True))
            self.where='bot=? AND persona=? AND parent_original_id=?'
            self.key=(*self.producer.maintenance.namespace_id.as_tuple,self.preparation['parent_original_id'])
            self.phase='seal';return
        if self.phase=='seal':
            if self.total is None:
                _,self.total=self._cell(graph,'seal_json',0,0);self._request_arena(self.total*2+16384)
            elif self.offset<self.total:
                raw,total=self._cell(graph,'seal_json',self.offset,min(1024,self.total-self.offset))
                if total!=self.total:raise AuthorityUnavailable('natural seal source length changed')
                self._request_arena((len(self.buffer)+len(raw))*2+32768);self.buffer.extend(raw);self.offset+=len(raw)
            else:
                from .c09_model_budget_original_v1 import _json
                self._request_arena(self.total*32+65536);text=self.buffer.decode('ascii');meter.charge_encode(len(text))
                self.seal_raw=_json(text);self.buffer.clear();self.offset=0;self.total=None;self.phase='seal_identity'
        elif self.phase=='seal_identity':self._seal_identity(self.seal_raw,meter);self.seal_raw=None
        elif self.phase=='frozen_length':_,self.total=self._cell(graph,'frozen_json',0,0);self.offset=0;self.phase='frozen'
        elif self.phase=='frozen':
            if self.offset==self.total:
                if self.frozen.finish().byte_count!=self.total:raise AuthorityUnavailable('natural frozen canonical EOF differs')
                self._frozen_identity();self.offset=0;self.total=None;self.phase='request_length'
            else:
                amount=min(1024,self.total-self.offset);self._request_arena(amount*32+32768);raw,total=self._cell(graph,'frozen_json',self.offset,amount)
                if total!=self.total:raise AuthorityUnavailable('natural frozen length changed')
                self.frozen.feed(raw,self._frozen_event);self.frozen._emit_callback=None;self.offset+=amount
        elif self.phase=='request_length':
            _,self.total=self._cell(graph,'typed_request_wire',0,0);self.offset=0
            self.inner_parser=_D13PaidInnerObjectStreamV3('call',arena=self.arena,call_profile='natural',ensure_ascii=True);self.phase='request'
        elif self.phase=='request':
            if self.offset==self.total:
                eof=self.inner_parser.finish();self.wire_sha=eof.sha256
                if (eof.byte_count!=self.total or self.inner_parser.payload_hash.hexdigest()!=self.frozen.wire_hashes['canonical_wire'].hexdigest()
                        or self.inner_parser.payload_bytes!=self.frozen.wire_bytes['canonical_wire']):
                    raise AuthorityUnavailable('actual request payload differs from frozen provider wire')
                self.phase='request_fields'
            else:
                raw=self._read(self.offset,min(1024,self.total-self.offset),meter);self.inner_parser.feed(raw,lambda event:None)
                self.inner_parser._emit_callback=None;self.offset+=len(raw)
        elif self.phase=='request_fields':
            names=('envelope','call_id','provider_id','model_id','required_capabilities','privacy_tier','prompt_template_digest','timeout_seconds','max_output_tokens')
            if self.field_index==len(names):self.phase='request_identity'
            else:
                n=names[self.field_index];left,right=self.inner_parser.ranges[(n,)]
                if self.field_offset==right-left:
                    self._request_arena(len(self.buffer)*32+65536);self.inner_values[n]=json.loads(self.buffer)
                    self.buffer.clear();self.field_offset=0;self.field_index+=1
                else:
                    amount=min(1024,right-left-self.field_offset);self._request_arena((len(self.buffer)+amount)*2+32768)
                    self.buffer.extend(self._read(left+self.field_offset,amount,meter));self.field_offset+=amount
        elif self.phase=='request_identity':self._request_identity(meter)
        elif self.phase=='input_actions':self._input_projection_advance(meter)
        elif self.phase=='input_eof':
            self.input_pending_offset=len(self.input_pending)
            if self.input_encoded_offset<self.total:self._input_projection_read(meter)
            else:self.phase='request_digest'
        elif self.phase=='request_digest':
            if (self.input_replay_hash.hexdigest()!=self.wire_sha or self.input_text_complete!=2
                    or self.projection_tags_consumed!=len(self.projection_tags) or self.projection_replacements_consumed!=len(self.projection_replacements)
                    or self.input_hash.hexdigest()!=self.preparation['typed_request_digest']):
                raise AuthorityUnavailable('complete typed request digest/EOF/tags/key inventory differs')
            self._begin_rows(meter)
        elif self.phase in {'row_start','row_columns'}:self._row_advance(graph,meter)
        elif self.phase in {'guard_reads','guard_queries','guard_hash'}:self._guard_advance(meter)
        elif self.phase=='acquire_core':self._acquire_core_advance(core,meter)
        elif self.phase=='graph_identity':self._graph_identity(meter)
        elif self.phase!='complete':raise AuthorityUnavailable('unknown closed natural Graph proof phase')
    @contextmanager
    def common_read_scope(self,*,core,graph,meter,budget):
        if (not self.complete or self.producer._natural_model_connections_v3!=(core,graph,meter)
                or self.producer._natural_model_reservation_v3 is not budget):
            raise AuthorityUnavailable('actual completed natural common-reader reservation required')
        self.require_current();self._budget=budget;owned=0
        def preflight(size):
            nonlocal owned
            # The real SQL metadata is read before SQLite transfers each row.
            # Retain the bound for all rows/DTOs, not only the latest allocation.
            self._request_arena((owned+size)*64+65536)
            if size*6+4096>meter.remaining_bytes:
                raise AuthorityUnavailable('natural common original requires its segmented codec within unchanged byte cap')
            owned+=size
        if core._natural_preflight_v3 is not None or graph._natural_preflight_v3 is not None:
            raise AuthorityUnavailable('natural common reader cannot nest a reservation')
        core._natural_preflight_v3=preflight;graph._natural_preflight_v3=preflight
        try:
            with c09_sql_meter_quantum_v2(_NaturalQuantumMeterV3(meter,budget)):yield
        finally:
            core._natural_preflight_v3=None;graph._natural_preflight_v3=None;self._budget=None
    def issue(self,*,core,graph,meter,budget):return NaturalModelFrozenProofV3(_TOKEN,self,core,graph,meter,budget)
