"""Metered per-operation frozen Graph facts for C09 paged recovery.

These SQL readers grant no authority. The installed capture caller must bind the
actual source and C09 scope before and after the batch. No V4 whole-namespace
fact collector, namespace dictionary or caller-supplied fact is consumed.
"""
from __future__ import annotations

import json

from ..graph_types import AtomKey,GraphReceipt,GraphVersion,NamespaceEpoch
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from .c09_storage_rebase_contract_v1 import SanitizedGraphFactV4
from .c09_paged_sql_v2 import C09PagedCaptureHold,read_c09_table_shape_v2,_quote

_EVENT_COLUMNS=('session','event_id','digest','reads','epoch_reads','revisions','invalidated','epoch_revision')


def read_next_current_graph_original_key_v5(db,namespace,after_operation_id):
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise C09PagedCaptureHold('actual frozen namespace read transaction required')
    after='' if after_operation_id is None else after_operation_id
    row=db.execute('SELECT event_id FROM graph_events WHERE bot=? AND persona=? AND event_id COLLATE BINARY > ? ORDER BY event_id COLLATE BINARY LIMIT 1',
        (*namespace.as_tuple,after)).fetchone()
    return None if row is None else row[0]


def _meter_digest(value,meter):
    # The bounded source codec has reserved this value before decoding it.
    wire=canonical_serialize(value);meter.charge_encode(len(wire.encode('utf-8')))
    import hashlib
    return hashlib.sha256(wire.encode('utf-8')).hexdigest()


def _obligations_for_operation_v5(db,namespace,operation_id,meter):
    obligations=[]
    for table in ('graph_bundle_outbox','graph_outbox_jobs'):
        shape=read_c09_table_shape_v2(db,table)
        if 'operation_id' not in shape.columns or 'bot' not in shape.columns or 'persona' not in shape.columns:
            raise C09PagedCaptureHold('Graph obligation table actual namespace/key schema differs')
        # The V4 commitment used this exact SELECT iteration order. Validate
        # the complete single-operation transfer before repeating that SELECT;
        # imposing a new PK order would reinterpret previously issued bytes.
        lengths=','.join('length(CAST('+_quote(name)+' AS BLOB))' for name in shape.columns)
        reserved=0;row_count=0
        for metadata in db.execute('SELECT '+lengths+' FROM '+_quote(table)+' WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)):
            reserved+=sum(0 if length is None else length for length in metadata);row_count+=1
            if row_count>meter.budget.max_records or reserved*7>meter.remaining_bytes:
                raise C09PagedCaptureHold('one Graph obligation group requires its streaming codec')
        meter.require_available(reserved*7)
        for raw in db.execute('SELECT * FROM '+table+' WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)):
            row=tuple(raw);meter.charge_read(sum(_sql_bytes(item) for item in row))
            size=len(canonical_serialize((table,row)).encode('utf-8'));meter.charge_encode(size)
            obligations.append((table,row))
    return _meter_digest(tuple(obligations),meter) if obligations else None


def read_current_graph_fact_v5(db,namespace,operation_id,*,meter):
    """One genuine operation; caller already owns the frozen actual source."""
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise C09PagedCaptureHold('actual frozen Graph transaction required')
    # Three rows disprove the only registered two-event compound producer.
    sessions=tuple(db.execute('SELECT session FROM graph_events WHERE bot=? AND persona=? AND event_id=? ORDER BY session COLLATE BINARY LIMIT 3',
        (*namespace.as_tuple,operation_id)))
    if not sessions:return None
    if len(sessions)>2:raise C09PagedCaptureHold('Graph operation has ambiguous event originals')
    obligations=_obligations_for_operation_v5(db,namespace,operation_id,meter)
    parts=[]
    for (session,) in sessions:
        row=meter.read_fixed_row(db,'graph_events',_EVENT_COLUMNS,'bot=? AND persona=? AND event_id=? AND session=?',
            (*namespace.as_tuple,operation_id,session))
        if row is None:raise C09PagedCaptureHold('actual committed event disappeared')
        _session,event_id,digest,reads,epoch_reads,revisions,invalidated,epoch=row
        try:
            written=tuple(GraphVersion(AtomKey.from_token(token),revision) for token,revision in json.loads(revisions))
            invalid=tuple(GraphVersion(AtomKey.from_token(token),revision) for token,revision in json.loads(invalidated))
            for raw in (reads,epoch_reads):json.loads(raw)
            receipt=GraphReceipt('committed',written,invalid,NamespaceEpoch(*namespace.as_tuple,epoch))
        except (TypeError,ValueError,KeyError) as exc:
            raise C09PagedCaptureHold('actual Graph event original cannot be decoded') from exc
        fact=SanitizedGraphFactV4(event_id,_meter_digest(receipt,meter),
            _meter_digest((digest,reads,epoch_reads,revisions,invalidated),meter),obligations)
        parts.append((session,fact))
    if len(parts)==1:return parts[0][1]
    if {part[0] for part in parts}!={'d12.scheme_adoption.v1','d04.authored_root.v3'}:
        raise C09PagedCaptureHold('Graph compound operation is not a registered producer')
    from .c09_d04_originals_v3 import validate_d04_original_payload_v3,COLUMNS,TABLE
    original=meter.read_fixed_row(db,TABLE,COLUMNS,'bot=? AND persona=? AND kind=? AND original_ref=?',
        (*namespace.as_tuple,'root_execution_link',operation_id))
    if original is None:raise C09PagedCaptureHold('compound Graph root lacks actual execution-link original')
    link=validate_d04_original_payload_v3('root_execution_link',json.loads(original[COLUMNS.index('payload_json')]))
    receipts={session:fact.receipt_commitment for session,fact in parts}
    if (link['operation_id']!=operation_id or link['head_receipt_digest']!=receipts['d12.scheme_adoption.v1']
            or link['root_receipt_digest']!=receipts['d04.authored_root.v3']):
        raise C09PagedCaptureHold('compound Graph root actual receipt commitments differ')
    ordered=tuple(sorted(parts,key=lambda part:part[0]))
    return SanitizedGraphFactV4(operation_id,
        _meter_digest(tuple((session,fact.receipt_commitment) for session,fact in ordered),meter),
        _meter_digest(tuple((session,fact.write_set_commitment) for session,fact in ordered),meter),
        _meter_digest(tuple((session,fact.unresolved_obligation_commitment) for session,fact in ordered),meter)
            if any(fact.unresolved_obligation_commitment is not None for _,fact in ordered) else None)


def read_next_orphan_graph_operation_v5(db,namespace,after_key):
    """Indexed anti-join covers the complete namespace over bounded calls."""
    after='' if after_key is None else after_key
    candidates=[]
    for table in ('graph_bundle_operations','graph_bundle_outbox','graph_outbox_jobs'):
        row=db.execute('SELECT o.operation_id FROM '+table+' o WHERE o.bot=? AND o.persona=? AND o.operation_id COLLATE BINARY > ? '+
            'AND NOT EXISTS (SELECT 1 FROM graph_events e WHERE e.bot=o.bot AND e.persona=o.persona AND e.event_id=o.operation_id) '+
            'ORDER BY o.operation_id COLLATE BINARY LIMIT 1',(*namespace.as_tuple,after)).fetchone()
        if row is not None:candidates.append(row[0])
    return min(candidates) if candidates else None


def _sql_bytes(value):
    if value is None:return 0
    if type(value) is bytes:return len(value)
    if type(value) is str:return len(value.encode('utf-8'))
    return len(str(value).encode('ascii'))


PRIOR_GRAPH_VIEW_DDLS_V2={
 'c09_prior_graph_spans_v2':'CREATE TABLE c09_prior_graph_spans_v2 (scope_digest TEXT NOT NULL, certificate_operation_id TEXT NOT NULL, path_json TEXT NOT NULL, start_offset INTEGER NOT NULL, end_offset INTEGER NOT NULL, PRIMARY KEY(scope_digest,certificate_operation_id,path_json))',
 'c09_prior_graph_types_v2':'CREATE TABLE c09_prior_graph_types_v2 (scope_digest TEXT NOT NULL, certificate_operation_id TEXT NOT NULL, byte_offset INTEGER NOT NULL, type_name TEXT NOT NULL, PRIMARY KEY(scope_digest,certificate_operation_id,byte_offset))',
 'c09_prior_graph_rows_v2':'CREATE TABLE c09_prior_graph_rows_v2 (scope_digest TEXT NOT NULL, certificate_operation_id TEXT NOT NULL, table_index INTEGER NOT NULL, row_index INTEGER NOT NULL, row_key_digest TEXT NOT NULL, old_commitment TEXT NOT NULL, disposition TEXT NOT NULL, new_commitment TEXT, start_offset INTEGER NOT NULL, end_offset INTEGER NOT NULL, PRIMARY KEY(scope_digest,certificate_operation_id,table_index,row_index), UNIQUE(scope_digest,certificate_operation_id,table_index,row_key_digest))',
 'c09_prior_graph_keys_v2':'CREATE TABLE c09_prior_graph_keys_v2 (scope_digest TEXT NOT NULL, certificate_operation_id TEXT NOT NULL, family TEXT NOT NULL, item_index INTEGER NOT NULL, item_key TEXT NOT NULL, PRIMARY KEY(scope_digest,certificate_operation_id,family,item_index), UNIQUE(scope_digest,certificate_operation_id,family,item_key))',
}
PRIOR_GRAPH_VIEW_DDLS_V2['c09_prior_graph_manifests_v2']='CREATE TABLE c09_prior_graph_manifests_v2 (scope_digest TEXT NOT NULL, certificate_operation_id TEXT NOT NULL, table_index INTEGER NOT NULL, table_name TEXT NOT NULL, PRIMARY KEY(scope_digest,certificate_operation_id,table_index), UNIQUE(scope_digest,certificate_operation_id,table_name))'
PRIOR_GRAPH_VIEW_DDLS_V2['c09_prior_graph_streams_v2']='CREATE TABLE c09_prior_graph_streams_v2 (scope_digest TEXT NOT NULL, certificate_operation_id TEXT NOT NULL, stream_kind TEXT NOT NULL, family TEXT NOT NULL, identity_json TEXT NOT NULL, complete_json TEXT NOT NULL, outer_primary_key_json TEXT NOT NULL, outer_record_ordinal INTEGER NOT NULL, outer_row_commitment TEXT NOT NULL, PRIMARY KEY(scope_digest,certificate_operation_id,stream_kind,family))'
PRIOR_GRAPH_VIEW_TABLES_V2=frozenset(PRIOR_GRAPH_VIEW_DDLS_V2)
_PRIOR_VIEW_TOKEN_V2=object()


def install_c09_prior_graph_view_schema_v2(candidate):
    for name,ddl in PRIOR_GRAPH_VIEW_DDLS_V2.items():
        saved=candidate.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()
        if saved is None:candidate.execute(ddl)
        elif saved!=(ddl,):raise C09PagedCaptureHold('prior Graph candidate metadata schema differs')


def _metered_prior_certificate_v2(function):
    from functools import wraps
    @wraps(function)
    def run(self,*,budget,meter):
        from .c09_paged_capture_contract_v2 import meter_c09_commitments_v2
        if meter.budget!=budget:raise C09PagedCaptureHold('prior reader crossed its actual batch reservation')
        with meter_c09_commitments_v2(meter):return function(self,budget=budget,meter=meter)
    return run


class C09PriorGraphCertificateReaderV2:
    """Actual frozen certificate scan; persisted metadata never mints a view."""
    def __init__(self,token,session,pair,operation,expected,read_only):
        if token is not _PRIOR_VIEW_TOKEN_V2:raise TypeError('actual prior Graph reader required')
        from ..authority_service.c09_paged_recovery_facts_v2 import C09CanonicalSqlCellReaderV2
        self.session=session;self.pair=pair;self.operation=operation;self.scope=session.scope.scope_digest;self.expected=expected
        ns=json.loads(session.scope.graph_namespace)
        self.cell=C09CanonicalSqlCellReaderV2('graph_c09_rebase_certificates_v1','certificate_json',
            'bot=? AND persona=? AND operation_id=?',(*ns,operation),ensure_ascii=True,observe=self._event)
        self.read_only=read_only;self.phase='scan';self.starts={};self.row_last='';self.rows=0;self.tables=0;self.key_last={};self.key_counts={}
        self.header={};self.header_index=0;self.table_index=0;self.manifest_hash=None;self.cert_hash=None;self.view=None
        self.db=None;self.meter=None;self.last_table='';self.current_table_index=-1;self.span_count=0;self.tombstone_hash=__import__('hashlib').sha256();self.tombstone_offset=0

    def _read(self,sql,args):
        from ..authority_service.c09_paged_recovery_facts_v2 import _read_one
        return _read_one(self.pair.candidate,sql,args,self.meter)

    def _store(self,table,columns,values,where,args):
        old=self.meter.read_fixed_row(self.pair.candidate,table,columns,where,args)
        if old is not None:
            if old!=values:raise C09PagedCaptureHold('prior Graph metadata differs during actual source replay')
            return
        if self.read_only:raise C09PagedCaptureHold('independent cold prior metadata member is absent')
        from .c09_paged_sql_v2 import _sql_scalar_size_v2
        self.meter.charge_write(sum(_sql_scalar_size_v2(x) for x in values))
        self.pair.candidate.execute('INSERT INTO '+table+' ('+','.join(columns)+') VALUES ('+','.join('?' for _ in values)+')',values)

    def _span(self,path,start,end):
        self.span_count+=1
        wire=canonical_serialize(path);self.meter.charge_encode(len(wire.encode()))
        values=(self.scope,self.operation,wire,start,end)
        self._store('c09_prior_graph_spans_v2',('scope_digest','certificate_operation_id','path_json','start_offset','end_offset'),values,
            'scope_digest=? AND certificate_operation_id=? AND path_json=?',values[:3])

    def _type(self,event,cls):
        values=(self.scope,self.operation,event.start_offset+1,cls.__module__+'.'+cls.__qualname__)
        self._store('c09_prior_graph_types_v2',('scope_digest','certificate_operation_id','byte_offset','type_name'),values,
            'scope_digest=? AND certificate_operation_id=? AND byte_offset=?',values[:3])

    def _event(self,event):
        from .c09_storage_rebase_contract_v1 import GraphRowDispositionV1,GraphTableDispositionManifestV1
        path=event.path;kind=event.kind
        is_manifest=len(path)==2 and path[0]=='table_manifests' and type(path[1]) is int
        is_row=len(path)==4 and path[0]=='table_manifests' and path[2]=='rows' and type(path[3]) is int
        if len(path)==3 and path[0]=='table_manifests' and path[2] not in {'table_name','rows','manifest_digest','schema'}:raise C09PagedCaptureHold('prior manifest has unknown fields')
        wanted=(len(path)==1 or is_manifest or is_row or len(path)==3 and path[0]=='table_manifests'
            or len(path)==2 and path[0] in {'prior_erased_key_digests','newly_erased_key_digests','cumulative_erased_key_digests','component_hashes'})
        if not wanted:return
        if kind in {'object_start','array_start','scalar_start'}:
            self.starts[path]=event.start_offset
            if is_manifest:
                if path[1]!=self.tables:raise C09PagedCaptureHold('prior manifest ordinal differs')
                self.current_table_index=path[1];self.row_last='';self._type(event,GraphTableDispositionManifestV1)
            elif is_row:self._type(event,GraphRowDispositionV1)
            return
        if kind not in {'object_end','array_end','scalar_end'}:return
        start=self.starts.pop(path);end=event.end_offset
        if is_row:
            if end-start>65536:raise C09PagedCaptureHold('prior disposition descriptor exceeds its registered bound')
            raw=json.loads(self.cell.read(self.db,start,end-start,self.meter))
            value=GraphRowDispositionV1(**raw)
            if value.row_key_digest<=self.row_last:raise C09PagedCaptureHold('prior disposition rows are not strictly ordered')
            self.row_last=value.row_key_digest;self.rows+=1
            values=(self.scope,self.operation,path[1],path[3],value.row_key_digest,value.old_commitment,value.disposition,value.new_commitment,start,end)
            self._store('c09_prior_graph_rows_v2',('scope_digest','certificate_operation_id','table_index','row_index','row_key_digest','old_commitment','disposition','new_commitment','start_offset','end_offset'),values,
                'scope_digest=? AND certificate_operation_id=? AND table_index=? AND row_index=?',values[:4])
        elif len(path)==2 and path[0] in {'prior_erased_key_digests','newly_erased_key_digests','cumulative_erased_key_digests','component_hashes'}:
            if end-start>65536:raise C09PagedCaptureHold('prior scalar descriptor exceeds its registered bound')
            value=json.loads(self.cell.read(self.db,start,end-start,self.meter))
            if path[0]=='component_hashes':
                if type(value) is not list or len(value)!=2:raise C09PagedCaptureHold('prior component descriptor differs')
                name,digest=value
                from .c09_storage_rebase_contract_v1 import _id,_digest
                _id(name,'component_name');_digest(digest,'component_hash');item=canonical_serialize(value)
            else:
                from .c09_storage_rebase_contract_v1 import _digest
                _digest(value,path[0]);item=value
            if item<=self.key_last.get(path[0],''):raise C09PagedCaptureHold('prior key/component ordering differs')
            self.key_last[path[0]]=item;self.key_counts[path[0]]=self.key_counts.get(path[0],0)+1
            values=(self.scope,self.operation,path[0],path[1],item)
            self._store('c09_prior_graph_keys_v2',('scope_digest','certificate_operation_id','family','item_index','item_key'),values,
                'scope_digest=? AND certificate_operation_id=? AND family=? AND item_index=?',values[:4])
        else:
            self._span(path,start,end)
            if len(path)==3 and path[0]=='table_manifests' and path[2]=='table_name':
                if end-start>1024:raise C09PagedCaptureHold('prior manifest name exceeds its installed codec')
                name=json.loads(self.cell.read(self.db,start,end-start,self.meter))
                from .c09_storage_rebase_contract_v1 import _id
                _id(name,'table_name')
                values=(self.scope,self.operation,path[1],name)
                self._store('c09_prior_graph_manifests_v2',('scope_digest','certificate_operation_id','table_index','table_name'),values,
                    'scope_digest=? AND certificate_operation_id=? AND table_index=?',values[:3])
        if is_manifest:self.tables+=1

    def _annotation(self,position,last,end,meter):
        return self._read('SELECT byte_offset,type_name FROM c09_prior_graph_types_v2 WHERE scope_digest=? AND certificate_operation_id=? AND byte_offset>=? AND byte_offset>? AND byte_offset<? ORDER BY byte_offset LIMIT 1',
            (self.scope,self.operation,position,last,end))

    def _nested_span(self,path):
        row=self._read('SELECT start_offset,end_offset FROM c09_prior_graph_spans_v2 WHERE scope_digest=? AND certificate_operation_id=? AND path_json=?',
            (self.scope,self.operation,canonical_serialize(path)))
        if row is None:raise C09PagedCaptureHold('prior certificate lost its actual nested span')
        self.cell.spans[path]=row

    @_metered_prior_certificate_v2
    def advance(self,*,budget,meter):
        from dataclasses import fields
        from .c09_storage_rebase_contract_v1 import GraphErasureRebaseCertificateV1
        from ..authority_service.c09_paged_recovery_facts_v2 import C09TypedCanonicalSpanHashV2
        from time import monotonic_ns
        self.session.require_current();self.pair.require_current();self.meter=meter;self.db=self.pair.source
        started=monotonic_ns();self.db.execute('BEGIN')
        try:
            if self.phase=='scan':
                with self.pair.candidate:
                    while monotonic_ns()-started<budget.max_local_ns and meter.remaining_bytes>16384:
                        if self.cell.advance(self.db,meter):break
                    if not self.cell.complete:return None
                    count=self._read('SELECT count(*) FROM c09_prior_graph_rows_v2 WHERE scope_digest=? AND certificate_operation_id=?',(self.scope,self.operation))
                    if count!=(self.rows,):raise C09PagedCaptureHold('prior disposition metadata has extra or missing rows')
                    for table,expected in (('c09_prior_graph_types_v2',self.tables+self.rows),('c09_prior_graph_spans_v2',self.span_count),('c09_prior_graph_manifests_v2',self.tables)):
                        count=self._read('SELECT count(*) FROM '+table+' WHERE scope_digest=? AND certificate_operation_id=?',(self.scope,self.operation))
                        if count!=(expected,):raise C09PagedCaptureHold('prior metadata index has extra or missing members')
                    for family,expected in self.key_counts.items():
                        count=self._read('SELECT count(*) FROM c09_prior_graph_keys_v2 WHERE scope_digest=? AND certificate_operation_id=? AND family=?',(self.scope,self.operation,family))
                        if count!=(expected,):raise C09PagedCaptureHold('prior scalar inventory has extra or missing members')
                    names={f.name for f in fields(GraphErasureRebaseCertificateV1)}
                    if {p[0] for p in self.cell.spans if len(p)==1}!=names:raise C09PagedCaptureHold('prior certificate exact fields differ')
                    self.header_keys=tuple(f.name for f in fields(GraphErasureRebaseCertificateV1) if f.name not in {'table_manifests','prior_erased_key_digests','newly_erased_key_digests','cumulative_erased_key_digests','component_hashes'})
                    self.phase='header'
                return None
            if self.phase=='header':
                if self.header_index<len(self.header_keys):
                    name=self.header_keys[self.header_index];self.header[name]=self.cell.value(self.db,(name,),meter);self.header_index+=1;return None
                self._validate_header();self.phase='tombstones';return None
            if self.phase=='tombstones':
                start,end=self.cell.spans[('cumulative_erased_key_digests',)]
                amount=min(16384,end-start-self.tombstone_offset)
                if amount:
                    self.tombstone_hash.update(self.cell.read(self.db,start+self.tombstone_offset,amount,meter));self.tombstone_offset+=amount;return None
                if self.tombstone_hash.hexdigest()!=self.header['tombstone_root']:raise C09PagedCaptureHold('prior complete cumulative tombstone root differs')
                self.phase='manifests';return None
            if self.phase=='manifests':
                if self.table_index<self.tables:
                    paths=tuple(('table_manifests',self.table_index,name) for name in ('table_name','rows','schema'))
                    if self.manifest_hash is None:
                        for path in (*paths,('table_manifests',self.table_index,'manifest_digest')):self._nested_span(path)
                        name=self.cell.value(self.db,paths[0],meter);schema=self.cell.value(self.db,paths[2],meter)
                        if type(name) is not str or name<=self.last_table or schema!='sylanne3.graph.c09_table_disposition.v1':raise C09PagedCaptureHold('prior manifest schema/order differs')
                        self.last_table=name;self.manifest_hash=C09TypedCanonicalSpanHashV2(self.cell,paths,next_type_annotation=self._annotation)
                    digest=self.manifest_hash.advance(self.db,meter)
                    if digest is None:return None
                    if digest!=self.cell.value(self.db,('table_manifests',self.table_index,'manifest_digest'),meter):raise C09PagedCaptureHold('prior typed manifest digest differs')
                    for path in tuple(self.cell.spans):
                        if len(path)>1:del self.cell.spans[path]
                    self.manifest_hash=None;self.table_index+=1;return None
                self.phase='certificate';self.cert_hash=C09TypedCanonicalSpanHashV2(self.cell,tuple((f.name,) for f in fields(GraphErasureRebaseCertificateV1) if f.name!='certificate_digest'),next_type_annotation=self._annotation);return None
            if self.phase=='certificate':
                digest=self.cert_hash.advance(self.db,meter)
                if digest is None:return None
                if digest!=self.header['certificate_digest']:raise C09PagedCaptureHold('prior typed complete certificate digest differs')
                self.phase='authority';return None
            if self.phase=='authority':
                anchor=self.session.require_historical_graph_issue_v2(self.header['schema'],self.operation,self.header['certificate_digest'])
                if anchor['maintenance_generation']!=self.header['maintenance_generation']:raise C09PagedCaptureHold('prior actual Core signed generation differs')
                self.view=VerifiedPriorGraphCertificateViewV2(_PRIOR_VIEW_TOKEN_V2,self);self.phase='complete'
                return self.view
            return self.view
        finally:
            self.db.rollback();self.db=None;self.meter=None
            if monotonic_ns()-started>budget.max_read_ns:raise C09PagedCaptureHold('actual prior certificate read exceeded its finite duration')

    def _validate_header(self):
        from .c09_storage_rebase_contract_v1 import _id,_digest,_number
        h=self.header
        for name in ('authority_id','installation_id','namespace','operation_id','old_incarnation','new_incarnation'):_id(h[name],name)
        for name in ('accepted_receipt_digest','barrier_receipt_digest','frozen_inventory_digest','source_closure_digest','derived_closure_digest','tombstone_root','new_data_root','cold_read_digest','certificate_digest'):_digest(h[name],name)
        for name in ('old_revision','old_graph_epoch','old_access_epoch','old_delete_epoch','maintenance_generation'):_number(h[name],name)
        if (h['schema']!='sylanne3.graph.c09_erasure_rebase.v1' or h['namespace']!=self.session.scope.authority_namespace or h['operation_id']!=self.operation or h['maintenance_generation']<1 or h['new_incarnation']==h['old_incarnation'] or not self.tables):raise C09PagedCaptureHold('prior actual certificate identity/schema differs')
        if (h['certificate_digest'],h['maintenance_generation'],h['new_incarnation'])!=self.expected:
            raise C09PagedCaptureHold('prior certificate is outside actual signed selected storage generation')
        if not self.key_counts.get('newly_erased_key_digests') or not self.key_counts.get('component_hashes'):raise C09PagedCaptureHold('prior complete certificate required inventory absent')
        if (h['prior_certificate_digest'] is None)!=(not self.key_counts.get('prior_erased_key_digests')):raise C09PagedCaptureHold('prior erased lineage differs')
        if h['prior_certificate_digest'] is not None:_digest(h['prior_certificate_digest'],'prior_certificate_digest')
        args=(self.scope,self.operation)
        overlap=self._read("SELECT 1 FROM c09_prior_graph_keys_v2 p JOIN c09_prior_graph_keys_v2 n ON n.scope_digest=p.scope_digest AND n.certificate_operation_id=p.certificate_operation_id AND n.item_key=p.item_key AND n.family='newly_erased_key_digests' WHERE p.scope_digest=? AND p.certificate_operation_id=? AND p.family='prior_erased_key_digests' LIMIT 1",args)
        missing=self._read("SELECT 1 FROM c09_prior_graph_keys_v2 p WHERE p.scope_digest=? AND p.certificate_operation_id=? AND p.family IN ('prior_erased_key_digests','newly_erased_key_digests') AND NOT EXISTS (SELECT 1 FROM c09_prior_graph_keys_v2 c WHERE c.scope_digest=p.scope_digest AND c.certificate_operation_id=p.certificate_operation_id AND c.family='cumulative_erased_key_digests' AND c.item_key=p.item_key) LIMIT 1",args)
        extra=self._read("SELECT 1 FROM c09_prior_graph_keys_v2 c WHERE c.scope_digest=? AND c.certificate_operation_id=? AND c.family='cumulative_erased_key_digests' AND NOT EXISTS (SELECT 1 FROM c09_prior_graph_keys_v2 p WHERE p.scope_digest=c.scope_digest AND p.certificate_operation_id=c.certificate_operation_id AND p.family IN ('prior_erased_key_digests','newly_erased_key_digests') AND p.item_key=c.item_key) LIMIT 1",args)
        if overlap or missing or extra:raise C09PagedCaptureHold('prior cumulative erased-key exact union differs')



class VerifiedPriorGraphCertificateViewV2:
    __slots__=('_token','reader','certificate_schema','certificate_digest')
    def __init__(self,token,reader):
        if token is not _PRIOR_VIEW_TOKEN_V2 or reader.phase!='authority':raise TypeError('actual completed prior certificate reader required')
        self._token=token;self.reader=reader;self.certificate_schema=reader.header['schema'];self.certificate_digest=reader.header['certificate_digest']

    def require_row_disposition(self,table,primary_key,old_commitment,*,meter):
        return self._require_disposition(table,primary_key,old_commitment,meter=meter,target=False)

    def require_target_row_disposition(self,table,primary_key,new_commitment,*,meter):
        return self._require_disposition(table,primary_key,new_commitment,meter=meter,target=True)

    def require_generated_erased_key_v3(self,token,tombstone,*,meter):
        """Legacy V1 first tombstone: re-read the signed certificate key span."""
        from ..authority_service.c09_paged_recovery_facts_v2 import _read_one
        r=self.reader;r.session.require_current();r.pair.require_current()
        expected=canonical_digest(token);ns=tuple(json.loads(r.session.scope.graph_namespace))
        if tombstone!=(*ns,expected,r.header['maintenance_generation'],r.operation):
            raise C09PagedCaptureHold('legacy generated tombstone changed original namespace/generation/operation')
        item=_read_one(r.pair.candidate,'SELECT item_index FROM c09_prior_graph_keys_v2 '
            'WHERE scope_digest=? AND certificate_operation_id=? AND family=? AND item_key=?',
            (r.scope,r.operation,'newly_erased_key_digests',expected),meter)
        count=r.key_counts.get('newly_erased_key_digests',0)
        if item is None or not 0<=item[0]<count:
            raise C09PagedCaptureHold('legacy generated tombstone is outside actual complete new-key census')
        start,end=r.cell.spans[('newly_erased_key_digests',)]
        offset=start+1+item[0]*67
        if offset+66>end-1:raise C09PagedCaptureHold('legacy generated key span crosses actual signed array EOF')
        raw=r.cell.read(r.pair.source,offset,66,meter)
        if raw!=canonical_serialize(expected).encode('utf-8'):
            raise C09PagedCaptureHold('legacy generated tombstone differs from actual signed certificate bytes')
        return {'certificate_digest':self.certificate_digest,'new_key_index':item[0],'key_digest':expected}

    def _require_disposition(self,table,primary_key,commitment,*,meter,target):
        from .c09_storage_rebase_contract_v1 import GraphRowDispositionV1
        from ..authority_service.c09_paged_recovery_facts_v2 import _read_one
        r=self.reader;r.session.require_current();r.pair.require_current()
        key=canonical_digest((table,primary_key));meter.charge_encode(len(canonical_serialize((table,primary_key)).encode()))
        manifest=_read_one(r.pair.candidate,'SELECT table_index FROM c09_prior_graph_manifests_v2 WHERE scope_digest=? AND certificate_operation_id=? AND table_name=?',(r.scope,r.operation,table),meter)
        if manifest is None:raise C09PagedCaptureHold('prior table has no fully verified actual manifest')
        row=_read_one(r.pair.candidate,'SELECT row_key_digest,old_commitment,disposition,new_commitment,start_offset,end_offset FROM c09_prior_graph_rows_v2 WHERE scope_digest=? AND certificate_operation_id=? AND table_index=? AND row_key_digest=?',(r.scope,r.operation,manifest[0],key),meter)
        if row is None or row[3 if target else 1]!=commitment:raise C09PagedCaptureHold('prior exact row commitment is outside its verified disposition')
        if row[5]-row[4]>65536:raise C09PagedCaptureHold('actual prior row descriptor exceeds its registered span')
        actual=GraphRowDispositionV1(**json.loads(r.cell.read(r.pair.source,row[4],row[5]-row[4],meter)))
        if (actual.row_key_digest,actual.old_commitment,actual.disposition,actual.new_commitment)!=row[:4]:raise C09PagedCaptureHold('prior point index differs from its actual streamed source span')
        return actual


def read_latest_verified_graph_certificate_view_v5(session,pair):
    return _begin_latest_graph_certificate_view_v5(session,pair,False)


def begin_verify_latest_graph_certificate_view_v5(session,pair):
    """Independent from-zero cold read; never repairs or rewrites proof metadata."""
    return _begin_latest_graph_certificate_view_v5(session,pair,True)


def _begin_latest_graph_certificate_view_v5(session,pair,read_only):
    """Return a private scan continuation; absence comes from real frozen SQL."""
    from ..authority_service.c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from ..authority_service.c09_role_capture_pair_v2 import InstalledC09RolePairV2
    if type(session) is not C09PagedCaptureSessionV2 or type(pair) is not InstalledC09RolePairV2 or pair.source_original.role!='graph':raise TypeError('actual installed Graph role pair required')
    session.require_current();pair.require_current();ns=tuple(json.loads(session.scope.graph_namespace))
    current,_=session._control._current(session.scope.operation_id)
    prepared=current.prepared_original
    if prepared is None:
        for table in ('graph_c09_rebase_certificates_v1','graph_c09_rebase_certificates_v2'):
            if pair.source.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() is not None and pair.source.execute('SELECT 1 FROM '+table+' WHERE bot=? AND persona=? LIMIT 1',ns).fetchone() is not None:
                raise C09PagedCaptureHold('initial storage has an unselected Graph certificate history')
        return None
    operation=prepared['operation_id']
    if read_only:
        for table,ddl in PRIOR_GRAPH_VIEW_DDLS_V2.items():
            if pair.candidate.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()!=(ddl,):raise C09PagedCaptureHold('independent prior fixed metadata schema differs')
    else:install_c09_prior_graph_view_schema_v2(pair.candidate)
    if prepared['schema']=='sylanne3.c09.storage_prepared_original.v2':
        return C09PagedPriorGraphCertificateReaderV2(_PRIOR_VIEW_TOKEN_V2,session,pair,current,read_only)
    if prepared['schema']!='sylanne3.c09.storage_prepared_original.v1':raise C09PagedCaptureHold('unknown actual selected certificate producer schema')
    row=pair.source.execute('SELECT 1 FROM graph_c09_rebase_certificates_v1 WHERE bot=? AND persona=? AND operation_id=?',(*ns,operation)).fetchone()
    if row is None:raise C09PagedCaptureHold('actual selected storage certificate mirror is absent')
    graph=next(member for member in current.manifest['members'] if member['role']=='graph')
    expected=(current.manifest['certificate_digest'],current.storage_generation,graph['incarnation_or_journal_id'])
    if read_only:
        for table,ddl in PRIOR_GRAPH_VIEW_DDLS_V2.items():
            if pair.candidate.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()!=(ddl,):raise C09PagedCaptureHold('independent cold prior fixed metadata schema differs')
    else:install_c09_prior_graph_view_schema_v2(pair.candidate)
    return C09PriorGraphCertificateReaderV2(_PRIOR_VIEW_TOKEN_V2,session,pair,operation,expected,read_only)


class C09PagedPriorGraphCertificateReaderV2:
    """Six signed finite directories and their actual row streams, from zero."""
    def __init__(self,token,session,pair,current,read_only):
        if token is not _PRIOR_VIEW_TOKEN_V2:raise TypeError('actual prior paged certificate reader required')
        self.session=session;self.pair=pair;self.selected=current;self.operation=current.prepared_original['operation_id']
        self.read_only=read_only;self.phase='header';self.certificate=None;self.directory_index=0;self.directory_reader=None
        self.nested_reader=None;self.nested_locator=None;self.directory_shape=None;self.view=None
        self.complete_directories=0;self.stream_count=0;self.db=None;self.meter=None
        self.inventory_locator_v3=None;self.inventory_version_v3=0;self.inventory_after_v3="";self.inventory_count_v3=0

    @_metered_prior_certificate_v2
    def advance(self,*,budget,meter):
        from time import monotonic_ns
        from .c09_paged_capture_contract_v2 import (GraphErasureRebaseCertificateV2,C09StreamIdentityV2,
            C09CompleteStreamV2,C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2)
        from ..authority_service.c09_paged_recovery_facts_v2 import C09HistoricalSealedStreamReaderV2
        self.session.require_current();self.pair.require_current();self.db=self.pair.source;self.meter=meter
        started=monotonic_ns();self.db.execute('BEGIN')
        try:
            if self.phase=='header':
                ns=tuple(json.loads(self.session.scope.graph_namespace))
                row=meter.read_fixed_row(self.db,'graph_c09_rebase_certificates_v2',('certificate_json','issue_digest'),
                    'bot=? AND persona=? AND operation_id=?',(*ns,self.operation))
                if row is None:raise C09PagedCaptureHold('signed selected paged Graph certificate mirror absent')
                certificate=c09_paged_value_from_wire_v2(json.loads(row[0]),GraphErasureRebaseCertificateV2)
                if (certificate.digest!=self.selected.manifest['certificate_digest']
                        or certificate.candidate.scope.operation_id!=self.operation
                        or certificate.candidate.scope.authority_namespace!=self.session.scope.authority_namespace
                        or certificate.candidate.scope.maintenance_generation!=self.selected.storage_generation):
                    raise C09PagedCaptureHold('prior compact certificate differs from actual signed selected storage')
                graph=next(m for m in self.selected.manifest['members'] if m['role']=='graph')
                if certificate.candidate.new_incarnation!=graph['incarnation_or_journal_id']:raise C09PagedCaptureHold('prior compact certificate Graph incarnation differs')
                self.certificate=certificate;self.mirrored_issue_digest=row[1];self.phase='authority';return None
            if self.phase=='authority':
                anchor=self.session.require_historical_graph_issue_v2(self.certificate.schema,self.operation,self.certificate.digest)
                if anchor['issue_digest']!=self.mirrored_issue_digest:raise C09PagedCaptureHold('prior signed issue differs from actual Graph mirror')
                self.phase='directories';return None
            if self.phase=='directories':
                if self.inventory_locator_v3 is not None:
                    if self._advance_disposition_inventory_v3(meter):self.inventory_locator_v3=None
                    return None
                if self.nested_reader is not None:
                    if self.nested_reader.advance(self.db,meter,self._nested_member):
                        if self.nested_locator.identity.stream_kind=='row_dispositions':
                            self.inventory_locator_v3=self.nested_locator
                            self.inventory_version_v3=0;self.inventory_after_v3='';self.inventory_count_v3=0
                        self.nested_reader=self.nested_locator=None
                    return None
                fields=('schema_catalogue','disposition_directory','closure','tombstones','target_directory','generated_directory')
                if self.directory_index==len(fields):
                    from ..authority_service.c09_paged_recovery_facts_v2 import _read_one
                    count=_read_one(self.pair.candidate,'SELECT count(*) FROM c09_prior_graph_streams_v2 WHERE scope_digest=? AND certificate_operation_id=?',(self.session.scope.scope_digest,self.operation),meter)
                    if count!=(self.stream_count,):raise C09PagedCaptureHold('prior paged directory metadata has extra or missing signed members')
                    self.complete_directories=6;self.view=VerifiedPagedPriorGraphCertificateViewV2(_PRIOR_VIEW_TOKEN_V2,self);self.phase='complete';return self.view
                if self.directory_reader is None:
                    locator=getattr(self.certificate.candidate,fields[self.directory_index])
                    self.directory_shape=read_c09_table_shape_v2(self.db,locator.identity.family)
                    self._require_shape(locator,self.directory_shape)
                    self.directory_reader=C09HistoricalSealedStreamReaderV2(locator)
                if self.directory_reader.advance(self.db,meter,self._directory_member):
                    self.directory_reader=None;self.directory_index+=1
                return None
            return self.view
        finally:
            self.db.rollback();self.db=None;self.meter=None
            if monotonic_ns()-started>budget.max_read_ns:raise C09PagedCaptureHold('actual prior paged stream read exceeded its duration')

    def _require_shape(self,locator,shape):
        if (shape.schema_digest,shape.primary_key_columns,shape.primary_key_types)!=(locator.identity.schema_digest,locator.identity.primary_key_columns,locator.identity.primary_key_types):
            if locator.identity.stream_kind!='row_dispositions' or shape.table not in ('graph_atoms','graph_history','graph_domain_production_originals_v3'):
                raise C09PagedCaptureHold('prior signed stream physical schema differs')
            from .c09_logical_source_v3 import read_c09_logical_source_shape_v3
            scope=self.session.begin_source_physical_read_v3(self.pair,meter=self.meter)
            logical=read_c09_logical_source_shape_v3(scope,shape.table,meter=self.meter)
            if (logical.physical_shape!=shape or logical.logical_shape_digest!=locator.identity.schema_digest
                    or shape.primary_key_columns!=locator.identity.primary_key_columns
                    or shape.primary_key_types!=locator.identity.primary_key_types):
                raise C09PagedCaptureHold('prior signed logical Source shape differs from its actual registered physical layout')
        old=self.certificate.candidate
        if locator.identity.scope_digest!=old.scope.scope_digest or locator.identity.role_source_digest!=old.source.role_source_digest:raise C09PagedCaptureHold('prior signed stream crossed actual scope/source')

    def _directory_member(self,record):
        from .c09_graph_rebase_candidate_v1 import _row_digest
        from .c09_paged_capture_contract_v2 import C09StreamIdentityV2,C09CompleteStreamV2,C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2
        from ..authority_service.c09_paged_recovery_facts_v2 import C09HistoricalSealedStreamReaderV2
        row=self.meter.read_row(self.db,self.directory_shape,record.primary_key)
        if row is None or _row_digest(tuple(row))!=record.commitment:raise C09PagedCaptureHold('prior signed directory row commitment differs')
        fields=('schema_catalogue','disposition_directory','closure','tombstones','target_directory','generated_directory')
        field=fields[self.directory_index];value=dict(zip(self.directory_shape.columns,row,strict=True))
        if field in {'disposition_directory','target_directory'}:
            identity=c09_paged_value_from_wire_v2(json.loads(value['identity_json']),C09StreamIdentityV2)
            complete=c09_paged_value_from_wire_v2(json.loads(value['complete_json']),C09CompleteStreamV2)
            locator=C09SealedStreamLocatorV2('graph',identity,complete)
            from dataclasses import asdict
            from ..authority_service.c09_paged_recovery_facts_v2 import _read_one
            args=(self.session.scope.scope_digest,self.operation,identity.stream_kind,identity.family)
            values=(*args,canonical_serialize(asdict(identity)),canonical_serialize(asdict(complete)),canonical_serialize(record.primary_key),
                self.directory_reader.cursor.record_offset+self.directory_reader.index+1,record.commitment)
            old=_read_one(self.pair.candidate,'SELECT scope_digest,certificate_operation_id,stream_kind,family,identity_json,complete_json,outer_primary_key_json,outer_record_ordinal,outer_row_commitment FROM c09_prior_graph_streams_v2 WHERE scope_digest=? AND certificate_operation_id=? AND stream_kind=? AND family=?',args,self.meter)
            if old is None:
                if self.read_only:raise C09PagedCaptureHold('independent prior paged directory metadata member is absent')
                from .c09_paged_sql_v2 import _sql_scalar_size_v2
                self.meter.charge_write(sum(_sql_scalar_size_v2(x) for x in values))
                self.pair.candidate.execute('INSERT INTO c09_prior_graph_streams_v2 VALUES (?,?,?,?,?,?,?,?,?)',values)
            elif old!=values:raise C09PagedCaptureHold('prior paged directory index differs from actual signed source member')
            self.stream_count+=1
            self.nested_locator=locator;self.nested_reader=C09HistoricalSealedStreamReaderV2(locator)
        elif field=='schema_catalogue':
            ddl=self.meter.read_fixed_row(self.db,'sqlite_master',('sql',),'type=? AND name=?',(value['object_type'],value['object_name']))
            if ddl!=(value['target_sql'],):raise C09PagedCaptureHold('prior actual schema descriptor differs')
        elif field=='generated_directory':
            shape=read_c09_table_shape_v2(self.db,value['table_name']);key=tuple(json.loads(value['key_json']))
            target=self.meter.read_row(self.db,shape,key)
            if target is None or _row_digest(tuple(target))!=value['row_commitment']:raise C09PagedCaptureHold('prior actual generated row commitment differs')
        elif field=='closure' and value['scope_digest']!=self.certificate.candidate.scope.scope_digest:
            raise C09PagedCaptureHold('prior closure directory has another actual scope')

    def _nested_member(self,record):
        from .c09_graph_rebase_candidate_v1 import _row_digest
        locator=self.nested_locator;shape=read_c09_table_shape_v2(self.db,locator.identity.family)
        self._require_shape(locator,shape)
        if locator.identity.stream_kind=='row_dispositions':
            from .c09_graph_rebase_candidate_v2 import _read_graph_disposition_original_row_v3
            row=_read_graph_disposition_original_row_v3(self.db,self.certificate.candidate.scope.scope_digest,
                shape.table,record.primary_key,self.meter)
            if row is None or tuple(json.loads(row[3]))!=record.primary_key:raise C09PagedCaptureHold('prior signed disposition metadata has another actual business key')
            if len(row)==13:
                from .c09_historical_logical_source_v3 import require_historical_logical_graph_disposition_v3
                anchor=self.session.require_historical_capture_scope_v2(self.certificate.candidate.scope.scope_digest)
                require_historical_logical_graph_disposition_v3(self.session,self.pair,anchor,row,meter=self.meter)
            else:
                from .c09_storage_rebase_contract_v1 import GraphRowDispositionV1
                GraphRowDispositionV1(row[2],row[4],row[5],row[6])
        elif locator.identity.stream_kind=='target_rows':
            # This is immutable historical snapshot evidence. Normal subsequent
            # business may change mutable targets; current qualification is a
            # separate full-source sweep. Point retention still checks the
            # specific current row against this signed target member.
            return
        else:raise C09PagedCaptureHold('prior directory contains an unknown nested stream kind')
        if row is None or _row_digest(tuple(row))!=record.commitment:raise C09PagedCaptureHold('prior actual nested signed stream member differs')


    def _advance_disposition_inventory_v3(self,meter):
        """One physical metadata row per quantum; complete both versions before EOF."""
        from .c09_graph_rebase_candidate_v2 import (GRAPH_DISPOSITION_COLUMNS_V2,GRAPH_DISPOSITION_COLUMNS_V3,
            _read_graph_disposition_original_row_v3)
        from .c09_paged_sql_v2 import c09_row_commitment_v2,require_c09_capture_member_v2
        version=self.inventory_version_v3;table=('c09_graph_dispositions_v2','c09_graph_dispositions_v3')[version]
        columns=(GRAPH_DISPOSITION_COLUMNS_V2,GRAPH_DISPOSITION_COLUMNS_V3)[version]
        locator=self.inventory_locator_v3
        present=meter.read_fixed_row(self.db,'sqlite_master',('name',),'type=? AND name=?',('table',table))
        row=None if present is None else meter.read_fixed_row(self.db,table,columns,
            'scope_digest=? AND table_name=? AND key_digest>? ORDER BY key_digest',
            (self.certificate.candidate.scope.scope_digest,locator.identity.family,self.inventory_after_v3))
        if row is None:
            if version==0:self.inventory_version_v3=1;self.inventory_after_v3='';return False
            if self.inventory_count_v3!=locator.complete.record_count:
                raise C09PagedCaptureHold('prior signed disposition two-version metadata/member EOF count differs')
            return True
        key=tuple(json.loads(row[3]))
        actual=_read_graph_disposition_original_row_v3(self.db,self.certificate.candidate.scope.scope_digest,
            locator.identity.family,key,meter)
        if actual!=tuple(row):raise C09PagedCaptureHold('prior disposition duplicate version or full primary key differs')
        member=meter.read_fixed_row(self.db,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND primary_key_json=?',(locator.identity.stream_id,canonical_serialize(key)))
        if member is None or member[1]!=c09_row_commitment_v2(tuple(row)):
            raise C09PagedCaptureHold('extra prior disposition outside its signed complete stream')
        require_c09_capture_member_v2(self.db,locator.identity,member[0],key,member[1],meter=meter)
        if version==1:
            from .c09_historical_logical_source_v3 import require_historical_logical_graph_disposition_v3
            anchor=self.session.require_historical_capture_scope_v2(self.certificate.candidate.scope.scope_digest)
            require_historical_logical_graph_disposition_v3(self.session,self.pair,anchor,tuple(row),meter=meter)
        self.inventory_after_v3=row[2];self.inventory_count_v3+=1
        if self.inventory_count_v3>locator.complete.record_count:raise C09PagedCaptureHold('prior disposition inventory has extra records')
        return False


class VerifiedPagedPriorGraphCertificateViewV2:
    __slots__=('_token','reader','certificate_schema','certificate_digest')
    def __init__(self,token,reader):
        if token is not _PRIOR_VIEW_TOKEN_V2 or reader.complete_directories!=6:raise TypeError('actual prior complete paged view required')
        self._token=token;self.reader=reader;self.certificate_schema=reader.certificate.schema;self.certificate_digest=reader.certificate.digest

    def require_row_disposition(self,table,primary_key,old_commitment,*,meter):
        return self._require_disposition(table,primary_key,old_commitment,meter=meter,target=False)

    def require_target_row_disposition(self,table,primary_key,new_commitment,*,meter):
        return self._require_disposition(table,primary_key,new_commitment,meter=meter,target=True)

    def _require_disposition(self,table,primary_key,commitment,*,meter,target):
        from .c09_storage_rebase_contract_v1 import GraphRowDispositionV1
        r=self.reader;r.session.require_current();r.pair.require_current()
        key=canonical_digest((table,primary_key));meter.charge_encode(len(canonical_serialize((table,primary_key)).encode()))
        from .c09_graph_rebase_candidate_v2 import _read_graph_disposition_original_row_v3
        row=_read_graph_disposition_original_row_v3(r.pair.source,r.certificate.candidate.scope.scope_digest,table,primary_key,meter)
        if row is None or row[6 if target else 4]!=commitment or tuple(json.loads(row[3]))!=primary_key:raise C09PagedCaptureHold('prior exact row is outside its signed disposition')
        self._require_signed_disposition_member(table,primary_key,meter)
        if len(row)==13:
            from .c09_historical_logical_source_v3 import require_historical_logical_graph_disposition_v3
            anchor=r.session.require_historical_capture_scope_v2(r.certificate.candidate.scope.scope_digest)
            return require_historical_logical_graph_disposition_v3(r.session,r.pair,anchor,row,meter=meter)
        return GraphRowDispositionV1(row[2],row[4],row[5],row[6])

    def require_generated_erased_key_v3(self,token,tombstone,*,meter):
        """First generated tombstones use their actual signed generated directory."""
        from .c09_paged_sql_v2 import require_c09_capture_member_v2,c09_row_commitment_v2
        r=self.reader;r.session.require_current();r.pair.require_current()
        if r.complete_directories!=6:raise C09PagedCaptureHold('actual historical complete generated directory required')
        scope=r.certificate.candidate.scope
        ns=tuple(json.loads(scope.graph_namespace));pk=(*ns,canonical_digest(token))
        if tombstone!=(*pk,scope.maintenance_generation,scope.operation_id):
            raise C09PagedCaptureHold('historical generated tombstone has another original namespace/generation/operation')
        columns=('scope_digest','table_name','key_digest','key_json','row_commitment','producer','origin_ref','origin_digest')
        key=(scope.scope_digest,'graph_c09_erased_keys_v1',canonical_digest(('graph_c09_erased_keys_v1',pk)))
        row=meter.read_fixed_row(r.pair.source,'c09_graph_generated_rows_v2',columns,
            'scope_digest=? AND table_name=? AND key_digest=?',key)
        if (row is None or row[3]!=canonical_serialize(pk) or row[4]!=c09_row_commitment_v2(tombstone)
                or row[5:7]!=('c09_erased_key_v2',token)):
            raise C09PagedCaptureHold('historical first tombstone lost its actual generated original')
        locator=r.certificate.candidate.generated_directory
        member=meter.read_fixed_row(r.pair.source,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND primary_key_json=?',(locator.identity.stream_id,canonical_serialize(key)))
        if member is None or member[1]!=c09_row_commitment_v2(row):
            raise C09PagedCaptureHold('historical generated tombstone is outside actual signed directory')
        require_c09_capture_member_v2(r.pair.source,locator.identity,member[0],key,member[1],meter=meter)
        closure=meter.read_fixed_row(r.pair.source,'c09_closure_members_v2',('origin_commitment',),
            'scope_digest=? AND kind=? AND ref=?',(scope.scope_digest,'atom',token))
        if closure!=(row[7],):raise C09PagedCaptureHold('historical generated tombstone lost its exact closure origin')
        return {'generated_member_commitment':member[1],'generated_directory_digest':locator.complete.digest}

    def _require_signed_disposition_member(self,table,primary_key,meter):
        from .c09_paged_capture_contract_v2 import C09StreamIdentityV2,C09CompleteStreamV2,c09_paged_value_from_wire_v2
        from .c09_paged_sql_v2 import require_c09_capture_member_v2
        from ..authority_service.c09_paged_recovery_facts_v2 import _read_one
        from .c09_graph_rebase_candidate_v1 import _row_digest
        r=self.reader
        saved=_read_one(r.pair.candidate,'SELECT identity_json,complete_json,outer_primary_key_json,outer_record_ordinal,outer_row_commitment FROM c09_prior_graph_streams_v2 WHERE scope_digest=? AND certificate_operation_id=? AND stream_kind=? AND family=?',(r.session.scope.scope_digest,r.operation,'row_dispositions',table),meter)
        if saved is None:raise C09PagedCaptureHold('prior point disposition lacks its actual verified directory membership')
        outer=r.certificate.candidate.disposition_directory
        require_c09_capture_member_v2(r.pair.source,outer.identity,saved[3],tuple(json.loads(saved[2])),saved[4],meter=meter)
        shape=read_c09_table_shape_v2(r.pair.source,outer.identity.family)
        directory=meter.read_row(r.pair.source,shape,tuple(json.loads(saved[2])))
        if directory is None or _row_digest(tuple(directory))!=saved[4]:raise C09PagedCaptureHold('prior point directory row changed')
        values=dict(zip(shape.columns,directory,strict=True))
        if values['identity_json']!=saved[0] or values['complete_json']!=saved[1]:raise C09PagedCaptureHold('prior point nested locator differs from actual signed directory')
        identity=c09_paged_value_from_wire_v2(json.loads(saved[0]),C09StreamIdentityV2)
        complete=c09_paged_value_from_wire_v2(json.loads(saved[1]),C09CompleteStreamV2)
        member=_read_one(r.pair.source,'SELECT record_ordinal,commitment FROM c09_capture_members_v2 WHERE stream_id=? AND key_digest=?',(identity.stream_id,canonical_digest(primary_key)),meter)
        if member is None or not 1<=member[0]<=complete.record_count:raise C09PagedCaptureHold('prior disposition is outside its complete signed nested stream')
        from .c09_graph_rebase_candidate_v2 import _read_graph_disposition_original_row_v3
        raw=_read_graph_disposition_original_row_v3(r.pair.source,r.certificate.candidate.scope.scope_digest,table,primary_key,meter)
        if raw is None or _row_digest(tuple(raw))!=member[1]:raise C09PagedCaptureHold('prior exact disposition metadata is outside its signed record commitment')
        require_c09_capture_member_v2(r.pair.source,identity,member[0],primary_key,member[1],meter=meter)


    def require_generated_world_erasure_barrier_v1(self,primary_key,barrier,*,meter):
        """Verify the first barrier in the actual signed six-directory prior output."""
        from .d03_world_history_v1 import ERASURE_TABLE,ERASURE_COLUMNS,ERASURE_SIGN_KIND,decode_world_erasure_barrier_row_v1,TABLE
        from .c09_paged_sql_v2 import require_c09_capture_member_v2,c09_row_commitment_v2
        r=self.reader;r.session.require_current();r.pair.require_current()
        if r.complete_directories!=6:
            raise C09PagedCaptureHold('World prior generated barrier lacks complete six-directory verification')
        scope=r.certificate.candidate.scope
        value=decode_world_erasure_barrier_row_v1(ERASURE_COLUMNS,barrier)
        if (value.namespace.as_tuple!=tuple(json.loads(scope.graph_namespace))
                or primary_key!=tuple(barrier[:4])
                or value.deletion_generation!=scope.maintenance_generation
                or value.delete_original_commitment!=scope.accepted_receipt_digest):
            raise C09PagedCaptureHold('World prior generated barrier has another actual deletion original')
        issuer=r.session.get_c09_domain_original_issuer_v2()
        issuer._signer.verify(ERASURE_SIGN_KIND,barrier[8],barrier[10])
        columns=('scope_digest','table_name','key_digest','key_json','row_commitment','producer','origin_ref','origin_digest')
        key=(scope.scope_digest,ERASURE_TABLE,canonical_digest((ERASURE_TABLE,primary_key)))
        row=meter.read_fixed_row(r.pair.source,'c09_graph_generated_rows_v2',columns,
            'scope_digest=? AND table_name=? AND key_digest=?',key)
        if (row is None or row[3]!=canonical_serialize(primary_key)
                or row[4]!=c09_row_commitment_v2(barrier) or row[5]!='world_erasure_barrier_v1'):
            raise C09PagedCaptureHold('World prior generated barrier lost its exact generated original')
        directory=r.certificate.candidate.generated_directory
        member=meter.read_fixed_row(r.pair.source,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND primary_key_json=?',(directory.identity.stream_id,canonical_serialize(key)))
        if member is None or member[1]!=c09_row_commitment_v2(row):
            raise C09PagedCaptureHold('World prior generated barrier is outside the signed complete directory')
        require_c09_capture_member_v2(r.pair.source,directory.identity,member[0],key,member[1],meter=meter)
        origin=json.loads(row[6])
        if (type(origin)is not dict or set(origin)!={'schema','stream_id','ordinal'}
                or origin['schema']!='sylanne3.c09.world-erasure-origin.v1'
                or type(origin['stream_id'])is not str or type(origin['ordinal'])is not int or origin['ordinal']<0
                or canonical_serialize(origin)!=row[6]):
            raise C09PagedCaptureHold('World prior generated barrier opaque origin differs')
        stream_row=meter.read_fixed_row(r.pair.source,'c09_capture_streams_v2',('identity_json','status'),
            'stream_id=?',(origin['stream_id'],))
        if stream_row is None or stream_row[1]!='sealed':
            raise C09PagedCaptureHold('World prior barrier source origin is not sealed')
        from .c09_paged_capture_contract_v2 import C09StreamIdentityV2,c09_paged_value_from_wire_v2
        stream=c09_paged_value_from_wire_v2(json.loads(stream_row[0]),C09StreamIdentityV2)
        if (stream.stream_id!=origin['stream_id'] or stream.scope_digest!=scope.scope_digest
                or stream.stream_kind!='graph_facts' or stream.family!=TABLE):
            raise C09PagedCaptureHold('World prior barrier source origin has another scope/family')
        captured=meter.read_fixed_row(r.pair.source,'c09_capture_members_v2',('primary_key_json','commitment'),
            'stream_id=? AND record_ordinal=?',(stream.stream_id,origin['ordinal']))
        if captured is None or captured[1]!=row[7]:
            raise C09PagedCaptureHold('World prior barrier exact source commitment differs')
        original_key=tuple(json.loads(captured[0]))
        require_c09_capture_member_v2(r.pair.source,stream,origin['ordinal'],original_key,row[7],meter=meter)
        r.session.require_current();r.pair.require_current()
        return {'generated_member_commitment':member[1],'generated_directory_digest':directory.complete.digest}


def require_c09_erased_derived_fact_v2(db,table,columns,row,*,namespace,key,revision,view,meter):
    """Exact retained fact and erased history target inside a completed prior view."""
    from .c09_graph_rebase_candidate_v1 import _row_digest
    historical=type(view) in {VerifiedPriorGraphCertificateViewV2,VerifiedPagedPriorGraphCertificateViewV2}
    if not historical:
        from .c09_graph_rebase_candidate_v2 import VerifiedC09SourceDispositionV2
        if type(view) is not VerifiedC09SourceDispositionV2:raise C09PagedCaptureHold('actual qualified Source-disposition or completed historical view required')
        if tuple(json.loads(view.scope.graph_namespace))!=namespace.as_tuple:raise C09PagedCaptureHold('qualified source-disposition view crossed its actual namespace')
    if table not in {'graph_d13_derived_activations_v6','graph_d13_wire_evidence_v6','graph_d13_core_wire_evidence_v1'}:
        raise C09PagedCaptureHold('erased metadata cannot qualify a derived payload BLOB')
    token_digest=canonical_digest(key.token);meter.charge_encode(len(canonical_serialize(key.token).encode()))
    marker=meter.read_fixed_row(db,'graph_c09_erased_keys_v1',('maintenance_generation','operation_id'),
        'bot=? AND persona=? AND key_digest=?',(*namespace.as_tuple,token_digest))
    if historical:
        r=view.reader
        generation=r.header['maintenance_generation'] if type(view) is VerifiedPriorGraphCertificateViewV2 else r.certificate.candidate.scope.maintenance_generation
        operation=r.operation
        require_target=view.require_target_row_disposition
    else:
        generation=view.scope.maintenance_generation;operation=view.scope.operation_id
        require_target=view.require_generated_retained_row
    if marker!=(generation,operation):raise C09PagedCaptureHold('retained fact erased marker is outside its actual qualified generation')
    history_shape=read_c09_table_shape_v2(db,'graph_history')
    history=meter.read_row(db,history_shape,(key.token,revision))
    if history is None:raise C09PagedCaptureHold('retained fact lost its exact historical metadata revision')
    value=dict(zip(history_shape.columns,history,strict=True))
    if value['valid']!=0 or value['dependencies']!='[]' or json.loads(value['value'])!={'schema':'sylanne3.graph.erased_value.v1','key_digest':token_digest}:
        raise C09PagedCaptureHold('retained fact metadata is not its exact content-free erased history')
    from .domain_production_erasure_v1 import _derived_fact_primary_key_v6
    data=dict(zip(columns,row,strict=True));pk=_derived_fact_primary_key_v6(table)
    fact_hash=_row_digest(tuple(row));history_hash=_row_digest(tuple(history))
    fact=require_target(table,tuple(data[name] for name in pk),fact_hash,meter=meter)
    archived=require_target('graph_history',(key.token,revision),history_hash,meter=meter)
    if (fact.disposition!='preserved_exact' or fact.old_commitment!=fact_hash or fact.new_commitment!=fact_hash
            or archived.disposition!='payload_erased_retained_facts' or archived.new_commitment!=history_hash):
        raise C09PagedCaptureHold('retained actual fact/history is outside its pre-erasure qualified target commitments')
    return True
