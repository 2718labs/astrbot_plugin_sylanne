"""Shared immutable segmented SQL cells, selected only by installed storage owners.

Cell references, headers and progress DTOs carry integrity commitments. They
never grant Owner/Source/storage admission. C09 targets derive from actual
protected capture session/role pairs and their signed layout transition.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from time import monotonic_ns
from .authority_service.contract import AuthorityUnavailable
from .runtime.c09_paged_sql_v2 import (C09SqlByteMeterV2,current_c09_sql_meter_v2,
    capture_transaction_v2,capture_read_transaction_v2,c09_sql_meter_quantum_v2,_sql_scalar_size_v2,
    canonical_digest,canonical_serialize)

MAX_SEGMENT_BYTES=16384
LAYOUT_SCHEMA='sylanne3.segmented-storage-layout.v1'
TRANSITION_SCHEMA='sylanne3.segmented-storage-transition.v1'
_TARGET=object()
_QUANTUM=object()
_SEALED=object()
CODECS=frozenset({'canonical-json.ascii.v1','canonical-json.utf8.v1','opaque-bytes.v1'})
LAYOUTS={'graph':'graph-storage.v3','core':'authority-source-storage.v2',
    'deletion':'authority-source-storage.v2','execution':'authority-source-storage.v2'}
DDLS={
 'segmented_storage_layout_v1':"""CREATE TABLE segmented_storage_layout_v1 (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema TEXT NOT NULL,
    storage_instance_id TEXT NOT NULL,role TEXT NOT NULL,layout_id TEXT NOT NULL,
    layout_schema_digest TEXT NOT NULL,authority_id TEXT NOT NULL,authority_namespace TEXT NOT NULL,
    installation_id TEXT NOT NULL,storage_generation INTEGER NOT NULL,origin_scope_digest TEXT NOT NULL) STRICT""",
 'segmented_cells_v1':"""CREATE TABLE segmented_cells_v1 (
    cell_id TEXT PRIMARY KEY,codec_id TEXT NOT NULL,erasure_owner_ref TEXT NOT NULL,
    producer_operation_id TEXT NOT NULL,total_bytes INTEGER NOT NULL CHECK(total_bytes>=0),
    segment_count INTEGER NOT NULL CHECK(segment_count>=0),payload_sha256 TEXT NOT NULL,
    ordered_segment_root TEXT NOT NULL,origin_scope_digest TEXT NOT NULL) STRICT""",
 'segmented_cell_segments_v1':"""CREATE TABLE segmented_cell_segments_v1 (
    cell_id TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0),
    byte_offset INTEGER NOT NULL CHECK(byte_offset>=0),payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 16384),
    payload_sha256 TEXT NOT NULL,PRIMARY KEY(cell_id,ordinal)) STRICT""",
 'segmented_cell_writes_v1':"""CREATE TABLE segmented_cell_writes_v1 (
    cell_id TEXT PRIMARY KEY,origin_scope_digest TEXT NOT NULL,logical_locator_json TEXT NOT NULL,
    codec_id TEXT NOT NULL,producer_operation_id TEXT NOT NULL,erasure_owner_ref TEXT NOT NULL,
    phase TEXT NOT NULL,next_ordinal INTEGER NOT NULL,next_byte_offset INTEGER NOT NULL,
    prefix_root TEXT NOT NULL,prefix_sha256 TEXT NOT NULL,source_cursor_json TEXT NOT NULL,
    expected_total_bytes INTEGER NOT NULL,verify_next_ordinal INTEGER NOT NULL,
    verify_next_byte_offset INTEGER NOT NULL,verify_prefix_root TEXT NOT NULL,
    verify_prefix_sha256 TEXT NOT NULL,cursor_revision INTEGER NOT NULL) STRICT""",
}
GRAPH_REF_DDLS_V3={
 'graph_atoms':"""CREATE TABLE graph_atoms (
    token TEXT PRIMARY KEY,bot TEXT NOT NULL,persona TEXT NOT NULL,owner_kind TEXT NOT NULL,
    subject TEXT,type_name TEXT NOT NULL,name TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0),
    value_cell_id TEXT NOT NULL REFERENCES segmented_cells_v1(cell_id),valid INTEGER NOT NULL CHECK(valid IN (0,1)))""",
 'graph_history':"""CREATE TABLE graph_history (
    token TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0),
    value_cell_id TEXT NOT NULL REFERENCES segmented_cells_v1(cell_id),valid INTEGER NOT NULL CHECK(valid IN (0,1)),
    dependencies TEXT NOT NULL,event_bot TEXT NOT NULL,event_persona TEXT NOT NULL,event_session TEXT NOT NULL,event_id TEXT NOT NULL,
    PRIMARY KEY(token,revision),FOREIGN KEY(event_bot,event_persona,event_session,event_id)
    REFERENCES graph_events(bot,persona,session,event_id))""",
 'graph_d09_turn_slot_origins_v3':"""CREATE TABLE graph_d09_turn_slot_origins_v3 (
    token TEXT PRIMARY KEY REFERENCES graph_atoms(token),bot TEXT NOT NULL,persona TEXT NOT NULL,origin_ref TEXT NOT NULL) STRICT""",
}
CORE_REF_DDLS_V2={
 'authority_d13_counter_originals_v1':"""CREATE TABLE authority_d13_counter_originals_v1 (
    namespace TEXT NOT NULL,counter_operation_id TEXT NOT NULL,phase TEXT NOT NULL,
    payload_cell_id TEXT NOT NULL REFERENCES segmented_cells_v1(cell_id),payload_digest TEXT NOT NULL,
    PRIMARY KEY(namespace,counter_operation_id,phase)) STRICT""",
 'authority_d13_provider_http_bindings_v1':"""CREATE TABLE authority_d13_provider_http_bindings_v1 (
    namespace TEXT NOT NULL,call_id TEXT NOT NULL,phase TEXT NOT NULL,
    payload_cell_id TEXT NOT NULL REFERENCES segmented_cells_v1(cell_id),payload_digest TEXT NOT NULL,
    PRIMARY KEY(namespace,call_id,phase)) STRICT""",
}

GRAPH_REF_INDEXES_V3={
 'graph_d09_turn_slot_origin_v3':"CREATE INDEX graph_d09_turn_slot_origin_v3 ON graph_d09_turn_slot_origins_v3(bot,persona,origin_ref)",
}
TRIGGERS={}
for table in ('segmented_storage_layout_v1','segmented_cells_v1','segmented_cell_segments_v1'):
    for action in ('UPDATE','DELETE'):
        name=table+'_no_'+action.lower()
        TRIGGERS[name]=f"CREATE TRIGGER {name} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'segmented original is immutable'); END"
LAYOUT_SCHEMA_DIGEST=canonical_digest({'schema':LAYOUT_SCHEMA,'tables':DDLS,'triggers':TRIGGERS,
    'graph_ref_tables':GRAPH_REF_DDLS_V3,'graph_ref_indexes':GRAPH_REF_INDEXES_V3,'core_ref_tables':CORE_REF_DDLS_V2,
    'segment_bytes':MAX_SEGMENT_BYTES,'codecs':sorted(CODECS)})


@dataclass(frozen=True,slots=True)
class SegmentedCellRefV1:
    cell_id:str
    codec_id:str
    total_bytes:int
    segment_count:int
    payload_sha256:str
    ordered_segment_root:str
    origin_scope_digest:str
    schema:str='sylanne3.segmented-cell-ref.v1'
    def __post_init__(self):
        if self.schema!='sylanne3.segmented-cell-ref.v1' or self.codec_id not in CODECS:
            raise ValueError('registered segmented cell reference required')
        if type(self.total_bytes) is not int or self.total_bytes<0 or type(self.segment_count) is not int or self.segment_count<0:
            raise ValueError('actual segmented length and count required')
        for name in ('cell_id','payload_sha256','ordered_segment_root','origin_scope_digest'):
            value=getattr(self,name)
            if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
                raise ValueError('exact segmented SHA256 commitment required')


class _SegmentedQuantumV1:
    __slots__=('issuer','target','budget','meter','started_ns','completed','records','mutations')
    def __init__(self,token,target,budget,meter):
        if token is not _QUANTUM:raise AuthorityUnavailable('actual segmented storage quantum required')
        self.issuer,self.target,self.budget,self.meter,self.started_ns=token,target,budget,meter,monotonic_ns()
        self.completed=False;self.records=0;self.mutations=0
    def require_current(self,target):
        target.require_current()
        if (self.issuer is not _QUANTUM or self.target is not target
                or current_c09_sql_meter_v2() is not self.meter or self.meter.budget is not self.budget):
            raise AuthorityUnavailable('segmented storage quantum crossed actual scope or reservation')


    def read_one(self,db,sql,args=(),*,max_row_bytes=16384):
        self.require_current(self.target)
        if self.records>=self.budget.max_records:
            raise AuthorityUnavailable('segmented quantum reached unchanged record limit')
        statement_bytes=len(sql.encode('utf-8'))+sum(_sql_scalar_size_v2(v) for v in args)
        self.meter.require_available(statement_bytes+max_row_bytes)
        self.meter.charge_encode(statement_bytes)
        row=db.execute(sql,args).fetchone()
        actual=0 if row is None else sum(_sql_scalar_size_v2(v) for v in row)
        if actual>max_row_bytes:raise AuthorityUnavailable('segmented point read exceeds registered descriptor bound')
        self.meter.charge_read(actual);self.records+=1
        return row
    def read_descriptor(self,db,table,columns,where,args,limits):
        """Fixed producer point lookup bounds TEXT before crossing into Python."""
        from .runtime.c09_paged_sql_v2 import _quote
        if len(columns)!=len(limits):raise ValueError('fixed descriptor columns and bounds differ')
        projections=[]
        for name,limit in zip(columns,limits):
            quoted=_quote(name)
            projections.append('CASE WHEN '+quoted+' IS NULL THEN NULL WHEN length('+quoted+')<='
                +str(limit)+' THEN '+quoted+' ELSE NULL END')
        row=self.read_one(db,'SELECT '+','.join(projections)+' FROM '+_quote(table)+' WHERE '+where+' LIMIT 1',
            args,max_row_bytes=sum(limits)*4)
        if row is not None and any(_sql_scalar_size_v2(v)>limit for v,limit in zip(row,limits)):
            raise AuthorityUnavailable('actual SQL descriptor exceeds registered byte bound')
        return row
    def read_cursor(self,db,cell_id):
        columns=('cell_id','origin_scope_digest','logical_locator_json','codec_id','producer_operation_id',
            'erasure_owner_ref','phase','next_ordinal','next_byte_offset','prefix_root','prefix_sha256',
            'source_cursor_json','expected_total_bytes','verify_next_ordinal','verify_next_byte_offset',
            'verify_prefix_root','verify_prefix_sha256','cursor_revision')
        limits=(64,64,8192,64,256,8192,32,32,32,64,64,128,32,32,32,64,64,32)
        row=self.read_descriptor(db,'segmented_cell_writes_v1',columns,'cell_id=?',(cell_id,),limits)
        if row is not None and any(value is None for value in row):
            raise AuthorityUnavailable('actual segmented cursor descriptor is missing or exceeds bounds')
        return row
    def read_header(self,db,cell_id):
        columns=('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes',
            'segment_count','payload_sha256','ordered_segment_root','origin_scope_digest')
        limits=(64,64,8192,256,32,32,64,64,64)
        row=self.read_descriptor(db,'segmented_cells_v1',columns,'cell_id=?',(cell_id,),limits)
        if row is not None and any(value is None for value in row):
            raise AuthorityUnavailable('actual segmented header descriptor is missing or exceeds bounds')
        return row
    def mutate(self,db,sql,args=()):
        self.require_current(self.target)
        if not db.in_transaction:raise AuthorityUnavailable('segmented mutation requires actual transaction')
        if self.mutations>=64:raise AuthorityUnavailable('segmented quantum reached unchanged ordinary-write limit')
        amount=sum(_sql_scalar_size_v2(v) for v in args)
        encoded=amount+len(sql.encode('utf-8'))
        self.meter.require_available(amount+encoded)
        self.meter.charge_encode(encoded);self.meter.charge_write(amount)
        result=db.execute(sql,args);self.mutations+=1
        return result


class InstalledSegmentedTargetV1:
    __slots__=('_issuer','session','pair','transition','storage_instance_id')
    def __init__(self,token,session,pair,transition):
        if token is not _TARGET:raise AuthorityUnavailable('installed segmented target factory required')
        self._issuer,self.session,self.pair,self.transition=token,session,pair,transition
        self.storage_instance_id=canonical_digest({'schema':'sylanne3.segmented-storage-instance.v1',
            'scope':session.scope.scope_digest,'role':pair.source_original.role,'target_identity':pair.target_identity})
    def require_current(self):
        if self._issuer is not _TARGET:raise AuthorityUnavailable('segmented target instance changed')
        self.session.require_current();self.pair.require_current()
        actual=self.session.require_segmented_storage_transition_v1()
        if actual!=self.transition or self.pair._producer.session is not self.session:
            raise AuthorityUnavailable('segmented target transition or actual role session changed')
    @contextmanager
    def quantum(self):
        self.require_current()
        with self.session.reserve_batch() as budget:
            from .runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3
            meter=require_c09_reserved_meter_v3(budget)
            with c09_sql_meter_quantum_v2(meter):
                q=_SegmentedQuantumV1(_QUANTUM,self,budget,meter)
                yield q
                q.require_current(self)
        # The actual reservation's exit checks must succeed before qualification.
        q.completed=True
    def begin_cell_copy(self,q,*,table,primary_key,column):
        """Copy one registered frozen logical value; locator grants no new access."""
        q.require_current(self)
        registered={'graph':{'graph_atoms':'value','graph_history':'value'},
            'core':{'authority_d13_counter_originals_v1':'payload_json','authority_d13_provider_http_bindings_v1':'payload_json'}}
        role=self.pair.source_original.role
        codec_id='canonical-json.ascii.v1'
        if table not in registered.get(role,{}) or registered[role][table]!=column:
            raise AuthorityUnavailable('segmented logical family/column requires its registered codec')
        from .runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2,_quote
        source=self.pair.source
        with legacy_cell_read_transaction_v2(source):
            shape=read_c09_table_shape_v2(source,table,meter=q.meter)
            if type(primary_key) is not tuple or len(primary_key)!=len(shape.primary_key_columns):
                raise AuthorityUnavailable('actual registered logical primary key required')
            expected_types={'text':str,'integer':int}
            if (any(type(value) is not expected_types[kind] for value,kind in zip(primary_key,shape.primary_key_types))
                    or sum(_sql_scalar_size_v2(value) for value in primary_key)>8192):
                raise AuthorityUnavailable('actual logical primary key exceeds registered type or descriptor bound')
            from .runtime_contracts import NamespaceId,namespace_ref
            maintenance=self.session._control.maintenance
            namespace=maintenance.namespace_id
            if (type(namespace) is not NamespaceId
                    or canonical_serialize(namespace.as_tuple)!=self.session.scope.graph_namespace
                    or namespace_ref(namespace)!=self.session.scope.authority_namespace
                    or self.session.scope.authority_namespace!=maintenance.closure.namespace):
                raise AuthorityUnavailable('segmented source namespace differs from actual installed maintenance')
            where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in shape.primary_key_columns)
            if role=='graph':
                from .graph_types import AtomKey
                key=AtomKey.from_token(primary_key[0])
                if (key.owner.bot,key.owner.persona)!=namespace.as_tuple:
                    raise AuthorityUnavailable('segmented logical source crosses actual Graph namespace')
                if table=='graph_atoms':
                    actual=q.read_descriptor(source,'graph_atoms',('bot','persona','owner_kind','subject','type_name','name','revision','valid'),
                        'token=?',primary_key,(8192,8192,64,8192,8192,8192,32,1))
                    expected=(key.owner.bot,key.owner.persona,key.owner.kind,key.owner.subject,key.type_name,key.name)
                    if (actual is None or actual[:6]!=expected or type(actual[6]) is not int or actual[6]<1
                            or type(actual[7]) is not int or actual[7] not in (0,1)):
                        raise AuthorityUnavailable('actual graph atom identity or revision differs from canonical logical key')
                else:
                    actual=q.read_descriptor(source,'graph_history',('revision','valid','event_bot','event_persona','event_session','event_id'),
                        'token=? AND revision=?',primary_key,(32,1,8192,8192,8192,8192))
                    if (actual is None or type(primary_key[1]) is not int or primary_key[1]<1
                            or actual[0]!=primary_key[1] or type(actual[1]) is not int or actual[1] not in (0,1)
                            or actual[2:4]!=namespace.as_tuple
                            or any(type(v) is not str or not v for v in actual[4:])):
                        raise AuthorityUnavailable('actual graph history identity or revision differs from canonical logical key')
                    event=q.read_one(source,'SELECT 1 FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?',actual[2:])
                    if event!=(1,):raise AuthorityUnavailable('actual graph history lacks its original event foreign key')
                erasure_owner_ref=key.token
            else:
                if primary_key[0]!=self.session.scope.authority_namespace:
                    raise AuthorityUnavailable('segmented logical source crosses actual Core authority namespace')
                if type(primary_key[1]) is not str or not primary_key[1]:
                    raise AuthorityUnavailable('actual Core original operation or call identity required')
                if table=='authority_d13_counter_originals_v1':
                    if primary_key[2] not in ('draft','header','evidence'):
                        raise AuthorityUnavailable('unknown D13 counter original phase')
                    family='d13-counter-source' if primary_key[2]=='draft' else 'd13-counter-history'
                else:
                    if primary_key[2] not in ('expected','observed_before_send'):
                        raise AuthorityUnavailable('unknown D13 provider HTTP original phase')
                    family='d13-provider-http-history'
                erasure_owner_ref=canonical_serialize((family,primary_key[0],primary_key[1]))
            if len(erasure_owner_ref.encode('utf-8'))>8192:
                raise AuthorityUnavailable('actual derived erasure owner exceeds registered descriptor bound')
            _,total,kind=read_legacy_sql_cell_fragment_v2(source,table=table,column=column,where=where,
                parameters=primary_key,start=0,length=0,meter=q.meter)
        if kind!='text' or codec_id=='opaque-bytes.v1':
            raise AuthorityUnavailable('registered source family has canonical JSON text, not opaque bytes')
        locator={'role':role,'family':table,'primary_key':primary_key,'column':column,'source_schema_digest':shape.schema_digest}
        locator_json=canonical_serialize(locator)
        if len(locator_json.encode('utf-8'))>8192:raise AuthorityUnavailable('segmented locator exceeds descriptor bound')
        cell_id=canonical_digest({'schema':'sylanne3.segmented-cell-identity.v1','instance':self.storage_instance_id,
            'scope':self.session.scope.scope_digest,'erasure_owner':erasure_owner_ref,
            'producer':self.session.scope.operation_id,'locator':locator})
        writer=_CellCopyV1(_TARGET,self,cell_id,shape,primary_key,column,codec_id,erasure_owner_ref,total,locator_json)
        writer.register(q)
        return writer

    def begin_mapped_cell_copy(self,q,*,source_row,column):
        """Copy actual qualified mapped Source bytes into a new capture cell."""
        from .runtime.c09_logical_source_v3 import CompleteLogicalSourceRowV3
        q.require_current(self)
        if (type(source_row) is not CompleteLogicalSourceRowV3
                or source_row.scope.session is not self.session or source_row.scope.pair is not self.pair):
            raise AuthorityUnavailable('actual same-session complete logical Source row required')
        source_row.scope.require_current(meter=q.meter)
        if canonical_digest(source_row.descriptor)!=source_row.descriptor_digest:
            raise AuthorityUnavailable('actual logical Source row descriptor was changed')
        bindings=tuple(value for value in source_row.cell_bindings if value['logical_column']==column)
        if len(bindings)!=1:
            raise AuthorityUnavailable('actual registered mapped logical column required')
        binding=bindings[0]
        header=source_row.scope.read_cell_header_v3(binding['cell_id'],meter=q.meter)
        if canonical_digest(tuple(header))!=binding['header_digest']:
            raise AuthorityUnavailable('actual mapped Source header changed after complete row')
        shape=source_row.shape.physical_shape;key=source_row.primary_key
        from .runtime.c09_paged_sql_v2 import _quote
        where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in shape.primary_key_columns)
        actual=q.meter.read_fixed_row(self.pair.source,shape.table,(binding['physical_column'],),where,key)
        if actual!=(binding['cell_id'],):
            raise AuthorityUnavailable('mapped Source cell does not belong to its actual physical row')
        locator={'role':self.pair.source_original.role,'family':shape.table,'primary_key':key,
                 'column':column,'source_schema_digest':shape.schema_digest}
        locator_json=canonical_serialize(locator)
        cell_id=canonical_digest({'schema':'sylanne3.segmented-cell-identity.v1','instance':self.storage_instance_id,
            'scope':self.session.scope.scope_digest,'erasure_owner':header[2],
            'producer':self.session.scope.operation_id,'locator':locator})
        writer=_CellCopyV1(_TARGET,self,cell_id,shape,key,column,header[1],header[2],header[4],locator_json,
                           mapped_source=source_row)
        writer.register(q)
        return writer


    def begin_prepared_owner_output_copy_v3(self,q,*,source):
        """Named actual private prepared Source; no fabricated logical SQL row."""
        from .authority_service.c09_source_physical_read_v3 import VerifiedPreparedOwnerOutputSourceV3
        from .runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
        q.require_current(self)
        if type(source) is not VerifiedPreparedOwnerOutputSourceV3 or source.kind=='Retired':
            raise AuthorityUnavailable('actual retained prepared output Source proof required')
        source.require_current(meter=q.meter)
        if source.scope.session is not self.session or source.scope.pair is not self.pair:
            raise AuthorityUnavailable('prepared Source crossed actual session/pair')
        locator=dict(schema='sylanne3.c09.owner-source-output-prefix-target.v3' if source.kind!='Complete' else 'sylanne3.c09.owner-source-output-target.v3',
            capture_scope_digest=self.session.scope.scope_digest,prepared_digest=source.prepared_digest,
            cell_name=source.cell_name,original_owner_cell_id=source.original_owner_cell_id,
            source_cell_descriptor_digest=canonical_digest(source.source_descriptor_original))
        cell=canonical_digest(dict(schema='sylanne3.segmented-cell-identity.v1',instance=self.storage_instance_id,
            scope=self.session.scope.scope_digest,erasure_owner=source.metadata['source_ref'],
            producer=self.session.scope.operation_id,locator=locator))
        shape=read_c09_table_shape_v2(self.pair.source,'graph_owner_source_prepared_v3',meter=q.meter)
        writer=_PreparedOutputCopyV3(self,source,cell,shape,canonical_serialize(locator))
        writer.register(q)
        return writer

    def install_empty_layout(self,q):
        q.require_current(self)
        db=self.pair.candidate
        with capture_transaction_v2(db):
            for name,sql in {**DDLS,**TRIGGERS}.items():
                kind='table' if name in DDLS else 'trigger'
                found=q.read_one(db,'SELECT sql FROM sqlite_master WHERE type=? AND name=?',(kind,name))
                if found is None:
                    q.mutate(db,sql)
                elif found!=(sql,):raise AuthorityUnavailable('installed segmented schema differs')
            scope=self.session.scope;role=self.pair.source_original.role
            row=(1,LAYOUT_SCHEMA,self.storage_instance_id,role,LAYOUTS[role],LAYOUT_SCHEMA_DIGEST,
                scope.authority_id,scope.authority_namespace,scope.installation_id,scope.maintenance_generation,scope.scope_digest)
            prior=q.read_one(db,'SELECT * FROM segmented_storage_layout_v1 WHERE singleton=1')
            if prior is None:
                q.mutate(db,'INSERT INTO segmented_storage_layout_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)',row)
            elif prior!=row:raise AuthorityUnavailable('segmented layout is another actual storage instance')


def open_c09_segmented_target_v1(session,pair):
    from .authority_service.c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from .authority_service.c09_role_capture_pair_v2 import InstalledC09RolePairV2
    if (type(session) is not C09PagedCaptureSessionV2 or type(pair) is not InstalledC09RolePairV2
            or pair._producer.session is not session or pair.source_original.scope_digest!=session.scope.scope_digest):
        raise AuthorityUnavailable('actual same capture session and registered role pair required')
    session.require_current();pair.require_current()
    transition=session.require_segmented_storage_transition_v1()
    if transition['role_layouts']!=LAYOUTS or transition['layout_schema_digest']!=LAYOUT_SCHEMA_DIGEST:
        raise AuthorityUnavailable('segmented target differs from protected actual layout transition')
    return InstalledSegmentedTargetV1(_TARGET,session,pair,transition)


def graph_ref_columns_v3(source_columns):
    """Explicit physical column mapping; never a JSON pointer masquerading as value."""
    return tuple('value_cell_id' if name=='value' else name for name in source_columns)




def core_ref_columns_v2(source_columns):
    """Registered Core payload reference mapping preserves the original digest."""
    return tuple('payload_cell_id' if name=='payload_json' else name for name in source_columns)


class _CellCopyV1:
    __slots__=('issuer','target','cell_id','shape','key','column','codec','owner','total','locator',
        'hash','root','ordinal','offset','revision','phase','parser','verify_hash','verify_root','verify_ordinal','verify_offset','verify_parser','saved_cursor','mapped_source','__weakref__')
    def __init__(self,token,target,cell_id,shape,key,column,codec,owner,total,locator,*,mapped_source=None):
        if token is not _TARGET:raise AuthorityUnavailable('private installed cell writer required')
        self.issuer,self.target,self.cell_id,self.shape,self.key,self.column,self.codec,self.owner=token,target,cell_id,shape,key,column,codec,owner
        self.total,self.locator=total,locator
        self.mapped_source=mapped_source
        self.hash=sha256();self.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell_id))
        self.ordinal,self.offset,self.revision,self.phase=0,0,0,'write'
        from .runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        parser_type=C09CanonicalJSONStreamV2
        if target.pair.source_original.role=='graph' and shape.table in {'graph_atoms','graph_history'}:
            from .graph_types import AtomKey
            if AtomKey.from_token(key[0]).type_name=='memory.source':
                from .runtime.c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
                parser_type=C09MemorySourceJSONStreamV3
        self.parser=parser_type(ensure_ascii=codec=='canonical-json.ascii.v1',
            **({'source_arena':target.session._source_parser_arena_v3} if parser_type is not C09CanonicalJSONStreamV2 else {}))
        self.verify_hash=sha256();self.verify_root=self.root;self.verify_ordinal=self.verify_offset=0
        self.verify_parser=parser_type(ensure_ascii=codec=='canonical-json.ascii.v1',
            **({'source_arena':self.parser._source_arena} if parser_type is not C09CanonicalJSONStreamV2 else {}))
        self.saved_cursor=None
        if mapped_source is not None:mapped_source.scope.arena.add(self)
    def _source_heap_bytes(self):
        from .runtime.c09_logical_source_v3 import _retained_size
        return 8192+_retained_size((self.saved_cursor,self.parser._stack,self.parser._string,
            self.verify_parser._stack,self.verify_parser._string),set())
    def copy_progress_v3(self,q):
        from copy import copy,deepcopy
        q.require_current(self.target)
        if self.issuer is not _TARGET or self.mapped_source is None:
            raise AuthorityUnavailable('actual mapped Source target progress required')
        self.mapped_source.scope.require_current(meter=q.meter)
        arena=self.mapped_source.scope.arena
        if sum(value._source_heap_bytes() for value in arena)+self._source_heap_bytes()>q.budget.reserved_arena_bytes:
            raise AuthorityUnavailable('actual mapped writer prospective copy exceeds same Source arena')
        result=copy(self);result.hash=self.hash.copy();result.verify_hash=self.verify_hash.copy()
        result.parser=self.parser.copy();result.verify_parser=self.verify_parser.copy()
        result.saved_cursor=deepcopy(self.saved_cursor);arena.add(result)
        return result
    def _cursor(self):
        return (self.cell_id,self.target.session.scope.scope_digest,self.locator,self.codec,
            self.target.session.scope.operation_id,self.owner,self.phase,self.ordinal,self.offset,
            self.root,self.hash.hexdigest(),canonical_serialize({'source_byte_offset':self.offset}),self.total,
            self.verify_ordinal,self.verify_offset,self.verify_root,self.verify_hash.hexdigest(),self.revision)
    def register(self,q):
        q.require_current(self.target)
        with capture_transaction_v2(self.target.pair.candidate):
            row=q.read_cursor(self.target.pair.candidate,self.cell_id)
            if row is None:
                q.mutate(self.target.pair.candidate,'INSERT INTO segmented_cell_writes_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',self._cursor())
            elif row!=self._cursor():
                # A restarted process cannot infer an authenticated SHA state from cursor.
                if row[:6]!=self._cursor()[:6] or row[12]!=self.total:
                    raise AuthorityUnavailable('persisted cell cursor crosses original scope/locator')
                self.phase='replay_prefix'
                self.revision=row[-1];self.saved_cursor=tuple(row)
    def _read_source_fragment(self,q,start,length):
        if self.mapped_source is not None:
            source=self.mapped_source
            source.scope.require_current(meter=q.meter)
            binding=next(value for value in source.cell_bindings if value['logical_column']==self.column)
            header=source.scope.read_cell_header_v3(binding['cell_id'],meter=q.meter)
            if (canonical_digest(tuple(header))!=binding['header_digest'] or header[4]!=self.total
                    or header[1]!=self.codec or header[2]!=self.owner):
                raise AuthorityUnavailable('actual mapped Source header changed during independent copy')
            raw,total=source.scope.read_cell_fragment_v3(binding['cell_id'],start=start,length=length,meter=q.meter)
            return raw,total,'text'
        from .runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2,_quote
        where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in self.shape.primary_key_columns)
        with legacy_cell_read_transaction_v2(self.target.pair.source):
            return read_legacy_sql_cell_fragment_v2(self.target.pair.source,table=self.shape.table,
                column=self.column,where=where,parameters=self.key,start=start,length=length,meter=q.meter)

    def advance(self,q):
        """One segment plus its cursor CAS; update private state only after commit."""
        q.require_current(self.target)
        if self.phase!='write':raise AuthorityUnavailable('cell must complete explicit prefix replay/verification before writing')
        remaining=self.total-self.offset
        if not remaining:
            finalized_parser=self.parser.copy();finalized_parser.finish()
            next_cursor=list(self._cursor());next_cursor[6]='verify';next_cursor[-1]+=1
            with capture_transaction_v2(self.target.pair.candidate):
                db=self.target.pair.candidate
                if q.read_cursor(db,self.cell_id)!=self._cursor():
                    raise AuthorityUnavailable('cell EOF cursor changed before independent verification')
                changed=q.mutate(db,'UPDATE segmented_cell_writes_v1 SET phase=?,cursor_revision=? WHERE cell_id=? AND cursor_revision=?',
                    ('verify',next_cursor[-1],self.cell_id,self.revision))
                if changed.rowcount!=1:raise AuthorityUnavailable('cell EOF cursor CAS changed')
            self.parser=finalized_parser
            self.phase='verify';self.revision=next_cursor[-1]
            return {'phase':'verify','cell_id':self.cell_id,'bytes':self.offset}
        amount=min(MAX_SEGMENT_BYTES,remaining)
        if q.meter.remaining_bytes<amount*3+8192:
            return {'phase':'write','cell_id':self.cell_id,'bytes':self.offset,'needs_next_quantum':True}
        chunk,total,kind=self._read_source_fragment(q,self.offset,amount)
        if total!=self.total or kind!='text':raise AuthorityUnavailable('actual frozen cell source changed')
        next_hash=self.hash.copy();next_hash.update(chunk)
        next_parser=self.parser.copy();next_parser.feed(chunk,lambda event:None)
        chunk_sha=sha256(chunk).hexdigest()
        next_root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.root,self.cell_id,self.ordinal,self.offset,len(chunk),chunk_sha))
        row=(self.cell_id,self.ordinal,self.offset,chunk,chunk_sha)
        next_cursor=list(self._cursor());next_cursor[7]+=1;next_cursor[8]+=len(chunk);next_cursor[9]=next_root
        next_cursor[10]=next_hash.hexdigest();next_cursor[11]=canonical_serialize({'source_byte_offset':next_cursor[8]});next_cursor[-1]+=1
        with capture_transaction_v2(self.target.pair.candidate):
            db=self.target.pair.candidate
            observed=q.read_cursor(db,self.cell_id)
            if observed!=self._cursor():raise AuthorityUnavailable('actual cell cursor CAS changed')
            q.mutate(db,'INSERT INTO segmented_cell_segments_v1 VALUES(?,?,?,?,?)',row)
            names=('phase','next_ordinal','next_byte_offset','prefix_root','prefix_sha256','source_cursor_json',
                'verify_next_ordinal','verify_next_byte_offset','verify_prefix_root','verify_prefix_sha256','cursor_revision')
            positions=(6,7,8,9,10,11,13,14,15,16,17)
            changed=q.mutate(db,'UPDATE segmented_cell_writes_v1 SET '+','.join(name+'=?' for name in names)+' WHERE cell_id=? AND cursor_revision=?',
                (*(next_cursor[pos] for pos in positions),self.cell_id,self.revision))
            if changed.rowcount!=1:raise AuthorityUnavailable('cell segment cursor CAS changed')
        self.hash,self.parser,self.root=next_hash,next_parser,next_root
        self.ordinal,self.offset,self.revision=next_cursor[7],next_cursor[8],next_cursor[17]
        return {'phase':'write','cell_id':self.cell_id,'bytes':self.offset,'segments':self.ordinal}

    def _read_segment(self,q,ordinal,offset):
        q.require_current(self.target)
        if q.meter.remaining_bytes<MAX_SEGMENT_BYTES*3+8192:return None
        with capture_read_transaction_v2(self.target.pair.candidate):
            row=q.read_one(self.target.pair.candidate,'SELECT byte_offset,payload,payload_sha256 FROM segmented_cell_segments_v1 '
                'WHERE cell_id=? AND ordinal=?',(self.cell_id,ordinal),max_row_bytes=MAX_SEGMENT_BYTES+128)
        if (row is None or row[0]!=offset or type(row[1]) is not bytes or not 0<len(row[1])<=MAX_SEGMENT_BYTES
                or sha256(row[1]).hexdigest()!=row[2]):
            raise AuthorityUnavailable('actual stored segment missing, reordered or hash changed')
        return row
    def replay_prefix(self,q):
        """Cold process rebuilds real hash/parser state from actual immutable segments."""
        q.require_current(self.target)
        if self.phase!='replay_prefix' or self.saved_cursor is None:
            raise AuthorityUnavailable('actual cold prefix continuation required')
        row=self.saved_cursor
        if self.ordinal<row[7]:
            segment=self._read_segment(q,self.ordinal,self.offset)
            if segment is None:return {'phase':'replay_prefix','bytes':self.offset,'needs_next_quantum':True}
            offset,chunk,chunk_sha=segment
            actual_hash=self.hash.copy();actual_hash.update(chunk)
            parser=self.parser.copy();parser.feed(chunk,lambda event:None)
            root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.root,self.cell_id,self.ordinal,self.offset,len(chunk),chunk_sha))
            self.hash,self.parser,self.root=actual_hash,parser,root;self.ordinal+=1;self.offset+=len(chunk)
            return {'phase':'replay_prefix','bytes':self.offset}
        if (self.offset,self.root,self.hash.hexdigest())!=(row[8],row[9],row[10]):
            raise AuthorityUnavailable('cold actual payload prefix differs from committed cursor')
        if row[6] not in ('write','verify','sealed'):raise AuthorityUnavailable('unknown stored cell phase')
        next_phase='write' if row[6]=='write' else 'verify'
        # A real cursor CAS records that verification restarts at zero.
        fresh_root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',self.cell_id))
        fresh_hash=sha256()
        with capture_transaction_v2(self.target.pair.candidate):
            db=self.target.pair.candidate
            current=q.read_cursor(db,self.cell_id)
            if current!=row:raise AuthorityUnavailable('cold cell cursor changed during prefix replay')
            changed=q.mutate(db,'UPDATE segmented_cell_writes_v1 SET phase=?,verify_next_ordinal=0,'
                'verify_next_byte_offset=0,verify_prefix_root=?,verify_prefix_sha256=?,cursor_revision=cursor_revision+1 '
                'WHERE cell_id=? AND cursor_revision=?',
                (next_phase,fresh_root,fresh_hash.hexdigest(),self.cell_id,self.revision))
            if changed.rowcount!=1:raise AuthorityUnavailable('cold verification reset cursor CAS changed')
        self.phase=next_phase;self.revision+=1
        self.verify_hash=fresh_hash;self.verify_root=fresh_root
        self.verify_ordinal=self.verify_offset=0
        self.saved_cursor=None
        return {'phase':self.phase,'bytes':self.offset,'needs_fresh_verification':self.phase=='verify'}
    def verify_and_seal(self,q):
        """Independent actual segment sweep before issuing a private sealed result."""
        q.require_current(self.target)
        if self.phase!='verify':raise AuthorityUnavailable('cell source write EOF must precede independent seal')
        if self.verify_ordinal<self.ordinal:
            segment=self._read_segment(q,self.verify_ordinal,self.verify_offset)
            if segment is None:return {'phase':'verify','bytes':self.verify_offset,'needs_next_quantum':True}
            offset,chunk,chunk_sha=segment
            original,total,kind=self._read_source_fragment(q,self.verify_offset,len(chunk))
            if total!=self.total or kind!='text' or original!=chunk:
                raise AuthorityUnavailable('independent stored segment differs from actual frozen source')
            actual_hash=self.verify_hash.copy();actual_hash.update(chunk)
            parser=self.verify_parser.copy();parser.feed(chunk,lambda event:None)
            root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.verify_root,self.cell_id,self.verify_ordinal,self.verify_offset,len(chunk),chunk_sha))
            self.verify_hash,self.verify_parser,self.verify_root=actual_hash,parser,root
            self.verify_ordinal+=1;self.verify_offset+=len(chunk)
            return {'phase':'verify','bytes':self.verify_offset}
        original,total,kind=self._read_source_fragment(q,self.verify_offset,0)
        if original or total!=self.total or self.verify_offset!=total or kind!='text':
            raise AuthorityUnavailable('independent actual frozen source EOF differs')
        finalized_parser=self.verify_parser.copy();parsed=finalized_parser.finish()
        if (self.verify_offset,self.verify_root,self.verify_hash.hexdigest(),parsed.sha256)!=(
                self.total,self.root,self.hash.hexdigest(),self.hash.hexdigest()):
            raise AuthorityUnavailable('actual complete cell bytes, ordered root or canonical EOF differ')
        ref=SegmentedCellRefV1(self.cell_id,self.codec,self.total,self.ordinal,self.hash.hexdigest(),self.root,
            self.target.session.scope.scope_digest)
        header=(ref.cell_id,ref.codec_id,self.owner,self.target.session.scope.operation_id,ref.total_bytes,
            ref.segment_count,ref.payload_sha256,ref.ordered_segment_root,ref.origin_scope_digest)
        with capture_transaction_v2(self.target.pair.candidate):
            db=self.target.pair.candidate
            extra=q.read_one(db,'SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? LIMIT 1',
                (self.cell_id,self.ordinal))
            if extra is not None:raise AuthorityUnavailable('actual cell contains unexpected extra segment')
            prior=q.read_header(db,self.cell_id)
            if prior is None:q.mutate(db,'INSERT INTO segmented_cells_v1 VALUES(?,?,?,?,?,?,?,?,?)',header)
            elif prior!=header:raise AuthorityUnavailable('immutable cell header belongs to different actual bytes')
            changed=q.mutate(db,"UPDATE segmented_cell_writes_v1 SET phase='sealed',verify_next_ordinal=?,verify_next_byte_offset=?,"
                'verify_prefix_root=?,verify_prefix_sha256=?,cursor_revision=cursor_revision+1 WHERE cell_id=? AND cursor_revision=?',
                (self.verify_ordinal,self.verify_offset,self.verify_root,self.verify_hash.hexdigest(),self.cell_id,self.revision))
            if changed.rowcount!=1:raise AuthorityUnavailable('cell seal cursor CAS changed')
        self.verify_parser=finalized_parser
        self.phase='sealed';self.revision+=1
        return VerifiedSealedCellV1(_SEALED,self,ref,q)



class _GeneratedGraphMarkerWriterV3:
    """Single deterministic marker, independently sealed; never copies body bytes."""
    __slots__=('target','basis','shape','key','column','cell_id','locator','owner','marker','phase','revision','root','saved')
    def __init__(self,target,q,basis):
        from .runtime.c09_graph_rebase_candidate_v2 import _GeneratedGraphErasureBasisV3
        q.require_current(target)
        if type(basis) is not _GeneratedGraphErasureBasisV3 or basis.build.pair is not target.pair:
            raise AuthorityUnavailable('actual same-target generated Graph marker basis required')
        basis.require_current(q.meter)
        self.target,self.basis,self.shape,self.key,self.column=target,basis,basis.shape,basis.key,'value'
        self.marker,self.locator,self.owner=basis.marker,canonical_serialize(basis.locator),basis.key[0]
        self.cell_id=canonical_digest({'schema':'sylanne3.segmented-cell-identity.v1','instance':target.storage_instance_id,
            'scope':target.session.scope.scope_digest,'erasure_owner':self.owner,
            'producer':target.session.scope.operation_id,'locator':basis.locator})
        self.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',self.cell_id))
        self.phase,self.revision,self.saved='write',0,None
        with capture_transaction_v2(target.pair.candidate):
            prior=q.read_cursor(target.pair.candidate,self.cell_id)
            if prior is None:q.mutate(target.pair.candidate,'INSERT INTO segmented_cell_writes_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',self._cursor())
            else:
                if prior[:6]!=self._cursor()[:6] or prior[12]!=len(self.marker):
                    raise AuthorityUnavailable('generated marker continuation crosses actual basis/locator')
                self.saved=prior;self.phase='replay_prefix';self.revision=prior[-1]
    def _cursor(self):
        complete=self.phase in ('verify','sealed')
        amount=len(self.marker) if complete else 0
        digest=sha256(self.marker).hexdigest() if complete else sha256().hexdigest()
        genesis=canonical_digest(('sylanne3.segmented-cell-genesis.v1',self.cell_id))
        verified=self.phase=='sealed'
        return (self.cell_id,self.target.session.scope.scope_digest,self.locator,'canonical-json.ascii.v1',
            self.target.session.scope.operation_id,self.owner,self.phase,int(complete),amount,self.root,digest,
            canonical_serialize({'source_byte_offset':amount}),len(self.marker),int(verified),amount if verified else 0,
            self.root if verified else genesis,digest if verified else sha256().hexdigest(),self.revision)
    def _link(self):
        return canonical_digest(('sylanne3.segmented-cell-link.v1',
            canonical_digest(('sylanne3.segmented-cell-genesis.v1',self.cell_id)),self.cell_id,0,0,
            len(self.marker),sha256(self.marker).hexdigest()))
    def _read_segment(self,q):
        row=q.read_one(self.target.pair.candidate,
            'SELECT ordinal,byte_offset,payload,payload_sha256 FROM segmented_cell_segments_v1 WHERE cell_id=? ORDER BY ordinal LIMIT 1',
            (self.cell_id,),max_row_bytes=1024)
        if row!=(0,0,self.marker,sha256(self.marker).hexdigest()):
            raise AuthorityUnavailable('actual generated marker segment differs from independent expected facts')
        extra=q.read_one(self.target.pair.candidate,'SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>0 LIMIT 1',(self.cell_id,))
        if extra is not None:raise AuthorityUnavailable('generated marker has extra payload segments')
    def advance(self,q):
        q.require_current(self.target);self.basis.require_current(q.meter)
        if self.phase!='write':raise AuthorityUnavailable('generated marker requires exact write phase')
        old=self._cursor();next_root=self._link()
        with capture_transaction_v2(self.target.pair.candidate):
            db=self.target.pair.candidate
            if q.read_cursor(db,self.cell_id)!=old:raise AuthorityUnavailable('generated marker write cursor changed')
            q.mutate(db,'INSERT INTO segmented_cell_segments_v1 VALUES(?,?,?,?,?)',
                (self.cell_id,0,0,self.marker,sha256(self.marker).hexdigest()))
            changed=q.mutate(db,"UPDATE segmented_cell_writes_v1 SET phase='verify',next_ordinal=1,next_byte_offset=?,prefix_root=?,"
                'prefix_sha256=?,source_cursor_json=?,cursor_revision=cursor_revision+1 WHERE cell_id=? AND cursor_revision=?',
                (len(self.marker),next_root,sha256(self.marker).hexdigest(),canonical_serialize({'source_byte_offset':len(self.marker)}),self.cell_id,self.revision))
            if changed.rowcount!=1:raise AuthorityUnavailable('generated marker write cursor CAS changed')
        self.phase='verify';self.root=next_root;self.revision+=1
    def replay_prefix(self,q):
        q.require_current(self.target);self.basis.require_current(q.meter)
        if self.phase!='replay_prefix' or self.saved is None:raise AuthorityUnavailable('actual generated marker cold prefix required')
        prior=self.saved
        if prior[6]=='write':
            extra=q.read_one(self.target.pair.candidate,'SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? LIMIT 1',(self.cell_id,))
            if extra is not None or prior[7:11]!=(0,0,self.root,sha256().hexdigest()):
                raise AuthorityUnavailable('generated marker write prefix differs from its actual committed cursor')
            self.phase='write';self.saved=None;return
        if prior[6] not in ('verify','sealed'):raise AuthorityUnavailable('unknown generated marker committed phase')
        self._read_segment(q)
        if prior[7:11]!=(1,len(self.marker),self._link(),sha256(self.marker).hexdigest()):
            raise AuthorityUnavailable('generated marker cold prefix differs')
        with capture_transaction_v2(self.target.pair.candidate):
            db=self.target.pair.candidate
            if q.read_cursor(db,self.cell_id)!=prior:raise AuthorityUnavailable('generated marker cold cursor changed')
            changed=q.mutate(db,"UPDATE segmented_cell_writes_v1 SET phase='verify',verify_next_ordinal=0,verify_next_byte_offset=0,"
                'verify_prefix_root=?,verify_prefix_sha256=?,cursor_revision=cursor_revision+1 WHERE cell_id=? AND cursor_revision=?',
                (canonical_digest(('sylanne3.segmented-cell-genesis.v1',self.cell_id)),sha256().hexdigest(),self.cell_id,self.revision))
            if changed.rowcount!=1:raise AuthorityUnavailable('generated marker cold verification CAS changed')
        self.phase='verify';self.root=self._link();self.revision+=1;self.saved=None
    def verify_and_seal(self,q):
        q.require_current(self.target);self.basis.require_current(q.meter)
        if self.phase!='verify':raise AuthorityUnavailable('generated marker requires independent verification phase')
        with capture_transaction_v2(self.target.pair.candidate):
            db=self.target.pair.candidate
            if q.read_cursor(db,self.cell_id)!=self._cursor():raise AuthorityUnavailable('generated marker independent cursor differs')
            self._read_segment(q)
            ref=SegmentedCellRefV1(self.cell_id,'canonical-json.ascii.v1',len(self.marker),1,
                sha256(self.marker).hexdigest(),self._link(),self.target.session.scope.scope_digest)
            header=(ref.cell_id,ref.codec_id,self.owner,self.target.session.scope.operation_id,ref.total_bytes,
                ref.segment_count,ref.payload_sha256,ref.ordered_segment_root,ref.origin_scope_digest)
            prior=q.read_header(db,self.cell_id)
            if prior is None:q.mutate(db,'INSERT INTO segmented_cells_v1 VALUES(?,?,?,?,?,?,?,?,?)',header)
            elif prior!=header:raise AuthorityUnavailable('generated marker actual immutable header differs')
            changed=q.mutate(db,"UPDATE segmented_cell_writes_v1 SET phase='sealed',verify_next_ordinal=1,verify_next_byte_offset=?,"
                'verify_prefix_root=?,verify_prefix_sha256=?,cursor_revision=cursor_revision+1 WHERE cell_id=? AND cursor_revision=?',
                (len(self.marker),ref.ordered_segment_root,ref.payload_sha256,self.cell_id,self.revision))
            if changed.rowcount!=1:raise AuthorityUnavailable('generated marker seal cursor CAS changed')
        self.phase='sealed';self.revision+=1
        return _GeneratedGraphMarkerSealV3(_SEALED,self,ref,q)


class _GeneratedGraphMarkerSealV3:
    __slots__=('issuer','writer','ref','quantum')
    def __init__(self,token,writer,ref,q):
        if token is not _SEALED or type(writer) is not _GeneratedGraphMarkerWriterV3:
            raise AuthorityUnavailable('actual independent generated marker seal required')
        self.issuer,self.writer,self.ref,self.quantum=token,writer,ref,q
    def require_current(self,target,*,quantum,table,primary_key,column):
        quantum.require_current(target);w=self.writer
        if (self.issuer is not _SEALED or w.target is not target or not self.quantum.completed
                or self.quantum.target is not target or w.shape.table!=table or w.key!=primary_key or column!='value'):
            raise AuthorityUnavailable('generated marker seal crossed actual completed quantum/logical locator')
        w.basis.require_current(quantum.meter)
        with capture_read_transaction_v2(target.pair.candidate):
            header=quantum.read_header(target.pair.candidate,w.cell_id)
            cursor=quantum.read_cursor(target.pair.candidate,w.cell_id)
        if cursor!=w._cursor() or header!=(self.ref.cell_id,self.ref.codec_id,w.owner,target.session.scope.operation_id,
                self.ref.total_bytes,self.ref.segment_count,self.ref.payload_sha256,self.ref.ordered_segment_root,self.ref.origin_scope_digest):
            raise AuthorityUnavailable('generated marker seal lost actual header/cursor')
        return self.ref


class VerifiedSealedCellV1:
    __slots__=('issuer','target','ref','quantum','locator','owner','producer_operation_id')
    def __init__(self,token,writer,ref,quantum):
        if token is not _SEALED or type(writer) is not _CellCopyV1 or type(ref) is not SegmentedCellRefV1:
            raise AuthorityUnavailable('actual independent sealed cell required')
        self.issuer,self.target,self.ref,self.quantum=token,writer.target,ref,quantum
        self.locator,self.owner=writer.locator,writer.owner
        self.producer_operation_id=writer.target.session.scope.operation_id
    def require_current(self,target,*,quantum,table,primary_key,column):
        target.require_current();quantum.require_current(target)
        if (self.issuer is not _SEALED or self.target is not target
                or self.ref.origin_scope_digest!=target.session.scope.scope_digest
                or not self.quantum.completed or self.quantum.target is not target):
            raise AuthorityUnavailable('sealed cell qualification belongs to another actual target')
        from .runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
        with capture_read_transaction_v2(target.pair.source):
            shape=read_c09_table_shape_v2(target.pair.source,table,meter=quantum.meter)
        expected={'role':target.pair.source_original.role,'family':table,'primary_key':primary_key,
            'column':column,'source_schema_digest':shape.schema_digest}
        if (self.locator!=canonical_serialize(expected)
                or self.producer_operation_id!=target.session.scope.operation_id):
            raise AuthorityUnavailable('actual sealed cell belongs to another logical source locator')
        cell_id=canonical_digest({'schema':'sylanne3.segmented-cell-identity.v1','instance':target.storage_instance_id,
            'scope':target.session.scope.scope_digest,'erasure_owner':self.owner,
            'producer':self.producer_operation_id,'locator':expected})
        if cell_id!=self.ref.cell_id:
            raise AuthorityUnavailable('actual sealed cell identity differs from its logical source locator')
        with capture_read_transaction_v2(target.pair.candidate):
            row=quantum.read_header(target.pair.candidate,self.ref.cell_id)
            cursor=quantum.read_cursor(target.pair.candidate,self.ref.cell_id)
        if row is None or row!=(self.ref.cell_id,self.ref.codec_id,self.owner,self.producer_operation_id,
                self.ref.total_bytes,self.ref.segment_count,self.ref.payload_sha256,
                self.ref.ordered_segment_root,self.ref.origin_scope_digest):
            raise AuthorityUnavailable('actual sealed header changed or disappeared')
        if (cursor is None or cursor[:7]!=(self.ref.cell_id,self.ref.origin_scope_digest,self.locator,
                self.ref.codec_id,self.producer_operation_id,self.owner,'sealed')
                or cursor[7:11]!=(self.ref.segment_count,self.ref.total_bytes,
                    self.ref.ordered_segment_root,self.ref.payload_sha256)
                or cursor[12]!=self.ref.total_bytes):
            raise AuthorityUnavailable('actual sealed logical source cursor differs from its independent result')
        return self.ref



class C09ColdGraphCellV3:
    """Independent candidate reader issued only from an actual logical Graph row.

    This private maintenance reader confers no selected/business read permission.
    It compares every stored segment with the same frozen source column again.
    """
    def __init__(self,progress,source_shape,key):
        from .runtime.c09_graph_rebase_candidate_v2 import GraphRebaseColdProgressV2
        from .runtime.c09_paged_sql_v2 import _quote,read_c09_table_shape_v2
        if type(progress) is not GraphRebaseColdProgressV2 or source_shape.table not in {'graph_atoms','graph_history'}:
            raise AuthorityUnavailable('actual independent Graph cold row required')
        progress.session.require_current();progress.pair.require_current()
        meter=current_c09_sql_meter_v2()
        ddl=meter.read_fixed_row(progress.read_db,'sqlite_master',('sql',),'type=? AND name=?',('table',source_shape.table))
        if ddl!=(GRAPH_REF_DDLS_V3[source_shape.table],):
            raise AuthorityUnavailable('actual logical Graph row has another registered V3 schema')
        where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in source_shape.primary_key_columns)
        logical=meter.read_fixed_row(progress.read_db,source_shape.table,graph_ref_columns_v3(source_shape.columns),where,key)
        if logical is None:raise AuthorityUnavailable('actual logical Graph reference row is absent')
        mapped='value_cell_id' in source_shape.columns
        value_column='value_cell_id' if mapped else 'value'
        cell_id=logical[source_shape.columns.index(value_column)]
        if type(cell_id) is not str or len(cell_id)!=64:
            raise AuthorityUnavailable('actual logical Graph cell ID differs')
        layout=meter.read_fixed_row(progress.read_db,'segmented_storage_layout_v1',
            ('storage_instance_id','role','layout_id','layout_schema_digest','origin_scope_digest'),
            'singleton=?',(1,))
        instance=canonical_digest({'schema':'sylanne3.segmented-storage-instance.v1',
            'scope':progress.session.scope.scope_digest,'role':'graph','target_identity':progress.pair.target_identity})
        if layout!=(instance,'graph',LAYOUTS['graph'],LAYOUT_SCHEMA_DIGEST,progress.session.scope.scope_digest):
            raise AuthorityUnavailable('actual cold logical row differs from its source/target layout instance')
        header=meter.read_fixed_row(progress.read_db,'segmented_cells_v1',
            ('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
             'payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(cell_id,))
        from .graph_types import AtomKey
        owner=AtomKey.from_token(key[0]).token
        locator={'role':'graph','family':source_shape.table,'primary_key':key,'column':'value',
            'source_schema_digest':source_shape.schema_digest}
        expected_id=canonical_digest({'schema':'sylanne3.segmented-cell-identity.v1','instance':instance,
            'scope':progress.session.scope.scope_digest,'erasure_owner':owner,
            'producer':progress.session.scope.operation_id,'locator':locator})
        codec='canonical-json.ascii.v1'
        self.source_scope,self.source_header=None,None
        if mapped:
            self.source_scope=progress.session.begin_source_physical_read_v3(progress.pair,meter=meter)
            original=meter.read_fixed_row(progress.pair.source,source_shape.table,('value_cell_id',),where,key)
            if original is None:raise AuthorityUnavailable('actual cold mapped Source reference disappeared')
            self.source_header=self.source_scope.read_cell_header_v3(original[0],meter=meter)
            if self.source_header[2]!=owner:raise AuthorityUnavailable('actual cold mapped Source erasure owner differs')
            codec=self.source_header[1]
        if (header is None or cell_id!=expected_id or header[:4]!=(cell_id,codec,owner,
                progress.session.scope.operation_id) or header[8]!=progress.session.scope.scope_digest):
            raise AuthorityUnavailable('actual cold logical reference/header lost exact owner/locator/producer')
        self.progress,self.shape,self.key,self.where=progress,source_shape,key,where
        self.logical,self.header=logical,header
        self.ordinal=self.offset=0;self.hash=sha256()
        self.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell_id));self.complete=False

    def _target_row_commitment_v3(self):
        if 'value_cell_id' in self.shape.columns:
            from .authority_service.c09_authority_storage_rebase import _row_commitment
            return _row_commitment(self.shape.table,self.shape.columns,self.logical)
        from .runtime.c09_paged_sql_v2 import c09_row_commitment_v2
        return c09_row_commitment_v2(self.logical)

    def _source_fragment_v3(self,meter,start,length):
        if 'value_cell_id' in self.shape.columns:
            self.source_scope.require_current(meter=meter)
            raw,total=self.source_scope.read_cell_fragment_v3(self.source_header[0],start=start,length=length,meter=meter)
            return raw,total,'text'
        from .runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        with legacy_cell_read_transaction_v2(self.progress.pair.source):
            return read_legacy_sql_cell_fragment_v2(self.progress.pair.source,table=self.shape.table,
                column='value',where=self.where,parameters=self.key,start=start,length=length,meter=meter)

    def advance(self):
        from .runtime.c09_paged_sql_v2 import (read_legacy_sql_cell_fragment_v2,
            legacy_cell_read_transaction_v2,c09_row_commitment_v2)
        progress=self.progress;progress.session.require_current();progress.pair.require_current()
        meter=current_c09_sql_meter_v2();cell_id=self.header[0]
        if self.complete:return {'complete':True,'payload_sha256':self.hash.hexdigest(),'logical_commitment':self._target_row_commitment_v3(),'physical_row_commitment':self._target_row_commitment_v3()}
        if self.ordinal<self.header[5]:
            with legacy_cell_read_transaction_v2(progress.read_db):
                row=meter.read_fixed_row(progress.read_db,'segmented_cell_segments_v1',
                    ('byte_offset','payload','payload_sha256'),'cell_id=? AND ordinal=?',(cell_id,self.ordinal))
            if row is None or row[0]!=self.offset or type(row[1]) is not bytes or not 1<=len(row[1])<=MAX_SEGMENT_BYTES or sha256(row[1]).hexdigest()!=row[2]:
                raise AuthorityUnavailable('actual cold segment order/offset/bytes/hash differs')
            original,total,kind=self._source_fragment_v3(meter,self.offset,len(row[1]))
            if original!=row[1] or kind!='text' or total!=self.header[4]:
                raise AuthorityUnavailable('actual cold segment differs from its exact frozen logical Source bytes')
            self.hash.update(row[1])
            self.root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.root,cell_id,self.ordinal,self.offset,len(row[1]),row[2]))
            self.offset+=len(row[1]);self.ordinal+=1
            return {'complete':False,'bytes':self.offset}
        extra=meter.read_fixed_row(progress.read_db,'segmented_cell_segments_v1',('ordinal',),
            'cell_id=? AND ordinal>=? ORDER BY ordinal',(cell_id,self.ordinal))
        block,total,kind=self._source_fragment_v3(meter,self.offset,0)
        if (extra is not None or block or kind!='text' or total!=self.offset
                or (self.offset,self.hash.hexdigest(),self.root)!=(self.header[4],self.header[6],self.header[7])):
            raise AuthorityUnavailable('actual cold cell Source EOF/complete hash/ordered root differs')
        self.complete=True
        return {'complete':True,'payload_sha256':self.hash.hexdigest(),'logical_commitment':self._target_row_commitment_v3(),'physical_row_commitment':self._target_row_commitment_v3()}


class _ColdGeneratedGraphMarkerV3:
    """Independent actual generated-row reader, never uses a writer-issued ref."""
    def __init__(self,progress,shape,key,*,basis_kind='current_closure'):
        from .runtime.c09_graph_rebase_candidate_v2 import (GraphRebaseColdProgressV2,
            _require_graph_erasure_basis_v3)
        if type(progress) is not GraphRebaseColdProgressV2 or not progress.closure_semantic_eof:
            raise AuthorityUnavailable('generated marker cold reader requires independent actual closure EOF')
        self.progress,self.shape,self.key=progress,shape,key
        self.basis=_require_graph_erasure_basis_v3(progress.cold_build,shape,key,current_c09_sql_meter_v2(),basis_kind=basis_kind)
        self.complete=False
    def advance(self):
        from .runtime.c09_paged_sql_v2 import _quote,c09_row_commitment_v2
        progress=self.progress;meter=current_c09_sql_meter_v2()
        basis=self.basis.require_current(meter)
        progress.pair.require_current()
        instance=canonical_digest({'schema':'sylanne3.segmented-storage-instance.v1',
            'scope':progress.session.scope.scope_digest,'role':'graph','target_identity':progress.pair.target_identity})
        layout=meter.read_fixed_row(progress.read_db,'segmented_storage_layout_v1',
            ('storage_instance_id','role','layout_id','layout_schema_digest','origin_scope_digest'),'singleton=?',(1,))
        if layout!=(instance,'graph',LAYOUTS['graph'],LAYOUT_SCHEMA_DIGEST,progress.session.scope.scope_digest):
            raise AuthorityUnavailable('generated marker cold storage layout differs')
        where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in self.shape.primary_key_columns)
        logical=meter.read_fixed_row(progress.read_db,self.shape.table,graph_ref_columns_v3(self.shape.columns),where,self.key)
        if logical is None:raise AuthorityUnavailable('generated marker actual logical reference is absent')
        cell_id=canonical_digest({'schema':'sylanne3.segmented-cell-identity.v1','instance':instance,
            'scope':progress.session.scope.scope_digest,'erasure_owner':self.key[0],
            'producer':progress.session.scope.operation_id,'locator':basis.locator})
        if logical[self.shape.columns.index('value_cell_id' if 'value_cell_id' in self.shape.columns else 'value')]!=cell_id:
            raise AuthorityUnavailable('generated marker actual cell differs from its independent original basis')
        marker=basis.marker;payload_sha=sha256(marker).hexdigest()
        root=canonical_digest(('sylanne3.segmented-cell-link.v1',
            canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell_id)),cell_id,0,0,len(marker),payload_sha))
        header=meter.read_fixed_row(progress.read_db,'segmented_cells_v1',
            ('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
             'payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(cell_id,))
        if header!=(cell_id,'canonical-json.ascii.v1',self.key[0],progress.session.scope.operation_id,
                len(marker),1,payload_sha,root,progress.session.scope.scope_digest):
            raise AuthorityUnavailable('generated marker cold actual header differs')
        segment=meter.read_fixed_row(progress.read_db,'segmented_cell_segments_v1',
            ('ordinal','byte_offset','payload','payload_sha256'),'cell_id=? AND ordinal=?',(cell_id,0))
        extra=meter.read_fixed_row(progress.read_db,'segmented_cell_segments_v1',('ordinal',),
            'cell_id=? AND ordinal>0 ORDER BY ordinal',(cell_id,))
        if segment!=(0,0,marker,payload_sha) or extra is not None:
            raise AuthorityUnavailable('generated marker cold actual segment bytes/order/EOF differs')
        self.header,self.logical=header,logical;self.complete=True
        if 'value_cell_id' in self.shape.columns:
            from .authority_service.c09_authority_storage_rebase import _row_commitment
            commitment=_row_commitment(self.shape.table,self.shape.columns,logical)
        else:commitment=c09_row_commitment_v2(logical)
        return {'complete':True,'payload_sha256':payload_sha,'logical_commitment':commitment,
            'physical_row_commitment':commitment}


def require_legacy_storage_file_v3(path):
    """Reject actual segmented layout at legacy format gates; grants no access."""
    from pathlib import Path
    from contextlib import closing
    import sqlite3
    with closing(sqlite3.connect(Path(path).as_uri()+'?mode=ro',uri=True,isolation_level=None)) as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='segmented_storage_layout_v1'").fetchone() is not None:
            raise AuthorityUnavailable('actual segmented storage requires V3 manifest/PREPARED/selected provenance')
        for table in ('graph_atoms','graph_history'):
            if any(row[1]=='value_cell_id' for row in db.execute('PRAGMA table_info('+table+')')):
                raise AuthorityUnavailable('actual Graph reference layout cannot be selected as legacy storage')
        db.rollback()

class VerifiedPreparedTargetPrefixV3:
    """Actual cursor and prefix EOF; no complete body or execution permission."""
    def __init__(self,token,writer,cursor):
        if token is not _TARGET or not writer.prefix_finished:
            raise AuthorityUnavailable('actual independently verified prefix issuer required')
        self.target,self.source,self.cell_id=writer.target,writer.mapped_source,writer.cell_id
        self.cursor=tuple(cursor);self.prefix_sha256=writer.verify_hash.hexdigest()
        self.prefix_root,self.prefix_bytes,self.prefix_segments=writer.verify_root,writer.verify_offset,writer.verify_ordinal
    def require_current(self,target,*,quantum):
        quantum.require_current(target);self.source.require_current(meter=quantum.meter)
        if self.target is not target or quantum.read_cursor(target.pair.candidate,self.cell_id)!=self.cursor:
            raise AuthorityUnavailable('actual prepared target prefix cursor changed')
        if quantum.read_header(target.pair.candidate,self.cell_id) is not None:
            raise AuthorityUnavailable('prefix cannot claim a complete header')
        return self

class _PreparedOutputCopyV3(_CellCopyV1):
    def __init__(self,target,source,cell_id,shape,locator):
        self.expected_total_bytes=source.expected_total_bytes
        self.prefix_material=source.kind!='Complete';self.prefix_finished=False
        total=0 if source.factual_source_state=='not_started' else source.observed_bytes
        super().__init__(_TARGET,target,cell_id,shape,(source.prepared_digest,),source.cell_name,
            'canonical-json.ascii.v1',source.metadata['source_ref'],total,locator,mapped_source=source)
    def _cursor(self):
        values=list(super()._cursor());values[12]=self.expected_total_bytes
        return tuple(values)
    def register(self,q):
        q.require_current(self.target)
        with capture_transaction_v2(self.target.pair.candidate):
            old=q.read_cursor(self.target.pair.candidate,self.cell_id)
            if old is None:q.mutate(self.target.pair.candidate,'INSERT INTO segmented_cell_writes_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',self._cursor())
            elif old!=self._cursor():
                if old[:6]!=self._cursor()[:6] or old[12]!=self.expected_total_bytes:
                    raise AuthorityUnavailable('prepared output persisted cursor crossed scope/expected obligation')
                self.phase='replay_prefix';self.revision=old[-1];self.saved_cursor=tuple(old)
    def _read_source_fragment(self,q,start,length):
        source=self.mapped_source;source.require_current(meter=q.meter)
        if not 0<=start<=self.total or not 0<=length<=MAX_SEGMENT_BYTES:
            raise AuthorityUnavailable('prepared output fragment coordinates differ')
        if not length or start==self.total:return b'',self.total,'text'
        from .authority_service.c09_selected_history_v3 import _read_one
        low,high=0,source.observed_segments-1;ordinal=None
        with source.scope.read_database_v3(meter=q.meter) as db:
            while low<=high:
                middle=(low+high)//2
                metadata=_read_one(db,'SELECT byte_offset,length(payload) FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal=?',
                    (source.current_cell_id,middle),q.meter)
                if metadata is None:raise AuthorityUnavailable('actual prepared Source segment metadata absent')
                if start<metadata[0]:high=middle-1
                elif start>=metadata[0]+metadata[1]:low=middle+1
                else:ordinal=middle;break
        if ordinal is None:raise AuthorityUnavailable('Source offset has no qualified segment')
        raw=bytearray();position=start
        while len(raw)<length and position<self.total:
            offset,chunk,digest=source.read_segment_v3(ordinal,meter=q.meter)
            if not offset<=position<offset+len(chunk):raise AuthorityUnavailable('actual Source offsets changed')
            take=min(length-len(raw),len(chunk)-(position-offset),self.total-position)
            q.meter.require_available(len(raw)+take)
            raw.extend(chunk[position-offset:position-offset+take]);position+=take;ordinal+=1
        return bytes(raw),self.total,'text'
    def advance(self,q):
        if not self.prefix_material or self.offset<self.total:return super().advance(q)
        q.require_current(self.target)
        if self.phase!='write':raise AuthorityUnavailable('prepared prefix write phase differs')
        with capture_transaction_v2(self.target.pair.candidate):
            if q.read_cursor(self.target.pair.candidate,self.cell_id)!=self._cursor():
                raise AuthorityUnavailable('prefix EOF cursor changed')
            result=q.mutate(self.target.pair.candidate,'UPDATE segmented_cell_writes_v1 SET phase=?,cursor_revision=cursor_revision+1 WHERE cell_id=? AND cursor_revision=?',
                ('verify',self.cell_id,self.revision))
            if result.rowcount!=1:raise AuthorityUnavailable('prefix EOF cursor CAS differs')
        self.phase='verify';self.revision+=1
        return {'phase':'verify','bytes':self.offset}
    def replay_prefix(self,q):
        q.require_current(self.target)
        if self.phase!='replay_prefix':raise AuthorityUnavailable('actual prepared cold replay required')
        old=self.saved_cursor
        if self.ordinal<old[7]:
            segment=self._read_segment(q,self.ordinal,self.offset)
            if segment is None:return {'phase':'replay_prefix','needs_next_quantum':True}
            offset,raw,digest=segment
            actual,total,kind=self._read_source_fragment(q,self.offset,len(raw))
            if actual!=raw or total!=self.total:raise AuthorityUnavailable('cold prefix differs from Source')
            self.hash.update(raw);self.parser.feed(raw,lambda event:None)
            self.root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.root,self.cell_id,self.ordinal,self.offset,len(raw),digest))
            self.ordinal+=1;self.offset+=len(raw)
            return {'phase':'replay_prefix','bytes':self.offset}
        if (self.offset,self.root,self.hash.hexdigest())!=(old[8],old[9],old[10]):
            raise AuthorityUnavailable('cold actual prefix cursor EOF differs')
        if old[6] not in ('write','verify','sealed','staging'):raise AuthorityUnavailable('persisted prepared phase differs')
        phase='write' if old[6]=='write' else 'verify'
        root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',self.cell_id))
        with capture_transaction_v2(self.target.pair.candidate):
            if q.read_cursor(self.target.pair.candidate,self.cell_id)!=old:raise AuthorityUnavailable('cold cursor changed')
            result=q.mutate(self.target.pair.candidate,'UPDATE segmented_cell_writes_v1 SET phase=?,verify_next_ordinal=0,verify_next_byte_offset=0,verify_prefix_root=?,verify_prefix_sha256=?,cursor_revision=cursor_revision+1 WHERE cell_id=? AND cursor_revision=?',
                (phase,root,sha256().hexdigest(),self.cell_id,self.revision))
            if result.rowcount!=1:raise AuthorityUnavailable('cold prepared cursor CAS differs')
        self.phase=phase;self.revision+=1;self.saved_cursor=None
        self.verify_hash=sha256();self.verify_root=root;self.verify_ordinal=self.verify_offset=0
        return {'phase':phase,'bytes':self.offset}
    def _complete_seal_v3(self,q):
        original,total,kind=self._read_source_fragment(q,self.verify_offset,0)
        if original or total!=self.total or self.verify_offset!=total or kind!='text':
            raise AuthorityUnavailable('independent actual frozen source EOF differs')
        finalized_parser=self.verify_parser.copy();parsed=finalized_parser.finish()
        if (self.verify_offset,self.verify_root,self.verify_hash.hexdigest(),parsed.sha256)!=(
                self.total,self.root,self.hash.hexdigest(),self.hash.hexdigest()):
            raise AuthorityUnavailable('actual complete cell bytes, ordered root or canonical EOF differ')
        ref=SegmentedCellRefV1(self.cell_id,self.codec,self.total,self.ordinal,self.hash.hexdigest(),self.root,
            self.target.session.scope.scope_digest)
        header=(ref.cell_id,ref.codec_id,self.owner,self.target.session.scope.operation_id,ref.total_bytes,
            ref.segment_count,ref.payload_sha256,ref.ordered_segment_root,ref.origin_scope_digest)
        with capture_transaction_v2(self.target.pair.candidate):
            db=self.target.pair.candidate
            extra=q.read_one(db,'SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? LIMIT 1',
                (self.cell_id,self.ordinal))
            if extra is not None:raise AuthorityUnavailable('actual cell contains unexpected extra segment')
            prior=q.read_header(db,self.cell_id)
            if prior is None:q.mutate(db,'INSERT INTO segmented_cells_v1 VALUES(?,?,?,?,?,?,?,?,?)',header)
            elif prior!=header:raise AuthorityUnavailable('immutable cell header belongs to different actual bytes')
            changed=q.mutate(db,"UPDATE segmented_cell_writes_v1 SET phase='sealed',verify_next_ordinal=?,verify_next_byte_offset=?,"
                'verify_prefix_root=?,verify_prefix_sha256=?,cursor_revision=cursor_revision+1 WHERE cell_id=? AND cursor_revision=?',
                (self.verify_ordinal,self.verify_offset,self.verify_root,self.verify_hash.hexdigest(),self.cell_id,self.revision))
            if changed.rowcount!=1:raise AuthorityUnavailable('cell seal cursor CAS changed')
        self.verify_parser=finalized_parser
        self.phase='sealed';self.revision+=1
        return VerifiedPreparedTargetCompleteV3(_TARGET,self,ref,q)

    def verify_and_seal(self,q):
        if not self.prefix_material:
            if self.verify_ordinal<self.ordinal:return super().verify_and_seal(q)
            return self._complete_seal_v3(q)
        q.require_current(self.target)
        if self.phase!='verify':raise AuthorityUnavailable('actual prepared prefix verification required')
        if self.verify_ordinal<self.ordinal:
            segment=self._read_segment(q,self.verify_ordinal,self.verify_offset)
            if segment is None:return {'phase':'verify','needs_next_quantum':True}
            offset,raw,digest=segment
            actual,total,kind=self._read_source_fragment(q,self.verify_offset,len(raw))
            if actual!=raw or total!=self.total:raise AuthorityUnavailable('target prefix differs from Source')
            self.verify_hash.update(raw);self.verify_parser.feed(raw,lambda event:None)
            self.verify_root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.verify_root,self.cell_id,self.verify_ordinal,self.verify_offset,len(raw),digest))
            self.verify_ordinal+=1;self.verify_offset+=len(raw)
            return {'phase':'verify','bytes':self.verify_offset}
        if (self.verify_offset,self.verify_hash.hexdigest(),self.verify_root)!=(self.total,self.hash.hexdigest(),self.root):
            raise AuthorityUnavailable('independent prefix SHA/order/byte EOF differs')
        with capture_transaction_v2(self.target.pair.candidate):
            extra=q.read_one(self.target.pair.candidate,'SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? LIMIT 1',(self.cell_id,self.ordinal))
            if extra is not None or q.read_header(self.target.pair.candidate,self.cell_id) is not None:
                raise AuthorityUnavailable('target prefix has extra segments or complete header')
            if q.read_cursor(self.target.pair.candidate,self.cell_id)!=self._cursor():
                raise AuthorityUnavailable('prefix verification cursor changed')
            result=q.mutate(self.target.pair.candidate,'UPDATE segmented_cell_writes_v1 SET phase=?,verify_next_ordinal=?,verify_next_byte_offset=?,verify_prefix_root=?,verify_prefix_sha256=?,cursor_revision=cursor_revision+1 WHERE cell_id=? AND cursor_revision=?',
                ('staging',self.verify_ordinal,self.verify_offset,self.verify_root,self.verify_hash.hexdigest(),self.cell_id,self.revision))
            if result.rowcount!=1:raise AuthorityUnavailable('prefix verified cursor CAS differs')
        self.phase='staging';self.revision+=1;self.prefix_finished=True
        return VerifiedPreparedTargetPrefixV3(_TARGET,self,self._cursor())

class VerifiedPreparedTargetCompleteV3:
    """Named complete output seal after actual target quantum exits."""
    def __init__(self,token,writer,ref,quantum):
        if token is not _TARGET or type(writer) is not _PreparedOutputCopyV3 or writer.prefix_material:
            raise AuthorityUnavailable('actual named prepared complete seal issuer required')
        self.target,self.source,self.ref,self.quantum=writer.target,writer.mapped_source,ref,quantum
        self.locator=writer.locator;self.owner=writer.owner
    def require_current(self,target,*,quantum):
        quantum.require_current(target);self.source.require_current(meter=quantum.meter)
        if self.target is not target or not self.quantum.completed or self.quantum.target is not target:
            raise AuthorityUnavailable('complete prepared seal requires its successful original reservation exit')
        header=quantum.read_header(target.pair.candidate,self.ref.cell_id)
        expected=(self.ref.cell_id,self.ref.codec_id,self.owner,target.session.scope.operation_id,self.ref.total_bytes,
            self.ref.segment_count,self.ref.payload_sha256,self.ref.ordered_segment_root,target.session.scope.scope_digest)
        cursor=quantum.read_cursor(target.pair.candidate,self.ref.cell_id)
        if header!=expected or cursor is None or cursor[2]!=self.locator or cursor[6]!='sealed':
            raise AuthorityUnavailable('actual named prepared seal header/cursor identity changed')
        return self.ref
