"""Installed four-stream segmented census in protected Control metadata.

Projection rows contain structural commitments only. A private sweep is issued
from the registered target, never from a caller path, DTO, or completed cursor.
"""
from contextlib import closing
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from time import monotonic_ns
import json,sqlite3
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..runtime.c09_paged_sql_v2 import (C09PagedCaptureHold,C09SqlByteMeterV2,c09_sql_meter_quantum_v2,
    read_c09_table_shape_v2,read_c09_next_row_metadata_v2,_quote,c09_row_commitment_v2,
    begin_capture_stream_v2,seal_capture_stream_v2,read_capture_cursor_v2,
    _advance_c09_census_in_transaction_v3,_advance_c09_rows_in_transaction_v3,
    C09RowTransformResultV2,CAPTURE_DDLS_V2,CAPTURE_TRIGGERS_V2)
from ..runtime.c09_paged_capture_contract_v2 import C09StreamIdentityV2
from ..segmented_sql_cell_v1 import DDLS,TRIGGERS,LAYOUTS,LAYOUT_SCHEMA_DIGEST,MAX_SEGMENT_BYTES
_BOUND=object()
_VERIFIED=object()
TABLES=('c09_segmented_headers_v3','c09_segmented_segments_v3',
    'c09_segmented_logical_refs_v3','c09_segmented_orphan_audit_v3')
KINDS=('headers','segments','logical_refs','orphan_audit')
PROJECTION_DDLS_V3={
 TABLES[0]:"CREATE TABLE c09_segmented_headers_v3 (scope_digest TEXT NOT NULL,role TEXT NOT NULL,cell_id TEXT NOT NULL,header_json TEXT NOT NULL,PRIMARY KEY(scope_digest,role,cell_id)) STRICT",
 TABLES[1]:"CREATE TABLE c09_segmented_segments_v3 (scope_digest TEXT NOT NULL,role TEXT NOT NULL,cell_id TEXT NOT NULL,ordinal INTEGER NOT NULL,byte_offset INTEGER NOT NULL,payload_bytes INTEGER NOT NULL,payload_sha256 TEXT NOT NULL,PRIMARY KEY(scope_digest,role,cell_id,ordinal)) STRICT",
 TABLES[2]:"CREATE TABLE c09_segmented_logical_refs_v3 (scope_digest TEXT NOT NULL,role TEXT NOT NULL,family TEXT NOT NULL,logical_key_digest TEXT NOT NULL,column_name TEXT NOT NULL,primary_key_json TEXT NOT NULL,cell_id TEXT NOT NULL,erasure_owner_ref TEXT NOT NULL,codec_id TEXT NOT NULL,logical_row_commitment TEXT NOT NULL,PRIMARY KEY(scope_digest,role,family,logical_key_digest,column_name)) STRICT",
 TABLES[3]:"CREATE TABLE c09_segmented_orphan_audit_v3 (scope_digest TEXT NOT NULL,role TEXT NOT NULL,basis_kind TEXT NOT NULL,basis_ordinal INTEGER NOT NULL,basis_key_digest TEXT NOT NULL,witness_json TEXT NOT NULL,PRIMARY KEY(scope_digest,role,basis_kind,basis_ordinal),UNIQUE(scope_digest,role,basis_kind,basis_key_digest)) STRICT",
}
PROJECTION_TRIGGERS_V3=tuple((table+'_no_'+action.lower(),
    'CREATE TRIGGER '+table+'_no_'+action.lower()+' BEFORE '+action+' ON '+table+" BEGIN SELECT RAISE(ABORT,'immutable segmented census original'); END")
    for table in TABLES for action in ('UPDATE','DELETE'))
_HEADER_COLUMNS=('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
    'payload_sha256','ordered_segment_root','origin_scope_digest')
PROJECTION_INDEXES_V3={'c09_segmented_refs_by_cell_v3':'CREATE INDEX c09_segmented_refs_by_cell_v3 ON c09_segmented_logical_refs_v3(scope_digest,role,cell_id,family,logical_key_digest,column_name)'}
_WRITE_COLUMNS=('cell_id','origin_scope_digest','logical_locator_json','codec_id','producer_operation_id','erasure_owner_ref',
    'phase','next_ordinal','next_byte_offset','prefix_root','prefix_sha256','source_cursor_json','expected_total_bytes',
    'verify_next_ordinal','verify_next_byte_offset','verify_prefix_root','verify_prefix_sha256','cursor_revision')


def _catalogue():
    yield from (('table',name,ddl) for name,ddl in {**CAPTURE_DDLS_V2,**PROJECTION_DDLS_V3}.items())
    yield from (('trigger',name,ddl) for name,ddl in (*CAPTURE_TRIGGERS_V2,*PROJECTION_TRIGGERS_V3))
    yield from (('index',name,ddl) for name,ddl in PROJECTION_INDEXES_V3.items())


class _SegmentedProofMeterV3(C09SqlByteMeterV2):
    def count_mutation(self):
        if self.sql_mutations>=64:raise C09PagedCaptureHold('segmented Control quantum reached unchanged 64 writes')
        super().count_mutation()



class InstalledSegmentedCensusV3:
    def __init__(self,token,session,pair):
        if token is not _BOUND:raise AuthorityUnavailable('actual registered segmented census factory required')
        self._issuer,self.session,self.pair=token,session,pair
        self.role=pair.source_original.role;self.scope=session.scope;self.control=session._control.maintenance.control
        self.instance=canonical_digest({'schema':'sylanne3.segmented-storage-instance.v1',
            'scope':self.scope.scope_digest,'role':self.role,'target_identity':pair.target_identity})
        self.phase='schema';self.after=None;self.table_index=0;self.counts=[0,0,0,0]
        self.write_chain=None;self.write_count_original=None;self.write_identity=None
        self.target_eof_digests={};self.ref_table_eofs=[]
        self.write_count=0;self.audit_verified_counts=[0,0,0,0];self.cell=None;self.stream_index=0;self.stream_phase='census'
        self.locators={};self.done=None;self.failed=False;self.rechecking=False;self.target=None
        self.require_current()
        self.target=sqlite3.connect(Path(pair.target_path).as_uri()+'?mode=ro',uri=True,isolation_level=None)
        self.target.execute('PRAGMA query_only=ON')
        stat=Path(pair.target_path).stat();self.target_stamp=(stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns)
        self.target_data_version=self.target.execute('PRAGMA data_version').fetchone()[0]
        self.projection=sqlite3.connect(self.control.path.as_uri()+'?mode=ro',uri=True,isolation_level=None)
        self.projection.execute('PRAGMA query_only=ON')
        self.proof_reader=sqlite3.connect(self.control.path.as_uri()+'?mode=ro',uri=True,isolation_level=None)
        self.proof_reader.execute('PRAGMA query_only=ON')
    def require_current(self):
        self.session.require_current();self.pair.require_current()
        producer=self.session._control._role_pairs.get(self.role)
        if (self._issuer is not _BOUND or self.failed or producer is None or producer.pair is not self.pair
                or self.scope!=self.session.scope or self.pair._producer.session is not self.session):
            raise AuthorityUnavailable('segmented census crossed actual installed pair/scope or failed quantum')
        self.session.require_segmented_storage_transition_v1()
        if self.target is not None:
            stat=Path(self.pair.target_path).stat()
            if (stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns)!=self.target_stamp or self.target.execute('PRAGMA data_version').fetchone()[0]!=self.target_data_version:
                raise AuthorityUnavailable('actual segmented target changed during or after independent physical sweep')
        return self
    def close(self):
        self.target.close();self.projection.close();self.proof_reader.close()
    def _layout(self,meter):
        for name,ddl in DDLS.items():
            if meter.read_fixed_row(self.target,'sqlite_master',('sql',),'type=? AND name=?',('table',name))!=(ddl,):
                raise AuthorityUnavailable('segmented census actual target physical schema differs')
        for name,ddl in TRIGGERS.items():
            if meter.read_fixed_row(self.target,'sqlite_master',('sql',),'type=? AND name=?',('trigger',name))!=(ddl,):
                raise AuthorityUnavailable('segmented census actual target immutable trigger differs')
        from ..segmented_sql_cell_v1 import LAYOUT_SCHEMA
        expected=(1,LAYOUT_SCHEMA,self.instance,self.role,LAYOUTS[self.role],LAYOUT_SCHEMA_DIGEST,
            self.scope.authority_id,self.scope.authority_namespace,self.scope.installation_id,
            self.scope.maintenance_generation,self.scope.scope_digest)
        row=meter.read_fixed_row(self.target,'segmented_storage_layout_v1',
            ('singleton','schema','storage_instance_id','role','layout_id','layout_schema_digest',
             'authority_id','authority_namespace','installation_id','storage_generation','origin_scope_digest'),'singleton=?',(1,))
        if row!=expected:raise AuthorityUnavailable('segmented census target layout/instance/source scope differs')
    def _put(self,db,table,row,meter):
        shape=read_c09_table_shape_v2(db,table,meter=meter)
        key=tuple(row[shape.columns.index(name)] for name in shape.primary_key_columns)
        old=meter.read_row(db,shape,key)
        if old is None:
            if self.rechecking:raise AuthorityUnavailable('independent full target scan found an unprojected physical row')
            meter.write_row(db,table,shape.columns,row)
        elif tuple(old)!=row:raise AuthorityUnavailable('immutable actual segmented projection replay differs')
    def _header(self,cell_id,meter):
        header=meter.read_fixed_row(self.target,'segmented_cells_v1',_HEADER_COLUMNS,'cell_id=?',(cell_id,))
        if (header is None or header[3]!=self.scope.operation_id or header[8]!=self.scope.scope_digest
                or header[1] not in {'canonical-json.ascii.v1','canonical-json.utf8.v1','opaque-bytes.v1'}):
            raise AuthorityUnavailable('actual segmented header crossed producer/scope/codec')
        return tuple(header)
    def _refs(self):
        if self.role=='graph':return (('graph_atoms','value_cell_id'),('graph_history','value_cell_id'))
        # Core's two registered large families are enabled only once their actual
        # reference DDL is present. An old payload column cannot qualify a cell.
        if self.role=='core':return (('authority_d13_counter_originals_v1','payload_cell_id'),
            ('authority_d13_provider_http_bindings_v1','payload_cell_id'))
        return ()
    def _logical(self,table,column,key,meter):
        shape=read_c09_table_shape_v2(self.target,table,meter=meter)
        if column not in shape.columns:raise AuthorityUnavailable('actual segmented logical family needs its registered reference schema')
        row=meter.read_row(self.target,shape,key)
        if row is None:raise AuthorityUnavailable('actual segmented logical reference disappeared')
        row=tuple(row);cell_id=row[shape.columns.index(column)];header=self._header(cell_id,meter)
        if self.role=='graph':
            from ..graph_types import AtomKey
            atom=AtomKey.from_token(key[0]);ns=tuple(json.loads(self.scope.graph_namespace))
            if (atom.owner.bot,atom.owner.persona)!=ns or header[2]!=atom.token:
                raise AuthorityUnavailable('actual logical reference crossed its erasure owner/namespace')
            owner=atom.token
        else:
            if key[0]!=self.scope.authority_namespace:raise AuthorityUnavailable('actual Core cell crossed authority namespace')
            if table=='authority_d13_counter_originals_v1':
                if key[2] not in {'draft','header','evidence'}:raise AuthorityUnavailable('unknown actual D13 counter phase')
                family='d13-counter-source' if key[2]=='draft' else 'd13-counter-history'
            elif table=='authority_d13_provider_http_bindings_v1':
                if key[2] not in {'expected','observed_before_send'}:raise AuthorityUnavailable('unknown actual provider HTTP phase')
                family='d13-provider-http-history'
            else:raise AuthorityUnavailable('unknown registered segmented Core family')
            owner=canonical_serialize((family,key[0],key[1]))
            if header[2]!=owner:raise AuthorityUnavailable('actual Core cell crossed its counter/call erasure owner')
        if header[1]!='canonical-json.ascii.v1':raise AuthorityUnavailable('registered logical family has another actual codec')
        return (self.scope.scope_digest,self.role,table,canonical_digest(key),column,canonical_serialize(key),
            cell_id,owner,header[1],c09_row_commitment_v2(row))
    def advance(self):
        self.require_current()
        if self.done is not None:return self.done
        started=monotonic_ns()
        try:
            with self.session.reserve_batch() as budget:
                meter=_SegmentedProofMeterV3(budget)
                with c09_sql_meter_quantum_v2(meter):
                    if self.phase=='independent':self._independent(self.proof_reader,budget,meter)
                    else:
                        with self.control._db(write=True) as db:
                            self.control._current(db);db.row_factory=None
                            if self.phase=='schema':self._schema(db,meter)
                            elif self.phase=='headers':self._headers(db,meter)
                            elif self.phase=='segments':self._segments(db,meter)
                            elif self.phase=='refs':self._references(db,meter)
                            elif self.phase=='writes':self._writes(db,meter)
                            elif self.phase=='audit':self._audit(db,meter)
                            elif self.phase=='streams':self._streams(db,budget,meter)
                            else:raise AuthorityUnavailable('unknown actual segmented census phase')
            self.require_current()
            if self.phase=='complete':
                self.done=VerifiedSegmentedPhysicalSweepV3(_VERIFIED,self)
                return self.done
            return {'status':'progress','phase':self.phase,'actual_meter_bytes':meter.consumed_bytes,
                'local_ns':monotonic_ns()-started,'role':self.role}
        except BaseException:
            self.failed=True
            raise
    def _schema(self,db,meter):
        self._layout(meter)
        for kind,name,ddl in _catalogue():
            existing=meter.read_fixed_row(db,'sqlite_master',('sql',),'type=? AND name=?',(kind,name))
            if existing is None:
                meter.charge_write(len(ddl.encode()));meter.count_mutation();db.execute(ddl)
                return
            if existing!=(ddl,):raise AuthorityUnavailable('actual protected segmented proof catalogue differs')
        self.phase='headers';self.after=None
    def _headers(self,db,meter):
        row=meter.read_fixed_row(self.target,'segmented_cells_v1',_HEADER_COLUMNS,
            'cell_id COLLATE BINARY>? ORDER BY cell_id COLLATE BINARY',('' if self.after is None else self.after,))
        if row is None:
            eof=canonical_digest(('sylanne3.c09.segmented-target-eof.v3',self.scope.scope_digest,self.role,
                self.pair.target_identity,'headers',self.counts[0],self.after))
            self._retain_target_eof('cell_headers',eof)
            self.phase='segments';self.after=None;return
        header=self._header(row[0],meter)
        self._put(db,TABLES[0],(self.scope.scope_digest,self.role,header[0],canonical_serialize(header)),meter)
        self.counts[0]+=1;self.after=header[0]
    def _finish_cell(self):
        if self.cell is None:return
        header,ordinal,offset,digest,root=self.cell
        if (ordinal,offset,digest.hexdigest(),root)!=(header[5],header[4],header[6],header[7]):
            raise AuthorityUnavailable('independent actual cell segment count/bytes/full SHA/root differs')
    def _segments(self,db,meter):
        after=('',-1) if self.after is None else self.after
        row=meter.read_fixed_row(self.target,'segmented_cell_segments_v1',('cell_id','ordinal','byte_offset','payload','payload_sha256'),
            '(cell_id COLLATE BINARY>? OR cell_id=? AND ordinal>?) ORDER BY cell_id COLLATE BINARY,ordinal',
            (after[0],after[0],after[1]))
        if row is None:
            self._finish_cell()
            eof=canonical_digest(('sylanne3.c09.segmented-target-eof.v3',self.scope.scope_digest,self.role,
                self.pair.target_identity,'segments',self.counts[1],self.after))
            self._retain_target_eof('segments',eof)
            self.cell=None;self.phase='refs';self.after=None;self.table_index=0;self.ref_table_eofs=[];return
        cell_id,ordinal,offset,payload,digest=row
        header=self._header(cell_id,meter)
        if self.cell is None or self.cell[0][0]!=cell_id:
            self._finish_cell()
            state=(header,0,0,sha256(),canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell_id)))
        else:state=self.cell
        if (ordinal,offset)!=(state[1],state[2]) or type(payload) is not bytes or not 1<=len(payload)<=MAX_SEGMENT_BYTES or sha256(payload).hexdigest()!=digest:
            raise AuthorityUnavailable('actual segment missing/reordered/offset/bytes/SHA differs')
        actual_sha=state[3].copy();actual_sha.update(payload)
        actual_root=canonical_digest(('sylanne3.segmented-cell-link.v1',state[4],cell_id,ordinal,offset,len(payload),digest))
        self._put(db,TABLES[1],(self.scope.scope_digest,self.role,cell_id,ordinal,offset,len(payload),digest),meter)
        self.cell=(header,ordinal+1,offset+len(payload),actual_sha,actual_root)
        self.counts[1]+=1;self.after=(cell_id,ordinal)
    def _references(self,db,meter):
        families=self._refs()
        if self.table_index==len(families):
            eof=canonical_digest(('sylanne3.c09.segmented-target-eof.v3',self.scope.scope_digest,self.role,
                self.pair.target_identity,'logical_refs',self.counts[2],self.ref_table_eofs))
            self._retain_target_eof('logical_refs',eof)
            self.phase='writes';self.after=None;return
        table,column=families[self.table_index];shape=read_c09_table_shape_v2(self.target,table,meter=meter)
        if column not in shape.columns:raise AuthorityUnavailable('actual logical cell family lacks registered reference layout')
        found=read_c09_next_row_metadata_v2(self.target,shape,self.after)
        if found is None:
            self.ref_table_eofs.append((table,column,shape.schema_digest,self.after))
            self.table_index+=1;self.after=None;return
        key,_=found;row=self._logical(table,column,key,meter)
        self._put(db,TABLES[2],row,meter);self.counts[2]+=1;self.after=key
    def _writes(self,db,meter):
        from ..runtime.c09_paged_capture_contract_v2 import C09CountOriginalV2
        shape=read_c09_table_shape_v2(self.target,'segmented_cell_writes_v1',meter=meter)
        identity=C09StreamIdentityV2(self.scope.scope_digest,self.pair.source_original.role_source_digest,
            'control_metadata',shape.table,shape.schema_digest,shape.primary_key_columns,shape.primary_key_types)
        if self.write_chain is None:
            self.write_chain=canonical_digest(('sylanne3.c09.census.v2',identity.stream_id));self.write_identity=identity
        found=read_c09_next_row_metadata_v2(self.target,shape,None if self.after is None else (self.after,))
        row=None if found is None else tuple(meter.read_row(self.target,shape,found[0]))
        if row is None:
            last=None if self.after is None else (self.after,)
            eof=canonical_digest(('sylanne3.c09.census-eof.v2',identity.stream_id,self.write_count,last,self.write_chain))
            count=C09CountOriginalV2(identity.stream_id,self.write_count,last,eof,
                'c09-count:'+canonical_digest((identity.stream_id,self.write_chain,eof)),
                canonical_digest(('sylanne3.c09.actual-count-original.v2',identity.stream_id,self.write_count,last,self.write_chain,eof)))
            if self.rechecking:
                if count!=self.first_write_count_original:
                    raise AuthorityUnavailable('independent actual write-progress count/schema/EOF changed')
            self.write_count_original=count
            self._retain_target_eof('write_progress',count.eof_observation_digest)
            if self.rechecking:
                if tuple(self.counts[:3])!=self.first_counts[:3] or self.write_count!=self.first_write_count:
                    raise AuthorityUnavailable('independent full target EOF counts differ from initial physical census')
                self.counts=list(self.first_counts);self.phase='independent';self.stream_index=0;self.verification=None
            else:self.phase='audit';self.table_index=0
            self.after=None;return
        header=self._header(row[0],meter)
        if (row[1]!=self.scope.scope_digest or row[3:7]!=(header[1],self.scope.operation_id,header[2],'sealed')
                or row[7:11]!=(header[5],header[4],header[7],header[6]) or row[12:17]!=(header[4],header[5],header[4],header[7],header[6])):
            raise AuthorityUnavailable('actual cell write cursor lacks independent closed header/count/EOF')
        self.write_count+=1;self.after=row[0]
        self.write_chain=canonical_digest(('sylanne3.c09.census-row.v2',identity.stream_id,self.write_count,
            self.write_chain,found[0],found[1]))

    def _retain_target_eof(self,kind,digest):
        if self.rechecking:
            if self.target_eof_digests.get(kind)!=digest:
                raise AuthorityUnavailable('independent actual target physical EOF differs')
        else:self.target_eof_digests[kind]=digest

    def _projection_actual(self,index,row,meter):
        if tuple(row[:2])!=(self.scope.scope_digest,self.role):
            raise AuthorityUnavailable('segmented projection crossed actual installed scope/role')
        if index==0:
            header=self._header(row[2],meter)
            expected=(self.scope.scope_digest,self.role,header[0],canonical_serialize(header))
            if tuple(row)!=expected:raise AuthorityUnavailable('actual header projection differs from target original')
        elif index==1:
            actual=meter.read_fixed_row(self.target,'segmented_cell_segments_v1',
                ('cell_id','ordinal','byte_offset','payload','payload_sha256'),'cell_id=? AND ordinal=?',(row[2],row[3]))
            if actual is None or type(actual[3]) is not bytes or sha256(actual[3]).hexdigest()!=actual[4]:
                raise AuthorityUnavailable('segment projection has no actual independent payload SHA')
            expected=(*row[:2],actual[0],actual[1],actual[2],len(actual[3]),actual[4])
            if tuple(row)!=expected:raise AuthorityUnavailable('segment projection differs from actual original offset/bytes/SHA')
            self._header(actual[0],meter)
        elif index==2:
            table,key_digest,column,key_json=row[2:6];key=tuple(json.loads(key_json))
            if (table,column) not in self._refs() or canonical_serialize(key)!=key_json or canonical_digest(key)!=key_digest:
                raise AuthorityUnavailable('logical projection has another registered family/canonical PK')
            if tuple(row)!=self._logical(table,column,key,meter):
                raise AuthorityUnavailable('logical ref projection differs from actual target row and header')
        else:raise AuthorityUnavailable('unknown actual segmented projection family')
    def _witness(self,db,index,key,row,meter):
        if index<3:self._projection_actual(index,row,meter)
        if index==0:
            ref=meter.read_fixed_row(db,TABLES[2],('family','logical_key_digest','column_name'),
                'scope_digest=? AND role=? AND cell_id=? ORDER BY family,logical_key_digest,column_name',
                (self.scope.scope_digest,self.role,row[2]))
            if ref is None:raise AuthorityUnavailable('actual segmented header is orphaned from every logical ref')
            relation='header_has_ref';facts=(key,ref)
            header=json.loads(row[3])
            if header[5]==0:
                extra=meter.read_fixed_row(self.target,'segmented_cell_segments_v1',('ordinal',),'cell_id=?',(row[2],))
                genesis=canonical_digest(('sylanne3.segmented-cell-genesis.v1',row[2]))
                if extra is not None or (header[4],header[6],header[7])!=(0,sha256().hexdigest(),genesis):
                    raise AuthorityUnavailable('zero-segment header lacks actual empty cell EOF')
            else:
                tail=meter.read_fixed_row(self.target,'segmented_cell_segments_v1',('ordinal','byte_offset','payload'),
                    'cell_id=? ORDER BY ordinal DESC',(row[2],))
                if tail is None or tail[0]!=header[5]-1 or tail[1]+len(tail[2])!=header[4]:
                    raise AuthorityUnavailable('header lacks actual final segment count/byte EOF')
        elif index==1:
            header=self._header(row[2],meter);relation='segment_has_header';facts=(key,c09_row_commitment_v2(header))
        elif index==2:
            header=self._header(row[6],meter);relation='ref_matches_header';facts=(key,c09_row_commitment_v2(header))
        else:
            header=self._header(row[0],meter)
            if (row[1]!=self.scope.scope_digest or row[3:7]!=(header[1],self.scope.operation_id,header[2],'sealed')
                    or row[7:11]!=(header[5],header[4],header[7],header[6])
                    or row[12:17]!=(header[4],header[5],header[4],header[7],header[6])):
                raise AuthorityUnavailable('orphan audit actual write cursor is not independently closed')
            locator=json.loads(row[2]);family=locator['family'];source_key=tuple(locator['primary_key']);column=locator['column']
            if (self.role=='graph' and column=='value'):column='value_cell_id'
            elif self.role=='core' and column=='payload_json':column='payload_cell_id'
            if (family,column) not in self._refs():raise AuthorityUnavailable('actual closed cursor names an unregistered logical family/column')
            source_shape=read_c09_table_shape_v2(self.pair.source,family,meter=meter)
            original_column='value' if self.role=='graph' else 'payload_json'
            base_locator={'role':self.role,'family':family,'primary_key':source_key,'column':original_column,
                'source_schema_digest':source_shape.schema_digest}
            if 'producer_kind' in locator:
                if self.role!='graph' or set(locator)!=set(base_locator)|{'producer_kind','basis_digest'} or locator['producer_kind'] not in {'current_closure_erased_marker.v3','prior_erased_erased_marker.v3'}:
                    raise AuthorityUnavailable('actual closed cursor has an unregistered generated producer locator')
                digest=locator['basis_digest']
                if type(digest) is not str or len(digest)!=64 or any(char not in '0123456789abcdef' for char in digest):
                    raise AuthorityUnavailable('actual closed cursor generated basis commitment differs')
                expected_locator={**base_locator,'producer_kind':locator['producer_kind'],'basis_digest':digest}
            else:expected_locator=base_locator
            if row[2]!=canonical_serialize(expected_locator):
                raise AuthorityUnavailable('actual closed cursor locator differs from canonical source role/schema/PK')
            expected_id=canonical_digest({'schema':'sylanne3.segmented-cell-identity.v1','instance':self.instance,
                'scope':self.scope.scope_digest,'erasure_owner':header[2],'producer':self.scope.operation_id,'locator':expected_locator})
            if expected_id!=row[0]:raise AuthorityUnavailable('actual closed cursor cell identity differs from its complete source locator')
            expected=self._logical(family,column,source_key,meter)
            if expected[6]!=row[0] or row[11]!=canonical_serialize({'source_byte_offset':header[4]}):
                raise AuthorityUnavailable('actual closed write cursor lost its logical cell/byte EOF')
            relation='write_cursor_closed';facts=(key,c09_row_commitment_v2(header),c09_row_commitment_v2(tuple(row)))
        return {'schema':'sylanne3.c09.segmented-orphan-witness.v1','relation':relation,'facts':facts}
    def _audit(self,db,meter):
        from ..runtime.c09_paged_sql_v2 import _read_c09_scoped_row_metadata_v3
        if self.table_index==4:
            if self.counts[3]!=sum(self.counts[:3])+self.write_count:
                raise AuthorityUnavailable('actual orphan basis count differs from full physical census')
            self.phase='streams';self.stream_index=0;self.stream_phase='census';self.after=None;return
        index=self.table_index;table=TABLES[index] if index<3 else 'segmented_cell_writes_v1'
        source=db if index<3 else self.target;shape=read_c09_table_shape_v2(source,table,meter=meter)
        found=(_read_c09_scoped_row_metadata_v3(source,shape,self.after,(self.scope.scope_digest,self.role))
            if index<3 else read_c09_next_row_metadata_v2(source,shape,self.after))
        if found is None:
            self.table_index+=1;self.after=None;self.audit_ordinal=0;return
        key,_=found;row=tuple(meter.read_row(source,shape,key))
        witness=self._witness(db,index,key,row,meter)
        ordinal=getattr(self,'audit_ordinal',0)+1
        basis=('header','segment','ref','write_cursor')[index]
        self._put(db,TABLES[3],(self.scope.scope_digest,self.role,basis,ordinal,canonical_digest(key),canonical_serialize(witness)),meter)
        self.audit_ordinal=ordinal;self.counts[3]+=1;self.after=key
    def _identity(self,db,index,meter):
        table=TABLES[index];shape=read_c09_table_shape_v2(db,table,meter=meter)
        stream=C09StreamIdentityV2(self.scope.scope_digest,self.pair.source_original.role_source_digest,
            'control_metadata' if index==3 else 'target_rows',table,shape.schema_digest,
            shape.primary_key_columns,shape.primary_key_types)
        return shape,stream
    def _streams(self,db,budget,meter):
        if self.stream_index==4:
            self.first_counts=tuple(self.counts);self.first_write_count=self.write_count
            self.first_write_count_original=self.write_count_original;self.write_chain=None
            self.counts=[0,0,0,0];self.write_count=0;self.rechecking=True
            self.phase='headers';self.after=None;self.cell=None;return
        index=self.stream_index;shape,stream=self._identity(db,index,meter)
        begin_capture_stream_v2(db,stream)
        scope=(self.scope.scope_digest,self.role)
        if self.stream_phase=='census':
            result=_advance_c09_census_in_transaction_v3(self.projection,db,stream,shape,budget,
                check_frozen_source=self.require_current,row_scope=scope)
            if result['eof']:self.stream_phase='rows'
        else:
            saved=meter.read_fixed_row(db,'c09_capture_streams_v2',('status','seal_json'),'stream_id=?',(stream.stream_id,))
            if saved[0]=='sealed':
                from ..runtime.c09_paged_capture_contract_v2 import C09CompleteStreamV2,c09_paged_value_from_wire_v2
                complete=c09_paged_value_from_wire_v2(json.loads(saved[1]),C09CompleteStreamV2)
                eof=True
            else:
                result=_advance_c09_rows_in_transaction_v3(self.projection,db,stream,shape,budget,
                    check_frozen_source=self.require_current,transform_row=lambda unused,sh,key,row,remaining:
                        C09RowTransformResultV2(c09_row_commitment_v2(tuple(row)),0,0),max_page_records=16,row_scope=scope)
                eof=result['eof'];complete=seal_capture_stream_v2(db,stream) if eof else None
            if eof:
                if complete.record_count!=self.counts[index]:
                    raise AuthorityUnavailable('actual segmented raw stream count differs from complete target census')
                self.locators[KINDS[index]]=(stream,complete,read_capture_cursor_v2(db,stream))
                self.stream_index+=1;self.stream_phase='census'
    def _independent(self,db,budget,meter):
        from ..runtime.c09_paged_sql_v2 import (begin_c09_stream_verification_v2,
            _advance_verify_c09_scoped_census_v3,advance_verify_c09_stream_v2)
        if self.stream_index==4:
            if self.audit_verified_counts!=[*self.counts[:3],self.write_count]:
                raise AuthorityUnavailable('independent orphan audit did not cover every actual basis EOF')
            self.phase='complete';return
        index=self.stream_index;shape,stream=self._identity(db,index,meter)
        complete=self.locators[KINDS[index]][1]
        if self.verification is None:
            self.verification=begin_c09_stream_verification_v2(db,stream)
            if self.verification.seal_digest!=complete.digest:raise AuthorityUnavailable('actual segmented complete stream changed')
        if not self.verification.census_complete:
            _advance_verify_c09_scoped_census_v3(self.projection,db,stream,shape,budget,
                verification=self.verification,check_frozen_source=self.require_current,meter=meter,
                row_scope=(self.scope.scope_digest,self.role))
        else:
            def verify(record):
                if meter.remaining_bytes<131072:return False
                if record.primary_key[:2]!=(self.scope.scope_digest,self.role):
                    raise AuthorityUnavailable('actual segmented proof member crosses scope/role')
                row=meter.read_row(db,shape,record.primary_key)
                if row is None or c09_row_commitment_v2(tuple(row))!=record.commitment:
                    raise AuthorityUnavailable('actual segmented proof member lost its original row')
                if index<3:self._projection_actual(index,tuple(row),meter)
                else:self._verify_audit_row(db,tuple(row),meter)
            result=advance_verify_c09_stream_v2(db,stream,budget,verification=self.verification,verify_record=verify,meter=meter)
            if result['complete']:self.stream_index+=1;self.verification=None
    def _verify_audit_row(self,db,row,meter):
        witness=json.loads(row[5]);facts=witness['facts'];key=tuple(facts[0])
        if row[4]!=canonical_digest(key):raise AuthorityUnavailable('orphan witness basis key digest differs')
        basis=row[2];index=('header','segment','ref','write_cursor').index(basis)
        table=TABLES[index] if index<3 else 'segmented_cell_writes_v1'
        source=db if index<3 else self.target;shape=read_c09_table_shape_v2(source,table,meter=meter)
        actual=meter.read_row(source,shape,key)
        if actual is None:raise AuthorityUnavailable('actual orphan audit witness lost its real basis')
        expected=self._witness(db,index,key,tuple(actual),meter)
        if canonical_serialize(expected)!=row[5]:raise AuthorityUnavailable('actual orphan witness differs from independently recomputed relation')
        if row[3]!=self.audit_verified_counts[index]+1:
            raise AuthorityUnavailable('actual orphan witness ordinals do not cover each full basis')
        self.audit_verified_counts[index]+=1


class VerifiedSegmentedPhysicalSweepV3:
    """Complete real four-stream sweep; does not grant selection or body reads."""
    __slots__=('_issuer','bound','counts','write_count','locators','digest')
    def __init__(self,token,bound):
        if token is not _VERIFIED or type(bound) is not InstalledSegmentedCensusV3 or bound.phase!='complete':
            raise AuthorityUnavailable('actual independently completed segmented physical sweep required')
        self._issuer,self.bound=token,bound
        self.counts=tuple(bound.counts);self.write_count=bound.write_count;self.locators=dict(bound.locators)
        self.digest=canonical_digest({'schema':'sylanne3.c09.segmented-physical-sweep.v3',
            'scope':bound.scope.scope_digest,'role':bound.role,'target_identity':bound.pair.target_identity,
            'storage_instance_id':bound.instance,'counts':self.counts,'write_count':self.write_count,
            'streams':{kind:asdict(value[1]) for kind,value in self.locators.items()}})
    def require_current(self):
        self.bound.require_current()
        if (self._issuer is not _VERIFIED or self.bound.done is not self or self.bound.phase!='complete'
                or self.counts!=tuple(self.bound.counts) or set(self.locators)!=set(KINDS)):
            raise AuthorityUnavailable('actual segmented sweep private qualification differs')
        return self


def begin_segmented_census_v3(session,role):
    from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from .c09_role_capture_pair_v2 import InstalledC09RolePairV2
    if type(session) is not C09PagedCaptureSessionV2:raise AuthorityUnavailable('actual installed capture session required')
    session.require_current();producer=session._control._role_pairs.get(role)
    if producer is None or type(producer.pair) is not InstalledC09RolePairV2:
        raise AuthorityUnavailable('actual registered segmented role pair required')
    return InstalledSegmentedCensusV3(_BOUND,session,producer.pair)


def require_segmented_target_row_v3(sweep,table,key,row,*,meter):
    """Every actual target row has a member in the independently completed sweep."""
    from ..runtime.c09_paged_sql_v2 import require_c09_capture_member_v2
    if type(sweep) is not VerifiedSegmentedPhysicalSweepV3:
        raise AuthorityUnavailable('actual complete private segmented target sweep required')
    sweep.require_current();bound=sweep.bound;scope=(bound.scope.scope_digest,bound.role)
    if table=='segmented_storage_layout_v1':
        if key!=(1,):raise AuthorityUnavailable('actual target has extra segmented layout singleton')
        bound._layout(meter);return
    if table=='segmented_cells_v1':
        index=0;projection=(*scope,row[0],canonical_serialize(tuple(row)));projection_key=(*scope,row[0])
    elif table=='segmented_cell_segments_v1':
        if type(row[3]) is not bytes or sha256(row[3]).hexdigest()!=row[4]:
            raise AuthorityUnavailable('actual target segment differs from its body SHA')
        index=1;projection=(*scope,row[0],row[1],row[2],len(row[3]),row[4]);projection_key=(*scope,row[0],row[1])
    elif table=='segmented_cell_writes_v1':
        with bound.control._db() as db:
            bound.control._current(db);db.row_factory=None
            audit=meter.read_fixed_row(db,TABLES[3],('scope_digest','role','basis_kind','basis_ordinal','basis_key_digest','witness_json'),
                'scope_digest=? AND role=? AND basis_kind=? AND basis_key_digest=?',
                (*scope,'write_cursor',canonical_digest(key)))
            if audit is None:raise AuthorityUnavailable('actual target write cursor is outside complete orphan audit')
            expected=bound._witness(db,3,key,tuple(row),meter)
            if audit[5]!=canonical_serialize(expected):raise AuthorityUnavailable('actual target closed cursor changed after sweep')
        index=3;projection=tuple(audit);projection_key=tuple(audit[:4])
    else:raise AuthorityUnavailable('unknown actual segmented physical target table')
    stream,complete,_=sweep.locators[KINDS[index]]
    with bound.control._db() as db:
        bound.control._current(db);db.row_factory=None
        shape=read_c09_table_shape_v2(db,TABLES[index],meter=meter)
        actual=meter.read_row(db,shape,projection_key)
        if actual is None or tuple(actual)!=projection:
            raise AuthorityUnavailable('actual target row differs from protected complete projection')
        member=meter.read_fixed_row(db,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND key_digest=?',(stream.stream_id,canonical_digest(projection_key)))
        if member is None or not 1<=member[0]<=complete.record_count or member[1]!=c09_row_commitment_v2(projection):
            raise AuthorityUnavailable('actual segmented target row lost complete member commitment')
        require_c09_capture_member_v2(db,stream,member[0],projection_key,member[1],meter=meter)
    sweep.require_current()


_COMPLETIONS_V3={
 'headers':('sylanne3.c09.segmented-cell-headers-complete.v1','segmented_cell_headers_complete_v1_'),
 'segments':('sylanne3.c09.segmented-segments-complete.v1','segmented_segments_complete_v1_'),
 'logical_refs':('sylanne3.c09.segmented-logical-refs-complete.v1','segmented_logical_refs_complete_v1_'),
 'orphan_audit':('sylanne3.c09.segmented-orphan-audit-complete.v1','segmented_orphan_audit_complete_v1_'),
}


def retain_segmented_role_complete_v3(session,sweep):
    """One genuine Control completion per reserved call, after actual base cold."""
    from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from ..runtime.c09_paged_sql_v2 import _load_census,_capture_data_state
    if type(session) is not C09PagedCaptureSessionV2 or type(sweep) is not VerifiedSegmentedPhysicalSweepV3:
        raise AuthorityUnavailable('actual installed segmented complete sweep required')
    sweep.require_current();bound=sweep.bound
    if bound.session is not session:raise AuthorityUnavailable('segmented completion crossed actual installed session')
    control=bound.control;role=bound.role;op=bound.scope.operation_id
    with session.reserve_batch() as budget:
        meter=_SegmentedProofMeterV3(budget)
        with c09_sql_meter_quantum_v2(meter):
            sweep.require_current()
            base=control.read_build_original_v1(operation_id=op,kind='capture_role_complete_v2_'+role)
            if base is None:raise AuthorityUnavailable('segmented completion requires actual independently completed base role original')
            facts=base['details'];identity=tuple(facts['target_identity'] if role=='graph' else facts['target_file_identity'])
            if facts['scope_digest']!=bound.scope.scope_digest or facts['role']!=role or facts['target_path']!=bound.pair.target_path or identity!=bound.target_stamp:
                raise AuthorityUnavailable('segmented completion base original crossed actual target/scope/frozen identity')
            common={'operation_id':op,'scope_digest':bound.scope.scope_digest,'role':role,
                'source_role_source_digest':bound.pair.source_original.role_source_digest,
                'target_identity':bound.pair.target_identity,
                'layout_id':LAYOUTS[role],'layout_schema_digest':LAYOUT_SCHEMA_DIGEST,'storage_instance_id':bound.instance,
                'role_complete_original_digest':base['original_digest']}
            originals={}
            for kind in KINDS:
                schema,prefix=_COMPLETIONS_V3[kind];stream,complete,cursor=sweep.locators[kind]
                with control._db() as db:
                    control._current(db);db.row_factory=None
                    census=_load_census(db,stream);data=_capture_data_state(db,stream)
                    saved=meter.read_fixed_row(db,'c09_capture_streams_v2',('status','seal_json'),'stream_id=?',(stream.stream_id,))
                    if (saved is None or saved[0]!='sealed' or json.loads(saved[1])!=json.loads(canonical_serialize(asdict(complete)))
                            or data['cursor']!=json.loads(canonical_serialize(asdict(cursor))) or data['eof'] is None):
                        raise AuthorityUnavailable('actual segmented complete stream/cursor/data EOF changed before signing')
                details={'schema':schema,**common,'proof_store_id':control.control_store_id,
                    'identity':asdict(stream),'count_original':asdict(census),
                    'final_cursor':asdict(cursor),'complete_stream':asdict(complete),'data_eof_observation_digest':data['eof']}
                if kind in {'segments','logical_refs'}:
                    details['cell_headers_complete_original_digest']=originals['headers']['original_digest']
                elif kind=='orphan_audit':
                    details.update(cell_headers_complete_original_digest=originals['headers']['original_digest'],
                        segments_complete_original_digest=originals['segments']['original_digest'],
                        logical_refs_complete_original_digest=originals['logical_refs']['original_digest'],
                        write_progress_count_original=asdict(bound.write_count_original),
                        write_progress_schema_digest=bound.write_identity.schema_digest,
                        scan_counts=dict(zip(('headers','segments','refs','write_progress'),(*sweep.counts[:3],sweep.write_count))),
                        scan_eof_digests={'headers':bound.target_eof_digests['cell_headers'],
                            'segments':bound.target_eof_digests['segments'],'refs':bound.target_eof_digests['logical_refs'],
                            'write_progress':bound.target_eof_digests['write_progress']},violation_count=0)
                    if complete.record_count!=sum(sweep.counts[:3])+sweep.write_count:
                        raise AuthorityUnavailable('actual complete orphan audit did not cover every target basis')
                prior=control.read_build_original_v1(operation_id=op,kind=prefix+role)
                if prior is not None:
                    if prior['details']!=json.loads(canonical_serialize(details)):
                        raise AuthorityUnavailable('segmented completion replay differs from exact current physical/base provenance')
                    originals[kind]=prior
                    continue
                meter.count_mutation()
                control.record_build_original_v1(operation_id=op,kind=prefix+role,details=details)
                result={'status':'progress','phase':'segmented_complete_original','role':role,'kind':kind}
                break
            else:
                details={'schema':'sylanne3.c09.segmented-role-complete.v1',**common,
                    'cell_headers_complete_original_digest':originals['headers']['original_digest'],
                    'segments_complete_original_digest':originals['segments']['original_digest'],
                    'logical_refs_complete_original_digest':originals['logical_refs']['original_digest'],
                    'orphan_census_complete_original_digest':originals['orphan_audit']['original_digest']}
                meter.count_mutation()
                result=control.record_build_original_v1(operation_id=op,kind='segmented_role_complete_v1_'+role,details=details)
    sweep.require_current();session.require_current()
    return result
