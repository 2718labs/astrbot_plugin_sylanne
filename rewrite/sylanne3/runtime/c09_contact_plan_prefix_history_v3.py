"""C09 preserves actual uncommitted Contact prefixes as non-executable history.

No sealed header or full-payload equivalence is created. The original instance,
cell identity, WRITE attempt and cursor phase remain immutable facts.
"""
from copy import copy
from hashlib import sha256
from weakref import WeakSet
import json
from ..runtime_contracts import canonical_digest,canonical_serialize,NamespaceId
from .c09_paged_sql_v2 import C09PagedCaptureHold,capture_transaction_v2,read_c09_table_shape_v2
from .c09_contact_plan_stage_v3 import (FrozenContactPlanStagePrefixReadV3,_FROZEN_READERS,
    begin_frozen_contact_plan_stage_prefix_v3,_COLUMNS,_STREAM_COLUMNS)
from .contact_plan_physical_write_v3 import STREAM_TABLE

TABLE='c09_contact_plan_prefix_history_v3'
COLUMNS=('capture_scope_digest','old_storage_instance','original_cell_id','operation_id','attempt_id',
    'coverage','disposition','original_json','original_digest')
DDL="CREATE TABLE c09_contact_plan_prefix_history_v3(capture_scope_digest TEXT NOT NULL,old_storage_instance TEXT NOT NULL,original_cell_id TEXT NOT NULL,operation_id TEXT NOT NULL,attempt_id TEXT NOT NULL,coverage TEXT NOT NULL CHECK(coverage='prefix_only'),disposition TEXT NOT NULL CHECK(disposition IN ('preserved_non_executable','erased')),original_json TEXT NOT NULL,original_digest TEXT NOT NULL,PRIMARY KEY(capture_scope_digest,old_storage_instance,original_cell_id)) STRICT"
INDEX='CREATE INDEX c09_contact_prefix_operation_v3 ON c09_contact_plan_prefix_history_v3(operation_id,capture_scope_digest,old_storage_instance,original_cell_id)'
DDL_MAP={TABLE:DDL}
_FIELDS={'schema','capture_scope_digest','source_role_digest','source_identity_digest','namespace',
    'old_storage_instance','original_cell_id','operation_id','attempt_id','permit_digest','coverage',
    'header_absent','original_stream','original_cursor','prefix','source_producer_original',
    'disposition','target_cursor','target_segment_commitment','erasure_refs'}
_PUBLISHERS=WeakSet()


def decode_contact_prefix_history_row_v3(row):
    if type(row) is not tuple or len(row)!=len(COLUMNS):
        raise C09PagedCaptureHold('Contact prefix history exact physical row differs')
    raw=json.loads(row[7])
    if (type(raw)is not dict or set(raw)!=_FIELDS or raw['schema']!='d10.contact-plan-prefix-history.v3'
            or canonical_serialize(raw)!=row[7] or canonical_digest(raw)!=row[8]
            or (raw['capture_scope_digest'],raw['old_storage_instance'],raw['original_cell_id'],
                raw['operation_id'],raw['attempt_id'],raw['coverage'],raw['disposition'])!=row[:7]
            or raw['coverage']!='prefix_only' or raw['header_absent'] is not True
            or raw['disposition']not in ('preserved_non_executable','erased')):
        raise C09PagedCaptureHold('Contact prefix history canonical/non-executable closed original differs')
    cursor,stream=tuple(raw['original_cursor']),tuple(raw['original_stream'])
    prefix=raw['prefix']
    if (len(cursor)!=18 or len(stream)!=11 or cursor[0]!=row[2] or cursor[4]!=row[3]
            or stream[2]!=row[3] or stream[4]!=row[4] or stream[5]!=raw['permit_digest']
            or stream[10]not in ('preparing','sealed') or cursor[6]not in ('staging','sealed')
            or set(prefix)!={'bytes','segments','sha256','ordered_root','expected_total_bytes'}
            or (prefix['segments'],prefix['bytes'],prefix['ordered_root'],prefix['sha256'])!=cursor[7:11]
            or prefix['expected_total_bytes']!=cursor[12] or prefix['bytes']>prefix['expected_total_bytes']):
        raise C09PagedCaptureHold('Contact history cannot relabel the actual original finite cursor or phase')
    if raw['disposition']=='erased':
        if raw['target_cursor']is not None or raw['target_segment_commitment']is not None or not raw['erasure_refs']:
            raise C09PagedCaptureHold('Contact erased prefix history retained a target body obligation')
    elif (tuple(raw['target_cursor'])!=cursor or not raw['target_segment_commitment'] or raw['erasure_refs']):
        raise C09PagedCaptureHold('Contact preserved prefix changed original cursor/cell or lacks target EOF')
    return raw


class ContactPlanPrefixPublicationV3:
    def __init__(self,build,source):
        from .c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
        if (type(build)is not InstalledGraphRebaseBuildV2 or type(source)is not FrozenContactPlanStagePrefixReadV3
                or source not in _FROZEN_READERS or not source.complete or source.scope.session is not build.session
                or source.scope.pair is not build.pair or source.scope.role!='graph'):
            raise C09PagedCaptureHold('Contact prefix publication requires actual completed frozen Graph Source EOF')
        build.require_current()
        self.build,self.source=build,source
        self.ordinal=self.offset=self.verify_ordinal=self.verify_offset=0
        self.hash,self.verify_hash=sha256(),sha256()
        self.root=self.verify_root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',source.cell_id))
        self.phase,self.complete,self.row='source_original',False,None
        self.source_original=None
        _PUBLISHERS.add(self);source.scope.arena.add(self)
    def _source_heap_bytes(self):return 65536
    def require_current(self,meter):
        if self not in _PUBLISHERS:
            raise C09PagedCaptureHold('Contact prefix publisher lost its actual private producer')
        self.build.require_current();self.source.require_current(meter=meter)
        return self
    def _erasure(self,meter):
        from .c09_closure_index_v2 import C09ClosureIndexV2
        closure=C09ClosureIndexV2(self.build.pair.candidate,self.build.scope)
        if closure._state()[3]!='sealed':
            raise C09PagedCaptureHold('Contact prefix disposition requires the real complete erasure fixed point')
        refs=[]
        if closure.contains_operation(self.source.stream[2]):refs.append(('operation',self.source.stream[2]))
        for member in self.source.descriptor['source_closure']:
            ref=member['ref']
            if closure.contains_atom(ref):refs.append(('atom',ref))
        return tuple(refs)
    def advance(self):
        from ..segmented_sql_cell_v1 import open_c09_segmented_target_v1
        target=self.build.segmented_target_v3
        if target is None:target=open_c09_segmented_target_v1(self.build.session,self.build.pair)
        result=copy(self);result.hash=self.hash.copy();result.verify_hash=self.verify_hash.copy()
        _PUBLISHERS.add(result);self.source.scope.arena.add(result)
        with target.quantum() as q:
            meter=q.meter;self.require_current(meter)
            db=self.build.pair.candidate
            table=meter.read_fixed_row(db,'sqlite_master',('sql',),"type='table' AND name=?",(TABLE,))
            if table is None:
                q.mutate(db,DDL,());self.build.segmented_target_v3=target;return result
            if table!=(DDL,):raise C09PagedCaptureHold('Contact prefix history table schema differs')
            erasure=self._erasure(meter)
            cell=self.source.cell_id
            if self.phase=='source_original':
                with self.source.scope.read_database_v3(meter=meter) as source_db:
                    layout=meter.read_fixed_row(source_db,'segmented_storage_layout_v1',('storage_instance_id',),'singleton=1',())
                details={'schema':'d10.contact-plan-prefix-source-original.v3','capture_scope_digest':self.build.scope.scope_digest,
                    'source_role_digest':self.build.pair.source_original.role_source_digest,
                    'source_identity_digest':canonical_digest(self.build.pair.source_original),
                    'old_storage_instance':self.source.original_instance or layout[0],'cell_id':cell,'stream':self.source.stream,'cursor':self.source.cursor,
                    'prefix_bytes':self.source.offset,'prefix_segments':self.source.ordinal,
                    'prefix_sha256':self.source.hash.hexdigest(),'prefix_root':self.source.root,
                    'prior_history_digest':None if self.source.history_row is None else self.source.history_row[8]}
                control=self.build.session._control.maintenance.control
                kind='contact-prefix-source:'+canonical_digest((details['old_storage_instance'],cell))[:48]
                previous=control.read_build_original_v1(operation_id=self.build.scope.operation_id,kind=kind)
                if previous is None:
                    control.record_build_original_v1(operation_id=self.build.scope.operation_id,kind=kind,details=details)
                    previous=control.read_build_original_v1(operation_id=self.build.scope.operation_id,kind=kind)
                if previous is None or previous['details']!=json.loads(canonical_serialize(details)):
                    raise C09PagedCaptureHold('Contact prefix has no matching actual protected Source producer original')
                result.source_original=previous;result.phase='copy'
            elif erasure:
                result.phase='publish'
            elif self.phase=='copy':
                if self.ordinal<self.source.cursor[7]:
                    with self.source.scope.read_database_v3(meter=meter) as source_db:
                        segment=meter.read_fixed_row(source_db,'segmented_cell_segments_v1',
                            ('cell_id','ordinal','byte_offset','payload','payload_sha256'),'cell_id=? AND ordinal=?',(cell,self.ordinal))
                    if segment is None or segment[2]!=self.offset or sha256(segment[3]).hexdigest()!=segment[4]:
                        raise C09PagedCaptureHold('Contact prefix frozen Source segment changed during target copy')
                    with capture_transaction_v2(db):
                        old=meter.read_fixed_row(db,'segmented_cell_segments_v1',('cell_id','ordinal','byte_offset','payload','payload_sha256'),
                            'cell_id=? AND ordinal=?',(cell,self.ordinal))
                        if old is None:q.mutate(db,'INSERT INTO segmented_cell_segments_v1 VALUES(?,?,?,?,?)',segment)
                        elif old!=segment:raise C09PagedCaptureHold('Contact prefix target replay changed an original segment')
                    result.hash.update(segment[3]);result.root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.root,
                        cell,self.ordinal,self.offset,len(segment[3]),segment[4]))
                    result.ordinal+=1;result.offset+=len(segment[3])
                else:result.phase='verify'
            elif self.phase=='verify':
                if self.verify_ordinal<self.source.cursor[7]:
                    actual=meter.read_fixed_row(db,'segmented_cell_segments_v1',('byte_offset','payload','payload_sha256'),
                        'cell_id=? AND ordinal=?',(cell,self.verify_ordinal))
                    with self.source.scope.read_database_v3(meter=meter) as source_db:
                        expected=meter.read_fixed_row(source_db,'segmented_cell_segments_v1',('byte_offset','payload','payload_sha256'),
                            'cell_id=? AND ordinal=?',(cell,self.verify_ordinal))
                    if actual!=expected or actual is None or actual[0]!=self.verify_offset or sha256(actual[1]).hexdigest()!=actual[2]:
                        raise C09PagedCaptureHold('Contact target independent prefix bytes/order/SHA differ from actual Source')
                    result.verify_hash.update(actual[1]);result.verify_root=canonical_digest(('sylanne3.segmented-cell-link.v1',
                        self.verify_root,cell,self.verify_ordinal,self.verify_offset,len(actual[1]),actual[2]))
                    result.verify_ordinal+=1;result.verify_offset+=len(actual[1])
                else:
                    if (self.verify_ordinal,self.verify_offset,self.verify_root,self.verify_hash.hexdigest())!=self.source.cursor[7:11]:
                        raise C09PagedCaptureHold('Contact target complete finite prefix EOF differs')
                    if (meter.read_fixed_row(db,'segmented_cells_v1',('cell_id',),'cell_id=?',(cell,))is not None
                            or meter.read_fixed_row(db,'segmented_cell_segments_v1',('ordinal',),'cell_id=? AND ordinal>=? ORDER BY ordinal',(cell,self.verify_ordinal))is not None):
                        raise C09PagedCaptureHold('Contact preserved prefix gained a header or extra segment')
                    result.phase='publish'
            elif self.phase=='publish':
                result.row=_publish_contact_prefix_history_v3(self,db,q,erasure)
                result.complete=True
            else:raise C09PagedCaptureHold('Contact prefix publisher has no actual bounded phase')
        self.build.segmented_target_v3=target
        self.build.require_current()
        return result


def _publish_contact_prefix_history_v3(publisher,db,q,erasure):
    from .c09_paged_capture_contract_v2 import C09StreamIdentityV2,C09CaptureRecordV2,append_c09_page_v2
    from .c09_paged_sql_v2 import (begin_capture_stream_v2,read_capture_cursor_v2,_capture_data_state,_wire,
        c09_row_commitment_v2,require_c09_capture_member_v2)
    from dataclasses import asdict
    source,build,meter=publisher.source,publisher.build,q.meter
    if publisher.source_original is None:
        raise C09PagedCaptureHold('Contact target prefix lacks its real protected Source EOF original')
    old_instance=publisher.source_original['details']['old_storage_instance']
    cursor=source.cursor;cell=source.cell_id
    raw={'schema':'d10.contact-plan-prefix-history.v3','capture_scope_digest':build.scope.scope_digest,
        'source_role_digest':build.pair.source_original.role_source_digest,'source_identity_digest':canonical_digest(build.pair.source_original),
        'namespace':list(source.stream[:2]),'old_storage_instance':old_instance,'original_cell_id':cell,
        'operation_id':source.stream[2],'attempt_id':source.stream[4],'permit_digest':source.stream[5],
        'coverage':'prefix_only','header_absent':True,'original_stream':list(source.stream),'original_cursor':list(cursor),
        'prefix':{'bytes':cursor[8],'segments':cursor[7],'sha256':cursor[10],'ordered_root':cursor[9],'expected_total_bytes':cursor[12]},
        'source_producer_original':publisher.source_original,'disposition':'erased' if erasure else 'preserved_non_executable',
        'target_cursor':None if erasure else list(cursor),
        'target_segment_commitment':None if erasure else canonical_digest((cursor[7],cursor[8],cursor[9],cursor[10])),
        'erasure_refs':list(erasure)}
    row=(build.scope.scope_digest,old_instance,cell,source.stream[2],source.stream[4],
        'prefix_only',raw['disposition'],canonical_serialize(raw),canonical_digest(raw))
    decode_contact_prefix_history_row_v3(row)
    shape=read_c09_table_shape_v2(db,TABLE,meter=meter)
    stream=C09StreamIdentityV2(build.scope.scope_digest,build.pair.source_original.role_source_digest,
        'target_rows',TABLE,shape.schema_digest,shape.primary_key_columns,shape.primary_key_types)
    with capture_transaction_v2(db):
        if erasure:
            segment=meter.read_fixed_row(db,'segmented_cell_segments_v1',('ordinal',),'cell_id=? ORDER BY ordinal',(cell,))
            target_cursor=meter.read_fixed_row(db,'segmented_cell_writes_v1',('cell_id',),'cell_id=?',(cell,))
            if segment is not None or target_cursor is not None:
                raise C09PagedCaptureHold('Contact erased prefix retained target bytes/cursor before disposition')
        else:
            old_cursor=meter.read_fixed_row(db,'segmented_cell_writes_v1',_COLUMNS,'cell_id=?',(cell,))
            if old_cursor is None:q.mutate(db,'INSERT INTO segmented_cell_writes_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',cursor)
            elif old_cursor!=cursor:raise C09PagedCaptureHold('Contact target history changed original cursor phase/instance')
        begin_capture_stream_v2(db,stream)
        old=meter.read_fixed_row(db,TABLE,COLUMNS,'capture_scope_digest=? AND old_storage_instance=? AND original_cell_id=?',row[:3])
        if old is not None:
            if old!=row:raise C09PagedCaptureHold('Contact prefix history replay changed its immutable original')
            member=meter.read_fixed_row(db,'c09_capture_members_v2',('record_ordinal','commitment'),
                'stream_id=? AND primary_key_json=?',(stream.stream_id,canonical_serialize(row[:3])))
            if member is None or member[1]!=c09_row_commitment_v2(row):raise C09PagedCaptureHold('Contact prefix target replay lost its captured member')
            require_c09_capture_member_v2(db,stream,member[0],row[:3],member[1],meter=meter)
            return row
        meter.write_row(db,TABLE,COLUMNS,row)
        current=read_capture_cursor_v2(db,stream);record=C09CaptureRecordV2(row[:3],c09_row_commitment_v2(row))
        page=append_c09_page_v2(stream,current,(record,))
        q.mutate(db,'INSERT INTO c09_capture_pages_v2 VALUES(?,?,?,?)',(stream.stream_id,page.page_index,_wire(page),canonical_serialize([asdict(record)])))
        q.mutate(db,'INSERT INTO c09_capture_members_v2 VALUES(?,?,?,?,?,?)',(stream.stream_id,current.record_offset+1,
            canonical_digest(row[:3]),canonical_serialize(row[:3]),record.commitment,page.page_index))
        data=_capture_data_state(db,stream);data['cursor']=asdict(page.next_cursor)
        q.mutate(db,"UPDATE c09_capture_progress_v2 SET progress_json=? WHERE stream_id=? AND phase='data'",(canonical_serialize(data),stream.stream_id))
    return row


def advance_contact_prefix_history_stage_v3(build,progress):
    from .c09_paged_sql_v2 import require_c09_reserved_meter_v3,c09_sql_meter_quantum_v2
    from .c09_graph_rebase_candidate_v2 import _save_graph_progress_v2,_graph_step_report_v2
    from time import monotonic_ns
    started=monotonic_ns();build.require_current()
    reader=build.contact_prefix_source_v3
    publisher=build.contact_prefix_publisher_v3
    if publisher is not None:
        advanced=publisher.advance();build.contact_prefix_publisher_v3=advanced
        if not advanced.complete:return {'status':'progress','phase':'contact_prefix_history','cell_id':advanced.source.cell_id}
        with build.session.reserve_batch() as budget:
            meter=require_c09_reserved_meter_v3(budget)
            with c09_sql_meter_quantum_v2(meter),capture_transaction_v2(build.pair.candidate):
                stored=meter.read_fixed_row(build.pair.candidate,TABLE,COLUMNS,
                    'capture_scope_digest=? AND old_storage_instance=? AND original_cell_id=?',advanced.row[:3])
                if stored!=advanced.row:raise C09PagedCaptureHold('Contact prefix completion lost its actual durable publication')
                _save_graph_progress_v2(build,'contact_prefix_history',{'after_cell':advanced.source.cell_id},meter)
        build.contact_prefix_publisher_v3=build.contact_prefix_source_v3=None
        return {'status':'progress','phase':'contact_prefix_history','cell_id':advanced.source.cell_id}
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            scope=build.mapped_source_scope_v3
            if scope is None:scope=build.session.begin_source_physical_read_v3(build.pair,meter=meter)
            scope.require_current(meter=meter)
            if reader is not None:
                advanced=reader.advance(meter)
                build.contact_prefix_source_v3=advanced
                if advanced.complete:build.contact_prefix_publisher_v3=ContactPlanPrefixPublicationV3(build,advanced)
                return _graph_step_report_v2(build,'contact_prefix_history',meter,started)
            with scope.read_database_v3(meter=meter) as db:
                cursor=meter.read_fixed_row(db,'segmented_cell_writes_v1',_COLUMNS,
                    'cell_id>? ORDER BY cell_id COLLATE BINARY',(progress.get('after_cell',''),))
                if cursor is None:
                    with capture_transaction_v2(build.pair.candidate):
                        _save_graph_progress_v2(build,'generated',{'after_ref':None},meter)
                    return _graph_step_report_v2(build,'generated',meter,started)
                locator=json.loads(cursor[2])
                header=meter.read_fixed_row(db,'segmented_cells_v1',('cell_id',),'cell_id=?',(cursor[0],))
                eligible=type(locator)is dict and locator.get('schema')=='d10.contact-plan-cell-locator.v3' and header is None
                if eligible:
                    reader=begin_frozen_contact_plan_stage_prefix_v3(scope,cursor,meter=meter)
            build.mapped_source_scope_v3=scope
            if eligible:
                if reader is None:raise C09PagedCaptureHold('Contact selected prefix metadata has no actual frozen producer')
                build.contact_prefix_source_v3=reader
            else:
                with capture_transaction_v2(build.pair.candidate):
                    _save_graph_progress_v2(build,'contact_prefix_history',{'after_cell':cursor[0]},meter)
    return _graph_step_report_v2(build,'contact_prefix_history',meter,started)


def read_contact_prefix_extent_for_sweep_v3(db,scope,source_original,cell_id,meter):
    """Structural prefix extent only; semantic cold verification is independent."""
    row=meter.read_fixed_row(db,TABLE,COLUMNS,'capture_scope_digest=? AND original_cell_id=? ORDER BY old_storage_instance',
        (scope.scope_digest,cell_id))
    if row is None:return None
    raw=decode_contact_prefix_history_row_v3(tuple(row))
    if (raw['disposition']!='preserved_non_executable' or raw['source_role_digest']!=source_original.role_source_digest
            or raw['source_identity_digest']!=canonical_digest(source_original)
            or tuple(raw['namespace'])!=tuple(json.loads(scope.graph_namespace))):
        raise C09PagedCaptureHold('Contact target prefix structural extent crossed actual namespace/Source role')
    cursor=meter.read_fixed_row(db,'segmented_cell_writes_v1',_COLUMNS,'cell_id=?',(cell_id,))
    if cursor!=tuple(raw['original_cursor']) or meter.read_fixed_row(db,'segmented_cells_v1',('cell_id',),'cell_id=?',(cell_id,))is not None:
        raise C09PagedCaptureHold('Contact prefix extent lacks its actual original headerless target cursor')
    details=raw['source_producer_original']['details']
    if (details['capture_scope_digest']!=scope.scope_digest or details['cell_id']!=cell_id
            or tuple(details['cursor'])!=cursor or details['old_storage_instance']!=row[1]
            or (details['prefix_segments'],details['prefix_bytes'],details['prefix_root'],details['prefix_sha256'])!=cursor[7:11]):
        raise C09PagedCaptureHold('Contact prefix structural extent is not its preserved actual Source descriptor')
    return {'coverage':'prefix_only','cell_id':cell_id,'segment_count':cursor[7],'total_bytes':cursor[8],
        'payload_sha256':cursor[10],'ordered_segment_root':cursor[9],'cursor':cursor,'history_row':tuple(row)}

_COLD_READERS=WeakSet()
_COLD_PROOFS=WeakSet()


def _contact_prefix_target_family_v3(progress,meter):
    from .c09_paged_capture_contract_v2 import C09StreamIdentityV2,C09CompleteStreamV2,C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2
    from .c09_historical_proof_row_codec_v2 import _require_exact_structural_member
    db=progress.read_db
    row=meter.read_fixed_row(db,'c09_graph_target_directory_v2',('scope_digest','family','identity_json','complete_json'),
        'scope_digest=? AND family=?',(progress.session.scope.scope_digest,TABLE))
    if row is None:raise C09PagedCaptureHold('Contact prefixes lack their actual complete target history family')
    _require_exact_structural_member(db,progress.candidate.target_directory,row[:2],row,meter)
    stream=c09_paged_value_from_wire_v2(json.loads(row[2]),C09StreamIdentityV2)
    complete=c09_paged_value_from_wire_v2(json.loads(row[3]),C09CompleteStreamV2)
    if stream.family!=TABLE or stream.scope_digest!=progress.session.scope.scope_digest or complete.stream_id!=stream.stream_id:
        raise C09PagedCaptureHold('Contact prefix family escaped its actual Source/target capture')
    return C09SealedStreamLocatorV2('graph',stream,complete)


class ContactPlanPrefixesColdReadV3:
    def __init__(self,progress,meter):
        from .c09_graph_rebase_candidate_v2 import GraphRebaseColdProgressV2
        if type(progress)is not GraphRebaseColdProgressV2:
            raise C09PagedCaptureHold('Contact prefix cold requires actual independently opened target progress')
        self.progress=progress
        self.scope=progress.cold_build.mapped_source_scope_v3
        if self.scope is None:self.scope=progress.session.begin_source_physical_read_v3(progress.pair,meter=meter)
        self.scope.require_current(meter=meter)
        self.family=_contact_prefix_target_family_v3(progress,meter)
        self.phase,self.after,self.reader,self.row='source', '',None,None
        self.ordinal=self.offset=self.count=self.reverse_count=self.current_reverse_count=0
        self.hash=sha256();self.root=None
        self.complete,self.quantum_completed,self.proof=False,False,None
        _COLD_READERS.add(self);self.scope.arena.add(self)
    def _source_heap_bytes(self):return 65536
    def advance(self,meter):
        from .c09_historical_proof_row_codec_v2 import _require_exact_structural_member
        from .c09_closure_index_v2 import C09ClosureIndexV2
        if self not in _COLD_READERS or self.complete:
            raise C09PagedCaptureHold('actual unfinished Contact prefix cold reader required')
        p=self.progress;p.session.require_current();p.pair.check_source();self.scope.require_current(meter=meter)
        result=copy(self);result.hash=self.hash.copy();result.quantum_completed=False
        _COLD_READERS.add(result);self.scope.arena.add(result)
        db=p.read_db
        if self.phase=='source':
            with self.scope.read_database_v3(meter=meter) as source_db:
                cursor=meter.read_fixed_row(source_db,'segmented_cell_writes_v1',_COLUMNS,
                    'cell_id>? ORDER BY cell_id COLLATE BINARY',(self.after,))
                if cursor is None:result.phase='reverse';result.after=('', '', '');return result
                header=meter.read_fixed_row(source_db,'segmented_cells_v1',('cell_id',),'cell_id=?',(cursor[0],))
                locator=json.loads(cursor[2])
                eligible=header is None and type(locator)is dict and locator.get('schema')=='d10.contact-plan-cell-locator.v3'
                if eligible:result.reader=begin_frozen_contact_plan_stage_prefix_v3(self.scope,cursor,meter=meter)
            if not eligible:result.after=cursor[0];return result
            if result.reader is None:raise C09PagedCaptureHold('Contact cold Source prefix has no actual frozen producer')
            result.phase='source_eof';return result
        if self.phase=='source_eof':
            result.reader=self.reader.advance(meter)
            if result.reader.complete:result.phase='original'
            return result
        source=self.reader
        if self.phase=='original':
            source.require_current(meter=meter)
            with self.scope.read_database_v3(meter=meter) as source_db:
                instance=source.original_instance or meter.read_fixed_row(source_db,'segmented_storage_layout_v1',('storage_instance_id',),'singleton=1',())[0]
            row=meter.read_fixed_row(db,TABLE,COLUMNS,'capture_scope_digest=? AND old_storage_instance=? AND original_cell_id=?',
                (p.session.scope.scope_digest,instance,source.cell_id))
            if row is None:raise C09PagedCaptureHold('Contact frozen Source prefix has no target history disposition')
            raw=decode_contact_prefix_history_row_v3(tuple(row))
            _require_exact_structural_member(db,self.family,row[:3],tuple(row),meter)
            actual=p.session._control.maintenance.control.read_build_original_v1(operation_id=p.session.scope.operation_id,
                kind='contact-prefix-source:'+canonical_digest((instance,source.cell_id))[:48])
            if (actual!=raw['source_producer_original'] or raw['source_role_digest']!=p.pair.source_original.role_source_digest
                    or raw['source_identity_digest']!=canonical_digest(p.pair.source_original)
                    or tuple(raw['original_stream'])!=source.stream or tuple(raw['original_cursor'])!=source.cursor
                    or (source.ordinal,source.offset,source.root,source.hash.hexdigest())!=source.cursor[7:11]
                    or actual['details']['prior_history_digest']!=(None if source.history_row is None else source.history_row[8])):
                raise C09PagedCaptureHold('Contact cold prefix original differs from actual Source full prefix EOF/Control producer')
            closure=C09ClosureIndexV2(db,p.session.scope)
            if closure._state()[3]!='sealed':raise C09PagedCaptureHold('Contact cold requires actual complete erasure closure')
            erased=closure.contains_operation(source.stream[2]) or any(closure.contains_atom(member['ref']) for member in source.descriptor['source_closure'])
            if (raw['disposition']=='erased')!=bool(erased):
                raise C09PagedCaptureHold('Contact prefix current erasure disposition differs from independently replayed Source closure')
            if erased:
                if (meter.read_fixed_row(db,'segmented_cell_writes_v1',('cell_id',),'cell_id=?',(source.cell_id,))is not None
                        or meter.read_fixed_row(db,'segmented_cell_segments_v1',('ordinal',),'cell_id=? ORDER BY ordinal',(source.cell_id,))is not None
                        or meter.read_fixed_row(db,STREAM_TABLE,('operation_id',),'bot=? AND persona=? AND operation_id=?',source.stream[:3])is not None):
                    raise C09PagedCaptureHold('Contact erased prefix retained target stream/cursor/segments')
                result.count+=1;result.after=source.cell_id;result.reader=None;result.phase='source';return result
            if meter.read_fixed_row(db,'segmented_cell_writes_v1',_COLUMNS,'cell_id=?',(source.cell_id,))!=source.cursor:
                raise C09PagedCaptureHold('Contact cold target changed its original non-executable cursor phase')
            result.row=tuple(row);result.phase='target_eof';result.ordinal=result.offset=0
            result.hash=sha256();result.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',source.cell_id));return result
        if self.phase=='target_eof':
            source.require_current(meter=meter)
            if self.ordinal<source.cursor[7]:
                actual=meter.read_fixed_row(db,'segmented_cell_segments_v1',('byte_offset','payload','payload_sha256'),
                    'cell_id=? AND ordinal=?',(source.cell_id,self.ordinal))
                with self.scope.read_database_v3(meter=meter) as source_db:
                    expected=meter.read_fixed_row(source_db,'segmented_cell_segments_v1',('byte_offset','payload','payload_sha256'),
                        'cell_id=? AND ordinal=?',(source.cell_id,self.ordinal))
                if actual!=expected or actual is None or actual[0]!=self.offset or sha256(actual[1]).hexdigest()!=actual[2]:
                    raise C09PagedCaptureHold('Contact cold target prefix bytes/order/hash differ from independently read Source')
                result.hash.update(actual[1]);result.root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.root,
                    source.cell_id,self.ordinal,self.offset,len(actual[1]),actual[2]));result.ordinal+=1;result.offset+=len(actual[1])
                return result
            if ((self.ordinal,self.offset,self.root,self.hash.hexdigest())!=source.cursor[7:11]
                    or meter.read_fixed_row(db,'segmented_cells_v1',('cell_id',),'cell_id=?',(source.cell_id,))is not None
                    or meter.read_fixed_row(db,'segmented_cell_segments_v1',('ordinal',),'cell_id=? AND ordinal>=? ORDER BY ordinal',(source.cell_id,self.ordinal))is not None):
                raise C09PagedCaptureHold('Contact cold complete prefix EOF gained header/extra bytes or changed root')
            result.count+=1;result.after=source.cell_id;result.reader=result.row=None;result.phase='source';return result
        if self.phase=='reverse':
            row=meter.read_fixed_row(db,TABLE,COLUMNS,
                '(capture_scope_digest,old_storage_instance,original_cell_id)>(?,?,?) ORDER BY capture_scope_digest,old_storage_instance,original_cell_id',
                self.after)
            if row is None:
                if self.count!=self.current_reverse_count or self.reverse_count!=self.family.complete.record_count:
                    raise C09PagedCaptureHold('Contact prefix forward/current reverse/full historical family counts differ')
                result.complete=True;return result
            raw=decode_contact_prefix_history_row_v3(tuple(row))
            _require_exact_structural_member(db,self.family,row[:3],tuple(row),meter)
            if row[0]==p.session.scope.scope_digest:
                with self.scope.read_database_v3(meter=meter) as source_db:
                    cursor=meter.read_fixed_row(source_db,'segmented_cell_writes_v1',_COLUMNS,'cell_id=?',(row[2],))
                if cursor!=tuple(raw['original_cursor']):raise C09PagedCaptureHold('Contact target history has no actual original Source cursor')
                result.current_reverse_count+=1
            else:
                # The cold source/disposition driver independently verifies this
                # prior signed family and preserves its exact source row.
                from .c09_paged_sql_v2 import c09_row_commitment_v2
                proof=meter.read_fixed_row(db,'c09_graph_dispositions_v2',('new_commitment','disposition'),
                    'scope_digest=? AND table_name=? AND key_digest=?',
                    (p.session.scope.scope_digest,TABLE,canonical_digest((TABLE,tuple(row[:3])))))
                if proof!=(c09_row_commitment_v2(tuple(row)),'preserved_exact'):
                    raise C09PagedCaptureHold('Contact historical prefix lacks its actual independently verified current preservation disposition')
            result.after=tuple(row[:3]);result.reverse_count+=1;return result
        raise C09PagedCaptureHold('Contact cold prefix has no registered bounded phase')
    def require_complete(self,meter):
        if self not in _COLD_READERS or not self.complete or not self.quantum_completed:
            raise C09PagedCaptureHold('Contact prefix proof requires its actual successful final quantum and full two-way EOF')
        self.scope.require_current(meter=meter)
        if self.proof is None:
            self.proof=ContactPlanPrefixesColdProofV3(self)
        return self.proof


class ContactPlanPrefixesColdProofV3:
    def __init__(self,reader):
        if reader not in _COLD_READERS or not reader.complete or not reader.quantum_completed:
            raise C09PagedCaptureHold('Contact cold prefix proof cannot be issued from a caller marker')
        self.reader=reader;_COLD_PROOFS.add(self)
    def require_current(self,meter):
        if self not in _COLD_PROOFS or not self.reader.complete:
            raise C09PagedCaptureHold('actual current Contact cold prefix proof required')
        self.reader.progress.session.require_current();self.reader.scope.require_current(meter=meter)
        return self


def require_contact_prefix_source_history_v3(scope,db,cursor,meter,*,expected_row=None):
    """Read only an actual captured non-executable prefix; never restore WRITE."""
    from .c09_paged_capture_contract_v2 import (C09StreamIdentityV2,C09CompleteStreamV2,
        C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2)
    from .c09_historical_proof_row_codec_v2 import _require_exact_structural_member
    from .contact_plan_physical_write_v3 import validate_contact_plan_stream_row_v3
    scope.require_current(meter=meter)
    if scope.role!='graph' or db is not scope.source or scope.source_original is not scope.pair.source_original:
        raise C09PagedCaptureHold('Contact historical prefix requires the actual frozen Graph-role Source')
    shape=meter.read_fixed_row(db,'sqlite_master',('sql',),"type='table' AND name=?",(TABLE,))
    if shape is None:
        if expected_row is not None:raise C09PagedCaptureHold('Contact authenticated prefix history disappeared')
        return None
    if shape!=(DDL,):raise C09PagedCaptureHold('Contact Source prefix history exact physical schema differs')
    basis=scope.previous_selected_basis
    if basis is None:
        if expected_row is not None:raise C09PagedCaptureHold('Contact historical prefix lost its actual installed prior selection')
        return None
    basis.require_current(meter=meter)
    row=meter.read_fixed_row(db,TABLE,COLUMNS,'capture_scope_digest=? AND original_cell_id=? ORDER BY old_storage_instance',
        (basis.prepared['capture_scope_digest'],cursor[0]))
    if row is None:
        if expected_row is not None:raise C09PagedCaptureHold('Contact authenticated prefix history disappeared')
        return None
    row=tuple(row);raw=decode_contact_prefix_history_row_v3(row)
    if (expected_row is not None and row!=expected_row or raw['disposition']!='preserved_non_executable'
            or tuple(raw['namespace'])!=tuple(json.loads(scope.session.scope.graph_namespace))
            or tuple(raw['original_cursor'])!=tuple(cursor)):
        raise C09PagedCaptureHold('Contact Source history is not its exact preserved original cursor/namespace')
    directory=meter.read_fixed_row(db,'c09_graph_target_directory_v2',('scope_digest','family','identity_json','complete_json'),
        'scope_digest=? AND family=?',(row[0],TABLE))
    if directory is None:raise C09PagedCaptureHold('Contact Source prefix history lacks its actual sealed producing target family')
    identity=c09_paged_value_from_wire_v2(json.loads(directory[2]),C09StreamIdentityV2)
    complete=c09_paged_value_from_wire_v2(json.loads(directory[3]),C09CompleteStreamV2)
    actual_shape=read_c09_table_shape_v2(db,TABLE,meter=meter)
    if (identity.scope_digest!=row[0] or identity.family!=TABLE or identity.stream_kind!='target_rows'
            or identity.role_source_digest!=raw['source_role_digest'] or complete.stream_id!=identity.stream_id
            or identity.schema_digest!=actual_shape.schema_digest
            or identity.primary_key_columns!=actual_shape.primary_key_columns
            or identity.primary_key_types!=actual_shape.primary_key_types):
        raise C09PagedCaptureHold('Contact Source prefix history directory/shape/producing scope differs')
    from .c09_historical_proof_row_codec_v2 import _actual_anchor,_require_signed_locator
    anchor=_actual_anchor(scope.session,scope.pair,row[0])
    signed=_require_signed_locator(db,anchor,identity,meter)
    if signed.complete!=complete:raise C09PagedCaptureHold('Contact Source history complete family differs from actual signed historical certificate')
    _require_exact_structural_member(db,signed,row[:3],row,meter)
    stream=tuple(raw['original_stream']);descriptor=validate_contact_plan_stream_row_v3(_STREAM_COLUMNS,stream)
    locator=json.loads(cursor[2]);cell=descriptor['cells'].get(locator['name'])
    if cell is None or cell['origin'] is None:raise C09PagedCaptureHold('Contact Source history has no exact original cell descriptor')
    origin_digest=canonical_digest(cell['origin'])
    expected=canonical_digest({'schema':'sylanne3.runtime-cell-identity.v3','instance':raw['old_storage_instance'],
        'origin_digest':origin_digest,'locator':cell['locator'],'payload_sha256':cell['payload_sha256']})
    details=raw['source_producer_original']['details']
    if (expected!=cursor[0] or cell['cell_id']!=cursor[0] or cell['origin_digest']!=origin_digest
            or cell['byte_count']!=cursor[12] or canonical_serialize(locator)!=cursor[2]
            or details['old_storage_instance']!=raw['old_storage_instance'] or details['cell_id']!=cursor[0]
            or tuple(details['cursor'])!=tuple(cursor) or tuple(details['stream'])!=stream
            or (details['prefix_segments'],details['prefix_bytes'],details['prefix_root'],details['prefix_sha256'])!=tuple(cursor[7:11])
            or meter.read_fixed_row(db,'segmented_cells_v1',('cell_id',),'cell_id=?',(cursor[0],)) is not None):
        raise C09PagedCaptureHold('Contact Source history old-instance identity/producer/headerless extent differs')
    return row,raw
