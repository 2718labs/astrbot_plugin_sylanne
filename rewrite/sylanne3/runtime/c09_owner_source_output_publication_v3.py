"""Six prepared outputs: same-transaction publication and independent byte EOF."""
from __future__ import annotations
from copy import copy
from dataclasses import asdict
from hashlib import sha256
import json
from weakref import WeakSet
from .c09_paged_sql_v2 import (
    C09PagedCaptureHold,capture_transaction_v2,read_c09_table_shape_v2,
    begin_capture_stream_v2,read_capture_cursor_v2,_capture_data_state,_wire,
    require_c09_capture_member_v2,c09_row_commitment_v2)
from .c09_paged_capture_contract_v2 import C09StreamIdentityV2,C09CaptureRecordV2,append_c09_page_v2
from .c09_owner_source_output_mappings_v3 import TABLE,COLUMNS,NAMES,decode_owner_source_output_mapping_row_v3
from .c09_prepared_owner_output_semantics_v3 import PreparedOwnerOutputSemanticReadV3
from ..runtime_contracts import canonical_digest,canonical_serialize
_READS=WeakSet()
_PUBLISHERS=WeakSet()
_HEADER=('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes',
         'segment_count','payload_sha256','ordered_segment_root','origin_scope_digest')
_PREPARED='graph_owner_source_prepared_v3'

def _source_descriptor(source):
    # Q05 alone mints this exact Source descriptor in its protected scope original.
    descriptor=source.source_descriptor_original
    if descriptor!=source.scope_original['details']['source_descriptor']:
        raise C09PagedCaptureHold('Source descriptor differs from the actual protected Q05 original')
    return descriptor

def _source_disposition_original(source,meter):
    if source.disposition is None:return None
    source.disposition.require_current(meter=meter)
    return json.loads(canonical_serialize(source.disposition.original))

def _retirement_original(source,erasure,meter):
    scope=source.scope.session.scope.scope_digest
    previous=None
    if source.kind=='Retired' and source.previous_mapping_original_ref is not None:
        previous=source.read_previous_retirement_original_v3(meter=meter)
    if previous is not None:
        reason=previous['reason'];digest=previous['source_disposition_digest']
        refs=previous['erasure_disposition_refs']
    else:
        reason='erased' if erasure else 'aborted_verified'
        digest=canonical_digest(_source_disposition_original(source,meter));refs=erasure
    return dict(schema='sylanne3.c09.owner-output-retirement.v3',scope_digest=scope,
        prepared_digest=source.prepared_digest,cell_name=source.cell_name,
        source_cell_descriptor_digest=canonical_digest(_source_descriptor(source)),
        reason=reason,source_disposition_digest=digest,erasure_disposition_refs=refs)

def _prepared_member(build,source,meter,*,db=None):
    if db is None:db=build.pair.candidate
    from .c09_graph_rebase_candidate_v2 import _actual_source_locator_v2
    from ..authority_service.c09_authority_storage_rebase import _row_commitment
    shape=read_c09_table_shape_v2(build.pair.source,_PREPARED,meter=meter)
    locator=_actual_source_locator_v2(build,shape,meter)
    key=(source.prepared_digest,)
    item=meter.read_fixed_row(db,'c09_capture_members_v2',('record_ordinal','commitment'),
        'stream_id=? AND primary_key_json=?',(locator.identity.stream_id,canonical_serialize(key)))
    expected=c09_row_commitment_v2(tuple(source.prepared.row))
    if item is None or item[1]!=expected:
        raise C09PagedCaptureHold('prepared output has no actual complete prepared Source member')
    require_c09_capture_member_v2(db,locator.identity,item[0],key,item[1],meter=meter)
    descriptor=dict(schema='sylanne3.c09.owner-prepared-source-row.v3',
        scope_digest=build.scope.scope_digest,table_name=_PREPARED,primary_key=key,
        physical_schema_digest=shape.schema_digest,
        row_commitment=_row_commitment(_PREPARED,shape.columns,tuple(source.prepared.row)),
        origin_stream_id=locator.identity.stream_id,origin_record_ordinal=item[0])
    return descriptor

def _row_disposition(build,table,key,meter,*,db=None):
    if db is None:db=build.pair.candidate
    from .c09_graph_rebase_candidate_v2 import _read_graph_disposition_original_row_v3,_source_stream_identity_v2
    proof=_read_graph_disposition_original_row_v3(db,build.scope.scope_digest,table,key,meter)
    if proof is None:raise C09PagedCaptureHold('prepared adopted output is missing its actual target row disposition')
    shape=read_c09_table_shape_v2(build.pair.source,table,meter=meter)
    stream=_source_stream_identity_v2(build,shape,'row_dispositions')
    member=meter.read_fixed_row(db,'c09_capture_members_v2',('record_ordinal','commitment'),
        'stream_id=? AND primary_key_json=?',(stream.stream_id,canonical_serialize(key)))
    if member is None or member[1]!=c09_row_commitment_v2(proof):
        raise C09PagedCaptureHold('prepared target disposition lost its actual publication member')
    require_c09_capture_member_v2(db,stream,member[0],key,member[1],meter=meter)
    return proof

def _adopted_rows(build,metadata,meter):
    ns=metadata['namespace']
    return (('graph_atoms',(metadata['source_ref'],)),
        ('graph_domain_production_originals_v3',(ns['bot_id'],ns['persona_id'],metadata['operation_id'])))

def _erasure(build,source,meter,*,db=None):
    if source.kind=='Retired' or not source.prepared.original['actual_committed']:return ()
    refs=[]
    for table,key in _adopted_rows(build,source.metadata,meter):
        proof=_row_disposition(build,table,key,meter,db=db)
        if proof[5] in ('payload_erased_retained_facts','derived_removed'):
            refs.append(dict(table_name=table,primary_key=key,disposition=proof[5],
                disposition_digest=canonical_digest(proof),origin_stream_id=proof[7],
                origin_record_ordinal=proof[8]))
    return tuple(refs)

def _reuse_header(build,source,meter):
    if source.cell_name not in ('source','original'):return None
    if not source.prepared.original['actual_committed']:return None
    table,key=_adopted_rows(build,source.metadata,meter)[0 if source.cell_name=='source' else 1]
    proof=_row_disposition(build,table,key,meter)
    if proof[5]!='logical_preserved_v3':
        raise C09PagedCaptureHold('adopted prepared output has no complete logical-preserved target')
    column='value_cell_id' if source.cell_name=='source' else 'original_payload_cell_id'
    where='token=?' if source.cell_name=='source' else 'bot=? AND persona=? AND operation_id=?'
    row=meter.read_fixed_row(build.pair.candidate,table,(column,),where,key)
    if row is None:raise C09PagedCaptureHold('adopted target output reference is absent')
    header=meter.read_fixed_row(build.pair.candidate,'segmented_cells_v1',_HEADER,'cell_id=?',row)
    if header is None:raise C09PagedCaptureHold('adopted target output seal is absent')
    original=json.loads(proof[12])
    if tuple(original['target_cell_seal']['header'])!=header:
        raise C09PagedCaptureHold('reused adopted target header differs from its real producer original')
    return header

def _fragment(db,cell,ordinal,meter):
    row=meter.read_fixed_row(db,'segmented_cell_segments_v1',
        ('ordinal','byte_offset','payload','payload_sha256'),
        'cell_id=? AND ordinal=?',(cell,ordinal))
    if (row is None or not 0<len(row[2])<=16384 or sha256(row[2]).hexdigest()!=row[3]
            or row[0]!=ordinal or row[1]<0):
        raise C09PagedCaptureHold('actual output segment offset/length/SHA differs')
    return row

class PreparedOutputTargetReadV3:
    """Independent bounded Source/target byte comparison; no execution permission."""
    def __init__(self,source,db,header,cursor,*,meter):
        source.require_current(meter=meter)
        self.source,self.header,self.cursor=source,header,cursor
        self.cell=header[0] if header is not None else cursor[0]
        self.total=header[4] if header is not None else cursor[8]
        self.count=header[5] if header is not None else cursor[7]
        self.expected_sha=header[6] if header is not None else cursor[10]
        self.expected_root=header[7] if header is not None else cursor[9]
        self.offset=self.ordinal=self.source_ordinal=self.source_segment_offset=0;self.digest=sha256()
        self.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',self.cell))
        self.complete=False
        if (header is not None and (header[1],header[2],header[3],header[4],header[6],header[8])!=
                ('canonical-json.ascii.v1',source.metadata['source_ref'],
                 source.scope.session.scope.operation_id,source.expected_total_bytes,
                 source.expected_sha256,source.scope.session.scope.scope_digest)):
            raise C09PagedCaptureHold('actual reused target seal crossed namespace/owner/capture/Source bytes')
        _READS.add(self);source.scope.arena.add(self)
    def _source_heap_bytes(self):return 8192
    def advance(self,db,meter):
        if self not in _READS or self.complete:raise C09PagedCaptureHold('actual unfinished target read required')
        self.source.require_current(meter=meter)
        result=copy(self);result.digest=self.digest.copy()
        _READS.add(result);self.source.scope.arena.add(result)
        if self.offset<self.total:
            row=_fragment(db,self.cell,self.ordinal,meter)
            if not row[1]<=self.offset<row[1]+len(row[2]):raise C09PagedCaptureHold('target output segment offset differs')
            amount=min(1024,self.total-self.offset,len(row[2])-(self.offset-row[1]))
            source_offset,source_chunk,source_sha=self.source.read_segment_v3(self.source_ordinal,meter=meter)
            if source_offset!=self.source_segment_offset or not source_offset<=self.offset<source_offset+len(source_chunk):
                raise C09PagedCaptureHold('Source output ordinal/offset differs from actual qualified segment')
            amount=min(amount,len(source_chunk)-(self.offset-source_offset))
            raw=row[2][self.offset-row[1]:self.offset-row[1]+amount]
            if raw!=source_chunk[self.offset-source_offset:self.offset-source_offset+amount]:
                raise C09PagedCaptureHold('prepared target bytes differ from actual immutable Source')
            result.digest.update(raw);result.offset+=amount
            if result.offset==source_offset+len(source_chunk):
                result.source_ordinal+=1;result.source_segment_offset=result.offset
            if result.offset==row[1]+len(row[2]):
                result.root=canonical_digest(('sylanne3.segmented-cell-link.v1',
                    self.root,self.cell,self.ordinal,row[1],len(row[2]),row[3]))
                result.ordinal+=1
            return result
        if (self.offset,self.ordinal,self.digest.hexdigest(),self.root)!=(self.total,self.count,self.expected_sha,self.expected_root):
            raise C09PagedCaptureHold('prepared target independent SHA/root/count/byte EOF differs')
        extra=meter.read_fixed_row(db,'segmented_cell_segments_v1',('ordinal',),
            'cell_id=? AND ordinal>=? ORDER BY ordinal',(self.cell,self.count))
        header=meter.read_fixed_row(db,'segmented_cells_v1',_HEADER,'cell_id=?',(self.cell,))
        if extra is not None or header!=self.header:
            raise C09PagedCaptureHold('prepared target extra-segment EOF or header differs')
        if self.cursor is not None:
            cursor=meter.read_fixed_row(db,'segmented_cell_writes_v1',
                ('cell_id','origin_scope_digest','logical_locator_json','codec_id','producer_operation_id',
                 'erasure_owner_ref','phase','next_ordinal','next_byte_offset','prefix_root','prefix_sha256',
                 'source_cursor_json','expected_total_bytes','verify_next_ordinal','verify_next_byte_offset',
                 'verify_prefix_root','verify_prefix_sha256','cursor_revision'),'cell_id=?',(self.cell,))
            if cursor!=self.cursor:raise C09PagedCaptureHold('prepared target prefix cursor changed at EOF')
        result.complete=True;return result

def _stream(build,meter):
    shape=read_c09_table_shape_v2(build.pair.candidate,TABLE,meter=meter)
    return C09StreamIdentityV2(build.scope.scope_digest,build.pair.source_original.role_source_digest,
        'target_rows',TABLE,shape.schema_digest,shape.primary_key_columns,shape.primary_key_types)

def _publish(build,source,prepared_descriptor,header,cursor,erasure,clock,q):
    db=build.pair.candidate;meter=q.meter;scope=build.scope.scope_digest
    source.require_current(meter=meter)
    clock.require_current(session=build.session,prepared_metadata=clock.prepared_metadata,meter=meter)
    old=meter.read_fixed_row(db,TABLE,COLUMNS,'capture_scope_digest=? AND prepared_digest=? AND cell_name=?',
        (scope,source.prepared_digest,source.cell_name))
    if old is None and clock.expires_status=='ambiguous':raise C09PagedCaptureHold('actual installed output lifecycle clock is ambiguous')
    if old is None and source.kind=='Prefix' and not erasure and clock.expires_status!='alive':
        raise C09PagedCaptureHold('expired unresolved prepared obligation needs actual retirement evidence')
    desc=_source_descriptor(source)
    src_digest=canonical_digest(desc)
    seal=equiv=prefix=retirement=None
    if erasure or source.kind=='Retired':
        outcome='retired'
        retirement=_retirement_original(source,erasure,meter)
    elif header is not None:
        outcome='complete'
        actual_cursor=q.read_cursor(db,header[0])
        if actual_cursor is None or actual_cursor[6]!='sealed':
            raise C09PagedCaptureHold('complete output has no actual sealed writer locator')
        locator=json.loads(actual_cursor[2])
        seal=dict(schema='sylanne3.c09.owner-output-target-seal.v3',scope_digest=scope,
            prepared_digest=source.prepared_digest,cell_name=source.cell_name,
            header9=header,locator=locator,prefix_sha256=header[6])
        equiv=dict(schema='sylanne3.c09.owner-output-logical-equivalence.v3',scope_digest=scope,
            prepared_digest=source.prepared_digest,cell_name=source.cell_name,
            source_cell_descriptor_digest=src_digest,target_cell_seal_digest=canonical_digest(seal),
            codec_id=header[1],total_bytes=header[4],payload_sha256=header[6],
            source_business_operation_id=source.metadata['operation_id'],source_role_digest=source.source_role_digest)
    else:
        outcome='carry_prefix'
        prefix=dict(schema='sylanne3.c09.owner-output-prefix-equivalence.v3',scope_digest=scope,
            prepared_digest=source.prepared_digest,cell_name=source.cell_name,
            source_descriptor_digest=src_digest,cursor=cursor,prefix_sha256=cursor[10],
            prefix_bytes=cursor[8],prefix_segments=cursor[7],prefix_root=cursor[9])
    original=dict(schema='sylanne3.c09.owner-source-output-mapping-original.v3',
        capture_scope_digest=scope,namespace=source.metadata['namespace'],prepared_digest=source.prepared_digest,
        cell_name=source.cell_name,operation_id=source.metadata['operation_id'],attempt_id=source.metadata['attempt_id'],
        source_role_digest=source.source_role_digest,prepared_metadata=source.metadata,
        prepared_row_descriptor=prepared_descriptor,original_owner_cell_id=source.original_owner_cell_id,
        source_cell_descriptor=desc,source_origin=source.scope_original,
        source_disposition=_source_disposition_original(source,meter),outcome=outcome,target_cell_seal=seal,
        prefix_equivalence=prefix,retirement_original=retirement,logical_equivalence_original=equiv,
        clock_original=clock.original,clock_original_digest=clock.original['original_digest'])
    row=(scope,source.prepared_digest,source.cell_name,source.source_role_digest,canonical_digest(prepared_descriptor),
        source.original_owner_cell_id,src_digest,outcome,
        header[0] if header is not None and outcome=='complete' else cursor[0] if outcome=='carry_prefix' else None,
        None if seal is None else canonical_digest(seal),None if equiv is None else canonical_digest(equiv),
        canonical_serialize(original),canonical_digest(original),
        prepared_descriptor['origin_stream_id'],prepared_descriptor['origin_record_ordinal'])
    decode_owner_source_output_mapping_row_v3(row)
    stream=_stream(build,meter)
    with capture_transaction_v2(db):
        begin_capture_stream_v2(db,stream)
        old=meter.read_fixed_row(db,TABLE,COLUMNS,'capture_scope_digest=? AND prepared_digest=? AND cell_name=?',row[:3])
        cursor0=read_capture_cursor_v2(db,stream)
        if old is not None:
            # The as-of clock is immutable once published: replay reads it independently in cold.
            if old[:11]!=row[:11] or old[13:]!=row[13:]:
                raise C09PagedCaptureHold('replayed Owner output mapping changed its body/source/member')
            member=meter.read_fixed_row(db,'c09_capture_members_v2',('record_ordinal','commitment'),
                'stream_id=? AND primary_key_json=?',(stream.stream_id,canonical_serialize(row[:3])))
            if member is None or member[1]!=c09_row_commitment_v2(old):
                raise C09PagedCaptureHold('mapped output replay lost its same-transaction member')
            require_c09_capture_member_v2(db,stream,member[0],row[:3],member[1],meter=meter)
            return old
        meter.write_row(db,TABLE,COLUMNS,row)
        record=C09CaptureRecordV2(row[:3],c09_row_commitment_v2(row));page=append_c09_page_v2(stream,cursor0,(record,))
        q.mutate(db,'INSERT INTO c09_capture_pages_v2 VALUES(?,?,?,?)',
            (stream.stream_id,page.page_index,_wire(page),canonical_serialize([asdict(record)])))
        q.mutate(db,'INSERT INTO c09_capture_members_v2 VALUES(?,?,?,?,?,?)',
            (stream.stream_id,cursor0.record_offset+1,canonical_digest(row[:3]),canonical_serialize(row[:3]),
             record.commitment,page.page_index))
        data=_capture_data_state(db,stream);data['cursor']=asdict(page.next_cursor)
        q.mutate(db,"UPDATE c09_capture_progress_v2 SET progress_json=? WHERE stream_id=? AND phase='data'",
            (canonical_serialize(data),stream.stream_id))
    return row

class PreparedOwnerOutputPublicationV3:
    """One real prepared/name consumer, retained only after its own successful quantum."""
    def __init__(self,build,prepared_digest,cell_name):
        self.build,self.prepared_digest,self.cell_name=build,prepared_digest,cell_name
        self.semantic=self.writer=self.target_read=self.header=self.cursor=None
        self.complete=False;self.row=None
        _PUBLISHERS.add(self)
    def _source_heap_bytes(self):return 8192
    def advance(self):
        from ..segmented_sql_cell_v1 import (open_c09_segmented_target_v1,
            VerifiedPreparedTargetCompleteV3,VerifiedPreparedTargetPrefixV3)
        if self not in _PUBLISHERS or self.complete:raise C09PagedCaptureHold('actual unfinished output publisher required')
        build=self.build;build.require_current()
        target=build.segmented_target_v3
        if target is None:target=open_c09_segmented_target_v1(build.session,build.pair)
        result=copy(self);_PUBLISHERS.add(result)
        with target.quantum() as q:
            meter=q.meter
            scope=build.mapped_source_scope_v3
            if scope is None:scope=build.session.begin_source_physical_read_v3(build.pair,meter=meter)
            scope.require_current(meter=meter);scope.arena.add(result)
            if self.semantic is None:
                result.semantic=PreparedOwnerOutputSemanticReadV3(scope,self.prepared_digest,self.cell_name,meter=meter)
            elif not self.semantic.complete:
                result.semantic=self.semantic.advance(meter)
            else:
                source=self.semantic.require_complete(meter=meter)
                erased=_erasure(build,source,meter)
                if source.kind=='Retired' or erased:
                    result.header=result.cursor=None
                elif self.header is None and self.cursor is None:
                    result.header=_reuse_header(build,source,meter)
                    if result.header is None:
                        writer=target.begin_prepared_owner_output_copy_v3(q,source=source) if self.writer is None else self.writer.copy_progress_v3(q)
                        if writer.phase=='write':writer.advance(q)
                        elif writer.phase=='replay_prefix':writer.replay_prefix(q)
                        elif writer.phase=='verify':
                            sealed=writer.verify_and_seal(q)
                            if type(sealed) is VerifiedPreparedTargetCompleteV3:
                                result.header=q.read_header(build.pair.candidate,sealed.ref.cell_id)
                            elif type(sealed) is VerifiedPreparedTargetPrefixV3:result.cursor=sealed.cursor
                        else:raise C09PagedCaptureHold('prepared writer has no actual unfinished phase')
                        result.writer=writer
                elif self.target_read is None:
                    result.target_read=PreparedOutputTargetReadV3(source,build.pair.candidate,self.header,self.cursor,meter=meter)
                elif not self.target_read.complete:
                    result.target_read=self.target_read.advance(build.pair.candidate,meter)
                ready=source.kind=='Retired' or erased or (self.target_read is not None and self.target_read.complete)
                if ready:
                    prepared=scope.read_owner_source_prepared_metadata_v3(self.prepared_digest,meter=meter)
                    clock=build.session._control.maintenance._installed_lifecycle_clock_v3.issue_owner_output_disposition_clock_v3(
                        session=build.session,prepared_metadata=prepared,meter=meter)
                    result.row=_publish(build,source,_prepared_member(build,source,meter),
                        self.header,self.cursor,erased,clock,q)
                    result.complete=True
        # Prospective state is never adopted from an unsuccessful real reservation.
        if result.semantic is not None:result.semantic.quantum_completed=True
        build.segmented_target_v3=target;build.mapped_source_scope_v3=scope
        build.require_current();return result
