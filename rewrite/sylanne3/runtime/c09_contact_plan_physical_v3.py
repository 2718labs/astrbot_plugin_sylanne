"""Exact C09 physical Contact Plan3 row capture and logical preservation."""
from copy import copy
import json
from types import SimpleNamespace
from .c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
from .c09_graph_row_codec_v2 import _C09RegisteredGraphValueV3
from .c09_paged_sql_v2 import C09PagedCaptureHold,current_c09_sql_meter_v2,require_c09_reserved_meter_v3
from .c09_logical_source_v3 import read_c09_logical_source_shape_v3,begin_logical_source_row_v3
from .contact_plan_adoption_v3 import TABLE,COLUMNS,SIGN_KIND,contact_plan_logical_descriptor_v3,validate_contact_plan_original_payload_v3
from ..runtime_contracts import canonical_digest,canonical_serialize


class C09MappedContactPlanCaptureV3:
    def __init__(self,build,shape,key,metadata,*,pattern_kind=None,pattern_ref=None):
        if type(build) is not InstalledGraphRebaseBuildV2 or shape.table!=TABLE or shape.columns!=COLUMNS:
            raise C09PagedCaptureHold('actual installed Graph-role Contact Plan3 physical row required')
        build.require_current();meter=current_c09_sql_meter_v2()
        self.build,self.shape,self.key,self.metadata = build,shape,tuple(key),metadata
        self.pattern_kind,self.pattern_ref,self.quantum_completed = pattern_kind,pattern_ref,False
        self.scope = build.session.begin_source_physical_read_v3(build.pair,meter=meter)
        self.logical_shape = read_c09_logical_source_shape_v3(self.scope,TABLE,meter=meter)
        self.row = begin_logical_source_row_v3(self.scope,self.logical_shape,self.key,meter)
        self.physical = meter.read_fixed_row(build.pair.source,TABLE,COLUMNS,'bot=? AND persona=? AND contact_id=?',self.key)
        if self.physical is None:
            raise C09PagedCaptureHold('actual Contact physical Plan3 row absent')
        issuer = build.session.get_c09_domain_original_issuer_v2()
        issuer._signer.verify(SIGN_KIND,canonical_serialize(contact_plan_logical_descriptor_v3(self.physical)),self.physical[13])
        self.parsers = {column:_C09RegisteredGraphValueV3(source_arena=self.scope.arena,ensure_ascii=True)
            for column in ('payload_json','source_selection_json')}
        self.finished = set()
        self.value = SimpleNamespace(complete=False)
    def next_quantum(self,budget):
        meter = require_c09_reserved_meter_v3(budget)
        self.build.require_current();self.scope.require_current(meter=meter)
        result = copy(self)
        result.parsers = {key:value.copy()for key,value in self.parsers.items()}
        result.finished = set(self.finished)
        result.value = copy(self.value)
        result.quantum_completed = False
        if not self.row.complete:
            result.row = self.row.advance(meter)
            fragment = result.row.last_logical_fragment
            if fragment is not None and fragment[0] in result.parsers:
                result.parsers[fragment[0]].feed(fragment[1],lambda event:None)
            eof = result.row.last_cell_eof
            if eof in result.parsers:
                parsed=result.parsers[eof].finish()
                expected=(self.physical[6],self.physical[7]) if eof=='payload_json'else(self.physical[10],self.physical[11])
                if (parsed.byte_count,parsed.sha256)!=expected:
                    raise C09PagedCaptureHold('Contact Plan3 actual physical mapped canonical EOF differs')
                result.finished.add(eof)
        elif not result.value.complete:
            if result.finished!={'payload_json','source_selection_json'}:
                raise C09PagedCaptureHold('Contact Plan3 physical mapping omitted an actual body cell')
            payload,selection = (result.parsers[column].value for column in ('payload_json','source_selection_json'))
            plan,expression,proof = validate_contact_plan_original_payload_v3(payload)
            if (selection['plan']!=payload['plan'] or selection['contact_id']!=self.key[2]
                    or proof.producing_operation_id!=self.physical[3] or payload['receipt_digest']!=self.physical[12]):
                raise C09PagedCaptureHold('Contact Plan3 mapped body and independent Source selection differ')
            result.plan,result.expression,result.proof,result.value.complete=plan,expression,proof,True
        self.build.require_current()
        return result
    def require_complete(self,build,shape,key,metadata):
        self.scope.require_current(meter=current_c09_sql_meter_v2())
        if (build is not self.build or shape!=self.shape or tuple(key)!=self.key or metadata!=self.metadata
                or not self.quantum_completed or not self.row.complete or not self.value.complete):
            raise C09PagedCaptureHold('actual Contact mapped row/whole semantic EOF/quantum proof required')
        return self.row.result.commitment
    def require_nested_hit(self,build,shape,key,metadata,small_sql):
        self.require_complete(build,shape,key,metadata)
        from .c09_closure_index_v2 import _nested_pattern_hit
        if self.pattern_kind not in ('atom','source_id') or type(self.pattern_ref) is not str:
            raise C09PagedCaptureHold('Contact physical closure has no exact actual pattern')
        return _nested_pattern_hit(self.parsers['payload_json'].value,self.pattern_ref,
            source_id=self.pattern_kind=='source_id')


def contact_plan_logical_preservation_original_v3(scope_digest,key,descriptor,source_headers,target_headers,new_commitment):
    if len(descriptor['cell_bindings'])!=2 or len(source_headers)!=2 or len(target_headers)!=2:
        raise C09PagedCaptureHold('Contact Plan3 preservation requires both actual physical cells')
    expected_columns=('payload_json','source_selection_json')
    seals=[]
    for binding,column,source,target in zip(descriptor['cell_bindings'],expected_columns,source_headers,target_headers,strict=True):
        if (binding['logical_column']!=column or tuple(binding['source_header9'])!=tuple(source)
                or binding['cell_id']!=source[0] or canonical_digest(tuple(source))!=binding['header_digest']
                or target[2]!=source[2] or (target[1],target[4],target[6])!=
                    (binding['codec_id'],binding['total_bytes'],binding['payload_sha256'])):
            raise C09PagedCaptureHold('Contact Plan3 actual Source/target header/logical byte preservation differs')
        seals.append({'logical_column':column,'header':tuple(target),'codec_id':binding['codec_id'],
            'total_bytes':binding['total_bytes'],'payload_sha256':binding['payload_sha256']})
    seal={'schema':'d10.contact-plan-target-seal.v3','scope_digest':scope_digest,'role':'graph','table_name':TABLE,
        'primary_key':key,'physical_row_commitment':new_commitment,'members':tuple(seals)}
    equivalence={'schema':'d10.contact-plan-logical-equivalence.v3','scope_digest':scope_digest,'role':'graph',
        'table_name':TABLE,'primary_key':key,'source_role_digest':descriptor['source_role_digest'],
        'logical_shape_digest':descriptor['logical_shape_digest'],'source_logical_row_descriptor_digest':canonical_digest(descriptor),
        'source_logical_row_commitment':descriptor['logical_row_commitment'],
        'target_logical_row_commitment':descriptor['logical_row_commitment'],'source_cell_headers':tuple(tuple(row)for row in source_headers),
        'target_cell_seal_digest':canonical_digest(seal)}
    return (canonical_digest(descriptor),canonical_digest(seal),canonical_digest(equivalence),
        canonical_serialize({'target_cell_seal':seal,'logical_equivalence_original':equivalence}))


class _ContactPlanTargetV3:
    def __init__(self,build,capture):
        self.build,self.capture,self.key = build,capture,capture.key
        self.index,self.writer,self.seals = 0,None,[]


def advance_contact_plan_target_v3(build,progress,shape):
    from ..segmented_sql_cell_v1 import open_c09_segmented_target_v1,VerifiedSealedCellV1
    from .c09_closure_index_v2 import C09ClosureIndexV2
    from .c09_paged_sql_v2 import (capture_transaction_v2,_load_census,_capture_data_state,read_capture_cursor_v2,
        read_c09_next_row_metadata_v2,require_c09_capture_member_v2,c09_row_commitment_v2,_wire)
    from .c09_paged_capture_contract_v2 import C09CaptureRecordV2,append_c09_page_v2
    from .c09_graph_rebase_candidate_v2 import (_source_stream_identity_v2,_actual_source_locator_v2,
        _read_graph_disposition_original_row_v3,GRAPH_DISPOSITION_COLUMNS_V2,GRAPH_DISPOSITION_COLUMNS_V3,
        _save_graph_progress_v2,_graph_step_report_v2)
    from ..authority_service.c09_authority_storage_rebase import _row_commitment
    from dataclasses import asdict
    from time import monotonic_ns
    build.require_current()
    key=tuple(progress['row_complete'])
    capture=build.source_row_capture_v3
    if type(capture) is not C09MappedContactPlanCaptureV3 or capture.key!=key:
        raise C09PagedCaptureHold('Contact target requires its actual completed two-cell Source producer')
    if build.segmented_target_v3 is None:
        build.segmented_target_v3=open_c09_segmented_target_v1(build.session,build.pair)
    target=build.segmented_target_v3;started=monotonic_ns()
    state=build.contact_plan_target_v3
    if state is None:
        state=_ContactPlanTargetV3(build,capture)
    elif state.build is not build or state.capture is not capture or state.key!=key:
        raise C09PagedCaptureHold('Contact target state changed actual Source row/descriptor')
    prospective=copy(state);prospective.seals=list(state.seals)
    next_progress=dict(progress)
    with target.quantum() as quantum:
        meter=quantum.meter;candidate,source=build.pair.candidate,build.pair.source
        capture.require_complete(build,shape,key,capture.metadata)
        born=build.contact_plan_birth_proofs_v3.get(key)
        if born is None:
            raise C09PagedCaptureHold('Contact target has no actual complete Source birth joins')
        born.require_complete(build,meter)
        closure=C09ClosureIndexV2(candidate,build.scope)
        if closure._state()[3]!='sealed':
            raise C09PagedCaptureHold('Contact target requires actual complete accepted closure')
        removed=closure.contains_operation(capture.proof.producing_operation_id) or progress.get('nested_hit',False)
        stream=_source_stream_identity_v2(build,shape,'row_dispositions')
        locator=_actual_source_locator_v2(build,shape,meter)
        member=meter.read_fixed_row(candidate,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND primary_key_json=?',(locator.identity.stream_id,canonical_serialize(key)))
        if member is None or member[1]!=capture.row.result.commitment:
            raise C09PagedCaptureHold('Contact target Source member commitment differs')
        require_c09_capture_member_v2(candidate,locator.identity,member[0],key,member[1],meter=meter)
        cursor=read_capture_cursor_v2(candidate,stream)
        found=read_c09_next_row_metadata_v2(source,shape,cursor.last_key)
        existing=_read_graph_disposition_original_row_v3(candidate,build.scope.scope_digest,shape.table,key,meter)
        if existing is None and (found is None or found[0]!=key):
            raise C09PagedCaptureHold('Contact target is outside its actual Source publication cursor')
        if not removed and prospective.index<2:
            column=('payload_json','source_selection_json')[prospective.index]
            writer=prospective.writer
            if writer is None:
                writer=target.begin_mapped_cell_copy(quantum,source_row=capture.row.result,column=column)
            else:
                writer=writer.copy_progress_v3(quantum)
            if writer.phase=='write':writer.advance(quantum)
            elif writer.phase=='replay_prefix':writer.replay_prefix(quantum)
            elif writer.phase=='verify':
                seal=writer.verify_and_seal(quantum)
                if type(seal) is VerifiedSealedCellV1:
                    prospective.seals.append(seal);prospective.index+=1;writer=None
            else:
                raise C09PagedCaptureHold('Contact target copy needs exact same-prefix recovery')
            prospective.writer=writer
            next_progress['scan_phase']='contact_plan_publish' if prospective.index==2 else 'contact_plan_copy'
            with capture_transaction_v2(candidate):
                _save_graph_progress_v2(build,'target',next_progress,meter)
        else:
            row=None;new_commitment=None
            if not removed:
                refs=[seal.require_current(target,quantum=quantum,table=shape.table,primary_key=key,column=column)
                    for seal,column in zip(prospective.seals,('payload_json','source_selection_json'),strict=True)]
                values=list(capture.physical);values[4],values[9]=refs[0].cell_id,refs[1].cell_id;row=tuple(values)
                if contact_plan_logical_descriptor_v3(row)!=contact_plan_logical_descriptor_v3(capture.physical):
                    raise C09PagedCaptureHold('Contact target changed its signed logical record')
                new_commitment=_row_commitment(shape.table,shape.columns,row)
            proof=(build.scope.scope_digest,shape.table,canonical_digest((shape.table,key)),canonical_serialize(key),
                member[1],'derived_removed' if removed else 'logical_preserved_v3',new_commitment,locator.identity.stream_id,member[0])
            disposition_table='c09_graph_dispositions_v2' if removed else 'c09_graph_dispositions_v3'
            disposition_columns=GRAPH_DISPOSITION_COLUMNS_V2 if removed else GRAPH_DISPOSITION_COLUMNS_V3
            if not removed:
                source_headers=tuple(tuple(binding['source_header9'])for binding in capture.row.result.descriptor['cell_bindings'])
                target_headers=tuple(quantum.read_header(candidate,ref.cell_id)for ref in refs)
                proof+=contact_plan_logical_preservation_original_v3(build.scope.scope_digest,key,capture.row.result.descriptor,
                    source_headers,target_headers,new_commitment)
            with capture_transaction_v2(candidate):
                _load_census(candidate,stream);data=_capture_data_state(candidate,stream)
                actual=meter.read_row(candidate,shape,key)
                if existing is not None:
                    if existing!=proof or actual!=row:
                        raise C09PagedCaptureHold('Contact actual target publication/disposition retry differs')
                    sealed=meter.read_fixed_row(candidate,'c09_capture_members_v2',('record_ordinal','commitment'),
                        'stream_id=? AND primary_key_json=?',(stream.stream_id,canonical_serialize(key)))
                    if sealed is None or sealed[1]!=c09_row_commitment_v2(proof):
                        raise C09PagedCaptureHold('Contact target publication replay lost its actual page member')
                    require_c09_capture_member_v2(candidate,stream,sealed[0],key,sealed[1],meter=meter)
                else:
                    if actual is not None or data['eof'] is not None:
                        raise C09PagedCaptureHold('Contact target row exists without atomic actual disposition')
                    if row is not None:meter.write_row(candidate,shape.table,shape.columns,row)
                    meter.write_row(candidate,disposition_table,disposition_columns,proof)
                    record=C09CaptureRecordV2(key,c09_row_commitment_v2(proof))
                    page=append_c09_page_v2(stream,cursor,(record,))
                    quantum.mutate(candidate,'INSERT INTO c09_capture_pages_v2 VALUES(?,?,?,?)',
                        (stream.stream_id,page.page_index,_wire(page),json.dumps([asdict(record)],sort_keys=True,separators=(',',':'))))
                    quantum.mutate(candidate,'INSERT INTO c09_capture_members_v2 VALUES(?,?,?,?,?,?)',
                        (stream.stream_id,cursor.record_offset+1,canonical_digest(key),canonical_serialize(key),record.commitment,page.page_index))
                    data['cursor']=asdict(page.next_cursor)
                    quantum.mutate(candidate,"UPDATE c09_capture_progress_v2 SET progress_json=? WHERE stream_id=? AND phase='data'",
                        (canonical_serialize(data),stream.stream_id))
                next_progress.update(scan_phase='patterns',pattern_kind='atom',pattern_after=None,nested_hit=False,row_complete=None)
                _save_graph_progress_v2(build,'target',next_progress,meter)
            prospective=None
    build.contact_plan_target_v3=prospective
    if prospective is None:build.source_row_capture_v3=None
    build.require_current()
    return _graph_step_report_v2(build,'target',meter,started)


class _ContactPlanColdCellsV3:
    def __init__(self,progress,shape,key):
        from .c09_graph_rebase_candidate_v2 import GraphRebaseColdProgressV2,_SWEEP
        from hashlib import sha256
        if type(progress) is not GraphRebaseColdProgressV2 or progress._issuer is not _SWEEP or shape.table!=TABLE:
            raise C09PagedCaptureHold('actual independently opened Graph cold Contact reader required')
        progress.session.require_current();progress.pair.require_current()
        self.progress,self.shape,self.key=progress,shape,tuple(key)
        self.row=None;self.index=0;self.headers=[];self.parsers=[]
        self.header,self.parser,self.fragment=None,None,b''
        self.fragment_offset,self.ordinal,self.offset,self.complete=0,0,0,False
        self.hash=sha256();self.root=None
    def advance(self,meter):
        from hashlib import sha256
        self.progress.session.require_current();self.progress.pair.require_current()
        db=self.progress.read_db
        if self.row is None:
            self.row=meter.read_fixed_row(db,TABLE,COLUMNS,'bot=? AND persona=? AND contact_id=?',self.key)
            if self.row is None:
                raise C09PagedCaptureHold('Contact cold target physical record absent')
            self.progress.session.get_c09_domain_original_issuer_v2()._signer.verify(SIGN_KIND,
                canonical_serialize(contact_plan_logical_descriptor_v3(self.row)),self.row[13])
            return False
        actual=meter.read_fixed_row(db,TABLE,COLUMNS,'bot=? AND persona=? AND contact_id=?',self.key)
        if actual!=self.row:
            raise C09PagedCaptureHold('Contact cold target immutable record changed during EOF')
        if self.index==2:
            self.complete=True
            return True
        cell=self.row[4]if self.index==0 else self.row[9]
        if self.header is None:
            self.header=meter.read_fixed_row(db,'segmented_cells_v1',
                ('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
                    'payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(cell,))
            expected=('canonical-json.ascii.v1',self.row[6],self.row[7])if self.index==0 else('canonical-json.ascii.v1',self.row[10],self.row[11])
            if self.header is None or (self.header[1],self.header[4],self.header[6])!=expected:
                raise C09PagedCaptureHold('Contact cold target signed physical descriptor differs')
            self.parser=_C09RegisteredGraphValueV3(source_arena=self.progress.session._source_parser_arena_v3,ensure_ascii=True)
            self.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell))
            return False
        if self.fragment_offset<len(self.fragment):
            end=min(len(self.fragment),self.fragment_offset+1024)
            self.parser.feed(self.fragment[self.fragment_offset:end],lambda event:None)
            self.fragment_offset=end
            return False
        if self.ordinal<self.header[5]:
            segment=meter.read_fixed_row(db,'segmented_cell_segments_v1',('byte_offset','payload','payload_sha256'),
                'cell_id=? AND ordinal=?',(cell,self.ordinal))
            if (segment is None or segment[0]!=self.offset or type(segment[1]) is not bytes
                    or not 0<len(segment[1])<=16384 or sha256(segment[1]).hexdigest()!=segment[2]):
                raise C09PagedCaptureHold('Contact cold actual target segment order/length/hash differs')
            self.hash.update(segment[1])
            self.root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.root,cell,self.ordinal,
                self.offset,len(segment[1]),segment[2]))
            self.ordinal+=1;self.offset+=len(segment[1]);self.fragment=segment[1];self.fragment_offset=0
            return False
        extra=meter.read_fixed_row(db,'segmented_cell_segments_v1',('ordinal',),
            'cell_id=? AND ordinal>=? ORDER BY ordinal',(cell,self.ordinal))
        parsed=self.parser.finish()
        if (extra is not None or self.offset!=self.header[4] or self.hash.hexdigest()!=self.header[6]
                or self.root!=self.header[7] or (parsed.byte_count,parsed.sha256)!=(self.header[4],self.header[6])):
            raise C09PagedCaptureHold('Contact cold target independent complete physical/canonical EOF differs')
        self.headers.append(self.header);self.parsers.append(self.parser)
        self.index+=1;self.header=self.parser=None;self.fragment=b'';self.fragment_offset=self.ordinal=self.offset=0
        self.hash=sha256();self.root=None
        return False


def verify_cold_contact_plan_v3(progress,shape,key,metadata,meter,*,verify_semantics=True):
    from .c09_closure_index_v2 import C09ClosureIndexV2
    from .c09_graph_rebase_candidate_v2 import (_advance_source_nested_match_v3,_actual_streamed_source_origin_v3,
        _read_graph_disposition_original_row_v3,_require_graph_logical_disposition_original_v3)
    from .c09_storage_rebase_contract_v1 import GraphRowDispositionV1
    from ..authority_service.c09_authority_storage_rebase import _row_commitment
    build=progress.cold_build;build.require_current()
    closure=C09ClosureIndexV2(progress.read_db,progress.session.scope)
    if closure._state()[3]!='sealed' or not verify_semantics and not progress.source_semantic_eof:
        raise C09PagedCaptureHold('Contact cold requires actual accepted closure/independent Source semantics')
    hit,done,pending,_=_advance_source_nested_match_v3(build,shape,key,metadata,closure,
        progress.pattern_progress,meter.budget,meter)
    progress.prospective_source_capture_v3=pending
    if not done:
        return None
    capture=pending if pending is not None else build.source_row_capture_v3
    if type(capture) is not C09MappedContactPlanCaptureV3:
        raise C09PagedCaptureHold('Contact cold lost its actual completed two-cell Source producer')
    origin=_actual_streamed_source_origin_v3(build,shape,key,metadata,capture,meter)
    proof=_read_graph_disposition_original_row_v3(progress.read_db,progress.session.scope.scope_digest,shape.table,key,meter)
    if proof is None or (proof[4],proof[7],proof[8])!=(origin['origin_commitment'],origin['origin_stream_id'],origin['origin_record_ordinal']):
        raise C09PagedCaptureHold('Contact cold Source member/stream/ordinal differs')
    removed=closure.contains_operation(capture.proof.producing_operation_id) or hit
    if removed:
        actual=meter.read_fixed_row(progress.read_db,TABLE,COLUMNS,'bot=? AND persona=? AND contact_id=?',tuple(key))
        if actual is not None or proof[5:7]!=('derived_removed',None):
            raise C09PagedCaptureHold('Contact erased Plan retained target bodies or refs')
        result=GraphRowDispositionV1(proof[2],proof[4],proof[5],proof[6])
    else:
        reader=progress.contact_plan_cold_cells_v3
        if reader is None:
            reader=_ContactPlanColdCellsV3(progress,shape,key)
        if reader.shape!=shape or reader.key!=tuple(key):
            raise C09PagedCaptureHold('Contact cold cell cursor crossed its actual row')
        prospective=copy(reader)
        prospective.headers=list(reader.headers);prospective.parsers=list(reader.parsers)
        prospective.hash=reader.hash.copy()
        if reader.parser is not None:prospective.parser=reader.parser.copy()
        progress.prospective_contact_plan_cold_v3=prospective
        if not prospective.advance(meter):
            return None
        values=list(capture.physical);values[4],values[9]=prospective.headers[0][0],prospective.headers[1][0]
        if (prospective.row!=tuple(values) or _row_commitment(TABLE,COLUMNS,prospective.row)!=proof[6]
                or any(prospective.parsers[index].value!=capture.parsers[column].value
                    for index,column in enumerate(('payload_json','source_selection_json')))):
            raise C09PagedCaptureHold('Contact cold target full bytes/physical row differ from captured Source')
        result=_require_graph_logical_disposition_original_v3(build,progress.read_db,shape,key,proof,meter,
            target_header=tuple(prospective.headers))
        progress.prospective_contact_plan_cold_v3=None
        progress.contact_plan_cold_cells_v3=None
    progress.pattern_progress={'pattern_kind':'atom','pattern_after':None,'nested_hit':False}
    return result


class C09MappedContactDomainCaptureV3:
    def __init__(self,build,shape,key,metadata,*,pattern_kind=None,pattern_ref=None):
        from .domain_production_originals_v1 import PHYSICAL_TABLE
        from ..runtime_contracts import NamespaceId
        if type(build) is not InstalledGraphRebaseBuildV2 or shape.table!=PHYSICAL_TABLE:
            raise C09PagedCaptureHold('actual Contact physical domain Source capture requires installed Graph build')
        build.require_current();meter=current_c09_sql_meter_v2()
        self.build,self.shape,self.key,self.metadata=build,shape,tuple(key),metadata
        self.pattern_kind,self.pattern_ref,self.quantum_completed=pattern_kind,pattern_ref,False
        self.namespace,self.operation_id=NamespaceId(*key[:2]),key[2]
        self.scope=build.session.begin_source_physical_read_v3(build.pair,meter=meter)
        self.logical_shape=read_c09_logical_source_shape_v3(self.scope,shape.table,meter=meter)
        self.row=begin_logical_source_row_v3(self.scope,self.logical_shape,self.key,meter)
        self.identity=meter.read_fixed_row(build.pair.source,shape.table,
            ('domain','operation_kind','original_digest','original_payload_cell_id','prepared_digest','bundle_digest',
                'receipt_digest','request_digest'),'bot=? AND persona=? AND operation_id=?',self.key)
        if self.identity is None or self.identity[:2]!=('d08','adopt_contact_expression_plan_v2'):
            raise C09PagedCaptureHold('Contact Source domain original has another actual registered kind')
        self.header=self.scope.read_cell_header_v3(self.identity[3],meter=meter)
        if self.header[6]!=self.identity[2]:
            raise C09PagedCaptureHold('Contact Source domain original complete cell descriptor differs')
        self.value=SimpleNamespace(parser=_C09RegisteredGraphValueV3(source_arena=self.scope.arena,ensure_ascii=True),complete=False)
        self.aux={column:_C09RegisteredGraphValueV3(source_arena=self.scope.arena,ensure_ascii=True)
            for column in ('receipt_json','read_versions_json')}
        self.aux_finished=set();self.graph_refs=set()
    def next_quantum(self,budget):
        meter=require_c09_reserved_meter_v3(budget);self.build.require_current();self.scope.require_current(meter=meter)
        result=copy(self);result.quantum_completed=False
        result.value=copy(self.value);result.value.parser=self.value.parser.copy()
        result.aux={column:parser.copy()for column,parser in self.aux.items()}
        result.aux_finished=set(self.aux_finished);result.graph_refs=set(self.graph_refs)
        if not self.row.complete:
            result.row=self.row.advance(meter);fragment=result.row.last_logical_fragment
            if fragment is not None:
                name,raw=fragment
                if name=='original_payload_json':result.value.parser.feed(raw,lambda event:None)
                elif name in result.aux:result.aux[name].feed(raw,lambda event:None)
            eof=result.row.last_cell_eof
            if eof=='original_payload_json':
                parsed=result.value.parser.finish()
                if (parsed.byte_count,parsed.sha256)!=(self.header[4],self.identity[2]):
                    raise C09PagedCaptureHold('Contact domain physical original canonical EOF differs')
            elif eof in result.aux:
                result.aux[eof].finish();result.aux_finished.add(eof)
        elif not result.value.complete:
            from .domain_production_originals_v1 import _receipt
            from .domain_production_original_codec_v1 import _PAYLOAD_FIELDS
            from .contact_plan_adoption_v3 import validate_contact_plan_original_payload_v3
            from ..domains.d01.production_operations_v1 import plain_v1
            from ..domains.d08.contact_plan_v3 import decode_contact_plan_member_v3,PROVENANCE,contact_plan_keys_v3
            from ..domains.d08.contact_plan_v2 import decode_contact_plan_v2
            payload=result.value.parser.value
            if (type(payload) is not dict or set(payload)!=set(_PAYLOAD_FIELDS)
                    or payload['schema']!='d08.current-adopt_contact_expression_plan_v2.v1'
                    or payload['namespace']!={'bot_id':self.namespace.bot_id,'persona_id':self.namespace.persona_id}
                    or payload['identity']['operation_id']!=self.operation_id or payload['coverage']!='complete'
                    or payload['missing_inputs']!=[] or payload['continuation_ref'] is not None):
                raise C09PagedCaptureHold('Contact domain original exact phase/namespace/canonical schema differs')
            proof=decode_contact_plan_member_v3(PROVENANCE,payload['provenance']['proof'])
            plan=decode_contact_plan_v2(payload['provenance']['contact_plan'])
            if proof.plan!=plan or proof.producing_operation_id!=self.operation_id:
                raise C09PagedCaptureHold('Contact domain original exact metadata provenance differs')
            receipt_raw=result.aux['receipt_json'].value if 'receipt_json' in result.aux_finished else json.loads(self.row.metadata['receipt_json'])
            reads=result.aux['read_versions_json'].value if 'read_versions_json' in result.aux_finished else json.loads(self.row.metadata['read_versions_json'])
            receipt=_receipt(receipt_raw)
            if (canonical_digest(receipt)!=self.identity[6] or receipt.operation_id!=self.operation_id
                    or receipt.operation_digest!=self.identity[5] or receipt.status!='committed'
                    or reads!=[[v.key.token,v.revision]for v in receipt.read_versions]
                    or {(v.key.token,v.revision)for v in receipt.write_versions}!={(key.token,1)for key in contact_plan_keys_v3(plan)}):
                raise C09PagedCaptureHold('Contact domain original actual W01 receipt/read/write identities differ')
            bundle=meter.read_fixed_row(self.build.pair.source,'graph_bundle_operations',
                ('digest','activity_id','effect_id','commit_seq'),'bot=? AND persona=? AND operation_id=?',self.key)
            if bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
                raise C09PagedCaptureHold('Contact domain original has no actual shared W01 producer')
            expected={r.ref:r.revision for r in proof.historical_reads}
            if reads!=[[r.ref,r.revision]for r in proof.historical_reads]:
                raise C09PagedCaptureHold('Contact domain original readset order differs from its immutable Plan birth')
            result.graph_refs.update(expected)
            result.proof,result.plan,result.value.complete=proof,plan,True
        self.build.require_current();return result
    def require_complete(self,build,shape,key,metadata):
        self.scope.require_current(meter=current_c09_sql_meter_v2())
        if (self.build is not build or self.shape!=shape or self.key!=tuple(key) or self.metadata!=metadata
                or not self.quantum_completed or not self.row.complete or not self.value.complete):
            raise C09PagedCaptureHold('Contact domain actual whole row/canonical/semantic EOF required')
        return self.row.result.commitment
    def require_nested_hit(self,build,shape,key,metadata,small_sql):
        from .c09_closure_index_v2 import _nested_pattern_hit
        self.require_complete(build,shape,key,metadata)
        if self.pattern_kind not in ('atom','source_id') or type(self.pattern_ref) is not str:
            raise C09PagedCaptureHold('Contact domain closure requires its exact actual Source pattern')
        return _nested_pattern_hit(self.value.parser.value,self.pattern_ref,source_id=self.pattern_kind=='source_id')
