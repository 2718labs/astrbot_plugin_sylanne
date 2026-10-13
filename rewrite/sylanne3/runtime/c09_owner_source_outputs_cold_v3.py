"""Independent six-name Source/material and immutable mapping/member full EOF."""
from __future__ import annotations
from copy import copy
from weakref import WeakSet
import json
from .c09_paged_sql_v2 import C09PagedCaptureHold,read_c09_table_shape_v2
from .c09_paged_capture_contract_v2 import (
    C09StreamIdentityV2,C09CompleteStreamV2,C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2)
from .c09_historical_proof_row_codec_v2 import _require_exact_structural_member
from .c09_owner_source_output_mappings_v3 import TABLE,COLUMNS,NAMES,decode_owner_source_output_mapping_row_v3
from .c09_owner_source_output_publication_v3 import (
    PreparedOutputTargetReadV3,_source_descriptor,_prepared_member,_erasure,_retirement_original)
from .c09_prepared_owner_output_semantics_v3 import PreparedOwnerOutputSemanticReadV3
from ..runtime_contracts import canonical_digest,canonical_serialize
_READS=WeakSet()
_PROOFS=WeakSet()
_TOKEN=object()

def _family(progress,db,meter):
    row=meter.read_fixed_row(db,'c09_graph_target_directory_v2',
        ('scope_digest','family','identity_json','complete_json'),
        'scope_digest=? AND family=?',(progress.session.scope.scope_digest,TABLE))
    if row is None:raise C09PagedCaptureHold('six outputs have no actual complete target family')
    _require_exact_structural_member(db,progress.candidate.target_directory,row[:2],row,meter)
    stream=c09_paged_value_from_wire_v2(json.loads(row[2]),C09StreamIdentityV2)
    seal=c09_paged_value_from_wire_v2(json.loads(row[3]),C09CompleteStreamV2)
    if stream.family!=TABLE or stream.scope_digest!=progress.session.scope.scope_digest or seal.stream_id!=stream.stream_id:
        raise C09PagedCaptureHold('Owner output family crossed actual scope/table/stream')
    return C09SealedStreamLocatorV2('graph',stream,seal)

def _clock_original(progress,source,original,meter):
    clock=original['clock_original'];details=clock['details']
    kind='capture_owner_output_clock_v3:'+canonical_digest(details)
    actual=progress.session._control.maintenance.control.read_build_original_v1(
        operation_id=progress.session.scope.operation_id,kind=kind)
    if actual!=clock or clock['original_digest']!=original['clock_original_digest']:
        raise C09PagedCaptureHold('as-of Owner output clock lacks the actual signed Control original')
    prepared=source.scope.read_owner_source_prepared_metadata_v3(source.prepared_digest,meter=meter)
    if (details['schema']!='sylanne3.c09.owner-output-disposition-clock.v3'
            or details['scope_digest']!=progress.session.scope.scope_digest
            or details['maintenance_operation_id']!=progress.session.scope.operation_id
            or details['prepared_digest']!=source.prepared_digest
            or details['prepared_values_digest']!=canonical_digest(tuple(prepared.row))
            or details['graph_role_source_digest']!=source.source_role_digest
            or details['old_manifest_digest']!=progress.session.scope.old_manifest_digest
            or details['expected_pointer_version']!=progress.session.scope.expected_pointer_version
            or details['original_deadline_utc']!=source.metadata['original_deadline_utc']):
        raise C09PagedCaptureHold('as-of clock changed actual prepared/Source/capture/deadline binding')
    reading=details['reading'];lower=reading['utc_seconds']-reading['utc_error_seconds']
    upper=reading['utc_seconds']+reading['utc_error_seconds']
    if not reading['healthy'] or (upper>=details['original_deadline_utc'] and lower<details['original_deadline_utc']):
        raise C09PagedCaptureHold('as-of output lifecycle clock was unhealthy or ambiguous')
    if original['outcome']=='carry_prefix' and upper>=details['original_deadline_utc']:
        raise C09PagedCaptureHold('output prefix was carried after its actual original deadline')

class PreparedOwnerOutputsColdReadV3:
    """All prepared/name forward and mapping reverse scans; each advance is prospective."""
    def __init__(self,progress,*,meter):
        from .c09_graph_rebase_candidate_v2 import GraphRebaseColdProgressV2
        if type(progress) is not GraphRebaseColdProgressV2:
            raise C09PagedCaptureHold('actual independent Graph cold progress required')
        self.progress=progress;self.scope=progress.cold_build.mapped_source_scope_v3
        if self.scope is None:self.scope=progress.session.begin_source_physical_read_v3(progress.pair,meter=meter)
        self.scope.require_current(meter=meter)
        self.family=_family(progress,progress.read_db,meter)
        self.phase='forward';self.after=None;self.prepared_digest=None;self.name_index=0
        self.semantic=self.target_read=self.row=None
        self.count=self.reverse_count=0;self.reverse_after=None
        self.forward_root=canonical_digest(('c09.owner-output-forward.v3',progress.session.scope.scope_digest))
        self.reverse_root=self.forward_root
        self.complete=False;self.quantum_completed=False;self.proof=None
        _READS.add(self);self.scope.arena.add(self)
    def _source_heap_bytes(self):return 16384
    def advance(self,meter):
        if self not in _READS or self.complete:raise C09PagedCaptureHold('actual unfinished six-output cold reader required')
        p=self.progress;p.session.require_current();p.pair.check_source();self.scope.require_current(meter=meter)
        result=copy(self);result.quantum_completed=False;_READS.add(result);self.scope.arena.add(result)
        db=p.read_db
        if self.phase=='forward':
            if self.prepared_digest is None:
                with self.scope.read_database_v3(meter=meter) as source_db:
                    present=meter.read_fixed_row(source_db,'sqlite_master',('name',),'type=? AND name=?',('table','graph_owner_source_prepared_v3'))
                    if present is None:
                        from .c09_graph_rebase_candidate_v2 import _require_graph_owner_zero_family_v3
                        _require_graph_owner_zero_family_v3(p.cold_build,meter,record=False)
                        if self.family.complete.record_count!=0:
                            raise C09PagedCaptureHold('signed no-Owner Source has a nonzero target output family')
                        result.phase='reverse';return result
                    key=meter.read_fixed_row(source_db,'graph_owner_source_prepared_v3',('prepared_digest',),
                        'prepared_digest>? ORDER BY prepared_digest COLLATE BINARY',(self.after or '',))
                if key is None:
                    result.phase='reverse';return result
                result.prepared_digest=key[0];result.name_index=0;return result
            name=NAMES[self.name_index]
            if self.semantic is None:
                result.semantic=PreparedOwnerOutputSemanticReadV3(self.scope,self.prepared_digest,name,meter=meter)
                return result
            if not self.semantic.complete:
                result.semantic=self.semantic.advance(meter);return result
            source=self.semantic.require_complete(meter=meter)
            row=meter.read_fixed_row(db,TABLE,COLUMNS,
                'capture_scope_digest=? AND prepared_digest=? AND cell_name=?',
                (p.session.scope.scope_digest,self.prepared_digest,name))
            if row is None:raise C09PagedCaptureHold('actual six-name Source has no target mapping member')
            original=decode_owner_source_output_mapping_row_v3(row)
            _require_exact_structural_member(db,self.family,row[:3],row,meter)
            descriptor=_prepared_member(p.cold_build,source,meter,db=db)
            if (canonical_serialize(original['source_cell_descriptor'])!=canonical_serialize(_source_descriptor(source))
                    or original['prepared_row_descriptor']!=json.loads(canonical_serialize(descriptor))
                    or original['prepared_metadata']!=source.metadata):
                raise C09PagedCaptureHold('cold mapping differs from independently completed Source facts')
            _clock_original(p,source,original,meter)
            if original['source_origin']!=source.scope_original:
                raise C09PagedCaptureHold('cold Source origin is not the protected actual current Q05 original')
            erased=_erasure(p.cold_build,source,meter,db=db)
            if original['outcome']=='retired':
                if not erased and source.kind!='Retired':
                    raise C09PagedCaptureHold('bodyless retirement has no actual Source refusal/erasure')
                expected=_retirement_original(source,erased,meter)
                if canonical_serialize(original['retirement_original'])!=canonical_serialize(expected):
                    raise C09PagedCaptureHold('cold retirement changed its actual current/prior qualified facts')
            else:
                if erased or source.kind=='Retired':
                    raise C09PagedCaptureHold('erased or refused prepared output retained byte authority')
                header=tuple(original['target_cell_seal']['header9']) if original['outcome']=='complete' else None
                cursor=tuple(original['prefix_equivalence']['cursor']) if original['outcome']=='carry_prefix' else None
                if self.target_read is None:
                    result.target_read=PreparedOutputTargetReadV3(source,db,header,cursor,meter=meter);return result
                if not self.target_read.complete:
                    result.target_read=self.target_read.advance(db,meter);return result
            result.count+=1
            result.forward_root=canonical_digest((self.forward_root,row[:3],row[12]))
            result.semantic=result.target_read=result.row=None
            result.name_index+=1
            if result.name_index==len(NAMES):
                result.after=self.prepared_digest;result.prepared_digest=None;result.name_index=0
            return result
        if self.phase=='reverse':
            after=self.reverse_after
            where='capture_scope_digest=?'
            params=(p.session.scope.scope_digest,)
            if after is not None:
                where+=' AND (prepared_digest>? OR (prepared_digest=? AND cell_name>?))'
                params+=(after[0],after[0],after[1])
            row=meter.read_fixed_row(db,TABLE,COLUMNS,where+' ORDER BY prepared_digest COLLATE BINARY,cell_name COLLATE BINARY',params)
            if row is None:
                if self.count!=self.reverse_count or self.count!=self.family.complete.record_count or self.forward_root!=self.reverse_root:
                    raise C09PagedCaptureHold('six-name mapping forward/reverse/full family EOF counts or roots differ')
                result.complete=True;result.phase='complete';return result
            original=decode_owner_source_output_mapping_row_v3(row)
            _require_exact_structural_member(db,self.family,row[:3],row,meter)
            with self.scope.read_database_v3(meter=meter) as source_db:
                prepared=meter.read_fixed_row(source_db,'graph_owner_source_prepared_v3',('prepared_digest',),'prepared_digest=?',(row[1],))
            if prepared is None or row[2] not in NAMES:
                raise C09PagedCaptureHold('target mapping has an extra name or no actual Source prepared')
            result.reverse_after=(row[1],row[2]);result.reverse_count+=1
            result.reverse_root=canonical_digest((self.reverse_root,row[:3],row[12]))
            return result
        raise C09PagedCaptureHold('unknown registered six-output cold phase')
    def require_complete(self,*,meter):
        if self not in _READS or not self.complete or not self.quantum_completed:
            raise C09PagedCaptureHold('actual successful reserved exit and dual EOF required')
        self.scope.require_current(meter=meter);self.progress.session.require_current()
        if self.proof is None:self.proof=VerifiedPreparedOwnerOutputsColdV3(_TOKEN,self)
        return self.proof

class VerifiedPreparedOwnerOutputsColdV3:
    """Private full six-name/source/member/target byte closure."""
    def __init__(self,token,reader):
        if token is not _TOKEN or reader not in _READS or not reader.complete or not reader.quantum_completed:
            raise C09PagedCaptureHold('actual six-output cold issuer required')
        self.reader=reader;self.scope=reader.scope;self.count=reader.count;self.root=reader.forward_root
        _PROOFS.add(self);self.scope.arena.add(self)
    def require_current(self,*,meter):
        if self not in _PROOFS:raise C09PagedCaptureHold('actual private six-output cold proof required')
        self.scope.require_current(meter=meter);self.reader.progress.session.require_current()
        return self
