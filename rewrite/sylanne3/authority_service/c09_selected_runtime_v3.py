"""Actual selected runtime physical EOF; pending cells retain producer qualification only."""
from __future__ import annotations
from hashlib import sha256
import json
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..segmented_sql_cell_v1 import CODECS

from weakref import WeakSet

_ISSUER = object()
_READERS=WeakSet()
_HEADER = ('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
    'payload_sha256','ordered_segment_root','origin_scope_digest')
_WRITE = ('cell_id','origin_scope_digest','logical_locator_json','codec_id','producer_operation_id','erasure_owner_ref',
    'phase','next_ordinal','next_byte_offset','prefix_root','prefix_sha256','source_cursor_json','expected_total_bytes',
    'verify_next_ordinal','verify_next_byte_offset','verify_prefix_root','verify_prefix_sha256','cursor_revision')


class SelectedRuntimePhysicalProofV3:
    def __init__(self, token, reader):
        if token is not _ISSUER or reader not in _READERS or not reader.complete:
            raise AuthorityUnavailable('actual complete selected runtime physical issuer required')
        self.basis, self.counts, self.root = reader.basis, tuple(reader.counts), reader.root
        self.source_scope=reader.source_scope
        self.initial_qualification=reader.initial_qualification
        if self.initial_qualification is None:
            self.eof_digest = canonical_digest(('sylanne3.c09.selected-runtime-eof.v3',
                self.basis.selection_digest, self.counts, self.root))
        else:
            self.eof_digest=canonical_digest(('sylanne3.c09.initial-source-runtime-eof.v3',
                reader.initial_source_anchor,self.counts,self.root))
    def require_current(self, *, meter):
        if self.initial_qualification is None:self.basis.require_current(meter=meter)
        else:self.initial_qualification.require_current(meter=meter)
        if self.source_scope is not None:self.source_scope.require_current(meter=meter)
        return self


class SelectedRuntimePhysicalReadV3:
    def __init__(self, token, basis, scope, *, roles=('core','deletion','execution','graph'), source_scope=None, initial_qualification=None):
        if token is not _ISSUER:
            raise AuthorityUnavailable('actual private selected runtime physical factory required')
        self.initial_qualification=initial_qualification;self.initial_source_anchor=None
        if initial_qualification is not None:
            from .c09_source_physical_read_v3 import InitialOwnerSourceReadQualificationV3,_INITIAL_OWNER_SOURCE
            if (type(initial_qualification) is not InitialOwnerSourceReadQualificationV3 or initial_qualification not in _INITIAL_OWNER_SOURCE
                    or basis is not None or initial_qualification.scope is not source_scope or roles!=('graph',)):
                raise AuthorityUnavailable('actual initial Graph Source mode is distinct from selected runtime')
            self.initial_source_anchor=(initial_qualification.initial_manifest_digest,initial_qualification.initial_pointer,
                initial_qualification.source_original_digest,scope.scope_digest)
        self.basis, self.scope, self.roles, self.source_scope = basis, scope, roles, source_scope
        self.role_index = 0;self.phase = 'schema';self.after = ''
        self.catalogue = None;self.catalogue_index = 0;self.runtime_schema = None
        self.header = self.producer = self.pending = None
        self.ordinal = self.offset = 0;self.cell_hash = None;self.cell_root = None
        self.ref_index = 0;self.ref_shape = None
        self.counter_reader=None
        self.owner_outputs=None;self.owner_output_index=0;self.owner_output_count=0;self.owner_output_reverse_count=0
        self.counts = [0,0,0,0,0,0,0,0,0,0,0]
        self.root = (canonical_digest(('sylanne3.c09.selected-runtime-genesis.v3', basis.selection_digest))
            if initial_qualification is None else canonical_digest(('sylanne3.c09.initial-source-runtime-genesis.v3',self.initial_source_anchor)))
        self.complete = False;self.proof = None
        _READERS.add(self)
        self.control.register_c09_retained_state_v3(self)
    @property
    def control(self):return self.basis.control if self.initial_qualification is None else self.initial_qualification.control
    def _require_current(self,meter):
        if self.initial_qualification is None:self.basis.require_current(meter=meter)
        else:self.initial_qualification.require_current(meter=meter)
        if self.source_scope is not None:self.source_scope.require_current(meter=meter)
    def _c09_retained_heap_bytes_v3(self):
        from sys import getsizeof
        amount=8192
        if self.catalogue is not None:
            amount+=getsizeof(self.catalogue)+sum(getsizeof(descriptor)+sum(getsizeof(value) for value in descriptor)
                for descriptor in self.catalogue)
        if self.header is not None:amount+=getsizeof(self.header)+sum(getsizeof(value) for value in self.header)
        if self.pending is not None:
            amount+=self.pending._c09_retained_heap_bytes_v3()
        if self.owner_outputs is not None:
            encoded=self.owner_outputs['row'][6]
            amount+=getsizeof(encoded)*12
        if self.counter_reader is not None:
            encoded=getattr(self.counter_reader,'encoded',None)
            child=getattr(self.counter_reader,'reader',None)
            if child is not None:encoded=child.encoded
            if encoded is not None:amount+=getsizeof(encoded)*8
        return amount
    def copy_for_c09_quantum_v3(self,*,meter):
        from copy import copy
        from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3
        if (type(self) is not SelectedRuntimePhysicalReadV3 or self not in _READERS
                or meter is not require_c09_reserved_meter_v3(meter.budget)):
            raise AuthorityUnavailable('actual private physical progress and Root quantum required')
        self._require_current(meter)
        control=self.control
        control.require_c09_retained_arena_v3(meter=meter,additional_bytes=self._c09_retained_heap_bytes_v3())
        result=copy(self);result.counts=list(self.counts)
        if self.owner_outputs is not None:result.owner_outputs=dict(self.owner_outputs)
        if self.cell_hash is not None:result.cell_hash=self.cell_hash.copy()
        if self.producer is not None:result.producer=dict(self.producer)
        if self.pending is not None:result.pending=self.pending.copy_for_c09_quantum_v3(meter=meter)
        if self.counter_reader is not None:result.counter_reader=self.counter_reader.copy_for_c09_quantum_v3(meter=meter)
        _READERS.add(result);control.register_c09_retained_state_v3(result)
        control.require_c09_retained_arena_v3(meter=meter)
        return result

    @property
    def role(self):return self.roles[self.role_index]
    def _link(self, kind, material):
        self.root = canonical_digest(('sylanne3.c09.selected-runtime-link.v3',self.root,self.role,kind,material))
    def _header(self, db, cell_id, meter, *, published=False):
        from .c09_selected_history_v3 import _read_one
        header = meter.read_fixed_row(db, 'segmented_cells_v1', _HEADER, 'cell_id=?', (cell_id,))
        if header is None or header[1] not in CODECS:
            raise AuthorityUnavailable('actual selected logical cell lacks its registered complete header')
        if self.initial_qualification is not None:
            from .c09_source_physical_read_v3 import _initial_owner_cell_values_read_v3
            producer=_initial_owner_cell_values_read_v3(self.initial_qualification,cell_id,tuple(header[1:]),meter)
            if producer is None or (published and producer['phase']!='committed'):
                raise AuthorityUnavailable('initial Source cell has no qualified Owner producer at this visibility')
            return tuple(header),producer
        if header[8] == self.basis.prepared['capture_scope_digest']:
            with self.basis.control._db() as control_db:
                original = _read_one(control_db, 'SELECT header_json FROM c09_segmented_headers_v3 WHERE scope_digest=? AND role=? AND cell_id=?',
                    (header[8],self.role,cell_id),meter)
            if original != (canonical_serialize(tuple(header)),):
                raise AuthorityUnavailable('actual selected cutoff header is outside its immutable original')
            producer = None
        else:
            if self.role not in ('core','graph'):
                raise AuthorityUnavailable('actual runtime producer is not registered for this role')
            from ..runtime_storage_v3 import read_selected_runtime_cell_origin_v3
            producer = read_selected_runtime_cell_origin_v3(db,selected_basis=self.basis,role=self.role,
                cell_id=cell_id,header=tuple(header[1:]),meter=meter)
            if producer is None:
                raise AuthorityUnavailable('actual selected extra cell has no qualified runtime producer')
            if (published and producer.get('producer_kind') == 'owner_material_source_prepared_v3'
                    and producer['phase'] != 'committed'):
                raise AuthorityUnavailable('actual prepared or aborted runtime cell appears in a published logical reference')
        return tuple(header),producer
    def _read_database(self,meter):
        if self.source_scope is not None:
            if self.source_scope.role!=self.role:raise AuthorityUnavailable('actual physical Source role changed')
            return self.source_scope.read_database_v3(meter=meter)
        return self.basis.read_database(self.role,meter=meter)

    def _require_initial_inline_refs_v3(self,db,shape,meter):
        import re
        from ..graph_store import GraphStore
        from .c09_selected_history_v3 import _read_one
        if self.initial_qualification is None or shape.table not in ('graph_atoms','graph_history'):
            raise AuthorityUnavailable('only the actual initial Graph Source may qualify inline physical references')
        catalogue=tuple(value for value in GraphStore._create_graph_schema.__code__.co_consts if type(value) is str)
        pattern=r'CREATE TABLE IF NOT EXISTS '+shape.table+r' \(.*?;'
        ddls=tuple(match.group(0) for text in catalogue for match in re.finditer(pattern,text,re.DOTALL))
        actual=_read_one(db,'SELECT sql FROM sqlite_master WHERE type=? AND name=?',('table',shape.table),meter)
        if (len(ddls)!=1 or actual is None
                or ' '.join(actual[0].split())!=' '.join(ddls[0].replace('IF NOT EXISTS ','',1).rstrip(';').split())
                or 'value' not in shape.columns or 'value_cell_id' in shape.columns
                or shape.primary_key_columns!=(('token',) if shape.table=='graph_atoms' else ('token','revision'))
                or shape.primary_key_types!=(('text',) if shape.table=='graph_atoms' else ('text','integer'))):
            raise AuthorityUnavailable('initial inline Graph references differ from actual registered GraphStore DDL/PK')
        return shape

    def _refs(self):
        if self.role == 'graph':return (('graph_atoms','value_cell_id'),('graph_history','value_cell_id'))
        if self.role == 'core':return (('authority_d13_counter_originals_v1','payload_cell_id'),('authority_d13_provider_http_bindings_v1','payload_cell_id'))
        return ()
    def advance(self, meter):
        from .c09_selected_history_v3 import _read_one
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,read_c09_next_row_metadata_v2
        self._require_current(meter)
        self.control.require_c09_retained_arena_v3(meter=meter)
        if self.complete:return True
        if self.initial_qualification is not None and self.phase=='writes' and self.pending is not None:
            self.pending=self.pending.advance(meter)
            if self.pending.complete:
                self._link('pending_prefix',(self.pending.cell_id,self.pending.cursor,self.pending.hash.hexdigest()))
                self.after=self.pending.cell_id;self.pending=None;self.counts[2]+=1
            return False
        with self._read_database(meter) as db:
            if self.phase == 'schema':
                from ..runtime_storage_v3 import selected_runtime_catalogue_v3
                if self.catalogue is None:
                    self.runtime_schema = _read_one(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_cell_origins_v3'", (), meter) is not None
                    self.catalogue = tuple(selected_runtime_catalogue_v3(self.role));self.catalogue_index=0
                    return False
                descriptor = self.catalogue[self.catalogue_index] if self.catalogue_index<len(self.catalogue) else None
                if descriptor is None:
                    self.catalogue = None;self.catalogue_index=0;self.phase = 'headers';return False
                kind,name,ddl = descriptor
                actual = _read_one(db, 'SELECT sql FROM sqlite_master WHERE type=? AND name=?', (kind,name), meter)
                if actual != ((ddl,) if self.runtime_schema else None):
                    raise AuthorityUnavailable('actual selected runtime catalogue is partial or differs from registered DDL')
                self._link('schema', descriptor);self.catalogue_index+=1;return False
            if self.phase == 'headers':
                if self.header is None:
                    row = meter.read_fixed_row(db,'segmented_cells_v1',('cell_id',),'cell_id COLLATE BINARY>? ORDER BY cell_id COLLATE BINARY',(self.after,))
                    if row is None:
                        self._link('headers_eof',(self.after,self.counts[0]));self.phase='orphan_segments';self.after=('',-1);return False
                    self.header,self.producer = self._header(db,row[0],meter)
                    self.ordinal=self.offset=0;self.cell_hash=sha256()
                    self.cell_root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',row[0]))
                    return False
                cell_id=self.header[0]
                if self.ordinal < self.header[5]:
                    row=meter.read_fixed_row(db,'segmented_cell_segments_v1',('byte_offset','payload','payload_sha256'),
                        'cell_id=? AND ordinal=?',(cell_id,self.ordinal))
                    if (row is None or row[0]!=self.offset or type(row[1]) is not bytes or not 1<=len(row[1])<=16384
                            or sha256(row[1]).hexdigest()!=row[2]):
                        raise AuthorityUnavailable('actual selected runtime cell segment offset/length/SHA differs')
                    self.cell_hash.update(row[1])
                    self.cell_root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.cell_root,cell_id,self.ordinal,self.offset,len(row[1]),row[2]))
                    self.ordinal+=1;self.offset+=len(row[1]);return False
                extra=_read_one(db,'SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? LIMIT 1',(cell_id,self.ordinal),meter)
                if (extra is not None or (self.offset,self.cell_hash.hexdigest(),self.cell_root)!=(self.header[4],self.header[6],self.header[7])):
                    raise AuthorityUnavailable('actual selected runtime complete cell bytes/count/root/EOF differs')
                self._link('cell',(self.header,self.producer));self.counts[0]+=1;self.after=cell_id
                self.header=self.producer=None;self.cell_hash=None;return False
            if self.phase == 'orphan_segments':
                row=_read_one(db,'SELECT cell_id,ordinal,byte_offset,length(payload),payload_sha256 FROM segmented_cell_segments_v1 '
                    'WHERE cell_id COLLATE BINARY>? OR cell_id=? AND ordinal>? ORDER BY cell_id COLLATE BINARY,ordinal LIMIT 1',
                    (self.after[0],self.after[0],self.after[1]),meter)
                if row is None:
                    self._link('segments_eof',(self.after,self.counts[1]));self.phase='writes';self.after='';return False
                header=_read_one(db,'SELECT segment_count,total_bytes FROM segmented_cells_v1 WHERE cell_id=?',(row[0],),meter)
                if header is None:
                    cursor=_read_one(db,'SELECT next_ordinal,next_byte_offset FROM segmented_cell_writes_v1 WHERE cell_id=?',(row[0],),meter)
                    if cursor is None or not 0<=row[1]<cursor[0] or row[2]+row[3]>cursor[1]:
                        raise AuthorityUnavailable('actual extra segment has neither a sealed header nor a finite producer cursor')
                elif not 0<=row[1]<header[0] or row[2]+row[3]>header[1]:
                    raise AuthorityUnavailable('actual extra segment is outside its complete header')
                self._link('segment',row);self.counts[1]+=1;self.after=(row[0],row[1]);return False
            if self.phase == 'writes':
                if self.pending is not None:
                    self.pending.advance(db=db,meter=meter)
                    if self.pending.complete:
                        self._link('pending_prefix',(self.pending.cell_id,self.pending.cursor,self.pending.hash.hexdigest()))
                        self.after=self.pending.cell_id;self.pending=None;self.counts[2]+=1
                    return False
                row=meter.read_fixed_row(db,'segmented_cell_writes_v1',_WRITE,'cell_id COLLATE BINARY>? ORDER BY cell_id COLLATE BINARY',(self.after,))
                if row is None:
                    self._link('writes_eof',(self.after,self.counts[2]));self.phase='refs';self.after=None;return False
                header=_read_one(db,'SELECT '+','.join(_HEADER)+' FROM segmented_cells_v1 WHERE cell_id=?',(row[0],),meter)
                if self.initial_qualification is not None:
                    from .c09_source_physical_read_v3 import begin_initial_owner_source_cursor_read_v3
                    self.pending=begin_initial_owner_source_cursor_read_v3(self.initial_qualification,row,meter=meter)
                    return False
                if row[1] == self.basis.prepared['capture_scope_digest']:
                    if header is None and self.role=='graph':
                        from ..runtime.c09_selected_owner_source_outputs_v3 import begin_selected_mapped_owner_source_prefix_read_v3
                        self.pending=begin_selected_mapped_owner_source_prefix_read_v3(db,basis=self.basis,
                            cursor=tuple(row),meter=meter)
                        return False
                    if (header is None or row[3:7]!=(header[1],header[3],header[2],'sealed')
                            or row[7:11]!=(header[5],header[4],header[7],header[6])
                            or row[12:17]!=(header[4],header[5],header[4],header[7],header[6])):
                        raise AuthorityUnavailable('actual cutoff write cursor lost its complete sealed header')
                elif self.role=='graph':
                    from ..runtime.owner_material_source_storage_v3 import begin_selected_owner_source_stage_read_v3
                    self.pending=begin_selected_owner_source_stage_read_v3(db,selected_basis=self.basis,cell_id=row[0],meter=meter)
                    if self.pending is None:raise AuthorityUnavailable('actual extra write cursor lacks a registered prepared producer')
                    return False
                else:raise AuthorityUnavailable('actual extra runtime write cursor has no registered producer')
                self._link('write',tuple(row));self.after=row[0];self.counts[2]+=1;return False
            if self.phase=='refs':
                families=self._refs()
                if self.ref_index==len(families):
                    self._link('refs_eof',self.counts[3]);self.phase='origins';self.after='';return False
                table,column=families[self.ref_index]
                if self.ref_shape is None:
                    self.ref_shape=read_c09_table_shape_v2(db,table,meter=meter)
                    if column not in self.ref_shape.columns:
                        self._require_initial_inline_refs_v3(db,self.ref_shape,meter)
                    elif self.initial_qualification is not None:
                        raise AuthorityUnavailable('initial Graph Source must retain its actual legacy inline reference schema')
                    return False
                found=read_c09_next_row_metadata_v2(db,self.ref_shape,self.after)
                if found is None:
                    self._link('ref_table_eof',(table,self.ref_shape.schema_digest,self.after));self.ref_index+=1;self.ref_shape=None;self.after=None;return False
                key=found[0]
                if self.initial_qualification is not None:
                    from ..graph_types import AtomKey
                    atom=AtomKey.from_token(key[0])
                    if ((atom.owner.bot,atom.owner.persona)!=tuple(json.loads(self.source_scope.session.scope.graph_namespace))
                            or found[1][self.ref_shape.columns.index('value')][0]!='text'):
                        raise AuthorityUnavailable('initial inline physical reference namespace/value representation differs')
                    self._link('initial_inline_ref',(table,self.ref_shape.schema_digest,key,found[1]))
                    self.after=key;self.counts[3]+=1;return False
                where=' AND '.join(name+'=?' for name in self.ref_shape.primary_key_columns)
                value=_read_one(db,'SELECT '+column+' FROM '+table+' WHERE '+where,key,meter)
                if value is None:raise AuthorityUnavailable('actual selected logical reference disappeared')
                header,producer=self._header(db,value[0],meter,published=True)
                if self.role=='graph':
                    from ..graph_types import AtomKey
                    atom=AtomKey.from_token(key[0])
                    if (atom.owner.bot,atom.owner.persona)!=tuple(json.loads(self.source_scope.session.scope.graph_namespace if self.source_scope is not None else self.scope.graph_namespace)) or header[2]!=atom.token:
                        raise AuthorityUnavailable('actual runtime logical reference crossed its erasure owner or namespace')
                else:
                    if key[0]!=self.basis.prepared['namespace']:
                        raise AuthorityUnavailable('actual runtime Core reference crossed its authority namespace')
                    if table=='authority_d13_counter_originals_v1':
                        if key[2] not in ('draft','header','evidence'):raise AuthorityUnavailable('actual Core counter phase is unregistered')
                        family='d13-counter-source' if key[2]=='draft' else 'd13-counter-history'
                    else:
                        if key[2] not in ('expected','observed_before_send'):raise AuthorityUnavailable('actual Core provider phase is unregistered')
                        family='d13-provider-http-history'
                    if header[2]!=canonical_serialize((family,key[0],key[1])):
                        raise AuthorityUnavailable('actual Core runtime reference crossed its erasure owner')
                self._link('ref',(table,key,value[0],found[1]));self.after=key;self.counts[3]+=1;return False
            if self.phase=='origins':
                exists=_read_one(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_cell_origins_v3'",(),meter)
                row=None if exists is None else _read_one(db,'SELECT origin_digest FROM runtime_cell_origins_v3 WHERE origin_digest COLLATE BINARY>? ORDER BY origin_digest COLLATE BINARY LIMIT 1',(self.after,),meter)
                if row is None:
                    self._link('origins_eof',(self.after,self.counts[4]))
                    self.phase='prepared';self.after='';return False
                if self.initial_qualification is not None:
                    raise AuthorityUnavailable('initial Owner Source does not qualify another runtime-origin producer')
                cell=_read_one(db,'SELECT cell_id FROM segmented_cells_v1 WHERE origin_scope_digest=? ORDER BY cell_id LIMIT 1',(row[0],),meter)
                if cell is None:raise AuthorityUnavailable('actual runtime producer original has no committed immutable cell')
                self._header(db,cell[0],meter,published=True)
                self._link('origin',(row[0],cell[0]));self.after=row[0];self.counts[4]+=1;return False
            if self.phase=='prepared':
                if self.initial_qualification is None and self.owner_outputs is not None:
                    from ..runtime.c09_selected_owner_source_outputs_v3 import (
                        resolve_selected_owner_source_output_v3,VerifiedSelectedOwnerSourceCompleteOutputV3,
                        VerifiedSelectedOwnerSourcePrefixOutputV3,VerifiedSelectedOwnerSourceRetiredOutputV3)
                    names=('bundle','http_request','input','original','source','stage_request')
                    prepared=self.owner_outputs
                    name=names[self.owner_output_index]
                    output=resolve_selected_owner_source_output_v3(db,basis=self.basis,
                        prepared_digest=prepared['row'][0],cell_name=name,meter=meter)
                    if output is None:
                        self._link('live_owner_output',(prepared['row'][0],name))
                    else:
                        if type(output) is VerifiedSelectedOwnerSourceCompleteOutputV3:
                            self._header(db,output.current_cell_id,meter,published=prepared['actual_committed'])
                        elif type(output) is VerifiedSelectedOwnerSourcePrefixOutputV3:
                            if prepared['actual_committed']:
                                raise AuthorityUnavailable('actual W01 adoption has only a carried prefix')
                        elif type(output) is VerifiedSelectedOwnerSourceRetiredOutputV3:
                            # Actual erasure can retire bytes while retaining the historical W01.
                            pass
                        else:
                            raise AuthorityUnavailable('selected Owner output has no exact private outcome')
                        self._link('owner_output_mapping',output.mapping_row)
                        self.owner_output_count+=1
                    self.owner_output_index+=1
                    if self.owner_output_index==len(names):
                        self._link('owner_outputs_six_eof',(prepared['row'][0],names))
                        self.owner_outputs=None;self.owner_output_index=0
                    return False
                if self.role!='graph' or not self.runtime_schema:
                    self.phase='dispositions';self.after='';return False
                row=_read_one(db,'SELECT prepared_digest FROM graph_owner_source_prepared_v3 WHERE prepared_digest COLLATE BINARY>? ORDER BY prepared_digest COLLATE BINARY LIMIT 1',(self.after,),meter)
                if row is None:
                    self._link('prepared_eof',(self.after,self.counts[5]))
                    self.phase='owner_mapping_reverse' if self.initial_qualification is None else 'dispositions'
                    self.after=('','') if self.initial_qualification is None else '';return False
                from ..runtime.owner_material_source_storage_v3 import read_selected_owner_source_prepared_v3
                prepared=(read_selected_owner_source_prepared_v3(db,basis=self.basis,prepared_digest=row[0],meter=meter)
                    if self.initial_qualification is None else self.source_scope.qualify_owner_source_storage_row_v3(
                        'graph_owner_source_prepared_v3',(row[0],),meter=meter).original)
                if prepared is None:raise AuthorityUnavailable('actual selected prepared producer disappeared')
                self._link('prepared',prepared['row']);self.after=row[0];self.counts[5]+=1
                if self.initial_qualification is None:self.owner_outputs=prepared;self.owner_output_index=0
                return False
            if self.phase=='owner_mapping_reverse':
                from ..runtime.c09_owner_source_output_mappings_v3 import TABLE
                present=meter.read_fixed_row(db,'sqlite_master',('name',),'type=? AND name=?',('table',TABLE))
                found=None if present is None else _read_one(db,'SELECT prepared_digest,cell_name FROM '+TABLE+
                    ' WHERE capture_scope_digest=? AND (prepared_digest COLLATE BINARY>? OR '
                    '(prepared_digest=? AND cell_name COLLATE BINARY>?)) ORDER BY prepared_digest COLLATE BINARY,'
                    'cell_name COLLATE BINARY LIMIT 1',
                    (self.basis.prepared['capture_scope_digest'],self.after[0],self.after[0],self.after[1]),meter)
                if found is None:
                    if self.owner_output_reverse_count!=self.owner_output_count:
                        raise AuthorityUnavailable('Owner output mapping forward/reverse EOF counts differ')
                    self._link('owner_output_mapping_reverse_eof',(self.after,self.owner_output_count))
                    self.phase='dispositions';self.after='';return False
                from ..runtime.c09_selected_owner_source_outputs_v3 import resolve_selected_owner_source_output_v3
                output=resolve_selected_owner_source_output_v3(db,basis=self.basis,
                    prepared_digest=found[0],cell_name=found[1],meter=meter)
                if output is None:raise AuthorityUnavailable('retained Owner output mapping has no actual prepared producer')
                self._link('owner_output_mapping_reverse',output.mapping_row)
                self.owner_output_reverse_count+=1
                self.after=tuple(found)
                return False
            if self.phase=='dispositions':
                if self.role!='graph' or not self.runtime_schema:
                    self.phase='domain_originals';self.after=None;return False
                row=_read_one(db,'SELECT prepared_digest FROM graph_owner_source_dispositions_v3 WHERE prepared_digest COLLATE BINARY>? ORDER BY prepared_digest COLLATE BINARY LIMIT 1',(self.after,),meter)
                if row is None:
                    self._link('dispositions_eof',(self.after,self.counts[6]));self.phase='domain_originals';self.after=None;return False
                from ..runtime.owner_material_source_storage_v3 import read_selected_owner_source_disposition_v3
                disposition=(read_selected_owner_source_disposition_v3(db,basis=self.basis,prepared_digest=row[0],meter=meter)
                    if self.initial_qualification is None else self.source_scope.qualify_owner_source_storage_row_v3(
                        'graph_owner_source_dispositions_v3',(row[0],),meter=meter).original)
                if disposition is None:raise AuthorityUnavailable('actual selected terminal producer disappeared')
                self._link('disposition',disposition['row']);self.after=row[0];self.counts[6]+=1;return False
            if self.phase=='domain_originals':
                if self.role=='graph' and self.runtime_schema:
                    if self.ref_shape is None:
                        self.ref_shape=read_c09_table_shape_v2(db,'graph_domain_production_originals_v3',meter=meter);return False
                    found=read_c09_next_row_metadata_v2(db,self.ref_shape,self.after)
                    if found is not None:
                        key=found[0]
                        row=_read_one(db,'SELECT domain,operation_kind,original_digest,original_payload_cell_id,prepared_digest,bundle_digest '
                            'FROM graph_domain_production_originals_v3 WHERE bot=? AND persona=? AND operation_id=?',key,meter)
                        from ..runtime.owner_material_source_storage_v3 import read_selected_owner_source_prepared_v3
                        prepared=(read_selected_owner_source_prepared_v3(db,basis=self.basis,prepared_digest=row[4],meter=meter)
                            if self.initial_qualification is None else self.source_scope.qualify_owner_source_storage_row_v3(
                                'graph_owner_source_prepared_v3',(row[4],),meter=meter).original)
                        if (prepared is None or not prepared['actual_committed'] or row[:2]!=('d06','admit_owner_material_source_v1')
                                or prepared['operation_id']!=key[2] or prepared['namespace'].as_tuple!=tuple(key[:2])):
                            raise AuthorityUnavailable('actual physical domain original lacks its registered committed producer')
                        self._header(db,row[3],meter,published=True)
                        self._link('domain_original',(key,row,found[1]));self.after=key;self.counts[7]+=1;return False
                self._link('domain_originals_eof',(self.after,self.counts[7]));self.phase='command_seeds';self.ref_shape=None;self.after=None;return False
            if self.phase=='command_seeds':
                if self.role=='graph' and self.runtime_schema:
                    if self.ref_shape is None:
                        self.ref_shape=read_c09_table_shape_v2(db,'graph_owner_source_command_seeds_v3',meter=meter);return False
                    found=read_c09_next_row_metadata_v2(db,self.ref_shape,self.after)
                    if found is not None:
                        key=found[0]
                        from ..runtime.owner_material_source_storage_v3 import read_selected_owner_source_command_seed_v3
                        from ..runtime_contracts import NamespaceId
                        seed=(read_selected_owner_source_command_seed_v3(db,basis=self.basis,namespace=NamespaceId(*key[:2]),operation_id=key[2],meter=meter)
                            if self.initial_qualification is None else self.source_scope.qualify_owner_source_storage_row_v3(
                                'graph_owner_source_command_seeds_v3',key,meter=meter).original)
                        if seed is None:raise AuthorityUnavailable('actual Owner command seed disappeared')
                        self._link('command_seed',(key,seed['row'],found[1]));self.after=key;self.counts[8]+=1;return False
                self._link('command_seeds_eof',(self.after,self.counts[8]));self.phase='counter_rows';self.ref_shape=None;self.after=None;return False
            if self.phase=='counter_rows':
                if self.role=='core' and self.runtime_schema:
                    if self.counter_reader is not None:
                        result=self.counter_reader.advance(db=db,meter=meter)
                        if result['status']=='complete':
                            self._link('counter_index',result['row']);self.after=tuple(result['row'][:3]);self.counts[9]+=1;self.counter_reader=None
                        return False
                    if self.ref_shape is None:
                        self.ref_shape=read_c09_table_shape_v2(db,'runtime_d13_counter_calls_v3',meter=meter);return False
                    found=read_c09_next_row_metadata_v2(db,self.ref_shape,self.after)
                    if found is not None:
                        key=found[0]
                        from .d13_provider_http_admission_v1 import read_selected_runtime_counter_index_v3
                        reader=read_selected_runtime_counter_index_v3(db,basis=self.basis,selection_digest=key[0],namespace=key[1],counter_operation_id=key[2],meter=meter)
                        if reader is None:raise AuthorityUnavailable('actual counter index disappeared')
                        if type(reader) is dict:
                            from .c09_selected_core_source_v3 import require_selected_retired_counter_source_v3, VerifiedSelectedRetiredCounterSourceV3
                            proof=require_selected_retired_counter_source_v3(self.basis,
                                retirement_original=reader['retirement_original'],meter=meter)
                            if (type(proof) is not VerifiedSelectedRetiredCounterSourceV3 or proof.basis is not self.basis
                                    or proof.original['retirement_digest']!=reader['retirement_original']['retirement_digest']):
                                raise AuthorityUnavailable('actual retired counter Source member chain required')
                            proof.require_current(meter=meter)
                            self._link('counter_retired_index',reader['row']);self.after=key;self.counts[9]+=1
                        else:self.counter_reader=reader
                        return False
                self._link('counter_index_eof',(self.after,self.counts[9]));self.phase='counter_cutoffs';self.ref_shape=None;self.after=None;return False
            if self.phase=='counter_cutoffs':
                if self.role=='core' and self.runtime_schema:
                    if self.counter_reader is not None:
                        self.counter_reader.advance(db=db,meter=meter)
                        if self.counter_reader.complete:
                            self._link('counter_cutoff',(self.counter_reader.cursor,self.counter_reader.seal,self.counter_reader.root))
                            self.after=(self.counter_reader.cursor[0],);self.counter_reader=None;self.counts[10]+=1
                        return False
                    if self.ref_shape is None:
                        self.ref_shape=read_c09_table_shape_v2(db,'runtime_d13_counter_index_cursor_v3',meter=meter);return False
                    found=read_c09_next_row_metadata_v2(db,self.ref_shape,self.after)
                    if found is not None:
                        from .d13_provider_http_admission_v1 import begin_selected_runtime_counter_cutoff_read_v3
                        self.counter_reader=begin_selected_runtime_counter_cutoff_read_v3(db,basis=self.basis,selection_digest=found[0][0],meter=meter)
                        if self.counter_reader is None:raise AuthorityUnavailable('actual counter cutoff cursor disappeared')
                        return False
                self._link('counter_cutoffs_eof',(self.after,self.counts[10]));self.phase='counter_seals';self.ref_shape=None;self.after=None;return False
            if self.phase=='counter_seals':
                if self.role=='core' and self.runtime_schema:
                    if self.ref_shape is None:
                        self.ref_shape=read_c09_table_shape_v2(db,'runtime_d13_counter_index_seals_v3',meter=meter);return False
                    found=read_c09_next_row_metadata_v2(db,self.ref_shape,self.after)
                    if found is not None:
                        key=found[0]
                        cursor=_read_one(db,'SELECT selection_digest FROM runtime_d13_counter_index_cursor_v3 WHERE selection_digest=?',key,meter)
                        if cursor is None:raise AuthorityUnavailable('actual immutable counter seal has no validated cursor prefix')
                        self._link('counter_seal',(key,found[1]));self.after=key;return False
                self._link('counter_seals_eof',self.after);self.role_index+=1;self.ref_shape=None
                if self.role_index==len(self.roles):
                    self.complete=True;self.proof=SelectedRuntimePhysicalProofV3(_ISSUER,self);return True
                self.phase='schema';self.after='';self.ref_index=0;self.runtime_schema=None;return False
        raise AuthorityUnavailable('actual selected runtime physical phase differs')


def begin_selected_runtime_physical_read_v3(basis,scope,*,meter):
    from .c09_selected_history_v3 import _InstalledSelectedStorageBasisV3
    from ..runtime.c09_paged_capture_contract_v2 import C09CaptureScopeV2
    if type(basis) is not _InstalledSelectedStorageBasisV3 or type(scope) is not C09CaptureScopeV2 or scope.scope_digest != basis.prepared['capture_scope_digest']:
        raise AuthorityUnavailable('actual private selected runtime basis required')
    basis.require_current(meter=meter)
    return SelectedRuntimePhysicalReadV3(_ISSUER,basis,scope)
