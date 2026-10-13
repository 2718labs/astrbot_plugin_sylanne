"""Selected Core Source member chains; bodyless retirement is never read authority."""
from __future__ import annotations
import json
from weakref import WeakSet
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.c09_paged_capture_contract_v2 import C09SealedStreamLocatorV2, C09StreamIdentityV2, C09CompleteStreamV2, c09_paged_value_from_wire_v2
from ..runtime.c09_paged_sql_v2 import require_c09_logical_source_row_member_v3, require_c09_capture_member_v2, read_c09_table_shape_v2

_TOKEN=object()
_PROOFS=WeakSet()
_ROWS=WeakSet()
_TABLES=('authority_d13_counter_originals_v1','authority_d13_provider_http_bindings_v1')
_DIRECTORY=('scope_digest','role','table_name','stream_kind','stream_json','seal_json')
_DISPOSITION=('scope_digest','role','table_name','key_digest','key_json','old_commitment','disposition','new_commitment')


def _locator(row):
    identity=c09_paged_value_from_wire_v2(json.loads(row[4]),C09StreamIdentityV2)
    seal=c09_paged_value_from_wire_v2(json.loads(row[5]),C09CompleteStreamV2)
    if (identity.scope_digest!=row[0] or row[1]!='core' or identity.family!=row[2]
            or identity.stream_kind!=row[3]):
        raise AuthorityUnavailable('selected Core Source directory identity differs')
    return C09SealedStreamLocatorV2(storage_role='core',identity=identity,complete=seal)


class SelectedCoreSourceMetadataV3:
    def __init__(self,token,reader):
        if token is not _TOKEN or not reader.complete:
            raise AuthorityUnavailable('actual complete selected Core Source issuer required')
        self.basis,self.root,self.counts=reader.basis,reader.root,tuple(reader.counts)
        self.directory=reader.directory
        _PROOFS.add(self)
    def require_current(self,*,meter):
        if self not in _PROOFS:raise AuthorityUnavailable('registered selected Core Source proof required')
        self.basis.require_current(meter=meter)
        return self


class SelectedCoreSourceMetadataReadV3:
    def __init__(self,token,basis):
        if token is not _TOKEN:raise AuthorityUnavailable('actual selected Core Source factory required')
        self.basis=basis;self.phase='header';self.directory=None;self.reader=None
        self.last=None;self.row=None;self.stream_last=None;self.stream_count=0
        self.counts=[0,0,0];self.root=canonical_digest(('sylanne3.c09.selected-core-source.v3',basis.selection_digest))
        self.complete=False;self.proof=None;self.shape=None;self.schema_index=0
        basis.control.register_c09_retained_state_v3(self)
    def _c09_retained_heap_bytes_v3(self):
        from sys import getsizeof
        from dataclasses import fields, is_dataclass
        seen=set()
        def retained(value):
            if id(value) in seen:return 0
            seen.add(id(value));amount=getsizeof(value)
            if isinstance(value,(tuple,list)):amount+=sum(retained(item) for item in value)
            elif isinstance(value,dict):amount+=sum(retained(key)+retained(item) for key,item in value.items())
            elif is_dataclass(value):amount+=sum(retained(getattr(value,field.name)) for field in fields(value))
            return amount
        return 8192+retained((self.row,None if self.reader is None else self.reader.records))
    def _link(self,kind,value):self.root=canonical_digest((self.root,kind,value))
    def advance(self,meter):
        from .c09_prepared_storage_v3 import _read_original
        from .c09_paged_recovery_facts_v2 import C09HistoricalSealedStreamReaderV2,_read_one
        self.basis.require_current(meter=meter)
        self.basis.control.require_c09_retained_arena_v3(meter=meter)
        if self.complete:return True
        if self.phase=='header':
            with self.basis.control._db() as db:
                header=_read_original(self.basis.control,db,self.basis.prepared['operation_id'],
                    'capture_role_complete_v2_core',self.basis.prepared['four_role_complete_original_digests']['core'],meter)
            if header['scope_digest']!=self.basis.prepared['capture_scope_digest'] or header['role']!='core':
                raise AuthorityUnavailable('selected Core Source header scope differs')
            self.directory=c09_paged_value_from_wire_v2(header['stream_directory'],C09SealedStreamLocatorV2)
            self.reader=C09HistoricalSealedStreamReaderV2(self.directory);self.phase='directory_shape';return False
        with self.basis.read_database('core',meter=meter) as db:
            if self.phase=='directory_shape':
                self.shape=read_c09_table_shape_v2(db,'authority_c09_role_streams_v2',meter=meter)
                if self.shape.schema_digest!=self.directory.identity.schema_digest:
                    raise AuthorityUnavailable('actual selected Core directory physical schema differs')
                self.phase='source_schema';return False
            if self.phase=='source_schema':
                from ..runtime.c09_paged_sql_v2 import LOGICAL_SOURCE_DDL_V3,CAPTURE_TRIGGERS_V2
                descriptors=(('table','c09_logical_source_rows_v3',LOGICAL_SOURCE_DDL_V3),
                    *(( 'trigger',name,ddl) for name,ddl in CAPTURE_TRIGGERS_V2 if name.startswith('c09_logical_source_rows_v3_')))
                if self.schema_index==len(descriptors):self.phase='directory';return False
                kind,name,ddl=descriptors[self.schema_index]
                row=_read_one(db,'SELECT sql FROM sqlite_master WHERE type=? AND name=?',(kind,name),meter)
                if row is None and self.schema_index==0:self.phase='directory';return False
                if row!=(ddl,):raise AuthorityUnavailable('selected immutable logical Source metadata schema differs')
                self.schema_index+=1;return False
            if self.phase=='directory':
                def observe(record):
                    row=meter.read_fixed_row(db,'authority_c09_role_streams_v2',_DIRECTORY,
                        'scope_digest=? AND role=? AND table_name=? AND stream_kind=?',record.primary_key)
                    actual=_read_one(db,'SELECT scope_digest,role,table_name,stream_kind FROM authority_c09_role_streams_v2 '
                        'WHERE (scope_digest,role,table_name,stream_kind)>(?,?,?,?) ORDER BY scope_digest,role,table_name,stream_kind LIMIT 1',self.last or ('','','',''),meter)
                    if (row is None or actual!=record.primary_key or tuple(row[:4])!=record.primary_key
                            or canonical_digest(('sylanne3.c09.authority-directory-row.v2',self.directory.identity.stream_kind,
                                self.shape.table,record.primary_key,tuple(row)))!=record.commitment):
                        raise AuthorityUnavailable('selected Core directory omits or substitutes actual row')
                    self.last=record.primary_key;self.counts[0]+=1
                    self._link('directory',record.commitment)
                if self.reader.advance(db,meter,observe):
                    if (_read_one(db,'SELECT 1 FROM authority_c09_role_streams_v2 WHERE '
                            '(scope_digest,role,table_name,stream_kind)>(?,?,?,?) LIMIT 1',self.last or ('','','',''),meter) is not None
                            or self.counts[0]!=self.directory.complete.record_count):
                        raise AuthorityUnavailable('selected Core directory has extra EOF material')
                    self.phase='next';self.last=None;self.reader=None
                return False
            if self.phase=='next':
                row=_read_one(db,'SELECT '+','.join(_DIRECTORY)+' FROM authority_c09_role_streams_v2 '
                    'WHERE (scope_digest,role,table_name,stream_kind)>(?,?,?,?) ORDER BY scope_digest,role,table_name,stream_kind LIMIT 1',self.last or ('','','',''),meter)
                if row is None:self.phase='metadata';self.last=None;return False
                self.last=tuple(row[:4])
                if row[1]=='core' and row[2] in _TABLES and row[3] in ('source_originals_v3','row_dispositions'):
                    self.row=row;self.reader=C09HistoricalSealedStreamReaderV2(_locator(row))
                    self.stream_last=None;self.stream_count=0;self.phase='stream'
                return False
            if self.phase=='stream':
                stream=self.reader.locator.identity
                def observe(record):
                    ordinal=self.reader.cursor.record_offset+self.reader.index+1
                    if self.row[3]=='source_originals_v3':
                        descriptor=require_c09_logical_source_row_member_v3(db,stream,role='core',table_name=self.row[2],
                            key=record.primary_key,record_ordinal=ordinal,meter=meter)
                        if canonical_digest(descriptor)!=record.commitment:
                            raise AuthorityUnavailable('selected Core Source descriptor differs from its sealed page')
                    else:
                        row=meter.read_fixed_row(db,'authority_c09_role_rows_v2',_DISPOSITION,
                            'scope_digest=? AND role=? AND table_name=? AND key_digest=?',
                            (self.row[0],'core',self.row[2],canonical_digest(record.primary_key)))
                        if (row is None or json.loads(row[4])!=list(record.primary_key)
                                or canonical_digest(('sylanne3.c09.authority-row-disposition.v2',tuple(row)))!=record.commitment):
                            raise AuthorityUnavailable('selected D13 disposition member differs')
                    if self.stream_last is not None and record.primary_key<=self.stream_last:
                        raise AuthorityUnavailable('selected Core Source order differs')
                    self.stream_last=record.primary_key;self.stream_count+=1
                    self._link(self.row[3],record.commitment)
                if self.reader.advance(db,meter,observe):
                    if self.stream_count!=self.reader.locator.complete.record_count:
                        raise AuthorityUnavailable('selected Core Source sealed record count differs')
                    self.phase='reverse';self.stream_last=''
                return False
            if self.phase=='reverse':
                stream=self.reader.locator.identity
                table='c09_logical_source_rows_v3' if self.row[3]=='source_originals_v3' else 'authority_c09_role_rows_v2'
                row=_read_one(db,'SELECT key_digest,'+('primary_key_json' if self.row[3]=='source_originals_v3' else 'key_json')+' FROM '+table+' WHERE scope_digest=? AND role=? AND table_name=? '
                    'AND key_digest>? ORDER BY key_digest LIMIT 1',(self.row[0],'core',self.row[2],self.stream_last),meter)
                if row is None:
                    self.counts[1]+=self.stream_count;self.reader=self.row=None;self.phase='next';return False
                key=tuple(json.loads(row[1]));member=_read_one(db,'SELECT record_ordinal,commitment FROM c09_capture_members_v2 '
                    'WHERE stream_id=? AND key_digest=?',(stream.stream_id,row[0]),meter)
                if member is None or not 1<=member[0]<=self.reader.locator.complete.record_count:
                    raise AuthorityUnavailable('selected Core Source has unsealed extra row')
                if self.row[3]=='source_originals_v3':
                    descriptor=require_c09_logical_source_row_member_v3(db,stream,role='core',table_name=self.row[2],
                        key=key,record_ordinal=member[0],meter=meter)
                    if canonical_digest(descriptor)!=member[1]:raise AuthorityUnavailable('selected Source reverse member differs')
                else:
                    saved=meter.read_fixed_row(db,table,_DISPOSITION,'scope_digest=? AND role=? AND table_name=? AND key_digest=?',
                        (self.row[0],'core',self.row[2],row[0]))
                    require_c09_capture_member_v2(db,stream,member[0],key,canonical_digest(('sylanne3.c09.authority-row-disposition.v2',tuple(saved))),meter=meter)
                self.stream_last=row[0];return False
            if self.phase=='metadata':
                present=_read_one(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='c09_logical_source_rows_v3'",(),meter)
                if present is None:self.phase='issue';return False
                row=_read_one(db,'SELECT scope_digest,role,table_name,key_digest,primary_key_json,origin_stream_id,origin_record_ordinal '
                    'FROM c09_logical_source_rows_v3 WHERE (scope_digest,role,table_name,key_digest)>(?,?,?,?) '
                    'ORDER BY scope_digest,role,table_name,key_digest LIMIT 1',self.last or ('','','',''),meter)
                if row is None:self.phase='issue';return False
                directory=meter.read_fixed_row(db,'authority_c09_role_streams_v2',_DIRECTORY,
                    'scope_digest=? AND role=? AND table_name=? AND stream_kind=?',(*row[:3],'source_originals_v3'))
                if directory is None or row[1]!='core' or row[2] not in _TABLES:
                    raise AuthorityUnavailable('selected Core Source metadata has no registered signed directory')
                stream=_locator(directory).identity
                if stream.stream_id!=row[5]:raise AuthorityUnavailable('selected Core Source metadata borrows another stream')
                require_c09_logical_source_row_member_v3(db,stream,role='core',table_name=row[2],key=tuple(json.loads(row[4])),record_ordinal=row[6],meter=meter)
                self.last=tuple(row[:4]);self.counts[2]+=1;return False
        if self.phase=='issue':
            self.complete=True;self.proof=SelectedCoreSourceMetadataV3(_TOKEN,self)
            self.basis._core_source_metadata_v3=self.proof;return True
        raise AuthorityUnavailable('unknown selected Core Source verification phase')


def begin_selected_core_source_metadata_read_v3(basis,*,meter):
    from .c09_selected_history_v3 import _InstalledSelectedStorageBasisV3
    if type(basis) is not _InstalledSelectedStorageBasisV3:
        raise AuthorityUnavailable('actual selected Core Source basis required')
    basis.require_current(meter=meter)
    return SelectedCoreSourceMetadataReadV3(_TOKEN,basis)


class VerifiedSelectedRetiredCounterSourceV3:
    def __init__(self,token,coverage,original,descriptor):
        if token is not _TOKEN or coverage not in _PROOFS:
            raise AuthorityUnavailable('actual selected retirement Source chain issuer required')
        self.coverage,self.basis,self.original,self.descriptor=coverage,coverage.basis,dict(original),descriptor
        _ROWS.add(self)
    def require_current(self,*,meter):
        if self not in _ROWS:raise AuthorityUnavailable('registered retirement Source row proof required')
        self.coverage.require_current(meter=meter)
        return self


def require_selected_retired_counter_source_v3(basis,*,retirement_original,meter):
    from .c09_d13_source_retirement_v3 import validate_retirement_original_v3,TABLE,COLUMNS
    from .c09_selected_history_v3 import _read_one
    from ..runtime_storage_v3 import _core_payload_owner_v3
    coverage=getattr(basis,'_core_source_metadata_v3',None)
    if type(coverage) is not SelectedCoreSourceMetadataV3 or coverage.basis is not basis:
        raise AuthorityUnavailable('complete actual selected Core Source metadata qualification required')
    coverage.require_current(meter=meter)
    original=validate_retirement_original_v3(basis.control,retirement_original)
    if original['namespace']!=basis.prepared['namespace'] or original['kind']!='counter':
        raise AuthorityUnavailable('selected retirement counter scope differs')
    key=tuple(original['source_primary_key']);descriptor=None
    with basis.read_database('core',meter=meter) as db:
        saved=meter.read_fixed_row(db,TABLE,COLUMNS,'namespace=? AND kind=? AND item_id=? AND phase=?',
            (original['namespace'],original['kind'],original['item_id'],original['phase']))
        if saved is None or saved[7]!=canonical_serialize(original):
            raise AuthorityUnavailable('selected retirement row differs from signed original')
        kind='row_dispositions' if original['source_member'] is None else 'source_originals_v3'
        directory=meter.read_fixed_row(db,'authority_c09_role_streams_v2',_DIRECTORY,
            'scope_digest=? AND role=? AND table_name=? AND stream_kind=?',
            (original['scope_digest'],'core',original['source_table'],kind))
        if directory is None:raise AuthorityUnavailable('retired counter lost its authenticated Source directory')
        locator=_locator(directory);stream=locator.identity
        member=_read_one(db,'SELECT record_ordinal,commitment FROM c09_capture_members_v2 WHERE stream_id=? AND key_digest=?',
            (stream.stream_id,canonical_digest(key)),meter)
        if member is None or not 1<=member[0]<=locator.complete.record_count:
            raise AuthorityUnavailable('retired counter lost its sealed Source member')
        if original['source_member'] is None:
            row=meter.read_fixed_row(db,'authority_c09_role_rows_v2',_DISPOSITION,
                'scope_digest=? AND role=? AND table_name=? AND key_digest=?',
                (original['scope_digest'],'core',original['source_table'],canonical_digest(key)))
            if row is None or row[5]!=original['source_physical_row_commitment'] or row[6]!='d13_content_retired_v3':
                raise AuthorityUnavailable('legacy counter retirement lacks its complete erased Source disposition')
            require_c09_capture_member_v2(db,stream,member[0],key,canonical_digest(('sylanne3.c09.authority-row-disposition.v2',tuple(row))),meter=meter)
        else:
            source=original['source_member']
            if source['stream_id']!=stream.stream_id or source['record_ordinal']!=member[0]:
                raise AuthorityUnavailable('counter retirement borrows another historical Source member')
            descriptor=require_c09_logical_source_row_member_v3(db,stream,role='core',table_name=original['source_table'],key=key,record_ordinal=member[0],meter=meter)
            if (canonical_digest(descriptor)!=original['source_descriptor_digest']
                    or descriptor['physical_row_commitment']!=original['source_physical_row_commitment']
                    or descriptor['logical_row_commitment']!=original['source_logical_row_commitment']
                    or descriptor['source_role_digest']!=original['source_role_digest']
                    or descriptor['physical_schema_digest']!=original['physical_schema_digest']
                    or descriptor['logical_shape_digest']!=original['logical_shape_digest']):
                raise AuthorityUnavailable('counter retirement and full Source descriptor differ')
            header=tuple(original['source_cell_header']);bindings=descriptor['cell_bindings']
            if len(bindings)!=1:raise AuthorityUnavailable('counter retirement mapped Source binding count differs')
            binding=bindings[0]
            if 'source_header9' not in binding:
                raise AuthorityUnavailable('retired mapped Source descriptor has no original full header carrier')
            if (tuple(binding['source_header9'])!=header or len(header)!=9 or canonical_digest(header)!=binding['header_digest'] or header[0]!=binding['cell_id']
                    or header[1]!=binding['codec_id'] or header[4]!=binding['total_bytes'] or header[5]!=binding['segment_count']
                    or header[6]!=binding['payload_sha256'] or header[7]!=binding['ordered_segment_root']
                    or header[6]!=original['source_payload_digest'] or header[8]!=original['source_payload_origin_scope_digest']
                    or header[2]!=_core_payload_owner_v3(original['source_table'],key)
                    or binding['logical_column']!='payload_json' or binding['physical_column']!='payload_cell_id'):
                raise AuthorityUnavailable('counter retirement observed Source header differs from complete descriptor')
        disposition=meter.read_fixed_row(db,'authority_c09_role_rows_v2',_DISPOSITION,
            'scope_digest=? AND role=? AND table_name=? AND key_digest=?',
            (original['scope_digest'],'core',original['source_table'],canonical_digest(key)))
        expected=original['source_physical_row_commitment'] if descriptor is None else original['source_descriptor_digest']
        if disposition is None or disposition[5]!=expected or disposition[6]!='d13_content_retired_v3' or disposition[7] is not None:
            raise AuthorityUnavailable('counter retirement lacks its actual complete content retirement disposition')
    return VerifiedSelectedRetiredCounterSourceV3(_TOKEN,coverage,original,descriptor).require_current(meter=meter)
