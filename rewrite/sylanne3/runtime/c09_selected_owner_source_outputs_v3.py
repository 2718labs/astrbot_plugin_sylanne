"""Explicit selected OwnerSource output mappings and bounded cold byte readers."""
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from weakref import WeakSet

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.c09_selected_history_v3 import _InstalledSelectedStorageBasisV3, _read_one
from ..runtime_contracts import canonical_digest, canonical_serialize
from .c09_paged_sql_v2 import require_c09_reserved_meter_v3
from .c09_owner_source_output_mappings_v3 import (
    VerifiedSelectedOwnerOutputMappingRowV3, require_selected_owner_output_mapping_row_v3,
)
from .owner_material_source_storage_v3 import read_selected_owner_source_prepared_v3

_ISSUER = object()
_BYTES_READERS = WeakSet()
_HEADER = ('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes',
    'segment_count','payload_sha256','ordered_segment_root','origin_scope_digest')
_CURSOR = ('cell_id','origin_scope_digest','logical_locator_json','codec_id',
    'producer_operation_id','erasure_owner_ref','phase','next_ordinal','next_byte_offset',
    'prefix_root','prefix_sha256','source_cursor_json','expected_total_bytes',
    'verify_next_ordinal','verify_next_byte_offset','verify_prefix_root','verify_prefix_sha256',
    'cursor_revision')


def _database(db, basis, meter):
    if (type(basis) is not _InstalledSelectedStorageBasisV3
            or type(db) is not sqlite3.Connection
            or require_c09_reserved_meter_v3(meter.budget) is not meter):
        raise AuthorityUnavailable('actual selected Owner output database and reserved Root required')
    basis.require_current(meter=meter)
    rows = db.execute('PRAGMA database_list').fetchall()
    if (not db.in_transaction or len(rows)!=1
            or Path(rows[0][2]).resolve(strict=True)!=Path(basis.member('graph')['resolved_path']).resolve(strict=True)):
        raise AuthorityUnavailable('Owner output lookup crossed the actual selected Graph transaction')


class _SelectedOutputV3:
    __slots__ = ('_issuer','_proof','prepared_digest','cell_name','original_owner_cell_id',
        'metadata','mapping_row','_prepared_phase','_actual_committed')

    def __init__(self, token, proof, prepared):
        if token is not _ISSUER or type(proof) is not VerifiedSelectedOwnerOutputMappingRowV3:
            raise AuthorityUnavailable('private retained mapping original required')
        self._issuer,self._proof = token,proof
        self.prepared_digest,self.cell_name = proof.row[1:3]
        self.original_owner_cell_id = proof.original_owner_cell_id
        self.metadata,self.mapping_row = proof.metadata,proof.row
        self._prepared_phase,self._actual_committed = prepared['phase'],prepared['actual_committed']

    def require_current(self, meter):
        if self._issuer is not _ISSUER:
            raise AuthorityUnavailable('issued selected output required')
        with self._proof.basis.read_database('graph',meter=meter) as db:
            self.require_database_current_v3(db=db,meter=meter)

    def require_database_current_v3(self, *, db, meter):
        if self._issuer is not _ISSUER:
            raise AuthorityUnavailable('issued selected output required')
        _database(db,self._proof.basis,meter)
        self._proof.require_current(db=db,meter=meter)

    def require_committed(self, *, db, meter):
        self.require_database_current_v3(db=db,meter=meter)
        prepared=read_selected_owner_source_prepared_v3(db,basis=self._proof.basis,
            prepared_digest=self.prepared_digest,meter=meter)
        if (prepared is None or prepared['metadata']!=self.metadata
                or prepared['phase']!='committed' or not prepared['actual_committed']):
            raise AuthorityUnavailable('ordinary Owner output read needs its actual committed W01 original')


class VerifiedSelectedOwnerSourceCompleteOutputV3(_SelectedOutputV3):
    __slots__ = ('current_cell_id','current_header9')

    def __init__(self, token, proof, prepared, header):
        super().__init__(token,proof,prepared)
        self.current_header9,self.current_cell_id = header,header[0]

    def begin_cold_verification_v3(self):
        return SelectedOwnerSourceOutputBytesReadV3(_ISSUER,self)

    def begin_committed_material_read_v3(self, *, db, meter):
        self.require_committed(db=db,meter=meter)
        return self.begin_cold_verification_v3()


class VerifiedSelectedOwnerSourcePrefixOutputV3(_SelectedOutputV3):
    __slots__ = ('current_cell_id','current_cursor')

    def __init__(self, token, proof, prepared, cursor):
        super().__init__(token,proof,prepared)
        self.current_cursor,self.current_cell_id = cursor,cursor[0]

    def begin_prefix_verification_v3(self):
        return SelectedOwnerSourceOutputBytesReadV3(_ISSUER,self)


class VerifiedSelectedOwnerSourceRetiredOutputV3(_SelectedOutputV3):
    __slots__ = ()


def resolve_selected_owner_source_output_v3(db, *, basis, prepared_digest, cell_name, meter):
    """Resolve an explicit prepared/name mapping; byte EOF is a separate reader."""
    _database(db,basis,meter)
    proof=require_selected_owner_output_mapping_row_v3(db,basis,prepared_digest,cell_name,meter)
    if proof is None:
        return None
    if type(proof) is not VerifiedSelectedOwnerOutputMappingRowV3 or proof.basis is not basis:
        raise AuthorityUnavailable('actual private selected mapping row proof required')
    proof.require_current(db=db,meter=meter)
    prepared=read_selected_owner_source_prepared_v3(db,basis=basis,
        prepared_digest=prepared_digest,meter=meter)
    if (prepared is None or prepared['metadata']!=proof.metadata
            or proof.row[1:3]!=(prepared_digest,cell_name)):
        raise AuthorityUnavailable('retained output mapping changed its immutable prepared metadata')
    expected=proof.metadata['expected_outputs'][cell_name]
    original_id=canonical_digest(dict(schema='sylanne3.owner-source-cell.v3',
        instance=proof.metadata['storage_instance'],prepared_digest=prepared_digest,
        name=cell_name,sha256=expected['payload_sha256']))
    if proof.original_owner_cell_id!=original_id:
        raise AuthorityUnavailable('mapping crossed its initial Owner output identity')
    if proof.outcome=='retired':
        return VerifiedSelectedOwnerSourceRetiredOutputV3(_ISSUER,proof,prepared)
    if proof.outcome=='complete':
        header=tuple(proof.target_descriptor['header9'])
        actual=meter.read_fixed_row(db,'segmented_cells_v1',_HEADER,'cell_id=?',(header[0],))
        if (len(header)!=9 or actual!=header or header[0]!=proof.row[8]
                or header[1]!='canonical-json.ascii.v1'
                or header[2]!=proof.metadata['source_ref']
                or (header[4],header[6])!=(expected['total_bytes'],expected['payload_sha256'])):
            raise AuthorityUnavailable('mapped complete output lost its real target header/bytes/SHA')
        return VerifiedSelectedOwnerSourceCompleteOutputV3(_ISSUER,proof,prepared,header)
    cursor=tuple(proof.target_descriptor['cursor'])
    actual=meter.read_fixed_row(db,'segmented_cell_writes_v1',_CURSOR,'cell_id=?',(cursor[0],))
    if (len(cursor)!=18 or actual!=cursor or cursor[0]!=proof.row[8]
            or cursor[3]!='canonical-json.ascii.v1' or cursor[5]!=proof.metadata['source_ref']
            or cursor[12]!=expected['total_bytes'] or not 0<=cursor[8]<=cursor[12]):
        raise AuthorityUnavailable('mapped prefix lost its real finite target cursor')
    return VerifiedSelectedOwnerSourcePrefixOutputV3(_ISSUER,proof,prepared,cursor)


def begin_selected_mapped_owner_source_prefix_read_v3(db, *, basis, cursor, meter):
    """Consume the explicit new prefix locator, never an old cell-ID alias."""
    _database(db,basis,meter)
    locator=json.loads(cursor[2])
    fields={'schema','capture_scope_digest','prepared_digest','cell_name',
        'original_owner_cell_id','source_cell_descriptor_digest'}
    if (type(locator) is not dict or set(locator)!=fields
            or canonical_serialize(locator)!=cursor[2]
            or locator['schema']!='sylanne3.c09.owner-source-output-prefix-target.v3'
            or locator['capture_scope_digest']!=basis.prepared['capture_scope_digest']
            or cursor[1]!=locator['capture_scope_digest']):
        raise AuthorityUnavailable('cutoff prefix lacks its explicit Owner output mapping locator')
    output=resolve_selected_owner_source_output_v3(db,basis=basis,
        prepared_digest=locator['prepared_digest'],cell_name=locator['cell_name'],meter=meter)
    if (type(output) is not VerifiedSelectedOwnerSourcePrefixOutputV3
            or output.current_cursor!=tuple(cursor)
            or output.original_owner_cell_id!=locator['original_owner_cell_id']
            or output.mapping_row[6]!=locator['source_cell_descriptor_digest']):
        raise AuthorityUnavailable('actual prefix crossed its retained output mapping original')
    return output.begin_prefix_verification_v3()


class SelectedOwnerSourceOutputBytesReadV3:
    """Stream target bytes without retaining a whole output or reviving a command."""
    __slots__=('output','cell_id','cursor','ordinal','offset','hash','root','complete',
        'last_fragment','_segment','_segment_offset','_segment_hash','_count','_bytes','_sha','_root','__weakref__')

    def __init__(self, token, output):
        if token is not _ISSUER or type(output) not in (
                VerifiedSelectedOwnerSourceCompleteOutputV3,VerifiedSelectedOwnerSourcePrefixOutputV3):
            raise AuthorityUnavailable('actual Complete or Prefix selected output required')
        self.output,self.cell_id=output,output.current_cell_id
        self.cursor=output.current_cursor if type(output) is VerifiedSelectedOwnerSourcePrefixOutputV3 else None
        if self.cursor is None:
            header=output.current_header9
            self._count,self._bytes,self._sha,self._root=header[5],header[4],header[6],header[7]
        else:
            self._count,self._bytes,self._sha,self._root=self.cursor[7],self.cursor[8],self.cursor[10],self.cursor[9]
        self.ordinal,self.offset=0,0
        self.hash=sha256()
        self.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',self.cell_id))
        self.complete=False
        self.last_fragment=None
        self._segment=None
        self._segment_offset=0
        self._segment_hash=None
        _BYTES_READERS.add(self)

    def copy_for_c09_quantum_v3(self, *, meter):
        from copy import copy
        if (type(self) is not SelectedOwnerSourceOutputBytesReadV3 or self not in _BYTES_READERS
                or require_c09_reserved_meter_v3(meter.budget) is not meter):
            raise AuthorityUnavailable('actual private mapped output progress and reserved Root required')
        self.output.require_current(meter)
        result=copy(self)
        result.hash=self.hash.copy()
        if self._segment_hash is not None:
            result._segment_hash=self._segment_hash.copy()
        _BYTES_READERS.add(result)
        return result

    def _c09_retained_heap_bytes_v3(self):
        # The canonical original includes the decoded metadata and nested descriptors.
        return 8192+len(self.output.mapping_row[11].encode('ascii'))*12

    def advance(self, *, db, meter):
        self.output.require_database_current_v3(db=db,meter=meter)
        self.last_fragment=None
        if self.cursor is None:
            actual=meter.read_fixed_row(db,'segmented_cells_v1',_HEADER,'cell_id=?',(self.cell_id,))
            if actual!=self.output.current_header9:
                raise AuthorityUnavailable('mapped complete target changed during its byte verification')
        else:
            actual=meter.read_fixed_row(db,'segmented_cell_writes_v1',_CURSOR,'cell_id=?',(self.cell_id,))
            if actual!=self.cursor:
                raise AuthorityUnavailable('mapped prefix cursor changed during byte verification')
        if self.complete:
            return {'status':'complete','cell_id':self.cell_id,'prefix_sha256':self.hash.hexdigest()}
        if self.ordinal==self._count:
            extra=_read_one(db,'SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? LIMIT 1',
                (self.cell_id,self.ordinal),meter)
            if (extra is not None or (self.offset,self.hash.hexdigest(),self.root)!=(self._bytes,self._sha,self._root)):
                raise AuthorityUnavailable('mapped Owner output bytes/count/root/SHA/EOF differs')
            self.complete=True
            return {'status':'complete','cell_id':self.cell_id,'prefix_sha256':self.hash.hexdigest()}
        if self._segment is None:
            row=_read_one(db,'SELECT byte_offset,length(payload),payload_sha256 FROM segmented_cell_segments_v1 '
                'WHERE cell_id=? AND ordinal=?',(self.cell_id,self.ordinal),meter)
            if row is None or row[0]!=self.offset or not 1<=row[1]<=16384 or self.offset+row[1]>self._bytes:
                raise AuthorityUnavailable('mapped output segment offset/finite length differs')
            self._segment,self._segment_offset,self._segment_hash=row,0,sha256()
            return {'status':'progress'}
        length=min(1024,self._segment[1]-self._segment_offset)
        row=_read_one(db,'SELECT substr(payload,?,?) FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal=?',
            (self._segment_offset+1,length,self.cell_id,self.ordinal),meter)
        if row is None or type(row[0]) is not bytes or len(row[0])!=length:
            raise AuthorityUnavailable('mapped output fragment is missing or changed length')
        fragment=row[0]
        self.hash.update(fragment)
        self._segment_hash.update(fragment)
        self._segment_offset+=length
        self.last_fragment=fragment
        if self._segment_offset==self._segment[1]:
            if self._segment_hash.hexdigest()!=self._segment[2]:
                raise AuthorityUnavailable('mapped output segment SHA differs')
            self.root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.root,self.cell_id,
                self.ordinal,self.offset,self._segment[1],self._segment[2]))
            self.offset+=self._segment[1]
            self.ordinal+=1
            self._segment=self._segment_hash=None
        return {'status':'progress'}
