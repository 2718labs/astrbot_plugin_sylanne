"""Actual frozen C09 Source rows over registered physical cell bindings.

Physical schema and physical row commitments retain their original meaning.
Logical commitments reproduce the legacy SQLite tagged-cell UTF-8 algorithm.
"""
from __future__ import annotations

import codecs
import json
from copy import copy
from dataclasses import dataclass, fields, is_dataclass
from hashlib import sha256
import sys
from weakref import WeakKeyDictionary

from ..authority_service.c09_source_physical_read_v3 import SourcePhysicalReadScopeV3
from ..authority_service.c09_paged_recovery_facts_v2 import _read_one
from ..authority_service import c09_authority_storage_rebase as legacy
from ..runtime_contracts import canonical_digest
from ..graph_types import AtomKey
from ..runtime_storage_v3 import _core_payload_owner_v3
from ..segmented_sql_cell_v1 import LAYOUTS
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .c09_paged_sql_v2 import (
    C09TableShapeV2, C09PagedCaptureHold, require_c09_reserved_meter_v3,
    read_c09_table_shape_v2, _quote, legacy_cell_read_transaction_v2,
    read_legacy_sql_cell_fragment_v2,
)

_SHAPE = object()
_COMPLETE = object()
_ISSUED_SHAPES = WeakKeyDictionary()
_CORE_PAYLOAD_TABLES = frozenset((
    'authority_d13_counter_originals_v1', 'authority_d13_provider_http_bindings_v1',
))


def _retained_size(value, seen):
    if id(value) in seen:
        return 0
    seen.add(id(value))
    size = sys.getsizeof(value)
    if type(value) is dict:
        return size + sum(_retained_size(k, seen) + _retained_size(v, seen) for k, v in value.items())
    if type(value) in (list, tuple, set, frozenset):
        return size + sum(_retained_size(v, seen) for v in value)
    if is_dataclass(value):
        return size + sum(_retained_size(getattr(value, field.name), seen) for field in fields(value))
    return size


@dataclass(frozen=True)
class C09LogicalSourceShapeV3:
    physical_shape: C09TableShapeV2
    storage_role: str
    layout_id: str
    layout_schema_digest: str
    logical_columns: tuple[str, ...]
    logical_types: tuple[str, ...]
    fixed_column_bindings: tuple[tuple[str, str, str], ...]
    logical_codec_id: str
    logical_codec_version: int
    logical_shape_digest: str
    schema: str = 'sylanne3.c09.logical-source-shape.v3'

    @property
    def table(self):
        return self.physical_shape.table


def _shape_descriptor(physical, role, layout, layout_digest, columns, types, bindings):
    return {'schema': 'sylanne3.c09.logical-source-shape.v3',
        'physical_schema_digest': physical.schema_digest,
        'physical_table': physical.table, 'physical_columns': physical.columns,
        'physical_primary_key_columns': physical.primary_key_columns,
        'physical_primary_key_types': physical.primary_key_types,
        'storage_role': role, 'layout_id': layout,
        'layout_schema_digest': layout_digest, 'logical_columns': columns,
        'logical_types': types, 'fixed_column_bindings': bindings,
        'logical_codec_id': 'c09.legacy-tagged-sql-row.utf8.v1',
        'logical_codec_version': 1}


def _current(scope, meter):
    if type(scope) is not SourcePhysicalReadScopeV3:
        raise C09PagedCaptureHold('actual private frozen Source physical read scope required')
    if require_c09_reserved_meter_v3(meter.budget) is not meter:
        raise C09PagedCaptureHold('logical Source cannot replace the actual reserved quantum')
    scope.require_current(meter=meter)


def read_c09_logical_source_shape_v3(scope, table, *, meter):
    """Resolve actual physical DDL and only the registered logical bindings."""
    _current(scope, meter)
    physical = read_c09_table_shape_v2(scope.source, table, meter=meter)
    meter.require_available(65536)
    layout = meter.read_fixed_row(scope.source, 'segmented_storage_layout_v1',
        ('role', 'layout_id', 'layout_schema_digest'), 'singleton=1', ())
    if layout is None or layout[0] != scope.role or layout[1] != LAYOUTS[scope.role]:
        raise C09PagedCaptureHold('logical Source requires its actual registered segmented role layout')
    metadata = tuple(scope.source.execute('PRAGMA table_xinfo(' + _quote(table) + ')').fetchmany(101))
    if len(metadata) != len(physical.columns) or tuple(row[1] for row in metadata) != physical.columns:
        raise C09PagedCaptureHold('actual physical Source column inventory changed')
    meter.charge_read(sum(sum(len(str(v).encode('utf8')) for v in row if v is not None) for row in metadata))
    bindings, columns, types = [], [], []
    from .domain_production_originals_v1 import PHYSICAL_TABLE,PHYSICAL_DDL
    if scope.role=='graph' and table==PHYSICAL_TABLE:
        registered=('bot','persona','operation_id','domain','operation_kind','request_digest','original_digest',
            'original_payload_cell_id','prepared_digest','read_versions_json','bundle_digest','receipt_json','receipt_digest')
        actual=meter.read_fixed_row(scope.source,'sqlite_master',('sql',),'type=? AND name=?',('table',PHYSICAL_TABLE))
        if physical.columns!=registered or physical.primary_key_columns!=('bot','persona','operation_id') or actual!=(PHYSICAL_DDL.replace(' IF NOT EXISTS',''),):
            raise C09PagedCaptureHold('registered actual13-column Domain Source schema differs')
        mapped={'original_payload_cell_id':'original_payload_json'}
    else:
        mapped = {'value_cell_id': 'value'} if scope.role == 'graph' and table in ('graph_atoms', 'graph_history') else (
            {'payload_cell_id': 'payload_json'} if scope.role == 'core' and table in _CORE_PAYLOAD_TABLES else {})
    if mapped and (not set(mapped) <= set(physical.columns)
                   or any(name in physical.columns for name in mapped.values())):
        raise C09PagedCaptureHold('registered Source cell binding is absent from its actual physical DDL')
    for row in metadata:
        physical_column = row[1]
        logical_column = mapped.get(physical_column, physical_column)
        columns.append(logical_column)
        types.append('TEXT' if physical_column in mapped else row[2])
        bindings.append((logical_column, physical_column,
                         'segmented_cell' if physical_column in mapped else 'physical_scalar'))
    columns, types, bindings = tuple(columns), tuple(types), tuple(bindings)
    meter.require_available(65536)
    digest = canonical_digest(_shape_descriptor(physical, scope.role, layout[1], layout[2], columns, types, bindings))
    result = C09LogicalSourceShapeV3(physical, scope.role, layout[1], layout[2], columns, types,
        bindings, 'c09.legacy-tagged-sql-row.utf8.v1', 1, digest)
    _ISSUED_SHAPES[result] = scope
    _current(scope, meter)
    return result


@dataclass(frozen=True)
class C09LogicalSourceCellDescriptorV3:
    logical_column: str
    physical_column: str
    cell_id: str
    header: tuple
    binding_kind: str = 'segmented_cell'

    @property
    def total_bytes(self):
        return self.header[4]


@dataclass(frozen=True)
class C09LogicalSourceScalarDescriptorV3:
    table: str
    primary_key: tuple
    physical_column: str
    sqlite_type: str
    total_bytes: int
    binding_kind: str = 'physical_scalar'


class CompleteLogicalSourceRowV3:
    """Issued only after physical row, mapped cells and scope EOF are complete."""
    def __init__(self, token, scope, shape, key, physical, logical, bindings):
        if token is not _COMPLETE:
            raise C09PagedCaptureHold('actual complete logical Source producer required')
        self.scope, self.shape, self.primary_key = scope, shape, key
        self.physical_row_commitment, self.logical_row_commitment = physical, logical
        self.cell_bindings = tuple(bindings)
        self.source_role_digest = scope.source_original.role_source_digest
        self.descriptor = {'schema': 'sylanne3.c09.logical-source-row.v3',
            'source_role_digest': self.source_role_digest,
            'physical_schema_digest': shape.physical_shape.schema_digest,
            'logical_shape_digest': shape.logical_shape_digest, 'primary_key': key,
            'physical_row_commitment': physical, 'cell_bindings': self.cell_bindings,
            'logical_row_commitment': logical}
        self.descriptor_digest = canonical_digest(self.descriptor)

    @property
    def commitment(self):
        return self.descriptor_digest


class C09LogicalSourceRowReadV3:
    """Resumable, bodyless descriptor plus exact physical/logical digest state."""
    def __init__(self, token, scope, shape, key):
        if token is not _SHAPE:
            raise C09PagedCaptureHold('actual begin logical Source row required')
        self.scope, self.shape, self.primary_key = scope, shape, tuple(key)
        self.metadata, self.cell_bindings = {}, []
        self.physical, self.logical = sha256(), sha256()
        self.column, self.phase = 0, 'begin'
        self.kind, self.total, self.offset = None, 0, 0
        self.cell, self.ordinal = None, 0
        self.cell_hash, self.cell_root, self.parser, self.decoder = None, None, None, None
        self.fragment, self.fragment_offset = b'', 0
        self.last_logical_fragment, self.last_cell_eof = None, None
        self.complete, self.result = False, None
        self._arena = scope.arena
        self._arena.add(self)

    @property
    def commitment(self):
        if not self.complete:
            raise C09PagedCaptureHold('logical Source composite requires whole row EOF')
        return self.result.commitment

    def _source_heap_bytes(self):
        payload = (self.metadata, self.cell_bindings, self.primary_key, self.shape,
                   self.fragment, self.last_logical_fragment, self.last_cell_eof, self.cell,
                   None if self.result is None else self.result.descriptor)
        if self.parser is not None:
            payload += (self.parser._stack, self.parser._string, self.parser._literal,
                        self.parser._number, self.parser._active_scalar)
        if self.decoder is not None:
            payload += (self.decoder.getstate(),)
        return sys.getsizeof(self.__dict__) + _retained_size(payload, set()) + 32768

    def require_arena(self, meter, additional=0):
        if sum(value._source_heap_bytes() for value in self._arena) + additional > meter.budget.reserved_arena_bytes:
            raise C09PagedCaptureHold('actual retained logical Source/copies exceed the reserved arena')

    def copy(self, meter):
        self.require_arena(meter, self._source_heap_bytes())
        result = copy(self)
        result.metadata, result.cell_bindings = dict(self.metadata), list(self.cell_bindings)
        result.physical, result.logical = self.physical.copy(), self.logical.copy()
        if self.cell_hash is not None:
            result.cell_hash = self.cell_hash.copy()
        if self.parser is not None:
            result.parser = self.parser.copy()
        if self.decoder is not None:
            result.decoder = codecs.getincrementaldecoder('utf-8')('strict')
            result.decoder.setstate(self.decoder.getstate())
        self._arena.add(result)
        result.require_arena(meter)
        return result

    def _where(self):
        return ' AND '.join(_quote(name) + '=?' for name in self.shape.physical_shape.primary_key_columns)

    def _encode(self, value, meter):
        encoded = legacy._canonical(value)
        meter.charge_encode(len(encoded))
        return encoded

    def _write(self, encoded, *, physical=False, logical=False):
        if physical:
            self.physical.update(encoded)
        if logical:
            self.logical.update(encoded)

    def _begin(self, meter):
        self.require_arena(meter, 65536)
        physical_shape = self.shape.physical_shape
        row = meter.read_fixed_row(self.scope.source, physical_shape.table,
            physical_shape.primary_key_columns, self._where(), self.primary_key)
        if row is None or tuple(row) != self.primary_key:
            raise C09PagedCaptureHold('actual frozen logical Source primary key is absent or differs')
        self.physical.update(self._encode((physical_shape.table, physical_shape.columns), meter)[:-1] + b',[')
        self.logical.update(self._encode((physical_shape.table, self.shape.logical_columns), meter)[:-1] + b',[')
        self.phase = 'column'

    def _column(self, meter):
        if self.column == len(self.shape.logical_columns):
            meter.charge_encode(4)
            self.physical.update(b']]'); self.logical.update(b']]')
            self.phase = 'finish'
            return
        logical_column, name, binding = self.shape.fixed_column_bindings[self.column]
        comma = b',' if self.column else b''
        meter.require_available(65536)
        if binding == 'segmented_cell':
            row = meter.read_fixed_row(self.scope.source, self.shape.table, (name,), self._where(), self.primary_key)
            if row is None or type(row[0]) is not str:
                raise C09PagedCaptureHold('actual mapped Source cell reference is absent or differs')
            header = self.scope.read_cell_header_v3(row[0], meter=meter)
            if header[0] != row[0] or header[1] not in ('canonical-json.ascii.v1', 'canonical-json.utf8.v1'):
                raise C09PagedCaptureHold('mapped SQLite TEXT requires its registered JSON cell codec')
            from .domain_production_originals_v1 import PHYSICAL_TABLE
            if self.scope.role=='graph' and self.shape.table==PHYSICAL_TABLE:
                from ..runtime_contracts import NamespaceId
                from ..memory_types import source_key
                from .owner_material_source_v1 import owner_material_source_id_v1
                ns=NamespaceId(*self.primary_key[:2]);owner=source_key(*ns.as_tuple,owner_material_source_id_v1(ns,self.primary_key[2]))
                original=meter.read_fixed_row(self.scope.source,PHYSICAL_TABLE,('domain','operation_kind','original_digest'),
                    'bot=? AND persona=? AND operation_id=?',self.primary_key)
                if (ns.as_tuple!=tuple(json.loads(self.scope.session.scope.graph_namespace)) or header[2]!=owner.token
                        or header[1]!='canonical-json.ascii.v1' or original!=('d06','admit_owner_material_source_v1',header[6])):
                    raise C09PagedCaptureHold('actual Domain Source namespace/Owner/kind/original canonical SHA differs')
            elif self.scope.role == 'graph':
                atom = AtomKey.from_token(self.primary_key[0])
                if (header[2] != atom.token
                        or (atom.owner.bot, atom.owner.persona) != tuple(json.loads(self.scope.session.scope.graph_namespace))):
                    raise C09PagedCaptureHold('mapped Source header erasure owner/namespace differs from its actual Graph row')
            elif self.shape.table in _CORE_PAYLOAD_TABLES:
                phases = ('draft', 'header', 'evidence') if self.shape.table == 'authority_d13_counter_originals_v1' else ('expected', 'observed_before_send')
                if (self.primary_key[0] != self.scope.session.scope.authority_namespace
                        or self.primary_key[2] not in phases
                        or header[2] != _core_payload_owner_v3(self.shape.table, self.primary_key)):
                    raise C09PagedCaptureHold('mapped Core Source header erasure owner/phase differs from its actual row')
            self.require_arena(meter, 32768)
            self.cell = C09LogicalSourceCellDescriptorV3(logical_column, name, row[0], tuple(header))
            self.metadata[logical_column] = self.cell
            self.physical.update(comma + self._encode(legacy._cell(row[0]), meter))
            prefix = comma + b'["text","'
            meter.charge_encode(len(prefix)); self.logical.update(prefix)
            self.total, self.offset, self.ordinal = header[4], 0, 0
            self.cell_hash = sha256()
            self.cell_root = canonical_digest(('sylanne3.segmented-cell-genesis.v1', row[0]))
            self.parser = C09CanonicalJSONStreamV2(ensure_ascii=header[1] == 'canonical-json.ascii.v1')
            self.decoder = codecs.getincrementaldecoder('utf-8')('strict')
            self.phase = 'segment'
            return
        found = _read_one(self.scope.source, 'SELECT typeof(' + _quote(name) + '),length(CAST('
            + _quote(name) + ' AS BLOB)) FROM ' + _quote(self.shape.table) + ' WHERE ' + self._where(), self.primary_key, meter)
        if found is None:
            raise C09PagedCaptureHold('actual frozen physical Source scalar is absent')
        self.kind, self.total = found[0], 0 if found[1] is None else found[1]
        if self.kind not in ('text', 'blob') or self.total <= 4096:
            self.require_arena(meter, self.total * 8 + 32768)
            row = meter.read_fixed_row(self.scope.source, self.shape.table, (name,), self._where(), self.primary_key)
            encoded = comma + self._encode(legacy._cell(row[0]), meter)
            self._write(encoded, physical=True, logical=True)
            self.metadata[logical_column] = row[0]
            self.column += 1
            self.kind = None
            return
        self.metadata[logical_column] = C09LogicalSourceScalarDescriptorV3(self.shape.table, self.primary_key, name, self.kind, self.total)
        prefix = comma + b'["' + self.kind.encode('ascii') + b'","'
        meter.charge_encode(len(prefix)); self._write(prefix, physical=True, logical=True)
        self.decoder = codecs.getincrementaldecoder('utf-8')('strict') if self.kind == 'text' else None
        self.offset, self.phase = 0, 'scalar'

    def _scalar(self, meter):
        name = self.shape.fixed_column_bindings[self.column][1]
        amount = min(1024, self.total - self.offset)
        self.require_arena(meter, amount * 16 + 32768)
        meter.require_available(amount * 8 + 4096)
        raw, total, kind = read_legacy_sql_cell_fragment_v2(self.scope.source, table=self.shape.table,
            column=name, where=self._where(), parameters=self.primary_key,
            start=self.offset, length=amount, meter=meter)
        if total != self.total or kind != self.kind or len(raw) != amount:
            raise C09PagedCaptureHold('actual frozen physical scalar fragment changed')
        self.last_logical_fragment = (self.shape.logical_columns[self.column], raw)
        encoded = raw.hex().encode('ascii') if kind == 'blob' else legacy._canonical(
            self.decoder.decode(raw, final=self.offset + amount == total))[1:-1]
        meter.charge_encode(len(encoded)); self._write(encoded, physical=True, logical=True)
        self.offset += amount
        if self.offset == self.total:
            meter.charge_encode(2); self._write(b'"]', physical=True, logical=True)
            self.last_cell_eof = self.shape.logical_columns[self.column]
            self.column += 1
            self.kind, self.decoder, self.phase = None, None, 'column'

    def _segment(self, meter):
        self.require_arena(meter, 16384 * 4 + 32768)
        meter.require_available(131072)
        row = self.scope.read_cell_segment_v3(self.cell.cell_id, self.ordinal, meter=meter)
        if row is None:
            self.phase = 'cell_eof'
            return
        offset, raw, digest = row
        if offset != self.offset or sha256(raw).hexdigest() != digest:
            raise C09PagedCaptureHold('actual mapped Source segment order or hash differs')
        self.cell_root = canonical_digest(('sylanne3.segmented-cell-link.v1', self.cell_root,
            self.cell.cell_id, self.ordinal, offset, len(raw), digest))
        self.cell_hash.update(raw)
        self.ordinal += 1
        self.offset += len(raw)
        if self.offset > self.total:
            raise C09PagedCaptureHold('actual mapped Source segment exceeds its declared total')
        self.fragment, self.fragment_offset, self.phase = raw, 0, 'cell_parse'

    def _cell_parse(self, meter):
        end = min(self.fragment_offset + 1024, len(self.fragment))
        raw = self.fragment[self.fragment_offset:end]
        self.require_arena(meter, len(raw) * 16 + 32768)
        meter.require_available(len(raw) * 8 + 4096)
        self.parser.feed(raw, lambda event: None)
        self.last_logical_fragment = (self.cell.logical_column, raw)
        encoded = legacy._canonical(self.decoder.decode(raw, final=False))[1:-1]
        meter.charge_encode(len(encoded)); self.logical.update(encoded)
        self.fragment_offset = end
        if end == len(self.fragment):
            self.fragment, self.fragment_offset, self.phase = b'', 0, 'segment'

    def _cell_eof(self, meter):
        header = self.scope.require_cell_eof_v3(self.cell.cell_id, self.ordinal, meter=meter)
        parsed = self.parser.finish()
        tail = legacy._canonical(self.decoder.decode(b'', final=True))[1:-1]
        meter.charge_encode(len(tail) + 2); self.logical.update(tail + b'"]')
        if (tuple(header) != self.cell.header or self.offset != self.total
                or self.cell_hash.hexdigest() != header[6] or self.cell_root != header[7]
                or parsed.byte_count != self.total or parsed.sha256 != header[6]):
            raise C09PagedCaptureHold('actual mapped Source complete canonical/hash/root/EOF differs')
        self.last_cell_eof = self.cell.logical_column
        self.cell_bindings.append({'logical_column': self.cell.logical_column,
            'physical_column': self.cell.physical_column, 'cell_id': self.cell.cell_id,
            'codec_id': header[1], 'total_bytes': header[4], 'segment_count': header[5],
            'payload_sha256': header[6], 'ordered_segment_root': header[7],
            'header_digest': canonical_digest(tuple(header)),
            'source_header9': tuple(header)})
        self.column += 1
        self.cell, self.cell_hash, self.cell_root, self.parser, self.decoder = None, None, None, None, None
        self.phase = 'column'

    def advance(self, meter):
        _current(self.scope, meter)
        if self.complete:
            raise C09PagedCaptureHold('logical Source row already completed')
        result = self.copy(meter)
        result.last_logical_fragment, result.last_cell_eof = None, None
        with legacy_cell_read_transaction_v2(self.scope.source):
            if result.phase == 'begin': result._begin(meter)
            elif result.phase == 'column': result._column(meter)
            elif result.phase == 'scalar': result._scalar(meter)
            elif result.phase == 'segment': result._segment(meter)
            elif result.phase == 'cell_parse': result._cell_parse(meter)
            elif result.phase == 'cell_eof': result._cell_eof(meter)
            else:
                result.require_arena(meter, 65536)
                meter.require_available(65536)
                result.result = CompleteLogicalSourceRowV3(_COMPLETE, self.scope, self.shape,
                    self.primary_key, result.physical.hexdigest(), result.logical.hexdigest(), result.cell_bindings)
                result.complete = True
        result.require_arena(meter)
        _current(self.scope, meter)
        return result



def require_logical_source_shape_v3(shape, *, source=None):
    from .c09_paged_sql_v2 import current_c09_sql_meter_v2
    if type(shape) is not C09LogicalSourceShapeV3:
        raise C09PagedCaptureHold('actual private-issued logical Source shape required')
    scope = _ISSUED_SHAPES.get(shape)
    if scope is None or source is not None and scope.source is not source:
        raise C09PagedCaptureHold('logical Source shape belongs to another actual frozen source')
    _current(scope, current_c09_sql_meter_v2())
    return shape.physical_shape


def begin_logical_source_row_v3(scope, shape, physicalkey, meter):
    _current(scope, meter)
    if (type(shape) is not C09LogicalSourceShapeV3 or shape.storage_role != scope.role
            or _ISSUED_SHAPES.get(shape) is not scope):
        raise C09PagedCaptureHold('actual same-role logical Source shape required')
    if (len(physicalkey) != len(shape.physical_shape.primary_key_columns)
            or any(type(value) is not (int if kind == 'integer' else str)
                   for value, kind in zip(physicalkey, shape.physical_shape.primary_key_types))):
        raise C09PagedCaptureHold('actual logical Source physical primary key types differ')
    expected = canonical_digest(_shape_descriptor(shape.physical_shape, shape.storage_role,
        shape.layout_id, shape.layout_schema_digest, shape.logical_columns, shape.logical_types,
        shape.fixed_column_bindings))
    if expected != shape.logical_shape_digest:
        raise C09PagedCaptureHold('actual logical Source shape descriptor digest differs')
    result = C09LogicalSourceRowReadV3(_SHAPE, scope, shape, physicalkey)
    result.require_arena(meter)
    return result
