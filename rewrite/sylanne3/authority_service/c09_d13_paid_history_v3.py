"""Bounded read-only qualification of actual saved D13 paid history."""
from __future__ import annotations

from copy import copy, deepcopy
from dataclasses import asdict, fields, is_dataclass
from hashlib import sha256
from weakref import WeakSet
import json
import sys

from ..runtime_contracts import canonical_digest, canonical_serialize, VersionedRef
from ..runtime.d13_paid_intent_original_v1 import PAID_WORK_KIND
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from ..runtime.c09_paged_sql_v2 import (
    C09PagedCaptureHold, require_c09_reserved_meter_v3,
    legacy_cell_read_transaction_v2, read_c09_table_shape_v2,
)
from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
from .c09_authority_storage_rebase_v2 import (
    _D13PaidRowStreamV3, _D13PaidIdentityOriginalReadV3,
    _D13BoundBlockMetadataReadV3, _read_d13_original_fragment_v3,
    _copy_c09_canonical_state_v3,
)

_ISSUER = object()
_PROOFS = WeakSet()
_RESULT_JSON = ('read', 'observation', 'result_json')
_BILL_JSON = ('read', 'observation', 'billing_receipt_json')


def _heap(value):
    total = sys.getsizeof(value)
    if type(value) is dict:
        total += sum(_heap(key) + _heap(child) for key, child in value.items())
    elif type(value) in (tuple, list, set):
        total += sum(_heap(child) for child in value)
    elif is_dataclass(value) and not isinstance(value, type):
        total += sum(_heap(getattr(value, field.name)) for field in fields(value))
    return total


def _actual_meter(meter):
    if require_c09_reserved_meter_v3(meter.budget) is not meter:
        raise C09PagedCaptureHold('actual same-root paid history quantum required')
    return meter


def _digest(value, capture, meter):
    from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
    size = c09_canonical_json_size_v3(value, typed=True, exact=True)
    capture.parser._require_arena(size * 16 + 16384)
    meter.require_available(size * 2)
    wire = canonical_serialize(value).encode('ascii')
    meter.charge_encode(len(wire))
    return sha256(wire).hexdigest()


class _PaidProjectionV3(C09CanonicalJSONStreamV2):
    """Keep bodyless fields and byte ranges; never retain provider result strings."""
    def __init__(self, *, ensure_ascii=True, max_depth=64, max_key_bytes=1024):
        super().__init__(ensure_ascii=ensure_ascii, max_depth=max_depth, max_key_bytes=max_key_bytes)
        self.objects, self.arrays, self.values, self.starts, self.ranges = {}, {}, {}, {}, {}
        self.scalar = bytearray()

    def copy(self):
        result = super().copy()
        result.objects = {path: set(names) for path, names in self.objects.items()}
        result.arrays, result.values = dict(self.arrays), deepcopy(self.values)
        result.starts, result.ranges = dict(self.starts), dict(self.ranges)
        result.scalar = bytearray(self.scalar)
        return result

    def _observe(self, event):
        path = event.path
        if event.kind == 'key':
            self.objects[path[:-1]].add(event.key)
        elif event.kind in ('object_start', 'array_start', 'scalar_start'):
            self.starts[path] = event.start_offset
            if event.kind == 'object_start':
                self.objects[path] = set()
            elif event.kind == 'array_start':
                self.arrays[path] = 0
            else:
                self.scalar.clear()
            if path and type(path[-1]) is int:
                self.arrays[path[:-1]] = max(self.arrays[path[:-1]], path[-1] + 1)
        elif event.kind == 'scalar_chunk' and path not in (_RESULT_JSON, _BILL_JSON):
            self.scalar.extend(event.raw)
        elif event.kind in ('object_end', 'array_end', 'scalar_end'):
            self.ranges[path] = (self.starts[path], event.end_offset)
            if event.kind == 'scalar_end' and path not in (_RESULT_JSON, _BILL_JSON):
                self.values[path] = json.loads(self.scalar)
                self.scalar.clear()

    def feed(self, raw, emit=None):
        return super().feed(raw, self._observe)

    def project(self, path):
        if path in self.values:
            return self.values[path]
        if path in self.objects:
            return {name: self.project(path + (name,)) for name in self.objects[path]}
        if path in self.arrays:
            return [self.project(path + (index,)) for index in range(self.arrays[path])]
        raise C09PagedCaptureHold('actual saved paid metadata projection lacks a declared field')


class _PaidLifecycleRowV3(_D13PaidRowStreamV3):
    """Original source/target row commitment plus complete canonical payload EOF."""
    def __init__(self, owner, family):
        if family not in ('result', 'cost'):
            raise C09PagedCaptureHold('closed paid lifecycle family required')
        self.capture, self.graph, self.metadata = owner.capture, owner.graph, owner.metadata
        self.family = family
        self.table = 'graph_d13_paid_' + ('result_reads_v1' if family == 'result' else 'cost_receipts_v1')
        self.phase, self.small, self.shape, self.disposition = 'source', None, None, None
        self.target_small, self.parser, self.projection = None, None, None
        self.json_columns, self.decode_names = ('payload_json',), ()
        self.row_where = 'bot=? AND persona=? AND job_ref=?'
        self.row_key = (*self.metadata.namespace.as_tuple, self.metadata.job_ref)
        self.source_hash, self.target_hash = sha256(), sha256()
        self.column = self.offset = 0
        self.total = None
        self.buffer, self.values, self.json_source_bytes = bytearray(), {}, {}
        self.complete = False
        self.capture.parser._source_arena.add(self)

    def owned_values(self):
        return ()

    def _source_heap_bytes(self):
        parser = 0 if self.parser is None else _heap(self.parser.__dict__) + 4096
        projection = 0 if self.projection is None else _heap(self.projection.__dict__) + 4096
        return _heap(self.small) + _heap(self.target_small) + _heap(self.values) + parser + projection + len(self.buffer) + 8192

    def copy(self):
        result = super().copy()
        result.projection = None if self.projection is None else self.projection.copy()
        return result

    def _new_source_parser(self, name):
        return _PaidProjectionV3()

    def _source_json_complete(self, name, parser, eof):
        if eof.sha256 != self.small['payload_digest']:
            raise C09PagedCaptureHold('actual saved paid payload canonical hash differs from immutable row')
        self.projection = parser

    def advance(self, meter):
        _actual_meter(meter)
        builder = self.capture.builder
        self.capture.require_complete(builder, self.capture.shape, self.capture.key)
        if self.graph is not builder.session.require_actual_post_mirror_graph_v3():
            raise C09PagedCaptureHold('actual paid lifecycle lost its same Source/cold verifier')
        self.graph.require_current()
        result = self.copy()
        if result.phase == 'source':
            columns = ('bot', 'persona', 'job_ref') + (('read_attempt_id',) if self.family == 'result' else ()) + ('payload_json', 'payload_digest')
            with legacy_cell_read_transaction_v2(self.graph.pair.source):
                result.shape = read_c09_table_shape_v2(self.graph.pair.source, self.table, meter=meter)
                if (result.shape.columns != columns or result.shape.primary_key_columns != ('bot', 'persona', 'job_ref')
                        or result.shape.primary_key_types != ('text', 'text', 'text')):
                    raise C09PagedCaptureHold('actual paid lifecycle schema or key differs')
                names = tuple(name for name in columns if name != 'payload_json')
                row = meter.read_fixed_row(self.graph.pair.source, self.table, names, self.row_where, self.row_key)
                if row is None:
                    raise C09PagedCaptureHold('actual saved paid lifecycle original absent')
                result.small = dict(zip(names, row, strict=True))
                result.disposition = builder.basis._graph_disposition_original_v3(self.graph, result.shape, self.row_key, meter)
            result.phase = 'source_row'
        elif result.phase == 'source_row':
            result._row_advance(False, meter)
        elif result.phase == 'target':
            with legacy_cell_read_transaction_v2(self.graph._read_db):
                shape = read_c09_table_shape_v2(self.graph._read_db, self.table, meter=meter)
                if shape != result.shape:
                    raise C09PagedCaptureHold('actual paid lifecycle target schema differs')
                names = tuple(name for name in shape.columns if name != 'payload_json')
                row = meter.read_fixed_row(self.graph._read_db, self.table, names, self.row_where, self.row_key)
            if result.disposition.disposition == 'derived_removed':
                if row is not None:
                    raise C09PagedCaptureHold('removed paid lifecycle original survives in target')
                result.phase = 'fields'
            else:
                if row is None or dict(zip(names, row, strict=True)) != result.small:
                    raise C09PagedCaptureHold('actual saved paid lifecycle target descriptor differs')
                result.target_small = dict(zip(names, row, strict=True))
                result.phase = 'target_row'
        elif result.phase == 'target_row':
            result._row_advance(True, meter)
        elif result.phase == 'fields':
            if result.projection is None:
                raise C09PagedCaptureHold('actual saved paid lifecycle has no complete payload projection')
            result.complete = True
        else:
            raise C09PagedCaptureHold('actual saved paid lifecycle private phase differs')
        self.graph.require_current()
        self.capture.parser._require_arena()
        return result

    def _row_advance(self,target,meter):
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2
        db=self.graph._read_db if target else self.graph.pair.source;digest=self.target_hash if target else self.source_hash
        small=self.target_small if target else self.small
        if self.column==len(self.shape.columns):
            meter.charge_encode(1);digest.update(b']')
            expected=self.disposition.new_commitment if target else self.disposition.old_commitment
            if digest.hexdigest()!=expected:raise C09PagedCaptureHold('actual complete worker row differs from Source/disposition commitment')
            self.column=0;self.phase='fields' if target else 'target';return
        name=self.shape.columns[self.column];key=self.row_key
        if self.offset==0 and self.total is None:
            meter.charge_encode(1);digest.update(b'[' if self.column==0 else b',')
            if name not in self.json_columns:
                digest.update(self._encoded(small[name],meter));self.column+=1;return
            with legacy_cell_read_transaction_v2(db):
                _,self.total,kind=_read_d13_original_fragment_v3(db,table=self.shape.table,column=name,
                    where=self.row_where,parameters=key,start=0,length=0,meter=meter,builder=self.capture.builder)
            if kind!='text' or self.total<=0:raise C09PagedCaptureHold('actual committed paid worker JSON original absent')
            meter.charge_encode(1);digest.update(b'"')
            if not target:self.json_source_bytes[name]=self.total;self.parser=self._new_source_parser(name)
            return
        amount=min(8192,self.total-self.offset);self.capture.parser._require_arena(amount*16+32768)
        with legacy_cell_read_transaction_v2(db):
            raw,total,kind=_read_d13_original_fragment_v3(db,table=self.shape.table,column=name,
                where=self.row_where,parameters=key,start=self.offset,length=amount,meter=meter,builder=self.capture.builder)
        if kind!='text' or total!=self.total or len(raw)!=amount or any(byte>=128 for byte in raw):
            raise C09PagedCaptureHold('actual worker JSON bytes changed or differ from original ASCII wire')
        meter.require_available(amount*3)
        text=canonical_serialize(raw.decode('ascii'));escaped=text[1:-1].encode('ascii');meter.charge_encode(len(escaped));digest.update(escaped)
        if not target:self._feed_source_json(raw)
        self.offset+=amount
        if self.offset==self.total:
            if not target:
                eof=self.parser.finish()
                if eof.byte_count!=self.total:raise C09PagedCaptureHold('actual worker JSON original canonical EOF differs')
                self._source_json_complete(name,self.parser,eof)
            meter.charge_encode(1);digest.update(b'"');self.total=None;self.offset=0;self.parser=None;self.column+=1


    def fragment(self, start, length, meter):
        return _read_d13_original_fragment_v3(self.graph.pair.source, table=self.table, column='payload_json',
            where=self.row_where, parameters=self.row_key, start=start, length=length,
            meter=meter, builder=self.capture.builder)


class _PaidSubtreeHashV3:
    def __init__(self, row, path):
        if type(row) is not _PaidLifecycleRowV3 or not row.complete:
            raise C09PagedCaptureHold('actual complete paid payload required before subtree read')
        self.row, self.path = row, path
        self.start, self.end = row.projection.ranges[path]
        self.offset, self.hash, self.complete = 0, sha256(), False

    def copy(self):
        result = copy(self)
        result.hash = self.hash.copy()
        return result

    def advance(self, meter):
        result = self.copy()
        amount = min(8192, self.end - self.start - self.offset)
        self.row.capture.parser._require_arena(amount * 8 + 16384)
        raw, total, kind = self.row.fragment(self.start + self.offset, amount, meter)
        if kind != 'text' or total != self.row.json_source_bytes['payload_json'] or len(raw) != amount:
            raise C09PagedCaptureHold('actual saved paid subtree byte range changed')
        result.hash.update(raw)
        result.offset += len(raw)
        result.complete = result.offset == self.end - self.start
        return result


class _PaidGraphNodeV3:
    """Actual inline or Source-cell graph value, with physical hash and ordered EOF."""
    def __init__(self, owner, token, revision=None):
        self.capture, self.graph, self.token, self.revision = owner.capture, owner.graph, token, revision
        self.table = 'graph_atoms' if revision is None else 'graph_history'
        self.where = 'token=?' if revision is None else 'token=? AND revision=?'
        self.key = (token,) if revision is None else (token, revision)
        self.phase, self.shape, self.row, self.disposition, self.scope, self.header = 'metadata', None, None, None, None, None
        self.offset = self.ordinal = 0
        self.hash, self.root, self.buffer = sha256(), None, bytearray()
        self.total, self.value, self.complete = None, None, False
        self.ensure_ascii = False
        self.capture.parser._source_arena.add(self)

    def _source_heap_bytes(self):
        return _heap(self.row) + _heap(self.value) + len(self.buffer) + 8192

    def copy(self):
        self.capture.parser._require_arena(self._source_heap_bytes())
        result = copy(self)
        result.hash, result.buffer = self.hash.copy(), bytearray(self.buffer)
        self.capture.parser._source_arena.add(result)
        return result

    def advance(self, meter):
        _actual_meter(meter)
        result = self.copy()
        builder = self.capture.builder
        builder.require_current()
        self.graph.require_current()
        if result.phase == 'metadata':
            with legacy_cell_read_transaction_v2(self.graph.pair.source):
                result.shape = read_c09_table_shape_v2(self.graph.pair.source, self.table, meter=meter)
                if result.shape.primary_key_columns != (('token',) if self.revision is None else ('token', 'revision')):
                    raise C09PagedCaptureHold('actual saved paid graph reference key differs')
                columns = ('token', 'revision', 'valid') + (('value_cell_id',) if 'value_cell_id' in result.shape.columns else ())
                result.row = meter.read_fixed_row(self.graph.pair.source, self.table, columns, self.where, self.key)
                result.disposition = builder.basis._graph_disposition_original_v3(self.graph, result.shape, self.key, meter)
            if result.row is None or result.row[2] != 1 or self.revision is not None and result.row[1] != self.revision:
                raise C09PagedCaptureHold('actual saved paid graph value is absent or invalid')
            if 'value_cell_id' in result.shape.columns:
                result.scope = builder.session.begin_source_physical_read_v3(self.graph.pair, meter=meter)
                with result.scope.read_database_v3(meter=meter):
                    result.header = result.scope.read_cell_header_v3(result.row[3], meter=meter)
                if result.header[2] != self.token or result.header[1] not in {'canonical-json.ascii.v1','canonical-json.utf8.v1'}:
                    raise C09PagedCaptureHold('actual saved paid Source cell owner or codec differs')
                result.total = result.header[4]
                result.ensure_ascii = result.header[1] == 'canonical-json.ascii.v1'
                result.root = canonical_digest(('sylanne3.segmented-cell-genesis.v1', result.header[0]))
                result.phase = 'segments'
            else:
                raw, result.total, kind = _read_d13_original_fragment_v3(self.graph.pair.source,
                    table=self.table, column='value', where=self.where, parameters=self.key,
                    start=0, length=0, meter=meter, builder=builder)
                if raw or kind != 'text':
                    raise C09PagedCaptureHold('actual saved paid inline value descriptor differs')
                result.phase = 'inline'
            self.capture.parser._require_arena(result.total * 36 + 65536)
        elif result.phase == 'segments':
            with result.scope.read_database_v3(meter=meter):
                if self.ordinal < self.header[5]:
                    row = result.scope.read_cell_segment_v3(self.header[0], self.ordinal, meter=meter)
                    if row[0] != self.offset:
                        raise C09PagedCaptureHold('actual saved paid Source segment offset differs')
                    result.buffer.extend(row[1])
                    result.hash.update(row[1])
                    result.root = canonical_digest(('sylanne3.segmented-cell-link.v1', self.root, self.header[0],
                        self.ordinal, self.offset, len(row[1]), row[2]))
                    result.ordinal += 1
                    result.offset += len(row[1])
                else:
                    result.scope.require_cell_eof_v3(self.header[0], self.ordinal, meter=meter)
                    if (self.offset, self.hash.hexdigest(), self.root) != (self.header[4], self.header[6], self.header[7]):
                        raise C09PagedCaptureHold('actual saved paid Source cell ordered root or full EOF differs')
                    result.phase = 'decode'
        elif result.phase == 'inline':
            amount = min(8192, self.total - self.offset)
            raw, total, kind = _read_d13_original_fragment_v3(self.graph.pair.source, table=self.table,
                column='value', where=self.where, parameters=self.key, start=self.offset, length=amount,
                meter=meter, builder=builder)
            if kind != 'text' or total != self.total or len(raw) != amount:
                raise C09PagedCaptureHold('actual saved paid inline graph bytes changed')
            result.buffer.extend(raw)
            result.hash.update(raw)
            result.offset += len(raw)
            if result.offset == result.total:
                result.phase = 'decode'
        elif result.phase == 'decode':
            self.capture.parser._require_arena(len(self.buffer) * 36 + 65536)
            parser = C09CanonicalJSONStreamV2(ensure_ascii=self.ensure_ascii)
            for offset in range(0, len(self.buffer), 8192):
                parser.feed(self.buffer[offset:offset + 8192], lambda event: None)
            if parser.finish().byte_count != self.total:
                raise C09PagedCaptureHold('actual saved paid graph metadata canonical EOF differs')
            result.value = json.loads(self.buffer)
            result.buffer.clear()
            result.complete = True
        else:
            raise C09PagedCaptureHold('actual saved paid graph metadata phase differs')
        self.graph.require_current()
        self.capture.parser._require_arena()
        return result


class PaidHistoryProofV3:
    def __init__(self, token, reader):
        if token is not _ISSUER or reader.phase != 'qualified' or not reader.complete:
            raise C09PagedCaptureHold('actual complete paid history issuer required')
        self.capture, self.graph, self.metadata = reader.capture, reader.graph, reader.metadata
        self.call_digest, self.request_digest = reader.parent.values['original_digest'], reader.parent.values['request_digest']
        self.request_envelope=reader.parent.request_envelope
        self.source_row_commitment=self.capture.require_complete(self.capture.builder,self.capture.shape,self.capture.key)
        self.model, self.evidence, self.cost, self.terminal = reader.model, reader.evidence, reader.cost, reader.terminal
        self.owner_grant, self.owner_receipt = reader.owner_grant, reader.owner_receipt
        self.owner_interval=reader.owner_interval.proof
        if type(self.owner_interval) is _PaidOwnerUnrevokedThroughCutProofV3:
            self.owner_permission_basis='unrevoked-through-frozen-cut.v3'
        elif type(self.owner_interval) is _PaidOwnerObservedPermissionsProofV3:
            self.owner_permission_basis='actual-schedule-acquire-observations.v3'
        else:
            raise C09PagedCaptureHold('actual paid history lacks a closed private Owner permission basis')
        self.cost_value, self.settlement = reader.cost_node.value, reader.settlement
        self.observation_digest = reader.observation.hash.hexdigest()
        _PROOFS.add(self)

    def require_current(self, parent, meter):
        _actual_meter(meter)
        if (self not in _PROOFS or type(parent) is not _D13PaidIdentityOriginalReadV3
                or parent.kind != 'call' or parent.phase not in {'historical_sources','complete'}
                or parent.capture is not self.capture or parent.graph is not self.graph
                or parent.metadata != self.metadata or parent.values['original_digest'] != self.call_digest
                or parent.values['request_digest'] != self.request_digest
                or parent.request_envelope!=self.request_envelope):
            raise C09PagedCaptureHold('actual paid history proof crossed its adopted immutable original')
        if self.capture.require_complete(self.capture.builder, self.capture.shape, self.capture.key)!=self.source_row_commitment:
            raise C09PagedCaptureHold('paid history proof complete original Source row commitment changed')
        if self.graph is not self.capture.builder.session.require_actual_post_mirror_graph_v3():
            raise C09PagedCaptureHold('actual paid history lost its frozen post-mirror Graph verifier')
        expected_kind={_PaidOwnerUnrevokedThroughCutProofV3:'unrevoked-through-frozen-cut.v3',
            _PaidOwnerObservedPermissionsProofV3:'actual-schedule-acquire-observations.v3'}.get(type(self.owner_interval))
        if expected_kind is None or self.owner_permission_basis!=expected_kind:
            raise C09PagedCaptureHold('actual paid Owner permission basis type changed')
        self.owner_interval.require_current(parent,meter)
        self.graph.require_current()
        self.capture.parser._require_arena()
        return self


class PaidHistoricalPermissionsSettlementReadV3:
    """Read actual permissions, signed budget versions, paid result and cost originals."""
    def __init__(self, parent):
        if (type(parent) is not _D13PaidIdentityOriginalReadV3 or parent.kind != 'call'
                or parent.phase != 'historical_sources' or parent.context_epochs is None
                or not parent.context_epochs.complete or parent.request_envelope is None
                or parent.schedule_fence is None or not parent.schedule_fence.complete
                or parent.write_fence is None or not parent.write_fence.complete):
            raise C09PagedCaptureHold('paid qualification needs actual complete historical context and write-fence provenance')
        self.parent, self.capture, self.graph, self.metadata = parent, parent.capture, parent.graph, parent.metadata
        self.phase, self.model, self.execution, self.binding = 'model', None, None, None
        self.unit_index, self.issuer, self.quote, self.grant, self.lease = 0, None, None, None, None
        self.evidence, self.cost, self.observation = None, None, None
        self.fact, self.terminal = None, None
        self.cost_node, self.settlement = None, None
        self.owner_node, self.owner_grant, self.owner_receipt = None, None, None
        self.owner_epoch = self.owner_ref_index = 0
        self.owner_values, self.owner_temporal = {}, None
        self.owner_interval=None
        self.complete, self.proof = False, None
        self.capture.parser._source_arena.add(self)

    def _source_heap_bytes(self):
        return sum(_heap(value) for value in (self.model, self.execution, self.binding, self.quote, self.grant,
            self.lease, self.fact, self.terminal, self.settlement, self.owner_grant, self.owner_receipt,self.owner_values)) + 16384

    def copy(self):
        self.capture.parser._require_arena(self._source_heap_bytes())
        result = copy(self)
        result.owner_values=dict(self.owner_values)
        self.capture.parser._source_arena.add(result)
        return result

    def _require(self, meter):
        _actual_meter(meter)
        self.capture.require_complete(self.capture.builder, self.capture.shape, self.capture.key)
        if self.graph is not self.capture.builder.session.require_actual_post_mirror_graph_v3():
            raise C09PagedCaptureHold('paid history has another actual post-mirror Graph')
        self.graph.require_current()
        self.capture.parser._require_arena()

    def _budget(self, family, meter):
        from ..runtime.budget import get_budget_lease
        builder, original = self.capture.builder, self.parent.intent.values
        issuer = builder.session.get_c09_domain_original_issuer_v2()
        self.issuer = issuer
        with legacy_cell_read_transaction_v2(self.graph.pair.source):
            db = _BoundedReadConnectionV2(self.graph.pair.source, meter)
            if family == 'quote':
                row = db.execute('SELECT length(CAST(quote_json AS BLOB)) FROM runtime_resource_quotes WHERE quote_id=? AND version=?',
                    (original['quote_id'], original['quote_version'])).fetchone()
                if row is None:
                    raise C09PagedCaptureHold('actual historical paid quote absent')
                self.capture.parser._require_arena(row[0] * 36 + 65536)
                meter.require_available(row[0] + len('resource-quote.v1\n'))
                self.quote = issuer.resource_issuer.original_signed_quote(db, original['quote_id'], original['quote_version'])
                meter.charge_encode(row[0] + len('resource-quote.v1\n'))
                if (_digest(self.quote, self.capture, meter) != original['quote_digest']
                        or self.quote.work_kind != PAID_WORK_KIND
                        or self.quote.operation_id != original['budget_operation_id']
                        or self.quote.parent_budget_lease_ref != self.parent.job.value.parent_budget_lease_ref
                        or self.quote.resource_ref != self.parent.job.value.resource_ref
                        or dict(self.quote.ceiling) != original['ceiling']):
                    raise C09PagedCaptureHold('actual signed paid quote differs from original job/reservation')
            elif family == 'grant':
                lease_id = self.parent.job.value.parent_budget_lease_ref
                row = db.execute('SELECT length(CAST(grant_json AS BLOB)) FROM runtime_budget_grants WHERE lease_id=? AND version=?',
                    (lease_id, original['grant_version'])).fetchone()
                if row is None:
                    raise C09PagedCaptureHold('actual historical paid grant absent')
                self.capture.parser._require_arena(row[0] * 36 + 65536)
                meter.require_available(row[0] + len('budget-grant.v1\n'))
                self.grant, signature = issuer.signed_budget_grant_at_version(db, lease_id, original['grant_version'])
                meter.charge_encode(row[0] + len('budget-grant.v1\n'))
                if (_digest(self.grant, self.capture, meter) != original['grant_digest']
                        or self.grant.grant_id != original['grant_id']
                        or (self.grant.bot_id, self.grant.persona_id) != self.metadata.namespace.as_tuple
                        or PAID_WORK_KIND not in self.grant.allowed_work_kinds):
                    raise C09PagedCaptureHold('actual historical paid signed grant identity differs')
            else:
                sizes = db.execute('SELECT length(CAST(limits_json AS BLOB)),length(CAST(used_json AS BLOB)),'
                    'length(CAST(reserved_json AS BLOB)),length(CAST(unconfirmed_json AS BLOB)) '
                    'FROM runtime_budget_leases WHERE lease_id=?',
                    (self.parent.job.value.parent_budget_lease_ref,)).fetchone()
                if sizes is None:
                    raise C09PagedCaptureHold('actual historical paid lease descriptor absent')
                self.capture.parser._require_arena(sum(sizes)*36+65536)
                self.lease = get_budget_lease(db, self.parent.job.value.parent_budget_lease_ref)
                reservation = db.execute('SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
                    (self.lease.lease_id, original['budget_operation_id'])).fetchone()
                if ((self.lease.bot_id, self.lease.persona_id) != self.metadata.namespace.as_tuple
                        or self.lease.currency != self.grant.currency or reservation is None
                        or reservation[0] != original['budget_reservation_digest']
                        or json.loads(reservation[1]) != original['ceiling']
                        or reservation[2] != self.model.reservation_state
                        or any(unit not in self.grant.max_ceiling or amount > self.grant.max_ceiling[unit] for unit, amount in original['ceiling'].items())
                        or max(self.parent.context_epochs.schedule_time,self.parent.request_envelope.source_qualification.learned_at) >= min(self.quote.valid_until_utc, self.grant.valid_until_utc)):
                    raise C09PagedCaptureHold('actual historical paid lease/reservation/expiry original differs')

    def _evidence_identity(self, meter):
        from .v2_worker_model_result_contract import from_wire as result_from_wire, WorkerModelResultReadRequestV1, d13_paid_read_attempt_id_v1, SCHEMA as worker_read_schema
        from ..runtime.d13_paid_coordinator_v1 import _fact_from_wire
        projection, parent = self.evidence.projection, self.parent
        original, call = parent.intent.values, parent.values
        if projection.objects[()] != {'schema','original_digest','call_original_digest','read','fact'}:
            raise C09PagedCaptureHold('actual saved paid result evidence fields differ')
        if (projection.values[('schema',)] != 'd13.paid_result_read_evidence.v1'
                or projection.values[('original_digest',)] != original['original_digest']
                or projection.values[('call_original_digest',)] != call['original_digest']):
            raise C09PagedCaptureHold('actual saved paid evidence refers to another intent or call')
        if (projection.objects[('read',)] != {'request','observation','terminal_receipt','schema'}
                or projection.values[('read','schema')]!=worker_read_schema
                or projection.objects[('fact',)]!={'intent','recovery','admission','receipt'}):
            raise C09PagedCaptureHold('actual saved worker result fields differ')
        request = result_from_wire(projection.project(('read','request')), WorkerModelResultReadRequestV1)
        binding = original['binding']
        consumer = 'd13-adopt:' + binding['binding_digest']
        if (request.purpose != 'd13_precompress_paid'
                or (request.authority_id, request.authority_namespace, request.namespace, request.installation_id,
                    request.job_id, request.acquire_operation_id, request.original_operation_id, request.call_id,
                    request.binding_digest, request.model_request_digest, request.consumer_operation_id) !=
                    (self.model.authority_id, self.model.namespace, self.metadata.namespace, self.model.installation_id,
                        binding['job_ref'], binding['original_operation_id'], original['budget_operation_id'],
                        binding['call_id'], binding['binding_digest'], call['request_digest'], consumer)
                or request.read_attempt_id != self.evidence.small['read_attempt_id']
                or not any(request.read_attempt_id == d13_paid_read_attempt_id_v1(consumer, attempt) for attempt in range(1,65))):
            raise C09PagedCaptureHold('actual saved paid result read consumer or original identity differs')
        observation_fields = {'authority_id','namespace','subject','operation_id','call_id','request_digest',
            'status','result_json','usage','cost','provider_call_ref'}
        if projection.objects[('read','observation')] not in (observation_fields, observation_fields | {'billing_receipt_json'}):
            raise C09PagedCaptureHold('actual saved paid observation wire fields differ')
        self.capture.parser._require_arena(_heap(projection.values) * 4 + 65536)
        self.fact = _fact_from_wire(projection.project(('fact',)))
        intent, recovery = self.fact.intent, self.fact.recovery
        if (intent.request_digest != call['request_digest'] or intent.binding_digest != binding['binding_digest']
                or intent.operation_id != binding['original_operation_id'] or intent.acquire_operation_id != binding['original_operation_id']
                or intent.worker_fence != call['worker_fence'] or intent.subject != parent.request_envelope.authority.actor
                or (intent.provider_id,intent.model_id,intent.provider_config_digest,intent.max_output_tokens) !=
                    (binding['provider_id'],binding['model_id'],binding['provider_config_digest'],parent.intent.inner_values['installation']['max_output_tokens'])
                or intent.budget_lease_id != self.model.parent_budget_id
                or intent.budget_reservation_operation_id != original['budget_operation_id']
                or intent.budget_reservation_digest != original['budget_reservation_digest']
                or dict(intent.budget_ceiling) != original['ceiling'] or recovery.state != 'observed'):
            raise C09PagedCaptureHold('actual saved paid fact intent/model/worker/accounting scope differs')
        obs = ('read','observation')
        for field, expected in (('authority_id',intent.authority_id),('namespace',intent.namespace),('subject',intent.subject),
                ('operation_id',intent.operation_id),('call_id',intent.call_id),('request_digest',intent.request_digest),('status','completed')):
            if projection.values[obs + (field,)] != expected:
                raise C09PagedCaptureHold('actual saved paid observation differs from original Authority intent')
        if (tuple(tuple(item) for item in projection.project(obs + ('usage',))) != recovery.usage
                or tuple(tuple(item) for item in projection.project(obs + ('cost',))) != recovery.cost):
            raise C09PagedCaptureHold('actual saved paid observation amounts differ from original recovery')
        from .v2_model_egress_contract import ModelTerminalReceiptV2
        self.terminal = ModelTerminalReceiptV2(**projection.project(('read','terminal_receipt')))
        if self.terminal != self.fact.receipt or self.terminal.observation_digest != self.model.observation_digest_or_none:
            raise C09PagedCaptureHold('actual saved paid terminal differs from model obligation')
        self.observation = _PaidSubtreeHashV3(self.evidence, ('read','observation'))

    def _core_fact(self, meter):
        from .v2_model_egress_store import AuthorityV2ModelEgressStore
        from .v2_model_egress_contract import ModelAdmissionV2, ModelTerminalReceiptV2
        builder, model = self.capture.builder, self.model
        with legacy_cell_read_transaction_v2(builder.pair.source):
            db = _BoundedReadConnectionV2(builder.pair.source, meter)
            sizes = db.execute('SELECT length(CAST(e.identity_json AS BLOB)),'
                'length(CAST(o.usage_json AS BLOB)),length(CAST(o.cost_json AS BLOB)),'
                'length(CAST(a.admission_json AS BLOB)),length(CAST(a.receipt_json AS BLOB)) '
                'FROM authority_model_egress_v1 e '
                'JOIN authority_model_egress_observation_status_v1 o ON o.call_id=e.call_id '
                'JOIN authority_model_admissions_v2 a ON a.call_id=e.call_id WHERE e.call_id=?',
                (model.call_id,)).fetchone()
            if sizes is None or any(type(size) is not int for size in sizes):
                raise C09PagedCaptureHold('actual original Core model metadata lacks complete payload lengths')
            self.capture.parser._require_arena(sum(sizes)*36+65536)
            record = AuthorityV2ModelEgressStore._read(db, model.call_id)
            admission = db.execute('SELECT admission_id,admission_json,report_digest,receipt_json FROM authority_model_admissions_v2 WHERE call_id=?',
                (model.call_id,)).fetchone()
        if record is None or admission is None or admission[3] is None:
            raise C09PagedCaptureHold('actual original paid Core intent/admission/terminal unavailable')
        self.capture.parser._require_arena((len(admission[1]) + len(admission[3])) * 36 + 65536)
        admitted, terminal = ModelAdmissionV2(**json.loads(admission[1])), ModelTerminalReceiptV2(**json.loads(admission[3]))
        if (record.intent != self.fact.intent or record.state != 'observed'
                or (record.observation_digest,record.usage,record.cost) !=
                    (self.fact.recovery.observation_digest,self.fact.recovery.usage,self.fact.recovery.cost)
                or admitted != self.fact.admission or terminal != self.terminal
                or admission[:1] != (model.admission_id_or_none,) or admission[2] != terminal.report_digest
                or _digest(terminal,self.capture,meter) != model.terminal_digest_or_none):
            raise C09PagedCaptureHold('actual saved paid fact differs from independent frozen Core originals')

    def _cost_identity(self, meter):
        from ..runtime.budget import BudgetReceipt
        from ..runtime.d11_types import RuntimeCostSettlement, _strict_payload
        value = self.cost.projection.project(())
        if (set(value) != {'schema','evidence_digest','receipt','cost_write'}
                or value['schema'] != 'd13.paid_cost_receipt.v1'
                or value['evidence_digest'] != self.evidence.small['payload_digest']
                or set(value['cost_write']) != {'key','value','dependencies'}):
            raise C09PagedCaptureHold('actual saved paid cost original fields/evidence differ')
        receipt = BudgetReceipt(**value['receipt'])
        if receipt.status != 'settled' or receipt.lease_id != self.model.parent_budget_id:
            raise C09PagedCaptureHold('paid product cannot consume an unknown, pending or overrun original cost')
        settlement = _strict_payload(value['cost_write']['value'], RuntimeCostSettlement)
        from ..runtime.model_cost_settlement import original_model_cost_operation_id_v1, original_model_budget_measurement
        from ..runtime.d11_types import cost_settlement_graph_write
        bundle = original_model_cost_operation_id_v1(self.metadata.namespace,self.model.call_id)
        actual, unknown = original_model_budget_measurement(self.fact,self.quote,work_kind=PAID_WORK_KIND)
        if (unknown or (settlement.bot_id,settlement.persona_id) != self.metadata.namespace.as_tuple
                or settlement.activity_id != self.quote.activity_id or settlement.bundle_operation_id != bundle
                or settlement.settlement_id != bundle or settlement.lease_id != self.model.parent_budget_id
                or settlement.cost_operation_id != self.model.reservation_operation_id
                or settlement.budget_operation_id != self.model.reservation_operation_id
                or settlement.budget_phase != 'settle' or settlement.status != 'settled'
                or dict(settlement.ceiling) != dict(self.quote.ceiling) or dict(settlement.actual) != actual
                or settlement.budget_receipt_digest != receipt.digest
                or receipt.operation_id != self.model.reservation_operation_id
                or not settlement.execution_revoked):
            raise C09PagedCaptureHold('actual saved paid cost settlement identity/conservation differs from original model')
        expected = cost_settlement_graph_write(settlement)
        if value['cost_write'] != {'key':expected.key.token,'value':expected.value,'dependencies':[]}:
            raise C09PagedCaptureHold('actual saved paid cost graph key/dependencies differ from official producer')
        with legacy_cell_read_transaction_v2(self.graph.pair.source):
            db = _BoundedReadConnectionV2(self.graph.pair.source,meter)
            operation = db.execute('SELECT digest,lease_id,receipt_json FROM runtime_budget_operations '
                'WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase=?',
                (*self.metadata.namespace.as_tuple,self.model.reservation_operation_id,'settle')).fetchone()
        if operation is None or operation[:2] != (receipt.digest,receipt.lease_id) or json.loads(operation[2]) != asdict(receipt):
            raise C09PagedCaptureHold('actual saved paid budget receipt differs from its original settle operation')
        self.settlement = receipt
        self.cost_node = _PaidGraphNodeV3(self, value['cost_write']['key'])

    def advance(self, meter):
        self._require(meter)
        result, parent = self.copy(), self.parent
        builder, original = self.capture.builder, parent.intent.values
        facts = builder.transform.facts
        if result.phase == 'model':
            result.model = facts.lookup_model_original(original['binding']['call_id'], meter=meter)
            model = result.model
            if (model is None or (model.authority_id,model.installation_id,model.namespace,model.call_id,model.job_id,
                    model.acquire_operation_id,model.request_digest,model.parent_budget_id,model.reservation_operation_id,
                    model.reservation_digest,model.quote_id,model.quote_version,model.quote_digest) !=
                    (builder.scope.authority_id,builder.scope.installation_id,builder.scope.authority_namespace,
                        original['binding']['call_id'],self.metadata.job_ref,original['binding']['original_operation_id'],
                        parent.values['request_digest'],parent.job.value.parent_budget_lease_ref,original['budget_operation_id'],
                        original['budget_reservation_digest'],original['quote_id'],original['quote_version'],original['quote_digest'])
                    or model.provider_state != 'observed' or model.reservation_state != 'settled'
                    or model.admission_id_or_none is None or model.observation_digest_or_none is None or model.terminal_digest_or_none is None):
                raise C09PagedCaptureHold('actual paid original model accounting identity is incomplete')
            result.phase = 'execution'
        elif result.phase == 'execution':
            result.execution = facts.lookup_execution(result.model.call_id, meter=meter)
            execution, model = result.execution, result.model
            if (execution is None or execution.status != 'completed' or not execution.consumed
                    or (execution.signature_commitment,execution.input_commitment,execution.result_commitment,execution.terminal_commitment) !=
                        (model.original_digest,model.request_digest,model.observation_digest_or_none,model.terminal_digest_or_none)):
                raise C09PagedCaptureHold('actual paid execution differs from complete admitted model original')
            result.phase = 'binding'
        elif result.phase == 'binding':
            from .c09_model_budget_original_v1 import model_unit_fact_v4
            result.binding = facts.lookup_execution_binding(result.model.call_id, meter=meter)
            binding, model = result.binding, result.model
            if (binding is None or binding.execution_kind != 'model' or binding.business_operation_id != model.model_operation_id
                    or binding.input_commitment != model.request_digest or binding.originating_journal_id != model.originating_journal_id
                    or binding.dispatch_generation != model.dispatch_generation or model.original_digest not in binding.source_row_commitments
                    or binding.d11_settlement_ids != tuple(sorted(model_unit_fact_v4(model, unit).settlement_id
                        for unit in model.units if unit.actual_or_none is not None))):
                raise C09PagedCaptureHold('actual paid execution binding and cost inventory differ')
            result.phase = 'units'
        elif result.phase == 'units':
            from .c09_model_budget_original_v1 import model_unit_fact_v4
            if result.unit_index == len(result.model.units):
                result.phase = 'quote'
            else:
                unit = result.model.units[result.unit_index]
                if unit.actual_or_none is None:
                    facts.lookup_unknown(result.model.call_id, meter=meter)
                    raise C09PagedCaptureHold('actual paid product retains original unknown cost obligation')
                expected = model_unit_fact_v4(result.model, unit)
                if facts.lookup_d11(expected.settlement_id, meter=meter) != expected:
                    raise C09PagedCaptureHold('actual paid original unit cost conservation differs')
                result.unit_index += 1
        elif result.phase in ('quote','grant','lease'):
            result._budget(result.phase, meter)
            result.phase = {'quote':'grant','grant':'lease','lease':'evidence'}[result.phase]
        elif result.phase == 'evidence':
            if result.evidence is None:
                result.evidence = _PaidLifecycleRowV3(self,'result')
            elif not self.evidence.complete:
                result.evidence = self.evidence.advance(meter)
            else:
                result._evidence_identity(meter)
                result.phase = 'observation'
        elif result.phase == 'observation':
            if not self.observation.complete:
                result.observation = self.observation.advance(meter)
            else:
                if self.observation.hash.hexdigest() != result.model.observation_digest_or_none:
                    raise C09PagedCaptureHold('actual full saved observation differs from Authority model result commitment')
                result.phase = 'core_fact'
        elif result.phase == 'core_fact':
            result._core_fact(meter)
            result.phase = 'cost'
        elif result.phase == 'cost':
            if result.cost is None:
                result.cost = _PaidLifecycleRowV3(self,'cost')
            elif not self.cost.complete:
                result.cost = self.cost.advance(meter)
            else:
                result._cost_identity(meter)
                result.phase = 'cost_node'
        elif result.phase == 'cost_node':
            if not self.cost_node.complete:
                result.cost_node = self.cost_node.advance(meter)
            else:
                if self.cost_node.value != self.cost.projection.project(('cost_write','value')):
                    raise C09PagedCaptureHold('actual saved cost graph original differs from paid cost receipt')
                result.phase = 'owner'
        elif result.phase == 'owner':
            result._owner_advance(meter)
        elif result.phase == 'owner_interval':
            if result.owner_interval is None:
                result.owner_interval=_PaidOwnerOriginalObservationsReadV3(self)
            elif not self.owner_interval.complete:
                result.owner_interval=self.owner_interval.advance(meter)
            else:
                result.owner_interval.proof.require_current(self.parent,meter)
                result.phase='qualified'
        elif result.phase == 'qualified':
            result.complete = True
            result.proof = PaidHistoryProofV3(_ISSUER,result)
        else:
            raise C09PagedCaptureHold('actual paid historical qualification phase differs')
        result._require(meter)
        return result



    def _owner_advance(self,meter):
        from ..domains.d01 import _activation_key, _validate_persona_activation
        from ..domains.d03 import RoleBinding
        from ..graph_types import owner_grant_key, validate_owner_grant_v1
        from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore
        from .v2_owner_contract import OwnerGraphCommitProofV1, canonical_digest as owner_digest
        from ..contracts import canonical_json
        namespace=self.metadata.namespace
        tokens=(_activation_key(namespace).token,owner_grant_key(*namespace.as_tuple).token,self.parent.intent.job.plan.scene_ref.ref)
        epoch=(self.parent.context_epochs.schedule_epoch,self.parent.call_graph_epoch)[self.owner_epoch]
        instant=(self.parent.context_epochs.schedule_time,self.parent.request_envelope.source_qualification.learned_at)[self.owner_epoch]
        reads=(self.parent.schedule_event.values['reads'] if self.owner_epoch==0 else
            [(item.key.token,item.revision) for item in self.parent.request_envelope.version_guard.read_versions])
        inventory=dict(reads)
        if self.owner_ref_index<len(tokens):
            token=tokens[self.owner_ref_index]
            revision=inventory.get(token)
            if type(revision) is not int or revision<1:
                raise C09PagedCaptureHold('actual paid original window lacks guarded Owner/activation/scene revision')
            reference=VersionedRef(token,revision)
            if self.owner_temporal is None:
                self.owner_temporal=_PaidTemporalReferenceV3(self,reference,epoch)
            elif not self.owner_temporal.complete:
                self.owner_temporal=self.owner_temporal.advance(meter)
            elif self.owner_node is None:
                self.owner_node=_PaidGraphNodeV3(self,token,revision)
            elif not self.owner_node.complete:
                self.owner_node=self.owner_node.advance(meter)
            else:
                self.owner_values[token]=(revision,self.owner_node.value,self.owner_temporal.history)
                self.owner_ref_index+=1
                self.owner_node=self.owner_temporal=None
            return
        activation=self.owner_values[tokens[0]][1]
        grant_revision,grant,grant_history=self.owner_values[tokens[1]]
        scene_revision,scene,scene_history=self.owner_values[tokens[2]]
        _validate_persona_activation(activation)
        validate_owner_grant_v1(grant)
        if (activation['activation_generation']!=self.parent.intent.job.plan.activation_epoch
                or activation['authorization_revision']!=1
                or activation['owner_grant_id']!=grant['grant_id']
                or activation['owner_grant_revision']!=grant_revision
                or activation['graph_incarnation']!=grant['graph_incarnation']):
            raise C09PagedCaptureHold('actual paid historical persona activation/Owner grant differs')
        with legacy_cell_read_transaction_v2(self.graph.pair.source):
            db=_BoundedReadConnectionV2(self.graph.pair.source,meter)
            row=db.execute('SELECT operation_id,request_digest,grant_id,grant_digest,graph_incarnation,graph_access_epoch,'
                'graph_epoch,graph_receipt_digest,proof_json FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?',
                namespace.as_tuple).fetchone()
        if row is None:
            raise C09PagedCaptureHold('actual paid historical Owner issue original absent')
        proof=OwnerGraphCommitProofV1(namespace,row[0],row[1],row[2],row[3],row[4],1,row[5],row[6],row[7])
        with legacy_cell_read_transaction_v2(self.capture.builder.pair.source):
            core=_BoundedReadConnectionV2(self.capture.builder.pair.source,meter)
            sizes=core.execute('SELECT length(c.proof_bytes),length(c.receipt_bytes),length(c.guard_bytes),'
                'length(p.operation_bytes),length(p.receipt_bytes),length(t.ticket_bytes) '
                'FROM authority_owner_issue_committed_v1 c '
                'JOIN authority_owner_issue_pending_v1 p ON p.operation_id=c.operation_id '
                'JOIN authority_owner_claim_tickets_v1 t '
                'ON t.authority_namespace=p.authority_namespace AND t.ticket_id=p.ticket_id '
                'WHERE c.authority_namespace=? AND c.operation_id=?',
                (self.capture.builder.scope.authority_namespace,proof.operation_id)).fetchone()
            if sizes is None or any(type(size) is not int for size in sizes):
                raise C09PagedCaptureHold('actual historical Owner Core origin payload descriptor absent')
            self.capture.parser._require_arena(sum(sizes)*36+65536)
            original=AuthorityV2OwnerTicketStore._checked_committed(core,self.capture.builder.scope.authority_namespace,proof.operation_id)
        if (original is None or original[0]!=proof or row[8]!=canonical_json(asdict(proof))
                or proof.grant_id!=grant['grant_id'] or proof.grant_digest!='sha256:'+_digest(grant,self.capture,meter)
                or original[1].guard.authorization_head!=owner_digest(proof)
                or proof.graph_epoch>epoch or original[1].operation.authority_id!=self.capture.builder.scope.authority_id
                or original[1].operation.installation_id!=self.capture.builder.scope.installation_id):
            raise C09PagedCaptureHold('actual paid Owner Graph/Core issue proof differs from saved grant')
        role=RoleBinding(**{**scene,'norm_refs':tuple(scene['norm_refs']),'source_refs':tuple(scene['source_refs'])})
        if (scene_revision!=role.binding_version or role.status!='active' or role.visibility_scope!='private'
                or role.subject_persona_ref!='persona:'+namespace.persona_id
                or self.parent.intent.window_metadata['owner_ref']!=role.subject_persona_ref
                or not role.effective_from<=instant
                or role.effective_until is not None and instant>=role.effective_until):
            raise C09PagedCaptureHold('actual paid scene/Owner persona permission was not valid at original time')
        if scene_history[5]!='d03-scene-binding':
            raise C09PagedCaptureHold('actual paid scene revision lacks its named creation event')
        with legacy_cell_read_transaction_v2(self.graph.pair.source):
            db=_BoundedReadConnectionV2(self.graph.pair.source,meter)
            receipt=db.execute('SELECT receipt_json FROM graph_scene_binding_receipts_v1 WHERE bot=? AND persona=? AND operation_id=?',
                (*namespace.as_tuple,scene_history[6])).fetchone()
        if receipt is None:
            raise C09PagedCaptureHold('actual paid scene binding receipt absent')
        scene_seal=json.loads(receipt[0])
        if (scene_seal['scene_ref']!=role.scene_ref or scene_seal['binding_id']!=role.role_binding_id
                or scene_seal['role_head_id']!=activation['head_id']):
            raise C09PagedCaptureHold('actual paid scene binding receipt differs from activated Owner role')
        self.owner_grant,self.owner_receipt=grant,original[1]
        if self.owner_epoch==0:
            self.owner_epoch,self.owner_ref_index,self.owner_values=1,0,{}
        else:
            self.phase='owner_interval'


class _PaidTemporalReferenceV3:
    """The exact positive graph revision at one saved epoch, including successor EOF."""
    def __init__(self, owner, reference, epoch):
        self.capture,self.graph,self.reference,self.epoch = owner.capture,owner.graph,reference,epoch
        self.phase,self.history,self.head,self.successor = 'history',None,None,None
        self.complete = False

    def advance(self,meter):
        result=copy(self)
        builder=self.capture.builder
        expected_ns=self.capture.builder.session._control.maintenance.namespace_id.as_tuple
        with legacy_cell_read_transaction_v2(self.graph.pair.source):
            source=self.graph.pair.source
            if result.phase=='history':
                shape=read_c09_table_shape_v2(source,'graph_history',meter=meter)
                result.history=meter.read_fixed_row(source,'graph_history',
                    ('token','revision','valid','event_bot','event_persona','event_session','event_id'),
                    'token=? AND revision=?',(self.reference.ref,self.reference.version))
                if (result.history is None or result.history[:3] != (self.reference.ref,self.reference.version,1)
                        or result.history[3:5] != expected_ns):
                    raise C09PagedCaptureHold('actual paid historical graph reference identity/validity differs')
                builder.basis._graph_disposition_original_v3(self.graph,shape,(self.reference.ref,self.reference.version),meter)
                result.phase='birth'
            elif result.phase=='birth':
                row=meter.read_fixed_row(source,'graph_events',('epoch_revision',),
                    'bot=? AND persona=? AND session=? AND event_id=?',self.history[3:])
                if row is None or not 0<=row[0]<=self.epoch:
                    raise C09PagedCaptureHold('actual paid graph value was not current by original epoch')
                shape=read_c09_table_shape_v2(source,'graph_events',meter=meter)
                builder.basis._graph_disposition_original_v3(self.graph,shape,self.history[3:],meter)
                result.phase='successor'
            elif result.phase=='successor':
                result.head=meter.read_fixed_row(source,'graph_atoms',('revision',),'token=?',(self.reference.ref,))
                result.successor=meter.read_fixed_row(source,'graph_history',
                    ('revision','event_bot','event_persona','event_session','event_id'),
                    'token=? AND revision>? ORDER BY revision',(self.reference.ref,self.reference.version))
                if result.head is None or result.head[0]<self.reference.version:
                    raise C09PagedCaptureHold('actual paid graph history has no coherent frozen head')
                if result.successor is None:
                    if result.head[0]!=self.reference.version:
                        raise C09PagedCaptureHold('actual paid graph history omits its successor')
                    result.complete=True
                else:
                    if result.successor[0]!=self.reference.version+1 or result.successor[1:3]!=expected_ns:
                        raise C09PagedCaptureHold('actual paid graph history successor has an identity/revision gap')
                    shape=read_c09_table_shape_v2(source,'graph_history',meter=meter)
                    builder.basis._graph_disposition_original_v3(self.graph,shape,(self.reference.ref,result.successor[0]),meter)
                    result.phase='following'
            elif result.phase=='following':
                row=meter.read_fixed_row(source,'graph_events',('epoch_revision',),
                    'bot=? AND persona=? AND session=? AND event_id=?',self.successor[1:])
                if row is None or row[0]<=self.epoch:
                    raise C09PagedCaptureHold('actual paid graph reference was superseded at original epoch')
                shape=read_c09_table_shape_v2(source,'graph_events',meter=meter)
                builder.basis._graph_disposition_original_v3(self.graph,shape,self.successor[1:],meter)
                result.complete=True
            else:
                raise C09PagedCaptureHold('actual paid graph temporal private phase differs')
        self.graph.require_current()
        return result


class _PaidResultBodyV3:
    """Decode the bounded official result text without materializing the saved DTO."""
    def __init__(self, owner, proof):
        from .c09_authority_storage_rebase_v2 import _D13PaidEncodedStringStreamV3
        self.capture,self.proof=owner.capture,proof
        if type(proof) is PaidBlockCompletionProofV3:
            self.row=_PaidCompactResultLocatorV3(proof)
            self.start,self.end=proof.result_range
        else:
            self.row=proof.evidence
            self.start,self.end=self.row.projection.ranges[_RESULT_JSON]
        self.offset,self.decoder,self.parser=0,_D13PaidEncodedStringStreamV3(ensure_ascii=True),_PaidProjectionV3()
        self.complete,self.text=False,None
        self.capture.parser._source_arena.add(self)

    def _source_heap_bytes(self):
        return _heap(self.parser.__dict__)+_heap(self.text)+len(self.decoder.pending)+8192

    def copy(self):
        self.capture.parser._require_arena(self._source_heap_bytes())
        result=copy(self)
        result.decoder=self.decoder.copy()
        result.parser=self.parser.copy()
        self.capture.parser._source_arena.add(result)
        return result

    def advance(self,meter):
        result=self.copy()
        amount=min(4096,self.end-self.start-self.offset)
        self.capture.parser._require_arena(amount*24+65536)
        raw,total,kind=self.row.fragment(self.start+self.offset,amount,meter)
        if kind!='text' or total!=self.row.json_source_bytes['payload_json'] or len(raw)!=amount:
            raise C09PagedCaptureHold('actual saved paid result string range changed')
        result.decoder.pending.clear()
        result.decoder.feed(raw,lambda event:None)
        decoded=bytes(result.decoder.pending)
        meter.charge_encode(len(decoded))
        result.parser.feed(decoded)
        result.offset+=amount
        if result.offset==self.end-self.start:
            if result.decoder.finish().byte_count!=self.end-self.start:
                raise C09PagedCaptureHold('actual saved paid result encoded EOF differs')
            result.parser.finish()
            if result.parser.objects[()]!={'text'} or result.parser.arrays:
                raise C09PagedCaptureHold('actual paid provider result is not the official text-only product shape')
            text=result.parser.values[('text',)]
            if type(text) is not str:
                raise C09PagedCaptureHold('actual paid provider result text type differs')
            self.capture.parser._require_arena(len(text)*40+65536)
            encoded=text.encode('utf8')
            meter.charge_encode(len(encoded))
            if not 0<len(encoded)<=65536:
                raise C09PagedCaptureHold('actual paid model output exceeds its official product ceiling')
            result.text=text
            result.complete=True
        self.capture.parser._require_arena()
        return result


class _PaidExcerptStreamV3(C09CanonicalJSONStreamV2):
    """Search model excerpts against each complete original planned turn as a stream."""
    def __init__(self, patterns, *, ensure_ascii=True, max_depth=64, max_key_bytes=1024):
        super().__init__(ensure_ascii=ensure_ascii,max_depth=max_depth,max_key_bytes=max_key_bytes)
        self.patterns=patterns
        self.found={index:[False]*len(values) for index,values in patterns.items()}
        self.path,self.high,self.pending,self.tail=None,None,[], ''
        self.text_hash=sha256()
        self.text_bytes=0
        self.texts={}

    def copy(self):
        result=_copy_c09_canonical_state_v3(self)
        result.found={index:list(values) for index,values in self.found.items()}
        result.pending=list(self.pending)
        result.text_hash=self.text_hash.copy()
        result.texts=dict(self.texts)
        return result

    def _flush(self):
        if not self.pending:
            return
        chunk=''.join(self.pending)
        encoded=chunk.encode('utf8')
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        current_c09_sql_meter_v2().charge_encode(len(encoded))
        self.text_hash.update(encoded)
        self.text_bytes+=len(encoded)
        text=self.tail+chunk
        index=self.path[1]
        patterns=self.patterns[index]
        for ordinal,needle in enumerate(patterns):
            if needle in text:
                self.found[index][ordinal]=True
        width=max(len(value) for value in patterns)-1
        self.tail=text[-width:] if width else ''
        self.pending.clear()

    def _append_decoded_codepoint(self,codepoint):
        state=self._string
        if state is not None and state['mode']=='value' and state['path']==self.path:
            if 0xd800<=codepoint<=0xdbff:
                self.high=codepoint
            else:
                if self.high is not None:
                    if not 0xdc00<=codepoint<=0xdfff:
                        raise C09PagedCaptureHold('actual frozen paid source text has an invalid surrogate')
                    codepoint=0x10000+((self.high-0xd800)<<10)+codepoint-0xdc00
                    self.high=None
                elif 0xdc00<=codepoint<=0xdfff:
                    raise C09PagedCaptureHold('actual frozen paid source text has an invalid surrogate')
                self.pending.append(chr(codepoint))
                if len(self.pending)==256:
                    self._flush()
        return super()._append_decoded_codepoint(codepoint)

    def _emit(self,emit,kind,path,start,end,**values):
        if len(path)==3 and path[0]=='turns' and path[2]=='text' and path[1] in self.patterns:
            if kind=='scalar_start':
                if values.get('scalar_kind')!='string':
                    raise C09PagedCaptureHold('actual frozen planned turn text is not a string')
                self.path,self.high,self.pending,self.tail=path,None,[], ''
                self.text_hash,self.text_bytes=sha256(),0
            elif kind=='scalar_end':
                self._flush()
                if self.high is not None or not all(self.found[path[1]]):
                    raise C09PagedCaptureHold('actual paid model output contains an excerpt outside its original turn')
                self.texts[path[1]]=(self.text_hash.hexdigest(),self.text_bytes)
                self.path=None
        return super()._emit(emit,kind,path,start,end,**values)


class _PaidExcerptReadV3:
    def __init__(self, owner, model):
        from .c09_authority_storage_rebase_v2 import _D13PaidEncodedStringStreamV3
        self.capture,self.graph,self.intent=owner.capture,owner.graph,owner.parent.paid_intent
        self.start,self.end=self.intent.parser.ranges[('frozen_json',)]
        self.offset,self.decoder=0,_D13PaidEncodedStringStreamV3(ensure_ascii=True)
        self.patterns={index:tuple([turn['beat'],*turn['details']]) for index,turn in enumerate(model['turns'])}
        self.parser=_PaidExcerptStreamV3(self.patterns)
        self.complete=False
        self.capture.parser._source_arena.add(self)

    def _source_heap_bytes(self):
        return _heap(self.patterns)+_heap(self.parser.found)+_heap(self.parser.texts)+_heap(self.parser.pending)+_heap(self.parser.tail)+len(self.decoder.pending)+8192

    def copy(self):
        self.capture.parser._require_arena(self._source_heap_bytes())
        result=copy(self)
        result.decoder,result.parser=self.decoder.copy(),self.parser.copy()
        self.capture.parser._source_arena.add(result)
        return result

    def advance(self,meter):
        result=self.copy()
        amount=min(4096,self.end-self.start-self.offset)
        raw,total,kind=_read_d13_original_fragment_v3(self.graph.pair.source,
            table='graph_d13_paid_intent_originals_v1',column='original_json',
            where='bot=? AND persona=? AND job_ref=?',parameters=(*self.intent.metadata.namespace.as_tuple,self.intent.metadata.job_ref),
            start=self.start+self.offset,length=amount,meter=meter,builder=self.capture.builder)
        if kind!='text' or total!=self.intent.total or len(raw)!=amount:
            raise C09PagedCaptureHold('actual frozen paid intent excerpt source range changed')
        result.decoder.pending.clear()
        result.decoder.feed(raw,lambda event:None)
        decoded=bytes(result.decoder.pending)
        meter.charge_encode(len(decoded))
        result.parser.feed(decoded,lambda event:None)
        result.offset+=amount
        if result.offset==self.end-self.start:
            outer=result.decoder.finish()
            inner=result.parser.finish()
            if (outer.byte_count!=self.end-self.start or inner.byte_count!=self.intent.inner_bytes
                    or inner.sha256!=self.intent.inner_digest or set(result.parser.texts)!=set(result.patterns)):
                raise C09PagedCaptureHold('actual paid excerpt search did not reach its complete frozen source EOF')
            result.complete=True
        self.graph.require_current()
        self.capture.parser._require_arena()
        return result


class PaidBlockCompletionProofV3:
    def __init__(self,token,reader):
        if token is not _ISSUER or not reader.complete or reader.phase!='qualified':
            raise C09PagedCaptureHold('actual complete saved paid block issuer required')
        self.capture,self.graph,self.metadata,self.binding=reader.capture,reader.graph,reader.metadata,reader.parent.binding
        self.source_row_commitment=reader.capture.require_complete(reader.capture.builder,reader.capture.shape,reader.capture.key)
        self.anchors=tuple(reader.parent.payload.anchors)
        self.result_range=reader.history.evidence.projection.ranges[_RESULT_JSON]
        self.result_total=reader.history.evidence.json_source_bytes['payload_json']
        self.result_digest=reader.history.evidence.small['payload_digest']
        self.stable_bytes=reader.stable_bytes
        self.payload_digest=reader.metadata.payload_digest
        self.observation_digest=reader.history.observation_digest
        _PROOFS.add(self)
        self.capture.parser._source_arena.add(self)

    def require_current(self,parent,meter):
        _actual_meter(meter)
        if (self not in _PROOFS or type(parent) is not _D13BoundBlockMetadataReadV3
                or parent.capture is not self.capture or parent.graph is not self.graph
                or parent.metadata!=self.metadata or parent.binding!=self.binding or parent.phase not in {'payload','paid_originals'}
                or parent.payload.phase!='paid_originals'):
            raise C09PagedCaptureHold('actual paid block proof has another adopted block binding/source')
        self.require_source(self.capture,meter)
        self.graph.require_current()
        self.capture.parser._require_arena()
        return self

    def _source_heap_bytes(self):
        return _heap(self.metadata)+_heap(self.binding)+_heap(self.anchors)+2048

    def require_source(self,capture,meter):
        _actual_meter(meter)
        if self not in _PROOFS or capture is not self.capture:
            raise C09PagedCaptureHold('actual issued paid block compilation proof required')
        if capture.require_complete(capture.builder,capture.shape,capture.key)!=self.source_row_commitment:
            raise C09PagedCaptureHold('actual paid block complete Source row commitment changed')
        if self.graph is not capture.builder.session.require_actual_post_mirror_graph_v3():
            raise C09PagedCaptureHold('paid block compilation lost actual frozen Graph')
        self.graph.require_current()
        return self


class PaidBlockCompletionOriginalReadV3:
    """Original result -> exact source excerpts -> payload slots and omissions."""
    def __init__(self,parent):
        if (type(parent) is not _D13BoundBlockMetadataReadV3 or parent.phase!='payload'
                or parent.payload is None or parent.payload.phase!='paid_originals'
                or parent.paid_call is None or not parent.paid_call.complete):
            raise C09PagedCaptureHold('paid block completion needs actual completed paid call/source identity')
        reader=parent.paid_call.historical_permissions_settlement
        if (type(reader) is not PaidHistoricalPermissionsSettlementReadV3 or not reader.complete
                or type(reader.proof) is not PaidHistoryProofV3):
            raise C09PagedCaptureHold('paid block completion requires actual full paid history proof')
        self.parent,self.capture,self.graph,self.metadata=parent,parent.capture,parent.graph,parent.metadata
        self.history=reader.proof
        self.phase,self.body,self.model,self.excerpts='result',None,None,None
        self.omissions,self.omission_index,self.omission_buffer,self.omission_offset=[],0,bytearray(),0
        self.turn_index,self.complete,self.proof=0,False,None
        self.stable_bytes=0
        self.capture.parser._source_arena.add(self)

    def _source_heap_bytes(self):
        return _heap(self.model)+_heap(self.omissions)+len(self.omission_buffer)+8192

    def copy(self):
        self.capture.parser._require_arena(self._source_heap_bytes())
        result=copy(self)
        result.omissions,result.omission_buffer=list(self.omissions),bytearray(self.omission_buffer)
        self.capture.parser._source_arena.add(result)
        return result

    def _parse_model(self,meter):
        from ..domains.d13.precompression import EXTRACTIVE_OUTPUT_SCHEMA
        def unique(pairs):
            value={}
            for name,item in pairs:
                if name in value:
                    raise C09PagedCaptureHold('actual paid model output repeats a field')
                value[name]=item
            return value
        text=self.body.text
        self.capture.parser._require_arena(len(text)*40+65536)
        model=json.loads(text,object_pairs_hook=unique)
        anchors=self.parent.paid_intent.selected_anchors
        if (type(model) is not dict or set(model)!={'schema','turns'} or model['schema']!=EXTRACTIVE_OUTPUT_SCHEMA
                or type(model['turns']) is not list or len(model['turns'])!=len(anchors)
                or tuple(anchors)!=self.parent.payload.anchors):
            raise C09PagedCaptureHold('actual paid model output has another original selected-turn coverage')
        for anchor,item in zip(anchors,model['turns']):
            if (type(item) is not dict or set(item)!={'sequence','beat','details'}
                    or type(item['sequence']) is not int or item['sequence']!=anchor.sequence
                    or type(item['beat']) is not str or not item['beat']
                    or type(item['details']) is not list or len(item['details'])>4
                    or any(type(value) is not str or not value for value in item['details'])
                    or len(set(item['details']))!=len(item['details'])):
                raise C09PagedCaptureHold('actual paid model turn/detail shape or order differs')
        self.model=model
        self.excerpts=_PaidExcerptReadV3(self,model)

    def _turn_parity(self,meter):
        index=self.turn_index
        item=self.model['turns'][index]
        payload=self.parent.payload
        anchor=payload.anchors[index]
        summary=payload.parser.texts[('timeline',index,'text')]
        line=f'[{anchor.sequence} {anchor.speaker_ref}] '+item['beat']
        line_bytes=line.encode('utf8');meter.charge_encode(len(line_bytes))
        self.stable_bytes+=len(line_bytes)+(1 if index else 0)
        raw=item['beat'].encode('utf8')
        meter.charge_encode(len(raw))
        if (summary['utf8'].hexdigest()!=sha256(raw).hexdigest() or summary['utf8_bytes']!=len(raw)
                or payload.timeline[index]!=(anchor.sequence,anchor.source_ref,anchor.speaker_ref)):
            raise C09PagedCaptureHold('actual paid payload beat differs from original model output')
        actual=[row for row in payload.details if row[0]==anchor.sequence]
        if len(actual)!=len(item['details']):
            raise C09PagedCaptureHold('actual paid payload detail count differs from original model output')
        for ordinal,(detail,row) in enumerate(zip(item['details'],actual)):
            encoded=detail.encode('utf8')
            meter.charge_encode(len(encoded))
            if (row[:6]!=(anchor.sequence,(anchor.source_ref.ref,anchor.source_ref.version),anchor.speaker_ref,
                    sha256(encoded).hexdigest(),len(encoded),f'turn:{anchor.sequence}:detail:{ordinal}')):
                raise C09PagedCaptureHold('actual paid payload detail source/order/text differs from original model output')
        self.turn_index+=1

    def _omission_advance(self,meter):
        payload=self.parent.payload
        count=payload.parser.counts.get('omitted_ranges',0)
        if self.omission_index==count:
            from ..domains.d13.precompression import _omission_ranges
            omitted=[]
            for index,item in enumerate(self.model['turns']):
                digest,length=self.excerpts.parser.texts[index]
                represented=False
                for text in [item['beat'],*item['details']]:
                    raw=text.encode('utf8')
                    meter.charge_encode(len(raw))
                    if (sha256(raw).hexdigest(),len(raw))==(digest,length):
                        represented=True
                if not represented:
                    omitted.append(item['sequence'])
            if tuple(self.omissions)!=_omission_ranges(omitted):
                raise C09PagedCaptureHold('actual paid payload omission ranges differ from complete original source/model coverage')
            self.phase='qualified'
            return
        start,end=payload.parser.ranges[('omitted_ranges',self.omission_index)]
        if self.omission_offset==end-start:
            value=json.loads(self.omission_buffer)
            if type(value) is not list or len(value)!=2:
                raise C09PagedCaptureHold('actual paid payload omission range shape differs')
            self.omissions.append(tuple(value))
            self.omission_buffer.clear()
            self.omission_offset=0
            self.omission_index+=1
            return
        amount=min(8192,end-start-self.omission_offset)
        raw,total,kind=_read_d13_original_fragment_v3(self.graph.pair.source,
            table='graph_d11_derived_cache_payloads_v1',column='payload_bytes',
            where='bot=? AND persona=? AND block_ref=?',parameters=(*self.metadata.namespace.as_tuple,self.metadata.block_ref),
            start=start+self.omission_offset,length=amount,meter=meter,builder=self.capture.builder)
        if kind!='blob' or total!=payload.total or len(raw)!=amount:
            raise C09PagedCaptureHold('actual paid payload omission byte range changed')
        self.omission_buffer.extend(raw)
        self.omission_offset+=amount

    def advance(self,meter):
        _actual_meter(meter)
        self.history.require_current(self.parent.paid_call,meter)
        result=self.copy()
        if result.phase=='result':
            if result.body is None:
                result.body=_PaidResultBodyV3(self,self.history)
            elif not self.body.complete:
                result.body=self.body.advance(meter)
            else:
                result._parse_model(meter)
                result.phase='excerpts'
        elif result.phase=='excerpts':
            if not self.excerpts.complete:
                result.excerpts=self.excerpts.advance(meter)
            else:
                result.phase='turns'
        elif result.phase=='turns':
            if result.turn_index==len(result.model['turns']):
                result.phase='omissions'
            else:
                result._turn_parity(meter)
        elif result.phase=='omissions':
            result._omission_advance(meter)
        elif result.phase=='qualified':
            result.complete=True
            result.proof=PaidBlockCompletionProofV3(_ISSUER,result)
        else:
            raise C09PagedCaptureHold('actual paid block completion private phase differs')
        self.graph.require_current()
        self.capture.parser._require_arena()
        return result


class _PaidTextMeasureStreamV3(C09CanonicalJSONStreamV2):
    """Full canonical scalar EOF; UTF8 measure and a bounded Unicode query prefix."""
    def __init__(self, prefix_limit=0, *, ensure_ascii=True,max_depth=64,max_key_bytes=1024):
        super().__init__(ensure_ascii=ensure_ascii,max_depth=max_depth,max_key_bytes=max_key_bytes)
        self.prefix_limit,self.prefix,self.high,self.pending=prefix_limit,[],None,[]
        self.utf8_bytes,self.text_hash=0,sha256()

    def copy(self):
        result=_copy_c09_canonical_state_v3(self)
        result.prefix,result.pending=list(self.prefix),list(self.pending)
        result.text_hash=self.text_hash.copy()
        return result

    def _flush(self):
        if self.pending:
            from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
            raw=''.join(self.pending).encode('utf8')
            current_c09_sql_meter_v2().charge_encode(len(raw))
            self.utf8_bytes+=len(raw);self.text_hash.update(raw);self.pending.clear()

    def _append_decoded_codepoint(self,codepoint):
        state=self._string
        if state is not None and state['mode']=='value':
            if state['path']!=():
                raise C09PagedCaptureHold('paid historical text measure requires one original scalar')
            if 0xd800<=codepoint<=0xdbff:
                self.high=codepoint
            else:
                if self.high is not None:
                    if not 0xdc00<=codepoint<=0xdfff:
                        raise C09PagedCaptureHold('paid original text surrogate differs')
                    codepoint=0x10000+((self.high-0xd800)<<10)+codepoint-0xdc00;self.high=None
                elif 0xdc00<=codepoint<=0xdfff:
                    raise C09PagedCaptureHold('paid original text surrogate differs')
                char=chr(codepoint)
                if len(self.prefix)<self.prefix_limit:self.prefix.append(char)
                self.pending.append(char)
                if len(self.pending)==256:self._flush()
        return super()._append_decoded_codepoint(codepoint)

    def finish(self):
        result=super().finish();self._flush()
        if self.high is not None:
            raise C09PagedCaptureHold('paid original text measure incomplete Unicode EOF')
        return result


class _PaidFrozenTextMeasureV3:
    def __init__(self,source,path,prefix_limit=0):
        self.source,self.path=source,path
        self.start,self.end=source.evidence.projection_ranges[path]
        self.offset,self.complete=0,False
        self.parser=_PaidTextMeasureStreamV3(prefix_limit)
        source.arena.add(self);source.require_arena()

    def _source_heap_bytes(self):
        return _heap(self.parser.prefix)+_heap(self.parser.pending)+4096

    def copy(self):
        self.source.require_arena(self._source_heap_bytes())
        result=copy(self);result.parser=self.parser.copy();self.source.arena.add(result);return result

    def advance(self,meter):
        _actual_meter(meter);self.source.require_current()
        result=self.copy();amount=min(8192,self.end-self.start-self.offset)
        raw=self.source._read_fragment(self.start+self.offset,amount,meter)
        result.parser.feed(raw,lambda event:None);result.offset+=len(raw)
        if result.offset==self.end-self.start:
            if result.parser.finish().byte_count!=self.end-self.start:
                raise C09PagedCaptureHold('paid frozen text measure did not consume its actual scalar EOF')
            result.complete=True
        self.source.require_current();self.source.require_arena();return result


class _PaidCompactResultLocatorV3:
    def __init__(self,proof):
        self.capture,self.graph,self.metadata=proof.capture,proof.graph,proof.metadata
        self.json_source_bytes={'payload_json':proof.result_total}

    def fragment(self,start,length,meter):
        return _read_d13_original_fragment_v3(self.graph.pair.source,
            table='graph_d13_paid_result_reads_v1',column='payload_json',
            where='bot=? AND persona=? AND job_ref=?',
            parameters=(*self.metadata.namespace.as_tuple,self.metadata.job_ref),
            start=start,length=length,meter=meter,builder=self.capture.builder)


class PaidCounterDetailSelectionProofV3:
    def __init__(self,token,reader):
        if token is not _ISSUER or not reader.complete or reader.phase!='qualified':
            raise C09PagedCaptureHold('complete actual global paid detail selection issuer required')
        self.capture,self.graph=reader.capture,reader.graph
        self.payload_digest=reader.capture.payload_digest
        self.source_row_commitment=reader.capture.require_complete(reader.capture.builder,reader.capture.shape,reader.capture.key)
        self.block_commitments=tuple((proof.metadata.block_ref,proof.payload_digest,proof.observation_digest)
            for proof in reader.blocks)
        self.selected=tuple(reader.selected)
        _PROOFS.add(self)
        self.capture.parser._source_arena.add(self)

    def require_current(self,capture,meter):
        _actual_meter(meter)
        if self not in _PROOFS or capture is not self.capture:
            raise C09PagedCaptureHold('issued actual global paid selection proof required')
        if capture.require_complete(capture.builder,capture.shape,capture.key)!=self.source_row_commitment or capture.payload_digest!=self.payload_digest:
            raise C09PagedCaptureHold('actual paid selection Source row commitment changed')
        self.graph.require_current()
        if self.graph is not capture.builder.session.require_actual_post_mirror_graph_v3():
            raise C09PagedCaptureHold('global paid selection lost actual same Graph Source')
        return self

    def _source_heap_bytes(self):
        return _heap(self.payload_digest)+_heap(self.source_row_commitment)+_heap(self.block_commitments)+_heap(self.selected)+4096


class PaidCounterDetailSelectionReadV3:
    """Replay the installed counter Source's one shared historical detail budget."""
    def __init__(self,capture,blocks):
        from .c09_authority_storage_rebase_v2 import _D13CoreRowCaptureV3,_D13FrozenSourceV3
        from ..runtime.installed_d13_natural_frame_v7 import POLICY_REF
        if type(capture) is not _D13CoreRowCaptureV3 or type(blocks) is not tuple:
            raise C09PagedCaptureHold('global detail selection requires actual draft capture and issued block inventory')
        capture.require_complete(capture.builder,capture.shape,capture.key)
        bindings=capture.parser.metadata['block_bindings']
        selection=capture.parser.history_selections['compressed']
        if (len(blocks)!=len(bindings) or len(blocks)>4 or selection.policy_ref!=POLICY_REF
                or any(type(proof) is not PaidBlockCompletionProofV3 or proof not in _PROOFS
                    or proof.capture is not capture or asdict(proof.binding)!=binding for proof,binding in zip(blocks,bindings))):
            raise C09PagedCaptureHold('global detail selection differs from actual qualified block/policy inventory')
        self.capture,self.blocks=capture,blocks
        self.graph=capture.builder.session.require_actual_post_mirror_graph_v3()
        self.source=_D13FrozenSourceV3.from_draft(capture,'compressed')
        self.phase,self.complete,self.proof='raw',False,None
        # This exact installed Source call is d13_core_counter_source_v1:
        # prepare_current_natural_history_pair_v7 uses the official 262144-byte contract.
        self.used=sum(proof.stable_bytes for proof in blocks)
        if self.used>262144:
            raise C09PagedCaptureHold('actual selected paid stable history exceeds installed total history budget')
        self.raw_paths=tuple(sorted(path for path in self.source.evidence.projection_ranges
            if path[:2]==('input','recent_history') and len(path)==5 and path[-2:]==('turn','text')))
        self.raw_index,self.text_reader,self.query=0,None,None
        self.raw_sources={ref for path,ref in capture.parser.references.items()
            if path[:3]==('compressed','input','recent_history') and path[-2:]==('turn','source_ref')}
        self.evidence={ref for path,ref in capture.parser.references.items()
            if path[:4]==('compressed','input','plan','units') and len(path)>=6 and path[-2]=='source_refs'}
        self.block_index,self.body,self.model,self.slot_index=0,None,None,0
        self.ranked,self.chosen,self.selected=[],[],[]
        self.rank_index,self.rank_used,self.emit_index=0,0,0
        capture.parser._source_arena.add(self)

    def _source_heap_bytes(self):
        return _heap(self.raw_paths)+_heap(self.raw_sources)+_heap(self.evidence)+_heap(self.query)+_heap(self.model)+_heap(self.ranked)+_heap(self.chosen)+_heap(self.selected)+8192

    def copy(self):
        self.capture.parser._require_arena(self._source_heap_bytes())
        result=copy(self)
        result.ranked,result.chosen,result.selected=list(self.ranked),list(self.chosen),list(self.selected)
        self.capture.parser._source_arena.add(result);return result

    def _load_model(self,meter):
        proof=self.blocks[self.block_index]
        proof.require_source(self.capture,meter)
        model=json.loads(self.body.text)
        # The private issued compilation already checked exact shape and original
        # result/source/payload parity. Re-read these same immutable original bytes.
        if (model['schema']!='d13.extractive_model_output.v1'
                or tuple(turn['sequence'] for turn in model['turns'])!=tuple(anchor.sequence for anchor in proof.anchors)):
            raise C09PagedCaptureHold('issued paid result locator no longer matches original compiled block')
        self.model=model;self.slot_index=0;self.ranked=[];self.phase='rank'

    def _rank_slot(self,meter):
        from ..domains.d13.precompression import _lexical_terms,_QUALIFIER
        proof=self.blocks[self.block_index]
        slots=[(index,ordinal,text) for index,turn in enumerate(self.model['turns'])
            for ordinal,text in enumerate(turn['details'])]
        if self.slot_index==len(slots):
            self.ranked.sort(key=lambda row:row[:3])
            self.rank_index,self.rank_used,self.chosen=0,0,[];self.phase='choose';return
        index,ordinal,text=slots[self.slot_index];anchor=proof.anchors[index]
        source=(anchor.source_ref.ref,anchor.source_ref.version)
        key=f'turn:{anchor.sequence}:detail:{ordinal}'
        if source not in self.evidence:
            score=min(len(_lexical_terms(self.query)&_lexical_terms(text)),5)*10
            if score:
                score+=2 if _QUALIFIER.search(text) else 0
                rendered=f'[detail {anchor.sequence} {anchor.trusted_utc} {anchor.speaker_ref} '+f'{source[0]}@{source[1]}] {text}'
                raw=rendered.encode('utf8');meter.charge_encode(len(raw))
                detail=text.encode('utf8');meter.charge_encode(len(detail))
                self.ranked.append((-score,anchor.sequence,key,index,ordinal,len(raw),
                    len(detail),sha256(detail).hexdigest(),source,anchor.speaker_ref,text))
        self.slot_index+=1

    def _choose(self):
        if self.rank_index==len(self.ranked):
            self.chosen.sort(key=lambda row:(row[1],row[2]));self.emit_index=0;self.phase='emit';return
        row=self.ranked[self.rank_index]
        cost=row[5]+(1 if self.chosen else 0)
        if self.rank_used+cost<=max(0,262144-self.used):
            self.chosen.append(row);self.rank_used+=cost
        self.rank_index+=1

    def _emit_detail(self):
        if self.emit_index==len(self.chosen):
            self.block_index+=1;self.body=self.model=None;self.ranked=self.chosen=[]
            self.phase='blocks';return
        row=self.chosen[self.emit_index]
        if row[8] not in self.raw_sources and self.used+row[6]<=262144:
            self.selected.append((row[1],row[8],row[9],row[7],row[6],row[10]))
            self.used+=row[6]
        self.emit_index+=1

    def _parity(self):
        expected=tuple(sorted(self.selected,key=lambda row:(row[0],row[1][0],row[5])))
        actual=tuple((part[0],part[1],
            self.capture.parser.frozen_inputs['compressed'].projection_metadata[path[1:]+('speaker_ref',)],
            part[3],part[4]) for path,part in sorted(self.capture.parser.semantic_parts.items())
            if path[:3]==('compressed','input','detail_history'))
        if tuple(row[:5] for row in expected)!=actual:
            raise C09PagedCaptureHold('actual frozen paid details differ from complete global installed selection')
        if any(part[2]!=self.capture.parser.metadata['expires_at_utc'] for path,part in
                self.capture.parser.semantic_parts.items() if path[:3]==('compressed','input','detail_history')):
            raise C09PagedCaptureHold('actual globally selected paid detail absolute expiry differs')
        self.selected=[row[:5] for row in expected];self.phase='qualified'

    def advance(self,meter):
        _actual_meter(meter);self.source.require_current()
        result=self.copy()
        if result.phase=='raw':
            if result.raw_index==len(result.raw_paths):
                result.phase='query';result.text_reader=None
            elif result.text_reader is None:
                result.text_reader=_PaidFrozenTextMeasureV3(result.source,result.raw_paths[result.raw_index])
            elif not result.text_reader.complete:
                result.text_reader=self.text_reader.advance(meter)
            else:
                result.used+=result.text_reader.parser.utf8_bytes
                if result.used>262144:
                    raise C09PagedCaptureHold('actual selected raw tail exceeds shared installed history budget')
                result.raw_index+=1;result.text_reader=None
        elif result.phase=='query':
            if result.text_reader is None:
                result.text_reader=_PaidFrozenTextMeasureV3(result.source,('input','question','text'),1024)
            elif not result.text_reader.complete:
                result.text_reader=self.text_reader.advance(meter)
            else:
                result.query=''.join(result.text_reader.parser.prefix);result.text_reader=None;result.phase='blocks'
        elif result.phase=='blocks':
            if result.block_index==len(result.blocks):
                result.phase='parity'
            elif result.body is None:
                block=result.blocks[result.block_index];block.require_source(result.capture,meter)
                result.body=_PaidResultBodyV3(result,block)
            elif not result.body.complete:
                result.body=self.body.advance(meter)
            else:
                result._load_model(meter)
        elif result.phase=='rank':
            result._rank_slot(meter)
        elif result.phase=='choose':
            result._choose()
        elif result.phase=='emit':
            result._emit_detail()
        elif result.phase=='parity':
            result._parity()
        elif result.phase=='qualified':
            result.complete=True;result.proof=PaidCounterDetailSelectionProofV3(_ISSUER,result)
        else:
            raise C09PagedCaptureHold('actual global paid selection private phase differs')
        self.graph.require_current();self.source.require_current();self.capture.parser._require_arena()
        return result


class _PaidOwnerUnrevokedThroughCutProofV3:
    """A ledger interval fact; it never invents two historical guard observations."""
    def __init__(self,token,reader):
        if token is not _ISSUER or not reader.complete or reader.phase!='qualified':
            raise C09PagedCaptureHold('complete actual frozen Owner interval issuer required')
        self.capture,self.builder,self.pair=reader.capture,reader.builder,reader.pair
        self.source_original=reader.pair.source_original
        self.namespace=reader.namespace
        self.issue_operation_id=reader.issue_receipt.operation.operation_id
        self.issue_commitment,self.head_commitment=reader.issue_commitment,reader.head_commitment
        self.zero_records=tuple(reader.zero_records)
        self.fence_commitments=reader.fence_commitments
        self.digest=reader.digest
        _PROOFS.add(self)
        self.capture.parser._source_arena.add(self)

    def _source_heap_bytes(self):
        return _heap(self.source_original)+_heap(self.zero_records)+_heap(self.fence_commitments)+4096

    def require_current(self,parent,meter):
        _actual_meter(meter)
        if (self not in _PROOFS or type(parent) is not _D13PaidIdentityOriginalReadV3
                or parent.capture is not self.capture or parent.graph is not self.builder.session.require_actual_post_mirror_graph_v3()
                or (parent.schedule_fence.row_commitment,parent.write_fence.row_commitment)!=self.fence_commitments
                or self.builder.pair is not self.pair or self.pair.source_original!=self.source_original):
            raise C09PagedCaptureHold('actual frozen Owner interval crossed its paid original fences or Source cut')
        self.builder.require_current();self.pair.require_current()
        self.capture.require_complete(self.builder,self.capture.shape,self.capture.key)
        return self


class _PaidOwnerUnrevokedThroughCutReadV3:
    """Actual signed full-file/schema Source plus both exact zero-record revoke EOFs."""
    def __init__(self,parent):
        from .c09_authority_storage_rebase_v2 import _InstalledAuthorityRoleBuilderV2
        from .c09_role_capture_pair_v2 import InstalledC09RolePairV2
        if (type(parent) is not PaidHistoricalPermissionsSettlementReadV3 or parent.phase!='owner_interval'
                or parent.owner_receipt is None or type(parent.capture.builder) is not _InstalledAuthorityRoleBuilderV2
                or type(parent.capture.builder.pair) is not InstalledC09RolePairV2):
            raise C09PagedCaptureHold('Owner interval requires the actual adopted paid history and frozen Core producer')
        self.capture,self.builder=parent.capture,parent.capture.builder
        self.pair=self.builder.pair;self.namespace=self.builder.scope.authority_namespace
        if (self.pair._producer.session is not self.builder.session or self.pair.source_original.role!='core'
                or self.pair.source_original.scope_digest!=self.builder.scope.scope_digest):
            raise C09PagedCaptureHold('Owner interval has another actual Core Source producer')
        self.issue_receipt=parent.owner_receipt
        self.fence_commitments=(parent.parent.schedule_fence.row_commitment,parent.parent.write_fence.row_commitment)
        self.phase,self.table_index,self.complete,self.proof='source',0,False,None
        self.zero_records,self.issue_commitment,self.head_commitment=[],None,None
        self.digest=None
        self.capture.parser._source_arena.add(self)

    def _source_heap_bytes(self):
        return _heap(self.zero_records)+_heap(self.issue_commitment)+_heap(self.head_commitment)+4096

    def copy(self):
        self.capture.parser._require_arena(self._source_heap_bytes())
        result=copy(self);result.zero_records=list(self.zero_records)
        self.capture.parser._source_arena.add(result);return result

    def advance(self,meter):
        from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore,_COLUMNS,_TICKETS,_PENDING,_COMMITTED,_HEAD,_REVOKE_PENDING,_REVOKE_COMMITTED
        from .v2_owner_contract import canonical_bytes as owner_bytes
        from ..runtime.c09_paged_sql_v2 import c09_row_commitment_v2
        _actual_meter(meter);self.builder.require_current();self.pair.require_current()
        result=self.copy()
        if result.phase=='source':
            control=self.builder.session._control.maintenance.control
            original=control.read_build_original_v1(operation_id=self.builder.scope.operation_id,kind='capture_role_source_v2_core')
            if original is None or original['details']!=asdict(self.pair.source_original):
                raise C09PagedCaptureHold('Owner interval lacks signed complete actual Core file/schema Source')
            result.phase='schema'
        else:
            with legacy_cell_read_transaction_v2(self.pair.source):
                db=_BoundedReadConnectionV2(self.pair.source,meter)
                if result.phase=='schema':
                    descriptors=tuple(zip(_COLUMNS,(_TICKETS,_PENDING,_COMMITTED,_HEAD,_REVOKE_PENDING,_REVOKE_COMMITTED),strict=True))
                    if result.table_index==len(descriptors):
                        result.table_index=0;result.phase='revoke_eof'
                    else:
                        table,ddl=descriptors[result.table_index]
                        actual=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
                        columns=tuple(row[1] for row in db.execute('PRAGMA table_info('+table+')'))
                        if actual!=(ddl,) or columns!=_COLUMNS[table]:
                            raise C09PagedCaptureHold('Owner interval requires all original formal Owner ledger schemas')
                        result.table_index+=1
                elif result.phase=='revoke_eof':
                    tables=('authority_owner_revoke_pending_v1','authority_owner_revoke_committed_v1')
                    if result.table_index==len(tables):
                        result.phase='head'
                    else:
                        table=tables[result.table_index]
                        # Formal UNIQUE(authority_namespace) bounds this complete
                        # matching collection. The real cursor is consumed to EOF.
                        rows=db.execute('SELECT operation_id,authority_namespace FROM '+table+' WHERE authority_namespace=?',
                            (self.namespace,)).fetchall()
                        if rows:
                            raise C09PagedCaptureHold('paid original has revoke history without authenticated schedule/acquire guard observations')
                        shape=read_c09_table_shape_v2(self.pair.source,table,meter=meter)
                        result.zero_records.append((table,shape.schema_digest,self.namespace,0,'actual_matching_collection_eof'))
                        result.table_index+=1
                elif result.phase=='head':
                    lengths=db.execute('SELECT length(guard_bytes) FROM authority_owner_authorization_heads_v1 WHERE authority_namespace=?',
                        (self.namespace,)).fetchone()
                    if lengths is None:
                        raise C09PagedCaptureHold('Owner interval exact original active issue head absent')
                    self.capture.parser._require_arena(lengths[0]*36+65536)
                    head=meter.read_fixed_row(self.pair.source,'authority_owner_authorization_heads_v1',
                        ('authority_namespace','issue_operation_id','current_operation_id','revision','state','guard_bytes'),
                        'authority_namespace=?',(self.namespace,))
                    guard=AuthorityV2OwnerTicketStore._checked_current_head(db,self.namespace)
                    expected=self.issue_receipt.guard;operation=self.issue_receipt.operation
                    if (head[:5]!=(self.namespace,operation.operation_id,operation.operation_id,1,'active')
                            or head[5]!=owner_bytes(expected) or guard!=expected
                            or guard.authorization_revision!=1 or guard.pending_revoke_operation_id is not None
                            or guard.minimum_revocation_revision!=0 or guard.minimum_revocation_epoch!=0
                            or guard.authority_id!=self.builder.scope.authority_id
                            or guard.installation_id!=self.builder.scope.installation_id):
                        raise C09PagedCaptureHold('Owner interval is not the exact original unrevoked issue head')
                    issue=meter.read_fixed_row(self.pair.source,'authority_owner_issue_committed_v1',
                        ('authority_namespace','operation_id','proof_bytes','receipt_bytes','guard_bytes'),
                        'authority_namespace=?',(self.namespace,))
                    if issue is None or issue[:2]!=(self.namespace,operation.operation_id):
                        raise C09PagedCaptureHold('Owner interval committed issue original absent')
                    result.head_commitment=c09_row_commitment_v2(head)
                    result.issue_commitment=c09_row_commitment_v2(issue)
                    result.digest=_digest(('sylanne3.c09.owner-unrevoked-through-frozen-cut.v3',asdict(self.pair.source_original),
                        self.namespace,result.issue_commitment,result.head_commitment,tuple(result.zero_records),self.fence_commitments),
                        self.capture,meter)
                    result.phase='qualified'
                elif result.phase=='qualified':
                    result.complete=True;result.proof=_PaidOwnerUnrevokedThroughCutProofV3(_ISSUER,result)
                else:
                    raise C09PagedCaptureHold('actual frozen Owner interval private phase differs')
        self.builder.require_current();self.pair.require_current();self.capture.parser._require_arena()
        return result


class _PaidOwnerOriginalObservationsReadV3:
    """Two real Core observations, each joined to its committed Graph worker receipt."""
    def __init__(self,parent):
        if type(parent) is not PaidHistoricalPermissionsSettlementReadV3 or parent.phase!='owner_interval':
            raise C09PagedCaptureHold('Owner original observations need actual adopted paid permissions phase')
        self.parent,self.capture,self.builder,self.graph=parent,parent.capture,parent.capture.builder,parent.graph
        self.pair=self.builder.pair;self.namespace=self.builder.scope.authority_namespace
        self.phase,self.index,self.complete,self.proof='source',0,False,None
        self.link,self.original,self.payload,self.payload_offset,self.payload_total=None,None,bytearray(),0,None
        self.receipt_hash,self.receipt_offset,self.receipt_total=sha256(),0,None
        self.commitments,self.missing=[],False
        self.cut_reader=None
        self.capture.parser._source_arena.add(self)

    def _source_heap_bytes(self):
        return _heap(self.link)+_heap(self.original)+len(self.payload)+_heap(self.commitments)+8192

    def copy(self):
        self.capture.parser._require_arena(self._source_heap_bytes())
        result=copy(self);result.payload=bytearray(self.payload);result.receipt_hash=self.receipt_hash.copy()
        result.commitments=list(self.commitments);self.capture.parser._source_arena.add(result);return result

    def _worker(self):
        return (self.parent.parent.schedule_attempt,self.parent.parent.acquire_attempt)[self.index]

    def advance(self,meter):
        from .v3_owner_paid_guard_observation import (TABLE,COLUMNS,GRAPH_TABLE,GRAPH_COLUMNS,
            require_owner_paid_guard_observation_schema_v3,require_paid_owner_guard_link_schema_v3,
            validate_paid_owner_guard_link_row_v3,validate_owner_paid_guard_observation_row_v3)
        from .v2_owner_contract import canonical_bytes as owner_bytes
        _actual_meter(meter);self.builder.require_current();self.graph.require_current()
        result=self.copy()
        if result.phase=='source':
            control=self.builder.session._control.maintenance.control
            original=control.read_build_original_v1(operation_id=self.builder.scope.operation_id,kind='capture_role_source_v2_core')
            if (original is None or original['details']!=asdict(self.pair.source_original)
                    or self.pair.source_original.role!='core' or self.pair._producer.session is not self.builder.session):
                raise C09PagedCaptureHold('Owner historical observations lack actual signed complete Core Source')
            result.phase='graph_schema'
        elif result.phase=='graph_schema':
            with legacy_cell_read_transaction_v2(self.graph.pair.source):
                db=_BoundedReadConnectionV2(self.graph.pair.source,meter)
                row=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(GRAPH_TABLE,)).fetchone()
                if row is None:
                    result.missing=True;result.phase='cut'
                else:
                    require_paid_owner_guard_link_schema_v3(db);result.phase='link'
        elif result.phase=='link':
            worker=self._worker();phase=('schedule','acquire')[self.index]
            with legacy_cell_read_transaction_v2(self.graph.pair.source):
                shape=read_c09_table_shape_v2(self.graph.pair.source,GRAPH_TABLE,meter=meter)
                if shape.columns!=GRAPH_COLUMNS or shape.primary_key_columns!=GRAPH_COLUMNS[:4]:
                    raise C09PagedCaptureHold('actual paid Owner Graph association Source shape differs')
                row=meter.read_fixed_row(self.graph.pair.source,GRAPH_TABLE,GRAPH_COLUMNS,
                    'bot=? AND persona=? AND business_operation_id=? AND phase=?',
                    (*self.parent.metadata.namespace.as_tuple,worker.operation_id,phase))
                if row is not None:
                    self.builder.basis._graph_disposition_original_v3(self.graph,shape,tuple(row[:4]),meter)
            if row is None:
                result.missing=True;result.phase='next'
            else:
                validate_paid_owner_guard_link_row_v3(tuple(row))
                if row[:6]!=(*self.parent.metadata.namespace.as_tuple,worker.operation_id,phase,
                        worker.permit.operation_id,worker.request_digest):
                    raise C09PagedCaptureHold('actual paid Owner business association crossed its original worker/fence')
                result.link=tuple(row);result.phase='core_schema'
        elif result.phase=='core_schema':
            with legacy_cell_read_transaction_v2(self.pair.source):
                require_owner_paid_guard_observation_schema_v3(_BoundedReadConnectionV2(self.pair.source,meter))
            result.phase='core_header'
        elif result.phase=='core_header':
            worker=self._worker();phase=('schedule','acquire')[self.index]
            with legacy_cell_read_transaction_v2(self.pair.source):
                row=meter.read_fixed_row(self.pair.source,TABLE,
                    ('authority_namespace','business_operation_id','phase','fence_operation_id','payload_digest'),
                    'authority_namespace=? AND business_operation_id=? AND phase=? AND fence_operation_id=?',
                    (self.namespace,worker.operation_id,phase,worker.permit.operation_id))
                raw,total,kind=_read_d13_original_fragment_v3(self.pair.source,table=TABLE,column='payload_json',
                    where='authority_namespace=? AND business_operation_id=? AND phase=? AND fence_operation_id=?',
                    parameters=(self.namespace,worker.operation_id,phase,worker.permit.operation_id),
                    start=0,length=0,meter=meter,builder=self.builder)
            if row is None or row[4]!=self.link[6] or raw or kind!='text' or total<=0:
                raise C09PagedCaptureHold('actual paid Graph association lacks its complete named Core observation original')
            self.capture.parser._require_arena(total*36+65536)
            result.payload_total=total;result.original=tuple(row);result.phase='core_payload'
        elif result.phase=='core_payload':
            worker=self._worker();phase=('schedule','acquire')[self.index]
            amount=min(8192,self.payload_total-self.payload_offset)
            with legacy_cell_read_transaction_v2(self.pair.source):
                raw,total,kind=_read_d13_original_fragment_v3(self.pair.source,table=TABLE,column='payload_json',
                    where='authority_namespace=? AND business_operation_id=? AND phase=? AND fence_operation_id=?',
                    parameters=(self.namespace,worker.operation_id,phase,worker.permit.operation_id),
                    start=self.payload_offset,length=amount,meter=meter,builder=self.builder)
            if total!=self.payload_total or kind!='text' or len(raw)!=amount:
                raise C09PagedCaptureHold('actual paid Core observation original bytes changed')
            result.payload.extend(raw);result.payload_offset+=len(raw)
            if result.payload_offset==result.payload_total:
                text=result.payload.decode('ascii')
                row=(*self.original[:4],text,self.original[4])
                value=validate_owner_paid_guard_observation_row_v3(row)
                expected=self.parent.owner_receipt
                if (value.permit!=worker.permit or value.guard!=expected.guard
                        or value.issue_operation_id!=expected.operation.operation_id
                        or value.request_digest!=worker.request_digest or value.phase!=phase):
                    raise C09PagedCaptureHold('actual historical Owner observation differs from original paid issue/permit')
                head=(self.namespace,value.issue_operation_id,value.issue_operation_id,1,'active',owner_bytes(value.guard))
                commitment=_digest(tuple({'blob_sha256':sha256(item).hexdigest(),'size':len(item)}
                    if type(item) is bytes else item for item in head),self.capture,meter)
                if value.head_commitment!=commitment:
                    raise C09PagedCaptureHold('actual Owner observation original head row commitment differs')
                result.commitments.append((phase,worker.operation_id,worker.request_digest,worker.permit.operation_id,
                    value.digest,self.link[7],value.head_commitment))
                result.payload.clear();result.payload_offset=0;result.payload_total=None;result.phase='receipt'
        elif result.phase=='receipt':
            worker=self._worker()
            if self.receipt_total is None:
                amount=0
            else:
                amount=min(8192,self.receipt_total-self.receipt_offset)
            raw,total,kind=_read_d13_original_fragment_v3(self.graph.pair.source,
                table=worker.shape.table,column='receipt_json',where=worker.row_where,parameters=worker.row_key,
                start=self.receipt_offset,length=amount,meter=meter,builder=self.builder)
            if kind!='text' or total!=worker.json_source_bytes['receipt_json'] or len(raw)!=amount:
                raise C09PagedCaptureHold('actual paid business receipt original bytes changed')
            if self.receipt_total is None:
                result.receipt_total=total
            else:
                result.receipt_hash.update(raw);result.receipt_offset+=len(raw)
                if result.receipt_offset==self.receipt_total:
                    if result.receipt_hash.hexdigest()!=self.link[7]:
                        raise C09PagedCaptureHold('actual paid Owner observation is not joined to its committed business receipt EOF')
                    result.phase='next'
        elif result.phase=='next':
            result.index+=1;result.link=result.original=None
            result.receipt_hash,result.receipt_offset,result.receipt_total=sha256(),0,None
            result.phase='link' if result.index<2 else ('cut' if result.missing else 'qualified')
        elif result.phase=='cut':
            if result.cut_reader is None:
                result.cut_reader=_PaidOwnerUnrevokedThroughCutReadV3(self.parent)
            elif not self.cut_reader.complete:
                result.cut_reader=self.cut_reader.advance(meter)
            else:
                result.cut_reader.proof.require_current(self.parent.parent,meter)
                result.proof=result.cut_reader.proof;result.complete=True
        elif result.phase=='qualified':
            result.complete=True;result.proof=_PaidOwnerObservedPermissionsProofV3(_ISSUER,result)
        else:
            raise C09PagedCaptureHold('actual historical Owner original observation private phase differs')
        self.builder.require_current();self.graph.require_current();self.capture.parser._require_arena();return result


class _PaidOwnerObservedPermissionsProofV3:
    """Issued only after both actual Core originals and actual Graph receipt EOFs."""
    def __init__(self,token,reader):
        if token is not _ISSUER or not reader.complete or reader.phase!='qualified' or len(reader.commitments)!=2:
            raise C09PagedCaptureHold('two complete actual paid Owner original observations required')
        self.capture,self.builder,self.graph=reader.capture,reader.builder,reader.graph
        self.source_original=reader.pair.source_original
        self.commitments=tuple(reader.commitments)
        self.fence_commitments=(reader.parent.parent.schedule_fence.row_commitment,reader.parent.parent.write_fence.row_commitment)
        _PROOFS.add(self);self.capture.parser._source_arena.add(self)

    def _source_heap_bytes(self):
        return _heap(self.source_original)+_heap(self.commitments)+_heap(self.fence_commitments)+4096

    def require_current(self,parent,meter):
        _actual_meter(meter)
        if (self not in _PROOFS or type(parent) is not _D13PaidIdentityOriginalReadV3 or parent.capture is not self.capture
                or parent.graph is not self.graph or self.builder.pair.source_original!=self.source_original
                or (parent.schedule_fence.row_commitment,parent.write_fence.row_commitment)!=self.fence_commitments):
            raise C09PagedCaptureHold('actual paid Owner permission originals crossed their frozen Source or fences')
        self.builder.require_current();self.graph.require_current()
        self.capture.require_complete(self.builder,self.capture.shape,self.capture.key)
        return self
