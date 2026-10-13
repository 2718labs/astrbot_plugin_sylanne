"""Installed selected V3 history reads over the actual sealed Graph originals.

This module reads the real stores. It contains no replacement fact ledger and
never treats a cursor, DTO, partial page or budget refusal as a complete proof.
"""
from __future__ import annotations

from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3

from contextlib import contextmanager, closing
from dataclasses import asdict, dataclass
from pathlib import Path
import json
import sqlite3
from time import monotonic_ns

from .contract import AuthorityUnavailable
from .c09_paged_recovery_facts_v2 import (
    _FAMILIES, _BoundedReadConnectionV2, _read_one, _decode_fact, _fact_key,
    _decode_completion, _LegacyRecoveryFrameReaderV2, _PriorPagedRecoveryFrameV2,
    C09VerifiedPagedPreparedSummaryV2, begin_next_authenticated_prepared_reader_v2,
)
from .c09_prepared_storage_v3 import (
    _read_selected_prepared_payload_v3, _read_original, verify_prepared_original_v3,
    begin_selected_segmented_role_original_read_v3, VerifiedSegmentedRoleOriginalV3,
)
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.c09_paged_capture_contract_v2 import (
    C09CaptureScopeV2, C09CaptureRecordV2, C09CapturePageV2, C09CountOriginalV2,
    begin_c09_stream_v2, verify_c09_page_v2, verify_c09_complete_stream_v2,
    c09_paged_value_from_wire_v2,
)
from ..runtime.c09_paged_sql_v2 import (
    C09SqlByteMeterV2, c09_sql_meter_quantum_v2, current_c09_sql_meter_v2,
    c09_row_commitment_v2, read_c09_table_shape_v2,
)
from ..segmented_sql_cell_v1 import DDLS, TRIGGERS, LAYOUT_SCHEMA, LAYOUTS, LAYOUT_SCHEMA_DIGEST

_BASIS = object()
_VERIFIED = object()
_FAMILY_NAMES = ('journal', *_FAMILIES, 'binding', 'model')
_LAYOUT_COLUMNS = ('singleton', 'schema', 'storage_instance_id', 'role', 'layout_id',
    'layout_schema_digest', 'authority_id', 'authority_namespace', 'installation_id',
    'storage_generation', 'origin_scope_digest')


def _bounded(db, meter):
    reader = _BoundedReadConnectionV2(db, meter)
    reader._natural_preflight_v3 = lambda size: meter.require_available(size * 7)
    return reader


class _InstalledSelectedStorageBasisV3:
    """Private read basis after real Control EOF and signed selected descriptors."""
    def __init__(self, token, control, current, manifest, prepared):
        if token is not _BASIS:
            raise AuthorityUnavailable('actual installed selected read basis required')
        self.control, self.current, self.manifest, self.prepared = control, dict(current), manifest, prepared
        self.selection_digest = canonical_digest(('sylanne3.c09.selected-history-scope.v3',
            control.authority_id, control.installation_id, prepared['namespace'],
            current['pointer_version'], manifest['manifest_digest'], manifest['generation'], prepared['prepared_digest']))

    def member(self, role):
        return next(member for member in self.manifest['members'] if member['role'] == role)

    def require_current(self, *, meter):
        if meter is not current_c09_sql_meter_v2():
            raise AuthorityUnavailable('actual installed selected read quantum required')
        control = self.control
        control.lease.require_held()
        with control._db() as db:
            proof = control._c09_control_chain_proof_v2
            current = proof.require_current(db, meter)
            row = _read_one(db, 'SELECT prepared_digest FROM c09_storage_operations_v3 '
                'WHERE operation_id=? AND new_manifest_digest=?',
                (self.prepared['operation_id'], self.manifest['manifest_digest']), meter)
        if ((current['pointer_version'], current['current_manifest_digest']) !=
                (self.current['pointer_version'], self.current['current_manifest_digest'])
                or current['stage'] not in {'INTENT', 'PREPARED', 'SWITCHED', 'CLEANED', 'RELEASED'}
                or current['stage'] not in {'INTENT', 'PREPARED'} and current['active_operation_id'] != self.prepared['operation_id']
                or row != (self.prepared['prepared_digest'],)):
            raise AuthorityUnavailable('actual selected pointer, stage or V3 PREPARED changed')
        for member in self.manifest['members']:
            from .c09_storage_control_v1 import _regular_path
            stat = _regular_path(member['resolved_path']).stat()
            if (stat.st_dev, stat.st_ino) != (member['device'], member['file_id']):
                raise AuthorityUnavailable('actual selected four-store inode changed')
        return current

    @contextmanager
    def read_database(self, role, *, meter):
        self.require_current(meter=meter)
        member = self.member(role)
        started = monotonic_ns()
        with closing(sqlite3.connect(Path(member['resolved_path']).as_uri() + '?mode=ro',
                uri=True, isolation_level=None)) as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            try:
                yield db
            finally:
                db.rollback()
        if monotonic_ns() - started > meter.budget.max_read_ns:
            raise AuthorityUnavailable('actual selected read transaction exceeded its unchanged duration')
        self.require_current(meter=meter)

    def require_layout(self, db, role, *, meter):
        bounded = _bounded(db, meter)
        for name, ddl in DDLS.items():
            if bounded.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() != (ddl,):
                raise AuthorityUnavailable('actual selected segmented table schema differs')
        for name, ddl in TRIGGERS.items():
            if bounded.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone() != (ddl,):
                raise AuthorityUnavailable('actual selected segmented immutable trigger differs')
        row = bounded.execute('SELECT ' + ','.join(_LAYOUT_COLUMNS) +
            ' FROM segmented_storage_layout_v1 WHERE singleton=1').fetchone()
        layout = self.manifest['segmented_layouts'][role]
        expected = (1, LAYOUT_SCHEMA, layout['storage_instance_id'], role, LAYOUTS[role], LAYOUT_SCHEMA_DIGEST,
            self.control.authority_id, self.prepared['namespace'], self.control.installation_id,
            self.manifest['generation'], self.prepared['capture_scope_digest'])
        if row != expected or bounded.execute('SELECT 1 FROM segmented_storage_layout_v1 WHERE singleton<>1 LIMIT 1').fetchone() is not None:
            raise AuthorityUnavailable('actual selected segmented layout or storage instance differs')


class _SelectedFamilyReaderV3:
    """Actual Graph family pages, members, typed rows, source count and EOF."""
    def __init__(self, basis, completion, family):
        if family not in _FAMILY_NAMES:
            raise AuthorityUnavailable('named selected recovery family required')
        self.basis, self.completion, self.family = basis, completion, family
        self.locator = getattr(completion, {'journal': 'journal_stream', 'binding': 'binding_stream', 'model': 'model_stream'}.get(family, family))
        self.cursor = begin_c09_stream_v2(self.locator.identity)
        self.page = self.records = None
        self.index = 0
        self.actual_after = None
        self.complete = False

    def _next(self, db, after, meter):
        if self.family == 'journal':
            row = _read_one(db, 'SELECT seq,row_commitment FROM c09_recovery_journal_index_v2 '
                'WHERE scope_digest=? AND seq>? ORDER BY seq LIMIT 1',
                (self.completion.scope_digest, 0 if after is None else after[0]), meter)
            return None if row is None else C09CaptureRecordV2((row[0],), row[1])
        row = _read_one(db, 'SELECT item_key,value_digest,origin_digest FROM c09_recovery_items_v2 '
            'WHERE scope_digest=? AND family=? AND item_key COLLATE BINARY>? ORDER BY item_key COLLATE BINARY LIMIT 1',
            (self.completion.scope_digest, self.family, '' if after is None else after[0]), meter)
        return None if row is None else C09CaptureRecordV2((row[0],), canonical_digest((self.family, *row)))

    def lookup(self, db, key, meter):
        row = _bounded(db, meter).execute('SELECT value_json,value_digest,origin_digest FROM c09_recovery_items_v2 '
            'WHERE scope_digest=? AND family=? AND item_key=?', (self.completion.scope_digest, self.family, key)).fetchone()
        if row is None:
            return None
        value = _decode_fact(self.family, row[0])
        if (_fact_key(self.family, value) != key or canonical_digest(value) != row[1]
                or canonical_serialize(asdict(value)) != row[0]):
            raise AuthorityUnavailable('actual selected typed recovery original differs')
        return value

    def advance(self, db, meter, observe):
        if self.complete:
            return True
        stream, seal = self.locator.identity, self.locator.complete
        if self.records is not None:
            record = self.records[self.index]
            if self._next(db, self.actual_after, meter) != record:
                raise AuthorityUnavailable('actual selected family omits or changes a retained original')
            ordinal = self.cursor.record_offset + self.index + 1
            member = _read_one(db, 'SELECT key_digest,primary_key_json,commitment,page_index FROM c09_capture_members_v2 '
                'WHERE stream_id=? AND record_ordinal=?', (stream.stream_id, ordinal), meter)
            if member != (canonical_digest(record.primary_key), canonical_serialize(record.primary_key), record.commitment, self.page.page_index):
                raise AuthorityUnavailable('actual selected family member index differs')
            value = None if self.family == 'journal' else self.lookup(db, record.primary_key[0], meter)
            if self.family != 'journal' and value is None:
                raise AuthorityUnavailable('actual selected sealed family body disappeared')
            observe(record, value)
            self.actual_after = record.primary_key
            self.index += 1
            if self.index == len(self.records):
                self.cursor = verify_c09_page_v2(stream, self.cursor, self.page, self.records)
                self.records = self.page = None
                self.index = 0
            return False
        if self.cursor.page_index < seal.page_count:
            row = _bounded(db, meter).execute('SELECT descriptor_json,records_json FROM c09_capture_pages_v2 '
                'WHERE stream_id=? AND page_index=?', (stream.stream_id, self.cursor.page_index)).fetchone()
            if row is None:
                raise AuthorityUnavailable('actual selected sealed family page is absent')
            self.page = c09_paged_value_from_wire_v2(json.loads(row[0]), C09CapturePageV2)
            records = json.loads(row[1])
            if type(records) is not list or not 1 <= len(records) <= 100:
                raise AuthorityUnavailable('actual selected family page exceeds its registered record codec')
            self.records = tuple(c09_paged_value_from_wire_v2(value, C09CaptureRecordV2) for value in records)
            self.actual_after = self.cursor.last_key
            return False
        if self._next(db, self.cursor.last_key, meter) is not None:
            raise AuthorityUnavailable('actual selected family has an unsealed suffix')
        for table, column, predicate, bound in (
                ('c09_capture_pages_v2', 'page_index', '<0 OR page_index>=?', seal.page_count),
                ('c09_capture_members_v2', 'record_ordinal', '<1 OR record_ordinal>?', seal.record_count)):
            if _read_one(db, 'SELECT 1 FROM ' + table + ' WHERE stream_id=? AND (' + column + predicate + ') LIMIT 1',
                    (stream.stream_id, bound), meter) is not None:
                raise AuthorityUnavailable('actual selected family includes extra unsealed material')
        progress = _bounded(db, meter).execute('SELECT progress_json FROM c09_recovery_progress_v2 '
            'WHERE scope_digest=? AND phase=?', (self.completion.scope_digest, 'seal:' + self.family)).fetchone()
        if progress is None:
            raise AuthorityUnavailable('actual selected family count and EOF original is absent')
        raw = json.loads(progress[0])
        census = c09_paged_value_from_wire_v2(raw['census'], C09CountOriginalV2)
        verify_c09_complete_stream_v2(stream, self.cursor, census, seal,
            data_eof_observation_digest=raw['data_eof'])
        if self.family == 'journal' and seal.record_count != self.completion.old_seq:
            raise AuthorityUnavailable('actual selected journal count differs from its complete signed pin')
        self.complete = True
        return True


class C09SelectedHistoryReadonlySinkV3:
    """Actual selected Graph history evidence, with no capture pair or SQL writes."""
    def __init__(self, token, basis, scope):
        if token is not _BASIS:
            raise AuthorityUnavailable('actual installed selected history sink required')
        self.basis, self.control, self.scope = basis, basis.control, scope
        self.db = None

    def history_storage_db_v3(self):
        if self.db is None or not self.db.in_transaction:
            raise AuthorityUnavailable('actual selected history read snapshot required')
        return self.db

    def _merge(self, family, value, origin, meter):
        row = _bounded(self.history_storage_db_v3(), meter).execute('SELECT value_json,value_digest FROM c09_recovery_items_v2 '
            'WHERE scope_digest=? AND family=? AND item_key=?', (self.scope.scope_digest, family, _fact_key(family, value))).fetchone()
        if row != (canonical_serialize(asdict(value)), canonical_digest(value)):
            raise AuthorityUnavailable('actual selected current facts omit or conflict with authenticated history')


class _LegacyReadonlyFrameV3(_LegacyRecoveryFrameReaderV2):
    def _mark(self, family, key, digest, auxiliary=None):
        raw = canonical_serialize({} if auxiliary is None else auxiliary)
        row = _read_one(self.producer.history_storage_db_v3(), 'SELECT value_digest,auxiliary_json FROM c09_recovery_history_members_v2 '
            'WHERE scope_digest=? AND generation=? AND family=? AND item_key=?',
            (self.scope, self.generation, family, key), self.meter)
        if row != (digest, raw):
            raise AuthorityUnavailable('actual selected immutable historical member is absent or differs')

    def _type(self, cell_kind, event, cls):
        row = _read_one(self.producer.history_storage_db_v3(), 'SELECT type_name FROM c09_recovery_history_types_v2 '
            'WHERE scope_digest=? AND generation=? AND cell_kind=? AND byte_offset=?',
            (self.scope, self.generation, cell_kind, event.start_offset + 1), self.meter)
        if row != (cls.__module__ + '.' + cls.__qualname__,):
            raise AuthorityUnavailable('actual selected historical canonical type annotation differs')


@dataclass(frozen=True, slots=True)
class C09SelectedSanitizedExecutionReadV3:
    execution_id: str
    business_operation_id: str
    status: str
    input_commitment: str
    result_commitment: str | None
    terminal_commitment: str | None
    consumed: bool
    d02_facts: tuple
    d11_facts: tuple
    unknown_footprint: object | None
    originating_journal_id: str
    current_prepared_digest: str
    history_count: int
    history_root: str
    schema: str = 'sylanne3.c09.selected-sanitized-execution-read.v3'


class VerifiedSelectedHistoryReadV3:
    """Private whole-history/whole-family EOF qualification of this selected store."""
    def __init__(self, token, builder):
        if token is not _VERIFIED or builder.phase != 'complete':
            raise AuthorityUnavailable('actual complete selected history read issuer required')
        self.basis, self.scope, self.completion = builder.basis, builder.scope, builder.completion
        self.verified_roles = tuple(builder.roles[role] for role in ('core', 'deletion', 'execution', 'graph'))
        self.history_count, self.history_root = builder.history_generation, builder.history_root
        self.natural_core_proof = builder.natural_core_proof
        self.core_source_proof = builder.core_source_proof
        self.runtime_physical_proof = builder.runtime_physical_proof
        self.provider_scope_proof = builder.provider_scope_proof
        self.family_eof = {name: dict(stream_id=reader.locator.identity.stream_id,
            complete_digest=reader.locator.complete.digest, record_count=reader.locator.complete.record_count,
            eof_observation_digest=reader.locator.complete.eof_observation_digest) for name, reader in builder.family_readers.items()}

    def require_current(self, *, meter):
        self.basis.require_current(meter=meter)
        self.natural_core_proof.require_current(meter=meter)
        self.core_source_proof.require_current(meter=meter)
        self.runtime_physical_proof.require_current(meter=meter)
        self.provider_scope_proof.require_current(meter=meter)
        return self

    def lookup(self, family, key, *, meter):
        if family not in _FAMILY_NAMES or family == 'journal':
            raise AuthorityUnavailable('named typed selected family point read required')
        self.require_current(meter=meter)
        with self.basis.read_database('graph', meter=meter) as db:
            reader = _SelectedFamilyReaderV3(self.basis, self.completion, family)
            return reader.lookup(db, key, meter)

    def lookup_execution(self, key, *, meter): return self.lookup('executions', key, meter=meter)
    def lookup_execution_binding(self, key, *, meter): return self.lookup('binding', key, meter=meter)
    def lookup_unknown(self, key, *, meter): return self.lookup('unknown_facts', key, meter=meter)
    def lookup_model_original(self, key, *, meter): return self.lookup('model', key, meter=meter)
    def lookup_d02(self, key, *, meter): return self.lookup('d02_facts', key, meter=meter)
    def lookup_d11(self, key, *, meter): return self.lookup('d11_facts', key, meter=meter)
    def lookup_graph(self, key, *, meter): return self.lookup('graph_facts', key, meter=meter)

    def read_sanitized_execution_v3(self, *, namespace, execution_id, meter):
        self.require_current(meter=meter)
        if namespace != self.basis.prepared['namespace']:
            raise AuthorityUnavailable('actual selected execution namespace differs')
        with self.basis.read_database('graph', meter=meter) as db:
            def point(family, key):
                return _SelectedFamilyReaderV3(self.basis, self.completion, family).lookup(db, key, meter)
            fact = point('executions', execution_id)
            if fact is None:
                return None
            binding = point('binding', execution_id)
            unknown = point('unknown_facts', execution_id)
            if (binding is None or binding.input_commitment != fact.input_commitment
                    or fact.status == 'unknown' and unknown is None):
                raise AuthorityUnavailable('actual selected typed execution binding or unknown constraint is absent')
            d02 = tuple(point('d02_facts', key) for key in binding.d02_quote_ids)
            d11 = tuple(point('d11_facts', key) for key in binding.d11_settlement_ids)
            if (any(value is None or value.component_id not in binding.d02_component_ids for value in d02)
                    or any(value is None for value in d11)):
                raise AuthorityUnavailable('actual selected execution accounting obligations are not completely covered')
        return C09SelectedSanitizedExecutionReadV3(execution_id, binding.business_operation_id,
            fact.status, fact.input_commitment, fact.result_commitment, fact.terminal_commitment, fact.consumed,
            d02, d11, None if unknown is None else unknown.footprint, binding.originating_journal_id,
            self.basis.prepared['prepared_digest'], self.history_count, self.history_root)

    def read_sanitized_model_budget_v3(self, *, namespace, call_id, meter):
        self.require_current(meter=meter)
        if namespace != self.basis.prepared['namespace']:
            raise AuthorityUnavailable('actual selected model namespace differs')
        with self.basis.read_database('graph', meter=meter) as graph:
            def point(family, key):
                return _SelectedFamilyReaderV3(self.basis, self.completion, family).lookup(graph, key, meter)
            model = point('model', call_id)
            if model is None:
                return None
            binding = point('binding', call_id)
            fact = point('executions', call_id)
            from .c09_model_budget_original_v1 import model_unit_fact_v4
            units = tuple(model_unit_fact_v4(model, unit) for unit in model.units if unit.actual_or_none is not None)
            if (model.namespace != namespace or fact is None or binding is None or binding.execution_kind != 'model'
                    or fact.signature_commitment != model.original_digest or fact.input_commitment != model.request_digest
                    or fact.terminal_commitment != model.terminal_digest_or_none
                    or binding.business_operation_id != model.model_operation_id
                    or binding.originating_journal_id != model.originating_journal_id
                    or binding.source_row_commitments != tuple(sorted({*model.source_row_commitments, model.original_digest}))
                    or binding.d11_settlement_ids != tuple(sorted(unit.settlement_id for unit in units))
                    or any(point('d11_facts', unit.settlement_id) != unit for unit in units)
                    or any(unit.actual_or_none is None for unit in model.units) and point('unknown_facts', call_id) is None):
                raise AuthorityUnavailable('actual selected model original is not exactly pinned by its typed accounting facts')
        with self.basis.read_database('core', meter=meter) as core:
            for kind, identity in (('model_call', call_id), ('model_operation', model.model_operation_id),
                    ('model_job', model.job_id), ('model_acquire', model.acquire_operation_id),
                    ('model_admission', model.admission_id_or_none)):
                if identity is not None and _read_one(core, 'SELECT original_commitment FROM authority_c09_consumed_execution_v1 '
                        'WHERE namespace=? AND kind=? AND item_id=?', (namespace, kind, identity), meter) != (model.original_digest,):
                    raise AuthorityUnavailable('actual selected model irreversible consumed identity differs')
            if _read_one(core, 'SELECT 1 FROM authority_model_egress_observations_v1 WHERE call_id=?', (call_id,), meter) is not None:
                raise AuthorityUnavailable('actual selected consumed model response body survives')
        return model

    def begin_family_consumer(self, family, *, meter):
        self.require_current(meter=meter)
        return _SelectedFamilyReaderV3(self.basis, self.completion, family)

    def next_family_page(self, family, *, after_key, limit, meter):
        self.require_current(meter=meter)
        if family not in _FAMILY_NAMES or family == 'journal' or type(limit) is not int or not 1 <= limit <= meter.budget.max_records:
            raise AuthorityUnavailable('actual bounded named selected family page required')
        with self.basis.read_database('graph', meter=meter) as db:
            reader = _SelectedFamilyReaderV3(self.basis, self.completion, family)
            rows = _bounded(db, meter).execute('SELECT item_key FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? '
                'AND item_key COLLATE BINARY>? ORDER BY item_key COLLATE BINARY LIMIT ?',
                (self.scope.scope_digest, family, '' if after_key is None else after_key, limit))
            result = tuple((key, reader.lookup(db, key, meter)) for (key,) in rows)
            last = after_key if not result else result[-1][0]
            eof = _read_one(db, 'SELECT 1 FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? '
                'AND item_key COLLATE BINARY>? LIMIT 1', (self.scope.scope_digest, family, '' if last is None else last), meter) is None
        return result, last, eof


class InstalledSelectedHistoryBuilderV3:
    def __init__(self, control):
        self.control = control
        self.phase = 'control'
        self.basis = self.scope = self.completion = None
        self.roles = {}
        self.role_index = self.layout_index = self.family_index = 0
        self.role_reader = None
        self.family_readers = {}
        self.history_generation = 0
        self.history_prior = self.history_manifest = None
        self.history_root = canonical_digest(('sylanne3.c09.selected-history-chain.v3', control.authority_id, control.installation_id))
        self.history_scan = self.history_frame = self.history_sink = None
        self.natural_core_reader = self.natural_core_proof = None
        self.core_source_reader = self.core_source_proof = None
        self.runtime_physical_reader = self.runtime_physical_proof = None
        self.provider_scope_reader = self.provider_scope_proof = None
        self.result = None
        self.failed = False

    def advance(self):
        if self.failed:
            raise AuthorityUnavailable('actual selected history preserves its first failed quantum')
        try:
            with self.control.reserve_control_read_v3() as budget:
                meter = require_c09_reserved_meter_v3(budget)
                with c09_sql_meter_quantum_v2(meter):
                    result = self._advance(meter)
            return result
        except BaseException:
            self.failed = True
            self.result = None
            raise

    def _advance(self, meter):
        if self.result is not None:
            return self.result.require_current(meter=meter)
        if self.phase == 'control':
            if self.control.advance_current_control_chain_v2(meter=meter) is not None:
                self.phase = 'manifest'
            return {'status': 'progress', 'phase': 'selected_control_chain'}
        if self.phase == 'manifest':
            with self.control._db() as db:
                current = self.control._c09_control_chain_proof_v2.require_current(db, meter)
                row = _bounded(db, meter).execute('SELECT manifest_json,issuer_id,key_id,signature,generation '
                    'FROM c09_storage_manifests_v1 WHERE manifest_digest=?', (current['current_manifest_digest'],)).fetchone()
                if row is None or len(row[0].encode()) > 65536:
                    raise AuthorityUnavailable('actual selected manifest descriptor is absent or exceeds its registered bound')
                manifest = json.loads(row[0])
                self.control._manifest(manifest)
                from .c09_storage_manifest_v2 import manifest_signature_domain
                signed = self.control.sign_original_v1(manifest_signature_domain(manifest),
                    dict(schema=manifest_signature_domain(manifest), manifest=manifest, issuer_id=self.control.authority_id), 'digest')
                if ((row[1], row[2], row[3], row[4]) !=
                        (self.control.authority_id, self.control.key_id, signed['signature'], manifest['generation'])
                        or current['stage'] not in {'INTENT', 'PREPARED', 'SWITCHED', 'CLEANED', 'RELEASED'}):
                    raise AuthorityUnavailable('actual selected manifest signature or current stage differs')
                prepared = _read_selected_prepared_payload_v3(self.control, db, manifest, meter)
            if prepared is None:
                raise AuthorityUnavailable('actual selected segmented PREPARED is absent')
            self.basis = _InstalledSelectedStorageBasisV3(_BASIS, self.control, current, manifest, prepared)
            self.phase = 'scope'
            return {'status': 'progress', 'phase': 'selected_manifest'}
        self.basis.require_current(meter=meter)
        if self.phase == 'scope':
            with self.control._db() as db:
                self.scope = C09CaptureScopeV2(**_read_original(self.control, db, self.basis.prepared['operation_id'], 'capture_scope_v2', None, meter))
            self.phase = 'roles'
            return {'status': 'progress', 'phase': 'selected_scope'}
        if self.phase == 'roles':
            names = ('core', 'deletion', 'execution', 'graph')
            if self.role_index == len(names):
                self.phase = 'prepared'
                return {'status': 'progress', 'phase': 'selected_role_originals'}
            role = names[self.role_index]
            if self.role_reader is None:
                self.role_reader = begin_selected_segmented_role_original_read_v3(self.basis, scope=self.scope, role=role,
                    base_complete_original_digest=self.basis.prepared['four_role_complete_original_digests'][role],
                    segmented_complete_original_digest=self.basis.prepared['segmented_role_complete_original_digests'][role])
            result = self.role_reader.advance(meter=meter)
            if type(result) is VerifiedSegmentedRoleOriginalV3:
                self.roles[role] = result
                self.role_reader = None
                self.role_index += 1
            return {'status': 'progress', 'phase': 'selected_role_originals', 'role': role}
        if self.phase == 'prepared':
            with self.control._db() as db:
                verify_prepared_original_v3(self.control, db, self.basis.prepared, self.basis.manifest,
                    verified_roles=tuple(self.roles[role] for role in ('core', 'deletion', 'execution', 'graph')), meter=meter)
            self.phase = 'layouts'
            return {'status': 'progress', 'phase': 'selected_prepared'}
        if self.phase == 'layouts':
            role = ('core', 'deletion', 'execution', 'graph')[self.layout_index]
            with self.basis.read_database(role, meter=meter) as db:
                self.basis.require_layout(db, role, meter=meter)
            self.layout_index += 1
            if self.layout_index == 4:
                self.phase = 'natural_core'
            return {'status': 'progress', 'phase': 'selected_layout', 'role': role}
        if self.phase == 'natural_core':
            from .c09_natural_final_history_v4 import begin_selected_natural_core_obligations_read_v4, SelectedNaturalCoreObligationsV4
            if self.natural_core_reader is None:
                self.natural_core_reader = begin_selected_natural_core_obligations_read_v4(self.basis,
                    preparedref=self.basis.prepared['natural_core_obligations_complete_original_digest'], meter=meter)
            else:
                self.natural_core_reader = self.natural_core_reader.advance(meter)
            if self.natural_core_reader.complete:
                proof = self.natural_core_reader.proof
                if type(proof) is not SelectedNaturalCoreObligationsV4:
                    raise AuthorityUnavailable('actual selected Core obligation issuer differs')
                self.natural_core_proof = proof.require_current(meter=meter)
                self.phase = 'core_source'
            return {'status': 'progress', 'phase': 'selected_natural_core_obligations'}
        if self.phase == 'core_source':
            from .c09_selected_core_source_v3 import begin_selected_core_source_metadata_read_v3
            if self.core_source_reader is None:
                self.core_source_reader = begin_selected_core_source_metadata_read_v3(self.basis, meter=meter)
            elif self.core_source_reader.advance(meter):
                self.core_source_proof = self.core_source_reader.proof.require_current(meter=meter)
                self.phase = 'runtime_physical'
            return {'status': 'progress', 'phase': 'selected_core_source_metadata_eof'}
        if self.phase == 'runtime_physical':
            from .c09_selected_runtime_v3 import begin_selected_runtime_physical_read_v3
            if self.runtime_physical_reader is None:
                self.runtime_physical_reader = begin_selected_runtime_physical_read_v3(self.basis, self.scope, meter=meter)
            elif self.runtime_physical_reader.advance(meter):
                self.runtime_physical_proof = self.runtime_physical_reader.proof.require_current(meter=meter)
                self.phase = 'facts'
            return {'status': 'progress', 'phase': 'selected_runtime_physical_eof'}
        if self.phase == 'facts':
            with self.control._db() as db:
                details = _read_original(self.control, db, self.basis.prepared['operation_id'], 'capture_facts_complete_v2',
                    self.basis.prepared['facts_complete_original_digest'], meter)
            self.completion = _decode_completion(details)
            if self.completion.scope_digest != self.scope.scope_digest or self.completion.pin_digest != self.basis.prepared['facts_pin_digest']:
                raise AuthorityUnavailable('actual selected facts completion pin differs')
            self.history_sink = C09SelectedHistoryReadonlySinkV3(_BASIS, self.basis, self.scope)
            self.phase = 'history'
            return {'status': 'progress', 'phase': 'selected_facts_pin'}
        if self.phase == 'history':
            return self._advance_history(meter)
        if self.phase == 'families':
            if self.family_index == len(_FAMILY_NAMES):
                self.phase = 'provider_scopes'
                return {'status':'progress','phase':'selected_model_families_complete'}
            family = _FAMILY_NAMES[self.family_index]
            if family not in self.family_readers:
                self.family_readers[family] = _SelectedFamilyReaderV3(self.basis, self.completion, family)
            with self.basis.read_database('graph', meter=meter) as graph:
                if self.family_readers[family].advance(graph, meter, lambda record, value: None):
                    self.family_index += 1
            return {'status': 'progress', 'phase': 'selected_family_eof', 'family': family}
        if self.phase == 'provider_scopes':
            from .c09_provider_scope_v3 import SelectedProviderScopeReadV3
            if self.provider_scope_reader is None:
                self.provider_scope_reader = SelectedProviderScopeReadV3(self.basis,self.scope,self.completion)
            elif self.provider_scope_reader.advance(meter):
                self.provider_scope_proof = self.provider_scope_reader.proof.require_current(meter=meter)
                self.phase = 'complete'
                self.result = VerifiedSelectedHistoryReadV3(_VERIFIED,self)
                return self.result
            return {'status':'progress','phase':'selected_provider_scope_eof'}
        raise AuthorityUnavailable('actual selected history private phase differs')

    def _advance_history(self, meter):
        through = self.basis.manifest['generation']
        if self.history_scan is None:
            self.history_scan = begin_next_authenticated_prepared_reader_v2(self.control,
                after_generation=self.history_generation, through_generation=through, meter=meter)
            if self.history_scan is None:
                if (self.history_generation != through or self.history_prior != self.basis.prepared['prepared_digest']
                        or self.history_manifest != self.basis.manifest['manifest_digest']):
                    raise AuthorityUnavailable('actual selected historical lineage does not reach current PREPARED')
                self.phase = 'families'
                return {'status': 'progress', 'phase': 'selected_history_eof'}
        if self.history_frame is None:
            summary = self.history_scan.advance(meter=meter)
            if summary is None:
                return {'status': 'progress', 'phase': 'selected_history_header'}
            if (summary['prior_prepared_digest'] != self.history_prior
                    or self.history_manifest is not None and summary['old_manifest_digest'] != self.history_manifest
                    or (summary['authority_id'], summary['installation_id'], summary['namespace']) !=
                        (self.control.authority_id, self.control.installation_id, self.basis.prepared['namespace'])):
                raise AuthorityUnavailable('actual selected historical signed chain, scope or namespace differs')
            if self.history_generation == 0:
                with self.control._db() as db:
                    genesis = _read_one(db, 'SELECT manifest_digest FROM c09_storage_manifests_v1 '
                        'WHERE installation_id=? AND generation=0', (self.control.installation_id,), meter)
                if genesis != (summary['old_manifest_digest'],):
                    raise AuthorityUnavailable('actual selected historical chain does not start at installed genesis')
            if summary['maintenance_generation'] == through:
                if summary['prepared_digest'] != self.basis.prepared['prepared_digest']:
                    raise AuthorityUnavailable('actual selected last history frame differs from current PREPARED')
                self._adopt_history(summary)
                return {'status': 'progress', 'phase': 'selected_history_current'}
            self.history_frame = (_PriorPagedRecoveryFrameV2(self.history_sink, summary)
                if isinstance(summary, C09VerifiedPagedPreparedSummaryV2) else _LegacyReadonlyFrameV3(self.history_sink, summary))
            return {'status': 'progress', 'phase': 'selected_history_frame'}
        with self.basis.read_database('core', meter=meter) as core, self.basis.read_database('graph', meter=meter) as graph:
            self.history_sink.db = graph
            try:
                frame = self.history_frame
                done = frame.advance(core, graph, meter) if type(frame) is _PriorPagedRecoveryFrameV2 else frame.advance(core, meter)
                if done:
                    summary = frame.summary
                    expected = (self.scope.scope_digest, summary['maintenance_generation'], summary['operation_id'],
                        summary['prepared_digest'], frame.facts_digest, frame.bindings_digest, frame.pin_digest,
                        frame.inventory_digest, summary['new_manifest_digest'])
                    actual = _read_one(graph, 'SELECT scope_digest,generation,operation_id,prepared_digest,facts_digest,'
                        'bindings_digest,pin_digest,inventory_digest,manifest_digest FROM c09_recovery_history_frames_v2 '
                        'WHERE scope_digest=? AND generation=?', expected[:2], meter)
                    if actual != expected:
                        raise AuthorityUnavailable('actual selected retained history frame completion differs')
                    self._adopt_history(summary)
            finally:
                self.history_sink.db = None
        return {'status': 'progress', 'phase': 'selected_history_frame_eof'}

    def _adopt_history(self, summary):
        self.history_generation = summary['maintenance_generation']
        self.history_prior = summary['prepared_digest']
        self.history_manifest = summary['new_manifest_digest']
        self.history_root = canonical_digest(('sylanne3.c09.selected-history-member.v3',
            self.history_root, self.history_generation, self.history_prior, self.history_manifest))
        self.history_scan = self.history_frame = None


def advance_selected_history_read_v3(control):
    from .c09_storage_control_v1 import C09StorageControlV1, InstalledC09StorageReaderV1
    if type(control) not in {C09StorageControlV1, InstalledC09StorageReaderV1}:
        raise AuthorityUnavailable('actual installed selected history entry required')
    control.lease.require_held()
    reader = getattr(control, '_selected_history_builder_v3', None)
    if reader is None:
        reader = InstalledSelectedHistoryBuilderV3(control)
        control._selected_history_builder_v3 = reader
    result = reader.advance()
    if type(result) is VerifiedSelectedHistoryReadV3:
        control._selected_history_read_v3 = result
    return result


_CHECKPOINT_TABLE = 'c09_selected_history_checkpoints_v3'
_CHECKPOINT_DDL = """CREATE TABLE c09_selected_history_checkpoints_v3 (
 selection_digest TEXT NOT NULL,consumer TEXT NOT NULL,step_index INTEGER NOT NULL CHECK(step_index>0),
 operation_id TEXT NOT NULL,pointer_version INTEGER NOT NULL,manifest_digest TEXT NOT NULL,
 prepared_digest TEXT NOT NULL,stage TEXT NOT NULL,previous_checkpoint_digest TEXT NOT NULL,
 checkpoint_json TEXT NOT NULL,checkpoint_digest TEXT NOT NULL UNIQUE,key_id TEXT NOT NULL,signature TEXT NOT NULL,
 PRIMARY KEY(selection_digest,consumer,step_index)) STRICT"""
_CHECKPOINT_SCHEMA = 'sylanne3.c09.selected-history-checkpoint.v3'


def require_selected_history_checkpoint_schema_v3(control, db):
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (_CHECKPOINT_TABLE,)).fetchone()
    if row is None or row[0] != _CHECKPOINT_DDL:
        raise AuthorityUnavailable('actual selected history checkpoint schema differs')
    for action in ('UPDATE', 'DELETE'):
        name = _CHECKPOINT_TABLE + '_no_' + action.lower()
        row = db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone()
        if row is None or row[0] != control._immutable_ddl(_CHECKPOINT_TABLE, action):
            raise AuthorityUnavailable('actual selected history checkpoint immutable trigger differs')


def _install_checkpoint_schema(control, db):
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (_CHECKPOINT_TABLE,)).fetchone() is None:
        db.execute(_CHECKPOINT_DDL)
        for action in ('UPDATE', 'DELETE'):
            db.execute(control._immutable_ddl(_CHECKPOINT_TABLE, action))
    require_selected_history_checkpoint_schema_v3(control, db)


def record_selected_history_checkpoint_v3(basis, *, consumer, details, meter):
    """Append protected continuation metadata; a cursor remains non-authoritative."""
    from .c09_storage_control_v1 import SURFACES
    if type(basis) is not _InstalledSelectedStorageBasisV3 or consumer not in {
            'selected_history', 'model_release', 'execution_cleanup', 'backup_coverage', 'backup_recheck', 'provider_cache',
            *('surface_' + name for name in SURFACES)}:
        raise AuthorityUnavailable('actual installed selected history consumer required')
    current = basis.require_current(meter=meter)
    control = basis.control
    if current['stage'] not in {'SWITCHED', 'CLEANED'}:
        raise AuthorityUnavailable('actual selected history checkpoint requires unfinished cleanup')
    with control._db(write=True) as db:
        pointer = control._c09_control_chain_proof_v2.require_current(db, meter)
        if pointer != current:
            raise AuthorityUnavailable('actual selected history checkpoint pointer CAS changed')
        _install_checkpoint_schema(control, db)
        row = _read_one(db, 'SELECT step_index,checkpoint_json,checkpoint_digest FROM ' + _CHECKPOINT_TABLE +
            ' WHERE selection_digest=? AND consumer=? ORDER BY step_index DESC LIMIT 1',
            (basis.selection_digest, consumer), meter)
        step, prior = (1, 'genesis') if row is None else (row[0] + 1, row[2])
        if row is not None:
            previous = json.loads(row[1])
            control.verify_original_v1(previous, 'checkpoint_digest')
            if previous['checkpoint_digest'] != prior:
                raise AuthorityUnavailable('actual selected history checkpoint predecessor differs')
        body = dict(schema=_CHECKPOINT_SCHEMA, authority_id=control.authority_id,
            installation_id=control.installation_id, control_store_id=control.control_store_id,
            selection_digest=basis.selection_digest, consumer=consumer, step_index=step,
            operation_id=basis.prepared['operation_id'], pointer_version=current['pointer_version'],
            manifest_digest=basis.manifest['manifest_digest'], prepared_digest=basis.prepared['prepared_digest'],
            stage=current['stage'], previous_checkpoint_digest=prior, details=details)
        original = control.sign_original_v1(_CHECKPOINT_SCHEMA, body, 'checkpoint_digest')
        wire = json.dumps(original, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
        meter.require_available(len(wire.encode()) * 8)
        meter.write_row(db, _CHECKPOINT_TABLE, ('selection_digest', 'consumer', 'step_index', 'operation_id',
            'pointer_version', 'manifest_digest', 'prepared_digest', 'stage', 'previous_checkpoint_digest',
            'checkpoint_json', 'checkpoint_digest', 'key_id', 'signature'),
            (basis.selection_digest, consumer, step, basis.prepared['operation_id'], current['pointer_version'],
             basis.manifest['manifest_digest'], basis.prepared['prepared_digest'], current['stage'], prior,
             wire, original['checkpoint_digest'], control.key_id, original['signature']))
        return original


def record_selected_history_completion_v3(view, *, meter):
    if type(view) is not VerifiedSelectedHistoryReadV3:
        raise AuthorityUnavailable('actual complete selected history view required')
    view.require_current(meter=meter)
    return record_selected_history_checkpoint_v3(view.basis, consumer='selected_history', meter=meter,
        details=dict(schema='sylanne3.c09.selected-history-completion.v3',
            history_count=view.history_count, history_root=view.history_root,
            facts_pin_digest=view.completion.pin_digest, family_eof=view.family_eof))


class InstalledSelectedCoverageV3:
    """One authenticated checkpoint or one actual obligation per reservation."""
    def __init__(self, view, consumer):
        if type(view) is not VerifiedSelectedHistoryReadV3 or consumer not in {'execution_cleanup', 'model_release'}:
            raise AuthorityUnavailable('actual selected cleanup coverage consumer required')
        self.view, self.consumer = view, consumer
        self.family = 'executions' if consumer == 'execution_cleanup' else 'model'
        self.step, self.previous, self.restored = 0, 'genesis', False
        self.details = dict(schema='sylanne3.c09.selected-obligation-coverage.v3', family=self.family,
            after_key=None, count=0, root=canonical_digest((consumer, view.basis.selection_digest)),
            eof=False, unknown_present=False, history_count=view.history_count, history_root=view.history_root)
        self.original = None
        self.failed = None

    def advance(self, *, meter):
        if self.failed is not None:
            raise AuthorityUnavailable(self.failed)
        try:
            result = self._advance(meter)
            return result
        except BaseException as exc:
            self.failed = str(exc)
            raise

    def _advance(self, meter):
        view, basis = self.view, self.view.basis
        current = basis.require_current(meter=meter)
        if current['stage'] not in {'SWITCHED', 'CLEANED'}:
            raise AuthorityUnavailable('actual cleanup coverage has no current maintenance admission')
        if not self.restored:
            with basis.control._db() as db:
                exists = _read_one(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (_CHECKPOINT_TABLE,), meter)
                row = None if exists is None else _bounded(db, meter).execute('SELECT step_index,checkpoint_json,checkpoint_digest '
                    'FROM ' + _CHECKPOINT_TABLE + ' WHERE selection_digest=? AND consumer=? AND step_index=?',
                    (basis.selection_digest, self.consumer, self.step + 1)).fetchone()
                if exists is not None:
                    require_selected_history_checkpoint_schema_v3(basis.control, db)
            if row is None:
                self.restored = True
            else:
                original = json.loads(row[1])
                basis.control.verify_original_v1(original, 'checkpoint_digest')
                if (row[0] != self.step + 1 or original['step_index'] != row[0]
                        or original['previous_checkpoint_digest'] != self.previous or original['checkpoint_digest'] != row[2]
                        or original['selection_digest'] != basis.selection_digest or original['consumer'] != self.consumer
                        or original['operation_id'] != basis.prepared['operation_id']
                        or original['pointer_version'] != current['pointer_version']
                        or original['manifest_digest'] != basis.manifest['manifest_digest']
                        or original['prepared_digest'] != basis.prepared['prepared_digest']
                        or original['stage'] not in {'SWITCHED', 'CLEANED'}
                        or original['details']['schema'] != self.details['schema']
                        or original['details']['family'] != self.family
                        or original['details']['history_count'] != view.history_count
                        or original['details']['history_root'] != view.history_root):
                    raise AuthorityUnavailable('actual coverage checkpoint chain or selected scope differs')
                self.step, self.previous = row[0], row[2]
                self.details, self.original = original['details'], original
            return dict(status='progress', phase=self.consumer + '_checkpoint_chain')
        if self.details['eof']:
            if self.details['count'] != view.family_eof[self.family]['record_count']:
                raise AuthorityUnavailable('actual coverage count does not prove the complete sealed family')
            return dict(status='complete', phase=self.consumer, certificate=self.original)
        # One key is selected independently; the body and all its point obligations
        # share this same meter. No accumulated tuple or namespace dictionary exists.
        with basis.read_database('graph', meter=meter) as graph:
            key = _read_one(graph, 'SELECT item_key FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? '
                'AND item_key COLLATE BINARY>? ORDER BY item_key COLLATE BINARY LIMIT 1',
                (view.scope.scope_digest, self.family, self.details['after_key'] or ''), meter)
        details = dict(self.details)
        if key is None:
            if details['count'] != view.family_eof[self.family]['record_count']:
                raise AuthorityUnavailable('actual coverage EOF omits a sealed obligation')
            details['eof'] = True
            details['family_complete_digest'] = view.family_eof[self.family]['complete_digest']
            details['family_eof_digest'] = view.family_eof[self.family]['eof_observation_digest']
        else:
            identity = key[0]
            if self.family == 'executions':
                read = view.read_sanitized_execution_v3(namespace=basis.prepared['namespace'], execution_id=identity, meter=meter)
                if read is None:
                    raise AuthorityUnavailable('actual selected execution coverage disappeared')
                unknown = read.status == 'unknown'
            else:
                read = view.read_sanitized_model_budget_v3(namespace=basis.prepared['namespace'], call_id=identity, meter=meter)
                if read is None:
                    raise AuthorityUnavailable('actual selected model coverage disappeared')
                unknown = (read.provider_state != 'observed' or read.reservation_state not in {'settled', 'overrun'}
                    or any(unit.actual_or_none is None or unit.pending_known or unit.unknown_upper_bound for unit in read.units))
                with basis.read_database('graph', meter=meter) as graph:
                    reservation = _bounded(graph, meter).execute('SELECT digest,ceiling_json,state,actual_json '
                        'FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
                        (read.parent_budget_id, read.reservation_operation_id)).fetchone()
                    if reservation is None or reservation[0] != read.reservation_digest or reservation[2] != read.reservation_state:
                        raise AuthorityUnavailable('actual selected model debt reservation changed or disappeared')
                    ceilings = json.loads(reservation[1])
                    amounts = None if reservation[3] is None else json.loads(reservation[3])
                    if (any(ceilings.get(unit.unit) != unit.ceiling for unit in read.units)
                            or any(unit.actual_or_none is not None and (amounts is None or amounts.get(unit.unit) != unit.actual_or_none)
                                for unit in read.units)):
                        raise AuthorityUnavailable('actual selected model measured dimensions or debt differ')
            details.update(after_key=identity, count=details['count'] + 1,
                root=canonical_digest((details['root'], identity, canonical_digest(read))),
                unknown_present=details['unknown_present'] or unknown)
        original = record_selected_history_checkpoint_v3(basis, consumer=self.consumer, details=details, meter=meter)
        self.step, self.previous, self.details, self.original = original['step_index'], original['checkpoint_digest'], details, original
        return dict(status='progress', phase=self.consumer, verified_count=details['count'], eof=details['eof'])


def advance_selected_obligation_coverage_v3(maintenance, *, view, consumer):
    from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
    from .c09_paged_capture_control_v2 import InstalledC09PagedCaptureControlV2
    if type(maintenance) is not InstalledC09MaintenanceV1 or type(view) is not VerifiedSelectedHistoryReadV3:
        raise AuthorityUnavailable('actual installed cleanup composition required')
    control = getattr(maintenance, '_paged_capture_control_v2', None)
    if control is None:
        control = InstalledC09PagedCaptureControlV2(maintenance)
        maintenance._paged_capture_control_v2 = control
    progresses = getattr(maintenance, '_selected_coverage_v3', None)
    if progresses is None:
        progresses = {}
        maintenance._selected_coverage_v3 = progresses
    progress = progresses.get(consumer)
    if progress is None:
        progress = InstalledSelectedCoverageV3(view, consumer)
        progresses[consumer] = progress
    elif progress.view is not view:
        raise AuthorityUnavailable('actual cleanup coverage selection changed')
    with control.reserve_selected_history_quantum_v2(view) as meter:
        result = progress.advance(meter=meter)
    return result


_PHYSICAL_COMPOSITION_V3 = object()
_MAINTENANCE_SELECTED_V3 = object()


class SelectedPhysicalCompositionV3:
    """Private identity/schema composition, carrying no business or delete permit."""
    def __init__(self, token, view, context):
        if token is not _PHYSICAL_COMPOSITION_V3 or type(view) is not VerifiedSelectedHistoryReadV3:
            raise AuthorityUnavailable('actual complete selected physical composition required')
        self._issuer, self.selected, self.basis, self.context = token, view, view.basis, context
        self.control = view.basis.control

    def require_current(self, *, meter):
        if self._issuer is not _PHYSICAL_COMPOSITION_V3:
            raise AuthorityUnavailable('actual selected physical composition issuer differs')
        current = self.basis.require_current(meter=meter)
        if current['stage'] in {'INTENT', 'PREPARED'}:
            intent = self.control._c09_control_chain_proof_v2.state.get('maintenance_intent')
            if (intent is None or intent['old_manifest_digest'] != self.basis.manifest['manifest_digest']
                    or intent['expected_pointer_version'] != current['pointer_version']
                    or intent['namespace'] != self.basis.prepared['namespace']):
                raise AuthorityUnavailable('actual previous selected cut is not the signed current maintenance source')
        return current

    def require_current_for_maintenance_v3(self, *, meter, context, operation_id):
        from .c09_storage_control_v1 import VerifiedStorageOpenContextV1
        current = self.require_current(meter=meter)
        if (type(context) is not VerifiedStorageOpenContextV1 or context._reader is not self.control
                or context._capability is not self.control._capability
                or context.pointer_version != current['pointer_version']
                or context.manifest_digest != current['current_manifest_digest']
                or context.stage != current['stage'] or current['active_operation_id'] != operation_id
                or current['stage'] not in {'INTENT', 'PREPARED', 'SWITCHED', 'CLEANED'}):
            raise AuthorityUnavailable('actual current installed maintenance context and operation required')
        intent = self.control._c09_control_chain_proof_v2.state.get('maintenance_intent')
        if intent is None or intent['namespace'] != self.basis.prepared['namespace']:
            raise AuthorityUnavailable('actual full authenticated INTENT source scope unavailable')
        if current['stage'] in {'SWITCHED', 'CLEANED'}:
            prepared = self.basis.prepared
            if (prepared['operation_id'] != operation_id or prepared['old_manifest_digest'] != intent['old_manifest_digest']
                    or prepared['expected_pointer_version'] != intent['expected_pointer_version']
                    or prepared['accepted_receipt_digest'] != intent['accepted_receipt_digest']
                    or current['pointer_version'] != intent['expected_pointer_version'] + 1):
                raise AuthorityUnavailable('actual new selected maintenance cut differs from its signed INTENT')
        return MaintenanceSelectedBasisV3(_MAINTENANCE_SELECTED_V3, self, context, operation_id)


class MaintenanceSelectedBasisV3:
    """Actual INTENT relation; executing maintenance still requires Core/delete authority."""
    def __init__(self, token, physical, context, operation_id):
        if token is not _MAINTENANCE_SELECTED_V3 or type(physical) is not SelectedPhysicalCompositionV3:
            raise AuthorityUnavailable('actual private maintenance selected basis required')
        self._issuer, self.physical, self.context, self.operation_id = token, physical, context, operation_id
        self.selected, self.basis = physical.selected, physical.basis

    def require_current(self, *, meter):
        if self._issuer is not _MAINTENANCE_SELECTED_V3:
            raise AuthorityUnavailable('actual maintenance selected basis issuer differs')
        current = self.physical.require_current(meter=meter)
        context = self.physical.control.read_verified_current_storage_v3(meter=meter)
        self.physical.require_current_for_maintenance_v3(meter=meter, context=context, operation_id=self.operation_id)
        return current


def begin_selected_physical_composition_v3(control, *, view, meter):
    if type(view) is not VerifiedSelectedHistoryReadV3 or view.basis.control is not control:
        raise AuthorityUnavailable('actual complete selected V3 physical qualification required')
    view.require_current(meter=meter)
    context = control.read_verified_current_storage_v3(meter=meter)
    physical = SelectedPhysicalCompositionV3(_PHYSICAL_COMPOSITION_V3, view, context)
    physical.require_current(meter=meter)
    return physical
