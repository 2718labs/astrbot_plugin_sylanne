"""Numeric Owner selectors from actual Core gates and whole signed metadata EOF."""
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from threading import get_ident
from weakref import WeakKeyDictionary
import sqlite3

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_serialize
from ..runtime.d01_ordinary_origin_stream_v3 import OrdinaryOriginMetadataStreamV3
from ..runtime_storage_v3 import (bind_runtime_database_from_control_v3, begin_runtime_storage_operation_v3,
    bind_runtime_storage_operation_v3, finish_runtime_storage_operation_v3, runtime_storage_quantum_v3,
    runtime_storage_v3, _operation)

_ISSUER = object()
_READERS = WeakKeyDictionary()
_TABLES = ('graph_d04_semantic_installations_v3', 'runtime_d11_owner_role_clock_originals_v1')


class _NumericInputControlsV4(OrdinaryOriginMetadataStreamV3):
    def __init__(self, reserve):
        super().__init__(profile='adoption', ensure_ascii=True, reserve=reserve)

    def _retains(self, path):
        return (not path or path[0] == 'mapping_original_refs'
            or path == ('evidence_inputs',) or path[:2] == ('evidence_inputs', 'clock'))

    def _commits(self, path):
        return not path

    def _append_decoded_codepoint(self, codepoint):
        from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        return C09CanonicalJSONStreamV2._append_decoded_codepoint(self, codepoint)


class _NumericPreparedControlsV4(OrdinaryOriginMetadataStreamV3):
    def __init__(self, reserve):
        super().__init__(profile='adoption', ensure_ascii=True, reserve=reserve)
        self.inner = _NumericInputControlsV4(reserve)
        self.inner_bytes = bytearray()

    def _retains(self, path):
        return not path or path[0] in ('binding', 'original_ref', 'schema')

    def _commits(self, path):
        return not path

    def _append_decoded_codepoint(self, codepoint):
        state = self._string
        if state is not None and state['mode'] == 'value' and state['path'] == ('input_payload_json',):
            if codepoint >= 128:
                raise AuthorityUnavailable('numeric frozen input is not its original canonical ASCII JSON')
            self.inner_bytes.append(codepoint)
            if len(self.inner_bytes) == 1024:
                self.flush_inner_v4()
        from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        return C09CanonicalJSONStreamV2._append_decoded_codepoint(self, codepoint)

    def flush_inner_v4(self):
        if self.inner_bytes:
            self.inner.advance_fragment_v3(bytes(self.inner_bytes), self.meter)
            self.inner_bytes.clear()

    def advance_fragment_v3(self, raw, meter):
        result = super().advance_fragment_v3(raw, meter)
        self.meter = meter
        try:
            self.flush_inner_v4()
        finally:
            self.meter = None
        return result


class CurrentNumericOwnerSelectorsMetadataReadV4:
    def __init__(self, issuer, service, binding, permit, *, gate=None, owner=None):
        if issuer is not _ISSUER:
            raise TypeError('actual installed numeric metadata issuer required')
        self.service, self.binding, self.permit = service, binding, permit
        self.namespace, self.gate, self.owner = binding.namespace, gate, owner
        self.thread = get_ident()
        self.db = self.handle = self.operation = self.context = None
        self.anchor = self.owner_head = self.selection_digest = self.stamp = None
        self.columns, self.rows = {}, {}
        self.parser = self.controls = self.prepared_metadata = None
        self.closed, self.in_quantum = False, False
        self.phase = self._capture_core_v4()
        self.deadline_utc = (None if self.phase in ('original','restore') else
            datetime.fromisoformat(binding.deadline_utc.replace('Z', '+00:00')).timestamp())
        core = service.bridge.core
        control = core._c09_storage_reader_v1
        actual = core._runtime_storage_v3
        if actual is None or actual.context._reader is not control:
            raise AuthorityUnavailable('numeric metadata has no actual selected Core/Control binding')
        from .daemon import _bootstrap_control_quantum_v3
        try:
            with _bootstrap_control_quantum_v3(control):
                self.context = control.read_verified_current_storage_v3()
                self.context.require_current('business')
                actual = core._runtime_storage_v3
                if (actual is None or actual.context._reader is not control
                        or (actual.context.manifest_digest, actual.context.pointer_version) !=
                           (self.context.manifest_digest, self.context.pointer_version)):
                    raise AuthorityUnavailable('numeric metadata Core and selected Graph differ')
                member = next(item for item in self.context.manifest['members'] if item['role'] == 'graph')
                if Path(member['resolved_path']).resolve(strict=True) != service.graph_path:
                    raise AuthorityUnavailable('numeric metadata Graph differs from the actual selected member')
                self.db = sqlite3.connect(service.graph_path.as_uri() + '?mode=ro', uri=True, isolation_level=None)
                self.db.execute('PRAGMA query_only=ON')
                self.handle = bind_runtime_database_from_control_v3(self.db, control=control, role='graph')
            if self.handle is None:
                raise AuthorityUnavailable('numeric metadata requires its actual installed segmented Graph')
            self.operation = begin_runtime_storage_operation_v3(self.db, permit.operation_id, self.deadline_utc)
            self.selection_digest = self.operation.selection_digest
            _READERS[self] = (service, binding, permit, gate, owner, self.db, self.operation, self.thread,
                self.handle, self.context, self.selection_digest, self.deadline_utc, self.phase)
            self.operation.register_retained_state_v3(self)
        except BaseException as first:
            try:
                self.release_v4()
            except BaseException as later:
                first.add_note('numeric metadata opening cleanup failed: ' + type(later).__name__)
            raise

    def _capture_core_v4(self):
        from .d04_numeric_service_v3 import AuthorityD04NumericServiceV3
        from .d04_numeric_claim_bridge_v3 import (D04NumericOriginalAppendV3,
            D04NumericAdoptionBridgeV3, numeric_gate_operation_id_v3)
        from .d04_numeric_journal_v3 import read_numeric_rows_locked_v3, numeric_cost_closure_basis_v3
        from .owner_location_read_v3 import _owner_location_actual_service_v3
        from .v2_contract import FencePermitV2
        service, binding, permit = self.service, self.binding, self.permit
        if type(service) is not AuthorityD04NumericServiceV3 or type(permit) is not FencePermitV2:
            raise AuthorityUnavailable('actual installed numeric service and original permit required')
        _owner_location_actual_service_v3(service, 'authority_numeric_location')
        service._binding(binding)
        phases = tuple(phase for phase in ('claim', 'original', 'adoption')
            if permit.operation_id == numeric_gate_operation_id_v3(binding, phase))
        restore_prefix = numeric_gate_operation_id_v3(binding, 'restore') + ':'
        suffix = permit.operation_id[len(restore_prefix):] if permit.operation_id.startswith(restore_prefix) else ''
        if len(suffix) == 16 and all(c in '0123456789abcdef' for c in suffix):
            phases = (*phases, 'restore')
        if len(phases) != 1:
            raise AuthorityUnavailable('numeric metadata permit is not an actual numeric gate')
        phase = phases[0]
        if self.gate is not None:
            if (type(self.gate) not in (D04NumericOriginalAppendV3, D04NumericAdoptionBridgeV3)
                    or self.gate.binding != binding or self.gate.permit != permit or self.owner is None
                    or (type(self.gate) is D04NumericOriginalAppendV3 and
                        (phase != 'original' or not self.gate.content_artifact_permitted))
                    or type(self.gate) is D04NumericAdoptionBridgeV3 and phase != 'adoption'):
                raise AuthorityUnavailable('numeric metadata differs from its actual Owner-qualified bridge')
        bridge = service.bridge
        bridge.core._require(service.credential, 'current', bridge.namespace)
        with service._frozen() as (db, deletion, execution):
            anchor, holder = service._current_anchor_locked(db, deletion, execution,
                action='accounting' if phase == 'original' else 'recovery' if phase == 'restore' else 'business')
            if (anchor.authority_id, anchor.namespace, anchor.activation_generation) != (
                    binding.authority_id, binding.authority_namespace, binding.activation_generation):
                raise AuthorityUnavailable('numeric metadata actual Self/activation changed')
            bridge.fences.validate_fence_locked(db, permit, subject=permit.subject, current_anchor=anchor)
            row = bridge.fences._row(db, permit.operation_id)
            if (row is None or bridge.fences._permit(row) != permit or row[6] != 'active'
                    or row[10] is not None or permit.holder != holder
                    or permit.operation != ('accounting' if phase == 'original' else 'read' if phase == 'restore' else 'write')
                    or permit.generation != binding.activation_generation):
                raise AuthorityUnavailable('numeric metadata original live gate changed')
            _, claim, measurement, claim_row, terminal_row = read_numeric_rows_locked_v3(bridge.journal, binding)
            if phase == 'claim':
                saved, _row = service._gate_locked(db, binding, phase)
                if saved != permit or claim is not None or permit.command_digest is not None:
                    raise AuthorityUnavailable('numeric metadata claim gate has already been consumed')
            else:
                if claim is None:
                    raise AuthorityUnavailable('numeric metadata has no actual consumed CPU claim')
                service._verify_claim(binding, claim)
                if phase == 'original':
                    saved, _row = service._gate_locked(db, binding, phase)
                    from ..runtime_contracts import canonical_digest
                    expected = 'sha256:' + canonical_digest((binding.digest, claim.signature, 'technical-originals'))
                    if saved != permit or permit.command_digest != expected or terminal_row is not None:
                        raise AuthorityUnavailable('numeric metadata accounting gate changed')
                elif phase == 'restore':
                    source, source_row = service._gate_locked(db, binding, 'claim')
                    if (permit.subject != service._subject or permit.command_digest is not None
                            or terminal_row is None or measurement.status != 'completed'
                            or numeric_cost_closure_basis_v3(terminal_row) is not None
                            or source_row[6] != 'finished'
                            or not service._same_location_epoch(source.pinned_anchor, anchor)):
                        raise AuthorityUnavailable('numeric restore metadata has no actual completed/current recovery lineage')
                elif (permit.subject != service._subject or permit.command_digest is not None
                        or terminal_row is None or measurement.status != 'completed'
                        or anchor.execution_seq != terminal_row[0] or anchor.execution_digest != terminal_row[6]
                        or claim_row[0] + 1 != terminal_row[0] or terminal_row[5] != claim_row[6]):
                    raise AuthorityUnavailable('numeric metadata adoption is not its actual consecutive terminal')
            service._require_owner_locked(db, binding, self.owner)
            head = service.owner_tickets.current_migration_head_in_tx(db,
                authority_namespace=binding.authority_namespace)
            if self.anchor is not None and (anchor != self.anchor or head != self.owner_head):
                raise AuthorityUnavailable('numeric metadata actual Core/Owner changed across Graph observation')
            self.anchor, self.owner_head = anchor, head
        return phase

    def _runtime_retained_heap_bytes_v3(self):
        from ..runtime.source_correction_read_v3 import _heap
        parser = self.parser
        parts = None if parser is None else (parser.nodes, parser.metadata, parser.fields,
            parser.scalar, parser.active_hashes, parser.commitments, parser.inner_bytes,
            parser.inner.nodes, parser.inner.metadata, parser.inner.fields, parser.inner.scalar,
            parser.inner.active_hashes, parser.inner.commitments)
        return _heap((self.rows, self.controls, self.prepared_metadata, parts)) + 131072

    def reserve_v4(self, extra=0):
        self.operation.finish_retained_state_growth_v3(self)
        self.operation.reserve_retained_state_growth_v3(self, extra + 65536)

    def fixed_v4(self, meter, table, columns, where, parameters, slot):
        from ..runtime.c09_paged_sql_v2 import _quote
        lengths = self.db.execute('SELECT ' + ','.join('length(CAST(' + _quote(c) + ' AS BLOB))' for c in columns)
            + ' FROM ' + _quote(table) + ' WHERE ' + where + ' LIMIT 1', parameters).fetchone()
        if lengths is None:
            self.rows.pop(slot, None)
            self.operation.refresh_retained_state_v3(self)
            return None
        amount = sum(v or 0 for v in lengths)
        meter.require_available(amount + 256)
        if amount * 12 + 4096 > meter.budget.reserved_arena_bytes:
            raise AuthorityUnavailable('numeric fixed metadata exceeds its actual registered arena')
        self.operation.reserve_retained_state_growth_v3(self, amount * 12 + 4096)
        try:
            self.rows[slot] = meter.read_fixed_row(self.db, table, columns, where, parameters)
            return self.rows[slot]
        finally:
            self.operation.finish_retained_state_growth_v3(self)

    @contextmanager
    def quantum_v4(self):
        self.context.require_current('business')
        if self.db.in_transaction:
            raise AuthorityUnavailable('numeric metadata cannot inherit Graph SQL')
        from ..runtime.role_control_signed_metadata_v4 import bind_numeric_owner_role_originals_v4
        with bind_runtime_storage_operation_v3(self.operation, self.db), runtime_storage_quantum_v3(self.db) as meter:
            self.db.execute('BEGIN')
            self.in_quantum = True
            try:
                with bind_numeric_owner_role_originals_v4(self):
                    epoch = self.fixed_v4(meter, 'graph_epochs', ('revision',),
                        'bot=? AND persona=?', self.namespace.as_tuple, 'epoch')
                    metadata = self.fixed_v4(meter, 'graph_recovery_metadata_v2',
                        ('schema','requirements_json','graph_revision'), 'bot=? AND persona=?',
                        self.namespace.as_tuple, 'recovery')
                    rights = self.fixed_v4(meter, 'graph_authority_epochs', ('access_epoch','delete_epoch'),
                        'bot=? AND persona=?', self.namespace.as_tuple, 'rights')
                    if metadata is None or epoch is None or rights is None:
                        raise AuthorityUnavailable('actual numeric Graph/rights metadata absent')
                    self.handle.require_current(meter)
                    stamp = (metadata, epoch, rights)
                    if self.stamp is None:
                        self.stamp = stamp
                    elif self.stamp != stamp:
                        raise AuthorityUnavailable('numeric Owner metadata Graph stamp changed')
                    yield meter
            finally:
                self.operation.finish_retained_state_growth_v3(self)
                self.in_quantum = False
                self.db.rollback()
        self.context.require_current('business')

    def prepare_v4(self):
        from ..runtime.c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
        self.parser = _NumericPreparedControlsV4(self.reserve_v4)
        self.operation.refresh_retained_state_v3(self)
        where, parameters = 'bot=? AND persona=? AND kind=? AND original_ref=?', (
            *self.namespace.as_tuple, 'numeric_prepared', self.binding.operation_id)
        with self.quantum_v4() as meter:
            original = self.fixed_v4(meter, 'graph_d04_originals_v3',
                ('payload_digest',), where, parameters, 'prepared_header')
            length = self.db.execute('SELECT length(CAST(payload_json AS BLOB)) FROM graph_d04_originals_v3 WHERE ' + where,
                parameters).fetchone()
            meter.charge_read(8 if length is not None else 0)
        if original is None:
            raise AuthorityUnavailable('actual numeric preparation metadata absent')
        offset, total = 0, length[0]
        while offset < total:
            with self.quantum_v4() as meter:
                raw, actual_total, kind = read_legacy_sql_cell_fragment_v2(self.db,
                    table='graph_d04_originals_v3', column='payload_json', where=where,
                    parameters=parameters, start=offset, length=min(1024,total-offset), meter=meter)
                if actual_total != total or kind != 'text':
                    raise AuthorityUnavailable('numeric preparation physical metadata changed')
                self.parser.advance_fragment_v3(raw, meter)
                offset += len(raw)
                self.operation.refresh_retained_state_v3(self)
        with self.quantum_v4() as meter:
            self.reserve_v4()
            projected, _commits, _ranges, fields, outer = self.parser.finish_metadata_v3()
            controls, _commits, _ranges, _fields, inner = self.parser.inner.finish_metadata_v3()
            if (outer.byte_count != total or outer.sha256 != original[0]
                    or inner.sha256 != self.binding.input_digest
                    or fields.get(()) != frozenset(('binding','input_payload_json','quote_payload_json',
                        'reserve_receipt_json','job_payload_json','original_ref','schema'))
                    or projected.get('schema') != 'd04.numeric_prepared_original.v3'
                    or canonical_serialize(projected.get('binding')) != canonical_serialize(asdict(self.binding))
                    or projected.get('original_ref') != self.binding.input_original_ref):
                raise AuthorityUnavailable('numeric preparation canonical EOF/binding/input commitment differs')
            self.controls, self.prepared_metadata = controls, projected
            self.parser = None
            self.operation.refresh_retained_state_v3(self)
        from ..runtime.role_control_signed_metadata_v4 import create_numeric_owner_role_original_column_v4
        for table in _TABLES:
            with self.quantum_v4() as meter:
                header = self.fixed_v4(meter, table, ('revision','signature'), 'bot=? AND persona=? ORDER BY revision DESC',
                    self.namespace.as_tuple, table)
                if header is None:
                    raise AuthorityUnavailable('actual numeric accepting Owner original absent')
                column = create_numeric_owner_role_original_column_v4(self, table=table,
                    revision=header[0], signature=header[1])
                self.columns[table] = column
            while not column.complete:
                with self.quantum_v4() as meter:
                    column.advance(meter)
        return self

    def require_role_original_column_v4(self, *, table, revision, signature):
        require_actual_numeric_owner_selectors_metadata_reader_v4(self, db=self.db)
        column = self.columns.get(table)
        if (table not in _TABLES or column is None or not column.complete
                or column.key != (*self.namespace.as_tuple, revision) or column.signature != signature):
            raise AuthorityUnavailable('numeric signed Owner metadata was not independently completed/current')
        return column

    def read_selectors_v4(self):
        from .current_d04_numeric_prepared_v3 import read_numeric_policy_owner_selectors_v3
        with self.quantum_v4():
            selectors = read_numeric_policy_owner_selectors_v3(self.db, self.binding,
                self.service.budget_issuer, self.controls, now_utc=self.service._clock(), require_current_budget=False)[0]
        return selectors

    def release_v4(self):
        if self.closed:
            return
        self.closed = True
        _READERS.pop(self, None)
        for column in self.columns.values():
            column.release_v4()
        self.columns.clear()
        self.parser = self.controls = self.prepared_metadata = None
        self.rows.clear()
        try:
            if self.operation is not None:
                self.operation.unregister_retained_state_v3(self)
                finish_runtime_storage_operation_v3(self.operation)
        finally:
            try:
                if self.handle is not None:
                    self.handle.close()
            finally:
                if self.db is not None:
                    self.db.close()


def require_actual_numeric_owner_selectors_metadata_reader_v4(reader, *, db):
    if (type(reader) is not CurrentNumericOwnerSelectorsMetadataReadV4
            or _READERS.get(reader) != (reader.service, reader.binding, reader.permit,
                reader.gate, reader.owner, db, reader.operation, reader.thread,
                reader.handle, reader.context, reader.selection_digest, reader.deadline_utc, reader.phase)
            or reader.db is not db or reader.thread != get_ident() or reader.closed
            or not reader.in_quantum or not db.in_transaction
            or reader.operation.closed or runtime_storage_v3(db) is not reader.handle
            or _operation(reader.handle) is not reader.operation
            or reader.operation.selection_digest != reader.selection_digest):
        raise AuthorityUnavailable('actual same-service/current numeric metadata quantum required')
    return reader


@contextmanager
def numeric_owner_selectors_metadata_read_v4(service, binding, *, permit, gate=None, owner=None):
    reader = CurrentNumericOwnerSelectorsMetadataReadV4(_ISSUER, service, binding, permit, gate=gate, owner=owner)
    try:
        reader.prepare_v4()
        reader._capture_core_v4()
        yield reader
        reader._capture_core_v4()
    except BaseException as first:
        try:
            reader.release_v4()
        except BaseException as later:
            first.add_note('numeric metadata cleanup failed: ' + type(later).__name__)
        raise
    else:
        reader.release_v4()
