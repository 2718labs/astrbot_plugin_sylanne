"""Actual frozen-Source labor accounting metadata and retained duration joins."""
from decimal import Decimal
from hashlib import sha256
import json
from weakref import WeakSet
from contextlib import contextmanager
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..runtime.c09_paged_sql_v2 import C09PagedCaptureHold
from ..runtime.d11_character_work_segment_v1 import PREPARED_METADATA_KIND, character_labor_prepared_metadata_from_wire_v1

def require_character_labor_cost_history_v1(session, pair, *, business, core_db, binding, terminal, meter):
    """Compare the actual content-free cost cell and original two-store fence."""
    from hashlib import sha256
    from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from .c09_role_capture_pair_v2 import InstalledC09RolePairV2
    from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
    from .v2_fence_store import AuthorityV2FenceStore
    from .v2_contract import canonical_bytes
    from .v2_contract import from_wire as permit_from_wire
    from ..runtime.d11_life_contract_v1 import life_adoption_operation_id_v1
    from ..runtime.d11_life_preparation_v1 import life_ids_from_binding_v1
    from ..runtime.d11_types import cost_settlement_from_runtime, cost_settlement_graph_write
    from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
    if type(session) is not C09PagedCaptureSessionV2 or type(pair) is not InstalledC09RolePairV2 or pair._producer.session is not session or (pair.source_original.role != 'graph') or (pair.source_original.scope_digest != session.scope.scope_digest) or (type(business) is not _BoundedReadConnectionV2) or (business.db is not pair.source) or (not business.in_transaction) or (not core_db.in_transaction):
        raise C09PagedCaptureHold('actual same-scope frozen Graph/Core cost sources required')
    session.require_current()
    pair.require_current()
    ns = binding.namespace
    operation = life_adoption_operation_id_v1(binding)
    gate_id = 'd11-life-gate:adoption:' + canonical_digest((binding.authority_namespace, binding.installation_id, binding.execution_id))
    fence = AuthorityV2FenceStore._row(core_db, gate_id)
    if fence is None:
        raise C09PagedCaptureHold('labor historical adoption has no actual original Core fence')
    permit = AuthorityV2FenceStore._permit(fence)
    if permit.namespace != binding.authority_namespace or permit.authority_id != binding.authority_id or permit.subject != 'd11-life:' + binding.installation_id or (permit.operation != 'write') or (permit.generation != binding.activation_generation) or (permit.pinned_anchor.execution_journal_id != terminal.journal_id) or (permit.pinned_anchor.execution_seq != terminal.terminal_sequence) or (permit.pinned_anchor.execution_digest != terminal.terminal_digest) or (fence[6] != 'finished') or (fence[10] is not None) or (fence[7] != canonical_bytes(permit)) or (fence[8] != gate_id + ':committed'):
        raise C09PagedCaptureHold('labor historical cost lacks its exact finished original adoption fence')
    graph_fence = business.execute('SELECT permit_json,pre_graph_revision,pre_graph_epoch,post_graph_revision,post_graph_epoch,finish_request_id,finish_request_digest FROM graph_bundle_fences_v2 WHERE bot=? AND persona=? AND operation_id=?', (*ns.as_tuple, operation)).fetchone()
    if graph_fence is None or permit_from_wire(json.loads(graph_fence[0])) != permit or graph_fence[3:5] != (graph_fence[1] + 1, graph_fence[2] + 1) or (graph_fence[5:] != fence[8:10]):
        raise C09PagedCaptureHold('labor historical Graph cost fence differs from actual Core finish')
    from ..runtime.budget import BudgetReceipt, _settlement_binding
    from ..runtime.d10_offline_tick_execution_v1 import _decode_json
    actual = None if terminal.actual_cpu_ms is None else {'thread_cpu_ms': terminal.actual_cpu_ms}
    expected_status = 'pending_confirmation' if actual is None else 'overrun' if terminal.actual_cpu_ms > binding.cpu_ceiling_ms else 'settled'
    immutable = business.execute('SELECT digest,lease_id,receipt_json,resolution_binding_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase=?', (*ns.as_tuple, binding.reservation_operation_id, 'settle')).fetchone()
    if immutable is None or immutable[0:2] != (binding.reservation_digest, binding.parent_budget_lease_ref) or immutable[3] != _settlement_binding(actual, True):
        raise C09PagedCaptureHold('labor adoption cost lost its immutable original usage/revocation settlement')
    receipt = _decode_json(immutable[2], BudgetReceipt)
    if (receipt.operation_id, receipt.digest, receipt.lease_id, receipt.status) != (binding.reservation_operation_id, binding.reservation_digest, binding.parent_budget_lease_ref, expected_status):
        raise C09PagedCaptureHold('labor adoption CPU receipt differs from its actual original terminal')
    ids = life_ids_from_binding_v1(binding)
    cost = cost_settlement_from_runtime(business, bot_id=ns.bot_id, persona_id=ns.persona_id, activity_id=binding.activity_id, bundle_operation_id=operation, effect_id=binding.effect_id, settlement_id=ids['reservation'], lease_id=binding.parent_budget_lease_ref, cost_operation_id=binding.reservation_operation_id, budget_operation_id=binding.reservation_operation_id, budget_phase='settle', prior_unknown_ref=None, execution_revoked=True)
    actual = None if terminal.actual_cpu_ms is None else {'thread_cpu_ms': terminal.actual_cpu_ms}
    if cost.actual != actual or cost.ceiling != {'thread_cpu_ms': binding.cpu_ceiling_ms} or cost.status not in ({'pending_confirmation'} if actual is None else {'settled', 'overrun'}):
        raise C09PagedCaptureHold('labor retained adoption CPU settlement differs from its real terminal')
    write = cost_settlement_graph_write(cost)
    event = business.execute('SELECT revisions,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?', (*ns.as_tuple, binding.activity_id, operation)).fetchone()
    if event is None or event[1] != graph_fence[4]:
        raise C09PagedCaptureHold('labor historical cost has no actual same-adoption event')
    revisions = json.loads(event[0])
    members = [item for item in revisions if item[0] == write.key.token]
    if len(members) != 1 or type(members[0][1]) is not int or members[0][1] < 1:
        raise C09PagedCaptureHold('labor historical cost is not a unique actual event write')
    revision = members[0][1]
    _require_labor_history_value_v1(session, pair, token=write.key.token, revision=revision, expected=canonical_serialize(write.value), event_identity=(*ns.as_tuple, binding.activity_id, operation), meter=meter)
    session.require_current()
    pair.require_current()
    return cost

def _require_labor_history_value_v1(session, pair, *, token, revision, expected, event_identity, meter):
    from hashlib import sha256
    from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
    key = AtomKey.from_token(token)
    if key.type_name not in {'runtime.job', 'runtime.cost_settlement', 'd02.reservation.v1'} or NamespaceId.from_key(key).as_tuple != event_identity[:2]:
        raise C09PagedCaptureHold('exact registered labor job, cost or reservation metadata history required')
    shape = read_c09_table_shape_v2(pair.source, 'graph_history', meter=meter)
    column = 'value_cell_id' if 'value_cell_id' in shape.columns else 'value'
    row = meter.read_fixed_row(pair.source, 'graph_history', (column, 'valid', 'event_bot', 'event_persona', 'event_session', 'event_id'), 'token=? AND revision=?', (token, revision))
    if row is None or row[1:] != (1, *event_identity):
        raise C09PagedCaptureHold('labor cost lacks its actual valid same-event historical member')
    expected = expected.encode('utf-8')
    session._control.require_c09_retained_arena_v3(meter=meter, additional_bytes=len(expected) * 8 + 32768)
    if column == 'value':
        if row[0].encode('utf-8') != expected:
            raise C09PagedCaptureHold('labor original native cost value differs from official runtime settlement')
    else:
        from ..segmented_sql_cell_v1 import GRAPH_REF_DDLS_V3
        ddl = meter.read_fixed_row(pair.source, 'sqlite_master', ('sql',), 'type=? AND name=?', ('table', 'graph_history'))
        if ddl != (GRAPH_REF_DDLS_V3['graph_history'],):
            raise C09PagedCaptureHold('labor cost history physical layout is not its registered Source')
        scope = session.begin_source_physical_read_v3(pair, meter=meter)
        header = scope.read_cell_header_v3(row[0], meter=meter)
        if header[1:3] != ('canonical-json.ascii.v1', token) or header[4] != len(expected) or header[6] != sha256(expected).hexdigest():
            raise C09PagedCaptureHold('labor cost physical source header differs from actual typed settlement')
        meter.require_available(len(expected) * 2 + header[5] * 1024 + 8192)
        offset = 0
        root = canonical_digest(('sylanne3.segmented-cell-genesis.v1', row[0]))
        digest = sha256()
        for ordinal in range(header[5]):
            segment = scope.read_cell_segment_v3(row[0], ordinal, meter=meter)
            if segment is None or segment[0] != offset or segment[1] != expected[offset:offset + len(segment[1])]:
                raise C09PagedCaptureHold('labor complete cost source segment changed')
            digest.update(segment[1])
            root = canonical_digest(('sylanne3.segmented-cell-link.v1', root, row[0], ordinal, offset, len(segment[1]), segment[2]))
            offset += len(segment[1])
        scope.require_cell_eof_v3(row[0], header[5], meter=meter)
        if (offset, digest.hexdigest(), root) != (header[4], header[6], header[7]):
            raise C09PagedCaptureHold('labor original cost complete Source EOF/hash/root differs')
        scope.require_current(meter=meter)

def require_character_labor_membership_history_v1(build, basis, *, meter):
    """Graph lineage headers; complete C bytes are independently streamed at final."""
    _require_history_graph_scope_v1(build)
    from .c09_character_labor_membership_v1 import require_character_labor_C_headers_v1
    require_character_labor_C_headers_v1(build.session, build.pair, basis, meter=meter)

def require_character_labor_body_history_v1(build, body, *, meter):
    from ..domains.d02 import BodyDomain, BodyReservation
    from ..runtime.d04_root_original_store_v1 import _receipt
    from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
    from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2
    _require_history_graph_scope_v1(build)
    build.require_current()
    with legacy_cell_read_transaction_v2(build.pair.source):
        receipt = _receipt(_BoundedReadConnectionV2(build.pair.source, meter), body.namespace, body.body_prepare_operation_id)
        if canonical_digest(receipt) != body.receipt_digest or len(receipt.write_versions) != 1 or receipt.activity_id != body.activity_id or (receipt.effect_id != body.effect_id) or ((receipt.write_versions[0].key.token, receipt.write_versions[0].revision) != (body.reservation_ref, body.reservation_revision)):
            raise C09PagedCaptureHold('labor B lacks its actual unique original reservation receipt')
        reservation = BodyReservation(AtomKey.from_token(body.reservation_ref).name, body.quote.quote_ref, body.effect_id, body.quote.max_energy_cost, body.quote.max_energy_cost)
        write = BodyDomain.reservation_write(body.namespace, body.activity_id, reservation)
        if write.key.token != body.reservation_ref or canonical_digest(write.value) != body.reservation_digest:
            raise C09PagedCaptureHold('labor B original reservation differs from its official initial numeric contract')
        _require_labor_history_value_v1(build.session, build.pair, token=body.reservation_ref, revision=body.reservation_revision, expected=canonical_serialize(write.value), event_identity=(*body.namespace.as_tuple, body.activity_id, body.body_prepare_operation_id), meter=meter)
    build.require_current()

def require_character_labor_plan_history_v1(build, plan, *, producing_operation_id, meter):
    from ..runtime.d04_root_original_store_v1 import _receipt
    from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
    from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2
    ns = NamespaceId.from_key(AtomKey.from_token(plan.input_source.ref))
    _require_history_graph_scope_v1(build)
    build.require_current()
    with legacy_cell_read_transaction_v2(build.pair.source):
        receipt = _receipt(_BoundedReadConnectionV2(build.pair.source, meter), ns, producing_operation_id)
        reads = {v.key.token: v.revision for v in receipt.read_versions}
        if receipt.activity_id != plan.activity_id or receipt.effect_id != plan.effect_id or any((reads.get(getattr(plan, name).ref) != getattr(plan, name).revision for name in ('project', 'recipe', 'action_intent', 'input_source', 'input_access'))):
            raise C09PagedCaptureHold('new labor Plan is outside its actual registration commit/read-set')
    build.require_current()
_LABOR_HISTORY = WeakSet()
_LABOR_HISTORY_TOKEN = object()

class _LaborHistoryPointV1:

    def __init__(self, row, columns):
        self.row = row
        self.description = tuple(((name, None, None, None, None, None, None) for name in columns))

    def fetchone(self):
        row, self.row = (self.row, None)
        return row

class _LaborAccountingHistoryReadV1:
    """Two fixed metadata history queries over an authenticated basis' job/cost."""

    def __init__(self, token, session, pair, basis, db, meter):
        from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
        from .c09_role_capture_pair_v2 import InstalledC09RolePairV2
        from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
        from ..runtime.d11_character_labor_accounting_v1 import read_character_labor_accounting_prepared_v1
        from ..runtime.d11_life_preparation_v1 import life_ids_from_binding_v1
        from ..runtime.d11_types import runtime_job_key, runtime_cost_settlement_key
        if token is not _LABOR_HISTORY_TOKEN or type(session) is not C09PagedCaptureSessionV2 or type(pair) is not InstalledC09RolePairV2 or (pair._producer.session is not session) or (pair.source_original.role != 'graph') or (pair.source_original.scope_digest != session.scope.scope_digest) or (type(db) is not _BoundedReadConnectionV2) or (db.db is not pair.source) or (not db.in_transaction):
            raise C09PagedCaptureHold('actual same-scope labor accounting Source reader required')
        issuer = session.get_c09_domain_original_issuer_v2()
        saved = read_character_labor_accounting_prepared_v1(db, binding=basis_binding_v1(db, basis, issuer), issuer=issuer, resource_issuer=issuer.resource_issuer)
        if saved is None or saved[0] != basis:
            raise C09PagedCaptureHold('labor accounting adapter has no authentic same-Source basis')
        self.session, self.pair, self.basis, self.accounting = (session, pair, *saved)
        self.db, self.meter, self.strings = (db, meter, [])
        b = self.accounting.binding
        self.allowed = frozenset((runtime_job_key(*b.namespace.as_tuple, b.activity_id, b.job_id).token, runtime_cost_settlement_key(*b.namespace.as_tuple, b.activity_id, life_ids_from_binding_v1(b)['reservation']).token))
        self.scope = session.begin_source_physical_read_v3(pair, meter=meter)
        _LABOR_HISTORY.add(self)
        session._source_parser_arena_v3.add(self)

    @property
    def in_transaction(self):
        return self.db.in_transaction

    def _source_heap_bytes(self):
        from ..runtime.c09_logical_source_v3 import _retained_size
        return 8192 + _retained_size((self.basis, self.accounting, self.strings), set())

    def require_current(self):
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        if self not in _LABOR_HISTORY or current_c09_sql_meter_v2() is not self.meter:
            raise C09PagedCaptureHold('labor accounting history left its exact reserved quantum')
        self.session.require_current()
        self.pair.require_current()
        self.scope.require_current(meter=self.meter)

    def execute(self, sql, parameters=()):
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
        text = ' '.join(sql.split()).lower()
        requests = {'select event_id,value,valid from graph_history where token=? and revision=?': ('event_id', 'value', 'valid'), 'select value,valid from graph_history where token=? and revision=?': ('value', 'valid')}
        columns = requests.get(text)
        if columns is None:
            self.require_current()
            return self.db.execute(sql, parameters)
        self.require_current()
        if type(parameters) is not tuple or len(parameters) != 2 or parameters[0] not in self.allowed or (type(parameters[1]) is not int) or (parameters[1] < 1):
            raise C09PagedCaptureHold('labor accounting history query is outside its actual two metadata keys')
        shape = read_c09_table_shape_v2(self.pair.source, 'graph_history', meter=self.meter)
        if 'value_cell_id' not in shape.columns:
            size = self.db.execute('SELECT length(CAST(value AS BLOB)) FROM graph_history WHERE token=? AND revision=?', parameters).fetchone()
            if size is not None:
                self.session._control.require_c09_retained_arena_v3(meter=self.meter, additional_bytes=size[0] * 40 + 32768)
            row = self.db.execute(sql, parameters).fetchone()
            if row is not None:
                value = row[columns.index('value')]
                from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
                parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
                encoded = value.encode('utf-8')
                for offset in range(0, len(encoded), 4096):
                    parser.feed(encoded[offset:offset + 4096], lambda event: None)
                parser.finish()
                parser._emit_callback = None
                self.meter.charge_encode(len(encoded) * 2)
                self.strings.append(value)
            self.require_current()
            return _LaborHistoryPointV1(row, columns)
        from ..segmented_sql_cell_v1 import GRAPH_REF_DDLS_V3
        ddl = self.meter.read_fixed_row(self.pair.source, 'sqlite_master', ('sql',), 'type=? AND name=?', ('table', 'graph_history'))
        if ddl != (GRAPH_REF_DDLS_V3['graph_history'],):
            raise C09PagedCaptureHold('labor metadata history has another physical Source layout')
        physical = tuple(('value_cell_id' if name == 'value' else name for name in columns))
        row = self.meter.read_fixed_row(self.pair.source, 'graph_history', physical, 'token=? AND revision=?', parameters)
        if row is None:
            return _LaborHistoryPointV1(None, columns)
        cell_id = row[columns.index('value')]
        header = self.scope.read_cell_header_v3(cell_id, meter=self.meter)
        if header[1:3] != ('canonical-json.ascii.v1', parameters[0]):
            raise C09PagedCaptureHold('labor metadata cell changed its actual codec/owner')
        size = header[4]
        self.session._control.require_c09_retained_arena_v3(meter=self.meter, additional_bytes=size * 40 + 32768)
        self.meter.require_available(size * 2 + header[5] * 1024 + 8192)
        raw = bytearray()
        digest = sha256()
        root = canonical_digest(('sylanne3.segmented-cell-genesis.v1', cell_id))
        for ordinal in range(header[5]):
            segment = self.scope.read_cell_segment_v3(cell_id, ordinal, meter=self.meter)
            if segment is None or segment[0] != len(raw):
                raise C09PagedCaptureHold('labor metadata history fragments changed')
            digest.update(segment[1])
            root = canonical_digest(('sylanne3.segmented-cell-link.v1', root, cell_id, ordinal, len(raw), len(segment[1]), segment[2]))
            raw.extend(segment[1])
        self.scope.require_cell_eof_v3(cell_id, header[5], meter=self.meter)
        if (len(raw), digest.hexdigest(), root) != (header[4], header[6], header[7]):
            raise C09PagedCaptureHold('labor metadata logical Source EOF/SHA/root differs')
        from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
        for offset in range(0, len(raw), 4096):
            parser.feed(bytes(raw[offset:offset + 4096]), lambda event: None)
        parser.finish()
        parser._emit_callback = None
        self.meter.charge_encode(len(raw) * 2)
        value = raw.decode('ascii')
        self.strings.append(value)
        result = tuple((value if name == 'value' else cell for name, cell in zip(columns, row, strict=True)))
        self.require_current()
        return _LaborHistoryPointV1(result, columns)

def basis_binding_v1(db, basis, issuer):
    from ..runtime.d11_character_labor_accounting_v1 import _signed, _require_accounting
    from ..runtime.d11_life_accounting_v1 import D11LifeAccountingPreparedV1
    from ..runtime.d10_offline_tick_execution_v1 import _decode_json
    saved = _signed(db, basis.namespace, 'accounting_prepared', basis.accounting_ref, issuer)
    if saved is None or saved[2] != basis.accounting_digest:
        raise C09PagedCaptureHold('labor historical basis lost its actual signed accounting predecessor')
    value = _decode_json(canonical_serialize(saved[0]), D11LifeAccountingPreparedV1)
    _require_accounting(basis, value)
    return value.binding

@contextmanager
def character_labor_accounting_history_v1(session, pair, basis, db, meter):
    reader = _LaborAccountingHistoryReadV1(_LABOR_HISTORY_TOKEN, session, pair, basis, db, meter)
    try:
        yield reader
    finally:
        reader.strings.clear()
        _LABOR_HISTORY.discard(reader)

def require_character_labor_cpu_closure_v1(session, pair, *, business, core_db, basis, accounting, terminal, meter):
    """Two exact historical cost producers; neither grants adoption or settles."""
    from ..runtime.d11_life_historical_accounting_v1 import _read_signed, validate_life_historical_accounting_composite_v1
    from .d11_life_historical_accounting_v1 import historical_accounting_from_wire_v1, historical_accounting_operation_id_v1
    from ..runtime.d11_life_contract_v1 import life_adoption_operation_id_v1
    from ..runtime.c09_storage_rebase_contract_v1 import SanitizedD11FactV4
    from .v2_fence_store import AuthorityV2FenceStore
    b = accounting.binding
    historical = _read_signed(business, b, 'historical_accounting_gate', session.get_c09_domain_original_issuer_v2())
    adoption = AuthorityV2FenceStore._row(core_db, 'd11-life-gate:adoption:' + canonical_digest((b.authority_namespace, b.installation_id, b.execution_id)))
    if (historical is None) == (adoption is None):
        raise C09PagedCaptureHold('labor terminal needs one actual immutable CPU closure producer')
    with character_labor_accounting_history_v1(session, pair, basis, business, meter) as reader:
        if historical is None:
            value = require_character_labor_cost_history_v1(session, pair, business=business, core_db=core_db, binding=b, terminal=terminal, meter=meter)
            kind, op, digest = ('original_adoption_cost', life_adoption_operation_id_v1(b), canonical_digest(value))
        else:
            gate = historical_accounting_from_wire_v1(historical)
            receipt = _read_signed(business, b, 'historical_accounting_receipt', session.get_c09_domain_original_issuer_v2())
            if gate.binding != b or gate.claim_digest != terminal.claim.claim_digest or gate.terminal_digest != terminal.terminal_digest or (gate.prepared_digest != basis.prepared_digest) or (gate.accounting_original_digest != basis.accounting_digest) or (gate.status != terminal.status) or (gate.actual_cpu_ms != terminal.actual_cpu_ms) or (receipt is None):
                raise C09PagedCaptureHold('labor historical CPU composite lost its authentic signed originals')
            validate_life_historical_accounting_composite_v1(reader, gate=gate, result=receipt)
            kind, op, digest = ('original_historical_cost', historical_accounting_operation_id_v1(b), canonical_digest(receipt))
    amount = terminal.actual_cpu_ms
    fact = None if amount is None else SanitizedD11FactV4(b.reservation_operation_id, b.parent_budget_lease_ref, b.reservation_operation_id, b.cpu_ceiling_ms, amount, amount, 0, max(0, amount - b.cpu_ceiling_ms), 'thread_cpu_ms')
    budget = business.execute('SELECT digest,lease_id,receipt_json,resolution_binding_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase=?', (*b.namespace.as_tuple, b.reservation_operation_id, 'settle')).fetchone()
    if budget is None or budget[:2] != (b.reservation_digest, b.parent_budget_lease_ref) or budget[3] is None:
        raise C09PagedCaptureHold('labor CPU closure lost its immutable original settle bytes')
    return (fact, dict(kind=kind, operation_id=op, original_digest=digest, fact_digest=None if fact is None else canonical_digest(fact), budget_receipt_sha256=sha256(budget[2].encode('utf-8')).hexdigest(), settlement_binding_sha256=sha256(budget[3].encode('utf-8')).hexdigest()))

def _require_history_graph_scope_v1(build):
    from ..runtime.c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
    from .c09_character_labor_execution_v1 import _FinalLaborGraphHistoryScopeV1
    if type(build) not in {InstalledGraphRebaseBuildV2, _FinalLaborGraphHistoryScopeV1}:
        raise C09PagedCaptureHold('actual Graph capture or private final labor scope required')
    build.require_current()
