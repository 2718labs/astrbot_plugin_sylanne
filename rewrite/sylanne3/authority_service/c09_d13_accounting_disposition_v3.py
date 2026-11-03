"""Finite C09 accounting metadata qualification against actual frozen originals."""
from copy import copy, deepcopy
from dataclasses import asdict, fields, is_dataclass
from weakref import WeakSet
import sys

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2, _CanonicalJSONValueBuilderV3
from ..runtime.c09_paged_sql_v2 import (current_c09_sql_meter_v2, legacy_cell_read_transaction_v2,
    read_legacy_sql_cell_fragment_v2, read_c09_table_shape_v2)
from .d13_accounting_metadata_v3 import (ADMISSION_PHASE, TERMINAL_PHASE, D13_ACCOUNTING_PHASES_V3,
    D13AccountingOriginalV3, D13AdmissionAccountingLineageV3, D13TerminalAccountingMetadataV3,
    accounting_original_from_wire_v3, verify_d13_accounting_source_originals_v3)
from .v2_model_egress_contract import ModelEgressIntentV1, ModelAdmissionV2, ModelTerminalReceiptV2, ModelEgressRecoveryV1
from .v2_model_egress_wire import from_wire as model_from_wire
from .v2_contract import FencePermitV2, decode_bytes
from .c09_model_budget_original_v1 import MODEL_COLUMNS, C09ModelBudgetOriginalV1

_ISSUED = WeakSet()


def _heap(value, seen=None):
    if seen is None:
        seen = set()
    if id(value) in seen:
        return 0
    seen.add(id(value))
    amount = sys.getsizeof(value)
    if type(value) in (tuple, list, set, frozenset):
        return amount + sum(_heap(item, seen) for item in value)
    if type(value) is dict:
        return amount + sum(_heap(k, seen) + _heap(v, seen) for k, v in value.items())
    if is_dataclass(value) and not isinstance(value, type):
        return amount + sum(_heap(getattr(value, f.name), seen) for f in fields(value))
    return amount


class _AccountingJSONV3(C09CanonicalJSONStreamV2, _CanonicalJSONValueBuilderV3):
    def __init__(self, owner, phase=None):
        C09CanonicalJSONStreamV2.__init__(self, ensure_ascii=True)
        self.owner, self.phase = owner, phase
        self._initialize_json_value_v3(incremental_retention=False, frozen_object_type=None, frozen_array_type=None)

    def _reserve(self, extra=0):
        self.owner._require_arena(extra + 32768)

    def emit_v3(self, event):
        if self.phase is not None and event.kind == 'key':
            path = event.path
            expected = None
            if len(path) == 1:
                expected = {f.name for f in fields(D13AccountingOriginalV3)}
            elif path[:-1] == ('payload',):
                cls = D13AdmissionAccountingLineageV3 if self.phase == ADMISSION_PHASE else D13TerminalAccountingMetadataV3
                expected = {f.name for f in fields(cls)}
            elif self.phase == ADMISSION_PHASE and path[:-1] == ('payload', 'intent'):
                expected = {f.name for f in fields(ModelEgressIntentV1)}
            elif self.phase == ADMISSION_PHASE and path[:-1] == ('payload', 'admission'):
                expected = {f.name for f in fields(ModelAdmissionV2)}
            elif self.phase == TERMINAL_PHASE and path[:-1] == ('payload', 'terminal_receipt'):
                expected = {f.name for f in fields(ModelTerminalReceiptV2)}
            if expected is not None and event.key not in expected:
                raise AuthorityUnavailable('accounting Source metadata has an unregistered field')
        _CanonicalJSONValueBuilderV3._emit(self, event)

    def copy_for_v3(self, owner):
        base = C09CanonicalJSONStreamV2(ensure_ascii=self.ensure_ascii,
            max_depth=self.max_depth, max_key_bytes=self.max_key_bytes)
        for name in C09CanonicalJSONStreamV2.__slots__:
            setattr(base, name, getattr(self, name))
        cloned = base.copy()
        result = copy(self)
        for name in C09CanonicalJSONStreamV2.__slots__:
            setattr(result, name, getattr(cloned, name))
        result.owner, result.phase = owner, self.phase
        result.nodes, result.value, result.scalar = deepcopy((self.nodes, self.value, self.scalar))
        result.source_members = []
        return result

    def heap_v3(self):
        return _heap((self.nodes, self.value, self.scalar, self.fragment, self._stack,
            self._string, self._number, self._literal, self._active_scalar))


class _MetadataColumnV3:
    """A canonical metadata column; no response/request/frozen column is admitted."""
    _COLUMNS = {
        ('authority_model_egress_v1', 'identity_json'),
        ('authority_model_admissions_v2', 'admission_json'),
        ('authority_model_admissions_v2', 'receipt_json'),
        ('authority_model_egress_observation_status_v1', 'usage_json'),
        ('authority_model_egress_observation_status_v1', 'cost_json'),
    }

    def __init__(self, owner, *, capture=None, table=None, column=None, call_id=None):
        self.owner, self.capture, self.table, self.column, self.call_id = owner, capture, table, column, call_id
        self.offset = 0
        if capture is not None:
            capture.require_complete(owner.builder, capture.shape, capture.key)
            self.total = capture.size
            if self.total > 65536:
                raise AuthorityUnavailable('accounting Source exceeds its actual installed producer metadata bound')
            phase = capture.key[2]
        else:
            if (table, column) not in self._COLUMNS:
                raise AuthorityUnavailable('registered bodyless Model Core metadata column required')
            shape = read_c09_table_shape_v2(owner.builder.pair.source, table, meter=current_c09_sql_meter_v2())
            if shape.columns != MODEL_COLUMNS[table]:
                raise AuthorityUnavailable('accounting Model metadata Source physical schema differs')
            with legacy_cell_read_transaction_v2(owner.builder.pair.source):
                _, self.total, kind = read_legacy_sql_cell_fragment_v2(owner.builder.pair.source,
                    table=table, column=column, where='call_id=?', parameters=(call_id,),
                    start=0, length=0, meter=current_c09_sql_meter_v2())
            if kind != 'text' or self.total < 1:
                raise AuthorityUnavailable('actual Model accounting metadata canonical column absent')
            phase = None
        self.parser = _AccountingJSONV3(owner, phase)
        self.complete = False

    def copy_for_v3(self, owner):
        result = copy(self)
        result.owner = owner
        result.parser = self.parser.copy_for_v3(owner)
        return result

    def advance(self, meter):
        amount = min(4096, self.total - self.offset)
        if self.capture is not None:
            raw = self.capture.read_payload_fragment_v3(start=self.offset, length=amount, meter=meter)
        else:
            with legacy_cell_read_transaction_v2(self.owner.builder.pair.source):
                raw, total, kind = read_legacy_sql_cell_fragment_v2(self.owner.builder.pair.source,
                    table=self.table, column=self.column, where='call_id=?', parameters=(self.call_id,),
                    start=self.offset, length=amount, meter=meter)
            if (kind, total, len(raw)) != ('text', self.total, amount):
                raise AuthorityUnavailable('frozen accounting Model metadata bytes changed')
        self.parser.feed(raw, self.parser.emit_v3)
        self.offset += len(raw)
        if self.offset == self.total:
            eof = self.parser.finish()
            if eof.byte_count != self.total or self.capture is not None and eof.sha256 != self.capture.payload_digest:
                raise AuthorityUnavailable('accounting Source complete canonical SHA/EOF differs')
            self.complete = True
        return self.complete

    @property
    def value(self):
        if not self.complete:
            raise AuthorityUnavailable('accounting metadata original has not reached complete EOF')
        return self.parser.value

    def heap_v3(self):
        return sys.getsizeof(self.__dict__) + self.parser.heap_v3()


class _D13AccountingDispositionReadV3:
    def __init__(self, capture):
        from .c09_authority_storage_rebase_v2 import _D13CoreRowCaptureV3, _InstalledAuthorityRoleBuilderV2
        if (type(capture) is not _D13CoreRowCaptureV3
                or type(capture.builder) is not _InstalledAuthorityRoleBuilderV2
                or capture.shape.table != 'authority_d13_provider_http_bindings_v1'
                or capture.key[2] not in D13_ACCOUNTING_PHASES_V3):
            raise AuthorityUnavailable('actual registered accounting Source capture required')
        capture.require_complete(capture.builder, capture.shape, capture.key)
        self.capture, self.builder = capture, capture.builder
        self.kind, self.phase = 'http', 'sibling'
        self.complete = self.quantum_completed = self.affected = False
        self.sibling_capture = self.column = None
        self.originals, self.metadata, self.actual_facts, self.reference_proofs = {}, {}, {}, {}
        self.counter_operation_id = self.frame_intent_digest = None
        self.generation_call_id = self.execution_id = capture.key[1]
        self.graph_root = canonical_digest(('sylanne3.c09.d13-graph-dispositions.v3', capture.key))
        self.graph_count = self.reference_index = self.metadata_index = 0
        self.references, self.metadata_queue = (), []
        self.model = self.lineage = self.terminal = None
        self.original_permit = self.fence_state = self.finish_request_id = self.finish_digest = None
        self.record = self.intent = self.admission = self.terminal_receipt = None
        self.reason = None
        _ISSUED.add(self)
        self.builder.session._source_parser_arena_v3.add(self)

    def _source_heap_bytes(self):
        seen = set()
        amount = sys.getsizeof(self.__dict__)
        for name, value in self.__dict__.items():
            if name in {'capture', 'builder', 'sibling_capture', 'column'}:
                continue
            amount += _heap(value, seen)
        if self.column is not None:
            amount += self.column.heap_v3()
        return amount

    def _require_arena(self, extra=0):
        meter = current_c09_sql_meter_v2()
        arena = self.builder.session._source_parser_arena_v3
        if sum(item._source_heap_bytes() for item in arena) + extra > meter.budget.reserved_arena_bytes:
            raise AuthorityUnavailable('accounting Source originals exceed the actual reserved metadata arena')

    def copy(self):
        self._require_arena(self._source_heap_bytes())
        result = copy(self)
        result.originals, result.metadata = dict(self.originals), dict(self.metadata)
        result.actual_facts, result.reference_proofs = dict(self.actual_facts), dict(self.reference_proofs)
        result.metadata_queue = list(self.metadata_queue)
        result.quantum_completed = False
        result.column = None if self.column is None else self.column.copy_for_v3(result)
        _ISSUED.add(result)
        self.builder.session._source_parser_arena_v3.add(result)
        return result

    def confirm_quantum_v3(self):
        """Called only by the installed builder's successful reserve callback."""
        if self not in _ISSUED:
            raise AuthorityUnavailable('actual prospective accounting disposition required')
        self.quantum_completed = True
        if self.sibling_capture is not None:
            self.sibling_capture.quantum_completed = True

    def _remember(self, name, original):
        self.actual_facts[name] = None if original is None else canonical_digest(original)

    def _read_fixed(self, table, columns, where, key, meter):
        return meter.read_fixed_row(self.builder.pair.source, table, columns, where, key)

    def _start_column(self, **arguments):
        self.column = _MetadataColumnV3(self, **arguments)

    def _core_metadata(self, meter):
        b, call = self.builder, self.generation_call_id
        ledger = self._read_fixed('authority_model_egress_v1',
            ('call_id', 'operation_id', 'namespace', 'subject', 'state', 'observation_digest'),
            'call_id=?', (call,), meter)
        admission = self._read_fixed('authority_model_admissions_v2',
            ('call_id', 'admission_id', 'report_digest'), 'call_id=?', (call,), meter)
        from .c09_paged_recovery_facts_v2 import _read_one
        terminal_exists = _read_one(b.pair.source,
            'SELECT receipt_json IS NOT NULL FROM authority_model_admissions_v2 WHERE call_id=?',
            (call,), meter)
        if ledger is None or admission is None or terminal_exists is None:
            raise AuthorityUnavailable('accounting Source lacks actual frozen model/admission originals')
        if (ledger[0], ledger[2]) != (call, b.scope.authority_namespace):
            raise AuthorityUnavailable('accounting Model source crosses actual namespace')
        identity = self._read_fixed('authority_model_original_identity_v2',
            MODEL_COLUMNS['authority_model_original_identity_v2'], 'call_id=?', (call,), meter)
        binding = self._read_fixed('authority_model_egress_bindings_v1',
            MODEL_COLUMNS['authority_model_egress_bindings_v1'], 'call_id=?', (call,), meter)
        status = self._read_fixed('authority_model_egress_observation_status_v1',
            ('call_id', 'observation_digest', 'status', 'content_erased'), 'call_id=?', (call,), meter)
        self.metadata.update(ledger=ledger, admission_row=admission, identity=identity, binding=binding, status=status)
        self.metadata_queue = [
            ('intent', 'authority_model_egress_v1', 'identity_json'),
            ('admission', 'authority_model_admissions_v2', 'admission_json')]
        if terminal_exists[0]:
            self.metadata_queue.append(('terminal_receipt', 'authority_model_admissions_v2', 'receipt_json'))
        if status is not None:
            self.metadata_queue.extend((('usage', 'authority_model_egress_observation_status_v1', 'usage_json'),
                ('cost', 'authority_model_egress_observation_status_v1', 'cost_json')))
        self.phase = 'model_columns'

    def _verify_model(self, meter):
        from .d13_core_counter_source_v1 import InstalledD13CounterSourceV1
        from .d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
        from .current_foreground_activity_v1 import InstalledCurrentForegroundActivityV1
        from ..runtime.issuers import D11BudgetJobIssuer
        b = self.builder
        service = b.session.require_installed_d13_counter_service_v1()
        if (type(service) is not InstalledD13CoreCounterServiceV1
                or type(service.source) is not InstalledD13CounterSourceV1
                or type(service.source.observer) is not InstalledCurrentForegroundActivityV1
                or type(service.source.observer.issuer) is not D11BudgetJobIssuer
                or service.namespace != b.session._control.maintenance.namespace_id
                or service.bridge.namespace != b.scope.authority_namespace
                or service.source.observer.installed_bundle.installation_policy.installation_id != b.scope.installation_id):
            raise AuthorityUnavailable('accounting Source requires its actual namespace installed D11 signer')
        self.intent = model_from_wire(self.metadata['intent'], ModelEgressIntentV1)
        self.admission = model_from_wire(self.metadata['admission'], ModelAdmissionV2)
        self.terminal_receipt = (None if 'terminal_receipt' not in self.metadata else
            model_from_wire(self.metadata['terminal_receipt'], ModelTerminalReceiptV2))
        intent, admission = self.intent, self.admission
        ledger, admission_row, status = self.metadata['ledger'], self.metadata['admission_row'], self.metadata['status']
        if (ledger[:4] != (intent.call_id, intent.operation_id, intent.namespace, intent.subject)
                or self.metadata['binding'] != (intent.call_id, intent.operation_id, intent.fence_token)
                or self.metadata['identity'] != (intent.call_id, b.scope.authority_id, b.scope.installation_id,
                    b.scope.authority_namespace, intent.job_id, intent.acquire_operation_id,
                    intent.operation_id, intent.request_digest, intent.binding_digest)
                or admission_row[:2] != (intent.call_id, admission.admission_id)
                or (self.terminal_receipt is None) != (admission_row[2] is None)
                or self.terminal_receipt is not None and self.terminal_receipt.report_digest != admission_row[2]):
            raise AuthorityUnavailable('accounting source has another complete Model identity/admission/receipt join')
        if ledger[4] in {'observed', 'unknown'}:
            if (status is None or status[:3] != (intent.call_id, ledger[5],
                    'completed' if ledger[4] == 'observed' else 'unknown')
                    or type(status[3]) is not int or status[3] not in (0, 1)):
                raise AuthorityUnavailable('actual accounting terminal status differs from frozen Model ledger')
            usage = tuple(tuple(pair) for pair in self.metadata['usage'])
            cost = tuple(tuple(pair) for pair in self.metadata['cost'])
            from .c09_model_budget_original_v1 import UNITS
            if any(name not in UNITS | {'cached_input_tokens'} for name, amount in (*usage, *cost)):
                raise AuthorityUnavailable('accounting captured usage/cost has another official dimension')
        else:
            if ledger[4] not in {'prepared', 'dispatch_started'} or ledger[5] is not None or status is not None:
                raise AuthorityUnavailable('unobserved Model has fabricated terminal accounting status')
            usage, cost = (), ()
        self.record = ModelEgressRecoveryV1(intent, ledger[4], ledger[5], usage, cost, bool(status[3]) if status else False)
        fence = self._read_fixed('authority_v2_fences',
            ('namespace', 'subject', 'token', 'fence_epoch', 'revision', 'state', 'permit',
             'finish_request_id', 'finish_request_digest', 'pending'),
            'operation_id=?', (intent.operation_id,), meter)
        if fence is None:
            raise AuthorityUnavailable('accounting Source actual original model fence is absent')
        self.original_permit = decode_bytes(fence[6])
        if (type(self.original_permit) is not FencePermitV2 or fence[:5] != (
                intent.namespace, intent.subject, intent.fence_token, intent.fence_epoch, intent.fence_revision)
                or fence[9] is not None and self.terminal_receipt is not None):
            raise AuthorityUnavailable('accounting Source original model fence physical metadata differs')
        self.fence_state, self.finish_request_id, self.finish_digest = fence[5], fence[7], fence[8]
        self.lineage, self.terminal = verify_d13_accounting_source_originals_v3(
            self.originals[ADMISSION_PHASE], self.originals.get(TERMINAL_PHASE),
            signer=service.source.observer.issuer._signer, namespace=service.namespace,
            authority_namespace=b.scope.authority_namespace, authority_id=b.scope.authority_id,
            installation_id=b.scope.installation_id,
            manifest_digest=service.source.observer.installed_bundle.installation_policy.manifest_digest,
            intent=intent, admission=admission, record=self.record, terminal_receipt=self.terminal_receipt,
            original_permit=self.original_permit, fence_state=self.fence_state,
            finish_request_id=self.finish_request_id, finish_digest=self.finish_digest)
        self.references = tuple(sorted(set((*intent.source_revisions, *intent.access_revisions))))
        if not self.references:
            raise AuthorityUnavailable('accounting lineage has no exact original Source/Access closure')
        self._remember('lineage_original', self.originals[ADMISSION_PHASE])
        self._remember('terminal_original', self.originals.get(TERMINAL_PHASE))
        self._remember('model_intent', intent)
        self._remember('model_admission', admission)
        self._remember('model_terminal_receipt', self.terminal_receipt)
        self._remember('model_fence', (self.original_permit, self.fence_state,
            self.finish_request_id, self.finish_digest))
        self.phase = 'graph_dispositions'

    def _graph_disposition(self, meter):
        from .c09_authority_storage_rebase_v2 import _table_shape
        graph = self.builder.session.require_actual_post_mirror_graph_v3()
        graph.require_current()
        if self.reference_index == len(self.references):
            self.phase = 'facts'
            return
        token, revision = self.references[self.reference_index]
        physical = _table_shape(graph.pair.source, 'graph_history')
        key = token, revision
        disposition = (graph.require_original_disposition_row_v3('graph_history', key, meter=meter)
            if 'value_cell_id' in physical.columns else
            self.builder.basis._graph_disposition_key_v3(graph, physical, key, meter))
        commitment = canonical_digest(disposition)
        self.reference_proofs[key] = commitment
        self.graph_root = canonical_digest((self.graph_root, self.graph_count + 1, key, commitment))
        self.graph_count += 1
        self.reference_index += 1
        if disposition.disposition in {'payload_erased_retained_facts', 'derived_removed', 'rebuilt_from_surviving_sources'}:
            self.affected = True
        elif disposition.disposition not in {'preserved_exact', 'logical_preserved_v3'}:
            raise AuthorityUnavailable('accounting Source dependency has no actual preserved/erased/rebuilt disposition')

    def _facts(self, meter):
        b = self.builder
        facts = b.transform.facts
        facts.require_complete(scope_digest=b.scope.scope_digest, facts_pin_digest=facts._completion.pin_digest)
        model = facts.lookup_model_original(self.generation_call_id, meter=meter)
        if type(model) is not C09ModelBudgetOriginalV1:
            raise AuthorityUnavailable('accounting Source lacks complete original model cost/obligation facts')
        intent = self.intent
        if (model.authority_id, model.installation_id, model.namespace, model.model_operation_id,
                model.call_id, model.job_id, model.acquire_operation_id, model.request_digest, model.binding_digest,
                model.parent_budget_id, model.reservation_operation_id, model.reservation_digest,
                model.admission_id_or_none, model.observation_digest_or_none, model.provider_state) != (
                b.scope.authority_id, b.scope.installation_id, b.scope.authority_namespace, intent.operation_id,
                intent.call_id, intent.job_id, intent.acquire_operation_id, intent.request_digest, intent.binding_digest,
                intent.budget_lease_id, intent.budget_reservation_operation_id, intent.budget_reservation_digest,
                self.admission.admission_id, self.record.observation_digest, self.record.state):
            raise AuthorityUnavailable('accounting original cost/parent reservation/terminal lineage differs')
        b.transform._verify_model(model, meter)
        execution = facts.lookup_execution(intent.call_id, meter=meter)
        binding = facts.lookup_execution_binding(intent.call_id, meter=meter)
        if execution is None or binding is None or binding.execution_kind != 'model':
            raise AuthorityUnavailable('accounting model execution/binding original unavailable')
        self._remember('model_budget', model)
        self._remember('model_execution', execution)
        self._remember('model_binding', binding)
        if self.record.state == 'observed':
            if self.terminal is None or execution.status not in {'completed', 'failed'} or not execution.consumed:
                raise AuthorityUnavailable('accounting terminal has no complete consumed model execution original')
            self.reason = 'source_revoked_terminal'
        elif self.record.state in {'dispatch_started', 'unknown'}:
            unknown = facts.lookup_unknown(intent.call_id, meter=meter)
            if unknown is None or unknown.execution_id != intent.call_id or execution.status != 'unknown':
                raise AuthorityUnavailable('accounting unknown original lost its retained upper bound')
            self._remember('model_unknown', unknown)
            self.reason = 'source_revoked_unknown_obligation'
        else:
            from .c09_paged_recovery_facts_v2 import _read_one
            entry = _read_one(facts._db,
                'SELECT seq FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND execution_id=? LIMIT 1',
                (b.scope.scope_digest, intent.call_id), meter)
            observed = self._read_fixed('authority_model_egress_observations_v1', ('call_id',),
                'call_id=?', (intent.call_id,), meter)
            if (self.record.state != 'prepared' or model.provider_state != 'prepared'
                    or execution.status != 'pending' or entry is not None or observed is not None
                    or self.terminal_receipt is not None or self.metadata['status'] is not None
                    or not facts._completion.journal_stream.complete or not facts._completion.model_stream.complete):
                raise AuthorityUnavailable('accounting uncompleted model needs its actual terminal/unknown footprint')
            self._remember('never_started_complete_journal', facts._completion.journal_stream)
            self._remember('never_started_complete_model', facts._completion.model_stream)
            self.reason = 'source_revoked_never_started'
        self.model = model
        self.complete, self.phase = True, 'complete'

    def advance(self, budget, meter):
        from .c09_authority_storage_rebase_v2 import _D13CoreRowCaptureV3, _table_shape
        b = self.builder
        self.capture.require_complete(b, self.capture.shape, self.capture.key)
        result = self.copy()
        if result.phase == 'sibling':
            sibling = TERMINAL_PHASE if result.capture.key[2] == ADMISSION_PHASE else ADMISSION_PHASE
            key = (*result.capture.key[:2], sibling)
            row = result._read_fixed(result.capture.shape.table, ('payload_digest',),
                'namespace=? AND call_id=? AND phase=?', key, meter)
            if row is None:
                if sibling == ADMISSION_PHASE:
                    raise AuthorityUnavailable('orphan accounting terminal cannot manufacture admission lineage')
                result.phase = 'capture_parse'
            else:
                result.sibling_capture = _D13CoreRowCaptureV3(b,
                    _table_shape(b.pair.source, result.capture.shape.table), key, budget, meter)
                result.phase = 'sibling_bytes'
        elif result.phase == 'sibling_bytes':
            if not (result.sibling_capture.complete and result.sibling_capture.quantum_completed):
                result.sibling_capture = result.sibling_capture.next_quantum(budget, meter)
            else:
                result.phase = 'capture_parse'
        elif result.phase in {'capture_parse', 'sibling_parse'}:
            capture = result.capture if result.phase == 'capture_parse' else result.sibling_capture
            if result.column is None:
                result._start_column(capture=capture)
            elif result.column.advance(meter):
                original = accounting_original_from_wire_v3(result.column.value)
                if original.phase != capture.key[2]:
                    raise AuthorityUnavailable('accounting original phase differs from actual frozen SQL key')
                result.originals[original.phase] = original
                result.column = None
                result.phase = ('sibling_parse' if result.phase == 'capture_parse'
                    and result.sibling_capture is not None else 'core_metadata')
        elif result.phase == 'core_metadata':
            result._core_metadata(meter)
        elif result.phase == 'model_columns':
            if result.column is None:
                if result.metadata_queue:
                    name, table, column = result.metadata_queue[0]
                    result._start_column(table=table, column=column, call_id=result.generation_call_id)
                else:
                    result.phase = 'verify_model'
            elif result.column.advance(meter):
                name, _, _ = result.metadata_queue.pop(0)
                result.metadata[name] = result.column.value
                result.column = None
        elif result.phase == 'verify_model':
            result._verify_model(meter)
        elif result.phase == 'graph_dispositions':
            result._graph_disposition(meter)
        elif result.phase == 'facts':
            result._facts(meter)
        b.require_current()
        result._require_arena()
        return result

    def require_accounting_retirement_body_v3(self, builder, *, meter):
        from .c09_d13_source_retirement_v3 import ACCOUNTING_SCHEMA
        from .c09_authority_storage_rebase_v2 import _stream
        if (self not in _ISSUED or self.builder is not builder or not self.complete
                or not self.quantum_completed or not self.affected):
            raise AuthorityUnavailable('actual completed affected accounting Source disposition required')
        capture = self.capture
        physical = capture.require_complete(builder, capture.shape, capture.key)
        logical = capture.logical_original
        descriptor = logical.descriptor_digest if logical is not None else canonical_digest((
            'sylanne3.c09.complete-legacy-core-phase.v3', capture.shape.schema_digest,
            capture.key, physical, capture.payload_digest))
        member = header = origin = None
        if logical is not None:
            from ..runtime.c09_paged_sql_v2 import require_c09_logical_source_row_member_v3
            stream = _stream(builder.pair, builder.scope, capture.logical_shape, 'source_originals_v3')
            row = meter.read_fixed_row(builder.pair.candidate, 'c09_capture_members_v2', ('record_ordinal',),
                'stream_id=? AND key_digest=?', (stream.stream_id, canonical_digest(capture.key)))
            if row is None:
                raise AuthorityUnavailable('accounting retirement lacks its actual captured Source member')
            require_c09_logical_source_row_member_v3(builder.pair.candidate, stream, role='core',
                table_name=capture.shape.table, key=capture.key, record_ordinal=row[0], meter=meter)
            member = dict(stream_id=stream.stream_id, record_ordinal=row[0], table_name=capture.shape.table,
                primary_key=list(capture.key), descriptor_digest=logical.descriptor_digest)
            header = capture.source_scope.read_cell_header_v3(capture.payload_cell_id, meter=meter)
            origin = header[8]
        return dict(schema=ACCOUNTING_SCHEMA, authority_id=builder.scope.authority_id,
            installation_id=builder.scope.installation_id, namespace=builder.scope.authority_namespace,
            maintenance_operation_id=builder.scope.operation_id, scope_digest=builder.scope.scope_digest,
            source_role_digest=builder.pair.source_original.role_source_digest,
            source_table=capture.shape.table, source_primary_key=list(capture.key),
            physical_schema_digest=capture.shape.schema_digest,
            logical_shape_digest=None if logical is None else capture.logical_shape.logical_shape_digest,
            source_descriptor_digest=descriptor, source_physical_row_commitment=physical,
            source_logical_row_commitment=None if logical is None else logical.logical_row_commitment,
            source_payload_digest=capture.payload_digest, source_payload_origin_scope_digest=origin,
            source_cell_header=None if header is None else list(header), source_member=member,
            kind='http', item_id=self.generation_call_id, phase=capture.key[2], counter_operation_id=None,
            frame_intent_digest=None, generation_call_id=self.generation_call_id, execution_id=self.execution_id,
            graph_disposition_root=self.graph_root, graph_disposition_count=self.graph_count,
            facts_pin_digest=builder.transform.completion.pin_digest, actual_facts=dict(self.actual_facts),
            pending_obligations=[], retirement_reason=self.reason,
            lineage_original_digest=canonical_digest(self.originals[ADMISSION_PHASE]),
            terminal_original_digest=None if TERMINAL_PHASE not in self.originals else canonical_digest(self.originals[TERMINAL_PHASE]),
            model_intent_digest=canonical_digest(asdict(self.intent)),
            model_admission_digest=canonical_digest(asdict(self.admission)),
            model_terminal_receipt_digest=None if self.terminal_receipt is None else canonical_digest(asdict(self.terminal_receipt)))
