"""One named metadata READ joins actual foreground HTTP use to original prep charges."""
from dataclasses import dataclass, fields, is_dataclass, asdict
from sys import getsizeof
from time import monotonic_ns
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable, identifier
from ..authority_service.d13_accounting_metadata_v3 import (D13CoreAccountingReadV3,
    ADMISSION_PHASE, TERMINAL_PHASE, verify_d13_accounting_original_v3)
from ..runtime_contracts import NamespaceId, FenceScope, canonical_digest
from ..graph_worker import (GraphStorageStepV3, create_graph_storage_work_v3,
    require_graph_storage_work_admission_v3)
from ..runtime_storage_v3 import (runtime_storage_v3, runtime_source_identity_v4,
    begin_runtime_storage_operation_v3, bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3, runtime_storage_quantum_v3,
    )
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .model_cost_settlement import original_model_cost_operation_id_v1
from .d11_types import RuntimeCostSettlement
from .budget import BudgetReceipt
from .d02_fixed_policy_read_v3 import _D02MetadataReadsV3

KIND = 'd13_accounting_diagnostic_v3'
_READERS = WeakKeyDictionary()
_PROOFS = WeakKeyDictionary()
_ISSUER = object()


@dataclass(frozen=True, slots=True)
class D13CallAccountingDiagnosticV3:
    call_id: str
    role: str
    terminal_state: str
    projection_status: str
    input_tokens: int | None
    output_tokens: int | None
    cached_input_tokens: int | None
    cache_write_tokens: int | None
    reported_model_microusd: int | None
    final_billed_microusd: int | None
    cache_storage_microusd: int | None
    billing_evidence_kind: str | None
    currency: str | None
    unit: str | None
    terminal_receipt_digest: str | None
    billing_receipt_ref: str | None
    c5_status: str
    c5_receipt_digest: str | None
    actual_http_use: str
    prep_charge_semantics: str = 'historical_original_call_cost_not_new_window_charge'
    token_semantics: str = 'provider_reported_not_exact'


@dataclass(frozen=True, slots=True)
class D13WindowCapacityDiagnosticV3:
    collection_digest: str | None
    collection_snapshot_commitment: str | None
    counter_evidence_digest: str | None
    raw_full_wire_token_bounds: tuple[int, int] | None
    compressed_full_wire_token_bounds: tuple[int, int] | None
    token_evidence: str | None
    raw_http_bytes: int | None
    compressed_http_bytes: int | None
    captured_http_bytes: int | None
    selected_paid_block_count: int | None
    representation_evidence_status: str
    store_occupancy_status: str = 'outside_this_http_diagnostic_scope'
    http_capture_semantics: str = 'designated_adapter_before_send_not_provider_delivery'


@dataclass(frozen=True, slots=True)
class D13WindowAccountingDiagnosticV3:
    namespace: NamespaceId
    foreground_call_id: str
    included_call_ids: tuple[str, ...]
    calls: tuple[D13CallAccountingDiagnosticV3, ...]
    actual_http_selection: str
    counter_operation_id: str | None
    frame_intent_digest: str | None
    known_billed_subtotals: tuple[tuple[str, str, str, int], ...]
    unknown_billing_call_count: int
    known_unused_prep_billed_subtotals: tuple[tuple[str, str, str, int], ...]
    unknown_unused_prep_billing_call_count: int
    legacy_single_prep_accounting: object | None
    capacity: D13WindowCapacityDiagnosticV3
    scope: str = 'actual_foreground_generation_http'
    excluded_scope: tuple[str, ...] = ('natural_review', 'other_conversation_calls',
        'counterfactual_token_or_cost_savings')
    schema: str = 'sylanne3.d13.window-accounting-diagnostic.v3'


def _heap(value, seen=None):
    if seen is None:
        seen = set()
    if id(value) in seen:
        return 0
    seen.add(id(value))
    size = getsizeof(value)
    if is_dataclass(value):
        return size + sum(_heap(getattr(value, f.name), seen) for f in fields(value))
    if type(value) is dict:
        return size + sum(_heap(k, seen) + _heap(v, seen) for k, v in value.items())
    if type(value) in (tuple, list):
        return size + sum(_heap(v, seen) for v in value)
    return size


class _DiagnosticColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self, owner, **args):
        super().__init__(owner, **args)
        if self.cell is not None:
            from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
            if self.cell.header[0] not in ('canonical-json.ascii.v1', 'canonical-json.utf8.v1'):
                raise AuthorityUnavailable('D13 diagnostic original has another JSON codec')
            self.parser = C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0] == 'canonical-json.ascii.v1')

    def _emit(self, event):
        if event.kind == 'key' and len(event.path) == 1:
            if self.table == 'graph_bundle_operations':
                allowed = {'original_model_cost', 'original_intent_digest', 'terminal_receipt_digest',
                    'quote_id', 'quote_version', 'work_kind', 'accounting_attempt_id', 'model_reported_usage_v1'}
            elif self.table == 'graph_d13_paid_cost_receipts_v1':
                allowed = {'schema', 'evidence_digest', 'receipt', 'cost_write'}
            elif self.table == 'graph_history':
                allowed = {field.name for field in fields(RuntimeCostSettlement)}
            elif self.table == 'runtime_budget_operations':
                allowed = {field.name for field in fields(BudgetReceipt)}
            else:
                allowed = None
            if allowed is not None and event.key not in allowed:
                raise AuthorityUnavailable('D13 diagnostic metadata column has an unregistered field')
        return super()._emit(event)


class _D13AccountingDiagnosticReadV3:
    def __init__(self, graph, bootstrap, namespace, call_id):
        require_graph_storage_work_admission_v3(graph)
        graph._admin(bootstrap)
        if type(namespace) is not NamespaceId:
            raise AuthorityUnavailable('diagnostic requires the actual selected namespace')
        identifier(call_id, 'foreground_call_id')
        self.graph, self.bootstrap, self.namespace, self.foreground_call_id = graph, bootstrap, namespace, call_id
        self.store = graph._GraphCoordinator__store
        self.db, self.port = self.store._db, graph._GraphCoordinator__content_fence_v2
        self.storage = runtime_storage_v3(self.db)
        if self.storage is None or self.storage.purpose != 'business':
            raise AuthorityUnavailable('D13 diagnostic requires actual installed ordinary runtime storage')
        self.operation = self.scope = self.work = self.metadata_reads = None
        self.read_finished = self.complete = self.closed = False
        self.core_reads, self.points, self.columns, self.queue, self.paid_locators = {}, {}, {}, [], {}
        self.pending_calls, self.c5, self.result, self.proof = [call_id], {}, None, None
        self.metadata_calls = []
        self.column = None
        self.phase = 'foreground'
        with self.store._lock, self.storage.quantum():
            if self.db.in_transaction:
                raise AuthorityUnavailable('D13 diagnostic cannot inherit a Graph transaction')
            self.graph_stamp = graph._v2_graph_stamp(namespace)
        target = self.graph_stamp[0].requirements
        anchor = self.port.current_anchor(namespace=namespace, authority_namespace=target.authority_namespace)
        if not graph._accounting_anchor_covers(target, anchor):
            raise AuthorityUnavailable('D13 diagnostic current Authority anchor differs')
        operation_id = KIND + ':' + canonical_digest((namespace, call_id, monotonic_ns()))[:48]
        try:
            permit = self.port.begin_fence(namespace=namespace, authority_namespace=target.authority_namespace,
                holder=graph._GraphCoordinator__holder, generation=target.activation_generation,
                operation='read', operation_id=operation_id, expected_anchor=anchor, retain_on_unknown=True)
            self.scope = FenceScope(namespace, target.authority_namespace, target.activation_generation,
                'read', operation_id, permit, anchor, self.graph_stamp[1], self.graph_stamp[0].graph_revision)
            self.operation = begin_runtime_storage_operation_v3(self.db, operation_id, None)
            self.selection_digest = self.operation.selection_digest
            self.metadata_reads = _D02MetadataReadsV3(self.operation, self.db)
            self.operation.register_retained_state_v3(self)
            _READERS[self] = self.identity()
        except BaseException as first:
            if self.scope is not None:
                try:
                    self.finish_fence_v3()
                except BaseException as later:
                    if later is not first:
                        first.add_note('D13 diagnostic constructor READ cleanup failed: '+type(later).__name__)
            if self.metadata_reads is not None:
                try:
                    self.metadata_reads.release()
                except BaseException as later:
                    if later is not first:
                        first.add_note('D13 diagnostic constructor metadata release failed: '+type(later).__name__)
            if self.operation is not None:
                try:
                    finish_runtime_storage_operation_v3(self.operation)
                except BaseException as later:
                    if later is not first:
                        first.add_note('D13 diagnostic constructor operation release failed: '+type(later).__name__)
            raise

    def identity(self):
        return (self.graph, self.bootstrap, self.namespace, self.foreground_call_id,
            self.operation, self.scope, self.graph_stamp)

    def _runtime_retained_heap_bytes_v3(self):
        return getsizeof(self) + getsizeof(self.__dict__) + _heap((self.core_reads, self.points,
            self.columns, self.queue, self.paid_locators, self.pending_calls, self.metadata_calls, self.c5, self.result))

    def require_current_v3(self, meter=None):
        if (_READERS.get(self) != self.identity() or self.closed or self.operation.closed
                or self.work is None or self.work.state is not self or self.work.coordinator is not self.graph
                or self.work.operation is not self.operation or self.work.kind != KIND
                or runtime_storage_v3(self.db) is not self.operation.handle):
            raise AuthorityUnavailable('D13 diagnostic lost its exact Work/operation/retention')
        self.work._require_invocation(self.graph)
        self.graph._admin(self.bootstrap)
        with self.store._lock, runtime_storage_quantum_v3(self.db):
            if self.graph._v2_graph_stamp(self.namespace) != self.graph_stamp:
                raise AuthorityUnavailable('D13 diagnostic current Graph metadata changed')
        if meter is not None:
            if runtime_source_identity_v4(self.operation.handle, meter=meter).selection_digest != self.selection_digest:
                raise AuthorityUnavailable('D13 diagnostic changed actual selected source')
            for (table, columns, where, key), expected in self.points.items():
                actual = self.metadata_reads.fixed(meter, table, columns, where, key)
                if actual != expected:
                    raise AuthorityUnavailable('D13 diagnostic original metadata changed')
        return self

    def point(self, meter, table, columns, where, key):
        selector = table, tuple(columns), where, tuple(key)
        actual = self.metadata_reads.fixed(meter, *selector)
        if selector in self.points and self.points[selector] != actual:
            raise AuthorityUnavailable('D13 diagnostic immutable point conflicts')
        self.points[selector] = actual
        return actual

    def enqueue(self, tag, table, column, keys, key, cell_id=None):
        self.queue.append((tag, table, column, tuple(keys), tuple(key), cell_id))

    def outside_sql_v3(self):
        self.require_current_v3()
        if self.db.in_transaction:
            raise AuthorityUnavailable('D13 diagnostic Core lookup must precede Graph SQL')
        if not self.pending_calls:
            return
        call_id = self.pending_calls[0]
        self.operation.reserve_retained_state_growth_v3(self, 1048576)
        try:
            value = self.port.read_d13_model_accounting_metadata_v3(namespace=self.namespace,
                authority_namespace=self.scope.authority_namespace, call_id=call_id)
            if (type(value) is not D13CoreAccountingReadV3 or value.namespace != self.namespace
                    or value.record.intent.call_id != call_id
                    or value.record.intent.namespace != self.scope.authority_namespace):
                raise AuthorityUnavailable('D13 diagnostic Core metadata crossed actual requested call')
            self.core_reads[call_id] = value
            self.pending_calls.pop(0)
        finally:
            self.operation.finish_retained_state_growth_v3(self)

    def _locate_preps(self, meter):
        foreground = self.core_reads[self.foreground_call_id]
        frame = foreground.frame
        if frame is not None:
            if frame.generation_call_id != self.foreground_call_id or frame.namespace != self.namespace:
                raise AuthorityUnavailable('diagnostic paid bindings cross actual foreground frame')
            for binding in frame.block_bindings:
                row = self.point(meter, 'graph_d13_paid_intent_originals_v1', ('job_ref', 'original_digest'),
                    'bot=? AND persona=? AND operation_id=?', (*self.namespace.as_tuple, binding.paid_original_ref))
                if row is None or row[1] != binding.paid_original_digest:
                    raise AuthorityUnavailable('signed foreground binding lacks its exact paid original metadata')
                call = self.point(meter, 'graph_d13_paid_call_originals_v1', ('call_id', 'original_digest'),
                    'bot=? AND persona=? AND job_ref=?', (*self.namespace.as_tuple, row[0]))
                if call is None:
                    raise AuthorityUnavailable('selected paid original has no actual call original')
                locator = row[0], binding.paid_original_ref, binding.paid_original_digest, call[1]
                if call[0] in self.paid_locators and self.paid_locators[call[0]] != locator:
                    raise AuthorityUnavailable('same paid call has conflicting selected original metadata')
                self.paid_locators[call[0]] = locator
            if self.foreground_call_id in self.paid_locators or len(self.paid_locators) > 4:
                raise AuthorityUnavailable('D13 diagnostic exceeds its exact distinct foreground/prep cohort')
        self.pending_calls.extend(self.paid_locators)
        self.phase = 'core_preps'

    def _plan_metadata(self, meter):
        if not self.metadata_calls:
            self.phase = 'columns'
            return
        ns = self.namespace.as_tuple
        call_id = self.metadata_calls.pop(0)
        core = self.core_reads[call_id]
        intent = core.record.intent
        lineage, terminal = core.lineage_original, core.terminal_original
        if lineage is not None:
            installed = self.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.installation_policy
            p = lineage.payload
            if (p.namespace, p.admission.installation_id, p.admission.manifest_digest) != (
                    self.namespace, installed.installation_id, installed.manifest_digest):
                raise AuthorityUnavailable('D13 accounting original crosses actual installed namespace/manifest')
            signer = self.graph._GraphCoordinator__d11_issuer._signer
            verify_d13_accounting_original_v3(lineage, signer=signer, phase=ADMISSION_PHASE)
            if terminal is not None:
                verify_d13_accounting_original_v3(terminal, signer=signer, phase=TERMINAL_PHASE)
            if (p.namespace != self.namespace or p.intent != intent or p.admission != core.admission):
                raise AuthorityUnavailable('D13 diagnostic actual lineage differs')
            expected_kind = 'foreground_generation_v7' if call_id == self.foreground_call_id else 'paid_precompression_v1'
            if p.kind != expected_kind:
                raise AuthorityUnavailable('D13 diagnostic model kind crosses actual selected cohort')
            if call_id in self.paid_locators and p.producer_operation_id != self.paid_locators[call_id][0]:
                raise AuthorityUnavailable('D13 prep admission was not the actual selected paid producer')
        if terminal is not None and (lineage is None or terminal.payload.lineage_digest != canonical_digest(lineage)
                or terminal.payload.terminal_receipt != core.terminal_receipt
                or terminal.payload.usage != core.record.usage or terminal.payload.cost != core.record.cost):
            raise AuthorityUnavailable('D13 terminal metadata does not join actual Core original')
        reserve = self.point(meter, 'runtime_budget_reservations', ('digest', 'state'),
            'lease_id=? AND operation_id=?', (intent.budget_lease_id, intent.budget_reservation_operation_id))
        if reserve is not None:
            if reserve[0] != intent.budget_reservation_digest:
                raise AuthorityUnavailable('D13 accounting original reserve conflicts')
            self.enqueue((call_id, 'ceiling'), 'runtime_budget_reservations', 'ceiling_json',
                ('lease_id', 'operation_id'), (intent.budget_lease_id, intent.budget_reservation_operation_id))
        reserve_op = self.point(meter, 'runtime_budget_operations', ('digest', 'lease_id'),
            "bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
            (*ns, intent.budget_reservation_operation_id))
        if reserve_op is not None:
            if reserve_op != (intent.budget_reservation_digest, intent.budget_lease_id):
                raise AuthorityUnavailable('D13 reserve operation differs from Core admission')
            self.enqueue((call_id, 'reserve'), 'runtime_budget_operations', 'receipt_json',
                ('bot_id', 'persona_id', 'operation_id', 'phase'), (*ns, intent.budget_reservation_operation_id, 'reserve'))
        settle = self.point(meter, 'runtime_budget_operations', ('digest', 'lease_id'),
            "bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
            (*ns, intent.budget_reservation_operation_id))
        if settle is None:
            self.c5[call_id] = ('not_recorded', None)
            return
        if reserve is None or reserve_op is None or settle != (intent.budget_reservation_digest, intent.budget_lease_id):
            raise AuthorityUnavailable('D13 C5 settle operation crossed original reservation')
        self.enqueue((call_id, 'settle'), 'runtime_budget_operations', 'receipt_json',
            ('bot_id', 'persona_id', 'operation_id', 'phase'), (*ns, intent.budget_reservation_operation_id, 'settle'))
        op = original_model_cost_operation_id_v1(self.namespace, call_id)
        bundle = self.point(meter, 'graph_bundle_operations', ('activity_id', 'digest'),
            'bot=? AND persona=? AND operation_id=?', (*ns, op))
        if bundle is None:
            raise AuthorityUnavailable('D13 recorded C5 settlement lacks actual Graph event')
        if call_id == self.foreground_call_id:
            self.enqueue((call_id, 'bundle'), 'graph_bundle_operations', 'receipt_json',
                ('bot', 'persona', 'operation_id'), (*ns, op))
        else:
            job = self.paid_locators[call_id][0]
            paid = self.point(meter, 'graph_d13_paid_cost_receipts_v1', ('payload_digest',),
                'bot=? AND persona=? AND job_ref=?', (*ns, job))
            if paid is None:
                raise AuthorityUnavailable('D13 paid C5 settlement lacks actual paid receipt')
            self.enqueue((call_id, 'paid'), 'graph_d13_paid_cost_receipts_v1', 'payload_json',
                ('bot', 'persona', 'job_ref'), (*ns, job))
        from .d11_types import runtime_cost_settlement_key
        cost_key = runtime_cost_settlement_key(*ns, bundle[0], op)
        head = self.point(meter, 'graph_atoms', ('revision', 'valid', 'value_cell_id'),
            'token=?', (cost_key.token,))
        if head is None or head[:2] != (1, 1):
            raise AuthorityUnavailable('D13 cost atom is absent or invalid')
        event_session = bundle[0] if call_id == self.foreground_call_id else 'd13-paid'
        history = self.point(meter, 'graph_history', ('valid', 'value_cell_id', 'event_bot',
            'event_persona', 'event_session', 'event_id'), 'token=? AND revision=?', (cost_key.token, 1))
        if history != (1, head[2], *ns, event_session, op):
            raise AuthorityUnavailable('D13 cost history lost actual same-commit producer')
        event = self.point(meter, 'graph_events', ('digest', 'epoch_revision'),
            'bot=? AND persona=? AND session=? AND event_id=?', (*ns, event_session, op))
        if event is None:
            raise AuthorityUnavailable('D13 accounting Graph event absent')
        self.enqueue((call_id, 'cost'), 'graph_history', 'value', ('token', 'revision'),
            (cost_key.token, 1), head[2])
        self.enqueue((call_id, 'event_revisions'), 'graph_events', 'revisions',
            ('bot', 'persona', 'session', 'event_id'), (*ns, event_session, op))
        self.c5[call_id] = ('pending_validation', cost_key.token)


    def _advance_column(self, meter):
        if self.column is not None:
            tag, column = self.column
            if column.advance(meter):
                self.columns[tag] = (column, column.require_v3(self))
                self.column = None
            return
        if self.queue:
            tag, table, column, keys, key, cell_id = self.queue.pop(0)
            self.column = tag, _DiagnosticColumnV3(self, table=table, column=column,
                key_columns=keys, key=key, cell_id=cell_id)
            return
        self.phase = 'aggregate'

    def _validate_costs(self):
        for call_id, core in self.core_reads.items():
            intent = core.record.intent
            if (call_id, 'ceiling') in self.columns and self.columns[call_id, 'ceiling'][1] != dict(intent.budget_ceiling):
                raise AuthorityUnavailable('D13 reserve ceiling differs from actual Core original')
            if (call_id, 'reserve') in self.columns:
                reserve = BudgetReceipt(**self.columns[call_id, 'reserve'][1])
                if (reserve.operation_id, reserve.digest, reserve.lease_id) != (
                        intent.budget_reservation_operation_id, intent.budget_reservation_digest, intent.budget_lease_id):
                    raise AuthorityUnavailable('D13 original reserve receipt differs')
            status, key = self.c5[call_id]
            if status == 'not_recorded':
                continue
            settle = BudgetReceipt(**self.columns[call_id, 'settle'][1])
            cost = RuntimeCostSettlement(**self.columns[call_id, 'cost'][1])
            op = original_model_cost_operation_id_v1(self.namespace, call_id)
            if ((settle.operation_id, settle.digest, settle.lease_id) != (intent.budget_reservation_operation_id,
                    intent.budget_reservation_digest, intent.budget_lease_id)
                    or cost.ceiling != dict(intent.budget_ceiling) or cost.status != settle.status
                    or (cost.bot_id, cost.persona_id) != self.namespace.as_tuple
                    or (cost.bundle_operation_id, cost.settlement_id, cost.cost_operation_id, cost.lease_id,
                        cost.budget_operation_id, cost.budget_phase, cost.budget_receipt_digest) !=
                       (op, op, intent.budget_reservation_operation_id, intent.budget_lease_id,
                        intent.budget_reservation_operation_id, 'settle', canonical_digest(asdict(settle)))):
                raise AuthorityUnavailable('D13 C5 receipt/financial atom link differs')
            revisions = self.columns[call_id, 'event_revisions'][1]
            if revisions != [[key, 1]]:
                raise AuthorityUnavailable('D13 financial atom is outside producing Graph event')
            if call_id == self.foreground_call_id:
                if core.terminal_receipt is None or core.admission is None:
                    raise AuthorityUnavailable('D13 natural C5 metadata lacks actual paired terminal')
                receipt = self.columns[call_id, 'bundle'][1]
                commit = receipt['original_model_cost']
                if (commit['call_id'] != call_id or commit['cost_ref'] != key
                        or commit['terminal_receipt_digest'] != canonical_digest(asdict(core.terminal_receipt))
                        or receipt['original_intent_digest'] != canonical_digest(asdict(intent))
                        or commit['budget_receipt_digest'] != cost.budget_receipt_digest):
                    raise AuthorityUnavailable('D13 actual natural C5 bundle crossed terminal/intent')
                from .model_cost_settlement import OriginalModelCostFactV1, reported_model_usage_original_v1
                fact = OriginalModelCostFactV1(intent, core.record, core.admission, core.terminal_receipt)
                if receipt.get('model_reported_usage_v1') != reported_model_usage_original_v1(
                        fact, budget_receipt_digest=cost.budget_receipt_digest):
                    raise AuthorityUnavailable('D13 reported usage differs from actual Core terminal/C5 original')
            else:
                column, receipt = self.columns[call_id, 'paid']
                if (receipt['schema'] != 'd13.paid_cost_receipt.v1'
                        or receipt['receipt'] != asdict(settle) or receipt['cost_write']['key'] != key
                        or receipt['cost_write']['value'] != asdict(cost)):
                    raise AuthorityUnavailable('D13 actual paid C5 original crossed financial atom')
                expected = next(value for (table, cols, where, params), value in self.points.items()
                    if table == 'graph_d13_paid_cost_receipts_v1' and params[-1] == self.paid_locators[call_id][0])
                if column.sha256 != expected[0]:
                    raise AuthorityUnavailable('D13 paid C5 canonical digest differs')
            self.c5[call_id] = (cost.status, cost.budget_receipt_digest)

    def aggregate(self):
        self._validate_costs()
        foreground = self.core_reads[self.foreground_call_id]
        selection = 'unknown'
        if foreground.http_expected is not None and foreground.http_observed is not None and foreground.frame is not None:
            template = foreground.http_expected['template_digest']
            if template == foreground.frame.raw_http_template_digest:
                selection = 'raw'
            elif template == foreground.frame.compressed_http_template_digest:
                selection = 'compressed'
            else:
                raise AuthorityUnavailable('D13 actual observed HTTP does not match its counted alternatives')
        calls, totals, unused, unknown, unused_unknown = [], {}, {}, 0, 0
        for call_id, core in self.core_reads.items():
            role = 'foreground' if call_id == self.foreground_call_id else 'precompression'
            usage, cost = dict(core.record.usage), dict(core.record.cost)
            terminal = core.terminal_original
            billing = None if terminal is None else terminal.payload.billing_receipt
            use = ('foreground_http' if role == 'foreground' else
                'used_in_this_http' if selection == 'compressed' else
                'unused_in_this_http' if selection == 'raw' else 'unknown')
            if billing is None:
                unknown += 1
                if use == 'unused_in_this_http':
                    unused_unknown += 1
            else:
                unit = billing.currency, billing.unit, billing.evidence_kind
                totals[unit] = totals.get(unit, 0) + billing.final_charged_amount
                if use == 'unused_in_this_http':
                    unused[unit] = unused.get(unit, 0) + billing.final_charged_amount
            calls.append(D13CallAccountingDiagnosticV3(call_id, role, core.record.state,
                'recorded' if terminal is not None else 'NOT_MIGRATED' if core.lineage_original is None else 'terminal_pending',
                usage.get('input_tokens'), usage.get('output_tokens'), usage.get('cached_input_tokens'),
                usage.get('cache_write_tokens'), cost.get('model_microusd'),
                None if billing is None else billing.final_charged_amount,
                cost.get('cache_storage_microusd'), None if billing is None else billing.evidence_kind,
                None if billing is None else billing.currency, None if billing is None else billing.unit,
                None if core.terminal_receipt is None else canonical_digest(asdict(core.terminal_receipt)),
                None if billing is None else billing.receipt_id, *self.c5[call_id], use))
        legacy = None
        if selection != 'unknown' and len(calls) <= 2 and all(c.input_tokens is not None and c.output_tokens is not None
                and c.terminal_receipt_digest is not None for c in calls):
            from .d13_precompression_job import D13ProviderUsageV2, account_d13_calls_v2
            converted = tuple(D13ProviderUsageV2(c.call_id, c.terminal_receipt_digest, c.role,
                c.input_tokens, c.output_tokens, c.cached_input_tokens, c.cache_write_tokens,
                c.final_billed_microusd, c.cache_storage_microusd) for c in calls)
            legacy = account_d13_calls_v2(converted[0], None if len(converted) == 1 else converted[1],
                candidate_used=selection == 'compressed')
        counted = None if foreground.evidence is None else foreground.evidence.payload
        capacity = D13WindowCapacityDiagnosticV3(
            None if foreground.frame is None else foreground.frame.collection_digest,
            None if foreground.frame is None else foreground.frame.collection_snapshot_commitment,
            None if foreground.evidence is None else canonical_digest(foreground.evidence),
            None if counted is None else (counted.raw_lower_tokens, counted.raw_upper_tokens),
            None if counted is None or counted.compressed_lower_tokens is None else
                (counted.compressed_lower_tokens, counted.compressed_upper_tokens),
            None if counted is None else counted.token_evidence,
            None if counted is None else counted.raw_http_bytes,
            None if counted is None else counted.compressed_http_bytes,
            None if foreground.http_observed is None else foreground.http_observed['payload']['http_bytes'],
            None if foreground.frame is None else len(foreground.frame.block_bindings),
            'unknown' if counted is None else 'no_compressed_variant' if counted.compressed_http_bytes is None else 'recorded_pair')
        return D13WindowAccountingDiagnosticV3(self.namespace, self.foreground_call_id, tuple(self.core_reads),
            tuple(calls), selection, None if foreground.frame is None else foreground.frame.counter_operation_id,
            None if foreground.frame is None else foreground.frame.frame_intent_digest,
            tuple((*unit, amount) for unit, amount in sorted(totals.items())), unknown,
            tuple((*unit, amount) for unit, amount in sorted(unused.items())), unused_unknown, legacy, capacity)

    def advance(self, meter):
        self.require_current_v3(meter)
        self.operation.reserve_retained_state_growth_v3(self, 1048576)
        try:
            if self.phase == 'foreground':
                self._locate_preps(meter)
            elif self.phase == 'core_preps':
                if not self.pending_calls:
                    self.metadata_calls = list(self.core_reads)
                    self.phase = 'metadata_plan'
            elif self.phase == 'metadata_plan':
                self._plan_metadata(meter)
            elif self.phase == 'columns':
                self._advance_column(meter)
            elif self.phase == 'aggregate':
                self.result = self.aggregate()
                self.complete = True
                self.proof = PreparedD13AccountingDiagnosticV3(_ISSUER, self)
        finally:
            self.operation.finish_retained_state_growth_v3(self)

    def finish_fence_v3(self):
        self.port.finish_fence(self.scope, request_id='finish:'+self.scope.operation_id,
            request_digest='sha256:'+canonical_digest((self.scope.operation_id, 'd13-diagnostic-read-closed')))
        self.read_finished = True

    def release_payload_v3(self):
        if self.closed:
            return
        _READERS.pop(self, None)
        if self.proof is not None:
            _PROOFS.pop(self.proof, None)
        self.core_reads.clear(); self.points.clear(); self.columns.clear(); self.queue.clear()
        self.paid_locators.clear(); self.pending_calls.clear(); self.metadata_calls.clear(); self.c5.clear()
        self.column = self.result = self.proof = None
        self.closed = True
        self.metadata_reads.release()
        self.operation.unregister_retained_state_v3(self)


class PreparedD13AccountingDiagnosticV3:
    def __init__(self, issuer, reader):
        if issuer is not _ISSUER or not reader.complete:
            raise TypeError('actual complete D13 diagnostic metadata producer required')
        self.reader = reader
        _PROOFS[self] = reader.identity()

    def result_v3(self, graph, namespace, foreground_call_id):
        r = self.reader
        if (_PROOFS.get(self) != r.identity() or graph is not r.graph or namespace != r.namespace
                or foreground_call_id != r.foreground_call_id or r.operation.closed or r.closed
                or not r.complete or not r.read_finished):
            raise AuthorityUnavailable('D13 diagnostic result left its actual retained caller/Work')
        graph._admin(r.bootstrap)
        return r.result

    def release_payload_v3(self):
        self.reader.release_payload_v3()


def begin_d13_accounting_diagnostic_v3(graph, bootstrap, namespace, foreground_call_id):
    r = _D13AccountingDiagnosticReadV3(graph, bootstrap, namespace, foreground_call_id)
    try:
        r.work = create_graph_storage_work_v3(graph, kind=KIND, operation_id=r.operation.operation_id,
            selection_digest=r.operation.selection_digest, deadline_utc=None, state=r, operation=r.operation)
        return r.work
    except BaseException as first:
        try:
            r.finish_fence_v3()
        except BaseException as later:
            if later is not first:
                first.add_note('D13 diagnostic Work READ cleanup failed: '+type(later).__name__)
        try:
            r.release_payload_v3()
        except BaseException as later:
            if later is not first:
                first.add_note('D13 diagnostic Work payload release failed: '+type(later).__name__)
        try:
            finish_runtime_storage_operation_v3(r.operation)
        except BaseException as later:
            if later is not first:
                first.add_note('D13 diagnostic Work operation release failed: '+type(later).__name__)
        raise


def advance_d13_accounting_diagnostic_v3(graph, work):
    r = work.state
    if type(r) is not _D13AccountingDiagnosticReadV3 or graph is not r.graph:
        raise AuthorityUnavailable('actual named D13 diagnostic Work required')
    with bind_runtime_storage_operation_v3(r.operation, r.db):
        r.require_current_v3()
        if r.port.validate_fence(r.scope) != r.scope.permit:
            raise AuthorityUnavailable('D13 diagnostic READ permit changed')
        r.outside_sql_v3()
        with r.store._lock:
            r.db.execute('BEGIN')
            try:
                with runtime_storage_quantum_v3(r.db) as meter:
                    r.advance(meter)
            finally:
                r.db.rollback()
    return GraphStorageStepV3('complete', r.proof) if r.complete else GraphStorageStepV3('progress')


def finish_d13_accounting_diagnostic_v3(graph, work, error):
    r = work.state
    if type(r) is not _D13AccountingDiagnosticReadV3 or graph is not r.graph:
        raise AuthorityUnavailable('D13 diagnostic finish crossed actual Graph')
    failure = error
    try:
        r.finish_fence_v3()
        if error is None and not r.complete:
            raise AuthorityUnavailable('D13 diagnostic cannot publish incomplete metadata')
    except BaseException as exc:
        if failure is None:
            failure = exc
        elif exc is not failure:
            failure.add_note('D13 diagnostic READ finish failed: '+type(exc).__name__)
    if failure is None:
        work.result_lease = r.operation
        return
    try:
        r.release_payload_v3()
    except BaseException as exc:
        if exc is not failure:
            failure.add_note('D13 diagnostic payload release failed: '+type(exc).__name__)
    try:
        finish_runtime_storage_operation_v3(r.operation)
    except BaseException as exc:
        if exc is not failure:
            failure.add_note('D13 diagnostic operation release failed: '+type(exc).__name__)
    if error is None:
        raise failure

