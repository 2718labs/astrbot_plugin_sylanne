"""Contact original-call accounting metadata on its own retained Work.

No Plan, frozen request, model result or Source body is an allowed column.
Core terminal and accounting calls occur between Graph storage quanta.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, replace
from weakref import WeakKeyDictionary
import json

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
from ..authority_service.v2_model_egress_wire import from_wire
from ..graph_types import AtomKey
from ..graph_worker import GraphStorageStepV3, create_graph_storage_work_v3, require_graph_storage_work_admission_v3
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3, bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3, runtime_storage_quantum_v3, _runtime_bounded_fixed_row_v3)
from .contact_paid_original_v2 import TABLE, SIGN_KIND, record_contact_original_v2
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .model_cost_settlement import (read_original_model_cost, OriginalModelCostCommitV1,
    original_model_cost_operation_id_v1, original_model_budget_measurement)
from .owner_material_source_storage_v3 import CanonicalValueStreamV3

_ISSUER = object()
_WORKS = WeakKeyDictionary()
_READING = ContextVar('contact_original_cost_metadata_work_v3', default=None)

@dataclass(frozen=True, slots=True)
class ContactCostMetadataSelectorV3:
    contact_id: str
    phase: str
    intent: ModelEgressIntentV1
    def __post_init__(self):
        if (type(self.contact_id) is not str or not self.contact_id.startswith('contact:')
                or self.phase not in {'contact_generation','contact_review'}
                or type(self.intent) is not ModelEgressIntentV1
                or not self.intent.job_id.startswith('contact-model-job-v2:')):
            raise AuthorityUnavailable('Contact cost metadata requires its exact original call selector')


def _require_cost_metadata_column_v3(column):
    if type(column) is _CostColumnV3:
        return require_contact_cost_work_v3(column.owner)
    from .current_life_numeric_accounting_v3 import require_numeric_accounting_column_v3
    owner = require_numeric_accounting_column_v3(column)
    if owner is not None:return owner
    from .current_life_numeric_paid_write_v3 import require_numeric_seal_prior_column_v3
    owner = require_numeric_seal_prior_column_v3(column)
    if owner is not None:return owner
    raise AuthorityUnavailable('Unregistered accounting metadata column origin')


class _CostColumnV3:
    def __init__(self, owner, request):
        self.owner,self.request = owner,request
        _require_cost_metadata_column_v3(self)
        self.table,self.columns,self.keys,self.key = request
        self.where = ' AND '.join(name+'=?' for name in self.keys)
        self.json_names = tuple(name for name in self.columns if name.endswith('_json') or name == 'value')
        self.small_names = tuple(dict.fromkeys((*self.keys,*(name for name in self.columns if name not in self.json_names),
            *(('value_cell_id',) if self.table == 'graph_atoms' else ()))))
        self.small,self.original,self.stream = None,None,None
        self.pending,self.values,self.parts = list(self.json_names),{},[]
        self.phase,self.complete,self.row = 'metadata',False,None
    def advance(self,meter):
        owner = _require_cost_metadata_column_v3(self)
        owner.require_current(meter=meter)
        if self.phase == 'metadata':
            row = _runtime_bounded_fixed_row_v3(owner.db,meter,self.table,self.small_names,self.where,self.key)
            self.metadata = row
            if row is None:
                self.complete = True
                return
            self.small = dict(zip(self.small_names,row))
            self.phase = 'column'
            return
        if self.phase == 'column':
            if self.original is not None:
                if self.original.advance(meter):
                    self.stream = CanonicalValueStreamV3(self.original.require_v3(owner))
                    self.parts = []
                    self.phase = 'wire'
                return
            if self.pending:
                name = self.pending.pop(0)
                self.original = DispatchOriginalJSONReadV3(owner,table=self.table,column=name,
                    key_columns=self.keys,key=self.key,cell_id=self.small.get('value_cell_id') if name == 'value' else None)
                return
            self.row = tuple(self.values[name] if name in self.values else self.small[name] for name in self.columns)
            self.complete = True
            return
        fragment = self.stream.read_fragment(meter)
        if fragment:
            owner.operation.retain(len(fragment)+128)
            self.parts.append(fragment)
        if self.stream.complete:
            if self.stream.hash.hexdigest() != self.original.sha256:
                raise AuthorityUnavailable('Contact accounting canonical wire differs from complete original EOF')
            size = sum(map(len,self.parts))
            owner.operation.retain(size*2+1024)
            self.values[self.original.column] = b''.join(self.parts).decode('ascii')
            self.original,self.stream,self.parts = None,None,[]
            self.phase = 'column'
    def require_row(self,meter):
        _require_cost_metadata_column_v3(self).require_current(meter=meter)
        if not self.complete or _runtime_bounded_fixed_row_v3(self.owner.db,meter,self.table,
                self.small_names,self.where,self.key) != self.metadata:
            raise AuthorityUnavailable('Contact original cost metadata changed after whole EOF')
        return self.row


class ContactCostMetadataWorkV3:
    def __init__(self,issuer,service,selector,operation):
        from .contact_graph_runtime_v2 import InstalledContactModelGraphRuntimeV2
        if issuer is not _ISSUER or type(service) is not InstalledContactModelGraphRuntimeV2:
            raise AuthorityUnavailable('Contact original cost reader requires its actual installed service')
        service._current()
        self.service,self.selector,self.operation = service,selector,operation
        self.graph,self.store,self.db = service.graph,service.store,service.store._db
        self.namespace = service.bundle.installation_policy.namespace
        self.graph_stamp = self.graph._v2_graph_stamp(self.namespace)
        self.work,self.closed,self.phase = None,False,'terminal'
        self.readers,self.pending,self.queue = {},None,[]
        self.fact,self.account,self.quote,self.receipt = None,None,None,None
        self.accounting_request,self.accounting_grant,self.accounting_recovered = None,None,False
        self.prefinal = self
        _WORKS[self] = (service,selector,operation,self.graph,self.db)
    def _actual(self):
        return require_contact_cost_work_v3(self)
    def require_current(self,*,meter):
        require_contact_cost_work_v3(self)
        self.operation.handle.require_current(meter)
        if self.graph._v2_graph_stamp(self.namespace) != self.graph_stamp:
            raise AuthorityUnavailable('Contact accounting metadata Graph stamp changed')
        return self
    def add(self,table,columns,keys,key):
        request = (table,tuple(columns),tuple(keys),tuple(key))
        if request not in self.readers and request not in self.queue:
            self.queue.append(request)
        return request
    def row(self,table,columns,keys,key,meter):
        request = (table,tuple(columns),tuple(keys),tuple(key))
        reader = self.readers.get(request)
        if reader is None:
            raise AuthorityUnavailable('Contact accounting column was not prepared by its fixed recipe')
        return reader.require_row(meter)
    def original(self,kind,meter):
        row = self.row(TABLE,('payload_json','payload_digest','signature'),
            ('bot','persona','kind','original_ref'),(*self.namespace.as_tuple,kind,self.selector.intent.job_id),meter)
        if row is None:
            raise AuthorityUnavailable('Contact original accounting/call metadata absent')
        raw = json.loads(row[0])
        from .c09_contact_originals_v2 import validate_contact_payload_v2
        validate_contact_payload_v2(kind,raw)
        digest = canonical_digest(raw)
        self.service.issuer._signer.verify(SIGN_KIND,
            canonical_serialize((self.namespace,kind,self.selector.intent.job_id,digest)),row[2])
        if digest != row[1]:
            raise AuthorityUnavailable('Contact signed accounting metadata whole EOF digest differs')
        return raw
    def release_payload_v3(self):
        self.closed = True
        self.readers.clear()
        self.queue.clear()
        self.pending = self.account = self.quote = self.fact = None
        _WORKS.pop(self,None)


def require_contact_cost_work_v3(state):
    if (type(state) is not ContactCostMetadataWorkV3 or state.closed
            or _WORKS.get(state) != (state.service,state.selector,state.operation,state.graph,state.db)
            or state.operation.closed or state.work is None or state.work.state is not state
            or state.work.operation is not state.operation):
        raise AuthorityUnavailable('Contact original accounting lost its actual metadata Work')
    state.service._current()
    return state


@contextmanager
def bind_contact_cost_metadata_v3(state):
    require_contact_cost_work_v3(state)
    token = _READING.set(state)
    try:
        yield state
    finally:
        _READING.reset(token)


def contact_cost_original_point_v3(db,*,table,columns,key_columns,key):
    state = _READING.get()
    if state is None:
        return False,None
    require_contact_cost_work_v3(state)
    if state.db is not db:
        raise AuthorityUnavailable('Contact accounting metadata crossed its selected connection')
    with runtime_storage_quantum_v3(db) as meter:
        return True,state.row(table,columns,key_columns,key,meter)


def capture_contact_accounting_operation_v3(graph,request,grant,committed,*,recovered=False):
    state = _READING.get()
    if state is None:
        return
    from ..authority_service.v2_accounting_contract import AccountingMaintenanceRequestV1,AccountingMaintenanceGrantV1
    require_contact_cost_work_v3(state)
    if (state.phase != 'commit' or state.graph is not graph or type(request) is not AccountingMaintenanceRequestV1
            or request.intent != state.selector.intent or type(committed) is not OriginalModelCostCommitV1
            or committed.call_id != request.intent.call_id or committed.operation_id != state.cost_operation
            or (not recovered and (type(grant) is not AccountingMaintenanceGrantV1
                or grant.permit.operation_id != request.operation_id
                or grant.terminal_receipt_digest != committed.terminal_receipt_digest))):
        raise AuthorityUnavailable('Contact cost reader cannot substitute the actual original maintenance operation')
    state.accounting_request,state.accounting_grant,state.accounting_recovered = request,grant,recovered


def prepare_contact_cost_metadata_work_v3(service,*,contact_id,phase,intent):
    service._current()
    require_graph_storage_work_admission_v3(service.graph)
    selector = ContactCostMetadataSelectorV3(contact_id,phase,intent)
    operation_id = original_model_cost_operation_id_v1(service.bundle.installation_policy.namespace,intent.call_id)
    operation = begin_runtime_storage_operation_v3(service.store._db,operation_id,None)
    try:
        state = ContactCostMetadataWorkV3(_ISSUER,service,selector,operation)
        state.cost_operation = operation_id
        work = create_graph_storage_work_v3(service.graph,kind='contact_cost_metadata_v3',operation_id=operation_id,
            selection_digest=operation.selection_digest,deadline_utc=None,state=state,operation=operation)
        state.work = work
        return work
    except BaseException:
        finish_runtime_storage_operation_v3(operation)
        raise


def advance_contact_cost_metadata_work_v3(graph,work):
    state = require_contact_cost_work_v3(work.state)
    if state.graph is not graph:
        raise AuthorityUnavailable('Contact accounting reader belongs to another installed Graph')
    intent,service = state.selector.intent,state.service
    with bind_runtime_storage_operation_v3(state.operation,state.db),bind_contact_cost_metadata_v3(state):
        if state.phase == 'terminal':
            if state.db.in_transaction:
                raise AuthorityUnavailable('Contact accounting Core observation cannot run in Graph SQL')
            state.fact = read_original_model_cost(graph._GraphCoordinator__model_terminal_cost_port,intent)
            if state.fact.recovery.state != 'observed':
                raise AuthorityUnavailable('Unobserved original Contact call retains its original cost and reservation')
            for kind in ('accounting_prepared','call'):
                state.add(TABLE,('payload_json','payload_digest','signature'),('bot','persona','kind','original_ref'),
                    (*state.namespace.as_tuple,kind,intent.job_id))
            state.phase = 'account'
            return GraphStorageStepV3('progress')
        if state.phase == 'commit':
            if state.db.in_transaction:
                raise AuthorityUnavailable('Original accounting writer must own its own actual transaction and Core fence')
            state.receipt = graph._commit_original_model_cost_v1(service.bootstrap,state.namespace,intent,
                quote_id=state.account['quote_id'],quote_version=state.account['quote_version'],work_kind=state.selector.phase)
            if state.accounting_request is None:
                raise AuthorityUnavailable('Actual original accounting writer did not return its sealed maintenance identity')
            cost_key = AtomKey.from_token(state.receipt.cost_ref)
            if (cost_key.type_name != 'runtime.cost_settlement'
                    or (cost_key.owner.bot,cost_key.owner.persona) != state.namespace.as_tuple
                    or cost_key.owner.subject != state.quote.activity_id):
                raise AuthorityUnavailable('Contact accounting reader is limited to the actual once D11 cost identity')
            state.graph_stamp = graph._v2_graph_stamp(state.namespace)
            state.readers.clear()
            state.add('graph_bundle_operations',('receipt_json','commit_seq'),('bot','persona','operation_id'),
                (*state.namespace.as_tuple,state.receipt.operation_id))
            state.add('graph_original_model_cost_attempts_v1',('intent_digest','attempt_id','anchor_json','state'),
                ('bot','persona','call_id'),(*state.namespace.as_tuple,intent.call_id))
            state.add('graph_atoms',('value','valid'),('token',),(state.receipt.cost_ref,))
            state.add('runtime_budget_operations',('receipt_json',),('bot_id','persona_id','operation_id','phase'),
                (*state.namespace.as_tuple,intent.budget_reservation_operation_id,'settle'))
            state.add(TABLE,('payload_json','payload_digest','signature'),('bot','persona','kind','original_ref'),
                (*state.namespace.as_tuple,'paid_cost',intent.job_id))
            state.phase = 'seal'
            return GraphStorageStepV3('progress')
        with state.store._lock,runtime_storage_quantum_v3(state.db) as meter:
            state.db.execute('BEGIN IMMEDIATE' if state.phase == 'seal' and not state.queue and state.pending is None else 'BEGIN')
            try:
                state.require_current(meter=meter)
                if state.pending is not None:
                    state.pending.advance(meter)
                    if state.pending.complete:
                        state.readers[state.pending.request] = state.pending
                        state.pending = None
                    return GraphStorageStepV3('progress')
                if state.queue:
                    state.pending = _CostColumnV3(state,state.queue.pop(0))
                    return GraphStorageStepV3('progress')
                if state.phase == 'account':
                    account = state.original('accounting_prepared',meter)
                    saved = from_wire(state.original('call',meter),ModelEgressIntentV1)
                    if (saved != intent or account['contact_id'] != state.selector.contact_id
                            or account['namespace'] != asdict(state.namespace) or account['work_kind'] != state.selector.phase
                            or (account['call_id'],account['prepared_digest'],account['acquire_operation_id'],
                                account['prepare_operation_id'],account['reservation_digest'],account['parent_budget_lease_id']) !=
                               (intent.call_id,intent.binding_digest,intent.operation_id,intent.budget_reservation_operation_id,
                                intent.budget_reservation_digest,intent.budget_lease_id)):
                        raise AuthorityUnavailable('Contact accounting cannot substitute another original call/parent/reservation')
                    state.account = account
                    state.add('runtime_resource_quotes',('quote_json','signature'),('quote_id','version'),
                        (account['quote_id'],account['quote_version']))
                    state.phase = 'quote'
                elif state.phase == 'quote':
                    state.quote = service.resource_issuer.original_signed_quote(state.db,state.account['quote_id'],state.account['quote_version'])
                    if canonical_digest(state.quote) != state.account['quote_digest']:
                        raise AuthorityUnavailable('Contact original accounting quote differs from its signed preparation')
                    state.phase = 'commit'
                elif state.phase == 'seal':
                    _seal_contact_cost_metadata_v3(state,meter)
                    state.db.commit()
                    return GraphStorageStepV3('complete',state.receipt)
                else:
                    raise AuthorityUnavailable('Contact original cost metadata phase is unregistered')
            finally:
                if state.db.in_transaction:
                    state.db.rollback()
    return GraphStorageStepV3('progress')


def _seal_contact_cost_metadata_v3(state,meter):
    from .budget import _receipt_from_json
    from ..domains.d01.production_operations_v1 import plain_v1
    intent,receipt = state.selector.intent,state.receipt
    original = state.row('graph_bundle_operations',('receipt_json','commit_seq'),('bot','persona','operation_id'),
        (*state.namespace.as_tuple,receipt.operation_id),meter)
    attempt = state.row('graph_original_model_cost_attempts_v1',('intent_digest','attempt_id','anchor_json','state'),
        ('bot','persona','call_id'),(*state.namespace.as_tuple,intent.call_id),meter)
    cost = state.row('graph_atoms',('value','valid'),('token',),(receipt.cost_ref,),meter)
    budget = state.row('runtime_budget_operations',('receipt_json',),('bot_id','persona_id','operation_id','phase'),
        (*state.namespace.as_tuple,intent.budget_reservation_operation_id,'settle'),meter)
    if original is None or attempt is None or cost is None or cost[1] != 1 or budget is None:
        raise AuthorityUnavailable('Contact original accounting COMMIT is incomplete')
    raw = json.loads(original[0])
    committed = OriginalModelCostCommitV1(**raw['original_model_cost'])
    settled = _receipt_from_json(budget[0])
    terminal = canonical_digest(asdict(state.fact.receipt))
    if (committed != (receipt if receipt.status == 'committed' else replace(receipt,status='committed'))
            or committed.commit_seq != original[1] or raw['original_intent_digest'] != canonical_digest(asdict(intent))
            or raw['terminal_receipt_digest'] != terminal or committed.terminal_receipt_digest != terminal
            or committed.budget_receipt_digest != canonical_digest(asdict(settled))
            or (committed.quote_id,committed.quote_version) != (state.quote.quote_id,state.quote.version)
            or (attempt[0],attempt[1],attempt[3]) != (canonical_digest(asdict(intent)),state.accounting_request.operation_id,'committed')
            or json.loads(attempt[2]) != asdict(state.accounting_request.expected_anchor)
            or raw['accounting_attempt_id'] != state.accounting_request.operation_id):
        raise AuthorityUnavailable('Contact accounting cost/terminal/settlement/maintenance original differs')
    _,unknown = original_model_budget_measurement(state.fact,state.quote,work_kind=state.selector.phase)
    paid = {'schema':'d10.contact-paid-cost-original.v2','prepared_digest':state.account['prepared_digest'],
        'terminal_digest':terminal,'cost_ref':receipt.cost_ref,'cost_value':json.loads(cost[0]),
        'budget_receipt':plain_v1(settled),'unknown_dimensions':list(unknown),'cost_operation_id':receipt.operation_id}
    record_contact_original_v2(state.db,state.service.issuer,state.namespace,'paid_cost',intent.job_id,paid)
    state.service._cost_facts[intent.job_id],state.service._actual_cost_commits[intent.job_id] = state.fact,receipt


def finish_contact_cost_metadata_work_v3(graph,work,error):
    state = require_contact_cost_work_v3(work.state)
    if state.graph is not graph:
        raise AuthorityUnavailable('Contact accounting finish crossed its actual installed Graph')
    if error is None:
        work.result_lease = state.operation
        state.release_payload_v3()
    else:
        state.release_payload_v3()
        finish_runtime_storage_operation_v3(state.operation)
