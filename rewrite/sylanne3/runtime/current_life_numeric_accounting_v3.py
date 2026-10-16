"""Original Numeric accounting metadata; only the real Accounting grant may settle."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict
from weakref import WeakKeyDictionary
import json

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
from ..graph_worker import GraphStorageStepV3,create_graph_storage_work_v3,require_graph_storage_work_admission_v3
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,finish_runtime_storage_operation_v3,runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
from .contact_cost_metadata_v3 import _CostColumnV3
from .model_cost_settlement import original_model_cost_operation_id_v1,read_original_model_cost
from .dispatch_current_inventory_v3 import _heap

_ISSUER=object()
_WORKS=WeakKeyDictionary()
_COLUMNS=WeakKeyDictionary()
_BOUND=ContextVar('numeric_actual_original_accounting_metadata_v3',default=None)
WORK_KIND_V3='current_life_numeric_accounting_v3'
_LEASE_COLUMNS=('lease_id','parent_id','bot_id','persona_id','currency','limits_json','used_json','reserved_json','unconfirmed_json','version','state')
_LIFE_COLUMNS=('producing_operation_id','payload_json','payload_digest','signature')
_ATTEMPT_COLUMNS=('intent_digest','attempt_id','anchor_json','state')
_COST_COLUMNS=('digest','activity_id','effect_id','commit_seq','receipt_json')
_RESERVATION_COLUMNS=('digest','ceiling_json','state','actual_json')
_BUDGET_COLUMNS=('digest','lease_id','receipt_json','resolution_binding_json')

def require_numeric_accounting_column_v3(column):
    if type(column)is not _NumericAccountingColumnV3:return None
    state=require_numeric_accounting_work_v3(column.owner)
    if _COLUMNS.get(column)!=(state,column.request) or column.request not in state.allowed:
        raise AuthorityUnavailable('Numeric Accounting column requires its private exact recipe factory')
    return state


class _NumericAccountingColumnV3(_CostColumnV3):
    def __init__(self,issuer,state,request):
        if issuer is not _ISSUER or type(self)is not _NumericAccountingColumnV3:
            raise AuthorityUnavailable('Numeric Accounting column private issuer required')
        require_numeric_accounting_work_v3(state)
        if request not in state.allowed:raise AuthorityUnavailable('Numeric Accounting undeclared column recipe')
        _COLUMNS[self]=(state,request)
        super().__init__(state,request)
    def advance(self,meter):
        require_numeric_accounting_column_v3(self).require_current(meter=meter)
        if self.phase=='column' and self.original is None and self.pending:
            name=self.pending[0]
            with self.owner.store._lock:
                row=self.owner.db.execute('SELECT typeof('+name+') FROM '+self.table+' WHERE '+self.where,self.key).fetchone()
                meter.charge_read(8)
            if row==('null',):self.values[self.pending.pop(0)]=None;return
        return super().advance(meter)

class _NumericAccountingWorkV3:
    def __init__(self,issuer,graph,bootstrap,bundle,intent,quote_id,quote_version,operation):
        if issuer is not _ISSUER:raise AuthorityUnavailable('Actual Numeric accounting Work issuer required')
        self.graph,self.bootstrap,self.bundle,self.intent=graph,bootstrap,bundle,intent
        self.store,self.db,self.namespace=graph._GraphCoordinator__store,graph._GraphCoordinator__store._db,bundle.installation_policy.namespace
        self.quote_id,self.quote_version,self.operation=quote_id,quote_version,operation
        self.cost_operation=original_model_cost_operation_id_v1(self.namespace,intent.call_id)
        self.work=None;self.closed=False;self.phase='terminal';self.fact=None;self.quote=None
        self.pending=None;self.queue=[];self.readers={};self.allowed=set();self.lease_ids=set()
        self.accounting_request=self.accounting_grant=self.committed=None
        self.graph_stamp=None;self.prefinal=self;self.dirty=set();self.transitions={}
        _WORKS[self]=(graph,self.store,self.db,bundle,intent,quote_id,quote_version,operation)
        operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        return _heap((self.fact,self.quote,self.readers,self.allowed,self.queue,self.lease_ids,self.committed,self.dirty,self.transitions))
    def require_current(self,*,meter):
        require_numeric_accounting_work_v3(self)
        self.operation.handle.require_current(meter)
        if self.graph_stamp is not None and self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp:
            raise AuthorityUnavailable('Numeric accounting metadata actual selected Graph changed')
        return self
    def add(self,table,columns,keys,key):
        request=(table,tuple(columns),tuple(keys),tuple(key));self.allowed.add(request)
        if request not in self.readers and request not in self.queue:self.queue.append(request)
    def row(self,request,meter):
        require_numeric_accounting_work_v3(self)
        if request not in self.allowed:
            raise AuthorityUnavailable('Numeric accounting metadata escaped its fixed real once recipe')
        reader=self.readers.get(request)
        if reader is None:raise AuthorityUnavailable('Numeric accounting fixed metadata has not reached actual EOF')
        return reader.require_row(meter)
    def release_payload_v3(self):
        self.closed=True;_WORKS.pop(self,None);self.operation.unregister_retained_state_v3(self)
        for column in (*self.readers.values(),self.pending):
            if column is not None:_COLUMNS.pop(column,None)
        self.readers.clear();self.queue.clear();self.allowed.clear();self.lease_ids.clear();self.dirty.clear();self.transitions.clear()
        self.pending=self.fact=self.quote=None


def require_numeric_accounting_work_v3(state):
    if (type(state)is not _NumericAccountingWorkV3 or state.closed or state.operation.closed
            or _WORKS.get(state)!=(state.graph,state.store,state.db,state.bundle,state.intent,state.quote_id,state.quote_version,state.operation)
            or state.work is None or state.work.state is not state or state.work.operation is not state.operation
            or state.work.kind!=WORK_KIND_V3):
        raise AuthorityUnavailable('Numeric accounting metadata requires its actual independent retained Work')
    state.work._require_invocation(state.graph)
    state.graph._admin(state.bootstrap)
    assembly=state.graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is not state.bundle:
        raise AuthorityUnavailable('Numeric accounting actual installation changed')
    return state


def prepare_current_life_numeric_accounting_v3(graph,bootstrap,namespace,intent,*,quote_id,quote_version):
    require_graph_storage_work_admission_v3(graph);graph._admin(bootstrap)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if (type(namespace)is not NamespaceId or type(intent)is not ModelEgressIntentV1 or assembly is None
            or assembly.admin_bundle.installation_policy.namespace!=namespace
            or intent.namespace!=assembly.admin_bundle.installation_policy.authority_namespace
            or assembly.admin_bundle.model_workflows.life_numeric is None
            or assembly.admin_bundle.model_workflows.life_numeric.work_kind!='d06.encode_internal_life_numeric'
            or intent.acquire_operation_id is None or type(quote_id)is not str
            or type(quote_version)is not int or quote_version<1):
        raise AuthorityUnavailable('Numeric accounting needs its actual installed original call selector')
    operation_id=original_model_cost_operation_id_v1(namespace,intent.call_id)
    operation=begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,operation_id,None)
    state=_NumericAccountingWorkV3(_ISSUER,graph,bootstrap,assembly.admin_bundle,intent,quote_id,quote_version,operation)
    work=create_graph_storage_work_v3(graph,kind=WORK_KIND_V3,operation_id=operation_id,
        selection_digest=operation.selection_digest,deadline_utc=None,state=state,operation=operation)
    state.work=work;return work

@contextmanager
def bind_numeric_accounting_metadata_v3(state):
    require_numeric_accounting_work_v3(state);token=_BOUND.set(state)
    try:yield state
    finally:_BOUND.reset(token)


def numeric_accounting_state_v3(graph):
    state=_BOUND.get()
    if state is None:return None
    require_numeric_accounting_work_v3(state)
    if state.graph is not graph:raise AuthorityUnavailable('Numeric Accounting producer crossed its actual Graph')
    return state


def numeric_accounting_point_v3(db,*,table,columns,key_columns,key):
    state=_BOUND.get()
    if state is None:return False,None
    require_numeric_accounting_work_v3(state)
    if db is not state.db:raise AuthorityUnavailable('Numeric Accounting metadata crossed selected connection')
    with runtime_storage_quantum_v3(db)as meter:
        return True,state.row((table,tuple(columns),tuple(key_columns),tuple(key)),meter)


def _read_life_metadata_v3(state,kind):
    request=('graph_d11_life_originals_v1',_LIFE_COLUMNS,('bot','persona','kind','original_ref'),
        (*state.namespace.as_tuple,kind,state.intent.job_id))
    reader=state.readers[request];row=reader.row
    if row is None:raise AuthorityUnavailable('Numeric accounting signed original metadata is absent')
    raw=json.loads(row[1])
    from .d11_life_preparation_v1 import SIGN_KIND
    if canonical_digest(raw)!=row[2]:raise AuthorityUnavailable('Numeric accounting signed metadata canonical digest differs')
    state.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
        canonical_serialize((state.namespace,kind,state.intent.job_id,row[2])),row[3])
    if kind=='numeric_call_v1':
        from ..authority_service.v2_model_egress_wire import from_wire
        if (set(raw)!={'schema','prepared_digest','binding_digest','request_digest','intent','permit'}
                or raw['schema']!='d06.internal-life-numeric-call.v1' or from_wire(raw['intent'],ModelEgressIntentV1)!=state.intent
                or raw['binding_digest']!=state.intent.binding_digest or raw['request_digest']!=state.intent.request_digest
                or row[0]!=state.intent.acquire_operation_id):
            raise AuthorityUnavailable('Numeric accounting real sealed call identity differs')
    elif kind=='numeric_binding_v1':
        from .d06_life_numeric_worker_v1 import decode_life_numeric_worker_binding_v1
        binding=decode_life_numeric_worker_binding_v1(raw)
        if (binding.namespace!=state.namespace or binding.job_id!=state.intent.job_id
                or binding.call_id!=state.intent.call_id or binding.digest!=state.intent.binding_digest
                or binding.acquire_operation_id!=state.intent.operation_id or binding.worker_subject!=state.intent.subject
                or binding.installation_id!=state.bundle.installation_policy.installation_id
                or row[0]!=binding.acquire_operation_id):
            raise AuthorityUnavailable('Numeric accounting actual signed worker binding differs')
    elif kind=='numeric_acquire_commit_v1':
        from .domain_production_originals_v1 import _receipt
        receipt=_receipt(raw['receipt'])
        if (set(raw)!={'schema','prepared_digest','binding_digest','receipt','request_digest','receipt_digest'}
                or raw['schema']!='d06.internal-life-numeric-acquire-commit.v1'
                or raw['binding_digest']!=state.intent.binding_digest or raw['request_digest']!=state.intent.request_digest
                or receipt.status!='committed' or receipt.operation_id!=state.intent.acquire_operation_id
                or raw['receipt_digest']!=canonical_digest(receipt) or row[0]!=receipt.operation_id):
            raise AuthorityUnavailable('Numeric accounting actual acquired metadata differs')
    return raw


def _prepare_accounting_recipe_v3(state):
    ns=state.namespace.as_tuple;intent=state.intent
    for kind in ('numeric_call_v1','numeric_binding_v1','numeric_acquire_commit_v1'):
        state.add('graph_d11_life_originals_v1',_LIFE_COLUMNS,('bot','persona','kind','original_ref'),(*ns,kind,intent.job_id))
    state.add('runtime_resource_quotes',('quote_json','signature'),('quote_id','version'),(state.quote_id,state.quote_version))
    state.add('runtime_budget_reservations',_RESERVATION_COLUMNS,('lease_id','operation_id'),
        (intent.budget_lease_id,intent.budget_reservation_operation_id))
    for phase in ('reserve','settle'):
        state.add('runtime_budget_operations',_BUDGET_COLUMNS,('bot_id','persona_id','operation_id','phase'),
            (*ns,intent.budget_reservation_operation_id,phase))
    state.add('graph_bundle_operations',_COST_COLUMNS,('bot','persona','operation_id'),(*ns,state.cost_operation))
    state.add('graph_bundle_operations',('activity_id',),('bot','persona','operation_id'),(*ns,intent.budget_reservation_operation_id))
    state.add('graph_original_model_cost_attempts_v1',_ATTEMPT_COLUMNS,('bot','persona','call_id'),(*ns,intent.call_id))
    state.add('graph_bundle_sequence',('last_seq',),('bot','persona'),ns)
    state.add('graph_authority_epochs',('access_epoch','delete_epoch'),('bot','persona'),ns)
    state.add('runtime_budget_leases',_LEASE_COLUMNS,('lease_id',),(intent.budget_lease_id,))
    state.lease_ids.add(intent.budget_lease_id)


def _validate_accounting_metadata_v3(state):
    from .model_cost_settlement import OriginalModelCostCommitV1
    from .issuers import _decode_quote
    call=_read_life_metadata_v3(state,'numeric_call_v1')
    binding=_read_life_metadata_v3(state,'numeric_binding_v1')
    acquire=_read_life_metadata_v3(state,'numeric_acquire_commit_v1')
    if (call['prepared_digest']!=binding['prepared_digest'] or acquire['prepared_digest']!=binding['prepared_digest']):
        raise AuthorityUnavailable('Numeric accounting metadata lost actual prepared membership')
    q=state.readers[('runtime_resource_quotes',('quote_json','signature'),('quote_id','version'),(state.quote_id,state.quote_version))].row
    if q is None:raise AuthorityUnavailable('Numeric accounting real signed quote unavailable')
    state.quote=_decode_quote(q[0])
    state.graph._GraphCoordinator__d02_issuer._signer.verify('resource-quote.v1',q[0],q[1])
    intent=state.intent
    from .d11_types import runtime_job_key
    if (state.quote.work_kind!='d06.encode_internal_life_numeric'
            or (state.quote.bot_id,state.quote.persona_id)!=state.namespace.as_tuple
            or state.quote.graph_job_ref!=runtime_job_key(*state.namespace.as_tuple,state.quote.activity_id,intent.job_id).token
            or state.quote.operation_id!=intent.budget_reservation_operation_id
            or state.quote.parent_budget_lease_ref!=intent.budget_lease_id or dict(state.quote.ceiling)!=dict(intent.budget_ceiling)):
        raise AuthorityUnavailable('Numeric accounting actual Root/quote/call/reservation identity differs')
    request=('graph_bundle_operations',_COST_COLUMNS,('bot','persona','operation_id'),(*state.namespace.as_tuple,state.cost_operation))
    row=state.readers[request].row
    from .d11_types import runtime_cost_settlement_key
    cost_ref=runtime_cost_settlement_key(*state.namespace.as_tuple,state.quote.activity_id,state.cost_operation).token
    ns=state.namespace.as_tuple
    state.add('graph_events',('event_id',),('bot','persona','session','event_id'),(*ns,state.quote.activity_id,state.cost_operation))
    state.add('graph_atoms',('revision','valid'),('token',),(cost_ref,))
    state.add('graph_history',('event_id','valid','event_bot','event_persona'),('token','revision'),(cost_ref,1))
    attempt=state.readers[('graph_original_model_cost_attempts_v1',_ATTEMPT_COLUMNS,('bot','persona','call_id'),(*ns,state.intent.call_id))].row
    if attempt is not None:
        from dataclasses import fields
        from .restore_anchor import RestoreAnchor
        anchor=json.loads(attempt[2])
        if set(anchor)!={field.name for field in fields(RestoreAnchor)} or attempt[0]!=canonical_digest(asdict(state.intent)) or attempt[3]not in {'open','closed','committed'}:
            raise AuthorityUnavailable('Numeric accounting actual prior attempt metadata identity/schema differs')
        original_anchor=RestoreAnchor(**anchor)
        if (original_anchor.authority_id,original_anchor.namespace)!=(state.intent.authority_id,state.intent.namespace):
            raise AuthorityUnavailable('Numeric accounting prior anchor belongs to another original authority')
    if row is not None:
        raw=json.loads(row[-1])
        if set(raw)!={'original_model_cost','original_intent_digest','terminal_receipt_digest','quote_id','quote_version','work_kind','accounting_attempt_id'}:
            raise AuthorityUnavailable('Numeric accounting saved cost receipt has another closed schema')
        committed=OriginalModelCostCommitV1(**raw['original_model_cost'])
        if (committed.operation_id!=state.cost_operation or committed.call_id!=intent.call_id
                or raw['original_intent_digest']!=canonical_digest(asdict(intent))
                or raw['terminal_receipt_digest']!=canonical_digest(asdict(state.fact.receipt))
                or raw['quote_id']!=state.quote_id or raw['quote_version']!=state.quote_version
                or raw['work_kind']!='d06.encode_internal_life_numeric'):
            raise AuthorityUnavailable('Numeric accounting immutable saved cost membership differs')
        ns=state.namespace.as_tuple
        state.add('graph_events',('event_id',),('bot','persona','session','event_id'),(*ns,row[1],state.cost_operation))
        state.add('graph_atoms',('revision','valid'),('token',),(committed.cost_ref,))
        state.add('graph_history',('event_id','valid','event_bot','event_persona'),('token','revision'),(committed.cost_ref,1))
    return state


def advance_current_life_numeric_accounting_v3(graph,work):
    state=require_numeric_accounting_work_v3(work.state)
    with bind_runtime_storage_operation_v3(work.operation,state.db),bind_numeric_accounting_metadata_v3(state):
        if state.phase=='terminal':
            state.fact=read_original_model_cost(graph._GraphCoordinator__model_terminal_cost_port,state.intent)
            if state.fact.recovery.state!='observed':raise AuthorityUnavailable('Unobserved Numeric cost retains its original reservation; HOLD')
            with state.store._lock,runtime_storage_quantum_v3(state.db):state.graph_stamp=graph._v2_graph_stamp(state.namespace)
            _prepare_accounting_recipe_v3(state);state.phase='metadata'
            return GraphStorageStepV3('progress')
        if state.phase=='commit':
            result=graph._commit_original_model_cost_v1(state.bootstrap,state.namespace,state.intent,
                quote_id=state.quote_id,quote_version=state.quote_version,work_kind='d06.encode_internal_life_numeric')
            state.committed=result
            return GraphStorageStepV3('complete',result)
        with state.store._lock,runtime_storage_quantum_v3(state.db)as meter:
            state.db.execute('BEGIN')
            try:
                state.require_current(meter=meter)
                if state.pending is not None:
                    state.pending.advance(meter)
                    if state.pending.complete:
                        state.readers[state.pending.request]=state.pending;state.pending=None
                    return GraphStorageStepV3('progress')
                if state.queue:
                    request=state.queue.pop(0);state.pending=_NumericAccountingColumnV3(_ISSUER,state,request)
                    return GraphStorageStepV3('progress')
                for lease_id in tuple(state.lease_ids):
                    request=('runtime_budget_leases',_LEASE_COLUMNS,('lease_id',),(lease_id,))
                    row=state.readers[request].require_row(meter)
                    if row is None or row[2:4]!=state.namespace.as_tuple:
                        raise AuthorityUnavailable('Numeric accounting original Root/ancestor lease namespace differs')
                    if row[1] is not None and row[1] not in state.lease_ids:
                        state.lease_ids.add(row[1]);state.add('runtime_budget_leases',_LEASE_COLUMNS,('lease_id',),(row[1],))
                        return GraphStorageStepV3('progress')
                _validate_accounting_metadata_v3(state)
                if state.queue:return GraphStorageStepV3('progress')
                state.phase='commit'
            finally:state.db.rollback()
        return GraphStorageStepV3('progress')


def finish_current_life_numeric_accounting_v3(graph,work,error):
    state=work.state
    state.release_payload_v3();finish_runtime_storage_operation_v3(work.operation)


def bind_numeric_accounting_grant_v3(graph,request,grant):
    state=numeric_accounting_state_v3(graph)
    if state is None:return
    from ..authority_service.v2_accounting_contract import AccountingMaintenanceRequestV1,AccountingMaintenanceGrantV1
    if (state.phase!='commit' or type(request)is not AccountingMaintenanceRequestV1 or request.intent!=state.intent
            or type(grant)is not AccountingMaintenanceGrantV1 or grant.permit.operation_id!=request.operation_id
            or grant.call_id!=state.intent.call_id or grant.reservation_digest!=state.intent.budget_reservation_digest
            or grant.admission_id!=state.fact.admission.admission_id
            or grant.observation_digest!=state.fact.recovery.observation_digest):
        raise AuthorityUnavailable('Numeric metadata cannot replace the actual Accounting maintenance permission')
    state.accounting_request,state.accounting_grant=request,grant


@contextmanager
def numeric_accounting_quantum_v3(graph):
    state=numeric_accounting_state_v3(graph)
    if state is None:yield;return
    with runtime_storage_quantum_v3(state.db)as meter:
        state.require_current(meter=meter)
        yield meter


def numeric_accounting_attempt_transition_v3(graph,request,status):
    state=numeric_accounting_state_v3(graph)
    if state is None:return
    from ..authority_service.v2_accounting_contract import AccountingMaintenanceRequestV1
    if type(request)is not AccountingMaintenanceRequestV1 or request.intent!=state.intent or state.phase!='commit' or status not in {'open','closed','committed'}:
        raise AuthorityUnavailable('Numeric accounting attempted another original fence transition')
    if status=='committed' and (state.accounting_request!=request or state.accounting_grant is None or state.committed is None):
        raise AuthorityUnavailable('Numeric cost commit transition needs its real Accounting result')
    key=('graph_original_model_cost_attempts_v1',_ATTEMPT_COLUMNS,('bot','persona','call_id'),(*state.namespace.as_tuple,state.intent.call_id))
    prior=state.readers[key].row
    previous=state.transitions.get(key,prior)
    if status=='open':
        if previous is not None and previous[3]!='closed':raise AuthorityUnavailable('Numeric accounting attempt was not closed before its real new open')
    elif previous is None or previous[1]!=request.operation_id or previous[3]!='open':
        raise AuthorityUnavailable('Numeric accounting transition is not the exact original open attempt')
    state.transitions[key]=(canonical_digest(asdict(state.intent)),request.operation_id,canonical_serialize(asdict(request.expected_anchor)),status)
    state.dirty.add(key)


def numeric_accounting_graph_cas_v3(graph,receipt,candidate):
    state=numeric_accounting_state_v3(graph)
    if state is None:return
    from .d11_types import runtime_cost_settlement_key
    key=runtime_cost_settlement_key(*state.namespace.as_tuple,state.quote.activity_id,state.cost_operation)
    if (state.accounting_grant is None or receipt.status!='committed' or candidate.event.event_id!=state.cost_operation
            or len(candidate.writes)!=1 or candidate.writes[0].key!=key
            or len(receipt.revisions)!=1 or receipt.revisions[0].key!=key or receipt.revisions[0].revision!=1):
        raise AuthorityUnavailable('Numeric accounting observed another Graph mutation')
    state.graph_stamp=graph._v2_graph_stamp(state.namespace)
    for request in state.allowed:
        if request[0]in {'graph_events','graph_atoms','graph_history','graph_bundle_sequence'}:state.dirty.add(request)


def numeric_accounting_cost_receipt_v3(graph,result,receipt_data):
    state=numeric_accounting_state_v3(graph)
    if state is None:return
    from .model_cost_settlement import OriginalModelCostCommitV1
    if (type(result)is not OriginalModelCostCommitV1 or result.operation_id!=state.cost_operation
            or result.call_id!=state.intent.call_id or receipt_data['accounting_attempt_id']!=state.accounting_request.operation_id
            or receipt_data['original_model_cost']!=asdict(result)):
        raise AuthorityUnavailable('Numeric accounting actual result changed its original once producer')
    state.committed=result
    state.dirty.add(('graph_bundle_operations',_COST_COLUMNS,('bot','persona','operation_id'),(*state.namespace.as_tuple,state.cost_operation)))


def numeric_accounting_budget_transition_v3(db,lease,operation_id,phase,digest,receipt):
    state=_BOUND.get()
    if state is None:return
    require_numeric_accounting_work_v3(state)
    from .budget import BudgetReceipt
    if (db is not state.db or state.accounting_grant is None or phase!='settle' or type(receipt)is not BudgetReceipt
            or operation_id!=state.intent.budget_reservation_operation_id or lease.lease_id!=state.intent.budget_lease_id
            or digest!=state.intent.budget_reservation_digest or receipt.operation_id!=operation_id or receipt.lease_id!=lease.lease_id):
        raise AuthorityUnavailable('Numeric accounting cannot adopt another producer budget transition')
    lease_key=('runtime_budget_leases',_LEASE_COLUMNS,('lease_id',),(lease.lease_id,))
    prior=state.readers[lease_key].row
    if prior is None or prior[9]+1!=lease.version or prior[0:5]!=(lease.lease_id,lease.parent_id,lease.bot_id,lease.persona_id,lease.currency):
        raise AuthorityUnavailable('Numeric accounting Root counter is not its actual once settlement successor')
    state.transitions[lease_key]=(lease.lease_id,lease.parent_id,lease.bot_id,lease.persona_id,lease.currency,
        canonical_serialize(lease.limits),canonical_serialize(lease.used),canonical_serialize(lease.reserved),canonical_serialize(lease.unconfirmed),lease.version,lease.state)
    state.dirty.update((lease_key,
        ('runtime_budget_reservations',_RESERVATION_COLUMNS,('lease_id','operation_id'),(lease.lease_id,operation_id)),
        ('runtime_budget_operations',_BUDGET_COLUMNS,('bot_id','persona_id','operation_id','phase'),(*state.namespace.as_tuple,operation_id,'settle'))))


def _project_accounting_request_v3(state,table,columns,keys,key):
    columns,keys,key=tuple(columns),tuple(keys),tuple(key)
    candidates=[request for request in state.allowed if request[0]==table and request[2]==keys and request[3]==key
        and (columns==('1',) or set(columns)<=set(request[1]))]
    if len(candidates)!=1:raise AuthorityUnavailable('Numeric accounting consumer requested an undeclared exact metadata shape/key')
    return candidates[0],columns


def _read_current_accounting_column_v3(state,request,meter):
    column=_NumericAccountingColumnV3(_ISSUER,state,request)
    while not column.complete:column.advance(meter)
    if request in state.transitions and column.row!=state.transitions[request]:
        raise AuthorityUnavailable('Numeric accounting current metadata is not the exact actual producer transition')
    if request[0]=='graph_bundle_operations' and 'receipt_json'in request[1] and column.row is not None:
        value=json.loads(column.values['receipt_json'])
        if set(value)!={'original_model_cost','original_intent_digest','terminal_receipt_digest','quote_id','quote_version','work_kind','accounting_attempt_id'}:
            raise AuthorityUnavailable('Numeric accounting mutable cost receipt left its closed schema')
        if state.committed is not None and value['original_model_cost']!=asdict(state.committed):
            raise AuthorityUnavailable('Numeric accounting receipt is not the actual same-transaction result')
    old=state.readers.get(request)
    if old is not None:_COLUMNS.pop(old,None)
    state.readers[request]=column;state.dirty.discard(request)
    return column


def numeric_accounting_current_point_v3(db,*,table,columns,key_columns,key):
    state=_BOUND.get()
    if state is None:return False,None
    require_numeric_accounting_work_v3(state)
    if db is not state.db:raise AuthorityUnavailable('Numeric accounting current point crossed DB')
    request,projection=_project_accounting_request_v3(state,table,columns,key_columns,key)
    with runtime_storage_quantum_v3(db)as meter:
        reader=_read_current_accounting_column_v3(state,request,meter)if request in state.dirty else state.readers[request]
        row=reader.require_row(meter)
        if row is None:return True,None
        if projection==('1',):return True,(1,)
        values=dict(zip(request[1],row))
        return True,tuple(values[name]for name in projection)


def numeric_accounting_signed_quote_v3(db,issuer,quote_id,version):
    state=_BOUND.get()
    if state is None:return False,None
    require_numeric_accounting_work_v3(state)
    if issuer is not state.graph._GraphCoordinator__d02_issuer or (quote_id,version)!=(state.quote_id,state.quote_version):
        raise AuthorityUnavailable('Numeric accounting crossed its actual signed quote issuer or once selector')
    handled,row=numeric_accounting_current_point_v3(db,table='runtime_resource_quotes',columns=('quote_json','signature'),
        key_columns=('quote_id','version'),key=(quote_id,version))
    if row is None:raise AuthorityUnavailable('Numeric accounting signed original quote missing')
    issuer._signer.verify('resource-quote.v1',row[0],row[1])
    from .issuers import _decode_quote
    return True,_decode_quote(row[0])


def numeric_accounting_rollback_v3(graph):
    state=numeric_accounting_state_v3(graph)
    if state is None:return
    if state.db.in_transaction:raise AuthorityUnavailable('Numeric Accounting rollback origin must be completed SQLite rollback')
    state.graph_stamp=graph._v2_graph_stamp(state.namespace)
    state.transitions.clear();state.committed=None
    state.dirty.update(request for request in state.allowed if request[0]not in {'runtime_resource_quotes','graph_d11_life_originals_v1'})
