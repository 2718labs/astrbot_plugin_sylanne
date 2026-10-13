"""Named reconciliation of independently observed D13 counter CPU and Body cost."""
from dataclasses import dataclass,asdict,fields,replace
import hashlib,json
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..authority_service.internal_accounting_v1 import (HistoricalInternalCostEvidenceV1,
    HistoricalInternalCostRequestV1,HistoricalInternalCostGrantV1,from_wire,to_wire)
from ..authority_service.d13_core_counter_contract_v1 import D13CounterAwaitingAccountingV1
from ..domains.d02 import BodyDomain,BodyState,BodyReservation
from ..contracts import Event,Scope,canonical_json
from ..graph_types import AtomKey,GraphVersion,GraphCandidate
from ..graph_store import GraphStore
from .budget import get_budget_lease,settle_budget
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from .c04_historical_accounting_v1 import _body_lineage
from .d11_c04_internal_cost import C04CpuCostOriginalV1
from ..domains.d02.c04_fixed_component_cost import C04BodyCostOriginalV1
from .d11_types import cost_settlement_from_runtime,cost_settlement_graph_write,job_graph_write
from .jobs import get_job,_save_job
from .first_ingress_v2 import trusted_upper

CPU_TABLE='d11_d13_counter_cpu_cost_originals_v1'
BODY_TABLE='d02_d13_counter_body_cost_originals_v1'
ATTEMPT_TABLE='graph_d13_counter_accounting_attempts_v1'

class D13CounterAccountingHold(ValueError):
    """Real original bill requires reconciliation; this never asserts zero CPU."""

@dataclass(frozen=True)
class D13CounterCpuCostOriginalV1(C04CpuCostOriginalV1):
    schema:str='sylanne3.d13.counter.cpu-cost-original.v1'

@dataclass(frozen=True)
class D13CounterBodyCostOriginalV1(C04BodyCostOriginalV1):
    schema:str='sylanne3.d13.counter.body-cost-original.v1'

@dataclass(frozen=True)
class D13CounterCostStageV1:
    cpu:D13CounterCpuCostOriginalV1
    writes:tuple
    reads:tuple
    body_original:D13CounterBodyCostOriginalV1|None
    body_gap:str|None

TABLE_DDLS=tuple((table,f'CREATE TABLE {table} (bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,original_json TEXT NOT NULL,original_digest TEXT NOT NULL,PRIMARY KEY(bot,persona,operation_id))') for table in (CPU_TABLE,BODY_TABLE))
TRIGGER_DDLS=tuple((f'{table}_{op.lower()}_immutable',f"CREATE TRIGGER {table}_{op.lower()}_immutable BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'immutable D13 counter accounting original'); END") for table in (CPU_TABLE,BODY_TABLE) for op in ('UPDATE','DELETE'))
ATTEMPT_DDL='CREATE TABLE graph_d13_counter_accounting_attempts_v1 (bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,binding_digest TEXT NOT NULL,request_json TEXT NOT NULL,receipt_json TEXT,PRIMARY KEY(bot,persona,operation_id))'

def install_d13_counter_accounting_schema_v1(db):
    for name,kind,ddl in (*((n,'table',d) for n,d in TABLE_DDLS),(ATTEMPT_TABLE,'table',ATTEMPT_DDL),*((n,'trigger',d) for n,d in TRIGGER_DDLS)):
        old=db.execute('SELECT sql FROM sqlite_master WHERE type=? AND name=?',(kind,name)).fetchone()
        if old is None:db.execute(ddl)
        elif old!=(ddl,):raise D13CounterAccountingHold('registered D13 accounting schema differs')

def _read(db,namespace,operation_id,table,cls):
    if not db.in_transaction:raise D13CounterAccountingHold('actual accounting transaction required')
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() is None:return None
    row=db.execute(f'SELECT original_json,original_digest FROM {table} WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)).fetchone()
    if row is None:return None
    raw=json.loads(row[0])
    if type(raw) is not dict or set(raw)!={f.name for f in fields(cls)} or canonical_serialize(raw)!=row[0]:
        raise D13CounterAccountingHold('exact D13 accounting original fields differ')
    raw['namespace']=NamespaceId(**raw['namespace']);value=cls(**raw)
    if (canonical_digest(asdict(value))!=row[1] or value.namespace!=namespace or value.operation_id!=operation_id
            or value.schema!=cls.__dataclass_fields__['schema'].default):
        raise D13CounterAccountingHold('immutable D13 original identity differs')
    return value

def read_d13_counter_cpu_cost_original_v1(db,namespace,operation_id):
    return _read(db,namespace,operation_id,CPU_TABLE,D13CounterCpuCostOriginalV1)

def read_d13_counter_body_cost_original_v1(db,namespace,operation_id):
    return _read(db,namespace,operation_id,BODY_TABLE,D13CounterBodyCostOriginalV1)


def stage_d13_counter_cost_in_transaction_v1(db, namespace, evidence, *, resource_issuer, body_authority):
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(evidence) is not HistoricalInternalCostEvidenceV1):
        raise D13CounterAccountingHold("installed historical accounting transaction required")
    binding, operation_id = evidence.binding, evidence.binding.operation_id
    prepared = read_c04_internal_work_prepared_v1(db, namespace, operation_id)
    if prepared is None or prepared.binding != binding:
        raise D13CounterAccountingHold("original C04 preparation differs")
    quote = resource_issuer.original_signed_quote(db, binding.resource_quote_ref, binding.resource_quote_version)
    if (canonical_digest(quote) != binding.resource_quote_digest
            or quote.work_kind != "d13.full_http_counter.v1"
            or quote.parent_budget_lease_ref != binding.parent_budget_lease_ref
            or (quote.bot_id, quote.persona_id, quote.operation_id, quote.activity_id) !=
               (*namespace.as_tuple, operation_id, binding.activity_id)
            or set(quote.ceiling) != {"cpu_ms"}
            or prepared.budget_reservation_operation_id != "d13-counter-budget:" + binding.binding_digest):
        raise D13CounterAccountingHold("historical signed CPU quote differs")
    reserve = db.execute("SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*namespace.as_tuple, prepared.budget_reservation_operation_id)).fetchone()
    lease = get_budget_lease(db, binding.parent_budget_lease_ref)
    reservation = db.execute("SELECT digest,ceiling_json FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (lease.lease_id, prepared.budget_reservation_operation_id)).fetchone()
    if (reserve is None or reserve[:2] != (binding.binding_digest, lease.lease_id)
            or hashlib.sha256(reserve[2].encode()).hexdigest() != prepared.budget_reservation_digest
            or reservation is None or reservation[0] != binding.binding_digest
            or json.loads(reservation[1]) != dict(quote.ceiling)
            or (lease.bot_id, lease.persona_id) != namespace.as_tuple):
        raise D13CounterAccountingHold("original C04 reserve identity differs")
    receipt = settle_budget(db, lease.lease_id, prepared.budget_reservation_operation_id,
        binding.binding_digest, {"cpu_ms": evidence.actual_cpu_ms}, execution_revoked=True)
    if receipt.status not in {"settled", "overrun"}:
        raise D13CounterAccountingHold("original measured CPU remains unaccounted")
    cpu = D13CounterCpuCostOriginalV1(namespace, operation_id, binding.binding_digest,
        prepared.prepared_digest, evidence.proof_digest, evidence.terminal_receipt_ref,
        evidence.terminal_receipt_digest, evidence.status, evidence.actual_cpu_ms, lease.lease_id,
        prepared.budget_reservation_operation_id, prepared.budget_reservation_digest,
        receipt.status, evidence.component_completed)
    prior = read_d13_counter_cpu_cost_original_v1(db, namespace, operation_id)
    if prior is not None and prior != cpu:
        raise D13CounterAccountingHold("historical CPU original conflicts")
    if prior is None:
        db.execute("INSERT INTO d11_d13_counter_cpu_cost_originals_v1 VALUES(?,?,?,?,?)",
            (*namespace.as_tuple, operation_id, canonical_serialize(asdict(cpu)), canonical_digest(asdict(cpu))))
    cost_operation = "d13-counter-cost:" + binding.binding_digest[:48]
    cost = cost_settlement_from_runtime(db, bot_id=namespace.bot_id, persona_id=namespace.persona_id,
        activity_id=binding.activity_id, bundle_operation_id=cost_operation, effect_id=None,
        settlement_id=cost_operation, lease_id=lease.lease_id,
        cost_operation_id=prepared.budget_reservation_operation_id,
        budget_operation_id=prepared.budget_reservation_operation_id, budget_phase="settle",
        prior_unknown_ref=None, execution_revoked=True)
    cost_write = cost_settlement_graph_write(cost)
    writes, reads = [cost_write], [GraphVersion(cost_write.key, 0)]
    body_original = read_d13_counter_body_cost_original_v1(db, namespace, operation_id)
    if body_original is not None:
        if body_original.binding_digest != binding.binding_digest or body_original.proof_digest != evidence.proof_digest:
            raise D13CounterAccountingHold("historical body original conflicts")
        return D13CounterCostStageV1(cpu, tuple(writes), tuple(reads), body_original, None)
    state_row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                          (prepared.body_state_ref, *namespace.as_tuple)).fetchone()
    reservation_row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                          (binding.body_reservation_ref, *namespace.as_tuple)).fetchone()
    if state_row is None or reservation_row is None or state_row[2] != 1 or reservation_row[2] != 1:
        return D13CounterCostStageV1(cpu, tuple(writes), tuple(reads), None, "target_erased")
    try:
        state = BodyState(**json.loads(state_row[1]))
        reserved = BodyReservation(**json.loads(reservation_row[1]))
        _body_lineage(db, prepared.body_state_ref, prepared.body_state_revision, state_row[0], BodyState)
        _body_lineage(db, binding.body_reservation_ref, prepared.body_reservation_revision, reservation_row[0], BodyReservation)
        body_quote = body_authority.original_body_quote(db, binding.body_quote_ref,
            binding.body_quote_version, quote, operation_id)
        if (canonical_digest(body_quote) != binding.body_quote_digest
                or state.profile_id != body_quote.profile_id or state.version != state_row[0]
                or reserved.quote_id != body_quote.quote_id or reserved.effect_id != quote.effect_id):
            raise D13CounterAccountingHold("historical body quote or lineage differs")
        components = tuple(c for c in body_quote.components if c.component_id == binding.component_id)
        if len(components) != 1 or components[0].duration_rate != 0:
            raise D13CounterAccountingHold("historical fixed body component differs")
        if evidence.component_completed:
            settled = BodyDomain().settle_component(state, reserved, binding.component_id,
                actual_cost=components[0].fixed_cost, component_receipt=evidence.component_receipt_ref)
            if settled.duplicate or settled.overrun or settled.unpaid_cost:
                raise D13CounterAccountingHold("historical body charge requires reconciliation")
            settlement_key = AtomKey.from_token(quote.d02_settlement_refs[0])
            body_writes = (BodyDomain.state_write(namespace, settled.state),
                BodyDomain.reservation_write(namespace, binding.activity_id, settled.reservation),
                BodyDomain.settlement_write(namespace, binding.activity_id, settlement_key.name, settled))
            if len(quote.d02_settlement_refs) != 1 or body_writes[-1].key != settlement_key:
                raise D13CounterAccountingHold("historical body settlement reference differs")
            body_original = D13CounterBodyCostOriginalV1(namespace, operation_id, binding.binding_digest,
                evidence.proof_digest, prepared.body_state_ref, binding.body_reservation_ref,
                settlement_key.token, evidence.component_receipt_ref, components[0].fixed_cost,
                canonical_digest(body_writes), "d13-counter-outcome:" + binding.execution_id)
        else:
            # The installed signed failed terminal proves this fixed component
            # did not complete. It releases occupancy, without a body charge.
            cancellation = BodyDomain.release_or_cancel(reserved, execution_known=True)
            body_writes = (BodyDomain.reservation_write(namespace, binding.activity_id, cancellation.reservation),)
        for write in body_writes:
            row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
            reads.append(GraphVersion(write.key, row[0] if row else 0))
        writes.extend(body_writes)
        return D13CounterCostStageV1(cpu, tuple(writes), tuple(reads), body_original, None)
    except (D13CounterAccountingHold, TypeError, ValueError) as exc:
        return D13CounterCostStageV1(cpu, tuple(writes), tuple(reads), None,
                                       "unpaid_requires_reconciliation:" + type(exc).__name__)

def record_d13_counter_body_after_cas_v1(db, stage):
    if not db.in_transaction:
        raise D13CounterAccountingHold("historical body original requires same graph CAS")
    original = stage.body_original
    if original is None:
        return None
    prior = read_d13_counter_body_cost_original_v1(db, original.namespace, original.operation_id)
    if prior is not None:
        if prior != original:
            raise D13CounterAccountingHold("historical body original replay conflicts")
        return prior
    for write in stage.writes:
        row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
        if row is None or row[1] != 1 or json.loads(row[0]) != write.value:
            raise D13CounterAccountingHold("historical body graph CAS missing")
    db.execute("INSERT INTO d02_d13_counter_body_cost_originals_v1 VALUES(?,?,?,?,?)",
        (*original.namespace.as_tuple, original.operation_id, canonical_serialize(asdict(original)), canonical_digest(asdict(original))))
    return original

def settle_current_d13_counter_cpu_v1(graph,bootstrap,bundle,*,frame_intent_id,counter_operation_id,awaiting):
    graph._admin(bootstrap)
    if (type(awaiting) is not D13CounterAwaitingAccountingV1 or awaiting.frame_intent_id!=frame_intent_id
            or awaiting.counter_operation_id!=counter_operation_id or awaiting.namespace!=bundle.installation_policy.namespace):
        raise D13CounterAccountingHold('exact original D13 accounting locator required')
    if awaiting.status=='unknown':raise D13CounterAccountingHold('unknown counter CPU retains original reservation')
    store=graph._GraphCoordinator__store;port=graph._GraphCoordinator__c04_authority_port_v3
    content=graph._GraphCoordinator__content_fence_v2;ns=awaiting.namespace
    if graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not bundle or port is None:
        raise D13CounterAccountingHold('actual D13 historical accounting composition missing')
    with store._lock:
        db=store._db;db.execute('BEGIN')
        try:
            prepared=read_c04_internal_work_prepared_v1(db,ns,counter_operation_id)
            if prepared is None or prepared.binding.binding_digest!=awaiting.binding_digest:
                raise D13CounterAccountingHold('counter original CPU preparation differs')
            jobs=db.execute('SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? AND operation_id=?',(*ns.as_tuple,counter_operation_id)).fetchall()
            if len(jobs)!=1:raise D13CounterAccountingHold('actual counter job locator incomplete')
            job=get_job(db,jobs[0][0])
            saved=db.execute(f'SELECT binding_digest,request_json,receipt_json FROM {ATTEMPT_TABLE} WHERE bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,counter_operation_id)).fetchone()
            metadata,epoch=graph._v2_graph_stamp(ns)
        finally:db.rollback()
    if saved is not None:
        if saved[0]!=prepared.binding.binding_digest:raise D13CounterAccountingHold('accounting original binding changed')
        request=from_wire(json.loads(saved[1]),HistoricalInternalCostRequestV1)
        if saved[2] is not None:
            port.internal_accounting(request,'recover_finish');return json.loads(saved[2])
    else:
        anchor=content.current_anchor(namespace=ns,authority_namespace=metadata.requirements.authority_namespace)
        if not graph._accounting_anchor_covers(metadata.requirements,anchor):raise D13CounterAccountingHold('current accounting anchor changed')
        request=HistoricalInternalCostRequestV1('d13-counter-account:'+canonical_digest((ns,counter_operation_id,prepared.binding.binding_digest,anchor))[:48],prepared.binding,anchor)
        with store._lock:
            db.execute('BEGIN IMMEDIATE')
            try:
                if graph._v2_graph_stamp(ns)!=(metadata,epoch):raise D13CounterAccountingHold('Graph changed before accounting intent')
                db.execute(f'INSERT INTO {ATTEMPT_TABLE} VALUES(?,?,?,?,?,NULL)',(*ns.as_tuple,counter_operation_id,prepared.binding.binding_digest,canonical_json(to_wire(request))));db.commit()
            except BaseException:db.rollback();raise
    grant=port.internal_accounting(request,'begin')
    if (type(grant) is not HistoricalInternalCostGrantV1 or grant.evidence.binding!=prepared.binding
            or grant.evidence.terminal_receipt_digest!=awaiting.terminal_receipt_digest or grant.evidence.status!=awaiting.status):
        raise D13CounterAccountingHold('actual Core observed counter terminal differs')
    port.internal_accounting(request,'validate',grant)
    now=trusted_upper(content.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    with store._lock:
        db.execute('BEGIN IMMEDIATE')
        try:
            current,current_epoch=graph._v2_graph_stamp(ns)
            if (current,current_epoch)!=(metadata,epoch) or get_job(db,job.job_id)!=job:
                raise D13CounterAccountingHold('original counter accounting snapshot changed')
            stage=stage_d13_counter_cost_in_transaction_v1(db,ns,grant.evidence,
                resource_issuer=graph._GraphCoordinator__d02_issuer,body_authority=graph._GraphCoordinator__body_quote_authority)
            if stage.body_gap is not None:raise D13CounterAccountingHold('actual Body bill requires reconciliation')
            binding=prepared.binding
            if (job.operation_id,job.activity_id,job.effect_id,job.work_kind)!=(counter_operation_id,binding.activity_id,binding.execution_id,'d13.full_http_counter.v1'):
                raise D13CounterAccountingHold('original counter CPU job identity differs')
            if job.phase!='running' or job.cancel_epoch or job.continuation.get('binding_digest')!=binding.binding_digest:
                raise D13CounterAccountingHold('counter original job is not the adopted execution')
            closed=replace(job,phase='completed' if awaiting.status=='completed' else 'failed',lease_holder=None,lease_expires_utc=None,
                usage={**job.usage,'cpu_ms':grant.evidence.actual_cpu_ms},result_ref='d13-counter-terminal:'+awaiting.terminal_digest[:48],wake_condition=None)
            job_write=job_graph_write(closed);row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(job_write.key.token,)).fetchone()
            if row is None or row[2]!=1 or json.loads(row[1])!=job_graph_write(job).value:
                raise D13CounterAccountingHold('counter job Graph projection changed')
            candidate=GraphCandidate(Event(Scope(*ns.as_tuple,'d13-counter-v1'),counter_operation_id+':settle',now,
                'd13.counter.cpu.accounted.v1',{'frame_intent_id':frame_intent_id,'binding_digest':binding.binding_digest,'terminal_digest':awaiting.terminal_digest}),
                (*stage.reads,GraphVersion(job_write.key,row[0])),(*stage.writes,job_write),(current_epoch,))
            _save_job(db,closed)
            receipt=GraphStore._graph_commit_in_transaction(store,candidate,_capability=graph._GraphCoordinator__graph_capability)
            body=record_d13_counter_body_after_cas_v1(db,stage)
            anchor=request.expected_anchor
            replacement=replace(current.requirements,activation_generation=anchor.activation_generation,fence_epoch=anchor.fence_epoch,
                deletion_seq=anchor.deletion_seq,deletion_digest=anchor.deletion_digest,execution_seq=anchor.execution_seq,
                execution_digest=anchor.execution_digest,revocation_epoch=anchor.revocation_epoch)
            store.cas_graph_recovery_metadata(current,replacement,_capability=graph._GraphCoordinator__graph_capability)
            result={'schema':'sylanne3.d13.counter-accounting-receipt.v1','frame_intent_id':frame_intent_id,'operation_id':counter_operation_id,
                'binding_digest':binding.binding_digest,'cpu_original_digest':canonical_digest(asdict(stage.cpu)),
                'body_original_digest':None if body is None else canonical_digest(asdict(body)),
                'graph_receipt_digest':canonical_digest(receipt),'job_id':closed.job_id,'status':closed.phase}
            db.execute(f'UPDATE {ATTEMPT_TABLE} SET receipt_json=? WHERE bot=? AND persona=? AND operation_id=? AND receipt_json IS NULL',
                (canonical_json(result),*ns.as_tuple,counter_operation_id))
            if db.execute('SELECT changes()').fetchone()!=(1,):raise D13CounterAccountingHold('counter accounting receipt raced')
            db.commit()
        except BaseException:db.rollback();raise
    port.internal_accounting(request,'finish',grant)
    return result
