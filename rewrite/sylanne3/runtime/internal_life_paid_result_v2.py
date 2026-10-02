"""Actual Life worker cost/result originals; decoding grants no current rights.

The separate table has an explicit immutable closed inventory. A populated
inventory remains C09 HOLD until its authenticated disposal is implemented.
"""
from dataclasses import asdict, fields
import json
import sqlite3

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_types import AtomKey
from .internal_life_content_worker_v2 import read_life_worker_original_v2,read_committed_internal_life_request_v2
from .model_cost_settlement import OriginalModelCostCommitV1,original_model_cost_operation_id_v1
from ..model_broker.internal_life_content_v1 import WORK_KIND,thaw_internal_life_content_request_v1

TABLE='graph_internal_life_paid_originals_v2'
SIGN_KIND='d06.internal-life-paid-original.v2'
DDL=f'CREATE TABLE {TABLE} (bot TEXT NOT NULL, persona TEXT NOT NULL, kind TEXT NOT NULL, original_ref TEXT NOT NULL, payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL, signature TEXT NOT NULL, PRIMARY KEY(bot,persona,kind,original_ref))'
TRIGGERS=tuple(f"CREATE TRIGGER {TABLE}_no_{a.lower()} BEFORE {a} ON {TABLE} BEGIN SELECT RAISE(ABORT,'Life paid original is immutable'); END" for a in ('UPDATE','DELETE'))
COLUMNS=('bot','persona','kind','original_ref','payload_json','payload_digest','signature')

def require_life_paid_schema_v2(db):
    with sqlite3.connect(':memory:') as expected:
        expected.execute(DDL)
        for statement in TRIGGERS:expected.execute(statement)
        query='SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name'
        if tuple(db.execute(query,(TABLE,)))!=tuple(expected.execute(query,(TABLE,))):
            raise ValueError('Life paid original exact schema/immutable triggers/index inventory differs')

def install_life_paid_schema_v2(db):
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone() is None:
        db.execute(DDL)
        for statement in TRIGGERS:db.execute(statement)
    require_life_paid_schema_v2(db)

def validate_life_paid_inventory_v2(columns,row):
    from ..authority_service.internal_life_model_result_contract_v2 import (
        InternalLifeModelResultReadRequestV2,InternalLifeModelResultReadV2,internal_life_result_from_wire_v2)
    if tuple(columns)!=COLUMNS or type(row) not in (tuple,list) or len(row)!=7:raise ValueError('Life paid inventory columns differ')
    bot,persona,kind,ref,wire,digest,signature=row;ns=NamespaceId(bot,persona)
    from .d06_internal_life_episode_v2 import _sha
    _sha(digest);_sha(signature)
    if type(wire) is not str or len(wire)>1048576:raise ValueError("Life paid inventory exceeds finite original bound")
    raw=json.loads(wire)
    if canonical_serialize(raw)!=wire or canonical_digest(raw)!=digest:raise ValueError('Life paid inventory canonical bytes differ')
    if kind=='read_attempt':
        value=internal_life_result_from_wire_v2(raw,InternalLifeModelResultReadRequestV2)
        if value.namespace!=ns or value.read_attempt_id!=ref:raise ValueError('Life read attempt scope differs')
    elif kind=='result':
        value=internal_life_result_from_wire_v2(raw,InternalLifeModelResultReadV2)
        if value.request.namespace!=ns or value.request.job_id!=ref:raise ValueError('Life result original scope differs')
    elif kind=='adoption_commit':
        from .domain_production_originals_v1 import _receipt,_receipt_wire
        if type(raw) is not dict or set(raw)!={'schema','job_id','result_digest','trace_ref','operation_id','receipt','receipt_digest'}:
            raise ValueError('Life content adoption original fields differ')
        receipt=_receipt(raw['receipt']);_sha(raw['result_digest']);_sha(raw['receipt_digest'])
        if (raw['schema']!='d06.internal-life-content-adoption-commit.v1' or raw['job_id']!=ref
                or receipt.operation_id!=raw['operation_id'] or receipt.status!='committed'
                or canonical_digest(receipt)!=raw['receipt_digest']
                or canonical_serialize(_receipt_wire(receipt))!=canonical_serialize(raw['receipt'])):
            raise ValueError('Life adoption original receipt differs')
    else:raise ValueError('unregistered Life paid original kind')
    return raw

def read_life_paid_original_v2(db,namespace,issuer,kind,ref):
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone() is None:return None
    require_life_paid_schema_v2(db)
    row=db.execute(f'SELECT payload_json,payload_digest,signature FROM {TABLE} WHERE bot=? AND persona=? AND kind=? AND original_ref=?',(*namespace.as_tuple,kind,ref)).fetchone()
    if row is None:return None
    raw=validate_life_paid_inventory_v2(COLUMNS,(*namespace.as_tuple,kind,ref,*row))
    issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,kind,ref,row[1])),row[2])
    return raw

def record_life_paid_original_v2(db,namespace,issuer,kind,ref,value):
    if type(db) is not sqlite3.Connection or not db.in_transaction:raise ValueError('Life paid original requires actual SQL transaction')
    install_life_paid_schema_v2(db)
    raw=plain_v1(value);wire=canonical_serialize(raw);digest=canonical_digest(raw)
    sig=issuer._signer.sign(SIGN_KIND,canonical_serialize((namespace,kind,ref,digest)))
    row=(*namespace.as_tuple,kind,ref,wire,digest,sig);validate_life_paid_inventory_v2(COLUMNS,row)
    old=read_life_paid_original_v2(db,namespace,issuer,kind,ref)
    if old is not None:
        if old!=raw:raise ValueError('Life once paid original cannot change')
        return raw
    db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)',row);return raw

def read_life_cost_commit_v2(db,*,namespace,issuer,prepared,intent,terminal,fact=None):
    """Exact seven-field accounting family, distinct from a Domain COMMIT."""
    from ..contracts import canonical_json
    from .budget import _receipt_from_json
    if not db.in_transaction:raise ValueError('Life actual cost requires a pinned SQL snapshot')
    sealed=read_life_worker_original_v2(db,namespace=namespace,issuer=issuer,kind='call',job_id=prepared.job_id)
    from ..authority_service.v2_model_egress_wire import to_wire
    if sealed is None or sealed['intent']!=to_wire(intent):raise ValueError('Life cost lacks authenticated sealed call')
    op=original_model_cost_operation_id_v1(namespace,prepared.call_id)
    row=db.execute('SELECT activity_id,effect_id,commit_seq,receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,op)).fetchone()
    if row is None:raise ValueError('Life actual paid cost COMMIT absent')
    raw=json.loads(row[3])
    if type(raw) is not dict or set(raw)!={'original_model_cost','original_intent_digest','terminal_receipt_digest','quote_id','quote_version','work_kind','accounting_attempt_id'} or canonical_json(raw)!=row[3]:
        raise ValueError('Life cost actual receipt closed fields differ')
    c=raw['original_model_cost']
    if type(c) is not dict or set(c)!={f.name for f in fields(OriginalModelCostCommitV1)}:raise ValueError('Life actual typed cost fields differ')
    for n in ('quote_version','commit_seq','graph_revision','graph_epoch'):
        if type(c[n]) is not int or c[n]<1:raise ValueError('Life cost version is not strict positive integer')
    cost=OriginalModelCostCommitV1(**c);quote=issuer.resource_issuer.original_signed_quote(db,prepared.quote_id,prepared.quote_version)
    budget=db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",(*namespace.as_tuple,prepared.prepare_operation_id)).fetchone()
    reservation=db.execute('SELECT state,digest FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',(quote.parent_budget_lease_ref,prepared.prepare_operation_id)).fetchone()
    attempt=db.execute('SELECT state,attempt_id FROM graph_original_model_cost_attempts_v1 WHERE bot=? AND persona=? AND call_id=?',(*namespace.as_tuple,prepared.call_id)).fetchone()
    digest=canonical_digest(asdict(terminal))
    if (budget is None or reservation!=('settled',prepared.reservation_digest)
            or attempt!=('committed',raw['accounting_attempt_id']) or raw['original_intent_digest']!=canonical_digest(asdict(intent))
            or raw['terminal_receipt_digest']!=digest or raw['work_kind']!=WORK_KIND or type(raw['quote_version']) is not int
            or (raw['quote_id'],raw['quote_version'])!=(prepared.quote_id,prepared.quote_version)
            or (cost.schema,cost.status,cost.operation_id,cost.call_id,cost.quote_id,cost.quote_version,cost.terminal_receipt_digest,cost.commit_seq)!=
               ('sylanne.d11.original-model-cost-commit.v1','committed',op,prepared.call_id,prepared.quote_id,prepared.quote_version,digest,row[2])
            or cost.budget_receipt_digest!=canonical_digest(asdict(_receipt_from_json(budget[0])))
            or (row[0],row[1])!=(prepared.activity_id,quote.effect_id)):
        raise ValueError('Life actual cost/quote/settlement/original call linkage differs')
    key=AtomKey.from_token(cost.cost_ref)
    if key.type_name!='runtime.cost_settlement' or NamespaceId.from_key(key)!=namespace:raise ValueError('Life cost locator differs')
    event=db.execute('SELECT reads,revisions,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?',(*namespace.as_tuple,prepared.activity_id,op)).fetchone()
    def pair(encoded,rev):
        a=json.loads(encoded)
        return type(a) is list and len(a)==1 and type(a[0]) is list and len(a[0])==2 and type(a[0][0]) is str and a[0][0]==key.token and type(a[0][1]) is int and a[0][1]==rev and canonical_json(a)==encoded
    history=db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=1',(key.token,)).fetchone()
    head=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
    if (event is None or not pair(event[0],0) or not pair(event[1],1) or event[2]!=cost.graph_epoch
            or history is None or history[0]!=op or history[2]!=1 or head!=(1,history[1],1)):
        raise ValueError('Life cost actual exact event/history/immutable head differs')
    value=json.loads(history[1])
    from .d11_types import RuntimeCostSettlement,cost_settlement_from_runtime
    expected=cost_settlement_from_runtime(db,bot_id=namespace.bot_id,persona_id=namespace.persona_id,
        activity_id=prepared.activity_id,bundle_operation_id=op,effect_id=quote.effect_id,
        settlement_id=op,lease_id=quote.parent_budget_lease_ref,cost_operation_id=prepared.prepare_operation_id,
        budget_operation_id=prepared.prepare_operation_id,budget_phase='settle',prior_unknown_ref=None,
        execution_revoked=True)
    if (type(value) is not dict or canonical_serialize(value)!=history[1]
            or canonical_serialize(plain_v1(expected))!=history[1]
            or expected.status!='settled' or expected.unconfirmed):
        raise ValueError('Life cost unknown dimensions or noncanonical body HOLD')
    if fact is not None:
        from .model_cost_settlement import OriginalModelCostFactV1,original_model_budget_actual
        if (type(fact) is not OriginalModelCostFactV1 or fact.intent!=intent or fact.receipt!=terminal
                or dict(expected.actual)!=original_model_budget_actual(fact,quote,work_kind=WORK_KIND)):
            raise ValueError('Life cost measured amount differs from actual Authority observation')
    return cost

def prepare_life_result_selector_v2(db,*,namespace,issuer,job_id,authority_id,authority_namespace,attempt=1):
    from ..authority_service.internal_life_model_result_contract_v2 import InternalLifeModelResultReadRequestV2,internal_life_content_read_attempt_id_v2
    from ..authority_service.v2_model_egress_wire import from_wire
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    prepared,binding,model=read_committed_internal_life_request_v2(db,namespace=namespace,issuer=issuer,job_id=job_id)
    sealed=read_life_worker_original_v2(db,namespace=namespace,issuer=issuer,kind='call',job_id=job_id)
    if sealed is None:raise ValueError('Life result selector lacks actual sealed model call')
    intent=from_wire(sealed['intent'],ModelEgressIntentV1)
    frozen=thaw_internal_life_content_request_v1(json.loads(prepared.frozen_json));consumer='life-content-adopt:'+job_id.removeprefix('life-content-job:')
    request=InternalLifeModelResultReadRequestV2(authority_id,authority_namespace,namespace,prepared.installation_id,
        prepared.episode_ref,prepared.occurrence_digest,frozen.input.cause.occurrence.event.causal_operation_id,
        job_id,prepared.acquire_operation_id,prepared.prepare_operation_id,prepared.call_id,binding.digest,prepared.digest,
        model.digest,consumer,internal_life_content_read_attempt_id_v2(consumer,attempt))
    if (intent.authority_id,intent.namespace)!=(authority_id,authority_namespace):raise ValueError('Life result selector crossed Authority')
    record_life_paid_original_v2(db,namespace,issuer,'read_attempt',request.read_attempt_id,request)
    return request
