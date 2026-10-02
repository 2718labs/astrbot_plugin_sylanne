"""Actual SQL/event/history cost-family reader; signing/quote issuer are seams.

This closed read does not issue model/Owner/Source permission. The installed
paired reader separately authenticates seven signed paid originals.
"""
from dataclasses import asdict
import json,sqlite3
from types import SimpleNamespace
import pytest
from sylanne3.contracts import canonical_json
from sylanne3.graph_types import AtomKey,Owner
from sylanne3.runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from sylanne3.runtime.budget import BudgetReceipt
from sylanne3.runtime.model_cost_settlement import OriginalModelCostCommitV1,original_model_cost_operation_id_v1
from sylanne3.authority_service.v2_model_egress_contract import ModelEgressIntentV1
from sylanne3.authority_service.v2_model_egress_wire import to_wire
from sylanne3.runtime import contact_reviewed_content_v2 as reader

@pytest.fixture
def cost(monkeypatch):
    ns=NamespaceId('bot','persona');key=AtomKey(Owner('activity',*ns.as_tuple,'activity'),'runtime.cost_settlement','cost')
    intent=ModelEgressIntentV1('authority','authority-ns','worker','acquire','call','a'*64,'job',1,'f'*32,1,0,'b'*64,
        ('source',),(('source',1),),(('access',1),),0,0,1,1,1,0,0,0,'lease','prepare','c'*64,
        (('model',10),),'provider','model','d'*64,128,'acquire','e'*64)
    budget=BudgetReceipt('settled','prepare','f'*64,'lease',1,{'model':1},{},{})
    op=original_model_cost_operation_id_v1(ns,'call')
    commit=OriginalModelCostCommitV1('committed',op,'call','quote',1,'a'*64,key.token,canonical_digest(asdict(budget)),7,2,3)
    raw={'original_model_cost':asdict(commit),'original_intent_digest':canonical_digest(asdict(intent)),
        'terminal_receipt_digest':'a'*64,'quote_id':'quote','quote_version':1,'work_kind':'contact_generation','accounting_attempt_id':'attempt'}
    db=sqlite3.connect(':memory:')
    db.executescript('CREATE TABLE graph_bundle_operations(bot,persona,operation_id,digest,activity_id,effect_id,commit_seq,receipt_json);'
        'CREATE TABLE runtime_budget_operations(bot_id,persona_id,operation_id,phase,receipt_json);'
        'CREATE TABLE graph_original_model_cost_attempts_v1(bot,persona,call_id,state,attempt_id);'
        'CREATE TABLE graph_events(bot,persona,session,event_id,reads,revisions,epoch_revision);'
        'CREATE TABLE graph_history(token,revision,event_id,value,valid);')
    db.execute('INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)',(*ns.as_tuple,op,'b'*64,'activity','effect',7,canonical_json(raw)))
    db.execute('INSERT INTO runtime_budget_operations VALUES(?,?,?,?,?)',(*ns.as_tuple,'prepare','settle',canonical_json(asdict(budget))))
    db.execute('INSERT INTO graph_original_model_cost_attempts_v1 VALUES(?,?,?,?,?)',(*ns.as_tuple,'call','committed','attempt'))
    db.execute('INSERT INTO graph_events VALUES(?,?,?,?,?,?,?)',(*ns.as_tuple,'activity',op,canonical_json([[key.token,0]]),canonical_json([[key.token,1]]),3))
    db.execute('INSERT INTO graph_history VALUES(?,?,?,?,?)',(key.token,1,op,canonical_serialize({'fixture_cost':1}),1))
    monkeypatch.setattr(reader,'require_contact_original_v2',lambda *args:(to_wire(intent),'a'*64))
    issuer=SimpleNamespace(_d02=SimpleNamespace(_load_quote=lambda *args:SimpleNamespace(effect_id='effect')))
    prepared=SimpleNamespace(call_id='call',prepare_operation_id='prepare',job_id='job',quote_id='quote',quote_version=1,phase='contact_generation',activity_id='activity')
    paid={'cost_operation_id':op,'terminal_digest':'a'*64,'cost_ref':key.token,'cost_value':{'fixture_cost':1}}
    yield db,ns,issuer,prepared,paid,raw,commit
    db.close()

def check(cost):
    db,ns,issuer,prepared,paid,*_=cost
    return reader._read_contact_paid_cost_commit_v2(db,namespace=ns,prepared=prepared,paid=paid,issuer=issuer)

def test_actual_model_cost_family_roundtrip_not_a_root_receipt(cost):
    assert check(cost)==cost[-1]
    assert 'ledger_refs' not in cost[-2]

@pytest.mark.parametrize('drift',['extra','bool','quote','history','epoch','budget','attempt','member'])
def test_sql_cost_original_drift_refuses_without_accounting_mutation(cost,drift):
    db,ns,issuer,prepared,paid,raw,commit=cost
    if drift in ('extra','bool','quote','budget'):
        if drift=='extra':raw['ledger_refs']=[]
        elif drift=='bool':raw['original_model_cost']['quote_version']=True
        elif drift=='quote':raw['quote_id']='another'
        else:raw['original_model_cost']['budget_receipt_digest']='0'*64
        db.execute('UPDATE graph_bundle_operations SET receipt_json=?',(canonical_json(raw),))
    elif drift=='history':db.execute('UPDATE graph_history SET value=?',(canonical_serialize({'fixture_cost':2}),))
    elif drift=='epoch':db.execute('UPDATE graph_events SET epoch_revision=4')
    elif drift=='attempt':db.execute("UPDATE graph_original_model_cost_attempts_v1 SET state='pending'")
    else:db.execute('UPDATE graph_events SET revisions=?',(canonical_json([[paid['cost_ref'],2]]),))
    before=db.total_changes
    with pytest.raises((ValueError,TypeError)):check(cost)
    assert db.total_changes==before

@pytest.mark.parametrize('column,revision',[('reads',False),('revisions',True)])
def test_sql_event_bool_revision_cannot_match_integer_member(cost,column,revision):
    db,*_=cost
    db.execute('UPDATE graph_events SET '+column+'=?',(canonical_json([[cost[4]['cost_ref'],revision]]),))
    with pytest.raises(ValueError,match='event/history'):check(cost)
