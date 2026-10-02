"""Real GraphStore immutable-history / current-eligibility regressions.

The prepared original is the signed SQL fixture, not an Authority permission.
Graph CAS, rollback, invalidation and typed physical closure run for real;
installed Authority consumption remains the separate permanent integration.
"""
from copy import deepcopy
from dataclasses import replace
import json
import sqlite3

import pytest

from test_d11_life_job_result_binding_v1 import case
from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06 import D06DomainProvider, source_correction_head_key
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphVersion, GraphWrite, TypeRegistry, TypeSpec, owner_grant_spec
from sylanne3.memory_types import access_key
from sylanne3.runtime.c09_graph_rebase_candidate_v1 import _dependency_closure
from sylanne3.runtime.d11_life_graph_types_v1 import life_fact_writes_v1, life_graph_type_specs_v1
from sylanne3.runtime.d11_life_fact_provenance_v1 import (
    PROVENANCE_TYPE, ELIGIBILITY_TYPE, decode_life_fact_auxiliary_v1,
    life_current_fact_reads_v1, require_current_life_fact_eligibility_v1,
)
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize


@pytest.fixture
def graph(case,tmp_path):
    registry=TypeRegistry()
    for spec in (*D06DomainProvider().type_specs(),*life_graph_type_specs_v1()):registry.register(spec)
    registry.register(owner_grant_spec())
    # These three placeholder plan values are confined to this Graph/SQL
    # seam; the full installed test uses actual domain catalogue validators.
    for name in ('d10.life_project.v1','d10.life_recipe.v1','d08.action_intent.v1'):
        registry.register(TypeSpec(name,('activity',),'state',lambda value:None))
    from sylanne3.domains.d08.execution import GoalExecutionProvider
    registry.register(next(spec for spec in GoalExecutionProvider().register_types() if spec.name=='d08.action_outcome.v1'))
    store=GraphStore(tmp_path/'current.db',registry);db=store._db
    # Seed the genuine prepared input head bytes. Plan/Owner contents are the
    # bounded SQL seam's placeholders, never authenticated Owner permission.
    for row in case.prepared.read_rows:
        if row.revision==0:continue
        key=AtomKey.from_token(row.ref)
        db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',
            (key.token,key.owner.bot,key.owner.persona,key.owner.kind,key.owner.subject,
                key.type_name,key.name,row.revision,row.value_json,int(row.valid)))
    writes=life_fact_writes_v1(case.prepared,case.terminal.claim,case.terminal,
        (case.data,case.terminal.payload.artifact_digest,len(case.data)))
    reads=tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision) for row in case.prepared.read_rows)
    candidate=GraphCandidate(Event(Scope(*case.binding.namespace.as_tuple,case.binding.activity_id),
        'actual-fact-commit',0,'fixture.fact',{}),(*reads,*(GraphVersion(w.key,0) for w in writes)),writes)
    adopted={'schema':'d11.adopted-life-original.v4','write_commitments':[
        {'ref':w.key.token,'revision':1,'digest':canonical_digest(w.value)} for w in writes]}
    yield case,store,candidate,adopted
    store.close()


def current(graph,db=None):
    case,store,_,adopted=graph
    return require_current_life_fact_eligibility_v1(db or store._db,
        prepared=case.prepared,terminal=case.terminal,adopted=adopted)


def commit_change(store,key,value,event='change'):
    revision=store._db.execute('SELECT revision FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
    return store.graph_commit(GraphCandidate(Event(Scope(key.owner.bot,key.owner.persona,'change'),event,1,'fixture.change',{}),
        (GraphVersion(key,0 if revision is None else revision[0]),),(GraphWrite(key,value),)))


def test_real_fact_proof_and_projection_commit_and_cold_read(graph):
    _,store,candidate,_=graph
    receipt=store.graph_commit(candidate)
    assert receipt.status=='committed' and len(receipt.revisions)==12
    assert len(current(graph))==4
    with sqlite3.connect(__import__('pathlib').Path(store._db.execute('PRAGMA database_list').fetchone()[2]).as_uri()+'?mode=ro',uri=True) as cold:
        cold.execute('PRAGMA query_only=ON');cold.execute('BEGIN')
        assert current(graph,cold)==current(graph) and cold.total_changes==0


@pytest.mark.parametrize('parent',[False,True])
def test_actual_access_withdrawal_invalidates_projection_not_history(graph,parent):
    case,store,candidate,_=graph;store.graph_commit(candidate)
    key=access_key(*case.binding.namespace.as_tuple,'parent-1' if parent else 'input-1')
    value=json.loads(store._db.execute('SELECT value FROM graph_atoms WHERE token=?',(key.token,)).fetchone()[0]);value['status']='withdrawn'
    receipt=commit_change(store,key,value)
    assert len(receipt.invalidated)==4
    with pytest.raises(ValueError):current(graph)
    assert store._db.execute('SELECT count(*) FROM graph_atoms WHERE type_name=? AND valid=1',(ELIGIBILITY_TYPE,)).fetchone()==(0,)
    assert store._db.execute('SELECT count(*) FROM graph_atoms WHERE type_name=? AND valid=1',(PROVENANCE_TYPE,)).fetchone()==(3,)
    assert all(store._db.execute('SELECT revision,valid FROM graph_atoms WHERE token=?',(w.key.token,)).fetchone()==(1,1)
        for w in candidate.writes if w.key.type_name in ('d11.role_segment_start.v1','d11.role_segment_end.v1','d11.life_artifact.v1','d08.action_outcome.v1'))


def test_actual_negative_correction_head_invalidates_current_eligibility(graph):
    case,store,candidate,_=graph;store.graph_commit(candidate);ns=case.binding.namespace
    from sylanne3.memory_types import source_key, interpretation_key
    key=source_correction_head_key(ns,'input-1')
    value={'source_ref':source_key(*ns.as_tuple,'input-1').token,'source_revision':1,
        'correction_source_ref':source_key(*ns.as_tuple,'correction-1').token,
        'target_refs':[interpretation_key(*ns.as_tuple,'input-1').token],
        'operation_id':'correction-op','state':'pending_reevaluation','access_epoch':1,'deletion_epoch':0}
    receipt=commit_change(store,key,value)
    assert len(receipt.invalidated)==4
    with pytest.raises(ValueError):current(graph)


def test_real_graph_transaction_rolls_back_all_nine_writes_and_edges(graph):
    _,store,candidate,_=graph
    def fail(db,receipt):raise ValueError('business hook refused')
    with pytest.raises(ValueError,match='business hook'):store.graph_commit(candidate,_receipt_hook=fail)
    for write in candidate.writes:
        assert store._db.execute('SELECT token FROM graph_atoms WHERE token=?',(write.key.token,)).fetchone() is None
        assert store._db.execute('SELECT token FROM graph_history WHERE token=?',(write.key.token,)).fetchone() is None
    assert store._db.execute('SELECT count(*) FROM graph_dependencies').fetchone()==(0,)
    assert store._db.execute('SELECT count(*) FROM graph_events').fetchone()==(0,)


def test_typed_physical_closure_reaches_source_free_start_and_end_facts(graph):
    case,store,candidate,_=graph;store.graph_commit(candidate)
    affected=_dependency_closure(store._db,{case.prepared.plan.input_source.ref})
    roles=[w for w in candidate.writes if w.key.type_name in ('d11.role_segment_start.v1','d11.role_segment_end.v1')]
    assert all(not w.dependencies and 'source_refs' not in w.value for w in roles)
    assert all(w.key.token in affected for w in candidate.writes)


@pytest.mark.parametrize('change',['deleted_edge','same_name_revision','deleted_source','legacy','missing_owner','missing_correction'])
def test_current_reader_refuses_incomplete_or_changed_actual_bindings(graph,change):
    case,store,candidate,adopted=graph;store.graph_commit(candidate)
    if change=='deleted_edge':store._db.execute('DELETE FROM graph_dependencies WHERE dependent_token=?',(next(w.key.token for w in candidate.writes if w.key.type_name==ELIGIBILITY_TYPE),))
    if change=='same_name_revision':store._db.execute('UPDATE graph_atoms SET revision=2 WHERE token=?',(case.binding.artifact_ref,))
    if change=='deleted_source':store._db.execute('DELETE FROM graph_atoms WHERE token=?',(case.prepared.plan.input_source.ref,))
    if change=='legacy':adopted['schema']='d11.adopted-life-original.v2'
    if change in ('missing_owner','missing_correction'):
        kind='d11.owner_grant.v1' if change=='missing_owner' else 'd06.source_correction_head.v1'
        prepared=replace(case.prepared,read_rows=tuple(row for row in case.prepared.read_rows if AtomKey.from_token(row.ref).type_name!=kind),
            binding=replace(case.binding,input_digest=__import__('sylanne3.runtime.d11_life_preparation_v1',fromlist=['life_input_digest_v1']).life_input_digest_v1(case.prepared.plan,case.prepared.source_record_json,
                tuple(row for row in case.prepared.read_rows if AtomKey.from_token(row.ref).type_name!=kind))))
        with pytest.raises(ValueError):life_current_fact_reads_v1(prepared)
        return
    with pytest.raises(ValueError):current(graph)


@pytest.mark.parametrize('change',['name','namespace','revision','digest','unknown_field'])
def test_typed_provenance_rejects_cross_scope_same_family_forgery(graph,change):
    _,_,candidate,_=graph
    value=deepcopy(next(w.value for w in candidate.writes if w.key.type_name==PROVENANCE_TYPE))
    key=AtomKey.from_token(value['fact_ref'])
    if change=='name':value['fact_ref']=replace(key,name='other').token
    if change=='namespace':value['fact_ref']=replace(key,owner=replace(key.owner,bot='other')).token
    if change=='revision':value['fact_revision']=True
    if change=='digest':value['fact_digest']='non-digest'
    if change=='unknown_field':value['caller_authority']=True
    with pytest.raises((ValueError,TypeError)):decode_life_fact_auxiliary_v1(PROVENANCE_TYPE,value)
