"""Real GraphStore progress/access invalidation and bounded provenance tests.

The execution/prepared originals use the existing signed SQL seam. This does
not replace installed Authority acceptance or certify a caller permission.
"""
from copy import deepcopy
from dataclasses import replace
import json
import sqlite3

import pytest

from test_d11_life_fact_eligibility_v1 import graph,case,commit_change
from sylanne3.contracts import Event,Scope
from sylanne3.graph_types import GraphCandidate,GraphVersion,GraphWrite,AtomKey
from sylanne3.memory_types import SourceRecord,source_key,access_key
from sylanne3.domains.d10.production_operations_v1 import LifeProgressHeadV1,d10_production_type_specs_v1
from sylanne3.runtime_contracts import canonical_serialize
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.runtime.d11_life_contract_v1 import life_adoption_operation_id_v1
from sylanne3.runtime.d11_life_outcome_provenance_v1 import life_outcome_key_v1
from sylanne3.runtime.d10_life_progress_provenance_v1 import (
    PROVENANCE_TYPE,ELIGIBILITY_TYPE,life_progress_qualified_writes_v1,
    life_experience_access_dependencies_v1,decode_life_progress_auxiliary_v1,
    require_life_experience_access_edges_v1,life_progress_current_read_inputs_v1,
    validate_life_progress_provenance_history_v1,
)
from sylanne3.runtime.c09_graph_rebase_candidate_v1 import _dependency_closure


def progress(case):
    p=case.prepared;b=case.binding;t=case.terminal
    return LifeProgressHeadV1(p.plan.project.ref,p.plan.recipe.ref,b.activity_id,b.effect_id,'real_execution','source_note',
        float(t.claim.payload.character_at),float(t.payload.character_at),b.artifact_ref,t.original_ref,
        (t.claim.original_ref,t.original_ref,life_outcome_key_v1(b,p.plan.action_intent.ref).token),(p.plan.input_source.ref,))


def candidate(graph):
    case,store,first,_=graph
    store.graph_commit(replace(first,event=replace(first.event,event_id=life_adoption_operation_id_v1(case.binding))))
    for spec in d10_production_type_specs_v1():store._registry.register(spec)
    writes=life_progress_qualified_writes_v1(case.prepared,case.terminal,progress(case),'advance:fixture')
    ns=case.binding.namespace;source=source_key(*ns.as_tuple,'fixture-experience')
    record=SourceRecord(source.owner.subject,'Fixture internal','persona:'+ns.persona_id,'internal','confirmed',1.,2.,
        'fixture-actual-terminal',case.prepared.plan.audiences,('context','consolidation'),('input-1',),'same_root')
    access=access_key(*ns.as_tuple,record.source_id)
    all_writes=(*writes,GraphWrite(source,record.to_dict()),GraphWrite(access,{'source_id':record.source_id,
        'audiences':list(record.audiences),'purposes':list(record.purposes),'status':'active','recorded_at':record.recorded_at},
        life_experience_access_dependencies_v1(case.prepared,source)))
    deps={key for write in all_writes for key in write.dependencies}|{write.key for write in all_writes}
    reads=tuple(GraphVersion(key,(store._db.execute('SELECT revision FROM graph_atoms WHERE token=?',(key.token,)).fetchone() or (0,))[0])
        for key in sorted(deps,key=lambda key:key.token))
    return case,store,source,access,GraphCandidate(Event(Scope(*ns.as_tuple,case.binding.activity_id),
        'advance:fixture',2.,'fixture.progress',{}),reads,all_writes)


def test_actual_progress_and_source_history_have_no_invalidation_edges_and_cold_access(graph):
    case,store,source,access,second=candidate(graph)
    receipt=store.graph_commit(second);assert receipt.status=='committed' and len(receipt.revisions)==5
    assert all(not w.dependencies for w in second.writes if w.key.type_name in {'memory.source','d10.life_progress.v1',PROVENANCE_TYPE})
    assert require_life_experience_access_edges_v1(store._db,prepared=case.prepared,source=source)==access
    for w in second.writes:
        if w.key.type_name in {'memory.source','d10.life_progress.v1',PROVENANCE_TYPE}:
            assert store._db.execute('SELECT dependencies FROM graph_history WHERE token=? AND revision=1',(w.key.token,)).fetchone()==('[]',)
    from pathlib import Path
    path=Path(store._db.execute('PRAGMA database_list').fetchone()[2])
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        assert require_life_experience_access_edges_v1(db,prepared=case.prepared,source=source)==access
        assert db.total_changes==0


@pytest.mark.parametrize('parent',[False,True])
def test_actual_access_revocation_invalidates_progress_and_experience_access_not_facts(graph,parent):
    case,store,source,access,second=candidate(graph);store.graph_commit(second)
    key=access_key(*case.binding.namespace.as_tuple,'parent-1' if parent else 'input-1')
    value=json.loads(store._db.execute('SELECT value FROM graph_atoms WHERE token=?',(key.token,)).fetchone()[0]);value['status']='withdrawn'
    commit_change(store,key,value)
    assert store._db.execute('SELECT valid FROM graph_atoms WHERE token=?',(second.writes[2].key.token,)).fetchone()==(0,)
    with pytest.raises(ValueError):require_life_experience_access_edges_v1(store._db,prepared=case.prepared,source=source)
    for w in second.writes:
        if w.key.type_name in {'memory.source','d10.life_progress.v1',PROVENANCE_TYPE}:
            assert store._db.execute('SELECT revision,valid FROM graph_atoms WHERE token=?',(w.key.token,)).fetchone()==(1,1)


def test_actual_progress_source_transaction_rolls_back(graph):
    _,store,_,_,second=candidate(graph)
    def refuse(db,receipt):raise ValueError('exact post-CAS refusal')
    with pytest.raises(ValueError,match='post-CAS'):store.graph_commit(second,_receipt_hook=refuse)
    for write in second.writes:
        assert store._db.execute('SELECT token FROM graph_atoms WHERE token=?',(write.key.token,)).fetchone() is None


def test_actual_c09_typed_end_proof_closure_includes_progress_and_source(graph):
    case,store,source,access,second=candidate(graph);store.graph_commit(second)
    closure=_dependency_closure(store._db,{case.prepared.plan.input_source.ref})
    # Access is the existing separately sanitized permission surface. The
    # content closure intentionally excludes all memory.access values.
    assert {w.key.token for w in second.writes if w.key.type_name!='memory.access'}<=closure


@pytest.mark.parametrize('field,value',[
    ('effect_id','effect:wrong'),('terminal_ref','terminal:wrong'),('artifact_ref','artifact:wrong'),('role_end',2.),
])
def test_progress_producer_rejects_changed_actual_terminal_fields(case,field,value):
    with pytest.raises(ValueError):life_progress_qualified_writes_v1(case.prepared,case.terminal,replace(progress(case),**{field:value}),'advance:fixture')


@pytest.mark.parametrize('kind',[PROVENANCE_TYPE,ELIGIBILITY_TYPE])
def test_closed_progress_decoder_rejects_bool_revision_and_extra_field(case,kind):
    writes=life_progress_qualified_writes_v1(case.prepared,case.terminal,progress(case),'advance:fixture')
    value=deepcopy(next(write.value for write in writes if write.key.type_name==kind))
    value['fact_revision']=True
    with pytest.raises(ValueError):decode_life_progress_auxiliary_v1(kind,value)
    value['fact_revision']=1;value['caller_ok']=True
    with pytest.raises(ValueError):decode_life_progress_auxiliary_v1(kind,value)


def test_changed_or_missing_access_edges_cannot_become_current_permission(graph):
    case,store,source,access,second=candidate(graph);store.graph_commit(second)
    store._db.execute('DELETE FROM graph_dependencies WHERE dependent_token=?',(access.token,))
    with pytest.raises(ValueError,match='edges differ'):require_life_experience_access_edges_v1(store._db,prepared=case.prepared,source=source)


def test_real_current_planner_requires_complete_provenance_and_prepared_scope(graph):
    case,store,_,_,second=candidate(graph);store.graph_commit(second)
    from sylanne3.runtime.d11_life_preparation_v1 import install_d11_life_schema_v1,TABLE
    install_d11_life_schema_v1(store._db)
    row=case.db.execute('SELECT * FROM '+TABLE+' WHERE kind=?',('prepared',)).fetchone()
    store._db.execute('INSERT INTO '+TABLE+' VALUES(?,?,?,?,?,?,?,?)',row)
    keys,roots,originals=life_progress_current_read_inputs_v1(store._db,case.binding.namespace,second.writes[0].key.token)
    assert {row.ref for row in __import__('sylanne3.runtime.d11_life_fact_provenance_v1',fromlist=['life_current_fact_reads_v1']).life_current_fact_reads_v1(case.prepared)}<={key.token for key in keys}
    assert case.prepared.plan.input_source.ref in roots and case.binding.prepared_original_ref in originals
    store._db.execute('DELETE FROM '+TABLE)
    with pytest.raises(ValueError,match='prepared'):life_progress_current_read_inputs_v1(store._db,case.binding.namespace,second.writes[0].key.token)


def historical(graph):
    case,store,_,_,second=candidate(graph);receipt=store.graph_commit(second)
    from types import SimpleNamespace
    production={'domain':'d10','operation_kind':'advance_life',
        'receipt':SimpleNamespace(operation_id=second.event.event_id,write_versions=receipt.revisions),
        'payload':{'writes':plain_v1(second.writes[:3]),'provenance':{'actual_progress':plain_v1(progress(case))}}}
    return case,store,second,production


def test_actual_historical_progress_join_survives_current_parent_revocation(graph):
    case,store,second,production=historical(graph)
    key=access_key(*case.binding.namespace.as_tuple,'parent-1')
    value=json.loads(store._db.execute('SELECT value FROM graph_atoms WHERE token=?',(key.token,)).fetchone()[0]);value['status']='withdrawn'
    commit_change(store,key,value)
    assert store._db.execute('SELECT valid FROM graph_atoms WHERE token=?',(second.writes[2].key.token,)).fetchone()==(0,)
    assert validate_life_progress_provenance_history_v1(store._db,prepared=case.prepared,terminal=case.terminal,
        progress=progress(case),production=production)==second.writes[:3]


@pytest.mark.parametrize('drift',['history_value','history_operation','history_dependencies','payload_writes','missing_terminal_proof'])
def test_actual_historical_progress_rejects_unjoined_or_changed_originals(graph,drift):
    case,store,second,production=historical(graph)
    if drift=='history_value':store._db.execute('UPDATE graph_history SET value=? WHERE token=?',('{}',second.writes[1].key.token))
    elif drift=='history_operation':store._db.execute('UPDATE graph_history SET event_id=? WHERE token=?',('different-op',second.writes[1].key.token))
    elif drift=='history_dependencies':store._db.execute('UPDATE graph_history SET dependencies=? WHERE token=?',('[]',second.writes[2].key.token))
    elif drift=='payload_writes':production['payload']['writes']=plain_v1(second.writes[:2])
    else:store._db.execute('DELETE FROM graph_history WHERE token=?',(second.writes[1].value['terminal_provenance_ref'],))
    with pytest.raises(ValueError):validate_life_progress_provenance_history_v1(store._db,prepared=case.prepared,terminal=case.terminal,
        progress=progress(case),production=production)
