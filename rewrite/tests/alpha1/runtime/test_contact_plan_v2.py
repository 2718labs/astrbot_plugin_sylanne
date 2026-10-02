"""Plan B closed shapes, actual Graph invalidation and durable SQL boundaries.

Owner/provider/D06 originals are fixture seams here; these public values do
not issue an installed stage. The registered production command is separate.
"""
from dataclasses import replace
import json
import sqlite3

import pytest

from test_contact_qualification_evidence_v1 import qualification_fixture_values,NS
from sylanne3.contracts import Event,Scope
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.domains.d08.contact_plan_v1 import contact_ids_v1
from sylanne3.domains.d08.contact_plan_v2 import (
    PLAN,PROVENANCE,ELIGIBILITY,CURRENT_TYPES,AdoptedContactExpressionPlanV2,
    ContactExpressionPlanProvenanceV2,contact_plan_keys_v2,contact_plan_writes_v2,
    decode_contact_plan_member_v2,contact_plan_type_specs_v2,
)
from sylanne3.graph_types import AtomKey,GraphVersion,GraphWrite,GraphCandidate,Owner,TypeRegistry,TypeSpec
from sylanne3.graph_store import GraphStore
from sylanne3.memory_types import source_key,access_key
from sylanne3.runtime.contact_plan_adoption_v2 import (
    AdoptCurrentContactExpressionPlanRequestV2,require_exact_contact_plan_issuance_v2,
    install_contact_plan_original_schema_v2,_require_durable_contact_plan_row_v2,TABLE,
)
from sylanne3.runtime.d10_offline_tick_execution_v1 import OfflineTickGraphReadV1
from sylanne3.runtime.domain_production_contracts_v1 import ProductionQueryCoverageV1
from sylanne3.runtime_contracts import VersionedRef,canonical_digest,canonical_serialize

D='a'*64


@pytest.fixture
def proof():
    evidence,_=qualification_fixture_values()
    from sylanne3.runtime.contact_final_stage_v1 import _CONTACT_FINAL_WRITE_TYPES
    rows=[row for row in evidence.members if AtomKey.from_token(row.ref).type_name not in _CONTACT_FINAL_WRITE_TYPES]
    keys={kind:AtomKey(Owner('persona',*NS.as_tuple),kind,'plan-fixture') for kind in ('d10.proactive_opportunity.v1','d10.contact_policy.v1')}
    rows.extend(OfflineTickGraphReadV1(key.token,1,canonical_serialize({'fixture':kind}),True) for kind,key in keys.items())
    rows=tuple(sorted(rows,key=lambda row:row.ref))
    source=source_key(*NS.as_tuple,'claim');account=AtomKey.from_token(evidence.route.account_version.key.token)
    ids=contact_ids_v1(NS,source.token,'entity:fixture','private_text')
    versions=tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision) for row in rows)
    plan=AdoptedContactExpressionPlanV2(PLAN,NS,ids['plan'],ids['contact'],ids['activity'],source.token,D,
        VersionedRef(keys['d10.proactive_opportunity.v1'].token,1),VersionedRef(source.token,1),'entity:fixture',
        VersionedRef(account.token,1),D,'scene','user','policy-original',D,1,('contact',),('paraphrase',),D,(D,),versions,
        'lease',1,D,'generation-reservation','review-reservation',(('model',10),),(('model',10),),3,2048,0,10.)
    from sylanne3.runtime.contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
    pages=tuple(ProductionQueryCoverageV1(page.epoch,page.type_id,
        tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision) for row in rows if row.revision and AtomKey.from_token(row.ref).type_name==page.type_id),
        True,None) for page in evidence.query_coverage if page.type_id in CONTACT_CURRENT_TYPES)
    return ContactExpressionPlanProvenanceV2(plan,'adopt-plan',1,'incarnation',evidence.owner_guard,rows,
        tuple(row for row in rows if AtomKey.from_token(row.ref).type_name in CURRENT_TYPES),pages)


@pytest.fixture
def graph(proof,tmp_path):
    registry=TypeRegistry()
    for spec in contact_plan_type_specs_v2():registry.register(spec)
    for kind in {AtomKey.from_token(row.ref).type_name for row in proof.historical_reads}:
        registry.register(TypeSpec(kind,('persona','activity','event'),'state',lambda value:None))
    store=GraphStore(tmp_path/'plan.db',registry)
    for row in proof.historical_reads:
        if not row.revision:continue
        key=AtomKey.from_token(row.ref)
        store._db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',
            (key.token,*NS.as_tuple,key.owner.kind,key.owner.subject,key.type_name,key.name,row.revision,row.value_json,int(row.valid)))
    store._db.commit()
    yield store
    store.close()


def candidate(proof):
    writes=contact_plan_writes_v2(proof)
    reads=tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision) for row in proof.historical_reads)+tuple(GraphVersion(w.key,0) for w in writes)
    return GraphCandidate(Event(Scope(*NS.as_tuple,'plan'),proof.producing_operation_id,1.,'plan-v2-fixture',{}),reads,writes)


def test_actual_graph_cas_writes_immutable_facts_and_mutable_eligibility(proof,graph):
    assert decode_contact_plan_member_v2(PROVENANCE,plain_v1(proof))==proof
    writes=contact_plan_writes_v2(proof)
    assert not writes[0].dependencies and not writes[1].dependencies and writes[2].dependencies
    receipt=graph.graph_commit(candidate(proof));assert receipt.status=='committed'
    for write in writes:
        assert graph._db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(write.key.token,)).fetchone()==(1,canonical_serialize(write.value),1)


@pytest.mark.parametrize('change',['missing_access','missing_correction','missing_owner','missing_current','missing_query','query_rows','generation_bool','foreign_ref'])
def test_canonical_plan_proof_rejects_incomplete_scope(proof,change):
    raw=plain_v1(proof)
    if change in {'missing_access','missing_correction','missing_owner'}:
        kind={'missing_access':'memory.access','missing_correction':'d06.source_correction_head.v1','missing_owner':'d11.owner_grant.v1'}[change]
        for field in ('historical_reads','current_reads'):raw[field]=[row for row in raw[field] if AtomKey.from_token(row['ref']).type_name!=kind]
        raw['plan']['qualified_read_versions']=[row for row in raw['plan']['qualified_read_versions'] if AtomKey.from_token(row['key']).type_name!=kind]
    elif change=='missing_current':raw['current_reads'].pop()
    elif change=='missing_query':raw['query_coverage'].pop()
    elif change=='query_rows':next(page for page in raw['query_coverage'] if page['type_id']=='d03.account_binding')['row_versions']=[]
    elif change=='generation_bool':raw['activation_generation']=True
    else:raw['plan']['source_ref']['ref']=source_key('other','persona','claim').token
    with pytest.raises((ValueError,TypeError)):decode_contact_plan_member_v2(PROVENANCE,raw)


def test_actual_graph_access_withdrawal_invalidates_projection_not_history(proof,graph):
    graph.graph_commit(candidate(proof));write=next(row for row in proof.current_reads if row.ref==access_key(*NS.as_tuple,'claim').token)
    value=json.loads(write.value_json);value['status']='withdrawn';key=AtomKey.from_token(write.ref)
    graph.graph_commit(GraphCandidate(Event(Scope(*NS.as_tuple,'change'),'withdraw-access',2.,'fixture',{}),
        (GraphVersion(key,write.revision),),(GraphWrite(key,value),)))
    for fact in contact_plan_writes_v2(proof)[:2]:
        assert graph._db.execute('SELECT value,valid FROM graph_atoms WHERE token=?',(fact.key.token,)).fetchone()==(canonical_serialize(fact.value),1)
    assert graph._db.execute('SELECT valid FROM graph_atoms WHERE token=?',(contact_plan_keys_v2(proof.plan)[2].token,)).fetchone()==(0,)


def test_real_same_transaction_refusal_rolls_back_three_members(proof,graph):
    def refuse(db,receipt):raise ValueError('fixture plan original refusal')
    with pytest.raises(ValueError,match='fixture plan original refusal'):graph.graph_commit(candidate(proof),_receipt_hook=refuse)
    assert graph._db.execute('SELECT count(*) FROM graph_history').fetchone()==(0,)


def test_independent_connection_requires_durable_commit_and_exact_saved_row(graph):
    db=graph._db;db.execute('BEGIN');install_contact_plan_original_schema_v2(db)
    row=(*NS.as_tuple,'contact:fixture','{}',D,D)
    db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?)',row)
    with pytest.raises(ValueError,match='durably committed'):_require_durable_contact_plan_row_v2(db,row)
    db.commit();_require_durable_contact_plan_row_v2(db,row)
    with pytest.raises(ValueError,match='durably committed'):_require_durable_contact_plan_row_v2(db,(*row[:3],'changed',*row[4:]))
    with pytest.raises(sqlite3.IntegrityError,match='immutable'):db.execute(f'DELETE FROM {TABLE}')
    db.rollback()


def test_public_stage_shape_cannot_issue_plan_or_change_request_family(proof):
    with pytest.raises(ValueError):require_exact_contact_plan_issuance_v2(proof,object(),object())
    opportunity=proof.plan.opportunity_ref.ref;route=proof.plan.route_account_ref.ref
    policy=next(row.ref for row in proof.historical_reads if AtomKey.from_token(row.ref).type_name=='d10.contact_policy.v1')
    assert AdoptCurrentContactExpressionPlanRequestV2(opportunity,policy,route)
    with pytest.raises(ValueError):AdoptCurrentContactExpressionPlanRequestV2(opportunity,route,policy)
