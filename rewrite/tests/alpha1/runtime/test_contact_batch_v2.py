"""Permanent Contact v2 shape/Graph-CAS tests; no provider permission is issued.

The full six-provider fixture uses synthetic check originals. Graph immutable
facts, real SQLite history, dependency invalidation and rollback are real.
The installed freezer explicitly rejects these public DTOs as authority.
"""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from test_contact_qualification_evidence_v1 import qualification_fixture_values, NS
from sylanne3.contracts import Event, Scope
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.domains.d08.contact_plan_v1 import contact_segment_ids_v1
from sylanne3.domains.d09 import ClaimKind, ClaimUse, ExpressionClaim, SegmentCandidate, segment_payload_digest
from sylanne3.domains.d09.contact_batch_v1 import ContactPaidModelBindingV1, ContactReviewedContentV1, ContactReviewedSegmentV1
from sylanne3.domains.d09.contact_batch_v2 import (
    BATCH, PROVENANCE, ELIGIBILITY, CURRENT_TYPES, ContactVerifiedBatchV2, ContactBatchProvenanceV2,
    contact_batch_keys_v2, contact_batch_writes_from_proof_v2, decode_contact_batch_companion_v2,
    contact_batch_type_specs_v2,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry, TypeSpec
from sylanne3.memory_types import source_key, access_key
from sylanne3.runtime.contact_batch_current_v2 import require_current_contact_batch_v2
from sylanne3.runtime.contact_batch_freezer_v2 import freeze_installed_contact_verified_batch_v2
from sylanne3.runtime.contact_final_action_v1 import contact_final_action_ids_v1
from sylanne3.runtime.contact_final_stage_v1 import _CONTACT_FINAL_WRITE_TYPES
from sylanne3.runtime.d10_offline_tick_execution_v1 import OfflineTickGraphReadV1
from sylanne3.runtime.domain_production_contracts_v1 import ProductionQueryCoverageV1
from sylanne3.runtime_contracts import QueryEpoch, canonical_digest, canonical_serialize

D='a'*64


@pytest.fixture
def proof():
    evidence,_=qualification_fixture_values()
    rows=[row for row in evidence.members if AtomKey.from_token(row.ref).type_name not in _CONTACT_FINAL_WRITE_TYPES]
    plan=AtomKey(Owner('activity',*NS.as_tuple,'activity'),'d08.contact_expression_plan.v1','plan')
    rows.append(OfflineTickGraphReadV1(plan.token,1,canonical_serialize({'fixture':'plan'}),True))
    rows=tuple(sorted(rows,key=lambda row:row.ref))
    source=source_key(*NS.as_tuple,'claim').token
    claim=ExpressionClaim('claim:one','fixture',ClaimKind.REPORTED_CLAIM,(source,),('user',),('expression',),'disclosure')
    ids=contact_segment_ids_v1('contact:one',0)
    segment=SegmentCandidate(ids['segment'],ids['effect'],'fixture',(ClaimUse(claim.claim_id,0,7,claim.kind),),(),(),0.)
    reviewed=ContactReviewedSegmentV1(0,ids['operation'],segment,segment_payload_digest(segment.body,(),segment.claim_uses),None,(claim,))
    generation=ContactPaidModelBindingV1('contact_generation','generation','prepare-gen','call-gen',D,D,(),D,'cost',1,D,'settle-gen',D)
    review=replace(generation,phase='contact_review',job_id='review',prepare_operation_id='prepare-review',call_id='call-review',cost_operation_id='settle-review')
    versions=tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision) for row in rows)
    content=ContactReviewedContentV1(NS,'contact:one','activity',GraphVersion(plan,1),D,D,D,(),evidence.qualification.route_semantic_digest,
        'user','scene',(),versions,generation,review,(reviewed,),10.,0)
    keys=contact_batch_keys_v2(NS,'activity','contact:one')
    parent=AtomKey(keys[0].owner,'d08.communication_intent_grant.v1','grant')
    batch=ContactVerifiedBatchV2(BATCH,keys[0].name,1,ids['operation'],content,content.digest,parent.token,1,D,D)
    action=contact_final_action_ids_v1('contact:one',0)['action']
    checks=tuple(replace(check,action_ref=action) for check in evidence.qualification.checks)
    q=replace(evidence.qualification,checks=checks,d08_scope=replace(evidence.qualification.d08_scope,action_id=action))
    pages=tuple(ProductionQueryCoverageV1(QueryEpoch(NS,'namespace',1),page.type_id,
        tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision) for row in rows if row.revision and AtomKey.from_token(row.ref).type_name==page.type_id),True,None)
        for page in evidence.query_coverage)
    return ContactBatchProvenanceV2(batch,1,'incarnation',D,rows,tuple(row for row in rows if AtomKey.from_token(row.ref).type_name in CURRENT_TYPES),pages,q)


@pytest.fixture
def graph(proof,tmp_path):
    registry=TypeRegistry()
    for spec in contact_batch_type_specs_v2():registry.register(spec)
    for kind in {AtomKey.from_token(row.ref).type_name for row in proof.historical_reads}:
        registry.register(TypeSpec(kind,('persona','event','activity'),'state',lambda value:None))
    store=GraphStore(tmp_path/'contact.db',registry)
    for row in proof.historical_reads:
        if not row.revision:continue
        key=AtomKey.from_token(row.ref)
        store._db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',
            (key.token,*NS.as_tuple,key.owner.kind,key.owner.subject,key.type_name,key.name,row.revision,row.value_json,int(row.valid)))
    store._db.commit()
    yield store
    store.close()


def candidate(proof):
    writes=contact_batch_writes_from_proof_v2(proof)
    versions=tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision) for row in proof.historical_reads)+tuple(GraphVersion(w.key,0) for w in writes)
    return GraphCandidate(Event(Scope(*NS.as_tuple,'activity'),proof.batch.producing_operation_id,1.,'contact-v2-fixture',{}),versions,writes)


def read(db,proof):
    return require_current_contact_batch_v2(db,namespace=NS,batch_ref=contact_batch_keys_v2(NS,'activity','contact:one')[0].token,
        operation_id=proof.batch.producing_operation_id,generation=1,graph_incarnation='incarnation')


def test_closed_codec_fact_proof_projection_and_actual_graph_cas(proof,graph):
    assert decode_contact_batch_companion_v2(PROVENANCE,plain_v1(proof))==proof
    writes=contact_batch_writes_from_proof_v2(proof)
    assert not writes[0].dependencies and not writes[1].dependencies and writes[2].dependencies
    result=graph.graph_commit(candidate(proof));assert result.status=='committed'
    graph._db.execute('BEGIN')
    try:assert read(graph._db,proof)[0]==proof.batch
    finally:graph._db.rollback()


@pytest.mark.parametrize('field,value', [('activation_generation',True),('graph_incarnation',''),('owner_head_digest','bad')])
def test_closed_provenance_rejects_typed_identity_drift(proof,field,value):
    raw=plain_v1(proof);raw[field]=value
    with pytest.raises((ValueError,TypeError)):decode_contact_batch_companion_v2(PROVENANCE,raw)


@pytest.mark.parametrize('change', ['missing_access','missing_correction','missing_plan','withdrawn_access','foreign_parent','missing_query','query_rows','qualification_action'])
def test_complete_proof_closure_rejects_canonical_tampering(proof,change):
    raw=plain_v1(proof)
    if change.startswith('missing_') and change not in ('missing_query',):
        kinds={'missing_access':'memory.access','missing_correction':'d06.source_correction_head.v1','missing_plan':'d08.contact_expression_plan.v1'}
        for field in ('historical_reads','current_reads'):raw[field]=[r for r in raw[field] if AtomKey.from_token(r['ref']).type_name!=kinds[change]]
    elif change=='withdrawn_access':
        for field in ('historical_reads','current_reads'):
            row=next(r for r in raw[field] if r['ref']==access_key(*NS.as_tuple,'claim').token)
            value=json.loads(row['value_json']);value['status']='withdrawn';row['value_json']=canonical_serialize(value)
    elif change=='foreign_parent':
        for field in ('historical_reads','current_reads'):
            row=next(r for r in raw[field] if r['ref']==source_key(*NS.as_tuple,'claim').token)
            value=json.loads(row['value_json']);value['parent_source_ids']=['missing-parent'];row['value_json']=canonical_serialize(value)
    elif change=='missing_query':raw['query_coverage'].pop()
    elif change=='query_rows':raw['query_coverage'][0]['row_versions']=[]
    else:raw['qualification']['checks'][0]['action_ref']='other-action'
    with pytest.raises((ValueError,TypeError)):decode_contact_batch_companion_v2(PROVENANCE,raw)


def test_public_typed_proof_cannot_issue_installed_freezer(proof,graph):
    with pytest.raises((ValueError,TypeError,AttributeError)):
        freeze_installed_contact_verified_batch_v2(proof,graph._db,read=object(),action=object(),qualification=proof.qualification,parent_grant_ref=proof.batch.parent_grant_ref,grant=object())
    assert graph._db.execute('SELECT count(*) FROM graph_history').fetchone()==(0,)


@pytest.mark.parametrize('change',['delete_edge','revision','namespace','generation'])
def test_current_reader_rejects_actual_sql_or_scope_drift(proof,graph,change):
    graph.graph_commit(candidate(proof));db=graph._db;db.execute('BEGIN')
    try:
        if change=='delete_edge':db.execute('DELETE FROM graph_dependencies WHERE dependent_token=?',(contact_batch_keys_v2(NS,'activity','contact:one')[2].token,))
        elif change=='revision':db.execute('UPDATE graph_atoms SET revision=2 WHERE token=?',(access_key(*NS.as_tuple,'claim').token,))
        if change in ('namespace','generation'):
            from sylanne3.runtime_contracts import NamespaceId
            with pytest.raises(ValueError):require_current_contact_batch_v2(db,namespace=NamespaceId('other','persona') if change=='namespace' else NS,
                batch_ref=contact_batch_keys_v2(NS,'activity','contact:one')[0].token,operation_id=proof.batch.producing_operation_id,
                generation=2 if change=='generation' else 1,graph_incarnation='incarnation')
        else:
            with pytest.raises(ValueError):read(db,proof)
    finally:db.rollback()


def test_same_transaction_receipt_failure_rolls_back_all_three_families(proof,graph):
    def refuse(db,receipt):raise ValueError('fixture receipt refusal')
    with pytest.raises(ValueError,match='fixture receipt refusal'):graph.graph_commit(candidate(proof),_receipt_hook=refuse)
    assert graph._db.execute('SELECT count(*) FROM graph_history').fetchone()==(0,)


@pytest.mark.parametrize('kind',['memory.source','memory.access','d11.owner_grant.v1'])
def test_real_graph_change_invalidates_only_current_projection(proof,graph,kind):
    graph.graph_commit(candidate(proof))
    original=contact_batch_writes_from_proof_v2(proof)
    row=next(row for row in proof.current_reads if AtomKey.from_token(row.ref).type_name==kind and row.revision>0)
    key=AtomKey.from_token(row.ref);value=json.loads(row.value_json)
    if kind=='memory.access':value['status']='withdrawn'
    elif kind=='memory.source':value['text']='changed fixture Source'
    else:value['fixture']='changed Owner'
    change=GraphCandidate(Event(Scope(*NS.as_tuple,'change'),'change-'+kind,2.,'fixture-change',{}),
        (GraphVersion(key,row.revision),),(GraphWrite(key,value),))
    if kind=='d11.owner_grant.v1':
        # The actual global Owner guard still requires W01's private path;
        # this fixture does not manufacture that authority.
        with pytest.raises(PermissionError):graph.graph_commit(change)
        return
    graph.graph_commit(change)
    for write in original[:2]:
        assert graph._db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',
            (write.key.token,)).fetchone()==(1,canonical_serialize(write.value),1)
    assert graph._db.execute('SELECT valid FROM graph_atoms WHERE token=?',(original[2].key.token,)).fetchone()==(0,)
    graph._db.execute('BEGIN')
    try:
        with pytest.raises(ValueError,match='invalidated'):read(graph._db,proof)
    finally:graph._db.rollback()


@pytest.mark.parametrize('kind',[PROVENANCE,ELIGIBILITY])
def test_actual_sql_companion_content_change_is_not_current_authority(proof,graph,kind):
    graph.graph_commit(candidate(proof));db=graph._db;db.execute('BEGIN')
    try:
        key=next(w.key for w in candidate(proof).writes if w.key.type_name==kind)
        value=json.loads(db.execute('SELECT value FROM graph_atoms WHERE token=?',(key.token,)).fetchone()[0])
        value['activation_generation']=2
        db.execute('UPDATE graph_atoms SET value=? WHERE token=?',(canonical_serialize(value),key.token))
        with pytest.raises(ValueError,match='producing history'):read(db,proof)
    finally:db.rollback()


def test_cold_sql_read_reauthenticates_actual_three_members(proof,graph):
    import sqlite3
    graph.graph_commit(candidate(proof));graph._db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    path=graph._db.execute('PRAGMA database_list').fetchone()[2]
    with sqlite3.connect('file:'+path+'?mode=ro',uri=True) as db:
        db.execute('BEGIN');assert read(db,proof)[0]==proof.batch;db.rollback()
