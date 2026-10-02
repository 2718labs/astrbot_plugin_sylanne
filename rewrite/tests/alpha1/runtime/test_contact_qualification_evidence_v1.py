"""Permanent closed-evidence SQL/codec regressions, with bounded local rows.

These fixtures prove wire, inventory, Source purpose and actual SQLite joins.
Their nine write bodies/Owner grant use fixture TypeSpecs, not installed six
provider permission or Authority authentication. No network clients exist.
"""
from copy import deepcopy
from dataclasses import replace
import json
import sqlite3

import pytest

from sylanne3.authority_service.d10_contact_policy_service_v1 import D10ContactPolicyOriginalV1
from sylanne3.authority_service.v2_contract import AuthorityCurrentEffectSnapshotV2, canonical_digest as adigest
from sylanne3.authority_service.v2_execution_bridge import CurrentEffectReadV2
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.domains.d08.contact_dispatch_check_v1 import D08NegativeQueryV2, DispatchCheckScopeV2
from sylanne3.domains.d10 import ContactPolicy
from sylanne3.domains.d10.contact_claim_v2 import contact_window_id_v2
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphVersion, Owner, TypeRegistry, TypeSpec, owner_grant_key
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.runtime.contact_final_action_v1 import CONTACT_REQUIRED_PROVIDERS_V1, ContactCheckVersionSetV1, CurrentContactCheckVersionsV1
from sylanne3.runtime.contact_final_stage_v1 import _CONTACT_FINAL_WRITE_TYPES, validate_contact_final_provenance_v1
from sylanne3.runtime.contact_qualification_v1 import CurrentContactQualificationV1
from sylanne3.runtime.contact_route_binding_v1 import CurrentContactRouteBindingV1, contact_route_semantic_digest_v1
from sylanne3.graph_types import IngressIdentityReceipt
from sylanne3.runtime.first_ingress_v2 import ingress_ids
from sylanne3.runtime.contact_qualification_evidence_v1 import (
    ContactQualificationEvidenceV1, CONTACT_FINAL_QUERY_TYPES_V1, decode_contact_qualification_evidence_v1,
    verify_contact_qualification_sql_v1, verify_historical_contact_qualification_sql_v1,
)
from sylanne3.runtime.c09_contact_final_v1 import require_contact_final_erasure_finish_v1
from sylanne3.runtime.d10_offline_tick_execution_v1 import OfflineTickGraphReadV1
from sylanne3.runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1, ProductionQueryCoverageV1
from sylanne3.runtime.domain_production_erasure_v1 import DomainProductionErasureHold
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import CheckReceipt, NamespaceId, QueryEpoch, VersionedRef, canonical_digest, canonical_serialize

NS=NamespaceId('bot','persona')
D='a'*64
ROUTE='b'*64


def qualification_fixture_values():
    """Full finite typed evidence for a schema seam; never a provider grant."""
    members=[]
    for kind in sorted(_CONTACT_FINAL_WRITE_TYPES):
        owner=Owner('persona',*NS.as_tuple) if kind=='d10.contact_claim.v2' else Owner('activity',*NS.as_tuple,'activity')
        key=AtomKey(owner,kind,'member');members.append(OfflineTickGraphReadV1(key.token,1,canonical_serialize({'fixture':kind}),True))
    owner=owner_grant_key(*NS.as_tuple);owner_value={'fixture':'owner'}
    members.append(OfflineTickGraphReadV1(owner.token,1,canonical_serialize(owner_value),True))
    structure_key=AtomKey(Owner('persona',*NS.as_tuple),'d03.role_binding','structure')
    members.append(OfflineTickGraphReadV1(structure_key.token,1,canonical_serialize({'source_refs':[source_key(*NS.as_tuple,'structure').token]}),True))
    entity_key=AtomKey(Owner('persona',*NS.as_tuple),'d03.entity_anchor','entity:fixture')
    event_key=AtomKey(Owner('event',*NS.as_tuple,ROUTE),'d03.world_event','event')
    account_key=AtomKey(Owner('persona',*NS.as_tuple),'d03.account_binding','account:fixture')
    for key,value in ((entity_key,{'entity_id':'entity:fixture'}),
            (event_key,{'source_refs':[source_key(*NS.as_tuple,ROUTE).token]}),
            (account_key,{'verification_ref':event_key.token,'entity_id':'entity:fixture','platform_namespace':'fixture', 'platform_identifier':'user'})):
        members.append(OfflineTickGraphReadV1(key.token,1,canonical_serialize(value),True))
    for source_id,audiences,purposes in (('claim',('user',),('expression',)),(ROUTE,('user',),('context',)),
            ('structure',('owner',),('audit',)),('criterion',('owner',),('context',))):
        source=SourceRecord(source_id,'Fixture','owner','reported','confirmed',0,0,'fixture',audiences,purposes)
        members.extend((OfflineTickGraphReadV1(source_key(*NS.as_tuple,source_id).token,1,canonical_serialize(source.to_dict()),True),
            OfflineTickGraphReadV1(access_key(*NS.as_tuple,source_id).token,1,canonical_serialize({
                'source_id':source_id,'audiences':list(audiences),'purposes':list(purposes),'status':'active','recorded_at':0.}),True),
            OfflineTickGraphReadV1(source_correction_head_key(NS,source_id).token,0,'{}',False)))
    members=tuple(sorted(members,key=lambda row:row.ref));positives=tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision) for row in members if row.valid)
    pages=tuple(ProductionQueryCoverageV1(QueryEpoch(NS,'namespace',2),kind,
        tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision) for row in members
            if row.revision and AtomKey.from_token(row.ref).type_name==kind),True,None) for kind in CONTACT_FINAL_QUERY_TYPES_V1)
    policy=ContactPolicy('policy:one',NS,1,'user','private','ordinary',True,False,1,0.,24.)
    original=D10ContactPolicyOriginalV1('authority:fixture','authority','installation',NS,policy,'owner','sha256:'+D,1,1,
        contact_window_id_v2(policy),'approve','issue',0.,D)
    anchor=RestoreAnchor('authority','authority:fixture',1,'deletion',0,'genesis','execution',0,'genesis',0,'fixture-proof')
    snapshot=AuthorityCurrentEffectSnapshotV2('authority','authority:fixture',anchor,'sha256:'+D,0,'genesis','complete',())
    effect=CurrentEffectReadV2('authority','authority:fixture','effect',1,'absent',0,'genesis')
    identity=ingress_fixture_identity()
    ingress=IngressIdentityReceipt(canonical_serialize(identity),D,1.,D)
    route=CurrentContactRouteBindingV1(NS,'entity:fixture','fixture','user','user','scene:fixture',
        GraphVersion(account_key,1),GraphVersion(entity_key,1),GraphVersion(event_key,1),source_key(*NS.as_tuple,ROUTE).token,
        canonical_digest(ingress),QueryEpoch(NS,'all',2))
    sets=[];checks=[]
    for kind,issuer in CONTACT_REQUIRED_PROVIDERS_V1:
        criterion='criterion:'+kind;versions=(VersionedRef(criterion,1),)
        if kind=='source_grant':
            criterion=source_key(*NS.as_tuple,'criterion').token
            versions=tuple(VersionedRef(key.token,1) for key in (source_key(*NS.as_tuple,'claim'),access_key(*NS.as_tuple,'claim'),AtomKey.from_token(criterion)))
        sets.append(ContactCheckVersionSetV1(kind,criterion,versions))
        checks.append(CheckReceipt(kind,'persona:persona','member','expression',versions,'full','pass',10.,issuer))
    versions=CurrentContactCheckVersionsV1(NS,2,positives,tuple(sets),'quote',1,'grant',1,D,original.original_ref,original.digest)
    negative=tuple(D08NegativeQueryV2(predicate,QueryEpoch(NS,'all',2),tuple(VersionedRef(row.ref,row.revision)
        for row in members if row.valid and AtomKey.from_token(row.ref).type_name in types),()) for predicate,types in (
            ('d08.same_target_unfinished_commitments.v1',{'d08.commitment.v1'}),
            ('d08.same_target_unfinished_actions.v1',{'d08.action_intent.v1','d08.action_outcome.v1'})))
    d08=DispatchCheckScopeV2('member',QueryEpoch(NS,'all',2),anchor,adigest(snapshot),(),negative,checks[3])
    predicates=(source_correction_head_key(NS,'structure').token,'d03.role_binding:all_valid','d05.boundary_rule:all_valid',
        'd10.contact_policy.v1:all','d10.proactive_opportunity.v1:all','d10.contact_claim.v1:all','d10.contact_claim.v2:all')
    qualified=CurrentContactQualificationV1(tuple(checks),versions,positives,predicates,d08,contact_route_semantic_digest_v1(route),original.digest)
    evidence=ContactQualificationEvidenceV1(NS,'operation',1,2,0,0,1.,10.,'user',
        (source_key(*NS.as_tuple,'claim').token,),(source_key(*NS.as_tuple,ROUTE).token,),
        (source_key(*NS.as_tuple,'structure').token,),route,qualified,members,pages,
        ProductionOwnerGuardV1(owner.token,1,canonical_digest(owner_value),D),original,effect,snapshot)
    writes=[{'ref':row.ref,'revision':row.revision,'digest':canonical_digest(json.loads(row.value_json))} for row in members
        if AtomKey.from_token(row.ref).type_name in _CONTACT_FINAL_WRITE_TYPES]
    refs={AtomKey.from_token(row['ref']).type_name:row['ref'] for row in writes}
    provenance=dict(reviewed_content_digest=D,qualification_digest=qualified.digest,admission_ref='admission:'+'c'*40,
        admission_receipt_digest='d'*64,request_digest='e'*64,footprint_digest='f'*64,write_commitments=writes,
        job_ref=refs['runtime.job'],outbox_ref=refs['runtime.outbox'],qualification_evidence=plain_v1(evidence),commit_state='committed_pending_finish')
    return evidence,provenance


def ingress_fixture_identity():
    return dict(schema='sylanne3.ingress.identity.v1',namespace=list(NS.as_tuple),operation_id=ingress_ids(ROUTE)[2],
        source_ref=ROUTE,platform_ref='fixture',conversation_ref='user',sender_ref='user',message_id='message',visibility='private',lineage=[])


@pytest.fixture
def sql_evidence(tmp_path):
    evidence,proof=qualification_fixture_values();registry=TypeRegistry()
    for kind in {AtomKey.from_token(row.ref).type_name for row in evidence.members} | set(CONTACT_FINAL_QUERY_TYPES_V1):
        registry.register(TypeSpec(kind,('persona','activity','event'),'state',lambda value:value))
    store=GraphStore(tmp_path/'contact.db',registry);db=store._db
    # The actual identity reader joins all four installed identity/intent/
    # observation/bundle records. Only their fixture content is synthetic.
    from pathlib import Path
    import re
    coordinator=Path(__file__).parents[3]/'sylanne3'/'graph_coordinator.py'
    source=coordinator.read_text()
    ddl=re.search(r'CREATE TABLE IF NOT EXISTS graph_first_ingress_identity_v1\(.*?\)"""',source,re.S).group(0)[:-3]
    db.execute(ddl)
    db.execute('CREATE TABLE ingress_first_observations(bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,'
        'content_fingerprint TEXT NOT NULL,learned_at REAL NOT NULL CHECK(learned_at>0),bundle_digest TEXT,PRIMARY KEY(bot,persona,operation_id))')
    ingress_op=ingress_ids(ROUTE)[2];identity=ingress_fixture_identity()
    db.execute('INSERT INTO graph_first_ingress_identity_v1(bot,persona,operation_id,source_ref,platform_ref,conversation_ref,sender_ref,message_id,'
        'visibility,identity_json,content_fingerprint,learned_at,bundle_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (*NS.as_tuple,ingress_op,ROUTE,'fixture','user','user','message','private',canonical_serialize(identity),D,1.,D))
    db.execute('INSERT INTO ingress_first_observations VALUES(?,?,?,?,?,?)',(*NS.as_tuple,ingress_op,D,1.,D))
    db.execute('INSERT INTO graph_first_ingress_intents_v2 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        (*NS.as_tuple,ingress_op,canonical_serialize({'fingerprint':D}),1.,10.,10.,'ingress-fence','{}','{}',0,0))
    db.execute('INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)',(*NS.as_tuple,ingress_op,D,'activity',None,1,'{}'))
    db.execute('INSERT INTO graph_authority_epochs VALUES(?,?,?,?)',(*NS.as_tuple,0,0))
    db.execute('INSERT INTO graph_events VALUES(?,?,?,?,?,?,?,?,?,?)',(*NS.as_tuple,'activity','operation',D,'[]','[]','[]','[]',2))
    for row in evidence.members:
        if row.revision:
            key=AtomKey.from_token(row.ref)
            db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',(row.ref,*NS.as_tuple,key.owner.kind,key.owner.subject,key.type_name,key.name,row.revision,row.value_json,int(row.valid)))
            db.execute('INSERT INTO graph_history VALUES(?,?,?,?,?,?,?,?,?)',(row.ref,row.revision,row.value_json,int(row.valid),'[]',*NS.as_tuple,'activity','operation'))
    db.commit()
    try:yield evidence,proof,store
    finally:store.close()


def test_typed_canonical_full_evidence_and_context_only_scope_roundtrip():
    evidence,proof=qualification_fixture_values()
    assert decode_contact_qualification_evidence_v1(proof['qualification_evidence'],expected_digest=proof['qualification_digest'])==evidence
    assert len(validate_contact_final_provenance_v1(proof))==len(evidence.members)
    assert evidence.structural_roots != evidence.context_roots != evidence.expression_roots
    assert evidence.owner_policy.digest==evidence.qualification.owner_policy_digest


def test_real_cold_sql_current_and_historical_inventory_are_readonly(sql_evidence):
    evidence,_,store=sql_evidence
    with sqlite3.connect(store._db.execute('PRAGMA database_list').fetchone()[2]) as cold:
        cold.execute('PRAGMA query_only=ON');cold.execute('BEGIN')
        assert verify_contact_qualification_sql_v1(cold,evidence,registry=store._registry)==evidence
        assert verify_historical_contact_qualification_sql_v1(cold,evidence,registry=store._registry)==evidence
        assert cold.total_changes==0


@pytest.mark.parametrize('change',('missing','bool_generation','wrong_digest','trim_inventory','missing_query','partial_query',
    'provider_version','criterion_version','fake_criterion','missing_criterion','fake_owner','source_permission','missing_ancestor',
    'route_expression_only','structural_wrong_audience','fake_d08_scan','missing_d08_family','fake_effect','fake_namespace',
    'missing_predicate','changed_predicate','wrong_subject','wrong_action','owner_head_drift'))
def test_closed_qualification_missing_tampered_or_fabricated_inputs_refuse(change):
    evidence,proof=qualification_fixture_values();raw=deepcopy(proof['qualification_evidence'])
    expected=proof['qualification_digest'];q=raw['qualification']
    if change=='missing':del raw['owner_policy']
    if change=='bool_generation':raw['activation_generation']=True
    if change=='wrong_digest':expected='f'*64
    if change=='trim_inventory':raw['members'].pop()
    if change=='missing_query':raw['query_coverage'].pop()
    if change=='partial_query':raw['query_coverage'][0]['complete']=False
    if change=='provider_version':q['checks'][0]['input_versions'][0]['version']=2
    if change=='criterion_version':q['check_versions']['sets'][2]['versions'][-1]['version']=2
    if change=='fake_criterion':q['check_versions']['sets'][2]['criteria_ref']='unbacked'
    if change=='missing_criterion':q['check_versions']['sets'][2]['versions'].pop()
    if change=='fake_owner':raw['owner_policy']['signature']='f'*64
    if change in ('source_permission','route_expression_only','structural_wrong_audience'):
        source={'source_permission':'claim','route_expression_only':ROUTE,'structural_wrong_audience':'structure'}[change]
        row=next(row for row in raw['members'] if row['ref']==source_key(*NS.as_tuple,source).token)
        value=json.loads(row['value_json'])
        if change=='structural_wrong_audience':value['audiences']=['user']
        else:value['purposes']=['context' if change=='source_permission' else 'expression']
        row['value_json']=canonical_serialize(value)
    if change=='missing_ancestor':
        row=next(row for row in raw['members'] if row['ref']==source_key(*NS.as_tuple,'claim').token)
        value=json.loads(row['value_json']);value['parent_source_ids']=['absent'];row['value_json']=canonical_serialize(value)
    if change=='fake_d08_scan':q['d08_scope']['negative_queries'][1]['scanned_versions']=[]
    if change=='missing_d08_family':q['d08_scope']['negative_queries'].pop()
    if change=='fake_effect':raw['current_effect']['state']='unresolved'
    if change=='fake_namespace':raw['namespace']['bot_id']='other'
    if change=='missing_predicate':q['negative_predicates'].pop()
    if change=='changed_predicate':q['negative_predicates'][-1]='d10.arbitrary:all'
    if change=='wrong_subject':q['checks'][0]['subject_ref']='persona:other'
    if change=='wrong_action':q['checks'][0]['action_ref']='other'
    if change=='owner_head_drift':raw['owner_guard']['owner_head_digest']='f'*64
    if change!='wrong_digest':
        from sylanne3.runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        expected=decode_typed_production_value_v1(q,CurrentContactQualificationV1).digest
    with pytest.raises((ValueError,TypeError,KeyError,DomainProductionErasureHold)):
        decode_contact_qualification_evidence_v1(raw,expected_digest=expected)


@pytest.mark.parametrize('change',('member','new_outcome','deleted_source','historical','new_historical','rights'))
def test_actual_sql_or_history_drift_is_refused(sql_evidence,change):
    evidence,_,store=sql_evidence;db=store._db
    if change=='member':db.execute('UPDATE graph_atoms SET value=? WHERE token=?',('{}',evidence.owner_guard.grant_ref))
    if change=='deleted_source':db.execute('DELETE FROM graph_atoms WHERE token=?',(evidence.expression_roots[0],))
    if change=='rights':db.execute('UPDATE graph_authority_epochs SET delete_epoch=1')
    if change in ('new_outcome','new_historical'):
        key=AtomKey(Owner('activity',*NS.as_tuple,'activity'),'d08.action_outcome.v1','extra')
        if change=='new_outcome':db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',(key.token,*NS.as_tuple,key.owner.kind,key.owner.subject,key.type_name,key.name,1,'{}',1))
        else:db.execute('INSERT INTO graph_history VALUES(?,?,?,?,?,?,?,?,?)',(key.token,1,'{}',1,'[]',*NS.as_tuple,'activity','operation'))
    if change=='historical':db.execute('UPDATE graph_history SET value=? WHERE token=?',('{}',evidence.expression_roots[0]))
    db.commit();db.execute('BEGIN')
    verifier=verify_historical_contact_qualification_sql_v1 if change in ('historical','new_historical') else verify_contact_qualification_sql_v1
    with pytest.raises(ValueError):verifier(db,evidence,registry=store._registry)
    db.rollback()


def test_c09_pending_marker_cannot_release_or_erase_unknown_inventory(sql_evidence):
    _,proof,store=sql_evidence;before=store._db.total_changes
    with pytest.raises(ValueError,match='preserve full inventory'):
        require_contact_final_erasure_finish_v1(proof)
    assert store._db.total_changes==before
    changed=deepcopy(proof);changed['commit_state']='finished'
    with pytest.raises(ValueError,match='cannot claim'):
        validate_contact_final_provenance_v1(changed)


def test_c09_rejects_previous_digest_only_final_shape():
    _,proof=qualification_fixture_values()
    del proof['qualification_evidence'];del proof['commit_state']
    with pytest.raises(ValueError,match='fields differ'):validate_contact_final_provenance_v1(proof)
