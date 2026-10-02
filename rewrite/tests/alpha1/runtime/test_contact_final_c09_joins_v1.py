"""C09 historical Contact joins against actual fixture history/Owner tables.

Real closed decoders and SQL joins run; local fixture TypeSpecs and unsigned
permit contents do not authenticate a current Authority finish. Erasure stays
HOLD and no installed immutable Contact adoption is claimed.
"""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import re

import pytest

from test_contact_qualification_evidence_v1 import sql_evidence
from sylanne3.authority_service.v2_contract import FencePermitV2, canonical_digest as adigest, to_wire
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.graph_types import AtomKey, GraphVersion, NamespaceEpoch
from sylanne3.runtime.c09_contact_final_v1 import validate_contact_final_original_joins_v1, require_contact_final_erasure_finish_v1
from sylanne3.runtime.contact_final_stage_v1 import _contact_final_result_v1
from sylanne3.runtime.d11_types import job_graph_write
from sylanne3.runtime.jobs import PersistentJob
from sylanne3.runtime_contracts import CommitReceipt, canonical_digest, canonical_serialize


@pytest.fixture
def history_join(sql_evidence):
    evidence,proof,store=sql_evidence;db=store._db;ns=evidence.namespace
    source=(Path(__file__).parents[3]/'sylanne3'/'graph_coordinator.py').read_text()
    ddl=re.search(r'CREATE TABLE IF NOT EXISTS graph_owner_domain_attempts_v3\s*\(.*?\);',source,re.S).group(0)
    db.execute(ddl)
    job_ref=AtomKey.from_token(proof['job_ref'])
    job=PersistentJob(job_ref.name,'operation','activity','effect',*ns.as_tuple,'snapshot','waiting','message',{},
        {'kind':'contact_host_takeover','operation_id':'operation'},'2030-01-01T00:01:00Z',
        'lease','quote',{},None,None,0,0,{},None)
    value=canonical_serialize(job_graph_write(job).value)
    db.execute('UPDATE graph_atoms SET value=? WHERE token=?',(value,job_ref.token))
    db.execute('UPDATE graph_history SET value=? WHERE token=?',(value,job_ref.token))
    permit=FencePermitV2('authority','authority:fixture','subject','holder',1,'write','attempt','1'*64,1,0,evidence.effect_snapshot.anchor)
    snapshot=replace(evidence.effect_snapshot,permit_digest=adigest(permit))
    qualified=replace(evidence.qualification,d08_scope=replace(evidence.qualification.d08_scope,authority_snapshot_digest=adigest(snapshot)))
    evidence=replace(evidence,qualification=qualified,effect_snapshot=snapshot,
        members=tuple(replace(row,value_json=value) if row.ref==job_ref.token else row for row in evidence.members))
    proof=deepcopy(proof);proof['qualification_evidence']=plain_v1(evidence);proof['qualification_digest']=qualified.digest
    next(row for row in proof['write_commitments'] if row['ref']==job_ref.token)['digest']=canonical_digest(json.loads(value))
    receipt=CommitReceipt('committed','operation','a'*64,'activity','effect',1,(),
        tuple(GraphVersion(AtomKey.from_token(row['ref']),row['revision']) for row in proof['write_commitments']),
        (NamespaceEpoch(*ns.as_tuple,2),),(),())
    payload={'provenance':proof,'authority':{'activation_generation':1}}
    digest=canonical_digest(payload)
    result=_contact_final_result_v1(receipt=receipt,original_digest=digest,job_id=job.job_id,
        admission_ref=proof['admission_ref'],dispatch_request_digest=proof['request_digest'])
    wire=canonical_serialize(to_wire(permit))
    db.execute('INSERT INTO graph_owner_domain_attempts_v3 VALUES(?,?,?,?,?,?,?,?,?,?)',
        (*ns.as_tuple,'operation','a'*64,'attempt','{}',1,1,wire,canonical_serialize(result)))
    db.execute('INSERT INTO graph_bundle_fences_v2 VALUES(?,?,?,?,?,?,?,?,?,?,?)',
        (*ns.as_tuple,'operation','a'*64,wire,1,1,2,2,'finish:attempt','sha256:'+'a'*64))
    db.commit()
    return evidence,payload,receipt,digest,result,store


def _read(case):
    evidence,payload,receipt,digest,_,store=case
    return validate_contact_final_original_joins_v1(store._db,namespace=evidence.namespace,
        operation_id='operation',payload=payload,receipt=receipt,original_digest=digest,registry=store._registry)


def test_actual_history_join_authenticates_closed_result_but_not_finish(history_join):
    evidence,payload,_,_,_,store=history_join;db=store._db;before=db.total_changes
    db.execute('BEGIN')
    try:
        assert _read(history_join)==evidence
        with pytest.raises(ValueError,match='preserve full inventory'):require_contact_final_erasure_finish_v1(payload['provenance'])
        assert db.total_changes==before
    finally:db.rollback()


def test_historical_qualification_uses_complete_latest_heads_not_truncated_history(history_join):
    from sylanne3.runtime.contact_qualification_evidence_v1 import verify_historical_contact_qualification_sql_v1
    evidence,_,_,_,_,store=history_join;db=store._db
    db.execute('BEGIN')
    try:
        assert verify_historical_contact_qualification_sql_v1(db,evidence,registry=store._registry)==evidence
        # A new fixed-family token was present at the recorded epoch but is
        # absent from the authenticated complete query. It must not disappear
        # through a historical prefix LIMIT or a proof-members-only query.
        from sylanne3.graph_types import Owner
        key=AtomKey(Owner('event',*evidence.namespace.as_tuple,'orphan'),'d08.action_outcome.v1','orphan')
        event=db.execute('SELECT event_bot,event_persona,event_session,event_id FROM graph_history LIMIT 1').fetchone()
        db.execute('INSERT INTO graph_history VALUES(?,?,?,?,?,?,?,?,?)',
            (key.token,1,'{}',1,'[]',*event))
        with pytest.raises(ValueError,match='full query inventory'):
            verify_historical_contact_qualification_sql_v1(db,evidence,registry=store._registry)
    finally:db.rollback()


@pytest.mark.parametrize('change',('result_extra','result_ref','receipt_bool','job_state','permit','deleted_source','history_job'))
def test_c09_actual_history_or_saved_shell_drift_refuses(history_join,change):
    evidence,_,_,_,result,store=history_join;db=store._db
    bad=deepcopy(result)
    if change=='result_extra':bad['caller_permission']=True
    if change=='result_ref':bad['original_ref']='fake'
    if change=='receipt_bool':bad['receipt']['commit_seq']=True
    if change=='job_state':bad['job_states'][0][1]='completed'
    if change in ('result_extra','result_ref','receipt_bool','job_state'):
        db.execute('UPDATE graph_owner_domain_attempts_v3 SET receipt_json=?',(canonical_serialize(bad),))
    if change=='permit':
        raw=json.loads(db.execute('SELECT permit_json FROM graph_owner_domain_attempts_v3').fetchone()[0]);raw['holder']='changed'
        wire=canonical_serialize(raw)
        db.execute('UPDATE graph_owner_domain_attempts_v3 SET permit_json=?',(wire,));db.execute('UPDATE graph_bundle_fences_v2 SET permit_json=?',(wire,))
    if change=='deleted_source':db.execute('DELETE FROM graph_history WHERE token=?',(evidence.expression_roots[0],))
    if change=='history_job':db.execute('UPDATE graph_history SET value=? WHERE token=?',('{}',next(row.ref for row in evidence.members if AtomKey.from_token(row.ref).type_name=='runtime.job')))
    db.commit();db.execute('BEGIN')
    try:
        with pytest.raises((ValueError,TypeError)):_read(history_join)
    finally:db.rollback()
