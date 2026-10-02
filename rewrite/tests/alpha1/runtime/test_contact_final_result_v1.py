"""Closed Contact return value against real adopted-original/ledger/Jobs SQL.

Admission and command digests are bounded fixture inputs to this codec seam;
the complete installed qualification/admission route remains a separate gate.
No mocked result assertion is used as the product result validator.
"""
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import sqlite3

import pytest

from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.runtime.contact_final_stage_v1 import _contact_final_result_v1, validate_contact_final_result_v1
from sylanne3.runtime.domain_production_originals_v1 import (
    TABLE, _receipt_wire, install_domain_production_originals_v1, read_adopted_domain_operation_v1,
)
from sylanne3.runtime.jobs import PersistentJob, install_schema, create_job, get_job
from sylanne3.runtime_contracts import CommitReceipt, NamespaceId, canonical_digest, canonical_serialize

NS=NamespaceId('bot','persona');D='a'*64


@pytest.fixture
def result_sql(tmp_path):
    store=GraphStore(tmp_path/'result.sqlite',TypeRegistry());db=store._db
    install_domain_production_originals_v1(db);install_schema(db)
    job=PersistentJob('job','operation','activity','effect',*NS.as_tuple,'snapshot','waiting','message',{},
        {'kind':'contact_host_takeover','operation_id':'operation'},'2030-01-01T00:01:00Z',
        'lease','quote',{},None,None,0,0,{},None)
    create_job(db,job,'create-job',D)
    receipt=CommitReceipt('committed','operation',D,'activity','effect',1,(),(),(),(),())
    payload={'namespace':asdict(NS),'identity':{'operation_id':'operation'}}
    digest=canonical_digest(payload)
    db.execute('INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)',
        (*NS.as_tuple,'operation',D,'activity','effect',1,canonical_serialize(_receipt_wire(receipt))))
    db.execute('INSERT INTO '+TABLE+' VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        (*NS.as_tuple,'operation','d08','prepare_contact_dispatch',D,digest,canonical_serialize(payload),'[]',
        D,canonical_serialize(_receipt_wire(receipt)),canonical_digest(receipt)))
    db.commit()
    result=_contact_final_result_v1(receipt=receipt,original_digest=digest,job_id=job.job_id,
        admission_ref='admission:fixture',dispatch_request_digest='b'*64)
    try:yield store,result
    finally:store.close()


def _validate(db,result):
    original=read_adopted_domain_operation_v1(db,NS,'operation')
    job=get_job(db,'job')
    return validate_contact_final_result_v1(result,original=original,job_id=job.job_id,
        admission_ref='admission:fixture',dispatch_request_digest='b'*64)


def test_closed_result_cold_sql_original_and_actual_job_are_readonly(result_sql):
    store,result=result_sql
    path=Path(store._db.execute('PRAGMA database_list').fetchone()[2])
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as cold:
        cold.execute('PRAGMA query_only=ON');cold.execute('BEGIN')
        assert _validate(cold,result)==result and cold.total_changes==0


@pytest.mark.parametrize('field',('schema','domain','operation_kind','operation_id','activity_id','original_ref',
    'original_digest','receipt','receipt_digest','job_states','coverage','missing_inputs','continuation_ref','outbox',
    'contact_admission_ref','dispatch_request_digest','unknown_key','receipt_bool'))
def test_saved_result_every_field_is_bound_to_independent_original(result_sql,field):
    store,result=result_sql;bad=deepcopy(result)
    if field=='unknown_key':bad['caller_permission']=True
    elif field=='receipt_bool':bad['receipt']['commit_seq']=True
    elif field=='receipt':bad['receipt']['operation_id']='another'
    elif field=='job_states':bad[field]=[['job','completed']]
    elif field in ('outbox','missing_inputs'):bad[field]=['invented']
    elif field=='continuation_ref':bad[field]='invented'
    else:bad[field]='changed'
    store._db.execute('BEGIN')
    try:
        with pytest.raises(ValueError,match='closed actual'):_validate(store._db,bad)
    finally:store._db.rollback()


@pytest.mark.parametrize('table',('original','ledger'))
def test_result_cannot_replace_corrupted_independent_sql_original(result_sql,table):
    store,result=result_sql
    if table=='original':store._db.execute('UPDATE '+TABLE+" SET receipt_digest=?",('b'*64,))
    else:store._db.execute('UPDATE graph_bundle_operations SET digest=?',('b'*64,))
    store._db.commit();store._db.execute('BEGIN')
    try:
        with pytest.raises(ValueError):_validate(store._db,result)
    finally:store._db.rollback()
