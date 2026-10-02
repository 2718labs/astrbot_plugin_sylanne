"""Synthetic signature/SQLite archive mechanics, not a Life producer test."""
import copy
import json
import sqlite3
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.c09_life_completed_archive_v1 import (
    SCHEMA,TABLE,TABLES,DDL,TRIGGERS,COLUMNS,life_inventory_fact_v1,
    read_completed_life_archive_v1,validate_life_archive_frame_v1,
    validate_completed_life_original_v1,validate_selected_life_carriers_v1,
    require_life_table_disposition_v1,
)
from sylanne3.runtime_contracts import canonical_digest,canonical_serialize
from c09_history_fixture_v2 import make_history_fixture


@pytest.fixture
def actual_control(tmp_path):
    control,_,_=make_history_fixture(tmp_path,build=False)
    try:yield control
    finally:control.lease.close()


def _unsigned(control):
    return dict(schema=SCHEMA,authority_id=control.authority_id,installation_id=control.installation_id,
        namespace='synthetic',operation_id='synthetic-erasure',pointer_version=1,
        manifest_digest='1'*64,quiescence_digest='2'*64,graph_barrier_commitment='3'*64,
        affected_atom_commitments=['4'*64],tables=[dict(table=t,present=False,columns=[],
            schema_commitment=canonical_digest(()),rows=[]) for t in TABLES],
        completed_jobs=[],status='authenticated_inventory_only_hold')


def _db(original=None):
    db=sqlite3.connect(':memory:',isolation_level=None);db.execute('BEGIN')
    db.execute(DDL)
    for sql in TRIGGERS:db.execute(sql)
    if original is not None:
        db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?)',(original['namespace'],original['operation_id'],
            canonical_serialize(original),original['inventory_digest']))
    return db


def test_actual_signature_empty_presence_and_bidirectional_fact(actual_control):
    original=actual_control.sign_original_v1(SCHEMA,_unsigned(actual_control),'inventory_digest')
    db=_db(original)
    try:
        facts=SimpleNamespace(namespace='synthetic',operation_id='synthetic-erasure',graph_facts=(life_inventory_fact_v1(original),))
        assert validate_life_archive_frame_v1(db,actual_control,facts,required=True)==original
        with pytest.raises(AuthorityUnavailable,match='bidirectional'):
            validate_life_archive_frame_v1(db,actual_control,SimpleNamespace(**{**vars(facts),'graph_facts':()}))
        db.execute(f'DROP TABLE {TABLE}')
        with pytest.raises(AuthorityUnavailable,match='bidirectional'):
            validate_life_archive_frame_v1(db,actual_control,facts,required=True)
        with pytest.raises(AuthorityUnavailable,match='bidirectional'):
            validate_life_archive_frame_v1(db,actual_control,SimpleNamespace(**{**vars(facts),'graph_facts':()}),required=True)
    finally:db.close()


def test_digest_recomputed_without_actual_signature_is_rejected(actual_control):
    original=actual_control.sign_original_v1(SCHEMA,_unsigned(actual_control),'inventory_digest')
    changed=copy.deepcopy(original);changed['manifest_digest']='9'*64
    replacement=actual_control.sign_original_v1(SCHEMA,changed,'inventory_digest')
    changed['inventory_digest']=replacement['inventory_digest']  # intentionally keep old signature
    db=_db(changed)
    try:
        with pytest.raises(AuthorityUnavailable,match='signature'):
            read_completed_life_archive_v1(db,actual_control,namespace='synthetic',operation_id='synthetic-erasure')
    finally:db.close()


@pytest.mark.parametrize('change',['old_schema','missing_family','unregistered_field','absent_with_rows'])
def test_closed_versions_and_full_family_presence(actual_control,change):
    original=actual_control.sign_original_v1(SCHEMA,_unsigned(actual_control),'inventory_digest')
    if change=='old_schema':original['schema']='sylanne3.c09.completed-life-inventory.v1'
    elif change=='missing_family':original['tables'].pop()
    elif change=='unregistered_field':original['source_text']='not permitted'
    else:original['tables'][0]['rows']=[{}]
    with pytest.raises(AuthorityUnavailable):validate_completed_life_original_v1(original)


def test_signed_document_never_substitutes_for_actual_private_scope(actual_control):
    original=actual_control.sign_original_v1(SCHEMA,_unsigned(actual_control),'inventory_digest')
    db=sqlite3.connect(':memory:',isolation_level=None);db.execute('BEGIN')
    try:
        with pytest.raises(AuthorityUnavailable,match='issued candidate scope'):
            require_life_table_disposition_v1(db,scope=original,table=TABLES[0],columns=(),rows=())
    finally:db.close()


def test_selected_rows_exact_and_removed_resurrection_refused(actual_control):
    # Real SQLite rows exercise the post-candidate invariant. Their synthetic
    # payloads are not represented as authenticated producer originals.
    from sylanne3.runtime.internal_life_content_preparation_v1 import DDL as D0,TRIGGERS as T0
    from sylanne3.runtime.internal_life_content_worker_v2 import DDL as D1,TRIGGERS as T1
    from sylanne3.runtime.internal_life_paid_result_v2 import DDL as D2,TRIGGERS as T2
    db=sqlite3.connect(':memory:',isolation_level=None);db.execute('BEGIN')
    body=_unsigned(actual_control);families=[];saved=[]
    try:
        for table,ddl,triggers,kinds in zip(TABLES,(D0,D1,D2),(T0,T1,T2),
                (('prepared','prepare_commit'),('binding','request','acquire_commit','call'),('read_attempt','result','adoption_commit'))):
            db.execute(ddl)
            for sql in triggers:db.execute(sql)
            columns=tuple(v[1] for v in db.execute(f'PRAGMA table_info({table})'))
            members=[]
            for job,disposition in (('keep','preserved_exact'),('remove','derived_removed')):
                for kind in kinds:
                    row=('synthetic','persona',kind,job,canonical_serialize({'synthetic':job}),canonical_digest(job),'5'*64)
                    member=dict(kind=kind,locator_commitment=canonical_digest(row[:4]),row_commitment=canonical_digest((table,columns,row)),
                        job_commitment=canonical_digest(job),disposition=disposition)
                    members.append(member)
                    if disposition=='preserved_exact':db.execute(f'INSERT INTO {table} VALUES(?,?,?,?,?,?,?)',row)
                    else:saved.append((table,row))
            families.append(dict(table=table,present=True,columns=list(columns),rows=members,
                schema_commitment=canonical_digest(tuple(db.execute('SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? ORDER BY type,name',(table,))))))
        body['tables']=families
        body['completed_jobs']=[dict(job_commitment=canonical_digest(job),model_original_digest='6'*64,
            adoption_commitment='7'*64,receipt_commitment='8'*64,source_association_commitment='9'*64,disposition=disposition)
            for job,disposition in (('keep','preserved_exact'),('remove','derived_removed'))]
        original=actual_control.sign_original_v1(SCHEMA,body,'inventory_digest')
        validate_selected_life_carriers_v1(db,original)
        table,row=saved[0];db.execute(f'INSERT INTO {table} VALUES(?,?,?,?,?,?,?)',row)
        with pytest.raises(AuthorityUnavailable,match='resurrected'):
            validate_selected_life_carriers_v1(db,original)
    finally:db.close()


def test_real_genesis_pointer_is_a_valid_pre_switch_archive_basis(actual_control):
    # Real Control keeps pointer zero through INTENT/PREPARED. Only SWITCHED
    # increments it; an archive cannot demand a not-yet-performed switch.
    current=actual_control.read_verified_current_storage_v1()
    assert current.pointer_version==0
    body=_unsigned(actual_control);body['pointer_version']=current.pointer_version
    original=actual_control.sign_original_v1(SCHEMA,body,'inventory_digest')
    assert validate_completed_life_original_v1(original)==original
    for bad in (-1,False):
        changed={**original,'pointer_version':bad}
        with pytest.raises(AuthorityUnavailable,match='closed original'):
            validate_completed_life_original_v1(changed)
