"""Opaque authentication contracts and real SQL; signing fixtures are seams.

The private issuer's installed positive path is tested by the separate four
store case. No fixture signature authorizes erasure or sanitized restore.
"""
from dataclasses import asdict, fields, replace
import hashlib
import hmac
import json
import sqlite3

import pytest

from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.c09_contact_frame_authentication_v1 import (
    AuthenticatedContactFrozenFrameV1, SignedContactFrozenFrameV1, SIGNED_SCHEMA,
    TABLE, COLUMNS, DDL, decode_contact_frame_authentication_v1,
    install_contact_frame_authentication_schema_v1, require_contact_frame_authentication_schema_v1,
    validate_contact_frame_authentication_row_v1, verify_contact_frame_authentication_v1,
    _issue_authenticated_contact_frames_v1,
)
from sylanne3.authority_service.c09_contact_carrier_inventory_v2 import (
    _authentication_family_in_tx_v2, ContactCarrierFamilyV2, ContactCarrierInventoryV2,
    CARRIER_FAMILIES_V2, decode_contact_carrier_inventory_v2,
)
from sylanne3.authority_service.c09_storage_control_v1 import C09StorageControlV1, InstalledC09InstanceLeaseV1


def committed(kind, field, values):
    values = dict(values)
    values[field] = canonical_digest(tuple(values[f.name] if f.name in values else f.default
        for f in fields(kind) if f.name != field))
    return kind(**values)


@pytest.fixture
def control(tmp_path):
    state = tmp_path / 'state'; state.mkdir()
    key = tmp_path / 'fixture-signing-key'; key.write_bytes(b'generated-test-key-material-only!!')
    with InstalledC09InstanceLeaseV1(tmp_path / 'lease') as lease:
        yield C09StorageControlV1(control_path=tmp_path/'control.db', key_path=key,
            installation_id='test-installation', authority_id='test-authority',
            control_store_id='test-control', key_id='test-key', lease=lease, resource_roots=(state,))


@pytest.fixture
def authentication(control):
    return committed(AuthenticatedContactFrozenFrameV1,'authentication_digest',dict(
        authority_commitment=canonical_digest(('authority',control.authority_id)),
        installation_commitment=canonical_digest(('installation',control.installation_id)),
        namespace_commitment=canonical_digest(('namespace','bot/persona')),
        source_operation_commitment=canonical_digest(('operation','erase')),
        frame_operation_commitment=canonical_digest(('operation','erase')),
        origin='actual_unswitched_freeze',frame_digest='a'*64,pin_digest='b'*64,inventory_digest='c'*64,
        source_seal_digest='d'*64,prepared_digest=None,old_signature_commitment=None,
        member_commitments=(),producing_generation=1,observed_generation=1,
        observation_seq=4,observation_anchor_digest='e'*64))


def signing_seam(control, authentication):
    key = canonical_digest(('c09.key',control.key_id))
    digest = canonical_digest((authentication,key,SIGNED_SCHEMA))
    signature = hmac.new(control._key,(SIGNED_SCHEMA+'\n'+digest).encode(),hashlib.sha256).hexdigest()
    return SignedContactFrozenFrameV1(authentication,key,digest,signature)


def wire(value):return json.loads(canonical_serialize(asdict(value)))


def sql_row(value):
    a=value.authentication
    return (a.namespace_commitment,a.source_operation_commitment,a.frame_digest,
        canonical_serialize(asdict(value)),value.original_digest)


def test_actual_protected_lease_signature_and_closed_roundtrip(control,authentication):
    value=signing_seam(control,authentication)
    assert verify_contact_frame_authentication_v1(control,decode_contact_frame_authentication_v1(wire(value)))==value
    assert not {'namespace','operation_id','facts_json','prepared_original_json','resolved_path','key_id'} & set(wire(authentication))
    with pytest.raises(AuthorityUnavailable):verify_contact_frame_authentication_v1(control,replace(value,signature='0'*64))
    control.lease.close()
    with pytest.raises(AuthorityUnavailable):verify_contact_frame_authentication_v1(control,value)


@pytest.mark.parametrize('change',['generation_bool','invent_signature','old_origin_no_prepared','member_duplicate','observer_backwards'])
def test_recomputed_authentication_rejects_origin_and_inventory_drift(authentication,change):
    values={f.name:getattr(authentication,f.name) for f in fields(authentication)}
    if change=='generation_bool':values['observed_generation']=True
    elif change=='invent_signature':values['old_signature_commitment']='f'*64
    elif change=='old_origin_no_prepared':values['origin']='signed_prepared_history'
    elif change=='member_duplicate':values['member_commitments']=('f'*64,'f'*64)
    else:values['producing_generation']=2
    with pytest.raises(AuthorityUnavailable):committed(AuthenticatedContactFrozenFrameV1,'authentication_digest',values)


@pytest.mark.parametrize('change',['unknown','missing','oversized'])
def test_closed_authentication_wire_rejects_unrecognized_body(control,authentication,change):
    raw=wire(signing_seam(control,authentication))
    if change=='unknown':raw['authentication']['old_prepared_json']={}
    elif change=='missing':del raw['authentication']['frame_digest']
    else:raw['authentication']['member_commitments']=['a'*64]*1025
    with pytest.raises(AuthorityUnavailable):decode_contact_frame_authentication_v1(raw)


def test_actual_sql_authentication_rollback_cold_read_and_immutable_guard(tmp_path,control,authentication):
    value=signing_seam(control,authentication);row=sql_row(value);path=tmp_path/'core.db'
    with sqlite3.connect(path) as db:
        db.execute('BEGIN');install_contact_frame_authentication_schema_v1(db)
        db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?)',row);db.rollback()
        assert db.execute("SELECT 1 FROM sqlite_master WHERE name=?",(TABLE,)).fetchone() is None
        db.execute('BEGIN');install_contact_frame_authentication_schema_v1(db)
        db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?)',row);db.commit()
    with sqlite3.connect(path) as db:
        db.execute('BEGIN');require_contact_frame_authentication_schema_v1(db)
        actual=db.execute(f'SELECT * FROM {TABLE}').fetchone()
        assert verify_contact_frame_authentication_v1(control,validate_contact_frame_authentication_row_v1(COLUMNS,actual))==value
        family=_authentication_family_in_tx_v2(db,namespace='bot/persona')
        assert family.present and len(family.rows)==1
        assert not _authentication_family_in_tx_v2(db,namespace='other/persona').rows
        for sql in (f'UPDATE {TABLE} SET original_digest=original_digest',f'DELETE FROM {TABLE}'):
            with pytest.raises(sqlite3.IntegrityError,match='immutable'):db.execute(sql)
        db.rollback()


def test_actual_sql_row_requires_exact_locator_and_canonical_body(control,authentication):
    row=sql_row(signing_seam(control,authentication))
    for index,replacement in ((0,'f'*64),(2,'f'*64),(3,json.dumps(wire(signing_seam(control,authentication)),indent=2))):
        changed=list(row);changed[index]=replacement
        with pytest.raises(AuthorityUnavailable):validate_contact_frame_authentication_row_v1(COLUMNS,changed)


def test_public_frame_dto_cannot_issue_old_frame_authentication(authentication):
    with pytest.raises(AuthorityUnavailable):_issue_authenticated_contact_frames_v1(object(),facts=authentication,pin=object())


def test_v2_inventory_requires_new_family_without_mutating_v1_wire():
    from sylanne3.authority_service.c09_contact_disposition_v1 import CARRIER_FAMILIES
    assert len(CARRIER_FAMILIES)==19 and len(CARRIER_FAMILIES_V2)==20
    families=tuple(ContactCarrierFamilyV2(role,table,False,canonical_digest((role,table,'absent')),())
        for role,table in CARRIER_FAMILIES_V2)
    values=dict(namespace_commitment='a'*64,operation_commitment='b'*64,source_seal_digest='c'*64,
        current_manifest_digest='d'*64,source_files_commitment='e'*64,observed_generation=1,
        observed_execution_seq=2,families=families)
    result=committed(ContactCarrierInventoryV2,'inventory_digest',values)
    assert decode_contact_carrier_inventory_v2(wire(result))==result
    values['families']=families[:-1]
    with pytest.raises(AuthorityUnavailable):committed(ContactCarrierInventoryV2,'inventory_digest',values)
