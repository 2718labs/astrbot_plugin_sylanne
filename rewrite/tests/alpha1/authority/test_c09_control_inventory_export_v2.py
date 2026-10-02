"""Real protected Control export on new synthetic genesis files only.

No populated PREPARED conversion, sanitized recovery or disposal is claimed.
"""
import copy
import json
import sqlite3

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.c09_storage_control_v1 import (
    C09StorageControlV1, InstalledC09InstanceLeaseV1, ROLES, digest, file_observation_v1,
)
from sylanne3.authority_service.c09_control_inventory_export_v2 import (
    capture_control_inventory_export_v2, verify_control_inventory_export_v2, FAMILIES,
)


@pytest.fixture
def control(tmp_path):
    state = tmp_path/'state'; state.mkdir()
    key = tmp_path/'synthetic-key'; key.write_bytes(b'synthetic-test-only-control-key!!')
    with InstalledC09InstanceLeaseV1(tmp_path/'lease') as lease:
        control = C09StorageControlV1(control_path=tmp_path/'control.db',key_path=key,
            installation_id='fixture-install',authority_id='fixture-authority',control_store_id='fixture-control',
            key_id='fixture-key',lease=lease,resource_roots=(state,))
        members = []
        for role in ROLES:
            path = state/(role+'.db')
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE synthetic(value TEXT)')
            members.append(dict(role=role,**file_observation_v1(path),store_id='fixture:'+role,
                schema_version='1',namespace='fixture/persona',storage_generation=0,
                incarnation_or_journal_id='fixture:'+role,logical_data_root='a'*64,
                schema_objects_digest='b'*64,cold_read_digest='c'*64,wal_policy='closed',companion_resource_ids=[]))
        manifest=dict(schema='sylanne3.c09.storage_manifest.v1',authority_id=control.authority_id,
            installation_id=control.installation_id,cohort_namespaces=['fixture/persona'],generation=0,
            prior_manifest_digest=None,members=members,inventory_manifest_digest='d'*64,
            certificate_digest=None,graph_issue_digest=None,recovery_pin_digest=None,
            cumulative_tombstone_root='e'*64,deletion_watermark=0)
        manifest['manifest_digest']=digest(manifest)
        control.bootstrap_installed_storage_v1(manifest=manifest)
        yield control


def test_real_complete_signed_export_and_cold_wire_verification(control):
    value=capture_control_inventory_export_v2(control)
    assert [f['table'] for f in value['families']] == list(FAMILIES)
    assert sum(len(f['row_commitments']) for f in value['families']) == 7
    encoded=json.dumps(value)
    assert 'fixture/persona' not in encoded and str(control.path) not in encoded
    assert verify_control_inventory_export_v2(control,json.loads(encoded)) == value
    assert control.read_verified_current_storage_v1().stage == 'READY'


def test_actual_signature_and_closed_family_reject_tampering(control):
    value=capture_control_inventory_export_v2(control)
    bad=copy.deepcopy(value);bad['signature']='0'*64
    with pytest.raises(AuthorityUnavailable,match='signature'):
        verify_control_inventory_export_v2(control,bad)
    bad=copy.deepcopy(value);bad['families'].pop()
    with pytest.raises(AuthorityUnavailable,match='families'):
        verify_control_inventory_export_v2(control,bad)
    control.lease.close()
    with pytest.raises(AuthorityUnavailable):verify_control_inventory_export_v2(control,value)


def test_unknown_empty_table_refuses_entire_export(control):
    with sqlite3.connect(control.path) as db:db.execute('CREATE TABLE unclassified(value TEXT)')
    with pytest.raises(AuthorityUnavailable,match='complete Control schema'):
        capture_control_inventory_export_v2(control)


def test_build_extension_has_explicit_negative_and_positive_inventory(control):
    before=capture_control_inventory_export_v2(control)
    assert not next(f for f in before['families'] if f['table']=='c09_storage_build_originals_v1')['present']
    control.install_build_originals_schema_v1()
    after=capture_control_inventory_export_v2(control)
    assert next(f for f in after['families'] if f['table']=='c09_storage_build_originals_v1')['present']


def test_resource_bound_refuses_whole_inventory_before_replay(control,monkeypatch):
    from sylanne3.authority_service import c09_control_inventory_export_v2 as module
    monkeypatch.setattr(module,'MAX_ROWS',1)
    def forbidden_replay(*args):
        raise AssertionError('unbounded original replay was reached')
    monkeypatch.setattr(C09StorageControlV1,'_current',forbidden_replay)
    with pytest.raises(AuthorityUnavailable,match='complete Control inventory exceeds bound'):
        capture_control_inventory_export_v2(control)
