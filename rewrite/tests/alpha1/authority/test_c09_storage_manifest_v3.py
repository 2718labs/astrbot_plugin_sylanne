"""Permanent V3 format and legacy version boundaries on fresh real Control files.

Completion digest placeholders exercise format only. They never stand for actual
segmented completion, V3 selection, Source permission or installation acceptance.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import pytest
from test_c09_control_inventory_export_v2 import control
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.c09_storage_control_v1 import ROLES,digest
from sylanne3.authority_service.c09_storage_manifest_v2 import (
    PROVENANCE_FIELDS_V2,ROOT_ALGORITHM_V2,require_manifest_provenance_shape_v2,manifest_signature_domain)
from sylanne3.authority_service.c09_storage_manifest_v3 import (
    SCHEMA_V3,SIGNATURE_DOMAIN_V3,SEGMENTED_ROOT_ALGORITHM_V1,require_manifest_provenance_shape_v3)
from sylanne3.authority_service.c09_prepared_storage_v2 import (
    verify_prepared_original_v2,record_prepared_storage_v2)
from sylanne3.segmented_sql_cell_v1 import LAYOUTS,LAYOUT_SCHEMA_DIGEST


def format_only_v3(control):
    value=deepcopy(control.read_verified_current_storage_v1().manifest)
    value.update({name:'a'*64 for name in PROVENANCE_FIELDS_V2})
    value['root_algorithm']=ROOT_ALGORITHM_V2
    value['four_role_complete_original_digests']={role:'b'*64 for role in ROLES}
    value['schema']=SCHEMA_V3
    value['segmented_root_algorithm']=SEGMENTED_ROOT_ALGORITHM_V1
    value['segmented_layouts']={role:{'layout_id':LAYOUTS[role],
        'layout_schema_digest':LAYOUT_SCHEMA_DIGEST,'storage_instance_id':digest(('format-only',role))} for role in ROLES}
    value['segmented_role_complete_original_digests']={role:'c'*64 for role in ROLES}
    value['manifest_digest']=digest({key:item for key,item in value.items() if key!='manifest_digest'})
    return value


def test_real_control_v3_format_cannot_cross_legacy_qualification(control):
    original=control.read_verified_current_storage_v1()
    files={item['resolved_path']:sha256(Path(item['resolved_path']).read_bytes()).hexdigest()
        for item in original.manifest['members']}
    value=format_only_v3(control)
    require_manifest_provenance_shape_v3(value);control._manifest(value)
    assert manifest_signature_domain(value)==SIGNATURE_DOMAIN_V3
    with pytest.raises(AuthorityUnavailable,match='V2 manifest closed'):
        require_manifest_provenance_shape_v2(value)
    for apply,reason in (
        (lambda:control.bootstrap_installed_storage_v1(manifest=value),'legacy bootstrap'),
        (lambda:control.record_prepared_storage_v1(manifest=value,prepared_original={}), 'V1 PREPARED'),
        (lambda:record_prepared_storage_v2(control,manifest=value,prepared_original={},closing_continuation=None),'V2 PREPARED'),
        (lambda:verify_prepared_original_v2(control,None,{},value),'V2 PREPARED')):
        with pytest.raises(AuthorityUnavailable,match=reason):apply()
    current=control.read_verified_current_storage_v1()
    assert (current.manifest_digest,current.pointer_version,current.storage_generation)==(
        original.manifest_digest,original.pointer_version,original.storage_generation)
    assert all(sha256(Path(path).read_bytes()).hexdigest()==pin for path,pin in files.items())
    with control._db() as db:
        assert db.execute('SELECT count(*) FROM c09_storage_events_v1').fetchone()[0]==0
        assert db.execute('SELECT count(*) FROM c09_storage_operations_v1').fetchone()[0]==0
        assert db.execute("SELECT 1 FROM sqlite_master WHERE name='c09_storage_operations_v2'").fetchone() is None


def test_v3_rejects_wrong_role_layout_and_incomplete_closed_mapping(control):
    good=format_only_v3(control);require_manifest_provenance_shape_v3(good)
    wrong=deepcopy(good);wrong['segmented_layouts']['graph']['layout_id']='graph-storage.v2'
    with pytest.raises(AuthorityUnavailable,match='registered role schema'):
        require_manifest_provenance_shape_v3(wrong)
    wrong=deepcopy(good);wrong['segmented_role_complete_original_digests'].pop('execution')
    with pytest.raises(AuthorityUnavailable,match='exact four segmented roles'):
        require_manifest_provenance_shape_v3(wrong)
    wrong=deepcopy(good);wrong['segmented_layouts']['graph']['allow_legacy']=True
    with pytest.raises(AuthorityUnavailable,match='registered role schema'):
        require_manifest_provenance_shape_v3(wrong)
    wrong=deepcopy(good);wrong['segmented_root_algorithm']=ROOT_ALGORITHM_V2
    with pytest.raises(AuthorityUnavailable,match='exact segmented-root fields'):
        require_manifest_provenance_shape_v3(wrong)
