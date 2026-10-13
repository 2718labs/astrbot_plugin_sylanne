"""Actual immutable test-snapshot ZIP mechanics and provenance rejection."""
import hashlib
import json
import os
from pathlib import Path
import zipfile
from copy import deepcopy
import pytest


@pytest.fixture(scope='module')
def actual_snapshot_package():
    alpha1=os.environ.get('SYLANNE_ALPHA1_TEST_PACKAGE')
    alpha2=os.environ.get('SYLANNE_ALPHA2_CANDIDATE_PACKAGE')
    if alpha1 and alpha2:raise ValueError('select one independently frozen package identity')
    configured=alpha2 or alpha1
    if not configured:pytest.skip('requires one actual frozen alpha1 or alpha2 package ZIP')
    path=Path(configured).resolve(strict=True)
    with zipfile.ZipFile(path) as archive:
        content=archive.read('release-manifest.json');manifest=json.loads(content)
    expected=os.environ.get('SYLANNE_ALPHA2_CANDIDATE_MANIFEST_SHA256' if alpha2 else 'SYLANNE_ALPHA1_TEST_MANIFEST_SHA256')
    assert expected and hashlib.sha256(content).hexdigest()==expected
    return path,expected,manifest


def test_actual_snapshot_cold_load_and_full_provenance(actual_snapshot_package):
    from scripts.alpha1.verify_formal_cold_install import _cold_verify_package
    from sylanne3.host.alpha1_test_snapshot_v1 import validate_test_snapshot_manifest_v1
    path,pin,manifest=actual_snapshot_package
    if manifest['build_mode']=='alpha2-candidate':
        from sylanne3.host.alpha1_test_snapshot_v1 import validate_alpha2_candidate_manifest_v1
        evidence=validate_alpha2_candidate_manifest_v1(manifest)
        assert manifest['package_version']=='3.0.0-alpha2'
        assert evidence['specification']['task_count']==39
        assert evidence['specification']['resource_contract']['process_group_memory_max_bytes']==2000000000
    else:
        evidence=validate_test_snapshot_manifest_v1(manifest)
        assert manifest['package_version']=='3.0.0-alpha1'
        assert manifest['build_mode']=='snapshot-alpha1-test'
    assert evidence['public_release'] is False
    assert any(row['path'].startswith('rewrite/tests/') for row in evidence['engineering_source_inventory']['files'])
    assert {'resources/workbench/index.html','_runtime_bootstrap.py','scripts/alpha1/authority_linux_maintain.py',
        'scripts/alpha1/stage_linux_package.py'} <= {row['path'] for row in manifest['files']}
    result=_cold_verify_package(path,pin,expected_mode=manifest['build_mode'])
    assert result['status']==('alpha2_local_candidate_package_mechanics_only' if manifest['build_mode']=='alpha2-candidate'
        else 'snapshot_alpha1_test_package_mechanics_only')
    assert result['abi_version']==2 and result['native_sha256']==manifest['native']['sha256']


def test_actual_snapshot_cannot_claim_formal_or_omit_evidence(actual_snapshot_package):
    from sylanne3.host.alpha1_test_snapshot_v1 import validate_test_snapshot_manifest_v1
    _,_,original=actual_snapshot_package
    from sylanne3.host.alpha1_test_snapshot_v1 import validate_alpha2_candidate_manifest_v1
    validator=validate_alpha2_candidate_manifest_v1 if original['build_mode']=='alpha2-candidate' else validate_test_snapshot_manifest_v1
    for mutate in (
        lambda value:value['test_snapshot'].__setitem__('public_release',True),
        lambda value:value.__setitem__('build_mode','formal-alpha1'),
        lambda value:value['test_snapshot'].__setitem__('verification_evidence',{'schema':'sylanne.alpha1-test-evidence.v1','checks':[]}),
        lambda value:value['test_snapshot']['engineering_source_inventory']['files'][0].__setitem__('sha256','0'*64),
    ):
        changed=deepcopy(original);mutate(changed)
        with pytest.raises(ValueError):validator(changed)


def test_actual_alpha2_rejects_legacy_identity_and_wrong_v3_resource(actual_snapshot_package):
    from sylanne3.host.alpha1_test_snapshot_v1 import validate_alpha2_candidate_manifest_v1, validate_test_snapshot_manifest_v1
    _,_,original=actual_snapshot_package
    if original['build_mode']!='alpha2-candidate':pytest.skip('requires the independently frozen alpha2 candidate')
    with pytest.raises(ValueError):validate_test_snapshot_manifest_v1(original)
    for mutate in (
        lambda value:value.__setitem__('package_version','3.0.0-alpha1'),
        lambda value:value.__setitem__('candidate_scope','alpha1-test'),
        lambda value:value['test_snapshot']['specification'].__setitem__('task_count',38),
        lambda value:value['test_snapshot']['specification']['input_sha256'].__setitem__('json','0'*64),
        lambda value:value['test_snapshot']['specification']['resource_contract'].__setitem__('process_group_memory_max_bytes',4000000000),
    ):
        changed=deepcopy(original);mutate(changed)
        with pytest.raises(ValueError):validate_alpha2_candidate_manifest_v1(changed)
