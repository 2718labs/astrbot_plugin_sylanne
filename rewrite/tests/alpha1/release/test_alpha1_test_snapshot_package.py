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
    configured=os.environ.get('SYLANNE_ALPHA1_TEST_PACKAGE')
    if not configured:pytest.skip('requires the actual frozen alpha1 test snapshot ZIP')
    path=Path(configured).resolve(strict=True)
    with zipfile.ZipFile(path) as archive:
        content=archive.read('release-manifest.json');manifest=json.loads(content)
    expected=os.environ.get('SYLANNE_ALPHA1_TEST_MANIFEST_SHA256')
    assert expected and hashlib.sha256(content).hexdigest()==expected
    return path,expected,manifest


def test_actual_snapshot_cold_load_and_full_provenance(actual_snapshot_package):
    from scripts.alpha1.verify_formal_cold_install import _cold_verify_package
    from sylanne3.host.alpha1_test_snapshot_v1 import validate_test_snapshot_manifest_v1
    path,pin,manifest=actual_snapshot_package
    evidence=validate_test_snapshot_manifest_v1(manifest)
    assert manifest['package_version']=='3.0.0-alpha1'
    assert manifest['build_mode']=='snapshot-alpha1-test'
    assert evidence['public_release'] is False
    assert any(row['path'].startswith('rewrite/tests/') for row in evidence['engineering_source_inventory']['files'])
    assert {'resources/workbench/index.html','_runtime_bootstrap.py','scripts/alpha1/authority_linux_maintain.py',
        'scripts/alpha1/stage_linux_package.py'} <= {row['path'] for row in manifest['files']}
    result=_cold_verify_package(path,pin,expected_mode='snapshot-alpha1-test')
    assert result['status']=='snapshot_alpha1_test_package_mechanics_only'
    assert result['abi_version']==2 and result['native_sha256']==manifest['native']['sha256']


def test_actual_snapshot_cannot_claim_formal_or_omit_evidence(actual_snapshot_package):
    from sylanne3.host.alpha1_test_snapshot_v1 import validate_test_snapshot_manifest_v1
    _,_,original=actual_snapshot_package
    for mutate in (
        lambda value:value['test_snapshot'].__setitem__('public_release',True),
        lambda value:value.__setitem__('build_mode','formal-alpha1'),
        lambda value:value['test_snapshot'].__setitem__('verification_evidence',{'schema':'sylanne.alpha1-test-evidence.v1','checks':[]}),
        lambda value:value['test_snapshot']['engineering_source_inventory']['files'][0].__setitem__('sha256','0'*64),
    ):
        changed=deepcopy(original);mutate(changed)
        with pytest.raises(ValueError):validate_test_snapshot_manifest_v1(changed)
