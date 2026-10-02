"""Baseline W09 assets may be retained only by the existing test snapshot mode."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture
def builder():
    spec = importlib.util.spec_from_file_location('frozen_snapshot_builder', ROOT/'rewrite/tools/build_plugin_package.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def assets():
    return {str(path.relative_to(ROOT)): path.read_bytes()
            for path in (ROOT/'resources/workbench/index.html', ROOT/'resources/workbench/workbench-manifest.json')}


def test_actual_committed_asset_bytes_are_retained_without_claiming_a_vue_rebuild(builder, assets):
    assert not (ROOT/'webui-heritage/dist/index.html').exists()
    builder._verify_workbench_source(ROOT, assets, formal=False, frozen_test_snapshot=True)


def test_engineering_inventory_includes_exact_packaged_root_assets(builder):
    inventory, _delta = builder._snapshot_workspace_inventory(ROOT, {'files': []})
    rows = {row['path']: row for row in inventory['files']}
    for name in builder.ROOT_FILE_ALLOWLIST:
        data = (ROOT/name).read_bytes()
        assert rows[name] == {'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


@pytest.mark.parametrize('formal', (True, False))
def test_missing_build_output_still_refuses_formal_and_ordinary_builds(builder, assets, formal):
    with pytest.raises(ValueError, match='build output is missing'):
        builder._verify_workbench_source(ROOT, assets, formal=formal, frozen_test_snapshot=formal)


@pytest.mark.parametrize('change', ('html', 'manifest'))
def test_self_consistent_changed_assets_cannot_claim_the_committed_baseline(builder, assets, change):
    changed = deepcopy(assets)
    manifest = json.loads(changed['resources/workbench/workbench-manifest.json'])
    if change == 'html':
        content = changed['resources/workbench/index.html'] + b'<!-- changed snapshot -->'
        changed['resources/workbench/index.html'] = content
        manifest['files'][0].update(bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
    else:
        manifest['snapshot_caller_claim'] = True
    changed['resources/workbench/workbench-manifest.json'] = json.dumps(manifest).encode()
    with pytest.raises(ValueError, match='differs from committed baseline'):
        builder._verify_workbench_source(ROOT, changed, formal=False, frozen_test_snapshot=True)
