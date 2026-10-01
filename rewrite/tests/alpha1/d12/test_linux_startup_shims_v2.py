"""Actual AstrBot import through shim with an explicit unprivileged probe seam.

This proves module/class/metadata loading only. It does not prove privileged
cohort verification, initialized plugin behavior, process readiness or upgrade.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile
import pytest

ROOT=Path(__file__).resolve().parents[4]
spec=importlib.util.spec_from_file_location('startup_sources',ROOT/'scripts/alpha1/linux_startup_shims_v2.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def test_generated_sources_compile_and_reject_relative_control():
    sources=module.startup_shim_sources_v2(profile_id='installed')
    assert set(sources)=={'selection_probe.py','authority_entry.py','maintenance_entry.py','stage_entry.py','control_entry.py','admin_entry.py','host/__init__.py','host/main.py'}
    for name,source in sources.items():compile(source,name,'exec')
    with pytest.raises(ValueError):module.startup_shim_sources_v2(profile_id='installed',control_directory='../unsafe')


def test_real_sdk_imports_candidate_class_and_metadata_without_old_runtime(tmp_path):
    raw=os.environ.get('SYLANNE_ALPHA1_PACKAGE')
    if not raw:pytest.skip('actual pinned candidate package not supplied')
    candidate=tmp_path/'candidate';candidate.mkdir()
    with zipfile.ZipFile(raw) as archive:archive.extractall(candidate)
    boot=tmp_path/'bootstrap';boot.mkdir()
    plugin=tmp_path/'fixture_plugin';plugin.mkdir()
    sources=module.startup_shim_sources_v2(profile_id='installed',bootstrap_root=str(boot),control_directory=str(tmp_path/'control'))
    (plugin/'__init__.py').write_text(sources['host/__init__.py'])
    (plugin/'main.py').write_text(sources['host/main.py'])
    # The root-only probe is a clearly declared test boundary. No root ownership
    # checker or package validator is monkeypatched or represented as passed.
    selected=dict(selection={'revision':0,'cohort_digest':'a'*64},package_root=str(candidate),
        deployment_path=str(tmp_path/'unused.json'),profile_id='installed',verification_scope='host_public_only')
    (boot/'selection_probe.py').write_text('print('+repr(json.dumps(selected))+')\n')
    code="""import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import fixture_plugin.main as actual
from astrbot.core.star.star import star_map
from astrbot.core.star.star_manager import PluginManager
metadata=star_map[actual.__name__]
assert metadata.star_cls_type is actual.Sylanne3Plugin
assert Path(actual.__file__).absolute()==Path(sys.argv[2])/'main.py'
assert metadata.name=='astrbot_plugin_sylanne'
assert PluginManager._load_plugin_metadata(str(Path(sys.argv[1])/'fixture_plugin')) is None
wrong=[name for name in sys.modules if name=='sylanne3' or name.startswith('sylanne3.')]
assert not wrong,wrong
print('SHIM_RESULT='+json.dumps({'module':actual.__name__,'file':actual.__file__,'name':metadata.name,'version':metadata.version}))
"""
    result=subprocess.run([sys.executable,'-I','-B','-c',code,str(tmp_path),str(candidate)],
        cwd=tmp_path,capture_output=True,text=True,timeout=90)
    assert result.returncode==0,result.stdout+'\n'+result.stderr
    lines=[line for line in result.stdout.splitlines() if line.startswith('SHIM_RESULT=')]
    assert len(lines)==1
    value=json.loads(lines[0].partition('=')[2]);assert value['module']=='fixture_plugin.main'
