"""Actual AstrBot plugin imports and Authority imports use identical wire tags."""
import json
import os
from pathlib import Path
import subprocess

PROJECT = Path(__file__).resolve().parents[3]


def _run(tmp_path, mode):
    code = r'''
import importlib,importlib.util,json,sys,types
from pathlib import Path
root=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(root))
if sys.argv[2]=='plugin':
    name='actual_astrbot_plugin_namespace_probe'
    spec=importlib.util.spec_from_file_location(name,root/'__init__.py',submodule_search_locations=[str(root)])
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    main=importlib.import_module(name+'.main')
else:
    from _runtime_bootstrap import load_canonical_runtime_v1
    load_canonical_runtime_v1(root)
from sylanne3.runtime_contracts import NamespaceId,canonical_serialize,namespace_ref
from sylanne3.graph_coordinator import namespace_ref as graph_namespace_ref
assert graph_namespace_ref is namespace_ref
from sylanne3.runtime.issuers import ResourceQuote
namespace=NamespaceId('bot','persona')
quote=ResourceQuote('quote',1,'bot','persona','activity','operation',None,'lease','probe','snapshot',100.,'resource',None,(),(),{'cpu_ms':1},None,100.)
assert NamespaceId.__module__=='sylanne3.runtime_contracts'
assert ResourceQuote.__module__=='sylanne3.runtime.issuers'
assert not any(name.endswith('.sylanne3.runtime_contracts') and name!='sylanne3.runtime_contracts' for name in sys.modules)
print('WIRE_RESULT='+json.dumps({'namespace':canonical_serialize(namespace),'quote':canonical_serialize(quote)},sort_keys=True))
'''
    result = subprocess.run([str(Path(os.sys.executable)), '-c', code, str(PROJECT), mode],
        cwd=tmp_path, env={**os.environ, 'PYTHONPATH':'', 'PYTHONDONTWRITEBYTECODE':'1'},
        text=True, capture_output=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(next(line.removeprefix('WIRE_RESULT=') for line in result.stdout.splitlines() if line.startswith('WIRE_RESULT=')))


def test_actual_plugin_and_independent_authority_emit_same_wire(tmp_path):
    assert _run(tmp_path, 'plugin') == _run(tmp_path, 'authority')


def test_existing_foreign_runtime_cannot_be_rebound(tmp_path):
    code = r'''
import importlib.util,sys,types
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root))
from _runtime_bootstrap import load_canonical_runtime_v1
wrong=Path(sys.argv[2])/'foreign'/'__init__.py'
module=types.ModuleType('sylanne3');module.__file__=str(wrong);module.__path__=[str(wrong.parent)]
module.__spec__=importlib.util.spec_from_file_location('sylanne3',wrong,submodule_search_locations=[str(wrong.parent)])
sys.modules['sylanne3']=module
try:load_canonical_runtime_v1(root)
except RuntimeError as exc:
    assert 'another Sylanne runtime' in str(exc)
else:raise AssertionError('foreign package was silently rebound')
assert sys.modules['sylanne3'] is module
'''
    result=subprocess.run([os.sys.executable,'-c',code,str(PROJECT),str(tmp_path)],cwd=tmp_path,
        env={**os.environ,'PYTHONPATH':'','PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stdout+result.stderr
