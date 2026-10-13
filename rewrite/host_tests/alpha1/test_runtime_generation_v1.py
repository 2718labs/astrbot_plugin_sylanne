"""Canonical source generations remain one type universe in each process."""
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[3]


def _run(tmp_path, scenario):
    source = ROOT / '_runtime_bootstrap.py'
    code = r'''
from pathlib import Path
import importlib.util, json, os, py_compile, shutil, sys, types
root = Path(sys.argv[1]); root.mkdir()
package = root / 'rewrite/sylanne3'; package.mkdir(parents=True)
(package / '__init__.py').write_text('')
(root / 'main.py').write_text('')
shutil.copyfile(sys.argv[2], root / '_runtime_bootstrap.py')
spec = importlib.util.spec_from_file_location('generation_bootstrap', root / '_runtime_bootstrap.py')
bootstrap = importlib.util.module_from_spec(spec); spec.loader.exec_module(bootstrap)
scenario = sys.argv[3]
if scenario == 'source':
    item = package / 'sample.py'; item.write_text("VALUE='old'\n")
    stamp = item.stat(); py_compile.compile(str(item), doraise=True)
    item.write_text("VALUE='new'\n"); os.utime(item, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    module = bootstrap.load_canonical_runtime_v1(root)
    import sylanne3.sample as sample
    assert sample.VALUE == 'new'
    assert bootstrap.load_canonical_runtime_v1(root) is module
    original = sample
    item.write_text("VALUE='end'\n")
    try: bootstrap.load_canonical_runtime_v1(root)
    except bootstrap.RuntimeRestartRequired: pass
    else: raise AssertionError('changed source silently reused cached code')
    assert sys.modules['sylanne3.sample'] is original and sample.VALUE == 'new'
    item.write_text("VALUE='new'\n")
    added = package / 'added.py'; added.write_text('X=1\n')
    try: bootstrap.load_canonical_runtime_v1(root)
    except bootstrap.RuntimeRestartRequired: pass
    else: raise AssertionError('added module did not change generation')
    added.unlink()
    assert bootstrap.load_canonical_runtime_v1(root) is module
elif scenario in ('late_content', 'late_symlink'):
    import importlib
    item = package / 'sample.py'
    marker = root / 'child-executed'
    original = "VALUE='old'; open(" + repr(str(marker)) + ", 'w').write('executed')\n"
    changed = original.replace("VALUE='old'", "VALUE='new'")
    assert len(original) == len(changed)
    item.write_text(original)
    bootstrap.load_canonical_runtime_v1(root)
    if scenario == 'late_content':
        item.write_text(changed)
    else:
        replacement = root.parent / 'outside-sample.py'
        replacement.write_text(original)
        item.unlink(); item.symlink_to(replacement)
    try: importlib.import_module('sylanne3.sample')
    except RuntimeError as exc:
        assert 'source changed during canonical import' in str(exc)
    else: raise AssertionError('changed unimported child executed')
    assert not marker.exists() and 'sylanne3.sample' not in sys.modules
elif scenario == 'legacy':
    sys.path.insert(0, str(root / 'rewrite'))
    import sylanne3
    original = sylanne3
    try: bootstrap.load_canonical_runtime_v1(root)
    except bootstrap.RuntimeRestartRequired: pass
    else: raise AssertionError('legacy cache was relabeled as current')
    assert sys.modules['sylanne3'] is original
elif scenario == 'prefix':
    foreign = types.ModuleType('foreign.sylanne3')
    foreign.__file__ = str(root.parent / 'other/rewrite/sylanne3/__init__.py')
    sys.modules[foreign.__name__] = foreign
    try: bootstrap.load_canonical_runtime_v1(root)
    except bootstrap.RuntimeRestartRequired: raise AssertionError('foreign prefix was allowed as maintenance')
    except RuntimeError: pass
    else: raise AssertionError('foreign prefixed tree was accepted')
    assert 'sylanne3' not in sys.modules and sys.modules[foreign.__name__] is foreign
elif scenario == 'path':
    module = bootstrap.load_canonical_runtime_v1(root)
    other = root.parent / 'other'; shutil.copytree(root, other)
    try: bootstrap.load_canonical_runtime_v1(other)
    except bootstrap.RuntimeRestartRequired: raise AssertionError('different root was allowed as maintenance')
    except RuntimeError: pass
    else: raise AssertionError('different runtime root was accepted')
    assert sys.modules['sylanne3'] is module
elif scenario == 'manifest':
    import hashlib
    rows = []
    for name in ('main.py', '_runtime_bootstrap.py', 'rewrite/sylanne3/__init__.py'):
        data = (root / name).read_bytes()
        rows.append({'path':name, 'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest()})
    (root / 'release-manifest.json').write_text(json.dumps({'files':rows}))
    module = bootstrap.load_canonical_runtime_v1(root)
    (package / '__init__.py').write_text('X=1\n')
    try: bootstrap.load_canonical_runtime_v1(root)
    except bootstrap.RuntimeRestartRequired: raise AssertionError('tamper was allowed as maintenance')
    except RuntimeError: pass
    else: raise AssertionError('changed manifest-pinned source was accepted')
    assert sys.modules['sylanne3'] is module
print('PASS', scenario)
'''
    done = subprocess.run([sys.executable, '-B', '-c', code,
        str(tmp_path / scenario), str(source), scenario],
        capture_output=True, text=True, timeout=15)
    assert done.returncode == 0, done.stdout + done.stderr


def test_source_generation_reuses_identity_and_rejects_changed_code_with_stale_pyc(tmp_path):
    _run(tmp_path, 'source')


def test_legacy_foreign_prefixed_and_manifest_tamper_do_not_replace_the_namespace(tmp_path):
    for scenario in ('legacy', 'prefix', 'path', 'manifest'):
        _run(tmp_path, scenario)


def test_unimported_child_rejects_same_size_change_and_symlink_after_generation_scan(tmp_path):
    for scenario in ('late_content', 'late_symlink'):
        _run(tmp_path, scenario)
