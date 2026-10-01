"""Load one exact Sylanne runtime under its stable cross-process wire name.

The selected installation is still authenticated by the normal Authority,
cohort, source and native admission. This import bootstrap grants no rights.
It only prevents the AstrBot plugin's incidental Python prefix from changing
canonical DTO type names relative to the independent Authority process.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import types


def load_canonical_runtime_v1(package_root):
    root=Path(package_root).resolve(strict=True)
    package=root/'rewrite'/'sylanne3'
    entry=package/'__init__.py'
    if package.is_symlink() or entry.is_symlink() or not package.is_dir() or not entry.is_file():
        raise RuntimeError('exact installed Sylanne runtime package is unavailable')
    content=entry.read_bytes()
    manifest=root/'release-manifest.json'
    if manifest.exists():
        if manifest.is_symlink():raise RuntimeError('Sylanne source manifest is unsafe')
        raw=json.loads(manifest.read_text(encoding='utf-8'))
        rows=[item for item in raw['files'] if item.get('path')=='rewrite/sylanne3/__init__.py']
        if len(rows)!=1 or rows[0].get('sha256')!=hashlib.sha256(content).hexdigest() or rows[0].get('bytes')!=len(content):
            raise RuntimeError('Sylanne runtime package differs from selected source manifest')
    loaded=sys.modules.get('sylanne3')
    if loaded is not None:
        spec=getattr(loaded,'__spec__',None)
        if (type(loaded) is not types.ModuleType or getattr(loaded,'__name__',None)!='sylanne3'
                or spec is None or Path(spec.origin or '').resolve()!=entry
                or Path(getattr(loaded,'__file__','')).resolve()!=entry
                or tuple(Path(value).resolve() for value in getattr(loaded,'__path__',()))!=(package,)):
            raise RuntimeError('another Sylanne runtime is already loaded; restart into the selected package')
        return loaded
    # Prefixed old imports cannot coexist as a second authority/type universe.
    for name,module in tuple(sys.modules.items()):
        if name.endswith('.sylanne3') or '.sylanne3.' in name:
            file=getattr(module,'__file__',None)
            if file is not None and Path(file).resolve().is_relative_to(package):
                raise RuntimeError('noncanonical Sylanne runtime was imported before installed bootstrap')
    spec=importlib.util.spec_from_file_location('sylanne3',entry,submodule_search_locations=[str(package)])
    if spec is None or spec.loader is None:raise RuntimeError('canonical Sylanne module loader unavailable')
    module=importlib.util.module_from_spec(spec)
    sys.modules['sylanne3']=module
    try:spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop('sylanne3',None)
        raise
    return module
