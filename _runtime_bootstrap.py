"""Bind one canonical runtime code generation without mixing live DTO types."""
from __future__ import annotations

import hashlib
import importlib.abc
import importlib.util
import json
from pathlib import Path
import sys
import types


_PROVENANCE = "__sylanne_runtime_provenance_v1__"


class RuntimeRestartRequired(RuntimeError):
    """A same-root code update is installed but cannot run in this process."""


def _code_files(root):
    package = root / "rewrite" / "sylanne3"
    if package.is_symlink() or not package.is_dir():
        raise RuntimeError("exact installed Sylanne runtime package is unavailable")
    selected = {}
    for path in package.rglob("*"):
        if path.is_symlink():
            raise RuntimeError("Sylanne runtime source contains a symlink")
        if path.is_file() and (path.suffix == ".py" or
                path.suffix in {".so", ".dll", ".dylib"}):
            content = path.read_bytes()
            selected[path.relative_to(root).as_posix()] = (len(content), hashlib.sha256(content).hexdigest())
    for name in ("main.py", "_runtime_bootstrap.py", "_restart_required.py"):
        path = root / name
        if name == "_restart_required.py" and not path.exists():
            continue
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("Sylanne runtime entry source is unavailable")
        content = path.read_bytes()
        selected[name] = (len(content), hashlib.sha256(content).hexdigest())
    if "rewrite/sylanne3/__init__.py" not in selected:
        raise RuntimeError("exact installed Sylanne runtime package is unavailable")
    manifest = root / "release-manifest.json"
    if manifest.exists():
        if manifest.is_symlink():
            raise RuntimeError("Sylanne source manifest is unsafe")
        raw = json.loads(manifest.read_bytes())
        rows = {}
        for row in raw["files"]:
            path = row["path"]
            if path in rows:
                raise RuntimeError("Sylanne source manifest repeats a file")
            rows[path] = row
        expected = {name for name in rows if
            (name.startswith("rewrite/sylanne3/") and
             Path(name).suffix in {".py", ".so", ".dll", ".dylib"})
            or name in {"main.py", "_runtime_bootstrap.py", "_restart_required.py"}}
        if expected != set(selected):
            raise RuntimeError("Sylanne runtime code tree differs from selected source manifest")
        for name, (size, digest) in selected.items():
            row = rows[name]
            if row["bytes"] != size or row["sha256"] != digest:
                raise RuntimeError("Sylanne runtime code differs from selected source manifest")
    hashes = {name: digest for name, (_, digest) in selected.items()}
    generation = hashlib.sha256(json.dumps(hashes, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    return package, selected, generation


class _SourceLoader(importlib.abc.Loader):
    def __init__(self, path, identity):
        self.path = path
        self.size, self.sha256 = identity

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        if self.path.is_symlink():
            raise RuntimeError("Sylanne source changed during canonical import")
        content = self.path.read_bytes()
        if len(content) != self.size or hashlib.sha256(content).hexdigest() != self.sha256:
            raise RuntimeError("Sylanne source changed during canonical import")
        # Validate and compile the same local bytes; never retain source or use pyc.
        exec(compile(content, str(self.path), "exec"), module.__dict__)


class _RuntimeFinder(importlib.abc.MetaPathFinder):
    def __init__(self, root, files):
        self.root = root
        self.files = files

    def find_spec(self, fullname, path=None, target=None):
        if fullname != "sylanne3" and not fullname.startswith("sylanne3."):
            return None
        stem = "rewrite/sylanne3"
        if fullname != "sylanne3":
            stem += "/" + fullname[len("sylanne3."):].replace(".", "/")
        package = stem + "/__init__.py"
        source = package if package in self.files else stem + ".py"
        if source not in self.files:
            raise ModuleNotFoundError("module is not in the verified Sylanne generation", name=fullname)
        location = self.root / source
        return importlib.util.spec_from_file_location(fullname, location,
            loader=_SourceLoader(location, self.files[source]),
            submodule_search_locations=[str(location.parent)] if source == package else None)


def load_canonical_runtime_v1(package_root):
    root = Path(package_root).resolve(strict=True)
    package, files, generation = _code_files(root)
    entry = package / "__init__.py"
    for name, module in tuple(sys.modules.items()):
        if name.endswith(".sylanne3") or ".sylanne3." in name:
            raise RuntimeError("noncanonical Sylanne runtime was imported before installed bootstrap")
    loaded = sys.modules.get("sylanne3")
    if loaded is not None:
        spec = getattr(loaded, "__spec__", None)
        if (type(loaded) is not types.ModuleType or loaded.__name__ != "sylanne3"
                or spec is None or Path(spec.origin or "").resolve() != entry
                or Path(getattr(loaded, "__file__", "")).resolve() != entry
                or tuple(Path(value).resolve() for value in getattr(loaded, "__path__", ())) != (package,)):
            raise RuntimeError("another Sylanne runtime is already loaded; restart into the selected package")
        for name, module in tuple(sys.modules.items()):
            if name.startswith("sylanne3."):
                file = getattr(module, "__file__", None)
                if file is None or not Path(file).resolve().is_relative_to(package):
                    raise RuntimeError("canonical Sylanne child module comes from another runtime root")
        provenance = getattr(loaded, _PROVENANCE, None)
        if provenance != (str(root), generation):
            raise RuntimeRestartRequired(
                "runtime_restart_required: installed Sylanne code differs from this process cache; "
                "stop and restart the entire AstrBot process, plugin reload is insufficient")
        return loaded
    if any(name.startswith("sylanne3.") for name in sys.modules):
        raise RuntimeError("orphaned canonical Sylanne child modules are already loaded")
    finder = _RuntimeFinder(root, files)
    spec = finder.find_spec("sylanne3")
    if spec is None or spec.loader is None:
        raise RuntimeError("canonical Sylanne module loader unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.meta_path.insert(0, finder)
    sys.modules["sylanne3"] = module
    try:
        spec.loader.exec_module(module)
        setattr(module, _PROVENANCE, (str(root), generation))
    except BaseException:
        sys.modules.pop("sylanne3", None)
        sys.meta_path.remove(finder)
        raise
    return module
