from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import sys
import zipfile

import pytest

BUILDER_PATH = Path(__file__).resolve().parents[3] / "tools" / "build_plugin_package.py"
VERIFIER_PATH = Path(__file__).resolve().parents[3] / "sylanne3" / "host" / "installed_package.py"


def _load_verifier():
    spec = importlib.util.spec_from_file_location("installed_package", VERIFIER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.verify_installed_package


verify_installed_package = _load_verifier()


@pytest.fixture
def installed_dev_probe(tmp_path: Path) -> tuple[Path, str]:
    source = tmp_path / "source"
    files = {
        "__init__.py": b"",
        "main.py": b"VALUE = 1\n",
        "metadata.yaml": b'name: sylanne\nversion: "3.0.0-dev.1"\n',
        "_conf_schema.json": b"{}\n",
        "requirements.txt": b"\n",
        "README.md": b"# Sylanne\n",
        "LICENSE": b"license\n",
        "logo.png": b"png",
        "rewrite/__init__.py": b"",
        "rewrite/sylanne3/__init__.py": b"",
        "rewrite/sylanne3/runtime.py": b"VALUE = True\n",
    }
    for relative, content in files.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    for args in (("init", "--quiet"), ("config", "user.name", "Test"),
                 ("config", "user.email", "test@example.invalid"),
                 ("add", "."), ("commit", "--quiet", "-m", "fixture")):
        subprocess.run(("git", *args), cwd=source, check=True, capture_output=True)
    spec = importlib.util.spec_from_file_location("build_plugin_package", BUILDER_PATH)
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    os_name = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}[platform.system()]
    arch = {"AMD64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}[platform.machine()]
    native_name = builder.TARGETS[os_name]
    native = tmp_path / native_name
    native.write_bytes(b"native fixture")
    package = builder.build_package(
        project_root=source, target_os=os_name, target_arch=arch,
        native_library=native, output_dir=tmp_path / "dist",
        allow_dirty_dev_probe=True,
        target_libc="glibc" if os_name == "linux" else None,
    )
    installed = tmp_path / "installed"
    installed.mkdir()
    with zipfile.ZipFile(package) as archive:
        archive.extractall(installed)
    digest = hashlib.sha256((installed / "release-manifest.json").read_bytes()).hexdigest()
    return installed, digest


def test_valid_extracted_dev_probe(installed_dev_probe: tuple[Path, str]) -> None:
    root, digest = installed_dev_probe
    result = verify_installed_package(root, digest)
    assert result.verified
    assert result.manifest_digest == digest
    assert result.build_mode == "dev-probe"


def test_rejects_tampered_listed_file(installed_dev_probe: tuple[Path, str]) -> None:
    root, digest = installed_dev_probe
    (root / "main.py").write_bytes(b"VALUE = 2\n")
    result = verify_installed_package(root, digest)
    assert not result.verified
    assert result.reason == "file_mismatch"


def test_rejects_manifest_digest_mismatch(installed_dev_probe: tuple[Path, str]) -> None:
    root, _ = installed_dev_probe
    result = verify_installed_package(root, "0" * 64)
    assert not result.verified
    assert result.reason == "manifest_digest_mismatch"


def test_rejects_platform_mismatch(installed_dev_probe: tuple[Path, str]) -> None:
    root, _ = installed_dev_probe
    manifest_path = root / "release-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["platform"]["os"] = "macos" if platform.system() != "Darwin" else "windows"
    manifest["platform"]["arch"] = "x86_64"
    manifest["platform"]["libc"] = None
    manifest["platform"]["native_filename"] = (
        "libsylanne3_kernel.dylib" if platform.system() != "Darwin" else "sylanne3_kernel.dll"
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    result = verify_installed_package(root, digest)
    assert not result.verified
    assert result.reason == "platform_mismatch"


def test_rejects_abi_mismatch(installed_dev_probe: tuple[Path, str]) -> None:
    root, _ = installed_dev_probe
    manifest_path = root / "release-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["platform"]["abi_version"] = 3
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    result = verify_installed_package(root, digest)
    assert not result.verified
    assert result.reason == "abi_mismatch"


def test_rejects_tampered_native_file(installed_dev_probe: tuple[Path, str]) -> None:
    root, digest = installed_dev_probe
    manifest = json.loads((root / "release-manifest.json").read_bytes())
    native_path = manifest["native"]["path"]
    (root / native_path).write_bytes(b"altered native")
    result = verify_installed_package(root, digest)
    assert not result.verified
    assert result.reason == "file_mismatch"
    assert result.failed_path == native_path


@pytest.mark.parametrize("relative", (
    "extra.py", "extra.pyc", "rewrite/sylanne3/host/extra.py",
    "rewrite/sylanne3/_native/extra.dll",
))
def test_rejects_unlisted_executable(installed_dev_probe: tuple[Path, str], relative: str) -> None:
    root, digest = installed_dev_probe
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"unlisted executable")
    result = verify_installed_package(root, digest)
    assert not result.verified
    assert result.reason == "unlisted_executable"
    assert result.failed_path == relative
