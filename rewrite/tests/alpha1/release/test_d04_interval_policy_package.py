"""Pin the D04 interval projection policy as an uncalibrated package candidate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[4]
POLICY_PATH = "resources/catalogue/d04-interval-projection-policy.v2.json"
SCHEME_PATH = "resources/catalogue/d04-affect-scheme.json"
READOUT_PATH = "resources/catalogue/d04-tanh-readout.v1.json"
POLICY_SHA256 = "f41fdd7e5738eba1da582b3ccb5c83322650241d921a81b19c49c2a7f6b05a53"


def _builder():
    path = ROOT / "rewrite" / "tools" / "build_plugin_package.py"
    spec = importlib.util.spec_from_file_location("build_plugin_package", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _resources() -> dict[str, bytes]:
    return {
        relative: (ROOT / relative).read_bytes()
        for relative in (POLICY_PATH, SCHEME_PATH, READOUT_PATH)
    }


def test_policy_bytes_and_readout_identity_are_pinned() -> None:
    builder = _builder()
    resources = _resources()
    assert hashlib.sha256(resources[POLICY_PATH]).hexdigest() == POLICY_SHA256
    binding = builder._d04_interval_policy_binding(resources)
    assert binding["semantic_calibration"] == "unvalidated"
    assert binding["status"] == "candidate"
    assert binding["sha256"] == POLICY_SHA256
    altered = dict(resources)
    altered[POLICY_PATH] += b"\n"
    with pytest.raises(ValueError, match="bytes changed"):
        builder._d04_interval_policy_binding(altered)


def test_dev_package_verifier_rejects_rebound_policy_manifest(tmp_path: Path) -> None:
    builder = _builder()
    source = tmp_path / "source"
    files = {
        "__init__.py": b"", "main.py": b"VALUE = 1\n",
        "metadata.yaml": b'name: sylanne\nversion: "3.0.0-dev.1"\n',
        "_conf_schema.json": b"{}\n", "requirements.txt": b"\n",
        "README.md": b"# Sylanne\n", "LICENSE": b"license\n",
        "logo.png": b"png", "rewrite/__init__.py": b"",
        "rewrite/sylanne3/__init__.py": b"",
        "rewrite/sylanne3/runtime.py": b"VALUE = True\n",
        **_resources(),
    }
    for relative, content in files.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    for args in (("init", "--quiet"), ("config", "user.name", "Test"),
                 ("config", "user.email", "test@example.invalid"),
                 ("add", "."), ("commit", "--quiet", "-m", "fixture")):
        subprocess.run(("git", *args), cwd=source, check=True, capture_output=True)
    os_name = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}[platform.system()]
    arch = {"AMD64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}[
        platform.machine()
    ]
    native = tmp_path / builder.TARGETS[os_name]
    native.write_bytes(b"native fixture")
    package = builder.build_package(
        project_root=source, target_os=os_name, target_arch=arch,
        native_library=native, output_dir=tmp_path / "dist",
        allow_dirty_dev_probe=True, backend_only_dev_probe=True,
        target_libc="glibc" if os_name == "linux" else None,
    )
    builder.verify_package(package)
    with zipfile.ZipFile(package) as archive:
        payload = {name: archive.read(name) for name in archive.namelist()}
    manifest = json.loads(payload["release-manifest.json"])
    assert manifest["interval_projection_policy"]["sha256"] == POLICY_SHA256
    assert manifest["interval_projection_policy"]["status"] == "candidate"
    manifest["interval_projection_policy"]["stage_contract"] = "wrong_stage"
    payload["release-manifest.json"] = json.dumps(manifest, sort_keys=True).encode()
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(tampered, "w") as archive:
        for name, content in payload.items():
            archive.writestr(name, content)
    with pytest.raises(ValueError, match="policy manifest binding"):
        builder.verify_package(tampered)
