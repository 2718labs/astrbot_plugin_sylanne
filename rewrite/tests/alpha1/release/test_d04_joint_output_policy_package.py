"""The candidate package pins D04 full-output policy and identity readout."""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[4]
POLICY_PATH = "resources/catalogue/d04-joint-state-output-policy.v1.json"
SCHEME_PATH = "resources/catalogue/d04-affect-scheme.json"
READOUT_PATH = "resources/catalogue/d04-tanh-readout.v1.json"
POLICY_SHA256 = "7faef300b10792e3f09d3959b1c6c6e6be4c7abb1a843dcff42e2b12aa250911"


def _builder():
    spec = importlib.util.spec_from_file_location(
        "build_plugin_package", ROOT / "rewrite/tools/build_plugin_package.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _resources() -> dict[str, bytes]:
    return {path: (ROOT / path).read_bytes()
            for path in (POLICY_PATH, SCHEME_PATH, READOUT_PATH)}


def test_joint_output_policy_identity_and_manifest_tamper(tmp_path: Path) -> None:
    builder = _builder()
    resources = _resources()
    assert hashlib.sha256(resources[POLICY_PATH]).hexdigest() == POLICY_SHA256
    binding = builder._d04_joint_output_policy_binding(resources)
    assert binding["status"] == "candidate"
    assert binding["semantic_calibration"] == "unvalidated"
    assert binding["algorithm_id"] == "abi2-full-output.identity-tanh24.rational-midpoint-rne.v1"
    assert len(binding["axis_ids"]) == 24
    altered = dict(resources)
    readout = json.loads(resources[READOUT_PATH])
    readout["outputs"][0]["coefficients"][0] = 0
    altered[READOUT_PATH] = json.dumps(readout).encode()
    with pytest.raises(ValueError, match="identity readout differs"):
        builder._d04_joint_output_policy_binding(altered)

    source = tmp_path / "source"
    files = {
        "__init__.py": b"", "main.py": b"VALUE = 1\n",
        "metadata.yaml": b'name: sylanne\nversion: "3.0.0-dev.1"\n',
        "_conf_schema.json": b"{}\n", "requirements.txt": b"\n",
        "README.md": b"# Sylanne\n", "LICENSE": b"license\n",
        "logo.png": b"png", "rewrite/__init__.py": b"",
        "rewrite/sylanne3/__init__.py": b"",
        "rewrite/sylanne3/runtime.py": b"VALUE = True\n",
        **resources,
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
    assert manifest["joint_state_output_policy"] == binding
    installed_root = tmp_path / "installed-candidate-fixture"
    with zipfile.ZipFile(package) as archive:
        archive.extractall(installed_root)
    candidate_manifest = dict(manifest)
    candidate_manifest["build_mode"] = "backend-alpha1-candidate"
    candidate_bytes = (json.dumps(candidate_manifest, sort_keys=True) + "\n").encode()
    (installed_root / "release-manifest.json").write_bytes(candidate_bytes)
    candidate_digest = hashlib.sha256(candidate_bytes).hexdigest()
    loader = importlib.import_module("sylanne3.host.installed_d04_output_policy")
    from sylanne3.host.installed_package import InstalledPackageVerification

    # Native verification is covered by installed_package; this fixture isolates
    # the loader's candidate/formal gate and its policy DTO construction.
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(
            loader, "verify_installed_package",
            lambda *_: InstalledPackageVerification(
                True, "verified", candidate_digest, build_mode="backend-alpha1-candidate",
            ),
        )
        with pytest.raises(ValueError, match="requires a formal-alpha1 package"):
            loader.load_installed_d04_output_policy_v1(installed_root, candidate_digest)
        loaded = loader.load_installed_d04_output_policy_v1(
            installed_root, candidate_digest, require_formal=False,
        )
        assert loaded.policy_sha256 == POLICY_SHA256
        assert loaded.policy.algorithm_id == binding["algorithm_id"]
        assert loaded.policy.axis_ids == tuple(binding["axis_ids"])
        assert loaded.build_mode == "backend-alpha1-candidate"
    finally:
        monkeypatch.undo()
    manifest["joint_state_output_policy"]["algorithm_id"] = "caller_supplied"
    payload["release-manifest.json"] = json.dumps(manifest, sort_keys=True).encode()
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(tampered, "w") as archive:
        for name, content in payload.items():
            archive.writestr(name, content)
    with pytest.raises(ValueError, match="joint output policy manifest binding"):
        builder.verify_package(tampered)
