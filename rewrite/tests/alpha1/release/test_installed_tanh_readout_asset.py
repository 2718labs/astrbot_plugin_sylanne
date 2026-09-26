"""Installed D04 candidate checks against a pinned package and checkpoint."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import platform

import pytest

from sylanne3.domains.d04.root import RootAssetBindings
from sylanne3.host.installed_tanh_readout_asset import load_installed_tanh_readout_candidate


CATALOGUE = Path(__file__).resolve().parents[4] / "resources" / "catalogue"
SCHEME_PATH = "resources/catalogue/d04-affect-scheme.json"
READOUT_PATH = "resources/catalogue/d04-tanh-readout.v1.json"


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _write_manifest(root: Path, manifest: dict) -> str:
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (root / "release-manifest.json").write_bytes(raw)
    return _digest(raw)


def _fixture(root: Path) -> tuple[dict, RootAssetBindings, str]:
    scheme_bytes = (CATALOGUE / "d04-affect-scheme.json").read_bytes()
    readout_bytes = (CATALOGUE / "d04-tanh-readout.v1.json").read_bytes()
    scheme = json.loads(scheme_bytes)
    readout = json.loads(readout_bytes)
    os_name = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}[platform.system()]
    arch = {"AMD64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}[
        platform.machine()
    ]
    native_name = {"windows": "sylanne3_kernel.dll", "linux": "libsylanne3_kernel.so",
                   "macos": "libsylanne3_kernel.dylib"}[os_name]
    native_path = f"rewrite/sylanne3/_native/{os_name}-{arch}/{native_name}"
    files = {SCHEME_PATH: scheme_bytes, READOUT_PATH: readout_bytes, native_path: b"native fixture"}
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    entries = [{"path": path, "bytes": len(content), "sha256": _digest(content)}
               for path, content in sorted(files.items())]
    native_entry = next(entry for entry in entries if entry["path"] == native_path)
    binding = {
        "path": READOUT_PATH, "sha256": _digest(readout_bytes),
        "bytes": len(readout_bytes), "schema": readout["schema"],
        "readout_id": readout["readout_id"],
        "readout_version": readout["readout_version"],
        "scheme_version": readout["scheme_version"],
        "axis_ids": readout["axis_ids"], "axis_units": readout["axis_units"],
        "output_ids": [row["output_id"] for row in readout["outputs"]],
        "transform": "p=C*tanh(z)", "status": "candidate",
    }
    manifest = {
        "schema_version": 1, "package_version": "3.0.0-dev.1",
        "build_mode": "dev-probe",
        "platform": {"os": os_name, "arch": arch, "abi_version": 2,
                     "native_filename": native_name,
                     "libc": platform.libc_ver()[0] if os_name == "linux" else None,
                     "cpu_features": []},
        "native": native_entry, "files": entries, "tanh_readout": binding,
    }
    bindings = RootAssetBindings(
        scheme["scheme_version"], scheme["operator_version"],
        scheme["parameter_version"], scheme["coupling_version"],
        readout["readout_version"], _digest(scheme_bytes),
        "a" * 64, "b" * 64, "c" * 64, _digest(readout_bytes),
    )
    return manifest, bindings, _write_manifest(root, manifest)


def test_loads_manifest_and_checkpoint_pinned_candidate(tmp_path: Path) -> None:
    manifest, bindings, digest = _fixture(tmp_path)
    result = load_installed_tanh_readout_candidate(
        tmp_path, digest, bindings, expected_readout_id="d04-24d-tanh-identity",
    )
    assert result.status == "candidate" and result.build_mode == "dev-probe"
    assert result.manifest_sha256 == digest
    assert result.asset.asset_sha256 == manifest["tanh_readout"]["sha256"]
    assert result.asset.axis_ids == tuple(manifest["tanh_readout"]["axis_ids"])
    assert len(result.asset.rows) == 24


def test_rejects_wrong_manifest_or_checkpoint_pin(tmp_path: Path) -> None:
    _, bindings, digest = _fixture(tmp_path)
    with pytest.raises(ValueError, match="manifest_digest_mismatch"):
        load_installed_tanh_readout_candidate(
            tmp_path, "0" * 64, bindings, expected_readout_id="d04-24d-tanh-identity",
        )
    with pytest.raises(ValueError, match="checkpoint"):
        load_installed_tanh_readout_candidate(
            tmp_path, digest, replace(bindings, readout_sha256="0" * 64),
            expected_readout_id="d04-24d-tanh-identity",
        )


def test_rejects_manifest_binding_change_with_re_pinned_manifest(tmp_path: Path) -> None:
    manifest, bindings, _ = _fixture(tmp_path)
    manifest["tanh_readout"]["transform"] = "c*z"
    digest = _write_manifest(tmp_path, manifest)
    with pytest.raises(ValueError, match="manifest binding"):
        load_installed_tanh_readout_candidate(
            tmp_path, digest, bindings, expected_readout_id="d04-24d-tanh-identity",
        )


def test_rejects_changed_scheme_axis_even_when_file_and_manifest_rehashed(tmp_path: Path) -> None:
    manifest, bindings, _ = _fixture(tmp_path)
    path = tmp_path / SCHEME_PATH
    scheme = json.loads(path.read_bytes())
    scheme["axes"][0], scheme["axes"][1] = scheme["axes"][1], scheme["axes"][0]
    changed = json.dumps(scheme, sort_keys=True).encode()
    path.write_bytes(changed)
    entry = next(entry for entry in manifest["files"] if entry["path"] == SCHEME_PATH)
    entry.update(bytes=len(changed), sha256=_digest(changed))
    digest = _write_manifest(tmp_path, manifest)
    with pytest.raises(ValueError, match="24-axis identity"):
        load_installed_tanh_readout_candidate(
            tmp_path, digest, replace(bindings, scheme_sha256=_digest(changed)),
            expected_readout_id="d04-24d-tanh-identity",
        )
