"""Synthetic package bytes exercise the D04 admission boundary, not release readiness."""

from __future__ import annotations

import hashlib
import json
import platform
from pathlib import Path

import pytest

from sylanne3.domain_registry import discover_domain_registry
from sylanne3.domains.d04 import AffectAxis, AffectScheme
from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme


def _encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _package(tmp_path: Path, *, axis_count: int = 1) -> tuple[Path, dict, dict, dict]:
    target_os = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}[platform.system()]
    target_arch = {"AMD64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}[platform.machine()]
    native_name = {
        "windows": "sylanne3_kernel.dll", "linux": "libsylanne3_kernel.so",
        "macos": "libsylanne3_kernel.dylib",
    }[target_os]
    native_path = f"rewrite/sylanne3/_native/{target_os}-{target_arch}/{native_name}"
    asset_path = "resources/catalogue/d04-affect-scheme.json"
    catalogue_path = "resources/catalogue/current.json"
    versions = {
        "scheme_version": "fixture:scheme:1", "operator_version": "fixture:operator:1",
        "parameter_version": "fixture:parameter:1", "coupling_version": "fixture:coupling:1",
    }
    scheme = {
        "schema": "d04.affect.scheme.v1", **versions,
        "axes": [
            {"axis_id": f"fixture:axis:{index}", "unit": "normalized", "meaning": "synthetic test axis"}
            for index in range(axis_count)
        ],
        "parameter_bounds": [],
    }
    runtime_scheme = AffectScheme(
        schema=scheme["schema"], **versions,
        axes=tuple(AffectAxis(**axis) for axis in scheme["axes"]),
        parameter_bounds=(),
    )
    registry = discover_domain_registry(active_affect_scheme=runtime_scheme)
    assert registry.complete
    catalogue = {
        "activation_status": "runtime_verified", "release_eligibility": "READY",
        "domain_capabilities": {"d04": ["d04.affect.scheme.v1"]},
        "catalogue_hash": registry.type_registry.catalogue_hash,
    }
    payload = {
        native_path: b"synthetic native fixture",
        asset_path: _encoded(scheme),
        catalogue_path: _encoded(catalogue),
    }
    entries = []
    for relative, content in payload.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        entries.append({"path": relative, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    manifest = {
        "schema_version": 1, "package_version": "fixture-alpha1", "build_mode": "formal-alpha1",
        "platform": {
            "os": target_os, "arch": target_arch, "native_filename": native_name,
            "abi_version": 2, "libc": platform.libc_ver()[0] if target_os == "linux" else None,
            "cpu_features": [],
        },
        "native": next(entry for entry in entries if entry["path"] == native_path),
        "files": entries,
        "affect_scheme": {
            **next(entry for entry in entries if entry["path"] == asset_path),
            **versions, "catalogue_capability": "d04.affect.scheme.v1",
        },
    }
    return tmp_path, manifest, scheme, catalogue


def _write_manifest(root: Path, manifest: dict) -> str:
    content = _encoded(manifest)
    (root / "release-manifest.json").write_bytes(content)
    return hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize("axis_count", (1, 5))
def test_loads_only_same_verified_scheme_bytes(tmp_path: Path, axis_count: int) -> None:
    root, manifest, scheme, catalogue = _package(tmp_path, axis_count=axis_count)
    digest = _write_manifest(root, manifest)
    result = load_verified_affect_scheme(root, digest)
    assert result.manifest_sha256 == digest
    assert result.asset_sha256 == manifest["affect_scheme"]["sha256"]
    assert result.scheme.scheme_version == scheme["scheme_version"]
    assert len(result.scheme.axes) == axis_count
    assert result.registry.complete
    assert result.registry.type_registry.catalogue_hash == catalogue["catalogue_hash"]


@pytest.mark.parametrize("change", ("asset_bytes", "binding_digest", "binding_version", "capability", "catalogue_hash", "missing_binding"))
def test_rejects_unproven_scheme(tmp_path: Path, change: str) -> None:
    root, manifest, _, catalogue = _package(tmp_path)
    if change == "asset_bytes":
        (root / "resources/catalogue/d04-affect-scheme.json").write_bytes(b"{}")
    elif change == "binding_digest":
        manifest["affect_scheme"]["sha256"] = "0" * 64
    elif change == "binding_version":
        manifest["affect_scheme"]["parameter_version"] = "wrong"
    elif change in {"capability", "catalogue_hash"}:
        if change == "capability":
            catalogue["domain_capabilities"] = {"d04": []}
        else:
            catalogue["catalogue_hash"] = "0" * 64
        content = _encoded(catalogue)
        (root / "resources/catalogue/current.json").write_bytes(content)
        entry = next(item for item in manifest["files"] if item["path"] == "resources/catalogue/current.json")
        entry.update(bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
    else:
        del manifest["affect_scheme"]
    digest = _write_manifest(root, manifest)
    with pytest.raises(ValueError):
        load_verified_affect_scheme(root, digest)


def test_rejects_duplicate_scheme_fields_after_byte_verification(tmp_path: Path) -> None:
    root, manifest, _, _ = _package(tmp_path)
    asset_path = root / "resources/catalogue/d04-affect-scheme.json"
    content = asset_path.read_bytes().replace(b'"schema":', b'"schema":"d04.affect.scheme.v1","schema":')
    asset_path.write_bytes(content)
    entry = next(item for item in manifest["files"] if item["path"] == "resources/catalogue/d04-affect-scheme.json")
    entry.update(bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
    manifest["affect_scheme"].update(bytes=entry["bytes"], sha256=entry["sha256"])
    digest = _write_manifest(root, manifest)
    with pytest.raises(ValueError, match="duplicate JSON field"):
        load_verified_affect_scheme(root, digest)


def test_rejects_non_json_nan_after_byte_verification(tmp_path: Path) -> None:
    root, manifest, _, _ = _package(tmp_path)
    asset_path = root / "resources/catalogue/d04-affect-scheme.json"
    content = asset_path.read_bytes().replace(
        b'"parameter_bounds":[]', b'"parameter_bounds":[["fixture",NaN,1]]',
    )
    asset_path.write_bytes(content)
    entry = next(item for item in manifest["files"] if item["path"] == "resources/catalogue/d04-affect-scheme.json")
    entry.update(bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
    manifest["affect_scheme"].update(bytes=entry["bytes"], sha256=entry["sha256"])
    digest = _write_manifest(root, manifest)
    with pytest.raises(ValueError, match="non-JSON numeric constant"):
        load_verified_affect_scheme(root, digest)
