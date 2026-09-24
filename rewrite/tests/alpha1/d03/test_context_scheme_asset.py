"""Synthetic formal package exercises D03 asset trust, not release readiness."""

from __future__ import annotations

import hashlib
import json
import platform
from pathlib import Path

import pytest

from sylanne3.domains.d03.context import ContextProvider, RoleBinding, RoleBindingRequest
from sylanne3.host.context_scheme_asset import load_verified_context_scheme


SOURCE_ROOT = Path(__file__).resolve().parents[4]
ASSET = "resources/catalogue/d03-neutral-context-scheme.json"


def _encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _package(tmp_path: Path) -> tuple[Path, dict]:
    os_name = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}[platform.system()]
    arch = {"AMD64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}[
        platform.machine()
    ]
    native_name = {
        "windows": "sylanne3_kernel.dll", "linux": "libsylanne3_kernel.so",
        "macos": "libsylanne3_kernel.dylib",
    }[os_name]
    native = f"rewrite/sylanne3/_native/{os_name}-{arch}/{native_name}"
    payload = {
        native: b"synthetic native fixture",
        ASSET: (SOURCE_ROOT / ASSET).read_bytes(),
    }
    entries = []
    for relative, content in payload.items():
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        entries.append({
            "path": relative, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
        })
    manifest = {
        "schema_version": 1, "package_version": "fixture-alpha1", "build_mode": "formal-alpha1",
        "platform": {
            "os": os_name, "arch": arch, "native_filename": native_name,
            "abi_version": 2, "libc": platform.libc_ver()[0] if os_name == "linux" else None,
            "cpu_features": [],
        },
        "native": entries[0], "files": entries,
        "context_scheme": {**entries[1], "schema": "d03.context.scheme.v1"},
    }
    return tmp_path, manifest


def _write_manifest(root: Path, manifest: dict) -> str:
    content = _encoded(manifest)
    (root / "release-manifest.json").write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def test_pinned_formal_asset_compiles_only_neutral_role_and_empty_norms(tmp_path: Path) -> None:
    root, manifest = _package(tmp_path)
    digest = _write_manifest(root, manifest)
    verified = load_verified_context_scheme(root, digest)
    assert verified.manifest_sha256 == digest
    assert verified.asset_sha256 == manifest["context_scheme"]["sha256"]
    provider = ContextProvider()
    compiled = provider.compile_scheme(verified.draft(), None)
    assert compiled == {
        "schema": "d03.context.scheme.v1", "roles": ("scene_participant",), "norms": (),
    }
    binding = RoleBinding(
        "binding:first", "persona:local", "scene_participant", None, None,
        "scene:local", "scene", "private", (), 1.0, None, 0,
        ("source:first",), 1, "active",
    )
    request = RoleBindingRequest(
        "persona:local", None, None, "scene:local", "respond", "reply", 1.0, True,
    )
    assert provider.resolve_role_binding(request, (binding,)).status == "complete"


@pytest.mark.parametrize("change", ("asset_bytes", "binding_digest", "binding_missing", "manifest_digest"))
def test_rejects_unverified_or_changed_asset(tmp_path: Path, change: str) -> None:
    root, manifest = _package(tmp_path)
    original_digest = _write_manifest(root, manifest)
    if change == "asset_bytes":
        (root / ASSET).write_bytes(b"{}")
    elif change == "binding_digest":
        manifest["context_scheme"]["sha256"] = "0" * 64
        _write_manifest(root, manifest)
    elif change == "binding_missing":
        del manifest["context_scheme"]
        _write_manifest(root, manifest)
    else:
        manifest["package_version"] = "changed"
        _write_manifest(root, manifest)
    digest = original_digest if change in {"asset_bytes", "manifest_digest"} else hashlib.sha256(
        (root / "release-manifest.json").read_bytes()
    ).hexdigest()
    with pytest.raises(ValueError):
        load_verified_context_scheme(root, digest)


def test_rejects_non_neutral_role_even_when_manifest_is_rebound(tmp_path: Path) -> None:
    root, manifest = _package(tmp_path)
    content = _encoded({"schema": "d03.context.scheme.v1", "roles": ["friend"], "norms": []})
    (root / ASSET).write_bytes(content)
    entry = manifest["files"][1]
    entry.update(bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
    manifest["context_scheme"].update(bytes=entry["bytes"], sha256=entry["sha256"])
    with pytest.raises(ValueError, match="neutral scene role"):
        load_verified_context_scheme(root, _write_manifest(root, manifest))


def test_dev_probe_cannot_activate_context_scheme(tmp_path: Path) -> None:
    root, manifest = _package(tmp_path)
    manifest["build_mode"] = "dev-probe"
    with pytest.raises(ValueError, match="formal-alpha1"):
        load_verified_context_scheme(root, _write_manifest(root, manifest))
