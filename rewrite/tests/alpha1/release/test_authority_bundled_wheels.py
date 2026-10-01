"""Offline Authority staging imports exact bundled Windows wheels."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import zipfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest


ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts" / "alpha1"))

import authority_installer as installer  # noqa: E402
from authority_staging_package import (  # noqa: E402
    MANIFEST_PATH, NOTICES_PATH, SBOM_PATH, build_staging_authority,
    verify_staging_authority,
)


def test_bundled_wheels_install_offline_and_import_from_private_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheelhouse_env = os.environ.get("SYLANNE_AUTHORITY_TEST_WHEELHOUSE")
    if not wheelhouse_env:
        pytest.skip("set SYLANNE_AUTHORITY_TEST_WHEELHOUSE to exact locked Windows wheels")
    package = tmp_path / "authority.zip"
    receipt = build_staging_authority(ROOT, package, wheelhouse=Path(wheelhouse_env))
    assert receipt["dependency_wheels"] == "bundled_exact_locked"
    assert receipt["wheel_count"] == 3
    with zipfile.ZipFile(package) as archive:
        manifest = json.loads(archive.read(MANIFEST_PATH))
        sbom = json.loads(archive.read(SBOM_PATH))
        notices = archive.read(NOTICES_PATH).decode("utf-8")
    assert len(manifest["wheels"]) == 3
    assert {row["path"] for row in manifest["legal_inventory"]} == {NOTICES_PATH, SBOM_PATH}
    assert {component["name"] for component in sbom["components"]} == {
        "cryptography", "cffi", "pycparser",
    }
    assert "Apache-2.0 OR BSD-3-Clause" in notices
    assert "This inventory has not received legal review." in notices
    private = Ed25519PrivateKey.generate()
    key = tmp_path / "publisher.pub"
    key.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    ))
    signature = tmp_path / "publisher.sig"
    signature.write_bytes(private.sign(
        b"sylanne.authority.bundle.v1\0" + package.read_bytes(),
    ))
    pins = {
        "trusted_root_sha256": hashlib.sha256(key.read_bytes()).hexdigest(),
        "expected_package_sha256": receipt["package_sha256"],
        "expected_manifest_sha256": receipt["manifest_sha256"],
    }
    verified = installer.verify_publisher_bundle(package, signature, key, **pins)
    monkeypatch.setattr(installer, "_require_elevated_windows", lambda: None)
    monkeypatch.setattr(installer, "_acl", lambda *_: None)
    root = tmp_path / "installed"
    staged = installer.prepare_install(root, package, verified, service_sid="S-1-5-18",
                                       signature=signature, publisher_key=key)
    assert staged["dependency_dir"] == "dependencies\\" + receipt["package_sha256"]
    cold = installer.verify_disabled_install(root, **pins)
    assert cold["dependency_runtime"] == "bundled_offline_private_root"
    assert cold["installed_dependencies"] == {
        "cryptography": "50.0.1", "cffi": "2.1.1", "pycparser": "3.0",
    }
    assert cold["entrypoints_imported"] > 0
    assert cold["cold_install_pass"] is False
    with zipfile.ZipFile(package) as source, zipfile.ZipFile(tmp_path / "tampered.zip", "w") as target:
        for name in source.namelist():
            data = source.read(name)
            if name.startswith("wheels/"):
                data += b"tampered"
            target.writestr(name, data)
    with pytest.raises(ValueError, match="digest differs"):
        verify_staging_authority(tmp_path / "tampered.zip",
                                 expected_manifest_sha256=receipt["manifest_sha256"])
    with zipfile.ZipFile(package) as source, zipfile.ZipFile(tmp_path / "bad-notices.zip", "w") as target:
        for name in source.namelist():
            data = source.read(name)
            if name == NOTICES_PATH:
                data += b"tampered"
            target.writestr(name, data)
    with pytest.raises(ValueError, match="digest differs"):
        verify_staging_authority(tmp_path / "bad-notices.zip",
                                 expected_manifest_sha256=receipt["manifest_sha256"])
