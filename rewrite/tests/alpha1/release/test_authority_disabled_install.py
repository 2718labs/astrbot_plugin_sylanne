"""A signed local staging layout reopens from installed bytes while disabled."""

from __future__ import annotations

import hashlib
import importlib.metadata
from pathlib import Path
import sys

import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest


ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts" / "alpha1"))

import authority_installer as installer  # noqa: E402
from authority_staging_package import build_staging_authority  # noqa: E402


def test_disabled_install_reopens_pinned_bytes_and_rejects_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "authority.zip"
    staging = build_staging_authority(ROOT, package)
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
        "expected_package_sha256": staging["package_sha256"],
        "expected_manifest_sha256": staging["manifest_sha256"],
    }
    dependency_root = Path(cryptography.__file__).resolve().parent.parent
    verified = installer.verify_publisher_bundle(package, signature, key, **pins)
    monkeypatch.setattr(installer, "_require_elevated_windows", lambda: None)
    monkeypatch.setattr(installer, "_acl", lambda *_: None)
    root = tmp_path / "installed"
    installer.prepare_install(root, package, verified, service_sid="S-1-5-18",
                              signature=signature, publisher_key=key)
    if importlib.metadata.version("cryptography") == "50.0.1":
        receipt = installer.verify_disabled_install(root, dependency_root=dependency_root, **pins)
        assert receipt["status"] == "disabled_installed_diagnostic"
        assert receipt["entrypoints_imported"] > 0
        assert receipt["installed_dependencies"]["cryptography"] == "50.0.1"
        assert receipt["cold_install_pass"] is False
    else:
        with pytest.raises(RuntimeError, match="installed dependency differs"):
            installer.verify_disabled_install(root, dependency_root=dependency_root, **pins)
    code = root / "code" / staging["package_sha256"] / "rewrite/sylanne3/authority_service/daemon.py"
    code.write_bytes(code.read_bytes() + b"\n# tampered\n")
    with pytest.raises(ValueError, match="installed Authority code differs"):
        installer.verify_disabled_install(root, dependency_root=dependency_root, **pins)
