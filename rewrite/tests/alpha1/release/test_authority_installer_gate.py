"""Signed diagnostic Authority staging cannot be mistaken for product install."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest


ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts" / "alpha1"))

from authority_installer import verify_publisher_bundle  # noqa: E402
from authority_staging_package import build_staging_authority  # noqa: E402
from authority_windows_scm import _formal  # noqa: E402


def test_ephemeral_publisher_signature_checks_exact_bundle_and_keeps_hold(tmp_path: Path) -> None:
    package = tmp_path / "authority.zip"
    staging = build_staging_authority(ROOT, package)
    private = Ed25519PrivateKey.generate()
    key = tmp_path / "publisher.pub"
    key.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    ))
    signature = tmp_path / "package.sig"
    signature.write_bytes(private.sign(
        b"sylanne.authority.bundle.v1\0" + package.read_bytes(),
    ))
    pins = {
        "trusted_root_sha256": hashlib.sha256(key.read_bytes()).hexdigest(),
        "expected_package_sha256": staging["package_sha256"],
        "expected_manifest_sha256": staging["manifest_sha256"],
    }
    result = verify_publisher_bundle(package, signature, key, **pins)
    assert result["publisher_signature"] == "verified_against_supplied_pinned_key"
    assert result["formal_publisher_root"] == "unproven"
    assert result["service_installer"] == "absent"
    assert result["cold_install_pass"] is False
    with pytest.raises(RuntimeError, match="activation remains HOLD"):
        _formal({"status": "formal_authority_release"}, result)
    with pytest.raises(ValueError, match="externally pinned digest"):
        verify_publisher_bundle(package, signature, key,
                                **{**pins, "trusted_root_sha256": "0" * 64})
    signature.write_bytes(b"0" * 64)
    with pytest.raises(ValueError, match="publisher signature differs"):
        verify_publisher_bundle(package, signature, key, **pins)
