"""Cold candidate preflight rejects a changed D04 output policy pin."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[4]
POLICY = "resources/catalogue/d04-joint-state-output-policy.v1.json"


def _diagnostic():
    spec = importlib.util.spec_from_file_location(
        "windows_backend_cold_diagnostic",
        ROOT / "scripts/alpha1/windows_backend_cold_diagnostic.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _archive(policy: bytes, binding: dict) -> zipfile.ZipFile:
    buffer = io.BytesIO()
    digest = hashlib.sha256(policy).hexdigest()
    manifest = {
        "files": [{"path": POLICY, "bytes": len(policy), "sha256": digest}],
        "joint_state_output_policy": binding,
    }
    with zipfile.ZipFile(buffer, "w") as target:
        target.writestr(POLICY, policy)
        target.writestr("release-manifest.json", json.dumps(manifest))
    buffer.seek(0)
    return zipfile.ZipFile(buffer)


def test_cold_candidate_preflight_requires_exact_policy_bytes_and_binding() -> None:
    diagnostic = _diagnostic()
    policy = (ROOT / POLICY).read_bytes()
    digest = hashlib.sha256(policy).hexdigest()
    binding = {
        "path": POLICY, "bytes": len(policy), "sha256": digest,
        "status": "candidate", "axis_ids": json.loads(policy)["axis_ids"],
    }
    with _archive(policy, binding) as archive:
        assert diagnostic._verify_d04_output_policy_member(archive) == {
            "path": POLICY, "bytes": len(policy), "sha256": digest,
        }
    with _archive(policy + b"\n", binding) as archive:
        with pytest.raises(ValueError, match="manifest pin differs"):
            diagnostic._verify_d04_output_policy_member(archive)
    with _archive(policy, {**binding, "status": "installed_bytes_only"}) as archive:
        with pytest.raises(ValueError, match="manifest pin differs"):
            diagnostic._verify_d04_output_policy_member(archive)
