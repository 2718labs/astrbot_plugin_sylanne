"""Load the manifest-pinned D04 output policy from installed package bytes."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

from .installed_package import (
    _safe_file, verify_installed_backend_runtime_v1, verify_installed_package,
)


POLICY_PATH = "resources/catalogue/d04-joint-state-output-policy.v1.json"
READOUT_PATH = "resources/catalogue/d04-tanh-readout.v1.json"
POLICY_SHA256 = "7faef300b10792e3f09d3959b1c6c6e6be4c7abb1a843dcff42e2b12aa250911"
READOUT_SHA256 = "5d56a8de7a98c9792bc850cbd7b62a2a77d0b75e31a0ec02138e5640937d6004"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class InstalledD04OutputPolicyBindingV1:
    policy: object
    manifest_sha256: str
    build_mode: str
    policy_sha256: str
    runtime_scope: str | None = None


def load_installed_d04_output_policy_v1(
    package_root: Path, trusted_manifest_sha256: str, *,
    require_formal: bool = True,
    require_backend_runtime: bool = False,
) -> InstalledD04OutputPolicyBindingV1:
    """Bind policy, identity readout and native bytes to one external manifest pin.

    Candidate mode is exposed only for diagnostics. Publisher trust is not
    established by this API.
    """
    if _DIGEST.fullmatch(trusted_manifest_sha256) is None:
        raise ValueError("externally pinned manifest SHA256 is required")
    original = Path(package_root)
    if original.is_symlink() or bool(getattr(original, "is_junction", lambda: False)()):
        raise ValueError("installed package root is linked")
    root = original.resolve(strict=True)
    installed = (verify_installed_backend_runtime_v1(root, trusted_manifest_sha256)
                 if require_backend_runtime else
                 verify_installed_package(root, trusted_manifest_sha256))
    if not installed.verified:
        raise ValueError(f"installed package verification failed: {installed.reason}")
    return _read_verified_d04_output_policy_v1(
        root, trusted_manifest_sha256, installed,
        require_formal=require_formal, require_backend_runtime=require_backend_runtime,
    )


def _read_verified_d04_output_policy_v1(
    root, trusted_manifest_sha256, installed, *, require_formal, require_backend_runtime,
):
    """Consume the result of this reader's actual package verification."""
    if installed.build_mode not in {"formal-alpha1", "backend-alpha1-candidate", "snapshot-alpha1-test", "alpha2-candidate", "beta1-candidate"}:
        raise ValueError("D04 output policy requires a formal or backend candidate package")
    if require_formal and installed.build_mode != "formal-alpha1":
        raise ValueError("formal D04 output policy requires a formal-alpha1 package")
    if require_backend_runtime and installed.runtime_scope not in {
        "formal-alpha1", "backend-production-acceptance", "backend-local-alpha2-acceptance", "backend-beta1-server-test",
    }:
        raise ValueError("installed D04 runtime qualification is unavailable")
    manifest_path = _safe_file(root, "release-manifest.json")
    policy_path = _safe_file(root, POLICY_PATH)
    readout_path = _safe_file(root, READOUT_PATH)
    if any(path is None for path in (manifest_path, policy_path, readout_path)):
        raise ValueError("installed D04 output policy files are absent or unsafe")
    manifest_bytes = manifest_path.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != trusted_manifest_sha256:
        raise ValueError("installed manifest changed after verification")
    manifest = json.loads(manifest_bytes)
    if manifest.get("build_mode") != installed.build_mode:
        raise ValueError("installed build mode differs")
    rows = manifest.get("files")
    if not isinstance(rows, list):
        raise ValueError("installed file list is absent")

    def listed_exact(relative: str, data: bytes) -> None:
        matches = [row for row in rows if isinstance(row, dict) and row.get("path") == relative]
        if (len(matches) != 1 or matches[0].get("sha256") != hashlib.sha256(data).hexdigest()
                or matches[0].get("bytes") != len(data)):
            raise ValueError(f"installed D04 file differs from manifest: {relative}")

    policy_bytes, readout_bytes = policy_path.read_bytes(), readout_path.read_bytes()
    listed_exact(POLICY_PATH, policy_bytes)
    listed_exact(READOUT_PATH, readout_bytes)
    if (hashlib.sha256(policy_bytes).hexdigest() != POLICY_SHA256
            or hashlib.sha256(readout_bytes).hexdigest() != READOUT_SHA256):
        raise ValueError("installed D04 fixed policy or readout bytes differ")
    policy_data = json.loads(policy_bytes)
    readout = json.loads(readout_bytes)
    from ..domains.d04.numeric_coupling import REGISTERED_AXIS_IDS
    from ..domains.d04.joint_state_output_v1 import JointStateOutputPolicyV1

    if (tuple(policy_data.get("axis_ids", ())) != REGISTERED_AXIS_IDS
            or readout.get("axis_ids") != list(REGISTERED_AXIS_IDS)
            or policy_data.get("readout_id") != readout.get("readout_id")
            or policy_data.get("readout_version") != readout.get("readout_version")
            or policy_data.get("readout_sha256") != READOUT_SHA256):
        raise ValueError("installed D04 policy and readout identity differ")
    outputs = readout.get("outputs")
    if (not isinstance(outputs, list) or len(outputs) != 24
            or any(row.get("axis_id") != REGISTERED_AXIS_IDS[index]
                   or row.get("transform") != "p=C*tanh(z)"
                   or row.get("coefficients") != [int(column == index) for column in range(24)]
                   for index, row in enumerate(outputs))):
        raise ValueError("installed D04 readout must be 24-axis identity tanh")
    expected_binding = {
        "path": POLICY_PATH, "sha256": POLICY_SHA256, "bytes": len(policy_bytes),
        **policy_data,
        "status": "installed_bytes_only" if installed.build_mode == "formal-alpha1" else "candidate",
    }
    if manifest.get("joint_state_output_policy") != expected_binding:
        raise ValueError("installed D04 output policy manifest binding differs")
    policy = JointStateOutputPolicyV1(
        **{**policy_data, "axis_ids": REGISTERED_AXIS_IDS},
    )
    return InstalledD04OutputPolicyBindingV1(
        policy=policy,
        manifest_sha256=trusted_manifest_sha256,
        build_mode=installed.build_mode,
        policy_sha256=POLICY_SHA256,
        runtime_scope=installed.runtime_scope,
    )


__all__ = ["InstalledD04OutputPolicyBindingV1", "load_installed_d04_output_policy_v1"]
