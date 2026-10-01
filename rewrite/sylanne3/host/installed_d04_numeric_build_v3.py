"""One manifest-pinned identity for the installed D04 full/LOO/output recipe."""
from __future__ import annotations

import json
from pathlib import Path

from ..runtime_contracts import canonical_digest
from .installed_package import verify_installed_backend_runtime_v1, _safe_file
from .installed_d04_output_policy import _read_verified_d04_output_policy_v1

ALGORITHM_ID = "d04.joint_numeric_full_loo_output.v3"


def read_installed_d04_numeric_identity_v3(package_root, manifest_sha256):
    root = Path(package_root).resolve(strict=True)
    installed = verify_installed_backend_runtime_v1(root, manifest_sha256)
    if not installed.verified:
        raise ValueError("D04 installed backend runtime bytes are unverified: " + installed.reason)
    manifest = json.loads((root / "release-manifest.json").read_bytes())
    # Bind every Python dependency, including shared graph/native codecs. A
    # dirty source revision is identified by actual packaged bytes, not Git SHA.
    source_rows = sorted((row for row in manifest["files"]
        if row["path"].startswith("rewrite/sylanne3/") and row["path"].endswith(".py")),
        key=lambda row: row["path"])
    if not source_rows:
        raise ValueError("D04 algorithm source closure is absent")
    for relative in ("rewrite/sylanne3/runtime/d04_numeric_cost_v3.py",
            "rewrite/sylanne3/runtime/d04_joint_product_assembly_v3.py",
            "rewrite/sylanne3/native_runtime/d04_joint_product_math.py",
            "rewrite/sylanne3/domains/d04/joint_state_output_v1.py"):
        if _safe_file(root, relative) is None or not any(row["path"] == relative for row in source_rows):
            raise ValueError("D04 installed numeric recipe source is absent")
    # This module itself must be loaded from those exact installed bytes.
    if Path(__file__).resolve(strict=True) != (root / "rewrite/sylanne3/host/installed_d04_numeric_build_v3.py"):
        raise ValueError("loaded D04 numeric build reader differs from installation")
    policy = _read_verified_d04_output_policy_v1(root, manifest_sha256, installed,
        require_formal=False, require_backend_runtime=True)
    native = manifest["native"]
    return {"algorithm_id": ALGORITHM_ID,
        "algorithm_build_digest": canonical_digest({"schema": "d04.numeric-recipe-build.v3",
            "algorithm_id": ALGORITHM_ID, "sources": source_rows}),
        "native_manifest_sha256": manifest_sha256,
        "native_sha256": native["sha256"], "output_policy_digest": policy.policy.digest}
