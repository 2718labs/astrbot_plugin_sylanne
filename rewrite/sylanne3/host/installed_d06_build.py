"""Verify the installed D06 algorithm bytes against an external manifest pin."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re

from .installed_package import verify_installed_backend_runtime_v1, verify_installed_package


ALGORITHM_ID = "d06.association_activation.v2"
ENTRY_PATH = "rewrite/sylanne3/domains/d06/c04_work_input_v2.py"
KERNEL_PATH = "rewrite/sylanne3/memory_association.py"
ALGORITHM_ID_V3 = "d06.association_activation.v3"
ENTRY_PATH_V3 = "rewrite/sylanne3/domains/d06/c04_work_algorithm_v3.py"
_SOURCES = {
    ALGORITHM_ID: (ENTRY_PATH, KERNEL_PATH),
    ALGORITHM_ID_V3: (
        ENTRY_PATH_V3, KERNEL_PATH,
        "rewrite/sylanne3/runtime/c04_v3_contracts.py",
        "rewrite/sylanne3/domains/d06/c04_work_input_v2.py",
        "rewrite/sylanne3/runtime/c04_frozen_association_original_v3.py",
        "rewrite/sylanne3/runtime/c04_internal_work_original_v1.py",
    ),
}
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def verify_d06_algorithm_build(
    package_root: Path, trusted_manifest_sha256: str, *,
    require_formal: bool = False,
    require_backend_runtime: bool = False,
    algorithm_id: str = ALGORITHM_ID,
) -> dict:
    """Bind the installed algorithm source; publisher trust is external."""
    if _DIGEST.fullmatch(trusted_manifest_sha256) is None:
        raise ValueError("externally pinned manifest SHA256 is required")
    if algorithm_id not in _SOURCES:
        raise ValueError("unknown installed D06 algorithm version")
    entry_path = _SOURCES[algorithm_id][0]
    package_root = package_root.resolve(strict=True)
    installed = (verify_installed_backend_runtime_v1(package_root, trusted_manifest_sha256)
                 if require_backend_runtime else
                 verify_installed_package(package_root, trusted_manifest_sha256))
    if not installed.verified:
        raise ValueError(f"installed package verification failed: {installed.reason}")
    if require_formal and installed.build_mode != "formal-alpha1":
        raise ValueError("formal D06 build binding requires a formal-alpha1 package")
    if require_backend_runtime and installed.runtime_scope not in {
        "formal-alpha1", "backend-production-acceptance",
    }:
        raise ValueError("D06 production runtime qualification is unavailable")
    manifest_bytes = (package_root / "release-manifest.json").read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != trusted_manifest_sha256:
        raise ValueError("installed manifest changed after package verification")
    manifest = json.loads(manifest_bytes)
    rows = manifest.get("files")
    if not isinstance(rows, list):
        raise ValueError("installed package file list is absent")
    sources = []
    source_paths = _SOURCES[algorithm_id]
    if algorithm_id == ALGORITHM_ID_V3:
        # V3 executes authored/legacy codecs, current D04 projections and the
        # fixed D07 code-policy. Bind every installed runtime module's bytes so
        # dynamic imports and future pure dependencies cannot evade the build pin.
        source_paths = tuple(sorted(row["path"] for row in rows
                                    if type(row) is dict
                                    and type(row.get("path")) is str
                                    and row["path"].startswith("rewrite/sylanne3/")
                                    and row["path"].endswith(".py")))
        if not set(_SOURCES[algorithm_id]).issubset(source_paths):
            raise ValueError("installed V3 runtime source closure is incomplete")
    for relative in source_paths:
        entries = [row for row in rows if isinstance(row, dict) and row.get("path") == relative]
        if len(entries) != 1:
            raise ValueError(f"D06 algorithm source is not uniquely installed: {relative}")
        path = package_root / relative
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(package_root):
            raise ValueError("D06 installed algorithm source is absent or unsafe")
        data = path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        if entries[0].get("sha256") != sha or entries[0].get("bytes") != len(data):
            raise ValueError("D06 installed algorithm source differs from manifest")
        sources.append({"path": relative, "sha256": sha, "bytes": len(data)})
    tree = ast.parse((package_root / entry_path).read_bytes(), filename=entry_path)
    declared = [node.value.value for node in tree.body
                if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "ALGORITHM_ID"
                        for target in node.targets)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)]
    if declared != [algorithm_id]:
        raise ValueError("installed D06 algorithm ID differs")
    binding = {
        "schema": "sylanne.d06.algorithm-build.v1",
        "algorithm_id": algorithm_id,
        "manifest_sha256": trusted_manifest_sha256,
        "sources": sorted(sources, key=lambda row: row["path"]),
    }
    encoded = json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        **binding,
        "build_digest": "sha256:" + hashlib.sha256(encoded).hexdigest(),
        "package_mode": installed.build_mode,
        "publisher_trust": "not_verified_by_this_api",
        "status": ("formal_package_bytes_only" if installed.build_mode == "formal-alpha1"
                   else "backend_acceptance_package_bytes_only"
                   if installed.runtime_scope == "backend-production-acceptance"
                   else "diagnostic_installed_source_only"),
        "runtime_scope": installed.runtime_scope,
    }


__all__ = ["ALGORITHM_ID", "ENTRY_PATH", "KERNEL_PATH",
           "ALGORITHM_ID_V3", "ENTRY_PATH_V3", "verify_d06_algorithm_build"]
