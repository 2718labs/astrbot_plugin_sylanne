"""Build or audit a frozen backend-only alpha1 ZIP without publishing it.

Run ``build`` only after backend acceptance and source/catalogue/native bytes are
frozen. Its output directory and audit receipt must be outside the checkout.
Run ``audit`` for each platform ZIP; the receipt is a file-by-file inventory,
not a cold-load or product acceptance result. On each target host, separately
run verify_formal_cold_install.py with the pinned manifest SHA256 it reports.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(ROOT)

from rewrite.tools.build_plugin_package import (  # noqa: E402
    build_package, verify_package, FORMAL_VERSION,
)
from sylanne3.native_runtime.loader import _runtime_target  # noqa: E402


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(value: str, label: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{label} must be a lowercase SHA256 digest")
    return value


def _commit(value: str) -> str:
    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None:
        raise ValueError("source commit must be a full Git object ID")
    return value


def _outside_checkout(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if resolved == ROOT or resolved.is_relative_to(ROOT):
        raise ValueError(f"{label} must be outside the source checkout")
    return resolved


def _frozen_source(expected_source: str, expected_catalogue: str) -> None:
    source = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                            check=True, capture_output=True, text=True).stdout.strip()
    if source != expected_source:
        raise RuntimeError("frozen source commit differs from checkout HEAD")
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=normal"],
                           cwd=ROOT, check=True, capture_output=True, text=True).stdout
    if dirty:
        raise RuntimeError("frozen source checkout is dirty")
    catalogue = json.loads((ROOT / "resources/catalogue/current.json").read_bytes())
    if (catalogue.get("catalogue_hash") != expected_catalogue
            or catalogue.get("activation_status") != "runtime_verified"
            or catalogue.get("release_eligibility") != "READY"):
        raise RuntimeError("frozen live catalogue identity or eligibility differs")


def audit_package(package: Path, *, expected_source: str,
                  expected_catalogue: str, expected_native: str,
                  expected_os: str, expected_arch: str, expected_libc: str | None,
                  expected_manifest: str | None = None,
                  expected_package: str | None = None) -> dict:
    """Independently hash every ZIP member after the builder's structural audit."""
    verify_package(package)
    archive_bytes = package.read_bytes()
    package_hash = _sha256(archive_bytes)
    if expected_package is not None and package_hash != expected_package:
        raise ValueError("package bytes differ from pinned SHA256")
    with zipfile.ZipFile(package) as archive:
        manifest_bytes = archive.read("release-manifest.json")
        manifest_hash = _sha256(manifest_bytes)
        if expected_manifest is not None and manifest_hash != expected_manifest:
            raise ValueError("manifest bytes differ from pinned SHA256")
        manifest = json.loads(manifest_bytes)
        platform = manifest["platform"]
        if (manifest.get("package_version") != FORMAL_VERSION
                or manifest.get("build_mode") != "formal-alpha1"
                or manifest.get("candidate_scope") != "backend-only"
                or manifest.get("source") != {"git_sha": expected_source, "dirty": False}
                or platform.get("os") != expected_os
                or platform.get("arch") != expected_arch
                or platform.get("libc") != expected_libc
                or manifest["native"].get("sha256") != expected_native):
            raise ValueError("backend candidate differs from frozen scope, source or native")
        inventory = []
        names = set(archive.namelist())
        for row in manifest["files"]:
            path = row["path"]
            data = archive.read(path)
            observed = {"path": path, "bytes": len(data), "sha256": _sha256(data)}
            if observed != row:
                raise ValueError(f"manifest file differs from archive bytes: {path}")
            inventory.append(observed)
        if names != {row["path"] for row in inventory} | {"release-manifest.json"}:
            raise ValueError("ZIP contains unlisted or missing members")
        if any(path.startswith(("resources/workbench/", "webui-heritage/"))
               or "/webui-src/" in path for path in names):
            raise ValueError("backend candidate contains frontend assets")
        catalogue = json.loads(archive.read("resources/catalogue/current.json"))
        if (catalogue.get("catalogue_hash") != expected_catalogue
                or catalogue.get("activation_status") != "runtime_verified"
                or catalogue.get("release_eligibility") != "READY"):
            raise ValueError("packaged catalogue differs from frozen live registry")
        migration = json.loads(archive.read("resources/migrations/v1.json"))
        if (migration.get("native_data_policy", {}).get("automatic_legacy_migration") is not False
                or not str(migration.get("release_eligibility", "")).startswith("HOLD:")):
            raise ValueError("backend legacy data policy is not explicitly HOLD")
    return {
        "schema": "sylanne.backend-candidate-audit.v1",
        "classification": "local package mechanics; target-host cold load and product gates separate",
        "package": str(package.resolve()), "package_bytes": len(archive_bytes),
        "package_sha256": package_hash, "manifest_sha256": manifest_hash,
        "source_git_sha": expected_source, "catalogue_hash": expected_catalogue,
        "native_sha256": expected_native,
        "platform": {"os": expected_os, "arch": expected_arch, "libc": expected_libc},
        "file_count": len(inventory), "files": inventory,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "audit"))
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-catalogue-sha256", required=True)
    parser.add_argument("--expected-native-sha256", required=True)
    parser.add_argument("--target-os", required=True, choices=("windows", "linux", "macos"))
    parser.add_argument("--target-arch", required=True, choices=("x86_64", "aarch64"))
    parser.add_argument("--target-libc", choices=("glibc", "musl"))
    parser.add_argument("--native-library", type=Path, help="required for build")
    parser.add_argument("--output-dir", type=Path, help="required for build; outside checkout")
    parser.add_argument("--package", type=Path, help="required for audit")
    parser.add_argument("--expected-manifest-sha256", help="optional pinned manifest for audit")
    parser.add_argument("--expected-package-sha256", help="optional pinned ZIP for audit")
    parser.add_argument("--inventory-output", type=Path, required=True,
                        help="write independent per-file audit receipt outside checkout")
    args = parser.parse_args(argv)
    expected_source = _commit(args.expected_source_commit)
    expected_catalogue = _digest(args.expected_catalogue_sha256, "catalogue")
    expected_native = _digest(args.expected_native_sha256, "native library")
    expected_manifest = (_digest(args.expected_manifest_sha256, "manifest")
                         if args.expected_manifest_sha256 else None)
    expected_package = (_digest(args.expected_package_sha256, "package")
                        if args.expected_package_sha256 else None)
    inventory_path = _outside_checkout(args.inventory_output, "audit receipt")
    if args.mode == "build":
        if args.native_library is None or args.output_dir is None or args.package is not None:
            parser.error("build requires --native-library and --output-dir, without --package")
        if _runtime_target() != (args.target_os, args.target_arch, args.target_libc):
            raise RuntimeError("formal candidate build requires the matching OS, architecture and libc host")
        output_dir = _outside_checkout(args.output_dir, "package output")
        _frozen_source(expected_source, expected_catalogue)
        if _sha256(args.native_library.read_bytes()) != expected_native:
            raise ValueError("native library differs from pinned SHA256")
        package = build_package(
            project_root=ROOT, target_os=args.target_os, target_arch=args.target_arch,
            target_libc=args.target_libc, native_library=args.native_library,
            output_dir=output_dir, backend_only_alpha1=True,
        )
    else:
        if args.package is None or args.native_library is not None or args.output_dir is not None:
            parser.error("audit requires --package, without build inputs")
        package = args.package
    receipt = audit_package(
        package, expected_source=expected_source, expected_catalogue=expected_catalogue,
        expected_native=expected_native, expected_os=args.target_os,
        expected_arch=args.target_arch, expected_libc=args.target_libc,
        expected_manifest=expected_manifest, expected_package=expected_package,
    )
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    inventory_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n",
                              encoding="utf-8")
    print(json.dumps({key: value for key, value in receipt.items() if key != "files"}
                     | {"inventory_path": str(inventory_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
