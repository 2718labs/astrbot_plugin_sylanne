"""Check release resources are deterministic, traceable, and free of obvious secrets."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


FORBIDDEN_NAMES = {".env", "credentials.json", "secrets.json"}
FORBIDDEN_SUFFIXES = {".log", ".pyc", ".pem", ".key", ".sqlite", ".sqlite3"}
EXPECTED_MIGRATION_PREVIEW = {
    "schema_version": "sylanne.migrations.v1",
    "legacy_data_policy": "registered_migrators",
    "migrations": [{
        "id": "sylanne-2.5-person-profile-preview.v1",
        "source_schema": "sylanne-2.5.person-profile.v1",
        "source_revision": "72de068bf6f97a70086abdddc8cc487933350c5c",
        "source_blob_id": "ddfd064a06940c28cac3deb390fd71721443c548",
        "target_schema": "d12.character_draft.v1",
        "activation": "prohibited_preview_only",
        "deletion_proof": "independent_authority_required",
        "mapping": {
            "all_legacy_profile_values": "unmapped_user_review",
            "legacy_affinity": "never_maps_to_trust",
            "legacy_relationship_counts": "never_maps_to_shared_experience",
        },
    }],
    "release_eligibility": "HOLD: only a quarantined v2.5 profile preview is registered; no verified legacy export/archive format, target identity mapping, complete deletion/execution watermark proof, or D11 atomic adoption path exists",
}


def verify_migration_preview(migration: object) -> None:
    if migration != EXPECTED_MIGRATION_PREVIEW:
        raise ValueError("migration resource must be the registered, activation-prohibited v2.5 profile preview")


def verify_workbench(root: Path) -> None:
    workbench = root / "resources" / "workbench"
    source = root / "webui-src"
    manifest_path = workbench / "workbench-manifest.json"
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    if document.get("schema_version") != "sylanne.workbench-assets.v1": raise ValueError("unknown workbench asset schema")
    if document.get("source") != "webui-src": raise ValueError("workbench manifest source is stale")
    listed = {row["path"]: row for row in document.get("files", [])}
    if not listed or "index.html" not in listed: raise ValueError("workbench manifest is incomplete")
    source_files = {"index.html", *(path.relative_to(source).as_posix() for path in (source / "src").rglob("*") if path.is_file())}
    if source_files != set(listed): raise ValueError("workbench source and manifest file sets differ")
    for relative in source_files:
        path = source / relative
        if path.is_symlink() or path.read_bytes() != (workbench / relative).read_bytes():
            raise ValueError(f"workbench resource differs from source: {relative}")
    actual = set()
    for resource_root in (workbench,):
        if not resource_root.is_dir(): raise ValueError(f"missing resource root: {resource_root.name}")
        for path in resource_root.rglob("*"):
            if path.is_symlink(): raise ValueError(f"symlink resource: {path}")
            if path.is_file() and (path.name.casefold() in FORBIDDEN_NAMES or path.suffix.casefold() in FORBIDDEN_SUFFIXES): raise ValueError(f"forbidden release resource: {path}")
            if resource_root == workbench and path.is_file() and path.name != "workbench-manifest.json":
                relative = path.relative_to(workbench).as_posix(); actual.add(relative)
                row = listed.get(relative)
                if not row or row.get("bytes") != path.stat().st_size or row.get("sha256") != hashlib.sha256(path.read_bytes()).hexdigest(): raise ValueError(f"workbench asset mismatch: {relative}")
    if actual != set(listed): raise ValueError("workbench manifest file set mismatch")


def verify(root: Path) -> None:
    verify_workbench(root)
    for resource_root in (root / "resources" / "catalogue", root / "resources" / "migrations"):
        if not resource_root.is_dir(): raise ValueError(f"missing resource root: {resource_root.name}")
        for path in resource_root.rglob("*"):
            if path.is_symlink(): raise ValueError(f"symlink resource: {path}")
            if path.is_file() and (path.name.casefold() in FORBIDDEN_NAMES or path.suffix.casefold() in FORBIDDEN_SUFFIXES): raise ValueError(f"forbidden release resource: {path}")
    catalogue = json.loads((root / "resources" / "catalogue" / "current.json").read_text(encoding="utf-8"))
    if not catalogue.get("types") or catalogue.get("completeness") not in {"candidate-exports-only", "registered-exports"}: raise ValueError("catalogue completeness declaration is missing")
    if catalogue.get("activation_status") != "candidate_only": raise ValueError("catalogue must not claim runtime activation")
    actual_domains = {row.get("writer_domain") for row in catalogue["types"]}
    expected_domains = {f"d{number:02d}" for number in range(1, 13)}
    if set(catalogue.get("declared_domains", ())) != actual_domains: raise ValueError("catalogue domain declaration differs from its TypeSpecs")
    if set(catalogue.get("missing_domain_exports", ())) != expected_domains - actual_domains: raise ValueError("catalogue hides a missing domain exporter")
    if catalogue.get("release_eligibility", "").split(":", 1)[0] != "HOLD": raise ValueError("candidate catalogue must not be release eligible")
    migration = json.loads((root / "resources" / "migrations" / "v1.json").read_text(encoding="utf-8"))
    verify_migration_preview(migration)
    if not (root / "THIRD_PARTY_NOTICES.md").is_file() or not (root / "SBOM.cdx.json").is_file(): raise ValueError("notices or SBOM missing")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--workbench-only", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    (verify_workbench if args.workbench_only else verify)(root)
