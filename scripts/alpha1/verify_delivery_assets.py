"""Check release resources are deterministic, traceable, and free of obvious secrets."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


FORBIDDEN_NAMES = {".env", "credentials.json", "secrets.json"}
FORBIDDEN_SUFFIXES = {".log", ".pyc", ".pem", ".key", ".sqlite", ".sqlite3"}


def verify(root: Path) -> None:
    workbench = root / "resources" / "workbench"
    manifest_path = workbench / "workbench-manifest.json"
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    if document.get("schema_version") != "sylanne.workbench-assets.v1": raise ValueError("unknown workbench asset schema")
    listed = {row["path"]: row for row in document.get("files", [])}
    if not listed or "index.html" not in listed: raise ValueError("workbench manifest is incomplete")
    actual = set()
    for resource_root in (root / "resources" / "workbench", root / "resources" / "catalogue", root / "resources" / "migrations"):
        if not resource_root.is_dir(): raise ValueError(f"missing resource root: {resource_root.name}")
        for path in resource_root.rglob("*"):
            if path.is_symlink(): raise ValueError(f"symlink resource: {path}")
            if path.is_file() and (path.name.casefold() in FORBIDDEN_NAMES or path.suffix.casefold() in FORBIDDEN_SUFFIXES): raise ValueError(f"forbidden release resource: {path}")
            if resource_root == workbench and path.is_file() and path.name != "workbench-manifest.json":
                relative = path.relative_to(workbench).as_posix(); actual.add(relative)
                row = listed.get(relative)
                if not row or row.get("bytes") != path.stat().st_size or row.get("sha256") != hashlib.sha256(path.read_bytes()).hexdigest(): raise ValueError(f"workbench asset mismatch: {relative}")
    if actual != set(listed): raise ValueError("workbench manifest file set mismatch")
    catalogue = json.loads((root / "resources" / "catalogue" / "current.json").read_text(encoding="utf-8"))
    if not catalogue.get("types") or catalogue.get("completeness") not in {"candidate-exports-only", "registered-exports"}: raise ValueError("catalogue completeness declaration is missing")
    if catalogue.get("activation_status") != "candidate_only": raise ValueError("catalogue must not claim runtime activation")
    actual_domains = {row.get("writer_domain") for row in catalogue["types"]}
    expected_domains = {f"d{number:02d}" for number in range(1, 13)}
    if set(catalogue.get("declared_domains", ())) != actual_domains: raise ValueError("catalogue domain declaration differs from its TypeSpecs")
    if set(catalogue.get("missing_domain_exports", ())) != expected_domains - actual_domains: raise ValueError("catalogue hides a missing domain exporter")
    if catalogue.get("release_eligibility", "").split(":", 1)[0] != "HOLD": raise ValueError("candidate catalogue must not be release eligible")
    migration = json.loads((root / "resources" / "migrations" / "v1.json").read_text(encoding="utf-8"))
    if migration.get("legacy_data_policy") != "reject_without_proven_migrator" or migration.get("migrations") != []: raise ValueError("migration placeholder must reject unproven legacy data")
    if not (root / "THIRD_PARTY_NOTICES.md").is_file() or not (root / "SBOM.cdx.json").is_file(): raise ValueError("notices or SBOM missing")


if __name__ == "__main__": verify(Path(__file__).resolve().parents[2])
