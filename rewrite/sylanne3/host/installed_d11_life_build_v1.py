"""Actual installed file closure of the fixed Life executor and verifier."""
import hashlib
import json
from pathlib import Path

from .installed_package import verify_installed_backend_runtime_v1
from ..runtime_contracts import canonical_digest

EXECUTOR_FILES = (
    "rewrite/sylanne3/runtime/d01_life_activation_original_v1.py",
    "rewrite/sylanne3/runtime/d11_life_scope_v1.py",
    "rewrite/sylanne3/runtime/d08_life_admission_v1.py",
    "rewrite/sylanne3/runtime/d08_source_note_action_v1.py",
    "rewrite/sylanne3/runtime/d02_life_body_preparation_v1.py",
    "rewrite/sylanne3/authority_service/d11_life_execution_inventory_v1.py",
    "rewrite/sylanne3/runtime/d11_life_preparation_v1.py",
    "rewrite/sylanne3/runtime/d02_life_effect_v1.py",
    "rewrite/sylanne3/domains/d03/context.py",
    "rewrite/sylanne3/domains/d05/relationship.py",
    "rewrite/sylanne3/domains/d07/qualified_attention_read.py",
    "rewrite/sylanne3/domains/d08/execution.py",
    "rewrite/sylanne3/authority_service/d11_life_service_v1.py",
    "rewrite/sylanne3/authority_service/d11_bounded_execution_lifecycle_v1.py",
    "rewrite/sylanne3/authority_service/d11_life_journal_v1.py",
    "rewrite/sylanne3/runtime/d11_life_contract_v1.py",
    "rewrite/sylanne3/runtime/d11_life_source_note_v1.py",
    "rewrite/sylanne3/runtime_contracts.py",
    "rewrite/sylanne3/domains/d01/production_operations_v1.py",
)
VERIFIER_FILES = (
    "rewrite/sylanne3/runtime/d11_life_source_note_v1.py",
    "rewrite/sylanne3/runtime/d11_life_contract_v1.py",
    "rewrite/sylanne3/memory_types.py",
    "rewrite/sylanne3/runtime_contracts.py",
    "rewrite/sylanne3/domains/d01/production_operations_v1.py",
)


def read_installed_d11_life_build_v1(package_root, manifest_digest):
    root = Path(package_root).resolve(strict=True)
    installed = verify_installed_backend_runtime_v1(root, manifest_digest)
    if not installed.verified or installed.runtime_scope not in {"formal-alpha1", "backend-production-acceptance"}:
        raise ValueError("Life requires the actual qualified installed backend package")
    manifest = json.loads((root / "release-manifest.json").read_bytes())
    sources = {}
    for relative in set(EXECUTOR_FILES + VERIFIER_FILES):
        rows = tuple(row for row in manifest["files"] if row["path"] == relative)
        path = root / relative
        data = path.read_bytes()
        identity = {"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        if len(rows) != 1 or any(rows[0].get(k) != v for k, v in identity.items()):
            raise ValueError("Life installed build file differs from manifest: " + relative)
        module_path = Path(__file__).resolve().parents[1] / relative.removeprefix("rewrite/sylanne3/")
        if module_path.resolve() != path.resolve():
            raise ValueError("Life loaded source origin differs from installed manifest")
        sources[relative] = identity
    return {name: canonical_digest({"schema": "d11.life-installed-build.v1", "kind": name,
        "manifest_digest": manifest_digest, "files": [sources[p] for p in sorted(paths)]})
        for name, paths in (("algorithm_build_digest", EXECUTOR_FILES), ("postcondition_build_digest", VERIFIER_FILES))}
