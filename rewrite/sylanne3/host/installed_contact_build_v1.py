"""Manifest-pinned installed contact algorithms and actual loaded source origin."""
import hashlib
import json
from pathlib import Path
from .installed_package import verify_installed_backend_runtime_v1
from ..runtime_contracts import canonical_digest

FILES = (
    "rewrite/sylanne3/domains/d08/contact_plan_v1.py",
    "rewrite/sylanne3/domains/d06/qualified_expression.py",
    "rewrite/sylanne3/model_broker/contact_expression_v1.py",
    "rewrite/sylanne3/runtime/contact_plan_adoption_v1.py",
    "rewrite/sylanne3/runtime/contact_model_job_v1.py",
    "rewrite/sylanne3/runtime/contact_model_preparation_v1.py",
    "rewrite/sylanne3/runtime/contact_paid_original_v1.py",
    "rewrite/sylanne3/runtime/contact_product_adapter_v1.py",
    "rewrite/sylanne3/runtime/contact_model_preparation_commit_v1.py",
    "rewrite/sylanne3/runtime/contact_graph_runtime_v1.py",
    "rewrite/sylanne3/runtime/c09_contact_originals_v1.py",
    "rewrite/sylanne3/runtime/model_cost_settlement.py",
    "rewrite/sylanne3/runtime/contact_route_binding_v1.py",
    "rewrite/sylanne3/authority_service/contact_model_graph_v1.py",
    "rewrite/sylanne3/authority_service/contact_model_result_contract_v1.py",
    "rewrite/sylanne3/authority_service/contact_model_result_service_v1.py",
    "rewrite/sylanne3/authority_service/current_model_egress_graph_verifier.py",
    "rewrite/sylanne3/host/installed_contact_model_driver_v1.py",
    "rewrite/sylanne3/host/installed_contact_build_v1.py",
    "rewrite/sylanne3/host/astrbot_model_call.py",
    "rewrite/sylanne3/runtime_contracts.py",
)


def read_installed_contact_build_v1(package_root, manifest_digest):
    root = Path(package_root).resolve(strict=True)
    installed = verify_installed_backend_runtime_v1(root, manifest_digest)
    if not installed.verified or installed.runtime_scope not in {"formal-alpha1", "backend-production-acceptance"}:
        raise ValueError("contact models require actual qualified installed backend")
    manifest = json.loads((root / "release-manifest.json").read_bytes())
    identity = []
    for relative in FILES:
        path = root / relative
        data = path.read_bytes()
        row = {"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        matches = tuple(record for record in manifest["files"] if record["path"] == relative)
        origin = Path(__file__).resolve().parents[1] / relative.removeprefix("rewrite/sylanne3/")
        if len(matches) != 1 or any(matches[0].get(key) != value for key, value in row.items()) or origin.resolve() != path.resolve():
            raise ValueError("contact loaded algorithm differs from its installed manifest: " + relative)
        identity.append(row)
    return canonical_digest({"schema": "d10.contact-installed-build.v1", "manifest_digest": manifest_digest,
        "files": sorted(identity, key=lambda row: row["path"])})
