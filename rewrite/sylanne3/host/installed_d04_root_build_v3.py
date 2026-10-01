"""Independent manifest identity of the installed authored-root CPU recipe."""
from pathlib import Path
import json
from ..authority_service.d04_root_execution_contract_v3 import ROOT_ALGORITHM_ID_V3
from ..runtime_contracts import canonical_digest
from .installed_d04_numeric_build_v3 import read_installed_d04_numeric_identity_v3
from .installed_d04_root_resources import load_installed_d04_root_preset_v3


def read_installed_d04_root_identity_v3(package_root, manifest_sha256):
    root = Path(package_root).resolve(strict=True)
    numeric = read_installed_d04_numeric_identity_v3(root, manifest_sha256)
    if Path(__file__).resolve(strict=True) != root / "rewrite/sylanne3/host/installed_d04_root_build_v3.py":
        raise ValueError("loaded root recipe identity differs from pinned installation")
    manifest = json.loads((root / "release-manifest.json").read_bytes())
    rows = sorted((row for row in manifest["files"] if row["path"].startswith("rewrite/sylanne3/")
        and row["path"].endswith(".py")), key=lambda row: row["path"])
    preset = load_installed_d04_root_preset_v3(root, manifest_sha256)
    return {**numeric, "algorithm_id": ROOT_ALGORITHM_ID_V3,
        "algorithm_build_digest": canonical_digest({"schema": "d04.authored-root-recipe-build.v3",
            "algorithm_id": ROOT_ALGORITHM_ID_V3, "sources": rows}),
        "preset_id": preset.preset_id, "preset_digest": preset.digest}
