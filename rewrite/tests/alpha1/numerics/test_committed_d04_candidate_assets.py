"""The committed D04 package resources remain exact conditional candidate bytes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from rewrite.tools.build_plugin_package import _d04_binding, _d04_operator_binding
from scripts.alpha1.generate_d04_candidate_assets import candidate_asset_bytes
from sylanne3.native_runtime.d04_engineering_scheme import (
    DIMENSION,
    LAYERS,
    MECHANISMS,
    build_d04_engineering_candidate,
)


ROOT = Path(__file__).resolve().parents[4]
CATALOGUE = ROOT / "resources" / "catalogue"


def test_committed_d04_candidate_assets_match_complete_versioned_operator() -> None:
    affect_bytes = (CATALOGUE / "d04-affect-scheme.json").read_bytes()
    operator_bytes = (CATALOGUE / "d04-fixed-block-operator.json").read_bytes()
    assert (affect_bytes, operator_bytes) == candidate_asset_bytes()
    assert hashlib.sha256(affect_bytes).hexdigest() == (
        "da94af68236cfd509a7330407c094acaf47a3db5633c271bd5a0abafb1409fa3"
    )
    assert hashlib.sha256(operator_bytes).hexdigest() == (
        "37af57ea3d6fa1e5623bf0db51d38c1189123d6569bc982e28ef431137175a8b"
    )

    affect = json.loads(affect_bytes)
    operator = json.loads(operator_bytes)
    model = build_d04_engineering_candidate()
    assert len(affect["axes"]) == DIMENSION == 24
    assert [axis["axis_id"] for axis in affect["axes"]] == list(model.axis_ids)
    assert all(axis["unit"] == "normalized" and axis["meaning"] for axis in affect["axes"])
    assert {axis["axis_id"] for axis in affect["axes"]} == {
        f"{mechanism}:{layer}" for mechanism in MECHANISMS for layer in LAYERS
    }
    assert operator["axis_ids"] == list(model.axis_ids)
    assert operator["parameter_bounds"] == affect["parameter_bounds"]
    assert all(operator[field] == affect[field] for field in (
        "scheme_version", "operator_version", "parameter_version", "coupling_version",
    ))
    assert set(operator["operator"]) == {"k", "r", "j", "a", "alpha"}
    assert operator["operator"]["alpha"] == list(model.alpha)

    # Validate the exact committed bytes against the package builder's asset
    # contract with an in-memory capability declaration. The repository's
    # candidate-only catalogue is left untouched.
    payload = {
        "resources/catalogue/current.json": json.dumps({
            "activation_status": "candidate_only",
            "domain_capabilities": {"d04": ["d04.affect.scheme.v1"]},
        }).encode(),
        "resources/catalogue/d04-affect-scheme.json": affect_bytes,
        "resources/catalogue/d04-fixed-block-operator.json": operator_bytes,
    }
    binding = _d04_binding(payload)
    operator_binding = _d04_operator_binding(payload)
    assert binding["sha256"] == hashlib.sha256(affect_bytes).hexdigest()
    assert operator_binding["sha256"] == hashlib.sha256(operator_bytes).hexdigest()
    assert operator_binding["affect_scheme_sha256"] == binding["sha256"]


def test_committed_catalogue_does_not_activate_candidate() -> None:
    catalogue = json.loads((CATALOGUE / "current.json").read_bytes())
    assert catalogue["activation_status"] == "candidate_only"
    assert catalogue["release_eligibility"].startswith("HOLD:")
    assert "d04.affect.scheme.v1" not in catalogue.get("domain_capabilities", {}).get("d04", [])
