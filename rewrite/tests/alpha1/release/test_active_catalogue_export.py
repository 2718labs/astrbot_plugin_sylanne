"""An explicit D04 asset can describe real registrations without claiming release readiness."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.alpha1.generate_catalogue import export
from rewrite.tools.build_plugin_package import _d04_binding
from sylanne3.domain_registry import discover_domain_registry
from sylanne3.domains.d04 import AffectAxis, AffectScheme


def test_active_scheme_export_matches_runtime_registry_and_remains_hold(tmp_path: Path) -> None:
    asset = {
        "schema": "d04.affect.scheme.v1",
        "scheme_version": "fixture:scheme:1",
        "operator_version": "fixture:operator:1",
        "parameter_version": "fixture:parameter:1",
        "coupling_version": "fixture:coupling:1",
        "axes": [{"axis_id": "fixture:axis:1", "unit": "normalized", "meaning": "fixture only"}],
        "parameter_bounds": [],
    }
    path = tmp_path / "fixture-scheme.json"
    path.write_text(json.dumps(asset), encoding="utf-8")
    output = tmp_path / "catalogue.json"
    export([], output, allow_incomplete=False,
           expected_domains=tuple(f"d{index:02d}" for index in range(1, 13)),
           active_affect_scheme_path=path)
    document = json.loads(output.read_text(encoding="utf-8"))
    runtime = discover_domain_registry(active_affect_scheme=AffectScheme(
        schema=asset["schema"], scheme_version=asset["scheme_version"],
        operator_version=asset["operator_version"], parameter_version=asset["parameter_version"],
        coupling_version=asset["coupling_version"],
        axes=(AffectAxis(**asset["axes"][0]),), parameter_bounds=(),
    ))
    assert runtime.complete
    assert document["catalogue_hash"] == runtime.type_registry.catalogue_hash
    assert {row["name"] for row in document["types"]} == {spec.name for spec in runtime.type_registry.specs}
    assert "d11.owner_grant.v1" in {row["name"] for row in document["types"]}
    assert document["domain_capabilities"] == {"d04": ["d04.affect.scheme.v1"]}
    assert document["activation_status"] == "candidate_only"
    assert document["release_eligibility"].startswith("HOLD:")
    binding = _d04_binding({
        "resources/catalogue/current.json": output.read_bytes(),
        "resources/catalogue/d04-affect-scheme.json": path.read_bytes(),
    })
    assert binding["scheme_version"] == asset["scheme_version"]
    assert binding["catalogue_capability"] == asset["schema"]


def test_active_scheme_export_rejects_duplicate_asset_fields(tmp_path: Path) -> None:
    path = tmp_path / "invalid-scheme.json"
    path.write_text('{"schema":"d04.affect.scheme.v1","schema":"duplicate"}', encoding="utf-8")
    try:
        export([], tmp_path / "catalogue.json", allow_incomplete=False,
               expected_domains=(), active_affect_scheme_path=path)
    except ValueError as exc:
        assert "duplicate D04 scheme field" in str(exc)
    else:
        raise AssertionError("duplicate asset field was accepted")
    assert not (tmp_path / "catalogue.json").exists()
