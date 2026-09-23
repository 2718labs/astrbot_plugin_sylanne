"""Candidate-only D04 asset generation and packager-shape compatibility."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[4] / "scripts" / "alpha1" / "generate_d04_candidate_assets.py"


def _generator():
    spec = importlib.util.spec_from_file_location("generate_d04_candidate_assets", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_d04_assets_are_deterministic_candidates_outside_release_tree(tmp_path: Path) -> None:
    generator = _generator()
    destination = tmp_path / "candidate"
    first = generator.write_candidate_assets(destination)
    contents = tuple(path.read_bytes() for path in first)
    assert first == generator.write_candidate_assets(destination)
    assert contents == generator.candidate_asset_bytes()
    assert all("candidate" in path.name for path in first)

    scheme, operator = (json.loads(content) for content in contents)
    assert len(scheme["axes"]) == 24
    assert all(value.startswith("candidate:") for value in (
        scheme["scheme_version"], scheme["operator_version"],
        scheme["parameter_version"], scheme["coupling_version"],
    ))
    assert operator["axis_ids"] == [axis["axis_id"] for axis in scheme["axes"]]
    assert operator["parameter_bounds"] == scheme["parameter_bounds"]
    assert operator["operator"]["k"]["rows"] == 24
    assert operator["operator"]["alpha"] == [0.25] * 24
    assert not (destination / "current.json").exists()

    release_resources = SCRIPT.parents[2] / "resources" / "catalogue"
    with pytest.raises(ValueError, match="release resources"):
        generator.write_candidate_assets(release_resources)
