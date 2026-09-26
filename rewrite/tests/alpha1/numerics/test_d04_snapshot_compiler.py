"""A fixed-chain compiler cannot silently drop supplied numeric coupling."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import inspect
import json
from pathlib import Path
import struct

import pytest

from sylanne3.native_runtime import d04_snapshot_compiler as compiler
from sylanne3.native_runtime.d04_engineering_scheme import build_d04_engineering_candidate


ROOT = Path(__file__).resolve().parents[4]
AFFECT = (ROOT / "resources/catalogue/d04-affect-scheme.json").read_bytes()
OPERATOR = (ROOT / "resources/catalogue/d04-fixed-block-operator.json").read_bytes()
AXES = build_d04_engineering_candidate().axis_ids


def rows() -> tuple[compiler.D04NumericTopologyRow, ...]:
    return tuple(compiler.D04NumericTopologyRow(axis, ()) for axis in AXES)


def arguments() -> dict:
    return dict(
        affect_template=AFFECT,
        operator_template=OPERATOR,
        graph_version="graph:17",
        topology_rows=rows(),
        external_numeric_nodes=(),
        initial_state=(0.25,) * 24,
        drive=(0.125,) * 24,
        readout=(1.0,) + (0.0,) * 23,
    )


def test_exact_template_compiles_deterministically_with_field_digests() -> None:
    assert hashlib.sha256(AFFECT).hexdigest() == compiler.AFFECT_SHA256
    assert hashlib.sha256(OPERATOR).hexdigest() == compiler.OPERATOR_SHA256
    result = compiler.compile_d04_fixed_chain_snapshot_candidate(**arguments())
    assert result == compiler.compile_d04_fixed_chain_snapshot_candidate(**arguments())
    assert result.axis_ids == AXES
    assert result.schema == "d04.fixed-chain-snapshot-candidate.v1"
    model = build_d04_engineering_candidate()
    assert (result.k, result.r, result.j, result.a, result.alpha) == (
        model.k, model.r, model.j, model.a, model.alpha,
    )
    digests = dict(result.field_sha256)
    assert set(digests) == {
        "affect_template", "operator_template", "axis_ids", "parameter_bounds",
        "topology", "k", "r", "j", "a", "alpha", "initial_state", "drive", "readout",
    }
    # Independent byte-level check of one field's binary64 digest contract.
    payload = struct.pack("<Q", 24) + struct.pack("<24d", *result.initial_state)
    name = b"initial_state"
    expected = hashlib.sha256(
        b"sylanne3-d04-snapshot-field-v1\0"
        + struct.pack("<Q", 1) + struct.pack("<Q", len(name)) + name + payload
    ).hexdigest()
    assert digests["initial_state"] == expected
    assert "boundary_eta" not in inspect.signature(
        compiler.compile_d04_fixed_chain_snapshot_candidate,
    ).parameters
    assert not hasattr(result, "product_certificate_flags")


@pytest.mark.parametrize("field,changed", (
    ("initial_state", (0.5,) + (0.25,) * 23),
    ("drive", (0.25,) + (0.125,) * 23),
    ("readout", (0.0, 1.0) + (0.0,) * 22),
    ("graph_version", "graph:18"),
))
def test_input_change_changes_relevant_digest(field: str, changed: object) -> None:
    baseline = compiler.compile_d04_fixed_chain_snapshot_candidate(**arguments())
    input_values = arguments()
    input_values[field] = changed
    revised = compiler.compile_d04_fixed_chain_snapshot_candidate(**input_values)
    assert revised.snapshot_sha256 != baseline.snapshot_sha256
    expected_field = "topology" if field == "graph_version" else field
    assert dict(revised.field_sha256)[expected_field] != dict(baseline.field_sha256)[expected_field]


@pytest.mark.parametrize("topology", (
    rows()[:-1],
    rows() + (rows()[0],),
    (rows()[1], rows()[0]) + rows()[2:],
    (replace(rows()[0], additional_targets=(AXES[1],)),) + rows()[1:],
))
def test_missing_duplicate_reordered_or_added_coupling_row_is_held(topology) -> None:
    values = arguments()
    values["topology_rows"] = topology
    with pytest.raises(compiler.D04SnapshotHold):
        compiler.compile_d04_fixed_chain_snapshot_candidate(**values)


def test_external_numeric_node_is_held() -> None:
    values = arguments()
    values["external_numeric_nodes"] = ("other-source:latent",)
    with pytest.raises(compiler.D04SnapshotHold, match="external node"):
        compiler.compile_d04_fixed_chain_snapshot_candidate(**values)


@pytest.mark.parametrize("field,invalid", (
    ("initial_state", (5.0,) + (0.25,) * 23),
    ("drive", (float("nan"),) + (0.125,) * 23),
    ("readout", (float("inf"),) + (0.0,) * 23),
    ("initial_state", (True,) + (0.25,) * 23),
))
def test_invalid_numeric_input_is_held(field: str, invalid: tuple) -> None:
    values = arguments()
    values[field] = invalid
    with pytest.raises(compiler.D04SnapshotHold):
        compiler.compile_d04_fixed_chain_snapshot_candidate(**values)


def test_template_byte_tamper_is_held_even_when_json_still_parses() -> None:
    values = arguments()
    values["operator_template"] = OPERATOR + b" "
    with pytest.raises(compiler.D04SnapshotHold, match="digest mismatch"):
        compiler.compile_d04_fixed_chain_snapshot_candidate(**values)


@pytest.mark.parametrize("asset,mutate,match", (
    ("affect_template", lambda obj: obj["axes"].reverse(), "axis order"),
    ("operator_template", lambda obj: obj["parameter_bounds"][0].__setitem__(1, 0.25),
     "parameter bounds"),
))
def test_semantic_checks_reject_axis_or_parameter_drift_even_with_updated_digest(
    monkeypatch, asset, mutate, match,
) -> None:
    values = arguments()
    object_data = json.loads(values[asset])
    mutate(object_data)
    changed = json.dumps(object_data, sort_keys=True, separators=(",", ":")).encode()
    values[asset] = changed
    digest_constant = "AFFECT_SHA256" if asset == "affect_template" else "OPERATOR_SHA256"
    monkeypatch.setattr(compiler, digest_constant, hashlib.sha256(changed).hexdigest())
    with pytest.raises(compiler.D04SnapshotHold, match=match):
        compiler.compile_d04_fixed_chain_snapshot_candidate(**values)
