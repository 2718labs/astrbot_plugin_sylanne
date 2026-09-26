"""Checkpoint-pinned candidate readout bytes and fail-closed schema checks."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, SCHEME_VERSION
from sylanne3.domains.d04.root import RootAssetBindings
from sylanne3.native_runtime.d04_tanh_readout_asset import (
    ASSET_NAME, D04TanhReadoutAssetUnavailable, TRANSFORM,
    load_d04_tanh_readout_asset,
)


CATALOGUE_ASSET = Path(__file__).resolve().parents[4] / "resources" / "catalogue" / ASSET_NAME
READOUT_ID = "d04-24d-tanh-identity"


def _bindings(raw: bytes) -> RootAssetBindings:
    return RootAssetBindings(
        SCHEME_VERSION, "operator:v1", "parameter:v1", "coupling:v1",
        "candidate:d04-24d-chain:tanh-readout:1",
        "a" * 64, "b" * 64, "c" * 64, "d" * 64,
        hashlib.sha256(raw).hexdigest(),
    )


def _write(root: Path, value: dict) -> bytes:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (root / ASSET_NAME).write_bytes(raw)
    return raw


def test_committed_identity_asset_loads_as_candidate(tmp_path: Path) -> None:
    raw = CATALOGUE_ASSET.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == (
        "5d56a8de7a98c9792bc850cbd7b62a2a77d0b75e31a0ec02138e5640937d6004"
    )
    (tmp_path / ASSET_NAME).write_bytes(raw)
    loaded = load_d04_tanh_readout_asset(
        tmp_path, _bindings(raw), expected_readout_id=READOUT_ID,
    )
    assert loaded.status == "asset_loaded_candidate"
    assert loaded.asset_sha256 == hashlib.sha256(raw).hexdigest()
    assert loaded.axis_ids == REGISTERED_AXIS_IDS
    assert len(loaded.rows) == 24
    assert len({row.output_id for row in loaded.rows}) == 24
    for index, row in enumerate(loaded.rows):
        assert row.output_id == f"p:{REGISTERED_AXIS_IDS[index]}"
        assert row.axis_id == REGISTERED_AXIS_IDS[index]
        assert row.unit == "normalized" and row.transform == TRANSFORM
        assert row.output_version == loaded.readout_version
        assert row.coefficients == tuple(float(index == column) for column in range(24))


def test_rejects_wrong_checkpoint_hash(tmp_path: Path) -> None:
    raw = CATALOGUE_ASSET.read_bytes()
    (tmp_path / ASSET_NAME).write_bytes(raw)
    with pytest.raises(D04TanhReadoutAssetUnavailable, match="SHA-256"):
        load_d04_tanh_readout_asset(
            tmp_path, replace(_bindings(raw), readout_sha256="0" * 64),
            expected_readout_id=READOUT_ID,
        )


def test_rejects_wrong_axis_even_when_hash_matches(tmp_path: Path) -> None:
    value = json.loads(CATALOGUE_ASSET.read_bytes())
    value["axis_ids"][0], value["axis_ids"][1] = value["axis_ids"][1], value["axis_ids"][0]
    raw = _write(tmp_path, value)
    with pytest.raises(D04TanhReadoutAssetUnavailable, match="axes"):
        load_d04_tanh_readout_asset(
            tmp_path, _bindings(raw), expected_readout_id=READOUT_ID,
        )


def test_rejects_legacy_single_output_replacement_even_when_hash_matches(tmp_path: Path) -> None:
    value = json.loads(CATALOGUE_ASSET.read_bytes())
    value["outputs"] = value["outputs"][:1]
    raw = _write(tmp_path, value)
    with pytest.raises(D04TanhReadoutAssetUnavailable, match="24 output"):
        load_d04_tanh_readout_asset(
            tmp_path, _bindings(raw), expected_readout_id=READOUT_ID,
        )


def test_rejects_nonmonotone_or_linear_row_even_when_hash_matches(tmp_path: Path) -> None:
    value = json.loads(CATALOGUE_ASSET.read_bytes())
    value["outputs"][0]["coefficients"][0] = -1
    raw = _write(tmp_path, value)
    with pytest.raises(D04TanhReadoutAssetUnavailable, match="monotone"):
        load_d04_tanh_readout_asset(
            tmp_path, _bindings(raw), expected_readout_id=READOUT_ID,
        )
    value["outputs"][0]["coefficients"][0] = 1
    value["outputs"][0]["transform"] = "c*z"
    raw = _write(tmp_path, value)
    with pytest.raises(D04TanhReadoutAssetUnavailable, match="mapping"):
        load_d04_tanh_readout_asset(
            tmp_path, _bindings(raw), expected_readout_id=READOUT_ID,
        )
