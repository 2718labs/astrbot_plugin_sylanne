"""Fixture assets exercise loader checks, not product readout admission."""

from dataclasses import replace
import hashlib

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, SCHEME_VERSION
from sylanne3.domains.d04.root import RootAssetBindings
from sylanne3.native_runtime.d04_readout_asset import (
    ASSET_NAME, D04ReadoutAssetUnavailable, load_d04_readout_asset,
)


def _value():
    return {
        "schema": "d04.linear-readout-asset.v1", "readout_id": "feeling:calm",
        "readout_version": "readout:1", "scheme_version": SCHEME_VERSION,
        "output_id": "calmness", "output_unit": "normalized",
        "axis_ids": list(REGISTERED_AXIS_IDS), "axis_units": ["normalized"] * 24,
        "coefficients": [0.125] * 24,
    }


def _bindings(digest):
    return RootAssetBindings(
        SCHEME_VERSION, "operator:1", "parameters:1", "coupling:1", "readout:1",
        "a" * 64, "b" * 64, "c" * 64, "d" * 64, digest,
    )


def _load(root, bindings, **changes):
    target = {"expected_readout_id": "feeling:calm", "expected_output_id": "calmness"}
    target.update(changes)
    return load_d04_readout_asset(root, bindings, **target)


def test_missing_real_asset_fails_closed(tmp_path):
    with pytest.raises(D04ReadoutAssetUnavailable, match="absent"):
        _load(tmp_path, _bindings("e" * 64))


def test_hash_pinned_fixture_loads_only_matching_24d_mapping(tmp_path):
    raw = canonical_json(_value()).encode("utf-8")
    (tmp_path / ASSET_NAME).write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    loaded = _load(tmp_path, _bindings(digest))
    assert loaded.coefficients == (0.125,) * 24
    assert loaded.axis_ids == REGISTERED_AXIS_IDS
    assert loaded.status == "asset_loaded_candidate"
    with pytest.raises(D04ReadoutAssetUnavailable, match="SHA-256"):
        _load(tmp_path, _bindings("f" * 64))
    with pytest.raises(D04ReadoutAssetUnavailable, match="version"):
        _load(tmp_path, replace(_bindings(digest), readout_version="readout:2"))
    with pytest.raises(D04ReadoutAssetUnavailable, match="mapping"):
        _load(tmp_path, _bindings(digest), expected_output_id="another_target")


def test_hash_matching_wrong_axis_and_duplicate_fields_still_fail(tmp_path):
    bad = _value()
    bad["axis_ids"] = list(reversed(REGISTERED_AXIS_IDS))
    raw = canonical_json(bad).encode("utf-8")
    (tmp_path / ASSET_NAME).write_bytes(raw)
    with pytest.raises(D04ReadoutAssetUnavailable, match="axes"):
        _load(tmp_path, _bindings(hashlib.sha256(raw).hexdigest()))
    duplicate = b'{"schema":"d04.linear-readout-asset.v1","schema":"bad"}'
    (tmp_path / ASSET_NAME).write_bytes(duplicate)
    with pytest.raises(D04ReadoutAssetUnavailable, match="repeats"):
        _load(tmp_path, _bindings(hashlib.sha256(duplicate).hexdigest()))
