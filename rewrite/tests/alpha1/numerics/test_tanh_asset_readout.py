"""Conditional matrix readout checks with actual checkpoint-pinned candidate bytes."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal, localcontext
from fractions import Fraction
import hashlib
import json
from pathlib import Path

import pytest

from sylanne3.domains.d04.numeric_coupling import SCHEME_VERSION
from sylanne3.domains.d04.root import RootAssetBindings
from sylanne3.native_runtime.d04_tanh_readout_asset import (
    ASSET_NAME, load_d04_tanh_readout_asset,
)
from sylanne3.native_runtime.tanh_asset_readout import (
    run_d04_conditional_tanh_readout_math,
)


CATALOGUE_ASSET = Path(__file__).resolve().parents[4] / "resources" / "catalogue" / ASSET_NAME
READOUT_ID = "d04-24d-tanh-identity"


def _load(tmp_path: Path, raw: bytes):
    (tmp_path / ASSET_NAME).write_bytes(raw)
    payload = json.loads(raw)
    bindings = RootAssetBindings(
        SCHEME_VERSION, "operator:v1", "parameter:v1", "coupling:v1",
        payload["readout_version"],
        "a" * 64, "b" * 64, "c" * 64, "d" * 64,
        hashlib.sha256(raw).hexdigest(),
    )
    return load_d04_tanh_readout_asset(
        tmp_path, bindings, expected_readout_id=READOUT_ID,
    )


def test_identity_asset_preserves_24_conditional_marginals(tmp_path: Path) -> None:
    asset = _load(tmp_path, CATALOGUE_ASSET.read_bytes())
    centers = (2.0,) * 24
    result = run_d04_conditional_tanh_readout_math(asset, centers, 0.1)
    assert result.status == "conditional_math_only"
    assert result.asset_sha256 == asset.asset_sha256
    assert result.readout_id == asset.readout_id
    assert result.state_centers == centers and result.state_error_2norm == 0.1
    assert len(result.outputs) == 24
    for output, row, marginal in zip(result.outputs, asset.rows, result.tanh_marginals):
        assert (output.output_id, output.axis_id) == (row.output_id, row.axis_id)
        assert (output.lower, output.upper) == marginal


def test_mixed_rows_use_exact_products_and_outward_final_rounding(tmp_path: Path) -> None:
    payload = json.loads(CATALOGUE_ASSET.read_bytes())
    payload["outputs"][0]["coefficients"] = [0.3, 0.7] + [0] * 22
    payload["outputs"][1]["coefficients"] = [0.1, 0.2, 0.3] + [0] * 21
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    asset = _load(tmp_path, raw)
    result = run_d04_conditional_tanh_readout_math(asset, (0.1,) * 24, 0.0)
    assert result.asset_sha256 == hashlib.sha256(raw).hexdigest()

    exact_row_bounds = []
    for index in (0, 1):
        weights = asset.rows[index].coefficients
        exact_lower = sum((Fraction.from_float(weight) * Fraction.from_float(bounds[0])
                           for weight, bounds in zip(weights, result.tanh_marginals)), Fraction())
        exact_upper = sum((Fraction.from_float(weight) * Fraction.from_float(bounds[1])
                           for weight, bounds in zip(weights, result.tanh_marginals)), Fraction())
        exact_row_bounds.append((exact_lower, exact_upper))
        output = result.outputs[index]
        assert Fraction.from_float(output.lower) <= exact_lower
        assert Fraction.from_float(output.upper) >= exact_upper
        assert output.output_id == asset.rows[index].output_id
        with localcontext() as context:
            context.prec = 110
            x = (2 * Decimal.from_float(0.1)).exp()
            reference = (x - 1) / (x + 1)
            reference *= sum(Decimal.from_float(weight) for weight in weights)
            assert Decimal.from_float(output.lower) <= reference <= Decimal.from_float(output.upper)

    # Ordinary binary64 arithmetic rounds inward on these two legal rows.
    lower_naive = sum(weight * result.tanh_marginals[column][0]
                      for column, weight in enumerate(asset.rows[0].coefficients))
    upper_naive = sum(weight * result.tanh_marginals[column][1]
                      for column, weight in enumerate(asset.rows[1].coefficients))
    assert Fraction.from_float(lower_naive) > exact_row_bounds[0][0]
    assert Fraction.from_float(upper_naive) < exact_row_bounds[1][1]
    assert result.outputs[0].lower < lower_naive
    assert result.outputs[1].upper > upper_naive


def test_rejects_nonmonotone_row_even_if_loaded_dto_is_replaced(tmp_path: Path) -> None:
    asset = _load(tmp_path, CATALOGUE_ASSET.read_bytes())
    bad_row = replace(asset.rows[0], coefficients=(-0.1,) + asset.rows[0].coefficients[1:])
    bad_asset = replace(asset, rows=(bad_row,) + asset.rows[1:])
    with pytest.raises(ValueError, match="nonnegative"):
        run_d04_conditional_tanh_readout_math(bad_asset, (2.0,) * 24, 0.0)
