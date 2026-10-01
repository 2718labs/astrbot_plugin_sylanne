"""Narrow binary64 gates for the conditional joint-state output issuer."""

from dataclasses import replace
from fractions import Fraction
import json
import math
from pathlib import Path
import unittest

from sylanne3.domains.d04.joint_state_output_v1 import (
    JointStateOutputHold, JointStateOutputPolicyV1,
    _axis_output, _identity_readout, _latent_box,
)
from sylanne3.native_runtime.d04_tanh_readout_asset import (
    D04LoadedTanhReadoutAsset, D04TanhReadoutRow,
)
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS


class JointStateOutputNumericsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[4]
        data = json.loads((root / "resources/catalogue/"
                           "d04-joint-state-output-policy.v1.json").read_text())
        cls.policy = JointStateOutputPolicyV1(
            **{**data, "axis_ids": tuple(data["axis_ids"])},
        )

    def test_exact_rational_midpoint_tie_and_zero_width(self):
        adjacent = math.nextafter(0.5, math.inf)
        row = _axis_output(REGISTERED_AXIS_IDS[0], "output:0", 0.5,
                           adjacent, 1.0)
        self.assertEqual(row.representative, 0.5)
        self.assertEqual(row.representative_error, adjacent - 0.5)
        exact = _axis_output(REGISTERED_AXIS_IDS[1], "output:1", 0.5,
                             0.5, 1.0)
        self.assertEqual((exact.representative, exact.representative_error),
                         (0.5, 0.0))
        with self.assertRaisesRegex(JointStateOutputHold, "exceeds policy"):
            _axis_output(REGISTERED_AXIS_IDS[0], "output:0", -1.0, 1.0,
                         self.policy.max_readout_interval_width)

    def test_latent_box_is_outward_and_never_clipped(self):
        error = math.ldexp(1.0, -53)
        boxes, scalar = _latent_box((0.5,) * 24, error, self.policy)
        self.assertEqual(len(boxes), 24)
        self.assertTrue(all(low <= 0.5 <= high for low, high in boxes))
        exact = sum((max(Fraction.from_float(0.5) - Fraction.from_float(low),
                         Fraction.from_float(high) - Fraction.from_float(0.5)) ** 2
                     for low, high in boxes), Fraction())
        self.assertGreaterEqual(Fraction.from_float(scalar) ** 2, exact)
        with self.assertRaisesRegex(JointStateOutputHold, r"leaves \[0, 4\]"):
            _latent_box((0.0,) * 24, error, self.policy)

    def test_exact_identity_tanh_matrix_is_required(self):
        rows = tuple(D04TanhReadoutRow(
            f"output:{index}", axis, "normalized",
            self.policy.readout_version, "p=C*tanh(z)",
            tuple(float(position == index) for position in range(24)),
        ) for index, axis in enumerate(REGISTERED_AXIS_IDS))
        asset = D04LoadedTanhReadoutAsset(
            self.policy.readout_id, self.policy.readout_version,
            "scheme:one", REGISTERED_AXIS_IDS, ("normalized",) * 24,
            rows, self.policy.readout_sha256,
        )
        _identity_readout(type("Replay", (), {"readout": asset})(), self.policy)
        changed = replace(rows[0], coefficients=(0.5, 0.5) + (0.0,) * 22)
        with self.assertRaisesRegex(JointStateOutputHold, "exact identity"):
            _identity_readout(type("Replay", (), {
                "readout": replace(asset, rows=(changed,) + rows[1:]),
            })(), self.policy)


if __name__ == "__main__":
    unittest.main()
