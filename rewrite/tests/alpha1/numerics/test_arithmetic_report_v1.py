from __future__ import annotations

import ctypes
import math
from pathlib import Path
import platform
import subprocess
import unittest

from sylanne3.native_runtime.arithmetic_report import (
    ArithmeticReportLibrary, RawArithmeticReport, ReportInput,
    parse_arithmetic_report,
)


class ArithmeticReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native = Path(__file__).resolve().parents[3] / "native"
        subprocess.run(["cargo", "build", "--release", "--locked", "--quiet"],
                       cwd=native, check=True, timeout=120)
        root = native / "target" / "release"
        filename = {"Windows": "sylanne3_kernel.dll", "Linux": "libsylanne3_kernel.so",
                    "Darwin": "libsylanne3_kernel.dylib"}[platform.system()]
        cls.library = ctypes.CDLL(str(root / filename))
        cls.reporter = ArithmeticReportLibrary(cls.library)

    def args(self):
        return dict(n=1, k=((0, 1), (0,), (2.0,)),
                    r=((0, 1), (0,), (1.0,)), j=((0, 0), (), ()),
                    a=((0,), (), ()), alpha=(), x=(0.4,), y=(0.35,),
                    drive=(0.0,), readout=(2.0,), h=0.1,
                    inherited_error_upper=0.0, threshold=0.7)

    def test_energy_ledger_readout_and_input_binding(self):
        report = self.reporter.report(**self.args())
        ledger = report.intervals
        for name, value in (("energy_difference", -0.0375),
                            ("gradient_displacement", -0.0375),
                            ("dissipation", -0.05625),
                            ("drive_work", 0.0),
                            ("residual_work", 0.01875),
                            ("gradient_identity_defect", 0.0),
                            ("energy_balance_defect", 0.0)):
            self.assertLessEqual(ledger[name][0], value, name)
            self.assertGreaterEqual(ledger[name][1], value, name)
        self.assertEqual(report.threshold_relation, 0)
        self.assertFalse(report.product_certified)
        changed = self.args()
        changed["threshold"] = 1.0
        other = self.reporter.report(**changed)
        self.assertNotEqual(report.input_sha256, other.input_sha256)
        self.assertEqual(other.threshold_relation, -1)

    def test_failure_and_cancel_cannot_reuse_success(self):
        self.reporter.report(**self.args())
        bad = self.args()
        bad["x"] = (float("nan"),)
        with self.assertRaises(ArithmeticError):
            self.reporter.report(**bad)
        bad["x"] = (float("inf"),)
        with self.assertRaises(ArithmeticError):
            self.reporter.report(**bad)
        with self.assertRaises(ArithmeticError):
            self.reporter.report(**self.args(), cancelled=True)

    def test_near_equal_nonlinearity_and_full_coupling(self):
        near = self.args()
        near["a"] = ((0, 1), (0,), (0.5,))
        near["alpha"] = (0.2,)
        near["x"] = (0.25,)
        near["y"] = (math.nextafter(0.25, 1.0),)
        self.assertTrue(math.isfinite(self.reporter.report(**near).intervals["energy_difference"][1]))

        coupled = dict(n=2, k=((0, 1, 2), (0, 1), (1.0, 1.0)),
                       r=((0, 1, 2), (0, 1), (1.0, 1.0)),
                       j=((0, 1, 2), (1, 0), (-2.0, 2.0)),
                       a=((0,), (), ()), alpha=(), x=(0.2, 0.0),
                       y=(0.2, 0.0), drive=(0.0, 0.0),
                       readout=(1.0, 0.0), h=0.1,
                       inherited_error_upper=0.0, threshold=0.2)
        report = self.reporter.report(**coupled)
        self.assertGreater(report.intervals["residual_norm"][1], 0.03)

    def test_layout_and_parser_fail_closed(self):
        raw = RawArithmeticReport()
        raw.struct_size = ctypes.sizeof(raw)
        raw.version = 1
        raw.status = 0
        raw.input_sha256[:] = b"x" * 32
        with self.assertRaises(ValueError):
            parse_arithmetic_report(raw, b"y" * 32)
        raw.version = 2
        with self.assertRaises(ValueError):
            parse_arithmetic_report(raw, b"x" * 32)
        raw.version = 1
        raw.status = -3
        with self.assertRaises(ValueError):
            parse_arithmetic_report(raw, b"x" * 32)
        raw_input = ReportInput()
        self.assertEqual(self.reporter._call(ctypes.byref(raw_input),
                                             ctypes.sizeof(raw_input) - 1,
                                             ctypes.byref(raw), ctypes.sizeof(raw)), -1)
        self.assertEqual(raw.status, -1)


if __name__ == "__main__":
    unittest.main()
