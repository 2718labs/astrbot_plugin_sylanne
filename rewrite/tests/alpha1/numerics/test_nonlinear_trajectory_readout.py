from __future__ import annotations

import ctypes
from decimal import Decimal, localcontext
from pathlib import Path
import platform
import subprocess
import unittest

from sylanne3.native_runtime.arithmetic_report import ReportCSR, ReportInterval


class Step(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32), ("version", ctypes.c_uint32),
        ("n", ctypes.c_uint32), ("k", ReportCSR), ("r", ReportCSR),
        ("j", ReportCSR), ("a", ReportCSR),
        ("alpha", ctypes.POINTER(ctypes.c_double)),
        ("x", ctypes.POINTER(ctypes.c_double)),
        ("y", ctypes.POINTER(ctypes.c_double)),
        ("drive", ctypes.POINTER(ctypes.c_double)), ("h", ctypes.c_double),
    ]


class NonlinearReport(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32), ("version", ctypes.c_uint32),
        ("status", ctypes.c_int32), ("product_certificate_flags", ctypes.c_uint32),
        ("steps_verified", ctypes.c_uint32), ("input_sha256", ctypes.c_ubyte * 32),
        ("final_time_error", ReportInterval),
        ("readout_point", ReportInterval),
        ("readout_enclosure", ReportInterval),
        ("threshold_relation", ctypes.c_int32),
    ]


class NonlinearTrajectoryReadoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native = Path(__file__).resolve().parents[3] / "native"
        subprocess.run(["cargo", "build", "--release", "--locked", "--quiet"],
                       cwd=native, check=True, timeout=120)
        filename = {"Windows": "sylanne3_kernel.dll", "Linux": "libsylanne3_kernel.so",
                    "Darwin": "libsylanne3_kernel.dylib"}[platform.system()]
        library = ctypes.CDLL(str(native / "target" / "release" / filename))
        cls.call = library.sylanne3_v2_trajectory_nonlinear_readout_math_v1
        cls.call.argtypes = [ctypes.POINTER(Step), ctypes.c_uint32, ctypes.c_double,
                             ctypes.POINTER(ctypes.c_double), ReportCSR,
                             ctypes.POINTER(ctypes.c_double), ctypes.c_double,
                             ctypes.POINTER(NonlinearReport), ctypes.c_uint32]
        cls.call.restype = ctypes.c_int32

    def fixture(self):
        offsets = (ctypes.c_uint32 * 2)(0, 1)
        index = (ctypes.c_uint32 * 1)(0)
        one = (ctypes.c_double * 1)(1.0)
        half = (ctypes.c_double * 1)(0.5)
        zero_offsets = (ctypes.c_uint32 * 2)(0, 0)
        scalar = ReportCSR(1, 1, 1, offsets, index, one)
        zero = ReportCSR(1, 1, 0, zero_offsets, None, None)
        state = (ctypes.c_double * 1)(0.0)
        drive = (ctypes.c_double * 1)(0.0)
        steps = (Step * 1)(Step(ctypes.sizeof(Step), 1, 1, scalar, scalar, zero,
                                scalar, half, state, state, drive, 0.001))
        linear = (ctypes.c_double * 1)(0.0)
        beta = (ctypes.c_double * 1)(1.0)
        # Keep every referenced ctypes buffer alive through each FFI call.
        return locals()

    def invoke(self, fixture, initial_error, threshold=0.003, b=None, beta=None):
        report = NonlinearReport()
        rc = self.call(fixture["steps"], 1, initial_error, fixture["linear"],
                       b if b is not None else fixture["scalar"],
                       beta if beta is not None else fixture["beta"], threshold,
                       ctypes.byref(report), ctypes.sizeof(report))
        return rc, report

    def test_nonlinear_threshold_uses_inherited_trajectory_error(self):
        fixture = self.fixture()
        rc, report = self.invoke(fixture, 0.1)
        self.assertEqual(rc, 0)
        self.assertEqual(report.product_certificate_flags, 0)
        self.assertEqual(report.steps_verified, 1)
        self.assertEqual(report.threshold_relation, 0)
        self.assertLessEqual(report.readout_enclosure.lower, 0.0)
        self.assertGreater(report.readout_enclosure.upper, 0.003)
        # Independent scalar comparison: z'=-z-0.5*tanh(z), z(0)=0.1.
        # On [0,0.001], 0<z<=0.1 and z'>=-0.15, hence z_end>=0.09985.
        # log(cosh(z_end)) must lie above the threshold.
        with localcontext() as context:
            context.prec = 70
            lower_z = Decimal("0.09985")
            reference_lower = ((lower_z.exp() + (-lower_z).exp()) / 2).ln()
            self.assertGreater(reference_lower, Decimal("0.003"))
            self.assertGreaterEqual(Decimal.from_float(report.readout_enclosure.upper),
                                    reference_lower)
        digest = bytes(report.input_sha256)

        # The native verifier cannot authenticate the caller's initial box.
        # A false zero claim gives a misleading decisive answer, so production
        # admission must retain the external provenance gate.
        rc, false_premise = self.invoke(fixture, 0.0)
        self.assertEqual(rc, 0)
        self.assertEqual(false_premise.threshold_relation, -1)
        self.assertNotEqual(bytes(false_premise.input_sha256), digest)

        changed_beta = (ctypes.c_double * 1)(2.0)
        rc, changed = self.invoke(fixture, 0.1, beta=changed_beta)
        self.assertEqual(rc, 0)
        self.assertNotEqual(bytes(changed.input_sha256), digest)

    def test_rejects_invalid_readout_and_clears_prior_result(self):
        fixture = self.fixture()
        bad_offsets = (ctypes.c_uint32 * 2)(0, 2)
        bad_b = ReportCSR(1, 1, 1, bad_offsets, fixture["index"], fixture["one"])
        rc, report = self.invoke(fixture, 0.1, b=bad_b)
        self.assertEqual(rc, -2)
        self.assertEqual(report.status, -2)
        self.assertEqual(bytes(report.input_sha256), bytes(32))
        self.assertEqual(report.product_certificate_flags, 0)

        wide_b_value = (ctypes.c_double * 1)(50.0)
        wide_b = ReportCSR(1, 1, 1, fixture["offsets"], fixture["index"], wide_b_value)
        rc, report = self.invoke(fixture, 0.1, b=wide_b)
        self.assertEqual(rc, -2)  # log-cosh argument leaves proved interval domain
        self.assertEqual(report.steps_verified, 0)
        rc, report = self.invoke(fixture, -0.1)
        self.assertEqual(rc, -2)
        self.assertEqual(report.steps_verified, 0)

    def test_signed_nonlinear_weight_encloses_independent_decimal_value(self):
        fixture = self.fixture()
        fixture["state"][0] = 0.5
        fixture["linear"][0] = 0.25
        signed_beta = (ctypes.c_double * 1)(-1.0)
        rc, report = self.invoke(fixture, 0.0, threshold=0.1, beta=signed_beta)
        self.assertEqual(rc, 0)
        self.assertEqual(report.threshold_relation, -1)
        with localcontext() as context:
            context.prec = 70
            z = Decimal("0.5")
            reference = z / 4 - ((z.exp() + (-z).exp()) / 2).ln()
            for interval in (report.readout_point, report.readout_enclosure):
                self.assertLessEqual(Decimal.from_float(interval.lower), reference)
                self.assertGreaterEqual(Decimal.from_float(interval.upper), reference)


if __name__ == "__main__":
    unittest.main()
