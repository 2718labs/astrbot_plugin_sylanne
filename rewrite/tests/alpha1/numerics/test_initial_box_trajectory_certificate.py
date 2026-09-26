from __future__ import annotations

import ctypes
from decimal import Decimal, localcontext
import hashlib
from pathlib import Path
import platform
import struct
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


class TrajectoryReport(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32), ("version", ctypes.c_uint32),
        ("status", ctypes.c_int32), ("product_certificate_flags", ctypes.c_uint32),
        ("steps_verified", ctypes.c_uint32), ("input_sha256", ctypes.c_ubyte * 32),
        ("final_time_error", ReportInterval),
        ("max_endpoint_error", ReportInterval),
        ("max_reconstruction_defect", ReportInterval),
    ]


class BoxReadoutReport(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32), ("version", ctypes.c_uint32),
        ("status", ctypes.c_int32), ("product_certificate_flags", ctypes.c_uint32),
        ("steps_verified", ctypes.c_uint32), ("input_sha256", ctypes.c_ubyte * 32),
        ("initial_error", ReportInterval),
        ("final_time_error", ReportInterval),
        ("readout_point", ReportInterval),
        ("readout_enclosure", ReportInterval),
        ("threshold_relation", ctypes.c_int32),
    ]


class InitialBoxTrajectoryCertificateTests(unittest.TestCase):
    @staticmethod
    def box_digest(nominal, lower, upper):
        digest = hashlib.sha256(b"sylanne3-initial-box-math-v1\0")
        for values in (nominal, lower, upper):
            digest.update(struct.pack("<Q", len(values)))
            for value in values:
                digest.update(struct.pack("<d", value))
        return (ctypes.c_ubyte * 32).from_buffer_copy(digest.digest())

    @classmethod
    def setUpClass(cls):
        native = Path(__file__).resolve().parents[3] / "native"
        subprocess.run(["cargo", "build", "--release", "--locked", "--quiet"],
                       cwd=native, check=True, timeout=120)
        filename = {"Windows": "sylanne3_kernel.dll", "Linux": "libsylanne3_kernel.so",
                    "Darwin": "libsylanne3_kernel.dylib"}[platform.system()]
        library = ctypes.CDLL(str(native / "target" / "release" / filename))
        cls.trajectory = library.sylanne3_v2_trajectory_math_report_from_box_v1
        cls.trajectory.argtypes = [ctypes.POINTER(Step), ctypes.c_uint32,
                                   ctypes.POINTER(ctypes.c_double),
                                   ctypes.POINTER(ctypes.c_double),
                                   ctypes.POINTER(ctypes.c_ubyte),
                                   ctypes.POINTER(TrajectoryReport), ctypes.c_uint32]
        cls.trajectory.restype = ctypes.c_int32
        cls.readout = library.sylanne3_v2_trajectory_nonlinear_readout_from_box_math_v1
        cls.readout.argtypes = [ctypes.POINTER(Step), ctypes.c_uint32,
                                ctypes.POINTER(ctypes.c_double),
                                ctypes.POINTER(ctypes.c_double),
                                ctypes.POINTER(ctypes.c_ubyte),
                                ctypes.POINTER(ctypes.c_double), ReportCSR,
                                ctypes.POINTER(ctypes.c_double), ctypes.c_double,
                                ctypes.POINTER(BoxReadoutReport), ctypes.c_uint32]
        cls.readout.restype = ctypes.c_int32

    def fixture(self):
        offsets = (ctypes.c_uint32 * 2)(0, 1)
        indices = (ctypes.c_uint32 * 1)(0)
        one = (ctypes.c_double * 1)(1.0)
        empty_offsets = (ctypes.c_uint32 * 2)(0, 0)
        no_rows_offsets = (ctypes.c_uint32 * 1)(0)
        scalar = ReportCSR(1, 1, 1, offsets, indices, one)
        zero = ReportCSR(1, 1, 0, empty_offsets, None, None)
        no_nonlinear = ReportCSR(0, 1, 0, no_rows_offsets, None, None)
        x = (ctypes.c_double * 1)(1.0)
        h = 0.1
        y = (ctypes.c_double * 1)((1 - h / 2) / (1 + h / 2))
        drive = (ctypes.c_double * 1)(0.0)
        steps = (Step * 1)(Step(ctypes.sizeof(Step), 1, 1, scalar, scalar, zero,
                                no_nonlinear, None, x, y, drive, h))
        lower = (ctypes.c_double * 1)(0.9)
        upper = (ctypes.c_double * 1)(1.1)
        linear = (ctypes.c_double * 1)(0.0)
        beta = (ctypes.c_double * 1)(1.0)
        return locals()  # retains all C buffers referenced by structures

    def call_readout(self, f, lower=None, upper=None, steps=None, count=1, expected=None):
        report = BoxReadoutReport()
        lo = lower if lower is not None else f["lower"]
        hi = upper if upper is not None else f["upper"]
        digest = expected if expected is not None else self.box_digest(f["x"], lo, hi)
        rc = self.readout(steps if steps is not None else f["steps"], count,
                          lo, hi, digest,
                          f["linear"], f["scalar"], f["beta"], 0.4,
                          ctypes.byref(report), ctypes.sizeof(report))
        return rc, report

    def test_box_corners_enclose_independent_continuous_solution_and_readout(self):
        f = self.fixture()
        rc, report = self.call_readout(f)
        self.assertEqual(rc, 0)
        self.assertEqual(report.product_certificate_flags, 0)
        self.assertEqual(report.steps_verified, 1)
        self.assertGreaterEqual(report.initial_error.upper, 0.1)
        self.assertEqual(report.threshold_relation, 0)
        with localcontext() as context:
            context.prec = 70
            d = Decimal.from_float
            nominal = d(f["y"][0])
            for initial in (d(f["lower"][0]), d(f["upper"][0])):
                true_end = initial * (-Decimal("0.1")).exp()
                self.assertLessEqual(abs(true_end - nominal), d(report.final_time_error.upper))
                readout = ((true_end.exp() + (-true_end).exp()) / 2).ln()
                self.assertLessEqual(d(report.readout_enclosure.lower), readout)
                self.assertGreaterEqual(d(report.readout_enclosure.upper), readout)
            high_end = d(f["upper"][0]) * (-Decimal("0.1")).exp()
            high_readout = ((high_end.exp() + (-high_end).exp()) / 2).ln()
            self.assertGreater(high_readout, Decimal("0.4"))
        digest = bytes(report.input_sha256)

        changed_lower = (ctypes.c_double * 1)(0.89)
        trusted_digest = self.box_digest(f["x"], f["lower"], f["upper"])
        rc, tampered = self.call_readout(f, lower=changed_lower, expected=trusted_digest)
        self.assertEqual(rc, -2)
        self.assertEqual(tampered.steps_verified, 0)
        self.assertEqual(bytes(tampered.input_sha256), bytes(32))
        rc, changed = self.call_readout(f, lower=changed_lower)
        self.assertEqual(rc, 0)
        self.assertNotEqual(bytes(changed.input_sha256), digest)
        self.assertGreater(changed.initial_error.upper, report.initial_error.upper)

        # A forged singleton box would produce a false decisive result for the
        # true upper-corner state. The source of the box remains an external gate.
        singleton = (ctypes.c_double * 1)(1.0)
        rc, false_premise = self.call_readout(f, lower=singleton, upper=singleton)
        self.assertEqual(rc, 0)
        self.assertEqual(false_premise.threshold_relation, -1)
        self.assertNotEqual(bytes(false_premise.input_sha256), digest)

    def test_excluded_nominal_and_forged_history_fail_closed(self):
        f = self.fixture()
        excluded_upper = (ctypes.c_double * 1)(0.99)
        rc, report = self.call_readout(f, upper=excluded_upper)
        self.assertEqual(rc, -2)
        self.assertEqual(report.status, -2)
        self.assertEqual(report.steps_verified, 0)
        self.assertEqual(bytes(report.input_sha256), bytes(32))

        bad_lower = (ctypes.c_double * 1)(float("nan"))
        rc, report = self.call_readout(f, lower=bad_lower)
        self.assertEqual(rc, -2)
        self.assertEqual(bytes(report.input_sha256), bytes(32))

        reset_x = (ctypes.c_double * 1)(0.8)
        reset_y = (ctypes.c_double * 1)(0.7)
        second = Step(ctypes.sizeof(Step), 1, 1, f["scalar"], f["scalar"],
                      f["zero"], f["no_nonlinear"], None, reset_x, reset_y,
                      f["drive"], 0.1)
        forged = (Step * 2)(f["steps"][0], second)
        rc, report = self.call_readout(f, steps=forged, count=2)
        self.assertEqual(rc, -2)
        self.assertEqual(report.steps_verified, 0)

        trajectory = TrajectoryReport()
        expected = self.box_digest(f["x"], f["lower"], f["upper"])
        rc = self.trajectory(f["steps"], 1, f["lower"], f["upper"], expected,
                             ctypes.byref(trajectory), ctypes.sizeof(trajectory))
        self.assertEqual(rc, 0)
        self.assertEqual(trajectory.product_certificate_flags, 0)
        self.assertGreaterEqual(trajectory.final_time_error.upper, 0.1)
        rc = self.trajectory(forged, 2, f["lower"], f["upper"], expected,
                             ctypes.byref(trajectory), ctypes.sizeof(trajectory))
        self.assertEqual(rc, -2)
        self.assertEqual(trajectory.steps_verified, 0)
        self.assertEqual(bytes(trajectory.input_sha256), bytes(32))


if __name__ == "__main__":
    unittest.main()
