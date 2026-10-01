from __future__ import annotations

import ctypes
from decimal import Decimal, localcontext
import math
from pathlib import Path
import platform
import subprocess
import unittest

from sylanne3.native_runtime.arithmetic_report import (
    ArithmeticReportLibrary, RawArithmeticReport, ReportCSR, ReportInput, ReportInterval,
    parse_arithmetic_report,
)


class TrajectoryMathStep(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32), ("version", ctypes.c_uint32),
        ("n", ctypes.c_uint32), ("k", ReportCSR), ("r", ReportCSR),
        ("j", ReportCSR), ("a", ReportCSR),
        ("alpha", ctypes.POINTER(ctypes.c_double)),
        ("x", ctypes.POINTER(ctypes.c_double)),
        ("y", ctypes.POINTER(ctypes.c_double)),
        ("drive", ctypes.POINTER(ctypes.c_double)), ("h", ctypes.c_double),
    ]


class TrajectoryMathReport(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32), ("version", ctypes.c_uint32),
        ("status", ctypes.c_int32), ("product_certificate_flags", ctypes.c_uint32),
        ("steps_verified", ctypes.c_uint32), ("input_sha256", ctypes.c_ubyte * 32),
        ("final_time_error", ReportInterval),
        ("max_endpoint_error", ReportInterval),
        ("max_reconstruction_defect", ReportInterval),
    ]


class AffineSwitchedTrajectoryMathReport(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32), ("version", ctypes.c_uint32),
        ("status", ctypes.c_int32), ("product_certificate_flags", ctypes.c_uint32),
        ("before_steps_verified", ctypes.c_uint32),
        ("after_steps_verified", ctypes.c_uint32),
        ("input_sha256", ctypes.c_ubyte * 32),
        ("before_final_time_error", ReportInterval),
        ("mapping_lipschitz_upper", ctypes.c_double),
        ("nominal_mapping_error", ReportInterval),
        ("mapped_error", ReportInterval),
        ("final_time_error", ReportInterval),
    ]


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

    def test_multiaxis_nonlinear_input_ledger_encloses_decimal_reference(self):
        # Dense Decimal reference is independent of the native CSR arithmetic.
        k = ((2.0, -0.25, 0.0), (-0.25, 1.5, 0.125), (0.0, 0.125, 1.0))
        r = ((1.0, 0.125, 0.0), (0.125, 0.75, 0.0), (0.0, 0.0, 0.5))
        j = ((0.0, 0.25, 0.0), (-0.25, 0.0, 0.125), (0.0, -0.125, 0.0))
        a = ((0.5, -0.25, 0.0), (0.0, 0.5, 0.25))
        alpha = (0.25, 0.125)
        x, y = (0.25, -0.125, 0.0625), (0.23, -0.11, 0.07)
        drive, h = (0.125, -0.0625, 0.03125), 0.0625

        def csr(matrix):
            offsets, indices, values = [0], [], []
            for row in matrix:
                for column, value in enumerate(row):
                    if value:
                        indices.append(column)
                        values.append(value)
                offsets.append(len(indices))
            return tuple(offsets), tuple(indices), tuple(values)

        report = self.reporter.report(
            n=3, k=csr(k), r=csr(r), j=csr(j), a=csr(a),
            alpha=alpha, x=x, y=y, drive=drive, readout=(1.0, 0.0, 0.0),
            h=h, inherited_error_upper=0.0, threshold=0.0,
        )

        with localcontext() as context:
            context.prec = 90
            d = Decimal.from_float
            xd, yd, ud = tuple(map(d, x)), tuple(map(d, y)), tuple(map(d, drive))
            kd, rd, jd, ad = (
                tuple(tuple(map(d, row)) for row in matrix)
                for matrix in (k, r, j, a)
            )
            weights, step = tuple(map(d, alpha)), d(h)

            def dot(left, right):
                return sum((u * v for u, v in zip(left, right)), Decimal(0))

            def multiply(matrix, vector):
                return tuple(dot(row, vector) for row in matrix)

            def log_cosh(value):
                return ((value.exp() + (-value).exp()) / 2).ln()

            def energy(state):
                quadratic = dot(state, multiply(kd, state)) / 2
                return quadratic + sum((weight * log_cosh(dot(row, state))
                                        for row, weight in zip(ad, weights)), Decimal(0))

            midpoint = tuple((left + right) / 2 for left, right in zip(xd, yd))
            gradient = list(multiply(kd, midpoint))
            for row, weight in zip(ad, weights):
                before, after = dot(row, xd), dot(row, yd)
                secant = ((log_cosh(after) - log_cosh(before)) / (after - before)
                           if after != before else (before.exp() - (-before).exp())
                           / (before.exp() + (-before).exp()))
                gradient = [value + weight * coefficient * secant
                            for value, coefficient in zip(gradient, row)]
            displacement = tuple(right - left for left, right in zip(xd, yd))
            damping, rotation = multiply(rd, gradient), multiply(jd, gradient)
            residual = tuple(delta - step * (spin - loss + applied)
                             for delta, spin, loss, applied
                             in zip(displacement, rotation, damping, ud))
            reference = {
                "energy_difference": energy(yd) - energy(xd),
                "gradient_displacement": dot(gradient, displacement),
                "dissipation": -step * dot(gradient, damping),
                "drive_work": step * dot(gradient, ud),
                "residual_work": dot(gradient, residual),
                "residual_norm": dot(residual, residual).sqrt(),
            }
            reference["gradient_identity_defect"] = (
                reference["energy_difference"] - reference["gradient_displacement"]
            )
            reference["energy_balance_defect"] = (
                reference["energy_difference"] - reference["dissipation"]
                - reference["drive_work"] - reference["residual_work"]
            )
            self.assertGreater(abs(reference["drive_work"]), Decimal("1e-5"))
            for name, exact in reference.items():
                lower, upper = report.intervals[name]
                self.assertLessEqual(d(lower), exact, name)
                self.assertGreaterEqual(d(upper), exact, name)

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

    def test_trajectory_inherits_nonzero_initial_error_without_reset(self):
        offsets = (ctypes.c_uint32 * 2)(0, 1)
        indices = (ctypes.c_uint32 * 1)(0)
        values = (ctypes.c_double * 1)(1.0)
        empty_offsets = (ctypes.c_uint32 * 2)(0, 0)
        empty_a_offsets = (ctypes.c_uint32 * 1)(0)
        positive = ReportCSR(1, 1, 1, offsets, indices, values)
        zero = ReportCSR(1, 1, 0, empty_offsets, None, None)
        no_nonlinear = ReportCSR(0, 1, 0, empty_a_offsets, None, None)
        h = 0.001
        midpoint_factor = (1.0 - h / 2) / (1.0 + h / 2)
        x0, y0 = (ctypes.c_double * 1)(1.0), (ctypes.c_double * 1)(midpoint_factor)
        x1, y1 = (ctypes.c_double * 1)(midpoint_factor), (ctypes.c_double * 1)(midpoint_factor**2)
        drive = (ctypes.c_double * 1)(0.0)
        steps = (TrajectoryMathStep * 2)(
            TrajectoryMathStep(ctypes.sizeof(TrajectoryMathStep), 1, 1,
                               positive, positive, zero, no_nonlinear,
                               None, x0, y0, drive, h),
            TrajectoryMathStep(ctypes.sizeof(TrajectoryMathStep), 1, 1,
                               positive, positive, zero, no_nonlinear,
                               None, x1, y1, drive, h),
        )
        call = self.library.sylanne3_v2_trajectory_math_report_from_error_v1
        call.argtypes = [ctypes.POINTER(TrajectoryMathStep), ctypes.c_uint32,
                         ctypes.c_double, ctypes.POINTER(TrajectoryMathReport), ctypes.c_uint32]
        call.restype = ctypes.c_int32
        report = TrajectoryMathReport()
        size = ctypes.sizeof(report)
        self.assertEqual(call(steps, 2, 0.01, ctypes.byref(report), size), 0)
        self.assertEqual(report.product_certificate_flags, 0)
        self.assertEqual(report.steps_verified, 2)
        first_hash = bytes(report.input_sha256)
        with localcontext() as context:
            context.prec = 80
            d = Decimal.from_float
            exact = (d(x0[0]) + d(0.01)) * (-2 * d(steps[0].h)).exp()
            actual_error = abs(d(y1[0]) - exact)
            self.assertLessEqual(actual_error, d(report.final_time_error.upper))
        first_bound = report.final_time_error.upper
        self.assertEqual(call(steps, 2, 0.0, ctypes.byref(report), size), 0)
        # Falsely claiming an exact first state excludes the real trajectory.
        # This is why external provenance for e0 remains a production HOLD.
        self.assertLess(Decimal.from_float(report.final_time_error.upper), actual_error)
        self.assertEqual(call(steps, 2, 0.02, ctypes.byref(report), size), 0)
        self.assertGreater(report.final_time_error.upper, first_bound)
        self.assertNotEqual(bytes(report.input_sha256), first_hash)
        self.assertEqual(call(steps, 2, -1.0, ctypes.byref(report), size), -2)
        self.assertEqual(report.steps_verified, 0)
        self.assertEqual(bytes(report.input_sha256), bytes(32))

    def test_affine_switch_propagates_error_and_binds_mapping(self):
        offsets = (ctypes.c_uint32 * 2)(0, 1)
        indices = (ctypes.c_uint32 * 1)(0)
        ones = (ctypes.c_double * 1)(1.0)
        halves = (ctypes.c_double * 1)(0.5)
        twos = (ctypes.c_double * 1)(2.0)
        changed_twos = (ctypes.c_double * 1)(2.1)
        empty_offsets = (ctypes.c_uint32 * 2)(0, 0)
        empty_a_offsets = (ctypes.c_uint32 * 1)(0)
        positive = ReportCSR(1, 1, 1, offsets, indices, ones)
        new_r = ReportCSR(1, 1, 1, offsets, indices, halves)
        zero = ReportCSR(1, 1, 0, empty_offsets, None, None)
        no_nonlinear = ReportCSR(0, 1, 0, empty_a_offsets, None, None)
        h = 0.001
        old_factor = (1 - h / 2) / (1 + h / 2)
        new_factor = (1 - h / 4) / (1 + h / 4)
        old_x = (ctypes.c_double * 1)(1.0)
        old_y = (ctypes.c_double * 1)(old_factor)
        # Include a nominal jump: its 0.001 discrepancy must enter the envelope.
        new_x = (ctypes.c_double * 1)(2 * old_y[0] + 0.251)
        new_y = (ctypes.c_double * 1)(new_x[0] * new_factor)
        drive = (ctypes.c_double * 1)(0.0)
        offset = (ctypes.c_double * 1)(0.25)
        before = (TrajectoryMathStep * 1)(TrajectoryMathStep(
            ctypes.sizeof(TrajectoryMathStep), 1, 1,
            positive, positive, zero, no_nonlinear,
            None, old_x, old_y, drive, h))
        after = (TrajectoryMathStep * 1)(TrajectoryMathStep(
            ctypes.sizeof(TrajectoryMathStep), 1, 1,
            positive, new_r, zero, no_nonlinear,
            None, new_x, new_y, drive, h))
        mapping = ReportCSR(1, 1, 1, offsets, indices, twos)
        call = self.library.sylanne3_v2_affine_switched_trajectory_math_report_v1
        call.argtypes = [ctypes.POINTER(TrajectoryMathStep), ctypes.c_uint32,
                         ctypes.POINTER(TrajectoryMathStep), ctypes.c_uint32,
                         ctypes.c_double, ReportCSR, ctypes.POINTER(ctypes.c_double),
                         ctypes.POINTER(AffineSwitchedTrajectoryMathReport), ctypes.c_uint32]
        call.restype = ctypes.c_int32
        report = AffineSwitchedTrajectoryMathReport()
        size = ctypes.sizeof(report)
        self.assertEqual(call(before, 1, after, 1, 0.01, mapping,
                              offset, ctypes.byref(report), size), 0)
        self.assertEqual(report.product_certificate_flags, 0)
        self.assertEqual((report.before_steps_verified, report.after_steps_verified), (1, 1))
        self.assertGreaterEqual(report.mapping_lipschitz_upper, 2.0)
        self.assertGreaterEqual(report.nominal_mapping_error.upper, 0.001)
        self.assertGreater(report.mapped_error.upper, 2 * report.before_final_time_error.upper)
        digest = bytes(report.input_sha256)
        with localcontext() as context:
            context.prec = 80
            d = Decimal.from_float
            true_old_end = (d(old_x[0]) + d(0.01)) * (-d(h)).exp()
            true_new_end = (2 * true_old_end + d(0.25)) * (-d(0.5) * d(h)).exp()
            actual_error = abs(d(new_y[0]) - true_new_end)
            self.assertLessEqual(actual_error, d(report.final_time_error.upper))
            self.assertEqual(call(before, 1, after, 1, 0.0, mapping,
                                  offset, ctypes.byref(report), size), 0)
            # A falsely exact old state cannot enclose the independently
            # constructed switched trajectory.
            self.assertLess(d(report.final_time_error.upper), actual_error)
        changed_map = ReportCSR(1, 1, 1, offsets, indices, changed_twos)
        self.assertEqual(call(before, 1, after, 1, 0.01, changed_map,
                              offset, ctypes.byref(report), size), 0)
        self.assertNotEqual(bytes(report.input_sha256), digest)
        self.assertEqual(call(before, 1, after, 1, -1.0, mapping,
                              offset, ctypes.byref(report), size), -2)
        self.assertEqual(report.after_steps_verified, 0)
        self.assertEqual(bytes(report.input_sha256), bytes(32))


if __name__ == "__main__":
    unittest.main()
