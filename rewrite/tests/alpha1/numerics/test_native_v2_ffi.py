from __future__ import annotations

import ctypes
import math
from pathlib import Path
import platform
import subprocess
import unittest

from sylanne3.native_runtime import (
    ABI2_FIXED_BLOCK_INTERVAL_V1,
    ABI2CSR,
    ABI2StepInput,
    ABI2StepResult,
    diagnostic_step_result,
    parse_fixed_block_interval_result,
)


class NativeV2FFITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        repository = Path(__file__).resolve().parents[4]
        cls.native_root = repository / "rewrite" / "native"
        filename = {
            "Windows": "sylanne3_kernel.dll",
            "Linux": "libsylanne3_kernel.so",
            "Darwin": "libsylanne3_kernel.dylib",
        }[platform.system()]
        cls.library_path = cls.native_root / "target" / "debug" / filename
        subprocess.run(
            ["cargo", "build", "--quiet"],
            cwd=cls.native_root,
            check=True,
            timeout=120,
        )
        if not cls.library_path.is_file():
            raise RuntimeError(f"cargo build did not produce {cls.library_path}")
        cls.library = ctypes.CDLL(str(cls.library_path))
        cls.library.sylanne3_v2_abi_version.argtypes = []
        cls.library.sylanne3_v2_abi_version.restype = ctypes.c_uint32
        cls.library.sylanne3_v2_supported_certificate_flags.argtypes = []
        cls.library.sylanne3_v2_supported_certificate_flags.restype = ctypes.c_uint32
        cls.library.sylanne3_v2_step.argtypes = [
            ctypes.POINTER(ABI2StepInput),
            ctypes.POINTER(ctypes.c_double),
            ctypes.c_uint32,
            ctypes.POINTER(ABI2StepResult),
        ]
        cls.library.sylanne3_v2_step.restype = ctypes.c_int32
        cls.library.sylanne3_v2_step_cancelable.argtypes = [
            ctypes.POINTER(ABI2StepInput),
            ctypes.POINTER(ctypes.c_double),
            ctypes.c_uint32,
            ctypes.POINTER(ABI2StepResult),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_uint32,
        ]
        cls.library.sylanne3_v2_step_cancelable.restype = ctypes.c_int32
        cls.library.sylanne3_v2_propagate_parameter_switch_bounds.argtypes = [
            ctypes.c_double,
            ctypes.c_double,
            ctypes.c_double,
            ctypes.c_double,
            ctypes.c_double,
            ctypes.POINTER(ctypes.c_double),
            ctypes.c_uint32,
        ]
        cls.library.sylanne3_v2_propagate_parameter_switch_bounds.restype = ctypes.c_int32

    @staticmethod
    def _csr(rows: int, cols: int, offsets, indices, values) -> ABI2CSR:
        return ABI2CSR(
            rows,
            cols,
            len(values),
            ctypes.cast(offsets, ctypes.POINTER(ctypes.c_uint32)),
            ctypes.cast(indices, ctypes.POINTER(ctypes.c_uint32)),
            ctypes.cast(values, ctypes.POINTER(ctypes.c_double)),
        )

    def _linear_input(self):
        offsets = (ctypes.c_uint32 * 2)(0, 1)
        indices = (ctypes.c_uint32 * 1)(0)
        kval = (ctypes.c_double * 1)(2.0)
        rval = (ctypes.c_double * 1)(1.0)
        zero_offsets = (ctypes.c_uint32 * 2)(0, 0)
        empty_indices = (ctypes.c_uint32 * 0)()
        empty_values = (ctypes.c_double * 0)()
        a_offsets = (ctypes.c_uint32 * 1)(0)
        previous = (ctypes.c_double * 1)(0.4)
        drive = (ctypes.c_double * 1)(0.1)
        iterate = (ctypes.c_double * 1)(0.4)
        keepalive = (
            offsets,
            indices,
            kval,
            rval,
            zero_offsets,
            empty_indices,
            empty_values,
            a_offsets,
            previous,
            drive,
            iterate,
        )
        value = ABI2StepInput(
            ctypes.sizeof(ABI2StepInput),
            2,
            1,
            self._csr(1, 1, offsets, indices, kval),
            self._csr(1, 1, offsets, indices, rval),
            self._csr(1, 1, zero_offsets, empty_indices, empty_values),
            self._csr(0, 1, a_offsets, empty_indices, empty_values),
            ctypes.POINTER(ctypes.c_double)(),
            previous,
            drive,
            iterate,
            0.1,
            0.0,
            80,
            1e-12,
            0.0,
        )
        return value, keepalive

    def _coupled_linear_input(self):
        offsets = (ctypes.c_uint32 * 3)(0, 1, 2)
        diagonal_indices = (ctypes.c_uint32 * 2)(0, 1)
        kval = (ctypes.c_double * 2)(2.0, 2.0)
        rval = (ctypes.c_double * 2)(1.0, 1.0)
        j_indices = (ctypes.c_uint32 * 2)(1, 0)
        jval = (ctypes.c_double * 2)(0.2, -0.2)
        a_offsets = (ctypes.c_uint32 * 1)(0)
        empty_indices = (ctypes.c_uint32 * 0)()
        empty_values = (ctypes.c_double * 0)()
        previous = (ctypes.c_double * 2)(0.4, -0.2)
        drive = (ctypes.c_double * 2)(0.0, 0.0)
        iterate = (ctypes.c_double * 2)(0.4, -0.2)
        keepalive = (
            offsets, diagonal_indices, kval, rval, j_indices, jval,
            a_offsets, empty_indices, empty_values, previous, drive, iterate,
        )
        step = ABI2StepInput(
            ctypes.sizeof(ABI2StepInput),
            2,
            2,
            self._csr(2, 2, offsets, diagonal_indices, kval),
            self._csr(2, 2, offsets, diagonal_indices, rval),
            self._csr(2, 2, offsets, j_indices, jval),
            self._csr(0, 2, a_offsets, empty_indices, empty_values),
            ctypes.POINTER(ctypes.c_double)(),
            previous,
            drive,
            iterate,
            0.1,
            1e-4,
            30,
            1e-10,
            0.0,
        )
        return step, keepalive

    def test_python_ffi_certifies_coupled_linear_fixed_block(self) -> None:
        self.assertEqual(self.library.sylanne3_v2_abi_version(), 2)
        self.assertEqual(
            self.library.sylanne3_v2_supported_certificate_flags(),
            ABI2_FIXED_BLOCK_INTERVAL_V1,
        )
        step, keepalive = self._coupled_linear_input()
        output = (ctypes.c_double * 2)(0.0, 0.0)
        result = ABI2StepResult()
        status = self.library.sylanne3_v2_step(
            ctypes.byref(step), output, len(output), ctypes.byref(result)
        )
        self.assertEqual(status, 0)
        self.assertEqual(result.struct_size, ctypes.sizeof(ABI2StepResult))
        self.assertEqual(
            result.certificate_flags,
            ABI2_FIXED_BLOCK_INTERVAL_V1,
        )
        report = parse_fixed_block_interval_result(result)
        self.assertLessEqual(report.iteration_error, step.tolerance)
        self.assertLessEqual(report.q_upper, 0.8)
        x0, x1 = 0.4, -0.2
        rhs0 = 0.9 * x0 + 0.02 * x1
        rhs1 = -0.02 * x0 + 0.9 * x1
        denominator = 1.1**2 + 0.02**2
        discrete = (
            (1.1 * rhs0 + 0.02 * rhs1) / denominator,
            (-0.02 * rhs0 + 1.1 * rhs1) / denominator,
        )
        endpoint_distance = math.hypot(output[0] - discrete[0], output[1] - discrete[1])
        self.assertLessEqual(endpoint_distance, report.iteration_error)
        damping = math.exp(-0.2)
        continuous = (
            damping * (math.cos(0.04) * x0 + math.sin(0.04) * x1),
            damping * (-math.sin(0.04) * x0 + math.cos(0.04) * x1),
        )
        trajectory_distance = math.hypot(output[0] - continuous[0], output[1] - continuous[1])
        self.assertLessEqual(trajectory_distance, report.trajectory_error)
        self.assertGreaterEqual(report.trajectory_error, step.previous_error)
        self.assertTrue(keepalive)

    def test_nonzero_boundary_remains_diagnostic(self) -> None:
        step, keepalive = self._linear_input()
        step.boundary_eta = 0.01
        output = (ctypes.c_double * 1)(0.0)
        result = ABI2StepResult()
        status = self.library.sylanne3_v2_step(
            ctypes.byref(step), output, len(output), ctypes.byref(result)
        )
        self.assertEqual(status, 0)
        self.assertEqual(result.certificate_flags, 0)
        self.assertEqual(diagnostic_step_result(result).certificate_flags, 0)
        self.assertTrue(keepalive)

    def test_python_ffi_observes_cancel_without_publishing_output(self) -> None:
        step, keepalive = self._linear_input()
        output = (ctypes.c_double * 1)(123.0)
        result = ABI2StepResult()
        result.certificate_flags = ABI2_FIXED_BLOCK_INTERVAL_V1
        cancel_epoch = ctypes.c_uint32(2)
        status = self.library.sylanne3_v2_step_cancelable(
            ctypes.byref(step),
            output,
            len(output),
            ctypes.byref(result),
            ctypes.byref(cancel_epoch),
            1,
        )
        self.assertEqual(status, -4)
        self.assertEqual(result.status, -4)
        self.assertEqual(result.certificate_flags, 0)
        self.assertEqual(output[0], 123.0)
        self.assertTrue(keepalive)

    def test_python_ffi_parameter_switch_propagates_error_and_energy_account(self) -> None:
        output = (ctypes.c_double * 3)()
        status = self.library.sylanne3_v2_propagate_parameter_switch_bounds(
            0.1, 3.0, 0.02, 2.0, 1.5, output, len(output)
        )
        self.assertEqual(status, 0)
        self.assertGreaterEqual(output[0], 0.32)
        self.assertEqual(output[1], -0.5)
        self.assertGreater(output[2], 0.0)


if __name__ == "__main__":
    unittest.main()
