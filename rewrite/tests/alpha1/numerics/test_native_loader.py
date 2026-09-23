from __future__ import annotations

import ctypes
from dataclasses import FrozenInstanceError
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import tempfile
import unittest
from unittest import mock

from sylanne3.native_runtime import (
    ABI2NativeLibrary,
    ABI2_FIXED_BLOCK_INTERVAL_V1,
    ABI2ResultError,
    ABI2StepResult,
    NativeReportedFixedBlockIntervalBounds,
    NativeIntegrityError,
    NativePlatformError,
    diagnostic_step_result,
    load_production_native,
    parse_fixed_block_interval_result,
)
from sylanne3.native import NativeKernel


class _Symbol:
    def __init__(self, value: int) -> None:
        self.value = value
        self.argtypes = None
        self.restype = None

    def __call__(self) -> int:
        return self.value


class _Library:
    def __init__(self, abi: int = 2, maximum: int = 65_536, math_flags: int = 0x1) -> None:
        self.sylanne3_v2_abi_version = _Symbol(abi)
        self.sylanne3_v2_max_dimension = _Symbol(maximum)
        self.sylanne3_v2_math_capabilities = _Symbol(math_flags)
        self.sylanne3_v2_step = _Symbol(0)


def _runtime_platform() -> tuple[str, str]:
    system = platform.system().lower()
    os_name = {"windows": "windows", "linux": "linux", "darwin": "macos"}[system]
    machine = platform.machine().lower()
    arch = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }[machine]
    return os_name, arch


def _fixed_block_raw() -> ABI2StepResult:
    """Hand-built ABI2 output for parser tests; no native call is made."""
    raw = ABI2StepResult()
    raw.struct_size = ctypes.sizeof(ABI2StepResult)
    raw.abi_version = 2
    raw.status = 0
    raw.iterations = 3
    raw.certificate_flags = ABI2_FIXED_BLOCK_INTERVAL_V1
    raw.residual = 1e-9
    raw.iteration_error = 0.1
    raw.time_defect = 0.2
    raw.trajectory_error = 0.3
    raw.energy_before = 4.0
    raw.energy_after = 3.5
    raw.energy_balance_defect = 0.4
    raw.q_upper = 0.8
    raw.boundary_eta = 0.0
    return raw


class NativeLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)

    def _package(self, *, abi: int = 2, os_name: str | None = None, arch: str | None = None) -> tuple[str, Path]:
        actual_os, actual_arch = _runtime_platform()
        arch = arch or actual_arch
        target_os = os_name or actual_os
        filename = {
            "windows": "sylanne3_kernel.dll",
            "linux": "libsylanne3_kernel.so",
            "macos": "libsylanne3_kernel.dylib",
        }[target_os]
        relative = f"rewrite/sylanne3/_native/{target_os}-{arch}/{filename}"
        library = self.root / Path(relative)
        library.parent.mkdir(parents=True)
        content = b"native-abi2"
        library.write_bytes(content)
        libc = None
        if target_os == "linux":
            if actual_os == "linux":
                family = platform.libc_ver()[0].strip().lower()
                libc = "glibc" if family in {"glibc", "gnu libc"} else family
            else:
                libc = "glibc"
        native_entry = {
            "path": relative,
            "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        manifest = {
            "schema_version": 1,
            "native_math": {
                "contract": "abi2.fixed-block-interval.v1",
                "capability_flags": ABI2_FIXED_BLOCK_INTERVAL_V1,
            },
            "platform": {
                "os": target_os,
                "arch": arch,
                "abi_version": abi,
                "native_filename": filename,
                "libc": libc,
                "cpu_features": [],
            },
            "native": native_entry,
            "files": [native_entry],
        }
        raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        manifest_path = self.root / "release-manifest.json"
        manifest_path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest(), library

    def test_loads_only_manifest_bound_canonical_abi2_asset(self) -> None:
        trust_root, expected_library = self._package()
        loaded: list[Path] = []

        def load(path: str):
            loaded.append(Path(path))
            return _Library()

        kernel = load_production_native(
            self.root,
            trusted_manifest_sha256=trust_root,
            _cdll_factory=load,
        )

        self.assertEqual(loaded, [expected_library.resolve()])
        self.assertEqual(kernel.capabilities.abi_version, 2)
        self.assertEqual(kernel.capabilities.max_dimension, 65_536)
        self.assertTrue(kernel.capabilities.supports_fixed_block_interval_math_v1)
        self.assertFalse(kernel.capabilities.numerically_certified)
        self.assertFalse(kernel.capabilities.supports_cancellation)
        self.assertTrue(kernel.capabilities.diagnostic_only)
        binding = kernel.production_binding
        self.assertIsNotNone(binding)
        self.assertEqual(binding.manifest_sha256, trust_root)
        self.assertEqual(binding.native_sha256, hashlib.sha256(expected_library.read_bytes()).hexdigest())
        expected_os, expected_arch = _runtime_platform()
        self.assertEqual((binding.os, binding.arch), (expected_os, expected_arch))
        self.assertEqual(binding.libc, None if expected_os != "linux" else (
            "glibc" if platform.libc_ver()[0].strip().lower() in {"glibc", "gnu libc"}
            else platform.libc_ver()[0].strip().lower()
        ))
        self.assertEqual(binding.abi_version, 2)
        with self.assertRaises(FrozenInstanceError):
            binding.abi_version = 1

    def test_direct_abi2_handle_has_no_production_binding(self) -> None:
        direct = ABI2NativeLibrary(_Library(), self.root / "unverified.dll")
        self.assertIsNone(direct.production_binding)
        self.assertTrue(direct.capabilities.supports_fixed_block_interval_math_v1)
        self.assertFalse(direct.capabilities.numerically_certified)
        with self.assertRaises(AttributeError):
            direct.production_binding = object()

    def test_rejects_native_math_capability_disagreement(self) -> None:
        trust_root, _ = self._package()
        for flags in (0, 0x2):
            with self.subTest(flags=flags), self.assertRaisesRegex(
                NativeIntegrityError, "math capabilities"
            ):
                load_production_native(
                    self.root,
                    trusted_manifest_sha256=trust_root,
                    _cdll_factory=lambda _, flags=flags: _Library(math_flags=flags),
                )

        missing_export = _Library()
        del missing_export.sylanne3_v2_math_capabilities
        with self.assertRaisesRegex(NativeIntegrityError, "math capabilities export"):
            load_production_native(
                self.root,
                trusted_manifest_sha256=trust_root,
                _cdll_factory=lambda _: missing_export,
            )

    def test_rejects_manifest_without_math_contract(self) -> None:
        self._package()
        manifest_path = self.root / "release-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        del manifest["native_math"]
        raw = json.dumps(manifest).encode()
        manifest_path.write_bytes(raw)
        with self.assertRaisesRegex(NativeIntegrityError, "math contract"):
            load_production_native(
                self.root,
                trusted_manifest_sha256=hashlib.sha256(raw).hexdigest(),
                _cdll_factory=lambda _: self.fail("library must not be loaded"),
            )

    def test_rejects_manifest_without_matching_external_trust_root(self) -> None:
        self._package()
        with self.assertRaisesRegex(NativeIntegrityError, "manifest trust root"):
            load_production_native(
                self.root,
                trusted_manifest_sha256="0" * 64,
                _cdll_factory=lambda _: self.fail("library must not be loaded"),
            )

    def test_rejects_wrong_platform_or_abi_before_loading(self) -> None:
        current_os, _ = _runtime_platform()
        wrong_os = "linux" if current_os != "linux" else "windows"
        trust_root, _ = self._package(os_name=wrong_os)
        with self.assertRaises(NativePlatformError):
            load_production_native(
                self.root,
                trusted_manifest_sha256=trust_root,
                _cdll_factory=lambda _: self.fail("library must not be loaded"),
            )

        self.root.joinpath("release-manifest.json").unlink()
        trust_root, _ = self._package(abi=1)
        with self.assertRaisesRegex(NativePlatformError, "ABI 2"):
            load_production_native(
                self.root,
                trusted_manifest_sha256=trust_root,
                _cdll_factory=lambda _: self.fail("library must not be loaded"),
            )

    def test_rejects_platform_combination_outside_release_matrix(self) -> None:
        trust_root, _ = self._package(os_name="windows", arch="aarch64")
        with mock.patch("platform.system", return_value="Windows"), mock.patch(
            "platform.machine", return_value="ARM64"
        ), self.assertRaisesRegex(NativePlatformError, "unsupported runtime platform"):
            load_production_native(
                self.root,
                trusted_manifest_sha256=trust_root,
                _cdll_factory=lambda _: self.fail("library must not be loaded"),
            )

    def test_rejects_native_bytes_changed_after_manifest(self) -> None:
        trust_root, library = self._package()
        library.write_bytes(b"tampered!!!")
        with self.assertRaisesRegex(NativeIntegrityError, "native SHA256"):
            load_production_native(
                self.root,
                trusted_manifest_sha256=trust_root,
                _cdll_factory=lambda _: self.fail("library must not be loaded"),
            )

    def test_rejects_symlinked_native_even_when_bytes_match(self) -> None:
        trust_root, library = self._package()
        external = self.root / "external-native.dll"
        external.write_bytes(library.read_bytes())
        library.unlink()
        try:
            os.symlink(external, library)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        with self.assertRaisesRegex(NativeIntegrityError, "symlink"):
            load_production_native(
                self.root,
                trusted_manifest_sha256=trust_root,
                _cdll_factory=lambda _: self.fail("library must not be loaded"),
            )

    def test_step_result_is_diagnostic_and_rejects_claimed_certificate(self) -> None:
        raw = ABI2StepResult()
        raw.struct_size = __import__("ctypes").sizeof(ABI2StepResult)
        raw.abi_version = 2
        raw.status = 0
        raw.iterations = 3
        raw.certificate_flags = 0
        raw.residual = 1e-9
        result = diagnostic_step_result(raw)
        self.assertFalse(result.certified)
        self.assertEqual(result.certificate_flags, 0)
        self.assertEqual(result.residual, 1e-9)

        raw.certificate_flags = 1
        with self.assertRaisesRegex(ABI2ResultError, "certificate flags"):
            diagnostic_step_result(raw)

    def test_parses_native_reported_fixed_block_math_without_product_authority(self) -> None:
        raw = _fixed_block_raw()
        report = parse_fixed_block_interval_result(raw)
        self.assertIsInstance(report, NativeReportedFixedBlockIntervalBounds)
        self.assertEqual(report.certificate_flags, ABI2_FIXED_BLOCK_INTERVAL_V1)
        for field in (
            "residual",
            "iteration_error",
            "time_defect",
            "trajectory_error",
            "energy_before",
            "energy_after",
            "energy_balance_defect",
            "q_upper",
            "boundary_eta",
        ):
            self.assertEqual(getattr(report, field), getattr(raw, field))
        with self.assertRaisesRegex(ABI2ResultError, "certificate flags"):
            diagnostic_step_result(raw)

    def test_fixed_block_parser_rejects_wrong_layout_status_and_flags(self) -> None:
        cases = (
            ("struct_size", ctypes.sizeof(ABI2StepResult) - 1),
            ("abi_version", 1),
            ("status", 1),
            ("certificate_flags", 0),
            ("certificate_flags", ABI2_FIXED_BLOCK_INTERVAL_V1 | 0x2),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                raw = _fixed_block_raw()
                setattr(raw, field, value)
                with self.assertRaises(ABI2ResultError):
                    parse_fixed_block_interval_result(raw)

    def test_fixed_block_parser_rejects_invalid_bounds_and_point_values(self) -> None:
        bounds = (
            "residual",
            "iteration_error",
            "time_defect",
            "trajectory_error",
            "energy_balance_defect",
            "q_upper",
            "boundary_eta",
        )
        for field in bounds:
            for value in (-0.1, math.nan, math.inf):
                with self.subTest(field=field, value=value):
                    raw = _fixed_block_raw()
                    setattr(raw, field, value)
                    with self.assertRaises(ABI2ResultError):
                        parse_fixed_block_interval_result(raw)
        for field in ("energy_before", "energy_after"):
            with self.subTest(field=field):
                raw = _fixed_block_raw()
                setattr(raw, field, math.inf)
                with self.assertRaises(ABI2ResultError):
                    parse_fixed_block_interval_result(raw)
        for field, value in (("q_upper", 0.800001), ("boundary_eta", 0.01)):
            with self.subTest(field=field, value=value):
                raw = _fixed_block_raw()
                setattr(raw, field, value)
                with self.assertRaisesRegex(ABI2ResultError, "preconditions"):
                    parse_fixed_block_interval_result(raw)

    def test_abi1_reference_requires_explicit_library_and_developer_opt_in(self) -> None:
        with self.assertRaisesRegex(TypeError, "library_path"):
            NativeKernel()
        with self.assertRaisesRegex(RuntimeError, "developer reference"):
            NativeKernel(self.root / "reference.dll")


if __name__ == "__main__":
    unittest.main()
