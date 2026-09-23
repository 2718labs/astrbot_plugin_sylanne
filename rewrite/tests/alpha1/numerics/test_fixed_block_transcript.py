from __future__ import annotations

import ctypes
import _ctypes
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal, localcontext
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

from sylanne3.native_runtime import (
    ABI2NativeLibrary,
    ABI2ResultError,
    D04CandidateError,
    D04ProductionReadoutUnavailable,
    FixedBlockCSR,
    FixedBlockStep,
    load_production_native,
    require_d04_production_readout,
    run_d04_fixed_block_candidate,
    run_fixed_block_math,
)
from sylanne3.domains.d04 import AffectAxis, AffectScheme
from sylanne3.native_runtime.d04_engineering_scheme import build_d04_engineering_candidate
from sylanne3.native_runtime.loader import _runtime_target


def _block() -> FixedBlockStep:
    offsets = [0, 1, 2]
    diagonal = [0, 1]
    k = FixedBlockCSR(2, 2, offsets, diagonal, [2.0, 2.0])
    r = FixedBlockCSR(2, 2, offsets, diagonal, [1.0, 1.0])
    j = FixedBlockCSR(2, 2, offsets, [1, 0], [0.2, -0.2])
    a = FixedBlockCSR(0, 2, [0], [], [])
    previous = [0.4, -0.2]
    block = FixedBlockStep(k, r, j, a, [], previous, [0.0, 0.0], previous,
                           0.1, 1e-4, 30, 1e-10)
    offsets[1] = 0
    previous[0] = 100.0
    return block


def _scheme() -> AffectScheme:
    return AffectScheme(
        "d04.affect.scheme.v1", "scheme:test:1", "operator:test:1",
        "parameters:test:1", "coupling:test:1",
        (AffectAxis("care", "normalized", "care"), AffectAxis("guard", "normalized", "guard")),
        (),
    )


def _affect_asset() -> dict[str, object]:
    scheme = _scheme()
    return {
        "schema": scheme.schema,
        "scheme_version": scheme.scheme_version, "operator_version": scheme.operator_version,
        "parameter_version": scheme.parameter_version, "coupling_version": scheme.coupling_version,
        "axes": [{"axis_id": axis.axis_id, "unit": axis.unit, "meaning": axis.meaning}
                 for axis in scheme.axes],
        "parameter_bounds": [list(bounds) for bounds in scheme.parameter_bounds],
    }


def _operator_asset(block: FixedBlockStep) -> dict[str, object]:
    scheme = _scheme()

    def matrix(value: FixedBlockCSR) -> dict[str, object]:
        return dict(rows=value.rows, cols=value.cols, offsets=value.offsets,
                    indices=value.indices, values=value.values)

    return {
        "schema": "d04.fixed-block-operator.v1", "affect_schema": scheme.schema,
        "scheme_version": scheme.scheme_version, "operator_version": scheme.operator_version,
        "parameter_version": scheme.parameter_version, "coupling_version": scheme.coupling_version,
        "axis_ids": [axis.axis_id for axis in scheme.axes],
        "parameter_bounds": [list(bounds) for bounds in scheme.parameter_bounds],
        "operator": {"k": matrix(block.k), "r": matrix(block.r), "j": matrix(block.j),
                     "a": matrix(block.a), "alpha": block.alpha},
    }


class FixedBlockTranscriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = Path(__file__).resolve().parents[4]
        native_root = root / "rewrite" / "native"
        subprocess.run(["cargo", "build", "--quiet"], cwd=native_root, check=True, timeout=120)
        cls.native_asset = native_root / "target" / "debug" / {
            "Windows": "sylanne3_kernel.dll",
            "Linux": "libsylanne3_kernel.so",
            "Darwin": "libsylanne3_kernel.dylib",
        }[platform.system()]

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        root = Path(self.tempdir.name)
        os_name, arch, libc = _runtime_target()
        relative = f"rewrite/sylanne3/_native/{os_name}-{arch}/{self.native_asset.name}"
        asset = root / relative
        asset.parent.mkdir(parents=True)
        shutil.copyfile(self.native_asset, asset)
        native_entry = {"path": relative, "bytes": asset.stat().st_size,
                        "sha256": hashlib.sha256(asset.read_bytes()).hexdigest()}
        catalogue = root / "resources" / "catalogue"
        catalogue.mkdir(parents=True)
        catalogue_path = catalogue / "current.json"
        catalogue_path.write_text(json.dumps({
            "activation_status": "candidate_only",
            "domain_capabilities": {"d04": ["d04.affect.scheme.v1"]},
        }), encoding="utf-8")
        catalogue_entry = {"path": "resources/catalogue/current.json",
                           "bytes": catalogue_path.stat().st_size,
                           "sha256": hashlib.sha256(catalogue_path.read_bytes()).hexdigest()}
        affect_path = catalogue / "d04-affect-scheme.json"
        affect_path.write_text(json.dumps(_affect_asset()), encoding="utf-8")
        affect_entry = {"path": "resources/catalogue/d04-affect-scheme.json",
                        "bytes": affect_path.stat().st_size,
                        "sha256": hashlib.sha256(affect_path.read_bytes()).hexdigest()}
        operator_path = catalogue / "d04-fixed-block-operator.json"
        operator_path.write_text(json.dumps(_operator_asset(_block())), encoding="utf-8")
        operator_entry = {"path": "resources/catalogue/d04-fixed-block-operator.json",
                          "bytes": operator_path.stat().st_size,
                          "sha256": hashlib.sha256(operator_path.read_bytes()).hexdigest()}
        manifest = {
            "schema_version": 1,
            "native_math": {"contract": "abi2.fixed-block-interval.v1", "capability_flags": 1},
            "platform": {"os": os_name, "arch": arch, "abi_version": 2,
                         "native_filename": asset.name, "libc": libc, "cpu_features": []},
            "native": native_entry,
            "affect_scheme": {**affect_entry, "catalogue_capability": "d04.affect.scheme.v1",
                              "scheme_version": _scheme().scheme_version,
                              "operator_version": _scheme().operator_version,
                              "parameter_version": _scheme().parameter_version,
                              "coupling_version": _scheme().coupling_version},
            "files": [native_entry, catalogue_entry, affect_entry, operator_entry],
        }
        raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        (root / "release-manifest.json").write_bytes(raw)
        self.handle = load_production_native(root, trusted_manifest_sha256=hashlib.sha256(raw).hexdigest())
        self.package_root = root
        self.scheme_path = affect_path
        self.operator_path = operator_path
        self.catalogue_path = catalogue_path
        self.addCleanup(self._unload_package_library)

    def _unload_package_library(self) -> None:
        library = self.handle._library
        if platform.system() == "Windows":
            _ctypes.FreeLibrary(library._handle)
        else:
            _ctypes.dlclose(library._handle)
        library._handle = 0

    def test_real_package_bound_step_retains_actual_values_and_hashes(self) -> None:
        block = _block()
        transcript = run_fixed_block_math(self.handle, block)
        self.assertEqual(transcript.input.previous, (0.4, -0.2))
        self.assertEqual(transcript.input.k.offsets, (0, 1, 2))
        self.assertEqual(len(transcript.output), 2)
        self.assertNotEqual(transcript.output, transcript.input.previous)
        self.assertEqual(transcript.bounds.certificate_flags, 1)
        self.assertEqual(transcript.input_sha256, block.digest())
        self.assertEqual(transcript.production_binding, self.handle.production_binding)
        output_bytes = json.dumps(transcript.output, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        self.assertEqual(transcript.output_sha256, hashlib.sha256(output_bytes).hexdigest())
        self.assertEqual(transcript.production_binding.native_sha256,
                         hashlib.sha256(self.native_asset.read_bytes()).hexdigest())
        self.assertEqual(len(transcript.transcript_sha256), 64)
        self.assertNotEqual(transcript.input_sha256, replace(block, previous_error=2e-4).digest())
        with self.assertRaises(FrozenInstanceError):
            transcript.output = (0.0, 0.0)

    def test_24d_engineering_candidate_interval_contains_independent_reference(self) -> None:
        candidate = build_d04_engineering_candidate()
        previous = (0.5, 0.25, 0.125) + (0.0,) * 21
        drive = (0.0, 0.0625, 0.0) + (0.0,) * 21
        block = FixedBlockStep(
            candidate.k, candidate.r, candidate.j, candidate.a, candidate.alpha,
            previous, drive, previous, 1.0 / 256.0, 0.0, 64, 1e-5,
        )
        transcript = run_fixed_block_math(self.handle, block)
        self.assertEqual(transcript.bounds.certificate_flags, 1)
        self.assertTrue(self.handle.capabilities.diagnostic_only)
        self.assertFalse(self.handle.capabilities.numerically_certified)
        self.assertLessEqual(transcript.bounds.q_upper, 0.8)

        # Independent high-precision AVF fixed point for the active three-node chain.
        # The other seven chains have zero state and drive and remain exactly zero.
        with localcontext() as context:
            context.prec = 80
            d = Decimal
            x = tuple(d(str(value)) for value in previous[:3])
            u = tuple(d(str(value)) for value in drive[:3])
            h = d(1) / d(256)
            rates = (d(1), d(1) / d(8), d(1) / d(64))
            k = ((d(9) / d(8), -d(1) / d(8), d(0)),
                 (-d(1) / d(8), d(5) / d(4), -d(1) / d(8)),
                 (d(0), -d(1) / d(8), d(9) / d(8)))

            def log_cosh(value: Decimal) -> Decimal:
                return ((value.exp() + (-value).exp()) / d(2)).ln()

            y = x
            for _ in range(100):
                midpoint = tuple((x[index] + y[index]) / d(2) for index in range(3))
                gradient = tuple(
                    sum(k[index][col] * midpoint[col] for col in range(3))
                    + d(1) / d(4) * (
                        (log_cosh(y[index]) - log_cosh(x[index])) / (y[index] - x[index])
                        if y[index] != x[index]
                        else (x[index].exp() - (-x[index]).exp())
                             / (x[index].exp() + (-x[index]).exp())
                    )
                    for index in range(3)
                )
                next_y = tuple(x[index] + h * (u[index] - rates[index] * gradient[index])
                               for index in range(3))
                if max(abs(next_y[index] - y[index]) for index in range(3)) < d("1e-60"):
                    y = next_y
                    break
                y = next_y
            else:
                self.fail("independent high-precision AVF reference did not converge")
            reference = y + (d(0),) * 21
            endpoint_bound = d.from_float(transcript.bounds.iteration_error) + d("1e-55")
            for actual, expected in zip(transcript.output, reference):
                error = abs(d.from_float(actual) - expected)
                self.assertLess(error, d("1e-12"))
                self.assertLessEqual(error, endpoint_bound)
        self.assertTrue(all(0.0 <= value <= 4.0 for value in transcript.output))

    def test_24d_high_latent_state_has_package_bound_interval_certificate(self) -> None:
        candidate = build_d04_engineering_candidate()
        previous = (4.0, 2.0, 1.0) * 8
        block = FixedBlockStep(
            candidate.k, candidate.r, candidate.j, candidate.a, candidate.alpha,
            previous, (0.0,) * 24, previous, 1.0 / 8.0, 0.0, 80, 1e-10,
        )
        transcript = run_fixed_block_math(self.handle, block)
        self.assertEqual(transcript.bounds.certificate_flags, 1)
        self.assertEqual(transcript.bounds.status, 0)
        self.assertEqual(len(transcript.output), 24)

        # Eight disjoint, identical chains make an independent 3D Decimal
        # fixed point sufficient to check the complete 24D Euclidean bound.
        with localcontext() as context:
            context.prec = 80
            d = Decimal
            x = (d(4), d(2), d(1))
            y = (x[0] - d("0.1"), x[1] - d("0.01"), x[2] - d("0.001"))
            h = d(1) / d(8)
            rates = (d(1), d(1) / d(8), d(1) / d(64))
            k = ((d(9) / d(8), -d(1) / d(8), d(0)),
                 (-d(1) / d(8), d(5) / d(4), -d(1) / d(8)),
                 (d(0), -d(1) / d(8), d(9) / d(8)))
            ln_two = d(2).ln()

            def log_cosh(value: Decimal) -> Decimal:
                magnitude = abs(value)
                return magnitude + (d(1) + (-d(2) * magnitude).exp()).ln() - ln_two

            for _ in range(150):
                midpoint = tuple((left + right) / d(2) for left, right in zip(x, y))
                gradient = tuple(
                    sum(k[index][column] * midpoint[column] for column in range(3))
                    + d(1) / d(4) * (
                        (log_cosh(y[index]) - log_cosh(x[index])) / (y[index] - x[index])
                    )
                    for index in range(3)
                )
                next_y = tuple(x[index] - h * rates[index] * gradient[index]
                               for index in range(3))
                if max(abs(next_y[index] - y[index]) for index in range(3)) < d("1e-60"):
                    y = next_y
                    break
                y = next_y
            else:
                self.fail("independent 24D high-state reference did not converge")

            error = sum((d.from_float(actual) - y[index % 3]) ** 2
                        for index, actual in enumerate(transcript.output)).sqrt()
            self.assertLessEqual(error, d.from_float(transcript.bounds.iteration_error))
            self.assertLess(error, d("1e-12"))

    def test_direct_handle_and_incomplete_block_do_not_emit_transcript(self) -> None:
        direct = ABI2NativeLibrary(ctypes.CDLL(str(self.native_asset)), self.native_asset)
        with self.assertRaisesRegex(ABI2ResultError, "package-bound"):
            run_fixed_block_math(direct, _block())
        with self.assertRaisesRegex(ValueError, "zero boundary eta"):
            replace(_block(), boundary_eta=0.01)

    def test_package_scheme_binds_candidate_but_does_not_unlock_production_readout(self) -> None:
        candidate = run_d04_fixed_block_candidate(
            self.handle, self.package_root, _scheme(), _block(),
        )
        self.assertEqual(candidate.affect_scheme_sha256, hashlib.sha256(self.scheme_path.read_bytes()).hexdigest())
        self.assertEqual(candidate.operator_sha256, hashlib.sha256(self.operator_path.read_bytes()).hexdigest())
        self.assertEqual(candidate.math.bounds.certificate_flags, 1)
        self.assertFalse(self.handle.capabilities.numerically_certified)
        self.assertTrue(self.handle.capabilities.diagnostic_only)
        with self.assertRaisesRegex(D04ProductionReadoutUnavailable, "conditional"):
            require_d04_production_readout(candidate)

    def test_missing_or_changed_scheme_and_operator_are_rejected(self) -> None:
        with self.assertRaisesRegex(D04CandidateError, "version does not match"):
            run_d04_fixed_block_candidate(
                self.handle, self.package_root,
                replace(_scheme(), operator_version="operator:changed"), _block(),
            )
        different = replace(_block(), j=FixedBlockCSR(2, 2, [0, 0, 0], [], []))
        with self.assertRaisesRegex(D04CandidateError, "differs from trusted complete operator"):
            run_d04_fixed_block_candidate(self.handle, self.package_root, _scheme(), different)
        self.operator_path.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(Exception, "does not match trusted release manifest"):
            run_d04_fixed_block_candidate(self.handle, self.package_root, _scheme(), _block())
        self.operator_path.unlink()
        with self.assertRaisesRegex(D04CandidateError, "asset is absent"):
            run_d04_fixed_block_candidate(self.handle, self.package_root, _scheme(), _block())

    def test_missing_affect_scheme_rejects_candidate(self) -> None:
        self.scheme_path.unlink()
        with self.assertRaisesRegex(D04CandidateError, "asset is absent"):
            run_d04_fixed_block_candidate(self.handle, self.package_root, _scheme(), _block())

    def test_omitted_coupling_has_zero_local_residual_but_large_full_residual(self) -> None:
        # Midpoint step for x=(1,0), K=R=I, J_10=-1, h=0.1.
        # Solving only coordinate 0 suppresses the equation that moves coordinate 1.
        y0 = (1.0 - 0.05) / (1.0 + 0.05)
        local_residual = y0 - 1.0 + 0.1 * (1.0 + y0) / 2.0
        omitted_residual = 0.1 * (1.0 + y0) / 2.0
        self.assertAlmostEqual(local_residual, 0.0)
        self.assertGreater(omitted_residual, 0.09)


if __name__ == "__main__":
    unittest.main()
