"""The generated 24D nonlinear assets through a real package-bound ABI2 chain."""

from __future__ import annotations

import _ctypes
from dataclasses import replace
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest

from sylanne3.domains.d04 import AffectAxis, AffectScheme
from sylanne3.native_runtime import (
    D04CandidateError,
    D04ProductionReadoutUnavailable,
    FixedBlockCSR,
    FixedBlockContinuation,
    FixedBlockStep,
    load_production_native,
    require_d04_production_readout,
    run_d04_fixed_block_box_trajectory_candidate,
    run_fixed_block_box_trajectory_math,
)
from sylanne3.native_runtime.d04_engineering_scheme import build_d04_engineering_candidate
from sylanne3.native_runtime.loader import _runtime_target


def _entry(path: str, content: bytes) -> dict[str, object]:
    return {"path": path, "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest()}


def _rk4_reference(initial: tuple[float, float, float], total: float,
                   panels: int) -> tuple[float, float, float]:
    """Independent continuous ODE reference; no AVF or interval formulas."""
    rates = (1.0, 0.125, 0.015625)
    k = ((1.125, -0.125, 0.0),
         (-0.125, 1.25, -0.125),
         (0.0, -0.125, 1.125))
    drive = (0.0, 0.0625, 0.0)

    def field(state: tuple[float, float, float]) -> tuple[float, float, float]:
        return tuple(
            drive[row] - rates[row] * (
                math.fsum(k[row][col] * state[col] for col in range(3))
                + 0.25 * math.tanh(state[row])
            ) for row in range(3)
        )

    def shifted(state: tuple[float, float, float], slope: tuple[float, float, float],
                factor: float) -> tuple[float, float, float]:
        return tuple(state[index] + factor * slope[index] for index in range(3))

    state = initial
    h = total / panels
    for _ in range(panels):
        a = field(state)
        b = field(shifted(state, a, h / 2))
        c = field(shifted(state, b, h / 2))
        d = field(shifted(state, c, h))
        state = tuple(
            state[index] + h * (a[index] + 2 * b[index] + 2 * c[index] + d[index]) / 6
            for index in range(3)
        )
    return state


class GeneratedNonlinearPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[4]
        native_root = cls.root / "rewrite" / "native"
        subprocess.run(["cargo", "build", "--quiet"], cwd=native_root, check=True, timeout=120)
        cls.native_asset = native_root / "target" / "debug" / {
            "Windows": "sylanne3_kernel.dll",
            "Linux": "libsylanne3_kernel.so",
            "Darwin": "libsylanne3_kernel.dylib",
        }[platform.system()]

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        outer = Path(temporary.name)
        generated = outer / "generated"
        subprocess.run(
            [sys.executable, str(self.root / "scripts" / "alpha1" / "generate_d04_candidate_assets.py"),
             "--output-dir", str(generated)],
            cwd=self.root, check=True, capture_output=True, text=True, timeout=60,
        )
        scheme_bytes = (generated / "d04-affect-scheme.candidate.json").read_bytes()
        operator_bytes = (generated / "d04-fixed-block-operator.candidate.json").read_bytes()
        self.scheme_data = json.loads(scheme_bytes)
        self.operator_data = json.loads(operator_bytes)
        self.scheme = AffectScheme(
            self.scheme_data["schema"],
            *(self.scheme_data[name] for name in (
                "scheme_version", "operator_version", "parameter_version", "coupling_version")),
            tuple(AffectAxis(**axis) for axis in self.scheme_data["axes"]),
            tuple(tuple(item) for item in self.scheme_data["parameter_bounds"]),
        )
        package = outer / "package"
        os_name, arch, libc = _runtime_target()
        native_path = f"rewrite/sylanne3/_native/{os_name}-{arch}/{self.native_asset.name}"
        catalogue_path = "resources/catalogue/current.json"
        scheme_path = "resources/catalogue/d04-affect-scheme.json"
        operator_path = "resources/catalogue/d04-fixed-block-operator.json"
        catalogue_bytes = json.dumps({
            "activation_status": "candidate_only",
            "domain_capabilities": {"d04": ["d04.affect.scheme.v1"]},
        }, sort_keys=True, separators=(",", ":")).encode()
        entries = []
        for relative, content in (
            (native_path, self.native_asset.read_bytes()),
            (catalogue_path, catalogue_bytes),
            (scheme_path, scheme_bytes),
            (operator_path, operator_bytes),
        ):
            target = package / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            entries.append(_entry(relative, content))
        manifest = {
            "schema_version": 1,
            "native_math": {"contract": "abi2.fixed-block-interval.v1", "capability_flags": 1},
            "platform": {"os": os_name, "arch": arch, "abi_version": 2,
                         "native_filename": self.native_asset.name, "libc": libc,
                         "cpu_features": []},
            "native": entries[0],
            "affect_scheme": {**entries[2], "catalogue_capability": "d04.affect.scheme.v1",
                              **{name: self.scheme_data[name] for name in (
                                  "scheme_version", "operator_version", "parameter_version",
                                  "coupling_version")}},
            "files": entries,
        }
        manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        (package / "release-manifest.json").write_bytes(manifest_bytes)
        self.handle = load_production_native(
            package, trusted_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        )
        self.package = package
        self.scheme_sha256 = hashlib.sha256(scheme_bytes).hexdigest()
        self.operator_sha256 = hashlib.sha256(operator_bytes).hexdigest()
        self.addCleanup(self._unload)

    def _unload(self) -> None:
        library = self.handle._library
        if platform.system() == "Windows":
            _ctypes.FreeLibrary(library._handle)
        else:
            _ctypes.dlclose(library._handle)
        library._handle = 0

    def _first(self) -> FixedBlockStep:
        model = build_d04_engineering_candidate()
        state = (0.5, 0.25, 0.125) + (0.0,) * 21
        return FixedBlockStep(
            model.k, model.r, model.j, model.a, model.alpha,
            state, (0.0, 0.0625, 0.0) + (0.0,) * 21,
            state, 1.0 / 256.0, 0.0, 64, 1e-5,
        )

    def test_generated_alpha_positive_coupled_asset_has_conditional_native_chain(self) -> None:
        first = self._first()
        self.assertTrue(all(value > 0 for value in first.alpha))
        self.assertIn(-0.125, first.k.values)
        lower = first.previous
        upper = tuple(value + 1e-6 for value in lower)
        candidate = run_d04_fixed_block_box_trajectory_candidate(
            self.handle, self.package, self.scheme, first,
            (FixedBlockContinuation.from_step(first),), lower=lower, upper=upper,
        )
        self.assertEqual(candidate.affect_scheme_sha256, self.scheme_sha256)
        self.assertEqual(candidate.operator_sha256, self.operator_sha256)
        self.assertEqual(len(candidate.math.trajectory.steps), 2)
        self.assertTrue(all(step.bounds.certificate_flags == 1
                            for step in candidate.math.trajectory.steps))
        actual_initial = tuple(upper[:3])
        elapsed = sum(step.input.h for step in candidate.math.trajectory.steps)
        reference = _rk4_reference(actual_initial, elapsed, 512)
        coarse = _rk4_reference(actual_initial, elapsed, 256)
        self.assertLess(math.dist(reference, coarse), 1e-12)
        observed = candidate.math.trajectory.steps[-1].output
        self.assertLessEqual(
            math.dist(observed, reference + (0.0,) * 21),
            candidate.math.trajectory.final_error,
        )
        self.assertFalse(self.handle.capabilities.numerically_certified)
        with self.assertRaises(D04ProductionReadoutUnavailable):
            require_d04_production_readout(candidate)

    def test_generated_asset_rejects_missing_coupling_or_changed_alpha(self) -> None:
        first = self._first()
        lower = first.previous
        upper = tuple(value + 1e-6 for value in lower)
        altered_alpha = replace(first, alpha=(0.0,) + first.alpha[1:])
        values = list(first.k.values)
        # Remove the symmetric 0↔1 coupling without altering row shape.
        values[1] = 0.0
        values[2] = 0.0
        altered_k = replace(first.k, values=tuple(values))
        missing_coupling = replace(first, k=altered_k)
        admitted = run_d04_fixed_block_box_trajectory_candidate(
            self.handle, self.package, self.scheme, first,
            (FixedBlockContinuation.from_step(first),), lower=lower, upper=upper,
        )
        admitted_output = admitted.math.trajectory.steps[-1].output
        for altered in (altered_alpha, missing_coupling):
            with self.subTest(kind="alpha" if altered is altered_alpha else "coupling"):
                # The native verifier can still prove its received *different*
                # operator. Package binding must refuse to call that D04's asset.
                bare = run_fixed_block_box_trajectory_math(
                    self.handle, altered, (FixedBlockContinuation.from_step(altered),),
                    lower=lower, upper=upper,
                )
                self.assertEqual(bare.trajectory.steps[-1].bounds.certificate_flags, 1)
                self.assertGreater(
                    math.dist(bare.trajectory.steps[-1].output, admitted_output), 1e-6,
                )
                with self.assertRaisesRegex(D04CandidateError, "trusted complete operator"):
                    run_d04_fixed_block_box_trajectory_candidate(
                        self.handle, self.package, self.scheme, altered,
                        (FixedBlockContinuation.from_step(altered),),
                        lower=lower, upper=upper,
                    )
