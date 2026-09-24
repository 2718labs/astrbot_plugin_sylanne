"""Build and cold-load a non-release package on the current CI host.

The manifest digest used here is read from the package itself. This proves
package/loader mechanics only; it is not a publisher or installer trust root,
or a real AstrBot installation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rewrite.sylanne3.native_runtime.loader import CANONICAL_LIBRARIES, _runtime_target  # noqa: E402
from rewrite.tools.build_plugin_package import build_package, verify_package  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Cold-load a current-platform non-release ZIP")
    parser.add_argument(
        "--output-dir", type=Path,
        help="retain the dev-probe ZIP here; extraction remains temporary",
    )
    args = parser.parse_args()
    target_os, target_arch, libc = _runtime_target()
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "rewrite" / "native" / "target"))
    native = target_dir / "release" / CANONICAL_LIBRARIES[target_os]
    if not native.is_file():
        raise FileNotFoundError(f"cargo release library is missing: {native}")
    with tempfile.TemporaryDirectory(prefix="sylanne-alpha1-probe-") as directory:
        temporary = Path(directory)
        package = build_package(
            project_root=ROOT,
            target_os=target_os,
            target_arch=target_arch,
            target_libc=libc,
            native_library=native,
            output_dir=args.output_dir if args.output_dir is not None else temporary / "package",
            allow_dirty_dev_probe=True,
        )
        verify_package(package)
        extracted = temporary / "extracted"
        with zipfile.ZipFile(package) as archive:
            manifest_bytes = archive.read("release-manifest.json")
            archive.extractall(extracted)
        manifest = extracted / "release-manifest.json"
        digest = hashlib.sha256(manifest_bytes).hexdigest()
        if hashlib.sha256(manifest.read_bytes()).hexdigest() != digest:
            raise AssertionError("extracted manifest differs from the verified ZIP")
        extracted_native = (
            extracted
            / "rewrite"
            / "sylanne3"
            / "_native"
            / f"{target_os}-{target_arch}"
            / CANONICAL_LIBRARIES[target_os]
        )
        native_digest = hashlib.sha256(extracted_native.read_bytes()).hexdigest()
        run_dir = temporary / "cold-run"
        run_dir.mkdir()
        code = "\n".join(
            (
                "import hashlib, json, math, os, shutil, sys",
                "from dataclasses import fields",
                "from decimal import Decimal, localcontext",
                "from pathlib import Path",
                "package_root, source_root = (Path(value).resolve() for value in sys.argv[1:3])",
                "assert sys.flags.isolated and sys.flags.no_site",
                "assert os.environ.get('PATH', '') == ''",
                "assert shutil.which('cargo') is None and shutil.which('rustc') is None",
                "assert all(not Path(value).resolve().is_relative_to(source_root) for value in sys.path if value)",
                "sys.path.insert(0, str(package_root))",
                "import rewrite",
                "import rewrite.sylanne3.native_runtime.loader as loader",
                "assert Path(rewrite.__file__).resolve().is_relative_to(package_root)",
                "assert Path(loader.__file__).resolve().is_relative_to(package_root)",
                "from rewrite.sylanne3.host.installed_package import verify_installed_package",
                "installed = verify_installed_package(package_root, sys.argv[3])",
                "assert installed.verified and installed.build_mode == 'dev-probe', installed",
                "from rewrite.sylanne3.native_runtime import load_production_native",
                "library = load_production_native(package_root, trusted_manifest_sha256=sys.argv[3])",
                "assert Path(library.path).resolve() == (package_root / sys.argv[8]).resolve()",
                "assert all(Path(module.__file__).resolve().is_relative_to(package_root) for name, module in sys.modules.items() if (name == 'rewrite' or name.startswith('rewrite.')) and getattr(module, '__file__', None))",
                "capabilities = library.capabilities",
                "assert capabilities.abi_version == 2 and capabilities.diagnostic_only",
                "assert not capabilities.numerically_certified",
                "assert capabilities.supports_fixed_block_interval_math_v1",
                "from rewrite.sylanne3.native_runtime import FixedBlockCSR, FixedBlockStep, run_fixed_block_math",
                "diagonal = FixedBlockCSR(1, 1, (0, 1), (0,), (2.0,))",
                "recovery = FixedBlockCSR(1, 1, (0, 1), (0,), (1.0,))",
                "zero = FixedBlockCSR(1, 1, (0, 0), (), ())",
                "arguments = FixedBlockCSR(0, 1, (0,), (), ())",
                "block = FixedBlockStep(diagonal, recovery, zero, arguments, (), (0.4,), (0.1,), (0.4,), 0.1, 0.0, 80, 1e-12)",
                "transcript = run_fixed_block_math(library, block)",
                "bounds = transcript.bounds",
                "expected_endpoint = (0.4 * (1.0 - 0.1) + 0.1 * 0.1) / (1.0 + 0.1)",
                "assert bounds.status == 0 and bounds.certificate_flags == 1 and bounds.boundary_eta == 0.0",
                "assert bounds.q_upper <= 0.8 and bounds.iteration_error <= block.tolerance",
                "assert math.isfinite(transcript.output[0]) and abs(transcript.output[0] - expected_endpoint) <= bounds.iteration_error",
                "binding = library.production_binding",
                "if binding is None: raise AssertionError('loaded native has no production binding')",
                "expected = dict(manifest_sha256=sys.argv[3], native_sha256=sys.argv[4], os=sys.argv[5], arch=sys.argv[6], libc=json.loads(sys.argv[7]), abi_version=2)",
                "for field, value in expected.items():",
                "    if getattr(binding, field) != value: raise AssertionError(f'native binding {field} mismatch')",
                "coupled_k = FixedBlockCSR(2, 2, (0, 1, 2), (0, 1), (2.0, 2.0))",
                "coupled_r = FixedBlockCSR(2, 2, (0, 1, 2), (0, 1), (1.0, 1.0))",
                "coupled_j = FixedBlockCSR(2, 2, (0, 1, 2), (1, 0), (0.2, -0.2))",
                "coupled_a = FixedBlockCSR(0, 2, (0,), (), ())",
                "coupled = FixedBlockStep(coupled_k, coupled_r, coupled_j, coupled_a, (), (0.4, -0.2), (0.0, 0.0), (0.4, -0.2), 0.1, 1e-4, 30, 1e-10)",
                "coupled_transcript = run_fixed_block_math(library, coupled)",
                "coupled_bounds = coupled_transcript.bounds",
                "assert coupled_bounds.status == 0 and coupled_bounds.certificate_flags == 1 and coupled_bounds.boundary_eta == 0.0",
                "assert coupled_bounds.q_upper <= 0.8 and coupled_bounds.iteration_error <= coupled.tolerance",
                "with localcontext() as context:",
                "    context.prec = 80",
                "    d = Decimal.from_float",
                "    half_step = d(coupled.h) / 2",
                "    damping = half_step * d(coupled.k.values[0]) * d(coupled.r.values[0])",
                "    coupling = half_step * d(coupled.k.values[0]) * d(coupled.j.values[0])",
                "    x0, x1 = (d(value) for value in coupled.previous)",
                "    rhs0 = (1 - damping) * x0 + coupling * x1",
                "    rhs1 = -coupling * x0 + (1 - damping) * x1",
                "    divisor = (1 + damping) ** 2 + coupling ** 2",
                "    reference = (((1 + damping) * rhs0 + coupling * rhs1) / divisor, (-coupling * rhs0 + (1 + damping) * rhs1) / divisor)",
                "    endpoint_distance = sum((d(actual) - exact) ** 2 for actual, exact in zip(coupled_transcript.output, reference)).sqrt()",
                "    assert endpoint_distance <= d(coupled_bounds.iteration_error)",
                "decay = math.exp(-0.2)",
                "x0, x1 = coupled.previous",
                "continuous = (decay * (math.cos(0.04) * x0 + math.sin(0.04) * x1), decay * (-math.sin(0.04) * x0 + math.cos(0.04) * x1))",
                "trajectory_distance = math.dist(coupled_transcript.output, continuous)",
                "assert trajectory_distance <= coupled_bounds.trajectory_error and coupled_bounds.trajectory_error >= coupled.previous_error",
                "assert coupled_transcript.production_binding == binding and coupled_transcript.input_sha256 == coupled.digest()",
                "def digest(value):",
                "    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')).hexdigest()",
                "assert coupled_transcript.output_sha256 == digest(coupled_transcript.output)",
                "assert coupled_transcript.transcript_sha256 == digest({'schema': 'abi2.fixed-block-math-transcript.v1', 'input_sha256': coupled_transcript.input_sha256, 'output_sha256': coupled_transcript.output_sha256, 'manifest_sha256': binding.manifest_sha256, 'native_sha256': binding.native_sha256, 'bounds': {field.name: getattr(coupled_bounds, field.name) for field in fields(coupled_bounds)}})",
                "math_receipt = {'scope': 'one_complete_fixed_scalar_block', 'certificate_flags': bounds.certificate_flags, 'input_sha256': transcript.input_sha256, 'output_sha256': transcript.output_sha256, 'transcript_sha256': transcript.transcript_sha256, 'endpoint_error_upper': bounds.iteration_error}",
                "coupled_receipt = {'scope': 'one_complete_coupled_2x2_linear_block', 'certificate_flags': coupled_bounds.certificate_flags, 'input_sha256': coupled_transcript.input_sha256, 'output_sha256': coupled_transcript.output_sha256, 'transcript_sha256': coupled_transcript.transcript_sha256, 'endpoint_error_upper': coupled_bounds.iteration_error, 'reference_endpoint_distance': str(endpoint_distance), 'trajectory_error_upper': coupled_bounds.trajectory_error, 'reference_trajectory_distance': trajectory_distance}",
                "print(json.dumps({'abi_version': capabilities.abi_version, 'max_dimension': capabilities.max_dimension, 'fixed_block_interval_math_v1': capabilities.supports_fixed_block_interval_math_v1, 'numerically_certified': capabilities.numerically_certified, 'diagnostic_only': capabilities.diagnostic_only, 'binding': expected, 'fixed_block_math': math_receipt, 'coupled_fixed_block_math': coupled_receipt}))",
            )
        )
        cold_env = {
            name: value for name, value in os.environ.items()
            if not name.upper().startswith(("PYTHON", "RUST", "CARGO"))
        }
        cold_env["PATH"] = ""
        loaded = subprocess.run(
            [
                sys.executable, "-I", "-S", "-c", code,
                str(extracted), str(ROOT.resolve()), digest, native_digest,
                target_os, target_arch, json.dumps(libc),
                str(extracted_native.relative_to(extracted)),
            ],
            cwd=run_dir,
            env=cold_env,
            check=True,
            capture_output=True,
            text=True,
        )
        result = {
            "status": "dev_probe_only",
            "package": str(package) if args.output_dir is not None else None,
            "package_bytes": package.stat().st_size,
            "platform": f"{target_os}-{target_arch}",
            "libc": libc,
            "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
            "cold_load": "isolated_python_verified_install_and_native_without_source_path_or_rust",
            "native": json.loads(loaded.stdout),
        }
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
