"""Cold-load a pinned formal alpha1 ZIP on its target host.

The caller supplies the trusted manifest digest. This probe validates package
mechanics; product acceptance still requires the other alpha1 release gates.
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

from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(ROOT)

from rewrite.tools.build_plugin_package import verify_package  # noqa: E402


def _cold_verify_package(package: Path, expected_manifest_sha256: str, *, expected_mode: str) -> dict:
    """Verify a formal ZIP and load its D04 scheme and ABI2 library in isolation."""
    if len(expected_manifest_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in expected_manifest_sha256
    ):
        raise ValueError("expected manifest SHA256 must be 64 lowercase hex characters")
    verify_package(package)
    with zipfile.ZipFile(package) as archive:
        manifest_bytes = archive.read("release-manifest.json")
        manifest = json.loads(manifest_bytes)
        if manifest.get("build_mode") != expected_mode:
            raise ValueError("cold install package mode differs from explicitly selected mode")
        digest = hashlib.sha256(manifest_bytes).hexdigest()
        if digest != expected_manifest_sha256:
            raise ValueError("formal manifest differs from the trusted digest")
        with tempfile.TemporaryDirectory(prefix="sylanne-alpha1-formal-") as directory:
            temporary = Path(directory)
            extracted = temporary / "plugin"
            archive.extractall(extracted)
            run_dir = temporary / "cold-run"
            run_dir.mkdir()
            code = "\n".join((
                "import hashlib, json, os, shutil, sys",
                "from pathlib import Path",
                "root = Path(sys.argv[1]).resolve()",
                "source_root = Path(sys.argv[3]).resolve()",
                "assert sys.flags.isolated and sys.flags.no_site",
                "assert os.environ.get('PATH', '') == ''",
                "assert shutil.which('cargo') is None and shutil.which('rustc') is None",
                "assert all(not Path(value).resolve().is_relative_to(source_root) for value in sys.path if value)",
                "sys.path.insert(0, str(root))",
                "from _runtime_bootstrap import load_canonical_runtime_v1; load_canonical_runtime_v1(root)",
                "import rewrite",
                "from sylanne3.host.installed_package import verify_installed_backend_runtime_v1",
                "from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme",
                "from sylanne3.native_runtime import load_production_native",
                "assert Path(rewrite.__file__).resolve().is_relative_to(root)",
                "installed = verify_installed_backend_runtime_v1(root, sys.argv[2])",
                "assert installed.verified and installed.build_mode == sys.argv[4], installed",
                "scheme = load_verified_affect_scheme(root, sys.argv[2])",
                "manifest = json.loads((root / 'release-manifest.json').read_bytes())",
                "relative = 'resources/catalogue/d04-fixed-block-operator.json'",
                "operator_bytes = (root / relative).read_bytes()",
                "operator_sha = hashlib.sha256(operator_bytes).hexdigest()",
                "entry = next((row for row in manifest['files'] if row['path'] == relative), None)",
                "claim = manifest.get('fixed_block_operator')",
                "assert entry is not None and isinstance(claim, dict)",
                "assert all(claim.get(key) == entry.get(key) for key in ('path', 'sha256', 'bytes'))",
                "assert claim['sha256'] == operator_sha and claim['bytes'] == len(operator_bytes)",
                "assert claim['affect_scheme_sha256'] == scheme.asset_sha256",
                "assert all(claim[name] == getattr(scheme.scheme, name) for name in ('scheme_version', 'operator_version', 'parameter_version', 'coupling_version'))",
                "native = load_production_native(root, trusted_manifest_sha256=sys.argv[2])",
                "assert Path(native.path).resolve().is_relative_to(root)",
                "binding = native.production_binding",
                "assert binding is not None",
                "native_sha = hashlib.sha256(Path(native.path).read_bytes()).hexdigest()",
                "expected = dict(manifest_sha256=sys.argv[2], native_sha256=native_sha, os=manifest['platform']['os'], arch=manifest['platform']['arch'], libc=manifest['platform']['libc'], abi_version=2)",
                "assert all(getattr(binding, field) == value for field, value in expected.items())",
                "assert manifest['native']['sha256'] == native_sha",
                "assert native.capabilities.abi_version == 2 and native.capabilities.supports_fixed_block_interval_math_v1",
                "assert all(Path(module.__file__).resolve().is_relative_to(root) for name, module in sys.modules.items() if (name == 'rewrite' or name.startswith('rewrite.')) and getattr(module, '__file__', None))",
                "print(json.dumps({'manifest_sha256': sys.argv[2], 'scheme_sha256': scheme.asset_sha256, 'operator_sha256': operator_sha, 'catalogue_hash': scheme.registry.type_registry.catalogue_hash, 'abi_version': native.capabilities.abi_version, 'native_sha256': native_sha, 'native_binding': expected, 'd04_product_certified': native.capabilities.numerically_certified and not native.capabilities.diagnostic_only}))",
            ))
            environment = {
                name: value for name, value in os.environ.items()
                if not name.upper().startswith(("PYTHON", "RUST", "CARGO"))
            }
            environment["PATH"] = ""
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-c", code, str(extracted), digest, str(ROOT.resolve()), expected_mode],
                cwd=run_dir, env=environment, check=True, capture_output=True, text=True,
            )
            return {
                "status": ("formal_package_mechanics_only" if expected_mode == "formal-alpha1"
                           else "snapshot_alpha1_test_package_mechanics_only" if expected_mode == "snapshot-alpha1-test"
                           else "alpha2_local_candidate_package_mechanics_only" if expected_mode == "alpha2-candidate"
                           else "backend_candidate_package_mechanics_only"),
                "package_bytes": package.stat().st_size,
                "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                **json.loads(result.stdout),
            }


def cold_verify_formal_package(package: Path, expected_manifest_sha256: str) -> dict:
    return _cold_verify_package(package, expected_manifest_sha256, expected_mode="formal-alpha1")


def cold_verify_backend_candidate_package(package: Path, expected_manifest_sha256: str) -> dict:
    return _cold_verify_package(package, expected_manifest_sha256,
                                expected_mode="backend-alpha1-candidate")


def cold_verify_alpha2_candidate_package(package: Path, expected_manifest_sha256: str) -> dict:
    return _cold_verify_package(package, expected_manifest_sha256, expected_mode="alpha2-candidate")


def main() -> None:
    parser = argparse.ArgumentParser(description="Cold-verify a pinned formal alpha1 ZIP")
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--backend-alpha1-candidate", action="store_true")
    modes.add_argument("--snapshot-alpha1-test", action="store_true")
    modes.add_argument("--alpha2-candidate", action="store_true")
    args = parser.parse_args()
    verifier = (cold_verify_alpha2_candidate_package if args.alpha2_candidate else
                (lambda package, pin: _cold_verify_package(package, pin, expected_mode="snapshot-alpha1-test"))
                if args.snapshot_alpha1_test else cold_verify_backend_candidate_package if args.backend_alpha1_candidate
                else cold_verify_formal_package)
    print(json.dumps(verifier(args.package, args.expected_manifest_sha256), sort_keys=True))


if __name__ == "__main__":
    main()
