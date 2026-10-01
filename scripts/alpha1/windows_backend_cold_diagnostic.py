"""Build and cold-load a local Windows backend candidate for diagnostics only.

This proves package bytes, necessary backend assets, and ABI2 loading from an
isolated extraction. It does not install the Authority service or activate the
AstrBot plugin. The manifest digest is self-derived, so it is no trust root.
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
sys.path.insert(0, str(ROOT))

from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(ROOT)

from rewrite.tools.build_plugin_package import build_package, verify_package  # noqa: E402


_D04_OUTPUT_POLICY_PATH = "resources/catalogue/d04-joint-state-output-policy.v1.json"
_D04_OUTPUT_POLICY_SHA256 = "7faef300b10792e3f09d3959b1c6c6e6be4c7abb1a843dcff42e2b12aa250911"


def _verify_d04_output_policy_member(archive: zipfile.ZipFile) -> dict:
    """Check the candidate's exact D04 policy member before cold extraction."""
    manifest = json.loads(archive.read("release-manifest.json"))
    rows = manifest.get("files")
    if not isinstance(rows, list):
        raise ValueError("backend candidate file list is absent")
    matches = [row for row in rows if isinstance(row, dict)
               and row.get("path") == _D04_OUTPUT_POLICY_PATH]
    if len(matches) != 1:
        raise ValueError("D04 joint output policy member is not unique")
    data = archive.read(_D04_OUTPUT_POLICY_PATH)
    digest = hashlib.sha256(data).hexdigest()
    binding = manifest.get("joint_state_output_policy")
    if (digest != _D04_OUTPUT_POLICY_SHA256
            or matches[0].get("sha256") != digest or matches[0].get("bytes") != len(data)
            or not isinstance(binding, dict)
            or any(binding.get(field) != value for field, value in (
                ("path", _D04_OUTPUT_POLICY_PATH), ("sha256", digest),
                ("bytes", len(data)), ("status", "candidate"),
            ))
            or binding.get("axis_ids") != json.loads(data).get("axis_ids")):
        raise ValueError("D04 joint output policy manifest pin differs")
    return {"path": _D04_OUTPUT_POLICY_PATH, "sha256": digest, "bytes": len(data)}


_COLD_CODE = """
import hashlib, json, os, shutil, sys
from pathlib import Path
root = Path(sys.argv[1]).resolve(strict=True)
source = Path(sys.argv[2]).resolve(strict=True)
manifest_sha = sys.argv[3]
assert sys.flags.isolated and sys.flags.no_site
assert os.environ.get('PATH', '') == ''
assert shutil.which('cargo') is None and shutil.which('rustc') is None
assert all(not Path(value).resolve().is_relative_to(source) for value in sys.path if value)
sys.path.insert(0, str(root))
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(root)
from sylanne3.host.installed_package import (
    verify_installed_package, verify_backend_candidate_qualification,
)
from sylanne3.host.installed_d04_output_policy import load_installed_d04_output_policy_v1
from sylanne3.native_runtime import (
    FixedBlockCSR, FixedBlockStep, load_production_native, run_fixed_block_math,
)
installed = verify_installed_package(root, manifest_sha)
assert installed.verified and installed.build_mode == 'backend-alpha1-candidate'
qualified = verify_backend_candidate_qualification(root, manifest_sha)
assert qualified.qualified, qualified
manifest = json.loads((root / 'release-manifest.json').read_bytes())
listed = {entry['path']: entry for entry in manifest['files']}
required = (
    'resources/catalogue/current.json',
    'resources/catalogue/d01-onboarding-presets.json',
    'resources/catalogue/d03-neutral-context-scheme.json',
    'resources/catalogue/d04-affect-scheme.json',
    'resources/catalogue/d04-fixed-block-operator.json',
    'resources/catalogue/d04-tanh-readout.v1.json',
    'resources/catalogue/d04-joint-state-output-policy.v1.json',
    'resources/migrations/v1.json',
)
assets = {}
for relative in required:
    data = (root / relative).read_bytes()
    assert listed[relative]['sha256'] == hashlib.sha256(data).hexdigest()
    assert listed[relative]['bytes'] == len(data)
    json.loads(data)
    assets[relative] = listed[relative]['sha256']
policy = load_installed_d04_output_policy_v1(root, manifest_sha, require_formal=False)
assert policy.build_mode == 'backend-alpha1-candidate'
assert policy.manifest_sha256 == manifest_sha
assert policy.policy_sha256 == assets['resources/catalogue/d04-joint-state-output-policy.v1.json']
assert policy.policy.semantic_calibration == 'unvalidated'
assert len(policy.policy.axis_ids) == 24
native = load_production_native(root, trusted_manifest_sha256=manifest_sha)
assert Path(native.path).resolve().is_relative_to(root)
assert native.capabilities.abi_version == 2
assert native.capabilities.supports_fixed_block_interval_math_v1
binding = native.production_binding
assert binding is not None and binding.manifest_sha256 == manifest_sha
assert binding.native_sha256 == hashlib.sha256(Path(native.path).read_bytes()).hexdigest()
k = FixedBlockCSR(1, 1, (0, 1), (0,), (2.0,))
r = FixedBlockCSR(1, 1, (0, 1), (0,), (1.0,))
zero = FixedBlockCSR(1, 1, (0, 0), (), ())
a = FixedBlockCSR(0, 1, (0,), (), ())
block = FixedBlockStep(k, r, zero, a, (), (0.4,), (0.1,), (0.4,), 0.1, 0.0, 80, 1e-12)
solved = run_fixed_block_math(native, block)
assert solved.bounds.status == 0 and solved.bounds.certificate_flags == 1
assert solved.bounds.iteration_error <= block.tolerance
assert solved.production_binding == binding
assert all(Path(module.__file__).resolve().is_relative_to(root)
           for name, module in sys.modules.items()
           if (name == 'rewrite' or name.startswith('rewrite.'))
           and getattr(module, '__file__', None))
print(json.dumps({
    'installed_package': installed.reason,
    'backend_qualification': qualified.reason,
    'assets': assets,
    'd04_joint_output_policy': {
        'sha256': policy.policy_sha256,
        'algorithm_id': policy.policy.algorithm_id,
        'mode': policy.build_mode,
        'semantic_calibration': policy.policy.semantic_calibration,
    },
    'native_sha256': binding.native_sha256,
    'abi_version': native.capabilities.abi_version,
    'diagnostic_only': native.capabilities.diagnostic_only,
    'native_solve': 'bounded_fixed_block_pass',
}))
"""


def run_diagnostic(output_dir: Path, native: Path) -> dict:
    if os.name != "nt":
        raise RuntimeError("this diagnostic must execute on Windows")
    package = build_package(
        project_root=ROOT, target_os="windows", target_arch="x86_64",
        native_library=native, output_dir=output_dir,
        backend_alpha1_candidate=True,
    )
    verify_package(package)
    with zipfile.ZipFile(package) as archive:
        names = archive.namelist()
        if any(name.startswith(("data/", "artifacts/", "output/"))
               or name.endswith((".db", ".sqlite3", ".log", ".key", ".pem"))
               for name in names):
            raise ValueError("backend candidate includes runtime data or credentials")
        manifest_sha = hashlib.sha256(archive.read("release-manifest.json")).hexdigest()
        policy_member = _verify_d04_output_policy_member(archive)
        with tempfile.TemporaryDirectory(prefix="sylanne-windows-cold-") as directory:
            temporary = Path(directory)
            extracted = temporary / "plugin"
            archive.extractall(extracted)
            run_dir = temporary / "run"
            run_dir.mkdir()
            environment = {
                name: value for name, value in os.environ.items()
                if not name.upper().startswith(("PYTHON", "RUST", "CARGO", "DYLD_", "LD_"))
            }
            environment["PATH"] = ""
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-c", _COLD_CODE,
                 str(extracted), str(ROOT.resolve()), manifest_sha],
                cwd=run_dir, env=environment, capture_output=True, text=True,
            )
            if result.returncode:
                raise RuntimeError("isolated backend candidate load HOLD: " + result.stderr.strip())
            return {
                "status": "diagnostic_only",
                "cold_install_pass": False,
                "service_bootstrap": "absent",
                "publisher_trust_root": "absent",
                "package": str(package),
                "package_bytes": package.stat().st_size,
                "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                "manifest_sha256": manifest_sha,
                "d04_joint_output_policy_member": policy_member,
                "cold_load": json.loads(result.stdout),
            }


def main() -> None:
    parser = argparse.ArgumentParser(description="Windows backend candidate cold-load diagnostic")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--native-library", type=Path,
                        default=ROOT / "rewrite/native/target/release/sylanne3_kernel.dll")
    args = parser.parse_args()
    print(json.dumps(run_diagnostic(args.output_dir, args.native_library), sort_keys=True))


if __name__ == "__main__":
    main()
