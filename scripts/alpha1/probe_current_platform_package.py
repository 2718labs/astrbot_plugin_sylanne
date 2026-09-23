"""Build and cold-load a non-release package on the current CI host.

The manifest digest used here is read from the package itself. This proves
package/loader mechanics only; it is not a publisher or installer trust root,
or a real AstrBot installation.
"""

from __future__ import annotations

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
            output_dir=temporary / "package",
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
                "import json, os, shutil, sys",
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
                "from rewrite.sylanne3.native_runtime import load_production_native",
                "library = load_production_native(package_root, trusted_manifest_sha256=sys.argv[3])",
                "assert Path(library.path).resolve() == (package_root / sys.argv[8]).resolve()",
                "assert all(Path(module.__file__).resolve().is_relative_to(package_root) for name, module in sys.modules.items() if (name == 'rewrite' or name.startswith('rewrite.')) and getattr(module, '__file__', None))",
                "capabilities = library.capabilities",
                "assert capabilities.abi_version == 2 and capabilities.diagnostic_only",
                "assert not capabilities.numerically_certified",
                "assert capabilities.supports_fixed_block_interval_math_v1",
                "binding = library.production_binding",
                "if binding is None: raise AssertionError('loaded native has no production binding')",
                "expected = dict(manifest_sha256=sys.argv[3], native_sha256=sys.argv[4], os=sys.argv[5], arch=sys.argv[6], libc=json.loads(sys.argv[7]), abi_version=2)",
                "for field, value in expected.items():",
                "    if getattr(binding, field) != value: raise AssertionError(f'native binding {field} mismatch')",
                "print(json.dumps({'abi_version': capabilities.abi_version, 'max_dimension': capabilities.max_dimension, 'fixed_block_interval_math_v1': capabilities.supports_fixed_block_interval_math_v1, 'numerically_certified': capabilities.numerically_certified, 'diagnostic_only': capabilities.diagnostic_only, 'binding': expected}))",
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
            "platform": f"{target_os}-{target_arch}",
            "libc": libc,
            "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
            "cold_load": "isolated_python_without_source_path_or_rust",
            "native": json.loads(loaded.stdout),
        }
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
