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

from rewrite.tools.build_plugin_package import verify_package  # noqa: E402


def cold_verify_formal_package(package: Path, expected_manifest_sha256: str) -> dict:
    """Verify a formal ZIP and load its D04 scheme and ABI2 library in isolation."""
    verify_package(package)
    with zipfile.ZipFile(package) as archive:
        manifest_bytes = archive.read("release-manifest.json")
        manifest = json.loads(manifest_bytes)
        if manifest.get("build_mode") != "formal-alpha1":
            raise ValueError("cold formal install requires a formal-alpha1 ZIP")
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
                "import json, os, sys",
                "from pathlib import Path",
                "root = Path(sys.argv[1]).resolve()",
                "assert sys.flags.isolated and sys.flags.no_site",
                "assert os.environ.get('PATH', '') == ''",
                "sys.path.insert(0, str(root))",
                "from rewrite.sylanne3.host.installed_package import verify_installed_package",
                "from rewrite.sylanne3.host.affect_scheme_asset import load_verified_affect_scheme",
                "from rewrite.sylanne3.native_runtime import load_production_native",
                "installed = verify_installed_package(root, sys.argv[2])",
                "assert installed.verified and installed.build_mode == 'formal-alpha1', installed",
                "scheme = load_verified_affect_scheme(root, sys.argv[2])",
                "native = load_production_native(root, trusted_manifest_sha256=sys.argv[2])",
                "assert Path(native.path).resolve().is_relative_to(root)",
                "assert all(Path(module.__file__).resolve().is_relative_to(root) for name, module in sys.modules.items() if (name == 'rewrite' or name.startswith('rewrite.')) and getattr(module, '__file__', None))",
                "print(json.dumps({'manifest_sha256': sys.argv[2], 'scheme_sha256': scheme.asset_sha256, 'catalogue_hash': scheme.registry.type_registry.catalogue_hash, 'abi_version': native.capabilities.abi_version}))",
            ))
            environment = {
                name: value for name, value in os.environ.items()
                if not name.upper().startswith(("PYTHON", "RUST", "CARGO"))
            }
            environment["PATH"] = ""
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-c", code, str(extracted), digest],
                cwd=run_dir, env=environment, check=True, capture_output=True, text=True,
            )
            return json.loads(result.stdout)


def main() -> None:
    parser = argparse.ArgumentParser(description="Cold-verify a pinned formal alpha1 ZIP")
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(cold_verify_formal_package(args.package, args.expected_manifest_sha256), sort_keys=True))


if __name__ == "__main__":
    main()
