"""Build and load a non-release package on the current CI host.

The manifest digest used here is read from the package itself. This proves
package/loader mechanics only; it is not a publisher or installer trust root.
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
            archive.extractall(extracted)
        manifest = extracted / "release-manifest.json"
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        code = "\n".join(
            (
                "import json, sys",
                "from pathlib import Path",
                "from rewrite.sylanne3.native_runtime import load_production_native",
                "library = load_production_native(Path(sys.argv[1]), trusted_manifest_sha256=sys.argv[2])",
                "capabilities = library.capabilities",
                "assert capabilities.abi_version == 2 and capabilities.diagnostic_only",
                "assert not capabilities.numerically_certified",
                "print(json.dumps({'abi_version': capabilities.abi_version, 'max_dimension': capabilities.max_dimension, 'diagnostic_only': capabilities.diagnostic_only}))",
            )
        )
        loaded = subprocess.run(
            [sys.executable, "-c", code, str(extracted), digest],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        result = {
            "status": "dev_probe_only",
            "platform": f"{target_os}-{target_arch}",
            "libc": libc,
            "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
            "native": json.loads(loaded.stdout),
        }
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
