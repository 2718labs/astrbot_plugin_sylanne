"""Isolated import check for a pinned Authority staging ZIP, not a cold install."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from authority_staging_package import verify_staging_authority


_PROBE = """
import importlib, json, os, sys
from pathlib import Path
root = Path(sys.argv[1]).resolve(strict=True)
source = Path(sys.argv[2]).resolve(strict=True)
assert sys.flags.isolated and sys.flags.no_site
assert not any(Path(part).resolve().is_relative_to(source) for part in sys.path if part)
sys.path.insert(0, str(root))
entries = (
    'rewrite.sylanne3.authority_service.daemon',
    'rewrite.sylanne3.authority_service.admin_cli',
    'scripts.alpha1.verify_d06_algorithm_build',
    'rewrite.sylanne3.domains.d06.c04_work_input_v2',
)
for name in entries:
    module = importlib.import_module(name)
    assert Path(module.__file__).resolve().is_relative_to(root)
assert all(Path(module.__file__).resolve().is_relative_to(root)
           for name, module in sys.modules.items()
           if (name == 'rewrite' or name.startswith('rewrite.'))
           and getattr(module, '__file__', None))
print(json.dumps({'imported': list(entries), 'isolated': True}))
"""


def isolated_import_probe(package: Path, expected_manifest_sha256: str) -> dict:
    verified = verify_staging_authority(
        package, expected_manifest_sha256=expected_manifest_sha256,
    )
    with tempfile.TemporaryDirectory(prefix="sylanne-authority-staging-") as directory:
        temporary = Path(directory)
        extracted = temporary / "authority"
        extracted.mkdir()
        with zipfile.ZipFile(package) as archive:
            archive.extractall(extracted)
        run_dir = temporary / "run"
        run_dir.mkdir()
        environment = {
            name: value for name, value in os.environ.items()
            if not name.upper().startswith(("PYTHON", "RUST", "CARGO"))
        }
        environment["PATH"] = ""
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-c", _PROBE,
             str(extracted), str(Path(__file__).resolve().parents[2])],
            cwd=run_dir, env=environment, check=True, capture_output=True,
            text=True,
        )
        return {**verified, **json.loads(result.stdout), "cold_install_pass": False}


def main() -> None:
    parser = argparse.ArgumentParser(description="Probe pinned Authority staging ZIP imports")
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(isolated_import_probe(args.package, args.expected_manifest_sha256), sort_keys=True))


if __name__ == "__main__":
    main()
