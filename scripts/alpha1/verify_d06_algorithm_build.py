"""CLI wrapper for the installed D06 algorithm build verifier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(ROOT)

from sylanne3.host.installed_d06_build import (  # noqa: E402
    ALGORITHM_ID, ENTRY_PATH, KERNEL_PATH, verify_d06_algorithm_build,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify installed D06 C04 algorithm build identity")
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--trusted-manifest-sha256", required=True)
    parser.add_argument("--require-formal", action="store_true")
    args = parser.parse_args()
    print(json.dumps(verify_d06_algorithm_build(
        args.package_root, args.trusted_manifest_sha256,
        require_formal=args.require_formal), sort_keys=True))


if __name__ == "__main__":
    main()
