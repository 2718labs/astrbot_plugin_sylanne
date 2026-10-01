"""Build and cold-load a local alpha1 dev probe on the current host.

Run this separately on each supported OS/architecture/libc host. A successful
run proves only that host's package mechanics; it does not publish a release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(ROOT)

from sylanne3.native_runtime.loader import CANONICAL_LIBRARIES, _runtime_target  # noqa: E402


def select_rust_target(host: str, target_os: str, target_arch: str, libc: str | None) -> str:
    """Require rustc's native target to match the package loader's platform."""
    allowed = {
        ("windows", "x86_64", None): {
            "x86_64-pc-windows-msvc",
            "x86_64-pc-windows-gnu",
        },
        ("linux", "x86_64", "glibc"): {"x86_64-unknown-linux-gnu"},
        ("linux", "aarch64", "glibc"): {"aarch64-unknown-linux-gnu"},
        ("linux", "x86_64", "musl"): {"x86_64-unknown-linux-musl"},
        ("linux", "aarch64", "musl"): {"aarch64-unknown-linux-musl"},
        ("macos", "x86_64", None): {"x86_64-apple-darwin"},
        ("macos", "aarch64", None): {"aarch64-apple-darwin"},
    }.get((target_os, target_arch, libc), set())
    if host not in allowed:
        raise RuntimeError(
            f"rustc host {host!r} does not match runtime "
            f"{target_os}-{target_arch}-{libc}; run on a matching host/toolchain"
        )
    return host


def build_and_probe(output_dir: Path, target_dir: Path | None = None,
                    *, backend_only_dev_probe: bool = False) -> dict:
    target_os, target_arch, libc = _runtime_target()
    rustc = shutil.which("rustc")
    cargo = shutil.which("cargo")
    if rustc is None or cargo is None:
        raise RuntimeError("Rust host toolchain is required: rustc and cargo must be on PATH")
    version = subprocess.run(
        [rustc, "-vV"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    hosts = [line.removeprefix("host: ").strip() for line in version.splitlines() if line.startswith("host: ")]
    if len(hosts) != 1:
        raise RuntimeError("rustc -vV did not report exactly one host target")
    rust_target = select_rust_target(hosts[0], target_os, target_arch, libc)

    build_dir = (target_dir or ROOT / "rewrite" / "native" / "target").resolve()
    native = build_dir / rust_target / "release" / CANONICAL_LIBRARIES[target_os]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(build_dir)
    subprocess.run(
        [
            cargo,
            "build",
            "--locked",
            "--release",
            "--target",
            rust_target,
            "--manifest-path",
            str(ROOT / "rewrite" / "native" / "Cargo.toml"),
        ],
        cwd=ROOT,
        env=environment,
        check=True,
    )
    if not native.is_file() or native.is_symlink():
        raise FileNotFoundError(f"cargo succeeded without a safe native asset: {native}")
    native_sha256 = hashlib.sha256(native.read_bytes()).hexdigest()

    # The existing probe expects CARGO_TARGET_DIR/release. Point it at the
    # selected target subdirectory so its package and isolated load use this build.
    environment["CARGO_TARGET_DIR"] = str(build_dir / rust_target)
    probe_command = [
            sys.executable,
            str(ROOT / "scripts" / "alpha1" / "probe_current_platform_package.py"),
            "--output-dir",
            str(output_dir.resolve()),
    ]
    if backend_only_dev_probe:
        probe_command.append("--backend-only-dev-probe")
    result = subprocess.run(
        probe_command,
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    probe = json.loads(result.stdout)
    if probe.get("status") != "dev_probe_only" or probe.get("platform") != f"{target_os}-{target_arch}":
        raise RuntimeError("current-platform cold probe reported an unexpected build or platform")
    binding = probe.get("native", {}).get("binding", {})
    if binding.get("native_sha256") != native_sha256 or probe.get("libc") != libc:
        raise RuntimeError("cold probe did not load the selected native asset and libc")
    return {
        "status": "dev_probe_only",
        "rust_target": rust_target,
        "rustc_version": version.splitlines()[0],
        "native_sha256": native_sha256,
        "probe": probe,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True, help="directory for the local dev-probe ZIP")
    parser.add_argument("--target-dir", type=Path, help="Cargo build directory (default: rewrite/native/target)")
    parser.add_argument("--backend-only-dev-probe", action="store_true",
                        help="build a non-release candidate without unfinished workbench assets")
    args = parser.parse_args()
    print(json.dumps(build_and_probe(args.output_dir, args.target_dir,
                                     backend_only_dev_probe=args.backend_only_dev_probe), sort_keys=True))


if __name__ == "__main__":
    main()
