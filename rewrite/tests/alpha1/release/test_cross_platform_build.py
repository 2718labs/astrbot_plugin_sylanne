from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest


SCRIPT = Path(__file__).resolve().parents[4] / "scripts" / "alpha1" / "cross_platform_build.py"
PROBE_SCRIPT = Path(__file__).resolve().parents[4] / "scripts" / "alpha1" / "probe_current_platform_package.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("cross_platform_build", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rust_host_must_match_runtime_profile() -> None:
    script = _load_script()
    assert script.select_rust_target("x86_64-pc-windows-msvc", "windows", "x86_64", None) == "x86_64-pc-windows-msvc"
    assert script.select_rust_target("x86_64-apple-darwin", "macos", "x86_64", None) == "x86_64-apple-darwin"
    assert script.select_rust_target("aarch64-apple-darwin", "macos", "aarch64", None) == "aarch64-apple-darwin"
    assert (
        script.select_rust_target("x86_64-unknown-linux-musl", "linux", "x86_64", "musl") == "x86_64-unknown-linux-musl"
    )
    with pytest.raises(RuntimeError, match="does not match runtime"):
        script.select_rust_target("x86_64-unknown-linux-gnu", "linux", "aarch64", "glibc")
    with pytest.raises(RuntimeError, match="does not match runtime"):
        script.select_rust_target("x86_64-unknown-linux-gnu", "linux", "x86_64", "musl")
    with pytest.raises(RuntimeError, match="does not match runtime"):
        script.select_rust_target("aarch64-apple-darwin", "macos", "x86_64", None)


def test_cold_probe_strips_dynamic_loader_and_toolchain_overrides() -> None:
    spec = importlib.util.spec_from_file_location("probe_current_platform_package", PROBE_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    environment = module._cold_environment(
        {
            "PATH": "host-tools",
            "PYTHONPATH": "source-tree",
            "CARGO_HOME": "cargo-home",
            "DYLD_LIBRARY_PATH": "host-libraries",
            "DYLD_INSERT_LIBRARIES": "injected.dylib",
            "LD_LIBRARY_PATH": "host-libraries",
            "LD_PRELOAD": "injected.so",
            "HOME": "home",
        }
    )

    assert environment == {"PATH": "", "HOME": "home"}


def test_build_selects_host_asset_and_runs_existing_cold_probe(tmp_path: Path) -> None:
    script = _load_script()
    native = tmp_path / "target" / "x86_64-pc-windows-msvc" / "release" / "sylanne3_kernel.dll"
    native.parent.mkdir(parents=True)
    native.write_bytes(b"native fixture")
    calls: list[tuple[list[str], dict | None]] = []

    def run(command, **kwargs):
        environment = kwargs.get("env")
        calls.append((command, environment.copy() if environment is not None else None))
        if command[1] == "-vV":
            return subprocess.CompletedProcess(command, 0, stdout="host: x86_64-pc-windows-msvc\n")
        if command[1].endswith("probe_current_platform_package.py"):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(
                    {
                        "status": "dev_probe_only",
                        "platform": "windows-x86_64",
                        "libc": None,
                        "native": {"binding": {"native_sha256": script.hashlib.sha256(b"native fixture").hexdigest()}},
                    }
                ),
            )
        return subprocess.CompletedProcess(command, 0)

    with (
        patch.object(script, "_runtime_target", return_value=("windows", "x86_64", None)),
        patch.object(script.shutil, "which", side_effect=lambda name: name),
        patch.object(script.subprocess, "run", side_effect=run),
    ):
        result = script.build_and_probe(tmp_path / "packages", tmp_path / "target")

    assert result["rust_target"] == "x86_64-pc-windows-msvc"
    assert result["probe"]["status"] == "dev_probe_only"
    assert calls[1][0][1:5] == ["build", "--locked", "--release", "--target"]
    assert calls[1][0][5] == "x86_64-pc-windows-msvc"
    assert calls[1][1]["CARGO_TARGET_DIR"] == str((tmp_path / "target").resolve())
    assert calls[2][0][0] == sys.executable
    assert calls[2][1]["CARGO_TARGET_DIR"] == str((tmp_path / "target" / "x86_64-pc-windows-msvc").resolve())


def test_missing_toolchain_or_native_asset_fails_closed(tmp_path: Path) -> None:
    script = _load_script()
    with (
        patch.object(script, "_runtime_target", return_value=("windows", "x86_64", None)),
        patch.object(script.shutil, "which", return_value=None),
    ):
        with pytest.raises(RuntimeError, match="Rust host toolchain is required"):
            script.build_and_probe(tmp_path / "packages")

    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="host: x86_64-pc-windows-msvc\n")

    with (
        patch.object(script, "_runtime_target", return_value=("windows", "x86_64", None)),
        patch.object(script.shutil, "which", side_effect=lambda name: name),
        patch.object(script.subprocess, "run", side_effect=run),
    ):
        with pytest.raises(FileNotFoundError, match="without a safe native asset"):
            script.build_and_probe(tmp_path / "packages", tmp_path / "target")
