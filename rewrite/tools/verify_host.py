"""Verify the root AstrBot adapter against the pinned installed SDK."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

EXPECTED_ASTRBOT = "4.28.1"


def find_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (
            (candidate / "main.py").is_file()
            and (candidate / "rewrite" / "host_tests").is_dir()
            and (candidate / "rewrite" / "sylanne3").is_dir()
        ):
            return candidate
    raise RuntimeError("cannot locate Sylanne plugin root")


def source_manifest(root: Path) -> dict[str, str]:
    patterns = (
        "main.py",
        "metadata.yaml",
        "_conf_schema.json",
        "rewrite/__init__.py",
        "rewrite/sylanne3/*.py",
        "rewrite/native/Cargo.toml",
        "rewrite/native/Cargo.lock",
        "rewrite/native/src/*.rs",
        "rewrite/host_tests/*.py",
        "rewrite/tools/verify_host.py",
        "rewrite/HOST_TESTING.md",
    )
    files: set[Path] = set()
    for pattern in patterns:
        files.update(path for path in root.glob(pattern) if path.is_file())
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(files)
    }


def run(command: list[str], cwd: Path, env: dict[str, str], timeout: int) -> dict:
    started = time.time()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return {
            "command": command,
            "cwd": str(cwd),
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "duration_seconds": round(time.time() - started, 3),
            "passed": completed.returncode == 0,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        stdout = getattr(exc, "stdout", "") or ""
        stderr = getattr(exc, "stderr", "") or str(exc)
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return {
            "command": command,
            "cwd": str(cwd),
            "exit_code": None,
            "stdout": stdout,
            "stderr": stderr,
            "duration_seconds": round(time.time() - started, 3),
            "passed": False,
            "error_type": type(exc).__name__,
        }


def main() -> int:
    root = find_root()
    artifacts = root / "rewrite" / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    receipt_path = artifacts / f"host-verification-{stamp}.json"
    log_path = artifacts / f"host-verification-{stamp}.log"
    before = source_manifest(root)

    try:
        import astrbot

        sdk_version = importlib.metadata.version("AstrBot")
        sdk_source = str(Path(astrbot.__file__).resolve())
        sdk_error = None
    except Exception as exc:
        sdk_version = None
        sdk_source = None
        sdk_error = f"{type(exc).__name__}: {exc}"

    sdk_check = {
        "name": "astrbot_sdk",
        "expected_version": EXPECTED_ASTRBOT,
        "observed_version": sdk_version,
        "source": sdk_source,
        "error": sdk_error,
        "passed": sdk_version == EXPECTED_ASTRBOT and sdk_source is not None,
    }
    results: list[dict] = [sdk_check]
    env = os.environ.copy()
    source_roots = (str(root), str(root / "rewrite"))
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = os.pathsep.join(
        (*source_roots, *((existing,) if existing else ()))
    )
    env["SYLANNE3_PLUGIN_ROOT"] = str(root)

    with tempfile.TemporaryDirectory(prefix="sylanne3-host-") as temp_name:
        temp = Path(temp_name)
        compile_command = [
            sys.executable,
            "-m",
            "py_compile",
            str(root / "main.py"),
            *[str(path) for path in sorted((root / "rewrite" / "sylanne3").glob("*.py"))],
            str(root / "rewrite" / "host_tests" / "test_astrbot_adapter.py"),
        ]
        compile_result = run(compile_command, temp, env, 60)
        compile_result["name"] = "python_compile"
        results.append(compile_result)
        if sdk_check["passed"] and compile_result["passed"]:
            test_result = run(
                [
                    sys.executable,
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    str(root / "rewrite" / "host_tests"),
                    "-p",
                    "test_*.py",
                    "-v",
                ],
                temp,
                env,
                120,
            )
            test_result["name"] = "astrbot_host_unittest"
        else:
            test_result = {
                "name": "astrbot_host_unittest",
                "passed": False,
                "status": "SKIPPED",
                "reason": "SDK version or compilation gate failed",
            }
        results.append(test_result)

    after = source_manifest(root)
    drift = before != after
    results.append(
        {
            "name": "source_drift",
            "passed": not drift,
            "before": before,
            "after": after,
        }
    )
    status = "PASS" if all(item.get("passed", False) for item in results) else "FAIL"
    receipt = {
        "status": status,
        "timestamp_utc": stamp,
        "root": str(root),
        "executable": str(Path(sys.executable).resolve()),
        "python_version": sys.version,
        "astrbot": sdk_check,
        "source_sha256_before": before,
        "source_sha256": after,
        "source_drift": drift,
        "results": results,
        "log": str(log_path),
        "acceptance_boundary": "source-based AstrBot SDK test with controlled provider and platform; no live bot or external model",
    }
    log_parts = []
    for result in results:
        log_parts.append(f"[{result.get('name')}] passed={result.get('passed')}\n")
        if result.get("command"):
            log_parts.append("$ " + " ".join(result["command"]) + "\n")
        log_parts.append(result.get("stdout", ""))
        log_parts.append(result.get("stderr", ""))
        if not log_parts[-1].endswith("\n"):
            log_parts.append("\n")
    log_path.write_text("".join(log_parts), encoding="utf-8")
    receipt_path.write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "status": status,
                "receipt": str(receipt_path),
                "log": str(log_path),
                "executable": receipt["executable"],
                "astrbot_version": sdk_version,
                "astrbot_source": sdk_source,
            },
            ensure_ascii=False,
        )
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
