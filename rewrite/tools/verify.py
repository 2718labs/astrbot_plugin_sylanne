"""Run the foundation-slice checks and write an auditable verification receipt."""
from __future__ import annotations

import ast
import compileall
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone


FORBIDDEN = ("sylanne_alpha", "v2core", "_engine", "v3core")


def find_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in (here.parent.parent, *here.parents):
        if (candidate / "CONTRACT.md").is_file() and (candidate / "native" / "Cargo.toml").is_file():
            return candidate
    raise RuntimeError("cannot locate rewrite root")


def boundary_check(root: Path) -> dict:
    scanned = []
    violations = []
    repo_root = root.parent
    bases = (root / "sylanne3", root / "tools")
    repo_root = root.parent
    entry_points = (repo_root / "main.py", repo_root / "__init__.py", root / "__init__.py")
    paths = [path for path in entry_points if path.is_file()]
    for base in bases:
        if not base.is_dir():
            continue
        paths.extend(base.rglob("*.py"))
    for path in sorted(paths):
        scanned.append(str(path.relative_to(repo_root)))
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""] + [a.name for a in node.names]
            else:
                continue
            for name in names:
                if any(part in name.split(".") for part in FORBIDDEN):
                    violations.append({"file": str(path.relative_to(repo_root)), "name": name})
    return {"scanned": scanned, "violations": violations, "passed": not violations}


def run_command(name: str, command: list[str], cwd: Path, env: dict[str, str], log, timeout: int) -> dict:
    started = time.time()
    elapsed = time.time() - started
    try:
        proc = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True,
                              timeout=timeout)
        result = {"name": name, "command": command, "exit_code": proc.returncode,
                  "duration_seconds": round(time.time() - started, 3), "stdout": proc.stdout,
                  "stderr": proc.stderr, "timeout_seconds": timeout,
                  "passed": proc.returncode == 0}
    except (OSError, subprocess.TimeoutExpired) as exc:
        stdout = getattr(exc, "stdout", "") or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        stderr = getattr(exc, "stderr", "") or str(exc)
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        result = {"name": name, "command": command, "exit_code": None,
                  "duration_seconds": round(time.time() - started, 3), "stdout": stdout,
                  "stderr": stderr, "timeout_seconds": timeout, "passed": False,
                  "error_type": type(exc).__name__}
    log.write(f"\n$ {' '.join(command)}\n{result['stdout']}{result['stderr']}")
    return result


def source_manifest(root: Path) -> dict:
    files = []
    repo_root = root.parent
    for pattern in ("main.py", "__init__.py", "metadata.yaml", "_conf_schema.json"):
        files.extend(repo_root.glob(pattern))
    for pattern in ("__init__.py", "sylanne3/*.py", "native/src/*.rs", "native/Cargo.toml", "native/Cargo.lock", "tests/*.py", "tools/*.py"):
        files.extend(root.glob(pattern))
    manifest = {}
    for path in sorted(set(files)):
        if not path.is_file():
            continue
        manifest[str(path.relative_to(repo_root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return manifest


def git_info(root: Path) -> dict:
    def git(*args: str) -> str:
        try:
            return subprocess.run(["git", *args], cwd=root.parent, text=True,
                                  capture_output=True, check=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return "unavailable"
    return {"head": git("rev-parse", "HEAD"), "branch": git("branch", "--show-current")}


def main() -> int:
    root = find_root()
    artifacts = root / "artifacts"
    artifacts.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    log_path = artifacts / f"verification-{stamp}.log"
    receipt_path = artifacts / f"verification-{stamp}.json"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    results = []
    with log_path.open("w", encoding="utf-8") as log:
        boundary = boundary_check(root)
        log.write(json.dumps(boundary, ensure_ascii=False, indent=2) + "\n")
        results.append({"name": "ast_boundary", **boundary})
        commands = [
            ("cargo_fmt_check", ["cargo", "fmt", "--check"]),
            ("cargo_check", ["cargo", "check"]),
            ("cargo_test", ["cargo", "test"]),
            ("cargo_build_release", ["cargo", "build", "--release"]),
        ]
        before_source = source_manifest(root)
        failed = not boundary["passed"]
        for name, command in commands:
            if failed:
                results.append({"name": name, "command": command, "status": "SKIPPED", "passed": False})
                continue
            result = run_command(name, command, root / "native", env, log, 180 if name in ("cargo_test", "cargo_build_release") else 120)
            results.append(result)
            failed = not result["passed"]
        if failed:
            results.append({"name": "python_unittest", "status": "SKIPPED", "passed": False})
            results.append({"name": "python_compileall", "status": "SKIPPED", "passed": False})
        else:
            results.append(run_command("python_unittest", [sys.executable, "-m", "unittest", "discover", "-s", "rewrite/tests", "-p", "test_*.py", "-v"], root.parent, env, log, 180))
            started = time.time()
            compiled = compileall.compile_dir(str(root / "sylanne3"), quiet=1, force=False)
            for entry_point in (root.parent / "main.py", root.parent / "__init__.py", root / "__init__.py"):
                if entry_point.is_file():
                    compiled = compileall.compile_file(str(entry_point), quiet=1, force=False) and compiled
            results.append({"name": "python_compileall", "passed": compiled,
                            "duration_seconds": round(time.time() - started, 3)})
    after_source = source_manifest(root)
    drift = before_source != after_source
    if drift:
        results.append({"name": "source_drift", "passed": False, "before": before_source, "after": after_source})
    receipt = {"status": "PASS" if all(r.get("passed", False) for r in results) and not drift else "FAIL",
               "root": str(root), "timestamp_utc": stamp, "results": results,
               "git": git_info(root), "source_sha256": after_source,
               "source_sha256_before": before_source, "source_drift": drift,
               "log": str(log_path), "static_boundary_check": True}
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "receipt": str(receipt_path), "log": str(log_path)}, ensure_ascii=False))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
