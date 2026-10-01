"""Sync W11's built Vue workbench into the plugin's packaged resources."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


FORBIDDEN_NAMES = {".env", "credentials.json", "secrets.json"}
FORBIDDEN_SUFFIXES = {".log", ".pyc", ".pem", ".key", ".sqlite", ".sqlite3"}
SOURCE_ID = "webui-heritage"
BUILD_OUTPUT = Path("webui-heritage/dist/index.html")
RESOURCE_FILES = {Path("index.html"), Path("workbench-manifest.json")}


def prepare(project_root: Path) -> None:
    root = project_root.resolve()
    source = root / SOURCE_ID
    build_output = root / BUILD_OUTPUT
    destination = root / "resources" / "workbench"
    if source.is_symlink() or not source.is_dir():
        raise ValueError("workbench source must be the declared webui-heritage directory")
    if any(path.is_symlink() for path in (source / "dist", build_output)) or not build_output.is_file():
        raise FileNotFoundError("webui-heritage build output dist/index.html is missing or unsafe")
    if not destination.is_dir() or destination.is_symlink():
        raise FileNotFoundError("tracked workbench resource directory is missing or unsafe")

    tracked = subprocess.check_output(
        ["git", "ls-files", "-z", "--", "resources/workbench"], cwd=root,
    )
    tracked_files = {
        Path(path.decode("utf-8")).relative_to("resources/workbench")
        for path in tracked.split(b"\0") if path
    }
    if RESOURCE_FILES - tracked_files:
        raise ValueError("built workbench output targets must already be tracked resources")

    for item in destination.rglob("*"):
        if item.is_symlink():
            raise ValueError(f"unsafe workbench resource symlink: {item.relative_to(destination)}")
        if item.is_file():
            relative = item.relative_to(destination)
            if relative not in tracked_files and relative not in RESOURCE_FILES:
                raise ValueError(f"untracked file in workbench resource directory: {relative}")

    data = build_output.read_bytes()
    if not data.strip():
        raise ValueError("webui-heritage build output is empty")
    files = [{"path": "index.html", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}]
    manifest = {
        "schema_version": "sylanne.workbench-assets.v1",
        "source": SOURCE_ID,
        "build_output": BUILD_OUTPUT.as_posix(),
        "files": files,
        "release_eligibility": "HOLD: static asset only; live W09/W10 integration is unverified",
    }
    targets = {Path("index.html"): data,
               Path("workbench-manifest.json"): (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")}
    for relative, content in targets.items():
        (destination / relative).write_bytes(content)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    root = args.project_root.resolve()
    prepare(root)


if __name__ == "__main__":
    main()
