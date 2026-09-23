"""Sync the W11 source client into its tracked package resources."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess


FIXED_TIME = 315532800  # 1980-01-01 UTC, also used by the ZIP builder.
FORBIDDEN = {".env", "credentials.json", "secrets.json"}


def prepare(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise FileNotFoundError("W11 source client is absent")
    if not destination.is_dir():
        raise FileNotFoundError("tracked W11 resource directory is absent")
    source_files = {Path("index.html"), *(path.relative_to(source) for path in (source / "src").rglob("*") if path.is_file())}
    destination_files = {path.relative_to(destination) for path in destination.rglob("*") if path.is_file() and path.name != "workbench-manifest.json"}
    if source_files != destination_files:
        raise ValueError("W11 source and tracked resource file sets differ")
    root = destination.parents[1]
    tracked = subprocess.check_output(["git", "ls-files", "-z", "--", "resources/workbench"], cwd=root)
    tracked_files = {Path(path.decode("utf-8")).relative_to("resources/workbench") for path in tracked.split(b"\0") if path}
    if source_files | {Path("workbench-manifest.json")} != tracked_files:
        raise ValueError("W11 sync targets must be tracked resources")
    files: list[dict[str, object]] = []
    for relative in sorted(source_files):
        item = source / relative
        if item.is_symlink() or (destination / relative).is_symlink():
            raise ValueError(f"unsafe workbench asset: {relative}")
        if item.name.casefold() in FORBIDDEN or item.suffix.casefold() in {".log", ".pyc", ".pem", ".key"}:
            raise ValueError(f"forbidden workbench asset: {relative}")
        target = destination / relative
        data = item.read_bytes(); target.write_bytes(data); os.utime(target, (FIXED_TIME, FIXED_TIME))
        files.append({"path": relative.as_posix(), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    manifest = {"schema_version": "sylanne.workbench-assets.v1", "source": "webui-src", "files": files,
                "release_eligibility": "HOLD: static asset only; live W09/W10 integration is unverified"}
    (destination / "workbench-manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    os.utime(destination / "workbench-manifest.json", (FIXED_TIME, FIXED_TIME))


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[2]
    prepare(root / "webui-src", root / "resources" / "workbench")
