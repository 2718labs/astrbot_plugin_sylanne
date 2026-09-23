"""Copy the already-built W11 client as deterministic package resources."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil


FIXED_TIME = 315532800  # 1980-01-01 UTC, also used by the ZIP builder.
FORBIDDEN = {".env", "credentials.json", "secrets.json"}


def prepare(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise FileNotFoundError("W11 build output is absent; run npm run build first")
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    files: list[dict[str, object]] = []
    for item in sorted(source.rglob("*")):
        relative = item.relative_to(source)
        if item.is_symlink() or not item.is_file() or any(part in {"..", "__pycache__", ".playwright-cli", "output"} for part in relative.parts):
            if item.is_symlink(): raise ValueError(f"unsafe workbench asset: {relative}")
            continue
        if item.name.casefold() in FORBIDDEN or item.suffix.casefold() in {".log", ".pyc", ".pem", ".key"}:
            raise ValueError(f"forbidden workbench asset: {relative}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        data = item.read_bytes(); target.write_bytes(data); os.utime(target, (FIXED_TIME, FIXED_TIME))
        files.append({"path": relative.as_posix(), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    if not files or not (destination / "index.html").is_file(): raise RuntimeError("workbench build lacks index.html")
    manifest = {"schema_version": "sylanne.workbench-assets.v1", "source": "webui-src/dist", "files": files,
                "release_eligibility": "HOLD: static asset only; live W09/W10 integration is unverified"}
    (destination / "workbench-manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    os.utime(destination / "workbench-manifest.json", (FIXED_TIME, FIXED_TIME))


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[2]
    prepare(root / "webui-src" / "dist", root / "resources" / "workbench")
