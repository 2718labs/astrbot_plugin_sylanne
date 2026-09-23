"""Generate notices and SBOM from files actually included or hosted by this repository."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def digest(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()


def generate(root: Path) -> None:
    sources = [root / "LICENSE", root / "requirements.txt", root / "webui-src" / "package.json", root / "rewrite" / "native" / "Cargo.lock"]
    if any(not path.is_file() for path in sources): raise FileNotFoundError("legal inventory source is missing")
    evidence = {path.relative_to(root).as_posix(): digest(path) for path in sources}
    notices = "# Third-party notices\n\n"
    notices += "This inventory is generated from the listed source files and only covers bundled dependencies.\n\n"
    notices += "- Sylanne project license: AGPL-3.0-or-later; see `LICENSE`.\n"
    notices += "- `requirements.txt` declares no third-party Python runtime dependency.\n"
    notices += "- `webui-src/package.json` declares no third-party JavaScript dependency.\n"
    notices += "- `rewrite/native/Cargo.lock` contains only the local `sylanne3_kernel` crate.\n"
    notices += "- AstrBot is host-provided and is not represented here as a bundled component.\n\n"
    notices += "Source evidence SHA-256:\n" + "\n".join(f"- `{path}`: `{value}`" for path, value in sorted(evidence.items())) + "\n"
    (root / "THIRD_PARTY_NOTICES.md").write_text(notices, encoding="utf-8")
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": "Sylanne", "licenses": [{"license": {"id": "AGPL-3.0-or-later"}}]}},
            "components": [{"type": "library", "name": "sylanne3_kernel", "version": "0.1.0", "scope": "required", "properties": [{"name": "sylanne:source", "value": "rewrite/native/Cargo.lock"}]},
                           {"type": "application", "name": "sylanne-workbench-client", "version": "0.0.0-dev", "scope": "required", "properties": [{"name": "sylanne:source", "value": "webui-src/package.json"}]}],
            "properties": [{"name": f"sylanne:source-sha256:{path}", "value": value} for path, value in sorted(evidence.items())],
            "externalReferences": []}
    (root / "SBOM.cdx.json").write_text(json.dumps(sbom, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


if __name__ == "__main__": generate(Path(__file__).resolve().parents[2])
