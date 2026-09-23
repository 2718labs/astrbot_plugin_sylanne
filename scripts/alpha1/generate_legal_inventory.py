"""Generate a local, evidence-backed inventory of native runtime dependencies."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tomllib


SOURCE_FILES = ("LICENSE", "requirements.txt", "webui-src/package.json",
                "rewrite/native/Cargo.toml", "rewrite/native/Cargo.lock")
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native_dependencies(root: Path) -> list[dict[str, str]]:
    native = root / "rewrite" / "native"
    locked = tomllib.loads((native / "Cargo.lock").read_text(encoding="utf-8"))
    lock_packages = {(item["name"], item["version"], item.get("source")): item
                     for item in locked["package"]}
    try:
        result = subprocess.run(
            ("cargo", "metadata", "--offline", "--locked", "--format-version", "1",
             "--manifest-path", str(native / "Cargo.toml")),
            cwd=root, capture_output=True, text=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) else str(error)
        raise RuntimeError(f"HOLD: offline locked Cargo metadata unavailable: {detail}") from error
    metadata = json.loads(result.stdout)
    packages = {item["id"]: item for item in metadata["packages"]}
    nodes = {item["id"]: item for item in metadata["resolve"]["nodes"]}
    root_id = metadata["resolve"]["root"]
    if root_id is None or packages[root_id]["name"] != "sylanne3_kernel":
        raise ValueError("unexpected native Cargo root")

    # Union across targets; build and development dependencies are not runtime components.
    visited = set()
    pending = [root_id]
    while pending:
        package_id = pending.pop()
        if package_id in visited:
            continue
        visited.add(package_id)
        for edge in nodes[package_id]["deps"]:
            if any(kind["kind"] is None for kind in edge["dep_kinds"]):
                pending.append(edge["pkg"])

    dependencies = []
    for package_id in visited - {root_id}:
        package = packages[package_id]
        key = package["name"], package["version"], package["source"]
        locked_package = lock_packages.get(key)
        if package["source"] != REGISTRY or not locked_package or not locked_package.get("checksum"):
            raise ValueError(f"unverified locked registry dependency: {key}")
        manifest_path = Path(package["manifest_path"])
        if not manifest_path.is_file():
            raise FileNotFoundError(f"HOLD: downloaded crate metadata missing for {key}")
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))["package"]
        if (manifest.get("name"), manifest.get("version")) != key[:2]:
            raise ValueError(f"HOLD: downloaded crate metadata identity mismatch for {key}")
        license_value = manifest.get("license")
        if not isinstance(license_value, str) or not license_value.strip():
            raise ValueError(f"HOLD: downloaded crate license metadata missing for {key}")
        dependencies.append({"name": key[0], "version": key[1],
                             "license": license_value, "checksum": locked_package["checksum"],
                             "metadata_sha256": digest(manifest_path)})
    return sorted(dependencies, key=lambda item: (item["name"], item["version"]))


def generate(root: Path) -> None:
    sources = {relative: root / relative for relative in SOURCE_FILES}
    missing = [relative for relative, path in sources.items() if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"legal inventory source is missing: {', '.join(missing)}")
    dependencies = native_dependencies(root)
    evidence = {relative: digest(path) for relative, path in sources.items()}
    notices = [
        "# Third-party notices", "",
        "This inventory records the native production dependency closure across Cargo targets. "
        "License values below are copied from the downloaded, locked crate Cargo.toml metadata; "
        "they are not a legal review or a formal release acceptance.", "",
        "- Sylanne project license: AGPL-3.0-or-later; see `LICENSE`.",
        "- `requirements.txt` declares no third-party Python runtime dependency.",
        "- `webui-src/package.json` declares no third-party JavaScript dependency.",
        "- AstrBot is host-provided and is not represented as a bundled component.", "",
        "Native third-party production dependencies (name, version, declared license):", "",
    ]
    notices.extend(f"- `{item['name']} {item['version']}`: `{item['license']}` "
                   f"(crate SHA-256 `{item['checksum']}`; Cargo.toml SHA-256 "
                   f"`{item['metadata_sha256']}`)." for item in dependencies)
    notices.extend(["", "Source evidence SHA-256:"])
    notices.extend(f"- `{path}`: `{value}`" for path, value in sorted(evidence.items()))
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": "Sylanne",
                                    "licenses": [{"license": {"id": "AGPL-3.0-or-later"}}]}},
        "components": [
            {"type": "library", "name": "sylanne3_kernel", "version": "0.1.0", "scope": "required",
             "properties": [{"name": "sylanne:source", "value": "rewrite/native/Cargo.lock"}]},
            {"type": "application", "name": "sylanne-workbench-client", "version": "0.0.0-dev",
             "scope": "required", "properties": [{"name": "sylanne:source", "value": "webui-src/package.json"}]},
            *({"type": "library", "name": item["name"], "version": item["version"],
               "scope": "required", "purl": f"pkg:cargo/{item['name']}@{item['version']}",
               "licenses": [{"license": {"name": item["license"]}}],
               "hashes": [{"alg": "SHA-256", "content": item["checksum"]}],
               "properties": [{"name": "sylanne:cargo-toml-sha256", "value": item["metadata_sha256"]}]}
              for item in dependencies),
        ],
        "properties": [{"name": f"sylanne:source-sha256:{path}", "value": value}
                       for path, value in sorted(evidence.items())],
        "externalReferences": [],
    }
    (root / "THIRD_PARTY_NOTICES.md").write_text("\n".join(notices) + "\n", encoding="utf-8")
    (root / "SBOM.cdx.json").write_text(
        json.dumps(sbom, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


if __name__ == "__main__":
    generate(Path(__file__).resolve().parents[2])
