"""Generate a local, evidence-backed inventory of native runtime dependencies."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tomllib
from urllib.parse import quote


SOURCE_FILES = ("LICENSE", "requirements.txt", "webui-heritage/package.json",
                "webui-heritage/pnpm-lock.yaml", "rewrite/native/Cargo.toml",
                "rewrite/native/Cargo.lock")
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


def javascript_dependencies(root: Path) -> list[dict[str, str]]:
    """Inventory the installed production dependency closure from pnpm."""
    project = root / "webui-heritage"
    pnpm = shutil.which("pnpm.cmd") or shutil.which("pnpm")
    if pnpm is None:
        raise RuntimeError("HOLD: pnpm is required to inspect the frozen workbench dependencies")
    try:
        result = subprocess.run(
            (pnpm, "--dir", str(project), "list", "--prod", "--json", "--depth", "Infinity"),
            cwd=root, capture_output=True, text=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) else str(error)
        raise RuntimeError(f"HOLD: pnpm production dependency inventory unavailable: {detail}") from error
    try:
        documents = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("HOLD: pnpm returned invalid production dependency JSON") from error
    if not isinstance(documents, list) or len(documents) != 1 or not isinstance(documents[0], dict):
        raise ValueError("unexpected pnpm production dependency root")
    app = documents[0]
    package = json.loads((project / "package.json").read_text(encoding="utf-8"))
    direct = package.get("dependencies")
    if not isinstance(direct, dict) or not direct:
        raise ValueError("webui-heritage must declare production dependencies")
    installed_direct = app.get("dependencies")
    if not isinstance(installed_direct, dict) or set(installed_direct) != set(direct):
        raise ValueError("installed production dependencies differ from package.json")

    closure: dict[tuple[str, str], bool] = {}
    pending = [(name, item, True) for name, item in installed_direct.items()]
    while pending:
        name, item, is_direct = pending.pop()
        if not isinstance(item, dict) or not isinstance(item.get("version"), str):
            raise ValueError(f"invalid pnpm dependency record: {name}")
        version = item["version"]
        key = name, version
        closure[key] = closure.get(key, False) or is_direct
        dependencies = item.get("dependencies", {})
        if not isinstance(dependencies, dict):
            raise ValueError(f"invalid nested pnpm dependencies: {name}@{version}")
        pending.extend((dependency_name, dependency, False)
                       for dependency_name, dependency in dependencies.items())

    metadata_by_package: dict[tuple[str, str], dict[str, str]] = {}
    store = project / "node_modules" / ".pnpm"
    if not store.is_dir():
        raise FileNotFoundError("pnpm virtual store is missing")
    for virtual_package in store.iterdir():
        modules = virtual_package / "node_modules"
        if not modules.is_dir() or modules.is_symlink():
            continue
        package_files = (*modules.glob("*/package.json"), *modules.glob("@*/*/package.json"))
        for package_path in package_files:
            if package_path.is_symlink():
                continue
            metadata_bytes = package_path.read_bytes()
            metadata = json.loads(metadata_bytes)
            name, version = metadata.get("name"), metadata.get("version")
            key = (name, version)
            if key not in closure:
                continue
            license_value = metadata.get("license")
            if isinstance(license_value, dict):
                license_value = license_value.get("type")
            if not isinstance(license_value, str) or not license_value.strip():
                raise ValueError(f"installed package license metadata missing: {name}@{version}")
            row = {"name": name, "version": version, "license": license_value,
                   "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest()}
            previous = metadata_by_package.get(key)
            if previous is not None and previous != row:
                raise ValueError(f"installed package metadata conflicts: {name}@{version}")
            metadata_by_package[key] = row
    for key, is_direct in closure.items():
        if is_direct and key not in metadata_by_package:
            raise FileNotFoundError(f"direct production package metadata is missing: {key[0]}@{key[1]}")
    return sorted(metadata_by_package.values(), key=lambda item: (item["name"], item["version"]))


def generate(root: Path) -> None:
    sources = {relative: root / relative for relative in SOURCE_FILES}
    missing = [relative for relative, path in sources.items() if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"legal inventory source is missing: {', '.join(missing)}")
    dependencies = native_dependencies(root)
    js_dependencies = javascript_dependencies(root)
    frontend = json.loads((root / "webui-heritage" / "package.json").read_text(encoding="utf-8"))
    evidence = {relative: digest(path) for relative, path in sources.items()}
    notices = [
        "# Third-party notices", "",
        "This inventory records the pnpm production dependency closure and native Cargo production dependency closure. "
        "JavaScript licenses are copied from the installed production dependency closure; optional packages absent for this build host are not included. Native licenses are copied from locked crate metadata. "
        "These records are not a legal review or formal release acceptance.", "",
        "- Sylanne project license: AGPL-3.0-or-later; see `LICENSE`.",
        "- `requirements.txt` declares no third-party Python runtime dependency.",
        "- `webui-heritage/package.json` declares the Vue workbench production dependency closure below; its source is bundled into `resources/workbench/index.html`.",
        "- AstrBot is host-provided and is not represented as a bundled component.", "",
        "Workbench production dependencies (name, version, declared license):", "",
    ]
    notices.extend(f"- `{item['name']} {item['version']}`: `{item['license']}` "
                   f"(package.json SHA-256 `{item['metadata_sha256']}`)." for item in js_dependencies)
    notices.extend(["", "Native third-party production dependencies (name, version, declared license):", ""])
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
            {"type": "application", "name": frontend.get("name", "sylanne-workbench-client"), "version": frontend.get("version", "0.0.0-dev"),
             "scope": "required", "properties": [{"name": "sylanne:source", "value": "webui-heritage/package.json"}]},
            *({"type": "library", "name": item["name"], "version": item["version"],
               "scope": "required", "purl": f"pkg:npm/{quote(item['name'], safe='/')}@{item['version']}",
               "licenses": [{"license": {"name": item["license"]}}],
               "hashes": [{"alg": "SHA-256", "content": item["metadata_sha256"]}],
               "properties": [{"name": "sylanne:package-json-sha256", "value": item["metadata_sha256"]}]}
              for item in js_dependencies),
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
