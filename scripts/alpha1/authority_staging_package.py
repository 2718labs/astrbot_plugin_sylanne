"""Build and inspect a diagnostic Authority staging ZIP.

This is not an installer or a Windows service. It never copies durable state,
TLS material or a Python runtime. An explicit wheelhouse may supply exact
locked third-party wheels for offline installation into private staging.
"""

from __future__ import annotations

import argparse
import ast
from email.parser import BytesParser
from email.policy import default as email_policy
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINTS = (
    "rewrite.sylanne3.authority_service.daemon",
    "rewrite.sylanne3.authority_service.admin_cli",
    "rewrite.sylanne3.authority_service.installed_core_verifiers",
    "rewrite.sylanne3.authority_service.installed_policy",
    "rewrite.sylanne3.domains.d06.c04_work_input_v2",
    "rewrite.sylanne3.host.installed_d06_build",
    "rewrite.sylanne3.memory_association",
)
LOCK_PATH = "requirements-authority.txt"
MANIFEST_PATH = "authority-staging-manifest.json"
NOTICES_PATH = "authority-third-party-notices.md"
SBOM_PATH = "authority-sbom.cdx.json"
SERVICE_SOURCE = (
    "scripts/alpha1/authority_windows_service.py",
    "scripts/alpha1/authority_windows_scm.py",
    "scripts/alpha1/authority_installer.py",
    "scripts/alpha1/authority_staging_package.py",
    "scripts/alpha1/verify_d06_algorithm_build.py",
)
REQUIRED_D06_SOURCE = frozenset({
    "rewrite/sylanne3/domains/d06/c04_work_input_v2.py",
    "rewrite/sylanne3/memory_association.py",
    "rewrite/sylanne3/host/installed_package.py",
    "rewrite/sylanne3/host/installed_d06_build.py",
    "scripts/alpha1/verify_d06_algorithm_build.py",
})
STATUS = "staging_diagnostic_only"
ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_LOCK_LINE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*==[A-Za-z0-9_.+!-]+$")
_WHEEL_NAME = re.compile(r"^([A-Za-z0-9_]+)-([A-Za-z0-9_.!+]+)-.+\.whl$")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _module_path(root: Path, module: str) -> str | None:
    if not (module == "rewrite" or module.startswith("rewrite.")):
        return None
    relative = module.replace(".", "/")
    for suffix in ("/__init__.py", ".py"):
        path = relative + suffix
        if (root / path).is_file():
            return path
    return None


def _source_closure(root: Path) -> dict[str, bytes]:
    queued = list(ENTRYPOINTS)
    seen: set[str] = set()
    files: dict[str, bytes] = {}
    while queued:
        module = queued.pop()
        if module in seen:
            continue
        seen.add(module)
        path = _module_path(root, module)
        if path is None:
            if module in ENTRYPOINTS:
                raise ValueError(f"Authority entrypoint is absent: {module}")
            continue
        if not path.startswith("rewrite/") or not path.endswith(".py"):
            raise ValueError("Authority source escaped the rewrite package")
        data = (root / path).read_bytes()
        files[path] = data
        package = module if path.endswith("/__init__.py") else module.rpartition(".")[0]
        parts = module.split(".")
        queued.extend(".".join(parts[:index]) for index in range(1, len(parts)))
        for node in ast.walk(ast.parse(data, filename=path)):
            if isinstance(node, ast.Import):
                queued.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = package.split(".")
                    if node.level > len(base):
                        raise ValueError(f"relative import escaped package: {path}")
                    base = base[:len(base) - node.level + 1]
                    target = ".".join((*base, *(node.module.split(".") if node.module else ())))
                else:
                    target = node.module or ""
                queued.append(target)
                queued.extend(target + "." + alias.name for alias in node.names if alias.name != "*")
    return files


def _locked_dependencies(data: bytes) -> list[str]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("Authority dependency lock is not UTF-8") from exc
    locked = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if not locked or any(not _LOCK_LINE.fullmatch(line) for line in locked):
        raise ValueError("Authority dependencies must be exact pinned versions")
    if len({line.split("==")[0].casefold() for line in locked}) != len(locked):
        raise ValueError("Authority dependency lock repeats a package")
    return locked


def _wheel_files(wheelhouse: Path, dependencies: list[str]) -> dict[str, bytes]:
    wheelhouse = wheelhouse.resolve(strict=True)
    if not wheelhouse.is_dir():
        raise ValueError("Authority wheelhouse must be a directory")
    expected = {name.replace("-", "_").replace(".", "_").lower(): version
                for name, version in (line.split("==", 1) for line in dependencies)}
    found: dict[str, bytes] = {}
    for wheel in wheelhouse.iterdir():
        match = _WHEEL_NAME.fullmatch(wheel.name)
        if not wheel.is_file() or wheel.is_symlink() or match is None:
            raise ValueError("Authority wheelhouse contains a non-wheel or linked file")
        name, version = match.group(1).lower(), match.group(2)
        if name not in expected or expected[name] != version or name in found:
            raise ValueError("Authority wheelhouse differs from exact dependency lock")
        found[name] = wheel.read_bytes()
    if set(found) != set(expected):
        raise ValueError("Authority wheelhouse lacks an exact locked wheel")
    return {"wheels/" + wheel.name: wheel.read_bytes()
            for wheel in sorted(wheelhouse.iterdir(), key=lambda path: path.name)}


def _legal_inventory(wheels: dict[str, bytes], dependencies: list[str]) -> dict[str, bytes]:
    if not wheels:
        return {}
    expected = {name.replace("_", "-").lower(): version
                for name, version in (line.split("==", 1) for line in dependencies)}
    components = []
    sections = ["# Sylanne Authority bundled Python dependency notices",
                "", "Generated from exact bundled wheel METADATA and license files.",
                "This inventory has not received legal review.", ""]
    for path, data in sorted(wheels.items()):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            metadata_paths = [name for name in archive.namelist()
                              if name.endswith(".dist-info/METADATA")]
            if len(metadata_paths) != 1:
                raise ValueError(f"Authority wheel METADATA differs: {path}")
            metadata = BytesParser(policy=email_policy).parsebytes(archive.read(metadata_paths[0]))
            name, version = metadata.get("Name"), metadata.get("Version")
            license_expression = metadata.get("License-Expression")
            if (not name or expected.get(name.replace("_", "-").lower()) != version
                    or not license_expression):
                raise ValueError(f"Authority wheel identity or license differs: {path}")
            license_prefix = metadata_paths[0].rsplit("/", 1)[0] + "/licenses/"
            license_files = sorted(name for name in archive.namelist()
                                   if name.startswith(license_prefix) and not name.endswith("/"))
            if not license_files:
                raise ValueError(f"Authority wheel has no license files: {path}")
            component = {
                "type": "library", "name": name, "version": version,
                "purl": f"pkg:pypi/{name.lower().replace('_', '-')}@{version}",
                "hashes": [{"alg": "SHA-256", "content": _hash(data)}],
                "licenses": [{"expression": license_expression}],
                "properties": [{"name": "sylanne:bundled-wheel", "value": path}],
            }
            components.append(component)
            sections.extend((f"## {name} {version}", "",
                             f"License expression (wheel METADATA): {license_expression}",
                             f"Wheel: {path}", f"Wheel SHA-256: {_hash(data)}", ""))
            for license_path in license_files:
                try:
                    license_text = archive.read(license_path).decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ValueError(f"Authority wheel license is not UTF-8: {path}") from exc
                sections.extend((f"### {license_path}", "", license_text.rstrip(), ""))
    if {item["name"].replace("_", "-").lower() for item in components} != set(expected):
        raise ValueError("Authority legal inventory differs from dependency lock")
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": "sylanne-authority-diagnostic-staging"}},
        "components": components,
    }
    return {
        NOTICES_PATH: ("\n".join(sections) + "\n").encode("utf-8"),
        SBOM_PATH: (json.dumps(sbom, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
    }


def build_staging_authority(root: Path, output: Path, *,
                            wheelhouse: Path | None = None) -> dict:
    root = root.resolve(strict=True)
    files = _source_closure(root)
    for relative in SERVICE_SOURCE:
        files[relative] = (root / relative).read_bytes()
    lock = (root / LOCK_PATH).read_bytes()
    dependencies = _locked_dependencies(lock)
    files[LOCK_PATH] = lock
    wheels = _wheel_files(wheelhouse, dependencies) if wheelhouse is not None else {}
    files.update(wheels)
    legal = _legal_inventory(wheels, dependencies)
    files.update(legal)
    manifest = {
        "schema": "sylanne.authority.staging.v1",
        "status": STATUS,
        "entrypoints": list(ENTRYPOINTS),
        "dependencies": dependencies,
        "dependency_lock_scope": "all_locked_wheels" if wheels else "direct_requirements_only",
        "dependency_lock_sha256": _hash(lock),
        "dependency_wheels": "bundled_exact_locked" if wheels else "absent",
        "wheels": [
            {"path": path, "sha256": _hash(data), "bytes": len(data)}
            for path, data in sorted(wheels.items())
        ],
        "legal_inventory": [
            {"path": path, "sha256": _hash(data), "bytes": len(data)}
            for path, data in sorted(legal.items())
        ],
        "source_provenance": "unfrozen_worktree",
        "files": [
            {"path": path, "sha256": _hash(data), "bytes": len(data)}
            for path, data in sorted(files.items())
        ],
        "excluded": "state, credentials, logs, native build outputs and source checkout paths",
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if output.exists():
        raise FileExistsError("refusing to replace an existing Authority staging ZIP")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, data in sorted({**files, MANIFEST_PATH: manifest_bytes}.items()):
            item = zipfile.ZipInfo(path, ZIP_TIME)
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = 0o600 << 16
            archive.writestr(item, data)
    return verify_staging_authority(output, expected_manifest_sha256=_hash(manifest_bytes))


def verify_staging_authority(package: Path, *, expected_manifest_sha256: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256):
        raise ValueError("trusted manifest SHA256 must be lowercase hex")
    with zipfile.ZipFile(package) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or MANIFEST_PATH not in names:
            raise ValueError("Authority ZIP has duplicate names or no manifest")
        for name in names:
            pure = PurePosixPath(name)
            if name.startswith("/") or "\\" in name or ".." in pure.parts or pure.as_posix() != name:
                raise ValueError("unsafe Authority ZIP path")
            info = archive.getinfo(name)
            if info.is_dir() or ((info.external_attr >> 16) & 0o170000) == 0o120000:
                raise ValueError("Authority ZIP contains a directory or symlink")
        manifest_bytes = archive.read(MANIFEST_PATH)
        if _hash(manifest_bytes) != expected_manifest_sha256:
            raise ValueError("Authority staging manifest digest differs")
        manifest = json.loads(manifest_bytes)
        if (manifest.get("schema") != "sylanne.authority.staging.v1"
                or manifest.get("status") != STATUS
                or manifest.get("entrypoints") != list(ENTRYPOINTS)):
            raise ValueError("Authority staging manifest is invalid")
        listed = manifest.get("files")
        if not isinstance(listed, list) or set(names) != {MANIFEST_PATH, *(row.get("path") for row in listed)}:
            raise ValueError("Authority staging file set differs")
        if not REQUIRED_D06_SOURCE <= set(names):
            raise ValueError("Authority staging lacks D06 installed build verifier or algorithm source")
        for row in listed:
            path = row["path"]
            if (path != LOCK_PATH and path not in SERVICE_SOURCE
                    and path not in (NOTICES_PATH, SBOM_PATH)
                    and not (path.startswith("wheels/") and path.endswith(".whl"))
                    and (not path.startswith("rewrite/") or not path.endswith(".py"))):
                raise ValueError("Authority staging contains a non-source file")
            data = archive.read(path)
            if row.get("sha256") != _hash(data) or row.get("bytes") != len(data):
                raise ValueError(f"Authority staging file digest differs: {path}")
        lock = archive.read(LOCK_PATH)
        if (_hash(lock) != manifest.get("dependency_lock_sha256")
                or _locked_dependencies(lock) != manifest.get("dependencies")):
            raise ValueError("Authority dependency lock differs")
        wheel_rows = manifest.get("wheels")
        if not isinstance(wheel_rows, list):
            raise ValueError("Authority wheel manifest differs")
        actual_wheels = {path for path in names if path.startswith("wheels/")}
        if actual_wheels != {row.get("path") for row in wheel_rows}:
            raise ValueError("Authority wheel file set differs")
        if actual_wheels:
            expected = {name.replace("-", "_").replace(".", "_").lower(): version
                        for name, version in (line.split("==", 1) for line in manifest["dependencies"])}
            found = {}
            for row in wheel_rows:
                path = row["path"]
                match = _WHEEL_NAME.fullmatch(PurePosixPath(path).name)
                if match is None or match.group(1).lower() in found:
                    raise ValueError("Authority wheel name differs")
                name, version = match.group(1).lower(), match.group(2)
                if expected.get(name) != version:
                    raise ValueError("Authority wheel version differs")
                data = archive.read(path)
                if row.get("sha256") != _hash(data) or row.get("bytes") != len(data):
                    raise ValueError("Authority wheel digest differs")
                found[name] = version
            if found != expected or manifest.get("dependency_wheels") != "bundled_exact_locked":
                raise ValueError("Authority bundled wheels differ from lock")
        elif manifest.get("dependency_wheels") != "absent":
            raise ValueError("Authority wheel status differs")
        legal = _legal_inventory({path: archive.read(path) for path in actual_wheels},
                                 manifest["dependencies"])
        legal_rows = manifest.get("legal_inventory")
        if (not isinstance(legal_rows, list)
                or {row.get("path") for row in legal_rows} != set(legal)):
            raise ValueError("Authority legal inventory file set differs")
        for row in legal_rows:
            path = row["path"]
            data = legal[path]
            if (archive.read(path) != data or row.get("sha256") != _hash(data)
                    or row.get("bytes") != len(data)):
                raise ValueError(f"Authority legal inventory differs: {path}")
    return {
        "status": STATUS,
        "package_sha256": _hash(package.read_bytes()),
        "manifest_sha256": expected_manifest_sha256,
        "source_file_count": len(listed) - 1 - len(wheel_rows) - len(legal_rows),
        "dependency_lock_sha256": _hash(lock),
        "dependency_lock_scope": manifest["dependency_lock_scope"],
        "dependency_wheels": manifest["dependency_wheels"],
        "wheel_count": len(wheel_rows),
        "legal_inventory": [row["path"] for row in legal_rows],
        "source_provenance": "unfrozen_worktree",
        "service_bootstrap": "absent",
        "cold_install_pass": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build or verify diagnostic Authority staging ZIP")
    parser.add_argument("mode", choices=("build", "verify"))
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    args = parser.parse_args()
    if args.mode == "build":
        result = build_staging_authority(args.source_root, args.package,
                                         wheelhouse=args.wheelhouse)
    else:
        if args.expected_manifest_sha256 is None:
            parser.error("verify requires --expected-manifest-sha256")
        result = verify_staging_authority(args.package, expected_manifest_sha256=args.expected_manifest_sha256)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
