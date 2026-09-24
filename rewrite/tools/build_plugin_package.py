"""Build and verify deterministic, platform-specific Sylanne plugin ZIPs.

The archive is assembled from a deliberately small allowlist.  It never walks
the repository wholesale, so runtime data, credentials, virtual environments,
test evidence, build trees, caches, and logs cannot enter by exclusion drift.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import zipfile


MANIFEST_PATH = "release-manifest.json"
ABI_VERSION = 2
ABI2_FIXED_BLOCK_INTERVAL_V1 = 0x1
NATIVE_MATH_CONTRACT = "abi2.fixed-block-interval.v1"
FORMAL_VERSION = "3.0.0-alpha1"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
ROOT_FILE_ALLOWLIST = (
    "__init__.py",
    "main.py",
    "metadata.yaml",
    "_conf_schema.json",
    "requirements.txt",
    "README.md",
    "LICENSE",
    "logo.png",
    "rewrite/__init__.py",
)
REQUIRED_ROOT_FILES = frozenset(ROOT_FILE_ALLOWLIST)
TARGETS = {
    "windows": "sylanne3_kernel.dll",
    "linux": "libsylanne3_kernel.so",
    "macos": "libsylanne3_kernel.dylib",
}
TARGET_MATRIX = {
    "windows": frozenset({"x86_64"}),
    "linux": frozenset({"x86_64", "aarch64"}),
    "macos": frozenset({"x86_64", "aarch64"}),
}
TARGET_ARCHITECTURES = frozenset().union(*TARGET_MATRIX.values())
RESOURCE_ROOT_ALLOWLIST = (
    "resources/workbench",
    "resources/catalogue",
    "resources/migrations",
)
NOTICE_FILE_ALLOWLIST = (
    "THIRD_PARTY_NOTICES",
    "THIRD_PARTY_NOTICES.md",
    "THIRD_PARTY_NOTICES.txt",
)
SBOM_FILE_ALLOWLIST = (
    "SBOM",
    "SBOM.json",
    "SBOM.spdx.json",
    "SBOM.cdx.json",
)
_FORBIDDEN_RESOURCE_PARTS = frozenset(
    {".venv", "venv", "artifacts", "target", "__pycache__", ".cache", "cache"}
)
_FORBIDDEN_RESOURCE_NAMES = frozenset(
    {".env", "credentials.json", "secrets.json"}
)
_VERSION_PATTERN = re.compile(
    r'^version\s*:\s*["\']?([^\s"\']+)["\']?\s*$', re.MULTILINE
)
_D04_ASSET_PATH = "resources/catalogue/d04-affect-scheme.json"
_D03_ASSET_PATH = "resources/catalogue/d03-neutral-context-scheme.json"
_D03_SCHEME = {"schema": "d03.context.scheme.v1", "roles": ["scene_participant"], "norms": []}
_D04_OPERATOR_PATH = "resources/catalogue/d04-fixed-block-operator.json"
_D04_CATALOGUE_CAPABILITY = "d04.affect.scheme.v1"
_D04_VERSION_FIELDS = (
    "scheme_version", "operator_version", "parameter_version", "coupling_version",
)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant: {value}")


def _strict_json_object(content: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            content,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _d04_binding(payload: dict[str, bytes]) -> dict[str, object]:
    """Validate D04 asset structure and construct its file-list binding."""
    content = payload.get(_D04_ASSET_PATH)
    if content is None:
        raise RuntimeError("formal alpha1 requires a D04 affect scheme asset")
    data = _strict_json_object(content, "D04 affect scheme asset")
    if set(data) != {"schema", *_D04_VERSION_FIELDS, "axes", "parameter_bounds"}:
        raise ValueError("D04 affect scheme asset fields are invalid")
    if data.get("schema") != _D04_CATALOGUE_CAPABILITY:
        raise ValueError("D04 affect scheme schema is invalid")
    versions = {name: data.get(name) for name in _D04_VERSION_FIELDS}
    if any(not isinstance(value, str) or not value for value in versions.values()):
        raise ValueError("D04 affect scheme versions must be nonempty strings")

    axes = data.get("axes")
    if (not isinstance(axes, list) or not axes
            or any(not isinstance(axis, dict)
                   or set(axis) != {"axis_id", "unit", "meaning"}
                   or any(not isinstance(axis.get(field), str) or not axis[field]
                          for field in ("axis_id", "unit", "meaning"))
                   or axis.get("unit") != "normalized"
                   for axis in axes)
            or len({axis["axis_id"] for axis in axes}) != len(axes)):
        raise ValueError("D04 affect scheme axes are invalid")

    bounds = data.get("parameter_bounds")
    if not isinstance(bounds, list):
        raise ValueError("D04 affect scheme parameter bounds are invalid")
    bound_names: set[str] = set()
    for item in bounds:
        if (not isinstance(item, list) or len(item) != 3
                or not isinstance(item[0], str) or not item[0]
                or type(item[1]) not in (int, float)
                or type(item[2]) not in (int, float)
                or not math.isfinite(item[1]) or not math.isfinite(item[2])
                or item[1] > item[2] or item[0] in bound_names):
            raise ValueError("D04 affect scheme parameter bounds are invalid")
        bound_names.add(item[0])

    catalogue = _strict_json_object(
        payload.get("resources/catalogue/current.json", b""), "type catalogue",
    )
    capabilities = catalogue.get("domain_capabilities")
    if (not isinstance(capabilities, dict)
            or not isinstance(capabilities.get("d04"), list)
            or _D04_CATALOGUE_CAPABILITY not in capabilities["d04"]):
        raise ValueError("type catalogue does not declare the D04 scheme capability")
    return {
        "path": _D04_ASSET_PATH,
        "sha256": _sha256(content),
        "bytes": len(content),
        "catalogue_capability": _D04_CATALOGUE_CAPABILITY,
        **versions,
    }


def _d03_binding(payload: dict[str, bytes]) -> dict[str, object]:
    """Bind the exact neutral scene role without implying trust or send rights."""

    content = payload.get(_D03_ASSET_PATH)
    if content is None:
        raise RuntimeError("formal alpha1 requires a D03 neutral context scheme asset")
    if _strict_json_object(content, "D03 context scheme asset") != _D03_SCHEME:
        raise ValueError("D03 context scheme must contain only the neutral scene role and no norms")
    return {
        "path": _D03_ASSET_PATH, "sha256": _sha256(content),
        "bytes": len(content), "schema": _D03_SCHEME["schema"],
    }


def _d04_operator_binding(payload: dict[str, bytes]) -> dict[str, object]:
    """Bind a structurally admissible block; this does not certify numerical accuracy."""
    content = payload.get(_D04_OPERATOR_PATH)
    if content is None:
        raise RuntimeError("formal alpha1 requires a D04 fixed-block operator asset")
    operator = _strict_json_object(content, "D04 fixed-block operator asset")
    scheme = _strict_json_object(payload[_D04_ASSET_PATH], "D04 affect scheme asset")
    expected = {"schema", "affect_schema", *_D04_VERSION_FIELDS,
                "axis_ids", "parameter_bounds", "operator"}
    if set(operator) != expected or operator["schema"] != "d04.fixed-block-operator.v1":
        raise ValueError("D04 fixed-block operator fields or schema are invalid")
    if (operator["affect_schema"] != scheme["schema"]
            or any(operator[name] != scheme[name] for name in _D04_VERSION_FIELDS)
            or operator["axis_ids"] != [axis["axis_id"] for axis in scheme["axes"]]
            or operator["parameter_bounds"] != scheme["parameter_bounds"]):
        raise ValueError("D04 fixed-block operator differs from affect scheme")
    block = operator["operator"]
    if not isinstance(block, dict) or set(block) != {"k", "r", "j", "a", "alpha"}:
        raise ValueError("D04 fixed-block operator is incomplete")

    def matrix(value: object) -> tuple[int, int, list[dict[int, float]]]:
        if not isinstance(value, dict) or set(value) != {"rows", "cols", "offsets", "indices", "values"}:
            raise ValueError("D04 fixed-block matrix is incomplete")
        rows, cols = value["rows"], value["cols"]
        offsets, indices, values = value["offsets"], value["indices"], value["values"]
        if (type(rows) is not int or type(cols) is not int or rows < 0 or cols < 0
                or not isinstance(offsets, list) or not isinstance(indices, list)
                or not isinstance(values, list) or len(offsets) != rows + 1
                or len(indices) != len(values) or not offsets or offsets[0] != 0
                or offsets[-1] != len(values)
                or any(type(item) is not int or item < 0 for item in offsets)
                or offsets != sorted(offsets)
                or any(type(item) is not int or not 0 <= item < cols for item in indices)
                or any(type(item) not in (int, float) or not math.isfinite(item) for item in values)):
            raise ValueError("D04 fixed-block matrix is invalid")
        sparse_rows: list[dict[int, float]] = []
        for row in range(rows):
            start, end = offsets[row], offsets[row + 1]
            columns = indices[start:end]
            if any(left >= right for left, right in zip(columns, columns[1:])):
                raise ValueError("D04 fixed-block CSR columns must be strictly ordered")
            sparse_rows.append(dict(zip(columns, values[start:end])))
        return rows, cols, sparse_rows

    n = len(scheme["axes"])
    state_matrices = {name: matrix(block[name]) for name in ("k", "r", "j")}
    if any(shape[:2] != (n, n) for shape in state_matrices.values()):
        raise ValueError("D04 fixed-block state dimensions differ from affect axes")
    for name in ("k", "r"):
        rows = state_matrices[name][2]
        for row, entries in enumerate(rows):
            try:
                off_diagonal = math.fsum(abs(value) for col, value in entries.items() if col != row)
            except OverflowError as exc:
                raise ValueError(f"D04 fixed-block {name.upper()} row magnitude overflows") from exc
            lower_bound = entries.get(row, 0.0) - math.nextafter(off_diagonal, math.inf)
            if not math.isfinite(lower_bound) or lower_bound <= 0:
                raise ValueError(f"D04 fixed-block {name.upper()} lacks a positive diagonal-dominance witness")
            for col, value in entries.items():
                if rows[col].get(row, 0.0) != value:
                    raise ValueError(f"D04 fixed-block {name.upper()} is not symmetric")
    skew_rows = state_matrices["j"][2]
    for row, entries in enumerate(skew_rows):
        for col, value in entries.items():
            if (row == col and value != 0.0) or skew_rows[col].get(row, 0.0) != -value:
                raise ValueError("D04 fixed-block J is not skew-symmetric")
    a_rows, a_cols, _ = matrix(block["a"])
    alpha = block["alpha"]
    if (a_cols != n or not isinstance(alpha, list) or len(alpha) != a_rows
            or any(type(item) not in (int, float) or not math.isfinite(item) or item < 0
                   for item in alpha)):
        raise ValueError("D04 fixed-block A/alpha dimensions are invalid")
    return {"path": _D04_OPERATOR_PATH, "sha256": _sha256(content), "bytes": len(content),
            "schema": operator["schema"], "affect_scheme_sha256": _sha256(payload[_D04_ASSET_PATH]),
            **{name: operator[name] for name in _D04_VERSION_FIELDS}}


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _validate_member_path(path: str) -> None:
    if not path or "\x00" in path or "\\" in path or path.startswith("/"):
        raise ValueError(f"dangerous ZIP member path: {path!r}")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"dangerous ZIP member path: {path!r}")
    if ":" in parts[0] or str(PurePosixPath(path)) != path:
        raise ValueError(f"dangerous ZIP member path: {path!r}")


def _run_git(project_root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=project_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise RuntimeError(f"unable to inspect source Git state: {detail.strip()}") from exc
    return result.stdout.strip()


def _git_state(project_root: Path) -> tuple[str, bool]:
    sha = _run_git(project_root, "rev-parse", "--verify", "HEAD")
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", sha):
        raise RuntimeError("source Git SHA is invalid")
    status = _run_git(
        project_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    return sha.lower(), bool(status)


def _read_version(project_root: Path) -> str:
    metadata = (project_root / "metadata.yaml").read_text(encoding="utf-8")
    match = _VERSION_PATTERN.search(metadata)
    if match is None:
        raise ValueError("metadata.yaml has no scalar version")
    version = match.group(1)
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]*", version):
        raise ValueError("metadata.yaml version is unsafe for a package filename")
    return version


def _resource_is_forbidden(relative: str) -> bool:
    path = PurePosixPath(relative)
    lowered_parts = {part.casefold() for part in path.parts}
    name = path.name.casefold()
    return bool(
        lowered_parts & _FORBIDDEN_RESOURCE_PARTS
        or name in _FORBIDDEN_RESOURCE_NAMES
        or path.suffix.casefold() in {".log", ".pyc", ".key", ".pem"}
    )


def _allowed_package_member(path: str, native_path: str) -> bool:
    if path == native_path or path in ROOT_FILE_ALLOWLIST:
        return True
    if path in NOTICE_FILE_ALLOWLIST or path in SBOM_FILE_ALLOWLIST:
        return True
    if path.startswith("rewrite/sylanne3/_native/"):
        return False
    if path.startswith("rewrite/sylanne3/"):
        return path.endswith(".py") and "__pycache__" not in PurePosixPath(path).parts
    return any(
        path.startswith(root + "/") and not _resource_is_forbidden(path)
        for root in RESOURCE_ROOT_ALLOWLIST
    )


def _read_allowlisted_payload(
    project_root: Path, *, formal: bool
) -> dict[str, bytes]:
    payload: dict[str, bytes] = {}
    for relative in ROOT_FILE_ALLOWLIST:
        source = project_root / Path(relative)
        if not source.is_file() or source.is_symlink():
            raise FileNotFoundError(f"required package file is missing or unsafe: {relative}")
        _validate_member_path(relative)
        payload[relative] = source.read_bytes()

    runtime_root = project_root / "rewrite" / "sylanne3"
    if not runtime_root.is_dir() or runtime_root.is_symlink():
        raise FileNotFoundError("required runtime package is missing: rewrite/sylanne3")
    runtime_files = sorted(runtime_root.rglob("*.py"))
    if not runtime_files:
        raise FileNotFoundError("runtime allowlist matched no Python source files")
    for source in runtime_files:
        relative_parts = source.relative_to(project_root).parts
        if "__pycache__" in relative_parts:
            continue
        relative = PurePosixPath(*relative_parts).as_posix()
        if source.is_symlink():
            raise ValueError(f"runtime Python source is a symlink: {relative}")
        _validate_member_path(relative)
        payload[relative] = source.read_bytes()

    populated_resource_roots: set[str] = set()
    for relative_root in RESOURCE_ROOT_ALLOWLIST:
        source_root = project_root / Path(relative_root)
        if not source_root.exists():
            continue
        if not source_root.is_dir() or source_root.is_symlink():
            raise ValueError(f"release resource root is unsafe: {relative_root}")
        for source in sorted(source_root.rglob("*")):
            relative = PurePosixPath(*source.relative_to(project_root).parts).as_posix()
            if source.is_symlink():
                raise ValueError(f"release resource is a symlink: {relative}")
            if not source.is_file():
                continue
            if _resource_is_forbidden(relative):
                raise ValueError(f"forbidden file under release resources: {relative}")
            _validate_member_path(relative)
            payload[relative] = source.read_bytes()
            populated_resource_roots.add(relative_root)

    found_notices: list[str] = []
    found_sboms: list[str] = []
    for group, found in (
        (NOTICE_FILE_ALLOWLIST, found_notices),
        (SBOM_FILE_ALLOWLIST, found_sboms),
    ):
        for relative in group:
            source = project_root / relative
            if not source.exists():
                continue
            if not source.is_file() or source.is_symlink():
                raise ValueError(f"release declaration is unsafe: {relative}")
            payload[relative] = source.read_bytes()
            found.append(relative)

    if formal:
        missing_roots = sorted(set(RESOURCE_ROOT_ALLOWLIST) - populated_resource_roots)
        if missing_roots:
            raise RuntimeError(
                "formal alpha1 requires non-empty release resources: "
                + ", ".join(missing_roots)
            )
        if not found_notices or not found_sboms:
            raise RuntimeError(
                "formal alpha1 requires THIRD_PARTY_NOTICES and an allowlisted SBOM"
            )
        _validate_formal_resources(payload)
    return payload


def _validate_formal_resources(payload: dict[str, bytes]) -> None:
    """Reject candidate-only catalogues and migration placeholders in formal ZIPs."""

    try:
        catalogue = _strict_json_object(
            payload["resources/catalogue/current.json"], "type catalogue",
        )
        migration = _strict_json_object(
            payload["resources/migrations/v1.json"], "migration catalogue",
        )
    except (KeyError, ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError("formal alpha1 requires complete catalogue and migration resources") from exc
    required_domains = {f"d{number:02d}" for number in range(1, 13)}
    if (not isinstance(catalogue, dict)
            or catalogue.get("activation_status") != "runtime_verified"
            or catalogue.get("release_eligibility") != "READY"
            or set(catalogue.get("declared_domains", ())) != required_domains
            or catalogue.get("missing_domain_exports") != []):
        raise RuntimeError("formal alpha1 rejects candidate-only or incomplete type catalogues")
    if (not isinstance(migration, dict)
            or migration.get("legacy_data_policy") != "registered_migrators"
            or migration.get("release_eligibility") != "READY"
            or not isinstance(migration.get("migrations"), list)
            or not migration["migrations"]
            or any(not isinstance(item, dict)
                   or item.get("activation") != "validated"
                   for item in migration["migrations"])):
        raise RuntimeError("formal alpha1 rejects unproven migration placeholders")


def _verify_workbench_source(project_root: Path, payload: dict[str, bytes], *, formal: bool) -> None:
    """Keep packaged workbench bytes identical to the tested W11 source."""
    source = project_root / "webui-src"
    prefix = "resources/workbench/"
    packaged = {path.removeprefix(prefix): content for path, content in payload.items()
                if path.startswith(prefix)}
    if not source.is_dir() and not packaged and not formal:
        return  # Minimal development fixtures have no workbench.
    if not source.is_dir() or "workbench-manifest.json" not in packaged:
        raise ValueError("packaged workbench source or manifest is missing")
    manifest = _strict_json_object(packaged["workbench-manifest.json"], "workbench manifest")
    if (manifest.get("schema_version") != "sylanne.workbench-assets.v1"
            or manifest.get("source") != "webui-src"):
        raise ValueError("packaged workbench manifest has the wrong source")
    rows = manifest.get("files")
    if not isinstance(rows, list) or not rows:
        raise ValueError("packaged workbench manifest is incomplete")
    listed = {row.get("path"): row for row in rows if isinstance(row, dict)}
    if len(listed) != len(rows):
        raise ValueError("packaged workbench manifest has duplicate or invalid entries")
    source_paths = {"index.html", *(path.relative_to(source).as_posix()
                                   for path in (source / "src").rglob("*") if path.is_file())}
    if set(listed) != source_paths or set(packaged) - {"workbench-manifest.json"} != source_paths:
        raise ValueError("packaged workbench file set differs from source")
    for relative in source_paths:
        _validate_member_path(relative)
        source_file = source / relative
        if source_file.is_symlink() or source_file.read_bytes() != packaged[relative]:
            raise ValueError(f"packaged workbench differs from source: {relative}")
        if listed[relative].get("bytes") != len(packaged[relative]) or listed[relative].get("sha256") != _sha256(packaged[relative]):
            raise ValueError(f"packaged workbench manifest is stale: {relative}")


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    info.flag_bits |= 0x800
    return info


def _manifest(
    *,
    version: str,
    git_sha: str,
    dirty: bool,
    target_os: str,
    target_arch: str,
    native_filename: str,
    target_libc: str | None,
    cpu_features: tuple[str, ...],
    payload: dict[str, bytes],
    native_path: str,
    formal: bool,
    context_scheme: dict[str, object] | None = None,
    affect_scheme: dict[str, object] | None = None,
    fixed_block_operator: dict[str, object] | None = None,
) -> dict[str, object]:
    files = [
        {"path": path, "sha256": _sha256(content), "bytes": len(content)}
        for path, content in sorted(payload.items())
    ]
    manifest = {
        "schema_version": 1,
        "package_version": version,
        "build_mode": "formal-alpha1" if formal else "dev-probe",
        "source": {"git_sha": git_sha, "dirty": dirty},
        "platform": {
            "os": target_os,
            "arch": target_arch,
            "abi_version": ABI_VERSION,
            "native_filename": native_filename,
            "libc": target_libc,
            "cpu_features": list(cpu_features),
        },
        "native": {
            "path": native_path,
            "sha256": _sha256(payload[native_path]),
            "bytes": len(payload[native_path]),
        },
        "native_math": {
            "contract": NATIVE_MATH_CONTRACT,
            "capability_flags": ABI2_FIXED_BLOCK_INTERVAL_V1,
        },
        "files": files,
    }
    if context_scheme is not None:
        manifest["context_scheme"] = context_scheme
    if affect_scheme is not None:
        manifest["affect_scheme"] = affect_scheme
    if fixed_block_operator is not None:
        manifest["fixed_block_operator"] = fixed_block_operator
    return manifest


def build_package(
    *,
    project_root: Path | str,
    target_os: str,
    target_arch: str,
    native_library: Path | str,
    output_dir: Path | str,
    allow_dirty_dev_probe: bool = False,
    target_libc: str | None = None,
    cpu_features: tuple[str, ...] = (),
) -> Path:
    """Build a deterministic ZIP and return its absolute path."""

    root = Path(project_root).resolve()
    native = Path(native_library).resolve()
    destination = Path(output_dir).resolve()
    if target_os not in TARGETS:
        raise ValueError(f"unsupported target OS: {target_os!r}")
    if target_arch not in TARGET_MATRIX[target_os]:
        raise ValueError(
            f"unsupported target OS/architecture combination: {target_os}-{target_arch}"
        )
    if target_os == "linux":
        if target_libc not in {"glibc", "musl"}:
            raise ValueError("Linux packages require target_libc='glibc' or 'musl'")
    elif target_libc is not None:
        raise ValueError("target_libc must be omitted for Windows and macOS packages")
    normalized_features = tuple(sorted(set(cpu_features)))
    if len(normalized_features) != len(cpu_features) or any(
        not re.fullmatch(r"[a-z0-9][a-z0-9_.+-]*", feature)
        for feature in normalized_features
    ):
        raise ValueError("CPU features must be unique lowercase capability names")
    canonical_native = TARGETS[target_os]
    if native.name != canonical_native:
        raise ValueError(
            f"native library filename for {target_os} must be {canonical_native!r}"
        )
    if not native.is_file() or native.is_symlink():
        raise FileNotFoundError(f"native library is missing or unsafe: {native}")

    git_sha, dirty = _git_state(root)
    if dirty and not allow_dirty_dev_probe:
        raise RuntimeError(
            "dirty source tree cannot produce a formal alpha1 package; "
            "use --allow-dirty-dev-probe only for an explicitly non-release probe"
        )
    version = _read_version(root)
    formal = not allow_dirty_dev_probe
    if formal and version != FORMAL_VERSION:
        raise RuntimeError(
            f"formal alpha1 requires metadata version {FORMAL_VERSION!r}; found {version!r}"
        )
    payload = _read_allowlisted_payload(root, formal=formal)
    _verify_workbench_source(root, payload, formal=formal)
    context_scheme = _d03_binding(payload) if formal else None
    affect_scheme = _d04_binding(payload) if formal else None
    fixed_block_operator = _d04_operator_binding(payload) if formal else None
    native_path = (
        f"rewrite/sylanne3/_native/{target_os}-{target_arch}/{canonical_native}"
    )
    _validate_member_path(native_path)
    payload[native_path] = native.read_bytes()
    manifest = _manifest(
        version=version,
        git_sha=git_sha,
        dirty=dirty,
        target_os=target_os,
        target_arch=target_arch,
        native_filename=canonical_native,
        target_libc=target_libc,
        cpu_features=normalized_features,
        payload=payload,
        native_path=native_path,
        formal=formal,
        context_scheme=context_scheme,
        affect_scheme=affect_scheme,
        fixed_block_operator=fixed_block_operator,
    )
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    payload[MANIFEST_PATH] = manifest_bytes

    destination.mkdir(parents=True, exist_ok=True)
    platform_suffix = f"{target_os}-{target_arch}"
    if target_libc is not None:
        platform_suffix += f"-{target_libc}"
    package = destination / f"astrbot_plugin_sylanne-{version}-{platform_suffix}.zip"
    temporary = package.with_suffix(package.suffix + ".tmp")
    try:
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for path, content in sorted(payload.items()):
                archive.writestr(_zip_info(path), content, compresslevel=9)
        os.replace(temporary, package)
    finally:
        if temporary.exists():
            temporary.unlink()

    verify_package(package)
    return package


def verify_package(package: Path | str) -> None:
    """Fail closed if ZIP structure, CRCs, or ReleaseManifest disagree."""

    path = Path(package)
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise ValueError("ZIP contains duplicate member paths")
            for name in names:
                _validate_member_path(name)
            bad_crc = archive.testzip()
            if bad_crc is not None:
                raise ValueError(f"ZIP CRC check failed for {bad_crc}")
            if names.count(MANIFEST_PATH) != 1:
                raise ValueError("ZIP must contain exactly one release-manifest.json")
            try:
                manifest = _strict_json_object(
                    archive.read(MANIFEST_PATH), "release-manifest.json",
                )
            except ValueError as exc:
                raise ValueError("release-manifest.json is invalid") from exc
            if manifest.get("schema_version") != 1:
                raise ValueError("ReleaseManifest schema is unsupported")
            if manifest.get("native_math") != {
                "contract": NATIVE_MATH_CONTRACT,
                "capability_flags": ABI2_FIXED_BLOCK_INTERVAL_V1,
            }:
                raise ValueError("ReleaseManifest native math contract is invalid")
            entries = manifest.get("files")
            if not isinstance(entries, list):
                raise ValueError("ReleaseManifest files must be a list")
            listed: dict[str, dict[str, object]] = {}
            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                    raise ValueError("ReleaseManifest contains an invalid file entry")
                member = entry["path"]
                _validate_member_path(member)
                if member == MANIFEST_PATH or member in listed:
                    raise ValueError("ReleaseManifest contains duplicate or recursive paths")
                listed[member] = entry
            expected = set(names) - {MANIFEST_PATH}
            if set(listed) != expected:
                raise ValueError("ReleaseManifest file set does not match ZIP members")
            required_source = REQUIRED_ROOT_FILES | {
                "rewrite/sylanne3/__init__.py",
            }
            if not required_source.issubset(listed):
                raise ValueError("ReleaseManifest is missing required plugin or runtime source")
            if not any(
                member.startswith("rewrite/sylanne3/") and member.endswith(".py")
                and member != "rewrite/sylanne3/__init__.py"
                for member in listed
            ):
                raise ValueError("ReleaseManifest is missing runtime implementation source")
            for member, entry in listed.items():
                content = archive.read(member)
                if entry.get("bytes") != len(content):
                    raise ValueError(f"ReleaseManifest byte count mismatch: {member}")
                if entry.get("sha256") != _sha256(content):
                    raise ValueError(f"ReleaseManifest SHA256 mismatch: {member}")

            source = manifest.get("source")
            if (
                not isinstance(source, dict)
                or not isinstance(source.get("git_sha"), str)
                or not re.fullmatch(r"[0-9a-f]{40,64}", source["git_sha"])
                or type(source.get("dirty")) is not bool
            ):
                raise ValueError("ReleaseManifest source identity is invalid")
            mode = manifest.get("build_mode")
            version = manifest.get("package_version")
            if mode not in {"dev-probe", "formal-alpha1"} or not isinstance(
                version, str
            ):
                raise ValueError("ReleaseManifest build identity is invalid")
            if mode == "formal-alpha1":
                formal_resources_present = all(
                    any(path.startswith(root + "/") for path in listed)
                    for root in RESOURCE_ROOT_ALLOWLIST
                )
                if (
                    version != FORMAL_VERSION
                    or source["dirty"]
                    or not formal_resources_present
                    or not set(NOTICE_FILE_ALLOWLIST).intersection(listed)
                    or not set(SBOM_FILE_ALLOWLIST).intersection(listed)
                ):
                    raise ValueError(
                        "formal alpha1 manifest requires the frozen version, clean "
                        "source, release resources, notices, and SBOM"
                    )
                try:
                    resources = {
                        member: archive.read(member)
                        for member in (
                            "resources/catalogue/current.json",
                            "resources/migrations/v1.json",
                            _D03_ASSET_PATH,
                            _D04_ASSET_PATH,
                            _D04_OPERATOR_PATH,
                        )
                        if member in listed
                    }
                    _validate_formal_resources(resources)
                    expected_context = _d03_binding(resources)
                    context_binding = manifest.get("context_scheme")
                    context_entry = listed.get(_D03_ASSET_PATH)
                    if (not isinstance(context_binding, dict)
                            or context_binding != expected_context
                            or context_entry is None
                            or any(context_binding.get(field) != context_entry.get(field)
                                   for field in ("path", "sha256", "bytes"))):
                        raise ValueError("formal alpha1 D03 context scheme binding is invalid")
                    expected_binding = _d04_binding(resources)
                    binding = manifest.get("affect_scheme")
                    asset_entry = listed.get(_D04_ASSET_PATH)
                    if (not isinstance(binding, dict)
                            or set(binding) != set(expected_binding)
                            or binding != expected_binding
                            or asset_entry is None
                            or type(binding.get("bytes")) is not int
                            or not isinstance(binding.get("sha256"), str)
                            or any(binding.get(field) != asset_entry.get(field)
                                   for field in ("path", "sha256", "bytes"))):
                        raise ValueError("formal alpha1 D04 manifest binding is invalid")
                    expected_operator = _d04_operator_binding(resources)
                    operator_binding = manifest.get("fixed_block_operator")
                    operator_entry = listed.get(_D04_OPERATOR_PATH)
                    if (not isinstance(operator_binding, dict)
                            or operator_binding != expected_operator
                            or operator_entry is None
                            or any(operator_binding.get(field) != operator_entry.get(field)
                                   for field in ("path", "sha256", "bytes"))):
                        raise ValueError("formal alpha1 D04 operator binding is invalid")
                except RuntimeError as exc:
                    raise ValueError(str(exc)) from exc

            platform = manifest.get("platform")
            if not isinstance(platform, dict):
                raise ValueError("ReleaseManifest platform is invalid")
            target_os = platform.get("os")
            target_arch = platform.get("arch")
            filename = platform.get("native_filename")
            if (
                target_os not in TARGETS
                or target_arch not in TARGET_MATRIX[target_os]
                or filename != TARGETS[target_os]
                or platform.get("abi_version") != ABI_VERSION
            ):
                raise ValueError("ReleaseManifest platform or ABI is invalid")
            libc = platform.get("libc")
            if (target_os == "linux" and libc not in {"glibc", "musl"}) or (
                target_os != "linux" and libc is not None
            ):
                raise ValueError("ReleaseManifest libc target is invalid")
            cpu_features = platform.get("cpu_features")
            if (
                not isinstance(cpu_features, list)
                or cpu_features != sorted(set(cpu_features))
                or any(
                    not isinstance(feature, str)
                    or not re.fullmatch(r"[a-z0-9][a-z0-9_.+-]*", feature)
                    for feature in cpu_features
                )
            ):
                raise ValueError("ReleaseManifest CPU features are invalid")
            native_path = (
                f"rewrite/sylanne3/_native/{target_os}-{target_arch}/{filename}"
            )
            if native_path not in listed:
                raise ValueError("ReleaseManifest canonical native library is missing")
            unexpected = sorted(path for path in listed if not _allowed_package_member(path, native_path))
            if unexpected:
                raise ValueError(f"package member is not allowed: {unexpected[0]}")
            native = manifest.get("native")
            if not isinstance(native, dict) or native != {
                "path": native_path,
                "sha256": listed[native_path].get("sha256"),
                "bytes": listed[native_path].get("bytes"),
            }:
                raise ValueError("ReleaseManifest native binding is inconsistent")
    except zipfile.BadZipFile as exc:
        raise ValueError(f"invalid ZIP archive: {path}") from exc


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a deterministic Sylanne plugin package for one platform."
    )
    parser.add_argument("--target-os", required=True, choices=sorted(TARGETS))
    parser.add_argument(
        "--target-arch", required=True, choices=sorted(TARGET_ARCHITECTURES)
    )
    parser.add_argument(
        "--target-libc",
        choices=("glibc", "musl"),
        help="required for Linux; forbidden for Windows and macOS",
    )
    parser.add_argument(
        "--cpu-feature",
        action="append",
        default=[],
        help="required CPU capability; repeat for multiple features",
    )
    parser.add_argument("--native-library", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root (defaults to the root containing rewrite/)",
    )
    parser.add_argument(
        "--allow-dirty-dev-probe",
        action="store_true",
        help="allow a dirty tree and mark the archive as a non-release dev probe",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        package = build_package(
            project_root=args.project_root,
            target_os=args.target_os,
            target_arch=args.target_arch,
            native_library=args.native_library,
            output_dir=args.output_dir,
            allow_dirty_dev_probe=args.allow_dirty_dev_probe,
            target_libc=args.target_libc,
            cpu_features=tuple(args.cpu_feature),
        )
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"package build rejected: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {"package": str(package), "sha256": _sha256(package.read_bytes())},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
