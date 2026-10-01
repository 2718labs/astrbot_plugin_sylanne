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
from typing import Iterable
import unicodedata
import zipfile

if __package__ in {None, ""}:
    # Direct CLI execution otherwise exposes only rewrite/tools on sys.path.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


_BUILD_ROOT = Path(__file__).resolve().parents[2]
if str(_BUILD_ROOT) not in sys.path:
    sys.path.insert(0, str(_BUILD_ROOT))
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(_BUILD_ROOT)

MANIFEST_PATH = "release-manifest.json"
ABI_VERSION = 2
ABI2_FIXED_BLOCK_INTERVAL_V1 = 0x1
NATIVE_MATH_CONTRACT = "abi2.fixed-block-interval.v1"
FORMAL_VERSION = "3.0.0-alpha1"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
ROOT_FILE_ALLOWLIST = (
    "__init__.py",
    "main.py",
    "_runtime_bootstrap.py",
    "metadata.yaml",
    "_conf_schema.json",
    "requirements.txt",
    "README.md",
    "LICENSE",
    "logo.png",
    "rewrite/__init__.py",
    "requirements-authority.txt",
    "scripts/alpha1/install_linux.py",
    "scripts/alpha1/authority_linux_service.py",
    "scripts/alpha1/authority_linux_admin.py",
    "scripts/alpha1/authority_linux_control.py",
    "scripts/alpha1/authority_linux_maintain.py",
    "scripts/alpha1/stage_linux_package.py",
    "scripts/alpha1/install_linux_cohort_v2.py",
    "scripts/alpha1/linux_startup_shims_v2.py",
    "docs/install/linux-alpha1-lifecycle.md",
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
BACKEND_RESOURCE_ROOTS = frozenset({"resources/catalogue", "resources/migrations"})
BACKEND_RESOURCE_FILES = frozenset({
    "resources/catalogue/current.json",
    "resources/catalogue/d01-onboarding-presets.json",
    "resources/catalogue/d03-neutral-context-scheme.json",
    "resources/catalogue/d04-affect-scheme.json",
    "resources/catalogue/d04-authored-root-preset.v3.json",
    "resources/catalogue/d04-fixed-block-operator.json",
    "resources/catalogue/d04-interval-projection-policy.v2.json",
    "resources/catalogue/d04-joint-state-output-policy.v1.json",
    "resources/catalogue/d04-semantic-mapping-profile.v3.json",
    "resources/catalogue/d04-authored-root-topology.v3.json",
    "resources/catalogue/d04-tanh-readout.v1.json",
    "resources/migrations/README.md",
    "resources/migrations/v1.json",
})
FORMAL_BACKEND_SOURCE = frozenset({
    "rewrite/sylanne3/domain_registry.py",
    "rewrite/sylanne3/host/legacy_data_preflight.py",
    "rewrite/sylanne3/native_runtime/__init__.py",
    "rewrite/sylanne3/workbench_api/__init__.py",
    *(f"rewrite/sylanne3/domains/d{number:02d}/__init__.py"
      for number in range(1, 14)),
})
WORKBENCH_PACKAGE_FILES = frozenset({
    "resources/workbench/index.html",
    "resources/workbench/workbench-manifest.json",
})
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
_D04_AUTHORED_ROOT_PRESET_PATH = "resources/catalogue/d04-authored-root-preset.v3.json"
_D04_TANH_READOUT_PATH = "resources/catalogue/d04-tanh-readout.v1.json"
_D04_INTERVAL_POLICY_PATH = "resources/catalogue/d04-interval-projection-policy.v2.json"
_D04_INTERVAL_POLICY_SHA256 = "f41fdd7e5738eba1da582b3ccb5c83322650241d921a81b19c49c2a7f6b05a53"
_D04_JOINT_OUTPUT_POLICY_PATH = "resources/catalogue/d04-joint-state-output-policy.v1.json"
_D04_JOINT_OUTPUT_POLICY_SHA256 = "7faef300b10792e3f09d3959b1c6c6e6be4c7abb1a843dcff42e2b12aa250911"
_D04_CATALOGUE_CAPABILITY = "d04.affect.scheme.v1"
_D04_VERSION_FIELDS = (
    "scheme_version", "operator_version", "parameter_version", "coupling_version",
)
NATIVE_DATA_POLICY_V1 = {
    "schema": "sylanne.native-data-policy.v1",
    "startup_gate": "sylanne3.host.legacy_data_preflight:inspect_native_data_dir_v1",
    "graph_file": "sylanne3.sqlite3",
    "allowed_graph_sidecars": ["sylanne3.sqlite3-wal", "sylanne3.sqlite3-shm"],
    "fresh_install": "absent_or_empty_plugin_data_dir_only",
    "existing_native": "exact_catalogue_and_authority_recovery_required",
    "other_data": "migration_required_before_graph_open",
    "automatic_legacy_migration": False,
}


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


def _d04_tanh_readout_binding(payload: dict[str, bytes]) -> dict[str, object]:
    """Bind 24 ordered monotone tanh outputs; candidate status is not G2."""
    content = payload.get(_D04_TANH_READOUT_PATH)
    if content is None:
        raise RuntimeError("formal alpha1 requires a D04 tanh readout asset")
    scheme_content = payload.get(_D04_ASSET_PATH)
    if scheme_content is None:
        raise ValueError("D04 tanh readout requires the affect scheme asset")
    scheme = _strict_json_object(scheme_content, "D04 affect scheme asset")
    readout = _strict_json_object(content, "D04 tanh readout asset")
    if set(readout) != {"schema", "readout_id", "readout_version", "scheme_version",
                        "axis_ids", "axis_units", "outputs"}:
        raise ValueError("D04 tanh readout fields are invalid")
    if readout["schema"] != "d04.tanh-readout-asset.v1":
        raise ValueError("D04 tanh readout schema is invalid")
    if (type(readout["readout_id"]) is not str or not readout["readout_id"]
            or type(readout["readout_version"]) is not str or not readout["readout_version"]
            or type(readout["scheme_version"]) is not str
            or readout["scheme_version"] != scheme.get("scheme_version")):
        raise ValueError("D04 tanh readout identity or scheme version differs")
    scheme_axes = scheme.get("axes")
    if (type(scheme_axes) is not list or len(scheme_axes) != 24
            or any(type(axis) is not dict or type(axis.get("axis_id")) is not str
                   or axis.get("unit") != "normalized" for axis in scheme_axes)):
        raise ValueError("D04 tanh readout requires a normalized 24-axis scheme")
    axis_ids = [axis["axis_id"] for axis in scheme_axes]
    if (len(set(axis_ids)) != 24 or type(readout["axis_ids"]) is not list
            or readout["axis_ids"] != axis_ids
            or type(readout["axis_units"]) is not list
            or readout["axis_units"] != ["normalized"] * 24):
        raise ValueError("D04 tanh readout axes differ from affect scheme")
    outputs = readout["outputs"]
    if type(outputs) is not list or len(outputs) != 24:
        raise ValueError("D04 tanh readout requires 24 output rows")
    output_ids: list[str] = []
    for index, row in enumerate(outputs):
        if type(row) is not dict or set(row) != {
            "output_id", "axis_id", "unit", "output_version", "transform", "coefficients"
        }:
            raise ValueError("D04 tanh readout row fields are invalid")
        weights = row["coefficients"]
        if (type(row["output_id"]) is not str or not row["output_id"]
                or row["axis_id"] != axis_ids[index] or row["unit"] != "normalized"
                or row["output_version"] != readout["readout_version"]
                or row["transform"] != "p=C*tanh(z)"
                or type(weights) is not list or len(weights) != 24
                or any(type(weight) not in (int, float) or not math.isfinite(weight)
                       or not 0 <= weight <= 1.0e6 for weight in weights)):
            raise ValueError("D04 tanh readout row mapping or monotone coefficients differ")
        output_ids.append(row["output_id"])
    if len(set(output_ids)) != 24:
        raise ValueError("D04 tanh readout output IDs must be unique")
    return {
        "path": _D04_TANH_READOUT_PATH, "sha256": _sha256(content),
        "bytes": len(content), "schema": readout["schema"],
        "readout_id": readout["readout_id"],
        "readout_version": readout["readout_version"],
        "scheme_version": readout["scheme_version"],
        "axis_ids": axis_ids, "axis_units": ["normalized"] * 24,
        "output_ids": output_ids, "transform": "p=C*tanh(z)",
        "status": "candidate",
    }


def _d04_interval_policy_binding(
    payload: dict[str, bytes], *, installed: bool = False,
) -> dict[str, object]:
    """Pin the computational D04 policy without claiming semantic calibration."""
    content = payload.get(_D04_INTERVAL_POLICY_PATH)
    if content is None:
        raise ValueError("D04 interval projection policy candidate is missing")
    if _sha256(content) != _D04_INTERVAL_POLICY_SHA256:
        raise ValueError("D04 interval projection policy candidate bytes changed")
    policy = _strict_json_object(content, "D04 interval projection policy")
    if (set(policy) != {
            "aggregation", "block_selection", "max_axis_width",
            "max_projection_width", "mood_salience_gain", "mood_tone_gain",
            "policy_id", "readout_id", "readout_sha256", "readout_version",
            "semantic_calibration", "stage_contract", "version",
        }
            or policy["version"] != "d04.interval-projection.v2"
            or policy["block_selection"] != "all_baseline_then_feeling_versions"
            or policy["stage_contract"] != "encoding_baseline_then_recollection_current_mood"
            or policy["semantic_calibration"] != "unvalidated"):
        raise ValueError("D04 interval projection policy contract is invalid")
    readout = _d04_tanh_readout_binding(payload)
    if (policy["readout_sha256"] != readout["sha256"]
            or policy["readout_id"] != readout["readout_id"]
            or policy["readout_version"] != readout["readout_version"]):
        raise ValueError("D04 interval projection policy readout identity differs")
    return {
        "path": _D04_INTERVAL_POLICY_PATH,
        "sha256": _D04_INTERVAL_POLICY_SHA256,
        "bytes": len(content),
        "policy_id": policy["policy_id"],
        "version": policy["version"],
        "stage_contract": policy["stage_contract"],
        "semantic_calibration": "unvalidated",
        "status": "installed" if installed else "candidate",
    }


def _d04_authored_topology_binding(payload):
    from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
    path = "resources/catalogue/d04-authored-root-topology.v3.json"
    content = payload.get(path)
    if content is None:
        raise ValueError("D04 authored topology policy asset is missing")
    policy = _strict_json_object(content, "D04 authored topology policy")
    preset = _d04_root_preset_binding(payload)
    operator = _d04_operator_binding(payload)
    if (canonical_serialize(policy).encode() != content
            or policy.get("schema") != "d04.packaged-authored-root-topology.v3"
            or policy.get("content_digest") != canonical_digest({k: v for k, v in policy.items() if k != "content_digest"})
            or policy.get("root_preset_digest") != preset["preset_digest"]
            or policy.get("operator_sha256") != operator["sha256"]
            or policy.get("template_pairs") != [["feeling.initial.secondary.v3", "mood.initial.v3"], ["feeling.initial.v3", "mood.initial.v3"]]
            or policy.get("edge_count") != 48 or policy.get("coefficient") != 0.125
            or policy.get("lineage") != "owner_authored_configuration_not_d06_observation"):
        raise ValueError("D04 authored topology differs from pinned root/operator contract")
    return {"path": path, "sha256": _sha256(content), "bytes": len(content),
        "policy_digest": policy["content_digest"], "topology_id": policy["topology_id"],
        "lineage": policy["lineage"], "edge_count": policy["edge_count"]}


def _d04_semantic_profile_binding(payload):
    from sylanne3.host.installed_d04_semantic_mapping_v3 import (
        PROFILE_PATH, semantic_profile_manifest_binding_v3)
    if PROFILE_PATH not in payload:
        raise ValueError("D04 semantic profile asset is missing")
    return semantic_profile_manifest_binding_v3(payload[PROFILE_PATH])


def _d04_joint_output_policy_binding(
    payload: dict[str, bytes], *, installed: bool = False,
) -> dict[str, object]:
    content = payload.get(_D04_JOINT_OUTPUT_POLICY_PATH)
    if content is None or _sha256(content) != _D04_JOINT_OUTPUT_POLICY_SHA256:
        raise ValueError("D04 joint output policy asset is absent or bytes changed")
    policy = _strict_json_object(content, "D04 joint output policy")
    expected_fields = {
        "schema", "policy_id", "version", "axis_ids", "readout_id",
        "readout_version", "readout_sha256", "algorithm_id", "latent_lower",
        "latent_upper", "max_readout_interval_width", "semantic_calibration",
    }
    readout = _d04_tanh_readout_binding(payload)
    readout_asset = _strict_json_object(payload[_D04_TANH_READOUT_PATH], "D04 tanh readout")
    identity = all(
        row["coefficients"] == [int(column == index) for column in range(24)]
        for index, row in enumerate(readout_asset["outputs"])
    )
    if (set(policy) != expected_fields
            or policy["schema"] != "d04.joint-state-output-policy.v1"
            or policy["policy_id"] != "d04.joint-state-output.identity-tanh24.v1"
            or policy["version"] != "d04.joint-state-output.v1"
            or policy["axis_ids"] != readout["axis_ids"]
            or policy["readout_id"] != readout["readout_id"]
            or policy["readout_version"] != readout["readout_version"]
            or policy["readout_sha256"] != readout["sha256"]
            or policy["algorithm_id"] != "abi2-full-output.identity-tanh24.rational-midpoint-rne.v1"
            or type(policy["latent_lower"]) is not float or policy["latent_lower"] != 0.0
            or type(policy["latent_upper"]) is not float or policy["latent_upper"] != 4.0
            or type(policy["max_readout_interval_width"]) is not float
            or policy["max_readout_interval_width"] != 1.0
            or policy["semantic_calibration"] != "unvalidated"
            or not identity):
        raise ValueError("D04 joint output policy or identity readout differs")
    return {
        "path": _D04_JOINT_OUTPUT_POLICY_PATH,
        "sha256": _D04_JOINT_OUTPUT_POLICY_SHA256,
        "bytes": len(content),
        **policy,
        "status": "installed_bytes_only" if installed else "candidate",
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


def _verify_native_target(content: bytes, target_os: str, target_arch: str) -> None:
    """Check the object format and machine before admitting a formal native asset.

    A matching header does not prove loadability, dependencies, or Linux libc.
    Those remain cold-install gates for the exact package on the target host.
    """
    valid = False
    if target_os == "windows" and len(content) >= 64 and content[:2] == b"MZ":
        offset = int.from_bytes(content[0x3c:0x40], "little")
        valid = (offset >= 64 and offset + 6 <= len(content)
                 and content[offset:offset + 4] == b"PE\0\0"
                 and int.from_bytes(content[offset + 4:offset + 6], "little") == 0x8664
                 and target_arch == "x86_64")
    elif target_os == "linux" and len(content) >= 20 and content[:4] == b"\x7fELF":
        machines = {"x86_64": 62, "aarch64": 183}
        valid = (content[4] == 2 and content[5] == 1
                 and int.from_bytes(content[18:20], "little") == machines[target_arch])
    elif target_os == "macos" and len(content) >= 8:
        machines = {"x86_64": 0x01000007, "aarch64": 0x0100000c}
        valid = (content[:4] == b"\xcf\xfa\xed\xfe"
                 and int.from_bytes(content[4:8], "little") == machines[target_arch])
    if not valid:
        raise ValueError(f"native binary header does not match {target_os}-{target_arch}")


def _validate_member_path(path: str) -> None:
    if (not path or any(ord(character) < 32 or ord(character) == 127 for character in path)
            or "\\" in path or path.startswith("/")):
        raise ValueError(f"dangerous ZIP member path: {path!r}")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"dangerous ZIP member path: {path!r}")
    reserved = {"con", "prn", "aux", "nul", *(f"com{number}" for number in range(1, 10)),
                *(f"lpt{number}" for number in range(1, 10))}
    if (any(any(character in ':<>"|?*' for character in part)
            or part.endswith((".", " "))
            or part.split(".", 1)[0].casefold() in reserved for part in parts)
            or str(PurePosixPath(path)) != path):
        raise ValueError(f"dangerous ZIP member path: {path!r}")


def _validate_portable_member_set(paths: Iterable[str]) -> None:
    """Reject paths that collide on case or Unicode-normalizing filesystems."""
    seen: dict[str, str] = {}
    for path in paths:
        _validate_member_path(path)
        key = unicodedata.normalize("NFD", path.casefold())
        previous = seen.setdefault(key, path)
        if previous != path:
            raise ValueError(f"ZIP member paths collide across platforms: {previous!r}, {path!r}")


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


def _handoff_source(project_root: Path, manifest_path: Path) -> tuple[str, dict]:
    """Retain archive provenance without claiming a clean Git checkout."""
    data = Path(manifest_path).read_bytes()
    value = _strict_json_object(data, "development handoff manifest")
    head = value.get("origin_head")
    rows = value.get("files")
    if (value.get("schema") != "sylanne.dot.development-handoff.v1"
            or type(head) is not str or re.fullmatch(r"[0-9a-f]{40,64}", head) is None
            or type(rows) is not list or value.get("file_count") != len(rows)):
        raise ValueError("development handoff source identity differs")
    seen, changed, deleted = set(), [], []
    for row in rows:
        relative = row.get("path")
        _validate_member_path(relative)
        if relative in seen or type(row.get("size")) is not int:
            raise ValueError("development handoff source row differs")
        seen.add(relative)
        path = project_root / relative
        if not path.is_file():
            deleted.append(relative)
        elif path.is_symlink():
            raise ValueError("development handoff source contains a symlink")
        else:
            actual = path.read_bytes()
            if len(actual) != row["size"] or _sha256(actual) != row.get("sha256"):
                changed.append(relative)
    return head, {
        "schema": "sylanne.development-handoff-provenance.v1",
        "origin_head_is_baseline_only": True,
        "handoff_manifest_sha256": _sha256(data),
        "baseline_file_count": len(rows),
        "changed_baseline_files": sorted(changed),
        "deleted_baseline_files": sorted(deleted),
        "packaged_bytes_identity": "source_inventory.sha256",
    }


def _snapshot_workspace_inventory(root: Path, baseline: dict) -> tuple[dict, dict]:
    """Hash the actual engineering snapshot as well as separately pinned payload."""
    old = {row["path"]: row for row in baseline["files"]}
    paths = set(old)
    roots = ("rewrite/sylanne3", "rewrite/tests", "rewrite/host_tests", "rewrite/tools", "rewrite/native/src",
             "scripts", "docs", "resources", "webui-src", "webui-heritage/src")
    excluded = {"node_modules", "__pycache__", ".git", ".venv", "target", "build"}
    for relative in roots:
        directory = root / relative
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            name = path.relative_to(root)
            if path.is_file() and not excluded.intersection(name.parts) and path.suffix not in {".pyc", ".pyo", ".so", ".dll", ".dylib"}:
                paths.add(name.as_posix())
    paths.update(path.name for path in root.iterdir() if path.is_file() and path.suffix in {".py", ".md", ".json", ".yaml", ".yml", ".toml"})
    rows, added, changed, removed = [], [], [], []
    for relative in sorted(paths):
        _validate_member_path(relative)
        path = root / relative
        if not path.is_file():
            if relative in old:
                removed.append(relative)
            continue
        if path.is_symlink():
            raise ValueError("snapshot source inventory cannot follow symlinks")
        data = path.read_bytes()
        row = {"path": relative, "bytes": len(data), "sha256": _sha256(data)}
        rows.append(row)
        previous = old.get(relative)
        if previous is None:
            added.append({**row, "previous_sha256": None})
        elif previous["sha256"] != row["sha256"] or previous["size"] != row["bytes"]:
            changed.append({**row, "previous_sha256": previous["sha256"]})
    encoded = json.dumps(rows, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    return ({"schema": "sylanne.engineering-source-inventory.v1", "files": rows, "sha256": _sha256(encoded)},
            {"added": added, "changed": changed, "removed": removed})


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
    if path.startswith("resources/workbench/"):
        return path in WORKBENCH_PACKAGE_FILES
    if path.startswith("rewrite/sylanne3/"):
        return path.endswith(".py") and "__pycache__" not in PurePosixPath(path).parts
    return any(
        path.startswith(root + "/") and not _resource_is_forbidden(path)
        for root in RESOURCE_ROOT_ALLOWLIST
    )


def _read_allowlisted_payload(
    project_root: Path, *, formal: bool, include_workbench: bool = True,
    backend_only: bool = False, backend_candidate: bool = False,
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
        if relative_root == "resources/workbench" and not include_workbench:
            continue
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
            if formal and backend_only and relative not in BACKEND_RESOURCE_FILES:
                raise ValueError(f"unreviewed backend release resource: {relative}")
            if _resource_is_forbidden(relative):
                raise ValueError(f"forbidden file under release resources: {relative}")
            # Old source-mirror files stay in the checkout for recovery, but
            # only the currently declared built page enters the package.
            if relative_root == "resources/workbench" and relative not in WORKBENCH_PACKAGE_FILES:
                continue
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
        required_roots = (BACKEND_RESOURCE_ROOTS if not include_workbench
                          else set(RESOURCE_ROOT_ALLOWLIST))
        missing_roots = sorted(required_roots - populated_resource_roots)
        if missing_roots:
            raise RuntimeError(
                "formal alpha1 requires non-empty release resources: "
                + ", ".join(missing_roots)
            )
        if not found_notices or not found_sboms:
            raise RuntimeError(
                "formal alpha1 requires THIRD_PARTY_NOTICES and an allowlisted SBOM"
            )
        _validate_formal_resources(
            payload, backend_only=backend_only, backend_candidate=backend_candidate,
        )
    return payload


def _validate_formal_resources(
    payload: dict[str, bytes], *, backend_only: bool = False,
    backend_candidate: bool = False,
) -> None:
    """Require a live catalogue and an explicit, fail-closed data policy."""

    try:
        catalogue = _strict_json_object(
            payload["resources/catalogue/current.json"], "type catalogue",
        )
        migration = _strict_json_object(
            payload["resources/migrations/v1.json"], "migration catalogue",
        )
    except (KeyError, ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError("formal alpha1 requires complete catalogue and migration resources") from exc
    required_domains = {f"d{number:02d}" for number in range(1, 14)}
    accepted_catalogue = (
        catalogue.get("activation_status") == "candidate_only"
        and str(catalogue.get("release_eligibility", "")).startswith("HOLD:")
    ) if backend_candidate else (
        catalogue.get("activation_status") == "runtime_verified"
        and catalogue.get("release_eligibility") == "READY"
    )
    if (not isinstance(catalogue, dict)
            or not accepted_catalogue
            or set(catalogue.get("declared_domains", ())) != required_domains
            or catalogue.get("missing_domain_exports") != []):
        raise RuntimeError("formal alpha1 rejects candidate-only or incomplete type catalogues")
    if (not isinstance(migration, dict)
            or migration.get("schema_version") != "sylanne.migrations.v1"
            or migration.get("legacy_data_policy") != "registered_migrators"
            or migration.get("native_data_policy") != NATIVE_DATA_POLICY_V1
            or not isinstance(migration.get("migrations"), list)
            or not migration["migrations"]):
        raise RuntimeError("formal alpha1 rejects unproven migration placeholders")
    if backend_only or backend_candidate:
        # This edition admits only fresh installations and exact native graph
        # candidates. Legacy data must stop at startup; preview is not upgrade.
        if (not str(migration.get("release_eligibility", "")).startswith("HOLD:")
                or any(type(item) is not dict
                       or item.get("activation") != "prohibited_preview_only"
                       for item in migration["migrations"])):
            raise RuntimeError("formal backend requires a migration HOLD and preview-only legacy entries")
    elif (migration.get("release_eligibility") != "READY"
          or any(type(item) is not dict or item.get("activation") != "validated"
                 for item in migration["migrations"])):
        raise RuntimeError("formal alpha1 rejects unproven migration placeholders")


def _backend_catalogue_identity(payload: dict[str, bytes]) -> tuple[str, list[dict]]:
    catalogue = _strict_json_object(
        payload.get("resources/catalogue/current.json", b""), "type catalogue",
    )
    rows = catalogue.get("types")
    required = {f"d{number:02d}" for number in range(1, 14)}
    fields = {"name", "owner_kinds", "storage_role", "immutable",
              "schema_version", "writer_domain", "schema_hash"}
    if (catalogue.get("schema_version") != "sylanne.catalogue.v1"
            or catalogue.get("runtime_registry") != "sylanne3.domain_registry:discover_domain_registry"
            or catalogue.get("registrars") != []
            or not isinstance(rows, list) or not rows
            or any(type(row) is not dict or set(row) != fields
                   or type(row["name"]) is not str or not row["name"]
                   or type(row["owner_kinds"]) is not list or not row["owner_kinds"]
                   or any(type(kind) is not str or not kind for kind in row["owner_kinds"])
                   or row["storage_role"] not in {"source", "state", "projection", "cache"}
                   or type(row["immutable"]) is not bool
                   or type(row["schema_version"]) is not int or row["schema_version"] < 1
                   or row["writer_domain"] not in required
                   or type(row["schema_hash"]) is not str
                   or re.fullmatch(r"[0-9a-f]{64}", row["schema_hash"]) is None
                   for row in rows)):
        raise ValueError("formal backend catalogue has invalid TypeSpec rows")
    names = [row["name"] for row in rows]
    if (names != sorted(set(names))
            or set(catalogue.get("declared_domains", ())) != required
            or catalogue.get("missing_domain_exports") != []):
        raise ValueError("formal backend catalogue omits or duplicates a domain TypeSpec")
    canonical_rows = [[row[name] for name in (
        "name", "owner_kinds", "storage_role", "immutable", "schema_version",
        "writer_domain", "schema_hash",
    )] for row in rows]
    digest = _sha256(json.dumps(
        canonical_rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8"))
    if catalogue.get("catalogue_hash") != digest:
        raise ValueError("formal backend catalogue hash differs from TypeSpec rows")
    return digest, rows


def _d04_root_preset_binding(payload: dict[str, bytes]) -> dict[str, object]:
    """Bind the actual authored root preset without granting Owner adoption."""
    from sylanne3.domains.d04.root import decode_root_preset
    from sylanne3.runtime_contracts import canonical_serialize

    content = payload.get(_D04_AUTHORED_ROOT_PRESET_PATH)
    if content is None:
        raise ValueError("installed backend requires an authored D04 root preset")
    raw = _strict_json_object(content, "D04 authored root preset")
    if canonical_serialize(raw).encode("utf-8") != content:
        raise ValueError("D04 authored root preset bytes are not canonical")
    preset = decode_root_preset(raw)
    return {
        "path": _D04_AUTHORED_ROOT_PRESET_PATH,
        "sha256": _sha256(content), "bytes": len(content),
        "preset_id": preset.preset_id, "preset_version": preset.preset_version,
        "preset_digest": preset.digest,
    }


def _backend_candidate_qualification(
    payload: dict[str, bytes], *, schema_version: int = 2,
) -> dict[str, object]:
    """Bind the installable backend candidate's byte-level qualification inputs."""
    catalogue = _strict_json_object(
        payload.get("resources/catalogue/current.json", b""), "type catalogue",
    )
    if (catalogue.get("activation_status") != "candidate_only"
            or not str(catalogue.get("release_eligibility", "")).startswith("HOLD:")):
        raise ValueError("backend candidate must preserve the live candidate_only/HOLD catalogue")
    catalogue_hash, _ = _backend_catalogue_identity(payload)
    migration = _strict_json_object(
        payload.get("resources/migrations/v1.json", b""), "migration catalogue",
    )
    if (migration.get("legacy_data_policy") != "registered_migrators"
            or migration.get("native_data_policy") != NATIVE_DATA_POLICY_V1
            or not str(migration.get("release_eligibility", "")).startswith("HOLD:")
            or not isinstance(migration.get("migrations"), list)
            or not migration["migrations"]
            or any(type(item) is not dict
                   or item.get("activation") != "prohibited_preview_only"
                   for item in migration["migrations"])):
        raise ValueError("backend candidate requires fail-closed migration HOLD and fresh-install policy")
    asset_paths = (
        _D03_ASSET_PATH, _D04_ASSET_PATH, _D04_OPERATOR_PATH,
        _D04_TANH_READOUT_PATH, _D04_INTERVAL_POLICY_PATH,
        "resources/migrations/v1.json",
    )
    missing = [path for path in asset_paths if path not in payload]
    if missing:
        raise ValueError(f"backend candidate qualification asset is missing: {missing[0]}")
    context = _d03_binding(payload)
    affect = _d04_binding(payload)
    operator = _d04_operator_binding(payload)
    readout = _d04_tanh_readout_binding(payload)
    interval_policy = _d04_interval_policy_binding(payload)
    if schema_version not in {1, 2}:
        raise ValueError("unknown backend candidate qualification schema")
    production = schema_version == 2
    result = {
        "schema": f"sylanne.backend-alpha1-candidate-qualification.v{schema_version}",
        "status": "backend_candidate",
        "product_status": "candidate_only",
        "runtime_scope": ("backend-production-acceptance" if production
                          else "limited-diagnostics"),
        "message_processing": ("requires_installed_authority_and_current_effect_admission"
                               if production else "disabled"),
        "outbound_sending": ("requires_installed_authority_and_current_effect_admission"
                            if production else "disabled"),
        "unmet_product_gates": [
            "catalogue_runtime_verified", "migration_validated",
            "formal_alpha1_source_freeze", "full_host_acceptance",
        ],
        "catalogue_hash": catalogue_hash,
        "domains": [f"d{number:02d}" for number in range(1, 14)],
        "registry_source": "sylanne3.domain_registry:discover_domain_registry",
        "catalogue_status": "candidate_only",
        "catalogue_release_eligibility": catalogue["release_eligibility"],
        "native_abi_version": ABI_VERSION,
        "native_math_contract": NATIVE_MATH_CONTRACT,
        "fresh_install_only": True,
        "migration_policy": {
            "sha256": _sha256(payload["resources/migrations/v1.json"]),
            "legacy_data_policy": migration["legacy_data_policy"],
            "native_data_policy": NATIVE_DATA_POLICY_V1,
            "activation": "prohibited_preview_only",
        },
        "assets": {
            "context_scheme": {"path": context["path"], "sha256": context["sha256"]},
            "affect_scheme": {"path": affect["path"], "sha256": affect["sha256"]},
            "fixed_block_operator": {"path": operator["path"], "sha256": operator["sha256"]},
            "tanh_readout": {"path": readout["path"], "sha256": readout["sha256"]},
            "interval_projection_policy": {
                "path": interval_policy["path"], "sha256": interval_policy["sha256"],
                "semantic_calibration": "unvalidated",
            },
        },
    }
    if production:
        for name, binding in (
            ("joint_state_output_policy", _d04_joint_output_policy_binding(payload)),
            ("authored_root_preset", _d04_root_preset_binding(payload)),
            ("semantic_mapping_profile", _d04_semantic_profile_binding(payload)),
            ("authored_root_topology", _d04_authored_topology_binding(payload)),
        ):
            result["assets"][name] = {"path": binding["path"], "sha256": binding["sha256"]}
    return result


def _verify_live_backend_catalogue(project_root: Path, payload: dict[str, bytes]) -> None:
    """Compare a formal backend ZIP's catalogue to its exact checkout registry."""
    digest, rows = _backend_catalogue_identity(payload)
    code = (
        "import json,sys; from pathlib import Path; "
        "root=Path(sys.argv[1]).resolve(); "
        "sys.path[:0]=[str(root),str(root/'rewrite')]; "
        "from scripts.alpha1.generate_catalogue import _load_active_scheme; "
        "from sylanne3.domain_registry import discover_domain_registry; "
        "registry=discover_domain_registry(active_affect_scheme="
        "_load_active_scheme(root/'resources/catalogue/d04-affect-scheme.json')); "
        "assert registry.complete, registry.unavailable; "
        "specs=registry.type_registry.specs; "
        "print(json.dumps({'hash':registry.type_registry.catalogue_hash,'types':["
        "{'name':s.name,'owner_kinds':list(s.owner_kinds),'storage_role':s.storage_role,"
        "'immutable':s.immutable,'schema_version':s.schema_version,"
        "'writer_domain':s.writer_domain,'schema_hash':s.schema_hash} for s in specs]}))"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-c", code, str(project_root)],
            cwd=project_root, check=True, capture_output=True, text=True,
        )
        live = _strict_json_object(result.stdout.encode("utf-8"), "live domain registry")
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        raise RuntimeError("formal backend live domain registry verification failed") from exc
    if live.get("hash") != digest or live.get("types") != rows:
        raise RuntimeError("formal backend catalogue differs from current domain registry")


def _verify_workbench_source(project_root: Path, payload: dict[str, bytes], *, formal: bool) -> None:
    """Bind the packaged workbench to W11's self-contained Vue build output."""
    source = project_root / "webui-heritage"
    build_output = project_root / "webui-heritage" / "dist" / "index.html"
    prefix = "resources/workbench/"
    packaged = {path.removeprefix(prefix): content for path, content in payload.items()
                if path.startswith(prefix)}
    if not source.is_dir() and not packaged and not formal:
        return  # Minimal development fixtures have no workbench.
    if (source.is_symlink() or not source.is_dir()
            or "workbench-manifest.json" not in packaged):
        raise ValueError("packaged workbench source or manifest is missing")
    manifest = _strict_json_object(packaged["workbench-manifest.json"], "workbench manifest")
    if (manifest.get("schema_version") != "sylanne.workbench-assets.v1"
            or manifest.get("source") != "webui-heritage"
            or manifest.get("build_output") != "webui-heritage/dist/index.html"):
        raise ValueError("packaged workbench manifest has the wrong source")
    rows = manifest.get("files")
    if not isinstance(rows, list) or not rows:
        raise ValueError("packaged workbench manifest is incomplete")
    listed = {row.get("path"): row for row in rows if isinstance(row, dict)}
    if len(listed) != len(rows) or set(listed) != {"index.html"}:
        raise ValueError("packaged workbench manifest has duplicate or invalid entries")
    if set(packaged) - {"workbench-manifest.json"} != {"index.html"}:
        raise ValueError("packaged workbench file set differs from the built output")
    if ((source / "dist").is_symlink() or build_output.is_symlink()
            or not build_output.is_file()):
        raise ValueError("webui-heritage build output is missing or unsafe")
    relative = "index.html"
    _validate_member_path(relative)
    if build_output.read_bytes() != packaged[relative]:
        raise ValueError("packaged workbench differs from webui-heritage build output")
    if (listed[relative].get("bytes") != len(packaged[relative])
            or listed[relative].get("sha256") != _sha256(packaged[relative])):
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
    backend_alpha1_candidate: bool = False,
    backend_only_dev_probe: bool = False,
    backend_only_alpha1: bool = False,
    context_scheme: dict[str, object] | None = None,
    affect_scheme: dict[str, object] | None = None,
    fixed_block_operator: dict[str, object] | None = None,
    tanh_readout: dict[str, object] | None = None,
    interval_projection_policy: dict[str, object] | None = None,
    joint_state_output_policy: dict[str, object] | None = None,
    semantic_mapping_profile: dict[str, object] | None = None,
    authored_root_topology: dict[str, object] | None = None,
    backend_qualification: dict[str, object] | None = None,
    authored_root_preset: dict[str, object] | None = None,
) -> dict[str, object]:
    files = [
        {"path": path, "sha256": _sha256(content), "bytes": len(content)}
        for path, content in sorted(payload.items())
    ]
    manifest = {
        "schema_version": 1,
        "package_version": version,
        "build_mode": ("formal-alpha1" if formal else
                       "backend-alpha1-candidate" if backend_alpha1_candidate else "dev-probe"),
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
    if backend_only_dev_probe or backend_only_alpha1 or backend_alpha1_candidate:
        manifest["candidate_scope"] = "backend-only"
    if context_scheme is not None:
        manifest["context_scheme"] = context_scheme
    if affect_scheme is not None:
        manifest["affect_scheme"] = affect_scheme
    if fixed_block_operator is not None:
        manifest["fixed_block_operator"] = fixed_block_operator
    if tanh_readout is not None:
        manifest["tanh_readout"] = tanh_readout
    if interval_projection_policy is not None:
        manifest["interval_projection_policy"] = interval_projection_policy
    if joint_state_output_policy is not None:
        manifest["joint_state_output_policy"] = joint_state_output_policy
    if authored_root_topology is not None:
        manifest["authored_root_topology"] = authored_root_topology
    if semantic_mapping_profile is not None:
        manifest["semantic_mapping_profile"] = semantic_mapping_profile
    if backend_qualification is not None:
        manifest["backend_qualification"] = backend_qualification
        source_rows = [row for row in files if row["path"] != native_path]
        encoded = json.dumps(source_rows, ensure_ascii=True, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
        manifest["source_inventory"] = {
            "schema": "sylanne.packaged-source-inventory.v1",
            "files": source_rows, "sha256": _sha256(encoded),
        }
    if authored_root_preset is not None:
        manifest["authored_root_preset"] = authored_root_preset
    return manifest


def build_package(
    *,
    project_root: Path | str,
    target_os: str,
    target_arch: str,
    native_library: Path | str,
    output_dir: Path | str,
    allow_dirty_dev_probe: bool = False,
    backend_only_dev_probe: bool = False,
    backend_only_alpha1: bool = False,
    backend_alpha1_candidate: bool = False,
    target_libc: str | None = None,
    cpu_features: tuple[str, ...] = (),
    source_handoff_manifest: Path | str | None = None,
    snapshot_alpha1_test: bool = False,
    handoff_archive_sha256: str | None = None,
    snapshot_evidence: Path | str | None = None,
) -> Path:
    """Build a deterministic ZIP and return its absolute path."""

    root = Path(project_root).resolve()
    from sylanne3.host.alpha1_test_snapshot_v1 import MODE as TEST_MODE, SCHEMA as TEST_SCHEMA, qualify_test_snapshot_v1
    if snapshot_alpha1_test and (allow_dirty_dev_probe or backend_only_dev_probe or backend_only_alpha1 or backend_alpha1_candidate):
        raise ValueError("alpha1 test snapshot has its own explicit independent build mode")
    if snapshot_alpha1_test and (source_handoff_manifest is None or snapshot_evidence is None
            or type(handoff_archive_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}",handoff_archive_sha256) is None):
        raise ValueError("test snapshot requires actual handoff provenance and scoped verification evidence")
    candidate_build = backend_alpha1_candidate or snapshot_alpha1_test
    if backend_only_dev_probe and not allow_dirty_dev_probe:
        raise ValueError("backend-only candidate requires non-release dev-probe mode")
    if backend_only_alpha1 and (allow_dirty_dev_probe or backend_only_dev_probe):
        raise ValueError("formal backend-only alpha1 cannot use dev-probe mode")
    if backend_alpha1_candidate and (allow_dirty_dev_probe or backend_only_dev_probe
                                     or backend_only_alpha1):
        raise ValueError("backend alpha1 candidate has its own explicit package mode")
    native_input = Path(native_library)
    if native_input.is_symlink():
        raise FileNotFoundError(f"native library is missing or unsafe: {native_input}")
    native = native_input.resolve()
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

    handoff = None
    if source_handoff_manifest is not None:
        if not candidate_build:
            raise ValueError("handoff snapshots require explicit candidate or test-snapshot mode")
        git_sha, handoff = _handoff_source(root, Path(source_handoff_manifest))
        dirty = True
    else:
        git_sha, dirty = _git_state(root)
    if dirty and not (allow_dirty_dev_probe or candidate_build):
        raise RuntimeError(
            "dirty source tree cannot produce a formal alpha1 package; "
            "use --allow-dirty-dev-probe only for an explicitly non-release probe"
        )
    version = _read_version(root)
    formal = not (allow_dirty_dev_probe or candidate_build)
    if snapshot_alpha1_test and version != FORMAL_VERSION:
        raise ValueError("alpha1 test snapshot requires actual source metadata version 3.0.0-alpha1")
    if formal and version != FORMAL_VERSION:
        raise RuntimeError(
            f"formal alpha1 requires metadata version {FORMAL_VERSION!r}; found {version!r}"
        )
    payload = _read_allowlisted_payload(
        root, formal=(formal or candidate_build),
        include_workbench=not (backend_only_dev_probe or backend_only_alpha1
                                or backend_alpha1_candidate),
        backend_only=backend_only_alpha1 or backend_alpha1_candidate,
        backend_candidate=candidate_build,
    )
    if not (backend_only_dev_probe or backend_only_alpha1 or backend_alpha1_candidate):
        _verify_workbench_source(root, payload, formal=formal)
    if backend_only_alpha1:
        _verify_live_backend_catalogue(root, payload)
    if candidate_build:
        _verify_live_backend_catalogue(root, payload)
    bind_assets = formal or candidate_build
    context_scheme = _d03_binding(payload) if bind_assets else None
    affect_scheme = _d04_binding(payload) if bind_assets else None
    fixed_block_operator = _d04_operator_binding(payload) if bind_assets else None
    tanh_readout = (_d04_tanh_readout_binding(payload)
                    if bind_assets or _D04_TANH_READOUT_PATH in payload else None)
    interval_projection_policy = (
        _d04_interval_policy_binding(payload, installed=formal)
        if candidate_build or _D04_INTERVAL_POLICY_PATH in payload else None
    )
    joint_state_output_policy = (
        _d04_joint_output_policy_binding(payload, installed=formal)
        if bind_assets or _D04_JOINT_OUTPUT_POLICY_PATH in payload else None
    )
    backend_qualification = (
        _backend_candidate_qualification(payload) if candidate_build else None
    )
    authored_root_preset = (_d04_root_preset_binding(payload)
                            if bind_assets else None)
    native_path = (
        f"rewrite/sylanne3/_native/{target_os}-{target_arch}/{canonical_native}"
    )
    _validate_member_path(native_path)
    payload[native_path] = native.read_bytes()
    if formal or candidate_build:
        _verify_native_target(payload[native_path], target_os, target_arch)
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
        backend_only_dev_probe=backend_only_dev_probe,
        backend_only_alpha1=backend_only_alpha1,
        backend_alpha1_candidate=backend_alpha1_candidate,
        context_scheme=context_scheme,
        affect_scheme=affect_scheme,
        fixed_block_operator=fixed_block_operator,
        tanh_readout=tanh_readout,
        interval_projection_policy=interval_projection_policy,
        joint_state_output_policy=joint_state_output_policy,
        semantic_mapping_profile=(_d04_semantic_profile_binding(payload) if bind_assets else None),
        authored_root_topology=(_d04_authored_topology_binding(payload) if bind_assets else None),
        backend_qualification=backend_qualification,
        authored_root_preset=authored_root_preset,
    )
    if handoff is not None:
        manifest["source"]["handoff_snapshot"] = handoff
    if snapshot_alpha1_test:
        from sylanne3.runtime_contracts import canonical_digest
        from sylanne3.host.alpha1_test_snapshot_v1 import validate_test_snapshot_manifest_v1
        baseline = _strict_json_object(Path(source_handoff_manifest).read_bytes(), "handoff manifest")
        old = {row["path"]: row for row in baseline["files"]}
        actual = manifest["source_inventory"]["files"]
        workspace_inventory, workspace_delta = _snapshot_workspace_inventory(root, baseline)
        added, changed = [], []
        for row in actual:
            prior = old.get(row["path"])
            if prior is None:
                added.append({**row, "previous_sha256": None})
            elif prior["sha256"] != row["sha256"] or prior["size"] != row["bytes"]:
                changed.append({**row, "previous_sha256": prior["sha256"]})
        evidence_bytes = Path(snapshot_evidence).read_bytes()
        if len(evidence_bytes) > 1048576:
            raise ValueError("test snapshot evidence is unbounded")
        evidence = _strict_json_object(evidence_bytes, "actual test evidence")
        manifest["build_mode"] = TEST_MODE
        manifest["candidate_scope"] = "alpha1-test"
        manifest["backend_qualification"] = qualify_test_snapshot_v1(manifest["backend_qualification"])
        manifest["test_snapshot"] = {"schema": TEST_SCHEMA, "label": "Embodiment-3.0.0-alpha1 test snapshot",
            "handoff_archive_sha256": handoff_archive_sha256, "handoff_manifest_sha256": handoff["handoff_manifest_sha256"],
            "source_inventory_sha256": manifest["source_inventory"]["sha256"], "native_sha256": manifest["native"]["sha256"],
            "engineering_source_inventory": workspace_inventory, "engineering_source_delta": workspace_delta,
            "source_delta": {"added": added, "changed": changed, "removed": handoff["deleted_baseline_files"]},
            "verification_evidence": evidence, "verification_evidence_digest": canonical_digest(evidence), "public_release": False}
        validate_test_snapshot_manifest_v1(manifest)
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    payload[MANIFEST_PATH] = manifest_bytes
    _validate_portable_member_set(payload)

    destination.mkdir(parents=True, exist_ok=True)
    platform_suffix = f"{target_os}-{target_arch}"
    if target_libc is not None:
        platform_suffix += f"-{target_libc}"
    if snapshot_alpha1_test:
        platform_suffix += "-alpha1-test-snapshot"
    elif backend_alpha1_candidate:
        platform_suffix += "-backend-alpha1-candidate"
    elif backend_only_dev_probe or backend_only_alpha1:
        platform_suffix += "-backend-only"
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
            _validate_portable_member_set(names)
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
            if mode not in {"dev-probe", "formal-alpha1", "backend-alpha1-candidate", "snapshot-alpha1-test"} or not isinstance(
                version, str
            ):
                raise ValueError("ReleaseManifest build identity is invalid")
            scope = manifest.get("candidate_scope")
            if scope is not None and not (mode == "snapshot-alpha1-test" and scope == "alpha1-test") and (scope != "backend-only"
                                      or any(path.startswith("resources/workbench/") for path in listed)):
                raise ValueError("ReleaseManifest candidate scope is invalid")
            if mode == "snapshot-alpha1-test":
                from sylanne3.host.alpha1_test_snapshot_v1 import validate_test_snapshot_manifest_v1
                validate_test_snapshot_manifest_v1(manifest)
            if ((mode == "backend-alpha1-candidate" and scope != "backend-only")
                    or (mode == "formal-alpha1" and scope not in {None, "backend-only"})
                    or (mode == "dev-probe" and scope not in {None, "backend-only"})):
                raise ValueError("ReleaseManifest mode and candidate scope differ")
            if mode in {"formal-alpha1", "backend-alpha1-candidate", "snapshot-alpha1-test"} or _D04_TANH_READOUT_PATH in listed:
                readout_resources = {
                    member: archive.read(member)
                    for member in (_D04_ASSET_PATH, _D04_TANH_READOUT_PATH)
                    if member in listed
                }
                try:
                    expected_readout = _d04_tanh_readout_binding(readout_resources)
                except RuntimeError as exc:
                    raise ValueError(str(exc)) from exc
                readout_binding = manifest.get("tanh_readout")
                readout_entry = listed.get(_D04_TANH_READOUT_PATH)
                if (readout_binding != expected_readout or readout_entry is None
                        or any(readout_binding.get(field) != readout_entry.get(field)
                               for field in ("path", "sha256", "bytes"))):
                    raise ValueError("D04 tanh readout manifest binding is invalid")
            elif "tanh_readout" in manifest:
                raise ValueError("D04 tanh readout manifest binding lacks asset")
            if mode == "backend-alpha1-candidate" or _D04_INTERVAL_POLICY_PATH in listed:
                policy_resources = {
                    member: archive.read(member)
                    for member in (_D04_ASSET_PATH, _D04_TANH_READOUT_PATH,
                                   _D04_INTERVAL_POLICY_PATH)
                    if member in listed
                }
                expected_policy = _d04_interval_policy_binding(
                    policy_resources, installed=mode == "formal-alpha1",
                )
                policy_binding = manifest.get("interval_projection_policy")
                policy_entry = listed.get(_D04_INTERVAL_POLICY_PATH)
                if (policy_binding != expected_policy or policy_entry is None
                        or any(policy_binding.get(field) != policy_entry.get(field)
                               for field in ("path", "sha256", "bytes"))):
                    raise ValueError("D04 interval projection policy manifest binding is invalid")
            elif "interval_projection_policy" in manifest:
                raise ValueError("D04 interval projection policy binding lacks asset")
            if mode in {"formal-alpha1", "backend-alpha1-candidate", "snapshot-alpha1-test"} or _D04_JOINT_OUTPUT_POLICY_PATH in listed:
                joint_resources = {
                    member: archive.read(member)
                    for member in (_D04_ASSET_PATH, _D04_TANH_READOUT_PATH,
                                   _D04_JOINT_OUTPUT_POLICY_PATH)
                    if member in listed
                }
                expected_joint = _d04_joint_output_policy_binding(
                    joint_resources, installed=mode == "formal-alpha1",
                )
                joint_binding = manifest.get("joint_state_output_policy")
                joint_entry = listed.get(_D04_JOINT_OUTPUT_POLICY_PATH)
                if (joint_binding != expected_joint or joint_entry is None
                        or any(joint_binding.get(field) != joint_entry.get(field)
                               for field in ("path", "sha256", "bytes"))):
                    raise ValueError("D04 joint output policy manifest binding is invalid")
            elif "joint_state_output_policy" in manifest:
                raise ValueError("D04 joint output policy binding lacks asset")
            if mode in {"formal-alpha1", "backend-alpha1-candidate", "snapshot-alpha1-test"}:
                semantic_path = "resources/catalogue/d04-semantic-mapping-profile.v3.json"
                if semantic_path not in listed or manifest.get("semantic_mapping_profile") != _d04_semantic_profile_binding(
                        {semantic_path: archive.read(semantic_path)}):
                    raise ValueError("D04 semantic profile manifest binding is invalid")
            if mode in {"formal-alpha1", "backend-alpha1-candidate", "snapshot-alpha1-test"}:
                if not FORMAL_BACKEND_SOURCE.issubset(listed):
                    raise ValueError("formal alpha1 manifest is missing backend runtime source")
                if scope == "backend-only":
                    unreviewed = sorted(
                        member for member in listed
                        if any(member.startswith(root + "/") for root in BACKEND_RESOURCE_ROOTS)
                        and member not in BACKEND_RESOURCE_FILES
                    )
                    if unreviewed:
                        raise ValueError(f"unreviewed backend release resource: {unreviewed[0]}")
                    _backend_catalogue_identity({
                        "resources/catalogue/current.json": archive.read(
                            "resources/catalogue/current.json"
                        ) if "resources/catalogue/current.json" in listed else b"",
                    })
                required_roots = (BACKEND_RESOURCE_ROOTS if scope == "backend-only"
                                  else set(RESOURCE_ROOT_ALLOWLIST))
                formal_resources_present = all(
                    any(path.startswith(root + "/") for path in listed)
                    for root in required_roots
                )
                if (
                    (mode == "formal-alpha1" and version != FORMAL_VERSION)
                    or (mode == "formal-alpha1" and source["dirty"])
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
                            _D04_TANH_READOUT_PATH,
                            _D04_INTERVAL_POLICY_PATH,
                            _D04_JOINT_OUTPUT_POLICY_PATH,
                            "resources/catalogue/d04-semantic-mapping-profile.v3.json",
                            "resources/catalogue/d04-authored-root-topology.v3.json",
                            _D04_AUTHORED_ROOT_PRESET_PATH,
                        )
                        if member in listed
                    }
                    _validate_formal_resources(
                        resources, backend_only=scope == "backend-only",
                        backend_candidate=mode in {"backend-alpha1-candidate", "snapshot-alpha1-test"},
                    )
                    if mode in {"backend-alpha1-candidate", "snapshot-alpha1-test"}:
                        qualifier = manifest.get("backend_qualification")
                        schema = qualifier.get("schema") if type(qualifier) is dict else None
                        versions = {
                            "sylanne.backend-alpha1-candidate-qualification.v1": 1,
                            "sylanne.backend-alpha1-candidate-qualification.v2": 2,
                            "sylanne.alpha1-test-snapshot-qualification.v1": 2,
                        }
                        if schema not in versions:
                            raise ValueError("backend candidate qualification schema is invalid")
                        expected_qualification = _backend_candidate_qualification(
                            resources, schema_version=versions[schema])
                        if mode == "snapshot-alpha1-test":
                            from sylanne3.host.alpha1_test_snapshot_v1 import qualify_test_snapshot_v1
                            expected_qualification = qualify_test_snapshot_v1(expected_qualification)
                        if manifest.get("backend_qualification") != expected_qualification:
                            raise ValueError("backend candidate qualification binding is invalid")
                        if versions[schema] == 2:
                            source_rows = sorted((row for row in listed.values()
                                                  if row["path"] != manifest["native"]["path"]),
                                                 key=lambda row: row["path"])
                            encoded = json.dumps(source_rows, ensure_ascii=True, sort_keys=True,
                                                 separators=(",", ":")).encode("utf-8")
                            if manifest.get("source_inventory") != {
                                "schema": "sylanne.packaged-source-inventory.v1",
                                "files": source_rows, "sha256": _sha256(encoded),
                            }:
                                raise ValueError("backend candidate source inventory differs")
                    elif "backend_qualification" in manifest:
                        raise ValueError("backend qualification is only valid for its candidate mode")
                    if ("authored_root_preset" in manifest
                            or mode == "backend-alpha1-candidate" and versions[schema] == 2):
                        if manifest.get("authored_root_preset") != _d04_root_preset_binding(resources):
                            raise ValueError("authored D04 root preset manifest binding differs")
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
            if mode in {"formal-alpha1", "backend-alpha1-candidate", "snapshot-alpha1-test"}:
                _verify_native_target(archive.read(native_path), target_os, target_arch)
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
    parser.add_argument("--source-handoff-manifest", type=Path,
                        help="explicit development snapshot provenance; backend candidate mode only")
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
    parser.add_argument(
        "--backend-only-dev-probe", action="store_true",
        help="omit unfinished workbench assets from an explicitly non-release candidate",
    )
    parser.add_argument(
        "--backend-only-alpha1", action="store_true",
        help="formal backend-only alpha1 after all backend acceptance gates pass",
    )
    parser.add_argument(
        "--backend-alpha1-candidate", action="store_true",
        help="installable backend-only alpha1 development candidate; not a release",
    )
    parser.add_argument("--snapshot-alpha1-test", action="store_true",
        help="pinned Embodiment alpha1 test snapshot with existing W09 and honest handoff provenance")
    parser.add_argument("--handoff-archive-sha256")
    parser.add_argument("--snapshot-evidence", type=Path)
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
            backend_only_dev_probe=args.backend_only_dev_probe,
            backend_only_alpha1=args.backend_only_alpha1,
            backend_alpha1_candidate=args.backend_alpha1_candidate,
            target_libc=args.target_libc,
            cpu_features=tuple(args.cpu_feature),
            source_handoff_manifest=args.source_handoff_manifest,
            snapshot_alpha1_test=args.snapshot_alpha1_test,
            handoff_archive_sha256=args.handoff_archive_sha256,
            snapshot_evidence=args.snapshot_evidence,
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
