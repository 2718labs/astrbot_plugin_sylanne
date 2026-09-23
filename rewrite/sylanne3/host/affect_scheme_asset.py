"""Load D04 scheme bytes only from a pinned, verified formal package."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path

from ..domain_registry import DomainRegistry, discover_domain_registry
from ..domains.d04 import AffectAxis, AffectScheme
from .installed_package import _safe_file, verify_installed_package


_ASSET_PATH = "resources/catalogue/d04-affect-scheme.json"
_CATALOGUE_PATH = "resources/catalogue/current.json"
_CAPABILITY = "d04.affect.scheme.v1"
_VERSIONS = ("scheme_version", "operator_version", "parameter_version", "coupling_version")


@dataclass(frozen=True, slots=True)
class VerifiedAffectScheme:
    """Authenticated scheme bytes and versions, not a certified numerical configuration."""

    scheme: AffectScheme
    registry: DomainRegistry
    asset_sha256: str
    manifest_sha256: str


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant: {value}")


def _json_object(content: bytes, label: str) -> dict:
    try:
        value = json.loads(content, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _listed_bytes(root: Path, manifest: dict, relative: str) -> tuple[bytes, dict]:
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise ValueError("manifest file list is missing")
    matches = [item for item in entries if isinstance(item, dict) and item.get("path") == relative]
    if len(matches) != 1:
        raise ValueError(f"manifest must list {relative} exactly once")
    entry = matches[0]
    path = _safe_file(root, relative)
    if path is None:
        raise ValueError(f"package asset is missing or unsafe: {relative}")
    content = path.read_bytes()
    if (type(entry.get("bytes")) is not int or entry["bytes"] != len(content)
            or not isinstance(entry.get("sha256"), str)
            or not hmac.compare_digest(entry["sha256"], hashlib.sha256(content).hexdigest())):
        raise ValueError(f"package asset bytes differ from manifest: {relative}")
    return content, entry


def load_verified_affect_scheme(
    package_root: Path | str,
    expected_manifest_digest: str,
    *,
    available_cpu_features: frozenset[str] | None = None,
) -> VerifiedAffectScheme:
    """Return one D04 scheme or reject; the expected digest must be administrator pinned.

    The manifest v1 builder does not yet emit this opt-in binding. Existing
    packages therefore fail closed until release assembly supplies it. A
    matching asset does not certify operators, parameter values, or numerics.
    """
    root = Path(package_root).absolute()
    verification = verify_installed_package(
        root, expected_manifest_digest, available_cpu_features=available_cpu_features,
    )
    if not verification.verified or verification.build_mode != "formal-alpha1":
        raise ValueError("verified formal-alpha1 package is required for D04 scheme loading")
    manifest_path = _safe_file(root, "release-manifest.json")
    if manifest_path is None:
        raise ValueError("release manifest is missing or unsafe")
    manifest_bytes = manifest_path.read_bytes()
    if not hmac.compare_digest(hashlib.sha256(manifest_bytes).hexdigest(), expected_manifest_digest):
        raise ValueError("release manifest changed after package verification")
    manifest = _json_object(manifest_bytes, "release manifest")
    binding = manifest.get("affect_scheme")
    if not isinstance(binding, dict) or set(binding) != {"path", "sha256", "bytes", "catalogue_capability", *_VERSIONS}:
        raise ValueError("D04 manifest asset binding is missing or incomplete")
    if binding["path"] != _ASSET_PATH or binding["catalogue_capability"] != _CAPABILITY:
        raise ValueError("D04 manifest asset path or capability is invalid")
    content, entry = _listed_bytes(root, manifest, _ASSET_PATH)
    if any(binding.get(field) != entry.get(field) for field in ("path", "sha256", "bytes")):
        raise ValueError("D04 asset binding differs from manifest file entry")
    catalogue_bytes, _ = _listed_bytes(root, manifest, _CATALOGUE_PATH)
    catalogue = _json_object(catalogue_bytes, "type catalogue")
    capabilities = catalogue.get("domain_capabilities")
    if (catalogue.get("activation_status") != "runtime_verified"
            or catalogue.get("release_eligibility") != "READY"
            or not isinstance(capabilities, dict)
            or not isinstance(capabilities.get("d04"), list)
            or _CAPABILITY not in capabilities["d04"]):
        raise ValueError("type catalogue does not declare an active D04 scheme capability")
    data = _json_object(content, "D04 scheme asset")
    if set(data) != {"schema", *_VERSIONS, "axes", "parameter_bounds"}:
        raise ValueError("D04 scheme asset fields are invalid")
    if any(type(data[name]) is not str or data[name] != binding[name] for name in _VERSIONS):
        raise ValueError("D04 scheme versions differ from manifest binding")
    axes = data["axes"]
    bounds = data["parameter_bounds"]
    if (not isinstance(axes, list) or not axes
            or any(not isinstance(axis, dict) or set(axis) != {"axis_id", "unit", "meaning"} for axis in axes)
            or not isinstance(bounds, list)
            or any(not isinstance(item, list) or len(item) != 3 for item in bounds)):
        raise ValueError("D04 scheme axes or parameter bounds are invalid")
    scheme = AffectScheme(
        schema=data["schema"],
        **{name: data[name] for name in _VERSIONS},
        axes=tuple(AffectAxis(**axis) for axis in axes),
        parameter_bounds=tuple(tuple(item) for item in bounds),
    )
    registry = discover_domain_registry(active_affect_scheme=scheme)
    if not registry.complete or catalogue.get("catalogue_hash") != registry.type_registry.catalogue_hash:
        raise ValueError("type catalogue differs from the active DomainRegistry")
    return VerifiedAffectScheme(
        scheme, registry, hashlib.sha256(content).hexdigest(), expected_manifest_digest,
    )
