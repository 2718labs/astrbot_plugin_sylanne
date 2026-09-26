"""Load a D04 tanh readout candidate from a manifest-pinned installation.

The manifest digest and RootAssetBindings must come from trusted callers.
This validates asset identity for conditional math only; it does not issue a
numerical G2 certificate, semantic calibration, or startup admission.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path

from ..domains.d04.numeric_coupling import REGISTERED_AXIS_IDS
from ..domains.d04.root import RootAssetBindings
from ..native_runtime.d04_tanh_readout_asset import (
    ASSET_NAME, D04LoadedTanhReadoutAsset, load_d04_tanh_readout_asset,
)
from .installed_package import _safe_file, verify_installed_package


_ASSET_PATH = f"resources/catalogue/{ASSET_NAME}"
_SCHEME_PATH = "resources/catalogue/d04-affect-scheme.json"
_BINDING_FIELDS = {
    "path", "sha256", "bytes", "schema", "readout_id", "readout_version",
    "scheme_version", "axis_ids", "axis_units", "output_ids", "transform", "status",
}


@dataclass(frozen=True, slots=True)
class InstalledTanhReadoutCandidate:
    asset: D04LoadedTanhReadoutAsset
    manifest_sha256: str
    build_mode: str
    status: str = "candidate"


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"installed D04 JSON repeats field: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"installed D04 JSON has nonfinite number: {value}")


def _object(content: bytes, label: str) -> dict:
    try:
        value = json.loads(content, object_pairs_hook=_unique_fields,
                           parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid JSON") from exc
    if type(value) is not dict:
        raise ValueError(f"{label} must be a JSON object")
    return value


def _listed_bytes(root: Path, manifest: dict, relative: str) -> tuple[bytes, dict]:
    entries = manifest.get("files")
    if type(entries) is not list:
        raise ValueError("installed package file list is missing")
    matches = [entry for entry in entries
               if type(entry) is dict and entry.get("path") == relative]
    if len(matches) != 1:
        raise ValueError(f"installed package must list {relative} exactly once")
    path = _safe_file(root, relative)
    if path is None:
        raise ValueError(f"installed package asset is missing or unsafe: {relative}")
    content = path.read_bytes()
    entry = matches[0]
    if (type(entry.get("bytes")) is not int or entry["bytes"] != len(content)
            or type(entry.get("sha256")) is not str
            or not hmac.compare_digest(entry["sha256"], hashlib.sha256(content).hexdigest())):
        raise ValueError(f"installed package asset differs from manifest: {relative}")
    return content, entry


def load_installed_tanh_readout_candidate(
    package_root: Path | str, expected_manifest_digest: str,
    bindings: RootAssetBindings, *, expected_readout_id: str,
    available_cpu_features: frozenset[str] | None = None,
) -> InstalledTanhReadoutCandidate:
    """Bind one installed candidate to trusted manifest and checkpoint identities."""
    if type(bindings) is not RootAssetBindings:
        raise TypeError("installed D04 readout requires RootAssetBindings")
    root = Path(package_root).absolute()
    verified = verify_installed_package(
        root, expected_manifest_digest, available_cpu_features=available_cpu_features,
    )
    if not verified.verified:
        raise ValueError(f"installed package verification failed: {verified.reason}")
    manifest_path = _safe_file(root, "release-manifest.json")
    if manifest_path is None:
        raise ValueError("installed release manifest is missing or unsafe")
    manifest_bytes = manifest_path.read_bytes()
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    if not hmac.compare_digest(digest, expected_manifest_digest):
        raise ValueError("installed release manifest changed after verification")
    manifest = _object(manifest_bytes, "installed release manifest")
    binding = manifest.get("tanh_readout")
    if (type(binding) is not dict or set(binding) != _BINDING_FIELDS
            or binding["path"] != _ASSET_PATH
            or binding["schema"] != "d04.tanh-readout-asset.v1"
            or binding["transform"] != "p=C*tanh(z)"
            or binding["status"] != "candidate"):
        raise ValueError("installed D04 tanh manifest binding is missing or invalid")
    scheme_bytes, _ = _listed_bytes(root, manifest, _SCHEME_PATH)
    scheme = _object(scheme_bytes, "installed D04 affect scheme")
    axes = scheme.get("axes")
    if (hashlib.sha256(scheme_bytes).hexdigest() != bindings.scheme_sha256
            or scheme.get("schema") != "d04.affect.scheme.v1"
            or scheme.get("scheme_version") != bindings.scheme_version
            or type(axes) is not list or len(axes) != 24
            or any(type(axis) is not dict or axis.get("unit") != "normalized"
                   for axis in axes)
            or tuple(axis.get("axis_id") for axis in axes) != REGISTERED_AXIS_IDS):
        raise ValueError("installed D04 affect scheme differs from checkpoint or 24-axis identity")
    content, entry = _listed_bytes(root, manifest, _ASSET_PATH)
    if (any(binding[field] != entry.get(field) for field in ("path", "sha256", "bytes"))
            or binding["sha256"] != bindings.readout_sha256
            or binding["readout_version"] != bindings.readout_version
            or binding["scheme_version"] != bindings.scheme_version
            or binding["readout_id"] != expected_readout_id
            or binding["axis_ids"] != list(REGISTERED_AXIS_IDS)
            or binding["axis_units"] != ["normalized"] * 24):
        raise ValueError("installed D04 tanh binding differs from checkpoint, scheme or file entry")
    loaded = load_d04_tanh_readout_asset(
        root / "resources" / "catalogue", bindings,
        expected_readout_id=expected_readout_id,
    )
    if (loaded.asset_sha256 != hashlib.sha256(content).hexdigest()
            or binding["output_ids"] != [row.output_id for row in loaded.rows]):
        raise ValueError("installed D04 tanh outputs differ from manifest binding")
    return InstalledTanhReadoutCandidate(loaded, digest, verified.build_mode)


__all__ = ("InstalledTanhReadoutCandidate", "load_installed_tanh_readout_candidate")
