"""Load the minimal D03 context scheme from a pinned formal package."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path

from .installed_package import _safe_file, verify_installed_backend_runtime_v1


_ASSET_PATH = "resources/catalogue/d03-neutral-context-scheme.json"
_SCHEMA = "d03.context.scheme.v1"
_NEUTRAL_ROLE = "scene_participant"


@dataclass(frozen=True, slots=True)
class VerifiedContextScheme:
    """Authenticated D03 draft; it grants no scene binding or send authority."""

    asset_sha256: str
    manifest_sha256: str

    def draft(self) -> dict:
        return {"schema": _SCHEMA, "roles": (_NEUTRAL_ROLE,), "norms": ()}


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _json_object(content: bytes, label: str) -> dict:
    try:
        value = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid JSON") from exc
    if type(value) is not dict:
        raise ValueError(f"{label} must be a JSON object")
    return value


def load_verified_context_scheme(
    package_root: Path | str, expected_manifest_digest: str,
    *, available_cpu_features: frozenset[str] | None = None,
) -> VerifiedContextScheme:
    """Accept one exact neutral D03 draft only from pinned formal bytes."""

    root = Path(package_root).absolute()
    verification = verify_installed_backend_runtime_v1(
        root, expected_manifest_digest, available_cpu_features=available_cpu_features,
    )
    if not verification.verified:
        raise ValueError("verified formal-alpha1 package is required for D03 scheme loading")
    manifest_path = _safe_file(root, "release-manifest.json")
    if manifest_path is None:
        raise ValueError("release manifest is missing or unsafe")
    manifest_bytes = manifest_path.read_bytes()
    if not hmac.compare_digest(hashlib.sha256(manifest_bytes).hexdigest(), expected_manifest_digest):
        raise ValueError("release manifest changed after package verification")
    manifest = _json_object(manifest_bytes, "release manifest")
    entries = manifest.get("files")
    binding = manifest.get("context_scheme")
    if (type(entries) is not list or type(binding) is not dict
            or set(binding) != {"path", "sha256", "bytes", "schema"}
            or binding["path"] != _ASSET_PATH or binding["schema"] != _SCHEMA):
        raise ValueError("D03 manifest asset binding is missing or invalid")
    matches = [item for item in entries if type(item) is dict and item.get("path") == _ASSET_PATH]
    if len(matches) != 1 or any(binding[field] != matches[0].get(field)
                                for field in ("path", "sha256", "bytes")):
        raise ValueError("D03 asset binding differs from manifest file entry")
    asset_path = _safe_file(root, _ASSET_PATH)
    if asset_path is None:
        raise ValueError("D03 scheme asset is missing or unsafe")
    content = asset_path.read_bytes()
    asset_sha256 = hashlib.sha256(content).hexdigest()
    if (type(binding["bytes"]) is not int or binding["bytes"] != len(content)
            or type(binding["sha256"]) is not str
            or not hmac.compare_digest(binding["sha256"], asset_sha256)):
        raise ValueError("D03 scheme bytes differ from manifest")
    draft = _json_object(content, "D03 scheme asset")
    if (set(draft) != {"schema", "roles", "norms"}
            or draft != {"schema": _SCHEMA, "roles": [_NEUTRAL_ROLE], "norms": []}):
        raise ValueError("D03 scheme must contain only the neutral scene role and no norms")
    return VerifiedContextScheme(asset_sha256, expected_manifest_digest)


__all__ = ("VerifiedContextScheme", "load_verified_context_scheme")
