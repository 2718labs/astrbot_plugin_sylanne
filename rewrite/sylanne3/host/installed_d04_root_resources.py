"""Resolve a formally installed D04 authored root and its current D11 budget."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from ..runtime_contracts import NamespaceId, canonical_serialize
from ..workbench_api.service import AuthenticatedSession
from .installed_package import _safe_file, verify_installed_backend_runtime_v1

if TYPE_CHECKING:
    from ..domains.d04.root import AuthoredRootPreset


_PRESET_PATH = "resources/catalogue/d04-authored-root-preset.v3.json"
_BINDING_FIELDS = frozenset((
    "path", "sha256", "bytes", "preset_id", "preset_version", "preset_digest",
))


def _object(content: bytes, label: str) -> dict:
    def unique(pairs: list[tuple[str, object]]) -> dict:
        result: dict[str, object] = {}
        for name, value in pairs:
            if name in result:
                raise ValueError(f"duplicate {label} field")
            result[name] = value
        return result

    try:
        value = json.loads(content, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError(label)))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid JSON") from exc
    if type(value) is not dict:
        raise ValueError(f"{label} must be an object")
    return value


def load_installed_d04_root_preset_v3(
    package_root: Path | str, trusted_manifest_sha256: str, *,
    available_cpu_features: frozenset[str] | None = None,
) -> AuthoredRootPreset:
    """Decode only manifest-bound preset bytes from a verified formal package."""
    original = Path(package_root)
    if original.is_symlink() or bool(getattr(original, "is_junction", lambda: False)()):
        raise ValueError("installed package root is linked")
    root = original.resolve(strict=True)
    verification = verify_installed_backend_runtime_v1(
        root, trusted_manifest_sha256,
        available_cpu_features=available_cpu_features,
    )
    if (not verification.verified
            or verification.manifest_digest != trusted_manifest_sha256):
        raise ValueError("formal installed D04 root package is unavailable")
    manifest_path = _safe_file(root, "release-manifest.json")
    preset_path = _safe_file(root, _PRESET_PATH)
    if manifest_path is None or preset_path is None:
        raise ValueError("installed D04 root preset or manifest is missing or unsafe")
    manifest_bytes = manifest_path.read_bytes()
    if not hmac.compare_digest(hashlib.sha256(manifest_bytes).hexdigest(),
                               trusted_manifest_sha256):
        raise ValueError("installed D04 root manifest changed after verification")
    manifest = _object(manifest_bytes, "installed manifest")
    binding = manifest.get("authored_root_preset")
    if (type(binding) is not dict or frozenset(binding) != _BINDING_FIELDS
            or binding.get("path") != _PRESET_PATH):
        raise ValueError("formal D04 root preset manifest binding is absent")
    rows = manifest.get("files")
    if type(rows) is not list:
        raise ValueError("formal package file list is absent")
    matches = [row for row in rows if type(row) is dict and row.get("path") == _PRESET_PATH]
    if len(matches) != 1:
        raise ValueError("formal D04 root preset must be listed exactly once")
    content = preset_path.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    entry = matches[0]
    if (type(binding["bytes"]) is not int or binding["bytes"] != len(content)
            or type(binding["sha256"]) is not str
            or not hmac.compare_digest(binding["sha256"], digest)
            or any(entry.get(name) != binding[name]
                   for name in ("path", "sha256", "bytes"))):
        raise ValueError("formal D04 root preset bytes differ from manifest")
    raw = _object(content, "D04 root preset")
    if canonical_serialize(raw).encode("utf-8") != content:
        raise ValueError("D04 root preset bytes must be canonical")
    from ..domains.d04.root import AuthoredRootPreset, decode_root_preset

    preset = decode_root_preset(raw)
    if (type(preset) is not AuthoredRootPreset
            or binding["preset_id"] != preset.preset_id
            or binding["preset_version"] != preset.preset_version
            or binding["preset_digest"] != preset.digest):
        raise ValueError("D04 root preset identity differs from formal manifest")
    return preset


class InstalledD04RootResources:
    """Owner Workbench resolver; the Graph repeats budget checks in its write txn."""

    def __init__(self, *, namespace: NamespaceId, package_root: Path,
                 trusted_manifest_sha256: str,
                 read_current_dedicated_lease: Callable[[NamespaceId], str | None],
                 available_cpu_features: frozenset[str] | None = None) -> None:
        if (type(namespace) is not NamespaceId
                or not callable(read_current_dedicated_lease)):
            raise TypeError("trusted D04 root namespace and budget reader required")
        self._namespace = namespace
        self._package_root = Path(package_root)
        self._manifest_sha256 = trusted_manifest_sha256
        self._read_current_dedicated_lease = read_current_dedicated_lease
        self._available_cpu_features = available_cpu_features

    def resolve_current_d04_root_resources(
        self, *, namespace: NamespaceId, session: AuthenticatedSession,
    ) -> tuple[AuthoredRootPreset, str] | None:
        if (type(namespace) is not NamespaceId or namespace != self._namespace
                or type(session) is not AuthenticatedSession
                or not session.actor_id or not session.session_id
                or not session.owner_session_token):
            return None
        preset = load_installed_d04_root_preset_v3(
            self._package_root, self._manifest_sha256,
            available_cpu_features=self._available_cpu_features,
        )
        lease_id = self._read_current_dedicated_lease(namespace)
        if type(lease_id) is not str or not lease_id:
            return None
        return preset, lease_id


__all__ = ["InstalledD04RootResources", "load_installed_d04_root_preset_v3"]
