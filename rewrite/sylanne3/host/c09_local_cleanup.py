"""Bounded cleanup of Host-owned support exports after the runtime stops.

This is evidence for one managed directory, not a C09 surface or closure
attestation. Other local files and provider-side prompt caches are excluded.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from uuid import UUID

from ..runtime_contracts import NamespaceId
from ..workbench_api.support_export import SCHEMA
from .managed_data_layout_v1 import (
    ManagedDataLayoutError, support_export_files_v1, support_export_root_v1,
)


class LocalCleanupHold(RuntimeError):
    """A managed writer or complete file inventory is unavailable."""


@dataclass(frozen=True, slots=True)
class ManagedSupportExportPurgeV1:
    operation_id: str
    namespace: NamespaceId
    root: Path
    removed: tuple[tuple[str, str], ...]  # filename, exact old-byte SHA-256
    status: str = "managed_support_exports_purged"


def _inventory(root: Path) -> tuple[tuple[Path, dict, bytes], ...]:
    entries: list[tuple[Path, dict, bytes]] = []
    try:
        paths = support_export_files_v1(root)
    except (OSError, ManagedDataLayoutError) as exc:
        raise LocalCleanupHold("support export inventory contains an unmanaged entry") from exc
    for path in paths:
        try:
            operation = UUID(path.stem)
            content = path.read_bytes()
            raw = json.loads(content)
            if type(raw) is not dict:
                raise ValueError("support export must be an object")
            payload = {key: value for key, value in raw.items()
                       if key != "payload_sha256"}
            encoded = (json.dumps(raw, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False) + "\n").encode("utf-8")
            payload_digest = sha256(json.dumps(
                payload, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False).encode("utf-8")).hexdigest()
        except (OSError, TypeError, ValueError, UnicodeError) as exc:
            raise LocalCleanupHold("support export inventory is unreadable") from exc
        if (operation.version != 4 or str(operation) != path.stem
                or type(raw) is not dict
                or set(raw) != {"schema", "operation_id", "scope",
                               "access_generation", "allowed_data",
                               "retention_policy_ref", "view_status",
                               "payload_sha256"}
                or raw["schema"] != SCHEMA or raw["operation_id"] != path.stem
                or type(raw["scope"]) is not str
                or raw["allowed_data"] != ["view_status"]
                or raw["retention_policy_ref"] != "d12.local_manual_retention.v1"
                or raw["payload_sha256"] != payload_digest
                or encoded != content):
            raise LocalCleanupHold("support export original differs")
        entries.append((path, raw, content))
    return tuple(entries)


async def purge_stopped_support_exports_v1(
    runtime: object, namespace: NamespaceId, *, deletion_operation_id: str,
) -> ManagedSupportExportPurgeV1:
    """Stop the sole local graph writer, then delete verified scoped exports."""
    from ..runtime_context import RuntimeContext

    if (type(runtime) is not RuntimeContext or type(namespace) is not NamespaceId
            or type(deletion_operation_id) is not str
            or not deletion_operation_id):
        raise LocalCleanupHold("installed runtime and deletion identity required")
    health = await runtime.stop()
    if health.status != "stopped":
        raise LocalCleanupHold("runtime writer did not stop")
    async with runtime._lock:
        if (runtime.health.status != "stopped" or runtime._worker is not None
                or runtime._store is not None):
            raise LocalCleanupHold("runtime writer restarted")
        try:
            root = support_export_root_v1(runtime._data_dir)
        except (OSError, ManagedDataLayoutError) as exc:
            raise LocalCleanupHold("managed support export directory is absent or unsafe") from exc
        scope = "/".join(namespace.as_tuple)
        entries = _inventory(root)
        target = tuple((path, content) for path, raw, content in entries
                       if raw["scope"] == scope)
        if not target:
            raise LocalCleanupHold("no scoped managed support export to purge")
        removed = []
        for path, content in target:
            if path.read_bytes() != content:
                raise LocalCleanupHold("support export changed during cleanup")
            path.unlink()
            removed.append((path.name, sha256(content).hexdigest()))
        if any(raw["scope"] == scope for _, raw, _ in _inventory(root)):
            raise LocalCleanupHold("scoped support export remained after cleanup")
        return ManagedSupportExportPurgeV1(
            deletion_operation_id, namespace, root, tuple(removed))


__all__ = (
    "LocalCleanupHold", "ManagedSupportExportPurgeV1",
    "purge_stopped_support_exports_v1",
)
