"""Minimal local support export from a current Owner-fenced view read."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Mapping
from uuid import UUID


SCHEMA = "d12.support_view_status.v1"


def write_view_status_export_v1(
    *, root: Path, operation_id: str, scope: str,
    workspace: Mapping[str, object],
) -> dict[str, object]:
    """Write one immutable, content-free manifest under a trusted directory."""
    try:
        parsed = UUID(operation_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("canonical support operation id is required") from exc
    if parsed.version != 4 or str(parsed) != operation_id:
        raise ValueError("canonical support operation id is required")
    if not isinstance(root, Path) or not root.is_dir() or root.is_symlink():
        raise ValueError("trusted support export directory is unavailable")
    diagnostics = workspace.get("view_diagnostics")
    if type(diagnostics) not in (tuple, list):
        raise ValueError("current view diagnostics are unavailable")
    rows: list[dict[str, object]] = []
    for item in diagnostics:
        if not isinstance(item, Mapping):
            raise ValueError("invalid current view diagnostic")
        name, status = item.get("view_type"), item.get("read_status")
        if (type(name) is not str or not 1 <= len(name) <= 128
                or type(status) is not str
                or status not in {"ready", "stale", "partial", "unavailable", "unauthorized"}):
            raise ValueError("invalid current view diagnostic")
        row: dict[str, object] = {"view_type": name, "read_status": status}
        coverage = item.get("coverage")
        if coverage is not None and (type(coverage) is not str
                                     or coverage not in {"complete", "partial", "not_disclosed"}):
            raise ValueError("invalid current view diagnostic")
        if type(coverage) is str and coverage in {"complete", "partial", "not_disclosed"}:
            row["coverage"] = coverage
        revision = item.get("snapshot_epoch")
        if revision is not None and (type(revision) is not int or revision < 0):
            raise ValueError("invalid current view diagnostic")
        if type(revision) is int and revision >= 0:
            row["snapshot_epoch"] = revision
        rows.append(row)
    if len(rows) > 64 or len({row["view_type"] for row in rows}) != len(rows):
        raise ValueError("view diagnostics exceed the support contract")
    generation = workspace.get("access_generation")
    if type(generation) is not int or generation < 1:
        raise ValueError("current access generation is unavailable")
    namespace = workspace.get("namespace")
    if (len(scope.split("/")) != 2 or not isinstance(namespace, Mapping)
            or type(namespace.get("bot")) is not str
            or type(namespace.get("persona")) is not str
            or f"{namespace['bot']}/{namespace['persona']}" != scope):
        raise ValueError("current support namespace differs")
    payload = {
        "schema": SCHEMA, "operation_id": operation_id, "scope": scope,
        "access_generation": generation, "allowed_data": ["view_status"],
        "retention_policy_ref": "d12.local_manual_retention.v1",
        "view_status": sorted(rows, key=lambda row: row["view_type"]),
    }
    digest = sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8")).hexdigest()
    manifest = {**payload, "payload_sha256": digest}
    encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False) + "\n").encode("utf-8")
    root = root.resolve(strict=True)
    path = root / f"{operation_id}.json"
    if path.exists() or path.is_symlink():
        if path.is_symlink() or path.resolve(strict=True).parent != root:
            raise ValueError("support export path is not a regular managed file")
        if path.read_bytes() != encoded:
            raise ValueError("support export operation has a different current snapshot")
    else:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    return {
        "operation_id": operation_id, "phase": "local_support_export_recorded",
        "schema": SCHEMA, "local_path": str(path),
        "manifest_sha256": sha256(encoded).hexdigest(),
        "payload_sha256": digest, "view_count": len(rows),
        "allowed_data": ["view_status"],
        "retention_policy_ref": "d12.local_manual_retention.v1",
    }


__all__ = ("SCHEMA", "write_view_status_export_v1")
