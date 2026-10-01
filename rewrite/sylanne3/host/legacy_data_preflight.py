"""Conservative pre-open gate for native graph data and unmigrated plugin data.

The registered 2.5 PersonProfile migrator is preview-only. An unknown local
file is never evidence that its content was migrated or may be discarded.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class NativeDataPreflightV1:
    status: str  # fresh | existing_native_candidate | migration_required
    detail: str


def inspect_native_data_dir_v1(data_dir: Path) -> NativeDataPreflightV1:
    """Do not create, rename, read or clean any file while classifying data."""
    path = Path(data_dir)
    if not path.is_absolute() or path.is_symlink():
        return NativeDataPreflightV1("migration_required", "unsafe data directory")
    if not path.exists():
        return NativeDataPreflightV1("fresh", "no plugin data directory")
    if not path.is_dir():
        return NativeDataPreflightV1("migration_required", "plugin data is not a directory")
    try:
        entries = tuple(path.iterdir())
    except OSError:
        return NativeDataPreflightV1("migration_required", "plugin data cannot be inspected")
    names = {entry.name for entry in entries}
    graph_name = "sylanne3.sqlite3"
    allowed = {graph_name, graph_name + "-wal", graph_name + "-shm"}
    if (names - allowed
            or any(entry.is_symlink() or not entry.is_file() for entry in entries)):
        return NativeDataPreflightV1(
            "migration_required", "unrecognized or unsafe plugin data needs review")
    if graph_name not in names:
        if names:
            return NativeDataPreflightV1(
                "migration_required", "orphan graph journal needs review")
        return NativeDataPreflightV1("fresh", "empty plugin data directory")
    return NativeDataPreflightV1(
        "existing_native_candidate", "graph catalogue and Authority recovery still required")


__all__ = ("NativeDataPreflightV1", "inspect_native_data_dir_v1")
