"""Conservative pre-open gate for native graph data and unmigrated plugin data.

The registered 2.5 PersonProfile migrator is preview-only. An unknown local
file is never evidence that its content was migrated or may be discarded.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .managed_data_layout_v1 import (
    GRAPH_NAME, InstalledDataLayoutV1, ManagedDataLayoutError,
    managed_data_root_v1, inspect_installed_data_layout_v1,
)


@dataclass(frozen=True, slots=True)
class NativeDataPreflightV1:
    status: str  # fresh | existing_native_candidate | migration_required
    detail: str


def inspect_native_data_dir_v1(data_dir: Path) -> NativeDataPreflightV1:
    """Do not create, rename, read or clean any file while classifying data."""
    try:
        path = managed_data_root_v1(data_dir, allow_missing=True)
        graph_present, _ = inspect_installed_data_layout_v1(
            InstalledDataLayoutV1(path, path / GRAPH_NAME))
    except (OSError, ManagedDataLayoutError):
        return NativeDataPreflightV1(
            "migration_required", "unrecognized or unsafe plugin data needs review")
    if not graph_present:
        return NativeDataPreflightV1("fresh", "empty plugin data directory")
    return NativeDataPreflightV1(
        "existing_native_candidate", "graph catalogue and Authority recovery still required")


__all__ = ("NativeDataPreflightV1", "inspect_native_data_dir_v1")
