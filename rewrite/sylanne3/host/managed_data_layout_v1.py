"""V1 Host-owned data paths shared by startup, exports and stopped cleanup."""

from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass
import stat
from uuid import UUID


GRAPH_NAME = "sylanne3.sqlite3"
SUPPORT_EXPORTS_NAME = "support_exports"


class ManagedDataLayoutError(ValueError):
    """The supplied path is outside the managed V1 layout."""


@dataclass(frozen=True, slots=True)
class InstalledDataLayoutV1:
    """Selected paths, not authority; admission is the original installed IPC fact."""

    plugin_data_root: Path
    graph_path: Path
    storage_admission: object | None = None
    version: str = "sylanne3.managed_data_layout.v1"

    @property
    def support_export_root(self) -> Path:
        return self.plugin_data_root / SUPPORT_EXPORTS_NAME

    @property
    def graph_placement(self) -> str:
        return "admitted" if self.storage_admission is not None else "local-default"


def _kind(path: Path, *, missing: bool = False) -> int | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing:
            return None
        raise
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise ManagedDataLayoutError("managed path is a link or reparse path")
    return info.st_mode


def managed_data_root_v1(data_dir: Path, *, allow_missing: bool = False) -> Path:
    path = Path(data_dir)
    if not path.is_absolute():
        raise ManagedDataLayoutError("managed data root must be absolute")
    # Inspect the supplied path before resolve can hide any link in its ancestry.
    for ancestor in reversed(path.parents):
        mode = _kind(ancestor, missing=allow_missing)
        if mode is not None and not stat.S_ISDIR(mode):
            raise ManagedDataLayoutError("managed data ancestor is not a directory")
    mode = _kind(path, missing=allow_missing)
    if mode is not None and not stat.S_ISDIR(mode):
        raise ManagedDataLayoutError("managed data root is not a directory")
    return path.resolve(strict=mode is not None)


def require_managed_file_v1(path: Path, root: Path) -> None:
    if not stat.S_ISREG(_kind(path)) or path.resolve(strict=True).parent != root:
        raise ManagedDataLayoutError("managed entry is not a contained regular file")
    # Opening without reading checks access without treating bytes as migration proof.
    with path.open("rb"):
        pass


def support_export_root_v1(data_dir: Path, *, create: bool = False) -> Path:
    data = managed_data_root_v1(data_dir)
    root = data / SUPPORT_EXPORTS_NAME
    mode = _kind(root, missing=create)
    if mode is None:
        root.mkdir(mode=0o700)
        mode = _kind(root)
    if not stat.S_ISDIR(mode) or root.resolve(strict=True).parent != data:
        raise ManagedDataLayoutError("support export root is not a contained directory")
    return root.resolve(strict=True)


def support_export_filename_v1(operation_id: str) -> str:
    try:
        operation = UUID(operation_id)
    except (TypeError, ValueError, AttributeError) as exc:
        raise ManagedDataLayoutError("canonical support operation id is required") from exc
    if operation.version != 4 or str(operation) != operation_id:
        raise ManagedDataLayoutError("canonical support operation id is required")
    return operation_id + ".json"


def support_export_files_v1(root: Path) -> tuple[Path, ...]:
    if root.name != SUPPORT_EXPORTS_NAME:
        raise ManagedDataLayoutError("support export root has an unmanaged name")
    root = support_export_root_v1(root.parent)
    entries = tuple(root.iterdir())
    for path in entries:
        if path.name != support_export_filename_v1(path.stem):
            raise ManagedDataLayoutError("support export inventory contains an unmanaged entry")
        require_managed_file_v1(path, root)
    return entries


def inspect_installed_data_layout_v1(layout: InstalledDataLayoutV1) -> tuple[bool, bool]:
    """Check an exact selected inventory; return graph-present, exports-present.

    Constructing a layout in a fixture proves inventory behavior only. Production
    selection is derived by the actual installation assembler, never user config.
    """
    data = managed_data_root_v1(layout.plugin_data_root, allow_missing=True)
    graph = layout.graph_path
    if layout.storage_admission is None:
        if graph != data / GRAPH_NAME:
            raise ManagedDataLayoutError("local Graph selection differs from managed layout")
    elif graph != layout.storage_admission.graph_path:
        raise ManagedDataLayoutError("Graph selection differs from installed admission")
    if not graph.is_absolute():
        raise ManagedDataLayoutError("selected Graph path must be absolute")
    graph_parent = managed_data_root_v1(
        graph.parent, allow_missing=layout.storage_admission is None)
    graph_present = _kind(graph, missing=True) is not None
    if graph_present:
        require_managed_file_v1(graph, graph_parent)
    elif layout.storage_admission is not None:
        raise ManagedDataLayoutError("admitted Graph is absent; recovery is required")
    graph_files = {graph.name, graph.name + "-wal", graph.name + "-shm"}
    if graph_parent.is_relative_to(data):
        chain = graph_parent.relative_to(data).parts
        if chain and chain[0] == SUPPORT_EXPORTS_NAME:
            raise ManagedDataLayoutError("Graph overlaps managed support exports")
        roots = (data, *(data.joinpath(*chain[:n]) for n in range(1, len(chain) + 1)))
    else:
        chain = ()
        roots = (data, graph_parent)
    exported = False
    journals = False
    for root in roots:
        if _kind(root, missing=layout.storage_admission is None or root == data) is None:
            continue
        directory = managed_data_root_v1(root)
        for entry in directory.iterdir():
            if directory == data and entry.name == SUPPORT_EXPORTS_NAME:
                exported = bool(support_export_files_v1(entry))
            elif directory == graph_parent and entry.name in graph_files:
                require_managed_file_v1(entry, directory)
                journals |= entry.name != graph.name
            elif chain and directory != graph_parent and entry == roots[roots.index(root) + 1]:
                managed_data_root_v1(entry)
            else:
                raise ManagedDataLayoutError("unregistered or ambiguous installed data entry")
    if not graph_present and (journals or exported):
        raise ManagedDataLayoutError("orphan graph journal or support export needs review")
    return graph_present, exported


__all__ = (
    "GRAPH_NAME", "SUPPORT_EXPORTS_NAME", "ManagedDataLayoutError",
    "InstalledDataLayoutV1", "inspect_installed_data_layout_v1",
    "managed_data_root_v1", "require_managed_file_v1", "support_export_root_v1",
    "support_export_filename_v1", "support_export_files_v1",
)
