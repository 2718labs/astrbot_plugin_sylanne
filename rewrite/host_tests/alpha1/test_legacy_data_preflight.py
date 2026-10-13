"""Unmigrated data is rejected before a native graph store can create files."""

from pathlib import Path
import stat
from types import SimpleNamespace
from uuid import uuid4

import pytest

from sylanne3.host.legacy_data_preflight import inspect_native_data_dir_v1
from sylanne3.host.managed_data_layout_v1 import (
    InstalledDataLayoutV1, ManagedDataLayoutError, inspect_installed_data_layout_v1,
    support_export_root_v1,
)
from sylanne3.workbench_api.support_export import write_view_status_export_v1


def test_empty_and_existing_native_candidate_are_distinct(tmp_path):
    root = tmp_path / "plugin-data"
    assert inspect_native_data_dir_v1(root).status == "fresh"
    root.mkdir()
    assert inspect_native_data_dir_v1(root).status == "fresh"
    (root / "sylanne3.sqlite3").write_bytes(b"SQLite fixture bytes")
    result = inspect_native_data_dir_v1(root)
    assert result.status == "existing_native_candidate"
    assert "catalogue" in result.detail


def test_unknown_legacy_and_orphan_journal_require_migration(tmp_path):
    root = tmp_path / "plugin-data"
    root.mkdir()
    (root / "sylanne3.sqlite3-wal").write_bytes(b"orphan")
    assert inspect_native_data_dir_v1(root).status == "migration_required"
    (root / "sylanne3.sqlite3-wal").unlink()
    (root / "legacy-person-profile.json").write_text("{}", encoding="utf-8")
    assert inspect_native_data_dir_v1(root).status == "migration_required"
    assert (root / "legacy-person-profile.json").read_text(encoding="utf-8") == "{}"


def _export(root):
    receipt = write_view_status_export_v1(
        root=root, operation_id=str(uuid4()), scope="bot/persona",
        workspace={"namespace": {"bot": "bot", "persona": "persona"},
                   "access_generation": 1, "view_diagnostics": []})
    return Path(receipt["local_path"])


def test_managed_layout_accepts_interrupted_initialization_and_legal_export(tmp_path):
    assert inspect_native_data_dir_v1(tmp_path).status == "fresh"
    root = support_export_root_v1(tmp_path, create=True)
    assert inspect_native_data_dir_v1(tmp_path).status == "fresh"
    (tmp_path / "sylanne3.sqlite3").write_bytes(b"SQLite fixture bytes")
    exported = _export(root)
    before = exported.read_bytes()
    assert inspect_native_data_dir_v1(tmp_path).status == "existing_native_candidate"
    assert exported.read_bytes() == before
    (tmp_path / "sylanne3.sqlite3").unlink()
    assert inspect_native_data_dir_v1(tmp_path).status == "migration_required"
    assert exported.read_bytes() == before


@pytest.mark.parametrize("entry,kind", [
    ("unknown.bin", "file"), ("unknown", "directory"),
    ("sylanne3.sqlite3", "directory"), ("sylanne3.sqlite3-wal", "directory"),
    ("support_exports", "file"), ("support_exports/nested", "directory"),
    ("support_exports/unknown.json", "file"),
    ("support_exports/00000000-0000-4000-8000-000000000000.json", "directory"),
])
def test_unknown_entries_and_wrong_types_hold_valid_native_layout(tmp_path, entry, kind):
    graph = tmp_path / "sylanne3.sqlite3"
    graph.write_bytes(b"SQLite fixture bytes")
    support = support_export_root_v1(tmp_path, create=True)
    assert inspect_native_data_dir_v1(tmp_path).status == "existing_native_candidate"
    path = tmp_path / entry
    if path == graph:
        graph.unlink()
    elif path == support:
        support.rmdir()
    if kind == "directory":
        path.mkdir()
    else:
        path.write_bytes(b"unmanaged")
    assert inspect_native_data_dir_v1(tmp_path).status == "migration_required"
    assert path.exists()


@pytest.mark.parametrize("target", ["root", "ancestor", "graph", "support", "export"])
def test_link_paths_hold_before_following_them(tmp_path, target):
    data = tmp_path / "data"
    data.mkdir()
    graph = data / "sylanne3.sqlite3"
    graph.write_bytes(b"SQLite fixture bytes")
    support = support_export_root_v1(data, create=True)
    export = _export(support)
    assert inspect_native_data_dir_v1(data).status == "existing_native_candidate"
    outside = tmp_path / "outside"
    outside.mkdir()
    candidate = data
    if target in {"root", "ancestor"}:
        link = tmp_path / "link"
        destination = data if target == "root" else tmp_path
        candidate = link if target == "root" else link / "data"
        directory = True
    else:
        link = {"graph": graph, "support": support, "export": export}[target]
        directory = target == "support"
        destination = outside if directory else outside / "file"
        if directory:
            export.unlink()
            support.rmdir()
        else:
            link.unlink()
            destination.write_bytes(b"outside")
    try:
        link.symlink_to(destination, target_is_directory=directory)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    assert inspect_native_data_dir_v1(candidate).status == "migration_required"
    assert link.is_symlink()


def test_reparse_attribute_holds_native_root(tmp_path, monkeypatch):
    assert inspect_native_data_dir_v1(tmp_path).status == "fresh"
    original = Path.lstat

    def reparse(path):
        if path == tmp_path:
            return SimpleNamespace(st_mode=stat.S_IFDIR,
                                   st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
        return original(path)

    monkeypatch.setattr(Path, "lstat", reparse)
    assert inspect_native_data_dir_v1(tmp_path).status == "migration_required"


@pytest.mark.parametrize("failure", ["stat", "list", "read"])
def test_uninspectable_paths_hold_valid_native_layout(tmp_path, monkeypatch, failure):
    graph = tmp_path / "sylanne3.sqlite3"
    graph.write_bytes(b"SQLite fixture bytes")
    assert inspect_native_data_dir_v1(tmp_path).status == "existing_native_candidate"
    method, denied = {"stat": ("lstat", tmp_path), "list": ("iterdir", tmp_path),
                      "read": ("open", graph)}[failure]
    original = getattr(Path, method)

    def blocked(path, *args, **kwargs):
        if path == denied:
            raise PermissionError("isolated access denial")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, method, blocked)
    assert inspect_native_data_dir_v1(tmp_path).status == "migration_required"


def _admitted_layout_fixture(tmp_path, topology):
    """Pure inventory fixture; this is not authenticated Linux Host admission."""
    data = tmp_path / "plugin"
    data.mkdir()
    graph_parent = {"same": data, "disjoint": tmp_path / "graph-storage",
                    "descendant": data / "storage" / "generation-1"}[topology]
    graph_parent.mkdir(parents=True, exist_ok=True)
    graph = graph_parent / "current_graph.sqlite3"
    graph.write_bytes(b"existing admitted Graph fixture bytes")
    admission = SimpleNamespace(graph_path=graph)
    layout = InstalledDataLayoutV1(data, graph, admission)
    export = _export(support_export_root_v1(data, create=True))
    return layout, export


@pytest.mark.parametrize("topology", ["same", "disjoint", "descendant"])
def test_admitted_inventory_keeps_exact_graph_and_plugin_exports(tmp_path, topology):
    layout, export = _admitted_layout_fixture(tmp_path, topology)
    before = export.read_bytes()
    assert inspect_installed_data_layout_v1(layout) == (True, True)
    assert layout.graph_placement == "admitted"
    assert layout.graph_path.name == "current_graph.sqlite3"
    assert layout.support_export_root == export.parent
    assert export.read_bytes() == before
    # The same bytes do not authorize local-only startup without this selection.
    assert inspect_native_data_dir_v1(layout.plugin_data_root).status == "migration_required"


@pytest.mark.parametrize("failure", [
    "missing_graph", "wrong_basename", "local_graph_conflict", "unknown_plugin_file",
    "unknown_graph_file", "graph_directory", "sidecar_directory", "ancestor_sibling",
    "graph_in_exports",
])
def test_admitted_inventory_rejects_unregistered_or_broken_selection(tmp_path, failure):
    topology = "descendant" if failure == "ancestor_sibling" else "disjoint"
    layout, export = _admitted_layout_fixture(tmp_path, topology)
    assert inspect_installed_data_layout_v1(layout) == (True, True)
    before = export.read_bytes()
    graph = layout.graph_path
    if failure == "missing_graph":
        graph.unlink()
        (graph.parent / (graph.name + "-wal")).write_bytes(b"orphan")
    elif failure == "wrong_basename":
        graph.rename(graph.parent / "wrong_graph.sqlite3")
    elif failure in {"local_graph_conflict", "unknown_plugin_file"}:
        name = "sylanne3.sqlite3" if failure == "local_graph_conflict" else "unknown.bin"
        (layout.plugin_data_root / name).write_bytes(b"preserved unknown bytes")
    elif failure == "unknown_graph_file":
        (graph.parent / "unknown.bin").write_bytes(b"preserved unknown bytes")
    elif failure == "graph_directory":
        graph.unlink()
        graph.mkdir()
    elif failure == "sidecar_directory":
        (graph.parent / (graph.name + "-shm")).mkdir()
    elif failure == "ancestor_sibling":
        (graph.parent.parent / "unregistered_generation").mkdir()
    else:
        selected = export.parent / "current_graph.sqlite3"
        graph.rename(selected)
        layout = InstalledDataLayoutV1(layout.plugin_data_root, selected,
                                       SimpleNamespace(graph_path=selected))
    with pytest.raises((ManagedDataLayoutError, OSError)):
        inspect_installed_data_layout_v1(layout)
    assert export.read_bytes() == before


def test_admitted_inventory_does_not_substitute_another_graph_path(tmp_path):
    layout, _ = _admitted_layout_fixture(tmp_path, "disjoint")
    assert inspect_installed_data_layout_v1(layout) == (True, True)
    substitute = layout.graph_path.parent / "another.sqlite3"
    substitute.write_bytes(b"another existing file is not admission")
    changed = InstalledDataLayoutV1(layout.plugin_data_root, substitute, layout.storage_admission)
    with pytest.raises(ManagedDataLayoutError, match="differs from installed admission"):
        inspect_installed_data_layout_v1(changed)


@pytest.mark.parametrize("target", ["graph", "ancestor"])
def test_admitted_inventory_rejects_links_at_actual_graph_location(tmp_path, target):
    layout, export = _admitted_layout_fixture(tmp_path, "disjoint")
    assert inspect_installed_data_layout_v1(layout) == (True, True)
    before = export.read_bytes()
    outside = tmp_path / "outside"
    outside.mkdir()
    if target == "graph":
        destination = outside / layout.graph_path.name
        layout.graph_path.rename(destination)
        link = layout.graph_path
    else:
        destination = outside / "graph-storage"
        layout.graph_path.parent.rename(destination)
        link = layout.graph_path.parent
    try:
        link.symlink_to(destination, target_is_directory=target == "ancestor")
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    with pytest.raises(ManagedDataLayoutError, match="link or reparse"):
        inspect_installed_data_layout_v1(layout)
    assert export.read_bytes() == before
