"""Read the real D06 SQLite sidecar without granting deletion completion."""

import sqlite3

import pytest

from sylanne3.domains.d06.deletion_index_inventory import (
    read_d06_index_deletion_inventory_v1,
)
from sylanne3.domains.d06.projection_index import (
    DurableSourceProjectionIndex, SourceIndexEpochPage, SourceIndexMutation,
)
from sylanne3.graph_types import NamespaceEpoch
from sylanne3.memory_types import source_key
from sylanne3.runtime_contracts import NamespaceId


NAMESPACE = NamespaceId("bot", "persona")


def _sidecar(path):
    index = DurableSourceProjectionIndex(path)
    root = source_key("bot", "persona", "root").token
    other = source_key("bot", "persona", "other").token
    index.begin_generation(NAMESPACE, "old")
    index.apply_page("old", SourceIndexEpochPage(
        NAMESPACE, 1, (SourceIndexMutation(root, 1, 1, True),)))
    index.activate(NAMESPACE, "old", NamespaceEpoch("bot", "persona", 1))
    index.begin_generation(NAMESPACE, "new")
    index.apply_page("new", SourceIndexEpochPage(
        NAMESPACE, 1, (SourceIndexMutation(other, 1, 1, True),)))
    index.apply_page("new", SourceIndexEpochPage(
        NAMESPACE, 2, (SourceIndexMutation(
            root, 1, 1, False, "deletion"),)))
    index.activate(NAMESPACE, "new", NamespaceEpoch("bot", "persona", 2))
    index.close()
    return root, other


def test_sidecar_inventory_includes_inactive_generation_and_blocks_but_holds(tmp_path):
    path = tmp_path / "d06-index.sqlite"
    root, other = _sidecar(path)
    result = read_d06_index_deletion_inventory_v1(
        path, NAMESPACE, graph_epoch=NamespaceEpoch("bot", "persona", 2))
    assert result.scan_complete
    assert result.status == "observed_hold_unbound"
    assert result.generation_watermarks == (("new", 2, True), ("old", 1, False))
    assert result.active_source_refs == (other,)
    assert result.inactive_source_refs == (root,)
    assert result.blocked_source_refs == (root,)
    assert result.all_source_refs == tuple(sorted((root, other)))
    assert len(result.receipt_epochs) == 3
    assert len(result.sidecar_digest) == 64

    lag = read_d06_index_deletion_inventory_v1(
        path, NAMESPACE, graph_epoch=NamespaceEpoch("bot", "persona", 3))
    assert lag.status == "observed_hold_epoch_mismatch"
    assert lag.all_source_refs == result.all_source_refs


def test_sidecar_inventory_bounds_and_corruption_hold(tmp_path):
    path = tmp_path / "d06-index.sqlite"
    _sidecar(path)
    limited = read_d06_index_deletion_inventory_v1(
        path, NAMESPACE, graph_epoch=NamespaceEpoch("bot", "persona", 2),
        max_rows_per_table=1)
    assert limited.status == "partial_hold_row_bound"
    assert not limited.scan_complete and limited.sidecar_digest is None
    assert limited.all_source_refs == ()

    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM d06_index_receipts WHERE generation_id='new' AND epoch=1")
    with pytest.raises(ValueError, match="receipt continuity"):
        read_d06_index_deletion_inventory_v1(
            path, NAMESPACE, graph_epoch=NamespaceEpoch("bot", "persona", 2))


def test_sidecar_inventory_requires_existing_file_and_namespace_epoch(tmp_path):
    path = tmp_path / "missing.sqlite"
    with pytest.raises(FileNotFoundError):
        read_d06_index_deletion_inventory_v1(
            path, NAMESPACE, graph_epoch=NamespaceEpoch("bot", "persona", 1))
    assert not path.exists()
    with pytest.raises(ValueError, match="namespace and graph epoch"):
        read_d06_index_deletion_inventory_v1(
            path, NAMESPACE, graph_epoch=NamespaceEpoch("bot", "other", 1))
