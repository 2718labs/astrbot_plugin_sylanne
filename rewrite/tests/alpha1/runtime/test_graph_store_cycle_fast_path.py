"""Cycle validation may skip batches that introduce no dependency edges."""

from types import SimpleNamespace

import pytest

from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry


def test_empty_dependency_replacements_do_not_scan_the_graph():
    class NoScanDatabase:
        def execute(self, *_args, **_kwargs):
            raise AssertionError("empty-edge batch scanned the whole graph")

    GraphStore._assert_acyclic(
        SimpleNamespace(_db=NoScanDatabase()),
        ("bot", "persona"), {"new-source": (), "replaced-source": ()},
    )


def test_nonempty_dependency_replacements_still_reject_a_cycle(tmp_path):
    store = GraphStore(tmp_path / "graph.db", TypeRegistry())
    try:
        with pytest.raises(ValueError, match="dependency cycle"):
            store._assert_acyclic(
                ("bot", "persona"), {"source-a": ("source-b",),
                                     "source-b": ("source-a",)},
            )
    finally:
        store.close()
