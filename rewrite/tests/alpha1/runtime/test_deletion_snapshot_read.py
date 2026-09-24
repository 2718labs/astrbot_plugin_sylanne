"""Internal, epoch-bound graph evidence for a D06 deletion closure candidate."""

import json

import pytest

from sylanne3.contracts import Event, Scope, StaleRead
from sylanne3.graph_store import DeletionHistoryCursor, GraphStore, ProductionGraphStore
from sylanne3.graph_types import (
    AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry, TypeSpec,
)
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "persona")
OTHER = NamespaceId("bot", "other")


@pytest.fixture
def graph(tmp_path):
    registry = TypeRegistry()
    registry.register(TypeSpec("state", ("persona",), "state", lambda value: None))
    store = ProductionGraphStore(tmp_path / "graph.db", registry)
    capability = object()
    store._coordinator_capability = capability
    try:
        yield store, capability
    finally:
        store.close()


def key(name, namespace=NS):
    return AtomKey(Owner("persona", *namespace.as_tuple), "state", name)


def write(store, capability, name, *, namespace=NS, dependencies=()):
    target = key(name, namespace)
    all_keys = (target,) + tuple(dependencies)
    snapshot = GraphStore.graph_snapshot(store, all_keys, _capability=capability)
    event = Event(Scope(*namespace.as_tuple, "session"),
                  f"{name}-{snapshot.get(target).revision + 1}", 1.0,
                  "test", {"name": name})
    candidate = GraphCandidate(
        event, snapshot.versions,
        (GraphWrite(target, {"name": name, "revision": snapshot.get(target).revision + 1},
                    tuple(dependencies)),), snapshot.epochs)
    return GraphStore.graph_commit(store, candidate, _capability=capability)


def read(store, capability, keys, **kwargs):
    return GraphStore._deletion_snapshot_page(
        store, NS, tuple(keys), _capability=capability, **kwargs)


def test_current_reverse_edges_and_missing_key_are_versioned(graph):
    store, capability = graph
    source, dependent, absent = key("source"), key("dependent"), key("absent")
    write(store, capability, "dependent", dependencies=(source,))

    page = read(store, capability, (source, absent), limit=1)

    assert [(atom.key, atom.revision) for atom in page.snapshot.atoms] == [
        (source, 0), (absent, 0), (dependent, 1)]
    assert page.read_set == page.snapshot.versions
    assert [(edge.dependent, edge.dependency) for edge in page.current_reverse_edges] == [
        (GraphVersion(dependent, 1), GraphVersion(source, 0))]
    assert page.epoch == page.snapshot.epochs[0]


def test_history_edge_survives_current_edge_replacement_and_pages(graph):
    store, capability = graph
    source, dependent = key("source"), key("dependent")
    write(store, capability, "dependent", dependencies=(source,))
    write(store, capability, "dependent")

    first = read(store, capability, (source,), limit=1)
    assert first.current_reverse_edges == ()
    assert not first.complete and first.next_after is not None
    assert [(edge.dependent, edge.dependency) for edge in first.history_edges] == [
        (GraphVersion(dependent, 1), GraphVersion(source, 0))]

    second = read(store, capability, (source,), after=first.next_after,
                  expected_epoch=first.epoch, limit=1)
    assert second.complete and second.next_after is None
    assert [(row.atom.revision, row.dependency_count) for row in second.history_rows] == [(2, 0)]


def test_history_edges_are_bounded_even_for_one_dense_row(graph):
    store, capability = graph
    sources = tuple(key(f"source-{index}") for index in range(3))
    write(store, capability, "dependent", dependencies=sources)

    first = read(store, capability, (sources[0],), limit=1, edge_limit=1)
    assert len(first.history_rows) == len(first.history_edges) == 1
    assert not first.complete and first.next_after.edge_offset == 1
    second = read(store, capability, (sources[0],), after=first.next_after,
                  expected_epoch=first.epoch, limit=1, edge_limit=2)
    assert len(second.history_edges) == 2 and second.complete
    assert {edge.dependency.key for edge in first.history_edges + second.history_edges} == set(sources)


def test_page_rejects_drift_and_unbound_continuation(graph):
    store, capability = graph
    write(store, capability, "one")
    write(store, capability, "two")
    first = read(store, capability, (key("one"),), limit=1)
    with pytest.raises(ValueError, match="expected_epoch"):
        read(store, capability, (key("one"),), after=first.next_after, limit=1)
    write(store, capability, "three")
    with pytest.raises(StaleRead, match="epoch"):
        read(store, capability, (key("one"),), after=first.next_after,
             expected_epoch=first.epoch, limit=1)


def test_forged_cursor_cannot_skip_history(graph):
    store, capability = graph
    write(store, capability, "one")
    epoch = GraphStore.graph_epoch(store, *NS.as_tuple, _capability=capability)
    with pytest.raises(StaleRead, match="cursor"):
        read(store, capability, (key("one"),),
             after=DeletionHistoryCursor(key("later"), 99), expected_epoch=epoch)


def test_namespace_scope_and_production_gate(graph):
    store, capability = graph
    write(store, capability, "inside")
    write(store, capability, "outside", namespace=OTHER)
    page = read(store, capability, (key("inside"),), limit=10)
    assert [row.atom.key for row in page.history_rows] == [key("inside")]
    with pytest.raises(ValueError, match="namespace"):
        read(store, capability, (key("outside", OTHER),))
    with pytest.raises(ValueError, match="namespace"):
        read(store, capability, (key("inside"),), expected_epoch=GraphStore.graph_epoch(
            store, *OTHER.as_tuple, _capability=capability))
    with pytest.raises(PermissionError, match="GraphCoordinator"):
        store._deletion_snapshot_page(NS, (key("inside"),))


def test_corrupt_cross_namespace_history_edge_fails_closed(graph):
    store, capability = graph
    dependent = key("dependent")
    write(store, capability, "dependent")
    with store._lock:
        store._db.execute(
            "UPDATE graph_history SET dependencies=? WHERE token=? AND revision=1",
            (json.dumps([[key("outside", OTHER).token, 0]]), dependent.token))
    with pytest.raises(StaleRead, match="cross-namespace history dependency"):
        read(store, capability, (dependent,))
