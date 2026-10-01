"""D06 projection watermarks survive a missed page and a failed local commit."""

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06.projection_index import (
    DurableSourceProjectionIndex, SourceIndexEpochPage, SourceIndexMutation,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import NamespaceEpoch, TypeRegistry
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import SourceRecord, access_key, register_memory_types, source_key
from sylanne3.runtime_contracts import NamespaceId


def test_reopen_catches_up_and_switches_generation_only_at_coverage(tmp_path):
    namespace = NamespaceId("bot", "persona")
    source = source_key(*namespace.as_tuple, "source-1").token
    access = access_key(*namespace.as_tuple, "source-1")
    registry = TypeRegistry()
    register_memory_types(registry)
    graph = GraphStore(tmp_path / "graph.db", registry)
    repository = MemoryRepository(graph, *namespace.as_tuple)
    scope = Scope(*namespace.as_tuple, "session")
    repository.ingest(
        Event(scope, "ingest", 1.0, "ingest", {}),
        SourceRecord("source-1", "source text", "alice", "observed", "confirmed",
                     1.0, 1.0, "family-1", ("owner",), ("context",)),
    )
    assert graph.graph_epoch(*namespace.as_tuple).revision == 1
    initial = graph.graph_snapshot((source_key(*namespace.as_tuple, "source-1"), access))
    path = tmp_path / "d06-projection.db"
    page1 = SourceIndexEpochPage(namespace, 1,
                                 (SourceIndexMutation(source,
                                                      initial.get(source_key(*namespace.as_tuple, "source-1")).revision,
                                                      initial.get(access).revision, True),))

    index = DurableSourceProjectionIndex(path)
    index.begin_generation(namespace, "generation-1")
    assert index.apply_page("generation-1", page1) == 1
    index.activate(namespace, "generation-1", NamespaceEpoch(*namespace.as_tuple, 1))
    assert index.candidate_page(namespace, current_epoch=NamespaceEpoch(*namespace.as_tuple, 1)).candidates == (
        SourceIndexMutation(source, 1, 1, True),
    )
    index.close()

    # A graph commit at epoch 2 happened while the projection worker was down.
    repository.set_access(
        Event(scope, "scope-change", 2.0, "scope-change", {}), "source-1",
        audiences=("owner",), purposes=("context",), status="active",
        recorded_at=2.0,
    )
    assert graph.graph_epoch(*namespace.as_tuple).revision == 2
    page2 = SourceIndexEpochPage(namespace, 2,
                                 (SourceIndexMutation(source, 1,
                                                      graph.graph_snapshot((access,)).get(access).revision,
                                                      True),))
    index = DurableSourceProjectionIndex(path)
    try:
        lag = index.candidate_page(namespace, current_epoch=NamespaceEpoch(*namespace.as_tuple, 2))
        assert lag.status == "partial_watermark_lag"
        assert lag.candidates == ()
        assert lag.watermark == 1
        assert index.apply_page("generation-1", page2) == 2
        assert index.apply_page("generation-1", page2) == 2
        with pytest.raises(ValueError, match="conflicts"):
            index.apply_page("generation-1", SourceIndexEpochPage(namespace, 2, ()))
        assert index.candidate_page(
            namespace, current_epoch=NamespaceEpoch(*namespace.as_tuple, 2),
        ).candidates == (SourceIndexMutation(source, 1, 2, True),)

        index.begin_generation(namespace, "generation-2")
        index.apply_page("generation-2", page1)
        with pytest.raises(ValueError, match="not reached"):
            index.activate(namespace, "generation-2", NamespaceEpoch(*namespace.as_tuple, 2))
        assert index.candidate_page(
            namespace, current_epoch=NamespaceEpoch(*namespace.as_tuple, 2),
        ).generation_id == "generation-1"
        index.apply_page("generation-2", page2)
        index.activate(namespace, "generation-2", NamespaceEpoch(*namespace.as_tuple, 2))
        assert index.candidate_page(
            namespace, current_epoch=NamespaceEpoch(*namespace.as_tuple, 2),
        ).generation_id == "generation-2"
        # An access revocation removes this supplemental candidate only after
        # its next committed epoch has been consumed.
        repository.set_access(
            Event(scope, "withdraw", 3.0, "withdraw", {}), "source-1",
            audiences=("owner",), purposes=("context",), status="withdrawn",
            recorded_at=3.0,
        )
        assert graph.graph_epoch(*namespace.as_tuple).revision == 3
        removed = SourceIndexEpochPage(namespace, 3,
                                       (SourceIndexMutation(source, 1,
                                                            graph.graph_snapshot((access,)).get(access).revision,
                                                            False),))
        assert index.candidate_page(
            namespace, current_epoch=NamespaceEpoch(*namespace.as_tuple, 3),
        ).status == "partial_watermark_lag"
        index.apply_page("generation-2", removed)
        current = index.candidate_page(
            namespace, current_epoch=NamespaceEpoch(*namespace.as_tuple, 3),
        )
        assert current.status == "projection_current"
        assert current.candidates == ()
        assert current.page_complete
    finally:
        index.close()
        graph.close()


def test_failed_page_transaction_does_not_advance_entries_or_watermark(tmp_path):
    namespace = NamespaceId("bot", "persona")
    source = source_key(*namespace.as_tuple, "source-1").token
    index = DurableSourceProjectionIndex(tmp_path / "d06-projection.db")
    try:
        index.begin_generation(namespace, "generation-1")
        # Abort after the source row would be written but before its receipt
        # and watermark can commit. The transaction must roll back the row.
        index._db.execute("""
            CREATE TRIGGER fail_index_receipt BEFORE INSERT ON d06_index_receipts
            BEGIN SELECT RAISE(ABORT, 'simulated crash'); END
        """)
        page = SourceIndexEpochPage(namespace, 1,
                                    (SourceIndexMutation(source, 1, 1, True),))
        with pytest.raises(Exception, match="simulated crash"):
            index.apply_page("generation-1", page)
        assert index._db.execute("SELECT COUNT(*) FROM d06_index_sources").fetchone()[0] == 0
        assert index._db.execute(
            "SELECT watermark FROM d06_index_generations",
        ).fetchone()[0] == 0
        index._db.execute("DROP TRIGGER fail_index_receipt")
        assert index.apply_page("generation-1", page) == 1
        with pytest.raises(ValueError, match="skip"):
            index.apply_page("generation-1", SourceIndexEpochPage(namespace, 3, ()))
    finally:
        index.close()


@pytest.mark.parametrize("reason", ("correction", "revocation", "deletion"))
def test_terminal_invalidation_survives_reopen_and_new_generation(tmp_path, reason):
    namespace = NamespaceId("bot", "persona")
    source = source_key(*namespace.as_tuple, "source-1").token
    path = tmp_path / "d06-projection.db"
    present = SourceIndexEpochPage(namespace, 1,
                                   (SourceIndexMutation(source, 1, 1, True),))
    invalidated = SourceIndexEpochPage(namespace, 2,
                                      (SourceIndexMutation(source, 1, 2, False,
                                                           reason),))
    # A later malformed or stale projector page must not revive the source,
    # even if its epoch receipt is new or a new generation is activated.
    stale_reentry = SourceIndexEpochPage(namespace, 3,
                                        (SourceIndexMutation(source, 1, 1, True),))
    index = DurableSourceProjectionIndex(path)
    index.begin_generation(namespace, "first")
    index.apply_page("first", present)
    index.activate(namespace, "first", NamespaceEpoch(*namespace.as_tuple, 1))
    index.apply_page("first", invalidated)
    index.close()

    index = DurableSourceProjectionIndex(path)
    try:
        assert index.candidate_page(
            namespace, current_epoch=NamespaceEpoch(*namespace.as_tuple, 2),
        ).candidates == ()
        index.apply_page("first", stale_reentry)
        assert index.candidate_page(
            namespace, current_epoch=NamespaceEpoch(*namespace.as_tuple, 3),
        ).candidates == ()
        index.begin_generation(namespace, "second")
        for page in (present, invalidated, stale_reentry):
            index.apply_page("second", page)
        index.activate(namespace, "second", NamespaceEpoch(*namespace.as_tuple, 3))
        result = index.candidate_page(
            namespace, current_epoch=NamespaceEpoch(*namespace.as_tuple, 3),
        )
        assert result.page_complete and result.candidates == ()
        assert result.generation_id == "second"
    finally:
        index.close()


def test_terminal_invalidation_and_watermark_roll_back_together(tmp_path):
    namespace = NamespaceId("bot", "persona")
    source = source_key(*namespace.as_tuple, "source-1").token
    index = DurableSourceProjectionIndex(tmp_path / "d06-projection.db")
    try:
        index.begin_generation(namespace, "first")
        index._db.execute("""
            CREATE TRIGGER fail_receipt BEFORE INSERT ON d06_index_receipts
            BEGIN SELECT RAISE(ABORT, 'simulated crash'); END
        """)
        page = SourceIndexEpochPage(namespace, 1,
                                    (SourceIndexMutation(source, 1, 2, False,
                                                         "revocation"),))
        with pytest.raises(Exception, match="simulated crash"):
            index.apply_page("first", page)
        assert index._db.execute(
            "SELECT COUNT(*) FROM d06_index_source_blocks",
        ).fetchone()[0] == 0
        assert index._db.execute(
            "SELECT watermark FROM d06_index_generations",
        ).fetchone()[0] == 0
    finally:
        index.close()
