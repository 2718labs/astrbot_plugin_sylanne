"""SQL reader inputs survive restart and never inflate D06 query coverage."""

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06 import D06DomainProvider, source_correction_head_key
from sylanne3.domains.d06.current_memory_evidence import (
    project_current_memory_evidence_page_v1,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import GraphCandidate, GraphWrite, TypeRegistry
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import (
    InterpretationRecord, SourceRecord, interpretation_key, source_key,
)
from sylanne3.runtime.current_memory_read_v1 import (
    read_current_memory_evidence_page_v1,
)
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "persona")
SCOPE = Scope(*NS.as_tuple, "test")


def setup(path):
    registry = TypeRegistry()
    for spec in D06DomainProvider.type_specs():
        registry.register(spec)
    graph = GraphStore(path, registry)
    repository = MemoryRepository(graph, *NS.as_tuple)
    for source_id, parents in (("parent", ()), ("child", ("parent",))):
        repository.ingest(
            Event(SCOPE, "ingest-" + source_id, 1.0, "ingest", {}),
            SourceRecord(source_id, "private " + source_id, "alice", "reported",
                         "reported", 1.0, 2.0, "family", ("owner",),
                         ("context",), parents),
        )
    graph._db.execute(
        "INSERT INTO graph_authority_epochs(bot,persona,access_epoch,delete_epoch) "
        "VALUES(?,?,0,0)", NS.as_tuple,
    )
    return graph, registry, repository


def read(graph, *, after=None, limit=64, access_epoch=0):
    epoch = graph.graph_epoch(*NS.as_tuple)
    db = graph._db
    db.execute("BEGIN")
    try:
        page, closure, coverage = read_current_memory_evidence_page_v1(
            db, NS, after=after, limit=limit, audience="owner",
            purpose="context", graph_epoch=epoch, access_epoch=access_epoch,
            delete_epoch=0,
        )
        result = project_current_memory_evidence_page_v1(
            page, closure, namespace=NS, graph_epoch=epoch,
            access_epoch=access_epoch, deletion_epoch=0,
            audience="owner", purpose="context", query_coverage=coverage,
        )
        db.execute("COMMIT")
        return page, closure, coverage, result
    except BaseException:
        db.execute("ROLLBACK")
        raise


def test_reopened_access_withdrawal_excludes_child_through_ancestor(tmp_path):
    path = tmp_path / "business.db"
    graph, registry, repository = setup(path)
    try:
        _, closure, coverage, before = read(graph)
        assert coverage.status == "verified_complete"
        assert {item.source_ref for item in before.candidates} == {
            source_key(*NS.as_tuple, name).token for name in ("parent", "child")}
        assert len(closure.versions) == 6  # two sources, accesses, absent heads
        repository.set_access(
            Event(SCOPE, "withdraw", 3.0, "withdraw", {}), "parent",
            audiences=("owner",), purposes=("context",),
            status="withdrawn", recorded_at=3.0,
        )
        graph._db.execute(
            "UPDATE graph_authority_epochs SET access_epoch=1 "
            "WHERE bot=? AND persona=?", NS.as_tuple,
        )
    finally:
        graph.close()
    graph = GraphStore(path, registry)
    try:
        with pytest.raises(ValueError, match="barrier changed"):
            read(graph, access_epoch=0)
        _, _, coverage, after = read(graph, access_epoch=1)
        assert coverage.status == "verified_complete"
        assert after.candidates == ()
        assert len(after.excluded_refs) == 2
        assert after.page_complete  # complete authorized scan, no usable hit
    finally:
        graph.close()


def test_correction_head_and_page_cursor_hold_stale_source(tmp_path):
    path = tmp_path / "business.db"
    graph, registry, repository = setup(path)
    try:
        first_page, _, coverage, result = read(graph, limit=1)
        assert coverage.status == "partial"
        assert coverage.next_after == first_page.next_after.token
        assert not result.page_complete
        _, _, continuation, next_result = read(
            graph, after=first_page.next_after, limit=1)
        assert continuation.status == "partial"  # continuation is not a full scan
        assert not next_result.page_complete

        repository.ingest(
            Event(SCOPE, "ingest-correction", 4.0, "ingest", {}),
            SourceRecord("correction", "updated account", "alice", "reported",
                         "reported", 1.0, 4.0, "family", ("owner",),
                         ("context",), ("parent",)),
        )
        old = source_key(*NS.as_tuple, "parent")
        correction = source_key(*NS.as_tuple, "correction")
        target = interpretation_key(*NS.as_tuple, "meaning")
        repository.interpret(
            Event(SCOPE, "interpret", 4.5, "interpret", {}),
            InterpretationRecord("meaning", ("parent",), "alice", "old",
                                 "reported", 1.0, 4.5),
        )
        head = source_correction_head_key(NS, "parent")
        snapshot = graph.graph_snapshot((head, correction))
        graph.graph_commit(GraphCandidate(
            Event(SCOPE, "head", 5.0, "correction-head", {}), snapshot.versions,
            (GraphWrite(head, {
                "source_ref": old.token, "source_revision": 1,
                "correction_source_ref": correction.token,
                "target_refs": [target.token], "operation_id": "head",
                "state": "pending_reevaluation", "access_epoch": 0,
                "deletion_epoch": 0,
            }, (correction,)),), snapshot.epochs,
        ))
    finally:
        graph.close()
    graph = GraphStore(path, registry)
    try:
        _, _, _, current = read(graph)
        assert old.token in current.excluded_refs
        assert source_key(*NS.as_tuple, "child").token in current.excluded_refs
        assert all(item.source_ref not in current.excluded_refs
                   for item in current.candidates)
    finally:
        graph.close()


@pytest.mark.parametrize("hours",(72,96))
def test_controlled_future_read_preserves_created_source_and_ancestor_access(tmp_path,hours):
    """Software read-time evaluation only; no Authority clock or elapsed claim."""
    import time
    from sylanne3.memory_types import access_key
    registry=TypeRegistry()
    for spec in D06DomainProvider.type_specs():registry.register(spec)
    path=tmp_path/"temporal-memory.db"
    graph=GraphStore(path,registry);repository=MemoryRepository(graph,*NS.as_tuple)
    recorded=time.time()
    try:
        for index,(source_id,parents) in enumerate((("time-parent",()),("time-child",("time-parent",)))):
            repository.ingest(Event(SCOPE,"time-ingest-"+source_id,recorded,"ingest",{}),
                SourceRecord(source_id,"current fixture "+source_id,"alice","reported","reported",
                    recorded,recorded,"controlled-read-fixture",("owner",),("context",),parents))
        keys=tuple(key for name in ("time-parent","time-child") for key in
            (source_key(*NS.as_tuple,name),access_key(*NS.as_tuple,name)))
        before=graph.graph_snapshot(keys)
        actual,proof=repository.read_source_evidence("time-child",audience="owner",purpose="context",
            as_known_at=recorded+hours*3600)
        assert actual is not None and actual.recorded_at==recorded and actual.parent_source_ids==("time-parent",)
        assert repository.read_source_evidence("time-child",audience="foreign",purpose="context",
            as_known_at=recorded+hours*3600)[0] is None
        assert graph.graph_snapshot(keys)==before
    finally:graph.close()
    graph=GraphStore(path,registry);repository=MemoryRepository(graph,*NS.as_tuple)
    try:
        actual,proof=repository.read_source_evidence("time-child",audience="owner",purpose="context",
            as_known_at=recorded+hours*3600)
        assert actual is not None and actual.recorded_at==recorded
        assert graph.graph_snapshot(keys)==before
        now=time.time()
        repository.set_access(Event(SCOPE,"time-parent-withdraw",now,"withdraw",{}),"time-parent",
            audiences=("owner",),purposes=("context",),status="withdrawn",recorded_at=now)
        assert repository.read_source_evidence("time-child",audience="owner",purpose="context",
            as_known_at=recorded+hours*3600)[0] is None
        assert graph.graph_snapshot(tuple(source_key(*NS.as_tuple,name) for name in
            ("time-parent","time-child"))).versions==tuple(version for version in before.versions
                if version.key.type_name=="memory.source")
    finally:graph.close()
