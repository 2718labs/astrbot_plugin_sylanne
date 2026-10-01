"""Transaction-level C09 barrier storage; Authority and closure remain separate."""

from __future__ import annotations

from pathlib import Path
import sqlite3

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (
    GraphCandidate, GraphVersion, GraphWrite, NamespaceEpoch, TypeRegistry,
    TypeSpec,
)
from sylanne3.memory_types import (SourceRecord, access_key, register_memory_types,
                                   source_key)
from sylanne3.runtime.c09_erasure_barrier_store_v1 import (
    install_c09_erasure_barrier_store_v1, read_c09_erasure_barrier_v1,
    record_c09_erasure_barrier_after_graph_v1,
    verify_c09_graph_barrier_v1,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


def test_c09_barrier_joins_real_graph_event_and_rollback(tmp_path: Path) -> None:
    registry = TypeRegistry()
    registry.register(TypeSpec(
        "memory.access", ("event",), "state", lambda value: None,
    ))
    store = GraphStore(tmp_path / "graph.db", registry)
    capability = object()
    store._coordinator_capability = capability
    namespace = NamespaceId("bot", "persona")
    source = source_key("bot", "persona", "source-1")
    access = access_key("bot", "persona", "source-1")
    operation_id = "delete-1"
    candidate = GraphCandidate(
        Event(Scope("bot", "persona", "delete-session"), operation_id,
              1.0, "c09.erasure_barrier", {"operation_id": operation_id}),
        (GraphVersion(access, 0),),
        (GraphWrite(access, {"status": "withdrawn"}),),
        (NamespaceEpoch("bot", "persona", 0),),
    )
    try:
        with store._lock:
            db = store._db
            install_c09_erasure_barrier_store_v1(db)
            db.execute(
                "INSERT INTO graph_authority_epochs"
                "(bot,persona,access_epoch,delete_epoch) VALUES(?,?,?,?)",
                ("bot", "persona", 4, 7),
            )
            db.commit()

            def commit_barrier(*, fail_after: bool = False):
                db.execute("BEGIN IMMEDIATE")
                try:
                    graph_receipt = store._graph_commit_in_transaction(
                        candidate, _capability=capability,
                    )
                    barrier = record_c09_erasure_barrier_after_graph_v1(
                        db, namespace, operation_id=operation_id,
                        request_digest=canonical_digest("request"),
                        pending_receipt_digest=canonical_digest("pending"),
                        closure_digest=canonical_digest("closure"),
                        root_source_refs=(source.token,),
                        affected_source_refs=(source.token,),
                        graph_incarnation="incarnation-1",
                        graph_epoch_before=0, access_epoch_before=4,
                        delete_epoch_before=7, event_session="delete-session",
                        graph_receipt=graph_receipt,
                    )
                    if fail_after:
                        raise RuntimeError("after barrier")
                    db.execute("COMMIT")
                    return barrier
                except BaseException:
                    db.execute("ROLLBACK")
                    raise

            with pytest.raises(RuntimeError, match="after barrier"):
                commit_barrier(fail_after=True)
            assert read_c09_erasure_barrier_v1(db, namespace, operation_id) is None
            assert db.execute("SELECT COUNT(*) FROM graph_events").fetchone() == (0,)
            assert db.execute(
                "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
                "WHERE bot=? AND persona=?", namespace.as_tuple,
            ).fetchone() == (4, 7)

            barrier = commit_barrier()
            assert read_c09_erasure_barrier_v1(db, namespace, operation_id) == barrier
            assert (barrier.graph_epoch_after, barrier.access_epoch_after,
                    barrier.delete_epoch_after) == (1, 5, 8)
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                db.execute(
                    "DELETE FROM graph_c09_erasure_barriers_v1 "
                    "WHERE bot=? AND persona=?", namespace.as_tuple,
                )
    finally:
        store.close()


def test_c09_barrier_pinned_reread_finds_derived_source_and_history(
        tmp_path: Path) -> None:
    registry = TypeRegistry()
    register_memory_types(registry)
    path = tmp_path / "graph.db"
    store = GraphStore(path, registry)
    capability = object()
    store._coordinator_capability = capability
    namespace = NamespaceId("bot", "persona")
    root = source_key("bot", "persona", "root")
    child = source_key("bot", "persona", "child")
    root_access = access_key("bot", "persona", "root")
    child_access = access_key("bot", "persona", "child")
    def source(source_id: str, parents: tuple[str, ...]) -> dict:
        return SourceRecord(
            source_id, "text", "speaker", "observed", "confirmed", None,
            1.0, "root", ("owner",), ("context",), parents,
        ).to_dict()
    def access(source_id: str, status: str) -> dict:
        return {"source_id": source_id, "audiences": ["owner"],
                "purposes": ["context"], "status": status,
                "recorded_at": 1.0}
    try:
        with store._lock:
            db = store._db
            install_c09_erasure_barrier_store_v1(db)
            db.execute("INSERT INTO graph_authority_epochs VALUES(?,?,?,?)",
                       (*namespace.as_tuple, 1, 0))
            db.execute("BEGIN IMMEDIATE")
            store._graph_commit_in_transaction(GraphCandidate(
                Event(Scope("bot", "persona", "seed"), "seed", 1.0,
                      "seed_source", {}),
                tuple(GraphVersion(key, 0) for key in
                      (root, child, root_access, child_access)),
                (GraphWrite(root, source("root", ())),
                 GraphWrite(child, source("child", ("root",))),
                 GraphWrite(root_access, access("root", "active")),
                 GraphWrite(child_access, access("child", "active"))),
                (NamespaceEpoch("bot", "persona", 0),),
            ), _capability=capability)
            db.execute("COMMIT")
            operation_id = "erase-root"
            request_digest = canonical_digest("request")
            pending_digest = canonical_digest("durable-pending")
            db.execute("BEGIN IMMEDIATE")
            graph_receipt = store._graph_commit_in_transaction(GraphCandidate(
                Event(Scope("bot", "persona", "erasure"), operation_id,
                      2.0, "source_access_withdrawn", {}),
                (GraphVersion(root_access, 1), GraphVersion(child_access, 1)),
                (GraphWrite(root_access, access("root", "withdrawn")),
                 GraphWrite(child_access, access("child", "withdrawn"))),
                (NamespaceEpoch("bot", "persona", 1),),
            ), _capability=capability)
            recorded = record_c09_erasure_barrier_after_graph_v1(
                db, namespace, operation_id=operation_id,
                request_digest=request_digest,
                pending_receipt_digest=pending_digest,
                closure_digest=canonical_digest((root.token, child.token)),
                root_source_refs=(root.token,),
                affected_source_refs=tuple(sorted((root.token, child.token))),
                graph_incarnation="incarnation", graph_epoch_before=1,
                access_epoch_before=1, delete_epoch_before=0,
                event_session="erasure", graph_receipt=graph_receipt,
            )
            db.execute("COMMIT")
        with sqlite3.connect(path) as verifier:
            assert verify_c09_graph_barrier_v1(
                verifier, namespace, operation_id,
                request_digest=request_digest,
                pending_receipt_digest=pending_digest) == recorded
            with pytest.raises(ValueError, match="pending original"):
                verify_c09_graph_barrier_v1(
                    verifier, namespace, operation_id,
                    request_digest=request_digest,
                    pending_receipt_digest=canonical_digest("another"))
        with store._lock:
            store._db.execute(
                "UPDATE graph_events SET digest=? WHERE bot=? AND persona=? "
                "AND session=? AND event_id=?",
                (canonical_digest("tampered"), *namespace.as_tuple,
                 "erasure", operation_id),
            )
            store._db.commit()
        with sqlite3.connect(path) as verifier:
            with pytest.raises(ValueError, match="graph event differs"):
                verify_c09_graph_barrier_v1(
                    verifier, namespace, operation_id,
                    request_digest=request_digest,
                    pending_receipt_digest=pending_digest)
    finally:
        store.close()
