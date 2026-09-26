"""The final reverse callback keeps verified subsets and missing gates separate."""

import time

import pytest

from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard
from sylanne3.runtime.dispatch_current_projection import (
    read_current_dispatch_projection,
)

from test_dispatch_current_source_budget import _admitted
from test_dispatch_final_claim_v2 import _chain


def test_p0_and_complete_current_graph_are_read_in_one_write_transaction(tmp_path):
    store, namespace = _admitted(tmp_path)
    bootstrap = object()
    graph = GraphCoordinator(store, bootstrap)
    try:
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                binding, claimed = _chain(db, namespace)
                durable = graph._read_dispatch_final_claim_prerequisite_locked(
                    namespace, binding, claimed, "handoff:one", now_utc=time.time())
                snapshot, query = graph._dispatch_full_graph_snapshot_locked(namespace)
                projection = read_current_dispatch_projection(
                    db, namespace, snapshot, query)
                assert durable.admission_ref == binding.origin.admission_ref
                assert durable.source_proof_digest
                assert durable.budget_reservation_digest
                assert query.revision == projection.graph_epoch
                assert projection.coverage == "full"
                assert db.execute(
                    "SELECT COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? "
                    "AND type_name='d11.dispatch_claim.v1'",
                    namespace.as_tuple,
                ).fetchone() == (0,)
            finally:
                db.execute("ROLLBACK")
    finally:
        store.close()


def test_final_writer_rejects_uninstalled_or_caller_supplied_p2(tmp_path):
    store, namespace = _admitted(tmp_path)
    bootstrap = object()
    graph = GraphCoordinator(store, bootstrap)
    try:
        with pytest.raises(UnavailableGuard, match="installed final dispatch"):
            graph.register_dispatch_final_claim_writer_v1(bootstrap)
        with pytest.raises(UnavailableGuard, match="typed final dispatch"):
            graph._commit_dispatch_final_claim_v1(None, None, None, None, None)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d11.dispatch_claim.v1'",
            namespace.as_tuple,
        ).fetchone() == (0,)
    finally:
        store.close()
