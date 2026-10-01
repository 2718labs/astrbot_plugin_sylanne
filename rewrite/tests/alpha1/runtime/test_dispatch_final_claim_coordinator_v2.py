"""The final reverse callback keeps verified subsets and missing gates separate."""

import time
from dataclasses import asdict, replace
import json

import pytest

from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard
from sylanne3.contracts import StaleRead, canonical_json
from sylanne3.authority_service.v2_contract import canonical_digest as authority_digest
from sylanne3.runtime.dispatch_graph_claim import DispatchGraphClaimValueV1
from sylanne3.runtime_contracts import SnapshotRequirementsV2
from sylanne3.runtime.dispatch_current_projection import (
    read_current_dispatch_projection,
)
from sylanne3.runtime.dispatch_current_source_budget import CurrentDispatchHold

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


@pytest.mark.parametrize("mutation", ("source_access", "budget_reservation"))
def test_post_seal_source_or_budget_mutation_blocks_final_claim_prerequisite(
        tmp_path, mutation):
    store, namespace = _admitted(tmp_path)
    graph = GraphCoordinator(store, object())
    try:
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                binding, claimed = _chain(db, namespace)
                if mutation == "source_access":
                    changed = db.execute(
                        "UPDATE graph_atoms SET value=replace(value,'\"active\"',"
                        "'\"withdrawn\"') WHERE bot=? AND persona=? "
                        "AND type_name='memory.access'", namespace.as_tuple)
                else:
                    changed = db.execute(
                        "UPDATE runtime_budget_reservations SET state='settled' "
                        "WHERE lease_id=? AND operation_id=?",
                        ("parent", binding.operation_id))
                assert changed.rowcount == 1
                with pytest.raises(CurrentDispatchHold):
                    graph._read_dispatch_final_claim_prerequisite_locked(
                        namespace, binding, claimed, "handoff:one",
                        now_utc=time.time())
                assert db.execute(
                    "SELECT COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? "
                    "AND type_name='d11.dispatch_claim.v1'",
                    namespace.as_tuple).fetchone() == (0,)
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
        with pytest.raises(UnavailableGuard, match="installed final dispatch"):
            graph.register_dispatch_final_claim_writer_v1(
                bootstrap, route_port=object(), issuer_id="issuer:test")
        with pytest.raises(UnavailableGuard, match="typed final dispatch"):
            graph._commit_dispatch_final_claim_v1(None, None, None, None, None)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d11.dispatch_claim.v1'",
            namespace.as_tuple,
        ).fetchone() == (0,)
    finally:
        store.close()


def test_committed_claim_replay_rejects_older_business_recovery_stamp(tmp_path):
    store, namespace = _admitted(tmp_path)
    graph = GraphCoordinator(store, object())
    store._coordinator_capability = graph._GraphCoordinator__graph_capability
    try:
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                binding, claimed = _chain(db, namespace)
                anchor = claimed.after_anchor
                target = SnapshotRequirementsV2(
                    namespace, anchor.authority_id, anchor.namespace,
                    anchor.activation_generation, anchor.deletion_journal_id,
                    0, "genesis", anchor.execution_journal_id, 0, "genesis",
                    0, binding.graph_incarnation)
                db.execute(
                    "INSERT INTO graph_recovery_metadata_v2"
                    "(bot,persona,schema,requirements_json,graph_revision) "
                    "VALUES(?,?,?,?,0)",
                    namespace.as_tuple + (target.schema, canonical_json(asdict(target))),
                )
                p2 = replace(claimed.pending.permit,
                             revision=claimed.updated_revision,
                             pinned_anchor=anchor)
                value = DispatchGraphClaimValueV1(
                    *namespace.as_tuple, binding.graph_incarnation,
                    binding.origin.activity_id, binding.origin.effect_id,
                    binding.operation_id, "handoff:one",
                    binding.origin.admission_ref, anchor.namespace,
                    authority_digest(p2), p2.fence_epoch, p2.revision,
                    anchor.execution_seq, anchor.execution_digest,
                    "sha256:" + "1" * 64, "sha256:" + "2" * 64,
                    authority_digest(binding), authority_digest(claimed),
                    "sha256:" + "3" * 64,
                )
                _, _, inserted = graph._commit_dispatch_claim_atom_in_transaction(
                    namespace, value, claimed)
                assert inserted is True
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

            row = db.execute(
                "SELECT requirements_json FROM graph_recovery_metadata_v2 "
                "WHERE bot=? AND persona=?", namespace.as_tuple,
            ).fetchone()
            current = json.loads(row[0])
            current["execution_seq"] = 1
            current["execution_digest"] = claimed.pending.prepared_receipt.after_anchor.execution_digest
            db.execute(
                "UPDATE graph_recovery_metadata_v2 SET requirements_json=? "
                "WHERE bot=? AND persona=?",
                (canonical_json(current), *namespace.as_tuple),
            )
            db.execute("BEGIN IMMEDIATE")
            try:
                with pytest.raises(StaleRead, match="replay lacks its P2"):
                    graph._commit_dispatch_claim_atom_in_transaction(
                        namespace, value, claimed)
            finally:
                db.execute("ROLLBACK")
    finally:
        store.close()
