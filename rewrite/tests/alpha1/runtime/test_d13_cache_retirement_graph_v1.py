"""W01 D13 graph CAS primitive; no D11 window or product issuer is mocked."""

from dataclasses import replace
import json

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d13.precompression import (
    compile_deterministic_candidate, plan_precompression,
)
from sylanne3.domains.d13.provider import D13ShortContextProvider, block_graph_value
from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (
    AtomKey, GraphCandidate, GraphVersion, GraphWrite, NamespaceEpoch, Owner,
    TypeRegistry,
)
from sylanne3.runtime.d13_precompression_job import prepare_retirement_intent_v1
from sylanne3.runtime_contracts import (
    CompletedTurnV1, ConversationWindowProjectionV1, NamespaceId,
    SnapshotRequirementsV2, VersionedRef,
)


def _planned():
    scene, audience = VersionedRef("scene", 1), VersionedRef("audience", 1)
    turns = tuple(CompletedTurnV1(
        "conversation", audience, sequence,
        VersionedRef(f"raw:{sequence}", 1),
        VersionedRef(f"source:{sequence}", 1),
        VersionedRef(f"access:{sequence}", 1),
        f"speaker:{sequence % 2}", "A completed turn. " + "x" * 100,
        100_000 - 60 + sequence, "confirmed", "not_applicable",
    ) for sequence in range(6))
    dependencies = tuple(ref for turn in turns for ref in (
        turn.raw_ref, turn.source_ref, turn.access_ref))
    window = ConversationWindowProjectionV1(
        NamespaceId("bot", "persona"), "owner", "conversation", scene,
        audience, turns, 5, 100_000, dependencies,
        (scene, audience, *dependencies), 0, 0, 0,
    )
    plan = plan_precompression(window, 1000, background_capacity=True,
                               outstanding_candidate=False)
    assert plan is not None
    return window, plan


def test_expired_d13_retirement_is_atomic_but_does_not_claim_reclamation(tmp_path):
    window, plan = _planned()
    block = replace(compile_deterministic_candidate(window, plan), status="active")
    namespace = window.namespace
    registry = TypeRegistry()
    registry.register(D13ShortContextProvider.register_types()[0])
    store = GraphStore(tmp_path / "d13.db", registry)
    coordinator = GraphCoordinator(store, object())
    capability = coordinator._GraphCoordinator__graph_capability
    # This unit exercises the held GraphStore transaction primitive only.
    # GraphCoordinator normally binds this capability on ProductionGraphStore.
    store._coordinator_capability = capability
    requirements = SnapshotRequirementsV2(
        namespace, "authority", "authority-namespace", 1,
        "deletion-journal", 0, "genesis", "execution-journal", 0,
        "genesis", 0, "graph-incarnation",
    )
    key = AtomKey(Owner("persona", *namespace.as_tuple),
                  "d13.compressed_turn_block.v2", block.block_ref)
    try:
        store.install_graph_recovery_genesis(requirements, _capability=capability)
        before, epoch0 = coordinator._v2_graph_stamp(namespace)
        seed = GraphCandidate(
            Event(Scope(*namespace.as_tuple, "test-seed"), "seed", 1.0,
                  "d13.seed", {}),
            (GraphVersion(key, 0),), (GraphWrite(key, block_graph_value(block)),),
            (epoch0,),
        )
        def seal_seed(db, receipt):
            store.cas_graph_recovery_metadata(
                before, before.requirements, _capability=capability)
        store.graph_commit(seed, _capability=capability, _receipt_hook=seal_seed)
        current, epoch1 = coordinator._v2_graph_stamp(namespace)
        assert epoch1.revision == 1
        expired_window = replace(window, trusted_utc=block.expires_at_utc + 1)
        intent = prepare_retirement_intent_v1(
            block, expired_window, cache_revision=1)

        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                assert coordinator._current_d13_cache_block_locked_v1(
                    namespace, block.block_ref,
                    trusted_now_utc=block.expires_at_utc - 1) == block
                assert coordinator._current_d13_cache_block_locked_v1(
                    namespace, block.block_ref,
                    trusted_now_utc=block.expires_at_utc) is None
                with pytest.raises(UnavailableGuard, match="not currently due"):
                    coordinator._retire_expired_d13_cache_in_transaction_v1(
                        intent, trusted_now_utc=block.expires_at_utc - 1,
                        expected_metadata=current, expected_epoch=epoch1)
            finally:
                store._db.execute("ROLLBACK")
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_d13_cleanup_tasks_v1").fetchone() == (0,)

        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                receipt = coordinator._retire_expired_d13_cache_in_transaction_v1(
                    intent, trusted_now_utc=expired_window.trusted_utc,
                    expected_metadata=current, expected_epoch=epoch1)
                store._db.execute("COMMIT")
            except BaseException:
                store._db.execute("ROLLBACK")
                raise
        assert (receipt.read_blocked, receipt.payload_reclaimed) == (True, False)
        assert receipt.cleanup_task_ref
        assert store._db.execute(
            "SELECT revision,valid FROM graph_atoms WHERE token=?",
            (key.token,)).fetchone() == (2, 1)
        assert store._db.execute(
            "SELECT state FROM graph_d13_cleanup_tasks_v1 WHERE task_ref=?",
            (receipt.cleanup_task_ref,)).fetchone() == ("pending",)
        # Old plaintext is still in history. The cleanup task is not erasure.
        old_value = store._db.execute(
            "SELECT value FROM graph_history WHERE token=? AND revision=1",
            (key.token,)).fetchone()[0]
        assert json.loads(old_value)["timeline"][0]["text"] == block.timeline[0].text
        assert coordinator._v2_graph_stamp(namespace)[1].revision == 2
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                assert coordinator._current_d13_cache_block_locked_v1(
                    namespace, block.block_ref,
                    trusted_now_utc=block.expires_at_utc + 1) is None
                assert coordinator._retire_expired_d13_cache_in_transaction_v1(
                    intent, trusted_now_utc=expired_window.trusted_utc,
                    expected_metadata=current, expected_epoch=epoch1) == receipt
            finally:
                store._db.execute("ROLLBACK")
    finally:
        store.close()
