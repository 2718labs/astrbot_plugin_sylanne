"""A business recovery stamp cannot rewrite a journal head in place."""

from dataclasses import replace

import pytest

from sylanne3.contracts import StaleRead
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.runtime_contracts import NamespaceId, SnapshotRequirementsV2


def test_same_sequence_digest_replacement_is_rejected_and_durable_head_survives(tmp_path):
    capability = object()
    path = tmp_path / "business.sqlite"
    namespace = NamespaceId("bot-a", "persona-a")
    initial = SnapshotRequirementsV2(
        namespace=namespace,
        authority_id="authority-a",
        authority_namespace="namespace-a",
        activation_generation=1,
        deletion_journal_id="deletion-a",
        deletion_seq=0,
        deletion_digest="genesis",
        execution_journal_id="execution-a",
        execution_seq=0,
        execution_digest="genesis",
        revocation_epoch=0,
        graph_incarnation="graph-a",
    )
    store = GraphStore(path, TypeRegistry())
    store._coordinator_capability = capability
    try:
        genesis = store.install_graph_recovery_genesis(initial, _capability=capability)
        advanced = replace(
            initial, deletion_seq=1, deletion_digest="sha256:" + "a" * 64,
            execution_seq=1, execution_digest="sha256:" + "b" * 64,
        )
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            committed = store.cas_graph_recovery_metadata(
                genesis, advanced, _capability=capability)
            store._db.execute("COMMIT")
        for replacement in (
            replace(advanced, deletion_digest="sha256:" + "c" * 64),
            replace(advanced, execution_digest="sha256:" + "d" * 64),
        ):
            with store._lock:
                store._db.execute("BEGIN IMMEDIATE")
                try:
                    with pytest.raises(StaleRead, match="digest changed"):
                        store.cas_graph_recovery_metadata(
                            committed, replacement, _capability=capability)
                finally:
                    store._db.execute("ROLLBACK")
    finally:
        store.close()

    reopened = GraphStore(path, TypeRegistry())
    reopened._coordinator_capability = capability
    try:
        assert reopened.graph_recovery_metadata(
            namespace, _capability=capability) == committed
    finally:
        reopened.close()
