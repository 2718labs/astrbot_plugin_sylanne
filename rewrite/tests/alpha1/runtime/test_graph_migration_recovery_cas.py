"""Migration recovery changes identity only through a dedicated trusted seam."""

from dataclasses import replace

import pytest

from sylanne3.contracts import StaleRead
from sylanne3.graph_store import GraphMigrationVerifiedTransferV1, GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.runtime_contracts import NamespaceId, SnapshotRequirementsV2


NAMESPACE = NamespaceId("bot-migrate", "persona-migrate")


def source_requirements():
    return SnapshotRequirementsV2(
        namespace=NAMESPACE,
        authority_id="authority-a",
        authority_namespace="authority-namespace-a",
        activation_generation=1,
        deletion_journal_id="deletion-a",
        deletion_seq=0,
        deletion_digest="genesis",
        execution_journal_id="execution-a",
        execution_seq=0,
        execution_digest="genesis",
        revocation_epoch=0,
        graph_incarnation="graph-source",
    )


def test_migration_identity_change_holds_without_trusted_transfer_verifier(tmp_path):
    capability = object()
    store = GraphStore(tmp_path / "business.db", TypeRegistry())
    store._coordinator_capability = capability
    try:
        source = store.install_graph_recovery_genesis(
            source_requirements(), _capability=capability)
        target = replace(source.requirements, activation_generation=3,
                         revocation_epoch=1, graph_incarnation="graph-target")
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                with pytest.raises(StaleRead, match="identity"):
                    store.cas_graph_recovery_metadata(source, target,
                                                      _capability=capability)
                with pytest.raises(RuntimeError, match="trusted migration transfer verifier"):
                    store.cas_graph_migration_recovery_metadata(
                        source, target, transfer_receipt={"verified": True},
                        _capability=capability)
            finally:
                store._db.execute("ROLLBACK")
        assert store.graph_recovery_metadata(NAMESPACE, _capability=capability) == source
    finally:
        store.close()


class TrustedLocalVerifier:
    def __init__(self, receipt, proof):
        self.receipt = receipt
        self.proof = proof

    def verify_local(self, transfer_receipt):
        if transfer_receipt is not self.receipt:
            raise PermissionError("unrecognized migration transfer receipt")
        return self.proof


def test_migration_cas_requires_matching_transfer_and_exact_stored_source(tmp_path):
    capability = object()
    receipt = object()
    source = source_requirements()
    target = replace(source, activation_generation=3, revocation_epoch=1,
                     graph_incarnation="graph-target")
    from sylanne3.graph_store import GraphRecoveryMetadataV2
    expected = GraphRecoveryMetadataV2(source, 0)
    proof = GraphMigrationVerifiedTransferV1(
        "transfer-a", expected, target, "target_recovering", "snapshot-digest-a")
    store = GraphStore(tmp_path / "business.db", TypeRegistry(),
                       migration_transfer_verifier=TrustedLocalVerifier(receipt, proof))
    store._coordinator_capability = capability
    try:
        assert store.install_graph_recovery_genesis(source, _capability=capability) == expected
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                with pytest.raises(PermissionError, match="unrecognized"):
                    store.cas_graph_migration_recovery_metadata(
                        expected, target, {"verified": True}, _capability=capability)
                changed = store.cas_graph_migration_recovery_metadata(
                    expected, target, receipt, _capability=capability)
                assert changed == GraphRecoveryMetadataV2(target, 1)
                with pytest.raises(StaleRead, match="metadata changed"):
                    store.cas_graph_migration_recovery_metadata(
                        expected, target, receipt, _capability=capability)
            finally:
                store._db.execute("COMMIT")
        assert store.graph_recovery_metadata(NAMESPACE, _capability=capability) == changed
    finally:
        store.close()


def test_migration_rejects_target_head_rollback_even_with_matching_proof(tmp_path):
    capability = object()
    receipt = object()
    genesis = source_requirements()
    source = replace(genesis, deletion_seq=1,
                     deletion_digest="sha256:" + "a" * 64)
    target = replace(genesis, activation_generation=3, revocation_epoch=1,
                     graph_incarnation="graph-target")
    from sylanne3.graph_store import GraphRecoveryMetadataV2
    expected = GraphRecoveryMetadataV2(source, 1)
    proof = GraphMigrationVerifiedTransferV1(
        "transfer-a", expected, target, "target_recovering", "snapshot-digest-a")
    store = GraphStore(tmp_path / "business.db", TypeRegistry(),
                       migration_transfer_verifier=TrustedLocalVerifier(receipt, proof))
    store._coordinator_capability = capability
    try:
        installed = store.install_graph_recovery_genesis(genesis, _capability=capability)
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                assert store.cas_graph_recovery_metadata(
                    installed, source, _capability=capability) == expected
                with pytest.raises(StaleRead, match="watermark regressed"):
                    store.cas_graph_migration_recovery_metadata(
                        expected, target, receipt, _capability=capability)
            finally:
                store._db.execute("COMMIT")
        assert store.graph_recovery_metadata(NAMESPACE, _capability=capability) == expected
    finally:
        store.close()
