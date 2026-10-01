"""Installed source graph proof against a real sealed SQLite graph."""

from dataclasses import replace

from sylanne3.authority_service.installed_migration_graph_proofs import (
    InstalledSourceGraphProofV1, InstalledTargetGraphProofHoldV1,
)
from sylanne3.authority_service.v2_migration_contract import (
    MigrationPermitV2, MigrationPlanV2, SourceSnapshotReceiptV2,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.runtime.graph_migration_snapshot_v1 import (
    FORMAT, seal_source_namespace_in_tx,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import NamespaceId, SnapshotRequirementsV2


ROLE = NamespaceId("proof-bot", "proof-persona")


def test_installed_source_proof_rereads_real_graph_and_rejects_tamper(tmp_path):
    anchor = RestoreAnchor(
        "authority-a", "namespace-a", 1, "deletion-a", 0, "genesis",
        "execution-a", 0, "genesis", 0, "anchor-proof-a",
    )
    plan = MigrationPlanV2(
        "transfer-a", "namespace-a", ROLE, "holder-source",
        "install-source", "holder-target", "install-target", anchor,
    )
    permit = MigrationPermitV2(
        "transfer-a", "namespace-a", "source_snapshot", "holder-source",
        "install-source", 1, "a" * 48, anchor,
    )
    requirements = SnapshotRequirementsV2(
        ROLE, "authority-a", "namespace-a", 1,
        "deletion-a", 0, "genesis", "execution-a", 0, "genesis", 0,
        "graph-source-a",
    )
    graph_path = tmp_path / "source.db"
    graph = GraphStore(graph_path, TypeRegistry())
    capability = object()
    graph._coordinator_capability = capability
    try:
        metadata = graph.install_graph_recovery_genesis(
            requirements, _capability=capability)
        with graph._lock:
            graph._db.execute("BEGIN IMMEDIATE")
            try:
                sealed = seal_source_namespace_in_tx(
                    graph, ROLE, transfer_id="transfer-a",
                    source_installation_id="install-source",
                    permit_token=permit.token, expected=metadata,
                    _capability=capability,
                )
                graph._db.execute("COMMIT")
            except BaseException:
                graph._db.execute("ROLLBACK")
                raise
        receipt = SourceSnapshotReceiptV2(
            "transfer-a", "namespace-a", "install-source", permit.token,
            sealed.digest, FORMAT, "graph-source-a", 0, 0,
            requirements, sealed.closure_digest,
        )
        verifier = InstalledSourceGraphProofV1(
            graph_db=graph_path, namespace="namespace-a",
            namespace_id=ROLE, installation_id="install-source",
        )
        assert verifier(receipt, plan, permit) is True
        assert verifier(replace(receipt, snapshot_digest="sha256:" + "0" * 64),
                        plan, permit) is False
        assert verifier(receipt, plan,
                        replace(permit, token="b" * 48)) is False
        graph._db.execute(
            "INSERT INTO graph_bundle_outbox VALUES(?,?,?,?,?)",
            (*ROLE.as_tuple, "outbox-tamper", "operation-tamper", "pending"),
        )
        assert verifier(receipt, plan, permit) is False
        assert InstalledTargetGraphProofHoldV1()(object(), plan, permit) is False
    finally:
        graph.close()
