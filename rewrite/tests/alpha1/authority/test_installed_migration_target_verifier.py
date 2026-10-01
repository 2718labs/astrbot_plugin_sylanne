"""Target activation proof rereads real source and imported target SQLite rows."""

from dataclasses import replace
import sqlite3

import pytest

from rewrite.tests.alpha1.authority import test_v2_migration_local_state as fixture
from sylanne3.authority_service.installed_migration_graph_proofs import (
    InstalledSourceGraphProofV1,
)
from sylanne3.authority_service.installed_migration_target_verifier import (
    InstalledMigrationTargetVerifierV1,
)
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_migration_contract import (
    SourceSnapshotReceiptV2, TargetRecoveryReceiptV2,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.runtime.graph_migration_snapshot_v1 import (
    FORMAT, import_snapshot_into_isolated_target_in_tx,
    seal_source_namespace_in_tx,
)
from sylanne3.runtime.graph_migration_transfer_verifier_v2 import (
    InstalledGraphMigrationTransferVerifierV2,
)


def test_target_proof_reads_persistent_originals_and_rejects_tamper(tmp_path):
    (tmp_path / "pairing.txt").write_text(
        "install-source>install-target:transfer-a", encoding="utf-8")
    bundle = fixture._open(tmp_path, create=True, source_verifier=False)
    source = GraphStore(tmp_path / "source-graph.db", TypeRegistry())
    target = GraphStore(tmp_path / "target-graph.db", TypeRegistry())
    capability = object()
    source._coordinator_capability = target._coordinator_capability = capability
    try:
        service, migration, _, _, _, _, _ = bundle
        plan = fixture._plan(service)
        _, begun = migration.begin_transfer(
            credential="admin", subject="subject-a", plan=plan,
            request_id="begin-target-proof")
        source_requirements = fixture._requirements(
            begun.receipts[0].after_anchor, incarnation="source-incarnation")
        metadata = source.install_graph_recovery_genesis(
            source_requirements, _capability=capability)
        with source._lock:
            source._db.execute("BEGIN IMMEDIATE")
            try:
                snapshot = seal_source_namespace_in_tx(
                    source, fixture.ROLE, transfer_id=fixture.TRANSFER,
                    source_installation_id="install-source",
                    permit_token=begun.source_permit.token,
                    expected=metadata, _capability=capability)
                source._db.execute("COMMIT")
            except BaseException:
                source._db.execute("ROLLBACK")
                raise
        source_receipt = SourceSnapshotReceiptV2(
            fixture.TRANSFER, "ns-a", "install-source",
            begun.source_permit.token, snapshot.digest, FORMAT,
            source_requirements.graph_incarnation,
            metadata.graph_revision, snapshot.graph_epoch,
            source_requirements, snapshot.closure_digest)
        migration._source_verifier = InstalledSourceGraphProofV1(
            graph_db=tmp_path / "source-graph.db", namespace="ns-a",
            namespace_id=fixture.ROLE, installation_id="install-source")
        _, revoked = migration.revoke_source(
            credential="admin", subject="subject-a",
            permit=begun.source_permit, snapshot=source_receipt,
            request_id="revoke-target-proof")
        assert revoked.source_snapshot == source_receipt
        _, prepared = migration.prepare_target(
            credential="admin", subject="subject-a",
            transfer_id=fixture.TRANSFER, request_id="prepare-target-proof")
        target_requirements = fixture._requirements(
            prepared.current_anchor, incarnation="target-incarnation")
        transfer = InstalledGraphMigrationTransferVerifierV2(
            authority=migration, credential="admin", subject="subject-a",
            target_installation_id="install-target",
            target_requirements=target_requirements)
        handle = transfer.prepare(prepared.target_permit)
        target._migration_transfer_verifier = transfer
        with target._lock:
            target._db.execute("BEGIN IMMEDIATE")
            try:
                imported = import_snapshot_into_isolated_target_in_tx(
                    target, snapshot, target_requirements, handle,
                    _capability=capability)
                target._db.execute("COMMIT")
            except BaseException:
                target._db.execute("ROLLBACK")
                raise
        receipt = TargetRecoveryReceiptV2(
            fixture.TRANSFER, "ns-a", "install-target",
            prepared.target_permit.token, snapshot.digest,
            prepared.target_permit.generation,
            target_requirements.graph_incarnation,
            imported.graph_commit_digest, target_requirements,
            "sha256:" + "a" * 64)
        arguments = dict(
            authority=migration, credential="admin", subject="subject-a",
            source_graph_db=tmp_path / "source-graph.db",
            target_graph_db=tmp_path / "target-graph.db")
        verifier = InstalledMigrationTargetVerifierV1(**arguments)
        assert verifier._verify_persisted_graph_and_heads(
            receipt, plan, prepared.target_permit) is True
        assert verifier(receipt, plan, prepared.target_permit) is False
        with pytest.raises(AuthorityUnavailable, match="reconciliation original"):
            with verifier.hold(receipt, plan, prepared.target_permit):
                pytest.fail("unreconciled migration must never activate")
        with verifier._target_writer_lock():
            with sqlite3.connect(
                    tmp_path / "target-graph.db", isolation_level=None,
                    timeout=0.05) as competing:
                competing.execute("PRAGMA busy_timeout=50")
                with pytest.raises(sqlite3.OperationalError, match="locked"):
                    competing.execute(
                        "INSERT INTO graph_bundle_outbox VALUES(?,?,?,?,?)",
                        (*fixture.ROLE.as_tuple, "blocked-write", "op", "pending"))
                with pytest.raises(sqlite3.OperationalError, match="locked"):
                    competing.execute(
                        "INSERT INTO graph_migration_import_receipts_v1 "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (*fixture.ROLE.as_tuple, "blocked-import", "sha256:x",
                         "sha256:y", 0, 1, "{}"))
        assert verifier._verify_persisted_graph_and_heads(replace(
            receipt, graph_commit_digest="sha256:" + "0" * 64),
            plan, prepared.target_permit) is False
        with sqlite3.connect(
                tmp_path / "target-graph.db", isolation_level=None,
                timeout=0.05) as competing:
            competing.execute(
                "INSERT INTO graph_bundle_outbox VALUES(?,?,?,?,?)",
                (*fixture.ROLE.as_tuple, "released-write", "op", "pending"))
        assert verifier._verify_persisted_graph_and_heads(
            receipt, plan, prepared.target_permit) is False
        absent_source = InstalledMigrationTargetVerifierV1(
            **{**arguments, "source_graph_db": tmp_path / "missing-source.db"})
        assert absent_source(receipt, plan, prepared.target_permit) is False
    finally:
        source.close()
        target.close()
        fixture._close(bundle)
