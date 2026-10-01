"""Controlled Authority-only v2 migration through target preparation.

The file verifiers below are intentionally test-only. They cannot supply the
installed target SQLite writer hold required for activation.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_migration_contract import (
    MigrationPlanV2, SourceSnapshotReceiptV2, TargetRecoveryReceiptV2,
)
from sylanne3.authority_service.v2_migration_service import AuthorityV2MigrationService
from sylanne3.authority_service.v2_migration_store import AuthorityV2MigrationStore
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime.graph_migration_snapshot_v1 import (
    FORMAT, seal_source_namespace_in_tx,
)
from sylanne3.runtime_contracts import NamespaceId, SnapshotRequirementsV2


ROLE = NamespaceId("bot", "persona")
TRANSFER = "transfer-a"


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _head(deletion):
    head = deletion.latest_head()
    return JournalHead(head.journal_id, head.seq, head.chain_digest)


def _requirements(anchor, *, incarnation: str) -> SnapshotRequirementsV2:
    return SnapshotRequirementsV2(
        ROLE, anchor.authority_id, anchor.namespace,
        anchor.activation_generation, anchor.deletion_journal_id,
        anchor.deletion_seq, anchor.deletion_digest,
        anchor.execution_journal_id, anchor.execution_seq,
        anchor.execution_digest, anchor.revocation_epoch, incarnation)


def _source_receipt(root, status):
    permit = status.source_permit
    plan = status.plan
    incarnation = ("source-incarnation" if plan.transfer_id == TRANSFER
                   else "target-incarnation")
    return SourceSnapshotReceiptV2(
        plan.transfer_id, "ns-a", plan.source_installation_id, permit.token,
        _digest((root / "source.snapshot").read_bytes()), "graph-v1",
        incarnation, 1, 1,
        _requirements(status.receipts[0].after_anchor,
                      incarnation=incarnation),
        _digest(b"complete-closure"))


def _target_receipt(root, status):
    permit = status.target_permit
    plan = status.plan
    incarnation = ("target-incarnation" if plan.transfer_id == TRANSFER
                   else "target-incarnation-2")
    return TargetRecoveryReceiptV2(
        plan.transfer_id, "ns-a", plan.target_installation_id, permit.token,
        status.source_snapshot.snapshot_digest, permit.generation,
        incarnation,
        _digest((root / "target-graph-commit.bin").read_bytes()),
        _requirements(status.current_anchor,
                      incarnation=incarnation),
        _digest((root / "unknown-constraints.bin").read_bytes()))


def _open(root: Path, *, create: bool, source_verifier=True,
          target_verifier=True):
    deletion = DeletionJournal(root / "deletion.db", create=create)
    guard = AuthorityV2DeletionGuard(root / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        root / "execution.db", namespace="ns-a",
        journal_id="execution-a", create=create)
    core = AuthorityServiceCore(
        root / "authority.db", create=create,
        authorizer=lambda credential, *_: credential == "admin",
        deletion_verifier=lambda _ns, _before, current, phase:
            current == _head(deletion) and phase == "clear",
        execution_verifier=lambda _ns, _before, current, _phase:
            current == execution.verified_head(),
        effect_verifier=lambda *_: True,
        dispatch_verifier=lambda *_: True,
    )
    if create:
        core.register_namespace(
            "admin", "ns-a", "holder-source", _head(deletion),
            execution.verified_head())
        core.seal_v2_only("admin")
    fences = AuthorityV2FenceStore(core._db, create=create, lock=core._lock)
    service = AuthorityV2FenceService(
        core=core, fences=fences, deletion=guard,
        execution=execution, namespace="ns-a")
    store = AuthorityV2MigrationStore(
        core._db, lock=core._lock, create=create)

    def pairing(credential, subject, plan, phase):
        return (credential == "admin" and subject == "subject-a"
                and phase in {"begin", "revoke", "prepare_target", "activate_target"} and
                (root / "pairing.txt").read_text(encoding="utf-8")
                == (plan.source_installation_id + ">" +
                    plan.target_installation_id + ":" + plan.transfer_id))

    def source(snapshot, plan, permit):
        return (snapshot == _source_receipt(root, migration.recover_transfer(
            credential="admin", subject="subject-a",
            transfer_id=plan.transfer_id).history)
                and snapshot.permit_token == permit.token)

    def target(recovery, plan, permit):
        return (recovery.snapshot_digest == _digest(
                    (root / "source.snapshot").read_bytes())
                and recovery.graph_commit_digest == _digest(
                    (root / "target-graph-commit.bin").read_bytes())
                and recovery.unknown_constraints_digest == _digest(
                    (root / "unknown-constraints.bin").read_bytes())
                and recovery.permit_token == permit.token
                and recovery.target_installation_id == plan.target_installation_id)

    migration = AuthorityV2MigrationService(
        fences=service, store=store, pairing_verifier=pairing,
        source_snapshot_verifier=source if source_verifier else None,
        target_recovery_verifier=target if target_verifier else None)
    return service, migration, store, core, deletion, guard, execution


def _close(bundle):
    _, _, _, core, deletion, guard, execution = bundle
    core.close()
    deletion.close()
    guard.close()
    execution.close()


def _plan(service):
    return MigrationPlanV2(
        TRANSFER, "ns-a", ROLE, "holder-source", "install-source",
        "holder-target", "install-target",
        service.current_anchor(credential="admin", subject="subject-a"))


def _stage(name: str, root: Path):
    if name == "begin":
        (root / "pairing.txt").write_text(
            "install-source>install-target:transfer-a", encoding="utf-8")
        (root / "source.snapshot").write_bytes(b"controlled source closure")
        bundle = _open(root, create=True)
        try:
            service, migration, *_ = bundle
            plan = _plan(service)
            receipt, status = migration.begin_transfer(
                credential="admin", subject="subject-a",
                plan=plan, request_id="begin-a")
            assert receipt.permit == status.source_permit
            assert status.phase == "begun" and status.current_anchor.activation_generation == 1
            with pytest.raises(AuthorityUnavailable):
                service.begin_fence(
                    credential="admin", subject="subject-a",
                    holder="holder-source", operation="read",
                    operation_id="old-read-a", expected_anchor=plan.before_anchor)
        finally:
            _close(bundle)
    elif name == "revoke":
        bundle = _open(root, create=False)
        try:
            _, migration, *_ = bundle
            status = migration.recover_transfer(
                credential="admin", subject="subject-a", transfer_id=TRANSFER).history
            first, replayed = migration.begin_transfer(
                credential="admin", subject="subject-a",
                plan=status.plan, request_id="begin-a")
            assert first == status.receipts[0] and replayed == status
            snapshot = _source_receipt(root, status)
            receipt, current = migration.revoke_source(
                credential="admin", subject="subject-a",
                permit=status.source_permit, snapshot=snapshot,
                request_id="revoke-a")
            assert receipt.phase == current.phase == "revoked"
            assert current.current_anchor.activation_generation == 2
            assert current.current_anchor.revocation_epoch == 1
        finally:
            _close(bundle)
    elif name == "prepare":
        bundle = _open(root, create=False)
        try:
            _, migration, *_ = bundle
            status = migration.recover_transfer(
                credential="admin", subject="subject-a", transfer_id=TRANSFER).history
            previous, replayed = migration.revoke_source(
                credential="admin", subject="subject-a",
                permit=status.source_permit, snapshot=status.source_snapshot,
                request_id="revoke-a")
            assert previous == status.receipts[1] and replayed == status
            receipt, current = migration.prepare_target(
                credential="admin", subject="subject-a",
                transfer_id=TRANSFER, request_id="prepare-a")
            assert receipt.permit == current.target_permit
            assert current.phase == "target_prepared"
            assert current.current_anchor.activation_generation == 3
            (root / "target-graph-commit.bin").write_bytes(
                b"controlled target graph transaction receipt")
            (root / "unknown-constraints.bin").write_bytes(
                b"controlled unknown effect constraints")
        finally:
            _close(bundle)
    elif name == "activate":
        bundle = _open(root, create=False)
        try:
            _, migration, *_ = bundle
            status = migration.recover_transfer(
                credential="admin", subject="subject-a", transfer_id=TRANSFER).history
            previous, replayed = migration.prepare_target(
                credential="admin", subject="subject-a",
                transfer_id=TRANSFER, request_id="prepare-a")
            assert previous == status.receipts[2] and replayed == status
            recovery = _target_receipt(root, status)
            with pytest.raises(AuthorityUnavailable, match="target graph hold"):
                migration.activate_target(
                    credential="admin", subject="subject-a",
                    permit=status.target_permit, recovery=recovery,
                    request_id="activate-a")
            assert migration.recover_transfer(
                credential="admin", subject="subject-a",
                transfer_id=TRANSFER).history.phase == "target_prepared"
        finally:
            _close(bundle)
    elif name == "recover":
        bundle = _open(root, create=False)
        try:
            service, migration, *_ = bundle
            status = migration.recover_transfer(
                credential="admin", subject="subject-a", transfer_id=TRANSFER).history
            previous, replayed = migration.prepare_target(
                credential="admin", subject="subject-a",
                transfer_id=TRANSFER, request_id="prepare-a")
            assert previous == status.receipts[2] and replayed == status
            assert len(status.receipts) == 3 and status.phase == "target_prepared"
            with pytest.raises(AuthorityUnavailable, match="not settled"):
                service.current_anchor(
                    credential="admin", subject="subject-a")
            with pytest.raises(AuthorityUnavailable, match="target graph hold"):
                migration.activate_target(
                    credential="admin", subject="subject-a",
                    permit=status.target_permit,
                    recovery=_target_receipt(root, status),
                    request_id="activate-a")
            with pytest.raises(AuthorityUnavailable):
                service.begin_fence(
                    credential="admin", subject="subject-a",
                    holder="holder-source", operation="read",
                    operation_id="stale-source-read", expected_anchor=status.plan.before_anchor)
        finally:
            _close(bundle)
    else:
        raise ValueError(name)
    (root / f"{name}.json").write_text(
        json.dumps({"pid": os.getpid(), "stage": name}), encoding="utf-8")


def _run(name: str, root: Path):
    environment = os.environ.copy()
    rewrite_root = Path(__file__).resolve().parents[3]
    environment["PYTHONPATH"] = os.pathsep.join(filter(None, (
        str(rewrite_root), environment.get("PYTHONPATH", ""))))
    process = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), name, str(root)],
        cwd=rewrite_root, env=environment, text=True, capture_output=True,
        timeout=30, check=False)
    assert process.returncode == 0, process.stdout + process.stderr


def test_each_lost_ack_recovers_same_receipt_in_fresh_process(tmp_path):
    seen = {os.getpid()}
    for stage in ("begin", "revoke", "prepare", "activate", "recover"):
        _run(stage, tmp_path)
        result = json.loads((tmp_path / f"{stage}.json").read_text(encoding="utf-8"))
        assert result["stage"] == stage and result["pid"] not in seen
        seen.add(result["pid"])


def test_prepared_transfer_blocks_second_transfer_after_cold_reopen(tmp_path):
    seen = {os.getpid()}
    for stage in ("begin", "revoke", "prepare", "activate", "recover"):
        _run(stage, tmp_path)
        result = json.loads((tmp_path / f"{stage}.json").read_text(encoding="utf-8"))
        assert result["stage"] == stage and result["pid"] not in seen
        seen.add(result["pid"])
    bundle = _open(tmp_path, create=False)
    try:
        service, migration, *_ = bundle
        current = migration.recover_transfer(
            credential="admin", subject="subject-a",
            transfer_id=TRANSFER).history.current_anchor
        second = MigrationPlanV2(
            "transfer-b", "ns-a", ROLE, "holder-target", "install-target",
            "holder-final", "install-final", current)
        (tmp_path / "pairing.txt").write_text(
            "install-target>install-final:transfer-b", encoding="utf-8")
        with pytest.raises(AuthorityUnavailable, match="not settled"):
            migration.begin_transfer(
                credential="admin", subject="subject-a", plan=second,
                request_id="begin-b")
        assert migration.recover_transfer(
            credential="admin", subject="subject-a",
            transfer_id=TRANSFER).history.phase == "target_prepared"
    finally:
        _close(bundle)


def test_missing_graph_verifiers_hold_and_live_fence_blocks_begin(tmp_path):
    (tmp_path / "pairing.txt").write_text(
        "install-source>install-target:transfer-a", encoding="utf-8")
    (tmp_path / "source.snapshot").write_bytes(b"controlled source closure")
    bundle = _open(tmp_path, create=True)
    try:
        service, migration, store, core, _, _, _ = bundle
        plan = _plan(service)
        fence = service.begin_fence(
            credential="admin", subject="subject-a", holder="holder-source",
            operation="read", operation_id="busy-read",
            expected_anchor=plan.before_anchor)
        with pytest.raises(AuthorityUnavailable, match="active or pending"):
            migration.begin_transfer(
                credential="admin", subject="subject-a", plan=plan,
                request_id="begin-a")
        service.finish_fence(
            credential="admin", subject="subject-a", permit=fence,
            request_id="close-busy", request_digest="sha256:" + "a" * 64)
        _, status = migration.begin_transfer(
            credential="admin", subject="subject-a", plan=plan,
            request_id="begin-a")
        assert status.phase == "begun"
        held = AuthorityV2MigrationService(
            fences=service, store=store,
            pairing_verifier=migration._pairing_verifier,
            source_snapshot_verifier=None, target_recovery_verifier=None)
        with pytest.raises(AuthorityUnavailable, match="source graph snapshot verifier"):
            held.revoke_source(
                credential="admin", subject="subject-a",
                permit=status.source_permit,
                snapshot=_source_receipt(tmp_path, status),
                request_id="revoke-a")
        assert held.recover_transfer(
            credential="admin", subject="subject-a",
            transfer_id=TRANSFER).history.phase == "begun"
        assert core._db.execute(
            "SELECT generation,phase FROM authority_namespaces WHERE namespace='ns-a'"
        ).fetchone() == (1, "recovering")
    finally:
        _close(bundle)


def test_target_proof_and_request_identity_hold_until_independent_verification(tmp_path):
    (tmp_path / "pairing.txt").write_text(
        "install-source>install-target:transfer-a", encoding="utf-8")
    (tmp_path / "source.snapshot").write_bytes(b"controlled source closure")
    (tmp_path / "target-graph-commit.bin").write_bytes(b"controlled target receipt")
    (tmp_path / "unknown-constraints.bin").write_bytes(b"controlled unknowns")
    bundle = _open(tmp_path, create=True)
    try:
        service, migration, store, core, _, _, _ = bundle
        plan = _plan(service)
        with pytest.raises(AuthorityUnavailable, match="authentication denied"):
            migration.begin_transfer(
                credential="denied", subject="subject-a", plan=plan,
                request_id="begin-a")
        with pytest.raises(AuthorityUnavailable, match="dedicated management"):
            service.begin_fence(
                credential="admin", subject="subject-a", holder="holder-source",
                operation="migrate", operation_id="wrong-path",
                expected_anchor=plan.before_anchor)
        _, begun = migration.begin_transfer(
            credential="admin", subject="subject-a", plan=plan,
            request_id="begin-a")
        _, revoked = migration.revoke_source(
            credential="admin", subject="subject-a",
            permit=begun.source_permit,
            snapshot=_source_receipt(tmp_path, begun), request_id="revoke-a")
        _, prepared = migration.prepare_target(
            credential="admin", subject="subject-a",
            transfer_id=TRANSFER, request_id="prepare-a")
        recovery = _target_receipt(tmp_path, prepared)
        held = AuthorityV2MigrationService(
            fences=service, store=store,
            pairing_verifier=migration._pairing_verifier,
            source_snapshot_verifier=None, target_recovery_verifier=None)
        with pytest.raises(AuthorityUnavailable, match="target graph hold"):
            held.activate_target(
                credential="admin", subject="subject-a",
                permit=prepared.target_permit, recovery=recovery,
                request_id="activate-a")
        with pytest.raises(AuthorityUnavailable, match="target graph recovery identity"):
            migration.activate_target(
                credential="admin", subject="subject-a",
                permit=prepared.target_permit,
                recovery=replace(recovery, snapshot_digest=_digest(b"wrong")),
                request_id="activate-a")
        assert migration.recover_transfer(
            credential="admin", subject="subject-a",
            transfer_id=TRANSFER).history.phase == "target_prepared"
        assert core._db.execute(
            "SELECT holder,generation,phase FROM authority_namespaces "
            "WHERE namespace='ns-a'").fetchone() == (
                "holder-target", 3, "recovering")
        with pytest.raises(AuthorityUnavailable, match="target graph hold"):
            migration.activate_target(
                credential="admin", subject="subject-a",
                permit=prepared.target_permit, recovery=recovery,
                request_id="activate-a")
        assert migration.recover_transfer(
            credential="admin", subject="subject-a",
            transfer_id=TRANSFER).history.phase == "target_prepared"
        assert revoked.current_anchor.activation_generation == 2
    finally:
        _close(bundle)


def test_historical_receipt_digest_rejects_local_byte_change(tmp_path):
    (tmp_path / "pairing.txt").write_text(
        "install-source>install-target:transfer-a", encoding="utf-8")
    bundle = _open(tmp_path, create=True)
    try:
        service, migration, _, core, *_ = bundle
        migration.begin_transfer(
            credential="admin", subject="subject-a", plan=_plan(service),
            request_id="begin-a")
        trigger = core._db.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' "
            "AND name='authority_migration_v2_receipts_no_update'"
        ).fetchone()[0]
        core._db.execute("DROP TRIGGER authority_migration_v2_receipts_no_update")
        core._db.execute(
            "UPDATE authority_migration_v2_receipts "
            "SET receipt_json=replace(receipt_json,'begin-a','begin-z') "
            "WHERE transfer_id=?", (TRANSFER,))
        core._db.execute(trigger)
        with pytest.raises(AuthorityUnavailable, match="receipt digest differs"):
            migration.recover_transfer(
                credential="admin", subject="subject-a", transfer_id=TRANSFER)
    finally:
        _close(bundle)


def test_real_empty_graph_genesis_snapshot_has_valid_zero_revision_contract(tmp_path):
    (tmp_path / "pairing.txt").write_text(
        "install-source>install-target:transfer-a", encoding="utf-8")
    bundle = _open(tmp_path, create=True)
    graph = GraphStore(tmp_path / "graph.db", TypeRegistry())
    capability = object()
    graph._coordinator_capability = capability
    try:
        service, migration, *_ = bundle
        _, begun = migration.begin_transfer(
            credential="admin", subject="subject-a", plan=_plan(service),
            request_id="begin-a")
        permit = begun.source_permit
        requirements = _requirements(
            begun.current_anchor, incarnation="source-incarnation")
        metadata = graph.install_graph_recovery_genesis(
            requirements, _capability=capability)
        with graph._lock:
            graph._db.execute("BEGIN IMMEDIATE")
            try:
                snapshot = seal_source_namespace_in_tx(
                    graph, ROLE, transfer_id=TRANSFER,
                    source_installation_id="install-source",
                    permit_token=permit.token, expected=metadata,
                    _capability=capability)
            finally:
                graph._db.execute("ROLLBACK")
        receipt = SourceSnapshotReceiptV2(
            snapshot.transfer_id, "ns-a", snapshot.source_installation_id,
            snapshot.permit_token, snapshot.digest, FORMAT,
            snapshot.source_metadata.requirements.graph_incarnation,
            snapshot.source_metadata.graph_revision, snapshot.graph_epoch,
            snapshot.source_metadata.requirements, snapshot.closure_digest)
        assert receipt.graph_revision == metadata.graph_revision == 0
        assert receipt.graph_epoch == snapshot.graph_epoch == 0
        assert receipt.snapshot_digest == snapshot.digest
    finally:
        graph.close()
        _close(bundle)


if __name__ == "__main__":
    _stage(sys.argv[1], Path(sys.argv[2]))
