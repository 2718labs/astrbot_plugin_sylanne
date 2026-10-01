"""A real pending Owner revoke cannot cross target verification and Core CAS.

The source/target graph callbacks here are controlled fixtures; this test only
proves the Authority Owner-head race gate, not migration product readiness.
"""

from contextlib import contextmanager

import pytest

from rewrite.tests.alpha1.authority.test_local_owner_round_trip import (
    AUTH_NS, PEER, ROLE, SUBJECT, WORKER,
)
from rewrite.tests.alpha1.integration.test_owner_signed_chain import _real_owner_chain
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_migration_contract import (
    MigrationPlanV2, SourceSnapshotReceiptV2, TargetRecoveryReceiptV2,
)
from sylanne3.authority_service.v2_migration_service import AuthorityV2MigrationService
from sylanne3.authority_service.v2_migration_store import AuthorityV2MigrationStore
from sylanne3.authority_service.installed_migration_target_verifier import (
    InstalledMigrationTargetVerifierV1, TargetGraphHeldProofV1,
)
from sylanne3.runtime_contracts import SnapshotRequirementsV2


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def _requirements(anchor, incarnation: str) -> SnapshotRequirementsV2:
    return SnapshotRequirementsV2(
        ROLE, anchor.authority_id, anchor.namespace,
        anchor.activation_generation, anchor.deletion_journal_id,
        anchor.deletion_seq, anchor.deletion_digest,
        anchor.execution_journal_id, anchor.execution_seq,
        anchor.execution_digest, anchor.revocation_epoch, incarnation)


def test_pending_owner_revoke_during_target_verification_blocks_activation(
        tmp_path, monkeypatch):
    chain = _real_owner_chain(tmp_path)
    core = chain.resources[1]
    tickets = chain.server._v2_owner_tickets
    original_authorizer = core._authorize_callback
    core._authorize_callback = lambda credential, action, namespace, holder: (
        (namespace == AUTH_NS and credential == PEER and action in {
            "migration_begin", "migration_revoke", "migration_prepare_target",
            "migration_activate", "migration_recover",
            "owner_authorization_revoke"})
        or original_authorizer(credential, action, namespace, holder))
    try:
        operation, _ = chain.coordinator.freeze_current_owner_revoke_v2(
            chain.bootstrap, namespace=ROLE, operation_id="migration-owner-revoke")
        with core._tx() as db:
            source_holder = core._row(db, AUTH_NS)[0]
        before = chain.service.current_anchor(credential=WORKER, subject=SUBJECT)
        plan = MigrationPlanV2(
            "owner-race-transfer", AUTH_NS, ROLE, source_holder,
            "installation", "migration-target", "target-installation", before)
        migration = AuthorityV2MigrationService(
            fences=chain.service,
            store=AuthorityV2MigrationStore(core._db, lock=core._lock, create=True),
            pairing_verifier=lambda *_: True,
            source_snapshot_verifier=lambda *_: True,
            target_recovery_verifier=None,
            owner_tickets=tickets)
        _, begun = migration.begin_transfer(
            credential=PEER, subject=SUBJECT, plan=plan, request_id="begin-race")
        source = SourceSnapshotReceiptV2(
            plan.transfer_id, AUTH_NS, plan.source_installation_id,
            begun.source_permit.token, _digest("a"), "graph-v1",
            "source-incarnation", 1, 1,
            _requirements(begun.current_anchor, "source-incarnation"),
            _digest("b"))
        migration.revoke_source(
            credential=PEER, subject=SUBJECT, permit=begun.source_permit,
            snapshot=source, request_id="revoke-source-race")
        _, prepared = migration.prepare_target(
            credential=PEER, subject=SUBJECT,
            transfer_id=plan.transfer_id, request_id="prepare-race")
        recovery = TargetRecoveryReceiptV2(
            plan.transfer_id, AUTH_NS, plan.target_installation_id,
            prepared.target_permit.token, source.snapshot_digest,
            prepared.target_permit.generation, "target-incarnation",
            _digest("c"), _requirements(prepared.current_anchor, "target-incarnation"),
            _digest("d"))
        holder = InstalledMigrationTargetVerifierV1(
            authority=migration, credential=PEER, subject=SUBJECT,
            source_graph_db=tmp_path / "source-business.db",
            target_graph_db=tmp_path / "target-business.db")
        migration.install_target_recovery_holder(holder)

        @contextmanager
        def attempted_revoke(_recovery, _plan, _permit):
            tickets.reserve_revoke(
                credential=PEER, authority_namespace=AUTH_NS,
                operation=operation)
            yield  # The real Owner store rejects during migration recovery.

        monkeypatch.setattr(holder, "hold", attempted_revoke)
        with pytest.raises(AuthorityUnavailable,
                           match="Owner revoke namespace is unavailable"):
            migration.activate_target(
                credential=PEER, subject=SUBJECT,
                permit=prepared.target_permit, recovery=recovery,
                request_id="activate-race")
        assert migration.recover_transfer(
            credential=PEER, subject=SUBJECT,
            transfer_id=plan.transfer_id).history.phase == "target_prepared"

        # Controlled head-read race exercises the final CAS comparison itself.
        # An actual reserve_revoke above is independently denied while recovering.
        with core._tx() as db:
            original_head = tickets.current_migration_head_in_tx(
                db, authority_namespace=AUTH_NS)
        reads = 0

        def changing_head(db, *, authority_namespace):
            nonlocal reads
            assert authority_namespace == AUTH_NS
            reads += 1
            return original_head if reads == 1 else None

        monkeypatch.setattr(tickets, "current_migration_head_in_tx", changing_head)

        @contextmanager
        def controlled_held_proof(_recovery, _plan, _permit):
            yield TargetGraphHeldProofV1(
                recovery.transfer_id, recovery.target_installation_id,
                recovery.permit_token, recovery.snapshot_digest,
                recovery.graph_commit_digest, recovery.target_generation,
                recovery.new_graph_incarnation)

        monkeypatch.setattr(holder, "hold", controlled_held_proof)
        with pytest.raises(AuthorityUnavailable,
                           match="Owner head changed during target verification"):
            migration.activate_target(
                credential=PEER, subject=SUBJECT,
                permit=prepared.target_permit, recovery=recovery,
                request_id="activate-head-race")
        assert reads == 2
    finally:
        for resource in chain.resources:
            resource.close()
