"""Local v2-only Authority transfer state machine; no RPC or graph fallback.

Graph proof callbacks are installation-owned and run outside all journal and
Authority locks. Without them, source revocation or target activation stays HOLD.
"""

from __future__ import annotations

from dataclasses import asdict
import secrets
from typing import Callable

from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import (NamespaceRuntimeState, SnapshotRequirementsV2,
                                 canonical_digest)
from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .v2_fence_service import AuthorityV2FenceService
from .v2_fence_store import AuthorityV2FenceStore
from .v2_migration_contract import (
    MigrationCurrentNamespaceV2, MigrationPermitV2, MigrationPlanV2,
    MigrationRecoveryV2, MigrationStageReceiptV2, MigrationStatusV2,
    SourceSnapshotReceiptV2, TargetRecoveryReceiptV2,
)
from .v2_migration_store import AuthorityV2MigrationStore
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore


def _request_digest(value: object) -> str:
    return "sha256:" + canonical_digest(value)


def _requirements_match(requirements: SnapshotRequirementsV2,
                        anchor: RestoreAnchor, plan: MigrationPlanV2) -> bool:
    return (type(requirements) is SnapshotRequirementsV2
            and requirements.namespace == plan.namespace_id
            and (requirements.authority_id, requirements.authority_namespace,
                 requirements.activation_generation,
                 requirements.deletion_journal_id, requirements.deletion_seq,
                 requirements.deletion_digest, requirements.execution_journal_id,
                 requirements.execution_seq, requirements.execution_digest,
                 requirements.revocation_epoch)
            == (anchor.authority_id, anchor.namespace,
                anchor.activation_generation,
                anchor.deletion_journal_id, anchor.deletion_seq,
                anchor.deletion_digest, anchor.execution_journal_id,
                anchor.execution_seq, anchor.execution_digest,
                anchor.revocation_epoch))


class AuthorityV2MigrationService:
    """One namespace, one Core, and the same two frozen independent journals."""

    def __init__(self, *, fences: AuthorityV2FenceService,
                 store: AuthorityV2MigrationStore,
                 pairing_verifier: Callable[[object, str, MigrationPlanV2,
                                             str], bool] | None,
                 source_snapshot_verifier: Callable[[SourceSnapshotReceiptV2,
                                                    MigrationPlanV2,
                                                    MigrationPermitV2], bool] | None,
                 target_recovery_verifier: Callable[[TargetRecoveryReceiptV2,
                                                    MigrationPlanV2,
                                                    MigrationPermitV2], bool] | None,
                 owner_tickets: AuthorityV2OwnerTicketStore | None = None):
        if (type(fences) is not AuthorityV2FenceService
                or type(store) is not AuthorityV2MigrationStore
                or store._db is not fences.core._db
                or store._lock is not fences.core._lock
                or (owner_tickets is not None and (
                    type(owner_tickets) is not AuthorityV2OwnerTicketStore
                    or owner_tickets._core is not fences.core))
                or any(value is not None and not callable(value) for value in (
                    pairing_verifier, source_snapshot_verifier,
                    target_recovery_verifier))):
            raise AuthorityUnavailable("migration requires one installed Authority service")
        self.fences, self.store = fences, store
        self.core: AuthorityServiceCore = fences.core
        self.namespace = fences.namespace
        self._pairing_verifier = pairing_verifier
        self._source_verifier = source_snapshot_verifier
        self._target_verifier = target_recovery_verifier
        self._target_holder = None
        self._owner_tickets = owner_tickets
        with self.core._tx() as db:
            self.fences._require_mode(db)
            self.store.check_schema_locked(db)

    def install_target_recovery_holder(self, holder: object) -> None:
        """Pair one pinned same-host target lock before exposing activation RPC."""
        from .installed_migration_target_verifier import InstalledMigrationTargetVerifierV1

        if (type(holder) is not InstalledMigrationTargetVerifierV1
                or holder._authority is not self or self._target_holder is not None):
            raise AuthorityUnavailable("installed target graph holder identity differs")
        self._target_holder = holder

    def _require(self, credential, action: str, holder: str | None) -> None:
        self.core._require(credential, action, self.namespace, holder)

    def _verify_pairing(self, credential, subject: str,
                        plan: MigrationPlanV2, phase: str) -> None:
        if self._pairing_verifier is None:
            raise AuthorityUnavailable("trusted migration pairing unavailable")
        try:
            paired = self._pairing_verifier(credential, subject, plan, phase)
        except Exception as exc:
            raise AuthorityUnavailable("migration pairing verification failed") from exc
        if paired is not True:
            raise AuthorityUnavailable("migration pairing denied")

    def _owner_head_locked(self, db):
        if self._owner_tickets is None:
            if AuthorityV2OwnerTicketStore._present(db):
                raise AuthorityUnavailable("Owner migration head reader is not installed")
            return None
        self._owner_tickets._check_schema(db)
        return self._owner_tickets.current_migration_head_in_tx(
            db, authority_namespace=self.namespace)

    def _status_locked(self, db, deletion_head, execution_head,
                       transfer_id: str) -> MigrationStatusV2 | None:
        self.fences._require_mode(db)
        self.fences.fences._check_schema(db)
        status = self.store.status_locked(db, transfer_id)
        if status is None:
            return None
        if status.plan.namespace != self.namespace:
            raise AuthorityUnavailable("transfer belongs to another namespace")
        row = self.core._row(db, self.namespace)
        anchor = self.core._anchor(db, self.namespace, row)
        plan = status.plan
        expected = {
            "begun": (plan.source_holder, plan.before_anchor.activation_generation,
                      "recovering", transfer_id, plan.target_holder),
            "revoked": (None, plan.before_anchor.activation_generation + 1,
                        "revoked", transfer_id, plan.target_holder),
            "target_prepared": (
                plan.target_holder, plan.before_anchor.activation_generation + 2,
                "recovering", transfer_id, plan.target_holder),
            "activated": (
                plan.target_holder, plan.before_anchor.activation_generation + 2,
                "active", None, None),
        }[status.phase]
        if (row[:5] != expected or anchor != status.current_anchor
                or row[6:9] != (deletion_head.journal_id,
                                deletion_head.seq, deletion_head.digest)
                or row[10:13] != (execution_head.journal_id,
                                   execution_head.seq, execution_head.digest)):
            raise AuthorityUnavailable("migration state or independent heads differ")
        return status

    def _lookup(self, transfer_id: str, phase: str, request_id: str,
                request_digest: str):
        with self.fences._frozen() as (db, deletion_head, execution_head, _):
            return self._lookup_locked(
                db, deletion_head, execution_head, transfer_id, phase,
                request_id, request_digest)

    def _lookup_locked(self, db, deletion_head, execution_head,
                       transfer_id: str, phase: str, request_id: str,
                       request_digest: str):
        self.fences._require_mode(db)
        self.fences.fences._check_schema(db)
        history = self.store.status_locked(db, transfer_id)
        replay = self.store.replay_locked(
            db, transfer_id, phase, request_id, request_digest)
        if replay is not None:
            # A later transfer cannot invalidate an earlier immutable response.
            # This branch never authorizes another transition.
            return history, replay
        return self._status_locked(
            db, deletion_head, execution_head, transfer_id), None

    def _current_namespace_locked(self, db, deletion_head, execution_head,
                                  deletion_history: bool
                                  ) -> MigrationCurrentNamespaceV2:
        self.fences._require_mode(db)
        self.fences.fences._check_schema(db)
        row = self.core._row(db, self.namespace)
        heads_match = (row[6:9] == (
            deletion_head.journal_id, deletion_head.seq, deletion_head.digest)
            and row[10:13] == (
                execution_head.journal_id, execution_head.seq,
                execution_head.digest))
        blockers = []
        if not heads_match:
            blockers.append("journal_head_mismatch")
        if row[9] != "clear":
            blockers.append("deletion_barrier")
        if deletion_history:
            try:
                self.core.require_current_content_ready_locked(db, namespace=self.namespace)
            except AuthorityUnavailable:
                blockers.append("deletion_history")
        if db.execute(
                "SELECT 1 FROM authority_v2_fences WHERE namespace=? "
                "AND (state='active' OR pending IS NOT NULL) LIMIT 1",
                (self.namespace,)).fetchone():
            blockers.append("active_or_pending_fence")
        if db.execute(
                "SELECT 1 FROM authority_v2_mutations WHERE namespace=? "
                "AND state='pending' LIMIT 1", (self.namespace,)).fetchone():
            blockers.append("pending_mutation")
        if row[2] != "active" or row[0] is None or row[3] is not None:
            blockers.append("activation_unsettled")
        isolated = any(item in blockers for item in (
            "journal_head_mismatch", "deletion_barrier", "deletion_history"))
        state = (NamespaceRuntimeState.QUARANTINED if isolated else
                 NamespaceRuntimeState.RECOVERING if blockers else
                 NamespaceRuntimeState.ACTIVE)
        return MigrationCurrentNamespaceV2(
            self.namespace, row[0], row[1], row[2], row[3], row[4],
            state, self.core._anchor(db, self.namespace, row)
            if heads_match and not isolated else None, tuple(blockers))

    def begin_transfer(self, *, credential, subject: str,
                       plan: MigrationPlanV2, request_id: str
                       ) -> tuple[MigrationStageReceiptV2, MigrationStatusV2]:
        identifier(subject, "subject")
        identifier(request_id, "request_id")
        if type(plan) is not MigrationPlanV2 or plan.namespace != self.namespace:
            raise AuthorityUnavailable("typed migration plan for this namespace required")
        self._require(credential, "migration_begin", plan.source_holder)
        digest = _request_digest((plan, subject))
        status, replay = self._lookup(plan.transfer_id, "begun", request_id, digest)
        if replay is not None:
            if status is None or status.plan != plan:
                raise AuthorityUnavailable("migration begin replay plan differs")
            return replay, status
        if status is not None:
            raise AuthorityUnavailable("transfer ID already has another begin")
        self._verify_pairing(credential, subject, plan, "begin")
        with self.fences._frozen() as (db, deletion_head, execution_head,
                                     deletion_history):
            status, replay = self._lookup_locked(
                db, deletion_head, execution_head, plan.transfer_id,
                "begun", request_id, digest)
            if replay is not None:
                if status is None or status.plan != plan:
                    raise AuthorityUnavailable("migration begin replay plan differs")
                return replay, status
            if status is not None:
                raise AuthorityUnavailable("transfer ID already used")
            from .d12_lifecycle_gate_v1 import require_lifecycle_exclusion_in_tx_v1
            require_lifecycle_exclusion_in_tx_v1(db, self.namespace, operation="migration")
            current = self.fences._current_locked(
                db, deletion_head, execution_head,
                holder=plan.source_holder,
                generation=plan.before_anchor.activation_generation)
            if current != plan.before_anchor or deletion_history:
                raise AuthorityUnavailable("source anchor or deletion history differs")
            AuthorityV2FenceStore.require_idle_migration_in_tx(
                db, self.namespace)
            if db.execute(
                    "SELECT 1 FROM authority_permits WHERE namespace=? LIMIT 1",
                    (self.namespace,)).fetchone():
                raise AuthorityUnavailable("legacy permit blocks source freeze")
            changed = db.execute(
                "UPDATE authority_namespaces SET phase='recovering',"
                "transfer_id=?,target=?,anchor_nonce=? "
                "WHERE namespace=? AND holder=? AND generation=? "
                "AND phase='active' AND transfer_id IS NULL AND target IS NULL "
                "AND anchor_nonce=?",
                (plan.transfer_id, plan.target_holder, self.core._new_nonce(),
                 self.namespace, plan.source_holder,
                 plan.before_anchor.activation_generation,
                 plan.before_anchor.proof)).rowcount
            if changed != 1:
                raise AuthorityUnavailable("source freeze CAS failed")
            after = self.core._anchor(
                db, self.namespace, self.core._row(db, self.namespace))
            permit = MigrationPermitV2(
                plan.transfer_id, self.namespace, "source_snapshot",
                plan.source_holder, plan.source_installation_id,
                after.activation_generation, secrets.token_urlsafe(48), after)
            receipt = MigrationStageReceiptV2(
                plan.transfer_id, "begun", request_id, digest, after, permit)
            self.store.begin_locked(db, plan, permit, receipt)
            self.core._event(db, self.namespace, "v2_transfer_begun",
                             after.activation_generation,
                             (plan.transfer_id, request_id, digest))
            return receipt, self._status_locked(
                db, deletion_head, execution_head, plan.transfer_id)

    def revoke_source(self, *, credential, subject: str,
                      permit: MigrationPermitV2,
                      snapshot: SourceSnapshotReceiptV2,
                      request_id: str
                      ) -> tuple[MigrationStageReceiptV2, MigrationStatusV2]:
        identifier(subject, "subject")
        identifier(request_id, "request_id")
        if (type(permit) is not MigrationPermitV2
                or type(snapshot) is not SourceSnapshotReceiptV2
                or permit.namespace != self.namespace
                or snapshot.namespace != self.namespace
                or snapshot.transfer_id != permit.transfer_id):
            raise AuthorityUnavailable("typed source snapshot and permit required")
        self._require(credential, "migration_revoke", permit.holder)
        digest = _request_digest((permit, snapshot, subject))
        status, replay = self._lookup(
            permit.transfer_id, "revoked", request_id, digest)
        if replay is not None:
            return replay, status
        if status is None or status.phase != "begun":
            raise AuthorityUnavailable("source transfer is not frozen")
        plan = status.plan
        if (permit != status.source_permit
                or snapshot.permit_token != permit.token
                or snapshot.source_installation_id != plan.source_installation_id
                or not _requirements_match(
                    snapshot.requirements, status.current_anchor, plan)):
            raise AuthorityUnavailable("source snapshot identity or watermark differs")
        self._verify_pairing(credential, subject, plan, "revoke")
        from .installed_migration_graph_proofs import InstalledSourceGraphProofV1
        if type(self._source_verifier) is not InstalledSourceGraphProofV1:
            raise AuthorityUnavailable("trusted installed source graph snapshot verifier unavailable")
        try:
            verified = self._source_verifier.verify_snapshot_certificate_members_v1(snapshot, plan, permit)
        except Exception as exc:
            raise AuthorityUnavailable("source graph snapshot verification failed") from exc
        if verified is None:
            raise AuthorityUnavailable("source graph snapshot not verified")
        with self.fences._frozen() as (db, deletion_head, execution_head, _):
            status, replay = self._lookup_locked(
                db, deletion_head, execution_head, permit.transfer_id,
                "revoked", request_id, digest)
            if replay is not None:
                return replay, status
            if (status is None or status.phase != "begun"
                    or status.source_permit != permit
                    or not _requirements_match(
                        snapshot.requirements, status.current_anchor, status.plan)):
                raise AuthorityUnavailable("source snapshot state changed")
            AuthorityV2FenceStore.require_idle_migration_in_tx(db, self.namespace)
            row = self.core._row(db, self.namespace)
            changed = db.execute(
                "UPDATE authority_namespaces SET holder=NULL,generation=generation+1,"
                "phase='revoked',revocation_epoch=revocation_epoch+1,anchor_nonce=? "
                "WHERE namespace=? AND holder=? AND generation=? "
                "AND phase='recovering' AND transfer_id=? AND target=? "
                "AND anchor_nonce=?",
                (self.core._new_nonce(), self.namespace, permit.holder,
                 permit.generation, permit.transfer_id, plan.target_holder,
                 row[13])).rowcount
            if changed != 1:
                raise AuthorityUnavailable("source revocation CAS failed")
            after = self.core._anchor(
                db, self.namespace, self.core._row(db, self.namespace))
            receipt = MigrationStageReceiptV2(
                permit.transfer_id, "revoked", request_id, digest, after)
            self.store.advance_locked(
                db, transfer_id=permit.transfer_id, old_phase="begun",
                receipt=receipt, source_snapshot=snapshot)
            from .migration_snapshot_certificate_members_v1 import persist_snapshot_certificate_members_in_tx_v1
            persist_snapshot_certificate_members_in_tx_v1(
                self.core, db, verified, self._source_verifier, snapshot, plan, permit)
            self.core._event(db, self.namespace, "v2_source_revoked",
                             after.activation_generation,
                             (permit.transfer_id, request_id, digest))
            return receipt, self._status_locked(
                db, deletion_head, execution_head, permit.transfer_id)

    def prepare_target(self, *, credential, subject: str,
                       transfer_id: str, request_id: str
                       ) -> tuple[MigrationStageReceiptV2, MigrationStatusV2]:
        identifier(subject, "subject")
        identifier(transfer_id, "transfer_id")
        identifier(request_id, "request_id")
        self._require(credential, "migration_prepare_target", None)
        status, replay = self._lookup(
            transfer_id, "target_prepared", request_id,
            _request_digest((transfer_id, subject)))
        if status is None:
            raise AuthorityUnavailable("transfer is absent")
        self._require(credential, "migration_prepare_target",
                      status.plan.target_holder)
        digest = _request_digest((transfer_id, subject))
        if replay is not None:
            return replay, status
        if status.phase != "revoked":
            raise AuthorityUnavailable("source is not revoked")
        self._verify_pairing(credential, subject, status.plan, "prepare_target")
        with self.fences._frozen() as (db, deletion_head, execution_head, _):
            status, replay = self._lookup_locked(
                db, deletion_head, execution_head, transfer_id,
                "target_prepared", request_id, digest)
            if replay is not None:
                return replay, status
            if status is None or status.phase != "revoked":
                raise AuthorityUnavailable("source is not revoked")
            AuthorityV2FenceStore.require_idle_migration_in_tx(db, self.namespace)
            plan = status.plan
            row = self.core._row(db, self.namespace)
            changed = db.execute(
                "UPDATE authority_namespaces SET holder=?,generation=generation+1,"
                "phase='recovering',anchor_nonce=? "
                "WHERE namespace=? AND holder IS NULL AND generation=? "
                "AND phase='revoked' AND transfer_id=? AND target=? "
                "AND anchor_nonce=?",
                (plan.target_holder, self.core._new_nonce(), self.namespace,
                 plan.before_anchor.activation_generation + 1,
                 transfer_id, plan.target_holder, row[13])).rowcount
            if changed != 1:
                raise AuthorityUnavailable("target preparation CAS failed")
            after = self.core._anchor(
                db, self.namespace, self.core._row(db, self.namespace))
            permit = MigrationPermitV2(
                transfer_id, self.namespace, "target_recovery",
                plan.target_holder, plan.target_installation_id,
                after.activation_generation, secrets.token_urlsafe(48), after)
            receipt = MigrationStageReceiptV2(
                transfer_id, "target_prepared", request_id, digest,
                after, permit)
            self.store.advance_locked(
                db, transfer_id=transfer_id, old_phase="revoked",
                receipt=receipt, target_permit=permit)
            self.core._event(db, self.namespace, "v2_target_prepared",
                             after.activation_generation,
                             (transfer_id, request_id, digest))
            return receipt, self._status_locked(
                db, deletion_head, execution_head, transfer_id)

    def activate_target(self, *, credential, subject: str,
                        permit: MigrationPermitV2,
                        recovery: TargetRecoveryReceiptV2,
                        request_id: str
                        ) -> tuple[MigrationStageReceiptV2, MigrationStatusV2]:
        identifier(subject, "subject")
        identifier(request_id, "request_id")
        if (type(permit) is not MigrationPermitV2
                or type(recovery) is not TargetRecoveryReceiptV2
                or permit.namespace != self.namespace
                or recovery.namespace != self.namespace
                or recovery.transfer_id != permit.transfer_id):
            raise AuthorityUnavailable("typed target recovery and permit required")
        self._require(credential, "migration_activate", permit.holder)
        digest = _request_digest((permit, recovery, subject))
        status, replay = self._lookup(
            permit.transfer_id, "activated", request_id, digest)
        if replay is not None:
            return replay, status
        if status is None or status.phase != "target_prepared":
            raise AuthorityUnavailable("target is not prepared")
        plan = status.plan
        if (permit != status.target_permit
                or recovery.permit_token != permit.token
                or recovery.target_installation_id != plan.target_installation_id
                or recovery.target_generation != permit.generation
                or recovery.snapshot_digest != status.source_snapshot.snapshot_digest
                or recovery.new_graph_incarnation
                   == status.source_snapshot.graph_incarnation
                or not _requirements_match(
                    recovery.current_requirements, status.current_anchor, plan)):
            raise AuthorityUnavailable("target graph recovery identity differs")
        self._verify_pairing(credential, subject, plan, "activate_target")
        holder = self._target_holder
        if holder is None:
            raise AuthorityUnavailable("trusted target graph hold is unavailable")
        with self.fences._frozen() as (db, _, _, _):
            owner_head_before = self._owner_head_locked(db)
        try:
            held_context = holder.hold(recovery, plan, permit)
        except Exception as exc:
            raise AuthorityUnavailable("target graph hold construction failed") from exc
        from .installed_migration_target_verifier import TargetGraphHeldProofV1

        with held_context as held:
            if (type(held) is not TargetGraphHeldProofV1
                    or (held.transfer_id, held.target_installation_id,
                        held.permit_token, held.snapshot_digest,
                        held.graph_commit_digest, held.target_generation,
                        held.new_graph_incarnation)
                    != (recovery.transfer_id, recovery.target_installation_id,
                        recovery.permit_token, recovery.snapshot_digest,
                        recovery.graph_commit_digest, recovery.target_generation,
                        recovery.new_graph_incarnation)):
                raise AuthorityUnavailable("target graph held proof identity differs")
            with self.fences._frozen() as (db, deletion_head, execution_head,
                                         deletion_history):
                status, replay = self._lookup_locked(
                    db, deletion_head, execution_head, permit.transfer_id,
                    "activated", request_id, digest)
                if replay is not None:
                    return replay, status
                if (status is None or status.phase != "target_prepared"
                        or status.target_permit != permit
                        or deletion_history
                        or not _requirements_match(
                            recovery.current_requirements,
                            status.current_anchor, status.plan)):
                    raise AuthorityUnavailable("target recovery state or journals changed")
                if self._owner_head_locked(db) != owner_head_before:
                    raise AuthorityUnavailable("Owner head changed during target verification")
                AuthorityV2FenceStore.require_idle_migration_in_tx(db, self.namespace)
                holder.require_current_reconciliation_in_tx(
                    db, held, execution_head, deletion_head)
                row = self.core._row(db, self.namespace)
                changed = db.execute(
                    "UPDATE authority_namespaces SET phase='active',"
                    "transfer_id=NULL,target=NULL,anchor_nonce=? "
                    "WHERE namespace=? AND holder=? AND generation=? "
                    "AND phase='recovering' AND transfer_id=? AND target=? "
                    "AND anchor_nonce=?",
                    (self.core._new_nonce(), self.namespace, plan.target_holder,
                     permit.generation, permit.transfer_id,
                     plan.target_holder, row[13])).rowcount
                if changed != 1:
                    raise AuthorityUnavailable("target activation CAS failed")
                after = self.core._anchor(
                    db, self.namespace, self.core._row(db, self.namespace))
                receipt = MigrationStageReceiptV2(
                    permit.transfer_id, "activated", request_id, digest, after)
                self.store.advance_locked(
                    db, transfer_id=permit.transfer_id,
                    old_phase="target_prepared", receipt=receipt,
                    target_recovery=recovery)
                if held.certificate_member_set_digest is not None:
                    from .migration_snapshot_certificate_members_v1 import persist_activation_certificate_members_in_tx_v1
                    persist_activation_certificate_members_in_tx_v1(
                        self.core, db, status, held, permit, recovery, receipt)
                self.core._event(db, self.namespace, "v2_target_activated",
                                 after.activation_generation,
                                 (permit.transfer_id, request_id, digest))
                return receipt, self._status_locked(
                    db, deletion_head, execution_head, permit.transfer_id)

    def recover_transfer(self, *, credential, subject: str,
                         transfer_id: str) -> MigrationRecoveryV2:
        """Authenticated, read-only stage discovery after a lost response."""
        identifier(subject, "subject")
        identifier(transfer_id, "transfer_id")
        self._require(credential, "migration_recover", None)
        with self.fences._frozen() as (db, deletion_head, execution_head,
                                     deletion_history):
            self.fences._require_mode(db)
            self.fences.fences._check_schema(db)
            history = self.store.status_locked(db, transfer_id)
            if history is None or history.plan.namespace != self.namespace:
                raise AuthorityUnavailable("transfer is absent")
            current = self._current_namespace_locked(
                db, deletion_head, execution_head, deletion_history)
            owner_head = self._owner_head_locked(db)
            return MigrationRecoveryV2(history, current, owner_head)


__all__ = ["AuthorityV2MigrationService"]
