"""Internal recovery of a durably prepared original v2 deletion intent.

This service cannot create a deletion request, append a journal event, or
advance accepted/closed. A trusted D12 issuer and prepare service are still
required before this recovery core can be used by a production caller.
"""

from __future__ import annotations

from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .v2_contract import DeletionMutationReceiptV1, DeletionPendingV1, canonical_bytes
from .v2_deletion_guard import AuthorityV2DeletionGuard
from .v2_execution_journal import AuthorityV2ExecutionJournal
from .v2_fence_store import AuthorityV2FenceStore


class AuthorityV2DeletionPendingRecovery:
    """Complete only the exact absent→pending mutation already in Authority."""

    def __init__(self, *, core: AuthorityServiceCore,
                 fences: AuthorityV2FenceStore,
                 deletion: AuthorityV2DeletionGuard,
                 execution: AuthorityV2ExecutionJournal,
                 namespace: str):
        identifier(namespace, "namespace")
        if (type(core) is not AuthorityServiceCore
                or type(fences) is not AuthorityV2FenceStore
                or type(deletion) is not AuthorityV2DeletionGuard
                or type(execution) is not AuthorityV2ExecutionJournal
                or core._db is not fences._db or core._lock is not fences._lock
                or execution.namespace != namespace):
            raise AuthorityUnavailable("deletion recovery requires one Authority DB and namespace")
        self.core, self.fences = core, fences
        self.deletion, self.execution = deletion, execution
        self.namespace = namespace
        with core._tx() as db:
            self._require_mode(db)

    @staticmethod
    def _require_mode(db):
        if db.execute("SELECT value FROM authority_meta WHERE key='service_mode'").fetchone() != ("v2-only",):
            raise AuthorityUnavailable("deletion recovery requires persistent v2-only mode")
        AuthorityServiceCore._require_no_deletion_migration(db)

    def recover(self, *, credential, subject: str,
                mutation_id: str) -> DeletionMutationReceiptV1 | None:
        """Return None while unappended; otherwise commit or read the one receipt.

        The subject and credential come from the trusted local caller. No RPC
        route is installed. The persisted mutation, not a supplied DTO, fixes
        the deletion operation, request, proof and expected journal append.
        """
        identifier(subject, "subject")
        identifier(mutation_id, "mutation_id")
        kind, pending, _, _ = self.fences.get_mutation(
            mutation_id, subject=subject, namespace=self.namespace)
        if kind != "deletion" or type(pending) is not DeletionPendingV1:
            raise AuthorityUnavailable("original deletion mutation required")
        permit = pending.permit
        self.core._require(credential, "deletion", self.namespace, permit.holder)
        if (pending.source_phase, pending.target_phase, pending.evidence.kind) != (
                "absent", "pending", "request_authorized"):
            raise AuthorityUnavailable("later deletion phases remain HOLD")

        # Fixed lock order. No credential verifier, graph callback or D12 issuer
        # is invoked while any journal guard or Authority transaction is held.
        with self.deletion.freeze_writes():
            with self.execution.freeze_writes():
                deletion_head = self.deletion.verified_head()
                execution_head = self.execution.verified_head()
                observed = self.deletion._inspect_pending_locked(pending)
                with self.core._tx() as db:
                    self._require_mode(db)
                    self.fences._check_schema(db)
                    self.fences._require_no_migration(db)
                    self.deletion.require_target_schema_locked(
                        db, authority_id=self.core._id(db),
                        namespace=self.namespace,
                        journal_id=deletion_head.journal_id)
                    mutation = self.fences.mutation_locked(db, mutation_id)
                    if mutation is None or mutation[1:3] != (self.namespace, subject):
                        raise AuthorityUnavailable("deletion mutation identity differs")
                    live_kind, live_pending, receipt, updated = (
                        self.fences._decode_mutation_row(mutation))
                    if live_kind != "deletion" or live_pending != pending:
                        raise AuthorityUnavailable("deletion mutation changed during recovery")
                    row = self.core._row(db, self.namespace)
                    fence = self.fences._row(db, permit.operation_id)
                    if (fence is None or fence[6] != "active"
                            or row[0] != permit.holder or row[1] != permit.generation
                            or row[2] != "active" or row[3] is not None
                            or row[4] is not None or row[10:13] != (
                                execution_head.journal_id, execution_head.seq,
                                execution_head.digest)
                            or (execution_head.journal_id, execution_head.seq,
                                execution_head.digest) != (
                                pending.before_anchor.execution_journal_id,
                                pending.before_anchor.execution_seq,
                                pending.before_anchor.execution_digest)):
                        raise AuthorityUnavailable("deletion owner or execution anchor differs")

                    if receipt is not None:
                        if (type(receipt) is not DeletionMutationReceiptV1
                                or updated is None
                                or observed is None
                                or deletion_head.seq != receipt.after_anchor.deletion_seq
                                or deletion_head.digest != receipt.after_anchor.deletion_digest
                                or self.core._anchor(db, self.namespace, row)
                                   != receipt.after_anchor
                                or row[9] != "pending"
                                or fence[10] is not None
                                or self.fences._permit(fence) != updated):
                            raise AuthorityUnavailable("completed deletion receipt differs from heads")
                        return receipt

                    if (self.core._anchor(db, self.namespace, row) != pending.before_anchor
                            or row[9] != "clear"
                            or self.fences._permit(fence) != permit
                            or fence[10] != canonical_bytes(pending)):
                        raise AuthorityUnavailable("original deletion pending anchor differs")
                    if observed is None:
                        return None

                    changed = db.execute(
                        "UPDATE authority_namespaces SET deletion_seq=?,deletion_digest=?,"
                        "deletion_phase='pending',revocation_epoch=?,anchor_nonce=? "
                        "WHERE namespace=? AND holder=? AND generation=? AND phase='active' "
                        "AND deletion_phase='clear' AND deletion_journal_id=? "
                        "AND deletion_seq=? AND deletion_digest=? AND execution_journal_id=? "
                        "AND execution_seq=? AND execution_digest=? AND revocation_epoch=? "
                        "AND anchor_nonce=?",
                        (pending.expected_deletion_seq, pending.expected_append_digest,
                         pending.before_anchor.revocation_epoch + 1,
                         self.core._new_nonce(), self.namespace, permit.holder,
                         permit.generation, pending.before_anchor.deletion_journal_id,
                         pending.before_anchor.deletion_seq,
                         pending.before_anchor.deletion_digest,
                         pending.before_anchor.execution_journal_id,
                         pending.before_anchor.execution_seq,
                         pending.before_anchor.execution_digest,
                         pending.before_anchor.revocation_epoch,
                         pending.before_anchor.proof)).rowcount
                    if changed != 1:
                        raise AuthorityUnavailable("deletion head CAS failed")
                    after = self.core._anchor(
                        db, self.namespace, self.core._row(db, self.namespace))
                    result = DeletionMutationReceiptV1(
                        pending, after, permit.revision + 1)
                    self.fences.finish_deletion_mutation_locked(
                        db, result, subject=subject)
                    self.core._event(
                        db, self.namespace, "v2_deletion_pending",
                        permit.generation,
                        (pending.deletion_operation_id, pending.mutation_id,
                         pending.expected_append_id, pending.expected_append_digest))
                    return result


__all__ = ["AuthorityV2DeletionPendingRecovery"]
