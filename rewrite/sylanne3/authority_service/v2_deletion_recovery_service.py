"""Internal recovery of durably prepared original v2 deletion phases.

This service cannot create a deletion request, append a journal event, or
issue phase evidence. A trusted Owner/D12 issuer, graph barrier verifier, and
cleanup verifier are required before a production caller may prepare phases.
"""

from __future__ import annotations

from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .v2_contract import DeletionMutationReceiptV1, DeletionPendingV1, canonical_bytes
from .v2_deletion_guard import AuthorityV2DeletionGuard
from .v2_execution_journal import AuthorityV2ExecutionJournal
from .v2_fence_store import AuthorityV2FenceStore


class AuthorityV2DeletionPendingRecovery:
    """Complete one exact prepared deletion phase already in Authority."""

    def __init__(self, *, core: AuthorityServiceCore,
                 fences: AuthorityV2FenceStore,
                 deletion: AuthorityV2DeletionGuard,
                 execution: AuthorityV2ExecutionJournal,
                 namespace: str, scoped_store=None):
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
        if scoped_store is not None:
            from .v2_scoped_erasure_store import AuthorityV2ScopedErasureStore

            if (type(scoped_store) is not AuthorityV2ScopedErasureStore
                    or scoped_store.core is not core
                    or scoped_store.fences is not fences
                    or scoped_store.deletion is not deletion
                    or scoped_store.execution is not execution
                    or scoped_store.namespace != namespace):
                raise AuthorityUnavailable("paired scoped deletion store required")
        self.scoped_store = scoped_store
        with core._tx() as db:
            self._require_mode(db)
            scoped_present = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='authority_scoped_erasure_v2'").fetchone() is not None
            if scoped_present != (scoped_store is not None):
                raise AuthorityUnavailable("scoped deletion recovery mode differs")
            if scoped_store is not None:
                from ..runtime_storage_v3 import PhysicalRuntimeHandleV3, runtime_storage_v3
                if type(runtime_storage_v3(db)) is not PhysicalRuntimeHandleV3:
                    scoped_store.state_locked(db, allow_reserved=True)

    def initialize_current_selected_state_v3(self):
        """Run the original state check only inside the actual actor's bound lease."""
        from ..runtime_storage_v3 import PhysicalRuntimeHandleV3, runtime_storage_v3
        handle=runtime_storage_v3(self.core._db)
        if type(handle) is not PhysicalRuntimeHandleV3:
            raise AuthorityUnavailable("actual selected maintenance physical state required")
        with handle.quantum(),self.core._tx() as db:
            from ..runtime_storage_v3 import require_maintenance_runtime_operation_v3
            require_maintenance_runtime_operation_v3(db)
            self._require_mode(db)
            self.scoped_store.state_locked(db,allow_reserved=True)

    @staticmethod
    def _require_mode(db):
        from .c09_graph_application_v1 import c09_actual_root_read_v3
        if c09_actual_root_read_v3(db).execute("SELECT value FROM authority_meta WHERE key='service_mode'").fetchone() != ("v2-only",):
            raise AuthorityUnavailable("deletion recovery requires persistent v2-only mode")
        AuthorityServiceCore._require_no_deletion_migration(c09_actual_root_read_v3(db))

    def recover(self, *, credential, subject: str,
                mutation_id: str, selected_proof=None) -> DeletionMutationReceiptV1 | None:
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
        phase_sources = {
            ("absent", "pending", "request_authorized"): "clear",
            ("pending", "accepted", "barrier_installed"): "pending",
            ("accepted", "closed", "cleanup_complete"): "accepted",
        }
        source_phase = phase_sources.get((pending.source_phase,
                                          pending.target_phase,
                                          pending.evidence.kind))
        if source_phase is None:
            raise AuthorityUnavailable("unknown deletion phase transition")

        # Fixed lock order. No credential verifier, graph callback or D12 issuer
        # is invoked while any journal guard or Authority transaction is held.
        with self.deletion.freeze_writes():
            with self.execution.freeze_writes():
                if selected_proof is None:
                    deletion_head = self.deletion.verified_head()
                    execution_head = self.execution.verified_head()
                else:
                    from .c09_graph_application_v1 import SelectedC09JournalProofV3
                    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
                    if type(selected_proof) is not SelectedC09JournalProofV3:
                        raise AuthorityUnavailable('actual private selected recovery journal proof required')
                    selected_proof.require_identity(deletion=self.deletion,execution=self.execution,core=self.core)
                    meter = current_c09_sql_meter_v2()
                    deletion_head = selected_proof.deletion_head_locked(self.deletion,meter=meter)
                    execution_head = selected_proof.execution_head_locked(self.execution,meter=meter)
                observed = self.deletion._inspect_pending_locked(pending,selected_proof=selected_proof)
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
                    self.fences.require_prior_deletion_transition_locked(db, pending, core=self.core,selected_proof=selected_proof)
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
                                or row[9] != (
                                    "accepted" if self.scoped_store is not None
                                    and pending.target_phase == "closed"
                                    else pending.target_phase)
                                or fence[10] is not None
                                or self.fences._permit(fence) != updated):
                            raise AuthorityUnavailable("completed deletion receipt differs from heads")
                        return receipt

                    if (self.core._anchor(db, self.namespace, row) != pending.before_anchor
                            or row[9] != source_phase
                            or self.fences._permit(fence) != permit
                            or fence[10] != canonical_bytes(pending)):
                        raise AuthorityUnavailable("original deletion pending anchor differs")
                    if observed is None:
                        return None

                    target_phase = (
                        self.scoped_store.transition_locked(db, pending)
                        if self.scoped_store is not None else pending.target_phase)
                    from ..runtime.c09_paged_sql_v2 import _capture_write_v2
                    changed = _capture_write_v2(db,
                        "UPDATE authority_namespaces SET deletion_seq=?,deletion_digest=?,"
                        "deletion_phase=?,revocation_epoch=?,anchor_nonce=? "
                        "WHERE namespace=? AND holder=? AND generation=? AND phase='active' "
                        "AND deletion_phase=? AND deletion_journal_id=? "
                        "AND deletion_seq=? AND deletion_digest=? AND execution_journal_id=? "
                        "AND execution_seq=? AND execution_digest=? AND revocation_epoch=? "
                        "AND anchor_nonce=?",
                        (pending.expected_deletion_seq, pending.expected_append_digest,
                         target_phase,
                         pending.before_anchor.revocation_epoch + 1,
                         self.core._new_nonce(), self.namespace, permit.holder,
                         permit.generation, source_phase,
                         pending.before_anchor.deletion_journal_id,
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
                        db, self.namespace, "v2_deletion_" + pending.target_phase,
                        permit.generation,
                        (pending.deletion_operation_id, pending.mutation_id,
                         pending.expected_append_id, pending.expected_append_digest))
                    return result


__all__ = ["AuthorityV2DeletionPendingRecovery"]
