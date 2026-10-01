"""Installed, fail-closed transfer verifier for an isolated graph target.

The Authority service is the trust root: its authenticated recovery read freezes
both independent journals and reads the durable transfer history.  The target
requirements are administrator-installed facts, never taken from the import
caller or from the graph snapshot being imported.
"""

from __future__ import annotations

from threading import RLock

from ..authority_service.v2_migration_contract import MigrationPermitV2
from ..authority_service.v2_migration_service import AuthorityV2MigrationService
from ..graph_store import (GraphMigrationVerifiedTransferV1,
                           GraphRecoveryMetadataV2)
from ..runtime_contracts import (NamespaceRuntimeState, SnapshotRequirementsV2)
from .graph_migration_snapshot_v1 import FORMAT


class InstalledGraphMigrationTransferVerifierV2:
    """Bind a GraphStore constructor to one installed Authority and target.

    ``credential`` and ``subject`` are installation-owned management identity;
    callers of ``prepare`` provide a target permit for comparison. It returns an
    opaque process-local handle for the short graph transaction. ``verify_local``
    performs no Authority or journal I/O while the graph lock is held.
    The service must have real journal adapters and a source graph verifier
    installed, as required by its revoke transition.  No file path or claimed
    verification bit is accepted at this boundary.
    """

    def __init__(self, *, authority: AuthorityV2MigrationService,
                 credential: object, subject: str,
                 target_installation_id: str,
                 target_requirements: SnapshotRequirementsV2):
        if (type(authority) is not AuthorityV2MigrationService
                or type(subject) is not str or not subject
                or type(target_installation_id) is not str
                or not target_installation_id
                or type(target_requirements) is not SnapshotRequirementsV2
                or target_requirements.authority_namespace != authority.namespace):
            raise ValueError("installed Authority and target identity required")
        self._authority = authority
        self._credential = credential
        self._subject = subject
        self._target_installation_id = target_installation_id
        self._target_requirements = target_requirements
        self._lock = RLock()
        self._prepared: tuple[object, MigrationPermitV2,
                              GraphMigrationVerifiedTransferV1] | None = None

    def prepare(self, transfer_receipt: object) -> object:
        """Check Authority and both journals before entering the graph transaction.

        A later independent head cannot be reconciled by this implementation;
        prepare then raises and the target remains recovering. Activation must
        separately recheck the latest Authority and journal state.
        """
        with self._lock:
            self._prepared = None
        if (type(transfer_receipt) is not MigrationPermitV2
                or transfer_receipt.kind != "target_recovery"
                or transfer_receipt.namespace != self._authority.namespace
                or transfer_receipt.installation_id
                   != self._target_installation_id):
            raise PermissionError("target recovery permit is required")

        # This is an authenticated read of durable Authority state and current
        # independent journal heads, not a replay of a caller-supplied DTO.
        recovery = self._authority.recover_transfer(
            credential=self._credential, subject=self._subject,
            transfer_id=transfer_receipt.transfer_id)
        status, current = recovery.history, recovery.current
        plan, source = status.plan, status.source_snapshot
        target = self._target_requirements
        if (status.phase != "target_prepared"
                or plan.transfer_id != transfer_receipt.transfer_id
                or plan.namespace != self._authority.namespace
                or plan.namespace_id != target.namespace
                or plan.target_installation_id != self._target_installation_id
                or status.target_permit != transfer_receipt
                or status.target_recovery is not None
                or source is None
                or source.transfer_id != plan.transfer_id
                or source.namespace != plan.namespace
                or source.source_installation_id != plan.source_installation_id
                or source.permit_token != status.source_permit.token
                or source.snapshot_format != FORMAT
                or source.requirements.namespace != plan.namespace_id
                or source.requirements.graph_incarnation
                   != source.graph_incarnation
                or source.graph_incarnation == target.graph_incarnation
                or len(status.receipts) != 3
                or tuple(item.phase for item in status.receipts)
                   != ("begun", "revoked", "target_prepared")
                or any(item.transfer_id != plan.transfer_id
                       for item in status.receipts)
                or status.receipts[0].permit != status.source_permit
                or status.receipts[2].permit != status.target_permit
                or current.namespace != plan.namespace
                or current.transfer_id != plan.transfer_id
                or current.phase != "recovering"
                or current.holder != plan.target_holder
                or current.target != plan.target_holder
                or current.generation != transfer_receipt.generation
                or current.state is not NamespaceRuntimeState.RECOVERING
                or current.blockers != ("activation_unsettled",)
                or current.anchor != status.current_anchor
                or current.anchor != transfer_receipt.pinned_anchor
                or status.receipts[2].after_anchor != current.anchor):
            raise PermissionError("Authority transfer or current journal state is not ready")

        source_anchor = status.receipts[0].after_anchor
        if (source.requirements.activation_generation
                != plan.before_anchor.activation_generation
                or not _requirements_match_anchor(source.requirements,
                                                  source_anchor)
                or not _requirements_match_anchor(target, current.anchor)
                or target.activation_generation
                   != source.requirements.activation_generation + 2
                or target.revocation_epoch
                   != source.requirements.revocation_epoch + 1
                or (target.authority_id, target.authority_namespace,
                    target.deletion_journal_id, target.execution_journal_id)
                   != (source.requirements.authority_id,
                       source.requirements.authority_namespace,
                       source.requirements.deletion_journal_id,
                       source.requirements.execution_journal_id)
                # The current source snapshot and target heads must still be
                # identical. A later head needs a trusted prefix/merge proof;
                # this verifier cannot invent that missing production read.
                or (target.deletion_seq, target.deletion_digest)
                   != (source.requirements.deletion_seq,
                       source.requirements.deletion_digest)
                or (target.execution_seq, target.execution_digest)
                   != (source.requirements.execution_seq,
                       source.requirements.execution_digest)):
            raise PermissionError("source or target requirements differ from Authority")

        proof = GraphMigrationVerifiedTransferV1(
            plan.transfer_id,
            GraphRecoveryMetadataV2(source.requirements, source.graph_revision),
            target, "target_recovering", source.snapshot_digest,
            recovery.owner_head)
        handle = object()
        with self._lock:
            # A new preparation invalidates an older local comparison result.
            self._prepared = (handle, transfer_receipt, proof)
        return handle

    def verify_local(self, transfer_receipt: object
                     ) -> GraphMigrationVerifiedTransferV1:
        """Compare only the exact prepared handle inside the graph transaction."""
        with self._lock:
            prepared = self._prepared
            if prepared is None or transfer_receipt is not prepared[0]:
                raise PermissionError("unprepared migration transfer")
            _, permit, proof = prepared
            if (permit.kind != "target_recovery"
                    or permit.transfer_id != proof.transfer_id
                    or permit.installation_id != self._target_installation_id
                    or permit.namespace != self._authority.namespace
                    or proof.target != self._target_requirements
                    or proof.source_snapshot_digest == ""):
                raise PermissionError("prepared migration transfer changed")
            return proof

    def discard(self, transfer_receipt: object) -> None:
        """Remove a local handle after COMMIT or ROLLBACK."""
        with self._lock:
            if self._prepared is not None and transfer_receipt is self._prepared[0]:
                self._prepared = None


def _requirements_match_anchor(requirements: SnapshotRequirementsV2,
                               anchor: object) -> bool:
    return (requirements.authority_id == anchor.authority_id
            and requirements.authority_namespace == anchor.namespace
            and requirements.activation_generation == anchor.activation_generation
            and requirements.deletion_journal_id == anchor.deletion_journal_id
            and requirements.deletion_seq == anchor.deletion_seq
            and requirements.deletion_digest == anchor.deletion_digest
            and requirements.execution_journal_id == anchor.execution_journal_id
            and requirements.execution_seq == anchor.execution_seq
            and requirements.execution_digest == anchor.execution_digest
            and requirements.revocation_epoch == anchor.revocation_epoch)


__all__ = ["InstalledGraphMigrationTransferVerifierV2"]
