"""Pinned, read-only Authority original for an active accepted erasure.

This proves the Authority accepted phase, not Graph cleanup or safe reopening.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .contract import AuthorityUnavailable, identifier
from .current_erasure_service import CurrentErasureAuthority
from .v2_contract import (
    DeletionMutationReceiptV1, FencePermitV2, deletion_scope_digest,
)
from .v2_fence_service import AuthorityV2FenceService
from .v2_fence_store import AuthorityV2FenceStore
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from .v2_scoped_erasure_store import AuthorityV2ScopedErasureStore


@dataclass(frozen=True, slots=True)
class CurrentAcceptedErasureV1:
    namespace: str
    deletion_operation_id: str
    pending_receipt: DeletionMutationReceiptV1
    accepted_receipt: DeletionMutationReceiptV1
    permit: FencePermitV2
    closure_roots: tuple[str, ...]
    deletion_epoch: int
    scope_digest: str
    graph_barrier_digest: str
    schema: str = "sylanne3.authority.current-accepted-erasure.v1"

    def __post_init__(self) -> None:
        identifier(self.namespace, "namespace")
        identifier(self.deletion_operation_id, "deletion_operation_id")
        if (type(self.pending_receipt) is not DeletionMutationReceiptV1
                or type(self.accepted_receipt) is not DeletionMutationReceiptV1
                or type(self.permit) is not FencePermitV2):
            raise ValueError("typed accepted erasure originals required")
        original = self.pending_receipt.pending
        accepted = self.accepted_receipt.pending
        if (self.schema != "sylanne3.authority.current-accepted-erasure.v1"
                or original.source_phase != "absent"
                or original.target_phase != "pending"
                or accepted.source_phase != "pending"
                or accepted.target_phase != "accepted"
                or original.deletion_operation_id != self.deletion_operation_id
                or accepted.deletion_operation_id != self.deletion_operation_id
                or original.permit.namespace != self.namespace
                or accepted.permit.namespace != self.namespace
                or original.closure_roots != self.closure_roots
                or accepted.closure_roots != self.closure_roots
                or original.deletion_epoch != self.deletion_epoch
                or accepted.deletion_epoch != self.deletion_epoch
                or original.evidence.scope_digest != self.scope_digest
                or accepted.evidence.scope_digest != self.scope_digest
                or accepted.evidence.proof_digest != self.graph_barrier_digest
                or accepted.before_anchor != self.pending_receipt.after_anchor
                or self.permit.pinned_anchor != self.accepted_receipt.after_anchor):
            raise ValueError("accepted erasure read identity differs")


class CurrentAcceptedErasureReadService:
    """Read two immutable deletion originals under the live Owner fence."""

    def __init__(self, *, fence_service: AuthorityV2FenceService,
                 owner_tickets: AuthorityV2OwnerTicketStore,
                 scoped_store: AuthorityV2ScopedErasureStore):
        if (type(fence_service) is not AuthorityV2FenceService
                or type(owner_tickets) is not AuthorityV2OwnerTicketStore
                or type(scoped_store) is not AuthorityV2ScopedErasureStore
                or owner_tickets._core is not fence_service.core
                or scoped_store.core is not fence_service.core
                or scoped_store.fences is not fence_service.fences
                or scoped_store.deletion is not fence_service.deletion
                or scoped_store.execution is not fence_service.execution
                or scoped_store.namespace != fence_service.namespace):
            raise TypeError("paired scoped erasure Authority is required")
        self._service = fence_service
        self._owner_tickets = owner_tickets
        self._scoped = scoped_store

    def read_current_accepted_erasure_v1(
        self, *, credential: object, subject: str, installation_id: str,
        deletion_operation_id: str, scope_digest: str, permit: FencePermitV2,
    ) -> CurrentAcceptedErasureV1:
        identifier(subject, "subject")
        identifier(installation_id, "installation_id")
        identifier(deletion_operation_id, "deletion_operation_id")
        service = self._service
        if (type(scope_digest) is not str or len(scope_digest) != 71
                or not scope_digest.startswith("sha256:")
                or any(c not in "0123456789abcdef" for c in scope_digest[7:])
                or type(permit) is not FencePermitV2
                or permit.operation != "delete"
                or permit.namespace != service.namespace
                or permit.subject != subject):
            raise AuthorityUnavailable("live scoped delete identity required")
        service.core._require(credential, "delete", service.namespace, permit.holder)
        with service._frozen() as (db, deletion_head, execution_head, _):
            current = service._current_locked(
                db, deletion_head, execution_head, holder=permit.holder,
                generation=permit.generation, require_clear=False)
            return read_current_accepted_erasure_in_tx_v1(
                db, deletion=service.deletion, fences=service.fences,
                namespace=service.namespace, subject=subject, installation_id=installation_id,
                deletion_operation_id=deletion_operation_id, scope_digest=scope_digest,
                permit=permit, current=current)


__all__ = ["CurrentAcceptedErasureV1", "CurrentAcceptedErasureReadService"]


def read_current_accepted_erasure_in_tx_v1(
        db, *, deletion, fences, namespace, subject, installation_id,
        deletion_operation_id, scope_digest, permit, current):
    """Read real Owner, scoped, mutation and deletion rows in one pinned snapshot."""
    from .v2_owner_ticket_store import read_owner_migration_head_in_tx_v1
    from .v2_scoped_erasure_store import read_scoped_erasure_state_in_tx_v1
    from .v2_deletion_guard import AuthorityV2DeletionGuard
    from .c09_connection_state_v1 import anchor_in_tx_v1
    if (not db.in_transaction or type(deletion) is not AuthorityV2DeletionGuard
            or type(fences) is not AuthorityV2FenceStore
            or fences._db is not db or not deletion._db.in_transaction
            or current != anchor_in_tx_v1(db, namespace)):
        raise AuthorityUnavailable("accepted erasure needs real pinned maintenance connections")
    deletion_head = deletion.verified_head()
    if (current != permit.pinned_anchor or db.execute(
            "SELECT deletion_phase FROM authority_namespaces WHERE namespace=?",
            (namespace,)).fetchone() != ("accepted",)):
        raise AuthorityUnavailable("current accepted Core anchor required")
    fences.validate_fence_locked(
        db, permit, subject=subject, current_anchor=current)
    owner = read_owner_migration_head_in_tx_v1(
        db, authority_namespace=namespace)
    if (owner is None or owner.state != "active"
            or owner.issue_operation.installation_id != installation_id):
        raise AuthorityUnavailable("current Owner authorization unavailable")
    state = read_scoped_erasure_state_in_tx_v1(db, namespace=namespace)
    if (state.aggregate_phase != "accepted"
            or state.active_operation_id != deletion_operation_id
            or state.closed_seq is not None):
        raise AuthorityUnavailable("current scoped accepted operation differs")
    tail = deletion._db.execute(
        "SELECT mutation_id,operation_id,phase FROM authority_deletion_v2_tail "
        "WHERE seq=?", (deletion_head.seq,)).fetchone()
    accepted_id = CurrentErasureAuthority._protocol_id(
        namespace, deletion_operation_id, "accepted-mutation")
    pending_id = CurrentErasureAuthority._protocol_id(
        namespace, deletion_operation_id, "mutation")
    if tail != (accepted_id, deletion_operation_id, "accepted"):
        raise AuthorityUnavailable("accepted deletion journal head differs")
    rows = (fences.mutation_locked(db, pending_id),
            fences.mutation_locked(db, accepted_id))
    if any(row is None or row[4] != "committed" for row in rows):
        raise AuthorityUnavailable("committed deletion originals absent")
    decoded = tuple(AuthorityV2FenceStore._decode_mutation_row(row)
                    for row in rows)
    (pending_kind, pending, pending_receipt, pending_permit), (
        accepted_kind, accepted, accepted_receipt, updated) = decoded
    prior_append = deletion._db.execute(
        "SELECT mutation_id,operation_id,phase,prev_digest,chain_digest "
        "FROM authority_deletion_v2_tail WHERE seq=?",
        (pending.expected_deletion_seq,)).fetchone()
    if (pending_kind != "deletion" or accepted_kind != "deletion"
            or type(pending_receipt) is not DeletionMutationReceiptV1
            or type(accepted_receipt) is not DeletionMutationReceiptV1
            or pending_receipt.pending != pending
            or accepted_receipt.pending != accepted
            or pending.source_phase != "absent" or pending.target_phase != "pending"
            or accepted.source_phase != "pending"
            or accepted.target_phase != "accepted"
            or pending.evidence.issuer_id != "authority-owner-graph-plan-v2"
            or accepted.evidence.issuer_id != "authority-pinned-graph-barrier-v1"
            or pending.deletion_operation_id != deletion_operation_id
            or accepted.deletion_operation_id != deletion_operation_id
            or pending.request_digest != accepted.request_digest
            or pending.closure_roots != accepted.closure_roots
            or pending.deletion_epoch != accepted.deletion_epoch
            or pending.policy_ref != accepted.policy_ref
            or state.active_epoch != accepted.deletion_epoch
            or pending.evidence.scope_digest != scope_digest
            or accepted.evidence.scope_digest != scope_digest
            or scope_digest != deletion_scope_digest(
                pending.closure_roots, pending.deletion_epoch, pending.policy_ref)
            or accepted.before_anchor != pending_receipt.after_anchor
            or pending_permit != accepted.permit
            or accepted_receipt.after_anchor != current
            or updated != permit
            or replace(accepted.permit,
                       revision=accepted_receipt.updated_revision,
                       pinned_anchor=current) != permit
            or accepted.evidence.deletion_epoch != accepted.deletion_epoch
            or pending.expected_append_digest != deletion.expected_digest(pending)
            or prior_append != (
                pending_id, deletion_operation_id, "pending",
                pending.before_anchor.deletion_digest,
                pending.expected_append_digest)
            or deletion._inspect_pending_locked(accepted) is None):
        raise AuthorityUnavailable("current accepted original differs")
    return CurrentAcceptedErasureV1(
        namespace, deletion_operation_id, pending_receipt,
        accepted_receipt, permit, pending.closure_roots,
        pending.deletion_epoch, scope_digest,
        accepted.evidence.proof_digest)
