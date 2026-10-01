"""Pinned Authority read of the one live deletion-pending original for Graph CAS."""

from __future__ import annotations

from dataclasses import replace

from .contract import AuthorityUnavailable, identifier
from .v2_contract import DeletionMutationReceiptV1, FencePermitV2
from .v2_fence_service import AuthorityV2FenceService
from .v2_fence_store import AuthorityV2FenceStore
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore


class AuthorityV2DeletionGraphReadService:
    """Return a durable pending receipt only under its updated live delete fence."""

    def __init__(self, *, fence_service: AuthorityV2FenceService,
                 owner_tickets: AuthorityV2OwnerTicketStore):
        if (type(fence_service) is not AuthorityV2FenceService
                or type(owner_tickets) is not AuthorityV2OwnerTicketStore
                or owner_tickets._core is not fence_service.core):
            raise TypeError("paired deletion fence and Owner ledger are required")
        self._service = fence_service
        self._owner_tickets = owner_tickets

    def get_pending_deletion_for_graph_write(
        self, *, credential: object, subject: str, installation_id: str,
        deletion_operation_id: str, permit: FencePermitV2,
    ) -> DeletionMutationReceiptV1:
        identifier(subject, "subject")
        identifier(installation_id, "installation_id")
        identifier(deletion_operation_id, "deletion_operation_id")
        service = self._service
        if (type(permit) is not FencePermitV2 or permit.operation != "delete"
                or permit.namespace != service.namespace or permit.subject != subject):
            raise AuthorityUnavailable("live delete fence identity required")
        service.core._require(credential, "delete", service.namespace, permit.holder)
        with service._frozen() as (db, deletion_head, execution_head, _):
            current = service._current_locked(
                db, deletion_head, execution_head, holder=permit.holder,
                generation=permit.generation, require_clear=False)
            if db.execute(
                    "SELECT deletion_phase FROM authority_namespaces WHERE namespace=?",
                    (service.namespace,)).fetchone() != ("pending",):
                raise AuthorityUnavailable("deletion is not at the pending barrier")
            service.fences.validate_fence_locked(
                db, permit, subject=subject, current_anchor=current)
            owner = self._owner_tickets.current_migration_head_in_tx(
                db, authority_namespace=service.namespace)
            if (owner is None or owner.state != "active"
                    or owner.issue_operation.installation_id != installation_id):
                raise AuthorityUnavailable("current Owner authorization is unavailable")
            tail = service.deletion._db.execute(
                "SELECT mutation_id,operation_id,phase FROM authority_deletion_v2_tail "
                "WHERE seq=?", (deletion_head.seq,)).fetchone()
            if (tail is None or tail[1:] != (deletion_operation_id, "pending")):
                raise AuthorityUnavailable("current deletion journal head differs")
            row = service.fences.mutation_locked(db, tail[0])
            if row is None:
                raise AuthorityUnavailable("deletion original is absent")
            kind, pending, receipt, updated = AuthorityV2FenceStore._decode_mutation_row(row)
            if (kind != "deletion" or row[4] != "committed"
                    or type(receipt) is not DeletionMutationReceiptV1
                    or pending != receipt.pending
                    or pending.source_phase != "absent"
                    or pending.target_phase != "pending"
                    or pending.evidence.issuer_id != "authority-owner-graph-plan-v2"
                    or pending.deletion_operation_id != deletion_operation_id
                    or pending.permit.operation_id != permit.operation_id
                    or pending.permit.token != permit.token
                    or pending.permit.subject != subject
                    or updated != permit
                    or replace(pending.permit, revision=receipt.updated_revision,
                               pinned_anchor=receipt.after_anchor) != permit
                    or receipt.after_anchor != current
                    or service.deletion._inspect_pending_locked(pending) is None):
                raise AuthorityUnavailable("current deletion receipt differs from original")
            return receipt


__all__ = ["AuthorityV2DeletionGraphReadService"]
