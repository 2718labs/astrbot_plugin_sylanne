"""Durable host ownership state for one original private ingress operation.

Only GraphCoordinator may issue these receipts.  A ready value is a hint to
the original handler, never authority to send a platform message.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..runtime_contracts import NamespaceId


@dataclass(frozen=True, slots=True)
class ReplyOwnershipReceiptV1:
    namespace: NamespaceId
    ingress_operation_id: str
    handler_invocation_id: str
    state: str
    reply_operation_id: str | None
    effect_id: str | None
    admission_ref: str | None
    admission_digest: str | None
    installation_id: str | None
    account_ref: str | None
    destination_ref: str | None
    handler_deadline_utc: float | None
    ack_digest: str | None


__all__ = ("ReplyOwnershipReceiptV1",)
