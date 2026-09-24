"""Versioned request and result for Owner-qualified terminal model reads.

These DTOs carry identity, not authority. The bearer session, transport
credential, read fence, and graph check are verified by the service.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..runtime_contracts import NamespaceId
from .contract import identifier
from .v2_model_egress_contract import ModelEgressObservationV1, ModelTerminalReceiptV2
from .v2_owner_session import OwnerSessionLoginRequestV1


SCHEMA = "sylanne3.authority.model_result_read.v1"
_PURPOSES = frozenset({"context", "expression", "consolidation", "audit"})


@dataclass(frozen=True, slots=True)
class ModelResultReadRequestV1:
    authority_id: str
    authority_namespace: str
    namespace: NamespaceId
    installation_id: str
    owner_actor_id: str
    owner_session_request: OwnerSessionLoginRequestV1
    purpose: str  # Owner grant purpose: workbench_view
    source_purpose: str  # D06 source/access purpose
    audience: tuple[str, ...]
    call_id: str
    read_operation_id: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise ValueError("unknown model result read schema")
        for name in ("authority_id", "authority_namespace", "installation_id",
                     "owner_actor_id", "call_id", "read_operation_id"):
            identifier(getattr(self, name), name)
        if type(self.namespace) is not NamespaceId:
            raise TypeError("typed business namespace required")
        session = self.owner_session_request
        if (type(session) is not OwnerSessionLoginRequestV1
                or (session.authority_id, session.authority_namespace,
                    session.installation_id, session.audience) !=
                   (self.authority_id, self.authority_namespace,
                    self.installation_id, "owner")):
            raise ValueError("Owner session identity differs from read request")
        if self.purpose != "workbench_view" or type(self.purpose) is not str:
            raise ValueError("result read requires the Owner view purpose")
        if type(self.source_purpose) is not str or self.source_purpose not in _PURPOSES:
            raise ValueError("unsupported source access purpose")
        if (type(self.audience) is not tuple or not self.audience
                or any(type(item) is not str or not item or item == "*"
                       for item in self.audience)
                or self.audience != tuple(sorted(set(self.audience)))):
            raise ValueError("result read audience must be a sorted nonempty set")


@dataclass(frozen=True, slots=True)
class ModelResultReadV1:
    call_id: str
    observation: ModelEgressObservationV1
    terminal_receipt: ModelTerminalReceiptV2
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA or type(self.observation) is not ModelEgressObservationV1
                or type(self.terminal_receipt) is not ModelTerminalReceiptV2
                or self.observation.status != "completed"
                or self.call_id != self.observation.call_id
                or self.terminal_receipt.call_id != self.call_id
                or self.terminal_receipt.request_digest != self.observation.request_digest
                or self.terminal_receipt.observation_digest != self.observation.digest):
            raise ValueError("completed original observation required")


__all__ = ("ModelResultReadRequestV1", "ModelResultReadV1")
