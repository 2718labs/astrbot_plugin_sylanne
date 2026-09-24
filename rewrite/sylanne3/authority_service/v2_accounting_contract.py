"""Content-free, versioned maintenance fence for an already observed model call.

This grant only serializes a later D11 accounting transaction. It does not
attest a current business reservation or grant a provider/content operation.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..runtime.restore_anchor import RestoreAnchor
from .contract import identifier
from .v2_contract import FencePermitV2
from .v2_model_egress_contract import ModelEgressIntentV1


@dataclass(frozen=True, slots=True)
class AccountingMaintenanceRequestV1:
    operation_id: str
    intent: ModelEgressIntentV1
    expected_anchor: RestoreAnchor
    schema: str = "sylanne3.authority.accounting-maintenance.v1"

    def __post_init__(self) -> None:
        identifier(self.operation_id, "operation_id")
        if (type(self.intent) is not ModelEgressIntentV1
                or type(self.expected_anchor) is not RestoreAnchor
                or self.expected_anchor.authority_id != self.intent.authority_id
                or self.expected_anchor.namespace != self.intent.namespace
                or self.schema != "sylanne3.authority.accounting-maintenance.v1"
                or self.operation_id == self.intent.operation_id):
            raise ValueError("invalid original accounting maintenance request")


@dataclass(frozen=True, slots=True)
class AccountingMaintenanceGrantV1:
    permit: FencePermitV2
    call_id: str
    admission_id: str
    reservation_digest: str
    observation_digest: str
    terminal_receipt_digest: str
    schema: str = "sylanne3.authority.accounting-grant.v1"

    def __post_init__(self) -> None:
        from .v2_model_egress_contract import _digest

        if type(self.permit) is not FencePermitV2 or self.permit.operation != "accounting":
            raise ValueError("accounting permit required")
        identifier(self.call_id, "call_id")
        for name in ("admission_id", "observation_digest", "terminal_receipt_digest"):
            _digest(getattr(self, name), name)
        _digest(self.reservation_digest, "reservation_digest")
        if self.schema != "sylanne3.authority.accounting-grant.v1":
            raise ValueError("unknown accounting grant schema")


__all__ = ("AccountingMaintenanceRequestV1", "AccountingMaintenanceGrantV1")
