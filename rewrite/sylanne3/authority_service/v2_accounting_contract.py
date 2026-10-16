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


@dataclass(frozen=True, slots=True)
class ModelNoDispatchAccountingRequestV1:
    operation_id: str
    witness: object
    expected_anchor: RestoreAnchor
    schema: str = "sylanne3.authority.model-no-dispatch-accounting.v1"

    def __post_init__(self):
        from .v2_model_egress_contract import ModelNoDispatchWitnessV1
        if (self.schema != "sylanne3.authority.model-no-dispatch-accounting.v1"
                or type(self.witness) is not ModelNoDispatchWitnessV1 or type(self.expected_anchor) is not RestoreAnchor
                or (self.expected_anchor.authority_id, self.expected_anchor.namespace) !=
                   (self.intent.authority_id, self.intent.namespace)
                or self.operation_id == self.intent.operation_id):
            raise ValueError("exact no-dispatch original accounting request required")
        identifier(self.operation_id, "operation_id")
        if not set(dict(self.intent.budget_ceiling)) <= {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}:
            raise ValueError("no-dispatch accounting cannot release local work/counter/body costs")

    @property
    def intent(self): return self.witness.request.intent


@dataclass(frozen=True, slots=True)
class ModelNoDispatchAccountingGrantV1:
    permit: FencePermitV2
    call_id: str
    reservation_digest: str
    witness_digest: str
    schema: str = "sylanne3.authority.model-no-dispatch-accounting-grant.v1"

    def __post_init__(self):
        from .v2_model_egress_contract import _digest
        if (self.schema != "sylanne3.authority.model-no-dispatch-accounting-grant.v1"
                or type(self.permit) is not FencePermitV2 or self.permit.operation != "accounting"):
            raise ValueError("actual accounting fence for this unsent original required")
        identifier(self.call_id, "call_id")
        _digest(self.reservation_digest, "reservation_digest")
        _digest(self.witness_digest, "witness_digest")

