"""Exact JSON envelope for content-free accounting maintenance."""

from __future__ import annotations

from dataclasses import asdict, fields

from ..runtime.restore_anchor import RestoreAnchor
from .v2_accounting_contract import (
    AccountingMaintenanceGrantV1, AccountingMaintenanceRequestV1,
)
from .v2_contract import FencePermitV2, from_wire as fence_from_wire
from .v2_contract import to_wire as fence_to_wire
from .v2_model_egress_contract import ModelEgressIntentV1
from .v2_model_egress_wire import from_wire as model_from_wire
from .v2_model_egress_wire import to_wire as model_to_wire


def _shape(value, kind):
    if type(value) is not dict or set(value) != {field.name for field in fields(kind)}:
        raise ValueError("accounting wire fields differ")
    return value


def to_wire(value):
    if type(value) is AccountingMaintenanceRequestV1:
        return {
            "operation_id": value.operation_id,
            "intent": model_to_wire(value.intent),
            "expected_anchor": asdict(value.expected_anchor),
            "schema": value.schema,
        }
    if type(value) is AccountingMaintenanceGrantV1:
        return {
            "permit": fence_to_wire(value.permit),
            "call_id": value.call_id,
            "admission_id": value.admission_id,
            "reservation_digest": value.reservation_digest,
            "observation_digest": value.observation_digest,
            "terminal_receipt_digest": value.terminal_receipt_digest,
            "schema": value.schema,
        }
    raise ValueError("unsupported accounting wire type")


def from_wire(value, kind):
    if kind is AccountingMaintenanceRequestV1:
        shaped = dict(_shape(value, kind))
        shaped["intent"] = model_from_wire(shaped["intent"], ModelEgressIntentV1)
        shaped["expected_anchor"] = RestoreAnchor(
            **_shape(shaped["expected_anchor"], RestoreAnchor))
        return kind(**shaped)
    if kind is AccountingMaintenanceGrantV1:
        shaped = dict(_shape(value, kind))
        shaped["permit"] = fence_from_wire(shaped["permit"])
        if type(shaped["permit"]) is not FencePermitV2:
            raise ValueError("accounting permit wire kind differs")
        return kind(**shaped)
    raise ValueError("unsupported accounting wire type")


__all__ = ("to_wire", "from_wire")
