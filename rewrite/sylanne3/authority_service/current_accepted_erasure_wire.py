"""Exact JSON wire for the current Authority accepted-erasure read."""

from __future__ import annotations

from .current_accepted_erasure_read import CurrentAcceptedErasureV1
from .v2_contract import DeletionMutationReceiptV1, FencePermitV2, from_wire, to_wire


_FIELDS = frozenset({
    "schema", "namespace", "deletion_operation_id", "pending_receipt",
    "accepted_receipt", "permit", "closure_roots", "deletion_epoch",
    "scope_digest", "graph_barrier_digest",
})


def accepted_to_wire(value: CurrentAcceptedErasureV1) -> dict[str, object]:
    if type(value) is not CurrentAcceptedErasureV1:
        raise TypeError("typed current accepted erasure required")
    return {
        "schema": value.schema,
        "namespace": value.namespace,
        "deletion_operation_id": value.deletion_operation_id,
        "pending_receipt": to_wire(value.pending_receipt),
        "accepted_receipt": to_wire(value.accepted_receipt),
        "permit": to_wire(value.permit),
        "closure_roots": list(value.closure_roots),
        "deletion_epoch": value.deletion_epoch,
        "scope_digest": value.scope_digest,
        "graph_barrier_digest": value.graph_barrier_digest,
    }


def accepted_from_wire(value: object) -> CurrentAcceptedErasureV1:
    if (type(value) is not dict or set(value) != _FIELDS
            or type(value["closure_roots"]) is not list
            or any(type(root) is not str for root in value["closure_roots"])):
        raise ValueError("current accepted erasure wire fields differ")
    pending = from_wire(value["pending_receipt"])
    accepted = from_wire(value["accepted_receipt"])
    permit = from_wire(value["permit"])
    if (type(pending) is not DeletionMutationReceiptV1
            or type(accepted) is not DeletionMutationReceiptV1
            or type(permit) is not FencePermitV2):
        raise ValueError("current accepted erasure wire types differ")
    result = CurrentAcceptedErasureV1(
        value["namespace"], value["deletion_operation_id"], pending,
        accepted, permit, tuple(value["closure_roots"]),
        value["deletion_epoch"], value["scope_digest"],
        value["graph_barrier_digest"], value["schema"])
    if accepted_to_wire(result) != value:
        raise ValueError("current accepted erasure wire is noncanonical")
    return result


__all__ = ["accepted_to_wire", "accepted_from_wire"]
