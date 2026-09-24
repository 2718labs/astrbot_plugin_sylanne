"""Stable business operation identity for one original first-ingress result."""

from __future__ import annotations

from dataclasses import asdict

from ..runtime_contracts import NamespaceId, canonical_digest


def first_ingress_c02_consumer_operation_id_v1(
    *, namespace: NamespaceId, authority_id: str, authority_namespace: str,
    installation_id: str, job_id: str, acquire_operation_id: str,
    original_operation_id: str, call_id: str, binding_digest: str,
    model_request_digest: str,
) -> str:
    """Derive from durable graph/installation facts, never a caller-selected ID."""
    if type(namespace) is not NamespaceId:
        raise TypeError("typed first-ingress namespace required")
    original = {
        "namespace": asdict(namespace),
        "authority_id": authority_id,
        "authority_namespace": authority_namespace,
        "installation_id": installation_id,
        "job_id": job_id,
        "acquire_operation_id": acquire_operation_id,
        "original_operation_id": original_operation_id,
        "call_id": call_id,
        "binding_digest": binding_digest,
        "model_request_digest": model_request_digest,
    }
    if any(type(value) is not str or not value for key, value in original.items()
           if key != "namespace"):
        raise ValueError("original C02 identity is incomplete")
    return "first-ingress-c02-" + canonical_digest({
        "schema": "sylanne3.first-ingress-c02-consumer.v1",
        "original": original,
    })[:48]


__all__ = ("first_ingress_c02_consumer_operation_id_v1",)
