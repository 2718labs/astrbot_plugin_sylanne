"""Stable worker result-read identities for an original first-ingress call.

These names are derived only from W01's durable, fenced original context.
They are not a read grant or evidence that the model result was released.
"""

from __future__ import annotations

from ..authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, first_ingress_read_attempt_id_v1,
)
from ..runtime.first_ingress_c02_identity import (
    first_ingress_c02_consumer_operation_id_v1,
)
from ..runtime.original_model_result_context import OriginalModelResultContextV1


def first_ingress_worker_result_request_v1(
    context: OriginalModelResultContextV1,
) -> WorkerModelResultReadRequestV1:
    """Name one consumer and its first read attempt across host restarts."""
    if type(context) is not OriginalModelResultContextV1:
        raise TypeError("fenced original model result context required")
    consumer_id = first_ingress_c02_consumer_operation_id_v1(
        namespace=context.namespace,
        authority_id=context.authority_id,
        authority_namespace=context.authority_namespace,
        installation_id=context.installation_id,
        job_id=context.job_id,
        acquire_operation_id=context.acquire_operation_id,
        original_operation_id=context.original_operation_id,
        call_id=context.call_id,
        binding_digest=context.binding_digest,
        model_request_digest=context.model_request_digest,
    )
    read_id = first_ingress_read_attempt_id_v1(consumer_id, 1)
    return WorkerModelResultReadRequestV1(
        context.authority_id, context.authority_namespace, context.namespace,
        context.installation_id, context.job_id, context.acquire_operation_id,
        context.original_operation_id, context.call_id, context.binding_digest,
        context.model_request_digest, consumer_id, read_id,
    )


__all__ = ("first_ingress_worker_result_request_v1",)
