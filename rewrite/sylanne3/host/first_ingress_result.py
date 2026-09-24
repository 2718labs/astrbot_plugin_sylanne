"""Owner-qualified read of one original first-ingress model result.

The original model operation is never re-admitted here.  D06 preparation is
only a held candidate; a separate D11 adoption port must authorize its write.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..authority_service.v2_contract import FencePermitV2
from ..authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelTerminalReceiptV2,
)
from ..authority_service.v2_model_result_read_contract import (
    ModelResultReadRequestV1, ModelResultReadV1,
)
from ..domains.d06 import EncodingContext
from ..domains.d06.pipeline import D06MemoryPipeline, HeldFirstIngressC02
from ..memory_types import SourceRecord
from ..runtime.encoding_call_binding import EncodingCallBinding
from ..runtime_contracts import CommandEnvelope


@dataclass(frozen=True, slots=True)
class OriginalFirstIngressRead:
    intent: ModelEgressIntentV1
    record: ModelEgressRecoveryV1
    permit: FencePermitV2
    admission: ModelAdmissionV2
    terminal: ModelTerminalReceiptV2
    read_request: ModelResultReadRequestV1
    read: ModelResultReadV1


def prepare_held_first_ingress_c02(
    original: OriginalFirstIngressRead, *, pipeline: D06MemoryPipeline,
    binding: EncodingCallBinding, source: SourceRecord,
    context: EncodingContext, encoding_baseline_ref: str,
    envelope: CommandEnvelope,
) -> HeldFirstIngressC02:
    """Compile only a HOLD from graph-qualified D04/D06 inputs.

    The caller still needs a trusted D04 baseline and C02 envelope source.
    D06 repeats current graph/source/baseline checks here.  The returned
    wrapper is deliberately never passed to generic graph commit.
    """
    if (type(original) is not OriginalFirstIngressRead
            or type(pipeline) is not D06MemoryPipeline
            or type(binding) is not EncodingCallBinding
            or type(source) is not SourceRecord
            or type(context) is not EncodingContext
            or type(envelope) is not CommandEnvelope
            or (original.intent.call_id, original.intent.request_digest,
                original.intent.source_refs) !=
               (binding.call_id, binding.model_request_digest,
                (binding.source_id,))):
        raise ValueError("original read and graph-qualified D06 inputs required")
    audience = original.read_request.audience
    if len(audience) != 1:
        raise ValueError("first-ingress C02 requires one original audience")
    purpose = original.read_request.source_purpose
    prepared = pipeline.prepare_authority_first_ingress_encoding(
        original.read_request, original.read, binding, source, context,
        encoding_baseline_ref=encoding_baseline_ref,
        audience=audience[0], purpose=purpose)
    held = pipeline.compile_first_ingress_c02_v2(
        envelope, prepared, original.read,
        audience=audience[0], purpose=purpose)
    if held.status != "candidate_hold":
        raise RuntimeError("first-ingress C02 is not held")
    return held


__all__ = ("OriginalFirstIngressRead", "prepare_held_first_ingress_c02")
