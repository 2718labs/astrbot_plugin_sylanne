"""D09's bounded expression candidate from one Authority-read reply result.

This issuer does not grant communication or qualify the destination. The host
must supply the typed result returned by Authority and current graph reads;
D08, the graph coordinator, and D11 still decide admission independently.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import TYPE_CHECKING

from ...authority_service.v2_model_egress_contract import ModelEgressIntentV1
from ...authority_service.v2_reply_worker_model_result_contract import ReplyWorkerModelResultReadV1
from ...graph_types import AtomKey
from ...memory_types import access_key
from ...runtime_contracts import CommandEnvelope, canonical_digest
from . import ClaimKind, ExpressionClaim, SegmentCandidate, segment_payload_digest

if TYPE_CHECKING:
    from ...model_broker.broker import ModelCallRequest
    from ...model_broker.reply_language import ReplyLanguageCandidate, ReplySourceSnapshot


@dataclass(frozen=True, slots=True)
class SourceReplyExpressionV1:
    """One quoted segment and its claim/provenance receipts, pending D08."""

    claims: tuple[ExpressionClaim, ...]
    segments: tuple[SegmentCandidate, ...]
    payload_digest: str
    provenance_digest: str
    result_read_request_digest: str
    observation_digest: str


def issue_source_reply_expression_v1(
    candidate: ReplyLanguageCandidate, *,
    result_read: ReplyWorkerModelResultReadV1,
    model_request: ModelCallRequest,
    original_intent: ModelEgressIntentV1,
    current_source: ReplySourceSnapshot,
    current_envelope: CommandEnvelope,
    scene_ref: str,
    covered_slots: tuple[str, ...],
    max_chars: int,
) -> SourceReplyExpressionV1:
    """Bind exact quoted model output to the current source and audience.

    The result-read DTO must be the one actually released by Authority. The
    current source and envelope must come from the graph worker's live read.
    A content digest is returned for D08's existing finite segment manifest;
    a separate provenance digest binds the call/read, audience, scene and
    source without changing D08's content-digest contract.
    """
    from ...model_broker.broker import ModelCallRequest
    from ...model_broker.reply_language import (
        ReplyLanguageCandidate, ReplySourceSnapshot, parse_reply_result_v1,
    )

    if (type(candidate) is not ReplyLanguageCandidate
            or type(result_read) is not ReplyWorkerModelResultReadV1
            or type(model_request) is not ModelCallRequest
            or type(original_intent) is not ModelEgressIntentV1
            or type(current_source) is not ReplySourceSnapshot
            or type(current_envelope) is not CommandEnvelope):
        raise TypeError("typed Authority reply and current graph inputs required")
    if (type(scene_ref) is not str or not scene_ref
            or type(covered_slots) is not tuple
            or not covered_slots
            or any(type(slot) is not str or not slot for slot in covered_slots)
            or len(set(covered_slots)) != len(covered_slots)
            or type(max_chars) is not int or not 1 <= max_chars <= 2048):
        raise ValueError("one bounded reply segment and explicit slots required")

    read = result_read.request
    source_ref = current_source.source_ref
    source_id = current_source.source.source_id
    audience = current_envelope.authority.audience
    namespace = current_envelope.authority.namespace
    versions = {row.key.token: row.revision
                for row in current_envelope.version_guard.read_versions}
    source_key = AtomKey.from_token(source_ref)
    access_ref = access_key(*namespace.as_tuple, source_id).token
    if (not audience or len(set(audience)) != len(audience)
            or current_envelope.authority.purpose != "expression"
            or (source_key.owner.bot, source_key.owner.persona) != namespace.as_tuple
            or current_envelope.source_qualification.source_refs != (source_ref,)
            or source_ref not in current_envelope.input_refs
            or versions.get(source_ref) != current_source.source_revision
            or versions.get(access_ref) != current_source.access_revision
            or not set(audience) <= set(current_source.source.audiences)
            or "expression" not in current_source.source.purposes
            or (read.namespace, read.source_ref, read.source_revision,
                read.access_revision, read.audience,
                read.consumer_operation_id) != (
                    namespace, source_ref, current_source.source_revision,
                    current_source.access_revision, audience,
                    current_envelope.identity.operation_id)
            or model_request.envelope.authority.audience != audience
            or model_request.envelope.authority.namespace != namespace
            or candidate.source_ref != source_ref
            or candidate.status != "candidate"
            or candidate.model_request_digest != model_request.digest
            or model_request.digest != read.model_request_digest
            or model_request.call_id != read.call_id):
        raise ValueError("reply source, access, audience or operation changed")
    result_read.require_original_intent(original_intent)
    if (original_intent.request_digest != model_request.digest
            or original_intent.call_id != model_request.call_id
            or result_read.observation.result_json is None):
        raise ValueError("reply result differs from original model call")
    parsed = parse_reply_result_v1(
        json.loads(result_read.observation.result_json),
        request=model_request, snapshot=current_source,
    )
    if parsed != candidate or not parsed.claims or not parsed.claim_uses:
        raise ValueError("reply claims differ from the Authority result")
    if any(claim.kind is not ClaimKind.REPORTED_CLAIM
           or claim.source_refs != (source_ref,)
           or claim.allowed_audiences != audience
           or claim.disclosure_ref != source_ref
           for claim in parsed.claims):
        raise ValueError("reply claim exceeds quoted source or audience")
    if len(parsed.body) > max_chars:
        raise ValueError("reply exceeds the granted candidate length")

    provenance = canonical_digest({
        "schema": "d09.source_reply_expression.v1",
        "model_call_id": model_request.call_id,
        "model_request_digest": model_request.digest,
        "result_read_request_digest": read.digest,
        "observation_digest": result_read.observation.digest,
        "consumer_operation_id": read.consumer_operation_id,
        "source_ref": source_ref,
        "source_revision": current_source.source_revision,
        "access_revision": current_source.access_revision,
        "audience": audience,
        "scene_ref": scene_ref,
    })
    segment = parsed.segment(
        segment_id="segment:" + provenance,
        effect_id="effect:" + canonical_digest({
            "operation_id": read.consumer_operation_id,
            "segment_provenance": provenance,
        }),
        covered_slots=covered_slots,
    )
    return SourceReplyExpressionV1(
        parsed.claims, (segment,),
        segment_payload_digest(segment.body, segment.media_refs,
                               segment.claim_uses),
        provenance, read.digest, result_read.observation.digest,
    )


__all__ = ["SourceReplyExpressionV1", "issue_source_reply_expression_v1"]
