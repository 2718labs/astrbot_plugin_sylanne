"""Content-only D09 review for context_reply.v1 model text.

This does not authenticate a model result or a current graph read. The host
must bind the original paid call and re-read D06 access before D08 can grant
an action. D13 history is never a claim source.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import math
from typing import Protocol

from ...authority_service.v2_context_reply_result_contract import (
    ContextReplyPaidResultReadV2, ContextReplyResultReadRequestV1,
)
from ...graph_types import AtomKey
from ...memory_types import access_key
from ...model_broker.context_reply import (
    ContextReplyInputV1, FrozenContextReplyRequestV1,
    freeze_context_reply_request_v1,
)
from ...runtime_contracts import VersionedRef, canonical_digest
from . import ClaimKind, ClaimUse, ExpressionClaim, SegmentCandidate, segment_payload_digest


CONTEXT_REPLY_OUTPUT_SCHEMA = "sylanne.d09.context_reply_output.v1"
PAID_BATCH_SCHEMA_V2 = "d09.paid_verified_segment_batch.v2"


@dataclass(frozen=True, slots=True)
class ContextReplyExpressionV1:
    status: str
    claims: tuple[ExpressionClaim, ...]
    segments: tuple[SegmentCandidate, ...]
    payload_digest: str | None
    input_digest: str
    output_digest: str
    missing: tuple[str, ...]


class ContextReplyResultServicePortV2(Protocol):
    """Pinned Authority service; the host must not implement this port itself."""

    def read_current_result_v2(
        self, request: ContextReplyResultReadRequestV1, *, now_utc: float,
    ) -> ContextReplyPaidResultReadV2 | None: ...


@dataclass(frozen=True, slots=True)
class PaidContextReplyExpressionV2:
    status: str
    claims: tuple[ExpressionClaim, ...]
    segments: tuple[SegmentCandidate, ...]
    payload_digest: str | None
    original_operation_id: str | None
    paid_result_digest: str | None
    read_fence_digest: str | None
    missing: tuple[str, ...]


def paid_batch_value_v2(verified_batch: dict, paid: PaidContextReplyExpressionV2) -> dict:
    """Freeze paid identity beside a V1-shaped content batch, without upgrading it."""
    from . import _validate_verified_batch_value_v1

    _validate_verified_batch_value_v1(verified_batch)
    if (type(paid) is not PaidContextReplyExpressionV2
            or paid.status != "paid_current_source_verified_hold"
            or not paid.original_operation_id or not paid.paid_result_digest
            or not paid.read_fence_digest or paid.missing):
        raise ValueError("original paid result and current read fence required")
    if (len(paid.segments) != 1 or len(verified_batch["segments"]) != 1
            or paid.payload_digest != verified_batch["segments"][0]["payload_digest"]
            or paid.segments[0].segment_id != verified_batch["segments"][0]["segment_id"]
            or paid.segments[0].effect_id != verified_batch["segments"][0]["effect_id"]
            or {claim.claim_id for claim in paid.claims}
            != {claim["claim_id"] for claim in verified_batch["claims"]}):
        raise ValueError("paid expression differs from finite batch")
    value = {
        "schema": PAID_BATCH_SCHEMA_V2, "version": 2,
        "qualification": "paid_current_source_verified_hold",
        "original_operation_id": paid.original_operation_id,
        "paid_result_digest": paid.paid_result_digest,
        "read_fence_digest": paid.read_fence_digest,
        "source_refs": sorted({ref for claim in paid.claims for ref in claim.source_refs}),
        "verified_batch": verified_batch,
    }
    value["batch_digest"] = canonical_digest(value)
    return value


def validate_paid_batch_value_v2(value: dict) -> None:
    """Structural graph validation; Authority re-read is still mandatory."""
    from . import _validate_verified_batch_value_v1

    fields = {"schema", "version", "qualification", "original_operation_id",
              "paid_result_digest", "read_fence_digest", "source_refs",
              "verified_batch", "batch_digest"}
    if type(value) is not dict or set(value) != fields:
        raise ValueError("paid batch fields differ")
    if (value["schema"] != PAID_BATCH_SCHEMA_V2 or value["version"] != 2
            or value["qualification"] != "paid_current_source_verified_hold"
            or type(value["original_operation_id"]) is not str
            or not value["original_operation_id"]):
        raise ValueError("paid batch identity differs")
    for name in ("paid_result_digest", "read_fence_digest", "batch_digest"):
        digest = value[name]
        if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("paid batch digest differs")
    _validate_verified_batch_value_v1(value["verified_batch"])
    refs = sorted({ref for segment in value["verified_batch"]["segments"]
                   for ref in segment["source_refs"]})
    if value["source_refs"] != refs:
        raise ValueError("paid batch source closure differs")
    if value["batch_digest"] != canonical_digest({k: v for k, v in value.items() if k != "batch_digest"}):
        raise ValueError("paid batch content digest differs")


def issue_context_reply_expression_v1(
    result: dict, *, frozen_request: FrozenContextReplyRequestV1,
    current_input: ContextReplyInputV1, scene_ref: str,
    covered_slots: tuple[str, ...], max_chars: int, now_utc: float,
) -> ContextReplyExpressionV1:
    """Review exact D06 quotes; return HOLD for other natural language.

    ``current_input`` must be rebuilt by a trusted graph reader. Equality here
    detects stale candidates, but cannot prove the reader's authority. The
    returned candidate deliberately remains ``content_verified_source_hold``.
    """
    if (type(frozen_request) is not FrozenContextReplyRequestV1
            or type(current_input) is not ContextReplyInputV1):
        raise TypeError("typed frozen and current context inputs required")
    if (type(scene_ref) is not str or not scene_ref
            or type(covered_slots) is not tuple or not covered_slots
            or any(type(slot) is not str or not slot for slot in covered_slots)
            or len(set(covered_slots)) != len(covered_slots)
            or type(max_chars) is not int or not 1 <= max_chars <= 2048
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        raise ValueError("bounded scene, slots, length and time required")
    if (current_input != frozen_request.input
            or freeze_context_reply_request_v1(
                current_input, frozen_request.installation).digest != frozen_request.digest
            or now_utc < current_input.frozen_at_utc
            or now_utc >= current_input.expires_at_utc):
        raise ValueError("context input changed or expired")
    if (type(result) is not dict or set(result) != {"schema", "body", "spans"}
            or result["schema"] != CONTEXT_REPLY_OUTPUT_SCHEMA
            or type(result["body"]) is not str
            or not 0 < len(result["body"]) <= max_chars
            or type(result["spans"]) is not list
            or not 0 < len(result["spans"]) <= 16):
        raise ValueError("context reply output schema or bounds differ")
    body = result["body"]
    if any(ord(char) < 32 and char not in "\n\t" for char in body):
        raise ValueError("context reply contains control characters")
    output_digest = canonical_digest(result)
    evidence = {part.ref.ref: part for part in current_input.evidence}
    claims: list[ExpressionClaim] = []
    uses: list[ClaimUse] = []
    cursor = 0
    missing: list[str] = []
    for index, span in enumerate(result["spans"]):
        if type(span) is not dict or set(span) != {
            "start", "end", "source_ref", "source_revision", "access_ref",
            "access_revision", "source_quote",
        }:
            raise ValueError("context reply span fields differ")
        start, end = span["start"], span["end"]
        if (type(start) is not int or type(end) is not int
                or not cursor <= start < end <= len(body)
                or body[cursor:start].strip()):
            raise ValueError("context reply spans do not cover ordered body text")
        quote = span["source_quote"]
        if type(quote) is not str or not quote or body[start:end] != quote:
            raise ValueError("context reply span does not match body")
        source_ref = span["source_ref"]
        part = evidence.get(source_ref) if type(source_ref) is str else None
        if (part is None or type(span["source_revision"]) is not int
                or span["source_revision"] != part.ref.version
                or type(span["access_ref"]) is not str
                or part.access_ref is None
                or span["access_ref"] != part.access_ref.ref
                or type(span["access_revision"]) is not int
                or span["access_revision"] != part.access_ref.version
                or quote not in part.text):
            missing.append(f"d06_exact_source:{index}")
        else:
            claim_id = "context-quote:" + canonical_digest({
                "input": frozen_request.digest, "output": output_digest,
                "source": source_ref, "index": index, "text": quote,
            })
            claims.append(ExpressionClaim(
                claim_id, quote, ClaimKind.REPORTED_CLAIM,
                (source_ref,), (current_input.audience_ref.ref,),
                ("expression",), source_ref,
            ))
            uses.append(ClaimUse(claim_id, start, end, ClaimKind.REPORTED_CLAIM))
        cursor = end
    if body[cursor:].strip():
        raise ValueError("context reply body has unmapped content")
    if missing:
        return ContextReplyExpressionV1(
            "hold", (), (), None, frozen_request.digest, output_digest,
            tuple(missing),
        )
    provenance = canonical_digest({
        "schema": "d09.context_reply_expression.v1",
        "input_digest": frozen_request.digest, "output_digest": output_digest,
        "scene_ref": scene_ref, "audience_ref": current_input.audience_ref,
        "source_refs": tuple(part.ref for part in current_input.evidence),
        "access_refs": tuple(part.access_ref for part in current_input.evidence),
    })
    segment = SegmentCandidate(
        "segment:" + provenance, "effect:" + provenance, body, tuple(uses),
        covered_slots, (), 0.0,
    )
    return ContextReplyExpressionV1(
        "content_verified_source_hold", tuple(claims), (segment,),
        segment_payload_digest(body, (), tuple(uses)), frozen_request.digest,
        output_digest, (),
    )


def issue_paid_context_reply_expression_v2(
    request: ContextReplyResultReadRequestV1, *,
    result_service: ContextReplyResultServicePortV2 | None,
    current_input: ContextReplyInputV1, scene_ref: VersionedRef,
    audience_ref: VersionedRef, covered_slots: tuple[str, ...],
    max_chars: int, now_utc: float,
) -> PaidContextReplyExpressionV2:
    """Consume only a service-read original paid result and D06 exact spans.

    The Authority service must authenticate the original paid call and hold a
    current graph/Owner read fence. This D09 function independently checks the
    multi-source version closure and content. It never issues D08/D11 admission.
    """
    if (type(request) is not ContextReplyResultReadRequestV1
            or type(current_input) is not ContextReplyInputV1
            or type(scene_ref) is not VersionedRef
            or type(audience_ref) is not VersionedRef):
        raise TypeError("typed current context result request required")

    def hold(reason: str) -> PaidContextReplyExpressionV2:
        return PaidContextReplyExpressionV2(
            "hold", (), (), None, None, None, None, (reason,),
        )

    if result_service is None:
        return hold("authority_result_service_unavailable")
    try:
        paid = result_service.read_current_result_v2(request, now_utc=now_utc)
    except Exception:
        return hold("authority_result_read_failed")
    if type(paid) is not ContextReplyPaidResultReadV2:
        return hold("authority_result_unavailable")
    seal = paid.original_seal
    frozen = paid.frozen_request
    if (paid.status != "paid_current_source_verified_hold"
            or paid.read_attempt_id != request.read_attempt_id
            or (paid.provider_observation.authority_id,
                paid.provider_observation.namespace) != (
                    request.authority_id, request.authority_namespace)
            or (seal.namespace, seal.c02_operation_id, seal.source_ref,
                seal.installation_id, seal.job_id, seal.acquire_operation_id,
                seal.original_operation_id, seal.call_id,
                seal.model_request_digest, seal.frozen_input_digest) != (
                    request.namespace, request.c02_operation_id,
                    request.source_ref, request.installation_id,
                    request.job_id, request.acquire_operation_id,
                    request.original_operation_id, request.call_id,
                    request.model_request_digest, request.frozen_input_digest)
            or paid.model_call_request_digest != paid.terminal_receipt.request_digest
            or frozen.input != current_input
            or current_input.namespace != request.namespace
            or current_input.scene_ref != scene_ref
            or current_input.audience_ref != audience_ref
            or not current_input.frozen_at_utc <= now_utc < current_input.expires_at_utc):
        return hold("paid_result_or_current_scope_changed")
    # GraphVersion rows are current only because the pinned Authority service
    # issued them; duplicate/missing rows or mismatched D06 heads still HOLD.
    versions = {row.key.token: row.revision for row in paid.current_read_versions}
    if len(versions) != len(paid.current_read_versions):
        return hold("current_source_versions_incomplete")
    from ..d06 import source_correction_head_key

    namespace = current_input.namespace
    source_refs = tuple(dict.fromkeys(
        ref for part in current_input.evidence
        for ref in (part.ref, *part.dependencies)
    ))
    for ref in source_refs:
        try:
            key = AtomKey.from_token(ref.ref)
        except (TypeError, ValueError):
            return hold("current_source_versions_incomplete")
        if (key.type_name != "memory.source" or key.owner.kind != "event"
                or (key.owner.bot, key.owner.persona) != namespace.as_tuple
                or versions.get(ref.ref) != ref.version
                or access_key(*namespace.as_tuple, key.owner.subject).token not in versions
                or source_correction_head_key(namespace, key.owner.subject).token not in versions):
            return hold("current_source_versions_incomplete")
    if any(part.access_ref is None or versions.get(part.access_ref.ref) != part.access_ref.version
           for part in current_input.evidence):
        return hold("current_access_versions_incomplete")
    try:
        content = issue_context_reply_expression_v1(
            json.loads(paid.canonical_output), frozen_request=frozen,
            current_input=current_input, scene_ref=scene_ref.ref,
            covered_slots=covered_slots, max_chars=max_chars, now_utc=now_utc,
        )
    except (TypeError, ValueError):
        return hold("d09_exact_span_unverified")
    if content.status != "content_verified_source_hold" or not content.segments:
        return hold("d09_exact_span_unverified")
    provenance = canonical_digest({
        "schema": "d09.paid_context_reply_expression.v2",
        "original_seal": paid.original_seal_digest,
        "model_call_request_digest": paid.model_call_request_digest,
        "terminal_observation": paid.provider_response_digest,
        "read_fence": paid.read_fence_digest,
        "output_digest": paid.output_digest,
        "current_guard": paid.current_guard_digest,
    })
    segment = replace(
        content.segments[0], segment_id="segment:" + provenance,
        effect_id="effect:" + provenance,
    )
    return PaidContextReplyExpressionV2(
        "paid_current_source_verified_hold", content.claims, (segment,),
        content.payload_digest, seal.original_operation_id, provenance,
        paid.read_fence_digest, (),
    )


__all__ = [
    "CONTEXT_REPLY_OUTPUT_SCHEMA", "ContextReplyExpressionV1",
    "issue_context_reply_expression_v1",
    "ContextReplyResultServicePortV2", "PaidContextReplyExpressionV2",
    "issue_paid_context_reply_expression_v2",
]
