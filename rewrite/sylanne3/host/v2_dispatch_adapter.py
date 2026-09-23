"""Bind a finite D08/D09 text batch to D11's per-segment dispatch runtime.

This is an orchestration boundary, not an admission authority.  The supplied
DispatchRuntime must have a real D11 authority and recovery gate; this module
cannot turn a prepared expression into permission to send.
"""

from __future__ import annotations

import hashlib

from ..dispatch_runtime import DispatchBlocked, DispatchRequest, DispatchResult, DispatchRuntime
from ..domains.d08.execution import CommunicationIntentGrant
from ..domains.d09 import StagingResult, segment_payload_digest


def dispatch_finite_text_batch(
    runtime: DispatchRuntime,
    grant: CommunicationIntentGrant,
    staged: StagingResult,
    requests: tuple[DispatchRequest, ...],
) -> tuple[DispatchResult, ...]:
    """Dispatch one verified text segment at a time; stop unless accepted.

    Every request is checked against the entire frozen finite manifest before
    the first effect.  D11 still has to issue a separate current permit and
    handoff-start receipt for each segment.  A merely handed-off or unknown
    preceding effect cannot authorize the next segment.
    """
    if not isinstance(runtime, DispatchRuntime):
        raise TypeError("a configured D11 DispatchRuntime is required")
    if not isinstance(grant, CommunicationIntentGrant) or not isinstance(staged, StagingResult):
        raise TypeError("a typed D08 grant and D09 staging result are required")
    if staged.status != "complete" or len(staged.segments) != len(grant.segment_grants):
        raise DispatchBlocked("finite expression manifest is incomplete")
    if type(requests) is not tuple or len(requests) != len(staged.segments):
        raise DispatchBlocked("one frozen D11 request is required for each segment")

    manifest = grant.segment_manifest_digest
    seen_operations: set[str] = set()
    for index, (segment, segment_grant, request) in enumerate(
        zip(staged.segments, grant.segment_grants, requests)
    ):
        if not isinstance(request, DispatchRequest):
            raise DispatchBlocked("finite segment has no typed D11 request")
        if segment.media_refs:
            raise DispatchBlocked("this AstrBot text route supports text only")
        expected = (
            grant.intent_ref, grant.action_id, segment_grant.segment_id,
            segment_grant.effect_id, index, segment_grant.payload_digest,
            segment_grant.prerequisite_segment_ref,
        )
        actual = (
            segment.intent_ref, segment.action_id, segment.segment_id,
            segment.effect_id, segment.position, segment.payload_digest,
            segment.prerequisite_segment_ref,
        )
        if (actual != expected or segment.audiences != grant.audiences
                or len(segment.body) > segment_grant.max_chars or segment_payload_digest(
            segment.body, segment.media_refs, segment.claim_uses,
        ) != segment_grant.payload_digest):
            raise DispatchBlocked("staged segment differs from the frozen D08 grant")
        if (
            request.footprint.communication_action != grant.communication_action_id
            or request.footprint.contact_id != grant.contact_id
            or request.footprint.segment_id != segment.segment_id
            or request.effect_id != segment.effect_id
            or request.required_check_refs != segment_grant.required_check_refs
            or request.cancel_epoch != grant.cancellation_epoch
            or request.segment_authorization_ref != grant.segment_authorization_ref(segment.segment_id)
            or request.segment_manifest_digest != manifest
            or request.segment_index != index
            or request.segment_count != len(requests)
            or request.contact_policy_check_ref != grant.contact_policy_check_ref
            or request.proactive_contact != (grant.contact_policy_check_ref is not None)
            or request.payload_digest != hashlib.sha256(segment.body.encode("utf-8")).hexdigest()
            or request.operation_id in seen_operations
        ):
            raise DispatchBlocked("D11 request differs from the finite segment authorization")
        seen_operations.add(request.operation_id)

    results: list[DispatchResult] = []
    accepted: set[str] = set()
    for segment, request in zip(staged.segments, requests):
        if segment.prerequisite_segment_ref not in (None, *accepted):
            break
        result = runtime.dispatch(request)
        results.append(result)
        if result.status != "accepted":
            break
        accepted.add(segment.segment_id)
    return tuple(results)


__all__ = ("dispatch_finite_text_batch",)
