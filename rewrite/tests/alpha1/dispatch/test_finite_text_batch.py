from __future__ import annotations

from dataclasses import replace
import hashlib

import pytest

from rewrite.sylanne3.dispatch_runtime import DispatchBlocked, DispatchRequest, DispatchResult, DispatchRuntime
from rewrite.sylanne3.domains.d08.execution import CommunicationIntentGrant, SegmentGrant
from rewrite.sylanne3.domains.d09 import StagingResult, VerifiedSegment, segment_payload_digest
from rewrite.sylanne3.host.v2_dispatch_adapter import dispatch_finite_text_batch
from rewrite.sylanne3.runtime_journal import RecoveryConstraintFootprint


def _fixture():
    texts = ("...", "?!")
    checks = ("check:role", "check:budget")
    grants = tuple(SegmentGrant(
        f"segment:{i}", f"effect:{i}", i - 1,
        segment_payload_digest(text, (), ()), 10, (),
        f"segment:{i - 1}" if i > 1 else None, checks, 100.0, 0,
    ) for i, text in enumerate(texts, 1))
    grant = CommunicationIntentGrant(
        "communication-grant:" + "1" * 64, "communication:reply", "contact:reply", 1,
        "action:reply", "action:reply", 1, "entity:recipient", ("entity:recipient",),
        "expression", (), ("rhetoric",), (), grants, "2" * 64, checks, 100.0, 0,
    )
    segments = tuple(VerifiedSegment(
        grant.intent_ref, grant.action_id, item.segment_id, item.effect_id,
        item.position, item.payload_digest, text, (), (), (),
        item.prerequisite_segment_ref, grant.audiences,
    ) for item, text in zip(grants, texts))
    requests = tuple(DispatchRequest(
        "namespace:1", f"operation:{i}", "activity:reply", item.effect_id,
        f"attempt:{i}", hashlib.sha256(f"command:{i}".encode()).hexdigest(),
        f"payload:{i}", item.payload_digest, "capability:astrbot",
        checks, 1, 1, 1, "content:fence", 0,
        RecoveryConstraintFootprint(
            "namespace:1", "activity:reply", item.effect_id,
            communication_action=grant.communication_action_id,
            contact_id=grant.contact_id, segment_id=item.segment_id,
        ),
        False, grant.segment_authorization_ref(item.segment_id),
        grant.segment_manifest_digest, i - 1, len(grants), None,
    ) for i, (item, text) in enumerate(zip(grants, texts), 1))
    return grant, StagingResult("complete", segments, (), ()), requests


def _runtime(statuses):
    runtime = object.__new__(DispatchRuntime)
    calls = []

    def dispatch(request):
        calls.append(request.operation_id)
        status = statuses[len(calls) - 1]
        return DispatchResult(status, request.operation_id, request.effect_id, "admission:1", None, None, 1, True)

    runtime.dispatch = dispatch
    return runtime, calls


def test_second_segment_requires_accepted_predecessor():
    grant, staged, requests = _fixture()
    runtime, calls = _runtime(("pending_confirmation", "accepted"))
    result = dispatch_finite_text_batch(runtime, grant, staged, requests)
    assert len(result) == 1
    assert calls == ["operation:1"]

    runtime, calls = _runtime(("accepted", "accepted"))
    result = dispatch_finite_text_batch(runtime, grant, staged, requests)
    assert len(result) == 2
    assert calls == ["operation:1", "operation:2"]


def test_entire_manifest_checked_before_first_send():
    grant, staged, requests = _fixture()
    runtime, calls = _runtime(("accepted", "accepted"))
    changed = replace(requests[1], segment_manifest_digest="0" * 64)
    with pytest.raises(DispatchBlocked):
        dispatch_finite_text_batch(runtime, grant, staged, (requests[0], changed))
    assert calls == []


def test_semantic_and_wire_payloads_both_bound_before_send():
    grant, staged, requests = _fixture()
    runtime, calls = _runtime(("accepted", "accepted"))
    changed = replace(staged.segments[1], body="!?", payload_digest=staged.segments[1].payload_digest)
    with pytest.raises(DispatchBlocked):
        dispatch_finite_text_batch(runtime, grant, replace(staged, segments=(staged.segments[0], changed)), requests)
    changed_request = replace(requests[1], payload_digest="0" * 64)
    with pytest.raises(DispatchBlocked):
        dispatch_finite_text_batch(runtime, grant, staged, (requests[0], changed_request))
    assert calls == []
