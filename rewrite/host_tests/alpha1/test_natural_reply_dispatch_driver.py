"""Natural V2 dispatch recovers the committed effect and waits for its claim."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from sylanne3.dispatch_runtime import DispatchRequest, HandoffUncertain
from sylanne3.authority_service.v2_execution_bridge import CurrentEffectReadV2
from sylanne3.domains.d09 import segment_payload_digest
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.graph_worker import GraphWorker
from sylanne3.host.natural_reply_dispatch_driver import (
    InstalledNaturalReplyContinuationV2, NaturalReplyDispatchDriverV2,
)
from sylanne3.host.mtls_transport import V2OwnerAuthorizationBarrier
from sylanne3.host.v2_fence_port import V2FenceOutcomeUnknown
from sylanne3.runtime.dispatch_admission import DispatchAdmissionReceiptV1
from sylanne3.runtime.dispatch_candidate import (
    GraphDispatchTextSegmentV1, NaturalDispatchCandidateEvidenceV2,
    natural_dispatch_segment_payload_ref_v2,
)
from sylanne3.runtime_contracts import CommitReceipt, NamespaceId, canonical_digest
from sylanne3.runtime_journal import RecoveryConstraintFootprint


NAMESPACE = NamespaceId("bot", "persona")
ACCOUNT = json.dumps(["platform", "aiocqhttp", "self"], separators=(",", ":"))
DESTINATION = json.dumps(
    ["platform:FriendMessage:123456", "conversation"], separators=(",", ":"))
BODY = "已核实的回答"


class _Graph:
    def __init__(self, *, paid_digest: str = "paid-digest") -> None:
        self.calls = []
        batch = AtomKey(Owner("activity", "bot", "persona", "activity"),
                        "d09.natural_verified_segment_batch.v2", "batch")
        payload_digest = segment_payload_digest(BODY, (), ())
        request = DispatchRequest(
            namespace="bot/persona", operation_id="natural-op",
            activity_id="activity", effect_id="effect", attempt_id="attempt",
            command_digest="a" * 64,
            payload_ref=natural_dispatch_segment_payload_ref_v2(batch.token, 0),
            payload_digest=payload_digest, platform_capability_ref="capability",
            required_check_refs=("check",), dispatch_generation=1,
            activation_generation=1, worker_fence=1, content_fence="fence",
            cancel_epoch=0,
            footprint=RecoveryConstraintFootprint(
                "bot/persona", "activity", "effect",
                communication_action="action", contact_id="contact",
                segment_id="segment"),
            proactive_contact=False, segment_authorization_ref="authorization",
            segment_manifest_digest="b" * 64, segment_index=0, segment_count=1,
        )
        evidence = NaturalDispatchCandidateEvidenceV2(
            request.operation_id, request.effect_id,
            "action-ref", "schema-ref", "grant-ref", batch.token,
            "action-digest", "schema-digest", "grant-digest", "batch-digest",
            "segment", payload_digest, paid_digest,
            "generation-original", "review-original", ("source-ref",),
            (GraphVersion(batch, 1),), 1, 1, 1,
        )
        admission = SimpleNamespace(
            namespace=request.namespace, operation_id=request.operation_id,
            effect_id=request.effect_id, activity_id=request.activity_id,
            admission_ref="admission", digest="c" * 64,
            request_digest=canonical_digest(request),
            candidate_digest=evidence.digest,
            batch_digest=evidence.batch_digest,
            payload_digest=payload_digest, account_ref=ACCOUNT,
            destination_ref=DESTINATION,
        )
        receipt = object.__new__(DispatchAdmissionReceiptV1)
        object.__setattr__(receipt, "admission", admission)
        operation = CommitReceipt(
            "committed", request.operation_id, "d" * 64, "activity", "effect",
            1, (), (), (), (), ("outbox",),
        )
        self.original = (receipt, request, evidence, operation)
        self.text = GraphDispatchTextSegmentV1(
            BODY, (), (), "platform", "aiocqhttp", "self",
            "platform:FriendMessage:123456", "conversation", "scene",
        )

    def read_committed_natural_dispatch_v2(self, authority, lease, operation_id):
        self.calls.append("original")
        assert operation_id == "natural-op"
        return self.original

    def get_natural_dispatch_text_segment_v2(self, authority, lease, request):
        self.calls.append("text")
        assert request == self.original[1]
        return self.text, self.original[2]

    def begin_dispatch_fence(self, *args, **kwargs):
        raise AssertionError("P2 began without an installed natural final claim")


async def _run(graph, continuation=None):
    worker = await GraphWorker.start(
        lambda: SimpleNamespace(close=lambda: None), lambda _store: graph)
    try:
        authority = SimpleNamespace(namespace=NAMESPACE)
        lease = object()
        if continuation is not None:
            continuation._worker = worker
            continuation._authority = authority
            continuation._lease = lease
        return await NaturalReplyDispatchDriverV2(
            worker, authority, lease, continuation).run_once(
                operation_id="natural-op")
    finally:
        await worker.close()


def test_committed_natural_original_is_read_then_holds_without_specific_claim():
    graph = _Graph()
    result = asyncio.run(_run(graph))
    assert result.status == "hold" and "final graph claim" in result.reason
    assert result.original is not None
    assert result.original.payload.payload.decode() == BODY
    assert graph.calls == ["original", "text"]


def test_missing_paid_receipt_holds_before_p2():
    graph = _Graph(paid_digest="")
    result = asyncio.run(_run(graph))
    assert result.status == "hold" and result.original is None
    assert graph.calls == ["original", "text"]


def test_lost_natural_handoff_ack_is_unknown_without_second_send():
    graph = _Graph()
    continuation = object.__new__(InstalledNaturalReplyContinuationV2)
    calls = []

    async def dispatch(original):
        calls.append(original.operation_id)
        raise HandoffUncertain("observation:lost")

    continuation.dispatch = dispatch
    async def absent(original):
        return CurrentEffectReadV2(
            "authority", "ns-a", original.effect_id, 1, "absent", 0, "head")
    continuation.read_recovery_state = absent
    result = asyncio.run(_run(graph, continuation))
    assert result.status == "unknown" and calls == ["natural-op"]
    assert graph.calls == ["original", "text"]


def test_observed_effect_recovery_never_calls_platform_dispatch():
    graph = _Graph()
    continuation = object.__new__(InstalledNaturalReplyContinuationV2)
    calls = []

    async def observed(original):
        return CurrentEffectReadV2(
            "authority", "ns-a", original.effect_id, 1, "observed", 1, "head",
            observation_id="observation")

    async def dispatch(original):
        calls.append(original.operation_id)
        raise AssertionError("observed effect must not send")

    continuation.read_recovery_state = observed
    continuation.dispatch = dispatch
    result = asyncio.run(_run(graph, continuation))
    assert result.status == "hold" and "already observed" in result.reason
    assert not calls


def test_verified_owner_barrier_holds_but_ambiguous_handoff_stays_unknown():
    graph = _Graph()
    continuation = object.__new__(InstalledNaturalReplyContinuationV2)

    async def absent(original):
        return CurrentEffectReadV2(
            "authority", "ns-a", original.effect_id, 1, "absent", 0, "head")

    continuation.read_recovery_state = absent

    async def owner_barrier(_original):
        raise V2OwnerAuthorizationBarrier("current Owner authorization bars handoff")

    continuation.dispatch = owner_barrier
    denied = asyncio.run(_run(graph, continuation))
    assert denied.status == "hold"

    async def socket_unknown(_original):
        raise V2FenceOutcomeUnknown("handoff response lost")

    continuation.dispatch = socket_unknown
    unknown = asyncio.run(_run(graph, continuation))
    assert unknown.status == "unknown"
