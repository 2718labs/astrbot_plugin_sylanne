"""The private reply driver reads original graph facts and cannot start P2."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from sylanne3.dispatch_runtime import DispatchRequest, HandoffUncertain
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.graph_worker import GraphWorker
from sylanne3.host.private_reply_dispatch_driver import (
    InstalledPrivateReplyContinuationV1, PrivateReplyDispatchDriver,
)
from sylanne3.host.v2_fence_port import V2FenceOutcomeUnknown
from sylanne3.authority_service.v2_execution_bridge import CurrentEffectReadV2
from sylanne3.runtime.dispatch_admission import DispatchAdmissionReceiptV1
from sylanne3.runtime.post_c02_reply_ownership_v1 import ReplyOwnershipReceiptV1
from sylanne3.runtime_contracts import CommitReceipt, NamespaceId, canonical_digest
from sylanne3.runtime_journal import RecoveryConstraintFootprint


NAMESPACE = NamespaceId("bot", "persona")
ACCOUNT = json.dumps(["platform", "aiocqhttp", "self"], separators=(",", ":"))
DESTINATION = json.dumps(["platform:FriendMessage:123456", "conversation"], separators=(",", ":"))
DIGEST = "a" * 64


def _request() -> DispatchRequest:
    return DispatchRequest(
        namespace="bot/persona", operation_id="reply-op", activity_id="activity",
        effect_id="effect", attempt_id="attempt", command_digest=DIGEST,
        payload_ref="payload", payload_digest=DIGEST,
        platform_capability_ref="platform-capability", required_check_refs=("check",),
        dispatch_generation=1, activation_generation=1, worker_fence=1,
        content_fence="fence", cancel_epoch=0,
        footprint=RecoveryConstraintFootprint(
            "bot/persona", "activity", "effect", communication_action="reply",
            contact_id="contact", segment_id="segment"),
        proactive_contact=False, segment_authorization_ref="manifest",
        segment_manifest_digest=DIGEST, segment_index=0, segment_count=1)


def _receipt(request: DispatchRequest) -> DispatchAdmissionReceiptV1:
    # This test focuses the host gate; the real admission constructor and
    # persistence round trip are exercised by D11's own tests.
    admission = SimpleNamespace(
        namespace=request.namespace, operation_id=request.operation_id,
        effect_id=request.effect_id, activity_id=request.activity_id,
        attempt_id=request.attempt_id, admission_ref="admission",
        digest=DIGEST, request_digest=canonical_digest(request),
        payload_digest=request.payload_digest, account_ref=ACCOUNT,
        destination_ref=DESTINATION, segment_index=0)
    receipt = object.__new__(DispatchAdmissionReceiptV1)
    object.__setattr__(receipt, "admission", admission)
    return receipt


def _ownership(*, state: str = "sylanne_owned") -> ReplyOwnershipReceiptV1:
    return ReplyOwnershipReceiptV1(
        NAMESPACE, "ingress", "handler", state, "reply-op", "effect",
        "admission", DIGEST, "installation", ACCOUNT, DESTINATION, 9999999999.0,
        DIGEST)


class _Graph:
    def __init__(self, *, state: str = "sylanne_owned", destination: str = DESTINATION,
                 outbox: tuple[str, ...] = ("original-outbox",),
                 reject_gate: bool = False) -> None:
        self.calls: list[str] = []
        self.ownership = _ownership(state=state)
        self.reject_gate = reject_gate
        self.request = _request()
        self.admission = _receipt(self.request)
        self.admission.admission.destination_ref = destination
        self.operation = CommitReceipt(
            "committed", "reply-op", DIGEST, "activity", "effect", 1,
            (), (), (), (), outbox)

    def read_reply_ownership_v1(self, authority, lease, **kwargs):
        self.calls.append("read")
        assert kwargs == {"ingress_operation_id": "ingress", "handler_invocation_id": "handler"}
        return self.ownership

    def require_reply_owned_before_dispatch_p2_v1(self, authority, lease, **kwargs):
        self.calls.append("require")
        assert kwargs == {"ingress_operation_id": "ingress", "admission_ref": "admission",
                          "effect_id": "effect"}
        if self.reject_gate:
            raise UnavailableGuard("current reply ownership revoked")
        return self.ownership

    def get_committed_dispatch_for_operation_v2(self, authority, lease, operation_id):
        self.calls.append("dispatch")
        assert operation_id == "reply-op"
        return self.admission, self.request

    def get_operation(self, authority, lease, operation_id):
        self.calls.append("operation")
        assert operation_id == "reply-op"
        return self.operation

    def begin_dispatch_fence(self, *args, **kwargs):
        raise AssertionError("P2 began before a final graph claim")


async def _run(graph: _Graph):
    worker = await GraphWorker.start(lambda: SimpleNamespace(close=lambda: None),
                                     lambda _store: graph)
    try:
        driver = PrivateReplyDispatchDriver(
            worker, SimpleNamespace(namespace=NAMESPACE), object())
        return await driver.run_once(ingress_operation_id="ingress",
                                     handler_invocation_id="handler")
    finally:
        await worker.close()


def test_owned_original_single_private_segment_reaches_explicit_hold() -> None:
    graph = _Graph()
    result = asyncio.run(_run(graph))
    assert result.status == "hold" and "final graph claim" in result.reason
    assert result.original is not None
    assert (result.original.operation_id, result.original.effect_id,
            result.original.admission_ref, result.original.outbox_ref) == (
            "reply-op", "effect", "admission", "original-outbox")
    assert graph.calls == ["read", "require", "dispatch", "operation"]


def test_unowned_reply_stops_before_required_gate_and_p2() -> None:
    graph = _Graph(state="host_default")
    result = asyncio.run(_run(graph))
    assert result.status == "hold" and result.original is None
    assert graph.calls == ["read"]


def test_current_ownership_gate_rejection_is_hold_before_p2() -> None:
    graph = _Graph(reject_gate=True)
    result = asyncio.run(_run(graph))
    assert result.status == "hold" and result.original is None
    assert graph.calls == ["read", "require"]


def test_non_private_route_and_missing_original_outbox_hold() -> None:
    group = json.dumps(["platform:GroupMessage:123456", "conversation"],
                       separators=(",", ":"))
    for graph in (_Graph(destination=group), _Graph(outbox=())):
        result = asyncio.run(_run(graph))
        assert result.status == "hold" and result.original is None
        assert graph.calls == ["read", "require", "dispatch", "operation"]


@pytest.mark.parametrize("error", [
    HandoffUncertain("observation:lost"),
    V2FenceOutcomeUnknown("handoff:lost"),
])
def test_uncertain_handoff_is_reported_unknown_without_retry(error) -> None:
    graph = _Graph()

    async def run():
        worker = await GraphWorker.start(
            lambda: SimpleNamespace(close=lambda: None), lambda _store: graph)
        try:
            authority = SimpleNamespace(namespace=NAMESPACE)
            lease = object()
            continuation = object.__new__(InstalledPrivateReplyContinuationV1)
            continuation._worker = worker
            continuation._authority = authority
            continuation._lease = lease
            calls = []

            async def dispatch(original):
                calls.append(original.effect_id)
                raise error

            continuation.dispatch = dispatch
            async def absent(original):
                return CurrentEffectReadV2(
                    "authority", "ns-a", original.effect_id, 1, "absent", 0, "head")
            continuation.read_recovery_state = absent
            driver = PrivateReplyDispatchDriver(
                worker, authority, lease, continuation)
            result = await driver.run_once(
                ingress_operation_id="ingress", handler_invocation_id="handler")
            return result, calls
        finally:
            await worker.close()

    result, calls = asyncio.run(run())
    assert result.status == "unknown"
    assert result.original is not None
    assert calls == ["effect"]
    assert graph.calls == ["read", "require", "dispatch", "operation"]


@pytest.mark.parametrize("state,status", [("observed", "hold"), ("unresolved", "unknown")])
def test_existing_private_effect_is_read_without_new_handoff(state, status):
    graph = _Graph()
    calls = []

    async def run():
        worker = await GraphWorker.start(
            lambda: SimpleNamespace(close=lambda: None), lambda _store: graph)
        try:
            authority, lease = SimpleNamespace(namespace=NAMESPACE), object()
            continuation = object.__new__(InstalledPrivateReplyContinuationV1)
            continuation._worker, continuation._authority, continuation._lease = worker, authority, lease

            def current(**kwargs):
                calls.append("current")
                assert kwargs == {"namespace": NAMESPACE, "authority_namespace": "ns-a",
                                  "effect_id": "effect"}
                return CurrentEffectReadV2(
                    "authority", "ns-a", "effect", 1, state, 1, "head",
                    observation_id="observation" if state == "observed" else None)

            async def dispatch(original):
                calls.append("dispatch")
                raise AssertionError("existing durable effect must not begin another handoff")

            continuation._policy = SimpleNamespace(namespace=NAMESPACE, authority_namespace="ns-a")
            continuation._grant = SimpleNamespace(authority_id="authority")
            continuation._port = SimpleNamespace(read_current_effect=current)
            continuation.dispatch = dispatch
            return await PrivateReplyDispatchDriver(worker, authority, lease, continuation).run_once(
                ingress_operation_id="ingress", handler_invocation_id="handler")
        finally:
            await worker.close()

    result = asyncio.run(run())
    assert calls == ["current"]
    assert result.status == status
    assert result.original is not None
