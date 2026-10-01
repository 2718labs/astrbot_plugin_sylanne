"""Contract tests; the simulated port is not a production ownership issuer."""

import asyncio

import pytest

from sylanne3.host.ingress import IngressReceipt
from sylanne3.host.reply_takeover import (
    HostReplyTakeoverReadyV1, rendezvous_private_reply_v1,
)
from sylanne3.runtime.post_c02_reply_ownership_v1 import ReplyOwnershipReceiptV1

from rewrite.host_tests.alpha1.test_reply_suppression import _LiveEvent, _envelope


class _SimulatedW01Port:
    def __init__(self, *, ready=None, delay=0, activation=None, recovery=None):
        self.ready = ready
        self.delay = delay
        self.activation = activation
        self.recovery = recovery
        self.closed = []
        self.activated = []
        self.recovered = []

    async def wait_for_durable_admission_v1(self, **identity):
        await asyncio.sleep(self.delay)
        return self.ready

    async def close_host_default_v1(self, **identity):
        self.closed.append(identity)
        return "closed"

    async def activate_reply_ownership_v1(self, **identity):
        self.activated.append(identity)
        if isinstance(self.activation, Exception):
            raise self.activation
        return self.activation

    async def recover_reply_ownership_v1(self, **identity):
        self.recovered.append(identity)
        return self.recovery


def _ready(envelope):
    return HostReplyTakeoverReadyV1(
        "ingress:one", "admission:one", "b" * 64,
        "install:one", envelope.platform_ref, envelope.conversation_ref)


def _owned(envelope, **changes):
    ready = _ready(envelope)
    values = dict(
        namespace=envelope.namespace,
        ingress_operation_id=ready.ingress_operation_id,
        handler_invocation_id="handler:one",
        state="sylanne_owned",
        reply_operation_id="reply:one",
        effect_id="effect:one",
        admission_ref=ready.admission_ref,
        admission_digest=ready.admission_digest,
        installation_id=ready.installation_id,
        account_ref=ready.account_ref,
        destination_ref=ready.destination_ref,
        handler_deadline_utc=None,
        ack_digest="sha256:" + "a" * 64,
    )
    return ReplyOwnershipReceiptV1(**(values | changes))


async def _run(event, envelope, port, *, seconds=1.0):
    return await rendezvous_private_reply_v1(
        event=event, envelope=envelope,
        ingress_receipt=IngressReceipt("accepted", "ingress:one"),
        installation_id="install:one", handler_invocation_id="handler:one",
        handler_nonce="nonce:one", port=port,
        deadline_monotonic=asyncio.get_running_loop().time() + seconds,
        close_timeout_seconds=0.05, activation_timeout_seconds=0.05)


@pytest.mark.asyncio
async def test_timeout_preserves_default_and_closes_original_invocation():
    event = _LiveEvent()
    envelope = _envelope()
    port = _SimulatedW01Port(ready=_ready(envelope), delay=0.2)
    outcome = await _run(event, envelope, port, seconds=0.05)
    assert outcome.status == "host_default"
    assert not event.is_stopped() and event.stops == 0
    assert port.closed == [{
        "ingress_operation_id": "ingress:one",
        "handler_invocation_id": "handler:one"}]
    assert port.activated == []


@pytest.mark.asyncio
async def test_matching_ready_stops_once_before_activation():
    event = _LiveEvent()
    envelope = _envelope()
    port = _SimulatedW01Port(ready=_ready(envelope), activation="simulated")
    outcome = await _run(event, envelope, port)
    assert outcome.status == "activation_unverified"
    assert event.is_stopped() and event.stops == 1
    assert port.closed == [] and len(port.activated) == 1
    assert port.activated[0]["evidence"].stop_confirmed


@pytest.mark.asyncio
async def test_only_exact_owned_receipt_allows_dispatch_continuation():
    envelope = _envelope()
    for receipt, expected in (
        (_owned(envelope), "sylanne_owned"),
        (_owned(envelope, state="awaiting_host_takeover"), "activation_unverified"),
        (_owned(envelope, effect_id=None), "activation_unverified"),
        (_owned(envelope, destination_ref="another"), "activation_unverified"),
        (_owned(envelope, ack_digest=None), "activation_unverified"),
    ):
        event = _LiveEvent()
        port = _SimulatedW01Port(ready=_ready(envelope), activation=receipt)
        outcome = await _run(event, envelope, port)
        assert outcome.status == expected
        assert event.is_stopped() and event.stops == 1


@pytest.mark.asyncio
async def test_stopped_then_lost_cas_response_is_unknown_without_default():
    event = _LiveEvent()
    envelope = _envelope()
    port = _SimulatedW01Port(
        ready=_ready(envelope), activation=RuntimeError("response lost"))
    outcome = await _run(event, envelope, port)
    assert outcome.status == "takeover_unknown"
    assert event.is_stopped() and event.stops == 1
    assert port.closed == [] and len(port.activated) == 1


@pytest.mark.asyncio
async def test_lost_cas_response_recovers_only_the_original_owned_receipt():
    envelope = _envelope()
    event = _LiveEvent()
    port = _SimulatedW01Port(
        ready=_ready(envelope), activation=RuntimeError("response lost"),
        recovery=_owned(envelope))
    outcome = await _run(event, envelope, port)
    assert outcome.status == "sylanne_owned"
    assert event.is_stopped() and event.stops == 1
    assert port.recovered == [{
        "ingress_operation_id": "ingress:one",
        "handler_invocation_id": "handler:one"}]

    wrong = _SimulatedW01Port(
        ready=_ready(envelope), activation=RuntimeError("response lost"),
        recovery=_owned(envelope, handler_invocation_id="handler:other"))
    assert (await _run(_LiveEvent(), envelope, wrong)).status == "takeover_unknown"


@pytest.mark.asyncio
async def test_wrong_route_never_stops_event():
    event = _LiveEvent()
    envelope = _envelope()
    ready = _ready(envelope)
    port = _SimulatedW01Port(ready=HostReplyTakeoverReadyV1(
        ready.ingress_operation_id, ready.admission_ref, ready.admission_digest,
        ready.installation_id, ready.account_ref, "other"))
    outcome = await _run(event, envelope, port)
    assert outcome.status == "host_default"
    assert not event.is_stopped() and event.stops == 0
    assert len(port.closed) == 1 and port.activated == []
