"""AstrBot handler stop evidence is one-shot and never dispatch authority."""

import asyncio
from dataclasses import replace
import time

import pytest
from astrbot.api.event import AstrMessageEvent

from sylanne3.host.ingress import HostIngressEnvelope, IngressReceipt, SourceLineage
from sylanne3.host.reply_suppression import (
    HostReplySuppressionAckV1, HostReplySuppressionRegistryV1,
    HostReplySuppressionWindowV1,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


class _LiveEvent(AstrMessageEvent):
    """Only the real AstrBot stop/is_stopped surface is exercised here."""

    def __init__(self, *, confirms=True):
        self._force_stopped = False
        self._result = None
        self.stops = 0
        self.confirms = confirms

    def stop_event(self):
        self.stops += 1
        if self.confirms:
            super().stop_event()


def _envelope(*, visibility="private"):
    return HostIngressEnvelope(
        NamespaceId("bot", "persona"),
        '["platform-1","aiocqhttp","bot-1"]',
        '["platform-1:FriendMessage:123456","conversation-1"]',
        '["platform-1","user-1"]', "message-1", "hello", 1.0, 2.0,
        visibility, SourceLineage("a" * 64, "reported", "onebot",
                                  "external_report", "reported_claim"),
    )


def _window(event, envelope=None, receipt=None):
    return HostReplySuppressionWindowV1(
        event=event, envelope=envelope or _envelope(),
        receipt=receipt or IngressReceipt("accepted", "ingress:one"),
        installation_id="install:one", handler_invocation_id="handler:one",
        handler_nonce="nonce:one")


@pytest.mark.asyncio
async def test_admitted_private_handler_stop_is_confirmed_once():
    event = _LiveEvent()
    envelope = _envelope()
    window = _window(event, envelope)
    evidence = window.suppress_for_admission(
        admission_ref="admission:one", admission_digest="b" * 64)
    assert event.is_stopped() and event.stops == 1
    assert evidence.stop_confirmed
    assert evidence.ingress_envelope_digest == canonical_digest(envelope)
    assert evidence.destination_ref == envelope.conversation_ref
    with pytest.raises(RuntimeError, match="unavailable"):
        window.suppress_for_admission(
            admission_ref="admission:one", admission_digest="b" * 64)
    assert event.stops == 1


@pytest.mark.asyncio
async def test_timeout_hold_or_late_background_task_cannot_stop_event():
    event = _LiveEvent()
    window = _window(event)
    async def late_background():
        with pytest.raises(RuntimeError, match="unavailable"):
            window.suppress_for_admission(
                admission_ref="admission:one", admission_digest="b" * 64)
    await asyncio.create_task(late_background())
    window.close()  # Handler returned on the default AstrBot path.
    with pytest.raises(RuntimeError, match="unavailable"):
        window.suppress_for_admission(
            admission_ref="admission:one", admission_digest="b" * 64)
    assert event.stops == 0 and not event.is_stopped()


@pytest.mark.asyncio
async def test_unadmitted_or_unconfirmed_stop_has_no_evidence():
    event = _LiveEvent()
    with pytest.raises(ValueError, match="private handler"):
        _window(event, _envelope(visibility="group"))
    with pytest.raises(ValueError, match="private handler"):
        _window(event, receipt=IngressReceipt("duplicate", "ingress:one"))
    window = _window(event)
    with pytest.raises(ValueError, match="admitted reply"):
        window.suppress_for_admission(admission_ref="", admission_digest="")
    with pytest.raises(ValueError, match="admitted reply"):
        window.suppress_for_admission(
            admission_ref="admission:one", admission_digest="sha256:" + "b" * 64)
    assert event.stops == 0
    failed = _LiveEvent(confirms=False)
    window = _window(failed)
    with pytest.raises(RuntimeError, match="did not confirm"):
        window.suppress_for_admission(
            admission_ref="admission:one", admission_digest="b" * 64)
    assert failed.stops == 1 and not failed.is_stopped()
    with pytest.raises(RuntimeError, match="unavailable"):
        window.suppress_for_admission(
            admission_ref="admission:one", admission_digest="b" * 64)


@pytest.mark.asyncio
async def test_only_live_original_stop_object_can_issue_one_graph_ack():
    registry = HostReplySuppressionRegistryV1()
    event = _LiveEvent()
    envelope = _envelope()
    deadline = time.time() + 20
    window = HostReplySuppressionWindowV1(
        event=event, envelope=envelope,
        receipt=IngressReceipt("accepted", "ingress:one"),
        installation_id="install:one", handler_invocation_id="handler:one",
        handler_nonce="nonce:one", registry=registry,
        handler_deadline_utc=deadline)
    kwargs = dict(
        namespace=envelope.namespace, ingress_operation_id="ingress:one",
        handler_invocation_id="handler:one", admission_ref="admission:one",
        admission_digest="b" * 64,
        installation_id="install:one", account_ref=envelope.platform_ref,
        destination_ref=envelope.conversation_ref,
        handler_deadline_utc=deadline)
    async with window:
        evidence = window.suppress_for_admission(
            admission_ref=kwargs["admission_ref"],
            admission_digest=kwargs["admission_digest"])
        with pytest.raises(RuntimeError, match="not live"):
            registry.verify_and_consume(replace(evidence), **kwargs)
        with pytest.raises(RuntimeError, match="identity differs"):
            registry.verify_and_consume(
                evidence, **(kwargs | {"destination_ref": "another"}))
        ack = registry.verify_and_consume(evidence, **kwargs)
        assert type(ack) is HostReplySuppressionAckV1
        assert ack.ingress_envelope_digest == canonical_digest(envelope)
        assert ack.proof_digest.startswith("sha256:")
        with pytest.raises(RuntimeError, match="not live"):
            registry.verify_and_consume(evidence, **kwargs)
    assert event.stops == 1


@pytest.mark.asyncio
async def test_expired_registered_handler_keeps_astrbot_default_available():
    event = _LiveEvent()
    window = HostReplySuppressionWindowV1(
        event=event, envelope=_envelope(),
        receipt=IngressReceipt("accepted", "ingress:one"),
        installation_id="install:one", handler_invocation_id="handler:one",
        handler_nonce="nonce:one", registry=HostReplySuppressionRegistryV1(),
        handler_deadline_utc=time.time() - 1)
    async with window:
        with pytest.raises(RuntimeError, match="deadline passed"):
            window.suppress_for_admission(
                admission_ref="admission:one",
                admission_digest="b" * 64)
    assert event.stops == 0 and not event.is_stopped()
