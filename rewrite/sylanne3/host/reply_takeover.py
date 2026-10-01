"""Bounded, handler-local AstrBot reply ownership rendezvous.

The port must be backed by W01 durable graph reads and compare-and-set writes.
This module has no production port implementation and cannot dispatch text.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import math
from typing import Protocol

from astrbot.api.event import AstrMessageEvent

from ..runtime.post_c02_reply_ownership_v1 import ReplyOwnershipReceiptV1
from .ingress import HostIngressEnvelope, IngressReceipt
from .reply_suppression import (
    HostReplySuppressionEvidenceV1, HostReplySuppressionRegistryV1,
    HostReplySuppressionWindowV1,
)


@dataclass(frozen=True, slots=True)
class HostReplyTakeoverReadyV1:
    """Identity W01 must certify from the original durable reply operation."""

    ingress_operation_id: str
    admission_ref: str
    admission_digest: str
    installation_id: str
    account_ref: str
    destination_ref: str


class HostReplyTakeoverPortV1(Protocol):
    async def wait_for_durable_admission_v1(
        self, *, ingress_operation_id: str,
        handler_invocation_id: str,
    ) -> HostReplyTakeoverReadyV1 | None: ...

    async def close_host_default_v1(
        self, *, ingress_operation_id: str,
        handler_invocation_id: str,
    ) -> object: ...

    async def activate_reply_ownership_v1(
        self, *, ready: HostReplyTakeoverReadyV1,
        evidence: HostReplySuppressionEvidenceV1,
    ) -> object: ...

    async def recover_reply_ownership_v1(
        self, *, ingress_operation_id: str,
        handler_invocation_id: str,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class HostReplyTakeoverResultV1:
    status: str


async def rendezvous_private_reply_v1(
    *, event: AstrMessageEvent, envelope: HostIngressEnvelope,
    ingress_receipt: IngressReceipt, installation_id: str,
    handler_invocation_id: str, handler_nonce: str,
    port: HostReplyTakeoverPortV1,
    deadline_monotonic: float, close_timeout_seconds: float,
    activation_timeout_seconds: float,
    suppression_registry: HostReplySuppressionRegistryV1 | None = None,
    handler_deadline_utc: float | None = None,
) -> HostReplyTakeoverResultV1:
    """Wait for W01 admission and stop AstrBot only while this handler owns it.

    A lost activation response remains unknown even if W01 committed.  This
    caller must not infer ownership from the local stop acknowledgement.
    """
    loop = asyncio.get_running_loop()
    if (type(deadline_monotonic) not in (int, float)
            or not math.isfinite(deadline_monotonic)
            or deadline_monotonic <= 0
            or any(type(value) not in (int, float) or not math.isfinite(value)
                   or not 0 < value <= 30 for value in (
                       close_timeout_seconds, activation_timeout_seconds))):
        raise ValueError("installed handler wait bounds are required")
    if not all(callable(getattr(port, name, None)) for name in (
            "wait_for_durable_admission_v1", "close_host_default_v1",
            "activate_reply_ownership_v1", "recover_reply_ownership_v1")):
        raise TypeError("installed W01 ownership port is required")

    async with HostReplySuppressionWindowV1(
        event=event, envelope=envelope, receipt=ingress_receipt,
        installation_id=installation_id,
        handler_invocation_id=handler_invocation_id,
        handler_nonce=handler_nonce,
        registry=suppression_registry,
        handler_deadline_utc=handler_deadline_utc,
    ) as window:
        async def host_default() -> HostReplyTakeoverResultV1:
            try:
                async with asyncio.timeout(close_timeout_seconds):
                    await port.close_host_default_v1(
                        ingress_operation_id=ingress_receipt.operation_id,
                        handler_invocation_id=handler_invocation_id)
            except Exception:
                # No ownership receipt exists; W01 must reject late send.
                pass
            return HostReplyTakeoverResultV1("host_default")

        try:
            if loop.time() >= deadline_monotonic:
                return await host_default()
            async with asyncio.timeout_at(deadline_monotonic):
                ready = await port.wait_for_durable_admission_v1(
                    ingress_operation_id=ingress_receipt.operation_id,
                    handler_invocation_id=handler_invocation_id)
        except TimeoutError:
            return await host_default()
        except Exception:
            return await host_default()
        if (type(ready) is not HostReplyTakeoverReadyV1
                or ready.ingress_operation_id != ingress_receipt.operation_id
                or ready.installation_id != installation_id
                or ready.account_ref != envelope.platform_ref
                or ready.destination_ref != envelope.conversation_ref
                or loop.time() >= deadline_monotonic):
            return await host_default()
        try:
            evidence = window.suppress_for_admission(
                admission_ref=ready.admission_ref,
                admission_digest=ready.admission_digest)
        except Exception:
            if event.is_stopped():
                return HostReplyTakeoverResultV1("takeover_unknown")
            return await host_default()
        def matches_owned(committed: object) -> bool:
            return (type(committed) is ReplyOwnershipReceiptV1
                and committed.state == "sylanne_owned"
                and committed.namespace == envelope.namespace
                and committed.ingress_operation_id == ingress_receipt.operation_id
                and committed.handler_invocation_id == handler_invocation_id
                and evidence.stop_confirmed is True
                and event.is_stopped()
                and committed.admission_ref == ready.admission_ref
                and committed.admission_digest == ready.admission_digest
                and committed.installation_id == installation_id
                and committed.account_ref == envelope.platform_ref
                and committed.destination_ref == envelope.conversation_ref
                and committed.handler_deadline_utc == handler_deadline_utc
                and type(committed.reply_operation_id) is str
                and bool(committed.reply_operation_id)
                and type(committed.effect_id) is str
                and bool(committed.effect_id)
                and type(committed.ack_digest) is str
                and committed.ack_digest.startswith("sha256:")
                and len(committed.ack_digest) == 71)

        try:
            async with asyncio.timeout(activation_timeout_seconds):
                committed = await port.activate_reply_ownership_v1(
                    ready=ready, evidence=evidence)
        except Exception:
            committed = None
        # An activation response can be lost after the durable CAS. Read only
        # the original handler's graph receipt; a missing or stale read stays
        # unknown. The sender still performs a separate current fenced claim.
        if not matches_owned(committed):
            try:
                async with asyncio.timeout(activation_timeout_seconds):
                    recovered = await port.recover_reply_ownership_v1(
                        ingress_operation_id=ingress_receipt.operation_id,
                        handler_invocation_id=handler_invocation_id)
            except Exception:
                recovered = None
            if matches_owned(recovered):
                committed = recovered
        if matches_owned(committed):
            return HostReplyTakeoverResultV1("sylanne_owned")
        return HostReplyTakeoverResultV1("activation_unverified" if committed is not None
                                         else "takeover_unknown")


__all__ = (
    "HostReplyTakeoverPortV1", "HostReplyTakeoverReadyV1",
    "HostReplyTakeoverResultV1", "rendezvous_private_reply_v1",
)
