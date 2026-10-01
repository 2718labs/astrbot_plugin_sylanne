"""Handler-local proof that AstrBot actually suppressed one private ingress.

This is evidence for a future graph ownership CAS, not dispatch authority.  In
particular, constructing or retaining this value cannot enable platform send.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import math
import secrets
import threading

from astrbot.api.event import AstrMessageEvent

from ..runtime_contracts import NamespaceId, canonical_digest
from .ingress import HostIngressEnvelope, IngressReceipt


@dataclass(frozen=True, slots=True)
class HostReplySuppressionEvidenceV1:
    ingress_operation_id: str
    ingress_envelope_digest: str
    handler_invocation_id: str
    handler_nonce: str
    installation_id: str
    admission_ref: str
    admission_digest: str
    account_ref: str
    destination_ref: str
    stopped_at_utc: str
    stop_confirmed: bool


@dataclass(frozen=True, slots=True)
class HostReplySuppressionAckV1:
    """One consumed, handler-local stop proof for the graph ownership CAS."""

    namespace: NamespaceId
    ingress_operation_id: str
    ingress_envelope_digest: str
    handler_invocation_id: str
    installation_id: str
    admission_ref: str
    admission_digest: str
    account_ref: str
    destination_ref: str
    stopped_at_utc: str
    proof_digest: str


@dataclass(slots=True)
class _LiveSuppression:
    window: HostReplySuppressionWindowV1
    deadline_utc: float
    secret: str
    evidence: HostReplySuppressionEvidenceV1 | None = None


class HostReplySuppressionRegistryV1:
    """Private, one-process capability registry for the original handler."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._live: dict[tuple[str, str, str, str], _LiveSuppression] = {}

    @staticmethod
    def _key(namespace: NamespaceId, ingress_operation_id: str,
             handler_invocation_id: str) -> tuple[str, str, str, str]:
        return (*namespace.as_tuple, ingress_operation_id, handler_invocation_id)

    def _register(self, window: HostReplySuppressionWindowV1,
                  deadline_utc: float) -> None:
        key = self._key(window._envelope.namespace,
                        window._receipt.operation_id,
                        window._handler_invocation_id)
        with self._lock:
            if key in self._live:
                raise RuntimeError("reply handler capability already registered")
            self._live[key] = _LiveSuppression(
                window, deadline_utc, secrets.token_hex(32))

    def _record(self, window: HostReplySuppressionWindowV1,
                evidence: HostReplySuppressionEvidenceV1) -> None:
        key = self._key(window._envelope.namespace,
                        window._receipt.operation_id,
                        window._handler_invocation_id)
        with self._lock:
            live = self._live.get(key)
            if live is None or live.window is not window or live.evidence is not None:
                raise RuntimeError("reply handler stop capability is unavailable")
            live.evidence = evidence

    def _revoke(self, window: HostReplySuppressionWindowV1) -> None:
        key = self._key(window._envelope.namespace,
                        window._receipt.operation_id,
                        window._handler_invocation_id)
        with self._lock:
            live = self._live.get(key)
            if live is not None and live.window is window:
                del self._live[key]

    def verify_and_consume(
        self, evidence: HostReplySuppressionEvidenceV1, *,
        namespace: NamespaceId, ingress_operation_id: str,
        handler_invocation_id: str, admission_ref: str,
        admission_digest: str, installation_id: str, account_ref: str,
        destination_ref: str, handler_deadline_utc: float,
    ) -> HostReplySuppressionAckV1:
        """Consume only the exact object emitted after this live task stopped."""
        if (type(evidence) is not HostReplySuppressionEvidenceV1
                or type(namespace) is not NamespaceId
                or type(handler_deadline_utc) not in (int, float)
                or not math.isfinite(handler_deadline_utc)):
            raise RuntimeError("reply suppression proof is invalid")
        key = self._key(namespace, ingress_operation_id, handler_invocation_id)
        with self._lock:
            live = self._live.get(key)
            if live is None or live.evidence is not evidence:
                raise RuntimeError("reply suppression proof is not live")
            window = live.window
            if (window._closed or not window._used
                    or not window._event.is_stopped()
                    or live.deadline_utc != handler_deadline_utc
                    or evidence.stop_confirmed is not True
                    or (evidence.ingress_operation_id,
                        evidence.ingress_envelope_digest,
                        evidence.handler_invocation_id,
                        evidence.installation_id,
                        evidence.admission_ref, evidence.admission_digest,
                        evidence.account_ref, evidence.destination_ref) != (
                        ingress_operation_id,
                        canonical_digest(window._envelope),
                        handler_invocation_id, installation_id,
                        admission_ref, admission_digest,
                        account_ref, destination_ref)
                    or window._installation_id != installation_id
                    or window._envelope.platform_ref != account_ref
                    or window._envelope.conversation_ref != destination_ref):
                raise RuntimeError("reply suppression proof identity differs")
            try:
                stopped_at = datetime.fromisoformat(
                    evidence.stopped_at_utc.replace("Z", "+00:00"))
            except ValueError as exc:
                raise RuntimeError("reply suppression stop time is invalid") from exc
            if (stopped_at.tzinfo is None
                    or stopped_at.timestamp() > handler_deadline_utc):
                raise RuntimeError("reply suppression stop missed its handler deadline")
            proof_digest = "sha256:" + canonical_digest({
                "schema": "sylanne.host_reply_suppression_ack.v1",
                "secret": live.secret, "namespace": namespace,
                "evidence": evidence,
            })
            del self._live[key]
            return HostReplySuppressionAckV1(
                namespace, ingress_operation_id,
                evidence.ingress_envelope_digest, handler_invocation_id,
                installation_id, admission_ref, admission_digest,
                account_ref, destination_ref, evidence.stopped_at_utc,
                proof_digest)


class HostReplySuppressionWindowV1:
    """One synchronous stop opportunity owned by the current AstrBot handler.

    Open at handler entry and close in its ``finally`` block.  A background
    continuation cannot stop the event after the handler has returned.
    """

    def __init__(self, *, event: AstrMessageEvent,
                 envelope: HostIngressEnvelope, receipt: IngressReceipt,
                 installation_id: str, handler_invocation_id: str,
                 handler_nonce: str,
                 registry: HostReplySuppressionRegistryV1 | None = None,
                 handler_deadline_utc: float | None = None) -> None:
        task = asyncio.current_task()
        if (not isinstance(event, AstrMessageEvent)
                or type(envelope) is not HostIngressEnvelope
                or type(receipt) is not IngressReceipt
                or receipt.status != "accepted"
                or envelope.visibility != "private"
                or task is None
                or any(type(value) is not str or not value or len(value) > 255
                       for value in (installation_id, handler_invocation_id,
                                     handler_nonce))):
            raise ValueError("current accepted private handler is required")
        self._event = event
        self._envelope = envelope
        self._receipt = receipt
        self._installation_id = installation_id
        self._handler_invocation_id = handler_invocation_id
        self._handler_nonce = handler_nonce
        self._task = task
        self._closed = False
        self._used = False
        if registry is not None and (type(registry) is not HostReplySuppressionRegistryV1
                                     or type(handler_deadline_utc) not in (int, float)
                                     or not math.isfinite(handler_deadline_utc)):
            raise ValueError("registered reply handler deadline is required")
        self._registry = registry
        self._handler_deadline_utc = handler_deadline_utc

    def close(self) -> None:
        self._closed = True
        if self._registry is not None:
            self._registry._revoke(self)

    async def __aenter__(self) -> HostReplySuppressionWindowV1:
        if self._registry is not None:
            self._registry._register(self, self._handler_deadline_utc)
        return self

    async def __aexit__(self, *_exc: object) -> None:
        self.close()

    def suppress_for_admission(self, *, admission_ref: str,
                               admission_digest: str) -> HostReplySuppressionEvidenceV1:
        if (self._closed or self._used
                or asyncio.current_task() is not self._task
                or self._event.is_stopped()):
            raise RuntimeError("private handler stop opportunity is unavailable")
        if (type(admission_ref) is not str or not admission_ref
                or type(admission_digest) is not str
                or len(admission_digest) != 64
                or any(character not in "0123456789abcdef"
                       for character in admission_digest)):
            raise ValueError("typed admitted reply identity is required")
        if (self._handler_deadline_utc is not None
                and datetime.now(timezone.utc).timestamp()
                    >= self._handler_deadline_utc):
            raise RuntimeError("private handler stop deadline passed")
        self._used = True
        self._event.stop_event()
        if not self._event.is_stopped():
            raise RuntimeError("AstrBot did not confirm event suppression")
        evidence = HostReplySuppressionEvidenceV1(
            ingress_operation_id=self._receipt.operation_id,
            ingress_envelope_digest=canonical_digest(self._envelope),
            handler_invocation_id=self._handler_invocation_id,
            handler_nonce=self._handler_nonce,
            installation_id=self._installation_id,
            admission_ref=admission_ref,
            admission_digest=admission_digest,
            account_ref=self._envelope.platform_ref,
            destination_ref=self._envelope.conversation_ref,
            stopped_at_utc=datetime.now(timezone.utc).isoformat(
                timespec="microseconds").replace("+00:00", "Z"),
            stop_confirmed=True,
        )
        if self._registry is not None:
            self._registry._record(self, evidence)
        return evidence


__all__ = (
    "HostReplySuppressionEvidenceV1", "HostReplySuppressionAckV1",
    "HostReplySuppressionRegistryV1", "HostReplySuppressionWindowV1",
)
