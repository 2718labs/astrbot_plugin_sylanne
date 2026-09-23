"""AstrBot 4.28.1 text handoff; delivery remains unobservable here.

The resolver must read a trusted, immutable dispatch payload and its original
AstrBot session binding. This adapter does not turn an ingress or chat setting
into business authorization.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import Future
from dataclasses import dataclass
import hashlib
from threading import Lock
from typing import Protocol

from astrbot.api.event import MessageChain
from astrbot.api.star import Context
from astrbot.core.platform.message_session import MessageSession

from ..dispatch_runtime import (
    DispatchBlocked, DispatchRequest, DispatchUnavailable, HandoffStartReceipt,
    HandoffUncertain, PlatformCapabilityDescriptor, PlatformObservation,
)


@dataclass(frozen=True)
class ResolvedTextPayload:
    """Trusted bytes and routing facts bound to one dispatch payload reference."""

    payload: bytes
    namespace: str
    platform_id: str
    self_id: str
    umo: str


class TextPayloadResolver(Protocol):
    def resolve(self, payload_ref: str) -> ResolvedTextPayload: ...


class AstrBotTextPlatformCapability:
    """Synchronous worker port to AstrBot's asynchronous host loop."""

    def __init__(
        self, context: Context, host_loop: asyncio.AbstractEventLoop,
        resolver: TextPayloadResolver, *, capability_ref: str,
        namespace: str, platform_id: str, self_id: str,
        timeout_seconds: float = 30.0,
    ) -> None:
        if not isinstance(context, Context) or not callable(getattr(resolver, "resolve", None)):
            raise DispatchUnavailable("AstrBot Context and trusted payload resolver are required")
        if not isinstance(host_loop, asyncio.AbstractEventLoop) or not host_loop.is_running():
            raise DispatchUnavailable("a running AstrBot host loop is required")
        if not all(isinstance(value, str) and value for value in (namespace, platform_id, self_id)):
            raise ValueError("namespace and platform identity must be nonempty")
        if not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds < float("inf"):
            raise ValueError("timeout_seconds must be finite and positive")
        self.descriptor = PlatformCapabilityDescriptor(
            capability_ref, platform_id, True, False, True,
        )
        self._context = context
        self._loop = host_loop
        self._resolver = resolver
        self._namespace = namespace
        self._platform_id = platform_id
        self._self_id = self_id
        self._timeout_seconds = float(timeout_seconds)
        self._lock = Lock()
        self._attempted: set[str] = set()
        self._pending: dict[str, Future[bool]] = {}

    def handoff(
        self, request: DispatchRequest, start: HandoffStartReceipt,
    ) -> PlatformObservation:
        if not isinstance(request, DispatchRequest) or not isinstance(start, HandoffStartReceipt):
            raise TypeError("handoff requires a dispatch request and start receipt")
        if (request.namespace != self._namespace
                or request.platform_capability_ref != self.descriptor.capability_ref
                or start.operation_id != request.operation_id
                or start.effect_id != request.effect_id
                or start.platform_capability_ref != request.platform_capability_ref):
            raise DispatchBlocked("handoff identity differs from the bound capability")
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is self._loop:
            raise DispatchUnavailable("synchronous handoff cannot wait on the AstrBot host loop")

        resolved = self._resolver.resolve(request.payload_ref)
        if not isinstance(resolved, ResolvedTextPayload):
            raise DispatchBlocked("trusted resolver returned an invalid payload")
        if (resolved.namespace != request.namespace
                or resolved.platform_id != self._platform_id
                or resolved.self_id != self._self_id):
            raise DispatchBlocked("payload routing identity differs from the bound namespace")
        if not isinstance(resolved.payload, bytes) or hashlib.sha256(resolved.payload).hexdigest() != request.payload_digest:
            raise DispatchBlocked("dispatch payload digest differs")
        if not isinstance(resolved.umo, str):
            raise DispatchBlocked("AstrBot session is invalid")
        try:
            text = resolved.payload.decode("utf-8", errors="strict")
            session = MessageSession.from_str(resolved.umo)
        except (UnicodeError, ValueError, TypeError, IndexError) as exc:
            raise DispatchBlocked("payload text or AstrBot session is invalid") from exc
        if not text or session.platform_id != self._platform_id or not session.session_id:
            raise DispatchBlocked("empty text or cross-platform session")
        # The resolver's self_id binds the UMO to the installed bot identity;
        # AstrBot's UMO itself contains only platform id, type and session id.
        observation_ref = "astrbot:handoff:" + hashlib.sha256(
            f"{request.namespace}\0{request.operation_id}".encode()
        ).hexdigest()
        with self._lock:
            if request.operation_id in self._attempted:
                raise HandoffUncertain(observation_ref)
            self._attempted.add(request.operation_id)
            try:
                future = asyncio.run_coroutine_threadsafe(
                    self._send(resolved.umo, text), self._loop,
                )
            except Exception as exc:
                raise HandoffUncertain(observation_ref) from exc
            self._pending[request.operation_id] = future
        future.add_done_callback(lambda done: self._forget_done(request.operation_id, done))
        try:
            matched = future.result(timeout=self._timeout_seconds)
        except Exception as exc:
            # Timeout/cancellation does not stop the host coroutine. The effect
            # may still complete, so the original operation stays unknown.
            raise HandoffUncertain(observation_ref) from exc
        if type(matched) is not bool:
            raise HandoffUncertain(observation_ref)
        return PlatformObservation(
            "handed_off" if matched else "failed", observation_ref, None,
        )

    async def _send(self, umo: str, text: str) -> bool:
        return await self._context.send_message(umo, MessageChain().message(text))

    def _forget_done(self, operation_id: str, future: Future[bool]) -> None:
        with self._lock:
            if self._pending.get(operation_id) is future:
                self._pending.pop(operation_id)

    def query_original(
        self, request: DispatchRequest, operation: object,
    ) -> PlatformObservation:
        raise DispatchUnavailable("AstrBot Context has no original-send query")


__all__ = ("AstrBotTextPlatformCapability", "ResolvedTextPayload", "TextPayloadResolver")
