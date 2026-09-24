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
import json
from threading import Lock
from typing import Protocol

from astrbot.api.star import Context
from astrbot.api.platform import MessageType
from astrbot.core.platform.message_session import MessageSession
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_platform_adapter import AiocqhttpAdapter

from ..dispatch_runtime import (
    DispatchBlocked, DispatchRequest, DispatchUnavailable, HandoffStartReceipt,
    HandoffUncertain, PlatformCapabilityDescriptor, PlatformObservation,
)
from ..domains.d09 import ClaimUse, segment_payload_digest
from ..runtime_contracts import NamespaceId
from .current_scene import verify_current_host_scene
from .scene_candidates import ObservedSceneCandidate


@dataclass(frozen=True)
class ResolvedTextPayload:
    """Trusted D09 text segment and routing facts bound to one payload reference."""

    payload: bytes
    media_refs: tuple[str, ...]
    claim_uses: tuple[ClaimUse, ...]
    namespace: str
    platform_id: str
    platform_name: str
    self_id: str
    umo: str
    conversation_id: str
    scene_ref: str


class TextPayloadResolver(Protocol):
    def resolve(self, request: DispatchRequest) -> ResolvedTextPayload: ...


class GraphTextPayloadResolver:
    """Resolve only a committed D11 admission and its exact D09 graph segment."""

    def __init__(self, coordinator, authority, lease: object) -> None:
        self._coordinator = coordinator
        self._authority = authority
        self._lease = lease

    def resolve(self, request: DispatchRequest) -> ResolvedTextPayload:
        segment = self._coordinator.get_dispatch_text_segment(
            self._authority, self._lease, request,
        )
        if segment is None:
            raise DispatchBlocked("committed dispatch text segment is absent")
        return ResolvedTextPayload(
            segment.body.encode("utf-8"), segment.media_refs,
            segment.claim_uses, request.namespace,
            segment.platform_id, segment.platform_name, segment.self_id,
            segment.umo, segment.conversation_id, segment.scene_ref,
        )


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
        self._pending: dict[str, Future[int | None]] = {}

    def handoff(
        self, request: DispatchRequest, start: HandoffStartReceipt,
    ) -> PlatformObservation:
        if not isinstance(request, DispatchRequest) or not isinstance(start, HandoffStartReceipt):
            raise TypeError("handoff requires a dispatch request and start receipt")
        if (request.namespace != self._namespace
                or request.platform_capability_ref != self.descriptor.capability_ref
                or start.operation_id != request.operation_id
                or start.effect_id != request.effect_id
                or start.platform_capability_ref != request.platform_capability_ref
                or start.dispatch_generation != request.dispatch_generation
                or start.activation_generation != request.activation_generation
                or start.worker_fence != request.worker_fence
                or start.content_fence != request.content_fence
                or start.cancel_epoch != request.cancel_epoch
                or start.proactive_contact != request.proactive_contact
                or start.segment_authorization_ref != request.segment_authorization_ref
                or start.segment_manifest_digest != request.segment_manifest_digest
                or start.segment_index != request.segment_index
                or start.segment_count != request.segment_count):
            raise DispatchBlocked("handoff identity differs from the bound capability")
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is self._loop:
            raise DispatchUnavailable("synchronous handoff cannot wait on the AstrBot host loop")

        resolved = self._resolver.resolve(request)
        if not isinstance(resolved, ResolvedTextPayload):
            raise DispatchBlocked("trusted resolver returned an invalid payload")
        if (resolved.namespace != request.namespace
                or resolved.platform_id != self._platform_id
                or resolved.self_id != self._self_id):
            raise DispatchBlocked("payload routing identity differs from the bound namespace")
        if type(resolved.payload) is not bytes or resolved.media_refs:
            raise DispatchBlocked("dispatch route requires text without media")
        if not isinstance(resolved.umo, str):
            raise DispatchBlocked("AstrBot session is invalid")
        try:
            text = resolved.payload.decode("utf-8", errors="strict")
            session = MessageSession.from_str(resolved.umo)
        except (UnicodeError, ValueError, TypeError, IndexError) as exc:
            raise DispatchBlocked("payload text or AstrBot session is invalid") from exc
        try:
            digest = segment_payload_digest(text, resolved.media_refs, resolved.claim_uses)
        except (ValueError, TypeError) as exc:
            raise DispatchBlocked("resolved D09 segment metadata is invalid") from exc
        if digest != request.payload_digest:
            raise DispatchBlocked("dispatch payload digest differs")
        if (not text or session.platform_id != self._platform_id
                or session.message_type not in {MessageType.FRIEND_MESSAGE, MessageType.GROUP_MESSAGE}
                or not session.session_id.isascii() or not session.session_id.isdigit()):
            raise DispatchBlocked("empty text or cross-platform session")
        namespace_parts = request.namespace.split("/", 1)
        if len(namespace_parts) != 2 or not all(namespace_parts):
            raise DispatchBlocked("dispatch namespace has no AstrBot bot and persona")
        namespace = NamespaceId(*namespace_parts)
        candidate = ObservedSceneCandidate(
            namespace,
            json.dumps([resolved.platform_id, resolved.platform_name, resolved.self_id],
                       ensure_ascii=True, separators=(",", ":")),
            json.dumps([resolved.umo, resolved.conversation_id],
                       ensure_ascii=True, separators=(",", ":")),
            "group" if session.message_type == MessageType.GROUP_MESSAGE else "private",
            resolved.scene_ref,
        )
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
                    self._send(session, text, candidate), self._loop,
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
        if matched is None:
            return PlatformObservation("failed", observation_ref, None)
        if type(matched) is not int or matched <= 0:
            raise HandoffUncertain(observation_ref)
        return PlatformObservation(
            "handed_off", observation_ref, self._provider_request_ref(matched),
        )

    def _provider_request_ref(self, message_id: int) -> str:
        scope = f"{self._platform_id}\0{self._self_id}"
        scope_digest = hashlib.sha256(scope.encode("utf-8")).hexdigest()
        return f"astrbot:onebot:{scope_digest}:{message_id}"

    async def _send(
        self, session: MessageSession, text: str, candidate: ObservedSceneCandidate,
    ) -> int | None:
        if await verify_current_host_scene(self._context, candidate) is None:
            return None
        # Context.send_message selects only the platform instance. OneBot may
        # have multiple accounts on that instance, so every action specifies
        # and revalidates the original account before the external handoff.
        matching = [
            platform for platform in self._context.platform_manager.platform_insts
            if platform.meta().id == self._platform_id
        ]
        if len(matching) != 1:
            return None
        adapter = self._context.get_platform_inst(self._platform_id)
        if (adapter is not matching[0] or not isinstance(adapter, AiocqhttpAdapter)
                or adapter.meta().id != self._platform_id
                or adapter.meta().name != "aiocqhttp"):
            return None
        action = (
            "send_group_msg" if session.message_type == MessageType.GROUP_MESSAGE
            else "send_private_msg"
        )
        destination = (
            "group_id" if session.message_type == MessageType.GROUP_MESSAGE
            else "user_id"
        )
        receipt = await adapter.bot.call_action(
            action, self_id=self._self_id,
            **{destination: int(session.session_id)},
            message=[{"type": "text", "data": {"text": text}}],
        )
        if (not isinstance(receipt, dict) or type(receipt.get("message_id")) is not int
                or receipt["message_id"] <= 0):
            # The API call may have reached OneBot. An absent or malformed
            # receipt cannot prove failure and must keep this operation unknown.
            raise ValueError("OneBot send receipt lacks a valid message_id")
        return receipt["message_id"]

    def _forget_done(self, operation_id: str, future: Future[int | None]) -> None:
        with self._lock:
            if self._pending.get(operation_id) is future:
                self._pending.pop(operation_id)

    def query_original(
        self, request: DispatchRequest, operation: object,
    ) -> PlatformObservation:
        raise DispatchUnavailable("AstrBot Context has no original-send query")


__all__ = (
    "AstrBotTextPlatformCapability", "GraphTextPayloadResolver",
    "ResolvedTextPayload", "TextPayloadResolver",
)
