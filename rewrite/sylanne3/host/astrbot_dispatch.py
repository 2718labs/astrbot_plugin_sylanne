"""AstrBot 4.28.1 text handoff; delivery remains unobservable here.

The resolver must read a trusted, immutable dispatch payload and its original
AstrBot session binding. This adapter does not turn an ingress or chat setting
into business authorization.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Awaitable, Callable, Protocol

from astrbot.api.star import Context
from astrbot.api.platform import MessageType
from astrbot.core.platform.message_session import MessageSession
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_platform_adapter import AiocqhttpAdapter

from ..dispatch_runtime import (
    DispatchBlocked, DispatchRequest, DispatchUnavailable,
    HandoffUncertain,
)
from ..domains.d09 import ClaimUse, segment_payload_digest
from ..runtime_contracts import NamespaceId
from .current_scene import verify_current_host_scene
from .scene_candidates import ObservedSceneCandidate

from ..authority_service.v2_contract import (
    ExecutionBindingV2, PlatformObservationV2,
    canonical_digest as authority_digest,
)
from ..authority_service.v2_execution_bridge import (
    HandoffStartV2, handoff_start_digest_v2,
)
from ..host.reverse_handoff import HandoffDecisionWindow
from .scene_candidates import SceneCandidateCatalog


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
    """Retired V1 worker port; V2 handoff owns every external send."""

    def __init__(self, *args, **kwargs) -> None:
        raise DispatchUnavailable("V1 AstrBot handoff is retired; use fresh V2 handoff")


class AstrBotV2TextSender:
    """One OneBot send inside a fresh V2 handoff decision window.

    A newly persisted Authority start is the cross-process one-shot gate.
    The OneBot message_id acknowledges acceptance by the adapter;
    it does not establish delivery or reading by the recipient.
    """

    def __init__(self, *, context: Context, candidates: SceneCandidateCatalog,
                 resolver: TextPayloadResolver,
                 record_observation: Callable[
                     [HandoffStartV2, PlatformObservationV2], Awaitable[object]]) -> None:
        if (not isinstance(context, Context)
                or not isinstance(candidates, SceneCandidateCatalog)
                or not callable(getattr(resolver, "resolve", None))
                or not callable(record_observation)):
            raise DispatchUnavailable("V2 sender requires graph resolver and Authority observation writer")
        self._context = context
        self._candidates = candidates
        self._resolver = resolver
        self._record_observation = record_observation

    async def send(self, *, decision: HandoffDecisionWindow,
                   binding: ExecutionBindingV2,
                   request: DispatchRequest) -> PlatformObservationV2:
        if (type(decision) is not HandoffDecisionWindow
                or type(binding) is not ExecutionBindingV2
                or type(request) is not DispatchRequest):
            raise DispatchBlocked("typed fresh V2 handoff, binding and command required")
        origin = binding.origin
        if (request.namespace != binding.graph_namespace
                or request.operation_id != binding.operation_id
                or request.effect_id != origin.effect_id
                or request.activity_id != origin.activity_id
                or request.attempt_id != origin.attempt_id
                or "sha256:" + request.payload_digest != origin.payload_digest
                or request.platform_capability_ref != origin.platform_capability_ref
                or request.dispatch_generation != origin.dispatch_generation
                or request.activation_generation != origin.activation_generation
                or request.worker_fence != origin.worker_fence
                or request.content_fence != origin.content_fence
                or request.cancel_epoch != origin.cancel_epoch
                or request.segment_authorization_ref != origin.segment_authorization_ref
                or ("sha256:" + request.segment_manifest_digest
                    if request.segment_manifest_digest is not None else None)
                   != origin.segment_manifest_digest
                or request.segment_index != origin.segment_index
                or request.segment_count != origin.segment_count):
            raise DispatchBlocked("V2 command differs from the frozen binding")
        resolved = self._resolver.resolve(request)
        if (type(resolved) is not ResolvedTextPayload
                or resolved.namespace != request.namespace
                or type(resolved.payload) is not bytes or resolved.media_refs):
            raise DispatchBlocked("committed finite text segment is unavailable")
        try:
            body = resolved.payload.decode("utf-8", errors="strict")
            session = MessageSession.from_str(resolved.umo)
            payload_digest = segment_payload_digest(
                body, resolved.media_refs, resolved.claim_uses)
            namespace = NamespaceId(*request.namespace.split("/", 1))
        except (ValueError, TypeError, UnicodeError, IndexError) as exc:
            raise DispatchBlocked("committed finite text segment is invalid") from exc
        account_ref = json.dumps(
            [resolved.platform_id, resolved.platform_name, resolved.self_id],
            ensure_ascii=True, separators=(",", ":"))
        destination_ref = json.dumps(
            [resolved.umo, resolved.conversation_id],
            ensure_ascii=True, separators=(",", ":"))
        visibility = {
            MessageType.FRIEND_MESSAGE: "private",
            MessageType.GROUP_MESSAGE: "group",
        }.get(session.message_type)
        if (not body or payload_digest != request.payload_digest
                or account_ref != origin.account_ref
                or destination_ref != origin.destination_ref
                or visibility is None or resolved.platform_name != "aiocqhttp"
                or session.platform_id != resolved.platform_id
                or not session.session_id.isascii()
                or not session.session_id.isdigit()):
            raise DispatchBlocked("committed text or route differs from binding")
        candidate = self._candidates.get_exact(
            namespace=namespace, platform_ref=account_ref,
            conversation_ref=destination_ref, visibility=visibility,
            scene_ref=resolved.scene_ref)
        if (candidate is None
                or await verify_current_host_scene(self._context, candidate) is None):
            raise DispatchBlocked("current observed AstrBot scene is unavailable")
        matching = [platform for platform in self._context.platform_manager.platform_insts
                    if platform.meta().id == resolved.platform_id]
        if len(matching) != 1:
            raise DispatchBlocked("current AstrBot platform is ambiguous")
        adapter = self._context.get_platform_inst(resolved.platform_id)
        if (adapter is not matching[0] or not isinstance(adapter, AiocqhttpAdapter)
                or adapter.meta().name != "aiocqhttp"):
            raise DispatchBlocked("current OneBot adapter differs")

        # The decision window is issued only after Authority persisted the real
        # graph claim and start. Replays cannot take a fresh start.
        start = decision.take_fresh_start()
        graph_receipt = start.graph_claim_receipt
        if (type(start) is not HandoffStartV2 or start.replay
                or graph_receipt is None
                or (start.namespace, start.operation_id, start.effect_id)
                   != (binding.namespace, request.operation_id, request.effect_id)
                or start.binding_digest != authority_digest(binding)
                or start.graph_claim_ref != graph_receipt.graph_claim_ref
                or graph_receipt.graph_namespace != binding.graph_namespace
                or graph_receipt.graph_incarnation != binding.graph_incarnation):
            raise DispatchBlocked("fresh Authority start or committed graph claim differs")
        deadline = datetime.fromisoformat(binding.utc_deadline.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) >= deadline:
            raise DispatchBlocked("fresh handoff deadline expired before external send")
        original_permit = binding.origin.permit
        if (start.permit.authority_id != original_permit.authority_id
                or start.permit.token != original_permit.token
                or start.permit.fence_epoch != original_permit.fence_epoch
                or start.permit.generation != original_permit.generation
                or start.permit.revision != original_permit.revision + 2
                or start.permit.operation_id != original_permit.operation_id
                or start.permit.effect_id != original_permit.effect_id
                or start.permit.command_digest != original_permit.command_digest
                or start.permit.footprint_digest != original_permit.footprint_digest):
            raise DispatchBlocked("fresh start differs from original dispatch permit")

        action = ("send_group_msg" if visibility == "group"
                  else "send_private_msg")
        destination = "group_id" if visibility == "group" else "user_id"
        async def call_onebot():
            return await adapter.bot.call_action(
                action, self_id=resolved.self_id,
                **{destination: int(session.session_id)},
                message=[{"type": "text", "data": {"text": body}}])

        # Shield keeps cancellation from stopping an already issued call and
        # then incorrectly claiming that no external effect was possible.
        task = asyncio.create_task(call_onebot())
        try:
            receipt = await asyncio.shield(task)
            message_id = (receipt.get("message_id")
                          if isinstance(receipt, dict) else None)
            accepted = type(message_id) is int and message_id > 0
        except (Exception, asyncio.CancelledError):
            message_id = None
            accepted = False
        observation = PlatformObservationV2(
            binding=binding, handoff_id=start.handoff_id,
            start_digest=handoff_start_digest_v2(start),
            adapter_ref=origin.adapter_ref, account_ref=account_ref,
            destination_ref=destination_ref,
            observation_id="observation:" + hashlib.sha256(
                start.handoff_id.encode()).hexdigest(),
            platform_request_id=None,
            platform_message_id=(str(message_id) if accepted else None),
            evidence_source_ref="astrbot:onebot:call_action",
            outcome="accepted" if accepted else "unknown",
            observed_at_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            time_source_ref="host:system_utc",
        )
        try:
            await self._record_observation(start, observation)
        except (Exception, asyncio.CancelledError) as exc:
            # The Authority write may have committed despite a lost response.
            # The durable start forbids another platform call either way.
            raise HandoffUncertain(observation.observation_id) from exc
        return observation


__all__ = (
    "AstrBotTextPlatformCapability", "GraphTextPayloadResolver",
    "ResolvedTextPayload", "TextPayloadResolver", "AstrBotV2TextSender",
)
