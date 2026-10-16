"""AstrBot 4.28.1 text handoff; delivery remains unobservable here.

The resolver must read a trusted, immutable dispatch payload and its original
AstrBot session binding. This adapter does not turn an ingress or chat setting
into business authorization.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
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
from ..runtime.dispatch_candidate import (
    GraphDispatchTextSegmentV1, NaturalDispatchCandidateEvidenceV2,
    natural_dispatch_segment_payload_ref_v2,
)
from ..runtime_contracts import NamespaceId
from .current_scene import verify_current_host_scene
from .scene_candidates import ObservedSceneCandidate

from ..authority_service.v2_contract import (
    ExecutionBindingV2, FencePermitV2, MutationReceiptV2,
    PlatformObservationV2,
    canonical_digest as authority_digest,
)
from ..authority_service.v2_execution_bridge import (
    CurrentEffectReadV2, HandoffStartV2, handoff_start_digest_v2,
)
from ..host.reverse_handoff import HandoffDecisionWindow
from ..host.authority_profile import AdminIngressClockPolicy
from ..host.v2_fence_port import VerifiedIngressClockV2
from ..runtime.first_ingress_v2 import trusted_upper
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import canonical_digest
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


class NaturalGraphTextPayloadResolver:
    """Adapt W01's committed V2 batch read to the existing one-shot sender.

    This is a content read only. The final Authority P2/claim/start window still
    decides whether this exact original effect may reach the platform.
    """

    def __init__(self, coordinator, authority, lease: object) -> None:
        self._coordinator = coordinator
        self._authority = authority
        self._lease = lease

    def resolve(self, request: DispatchRequest) -> ResolvedTextPayload:
        read = getattr(self._coordinator, "get_natural_dispatch_text_segment_v2", None)
        if not callable(read):
            raise DispatchBlocked("committed natural dispatch read is unavailable")
        result = read(self._authority, self._lease, request)
        if (type(result) is not tuple or len(result) != 2
                or type(result[0]) is not GraphDispatchTextSegmentV1
                or type(result[1]) is not NaturalDispatchCandidateEvidenceV2):
            raise DispatchBlocked("committed natural dispatch evidence is unavailable")
        segment, evidence = result
        try:
            payload_ref = natural_dispatch_segment_payload_ref_v2(
                evidence.batch_ref, request.segment_index)
        except (TypeError, ValueError) as exc:
            raise DispatchBlocked("natural batch reference is invalid") from exc
        if (evidence.operation_id != request.operation_id
                or evidence.effect_id != request.effect_id
                or evidence.payload_digest != request.payload_digest
                or request.payload_ref != payload_ref
                or request.segment_index != 0 or request.segment_count != 1
                or request.footprint.segment_id != evidence.segment_id
                or not evidence.paid_review_digest
                or evidence.generation_original_operation_id
                   == evidence.review_original_operation_id
                or not evidence.current_read_versions
                or segment.media_refs
                or segment_payload_digest(
                    segment.body, segment.media_refs, segment.claim_uses,
                ) != evidence.payload_digest):
            raise DispatchBlocked("natural text differs from paid final candidate")
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


@dataclass(frozen=True, slots=True)
class CurrentDispatchHandoffReadV1:
    """One Authority transaction's current P2, anchor and effect snapshot."""

    permit: FencePermitV2
    anchor: RestoreAnchor
    effect: CurrentEffectReadV2


class CurrentDispatchHandoffPort(Protocol):
    def read_current_dispatch_handoff(
        self, start: HandoffStartV2, claimed_receipt: MutationReceiptV2,
    ) -> CurrentDispatchHandoffReadV1: ...

    def read_ingress_clock(
        self, policy: AdminIngressClockPolicy,
    ) -> VerifiedIngressClockV2: ...


class AstrBotV2TextSender:
    """One OneBot send inside a fresh V2 handoff decision window.

    A newly persisted Authority start is the cross-process one-shot gate.
    The OneBot message_id acknowledges acceptance by the adapter;
    it does not establish delivery or reading by the recipient.
    """

    def __init__(self, *, context: Context, candidates: SceneCandidateCatalog,
                 resolver: TextPayloadResolver,
                 authority: CurrentDispatchHandoffPort,
                 clock_policy: AdminIngressClockPolicy,
                 record_observation: Callable[
                     [HandoffStartV2, PlatformObservationV2], Awaitable[object]],
                 send_timeout_seconds: float = 30.0,
                 local_module_admission=None, contact_measurement=None) -> None:
        if (not isinstance(context, Context)
                or not isinstance(candidates, SceneCandidateCatalog)
                or not callable(getattr(resolver, "resolve", None))
                or not callable(getattr(authority, "read_current_dispatch_handoff", None))
                or not callable(getattr(authority, "read_ingress_clock", None))
                or type(clock_policy) is not AdminIngressClockPolicy
                or type(send_timeout_seconds) not in (int, float)
                or not math.isfinite(send_timeout_seconds)
                or not 0 < send_timeout_seconds <= 120
                or not callable(record_observation)):
            raise DispatchUnavailable("V2 sender requires current Authority, clock and observation ports")
        self._context = context
        self._candidates = candidates
        self._resolver = resolver
        self._authority = authority
        self._clock_policy = clock_policy
        self._record_observation = record_observation
        self._send_timeout_seconds = float(send_timeout_seconds)
        from .contact_sender_measurement_v1 import InstalledContactSenderMeasurementV1
        if contact_measurement is not None and type(contact_measurement) is not InstalledContactSenderMeasurementV1:
            raise TypeError("Contact Sender requires its actual private measurement component")
        self._contact_measurement = contact_measurement
        from ..runtime.local_module_admission_v1 import LocalModuleAdmissionV1
        if local_module_admission is not None and type(local_module_admission) is not LocalModuleAdmissionV1:
            raise TypeError("sender requires the frozen native module admission")
        self._local_module_admission = local_module_admission or LocalModuleAdmissionV1()

    async def send(self, *, decision: HandoffDecisionWindow,
                   binding: ExecutionBindingV2,
                   claimed_receipt: MutationReceiptV2,
                   request: DispatchRequest) -> PlatformObservationV2:
        if (type(decision) is not HandoffDecisionWindow
                or type(binding) is not ExecutionBindingV2
                or type(claimed_receipt) is not MutationReceiptV2
                or type(request) is not DispatchRequest):
            raise DispatchBlocked("typed fresh V2 handoff, binding and command required")
        origin = binding.origin
        required = ("d08", "d09", "d10", "d11") if request.proactive_contact else ("d08", "d09", "d11")
        self._local_module_admission.require_v1(required, "dispatch:platform_first_send")
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
                or start.claim_digest != authority_digest(claimed_receipt)
                or claimed_receipt.pending.binding != binding
                or claimed_receipt.pending.phase != "claimed"
                or claimed_receipt.durable_state != "committed"
                or start.graph_claim_ref != graph_receipt.graph_claim_ref
                or graph_receipt.graph_namespace != binding.graph_namespace
                or graph_receipt.graph_incarnation != binding.graph_incarnation):
            raise DispatchBlocked("fresh Authority start or committed graph claim differs")
        if (binding.clock_policy_ref != self._clock_policy.source_id
                or binding.clock_policy_digest != "sha256:" + canonical_digest(
                    asdict(self._clock_policy))):
            raise DispatchBlocked("installed Authority clock policy differs")
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

        # This read must be one Authority transaction, not three independently
        # sampled heads. No send occurs if the installed port is missing.
        current = await asyncio.to_thread(
            self._authority.read_current_dispatch_handoff, start, claimed_receipt)
        if (type(current) is not CurrentDispatchHandoffReadV1
                or current.permit != start.permit
                or current.anchor != start.permit.pinned_anchor
                or type(current.effect) is not CurrentEffectReadV2
                or current.effect.authority_id != start.permit.authority_id
                or current.effect.namespace != start.namespace
                or current.effect.effect_id != start.effect_id
                or current.effect.activation_generation != start.permit.generation
                or current.effect.state != "unresolved"
                or current.effect.mutation_id != claimed_receipt.pending.mutation_id
                or current.effect.effect_seq != current.anchor.execution_seq
                or current.effect.append_digest != current.anchor.execution_digest
                or (current.effect.execution_head_seq,
                    current.effect.execution_head_digest) != (
                    current.anchor.execution_seq,
                    current.anchor.execution_digest)):
            raise DispatchBlocked("current P2, Owner or effect state differs")
        clock = await asyncio.to_thread(
            self._authority.read_ingress_clock, self._clock_policy)
        if (type(clock) is not VerifiedIngressClockV2
                or clock.sample.source_id != self._clock_policy.source_id
                or clock.sample.authority_id != start.permit.authority_id
                or clock.sample.utc_error_seconds
                   > self._clock_policy.max_utc_error_seconds
                or clock.monotonic_after_seconds < clock.monotonic_before_seconds
                or clock.monotonic_after_seconds - clock.monotonic_before_seconds
                   > self._clock_policy.max_round_trip_seconds):
            raise DispatchBlocked("current Authority clock sample is unqualified")
        deadline = datetime.fromisoformat(
            binding.utc_deadline.replace("Z", "+00:00")).timestamp()
        if trusted_upper(clock) >= deadline:
            raise DispatchBlocked("fresh handoff deadline expired before external send")

        action = ("send_group_msg" if visibility == "group"
                  else "send_private_msg")
        destination = "group_id" if visibility == "group" else "user_id"
        if request.proactive_contact and self._contact_measurement is None:
            raise DispatchBlocked("installed Contact effect pricing/measurement unavailable")
        async def call_onebot():
            if self._contact_measurement is not None:
                self._contact_measurement.start_invocation(binding, start, claimed_receipt, trusted_upper(clock))
            return await adapter.bot.call_action(
                action, self_id=resolved.self_id,
                **{destination: int(session.session_id)},
                message=[{"type": "text", "data": {"text": body}}])

        # Run in this task so cancellation cannot leave our own send task
        # running after the decision window closes. asyncio.timeout cancels
        # and awaits this coroutine's termination before returning.
        try:
            async with asyncio.timeout(self._send_timeout_seconds):
                receipt = await call_onebot()
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
            observed_at_utc=datetime.fromtimestamp(
                trusted_upper(clock), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            time_source_ref=self._clock_policy.source_id,
        )
        if self._contact_measurement is not None:
            try:
                await self._contact_measurement.complete_invocation(observation)
            except (Exception, asyncio.CancelledError):
                # Lost measurement acknowledgement is reconciled from Core; no SDK retry.
                pass
        try:
            await self._record_observation(start, observation)
        except (Exception, asyncio.CancelledError) as exc:
            # The Authority write may have committed despite a lost response.
            # The durable start forbids another platform call either way.
            raise HandoffUncertain(observation.observation_id) from exc
        return observation


__all__ = (
    "AstrBotTextPlatformCapability", "GraphTextPayloadResolver",
    "NaturalGraphTextPayloadResolver",
    "ResolvedTextPayload", "TextPayloadResolver", "AstrBotV2TextSender",
    "CurrentDispatchHandoffReadV1", "CurrentDispatchHandoffPort",
)
