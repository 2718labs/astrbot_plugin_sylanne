"""Recover one committed natural V2 effect before a fresh Authority handoff.

The graph read supplies original paid and admission identities.  Sending stays
HOLD until an installed natural-specific final claim writer is available.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib

from ..contracts import EventConflict, StaleRead
from ..authority_service.v2_execution_bridge import CurrentEffectReadV2
from ..dispatch_runtime import DispatchBlocked, DispatchRequest, HandoffUncertain
from ..graph_coordinator import UnavailableGuard
from ..graph_worker import GraphWorker
from ..runtime.dispatch_admission import DispatchAdmissionReceiptV1
from ..runtime.dispatch_candidate import (
    NaturalDispatchCandidateEvidenceV2,
    natural_dispatch_segment_payload_ref_v2,
)
from ..runtime.dispatch_binding_v2 import (
    authority_dispatch_footprint_v2, build_non_authorizing_execution_binding_v2,
)
from ..runtime_contracts import CommitReceipt, InstallationGrantV2, NamespaceId, canonical_digest
from ..installation_policy import AdminInstallationPolicy
from ..runtime.first_ingress_v2 import trusted_upper
from .astrbot_dispatch import NaturalGraphTextPayloadResolver, ResolvedTextPayload
from .current_dispatch_handoff_port import InstalledCurrentDispatchHandoffPort
from .private_reply_dispatch_driver import _is_private_route
from .reverse_handoff import HostReverseGraphClaimServer, begin_handoff_with_reverse_claim
from .v2_fence_port import V2FenceOutcomeUnknown, V2FencePort


class NaturalReplyDispatchHold(RuntimeError):
    """The original reviewed effect is not currently eligible for handoff."""


@dataclass(frozen=True, slots=True)
class OriginalNaturalReplyDispatchV2:
    namespace: NamespaceId
    operation_id: str
    effect_id: str
    admission_ref: str
    admission_digest: str
    outbox_ref: str
    request: DispatchRequest
    admission: DispatchAdmissionReceiptV1
    evidence: NaturalDispatchCandidateEvidenceV2
    payload: ResolvedTextPayload


@dataclass(frozen=True, slots=True)
class NaturalReplyDispatchResultV2:
    status: str
    reason: str
    original: OriginalNaturalReplyDispatchV2 | None = None


def _read_original(graph, authority, lease, operation_id: str) -> OriginalNaturalReplyDispatchV2:
    read = getattr(graph, "read_committed_natural_dispatch_v2", None)
    if not callable(read):
        raise NaturalReplyDispatchHold("committed natural V2 read is unavailable")
    result = read(authority, lease, operation_id)
    if (type(result) is not tuple or len(result) != 4
            or type(result[0]) is not DispatchAdmissionReceiptV1
            or type(result[1]) is not DispatchRequest
            or type(result[2]) is not NaturalDispatchCandidateEvidenceV2
            or type(result[3]) is not CommitReceipt):
        raise NaturalReplyDispatchHold("original natural V2 effect is unavailable")
    admission, request, evidence, operation = result
    frozen = admission.admission
    namespace = authority.namespace
    if (operation.status != "committed"
            or operation.operation_id != operation_id
            or operation.effect_id != request.effect_id
            or operation.activity_id != request.activity_id
            or len(operation.outbox_refs) != 1 or not operation.outbox_refs[0]
            or request.namespace != "/".join(namespace.as_tuple)
            or (request.operation_id, request.effect_id, request.activity_id)
               != (operation_id, evidence.effect_id, operation.activity_id)
            or (frozen.operation_id, frozen.effect_id, frozen.activity_id,
                frozen.request_digest, frozen.candidate_digest,
                frozen.batch_digest, frozen.payload_digest)
               != (request.operation_id, request.effect_id, request.activity_id,
                   canonical_digest(request), evidence.digest,
                   evidence.batch_digest, evidence.payload_digest)
            or request.payload_ref != natural_dispatch_segment_payload_ref_v2(
                evidence.batch_ref, 0)
            or request.segment_index != 0 or request.segment_count != 1
            or request.proactive_contact
            or not _is_private_route(frozen.account_ref, frozen.destination_ref)):
        raise NaturalReplyDispatchHold("natural original admission or private route differs")
    payload = NaturalGraphTextPayloadResolver(graph, authority, lease).resolve(request)
    return OriginalNaturalReplyDispatchV2(
        namespace, operation_id, request.effect_id, frozen.admission_ref,
        frozen.digest, operation.outbox_refs[0], request, admission,
        evidence, payload,
    )


class _FrozenNaturalTextResolver:
    def __init__(self, request: DispatchRequest, payload: ResolvedTextPayload) -> None:
        self._request = request
        self._payload = payload

    def resolve(self, request: DispatchRequest) -> ResolvedTextPayload:
        if request != self._request:
            raise NaturalReplyDispatchHold("natural dispatch command changed")
        return self._payload


class InstalledNaturalReplyContinuationV2:
    """The natural-specific final claim joins the existing P2 one-shot window."""

    def __init__(self, *, worker: GraphWorker, authority: object, lease: object,
                 fence_port: V2FencePort, policy: AdminInstallationPolicy,
                 grant: InstallationGrantV2, server: HostReverseGraphClaimServer,
                 natural_claim_writer: object, context: object, candidates: object,
                 clock_policy: object, adapter_ref: str) -> None:
        if (type(worker) is not GraphWorker or type(fence_port) is not V2FencePort
                or type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or type(server) is not HostReverseGraphClaimServer
                or policy.namespace != authority.namespace
                or (grant.installation_id, grant.authority_id,
                    grant.manifest_digest) != (
                    policy.installation_id, policy.expected_authority_id,
                    policy.manifest_digest)
                or server.profile.namespace != policy.authority_namespace
                or not callable(getattr(natural_claim_writer,
                                        "prepare_natural_for_handoff", None))):
            raise ValueError("installed natural V2 handoff is unavailable")
        self._worker, self._authority, self._lease = worker, authority, lease
        self._port, self._policy, self._grant = fence_port, policy, grant
        self._server, self._claim_writer = server, natural_claim_writer
        self._context, self._candidates = context, candidates
        self._clock_policy, self._adapter_ref = clock_policy, adapter_ref

    async def read_recovery_state(
        self, original: OriginalNaturalReplyDispatchV2,
    ) -> CurrentEffectReadV2:
        """Read the durable effect before deciding whether a send may begin."""
        if (type(original) is not OriginalNaturalReplyDispatchV2
                or original.namespace != self._policy.namespace):
            raise NaturalReplyDispatchHold("natural recovery identity differs")
        reading = await asyncio.to_thread(
            self._port.read_current_effect,
            namespace=original.namespace,
            authority_namespace=self._policy.authority_namespace,
            effect_id=original.effect_id)
        if (type(reading) is not CurrentEffectReadV2
                or reading.authority_id != self._grant.authority_id
                or reading.namespace != self._policy.authority_namespace
                or reading.effect_id != original.effect_id
                or reading.activation_generation
                   != original.request.activation_generation
                or reading.state not in {"absent", "unresolved", "observed"}):
            raise NaturalReplyDispatchHold("natural current effect read differs")
        return reading

    async def dispatch(self, original: OriginalNaturalReplyDispatchV2) -> str:
        from .astrbot_dispatch import AstrBotV2TextSender

        namespace, request = original.namespace, original.request
        if (type(original) is not OriginalNaturalReplyDispatchV2
                or namespace != self._authority.namespace
                or await asyncio.to_thread(lambda: self._port.installation_grant)
                   != self._grant):
            raise NaturalReplyDispatchHold("installed natural Authority grant differs")
        payload = await self._worker.call(lambda graph:
            NaturalGraphTextPayloadResolver(graph, self._authority, self._lease)
            .resolve(request))
        if type(payload) is not ResolvedTextPayload or payload != original.payload:
            raise NaturalReplyDispatchHold("natural original text changed before P2")
        clock = await asyncio.to_thread(self._port.read_ingress_clock,
                                        self._clock_policy)
        now_utc = trusted_upper(clock)
        original.admission.admission.require_current(now_utc)
        authority_namespace = self._policy.authority_namespace
        anchor = await asyncio.to_thread(
            self._port.current_anchor, namespace=namespace,
            authority_namespace=authority_namespace)
        footprint = authority_dispatch_footprint_v2(namespace, request)
        permit = await asyncio.to_thread(
            self._port.begin_dispatch_fence,
            namespace=namespace, authority_namespace=authority_namespace,
            holder=self._policy.administrator_holder,
            generation=request.activation_generation,
            operation_id=original.operation_id, expected_anchor=anchor,
            effect_id=original.effect_id,
            command_digest="sha256:" + request.command_digest,
            footprint=footprint)
        binding = build_non_authorizing_execution_binding_v2(
            namespace=namespace, admission_receipt=original.admission,
            recovered_request=request, original_dispatch_permit=permit,
            adapter_ref=self._adapter_ref, now_utc=now_utc)
        identity = hashlib.sha256(
            (original.operation_id + "\0" + original.effect_id).encode("utf-8")
        ).hexdigest()
        prepared, _ = await asyncio.to_thread(
            self._port.execution_prepare,
            namespace=namespace, authority_namespace=authority_namespace,
            permit=permit, mutation_id="dispatch:" + identity,
            footprint=footprint)
        claimed, _ = await asyncio.to_thread(
            self._port.execution_claim_v2,
            namespace=namespace, authority_namespace=authority_namespace,
            prepared_receipt=prepared, binding=binding)
        handoff_id = "handoff:" + identity
        claim_writer = await self._worker.call(lambda graph:
            self._claim_writer.prepare_natural_for_handoff(
                graph, claimed, handoff_id, original.operation_id))
        if not callable(claim_writer):
            raise NaturalReplyDispatchHold("natural final graph claim unavailable")
        handoff = await asyncio.to_thread(
            InstalledCurrentDispatchHandoffPort,
            fence_port=self._port, policy=self._policy, grant=self._grant,
            claimed_receipt=claimed)
        sender = AstrBotV2TextSender(
            context=self._context, candidates=self._candidates,
            resolver=_FrozenNaturalTextResolver(request, payload),
            authority=handoff, clock_policy=self._clock_policy,
            record_observation=handoff.record_observation)

        async def begin(receipt, handoff_id):
            return await asyncio.to_thread(
                self._port.execution_begin_handoff_v2,
                namespace=namespace, authority_namespace=authority_namespace,
                claimed_receipt=receipt, handoff_id=handoff_id)

        async with begin_handoff_with_reverse_claim(
            worker=self._worker, server=self._server, claimed=claimed,
            handoff_id=handoff_id, claim_writer=claim_writer, begin=begin,
        ) as decision:
            if decision.replay:
                return "replay"
            observation = await sender.send(
                decision=decision, binding=binding,
                claimed_receipt=claimed, request=request)
        return observation.outcome


class NaturalReplyDispatchDriverV2:
    """Recover original natural dispatch, then use only an installed V2 claim."""

    def __init__(self, worker: GraphWorker, authority: object, lease: object,
                 continuation: InstalledNaturalReplyContinuationV2 | None = None) -> None:
        if type(worker) is not GraphWorker or authority is None or lease is None:
            raise ValueError("trusted graph worker and Authority lease required")
        if (continuation is not None
                and (type(continuation) is not InstalledNaturalReplyContinuationV2
                     or continuation._worker is not worker
                     or continuation._authority is not authority
                     or continuation._lease is not lease)):
            raise ValueError("installed natural continuation differs")
        self._worker, self._authority, self._lease = worker, authority, lease
        self._continuation = continuation

    async def run_once(self, *, operation_id: str) -> NaturalReplyDispatchResultV2:
        if type(operation_id) is not str or not operation_id:
            return NaturalReplyDispatchResultV2("hold", "original operation required")
        try:
            original = await self._worker.call(
                _read_original, self._authority, self._lease, operation_id)
        except (NaturalReplyDispatchHold, DispatchBlocked, UnavailableGuard, EventConflict,
                StaleRead, ValueError, TypeError) as exc:
            return NaturalReplyDispatchResultV2("hold", str(exc))
        if self._continuation is None:
            return NaturalReplyDispatchResultV2(
                "hold", "installed natural final graph claim unavailable", original)
        try:
            effect = await self._continuation.read_recovery_state(original)
            if effect.state == "observed":
                return NaturalReplyDispatchResultV2(
                    "hold", "original effect already observed; no platform retry", original)
            if effect.state == "unresolved":
                return NaturalReplyDispatchResultV2(
                    "unknown", "original effect unresolved; reconcile before retry", original)
            outcome = await self._continuation.dispatch(original)
        except (HandoffUncertain, V2FenceOutcomeUnknown) as exc:
            return NaturalReplyDispatchResultV2("unknown", str(exc), original)
        except Exception as exc:
            return NaturalReplyDispatchResultV2("hold", str(exc), original)
        if outcome == "replay":
            return NaturalReplyDispatchResultV2(
                "hold", "durable handoff replay; no platform retry", original)
        return NaturalReplyDispatchResultV2(
            outcome, ("OneBot adapter accepted; delivery unobserved"
                      if outcome == "accepted" else
                      "platform outcome unknown after durable start"), original)


__all__ = (
    "InstalledNaturalReplyContinuationV2", "NaturalReplyDispatchDriverV2",
    "NaturalReplyDispatchHold", "NaturalReplyDispatchResultV2",
    "OriginalNaturalReplyDispatchV2",
)
