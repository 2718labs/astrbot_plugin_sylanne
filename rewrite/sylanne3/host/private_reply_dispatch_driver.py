"""Continue one owned, committed private reply through the installed V2 handoff.

The default entry remains HOLD until its installed continuation is supplied.
Only Authority's fresh start inside the reverse callback window reaches OneBot.
"""

from __future__ import annotations

from dataclasses import dataclass
import asyncio
import hashlib
import json
import re

from ..dispatch_runtime import DispatchRequest, HandoffUncertain
from ..contracts import EventConflict, StaleRead
from ..graph_coordinator import UnavailableGuard
from ..graph_worker import GraphWorker
from ..runtime.dispatch_admission import DispatchAdmissionReceiptV1
from ..runtime.post_c02_reply_ownership_v1 import ReplyOwnershipReceiptV1
from ..runtime_contracts import CommitReceipt, NamespaceId, canonical_digest
from ..runtime.dispatch_binding_v2 import (
    authority_dispatch_footprint_v2, build_non_authorizing_execution_binding_v2,
)
from ..host.reverse_handoff import (
    HostReverseGraphClaimServer, begin_handoff_with_reverse_claim,
)
from ..host.v2_fence_port import V2FenceOutcomeUnknown, V2FencePort
from ..installation_policy import AdminInstallationPolicy
from ..runtime.first_ingress_v2 import trusted_upper
from ..runtime_contracts import InstallationGrantV2


class PrivateReplyDispatchHold(RuntimeError):
    """Original reply evidence differs; no platform send is authorized."""


@dataclass(frozen=True, slots=True)
class OriginalPrivateReplyDispatchV1:
    """Read-only original identities. This object is never a send credential."""

    namespace: NamespaceId
    ingress_operation_id: str
    operation_id: str
    effect_id: str
    admission_ref: str
    admission_digest: str
    outbox_ref: str
    request: DispatchRequest
    admission: DispatchAdmissionReceiptV1


@dataclass(frozen=True, slots=True)
class PrivateReplyDispatchResultV1:
    status: str
    reason: str
    original: OriginalPrivateReplyDispatchV1 | None = None


class _FrozenGraphTextResolver:
    """A graph-worker read made before the reverse callback drains that worker."""

    def __init__(self, request: DispatchRequest, payload: object) -> None:
        self._request = request
        self._payload = payload

    def resolve(self, request: DispatchRequest) -> object:
        if request != self._request:
            raise PrivateReplyDispatchHold("frozen original D09 segment differs")
        return self._payload


class InstalledPrivateReplyContinuationV1:
    """One installed P0/P2/claim/start/send chain for the original effect.

    Construction belongs to the runtime after the authenticated reverse
    pairing is installed. No caller-provided business evidence enters here.
    """

    def __init__(self, *, worker: GraphWorker, authority: object, lease: object,
                 fence_port: V2FencePort, policy: AdminInstallationPolicy,
                 grant: InstallationGrantV2, server: HostReverseGraphClaimServer,
                 claim_writer: object, context: object, candidates: object,
                 clock_policy: object, adapter_ref: str) -> None:
        if (type(fence_port) is not V2FencePort
                or type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or type(server) is not HostReverseGraphClaimServer
                or policy.namespace != authority.namespace
                or grant.installation_id != policy.installation_id
                or grant.authority_id != policy.expected_authority_id
                or grant.manifest_digest != policy.manifest_digest
                or server.profile.namespace != policy.authority_namespace
                or not callable(getattr(claim_writer, "prepare_for_handoff", None))):
            raise ValueError("installed private reply P2 identity differs")
        self._worker = worker
        self._authority = authority
        self._lease = lease
        self._port = fence_port
        self._policy = policy
        self._grant = grant
        self._server = server
        self._claim_writer = claim_writer
        self._context = context
        self._candidates = candidates
        self._clock_policy = clock_policy
        self._adapter_ref = adapter_ref

    async def dispatch(self, original: OriginalPrivateReplyDispatchV1) -> str:
        from .astrbot_dispatch import (
            AstrBotV2TextSender, GraphTextPayloadResolver, ResolvedTextPayload,
        )
        from .current_dispatch_handoff_port import InstalledCurrentDispatchHandoffPort

        namespace = original.namespace
        request = original.request
        authority_namespace = self._policy.authority_namespace
        if await asyncio.to_thread(lambda: self._port.installation_grant) != self._grant:
            raise PrivateReplyDispatchHold("current installed Authority grant differs")

        # The reverse callback owns the only GraphWorker slot during start.
        # Freeze the original committed D09 text before acquiring that window;
        # W01's claim checks the same segment again in its graph transaction.
        payload = await self._worker.call(
            lambda graph: GraphTextPayloadResolver(
                graph, self._authority, self._lease).resolve(request))
        if type(payload) is not ResolvedTextPayload:
            raise PrivateReplyDispatchHold("original D09 text is unavailable")

        clock = await asyncio.to_thread(
            self._port.read_ingress_clock, self._clock_policy)
        now_utc = trusted_upper(clock)
        original.admission.admission.require_current(now_utc)
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
        # The paired clock is read on GraphWorker before the reverse callback
        # window. Authority waits for that callback, so an Authority RPC from
        # inside the callback would deadlock the two sides.
        claim_writer = await self._worker.call(
            lambda graph: self._claim_writer.prepare_for_handoff(
                graph, claimed, handoff_id))
        if not callable(claim_writer):
            raise PrivateReplyDispatchHold("prepared final graph claim unavailable")
        handoff = await asyncio.to_thread(
            InstalledCurrentDispatchHandoffPort,
            fence_port=self._port, policy=self._policy, grant=self._grant,
            claimed_receipt=claimed)
        sender = AstrBotV2TextSender(
            context=self._context, candidates=self._candidates,
            resolver=_FrozenGraphTextResolver(request, payload),
            authority=handoff, clock_policy=self._clock_policy,
            record_observation=handoff.record_observation)

        async def begin(receipt, handoff_id):
            return await asyncio.to_thread(
                self._port.execution_begin_handoff_v2,
                namespace=namespace, authority_namespace=authority_namespace,
                claimed_receipt=receipt, handoff_id=handoff_id)

        async with begin_handoff_with_reverse_claim(
            worker=self._worker, server=self._server, claimed=claimed,
            handoff_id=handoff_id,
            claim_writer=claim_writer, begin=begin,
        ) as decision:
            if decision.replay:
                return "replay"
            observation = await sender.send(
                decision=decision, binding=binding,
                claimed_receipt=claimed, request=request)
        return observation.outcome


def _is_private_route(account_ref: str, destination_ref: str) -> bool:
    try:
        account = json.loads(account_ref)
        destination = json.loads(destination_ref)
        if (type(account) is not list or len(account) != 3
                or type(destination) is not list or len(destination) != 2
                or any(type(value) is not str or not value
                       for value in (*account, *destination))
                or json.dumps(account, ensure_ascii=True, separators=(",", ":")) != account_ref
                or json.dumps(destination, ensure_ascii=True, separators=(",", ":")) != destination_ref
                or account[1] != "aiocqhttp"):
            return False
        # Conservative syntax filter only. The installed route port must
        # later parse the UMO with the AstrBot SDK at final-claim time.
        match = re.fullmatch(r"([^:]+):FriendMessage:([0-9]+)", destination[0])
        return match is not None and match.group(1) == account[0]
    except (TypeError, ValueError, IndexError, AttributeError):
        return False


def _read_original(graph: object, authority: object, lease: object,
                   ingress_operation_id: str,
                   handler_invocation_id: str) -> OriginalPrivateReplyDispatchV1:
    """Run entirely on GraphWorker; never make an Authority P2 RPC here."""
    ownership = graph.read_reply_ownership_v1(
        authority, lease, ingress_operation_id=ingress_operation_id,
        handler_invocation_id=handler_invocation_id)
    if (type(ownership) is not ReplyOwnershipReceiptV1
            or ownership.state != "sylanne_owned"
            or ownership.namespace != authority.namespace
            or ownership.ingress_operation_id != ingress_operation_id
            or ownership.handler_invocation_id != handler_invocation_id
            or not all((ownership.reply_operation_id, ownership.effect_id,
                        ownership.admission_ref, ownership.admission_digest,
                        ownership.ack_digest))):
        raise PrivateReplyDispatchHold("original reply ownership unavailable")

    # This must precede every Authority P2 begin/claim RPC. It checks the
    # durable takeover, original ingress route, admission and bundle attempt.
    current = graph.require_reply_owned_before_dispatch_p2_v1(
        authority, lease, ingress_operation_id=ingress_operation_id,
        admission_ref=ownership.admission_ref, effect_id=ownership.effect_id)
    if type(current) is not ReplyOwnershipReceiptV1 or current != ownership:
        raise PrivateReplyDispatchHold("original reply ownership changed")

    pair = graph.get_committed_dispatch_for_operation_v2(
        authority, lease, ownership.reply_operation_id)
    if (type(pair) is not tuple or len(pair) != 2
            or type(pair[0]) is not DispatchAdmissionReceiptV1
            or type(pair[1]) is not DispatchRequest):
        raise PrivateReplyDispatchHold("original committed dispatch unavailable")
    admission, request = pair
    frozen = admission.admission
    operation = graph.get_operation(authority, lease, ownership.reply_operation_id)
    namespace = authority.namespace
    if (type(operation) is not CommitReceipt
            or operation.status != "committed"
            or operation.operation_id != ownership.reply_operation_id
            or operation.effect_id != ownership.effect_id
            or len(operation.outbox_refs) != 1
            or not operation.outbox_refs[0]
            or frozen.namespace != "/".join(namespace.as_tuple)
            or request.namespace != frozen.namespace
            or (frozen.operation_id, frozen.effect_id, frozen.activity_id,
                frozen.attempt_id, frozen.admission_ref, frozen.digest) != (
                ownership.reply_operation_id, ownership.effect_id,
                operation.activity_id, request.attempt_id,
                ownership.admission_ref, ownership.admission_digest)
            or (request.operation_id, request.effect_id, request.activity_id,
                request.attempt_id) != (frozen.operation_id, frozen.effect_id,
                                       frozen.activity_id, frozen.attempt_id)
            or frozen.request_digest != canonical_digest(request)
            or frozen.payload_digest != request.payload_digest
            or (frozen.account_ref, frozen.destination_ref) != (
                ownership.account_ref, ownership.destination_ref)
            or not _is_private_route(frozen.account_ref, frozen.destination_ref)
            or request.proactive_contact
            or request.segment_index != 0 or request.segment_count != 1
            or frozen.segment_index != 0):
        raise PrivateReplyDispatchHold("original single private segment differs")
    return OriginalPrivateReplyDispatchV1(
        namespace, ingress_operation_id, operation.operation_id,
        operation.effect_id, frozen.admission_ref, frozen.digest,
        operation.outbox_refs[0], request, admission)


class PrivateReplyDispatchDriver:
    """Read the original sealed graph facts and HOLD before P2 or sending.

    W01 must supply a current final-claim continuation before this can send:
    current Authority P2 execution binding, current graph claim, reverse
    handoff, installed route, and a sender using the same original outbox.
    No callback or caller-supplied sealed facts can bypass this boundary.
    """

    def __init__(self, worker: GraphWorker, authority: object, lease: object,
                 continuation: InstalledPrivateReplyContinuationV1 | None = None) -> None:
        if type(worker) is not GraphWorker or authority is None or lease is None:
            raise ValueError("trusted graph worker and authority lease required")
        if (continuation is not None
                and (type(continuation) is not InstalledPrivateReplyContinuationV1
                     or continuation._worker is not worker
                     or continuation._authority is not authority
                     or continuation._lease is not lease)):
            raise ValueError("installed private reply continuation differs")
        self._worker = worker
        self._authority = authority
        self._lease = lease
        self._continuation = continuation

    async def run_once(self, *, ingress_operation_id: str,
                       handler_invocation_id: str) -> PrivateReplyDispatchResultV1:
        if any(type(value) is not str or not value for value in (
                ingress_operation_id, handler_invocation_id)):
            return PrivateReplyDispatchResultV1("hold", "original handler identity required")
        try:
            original = await self._worker.call(
                _read_original, self._authority, self._lease,
                ingress_operation_id, handler_invocation_id)
        except (PrivateReplyDispatchHold, UnavailableGuard,
                EventConflict, StaleRead) as exc:
            return PrivateReplyDispatchResultV1("hold", str(exc))
        if self._continuation is None:
            return PrivateReplyDispatchResultV1(
                "hold", "installed W01 final graph claim and paired P2 continuation unavailable",
                original)
        try:
            outcome = await self._continuation.dispatch(original)
        except (HandoffUncertain, V2FenceOutcomeUnknown) as exc:
            return PrivateReplyDispatchResultV1(
                "unknown", str(exc), original)
        except Exception as exc:
            return PrivateReplyDispatchResultV1("hold", str(exc), original)
        if outcome == "replay":
            return PrivateReplyDispatchResultV1(
                "hold", "durable handoff replay; no platform retry", original)
        reason = ("OneBot adapter accepted original handoff; delivery unobserved"
                  if outcome == "accepted"
                  else "platform outcome unknown after durable handoff start")
        return PrivateReplyDispatchResultV1(outcome, reason, original)


__all__ = (
    "OriginalPrivateReplyDispatchV1", "PrivateReplyDispatchDriver",
    "InstalledPrivateReplyContinuationV1",
    "PrivateReplyDispatchHold", "PrivateReplyDispatchResultV1",
)
