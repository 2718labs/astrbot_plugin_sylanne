"""One original Contact effect through the installed one-shot sender.

This entry cannot issue current Contact qualification. W01's separate private
P2 writer must qualify the actual SQL/Authority handoff before the SDK can run.
Later segments and shared-session ownership stay outside this first entry.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
import hashlib

from ..authority_service.v2_execution_bridge import CurrentEffectReadV2
from ..dispatch_runtime import DispatchRequest, HandoffUncertain
from ..graph_worker import GraphWorker
from ..installation_policy import AdminInstallationPolicy
from ..runtime.contact_dispatch_candidate_v3 import contact_dispatch_segment_payload_ref_v3
from ..runtime.dispatch_admission import DispatchAdmissionReceiptV1
from ..runtime.dispatch_binding_v2 import authority_dispatch_footprint_v2, build_non_authorizing_execution_binding_v2
from ..runtime.first_ingress_v2 import trusted_upper
from ..runtime_contracts import CommitReceipt, InstallationGrantV2, NamespaceId, canonical_digest
from .astrbot_dispatch import AstrBotV2TextSender, ResolvedTextPayload
from .current_dispatch_handoff_port import InstalledCurrentDispatchHandoffPort
from .private_reply_dispatch_driver import _is_private_route
from .reverse_handoff import HostReverseGraphClaimServer, begin_handoff_with_reverse_claim
from .v2_fence_port import V2FenceOutcomeUnknown, V2FencePort


class ContactDispatchHold(RuntimeError):
    """The original or its installed current qualification is unavailable."""


@dataclass(frozen=True, slots=True)
class OriginalContactDispatchV3:
    namespace: NamespaceId
    operation_id: str
    outbox_ref: str
    batch_ref: str
    request: DispatchRequest
    admission: DispatchAdmissionReceiptV1
    operation: CommitReceipt


@dataclass(frozen=True, slots=True)
class ContactDispatchResultV3:
    status: str
    reason: str
    original: OriginalContactDispatchV3 | None = None
    accounting: object | None = None
    _accounting_lifetime: object | None = field(default=None, repr=False, compare=False)
    _original_lifetime: object | None = field(default=None, repr=False, compare=False)

    def release_v3(self):
        if self._original_lifetime is not None:
            self._original_lifetime.release()
        if self._accounting_lifetime is not None:
            self._accounting_lifetime.release()


def _read_original(graph, authority, lease, operation_id):
    from ..graph_worker import GraphStorageWorkV3
    read=graph.read_committed_contact_dispatch_v3
    work=read(authority,lease,operation_id)
    if type(work)is not GraphStorageWorkV3:
        raise ContactDispatchHold('Contact original identity requires its actual current metadata Work')
    work.map_terminal_v3('caller',lambda value:_validate_original_metadata_v3(authority,operation_id,value),lambda error:(_ for _ in ()).throw(error))
    return work


def _validate_original_metadata_v3(authority,operation_id,original):
    if type(original) is not OriginalContactDispatchV3:
        raise ContactDispatchHold("actual adopted Contact original unavailable")
    request, receipt, operation = original.request, original.admission, original.operation
    admission = receipt.admission
    if (original.namespace != authority.namespace
            or original.operation_id != operation_id
            or request.namespace != "/".join(original.namespace.as_tuple)
            or request.proactive_contact is not True
            or not 0<=request.segment_index<request.segment_count<=3
            or request.payload_ref != contact_dispatch_segment_payload_ref_v3(original.batch_ref, request.segment_index)
            or operation.status != "committed" or operation.operation_id != operation_id
            or operation.outbox_refs != (original.outbox_ref,)
            or (operation.effect_id, operation.activity_id) != (request.effect_id, request.activity_id)
            or (admission.operation_id, admission.effect_id, admission.activity_id, admission.attempt_id)
               != (request.operation_id, request.effect_id, request.activity_id, request.attempt_id)
            or admission.request_digest != canonical_digest(request)
            or admission.payload_digest != request.payload_digest
            or admission.segment_index != request.segment_index or not admission.contact_reservation_ref
            or not request.footprint.communication_action or not request.footprint.contact_id
            or admission.action_ref == request.footprint.communication_action
            or not request.footprint.segment_id or not request.segment_manifest_digest
            or not request.segment_authorization_ref or not request.contact_policy_check_ref
            or bool(request.footprint.quota_occupancies)!=(request.segment_index==0) or len(request.footprint.object_gate_keys)!=1
            or not _is_private_route(admission.account_ref, admission.destination_ref)):
        raise ContactDispatchHold("original Contact segment/whole manifest/admission/claim differs")
    return original


class _FrozenContactTextResolver:
    def __init__(self, request, payload):
        self._request, self._payload = request, payload

    def resolve(self, request):
        if request != self._request:
            raise ContactDispatchHold("original Contact command changed")
        return self._payload


async def _settled_thread(call, **kwargs):
    """Drain a mutating RPC thread before interpreting cancellation receipts."""
    task = asyncio.create_task(asyncio.to_thread(call, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        # asyncio.to_thread itself is not cancelled by cancelling its waiter.
        # Await its actual terminal before a recovery read can report absence.
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if task.done():
            try:
                task.result()
            except (Exception, asyncio.CancelledError):
                pass
        raise


class InstalledContactContinuationV3:
    """Use the registered private Contact P2 writer, never caller evidence."""
    def __init__(self, *, worker, authority, lease, fence_port, policy, grant,
                 server, claim_writer, context, candidates, clock_policy,
                 adapter_ref="astrbot:onebot:call_action", send_timeout_seconds=30.0, local_module_admission=None):
        from ..runtime.local_module_admission_v1 import LocalModuleAdmissionV1
        if local_module_admission is not None and type(local_module_admission) is not LocalModuleAdmissionV1:
            raise TypeError("dispatch requires the frozen native module admission")
        self._local_module_admission = local_module_admission or LocalModuleAdmissionV1()
        from ..runtime.contact_dispatch_host_v3 import InstalledContactFinalClaimWriterV3
        if (type(worker) is not GraphWorker or type(fence_port) is not V2FencePort
                or type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or type(server) is not HostReverseGraphClaimServer
                or type(claim_writer) is not InstalledContactFinalClaimWriterV3
                or policy.namespace != authority.namespace
                or (grant.installation_id, grant.authority_id, grant.manifest_digest)
                   != (policy.installation_id, policy.expected_authority_id, policy.manifest_digest)
                or server.profile.namespace != policy.authority_namespace
                or claim_writer.port is not fence_port):
            raise ValueError("installed Contact P2 identity differs")
        self._worker, self._authority, self._lease = worker, authority, lease
        self._port, self._policy, self._grant = fence_port, policy, grant
        self._server, self._claim_writer = server, claim_writer
        self._context, self._candidates = context, candidates
        self._clock_policy, self._adapter_ref = clock_policy, adapter_ref
        self._timeout = send_timeout_seconds
        self._accounting_result = None
        self._accounting_lease = None

    async def read_recovery_state(self, original):
        if type(original) is not OriginalContactDispatchV3 or original.namespace != self._policy.namespace:
            raise ContactDispatchHold("Contact recovery original differs")
        reading = await asyncio.to_thread(self._port.read_current_effect,
            namespace=original.namespace, authority_namespace=self._policy.authority_namespace,
            effect_id=original.request.effect_id)
        if (type(reading) is not CurrentEffectReadV2
                or (reading.authority_id, reading.namespace, reading.effect_id, reading.activation_generation)
                   != (self._grant.authority_id, self._policy.authority_namespace,
                       original.request.effect_id, original.request.activation_generation)
                or reading.state not in {"absent", "unresolved", "observed"}):
            raise ContactDispatchHold("Contact durable effect identity differs")
        return reading

    async def reconcile_cost(self, operation_id):
        from ..graph_worker import OwnedGraphStorageResultV3
        from ..runtime.contact_effect_accounting_v1 import (
            prepare_contact_effect_accounting_work_v1, ContactEffectCompletionProofV1)
        owned = await self._worker.call(lambda graph:
            prepare_contact_effect_accounting_work_v1(graph, operation_id))
        if type(owned) is not OwnedGraphStorageResultV3:
            raise ContactDispatchHold("Contact accounting lost its actual retained Work result")
        result, lease = owned.take_value_v3()
        try:
            if type(result) is not ContactEffectCompletionProofV1 or not result.accounting_finished:
                raise ContactDispatchHold("Contact accounting COMMIT and Authority finish are unconfirmed")
            if self._accounting_lease is not None: self._accounting_lease.release()
            self._accounting_result, self._accounting_lease = result, lease
            return result
        except BaseException:
            lease.release()
            raise

    def take_accounting_result_v1(self):
        value, lease = self._accounting_result, self._accounting_lease
        self._accounting_result = self._accounting_lease = None
        return value, lease

    async def dispatch(self, original):
        from ..graph_worker import OwnedGraphStorageResultV3
        from ..runtime.contact_effect_accounting_v1 import prepare_contact_effect_accounting_work_v1
        from .contact_sender_measurement_v1 import issue_contact_sender_measurement_v1
        owned = await self._worker.call(lambda graph:
            prepare_contact_effect_accounting_work_v1(graph, original.operation_id, mode="sender"))
        if type(owned) is not OwnedGraphStorageResultV3:
            raise ContactDispatchHold("Contact Sender budget origin lost its actual retained Work")
        value, lease = owned.take_value_v3()
        try:
            origin, port = value
            measurement = issue_contact_sender_measurement_v1(port, origin)
            return await self._dispatch_measured(original, measurement)
        finally:
            value = None
            lease.release()

    async def _dispatch_measured(self, original, measurement):
        self._local_module_admission.require_v1(('d08', 'd09', 'd10', 'd11'), "dispatch:InstalledContactContinuationV3")
        request, namespace = original.request, original.namespace
        if await asyncio.to_thread(lambda: self._port.installation_grant) != self._grant:
            raise ContactDispatchHold("current Contact installation grant differs")
        # A qualification preflight must exist before reserving any P0/P2.
        # The final private writer repeats its checks inside the reverse SQL
        # transaction; this preflight is never a send permit.
        from ..graph_worker import OwnedGraphStorageResultV3
        owned=await self._worker.call(lambda graph:self._claim_writer.require_current_entry(
            graph,self._authority,self._lease,original))
        if type(owned)is not OwnedGraphStorageResultV3:
            raise ContactDispatchHold('Contact text has no actual retained Source/Owner Work result')
        payload,text_lease=owned.take_value_v3()
        sender=None
        try:
            if type(payload) is not ResolvedTextPayload:
                raise ContactDispatchHold("actual Contact text unavailable")
            clock = await asyncio.to_thread(self._port.read_ingress_clock, self._clock_policy)
            now = trusted_upper(clock)
            original.admission.admission.require_current(now)
            authority_namespace = self._policy.authority_namespace
            anchor = await asyncio.to_thread(self._port.current_anchor,
                namespace=namespace, authority_namespace=authority_namespace)
            footprint = authority_dispatch_footprint_v2(namespace, request)
            permit = await _settled_thread(self._port.begin_dispatch_fence,
                namespace=namespace, authority_namespace=authority_namespace,
                holder=self._policy.administrator_holder, generation=request.activation_generation,
                operation_id=original.operation_id, expected_anchor=anchor,
                effect_id=request.effect_id, command_digest="sha256:" + request.command_digest,
                footprint=footprint)
            binding = build_non_authorizing_execution_binding_v2(namespace=namespace,
                admission_receipt=original.admission, recovered_request=request,
                original_dispatch_permit=permit, adapter_ref=self._adapter_ref, now_utc=now)
            identity = hashlib.sha256((original.operation_id + "\0" + request.effect_id).encode()).hexdigest()
            from ..runtime.dispatch_current_inventory_v3 import prepare_dispatch_inventory_on_worker_v3
            async with prepare_dispatch_inventory_on_worker_v3(self._worker,self._authority,self._lease,
                    binding=binding,admission=original.admission,request=request,permit=permit,
                    now_utc=now,dispatch_family="contact") as prepared_inventory:
                prepared, _ = await _settled_thread(self._port.execution_prepare,
                    namespace=namespace, authority_namespace=authority_namespace,
                    permit=permit, mutation_id="dispatch:" + identity, footprint=footprint)
                claimed, _ = await _settled_thread(self._port.execution_claim_v2,
                    namespace=namespace, authority_namespace=authority_namespace,
                    prepared_receipt=prepared, binding=binding)
                handoff_id = "handoff:" + identity
                writer = await self._worker.call(lambda graph:
                    self._claim_writer.prepare_contact_for_handoff(graph, claimed, handoff_id, original, prepared_inventory=prepared_inventory))
                if not callable(writer):
                    raise ContactDispatchHold("current Contact P2 qualification unavailable")
                handoff = await asyncio.to_thread(InstalledCurrentDispatchHandoffPort,
                    fence_port=self._port, policy=self._policy, grant=self._grant, claimed_receipt=claimed)
                sender = AstrBotV2TextSender(context=self._context, candidates=self._candidates,
                    resolver=_FrozenContactTextResolver(request, payload), authority=handoff,
                    clock_policy=self._clock_policy, record_observation=handoff.record_observation,
                    send_timeout_seconds=self._timeout, local_module_admission=self._local_module_admission,
                    contact_measurement=measurement)

                async def begin(receipt, handoff_id):
                    return await _settled_thread(self._port.execution_begin_handoff_v2,
                        namespace=namespace, authority_namespace=authority_namespace,
                        claimed_receipt=receipt, handoff_id=handoff_id)

                async with begin_handoff_with_reverse_claim(worker=self._worker, server=self._server,
                        claimed=claimed, handoff_id=handoff_id, claim_writer=writer, begin=begin) as decision:
                    if decision.replay:
                        return "replay"
                    observation = await sender.send(decision=decision, binding=binding,
                        claimed_receipt=claimed, request=request)
                await self._worker.call(lambda graph:self._claim_writer.consume_observation(graph,original))
                await self.reconcile_cost(original.operation_id)
                return observation.outcome
        finally:
            sender=payload=None
            text_lease.release()


def contact_delivery_verification_capability_v3(continuation):
    """The actual installed OneBot path supplies accepted/unknown only."""
    if type(continuation)is not InstalledContactContinuationV3:
        raise ContactDispatchHold('actual installed Contact continuation is required for capability inspection')
    if continuation._adapter_ref!='astrbot:onebot:call_action':
        raise ContactDispatchHold('unregistered Contact delivery adapter capability')
    # No configured boolean, Owner confirmation or get_msg response can mint
    # communicated/d11.delivery evidence for this installed provider.
    return 'unsupported_delivery_verification'


class ContactDispatchDriverV3:
    def __init__(self, worker, authority, lease, continuation=None):
        if type(worker) is not GraphWorker or authority is None or lease is None:
            raise ValueError("trusted Contact GraphWorker/lease required")
        if continuation is not None and (type(continuation) is not InstalledContactContinuationV3
                or continuation._worker is not worker or continuation._authority is not authority
                or continuation._lease is not lease):
            raise ValueError("installed Contact continuation differs")
        self._worker, self._authority, self._lease = worker, authority, lease
        self._continuation = continuation

    async def _stop_after_error(self, original, reason, *, cancelled=False):
        # An RPC/thread may have durably prepared/claimed before a lost reply.
        # Only an authenticated current absent read can say no effect exists.
        try:
            effect = await self._continuation.read_recovery_state(original)
        except (Exception, asyncio.CancelledError):
            return ContactDispatchResultV3("unknown", reason + "; durable state unconfirmed", original)
        if effect.state != "absent":
            return ContactDispatchResultV3("unknown", reason + "; original effect requires reconciliation", original)
        return ContactDispatchResultV3("cancelled" if cancelled else "hold",
            reason + "; no durable effect or platform handoff", original)

    async def run_once(self, *, operation_id):
        try:
            result = await self._run_once(operation_id=operation_id)
        except BaseException:
            if self._continuation is not None:
                _, lease = self._continuation.take_accounting_result_v1()
                if lease is not None: lease.release()
            raise
        if self._continuation is None: return result
        accounting, lease = self._continuation.take_accounting_result_v1()
        return replace(result, accounting=accounting, _accounting_lifetime=lease)

    async def _run_once(self, *, operation_id):
        if self._continuation is not None:
            capability=contact_delivery_verification_capability_v3(self._continuation)

        if type(operation_id) is not str or not operation_id:
            return ContactDispatchResultV3("hold", "original Contact operation required")
        try:
            if self._continuation is not None:
                from ..authority_service.contract import AuthorityUnavailable
                try:
                    await self._continuation.reconcile_cost(operation_id)
                except (AuthorityUnavailable, ContactDispatchHold):
                    # Absent or unobserved effects have no financial terminal.
                    # Subsequent actual effect recovery still forbids a retry.
                    pass
                await self._worker.call(lambda graph:self._continuation._claim_writer.recover_observation_metadata(
                    graph,operation_id))
            from ..graph_worker import OwnedGraphStorageResultV3
            owned=await self._worker.call(_read_original,self._authority,self._lease,operation_id)
            if type(owned)is not OwnedGraphStorageResultV3:
                raise ContactDispatchHold('Contact identity lost its actual retained metadata result')
            original,original_lease=owned.take_value_v3()
        except asyncio.CancelledError:
            return ContactDispatchResultV3("cancelled", "cancelled before any Contact P2 attempt")
        except Exception as exc:
            return ContactDispatchResultV3("hold", str(exc))
        try:
            result=await self._run_original_v3(original,capability if self._continuation is not None else None)
        except BaseException:
            original_lease.release()
            raise
        return replace(result,_original_lifetime=original_lease)

    async def _run_original_v3(self,original,capability):
        if self._continuation is None:
            return ContactDispatchResultV3("hold", "installed current Contact P2 qualification unavailable", original)
        try:
            effect = await self._continuation.read_recovery_state(original)
            if effect.state == "observed":
                accounting = await self._continuation.reconcile_cost(original.operation_id)
                return ContactDispatchResultV3("pending_verification" if accounting.prefix_ready else "hold",
                    "original effect and cost observed; " + capability if accounting.prefix_ready else
                    "original effect observed; cost or outcome remains unresolved", original, accounting)
            if effect.state == "unresolved":
                return ContactDispatchResultV3("unknown", "original effect unresolved; no platform retry", original)
            outcome = await self._continuation.dispatch(original)
        except asyncio.CancelledError:
            return await self._stop_after_error(original, "Contact cancellation", cancelled=True)
        except (HandoffUncertain, V2FenceOutcomeUnknown) as exc:
            return ContactDispatchResultV3("unknown", str(exc), original)
        except Exception as exc:
            return await self._stop_after_error(original, str(exc))
        if outcome == "replay":
            return ContactDispatchResultV3("hold", "durable Contact handoff replay; no platform retry", original)
        if outcome not in {"accepted", "unknown"}:
            return ContactDispatchResultV3("unknown", "unsupported platform outcome; reconcile original effect", original)
        accounting = self._continuation._accounting_result
        if accounting is None or not accounting.prefix_ready:
            return ContactDispatchResultV3("unknown" if outcome == "unknown" else "hold",
                "Contact effect or original cost remains unresolved; next segment paused", original, accounting)
        return ContactDispatchResultV3("pending_verification",
            "OneBot accepted; original measured cost settled; " + capability, original, accounting)
