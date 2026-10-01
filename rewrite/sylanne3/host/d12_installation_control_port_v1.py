"""W01 intent commit followed by independent Authority whole-Host control."""
from __future__ import annotations

import json

from ..authority_service.d12_installation_lifecycle_rpc_v1 import CONTROL_METHOD
from ..authority_service.d12_lifecycle_contract_v1 import D12InstallationControlIntentV1
from ..authority_service.d12_lifecycle_gate_v1 import D12LifecycleAdmissionV1
from ..authority_service.v2_contract import SCHEMA
from ..authority_service.v2_owner_session import to_wire as session_to_wire
from ..domains.d12.backend_operation_contracts_v1 import D12ControlPayloadV1
from ..runtime.lifecycle_operations_v1 import D12PrerequisiteUnavailable, decode_original, digest


class InstalledD12InstallationControlPortV1:
    def __init__(self, *, coordinator, bootstrap, authority_port):
        coordinator._admin(bootstrap)
        if coordinator._GraphCoordinator__content_fence_v2 is not authority_port:
            raise TypeError("installation control requires W01's paired Authority")
        self.coordinator,self.port=coordinator,authority_port
        self.lifecycle=None

    def bind_lifecycle_v1(self,lifecycle):
        if self.lifecycle is not None or lifecycle.store.db is not self.coordinator._GraphCoordinator__store._db:
            raise ValueError("installation control must bind once to its actual W01 producer")
        self.lifecycle=lifecycle

    def _rpc(self, authority, lease, *, action, **extra):
        c=self.coordinator
        c._authorize(lease,authority,frozenset(),owner_read=True)
        token,request=c._GraphCoordinator__owner_session_proofs[lease]
        async def call():
            await self.port._mapped(authority.namespace,request.authority_namespace)
            handshake,grant=self.port._identity()
            response=await self.port._transport._content_rpc(self.port._request,handshake,CONTROL_METHOD,
                {"namespace":request.authority_namespace,"action":action,"owner_actor_id":authority.actor,
                 "owner_session_token":token,"owner_session_request":session_to_wire(request),**extra},protocol=SCHEMA)
            if action=="inspect":
                if set(response)!={"lifecycle_head","channel_binding_sha256"}:
                    raise RuntimeError("installed lifecycle inspection response differs")
                head=D12LifecycleAdmissionV1(**response["lifecycle_head"])
                if head.namespace!=request.authority_namespace or head.installation_id!=grant.installation_id:
                    raise PermissionError("lifecycle controller belongs to another installation")
                return head
            if set(response)!={"original","channel_binding_sha256"}:
                raise RuntimeError("installed lifecycle operation response differs")
            original=decode_original(response["original"])
            if original.namespace!=authority.namespace or original.kind!="control":
                raise PermissionError("lifecycle original belongs to another namespace/kind")
            return original
        return self.port._submit(self.port._with_session_repair(call))

    def read_current_installation_lifecycle_v1(self, authority, lease):
        head = self._rpc(authority, lease, action="inspect")
        return {"schema":"d12.installation_lifecycle_view.v1", "scope":"whole_host",
            "installation_id":head.installation_id, "state":head.state,
            "lifecycle_epoch":head.epoch, "head_digest":head.head_digest,
            "operation_id":head.operation_id}

    def execute_current_lifecycle_control_v1(self, authority, lease, *, operation_id, request_digest, command, input_data):
        try:
            intent=D12InstallationControlIntentV1.from_command(command)
        except ValueError as exc:
            raise D12PrerequisiteUnavailable("explicit_whole_host_control_intent_required") from exc
        lifecycle=self.lifecycle
        if lifecycle is None or lifecycle.operation_status_port is None:
            raise D12PrerequisiteUnavailable("installed_whole_host_producer_unavailable")
        with lifecycle.store.lock:
            existing=lifecycle.store.get_operation(authority.namespace,operation_id)
            original=(lifecycle.store.original(authority.namespace,existing[4])
                      if existing is not None and existing[4] is not None else None)
        if existing is not None and (existing[0]!=request_digest or existing[1]!="control"
                or json.loads(existing[3])!=input_data):
            from ..contracts import StaleRead
            raise StaleRead("original whole-Host operation request changed")
        if original is not None:
            # The head necessarily advances after accept. Replaying the exact
            # original uses independent current Owner status, never a new W01
            # command fence or an old-epoch write against the stopped Host.
            return self._submit_original(authority,lease,original)
        try:
            head=self._rpc(authority,lease,action="inspect")
        except PermissionError:
            raise
        except Exception as exc:
            raise D12PrerequisiteUnavailable("installed_whole_host_controller_unavailable") from exc
        if intent.installation_id!=head.installation_id or intent.expected_lifecycle_epoch!=head.epoch:
            from ..contracts import StaleRead
            raise StaleRead("whole-Host control current lifecycle epoch differs")
        def accept(owner):
            prior=lifecycle.store.claim(owner,operation_id,request_digest,"control",input_data)
            if prior is not None and prior[4] is not None:
                return lifecycle.store.original(owner.namespace,prior[4])
            return lifecycle.store.publish(owner,operation_id,request_digest,kind="control",
                payload=D12ControlPayloadV1(command.object_ref,command.control,head.epoch,(),False),state="accepted",
                authority_refs=(("lifecycle_head","installation:"+head.installation_id,head.head_digest),),
                coverage=("explicit_whole_host_scope","durable_owner_intent"))
        original=lifecycle._command(authority,lease,operation_id=operation_id,request_digest=request_digest,
            capability="workbench.maintain",commit=accept)
        return self._submit_original(authority,lease,original)

    def _submit_original(self, authority, lease, original):
        lifecycle=self.lifecycle
        registered=lifecycle.operation_status_port.ensure_registered_operation_v1(authority,lease,original=original)
        try:
            return self._rpc(authority,lease,action="submit",original_ref=registered.original_ref)
        except PermissionError:
            raise
        except Exception:
            # Exact independent status can resolve a lost submit ACK. No second
            # operation, process start, or guessed completed state is created.
            return lifecycle.operation_status_port.refresh_current_transfer_status_v1(
                authority,lease,original_ref=registered.original_ref)


__all__=("InstalledD12InstallationControlPortV1",)
