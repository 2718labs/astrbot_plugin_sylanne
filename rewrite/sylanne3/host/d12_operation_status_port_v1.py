"""Installed D12 exact-operation status over the existing authenticated mTLS port."""
from __future__ import annotations

from ..authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from ..authority_service.v2_contract import to_wire as fence_to_wire
from ..authority_service.v2_owner_session import to_wire as session_to_wire
from ..runtime.lifecycle_operations_v1 import decode_original


class InstalledD12OperationStatusPortV1:
    def __init__(self, *, coordinator, bootstrap, authority_port):
        coordinator._admin(bootstrap)
        if coordinator._GraphCoordinator__content_fence_v2 is not authority_port:
            raise TypeError("D12 status requires the coordinator's paired Authority port")
        self.coordinator, self.port = coordinator, authority_port

    @staticmethod
    def owns_original_ref_v1(original_ref):
        return type(original_ref) is str and original_ref.startswith("d12authority:")

    def _session(self, authority, lease):
        c = self.coordinator
        c._authorize(lease, authority, frozenset(), owner_read=True)
        owner = c._GraphCoordinator__owner_leases.get(lease)
        proof = c._GraphCoordinator__owner_session_proofs.get(lease)
        if owner is None or proof is None or owner.actor != authority.actor:
            raise PermissionError("D12 requires its signed initiating Owner session")
        return proof

    def _call(self, *, method, namespace, actor, token, request, original_ref, permit=None, refresh=False):
        async def call():
            await self.port._mapped(namespace, request.authority_namespace)
            handshake, grant = self.port._identity()
            command = {"namespace": request.authority_namespace,
                "owner_actor_id": actor, "owner_session_token": token,
                "owner_session_request": session_to_wire(request), "original_ref": original_ref}
            if permit is not None:
                command["permit"] = fence_to_wire(permit)
            else:
                command["refresh"] = refresh
            response = await self.port._transport._content_rpc(self.port._request, handshake,
                method, command, protocol=AUTHORITY_V2_PROTOCOL)
            if set(response) != {"original", "channel_binding_sha256"}:
                raise RuntimeError("D12 Authority status response shape differs")
            if response["original"] is None and method == "d12_resolve_operation_v1":
                return None
            original = decode_original(response["original"])
            if original.namespace != namespace or original.kind not in {"transfer_execution", "control"}:
                raise RuntimeError("D12 Authority status response identity differs")
            return original
        return self.port._submit(self.port._with_session_repair(call))

    def ensure_registered_operation_v1(self, authority, lease, *, original):
        token, request = self._session(authority, lease)
        registered = self._call(method="d12_resolve_operation_v1", namespace=authority.namespace,
            actor=authority.actor, token=token, request=request, original_ref=original.original_ref)
        if registered is None:
            registered = self.register_current_operation_v1(authority, lease, original=original)
        if (registered.operation_id, registered.request_digest, registered.plan_ref,
                registered.plan_digest, registered.owner_grant_digest) != (
                original.operation_id, original.request_digest, original.plan_ref,
                original.plan_digest, original.owner_grant_digest):
            raise PermissionError("registered D12 original identity differs")
        return registered

    def register_current_operation_v1(self, authority, lease, *, original):
        c = self.coordinator
        owner = c._GraphCoordinator__owner_leases.get(lease)
        token, request = self._session(authority, lease)
        # The callback executes outside Graph's lock and the registration RPC
        # independently rereads the original from the installed source Graph.
        registered = []
        def register(scope):
            result = self._call(method="d12_register_operation_v1", namespace=authority.namespace,
                actor=authority.actor, token=token, request=request,
                original_ref=original.original_ref, permit=scope.permit)
            registered.append(result)
            return result
        c._read_v2(authority, lambda: None, owner_binding=owner,
            owner_session_proof=(token, request), fence_observer=register)
        if not registered or any(value != registered[0] for value in registered):
            raise PermissionError("D12 operation registration changed during admission")
        return registered[0]

    def read_current_backend_operation_original_v1(self, authority, lease, *, original_ref):
        token, request = self._session(authority, lease)
        return self._call(method="d12_read_operation_v1", namespace=authority.namespace,
            actor=authority.actor, token=token, request=request, original_ref=original_ref)

    def refresh_current_transfer_status_v1(self, authority, lease, *, original_ref):
        token, request = self._session(authority, lease)
        return self._call(method="d12_read_operation_v1", namespace=authority.namespace,
            actor=authority.actor, token=token, request=request, original_ref=original_ref, refresh=True)

    def read_session_operation_status_v1(self, *, session, scope, original_ref, refresh=True):
        # HTTP recovery deliberately bypasses grant_current_owner, whose content
        # fence is unavailable after freeze. Authority authenticates the exact
        # initiating identity and original instead; no new Graph lease is minted.
        from ..runtime_contracts import NamespaceId
        parts = scope.split("/")
        request = session.owner_session_request
        if len(parts) != 2 or request is None or not session.owner_session_token:
            raise PermissionError("exact scope and signed Owner status session required")
        return self._call(method="d12_read_operation_v1", namespace=NamespaceId(*parts),
            actor=session.actor_id, token=session.owner_session_token, request=request,
            original_ref=original_ref, refresh=refresh)


__all__ = ("InstalledD12OperationStatusPortV1",)
