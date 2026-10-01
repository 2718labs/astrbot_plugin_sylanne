"""W01's installed mTLS read for source guard plus target Owner admission."""
from __future__ import annotations

from ..authority_service.d12_target_owner_admission_v1 import (
    D12CurrentOwnerAuthorityV1, current_owner_authority_from_wire_v1,
)
from ..authority_service.d12_target_owner_rpc_v1 import METHOD, BACKGROUND_METHOD
from ..authority_service.v2_contract import SCHEMA, to_wire, from_wire
from ..authority_service.v2_owner_contract import from_wire as owner_from_wire
from ..authority_service.v2_owner_session import to_wire as session_to_wire


def get_current_owner_authority_for_fence_v1(port, *, namespace, authority_namespace,
        permit, owner_actor_id, owner_session_token, owner_session_request):
    """Call only with the exact W01 permit and original signed-session proof."""
    async def read():
        await port._mapped(namespace, authority_namespace)
        port._owner_session_identity(namespace, authority_namespace, owner_session_request)
        handshake, grant = port._identity()
        if permit.authority_id != grant.authority_id or permit.subject != grant.subject:
            raise PermissionError("Owner authority fence belongs to another installation")
        response = await port._transport._content_rpc(port._request, handshake, METHOD,
            {"namespace": authority_namespace, "permit": to_wire(permit), "owner_actor_id": owner_actor_id,
             "owner_session_token": owner_session_token,
             "owner_session_request": session_to_wire(owner_session_request)}, protocol=SCHEMA)
        if set(response) not in ({"guard", "target_admission", "permit", "channel_binding_sha256"},{"guard", "target_admission", "storage_admission", "permit", "channel_binding_sha256"}):
            raise RuntimeError("current Owner authority response shape differs")
        observed = from_wire(response["permit"])
        current=current_owner_authority_from_wire_v1({k:v for k,v in response.items() if k not in {"permit","channel_binding_sha256"}})
        guard,admission=current.guard,current.target_admission
        storage=current.storage_admission
        if storage is not None and (storage.installation_id!=grant.installation_id or storage.holder!=permit.holder
                or storage.activation_generation!=permit.generation or storage.authority_namespace!=authority_namespace
                or storage.revocation_epoch!=permit.pinned_anchor.revocation_epoch):raise PermissionError("source Owner storage continuation differs from current fence")
        if observed != permit or guard.namespace != namespace or guard.authority_id != grant.authority_id:
            raise PermissionError("current Owner authority response identity differs")
        if storage is not None and storage.principal!=owner_session_request.principal:
            raise PermissionError("source Owner storage principal differs")
        if admission is None:
            if guard.installation_id != grant.installation_id:
                raise PermissionError("source Owner guard belongs to another installation")
        elif (admission.target_installation_id != grant.installation_id
                or admission.target_holder != permit.holder
                or admission.activation_generation != permit.generation
                or admission.principal != owner_session_request.principal
                or admission.target_actor_id != owner_actor_id
                or (admission.target_credential_id, admission.target_credential_epoch) != (
                    owner_session_request.credential_id, owner_session_request.credential_epoch)):
            raise PermissionError("target Owner admission belongs to another current session or fence")
        return current, observed
    return port._submit(port._with_session_repair(read))


def get_current_background_owner_authority_for_fence_v1(port, *, namespace, authority_namespace, permit):
    async def read():
        await port._mapped(namespace, authority_namespace)
        handshake, grant = port._identity()
        if permit.authority_id != grant.authority_id or permit.subject != grant.subject:
            raise PermissionError("background Owner fence belongs to another installation")
        response = await port._transport._content_rpc(port._request, handshake, BACKGROUND_METHOD,
            {"namespace": authority_namespace, "permit": to_wire(permit)}, protocol=SCHEMA)
        if set(response) not in ({"guard", "target_admission", "permit", "channel_binding_sha256"},{"guard", "target_admission", "storage_admission", "permit", "channel_binding_sha256"}):
            raise RuntimeError("current background Owner response shape differs")
        observed = from_wire(response["permit"])
        current=current_owner_authority_from_wire_v1({k:v for k,v in response.items() if k not in {"permit","channel_binding_sha256"}})
        guard,admission=current.guard,current.target_admission
        storage=current.storage_admission
        if storage is not None and (storage.installation_id!=grant.installation_id or storage.holder!=permit.holder
                or storage.activation_generation!=permit.generation or storage.authority_namespace!=authority_namespace
                or storage.revocation_epoch!=permit.pinned_anchor.revocation_epoch):raise PermissionError("source Owner storage continuation differs from current fence")
        if observed != permit or guard.namespace != namespace or guard.authority_id != grant.authority_id:
            raise PermissionError("current background Owner response identity differs")
        if admission is None:
            if guard.installation_id != grant.installation_id:
                raise PermissionError("background source Owner installation differs")
        elif (admission.target_installation_id != grant.installation_id
                or admission.target_holder != permit.holder
                or admission.activation_generation != permit.generation):
            raise PermissionError("background target Owner admission differs")
        return current, observed
    return port._submit(port._with_session_repair(read))


__all__ = ("get_current_owner_authority_for_fence_v1", "get_current_background_owner_authority_for_fence_v1")
