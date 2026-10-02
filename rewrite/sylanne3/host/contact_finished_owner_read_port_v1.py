"""Closed mTLS read association; caller dictionaries are never authority."""
from ..authority_service.contact_finished_owner_read_rpc_v1 import METHOD
from ..authority_service.contact_finished_owner_read_v1 import (
    OwnerContactFinishedReadUseV1, to_wire, validate_association, digest)
from ..authority_service.contact_owner_session_v3 import ContactOwnerSessionObservationV3, to_wire as session_observation_to_wire
from ..authority_service.contact_fence_finished_v3 import contact_finished_from_wire_v3
from ..authority_service.v2_owner_session import to_wire as session_to_wire
from ..authority_service.v2_contract import SCHEMA, FencePermitV2, to_wire as permit_to_wire, from_wire
from ..authority_service.d12_target_owner_admission_v1 import current_owner_authority_from_wire_v1


def associate_contact_finished_owner_read_v1(port, *, namespace, authority_namespace, permit,
        old_permit, owner_actor_id, owner_session_token, owner_session_request, original, use, signature):
    if (type(permit) is not FencePermitV2 or permit.operation != 'read'
            or type(old_permit) is not FencePermitV2 or old_permit.operation != 'write'
            or type(original) is not ContactOwnerSessionObservationV3
            or type(use) is not OwnerContactFinishedReadUseV1 or type(signature) is not bytes or len(signature) != 64):
        raise ValueError('finished Contact read needs exact signed readonly use and actual permits')
    async def read():
        await port._mapped(namespace, authority_namespace)
        port._owner_session_identity(namespace, authority_namespace, owner_session_request)
        handshake, grant = port._identity()
        if ((permit.authority_id, permit.subject) != (grant.authority_id, grant.subject)
                or (old_permit.authority_id, old_permit.subject) != (grant.authority_id, grant.subject)):
            raise PermissionError('finished Contact permits belong to another installation')
        response = await port._transport._content_rpc(port._request, handshake, METHOD,
            dict(namespace=authority_namespace, permit=permit_to_wire(permit), old_permit=permit_to_wire(old_permit),
                owner_actor_id=owner_actor_id, owner_session_token=owner_session_token,
                owner_session_request=session_to_wire(owner_session_request),
                original=session_observation_to_wire(original), use=to_wire(use), signature=signature.hex()), protocol=SCHEMA)
        if type(response) is not dict or set(response) != {'association', 'authority', 'finished', 'channel_binding_sha256'}:
            raise RuntimeError('finished Contact read authenticated response fields differ')
        authority = response['authority']
        if type(authority) is not dict or set(authority) not in (
                {'guard', 'target_admission', 'permit'}, {'guard', 'target_admission', 'storage_admission', 'permit'}):
            raise RuntimeError('finished Contact current authority fields differ')
        current = current_owner_authority_from_wire_v1({k:v for k,v in authority.items() if k != 'permit'})
        finished = contact_finished_from_wire_v3(response['finished'])
        if (from_wire(authority['permit']) != permit or current.guard.namespace != namespace
                or current.guard.authority_id != grant.authority_id or finished.permit != old_permit):
            raise PermissionError('finished Contact current read/old finished permit differs')
        session = validate_association(response['association'], original=original, use=use,
            finished=finished, read_permit=permit, read_guard_digest=digest(authority))
        if ((session.principal, session.actor, session.installation_id, session.authority_id, session.authority_namespace)
                != (owner_session_request.principal, owner_actor_id, grant.installation_id, grant.authority_id, authority_namespace)):
            raise PermissionError('finished Contact current read session identity differs')
        return response['association'], current, finished
    return port._submit(port._with_session_repair(read))
