"""Exact original Method/Owner fence transport for bodyless retention metadata."""
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.retention_control_metadata_v1 import METHOD
from ..authority_service.v2_contract import SCHEMA,to_wire
from ..authority_service.v2_owner_session import to_wire as session_to_wire
from ..runtime_contracts import canonical_digest


def read_retention_control_metadata_v1(port,*,reader,task,action):
    from ..runtime.retention_control_protection_v1 import (
        retention_control_transport_scope_v1,retention_control_work_identity_v1)
    if action not in {'advance','recheck','release'} or task.reader is not reader or task.port is not port:
        raise AuthorityUnavailable('retention metadata port requires its actual private task')
    if action=='release':
        scope=reader.fence.scope
    else:
        scope=retention_control_transport_scope_v1(reader,task,action)
        if action=='recheck' and reader.db.in_transaction:
            raise AuthorityUnavailable('retention Core observation cannot run inside Graph SQL')
        if action=='advance' and (reader.read_finished or reader.db.in_transaction):
            raise AuthorityUnavailable('retention metadata page requires its original live READ outside SQL')
        if action=='recheck' and scope.operation!=('write' if reader.read_finished else 'read'):
            raise AuthorityUnavailable('retention metadata recheck requires its real same-Work current fence')
    if port is not reader.graph._GraphCoordinator__content_fence_v2:
        raise AuthorityUnavailable('retention metadata crossed its actual installed Host port')
    token,request=reader.session_proof
    async def read():
        await port._mapped(reader.namespace,scope.authority_namespace)
        port._owner_session_identity(reader.namespace,scope.authority_namespace,request)
        handshake,grant=port._identity()
        if (scope.permit.authority_id!=grant.authority_id or scope.permit.subject!=grant.subject
                or reader.fence.scope.permit.holder!=scope.permit.holder):
            raise AuthorityUnavailable('retention metadata permit crossed its original installed subject')
        command=dict(namespace=scope.authority_namespace,
            graph_namespace={'bot_id':reader.namespace.bot_id,'persona_id':reader.namespace.persona_id},
            permit=to_wire(scope.permit),original_permit=to_wire(reader.fence.scope.permit),
            owner_actor_id=reader.authority.actor,owner_session_token=token,
            owner_session_request=session_to_wire(request),operation_kind=reader.operation_kind,
            source_ref=task.source_ref,work_identity=retention_control_work_identity_v1(reader),
            selection_digest=reader.selection_digest,graph_stamp_digest=canonical_digest(reader.graph_stamp),
            deadline_utc=reader.operation.deadline_utc,action=action,continuation=task.continuation)
        response=await port._transport._content_rpc(port._request,handshake,METHOD,command,protocol=SCHEMA)
        if (set(response)!={'continuation','complete','original','channel_binding_sha256'}
                or type(response['continuation']) is not str or type(response['complete']) is not bool
                or task.continuation is not None and response['continuation']!=task.continuation
                or not response['complete'] and response['original'] is not None):
            raise AuthorityUnavailable('retention metadata response differs from its actual private continuation')
        task.continuation=response['continuation']
        if action!='release' and response['complete'] and response['original'] is None:
            raise AuthorityUnavailable('retention Control EOF has no actual signed metadata original')
        return response['original']
    return port._submit(read())
