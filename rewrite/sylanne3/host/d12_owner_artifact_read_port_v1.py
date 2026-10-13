"""Actual fixed mTLS Host read observer, consumed only by W01's read fence."""
from ..authority_service.d12_owner_artifact_rpc_v1 import BODY_METHOD, BINDING_METHOD
from ..authority_service.v2_contract import SCHEMA, to_wire
from ..authority_service.v2_owner_session import to_wire as session_to_wire
from ..runtime_contracts import canonical_digest
from ..runtime.d12_owner_artifact_read_v1 import (OwnerArtifactReadRequestV1,OwnerArtifactReadBindingV1,
    request_to_wire_v1,binding_to_wire_v1,observation_from_wire_v1)

def observe_owner_artifact_for_fence_v1(port, *, scope, request, owner_actor_id, owner_session_token,
        owner_session_request, expected_binding=None):
    if type(request) is not OwnerArtifactReadRequestV1 or expected_binding is not None and type(expected_binding) is not OwnerArtifactReadBindingV1:
        raise TypeError('typed private Owner artifact read selector/binding required')
    async def observe():
        await port._mapped(request.namespace,scope.authority_namespace)
        port._owner_session_identity(request.namespace,scope.authority_namespace,owner_session_request)
        handshake,grant=await port._check_scope(scope)
        if (scope.operation!='read' or scope.namespace!=request.namespace or request.installation_id!=grant.installation_id
                or scope.permit.subject!=grant.subject or scope.permit.authority_id!=grant.authority_id):
            raise PermissionError('Owner artifact read crossed the actual paired read scope')
        command={'namespace':scope.authority_namespace,'permit':to_wire(scope.permit),'request':request_to_wire_v1(request),
            'owner_actor_id':owner_actor_id,'owner_session_token':owner_session_token,'owner_session_request':session_to_wire(owner_session_request)}
        if expected_binding is not None:command['expected_binding']=binding_to_wire_v1(expected_binding)
        response=await port._transport._content_rpc(port._request,handshake,
            BODY_METHOD if expected_binding is None else BINDING_METHOD,command,protocol=SCHEMA)
        if type(response) is not dict or set(response)!={'observation','channel_binding_sha256'} or response['channel_binding_sha256']!=handshake.channel_binding_sha256:raise RuntimeError('exact private artifact read response required')
        observation=observation_from_wire_v1(response['observation']);binding=observation.read_binding
        if (binding.request_digest!=request.digest or binding.permit_digest!=canonical_digest(scope.permit)
                or binding.current_owner_head.namespace!=request.namespace or binding.current_owner_head.authority_id!=grant.authority_id or binding.current_owner_head.installation_id!=grant.installation_id
                or binding.graph_revision!=scope.graph_revision or binding.graph_epoch!=scope.graph_epoch.revision):
            raise PermissionError('artifact actual request/Owner/read-permit/Graph stamp differs')
        if expected_binding is None:
            result=observation.result
            if result is None or (result.namespace,result.installation_id,result.project_ref,result.progress_ref,result.artifact_version,result.content_digest)!=                    (request.namespace,request.installation_id,request.project_ref,request.progress_ref,request.expected_artifact_version,request.expected_content_digest):
                raise PermissionError('artifact complete verified body result differs from actual selector')
        elif observation.result is not None or binding.current_commitment!=expected_binding.current_commitment:
            raise PermissionError('artifact second observer changed the actual bound read')
        return observation
    return port._submit(port._with_session_repair(observe))


async def read_owner_artifact_response_line_v2(reader, *, timeout_seconds):
    """One ordinary newline frame; only the named body RPC may use 1MiB."""
    import asyncio
    from ..runtime.d12_owner_artifact_read_v1 import BODY_RESPONSE_MAX_BYTES
    data=bytearray()
    async def receive():
        while True:
            block=await reader.read(min(65536,BODY_RESPONSE_MAX_BYTES+1-len(data)))
            if not block:raise RuntimeError('artifact body response ended before its complete frame')
            data.extend(block)
            end=data.find(b'\n')
            if len(data)>BODY_RESPONSE_MAX_BYTES or end>=0 and end!=len(data)-1:
                raise RuntimeError('artifact body response framing bound differs')
            if end>=0:return bytes(data)
    return await asyncio.wait_for(receive(),timeout_seconds)
