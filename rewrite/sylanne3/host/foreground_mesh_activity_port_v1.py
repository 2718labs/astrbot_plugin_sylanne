"""Exact paired Host port for independently issued Personal mesh evidence."""
from ..runtime_contracts import FenceScope
from ..authority_service.foreground_mesh_contract_v1 import (
    ForegroundMeshActivityRequestV1,OwnerTaskMeshActivityRequestV1,
    ForegroundMeshActivityEvidenceV1,OwnerTaskMeshActivityEvidenceV1,
    personal_mesh_to_wire_v1,personal_mesh_from_wire_v1,personal_mesh_fence_operation_id_v1)
from ..authority_service.v2_contract import FencePermitV2,SCHEMA as AUTHORITY_V2_PROTOCOL,to_wire,from_wire

async def personal_mesh_activity_rpc_v1(port,method,*,scope,request):
    methods = {
        "foreground_mesh_activity_admit_v1":(ForegroundMeshActivityRequestV1,ForegroundMeshActivityEvidenceV1),
        "foreground_mesh_activity_current_v1":(ForegroundMeshActivityRequestV1,ForegroundMeshActivityEvidenceV1),
        "owner_task_mesh_activity_admit_v1":(OwnerTaskMeshActivityRequestV1,OwnerTaskMeshActivityEvidenceV1),
        "owner_task_mesh_activity_current_v1":(OwnerTaskMeshActivityRequestV1,OwnerTaskMeshActivityEvidenceV1),
    }
    if method not in methods or type(scope) is not FenceScope or type(request) is not methods[method][0]:
        raise TypeError("Personal mesh port requires its exact registered selector and original scope")
    original = request.original
    if scope.namespace != original.namespace or scope.operation != "write":
        raise RuntimeError("Personal mesh changed its original WRITE namespace")
    await port._mapped(scope.namespace,scope.authority_namespace)
    handshake,grant = port._identity()
    permit = scope.permit
    if (permit.operation_id != personal_mesh_fence_operation_id_v1(request)
            or original.installation_id != grant.installation_id
            or (permit.authority_id,permit.namespace,permit.subject,permit.holder) !=
                (grant.authority_id,scope.authority_namespace,grant.subject,grant.administrator_holder)):
        raise RuntimeError("Personal mesh changed its actual paired installation or original fence")
    response = await port._transport._content_rpc(port._request,handshake,method,
        {"namespace":scope.authority_namespace,"permit":to_wire(permit),"request":personal_mesh_to_wire_v1(request)},
        protocol=AUTHORITY_V2_PROTOCOL)
    if set(response) != {"evidence","permit","channel_binding_sha256"}:
        raise RuntimeError("Personal mesh paired response fields differ")
    evidence = personal_mesh_from_wire_v1(response["evidence"],methods[method][1])
    observed = from_wire(response["permit"])
    if (type(observed) is not FencePermitV2 or observed != permit or evidence.request != request
            or evidence.original.current_self.permit != permit):
        raise RuntimeError("Personal mesh paired result changed its original request, permit or Self")
    return evidence,observed
