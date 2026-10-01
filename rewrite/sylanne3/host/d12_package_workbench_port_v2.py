"""Explicit signed Owner C11 calls over the coordinator's actual paired port."""
from ..authority_service.v2_contract import SCHEMA
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1,to_wire as session_to_wire
from ..runtime_contracts import NamespaceId,canonical_digest
from ..workbench_api.package_maintenance_v2 import decode_package_status_v2,decode_package_profile_v2


class InstalledD12PackageWorkbenchPortV2:
    def __init__(self,*,coordinator,bootstrap,authority_port):
        coordinator._admin(bootstrap)
        if coordinator._GraphCoordinator__content_fence_v2 is not authority_port:raise TypeError('actual coordinator paired package port required')
        self.coordinator=coordinator;self.port=authority_port

    def _call(self,*,session,scope,action,operation_id=None,**extra):
        request=session.owner_session_request
        if type(request) is not OwnerSessionLoginRequestV1 or not session.owner_session_token:raise PermissionError('current signed Owner package session required')
        namespace=NamespaceId(*scope.split('/'))
        async def call():
            await self.port._mapped(namespace,request.authority_namespace)
            handshake,grant=self.port._identity()
            command={'namespace':request.authority_namespace,'action':action,'owner_actor_id':session.actor_id,
                'owner_session_token':session.owner_session_token,'owner_session_request':session_to_wire(request),**extra}
            if operation_id is not None:command['operation_id']=operation_id
            response=await self.port._transport._content_rpc(self.port._request,handshake,'d12_package_maintenance_v2',command,protocol=SCHEMA)
            response=dict(response);response.pop('channel_binding_sha256',None)
            if action=='profile':
                if set(response)!={'profile'}:raise RuntimeError('package profile response differs')
                result=decode_package_profile_v2(response['profile'],scope=scope)
                if result['installation_id']!=grant.installation_id:raise PermissionError('package profile belongs to another installation')
                return result
            intent,result=decode_package_status_v2(response,scope=scope,operation_id=operation_id)
            if intent.authority_id!=grant.authority_id or intent.installation_id!=grant.installation_id:raise PermissionError('package operation belongs to another paired installation')
            if action=='accept':
                expected=canonical_digest({'schema':'d12.compatible-package-request.v2','operation_id':operation_id,**extra})
                if intent.request_digest!=expected:raise PermissionError('package acceptance does not bind exact requested candidate/epochs')
            return result
        return self.port._submit(self.port._with_session_repair(call))

    def read_session_package_maintenance_v2(self,*,session,scope):
        return self._call(session=session,scope=scope,action='profile')

    def accept_session_package_switch_v2(self,*,session,scope,operation_id,input_data):
        return self._call(session=session,scope=scope,action='accept',operation_id=operation_id,**dict(input_data))

    def read_session_package_operation_v2(self,*,session,scope,operation_id):
        return self._call(session=session,scope=scope,action='status',operation_id=operation_id)
