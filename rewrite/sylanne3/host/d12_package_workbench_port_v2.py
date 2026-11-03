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

    def _inspection_call_v1(self, *, session, scope, action, operation_id=None, **extra):
        from ..authority_service.d12_installation_lifecycle_rpc_v1 import CONTROL_METHOD
        from ..workbench_api.source_inspection_migration_v1 import decode_inspection_view_v1
        request = session.owner_session_request
        if type(request) is not OwnerSessionLoginRequestV1 or not session.owner_session_token:
            raise PermissionError('actual signed Owner inspection session required')
        namespace = NamespaceId(*scope.split('/'))
        async def call():
            await self.port._mapped(namespace, request.authority_namespace)
            handshake, grant = self.port._identity()
            command = dict(namespace=request.authority_namespace, action=action, owner_actor_id=session.actor_id,
                owner_session_token=session.owner_session_token, owner_session_request=session_to_wire(request), **extra)
            if operation_id is not None:
                command['operation_id'] = operation_id
            response = await self.port._transport._content_rpc(
                self.port._request, handshake, CONTROL_METHOD, command, protocol=SCHEMA)
            field = 'inspection_access' if action == 'inspection_access' else 'inspection_workflow'
            if set(response) != {field, 'channel_binding_sha256'}:
                raise RuntimeError('inspection workflow actual response differs')
            result = response[field]
            if action == 'inspection_access':
                if (type(result) is not dict or set(result) != {'schema', 'scope', 'installation_id', 'actor', 'owner_head',
                        'capabilities', 'purposes', 'audiences', 'lifecycle_head'}
                        or result['schema'] != 'd12.source-inspection-maintenance-access.v1'
                        or result['scope'] != scope or result['installation_id'] != grant.installation_id
                        or result['actor'] != session.actor_id):
                    raise PermissionError('inspection access belongs to another current Owner/installation')
            else:
                decode_inspection_view_v1(result, scope=scope, operation_id=operation_id)
                if result['installation_id'] != grant.installation_id:
                    raise PermissionError('inspection workflow belongs to another paired installation')
                if action == 'inspection_workflow_accept' and (
                        result['request_digest'] != canonical_digest(extra['input_data'])
                        or any(result[name] != value for name, value in extra['input_data'].items())):
                    raise RuntimeError('inspection workflow acceptance differs from its actual submitted request')
            return result
        return self.port._submit(self.port._with_session_repair(call))

    def read_session_inspection_access_v1(self, *, session, scope):
        return self._inspection_call_v1(session=session, scope=scope, action='inspection_access')

    def read_session_source_inspection_migration_v1(self, *, session, scope, operation_id):
        return self._inspection_call_v1(session=session, scope=scope,
            action='inspection_workflow_status', operation_id=operation_id)

    def accept_session_source_inspection_migration_v1(self, *, session, scope, operation_id, input_data):
        return self._inspection_call_v1(session=session, scope=scope,
            action='inspection_workflow_accept', operation_id=operation_id, input_data=dict(input_data))
