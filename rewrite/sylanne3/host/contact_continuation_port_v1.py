"""Installed Contact continuation transport with its actual TLS response binding."""
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.contact_continuation_contract_v1 import (ContactContinuationSelectorV1,ContactContinuationObservationV1,
    ContactContinuationObservationProjectionReadV1,contact_continuation_from_wire_v1,contact_continuation_to_wire_v1)
from ..authority_service.v2_contract import FencePermitV2,to_wire,canonical_digest as authority_digest,SCHEMA
from ..runtime_contracts import canonical_digest
from .v2_fence_port import V2FencePort
from .authority_profile import AdminInstallationBundle
_KEY=object()

class InstalledContactContinuationPortV1:
    def __init__(self,key,port,bundle):
        if (key is not _KEY or type(port)is not V2FencePort or type(bundle)is not AdminInstallationBundle
                or (port.installation_grant.installation_id,port.installation_grant.manifest_digest)!=(
                    bundle.installation_policy.installation_id,bundle.installation_policy.manifest_digest)):
            raise AuthorityUnavailable('Contact continuation needs its actual explicitly installed transport')
        self.port,self.bundle=port,bundle
    async def _call(self,method,selector,command):
        policy=self.bundle.installation_policy
        if type(selector)is not ContactContinuationSelectorV1 or selector.namespace!=policy.namespace:
            raise AuthorityUnavailable('Contact continuation transport changed its exact selector namespace')
        await self.port._mapped(policy.namespace,policy.authority_namespace)
        handshake,grant=self.port._identity()
        if (grant.installation_id,grant.administrator_holder,grant.manifest_digest)!=(
                policy.installation_id,policy.administrator_holder,policy.manifest_digest):
            raise AuthorityUnavailable('Contact continuation installed channel identity changed')
        response=await self.port._transport._content_rpc(self.port._request,handshake,method,
            {'namespace':policy.authority_namespace,'selector':contact_continuation_to_wire_v1(selector),**command},protocol=SCHEMA)
        expected=({'observation','authority','channel_binding_sha256'}if method in{'capture_contact_continuation_v1','read_existing_contact_continuation_v1'}else
            {'projection','channel_binding_sha256'})
        if type(response)is not dict or set(response)!=expected or response['channel_binding_sha256']!=handshake.channel_binding_sha256:
            raise AuthorityUnavailable('Contact continuation response escaped its actual authenticated channel')
        return response
    def capture_contact_continuation_v1(self,permit,selector):
        if type(permit)is not FencePermitV2 or type(selector)is not ContactContinuationSelectorV1:
            raise TypeError('Contact continuation requires its exact WRITE permit and later selector')
        return self.port._submit(self.port._with_session_repair(lambda:self._capture(permit,selector)))
    def capture(self,permit,selector):return self.capture_contact_continuation_v1(permit,selector)
    async def _capture(self,permit,selector):
        policy=self.bundle.installation_policy
        if permit.namespace!=policy.authority_namespace or permit.operation!='write':raise AuthorityUnavailable('Contact continuation actual WRITE scope differs')
        response=await self._call('capture_contact_continuation_v1',selector,{'permit':to_wire(permit)})
        observed=contact_continuation_from_wire_v1(response['observation'],ContactContinuationObservationV1);authority=response['authority']
        if (observed.selector!=selector or observed.installation_id!=policy.installation_id or observed.authority_namespace!=policy.authority_namespace
                or observed.attempt_id!=permit.operation_id or observed.permit_digest!=authority_digest(permit).removeprefix('sha256:')
                or type(authority)is not dict or authority.get('permit')!=to_wire(permit) or observed.owner_authority_digest!=canonical_digest(authority)):
            raise AuthorityUnavailable('Contact continuation actual reply/Owner/WRITE changed')
        return observed,authority
    def read_existing_contact_continuation_v1(self,original_write_permit,selector):
        if type(original_write_permit)is not FencePermitV2 or type(selector)is not ContactContinuationSelectorV1:
            raise TypeError('Existing Contact continuation requires its actual original WRITE and later selector')
        return self.port._submit(self.port._with_session_repair(lambda:self._existing(original_write_permit,selector)))
    async def _existing(self,write_permit,selector):
        from ..authority_service.d12_target_owner_admission_v1 import current_owner_authority_from_wire_v1
        policy=self.bundle.installation_policy
        if (write_permit.operation,write_permit.namespace,write_permit.holder)!=(
                'write',policy.authority_namespace,policy.administrator_holder):
            raise AuthorityUnavailable('Existing continuation original WRITE is outside its installed scope')
        response=await self._call('read_existing_contact_continuation_v1',selector,{'original_write_permit':to_wire(write_permit)})
        observed=contact_continuation_from_wire_v1(response['observation'],ContactContinuationObservationV1)
        authority=response['authority']
        if type(authority)is not dict or authority.get('permit')!=to_wire(write_permit):
            raise AuthorityUnavailable('Existing continuation current Authority changed its original WRITE identity')
        current=current_owner_authority_from_wire_v1({k:v for k,v in authority.items()if k!='permit'})
        guard=current.guard
        if (observed.selector!=selector or observed.installation_id!=policy.installation_id or observed.authority_namespace!=policy.authority_namespace
                or observed.subject!=write_permit.subject or observed.attempt_id!=write_permit.operation_id
                or observed.permit_digest!=authority_digest(write_permit).removeprefix('sha256:')
                or (guard.namespace,guard.installation_id,guard.authority_id,guard.authorization_head,guard.authorization_revision)!=(
                    selector.namespace,policy.installation_id,write_permit.authority_id,observed.owner_head_digest,observed.owner_revision)
                or guard.pending_revoke_operation_id is not None):
            raise AuthorityUnavailable('Existing continuation stored original or current authenticated Owner changed')
        return observed,authority
    def read_current_contact_continuation_observation_for_projection_v1(self,*,namespace,authority_namespace,installation_id,holder,effect_id,selector):
        policy=self.bundle.installation_policy
        if (namespace,authority_namespace,installation_id,holder)!=(policy.namespace,policy.authority_namespace,policy.installation_id,policy.administrator_holder):
            raise AuthorityUnavailable('Contact continuation projection crossed its explicit installation')
        return self.port._submit(self.port._with_session_repair(lambda:self._projection(effect_id,selector)))
    async def _projection(self,effect_id,selector):
        policy=self.bundle.installation_policy
        response=await self._call('read_current_contact_continuation_observation_for_projection_v1',selector,
            {'installation_id':policy.installation_id,'holder':policy.administrator_holder,'effect_id':effect_id})
        value=contact_continuation_from_wire_v1(response['projection'],ContactContinuationObservationProjectionReadV1)
        if (value.namespace!=policy.namespace or value.installation_id!=policy.installation_id
                or value.continuation.selector!=selector or value.observed_permit.effect_id!=effect_id
                or value.observed_permit.holder!=policy.administrator_holder or value.observed_permit.namespace!=policy.authority_namespace):
            raise AuthorityUnavailable('Contact continuation projection actual effect/scope/selector changed')
        return value

def install_contact_continuation_port_v1(port,bundle):return InstalledContactContinuationPortV1(_KEY,port,bundle)
