"""Actual installed Host transport for Contact prospective observations."""
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.contact_prospective_contract_v1 import (ContactProspectiveSelectorV1,
    ContactProspectiveObservationV1, contact_prospective_to_wire_v1, contact_prospective_from_wire_v1)
from ..authority_service.v2_contract import FencePermitV2, to_wire as authority_wire, canonical_digest as authority_digest
from ..runtime_contracts import canonical_digest
from .v2_fence_port import V2FencePort
from .authority_profile import AdminInstallationBundle

_KEY = object()


class InstalledContactProspectivePortV1:
    def __init__(self, key, port, bundle):
        if (key is not _KEY or type(port) is not V2FencePort or type(bundle) is not AdminInstallationBundle
                or port.installation_grant.installation_id != bundle.installation_policy.installation_id
                or port.installation_grant.manifest_digest != bundle.installation_policy.manifest_digest):
            raise AuthorityUnavailable('Contact prospective transport needs its actual installed port')
        self.port, self.bundle = port, bundle

    def capture(self, permit, selector):
        if type(permit) is not FencePermitV2 or type(selector) is not ContactProspectiveSelectorV1:
            raise TypeError('Contact prospective requires its actual permit and typed selector')
        return self.port._submit(self.port._with_session_repair(lambda: self._capture(permit, selector)))

    async def _capture(self, permit, selector):
        from ..authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
        policy = self.bundle.installation_policy
        if selector.namespace != policy.namespace or permit.namespace != policy.authority_namespace:
            raise AuthorityUnavailable('Contact prospective transport crossed its installed namespace')
        await self.port._mapped(policy.namespace, policy.authority_namespace)
        handshake, grant = self.port._identity()
        if (grant.installation_id, grant.administrator_holder, grant.manifest_digest) != (
                policy.installation_id, policy.administrator_holder, policy.manifest_digest):
            raise AuthorityUnavailable('Contact prospective installation changed')
        response = await self.port._transport._content_rpc(self.port._request, handshake,
            'capture_contact_prospective_v1', {'namespace': policy.authority_namespace,
                'permit': authority_wire(permit), 'selector': contact_prospective_to_wire_v1(selector)},
            protocol=AUTHORITY_V2_PROTOCOL)
        if (type(response) is not dict or set(response) != {'observation', 'authority', 'channel_binding_sha256'}
                or response['channel_binding_sha256'] != handshake.channel_binding_sha256):
            raise AuthorityUnavailable('Contact prospective response crossed its authenticated channel')
        observation = contact_prospective_from_wire_v1(response['observation'], ContactProspectiveObservationV1)
        authority = response['authority']
        if (observation.selector != selector or observation.installation_id != policy.installation_id
                or observation.authority_namespace != policy.authority_namespace
                or observation.attempt_id != permit.operation_id
                or observation.permit_digest != authority_digest(permit).removeprefix('sha256:')
                or type(authority) is not dict or authority.get('permit') != authority_wire(permit)
                or observation.owner_authority_digest != canonical_digest(authority)):
            raise AuthorityUnavailable('Contact prospective response changed its actual call or Owner observation')
        return observation, authority


def install_contact_prospective_port_v1(port, bundle):
    return InstalledContactProspectivePortV1(_KEY, port, bundle)
