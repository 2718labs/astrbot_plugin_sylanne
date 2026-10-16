"""Dedicated fixed named Joint current observation on the original paired permit."""
from .contract import AuthorityUnavailable, identifier
from .current_named_joint_binding_v1 import (InstalledCurrentNamedJointBindingV1,
    named_joint_selector_from_wire_v1, named_joint_current_to_wire_v1)
from .v2_contract import FencePermitV2, from_wire, to_wire

METHOD = 'named_joint_binding_current_v1'


def dispatch_current_named_joint_binding_v1(server, method, credential, profile_id, manifest_digest, command):
    if method not in {METHOD,'named_joint_source_note_current_v1'}:
        return None
    if type(command) is not dict or set(command) != {'namespace', 'permit', 'request'}:
        raise AuthorityUnavailable('Named Joint RPC fields differ')
    namespace = identifier(command['namespace'], 'namespace')
    fences = server._bound_v2_service(credential, profile_id, manifest_digest, namespace)
    installation = server._installations_v2[(credential.certificate_sha256, profile_id)]
    service = server._current_named_joint_binding_v1.get((namespace, installation.installation_id))
    permit = from_wire(command['permit'])
    if (type(service) is not InstalledCurrentNamedJointBindingV1 or service.self_identity._fences is not fences
            or type(permit) is not FencePermitV2 or permit.holder != installation.administrator_holder):
        raise AuthorityUnavailable('Named Joint service differs from its actual installed paired fence')
    if method=='named_joint_source_note_current_v1':
        from .current_named_joint_source_note_v1 import note_selector_from_wire_v1,note_current_to_wire_v1
        request=note_selector_from_wire_v1(command['request']);encode=note_current_to_wire_v1
    else:
        request = named_joint_selector_from_wire_v1(command['request']);encode=named_joint_current_to_wire_v1
    evidence, observed = service.current(credential=credential,
        subject='mtls:sha256:' + credential.certificate_sha256, permit=permit, request=request)
    if observed != permit:
        raise AuthorityUnavailable('Named Joint observation changed its original borrowed permit')
    return {'evidence': encode(evidence), 'permit': to_wire(observed)}
