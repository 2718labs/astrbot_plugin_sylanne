"""One closed Contact prospective observer on the actual installed mTLS channel."""
from .contract import AuthorityUnavailable, identifier
from .contact_prospective_contract_v1 import (ContactProspectiveSelectorV1,
    contact_prospective_from_wire_v1, contact_prospective_to_wire_v1)
from .contact_prospective_service_v1 import InstalledContactProspectiveObserverV1
from .v2_contract import from_wire

METHOD = 'capture_contact_prospective_v1'


def dispatch_contact_prospective_v1(server, method, credential, profile_id, manifest_digest, command):
    if method != METHOD:
        return None
    if type(command) is not dict or set(command) != {'namespace', 'permit', 'selector'}:
        raise AuthorityUnavailable('Contact prospective RPC closed fields differ')
    namespace = identifier(command['namespace'], 'namespace')
    fences = server._bound_v2_service(credential, profile_id, manifest_digest, namespace)
    installed = server._installations_v2[(credential.certificate_sha256, profile_id)]
    observer = server._contact_prospective_observers_v1.get((namespace, installed.installation_id))
    subject = 'mtls:sha256:' + credential.certificate_sha256
    if (type(observer) is not InstalledContactProspectiveObserverV1 or observer.fences is not fences
            or observer.reader is not server._contact_model_reads_v2.get(namespace)
            or observer.execution is not server._v2_execution.get(namespace)
            or observer.policy is not server._d10_contact_policy_services_v1.get((namespace, installed.installation_id))
            or observer.subject != subject or observer.holder != installed.administrator_holder
            or observer.bundle.installation_policy.manifest_digest != installed.manifest_digest):
        raise AuthorityUnavailable('Contact prospective observer is not this actual installed caller')
    selector = contact_prospective_from_wire_v1(command['selector'], ContactProspectiveSelectorV1)
    observation, authority = observer.capture(credential=credential, subject=subject,
        permit=from_wire(command['permit']), selector=selector)
    return {'observation': contact_prospective_to_wire_v1(observation), 'authority': authority}
