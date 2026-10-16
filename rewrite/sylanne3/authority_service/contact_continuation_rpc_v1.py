"""Closed continuation RPCs on the actual installed Host channel."""
from .contract import AuthorityUnavailable,identifier
from .contact_continuation_contract_v1 import ContactContinuationSelectorV1,contact_continuation_from_wire_v1,contact_continuation_to_wire_v1
from .contact_continuation_service_v1 import InstalledContactContinuationObserverV1
from .v2_contract import from_wire
METHODS={'capture_contact_continuation_v1','read_existing_contact_continuation_v1','read_current_contact_continuation_observation_for_projection_v1'}

def dispatch_contact_continuation_v1(server,method,credential,profile_id,manifest_digest,command):
    if method not in METHODS:return None
    expected={'capture_contact_continuation_v1':{'namespace','permit','selector'},
        'read_existing_contact_continuation_v1':{'namespace','original_write_permit','selector'},
        'read_current_contact_continuation_observation_for_projection_v1':{'namespace','installation_id','holder','effect_id','selector'}}[method]
    if type(command)is not dict or set(command)!=expected:raise AuthorityUnavailable('Contact continuation closed RPC fields differ')
    namespace=identifier(command['namespace'],'namespace')
    fences=server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    installed=server._installations_v2[(credential.certificate_sha256,profile_id)]
    key=(namespace,installed.installation_id);observer=server._contact_continuation_observers_v1.get(key)
    subject='mtls:sha256:'+credential.certificate_sha256
    if (type(observer)is not InstalledContactContinuationObserverV1 or observer.fences is not fences
            or observer.prospective is not server._contact_prospective_observers_v1.get(key)
            or observer.accounting is not server._contact_effect_accounting_v1.get(key)
            or observer.reader is not server._contact_model_reads_v2.get(namespace)
            or observer.execution is not server._v2_execution.get(namespace)
            or observer.policy is not server._d10_contact_policy_services_v1.get(key)
            or observer.subject!=subject or observer.holder!=installed.administrator_holder
            or observer.bundle.installation_policy.manifest_digest!=installed.manifest_digest):
        raise AuthorityUnavailable('Contact continuation is not this actual installed caller')
    selected=contact_continuation_from_wire_v1(command['selector'],ContactContinuationSelectorV1)
    if method=='capture_contact_continuation_v1':
        value,authority=observer.capture(credential=credential,subject=subject,permit=from_wire(command['permit']),selector=selected)
        return {'observation':contact_continuation_to_wire_v1(value),'authority':authority}
    if method=='read_existing_contact_continuation_v1':
        value,authority=observer.read_existing_contact_continuation_v1(credential=credential,subject=subject,
            original_write_permit=from_wire(command['original_write_permit']),selector=selected)
        return {'observation':contact_continuation_to_wire_v1(value),'authority':authority}
    if (command['installation_id'],command['holder'])!=(installed.installation_id,installed.administrator_holder):
        raise AuthorityUnavailable('Contact continuation projection installation/holder differs')
    value=observer.read_projection(credential=credential,subject=subject,holder=command['holder'],effect_id=command['effect_id'],selector=selected)
    return {'projection':contact_continuation_to_wire_v1(value)}
