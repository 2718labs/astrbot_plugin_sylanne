"""Paired independent control/status/bootstrap routes, usable while Host is down."""
from dataclasses import asdict

from .contract import AuthorityUnavailable, identifier
from .d12_installation_lifecycle_v1 import InstalledD12InstallationLifecycleV1

CONTROL_METHOD="d12_installation_control_v1"
BOOTSTRAP_METHOD="d12_lifecycle_host_bootstrap_v1"


def install_d12_installation_lifecycle_v1(server, service):
    if (type(service) is not InstalledD12InstallationLifecycleV1
            or service.core is not server._core or server._v2_fences.get(service.namespace) is not service.fences):
        raise AuthorityUnavailable("installed lifecycle Authority differs")
    services=getattr(server,"_d12_installation_lifecycle_services_v1",None)
    if services is None:
        services={};server._d12_installation_lifecycle_services_v1=services
    key=(service.namespace,service.installation_id)
    if key in services and services[key] is not service:
        raise AuthorityUnavailable("installation lifecycle already bound")
    services[key]=service


def dispatch_d12_installation_lifecycle_v1(server,method,credential,profile_id,manifest_digest,command):
    if method not in {CONTROL_METHOD,BOOTSTRAP_METHOD}:
        return None
    if type(command) is not dict or "namespace" not in command:
        raise AuthorityUnavailable("lifecycle command shape differs")
    namespace=identifier(command["namespace"],"namespace")
    fence=server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    installed=server._installations_v2[(credential.certificate_sha256,profile_id)]
    service=getattr(server,"_d12_installation_lifecycle_services_v1",{}).get((namespace,installed.installation_id))
    if service is None or service.fences is not fence:
        raise AuthorityUnavailable("whole-Host lifecycle service unavailable")
    if method==BOOTSTRAP_METHOD:
        expected={"namespace","operation_id","expected_epoch","process_id","invocation_id","catalogue_hash","ready_domains"}
        if set(command)!=expected or type(command["ready_domains"]) is not list:
            raise AuthorityUnavailable("Host bootstrap fields differ")
        fields={key:value for key,value in command.items() if key!="namespace"}
        fields["ready_domains"]=tuple(fields["ready_domains"])
        ref=service.register_current_host_bootstrap_v1(credential=credential,
            peer_certificate_sha256=credential.certificate_sha256,peer_profile_id=profile_id,**fields)
        return service.read_current_host_bootstrap_progress_v1(ref)
    common={"namespace","action","owner_actor_id","owner_session_token","owner_session_request"}
    extra={"inspect":set(),"submit":{"original_ref"},"status":{"operation_id"},"continue":{"operation_id"},
           "resume":{"pause_operation_id","operation_id","expected_lifecycle_epoch"}}
    action=command.get("action")
    if action not in extra or set(command)!=common|extra[action]:
        raise AuthorityUnavailable("whole-Host lifecycle action fields differ")
    kwargs=server._owner_session_kwargs(command,namespace,installed.installation_id)
    kwargs.update(credential=credential,actor=identifier(command["owner_actor_id"],"owner_actor_id"))
    if action=="inspect":
        return {"lifecycle_head":asdict(service.inspect_current_lifecycle_v1(**kwargs))}
    if action=="submit":
        original=service.submit_current_control_v1(original_ref=command["original_ref"],**kwargs)
    elif action=="resume":
        original=service.resume_paused_installation_v1(**{key:command[key] for key in extra[action]},**kwargs)
    else:
        original=service.read_current_control_v1(operation_id=command["operation_id"],continue_original=action=="continue",**kwargs)
    return {"original":original.to_wire()}


__all__=("CONTROL_METHOD","BOOTSTRAP_METHOD","install_d12_installation_lifecycle_v1","dispatch_d12_installation_lifecycle_v1")
