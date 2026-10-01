"""Current Owner guard plus explicit target-location original, on one fence."""
from __future__ import annotations

from .contract import AuthorityUnavailable, identifier
from .d12_target_owner_admission_v1 import InstalledD12TargetOwnerAdmissionServiceV1
from .v2_contract import FencePermitV2, from_wire, to_wire
from .v2_owner_contract import to_wire as owner_to_wire

METHOD = "d12_current_owner_authority_for_fence_v1"
BACKGROUND_METHOD = "d12_current_background_owner_authority_for_fence_v1"


def install_d12_target_owner_service_v1(server, service):
    if (type(service) is not InstalledD12TargetOwnerAdmissionServiceV1
            or server._v2_fences.get(service.namespace) is not service.fences
            or server._v2_owner_tickets is not service.tickets):
        raise AuthorityUnavailable("target Owner service installation differs")
    services = getattr(server, "_d12_target_owner_services_v1", None)
    if services is None:
        services = {}
        server._d12_target_owner_services_v1 = services
    key = (service.namespace, service.installation_id)
    if key in services and services[key] is not service:
        raise AuthorityUnavailable("target Owner service already installed")
    services[key] = service
    if service.operation_status_service is not None:
        source = service.operation_status_service
        source.install_target_owner_status_reader_v1(service)
        status_services = getattr(server, "_d12_operation_status_services_v1", None)
        if status_services is None:
            raise AuthorityUnavailable("source operation status service must be installed first")
        if key in status_services and status_services[key] is not source:
            raise AuthorityUnavailable("target exact status route already installed")
        status_services[key] = source


def dispatch_d12_target_owner_v1(server, method, credential, profile_id, manifest_digest, command):
    if method not in {METHOD, BACKGROUND_METHOD}:
        return None
    expected = {"namespace", "permit"} if method == BACKGROUND_METHOD else {
        "namespace", "permit", "owner_actor_id", "owner_session_token", "owner_session_request"}
    if type(command) is not dict or set(command) != expected:
        raise AuthorityUnavailable("current Owner authority fields differ")
    namespace = identifier(command["namespace"], "namespace")
    fences = server._bound_v2_service(credential, profile_id, manifest_digest, namespace)
    installed = server._installations_v2[(credential.certificate_sha256, profile_id)]
    permit = from_wire(command["permit"])
    subject = "mtls:sha256:" + credential.certificate_sha256
    if type(permit) is not FencePermitV2 or permit.holder != installed.administrator_holder:
        raise AuthorityUnavailable("current installed Owner holder fence required")
    kwargs = ({} if method == BACKGROUND_METHOD else
              server._owner_session_kwargs(command, namespace, installed.installation_id))
    actor = None if method == BACKGROUND_METHOD else identifier(command["owner_actor_id"], "owner_actor_id")
    service = getattr(server, "_d12_target_owner_services_v1", {}).get((namespace, installed.installation_id))
    if service is None:
        service=getattr(server,"_d12_owner_storage_services_v1",{}).get((namespace,installed.installation_id))
    if service is not None:
        if method == BACKGROUND_METHOD:
            current, observed = service.get_current_background_owner_authority_for_fence_v1(
                credential=credential, subject=subject, permit=permit)
        else:
            current, observed = service.get_current_owner_authority_for_fence_v1(
                credential=credential, subject=subject, permit=permit, actor=actor, **kwargs)
        from .d12_target_owner_admission_v1 import current_owner_authority_to_wire_v1
        return {**current_owner_authority_to_wire_v1(current),"permit":to_wire(observed)}
    # Original installation: its ordinary signed guard checks remain exact.
    # This is configured dispatch, never a retry after target admission denial.
    fences.validate_fence(credential=credential, subject=subject, permit=permit)
    guard = server._v2_owner_tickets.get_current_guard(credential=credential,
        authority_namespace=namespace, installation_id=installed.installation_id,
        subject=subject, permit=permit, owner_actor_id=actor,
        owner_session_token=kwargs.get("session_token"), owner_session_request=kwargs.get("session_request"))
    if guard is None:
        raise AuthorityUnavailable("current Owner guard unavailable")
    return {"guard": owner_to_wire(guard), "target_admission": None, "permit": to_wire(permit)}


__all__ = ("METHOD", "BACKGROUND_METHOD", "install_d12_target_owner_service_v1", "dispatch_d12_target_owner_v1")


def install_d12_owner_storage_service_v1(server,service):
    from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    if (type(service) is not InstalledD12OwnerStorageAdmissionServiceV1 or service.core is not server._core
            or server._v2_fences.get(service.namespace) is not service.fences or service.tickets is not server._v2_owner_tickets):raise AuthorityUnavailable("source Owner storage service installation differs")
    if not hasattr(server,"_d12_owner_storage_services_v1"):server._d12_owner_storage_services_v1={}
    key=(service.namespace,service.installation_id)
    if key in server._d12_owner_storage_services_v1 and server._d12_owner_storage_services_v1[key] is not service:raise AuthorityUnavailable("source Owner storage service already installed")
    server._d12_owner_storage_services_v1[key]=service
    status=getattr(server,"_d12_operation_status_services_v1",{}).get(key)
    if status is not None:status.install_owner_storage_reader_v1(service)
    erasure=getattr(server,"_current_erasure_prepares",{}).get(key)
    if erasure is not None:erasure.install_current_owner_storage_reader_v1(service)
