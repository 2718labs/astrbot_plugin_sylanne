"""Narrow mTLS dispatch for server-installed, content-free D12 status services."""
from __future__ import annotations

from .contract import AuthorityUnavailable, identifier
from .d12_operation_status_v1 import InstalledD12OperationStatusServiceV1
from .v2_contract import FencePermitV2, from_wire

METHODS = frozenset({"d12_register_operation_v1", "d12_read_operation_v1", "d12_resolve_operation_v1"})


def install_d12_operation_status_service_v1(server, service):
    if (type(service) is not InstalledD12OperationStatusServiceV1
            or server._v2_fences.get(service.namespace) is not service.fences
            or server._v2_owner_tickets is not service.tickets):
        raise AuthorityUnavailable("D12 status service installation differs")
    services = getattr(server, "_d12_operation_status_services_v1", None)
    if services is None:
        services = {}
        server._d12_operation_status_services_v1 = services
    key = (service.namespace, service.installation_id)
    if key in services and services[key] is not service:
        raise AuthorityUnavailable("D12 status service already installed")
    services[key] = service
    server.compose_installed_owner_stop_reply_service_v1(service)


def dispatch_d12_operation_status_v1(server, method, credential, profile_id,
                                    manifest_digest, command):
    if method not in METHODS:
        return None
    expected = {"namespace", "owner_actor_id", "owner_session_token",
                "owner_session_request", "original_ref"}
    expected.add("permit" if method == "d12_register_operation_v1" else "refresh")
    if type(command) is not dict or set(command) != expected:
        raise AuthorityUnavailable("D12 operation status fields differ")
    namespace = identifier(command["namespace"], "namespace")
    fence = server._bound_v2_service(credential, profile_id, manifest_digest, namespace)
    installed = server._installations_v2[(credential.certificate_sha256, profile_id)]
    services = getattr(server, "_d12_operation_status_services_v1", {})
    service = services.get((namespace, installed.installation_id))
    if service is None or service.fences is not fence:
        raise AuthorityUnavailable("installed D12 operation status unavailable")
    original_ref = command["original_ref"]
    if type(original_ref) is not str or len(original_ref) > 128:
        raise AuthorityUnavailable("bounded exact D12 original required")
    kwargs = server._owner_session_kwargs(command, namespace, installed.installation_id)
    kwargs.update(credential=credential, actor=identifier(command["owner_actor_id"], "owner_actor_id"),
                  original_ref=original_ref)
    if method == "d12_register_operation_v1":
        permit = from_wire(command["permit"])
        if type(permit) is not FencePermitV2 or permit.operation != "read":
            raise AuthorityUnavailable("current D12 registration read permit required")
        result = service.register_current_operation_v1(subject="mtls:sha256:" + credential.certificate_sha256,
            permit=permit, **kwargs)
    elif method == "d12_resolve_operation_v1":
        if command["refresh"] is not False:
            raise AuthorityUnavailable("D12 resolve does not refresh an operation")
        result = service.find_registered_current_operation_v1(**kwargs)
    else:
        if type(command["refresh"]) is not bool:
            raise AuthorityUnavailable("D12 refresh must be an exact boolean")
        result = service.read_current_operation_original_v1(refresh=command["refresh"], **kwargs)
    return {"original": None if result is None else result.to_wire()}


__all__ = ("METHODS", "install_d12_operation_status_service_v1", "dispatch_d12_operation_status_v1")
