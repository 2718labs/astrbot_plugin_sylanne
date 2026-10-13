"""Management dispatch bound to the installed mTLS peer and current Owner."""
from __future__ import annotations

from .contract import AuthorityUnavailable, identifier
from .installation_management_v1 import InstallationManagementServiceV1, ManagementProblem


METHODS = frozenset({"installation_management_v1", "installation_management_startup_v1"})


def install_installation_management_v1(server, service):
    if (type(service) is not InstallationManagementServiceV1
            or service.owner_sessions is not server._v2_owner_sessions
            or server._v2_fences[service.namespace].core is not service.core
            or not any(item.installation_id == service.installation_id
                       for item in server._installations_v2.values())):
        raise AuthorityUnavailable("installed management service binding differs")
    services = getattr(server, "_installation_management_services_v1", None)
    if services is None:
        services = {}
        server._installation_management_services_v1 = services
    key = (service.namespace, service.installation_id)
    if key in services:
        raise AuthorityUnavailable("management service already installed")
    services[key] = service


def dispatch_installation_management_v1(server, method, credential, profile_id,
                                       manifest_digest, command):
    if method not in METHODS:
        return None
    fields = {"namespace"}
    if method == "installation_management_v1":
        fields.update({"owner_token", "operation", "payload"})
    if type(command) is not dict or set(command) != fields:
        raise AuthorityUnavailable("installation management RPC fields differ")
    namespace = identifier(command["namespace"], "namespace")
    fence = server._bound_v2_service(credential, profile_id, manifest_digest, namespace)
    installed = server._installations_v2[(credential.certificate_sha256, profile_id)]
    service = getattr(server, "_installation_management_services_v1", {}).get(
        (namespace, installed.installation_id))
    if (service is None or service.core is not fence.core
            or service.authority_profile != profile_id):
        raise AuthorityUnavailable("installed management service unavailable")
    if method == "installation_management_startup_v1":
        return {"settings": service.startup_settings(credential)}
    try:
        return service.handle(credential, command["owner_token"],
                              command["operation"], command["payload"])
    except ManagementProblem as error:
        return {"http_status": error.status, "json": error.json()}
