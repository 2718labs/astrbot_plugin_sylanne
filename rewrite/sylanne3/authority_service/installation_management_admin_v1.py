"""Offline OS administrator operations for a pinned installed management scope."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import os

from .contract import AuthorityUnavailable, identifier
from .daemon import AuthorityDaemon
from .installation_management_v1 import InstallationManagementServiceV1
from .v2_owner_contract import OwnerPrincipalV1


@dataclass(frozen=True, slots=True)
class InstallationManagementAdminCommandV1:
    action: str
    namespace: str
    profile_id: str
    installation_id: str
    initial_enabled: bool | None = None
    principal: OwnerPrincipalV1 | None = None
    permissions: tuple[str, ...] = ()
    valid_until: datetime | None = None


def execute_installation_management_admin_v1(daemon, command):
    if type(daemon) is not AuthorityDaemon or type(command) is not InstallationManagementAdminCommandV1:
        raise TypeError("installed daemon and explicit management command required")
    if os.name == "nt":
        from .admin_cli import _require_windows_administrator_token
        _require_windows_administrator_token()
    else:
        from .linux_installation_security_v1 import require_linux_administrator_v1
        require_linux_administrator_v1()
    daemon.require_offline_admin_maintenance()
    for name in ("namespace", "profile_id", "installation_id"):
        identifier(getattr(command, name), name)
    daemon.installed_peer_certificate_sha256(command.profile_id, command.installation_id, command.namespace)
    if command.action not in {"initialize", "grant", "revoke"}:
        raise ValueError("unknown management administration operation")
    action = {"initialize": "installation_management_install",
              "grant": "installation_management_grant", "revoke": "installation_management_revoke"}[command.action]
    credential = daemon.require_local_administrator(action, command.namespace)
    sessions = daemon.server._v2_owner_sessions
    service = InstallationManagementServiceV1(daemon.core, sessions,
        namespace=command.namespace, installation_id=command.installation_id,
        authority_profile=command.profile_id, utc_clock=sessions._utc_clock,
        administrator_authorizer=daemon.config.administrator_authorizer)
    if command.action == "initialize":
        if command.principal is not None or command.permissions or command.valid_until is not None:
            raise ValueError("management initialization fields differ")
        service.initialize(credential, command.initial_enabled)
    elif command.action == "grant":
        if command.initial_enabled is not None:
            raise ValueError("management grant fields differ")
        service.grant_management(credential, command.principal, command.permissions, command.valid_until)
    else:
        if command.initial_enabled is not None or command.permissions or command.valid_until is not None:
            raise ValueError("management revocation fields differ")
        service.revoke_management(credential, command.principal)
    return {"status": command.action, "installation_id": command.installation_id,
            "namespace": command.namespace}
