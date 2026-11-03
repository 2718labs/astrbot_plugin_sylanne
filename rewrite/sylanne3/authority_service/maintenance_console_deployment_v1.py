"""Protected independent maintenance-console composition; no listener opens here."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import ssl
from urllib.parse import urlsplit

from .contract import AuthorityUnavailable
from .linux_installation_security_v1 import opened_installed_file_v1,read_installed_bytes_v1

CLIENT_SCHEMA="sylanne3.maintenance-console.client.v1"
_ASSETS=frozenset({"maintenance-console.html","assets/console.js","assets/maintenance-console.css"})
_TLS_FIELDS=frozenset({"profile_id","host","port","server_name","expected_authority_id","trust_root",
    "client_certificate","client_private_key","timeout_seconds","max_message_bytes"})


def _object_v1(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise AuthorityUnavailable("duplicate protected console configuration field")
        value[key]=item
    return value


def _client_config_v1(path):
    raw=read_installed_bytes_v1(path,limit=65536)
    value=json.loads(raw,object_pairs_hook=_object_v1,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite console configuration")))
    if (type(value) is not dict or set(value)!={"schema","role_config_path","authority_tls","listener","asset_root","assets"}
            or value["schema"]!=CLIENT_SCHEMA):
        raise AuthorityUnavailable("closed protected maintenance-console client configuration required")
    return value,hashlib.sha256(raw).hexdigest()


def _read_fd_v1(fd,limit):
    if os.fstat(fd).st_size>limit:raise AuthorityUnavailable("console TLS file exceeds installed bound")
    value=os.read(fd,limit+1)
    if len(value)>limit or os.read(fd,1):raise AuthorityUnavailable("console TLS file exceeds installed bound")
    os.lseek(fd,0,os.SEEK_SET)
    return value


def _prepared_authority_profile_v1(raw,binding,gid):
    from ..host.authority_transport_contract import AuthorityTlsProfile
    if type(raw) is not dict or set(raw)!=_TLS_FIELDS:
        raise AuthorityUnavailable("closed independent Authority TLS profile required")
    profile=AuthorityTlsProfile(**raw)
    if profile.profile_id!=binding.console_profile_id or profile.expected_authority_id!=binding.authority_id:
        raise AuthorityUnavailable("console TLS profile differs from its installed role")
    with ExitStack() as stack:
        trust=stack.enter_context(opened_installed_file_v1(profile.trust_root))
        certificate=stack.enter_context(opened_installed_file_v1(profile.client_certificate))
        key=stack.enter_context(opened_installed_file_v1(profile.client_private_key,private=True,allowed_gid=gid))
        ca=_read_fd_v1(trust,1048576).decode("ascii")
        pem=_read_fd_v1(certificate,1048576).decode("ascii")
        _read_fd_v1(key,1048576)
        if hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()!=binding.console_cert_sha256:
            raise AuthorityUnavailable("console certificate differs from its independent role")
        context=ssl.create_default_context(ssl.Purpose.SERVER_AUTH,cadata=ca)
        context.check_hostname=True
        context.verify_mode=ssl.CERT_REQUIRED
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain("/proc/self/fd/"+str(certificate),"/proc/self/fd/"+str(key))
    return AuthorityTlsProfile(**raw,prepared_ssl_context=context)


def _browser_tls_v1(raw,transport,gid,authority_key):
    if transport=="full_http":
        if raw is not None:raise AuthorityUnavailable("full_http console cannot carry an implicit HTTPS listener")
        return None
    if type(raw) is not dict or set(raw)!={"certificate","private_key"}:
        raise AuthorityUnavailable("HTTPS console requires its protected browser certificate/key")
    if Path(raw["private_key"])==authority_key:
        raise AuthorityUnavailable("browser and Authority console keys must be separate")
    with ExitStack() as stack:
        certificate=stack.enter_context(opened_installed_file_v1(raw["certificate"]))
        key=stack.enter_context(opened_installed_file_v1(raw["private_key"],private=True,allowed_gid=gid))
        _read_fd_v1(certificate,1048576)
        _read_fd_v1(key,1048576)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain("/proc/self/fd/"+str(certificate),"/proc/self/fd/"+str(key))
    return context


def build_linux_maintenance_console_v1(*,client_config_path):
    """Construct the fixed HTTP server under its real independent UID/GID."""
    from .maintenance_console_role_v1 import load_protected_maintenance_console_role_config_v1
    from ..maintenance_console_client_v1 import MaintenanceConsoleClientV1
    from ..maintenance_console_issuer_v1 import InstalledMaintenanceConsoleOwnerSessionsV1
    from ..maintenance_console_http_v1 import MaintenanceConsoleHttpServerV1
    config,config_digest=_client_config_v1(client_config_path)
    role=load_protected_maintenance_console_role_config_v1(config["role_config_path"])
    if (Path(client_config_path)!=Path(role.client_config_path) or config_digest!=role.client_config_sha256
            or os.name!="posix" or os.geteuid()!=role.console_uid or os.getegid()!=role.console_gid
            or role.console_uid<=0 or role.console_gid<=0):
        raise AuthorityUnavailable("console requires its exact protected configuration and independent nonroot UID/GID")
    binding=role.binding
    profile=_prepared_authority_profile_v1(config["authority_tls"],binding,role.console_gid)
    listener=config["listener"]
    if type(listener) is not dict or set(listener)!={"bind_host","bind_port","tls"}:
        raise AuthorityUnavailable("closed console listener configuration required")
    origin=urlsplit(binding.origin)
    port=origin.port or (443 if binding.transport_profile=="https" else 80)
    if listener["bind_port"]!=port:
        raise AuthorityUnavailable("console listener port differs from its fixed Origin")
    tls=_browser_tls_v1(listener["tls"],binding.transport_profile,role.console_gid,profile.client_private_key)
    assets=config["assets"];asset_root=Path(config["asset_root"])
    if type(assets) is not dict or set(assets)!=_ASSETS or not asset_root.is_absolute():
        raise AuthorityUnavailable("three fixed packaged console assets required")
    for name,expected in assets.items():
        if (type(expected) is not str or len(expected)!=64
                or any(c not in "0123456789abcdef" for c in expected)
                or hashlib.sha256(read_installed_bytes_v1(asset_root/name,limit=1048576)).hexdigest()!=expected):
            raise AuthorityUnavailable("protected packaged console asset differs: "+name)
    client=MaintenanceConsoleClientV1(profile=profile,binding=binding)
    issuer=InstalledMaintenanceConsoleOwnerSessionsV1(client=client,transport_profile=binding.transport_profile)
    return MaintenanceConsoleHttpServerV1(issuer=issuer,bind_host=listener["bind_host"],
        bind_port=listener["bind_port"],asset_root=asset_root,assets=assets,tls_context=tls)


def install_linux_maintenance_console_v1(daemon,*,role_config_path):
    """Install the independent console role before the Authority listener starts."""
    from .daemon import AuthorityDaemon
    from .d12_installed_supervisor_v1 import InstalledD12SystemdSupervisorV1
    from .maintenance_console_role_v1 import (load_protected_maintenance_console_role_config_v1,
        issue_verified_maintenance_console_role_v1)
    from .maintenance_console_rpc_v1 import install_maintenance_console_binding_v1
    if type(daemon) is not AuthorityDaemon or daemon.is_listening:
        raise AuthorityUnavailable("console installation requires the actual stopped Authority daemon")
    protected=load_protected_maintenance_console_role_config_v1(role_config_path)
    supervisor=InstalledD12SystemdSupervisorV1(config=protected.supervisor_config)
    proof=issue_verified_maintenance_console_role_v1(protected_console_config=protected,
        supervisor=supervisor,server=daemon.server)
    binding=protected.binding
    administrator=daemon.config.local_administrator_credential("d12_lifecycle_install",binding.authority_namespace)
    from .installed_policy_v2 import install_maintenance_console_policy_v1
    install_maintenance_console_policy_v1(daemon.server,binding=binding,role_proof=proof)
    install_maintenance_console_binding_v1(daemon.server,binding=binding,
        administrator_credential=administrator,role_proof=proof)
    return binding


__all__=("CLIENT_SCHEMA","install_linux_maintenance_console_v1","build_linux_maintenance_console_v1")
