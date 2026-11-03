"""Private Root-installed maintenance identity, separate from Host content peers."""
from dataclasses import dataclass, asdict
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
from weakref import WeakKeyDictionary

from .contract import AuthorityUnavailable
from .maintenance_console_contract_v1 import MaintenanceConsoleBindingV1
from .linux_installation_security_v1 import read_installed_bytes_v1, require_linux_administrator_v1
from ..runtime_contracts import NamespaceId, canonical_digest

_SCHEMA = 'sylanne3.maintenance-console.installed-role.v1'
_FIELDS = frozenset(('schema','scope','console_uid','console_gid','console_supervisor',
    'host_supervisor_digest','host_unit','host_control_group','client_config_path','client_config_sha256'))
_ISSUER = object()
_CONFIGS = WeakKeyDictionary()
_ROLES = WeakKeyDictionary()


@dataclass(frozen=True, eq=False)
class ProtectedMaintenanceConsoleRoleConfigV1:
    path: Path
    raw_sha256: str
    binding: MaintenanceConsoleBindingV1
    supervisor_config: object
    console_uid: int
    console_gid: int
    host_supervisor_digest: str
    host_unit: str
    host_control_group: str
    client_config_path: Path
    client_config_sha256: str

    def require_current_v1(self):
        if (_CONFIGS.get(self) is not _ISSUER
                or sha256(read_installed_bytes_v1(self.path, limit=32768)).hexdigest() != self.raw_sha256):
            raise AuthorityUnavailable('maintenance role is not the actual current protected Root configuration')
        return self


def load_protected_maintenance_console_role_config_v1(path):
    from .d12_installed_supervisor_v1 import D12SystemdSupervisorConfigV1
    path = Path(path)
    encoded = read_installed_bytes_v1(path, limit=32768)
    raw = json.loads(encoded)
    if type(raw) is not dict or set(raw) != _FIELDS or raw['schema'] != _SCHEMA:
        raise AuthorityUnavailable('closed installed maintenance role configuration required')
    scope = raw['scope']
    scope_fields = set(MaintenanceConsoleBindingV1.__dataclass_fields__) - {'root_role_binding_digest'}
    if type(scope) is not dict or set(scope) != scope_fields or type(scope['namespace']) is not dict:
        raise AuthorityUnavailable('maintenance role has no exact independently installed scope')
    scope = dict(scope, namespace=NamespaceId(**scope['namespace']), root_role_binding_digest=canonical_digest(raw))
    binding = MaintenanceConsoleBindingV1(**scope)
    if (type(raw['console_uid']) is not int or raw['console_uid'] < 1
            or type(raw['console_gid']) is not int or raw['console_gid'] < 1
            or type(raw['console_supervisor']) is not dict
            or set(raw['console_supervisor']) != set(D12SystemdSupervisorConfigV1.__dataclass_fields__)):
        raise AuthorityUnavailable('maintenance console requires its own non-root installed service identity')
    supervisor = D12SystemdSupervisorConfigV1(**raw['console_supervisor'])
    for name in ('host_supervisor_digest','client_config_sha256'):
        value = raw[name]
        if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise AuthorityUnavailable('maintenance configuration SHA256 differs')
    group = PurePosixPath(raw['host_control_group'])
    console_group = PurePosixPath(supervisor.control_group)
    if (not group.is_absolute() or '..' in group.parts or str(group) != raw['host_control_group']
            or group == console_group or group in console_group.parents or console_group in group.parents
            or not Path(raw['client_config_path']).is_absolute()
            or type(raw['host_unit']) is not str or not raw['host_unit']
            or raw['host_unit'] == supervisor.unit_name):
        raise AuthorityUnavailable('maintenance service must have an independent sibling control group and unit')
    result = ProtectedMaintenanceConsoleRoleConfigV1(path, sha256(encoded).hexdigest(), binding, supervisor,
        raw['console_uid'],raw['console_gid'],raw['host_supervisor_digest'],raw['host_unit'],
        raw['host_control_group'],Path(raw['client_config_path']),raw['client_config_sha256'])
    _CONFIGS[result] = _ISSUER
    return result


def _properties_v1(supervisor, unit, names):
    response = supervisor._run(['show',unit,'--no-pager','--property='+','.join(names)])
    if response.returncode != 0:
        raise AuthorityUnavailable('maintenance systemd identity observation failed')
    values = {}
    for line in response.stdout.splitlines():
        key, separator, value = line.partition('=')
        if not separator or key in values:
            raise AuthorityUnavailable('maintenance systemd observation fields differ')
        values[key] = value
    if set(values) != set(names):
        raise AuthorityUnavailable('maintenance systemd observation is incomplete')
    return values


def _host_scope_v1(source, console_observer):
    from .d12_installed_supervisor_v1 import D12SystemdSupervisorConfigV1
    from .installed_process_supervisor_v1 import InstalledProcessSupervisorSpecV2
    cfg = source.lifecycle.supervisor.config
    if type(cfg) is D12SystemdSupervisorConfigV1:
        import pwd
        values = _properties_v1(console_observer,cfg.unit_name,('User','Group'))
        user = values['User']
        uid = 0 if not user else int(user) if user.isdecimal() else pwd.getpwnam(user).pw_uid
        import grp
        group = values['Group']
        gid = pwd.getpwuid(uid).pw_gid if not group else int(group) if group.isdecimal() else grp.getgrnam(group).gr_gid
        return cfg.unit_name, cfg.control_group, uid, gid
    if type(cfg) is InstalledProcessSupervisorSpecV2:
        from .installed_root_lifetime_observer_v3 import (
            read_installed_root_lifetime_spec_v3, _read_root_lifetime_resource_original_v3)
        spec = read_installed_root_lifetime_spec_v3()
        if spec['host_spec']['path'] != cfg.installed_spec_path:
            raise AuthorityUnavailable('maintenance role and actual Host Root specification differ')
        resource = _read_root_lifetime_resource_original_v3(spec)
        group = Path(resource['cgroup_path']).relative_to('/sys/fs/cgroup')
        return resource['unit_name'], '/'+group.as_posix(), cfg.expected_uid, cfg.expected_gid
    raise AuthorityUnavailable('maintenance console has no actual installed Host supervision identity')


class VerifiedMaintenanceConsoleRoleV1:
    def __init__(self, issuer, protected_console_config, supervisor, server, source):
        if issuer is not _ISSUER:
            raise AuthorityUnavailable('private Root console role issuer required')
        self.config,self.supervisor,self.server,self.source = protected_console_config,supervisor,server,source
        _ROLES[self] = _ISSUER

    def require_installed_v1(self, *, binding, server):
        from .d12_installed_supervisor_v1 import InstalledD12SystemdSupervisorV1
        from .source_inspection_migration_v1 import InstalledSourceInspectionMigrationV1
        cfg = self.config.require_current_v1()
        source = getattr(server,'_d12_source_inspection_migration_services_v1',{}).get(
            (binding.authority_namespace,binding.installation_id))
        if (_ROLES.get(self) is not _ISSUER or server is not self.server or binding != cfg.binding
                or type(self.supervisor) is not InstalledD12SystemdSupervisorV1
                or self.supervisor.config != cfg.supervisor_config
                or source is not self.source or type(source) is not InstalledSourceInspectionMigrationV1
                or source.lifecycle.core is not server._core or source.lifecycle.namespace_id != binding.namespace
                or source.lifecycle.control.authority_id != binding.authority_id
                or source.lifecycle.expected_manifest_digest != binding.package_manifest_digest
                or canonical_digest(asdict(source.lifecycle.supervisor.config)) != cfg.host_supervisor_digest
                or any(peer[0] == binding.console_cert_sha256 for peer in server._installations_v2)):
            raise AuthorityUnavailable('maintenance role crossed its actual Root/server/Host/package identity')
        self.supervisor._verify_installation()
        unit,group,uid,gid = _host_scope_v1(source,self.supervisor)
        if (unit,group) != (cfg.host_unit,cfg.host_control_group) or uid == cfg.console_uid or gid == cfg.console_gid:
            raise AuthorityUnavailable('maintenance console shares or replaces the actual Host service identity')
        values = _properties_v1(self.supervisor,cfg.supervisor_config.unit_name,
            ('PartOf','BindsTo','DropInPaths','User','Group'))
        if (cfg.host_unit in values['PartOf'].split() or cfg.host_unit in values['BindsTo'].split()
                or values['DropInPaths']):
            raise AuthorityUnavailable('maintenance console is coupled to Host lifecycle or unpinned drop-ins')
        import pwd
        for key,expected in (('User',cfg.console_uid),('Group',cfg.console_gid)):
            value = values[key]
            if value.isdecimal():actual = int(value)
            elif key == 'User':actual = pwd.getpwnam(value).pw_uid
            else:
                import grp
                actual = grp.getgrnam(value).gr_gid
            if actual != expected:
                raise AuthorityUnavailable('maintenance unit effective user/group differs from its Root role')
        return self

    def require_current_v1(self, *, binding, server):
        self.require_installed_v1(binding=binding,server=server)
        from .c09_process_identity_v1 import read_process_identity_v1
        cfg = self.config
        observed = self.supervisor.read_current_host_state_v1()
        if (observed.active_state != 'active' or observed.main_pid < 1
                or observed.main_pid not in observed.process_ids
                or observed.control_group != cfg.supervisor_config.control_group):
            raise AuthorityUnavailable('maintenance console is not its actual active independent service')
        birth = read_process_identity_v1(observed.main_pid)
        if birth is None:
            raise AuthorityUnavailable('maintenance console actual process birth is absent')
        status = Path('/proc')/str(observed.main_pid)/'status'
        values = {key:value.split() for key,_,value in
            (line.partition(':') for line in status.read_text().splitlines()) if key in ('Uid','Gid','Groups')}
        if values.get('Uid') != [str(cfg.console_uid)]*4 or values.get('Gid') != [str(cfg.console_gid)]*4:
            raise AuthorityUnavailable('maintenance console process credentials differ from its installed role')
        if not set(values.get('Groups',())) <= {str(cfg.console_gid)}:
            raise AuthorityUnavailable('maintenance console has supplementary groups outside its installed identity')
        membership = (Path('/proc')/str(observed.main_pid)/'cgroup').read_text().strip()
        if membership != '0::'+cfg.supervisor_config.control_group or read_process_identity_v1(observed.main_pid) != birth:
            raise AuthorityUnavailable('maintenance console process incarnation or cgroup changed')
        return self


def issue_verified_maintenance_console_role_v1(*,protected_console_config,supervisor,server):
    require_linux_administrator_v1()
    from .mtls_server import AuthorityRpcServer
    from .d12_installed_supervisor_v1 import InstalledD12SystemdSupervisorV1
    if (type(protected_console_config) is not ProtectedMaintenanceConsoleRoleConfigV1
            or type(supervisor) is not InstalledD12SystemdSupervisorV1 or type(server) is not AuthorityRpcServer):
        raise AuthorityUnavailable('actual Root-protected console role, observer and server required')
    cfg = protected_console_config.require_current_v1()
    source = getattr(server,'_d12_source_inspection_migration_services_v1',{}).get(
        (cfg.binding.authority_namespace,cfg.binding.installation_id))
    role = VerifiedMaintenanceConsoleRoleV1(_ISSUER,cfg,supervisor,server,source)
    role.require_installed_v1(binding=cfg.binding,server=server)
    return role
