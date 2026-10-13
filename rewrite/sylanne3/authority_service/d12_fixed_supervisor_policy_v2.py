"""Read the fixed independently installed maintenance policy and bootstrap."""
from pathlib import Path
import hashlib
from .contract import AuthorityUnavailable
from .d12_package_files_v2 import InstalledPackageSelectionFilesV2,RegisteredPackageV2,_digest
from .d12_installed_supervisor_v1 import (
    D12SystemdSupervisorConfigV1, decode_installed_supervisor_config_v1, supervisor_identity_v1)
from .linux_installation_security_v1 import read_installed_json_v1,read_installed_bytes_v1

FIELDS=frozenset('schema installation_id authority_id profile_id namespace_cohort host_supervisor authority_supervisor bootstrap_root bootstrap_manifest_sha256 bootstrap_shim_sha256 control_directory instance_lock compatibility_plan_ref'.split())


def read_fixed_supervisor_policy_v2(package_files):
    if type(package_files) is not InstalledPackageSelectionFilesV2:raise TypeError('actual package registry required')
    raw=read_installed_json_v1(package_files.control_directory/'supervisor-policy.json')
    expected=package_files.read_maintenance_policy_v2()
    if (type(raw) is not dict or set(raw)!=FIELDS or raw['schema']!='sylanne3.d12.fixed-supervisor-policy.v2'
            or _digest(raw)!=expected['supervisor_policy_digest'] or raw['compatibility_plan_ref']!=expected['compatibility_plan_ref']
            or raw['control_directory']!=str(package_files.control_directory)
            or raw['bootstrap_root']!='/opt/sylanne/bootstrap' or raw['control_directory']!='/etc/sylanne/maintenance'
            or raw['instance_lock']!='/etc/sylanne/authority/authority.lock'
            or type(raw['namespace_cohort']) is not list or len(raw['namespace_cohort'])!=1
            or type(raw['installation_id']) is not str or not raw['installation_id']
            or type(raw['authority_id']) is not str or not raw['authority_id']):
        raise AuthorityUnavailable('fixed external supervisor policy differs')
    host=decode_installed_supervisor_config_v1(raw['host_supervisor'])
    authority=decode_installed_supervisor_config_v1(raw['authority_supervisor'])
    if type(host) is D12SystemdSupervisorConfigV1 and type(authority) is D12SystemdSupervisorConfigV1:
        if (host.unit_name==authority.unit_name or authority.unit_name!='sylanne-authority.service'
                or authority.unit_fragment_path!='/etc/systemd/system/sylanne-authority.service'
                or host.systemctl_path!='/usr/bin/systemctl' or authority.systemctl_path!='/usr/bin/systemctl'):
            raise AuthorityUnavailable('fixed supervised unit identities differ')
    else:
        from .installed_process_supervisor_v1 import InstalledProcessSupervisorSpecV2, verify_process_supervisor_spec_v1
        if (type(host) is not InstalledProcessSupervisorSpecV2 or type(authority) is not InstalledProcessSupervisorSpecV2
                or host.service_role!='host' or authority.service_role!='authority'
                or supervisor_identity_v1(host)==supervisor_identity_v1(authority)
                or any(spec.installation_id!=raw['installation_id'] or spec.authority_id!=raw['authority_id']
                    or spec.profile_id!=raw['profile_id'] or list(spec.namespace_cohort)!=raw['namespace_cohort']
                    for spec in (host,authority))
                or host.control_socket_path!=authority.control_socket_path):
            raise AuthorityUnavailable('fixed process supervision roles/installation differ')
        verify_process_supervisor_spec_v1(host);verify_process_supervisor_spec_v1(authority)
        if any(spec.bootstrap_package_ref!='bootstrap:'+raw['bootstrap_manifest_sha256']
                or spec.selection_control_directory!=raw['control_directory'] for spec in (host,authority)):
            raise AuthorityUnavailable('fixed process bootstrap/control binding differs')
    bootstrap=Path(raw['bootstrap_root'])
    # Release manifests include the engineering source inventory, unlike the
    # small fixed-policy and selection documents read above.
    manifest=read_installed_json_v1(bootstrap/'runtime'/'release-manifest.json', limit=2097152)
    original=RegisteredPackageV2('bootstrap:'+raw['bootstrap_manifest_sha256'],str(bootstrap/'runtime'),
        raw['bootstrap_manifest_sha256'],manifest['package_version'])
    InstalledPackageSelectionFilesV2.verify_registered_package_v2(original)
    from scripts.alpha1.linux_startup_shims_v2 import startup_shim_sources_v2
    sources=startup_shim_sources_v2(profile_id=raw['profile_id'])
    if set(raw['bootstrap_shim_sha256'])!=set(sources):raise AuthorityUnavailable('closed fixed bootstrap surface required')
    for name,source in sources.items():
        actual=read_installed_bytes_v1(bootstrap/name,limit=1048576)
        if (actual!=source.encode() or hashlib.sha256(actual).hexdigest()!=raw['bootstrap_shim_sha256'][name]):
            raise AuthorityUnavailable('fixed bootstrap shim bytes differ')
    selected,cohort,_=package_files.read_selected_configuration_cohort_v2()
    if (selected.installation_id!=raw['installation_id'] or Path(cohort.credential_profile_directory).name!=raw['profile_id']):
        raise AuthorityUnavailable('fixed policy differs from selected installation')
    return raw,host,authority
