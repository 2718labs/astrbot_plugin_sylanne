"""Closed registered configuration cohort, separate from runtime compatibility.

A cohort proves that the two startup paths select the same protected config and
package. It never proves that candidate code can read current business history.
No original grant, budget, model destination or historical manifest is rewritten.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import copy
import hashlib
import json
from pathlib import Path

from .contract import AuthorityUnavailable
from .d12_package_files_v2 import RegisteredPackageV2, _digest, _sha
from .linux_installation_security_v1 import read_installed_bytes_v1

COHORT_SCHEMA = 'sylanne3.d12.configuration-cohort.v2'
ROLES = ('deployment', 'assets', 'host_profile')


def _validate_process_deployment_v2(deployment, policy):
    """Bind the static process spec without embedding its containing cohort.

    The selected cohort is bound later by the protected selection and the live
    launch observation.  Keeping that digest in this configuration would make
    the file hash (and therefore the cohort hash) depend on itself.
    """
    from .installed_process_supervisor_v1 import InstalledProcessSupervisorSpecV2

    expected = {
        'schema', 'assets_path', 'package_root', 'trusted_manifest_sha256',
        'profile_id', 'inventory_path', 'inventory_sha256', 'host_uid', 'host_gid',
        'host_supervisor_provider', 'admission_socket', 'target_directory',
        'provider_cache', 'host_observation', 'host_lifecycle',
    }
    raw = deployment.get('host_supervisor_provider')
    lifecycle = deployment.get('host_lifecycle')
    if (set(deployment) != expected or type(raw) is not dict
            or set(raw) != set(InstalledProcessSupervisorSpecV2.__dataclass_fields__)
            or type(lifecycle) is not dict
            or set(lifecycle) != {'supervisor', 'drain_timeout_seconds'}
            or lifecycle['supervisor'] != raw):
        raise AuthorityUnavailable('closed process deployment/spec binding differs')
    spec = InstalledProcessSupervisorSpecV2(**raw)
    if (spec.service_role != 'host'
            or spec.installation_id != policy['installation_id']
            or spec.authority_id != policy['expected_authority_id']
            or spec.profile_id != deployment['profile_id']
            or spec.namespace_cohort != (policy['authority_namespace'],)
            or spec.expected_uid != deployment['host_uid']
            or spec.expected_gid != deployment['host_gid']
            or spec.selection_control_directory != '/etc/sylanne/maintenance'
            or type(lifecycle['drain_timeout_seconds']) is not int
            or not 1 <= lifecycle['drain_timeout_seconds'] <= 3600):
        raise AuthorityUnavailable('process supervision changes installed identity or scope')


@dataclass(frozen=True, slots=True)
class ConfigurationFileV2:
    role: str
    path: str
    sha256: str

    def __post_init__(self):
        if (self.role not in ROLES or not Path(self.path).is_absolute()
                or str(Path(self.path)) != self.path or '..' in Path(self.path).parts or not _sha(self.sha256)):
            raise ValueError('exact registered configuration file required')


@dataclass(frozen=True, slots=True)
class RegisteredConfigurationCohortV2:
    cohort_ref: str
    installation_id: str
    package: RegisteredPackageV2
    files: tuple[ConfigurationFileV2, ...]
    credential_profile_directory: str
    compatibility_plan_ref: str
    supervisor_policy_digest: str
    identity_commitment: str
    cohort_digest: str
    schema: str = COHORT_SCHEMA

    def __post_init__(self):
        if (self.schema != COHORT_SCHEMA or type(self.cohort_ref) is not str or not self.cohort_ref
                or type(self.installation_id) is not str or not self.installation_id
                or type(self.package) is not RegisteredPackageV2 or type(self.files) is not tuple
                or any(type(item) is not ConfigurationFileV2 for item in self.files)
                or tuple(item.role for item in self.files) != ROLES
                or len({item.path for item in self.files}) != len(ROLES)
                or not Path(self.credential_profile_directory).is_absolute()
                or '..' in Path(self.credential_profile_directory).parts
                or type(self.compatibility_plan_ref) is not str or not self.compatibility_plan_ref
                or not _sha(self.supervisor_policy_digest)
                or not _sha(self.identity_commitment) or not _sha(self.cohort_digest)):
            raise ValueError('closed registered configuration cohort required')
        body = asdict(self); body.pop('cohort_digest')
        if self.cohort_digest != _digest(body): raise ValueError('configuration cohort digest differs')


def decode_configuration_cohort_v2(value):
    if type(value) is not dict or set(value) != set(RegisteredConfigurationCohortV2.__dataclass_fields__):
        raise ValueError('fixed configuration cohort fields required')
    fields = dict(value)
    fields['package'] = RegisteredPackageV2(**fields['package'])
    if type(fields['files']) is not list: raise ValueError('configuration file array required')
    fields['files'] = tuple(ConfigurationFileV2(**item) for item in fields['files'])
    return RegisteredConfigurationCohortV2(**fields)


def derive_cohort_identity_commitment_v2(*, deployment, assets, profile, package, credential_profile_directory):
    """Validate real mutual pins; normalize only declared package-selection fields.

    Full remaining config is committed, not a hand-picked subset of authorities.
    This permits neither changing provider/budget/TLS refs nor quietly omitting
    identity-bearing extra fields. Full strict profile parsing remains mandatory.
    """
    if any(type(value) is not dict for value in (deployment, assets, profile)):
        raise AuthorityUnavailable('actual configuration objects required')
    if type(package) is not RegisteredPackageV2:
        raise TypeError('registered package required')
    if (deployment.get('schema') not in {
                'sylanne3.authority.linux-deployment.v1',
                'sylanne3.authority.linux-deployment.v2'}
            or assets.get('schema') != 'sylanne3.authority.installed-assets.v1'
            or profile.get('schema') != 2 or type(profile.get('schema')) is not int):
        raise AuthorityUnavailable('known installed configuration schemas required')
    installations = assets.get('installations_v2')
    bindings = assets.get('namespace_bindings_v2')
    components = assets.get('c04_installations_v3')
    if (type(installations) is not list or len(installations) != 1
            or type(bindings) is not list or len(bindings) != 1
            or type(components) is not list or len(components) != 1):
        raise AuthorityUnavailable('one exact installed cohort and C04 component required')
    installation, binding, c04 = installations[0], bindings[0], components[0]
    policy = profile.get('installation_policy')
    if type(policy) is not dict: raise AuthorityUnavailable('actual Host installation policy required')
    if (any(type(policy.get(name)) is not str or not policy[name] for name in
            ('authority_namespace', 'installation_id', 'administrator_holder', 'expected_authority_id', 'catalogue_hash'))
            or not _sha(installation.get('certificate_sha256'))
            or type(deployment.get('profile_id')) is not str or not deployment['profile_id']):
        raise AuthorityUnavailable('complete installed identity fields required')
    role = policy.get('namespace')
    if (type(role) is not dict or set(role) != {'bot_id', 'persona_id'}
            or any(binding.get(key) != role[key] for key in role)
            or binding.get('authority_namespace') != policy.get('authority_namespace')
            or c04.get('namespace') != policy.get('authority_namespace')
            or binding.get('profile_id') != deployment.get('profile_id')
            or installation.get('profile_id') != deployment.get('profile_id')
            or installation.get('certificate_sha256') != binding.get('certificate_sha256')
            or installation.get('installation_id') != policy.get('installation_id')
            or installation.get('administrator_holder') != policy.get('administrator_holder')
            or profile.get('expected_authority_id') != policy.get('expected_authority_id')
            or Path(credential_profile_directory).name != deployment.get('profile_id')):
        raise AuthorityUnavailable('Authority and Host configuration identities differ')
    if (deployment.get('package_root') != package.package_root
            or deployment.get('trusted_manifest_sha256') != package.manifest_sha256
            or installation.get('manifest_digest') != package.manifest_sha256
            or policy.get('manifest_digest') != package.manifest_sha256
            or c04.get('package_root') != package.package_root
            or c04.get('formal_manifest_sha256') != package.manifest_sha256):
        raise AuthorityUnavailable('configuration package pins do not agree')
    if deployment['schema'] == 'sylanne3.authority.linux-deployment.v2':
        _validate_process_deployment_v2(deployment, policy)
    # These are all and only the fields changed by selecting registered code.
    d, a, p = copy.deepcopy(deployment), copy.deepcopy(assets), copy.deepcopy(profile)
    d['package_root'] = '<selected-package-root>'
    d['trusted_manifest_sha256'] = '<selected-package-manifest>'
    d['assets_path'] = '<selected-assets-file>'
    a['installations_v2'][0]['manifest_digest'] = '<selected-package-manifest>'
    a['c04_installations_v3'][0]['package_root'] = '<selected-package-root>'
    a['c04_installations_v3'][0]['formal_manifest_sha256'] = '<selected-package-manifest>'
    p['installation_policy']['manifest_digest'] = '<selected-package-manifest>'
    return _digest(dict(deployment=d, assets=a, host_profile=p,
                        credential_profile_directory=credential_profile_directory))


def read_verified_configuration_cohort_v2(cohort):
    if type(cohort) is not RegisteredConfigurationCohortV2:
        raise TypeError('registered configuration cohort required')
    values = {}
    for item in cohort.files:
        raw = read_installed_bytes_v1(item.path, limit=1048576)
        if hashlib.sha256(raw).hexdigest() != item.sha256:
            raise AuthorityUnavailable('protected configuration file changed: ' + item.role)
        def unique(pairs):
            result = {}
            for name, value in pairs:
                if name in result: raise ValueError('duplicate configuration field')
                result[name] = value
            return result
        value = json.loads(raw, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite configuration value')))
        values[item.role] = value
    paths = {item.role:item.path for item in cohort.files}
    if values['deployment'].get('assets_path') != paths['assets']:
        raise AuthorityUnavailable('selected deployment does not name selected assets')
    commitment = derive_cohort_identity_commitment_v2(deployment=values['deployment'], assets=values['assets'],
        profile=values['host_profile'], package=cohort.package,
        credential_profile_directory=cohort.credential_profile_directory)
    if (commitment != cohort.identity_commitment
            or values['host_profile']['installation_policy']['installation_id'] != cohort.installation_id):
        raise AuthorityUnavailable('registered cohort identity commitment differs')
    from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
    qualification = InstalledPackageSelectionFilesV2.verify_registered_package_v2(cohort.package)
    if values['host_profile']['installation_policy'].get('catalogue_hash') != qualification.catalogue_hash:
        raise AuthorityUnavailable('selected Host catalogue differs from actual package')
    from ..host.authority_profile import _policy_from_payload, _d13_wire_policy_from_payload, _d13_wire_counter_from_payload
    parsed = _policy_from_payload(values['host_profile'])
    _d13_wire_policy_from_payload(values['host_profile'], parsed)
    _d13_wire_counter_from_payload(values['host_profile'])
    return values


def read_verified_host_profile_cohort_v2(cohort):
    """Partial startup check: never reads private Authority configuration."""
    if type(cohort) is not RegisteredConfigurationCohortV2:
        raise TypeError('registered configuration cohort required')
    item = next(row for row in cohort.files if row.role == 'host_profile')
    raw = read_installed_bytes_v1(item.path, limit=32768)
    if hashlib.sha256(raw).hexdigest() != item.sha256:
        raise AuthorityUnavailable('selected public Host profile bytes changed')
    from .linux_installation_security_v1 import opened_installed_file_v1
    from ..host.authority_profile import _read_profile_json, _policy_from_payload, _d13_wire_policy_from_payload, _d13_wire_counter_from_payload
    with opened_installed_file_v1(item.path) as fd:
        import os
        with os.fdopen(os.dup(fd), 'rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != item.sha256:
                raise AuthorityUnavailable('Host profile changed before strict decode')
        profile = _read_profile_json(fd)
    policy = _policy_from_payload(profile)
    _d13_wire_policy_from_payload(profile, policy); _d13_wire_counter_from_payload(profile)
    from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
    verified = InstalledPackageSelectionFilesV2.verify_registered_package_v2(cohort.package)
    if (policy.installation_id != cohort.installation_id or policy.manifest_digest != cohort.package.manifest_sha256
            or policy.catalogue_hash != verified.catalogue_hash):
        raise AuthorityUnavailable('public Host policy differs from registered selected package')
    return {'host_profile': profile, 'evidence_scope': 'host_public_only'}
