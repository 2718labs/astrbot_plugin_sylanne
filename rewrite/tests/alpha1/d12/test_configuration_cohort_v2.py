"""Pure configuration identity/selection validation, not privileged startup."""
import copy
from dataclasses import asdict
import pytest
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.d12_package_files_v2 import RegisteredPackageV2, _digest
from sylanne3.authority_service.d12_configuration_cohort_v2 import (
    COHORT_SCHEMA, ConfigurationFileV2, RegisteredConfigurationCohortV2,
    decode_configuration_cohort_v2, derive_cohort_identity_commitment_v2,
)


def configuration():
    package=RegisteredPackageV2('old','/opt/sylanne/releases/old','a'*64,'3.0.0-alpha1')
    deployment=dict(schema='sylanne3.authority.linux-deployment.v1',profile_id='profile',
        package_root=package.package_root,trusted_manifest_sha256=package.manifest_sha256,assets_path='/etc/sylanne/cohorts/old/assets.json')
    policy=dict(namespace={'bot_id':'bot','persona_id':'role'},authority_namespace='ns:test',
        installation_id='installation:test',administrator_holder='holder',expected_authority_id='authority:test',
        catalogue_hash='c'*64,manifest_digest=package.manifest_sha256,
        root_lease={'limits':{'cpu_ms':100}},root_grant={'capabilities':['read']})
    profile=dict(schema=2,expected_authority_id='authority:test',installation_policy=policy,
        model_workflows={'reply':{'provider_id':'provider-a'}})
    assets=dict(schema='sylanne3.authority.installed-assets.v1',
        installations_v2=[dict(profile_id='profile',certificate_sha256='f'*64,installation_id='installation:test',
            administrator_holder='holder',manifest_digest=package.manifest_sha256)],
        namespace_bindings_v2=[dict(bot_id='bot',persona_id='role',authority_namespace='ns:test',profile_id='profile',certificate_sha256='f'*64)],
        c04_installations_v3=[dict(namespace='ns:test',package_root=package.package_root,formal_manifest_sha256=package.manifest_sha256)],
        tls={'private_key':'/etc/sylanne/credentials/authority.key'})
    return dict(deployment=deployment,assets=assets,profile=profile,package=package,credential_profile_directory='/etc/sylanne/credentials/profile')


def test_only_declared_package_fields_normalize():
    old=configuration(); before=derive_cohort_identity_commitment_v2(**old)
    new=copy.deepcopy(old); new['package']=RegisteredPackageV2('new','/opt/sylanne/releases/new','b'*64,'3.0.0-alpha2')
    new['deployment'].update(package_root=new['package'].package_root,trusted_manifest_sha256='b'*64,assets_path='/etc/sylanne/cohorts/new/assets.json')
    new['assets']['installations_v2'][0]['manifest_digest']='b'*64
    new['assets']['c04_installations_v3'][0].update(package_root=new['package'].package_root,formal_manifest_sha256='b'*64)
    new['profile']['installation_policy']['manifest_digest']='b'*64
    assert derive_cohort_identity_commitment_v2(**new)==before
    for mutation in ('budget','provider','tls'):
        changed=copy.deepcopy(new)
        if mutation=='budget': changed['profile']['installation_policy']['root_lease']['limits']['cpu_ms']=200
        elif mutation=='provider': changed['profile']['model_workflows']['reply']['provider_id']='provider-b'
        else: changed['assets']['tls']['private_key']='/etc/other.key'
        assert derive_cohort_identity_commitment_v2(**changed)!=before
    new['assets']['installations_v2'][0]['manifest_digest']='a'*64
    with pytest.raises(AuthorityUnavailable,match='package pins'):
        derive_cohort_identity_commitment_v2(**new)


def test_cohort_digest_covers_exact_files_and_credential_root():
    values=configuration()
    body=dict(schema=COHORT_SCHEMA,cohort_ref='cohort:old',installation_id='installation:test',package=asdict(values['package']),
        files=[dict(role=role,path='/etc/sylanne/cohorts/old/'+role+'.json',sha256='d'*64)
            for role in ('deployment','assets','host_profile')],
        credential_profile_directory=values['credential_profile_directory'],
        compatibility_plan_ref='plan:compatible-v2', supervisor_policy_digest='e'*64,
        identity_commitment=derive_cohort_identity_commitment_v2(**values))
    raw={**body,'cohort_digest':_digest(body)}
    cohort=decode_configuration_cohort_v2(raw)
    assert type(cohort) is RegisteredConfigurationCohortV2
    assert tuple(item.role for item in cohort.files)==('deployment','assets','host_profile')
    with pytest.raises(ValueError): decode_configuration_cohort_v2({**raw,'credential_profile_directory':'/etc/other/profile'})
    changed=copy.deepcopy(raw); changed['files'][0]['sha256']='e'*64
    with pytest.raises(ValueError): decode_configuration_cohort_v2(changed)
    with pytest.raises(ValueError): ConfigurationFileV2('arbitrary','/etc/a','a'*64)
