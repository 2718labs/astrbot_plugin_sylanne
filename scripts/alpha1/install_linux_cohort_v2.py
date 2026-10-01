"""Fresh-only protected package cohort and independent bootstrap installation.

This is called by the explicit root installer after actual four-store genesis.
It starts no process and creates no maintenance acceptance or activation claim.
"""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
from uuid import uuid4


def install_fixed_cohort_v2(*,code,profile_dir,config_dir,control,authority_unit_bytes,writer):
    from sylanne3.authority_service.linux_installation_security_v1 import require_linux_administrator_v1,read_installed_json_v1
    from sylanne3.authority_service.c09_storage_control_v1 import C09StorageControlV1
    from sylanne3.authority_service.d12_package_files_v2 import RegisteredPackageV2,PackageSelectionV2,InstalledPackageSelectionFilesV2,REGISTRY_SCHEMA,SELECTION_SCHEMA,_canonical,_digest
    from sylanne3.authority_service.d12_configuration_cohort_v2 import RegisteredConfigurationCohortV2,ConfigurationFileV2,COHORT_SCHEMA,derive_cohort_identity_commitment_v2
    from sylanne3.authority_service.d12_initial_selection_original_v1 import InitialPackageSelectionOriginalV1,SCHEMA as INITIAL_SCHEMA,SIGNATURE_DOMAIN,read_initial_selection_original_v1
    from sylanne3.authority_service.d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2,_install_schema
    from sylanne3.authority_service.d12_installed_supervisor_v1 import D12SystemdSupervisorConfigV1
    from sylanne3.host.selected_profile_cohort_v2 import BINDING_NAME,BINDING_SCHEMA
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from scripts.alpha1.linux_startup_shims_v2 import startup_shim_sources_v2
    require_linux_administrator_v1()
    if type(control) is not C09StorageControlV1:raise TypeError('actual held initial storage control required')
    control.lease.require_held()
    context=control.read_verified_current_storage_v1();context.require_current('business')
    if context.storage_generation!=0 or context.pointer_version!=0 or context.stage!='READY':
        raise ValueError('fresh initial sealed storage required')
    code,profile_dir,config_dir=Path(code),Path(profile_dir),Path(config_dir)
    root=Path('/opt/sylanne');bootstrap=root/'bootstrap';directory=Path('/etc/sylanne/maintenance')
    if code!=root/'code' or config_dir!=Path('/etc/sylanne/authority') or profile_dir.parent!=Path('/etc/sylanne/client/profiles'):
        raise ValueError('fixed installed filesystem layout required')
    if bootstrap.exists() or directory.exists():raise FileExistsError('fresh bootstrap/cohort refuses overwrite')
    deployment=read_installed_json_v1(config_dir/'deployment.json')
    assets=read_installed_json_v1(config_dir/'assets.json')
    profile=read_installed_json_v1(profile_dir/'profile.json')
    raw_manifest=(code/'release-manifest.json').read_bytes();manifest=json.loads(raw_manifest)
    pin=hashlib.sha256(raw_manifest).hexdigest()
    package=RegisteredPackageV2('release:'+pin,str(code),pin,manifest['package_version'])
    InstalledPackageSelectionFilesV2.verify_registered_package_v2(package)
    if profile['installation_policy']['expected_authority_id']!=control.authority_id or profile['installation_policy']['installation_id']!=control.installation_id:
        raise ValueError('actual sealed storage and installed profile differ')
    namespace=profile['installation_policy']['authority_namespace']
    authority_policy=D12SystemdSupervisorConfigV1('sylanne-authority.service','/usr/bin/systemctl',
        '/etc/systemd/system/sylanne-authority.service',hashlib.sha256(authority_unit_bytes).hexdigest(),'/system.slice/sylanne-authority.service',90)
    host_policy=D12SystemdSupervisorConfigV1(**deployment['host_lifecycle']['supervisor'])
    if host_policy.unit_name==authority_policy.unit_name:raise ValueError('Host and Authority must be separate units')
    plan='sylanne3.d12.compatible-package-no-data-migration.v2'
    shim_sources=startup_shim_sources_v2(profile_id=profile_dir.name)
    fixed_policy=dict(schema='sylanne3.d12.fixed-supervisor-policy.v2',installation_id=control.installation_id,
        authority_id=control.authority_id,profile_id=profile_dir.name,namespace_cohort=[namespace],
        host_supervisor=asdict(host_policy),authority_supervisor=asdict(authority_policy),
        bootstrap_root=str(bootstrap),bootstrap_manifest_sha256=pin,
        bootstrap_shim_sha256={name:hashlib.sha256(source.encode()).hexdigest() for name,source in shim_sources.items()},
        control_directory=str(directory),
        instance_lock=str(control.lease.path),compatibility_plan_ref=plan)
    policy_digest=_digest(fixed_policy)
    directory.mkdir(mode=0o755);cohort_dir=directory/'cohorts';cohort_dir.mkdir(mode=0o755)
    initial_dir=cohort_dir/pin;initial_dir.mkdir(mode=0o755)
    deployment={**deployment,'assets_path':str(initial_dir/'assets.json')}
    values={'deployment':deployment,'assets':assets,'host_profile':profile}
    entries=[]
    for role in ('deployment','assets','host_profile'):
        path=initial_dir/(role+'.json');raw=_canonical(values[role])
        writer(path,raw,mode=0o644 if role=='host_profile' else 0o600)
        entries.append(ConfigurationFileV2(role,str(path),hashlib.sha256(raw).hexdigest()))
    identity=derive_cohort_identity_commitment_v2(deployment=deployment,assets=assets,profile=profile,
        package=package,credential_profile_directory=str(profile_dir))
    body=dict(schema=COHORT_SCHEMA,cohort_ref='cohort:'+pin,installation_id=control.installation_id,
        package=asdict(package),files=[asdict(item) for item in entries],credential_profile_directory=str(profile_dir),
        compatibility_plan_ref=plan,supervisor_policy_digest=policy_digest,identity_commitment=identity)
    cohort=RegisteredConfigurationCohortV2(**{**body,'package':package,'files':tuple(entries),'cohort_digest':_digest(body)})
    operation=str(uuid4())
    selected=dict(schema=SELECTION_SCHEMA,installation_id=control.installation_id,revision=0,package_epoch=0,
        operation_id=operation,release_ref=package.release_ref,manifest_sha256=pin,cohort_ref=cohort.cohort_ref,
        cohort_digest=cohort.cohort_digest,prior_selection_digest=None)
    selection=PackageSelectionV2(**selected,selection_digest=_digest(selected))
    writer(directory/'supervisor-policy.json',_canonical(fixed_policy),mode=0o644)
    writer(directory/'registry.json',_canonical(dict(schema=REGISTRY_SCHEMA,installation_id=control.installation_id,
        cohorts=[asdict(cohort)],maintenance_policy=dict(compatibility_plan_ref=plan,supervisor_policy_digest=policy_digest))),mode=0o644)
    writer(directory/'selection.json',_canonical(asdict(selection)),mode=0o644)
    writer(directory/'selection.lock',b'\0')
    writer(directory/'executor.lock',b'\0')
    key=Ed25519PrivateKey.generate()
    writer(directory/'journal-signing.key',key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()))
    writer(directory/'journal-public.key',key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw),mode=0o644)
    journal_path=directory/'supervisor.sqlite3'
    writer(journal_path,b'')
    with sqlite3.connect(journal_path) as db:_install_schema(db)
    fd=os.open(journal_path,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)
    original=dict(schema=INITIAL_SCHEMA,installation_id=control.installation_id,authority_id=control.authority_id,
        namespace_cohort=(namespace,),selection=selection,identity_commitment=identity,supervisor_policy_digest=policy_digest,
        initial_storage_manifest_digest=context.manifest_digest,initial_storage_generation=0,initial_pointer_version=context.pointer_version,
        issuer_operation_id=operation)
    raw_original={**original,'selection':asdict(selection)}
    original=InitialPackageSelectionOriginalV1(**original,original_digest=_digest(raw_original))
    packet=dict(original=asdict(original),signature=key.sign(SIGNATURE_DOMAIN+_canonical(asdict(original))).hex())
    writer(directory/'initial-selection.json',_canonical(packet),mode=0o644)
    # Fixed launcher runtime is an independent immutable initial snapshot. It
    # never imports a switched candidate to decide which candidate is selected.
    bootstrap.mkdir(mode=0o755)
    shutil.copytree(code,bootstrap/'runtime')
    for path,dirs,names in os.walk(bootstrap/'runtime'):
        os.chmod(path,0o755)
        for name in names:
            copied=Path(path)/name;os.chmod(copied,0o644)
            fd=os.open(copied,os.O_RDONLY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    for name,source in shim_sources.items():
        path=bootstrap/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
        writer(path,source.encode(),mode=0o644)
    # These loader surfaces stay fixed throughout a compatible code switch.
    for name in ('_conf_schema.json','requirements.txt','logo.png','LICENSE'):
        source=code/name
        if source.is_file():writer(bootstrap/'host'/name,source.read_bytes(),mode=0o644)
    writer(profile_dir/BINDING_NAME,_canonical(dict(schema=BINDING_SCHEMA,control_directory=str(directory),
        profile_id=profile_dir.name,installation_id=control.installation_id)),mode=0o644)
    for path in (initial_dir,cohort_dir,directory,bootstrap/'host',bootstrap,root,profile_dir):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    files=InstalledPackageSelectionFilesV2(control_directory=directory)
    actual,actual_cohort,_=files.read_selected_configuration_cohort_v2()
    if actual!=selection or actual_cohort!=cohort:raise ValueError('initial selected cohort reread differs')
    journal=InstalledPackageSupervisorJournalV2(control_directory=directory,supervisor_policy_digest=policy_digest)
    if read_initial_selection_original_v1(package_files=files,supervisor_journal=journal)!=original:
        raise ValueError('initial signed selection reread differs')
    context.require_current('business')
    return dict(bootstrap_root=str(bootstrap),control_directory=str(directory),selection=asdict(selection),
        deployment=str(initial_dir/'deployment.json'),fixed_supervisor_policy_digest=policy_digest)
