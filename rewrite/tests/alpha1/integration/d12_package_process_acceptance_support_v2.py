"""Isolated OS boundary for real C11 Core/Graph/mTLS/native/process acceptance.

Only root-owned fixed filesystem paths and systemd are replaced by explicitly
registered test paths and real subprocess groups. All product Authority stores,
Owner/session proofs, supervisor signatures, package bytes, native loads,
SQLite backups, selection CAS, compatibility decoders and admission are real.
"""
from __future__ import annotations
import asyncio
from contextlib import ExitStack
from dataclasses import asdict
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import sys
import time
from uuid import uuid4

from sylanne3.runtime_contracts import canonical_serialize,canonical_digest,NamespaceId
from sylanne3.authority_service.contract import AuthorityUnavailable

REPO=Path(__file__).resolve().parents[4]


def wire(value):
    from dataclasses import is_dataclass,fields
    from collections.abc import Mapping
    if is_dataclass(value):return {field.name:wire(getattr(value,field.name)) for field in fields(value)}
    if isinstance(value,Mapping):return {key:wire(item) for key,item in value.items()}
    if isinstance(value,(tuple,list)):return [wire(item) for item in value]
    return value
def save(path,value):
    path=Path(path);temporary=path.with_name(path.name+'.new')
    temporary.write_text(canonical_serialize(wire(value)));os.chmod(temporary,0o600);temporary.replace(path)
def read(path):return json.loads(Path(path).read_text())


def install_os_boundary(root):
    """Actual descriptor types/bytes remain checked; only administrator UID/root changes."""
    import sylanne3.authority_service.linux_installation_security_v1 as security
    old_check=security._check;old_admin=security.require_linux_administrator_v1
    root=Path(root).resolve();permitted=(root,*root.parents)
    package_roots=(Path(read(root/'settings.json')['source_root']),Path(read(root/'settings.json')['candidate_root']))
    def check(fd,*,directory=False,private=False,allowed_gid=None):
        info=os.fstat(fd);path=Path(os.readlink('/proc/self/fd/'+str(fd)).removesuffix(' (deleted)'))
        if not (path in permitted or path.is_relative_to(root) or any(path.is_relative_to(package_root) for package_root in package_roots)):
            return old_check(fd,directory=directory,private=private,allowed_gid=allowed_gid)
        if info.st_uid not in {0,os.getuid()} or stat.S_ISLNK(info.st_mode) or (directory and not stat.S_ISDIR(info.st_mode)) or (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1)):
            raise AuthorityUnavailable('isolated installation descriptor identity differs')
        if not directory and info.st_mode&0o022:raise AuthorityUnavailable('isolated installation file is writable outside owner')
        if private and not directory and info.st_mode&0o077:raise AuthorityUnavailable('isolated private file permissions differ')
    def administrator():
        if os.geteuid()!=os.getuid():raise AuthorityUnavailable('isolated administrator UID changed')
    security._check=check;security.require_linux_administrator_v1=administrator
    from sylanne3.authority_service.d12_package_files_v2 import InstalledPackageSelectionFilesV2,RegisteredPackageV2
    from sylanne3.host.installed_package import verify_installed_backend_runtime_v1
    def registered(package):
        if type(package) is not RegisteredPackageV2 or Path(package.package_root) not in package_roots:
            raise AuthorityUnavailable('fixed isolated registered package required')
        for directory,dirs,files in os.walk(package.package_root,followlinks=False):
            for name in dirs+files:
                path=Path(directory)/name;info=path.lstat()
                if stat.S_ISLNK(info.st_mode) or info.st_uid not in {0,os.getuid()} or info.st_mode&0o022:
                    raise AuthorityUnavailable('isolated package descriptor is unprotected')
                flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC
                if stat.S_ISDIR(info.st_mode):flags|=os.O_DIRECTORY
                fd=os.open(path,flags)
                try:check(fd,directory=stat.S_ISDIR(info.st_mode))
                finally:os.close(fd)
        result=verify_installed_backend_runtime_v1(Path(package.package_root),package.manifest_sha256)
        if not result.verified or result.package_version!=package.package_version:
            raise AuthorityUnavailable('actual isolated package qualification failed')
        return result
    InstalledPackageSelectionFilesV2.verify_registered_package_v2=staticmethod(registered)
    for module in tuple(sys.modules.values()):
        if getattr(module,'__name__','').startswith('sylanne3.'):
            if getattr(module,'require_linux_administrator_v1',None) is old_admin:module.require_linux_administrator_v1=administrator
    import sylanne3.authority_service.d12_fixed_supervisor_policy_v2 as fixed
    old_fixed=fixed.read_fixed_supervisor_policy_v2
    def fixed_policy(files):
        from sylanne3.authority_service.d12_package_files_v2 import _digest
        from sylanne3.authority_service.d12_installed_supervisor_v1 import D12SystemdSupervisorConfigV1
        from scripts.alpha1.linux_startup_shims_v2 import startup_shim_sources_v2
        value=read(files.control_directory/'supervisor-policy.json')
        if set(value)!=fixed.FIELDS or _digest(value)!=files.read_maintenance_policy_v2()['supervisor_policy_digest']:
            raise AuthorityUnavailable('actual isolated fixed policy commitment differs')
        if value['control_directory']!=str(root/'control') or Path(value['bootstrap_root'])/'runtime'!=package_roots[0]:
            raise AuthorityUnavailable('isolated fixed bootstrap path differs')
        for name,source in startup_shim_sources_v2(profile_id='reply').items():
            actual=(Path(value['bootstrap_root'])/name).read_bytes()
            if actual!=source.encode() or hashlib.sha256(actual).hexdigest()!=value['bootstrap_shim_sha256'][name]:
                raise AuthorityUnavailable('actual fixed startup shim changed')
        return value,D12SystemdSupervisorConfigV1(**value['host_supervisor']),D12SystemdSupervisorConfigV1(**value['authority_supervisor'])
    fixed.read_fixed_supervisor_policy_v2=fixed_policy
    for module in tuple(sys.modules.values()):
        if getattr(module,'__name__','').startswith('sylanne3.') and getattr(module,'read_fixed_supervisor_policy_v2',None) is old_fixed:
            module.read_fixed_supervisor_policy_v2=fixed_policy
    from sylanne3.authority_service.d12_installed_supervisor_v1 import InstalledD12SystemdSupervisorV1
    InstalledD12SystemdSupervisorV1.read_current_host_state_v1=lambda self:observe_process_group(root,self.config)
    InstalledD12SystemdSupervisorV1.stop_original_host_v1=lambda self,**kw:stop_process_group(root,self.config,**kw)
    InstalledD12SystemdSupervisorV1.start_stopped_host_v1=lambda self,**kw:start_process_group(root,self.config,**kw)
    from sylanne3.authority_service.d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2
    InstalledPackageSupervisorJournalV2.require_installed_executor_ready_v2=lambda self,**kw:qualify_isolated_executor(root,self,**kw)
    from sylanne3.authority_service.d12_package_supervisor_v2 import InstalledD12PackageSupervisorV2
    advance=InstalledD12PackageSupervisorV2._advance
    async def diagnosed_advance(self,*args,**kwargs):
        try:return await advance(self,*args,**kwargs)
        except Exception:
            import traceback
            traceback.print_exc();raise
    InstalledD12PackageSupervisorV2._advance=diagnosed_advance


def _role(config):return 'host' if config.unit_name=='fixture-host.service' else 'authority'

def _processes(pid):
    found=[]
    for item in Path('/proc').iterdir():
        if not item.name.isdigit():continue
        try:
            tail=(item/'stat').read_text().rsplit(')',1)[1].split()
            if int(tail[2])==pid and tail[0] not in {'Z','X'}:found.append(int(item.name))
        except (FileNotFoundError,ProcessLookupError,PermissionError):continue
    return tuple(sorted(found))

def observe_process_group(root,config):
    from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1
    from sylanne3.authority_service.d12_installed_supervisor_v1 import D12SupervisorObservationV1
    from sylanne3.runtime.lifecycle_operations_v1 import digest
    entry=read(root/'processes.json')[_role(config)];actual=read_process_identity_v1(entry['pid']) if entry['pid'] else None
    live=actual is not None and actual==entry['identity'];pids=_processes(entry['pid']) if entry['pid'] else ()
    body=dict(unit_name=config.unit_name,load_state='loaded',active_state='active' if live else 'inactive',sub_state='running' if live else 'dead',
        main_pid=entry['pid'] if live else 0,invocation_id=entry['invocation_id'],control_group=config.control_group,process_ids=pids,
        unit_fragment_sha256=config.unit_fragment_sha256)
    return D12SupervisorObservationV1(**body,observation_digest=digest(body))

def stop_process_group(root,config,*,expected_invocation_id):
    before=observe_process_group(root,config)
    if before.stopped_and_drained:return before
    if before.invocation_id!=expected_invocation_id:raise AuthorityUnavailable('isolated original invocation changed')
    os.killpg(before.main_pid,signal.SIGTERM)
    deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        now=observe_process_group(root,config)
        if now.stopped_and_drained:return now
        time.sleep(.03)
    raise AuthorityUnavailable('actual subprocess group did not retire')

def start_process_group(root,config,*,expected_prior_invocation_id):
    before=observe_process_group(root,config)
    if not before.stopped_and_drained or before.invocation_id not in {'',expected_prior_invocation_id}:raise AuthorityUnavailable('same original stopped invocation required')
    role=_role(config);selection=read(root/'control'/'selection.json')
    registry=read(root/'control'/'registry.json');cohort=next(c for c in registry['cohorts'] if c['cohort_ref']==selection['cohort_ref'])
    package=Path(cohort['package']['package_root']);settings=read(root/'settings.json')
    mode='fail_authority' if role=='authority' and settings.get('fail_candidate_authority') and selection['cohort_ref']=='cohort:candidate' else role
    environment=dict(os.environ,PYTHONPATH=str(package/'rewrite')+os.pathsep+str(package)+os.pathsep+str(REPO/'rewrite')+os.pathsep+str(REPO),SYLANNE_D04_INSTALLED_ROOT=str(package))
    log=(root/(role+'-'+str(selection['package_epoch'])+'.log')).open('a')
    process=subprocess.Popen([sys.executable,__file__,mode,str(root)],env=environment,stdout=log,stderr=log,start_new_session=True)
    log.close();record_process(root,role,process.pid)
    time.sleep(.1)
    after=observe_process_group(root,config)
    if not after.stopped_and_drained:return after
    raise AuthorityUnavailable('actual candidate process exited before readiness')

def record_process(root,role,pid):
    from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1
    values=read(root/'processes.json');identity=None
    until=time.monotonic()+3
    while identity is None and time.monotonic()<until:
        identity=read_process_identity_v1(pid);time.sleep(.005)
    if identity is None:raise AuthorityUnavailable('actual test process failed before registration')
    values[role]={'pid':pid,'identity':identity,'invocation_id':uuid4().hex};save(root/'processes.json',values)


def supervisor(root,role):
    from sylanne3.authority_service.d12_installed_supervisor_v1 import InstalledD12SystemdSupervisorV1,D12SystemdSupervisorConfigV1
    path=root/(role+'.service')
    if not path.exists():path.write_text('[Service]\n# explicitly isolated subprocess '+role+'\n')
    result=object.__new__(InstalledD12SystemdSupervisorV1)
    result.config=D12SystemdSupervisorConfigV1('fixture-'+role+'.service',sys.executable,str(path),hashlib.sha256(path.read_bytes()).hexdigest(),'/fixture/'+role,10)
    return result


def qualify_isolated_executor(root,journal,*,operation_id,candidate_cohort_ref,expected_selection_digest):
    from sylanne3.authority_service.d12_package_files_v2 import InstalledPackageSelectionFilesV2
    from sylanne3.authority_service.d12_configuration_cohort_v2 import read_verified_configuration_cohort_v2
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    files=InstalledPackageSelectionFilesV2(control_directory=root/'control');selected,_,_=files.read_selected_configuration_cohort_v2()
    _,candidate=files.read_registered_cohort_v2(candidate_cohort_ref);read_verified_configuration_cohort_v2(candidate)
    key=Ed25519PrivateKey.from_private_bytes((root/'control'/'journal-signing.key').read_bytes())
    if selected.selection_digest!=expected_selection_digest or key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)!=journal.public_key:
        raise AuthorityUnavailable('isolated actual executor key/selection differs')
    for role in ('host','authority'):
        service=supervisor(root,role)
        if hashlib.sha256(Path(service.config.unit_fragment_path).read_bytes()).hexdigest()!=service.config.unit_fragment_sha256:raise AuthorityUnavailable('actual isolated unit configuration differs')
    if not callable(getattr(__import__('sylanne3.authority_service.d12_package_supervisor_v2',fromlist=['InstalledD12PackageSupervisorV2']).InstalledD12PackageSupervisorV2,'run')):raise AuthorityUnavailable('actual fixed executor code absent')


def build_registry(root,case,support,candidate):
    from sylanne3.authority_service.d12_package_files_v2 import RegisteredPackageV2,PackageSelectionV2,_digest
    from sylanne3.authority_service.d12_configuration_cohort_v2 import ConfigurationFileV2,RegisteredConfigurationCohortV2,derive_cohort_identity_commitment_v2
    from sylanne3.authority_service.d12_package_supervisor_journal_v2 import _install_schema
    from sylanne3.authority_service.linux_bootstrap_v1 import build_initial_inventory_v1
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    root.mkdir(exist_ok=True);control_dir=root/'control';control_dir.mkdir(exist_ok=True)
    for lock_name in ('selection.lock','executor.lock'):
        (control_dir/lock_name).touch(mode=0o600,exist_ok=True)
    source=Path(case['package_root']);policy=case['policy'];control=support.storage_control
    context=control.read_verified_current_storage_v1();members={m['role']:Path(m['resolved_path']) for m in context.manifest['members']}
    managed=members['graph'].parent/'numeric-managed-artifacts'
    inventory=build_initial_inventory_v1(authority_id=control.authority_id,installation_id=control.installation_id,
        namespace=case['authority_namespace'],files=members,directories={name:managed/name for name in ('controlled_backup','export','rebuild_temp','cache')})
    assert inventory.manifest_digest==context.manifest['inventory_manifest_digest'];save(root/'inventory.json',inventory)
    private=os.urandom(32);(control_dir/'journal-signing.key').write_bytes(private);os.chmod(control_dir/'journal-signing.key',0o600)
    (control_dir/'journal-public.key').write_bytes(Ed25519PrivateKey.from_private_bytes(private).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
    db=sqlite3.connect(control_dir/'supervisor.sqlite3');_install_schema(db);db.close();os.chmod(control_dir/'supervisor.sqlite3',0o600)
    profile_root=root/'profiles'/'reply';profile_root.mkdir(parents=True,exist_ok=True)
    cohorts=[]
    from scripts.alpha1.linux_startup_shims_v2 import startup_shim_sources_v2
    bootstrap=source.parent
    assert source.name=='runtime'
    shims=startup_shim_sources_v2(profile_id='reply');shim_hashes={}
    for name,body in shims.items():
        path=bootstrap/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(body)
        shim_hashes[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    fixed_policy=dict(schema='sylanne3.d12.fixed-supervisor-policy.v2',installation_id=control.installation_id,
        authority_id=control.authority_id,profile_id='reply',namespace_cohort=[case['authority_namespace']],
        host_supervisor=wire(supervisor(root,'host').config),authority_supervisor=wire(supervisor(root,'authority').config),
        bootstrap_root=str(bootstrap),bootstrap_manifest_sha256=case['manifest_digest'],bootstrap_shim_sha256=shim_hashes,
        control_directory=str(control_dir),instance_lock=str(support.lease.path),compatibility_plan_ref='plan:compatible-v2')
    policy_digest=_digest(fixed_policy);save(control_dir/'supervisor-policy.json',fixed_policy)
    storage=dict(control_path=str(control.path),key_path=str(control.key_path),installation_id=control.installation_id,
        authority_id=control.authority_id,control_store_id=control.control_store_id,key_id=control.key_id,resource_roots=[str(p) for p in control._roots])
    for ref,path in (('source',source),('candidate',Path(candidate))):
        manifest=read(path/'release-manifest.json');pin=hashlib.sha256((path/'release-manifest.json').read_bytes()).hexdigest()
        package=RegisteredPackageV2('release:'+ref,str(path),pin,manifest['package_version']);directory=root/'cohorts'/ref;directory.mkdir(parents=True,exist_ok=True)
        profile={'schema':2,'host':case['installed_bundle'].tls_profile.host,'port':case['installed_bundle'].tls_profile.port,'server_name':'localhost',
            'expected_authority_id':control.authority_id,'installation_policy':{**wire(policy),'manifest_digest':pin},'ingress_clock':wire(case['ingress_clock'])}
        assets={'schema':'sylanne3.authority.installed-assets.v1','instance_lock':str(support.lease.path),'c09_storage_v1':storage,
            'installations_v2':[dict(profile_id='reply',certificate_sha256=case['peer'].certificate_sha256,installation_id=control.installation_id,administrator_holder=policy.administrator_holder,manifest_digest=pin)],
            'namespace_bindings_v2':[dict(profile_id='reply',certificate_sha256=case['peer'].certificate_sha256,bot_id=case['namespace'].bot_id,persona_id=case['namespace'].persona_id,authority_namespace=case['authority_namespace'])],
            'c04_installations_v3':[dict(namespace=case['authority_namespace'],package_root=str(path),formal_manifest_sha256=pin)]}
        deployment={'schema':'sylanne3.authority.linux-deployment.v1','profile_id':'reply','package_root':str(path),'trusted_manifest_sha256':pin,
            'assets_path':str(directory/'assets.json'),'inventory_path':str(root/'inventory.json'),'inventory_sha256':hashlib.sha256((root/'inventory.json').read_bytes()).hexdigest(),
            'host_lifecycle':{'drain_timeout_seconds':20}}
        values={'deployment':deployment,'assets':assets,'host_profile':profile}
        for role,value in values.items():save(directory/(role+'.json'),value)
        fields=tuple(ConfigurationFileV2(role,str(directory/(role+'.json')),hashlib.sha256((directory/(role+'.json')).read_bytes()).hexdigest()) for role in ('deployment','assets','host_profile'))
        body=dict(schema='sylanne3.d12.configuration-cohort.v2',cohort_ref='cohort:'+ref,installation_id=control.installation_id,package=package,files=fields,
            credential_profile_directory=str(profile_root),compatibility_plan_ref='plan:compatible-v2',supervisor_policy_digest=policy_digest,
            identity_commitment=derive_cohort_identity_commitment_v2(deployment=deployment,assets=assets,profile=profile,package=package,credential_profile_directory=str(profile_root)))
        cohorts.append(RegisteredConfigurationCohortV2(**body,cohort_digest=_digest(wire(body))))
    assert cohorts[0].identity_commitment==cohorts[1].identity_commitment
    save(control_dir/'registry.json',dict(schema='sylanne3.d12.package-registry.v2',installation_id=control.installation_id,cohorts=cohorts,
        maintenance_policy={'compatibility_plan_ref':'plan:compatible-v2','supervisor_policy_digest':policy_digest}))
    body=dict(schema='sylanne3.d12.package-selection.v2',installation_id=control.installation_id,revision=0,package_epoch=0,operation_id=str(uuid4()),
        release_ref=cohorts[0].package.release_ref,manifest_sha256=cohorts[0].package.manifest_sha256,cohort_ref=cohorts[0].cohort_ref,
        cohort_digest=cohorts[0].cohort_digest,prior_selection_digest=None)
    selected=PackageSelectionV2(**body,selection_digest=_digest(body));save(control_dir/'selection.json',selected)
    from sylanne3.authority_service.v2_owner_session import to_wire as owner_session_to_wire
    setup={'namespace':wire(case['namespace']),'authority_namespace':case['authority_namespace'],'authority_id':control.authority_id,'installation_id':control.installation_id,
        'peer_sha256':case['peer'].certificate_sha256,'admin_sha256':case['admin_peer'].certificate_sha256,'holder':policy.administrator_holder,
        'storage':storage,'instance_lock':str(support.lease.path),'members':{k:str(v) for k,v in members.items()},'profile':profile,
        'tls_files':{k:str(v) for k,v in case['files'].items()},'source_root':str(source),'candidate_root':str(candidate),
        'source_manifest':case['manifest_digest'],'supervisor_policy_digest':policy_digest,'policy':wire(policy),
        'd11_signing_key':case['installed_bundle'].d11_signing_key.hex(),'d02_signing_key':case['installed_bundle'].d02_signing_key.hex(),
        'owner_request':owner_session_to_wire(case['owner_session_request']),'owner_token':case['owner_session_token'],'owner_actor':'owner-actor-reply'}
    save(root/'setup.json',setup)
    from sylanne3.authority_service.d12_initial_selection_original_v1 import InitialPackageSelectionOriginalV1,SIGNATURE_DOMAIN
    from sylanne3.authority_service.d12_package_files_v2 import _canonical
    origin=dict(schema='d12.initial-package-selection.v1',installation_id=control.installation_id,authority_id=control.authority_id,
        namespace_cohort=(case['authority_namespace'],),selection=selected,identity_commitment=cohorts[0].identity_commitment,
        supervisor_policy_digest=policy_digest,initial_storage_manifest_digest=context.manifest_digest,
        initial_storage_generation=0,initial_pointer_version=context.pointer_version,issuer_operation_id=selected.operation_id)
    original=InitialPackageSelectionOriginalV1(**origin,original_digest=_digest(wire(origin)))
    save(control_dir/'initial-selection.json',dict(original=wire(original),signature=Ed25519PrivateKey.from_private_bytes(private).sign(SIGNATURE_DOMAIN+_canonical(wire(original))).hex()))
    return setup


def actual_bundle(root):
    from sylanne3.authority_service.d12_package_files_v2 import InstalledPackageSelectionFilesV2
    from sylanne3.host.authority_profile import AdminInstallationBundle,AdminIngressClockPolicy
    from sylanne3.host.mtls_transport import AuthorityTlsProfile
    from sylanne3.installation_policy import AdminInstallationPolicy
    setup=read(root/'setup.json');files=InstalledPackageSelectionFilesV2(control_directory=root/'control')
    selection,cohort,values=files.read_selected_configuration_cohort_v2();profile=values['host_profile'];tls=setup['tls_files']
    from sylanne3.host.authority_profile import _policy_from_payload
    policy=_policy_from_payload(profile)
    return AdminInstallationBundle(AuthorityTlsProfile('reply',profile['host'],profile['port'],'localhost',setup['authority_id'],
        Path(tls['ca.pem']),Path(tls['client.pem']),Path(tls['client.key']),timeout_seconds=30),policy,
        bytes.fromhex(setup['d11_signing_key']),bytes.fromhex(setup['d02_signing_key']),
        ingress_clock=AdminIngressClockPolicy(**profile['ingress_clock']),package_selection=selection)


def install_profile_boundary(root):
    # Only the fixed root profile location is remapped. The selected cohort,
    # file hashes, TLS private files and actual server-issued grant remain real.
    import sylanne3.host.authority_profile as profile
    profile._load_installation_bundle_from_root=lambda profile_id,path,platform:actual_bundle(root)


def package_components(root,*,server,control,graph_path,namespace,peer,admin,package_root,manifest,model_store):
    from sylanne3.authority_service.d12_operation_status_v1 import InstalledD12OperationStatusServiceV1
    from sylanne3.authority_service.d12_operation_status_rpc_v1 import install_d12_operation_status_service_v1
    from sylanne3.authority_service.d12_installation_lifecycle_v1 import InstalledD12InstallationLifecycleV1
    from sylanne3.authority_service.d12_installation_lifecycle_rpc_v1 import install_d12_installation_lifecycle_v1
    from sylanne3.authority_service.d12_package_files_v2 import InstalledPackageSelectionFilesV2
    from sylanne3.authority_service.d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2
    from sylanne3.authority_service.d12_package_maintenance_authority_v2 import InstalledD12PackageMaintenanceAuthorityV2
    from sylanne3.authority_service.d12_package_maintenance_rpc_v2 import install_d12_package_maintenance_authority_v2
    from sylanne3.graph_coordinator import namespace_ref
    ns=namespace_ref(namespace);files=InstalledPackageSelectionFilesV2(control_directory=root/'control')
    journal=InstalledPackageSupervisorJournalV2(control_directory=root/'control',supervisor_policy_digest=files.read_maintenance_policy_v2()['supervisor_policy_digest'])
    status=InstalledD12OperationStatusServiceV1(fences=server._v2_fences[ns],owner_tickets=server._v2_owner_tickets,
        source_graph_db=graph_path,namespace_id=namespace,installation_id=control.installation_id)
    status.install_schema(admin);install_d12_operation_status_service_v1(server,status)
    lifecycle=InstalledD12InstallationLifecycleV1(status_service=status,control=control,supervisor=supervisor(root,'host'),
        package_root=package_root,expected_manifest_digest=manifest,peer_certificate_sha256=peer.certificate_sha256,
        peer_profile_id='reply',model_store=model_store,drain_timeout_seconds=20)
    lifecycle.install_schema(admin);install_d12_installation_lifecycle_v1(server,lifecycle)
    service=InstalledD12PackageMaintenanceAuthorityV2(lifecycle=lifecycle,package_files=files,
        supervisor_journal=journal,authority_supervisor=supervisor(root,'authority'))
    service.install_schema_v2(admin);install_d12_package_maintenance_authority_v2(server,service)
    # Diagnostic only; authentication and all service gates remain unchanged.
    import functools,traceback
    for name in ('accept_current_package_switch_v2','read_supervisor_intent_v2','read_supervisor_backup_source_v2',
                 'read_current_authority_package_bootstrap_v2','register_current_package_host_ready_v2',
                 'read_current_package_host_bootstrap_v2','finish_current_package_activation_v2'):
        method=getattr(service,name)
        def traced(*args,_method=method,**kwargs):
            try:return _method(*args,**kwargs)
            except Exception:traceback.print_exc();raise
        setattr(service,name,functools.wraps(method)(traced))
    return service


async def source_authority(root):
    from test_d04_owner_semantic_initialization_v3 import real_owner_case,install_d04_test_composition
    from d04_numeric_authority_acceptance_support_v3 import install_actual_root_authority_case_v3
    settings=read(root/'settings.json')
    async def initialized(case):
        await asyncio.to_thread(install_d04_test_composition,case)
        support=await asyncio.to_thread(install_actual_root_authority_case_v3,case,owner_loop=asyncio.get_running_loop())
        build_registry(root,case,support,settings['candidate_root'])
        service=await asyncio.to_thread(package_components,root,server=case['server'],control=support.storage_control,
            graph_path=root/'business.db',namespace=case['namespace'],peer=case['peer'],admin=case['admin_peer'],
            package_root=case['package_root'],manifest=case['manifest_digest'],model_store=case['model_store'])
        save(root/'source-ready.json',{'namespace':case['authority_namespace'],'pid':os.getpid()})
        while True:await asyncio.sleep(1)
    await real_owner_case(root,'owned',installed_package_root=Path(os.environ['SYLANNE_D04_INSTALLED_ROOT']),
        after_role_initialization=initialized,enable_d09_workbench=True,enable_d12_package_maintenance=True,
        extra_owner_capabilities=('workbench.control','workbench.maintain'))


def fixed_authorizer(setup):
    from sylanne3.authority_service.mtls_server import MtlsPeerCredential
    peer=MtlsPeerCredential(setup['peer_sha256']);admin=MtlsPeerCredential(setup['admin_sha256']);ns=setup['authority_namespace']
    actions={'current','read','write','dispatch','execution','owner_guard_read','self_identity_read','model_egress','accounting',
        'owner_session','owner_claim','owner_pair','owner_authorization_revoke','d12_operation_status','d12_lifecycle_control',
        'd12_lifecycle_bootstrap','d12_package_control','d12_package_supervisor','d12_package_bootstrap','d12_package_activate'}
    def authorize(credential,action,namespace,holder):
        return namespace==ns and (credential==peer and action in actions and holder in {None,setup['holder']}
            or credential==admin and action in {'current','owner_pair','owner_identity_pair','owner_identity_revoke','self_identity_mutate',
                'd12_operation_install','d12_lifecycle_install','d12_package_install'})
    return authorize,peer,admin


async def reopened_authority(root,*,fail_before_listener=False):
    from sylanne3.authority_service import AuthorityServiceCore
    from sylanne3.authority_service.c09_storage_control_v1 import C09StorageControlV1,InstalledC09InstanceLeaseV1
    from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
    from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
    from sylanne3.authority_service.installed_core_verifiers import installed_core_verifier_factory
    from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
    from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
    from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
    from sylanne3.host.owner_deployment import OwnerDeploymentVerifier
    from sylanne3.authority_service.v2_owner_proof import AuthorityV2OwnerProofStore
    from sylanne3.authority_service.v2_owner_session import AuthorityV2OwnerSessionStore
    from sylanne3.authority_service.local_composition import compose_local_owner_authority
    from sylanne3.authority_service.mtls_server import AdministratorInstallationV2,AuthorityServerTlsConfig
    from sylanne3.authority_service.v2_clock import AuthorityClockReadingV2
    from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
    from sylanne3.runtime.issuers import build_runtime_issuers
    setup=read(root/'setup.json');bundle=actual_bundle(root);ns=setup['authority_namespace'];namespace=NamespaceId(**setup['namespace'])
    lease=InstalledC09InstanceLeaseV1(setup['instance_lock']);control=C09StorageControlV1(**setup['storage'],lease=lease)
    context=control.read_verified_current_storage_v1();paths={m['role']:Path(m['resolved_path']) for m in context.manifest['members']}
    execution_member=next(m for m in context.manifest['members'] if m['role']=='execution')
    deletion=AuthorityV2DeletionGuard(paths['deletion']);execution=AuthorityV2ExecutionJournal(paths['execution'],namespace=ns,
        journal_id=execution_member['incarnation_or_journal_id'],create=False)
    verifiers=installed_core_verifier_factory(deletion,{ns:execution});authorize,peer,admin=fixed_authorizer(setup)
    core=AuthorityServiceCore(paths['core'],authorizer=authorize,deletion_verifier=verifiers.deletion,
        execution_verifier=verifiers.execution,effect_verifier=verifiers.effect,dispatch_verifier=verifiers.dispatch,create=False)
    core.install_current_c09_storage_reader_v1(reader=control)
    fences=AuthorityV2FenceStore(core._db,create=False,lock=core._lock)
    protected=AuthorityV2FenceService(core=core,fences=fences,deletion=deletion,execution=execution,namespace=ns)
    clock=lambda:datetime.now(timezone.utc)
    pairing=AuthorityOwnerPairingSource(core,utc_clock=clock,create=False);deployment=OwnerDeploymentVerifier(pairing,clock)
    proofs=AuthorityV2OwnerProofStore(core,utc_clock=clock,pairing_verifier=deployment.pair_credential,create=False)
    sessions=AuthorityV2OwnerSessionStore(core,utc_clock=clock,current_pairing_source=pairing,create=False)
    if fail_before_listener:
        save(root/'failed-candidate-opened.json',{'pid':os.getpid(),'selected':wire(bundle.package_selection)})
        return
    policy=bundle.installation_policy;pin=policy.manifest_digest
    server=compose_local_owner_authority(core=core,v2_fences={ns:protected},graph_db_path=paths['graph'],utc_clock=clock,
        first_claim_verifier=deployment.first_claim,claimant_verifier=None,
        administrator_authorizer=lambda candidate,action,selected,holder:candidate==peer and action=='pair' and selected=='authority:enrollment' and holder=='reply',
        publisher_manifest_verifier=lambda profile,plugin,version,manifest:profile=='reply' and manifest==pin,
        installations_v2={(peer.certificate_sha256,'reply'):AdministratorInstallationV2(setup['installation_id'],setup['holder'],'policy:reply','v2',pin,'clock:reply',.5)},
        namespace_bindings_v2={(peer.certificate_sha256,'reply',namespace):ns},clock_provider=lambda:AuthorityClockReadingV2('clock:reply',time.time(),time.monotonic(),'epoch:reply',True,.1),
        create_owner_schema=False,create_self_identity_schema=False,create_worker_result_schema=False,
        owner_proofs=proofs,owner_sessions=sessions,creation_pairing_source=pairing)
    model_store=AuthorityV2ModelEgressStore(core._db,create=False,lock=core._lock)
    d02,d11=build_runtime_issuers(b'reply-issuer-key-'*2)
    bridge=server._v2_execution[ns]
    from sylanne3.authority_service.d04_numeric_service_v3 import AuthorityD04NumericServiceV3
    from sylanne3.authority_service.d04_root_execution_service_v3 import AuthorityD04RootExecutionServiceV3
    from sylanne3.host.installed_d04_numeric_build_v3 import read_installed_d04_numeric_identity_v3
    from sylanne3.host.installed_d04_root_build_v3 import read_installed_d04_root_identity_v3
    import hmac
    selected_root=Path(os.environ['SYLANNE_D04_INSTALLED_ROOT'])
    common=dict(bridge=bridge,owner_tickets=server._v2_owner_tickets,namespace=namespace,installation_id=setup['installation_id'],
        graph_db_path=paths['graph'],resource_issuer=d02,budget_issuer=d11,credential=peer,trusted_now_utc=time.time)
    numeric=AuthorityD04NumericServiceV3(**common,signing_key=hmac.digest(bundle.d11_signing_key,b'sylanne3.numeric-acceptance.v3\0'+setup['installation_id'].encode(),'sha256'),
        installed_identity=read_installed_d04_numeric_identity_v3(selected_root,pin))
    server.install_d04_numeric_service_v3(ns,numeric)
    root_service=AuthorityD04RootExecutionServiceV3(**common,signing_key=hmac.digest(bundle.d11_signing_key,b'sylanne3.root-acceptance.v3\0'+setup['installation_id'].encode(),'sha256'),
        installed_identity=read_installed_d04_root_identity_v3(selected_root,pin))
    server._d04_root_services_v3={ns:root_service};core.install_execution_redaction_d04_root_service_v3(ns,root_service)
    package_components(root,server=server,control=control,graph_path=paths['graph'],namespace=namespace,peer=peer,admin=admin,
        package_root=selected_root,manifest=pin,model_store=model_store)
    tls=setup['tls_files'];listener=await server.start(bundle.tls_profile.host,bundle.tls_profile.port,
        AuthorityServerTlsConfig(tls['server.pem'],tls['server.key'],tls['ca.pem'],timeout_seconds=30,max_message_bytes=65536))
    save(root/('authority-ready-'+str(bundle.package_selection.package_epoch)+'.json'),{'pid':os.getpid()})
    await asyncio.Event().wait()


async def paired_command(root,command):
    from sylanne3.host.authority_client import AuthorityProvisioningRequest,PublisherPackageIdentity,AUTHORITY_PROTOCOL,AUTHORITY_V2_PROTOCOL
    from sylanne3.host.mtls_transport import MtlsAuthorityTransport
    bundle=actual_bundle(root);selected=bundle.package_selection
    registry=read(root/'control'/'registry.json');cohort=next(c for c in registry['cohorts'] if c['cohort_ref']==selected.cohort_ref)
    package=Path(cohort['package']['package_root']);request=AuthorityProvisioningRequest(AUTHORITY_PROTOCOL,'reply','astrbot_plugin_sylanne','4.28.1',package,package,PublisherPackageIdentity(selected.manifest_sha256))
    transport=MtlsAuthorityTransport({'reply':bundle.tls_profile})
    try:
        handshake=await transport.handshake(request,protocol=AUTHORITY_V2_PROTOCOL)
        grant=await transport.installation_grant_v2(request,handshake)
        assert grant.installation_id==bundle.installation_policy.installation_id and grant.manifest_digest==selected.manifest_sha256
        return await transport._content_rpc(request,handshake,'d12_package_maintenance_v2',command,protocol=AUTHORITY_V2_PROTOCOL)
    finally:await transport.close()


async def actual_host(root):
    from sylanne3.native_runtime.loader import load_production_native
    from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
    setup=read(root/'setup.json');bundle=actual_bundle(root);selection=bundle.package_selection
    native=load_production_native(Path(os.environ['SYLANNE_D04_INSTALLED_ROOT']),trusted_manifest_sha256=selection.manifest_sha256)
    registry=load_verified_affect_scheme(Path(os.environ['SYLANNE_D04_INSTALLED_ROOT']),selection.manifest_sha256).registry
    while read(root/'processes.json')['host']['pid']!=os.getpid():await asyncio.sleep(.01)
    process=read(root/'processes.json')['host']
    with sqlite3.connect(setup['members']['core']) as db:
        operation=db.execute('SELECT operation_id FROM authority_d12_lifecycle_heads_v1 WHERE namespace=?',(setup['authority_namespace'],)).fetchone()[0]
    command=dict(namespace=setup['authority_namespace'],action='register_host_ready',operation_id=operation,process_id=os.getpid(),
        invocation_id=process['invocation_id'],selection_revision=selection.revision,cohort_digest=selection.cohort_digest,
        catalogue_hash=registry.type_registry.catalogue_hash,ready_domains=sorted(registry.registrations))
    while True:
        result=await paired_command(root,command)
        if result['lifecycle_state']=='active':
            save(root/('host-active-'+str(selection.package_epoch)+'.json'),result);break
        await asyncio.sleep(.1)
    await asyncio.Event().wait()


def isolated_executor(root):
    """Only fixed root locations/units move; actual private journal kernel runs."""
    from sylanne3.authority_service.d12_package_files_v2 import InstalledPackageSelectionFilesV2
    from sylanne3.authority_service.d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2,_SupervisorJournalKernelV2
    from sylanne3.authority_service.d12_package_supervisor_writer_v2 import _InstalledPackageSupervisorWriterV2
    from sylanne3.authority_service.d12_package_supervisor_client_v2 import InstalledPackageSupervisorAuthorityClientV2
    from sylanne3.authority_service.d12_package_supervisor_v2 import InstalledD12PackageSupervisorV2
    setup=read(root/'setup.json');writer=object.__new__(_InstalledPackageSupervisorWriterV2)
    writer.directory=root/'control';writer.files=InstalledPackageSelectionFilesV2(control_directory=writer.directory)
    writer.policy=read(writer.directory/'supervisor-policy.json')
    writer.reader=InstalledPackageSupervisorJournalV2(control_directory=writer.directory,supervisor_policy_digest=setup['supervisor_policy_digest'])
    writer._stack=ExitStack();writer.db=sqlite3.connect(writer.directory/'supervisor.sqlite3',check_same_thread=False)
    import fcntl
    lock=writer._stack.enter_context((writer.directory/'executor.lock').open('a+b'));fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    writer.kernel=_SupervisorJournalKernelV2(writer.db,(writer.directory/'journal-signing.key').read_bytes(),writer.reader.policy)
    value=object.__new__(InstalledD12PackageSupervisorV2);value.writer=writer;value.files=writer.files;value.journal=writer.reader
    value.policy=writer.policy;value._fresh_start_permissions=set();value.host=supervisor(root,'host');value.authority=supervisor(root,'authority')
    value.client=InstalledPackageSupervisorAuthorityClientV2(profile_id='reply',package_files=writer.files,supervisor_policy_digest=writer.reader.policy)
    return value


async def execute_supervisor(root,operation):
    controller=isolated_executor(root)
    try:
        result=await controller.run(operation)
        assert await controller.run(operation)==result
        save(root/'executor-result.json',result)
    finally:controller.close()


if __name__=='__main__':
    mode=sys.argv[1];root=Path(sys.argv[2]).resolve();install_os_boundary(root);install_profile_boundary(root)
    if mode=='source':asyncio.run(source_authority(root))
    elif mode=='authority':asyncio.run(reopened_authority(root))
    elif mode=='fail_authority':asyncio.run(reopened_authority(root,fail_before_listener=True))
    elif mode=='host':asyncio.run(actual_host(root))
    elif mode=='executor':asyncio.run(execute_supervisor(root,sys.argv[3]))
    else:raise ValueError('closed actual acceptance process role required')
