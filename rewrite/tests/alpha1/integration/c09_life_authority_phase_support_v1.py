"""Cold phases for one fresh, test-owned Life/C09 installation.

Initial configuration is signed and persisted before the first Host model
request. Later processes use that original installation, never keys or issuer
claims reconstructed from business records. No normal Host is reopened here.
"""
from contextlib import contextmanager
from dataclasses import asdict
import base64
import hashlib
import json
import os
from pathlib import Path

SCHEMA = 'sylanne.test.c09.life-cold-installation.v1'
CURRENT_SCHEMA_V3='sylanne.test.c09.life-cold-installation.v3'
_ACTIONS = ('accounting', 'current', 'delete', 'deletion', 'erasure_closure_install',
    'execution', 'execution_redaction_install', 'read', 'write')
_FIELDS = {'schema', 'control', 'namespace', 'authority_namespace', 'peer_certificate',
    'subject', 'holder', 'actions', 'package_root', 'manifest_digest', 'inventory',
    'target_directory', 'runtime_issuer_key', 'admin_d02_key', 'provider_cache',
    'initial_manifest_digest', 'initial_process', 'key_id', 'fixture_digest', 'signature'}


def persist_life_cold_fixture_v1(path, *, core, control, namespace, peer, subject, holder,
        package_root, manifest_digest, inventory, target_directory,
        runtime_issuer_signing_key, admin_d02_signing_key, provider_cache,
        deployment_config=None,phase_setup_file=None):
    from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1
    from sylanne3.authority_service.c09_storage_control_v1 import canonical
    from sylanne3.graph_coordinator import namespace_ref
    from c09_life_provider_cache_acceptance_v1 import _write_new
    control.lease.require_held()
    current = control.read_verified_current_storage_v1()
    current.require_current('business')
    auth_ns = namespace_ref(namespace)
    if (current.stage != 'READY' or current.pointer_version != 0
            or inventory.manifest_digest != current.manifest['inventory_manifest_digest']
            or Path(core.path).resolve() != Path(next(m['resolved_path'] for m in current.manifest['members'] if m['role'] == 'core')).resolve()
            or subject != 'mtls:sha256:' + peer.certificate_sha256):
        raise ValueError('original first-installation configuration required')
    for action in _ACTIONS:
        core._require(peer, action, auth_ns, holder)
        core._require(peer, action, auth_ns, None)
    with core._tx() as db:
        if db.execute('SELECT COUNT(*) FROM authority_model_egress_v1 WHERE namespace=?', (auth_ns,)).fetchone()[0]:
            raise ValueError('cold configuration must predate the first model request')
    if any(type(key) is not bytes or len(key) < 32 for key in (runtime_issuer_signing_key, admin_d02_signing_key)):
        raise ValueError('original initial fixture key configuration required')
    target = Path(path).absolute()
    if target.parent != control.key_path.parent or any(target.is_relative_to(root) for root in control._roots):
        raise ValueError('test installation configuration must stay in original protected directory')
    cache = provider_cache.installation_material()
    body = dict(schema=SCHEMA, control=dict(control_path=str(control.path), key_path=str(control.key_path),
        lease_path=str(control.lease.path), installation_id=control.installation_id, authority_id=control.authority_id,
        control_store_id=control.control_store_id, key_id=control.key_id, resource_roots=[str(p) for p in control._roots]),
        namespace=list(namespace.as_tuple), authority_namespace=auth_ns, peer_certificate=peer.certificate_sha256,
        subject=subject, holder=holder, actions=list(_ACTIONS), package_root=str(Path(package_root).resolve(strict=True)),
        manifest_digest=manifest_digest, inventory=asdict(inventory), target_directory=str(Path(target_directory).resolve(strict=True)),
        runtime_issuer_key=base64.b64encode(runtime_issuer_signing_key).decode(),
        admin_d02_key=base64.b64encode(admin_d02_signing_key).decode(), provider_cache=cache,
        initial_manifest_digest=current.manifest_digest, initial_process=read_process_identity_v1(os.getpid()))
    if deployment_config is not None:
        body['schema']=CURRENT_SCHEMA_V3
        body['deployment_original']=_current_deployment_assets_v3(deployment_config,phase_setup_file,control,namespace)
    elif phase_setup_file is not None:
        raise ValueError('current protected setup requires actual initial DeploymentConfig')
    original = control.sign_original_v1(body['schema'], body, 'fixture_digest')
    _write_new(target, canonical(original).encode())
    return {'path': str(target), 'fixture_digest': original['fixture_digest']}


def _current_deployment_assets_v3(config,setup_file,control,namespace):
    from sylanne3.authority_service.deployment_config import AuthorityDeploymentConfig,InstalledC04AuthorityV3
    from sylanne3.authority_service.linux_clock_v1 import LinuxKernelClockProviderV1
    from sylanne3.authority_service.linux_installation_security_v1 import read_installed_bytes_v1
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    if type(config) is not AuthorityDeploymentConfig or type(config.clock_provider) is not LinuxKernelClockProviderV1:
        raise ValueError('actual initial current DeploymentConfig and kernel clock required')
    setup=Path(setup_file).resolve(strict=True)
    setup_digest=hashlib.sha256(read_installed_bytes_v1(setup,limit=262144)).hexdigest()
    initial=M1PhaseFixtureInstallationV2.from_protected_setup_v2(setup)
    ans=next(iter(config.execution_journals))
    model=config.natural_model_authorities_v2[ans]
    installed=config.c04_installations_v3[ans]
    if (type(installed) is not InstalledC04AuthorityV3
            or initial.initial_bundle.installation_policy!=model.installation_bundle.installation_policy
            or initial.workflows!=model.workflows or initial.initial_bundle.d11_signing_key!=model.installation_bundle.d11_signing_key
            or initial.initial_bundle.d02_signing_key!=model.installation_bundle.d02_signing_key
            or model.d11_issuer.resource_issuer is not config.c09_maintenance_factory.resource_issuer
            or model.d11_issuer is not config.c09_maintenance_factory.budget_job_issuer
            or config.c09_storage_v1.control_path!=control.path
            or model.installation_bundle.installation_policy.namespace!=namespace):
        raise ValueError('initial current deployment assets crossed installation')
    component=read_installed_bytes_v1(installed.component_key_path,limit=32,private=True,allowed_gid=os.getegid())
    assert len(component)==32
    def wire(value):
        if isinstance(value,Path):return str(value)
        if isinstance(value,dict):return {key:wire(item) for key,item in value.items()}
        if isinstance(value,(tuple,list)):return [wire(item) for item in value]
        return value
    return dict(schema='sylanne.test.c09.current-deployment-assets.v3',
        fixture_policy='current_life_fixture_policy_v3',phase_setup_path=str(setup),phase_setup_sha256=setup_digest,
        authority_db=str(config.authority_db),deletion_db=str(config.deletion_db),graph_db=str(config.graph_db),
        instance_lock=str(config.instance_lock),execution_journals={key:wire(asdict(value)) for key,value in config.execution_journals.items()},
        tls=wire(asdict(config.tls)),bind_host=config.bind_host,bind_port=config.bind_port,
        installations=[dict(peer=list(key),value=wire(asdict(value))) for key,value in sorted(config.installations_v2.items())],
        namespace_bindings=[dict(peer=list(key[:2]),namespace=list(key[2].as_tuple),authority_namespace=value)
            for key,value in sorted(config.namespace_bindings_v2.items(),key=lambda item:repr(item[0]))],
        reverse_profiles={key:wire(asdict(value)) for key,value in config.reverse_handoff_profiles.items()},
        reverse_issuers=dict(config.reverse_handoff_issuers),self_readers={key:list(value) for key,value in config.self_identity_readers_v2.items()},
        worker_fact_committers={key:list(value) for key,value in config.worker_result_fact_committers_v2.items()},
        onebot_observations={key:wire(asdict(value)) for key,value in config.host_onebot_observations_v2.items()},
        observer_peer=list(model.observer_peer),clock=dict(source_id=config.clock_provider.source_id,
            maximum_error_seconds=config.clock_provider.maximum_error_seconds),
        c04=dict(package_root=str(installed.package_root),formal_manifest_sha256=installed.formal_manifest_sha256,
            component_key_path=str(installed.component_key_path),component_key_sha256=hashlib.sha256(component).hexdigest()))


def current_life_deployment_from_original_v3(raw):
    """Decode the pre-business signed installation; no writes, keys, or current Self observations."""
    from datetime import datetime,timezone
    import hmac
    from sylanne3.authority_service.deployment_config import (AuthorityDeploymentConfig,ExecutionJournalInstallation,
        InstalledC04AuthorityV3,InstalledC09AuthorityV1,InstalledNaturalModelAuthorityV2)
    from sylanne3.authority_service.mtls_server import MtlsPeerCredential,AdministratorInstallationV2,AuthorityServerTlsConfig
    from sylanne3.authority_service.reverse_handoff import AdministratorReverseHandoffProfile
    from sylanne3.authority_service.installed_platform_observation import HostOneBotObservationInstallationV2
    from sylanne3.authority_service.installed_core_verifiers import installed_core_verifier_factory
    from sylanne3.authority_service.linux_clock_v1 import LinuxKernelClockProviderV1
    from sylanne3.authority_service.linux_installation_security_v1 import read_installed_bytes_v1
    from sylanne3.authority_service.c09_installed_factory_v1 import InstalledC09MaintenanceFactoryV1
    from sylanne3.runtime_contracts import NamespaceId
    from sylanne3.runtime.issuers import D02ResourceIssuer,D11BudgetJobIssuer
    from sylanne3.domains.d02.body_quote_original import D02BodyQuoteAuthority
    from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    from d11_offline_authority_acceptance_support_v1 import current_life_fixture_policy_v3
    from c09_life_provider_cache_acceptance_v1 import ControlledLifeProviderCacheV1
    if raw['schema']!=CURRENT_SCHEMA_V3:raise ValueError('explicit current initial deployment original required')
    asset=raw['deployment_original']
    fields={'schema','fixture_policy','phase_setup_path','phase_setup_sha256','authority_db','deletion_db','graph_db','instance_lock',
        'execution_journals','tls','bind_host','bind_port','installations','namespace_bindings','reverse_profiles','reverse_issuers',
        'self_readers','worker_fact_committers','onebot_observations','observer_peer','clock','c04'}
    if set(asset)!=fields or asset['schema']!='sylanne.test.c09.current-deployment-assets.v3' or asset['fixture_policy']!='current_life_fixture_policy_v3':
        raise ValueError('exact original current deployment asset inventory required')
    setup=Path(asset['phase_setup_path']).resolve(strict=True)
    if hashlib.sha256(read_installed_bytes_v1(setup,limit=262144)).hexdigest()!=asset['phase_setup_sha256']:
        raise ValueError('original protected initial setup changed')
    initial=M1PhaseFixtureInstallationV2.from_protected_setup_v2(setup);bundle=initial.initial_bundle;ns=NamespaceId(*raw['namespace']);ans=raw['authority_namespace']
    if (bundle.installation_policy.namespace!=ns or bundle.installation_policy.installation_id!=raw['control']['installation_id']
            or bundle.installation_policy.manifest_digest!=raw['manifest_digest']
            or str(initial.package_root)!=raw['package_root'] or str(initial.authority_store)!=asset['authority_db']
            or base64.b64decode(raw['runtime_issuer_key'],validate=True)!=bundle.d11_signing_key
            or base64.b64decode(raw['admin_d02_key'],validate=True)!=bundle.d02_signing_key):
        raise ValueError('same protected initial bundle/Root/issuer keys required')
    installed=InstalledC04AuthorityV3(Path(asset['c04']['package_root']),asset['c04']['formal_manifest_sha256'],Path(asset['c04']['component_key_path']))
    if (installed.package_root!=initial.package_root or installed.formal_manifest_sha256!=raw['manifest_digest']
            or hashlib.sha256(read_installed_bytes_v1(installed.component_key_path,limit=32,private=True,allowed_gid=os.getegid())).hexdigest()!=asset['c04']['component_key_sha256']):
        raise ValueError('original installed C04 component asset changed')
    d02=D02ResourceIssuer(bundle.d02_signing_key);d11=D11BudgetJobIssuer(d02,bundle.d11_signing_key)
    body=D02BodyQuoteAuthority(hmac.digest(bundle.d02_signing_key,b'sylanne3.d02.body_quote_original.v1\0'+raw['control']['installation_id'].encode(),'sha256'))
    material=raw['provider_cache']
    cache=ControlledLifeProviderCacheV1.attach_installed(material['root'],initial.provider_configuration,
        authority_id=material['authority_id'],installation_id=material['installation_id'],namespace=material['namespace'],
        executable_sha256=material['executable_sha256'],public_key_sha256=material['public_key_sha256'],phase_config=initial)
    registry=load_verified_affect_scheme(initial.package_root,raw['manifest_digest']).registry.type_registry
    factory=InstalledC09MaintenanceFactoryV1(namespace=ns,peer=tuple(asset['observer_peer']),registry=registry,
        resource_issuer=d02,body_authority=body,inventory_manifest=_inventory(raw['inventory']),target_directory=Path(raw['target_directory']),
        provider_cache_cleanup=cache.installed_disposition(),budget_job_issuer=d11)
    installations={tuple(item['peer']):AdministratorInstallationV2(**item['value']) for item in asset['installations']}
    bindings={(*item['peer'],NamespaceId(*item['namespace'])):item['authority_namespace'] for item in asset['namespace_bindings']}
    admin=[key for key,value in installations.items() if value.installation_id=='installation-admin'];assert len(admin)==1
    peer=MtlsPeerCredential(raw['peer_certificate'])
    authorize,administrator,credential=current_life_fixture_policy_v3(peer,MtlsPeerCredential(admin[0][0]),ans,raw['control']['installation_id'])
    values=raw['control'];clock=LinuxKernelClockProviderV1(**asset['clock'])
    cfg=AuthorityDeploymentConfig(authority_db=Path(asset['authority_db']),deletion_db=Path(asset['deletion_db']),graph_db=Path(asset['graph_db']),
        instance_lock=Path(asset['instance_lock']),execution_journals={key:ExecutionJournalInstallation(**value) for key,value in asset['execution_journals'].items()},
        tls=AuthorityServerTlsConfig(**asset['tls']),bind_host=asset['bind_host'],bind_port=asset['bind_port'],installations_v2=installations,
        namespace_bindings_v2=bindings,reverse_handoff_profiles={key:AdministratorReverseHandoffProfile(**value) for key,value in asset['reverse_profiles'].items()},
        reverse_handoff_issuers=asset['reverse_issuers'],core_authorizer=authorize,administrator_authorizer=administrator,
        core_verifier_factory=installed_core_verifier_factory,publisher_manifest_verifier=lambda *args:True,
        utc_clock=lambda:datetime.now(timezone.utc),local_administrator_credential=credential,clock_provider=clock,
        natural_model_authorities_v2={ans:InstalledNaturalModelAuthorityV2(d11,bundle.model_workflows,tuple(asset['observer_peer']),bundle)},
        self_identity_readers_v2={key:tuple(value) for key,value in asset['self_readers'].items()},
        worker_result_fact_committers_v2={key:tuple(value) for key,value in asset['worker_fact_committers'].items()},
        host_onebot_observations_v2={key:HostOneBotObservationInstallationV2(**value) for key,value in asset['onebot_observations'].items()},
        c04_installations_v3={ans:installed},c09_storage_v1=InstalledC09AuthorityV1(values['control_path'],values['key_path'],values['installation_id'],
            values['authority_id'],values['control_store_id'],values['key_id'],tuple(Path(item) for item in values['resource_roots'])),c09_maintenance_factory=factory)
    from sylanne3.host.c09_controlled_sdk_bootstrap_v3 import read_controlled_sdk_root_descriptor_v3
    descriptor=read_controlled_sdk_root_descriptor_v3(initial.c09_sdk_peer_cohort,
        config=cfg,inventory=factory.inventory,peer=factory.peer)
    factory.install_controlled_sdk_peer_registry_v3(root_descriptor=descriptor,closed_services=None)
    return cfg,cache


@contextmanager
def open_life_cold_fixture_v1(path, *, expected_fixture_digest,current_only=False):
    from sylanne3.authority_service.c09_storage_control_v1 import C09StorageControlV1, InstalledC09InstanceLeaseV1
    from sylanne3.authority_service.linux_installation_security_v1 import read_installed_bytes_v1
    if current_only:
        import stat
        from c09_life_provider_cache_acceptance_v1 import _read
        target=Path(path).absolute()
        if any(item.is_symlink() for item in (target,*target.parents)):
            raise ValueError('owned current fixture descriptor traverses a symlink')
        info=target.stat()
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>262144:
            raise ValueError('actual Authority-owned private current fixture descriptor required')
        raw=json.loads(_read(target.parent,target.name))
        if raw['schema']!=CURRENT_SCHEMA_V3:raise ValueError('explicit current fixture schema required')
    else:
        raw=json.loads(read_installed_bytes_v1(Path(path),limit=262144))
    fields=_FIELDS if raw['schema']==SCHEMA else _FIELDS|{'deployment_original'}
    if type(raw) is not dict or set(raw)!=fields or raw['schema'] not in {SCHEMA,CURRENT_SCHEMA_V3} or raw['actions']!=list(_ACTIONS):
        raise ValueError('closed original test installation required')
    if type(expected_fixture_digest) is not str or raw['fixture_digest'] != expected_fixture_digest:
        raise ValueError('initial fixture descriptor differs')
    values = raw['control']
    if type(values) is not dict or set(values) != {'control_path','key_path','lease_path','installation_id',
            'authority_id','control_store_id','key_id','resource_roots'}:
        raise ValueError('closed original Control installation differs')
    if Path(path).resolve(strict=True).parent != Path(values['key_path']).resolve(strict=True).parent:
        raise ValueError('original protected configuration location differs')
    lease = InstalledC09InstanceLeaseV1(values['lease_path'])
    try:
        control = C09StorageControlV1(**{k:v for k,v in values.items() if k != 'lease_path'}, lease=lease)
        control.verify_original_v1(raw, 'fixture_digest')
        yield raw, control
    finally:
        lease.close()


def _inventory(raw):
    from sylanne3.runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2, InstalledResourceV2
    values = dict(raw)
    values['resources'] = tuple(InstalledResourceV2(**{**row, 'content_coverage': tuple(row['content_coverage'])})
        for row in values['resources'])
    return InstallationFilesystemManifestV2(**values)


@contextmanager
def _maintenance(raw, control):
    """Open the selected generation for actual cleanup, with original policy."""
    from sylanne3.runtime_contracts import NamespaceId
    from sylanne3.graph_coordinator import GraphCoordinator
    from sylanne3.graph_store import ProductionGraphStore
    from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
    from sylanne3.authority_service.mtls_server import MtlsPeerCredential
    from sylanne3.authority_service.core import AuthorityServiceCore
    from sylanne3.authority_service.installed_core_verifiers import installed_core_verifier_factory
    from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
    from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
    from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
    from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
    from sylanne3.authority_service.v2_scoped_erasure_store import AuthorityV2ScopedErasureStore
    from sylanne3.authority_service.v2_deletion_recovery_service import AuthorityV2DeletionPendingRecovery
    from sylanne3.authority_service.c09_installed_factory_v1 import _LocalInstalledFencePortV1
    from sylanne3.authority_service.c09_storage_control_v1 import SURFACES
    from sylanne3.authority_service.c09_storage_maintenance_v1 import InstalledC09WriterGateV1, InstalledC09MaintenanceV1
    from sylanne3.authority_service.c09_surface_cleanup_v1 import InstalledC09SurfaceCleanupV1
    from sylanne3.authority_service.c09_close_apply_v1 import InstalledC09CloseApplyV1
    from sylanne3.authority_service.c09_graph_application_v1 import InstalledC09GraphApplicationV1
    from sylanne3.authority_service.erasure_closure_inventory import AuthorityErasureClosureInventory
    from c09_life_provider_cache_acceptance_v1 import ControlledLifeProviderCacheV1

    ns = NamespaceId(*raw['namespace']); ans = raw['authority_namespace']
    peer = MtlsPeerCredential(raw['peer_certificate'])
    def authorizer(credential, action, namespace, holder):
        return (credential == peer and action in _ACTIONS and namespace == ans
            and holder in {None, raw['holder']})
    context = control.read_verified_current_storage_v1()
    if context.stage not in {'PREPARED', 'SWITCHED', 'CLEANED', 'RELEASED'}:
        raise ValueError('cold cleanup requires an existing actual prepared chain')
    members = {member['role']: member for member in context.manifest['members']}
    handles = []
    try:
        deletion = AuthorityV2DeletionGuard(members['deletion']['resolved_path']); handles.append(deletion)
        execution = AuthorityV2ExecutionJournal(members['execution']['resolved_path'], namespace=ans,
            journal_id=members['execution']['incarnation_or_journal_id'], installed_storage_reader=control); handles.append(execution)
        verifiers = installed_core_verifier_factory(deletion, {ans: execution})
        core = AuthorityServiceCore(members['core']['resolved_path'], authorizer=authorizer,
            deletion_verifier=verifiers.deletion, execution_verifier=verifiers.execution,
            effect_verifier=verifiers.effect, dispatch_verifier=verifiers.dispatch); handles.append(core)
        core.install_current_c09_storage_reader_v1(reader=control)
        fences = AuthorityV2FenceStore(core._db, lock=core._lock)
        service = AuthorityV2FenceService(core=core, fences=fences, deletion=deletion, execution=execution, namespace=ans)
        scoped = AuthorityV2ScopedErasureStore(core=core, fences=fences, deletion=deletion, execution=execution, namespace=ans)
        recovery = AuthorityV2DeletionPendingRecovery(core=core, fences=fences, deletion=deletion, execution=execution,
            namespace=ans, scoped_store=scoped)
        registry = load_verified_affect_scheme(Path(raw['package_root']), raw['manifest_digest']).registry.type_registry
        store = ProductionGraphStore(members['graph']['resolved_path'], registry); handles.append(store)
        bootstrap = object()
        graph = GraphCoordinator(store, bootstrap, holder=raw['holder'],
            content_fence_v2=_LocalInstalledFencePortV1(service, peer, raw['subject'], ns))
        app = InstalledC09GraphApplicationV1(control=control, core=core, scoped=scoped, coordinator=graph,
            bootstrap=bootstrap, namespace=ns, subject=raw['subject'], credential=peer)
        close_apply = InstalledC09CloseApplyV1(control=control, service=service, recovery=recovery,
            graph_application=app, subject=raw['subject'], credential=peer)
        control.install_applied_reader_v1(close_apply)
        gate = InstalledC09WriterGateV1(control=control)
        closure = AuthorityErasureClosureInventory(scoped=scoped, installation_id=control.installation_id)
        # These phases consume only the signed PREPARED transition and retained
        # facts. They do not install a live original producer or recreate C04 rights.
        inventory = _inventory(raw['inventory'])
        cache = raw['provider_cache']
        provider = ControlledLifeProviderCacheV1.attach_installed(cache['root'],
            {'id': cache['provider_id'], 'type': 'openai_chat_completion', 'model': 'model-1'},
            authority_id=cache['authority_id'], installation_id=cache['installation_id'], namespace=cache['namespace'],
            executable_sha256=cache['executable_sha256'], public_key_sha256=cache['public_key_sha256'])
        cleaners = {surface: InstalledC09SurfaceCleanupV1(control=control, gate=gate, inventory_manifest=inventory,
            surface=surface, registry=registry) for surface in SURFACES - {'model_prompt_caches'}}
        cleaners['model_prompt_caches'] = provider.installed_disposition()
        maintenance = InstalledC09MaintenanceV1(control=control, gate=gate, core=core, closure=closure, graph=store,
            namespace_id=ns, accepted_service=None, inventory_manifest=inventory, target_directory=raw['target_directory'],
            subject=raw['subject'], credential=peer, service_handles=(store,), surface_services=cleaners,
            close_apply_service=close_apply)
        yield maintenance
    finally:
        errors = []
        for handle in reversed(handles):
            try:handle.close()
            except Exception as error:errors.append(error)
        if errors:raise ExceptionGroup('cold fixture handles did not close', errors)


def run_life_cold_phase_v1(path, phase, *, expected_fixture_digest, source_execution_commitment=None):
    from sylanne3.authority_service.c09_process_identity_v1 import require_process_retired_v1
    from sylanne3.authority_service.c09_control_selector_v2 import InstalledC09ControlSelectorV2
    from sylanne3.authority_service.c09_sanitized_history_v2 import build_sanitized_history_v2, InstalledC09StorageReaderV2
    from sylanne3.authority_service.c09_storage_maintenance_v1 import InstalledC09WriterGateV1
    with open_life_cold_fixture_v1(path, expected_fixture_digest=expected_fixture_digest) as (raw, control):
        require_process_retired_v1(raw['initial_process'])
        if phase in {'switch', 'release'}:
            context = control.read_verified_current_storage_v1()
            operation = context.prepared_original['operation_id']
            with _maintenance(raw, control) as maintenance:
                if phase == 'switch':
                    maintenance.switch_prepared_storage_v1(operation_id=operation)
                else:
                    maintenance.resume_storage_maintenance_v1(operation_id=operation)
            return {'phase': phase, 'pid': os.getpid(), 'stage': control.read_verified_current_storage_v1().stage}
        selector = InstalledC09ControlSelectorV2(control, str(control.path)+'.selector-v2', str(control.path)+'.selector-v2.journal')
        history_path = control.path.parent / 'sanitized-history-v2.json'
        if phase == 'build':
            history = build_sanitized_history_v2(control, history_path, gate=InstalledC09WriterGateV1(control=control))
            assert history['frames'] and history['storage_stage'] == 'RELEASED'
            selector.prepare(history_path)
            return {'phase': phase, 'pid': os.getpid(), 'frames': len(history['frames'])}
        if phase == 'factual':
            return _read_actual_factual_v1(raw, control, selector, source_execution_commitment)
        if phase != 'dispose':
            raise ValueError('unknown exact Life cold phase')
        selector.switch(); selector.dispose()
        reader = InstalledC09StorageReaderV2(control=control, selector=selector)
        context, frames = reader.read_verified_frames_v2()
        context.require_current('recovery')
        assert frames and not control.path.exists()
        return {'phase': phase, 'pid': os.getpid(), 'frames': len(frames), 'history_digest': context.history_digest}


def _closed_file_observations_v1(control, selector, manifest):
    import stat
    paths = {control.key_path, control.lease.path, Path(str(control.path)+'.selector-v2'),
        Path(str(control.path)+'.selector-v2.journal'),
        Path(str(control.path)+'.selector-v2.pending'),
        Path(selector.current()['candidate_path'])}
    for base in [control.path, *(Path(m['resolved_path']) for m in manifest['members'])]:
        paths.update(Path(str(base)+suffix) for suffix in ('', '-wal', '-shm', '-journal'))
    result = {}
    for path in sorted(paths):
        if not os.path.lexists(path):
            result[str(path)] = None
            continue
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('closed factual file must be a single regular inode')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        after = path.lstat()
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
                  'st_mode', 'st_uid', 'st_gid', 'st_nlink')
        if tuple(getattr(before, name) for name in fields) != tuple(getattr(after, name) for name in fields):
            raise ValueError('factual file changed while observed')
        result[str(path)] = dict(device=before.st_dev, inode=before.st_ino, size=before.st_size,
            mtime_ns=before.st_mtime_ns, ctime_ns=before.st_ctime_ns, mode=before.st_mode,
            uid=before.st_uid, gid=before.st_gid, links=before.st_nlink, sha256=digest)
    return result


def _record_factual_observation_v1(control, phase, observations, previous=None):
    """Persist only safe stat/hash summaries, before checking each transition."""
    directory = control.key_path.parent / 'factual-file-observation-evidence'
    directory.mkdir(exist_ok=True)
    with (directory / (phase + '.json')).open('x') as stream:
        json.dump(dict(phase=phase, files=observations), stream, sort_keys=True, indent=2)
        stream.write('\n')
    if previous is None:
        return
    changes = []
    for path in sorted(set(previous) | set(observations)):
        left, right = previous.get(path), observations.get(path)
        if left != right:
            fields = ['existence'] if left is None or right is None else [
                name for name in left if left[name] != right[name]]
            changes.append(dict(path=path, changed_fields=fields, before=left, after=right))
    report = dict(phase=phase, changes=changes)
    with (directory / (phase + '-diff.json')).open('x') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    assert not changes, json.dumps(report, sort_keys=True)


def _assert_moved_model_census_v1(core, namespace, models):
    """Inspect actual immutable Core originals within the existing factual read."""
    from sylanne3.authority_service.c09_model_budget_original_v1 import (
        TABLE, MODEL_COLUMNS, validate_c09_model_budget_row_v1, validate_model_core_row_v1,
    )
    from sylanne3.authority_service.model_capacity_v1 import (
        install_model_capacity_functions_v1, model_capacity_census_locked_v1,
    )
    from sylanne3.authority_service.erasure_recovery_pin_v4 import read_execution_recovery_facts_pin_v4_locked
    from sylanne3.runtime_contracts import canonical_digest
    assert models, 'completed Life must retain nonempty authenticated model facts'
    with core._tx() as db:
        assert db.execute('PRAGMA query_only').fetchone() == (1,)
        changes = db.total_changes
        install_model_capacity_functions_v1(db)  # Connection-local UDFs; no schema write.
        census = model_capacity_census_locked_v1(db, namespace)
        original_columns = tuple(row[1] for row in db.execute('PRAGMA table_info(' + TABLE + ')'))
        for evidence in models:
            call = evidence.fact.execution_id
            originals = db.execute('SELECT * FROM ' + TABLE +
                ' WHERE namespace=? AND call_id=?', (namespace, call)).fetchall()
            assert len(originals) == 1, 'one real frozen model original required'
            original = validate_c09_model_budget_row_v1(original_columns, originals[0])
            assert original.provider_state == 'observed'
            assert original.observation_digest_or_none and original.terminal_digest_or_none
            assert (original.original_digest, original.request_digest, original.model_operation_id) == (
                evidence.fact.signature_commitment, evidence.fact.input_commitment,
                evidence.binding.business_operation_id)
            ledger = db.execute('SELECT * FROM authority_model_egress_v1 WHERE call_id=?',
                (call,)).fetchone()
            assert ledger is not None, 'nonempty passive model ledger must survive actual rebase'
            assert validate_model_core_row_v1('authority_model_egress_v1',
                MODEL_COLUMNS['authority_model_egress_v1'], ledger) == call
            assert (ledger[1], ledger[2], ledger[5], ledger[6]) == (
                original.model_operation_id, namespace, 'observed', original.observation_digest_or_none)
            assert json.loads(ledger[4])['request_digest'] == original.request_digest
            assert canonical_digest(('authority_model_egress_v1',
                MODEL_COLUMNS['authority_model_egress_v1'], ledger)) in original.source_row_commitments
            admission = db.execute('SELECT * FROM authority_model_admissions_v2 WHERE call_id=?',
                (call,)).fetchone()
            assert admission is not None and admission[4] is not None
            assert validate_model_core_row_v1('authority_model_admissions_v2',
                MODEL_COLUMNS['authority_model_admissions_v2'], admission) == call
            assert canonical_digest(json.loads(admission[4])) == original.terminal_digest_or_none
            assert db.execute('SELECT 1 FROM authority_v2_fences WHERE operation_id=?',
                (original.model_operation_id,)).fetchone() is None
            consumed = dict((row[0], row[1:]) for row in db.execute(
                "SELECT kind,item_id,operation_id,original_commitment,facts_pin_digest "
                "FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND "
                "((kind='model_call' AND item_id=?) OR "
                "(kind IN ('model_operation','fence') AND item_id=?))",
                (namespace, call, original.model_operation_id)))
            assert set(consumed) == {'model_call', 'model_operation', 'fence'}
            assert consumed['model_call'][:3] == (
                call, original.model_operation_id, original.original_digest)
            assert consumed['model_operation'][:3] == (
                original.model_operation_id, original.model_operation_id, original.original_digest)
            assert consumed['fence'][:2] == (original.model_operation_id, original.model_operation_id)
            pin = read_execution_recovery_facts_pin_v4_locked(
                db, namespace, operation_id=original.operation_id)
            assert pin is not None and {row[3] for row in consumed.values()} == {pin.pin_digest}
            # This original contributes no charge. Other actual unresolved
            # calls retain their counts; the fixture does not assert global zero.
            assert model_capacity_census_locked_v1(db, namespace,
                exclude=(namespace, call, original.model_operation_id,
                         original.request_digest)) == census
        assert db.total_changes == changes == 0
    return {'verified_moved_terminals': len(models), 'census': census}


def _read_actual_factual_v1(raw, control, selector, source_execution_commitment):
    from dataclasses import replace
    from sylanne3.authority_service.core import AuthorityFactualReadCoreV2
    from sylanne3.authority_service.mtls_server import MtlsPeerCredential
    from sylanne3.authority_service.contract import AuthorityUnavailable
    from sylanne3.authority_service.c09_sanitized_history_v2 import (
        InstalledC09StorageReaderV2, read_sanitized_history_v2)
    # Authenticate the signed JSON without opening any selected SQLite file.
    history = read_sanitized_history_v2(control, selector.current()['candidate_path'])
    before = _closed_file_observations_v1(control, selector, history['current_manifest'])
    _record_factual_observation_v1(control, 'before', before)
    reader = InstalledC09StorageReaderV2(control=control, selector=selector)
    peer = MtlsPeerCredential(raw['peer_certificate'])
    def authorize(credential, action, namespace, holder):
        return (credential == peer and action in _ACTIONS
            and namespace == raw['authority_namespace'] and holder in {None, raw['holder']})
    core = None
    previous = before
    opened_recorded = False
    read_started = False
    try:
        context, frames = reader.read_verified_frames_v2()
        executions = {item.execution_id for _, facts, _ in frames for item in facts.executions}
        assert executions, 'actual Life fixture must retain nonempty execution facts'
        assert type(source_execution_commitment) is str and any(
            hashlib.sha256(value.encode()).hexdigest() == source_execution_commitment for value in executions), \
            'authenticated Life donor execution absent from sanitized facts'
        core = AuthorityFactualReadCoreV2(reader=reader, authorizer=authorize)
        opened = _closed_file_observations_v1(control, selector, history['current_manifest'])
        opened_recorded = True
        _record_factual_observation_v1(control, 'open', opened, previous)
        previous = opened
        read_started = True
        model_evidence = []
        for execution_id in sorted(executions):
            evidence = core.read_current_sanitized_execution_v2(credential=peer,
                namespace=raw['authority_namespace'], execution_id=execution_id)
            assert evidence is not None and evidence.fact.execution_id == execution_id
            assert evidence.history_digest == context.history_digest
            reader.require_execution_evidence_v2(evidence)
            if evidence.binding.execution_kind == 'model':
                model_evidence.append(evidence)
            try:
                reader.require_execution_evidence_v2(replace(evidence))
            except AuthorityUnavailable:
                pass
            else:
                raise AssertionError('copied factual DTO acquired evidence authority')
        model_capacity = _assert_moved_model_census_v1(
            core, raw['authority_namespace'], model_evidence)
        try:
            core.read_current_sanitized_execution_v2(credential=object(),
                namespace=raw['authority_namespace'], execution_id=next(iter(executions)))
        except AuthorityUnavailable:
            pass
        else:
            raise AssertionError('uninstalled credential read factual evidence')
        for action in ('business', 'accounting'):
            try:
                context.require_current(action)
            except AuthorityUnavailable:
                pass
            else:
                raise AssertionError('factual context admitted business/accounting')
    finally:
        try:
            try:
                if not opened_recorded:
                    opened = _closed_file_observations_v1(control, selector, history['current_manifest'])
                    _record_factual_observation_v1(control, 'open', opened, previous)
                    previous = opened
                if read_started:
                    read = _closed_file_observations_v1(control, selector, history['current_manifest'])
                    _record_factual_observation_v1(control, 'read', read, previous)
                    previous = read
            finally:
                if core is not None:
                    core.close()
        finally:
            closed = _closed_file_observations_v1(control, selector, history['current_manifest'])
            _record_factual_observation_v1(control, 'close', closed, previous)
    assert not control.path.exists()
    return {'phase': 'factual', 'pid': os.getpid(), 'execution_count': len(executions),
        'history_digest': context.history_digest, 'files_unchanged': len(before),
        'model_capacity': model_capacity}


async def run_life_current_cold_phase_v3(path,phase,*,expected_fixture_digest,operation_id,source_execution_id):
    """Each call is a fresh real process with the original installed config."""
    import asyncio
    from sylanne3.authority_service.daemon import open_authority_daemon
    from sylanne3.authority_service.c09_process_identity_v1 import require_process_retired_v1
    from sylanne3.authority_service.c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
    from sylanne3.authority_service.c09_prepared_storage_v3 import VerifiedSegmentedRoleOriginalV3,_read_original
    from sylanne3.authority_service.c09_paged_recovery_facts_v2 import _decode_completion
    from sylanne3.authority_service.c09_close_apply_v1 import SelectedAppliedReadV3
    from sylanne3.runtime.c09_storage_rebase_contract_v1 import SanitizedExecutionFactV4
    with open_life_cold_fixture_v1(path,expected_fixture_digest=expected_fixture_digest,current_only=True) as (raw,control):
        assert raw['schema']==CURRENT_SCHEMA_V3
        retired=require_process_retired_v1(raw['initial_process'])
        assert retired['state']=='retired' and raw['initial_process']['pid']!=os.getpid()
        cfg,cache=current_life_deployment_from_original_v3(raw)
    bootstrap=open_authority_daemon(cfg)
    actor=None
    try:
        if phase=='cold_current_v3':
            daemon=await bootstrap.await_business_ready_v3()
        else:
            daemon=await bootstrap.await_offline_ready_v3()
        m=daemon.c09_maintenance;control=daemon.c09_control
        assert m.control is control and m._installed_deployment_config_v2 is daemon.config
        assert daemon.config.c09_maintenance_factory.provider_cache_cleanup.provider_id==cache.provider_id
        quanta=0;stages=[]
        def advance():
            nonlocal quanta
            progress=m.advance_storage_maintenance_current_thread_v3(operation_id=operation_id)
            quanta+=1
            if not stages or stages[-1]!=progress['phase']:stages.append(progress['phase'])
            if progress['status']=='failed':
                raise RuntimeError('first C09 maintenance failure: '+json.dumps(progress,sort_keys=True))
            return progress
        if phase=='prepare_switch_current_v3':
            actor=m.bind_current_thread_actor_v3(operation_id=operation_id)
            while True:
                prepared_progress=advance()
                if prepared_progress['status']=='complete':break
                await asyncio.sleep(0)
            assert prepared_progress['phase']=='PREPARED'
            prepared=actor.result
            control.verify_original_v1(prepared,'prepared_digest')
            assert prepared['schema']=='sylanne3.c09.storage_prepared_original.v3' and prepared['operation_id']==operation_id
            assert set(prepared['segmented_role_complete_original_digests'])=={'core','deletion','execution','graph'}
            assert set(prepared['four_role_complete_original_digests'])=={'core','deletion','execution','graph'}
            assert prepared['graph_issue_original_digest'] and prepared['graph_mirror_original_digest']
            with control._resource_sql_quantum_v3() as meter:
                with control._db() as db:
                    completion=_decode_completion(_read_original(control,db,operation_id,'capture_facts_complete_v2',
                        prepared['facts_complete_original_digest'],meter))
            assert completion.pin_digest==prepared['facts_pin_digest']
            assert completion.executions.complete.record_count>0 and completion.model_stream.complete.record_count>0
            assert completion.graph_facts.complete.record_count>0 and completion.d11_facts.complete.record_count>0
            actor.close_current_thread_v3();actor=None
            while True:
                switched=advance()
                if switched['status']=='complete':break
                await asyncio.sleep(0)
            assert switched['phase']=='SWITCHED' and switched['restart_required'] is True
            return dict(phase=phase,pid=os.getpid(),operation_id=operation_id,prepared_digest=prepared['prepared_digest'],
                facts_pin_digest=prepared['facts_pin_digest'],graph_issue_original_digest=prepared['graph_issue_original_digest'],
                graph_mirror_original_digest=prepared['graph_mirror_original_digest'],
                segmented_roles=prepared['segmented_role_complete_original_digests'],
                execution_count=completion.executions.complete.record_count,model_count=completion.model_stream.complete.record_count,
                quanta=quanta,observed_phases=stages,restart_required=True)
        view=control._selected_history_read_v3
        assert type(view) is VerifiedSelectedHistoryReadV3 and len(view.verified_roles)==4
        assert {item.role for item in view.verified_roles}=={'core','deletion','execution','graph'}
        assert all(type(item) is VerifiedSegmentedRoleOriginalV3 and len(item.child_original_digests)==4 for item in view.verified_roles)
        assert view.history_count>0 and view.family_eof['executions']['record_count']>0 and view.family_eof['model']['record_count']>0
        assert view.basis.prepared['operation_id']==operation_id
        if phase=='release_current_v3':
            actor=m.bind_current_thread_actor_v3(operation_id=operation_id)
            while True:
                released=advance()
                if released['status']=='complete':break
                await asyncio.sleep(0)
            assert released['phase']=='RELEASED' and released['restart_required'] is False
            actor.close_current_thread_v3();actor=None
            while True:
                applied=control.advance_selected_storage_applied_read_v3()
                if type(applied) is SelectedAppliedReadV3:break
                await asyncio.sleep(0)
        else:
            assert phase=='cold_current_v3'
            assert type(control._selected_applied_read_v3) is SelectedAppliedReadV3
        current=control.read_verified_current_storage_v3()
        current.require_current('business')
        assert current.stage=='RELEASED' and current.prepared_original['operation_id']==operation_id
        def file_stamps():
            return {item['role']:(lambda stat:(stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns))(Path(item['resolved_path']).stat())
                for item in current.manifest['members']}
        before=file_stamps()
        with control._resource_sql_quantum_v3() as meter:
            fact=view.lookup_execution(source_execution_id,meter=meter)
            assert meter.written_bytes==meter.sql_mutations==0
            factual_meter_bytes=meter.consumed_bytes
        assert file_stamps()==before
        assert type(fact) is SanitizedExecutionFactV4 and fact.execution_id==source_execution_id
        assert fact.status=='completed' and fact.consumed and fact.result_commitment and fact.terminal_commitment and fact.signature_commitment
        return dict(phase=phase,pid=os.getpid(),operation_id=operation_id,stage=current.stage,
            prepared_digest=current.prepared_original['prepared_digest'],manifest_digest=current.manifest_digest,
            pointer_version=current.pointer_version,storage_generation=current.storage_generation,
            history_count=view.history_count,selected_roles={item.role:item.original_digest for item in view.verified_roles},
            family_eof=view.family_eof,source_execution_commitment=hashlib.sha256(source_execution_id.encode()).hexdigest(),
            terminal_commitment=fact.terminal_commitment,quanta=quanta,observed_phases=stages,
            factual_meter_bytes=factual_meter_bytes,exact_selected_files_unchanged=True,
            provider_cache_request_count=cache.recorded_request_count())
    finally:
        if actor is not None:actor.close_current_thread_v3()
        await bootstrap.aclose()
