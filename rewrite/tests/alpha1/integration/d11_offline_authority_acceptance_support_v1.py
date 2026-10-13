"""Actual initial four-store D11 service and current Host admission composition.

The fixture uses the existing real Owner/TLS/CPU/initial C09 stores. Local
installation provisioning is controlled here; no boundary, permit, paid fact,
prepared row, source, claim or terminal is inserted as acceptance evidence.
"""
from dataclasses import replace
import hashlib
import hmac
import json
import os
from pathlib import Path
from dataclasses import dataclass
import sqlite3
import tempfile
from types import SimpleNamespace
import time

from sylanne3.authority_service.c09_graph_application_v1 import InstalledC09GraphApplicationV1
from sylanne3.authority_service.c09_close_apply_v1 import InstalledC09CloseApplyV1
from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1
from sylanne3.authority_service.c09_storage_maintenance_v1 import InstalledC09WriterGateV1
from sylanne3.authority_service.d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
from sylanne3.authority_service.d11_offline_tick_service_v1 import AuthorityD11OfflineTickServiceV1
from sylanne3.authority_service.v2_deletion_recovery_service import AuthorityV2DeletionPendingRecovery
from sylanne3.authority_service.v2_scoped_erasure_store import AuthorityV2ScopedErasureStore
from sylanne3.host.c09_storage_admission_v1 import InstalledHostStorageAdmissionV1


@dataclass
class FreshOfflineStorageCaseV1:
    storage_control: object
    lease: object
    protected_directory: object
    deployment_config: object = None
    maintenance_factory: object = None
    provider_cache: object = None
    body_authority: object = None

    def close(self):
        self.lease.close()
        self.protected_directory.cleanup()


@dataclass
class OuterOwnedProtectedRootV1:
    """Test supervisor owns this new directory beyond the Authority process."""
    name: str

    def cleanup(self):
        # The outer permanent acceptance owns deletion after all cold phases.
        pass


def install_fresh_offline_storage_case_v1(*, core, protected, execution, graph_store,
        root, server_kwargs, peer, namespace, authority_namespace, registry, protected_root=None,
        initial_m1_configuration=None, current_initial_assets=None):
    """Use the installer genesis and actual initial four-file selection.

    All migrations have run before Owner login or business writes. The later
    numeric/root installation shares this selection instead of replacing it.
    """
    from sylanne3.authority_service.c09_storage_control_v1 import C09StorageControlV1, InstalledC09InstanceLeaseV1
    from sylanne3.authority_service.installer_genesis_v1 import (
        record_installer_genesis_original_v1, install_first_graph_provision_composition_v1,
    )
    from sylanne3.authority_service.linux_bootstrap_v1 import build_initial_inventory_v1, bootstrap_current_storage_v1
    root_assets=None
    if current_initial_assets is not None:
        from sylanne3.authority_service.linux_installation_security_v1 import read_installed_bytes_v1
        from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
        if type(initial_m1_configuration) is not M1PhaseFixtureInstallationV2 or initial_m1_configuration.c09_installation_assets is None:
            raise ValueError('current C09 requires its actual Root-prepared protected installation assets')
        root_assets=json.loads(read_installed_bytes_v1(initial_m1_configuration.c09_installation_assets,
            limit=16384,private=True,allowed_gid=os.getegid()))
        fields={'schema','authority_id','installation_id','control_store_id','key_id','namespace','sdk_peer_descriptor',
            'manifest_digest','inventory_manifest_digest','control_path','key_path','instance_lock'}
        if set(root_assets)!=fields or root_assets['schema']!='sylanne3.c09.controlled-sdk-installation-assets.v3':
            raise ValueError('exact Root-prepared current C09 installation asset inventory required')
        if (Path(root).resolve()!=initial_m1_configuration.data_dir.resolve() or root_assets['namespace']!=authority_namespace
                or root_assets['sdk_peer_descriptor']!=[peer.certificate_sha256,'reply']):
            raise ValueError('actual current C09 data root/Namespace/peer changed from Root installation')
        protected_directory=OuterOwnedProtectedRootV1(str(Path(root_assets['control_path']).parent))
        lease_path=Path(root_assets['instance_lock'])
    else:
        if protected_root is None:
            protected_directory = tempfile.TemporaryDirectory(prefix="sylanne-offline-current-control-")
        else:
            path = Path(protected_root)
            if not path.is_absolute() or path.is_symlink() or (path.exists() and any(path.iterdir())):
                raise ValueError("outer C09 protected fixture root must be new and empty")
            path.mkdir(parents=True, exist_ok=True)
            protected_directory = OuterOwnedProtectedRootV1(str(path))
        lease_path=Path(protected_directory.name)/"instance.lock"
    protected_root = Path(protected_directory.name)
    lease = InstalledC09InstanceLeaseV1(lease_path)
    try:
        key = protected_root / "control.key" if root_assets is None else Path(root_assets['key_path'])
        if root_assets is None:key.write_bytes(os.urandom(32))
        else:
            if len(read_installed_bytes_v1(key,limit=33,private=True,allowed_gid=os.getegid()))!=32:
                raise ValueError('actual preinstalled C09 Control key changed')
        with graph_store._lock:
            graph_files = tuple(row[2] for row in graph_store._db.execute("PRAGMA database_list") if row[1] == "main")
        if len(graph_files) != 1 or not graph_files[0]:
            raise ValueError("offline installation requires the actual main Graph database file")
        graph_file = Path(graph_files[0]).resolve(strict=True)
        files = {"core": Path(core.path).resolve(), "deletion": Path(protected.deletion.path).resolve(),
            "execution": Path(execution.path).resolve(), "graph": graph_file}
        installation_peer = (peer.certificate_sha256, "reply")
        installation = server_kwargs["installations_v2"][installation_peer]
        config=None
        if current_initial_assets is None:
            config = SimpleNamespace(instance_lock=lease.path, authority_db=files["core"], deletion_db=files["deletion"],
                graph_db=files["graph"], execution_journals={authority_namespace: SimpleNamespace(path=files["execution"])},
                installations_v2={installation_peer: installation},
                namespace_bindings_v2={(*installation_peer, namespace): authority_namespace})
        authority_id = core._db.execute("SELECT value FROM authority_meta WHERE key='authority_id'").fetchone()[0]
        if root_assets is not None and (root_assets['authority_id']!=authority_id
                or root_assets['installation_id']!=installation.installation_id or root_assets['manifest_digest']!=installation.manifest_digest):
            raise ValueError('actual initial installation differs from Root-prepared C09 assets')
        control = C09StorageControlV1(control_path=protected_root / "control.db" if root_assets is None else Path(root_assets['control_path']), key_path=key,
            installation_id=installation.installation_id, authority_id=authority_id,
            control_store_id="offline-acceptance-control" if root_assets is None else root_assets['control_store_id'],
            key_id="offline-acceptance-key" if root_assets is None else root_assets['key_id'],lease=lease,
            resource_roots=(Path(root).resolve(),))
        managed = root / "offline-managed-artifacts"
        if root_assets is None:managed.mkdir()
        elif not managed.is_dir() or managed.is_symlink():raise ValueError('actual Root-prepared managed directory is absent')
        directories = {name: managed / name for name in ("controlled_backup", "export", "rebuild_temp", "cache")}
        for directory in directories.values():
            if root_assets is None:directory.mkdir()
            elif not directory.is_dir() or directory.is_symlink():raise ValueError('actual Root-prepared resource directory is absent')
        with protected.deletion._lock, execution._lock, core._lock, graph_store._lock:
            if current_initial_assets is None:
                record_installer_genesis_original_v1(core=core, config=config, registry=registry,
                    instance_lease=lease, files=files)
            with protected.deletion.freeze_writes():
                deletion_head = protected.deletion.verified_head()
            for path in files.values():
                with sqlite3.connect(path) as db:
                    assert db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
            inventory = build_initial_inventory_v1(authority_id=authority_id, installation_id=installation.installation_id,
                namespace=authority_namespace, files=files, directories=directories)
            if initial_m1_configuration is not None:
                from m1_artifact_draft_acceptance_support_v1 import M1InitialInstallationFixtureV1
                from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
                from sylanne3.runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2
                from sylanne3.runtime_contracts import canonical_digest
                assert type(initial_m1_configuration) in {M1InitialInstallationFixtureV1, M1PhaseFixtureInstallationV2}
                scope = initial_m1_configuration.artifact_draft.tool_scope
                exports = tuple(resource for resource in inventory.resources
                    if resource.resource_id == scope.resource_id and resource.kind == "export")
                assert len(exports) == 1 and Path(exports[0].path) == directories["export"].resolve(strict=True)
                assert not (Path(exports[0].path) / scope.filename).exists()
                resources = tuple(replace(resource,
                    content_coverage=tuple(sorted({*resource.content_coverage, "jobs_drafts", "imports_exports"})))
                    if resource is exports[0] else resource for resource in inventory.resources)
                inventory = InstallationFilesystemManifestV2(inventory.authority_id, inventory.installation_id,
                    inventory.namespace, resources, canonical_digest((inventory.schema, inventory.authority_id,
                        inventory.installation_id, inventory.namespace, resources)))
            if root_assets is not None and inventory.manifest_digest!=root_assets['inventory_manifest_digest']:
                raise ValueError('actual four-role resource inventory differs from the Root-prepared canonical inventory')
            current_components=(None,None,None,None)
            if current_initial_assets is not None:
                current_components=_initial_current_life_deployment_v3(core=core,protected=protected,execution=execution,
                    registry=registry,server_kwargs=server_kwargs,peer=peer,namespace=namespace,authority_namespace=authority_namespace,
                    files=files,control=control,inventory=inventory,directories=directories,initial=initial_m1_configuration,assets=current_initial_assets)
                config=current_components[0]
                record_installer_genesis_original_v1(core=core,config=config,registry=registry,instance_lease=lease,files=files)
                for path in files.values():
                    with sqlite3.connect(path) as db:
                        assert db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]==0
            bootstrap_current_storage_v1(control=control, files=files, inventory=inventory,
                identities={"core": authority_id, "deletion": deletion_head.journal_id,
                    "execution": execution.journal_id, "graph": "unprovisioned"})
        core.install_current_c09_storage_reader_v1(reader=control)
        install_first_graph_provision_composition_v1(protected, config, registry)
        return FreshOfflineStorageCaseV1(control,lease,protected_directory,
            deployment_config=current_components[0],maintenance_factory=current_components[1],
            provider_cache=current_components[2],body_authority=current_components[3])
    except BaseException:
        lease.close()
        protected_directory.cleanup()
        raise


def current_life_fixture_policy_v3(peer,admin_peer,authority_namespace,installation_id):
    """The same finite installed policy supplies initial and cold current config."""
    def authorize(candidate,action,selected,holder):
        if action in {'deletion','delete','erasure_closure_install','execution_redaction_install'}:
            return candidate==peer and selected==authority_namespace and holder in {None,'host:reply'}
        if action=='migrate_deletion':return candidate==peer and selected==authority_namespace
        if action=='owner_pair':return candidate in {peer,admin_peer} and selected==authority_namespace
        if action in {'owner_identity_pair','owner_identity_revoke','self_identity_mutate'}:
            return candidate==admin_peer and selected==authority_namespace
        if action in {'owner_claim','owner_session'}:return candidate==peer and selected==authority_namespace
        if action=='current' and candidate==admin_peer:return selected==authority_namespace
        return (candidate==peer and selected in {authority_namespace,'ns:bootstrap'}
            and action in {'install','seal_v2_only','namespace_genesis','current','read','write','dispatch',
                'execution','owner_guard_read','self_identity_read','model_egress','accounting','owner_authorization_revoke'}
            and holder in {None,'host:reply'})
    def administrator(candidate,action,selected,holder):
        return ((candidate in {peer,admin_peer} and action=='pair' and selected=='authority:enrollment')
            or (candidate==admin_peer and action=='self_identity_mutate' and selected==authority_namespace
                and holder==installation_id))
    def credential(action,selected):
        if selected!=authority_namespace:raise ValueError('installed current credential crossed Namespace')
        return peer
    return authorize,administrator,credential


def _initial_current_life_deployment_v3(*,core,protected,execution,registry,server_kwargs,peer,namespace,
        authority_namespace,files,control,inventory,directories,initial,assets):
    """Official initial config and assets, before the first business call."""
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    from sylanne3.authority_service.deployment_config import (AuthorityDeploymentConfig,ExecutionJournalInstallation,
        InstalledNaturalModelAuthorityV2,InstalledC09AuthorityV1,InstalledC04AuthorityV3)
    from sylanne3.authority_service.c09_installed_factory_v1 import InstalledC09MaintenanceFactoryV1
    from sylanne3.authority_service.installed_core_verifiers import installed_core_verifier_factory
    from sylanne3.domains.d02.body_quote_original import D02BodyQuoteAuthority
    from c09_life_provider_cache_acceptance_v1 import ControlledLifeProviderCacheV1
    if type(initial) is not M1PhaseFixtureInstallationV2 or initial.data_dir.resolve()!=Path(assets['data_dir']).resolve():
        raise ValueError('C09 current requires the actual protected initial phase installation')
    bundle=initial.initial_bundle;policy=bundle.installation_policy;installation_peer=(peer.certificate_sha256,'reply')
    if (policy.namespace!=namespace or policy.installation_id!=control.installation_id
            or policy.manifest_digest!=server_kwargs['installations_v2'][installation_peer].manifest_digest
            or bundle.model_workflows is not initial.workflows
            or assets['d11_issuer'].resource_issuer is not assets['d02_issuer']):
        raise ValueError('C09 current initial bundle/issuer/Namespace installation changed')
    body=D02BodyQuoteAuthority(hmac.digest(bundle.d02_signing_key,
        b'sylanne3.d02.body_quote_original.v1\0'+policy.installation_id.encode(),'sha256'))
    graph_parent=files['graph'].parent
    cache=ControlledLifeProviderCacheV1(graph_parent.parent/(graph_parent.name+'-c09-provider-cache'),assets['provider_configuration'],phase_config=initial)
    cache.bind(authority_id=control.authority_id,installation_id=control.installation_id,namespace=authority_namespace)
    factory=InstalledC09MaintenanceFactoryV1(namespace=namespace,peer=installation_peer,registry=registry,
        resource_issuer=assets['d02_issuer'],body_authority=body,inventory_manifest=inventory,
        target_directory=directories['rebuild_temp'],provider_cache_cleanup=cache.installed_disposition(),
        budget_job_issuer=assets['d11_issuer'])
    from sylanne3.authority_service.mtls_server import MtlsPeerCredential
    admin_installations=[entry for entry,value in server_kwargs['installations_v2'].items()
        if value.installation_id=='installation-admin']
    assert len(admin_installations)==1
    core_authorizer,administrator_authorizer,local_credential=current_life_fixture_policy_v3(
        peer,MtlsPeerCredential(admin_installations[0][0]),authority_namespace,policy.installation_id)
    if initial.c04_component_key is None:
        raise ValueError('C09 current requires its actual Root-prepared component key')
    component_key=initial.c04_component_key
    config=AuthorityDeploymentConfig(authority_db=files['core'],deletion_db=files['deletion'],graph_db=files['graph'],
        instance_lock=control.lease.path,execution_journals={authority_namespace:ExecutionJournalInstallation(files['execution'],execution.journal_id)},
        tls=assets['tls'],bind_host='127.0.0.1',bind_port=bundle.tls_profile.port,
        installations_v2=server_kwargs['installations_v2'],namespace_bindings_v2=server_kwargs['namespace_bindings_v2'],
        reverse_handoff_profiles={authority_namespace:assets['reverse_profile']},
        reverse_handoff_issuers=server_kwargs['v2_final_handoff_issuers'],core_authorizer=core_authorizer,
        core_verifier_factory=installed_core_verifier_factory,administrator_authorizer=administrator_authorizer,
        publisher_manifest_verifier=server_kwargs['publisher_manifest_verifier'],utc_clock=server_kwargs['utc_clock'],
        local_administrator_credential=local_credential,
        natural_model_authorities_v2={authority_namespace:InstalledNaturalModelAuthorityV2(assets['d11_issuer'],initial.workflows,installation_peer,bundle)},
        clock_provider=server_kwargs['clock_provider'],self_identity_readers_v2=server_kwargs['self_identity_readers_v2'],
        worker_result_fact_committers_v2=server_kwargs['worker_result_fact_committers_v2'],
        host_onebot_observations_v2=server_kwargs['host_onebot_observations_v2'],
        c04_installations_v3={authority_namespace:InstalledC04AuthorityV3(initial.package_root,policy.manifest_digest,component_key)},
        d13_counter_assets_v1=assets.get('d13_counter_assets'),
        c09_storage_v1=InstalledC09AuthorityV1(control.path,control.key_path,control.installation_id,control.authority_id,
            control.control_store_id,control.key_id,control._roots),c09_maintenance_factory=factory)
    return config,factory,cache,body


def install_actual_offline_authority_case_v1(case, *, register_host_process=True):
    graph, store, core, server = case["graph"], case["store"], case["core"], case["server"]
    authority_namespace = case["authority_namespace"]
    selected = graph._actual_d04_authority_acceptance_v3
    control = selected.storage_control
    fence_service = server._v2_fences[authority_namespace]
    bridge = server._v2_execution[authority_namespace]
    assert bridge.core is core and fence_service.core is core
    context = control.read_verified_current_storage_v1()
    context.require_current("business")
    assert context.stage != "RELEASED", "this fixture is actual initial selection, not a C09 rebase"
    graph_path = Path(store._db.execute("PRAGMA database_list").fetchone()[2]).resolve()
    assert graph_path == Path(next(member["resolved_path"] for member in context.manifest["members"] if member["role"] == "graph"))
    daemon=case.get('c09_daemon')
    if daemon is not None:
        assert daemon.core is core and daemon.server is server and daemon.c09_control is control
        gate=daemon.c09_gate;maintenance=daemon.c09_maintenance
        assert gate.control is control and maintenance.control is control
        service=server._d11_offline_tick_services_v1[authority_namespace]
        assert service.bridge is bridge
        admission=None
        if register_host_process:
            process=read_process_identity_v1(os.getpid());assert process is not None
            writer_original=gate.register_peer_process_v1(
                peer=(case['peer'].certificate_sha256,case['installed_bundle'].tls_profile.profile_id),
                process_id=os.getpid(),process_incarnation='current-c09-business:'+process['birth'],
                pointer_version=context.pointer_version,storage_generation=context.storage_generation)
            control.verify_original_v1(writer_original,'admission_digest')
            assert writer_original['schema']=='sylanne3.c09.writer-peer-admission.v3'
            assert writer_original['peer']==[case['peer'].certificate_sha256,case['installed_bundle'].tls_profile.profile_id]
            assert writer_original['process_original']==writer_original['authority_process_original']==process
            assert writer_original['namespace']==case['authority_namespace']
            assert writer_original['installation_id']==daemon.config.installations_v2[tuple(writer_original['peer'])].installation_id
            assert writer_original['authority_id']==control.authority_id
            assert (writer_original['manifest_digest'],writer_original['pointer_version'],writer_original['storage_generation'])==(
                context.manifest_digest,context.pointer_version,context.storage_generation)
            case['c09_writer_admission_original']=writer_original
            admission=InstalledHostStorageAdmissionV1(control.installation_id,control.authority_id,
                context.pointer_version,context.storage_generation,context.manifest_digest,graph_path,process)
            admission.require_current_process_v1()
        case.update(c09_writer_gate=gate,c09_authority_graph_store=maintenance.graph,
            c09_maintenance_factory=daemon.config.c09_maintenance_factory,c09_deployment_config=daemon.config,
            c09_provider_cache=graph._initial_offline_storage_case_v1.provider_cache)
        return service,service.owner_service,admission
    scoped = AuthorityV2ScopedErasureStore(core=core, fences=fence_service.fences,
        deletion=bridge.deletion, execution=bridge.journal, namespace=authority_namespace)
    recovery = AuthorityV2DeletionPendingRecovery(core=core, fences=fence_service.fences,
        deletion=bridge.deletion, execution=bridge.journal, namespace=authority_namespace, scoped_store=scoped)
    subject = "mtls:sha256:" + case["peer"].certificate_sha256
    application_graph, application_bootstrap = graph, case["bootstrap"]
    if not register_host_process:
        from sylanne3.graph_store import ProductionGraphStore
        from sylanne3.graph_coordinator import GraphCoordinator
        from sylanne3.authority_service.c09_installed_factory_v1 import _LocalInstalledFencePortV1
        authority_store = ProductionGraphStore(graph_path, case["domain_registry"].type_registry)
        application_bootstrap = object()
        application_graph = GraphCoordinator(authority_store, application_bootstrap,
            holder=case["policy"].administrator_holder,
            content_fence_v2=_LocalInstalledFencePortV1(fence_service, case["peer"], subject, case["namespace"]),
            d02_issuer=case["d02_issuer"], d11_issuer=case["d11_issuer"])
        case["c09_authority_graph"] = application_graph
        case["c09_authority_store"] = authority_store
        case["c09_authority_graph_store"] = authority_store
    application = InstalledC09GraphApplicationV1(control=control, core=core, scoped=scoped,
        coordinator=application_graph, bootstrap=application_bootstrap, namespace=case["namespace"], subject=subject, credential=case["peer"])
    close_apply = InstalledC09CloseApplyV1(control=control, service=fence_service, recovery=recovery,
        graph_application=application, subject=subject, credential=case["peer"])
    control.install_applied_reader_v1(close_apply)
    owner_service = InstalledD12OwnerStorageAdmissionServiceV1(fences=fence_service, owner_tickets=server._v2_owner_tickets,
        graph_db_path=graph_path, namespace_id=case["namespace"], installation_id=case["policy"].installation_id,
        holder=case["policy"].administrator_holder, control=control, close_apply=close_apply)
    bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    service = AuthorityD11OfflineTickServiceV1(bridge=bridge, owner_tickets=server._v2_owner_tickets,
        namespace=case["namespace"], installation_id=case["policy"].installation_id,
        manifest_digest=case["manifest_digest"], graph_db_path=graph_path, issuer=case["d11_issuer"],
        resource_issuer=case["d02_issuer"], credential=case["peer"],
        signing_key=hmac.new(bundle.d11_signing_key, b"sylanne.authority.d11-offline-signing.v1", hashlib.sha256).digest(),
        trusted_now_utc=time.time, owner_service=owner_service)
    # Keep the real RPC/service gates while exposing the underlying error in
    # this permanent acceptance's log; transport deliberately sanitizes it.
    import functools
    import traceback
    def diagnosed(method):
        @functools.wraps(method)
        def call(*args, **kwargs):
            try:
                return method(*args, **kwargs)
            except Exception:
                traceback.print_exc()
                raise
        return call
    for method in ("execute_d11_offline_tick_v1", "read_d11_offline_tick_original_v1",
            "read_historical_d11_offline_tick_original_v1", "recover_claimed_d11_offline_tick_v1",
            "offline_adoption_bridge_v1", "offline_historical_accounting_v1", "offline_unstarted_cancellation_v1"):
        setattr(service, method, diagnosed(getattr(service, method)))
    if not hasattr(server, "_d11_offline_tick_services_v1"):
        server._d11_offline_tick_services_v1 = {}
    assert authority_namespace not in server._d11_offline_tick_services_v1
    server._d11_offline_tick_services_v1[authority_namespace] = service
    core.install_execution_redaction_d11_offline_service_v1(authority_namespace, service)
    # The supervisor boundary registers this actual live PID/birth against the
    # independently observed selected pointer and files, then gives the Host
    # those exact admitted values. It does not assert lifecycle state.
    gate = InstalledC09WriterGateV1(control=control)
    admission = None
    if register_host_process:
        process = read_process_identity_v1(os.getpid())
        assert process is not None
        gate.register_peer_process_v1(peer=(case["peer"].certificate_sha256, bundle.tls_profile.profile_id), process_id=os.getpid(),
            process_incarnation="offline-acceptance-host:" + process["birth"], pointer_version=context.pointer_version,
            storage_generation=context.storage_generation)
        admission = InstalledHostStorageAdmissionV1(case["policy"].installation_id, case["grant"].authority_id,
            context.pointer_version, context.storage_generation, context.manifest_digest, graph_path, process)
        admission.require_current_process_v1()
    case["c09_writer_gate"] = gate
    return service, owner_service, admission


def phase_fixture_recall_declaration_v1():
    """Initial finite recall selection for a new protected phase fixture."""
    from sylanne3.host.authority_profile import AdminD06RecallPolicyV1, AdminD06RecallProfileV1
    from sylanne3.runtime.c04_interpretation_policy_v3 import installed_c04_presence_policy_v3
    interpretation = installed_c04_presence_policy_v3()
    return AdminD06RecallPolicyV1(
        policy_ref="phase-fixture:recall-policy:v1", policy_version=1,
        body_policy_id="phase-fixture:c04-self-body:v4", body_policy_version=1,
        cognition_body_policy_id="phase-fixture:d07-recall-body:v1", cognition_body_policy_version=1,
        cpu_policy_id="phase-fixture:c04-self-cpu:v4", cpu_policy_version=1,
        interpretation_policy_id=interpretation.policy_id,
        interpretation_policy_version=interpretation.policy_version,
        profiles=(AdminD06RecallProfileV1("light", 1, 32, 128, 0),
                  AdminD06RecallProfileV1("normal", 3, 64, 128, 1),
                  AdminD06RecallProfileV1("deep", 4, 64, 128, 2)),
        max_search_plans=5, max_candidates_per_channel=32,
        max_ledger_pages=6, max_ledger_nodes=768, read_timeout_seconds=30.0,
        max_edges=128, max_iterations=64, max_recollection_candidates=32,
        recall_token_ceiling=2048, working_ref_ceiling=16, working_token_ceiling=4096)


def install_phase_fixture_recall_owner_policies_v1(case):
    """Register actual fixed Body and V4 CPU originals before this fixture's C1."""
    from test_current_domain_production_v1 import domain_owner
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    from sylanne3.domains.d02 import WorkComponent
    from sylanne3.domains.d02.body_quote_original import FixedBodyPolicyV1
    from sylanne3.runtime.c04_cpu_quote_policy import C04InternalCpuQuotePolicyV1, C04_INTERNAL_CPU_WORK_KIND
    from sylanne3.runtime.c04_direct_seed_v4 import ALGORITHM_ID_V4
    from sylanne3.runtime_contracts import canonical_digest

    assert type(case["m1_initial_configuration"]) is M1PhaseFixtureInstallationV2
    graph, store, namespace = case["graph"], case["store"], case["namespace"]
    bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    recall = bundle.d06_recall
    assert recall == phase_fixture_recall_declaration_v1()
    configured = bundle.artifact_draft.body_policy
    body_authority = graph._GraphCoordinator__body_quote_authority
    with store._lock:
        original_body = body_authority.policy(store._db, namespace, configured.policy_ref, configured.policy_version)
        grant = graph._GraphCoordinator__d11_issuer.current_budget_grant(
            store._db, bundle.installation_policy.root_grant.lease_id)
    assert grant == bundle.installation_policy.root_grant
    assert {"d07.cognition", C04_INTERNAL_CPU_WORK_KIND} <= set(grant.allowed_work_kinds)
    until = grant.valid_until_utc
    assert original_body.valid_until == until
    profile, initial_state = original_body.profile, original_body.initial_state
    cognition = FixedBodyPolicyV1(recall.cognition_body_policy_id, recall.cognition_body_policy_version,
        profile, initial_state, "d07.cognition", WorkComponent("phase-recall-cognition", "body-energy", .0625, 0.0), until)
    c04_body = FixedBodyPolicyV1(recall.body_policy_id, recall.body_policy_version,
        profile, initial_state, C04_INTERNAL_CPU_WORK_KIND,
        WorkComponent("phase-c04-self-cpu", "body-energy", .02, 0.0), until)
    cpu = C04InternalCpuQuotePolicyV1(recall.cpu_policy_id, recall.cpu_policy_version,
        namespace, bundle.installation_policy.installation_id, ALGORITHM_ID_V4,
        min(100, grant.max_ceiling["cpu_ms"]), until)
    with domain_owner(case) as (authority, lease):
        cognition_adoption = graph.adopt_current_fixed_body_work_policy_v1(authority, lease,
            operation_id=recall.cognition_body_policy_id + ":install", policy=cognition)
        c04_body_adoption = graph.adopt_current_fixed_body_work_policy_v1(authority, lease,
            operation_id=recall.body_policy_id + ":install", policy=c04_body)
        cpu_signature = graph.install_current_c04_cpu_quote_policy_v1(case["bootstrap"], authority, lease,
            operation_id=recall.cpu_policy_id + ":install", policy=cpu)
    with store._lock:
        db = store._db
        db.execute("BEGIN")
        try:
            assert body_authority.policy(db, namespace, cognition.policy_id, cognition.version) == cognition
            assert body_authority.policy(db, namespace, c04_body.policy_id, c04_body.version) == c04_body
            assert graph._GraphCoordinator__c04_cpu_quote_authority.read_policy(
                db, namespace, cpu.policy_id, cpu.version) == cpu
        finally:
            db.execute("ROLLBACK")
    originals = {"declaration_digest": recall.policy_digest,
        "cognition_adoption": cognition_adoption, "c04_body_adoption": c04_body_adoption,
        "cpu_policy": cpu, "cpu_policy_digest": canonical_digest(cpu), "cpu_signature": cpu_signature}
    case["phase_fixture_recall_owner_originals"] = originals
    return originals