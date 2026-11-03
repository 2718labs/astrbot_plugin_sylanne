"""Concrete Linux installation composition from protected, externally pinned assets."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import hmac
from pathlib import Path

from .contract import AuthorityUnavailable
from .c09_installed_factory_v1 import InstalledC09MaintenanceFactoryV1
from .c09_provider_cache_v1 import InstalledProviderCacheDispositionV1
from .daemon import open_authority_daemon
from .deployment_config import load_installed_asset_config_v1, InstalledNaturalModelAuthorityV2
from .installed_core_verifiers import installed_core_verifier_factory
from .installed_platform_observation import HostOneBotObservationInstallationV2
from .installed_policy import InstalledPeerScopeV1
from .installed_policy_v2 import InstalledAuthorityPolicyV2
from .linux_clock_v1 import LinuxKernelClockProviderV1
from .linux_installation_security_v1 import read_installed_bytes_v1, read_installed_json_v1, require_linux_administrator_v1
from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
from ..host.affect_scheme_asset import load_verified_affect_scheme
from ..host.authority_profile import _load_installation_bundle_from_root
from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2, InstalledResourceV2
from ..runtime.issuers import D02ResourceIssuer, D11BudgetJobIssuer

_FIELDS = {"schema", "assets_path", "package_root", "trusted_manifest_sha256", "profile_id",
    "inventory_path", "inventory_sha256", "host_uid", "host_gid", "host_systemd_unit",
    "admission_socket", "target_directory", "provider_cache", "host_observation", "host_lifecycle"}


def require_complete_provider_cache_binding_v1(bundle, provider_id):
    """One installed adapter cannot attest absence at any other provider.

    This checks current configuration only. Maintenance must independently
    inventory historical provider calls before it can claim complete erasure.
    """
    workflows = bundle.model_workflows
    if workflows is None:
        raise AuthorityUnavailable("installed model provider inventory required")
    providers = {workflow.provider_id for name in (
        "encode", "reply", "context_reply", "natural_generation", "natural_review", "appraisal",
        "d07_cognition", "contact_generation", "contact_review", "life_content", "life_numeric")
        if (workflow := getattr(workflows, name, None)) is not None}
    paid = bundle.d13_paid_precompression
    if paid is not None:
        providers.add(paid.selected_main.provider_id)
    if providers != {provider_id}:
        raise AuthorityUnavailable("single cache adapter does not cover every installed model provider")


def load_linux_deployment_config_v1(path):
    require_linux_administrator_v1()
    launch = read_installed_json_v1(path)
    process_mode = launch.get("schema") in {"sylanne3.authority.linux-deployment.v2","sylanne3.authority.linux-deployment.v3","sylanne3.authority.linux-deployment.v4"}
    fields = (_FIELDS - {"host_systemd_unit"}) | {"host_supervisor_provider"} if process_mode else _FIELDS
    if launch.get('schema') in {'sylanne3.authority.linux-deployment.v3','sylanne3.authority.linux-deployment.v4'}:
        fields=fields|{'root_lifetime_spec_path','root_lifetime_spec_digest'}
    if launch.get('schema')=='sylanne3.authority.linux-deployment.v4':
        fields=fields|{'maintenance_console_role_path','maintenance_console_role_sha256'}
    if set(launch) != fields or launch["schema"] not in {
            "sylanne3.authority.linux-deployment.v1", "sylanne3.authority.linux-deployment.v2","sylanne3.authority.linux-deployment.v3","sylanne3.authority.linux-deployment.v4"}:
        raise AuthorityUnavailable("installed Linux deployment fields differ")
    if process_mode:
        from .d12_installed_supervisor_v1 import decode_installed_supervisor_config_v1
        from .installed_process_supervisor_v1 import InstalledProcessSupervisorSpecV2
        selected_provider = decode_installed_supervisor_config_v1(launch["host_supervisor_provider"])
        if launch['schema'] in {'sylanne3.authority.linux-deployment.v3','sylanne3.authority.linux-deployment.v4'}:
            from .installed_root_lifetime_observer_v3 import (SPEC_PATH,read_installed_root_lifetime_spec_v3,
                read_root_lifetime_resource_approval_v3)
            if launch['root_lifetime_spec_path']!=SPEC_PATH:
                raise AuthorityUnavailable('production Root lifetime must use its fixed protected installed spec')
            lifetime=read_installed_root_lifetime_spec_v3(SPEC_PATH)
            if (lifetime['spec_digest']!=launch['root_lifetime_spec_digest']
                    or lifetime['host_spec']['path']!=selected_provider.installed_spec_path
                    or lifetime['authority_id']!=selected_provider.authority_id
                    or lifetime['installation_id']!=selected_provider.installation_id):
                raise AuthorityUnavailable('Linux deployment and actual outer Root lifetime scope differ')
            read_root_lifetime_resource_approval_v3(lifetime)
        if type(selected_provider) is not InstalledProcessSupervisorSpecV2 or selected_provider.service_role != "host":
            raise AuthorityUnavailable("V2 deployment requires its exact installed process Host provider")
    assets = read_installed_json_v1(launch["assets_path"], limit=65536)
    bundle = _load_installation_bundle_from_root(launch["profile_id"], Path("/etc/sylanne/client/profiles"), "Linux")
    policy = bundle.installation_policy
    if process_mode and (selected_provider.installation_id != policy.installation_id
            or selected_provider.authority_id != policy.expected_authority_id
            or selected_provider.profile_id != launch["profile_id"]
            or selected_provider.namespace_cohort != (policy.authority_namespace,)
            or selected_provider.expected_uid != launch["host_uid"]
            or selected_provider.expected_gid != launch["host_gid"]):
        raise AuthorityUnavailable("installed process provider differs from the actual Host/Authority identity")
    if (bundle.model_workflows is None or bundle.ingress_clock is None
            or policy.manifest_digest != launch["trusted_manifest_sha256"]):
        raise AuthorityUnavailable("installed Linux model, clock and exact package pins required")
    peers = [row for row in assets["installations_v2"] if row["profile_id"] == launch["profile_id"]]
    if len(peers) != 1 or len(assets["installations_v2"]) != 1 or len(assets["namespace_bindings_v2"]) != 1:
        raise AuthorityUnavailable("Linux alpha1 installation requires one exact namespace cohort")
    installed = peers[0]
    if (installed["installation_id"] != policy.installation_id
            or installed["manifest_digest"] != policy.manifest_digest
            or installed["administrator_holder"] != policy.administrator_holder
            or installed["source_id"] != bundle.ingress_clock.source_id
            or installed["max_utc_error_seconds"] != bundle.ingress_clock.max_utc_error_seconds):
        raise AuthorityUnavailable("installed Host and Authority profiles differ")
    peer = (installed["certificate_sha256"], launch["profile_id"])
    if launch['schema']=='sylanne3.authority.linux-deployment.v4':
        from .maintenance_console_role_v1 import load_protected_maintenance_console_role_config_v1
        console_role=load_protected_maintenance_console_role_config_v1(launch['maintenance_console_role_path'])
        if (console_role.raw_sha256!=launch['maintenance_console_role_sha256']
                or console_role.binding.installation_id!=policy.installation_id
                or console_role.binding.authority_id!=policy.expected_authority_id
                or console_role.binding.namespace!=policy.namespace
                or console_role.binding.package_manifest_digest!=policy.manifest_digest
                or console_role.binding.console_cert_sha256==peer[0]
                or console_role.binding.console_profile_id==peer[1]):
            raise AuthorityUnavailable('independent console role differs from the protected Linux installation')
    authorizer = InstalledAuthorityPolicyV2(
        peer_scopes={peer[0]: InstalledPeerScopeV1(policy.authority_namespace, policy.administrator_holder)},
        profile_peers={peer[1]: peer[0]}, package_root=launch["package_root"],
        trusted_manifest_sha256=launch["trusted_manifest_sha256"],
        d13_owner_peers_v3=({peer[0]: (peer[1], policy.authority_namespace,
            policy.administrator_holder, bundle.d13_cache_use_control_v2.consumer_cohort_digest)}
            if bundle.d13_cache_use_control_v2 is not None and bundle.d13_cache_use_control_v2.enabled else None))
    raw_inventory = read_installed_bytes_v1(launch["inventory_path"], limit=1048576)
    if hashlib.sha256(raw_inventory).hexdigest() != launch["inventory_sha256"]:
        raise AuthorityUnavailable("installed C09 filesystem inventory pin differs")
    import json
    data = json.loads(raw_inventory)
    if type(data.get("resources")) is not list:
        raise AuthorityUnavailable("installed C09 inventory resources required")
    data["resources"] = tuple(InstalledResourceV2(**{**row, "content_coverage": tuple(row["content_coverage"])})
                              for row in data["resources"])
    inventory = InstallationFilesystemManifestV2(**data)
    if (inventory.installation_id != policy.installation_id or inventory.authority_id != policy.expected_authority_id
            or inventory.namespace != policy.authority_namespace):
        raise AuthorityUnavailable("installed C09 inventory and Host scope differ")
    affect = load_verified_affect_scheme(launch["package_root"], launch["trusted_manifest_sha256"])
    if affect.registry.type_registry.catalogue_hash != policy.catalogue_hash:
        raise AuthorityUnavailable("installed domain catalogue differs from Host policy")
    resource = D02ResourceIssuer(bundle.d02_signing_key)
    budget_issuer = D11BudgetJobIssuer(resource, bundle.d11_signing_key)
    body = D02BodyQuoteAuthority(hmac.digest(bundle.d02_signing_key,
        b"sylanne3.d02.body_quote_original.v1\0" + policy.installation_id.encode(), "sha256"))
    factory = None
    if "c09_storage_v2" not in assets:
        require_complete_provider_cache_binding_v1(bundle, launch["provider_cache"].get("provider_id"))
        cache = InstalledProviderCacheDispositionV1(**launch["provider_cache"])
        factory = InstalledC09MaintenanceFactoryV1(namespace=policy.namespace, peer=peer,
            registry=affect.registry.type_registry, resource_issuer=resource, body_authority=body,
            budget_job_issuer=budget_issuer,
            inventory_manifest=inventory, target_directory=Path(launch["target_directory"]), provider_cache_cleanup=cache)
    clock = LinuxKernelClockProviderV1(source_id=bundle.ingress_clock.source_id,
        maximum_error_seconds=bundle.ingress_clock.max_utc_error_seconds)
    config = load_installed_asset_config_v1(launch["assets_path"], core_authorizer=authorizer.core_authorizer,
        core_verifier_factory=installed_core_verifier_factory, administrator_authorizer=authorizer.administrator_authorizer,
        publisher_manifest_verifier=authorizer.publisher_manifest_verifier,
        utc_clock=lambda: datetime.now(timezone.utc), local_administrator_credential=authorizer.local_administrator_credential,
        c09_maintenance_factory=factory)
    if factory is not None and process_mode:
        from .d12_installed_supervisor_v1 import decode_installed_supervisor_config_v1,build_installed_supervisor_v1
        from .c09_writer_peer_activation_v3 import InstalledPeerRegistryCensusV3
        lifecycle=launch['host_lifecycle']
        if type(lifecycle) is not dict or set(lifecycle)!={'supervisor','drain_timeout_seconds'}:
            raise AuthorityUnavailable('actual protected complete Host lifecycle provider required for registry genesis')
        actual_spec=decode_installed_supervisor_config_v1(lifecycle['supervisor'])
        if actual_spec!=selected_provider:
            raise AuthorityUnavailable('registry genesis and installed Host starts use different supervisors')
        census=InstalledPeerRegistryCensusV3(supervisor=build_installed_supervisor_v1(actual_spec),
            inventory_manifest=inventory,peer=peer)
        factory.install_peer_registry_census_v3(census)
    c09 = config.c09_storage_v2 or config.c09_storage_v1
    if (c09 is None or c09.authority_id != policy.expected_authority_id
            or config.namespace_bindings_v2.get((*peer, policy.namespace)) != policy.authority_namespace):
        raise AuthorityUnavailable("installed current C09 cohort differs from Host")
    namespace = policy.authority_namespace
    observer = HostOneBotObservationInstallationV2(peer[0], peer[1], **launch["host_observation"])
    config = replace(config, clock_provider=clock,
        natural_model_authorities_v2={namespace: InstalledNaturalModelAuthorityV2(
            budget_issuer, bundle.model_workflows, peer, bundle)},
        self_identity_readers_v2={namespace: peer}, worker_result_fact_committers_v2={namespace: peer},
        host_onebot_observations_v2={namespace: observer})
    if factory is not None and process_mode:
        from ..runtime.d13_consumer_manifest_v3 import requires_current_core_birth_v4
        if requires_current_core_birth_v4(config):
            from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
            from .d12_fixed_supervisor_policy_v2 import read_fixed_supervisor_policy_v2
            fixed,host_spec,authority_spec=read_fixed_supervisor_policy_v2(InstalledPackageSelectionFilesV2(
                control_directory=actual_spec.selection_control_directory))
            if host_spec!=actual_spec or fixed['instance_lock']!=str(config.instance_lock):
                raise AuthorityUnavailable('current Core uses another actual fixed Host/Authority supervisor policy')
            census.prepare_authority_birth_spec_v4(authority_spec)
    use_assets = config.d13_cache_use_assets_v2 or {}
    use = bundle.d13_cache_use_control_v2
    if set(use_assets) != ({namespace} if use is not None and use.enabled else set()):
        raise AuthorityUnavailable("D13 enabled pair and protected asset scope differ")
    if use_assets:
        use_assets[namespace].require_installation_v2(bundle)
    # Every service private key and asset is pinned below administrator-owned
    # parents, independently of the Host's group-readable installation profile.
    for item in (config.tls.certificate, config.tls.client_trust_root):
        read_installed_bytes_v1(item)
    read_installed_bytes_v1(config.tls.private_key, private=True, allowed_gid=0)
    if config.c09_storage_v2 is not None:
        # The retired Control path must stay absent. Protect only the installed
        # identity and the independent, fixed-name V2 selector assets here.
        read_installed_bytes_v1(c09.key_path, private=True, allowed_gid=0)
        read_installed_bytes_v1(c09.selector_path, private=True, allowed_gid=0)
        read_installed_bytes_v1(c09.selector_journal_path, private=True, allowed_gid=0)
    from ..host.selected_profile_cohort_v2 import require_current_bundle_selection_v2
    require_current_bundle_selection_v2(bundle, launch['package_root'], require_selected_python=True, authority_private_config=True)
    return config, launch


def install_linux_d13_cache_use_v2(config, *, core, bundle, coverage_installation=None):
    """Explicit administrator install/migration on the protected existing Core.

    Normal and cold opens verify these originals; neither invokes this signer.
    The caller retains the actual installation window and storage composition.
    """
    require_linux_administrator_v1()
    from .core import AuthorityServiceCore
    from .deployment_config import AuthorityDeploymentConfig
    from ..host.authority_profile import AdminInstallationBundle
    from .d13_cache_use_control_v2 import install_d13_cache_use_policy_pair_v2
    if type(config) is not AuthorityDeploymentConfig or type(core) is not AuthorityServiceCore or type(bundle) is not AdminInstallationBundle:
        raise AuthorityUnavailable("D13 installation requires actual protected config, Core and bundle")
    namespace = bundle.installation_policy.authority_namespace
    installed = (config.natural_model_authorities_v2 or {}).get(namespace)
    assets = (config.d13_cache_use_assets_v2 or {}).get(namespace)
    if (installed is None or installed.installation_bundle is not bundle or assets is None
            or core._authorize_callback is not config.core_authorizer
            or core.path.resolve() != config.authority_db.resolve()):
        raise AuthorityUnavailable("D13 explicit install differs from actual protected Core composition")
    assets.require_installation_v2(bundle)
    credential = config.local_administrator_credential("d13_cache_use_install", namespace)
    install_d13_cache_use_policy_pair_v2(core=core, credential=credential, bundle=bundle,
        budget_issuer=installed.d11_issuer, coverage_installation=coverage_installation)



def _fresh_linux_d13_request_v3(path,*,mode,publication_receipt=None):
    from ..runtime.d13_consumer_manifest_v3 import _issue_fresh_d13_installation_request_v3
    from ..host.authority_profile import _MAX_PROFILE_BYTES
    config,launch=load_linux_deployment_config_v1(path)
    from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
    from .d12_fixed_supervisor_policy_v2 import read_fixed_supervisor_policy_v2
    census=config.c09_maintenance_factory._peer_registry_census_v3
    fixed,host_spec,authority_spec=read_fixed_supervisor_policy_v2(InstalledPackageSelectionFilesV2(
        control_directory=census.supervisor.config.selection_control_directory))
    if (host_spec!=census.supervisor.config or fixed['installation_id']!=config.c09_storage_v1.installation_id
            or fixed['authority_id']!=config.c09_storage_v1.authority_id
            or fixed['namespace_cohort']!=list(host_spec.namespace_cohort)
            or fixed['profile_id']!=launch['profile_id'] or Path(fixed['instance_lock'])!=config.instance_lock):
        raise AuthorityUnavailable('fresh Core Authority birth and Host registry use different protected fixed policy')
    if census.authority_spec_v4 is None:census.prepare_authority_birth_spec_v4(authority_spec)
    elif census.authority_spec_v4!=authority_spec:
        raise AuthorityUnavailable('fresh and current fixed Authority specs differ')
    profile_path=Path('/etc/sylanne/client/profiles')/launch['profile_id']/'profile.json'
    profile_bytes=read_installed_bytes_v1(profile_path,limit=_MAX_PROFILE_BYTES)
    assets_bytes=read_installed_bytes_v1(launch['assets_path'],limit=65536)
    request=_issue_fresh_d13_installation_request_v3(config,mode=mode,
        profile_bytes=profile_bytes,assets_bytes=assets_bytes,expected=publication_receipt)
    return config,launch,request


async def prepare_linux_d13_fresh_installation_v3(path):
    """Return exact protected publication bytes; install no policy and start no business."""
    from .daemon import open_fresh_d13_authority_installation_v3
    config,launch,request=_fresh_linux_d13_request_v3(path,mode='prepare')
    bootstrap=open_fresh_d13_authority_installation_v3(config,fresh_request=request)
    try:
        prepared=await bootstrap.await_fresh_prepared_v3()
        return dict(status=prepared.status,profile_path=str(Path('/etc/sylanne/client/profiles')/
            launch['profile_id']/'profile.json'),assets_path=launch['assets_path'],
            profile_bytes=prepared.profile_bytes,assets_bytes=prepared.assets_bytes,
            publication_receipt=prepared.publication_receipt,
            supported_mode='production_root_prehost',controlled_sdk='NOT_YET_SUPPORTED')
    finally:await bootstrap.aclose()


async def finalize_linux_d13_fresh_installation_v3(path,*,publication_receipt):
    """Cold-read the actually published cohort; sign only after a new exact fresh census."""
    from .daemon import open_fresh_d13_authority_installation_v3
    config,launch,request=_fresh_linux_d13_request_v3(path,mode='finalize',publication_receipt=publication_receipt)
    bootstrap=open_fresh_d13_authority_installation_v3(config,fresh_request=request)
    try:
        daemon=await bootstrap.await_business_ready_v3()
        return daemon,launch
    except BaseException:
        await bootstrap.aclose()
        raise



def open_controlled_sdk_d13_fresh_installation_v3(config,*,mode,profile_bytes,assets_bytes,
        publication_receipt=None,consumer_closures=()):
    """Explicit finite SDK installer; all dormant/ready work retains its actual worker."""
    from .daemon import open_fresh_d13_authority_installation_v3
    from ..runtime.d13_consumer_manifest_v3 import _issue_fresh_d13_installation_request_v3
    request=_issue_fresh_d13_installation_request_v3(config,mode=mode,profile_bytes=profile_bytes,
        assets_bytes=assets_bytes,expected=publication_receipt,consumer_mode='controlled_sdk',
        consumer_closures=consumer_closures)
    return open_fresh_d13_authority_installation_v3(config,fresh_request=request)


def open_linux_authority_v1(path):
    config, launch = load_linux_deployment_config_v1(path)
    return open_authority_daemon(config), launch


def install_linux_lifecycle_v1(daemon, launch):
    """Compose the real independent controller before opening any RPC listener."""
    from .daemon import AuthorityDaemon
    if type(daemon) is not AuthorityDaemon:
        raise AuthorityUnavailable("Linux lifecycle requires the actual completed bootstrap daemon")
    from .d12_installed_supervisor_v1 import decode_installed_supervisor_config_v1, build_installed_supervisor_v1
    from .d12_operation_status_v1 import InstalledD12OperationStatusServiceV1
    from .d12_operation_status_rpc_v1 import install_d12_operation_status_service_v1
    from .d12_installation_lifecycle_v1 import InstalledD12InstallationLifecycleV1
    from .d12_installation_lifecycle_rpc_v1 import install_d12_installation_lifecycle_v1
    if daemon.is_listening or daemon.c09_control is None:
        raise AuthorityUnavailable("Linux lifecycle must compose on the stopped current Authority")
    specification = launch["host_lifecycle"]
    if type(specification) is not dict or set(specification) != {"supervisor", "drain_timeout_seconds"}:
        raise AuthorityUnavailable("exact installed lifecycle configuration required")
    supervisor_config = decode_installed_supervisor_config_v1(specification["supervisor"])
    if launch["schema"] in {"sylanne3.authority.linux-deployment.v2","sylanne3.authority.linux-deployment.v3","sylanne3.authority.linux-deployment.v4"}:
        supervisor=daemon.config.c09_maintenance_factory._peer_registry_census_v3.supervisor
        if supervisor.config!=supervisor_config:
            raise AuthorityUnavailable("actual bootstrap and lifecycle Root supervisors differ")
        supervisor.install_peer_registry_start_v3(control=daemon.c09_control,gate=daemon.c09_gate)
        if supervisor_config != decode_installed_supervisor_config_v1(launch["host_supervisor_provider"]):
            raise AuthorityUnavailable("lifecycle and C09 process supervisors differ")
    else:
        supervisor=build_installed_supervisor_v1(supervisor_config)
        if supervisor.config.unit_name != launch["host_systemd_unit"]:
            raise AuthorityUnavailable("lifecycle and C09 supervisor units differ")
    bindings = tuple(daemon.config.namespace_bindings_v2.items())
    if len(bindings) != 1:
        raise AuthorityUnavailable("Linux whole-Host lifecycle requires one exact cohort")
    (certificate, profile, namespace_id), namespace = bindings[0]
    installation = daemon.config.installations_v2[(certificate, profile)]
    context = daemon.c09_control.read_verified_current_storage_v1()
    graph = Path(next(member["resolved_path"] for member in context.manifest["members"] if member["role"] == "graph"))
    fences = daemon.server._v2_fences[namespace]
    model = daemon.server._v2_model_egress.get(namespace)
    if model is None:
        raise AuthorityUnavailable("lifecycle requires actual independent model/accounting originals")
    status = InstalledD12OperationStatusServiceV1(fences=fences, owner_tickets=daemon.server._v2_owner_tickets,
        source_graph_db=graph, namespace_id=namespace_id, installation_id=installation.installation_id)
    status.install_schema(daemon.config.local_administrator_credential("d12_operation_install", namespace))
    install_d12_operation_status_service_v1(daemon.server, status)
    service = InstalledD12InstallationLifecycleV1(status_service=status, control=daemon.c09_control,
        supervisor=supervisor, package_root=launch["package_root"], expected_manifest_digest=launch["trusted_manifest_sha256"],
        peer_certificate_sha256=certificate, peer_profile_id=profile, model_store=model._store,
        drain_timeout_seconds=specification["drain_timeout_seconds"])
    service.install_schema(daemon.config.local_administrator_credential("d12_lifecycle_install", namespace))
    install_d12_installation_lifecycle_v1(daemon.server, service)
    bundle = next(item.installation_bundle for item in daemon.config.natural_model_authorities_v2.values()
        if item.observer_peer == (certificate, profile))
    if bundle.package_selection is not None:
        from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
        from .d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2
        from .d12_fixed_supervisor_policy_v2 import read_fixed_supervisor_policy_v2
        from .d12_package_maintenance_authority_v2 import InstalledD12PackageMaintenanceAuthorityV2
        from .d12_package_maintenance_rpc_v2 import install_d12_package_maintenance_authority_v2
        files = InstalledPackageSelectionFilesV2(control_directory='/etc/sylanne/maintenance')
        fixed, host_config, authority_config = read_fixed_supervisor_policy_v2(files)
        if (fixed['installation_id'] != installation.installation_id or fixed['authority_id'] != context.manifest['authority_id']
                or fixed['namespace_cohort'] != [namespace] or fixed['profile_id'] != profile
                or host_config != supervisor.config):
            raise AuthorityUnavailable('fixed package supervisor does not match actual lifecycle installation')
        journal = InstalledPackageSupervisorJournalV2(control_directory=files.control_directory,
            supervisor_policy_digest=files.read_maintenance_policy_v2()['supervisor_policy_digest'])
        package_service = InstalledD12PackageMaintenanceAuthorityV2(lifecycle=service,package_files=files,
            supervisor_journal=journal,authority_supervisor=build_installed_supervisor_v1(authority_config))
        package_service.install_schema_v2(daemon.config.local_administrator_credential('d12_package_install',namespace))
        install_d12_package_maintenance_authority_v2(daemon.server,package_service)
        from .graph_catalogue_upgrade_v1 import InstalledGraphCatalogueUpgradeV1
        catalogue = InstalledGraphCatalogueUpgradeV1(
            lifecycle=service, package_files=files,
            target_registry=load_verified_affect_scheme(
                launch['package_root'], launch['trusted_manifest_sha256']).registry.type_registry)
        catalogue.install_schema(daemon.config.local_administrator_credential('d12_lifecycle_install',namespace))
        daemon.server._d12_graph_catalogue_upgrade_services_v1 = {
            (namespace, installation.installation_id): catalogue}
        from .source_inspection_migration_v1 import InstalledSourceInspectionMigrationV1
        from .d12_installation_lifecycle_rpc_v1 import install_d12_source_inspection_migration_v1
        from .source_inspection_workflow_resource_v1 import InstalledInspectionWorkflowResourceV1
        resource = (InstalledInspectionWorkflowResourceV1.from_controlled_sdk_v4(daemon=daemon)
            if daemon.c09_gate._controlled_sdk_activation_v3 is not None
            else InstalledInspectionWorkflowResourceV1())
        migration=InstalledSourceInspectionMigrationV1(lifecycle=service,package_files=files,
            registry=catalogue.registry,workflow_resource=resource)
        migration.install_schema(daemon.config.local_administrator_credential('d12_lifecycle_install',namespace))
        install_d12_source_inspection_migration_v1(daemon.server,migration)
        from ..runtime.source_inspection_member_admission_v1 import install_source_inspection_migration_history_v1
        install_source_inspection_migration_history_v1(daemon.server, migration,
            credential=daemon.config.local_administrator_credential('c09_maintenance', namespace))
        if launch['schema']=='sylanne3.authority.linux-deployment.v4':
            from .v2_model_egress_service import install_d13_accounting_metadata_producer_v3
            model=daemon.server._v2_model_egress.get(namespace)
            if model is None:
                raise AuthorityUnavailable('new Linux cohort requires its actual installed model accounting producer')
            install_d13_accounting_metadata_producer_v3(model,server=daemon.server,
                bundle=daemon.config.natural_model_authorities_v2[namespace].installation_bundle)
            from .maintenance_console_deployment_v1 import install_linux_maintenance_console_v1
            role_bytes=read_installed_bytes_v1(launch['maintenance_console_role_path'],limit=32768)
            if hashlib.sha256(role_bytes).hexdigest()!=launch['maintenance_console_role_sha256']:
                raise AuthorityUnavailable('installed console role changed before Authority composition')
            install_linux_maintenance_console_v1(daemon,role_config_path=launch['maintenance_console_role_path'])
        migration.workflow.resume_pending_v1()
    if (launch['schema']=='sylanne3.authority.linux-deployment.v4'
            and not getattr(daemon.server,'_maintenance_console_bindings_v1',None)):
        raise AuthorityUnavailable('new Linux deployment requires its actual Source service and independent console binding')
    return service
