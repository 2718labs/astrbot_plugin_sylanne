"""Initial Authority services and finite material for the separate Life Host.

Only the initial fixture invokes this, before Owner/business work. Live Authority
objects stay in the parent; the child receives the closed installation material.
"""
from dataclasses import replace
from pathlib import Path
import hashlib


def prepare_parent_life_installation_v1(case, *, provider_config, reverse_profile,
        reverse_bind_port, owner_claim, c09_protected_root):
    from cryptography.hazmat.primitives import serialization
    from test_d04_owner_semantic_initialization_v3 import install_d04_test_composition
    from test_d11_installed_life_source_note_v1 import _installed_life_service
    from c09_life_host_process_support_v1 import HostInstallationCaseV1
    from c09_life_provider_cache_acceptance_v1 import ControlledLifeProviderCacheV1
    from c09_life_authority_phase_support_v1 import persist_life_cold_fixture_v1
    from sylanne3.host.authority_profile import AdminIngressEncodingPolicy
    from sylanne3.authority_service.linux_bootstrap_v1 import build_initial_inventory_v1
    from sylanne3.authority_service.d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    from sylanne3.authority_service.current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
    from sylanne3.authority_service.internal_life_model_graph_v2 import InstalledInternalLifeModelGraphReaderV2
    from sylanne3.authority_service.internal_life_model_result_service_v2 import InstalledInternalLifeModelResultServiceV2
    from sylanne3.runtime.d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1

    bundle = replace(case['installed_bundle'], ingress_clock=case['ingress_clock'],
        ingress_encoding=AdminIngressEncodingPolicy(120.0, {'output_tokens':128},
            'snapshot:reply-ingress', 'resource:reply-ingress', 'character:reply'))
    case['installed_bundle'] = bundle
    install_d04_test_composition(case)
    _installed_life_service(case, register_host_process=False)
    graph, server, ns = case['graph'], case['server'], case['namespace']
    control = graph._actual_d04_authority_acceptance_v3.storage_control
    if Path(c09_protected_root).resolve() != control.key_path.parent:
        raise ValueError('outer protected root differs from initial Control')
    path = Path(case['store']._db.execute('PRAGMA database_list').fetchone()[2]).resolve()
    fences = server._v2_fences[case['authority_namespace']]
    policy = case['policy']; issuer = case['d11_issuer']; model = case['model_service']
    owner = InstalledD12OwnerStorageAdmissionServiceV1(fences=fences,
        owner_tickets=server._v2_owner_tickets, graph_db_path=path, namespace_id=ns,
        installation_id=policy.installation_id, holder=policy.administrator_holder,
        control=control, close_apply=control._applied_reader)
    readers = InstalledD06StructuredExperienceReadersV1(issuer=issuer,
        resource_issuer=case['d02_issuer'], body_quote_authority=graph._GraphCoordinator__body_quote_authority)
    reader = InstalledInternalLifeModelGraphReaderV2(owner_storage=owner,
        structured_readers=readers, bundle=bundle, read_subject=case['client_grant'].subject)
    location = InstalledCurrentSourceLocationQualifierV1(fences=fences,
        scoped=control._applied_reader.scoped, control=control, graph_db_path=path,
        namespace_id=ns, installation_id=policy.installation_id)
    model.install_current_source_location_v1(location)
    model._graph_verifier.install_internal_life_reader_v2(reader)
    result_service = InstalledInternalLifeModelResultServiceV2(store=model._store,
        fences=fences, graph_db_path=path, d11_issuer=issuer,
        installation_id=policy.installation_id, read_subject=case['client_grant'].subject,
        holder=policy.administrator_holder, trusted_now_utc=model._graph_verifier._clock,
        source_location=location, graph_reader=reader)
    server.install_internal_life_model_result_reader_v2(case['authority_namespace'], result_service)
    cache = ControlledLifeProviderCacheV1(path.parent.parent / (path.parent.name+'-c09-provider-cache'), provider_config)
    cache.bind(authority_id=control.authority_id, installation_id=control.installation_id,
        namespace=case['authority_namespace'])
    case['c09_provider_cache'] = cache
    current = control.read_verified_current_storage_v1()
    files = {member['role']:Path(member['resolved_path']) for member in current.manifest['members']}
    directories = {name:path.parent/'offline-managed-artifacts'/name
        for name in ('controlled_backup','export','rebuild_temp','cache')}
    inventory = build_initial_inventory_v1(authority_id=control.authority_id,
        installation_id=control.installation_id, namespace=case['authority_namespace'],
        files=files, directories=directories)
    case['c09_cold_fixture'] = persist_life_cold_fixture_v1(control.key_path.parent/'life-cold-installation.json',
        core=case['core'], control=control, namespace=ns, peer=case['peer'],
        subject=case['client_grant'].subject, holder=policy.administrator_holder,
        package_root=case['package_root'], manifest_digest=case['manifest_digest'],
        inventory=inventory, target_directory=directories['rebuild_temp'],
        runtime_issuer_signing_key=b'reply-issuer-key-'*2,
        admin_d02_signing_key=bundle.d02_signing_key, provider_cache=cache)
    driver = Path(__file__).with_name('d11_life_host_actor_support_v1.py')
    return HostInstallationCaseV1(package_root=case['package_root'], data_dir=path.parent,
        graph_path=path, namespace=ns, authority_namespace=case['authority_namespace'],
        bundle=bundle, request=case['request'], grant=case['client_grant'], peer=case['peer'],
        reverse_profile=reverse_profile, reverse_bind_host='127.0.0.1', reverse_bind_port=reverse_bind_port,
        owner_fixture_private_key=case['owner_key'].private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw, serialization.NoEncryption()),
        provider_config=dict(provider_config), host_driver_module=driver.stem,
        host_driver_function='run_installed_life_host_actor_v1',
        host_driver_sha256=hashlib.sha256(driver.read_bytes()).hexdigest(),
        host_driver_configuration={'schema':'sylanne.c09.life-host-actor.v1',
            'owner_claim':owner_claim, 'bootstrap':{
                'schema':'sylanne.c09.life-host-bootstrap.v1',
                'runtime_issuer_signing_key':b'reply-issuer-key-'*2,
                'ingress_clock':case['ingress_clock'],
                'provider_domains':tuple(sorted(graph._GraphCoordinator__providers)),
                'owner_session_request':case['owner_session_request'],
                'provider_cache':cache.installation_material(), 'enable_c04_body_work':True}})
