"""Initial Authority services and finite material for the separate Life Host.

Only the initial fixture invokes this, before Owner/business work. Live Authority
objects stay in the parent; the child receives the closed installation material.
"""
from dataclasses import replace
from pathlib import Path
import hashlib


def prepare_parent_life_installation_v1(case, *, provider_config, reverse_profile,
        reverse_bind_port, owner_claim, c09_protected_root):
    from sylanne3.host.authority_profile import AdminIngressEncodingPolicy
    if case.get('c09_daemon') is not None:
        bundle=case['c09_daemon'].config.natural_model_authorities_v2[case['authority_namespace']].installation_bundle
        assert bundle is case['installed_bundle']
    else:
        bundle = replace(case['installed_bundle'], ingress_clock=case['ingress_clock'],
            ingress_encoding=AdminIngressEncodingPolicy(120.0, {'output_tokens':128},
                'snapshot:reply-ingress', 'resource:reply-ingress', 'character:reply'))
    return _prepare_parent_installation_components_v1(case, provider_config=provider_config,
        reverse_profile=reverse_profile, reverse_bind_port=reverse_bind_port, owner_claim=owner_claim,
        c09_protected_root=c09_protected_root,bundle=bundle,
        runtime_signing_key=bundle.d11_signing_key if case.get('c09_daemon') is not None else b'reply-issuer-key-'*2)


def _prepare_parent_installation_components_v1(case, *, provider_config, reverse_profile,
        reverse_bind_port, owner_claim, c09_protected_root, bundle, runtime_signing_key):
    from cryptography.hazmat.primitives import serialization
    from test_d04_owner_semantic_initialization_v3 import install_d04_test_composition
    from test_d11_installed_life_source_note_v1 import _installed_life_service
    from c09_life_host_process_support_v1 import HostInstallationCaseV1
    from c09_life_provider_cache_acceptance_v1 import ControlledLifeProviderCacheV1
    from c09_life_authority_phase_support_v1 import persist_life_cold_fixture_v1
    from sylanne3.authority_service.linux_bootstrap_v1 import build_initial_inventory_v1
    from sylanne3.authority_service.d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    from sylanne3.authority_service.current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
    from sylanne3.authority_service.internal_life_model_graph_v2 import InstalledInternalLifeModelGraphReaderV2
    from sylanne3.authority_service.internal_life_model_result_service_v2 import InstalledInternalLifeModelResultServiceV2
    from sylanne3.runtime.d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1

    case['installed_bundle'] = bundle
    install_d04_test_composition(case)
    _installed_life_service(case, register_host_process=False)
    graph, server, ns = case['graph'], case['server'], case['namespace']
    control = graph._actual_d04_authority_acceptance_v3.storage_control
    if c09_protected_root is not None and Path(c09_protected_root).resolve() != control.key_path.parent:
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
    if case.get('c09_daemon') is not None:
        initial=graph._initial_offline_storage_case_v1
        cache=initial.provider_cache
        assert cache is not None and case['c09_daemon'].config.c09_maintenance_factory is initial.maintenance_factory
    else:
        cache = ControlledLifeProviderCacheV1(path.parent.parent / (path.parent.name+'-c09-provider-cache'), provider_config)
    cache.bind(authority_id=control.authority_id, installation_id=control.installation_id,
        namespace=case['authority_namespace'])
    case['c09_provider_cache'] = cache
    current = control.read_verified_current_storage_v1()
    files = {member['role']:Path(member['resolved_path']) for member in current.manifest['members']}
    directories = {name:path.parent/'offline-managed-artifacts'/name
        for name in ('controlled_backup','export','rebuild_temp','cache')}
    if case.get('c09_daemon') is not None:
        inventory=case['c09_maintenance_factory'].inventory
        assert inventory.manifest_digest==current.manifest['inventory_manifest_digest']
    else:
        inventory = build_initial_inventory_v1(authority_id=control.authority_id,
            installation_id=control.installation_id, namespace=case['authority_namespace'],
            files=files, directories=directories)
    case['c09_cold_fixture'] = persist_life_cold_fixture_v1(control.key_path.parent/'life-cold-installation.json',
        core=case['core'], control=control, namespace=ns, peer=case['peer'],
        subject=case['client_grant'].subject, holder=policy.administrator_holder,
        package_root=case['package_root'], manifest_digest=case['manifest_digest'],
        inventory=inventory, target_directory=directories['rebuild_temp'],
        runtime_issuer_signing_key=runtime_signing_key,
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
                'runtime_issuer_signing_key':runtime_signing_key,
                'ingress_clock':case['ingress_clock'],
                'provider_domains':tuple(sorted(graph._GraphCoordinator__providers)),
                'owner_session_request':case['owner_session_request'],
                'provider_cache':cache.installation_material(), 'enable_c04_body_work':True}},
        initial_phase_setup_file=None if case.get('c09_daemon') is None else Path(case['c09_phase_setup_file']).resolve(strict=True))


def prepare_parent_l02_installation_v1(case, *, provider_config, reverse_profile, reverse_bind_port, owner_claim):
    """Initial-only exact protected material; no Host-bound phase qualification."""
    from sylanne3.host.v2_installation import V2InstallationAssembly
    from sylanne3.host.installed_d04_output_policy import load_installed_d04_output_policy_v1
    from sylanne3.host.installed_d04_semantic_mapping_v3 import InstalledD04SemanticMappingReaderV3
    from sylanne3.runtime.d04_semantic_installation_original_v3 import install_d04_semantic_installation_schema_v3
    from d04_numeric_authority_acceptance_support_v3 import install_actual_root_authority_case_v3
    graph,store,bundle = case['graph'],case['store'],case['installed_bundle']
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    initial = case['m1_initial_configuration']
    if type(initial) is not M1PhaseFixtureInstallationV2 or bundle != initial.initial_bundle:
        raise ValueError('L02 must retain its actual protected initial bundle')
    graph_path = Path(store._db.execute('PRAGMA database_list').fetchone()[2]).resolve(strict=True)
    assembly = V2InstallationAssembly(case['policy'],case['grant'],bundle.d11_signing_key,bundle.d02_signing_key,
        lambda:case['port'],case['package_root'],graph_path.parent,ingress_clock=bundle.ingress_clock,admin_bundle=bundle)
    graph._GraphCoordinator__d04_installed_joint_assembly=assembly
    graph._GraphCoordinator__d04_installed_joint_output_policy=load_installed_d04_output_policy_v1(
        case['package_root'],case['manifest_digest'],require_formal=False,require_backend_runtime=True)
    for domain in ('d02','d04','d11','d12'):
        registration=case['domain_registry'].registrations[domain]
        graph.register_provider(case['bootstrap'],domain,registration.provider,registration.proposal_schema,
            registration.proposal_schema_hash)
    with store._lock:install_d04_semantic_installation_schema_v3(store._db)
    reader=InstalledD04SemanticMappingReaderV3(graph,case['package_root'],case['manifest_digest'])
    graph._GraphCoordinator__d04_semantic_mapping_reader=reader
    case['mapping_reader']=reader
    install_actual_root_authority_case_v3(case,owner_loop=case['owner_loop'])
    material=_prepare_parent_installation_components_v1(case,provider_config=provider_config,reverse_profile=reverse_profile,
        reverse_bind_port=reverse_bind_port,owner_claim=owner_claim,c09_protected_root=None,bundle=bundle,
        runtime_signing_key=bundle.d11_signing_key)
    if material.bundle is not bundle or graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not bundle:
        raise ValueError('L02 changed its exact initial bundle during ordinary Core installation')
    gate=case['c09_writer_gate']
    if gate._peers or gate._active:
        raise ValueError('L02 supervisor initial parent cannot be a registered business Host')
    return material


def authenticate_parent_l02_phase_v1(case, material, result, *, phase):
    """Authenticate child locators after actual retirement, using selected RO originals."""
    import json
    import sqlite3
    from sylanne3.authority_service.c09_process_identity_v1 import require_process_retired_v1
    from sylanne3.runtime_contracts import canonical_digest
    from sylanne3.runtime.jobs import get_job
    from sylanne3.runtime.d07_execution_v1 import (read_prepared_d07_execution_v1,D07IngressRecallPreparedV1,read_d07_original_v1)
    from sylanne3.runtime.foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from sylanne3.runtime.d11_offline_originals_v1 import TABLE,read_current_d11_offline_original_ref_v1
    from sylanne3.runtime.d11_offline_adoption_v1 import _read_signed,verify_offline_adoption_commit_v1
    from sylanne3.authority_service.d11_offline_tick_bridge_v1 import offline_bridge_from_wire_v1
    if result['actual_exit_code']!=0 or require_process_retired_v1(result['process_identity'])!=result['retirement']:
        raise ValueError('L02 phase requires its actual retired successful Host process')
    control=case['c09_writer_gate'].control
    current=control.read_verified_current_storage_v1();current.require_current('business')
    selected=Path(next(member['resolved_path'] for member in current.manifest['members'] if member['role']=='graph')).resolve(strict=True)
    if selected!=Path(material.graph_path).resolve(strict=True):
        raise ValueError('L02 phase locator crossed the actual selected Graph')
    ns,issuer=case['namespace'],case['d11_issuer']
    outcome=result['outcome']
    with sqlite3.connect(selected.as_uri()+'?mode=ro',uri=True,isolation_level=None) as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        try:
            if phase=='waiting':
                locators=outcome['locators']
                if locators['namespace_creation_operation_id']!=case['namespace_creation_operation_id']:
                    raise ValueError('L02 namespace locator differs from its actual initial creation')
                prepared=read_prepared_d07_execution_v1(db,issuer,ns,locators['c3_job_id'])
                if (type(prepared) is not D07IngressRecallPreparedV1 or prepared.digest!=locators['prepared_digest']
                        or prepared.c02_operation_id!=locators['c02_operation_id']):
                    raise ValueError('L02 C3 waiting locator differs from its actual signed preparation')
                parent,child=get_job(db,locators['parent_job_id']),get_job(db,locators['c3_job_id'])
                wait=foreground_cycle_from_wire_v1(dict(parent.continuation)).wait
                if (parent.phase!='waiting' or parent.lease_holder is not None or child.phase!='queued' or child.fence
                        or wait is None or wait.producer_domain!='d07' or wait.event_kind!='ingress_recall_model_terminal'):
                    raise ValueError('L02 C3 has no actual durable parent wait/queued child')
                case['l02_c3_locators']=dict(locators)
                proof={'prepared_digest':prepared.digest,'parent_job_id':parent.job_id,'child_job_id':child.job_id}
            elif phase=='adopted':
                locators=case['l02_c3_locators'];prepared=read_prepared_d07_execution_v1(db,issuer,ns,locators['c3_job_id'])
                if prepared.digest!=locators['prepared_digest'] or get_job(db,prepared.job_id).phase!='completed':
                    raise ValueError('L02 C3 reopened another child or lacks actual completion')
                digests={}
                for kind,ref in (('paid_cost',prepared.job_id),('body_cost',prepared.job_id),('execution','d07-terminal:'+prepared.call_id)):
                    original=read_d07_original_v1(db,issuer,ns,kind,ref)
                    if original is None:raise ValueError('L02 C3 missing its actual signed '+kind)
                    digests[kind]=original[1]
                if digests!=outcome['after']['signed_original_digests'] or digests!=outcome['replay']['signed_original_digests']:
                    raise ValueError('L02 child packet differs from independently authenticated C3 originals')
                proof=digests
            elif phase=='offline_registered':
                locators=outcome['locators']
                if locators['namespace_creation_operation_id']!=case['namespace_creation_operation_id']:
                    raise ValueError('L02 offline namespace creation differs')
                schedule=read_current_d11_offline_original_ref_v1(db,namespace=ns,original_ref=locators['schedule_ref'],issuer=issuer)
                if schedule is None or schedule.original_digest!=locators['schedule_original_digest']:
                    raise ValueError('L02 offline schedule lacks its actual signed registration')
                case['l02_offline_locators']=dict(locators)
                proof={'schedule_ref':schedule.original_ref,'schedule_digest':schedule.original_digest}
            elif phase=='offline_adopted':
                locators=case['l02_offline_locators']
                schedule=read_current_d11_offline_original_ref_v1(db,namespace=ns,original_ref=locators['schedule_ref'],issuer=issuer)
                if schedule is None or schedule.original_digest!=locators['schedule_original_digest']:
                    raise ValueError('L02 offline schedule changed after downtime')
                refs=tuple(row[0] for row in db.execute('SELECT original_ref FROM '+TABLE+
                    " WHERE bot=? AND persona=? AND kind='adoption_receipt' ORDER BY original_ref LIMIT 5",ns.as_tuple))
                if not refs or len(refs)>4:raise ValueError('L02 offline actual adopted ticks exceed the finite original schedule')
                proof={}
                for ref in refs:
                    receipt=_read_signed(db,ns,'adoption_receipt',ref,issuer)
                    bridge=_read_signed(db,ns,'adoption_bridge',ref,issuer)
                    actual=offline_bridge_from_wire_v1(bridge[1])
                    verify_offline_adoption_commit_v1(db,gate=actual,issuer=issuer,
                        resource_issuer=issuer.resource_issuer,require_current_metadata=False)
                    if actual.terminal.status!='completed' or receipt[1]['status']!='completed':
                        raise ValueError('L02 offline tick has no actual completed adoption/CPU original')
                    proof[ref]={'receipt_digest':canonical_digest(receipt[1]),'terminal_digest':canonical_digest(actual.terminal),
                        'actual_cpu_ms':receipt[1]['actual_cpu_ms']}
                if proof!=outcome['signed_adoptions'] or proof!=outcome['signed_replay_adoptions']:
                    raise ValueError('L02 offline packet differs from its actual signed once originals')
            else:raise ValueError('unregistered closed L02 parent phase')
            if db.total_changes:raise ValueError('L02 authentication wrote business state')
        finally:db.rollback()
    current.require_current('business')
    return proof
