"""Reopen the authenticated Beta1 fixture cohort using the actual selected daemon."""
from contextlib import asynccontextmanager
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from threading import Thread
import asyncio
import hmac
import json
import os
import stat
import time

from beta1_fixture_phase_controller_v1 import (_SCENARIOS,_CONTINUATION_FIELDS,
    CONTINUATION_SCHEMA,read_beta1_fixture_context_original_v1,
    login_current_beta1_owner_after_cold_v3,register_current_beta1_fixture_case_v3,
    unregister_current_beta1_fixture_case_v3)


def _read_owned_original(path,expected_sha256):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid()
                or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>262144):
            raise ValueError("exact owned private Beta1 continuation original required")
        with os.fdopen(fd,"rb",closefd=False) as stream:data=stream.read(262145)
    finally:os.close(fd)
    if sha256(data).hexdigest()!=expected_sha256:
        raise ValueError("Beta1 continuation source pin differs")
    return json.loads(data)


def read_current_beta1_resume_configuration_v3(*,setup_file,setup_sha256,
        continuation_file,continuation_sha256,scenario):
    from sylanne3.authority_service.linux_installation_security_v1 import read_installed_bytes_v1
    from sylanne3.authority_service.c09_process_identity_v1 import require_process_retired_v1
    from c09_life_authority_phase_support_v1 import (open_life_cold_fixture_v1,
        current_life_deployment_from_original_v3,CURRENT_SCHEMA_V3)
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    if scenario not in _SCENARIOS:
        raise ValueError("closed Beta1 current fixture scenario required")
    setup=Path(setup_file).resolve(strict=True)
    if sha256(read_installed_bytes_v1(setup,limit=262144)).hexdigest()!=setup_sha256:
        raise ValueError("Root-prepared per-node setup source pin changed")
    initial=M1PhaseFixtureInstallationV2.from_protected_setup_v2(setup)
    assets=json.loads(read_installed_bytes_v1(initial.c09_installation_assets,
        limit=16384,private=True,allowed_gid=os.getegid()))
    directory=Path(assets["control_path"]).parent.resolve(strict=True)
    continuation_path=Path(continuation_file)
    if continuation_path!=directory/("beta1-continuation-"+scenario+".json"):
        raise ValueError("continuation left its original per-node Control directory")
    continuation=_read_owned_original(continuation_path,continuation_sha256)
    if (type(continuation) is not dict or set(continuation)!=_CONTINUATION_FIELDS
            or continuation["schema"]!=CONTINUATION_SCHEMA or continuation["scenario"]!=scenario
            or continuation["setup_file"]!=str(setup) or continuation["setup_sha256"]!=setup_sha256
            or continuation["package_root"]!=str(initial.package_root)
            or continuation["manifest_digest"]!=initial.initial_bundle.installation_policy.manifest_digest):
        raise ValueError("exact original same-cohort Beta1 continuation required")
    cold=continuation["initial_cold_fixture"]
    if type(cold) is not dict or set(cold)!={"path","fixture_digest"} or Path(cold["path"])!=directory/"life-cold-installation.json":
        raise ValueError("original pre-business current daemon selector differs")
    with open_life_cold_fixture_v1(cold["path"],expected_fixture_digest=cold["fixture_digest"],
            current_only=True) as (raw,control):
        control.verify_original_v1(continuation,"continuation_digest")
        if (raw["schema"]!=CURRENT_SCHEMA_V3 or raw["namespace"]!=continuation["namespace"]
                or raw["authority_namespace"]!=continuation["authority_namespace"]
                or raw["control"]["installation_id"]!=continuation["installation_id"]
                or raw["deployment_original"]["phase_setup_path"]!=str(setup)
                or raw["deployment_original"]["phase_setup_sha256"]!=setup_sha256
                or raw["initial_process"]!=continuation["initial_process"]):
            raise ValueError("Beta1 cold daemon selector changed the original installed cohort")
        retired=require_process_retired_v1(continuation["initial_process"])
        if retired["state"]!="retired" or continuation["initial_process"]["pid"]==os.getpid():
            raise ValueError("initial Beta1 Authority process has not actually retired")
        envelope=read_beta1_fixture_context_original_v1(control,continuation=continuation,
            setup_sha256=setup_sha256,scenario=scenario)
        config,cache=current_life_deployment_from_original_v3(raw)
    return initial,continuation,envelope,config,cache


@asynccontextmanager
async def resume_current_beta1_fixture_case_v3(*,setup_file,setup_sha256,
        continuation_file,continuation_sha256,scenario):
    from astrbot.api.star import Context
    from astrbot.core.provider.sources.openai_source import ProviderOpenAIOfficial
    from rewrite.host_tests.alpha1.test_astrbot_model_call import Manager
    from sylanne3.authority_service.daemon import open_authority_daemon
    from sylanne3.authority_service.mtls_server import MtlsPeerCredential
    from sylanne3.authority_service.current_model_egress_graph_verifier import PinnedCurrentModelEgressGraphVerifier
    from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService
    from sylanne3.graph_coordinator import GraphCoordinator
    from sylanne3.graph_worker import GraphWorker
    from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
    from sylanne3.host.authority_client import (AUTHORITY_PROTOCOL,AuthorityProvisioningRequest,
        PublisherPackageIdentity,AuthorityClient,AuthoritySelection)
    from sylanne3.host.mtls_transport import MtlsAuthorityTransport
    from sylanne3.host.v2_fence_port import V2FencePort
    from sylanne3.host.reply_suppression import HostReplySuppressionRegistryV1
    from sylanne3.host.accounting_maintenance_port import InstalledAccountingMaintenancePort
    from sylanne3.host.self_identity_current_port import InstalledCurrentSelfIdentityPort
    from sylanne3.host.model_terminal_cost_port import InstalledModelTerminalCostPort
    from sylanne3.host.worker_result_read_fact_port import InstalledWorkerResultReadFactPort
    from sylanne3.host.original_c02_cost_intent_port import InstalledOriginalC02CostIntentPort
    from sylanne3.host.authority_profile import (load_artifact_phase_local_fixture_bundle_v1,
        bind_artifact_phase_local_fixture_components_v1,artifact_phase_local_fixture_scope_v1,
        require_artifact_phase_fixture_qualification_v1,revoke_artifact_phase_local_fixture_qualification_v1)
    from sylanne3.runtime.c04_cpu_quote_policy import C04InternalCpuQuotePolicyAuthorityV1
    from sylanne3.runtime.d11_artifact_draft_model_v1 import InstalledArtifactDraftModelRuntimeV1
    from sylanne3.runtime.first_ingress_v2 import trusted_upper
    from sylanne3.host.installation_grant_identity import same_installed_grant_identity_v2
    from m1_artifact_draft_acceptance_support_v1 import build_m1_phase_mock_client_v2,_bind_m1_phase_verifier_scope_v2
    from d11_offline_authority_acceptance_support_v1 import FreshOfflineStorageCaseV1,OuterOwnedProtectedRootV1
    initial,continuation,envelope,config,cache=read_current_beta1_resume_configuration_v3(
        setup_file=setup_file,setup_sha256=setup_sha256,continuation_file=continuation_file,
        continuation_sha256=continuation_sha256,scenario=scenario)
    bootstrap_daemon=open_authority_daemon(config)
    worker=store=port=qualification=mock=initial_client_transport=transport=None
    authority_loop=authority_thread=None
    issued_case=None
    try:
        daemon=await bootstrap_daemon.await_business_ready_v3();control=daemon.c09_control
        current=control.read_verified_current_storage_v3();current.require_current("business")
        if (current.stage!="RELEASED" or current.storage_generation<1
                or current.prepared_original["operation_id"]!=continuation["c09_operation_id"]):
            raise ValueError("Beta1 resume needs the actual released four-role selected C09 generation")
        registry=load_verified_affect_scheme(initial.package_root,continuation["manifest_digest"]).registry
        store=daemon._resolved_storage_composition_v3.open_graph(registry.type_registry)
        graph_path=Path(next(member["resolved_path"] for member in current.manifest["members"] if member["role"]=="graph"))
        ans=continuation["authority_namespace"];model_installation=daemon.config.natural_model_authorities_v2[ans]
        base_bundle=model_installation.installation_bundle;policy=base_bundle.installation_policy
        if (policy.namespace!=envelope.namespace or policy.installation_id!=continuation["installation_id"]
                or base_bundle.ingress_clock.source_id!=continuation["original_clock"]["source_id"]):
            raise ValueError("cold selection changed the original installed namespace or clock")
        authority_loop=asyncio.new_event_loop()
        authority_thread=Thread(target=authority_loop.run_forever,name="beta1-current-cold-authority",daemon=True)
        authority_thread.start()
        listener=await asyncio.to_thread(lambda:asyncio.run_coroutine_threadsafe(
            daemon.start(),authority_loop).result(timeout=30))
        if listener.sockets[0].getsockname()[1]!=base_bundle.tls_profile.port:
            raise ValueError("cold daemon changed its Root-prepared TLS endpoint")
        transport=MtlsAuthorityTransport({initial.profile_id:base_bundle.tls_profile})
        request=AuthorityProvisioningRequest(AUTHORITY_PROTOCOL,initial.profile_id,
            "astrbot_plugin_sylanne","4.28.1",initial.package_root,initial.data_dir,
            PublisherPackageIdentity(continuation["manifest_digest"]))
        from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
        handshake=await transport.handshake(request,protocol=AUTHORITY_V2_PROTOCOL)
        grant=await transport.installation_grant_v2(request,handshake)
        port=await asyncio.to_thread(V2FencePort,request,{initial.profile_id:base_bundle.tls_profile},grant)
        initial_client_transport=MtlsAuthorityTransport({initial.profile_id:base_bundle.tls_profile})
        initial_client=AuthorityClient(AuthoritySelection(initial.profile_id),package_root=initial.package_root,
            data_dir=initial.data_dir,transport=initial_client_transport)
        if (await initial_client.status_v2()).state!="paired":
            raise ValueError("same cold installed Authority channel is not paired")
        client_grant=await initial_client.installation_grant_v2()
        if not same_installed_grant_identity_v2(grant,client_grant):
            raise ValueError("cold independent installed grants differ")
        now=port.read_ingress_clock(base_bundle.ingress_clock)
        if now.sample.epoch!=continuation["original_clock"]["epoch"] or trusted_upper(now)>=continuation["original_deadline_utc"]:
            raise ValueError("original fixture clock or absolute deadline changed")
        d11=model_installation.d11_issuer;d02=d11.resource_issuer
        factory=daemon.config.c09_maintenance_factory
        graph_bootstrap=object();suppressions=HostReplySuppressionRegistryV1()
        def principal_for(actor,namespace):
            binding=daemon.owner_pairings.current_actor_binding(authority_namespace=ans,
                installation_id=policy.installation_id,actor_id=actor)
            return binding.principal if binding is not None and binding.namespace==namespace else None
        cpu=C04InternalCpuQuotePolicyAuthorityV1(hmac.digest(base_bundle.d11_signing_key,
            b"sylanne3.c04.internal_cpu_quote_policy.v1\0"+policy.installation_id.encode(),"sha256"))
        graph=GraphCoordinator(store,graph_bootstrap,holder=policy.administrator_holder,
            content_fence_v2=port,d02_issuer=d02,d11_issuer=d11,
            body_quote_authority=factory.body_authority,c04_cpu_quote_authority=cpu,
            owner_principal_resolver=principal_for,scene_clock_policy=base_bundle.ingress_clock,
            d13_paid_precompression_policy=base_bundle.d13_paid_precompression,
            reply_suppression_ack_verifier=suppressions.verify_and_consume)
        initial_storage=FreshOfflineStorageCaseV1(control,control.lease,
            OuterOwnedProtectedRootV1(str(control.key_path.parent)),daemon.config,factory,cache,factory.body_authority)
        graph._initial_offline_storage_case_v1=initial_storage
        case=dict(graph=graph,store=store,bootstrap=graph_bootstrap,namespace=policy.namespace,
            authority_namespace=ans,c09_daemon=daemon,c09_bootstrap=bootstrap_daemon,
            c09_deployment_config=daemon.config,c09_maintenance_factory=factory,
            c09_phase_setup_file=setup_file,c09_cold_fixture=continuation["initial_cold_fixture"],
            c09_provider_cache=cache,server=daemon.server,core=daemon.core,
            execution=daemon.execution[ans],protected=daemon.server._v2_fences[ans],
            fences=daemon.server._v2_fences[ans].fences,model_service=daemon.server._v2_model_egress[ans],
            model_store=daemon.server._v2_model_egress[ans]._store,pairing_source=daemon.owner_pairings,
            owner_sessions=daemon.server._v2_owner_sessions,owner_proofs=daemon.server._v2_owner_proofs,
            peer=MtlsPeerCredential(factory.peer[0]),port=port,grant=grant,client_grant=client_grant,
            authority_client=initial_client,installed_bundle=base_bundle,policy=policy,
            d02_issuer=d02,d11_issuer=d11,domain_registry=registry,package_root=initial.package_root,
            manifest_digest=continuation["manifest_digest"],owner_loop=asyncio.get_running_loop(),
            ingress=envelope,ingress_clock=base_bundle.ingress_clock,m1_initial_configuration=initial,
            enable_d04_root_cpu=scenario.startswith("numeric-"),authority_loop=authority_loop,
            c02_operation_id=continuation["scenario_c02_operation_id"],source_ref=continuation["scenario_source_ref"],
            beta1_continuation=continuation,beta1_original_deadline_utc=continuation["original_deadline_utc"])
        if scenario.startswith("numeric-"):
            from test_d04_owner_semantic_initialization_v3 import install_d04_test_composition
            from d04_numeric_authority_acceptance_support_v3 import install_actual_numeric_authority_case_v3
            await asyncio.to_thread(install_d04_test_composition,case)
        for registration in registry.registrations.values():
            expected=(registration.provider,registration.proposal_schema,registration.proposal_schema_hash)
            prior=graph._GraphCoordinator__providers.get(registration.domain)
            if prior is not None:
                if prior!=expected:raise ValueError("cold provider differs from its actual selected type registry")
                continue
            graph.register_provider(graph_bootstrap,registration.domain,*expected)
        sdk,mock,mode,calls=build_m1_phase_mock_client_v2(initial,envelope.text,provider_cache=cache,positive_recall=True)
        provider=object.__new__(ProviderOpenAIOfficial)
        provider.provider_config=initial.provider_configuration;provider.model_name=initial.provider_configuration["model"]
        provider.client=sdk
        context=Context(asyncio.Queue(),{},None,Manager(provider),None,None,None,None,None,None,None)
        bundle,qualification=await load_artifact_phase_local_fixture_bundle_v1(initial.profile_id,
            profile_root=initial.profile_root,package_root=initial.package_root,data_dir=initial.data_dir,
            provider_client=sdk,mock_transport=mock._transport)
        if (bundle.installation_policy!=policy or bundle.model_workflows!=base_bundle.model_workflows
                or bundle.d11_signing_key!=base_bundle.d11_signing_key or bundle.d02_signing_key!=base_bundle.d02_signing_key):
            raise ValueError("actual protected fixture overlay changed its original policy, Root or issuer")
        client=qualification.authority_client;actual_grant=qualification.client_grant
        if not same_installed_grant_identity_v2(grant,actual_grant):
            raise ValueError("protected cold fixture is on another installed channel identity")
        assembly=graph._GraphCoordinator__d04_installed_joint_assembly
        if scenario.startswith("numeric-"):
            graph._GraphCoordinator__d04_installed_joint_assembly=replace(assembly,
                installation_policy=bundle.installation_policy,installation_grant=actual_grant,
                admin_bundle=bundle,ingress_clock=bundle.ingress_clock,ingress_encoding=bundle.ingress_encoding)
        parameters=dict(client=client,bundle=bundle,grant=actual_grant,owner_loop=asyncio.get_running_loop())
        graph._GraphCoordinator__accounting_maintenance_port=InstalledAccountingMaintenancePort(**parameters)
        graph._GraphCoordinator__self_identity_port=InstalledCurrentSelfIdentityPort(**parameters)
        graph._GraphCoordinator__model_terminal_cost_port=InstalledModelTerminalCostPort(**parameters)
        graph._GraphCoordinator__worker_result_fact_port=InstalledWorkerResultReadFactPort(**parameters)
        graph._GraphCoordinator__original_c02_cost_intent_port=InstalledOriginalC02CostIntentPort(**parameters)
        worker=await GraphWorker.start(lambda:store,lambda _store:graph)
        runtime=InstalledArtifactDraftModelRuntimeV1(graph=graph,bootstrap=graph_bootstrap,bundle=bundle,
            worker=worker,authority_client=client,client_grant=actual_grant,context=context,
            owner_loop=asyncio.get_running_loop())
        def install_runtime(actual_graph):
            with artifact_phase_local_fixture_scope_v1(qualification):
                actual_graph.install_artifact_draft_model_runtime_v1(graph_bootstrap,runtime)
        await worker.call(install_runtime)
        await bind_artifact_phase_local_fixture_components_v1(qualification,graph=graph,
            bootstrap=graph_bootstrap,model_runtime=runtime)
        def paired_clock():
            reading=daemon.config.clock_provider()
            return reading.utc_seconds+reading.utc_error_seconds,reading.epoch
        model=AuthorityV2ModelEgressService(case["model_store"],case["protected"],
            graph_verifier=PinnedCurrentModelEgressGraphVerifier(graph_path,d11_issuer=d11,
                trusted_now_utc=time.time,trusted_paired_clock=paired_clock,
                artifact_draft_bundle=bundle),admin_model_policy=bundle.model_workflows)
        _bind_m1_phase_verifier_scope_v2(verifier=model._graph_verifier,service=model,server=daemon.server,
            namespace=ans,qualification=qualification,graph_db_path=graph_path,issuer=d11)
        model.install_current_source_location_v1(daemon.c09_maintenance.current_source_location)
        daemon.server._v2_model_egress[ans]=model
        case.update(installed_bundle=bundle,policy=bundle.installation_policy,authority_client=client,
            client_grant=actual_grant,phase_fixture_qualification=qualification,phase_provider_calls=calls,
            phase_model_runtime=runtime,phase_worker=worker,model_context=context,model_http_client=mock,
            model_reply_mode=mode,model_service=model,ingress_clock=bundle.ingress_clock)
        if scenario.startswith("numeric-"):
            await asyncio.to_thread(install_actual_numeric_authority_case_v3,case,owner_loop=asyncio.get_running_loop())
        async def get_http_worker():return worker
        case["get_http_worker"]=get_http_worker
        require_artifact_phase_fixture_qualification_v1(bundle,client_grant=actual_grant)
        await login_current_beta1_owner_after_cold_v3(case,continuation=continuation)
        def current_owner(actual_graph):
            authority,lease,binding=actual_graph.grant_current_owner(graph_bootstrap,actor="owner-actor-reply",
                namespace=policy.namespace,domains=("d11",),purpose="context",audience=envelope.conversation_ref,
                activation_generation=1,owner_session_token=case["owner_session_token"],
                owner_session_request=case["owner_session_request"])
            actual_graph.release_current_owner_lease(graph_bootstrap,lease)
            return binding
        case["beta1_current_owner_binding"]=await worker.call(current_owner)
        selected=continuation["scenario_selectors"]
        if scenario.startswith("numeric-"):
            case.update(episode_ref=selected["episode_ref"],life_activity_id=selected["life_activity_id"],
                life_causal_operation_id=selected["life_causal_operation_id"],life_audience=selected["life_audience"],
                beta1_numeric_selectors=selected)
        from sylanne3.runtime.d12_installed_services_v1 import install_d12_services_v1
        case["beta1_workbench_lifecycle"]=await worker.call(lambda actual_graph:
            install_d12_services_v1(actual_graph,bootstrap=graph_bootstrap))
        import os
        from sylanne3.graph_worker import _register_beta1_engineering_metadata_provider_v3
        await worker.call(lambda actual_graph:_register_beta1_engineering_metadata_provider_v3(
            actual_graph,worker,engineering_root=os.environ['SYLANNE_C09_TEST_ROOT'],
            engineering_inventory_sha256=os.environ['SYLANNE_C09_ENGINEERING_INVENTORY_SHA256'],
            guard_sha256=os.environ['SYLANNE_C09_GUARD_SHA256']))
        register_current_beta1_fixture_case_v3(case);issued_case=case
        yield case
    finally:
        import sys
        original_failure=sys.exc_info()[1]
        cleanup_failures=[]
        async def finish_cleanup(pending):
            try:await pending
            except BaseException as failure:cleanup_failures.append(failure)
        if issued_case is not None:
            try:unregister_current_beta1_fixture_case_v3(issued_case)
            except BaseException as failure:cleanup_failures.append(failure)
        if worker is not None:
            # Accepted continuations must finish with their original provider still present.
            await finish_cleanup(worker.close())
            from sylanne3.graph_worker import _unregister_beta1_engineering_metadata_provider_v3
            try:_unregister_beta1_engineering_metadata_provider_v3(graph,worker)
            except BaseException as failure:cleanup_failures.append(failure)
        elif store is not None:
            try:store.close()
            except BaseException as failure:cleanup_failures.append(failure)
        if qualification is not None:
            try:revoke_artifact_phase_local_fixture_qualification_v1(qualification)
            except BaseException as failure:cleanup_failures.append(failure)
            await finish_cleanup(qualification.authority_client._transport.close())
        if mock is not None:await finish_cleanup(mock.aclose())
        if initial_client_transport is not None:await finish_cleanup(initial_client_transport.close())
        if port is not None:await finish_cleanup(asyncio.to_thread(port.close))
        if transport is not None:await finish_cleanup(transport.close())
        if authority_loop is not None:
            await finish_cleanup(asyncio.to_thread(lambda:asyncio.run_coroutine_threadsafe(
                bootstrap_daemon.aclose(),authority_loop).result(timeout=30)))
            try:authority_loop.call_soon_threadsafe(authority_loop.stop)
            except BaseException as failure:cleanup_failures.append(failure)
            await finish_cleanup(asyncio.to_thread(authority_thread.join,30))
            try:authority_loop.close()
            except BaseException as failure:cleanup_failures.append(failure)
        else:await finish_cleanup(bootstrap_daemon.aclose())
        if cleanup_failures:
            failures=([original_failure]if original_failure is not None else[])+cleanup_failures
            raise BaseExceptionGroup("Beta1 original failure and resource cleanup failures",failures)
