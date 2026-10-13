"""Actual installed Life content-only worker/result/adoption/readback chain.

Owner/Core/Graph/D12 and provider/terminal/settlement are product mechanisms.
This fixture assembles Host components around the existing installation; it
is not full Host startup. Provider HTTP uses only the finite MockTransport.
"""
import asyncio,json,sqlite3,traceback
from pathlib import Path
import pytest
from test_installed_internal_life_content_v1 import installed_d04_root,run_installed_life_content_preparation_case
from sylanne3.authority_service.internal_life_model_graph_v2 import InstalledInternalLifeModelGraphReaderV2
from sylanne3.authority_service.d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
from sylanne3.runtime.d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
from sylanne3.runtime.internal_life_model_call_v2 import internal_life_model_draft_v2,seal_internal_life_model_call_v2
from sylanne3.runtime.internal_life_content_worker_v2 import TABLE,read_life_worker_original_v2
from sylanne3.runtime.internal_life_content_preparation_v1 import read_committed_internal_life_prepared_v1
from sylanne3.model_broker.internal_life_content_v1 import OUTPUT_SCHEMA,WORK_KIND,thaw_internal_life_content_request_v1
from sylanne3.runtime_contracts import AuthorityContext,canonical_digest
from sylanne3.host.authority_client import AuthorityClient,AuthoritySelection
from sylanne3.host.mtls_transport import MtlsAuthorityTransport
from sylanne3.host.astrbot_model_call import AstrBotModelProvider
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.model_broker.broker import ModelProviderDescriptor
from sylanne3.runtime.model_cost_settlement import read_original_model_cost,OriginalModelCostCommitV1
from sylanne3.authority_service.v2_model_egress_contract import ModelTerminalReceiptV2

async def run_installed_life_content_fullchain_v1(tmp_path,installed_d04_root,*,after_completed=None,
        enable_c09_maintenance=False, terminal_after_completed=False,
        host_process_runner=None,c09_protected_root=None,initial_phase_fixture_installation=None,
        complete_c09_current_v3=False,c09_phase_setup_file=None):
    if terminal_after_completed and (after_completed is None or not enable_c09_maintenance):
        raise ValueError("terminal C09 scenario requires its maintenance callback")
    async def after(case):
        graph,store,server=(case[k] for k in ('graph','store','server'))
        ns=case['namespace'];policy=case['policy'];port=case['port'];issuer=case['d11_issuer']
        bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
        fences=server._v2_fences[case['authority_namespace']]
        control=graph._actual_d04_authority_acceptance_v3.storage_control
        path=Path(store._db.execute('PRAGMA database_list').fetchone()[2]).resolve()
        if complete_c09_current_v3:
            owner=server._d12_owner_storage_services_v1[(case['authority_namespace'],policy.installation_id)]
            assert owner.core is case['c09_daemon'].core and owner.control is control
        else:
            owner=InstalledD12OwnerStorageAdmissionServiceV1(fences=fences,owner_tickets=server._v2_owner_tickets,
                graph_db_path=path,namespace_id=ns,installation_id=policy.installation_id,
                holder=policy.administrator_holder,control=control,close_apply=control._applied_reader)
        readers=InstalledD06StructuredExperienceReadersV1(issuer=issuer,resource_issuer=issuer.resource_issuer,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority)
        reader=InstalledInternalLifeModelGraphReaderV2(owner_storage=owner,structured_readers=readers,
            bundle=bundle,read_subject=case['client_grant'].subject)
        model=case['model_service'];verifier=model._graph_verifier
        from sylanne3.authority_service.current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
        if complete_c09_current_v3:
            location=server._d11_life_services_v1[case['authority_namespace']].current_source_location
            assert location._control is control and location.core is case['c09_daemon'].core
        else:
            location=InstalledCurrentSourceLocationQualifierV1(fences=fences,scoped=control._applied_reader.scoped,
                control=control,graph_db_path=path,namespace_id=ns,installation_id=policy.installation_id)
        model.install_current_source_location_v1(location)
        verifier.install_internal_life_reader_v2(reader)
        original_current=verifier._current
        def diagnose(*args,**kwargs):
            result=original_current(*args,**kwargs)
            if not result:
                intent=args[0]
                with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
                    db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
                    import time
                    try:reader.read(db,intent,time.time())
                    except Exception:traceback.print_exc()
            return result
        verifier._current=diagnose
        def draft_read():
            with store._lock:
                store._db.execute('BEGIN')
                try:
                    job=store._db.execute(f"SELECT job_id FROM {TABLE} WHERE kind='binding'").fetchone()[0]
                    prepared=read_committed_internal_life_prepared_v1(store._db,namespace=ns,issuer=issuer,job_id=job)
                    metadata,_=graph._v2_graph_stamp(ns)
                finally:store._db.rollback()
            authority=AuthorityContext(port.installation_grant.subject,'d11','life-content-read:'+prepared.digest,
                ns,('activity','event','persona','scene'),'consolidation',(case['life_audience'],),
                prepared.provider_config_ref,metadata.requirements.activation_generation)
            def observe(scope):
                actual,permit=port.get_current_owner_guard_for_fence(namespace=ns,
                    authority_namespace=policy.authority_namespace,permit=scope.permit)
                assert permit==scope.permit
                return actual,permit
            def read():
                store._db.execute('BEGIN')
                try:
                    metadata,epoch=graph._v2_graph_stamp(ns)
                    return internal_life_model_draft_v2(store._db,namespace=ns,issuer=issuer,job_id=job,
                        metadata=metadata,epoch=epoch)
                finally:store._db.rollback()
            value,anchor,_,_=graph._read_v2(authority,read,fence_observer=observe,return_recovery_context=True)
            return (*value,anchor)
        prepared,binding,request,draft,anchor=await asyncio.to_thread(draft_read)
        frozen=thaw_internal_life_content_request_v1(json.loads(prepared.frozen_json))
        case['model_reply_mode']['content']=json.dumps({'schema':OUTPUT_SCHEMA,
            'occurrence_digest':frozen.input.occurrence_digest,'summary':'The internal activity completed.',
            'keywords':['internal activity']})
        transport=MtlsAuthorityTransport({bundle.tls_profile.profile_id:bundle.tls_profile})
        client=AuthorityClient(AuthoritySelection(bundle.tls_profile.profile_id),package_root=installed_d04_root,
            data_dir=tmp_path,transport=transport)
        workflow=bundle.model_workflows.life_content
        descriptor=ModelProviderDescriptor(workflow.provider_id,'astrbot-openai-official-v1',workflow.model_id,
            frozenset({'text'}),frozenset({workflow.purpose}),frozenset({workflow.privacy_tier}),
            workflow.provider_config_ref,'unknown',False,False)
        adapter=AstrBotModelProvider(context=case['model_context'],host_loop=asyncio.get_running_loop(),
            trusted_umo=json.loads(case['life_audience'])[0],descriptor=descriptor,admin_model=workflow,installation_bundle=bundle)
        mock=case['model_http_client']._transport;actual_handler=mock.handler;calls=[]
        def counted(req):calls.append(req.url.host);return actual_handler(req)
        mock.handler=counted
        try:
            assert (await client.status_v2()).state=='paired'
            actual_grant=await client.installation_grant_v2()
            from sylanne3.host.installation_grant_identity import same_installed_grant_identity_v2
            assert same_installed_grant_identity_v2(case['client_grant'],actual_grant)
            executor=HostModelEgressExecutor(authority=client,bundle=bundle,grant=actual_grant,adapter=adapter)
            record,permit=await client.model_prepare_fenced_v1(bundle,actual_grant,draft=draft,expected_anchor=anchor)
            intent=record.intent
            assert record.state=='prepared'
            def seal():
                actual,state=port.get_fence_operation(namespace=ns,authority_namespace=policy.authority_namespace,
                    operation_id=intent.operation_id)
                assert actual==permit and state=='active'
                with store._lock:
                    db=store._db;db.execute('BEGIN IMMEDIATE')
                    try:
                        metadata,epoch=graph._v2_graph_stamp(ns)
                        seal_internal_life_model_call_v2(db,namespace=ns,issuer=issuer,job_id=prepared.job_id,
                            intent=intent,permit=permit,metadata=metadata,epoch=epoch)
                        db.commit()
                    except BaseException:db.rollback();raise
            await asyncio.to_thread(seal)
            terminal=await executor.execute_once(intent=intent,expected_anchor=anchor,request=request)
            assert type(terminal) is ModelTerminalReceiptV2 and len(calls)==1
            assert (terminal.call_id,terminal.request_digest,terminal.installation_id)==(
                prepared.call_id,request.digest,prepared.installation_id)
            # The donor's original channel may have retired while actual Life
            # execution ran. Re-authenticate that client through the installed
            # APIs and bind its cost port to the newly issued channel grant.
            from sylanne3.host.model_terminal_cost_port import InstalledModelTerminalCostPort
            from sylanne3.host.accounting_maintenance_port import InstalledAccountingMaintenancePort
            donor=case['authority_client']
            assert (await donor.status_v2()).state=='paired'
            donor_grant=await donor.installation_grant_v2()
            assert same_installed_grant_identity_v2(case['client_grant'],donor_grant)
            graph._GraphCoordinator__model_terminal_cost_port=InstalledModelTerminalCostPort(
                client=donor,bundle=case['installed_bundle'],grant=donor_grant,
                owner_loop=asyncio.get_running_loop())
            graph._GraphCoordinator__accounting_maintenance_port=InstalledAccountingMaintenancePort(
                client=donor,bundle=case['installed_bundle'],grant=donor_grant,
                owner_loop=asyncio.get_running_loop())
            def settle():
                fact=read_original_model_cost(graph._GraphCoordinator__model_terminal_cost_port,intent)
                result=graph._commit_original_model_cost_v1(case['bootstrap'],ns,intent,
                    quote_id=prepared.quote_id,quote_version=prepared.quote_version,work_kind=WORK_KIND)
                assert type(result) is OriginalModelCostCommitV1
                return result
            cost=await asyncio.to_thread(settle)
            assert cost.call_id==prepared.call_id
            def ledger():
                return tuple(store._db.execute('SELECT phase,digest,receipt_json FROM runtime_budget_operations '
                    'WHERE bot_id=? AND persona_id=? AND operation_id=? ORDER BY phase',(*ns.as_tuple,prepared.prepare_operation_id)))
            before=await asyncio.to_thread(ledger)
            assert [r[0] for r in before]==['reserve','settle']
            assert await executor.recover_original_terminal(intent)==terminal and len(calls)==1
            again=await asyncio.to_thread(settle)
            assert again.commit_seq==cost.commit_seq and await asyncio.to_thread(ledger)==before
            assert len(calls)==1
            from sylanne3.authority_service.internal_life_model_result_service_v2 import InstalledInternalLifeModelResultServiceV2
            from sylanne3.runtime.internal_life_paid_result_v2 import (prepare_life_result_selector_v2,
                record_life_paid_original_v2,read_life_paid_original_v2,read_life_cost_commit_v2)
            from sylanne3.authority_service.internal_life_model_result_contract_v2 import internal_life_result_to_wire_v2
            from sylanne3.runtime.internal_life_content_adoption_v1 import (AdoptInternalLifeContentRequestV1,
                OPERATION,KINDS,PROVENANCE,content_keys_v1,decode_content_v1,validate_content_history_v1,
                InstalledInternalLifeContentReaderV1)
            from test_current_domain_production_v1 import domain_owner
            from sylanne3.runtime.jobs import get_job
            service=InstalledInternalLifeModelResultServiceV2(store=model._store,fences=fences,
                graph_db_path=path,d11_issuer=issuer,installation_id=policy.installation_id,
                read_subject=actual_grant.subject,holder=policy.administrator_holder,
                trusted_now_utc=verifier._clock,source_location=model._source_location,graph_reader=reader)
            server.install_internal_life_model_result_reader_v2(case['authority_namespace'],service)
            original_prepare=service.prepare
            def diagnose_result(**kwargs):
                try:return original_prepare(**kwargs)
                except Exception:traceback.print_exc();raise
            service.prepare=diagnose_result
            def fenced_sql(action):
                def observe(scope):
                    guard,actual=port.get_current_owner_guard_for_fence(namespace=ns,
                        authority_namespace=policy.authority_namespace,permit=scope.permit)
                    assert actual==scope.permit
                    return guard,actual
                authority=AuthorityContext(actual_grant.subject,'d11','life-content-read:'+prepared.digest,
                    ns,('activity','event','persona','scene'),'consolidation',(case['life_audience'],),
                    prepared.provider_config_ref,prepared.activation_generation)
                def transaction():
                    db=store._db;db.execute('BEGIN IMMEDIATE')
                    try:
                        value=action(db);db.commit();return value
                    except BaseException:db.rollback();raise
                return graph._read_v2(authority,transaction,fence_observer=observe)
            selector=await asyncio.to_thread(fenced_sql,lambda db:prepare_life_result_selector_v2(db,
                namespace=ns,issuer=issuer,job_id=prepared.job_id,authority_id=actual_grant.authority_id,
                authority_namespace=policy.authority_namespace))
            delivered=await client.internal_life_model_result_read_v2(bundle,actual_grant,read_request=selector)
            delivered.require_original(intent,prepared,frozen,binding)
            _,read_state=await asyncio.to_thread(port.get_fence_operation,namespace=ns,
                authority_namespace=policy.authority_namespace,operation_id=selector.read_attempt_id)
            assert read_state=='finished' and not service._inflight_deliveries
            fact=await asyncio.to_thread(read_original_model_cost,graph._GraphCoordinator__model_terminal_cost_port,intent)
            def save_result(db):
                current=reader.read(db,intent,verifier._clock(),allow_accounted_result=True)
                assert (current.prepared,current.binding,current.frozen)==(prepared,binding,frozen)
                assert read_life_paid_original_v2(db,ns,issuer,'read_attempt',selector.read_attempt_id)==internal_life_result_to_wire_v2(selector)
                assert delivered.terminal_receipt==fact.receipt and delivered.observation.digest==fact.recovery.observation_digest
                read_life_cost_commit_v2(db,namespace=ns,issuer=issuer,prepared=prepared,intent=intent,terminal=terminal,fact=fact)
                return record_life_paid_original_v2(db,ns,issuer,'result',prepared.job_id,delivered)
            await asyncio.to_thread(fenced_sql,save_result)
            operation='life-content-adopt:'+prepared.job_id.removeprefix('life-content-job:')
            locator=AdoptInternalLifeContentRequestV1(prepared.episode_ref,
                frozen.input.cause.occurrence.event.causal_operation_id)
            def adopt():
                with domain_owner(case) as (authority,lease):
                    result=graph.run_current_domain_operation_v1(authority,lease,operation_kind=OPERATION,
                        request=locator,operation_id=operation,activity_id=prepared.activity_id,
                        audience_ref=case['life_audience'],parent_budget_lease_ref=policy.root_grant.lease_id)
                runtime=graph._GraphCoordinator__domain_production_runtime_v1
                if result.get('schema')!='sylanne.internal-life-content-production-receipt.v1':
                    error=runtime._last_refusal_exception_v1
                    if error is not None:traceback.print_exception(type(error),error,error.__traceback__)
                assert result['schema']=='sylanne.internal-life-content-production-receipt.v1'
                assert (result['completion'],result['capability'],result['before_state'],result['comparison'],result['affect'])==(
                    'content_completed','content_only','evidence_unavailable','undetermined','unavailable')
                assert len(result['receipt']['write_versions'])==4 and not store._db.in_transaction
                return result
            adopted=await asyncio.to_thread(adopt)
            keys=content_keys_v1(prepared.episode_ref)
            def cold():
                from sylanne3.runtime.internal_life_completed_original_v1 import read_completed_internal_life_original_v1
                with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
                    db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
                    proof=decode_content_v1(PROVENANCE,json.loads(db.execute('SELECT value FROM graph_atoms WHERE token=?',(keys[1].token,)).fetchone()[0]))
                    completed=read_completed_internal_life_original_v1(db,namespace=ns,issuer=issuer,job_id=prepared.job_id)
                    assert completed.validated_proof==proof and completed.prepared==prepared
                    assert completed.intent==intent and completed.delivered==delivered and completed.cost==cost
                    assert completed.receipt.operation_id==operation and len(completed.receipt.write_versions)==4
                    assert get_job(db,prepared.job_id).phase=='completed'
                    assert all(db.execute('SELECT revision,valid FROM graph_atoms WHERE token=?',(key.token,)).fetchone()==(1,1) for key in keys)
                    assert proof.trace.before_state=='evidence_unavailable' and proof.trace.affect=='unavailable'
                    assert db.total_changes==0
                    return proof.trace
            trace=await asyncio.to_thread(cold)
            current_reader=InstalledInternalLifeContentReaderV1(graph=graph,installed_readers=readers)
            def current():
                authority,lease,_=graph.grant_current_owner(case['bootstrap'],actor='owner-actor-reply',namespace=ns,
                    domains=('d06',),purpose='consolidation',audience=case['life_audience'],activation_generation=1,
                    owner_session_token=case['owner_session_token'],owner_session_request=case['owner_session_request'])
                try:return current_reader.read(authority=authority,lease=lease,trace_ref=keys[0].token)
                finally:graph.release_current_owner_lease(case['bootstrap'],lease)
            assert await asyncio.to_thread(current)==trace
            def counts():
                return (tuple(store._db.execute('SELECT phase,digest,receipt_json FROM runtime_budget_operations '
                    'WHERE bot_id=? AND persona_id=? AND operation_id=? ORDER BY phase',(*ns.as_tuple,prepared.prepare_operation_id))),
                    tuple(store._db.execute('SELECT operation_id,commit_seq,receipt_json FROM graph_bundle_operations '
                    'WHERE bot=? AND persona=? AND operation_id IN (?,?) ORDER BY operation_id',(*ns.as_tuple,operation,cost.operation_id))),
                    store._db.execute('SELECT count(*) FROM graph_internal_life_paid_originals_v2').fetchone())
            once=await asyncio.to_thread(counts)
            assert await asyncio.to_thread(adopt)==adopted
            assert await asyncio.to_thread(current)==trace and await asyncio.to_thread(cold)==trace
            assert await asyncio.to_thread(counts)==once and len(calls)==1
            assert trace.candidate.assertion_scope=='model_description_only'
            # Obtain genuine separately scoped Owner leases. Their grant is
            # valid, but it cannot broaden the Life Source-family permissions.
            from sylanne3.runtime.d01_production_operations_v1 import MissingProductionOriginalV1
            from sylanne3.graph_coordinator import UnavailableGuard
            def refuse_scope(purpose,audience):
                authority,lease,_=graph.grant_current_owner(case['bootstrap'],actor='owner-actor-reply',namespace=ns,
                    domains=('d06',),purpose=purpose,audience=audience,activation_generation=1,
                    owner_session_token=case['owner_session_token'],owner_session_request=case['owner_session_request'])
                try:
                    with pytest.raises(UnavailableGuard,match='v2 content authority is unavailable') as denied:
                        current_reader.read(authority=authority,lease=lease,trace_ref=keys[0].token)
                    assert type(denied.value.__cause__) is MissingProductionOriginalV1
                    assert 'current_source_family_permission' in str(denied.value.__cause__)
                finally:graph.release_current_owner_lease(case['bootstrap'],lease)
            await asyncio.to_thread(refuse_scope,'expression',case['life_audience'])
            await asyncio.to_thread(refuse_scope,'consolidation','owner')
            if after_completed is not None:
                await after_completed({**case, 'content_prepared':prepared,
                    'content_intent':intent, 'content_delivered':delivered, 'content_cost':cost,
                    'content_trace':trace, 'content_adopted':adopted,
                    'content_mock_transport':mock, 'content_model_adapter':adapter,
                    'content_model_workflow':workflow, 'content_model_descriptor':descriptor,
                    'content_installation_bundle':bundle,
                    'content_source_execution_id':case['life_source_execution_id']})
                if terminal_after_completed:
                    return
            # Real Authority logout revokes this exact session. A process lease
            # acquired before logout must not keep authorizing current content.
            def revoke_session():
                authority,lease,_=graph.grant_current_owner(case['bootstrap'],actor='owner-actor-reply',namespace=ns,
                    domains=('d06',),purpose='consolidation',audience=case['life_audience'],activation_generation=1,
                    owner_session_token=case['owner_session_token'],owner_session_request=case['owner_session_request'])
                try:
                    assert port.current_owner_session(namespace=ns,authority_namespace=policy.authority_namespace,
                        request=case['owner_session_request'],token=case['owner_session_token']) is True
                    port.logout_owner_session(namespace=ns,authority_namespace=policy.authority_namespace,
                        request=case['owner_session_request'],token=case['owner_session_token'])
                    with pytest.raises(UnavailableGuard,match='v2 content authority is unavailable') as denied:
                        current_reader.read(authority=authority,lease=lease,trace_ref=keys[0].token)
                    assert type(denied.value.__cause__) is RuntimeError
                    assert str(denied.value.__cause__)=='authority service unavailable'
                finally:graph.release_current_owner_lease(case['bootstrap'],lease)
            await asyncio.to_thread(revoke_session)
            assert await asyncio.to_thread(cold)==trace
            assert await asyncio.to_thread(counts)==once and len(calls)==1
        finally:
            mock.handler=actual_handler;verifier._current=original_current;await transport.close()
    await run_installed_life_content_preparation_case(tmp_path,installed_d04_root,
        acquire=True,worker_v2=True,after_acquire=after,
        enable_c09_maintenance=enable_c09_maintenance,
        host_process_runner=host_process_runner,c09_protected_root=c09_protected_root,
        initial_phase_fixture_installation=initial_phase_fixture_installation,complete_c09_current_v3=complete_c09_current_v3,
        c09_phase_setup_file=c09_phase_setup_file)


@pytest.mark.asyncio
async def test_installed_life_content_fullchain_commits_and_reads_once(tmp_path,installed_d04_root):
    await run_installed_life_content_fullchain_v1(tmp_path,installed_d04_root)
