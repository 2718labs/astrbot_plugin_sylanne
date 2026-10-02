"""Permanent installed numerical Life chain with one finite model provider call.

Real before capture, Source/Owner qualification, independent paid task, native
CPU and interval readers are exercised through installed product entrypoints.
The finite HTTP transport supplies a candidate, never numeric evidence.
"""
import asyncio,json,sqlite3,traceback
from dataclasses import fields
from pathlib import Path
import pytest
from test_installed_life_numeric_before_v1 import installed_d04_root,run_installed_life_before_case
from test_d04_installed_semantic_drive_v3 import explicit_subjective_reply
from d04_numeric_life_acceptance_support_v1 import numeric_owner
from sylanne3.host.authority_profile import AdminModelWorkflowV2
from sylanne3.host.model_workflows_v3 import AdminModelWorkflowsV3
from sylanne3.authority_service.current_life_numeric_v1 import InstalledLifeNumericModelGraphReaderV1
from sylanne3.authority_service.d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
from sylanne3.runtime.d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
from sylanne3.runtime.d06_life_numeric_paid_v1 import life_numeric_model_draft_v1,seal_life_numeric_call_v1
from sylanne3.runtime.d06_life_numeric_task_v1 import read_life_numeric_prepared_v1
from sylanne3.model_broker.internal_life_numeric_v1 import WORK_KIND,TEMPLATE_VERSION,internal_life_numeric_ids_v1
from sylanne3.runtime_contracts import AuthorityContext
from sylanne3.host.authority_client import AuthorityClient,AuthoritySelection
from sylanne3.host.mtls_transport import MtlsAuthorityTransport
from sylanne3.host.astrbot_model_call import AstrBotModelProvider
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.model_broker.broker import ModelProviderDescriptor
from sylanne3.runtime.model_cost_settlement import read_original_model_cost,OriginalModelCostCommitV1
from sylanne3.authority_service.v2_model_egress_contract import ModelTerminalReceiptV2


def life_numeric_workflows(base,shared):
    common={f.name:getattr(base,f.name) for f in fields(base) if f.name not in {'version','life_numeric'}}
    return AdminModelWorkflowsV3(3,**common,life_numeric=AdminModelWorkflowV2(
        work_kind=WORK_KIND,purpose='consolidation',template_version=TEMPLATE_VERSION,
        max_output_tokens=2048,quote_ceiling={'input_tokens':16384,'output_tokens':2048},**shared))


def prepare_and_acquire(case):
    from sylanne3.runtime.d06_life_numeric_context_v1 import (PrepareLifeNumericContextRequestV1,
        life_numeric_context_ids_v1,decode_life_numeric_context_original_v1,KIND)
    from sylanne3.runtime.d06_life_numeric_task_v1 import PrepareInternalLifeNumericRequestV1,_identity
    from sylanne3.runtime.d06_life_numeric_worker_v1 import AcquireInternalLifeNumericRequestV1,read_committed_life_numeric_request_v1
    from sylanne3.runtime.d11_life_preparation_v1 import _read
    ns,store=case['namespace'],case['store']
    ep,causal=case['episode_ref'],case['life_causal_operation_id']
    context_ids=life_numeric_context_ids_v1(ns,ep)
    def run(kind,request,op):
        graph=case['graph']
        with numeric_owner(case) as (authority,lease):
            result=graph.run_current_domain_operation_v1(authority,lease,operation_kind=kind,
                request=request,operation_id=op,activity_id=case['life_activity_id'],
                audience_ref=case['life_audience'],parent_budget_lease_ref=case['policy'].root_grant.lease_id)
        if result.get('schema')!='sylanne.domain-production-receipt.v1':
            error=graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1
            if error is not None:traceback.print_exception(type(error),error,error.__traceback__)
        assert result['schema']=='sylanne.domain-production-receipt.v1'
        return result
    result=run('prepare_internal_life_numeric_context',PrepareLifeNumericContextRequestV1(ep,causal),context_ids['operation'])
    assert result['schema']=='sylanne.domain-production-receipt.v1'
    path=Path(store._db.execute('PRAGMA database_list').fetchone()[2])
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        saved=_read(db,namespace=ns,issuer=case['d11_issuer'],kind=KIND,ref=context_ids['original'])
        original=decode_life_numeric_context_original_v1(saved[0])
        ids=internal_life_numeric_ids_v1(_identity(original))
        assert db.total_changes==0
    request=PrepareInternalLifeNumericRequestV1(ep,causal)
    prepared=run('prepare_internal_life_numeric',request,ids['prepare'])
    assert prepared['job_states']==[[ids['job'],'queued']]
    assert run('prepare_internal_life_numeric',request,ids['prepare'])==prepared
    acquired=run('acquire_internal_life_numeric',AcquireInternalLifeNumericRequestV1(ep,causal),ids['acquire'])
    assert acquired['job_states']==[[ids['job'],'running']]
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        p,b,model=read_committed_life_numeric_request_v1(db,namespace=ns,issuer=case['d11_issuer'],job_id=ids['job'])
        assert b.worker_subject==model.envelope.authority.actor and model.identity.phase=='internal_life_numeric_v1'
        assert p.frozen.identity.before_digest==case['numeric_before'].digest and db.total_changes==0
    case['numeric_job_id']=ids['job']


async def run_installed_life_numeric_fullchain_v1(tmp_path,installed_d04_root):
    async def after(case):
        await asyncio.to_thread(prepare_and_acquire, case)
        graph,store,server=(case[k] for k in ('graph','store','server'))
        ns=case['namespace'];policy=case['policy'];port=case['port'];issuer=case['d11_issuer']
        bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
        fences=server._v2_fences[case['authority_namespace']]
        control=graph._actual_d04_authority_acceptance_v3.storage_control
        path=Path(store._db.execute('PRAGMA database_list').fetchone()[2]).resolve()
        owner=InstalledD12OwnerStorageAdmissionServiceV1(fences=fences,owner_tickets=server._v2_owner_tickets,
            graph_db_path=path,namespace_id=ns,installation_id=policy.installation_id,
            holder=policy.administrator_holder,control=control,close_apply=control._applied_reader)
        readers=InstalledD06StructuredExperienceReadersV1(issuer=issuer,resource_issuer=issuer.resource_issuer,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority)
        reader=InstalledLifeNumericModelGraphReaderV1(owner_storage=owner,structured_readers=readers,
            bundle=bundle,read_subject=case['client_grant'].subject)
        model=case['model_service'];verifier=model._graph_verifier
        from sylanne3.authority_service.current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
        location=InstalledCurrentSourceLocationQualifierV1(fences=fences,scoped=control._applied_reader.scoped,
            control=control,graph_db_path=path,namespace_id=ns,installation_id=policy.installation_id)
        model.install_current_source_location_v1(location)
        verifier.install_life_numeric_reader_v1(reader)
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
                    job=case['numeric_job_id']
                    prepared=read_life_numeric_prepared_v1(store._db,namespace=ns,issuer=issuer,job_id=job)
                    metadata,_=graph._v2_graph_stamp(ns)
                finally:store._db.rollback()
            authority=AuthorityContext(port.installation_grant.subject,'d11','life-numeric-read:'+prepared.digest,
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
                    return life_numeric_model_draft_v1(store._db,namespace=ns,issuer=issuer,job_id=job,
                        metadata=metadata,epoch=epoch)
                finally:store._db.rollback()
            value,anchor,_,_=graph._read_v2(authority,read,fence_observer=observe,return_recovery_context=True)
            return (*value,anchor)
        prepared,binding,request,draft,anchor=await asyncio.to_thread(draft_read)
        frozen=prepared.frozen
        from sylanne3.domains.d01.production_operations_v1 import plain_v1
        candidate=json.loads(explicit_subjective_reply(plain_v1(frozen.appraisal),0.5))
        candidate['facets'][0]['facet_id']='facet:internal-activity'
        candidate['facets'][0]['relation_meaning']='Possible subjective significance of the internal activity'
        for signal in candidate['mechanism_signals']:signal['facet_id']='facet:internal-activity'
        candidate['unknown_fields']=['identified_causal_affect']
        case['model_reply_mode']['content']=json.dumps(candidate)
        transport=MtlsAuthorityTransport({bundle.tls_profile.profile_id:bundle.tls_profile})
        client=AuthorityClient(AuthoritySelection(bundle.tls_profile.profile_id),package_root=installed_d04_root,
            data_dir=tmp_path,transport=transport)
        workflow=bundle.model_workflows.life_numeric
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
                        seal_life_numeric_call_v1(db,namespace=ns,issuer=issuer,
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
            from sylanne3.authority_service.life_numeric_model_result_service_v1 import InstalledLifeNumericModelResultServiceV1
            from sylanne3.runtime.d06_life_numeric_paid_v1 import (prepare_life_numeric_result_selector_v1,
                record_life_numeric_paid_result_v1,read_life_numeric_cost_commit_v1)
            from sylanne3.runtime.d06_life_numeric_task_v1 import (AdoptInternalLifeNumericRequestV1,
                ADOPT_OPERATION,read_life_numeric_appraisal_acceptance_v1)
            from sylanne3.runtime.jobs import get_job
            service=InstalledLifeNumericModelResultServiceV1(store=model._store,fences=fences,
                graph_db_path=path,d11_issuer=issuer,installation_id=policy.installation_id,
                read_subject=actual_grant.subject,holder=policy.administrator_holder,
                trusted_now_utc=verifier._clock,source_location=model._source_location,graph_reader=reader)
            server.install_life_numeric_model_result_reader_v1(case['authority_namespace'],service)
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
                authority=AuthorityContext(actual_grant.subject,'d11','life-numeric-read:'+prepared.digest,
                    ns,('activity','event','persona','scene'),'consolidation',(case['life_audience'],),
                    prepared.provider_config_ref,prepared.activation_generation)
                def transaction():
                    db=store._db;db.execute('BEGIN IMMEDIATE')
                    try:
                        value=action(db);db.commit();return value
                    except BaseException:db.rollback();raise
                return graph._read_v2(authority,transaction,fence_observer=observe)
            selector=await asyncio.to_thread(fenced_sql,lambda db:prepare_life_numeric_result_selector_v1(db,
                namespace=ns,issuer=issuer,job_id=prepared.job_id,authority_id=actual_grant.authority_id,
                authority_namespace=policy.authority_namespace))
            delivered=await client.life_numeric_model_result_read_v1(bundle,actual_grant,read_request=selector)
            delivered.require_original(intent,prepared,frozen,binding)
            _,read_state=await asyncio.to_thread(port.get_fence_operation,namespace=ns,
                authority_namespace=policy.authority_namespace,operation_id=selector.read_attempt_id)
            assert read_state=='finished' and not service._inflight_deliveries
            fact=await asyncio.to_thread(read_original_model_cost,graph._GraphCoordinator__model_terminal_cost_port,intent)
            def save_result(db):
                current=reader.read(db,intent,verifier._clock(),allow_accounted_result=True)
                assert (current.prepared,current.binding,current.frozen)==(prepared,binding,frozen)
                assert delivered.terminal_receipt==fact.receipt and delivered.observation.digest==fact.recovery.observation_digest
                read_life_numeric_cost_commit_v1(db,namespace=ns,issuer=issuer,prepared=prepared,intent=intent,terminal=terminal,fact=fact)
                return record_life_numeric_paid_result_v1(db,namespace=ns,issuer=issuer,job_id=prepared.job_id,result_read=delivered,fact=fact)
            await asyncio.to_thread(fenced_sql,save_result)
            operation='life-numeric-adopt:'+prepared.job_id.removeprefix('life-numeric-job:')
            locator=AdoptInternalLifeNumericRequestV1(prepared.episode_ref,
                prepared.causal_operation_id)
            def adopt():
                with numeric_owner(case) as (authority,lease):
                    result=graph.run_current_domain_operation_v1(authority,lease,operation_kind=ADOPT_OPERATION,
                        request=locator,operation_id=operation,activity_id=prepared.activity_id,
                        audience_ref=case['life_audience'],parent_budget_lease_ref=policy.root_grant.lease_id)
                runtime=graph._GraphCoordinator__domain_production_runtime_v1
                if result.get('schema')!='sylanne.domain-production-receipt.v1':
                    error=runtime._last_refusal_exception_v1
                    if error is not None:traceback.print_exception(type(error),error,error.__traceback__)
                assert result['schema']=='sylanne.domain-production-receipt.v1'
                assert len(result['receipt']['write_versions'])==2 and not store._db.in_transaction
                return result
            adopted=await asyncio.to_thread(adopt)
            def cold_appraisal():
                with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
                    db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
                    rows=db.execute("SELECT original_ref FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind='numeric_appraisal_acceptance_v1'",ns.as_tuple).fetchall()
                    assert len(rows)==1
                    acceptance=read_life_numeric_appraisal_acceptance_v1(db,namespace=ns,appraisal_ref=rows[0][0],issuer=issuer)
                    assert acceptance.job_id==prepared.job_id and acceptance.before_digest==case['numeric_before'].digest
                    assert acceptance.operation_id==operation and db.total_changes==0
                    return acceptance
            acceptance=await asyncio.to_thread(cold_appraisal)
            assert await asyncio.to_thread(adopt)==adopted and len(calls)==1
            from d04_numeric_life_acceptance_support_v1 import run_life_numeric_interval_acceptance_v1
            await run_life_numeric_interval_acceptance_v1(case,tmp_path=tmp_path,
                installed_d04_root=installed_d04_root,appraisal_ref=acceptance.appraisal_ref)
            assert len(calls)==1
        finally:
            mock.handler=actual_handler
            verifier._current=original_current
            await transport.close()
    await run_installed_life_before_case(tmp_path,installed_d04_root,
        natural_workflow_builder=life_numeric_workflows,after_before_async=after,
        enable_d04_semantic_drive=True,enable_d04_joint_numeric=True)


@pytest.mark.asyncio
async def test_installed_life_numeric_original_paid_native_interval_and_trace(tmp_path,installed_d04_root):
    await run_installed_life_numeric_fullchain_v1(tmp_path,installed_d04_root)
