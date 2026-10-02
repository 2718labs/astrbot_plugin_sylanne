"""Actual installed Life V2 admission/provider/accounting on the donor installation.

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

@pytest.mark.asyncio
async def test_installed_life_v2_model_terminal_and_cost_once(tmp_path,installed_d04_root):
    async def after(case):
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
        reader=InstalledInternalLifeModelGraphReaderV2(owner_storage=owner,structured_readers=readers,
            bundle=bundle,read_subject=case['client_grant'].subject)
        model=case['model_service'];verifier=model._graph_verifier
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
        finally:
            mock.handler=actual_handler;verifier._current=original_current;await transport.close()
    await run_installed_life_content_preparation_case(tmp_path,installed_d04_root,
        acquire=True,worker_v2=True,after_acquire=after)
