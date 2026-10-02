"""Actual installed Contact paid jobs, finite HTTP mock and original recovery.

The donor provisions real Owner/Core/Graph/TLS/quotes. Host RuntimeContext
fields are assembled around that same installation by the fixture, rather
than invoking full Host startup. GraphWorker, provider, Authority fences,
terminal accounting, result reader and business COMMIT are product code.
There is no platform send or final dispatch admission in this node.
"""
import asyncio
import json
import traceback
from dataclasses import replace

import pytest

from test_installed_contact_external_v2 import installed_d04_root,run_external_contact_plan_case
from test_installed_contact_paid_v2 import paid_workflows
from test_current_domain_production_v1 import command
from sylanne3.graph_worker import GraphWorker
from sylanne3.runtime_context import RuntimeContext
from sylanne3.host.v2_installation import V2InstallationAssembly
from sylanne3.host.installed_contact_model_driver_v2 import run_installed_contact_model_v2
from sylanne3.runtime.contact_product_adapter_v2 import PrepareCurrentContactModelRequestV2
from sylanne3.runtime.contact_model_job_v2 import contact_model_ids_v2
from sylanne3.runtime.contact_paid_original_v2 import require_contact_original_v2
from sylanne3.runtime.jobs import get_job
from sylanne3.model_broker.contact_expression_v2 import OUTPUT_SCHEMA,REVIEW_OUTPUT_SCHEMA
from sylanne3.authority_service import contact_model_result_contract_v2 as result_codec


@pytest.mark.asyncio
async def test_installed_contact_v2_actual_generation_review_and_once_replay(tmp_path,installed_d04_root):
    async def after_plan(case,plan,expression,cause):
        graph,store=(case[k] for k in ('graph','store'))
        bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
        worker=await GraphWorker.start(lambda:store,lambda actual_store:graph)
        assembly=V2InstallationAssembly(bundle.installation_policy,case['client_grant'],
            bundle.d11_signing_key,bundle.d02_signing_key,lambda:case['port'],
            installed_d04_root,tmp_path,ingress_clock=bundle.ingress_clock,
            ingress_encoding=bundle.ingress_encoding,admin_bundle=bundle)
        runtime=RuntimeContext(tmp_path,package_root=installed_d04_root,dependencies=None)
        runtime._worker=worker;runtime._v2_bootstrap=case['bootstrap'];runtime._v2_port=case['port']
        runtime._v2_namespace_provisioned=True;runtime._v2_model_bundle=bundle
        runtime._v2_policy=bundle.installation_policy;runtime._v2_installation_grant=case['client_grant']
        # The TLS service intentionally hides refusal details. Preserve only
        # the real product stack at this test-owned service, never its locals.
        reader=case['server']._contact_model_reads_v2[case['authority_namespace']]
        original_prepare=reader.prepare
        prepared_deliveries=[]
        def diagnosed_prepare(*args,**kwargs):
            try:
                delivery=original_prepare(*args,**kwargs)
                prepared_deliveries.append(delivery)
                return delivery
            except Exception:
                traceback.print_exc();raise
        reader.prepare=diagnosed_prepare
        original_rpc=case['server']._v2_command
        def diagnosed_rpc(method,*args,**kwargs):
            try:return original_rpc(method,*args,**kwargs)
            except Exception:
                if method in {'contact_model_result_read_v2','contact_model_result_recover_finish_v2'}:
                    traceback.print_exc()
                raise
        case['server']._v2_command=diagnosed_rpc
        actual_result_wire=result_codec.contact_result_to_wire_v2
        inject_encoding_failure=[True]
        def encode_with_one_failure(value):
            if type(value) is result_codec.ContactModelResultReadV2 and inject_encoding_failure[0]:
                inject_encoding_failure[0]=False
                raise ValueError('test-controlled post-prepare response encoding failure')
            return actual_result_wire(value)
        result_codec.contact_result_to_wire_v2=encode_with_one_failure
        transport=case['model_http_client']._transport
        assert type(transport).__name__=='MockTransport'
        original_handler=transport.handler;calls=[]
        def counted(request):
            calls.append(request.url.host)
            return original_handler(request)
        transport.handler=counted
        async def prepare(phase):
            ids=contact_model_ids_v2(plan,phase)
            def perform(_graph):
                try:return command(case,'prepare_contact_model_v2',
                    PrepareCurrentContactModelRequestV2(plan.contact_id,phase),
                    operation_id=ids['prepare'],activity_id=plan.activity_id,audience=plan.audience_id)
                except AssertionError:
                    error=graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1
                    traceback.print_exception(type(error),error,error.__traceback__);raise
            result=await worker.call(perform)
            assert result['coverage']=='deferred'
            return ids
        async def drive(phase):
            return await run_installed_contact_model_v2(runtime,assembly,context=case['model_context'],
                trusted_umo=json.loads(plan.audience_id)[0],
                contact_id=plan.contact_id,phase=phase)
        async def cost_snapshot(ids):
            def inspect(_graph):
                ns=plan.namespace.as_tuple
                operations=store._db.execute('SELECT phase,digest,receipt_json FROM runtime_budget_operations '
                    'WHERE bot_id=? AND persona_id=? AND operation_id=? ORDER BY phase',
                    (*ns,ids['prepare'])).fetchall()
                assert [row[0] for row in operations]==['reserve','settle']
                paid,_=require_contact_original_v2(store._db,case['d11_issuer'],plan.namespace,'paid_cost',ids['job'])
                commits=store._db.execute('SELECT operation_id,commit_seq,receipt_json FROM graph_bundle_operations '
                    'WHERE bot=? AND persona=? AND operation_id=?',(*ns,paid['cost_operation_id'])).fetchall()
                assert len(commits)==1 and commits[0][1]>0
                return operations,commits,paid
            return await worker.call(inspect)
        def same_original_progress(replayed,original):
            # The generic cost API labels a recovered ACK duplicate; the
            # durable SQL original remains committed. All original fields and
            # the SQL reserve/settle/commit bytes must still be identical.
            assert replayed.cost.status in {'committed','duplicate'}
            assert original.cost.status in {'committed','duplicate'}
            assert replace(replayed,cost=replace(replayed.cost,status=original.cost.status))==original
        try:
            generation=await prepare('contact_generation')
            unit=expression.units[0];body=unit.qualified_text
            case['model_reply_mode']['content']=json.dumps({'schema':OUTPUT_SCHEMA,'segments':[
                {'body':body,'units':[{'start':0,'end':len(body),'kind':unit.kind.value,
                    'basis_ids':[unit.basis_id],'speech_act':'paraphrase','promise_grant_id':None,
                    'slot_ids':list(plan.required_slots)}]}]})
            with pytest.raises(RuntimeError,match='authority service unavailable'):
                await drive('contact_generation')
            assert not inject_encoding_failure[0] and len(calls)==1
            assert len(prepared_deliveries)==1
            unresolved=prepared_deliveries[0]
            assert unresolved.result.request.read_attempt_id not in reader._inflight_deliveries
            with reader._fences.core._tx() as db:
                assert reader._fences.fences._row(db,unresolved.result.request.read_attempt_id)[6]=='active'
            generation_cost_after_failure=await cost_snapshot(generation)
            generated=await drive('contact_generation')
            assert generated.status=='review_required' and generated.cost is not None
            assert len(calls)==1
            generation_cost=await cost_snapshot(generation)
            assert generation_cost==generation_cost_after_failure
            with reader._fences.core._tx() as db:
                assert reader._fences.fences._row(db,unresolved.result.request.read_attempt_id)[6]=='finished'
            same_original_progress(await drive('contact_generation'),generated)
            assert len(calls)==1
            assert await cost_snapshot(generation)==generation_cost
            review=await prepare('contact_review')
            case['model_reply_mode']['content']=json.dumps({'schema':REVIEW_OUTPUT_SCHEMA,'verdict':'pass','issues':[]})
            reviewed=await drive('contact_review')
            assert reviewed.status=='whole_batch_paid_pass' and len(calls)==2
            review_cost=await cost_snapshot(review)
            same_original_progress(await drive('contact_review'),reviewed)
            assert len(calls)==2
            assert await cost_snapshot(review)==review_cost
            def inspect(_graph):
                for ids in (generation,review):
                    assert get_job(store._db,ids['job']).phase=='completed'
                    for kind in ('paid_cost','result','terminal'):
                        assert require_contact_original_v2(store._db,case['d11_issuer'],plan.namespace,kind,ids['job'])
            await worker.call(inspect)
        finally:
            transport.handler=original_handler
            reader.prepare=original_prepare
            case['server']._v2_command=original_rpc
            result_codec.contact_result_to_wire_v2=actual_result_wire
            await worker.close()
    await run_external_contact_plan_case(tmp_path,installed_d04_root,
        workflow_builder=paid_workflows,after_plan_async=after_plan)
