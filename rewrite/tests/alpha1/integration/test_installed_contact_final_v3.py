"""Actual installed Contact paid jobs, finite HTTP mock and original recovery.

The donor provisions real Owner/Core/Graph/TLS/quotes. Host RuntimeContext
fields are assembled around that same installation by the fixture, rather
than invoking full Host startup. GraphWorker, provider, Authority fences,
terminal accounting, result reader and business COMMIT are product code.
This new node adds actual final3 eleven-member admission and durable readback.
There is no platform send.
"""
import asyncio
import json
import traceback
from dataclasses import replace

import pytest

from test_installed_contact_external_v2 import installed_d04_root,run_external_contact_plan_case
from test_installed_contact_paid_v2 import paid_workflows
from test_current_domain_production_v1 import command,domain_owner
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
from sylanne3.host.authority_profile import AdminPrivateReplyDispatchPolicy


async def run_installed_contact_final3_case(tmp_path,installed_d04_root, *, validation_mode='basic', after_final_async=None):
    def install_current_contact_boundary(case, route, audience, now):
        # Proactive D05 qualification requires an independently adopted
        # current permission rule. A complete empty boundary query is not
        # permission, even after the Owner has approved the D10 quota policy.
        from sylanne3.runtime.d05_production_operations_v1 import InstalledRelationshipPolicyV1, BoundaryIntentOriginalV1
        from sylanne3.runtime.domain_production_inputs_v1 import InstallCurrentRelationshipInputRequestV1, RegisterCurrentBoundaryInputRequestV1
        from sylanne3.domains.d05.relationship import BoundaryRule
        from sylanne3.domains.d05.production_operations_v1 import ReviseCurrentBoundaryRequestV1
        from sylanne3.graph_types import AtomKey, Owner
        ns = case['namespace']
        registration = case['domain_registry'].registrations['d05']
        if 'd05' not in case['graph']._GraphCoordinator__providers:
            case['graph'].register_provider(case['bootstrap'], 'd05', registration.provider,
                registration.proposal_schema, registration.proposal_schema_hash)
        policy = InstalledRelationshipPolicyV1('relationship-policy:contact-final3', 1, ns,
            ('familiarity',), ('external_observation',), ('runtime_policy',))
        command(case, 'install_relationship_policy', InstallCurrentRelationshipInputRequestV1(policy), producer=True)
        rule = BoundaryRule('boundary:contact-final3', 'persona:' + ns.persona_id,
            route['entity_id'], 'message', audience, None, 'allow', 'runtime_policy',
            (case['source_ref'],), (), (), now - 60, now + 3600, 1, 'owner-actor-reply', (), 'active')
        key = AtomKey(Owner('relation', *ns.as_tuple, route['entity_id']), 'd05.boundary_rule', rule.rule_id)
        intent_ref = 'boundary-intent:contact-final3'
        registered = command(case, 'register_boundary_intent', RegisterCurrentBoundaryInputRequestV1(
            intent_ref, BoundaryIntentOriginalV1(key.token, 0, rule, (), ())), audience=audience, producer=True)
        assert registered['coverage'] == 'complete'
        revised = command(case, 'revise_boundary', ReviseCurrentBoundaryRequestV1(
            key.token, intent_ref, policy.policy_ref), audience=audience)
        assert revised['coverage'] == 'complete'
    async def after_plan(case,plan,expression,cause):
        from sylanne3.runtime.contact_qualification_evidence_v3 import ContactQualificationEvidenceV3
        from sylanne3.runtime.contact_final_action_v1 import CONTACT_REQUIRED_PROVIDERS_V1
        original_structure = ContactQualificationEvidenceV3.validate_structure
        def diagnosed_structure(value):
            try:
                return original_structure(value)
            except Exception:
                q = value.qualification
                # Fixed labels and booleans only: no ref, body, permit, key,
                # request payload or actual authorization identifier output.
                print('CONTACT3_QUALIFICATION_CLOSURE', {
                    'namespace_epoch_matches': (q.check_versions.namespace == value.namespace,
                        q.check_versions.graph_epoch == value.graph_epoch),
                    'six_checks_sets': (len(q.checks) == 6, len(q.check_versions.sets) == 6),
                    'provider_order_exact': tuple((c.check_kind,c.issuer) for c in q.checks) == CONTACT_REQUIRED_PROVIDERS_V1,
                    'version_set_kinds_exact': {r.kind for r in q.check_versions.sets} == {k for k,_ in CONTACT_REQUIRED_PROVIDERS_V1},
                    'command_live': value.now_utc < value.deadline_utc,
                    'checks': tuple((label, c.coverage == 'full', c.result == 'pass',
                        c.purpose == 'expression', c.subject_ref == 'persona:' + value.namespace.persona_id,
                        c.action_ref == q.d08_scope.action_id, c.valid_until <= value.now_utc,
                        c.valid_until > value.deadline_utc)
                        for (label,_),c in zip(CONTACT_REQUIRED_PROVIDERS_V1,q.checks))}, flush=True)
                raise
        ContactQualificationEvidenceV3.validate_structure = diagnosed_structure
        graph,store=(case[k] for k in ('graph','store'))
        bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
        assert type(bundle.private_reply_dispatch) is AdminPrivateReplyDispatchPolicy
        assert 'message' in bundle.installation_policy.root_grant.allowed_work_kinds
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
                if method in {'contact_model_result_read_v2','contact_model_result_recover_finish_v2','begin_fence',
                        'capture_current_contact_owner_session_v3','associate_contact_owner_recovery_v3'}:
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
            from sylanne3.runtime.contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3, verify_contact_final_committed_v3, _CONTACT_FINAL_WRITE_TYPES
            from sylanne3.domains.d08.contact_plan_v1 import contact_segment_ids_v1
            from sylanne3.graph_types import AtomKey
            ids=contact_segment_ids_v1(plan.contact_id,0)
            retained_owner={}
            def finalize(_graph):
                try:
                    if validation_mode in {'recovery','restart'}:
                        # Same-process interrupted-call recovery retains the
                        # actual authenticated Owner lease. A new Owner read
                        # cannot begin while this original write is active.
                        if not retained_owner:
                            manager=domain_owner(case)
                            authority,lease=manager.__enter__()
                            retained_owner.update(manager=manager,authority=authority,lease=lease)
                        result=graph.run_current_domain_operation_v1(retained_owner['authority'],retained_owner['lease'],
                            operation_kind='prepare_contact_dispatch_v3',request=PrepareCurrentContactDispatchRequestV3(plan.contact_id),
                            operation_id=ids['operation'],activity_id=plan.activity_id,audience_ref=plan.audience_id,
                            parent_budget_lease_ref=case['policy'].root_grant.lease_id)
                    else:
                        result=command(case,'prepare_contact_dispatch_v3',PrepareCurrentContactDispatchRequestV3(plan.contact_id),
                            operation_id=ids['operation'],activity_id=plan.activity_id,audience=plan.audience_id)
                except Exception:
                    error=graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1
                    if error is not None:traceback.print_exception(type(error),error,error.__traceback__)
                    raise
                assert result['coverage']=='complete'
                members=result['receipt']['write_versions']
                assert len(members)==11 and {AtomKey.from_token(row[0]).type_name for row in members}==_CONTACT_FINAL_WRITE_TYPES
                assert not store._db.in_transaction
                store._db.execute('BEGIN')
                try:verify_contact_final_committed_v3(store._db,namespace=plan.namespace,result=result,
                    issuer=case['d11_issuer'],graph=graph)
                finally:store._db.rollback()
                return result
            if validation_mode=='post_cas_negative':
                from sylanne3.runtime import contact_qualification_v3 as qualification_module
                actual_issue=qualification_module.issue_contact_checks_locked_v3
                injected={'hit':False}
                def added_claim(*args,**kwargs):
                    read=kwargs['current_read'];db=args[0]
                    if read.phase=='post_cas_e_plus_1' and not injected['hit']:
                        assert db.in_transaction and store._lock._is_owned()
                        row=db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d10.contact_claim.v2' AND valid=1",plan.namespace.as_tuple).fetchone()
                        assert row is not None
                        value=json.loads(row[0]);value['contact_id']='contact:injected-negative-row'
                        from sylanne3.domains.d10.contact_claim_v2 import contact_claim_key_v2,decode_contact_claim_v2
                        decode_contact_claim_v2(value)
                        key=contact_claim_key_v2(plan.namespace,value['contact_id'])
                        from sylanne3.runtime_contracts import canonical_serialize
                        db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',
                            (key.token,*plan.namespace.as_tuple,key.owner.kind,key.owner.subject,key.type_name,key.name,1,canonical_serialize(value),1))
                        injected['hit']=True
                    return actual_issue(*args,**kwargs)
                qualification_module.issue_contact_checks_locked_v3=added_claim
                try:
                    with pytest.raises((ValueError,AssertionError)):
                        await worker.call(finalize)
                finally:qualification_module.issue_contact_checks_locked_v3=actual_issue
                assert injected['hit'] and len(calls)==2
                refusal=graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1
                from sylanne3.runtime.d01_production_operations_v1 import MissingProductionOriginalV1
                assert isinstance(refusal,MissingProductionOriginalV1)
                assert refusal.missing_inputs==('current_query_coverage:d10.contact_claim.v2',)
                def rollback_inventory(_graph):
                    assert not store._db.in_transaction
                    assert store._db.execute('SELECT 1 FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND operation_id=?',
                        (*plan.namespace.as_tuple,ids['operation'])).fetchone() is None
                    assert store._db.execute("SELECT COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? AND type_name IN ('d09.contact_verified_batch.v3','d09.contact_batch_provenance.v3','d09.contact_batch_eligibility.v3','d10.contact_claim.v2')",
                        plan.namespace.as_tuple).fetchone()==(0,)
                await worker.call(rollback_inventory)
                assert await cost_snapshot(generation)==generation_cost
                assert await cost_snapshot(review)==review_cost
                return
            if validation_mode in {'recovery','restart'}:
                from sylanne3.runtime import contact_final_ack_v1 as ack_module
                actual_before_finish=ack_module.verify_contact_before_finish_v1
                injected={'hit':False}
                def crash_after_independent_verification(call,scope,result):
                    actual_before_finish(call,scope,result)
                    if call.operation_id==ids['operation'] and not injected['hit']:
                        injected['hit']=True
                        raise RuntimeError('controlled_contact3_after_commit_before_finish')
                ack_module.verify_contact_before_finish_v1=crash_after_independent_verification
                try:
                    with pytest.raises(RuntimeError,match='controlled_contact3_after_commit_before_finish'):
                        await worker.call(finalize)
                finally:ack_module.verify_contact_before_finish_v1=actual_before_finish
                assert injected['hit']
                def pending_commit(_graph):
                    from sylanne3.runtime_contracts import canonical_digest
                    from sylanne3.authority_service.v2_contract import from_wire
                    row=store._db.execute('SELECT attempt_id,permit_json,receipt_json FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',
                        (*plan.namespace.as_tuple,ids['operation'])).fetchone()
                    assert row and row[2]
                    saved=json.loads(row[2]);assert len(saved['receipt']['write_versions'])==11
                    permit=from_wire(json.loads(row[1]))
                    actual,state=graph._GraphCoordinator__content_fence_v2.get_fence_operation(namespace=plan.namespace,
                        authority_namespace=permit.namespace,operation_id=row[0])
                    assert actual==permit and state=='active'
                    return canonical_digest(saved),row[0]
                saved_digest,final_attempt_id=await worker.call(pending_commit)
                if validation_mode=='restart':
                    from contact_restart_process_support_v3 import run_contact_restart_process_v3
                    await run_contact_restart_process_v3(case,worker,retained_owner,
                        operation_id=ids['operation'],expected_digest=saved_digest)
                    assert len(calls)==2
                    return
                from sylanne3.runtime import contact_saved_owner_projection_v3 as saved_owner
                actual_saved_reader=saved_owner._read_saved_contact_owner_projection_v3
                negatives={'ran':False}
                def saved_reader_with_refusals(call,scope,result,owner,session):
                    if negatives['ran']:
                        return actual_saved_reader(call,scope,result,owner,session)
                    from sylanne3.runtime_contracts import canonical_serialize,NamespaceId
                    from sylanne3.graph_coordinator import UnavailableGuard,StaleRead,AuthorityDenied
                    failures=(ValueError,TypeError,UnavailableGuard,StaleRead,AuthorityDenied)
                    original_scope=canonical_serialize(scope);original_permit=scope.permit
                    # Rehashed public values cannot stand in for durable SQL.
                    with pytest.raises(failures):
                        actual_saved_reader(call,scope,{**result,'coverage':'deferred'},owner,session)
                    with pytest.raises(failures):
                        actual_saved_reader(call,replace(scope,graph_revision=scope.graph_revision+1),result,owner,session)
                    with pytest.raises(failures):
                        actual_saved_reader(call,replace(scope,namespace=NamespaceId('other',scope.namespace.persona_id)),result,owner,session)
                    with pytest.raises(failures):
                        actual_saved_reader(call,scope,result,replace(owner,revocation_epoch=owner.revocation_epoch+1),session)
                    assert not store._db.in_transaction
                    # Deliberate temporary SQL damage, restored byte for byte.
                    # This is not an Owner revocation or generation transition.
                    def damaged(sql,params,restore_sql,restore_params):
                        store._db.execute(sql,params)
                        try:
                            with pytest.raises(failures):actual_saved_reader(call,scope,result,owner,session)
                        finally:store._db.execute(restore_sql,restore_params)
                    where=(*plan.namespace.as_tuple,ids['operation'])
                    row=store._db.execute('SELECT request_digest,permit_json FROM graph_owner_domain_attempts_v3 '
                        'WHERE bot=? AND persona=? AND operation_id=?',where).fetchone()
                    for field,changed,old in (('request_digest','b'*64,row[0]),('permit_json','{}',row[1])):
                        sql='UPDATE graph_owner_domain_attempts_v3 SET '+field+'=? WHERE bot=? AND persona=? AND operation_id=?'
                        damaged(sql,(changed,*where),sql,(old,*where))
                    epoch=store._db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?',plan.namespace.as_tuple).fetchone()[0]
                    sql='UPDATE graph_epochs SET revision=? WHERE bot=? AND persona=?'
                    damaged(sql,(epoch+1,*plan.namespace.as_tuple),sql,(epoch,*plan.namespace.as_tuple))
                    member=store._db.execute("SELECT token,valid FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d09.contact_batch_eligibility.v3'",
                        plan.namespace.as_tuple).fetchone()
                    damaged('UPDATE graph_atoms SET valid=0 WHERE token=?',(member[0],),
                        'UPDATE graph_atoms SET valid=? WHERE token=?',(member[1],member[0]))
                    actual_port=graph._GraphCoordinator__content_fence_v2
                    current_clock=actual_port.read_ingress_clock
                    for expired_call in (1,2):
                        count={'n':0}
                        def expired_clock(*args,**kwargs):
                            value=current_clock(*args,**kwargs);count['n']+=1
                            # Typed verified-clock transport seam; not a claim
                            # that the real service emitted an expired sample.
                            return replace(value,utc_upper_bound_seconds=value.utc_upper_bound_seconds+10000.) if count['n']==expired_call else value
                        actual_port.read_ingress_clock=expired_clock
                        try:
                            with pytest.raises(ValueError,match='expired'):
                                actual_saved_reader(call,scope,result,owner,session)
                        finally:actual_port.read_ingress_clock=current_clock
                    owner_rpc=actual_port.get_current_owner_authority_for_fence_v1
                    requirements=store._db.execute('SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',plan.namespace.as_tuple).fetchone()[0]
                    def drift_after_rpc(*args,**kwargs):
                        assert not store._db.in_transaction and not store._lock._is_owned()
                        value=owner_rpc(*args,**kwargs)
                        raw=json.loads(requirements);raw['activation_generation']+=1
                        store._db.execute('UPDATE graph_recovery_metadata_v2 SET requirements_json=? WHERE bot=? AND persona=?',
                            (canonical_serialize(raw),*plan.namespace.as_tuple))
                        return value
                    actual_port.get_current_owner_authority_for_fence_v1=drift_after_rpc
                    try:
                        with pytest.raises(failures):actual_saved_reader(call,scope,result,owner,session)
                    finally:
                        actual_port.get_current_owner_authority_for_fence_v1=owner_rpc
                        store._db.execute('UPDATE graph_recovery_metadata_v2 SET requirements_json=? WHERE bot=? AND persona=?',
                            (requirements,*plan.namespace.as_tuple))
                    assert canonical_serialize(scope)==original_scope and scope.permit is original_permit
                    actual,state=actual_port.get_fence_operation(namespace=scope.namespace,
                        authority_namespace=scope.authority_namespace,operation_id=scope.operation_id)
                    assert actual==scope.permit and state=='active'
                    negatives['ran']=True
                    return actual_saved_reader(call,scope,result,owner,session)
                saved_owner._read_saved_contact_owner_projection_v3=saved_reader_with_refusals
            if validation_mode=='recovery':
                actual_port=graph._GraphCoordinator__content_fence_v2
                actual_finish_rpc=actual_port._transport.v2_finish_fence
                lost_ack={'calls':0,'hit':False}
                async def finish_then_lose_ack(request,handshake,permit,**kwargs):
                    value=await actual_finish_rpc(request,handshake,permit,**kwargs)
                    if permit.operation_id==final_attempt_id:
                        lost_ack['calls']+=1
                        if not lost_ack['hit']:
                            lost_ack['hit']=True
                            raise RuntimeError('controlled_contact3_lost_finish_ack')
                    return value
                actual_port._transport.v2_finish_fence=finish_then_lose_ack
            try:
                if validation_mode=='recovery':
                    with pytest.raises(RuntimeError,match='controlled_contact3_lost_finish_ack'):
                        await worker.call(finalize)
                    assert lost_ack['hit'] and lost_ack['calls']==1
                    assert actual_port._pending_finish is not None
                final=await worker.call(finalize)
            finally:
                if validation_mode=='recovery':saved_owner._read_saved_contact_owner_projection_v3=actual_saved_reader
            assert final['contact_admission_ref'] and len(calls)==2
            assert await cost_snapshot(generation)==generation_cost
            assert await cost_snapshot(review)==review_cost
            if after_final_async is not None:
                await after_final_async(case, worker, runtime, assembly, plan, final)
            if validation_mode=='finished_readonly':
                from contact_finished_owner_read_support_v1 import run_finished_contact_owner_read_case_v1
                await run_finished_contact_owner_read_case_v1(case,worker,
                    operation_id=ids['operation'],expected=final,model_calls=calls)
            if validation_mode=='recovery':
                assert negatives['ran'] and lost_ack['calls']==1 and actual_port._pending_finish is None
                def current_cold_and_refusals(_graph):
                    import sqlite3
                    from pathlib import Path
                    from sylanne3.runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
                    assert canonical_digest(final)==saved_digest
                    path=Path(store._db.execute('PRAGMA database_list').fetchone()[2])
                    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as cold:
                        cold.execute('PRAGMA query_only=ON');cold.execute('BEGIN')
                        verify_contact_final_committed_v3(cold,namespace=plan.namespace,result=final,issuer=case['d11_issuer'],graph=graph)
                        assert cold.total_changes==0
                        with pytest.raises(ValueError):
                            verify_contact_final_committed_v3(cold,namespace=NamespaceId('other',plan.namespace.persona_id),
                                result=final,issuer=case['d11_issuer'],graph=graph)
                    def refused(change):
                        store._db.execute('BEGIN')
                        try:
                            change(store._db)
                            with pytest.raises((ValueError,TypeError)):
                                verify_contact_final_committed_v3(store._db,namespace=plan.namespace,result=final,
                                    issuer=case['d11_issuer'],graph=graph)
                        finally:store._db.rollback()
                    def generation(db):
                        raw=db.execute('SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',plan.namespace.as_tuple).fetchone()[0]
                        data=json.loads(raw);data['activation_generation']+=1
                        db.execute('UPDATE graph_recovery_metadata_v2 SET requirements_json=? WHERE bot=? AND persona=?',
                            (canonical_serialize(data),*plan.namespace.as_tuple))
                    refused(generation)
                    def revoked_source(db):
                        from sylanne3.memory_types import access_key
                        key=access_key(*plan.namespace.as_tuple,AtomKey.from_token(case['source_ref']).owner.subject)
                        raw=json.loads(db.execute('SELECT value FROM graph_atoms WHERE token=?',(key.token,)).fetchone()[0]);raw['status']='withdrawn'
                        db.execute('UPDATE graph_atoms SET value=? WHERE token=?',(canonical_serialize(raw),key.token))
                    refused(revoked_source)
                    def negative_inventory(db):
                        from sylanne3.domains.d10.contact_claim_v2 import contact_claim_key_v2,decode_contact_claim_v2
                        raw=json.loads(db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d10.contact_claim.v2'",plan.namespace.as_tuple).fetchone()[0])
                        raw['contact_id']='contact:cold-extra';decode_contact_claim_v2(raw)
                        key=contact_claim_key_v2(plan.namespace,raw['contact_id'])
                        db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',
                            (key.token,*plan.namespace.as_tuple,key.owner.kind,key.owner.subject,key.type_name,key.name,1,canonical_serialize(raw),1))
                    refused(negative_inventory)
                    tables=('graph_dispatch_admissions','runtime_jobs','graph_bundle_outbox',
                        'graph_domain_production_originals_v1','runtime_budget_reservations','runtime_budget_operations')
                    counts=tuple((table,store._db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]) for table in tables)
                    seq=store._db.execute('SELECT commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
                        (*plan.namespace.as_tuple,ids['operation'])).fetchone()[0]
                    return seq,counts
                seq,counts=await worker.call(current_cold_and_refusals)
                replay=await worker.call(finalize)
                assert replay==final and len(calls)==2 and lost_ack['calls']==1
                assert await cost_snapshot(generation)==generation_cost
                assert await cost_snapshot(review)==review_cost
                def unchanged(_graph):
                    from sylanne3.authority_service.v2_contract import from_wire
                    assert store._db.execute('SELECT commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
                        (*plan.namespace.as_tuple,ids['operation'])).fetchone()==(seq,)
                    row=store._db.execute('SELECT attempt_id,permit_json FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',
                        (*plan.namespace.as_tuple,ids['operation'])).fetchone()
                    permit=from_wire(json.loads(row[1]))
                    actual,state=graph._GraphCoordinator__content_fence_v2.get_fence_operation(namespace=plan.namespace,
                        authority_namespace=permit.namespace,operation_id=row[0])
                    assert actual==permit and state=='finished'
                    assert tuple((table,store._db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]) for table,_ in counts)==counts
                await worker.call(unchanged)
        except Exception:
            # Preserve the primary chain before donor close may report its
            # separately unresolved fence. Never print request/body/locals.
            traceback.print_exc()
            raise
        finally:
            if 'actual_finish_rpc' in locals():actual_port._transport.v2_finish_fence=actual_finish_rpc
            ContactQualificationEvidenceV3.validate_structure = original_structure
            transport.handler=original_handler
            reader.prepare=original_prepare
            case['server']._v2_command=original_rpc
            result_codec.contact_result_to_wire_v2=actual_result_wire
            if 'retained_owner' in locals() and retained_owner:
                await worker.call(lambda _graph:retained_owner['manager'].__exit__(None,None,None))
            await worker.close()
    await run_external_contact_plan_case(tmp_path,installed_d04_root,
        workflow_builder=paid_workflows,before_plan=install_current_contact_boundary,after_plan_async=after_plan,
        private_reply_dispatch_policy=AdminPrivateReplyDispatchPolicy(
            120.0, {'cpu_ms': 1}, 'snapshot:reply-dispatch',
            'resource:reply-dispatch', 800, 120.0))


@pytest.mark.asyncio
async def test_installed_contact_paid2_final3_actual_eleven_member_commit(tmp_path,installed_d04_root):
    await run_installed_contact_final3_case(tmp_path,installed_d04_root)
