"""Real installed Contact originals cannot bypass the closed P2 gate.

The existing finite HTTP fixture produces the original paid generation and
review and actual eleven-member COMMIT. No platform/model user is contacted.
This permanent negative node does not establish positive sender acceptance.
"""
import asyncio
import pytest

from test_installed_contact_final_v3 import installed_d04_root, run_installed_contact_final3_case


@pytest.mark.asyncio
async def test_installed_contact_sender_original_and_closed_p2_gate(tmp_path, installed_d04_root):
    from sylanne3.host.contact_dispatch_driver_v3 import ContactDispatchDriverV3, OriginalContactDispatchV3
    from sylanne3.runtime.contact_dispatch_host_v3 import commit_contact_dispatch_final_claim_v3
    from sylanne3.runtime_contracts import AuthorityContext

    async def after_final(case, worker, runtime, assembly, plan, final):
        graph, store, bootstrap = case['graph'], case['store'], case['bootstrap']
        policy, grant = assembly.installation_policy, assembly.installation_grant
        tracked = ('graph_dispatch_admissions', 'graph_domain_production_originals_v1',
            'graph_bundle_outbox', 'runtime_jobs', 'runtime_budget_operations', 'runtime_budget_reservations')

        def install(actual):
            assert actual is graph
            anchor = case['port'].current_anchor(namespace=plan.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(bootstrap, actor=grant.administrator_holder,
                issuer_domain='d11', namespace=plan.namespace,
                domains=('d03', 'd05', 'd06', 'd08', 'd09', 'd10', 'd11'),
                activation_generation=anchor.activation_generation, operation_id=final['operation_id'])
            authority = AuthorityContext(grant.administrator_holder, 'd11', capability,
                plan.namespace, ('activity',), 'expression', ('internal',),
                policy.root_grant.policy_ref, anchor.activation_generation)
            counts = tuple((table, store._db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0])
                for table in tracked)
            return authority, lease, counts

        authority, lease, before = await worker.call(install)
        try:
            driver = ContactDispatchDriverV3(worker, authority, lease)
            result = await driver.run_once(operation_id=final['operation_id'])
            assert result.status == 'hold'
            assert type(result.original) is OriginalContactDispatchV3
            assert result.original.operation_id == final['operation_id']
            assert len(result.original.operation.write_versions) == 11
            assert result.original.request.segment_count == 1
            assert result.original.request.proactive_contact is True
            # No fake Authority issuer/current marker is supplied to install a
            # positive continuation. Both missing composition and direct P2
            # calls refuse before an effect/accounting mutation.
            with pytest.raises(RuntimeError, match='final claim dependencies unavailable'):
                await worker.call(lambda actual:
                    actual.register_contact_dispatch_final_claim_writer_v3(bootstrap))
            with pytest.raises(TypeError, match='required'):
                await worker.call(lambda actual: commit_contact_dispatch_final_claim_v3(actual))
            assert await driver.run_once(operation_id=final['operation_id']) == result
            task = asyncio.create_task(driver.run_once(operation_id=final['operation_id']))
            await asyncio.sleep(0)
            task.cancel()
            cancelled = await task
            assert cancelled.status == 'cancelled'
            assert 'before any Contact P2 attempt' in cancelled.reason
            def unchanged(actual):
                assert actual is graph and not store._db.in_transaction
                assert tuple((table, store._db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0])
                    for table in tracked) == before
                return case['port'].read_current_effect(namespace=plan.namespace,
                    authority_namespace=policy.authority_namespace,
                    effect_id=result.original.request.effect_id)
            effect = await worker.call(unchanged)
            assert effect.state == 'absent'
        finally:
            await worker.call(lambda actual: actual.release_authority_lease(bootstrap, lease))

    await run_installed_contact_final3_case(tmp_path, installed_d04_root, after_final_async=after_final)


async def _run_actual_contact_p2_sender_case(tmp_path,installed_d04_root,mode):
    from sylanne3.authority_service.contact_p2_contract_v1 import ContactP2PolicyCapsuleV1
    from sylanne3.host.contact_dispatch_driver_v3 import ContactDispatchDriverV3,InstalledContactContinuationV3
    from sylanne3.host.installed_dispatch_route import InstalledDispatchRoutePort
    from sylanne3.runtime_contracts import AuthorityContext
    from sylanne3.runtime.contact_p2_qualification_v1 import CONTACT_P2_PROOF_TYPE_V1
    import json

    async def after_final(case,worker,runtime,assembly,plan,final):
        graph,store,bootstrap=case['graph'],case['store'],case['bootstrap']
        policy,grant=assembly.installation_policy,assembly.installation_grant
        server=case['server'];ns=plan.namespace
        contact_policy=server._d10_contact_policy_services_v1[(case['authority_namespace'],policy.installation_id)]
        model=server._v2_model_egress[case['authority_namespace']]
        # The donor's actual same-Core Source qualifier is installed in the
        # same way as daemon composition. No D12 or fabricated current DTO is needed.
        core_p2=server.install_contact_p2_service_v1(contact_policy,model._source_location)
        assert core_p2.issuer is case['d11_issuer']
        sends=[]
        async def finite_onebot(action,**kwargs):
            if action=='send_private_msg':
                sends.append((action,kwargs))
                return {} if mode in {'unknown','unknown_unanswered'} else {'message_id':9042}
            return {'user_id':'10001'}
        case['adapter'].bot.call_action.side_effect=finite_onebot
        host_loop=asyncio.get_running_loop()
        def install(actual):
            assert actual is graph
            anchor=case['port'].current_anchor(namespace=ns,authority_namespace=policy.authority_namespace)
            lease,capability=graph.grant(bootstrap,actor=grant.administrator_holder,issuer_domain='d11',
                namespace=ns,domains=('d03','d05','d06','d08','d09','d10','d11'),
                activation_generation=anchor.activation_generation,operation_id=final['operation_id'])
            authority=AuthorityContext(grant.administrator_holder,'d11',capability,ns,('activity',),
                'expression',('internal',),policy.root_grant.policy_ref,anchor.activation_generation)
            route=InstalledDispatchRoutePort(context=case['host_context'],host_loop=host_loop,
                candidates=case['observed'],coordinator=graph,authority=authority,lease=lease,policy=policy,grant=grant)
            writer=graph.register_contact_dispatch_final_claim_writer_v3(bootstrap,route_port=route,
                issuer_id=server._v2_execution[case['authority_namespace']]._final_handoff_issuer_id)
            return authority,lease,writer
        authority,lease,writer=await worker.call(install)
        continuation=InstalledContactContinuationV3(worker=worker,authority=authority,lease=lease,
            fence_port=case['port'],policy=policy,grant=grant,server=case['reverse_server'],claim_writer=writer,
            context=case['host_context'],candidates=case['observed'],clock_policy=assembly.admin_bundle.ingress_clock)
        driver=ContactDispatchDriverV3(worker,authority,lease,continuation)
        original_prepare=None
        try:
            second_source=None
            if mode=='unknown_unanswered':
                from sylanne3.memory_types import source_key
                first_c02,second_c02,actual_ingress=await case['commit_second_c02'](
                    'message:contact-p2-next-parent','A later real private message asks for another reply.',return_envelope=True)
                assert actual_ingress.message_id!='message:reply'
                second_source=source_key(*ns.as_tuple,actual_ingress.lineage.source_id).token
                row=store._db.execute('SELECT revision,valid FROM graph_atoms WHERE token=?',(second_source,)).fetchone()
                assert row is not None and row[1]==1
            baseline=await worker.call(lambda actual:actual.read_committed_contact_dispatch_v3(authority,lease,final['operation_id']))
            assert all(v.result=='pass' and v.coverage=='full' for v in baseline.admission.admission.check_receipts)
            await worker.call(lambda actual:writer.require_current_entry(actual,authority,lease,baseline))
            before=await worker.call(lambda actual:tuple(store._db.execute(
                'SELECT lease_id,operation_id,phase,digest FROM runtime_budget_operations ORDER BY lease_id,operation_id,phase')))
            negative=mode in {'revoke','silent','boundary','expired'}
            cause_receipts=[]
            if mode=='silent':
                from dataclasses import replace
                from test_current_domain_production_v1 import command
                from sylanne3.runtime.domain_production_inputs_v1 import SetCurrentContactPolicyInputRequestV1
                # The exact selected actual policy comes from the original
                # immutable qualification, not a supplied permission flag.
                with store._lock:
                    store._db.execute('BEGIN')
                    try:
                        from sylanne3.runtime.contact_p2_birth_v1 import read_contact_p2_birth_v1
                        birth=read_contact_p2_birth_v1(store._db,namespace=ns,operation_id=final['operation_id'])
                        selected=birth.qualification.owner_policy.policy
                    finally:store._db.rollback()
                updated=replace(selected,version=selected.version+1,quiet=True)
                result=await worker.call(lambda actual:command(case,'set_contact_policy',
                    SetCurrentContactPolicyInputRequestV1(updated),producer=True))
                assert result['coverage']=='complete'
                cause_receipts.append(result)
            elif mode=='boundary':
                from dataclasses import replace
                from test_current_domain_production_v1 import command
                from sylanne3.domains.d05.relationship import BoundaryRule
                from sylanne3.runtime.d05_production_operations_v1 import BoundaryIntentOriginalV1
                from sylanne3.runtime.domain_production_inputs_v1 import RegisterCurrentBoundaryInputRequestV1
                from sylanne3.domains.d05.production_operations_v1 import ReviseCurrentBoundaryRequestV1
                def deny(actual):
                    row=store._db.execute("SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? "
                        "AND type_name='d05.boundary_rule' AND valid=1 AND json_extract(value,'$.rule_id')='boundary:contact-final3'",
                        ns.as_tuple).fetchone()
                    assert row is not None
                    raw=json.loads(row[2]);tuple_fields=('source_refs','communicated_refs','acknowledged_refs','exception_refs')
                    rule=BoundaryRule(**{**raw,**{k:tuple(raw[k]) for k in tuple_fields}})
                    updated=replace(rule,effect='deny',scope_version=rule.scope_version+1)
                    intent='boundary-intent:contact-p2-current-deny'
                    registered=command(case,'register_boundary_intent',RegisterCurrentBoundaryInputRequestV1(
                        intent,BoundaryIntentOriginalV1(row[0],rule.scope_version,updated,(),())),
                        audience=plan.audience_id,producer=True)
                    assert registered['coverage']=='complete'
                    result=command(case,'revise_boundary',ReviseCurrentBoundaryRequestV1(
                        row[0],intent,'relationship-policy:contact-final3'),audience=plan.audience_id)
                    assert result['coverage']=='complete'
                    return result
                cause_receipts.append(await worker.call(deny))
            elif mode=='revoke':
                from sylanne3.runtime.contact_dispatch_host_v3 import InstalledContactFinalClaimWriterV3
                from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationOperationV1
                original_prepare=InstalledContactFinalClaimWriterV3.prepare_contact_for_handoff
                def revoke_after_actual_claim(installed,actual,claimed,handoff_id,original):
                    value=original_prepare(installed,actual,claimed,handoff_id,original)
                    with contact_policy.core._tx() as db:
                        current=server._v2_owner_tickets._checked_current_head(db,case['authority_namespace'])
                    issue=case['owner_issue_operation']
                    operation=OwnerAuthorizationOperationV1('revoke','owner-revoke:contact-p2',issue.authority_id,
                        issue.installation_id,issue.namespace,issue.principal,issue.grant_id,issue.grant_digest,1,current)
                    pending=case['port'].reserve_owner_revoke(namespace=ns,authority_namespace=case['authority_namespace'],
                        operation=operation,owner_session_token=case['owner_console_session_token'],
                        owner_session_request=case['owner_console_session_request'])
                    assert pending.phase=='pending' and pending.guard.pending_revoke_operation_id==operation.operation_id
                    cause_receipts.append((pending,claimed))
                    return value
                InstalledContactFinalClaimWriterV3.prepare_contact_for_handoff=revoke_after_actual_claim
            elif mode=='expired':
                import time
                from datetime import datetime
                deadline=datetime.fromisoformat(baseline.admission.admission.utc_deadline.replace('Z','+00:00')).timestamp()
                remaining=deadline-time.time()
                assert remaining>0
                # One actual original 120-second window, with at most three
                # bounded sleeps; no clock substitution, TTL change or retry.
                while time.time()<deadline:
                    await asyncio.sleep(min(60.,deadline-time.time()+.01))
                cause_receipts.append(('actual_original_deadline',deadline))
            if mode in {'silent','boundary','revoke'}:
                import time
                # Each other negative has a live original deadline; expiry
                # cannot be used as their common reason for a blocked sender.
                baseline.admission.admission.require_current(time.time())
            if mode=='foreign_capsule':
                actual_read=core_p2.read_current_contact_policy_for_dispatch_in_tx_v1
                def wrong_original(*args,**kwargs):
                    from dataclasses import replace
                    value=actual_read(*args,**kwargs)
                    assert type(value) is ContactP2PolicyCapsuleV1
                    # A concrete namespace-correct but foreign admission
                    # locator must not acquire P2 through the actual channel.
                    return replace(value,admission_ref=value.admission_ref+'-foreign')
                core_p2.read_current_contact_policy_for_dispatch_in_tx_v1=wrong_original
            result=await driver.run_once(operation_id=final['operation_id'])
            def read_actual(actual):
                from sylanne3.runtime.dispatch_graph_claim import dispatch_claim_key
                from sylanne3.runtime.contact_p2_qualification_v1 import contact_p2_graph_proof_from_wire_v1
                rows=store._db.execute('SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? '
                    'AND type_name=?',(*ns.as_tuple,CONTACT_P2_PROOF_TYPE_V1)).fetchall()
                if mode=='foreign_capsule' or negative:
                    assert not rows
                    return None
                assert len(rows)==1 and rows[0][1]==1 and rows[0][3] in {0,1}
                proof=contact_p2_graph_proof_from_wire_v1(json.loads(rows[0][2]))
                assert proof.operation_id==final['operation_id'] and len(proof.qualification.checks)==6
                assert proof.qualification.actual_action_digest==result.original.admission.admission.action_intent_digest
                claim_key=dispatch_claim_key(ns,result.original.request.effect_id)
                claim=store._db.execute('SELECT value FROM graph_atoms WHERE token=?',(claim_key.token,)).fetchone()
                assert claim is not None and json.loads(claim[0])['current_evidence_digest']=='sha256:'+proof.digest
                birth=store._db.execute('SELECT event_id FROM graph_history WHERE token=? AND revision=1',(rows[0][0],)).fetchone()
                assert birth==('dispatch-claim:'+result.original.request.effect_id,)
                from sylanne3.runtime.contact_observation_v1 import TYPE as OBSERVATION_TYPE
                observed=store._db.execute('SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND type_name=?',
                    (*ns.as_tuple,OBSERVATION_TYPE)).fetchall()
                assert len(observed)==1 and observed[0][0]==1 and observed[0][2]==1
                assert json.loads(observed[0][1])['outcome']==('unknown' if mode in {'unknown','unknown_unanswered'} else 'accepted')
                actual_fact=json.loads(observed[0][1])
                job=store._db.execute('SELECT phase,result_ref FROM runtime_jobs WHERE operation_id=?',
                    (final['operation_id'],)).fetchone()
                assert job==('pending_confirmation' if mode in {'unknown','unknown_unanswered'} else 'completed',actual_fact['observation_id'])
                quota=store._db.execute("SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d10.contact_claim.v2'",
                    ns.as_tuple).fetchall()
                assert len(quota)==1 and quota[0][0]==2 and quota[0][2]==1
                assert json.loads(quota[0][1])['status']==('pending_confirmation' if mode in {'unknown','unknown_unanswered'} else 'handed_off')
                return rows,claim,observed,quota
            originals=await worker.call(read_actual)
            if negative:
                assert cause_receipts and sends==[] and result.status in {'hold','unknown'}
                assert result.original is not None
                if mode=='silent':assert 'quiet' in result.reason
                elif mode=='expired':assert 'expired' in result.reason
                elif mode=='revoke':
                    pending,actual_claimed=cause_receipts[0]
                    assert actual_claimed.durable_state=='committed' and actual_claimed.pending.phase=='claimed'
                    assert pending.guard.pending_revoke_operation_id=='owner-revoke:contact-p2'
                    assert result.status=='unknown'
                elif mode=='boundary':
                    row=store._db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? "
                        "AND type_name='d05.boundary_rule' AND json_extract(value,'$.rule_id')='boundary:contact-final3'",ns.as_tuple).fetchone()
                    assert json.loads(row[0])['effect']=='deny'
                assert await worker.call(lambda actual:tuple(store._db.execute(
                    'SELECT lease_id,operation_id,phase,digest FROM runtime_budget_operations ORDER BY lease_id,operation_id,phase')))==before
                return
            effect=await continuation.read_recovery_state(result.original)
            if mode=='foreign_capsule':
                assert result.status=='unknown' and sends==[] and effect.state=='unresolved'
            else:
                assert len(sends)==1
                if mode in {'unknown','unknown_unanswered'}:
                    assert result.status=='unknown' and effect.state in {'unresolved','observed'}
                else:
                    assert result.status=='accepted' and effect.state=='observed'
                replay=await driver.run_once(operation_id=final['operation_id'])
                assert len(sends)==1 and replay.status in {'unknown','hold'}
                assert await worker.call(read_actual)==originals
                if mode=='unknown_unanswered':
                    from test_current_domain_production_v1 import command
                    from sylanne3.domains.d10 import ProactiveOpportunity,LifeDomain,decode_contact_policy
                    from sylanne3.domains.d10.contact_claim_v2 import decode_contact_claim_v2
                    from sylanne3.domains.d10 import opportunity_key
                    from sylanne3.runtime.domain_production_inputs_v1 import CreateCurrentContactOpportunityInputRequestV1
                    from sylanne3.runtime.contact_plan_adoption_v2 import AdoptCurrentContactExpressionPlanRequestV2
                    from sylanne3.domains.d08.contact_plan_v1 import contact_ids_v1
                    import time
                    def try_new_parent(actual):
                        policy_ref,policy_wire=store._db.execute("SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? "
                            "AND type_name='d10.contact_policy.v1' AND valid=1",ns.as_tuple).fetchone()
                        current_policy=decode_contact_policy(json.loads(policy_wire),ns)
                        opportunity=ProactiveOpportunity('contact-opportunity:actual-next-parent',ns,second_source,
                            current_policy.subject_ref,current_policy.channel,current_policy.category,time.time()-1,current_policy.window_end)
                        registered=command(case,'create_contact_opportunity',CreateCurrentContactOpportunityInputRequestV1(opportunity),
                            audience=plan.audience_id,producer=True)
                        assert registered['coverage']=='complete'
                        new_ids=contact_ids_v1(ns,second_source,current_policy.subject_ref,'private_text')
                        assert new_ids['contact']!=plan.contact_id and new_ids['activity']!=plan.activity_id
                        claims=tuple(decode_contact_claim_v2(json.loads(wire)) for (wire,) in store._db.execute(
                            "SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d10.contact_claim.v2' AND valid=1",ns.as_tuple))
                        fresh_rule=LifeDomain.contact_policy_check(current_policy,opportunity,claims,now=time.time())
                        assert fresh_rule.result=='fail' and 'no_response_gate' in fresh_rule.reasons and 'quota' in fresh_rule.reasons
                        account_ref=store._db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d03.account_binding' AND valid=1",ns.as_tuple).fetchone()[0]
                        from test_current_domain_production_v1 import domain_owner
                        from uuid import uuid4
                        with domain_owner(case) as (actual_owner,actual_lease):
                            denied=graph.run_current_domain_operation_v1(actual_owner,actual_lease,
                                operation_kind='adopt_contact_expression_plan_v2',request=AdoptCurrentContactExpressionPlanRequestV2(
                                    opportunity_key(ns,opportunity.opportunity_id).token,policy_ref,account_ref),
                                operation_id=str(uuid4()),activity_id=new_ids['activity'],audience_ref=plan.audience_id,
                                parent_budget_lease_ref=policy.root_grant.lease_id)
                        assert denied.get('coverage')!='complete'
                        assert graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1 is not None
                        assert store._db.execute("SELECT COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d10.contact_claim.v2'",ns.as_tuple).fetchone()==(1,)
                        assert store._db.execute('SELECT COUNT(*) FROM graph_dispatch_admissions WHERE bot=? AND persona=?',ns.as_tuple).fetchone()==(1,)
                    await worker.call(try_new_parent)
                    assert len(sends)==1
                    assert await worker.call(read_actual)==originals
            assert await worker.call(lambda actual:tuple(store._db.execute(
                'SELECT lease_id,operation_id,phase,digest FROM runtime_budget_operations ORDER BY lease_id,operation_id,phase')))==before
        finally:
            if original_prepare is not None:
                from sylanne3.runtime.contact_dispatch_host_v3 import InstalledContactFinalClaimWriterV3
                InstalledContactFinalClaimWriterV3.prepare_contact_for_handoff=original_prepare
            await worker.call(lambda actual:actual.release_authority_lease(bootstrap,lease))
    await run_installed_contact_final3_case(tmp_path,installed_d04_root,after_final_async=after_final)


@pytest.mark.asyncio
async def test_installed_contact_p2_actual_sdk_accepted_once(tmp_path,installed_d04_root):
    await _run_actual_contact_p2_sender_case(tmp_path,installed_d04_root,'accepted')


@pytest.mark.asyncio
async def test_installed_contact_p2_actual_sdk_unknown_keeps_original_no_resend(tmp_path,installed_d04_root):
    await _run_actual_contact_p2_sender_case(tmp_path,installed_d04_root,'unknown')


@pytest.mark.asyncio
async def test_installed_contact_p2_foreign_current_capsule_denies_before_sdk(tmp_path,installed_d04_root):
    await _run_actual_contact_p2_sender_case(tmp_path,installed_d04_root,'foreign_capsule')


@pytest.mark.asyncio
@pytest.mark.parametrize('gate',('revoke','silent','boundary','expired'))
async def test_installed_contact_p2_current_gate_denies_before_sdk(tmp_path,installed_d04_root,gate):
    await _run_actual_contact_p2_sender_case(tmp_path,installed_d04_root,gate)


@pytest.mark.asyncio
async def test_installed_contact_p2_unknown_unanswered_blocks_actual_new_parent(tmp_path,installed_d04_root):
    await _run_actual_contact_p2_sender_case(tmp_path,installed_d04_root,'unknown_unanswered')
