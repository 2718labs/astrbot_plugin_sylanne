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
            with pytest.raises(RuntimeError, match='current P2 closed SQL witness'):
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
