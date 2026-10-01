"""Actual installed post-joint baseline and once-only C04 product lifecycle."""
import asyncio
from dataclasses import replace
import time
from uuid import uuid4
import pytest

from test_d04_owner_semantic_initialization_v3 import installed_d04_root  # noqa: F401
from test_d04_installed_semantic_drive_v3 import test_installed_owner_c02_appraisal_semantic_drive as _drive_case
from d04_numeric_authority_acceptance_support_v3 import install_actual_numeric_authority_case_v3


@pytest.mark.asyncio
async def test_actual_empty_c04_settles_once_without_recollection(tmp_path, installed_d04_root):
    from sylanne3.runtime.d04_numeric_policy_v3 import AdminD04JointNumericPolicyV3
    from sylanne3.runtime.d04_numeric_math_ticket_v3 import InstalledD04MathQueueV3, issue_current_numeric_math_ticket_v3
    from sylanne3.runtime.c04_current_trigger_v3 import CurrentC04TriggerV3
    from sylanne3.runtime.c04_v3_contracts import AssociationBudgetV3
    from sylanne3.runtime.c04_cpu_quote_policy import C04InternalCpuQuotePolicyV1
    from sylanne3.domains.d02 import BodyProfile, BodyState, WorkComponent
    from sylanne3.domains.d02.body_quote_original import FixedBodyPolicyV1
    from sylanne3.domains.d02.resource_outcome_verifier import C04_INTERNAL_CPU_WORK_KIND
    from sylanne3.host.installed_d06_build import verify_d06_algorithm_build, ALGORITHM_ID_V3
    queues=[];resources=[]
    async def after_drive(case):
        graph,worker,ns=case['graph'],case['http_worker'],case['namespace']
        root=case['policy'].root_grant
        policy=AdminD04JointNumericPolicyV3(ns,case['policy'].installation_id,root.grant_id,root.version,root.lease_id,100000,256,1e-8,600)
        bundle=replace(case['installed_bundle'],d04_joint_numeric=policy)
        assembly=replace(case['assembly'],admin_bundle=bundle)
        graph._GraphCoordinator__d04_installed_joint_assembly=assembly
        support=await asyncio.to_thread(install_actual_numeric_authority_case_v3,{**case,'installed_bundle':bundle,'assembly':assembly},owner_loop=asyncio.get_running_loop())
        resources.append(support)
        build=verify_d06_algorithm_build(case['package_root'],case['manifest_digest'],require_backend_runtime=True,algorithm_id=ALGORITHM_ID_V3)
        graph._GraphCoordinator__c04_algorithm_build_digest=build['build_digest'].removeprefix('sha256:')
        args={'c02_operation_id':case['c02'].operation_id,'source_ref':case['source_ref']}
        def issue(current):
            queue=InstalledD04MathQueueV3(current,case['bootstrap']);current._GraphCoordinator__d04_math_queue_v3=queue
            return queue,issue_current_numeric_math_ticket_v3(current,case['bootstrap'],bundle,queue,**args)
        queue,ticket=await worker.call(issue);queues.append(queue)
        measured=await asyncio.wrap_future(queue.submit(ticket))
        execution=await worker.call(lambda current:queue.accept(current,measured))
        assert execution.terminal.measurement.status=='completed'
        adopted=await worker.call(lambda current:current.adopt_post_c02_joint_numeric_v3(case['bootstrap'],bundle,operation_id=execution.prepared.binding.operation_id))
        assert adopted['status']=='joint_advance_committed'
        encoding=await worker.call(lambda current:current.commit_post_joint_c04_encoding_v3(case['bootstrap'],bundle,**args,joint_operation_id=execution.prepared.binding.operation_id))
        assert encoding['status']=='encoding_baseline_committed'
        def grant(current):
            return current.grant_current_owner(case['bootstrap'],actor='owner-actor-reply',namespace=ns,
                domains=('d02','d04','d06','d07','d11','d12'),purpose='workbench_user_action',audience='owner',
                activation_generation=1,owner_session_token=case['owner_session_token'],owner_session_request=case['owner_session_request'])
        authority,lease,_=await worker.call(grant)
        try:
            profile=BodyProfile('c04-actual-body',ns,1,('energy',),(C04_INTERNAL_CPU_WORK_KIND,))
            body=FixedBodyPolicyV1('c04-actual-body-policy',1,profile,BodyState(profile.profile_id,1,0.8,{'cognition':0.0},0.0,0.0),
                C04_INTERNAL_CPU_WORK_KIND,WorkComponent('c04-actual-component','cognition',0.1),time.time()+3600)
            await worker.call(lambda current:current.adopt_current_fixed_body_work_policy_v1(authority,lease,operation_id=str(uuid4()),policy=body))
            cpu=C04InternalCpuQuotePolicyV1('c04-actual-cpu-policy',1,ns,case['policy'].installation_id,ALGORITHM_ID_V3,1000,time.time()+3600)
            await worker.call(lambda current:current.adopt_current_c04_cpu_policy_v3(authority,lease,operation_id=str(uuid4()),policy=cpu))
            # A later unrelated real Body write does not rewrite the baseline.
            assert await worker.call(lambda current:current.commit_post_joint_c04_encoding_v3(case['bootstrap'],bundle,**args,joint_operation_id=execution.prepared.binding.operation_id))==encoding
            operation=str(uuid4())
            request=CurrentC04TriggerV3(case['source_ref'],body.policy_id,body.version,cpu.policy_id,cpu.version,
                root.lease_id,AssociationBudgetV3(2,32,16,16,8))
            prepared=await worker.call(lambda current:current.prepare_owner_c04_trigger_v3(authority,lease,operation_id=operation,request=request))
            assert prepared['status']=='prepared'
            assert await worker.call(lambda current:current.prepare_owner_c04_trigger_v3(authority,lease,operation_id=operation,request=request)) == prepared
            completed=await worker.call(lambda current:current.advance_owner_c04_work_v3(authority,lease,original_operation_id=operation))
            assert completed['status']=='no_eligible_recollection',completed
            assert completed['stop_reason']=='no_eligible_association'
            assert case['store']._db.execute("SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
                "('d06.recollection.v1','d04.recollection_experience.v1')").fetchone()==(0,)
            costs = tuple(case['store']._db.execute('SELECT original_digest FROM d11_c04_cpu_cost_originals_v1 '
                'WHERE bot=? AND persona=? AND operation_id=?', (*ns.as_tuple,operation)))
            assert len(costs)==1
            from sylanne3.domains.d06 import c04_work_algorithm_v3
            def forbidden(*args,**kwargs):raise AssertionError('C04 exact retry re-executed its consumed original')
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(c04_work_algorithm_v3,'activate_association_work_v3',forbidden)
                assert await worker.call(lambda current:current.advance_owner_c04_work_v3(authority,lease,original_operation_id=operation))==completed
            assert tuple(case['store']._db.execute('SELECT original_digest FROM d11_c04_cpu_cost_originals_v1 '
                'WHERE bot=? AND persona=? AND operation_id=?', (*ns.as_tuple,operation)))==costs
        finally:await worker.call(lambda current:current.release_current_owner_lease(case['bootstrap'],lease))
    try:await _drive_case(tmp_path,installed_d04_root,0.5,after_drive=after_drive,role_clock_rate='1')
    finally:
        for queue in queues:await asyncio.to_thread(queue.close)
        for resource in resources:resource.close()
