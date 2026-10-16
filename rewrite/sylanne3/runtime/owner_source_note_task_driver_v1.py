"""Bounded installed discovery and execution of explicit Owner SourceNote tasks."""
from dataclasses import replace

from ..runtime_contracts import canonical_digest
from .owner_source_note_task_contract_v1 import (OwnerSourceNoteTaskContinuationV2,
    CheckpointOwnerSourceNoteTaskRequestV1,owner_source_note_task_ids_v1)
from .owner_source_note_task_v1 import read_owner_source_note_task_authorization_v2
from .domain_production_erasure_v1 import decode_typed_production_value_v1
from .d11_types import runtime_job_key
from .jobs import get_job


def run_owner_source_note_task_command_v1(graph,bootstrap,bundle,*,authorization_original_ref,
        operation_kind,request,operation_id):
    selector=graph._owner_source_note_task_selector_v1(bootstrap,bundle,
        authorization_original_ref=authorization_original_ref,operation_kind=operation_kind,
        request=request,operation_id=operation_id)
    return graph._GraphCoordinator__domain_production_runtime_v1.run_owner_source_note_task_current_v1(
        selector=selector,operation_kind=operation_kind,request=request)


def _task(graph,bundle,authorization_original_ref):
    store=graph._GraphCoordinator__store
    with store._lock:
        db=store._db;db.execute('BEGIN')
        try:
            saved=read_owner_source_note_task_authorization_v2(db,namespace=bundle.installation_policy.namespace,
                original_ref=authorization_original_ref,issuer=graph._GraphCoordinator__d11_issuer)
            if saved is None:raise ValueError('actual signed Owner task authorization missing')
            auth=saved[0];ids=owner_source_note_task_ids_v1(auth.cause.namespace,auth.cause.owner_operation_id)
            from .owner_source_note_life_v1 import owner_source_note_life_ids_v1
            from .joint_node_execution_v1 import require_joint_bound_action_gate_v1
            require_joint_bound_action_gate_v1(db, namespace=auth.cause.namespace,
                action_ref=owner_source_note_life_ids_v1(auth)['action_ref'], issuer=graph._GraphCoordinator__d11_issuer)
            job=get_job(db,ids['job_id'])
            cont=None if job is None else decode_typed_production_value_v1(dict(job.continuation),OwnerSourceNoteTaskContinuationV2)
            return auth,ids,job,cont
        finally:db.rollback()


def checkpoint_owner_source_note_task_step_v1(graph,bootstrap,bundle,*,authorization_original_ref,
        next_step,completed_operation_ids=(),pending_effect_refs=(),wait_reason=None,completion_result_ref=None):
    auth,ids,job,old=_task(graph,bundle,authorization_original_ref)
    if job is None or job.phase!='running':
        raise ValueError('Owner task checkpoint requires its actual running original worker')
    cont=replace(old,step=next_step,completed_original_refs=tuple(dict.fromkeys((*old.completed_original_refs,
        *completed_operation_ids))),pending_effect_refs=tuple(pending_effect_refs),wait_reason=wait_reason)
    key=runtime_job_key(*auth.cause.namespace.as_tuple,ids['activity_id'],job.job_id)
    request=CheckpointOwnerSourceNoteTaskRequestV1(key.token,job.lease_holder,job.fence,cont,completion_result_ref)
    operation_id='owner-note-checkpoint:'+canonical_digest((job.job_id,job.fence,request))[:40]
    return run_owner_source_note_task_command_v1(graph,bootstrap,bundle,
        authorization_original_ref=authorization_original_ref,operation_kind='checkpoint_owner_source_note_task_v1',
        request=request,operation_id=operation_id)


def discover_owner_source_note_tasks_v1(graph,bootstrap,bundle):
    graph._admin(bootstrap)
    if (graph._GraphCoordinator__d04_installed_joint_assembly is None
            or graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not bundle):
        raise ValueError('Owner task discovery requires the actual installed bundle')
    store=graph._GraphCoordinator__store;ns=bundle.installation_policy.namespace
    with store._lock:
        db=store._db;db.execute('BEGIN')
        try:
            rows=db.execute("SELECT o.original_ref FROM graph_d11_life_originals_v1 o WHERE o.bot=? AND o.persona=? "
                "AND o.kind='owner_source_note_task_authorization_v2' AND NOT EXISTS(SELECT 1 FROM runtime_jobs j "
                "WHERE j.bot_id=o.bot AND j.persona_id=o.persona "
                "AND json_extract(j.continuation_json,'$.schema')='d11.owner-source-note-task-continuation.v2' "
                "AND json_extract(j.continuation_json,'$.authorization_original_ref')=o.original_ref "
                "AND j.phase NOT IN ('queued','running')) ORDER BY o.original_ref LIMIT 17",ns.as_tuple).fetchall()
            if len(rows)>16:raise ValueError('Owner task discovery exceeds its complete bounded page')
            result=[]
            for (ref,) in rows:
                saved=read_owner_source_note_task_authorization_v2(db,namespace=ns,original_ref=ref,
                    issuer=graph._GraphCoordinator__d11_issuer)
                if saved is None:raise ValueError('Owner task discovered original has no actual signed producer')
                auth=saved[0];ids=owner_source_note_task_ids_v1(ns,auth.cause.owner_operation_id)
                job=get_job(db,ids['job_id'])
                if job is None or job.phase in {'queued','running'}:
                    result.append(ref)
            return tuple(result)
        finally:db.rollback()










def prepare_owner_source_note_task_life_v1(graph,bootstrap,bundle,*,authorization_original_ref):
    from .owner_source_note_life_v1 import RegisterOwnerSourceNoteLifePlanRequestV1,owner_source_note_life_ids_v1
    from .d11_life_preparation_v1 import PrepareCurrentLifeRequestV1,read_registered_life_plan_v2,life_ids_v1
    auth,_,job,cont=_task(graph,bundle,authorization_original_ref);ids=owner_source_note_life_ids_v1(auth)
    if cont.step=='register_life_plan':
        registered=run_owner_source_note_task_command_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
            operation_kind='register_owner_source_note_life_plan_v1',request=RegisterOwnerSourceNoteLifePlanRequestV1(auth.original_ref),
            operation_id=ids['plan_operation_id'])
        if registered['coverage']!='complete':return registered
        checkpoint_owner_source_note_task_step_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
            next_step='prepare_life',completed_operation_ids=(ids['plan_operation_id'],))
    prepared=run_owner_source_note_task_command_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
        operation_kind='prepare_life',request=PrepareCurrentLifeRequestV1(ids['plan_ref'],ids['prepare_operation_id']),
        operation_id=ids['prepare_operation_id'])
    originals=prepared.get('produced_originals',())
    prepared_refs=[item['original_ref'] for item in originals if item['kind']=='d11.life_prepared']
    if not prepared_refs:
        store=graph._GraphCoordinator__store
        with store._lock:
            db=store._db;db.execute('BEGIN')
            try:
                plan=read_registered_life_plan_v2(db,namespace=auth.cause.namespace,
                    issuer=graph._GraphCoordinator__d11_issuer,original_ref=ids['plan_ref'])
                if plan is None:return prepared
                prepared_ref=life_ids_v1(plan)['prepared']
                from .d11_life_preparation_v1 import read_prepared_life_by_ref_v1
                if read_prepared_life_by_ref_v1(db,namespace=auth.cause.namespace,prepared_original_ref=prepared_ref,
                        issuer=graph._GraphCoordinator__d11_issuer) is None:return prepared
            finally:db.rollback()
    elif len(prepared_refs)==1:prepared_ref=prepared_refs[0]
    else:raise ValueError('Owner task preparation returned multiple actual execution originals')
    # First claim requires the exact prepared Graph stamp. No parent checkpoint
    # or other W01 is permitted between preparation and the official once driver.
    native=graph.run_prepared_source_note_v1(bootstrap,namespace=auth.cause.namespace,prepared_original_ref=prepared_ref)
    if native.terminal is not None and native.terminal.status=='failed' and native.adoption is not None:
        from .owner_source_note_native_observation_v1 import read_owner_source_note_native_observation_v1
        observed=read_owner_source_note_native_observation_v1(graph,bootstrap,authorization_original_ref=auth.original_ref)
        if observed.state=='failed' and observed.adoption_finished:
            _,_,_,actual_cont=_task(graph,bundle,authorization_original_ref)
            checkpoint=checkpoint_owner_source_note_task_step_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
                next_step=actual_cont.step,completed_operation_ids=(ids['prepare_operation_id'],observed.adoption_operation_id))
            return {'status':'failed','native':native,'checkpoint':checkpoint}
    if native.terminal is None or native.terminal.status!='completed' or native.adoption is None or native.state!='adopted_completed':
        # Prepared read rows include the parent task. Mutating that job before
        # actual Native adoption would invalidate recovery of the same effect.
        return {'status':'pending_original_native','native':native,'prepared_original_ref':prepared_ref,
            'pending_effect_refs':(ids['effect_id'],),'wait_reason':native.state}
    from .d11_life_contract_v1 import life_adoption_operation_id_v1
    adoption_id=life_adoption_operation_id_v1(native.terminal.binding)
    checkpoint_owner_source_note_task_step_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
        next_step='execute_life',completed_operation_ids=(ids['prepare_operation_id'],adoption_id))
    checkpoint=checkpoint_owner_source_note_task_step_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
        next_step='observe_life')
    return {'status':'native_completed','native':native,'checkpoint':checkpoint}


async def drive_owner_source_note_task_v1(runtime, installation, *, authorization_original_ref):
    """Finite actual Owner task phases; each Work reaches terminal before its consumer."""
    from .personal_candidate_eligibility_v1 import actual_owner_personal_candidates_v1
    worker, bootstrap, bundle = runtime._worker, runtime._v2_bootstrap, installation.admin_bundle
    async def graph_call(function):
        raw = await worker.call(function)
        return runtime._consume_background_graph_result_v3(raw)
    async def state():
        return await worker.call(lambda graph: _task(graph, bundle, authorization_original_ref))
    async def command(kind, request, operation_id):
        result = await graph_call(lambda graph: run_owner_source_note_task_command_v1(graph, bootstrap, bundle,
            authorization_original_ref=authorization_original_ref, operation_kind=kind,
            request=request, operation_id=operation_id))
        if result.get("coverage") != "complete":
            raise ValueError("Owner task waits for actual current producer: " + kind)
        return result
    async def checkpoint(step, completed=(), result_ref=None, wait_reason=None):
        return await graph_call(lambda graph: checkpoint_owner_source_note_task_step_v1(graph, bootstrap, bundle,
            authorization_original_ref=authorization_original_ref, next_step=step,
            completed_operation_ids=completed, completion_result_ref=result_ref, wait_reason=wait_reason))
    auth, ids, job, continuation = await state()
    if job is None:
        await graph_call(lambda graph: graph.create_owner_source_note_task_v1(bootstrap, bundle,
            authorization_original_ref=authorization_original_ref))
        auth, ids, job, continuation = await state()
    await graph_call(lambda graph: acknowledge_owner_task_submission_v1(graph,bootstrap,bundle,authorization_original_ref=authorization_original_ref))
    if job.phase == "queued":
        await graph_call(lambda graph: graph.acquire_owner_source_note_task_v1(bootstrap, bundle,
            authorization_original_ref=authorization_original_ref))
    for _ in range(16):
        auth, ids, job, continuation = await state()
        if job.phase != "running":
            return {"status": job.phase, "job_id": job.job_id, "step": continuation.step,
                "pending_effect_refs": continuation.pending_effect_refs}
        step = continuation.step
        key = runtime_job_key(*auth.cause.namespace.as_tuple, ids["activity_id"], job.job_id)
        if step == "qualify":
            from .d07_life_project_focus_v1 import FocusOwnerSourceNoteTaskRequestV1, owner_task_focus_operation_id_v1
            focus_operation = owner_task_focus_operation_id_v1(auth.cause.namespace,auth)
            await command("focus_owner_source_note_task_v1", FocusOwnerSourceNoteTaskRequestV1(auth.original_ref,key.token),
                focus_operation)
            from .owner_source_note_need_v1 import PrepareOwnerSourceNoteNeedRequestV1
            operation = "owner-note-need:" + canonical_digest((auth.cause.namespace, auth.original_ref))[:40]
            await command("prepare_owner_source_note_need_v1", PrepareOwnerSourceNoteNeedRequestV1(auth.original_ref, key.token), operation)
            await checkpoint("values", (operation,))
        elif step == "values":
            await run_owner_source_note_values_async_v1(runtime, installation, authorization_original_ref=auth.original_ref)
        elif step == "select":
            def candidates(graph):
                store = graph._GraphCoordinator__store
                with store._lock:
                    db = store._db; db.execute("BEGIN")
                    try:
                        return actual_owner_personal_candidates_v1(db, namespace=auth.cause.namespace,
                            authorization=auth, job=job, issuer=graph._GraphCoordinator__d11_issuer)
                    finally: db.rollback()
            base = await worker.call(candidates)
            await runtime.run_personal_candidate_eligibility_wave_v1(installation, candidates=base,
                authorization_original_ref=auth.original_ref)
            preparation = "owner-note-candidates:" + canonical_digest((auth.cause.namespace, auth.original_ref))[:40]
            await command("prepare_personal_candidates_v1", base, preparation)
            from ..domains.d08.personal_candidate_v1 import SelectCurrentPersonalStepRequestV2
            await command("select_personal_step_v2", SelectCurrentPersonalStepRequestV2(
                base.plan_ref, base.goal_ref, preparation), ids["selection_operation_id"])
            chosen = await worker.call(lambda graph: read_owner_source_note_selected_decision_v1(graph, bundle, auth))
            if chosen is None:
                await checkpoint("select", (preparation, ids["selection_operation_id"]), wait_reason="actual_candidate_check_or_resource_wait")
                return {"status": "waiting", "job_id": job.job_id, "step": "select"}
            await checkpoint("prepare_action", (preparation, ids["selection_operation_id"]))
        elif step == "prepare_action":
            from .d08_personal_candidate_v1 import ConsumePersonalDecisionRequestV1, prospective_personal_decision_key_v1
            from ..domains.d08.personal_candidate_v1 import SourceNoteCandidateBindingV1
            binding = SourceNoteCandidateBindingV1(ids["candidate_ref"], ids["node_id"], auth.request.project_ref,
                auth.request.recipe_ref, auth.request.body_source_ref, ids["goal_key"].token,
                auth.request.target_entity_ref, auth.request.role_binding_ref)
            action = "personal-source-note-action:" + canonical_digest((auth.cause.namespace, ids["selection_operation_id"], binding))[:48]
            preparation = "owner-note-candidates:" + canonical_digest((auth.cause.namespace, auth.original_ref))[:40]
            decision = prospective_personal_decision_key_v1(auth.cause.namespace, ids["activity_id"],
                ids["selection_operation_id"], ids["plan_key"].token)
            await command("prepare_selected_source_note_action_v2", ConsumePersonalDecisionRequestV1(decision.token, preparation), action)
            await checkpoint("prepare_body", (action,))
        elif step == "prepare_body":
            from .d02_life_body_preparation_v1 import PrepareSourceNoteBodyRequestV1
            root = await worker.call(lambda graph: read_owner_source_note_action_root_v1(graph, bundle, auth))
            operation = "d02-life-body:" + root.action_operation_id
            await command("prepare_source_note_body", PrepareSourceNoteBodyRequestV1(root.action_intent_ref,
                auth.body_policy.body_policy_id, auth.body_policy.body_policy_version,
                auth.body_policy.effect_policy_ref, auth.body_policy.cpu_ceiling_ms), operation)
            await checkpoint("register_life_plan", (operation,))
        elif step == "register_life_plan":
            from .owner_source_note_life_v1 import RegisterOwnerSourceNoteLifePlanRequestV1, owner_source_note_life_ids_v1
            life = owner_source_note_life_ids_v1(auth)
            await command("register_owner_source_note_life_plan_v1", RegisterOwnerSourceNoteLifePlanRequestV1(auth.original_ref), life["plan_operation_id"])
            await checkpoint("prepare_life", (life["plan_operation_id"],))
        elif step == "prepare_life":
            # This existing exact producer retains the once claim boundary with
            # no parent checkpoint between preparation and original Native claim.
            result = await graph_call(lambda graph: prepare_owner_source_note_task_life_v1(
                graph, bootstrap, bundle, authorization_original_ref=auth.original_ref))
            if result.get("status") != "native_completed":
                return result
        elif step in {"execute_life", "observe_life"}:
            await checkpoint("observe_life" if step == "execute_life" else "adopt_outcome")
        elif step == "adopt_outcome":
            await run_owner_source_note_outcome_async_v1(runtime, installation, authorization_original_ref=auth.original_ref)
        elif step == "completed":
            return {"status": "completed", "job_id": job.job_id, "result_ref": job.result_ref}
        else:
            raise ValueError("Owner task has an unregistered actual continuation step")
        _, _, current_job, current = await state()
        if current_job.phase == "completed":
            return {"status": "completed", "job_id": current_job.job_id, "result_ref": current_job.result_ref}
        if current.step == step:
            return {"status": "held", "job_id": current_job.job_id, "step": current.step}
    raise ValueError("Owner task exhausted its actual finite phase recipe without progress")


def read_owner_source_note_selected_decision_v1(graph, bundle, authorization):
    from .d08_personal_candidate_v1 import prospective_personal_decision_key_v1
    auth = authorization
    ids = owner_source_note_task_ids_v1(auth.cause.namespace, auth.cause.owner_operation_id)
    key = prospective_personal_decision_key_v1(auth.cause.namespace, ids["activity_id"],
        ids["selection_operation_id"], ids["plan_key"].token)
    with graph._GraphCoordinator__store._lock:
        row = graph._GraphCoordinator__store._db.execute(
            "SELECT value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
            (*auth.cause.namespace.as_tuple, key.token)).fetchone()
    if row is None or row[1] != 1: raise ValueError("Owner task has no actual adopted Decision")
    import json
    return json.loads(row[0])["chosen_action_ref"]


def read_owner_source_note_action_root_v1(graph, bundle, authorization):
    from ..domains.d08.personal_candidate_v1 import SourceNoteCandidateBindingV1
    from .d08_source_note_action_v1 import source_note_action_original_from_wire_v1
    from .d11_life_preparation_v1 import _read
    auth = authorization
    ids = owner_source_note_task_ids_v1(auth.cause.namespace, auth.cause.owner_operation_id)
    binding = SourceNoteCandidateBindingV1(ids["candidate_ref"], ids["node_id"], auth.request.project_ref,
        auth.request.recipe_ref, auth.request.body_source_ref, ids["goal_key"].token,
        auth.request.target_entity_ref, auth.request.role_binding_ref)
    action = "personal-source-note-action:" + canonical_digest((auth.cause.namespace, ids["selection_operation_id"], binding))[:48]
    with graph._GraphCoordinator__store._lock:
        db = graph._GraphCoordinator__store._db; db.execute("BEGIN")
        try:
            saved = _read(db, issuer=graph._GraphCoordinator__d11_issuer,
                namespace=auth.cause.namespace, kind="source_note_action", ref="life-root:" + action)
            if saved is None: raise ValueError("Owner task has no actual signed selected Action")
            return source_note_action_original_from_wire_v1(saved[0])
        finally: db.rollback()


async def run_owner_source_note_values_async_v1(runtime, installation, *, authorization_original_ref):
    from .owner_source_note_values_v1 import FreezeOwnerSourceNoteValuesParentRequestV1, owner_source_note_values_ids_v1, read_owner_task_values_parent_v1
    from .domain_production_inputs_v1 import FreezeCurrentValuesInputRequestV1
    from ..domains.d01.production_operations_v1 import EvaluateCurrentValuesRequestV1
    from ..authority_service.current_owner_source_note_task_v1 import OwnerTaskActivityValuesChildRequestV1, owner_task_typed_command_digest_v1
    from .domain_production_registry_v1 import installed_operation_v1
    worker, bootstrap, bundle = runtime._worker, runtime._v2_bootstrap, installation.admin_bundle
    auth, ids, job, _ = await worker.call(lambda graph: _task(graph, bundle, authorization_original_ref))
    key = runtime_job_key(*auth.cause.namespace.as_tuple, ids["activity_id"], job.job_id)
    need_op = "owner-note-need:" + canonical_digest((auth.cause.namespace, auth.original_ref))[:40]
    def need_ref(graph):
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        with graph._GraphCoordinator__store._lock:
            db = graph._GraphCoordinator__store._db; db.execute("BEGIN")
            try:
                original = read_adopted_domain_operation_v1(db, auth.cause.namespace, need_op)
                if original is None: raise ValueError("Owner values need has no actual adopted predecessor")
                return "d07-current:" + original["original_digest"][:48]
            finally: db.rollback()
    ref = await worker.call(need_ref)
    parent_request = FreezeOwnerSourceNoteValuesParentRequestV1(auth.original_ref, key.token, ref)
    values = owner_source_note_values_ids_v1(auth.cause.namespace, parent_request)
    raw = await worker.call(lambda graph: run_owner_source_note_task_command_v1(graph, bootstrap, bundle,
        authorization_original_ref=auth.original_ref, operation_kind="input:freeze_owner_source_note_values_parent_v1",
        request=parent_request, operation_id=values["parent_operation_id"]))
    parent_result = runtime._consume_background_graph_result_v3(raw)
    if parent_result.get("coverage") != "complete": return parent_result
    for slot, kind, request in (
            ("freeze", "input:freeze_values", FreezeCurrentValuesInputRequestV1(values["candidate_set_ref"], values["context_ref"])),
            ("evaluate", "evaluate_values", EvaluateCurrentValuesRequestV1(values["candidate_set_ref"], values["context_ref"]))):
        def child(graph):
            with graph._GraphCoordinator__store._lock:
                db = graph._GraphCoordinator__store._db; db.execute("BEGIN")
                try:
                    saved = read_owner_task_values_parent_v1(db, namespace=auth.cause.namespace,
                        original_ref=values["parent_ref"], issuer=graph._GraphCoordinator__d11_issuer)
                    if saved is None: raise ValueError("Owner Values child has no signed parent")
                    row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
                    current_job = get_job(db, job.job_id)
                finally: db.rollback()
            parent = saved[0]
            selector = OwnerTaskActivityValuesChildRequestV1(auth.cause.namespace, auth.cause.installation_id,
                auth.original_ref, auth.digest, values[slot + "_operation_id"], kind,
                owner_task_typed_command_digest_v1(installed_operation_v1(kind), request), key.token,
                row[0], current_job.cancel_epoch, values_parent_original_ref=parent.original_ref,
                values_parent_original_digest=parent.digest, child_slot=slot)
            return graph._GraphCoordinator__domain_production_runtime_v1.run_owner_source_note_task_current_v1(
                selector=selector, operation_kind=kind, request=request)
        raw = await worker.call(child)
        result = runtime._consume_background_graph_result_v3(raw)
        if result.get("coverage") != "complete": return result
    raw = await worker.call(lambda graph: checkpoint_owner_source_note_task_step_v1(graph, bootstrap, bundle,
        authorization_original_ref=auth.original_ref, next_step="select", completed_operation_ids=(
            values["parent_operation_id"], values["freeze_operation_id"], values["evaluate_operation_id"])))
    return runtime._consume_background_graph_result_v3(raw)


async def run_owner_source_note_outcome_async_v1(runtime, installation, *, authorization_original_ref):
    from .owner_source_note_life_v1 import RegisterOwnerSourceNoteLifeOutcomeRequestV1, owner_source_note_life_ids_v1
    from ..domains.d10.production_operations_v1 import AdvanceCurrentLifeRequestV1
    from .d08_personal_plan_v1 import SettleCurrentPersonalGoalRequestV1
    worker, bootstrap, bundle = runtime._worker, runtime._v2_bootstrap, installation.admin_bundle
    auth, _, _, _ = await worker.call(lambda graph: _task(graph, bundle, authorization_original_ref))
    life = owner_source_note_life_ids_v1(auth)
    ids = owner_source_note_task_ids_v1(auth.cause.namespace, auth.cause.owner_operation_id)
    for kind, request, operation in (
        ("register_owner_source_note_life_outcome_v1", RegisterOwnerSourceNoteLifeOutcomeRequestV1(auth.original_ref), life["outcome_operation_id"]),
        ("advance_life", AdvanceCurrentLifeRequestV1(auth.request.project_ref, life["outcome_ref"]), life["advance_operation_id"]),
        ("settle_personal_goal", SettleCurrentPersonalGoalRequestV1(ids["goal_key"].token, ids["plan_key"].token, life["progress_ref"], 1, 1), life["settle_operation_id"])):
        raw = await worker.call(lambda graph: run_owner_source_note_task_command_v1(graph, bootstrap, bundle,
            authorization_original_ref=auth.original_ref, operation_kind=kind, request=request, operation_id=operation))
        result = runtime._consume_background_graph_result_v3(raw)
        if result.get("coverage") != "complete": return result
    def completion(graph):
        from ..authority_service.current_owner_source_note_task_v1 import read_completed_owner_source_note_task_v1
        with graph._GraphCoordinator__store._lock:
            db = graph._GraphCoordinator__store._db; db.execute("BEGIN")
            try:
                proof = read_completed_owner_source_note_task_v1(db, namespace=auth.cause.namespace,
                    authorization=auth, issuer=graph._GraphCoordinator__d11_issuer)
                if proof is None: raise ValueError("Owner task completion lacks its real Native/Goal/Plan proof")
                return proof.artifact_ref
            finally: db.rollback()
    result_ref = await worker.call(completion)
    raw = await worker.call(lambda graph: checkpoint_owner_source_note_task_step_v1(graph, bootstrap, bundle,
        authorization_original_ref=auth.original_ref, next_step="completed", completed_operation_ids=(
            life["outcome_operation_id"], life["advance_operation_id"], life["settle_operation_id"]),
        completion_result_ref=result_ref))
    return runtime._consume_background_graph_result_v3(raw)


def acknowledge_owner_task_submission_v1(graph, bootstrap, bundle, *, authorization_original_ref):
    """Acknowledge actual task-carrier creation, never native work completion."""
    import json
    from ..runtime_contracts import canonical_serialize
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .owner_source_note_task_contract_v1 import SUBMITTED_EVENT, CreateOwnerSourceNoteTaskRequestV1
    graph._admin(bootstrap)
    auth, ids, job, continuation = _task(graph,bundle,authorization_original_ref)
    if job is None: raise ValueError("Owner submit consumer requires its actual created task carrier")
    ns = auth.cause.namespace
    dedupe = canonical_digest((ns,auth.cause.owner_operation_id,"d11",SUBMITTED_EVENT))
    store = graph._GraphCoordinator__store
    with store._lock:
        db=store._db; db.execute("BEGIN IMMEDIATE")
        try:
            causal=read_adopted_domain_operation_v1(db,ns,auth.cause.owner_operation_id)
            created=read_adopted_domain_operation_v1(db,ns,ids["create_operation_id"])
            if causal is None or created is None or created["operation_kind"] != "create_owner_source_note_task_v1":
                raise ValueError("Owner submit consumer lost its actual original W01 create receipt")
            body=decode_typed_production_value_v1(created["payload"]["request"],CreateOwnerSourceNoteTaskRequestV1)
            if body.authorization_original_ref != auth.original_ref or continuation.authorization_original_digest != auth.digest:
                raise ValueError("Owner submit consumer changed its signed task carrier")
            row=db.execute("SELECT causal_operation_id,receiver_domain,event_kind,original_ref,original_digest,state,consumer_operation_id,receipt_json "
                "FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?",(*ns.as_tuple,dedupe)).fetchone()
            if row is None: raise ValueError("Owner task has no actual same-submit outbox")
            expected=(auth.cause.owner_operation_id,"d11",SUBMITTED_EVENT,"d08-current:" + causal["original_digest"][:48],causal["original_digest"])
            if row[:5] != expected: raise ValueError("Owner submit event differs from the signed authorization")
            value={"schema":"d11.owner-source-note-submit-consumed.v1","dedupe_key":dedupe,
                "causal_operation_id":auth.cause.owner_operation_id,"authorization_original_ref":auth.original_ref,
                "authorization_original_digest":auth.digest,"consumer_operation_id":ids["create_operation_id"],
                "create_original_digest":created["original_digest"],"create_receipt_digest":canonical_digest(created["receipt"])}
            wire=canonical_serialize(value)
            if row[5] == "completed":
                if row[6:] != (ids["create_operation_id"],wire):
                    raise ValueError("Owner submit stored consumer acknowledgement changed")
            elif row[5] in {"pending","waiting"}:
                db.execute("UPDATE graph_domain_production_outbox_v1 SET state='completed',consumer_operation_id=?,receipt_json=? "
                    "WHERE bot=? AND persona=? AND dedupe_key=? AND state=?",
                    (ids["create_operation_id"],wire,*ns.as_tuple,dedupe,row[5]))
            else: raise ValueError("Owner submit was retired before task acknowledgement")
            db.commit()
            return value
        except BaseException:
            if db.in_transaction:db.rollback()
            raise


def validate_owner_task_submit_disposition_v1(db, *, namespace, row_data, value):
    """C09 closes the actual submission-to-create receipt join."""
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .owner_source_note_task_contract_v1 import SUBMITTED_EVENT, owner_source_note_task_ids_v1, CreateOwnerSourceNoteTaskRequestV1
    expected={"schema","dedupe_key","causal_operation_id","authorization_original_ref","authorization_original_digest",
        "consumer_operation_id","create_original_digest","create_receipt_digest"}
    if (db is None or type(value) is not dict or set(value) != expected
            or value["schema"] != "d11.owner-source-note-submit-consumed.v1"
            or row_data["state"] != "completed" or row_data["event_kind"] != SUBMITTED_EVENT
            or row_data["receiver_domain"] != "d11"
            or any(value[name] != row_data[name] for name in ("dedupe_key","causal_operation_id","consumer_operation_id"))
            ):
        raise ValueError("Owner submit disposition has another exact outbox/carrier schema")
    ids=owner_source_note_task_ids_v1(namespace,value["causal_operation_id"])
    if value["consumer_operation_id"] != ids["create_operation_id"]:
        raise ValueError("Owner submit consumer changed its deterministic task-create identity")
    causal=read_adopted_domain_operation_v1(db,namespace,value["causal_operation_id"])
    created=read_adopted_domain_operation_v1(db,namespace,value["consumer_operation_id"])
    if (causal is None or causal["operation_kind"] != "submit_owner_source_note_task_v1"
            or created is None or created["operation_kind"] != "create_owner_source_note_task_v1"
            or created["original_digest"] != value["create_original_digest"]
            or canonical_digest(created["receipt"]) != value["create_receipt_digest"]):
        raise ValueError("Owner submit consumer lost its actual committed task receipt")
    request=decode_typed_production_value_v1(created["payload"]["request"],CreateOwnerSourceNoteTaskRequestV1)
    if request.authorization_original_ref != value["authorization_original_ref"]:
        raise ValueError("Owner submit acknowledgement consumed another signed task")
    from .owner_source_note_task_contract_v1 import OwnerSourceNoteTaskAuthorizationV2
    auth=decode_typed_production_value_v1(causal["payload"]["provenance"]["owner_task_authorization"],OwnerSourceNoteTaskAuthorizationV2)
    if (row_data["original_ref"],row_data["original_digest"]) != ("d08-current:" + causal["original_digest"][:48],causal["original_digest"]):
        raise ValueError("Owner submit trigger changed its actual causal stage original")
    if auth.original_ref != value["authorization_original_ref"] or auth.digest != value["authorization_original_digest"]:
        raise ValueError("Owner submit causal authorization bytes differ")
    return True
