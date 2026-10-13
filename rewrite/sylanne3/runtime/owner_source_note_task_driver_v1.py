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


def prepare_owner_source_note_task_values_v1(graph,bootstrap,bundle,*,authorization_original_ref,need_original_ref):
    from .owner_source_note_values_v1 import (FreezeOwnerSourceNoteValuesParentRequestV1,
        owner_source_note_values_ids_v1,read_owner_task_values_parent_v1)
    from .domain_production_inputs_v1 import FreezeCurrentValuesInputRequestV1
    from ..domains.d01.production_operations_v1 import EvaluateCurrentValuesRequestV1
    from ..authority_service.current_owner_source_note_task_v1 import (
        OwnerTaskActivityValuesChildRequestV1,owner_task_typed_command_digest_v1)
    from .domain_production_registry_v1 import installed_operation_v1
    auth,ids,job,cont=_task(graph,bundle,authorization_original_ref)
    key=runtime_job_key(*auth.cause.namespace.as_tuple,ids['activity_id'],job.job_id)
    parent_request=FreezeOwnerSourceNoteValuesParentRequestV1(authorization_original_ref,key.token,need_original_ref)
    values_ids=owner_source_note_values_ids_v1(auth.cause.namespace,parent_request)
    parent_result=run_owner_source_note_task_command_v1(graph,bootstrap,bundle,
        authorization_original_ref=authorization_original_ref,operation_kind='input:freeze_owner_source_note_values_parent_v1',
        request=parent_request,operation_id=values_ids['parent_operation_id'])
    if parent_result['coverage']!='complete':return parent_result
    store=graph._GraphCoordinator__store
    with store._lock:
        db=store._db;db.execute('BEGIN')
        try:
            saved=read_owner_task_values_parent_v1(db,namespace=auth.cause.namespace,
                original_ref=values_ids['parent_ref'],issuer=graph._GraphCoordinator__d11_issuer)
            if saved is None:raise ValueError('Owner Values parent has no actual same-W01 signed original')
            parent=saved[0]
        finally:db.rollback()
    outputs=[]
    for slot,kind,command in (
            ('freeze','input:freeze_values',FreezeCurrentValuesInputRequestV1(values_ids['candidate_set_ref'],values_ids['context_ref'])),
            ('evaluate','evaluate_values',EvaluateCurrentValuesRequestV1(values_ids['candidate_set_ref'],values_ids['context_ref']))):
        operation_id=values_ids[slot+'_operation_id']
        with store._lock:
            row=store._db.execute('SELECT revision FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
            current_job=get_job(store._db,job.job_id)
        selector=OwnerTaskActivityValuesChildRequestV1(auth.cause.namespace,auth.cause.installation_id,
            auth.original_ref,auth.digest,operation_id,kind,owner_task_typed_command_digest_v1(installed_operation_v1(kind),command),
            key.token,row[0],current_job.cancel_epoch,values_parent_original_ref=parent.original_ref,
            values_parent_original_digest=parent.digest,child_slot=slot)
        result=graph._GraphCoordinator__domain_production_runtime_v1.run_owner_source_note_task_current_v1(
            selector=selector,operation_kind=kind,request=command)
        if result['coverage']!='complete':return result
        outputs.append(result)
    checkpoint=checkpoint_owner_source_note_task_step_v1(graph,bootstrap,bundle,
        authorization_original_ref=auth.original_ref,next_step='select',
        completed_operation_ids=(values_ids['parent_operation_id'],values_ids['freeze_operation_id'],values_ids['evaluate_operation_id']))
    return {'parent':parent_result,'children':tuple(outputs),'checkpoint':checkpoint,
        'value_evaluation_operation_id':values_ids['evaluate_operation_id']}


def qualify_owner_source_note_task_v1(graph,bootstrap,bundle,*,authorization_original_ref):
    from .owner_source_note_need_v1 import PrepareOwnerSourceNoteNeedRequestV1
    auth,ids,job,cont=_task(graph,bundle,authorization_original_ref)
    key=runtime_job_key(*auth.cause.namespace.as_tuple,ids['activity_id'],ids['job_id'])
    operation_id='owner-note-need:'+canonical_digest((auth.cause.namespace,auth.original_ref))[:40]
    request=PrepareOwnerSourceNoteNeedRequestV1(auth.original_ref,key.token)
    result=run_owner_source_note_task_command_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
        operation_kind='prepare_owner_source_note_need_v1',request=request,operation_id=operation_id)
    if result['coverage']!='complete':return result
    checkpoint=checkpoint_owner_source_note_task_step_v1(graph,bootstrap,bundle,
        authorization_original_ref=auth.original_ref,next_step='values',completed_operation_ids=(operation_id,))
    return {'need':result,'checkpoint':checkpoint,'need_original_ref':result['original_ref']}


def select_owner_source_note_task_v1(graph,bootstrap,bundle,*,authorization_original_ref,
        need_original_ref,value_evaluation_operation_id):
    from ..domains.d08.personal_candidate_v1 import (SourceNoteCandidateBindingV1,
        PrepareCurrentPersonalCandidatesRequestV1,SelectCurrentPersonalStepRequestV2)
    auth,ids,job,cont=_task(graph,bundle,authorization_original_ref)
    binding=SourceNoteCandidateBindingV1(ids['candidate_ref'],ids['node_id'],auth.request.project_ref,
        auth.request.recipe_ref,auth.request.body_source_ref,ids['goal_key'].token,
        auth.request.target_entity_ref,auth.request.role_binding_ref)
    prep_id='owner-note-candidates:'+canonical_digest((auth.cause.namespace,auth.original_ref))[:40]
    request=PrepareCurrentPersonalCandidatesRequestV1(ids['plan_key'].token,ids['goal_key'].token,1,1,
        ids['selection_operation_id'],value_evaluation_operation_id,need_original_ref,(binding,))
    prepared=run_owner_source_note_task_command_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
        operation_kind='prepare_personal_candidates_v1',request=request,operation_id=prep_id)
    if prepared['coverage']!='complete':return prepared
    selected=run_owner_source_note_task_command_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
        operation_kind='select_personal_step_v2',request=SelectCurrentPersonalStepRequestV2(ids['plan_key'].token,
            ids['goal_key'].token,prep_id),operation_id=ids['selection_operation_id'])
    if selected['coverage']!='complete':return selected
    checkpoint=checkpoint_owner_source_note_task_step_v1(graph,bootstrap,bundle,
        authorization_original_ref=auth.original_ref,next_step='prepare_action',
        completed_operation_ids=(prep_id,ids['selection_operation_id']))
    return {'prepared':prepared,'selected':selected,'checkpoint':checkpoint}


def prepare_owner_source_note_task_action_body_v1(graph,bootstrap,bundle,*,authorization_original_ref):
    from .d08_personal_candidate_v1 import ConsumePersonalDecisionRequestV1,prospective_personal_decision_key_v1
    from ..domains.d08.personal_candidate_v1 import SourceNoteCandidateBindingV1
    from .d02_life_body_preparation_v1 import PrepareSourceNoteBodyRequestV1
    auth,ids,job,cont=_task(graph,bundle,authorization_original_ref)
    prep_id='owner-note-candidates:'+canonical_digest((auth.cause.namespace,auth.original_ref))[:40]
    decision=prospective_personal_decision_key_v1(auth.cause.namespace,ids['activity_id'],ids['selection_operation_id'],ids['plan_key'].token)
    binding=SourceNoteCandidateBindingV1(ids['candidate_ref'],ids['node_id'],auth.request.project_ref,
        auth.request.recipe_ref,auth.request.body_source_ref,ids['goal_key'].token,auth.request.target_entity_ref,auth.request.role_binding_ref)
    action_id='personal-source-note-action:'+canonical_digest((auth.cause.namespace,ids['selection_operation_id'],binding))[:48]
    if cont.step=='prepare_action':
        action=run_owner_source_note_task_command_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
            operation_kind='prepare_selected_source_note_action_v2',request=ConsumePersonalDecisionRequestV1(decision.token,prep_id),
            operation_id=action_id)
        if action['coverage']!='complete':return action
        checkpoint_owner_source_note_task_step_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
            next_step='prepare_body',completed_operation_ids=(action_id,))
    auth,ids,job,cont=_task(graph,bundle,authorization_original_ref)
    store=graph._GraphCoordinator__store
    with store._lock:
        db=store._db;db.execute('BEGIN')
        try:
            from .d11_life_preparation_v1 import _read
            from .d08_source_note_action_v1 import source_note_action_original_from_wire_v1
            saved=_read(db,issuer=graph._GraphCoordinator__d11_issuer,namespace=auth.cause.namespace,
                kind='source_note_action',ref='life-root:'+action_id)
            if saved is None:raise ValueError('Owner task selected Action has no actual signed original')
            root=source_note_action_original_from_wire_v1(saved[0])
        finally:db.rollback()
    body_id='d02-life-body:'+action_id
    request=PrepareSourceNoteBodyRequestV1(root.action_intent_ref,auth.body_policy.body_policy_id,
        auth.body_policy.body_policy_version,auth.body_policy.effect_policy_ref,auth.body_policy.cpu_ceiling_ms)
    body=run_owner_source_note_task_command_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
        operation_kind='prepare_source_note_body',request=request,operation_id=body_id)
    if body['coverage']!='complete':return body
    checkpoint=checkpoint_owner_source_note_task_step_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
        next_step='register_life_plan',completed_operation_ids=(body_id,))
    return {'body':body,'checkpoint':checkpoint}


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


def adopt_owner_source_note_task_outcome_v1(graph,bootstrap,bundle,*,authorization_original_ref):
    from .owner_source_note_life_v1 import RegisterOwnerSourceNoteLifeOutcomeRequestV1,owner_source_note_life_ids_v1
    from .d11_life_preparation_v1 import read_registered_life_plan_v2,life_ids_v1,read_prepared_life_by_ref_v1
    from .d11_life_contract_v1 import life_adoption_operation_id_v1
    from ..domains.d10.production_operations_v1 import AdvanceCurrentLifeRequestV1
    from .d08_personal_plan_v1 import SettleCurrentPersonalGoalRequestV1
    auth,_,job,cont=_task(graph,bundle,authorization_original_ref);ids=owner_source_note_life_ids_v1(auth)
    store=graph._GraphCoordinator__store
    with store._lock:
        db=store._db;db.execute('BEGIN')
        try:
            plan=read_registered_life_plan_v2(db,namespace=auth.cause.namespace,issuer=graph._GraphCoordinator__d11_issuer,
                original_ref=ids['plan_ref'])
            prepared=read_prepared_life_by_ref_v1(db,namespace=auth.cause.namespace,issuer=graph._GraphCoordinator__d11_issuer,
                prepared_original_ref=life_ids_v1(plan)['prepared'])
            adoption_id=life_adoption_operation_id_v1(prepared.binding)
        finally:db.rollback()
    if cont.step=='observe_life':
        checkpoint_owner_source_note_task_step_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
            next_step='adopt_outcome',completed_operation_ids=(adoption_id,))
    outcome=run_owner_source_note_task_command_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
        operation_kind='register_owner_source_note_life_outcome_v1',request=RegisterOwnerSourceNoteLifeOutcomeRequestV1(auth.original_ref),
        operation_id=ids['outcome_operation_id'])
    if outcome['coverage']!='complete':return outcome
    progress=run_owner_source_note_task_command_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
        operation_kind='advance_life',request=AdvanceCurrentLifeRequestV1(auth.request.project_ref,ids['outcome_ref']),
        operation_id=ids['advance_operation_id'])
    if progress['coverage']!='complete':return progress
    settled=run_owner_source_note_task_command_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
        operation_kind='settle_personal_goal',request=SettleCurrentPersonalGoalRequestV1(ids['goal_key'].token,
            ids['plan_key'].token,ids['progress_ref'],1,1),operation_id=ids['settle_operation_id'])
    if settled['coverage']!='complete':return settled
    from ..authority_service.current_owner_source_note_task_v1 import read_completed_owner_source_note_task_v1
    with store._lock:
        db=store._db;db.execute('BEGIN')
        try:
            proof=read_completed_owner_source_note_task_v1(db,namespace=auth.cause.namespace,authorization=auth,
                issuer=graph._GraphCoordinator__d11_issuer)
            if proof is None:raise ValueError('Owner task settlement has no actual completed artifact proof')
            artifact_ref=proof.artifact_ref
        finally:db.rollback()
    checkpoint=checkpoint_owner_source_note_task_step_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
        next_step='completed',completed_operation_ids=(ids['outcome_operation_id'],ids['advance_operation_id'],
            ids['settle_operation_id']),completion_result_ref=artifact_ref)
    return {'status':'completed','outcome':outcome,'progress':progress,'settlement':settled,'checkpoint':checkpoint}


def drive_owner_source_note_task_v1(graph,bootstrap,bundle,*,authorization_original_ref):
    """Advance one actual task once; uncertainty returns without a second execution."""
    graph._admin(bootstrap)
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .owner_source_note_values_v1 import FreezeOwnerSourceNoteValuesParentRequestV1,owner_source_note_values_ids_v1
    auth,ids,job,cont=_task(graph,bundle,authorization_original_ref)
    if job is None:
        created=graph.create_owner_source_note_task_v1(bootstrap,bundle,authorization_original_ref=auth.original_ref)
        if created['coverage']!='complete':return created
        auth,ids,job,cont=_task(graph,bundle,authorization_original_ref)
    if job.phase=='queued':
        acquired=graph.acquire_owner_source_note_task_v1(bootstrap,bundle,authorization_original_ref=auth.original_ref)
        if acquired['coverage']!='complete':return acquired
        auth,ids,job,cont=_task(graph,bundle,authorization_original_ref)
    if job.phase!='running':
        return {'status':job.phase,'job_id':job.job_id,'step':cont.step,
            'pending_effect_refs':cont.pending_effect_refs,'original_deadline_utc':auth.cause.original_deadline_utc}
    results=[]
    for _ in range(8):
        auth,ids,job,cont=_task(graph,bundle,authorization_original_ref)
        before_step=cont.step
        if cont.step=='qualify':
            result=qualify_owner_source_note_task_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref)
        elif cont.step in {'values','select'}:
            need_op='owner-note-need:'+canonical_digest((auth.cause.namespace,auth.original_ref))[:40]
            store=graph._GraphCoordinator__store
            with store._lock:
                db=store._db;db.execute('BEGIN')
                try:
                    need=read_adopted_domain_operation_v1(db,auth.cause.namespace,need_op)
                    if need is None:raise ValueError('Owner task lacks its actual prior Need producer')
                    need_ref='d07-current:'+need['original_digest'][:48]
                finally:db.rollback()
            if cont.step=='values':
                result=prepare_owner_source_note_task_values_v1(graph,bootstrap,bundle,
                    authorization_original_ref=auth.original_ref,need_original_ref=need_ref)
            else:
                key=runtime_job_key(*auth.cause.namespace.as_tuple,ids['activity_id'],job.job_id)
                values_ids=owner_source_note_values_ids_v1(auth.cause.namespace,
                    FreezeOwnerSourceNoteValuesParentRequestV1(auth.original_ref,key.token,need_ref))
                result=select_owner_source_note_task_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref,
                    need_original_ref=need_ref,value_evaluation_operation_id=values_ids['evaluate_operation_id'])
        elif cont.step in {'prepare_action','prepare_body'}:
            result=prepare_owner_source_note_task_action_body_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref)
        elif cont.step in {'register_life_plan','prepare_life'}:
            result=prepare_owner_source_note_task_life_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref)
        elif cont.step in {'observe_life','adopt_outcome'}:
            result=adopt_owner_source_note_task_outcome_v1(graph,bootstrap,bundle,authorization_original_ref=auth.original_ref)
        elif cont.step=='execute_life':
            # Only an already adopted actual Native effect can have reached this
            # phase. The checkpoint itself re-reads those same formal originals.
            result=checkpoint_owner_source_note_task_step_v1(graph,bootstrap,bundle,
                authorization_original_ref=auth.original_ref,next_step='observe_life')
        elif cont.step=='completed':
            return {'status':'completed','job_id':job.job_id,'result_ref':job.result_ref,'operations':tuple(results)}
        else:raise ValueError('Owner task has an unregistered closed phase')
        results.append(result)
        _,_,current,current_cont=_task(graph,bundle,authorization_original_ref)
        if current.phase=='completed':
            return {'status':'completed','job_id':current.job_id,'result_ref':current.result_ref,'operations':tuple(results)}
        if current_cont.step==before_step or current.phase!='running':
            return {'status':result.get('status','held'),'job_id':current.job_id,'step':current_cont.step,
                'pending_effect_refs':result.get('pending_effect_refs',current_cont.pending_effect_refs),
                'operations':tuple(results)}
    raise ValueError('Owner task exceeded its finite phase walk without completion')
