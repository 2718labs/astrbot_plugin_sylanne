"""Seven closed Artifact task entry preludes on an already qualified Source Work.

These recipes return values or typed command locators. They never invoke a
Graph public entry, transfer a READ context, or execute a child operation.
"""
from dataclasses import asdict,replace
from contextlib import contextmanager
from ..graph_types import AtomKey,Owner
from ..runtime_contracts import canonical_digest

_TASK_ENTRIES_V3=frozenset({
    'run_current_post_c02_artifact_task_setup_v1',
    'read_current_post_c02_artifact_task_choice_material_v3',
    'read_current_post_c02_artifact_method_prerequisites_v1',
    'run_current_post_c02_artifact_preparation_step_v1',
    'begin_current_artifact_method_group_v3',
    'checkpoint_current_artifact_phase_v2',
    'run_current_post_c02_artifact_method_final_operation_v2'})


@contextmanager
def _snapshot_v3(reader):
    store=reader.graph._GraphCoordinator__store
    with store._lock:
        db=store._db;db.execute('BEGIN')
        try:yield db
        finally:db.rollback()


def _point_v3(reader,table,columns,key_columns,key):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    db=reader.graph._GraphCoordinator__store._db
    return _producer_original_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key,
        legacy_reader=lambda:db.execute('SELECT '+','.join(columns)+' FROM '+table+' WHERE '+
            ' AND '.join(name+'=?'for name in key_columns),key).fetchone())


def _cycle_v3(reader,state):
    from .artifact_host_control_algorithms_v3 import read_artifact_cycle_receipt_v3
    return read_artifact_cycle_receipt_v3(reader,state)


def _phase_v3(reader,state):
    from .artifact_host_control_algorithms_v3 import read_artifact_phase_resume_v3
    return read_artifact_phase_resume_v3(reader,state)


def _current_task_v3(reader,state,db):
    from ..graph_coordinator import UnavailableGuard
    from .foreground_cycle_v1 import foreground_cycle_ids_v1
    from .jobs import get_job
    from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    q=state.selector;namespace=reader.bundle.installation_policy.namespace
    job=get_job(db,foreground_cycle_ids_v1(namespace,q.c02_operation_id)[1])
    responsibility=read_original_foreground_responsibility_for_c09_v1(db,namespace=namespace,job=job,
        issuer=reader.graph._GraphCoordinator__d11_issuer)
    if responsibility is None or responsibility.source_ref!=q.source_ref or responsibility.root_registration_ref is None:
        raise UnavailableGuard('Artifact task recipe lost its actual Source/Root responsibility; HOLD')
    return artifact_draft_task_selector_v1(namespace,c02_operation_id=q.c02_operation_id,
        root_registration_ref=responsibility.root_registration_ref)


def _personal_readers_v3(reader):
    from .d08_personal_candidate_v1 import install_personal_candidate_readers_v1
    readers=getattr(reader.runtime,'_personal_candidate_readers_v1',None)
    if readers is None:
        readers=install_personal_candidate_readers_v1(graph=reader.graph,bootstrap=reader.bootstrap,bundle=reader.bundle)
    return readers


def _choice_material_v3(reader,state,*,complete):
    from .d08_personal_candidate_v1 import(CurrentArtifactTaskChoiceRequestV2,
        read_current_artifact_task_choice_material_v2,read_current_artifact_task_predecision_requests_v2)
    _cycle_v3(reader,state)
    readers=_personal_readers_v3(reader)
    with _snapshot_v3(reader)as db:
        task=_current_task_v3(reader,state,db)
        read=read_current_artifact_task_choice_material_v2 if complete else read_current_artifact_task_predecision_requests_v2
        return read(db,namespace=reader.bundle.installation_policy.namespace,
            request=CurrentArtifactTaskChoiceRequestV2(task),installed_readers=readers)


def _task_setup_v3(reader,state):
    from .artifact_host_control_algorithms_v3 import ArtifactControlCommandV3
    from .d08_personal_plan_v1 import CreateCurrentArtifactTaskPlanRequestV1,ReviseCurrentArtifactTaskPlanRequestV2
    from .d10_project_checkpoint_v1 import CreateCurrentArtifactTaskProjectRequestV1,InitializeCurrentArtifactTaskProjectCheckpointRequestV1
    constructors={'create_artifact_task_plan_v1':CreateCurrentArtifactTaskPlanRequestV1,
        'revise_artifact_task_plan_v2':ReviseCurrentArtifactTaskPlanRequestV2,
        'create_artifact_task_project_v1':CreateCurrentArtifactTaskProjectRequestV1,
        'initialize_artifact_task_project_checkpoint_v1':InitializeCurrentArtifactTaskProjectCheckpointRequestV1}
    kind=dict(state.selector.arguments)['operation_kind']
    if kind not in constructors:raise ValueError('unregistered Artifact task setup operation')
    _cycle_v3(reader,state)
    with _snapshot_v3(reader)as db:task=_current_task_v3(reader,state,db)
    return ArtifactControlCommandV3(kind,constructors[kind](task))


def _task_choice_v3(reader,state):
    from .artifact_host_control_algorithms_v3 import ArtifactControlValueV3
    complete=dict(state.selector.arguments).get('complete',False)
    if type(complete)is not bool:raise TypeError('Artifact choice completeness must retain its exact bool selector')
    return ArtifactControlValueV3(_choice_material_v3(reader,state,complete=complete))


def _method_prerequisites_v3(reader,state):
    from ..graph_coordinator import UnavailableGuard
    from .artifact_host_control_algorithms_v3 import ArtifactControlValueV3
    from .domain_background_read_v3 import background_json_loads_v3
    from .d08_personal_candidate_v1 import CurrentArtifactTaskChoiceMaterialV2,CurrentArtifactTaskPredecisionRequestsV2
    from ..model_broker.first_ingress_encoding import FIRST_INGRESS_METHOD_ENCODING_TEMPLATE_VERSION,FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION
    from .d02_method_readiness_v1 import QuoteCurrentMethodChoicesRequestV1,method_readiness_operation_id_v1
    from .d07_method_conditions_v1 import AdoptCurrentC1MethodConditionsRequestV1
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
    q=state.selector;material=dict(q.arguments)['material']
    if type(material)not in {CurrentArtifactTaskChoiceMaterialV2,CurrentArtifactTaskPredecisionRequestsV2}:
        raise TypeError('Artifact method prerequisites require their actual typed choice locator')
    actual=_choice_material_v3(reader,state,complete=False)
    if(material.selector,material.goal_head,material.plan_head)!=(actual.selector,actual.goal_head,actual.plan_head):
        raise UnavailableGuard('Artifact method prerequisites changed actual task/Goal/Plan heads; HOLD')
    with _snapshot_v3(reader):
        row=_point_v3(reader,'graph_first_ingress_c02_committed_seals_v2',('evidence_json','bundle_digest'),
            ('bot','persona','operation_id'),(*reader.bundle.installation_policy.namespace.as_tuple,q.c02_operation_id))
        evidence=None if row is None else background_json_loads_v3(row[0])
        nested=None if evidence is None else evidence.get('c1_task_result_v1')
        template=nested.get('template_version')if type(nested)is dict else None
    if template not in {FIRST_INGRESS_METHOD_ENCODING_TEMPLATE_VERSION,FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION}:
        return ArtifactControlValueV3(())
    return ArtifactControlValueV3((
        ('quote_current_method_choices_v1',QuoteCurrentMethodChoicesRequestV1(actual.selector)),
        ('adopt_current_c1_method_conditions_v1',AdoptCurrentC1MethodConditionsRequestV1(q.c02_operation_id,
            task_scope_ref_v1(actual.selector.root_registration_ref),actual.goal_head.key.token,
            actual.goal_head.revision,method_readiness_operation_id_v1(actual.selector,actual.plan_head)))))


def _preparation_step_v3(reader,state):
    from .artifact_host_control_algorithms_v3 import ArtifactControlCommandV3
    from .domain_production_registry_v1 import installed_operation_v1
    from .d08_personal_candidate_v1 import CurrentArtifactTaskChoiceRequestV2
    args=dict(state.selector.arguments);kind=args['operation_kind'];request=args['request']
    allowed={'input:register_artifact_task_text_extent','input:register_artifact_phase_postcondition_policy_v1',
        'quote_current_method_choices_v1','adopt_current_c1_method_conditions_v1',
        'input:freeze_artifact_candidate_preparation_v1','input:freeze_values','evaluate_values',
        'prepare_personal_candidates_v1','select_personal_step_v2'}
    if kind not in allowed:raise ValueError('unregistered exact Artifact preparation step')
    if type(request)is not installed_operation_v1(kind).request_type:raise TypeError('Artifact preparation requires its exact registered typed command')
    parent_steps={'input:freeze_artifact_candidate_preparation_v1','input:freeze_values','evaluate_values',
        'prepare_personal_candidates_v1','select_personal_step_v2'}
    preparation_task=None
    if kind in parent_steps:
        material=_choice_material_v3(reader,state,complete=True)
        preparation_task=CurrentArtifactTaskChoiceRequestV2(material.selector)
    else:_cycle_v3(reader,state)
    return ArtifactControlCommandV3(kind,request,preparation_task=preparation_task)


def _begin_method_group_v3(reader,state):
    from ..graph_coordinator import UnavailableGuard
    from .artifact_host_control_algorithms_v3 import ArtifactControlCommandV3,ArtifactControlValueV3
    from .foreground_cycle_v1 import(foreground_cycle_ids_v1,foreground_cycle_from_wire_v1,
        read_observed_foreground_call_plan_v1,CheckpointForegroundCycleRequestV2)
    from .foreground_call_plan_v1 import ForegroundCallPlanV1
    from .foreground_artifact_observation_plan_v3 import derive_initial_artifact_observation_plan_v3
    from .d08_personal_candidate_v1 import ConsumePersonalDecisionRequestV1,_selected_candidate_phase_selector_from_originals_v2
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    from .jobs import get_job
    from .first_ingress_v2 import trusted_upper
    q=state.selector;namespace=reader.bundle.installation_policy.namespace
    _cycle_v3(reader,state)
    now=trusted_upper(reader.graph._GraphCoordinator__content_fence_v2.read_ingress_clock(reader.graph._GraphCoordinator__scene_clock_policy))
    with _snapshot_v3(reader)as db:
        job=get_job(db,foreground_cycle_ids_v1(namespace,q.c02_operation_id)[1])
        current=foreground_cycle_from_wire_v1(job.continuation)
        if current.source_ref!=q.source_ref or job.cancel_epoch or job.phase!='running'or job.lease_holder is None:
            raise UnavailableGuard('initial Artifact group lost its current live task/worker; HOLD')
        if type(current.call_plan)is not ForegroundCallPlanV1:
            return ArtifactControlValueV3({'status':'existing_original_method_group','c02_operation_id':q.c02_operation_id})
        operation=dict(q.arguments)['prepared_candidates_operation_id']
        original=read_adopted_domain_operation_v1(db,namespace,operation)
        if original is None or(original['domain'],original['operation_kind'])!=('d08','prepare_personal_candidates_v1'):
            raise UnavailableGuard('initial Artifact group needs its actual D08 preparation; HOLD')
        decision_ref=original['payload']['provenance']['prepared_candidates']['future_decision_ref']
        selected=_selected_candidate_phase_selector_from_originals_v2(db,namespace=namespace,
            request=ConsumePersonalDecisionRequestV1(decision_ref=decision_ref,prepared_candidates_operation_id=operation),
            issuer=reader.graph._GraphCoordinator__d11_issuer)
        if selected is None:raise UnavailableGuard('initial Artifact group has no actual adopted eligible phase Decision; HOLD')
        responsibility=read_original_foreground_responsibility_for_c09_v1(db,namespace=namespace,job=job,
            issuer=reader.graph._GraphCoordinator__d11_issuer)
        if responsibility is None:raise UnavailableGuard('initial Artifact group lost actual Owner/Root responsibility; HOLD')
        observed=read_observed_foreground_call_plan_v1(db,namespace=namespace,continuation=current,
            issuer=reader.graph._GraphCoordinator__d11_issuer,installed_bundle=reader.bundle,owner_guard=responsibility.owner_guard)
        proposed=derive_initial_artifact_observation_plan_v3(db,namespace=namespace,continuation=replace(current,call_plan=observed),
            selector=selected,issuer=reader.graph._GraphCoordinator__d11_issuer,installed_bundle=reader.bundle,
            owner_guard=responsibility.owner_guard,now_utc=now)
        request=CheckpointForegroundCycleRequestV2(selected.task.cycle_job_ref,job.lease_holder,job.fence,replace(current,call_plan=proposed))
    return ArtifactControlCommandV3('checkpoint_foreground_cycle_v2',request)


def _checkpoint_phase_v3(reader,state):
    from ..graph_coordinator import UnavailableGuard
    from .artifact_host_control_algorithms_v3 import ArtifactControlCommandV3,ArtifactControlValueV3
    from .foreground_cycle_v1 import(foreground_cycle_ids_v1,foreground_cycle_from_wire_v1,
        derive_actual_completed_artifact_phase_plan_v2,CheckpointForegroundCycleRequestV2)
    from .jobs import get_job
    _cycle_v3(reader,state)
    actual=_phase_v3(reader,state)
    if actual is None:raise UnavailableGuard('actual Artifact phase group is absent; HOLD')
    q=state.selector;namespace=reader.bundle.installation_policy.namespace
    with _snapshot_v3(reader)as db:
        job=get_job(db,foreground_cycle_ids_v1(namespace,q.c02_operation_id)[1])
        continuation=foreground_cycle_from_wire_v1(job.continuation)
        updated=derive_actual_completed_artifact_phase_plan_v2(db,namespace=namespace,continuation=continuation,
            issuer=reader.graph._GraphCoordinator__d11_issuer)
        if updated==continuation.call_plan:
            return ArtifactControlValueV3({'status':'no_new_verified_phase','selector':actual['selector']})
        if job.phase!='running'or job.cancel_epoch or job.lease_holder is None:
            raise UnavailableGuard('phase checkpoint requires its actual live uncancelled cycle; HOLD')
        request=CheckpointForegroundCycleRequestV2(actual['selector'].task.cycle_job_ref,job.lease_holder,job.fence,
            replace(continuation,call_plan=updated))
    return ArtifactControlCommandV3('checkpoint_foreground_cycle_v2',request)


_FINAL_OPERATIONS_V3=frozenset({'input:register_life_outcome_v2','advance_life','settle_project_checkpoint','settle_personal_goal'})


def _read_saved_final_request_v3(reader,state,operation_kind):
    from ..graph_coordinator import UnavailableGuard
    from .foreground_cycle_v1 import foreground_cycle_ids_v1,foreground_cycle_from_wire_v1
    from .foreground_call_plan_v1 import ForegroundCallPlanV2
    from .foreground_artifact_observation_plan_v3 import ForegroundCallPlanV3
    from .d11_artifact_draft_content_v1 import artifact_method_final_operation_ids_v2
    from .artifact_task_observer_v1 import artifact_task_milestone_original_ref_v2,read_current_artifact_task_milestone_v2
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_registry_v1 import installed_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .jobs import get_job
    namespace=reader.bundle.installation_policy.namespace;q=state.selector
    with _snapshot_v3(reader)as db:
        job=get_job(db,foreground_cycle_ids_v1(namespace,q.c02_operation_id)[1])
        plan=foreground_cycle_from_wire_v1(job.continuation).call_plan
        if type(plan)not in {ForegroundCallPlanV2,ForegroundCallPlanV3}:return None
        phase=plan.phase_group.selector;ids=artifact_method_final_operation_ids_v2(phase)
        original=read_adopted_domain_operation_v1(db,namespace,ids[{
            'input:register_life_outcome_v2':'outcome_register','advance_life':'advance',
            'settle_project_checkpoint':'project_settle','settle_personal_goal':'goal'}[operation_kind]])
        if original is None:return None
        milestone=read_current_artifact_task_milestone_v2(db,namespace=namespace,
            original_ref=artifact_task_milestone_original_ref_v2(phase),issuer=reader.graph._GraphCoordinator__d11_issuer)
        operation=installed_operation_v1(operation_kind)
        if(original['domain'],original['operation_kind'])!=(operation.domain,operation_kind):
            raise UnavailableGuard('saved method settlement changed its exact producer; HOLD')
        if original['payload']['owner_guard']!=asdict(milestone.owner_guard):
            raise UnavailableGuard('saved method settlement changed its actual Owner; HOLD')
        return decode_typed_production_value_v1(original['payload']['request'],operation.request_type)


def _method_final_operation_v3(reader,state):
    from ..graph_coordinator import UnavailableGuard
    from .artifact_host_control_algorithms_v3 import ArtifactControlCommandV3
    from .foreground_cycle_v1 import foreground_cycle_ids_v1,foreground_cycle_from_wire_v1
    from .foreground_call_plan_v1 import ForegroundCallPlanV2
    from .foreground_artifact_observation_plan_v3 import ForegroundCallPlanV3
    from .jobs import get_job
    from .artifact_task_observer_v1 import artifact_task_milestone_original_ref_v2,read_current_artifact_task_milestone_v2
    from .d11_artifact_draft_content_v1 import artifact_method_final_operation_ids_v2,actual_artifact_phase_content_selector_v2
    from .d11_life_terminal_v1 import read_adopted_life_original_v1
    from .d11_life_contract_v1 import RegisteredLifeOutcomeV2,D11LifeTerminalV1,life_from_wire_v1
    from .domain_production_inputs_v1 import RegisterCurrentLifeOutcomeInputRequestV2
    from .d11_life_preparation_v1 import read_registered_life_plan_v2
    from ..domains.d10.production_operations_v1 import AdvanceCurrentLifeRequestV1
    from .d10_project_checkpoint_v1 import SettleCurrentProjectCheckpointRequestV1
    from .d08_personal_plan_v1 import SettleCurrentPersonalGoalRequestV1
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
    from .d11_types import runtime_cost_settlement_key
    from ..domains.d08.production_operations_v1 import observed_action_outcome_key_v1
    from ..domains.d08.execution import _decode_intent
    from .domain_background_read_v3 import background_json_loads_v3
    q=state.selector;kind=dict(q.arguments)['operation_kind']
    if kind not in _FINAL_OPERATIONS_V3:raise ValueError('unregistered Artifact method final operation')
    _cycle_v3(reader,state)
    replay=_read_saved_final_request_v3(reader,state,kind)
    if replay is not None:return ArtifactControlCommandV3(kind,replay)
    namespace=reader.bundle.installation_policy.namespace;issuer=reader.graph._GraphCoordinator__d11_issuer
    with _snapshot_v3(reader)as db:
        cycle=get_job(db,foreground_cycle_ids_v1(namespace,q.c02_operation_id)[1])
        continuation=foreground_cycle_from_wire_v1(cycle.continuation)
        if type(continuation.call_plan)not in {ForegroundCallPlanV2,ForegroundCallPlanV3}:
            raise UnavailableGuard('method finalization has no actual phase group; HOLD')
        phase=continuation.call_plan.phase_group.selector
        milestone=read_current_artifact_task_milestone_v2(db,namespace=namespace,
            original_ref=artifact_task_milestone_original_ref_v2(phase),issuer=issuer)
        if milestone.selector!=phase or milestone.ordered_phase_originals!=continuation.call_plan.phase_group.completed_phase_originals:
            raise UnavailableGuard('method finalization changed its actual completed prefix; HOLD')
        content=actual_artifact_phase_content_selector_v2(db,namespace=namespace,selector=phase,issuer=issuer)
        if content.phase_kind!='full':raise UnavailableGuard('method finalization requires its actual full file; HOLD')
        ids=artifact_method_final_operation_ids_v2(phase)
        actual=read_adopted_life_original_v1(db,namespace=namespace,result_ref=milestone.file_result_ref,issuer=issuer)
        if actual is None or canonical_digest(actual)!=milestone.file_result_digest:
            raise UnavailableGuard('method finalization lost its actual completed file original; HOLD')
        terminal=life_from_wire_v1(actual['terminal'],D11LifeTerminalV1)
        if terminal.status!='completed'or terminal.binding.effect_id!=milestone.readback.effect_id:
            raise UnavailableGuard('method finalization crossed its actual file effect; HOLD')
        progress_ref=AtomKey(Owner('activity',*namespace.as_tuple,terminal.binding.activity_id),
            'd10.life_progress.v1',terminal.binding.effect_id).token
        if kind=='input:register_life_outcome_v2':
            plan=read_registered_life_plan_v2(db,namespace=namespace,issuer=issuer,original_ref=terminal.binding.plan_original_ref)
            if plan is None:raise UnavailableGuard('method outcome lost its actual registered file plan; HOLD')
            action_key=AtomKey.from_token(plan.action_intent.ref)
            row=_point_v3(reader,'graph_atoms',('value','valid'),('token','bot','persona'),(action_key.token,*namespace.as_tuple))
            if row is None or row[1]!=1:raise UnavailableGuard('method outcome lost its actual adopted Action; HOLD')
            action=_decode_intent(background_json_loads_v3(row[0]))
            request=RegisterCurrentLifeOutcomeInputRequestV2(ids['outcome_ref'],RegisteredLifeOutcomeV2(
                plan_original_ref=terminal.binding.plan_original_ref,action_outcome_ref=observed_action_outcome_key_v1(action_key,action).token,
                start_original_ref=terminal.claim.original_ref,terminal_original_ref=terminal.original_ref,
                artifact_ref=terminal.binding.artifact_ref,artifact_digest=terminal.payload.artifact_digest,
                paid_cost_refs=(runtime_cost_settlement_key(*namespace.as_tuple,terminal.binding.activity_id,
                    terminal.binding.reservation_operation_id).token,)))
        elif kind=='advance_life':request=AdvanceCurrentLifeRequestV1(milestone.project_ref,ids['outcome_ref'])
        elif kind=='settle_project_checkpoint':
            key=project_checkpoint_key_v1(namespace,milestone.project_ref)
            row=_point_v3(reader,'graph_atoms',('revision','value','valid'),('token','bot','persona'),(key.token,*namespace.as_tuple))
            if row is None or row[2]!=1 or background_json_loads_v3(row[1])['plan_ref']!=phase.plan_ref:
                raise UnavailableGuard('method project settlement lost its actual checkpoint; HOLD')
            request=SettleCurrentProjectCheckpointRequestV1(milestone.project_ref,phase.plan_ref,progress_ref,None,row[0])
        else:
            rows=tuple(_point_v3(reader,'graph_atoms',('revision','value','valid'),('token','bot','persona'),
                (ref,*namespace.as_tuple))for ref in(milestone.goal_ref,phase.plan_ref))
            if any(row is None or row[2]!=1 for row in rows):raise UnavailableGuard('method Goal settlement lost actual control heads; HOLD')
            plan_value=background_json_loads_v3(rows[1][1])
            if(plan_value['goal_ref'],plan_value['goal_revision'])!=(milestone.goal_ref,rows[0][0]):
                raise UnavailableGuard('method Goal settlement changed current Goal/Plan pairing; HOLD')
            request=SettleCurrentPersonalGoalRequestV1(milestone.goal_ref,phase.plan_ref,progress_ref,rows[0][0],rows[1][0])
    return ArtifactControlCommandV3(kind,request)


def artifact_host_task_entry_recipe_v3(reader,state):
    """Only the exact admitted EntrySelector's seven task names dispatch here."""
    entry=state.selector.entry_kind
    if entry not in _TASK_ENTRIES_V3:raise ValueError('unregistered Artifact task entry recipe')
    if state.selector.stage!='start':raise ValueError('Artifact task recipe requires its initial immutable entry stage')
    recipe={
        'run_current_post_c02_artifact_task_setup_v1':_task_setup_v3,
        'read_current_post_c02_artifact_task_choice_material_v3':_task_choice_v3,
        'read_current_post_c02_artifact_method_prerequisites_v1':_method_prerequisites_v3,
        'run_current_post_c02_artifact_preparation_step_v1':_preparation_step_v3,
        'begin_current_artifact_method_group_v3':_begin_method_group_v3,
        'checkpoint_current_artifact_phase_v2':_checkpoint_phase_v3,
        'run_current_post_c02_artifact_method_final_operation_v2':_method_final_operation_v3}[entry]
    return recipe(reader,state)
