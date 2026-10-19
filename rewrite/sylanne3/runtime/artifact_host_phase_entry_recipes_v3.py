"""Actual phase and completion recipes; no WRITE or public entry replay."""
from dataclasses import replace
from ..runtime_contracts import canonical_digest
from ..graph_coordinator import UnavailableGuard
from .domain_background_read_v3 import background_json_loads_v3
from .artifact_host_control_algorithms_v3 import (ArtifactControlCommandV3,ArtifactControlValueV3,
    ArtifactControlNextV3,read_artifact_phase_resume_v3,_read_control_completed_method_v3)


def _entry_run_current_post_c02_artifact_phase_operation_v2(reader,state):
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    operation_kind=dict(state.selector.arguments)['operation_kind']
    """Derive an exact phase command from its currently selected original."""
    from .d11_artifact_draft_model_v1 import (PrepareArtifactDraftModelRequestV2,
        AcquireArtifactDraftModelRequestV2, read_artifact_draft_prepared_v2)
    from .d11_artifact_draft_content_v1 import AdoptArtifactDraftContentRequestV2, VerifyArtifactDraftPhaseRequestV2
    from .d08_personal_plan_v1 import ProposeCurrentArtifactPhaseActionRequestV2
    from .d02_life_body_preparation_v1 import PrepareArtifactDraftBodyRequestV1
    from .domain_production_inputs_v1 import RegisterCurrentPhaseDraftFilePlanInputRequestV2
    from .d11_life_product_adapter_v1 import artifact_phase_draft_plan_ref_v2
    from .d11_life_preparation_v1 import PrepareCurrentLifeRequestV1
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v2, artifact_draft_phase_original_ref_v2
    from .foreground_cycle_v1 import WakeArtifactDraftCycleRequestV2
    from .d10_project_checkpoint_v1 import (ActivateCurrentArtifactTaskProjectCheckpointRequestV1,
        ActivateCurrentArtifactTaskProjectCheckpointRequestV2)
    from .artifact_task_observer_v1 import RegisterCurrentArtifactTaskMilestoneRequestV2
    from .artifact_completion_receipt_v1 import DeriveArtifactCompletionReceiptRequestV1
    constructors = {"derive_artifact_completion_receipt_v1": DeriveArtifactCompletionReceiptRequestV1,
        "register_artifact_task_milestone_v2": RegisterCurrentArtifactTaskMilestoneRequestV2,
        "activate_artifact_task_project_checkpoint_v1": ActivateCurrentArtifactTaskProjectCheckpointRequestV1,
        "activate_artifact_task_project_checkpoint_v2": ActivateCurrentArtifactTaskProjectCheckpointRequestV2,
        "prepare_artifact_draft_model_v2": PrepareArtifactDraftModelRequestV2,
        "acquire_artifact_draft_model_v2": AcquireArtifactDraftModelRequestV2,
        "adopt_artifact_draft_content_v2": AdoptArtifactDraftContentRequestV2,
        "propose_artifact_draft_phase_action_v2": ProposeCurrentArtifactPhaseActionRequestV2,
        "input:register_artifact_phase_draft_plan_v2": RegisterCurrentPhaseDraftFilePlanInputRequestV2}
    if operation_kind not in {'serve_concern', "prepare_artifact_phase_observation_v1", *constructors, "wake_artifact_draft_cycle_v2", "prepare_artifact_draft_body", "prepare_life", "verify_artifact_draft_phase_v2", "register_artifact_phase_postcondition_contract_v1", "observe_artifact_phase_postconditions_v1"}:
        raise ValueError("unregistered installed artifact phase operation")
    if operation_kind=='derive_artifact_completion_receipt_v1':
        return ArtifactControlNextV3('prepare_current_artifact_completion_source_v1','start')
    actual = read_artifact_phase_resume_v3(reader,state)
    if actual is None:
        raise UnavailableGuard("actual current artifact phase is absent; HOLD")
    if not actual["generation"] and operation_kind not in {'derive_artifact_completion_receipt_v1', 'serve_concern', "prepare_artifact_phase_observation_v1", "observe_artifact_phase_postconditions_v1", "verify_artifact_draft_phase_v2", "register_artifact_task_milestone_v2"}:
        raise UnavailableGuard("actual check phase cannot perform a generation operation; HOLD")
    phase = actual["selector"]
    if operation_kind == "register_artifact_phase_postcondition_contract_v1":
        from .artifact_phase_postconditions_v1 import RegisterArtifactPhasePostconditionContractRequestV1
        from .d11_artifact_draft_model_v1 import _read_artifact_phase_selected_originals_v2
        from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV3
        with self._GraphCoordinator__store._lock:
            db = self._GraphCoordinator__store._db
            db.execute("BEGIN")
            try:
                _, chosen, _ = _read_artifact_phase_selected_originals_v2(db, selector=phase, issuer=self._GraphCoordinator__d11_issuer)
                if type(chosen.binding) is not ArtifactPhaseCandidateBindingV3:
                    raise UnavailableGuard("selected method lacks its preregistered policy; HOLD")
                request = RegisterArtifactPhasePostconditionContractRequestV1(phase, chosen.binding.postcondition_policy_ref)
            finally:
                db.rollback()
    elif operation_kind=='serve_concern':
        from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1
        from .foreground_artifact_observation_plan_v3 import artifact_observation_ids_v1
        condition='tone'if phase.phase_kind=='sample_check'else'task_semantics'
        request=ServeCurrentConcernRequestV1('background',artifact_observation_ids_v1(phase,condition)['question'])
    elif operation_kind=="prepare_artifact_phase_observation_v1":
        from .artifact_phase_observation_v1 import PrepareArtifactPhaseObservationRequestV1
        assessment=actual['assessment_request']
        condition='tone'if phase.phase_kind=='sample_check'else'task_semantics'
        request=PrepareArtifactPhaseObservationRequestV1(phase,assessment.contract_ref,assessment.file_result_ref,condition)
    elif operation_kind in {'serve_concern', "prepare_artifact_phase_observation_v1", "observe_artifact_phase_postconditions_v1", "verify_artifact_draft_phase_v2"}:
        from .d11_life_contract_v1 import draft_artifact_ref_v1
        from .artifact_phase_postconditions_v1 import artifact_phase_assessment_original_ref_v1
        if operation_kind == "observe_artifact_phase_postconditions_v1":
            request = actual["assessment_request"]
        else:
            if phase.generation:
                file_ref = draft_artifact_ref_v1(phase.task.namespace, artifact_draft_file_ids_v2(phase)["effect"])
            else:
                file_ref = actual["assessment_request"].file_result_ref
            refs = () if phase.generation else (artifact_phase_assessment_original_ref_v1(phase),)
            request = VerifyArtifactDraftPhaseRequestV2(phase, file_ref, refs)
    elif operation_kind == "wake_artifact_draft_cycle_v2":
        with self._GraphCoordinator__store._lock:
            db = self._GraphCoordinator__store._db
            db.execute("BEGIN")
            try:
                prepared = read_artifact_draft_prepared_v2(db, namespace=phase.task.namespace,
                    selector=phase, issuer=self._GraphCoordinator__d11_issuer)
                if prepared is None:
                    raise UnavailableGuard("phase wake lost actual original preparation; HOLD")
                request = WakeArtifactDraftCycleRequestV2(phase,
                    canonical_digest((phase.task.namespace, prepared.operation_id, "d11", "artifact_draft_phase_model_queued")))
            finally:
                db.rollback()
    elif operation_kind == "prepare_artifact_draft_body":
        configured = installed_bundle.artifact_draft.body_policy
        ids = artifact_draft_file_ids_v2(phase)
        request = PrepareArtifactDraftBodyRequestV1(ids["action"], configured.policy_ref,
            configured.policy_version, configured.effect_component_policy_ref, configured.cpu_ceiling_ms)
    elif operation_kind == "prepare_life":
        request = PrepareCurrentLifeRequestV1(artifact_phase_draft_plan_ref_v2(phase),
            artifact_draft_phase_original_ref_v2(phase) + ":file-prepare")
    else:
        request = constructors[operation_kind](phase)
    return ArtifactControlCommandV3(operation_kind,request,after='wake_acquire'if operation_kind=='wake_artifact_draft_cycle_v2'else'return')


def _entry_finish_current_artifact_receipt_cycle_v1(reader,state):
    self=reader.graph;bootstrap,installed_bundle=reader.bootstrap,reader.bundle
    c02_operation_id,source_ref=state.selector.c02_operation_id,state.selector.source_ref
    """Close only the real delivered V3 receipt, through a fresh formal Self W01."""
    self._admin(bootstrap)
    completed=_read_control_completed_method_v3(reader,state)
    if completed is None or completed['history_state']!='satisfied':
        raise UnavailableGuard('receipt completion lacks actual satisfied method history; HOLD')
    from .artifact_receipt_completion_v1 import FinishArtifactReceiptCycleRequestV1,finish_operation_id_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    body=FinishArtifactReceiptCycleRequestV1(completed['selector']);ns=installed_bundle.installation_policy.namespace
    with self._GraphCoordinator__store._lock:
        db=self._GraphCoordinator__store._db;db.execute('BEGIN')
        try:original=read_adopted_domain_operation_v1(db,ns,finish_operation_id_v1(body.selector))
        finally:db.rollback()
    if original is not None:return ArtifactControlValueV3({'status':'duplicate','receipt':original['receipt']})
    return ArtifactControlCommandV3('finish_artifact_receipt_cycle_v1',body)


def _completion_source_values_v3(reader,state,completed):
    from .artifact_completion_receipt_v1 import read_current_artifact_completion_receipt_v1
    from .first_ingress_v2 import trusted_upper
    ns=reader.namespace;q=reader.selector;graph=reader.graph
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    cue=state.source_metadata_v3(q.source_ref)
    if cue['source_id']!=state.seed.identity[0]or state.seed.identity[5]!='private':
        raise UnavailableGuard('completion receipt changed its actual admitted private ingress identity')
    with reader.store._lock:
        reader.db.execute('BEGIN')
        try:
            receipt=read_current_artifact_completion_receipt_v1(reader.db,namespace=ns,selector=completed['selector'],
                issuer=graph._GraphCoordinator__d11_issuer,installed_bundle=reader.bundle,
                owner_guard=completed['history'].owner_guard,now_utc=now,audiences=state.audiences)
            return {'status':'artifact_completion_source_current','receipt_original':receipt,
                'c02_operation_id':q.c02_operation_id,'source_ref':q.source_ref}
        finally:reader.db.rollback()


def _entry_prepare_current_artifact_completion_source_v1(reader,state):
    from .artifact_completion_receipt_v1 import DeriveArtifactCompletionReceiptRequestV1,receipt_ids_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    completed=_read_control_completed_method_v3(reader,state)
    if completed is None or completed['history_state']!='satisfied':
        raise UnavailableGuard('receipt requires actual satisfied method history; HOLD')
    with reader.store._lock:
        reader.db.execute('BEGIN')
        try:existing=read_adopted_domain_operation_v1(reader.db,reader.namespace,receipt_ids_v1(completed['selector'])['producer'])
        finally:reader.db.rollback()
    if existing is None:
        return ArtifactControlCommandV3('derive_artifact_completion_receipt_v1',
            DeriveArtifactCompletionReceiptRequestV1(completed['selector']),after='completion_source')
    return ArtifactControlValueV3(_completion_source_values_v3(reader,state,completed))
