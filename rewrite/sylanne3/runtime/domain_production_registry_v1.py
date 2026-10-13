"""Closed installed operation dispatch; no request controls code or SQL."""
from dataclasses import dataclass
from importlib import import_module


@dataclass(frozen=True, slots=True)
class InstalledDomainOperationV1:
    domain: str
    operation_kind: str
    request_type: type
    stage_name: str
    verifier_name: str
    capability: str


# Each row is part of the installed package. Public JSON selects an exact
# operation and supplies only that operation's strictly typed intent/locators.
_OPERATIONS = {
    "prepare_internal_life_numeric_drive": ("d04", "PrepareLifeNumericDriveRequestV1", "stage_life_numeric_drive_in_transaction_v1", "workbench.create"),
    "prepare_internal_life_numeric_joint": ("d04", "PrepareLifeNumericJointRequestV1", "stage_life_numeric_joint_in_transaction_v1", "workbench.create"),
    "prepare_internal_life_interval_baseline": ("d06", "PrepareLifeEncodingBaselineRequestV1", "stage_current_life_encoding_baseline_v1", "workbench.create"),
    "adopt_internal_life_numeric_trace": ("d06", "AdoptLifeNumericTraceRequestV1", "stage_life_numeric_trace_in_transaction_v1", "workbench.create"),
    "prepare_internal_life_numeric": ("d11", "PrepareInternalLifeNumericRequestV1", "stage_prepare_life_numeric_in_transaction_v1", "workbench.create"),
    "acquire_internal_life_numeric": ("d11", "AcquireInternalLifeNumericRequestV1", "stage_acquire_life_numeric_in_transaction_v1", "workbench.create"),
    "adopt_internal_life_numeric": ("d04", "AdoptInternalLifeNumericRequestV1", "stage_adopt_life_numeric_appraisal_in_transaction_v1", "workbench.create"),
    "prepare_internal_life_numeric_context": ("d06", "PrepareLifeNumericContextRequestV1", "stage_life_numeric_context_in_transaction_v1", "workbench.create"),
    "acquire_internal_life_content_v2": ("d11", "AcquireInternalLifeContentRequestV2", "stage_acquire_internal_life_content_in_transaction_v2", "workbench.create"),
    "acquire_internal_life_content": ("d11", "AcquireInternalLifeContentRequestV1", "stage_acquire_internal_life_content_in_transaction_v1", "workbench.create"),
    "prepare_contact_dispatch_v3": ("d08", "PrepareCurrentContactDispatchRequestV3", "stage_prepare_current_contact_dispatch_in_transaction_v3", "workbench.create"),
    "prepare_internal_life_content": ("d11", "PrepareInternalLifeContentRequestV1", "stage_prepare_internal_life_content_in_transaction_v1", "workbench.create"),
    "prepare_contact_model_v2": ("d11", "PrepareCurrentContactModelRequestV2", "stage_prepare_current_contact_model_in_transaction_v2", "workbench.create"),
    "adopt_contact_expression_plan_v2": ("d08", "AdoptCurrentContactExpressionPlanRequestV2", "stage_adopt_current_contact_expression_plan_in_transaction_v2", "workbench.create"),
    "adopt_internal_life_content_v1": ("d06","AdoptInternalLifeContentRequestV1","stage_adopt_internal_life_content_in_transaction_v1","workbench.create"),
    "prepare_contact_dispatch": ("d08", "PrepareCurrentContactDispatchRequestV2", "stage_prepare_current_contact_dispatch_in_transaction_v2", "workbench.create"),
    "adopt_contact_expression_plan": ("d08", "AdoptCurrentContactExpressionPlanRequestV1", "stage_adopt_current_contact_expression_plan_in_transaction_v1", "workbench.create"),
    "prepare_contact_model": ("d11", "PrepareCurrentContactModelRequestV1", "stage_prepare_current_contact_model_in_transaction_v1", "workbench.create"),
    "focus_life_project": ("d07", "FocusLifeProjectRequestV1", "stage_focus_life_project_in_transaction_v1", "workbench.create"),
    "prepare_life_project_context": ("d03", "PrepareLifeProjectContextRequestV1", "stage_prepare_life_project_context_in_transaction_v1", "workbench.create"),
    "prepare_source_note_action": ("d08", "PrepareSourceNoteActionRequestV1", "stage_prepare_source_note_action_in_transaction_v1", "workbench.create"),
    "prepare_source_note_body": ("d02", "PrepareSourceNoteBodyRequestV1", "stage_prepare_source_note_body_in_transaction_v1", "workbench.create"),
    "prepare_artifact_draft_body": ("d02", "PrepareArtifactDraftBodyRequestV1", "stage_prepare_artifact_draft_body_in_transaction_v1", "workbench.create"),
    "record_host_lifecycle": ("d11", "HostLifecycleRequestV1", "stage_current_host_lifecycle_in_transaction_v1", "workbench.create"),
    "prepare_offline_tick": ("d10", "PrepareCurrentOfflineTickRequestV1", "stage_prepare_current_offline_tick_in_transaction_v1", "workbench.create"),
    "prepare_life": ("d10", "PrepareCurrentLifeRequestV1", "stage_prepare_current_life_in_transaction_v1", "workbench.create"),
    "encode_structured_experience": ("d06", "EncodeCurrentStructuredExperienceRequestV1", "stage_encode_current_structured_experience_in_transaction_v1", "workbench.create"),
    "encode_internal_life": ("d06", "EncodeInternalLifeRequestV1", "stage_encode_internal_life_in_transaction_v1", "workbench.create"),
    "form_association": ("d06", "FormCurrentAssociationRequestV1", "stage_form_current_association_in_transaction_v1", "workbench.create"),
    "evaluate_values": ("d01", "EvaluateCurrentValuesRequestV1", "stage_evaluate_current_values_in_transaction_v1", "workbench.read"),
    "migrate_semantic_identity_v3": ("d01", "MigrateSemanticIdentityRequestV3", "stage_migrate_semantic_identity_v3", "workbench.activate"),
    "project_self_model_v3": ("d01", "ProjectSelfModelRequestV3", "stage_project_self_model_v3", "workbench.read"),
    "adopt_growth": ("d01", "AdoptCurrentGrowthRequestV1", "stage_adopt_current_growth_in_transaction_v1", "workbench.activate"),
    "advance_body": ("d02", "AdvanceCurrentBodyRequestV1", "stage_advance_current_body_in_transaction_v1", "workbench.activate"),
    "apply_body_effect": ("d02", "ApplyCurrentBodyEffectRequestV1", "stage_apply_current_body_effect_in_transaction_v1", "workbench.activate"),
    "adopt_relationship_contribution": ("d05", "AdoptCurrentRelationshipContributionRequestV1", "stage_adopt_current_relationship_contribution_in_transaction_v1", "workbench.create"),
    "revise_boundary": ("d05", "ReviseCurrentBoundaryRequestV1", "stage_revise_current_boundary_in_transaction_v1", "workbench.activate"),
    "reevaluate_relationship": ("d05", "ReevaluateCurrentRelationshipRequestV1", "stage_reevaluate_current_relationship_in_transaction_v1", "workbench.activate"),
    "serve_concern": ("d07", "ServeCurrentConcernRequestV1", "stage_serve_current_concern_in_transaction_v1", "workbench.create"),
    "advance_reflection": ("d07", "AdvanceCurrentReflectionRequestV1", "stage_advance_current_reflection_in_transaction_v1", "workbench.activate"),
    "run_simulation": ("d07", "RunCurrentSimulationRequestV1", "stage_run_current_simulation_in_transaction_v1", "workbench.create"),
    "recheck_action": ("d08", "RecheckCurrentActionRequestV1", "stage_recheck_current_action_in_transaction_v1", "workbench.read"),
    "settle_observed_action": ("d08", "SettleCurrentObservedActionRequestV1", "stage_settle_current_observed_action_in_transaction_v1", "workbench.activate"),
    "acknowledge_bilateral": ("d08", "AcknowledgeCurrentBilateralRequestV1", "stage_acknowledge_current_bilateral_in_transaction_v1", "workbench.activate"),
    "adopt_joint_plan": ("d08", "AdoptCurrentJointPlanRequestV1", "stage_adopt_current_joint_plan_in_transaction_v1", "workbench.activate"),
    "advance_life": ("d10", "AdvanceCurrentLifeRequestV1", "stage_current_life_effect_experience_bundle_in_transaction_v1", "workbench.activate"),
    "advance_offline": ("d10", "AdvanceCurrentOfflineRequestV1", "stage_current_offline_body_experience_bundle_in_transaction_v1", "workbench.activate"),
    "prepare_contact": ("d10", "PrepareCurrentContactRequestV1", "stage_prepare_current_contact_in_transaction_v1", "workbench.create"),
}


_PERSONAL_OPERATIONS = {
    "cancel_owner_source_note_task_v1": ("d11", ".cancel_owner_source_note_task_v1", "CancelOwnerSourceNoteTaskRequestV1", "stage_cancel_owner_source_note_task_v1", "verify_cancel_owner_source_note_task_stage_v1", "workbench.control"),
    "register_owner_source_note_life_plan_v1": ("d10", ".owner_source_note_life_v1", "RegisterOwnerSourceNoteLifePlanRequestV1", "stage_register_owner_source_note_life_plan_v1", "", "workbench.create"),
    "register_owner_source_note_life_outcome_v1": ("d10", ".owner_source_note_life_v1", "RegisterOwnerSourceNoteLifeOutcomeRequestV1", "stage_register_owner_source_note_life_outcome_v1", "", "workbench.create"),
    "input:freeze_owner_source_note_values_parent_v1": ("d08", ".owner_source_note_values_v1", "FreezeOwnerSourceNoteValuesParentRequestV1", "stage_freeze_owner_source_note_values_parent_v1", "", "workbench.create"),
    "admit_owner_material_source_v1": ("d06", ".owner_material_source_v1", "AdmitOwnerMaterialSourceRequestV1", "stage_admit_owner_material_source_v1", "", "workbench.create"),
    "checkpoint_owner_source_note_task_v1": ("d11", ".owner_source_note_task_execution_v1", "CheckpointOwnerSourceNoteTaskRequestV1", "stage_checkpoint_owner_source_note_task_v1", "", "workbench.create"),
    "create_owner_source_note_task_v1": ("d11", ".owner_source_note_task_execution_v1", "CreateOwnerSourceNoteTaskRequestV1", "stage_create_owner_source_note_task_v1", "", "workbench.create"),
    "acquire_owner_source_note_task_v1": ("d11", ".owner_source_note_task_execution_v1", "AcquireOwnerSourceNoteTaskRequestV1", "stage_acquire_owner_source_note_task_v1", "", "workbench.create"),
    "prepare_owner_source_note_need_v1": ("d07", ".owner_source_note_need_v1", "PrepareOwnerSourceNoteNeedRequestV1", "stage_prepare_owner_source_note_need_v1", "", "workbench.create"),
    "submit_owner_source_note_task_v1": ("d08", ".owner_source_note_task_v1", "SubmitOwnerSourceNoteTaskRequestV1", "stage_submit_owner_source_note_task_v1", "", "workbench.create"),
    "register_method_experiment_v2": ("d01", ".d01_method_learning_v1", "RegisterMethodExperimentRequestV2", "stage_register_method_experiment_v2", "verify_method_learning_stage_v1", "workbench.create"),
    "checkpoint_source_note_foreground_cycle_v1": ("d11", ".source_note_foreground_v1", "CheckpointSourceNoteForegroundCycleRequestV1", "stage_checkpoint_source_note_foreground_cycle_v1", "", "workbench.create"),
    "prepare_selected_source_note_action_v2": ("d08", ".d08_source_note_action_v1", "ConsumePersonalDecisionRequestV1", "stage_prepare_selected_source_note_action_v2", "", "workbench.create"),
    "register_method_trial_proposal_v2": ("d01", ".d01_method_learning_v1", "RegisterMethodTrialProposalRequestV2", "stage_register_method_trial_proposal_v2", "verify_method_learning_stage_v1", "workbench.create"),
    "register_scoped_method_trial_v2": ("d01", ".d01_method_learning_v1", "RegisterScopedMethodTrialRequestV2", "stage_register_scoped_method_trial_v2", "verify_method_learning_stage_v1", "workbench.create"),
    "register_method_blind_review_request_v2": ("d01", ".d01_method_learning_v1", "RegisterMethodBlindReviewRequestV2", "stage_register_method_blind_review_request_v2", "verify_method_learning_stage_v1", "workbench.create"),
    "authorize_source_note_task_v1": ("d11", ".source_note_task_authorization_v1", "AuthorizeSourceNoteTaskRequestV1", "stage_authorize_source_note_task_v1", "", "workbench.create"),
    "create_source_note_foreground_cycle_v1": ("d11", ".source_note_foreground_v1", "CreateSourceNoteForegroundCycleRequestV1", "stage_create_source_note_foreground_cycle_v1", "", "workbench.create"),
    "observe_method_comparison_v1": ("d11", ".d11_method_observation_v1", "ObserveMethodComparisonRequestV1", "stage_observe_method_comparison_v1", "verify_method_observation_stage_v1", "workbench.create"),
    "quote_current_method_choices_v1": ("d02", ".d02_method_readiness_v1", "QuoteCurrentMethodChoicesRequestV1", "stage_quote_current_method_choices_v1", "", "workbench.create"),
    "adopt_current_task_no_search_v1": ("d07", ".d07_task_history_v1", "AdoptCurrentTaskNoSearchRequestV1", "stage_adopt_current_task_no_search_v1", "", "workbench.create"),
    "initialize_relationship_prior_v2": ("d05", ".d05_relationship_revision_v2", "InitializeCurrentRelationshipPriorRequestV2", "stage_initialize_current_relationship_prior_v2", "", "workbench.create"),
    "adopt_current_c1_method_conditions_v1": ("d07", ".d07_method_conditions_v1", "AdoptCurrentC1MethodConditionsRequestV1", "stage_adopt_current_c1_method_conditions_v1", "", "workbench.create"),
    "register_method_evaluation_protocol_v1": ("d01", ".d01_method_learning_v1", "RegisterMethodEvaluationProtocolRequestV1", "stage_register_method_evaluation_protocol_v1", "verify_method_learning_stage_v1", "workbench.create"),
    "register_scoped_method_trial_v1": ("d01", ".d01_method_learning_v1", "RegisterScopedMethodTrialRequestV1", "stage_register_scoped_method_trial_v1", "verify_method_learning_stage_v1", "workbench.create"),
    "register_method_experiment_v1": ("d01", ".d01_method_learning_v1", "RegisterMethodExperimentRequestV1", "stage_register_method_experiment_v1", "verify_method_learning_stage_v1", "workbench.create"),
    "evaluate_current_method_outcome_v1": ("d01", ".d01_method_learning_v1", "EvaluateCurrentMethodOutcomeRequestV1", "stage_evaluate_current_method_outcome_v1", "verify_method_learning_stage_v1", "workbench.create"),
    "review_current_method_growth_v1": ("d01", ".d01_method_learning_v1", "ReviewCurrentMethodGrowthRequestV1", "stage_review_current_method_growth_v1", "verify_method_learning_stage_v1", "workbench.create"),
    "adopt_current_method_strategy_v1": ("d01", ".d01_method_learning_v1", "AdoptCurrentMethodStrategyRequestV1", "stage_adopt_current_method_strategy_v1", "verify_method_learning_stage_v1", "workbench.activate"),
    "pause_project_v1": ("d08", ".d08_project_control_v1", "PauseProjectRequestV1", "stage_pause_project_v1", "verify_project_control_stage_v1", "workbench.control"),
    "resume_project_v1": ("d08", ".d08_project_control_v1", "ResumeProjectRequestV1", "stage_resume_project_v1", "verify_project_control_stage_v1", "workbench.control"),
    "adopt_relationship_revision_v2": ("d05", ".d05_relationship_revision_v2", "AdoptCurrentRelationshipRevisionRequestV2", "stage_adopt_current_relationship_revision_in_transaction_v2", "", "workbench.create"),
    "create_artifact_task_plan_v1": ("d08", ".d08_personal_plan_v1", "CreateCurrentArtifactTaskPlanRequestV1", "stage_create_current_artifact_task_plan_in_transaction_v1", "verify_d08_personal_plan_stage_v1", "workbench.create"),
    "prepare_personal_candidates_v1": ("d08", ".d08_personal_candidate_v1", "PrepareCurrentPersonalCandidatesRequestV1", "stage_prepare_current_personal_candidates_in_transaction_v1", "", "workbench.create"),
    "select_personal_step_v2": ("d08", ".d08_personal_plan_v1", "SelectCurrentPersonalStepRequestV2", "stage_select_current_personal_step_in_transaction_v2", "", "workbench.create"),
    "create_personal_plan": ("d08", ".d08_personal_plan_v1", "CreateCurrentPersonalPlanRequestV1", "stage_create_current_personal_plan_in_transaction_v1", "verify_d08_personal_plan_stage_v1", "workbench.create"),
    "revise_personal_plan": ("d08", ".d08_personal_plan_v1", "ReviseCurrentPersonalPlanRequestV1", "stage_revise_current_personal_plan_in_transaction_v1", "verify_d08_personal_plan_stage_v1", "workbench.create"),
    "select_personal_step": ("d08", ".d08_personal_plan_v1", "SelectCurrentPersonalStepRequestV1", "stage_select_current_personal_step_in_transaction_v1", "verify_d08_personal_plan_stage_v1", "workbench.create"),
    "settle_personal_goal": ("d08", ".d08_personal_plan_v1", "SettleCurrentPersonalGoalRequestV1", "stage_settle_current_personal_goal_in_transaction_v1", "verify_d08_personal_plan_stage_v1", "workbench.activate"),
    "initialize_project_checkpoint": ("d10", ".d10_project_checkpoint_v1", "InitializeCurrentProjectCheckpointRequestV1", "stage_initialize_current_project_checkpoint_in_transaction_v1", "verify_d10_project_checkpoint_stage_v1", "workbench.create"),
    "refresh_project_checkpoint": ("d10", ".d10_project_checkpoint_v1", "RefreshCurrentProjectCheckpointRequestV1", "stage_refresh_current_project_checkpoint_in_transaction_v1", "verify_d10_project_checkpoint_stage_v1", "workbench.create"),
    "settle_project_checkpoint": ("d10", ".d10_project_checkpoint_v1", "SettleCurrentProjectCheckpointRequestV1", "stage_settle_current_project_checkpoint_in_transaction_v1", "verify_d10_project_checkpoint_stage_v1", "workbench.activate"),
}

_FOREGROUND_OPERATIONS = {
    "create_foreground_cycle_v2": "CreateForegroundCycleRequestV2",
    "checkpoint_foreground_cycle_v2": "CheckpointForegroundCycleRequestV2",
    "wake_artifact_draft_cycle_v1": "WakeArtifactDraftCycleRequestV1",
    "wake_artifact_draft_cycle_v2": "WakeArtifactDraftCycleRequestV2",
    "create_foreground_cycle": "CreateForegroundCycleRequestV1",
    "acquire_foreground_cycle": "AcquireForegroundCycleRequestV1",
    "checkpoint_foreground_cycle": "CheckpointForegroundCycleRequestV1",
    "wake_foreground_cycle": "WakeForegroundCycleRequestV1",
}

_ARTIFACT_OPERATIONS = {
    "revise_artifact_task_plan_v2": ("d08", ".d08_personal_plan_v1", "ReviseCurrentArtifactTaskPlanRequestV2", "stage_revise_current_artifact_task_plan_in_transaction_v2", ""),
    "activate_artifact_task_project_checkpoint_v2": ("d10", ".d10_project_checkpoint_v1", "ActivateCurrentArtifactTaskProjectCheckpointRequestV2", "stage_activate_current_artifact_task_project_checkpoint_v2", "verify_d10_project_checkpoint_stage_v1"),
    "register_artifact_task_milestone_v2": ("d08", ".artifact_task_observer_v1", "RegisterCurrentArtifactTaskMilestoneRequestV2", "stage_register_current_artifact_task_milestone_in_transaction_v2", ""),
    "prepare_artifact_draft_model_v2": ("d11", ".d11_artifact_draft_model_v1", "PrepareArtifactDraftModelRequestV2", "prepare_current_artifact_draft_model_v2", "validate_artifact_draft_model_proposal_v2"),
    "acquire_artifact_draft_model_v2": ("d11", ".d11_artifact_draft_model_v1", "AcquireArtifactDraftModelRequestV2", "acquire_current_artifact_draft_model_v2", "validate_artifact_draft_model_proposal_v2"),
    "derive_ingress_artifact_task_scope_v1": ("d10", ".ingress_artifact_task_scope_v1", "DeriveIngressArtifactTaskScopeRequestV1", "stage_derive_ingress_artifact_task_scope_v1", ""),
    "await_existing_artifact_revision_v1": ("d10", ".artifact_wait_checkpoint_v1", "ExistingArtifactContinuationRequestV1", "stage_await_existing_artifact_revision_v1", ""),
    "select_existing_artifact_continuation_v1": ("d08", ".artifact_continuation_originals_v1", "ExistingArtifactContinuationRequestV1", "stage_select_existing_artifact_continuation_v1", ""),
    "revise_existing_artifact_v1": ("d08", ".artifact_continuation_originals_v1", "ExistingArtifactContinuationRequestV1", "stage_revise_existing_artifact_v1", ""),
    "prepare_artifact_draft_model": ("d11", ".d11_artifact_draft_model_v1", "PrepareArtifactDraftModelRequestV1", "prepare_current_artifact_draft_model_v1", "validate_artifact_draft_model_proposal_v1"),
    "acquire_artifact_draft_model": ("d11", ".d11_artifact_draft_model_v1", "AcquireArtifactDraftModelRequestV1", "acquire_current_artifact_draft_model_v1", "validate_artifact_draft_model_proposal_v1"),
    "propose_artifact_draft_phase_action_v2": ("d08", ".d08_personal_plan_v1", "ProposeCurrentArtifactPhaseActionRequestV2", "stage_propose_current_artifact_phase_action_in_transaction_v2", "verify_d08_personal_plan_stage_v1"),
    "adopt_artifact_draft_content_v2": ("d06", ".d11_artifact_draft_content_v1", "AdoptArtifactDraftContentRequestV2", "adopt_current_artifact_draft_content_v2", "validate_artifact_draft_content_job_proposal_v2"),
    "verify_artifact_draft_phase_v2": ("d11", ".d11_artifact_draft_content_v1", "VerifyArtifactDraftPhaseRequestV2", "stage_verify_current_artifact_draft_phase_v2", ""),
    "adopt_artifact_draft_content": ("d06", ".d11_artifact_draft_content_v1", "AdoptArtifactDraftContentRequestV1", "adopt_current_artifact_draft_content_v1", "validate_artifact_draft_content_job_proposal_v1"),
    "compose_artifact_goal_plan": ("d08", ".d08_personal_plan_v1", "ComposeCurrentArtifactGoalPlanRequestV1", "stage_compose_current_artifact_goal_plan_in_transaction_v1", "verify_d08_personal_plan_stage_v1"),
    "create_artifact_project": ("d10", ".d10_project_checkpoint_v1", "CreateCurrentArtifactProjectRequestV1", "stage_create_current_artifact_project_in_transaction_v1", "verify_d10_artifact_project_stage_v1"),
    "create_artifact_task_project_v1": ("d10", ".d10_project_checkpoint_v1", "CreateCurrentArtifactTaskProjectRequestV1", "stage_create_current_artifact_task_project_in_transaction_v1", "verify_d10_artifact_task_stage_v1"),
    "initialize_artifact_task_project_checkpoint_v1": ("d10", ".d10_project_checkpoint_v1", "InitializeCurrentArtifactTaskProjectCheckpointRequestV1", "stage_initialize_current_artifact_task_project_checkpoint_v1", "verify_d10_artifact_task_stage_v1"),
    "activate_artifact_task_project_checkpoint_v1": ("d10", ".d10_project_checkpoint_v1", "ActivateCurrentArtifactTaskProjectCheckpointRequestV1", "stage_activate_current_artifact_task_project_checkpoint_v1", "verify_d10_artifact_task_stage_v1"),
    "prepare_artifact_draft_project_context": ("d03", ".d03_life_project_context_v1", "PrepareArtifactDraftProjectContextRequestV1", "stage_prepare_artifact_draft_project_context_in_transaction_v1", "verify_d03_artifact_project_context_stage_v1"),
    "propose_artifact_draft_action": ("d08", ".d08_personal_plan_v1", "ProposeCurrentArtifactActionRequestV1", "stage_propose_current_artifact_action_in_transaction_v1", "verify_d08_personal_plan_stage_v1"),
}


_POSTCONDITION_OPERATIONS = {
    "input:freeze_artifact_candidate_preparation_v1": ("d08", "FreezeArtifactCandidatePreparationRequestV1", "stage_freeze_artifact_candidate_preparation_v1"),
    "input:approve_artifact_standing_predecision_v2": ("d08", "ApproveArtifactStandingPredecisionRequestV2", "stage_approve_artifact_standing_predecision_v2"),
    "input:register_artifact_phase_postcondition_policy_v1": ("d08", "RegisterArtifactPhasePostconditionPolicyRequestV1", "stage_register_artifact_phase_postcondition_policy_v1"),
    "register_artifact_phase_postcondition_contract_v1": ("d08", "RegisterArtifactPhasePostconditionContractRequestV1", "stage_register_artifact_phase_postcondition_contract_v1"),
    "observe_artifact_phase_postconditions_v1": ("d11", "ObserveArtifactPhasePostconditionsRequestV1", "stage_observe_artifact_phase_postconditions_v1"),
}


def installed_operation_v1(operation_kind):
    if operation_kind == "input:freeze_owner_source_note_values_parent_v1":
        from .owner_source_note_values_v1 import FreezeOwnerSourceNoteValuesParentRequestV1
        return InstalledDomainOperationV1("d08", operation_kind, FreezeOwnerSourceNoteValuesParentRequestV1,
            "stage_freeze_owner_source_note_values_parent_v1", "", "workbench.create")
    if operation_kind in _POSTCONDITION_OPERATIONS:
        domain, request_name, stage_name = _POSTCONDITION_OPERATIONS[operation_kind]
        module = import_module(".artifact_phase_postconditions_v1", package=__package__)
        return InstalledDomainOperationV1(domain, operation_kind, getattr(module, request_name),
            stage_name, "", "workbench.create")
    if operation_kind in {"prepare_ingress_c04_v1", "adopt_ingress_c04_v1"}:
        from .c04_self_scope_v4 import PrepareIngressC04RequestV1
        return InstalledDomainOperationV1("d06", operation_kind, PrepareIngressC04RequestV1,
            "stage_self_c04_prepare_v4" if operation_kind == "prepare_ingress_c04_v1" else "stage_self_c04_adopt_v4",
            "", "workbench.create")
    if operation_kind == "select_ingress_recall_seed_v1":
        from .d06_ingress_c03_read_v1 import SelectIngressRecallSeedRequestV1
        return InstalledDomainOperationV1("d06", operation_kind, SelectIngressRecallSeedRequestV1,
            "stage_ingress_c03_selection_v1", "", "workbench.create")
    if operation_kind in {"prepare_ingress_recall_result_read_v1", "finish_ingress_recall_model_v1", "adopt_ingress_recall_model_v1"}:
        from .d07_ingress_recall_preparation_v1 import PrepareIngressRecallModelRequestV1
        domain = "d11" if operation_kind == "finish_ingress_recall_model_v1" else "d07"
        return InstalledDomainOperationV1(domain, operation_kind, PrepareIngressRecallModelRequestV1,
            "stage_current_ingress_recall_result_v1", "", "workbench.create")
    if operation_kind == "acquire_ingress_recall_model_v1":
        from .d07_ingress_recall_preparation_v1 import PrepareIngressRecallModelRequestV1
        return InstalledDomainOperationV1("d11", operation_kind, PrepareIngressRecallModelRequestV1,
            "acquire_current_ingress_recall_model_v1", "", "workbench.create")
    if operation_kind == "prepare_ingress_recall_model_v1":
        from .d07_ingress_recall_preparation_v1 import PrepareIngressRecallModelRequestV1
        return InstalledDomainOperationV1("d07", operation_kind, PrepareIngressRecallModelRequestV1,
            "prepare_current_ingress_recall_model_v1", "", "workbench.create")
    if operation_kind == "prepare_ingress_recall_need_v1":
        from .d06_ingress_recall_v1 import PrepareIngressRecallNeedRequestV1
        return InstalledDomainOperationV1("d07", operation_kind, PrepareIngressRecallNeedRequestV1,
            "stage_ingress_recall_need_in_transaction_v1", "", "workbench.create")
    if operation_kind == "adopt_owner_artifact_project_context_v1":
        from .d03_life_project_context_v1 import AdoptOwnerArtifactProjectContextRequestV1
        return InstalledDomainOperationV1("d03", operation_kind, AdoptOwnerArtifactProjectContextRequestV1,
            "stage_adopt_owner_artifact_project_context_in_transaction_v1", "", "workbench.create")
    if operation_kind == "owner_stop_reply_v1":
        from ..authority_service.owner_stop_reply_v1 import OwnerStopReplyRequestV1
        return InstalledDomainOperationV1("d11", operation_kind, OwnerStopReplyRequestV1,
            "stage_owner_stop_reply_projection_v1", "", "workbench.control")
    if operation_kind == "register_artifact_draft_root":
        from ..authority_service.current_foreground_activity_v1 import DraftRootRegistrationRequestV1
        return InstalledDomainOperationV1("d10", operation_kind, DraftRootRegistrationRequestV1,
            "stage_register_current_draft_root_in_transaction_v1", "", "workbench.create")
    if operation_kind in _ARTIFACT_OPERATIONS:
        domain, module_name, request_name, stage_name, verifier_name = _ARTIFACT_OPERATIONS[operation_kind]
        module = import_module(module_name, package=__package__)
        return InstalledDomainOperationV1(domain, operation_kind, getattr(module, request_name),
            stage_name, verifier_name, "workbench.create")
    if operation_kind in _FOREGROUND_OPERATIONS:
        from . import foreground_cycle_v1
        return InstalledDomainOperationV1("d11", operation_kind,
            getattr(foreground_cycle_v1, _FOREGROUND_OPERATIONS[operation_kind]),
            "stage_current_foreground_cycle_in_transaction_v1", "verify_foreground_cycle_stage_v1", "workbench.create")
    if type(operation_kind) is str and operation_kind.startswith("input:"):
        from .domain_production_inputs_v1 import input_operation_for_request_v1
        registered = input_operation_for_request_v1(operation_kind[len("input:"):])
        return InstalledDomainOperationV1(registered.domain, operation_kind, registered.request_type,
            "stage_current_domain_input_v1", "rebuild_current_domain_input_v1", registered.capability)
    if type(operation_kind) is str and operation_kind in _PERSONAL_OPERATIONS:
        domain, module_name, request_name, stage_name, verifier_name, capability = _PERSONAL_OPERATIONS[operation_kind]
        module = import_module(module_name, package=__package__)
        if operation_kind == "select_personal_step_v2":
            from ..domains.d08.personal_candidate_v1 import SelectCurrentPersonalStepRequestV2
            request_type = SelectCurrentPersonalStepRequestV2
        else:
            request_type = getattr(module, request_name)
        return InstalledDomainOperationV1(domain, operation_kind,
            request_type, stage_name, verifier_name, capability)
    if type(operation_kind) is not str or operation_kind not in _OPERATIONS:
        raise ValueError("unregistered installed domain operation")
    domain, request_name, stage_name, capability = _OPERATIONS[operation_kind]
    module = import_module(".d06_life_numeric_drive_v1" if operation_kind == "prepare_internal_life_numeric_drive" else
        ".d06_life_numeric_joint_v1" if operation_kind == "prepare_internal_life_numeric_joint" else
        ".d04_life_encoding_baseline_v1" if operation_kind == "prepare_internal_life_interval_baseline" else
        ".d06_life_numeric_trace_v1" if operation_kind == "adopt_internal_life_numeric_trace" else
        ".d06_life_numeric_task_v1" if operation_kind in {"prepare_internal_life_numeric", "adopt_internal_life_numeric"} else
        ".d06_life_numeric_worker_v1" if operation_kind == "acquire_internal_life_numeric" else
        ".d06_life_numeric_context_v1" if operation_kind == "prepare_internal_life_numeric_context" else
        ".internal_life_content_adoption_v1" if operation_kind == "adopt_internal_life_content_v1" else
        ".internal_life_content_worker_v2" if operation_kind == "acquire_internal_life_content_v2" else
        ".internal_life_content_worker_v1" if operation_kind == "acquire_internal_life_content" else
        ".internal_life_content_preparation_v1" if operation_kind == "prepare_internal_life_content" else
        ".d06_internal_life_encoding_v1" if operation_kind == "encode_internal_life" else
        ".contact_plan_adoption_v2" if operation_kind == "adopt_contact_expression_plan_v2" else
        ".contact_final_stage_v3" if operation_kind == "prepare_contact_dispatch_v3" else
        ".contact_final_stage_v2" if operation_kind == "prepare_contact_dispatch" else
        ".contact_plan_adoption_v1" if operation_kind == "adopt_contact_expression_plan" else
        ".contact_product_adapter_v2" if operation_kind == "prepare_contact_model_v2" else
        ".contact_product_adapter_v1" if operation_kind == "prepare_contact_model" else
        ".d07_life_project_focus_v1" if operation_kind == "focus_life_project" else
        ".d03_life_project_context_v1" if operation_kind == "prepare_life_project_context" else
        ".d08_source_note_action_v1" if operation_kind == "prepare_source_note_action" else
        ".d02_life_body_preparation_v1" if operation_kind in {"prepare_source_note_body", "prepare_artifact_draft_body"} else
        ".d11_host_lifecycle_v1" if operation_kind == "record_host_lifecycle" else
        ".d11_life_preparation_v1" if operation_kind == "prepare_life" else
        ".d10_offline_tick_execution_v1" if operation_kind == "prepare_offline_tick" else
        ".d06_association_formation_v1" if operation_kind == "form_association" else
        "..domains.d06.structured_experience_v1" if domain == "d06" else ".d07_current_behavior_v1" if domain == "d07"
        else "..domains." + domain + ".production_operations_v1", package=__package__)
    request_type = getattr(module, request_name)
    return InstalledDomainOperationV1(domain, operation_kind, request_type, stage_name,
        "verify_" + domain + "_production_stage_v1", capability)


def installed_readers_for_operation_v1(graph, operation, *, scope, owner_guard, execution_reader=None, foreground_issuance=None, owner_binding=None, owner_task_issuance=None):
    from ..graph_coordinator import GraphCoordinator
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from ..runtime_contracts import FenceScope
    if (type(graph) is not GraphCoordinator or type(operation) is not InstalledDomainOperationV1
            or type(scope) is not FenceScope
            or installed_operation_v1(operation.operation_kind) != operation
            or foreground_issuance is None and owner_task_issuance is None and (type(owner_guard) is not OwnerAuthorizationGuardV1
                or owner_guard.namespace != scope.namespace)):
        raise ValueError("domain operation needs its actual installed current Owner fence")
    if foreground_issuance is not None:
        from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
        evidence = require_foreground_activity_issuance_v1(foreground_issuance, graph, scope)
        if evidence.owner_guard != owner_guard or evidence.request.operation_kind != operation.operation_kind:
            raise ValueError("foreground readers need their actual paired current operation issuance")
    if owner_task_issuance is not None:
        if foreground_issuance is not None or owner_binding is not None:
            raise ValueError("Owner task Self issuance cannot borrow a Foreground or Owner lease")
        from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_issuance_v1
        task_evidence = require_owner_source_note_task_issuance_v1(owner_task_issuance, graph, scope)
        from .domain_production_contracts_v1 import ProductionOwnerGuardV1
        if (type(owner_guard) is not ProductionOwnerGuardV1
                or task_evidence.owner_guard != owner_guard
                or task_evidence.request.namespace != scope.namespace
                or task_evidence.request.operation_kind != operation.operation_kind):
            raise ValueError("Owner task readers changed their actual paired current Core issuance")
    issuer = graph._GraphCoordinator__d11_issuer
    if operation.operation_kind == "input:approve_artifact_standing_predecision_v2":
        if foreground_issuance is not None or type(owner_guard) is not OwnerAuthorizationGuardV1 or owner_guard.namespace != scope.namespace:
            raise ValueError("standing approval is exclusive to the actual Owner fence, never Self issuance")
        from .artifact_phase_postconditions_v1 import install_artifact_standing_predecision_approval_readers_v2
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None:
            raise ValueError("standing approval requires its actual installed initial bundle")
        return install_artifact_standing_predecision_approval_readers_v2(graph, scope=scope,
            owner_guard=owner_guard, bundle=assembly.admin_bundle)
    if operation.operation_kind in {"prepare_ingress_c04_v1", "adopt_ingress_c04_v1"}:
        from .c04_ingress_preparation_v4 import InstalledSelfC04ReadersV4
        if foreground_issuance is None:
            raise ValueError("Self C04 requires actual private Foreground issuance")
        environment = graph._GraphCoordinator__domain_production_runtime_v1._active_self_c04_environment_v4
        return InstalledSelfC04ReadersV4(graph, foreground_issuance, scope, environment)
    if operation.operation_kind == "select_ingress_recall_seed_v1":
        from .d06_ingress_c03_selection_v1 import InstalledIngressC03ReadersV1
        runtime = graph._GraphCoordinator__domain_production_runtime_v1
        search = runtime._active_ingress_c03_read_v1
        if foreground_issuance is None or search is None:
            raise ValueError("C03 selection requires its actual paired private retrieval")
        return InstalledIngressC03ReadersV1(graph, foreground_issuance, scope, search,
            graph._GraphCoordinator__d07_execution_service_v1)
    if operation.operation_kind == "input:freeze_artifact_candidate_preparation_v1":
        from .artifact_phase_postconditions_v1 import require_candidate_preparation_parent_handle_v1
        handle = require_candidate_preparation_parent_handle_v1(graph)
        if foreground_issuance is None or handle.task.namespace != scope.namespace:
            raise ValueError("internal parent start requires actual closed Self parent pipeline issuance")
    if operation.operation_kind in _POSTCONDITION_OPERATIONS:
        if operation.operation_kind != "input:register_artifact_phase_postcondition_policy_v1" and foreground_issuance is None:
            raise ValueError("postcondition contract and observation require actual private Self issuance")
        from .d08_personal_candidate_v1 import install_personal_candidate_readers_v1
        from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
        from .artifact_phase_postconditions_v1 import install_artifact_phase_postcondition_readers_v1
        runtime = graph._GraphCoordinator__domain_production_runtime_v1
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None:
            raise ValueError("postconditions require actual installed source/model package")
        personal = getattr(runtime, "_personal_candidate_readers_v1", None)
        if personal is None:
            personal = install_personal_candidate_readers_v1(graph=graph,
                bootstrap=runtime._bootstrap, bundle=assembly.admin_bundle)
            runtime._personal_candidate_readers_v1 = personal
        personal.current()
        model = InstalledArtifactDraftModelReadersV1(issuer, assembly.admin_bundle,
            graph._GraphCoordinator__artifact_draft_model_runtime_v1)
        return install_artifact_phase_postcondition_readers_v1(graph=graph,
            bootstrap=runtime._bootstrap, bundle=assembly.admin_bundle, model_readers=model)
    if operation.operation_kind == "prepare_source_note_action" and (foreground_issuance is not None or owner_task_issuance is not None):
        raise ValueError("Self SourceNote action must consume its actual selected Decision through the named V2 operation")
    if operation.operation_kind == "prepare_selected_source_note_action_v2":
        if foreground_issuance is None and owner_task_issuance is None:
            raise ValueError("selected SourceNote requires its actual private Self task issuance")
        from .d08_source_note_action_v1 import InstalledSelectedSourceNoteActionReadersV2
        from .d08_personal_candidate_v1 import install_personal_candidate_readers_v1
        from .d08_production_operations_v1 import InstalledD08ProductionReadersV1
        from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None:
            raise ValueError("selected SourceNote requires its actual installed initial package")
        legacy = InstalledD08ProductionReadersV1(issuer=issuer)
        legacy.body_readers = InstalledD02ProductionReadersV1(issuer=issuer,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority,
            role_clock_reader=graph._GraphCoordinator__d04_semantic_mapping_reader)
        legacy.package_root, legacy.manifest_digest = assembly.package_root, assembly.installation_policy.manifest_digest
        personal = install_personal_candidate_readers_v1(graph=graph,
            bootstrap=graph._GraphCoordinator__domain_production_runtime_v1._bootstrap, bundle=assembly.admin_bundle)
        personal.current()
        return InstalledSelectedSourceNoteActionReadersV2(legacy, personal)
    if operation.operation_kind == "cancel_owner_source_note_task_v1":
        if foreground_issuance is not None or owner_task_issuance is not None:
            raise ValueError("Owner task cancellation requires this actual Owner control lease")
        from .cancel_owner_source_note_task_v1 import install_cancel_owner_source_note_task_readers_v1
        return install_cancel_owner_source_note_task_readers_v1(graph, scope=scope, owner_guard=owner_guard, owner_binding=owner_binding)
    if operation.operation_kind in {"register_owner_source_note_life_plan_v1", "register_owner_source_note_life_outcome_v1"}:
        if owner_task_issuance is None:
            raise ValueError("Owner Life selectors require their actual independent task issuance")
        from .owner_source_note_life_v1 import install_owner_source_note_life_readers_v1
        return install_owner_source_note_life_readers_v1(graph, scope=scope, owner_guard=owner_guard, owner_task_issuance=owner_task_issuance)
    if operation.operation_kind in {"create_owner_source_note_task_v1", "acquire_owner_source_note_task_v1", "checkpoint_owner_source_note_task_v1"}:
        if owner_task_issuance is None:
            raise ValueError("Owner task execution requires its actual independent Core issued handle")
        from .owner_source_note_task_execution_v1 import install_owner_source_note_task_execution_readers_v1
        return install_owner_source_note_task_execution_readers_v1(graph, scope=scope, owner_guard=owner_guard,
            owner_binding=owner_binding, owner_task_issuance=owner_task_issuance)
    if operation.operation_kind == "prepare_owner_source_note_need_v1":
        if owner_task_issuance is None:
            raise ValueError("Owner fixed-recipe Need requires its actual independent Core issued handle")
        from .owner_source_note_need_v1 import install_owner_source_note_need_readers_v1
        return install_owner_source_note_need_readers_v1(graph)
    if operation.operation_kind == "input:freeze_owner_source_note_values_parent_v1":
        if owner_task_issuance is None: raise ValueError("Owner task Values parent requires its actual independent issued handle")
        from .owner_source_note_values_v1 import install_owner_task_values_readers_v1
        return install_owner_task_values_readers_v1(graph, scope=scope, owner_guard=owner_guard, owner_task_issuance=owner_task_issuance)
    if operation.operation_kind in {"input:freeze_values", "evaluate_values"} and owner_task_issuance is not None:
        from .owner_source_note_values_v1 import install_owner_task_values_child_readers_v1
        return install_owner_task_values_child_readers_v1(graph, scope=scope, owner_guard=owner_guard, owner_task_issuance=owner_task_issuance)
    if operation.operation_kind == "admit_owner_material_source_v1":
        if foreground_issuance is not None or owner_task_issuance is not None:
            raise ValueError("Owner material intake requires this actual Owner lease")
        from .owner_material_source_v1 import install_owner_material_source_readers_v1
        return install_owner_material_source_readers_v1(graph, scope=scope, owner_guard=owner_guard, owner_binding=owner_binding)
    if operation.operation_kind == "register_method_experiment_v2":
        if foreground_issuance is not None or owner_task_issuance is not None:
            raise ValueError("method pair input registration requires its actual Owner channel")
        from .method_pair_shared_input_v1 import install_method_pair_owner_readers_v2
        return install_method_pair_owner_readers_v2(graph, scope=scope, owner_guard=owner_guard, owner_binding=owner_binding)
    if operation.operation_kind == "submit_owner_source_note_task_v1":
        if foreground_issuance is not None or owner_task_issuance is not None:
            raise ValueError("Owner task submission requires its actual Owner channel")
        from .owner_source_note_task_v1 import install_owner_source_note_task_readers_v1
        return install_owner_source_note_task_readers_v1(graph, scope=scope, owner_guard=owner_guard, owner_binding=owner_binding)
    if operation.operation_kind == "authorize_source_note_task_v1":
        if foreground_issuance is not None or owner_task_issuance is not None:
            raise ValueError("SourceNote task authorization requires the actual Owner channel")
        from .source_note_task_authorization_v1 import install_source_note_task_authorization_readers_v1
        return install_source_note_task_authorization_readers_v1(graph, scope=scope,
            owner_guard=owner_guard, owner_binding=owner_binding)
    if operation.operation_kind in {"create_source_note_foreground_cycle_v1", "checkpoint_source_note_foreground_cycle_v1"}:
        if foreground_issuance is None:
            raise ValueError("SourceNote initial cycle requires its independently issued fixed Self channel")
        from .foreground_cycle_v1 import InstalledForegroundCycleReadersV1
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None:
            raise ValueError("SourceNote initial cycle requires its actual installed initial bundle")
        return InstalledForegroundCycleReadersV1(issuer, assembly.admin_bundle)
    if operation.operation_kind == "initialize_relationship_prior_v2" and (foreground_issuance is not None or owner_binding is None):
        raise ValueError("relationship authored prior requires this actual current Owner binding")
    if operation.operation_kind == "adopt_current_c1_method_conditions_v1":
        from .d07_method_conditions_v1 import InstalledD07MethodConditionReadersV1
        assembly=graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None:
            from .d01_production_operations_v1 import MissingProductionOriginalV1
            raise MissingProductionOriginalV1("actual_installed_A06_method_condition_bundle")
        return InstalledD07MethodConditionReadersV1(issuer=issuer,installed_bundle=assembly.admin_bundle)
    if operation.operation_kind in {"prepare_ingress_recall_model_v1", "acquire_ingress_recall_model_v1", "prepare_ingress_recall_result_read_v1", "finish_ingress_recall_model_v1", "adopt_ingress_recall_model_v1"}:
        from .d07_ingress_recall_preparation_v1 import InstalledIngressRecallModelReadersV1
        from .d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
        service = graph._GraphCoordinator__d07_execution_service_v1
        if foreground_issuance is None or type(service) is not InstalledD07ExecutionServiceV1:
            raise ValueError("Self C3 requires the actual private Foreground issuance and installed D07 service")
        return InstalledIngressRecallModelReadersV1(graph, scope, foreground_issuance, service)
    if operation.operation_kind in {"prepare_ingress_recall_need_v1", "adopt_current_task_no_search_v1"}:
        if foreground_issuance is None:
            raise ValueError("ingress recall need requires its actual private Self issuance")
        from .d06_ingress_recall_v1 import InstalledIngressRecallReadersV1
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None:
            raise ValueError("ingress recall need requires its installed production bundle")
        return InstalledIngressRecallReadersV1(issuer, assembly.admin_bundle)
    if operation.operation_kind == "register_artifact_draft_root":
        from .foreground_activity_issuance_v1 import InstalledDraftRootRegistrationReadersV1
        return InstalledDraftRootRegistrationReadersV1(graph, issuer,
            graph._GraphCoordinator__domain_production_runtime_v1._active_draft_root_registration_v1)
    if operation.operation_kind == "derive_ingress_artifact_task_scope_v1":
        from .ingress_artifact_task_scope_v1 import InstalledIngressTaskScopeReadersV1
        if foreground_issuance is None:raise ValueError("Self task scope needs its actual paired issuance")
        return InstalledIngressTaskScopeReadersV1(graph,issuer,
            graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle,foreground_issuance)
    if operation.operation_kind in {*_ARTIFACT_OPERATIONS, "adopt_owner_artifact_project_context_v1"}:
        owner_context = operation.operation_kind == "adopt_owner_artifact_project_context_v1"
        if owner_context and foreground_issuance is not None:
            raise ValueError("Owner project role adoption cannot use a Self foreground issuance")
        if foreground_issuance is None and not owner_context:
            raise ValueError("artifact task operations require their independently issued self channel")
        from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None:
            raise ValueError("artifact task requires its actual installed model assembly")
        readers = InstalledArtifactDraftModelReadersV1(issuer, assembly.admin_bundle,
            graph._GraphCoordinator__artifact_draft_model_runtime_v1,
            owner_assignment_guard=owner_guard if owner_context else None)
        if operation.operation_kind in {"await_existing_artifact_revision_v1", "select_existing_artifact_continuation_v1", "revise_existing_artifact_v1"}:
            from .artifact_continuation_originals_v1 import InstalledArtifactContinuationReadersV1
            return InstalledArtifactContinuationReadersV1(issuer, graph._GraphCoordinator__d02_issuer, readers)
        if operation.operation_kind == "propose_artifact_draft_phase_action_v2":
            from .d08_personal_plan_v1 import install_artifact_phase_action_readers_v2
            return install_artifact_phase_action_readers_v2(graph=graph,
                bootstrap=graph._GraphCoordinator__domain_production_runtime_v1._bootstrap,
                bundle=assembly.admin_bundle, model_readers=readers)
        return readers
    if operation.operation_kind in _FOREGROUND_OPERATIONS:
        if foreground_issuance is None:
            raise ValueError("cycle operations require their independently issued self channel")
        from .foreground_cycle_v1 import InstalledForegroundCycleReadersV1
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        return InstalledForegroundCycleReadersV1(issuer,
            None if assembly is None else assembly.admin_bundle)
    if operation.operation_kind in {"quote_current_method_choices_v1", "prepare_personal_candidates_v1", "select_personal_step_v2",
            "input:register_artifact_task_text_extent"}:
        from .d08_personal_candidate_v1 import (InstalledPersonalCandidateReadersV1,
            install_personal_candidate_readers_v1)
        runtime = graph._GraphCoordinator__domain_production_runtime_v1
        readers = getattr(runtime, "_personal_candidate_readers_v1", None)
        if readers is not None:
            if type(readers) is not InstalledPersonalCandidateReadersV1:
                raise TypeError("personal candidate reader must be the actual installed factory result")
            return readers.current()
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None:
            raise ValueError("current personal candidate installation is unavailable")
        readers = install_personal_candidate_readers_v1(graph=graph, bootstrap=runtime._bootstrap,
            bundle=assembly.admin_bundle)
        runtime._personal_candidate_readers_v1 = readers
        return readers
    if operation.operation_kind == "observe_method_comparison_v1":
        from .d11_method_observation_v1 import install_method_observation_readers_v1
        return install_method_observation_readers_v1(graph, scope=scope, owner_guard=owner_guard, owner_binding=owner_binding)
    if operation.operation_kind in {"pause_project_v1", "resume_project_v1"}:
        if foreground_issuance is not None:
            raise ValueError("project controls require the actual Owner channel, never Self foreground issuance")
        from .d08_project_control_v1 import install_project_control_readers_v1
        return install_project_control_readers_v1(graph, scope=scope, owner_guard=owner_guard, owner_binding=owner_binding)
    if operation.operation_kind in _PERSONAL_OPERATIONS:
        if operation.domain == "d05":
            from .d05_production_operations_v1 import InstalledD05ProductionReadersV1
            return InstalledD05ProductionReadersV1(issuer=issuer)
        if operation.domain == "d08":
            from .d08_personal_plan_v1 import InstalledD08PersonalPlanReadersV1
            assembly=graph._GraphCoordinator__d04_installed_joint_assembly
            if assembly is None:
                from .d01_production_operations_v1 import MissingProductionOriginalV1
                raise MissingProductionOriginalV1("actual_installed_A06_personal_plan_bundle")
            return InstalledD08PersonalPlanReadersV1(
                issuer=issuer, resource_issuer=graph._GraphCoordinator__d02_issuer,installed_bundle=assembly.admin_bundle)
        from .d10_project_checkpoint_v1 import InstalledD10ProjectReadersV1
        return InstalledD10ProjectReadersV1(issuer=issuer,
            cycle_job_ref=None if foreground_issuance is None else evidence.request.cycle_job_ref)
    if operation.operation_kind in {'prepare_internal_life_numeric_drive', 'prepare_internal_life_numeric_joint', 'prepare_internal_life_interval_baseline', 'adopt_internal_life_numeric_trace', 'prepare_internal_life_numeric_context', 'prepare_internal_life_numeric', 'acquire_internal_life_numeric', 'adopt_internal_life_numeric'}:
        from .d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None or assembly.admin_bundle.life_d04_before_capture_policy is None:
            raise ValueError('numeric Life requires its installed prospective before policy')
        readers = InstalledD06StructuredExperienceReadersV1(issuer=issuer,
            resource_issuer=graph._GraphCoordinator__d02_issuer,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority)
        readers.life_numeric_bundle = assembly.admin_bundle
        readers.life_numeric_owner_guard = owner_guard
        readers.life_numeric_scope = scope
        readers.life_numeric_mapping_reader = graph._GraphCoordinator__d04_semantic_mapping_reader
        runtime = graph._GraphCoordinator__domain_production_runtime_v1
        readers.life_numeric_topology = getattr(runtime, '_active_life_numeric_topology_v1', None)
        readers.life_numeric_environment = getattr(runtime, '_active_life_numeric_environment_v1', None)
        if operation.operation_kind == "acquire_internal_life_numeric":
            readers.life_numeric_issuance = getattr(graph._GraphCoordinator__domain_production_runtime_v1, "_active_life_numeric_issuance_v1", None)
        return readers
    if operation.operation_kind in {'prepare_internal_life_content', 'acquire_internal_life_content', 'acquire_internal_life_content_v2', 'adopt_internal_life_content_v1'}:
        from .d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
        assembly=graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None:
            raise ValueError('Life content requires the actual installed model assembly')
        readers=InstalledD06StructuredExperienceReadersV1(issuer=issuer,
            resource_issuer=graph._GraphCoordinator__d02_issuer,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority)
        readers.life_content_bundle=assembly.admin_bundle
        readers.life_content_fact_v2=getattr(graph._GraphCoordinator__domain_production_runtime_v1,"_active_life_content_fact_v2",None)
        return readers
    if operation.operation_kind == "focus_life_project":
        from .d07_life_project_focus_v1 import InstalledD07LifeFocusReadersV1
        from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
        return InstalledD07LifeFocusReadersV1(issuer=issuer, body_readers=InstalledD02ProductionReadersV1(
            issuer=issuer, body_quote_authority=graph._GraphCoordinator__body_quote_authority,
            role_clock_reader=graph._GraphCoordinator__d04_semantic_mapping_reader))
    if operation.operation_kind == "prepare_life_project_context":
        from .d03_life_project_context_v1 import InstalledD03LifeProjectContextReaderV1
        return InstalledD03LifeProjectContextReaderV1(issuer=issuer)
    if operation.domain == "d06":
        if operation.operation_kind == "form_association":
            from .d06_association_formation_v1 import InstalledD06AssociationReadersV1
            return InstalledD06AssociationReadersV1(issuer=issuer, resource_issuer=graph._GraphCoordinator__d02_issuer)
        from .d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
        return InstalledD06StructuredExperienceReadersV1(issuer=issuer,
            resource_issuer=graph._GraphCoordinator__d02_issuer,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority)
    contact = operation.operation_kind in {"adopt_contact_expression_plan", "adopt_contact_expression_plan_v2", "prepare_contact_model", "prepare_contact_model_v2", "prepare_contact_dispatch", "prepare_contact_dispatch_v3"}
    reader_domain = "d10" if contact else operation.domain
    module = import_module("." + reader_domain + "_production_operations_v1", package=__package__)
    cls = getattr(module, "Installed" + reader_domain.upper() + "ProductionReadersV1")
    if operation.domain == "d01":
        if operation.operation_kind in {"input:register_identity_plasticity_policy_v3","input:register_identity_trial_observer_policy_v3","migrate_semantic_identity_v3"}:
            if foreground_issuance is not None or owner_task_issuance is not None:
                raise ValueError("identity policy and migration require actual Owner management, never growth Self issuance")
        return cls(issuer=issuer, owner_guard=owner_guard,
            role_clock_reader=graph._GraphCoordinator__d04_semantic_mapping_reader)
    if operation.domain in {"d05", "d08"} and not contact:
        readers = cls(issuer=issuer)
        if operation.operation_kind == "prepare_source_note_action":
            from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
            readers.body_readers = InstalledD02ProductionReadersV1(issuer=issuer,
                body_quote_authority=graph._GraphCoordinator__body_quote_authority,
                role_clock_reader=graph._GraphCoordinator__d04_semantic_mapping_reader)
            assembly = graph._GraphCoordinator__d04_installed_joint_assembly
            if assembly is None:
                raise ValueError("actual installed source-note package is absent")
            readers.package_root = assembly.package_root
            readers.manifest_digest = assembly.installation_policy.manifest_digest
        return readers
    if operation.domain in {"d02", "d10"} or contact:
        from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
        clock = graph._GraphCoordinator__d04_semantic_mapping_reader
        body = InstalledD02ProductionReadersV1(issuer=issuer,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority, role_clock_reader=clock)
        if operation.domain == "d02":
            if operation.operation_kind == "prepare_source_note_body":
                assembly = graph._GraphCoordinator__d04_installed_joint_assembly
                if assembly is None:
                    raise ValueError("SourceNote Body requires the actual installed package bundle")
                body.installed_bundle = assembly.admin_bundle
            return body
        readers = cls(issuer=issuer, role_clock_reader=clock, current_restore_anchor=scope.pinned_anchor, body_readers=body)
        readers.life_scope = scope
        readers.life_execution_inventory = graph._GraphCoordinator__domain_production_runtime_v1._active_life_execution_inventory_v1
        return readers
    return cls(issuer=issuer, execution_reader=execution_reader)


def stage_installed_domain_operation_v1(db, *, operation, frame, request, installed_readers):
    if (type(operation) is not InstalledDomainOperationV1
            or installed_operation_v1(operation.operation_kind) != operation
            or type(request) is not operation.request_type or not db.in_transaction):
        raise ValueError("exact registered domain request and current transaction required")
    if operation.operation_kind == "input:freeze_owner_source_note_values_parent_v1":
        from .owner_source_note_values_v1 import stage_freeze_owner_source_note_values_parent_v1
        return stage_freeze_owner_source_note_values_parent_v1(db, frame=frame, request=request, installed_readers=installed_readers)
    if operation.operation_kind in _POSTCONDITION_OPERATIONS:
        module = import_module(".artifact_phase_postconditions_v1", package=__package__)
        return getattr(module, operation.stage_name)(db, frame=frame,
            request=request, installed_readers=installed_readers)
    if operation.operation_kind in {"prepare_ingress_c04_v1", "adopt_ingress_c04_v1"}:
        from .c04_ingress_preparation_v4 import stage_self_c04_prepare_v4
        from .c04_ingress_adoption_v4 import stage_self_c04_adopt_v4
        stage = stage_self_c04_prepare_v4 if operation.operation_kind == "prepare_ingress_c04_v1" else stage_self_c04_adopt_v4
        return stage(db, frame=frame, request=request, installed_readers=installed_readers)
    if operation.operation_kind == "select_ingress_recall_seed_v1":
        from .d06_ingress_c03_selection_v1 import stage_ingress_c03_selection_v1
        return stage_ingress_c03_selection_v1(db, frame=frame, request=request, installed_readers=installed_readers)
    if operation.operation_kind in {"prepare_ingress_recall_result_read_v1", "finish_ingress_recall_model_v1", "adopt_ingress_recall_model_v1"}:
        from .d07_ingress_recall_result_v1 import stage_current_ingress_recall_result_v1
        return stage_current_ingress_recall_result_v1(db, frame=frame, request=request,
            installed_readers=installed_readers, operation_kind=operation.operation_kind)
    if operation.operation_kind == "acquire_ingress_recall_model_v1":
        from .d07_ingress_recall_acquisition_v1 import acquire_current_ingress_recall_model_v1
        return acquire_current_ingress_recall_model_v1(db, frame=frame, request=request, installed_readers=installed_readers)
    if operation.operation_kind == "prepare_ingress_recall_model_v1":
        from .d07_ingress_recall_preparation_v1 import prepare_current_ingress_recall_model_v1
        return prepare_current_ingress_recall_model_v1(db, frame=frame, request=request, installed_readers=installed_readers)
    if operation.operation_kind == "prepare_ingress_recall_need_v1":
        from .d06_ingress_recall_v1 import stage_ingress_recall_need_in_transaction_v1
        return stage_ingress_recall_need_in_transaction_v1(db, frame=frame, request=request, installed_readers=installed_readers)
    if operation.operation_kind == "register_artifact_draft_root":
        from .foreground_activity_issuance_v1 import stage_register_current_draft_root_in_transaction_v1
        return stage_register_current_draft_root_in_transaction_v1(db, frame=frame, request=request, installed_readers=installed_readers)
    if operation.operation_kind == "adopt_owner_artifact_project_context_v1":
        from .d03_life_project_context_v1 import stage_adopt_owner_artifact_project_context_in_transaction_v1
        return stage_adopt_owner_artifact_project_context_in_transaction_v1(db, frame=frame, request=request, installed_readers=installed_readers)
    if operation.operation_kind in _ARTIFACT_OPERATIONS:
        module = import_module(_ARTIFACT_OPERATIONS[operation.operation_kind][1], package=__package__)
        return getattr(module, operation.stage_name)(db, frame=frame, request=request, installed_readers=installed_readers)
    if operation.operation_kind in _FOREGROUND_OPERATIONS:
        from .foreground_cycle_v1 import stage_current_foreground_cycle_in_transaction_v1
        return stage_current_foreground_cycle_in_transaction_v1(db, frame=frame, request=request, installed_readers=installed_readers)
    if operation.operation_kind.startswith("input:"):
        from .domain_production_inputs_v1 import stage_current_domain_input_v1
        return stage_current_domain_input_v1(db, frame=frame,
            producer_kind=operation.operation_kind[len("input:"):], request=request, installed_readers=installed_readers)
    if operation.operation_kind in _PERSONAL_OPERATIONS:
        module = import_module(_PERSONAL_OPERATIONS[operation.operation_kind][1], package=__package__)
        return getattr(module, operation.stage_name)(
            db, frame=frame, request=request, installed_readers=installed_readers)
    module = import_module(".d06_life_numeric_drive_v1" if operation.operation_kind == "prepare_internal_life_numeric_drive" else
        ".d06_life_numeric_joint_v1" if operation.operation_kind == "prepare_internal_life_numeric_joint" else
        ".d04_life_encoding_baseline_v1" if operation.operation_kind == "prepare_internal_life_interval_baseline" else
        ".d06_life_numeric_trace_v1" if operation.operation_kind == "adopt_internal_life_numeric_trace" else
        ".d06_life_numeric_task_v1" if operation.operation_kind in {"prepare_internal_life_numeric", "adopt_internal_life_numeric"} else
        ".d06_life_numeric_worker_v1" if operation.operation_kind == "acquire_internal_life_numeric" else
        ".d06_life_numeric_context_v1" if operation.operation_kind == "prepare_internal_life_numeric_context" else
        ".internal_life_content_adoption_v1" if operation.operation_kind == "adopt_internal_life_content_v1" else
        ".internal_life_content_worker_v2" if operation.operation_kind == "acquire_internal_life_content_v2" else
        ".internal_life_content_worker_v1" if operation.operation_kind == "acquire_internal_life_content" else
        ".internal_life_content_preparation_v1" if operation.operation_kind == "prepare_internal_life_content" else
        ".d06_internal_life_encoding_v1" if operation.operation_kind == "encode_internal_life" else
        ".contact_plan_adoption_v2" if operation.operation_kind == "adopt_contact_expression_plan_v2" else
        ".contact_final_stage_v3" if operation.operation_kind == "prepare_contact_dispatch_v3" else
        ".contact_final_stage_v2" if operation.operation_kind == "prepare_contact_dispatch" else
        ".contact_product_adapter_v2" if operation.operation_kind == "prepare_contact_model_v2" else
        ".contact_product_adapter_v1" if operation.operation_kind in {
        "adopt_contact_expression_plan", "prepare_contact_model"} else
        ".d07_life_project_focus_v1" if operation.operation_kind == "focus_life_project" else
        ".d03_life_project_context_v1" if operation.operation_kind == "prepare_life_project_context" else
        ".d08_source_note_action_v1" if operation.operation_kind == "prepare_source_note_action" else
        ".d02_life_body_preparation_v1" if operation.operation_kind in {"prepare_source_note_body", "prepare_artifact_draft_body"} else
        ".d10_offline_tick_execution_v1" if operation.operation_kind == "prepare_offline_tick" else
        ".d11_life_product_adapter_v1" if operation.operation_kind == "prepare_life" else
        ".d06_association_formation_v1" if operation.operation_kind == "form_association" else
        ".d06_structured_experience_v1" if operation.domain == "d06" else
        "." + operation.domain + "_production_operations_v1", package=__package__)
    if operation.operation_kind in {'prepare_internal_life_interval_baseline', 'adopt_internal_life_numeric_trace'}:
        return getattr(module, operation.stage_name)(db, frame=frame, request=request,
            installed_readers=installed_readers, environment=installed_readers.life_numeric_environment)
    return getattr(module, operation.stage_name)(db, frame=frame, request=request, installed_readers=installed_readers)
