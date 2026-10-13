"""Frozen host intent for new native work; never an Authority permission.

Disabled modules stop their own new production and the real first external
attempt. Original receipts, accounting and safety maintenance keep their
existing authorization and recovery checks.
"""
from dataclasses import dataclass
from types import MappingProxyType


MODULE_IDS_V1 = tuple(f"d{number:02d}" for number in range(1, 14))


class LocalModuleAdmissionDeniedV1(ValueError):
    def __init__(self, operation_kind, disabled_modules):
        self.operation_kind = operation_kind
        self.disabled_modules = tuple(disabled_modules)
        self.reason_code = "local_module_disabled"
        super().__init__("local_module_disabled:" + ",".join(self.disabled_modules))


@dataclass(frozen=True, slots=True)
class LocalModuleAdmissionV1:
    enabled: tuple[bool, ...] = (True,) * 13

    def __post_init__(self):
        if (type(self.enabled) is not tuple or len(self.enabled) != 13
                or any(type(value) is not bool for value in self.enabled)):
            raise TypeError("native modules require thirteen exact boolean flags")

    @classmethod
    def from_config_v1(cls, raw):
        if raw is None:
            return cls()
        if (type(raw) is not dict or set(raw) != set(MODULE_IDS_V1)
                or any(type(value) is not bool for value in raw.values())):
            raise ValueError("modules must contain exactly d01 through d13 booleans")
        return cls(tuple(raw[module] for module in MODULE_IDS_V1))

    @property
    def flags(self):
        return dict(zip(MODULE_IDS_V1, self.enabled))

    @property
    def disabled_modules(self):
        return tuple(module for module, enabled in zip(MODULE_IDS_V1, self.enabled)
                     if not enabled)

    def require_v1(self, required_modules, operation_kind):
        required = frozenset(required_modules)
        if not required <= set(MODULE_IDS_V1):
            raise ValueError("new native work has an unregistered module dependency")
        disabled = tuple(module for module in self.disabled_modules if module in required)
        if disabled:
            raise LocalModuleAdmissionDeniedV1(operation_kind, disabled)


# Closed installed production catalog. D12 is added only for actual workbench
# commands; installed background production does not depend on the WebUI.
OPERATION_MODULES_V1 = MappingProxyType({
    "migrate_semantic_identity_v3": ("d01", "d06", "d11"),
    "project_self_model_v3": ("d01", "d06", "d11"),
    "input:register_identity_plasticity_policy_v3": ("d01", "d11"),
    "input:register_identity_trial_observer_policy_v3": ("d01", "d11"),
    "input:prepare_semantic_growth_input_v3": ("d01", "d06", "d07", "d11"),
    "input:start_semantic_growth_trial_v3": ("d01", "d06", "d08", "d10", "d11"),
    "input:register_artifact_phase_postcondition_policy_v1": ("d03", "d06", "d08", "d10", "d11"),
    "register_artifact_phase_postcondition_contract_v1": ("d01", "d02", "d03", "d06", "d07", "d08", "d10", "d11"),
    "observe_artifact_phase_postconditions_v1": ("d03", "d06", "d08", "d10", "d11"),
    'prepare_personal_candidates_v1': ('d01', 'd02', 'd03', 'd05', 'd06', 'd07', 'd08', 'd10', 'd11'),
    'select_personal_step_v2': ('d01', 'd02', 'd03', 'd05', 'd06', 'd07', 'd08', 'd10', 'd11'),
    'prepare_artifact_draft_model_v2': ('d01', 'd02', 'd03', 'd06', 'd07', 'd08', 'd10', 'd11'),
    'acquire_artifact_draft_model_v2': ('d01', 'd02', 'd03', 'd06', 'd07', 'd08', 'd10', 'd11'),
    'adopt_artifact_draft_content_v2': ('d06', 'd08', 'd10', 'd11'),
    'verify_artifact_draft_phase_v2': ('d03', 'd06', 'd08', 'd10', 'd11'),
    'wake_artifact_draft_cycle_v2': ('d03', 'd06', 'd08', 'd10', 'd11'),
    'propose_artifact_draft_phase_action_v2': ('d01', 'd02', 'd03', 'd05', 'd06', 'd07', 'd08', 'd10', 'd11'),
    'input:register_artifact_phase_price_policy': ('d02', 'd11'),
    'input:register_artifact_task_text_extent': ('d03', 'd06', 'd07', 'd08', 'd10', 'd11'),
    'input:register_artifact_phase_draft_plan_v2': ('d02', 'd03', 'd06', 'd08', 'd10', 'd11'),
    'input:register_artifact_draft_plan_v3': ('d02', 'd03', 'd06', 'd08', 'd10', 'd11'),
    "prepare_ingress_c04_v1": ("d02", "d03", "d04", "d06", "d07", "d11"),
    "adopt_ingress_c04_v1": ("d02", "d03", "d04", "d06", "d07", "d11"),
    "prepare_ingress_recall_need_v1": ("d03", "d05", "d06", "d07", "d08", "d11"),
    "select_ingress_recall_seed_v1": ("d03", "d05", "d06", "d07", "d08", "d11"),
    "prepare_ingress_recall_model_v1": ("d02", "d03", "d05", "d06", "d07", "d08", "d11"),
    "acquire_ingress_recall_model_v1": ("d02", "d03", "d05", "d06", "d07", "d08", "d11"),
    "prepare_ingress_recall_result_read_v1": ("d02", "d03", "d05", "d06", "d07", "d08", "d11"),
    "finish_ingress_recall_model_v1": ("d02", "d03", "d05", "d06", "d07", "d08", "d11"),
    "adopt_ingress_recall_model_v1": ("d02", "d03", "d05", "d06", "d07", "d08", "d11"),
    "create_foreground_cycle_v2": ("d03", "d06", "d11"),
    "checkpoint_foreground_cycle_v2": ("d03", "d06", "d11"),
    "wake_artifact_draft_cycle_v1": ("d03", "d06", "d10", "d11"),
    "register_artifact_draft_root": ("d06", "d10", "d11"),
    "select_existing_artifact_continuation_v1": ("d03", "d06", "d08", "d10", "d11"),
    "revise_existing_artifact_v1": ("d03", "d06", "d08", "d10", "d11"),
    "prepare_artifact_draft_model": ("d06", "d10", "d11"),
    "acquire_artifact_draft_model": ("d06", "d10", "d11"),
    "adopt_artifact_draft_content": ("d06", "d10", "d11"),
    "derive_ingress_artifact_task_scope_v1": ("d03", "d06", "d08", "d10", "d11"),
    "adopt_current_task_no_search_v1": ("d03", "d06", "d07", "d08", "d10", "d11"),
    "adopt_current_c1_method_conditions_v1": ("d02", "d03", "d06", "d07", "d08", "d10", "d11"),
    "quote_current_method_choices_v1": ("d02", "d03", "d06", "d07", "d08", "d10", "d11"),
    "await_existing_artifact_revision_v1": ("d03", "d06", "d08", "d10", "d11"),
    "create_artifact_task_plan_v1": ("d03", "d06", "d08", "d11"),
    "create_personal_plan": ("d06", "d08", "d11"),
    "revise_personal_plan": ("d06", "d08", "d11"),
    "select_personal_step": ("d01", "d06", "d08", "d10", "d11"),
    "register_artifact_task_milestone_v2": ("d03", "d06", "d08", "d10", "d11"),
    "settle_personal_goal": ("d06", "d08", "d10", "d11"),
    "initialize_project_checkpoint": ("d06", "d08", "d10", "d11"),
    "refresh_project_checkpoint": ("d06", "d08", "d10", "d11"),
    "settle_project_checkpoint": ("d06", "d08", "d10", "d11"),
    "compose_artifact_goal_plan": ("d03", "d06", "d08", "d10", "d11"),
    "create_artifact_project": ("d06", "d08", "d10", "d11"),
    "create_artifact_task_project_v1": ("d03", "d06", "d08", "d10", "d11"),
    "initialize_artifact_task_project_checkpoint_v1": ("d03", "d06", "d08", "d10", "d11"),
    "activate_artifact_task_project_checkpoint_v1": ("d03", "d06", "d08", "d10", "d11"),
    "prepare_artifact_draft_project_context": ("d03", "d06", "d08", "d10", "d11"),
    "adopt_owner_artifact_project_context_v1": ("d03", "d06", "d08", "d10", "d11"),
    "propose_artifact_draft_action": ("d03", "d06", "d08", "d10", "d11"),
    "prepare_artifact_draft_body": ("d02", "d03", "d06", "d08", "d10", "d11"),
    "evaluate_values": ("d01", "d11"),
    "adopt_growth": ("d01", "d11"),
    "advance_body": ("d02", "d11"),
    "apply_body_effect": ("d02", "d11"),
    "prepare_source_note_body": ("d02", "d03", "d06", "d08", "d10", "d11"),
    "adopt_relationship_contribution": ("d05", "d11"),
    "revise_boundary": ("d05", "d11"),
    "reevaluate_relationship": ("d05", "d11"),
    "encode_structured_experience": ("d06", "d11"),
    "form_association": ("d06", "d11"),
    "encode_internal_life": ("d06", "d10", "d11"),
    "prepare_internal_life_numeric_context": ("d06", "d10", "d11"),
    "prepare_internal_life_interval_baseline": ("d06", "d10", "d11"),
    "prepare_internal_life_content": ("d06", "d10", "d11"),
    "acquire_internal_life_content": ("d06", "d10", "d11"),
    "acquire_internal_life_content_v2": ("d06", "d10", "d11"),
    "adopt_internal_life_content_v1": ("d06", "d10", "d11"),
    "prepare_internal_life_numeric": ("d04", "d06", "d10", "d11"),
    "acquire_internal_life_numeric": ("d04", "d06", "d10", "d11"),
    "adopt_internal_life_numeric": ("d04", "d06", "d10", "d11"),
    "prepare_internal_life_numeric_drive": ("d04", "d06", "d10", "d11"),
    "prepare_internal_life_numeric_joint": ("d04", "d06", "d10", "d11"),
    "adopt_internal_life_numeric_trace": ("d04", "d06", "d10", "d11"),
    "serve_concern": ("d07", "d11"),
    "advance_reflection": ("d07", "d11"),
    "run_simulation": ("d07", "d11"),
    "focus_life_project": ("d07", "d10", "d11"),
    "prepare_life_project_context": ("d03", "d10", "d11"),
    "prepare_source_note_action": ("d08", "d11"),
    "recheck_action": ("d08", "d11"),
    "acknowledge_bilateral": ("d08", "d11"),
    "adopt_joint_plan": ("d08", "d11"),
    "prepare_offline_tick": ("d10", "d11"),
    "prepare_life": ("d10", "d11"),
    "advance_life": ("d02", "d06", "d10", "d11"),
    "advance_offline": ("d02", "d06", "d10", "d11"),
    "prepare_contact": ("d10", "d11"),
    "prepare_contact_model": ("d09", "d10", "d11"),
    "prepare_contact_model_v2": ("d09", "d10", "d11"),
    "adopt_contact_expression_plan": ("d08", "d09", "d10", "d11"),
    "adopt_contact_expression_plan_v2": ("d08", "d09", "d10", "d11"),
    "prepare_contact_dispatch": ("d08", "d09", "d10", "d11"),
    "prepare_contact_dispatch_v3": ("d08", "d09", "d10", "d11"),
    "settle_observed_action": (),
    "record_host_lifecycle": (),
    "input:freeze_values": ("d01", "d11"),
    "input:prepare_growth_input": ("d01", "d11"),
    "input:derive_growth_trial": ("d01", "d11"),
    "input:initialize_body": ("d02", "d11"),
    "input:install_passive_body_policy": ("d02", "d11"),
    "input:install_body_effect_policy": ("d02", "d11"),
    "input:record_body_component": ("d02", "d11"),
    "input:install_relationship_policy": ("d05", "d11"),
    "prepare_selected_source_note_action_v2": ("d01", "d02", "d03", "d05", "d06", "d07", "d08", "d10", "d11"),
    "checkpoint_source_note_foreground_cycle_v1": ("d03", "d06", "d08", "d10", "d11"),
    "authorize_source_note_task_v1": ("d03", "d06", "d08", "d10", "d11"),
    "submit_owner_source_note_task_v1": ("d02", "d03", "d06", "d08", "d10", "d11", "d12"),
    "admit_owner_material_source_v1": ("d06", "d11"),
    "input:freeze_owner_source_note_values_parent_v1": ("d01", "d02", "d03", "d06", "d07", "d08", "d10", "d11"),
    "checkpoint_owner_source_note_task_v1": ("d02", "d03", "d06", "d08", "d10", "d11"),
    "create_owner_source_note_task_v1": ("d02", "d03", "d06", "d08", "d10", "d11"),
    "acquire_owner_source_note_task_v1": ("d02", "d03", "d06", "d08", "d10", "d11"),
    "prepare_owner_source_note_need_v1": ("d02", "d03", "d06", "d07", "d08", "d10", "d11"),
    "register_method_experiment_v2": ("d01", "d03", "d06", "d08", "d11"),
    "create_source_note_foreground_cycle_v1": ("d03", "d06", "d08", "d10", "d11"),
    "initialize_relationship_prior_v2": ("d03", "d05", "d06"),
    "observe_method_comparison_v1": ("d01", "d06", "d08", "d11"),
    "quote_current_method_choices_v1": ("d02", "d06", "d07", "d08", "d10", "d11"),
    "adopt_current_task_no_search_v1": ("d06", "d07", "d08", "d11"),
    "adopt_current_c1_method_conditions_v1": ("d01", "d02", "d06", "d07", "d08", "d10", "d11"),
    "register_method_trial_proposal_v2": ("d01", "d06", "d07", "d08", "d11"),
    "register_scoped_method_trial_v2": ("d01", "d06", "d07", "d08", "d11"),
    "register_method_blind_review_request_v2": ("d01", "d06", "d07", "d08", "d11"),
    "register_method_evaluation_protocol_v1": ("d01", "d06", "d07", "d08", "d11"),
    "register_scoped_method_trial_v1": ("d01", "d06", "d07", "d08", "d11"),
    "register_method_experiment_v1": ("d01", "d06", "d07", "d08", "d11"),
    "evaluate_current_method_outcome_v1": ("d01", "d06", "d07", "d08", "d11"),
    "review_current_method_growth_v1": ("d01", "d06", "d07", "d08", "d11"),
    "adopt_current_method_strategy_v1": ("d01", "d06", "d07", "d08", "d11"),
    "adopt_relationship_revision_v2": ("d05", "d06", "d07", "d03", "d11"),
    "cancel_owner_source_note_task_v1": (),
    "register_owner_source_note_life_plan_v1": ("d02", "d03", "d06", "d08", "d10", "d11"),
    "register_owner_source_note_life_outcome_v1": ("d02", "d03", "d06", "d08", "d10", "d11"),
    "pause_project_v1": (),
    "resume_project_v1": (),
    "input:register_boundary_intent": ("d05", "d11"),
    "input:create_goal": ("d08", "d11"),
    "input:register_joint_plan_intent": ("d08", "d11"),
    "input:register_party_consent": ("d08", "d11"),
    "input:register_semantic_question": ("d07", "d11"),
    "input:register_simulation": ("d07", "d11"),
    "input:create_life_project": ("d10", "d11"),
    "input:create_contact_opportunity": ("d10", "d11"),
    "input:register_life_plan": ("d10", "d11"),
    "input:register_life_plan_v2": ("d10", "d11"),
    "input:register_offline_schedule": ("d10", "d11"),
    "input:register_offline_interval": ("d10", "d11"),
    "input:set_contact_policy": ("d10", "d11"),
    "input:register_life_outcome": ("d10", "d11"),
    "input:register_life_outcome_v2": ("d10", "d11"),
})


MODEL_MODULES_V1 = MappingProxyType({
    "artifact_draft": ("d06", "d10", "d11"),
    "encode": ("d06", "d11"),
    "reply": ("d09", "d11"),
    "context_reply": ("d09", "d11"),
    "natural_generation": ("d09", "d11"),
    "natural_review": ("d09", "d11"),
    "appraisal": ("d04", "d11"),
    "d07_cognition": ("d07", "d11"),
    "d07_relationship_cognition": ("d03", "d04", "d05", "d06", "d07", "d11"),
    "growth_cognition": ("d01", "d03", "d06", "d07", "d11"),
    "contact_generation": ("d09", "d10", "d11"),
    "contact_review": ("d09", "d10", "d11"),
    "life_content": ("d06", "d10", "d11"),
    "life_numeric": ("d04", "d06", "d10", "d11"),
    "d13_precompression": ("d13", "d11"),
})


def required_operation_modules_v1(operation_kind):
    try:
        return OPERATION_MODULES_V1[operation_kind]
    except KeyError as exc:
        raise ValueError("unclassified installed native operation") from exc


def completed_original_input_v1(db, namespace, operation_kind, request, issuer):
    """Classify existing work completion; the current frame still verifies eligibility.

    This pure read cannot grant rights, stage writes, issue a model call or send.
    A browser's completed/result label alone is never enough for this category.
    """
    import json
    from ..graph_types import AtomKey
    from ..domains.d08.execution import _decode, _decode_intent
    from .d01_production_operations_v1 import raw_head_value_v1, table_exists_v1

    if operation_kind == "input:register_life_outcome_v2":
        from .d11_life_preparation_v1 import (
            TABLE, read_registered_life_plan_v2, read_prepared_life_v1,
        )
        from .d11_life_terminal_v1 import read_adopted_life_original_v1
        from .d11_life_contract_v1 import D11LifeTerminalV1, life_from_wire_v1
        from .d11_life_fact_provenance_v1 import require_current_life_fact_eligibility_v1
        from .d11_life_source_note_v1 import verify_durable_life_artifact_v1
        if not table_exists_v1(db, TABLE):
            return False
        outcome = request.outcome
        plan = read_registered_life_plan_v2(db, namespace=namespace, issuer=issuer,
            original_ref=outcome.plan_original_ref)
        adopted = read_adopted_life_original_v1(db, namespace=namespace, issuer=issuer,
            result_ref=outcome.artifact_ref)
        if plan is None or adopted is None:
            return False
        terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
        if (terminal.status != "completed" or terminal.binding.namespace != namespace
                or terminal.binding.plan_original_ref != outcome.plan_original_ref
                or outcome.start_original_ref != terminal.claim.original_ref
                or outcome.terminal_original_ref != terminal.original_ref
                or outcome.artifact_digest != terminal.payload.artifact_digest):
            return False
        prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=issuer)
        if prepared is None:
            return False
        require_current_life_fact_eligibility_v1(db, prepared=prepared, terminal=terminal, adopted=adopted)
        verify_durable_life_artifact_v1(db, prepared, digest=outcome.artifact_digest,
            length=terminal.payload.artifact_length)
        return True

    if operation_kind == "input:register_life_outcome":
        from .domain_production_read_plans_v1 import _signed_input
        if not table_exists_v1(db, "graph_d10_production_inputs_v1"):
            return False
        outcome = request.outcome
        original = _signed_input(db, namespace, outcome.plan_original_ref, issuer)
        if original is None or original.kind != "d10.life_plan":
            return False
        row = db.execute("SELECT payload_json FROM graph_d10_production_inputs_v1 "
            "WHERE bot=? AND persona=? AND original_ref=?", (*namespace.as_tuple, outcome.plan_original_ref)).fetchone()
        action_ref, outcome_ref = json.loads(row[0])["action_intent_ref"], outcome.action_outcome_ref
    elif operation_kind == "input:record_body_component":
        component = request.component
        action_ref, outcome_ref = component.action_intent_ref, component.action_outcome_ref
    else:
        return False
    action_key, outcome_key = AtomKey.from_token(action_ref), AtomKey.from_token(outcome_ref)
    if action_key.type_name != "d08.action_intent.v1" or outcome_key.type_name != "d08.action_outcome.v1":
        return False
    action_raw = raw_head_value_v1(db, namespace, action_key)
    outcome_raw = raw_head_value_v1(db, namespace, outcome_key)
    if action_raw is None or outcome_raw is None:
        return False
    action, actual = _decode_intent(action_raw), _decode("d08.action_outcome.v1", outcome_raw)
    if (actual.action_id != action.action_id or actual.effect_id != action.identity.effect_id
            or actual.attempt_id != action.identity.attempt_id
            or actual.result_level != "completed_verified" or actual.unknown_effects
            or actual.effect_id not in actual.completed_effects or not actual.observation_refs):
        return False
    if operation_kind == "input:record_body_component":
        from .d01_production_operations_v1 import read_adopted_outbound_observation_original_v1
        observed, original, _ = read_adopted_outbound_observation_original_v1(db, namespace, component.observation_ref)
        platform = observed.pending.platform_observation
        origin = getattr(platform.binding, "origin", platform.binding)
        return (action.action_kind in {"message", "communication"}
            and platform.outcome in {"accepted", "delivered"}
            and origin.effect_id == actual.effect_id
            and component.observation_ref in actual.observation_refs
            and original.original_digest == component.observation_digest)
    return True
