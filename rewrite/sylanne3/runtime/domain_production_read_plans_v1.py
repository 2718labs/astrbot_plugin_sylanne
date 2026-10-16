"""Closed W01 domain read planning and genuine original resolution.

No SQL identifier, callable, schema or scan type comes from a public request.
This module performs no RPC. Independently reread C04 terminals, trusted clock
samples and restore anchors enter through W01's installed pre-read adapter.
An absent original is omitted, so the domain reader returns its precise HOLD;
the locator's own hash is never used as an original or authority receipt.
"""
from __future__ import annotations

from ..runtime_storage_v3 import read_graph_row_v3, read_graph_rows_v3

from dataclasses import dataclass
import json

from ..graph_types import AtomKey, GraphVersion
from ..graph_types import Owner
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import (
    MissingProductionOriginalV1, production_read_plan_v1, raw_registered_input_v1,
    raw_head_value_v1, read_plan_current_d01_operation_v1, table_exists_v1,
)
from .d02_production_operations_v1 import read_plan_current_d02_operation_v1
from .d05_production_operations_v1 import read_plan_current_d05_operation_v1
from .d08_production_operations_v1 import read_plan_current_d08_operation_v1
from .d10_production_operations_v1 import read_plan_current_d10_operation_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1, ProductionPolicyRefV1, ProductionReadPlanV1
from .issuers import D11BudgetJobIssuer


_READ_PLANNERS = {"d01": read_plan_current_d01_operation_v1, "d02": read_plan_current_d02_operation_v1,
    "d05": read_plan_current_d05_operation_v1, "d08": read_plan_current_d08_operation_v1,
    "d10": read_plan_current_d10_operation_v1}
_INPUT_TABLES = (
    ("graph_d08_joint_node_originals_v1", "d11.d08-joint-node-original.v1", "d08", "kind"),
    ("graph_d01_production_inputs_v1", "d11.d01-production-input.v1", "d01", "kind"),
    ("graph_d05_boundary_intents_v1", "d11.d05-boundary-intent.v1", "d05", "boundary_intent"),
    ("graph_d08_joint_plan_intents_v1", "d11.d08-joint-plan-intent.v1", "d08", "joint_plan_intent"),
    ("graph_d08_party_consents_v1", "d11.d08-party-consent.v1", "d08", "party_consent"),
    ("graph_d10_production_inputs_v1", "d11.d10-production-input.v1", "d10", "kind"),
    ("graph_d02_action_components_v1", "d11.d02-completed-action-component.v1", "d02", "completed_action_component"),
)
_POLICY_TABLES = (
    ("graph_d02_production_policies_v1", "d11.d02-production-policy.v1", "d02"),
    ("graph_d05_production_policies_v1", "d11.d05-production-policy.v1", "d05"),
)


def read_plan_current_domain_operation_v1(db, *, namespace, activity_id, domain, operation_kind, request, operation_id=None, now_utc=None, audiences=None, life_d04_before_capture_policy=None, d06_recall_policy=None, d07_execution_service=None, ingress_c03_readers=None, self_c04_readers=None, ingress_task_scope_readers=None, personal_candidate_readers=None, artifact_phase_readers=None, installed_readers=None):
    from .conditioned_self_operations_v1 import OPERATIONS as CONDITIONED_OPERATIONS
    if operation_kind in CONDITIONED_OPERATIONS:
        from .current_conditioned_self_read_v3 import read_plan_current_conditioned_self_v1
        return read_plan_current_conditioned_self_v1(db,namespace,activity_id,operation_kind,request,installed_readers)
    from .d08_long_term_plan_v1 import OPERATIONS as LONG_TERM_OPERATIONS,read_plan_current_long_term_operation_v1
    from .d10_habit_v1 import OPERATIONS as HABIT_OPERATIONS,read_plan_current_habit_operation_v1
    if operation_kind in LONG_TERM_OPERATIONS or operation_kind in HABIT_OPERATIONS or operation_kind=='record_habit_window_cue_v1':
        from .domain_production_registry_v1 import installed_operation_v1
        actual=installed_operation_v1(operation_kind)
        if actual.domain!=domain or type(request)is not actual.request_type:
            raise ValueError('Habit/LongWindow read plan changed its exact installed domain/request')
        if operation_kind=='record_habit_window_cue_v1':
            from .current_habit_source_read_v3 import current_habit_source_read_plan_v3
            return current_habit_source_read_plan_v3(db,namespace=namespace,activity_id=activity_id,
                operation_kind=operation_kind,request=request)
        planner=read_plan_current_long_term_operation_v1 if operation_kind in LONG_TERM_OPERATIONS else read_plan_current_habit_operation_v1
        return planner(db,namespace=namespace,activity_id=activity_id,operation_kind=operation_kind,request=request)
    from ..domains.d03.world_history_v1 import WORLD_OPERATIONS
    if operation_kind in WORLD_OPERATIONS:
        from .d03_world_history_v1 import read_plan_world_operation_v1
        return read_plan_world_operation_v1(db,namespace=namespace,activity_id=activity_id,operation_id=operation_id,
            operation_kind=operation_kind,request=request,installed_readers=installed_readers)
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("domain read plan needs the actual W01 current transaction")
    from .current_method_learning_read_v3 import _NUMERIC_OWNER_OPERATIONS_V1
    if operation_kind in _NUMERIC_OWNER_OPERATIONS_V1:
        from .current_life_numeric_metadata_v1 import require_bound_numeric_plan_v1
        require_bound_numeric_plan_v1(db,operation_kind)
    if operation_kind in ("freeze_general_growth_intent_v1","register_general_growth_trial_start_v1","derive_general_growth_trial_v1","adopt_general_growth_v1"):
        from .d01_general_growth_v1 import (
            read_plan_freeze_current_general_growth_v1,
            read_plan_register_current_general_growth_trial_start_v1,
            read_plan_derive_current_general_growth_trial_v1,
            read_plan_adopt_current_general_growth_v1)
        if domain!='d01':raise ValueError('General growth read belongs to its exact D01 issuer')
        planner={"freeze_general_growth_intent_v1":read_plan_freeze_current_general_growth_v1,"register_general_growth_trial_start_v1":read_plan_register_current_general_growth_trial_start_v1,"derive_general_growth_trial_v1":read_plan_derive_current_general_growth_trial_v1,"adopt_general_growth_v1":read_plan_adopt_current_general_growth_v1}[operation_kind]
        return planner(db,namespace=namespace,request=request,issuer=_issuer(installed_readers))
    if operation_kind == "register_general_growth_attention_v1":
        from .d07_general_growth_attention_v1 import read_plan_register_general_growth_attention_v1
        from .domain_background_read_v3 import _active_v3
        return read_plan_register_general_growth_attention_v1(db, namespace=namespace, request=request,
            issuer=installed_readers.issuer if installed_readers is not None else _active_v3(db).graph._GraphCoordinator__d11_issuer)
    from .domain_production_registry_v1 import _POSTCONDITION_OPERATIONS
    if operation_kind in _POSTCONDITION_OPERATIONS:
        from .artifact_phase_postconditions_v1 import read_plan_artifact_phase_postconditions_v1
        return read_plan_artifact_phase_postconditions_v1(db, namespace=namespace,
            request=request, installed_readers=artifact_phase_readers)
    if operation_kind == "derive_ingress_artifact_task_scope_v1":
        from .ingress_artifact_task_scope_v1 import read_plan_ingress_artifact_task_scope_v1
        return read_plan_ingress_artifact_task_scope_v1(db,namespace=namespace,request=request,
            readers=ingress_task_scope_readers,now_utc=now_utc)
    from .domain_production_registry_v1 import _PERSONAL_OPERATIONS, _ARTIFACT_OPERATIONS
    from .domain_production_registry_v1 import _FOREGROUND_OPERATIONS
    if operation_kind in {"prepare_ingress_c04_v1", "adopt_ingress_c04_v1"}:
        from .c04_ingress_preparation_v4 import read_plan_self_c04_v4
        return read_plan_self_c04_v4(db, namespace=namespace, request=request, readers=self_c04_readers, operation_kind=operation_kind)
    if operation_kind == "select_ingress_recall_seed_v1":
        from .d06_ingress_c03_selection_v1 import read_plan_ingress_c03_selection_v1
        if domain != "d06" or ingress_c03_readers is None:
            raise ValueError("C03 history keys need the actual private installed retrieval handle")
        return read_plan_ingress_c03_selection_v1(db, namespace=namespace, request=request, readers=ingress_c03_readers)
    if operation_kind in {"prepare_ingress_recall_result_read_v1", "finish_ingress_recall_model_v1", "adopt_ingress_recall_model_v1"}:
        from .d07_ingress_recall_result_v1 import read_plan_ingress_recall_result_v1
        expected_domain = "d11" if operation_kind == "finish_ingress_recall_model_v1" else "d07"
        if domain != expected_domain or d07_execution_service is None:
            raise ValueError("Self C3 result requires its exact installed writer/service")
        return read_plan_ingress_recall_result_v1(db, namespace=namespace, request=request, service=d07_execution_service)
    if operation_kind == "acquire_ingress_recall_model_v1":
        from .d07_ingress_recall_acquisition_v1 import read_plan_ingress_recall_acquire_v1
        if domain != "d11" or d07_execution_service is None:
            raise ValueError("Self C3 acquisition needs its installed D07 reader")
        return read_plan_ingress_recall_acquire_v1(db, namespace=namespace, request=request, service=d07_execution_service)
    if operation_kind == "prepare_ingress_recall_model_v1":
        from .d07_ingress_recall_preparation_v1 import read_plan_ingress_recall_model_v1
        if domain != "d07" or d07_execution_service is None:
            raise ValueError("Self C3 read plan requires its actual installed D07 service")
        return read_plan_ingress_recall_model_v1(db, namespace=namespace, activity_id=activity_id,
            request=request, service=d07_execution_service)
    if operation_kind == "prepare_ingress_recall_need_v1":
        if domain != "d07":
            raise ValueError("ingress recall need has another actual issuer domain")
        from .d06_ingress_recall_v1 import read_plan_ingress_recall_need_v1
        return read_plan_ingress_recall_need_v1(db, namespace=namespace, request=request, policy=d06_recall_policy)
    if operation_kind == "register_artifact_draft_root":
        from .foreground_activity_issuance_v1 import read_plan_draft_root_registration_v1
        return read_plan_draft_root_registration_v1(db, namespace=namespace, request=request)
    if operation_kind == "adopt_owner_artifact_project_context_v1":
        from .d03_life_project_context_v1 import read_plan_artifact_draft_project_context_v1
        return read_plan_artifact_draft_project_context_v1(db, namespace=namespace, request=request)
    if operation_kind in _ARTIFACT_OPERATIONS:
        if _ARTIFACT_OPERATIONS[operation_kind][0] != domain:
            raise ValueError("artifact task operation belongs to another exact issuer domain")
        if operation_kind == "revise_artifact_task_plan_v2":
            from .d08_personal_plan_v1 import read_plan_current_artifact_task_plan_revision_v2
            return read_plan_current_artifact_task_plan_revision_v2(db, namespace=namespace,
                request=request, installed_readers=artifact_phase_readers)
        if operation_kind == "activate_artifact_task_project_checkpoint_v2":
            from .d10_project_checkpoint_v1 import read_plan_activate_current_artifact_task_project_checkpoint_v2
            return read_plan_activate_current_artifact_task_project_checkpoint_v2(db, namespace=namespace,
                request=request, installed_readers=artifact_phase_readers)
        if operation_kind == "register_artifact_task_milestone_v2":
            from .artifact_task_observer_v1 import read_plan_current_artifact_task_milestone_v2
            return read_plan_current_artifact_task_milestone_v2(db, namespace=namespace,
                request=request, installed_readers=artifact_phase_readers)
        if operation_kind in {"initialize_artifact_task_project_checkpoint_v1", "activate_artifact_task_project_checkpoint_v1"}:
            from .d10_project_checkpoint_v1 import read_plan_current_artifact_task_checkpoint_v1
            return read_plan_current_artifact_task_checkpoint_v1(db, namespace=namespace,
                request=request, installed_readers=artifact_phase_readers)
        if operation_kind == "create_artifact_task_project_v1":
            from .d10_project_checkpoint_v1 import read_plan_create_current_artifact_task_project_v1
            return read_plan_create_current_artifact_task_project_v1(db, namespace=namespace,
                request=request, installed_readers=artifact_phase_readers)
        if operation_kind in {"await_existing_artifact_revision_v1", "select_existing_artifact_continuation_v1", "revise_existing_artifact_v1"}:
            from .artifact_continuation_originals_v1 import read_plan_existing_artifact_continuation_v1
            plan = read_plan_existing_artifact_continuation_v1(db, namespace=namespace, request=request,
                include_content=operation_kind == "revise_existing_artifact_v1")
            if operation_kind == "await_existing_artifact_revision_v1":
                from ..domains.d10.project_checkpoint_v1 import CHECKPOINT_TYPE
                return production_read_plan_v1((*plan.fixed_type_ids, CHECKPOINT_TYPE),
                    plan.exact_keys, plan.source_roots, plan.required_original_refs)
            return plan
        if operation_kind in {"prepare_artifact_draft_model_v2", "acquire_artifact_draft_model_v2"}:
            from .d11_artifact_draft_model_v1 import read_plan_artifact_draft_model_v2
            return read_plan_artifact_draft_model_v2(db, namespace=namespace, operation_kind=operation_kind, request=request, installed_readers=artifact_phase_readers)
        if operation_kind in {"prepare_artifact_draft_model", "acquire_artifact_draft_model"}:
            from .d11_artifact_draft_model_v1 import read_plan_artifact_draft_model_v1
            return read_plan_artifact_draft_model_v1(db, namespace=namespace, operation_kind=operation_kind, request=request)
        if operation_kind == "propose_artifact_draft_phase_action_v2":
            from .d08_personal_plan_v1 import read_plan_current_artifact_phase_action_v2
            return read_plan_current_artifact_phase_action_v2(db, namespace=namespace,
                request=request, installed_readers=artifact_phase_readers)
        if operation_kind == "adopt_artifact_draft_content_v2":
            from .d11_artifact_draft_content_v1 import read_plan_artifact_draft_content_adoption_v2
            return read_plan_artifact_draft_content_adoption_v2(db, namespace=namespace, request=request, installed_readers=artifact_phase_readers)
        if operation_kind == "verify_artifact_draft_phase_v2":
            from .d11_artifact_draft_content_v1 import read_plan_artifact_draft_phase_verification_v2
            return read_plan_artifact_draft_phase_verification_v2(db, namespace=namespace, request=request, installed_readers=artifact_phase_readers)
        if operation_kind == "adopt_artifact_draft_content":
            from .d11_artifact_draft_content_v1 import read_plan_artifact_draft_content_adoption_v1
            return read_plan_artifact_draft_content_adoption_v1(db, namespace=namespace, request=request)
        if operation_kind in {"compose_artifact_goal_plan", "propose_artifact_draft_action"}:
            from .d08_personal_plan_v1 import read_plan_current_personal_plan_operation_v1
            return read_plan_current_personal_plan_operation_v1(db, namespace=namespace, activity_id=activity_id,
                operation_kind=operation_kind, request=request, operation_id=operation_id)
        if operation_kind == "create_artifact_project":
            from .d10_project_checkpoint_v1 import read_plan_create_current_artifact_project_v1
            return read_plan_create_current_artifact_project_v1(db, namespace=namespace, activity_id=activity_id, request=request)
        from .d03_life_project_context_v1 import read_plan_artifact_draft_project_context_v1
        return read_plan_artifact_draft_project_context_v1(db, namespace=namespace, request=request)
    if operation_kind in _FOREGROUND_OPERATIONS:
        if domain != "d11":
            raise ValueError("foreground cycle compiler has a different issuer domain")
        from .foreground_cycle_v1 import read_plan_current_foreground_cycle_v1
        return read_plan_current_foreground_cycle_v1(db, namespace=namespace, request=request)
    if operation_kind in {"prepare_personal_candidate_eligibility_v1", "adopt_personal_candidate_eligibility_v1"}:
        from .personal_candidate_eligibility_v1 import read_plan_personal_eligibility_v1
        return read_plan_personal_eligibility_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request, readers=personal_candidate_readers)
    if operation_kind in {"prepare_personal_candidates_v1", "select_personal_step_v2"}:
        if domain != "d08":
            raise ValueError("personal candidate operation belongs to D08")
        from .d08_personal_candidate_v1 import read_plan_personal_candidates_v1
        return read_plan_personal_candidates_v1(db, namespace=namespace, activity_id=activity_id,
            request=request, operation_id=operation_id, installed_readers=personal_candidate_readers)
    if operation_kind in {"pause_project_v1", "resume_project_v1"}:
        if domain != "d08":
            raise ValueError("project control has another domain writer")
        from .d08_project_control_v1 import read_plan_project_control_v1
        return read_plan_project_control_v1(db, namespace=namespace, operation_kind=operation_kind, request=request)
    from .d01_method_learning_v1 import OPERATIONS as METHOD_OPERATIONS, read_plan_current_method_learning_v1
    if operation_kind in METHOD_OPERATIONS:
        if domain != "d01" or installed_readers is None:
            raise ValueError("method-learning plan needs its actual installed D01 reader")
        return read_plan_current_method_learning_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request, installed_readers=installed_readers)
    if operation_kind == "observe_method_comparison_v1":
        if domain != "d11" or installed_readers is None:
            raise ValueError("actual method measurement needs its installed protected reader")
        from .d11_method_observation_v1 import read_plan_method_observation_v1
        return read_plan_method_observation_v1(db, namespace=namespace, request=request, installed_readers=installed_readers)
    if operation_kind == "quote_current_method_choices_v1":
        if domain != "d02" or installed_readers is None:
            raise ValueError("method readiness requires its actual installed prospective reader")
        from .d02_method_readiness_v1 import read_plan_current_method_readiness_v1
        return read_plan_current_method_readiness_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request, installed_readers=installed_readers)
    if operation_kind == "adopt_current_task_no_search_v1":
        if domain != "d07" or installed_readers is None:
            raise ValueError("task no-search requires its actual installed D07 reader")
        from .d07_task_history_v1 import read_plan_current_task_no_search_v1
        return read_plan_current_task_no_search_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request, installed_readers=installed_readers)
    if operation_kind == "adopt_current_c1_method_conditions_v1":
        if domain != "d07" or installed_readers is None:
            raise ValueError("C1 method-condition plan needs its actual installed D07 reader")
        from .d07_method_conditions_v1 import read_plan_current_c1_method_conditions_v1
        return read_plan_current_c1_method_conditions_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request, installed_readers=installed_readers)
    if operation_kind == "checkpoint_source_note_foreground_cycle_v1":
        from .foreground_cycle_v1 import read_plan_current_foreground_cycle_v1
        return read_plan_current_foreground_cycle_v1(db, namespace=namespace, request=request)
    if operation_kind == "prepare_selected_source_note_action_v2":
        if domain != "d08" or installed_readers is None:
            raise ValueError("selected SourceNote read plan needs its actual installed Self reader")
        from .d08_source_note_action_v1 import read_plan_selected_source_note_action_v2
        return read_plan_selected_source_note_action_v2(db, namespace=namespace, activity_id=activity_id,
            operation_id=operation_id, request=request, now_utc=now_utc, audiences=audiences, installed_readers=installed_readers)
    if operation_kind == "cancel_owner_source_note_task_v1":
        if domain != "d11" or installed_readers is None:
            raise ValueError("Owner task cancellation requires its actual installed Owner reader")
        from .cancel_owner_source_note_task_v1 import read_plan_cancel_owner_source_note_task_v1
        return read_plan_cancel_owner_source_note_task_v1(db, namespace=namespace, request=request, installed_readers=installed_readers)
    if operation_kind in {"register_owner_source_note_life_plan_v1", "register_owner_source_note_life_outcome_v1"}:
        if domain != "d10" or installed_readers is None:
            raise ValueError("Owner Life selectors require their actual installed task reader")
        from .owner_source_note_life_v1 import read_plan_owner_source_note_life_v1
        return read_plan_owner_source_note_life_v1(db, namespace=namespace, request=request, operation_kind=operation_kind, installed_readers=installed_readers)
    if operation_kind in {"create_owner_source_note_task_v1", "acquire_owner_source_note_task_v1", "checkpoint_owner_source_note_task_v1"}:
        if domain != "d11" or installed_readers is None:
            raise ValueError("Owner task execution needs its actual installed Self reader")
        from .owner_source_note_task_execution_v1 import read_plan_owner_source_note_task_execution_v1
        return read_plan_owner_source_note_task_execution_v1(db, namespace=namespace,
            operation_kind=operation_kind, request=request, installed_readers=installed_readers)
    if operation_kind == "prepare_owner_source_note_need_v1":
        if domain != "d07" or installed_readers is None:
            raise ValueError("Owner task Need needs its actual installed Self reader")
        from .owner_source_note_need_v1 import read_plan_owner_source_note_need_v1
        return read_plan_owner_source_note_need_v1(db, namespace=namespace, request=request, installed_readers=installed_readers)
    if operation_kind == "input:freeze_owner_source_note_values_parent_v1":
        if domain != "d08" or installed_readers is None: raise ValueError("Owner Values parent needs its actual installed task reader")
        from .owner_source_note_values_v1 import read_plan_owner_task_values_parent_v1
        return read_plan_owner_task_values_parent_v1(db, namespace=namespace, request=request, installed_readers=installed_readers)
    if operation_kind in {"input:freeze_values", "evaluate_values"} and installed_readers is not None and hasattr(installed_readers, "_owner_task_values_child_v1"):
        from .owner_source_note_values_v1 import read_plan_owner_task_values_child_v1
        evidence = installed_readers._owner_task_values_child_v1.current()
        return read_plan_owner_task_values_child_v1(db, namespace=namespace, selector=evidence.request, issuer=installed_readers.issuer)
    if operation_kind == "admit_owner_material_source_v1":
        if domain != "d06" or operation_id is None:
            raise ValueError("Owner material needs its actual D06 operation identity")
        from .owner_material_source_v1 import read_plan_owner_material_source_v1
        return read_plan_owner_material_source_v1(db, namespace=namespace, operation_id=operation_id, request=request)
    if operation_kind == "submit_owner_source_note_task_v1":
        if domain != "d08" or operation_id is None:
            raise ValueError("Owner task submission needs its actual D08 operation identity")
        from .owner_source_note_task_v1 import read_plan_owner_source_note_task_v1
        return read_plan_owner_source_note_task_v1(db, namespace=namespace, request=request, operation_id=operation_id)
    if operation_kind == "authorize_source_note_task_v1":
        if domain != "d11":
            raise ValueError("SourceNote authorization has another writer")
        from .source_note_task_authorization_v1 import read_plan_source_note_task_authorization_v1
        return read_plan_source_note_task_authorization_v1(db, namespace=namespace, request=request)
    if operation_kind == "create_source_note_foreground_cycle_v1":
        if domain != "d11" or installed_readers is None:
            raise ValueError("SourceNote initial creation needs its actual installed Self reader")
        from .source_note_foreground_v1 import read_plan_source_note_foreground_v1
        return read_plan_source_note_foreground_v1(db, namespace=namespace, request=request, installed_readers=installed_readers)
    if operation_kind == "initialize_relationship_prior_v2":
        if domain != "d05" or not operation_id:
            raise ValueError("relationship prior needs its actual Owner operation identity")
        from .d05_relationship_revision_v2 import read_plan_initialize_current_relationship_prior_v2
        return read_plan_initialize_current_relationship_prior_v2(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request, operation_id=operation_id)
    if operation_kind == "adopt_relationship_revision_v2":
        if domain != "d05":
            raise ValueError("relationship revision has another domain writer")
        from .d05_relationship_revision_v2 import read_plan_current_relationship_revision_v2
        return read_plan_current_relationship_revision_v2(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if operation_kind == "focus_owner_source_note_task_v1":
        from .d07_life_project_focus_v1 import read_plan_owner_source_note_focus_v1
        return read_plan_owner_source_note_focus_v1(db,namespace=namespace,operation_id=operation_id,
            request=request,installed_readers=installed_readers)
    if operation_kind in _PERSONAL_OPERATIONS:
        if _PERSONAL_OPERATIONS[operation_kind][0] != domain:
            raise ValueError("personal operation belongs to a different domain")
        if domain == "d08":
            if operation_kind == "create_artifact_task_plan_v1":
                from .d08_personal_plan_v1 import read_plan_current_artifact_task_plan_v1
                return read_plan_current_artifact_task_plan_v1(db, namespace=namespace,
                    request=request, installed_readers=artifact_phase_readers)
            from .d08_personal_plan_v1 import read_plan_current_personal_plan_operation_v1
            return read_plan_current_personal_plan_operation_v1(
                db, namespace=namespace, activity_id=activity_id,
                operation_kind=operation_kind, request=request,
                operation_id=operation_id)
        from .d10_project_checkpoint_v1 import read_plan_current_project_checkpoint_operation_v1
        return read_plan_current_project_checkpoint_operation_v1(
            db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if operation_kind == "input:register_artifact_task_text_extent":
        from .artifact_task_text_extent_v1 import read_plan_artifact_task_text_extent_v1
        return read_plan_artifact_task_text_extent_v1(db, namespace=namespace, request=request,
            installed_readers=personal_candidate_readers)
    if operation_kind.startswith("input:"):
        from .domain_production_inputs_v1 import read_plan_current_domain_input_v1
        return read_plan_current_domain_input_v1(db, namespace=namespace, activity_id=activity_id,
            producer_kind=operation_kind[len("input:"):], request=request, installed_readers=artifact_phase_readers)
    if operation_kind=='prepare_contact_prospective_v1':
        from .contact_prospective_v1 import read_plan_contact_prospective_v1
        return read_plan_contact_prospective_v1(db,namespace=namespace,activity_id=activity_id,operation_kind=operation_kind,request=request)
    if operation_kind == "prepare_contact_dispatch_v3":
        from .contact_final_stage_v3 import read_plan_contact_final_v3
        return read_plan_contact_final_v3(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if operation_kind == "prepare_contact_dispatch":
        from .contact_final_stage_v2 import read_plan_contact_final_v2
        return read_plan_contact_final_v2(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if operation_kind == "adopt_contact_expression_plan_v2":
        from .contact_plan_adoption_v2 import read_plan_contact_expression_v2
        return read_plan_contact_expression_v2(db,namespace=namespace,activity_id=activity_id,
            operation_kind=operation_kind,request=request)
    if operation_kind == "adopt_contact_expression_plan":
        from .contact_product_adapter_v1 import read_plan_contact_expression_v1
        return read_plan_contact_expression_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if operation_kind == "prepare_contact_model_v2":
        from .contact_product_adapter_v2 import read_plan_contact_model_v2
        return read_plan_contact_model_v2(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if operation_kind == "prepare_contact_model":
        from .contact_product_adapter_v1 import read_plan_contact_model_v1
        return read_plan_contact_model_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if operation_kind == "focus_life_project":
        from .d07_life_project_focus_v1 import read_plan_life_project_focus_v1
        return read_plan_life_project_focus_v1(db, namespace=namespace, operation_id=operation_id, request=request)
    if operation_kind == "prepare_life_project_context":
        from .d03_life_project_context_v1 import read_plan_life_project_context_v1
        return read_plan_life_project_context_v1(db, namespace=namespace, request=request)
    if operation_kind == "prepare_source_note_action":
        from .d08_source_note_action_v1 import read_plan_source_note_action_v1
        return read_plan_source_note_action_v1(db, namespace=namespace, activity_id=activity_id,
            operation_id=operation_id, request=request, now_utc=now_utc, audiences=audiences)
    if operation_kind in {"prepare_source_note_body", "prepare_artifact_draft_body"}:
        from .d02_life_body_preparation_v1 import read_plan_source_note_body_v1
        return read_plan_source_note_body_v1(db, namespace=namespace, activity_id=activity_id,
            operation_id=operation_id, request=request, now_utc=now_utc, installed_readers=installed_readers)
    if domain == "d10" and operation_kind == "prepare_offline_tick":
        from .d10_offline_tick_execution_v1 import read_plan_current_offline_tick_v1
        return read_plan_current_offline_tick_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if domain == "d10" and operation_kind == "prepare_life":
        from .d11_life_product_adapter_v1 import read_plan_current_life_preparation_v1
        return read_plan_current_life_preparation_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request, now_utc=now_utc,
            before_capture_policy=life_d04_before_capture_policy)
    if domain == "d10" and operation_kind == "advance_life":
        from .d10_production_operations_v1 import AdvanceCurrentLifeRequestV1
        from .d11_life_product_adapter_v1 import read_plan_current_life_progress_v2
        if type(request) is AdvanceCurrentLifeRequestV1:
            # The installed V2 planner already retains complete current query
            # inventories and separates Source roots from project/Owner
            # creation originals. Do not reinterpret these typed originals as
            # expression/source authority through the generic inventory path.
            actual = read_plan_current_life_progress_v2(
                db, namespace=namespace, activity_id=activity_id, request=request,
            )
            if actual is not None:
                return actual
    if operation_kind == "adopt_internal_life_content_v1":
        from .internal_life_content_adoption_v1 import read_plan_content_adoption_v1
        return read_plan_content_adoption_v1(db,namespace=namespace,activity_id=activity_id,operation_kind=operation_kind,request=request)
    if operation_kind == "acquire_internal_life_content_v2":
        from .internal_life_content_worker_v2 import read_plan_internal_life_acquire_v2
        return read_plan_internal_life_acquire_v2(db,namespace=namespace,activity_id=activity_id,
            operation_kind=operation_kind,request=request)
    if operation_kind == "acquire_internal_life_content":
        from .internal_life_content_worker_v1 import read_plan_internal_life_acquire_v1
        return read_plan_internal_life_acquire_v1(db,namespace=namespace,activity_id=activity_id,
            operation_kind=operation_kind,request=request)
    if operation_kind == "prepare_internal_life_content":
        from .internal_life_content_preparation_v1 import read_plan_internal_life_content_v1
        return read_plan_internal_life_content_v1(db,namespace=namespace,activity_id=activity_id,
            operation_kind=operation_kind,request=request)
    if operation_kind == "prepare_internal_life_numeric_drive":
        from .d06_life_numeric_drive_v1 import read_plan_life_numeric_drive_v1
        return read_plan_life_numeric_drive_v1(db, namespace=namespace, activity_id=activity_id, operation_kind=operation_kind, request=request)
    if operation_kind == "prepare_internal_life_numeric_joint":
        from .d06_life_numeric_joint_v1 import read_plan_life_numeric_joint_v1
        return read_plan_life_numeric_joint_v1(db, namespace=namespace, activity_id=activity_id, operation_kind=operation_kind, request=request)
    if operation_kind == "prepare_internal_life_interval_baseline":
        from .d04_life_encoding_baseline_v1 import read_plan_life_encoding_baseline_v1
        return read_plan_life_encoding_baseline_v1(db, namespace=namespace, activity_id=activity_id, operation_kind=operation_kind, request=request)
    if operation_kind == "adopt_internal_life_numeric_trace":
        from .d06_life_numeric_trace_v1 import read_plan_life_numeric_trace_v1
        return read_plan_life_numeric_trace_v1(db, namespace=namespace, activity_id=activity_id, operation_kind=operation_kind, request=request)
    if operation_kind in {'prepare_internal_life_numeric', 'acquire_internal_life_numeric', 'adopt_internal_life_numeric'}:
        from .d06_life_numeric_task_v1 import read_plan_life_numeric_prepare_v1, read_plan_life_numeric_adopt_v1
        from .d06_life_numeric_worker_v1 import read_plan_life_numeric_acquire_v1
        planner = {'prepare_internal_life_numeric':read_plan_life_numeric_prepare_v1,
            'acquire_internal_life_numeric':read_plan_life_numeric_acquire_v1,
            'adopt_internal_life_numeric':read_plan_life_numeric_adopt_v1}[operation_kind]
        return planner(db, namespace=namespace, activity_id=activity_id, operation_kind=operation_kind, request=request)
    if domain == "d06" and operation_kind == "prepare_internal_life_numeric_context":
        from .d06_life_numeric_context_v1 import read_plan_life_numeric_context_v1
        return read_plan_life_numeric_context_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if domain == "d06" and operation_kind == "encode_internal_life":
        from .d06_internal_life_encoding_v1 import read_plan_internal_life_encoding_v1
        return read_plan_internal_life_encoding_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if domain == "d06" and operation_kind == "encode_structured_experience":
        from .d06_structured_experience_v1 import read_plan_current_d06_structured_experience_v1
        return read_plan_current_d06_structured_experience_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if domain == "d06" and operation_kind == "form_association":
        from .d06_association_formation_v1 import read_plan_current_d06_association_v1
        return read_plan_current_d06_association_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if domain == "d07":
        from .d07_production_operations_v1 import read_plan_current_d07_operation_v1
        return read_plan_current_d07_operation_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if domain not in _READ_PLANNERS:
        raise ValueError("domain has no registered current production operations")
    plan = _READ_PLANNERS[domain](db, namespace=namespace, activity_id=activity_id,
                                operation_kind=operation_kind, request=request)
    # A typed inventory supplies current negative-query coverage. Its relevant
    # content/source fields are actual graph locators, not new instructions.
    roots = list(plan.source_roots)
    for type_name in plan.fixed_type_ids:
        if domain == "d08" and operation_kind == "recheck_action" and type_name == "d03.role_binding":
            # Owner configuration participates as an authoritative current
            # role head, not as conversation evidence or a passing D03 check.
            continue
        if type_name not in {"d03.entity_anchor", "d03.role_binding", "d03.world_event", "d05.boundary_rule"}:
            continue
        rows = read_graph_rows_v3(db, ('value',), where='bot=? AND persona=? AND type_name=? AND valid=1', parameters=(*namespace.as_tuple, type_name), history=False, order_by=('token',), limit=129)
        if len(rows) > 128:
            # Materialization records its partial page; it must not claim full
            # entity/boundary coverage or arbitrarily omit private tails.
            continue
        for (encoded,) in rows:
            from .domain_background_read_v3 import background_json_loads_v3
            value = background_json_loads_v3(encoded)
            for ref in value.get("source_refs", value.get("creation_evidence_refs", ())):
                roots.append(ref)
    keys = plan.exact_keys
    if operation_id is not None and domain == "d01" and operation_kind in {"adopt_growth","migrate_semantic_identity_v3","project_self_model_v3"}:
        pending_kind="growth" if operation_kind=="adopt_growth" else operation_kind
        keys += (waiting_domain_job_key_v1(namespace, operation_id, domain, pending_kind, activity_id),)
    return production_read_plan_v1(plan.fixed_type_ids, keys, roots, plan.required_original_refs)


def waiting_domain_job_key_v1(namespace, operation_id, domain, kind, activity_id):
    job_id = domain + "-pending:" + canonical_digest((namespace, operation_id, domain, kind, "waiting-original"))[:48]
    return AtomKey(Owner("activity", *namespace.as_tuple, activity_id), "runtime.job", job_id)


def _issuer(installed_readers):
    issuer = getattr(installed_readers, "issuer", None)
    if type(issuer) is not D11BudgetJobIssuer:
        raise TypeError("domain originals need the actual installed D11 issuer")
    return issuer


def _committed(db, namespace, operation):
    from .current_method_learning_read_v3 import read_bound_method_learning_attachment_v3
    from .domain_background_read_v3 import background_point_v3, background_json_loads_v3
    columns = ("digest", "receipt_json", "commit_seq")
    key_columns = ("bot", "persona", "operation_id")
    key = (*namespace.as_tuple, operation)
    handled, row = read_bound_method_learning_attachment_v3(
        db, table="graph_bundle_operations", columns=columns,
        key_columns=key_columns, key=key)
    if not handled:
        row = background_point_v3(
            db, table="graph_bundle_operations", columns=columns,
            key_columns=key_columns, key=key,
            legacy_reader=lambda: db.execute(
                "SELECT digest,receipt_json,commit_seq FROM graph_bundle_operations "
                "WHERE bot=? AND persona=? AND operation_id=?", key,
            ).fetchone())
    if row is None or row[2] < 1 or background_json_loads_v3(row[1]).get("commit_seq") != row[2]:
        raise ValueError("production original lost its actually committed producing operation")


def _signed_input(db, namespace, ref, issuer):
    from .domain_background_read_v3 import (background_signed_input_row_v3,background_json_loads_v3,
        background_json_matches_v3,background_json_digest_v3,background_verify_signature_v3)
    found = []
    for table, sign_kind, domain, kind in _INPUT_TABLES:
        if not table_exists_v1(db, table):
            continue
        select_kind = "kind" if kind == "kind" else "?"
        args = () if kind == "kind" else (kind,)
        row=background_signed_input_row_v3(db,namespace,table,ref,kind,legacy_reader=lambda:db.execute("SELECT " + select_kind + ",producing_operation_id,payload_json,payload_digest,signature "
            "FROM " + table + " WHERE bot=? AND persona=? AND original_ref=?", (*args, *namespace.as_tuple, ref)).fetchone())
        if row is None:
            continue
        if table=="graph_d01_production_inputs_v1" and row[0] in {"identity_plasticity_policy_v3","identity_trial_observation_policy_v3"}:
            continue  # Exact policy kinds are authenticated once by _signed_policy, never as ordinary inputs.
        background_verify_signature_v3(issuer._signer,sign_kind,row[2],row[4])
        raw = background_json_loads_v3(row[2])
        if not background_json_matches_v3(row[2],raw) or background_json_digest_v3(row[2],raw) != row[3]:
            raise ValueError("signed production input bytes changed")
        _committed(db, namespace, row[1])
        found.append(ProductionOriginalRefV1(domain + "." + row[0], ref, row[3]))
    if len(found) > 1:
        raise ValueError("production original locator collides across registered domains")
    return found[0] if found else None


def _signed_policy(db, namespace, ref, issuer):
    found = []
    from .d01_production_operations_v1 import TABLE as D01_TABLE, SIGN_KIND as D01_SIGN_KIND, _ORIGINAL_TYPES
    if table_exists_v1(db,D01_TABLE):
        row=db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature FROM "+D01_TABLE+
            " WHERE bot=? AND persona=? AND original_ref=?",(*namespace.as_tuple,ref)).fetchone()
        if row and row[0] in {"identity_plasticity_policy_v3","identity_trial_observation_policy_v3"}:
            issuer._signer.verify(D01_SIGN_KIND,row[2],row[4])
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            raw=json.loads(row[2]);policy=decode_typed_production_value_v1(raw,_ORIGINAL_TYPES[row[0]])
            actual=db.execute("SELECT commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                (*namespace.as_tuple,row[1])).fetchone()
            if (canonical_serialize(raw)!=row[2] or canonical_digest(raw)!=row[3]
                    or policy.namespace!=namespace or policy.policy_ref!=ref or actual is None or actual[0]<1):
                raise ValueError("D01 signed Owner policy original or producing commit changed")
            found.append((ProductionOriginalRefV1("d01."+row[0],ref,row[3]),
                ProductionPolicyRefV1(ref,policy.revision,row[3])))
    for table, sign_kind, domain in _POLICY_TABLES:
        if not table_exists_v1(db, table):
            continue
        row = db.execute("SELECT revision,payload_json,payload_digest,signature FROM " + table +
            " WHERE bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC LIMIT 1", (*namespace.as_tuple, ref)).fetchone()
        if row is None:
            continue
        raw = json.loads(row[1])
        if domain == "d05" and raw.get("schema_version") == 2:
            sign_kind = "d11.d05-production-policy.v2"
            from ..domains.d05.relationship_revision_v2 import InstalledRelationshipPolicyV2
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            decode_typed_production_value_v1(raw, InstalledRelationshipPolicyV2)
        issuer._signer.verify(sign_kind, row[1], row[3])
        if (canonical_serialize(raw) != row[1] or canonical_digest(raw) != row[2]
                or raw.get("policy_ref") != ref or raw.get("revision") != row[0]
                or raw.get("namespace") != {"bot_id": namespace.bot_id, "persona_id": namespace.persona_id}):
            raise ValueError("signed production policy current identity changed")
        found.append((ProductionOriginalRefV1(domain + ".installed_policy", ref, row[2]),
                      ProductionPolicyRefV1(ref, row[0], row[2])))
    if len(found) > 1:
        raise ValueError("production policy locator collides across domains")
    return found[0] if found else None


def read_committed_recollection_original_v1(db, namespace, ref):
    """Authenticate the immutable C04 activity against its actual W01 commit."""
    from ..domains.d06 import _validate_recollection
    from ..graph_store import GraphStore
    key = AtomKey.from_token(ref)
    if key.type_name != "d06.recollection.v1" or key.owner.kind != "activity" or NamespaceId.from_key(key) != namespace:
        raise ValueError("recollection original has another namespace/type")
    row = read_graph_row_v3(db, ('revision', 'value', 'valid'), where='token=? AND bot=? AND persona=?', parameters=(ref, *namespace.as_tuple), history=False)
    if row is None or row[0] < 1 or row[2] != 1:
        raise MissingProductionOriginalV1("actual_adopted_recollection_trigger:" + ref)
    value = json.loads(row[1])
    _validate_recollection(value)
    if value["activity_basis_refs"] != [value["selection_ref"], value["candidate_set_id"]]:
        raise ValueError("recollection activity basis differs from its selected ticket/set")
    history = read_graph_row_v3(db, ('value', 'valid', 'event_bot', 'event_persona', 'event_session', 'event_id'), where='token=? AND revision=?', parameters=(ref, row[0]), history=True)
    if (history is None or history[:2] != row[1:] or history[2:4] != namespace.as_tuple
            or history[4] != value["activity_id"] or key.owner.subject != value["activity_id"]
            or key.name != value["recollection_id"]):
        raise ValueError("recollection original has no exact adopted activity history")
    operation = history[5]
    committed = db.execute("SELECT digest,activity_id,effect_id,commit_seq,receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation)).fetchone()
    event = db.execute("SELECT reads,revisions FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        history[2:]).fetchone()
    if committed is None or event is None:
        raise MissingProductionOriginalV1("actual_committed_recollection_receipt:" + ref)
    receipt = json.loads(committed[4])
    version = GraphVersion(key, row[0])
    if (committed[1] != value["activity_id"] or type(committed[3]) is not int or committed[3] < 1
            or receipt.get("commit_seq") != committed[3]
            or receipt.get("status", "committed") not in {"committed", "duplicate"}
            or version not in GraphStore._version_rows(event[1])):
        raise ValueError("recollection original receipt/activity/write version differs")
    identity = {"namespace": namespace, "operation_id": operation, "activity_id": committed[1],
        "effect_id": committed[2], "commit_seq": committed[3], "bundle_digest": committed[0],
        "receipt": receipt, "write_version": (ref, row[0])}
    original = ProductionOriginalRefV1("d06.adopted_recollection", ref,
        canonical_digest({"value": value, "commit": identity}), (version,))
    canonical_activity = "recollection-activity:" + canonical_digest((namespace, committed[1], committed[2]))
    return original, canonical_activity


def read_d05_recollection_migration_material_v2(db, namespace, ref, *, legacy_source_token):
    """Actual immutable activity and original content families; no new qualification."""
    from ..domains.d05.relationship import AuthenticatedRecollectionMigrationMaterialV2
    from ..graph_store import GraphStore
    from ..memory_types import SourceRecord, source_key
    if not db.in_transaction:
        raise ValueError("D05 migration material needs the maintained read transaction")
    original, canonical = read_committed_recollection_original_v1(db, namespace, ref)
    version = original.read_versions[0]
    value, event_session, operation = read_graph_row_v3(db, ('value', 'event_session', 'event_id'), where='token=? AND revision=?', parameters=(ref, version.revision), history=True)
    value = json.loads(value)
    committed = db.execute("SELECT activity_id,effect_id,commit_seq FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation)).fetchone()
    reads = GraphStore._version_rows(db.execute("SELECT reads FROM graph_events "
        "WHERE bot=? AND persona=? AND session=? AND event_id=?", (*namespace.as_tuple, event_session, operation)).fetchone()[0])
    read_index = {item.key: item for item in reads}
    roots = tuple(source_key(*namespace.as_tuple, item).token for item in value["content_refs"])
    families, source_versions, seen, pending = [], [], set(), list(roots)
    while pending:
        source_ref = pending.pop()
        if source_ref in seen:
            continue
        seen.add(source_ref)
        if len(seen) > 32:
            raise MissingProductionOriginalV1("bounded_original_recollection_content_family")
        key = AtomKey.from_token(source_ref)
        source_version = read_index.get(key)
        if source_version is None or source_version.revision < 1:
            raise MissingProductionOriginalV1("actual_original_recollection_source_read:" + source_ref)
        row = read_graph_row_v3(db, ('value', 'valid'), where='token=? AND revision=?', parameters=(source_ref, source_version.revision), history=True)
        if row is None or row[1] != 1:
            raise MissingProductionOriginalV1("actual_original_recollection_source_history:" + source_ref)
        source = SourceRecord.from_dict(json.loads(row[0]))
        if source.source_id != key.owner.subject:
            raise ValueError("original recollection source identity differs")
        families.append(source.provenance_root)
        source_versions.append(source_version)
        pending.extend(source_key(*namespace.as_tuple, parent).token for parent in source.parent_source_ids)
    return AuthenticatedRecollectionMigrationMaterialV2(namespace, legacy_source_token, ref, canonical,
        committed[0], committed[1], operation, committed[2], version, original.original_digest,
        roots, tuple(sorted(set(families))), (version, *source_versions))


def _graph_original(db, namespace, ref):
    try:
        key = AtomKey.from_token(ref)
    except (TypeError, ValueError):
        return None
    if NamespaceId.from_key(key) != namespace:
        raise ValueError("production graph original crossed namespace")
    from ..domains.d01.method_learning_v1 import VALUE_TYPES
    if key.type_name in VALUE_TYPES:
        from .d01_method_learning_v1 import read_adopted_method_learning_original_v1
        return read_adopted_method_learning_original_v1(db, namespace=namespace, ref=ref)
    if key.type_name == "d07.current_interpretation.v1":
        from .d07_method_conditions_v1 import read_adopted_c1_method_condition_original_v1
        method_condition = read_adopted_c1_method_condition_original_v1(db, namespace=namespace, ref=ref)
        if method_condition is not None:
            return method_condition
    row = read_graph_row_v3(db, ('revision', 'value', 'valid'), where='token=? AND bot=? AND persona=?', parameters=(ref, *namespace.as_tuple), history=False)
    if row is None or row[0] < 1 or row[2] != 1:
        return None
    history = read_graph_row_v3(db, ('value', 'valid', 'event_bot', 'event_persona', 'event_session', 'event_id'), where='token=? AND revision=?', parameters=(ref, row[0]), history=True)
    if history is None or history[:2] != (row[1], row[2]) or history[2:4] != namespace.as_tuple:
        raise ValueError("production original has no exact adopted graph history")
    event = db.execute("SELECT revisions FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
                       history[2:]).fetchone()
    if event is None:
        raise ValueError("production graph original has no actual graph event")
    from ..graph_store import GraphStore
    if GraphVersion(key, row[0]) not in GraphStore._version_rows(event[0]):
        raise ValueError("production original head was not adopted by its graph event")
    value = json.loads(row[1])
    kind = key.type_name
    if key.type_name == "d06.recollection.v1":
        return read_committed_recollection_original_v1(db, namespace, ref)[0]
    if key.type_name == "runtime.cost_settlement":
        from .d11_types import cost_settlement_from_runtime
        cost = cost_settlement_from_runtime(db, **{name: value[name] for name in (
            "bot_id", "persona_id", "activity_id", "bundle_operation_id", "effect_id",
            "settlement_id", "lease_id", "cost_operation_id", "budget_operation_id", "budget_phase",
            "prior_unknown_ref", "execution_revoked")})
        from ..domains.d01.production_operations_v1 import plain_v1
        if plain_v1(cost) != value:
            raise ValueError("current cost head differs from the actual D11 budget settlement")
        kind = "d11.cost_settlement"
    return ProductionOriginalRefV1(kind, ref, canonical_digest(value), (GraphVersion(key, row[0]),))


def _role_clock_original(db, namespace, ref, issuer):
    from .d11_role_clock_installation_v1 import TABLE, SIGN_KIND, role_clock_mapping_id_v1
    if ref != role_clock_mapping_id_v1(namespace) or not table_exists_v1(db, TABLE):
        return None
    from .d04_semantic_installation_original_v3 import _read_signed
    saved = _read_signed(db, issuer, TABLE, SIGN_KIND, namespace)
    if saved is None:
        return None
    body, digest = saved
    if body["mapping"]["mapping_id"] != ref:
        raise ValueError("signed current role clock locator changed")
    from .clock import get_clock_mapping, _mapping_dict
    if _mapping_dict(get_clock_mapping(db, ref)) != body["mapping"]:
        raise ValueError("signed current clock mapping lost its actual D11 operation")
    versions = tuple(GraphVersion(AtomKey.from_token(row[0]), row[1]) for row in body["role_rows"])
    return ProductionOriginalRefV1("d11.role_clock", ref, digest, versions)


def _adopted_domain_original(db, namespace, ref):
    if not table_exists_v1(db, "graph_domain_production_originals_v1"):
        return None
    row = db.execute("SELECT operation_id FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? "
        "AND (operation_id=? OR domain || '-current:' || substr(original_digest,1,48)=?) LIMIT 2",
        (*namespace.as_tuple, ref, ref)).fetchall()
    physical = []
    if table_exists_v1(db, "graph_domain_production_originals_v3"):
        physical = db.execute("SELECT operation_id FROM graph_domain_production_originals_v3 WHERE bot=? AND persona=? "
            "AND (operation_id=? OR domain || '-current:' || substr(original_digest,1,48)=?) LIMIT 2",
            (*namespace.as_tuple, ref, ref)).fetchall()
    if physical:
        if row or len(physical) != 1:
            raise ValueError("domain adopted original identity is ambiguous across physical versions")
        from .domain_production_originals_v1 import _physical_original_row_v3, _validate_physical_original_metadata_v3
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
        saved = _physical_original_row_v3(db, namespace, physical[0][0])
        _validate_physical_original_metadata_v3(db, namespace, physical[0][0], saved)
        cell = begin_runtime_cell_read_v3(db, saved[4])
        if cell.header[5] != saved[3]:
            raise ValueError("adopted physical original header digest differs")
        return ProductionOriginalRefV1(saved[0] + ".current-" + saved[1], ref, saved[3])
    if not row:
        return None
    if len(row) != 1:
        raise ValueError("domain adopted original identity is ambiguous")
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    saved = read_adopted_domain_operation_v1(db, namespace, row[0][0])
    # These inputs are immutable historical adoptions. Their pre-CAS read
    # versions are retained by the original reader, not asserted as current
    # heads after that adoption has legitimately changed body/role state.
    # Each consumer's fixed read plan separately qualifies current sources.
    return ProductionOriginalRefV1(saved["domain"] + ".current-" + saved["operation_kind"], ref,
                                  saved["original_digest"])


def _outbound_original(db, namespace, ref):
    if not table_exists_v1(db, "graph_d13_outbound_observations_v1"):
        return None
    rows = db.execute("SELECT observation_digest,observation_json,original_json,original_digest FROM graph_d13_outbound_observations_v1 "
        "WHERE bot=? AND persona=? AND (source_ref=? OR observation_digest=? OR final_operation_id=?) LIMIT 3",
        (*namespace.as_tuple, ref, ref, ref)).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise MissingProductionOriginalV1("unique_current_outbound_observation:" + ref)
    from ..authority_service.v2_contract import MutationReceiptV2, from_wire
    digest, observed_json, original_json, original_digest = rows[0]
    observed, original = from_wire(json.loads(observed_json)), json.loads(original_json)
    if (type(observed) is not MutationReceiptV2 or observed.durable_state != "committed"
            or observed.pending.phase != "observed" or canonical_digest(observed) != digest
            or canonical_digest(original) != original_digest or original["observation_digest"] != digest):
        raise ValueError("actual independent outbound observation original changed")
    return ProductionOriginalRefV1("d11.outbound_observation", ref, digest)


def read_current_domain_original_refs_v1(db, *, namespace, plan, installed_readers, authenticated_external_originals=()):
    from .current_d07_simulation_source_read_v3 import read_bound_current_d07_simulation_original_refs_v3
    handled,refs=read_bound_current_d07_simulation_original_refs_v3(db,namespace=namespace,plan=plan,installed_readers=installed_readers,external=authenticated_external_originals)
    if handled:return refs
    from .d07_source_owner_read_v3 import read_bound_d07_source_original_refs_v3
    handled,refs=read_bound_d07_source_original_refs_v3(db,namespace=namespace,plan=plan,installed_readers=installed_readers,external=authenticated_external_originals)
    if handled:return refs
    if not db.in_transaction or type(namespace) is not NamespaceId or type(plan) is not ProductionReadPlanV1:
        raise ValueError("domain originals require the current W01 transaction and exact read plan")
    issuer = _issuer(installed_readers)
    if (type(authenticated_external_originals) is not tuple
            or any(type(original) is not ProductionOriginalRefV1 for original in authenticated_external_originals)):
        raise TypeError("outside-transaction originals must come from the installed Authority adapter")
    external = {original.original_ref: original for original in authenticated_external_originals}
    if len(external) != len(authenticated_external_originals):
        raise ValueError("independent production original references repeat")
    result = []
    for ref in plan.required_original_refs:
        original = _signed_input(db, namespace, ref, issuer)
        policy = _signed_policy(db, namespace, ref, issuer)
        if policy:
            if original:
                raise ValueError("production original and policy locator collide")
            original = policy[0]
        original = original or _role_clock_original(db, namespace, ref, issuer)
        original = original or _adopted_domain_original(db, namespace, ref)
        original = original or _outbound_original(db, namespace, ref)
        if original is None:
            from .d11_offline_originals_v1 import read_current_d11_offline_original_ref_v1
            original = read_current_d11_offline_original_ref_v1(db, namespace=namespace, original_ref=ref, issuer=issuer)
        if original is None:
            from .d11_life_product_adapter_v1 import read_current_life_original_ref_v1
            original = read_current_life_original_ref_v1(db, namespace=namespace, original_ref=ref, issuer=issuer)
        if original is None:
            from .artifact_phase_postconditions_v1 import read_current_artifact_phase_postcondition_original_ref_v1
            original = read_current_artifact_phase_postcondition_original_ref_v1(db, namespace=namespace,
                original_ref=ref, issuer=issuer)
        if original is None:
            from .artifact_task_observer_v1 import read_current_artifact_task_milestone_original_ref_v2
            original = read_current_artifact_task_milestone_original_ref_v2(db, namespace=namespace,
                original_ref=ref, issuer=issuer)
        if original is None and ref.startswith('contact-prospective-original:'):
            from .contact_prospective_v1 import read_contact_prospective_original_ref_v1
            original=read_contact_prospective_original_ref_v1(db,namespace=namespace,original_ref=ref,issuer=issuer)
        if original is None and ref.startswith("method-readiness-quote:"):
            from .d02_method_readiness_v1 import read_current_method_readiness_quote_original_v1
            original = read_current_method_readiness_quote_original_v1(db, namespace=namespace, ref=ref, issuer=issuer)
        if original is None and ref.startswith("method-comparison-observation:"):
            from .d11_method_observation_v1 import read_current_method_observation_original_ref_v1
            original = read_current_method_observation_original_ref_v1(db, namespace=namespace, original_ref=ref, issuer=issuer)
        if original is None and ref.startswith("owner-note-values-parent:"):
            from .owner_source_note_values_v1 import read_owner_task_values_parent_original_ref_v1
            original = read_owner_task_values_parent_original_ref_v1(db, namespace=namespace, original_ref=ref, issuer=issuer)
        if original is None and ref.startswith("owner-note-responsibility:"):
            from .owner_source_note_task_execution_v1 import read_owner_source_note_task_responsibility_v2
            saved_task = read_owner_source_note_task_responsibility_v2(db,namespace=namespace,original_ref=ref,issuer=issuer)
            if saved_task is not None:
                original = ProductionOriginalRefV1('d11.life_owner_source_note_task_responsibility_v2',ref,saved_task[0].digest)
        if original is None and ref.startswith(("owner-source-note-authorization:","owner-source-note-cause:")):
            from .owner_source_note_task_v1 import read_owner_source_note_task_original_ref_v1
            original = read_owner_source_note_task_original_ref_v1(db, namespace=namespace, original_ref=ref, issuer=issuer)
        if original is None and ref.startswith("source-note-task-authorization:"):
            from .source_note_task_authorization_v1 import read_source_note_task_authorization_v1
            saved = read_source_note_task_authorization_v1(db, namespace=namespace, original_ref=ref, issuer=issuer)
            if saved is not None:
                    original = ProductionOriginalRefV1("d11.life_source_note_task_authorization", ref, saved[0].digest)
        original = original or _graph_original(db, namespace, ref)
        if original is None:
            service = getattr(installed_readers, "execution_reader", None)
            if service is not None:
                from .d07_execution_v1 import read_current_original_ref_v1
                original = read_current_original_ref_v1(db, namespace=namespace, ref=ref, issuer=issuer)
        supplied = external.get(ref)
        if supplied is not None:
            if original is not None and (original.original_digest != supplied.original_digest
                    or original.read_versions != supplied.read_versions):
                raise ValueError("independent original differs from the durable current DB original")
            original = supplied
        if original is not None:
            result.append(original)
    # Actual external restore anchors/ticks may be implicit dependencies of a
    # fixed reader, even when their lookup is not a caller-controlled field.
    for original in authenticated_external_originals:
        if original.original_ref not in {item.original_ref for item in result}:
            if original.kind not in {"d11.restore_anchor", "d11.trusted_tick", "d11.clock_sample", "d03.current_self_identity"}:
                continue
            result.append(original)
    from .current_habit_source_read_v3 import current_habit_independent_core_original_refs_v3
    for original in current_habit_independent_core_original_refs_v3(db):
        prior=next((value for value in result if value.original_ref==original.original_ref),None)
        if prior is not None and prior!=original:
            raise ValueError('Habit actual independent Core original conflicts with the stored original')
        if prior is None:result.append(original)
    return tuple(result)


def read_current_domain_policy_refs_v1(db, *, namespace, plan, installed_readers):
    issuer = _issuer(installed_readers)
    refs = []
    for ref in plan.required_original_refs:
        found = _signed_policy(db, namespace, ref, issuer)
        if found:
            refs.append(found[1])
    # D02 passive advancement uses explicit historical boundaries for the
    # current profile; all those signed versions remain relevant to the read.
    if "d02.body_state.v1" in plan.fixed_type_ids and table_exists_v1(db, "graph_d02_production_policies_v1"):
        rows = db.execute("SELECT policy_ref,revision,payload_json,payload_digest,signature FROM graph_d02_production_policies_v1 "
                          "WHERE bot=? AND persona=? AND kind='passive' ORDER BY from_role_cursor,policy_ref,revision LIMIT 129",
                          namespace.as_tuple).fetchall()
        if len(rows) > 128:
            raise MissingProductionOriginalV1("bounded_passive_policy_history",
                continuation="passive-policy:" + canonical_digest(namespace)[:48])
        for ref, revision, encoded, digest, signature in rows:
            issuer._signer.verify("d11.d02-production-policy.v1", encoded, signature)
            if canonical_digest(json.loads(encoded)) != digest:
                raise ValueError("D02 historical passive policy bytes changed")
            refs.append(ProductionPolicyRefV1(ref, revision, digest))
    if len({(ref.policy_ref, ref.revision) for ref in refs}) != len(refs):
        refs = list({(ref.policy_ref, ref.revision): ref for ref in refs}.values())
    return tuple(sorted(refs, key=lambda item: (item.policy_ref, item.revision)))


@dataclass(frozen=True, slots=True)
class CurrentDomainCommandIdentityV1:
    activity_id: str
    effect_id: str | None
    purpose: str
    audience_ref: str


def read_current_domain_command_identity_v1(db, *, namespace, operation_kind, request,
        requested_activity_id, requested_audience_ref, installed_readers=None, operation_id=None):
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("command identity must be derived in the current W01 transaction")
    activity, effect, purpose = requested_activity_id, None, "context"
    from ..domains.d03.world_history_v1 import WORLD_OPERATIONS
    if operation_kind in WORLD_OPERATIONS:
        purpose=("consolidation" if operation_kind in {"adopt_world_assertion_v1","relearn_world_assertion_v1"} else
            "expression" if operation_kind=="project_world_perspective_v1" else request.purpose)
        if operation_kind=="query_world_view_v1" and request.audience!=requested_audience_ref:
            raise ValueError("World command audience differs from its explicit query")
        return CurrentDomainCommandIdentityV1(activity,None,purpose,requested_audience_ref)
    if operation_kind in {"prepare_personal_candidate_eligibility_v1", "adopt_personal_candidate_eligibility_v1"}:
        from .d08_personal_candidate_v1 import actual_personal_candidate_activity_v2
        activity = actual_personal_candidate_activity_v2(db, namespace=namespace, request=request.candidates, issuer=_issuer(installed_readers))
        return CurrentDomainCommandIdentityV1(activity, None, "consolidation", requested_audience_ref)
    if operation_kind in {"prepare_life_project_context", "focus_life_project", "focus_owner_source_note_task_v1", "prepare_personal_candidates_v1", "select_personal_step_v2",
            "input:register_artifact_phase_postcondition_policy_v1", "register_artifact_phase_postcondition_contract_v1",
            "observe_artifact_phase_postconditions_v1"}:
        purpose = "consolidation"
    elif operation_kind == "prepare_source_note_action":
        from .d08_source_note_action_v1 import source_note_effect_id_v1
        effect, purpose = source_note_effect_id_v1(namespace, request.project_ref, operation_id), "consolidation"
    elif operation_kind in {"prepare_source_note_body", "prepare_artifact_draft_body"}:
        if operation_kind == "prepare_artifact_draft_body":
            from .d08_life_admission_v1 import require_draft_action_root_v1
            root = require_draft_action_root_v1(db, namespace=namespace,
                action_intent_ref=request.action_intent_ref, issuer=_issuer(installed_readers))
        else:
            from .d08_source_note_action_v1 import require_source_note_action_original_v1
            root = require_source_note_action_original_v1(db, namespace=namespace,
                action_intent_ref=request.action_intent_ref, issuer=_issuer(installed_readers))
        if operation_id != "d02-life-body:" + root.action_operation_id:
            raise ValueError("Body B must be the actual distinct command of root A")
        activity, effect, purpose = root.activity_id, root.effect_id, "consolidation"
    elif operation_kind in {'prepare_internal_life_content', 'acquire_internal_life_content', 'acquire_internal_life_content_v2','adopt_internal_life_content_v1'}:
        from .internal_life_content_preparation_v1 import PrepareInternalLifeContentRequestV1
        from .internal_life_content_worker_v1 import AcquireInternalLifeContentRequestV1
        from .d06_internal_life_episode_v2 import PROVENANCE,decode_internal_life_value_v2
        from ..model_broker.internal_life_content_v1 import internal_life_content_ids_for_occurrence_v1
        from .internal_life_content_worker_v2 import AcquireInternalLifeContentRequestV2
        from .internal_life_content_adoption_v1 import AdoptInternalLifeContentRequestV1
        expected = (AdoptInternalLifeContentRequestV1 if operation_kind=="adopt_internal_life_content_v1" else PrepareInternalLifeContentRequestV1 if operation_kind == 'prepare_internal_life_content' else
            AcquireInternalLifeContentRequestV2 if operation_kind == 'acquire_internal_life_content_v2' else AcquireInternalLifeContentRequestV1)
        if type(request) is not expected:
            raise TypeError('exact Life content preparation request required')
        episode=AtomKey.from_token(request.episode_ref)
        proof=decode_internal_life_value_v2(PROVENANCE,
            raw_head_value_v1(db,namespace,AtomKey(episode.owner,PROVENANCE,'record')))
        ids=internal_life_content_ids_for_occurrence_v1(proof)
        if (proof.event.namespace!=namespace or proof.episode.episode_ref!=request.episode_ref
                or proof.event.causal_operation_id!=request.causal_operation_id
                or proof.event.activity.activity_id!=requested_activity_id
                or operation_id!=('life-content-adopt:'+ids['job'].removeprefix('life-content-job:') if operation_kind=='adopt_internal_life_content_v1' else ids['prepare' if operation_kind == 'prepare_internal_life_content' else 'acquire'])):
            raise ValueError('Life content command must use its immutable occurrence once identity')
        activity,effect,purpose=proof.event.activity.activity_id,None,'consolidation'
    elif operation_kind in {'prepare_internal_life_numeric', 'acquire_internal_life_numeric', 'adopt_internal_life_numeric'}:
        from .d06_life_numeric_context_v1 import life_numeric_context_ids_v1, decode_life_numeric_context_original_v1, KIND
        from .d06_life_numeric_task_v1 import _identity
        from .d11_life_product_adapter_v1 import raw_life_original_v1
        from ..model_broker.internal_life_numeric_v1 import internal_life_numeric_ids_v1
        raw = raw_life_original_v1(db, namespace, KIND, life_numeric_context_ids_v1(namespace, request.episode_ref)['original'])
        if raw is None:
            raise MissingProductionOriginalV1('actual_life_numeric_context')
        original = decode_life_numeric_context_original_v1(raw)
        ids = internal_life_numeric_ids_v1(_identity(original))
        suffix = {'prepare_internal_life_numeric':'prepare', 'acquire_internal_life_numeric':'acquire', 'adopt_internal_life_numeric':'adopt'}[operation_kind]
        from .d06_internal_life_episode_v2 import PROVENANCE, decode_internal_life_value_v2
        episode = AtomKey.from_token(request.episode_ref)
        proof_raw = raw_head_value_v1(db, namespace, AtomKey(episode.owner, PROVENANCE, 'record'))
        if proof_raw is None:
            raise MissingProductionOriginalV1('actual_internal_life_episode_provenance')
        proof = decode_internal_life_value_v2(PROVENANCE, proof_raw)
        if (original.namespace != namespace or original.episode_ref != request.episode_ref
                or proof.event.namespace != namespace or proof.episode.episode_ref != request.episode_ref
                or proof.event.causal_operation_id != request.causal_operation_id
                or proof.event.activity.activity_id != requested_activity_id or operation_id != ids[suffix]):
            raise ValueError('numeric Life task identity differs from its actual occurrence')
        activity, effect, purpose = proof.event.activity.activity_id, None, 'consolidation'
    elif operation_kind in {'prepare_internal_life_interval_baseline', 'adopt_internal_life_numeric_trace', 'prepare_internal_life_numeric_joint', 'prepare_internal_life_numeric_drive'}:
        from .d06_internal_life_episode_v2 import PROVENANCE, decode_internal_life_value_v2
        from .d06_life_numeric_drive_v1 import life_numeric_drive_ids_v1
        from .d06_life_numeric_joint_v1 import life_numeric_joint_ids_v1
        from .d04_life_encoding_baseline_v1 import life_encoding_baseline_ids_v1
        from .d06_life_numeric_trace_v1 import life_numeric_trace_operation_v1
        if operation_kind == 'prepare_internal_life_numeric_drive':
            expected = life_numeric_drive_ids_v1(namespace, request.episode_ref, request.appraisal_ref)['operation']
        elif operation_kind == 'prepare_internal_life_numeric_joint':
            expected = life_numeric_joint_ids_v1(namespace, request.episode_ref, request.appraisal_ref)['prepare']
        elif operation_kind == 'prepare_internal_life_interval_baseline':
            expected = life_encoding_baseline_ids_v1(namespace, request.episode_ref, request.joint_operation_id)['operation']
        else:
            expected = life_numeric_trace_operation_v1(namespace, request.episode_ref, request.joint_operation_id)
        episode = AtomKey.from_token(request.episode_ref)
        raw = raw_head_value_v1(db, namespace, AtomKey(episode.owner, PROVENANCE, 'record'))
        if raw is None:
            raise MissingProductionOriginalV1('actual_internal_life_episode_provenance')
        proof = decode_internal_life_value_v2(PROVENANCE, raw)
        if (proof.event.namespace != namespace or proof.episode.episode_ref != request.episode_ref
                or proof.event.causal_operation_id != request.causal_operation_id
                or proof.event.activity.activity_id != requested_activity_id or operation_id != expected):
            raise ValueError('numeric Life mathematical command differs from actual occurrence and adopted input')
        activity, effect, purpose = proof.event.activity.activity_id, None, 'consolidation'
    elif operation_kind == "prepare_internal_life_numeric_context":
        from .d06_life_numeric_context_v1 import PrepareLifeNumericContextRequestV1, life_numeric_context_ids_v1
        from .d06_internal_life_episode_v2 import PROVENANCE, decode_internal_life_value_v2
        if type(request) is not PrepareLifeNumericContextRequestV1:
            raise TypeError('exact numeric Life context request required')
        episode = AtomKey.from_token(request.episode_ref)
        raw = raw_head_value_v1(db, namespace, AtomKey(episode.owner, PROVENANCE, 'record'))
        if raw is None:
            raise MissingProductionOriginalV1('actual_internal_life_episode_provenance')
        proof = decode_internal_life_value_v2(PROVENANCE, raw)
        if (proof.event.namespace != namespace or proof.episode.episode_ref != request.episode_ref
                or proof.event.causal_operation_id != request.causal_operation_id
                or proof.event.activity.activity_id != requested_activity_id
                or operation_id != life_numeric_context_ids_v1(namespace, request.episode_ref)['operation']):
            raise ValueError('numeric Life context exact occurrence once identity differs')
        activity, effect, purpose = proof.event.activity.activity_id, None, 'consolidation'
    elif operation_kind == "encode_internal_life":
        from .d06_internal_life_encoding_v1 import EncodeInternalLifeRequestV1
        from .d06_internal_life_episode_v2 import PROVENANCE, decode_internal_life_value_v2
        if type(request) is not EncodeInternalLifeRequestV1:
            raise TypeError('exact Life encoding locator required')
        episode = AtomKey.from_token(request.episode_ref)
        proof_value = raw_head_value_v1(db, namespace, AtomKey(episode.owner, PROVENANCE, 'record'))
        if proof_value is None:
            raise MissingProductionOriginalV1('actual_internal_life_episode_provenance')
        proof = decode_internal_life_value_v2(PROVENANCE, proof_value)
        if (proof.event.namespace != namespace or proof.episode.episode_ref != request.episode_ref
                or proof.event.causal_operation_id != request.causal_operation_id
                or proof.event.activity.activity_id != requested_activity_id):
            raise ValueError('Life encoding identity is not its actual occurrence')
        activity = proof.event.activity.activity_id
        effect = 'effect:life-encoding:' + canonical_digest((namespace, request.episode_ref, operation_id))[:48]
        purpose = 'consolidation'
    elif operation_kind in {"encode_structured_experience", "form_association", "adopt_growth", "migrate_semantic_identity_v3", "project_self_model_v3", "adopt_relationship_contribution", "reevaluate_relationship",
            "input:prepare_growth_input", "input:derive_growth_trial", "input:prepare_semantic_growth_input_v3",
            "input:start_semantic_growth_trial_v3",
            "freeze_general_growth_intent_v1", "register_general_growth_trial_start_v1",
            "derive_general_growth_trial_v1", "adopt_general_growth_v1"}:
        purpose = "consolidation"
    elif operation_kind=='prepare_contact_prospective_v1':
        from .contact_prospective_v1 import command_identity_contact_prospective_v1
        activity,effect,audience=command_identity_contact_prospective_v1(db,namespace=namespace,
            request=request,operation_id=operation_id,issuer=_issuer(installed_readers))
        if (requested_activity_id,requested_audience_ref)!=(activity,audience):
            raise ValueError('Contact prospective changed its actual paid activity/audience')
        purpose='expression'
    elif operation_kind == "prepare_contact_dispatch_v3":
        from .contact_final_stage_v3 import command_identity_contact_final_v3
        activity, effect, audience = command_identity_contact_final_v3(db, namespace=namespace,
            request=request, operation_id=operation_id, issuer=_issuer(installed_readers))
        if (requested_activity_id, requested_audience_ref) != (activity, audience):
            raise ValueError("Contact3 final command differs from its actual paid activity/audience")
        purpose = "expression"
    elif operation_kind == "prepare_contact_dispatch":
        from .contact_final_stage_v2 import command_identity_contact_final_v2
        activity, effect, audience = command_identity_contact_final_v2(db, namespace=namespace,
            request=request, operation_id=operation_id, issuer=_issuer(installed_readers))
        if (requested_activity_id, requested_audience_ref) != (activity, audience):
            raise ValueError('Contact final command differs from its original activity/private audience')
        purpose = 'expression'
    elif operation_kind == "prepare_contact_model_v2":
        from .contact_product_adapter_v2 import command_identity_contact_model_v2
        activity, effect, purpose = command_identity_contact_model_v2(db, namespace=namespace,
            request=request, operation_id=operation_id, issuer=_issuer(installed_readers))
        if requested_activity_id != activity:
            raise ValueError("Contact V2 preparation must use its actual adopted activity")
    elif operation_kind == "prepare_contact_model":
        from .contact_product_adapter_v1 import command_identity_contact_model_v1
        activity, effect, purpose = command_identity_contact_model_v1(db, namespace=namespace,
            request=request, operation_id=operation_id, issuer=_issuer(installed_readers))
        if requested_activity_id != activity:
            raise ValueError("contact model preparation must use its adopted stable activity")
    elif operation_kind in {"adopt_contact_expression_plan", "adopt_contact_expression_plan_v2"}:
        from ..domains.d08.contact_plan_v1 import contact_ids_v1
        opportunity = raw_head_value_v1(db, namespace, AtomKey.from_token(request.opportunity_ref))
        if opportunity is None:
            raise MissingProductionOriginalV1("actual_current_contact_opportunity")
        activity = contact_ids_v1(namespace, opportunity["source_ref"], opportunity["subject_ref"], "private_text")["activity"]
        if requested_activity_id != activity:
            raise ValueError("contact command activity differs from its stable actual cause")
        purpose = "expression"
    elif operation_kind in {"prepare_contact", "input:create_goal", "input:create_contact_opportunity"}:
        purpose = "expression"
    elif operation_kind in {"recheck_action", "settle_observed_action"}:
        action = raw_head_value_v1(db, namespace, AtomKey.from_token(request.action_intent_ref))
        if action:
            from ..domains.d08.execution import _decode_intent
            intent = _decode_intent(action)
            activity, effect, purpose = intent.identity.activity_id, intent.identity.effect_id, intent.purpose
    elif operation_kind == "apply_body_effect":
        from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
        prepared = read_c04_internal_work_prepared_v1(db, namespace, request.settlement_operation_ref) if table_exists_v1(db, "graph_c04_internal_work_prepared_v1") else None
        if prepared:
            activity = prepared.binding.activity_id
            if installed_readers is not None:
                quote = _issuer(installed_readers).resource_issuer.original_signed_quote(db,
                    prepared.binding.resource_quote_ref, prepared.binding.resource_quote_version)
                effect = quote.effect_id
        else:
            completion = raw_registered_input_v1(db, "graph_d02_action_components_v1", namespace, request.settlement_operation_ref)
            if completion:
                if installed_readers is not None:
                    _signed_input(db, namespace, request.settlement_operation_ref, _issuer(installed_readers))
                action = raw_head_value_v1(db, namespace, AtomKey.from_token(completion["action_intent_ref"]))
                if action:
                    from ..domains.d08.execution import _decode_intent
                    intent = _decode_intent(action)
                    activity, effect, purpose = intent.identity.activity_id, intent.identity.effect_id, intent.purpose
    elif operation_kind in {"input:register_life_plan_v2", "input:register_life_outcome_v2", "prepare_life"}:
        from .d11_life_contract_v1 import RegisteredLifePlanV2, life_from_wire_v1
        from .d11_life_product_adapter_v1 import raw_life_original_v1
        if operation_kind == "input:register_life_plan_v2":
            plan = request.plan
        else:
            ref = request.plan_original_ref if operation_kind == "prepare_life" else request.outcome.plan_original_ref
            raw = raw_life_original_v1(db, namespace, "plan", ref)
            if raw is None:
                raise MissingProductionOriginalV1("actual_registered_life_plan_v2")
            plan = life_from_wire_v1(raw, RegisteredLifePlanV2)
            if installed_readers is not None:
                from .d11_life_preparation_v1 import read_registered_life_plan_v2
                plan = read_registered_life_plan_v2(db, namespace=namespace,
                    issuer=_issuer(installed_readers), original_ref=ref)
        action = raw_head_value_v1(db, namespace, AtomKey.from_token(plan.action_intent.ref))
        if action is None:
            raise MissingProductionOriginalV1("actual_current_life_root_action")
        from ..domains.d08.execution import _decode_intent
        intent = _decode_intent(action)
        if operation_kind == "prepare_life" and operation_id != request.prepare_operation_id:
            raise ValueError("Life prepare command differs from the actual requested Owner operation")
        activity, effect, purpose = intent.identity.activity_id, intent.identity.effect_id, intent.purpose
        if requested_audience_ref not in plan.audiences:
            raise ValueError("Life command audience is outside the actual registered input scope")
    elif operation_kind == "input:register_life_plan":
        action = raw_head_value_v1(db, namespace, AtomKey.from_token(request.plan.action_intent_ref))
        if action:
            from ..domains.d08.execution import _decode_intent
            intent = _decode_intent(action)
            activity, effect, purpose = intent.identity.activity_id, intent.identity.effect_id, intent.purpose
    elif operation_kind in {"advance_life", "input:register_life_outcome"}:
        from .d11_life_product_adapter_v1 import raw_life_original_v1
        life_outcome = raw_life_original_v1(db, namespace, "outcome", request.activity_outcome_ref) if operation_kind == "advance_life" else None
        if life_outcome is not None:
            from .d11_life_preparation_v1 import read_registered_life_plan_v2
            from .d11_life_contract_v1 import RegisteredLifeOutcomeV2, life_from_wire_v1
            current = life_from_wire_v1(life_outcome, RegisteredLifeOutcomeV2)
            plan = read_registered_life_plan_v2(db, namespace=namespace,
                issuer=_issuer(installed_readers), original_ref=current.plan_original_ref)
            if plan is None:
                raise MissingProductionOriginalV1("actual_registered_life_plan_v2")
            if plan.activity_id != requested_activity_id or requested_audience_ref not in plan.audiences:
                raise ValueError("Life V2 command differs from the actual plan identity/audience")
            return CurrentDomainCommandIdentityV1(plan.activity_id, plan.effect_id, "consolidation", requested_audience_ref)
        if operation_kind == "input:register_life_outcome":
            outcome = {"plan_original_ref": request.outcome.plan_original_ref}
        else:
            outcome = raw_registered_input_v1(db, "graph_d10_production_inputs_v1", namespace, request.activity_outcome_ref)
        if outcome:
            if installed_readers is not None and operation_kind == "advance_life":
                _signed_input(db, namespace, request.activity_outcome_ref, _issuer(installed_readers))
            plan = raw_registered_input_v1(db, "graph_d10_production_inputs_v1", namespace, outcome["plan_original_ref"])
            if plan:
                if installed_readers is not None:
                    _signed_input(db, namespace, outcome["plan_original_ref"], _issuer(installed_readers))
                action = raw_head_value_v1(db, namespace, AtomKey.from_token(plan["action_intent_ref"]))
                if action:
                    from ..domains.d08.execution import _decode_intent
                    intent = _decode_intent(action)
                    activity, effect, purpose = intent.identity.activity_id, intent.identity.effect_id, intent.purpose
    elif operation_kind in {"serve_concern", "advance_reflection", "run_simulation"}:
        service = getattr(installed_readers, "execution_reader", None)
        if service is not None and hasattr(service, "read_current_command_identity_v1"):
            value = service.read_current_command_identity_v1(db, namespace=namespace,
                operation_kind=operation_kind, request=request, operation_id=operation_id,
                requested_activity_id=requested_activity_id)
            if value is not None:
                activity, effect, purpose = value.activity_id, value.effect_id, value.purpose
    if activity != requested_activity_id:
        raise ValueError("requested activity differs from the actual prepared/outcome original")
    return CurrentDomainCommandIdentityV1(activity, effect, purpose, requested_audience_ref)


@dataclass(frozen=True, slots=True)
class C04IndependentOriginalReadRequestV1:
    binding: object
    component_ref: str
    component_proof_digest: str | None
    terminal_receipt_ref: str | None
    terminal_receipt_digest: str | None


def read_independent_current_original_requests_v1(db, *, namespace, plan):
    """Return actual immutable C04 identities for W01's OUTSIDE-SQL RPC."""
    from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
    from .d11_c04_internal_cost import read_c04_cpu_cost_original_v1
    if not table_exists_v1(db, "graph_c04_internal_work_prepared_v1"):
        return ()
    from .current_life_numeric_metadata_v1 import read_numeric_c04_original_requests_v1
    handled,selected=read_numeric_c04_original_requests_v1(db,namespace,plan)
    if handled:return selected
    requested = set(plan.required_original_refs)
    rows = db.execute("SELECT operation_id FROM graph_c04_internal_work_prepared_v1 WHERE bot=? AND persona=? ORDER BY operation_id LIMIT 129",
                      namespace.as_tuple).fetchall()
    if len(rows) > 128:
        raise MissingProductionOriginalV1("bounded_c04_original_lookup")
    result = []
    for (operation,) in rows:
        prepared = read_c04_internal_work_prepared_v1(db, namespace, operation)
        component = "internal-work:component:" + prepared.binding.binding_digest
        cost = read_c04_cpu_cost_original_v1(db, namespace, operation)
        if component not in requested and (cost is None or cost.terminal_receipt_ref not in requested):
            continue
        result.append(C04IndependentOriginalReadRequestV1(prepared.binding, component,
            cost.proof_digest if cost else None, cost.terminal_receipt_ref if cost else None,
            cost.terminal_receipt_digest if cost else None))
    return tuple(result)


def rebuild_current_domain_stage_v1(db, *, frame, request, domain, operation_kind, installed_readers):
    """Reissue through the same exact installed registry used by the initial W01 stage."""
    from .domain_production_registry_v1 import installed_operation_v1,stage_installed_domain_operation_v1
    if not db.in_transaction:
        raise ValueError("domain stage reissuance requires W01's current business transaction")
    operation=installed_operation_v1(operation_kind)
    if operation.domain!=domain or type(request)is not operation.request_type:
        raise ValueError('current stage reissuance changed its exact registered domain/request')
    return stage_installed_domain_operation_v1(db,operation=operation,frame=frame,request=request,
        installed_readers=installed_readers)


def verify_current_domain_operation_stage_v1(db, *, frame, request, domain, operation_kind,
        installed_readers, stage):
    if operation_kind=='prepare_contact_prospective_v1':
        from .contact_prospective_v1 import verify_contact_prospective_stage_v1
        return verify_contact_prospective_stage_v1(db,frame=frame,request=request,installed_readers=installed_readers,stage=stage)
    current = rebuild_current_domain_stage_v1(db, frame=frame, request=request, domain=domain,
        operation_kind=operation_kind, installed_readers=installed_readers)
    if current != stage:
        raise ValueError("domain stage differs from independently reissued current originals")
    return current
