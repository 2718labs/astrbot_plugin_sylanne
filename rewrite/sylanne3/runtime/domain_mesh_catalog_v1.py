"""Fixed installed mesh recipes and actual consumers; this is not an event bus."""
from dataclasses import dataclass

from .personal_candidate_eligibility_v1 import PersonalMeshRouteV1, PERSONAL_MESH_ROUTES_V1
from .domain_mesh_contract_v1 import RECIPES


@dataclass(frozen=True, slots=True)
class SemanticRecipeOperationV1:
    recipe_version: str
    domain: str
    operation_kind: str
    purpose: str
    receiver: str
    message_kind: str
    consumer: str
    cold_entry: str
    final: bool = False
    wake: bool = False
    control: bool = False

    @property
    def route(self):
        if self.recipe_version == "foreground-projection.v1":
            kind = "outcome" if self.final else "evidenceNotice"
            return next(route for route in PERSONAL_MESH_ROUTES_V1 if route.kind == kind)
        return PersonalMeshRouteV1(self.domain, self.receiver, self.message_kind,
            self.operation_kind + ".mesh-locator.v1", self.purpose, self.recipe_version)


_WORLD = (
    SemanticRecipeOperationV1("world-history.v1", "d03", "relearn_world_assertion_v1",
        "context", "d07", "evidenceNotice", "registered_world_semantic_question",
        "observe_committed_world_v1"),
    SemanticRecipeOperationV1("world-history.v1", "d03", "adopt_world_assertion_v1",
        "context", "d07", "evidenceNotice", "registered_world_semantic_question",
        "observe_committed_world_v1"),
    SemanticRecipeOperationV1("world-history.v1", "d09", "project_world_perspective_v1",
        "context", "d09", "outcome", "current_world_perspective_expression",
        "observe_committed_world_v1", final=True),
)

_PREDICTION = tuple(SemanticRecipeOperationV1("prediction-conditioned.v1", domain, operation,
    "consolidation", receiver, kind, consumer, "observe_current_conditioned_self_recovery_v1",
    final=final) for domain, operation, receiver, kind, consumer, final in (
        ("d01", "register_calibration_policy_v1", "d01", "evidenceNotice", "current_conditioned_self_calibration", False),
        ("d07", "register_simulation_forecast_plan_v1", "d07", "evidenceNotice", "registered_simulation_forecast", False),
        ("d01", "register_condition_predicate_v1", "d07", "evidenceNotice", "current_condition_matching", False),
        ("d07", "register_current_prediction_v1", "d07", "evidenceNotice", "registered_prediction_observer", False),
        ("d07", "resolve_current_prediction_v1", "d01", "outcome", "current_conditioned_self_review", True),
        ("d07", "record_current_simulation_v1", "d07", "evidenceNotice", "current_prediction_discrepancy", True),
        ("d01", "review_current_conditioned_self_v1", "d12", "evidenceNotice", "explicit_owner_conditioned_adoption", True),
        ("d01", "adopt_current_conditioned_self_v1", "d08", "outcome", "current_conditioned_choice_recheck", True),
        ("d01", "rollback_current_conditioned_strategy_v1", "d08", "outcome", "current_conditioned_choice_recheck", True),
        ("d07", "match_current_conditioned_strategy_v1", "d08", "projectionResult", "current_conditioned_personal_selection", True),
        ("d08", "select_current_conditioned_personal_step_v1", "d08", "outcome", "actual_selected_action_qualification", True),
        ("d10", "project_current_conditioned_life_strategy_v1", "d10", "projectionResult", "current_habit_strategy_input", True),
    ))

_JOINT_HABIT = tuple(SemanticRecipeOperationV1("joint-habit.v1", domain, operation,
    "consolidation" if operation in ("adopt_habit_outcome_v1",
        "prepare_current_habit_source_note_action_v1","register_current_habit_source_note_life_plan_v1") else "context", receiver,
    kind, consumer, "observe_current_joint_habit_recovery_v1", final=final, wake=wake,
    control=control) for domain, operation, receiver, kind, consumer, final, wake, control in (
        ("d08", "adopt_long_term_plan_v1", "d08", "evidenceNotice", "current_joint_window_preparation", False, False, False),
        ("d08", "prepare_joint_window_v1", "d08", "projectionResult", "current_joint_window_terms", False, False, False),
        ("d08", "enter_current_joint_window_v1", "d08", "outcome", "current_joint_window_execution", False, False, False),
        ("d08", "finalize_current_joint_window_v1", "d08", "outcome", "current_joint_window_results", True, False, False),
        ("d08", "advance_long_term_window_v1", "d08", "outcome", "current_next_window_terms", True, False, False),
        ("d08", "pause_long_term_plan_v1", "d08", "evidenceNotice", "current_window_cancellation", True, False, True),
        ("d08", "resume_long_term_plan_v1", "d08", "evidenceNotice", "current_window_requalification", False, False, True),
        ("d08", "stop_long_term_plan_v1", "d08", "evidenceNotice", "current_window_cancellation", True, False, True),
        ("d08", "instantiate_current_habit_source_note_context_v1", "d08", "evidenceNotice",
            "habit_source_note_context_ready_requires_action", False, False, False),
        ("d08", "prepare_current_habit_source_note_action_v1", "d11", "evidenceNotice",
            "habit_source_note_action_requires_original_life", False, False, False),
        ("d10", "register_current_habit_source_note_life_plan_v1", "d11", "evidenceNotice",
            "habit_life_plan_requires_original_preparation", False, False, False),
        ("d10", "create_habit_policy_v1", "d11", "evidenceNotice", "actual_habit_subscription", False, False, False),
        ("d10", "revise_habit_policy_v1", "d11", "evidenceNotice", "actual_habit_subscription", False, False, True),
        ("d10", "pause_habit_policy_v1", "d11", "evidenceNotice", "actual_habit_subscription", True, False, True),
        ("d10", "resume_habit_policy_v1", "d11", "evidenceNotice", "actual_habit_subscription", False, False, True),
        ("d10", "stop_habit_policy_v1", "d11", "evidenceNotice", "actual_habit_subscription", True, False, True),
        ("d10", "register_habit_occurrence_v1", "d11", "evidenceNotice", "actual_habit_occurrence_qualification", False, True, False),
        ("d10", "qualify_habit_occurrence_v1", "d08", "outcome", "actual_habit_recipe_admission", False, False, False),
        ("d10", "record_habit_miss_v1", "d10", "outcome", "actual_habit_miss_disposition", True, False, False),
        ("d10", "adopt_habit_outcome_v1", "d10", "outcome", "actual_habit_progress_encoding_growth", True, False, False),
        ("d11", "record_habit_window_cue_v1", "d10", "evidenceNotice", "actual_habit_window_cue", True, True, False),
    ))

_FOREGROUND = (
    SemanticRecipeOperationV1("foreground-projection.v1", "d08",
        "prepare_personal_candidate_eligibility_v1", "consolidation", "d08", "evidenceNotice",
        "compute_registered_personal_projection_v1", "observe_current_personal_mesh_recovery_v1"),
    SemanticRecipeOperationV1("foreground-projection.v1", "d08",
        "adopt_personal_candidate_eligibility_v1", "consolidation", "d08", "outcome",
        "current_personal_candidate_eligibility", "observe_current_personal_mesh_recovery_v1", final=True),
)

SEMANTIC_RECIPE_OPERATIONS_V1 = (*_FOREGROUND, *_WORLD, *_JOINT_HABIT, *_PREDICTION)
DOMAIN_MESH_ROUTES_V1 = (*PERSONAL_MESH_ROUTES_V1, *tuple(p.route for p in
    (*_WORLD, *_JOINT_HABIT, *_PREDICTION)))


def require_semantic_recipe_operation_v1(recipe, operation_kind):
    found = tuple(p for p in SEMANTIC_RECIPE_OPERATIONS_V1 if
        (p.recipe_version, p.operation_kind) == (recipe, operation_kind))
    if len(found) != 1:
        raise ValueError("operation is not a fixed installed semantic companion producer")
    return found[0]


def require_mesh_request_v1(recipe, operation_kind, request):
    from .domain_production_registry_v1 import installed_operation_v1
    profile = require_semantic_recipe_operation_v1(recipe, operation_kind)
    operation = installed_operation_v1(operation_kind)
    if operation.domain != profile.domain or type(request) is not operation.request_type:
        raise TypeError("semantic recipe needs its actual registered producer request")
    return profile


def require_domain_mesh_route_v1(route):
    if type(route) is not PersonalMeshRouteV1 or route not in DOMAIN_MESH_ROUTES_V1:
        raise ValueError("unregistered exact sender/receiver/kind/schema/purpose route")
    return route


def semantic_wait_event_v1(recipe):
    rows = {
        "foreground-projection.v1": ("d11", "foreground_cycle_ready"),
        "world-history.v1": ("d03", "world_assertion_adopted"),
        "joint-habit.v1": ("d10", "actual_habit_progress_requires_outcome"),
        "prediction-conditioned.v1": ("d07", "prediction_resolved"),
    }
    if recipe not in RECIPES:
        raise ValueError("unregistered semantic wait recipe")
    return rows[recipe]
