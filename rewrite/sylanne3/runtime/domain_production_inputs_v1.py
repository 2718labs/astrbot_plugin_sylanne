"""Finite Owner input producers for the current domain product paths.

Explicit policies and unexecuted intents are allowed input. Completed trials,
consent and life facts still come only from the installed original readers.
The fixed descriptor below contains no callback. W01 first commits its actual
bundle row, then calls record_current_domain_input_after_commit_v1 in that same
transaction; a failure rolls back the entire command.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import json

from ..domains.d01.production_operations_v1 import plain_v1, require_locator_v1, stage_result_v1
from ..domains.d01 import PersonaDomain
from ..domains.d02 import BodyDomain
from ..domains.d02.body_quote_original import FixedBodyPolicyV1
from ..domains.d05.relationship import RelationshipProvider
from ..domains.d08.execution import Goal, GoalExecutionProvider
from ..domains.d10 import (
    ActivityRecipe, ContactPolicy, LifeDomain, LifeProject, ProactiveOpportunity,
    contact_policy_graph_write, proactive_opportunity_graph_write,
)
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, GraphWrite, Owner, NamespaceEpoch, owner_grant_key
from ..runtime_contracts import CommitReceipt, NamespaceId, QueryEpoch, canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1, raw_registered_input_v1, raw_head_value_v1
from .d02_production_operations_v1 import PassiveBodyPolicyV1, SettledBodyEffectPolicyV1, CompletedActionBodyComponentV1
from .d05_production_operations_v1 import InstalledRelationshipPolicyV1, BoundaryIntentOriginalV1
from ..domains.d05.relationship_revision_v2 import InstalledRelationshipPolicyV2
from .d08_production_operations_v1 import JointPlanIntentOriginalV1, PartyConsentEvidenceV1
from .d10_production_operations_v1 import RegisteredLifePlanV1, RegisteredLifeOutcomeV1, RegisteredOfflineIntervalV1
from .d11_life_contract_v1 import RegisteredLifePlanV2, RegisteredLifeOutcomeV2
from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
from .domain_production_contracts_v1 import ProductionPolicyRefV1, ProductionQueryCoverageV1, StagedDomainOperationV1
from .d07_execution_v1 import D07SemanticQuestionV1, D07RelationshipSemanticQuestionV2
from .d07_method_growth_semantic_v2 import D07MethodGrowthSemanticQuestionV2
from ..domains.d07 import SimulationRequest
from .d10_offline_inputs_v1 import (
    RegisterCurrentOfflineScheduleInputRequestV1, RegisterCurrentOfflineIntervalInputRequestV1,
    derive_current_offline_schedule_v1, derive_current_offline_interval_v1, record_current_offline_schedule_after_commit_v1,
)


from .d01_production_operations_v1 import (
    RegisterIdentityPlasticityPolicyRequestV3, RegisterIdentityTrialObserverPolicyRequestV3,
    PrepareSemanticGrowthInputRequestV3, StartSemanticGrowthTrialRequestV3,
    IDENTITY_INPUT_KINDS_V3, read_plan_identity_input_v3,
)


@dataclass(frozen=True, slots=True)
class FreezeCurrentValuesInputRequestV1:
    candidate_set_ref: str
    context_ref: str

    def __post_init__(self):
        require_locator_v1(self.candidate_set_ref, "candidate_set_ref")
        require_locator_v1(self.context_ref, "context_ref")


@dataclass(frozen=True, slots=True)
class PrepareCurrentGrowthInputRequestV1:
    interpretation_ref: str
    trigger_original_ref: str
    growth_proposal_ref: str
    counterevidence_query_ref: str
    required_trial_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DeriveCurrentGrowthTrialInputRequestV1:
    original_ref: str
    growth_proposal_ref: str
    settled_progress_ref: str


@dataclass(frozen=True, slots=True)
class InstallCurrentBodyInputRequestV1:
    policy: FixedBodyPolicyV1

    def __post_init__(self):
        if type(self.policy) is not FixedBodyPolicyV1:
            raise TypeError("body initialization needs the exact explicit policy")


@dataclass(frozen=True, slots=True)
class InstallCurrentPassiveBodyInputRequestV1:
    policy: PassiveBodyPolicyV1


@dataclass(frozen=True, slots=True)
class InstallCurrentBodyEffectInputRequestV1:
    policy: SettledBodyEffectPolicyV1


@dataclass(frozen=True, slots=True)
class RecordCurrentBodyComponentInputRequestV1:
    component: CompletedActionBodyComponentV1


@dataclass(frozen=True, slots=True)
class InstallCurrentRelationshipInputRequestV1:
    policy: InstalledRelationshipPolicyV1 | InstalledRelationshipPolicyV2


@dataclass(frozen=True, slots=True)
class RegisterCurrentBoundaryInputRequestV1:
    original_ref: str
    intent: BoundaryIntentOriginalV1


@dataclass(frozen=True, slots=True)
class RegisterCurrentJointPlanInputRequestV1:
    original_ref: str
    intent: JointPlanIntentOriginalV1


@dataclass(frozen=True, slots=True)
class RegisterCurrentPartyConsentInputRequestV1:
    original_ref: str
    evidence: PartyConsentEvidenceV1


@dataclass(frozen=True, slots=True)
class CreateCurrentGoalInputRequestV1:
    source_ref: str
    goal: Goal


@dataclass(frozen=True, slots=True)
class CreateCurrentLifeProjectInputRequestV1:
    source_ref: str
    project: LifeProject
    recipe: ActivityRecipe


@dataclass(frozen=True, slots=True)
class SetCurrentContactPolicyInputRequestV1:
    policy: ContactPolicy


@dataclass(frozen=True, slots=True)
class CreateCurrentContactOpportunityInputRequestV1:
    opportunity: ProactiveOpportunity


@dataclass(frozen=True, slots=True)
class RegisterCurrentLifePlanInputRequestV1:
    original_ref: str
    plan: RegisteredLifePlanV1


@dataclass(frozen=True, slots=True)
class RegisterCurrentLifeOutcomeInputRequestV1:
    original_ref: str
    outcome: RegisteredLifeOutcomeV1


@dataclass(frozen=True, slots=True)
class RegisterCurrentLifePlanInputRequestV2:
    original_ref: str
    plan: RegisteredLifePlanV2


@dataclass(frozen=True, slots=True)
class RegisterCurrentDraftFilePlanInputRequestV3:
    original_ref: str
    plan: RegisteredDraftFilePlanV3


@dataclass(frozen=True, slots=True)
class RegisterCurrentLifeOutcomeInputRequestV2:
    original_ref: str
    outcome: RegisteredLifeOutcomeV2


@dataclass(frozen=True, slots=True)
class RegisterCurrentSemanticQuestionInputRequestV1:
    original_ref: str
    question: D07SemanticQuestionV1 | D07RelationshipSemanticQuestionV2 | D07MethodGrowthSemanticQuestionV2


@dataclass(frozen=True, slots=True)
class RegisterCurrentSimulationInputRequestV1:
    original_ref: str
    simulation: SimulationRequest


from .d02_artifact_phase_price_v1 import RegisterCurrentArtifactPhasePricePolicyRequestV1
from .artifact_task_text_extent_v1 import RegisterArtifactTaskTextExtentRequestV1
from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2


@dataclass(frozen=True, slots=True)
class RegisterCurrentPhaseDraftFilePlanInputRequestV2:
    selector: ArtifactDraftPhaseSelectorV2

    def __post_init__(self):
        if type(self.selector) is not ArtifactDraftPhaseSelectorV2 or not self.selector.generation:
            raise TypeError("phase file registration accepts only its exact generation selector")


_PRODUCERS = {
    "register_artifact_task_text_extent": ("d08", RegisterArtifactTaskTextExtentRequestV1),
    "register_artifact_phase_price_policy": ("d02", RegisterCurrentArtifactPhasePricePolicyRequestV1),
    "freeze_values": ("d01", FreezeCurrentValuesInputRequestV1),
    "register_identity_plasticity_policy_v3": ("d01", RegisterIdentityPlasticityPolicyRequestV3),
    "register_identity_trial_observer_policy_v3": ("d01", RegisterIdentityTrialObserverPolicyRequestV3),
    "prepare_semantic_growth_input_v3": ("d01", PrepareSemanticGrowthInputRequestV3),
    "start_semantic_growth_trial_v3": ("d01", StartSemanticGrowthTrialRequestV3),
    "prepare_growth_input": ("d01", PrepareCurrentGrowthInputRequestV1),
    "derive_growth_trial": ("d01", DeriveCurrentGrowthTrialInputRequestV1),
    "initialize_body": ("d02", InstallCurrentBodyInputRequestV1),
    "install_passive_body_policy": ("d02", InstallCurrentPassiveBodyInputRequestV1),
    "install_body_effect_policy": ("d02", InstallCurrentBodyEffectInputRequestV1),
    "record_body_component": ("d02", RecordCurrentBodyComponentInputRequestV1),
    "install_relationship_policy": ("d05", InstallCurrentRelationshipInputRequestV1),
    "register_boundary_intent": ("d05", RegisterCurrentBoundaryInputRequestV1),
    "create_goal": ("d08", CreateCurrentGoalInputRequestV1),
    "register_joint_plan_intent": ("d08", RegisterCurrentJointPlanInputRequestV1),
    "register_party_consent": ("d08", RegisterCurrentPartyConsentInputRequestV1),
    "create_life_project": ("d10", CreateCurrentLifeProjectInputRequestV1),
    "set_contact_policy": ("d10", SetCurrentContactPolicyInputRequestV1),
    "create_contact_opportunity": ("d10", CreateCurrentContactOpportunityInputRequestV1),
    "register_life_plan": ("d10", RegisterCurrentLifePlanInputRequestV1),
    "register_life_outcome": ("d10", RegisterCurrentLifeOutcomeInputRequestV1),
    "register_life_plan_v2": ("d10", RegisterCurrentLifePlanInputRequestV2),
    "register_artifact_draft_plan_v3": ("d10", RegisterCurrentDraftFilePlanInputRequestV3),
    "register_artifact_phase_draft_plan_v2": ("d10", RegisterCurrentPhaseDraftFilePlanInputRequestV2),
    "register_life_outcome_v2": ("d10", RegisterCurrentLifeOutcomeInputRequestV2),
    "register_semantic_question": ("d07", RegisterCurrentSemanticQuestionInputRequestV1),
    "register_simulation": ("d07", RegisterCurrentSimulationInputRequestV1),
    "register_offline_schedule": ("d10", RegisterCurrentOfflineScheduleInputRequestV1),
    "register_offline_interval": ("d10", RegisterCurrentOfflineIntervalInputRequestV1),
}


@dataclass(frozen=True, slots=True)
class DomainInputProducerRegistrationV1:
    domain: str
    producer_kind: str
    request_type: type
    capability: str = "workbench.create"


@dataclass(frozen=True, slots=True)
class StagedDomainInputV1:
    registration: DomainInputProducerRegistrationV1
    request: object
    stage: StagedDomainOperationV1


def input_operation_for_request_v1(producer_kind):
    if type(producer_kind) is not str or producer_kind not in _PRODUCERS:
        raise ValueError("unregistered domain input producer")
    domain, request_type = _PRODUCERS[producer_kind]
    capability = ("d02.body_policy.install" if producer_kind == "initialize_body" else
        "workbench.activate" if producer_kind in {
            "install_passive_body_policy", "install_body_effect_policy",
            "install_relationship_policy", "set_contact_policy", "register_offline_schedule",
            "register_artifact_phase_price_policy", "register_identity_plasticity_policy_v3",
            "register_identity_trial_observer_policy_v3"} else "workbench.create")
    return DomainInputProducerRegistrationV1(domain, producer_kind, request_type, capability)


def _checked_request(producer_kind, request):
    registration = input_operation_for_request_v1(producer_kind)
    if type(request) is not registration.request_type:
        raise TypeError("domain input requires its exact registered request type")
    # Nested dataclass values must also match the declared installed schema;
    # callers cannot smuggle a dictionary under a typed outer request.
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    decoded = decode_typed_production_value_v1(plain_v1(request), registration.request_type)
    if decoded != request:
        raise ValueError("domain input does not round-trip through its exact schema")
    return registration


def read_plan_current_domain_input_v1(db, *, namespace, activity_id, producer_kind, request, installed_readers=None):
    registration = _checked_request(producer_kind, request)
    if producer_kind == "register_artifact_phase_draft_plan_v2":
        from .d11_life_product_adapter_v1 import read_plan_current_phase_draft_file_registration_v2
        return read_plan_current_phase_draft_file_registration_v2(db, namespace=namespace,
            activity_id=activity_id, request=request, installed_readers=installed_readers)
    if producer_kind == "register_artifact_phase_price_policy":
        from .domain_production_contracts_v1 import ProductionReadPlanV1
        return ProductionReadPlanV1((), (owner_grant_key(*namespace.as_tuple),), (),
            (request.policy_ref,) if request.expected_revision else ())
    if producer_kind in IDENTITY_INPUT_KINDS_V3:
        return read_plan_identity_input_v3(db,namespace=namespace,producer_kind=producer_kind,request=request)
    types, keys, roots, originals = [], [owner_grant_key(*namespace.as_tuple)], [], []
    persona = Owner("persona", *namespace.as_tuple)
    if registration.domain == "d01":
        types += ["d01.persona_activation.v1", "d01.persona_plan.v1"]
    if producer_kind == "freeze_values":
        types += ["d08.action_intent.v1", "d07.attention_ticket.v1", "d03.world_event", "d03.role_binding",
            "d08.personal_plan.v1", "d08.goal.v1", "d07.current_interpretation.v1"]
        from .d01_production_operations_v1 import method_condition_read_inputs_v1
        plan_rows = db.execute("SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d08.personal_plan.v1' AND valid=1 ORDER BY token LIMIT 129", namespace.as_tuple).fetchall()
        if len(plan_rows) > 128:
            raise MissingProductionOriginalV1("complete_current_method_plan_inventory")
        goal_keys = []
        for token, encoded in plan_rows:
            plan_value = json.loads(encoded)
            if plan_value["state"] == "active" and plan_value.get("method_candidates"):
                keys.append(AtomKey.from_token(token))
                goal_keys.append(AtomKey.from_token(plan_value["goal_ref"]))
                roots.extend(plan_value["source_refs"])
        keys.extend(goal_keys)
        condition_keys, condition_roots, condition_originals = method_condition_read_inputs_v1(db, namespace, tuple(goal_keys))
        keys.extend(condition_keys)
        roots.extend(condition_roots)
        originals.extend(condition_originals)
    elif producer_kind == "prepare_growth_input":
        keys.append(AtomKey.from_token(request.interpretation_ref))
        types.append("d07.current_interpretation.v1")
        originals += [request.interpretation_ref, request.trigger_original_ref, *request.required_trial_refs]
    elif producer_kind == "derive_growth_trial":
        key = AtomKey.from_token(request.settled_progress_ref)
        if key.type_name not in {"d10.life_progress.v1", "d08.action_outcome.v1"}:
            raise ValueError("growth trial must name actual adopted life progress or settled action outcome")
        keys.append(key)
        originals += [request.growth_proposal_ref, request.settled_progress_ref]
        intent=raw_registered_input_v1(db,"graph_d01_production_inputs_v1",namespace,request.growth_proposal_ref)
        if intent and intent.get("schema")=="d01.growth-intent.v2":
            originals.extend((intent["plasticity_policy_ref"],intent["observer_policy_ref"]))
            rows=db.execute("SELECT original_ref,payload_json FROM graph_d01_production_inputs_v1 WHERE bot=? AND persona=? "
                "AND kind='identity_trial_start_v3' ORDER BY original_ref LIMIT 129",namespace.as_tuple).fetchall()
            if len(rows)>128:raise MissingProductionOriginalV1("bounded_deep_identity_trial_inventory")
            for ref,encoded in rows:
                start=json.loads(encoded)
                if (start["growth_proposal_ref"],start["completed_trial_ref"])==(request.growth_proposal_ref,request.original_ref):
                    originals.append(ref);keys.append(AtomKey.from_token(start["planned_progress_ref"]))
        actual = raw_head_value_v1(db, namespace, key)
        if actual:
            if key.type_name == "d10.life_progress.v1":
                from .d10_life_progress_provenance_v1 import life_progress_auxiliary_key_v1,PROVENANCE_TYPE,ELIGIBILITY_TYPE
                keys.extend(life_progress_auxiliary_key_v1(key,kind) for kind in (PROVENANCE_TYPE,ELIGIBILITY_TYPE))
                from .d10_life_progress_provenance_v1 import life_progress_current_read_inputs_v1
                current_keys,current_roots,current_originals=life_progress_current_read_inputs_v1(db,namespace,key.token)
                keys.extend(current_keys);roots.extend(current_roots);originals.extend(current_originals)
                roots += list(actual["source_refs"])
                originals += list(actual["receipt_refs"])
                types.append("d02.settlement.v1")
            else:
                types.append("d08.action_intent.v1")
                originals += list(actual["observation_refs"])
                for action_ref, encoded in db.execute("SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? "
                        "AND type_name='d08.action_intent.v1' AND valid=1 ORDER BY token LIMIT 129", namespace.as_tuple).fetchall():
                    action = json.loads(encoded)
                    if (action["action_id"], action["identity"]["effect_id"], action["identity"]["attempt_id"]) == (
                            actual["action_id"], actual["effect_id"], actual["attempt_id"]):
                        roots += list(action["source_refs"])
                        keys.append(AtomKey.from_token(action_ref))
                        for cost_ref, cost_json in db.execute("SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? "
                                "AND type_name='runtime.cost_settlement' AND valid=1 ORDER BY token LIMIT 129", namespace.as_tuple).fetchall():
                            cost = json.loads(cost_json)
                            if (cost["activity_id"], cost["effect_id"]) == (action["identity"]["activity_id"], actual["effect_id"]):
                                originals.append(cost_ref)
        types.append("runtime.cost_settlement")
    elif producer_kind == "initialize_body":
        if request.policy.profile.namespace != namespace:
            raise ValueError("body input namespace differs from the real Owner")
        keys += [BodyDomain.profile_write(request.policy.profile).key, BodyDomain.state_write(namespace, request.policy.initial_state).key]
    elif producer_kind in {"install_passive_body_policy", "install_body_effect_policy"}:
        if request.policy.namespace != namespace:
            raise ValueError("body policy namespace differs from real Owner")
        keys += [AtomKey(persona, "d02.body_profile.v1", request.policy.profile_id), AtomKey(persona, "d02.body_state.v1", request.policy.profile_id)]
    elif producer_kind == "record_body_component":
        component = request.component
        keys += [AtomKey.from_token(getattr(component, name)) for name in ("action_intent_ref", "action_outcome_ref", "reservation_ref", "settlement_ref")]
        originals += [component.observation_ref, *component.paid_cost_refs]
    elif producer_kind == "install_relationship_policy":
        if request.policy.namespace != namespace:
            raise ValueError("relationship policy namespace differs from real Owner")
        if type(request.policy) is InstalledRelationshipPolicyV2:
            roots.extend(request.policy.policy_source_refs)
            roots.extend(rule.authored_prior_source_ref for rule in request.policy.dimension_rules if rule.authored_prior_source_ref is not None)
    elif producer_kind == "register_boundary_intent":
        keys.append(AtomKey.from_token(request.intent.boundary_ref))
        roots += list(request.intent.next_rule.source_refs)
        keys += [AtomKey.from_token(ref) for ref in request.intent.acceptance_interpretation_refs]
        originals += [*request.intent.acceptance_interpretation_refs, *request.intent.outbound_receipt_refs]
        types += ["d03.entity_anchor", "d03.account_binding", "d05.boundary_rule"]
    elif producer_kind == "create_goal":
        roots.append(request.source_ref)
        keys.append(AtomKey(Owner("activity", *namespace.as_tuple, activity_id), "d08.goal.v1", request.goal.goal_id))
    elif producer_kind == "register_joint_plan_intent":
        roots += list(request.intent.source_refs)
        keys += [AtomKey.from_token(ref) for ref in request.intent.current_goal_refs]
        types += ["d03.entity_anchor"]
    elif producer_kind == "register_party_consent":
        keys.append(AtomKey.from_token(request.evidence.acceptance_interpretation_ref))
        roots.append(request.evidence.inbound_source_ref)
        originals += [request.evidence.plan_proposal_ref, request.evidence.acceptance_interpretation_ref, *request.evidence.outbound_receipt_refs]
        types += ["d03.entity_anchor", "d03.account_binding"]
    elif producer_kind == "create_life_project":
        roots.append(request.source_ref)
        keys += [AtomKey(persona, "d10.life_project.v1", request.project.project_id), AtomKey(persona, "d10.activity_recipe.v1", request.recipe.recipe_id)]
    elif producer_kind == "set_contact_policy":
        keys.append(AtomKey(persona, "d10.contact_policy.v1", request.policy.policy_id))
    elif producer_kind == "create_contact_opportunity":
        roots.append(request.opportunity.source_ref)
        keys.append(AtomKey(persona, "d10.proactive_opportunity.v1", request.opportunity.opportunity_id))
        originals.append(request.opportunity.opportunity_id)
        types += ["d03.entity_anchor", "d03.account_binding"]
    elif producer_kind in {"register_life_plan_v2", "register_artifact_draft_plan_v3"}:
        from .d11_life_product_adapter_v1 import life_plan_read_inputs_v1
        return life_plan_read_inputs_v1(db, namespace=namespace, plan=request.plan)
    elif producer_kind == "register_life_outcome_v2":
        from .d11_life_product_adapter_v1 import life_outcome_read_plan_v2
        return life_outcome_read_plan_v2(db, namespace=namespace, activity_id=activity_id,
            outcome=request.outcome, original_ref=request.original_ref)
    elif producer_kind == "register_life_plan":
        keys += [AtomKey.from_token(getattr(request.plan, name)) for name in ("project_ref", "recipe_ref", "action_intent_ref")]
        roots.append(request.plan.start_source_ref)
        originals.append(request.plan.start_source_ref)
        action = raw_head_value_v1(db, namespace, AtomKey.from_token(request.plan.action_intent_ref))
        if action:
            roots += list(action["source_refs"])
    elif producer_kind == "register_life_outcome":
        keys.append(AtomKey.from_token(request.outcome.action_outcome_ref))
        roots.append(request.outcome.terminal_source_ref)
        originals += [request.outcome.plan_original_ref, request.outcome.actual_terminal_ref, *request.outcome.paid_cost_refs]
        if request.outcome.artifact_ref is not None:
            originals.append(request.outcome.artifact_ref)
        plan = raw_registered_input_v1(db, "graph_d10_production_inputs_v1", namespace, request.outcome.plan_original_ref)
        if plan:
            keys += [AtomKey.from_token(plan[name]) for name in ("project_ref", "recipe_ref", "action_intent_ref")]
            roots.append(plan["start_source_ref"])
            originals.append(plan["start_source_ref"])
            from ..domains.d02.production_operations_v1 import ApplyCurrentBodyEffectRequestV1
            from .d02_production_operations_v1 import read_plan_current_d02_operation_v1
            body_plan = read_plan_current_d02_operation_v1(db, namespace=namespace, activity_id=activity_id,
                operation_kind="apply_body_effect", request=ApplyCurrentBodyEffectRequestV1(**plan["body_effect_request"]))
            types += list(body_plan.fixed_type_ids)
            keys += list(body_plan.exact_keys)
            roots += list(body_plan.source_roots)
            originals += list(body_plan.required_original_refs)
        actual = raw_head_value_v1(db, namespace, AtomKey.from_token(request.outcome.action_outcome_ref))
        if actual:
            originals += list(actual["observation_refs"])
    elif producer_kind == "register_semantic_question":
        try:
            keys.append(AtomKey.from_token(request.question.target_ref.ref))
        except (ValueError, TypeError):
            originals.append(request.question.target_ref.ref)
            target = raw_registered_input_v1(db, "graph_d08_joint_plan_intents_v1", namespace, request.question.target_ref.ref)
            if target:
                roots += list(target["source_refs"])
                keys += [AtomKey.from_token(ref) for ref in target["current_goal_refs"]]
        roots += list(request.question.source_refs)
        if type(request.question) is D07RelationshipSemanticQuestionV2:
            keys.append(request.question.cycle_ref.key)
            keys.append(AtomKey.from_token(request.question.trigger_original_ref))
            from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
            from .jobs import get_job
            cycle = foreground_cycle_from_wire_v1(get_job(db, request.question.cycle_ref.key.name).continuation)
            keys.append(AtomKey.from_token(cycle.source_ref))
            policy = db.execute("SELECT payload_json FROM graph_d05_production_policies_v1 WHERE bot=? AND persona=? AND policy_ref=? AND revision=?",
                (*namespace.as_tuple, request.question.policy_ref, request.question.policy_revision)).fetchone()
            if policy:
                roots.extend(json.loads(policy[0])["policy_source_refs"])
        elif type(request.question) is D07MethodGrowthSemanticQuestionV2:
            keys.extend((request.question.cycle_ref.key, request.question.proposal_head.key, request.question.source_head.key))
            originals.extend((request.question.proposal_head.key.token, request.question.c02_operation_id))
    elif producer_kind == "register_simulation":
        roots += list(request.simulation.snapshot_refs)
    elif producer_kind == "register_offline_schedule":
        from .d11_role_clock_installation_v1 import role_clock_mapping_id_v1
        originals.append(role_clock_mapping_id_v1(namespace))
    elif producer_kind == "register_offline_interval":
        from .d11_offline_originals_v1 import TABLE
        originals += [request.schedule_ref, request.disconnect_original_ref, request.reconnect_original_ref]
        for ref in (request.disconnect_original_ref, request.reconnect_original_ref):
            row = db.execute("SELECT payload_json FROM " + TABLE + " WHERE bot=? AND persona=? AND original_ref=?",
                (*namespace.as_tuple, ref)).fetchone()
            if row:
                roots.append(json.loads(row[0])["source_ref"])
        row = db.execute("SELECT payload_json FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='registered_schedule' AND original_ref=?",
            (*namespace.as_tuple, request.schedule_ref)).fetchone()
        if row:
            schedule = json.loads(row[0])
            originals += [schedule["clock_mapping_ref"], schedule["recipe_ref"]]
    # Fixed inventories and referenced typed heads provide their real source
    # roots. This expansion only plans reads; the installed issuer qualifies
    # the resulting current family in the stage/record functions below.
    for type_name in types:
        rows = db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? AND valid=1 ORDER BY token LIMIT 129",
                          (*namespace.as_tuple, type_name)).fetchall()
        if len(rows) > 128:
            raise MissingProductionOriginalV1("complete_input_inventory:" + type_name,
                continuation="input-query:" + canonical_digest((namespace, type_name))[:48])
        for (encoded,) in rows:
            value = json.loads(encoded)
            refs = tuple(value.get("source_refs", value.get("creation_evidence_refs", ())))
            if producer_kind == "freeze_values" and type_name in {"d07.current_interpretation.v1", "d08.personal_plan.v1", "d08.goal.v1"}:
                continue
            if producer_kind == "freeze_values" and (type_name == "d03.role_binding"
                    or type_name == "d03.world_event" and not set(refs) <= set(roots)):
                continue
            roots += list(refs)
    for key in tuple(keys):
        row = db.execute("SELECT value FROM graph_atoms WHERE token=? AND bot=? AND persona=? AND valid=1", (key.token, *namespace.as_tuple)).fetchone()
        if row:
            value = json.loads(row[0])
            roots += list(value.get("source_refs", ()))
    return production_read_plan_v1(types, keys, roots, originals)


def stage_current_domain_input_v1(db, *, frame, producer_kind, request, installed_readers):
    registration = _checked_request(producer_kind, request)
    if producer_kind == "register_artifact_task_text_extent":
        from .artifact_task_text_extent_v1 import stage_register_artifact_task_text_extent_v1
        return StagedDomainInputV1(registration, request,
            stage_register_artifact_task_text_extent_v1(db, frame=frame, request=request,
                installed_readers=installed_readers))
    if producer_kind == "register_artifact_phase_price_policy":
        from .d02_artifact_phase_price_v1 import stage_register_current_artifact_phase_price_policy_in_transaction_v1
        stage = stage_register_current_artifact_phase_price_policy_in_transaction_v1(db, frame=frame,
            request=request, installed_readers=installed_readers)
        return StagedDomainInputV1(registration, request, stage)
    if producer_kind == "register_artifact_phase_draft_plan_v2":
        from .d11_life_product_adapter_v1 import derive_current_phase_draft_file_plan_v2
        from .d01_production_operations_v1 import waiting_stage_v1
        try:
            derive_current_phase_draft_file_plan_v2(db, frame=frame, request=request, installed_readers=installed_readers)
            stage = stage_result_v1(frame, "d10", "input:" + producer_kind, request,
                provenance={"producer_kind": producer_kind, "input_request_digest": canonical_digest(plain_v1(request))})
        except MissingProductionOriginalV1 as missing:
            stage = waiting_stage_v1(frame, "d10", "input:" + producer_kind, request, missing)
        return StagedDomainInputV1(registration, request, stage)
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns, writes = frame.envelope.authority.namespace, ()
    policy_original = None
    schema = registration.domain + ".proposal.v1"
    if producer_kind in {"register_identity_plasticity_policy_v3","register_identity_trial_observer_policy_v3"}:
        installed_readers.validate_identity_policy_registration_v3(db,frame,request.policy)
    elif producer_kind == "start_semantic_growth_trial_v3":
        installed_readers.validate_semantic_trial_start_v3(db,frame,request)
    elif producer_kind == "prepare_semantic_growth_input_v3":
        installed_readers._identity_policy_v3(db,read,request.plasticity_policy_ref,require_growth=True)
        read.head(db,request.interpretation_ref,required=True)
        read.original(request.trigger_original_ref)
    elif producer_kind == "initialize_body":
        policy = request.policy
        if policy.profile.namespace != ns:
            raise ValueError("body initialization namespace differs")
        if any(read.head(db, key).revision != 0 for key in (
                BodyDomain.profile_write(policy.profile).key, BodyDomain.state_write(ns, policy.initial_state).key)):
            raise ValueError("body initialization cannot replace an existing body")
        writes = (BodyDomain.profile_write(policy.profile), BodyDomain.state_write(ns, policy.initial_state))
    elif producer_kind == "create_goal":
        read.source_family(db, (request.source_ref,))
        if request.goal.revision != 1 or request.goal.state != "active" or request.source_ref not in request.goal.reason_refs:
            raise ValueError("goal input must be a real source-bound unexecuted active goal")
        key = AtomKey(Owner("activity", *ns.as_tuple, frame.envelope.identity.activity_id), "d08.goal.v1", request.goal.goal_id)
        if read.head(db, key).revision != 0:
            raise ValueError("goal input requires a genuinely absent goal")
        writes = (GraphWrite(key, plain_v1(request.goal), (AtomKey.from_token(request.source_ref),)),)
    elif producer_kind == "create_life_project":
        if request.project.namespace != ns or request.project.next_step not in request.recipe.allowed_steps:
            raise ValueError("life plan input project/recipe differs")
        read.source_family(db, (request.source_ref,))
        owner = Owner("persona", *ns.as_tuple)
        project = {name: value for name, value in plain_v1(request.project).items() if name != "namespace"}
        writes = (GraphWrite(AtomKey(owner, "d10.life_project.v1", request.project.project_id), project, (AtomKey.from_token(request.source_ref),)),
            GraphWrite(AtomKey(owner, "d10.activity_recipe.v1", request.recipe.recipe_id), plain_v1(request.recipe), (AtomKey.from_token(request.source_ref),)))
        if any(read.head(db, write.key).revision != 0 for write in writes):
            raise ValueError("new life project/recipe cannot overwrite current heads")
    elif producer_kind == "set_contact_policy":
        policy = request.policy
        if policy.namespace != ns:
            raise ValueError("contact policy namespace differs")
        key = AtomKey(Owner("persona", *ns.as_tuple), "d10.contact_policy.v1", policy.policy_id)
        existing = read.head(db, key)
        if existing.valid and existing.revision and existing.value["version"] >= policy.version:
            raise ValueError("contact setting version is stale")
        grant = read.head(db, owner_grant_key(*ns.as_tuple), required=True)
        from ..authority_service.d10_contact_policy_service_v1 import D10ContactPolicyOriginalV1
        policy_original = getattr(installed_readers, "contact_policy_original", None)
        if (type(policy_original) is not D10ContactPolicyOriginalV1 or policy_original.action != "issue"
                or policy_original.policy != policy
                or policy_original.owner_actor_id != frame.envelope.authority.actor
                or policy_original.authority_id != grant.value["authority_id"]
                or policy_original.installation_id != grant.value["installation_id"]
                or policy_original.owner_authorization_revision != grant.revision):
            raise ValueError("contact policy has no actual current Owner-session issuance")
        read.original(policy_original.original_ref, kind="d10.owner_contact_policy", digest=policy_original.digest)
        writes = (contact_policy_graph_write(policy, owner_grant_revision=grant.revision,
            approval_ref=policy_original.original_ref,
            approval_authority_id=grant.value["authority_id"], installation_id=grant.value["installation_id"]),)
    elif producer_kind == "create_contact_opportunity":
        opportunity = request.opportunity
        if opportunity.namespace != ns:
            raise ValueError("opportunity namespace differs")
        source = read.head(db, opportunity.source_ref, required=True)
        read.source_family(db, (opportunity.source_ref,))
        targets = tuple(atom for atom in read.complete_inventory(db, "d03.entity_anchor")
            if atom.valid and atom.value["entity_id"] == opportunity.subject_ref
            and atom.value["status"] == "active")
        if len(targets) != 1:
            raise MissingProductionOriginalV1("current_contact_target_entity")
        from ..memory_types import access_key
        access = read.head(db, access_key(*ns.as_tuple, source.key.owner.subject), required=True)
        writes = (proactive_opportunity_graph_write(opportunity, source_revision=source.revision, access_revision=access.revision),)
        if read.head(db, writes[0].key).revision != 0:
            raise ValueError("new opportunity cannot overwrite an adopted opportunity")
    elif producer_kind == "register_offline_schedule":
        derive_current_offline_schedule_v1(db, frame=frame, request=request, issuer=installed_readers.issuer)
    elif producer_kind == "register_offline_interval":
        derive_current_offline_interval_v1(db, frame=frame, request=request, readers=installed_readers)
    from ..domains.d07 import D07DomainProvider
    providers = {"d01": PersonaDomain(), "d07": D07DomainProvider(),
        "d02": BodyDomain(), "d05": RelationshipProvider(), "d08": GoalExecutionProvider(), "d10": LifeDomain()}
    provider = providers[registration.domain]
    provenance = {"producer_kind": producer_kind, "input_request_digest": canonical_digest(plain_v1(request))}
    if policy_original is not None:
        provenance["owner_contact_policy_original"] = plain_v1(policy_original)
    stage = stage_result_v1(frame, registration.domain, "input:" + producer_kind, request, writes=writes,
        provenance=provenance,
        proposal_schema=schema, proposal_hash=provider.descriptor.request_schema_hash)
    for proposal in stage.proposals:
        specs = {spec.name: spec for spec in (provider.register_types() if registration.domain == "d08" else provider.type_specs())}
        for write in proposal.typed_writes:
            spec = specs[write.key.type_name]
            if write.key.owner.kind not in spec.owner_kinds:
                raise ValueError("Owner input contains another registered write owner")
            spec.validator(write.value)
    return StagedDomainInputV1(registration, request, stage)


def _post_commit_frame(db, frame, request, *, _successor_v3=None):
    """Read real post-CAS heads/epoch; never assume a synthetic +1 receipt."""
    ns = frame.envelope.authority.namespace
    if _successor_v3 is not None:
        from .current_method_learning_read_v3 import PreparedMethodPostCommitV3
        if type(_successor_v3) is not PreparedMethodPostCommitV3:
            raise TypeError("actual Method post-commit successor required")
        snapshot, coverage = _successor_v3.snapshot_and_coverage_v3(frame)
        epoch = snapshot.epochs[0]
    else:
        row = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
        if row is None:
            raise ValueError("input producer lost its actual post-commit namespace epoch")
        epoch = NamespaceEpoch(*ns.as_tuple, row[0])
        atoms = []
        for prior in frame.snapshot.atoms:
            current = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?", (prior.key.token, *ns.as_tuple)).fetchone()
            atoms.append(GraphAtom(prior.key, current[0], json.loads(current[1]), bool(current[2])) if current else GraphAtom(prior.key, 0, {}, False))
        snapshot = GraphSnapshot(tuple(atoms), (epoch,))
        coverage = []
        for page in frame.query_coverage:
            rows = db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129",
                              (*ns.as_tuple, page.type_id)).fetchall()
            if len(rows) > 128:
                raise ValueError("input producer post-CAS scope unexpectedly became incomplete")
            coverage.append(ProductionQueryCoverageV1(QueryEpoch(ns, page.epoch.scope_ref, epoch.revision), page.type_id,
                tuple(GraphVersion(AtomKey.from_token(ref), rev) for ref, rev in rows), True, None))
    policies = list(frame.installed_policy_refs)
    policy = getattr(request, "policy", None)
    if type(policy) in {PassiveBodyPolicyV1, SettledBodyEffectPolicyV1, InstalledRelationshipPolicyV1, InstalledRelationshipPolicyV2}:
        policies = [item for item in policies if not (item.policy_ref == policy.policy_ref and item.revision == policy.revision)]
        policies.append(ProductionPolicyRefV1(policy.policy_ref, policy.revision, canonical_digest(plain_v1(policy))))
    envelope = replace(frame.envelope, version_guard=replace(frame.envelope.version_guard,
        read_versions=snapshot.versions, query_epochs=(QueryEpoch(ns, "namespace", epoch.revision),)))
    return replace(frame, envelope=envelope, snapshot=snapshot, query_coverage=tuple(coverage), installed_policy_refs=tuple(policies))


def record_current_domain_input_after_commit_v1(db, *, frame, staged_input, actual_receipt, installed_readers):
    if type(staged_input) is not StagedDomainInputV1 or type(actual_receipt) is not CommitReceipt:
        raise TypeError("fixed internal input descriptor required")
    registration, request, stage = staged_input.registration, staged_input.request, staged_input.stage
    if (_checked_request(registration.producer_kind, request) != registration or stage.operation_id != actual_receipt.operation_id
            or actual_receipt.status != "committed" or stage.activity_id != actual_receipt.activity_id
            or stage.namespace != frame.envelope.authority.namespace):
        raise ValueError("input descriptor differs from its actual committed operation")
    actual = db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?", (*stage.namespace.as_tuple, stage.operation_id)).fetchone()
    if actual != (actual_receipt.operation_digest, actual_receipt.activity_id, actual_receipt.effect_id, actual_receipt.commit_seq):
        raise ValueError("Owner input receipt does not match its actual same-transaction bundle original")
    CurrentDomainReadV1(frame).committed_operation(db, actual_receipt.operation_id)
    frame = _post_commit_frame(db, frame, request)
    kind, operation = registration.producer_kind, actual_receipt.operation_id
    if kind in {"register_identity_plasticity_policy_v3","register_identity_trial_observer_policy_v3"}:
        return (installed_readers.register_identity_policy_after_commit_v3(db,frame=frame,
            producing_operation_id=operation,policy=request.policy),)
    if kind == "prepare_semantic_growth_input_v3":
        return installed_readers.freeze_semantic_growth_after_commit_v3(db,frame=frame,
            producing_operation_id=operation,request=request)
    if kind == "start_semantic_growth_trial_v3":
        return (installed_readers.start_semantic_trial_after_commit_v3(db,frame=frame,
            producing_operation_id=operation,request=request),)
    if kind == "freeze_values":
        return installed_readers.freeze_current_values_from_graph_v1(db, frame=frame,
            producing_operation_id=operation, candidate_set_ref=request.candidate_set_ref, context_ref=request.context_ref)
    if kind == "prepare_growth_input":
        return installed_readers.freeze_current_growth_from_interpretation_v1(db, frame=frame,
            producing_operation_id=operation, **plain_v1(request))
    if kind == "derive_growth_trial":
        return (installed_readers.derive_current_growth_trial_from_adopted_progress_v1(db,
            frame=frame, producing_operation_id=operation, original_ref=request.original_ref,
            growth_proposal_ref=request.growth_proposal_ref, settled_progress_ref=request.settled_progress_ref),)
    if kind == "register_artifact_task_text_extent":
        return ()  # Its signed original follows actual generic adoption below.
    if kind == "register_artifact_phase_price_policy":
        from .d02_artifact_phase_price_v1 import record_current_artifact_phase_price_policy_after_commit_v1
        return record_current_artifact_phase_price_policy_after_commit_v1(db, frame=frame,
            request=request, stage=stage, actual_receipt=actual_receipt, installed_readers=installed_readers)
    if kind == "initialize_body":
        installed_readers.body_quote_authority.install_policy(db, request.policy)
        return ()
    if kind in {"install_passive_body_policy", "install_body_effect_policy", "install_relationship_policy"}:
        installed_readers.install_policy(db, frame=frame, policy=request.policy)
        return ()
    if kind == "record_body_component":
        return (installed_readers.record_current_action_body_component_v1(db, frame=frame,
            producing_operation_id=operation, component=request.component),)
    if kind == "register_boundary_intent":
        return (installed_readers.record_boundary_intent(db, frame=frame, original_ref=request.original_ref,
            producing_operation_id=operation, intent=request.intent),)
    if kind == "register_joint_plan_intent":
        return (installed_readers.record_joint_plan_intent(db, frame=frame, original_ref=request.original_ref,
            producing_operation_id=operation, intent=request.intent),)
    if kind == "register_party_consent":
        return (installed_readers.record_party_consent(db, frame=frame, original_ref=request.original_ref,
            producing_operation_id=operation, evidence=request.evidence),)
    if kind == "register_life_plan":
        return (installed_readers.record_current_life_plan_v1(db, frame=frame, original_ref=request.original_ref,
            producing_operation_id=operation, plan=request.plan),)
    if kind == "register_artifact_phase_draft_plan_v2":
        from .d11_life_product_adapter_v1 import derive_current_phase_draft_file_plan_v2, artifact_phase_draft_plan_ref_v2
        from .d11_life_preparation_v1 import record_registered_life_plan_v2
        from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
        plan = derive_current_phase_draft_file_plan_v2(db, frame=frame, request=request, installed_readers=installed_readers)
        graph = installed_readers.role_clock_reader.graph
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        build = read_installed_d11_life_build_v1(assembly.package_root,
            assembly.installation_policy.manifest_digest, recipe_id=plan.recipe_id)
        return (record_registered_life_plan_v2(db, frame=frame, issuer=installed_readers.issuer,
            original_ref=artifact_phase_draft_plan_ref_v2(request.selector), producing_operation_id=operation,
            plan=plan, installed_build=build, body_quote_authority=graph._GraphCoordinator__body_quote_authority),)
    if kind in {"register_life_plan_v2", "register_artifact_draft_plan_v3"}:
        from .d11_life_preparation_v1 import record_registered_life_plan_v2
        from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
        assembly = installed_readers.role_clock_reader.graph._GraphCoordinator__d04_installed_joint_assembly
        build = read_installed_d11_life_build_v1(assembly.package_root,
            assembly.installation_policy.manifest_digest, recipe_id=request.plan.recipe_id)
        return (record_registered_life_plan_v2(db, frame=frame, issuer=installed_readers.issuer,
            original_ref=request.original_ref, producing_operation_id=operation, plan=request.plan, installed_build=build,
            body_quote_authority=installed_readers.role_clock_reader.graph._GraphCoordinator__body_quote_authority),)
    if kind == "register_life_outcome_v2":
        from .d10_life_outcome_v2 import record_current_life_outcome_v2
        return (record_current_life_outcome_v2(db, frame=frame, issuer=installed_readers.issuer,
            original_ref=request.original_ref, producing_operation_id=operation, outcome=request.outcome),)
    if kind == "register_life_outcome":
        return (installed_readers.record_current_life_outcome_v1(db, frame=frame, original_ref=request.original_ref,
            producing_operation_id=operation, outcome=request.outcome),)
    if kind == "register_semantic_question":
        from .d07_execution_v1 import record_current_d07_semantic_question_in_transaction_v1
        return (record_current_d07_semantic_question_in_transaction_v1(
            db, installed_readers.issuer, frame, request.original_ref, request.question),)
    if kind == "register_simulation":
        from .d07_execution_v1 import record_registered_simulation_request_in_transaction_v1
        return (record_registered_simulation_request_in_transaction_v1(
            db, installed_readers.issuer, frame, request.original_ref, request.simulation),)
    if kind == "register_offline_schedule":
        return record_current_offline_schedule_after_commit_v1(db, frame=frame, request=request,
            readers=installed_readers, operation_id=operation)
    if kind == "register_offline_interval":
        interval = derive_current_offline_interval_v1(db, frame=frame, request=request, readers=installed_readers)
        return (installed_readers.record_offline_interval_v1(db, frame=frame,
            producing_operation_id=operation, interval=interval),)
    # The remaining fixed inputs consist entirely of actual adopted typed
    # graph writes; the shared receipt is already their durable original.
    if kind in {"create_goal", "create_life_project", "set_contact_policy", "create_contact_opportunity"}:
        return ()
    raise ValueError("unregistered input producer completion")


def rebuild_current_domain_input_v1(db, *, frame, producer_kind, request, installed_readers):
    return stage_current_domain_input_v1(db, frame=frame, producer_kind=producer_kind,
                                        request=request, installed_readers=installed_readers)
