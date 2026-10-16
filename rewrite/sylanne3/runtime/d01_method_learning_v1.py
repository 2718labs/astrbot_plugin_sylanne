"""Current D01 trial/evaluation/adoption operations; all state remains in Graph.

Method observations are independent installed D11 originals. Owner registration,
files existing, and C5/C6 prose do not manufacture measured method benefit.
"""
from dataclasses import dataclass, replace
import json

from ..domains.d01 import PersonaDomain, GrowthProposal, method_policy_state_v1
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d01.method_learning_v1 import (MethodEvaluationProtocolV1, MethodScopedTrialV1,
    MethodTrialProposalV2, MethodBlindReviewRequestV2, MethodBlindResponseV2, TRIAL_PROPOSAL_TYPE_V2, BLIND_REQUEST_TYPE_V2,
    MethodExperimentPlanV1, MethodComparisonObservationV1, MethodComparisonObservationV2, MethodBlindReviewV1, MethodEvaluationV1,
    MethodOutcomeReviewV1, PROTOCOL_TYPE, TRIAL_TYPE, EXPERIMENT_TYPE, EVALUATION_TYPE, REVIEW_TYPE,
    BASELINE_METHOD, TRIAL_METHOD, POLICY_ID, VALUE_TYPES, method_learning_key_v1, evaluate_method_benefit_v1)
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner, owner_grant_key
from ..runtime_contracts import canonical_digest, canonical_serialize, NamespaceId
from .d01_production_operations_v1 import (CurrentDomainReadV1, InstalledD01ProductionReadersV1,
    MissingProductionOriginalV1, waiting_stage_v1, production_read_plan_v1)
from .domain_production_erasure_v1 import decode_typed_production_value_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d11_life_preparation_v1 import _read
from ..runtime_storage_v3 import runtime_storage_v3
from .current_method_learning_read_v3 import (require_bound_method_learning_rows_v3,
    require_bound_method_learning_head_v3, require_bound_method_learning_atom_v3,
    require_bound_method_learning_history_v3)


def _method_head(db, namespace, key):
    if runtime_storage_v3(db) is not None:
        return require_bound_method_learning_head_v3(db, namespace, key)
    return db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (key.token, *namespace.as_tuple)).fetchone()


def _method_history(db, namespace, key, revision):
    if runtime_storage_v3(db) is not None:
        return require_bound_method_learning_history_v3(db, namespace, key, revision)
    return db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
        (key.token, revision)).fetchone()


def _method_value(db, namespace, key):
    if key.type_name in {*VALUE_TYPES, "d07.current_interpretation.v1"}:
        row = _method_head(db, namespace, key)
        return None if row is None or row[2] != 1 else json.loads(row[1])
    from .d01_production_operations_v1 import raw_head_value_v1
    return raw_head_value_v1(db, namespace, key)


REGISTER_PROTOCOL = "register_method_evaluation_protocol_v1"
REGISTER_TRIAL = "register_scoped_method_trial_v1"
REGISTER_EXPERIMENT = "register_method_experiment_v1"
REGISTER_EXPERIMENT_V2 = "register_method_experiment_v2"
EVALUATE = "evaluate_current_method_outcome_v1"
REVIEW = "review_current_method_growth_v1"
ADOPT = "adopt_current_method_strategy_v1"
REGISTER_PROPOSAL_V2 = "register_method_trial_proposal_v2"
REGISTER_TRIAL_V2 = "register_scoped_method_trial_v2"
REGISTER_BLIND_REQUEST_V2 = "register_method_blind_review_request_v2"
OBSERVATION_KIND = "method_comparison_observation"
OBSERVATION_OPERATION = "observe_method_comparison_v1"


@dataclass(frozen=True, slots=True)
class RegisterMethodEvaluationProtocolRequestV1:
    protocol: MethodEvaluationProtocolV1


@dataclass(frozen=True, slots=True)
class RegisterScopedMethodTrialRequestV1:
    gp1_interpretation_ref: str


@dataclass(frozen=True, slots=True)
class RegisterMethodExperimentRequestV1:
    experiment: MethodExperimentPlanV1


@dataclass(frozen=True, slots=True)
class RegisterMethodExperimentRequestV2:
    experiment: MethodExperimentPlanV1


@dataclass(frozen=True, slots=True)
class EvaluateCurrentMethodOutcomeRequestV1:
    experiment_ref: str
    milestone_ref: str
    baseline_milestone_ref: str
    measurement_original_ref: str
    blind_response_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReviewCurrentMethodGrowthRequestV1:
    trial_ref: str
    evaluation_refs: tuple[str, ...]
    continuity_interpretation_ref: str


@dataclass(frozen=True, slots=True)
class AdoptCurrentMethodStrategyRequestV1:
    review_ref: str


@dataclass(frozen=True, slots=True)
class RegisterMethodTrialProposalRequestV2:
    proposal: MethodTrialProposalV2


@dataclass(frozen=True, slots=True)
class RegisterScopedMethodTrialRequestV2:
    proposal_ref: str
    gp1_interpretation_ref: str


@dataclass(frozen=True, slots=True)
class RegisterMethodBlindReviewRequestV2:
    review_request: MethodBlindReviewRequestV2


OPERATIONS = {REGISTER_PROPOSAL_V2: RegisterMethodTrialProposalRequestV2,
    REGISTER_TRIAL_V2: RegisterScopedMethodTrialRequestV2, REGISTER_BLIND_REQUEST_V2: RegisterMethodBlindReviewRequestV2,
REGISTER_PROTOCOL: RegisterMethodEvaluationProtocolRequestV1,
    REGISTER_TRIAL: RegisterScopedMethodTrialRequestV1, REGISTER_EXPERIMENT: RegisterMethodExperimentRequestV1,
    REGISTER_EXPERIMENT_V2: RegisterMethodExperimentRequestV2,
    EVALUATE: EvaluateCurrentMethodOutcomeRequestV1, REVIEW: ReviewCurrentMethodGrowthRequestV1,
    ADOPT: AdoptCurrentMethodStrategyRequestV1}


def _typed_head(db, read, ref, cls):
    atom = read.head(db, ref, required=True)
    value = decode_typed_production_value_v1(atom.value, cls)
    if value.namespace != read.frame.envelope.authority.namespace:
        raise ValueError("method learning record crossed namespace")
    read.source_family(db, value.source_refs, purpose="consolidation")
    return atom, value


def _origin(db, read, atom, operation_kind):
    namespace = read.frame.envelope.authority.namespace
    row = _method_history(db, namespace, atom.key, atom.revision)
    if runtime_storage_v3(db) is not None:
        if require_bound_method_learning_atom_v3(db, namespace, atom.key) != atom:
            raise ValueError("method history atom differs from its actual prepared EOF")
        wire = _method_head(db, namespace, atom.key)[1]
    else:
        wire = canonical_serialize(atom.value)
    if row is None or row[1:] != (wire, 1):
        raise MissingProductionOriginalV1("actual_method_learning_head_history")
    original = read_adopted_domain_operation_v1(db, read.frame.envelope.authority.namespace, row[0])
    accepted_operations = ({REGISTER_TRIAL, REGISTER_TRIAL_V2} if operation_kind == REGISTER_TRIAL else
        {REGISTER_EXPERIMENT, REGISTER_EXPERIMENT_V2} if operation_kind == REGISTER_EXPERIMENT else {operation_kind})
    if original is None or original["domain"] != "d01" or original["operation_kind"] not in accepted_operations:
        raise MissingProductionOriginalV1("actual_method_learning_producer:" + operation_kind)
    if not any(v.key == atom.key and v.revision == atom.revision for v in original["receipt"].write_versions):
        raise ValueError("method learning history lacks exact actual W01 membership")
    return original


def _deps(db, read, source_refs, extra=()):
    from ..memory_types import access_key
    from ..domains.d06 import source_correction_head_key
    records = read.source_family(db, tuple(dict.fromkeys(source_refs)), purpose="consolidation")
    ns = read.frame.envelope.authority.namespace
    return tuple(dict.fromkeys((*(key for ref, source in records.items() for key in
        (AtomKey.from_token(ref), access_key(*ns.as_tuple, source.source_id), source_correction_head_key(ns, source.source_id))),
        *(AtomKey.from_token(ref) for ref in extra))))


def _policy(read, protocol):
    if not protocol.valid_from <= read.frame.now_utc < protocol.valid_until:
        raise MissingProductionOriginalV1("current_frozen_method_evaluation_protocol")
    pins = tuple(pin for pin in read.frame.installed_policy_refs if pin.policy_ref == protocol.observer_policy_ref)
    if len(pins) != 1 or pins[0].policy_digest != protocol.observer_policy_digest:
        raise MissingProductionOriginalV1("actual_installed_method_observer_policy")


def _active(read, readers):
    return PersonaDomain().resolve_active_role(read.frame.snapshot,
        namespace=read.frame.envelope.authority.namespace, current_guard=readers.owner_guard)


def _semantic(db, read, ref, question):
    atom, original, sources = read.adopted_interpretation(db, ref, question_scope=question)
    return atom, original, sources


def trial_question_v1(target_block):
    return "d01.scoped-method-trial:" + target_block


def blind_review_question_v1(experiment_ref, treatment_digest, baseline_digest):
    return "d01.method-blind-review:" + canonical_digest((experiment_ref, treatment_digest, baseline_digest))


def continuity_question_v1(trial, evaluations):
    return "d01.method-continuity:" + canonical_digest((trial.base_persona_head, trial.target_block,
        trial.protocol_digest, tuple((ref, digest) for ref, digest in evaluations)))


def _stage(frame, kind, request, *, writes=(), provenance=None, missing=()):
    provider = PersonaDomain()
    if kind==REVIEW:
        provenance={**provenance,"conditioned_source_roots":frame.envelope.source_qualification.source_refs,"conditioned_original_deadline_utc":frame.envelope.deadline_utc}
    return stage_result_v1(frame, "d01", kind, request, writes=writes, provenance=provenance,
        coverage="complete" if not missing else "partial", missing=missing,
        receiver_events=(("d08", "method_learning_changed_requires_choice_recheck"),
            *((("d01","conditioned_method_review_committed_v1"),)if kind==REVIEW and not missing else())) if writes else (),
        proposal_schema="d01.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)


def _register_protocol(db, read, request, readers):
    value = request.protocol
    if type(value) is not MethodEvaluationProtocolV1 or value.namespace != read.frame.envelope.authority.namespace:
        raise TypeError("exact current Owner method protocol required")
    _policy(read, value)
    sources = read.source_family(db, value.source_refs, purpose="consolidation")
    if not all(sources[ref].source_kind == "authored" for ref in value.source_refs):
        raise ValueError("method evaluation protocol is an authored frozen policy, not an observed success")
    key = method_learning_key_v1(value.namespace, PROTOCOL_TYPE, value.protocol_id)
    if read.head(db, key).revision:
        raise ValueError("method evaluation protocol is immutable; changed thresholds need a new registered identity")
    return _stage(read.frame, REGISTER_PROTOCOL, request,
        writes=(GraphWrite(key, plain_v1(value), _deps(db, read, value.source_refs)),), provenance={"protocol": value})


def _register_trial(db, read, request, readers):
    atom = read.head(db, request.gp1_interpretation_ref, required=True)
    trial = decode_typed_production_value_v1(json.loads(atom.value["proposition"]), MethodScopedTrialV1)
    semantic, original, _ = _semantic(db, read, request.gp1_interpretation_ref, trial_question_v1(trial.target_block))
    if trial.gp1_interpretation_ref != request.gp1_interpretation_ref or trial.status != "scoped_trial":
        raise ValueError("GP1 proposes only its own bounded trial, never adopted ST2")
    _validate_trial_scope(db, read, trial, readers)
    if not set(trial.source_refs) <= set(semantic.value["source_refs"]):
        raise ValueError("trial lost its actual semantic source scope")
    key = method_learning_key_v1(trial.namespace, TRIAL_TYPE, trial.trial_id)
    if read.head(db, key).revision:
        raise ValueError("trial registration cannot replace an existing trial or its outcomes")
    deps = _deps(db, read, trial.source_refs, (trial.gp1_interpretation_ref, trial.protocol_ref))
    return _stage(read.frame, REGISTER_TRIAL, request, writes=(GraphWrite(key, plain_v1(trial), deps),),
        provenance={"trial": trial, "GP1": original, "active_strategy": "ST0", "selection_basis": "scoped_trial"})


def _require_registered_before_semantic(db, read, registered, semantic):
    sequences = []
    for atom in (registered, semantic):
        row = _method_history(db, read.frame.envelope.authority.namespace, atom.key, atom.revision)
        if row is None: raise MissingProductionOriginalV1("actual_preregistered_method_request_history")
        sequences.append(read.committed_operation(db, row[0])[2])
    if sequences[0] >= sequences[1]:
        raise ValueError("method request must actually commit before its semantic response")


def trial_question_v2(proposal_ref, proposal_digest):
    return "d01.scoped-method-trial.v2:" + canonical_digest((proposal_ref, proposal_digest))


def blind_review_question_v2(request_ref, request_digest):
    return "d01.method-blind-review.v2:" + canonical_digest((request_ref, request_digest))


def _validate_trial_scope(db, read, trial, readers):
    active = _active(read, readers)
    block = next((item for item in active.plan.blocks if item.block_id == trial.target_block), None)
    if (trial.base_persona_head != active.plan.head_id or block is None or block.kind != "strategy"
            or block.plasticity != "growth" or method_policy_state_v1(block.claim) != "ST0"):
        raise MissingProductionOriginalV1("current_plastic_ST0_method_block")
    protocol_atom, protocol = _typed_head(db, read, trial.protocol_ref, MethodEvaluationProtocolV1)
    _origin(db, read, protocol_atom, REGISTER_PROTOCOL); _policy(read, protocol)
    if (trial.protocol_digest != canonical_digest(protocol_atom.value) or not trial.valid_from <= read.frame.now_utc < trial.valid_until
            or trial.valid_until > protocol.valid_until or len(trial.goal_refs) > protocol.required_project_trials):
        raise ValueError("trial changed its frozen scope, evidence or original validity")
    for ref in trial.goal_refs:
        goal = read.head(db, ref, required=True)
        if goal.value["state"] != "active": raise MissingProductionOriginalV1("active_method_trial_goal")


def _register_proposal_v2(db, read, request, readers):
    value = request.proposal
    if type(value) is not MethodTrialProposalV2 or value.namespace != read.frame.envelope.authority.namespace:
        raise TypeError("exact independent method trial proposal required")
    _validate_trial_scope(db, read, value, readers)
    key = method_learning_key_v1(value.namespace, TRIAL_PROPOSAL_TYPE_V2, value.trial_id)
    if read.head(db, key).revision: raise ValueError("trial proposal cannot be replaced after semantic judgment")
    return _stage(read.frame, REGISTER_PROPOSAL_V2, request,
        writes=(GraphWrite(key, plain_v1(value), _deps(db, read, value.source_refs, (value.protocol_ref,))),),
        provenance={"method_trial_proposal": value, "active_strategy": "ST0"})


def _register_trial_v2(db, read, request, readers):
    proposal_atom, proposal = _typed_head(db, read, request.proposal_ref, MethodTrialProposalV2)
    proposal_original = _origin(db, read, proposal_atom, REGISTER_PROPOSAL_V2)
    semantic, original, _ = _semantic(db, read, request.gp1_interpretation_ref,
        trial_question_v2(request.proposal_ref, canonical_digest(proposal_atom.value)))
    _require_registered_before_semantic(db, read, proposal_atom, semantic)
    if semantic.value["proposition"] != "accepted" or not set(proposal.source_refs) <= set(semantic.value["source_refs"]):
        raise MissingProductionOriginalV1("actual_accepted_exact_method_proposal_GP1")
    # The interpretation key is known only after the real D07 output was adopted.
    trial = MethodScopedTrialV1(proposal.namespace, proposal.trial_id, request.gp1_interpretation_ref,
        proposal.growth_proposal_ref, proposal.base_persona_head, proposal.target_block,
        proposal.protocol_ref, proposal.protocol_digest, proposal.goal_refs, proposal.source_refs,
        proposal.valid_from, proposal.valid_until, "scoped_trial")
    _validate_trial_scope(db, read, trial, readers)
    key = method_learning_key_v1(trial.namespace, TRIAL_TYPE, trial.trial_id)
    if read.head(db, key).revision: raise ValueError("trial registration cannot replace an existing trial")
    deps = _deps(db, read, trial.source_refs, (request.proposal_ref, trial.gp1_interpretation_ref, trial.protocol_ref))
    return _stage(read.frame, REGISTER_TRIAL_V2, request, writes=(GraphWrite(key, plain_v1(trial), deps),),
        provenance={"trial": trial, "GP1": original, "proposal_original": proposal_original,
            "proposal_ref": request.proposal_ref, "proposal_digest": canonical_digest(proposal_atom.value),
            "active_strategy": "ST0", "selection_basis": "scoped_trial"})


def _register_blind_request_v2(db, read, request, readers):
    value = request.review_request
    if type(value) is not MethodBlindReviewRequestV2 or value.namespace != read.frame.envelope.authority.namespace:
        raise TypeError("exact independent blind review request required")
    experiment_atom, experiment = _typed_head(db, read, value.experiment_ref, MethodExperimentPlanV1)
    _origin(db, read, experiment_atom, REGISTER_EXPERIMENT)
    actual, _ = _milestone(db, read, value.treatment_milestone_ref, readers.issuer)
    baseline, _ = _milestone(db, read, value.baseline_milestone_ref, readers.issuer)
    if (value.experiment_digest != canonical_digest(experiment_atom.value)
            or (actual.goal_ref, baseline.goal_ref) != (experiment.treatment_goal_ref, experiment.baseline_goal_ref)
            or (value.treatment_milestone_digest, value.baseline_milestone_digest) != (actual.digest, baseline.digest)
            or (value.treatment_artifact_digest, value.baseline_artifact_digest) != (actual.readback.content_digest, baseline.readback.content_digest)
            or not read.frame.now_utc < value.valid_until <= experiment.valid_until):
        raise ValueError("blind review request changed its real pair, versions or deadline")
    key = method_learning_key_v1(value.namespace, BLIND_REQUEST_TYPE_V2, value.request_id)
    if read.head(db, key).revision: raise ValueError("blind review request is immutable")
    deps = _deps(db, read, value.source_refs, (value.experiment_ref, actual.source_head.key.token, baseline.source_head.key.token))
    return _stage(read.frame, REGISTER_BLIND_REQUEST_V2, request,
        writes=(GraphWrite(key, plain_v1(value), deps),), provenance={"method_blind_review_request": value})


def _register_experiment(db, read, request, readers):
    shared = type(request) is RegisterMethodExperimentRequestV2
    value = request.experiment
    if type(value) is not MethodExperimentPlanV1 or value.namespace != read.frame.envelope.authority.namespace:
        raise TypeError("exact prospectively registered method experiment required")
    trial_atom, trial = _typed_head(db, read, value.trial_ref, MethodScopedTrialV1)
    _origin(db, read, trial_atom, REGISTER_TRIAL)
    protocol_atom, protocol = _typed_head(db, read, value.protocol_ref, MethodEvaluationProtocolV1)
    _origin(db, read, protocol_atom, REGISTER_PROTOCOL); _policy(read, protocol)
    if (trial.status != "scoped_trial" or not trial.valid_from <= read.frame.now_utc < trial.valid_until
            or value.treatment_goal_ref not in trial.goal_refs
            or value.protocol_ref != trial.protocol_ref or value.protocol_digest != trial.protocol_digest
            or value.valid_until > trial.valid_until or read.frame.now_utc >= value.valid_until
            or value.parent_budget_lease_ref != read.frame.envelope.parent_budget_lease_ref):
        raise ValueError("experiment cannot expand actual trial, deadline or parent budget")
    for ref in (value.treatment_goal_ref, value.baseline_goal_ref):
        goal = read.head(db, ref, required=True)
        if goal.value["state"] != "active" or goal.value["progress_refs"]:
            raise MissingProductionOriginalV1("prospective_uncompleted_method_comparison_goals")
        inputs = read.source_family(db, tuple(goal.value["reason_refs"]), purpose="consolidation")
        if not shared and value.common_task_source_ref not in inputs:
            raise ValueError("paired experiment goals lack their registered common task input")
    from .budget import get_budget_lease, require_budget_family_admissible
    budget = get_budget_lease(db, value.parent_budget_lease_ref)
    require_budget_family_admissible(db, budget.lease_id)
    if (budget.bot_id, budget.persona_id) != value.namespace.as_tuple:
        raise ValueError("experiment parent budget crossed namespace")
    key = method_learning_key_v1(value.namespace, EXPERIMENT_TYPE, value.experiment_id)
    if read.head(db, key).revision: raise ValueError("comparison protocol cannot be registered again after outcomes")
    deps = _deps(db, read, value.source_refs, (value.trial_ref, value.protocol_ref))
    provenance = {"experiment": value, "real_experience_increment": 0}
    if shared:
        from .method_pair_shared_input_v1 import build_method_pair_shared_input_v1
        provenance["shared_input"] = build_method_pair_shared_input_v1(db, read=read, experiment=value, issuer=readers.issuer)
    return _stage(read.frame, REGISTER_EXPERIMENT_V2 if shared else REGISTER_EXPERIMENT, request,
        writes=(GraphWrite(key, plain_v1(value), deps),), provenance=provenance)


def _milestone(db, read, ref, issuer):
    from .artifact_task_observer_v1 import read_current_artifact_task_milestone_v2
    value = read_current_artifact_task_milestone_v2(db, namespace=read.frame.envelope.authority.namespace, original_ref=ref, issuer=issuer)
    read.head(db, value.source_head.key, required=True)
    read.source_family(db, (value.source_head.key.token,), purpose="consolidation")
    read.original(ref, kind="d11.life_artifact_task_milestone_v2", digest=value.digest)
    from .d11_life_terminal_v1 import read_adopted_life_original_v1
    original = read_adopted_life_original_v1(db, namespace=value.namespace, result_ref=value.file_result_ref, issuer=issuer)
    if original is None: raise MissingProductionOriginalV1("actual_method_evaluation_artifact_original")
    artifact = original["terminal"]["binding"]["artifact_ref"]
    return value, artifact


def _blind_reviews(db, read, refs, *, experiment_ref, actual, baseline):
    if type(refs) is not tuple or len(refs) > 8 or len(set(refs)) != len(refs):
        raise ValueError("bounded distinct actual blind review references required")
    result = []
    for ref in refs:
        candidate = read.head(db, ref, required=True)
        raw = json.loads(candidate.value["proposition"])
        if raw.get("schema") == "d01.method_blind_response.v2":
            response = decode_typed_production_value_v1(raw, MethodBlindResponseV2)
            request_atom, request = _typed_head(db, read, response.request_ref, MethodBlindReviewRequestV2)
            _origin(db, read, request_atom, REGISTER_BLIND_REQUEST_V2)
            atom, _, _ = _semantic(db, read, ref, blind_review_question_v2(response.request_ref, response.request_digest))
            _require_registered_before_semantic(db, read, request_atom, atom)
            if (response.request_digest != canonical_digest(request_atom.value) or request.experiment_ref != experiment_ref
                    or (request.treatment_milestone_ref, request.treatment_milestone_digest) != (actual.original_ref, actual.digest)
                    or (request.baseline_milestone_ref, request.baseline_milestone_digest) != (baseline.original_ref, baseline.digest)
                    or (request.treatment_artifact_digest, request.baseline_artifact_digest) != (actual.readback.content_digest, baseline.readback.content_digest)
                    or read.frame.now_utc >= request.valid_until):
                raise ValueError("blind response changed its independently registered request or actual pair")
            value = MethodBlindReviewV1(request.reviewer_entity_ref, ref, response.source_ref, response.quality_delta, response.blind)
        else:
            atom, _, _ = _semantic(db, read, ref, blind_review_question_v1(experiment_ref, actual.readback.content_digest, baseline.readback.content_digest))
            value = decode_typed_production_value_v1(raw, MethodBlindReviewV1)
        if value.response_interpretation_ref != ref or value.source_ref not in atom.value["source_refs"]:
            raise ValueError("blind review lost its actual source/semantic interpretation")
        read.actor_entity(db, value.source_ref, expected_entity=value.reviewer_entity_ref)
        result.append(value)
    if len({row.reviewer_entity_ref for row in result}) != len(result):
        raise ValueError("one reviewer cannot be counted twice")
    return tuple(result)


def _evaluate(db, read, request, readers):
    experiment_atom, experiment = _typed_head(db, read, request.experiment_ref, MethodExperimentPlanV1)
    experiment_original = _origin(db, read, experiment_atom, REGISTER_EXPERIMENT)
    trial_atom, trial = _typed_head(db, read, experiment.trial_ref, MethodScopedTrialV1)
    _origin(db, read, trial_atom, REGISTER_TRIAL)
    protocol_atom, protocol = _typed_head(db, read, experiment.protocol_ref, MethodEvaluationProtocolV1)
    _origin(db, read, protocol_atom, REGISTER_PROTOCOL); _policy(read, protocol)
    treatment, artifact = _milestone(db, read, request.milestone_ref, readers.issuer)
    baseline, baseline_artifact = _milestone(db, read, request.baseline_milestone_ref, readers.issuer)
    if (treatment.goal_ref, baseline.goal_ref, treatment.selector.method_ref, baseline.selector.method_ref) != (
            experiment.treatment_goal_ref, experiment.baseline_goal_ref, TRIAL_METHOD, BASELINE_METHOD):
        raise ValueError("method evaluation compared another actual task/method")
    for milestone in (treatment, baseline):
        for ref, _ in milestone.ordered_phase_originals:
            row = _read(db, issuer=readers.issuer, namespace=experiment.namespace, kind="c4_phase_verified", ref=ref)
            produced = None if row is None else read_adopted_domain_operation_v1(db, experiment.namespace, row[1])
            if produced is None or produced["receipt"].commit_seq <= experiment_original["receipt"].commit_seq:
                raise ValueError("method comparison was not frozen before its actual outcomes")
    observed = _read(db, issuer=readers.issuer, namespace=experiment.namespace, kind=OBSERVATION_KIND, ref=request.measurement_original_ref)
    if observed is None:
        raise MissingProductionOriginalV1("actual_installed_method_comparison_observer_original")
    observation_type = MethodComparisonObservationV2 if observed[0].get("schema") == "d11.method_comparison_observation.v2" else MethodComparisonObservationV1
    observation = decode_typed_production_value_v1(observed[0], observation_type)
    producer = read_adopted_domain_operation_v1(db, experiment.namespace, observed[1])
    if (producer is None or (producer["domain"], producer["operation_kind"]) != ("d11", OBSERVATION_OPERATION)
            or producer["payload"]["coverage"] != "complete"
            or producer["payload"]["provenance"].get("method_comparison_observation") != observed[0]
            or observation.experiment_ref != request.experiment_ref or observation.experiment_digest != canonical_digest(experiment_atom.value)
            or (observation.observer_policy_ref, observation.observer_policy_digest) != (protocol.observer_policy_ref, protocol.observer_policy_digest)
            or (observation.treatment_milestone_ref, observation.treatment_milestone_digest, observation.baseline_milestone_ref, observation.baseline_milestone_digest) != (
                treatment.original_ref, treatment.digest, baseline.original_ref, baseline.digest)
            or (observation.treatment_artifact_digest, observation.baseline_artifact_digest) != (treatment.readback.content_digest, baseline.readback.content_digest)):
        raise MissingProductionOriginalV1("actual_same_pair_version_hash_method_measurement")
    read.original(request.measurement_original_ref, kind="d11.life_" + OBSERVATION_KIND, digest=canonical_digest(observed[0]))
    sources = read.source_family(db, observation.source_refs, purpose="consolidation")
    if type(observation) is MethodComparisonObservationV2:
        source_atom = read.head(db, observation.source_refs[0], required=True)
        source_record = sources[observation.source_refs[0]]
        source_history = _method_history(db, read.frame.envelope.authority.namespace, source_atom.key, source_atom.revision)
        source_history_matches = (source_history is not None and source_history[0] == observed[1]
            and source_history[2] == 1 and json.loads(source_history[1]) == source_atom.value)
        if ((source_record.source_kind, source_record.assertion_status, source_record.independence) != ("internal", "confirmed", "same_root")
                or not source_record.parent_source_ids or source_record.provenance_root != observation.measurement_family_ref
                or not source_history_matches
                or not any(v.key == source_atom.key and v.revision == source_atom.revision for v in producer["receipt"].write_versions)):
            raise MissingProductionOriginalV1("actual_same_W01_derived_measurement_Source_lineage")
        families = {observation.measurement_family_ref}
    else:
        families = {sources[ref].provenance_root for ref in observation.source_refs if sources[ref].source_kind == "observed"
            and sources[ref].assertion_status == "confirmed" and sources[ref].independence == "independent"}
    if len(families) != 1:
        raise MissingProductionOriginalV1("one_actual_independent_method_trial_observation_family")
    reviews = _blind_reviews(db, read, request.blind_response_refs, experiment_ref=request.experiment_ref, actual=treatment, baseline=baseline)
    benefit, missing = evaluate_method_benefit_v1(protocol, observation.metrics, reviews)
    if observation.source_scope != "PRODUCTION":
        benefit, missing = "unknown", tuple(dict.fromkeys((*missing, "production_method_observer_qualification")))
    roots = tuple(dict.fromkeys((*observation.source_refs, treatment.source_head.key.token, baseline.source_head.key.token,
        *(row.source_ref for row in reviews))))
    evaluation_id = "method-evaluation:" + canonical_digest((request, treatment.digest, baseline.digest))[:48]
    value = MethodEvaluationV1(experiment.namespace, evaluation_id, experiment.trial_ref, experiment.protocol_ref,
        experiment.protocol_digest, treatment.project_ref, treatment.original_ref, treatment.digest, artifact,
        treatment.file_version, treatment.readback.content_digest, baseline.original_ref, baseline.digest,
        baseline_artifact, baseline.file_version, baseline.readback.content_digest, request.experiment_ref,
        canonical_digest(experiment_atom.value), request.measurement_original_ref, canonical_digest(observed[0]),
        protocol.observer_policy_ref, protocol.observer_policy_digest, observation.metrics, reviews, roots,
        next(iter(families)), "verified", "verified", "matched", benefit, missing, observation.source_scope)
    key = method_learning_key_v1(value.namespace, EVALUATION_TYPE, value.evaluation_id)
    if read.head(db, key).revision: raise ValueError("method evaluation original is immutable")
    deps = _deps(db, read, roots, (experiment.trial_ref, experiment.protocol_ref, request.experiment_ref, *request.blind_response_refs))
    return _stage(read.frame, EVALUATE, request, writes=(GraphWrite(key, plain_v1(value), deps),),
        provenance={"method_evaluation": value, "actual_observer_operation": observed[1]}, missing=missing)


def _review_inputs(db, read, request, readers):
    trial_atom, trial = _typed_head(db, read, request.trial_ref, MethodScopedTrialV1)
    _origin(db, read, trial_atom, REGISTER_TRIAL)
    protocol_atom, protocol = _typed_head(db, read, trial.protocol_ref, MethodEvaluationProtocolV1)
    _origin(db, read, protocol_atom, REGISTER_PROTOCOL); _policy(read, protocol)
    if type(request.evaluation_refs) is not tuple or len(request.evaluation_refs) > 16 or len(set(request.evaluation_refs)) != len(request.evaluation_refs):
        raise ValueError("bounded exact method trial evaluation inventory required")
    missing, evaluations, roots = [], [], list(trial.source_refs)
    inventory = read.complete_inventory(db, EVALUATION_TYPE)
    recorded = {atom.key.token for atom in inventory if atom.valid and atom.value["trial_ref"] == request.trial_ref}
    if recorded != set(request.evaluation_refs):
        missing.append("complete_method_trial_outcome_inventory")
    for ref in request.evaluation_refs:
        atom, value = _typed_head(db, read, ref, MethodEvaluationV1)
        _origin(db, read, atom, EVALUATE)
        if value.trial_ref != request.trial_ref or value.protocol_digest != trial.protocol_digest:
            raise ValueError("method review changed trial or frozen protocol")
        actual, _ = _milestone(db, read, value.milestone_ref, readers.issuer)
        baseline, _ = _milestone(db, read, value.baseline_milestone_ref, readers.issuer)
        if (actual.digest, actual.file_version, actual.readback.content_digest, baseline.digest, baseline.readback.content_digest) != (
                value.milestone_digest, value.artifact_version, value.artifact_digest, value.baseline_milestone_digest, value.baseline_artifact_digest):
            raise MissingProductionOriginalV1("current_F1_F2_artifact_version_hash_attribution")
        measured = _read(db, issuer=readers.issuer, namespace=value.namespace, kind=OBSERVATION_KIND, ref=value.measurement_original_ref)
        if measured is None or canonical_digest(measured[0]) != value.measurement_original_digest:
            raise MissingProductionOriginalV1("current_actual_method_measurement_original")
        read.original(value.measurement_original_ref, kind="d11.life_" + OBSERVATION_KIND, digest=value.measurement_original_digest)
        reviews = _blind_reviews(db, read, tuple(row.response_interpretation_ref for row in value.blind_reviews),
            experiment_ref=value.experiment_original_ref, actual=actual, baseline=baseline)
        benefit, gaps = evaluate_method_benefit_v1(protocol, value.metrics, reviews)
        if reviews != value.blind_reviews or benefit != "supported" or gaps or value.method_benefit != "supported" or value.source_scope != "PRODUCTION":
            missing.append("qualified_method_benefit:" + ref)
        evaluations.append((ref, atom, value)); roots.extend(value.source_refs)
    if (len(evaluations) < protocol.required_project_trials
            or len({value.project_ref for _, _, value in evaluations}) != len(evaluations)
            or len({value.evidence_family for _, _, value in evaluations}) != len(evaluations)):
        missing.append("required_independent_project_trials")
    inventory = read.complete_inventory(db, "d07.current_interpretation.v1")
    counter_scope = "d01.method-counterevidence:" + canonical_digest((request.trial_ref, trial.protocol_digest))
    scoped = tuple(atom for atom in inventory if atom.valid and atom.value["question_key"] == counter_scope and atom.value["current"])
    counters = tuple(atom for atom in scoped if atom.value["stance"] == "oppose" and atom.value["evidence_status"] == "supported")
    for atom in scoped:
        read.original(atom.key.token, digest=canonical_digest(atom.value))
        read.source_family(db, tuple(atom.value["source_refs"]), purpose="consolidation"); roots.extend(atom.value["source_refs"])
    if counters: missing.append("current_supported_method_counterevidence")
    if any(atom.value["meaningful_unknowns"] or atom.value["evidence_status"] in {"insufficient", "conflicted"} for atom in scoped):
        missing.append("unresolved_current_method_counterevidence")
    pairs = tuple((ref, canonical_digest(atom.value)) for ref, atom, _ in evaluations)
    continuity, _, _ = _semantic(db, read, request.continuity_interpretation_ref, continuity_question_v1(trial, pairs))
    if continuity.value["proposition"] != "accepted": missing.append("actual_method_continuity_review")
    roots.extend(continuity.value["source_refs"])
    active = _active(read, readers)
    if active.plan.head_id != trial.base_persona_head: missing.append("current_trial_base_persona_head")
    return trial_atom, trial, protocol, evaluations, counters, tuple(dict.fromkeys(roots)), tuple(dict.fromkeys(missing))


def _review(db, read, request, readers):
    _, trial, protocol, evaluations, counters, roots, missing = _review_inputs(db, read, request, readers)
    identity = "method-review:" + canonical_digest((request, tuple(canonical_digest(atom.value) for _, atom, _ in evaluations)))[:48]
    value = MethodOutcomeReviewV1(read.frame.envelope.authority.namespace, identity, request.trial_ref, trial.growth_proposal_ref,
        trial.protocol_ref, trial.protocol_digest, request.evaluation_refs, tuple(atom.key.token for atom in counters),
        request.continuity_interpretation_ref, trial.base_persona_head, trial.target_block,
        tuple(sorted({value.evidence_family for _, _, value in evaluations})), roots, "held" if missing else "qualified", missing)
    key = method_learning_key_v1(value.namespace, REVIEW_TYPE, value.review_id)
    if read.head(db, key).revision: raise ValueError("method outcome review is immutable")
    deps = _deps(db, read, roots, (request.trial_ref, trial.protocol_ref, request.continuity_interpretation_ref,
        *request.evaluation_refs, *value.counter_interpretation_refs))
    return _stage(read.frame, REVIEW, request, writes=(GraphWrite(key, plain_v1(value), deps),),
        provenance={"method_outcome_review": value}, missing=missing)


def _adopt(db, read, request, readers):
    review_atom, review = _typed_head(db, read, request.review_ref, MethodOutcomeReviewV1)
    _origin(db, read, review_atom, REVIEW)
    prior_request = ReviewCurrentMethodGrowthRequestV1(review.trial_ref, review.evaluation_refs, review.continuity_interpretation_ref)
    trial_atom, trial, protocol, evaluations, counters, roots, missing = _review_inputs(db, read, prior_request, readers)
    if review.qualification != "qualified" or missing or counters:
        raise MissingProductionOriginalV1(*(missing or ("current_qualified_method_outcome_and_continuity_review",)))
    active = _active(read, readers); domain = PersonaDomain()
    block = next((block for block in active.plan.blocks if block.block_id == trial.target_block), None)
    if block is None or block.kind != "strategy" or block.plasticity != "growth" or method_policy_state_v1(block.claim) != "ST0":
        raise MissingProductionOriginalV1("same_current_plastic_ST0_strategy_block")
    claim = canonical_serialize({"schema": "d01.method-policy.v1", "policy_id": POLICY_ID, "strategy_state": "ST2"})
    proposal = GrowthProposal(trial.growth_proposal_ref, active.plan.head_id, trial.target_block, claim,
        review.evidence_families, True, "local", "external")
    revision = domain.activate_revision(active.plan, proposal)
    plan = replace(active.plan, version=active.plan.version + 1, blocks=revision.blocks, authored=False)
    grant = read.head(db, owner_grant_key(*plan.namespace.as_tuple), required=True)
    deps = _deps(db, read, roots, (request.review_ref, review.trial_ref, review.protocol_ref, *review.evaluation_refs,
        review.continuity_interpretation_ref))
    writes = [replace(domain.plan_write(plan), dependencies=deps), replace(domain.revision_write(plan.namespace, revision), dependencies=deps),
        domain.activation_write(plan, grant, readers.owner_guard)]
    consumed = []
    for family in review.evidence_families:
        name = domain.contribution_key(trial.target_block, family, "local")
        key = AtomKey(Owner("persona", *plan.namespace.as_tuple), "d01.growth_contribution.v1", name)
        if read.head(db, key).revision: raise ValueError("method outcome family has already been adopted")
        writes.append(GraphWrite(key, plain_v1(proposal), deps)); consumed.append(name)
    for write in writes: read.head(db, write.key)
    return stage_result_v1(read.frame, "d01", ADOPT, request, writes=tuple(writes),
        provenance={"method_outcome_review_ref": request.review_ref, "method_outcome_review_digest": canonical_digest(review_atom.value),
            "growth_proposal": proposal, "semantic_identity_changed": False}, contribution_keys=tuple(consumed),
        receiver_events=(("d08", "method_strategy_adopted_requires_choice_recheck"),),
        proposal_schema="d01.proposal.v1", proposal_hash=domain.descriptor.request_schema_hash)


def stage_current_method_learning_v1(db, *, frame, request, installed_readers, operation_kind):
    if operation_kind == REGISTER_EXPERIMENT_V2:
        from .method_pair_shared_input_v1 import InstalledMethodPairOwnerReadersV2
        if type(installed_readers) is not InstalledMethodPairOwnerReadersV2:
            raise TypeError("explicit shared method input requires its actual Owner-only reader")
        installed_readers.require_owner_frame(frame)
        installed_readers = installed_readers.base_readers
    if operation_kind not in OPERATIONS or type(request) is not OPERATIONS[operation_kind] or type(installed_readers) is not InstalledD01ProductionReadersV1:
        raise TypeError("exact installed D01 method learning operation required")
    read = CurrentDomainReadV1(frame)
    try:
        read.check(db)
        stage = {REGISTER_PROPOSAL_V2: _register_proposal_v2, REGISTER_TRIAL_V2: _register_trial_v2,
            REGISTER_BLIND_REQUEST_V2: _register_blind_request_v2, REGISTER_PROTOCOL: _register_protocol, REGISTER_TRIAL: _register_trial, REGISTER_EXPERIMENT: _register_experiment, REGISTER_EXPERIMENT_V2: _register_experiment,
            EVALUATE: _evaluate, REVIEW: _review, ADOPT: _adopt}[operation_kind](db, read, request, installed_readers)
        return verify_method_learning_stage_v1(stage)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d01", operation_kind, request, missing)


def read_current_method_trial_projection_v1(db, read, *, persona_plan, goal_ref):
    inventory = read.complete_inventory(db, TRIAL_TYPE)
    choices = []
    for atom in inventory:
        if not atom.valid: continue
        value = decode_typed_production_value_v1(atom.value, MethodScopedTrialV1)
        if (value.status != "scoped_trial" or value.base_persona_head != persona_plan.head_id or goal_ref not in value.goal_refs
                or not value.valid_from <= read.frame.now_utc < value.valid_until): continue
        _origin(db, read, atom, REGISTER_TRIAL)
        protocol_atom, protocol = _typed_head(db, read, value.protocol_ref, MethodEvaluationProtocolV1)
        _origin(db, read, protocol_atom, REGISTER_PROTOCOL); _policy(read, protocol)
        if canonical_digest(protocol_atom.value) != value.protocol_digest:
            raise ValueError("method trial changed its immutable protocol")
        read.source_family(db, value.source_refs, purpose="consolidation")
        choices.append((atom.key.token, canonical_digest(atom.value)))
    if len(choices) > 1:
        raise MissingProductionOriginalV1("unique_current_scoped_method_trial")
    return choices[0] if choices else None

def method_trial_locator_inputs_v3(trials):
    """Compose exact trial locators from metadata; this grants no body access."""
    keys, roots, originals = [], [], []
    for ref, source_refs, protocol_ref, gp1_ref, proposal_ref, protocol_source_refs in trials:
        keys.extend(AtomKey.from_token(value) for value in (ref, protocol_ref, gp1_ref))
        roots.extend(source_refs); originals.append(gp1_ref)
        if proposal_ref is not None:keys.append(AtomKey.from_token(proposal_ref))
        roots.extend(protocol_source_refs)
    return (TRIAL_TYPE,), keys, roots, originals


def method_trial_read_inputs_v1(db, namespace):
    """Bounded locator expansion; the installed stage authenticates each candidate."""
    if runtime_storage_v3(db) is not None:
        rows = require_bound_method_learning_rows_v3(db, namespace, TRIAL_TYPE, ("token", "revision", "value"))
    else:
        rows = db.execute("SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? AND valid=1 ORDER BY token LIMIT 129",
            (*namespace.as_tuple, TRIAL_TYPE)).fetchall()
    if len(rows) > 128:
        raise MissingProductionOriginalV1("complete_scoped_method_trial_inventory")
    locators = []
    for ref, revision, raw in rows:
        value = json.loads(raw)
        history = _method_history(db, namespace, AtomKey.from_token(ref), revision)
        if history is None or history[1:] != (raw, 1):
            raise MissingProductionOriginalV1("actual_scoped_method_trial_head_history")
        original = None if history is None else read_adopted_domain_operation_v1(db, namespace, history[0])
        proposal_ref = (original["payload"]["provenance"]["proposal_ref"]
            if original and original["operation_kind"] == REGISTER_TRIAL_V2 else None)
        protocol = _method_value(db, namespace, AtomKey.from_token(value["protocol_ref"]))
        locators.append((ref, value["source_refs"], value["protocol_ref"], value["gp1_interpretation_ref"],
            proposal_ref, protocol["source_refs"] if protocol else ()))
    return method_trial_locator_inputs_v3(locators)


def read_plan_current_method_learning_v1(db, *, namespace, activity_id, operation_kind, request, installed_readers):
    from .artifact_task_observer_v1 import read_current_artifact_task_milestone_v2
    if not db.in_transaction or type(namespace) is not NamespaceId or type(request) is not OPERATIONS.get(operation_kind):
        raise ValueError("exact transactional method-learning read recipe required")
    types = ["d01.persona_activation.v1", "d01.persona_plan.v1", "d03.account_binding", "d03.entity_anchor"]
    keys, roots, originals, pending, milestones = [owner_grant_key(*namespace.as_tuple)], [], [], [], []
    def locate(ref):
        key = AtomKey.from_token(ref); keys.append(key)
        return _method_value(db, namespace, key)
    if operation_kind == REGISTER_PROPOSAL_V2:
        value = request.proposal; roots.extend(value.source_refs); pending.append(value.protocol_ref)
        keys.extend(AtomKey.from_token(ref) for ref in value.goal_refs)
        keys.append(method_learning_key_v1(namespace, TRIAL_PROPOSAL_TYPE_V2, value.trial_id))
    elif operation_kind == REGISTER_TRIAL_V2:
        pending.extend((request.proposal_ref, request.gp1_interpretation_ref))
        value = locate(request.proposal_ref)
        if value:
            keys.extend(AtomKey.from_token(ref) for ref in value["goal_refs"])
            keys.append(method_learning_key_v1(namespace, TRIAL_TYPE, value["trial_id"]))
    elif operation_kind == REGISTER_BLIND_REQUEST_V2:
        value = request.review_request; roots.extend(value.source_refs); pending.append(value.experiment_ref)
        milestones.extend((value.treatment_milestone_ref, value.baseline_milestone_ref))
        keys.append(method_learning_key_v1(namespace, BLIND_REQUEST_TYPE_V2, value.request_id))
    elif operation_kind == REGISTER_PROTOCOL:
        value = request.protocol; roots.extend(value.source_refs)
        keys.append(method_learning_key_v1(namespace, PROTOCOL_TYPE, value.protocol_id))
    elif operation_kind == REGISTER_TRIAL:
        raw = locate(request.gp1_interpretation_ref); originals.append(request.gp1_interpretation_ref)
        if raw:
            value = decode_typed_production_value_v1(json.loads(raw["proposition"]), MethodScopedTrialV1)
            roots.extend((*raw["source_refs"], *value.source_refs)); pending.append(value.protocol_ref)
            keys.extend(AtomKey.from_token(ref) for ref in value.goal_refs)
            keys.append(method_learning_key_v1(namespace, TRIAL_TYPE, value.trial_id))
    elif operation_kind in {REGISTER_EXPERIMENT, REGISTER_EXPERIMENT_V2}:
        value = request.experiment; roots.extend(value.source_refs); pending.extend((value.trial_ref, value.protocol_ref))
        for ref in (value.treatment_goal_ref, value.baseline_goal_ref):
            goal = locate(ref)
            if goal:
                roots.extend(goal["reason_refs"])
                if operation_kind == REGISTER_EXPERIMENT_V2:
                    objective_ref = dict(goal["satisfaction_predicate"]["parameters"]).get("objective_ref")
                    if objective_ref is not None: originals.append(objective_ref)
        keys.append(method_learning_key_v1(namespace, EXPERIMENT_TYPE, value.experiment_id))
    elif operation_kind == EVALUATE:
        pending.append(request.experiment_ref); milestones.extend((request.milestone_ref, request.baseline_milestone_ref))
        originals.extend((request.measurement_original_ref, *request.blind_response_refs)); pending.extend(request.blind_response_refs)
        observed = _read(db, issuer=installed_readers.issuer, namespace=namespace, kind=OBSERVATION_KIND, ref=request.measurement_original_ref)
        if observed: roots.extend(observed[0]["source_refs"])
        pair = tuple(read_current_artifact_task_milestone_v2(db, namespace=namespace, original_ref=ref,
            issuer=installed_readers.issuer) for ref in milestones)
        identity = "method-evaluation:" + canonical_digest((request, pair[0].digest, pair[1].digest))[:48]
        keys.append(method_learning_key_v1(namespace, EVALUATION_TYPE, identity))
    elif operation_kind in {REVIEW, ADOPT}:
        types.extend(("d07.current_interpretation.v1", EVALUATION_TYPE))
        prior = request
        if operation_kind == ADOPT:
            review = locate(request.review_ref)
            if review:
                pending.append(request.review_ref)
                prior = ReviewCurrentMethodGrowthRequestV1(review["trial_ref"], tuple(review["evaluation_refs"]), review["continuity_interpretation_ref"])
                keys.append(AtomKey(Owner("persona", *namespace.as_tuple), "d01.persona_revision.v1", review["growth_proposal_ref"]))
                for family in review["evidence_families"]:
                    keys.append(AtomKey(Owner("persona", *namespace.as_tuple), "d01.growth_contribution.v1",
                        PersonaDomain.contribution_key(review["target_block"], family, "local")))
            else:
                return production_read_plan_v1(types, keys, roots, originals)
        pending.extend((prior.trial_ref, prior.continuity_interpretation_ref, *prior.evaluation_refs))
        originals.append(prior.continuity_interpretation_ref)
        if operation_kind == REVIEW:
            values = tuple(locate(ref) for ref in prior.evaluation_refs)
            if all(value is not None for value in values):
                identity = "method-review:" + canonical_digest((request, tuple(canonical_digest(value) for value in values)))[:48]
                keys.append(method_learning_key_v1(namespace, REVIEW_TYPE, identity))
        if runtime_storage_v3(db) is not None:
            rows = require_bound_method_learning_rows_v3(db, namespace, "d07.current_interpretation.v1", ("token", "value"))
        else:
            rows = db.execute("SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d07.current_interpretation.v1' AND valid=1 ORDER BY token LIMIT 129", namespace.as_tuple).fetchall()
        if len(rows) > 128: raise MissingProductionOriginalV1("complete_method_counterevidence_inventory")
        trial = _method_value(db, namespace, AtomKey.from_token(prior.trial_ref))
        if trial:
            scope = "d01.method-counterevidence:" + canonical_digest((prior.trial_ref, trial["protocol_digest"]))
            pending.extend(ref for ref, raw in rows if json.loads(raw)["question_key"] == scope)
    visited = set()
    while pending:
        ref = pending.pop()
        if ref in visited: continue
        visited.add(ref)
        if len(visited) > 128: raise MissingProductionOriginalV1("bounded_method_learning_dependency_closure")
        value = locate(ref)
        if value is None: continue
        roots.extend(value.get("source_refs", ()))
        kind = AtomKey.from_token(ref).type_name
        if kind == "d07.current_interpretation.v1":
            originals.append(ref)
            if value["question_key"].startswith("d01.method-blind-review.v2:"):
                response = decode_typed_production_value_v1(json.loads(value["proposition"]), MethodBlindResponseV2)
                pending.append(response.request_ref); roots.append(response.source_ref)
        elif kind in VALUE_TYPES:
            pending.extend(value[name] for name in ("trial_ref", "protocol_ref", "gp1_interpretation_ref", "continuity_interpretation_ref", "experiment_original_ref", "experiment_ref") if name in value)
            pending.extend(value.get("evaluation_refs", ()))
            pending.extend(value.get("counter_interpretation_refs", ()))
            for row in value.get("blind_reviews", ()):
                pending.append(row["response_interpretation_ref"])
            if kind == EVALUATION_TYPE:
                milestones.extend((value["milestone_ref"], value["baseline_milestone_ref"]))
                originals.append(value["measurement_original_ref"])
    for ref in dict.fromkeys(milestones):
        value = read_current_artifact_task_milestone_v2(db, namespace=namespace, original_ref=ref, issuer=installed_readers.issuer)
        originals.append(ref); keys.append(value.source_head.key); roots.append(value.source_head.key.token)
    return production_read_plan_v1(types, keys, roots, originals)


def verify_method_learning_stage_v1(stage):
    from .domain_production_contracts_v1 import StagedDomainOperationV1
    if type(stage) is not StagedDomainOperationV1 or stage.domain != "d01" or stage.operation_kind not in OPERATIONS:
        raise TypeError("closed D01 method learning stage required")
    allowed = {REGISTER_PROPOSAL_V2: {TRIAL_PROPOSAL_TYPE_V2}, REGISTER_TRIAL_V2: {TRIAL_TYPE},
        REGISTER_BLIND_REQUEST_V2: {BLIND_REQUEST_TYPE_V2}, REGISTER_PROTOCOL: {PROTOCOL_TYPE}, REGISTER_TRIAL: {TRIAL_TYPE}, REGISTER_EXPERIMENT: {EXPERIMENT_TYPE}, REGISTER_EXPERIMENT_V2: {EXPERIMENT_TYPE},
        EVALUATE: {EVALUATION_TYPE}, REVIEW: {REVIEW_TYPE}, ADOPT: {"d01.persona_plan.v1", "d01.persona_revision.v1",
            "d01.persona_activation.v1", "d01.growth_contribution.v1"}}[stage.operation_kind]
    specs = {spec.name: spec for spec in PersonaDomain().type_specs()}
    for proposal in stage.proposals:
        if proposal.domain != "d01" or proposal.proposal_schema != "d01.proposal.v1":
            raise ValueError("method learning cannot write another domain")
        for write in proposal.typed_writes:
            if write.key.type_name not in allowed or write.key.owner.kind != "persona":
                raise ValueError("method operation crossed its finite registered write scope")
            specs[write.key.type_name].validator(write.value)
    return stage


def read_adopted_method_learning_original_v1(db, *, namespace, ref):
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    key = AtomKey.from_token(ref)
    if key.type_name not in VALUE_TYPES or NamespaceId.from_key(key) != namespace: return None
    row = _method_head(db, namespace, key)
    if row is None or row[2] != 1: return None
    history = _method_history(db, namespace, key, row[0])
    if history is None or history[1:] != row[1:]: return None
    original = read_adopted_domain_operation_v1(db, namespace, history[0])
    kind = {TRIAL_PROPOSAL_TYPE_V2: REGISTER_PROPOSAL_V2, BLIND_REQUEST_TYPE_V2: REGISTER_BLIND_REQUEST_V2, PROTOCOL_TYPE: REGISTER_PROTOCOL, TRIAL_TYPE: REGISTER_TRIAL, EXPERIMENT_TYPE: REGISTER_EXPERIMENT,
        EVALUATION_TYPE: EVALUATE, REVIEW_TYPE: REVIEW}[key.type_name]
    accepted = ({REGISTER_TRIAL, REGISTER_TRIAL_V2} if kind == REGISTER_TRIAL else
        {REGISTER_EXPERIMENT, REGISTER_EXPERIMENT_V2} if kind == REGISTER_EXPERIMENT else {kind})
    if original is None or original["domain"] != "d01" or original["operation_kind"] not in accepted: return None
    if not any(value.key == key and value.revision == row[0] for value in original["receipt"].write_versions):
        raise ValueError("method learning original lacks exact committed membership")
    value = json.loads(row[1]); decode_typed_production_value_v1(value, VALUE_TYPES[key.type_name])
    return ProductionOriginalRefV1("d01.actual-method-learning", ref, canonical_digest(value), (GraphVersion(key, row[0]),))


def stage_register_method_evaluation_protocol_v1(db, *, frame, request, installed_readers):
    return stage_current_method_learning_v1(db, frame=frame, request=request, installed_readers=installed_readers, operation_kind="register_method_evaluation_protocol_v1")


def stage_register_scoped_method_trial_v1(db, *, frame, request, installed_readers):
    return stage_current_method_learning_v1(db, frame=frame, request=request, installed_readers=installed_readers, operation_kind="register_scoped_method_trial_v1")


def stage_register_method_experiment_v1(db, *, frame, request, installed_readers):
    return stage_current_method_learning_v1(db, frame=frame, request=request, installed_readers=installed_readers, operation_kind="register_method_experiment_v1")


def stage_evaluate_current_method_outcome_v1(db, *, frame, request, installed_readers):
    return stage_current_method_learning_v1(db, frame=frame, request=request, installed_readers=installed_readers, operation_kind="evaluate_current_method_outcome_v1")


def stage_review_current_method_growth_v1(db, *, frame, request, installed_readers):
    return stage_current_method_learning_v1(db, frame=frame, request=request, installed_readers=installed_readers, operation_kind="review_current_method_growth_v1")


def stage_adopt_current_method_strategy_v1(db, *, frame, request, installed_readers):
    return stage_current_method_learning_v1(db, frame=frame, request=request, installed_readers=installed_readers, operation_kind="adopt_current_method_strategy_v1")


def stage_register_method_trial_proposal_v2(db, *, frame, request, installed_readers):
    return stage_current_method_learning_v1(db, frame=frame, request=request, installed_readers=installed_readers, operation_kind="register_method_trial_proposal_v2")


def stage_register_scoped_method_trial_v2(db, *, frame, request, installed_readers):
    return stage_current_method_learning_v1(db, frame=frame, request=request, installed_readers=installed_readers, operation_kind="register_scoped_method_trial_v2")


def stage_register_method_blind_review_request_v2(db, *, frame, request, installed_readers):
    return stage_current_method_learning_v1(db, frame=frame, request=request, installed_readers=installed_readers, operation_kind="register_method_blind_review_request_v2")


def stage_register_method_experiment_v2(db, *, frame, request, installed_readers):
    return stage_current_method_learning_v1(db, frame=frame, request=request, installed_readers=installed_readers,
        operation_kind=REGISTER_EXPERIMENT_V2)
