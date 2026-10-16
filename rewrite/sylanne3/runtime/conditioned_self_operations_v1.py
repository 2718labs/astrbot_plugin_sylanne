"""B2/B4 actual domain stages on current Work; D01 remains the sole adopter."""
from dataclasses import dataclass,replace
from ..domains.d01.conditioned_self_v1 import (CalibrationPolicyV1,CALIBRATION_POLICY_TYPE,ConditionPredicateV1,ConditionedCapabilityRevisionV1,
    ConditionedStrategyRevisionV1,ConditionedSelfReviewV1,ConditionedCalibrationViewV1,SelfViewV4,CONDITION_TYPE,CAPABILITY_TYPE,STRATEGY_TYPE,REVIEW_TYPE,conditioned_revision_record_name_v1)
from ..domains.d01.identity_v3 import RuntimeIdentityRef
from ..domains.d01.production_operations_v1 import plain_v1,stage_result_v1,ProjectSelfModelRequestV3,compile_adopt_current_growth_v1,AdoptCurrentGrowthRequestV1
from ..domains.d07.prediction_v1 import (PredictionRecordV1,PredictionResolutionV1,SimulationRecordV1,
    ConditionMatchProjectionV1,SelfDiscrepancyV1,PREDICTION_TYPE,RESOLUTION_TYPE,SIMULATION_TYPE,MATCH_TYPE,DISCREPANCY_TYPE,SimulationForecastPlanV1,FORECAST_PLAN_TYPE)
from ..graph_types import AtomKey,Owner,GraphWrite,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1,waiting_stage_v1
from .domain_production_erasure_v1 import decode_typed_production_value_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d01_general_growth_v1 import AdoptCurrentGeneralGrowthRequestV1


@dataclass(frozen=True,slots=True)
class RegisterCalibrationPolicyRequestV1:
    value: CalibrationPolicyV1

@dataclass(frozen=True,slots=True)
class RegisterConditionPredicateRequestV1:
    value: ConditionPredicateV1

@dataclass(frozen=True,slots=True)
class RegisterCurrentPredictionRequestV1:
    value: PredictionRecordV1
    forecast_plan_ref: str
    simulation_operation_id: str
    branch_ref: str
    forecast_index: int

@dataclass(frozen=True,slots=True)
class ResolveCurrentPredictionRequestV1:
    prediction_ref: str
    outcome_ref: str|None

@dataclass(frozen=True,slots=True)
class RecordCurrentSimulationRequestV1:
    value: SimulationRecordV1
    forecast_plan_ref: str
    simulation_operation_id: str

@dataclass(frozen=True,slots=True)
class RegisterSimulationForecastPlanRequestV1:
    value: SimulationForecastPlanV1

@dataclass(frozen=True,slots=True)
class ReviewCurrentConditionedSelfRequestV1:
    trigger_ref: str
    target_block: str
    predicate_ref: str
    prediction_refs: tuple[str,...]
    capability_id: str
    revision: int
    previous_ref: str|None
    strategy: ConditionedStrategyRevisionV1|None=None

@dataclass(frozen=True,slots=True)
class AdoptCurrentConditionedSelfRequestV1:
    candidate_ref: str
    expected_persona_head: GraphVersion
    general_request: AdoptCurrentGeneralGrowthRequestV1

@dataclass(frozen=True,slots=True)
class RollbackCurrentConditionedStrategyRequestV1(AdoptCurrentConditionedSelfRequestV1):
    rejected_strategy_ref: str=''

@dataclass(frozen=True,slots=True)
class ProjectCurrentSelfViewRequestV4:
    block_ids: tuple[str,...]=()
    def __post_init__(self):
        from ..domains.d01.production_operations_v1 import require_locator_v1
        if type(self.block_ids)is not tuple or len(self.block_ids)>32 or len(set(self.block_ids))!=len(self.block_ids):
            raise ValueError('SelfView selector requires at most 32 unique block IDs')
        for ref in self.block_ids:require_locator_v1(ref,'SelfView block')


def self_view_request_from_wire_v4(raw):
    if type(raw)is not dict or set(raw)!={'block_ids'}or type(raw['block_ids'])is not list:
        raise ValueError('SelfView request wire requires exactly block_ids list')
    return ProjectCurrentSelfViewRequestV4(tuple(raw['block_ids']))


def self_view_to_wire_v4(value):
    if type(value)is not SelfViewV4:raise TypeError('exact qualified actual SelfViewV4 result required')
    return plain_v1(value)

@dataclass(frozen=True,slots=True)
class MatchCurrentConditionedStrategyRequestV1:
    strategy_ref: str
    semantic_question_ref: str
    goal_ref: str
    goal_revision: int
    method_candidates: tuple[tuple[str,str],...]
    scope_project_ref: str|None=None

@dataclass(frozen=True,slots=True)
class SelectCurrentConditionedPersonalStepRequestV1:
    plan_ref: str
    goal_ref: str
    prepared_candidates_operation_id: str
    condition_match_refs: tuple[str,...]

@dataclass(frozen=True,slots=True)
class ProjectCurrentConditionedLifeStrategyRequestV1:
    project_ref: str
    recipe_ref: str
    strategy_ref: str

@dataclass(frozen=True,slots=True)
class ObserveCurrentConditionedSelfRecoveryRequestV1:
    producer_operation_id: str

OPERATIONS={
 'register_calibration_policy_v1':('d01',RegisterCalibrationPolicyRequestV1,'workbench.create'),
 'register_simulation_forecast_plan_v1':('d07',RegisterSimulationForecastPlanRequestV1,'workbench.create'),
 'select_current_conditioned_personal_step_v1':('d08',SelectCurrentConditionedPersonalStepRequestV1,'workbench.create'),
 'project_current_conditioned_life_strategy_v1':('d10',ProjectCurrentConditionedLifeStrategyRequestV1,'workbench.create'),
 'register_condition_predicate_v1':('d01',RegisterConditionPredicateRequestV1,'workbench.create'),
 'register_current_prediction_v1':('d07',RegisterCurrentPredictionRequestV1,'workbench.create'),
 'resolve_current_prediction_v1':('d07',ResolveCurrentPredictionRequestV1,'workbench.create'),
 'record_current_simulation_v1':('d07',RecordCurrentSimulationRequestV1,'workbench.create'),
 'review_current_conditioned_self_v1':('d01',ReviewCurrentConditionedSelfRequestV1,'workbench.create'),
 'adopt_current_conditioned_self_v1':('d01',AdoptCurrentConditionedSelfRequestV1,'workbench.activate'),
 'rollback_current_conditioned_strategy_v1':('d01',RollbackCurrentConditionedStrategyRequestV1,'workbench.activate'),
 'match_current_conditioned_strategy_v1':('d07',MatchCurrentConditionedStrategyRequestV1,'workbench.create')}
OWNER_CONFIGURED_CONDITIONED_OPERATIONS_V1=frozenset({
 'register_calibration_policy_v1','register_condition_predicate_v1','register_simulation_forecast_plan_v1',
 'adopt_current_conditioned_self_v1','rollback_current_conditioned_strategy_v1'})


def conditioned_request_from_wire_v1(operation_kind,raw):
    if operation_kind not in OPERATIONS or type(raw)is not dict:
        raise ValueError('exact registered conditional operation and complete typed request wire required')
    return decode_typed_production_value_v1(raw,OPERATIONS[operation_kind][1])


VALUE_TYPES={CALIBRATION_POLICY_TYPE:CalibrationPolicyV1,FORECAST_PLAN_TYPE:SimulationForecastPlanV1,CONDITION_TYPE:ConditionPredicateV1,CAPABILITY_TYPE:ConditionedCapabilityRevisionV1,
 STRATEGY_TYPE:ConditionedStrategyRevisionV1,REVIEW_TYPE:ConditionedSelfReviewV1,
 PREDICTION_TYPE:PredictionRecordV1,RESOLUTION_TYPE:PredictionResolutionV1,SIMULATION_TYPE:SimulationRecordV1,
 MATCH_TYPE:ConditionMatchProjectionV1,DISCREPANCY_TYPE:SelfDiscrepancyV1}
PRODUCERS={CALIBRATION_POLICY_TYPE:'register_calibration_policy_v1',FORECAST_PLAN_TYPE:'register_simulation_forecast_plan_v1',CONDITION_TYPE:'register_condition_predicate_v1',PREDICTION_TYPE:'register_current_prediction_v1',
 RESOLUTION_TYPE:'resolve_current_prediction_v1',SIMULATION_TYPE:'record_current_simulation_v1',
 CAPABILITY_TYPE:'review_current_conditioned_self_v1',STRATEGY_TYPE:'review_current_conditioned_self_v1',
 REVIEW_TYPE:'review_current_conditioned_self_v1',MATCH_TYPE:'match_current_conditioned_strategy_v1',
 DISCREPANCY_TYPE:'resolve_current_prediction_v1'}


def conditioned_key_v1(namespace,type_name,identity):
    return AtomKey(Owner('persona',*namespace.as_tuple),type_name,identity)


def _typed(db,read,ref,cls):
    atom=read.head(db,ref,required=True)
    if VALUE_TYPES.get(atom.key.type_name)is not cls:raise ValueError('conditional record has another exact registered type')
    value=decode_typed_production_value_v1(atom.value,cls)
    _origin(db,read,atom,PRODUCERS[atom.key.type_name])
    if value.source_refs:read.source_family(db,value.source_refs,purpose='consolidation')
    return atom,value


def _origin(db,read,atom,operation_kind=None):
    from .current_conditioned_self_read_v3 import conditioned_history_v3
    history=conditioned_history_v3(db,atom.key.token,atom.revision)
    if history is None or history[2]!=1 or canonical_serialize(atom.value)!=history[1]:
        raise MissingProductionOriginalV1('actual_conditioned_record_history_member')
    original=read_adopted_domain_operation_v1(db,read.frame.envelope.authority.namespace,history[0])
    if (original is None or operation_kind is not None and original['operation_kind']!=operation_kind
            or GraphVersion(atom.key,atom.revision)not in original['receipt'].write_versions):
        raise ValueError('conditional record lacks its exact producing COMMIT member')
    return original


def _deps(read,roots,refs=()):
    from ..memory_types import access_key
    from ..domains.d06 import source_correction_head_key
    ns=read.frame.envelope.authority.namespace
    return tuple(dict.fromkeys((*tuple(AtomKey.from_token(ref)for ref in refs),
        *(key for ref in roots for key in (AtomKey.from_token(ref),access_key(*ns.as_tuple,AtomKey.from_token(ref).owner.subject),
         source_correction_head_key(ns,AtomKey.from_token(ref).owner.subject))))))


def _write(db,read,type_name,identity,value,*,refs=()):
    ns=read.frame.envelope.authority.namespace
    if (getattr(value,'namespace',ns)!=ns or getattr(getattr(value,'runtime_identity',None),'namespace',ns)!=ns):
        raise ValueError('conditional stage crossed actual namespace')
    key=conditioned_key_v1(ns,type_name,identity)
    prior=read.head(db,key)
    if prior.revision:
        if not prior.valid or prior.value!=plain_v1(value):raise ValueError('immutable conditional original replay conflicts')
        _origin(db,read,prior,PRODUCERS[type_name]);return None
    roots=value.source_refs
    if roots:read.source_family(db,roots,purpose='consolidation')
    return GraphWrite(key,plain_v1(value),_deps(read,roots,refs))


def _active(read,readers):
    from ..domains.d01 import PersonaDomain
    return PersonaDomain().resolve_active_role(read.frame.snapshot,
        namespace=read.frame.envelope.authority.namespace,current_guard=readers.owner_guard)


def _stage(db,read,readers,kind,request,writes=(),*,contribution_keys=(),costs=(),coverage='complete',missing=(),adoption=None,**provenance):
    from .current_conditioned_self_read_v3 import require_conditioned_stage_readers_v3
    require_conditioned_stage_readers_v3(db,read.frame,readers,kind,request)
    domain=OPERATIONS[kind][0]
    if domain=='d01':
        from ..domains.d01 import PersonaDomain
        provider=PersonaDomain()
    elif domain=='d07':
        from ..domains.d07 import D07DomainProvider
        provider=D07DomainProvider()
    elif domain=='d08':
        from ..domains.d08.execution import GoalExecutionProvider
        provider=GoalExecutionProvider()
    else:
        from ..domains.d10 import LifeDomain
        provider=LifeDomain()
    provenance['conditioned_source_roots']=read.frame.envelope.source_qualification.source_refs
    provenance['conditioned_original_deadline_utc']=read.frame.envelope.deadline_utc
    from .current_conditioned_self_read_v3 import conditioned_followup_target_commitment_v3
    commitment=conditioned_followup_target_commitment_v3(db,read.frame)
    if commitment is not None:
        provenance['conditioned_followup_target_commitment']=commitment
        from .current_conditioned_self_read_v3 import conditioned_followup_frozen_targets_v3
        provenance['conditioned_frozen_targets']=conditioned_followup_frozen_targets_v3(db,read.frame)
    from .current_conditioned_self_read_v3 import conditioned_child_execution_provenance_v3
    execution=conditioned_child_execution_provenance_v3(db,read.frame)
    if execution is not None:provenance['conditioned_child_execution_v1']=execution
    events={
        'register_current_prediction_v1':(('d07','prediction_registered'),),
        'resolve_current_prediction_v1':(('d01','conditioned_calibration_resolution_committed_v1'),),
        'review_current_conditioned_self_v1':(('d01','conditioned_self_candidate_available'),),
        'adopt_current_conditioned_self_v1':(('d08','conditioned_self_adopted_requires_choice_recheck'),('d10','conditioned_self_adopted_requires_life_projection')),
        'rollback_current_conditioned_strategy_v1':(('d08','conditioned_self_adopted_requires_choice_recheck'),('d10','conditioned_self_adopted_requires_life_projection')),
        'project_current_conditioned_life_strategy_v1':(('d10','conditioned_life_strategy_projected'),)}
    stage=stage_result_v1(read.frame,domain,kind,request,writes=tuple(w for w in writes if w is not None),
        provenance=provenance,contribution_keys=contribution_keys,receiver_events=events.get(kind,())if any(w is not None for w in writes)else(),costs=costs,
        coverage=coverage,missing=missing,proposal_schema=domain+'.proposal.v1',proposal_hash=provider.descriptor.request_schema_hash)
    for proposal in stage.proposals:
        if kind in {'adopt_current_conditioned_self_v1','rollback_current_conditioned_strategy_v1'}:
            if adoption is None:raise ValueError('conditional adopter requires its live actual General compilation')
            validate_conditioned_general_adoption_proposal_v1(db,read,request,proposal,readers=readers,
                qualification=adoption[0],compiled=adoption[1])
        elif kind=='project_current_conditioned_life_strategy_v1':
            validate_conditioned_life_projection_proposal_v1(db,read,request,proposal,readers=readers,value=provenance['conditioned_life_strategy'])
        else:provider.validate(proposal,read.frame.snapshot)
    return verify_conditioned_self_stage_v1(stage)


def _register_calibration_policy(db,read,request,readers):
    value=request.value
    identity=RuntimeIdentityRef.from_owner_guard(read.frame.envelope.authority.namespace,readers.owner_guard)
    if (type(value)is not CalibrationPolicyV1 or value.runtime_identity!=identity
            or not value.valid_from<=read.frame.now_utc<value.valid_until
            or value.minimum_verified_outcomes>read.frame.limits.max_query_rows):
        raise ValueError('Owner calibration policy exceeds its actual identity, validity or installed bounded inventory')
    active=_active(read,readers)
    target=next((block for block in active.plan.blocks if block.block_id==value.review_target_block),None)
    if target is None or target.kind not in {'self_knowledge','strategy'}:
        raise ValueError('calibration policy requires its actual configured current review target')
    target_head=next(v for v in active.read_versions if v.key.type_name=='d01.persona_plan.v1')
    for ref in value.population_scope_refs:read.head(db,ref,required=True)
    write=_write(db,read,CALIBRATION_POLICY_TYPE,value.policy_id,value,refs=value.population_scope_refs)
    return _stage(db,read,readers,'register_calibration_policy_v1',request,(write,),calibration_policy=value,calibration_review_target={'persona_head':target_head,'block_id':target.block_id,'kind':target.kind})


def _calibration_policy(db,read,predicate):
    atom,policy=_typed(db,read,predicate.calibration_policy_ref,CalibrationPolicyV1)
    from .current_conditioned_self_read_v3 import conditioned_runtime_identity_v3
    if (policy.runtime_identity!=conditioned_runtime_identity_v3(db,read)or policy.runtime_identity.namespace!=predicate.namespace or policy.task_class!=predicate.task_class
            or not set(predicate.scope_refs)<=set(policy.population_scope_refs)
            or predicate.valid_from<policy.valid_from or predicate.valid_until>policy.valid_until
            or policy.minimum_verified_outcomes>read.frame.limits.max_query_rows):
        raise ValueError('conditioned calibration changed its immutable Owner policy or installed population bound')
    return atom,policy


def _register_condition(db,read,request,readers):
    value=request.value
    if type(value)is not ConditionPredicateV1 or not value.valid_from<=read.frame.now_utc<value.valid_until:
        raise ValueError('condition registration requires its actual active typed validity')
    _calibration_policy(db,read,value)
    if value.rollback_predicate_ref is not None:
        if value.rollback_predicate_ref==conditioned_key_v1(value.namespace,CONDITION_TYPE,value.predicate_id).token:
            raise ValueError('rollback condition cannot refer to itself')
        _,rollback=_typed(db,read,value.rollback_predicate_ref,ConditionPredicateV1)
        if rollback.rollback_predicate_ref is not None or not set(value.scope_refs)<=set(rollback.scope_refs):
            raise ValueError('strategy condition requires one prior registered same-scope terminal rollback condition')
    for ref in value.scope_refs:read.head(db,ref,required=True)
    write=_write(db,read,CONDITION_TYPE,value.predicate_id,value,refs=(*value.scope_refs,*(()if value.rollback_predicate_ref is None else(value.rollback_predicate_ref,))))
    return _stage(db,read,readers,'register_condition_predicate_v1',request,(write,),condition_predicate=value)


def _register_prediction(db,read,request,readers):
    value=request.value
    if type(value)is not PredictionRecordV1:raise TypeError('exact typed declared forecast required')
    _,forecast_plan,_,simulation=_actual_forecast_parent(db,read,readers,request.forecast_plan_ref,request.simulation_operation_id)
    if (type(request.forecast_index)is not int or not 0<=request.forecast_index<len(forecast_plan.forecasts)):
        raise ValueError('forecast index is outside its actual preregistered bounded plan')
    declared=forecast_plan.forecasts[request.forecast_index]
    if (replace(value,registered_at=declared.registered_at)!=declared or value.branch_ref!=request.branch_ref
            or not any(branch['branch_id']==AtomKey.from_token(request.branch_ref).name for branch in simulation['branches'])):
        raise ValueError('prediction value or branch differs from its explicitly declared actual forecast plan')
    value=replace(value,registered_at=read.frame.now_utc)
    prior=read.head(db,conditioned_key_v1(value.namespace,PREDICTION_TYPE,value.prediction_id))
    if prior.revision:
        _,saved=_typed(db,read,prior.key.token,PredictionRecordV1)
        if replace(value,registered_at=saved.registered_at)!=saved:raise ValueError('declared prediction replay changed its frozen original')
        return _stage(db,read,readers,'register_current_prediction_v1',request,prediction=saved)
    _,predicate=_typed(db,read,value.condition_predicate_ref,ConditionPredicateV1)
    _,policy=_calibration_policy(db,read,predicate)
    if (value.target_observable,value.resolution_rule)!=(policy.target_observable,policy.resolution_rule):
        raise ValueError('forecast changed its immutable calibration observable or rule')
    target=read.head(db,value.target_head.key,required=True)
    if (target.revision!=value.target_head.revision or value.task_class!=predicate.task_class
            or value.target_head.key.token not in predicate.scope_refs
            or not predicate.valid_from<=value.registered_at<value.expires_at<=predicate.valid_until):
        raise ValueError('forecast target and original conditional validity differ')
    if value.target_observable=='action_result_level' and target.key.type_name!='d08.action_intent.v1':
        raise ValueError('action forecast requires its actual planned Action head')
    if value.target_observable.startswith('artifact_') and target.key.type_name!='d08.goal.v1':
        raise ValueError('artifact forecast requires its actual task Goal')
    if value.target_observable=='life_postcondition' and target.key.type_name!='d10.life_project.v1':
        raise ValueError('Life forecast requires its actual project head')
    from .current_conditioned_self_read_v3 import require_conditioned_prediction_before_outcome_v3
    require_conditioned_prediction_before_outcome_v3(db,read,value)
    for ref in value.assumption_refs:_typed(db,read,ref,ConditionPredicateV1)
    write=_write(db,read,PREDICTION_TYPE,value.prediction_id,value,refs=(value.condition_predicate_ref,value.target_head.key.token,*value.assumption_refs))
    return _stage(db,read,readers,'register_current_prediction_v1',request,(write,),prediction=value)


def _actual_prediction_outcome(db,read,readers,prediction,outcome_ref):
    if outcome_ref!=prediction.resolution_target_ref:raise ValueError('prediction resolution substituted its frozen observer target')
    target=read.head(db,prediction.target_head.key,required=True)
    if prediction.target_observable.startswith('artifact_'):
        from .artifact_task_observer_v1 import read_current_artifact_task_milestone_v2
        actual=read_current_artifact_task_milestone_v2(db,namespace=prediction.namespace,original_ref=outcome_ref,issuer=readers.issuer)
        if actual.goal_ref!=target.key.token:raise ValueError('artifact resolution belongs to another frozen Goal')
        digest=actual.digest
        original=read.original(outcome_ref,digest=digest)
        read.source_family(db,(actual.source_head.key.token,),purpose='consolidation')
        if prediction.target_observable=='artifact_content_length':category=None;interval=(actual.readback.content_length,actual.readback.content_length)
        else:category=actual.readback.content_digest;interval=None
        from datetime import datetime
        observed=datetime.fromisoformat(actual.readback.verified_at_utc.replace('Z','+00:00')).timestamp()
        return original,digest,category,interval,observed,(actual.source_head.key.token,),False,'artifact-observation:'+canonical_digest((prediction.namespace,actual.readback.execution_call_id,actual.readback.effect_id))
    outcome=read.head(db,outcome_ref,required=True)
    _origin(db,read,outcome)
    original=read.original(outcome_ref,digest=canonical_digest(outcome.value))
    if prediction.target_observable=='action_result_level':
        from ..domains.d08.execution import _decode,_decode_intent
        if outcome.key.type_name!='d08.action_outcome.v1':raise ValueError('action resolver requires its actual Action outcome')
        actual=_decode('d08.action_outcome.v1',outcome.value);planned=_decode_intent(target.value)
        if (actual.action_id,actual.effect_id,actual.attempt_id)!=(planned.action_id,planned.identity.effect_id,planned.identity.attempt_id):
            raise ValueError('Action resolver crossed frozen Action/effect/attempt')
        for ref in actual.observation_refs:read.original(ref)
        roots=tuple(planned.source_refs)
        if roots:read.source_family(db,roots,purpose='consolidation')
        return original,canonical_digest(outcome.value),actual.result_level,None,actual.observed_at,roots,bool(actual.unknown_effects),'action-observation:'+canonical_digest((prediction.namespace,actual.effect_id,actual.attempt_id))
    from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
    from .d10_life_progress_provenance_v1 import require_current_life_progress_v1
    if outcome.key.type_name!='d10.life_progress.v1':raise ValueError('Life resolver requires its actual adopted progress')
    actual=decode_typed_production_value_v1(outcome.value,LifeProgressHeadV1)
    prepared,terminal,_=require_current_life_progress_v1(db,namespace=prediction.namespace,progress=actual,issuer=readers.issuer,read=read)
    if actual.project_ref!=target.key.token or prepared.plan.project.ref!=target.key.token:
        raise ValueError('Life resolver crossed frozen actual project')
    read.original(terminal.original_ref);read.original(terminal.binding.artifact_ref)
    from datetime import datetime
    observed=datetime.fromisoformat(terminal.payload.completed_at_utc.replace('Z','+00:00')).timestamp()
    return original,canonical_digest(outcome.value),actual.step,None,observed,actual.source_refs,terminal.status!='completed','life-observation:'+canonical_digest((prediction.namespace,terminal.binding.execution_id,terminal.binding.effect_id,terminal.binding.attempt_id))



def classify_conditioned_prediction_outcome_v1(prediction,*,now_utc,outcome_present,observed_at,
        outcome_range,outcome_category,unresolved,assumptions_witnessed):
    """Pure classification of independently verified real observation facts."""
    if type(prediction)is not PredictionRecordV1 or type(outcome_present)is not bool:
        raise TypeError('exact frozen prediction and actual outcome membership required')
    if not outcome_present:return 'expired_unknown'if now_utc>=prediction.expires_at else'unknown'
    if observed_at<prediction.registered_at:
        raise ValueError('prediction was not durably registered before its actual observed outcome')
    if unresolved or not assumptions_witnessed or observed_at>prediction.expires_at:
        return 'expired_unknown'if observed_at>prediction.expires_at else'unknown'
    if outcome_range is not None:
        low,high=prediction.predicted_range
        return'matched'if low<=outcome_range[0]<=outcome_range[1]<=high else'counterexample'if outcome_range[1]<low or outcome_range[0]>high else'unknown'
    return'matched'if outcome_category==prediction.predicted_category else'counterexample'


def conditioned_resolution_identity_v1(prediction_ref,outcome_ref,outcome_digest,status):
    if status not in{'matched','counterexample','unknown','expired_unknown'}or(outcome_ref is None)!=(outcome_digest is None):
        raise ValueError('resolution identity requires its actual classified outcome membership')
    return'prediction-resolution:'+canonical_digest((prediction_ref,None if outcome_ref is None else(outcome_ref,outcome_digest),status))[:48]


def conditioned_match_identity_v1(request,strategy_revision,condition_heads):
    if type(request)is not MatchCurrentConditionedStrategyRequestV1 or type(strategy_revision)is not int or strategy_revision<1:
        raise TypeError('match identity requires its actual typed request and strategy revision')
    return'condition-match:'+canonical_digest((request,strategy_revision,tuple(condition_heads)))[:48]


def conditioned_life_projection_identity_v1(request,project_head,recipe_head,plan_head,match_id):
    if type(request)is not ProjectCurrentConditionedLifeStrategyRequestV1 or any(type(head)is not GraphVersion for head in(project_head,recipe_head,plan_head)):
        raise TypeError('Life projection identity requires its exact actual project, recipe and plan heads')
    return'life-strategy-projection:'+canonical_digest((request,project_head,recipe_head,plan_head,match_id))[:48]

def _prediction_resolution_material_v1(db,read,request,readers):
    atom,prediction=_typed(db,read,request.prediction_ref,PredictionRecordV1)
    original=_origin(db,read,atom,'register_current_prediction_v1')
    now=read.frame.now_utc
    outcome=None;digest=category=interval=observed=observation_unit=None;roots=prediction.source_refs
    if request.outcome_ref is None:
        from .current_conditioned_self_read_v3 import require_conditioned_prediction_before_outcome_v3
        require_conditioned_prediction_before_outcome_v3(db,read,prediction)
        status=classify_conditioned_prediction_outcome_v1(prediction,now_utc=now,outcome_present=False,
            observed_at=None,outcome_range=None,outcome_category=None,unresolved=False,assumptions_witnessed=False)
    else:
        outcome,digest,category,interval,observed,actual_roots,unresolved,observation_unit=_actual_prediction_outcome(db,read,readers,prediction,request.outcome_ref)
        roots=tuple(sorted(set((*roots,*actual_roots))))
        if observed<prediction.registered_at:raise ValueError('prediction was not durably registered before its actual observed outcome')
        from .current_conditioned_self_read_v3 import require_prediction_original_sequence_v3
        require_prediction_original_sequence_v3(db,read,prediction,original,outcome)
        assumptions_witnessed=_prediction_assumptions_v1(db,read,prediction,outcome=outcome)
        status=classify_conditioned_prediction_outcome_v1(prediction,now_utc=now,outcome_present=True,
            observed_at=observed,outcome_range=interval,outcome_category=category,unresolved=unresolved,
            assumptions_witnessed=assumptions_witnessed)
    identity=conditioned_resolution_identity_v1(request.prediction_ref,None if outcome is None else outcome.original_ref,digest,status)
    value=PredictionResolutionV1(prediction.namespace,identity,request.prediction_ref,canonical_digest(atom.value),
        None if outcome is None else outcome.original_ref,digest,observation_unit,category,interval,observed,now,status,roots)
    discrepancy=None
    if status=='counterexample':
        _,predicate=_typed(db,read,prediction.condition_predicate_ref,ConditionPredicateV1)
        did='self-discrepancy:'+canonical_digest((request.prediction_ref,identity))[:48]
        resolution_ref=conditioned_key_v1(prediction.namespace,RESOLUTION_TYPE,identity).token
        discrepancy=SelfDiscrepancyV1(prediction.namespace,did,request.prediction_ref,resolution_ref,
            prediction.condition_predicate_ref,predicate.scope_refs,roots)
    return value,discrepancy


def _resolve_prediction(db,read,request,readers):
    value,discrepancy=_prediction_resolution_material_v1(db,read,request,readers)
    prior=read.head(db,conditioned_key_v1(value.namespace,RESOLUTION_TYPE,value.resolution_id))
    if prior.revision:
        _,saved=_typed(db,read,prior.key.token,PredictionResolutionV1)
        if replace(value,resolved_at=saved.resolved_at)!=saved:raise ValueError('resolution replay changed its exact actual original or calibration')
        value=saved
    writes=[_write(db,read,RESOLUTION_TYPE,value.resolution_id,value,refs=(request.prediction_ref,))]
    if discrepancy is not None:writes.append(_write(db,read,DISCREPANCY_TYPE,discrepancy.discrepancy_id,discrepancy,refs=(request.prediction_ref,)))
    return _stage(db,read,readers,'resolve_current_prediction_v1',request,tuple(writes),prediction_resolution=value,self_discrepancy=discrepancy)


def _record_simulation(db,read,request,readers):
    value=request.value
    if type(value)is not SimulationRecordV1:raise TypeError('fixed bounded actual simulation record required')
    _,plan,_,actual=_actual_forecast_parent(db,read,readers,request.forecast_plan_ref,request.simulation_operation_id)
    if value.baseline_snapshot!=plan.baseline_snapshot or value.namespace!=plan.namespace:
        raise ValueError('simulation record changed its original declared baseline')
    branches=(value.baseline,*value.alternatives)
    expected_assumptions=(plan.baseline_assumption_ref,*plan.alternative_assumption_refs)
    if len(branches)!=len(expected_assumptions)or tuple(branch.changed_assumption_refs for branch in branches)!=((),*((ref,)for ref in plan.alternative_assumption_refs)):
        raise ValueError('simulation retains the exact original baseline and at most two changed assumptions')
    for index,branch in enumerate(branches):
        recorded=next((row for row in actual['branches']if row['branch_id']==AtomKey.from_token(branch.branch_ref).name),None)
        expected=tuple(conditioned_key_v1(plan.namespace,PREDICTION_TYPE,prediction.prediction_id).token
            for prediction in plan.forecasts if prediction.branch_ref==branch.branch_ref)
        if (recorded is None or actual['branches'][index]['branch_id']!=AtomKey.from_token(branch.branch_ref).name)or branch.prediction_refs!=expected or recorded['content_reality']!='simulated'or recorded['evidence_eligibility']!='none':
            raise ValueError('simulation record substituted its true branch or declaration membership')
    for version in value.baseline_snapshot:
        if read.head(db,version.key,required=True).revision!=version.revision:
            raise MissingProductionOriginalV1('actual_frozen_simulation_baseline')
    for branch in (value.baseline,*value.alternatives):
        for ref in branch.changed_assumption_refs:_typed(db,read,ref,ConditionPredicateV1)
    write=_write(db,read,SIMULATION_TYPE,value.simulation_id,value,refs=tuple(v.key.token for v in value.baseline_snapshot))
    return _stage(db,read,readers,'record_current_simulation_v1',request,(write,),simulation=value,forecast_plan=plan)



def _conditioned_review_id_v1(persona_head,target_block,predicate_ref,record_id,revision,resolution_refs,trigger_ref,method_review_ref):
    return 'conditioned-review:'+canonical_digest((persona_head,target_block,predicate_ref,record_id,revision,
        tuple(resolution_refs),trigger_ref,method_review_ref))[:48]

def _conditioned_review_material_v1(db,read,request,readers):
    active=_active(read,readers);ns=read.frame.envelope.authority.namespace
    runtime_identity=RuntimeIdentityRef.from_owner_guard(ns,readers.owner_guard)
    block=next((block for block in active.plan.blocks if block.block_id==request.target_block),None)
    if block is None or block.kind not in {'self_knowledge','strategy'}:
        raise ValueError('conditional review targets only Self knowledge or strategy')
    _,predicate=_typed(db,read,request.predicate_ref,ConditionPredicateV1)
    _,policy=_calibration_policy(db,read,predicate)
    if request.target_block!=policy.review_target_block:
        raise ValueError('review cannot replace its actual Owner-configured target block')
    trigger=read.head(db,request.trigger_ref,required=True);trigger_counter=None
    if trigger.key.type_name==RESOLUTION_TYPE:
        _,resolution=_typed(db,read,request.trigger_ref,PredictionResolutionV1)
        _,trigger_prediction=_typed(db,read,resolution.prediction_ref,PredictionRecordV1)
        trigger_predicate_ref=trigger_prediction.condition_predicate_ref
        if resolution.calibration_status=='counterexample':trigger_counter=(request.trigger_ref,resolution)
    elif trigger.key.type_name==DISCREPANCY_TYPE:
        _,discrepancy=_typed(db,read,request.trigger_ref,SelfDiscrepancyV1)
        trigger_predicate_ref=discrepancy.condition_predicate_ref
        _,resolution=_typed(db,read,discrepancy.resolution_ref,PredictionResolutionV1)
        if resolution.calibration_status!='counterexample':raise ValueError('discrepancy lacks its actual counterexample resolution')
        trigger_counter=(discrepancy.resolution_ref,resolution)
    else:raise ValueError('conditional review requires its true resolution or D07 discrepancy precursor')
    calibration=_current_prediction_calibration_v1(db,read,request.predicate_ref,predicate)
    actual_predictions,resolution_refs,counterexamples,counts,unknown,roots,support=(calibration.prediction_refs,
        calibration.resolution_refs,calibration.counterexamples,dict(calibration.counts),calibration.unknown_count,
        calibration.source_refs,calibration.support_families)
    if tuple(sorted(request.prediction_refs))!=actual_predictions:
        raise MissingProductionOriginalV1('complete_actual_conditional_prediction_denominator')
    heads=tuple(v for v in active.read_versions if v.key.type_name=='d01.persona_plan.v1')
    if len(heads)!=1:raise ValueError('conditional review requires its exact active persona CAS head')
    review_id=_conditioned_review_id_v1(heads[0],request.target_block,request.predicate_ref,request.capability_id,request.revision,
        resolution_refs,request.trigger_ref,None if request.strategy is None else request.strategy.method_outcome_review_ref)
    review_ref=conditioned_key_v1(ns,REVIEW_TYPE,review_id).token
    qualification='qualified'if calibration.threshold_met else'unknown'if not sum(counts.values())else'limited'
    if request.previous_ref is not None:
        cls=ConditionedStrategyRevisionV1 if block.kind=='strategy'else ConditionedCapabilityRevisionV1
        _,previous=_typed(db,read,request.previous_ref,cls)
        identity=previous.strategy_id if cls is ConditionedStrategyRevisionV1 else previous.capability_id
        if previous.runtime_identity!=runtime_identity or request.revision!=previous.revision+1 or request.capability_id!=identity:
            raise ValueError('conditional revision did not retain its actual predecessor/runtime identity')
    if trigger_predicate_ref!=request.predicate_ref:
        if (block.kind!='strategy'or request.previous_ref is None or trigger_counter is None
                or previous.condition_predicate_ref!=trigger_predicate_ref
                or block.claim!=canonical_serialize(plain_v1(previous))):
            raise ValueError('condition review substituted its true trigger instead of narrowing the actual current strategy')
        resolution_refs=tuple(dict.fromkeys((*resolution_refs,trigger_counter[0])))
        counterexamples=tuple(dict.fromkeys((*counterexamples,trigger_counter[0])))
        roots=tuple(sorted(set((*roots,*trigger_counter[1].source_refs))))
    if block.kind=='self_knowledge':
        candidate=ConditionedCapabilityRevisionV1(runtime_identity,request.capability_id,request.revision,request.previous_ref,
            predicate.task_class,request.predicate_ref,predicate.scope_refs,tuple(sorted(support)),tuple(counterexamples),actual_predictions,
            tuple(resolution_refs),tuple(counts.items()),unknown,calibration.observation_unit_count,calibration.policy_ref,
            calibration.policy_digest,calibration.minimum_verified_outcomes,calibration.coverage,review_ref,predicate.valid_from,
            predicate.valid_until,'sample_threshold_met'if calibration.threshold_met else qualification,roots)
        candidate_type=CAPABILITY_TYPE
    else:
        candidate=request.strategy
        if (type(candidate)is not ConditionedStrategyRevisionV1 or candidate.runtime_identity!=runtime_identity
                or (candidate.strategy_id,candidate.revision,candidate.previous_ref)!=(request.capability_id,request.revision,request.previous_ref)
                or candidate.review_ref!=review_ref or candidate.condition_predicate_ref!=request.predicate_ref
                or predicate.rollback_predicate_ref is None or candidate.rollback_predicate_ref!=predicate.rollback_predicate_ref
                or candidate.applicable_scope!=predicate.scope_refs or candidate.support_families!=tuple(sorted(support))
                or candidate.counterexamples!=tuple(counterexamples) or candidate.source_refs!=roots
                or not predicate.valid_from<=candidate.valid_from<=read.frame.now_utc<candidate.valid_until<=predicate.valid_until):
            raise ValueError('strategy candidate differs from actual calibrated conditional review')
        rollback_candidate=candidate.qualification=='rolled_back'
        if rollback_candidate:
            if(request.previous_ref is None or trigger_counter is None or block.claim!=canonical_serialize(plain_v1(previous))
                    or candidate.preferred_method!=previous.alternative_method or candidate.alternative_method!=previous.preferred_method
                    or not set(candidate.applicable_scope)<=set(previous.applicable_scope)
                    or not set(previous.exclusions)<=set(candidate.exclusions)
                    or candidate.method_outcome_review_ref!=previous.method_outcome_review_ref):
                raise ValueError('rollback candidate must withdraw the actual adopted method within its existing scope')
            qualification='rollback_evidence_qualified'
            candidate=replace(candidate,qualification='rolled_back')
        elif counterexamples:
            if request.previous_ref is None:raise MissingProductionOriginalV1('actual_previous_strategy_for_counterexample_narrowing')
            _,old_predicate=_typed(db,read,previous.condition_predicate_ref,ConditionPredicateV1)
            if (not set(old_predicate.conditions)<set(predicate.conditions)
                    or not set(predicate.scope_refs)<=set(old_predicate.scope_refs)
                    or not set(previous.exclusions)<=set(candidate.exclusions)):
                raise ValueError('actual counterexample must narrow a candidate and preserve prior exclusions')
            candidate=replace(candidate,qualification='narrowed')
        else:candidate=replace(candidate,qualification='candidate'if qualification!='qualified'else'qualified')
        _,rollback_predicate=_typed(db,read,candidate.rollback_predicate_ref,ConditionPredicateV1)
        if not set(candidate.applicable_scope)<=set(rollback_predicate.scope_refs):
            raise ValueError('strategy rollback predicate does not cover its actual candidate scope')
        candidate_type=STRATEGY_TYPE
    candidate_id=conditioned_revision_record_name_v1(namespace=ns,type_name=candidate_type,record_id=request.capability_id,
        revision=request.revision,review_ref=review_ref)
    candidate_ref=conditioned_key_v1(ns,candidate_type,candidate_id).token
    review=ConditionedSelfReviewV1(runtime_identity,review_id,request.target_block,heads[0],request.predicate_ref,
        actual_predictions,tuple(resolution_refs),candidate_ref,roots,qualification,('unresolved_actual_outcomes',)if unknown else())
    return review,candidate,candidate_type,candidate_id


def _review_self(db,read,request,readers):
    review,candidate,candidate_type,candidate_id=_conditioned_review_material_v1(db,read,request,readers)
    refs=(request.predicate_ref,*review.prediction_refs,*review.resolution_refs)
    writes=(_write(db,read,candidate_type,candidate_id,candidate,refs=refs),
        _write(db,read,REVIEW_TYPE,review.review_id,review,refs=refs))
    return _stage(db,read,readers,'review_current_conditioned_self_v1',request,writes,conditioned_self_review=review,conditioned_self_candidate=candidate)


def _adopt_self(db,read,request,readers,*,rollback=False):
    from .d01_general_growth_v1 import read_current_general_growth_v1
    from ..domains.d01.conditioned_self_v1 import decode_conditioned_self_claim_v1
    active=_active(read,readers);atom=read.head(db,request.candidate_ref,required=True)
    cls=VALUE_TYPES.get(atom.key.type_name)
    if cls not in {ConditionedCapabilityRevisionV1,ConditionedStrategyRevisionV1}:raise ValueError('only exact conditional Self candidates may reach adopter')
    _,candidate=_typed(db,read,request.candidate_ref,cls)
    _,review=_typed(db,read,candidate.last_review_ref if cls is ConditionedCapabilityRevisionV1 else candidate.review_ref,ConditionedSelfReviewV1)
    current=tuple(v for v in active.read_versions if v.key.type_name=='d01.persona_plan.v1')
    target=next((block for block in active.plan.blocks if block.block_id==review.target_block),None)
    required_kind='self_knowledge'if cls is ConditionedCapabilityRevisionV1 else'strategy'
    if (current!=(request.expected_persona_head,)or review.expected_persona_head!=request.expected_persona_head
            or candidate.runtime_identity!=RuntimeIdentityRef.from_owner_guard(active.plan.namespace,readers.owner_guard)
            or review.candidate_ref!=request.candidate_ref or target is None or target.kind!=required_kind
            or target.plasticity!='growth' or review.qualification!=('rollback_evidence_qualified'if rollback else'qualified')
            or not candidate.valid_from<=read.frame.now_utc<candidate.valid_until):
        raise MissingProductionOriginalV1('current_exact_calibrated_candidate_and_explicit_D01_adopter_scope')
    if candidate.previous_ref is not None:
        current_claim=decode_conditioned_self_claim_v1(target.claim)
        _,previous=_typed(db,read,candidate.previous_ref,cls)
        if previous!=current_claim or candidate.revision!=previous.revision+1:
            raise ValueError('conditional adopter would replace another semantic revision')
    elif candidate.revision!=1:raise ValueError('initial conditional semantic revision must be one')
    if rollback:
        if (cls is not ConditionedStrategyRevisionV1 or request.rejected_strategy_ref!=candidate.previous_ref
                or candidate.qualification!='rolled_back'or not candidate.counterexamples):
            raise ValueError('rollback must retain and supersede its actual rejected strategy revision')
        require_conditioned_rollback_predicate_v1(db,read,candidate.rollback_predicate_ref,candidate.applicable_scope)
        for ref in candidate.counterexamples:
            _,counter=_typed(db,read,ref,PredictionResolutionV1)
            _,prediction=_typed(db,read,counter.prediction_ref,PredictionRecordV1)
            if counter.calibration_status!='counterexample'or prediction.condition_predicate_ref!=previous.condition_predicate_ref:
                raise ValueError('rollback substituted a counterexample of another actual adopted strategy')
    if cls is ConditionedStrategyRevisionV1 and not rollback:
        from ..domains.d01.method_learning_v1 import TRIAL_METHOD,BASELINE_METHOD
        if(candidate.preferred_method,candidate.alternative_method)!=(TRIAL_METHOD,BASELINE_METHOD):
            raise ValueError('current method benefit original supports only its actual treatment/baseline direction')
        require_conditioned_method_benefit_original_v1(db,read,candidate.method_outcome_review_ref,readers,candidate=candidate)
    inputs,provenance=read_current_general_growth_v1(readers.base,db,read.frame,request.general_request)
    proposal=inputs.proposal
    if (proposal.base_head!=active.plan.head_id or proposal.target_block!=review.target_block
            or proposal.replacement_claim!=canonical_serialize(plain_v1(candidate))or proposal.replacement_claim==target.claim):
        raise ValueError('explicit General proposal changed the exact conditional candidate or its actual trials')
    old_request=AdoptCurrentGrowthRequestV1(request.general_request.growth_proposal_ref,request.general_request.trigger_original_ref,
        request.general_request.trial_original_refs,request.general_request.counterevidence_query_ref)
    qualification=_ConditionedGrowthQualificationV1(_CONDITIONED_ADOPTION_ISSUER_V1,read.frame,request.candidate_ref,candidate)
    inputs=replace(inputs,semantic_qualification=qualification)
    try:
        adopted=compile_adopt_current_growth_v1(read.frame,old_request,inputs)
        _CONDITIONED_COMPILED_ADOPTIONS_V1[qualification]=adopted
        if not adopted.proposals:return waiting_stage_v1(read.frame,'d01',
            'rollback_current_conditioned_strategy_v1'if rollback else'adopt_current_conditioned_self_v1',request,
            MissingProductionOriginalV1(*(adopted.missing_inputs or('actual_complete_General_adoption_qualification',))))
        provenance.update({'conditioned_candidate_ref':request.candidate_ref,'conditioned_candidate_digest':canonical_digest(atom.value),
            'conditioned_review_ref':candidate.last_review_ref if cls is ConditionedCapabilityRevisionV1 else candidate.review_ref,
            'growth':__import__('json').loads(adopted.original_payload_json)['provenance'],'rollback':rollback,'conditioned_self_candidate':candidate,
            'candidate_method_trials':candidate.trial_refs if cls is ConditionedStrategyRevisionV1 else(),
            'general_required_trials':request.general_request.trial_original_refs})
        writes=tuple(write for proposal in adopted.proposals for write in proposal.typed_writes)
        kind='rollback_current_conditioned_strategy_v1'if rollback else'adopt_current_conditioned_self_v1'
        return _stage(db,read,readers,kind,request,writes,
            contribution_keys=tuple(key for proposal in adopted.proposals for key in proposal.contribution_keys),
            costs=adopted.paid_cost_originals,coverage=adopted.coverage,missing=adopted.missing_inputs,adoption=(qualification,adopted),**provenance)
    finally:
        _CONDITIONED_COMPILED_ADOPTIONS_V1.pop(qualification,None)
        _CONDITIONED_ADOPTIONS_V1.pop(qualification,None)


def _condition_facts_v1(db,read,goal,predicate):
    from ..domains.d07 import decode_method_condition_question_v1
    inventory=read.complete_inventory(db,'d07.current_interpretation.v1')
    pages=tuple(page for page in read.frame.query_coverage if page.type_id=='d07.current_interpretation.v1')
    if len(pages)!=1 or not pages[0].complete:raise MissingProductionOriginalV1('complete_actual_D07_condition_match_coverage')
    values={};heads=[];roots=set(predicate.source_refs)
    for atom in inventory:
        if not atom.valid or atom.value.get('current')is not True:continue
        scope=decode_method_condition_question_v1(atom.value.get('question_key'))
        if scope is None or(scope['goal_ref'],scope['goal_revision'])!=(goal.key.token,goal.value['revision']):continue
        _origin(db,read,atom,'adopt_current_c1_method_conditions_v1')
        condition=scope['condition_id']
        if condition not in dict(predicate.conditions):continue
        if condition in values:raise MissingProductionOriginalV1('unique_actual_current_condition_interpretation')
        roots.update(atom.value['source_refs']);heads.append(GraphVersion(atom.key,atom.revision))
        values[condition]=(atom.value['proposition']=='true')if(atom.value['stance']=='support'
            and atom.value['evidence_status']=='supported'and not atom.value['meaningful_unknowns']
            and atom.value['proposition']in {'true','false'})else None
    if roots:read.source_family(db,tuple(sorted(roots)),purpose='consolidation')
    return values,tuple(heads),tuple(sorted(roots)),pages[0]


def _forecast_goal_v1(db,read,prediction):
    target=read.head(db,prediction.target_head.key,required=True)
    if target.key.type_name=='d08.goal.v1':return target
    if target.key.type_name=='d08.action_intent.v1':
        from ..domains.d08.execution import _decode_intent
        intent=_decode_intent(target.value)
        goals=tuple(atom for atom in read.complete_inventory(db,'d08.goal.v1')
            if atom.valid and atom.value['goal_id']==intent.goal_ref)
        if len(goals)!=1:raise MissingProductionOriginalV1('exact_actual_forecast_Action_Goal')
        return goals[0]
    if target.key.type_name=='d10.life_project.v1':
        from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1,decode_project_checkpoint_type_v1,CHECKPOINT_TYPE
        from ..domains.d08.personal_plan_v1 import decode_personal_plan_type_v1,PLAN_TYPE
        checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,read.head(db,
            project_checkpoint_key_v1(prediction.namespace,target.key.token),required=True).value)
        plan=decode_personal_plan_type_v1(PLAN_TYPE,read.head(db,checkpoint.plan_ref,required=True).value)
        if checkpoint.plan_revision!=plan.revision:raise MissingProductionOriginalV1('actual_forecast_Life_plan_revision')
        return read.head(db,plan.goal_ref,required=True)
    raise ValueError('forecast has no registered actual Goal target')


def _prediction_assumptions_v1(db,read,prediction,*,outcome=None):
    _,predicate=_typed(db,read,prediction.condition_predicate_ref,ConditionPredicateV1)
    if outcome is None:
        goal=_forecast_goal_v1(db,read,prediction)
        if (GraphVersion(goal.key,goal.revision),goal.value['revision'])!=(prediction.condition_goal_head,prediction.condition_goal_revision):
            raise ValueError('forecast plan changed its frozen actual Goal condition scope')
        values,heads,roots,_=_condition_facts_v1(db,read,goal,predicate)
        if heads!=prediction.assumption_heads:raise ValueError('forecast plan substituted its original current D07 assumption versions')
        if not set(roots)<=set(prediction.source_refs):raise ValueError('forecast omitted its actual assumption Source roots')
    else:
        from .current_conditioned_self_read_v3 import conditioned_prediction_execution_assumptions_v3
        facts=conditioned_prediction_execution_assumptions_v3(db,read,prediction,outcome)
        if facts is None:return False
        from ..domains.d07 import decode_method_condition_question_v1
        if tuple(version for version,_,_ in facts)!=prediction.assumption_heads:
            raise ValueError('actual execution assumption EOF changed its frozen exact versions')
        values={}
        for version,raw,producer in facts:
            scope=decode_method_condition_question_v1(raw.get('question_key'))
            if (scope is None or(scope['goal_ref'],scope['goal_revision'])!=
                    (prediction.condition_goal_head.key.token,prediction.condition_goal_revision)
                    or scope['condition_id']not in dict(predicate.conditions)or scope['condition_id']in values):
                raise ValueError('actual historical execution condition crossed its frozen typed Goal scope')
            values[scope['condition_id']]=(raw['proposition']=='true')if(raw['stance']=='support'
                and raw['evidence_status']=='supported'and not raw['meaningful_unknowns']
                and raw['proposition']in {'true','false'})else None
    return all(key in values and values[key]is not None and values[key]==value for key,value in predicate.conditions)


def _condition_project_scope_v1(db,read,project_ref,goal,*,selected_plan_ref=None):
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1,decode_project_checkpoint_type_v1,CHECKPOINT_TYPE
    from ..domains.d08.personal_plan_v1 import decode_personal_plan_type_v1,PLAN_TYPE
    project=read.head(db,project_ref,required=True)
    if project.key.type_name!='d10.life_project.v1':raise ValueError('conditional scope has another actual project type')
    atom=read.head(db,project_checkpoint_key_v1(read.frame.envelope.authority.namespace,project_ref),required=True)
    checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,atom.value)
    plan=decode_personal_plan_type_v1(PLAN_TYPE,read.head(db,checkpoint.plan_ref,required=True).value)
    if (checkpoint.plan_revision!=plan.revision or plan.goal_ref!=goal.key.token or plan.goal_revision!=goal.value['revision']
            or selected_plan_ref is not None and checkpoint.plan_ref!=selected_plan_ref):
        raise MissingProductionOriginalV1('actual_conditional_Project_checkpoint_plan_Goal_scope')
    return project


def read_current_conditioned_match_v1(db,read,request,readers):
    from ..domains.d07 import decode_method_condition_question_v1
    strategy_atom,strategy=_typed(db,read,request.strategy_ref,ConditionedStrategyRevisionV1)
    active=_active(read,readers)
    adopted=tuple(block for block in active.plan.blocks if block.kind=='strategy'
        and block.claim==canonical_serialize(plain_v1(strategy)))
    if len(adopted)!=1:raise MissingProductionOriginalV1('actual_adopted_conditional_strategy_persona_member')
    _,predicate=_typed(db,read,strategy.condition_predicate_ref,ConditionPredicateV1)
    goal=read.head(db,request.goal_ref,required=True)
    if goal.key.type_name!='d08.goal.v1'or goal.value['revision']!=request.goal_revision:
        raise MissingProductionOriginalV1('current_actual_conditional_strategy_Goal')
    if request.semantic_question_ref is not None:
        question=read.head(db,request.semantic_question_ref,required=True)
        if question.key.type_name!='d07.current_interpretation.v1':raise ValueError('matching requires its actual current D07 semantic question')
        scope=decode_method_condition_question_v1(question.value.get('question_key'))
        if scope is None or(scope['goal_ref'],scope['goal_revision'])!=(goal.key.token,request.goal_revision):
            raise ValueError('condition matching question crossed its actual Goal scope')
        _origin(db,read,question,'adopt_current_c1_method_conditions_v1')
    values,heads,predicate_roots,page=_condition_facts_v1(db,read,goal,predicate)
    roots=set((*strategy.source_refs,*predicate_roots));gaps=[]
    scope_refs={goal.key.token}
    if request.scope_project_ref is not None:
        _condition_project_scope_v1(db,read,request.scope_project_ref,goal)
        scope_refs.add(request.scope_project_ref)
    project_scope_required=any(AtomKey.from_token(ref).type_name=='d10.life_project.v1'for ref in strategy.applicable_scope)
    _,rollback=_typed(db,read,strategy.rollback_predicate_ref,ConditionPredicateV1)
    rollback_values,rollback_heads,rollback_roots,_=_condition_facts_v1(db,read,goal,rollback)
    roots.update(rollback_roots);heads=tuple(dict.fromkeys((*heads,*rollback_heads)))
    rollback_covered=(bool(scope_refs.intersection(rollback.scope_refs))and rollback.valid_from<=read.frame.now_utc<rollback.valid_until
        and all(key in rollback_values and rollback_values[key]is not None for key,_ in rollback.conditions))
    rollback_triggered=rollback_covered and all(rollback_values[key]==value for key,value in rollback.conditions)
    matching='matched'
    if (strategy.qualification=='rolled_back'or rollback_triggered or scope_refs.intersection(strategy.exclusions)
            or not strategy.valid_from<=read.frame.now_utc<strategy.valid_until
            or not predicate.valid_from<=read.frame.now_utc<predicate.valid_until):matching='excluded'
    elif not rollback_covered:
        matching='unknown';gaps.append('current_rollback_predicate_not_covered')
    elif project_scope_required and request.scope_project_ref is None:
        matching='unknown';gaps.append('project_scope_not_covered')
    elif not scope_refs.intersection(strategy.applicable_scope):matching='excluded'
    elif request.semantic_question_ref is None or any(key not in values or values[key]is None for key,_ in predicate.conditions):
        matching='unknown';gaps.append('incomplete_actual_condition_evidence')
    elif any(values[key]!=value for key,value in predicate.conditions):matching='excluded'
    roots=tuple(sorted(roots))
    if roots:read.source_family(db,roots,purpose='consolidation')
    pairs=request.method_candidates
    if len(pairs)>6 or len({ref for ref,_ in pairs})!=len(pairs):raise ValueError('bounded exact conditional method candidates required')
    preferred=tuple(ref for ref,method in pairs if method==strategy.preferred_method)
    alternatives=tuple(ref for ref,method in pairs if method==strategy.alternative_method)
    edges=tuple((a,b)for a in preferred for b in alternatives if a!=b)if matching=='matched'else()
    identity=conditioned_match_identity_v1(request,strategy_atom.revision,heads)
    return ConditionMatchProjectionV1(active.plan.namespace,identity,request.strategy_ref,canonical_digest(strategy_atom.value),
        strategy.condition_predicate_ref,predicate.scope_refs,request.semantic_question_ref,request.scope_project_ref,tuple(heads),page.epoch.revision,True,matching,edges,roots,tuple(gaps))


def _match_strategy(db,read,request,readers):
    if not request.semantic_question_ref:raise ValueError('formal D07 matching requires its actual semantic question selector')
    value=read_current_conditioned_match_v1(db,read,request,readers)
    prior=read.head(db,conditioned_key_v1(value.namespace,MATCH_TYPE,value.match_id))
    if prior.revision:
        _,saved=_typed(db,read,prior.key.token,ConditionMatchProjectionV1)
        if replace(value,coverage_epoch=saved.coverage_epoch)!=saved:raise ValueError('condition matching replay changed actual semantic evidence')
        value=saved
    write=_write(db,read,MATCH_TYPE,value.match_id,value,refs=(request.strategy_ref,request.goal_ref,*tuple(v.key.token for v in value.condition_heads)))
    return _stage(db,read,readers,'match_current_conditioned_strategy_v1',request,(write,),condition_match=value)


def read_current_self_view_v4(db,read,request,readers):
    from ..domains.d01.conditioned_self_v1 import decode_conditioned_self_claim_v1
    active=_active(read,readers);runtime_identity=RuntimeIdentityRef.from_owner_guard(active.plan.namespace,readers.owner_guard)
    semantic=readers.base.read_self_model_v3(db,read.frame,ProjectSelfModelRequestV3(request.block_ids))
    capabilities=[];strategies=[];calibrations=[];gaps=[]
    for block in active.plan.blocks:
        if block.kind not in {'self_knowledge','strategy'}or request.block_ids and block.block_id not in request.block_ids:continue
        import json
        try:raw=json.loads(block.claim)
        except ValueError:continue
        if type(raw)is not dict or raw.get('schema')not in {'d01.conditioned-capability-revision.v1','d01.conditioned-strategy-revision.v1'}:continue
        value=decode_conditioned_self_claim_v1(block.claim)
        if value.runtime_identity!=runtime_identity:raise ValueError('SelfView changed stable RuntimeIdentity')
        value_type=CAPABILITY_TYPE if type(value)is ConditionedCapabilityRevisionV1 else STRATEGY_TYPE
        identity=conditioned_revision_record_name_v1(namespace=value.runtime_identity.namespace,type_name=value_type,
            record_id=value.capability_id if value_type==CAPABILITY_TYPE else value.strategy_id,revision=value.revision,
            review_ref=value.last_review_ref if value_type==CAPABILITY_TYPE else value.review_ref)
        ref=conditioned_key_v1(active.plan.namespace,value_type,identity).token
        _,actual=_typed(db,read,ref,type(value))
        if actual!=value:raise ValueError('SelfView semantic claim differs from its actual D01 reviewed revision')
        if not value.valid_from<=read.frame.now_utc<value.valid_until:gaps.append('expired_conditional_revision:'+ref);continue
        _,predicate=_typed(db,read,value.condition_predicate_ref,ConditionPredicateV1)
        if not predicate.valid_from<=read.frame.now_utc<predicate.valid_until:gaps.append('expired_conditional_predicate:'+ref);continue
        if value_type==CAPABILITY_TYPE:
            calibration=_current_prediction_calibration_v1(db,read,value.condition_predicate_ref,predicate)
            calibrations.append((ref,ConditionedCalibrationViewV1(ref,calibration.prediction_refs,calibration.resolution_refs,
                calibration.counterexamples,calibration.counts,calibration.unknown_count,calibration.observation_unit_count,
                calibration.policy_ref,calibration.policy_digest,calibration.minimum_verified_outcomes,calibration.coverage,
                calibration.threshold_met,calibration.source_refs)))
        (capabilities if value_type==CAPABILITY_TYPE else strategies).append((ref,value))
    commitments=tuple(atom.key.token for atom in read.complete_inventory(db,'d08.commitment.v1')if atom.valid
        and atom.value.get('fulfillment_state')not in {'fulfilled','cancelled'})
    limits=tuple(atom.key.token for atom in read.complete_inventory(db,'d02.body_state.v1')if atom.valid)
    head=next(v for v in active.read_versions if v.key.type_name=='d01.persona_plan.v1')
    return SelfViewV4(runtime_identity,head,semantic,tuple(capabilities),tuple(strategies),limits,commitments,
        read.frame.snapshot.versions,tuple(gaps),tuple(calibrations))


def stage_current_conditioned_self_v1(db,*,frame,request,installed_readers,operation_kind):
    from .current_conditioned_self_read_v3 import require_conditioned_stage_readers_v3
    require_conditioned_stage_readers_v3(db,frame,installed_readers,operation_kind,request)
    read=CurrentDomainReadV1(frame)
    try:
        read.check(db)
        return {'register_calibration_policy_v1':_register_calibration_policy,'register_simulation_forecast_plan_v1':_register_forecast_plan,
            'select_current_conditioned_personal_step_v1':_select_personal,
            'project_current_conditioned_life_strategy_v1':_project_life,
            'register_condition_predicate_v1':_register_condition,'register_current_prediction_v1':_register_prediction,
            'resolve_current_prediction_v1':_resolve_prediction,'record_current_simulation_v1':_record_simulation,
            'review_current_conditioned_self_v1':_review_self,'adopt_current_conditioned_self_v1':_adopt_self,
            'rollback_current_conditioned_strategy_v1':lambda db,read,request,readers:_adopt_self(db,read,request,readers,rollback=True),
'match_current_conditioned_strategy_v1':_match_strategy}[operation_kind](
                db,read,request,installed_readers)
    except MissingProductionOriginalV1 as missing:return waiting_stage_v1(frame,OPERATIONS[operation_kind][0],operation_kind,request,missing)


def _select_personal(db,read,request,readers):
    from .d08_personal_plan_v1 import stage_select_current_personal_step_in_transaction_v2
    from ..domains.d08.personal_candidate_v1 import SelectCurrentPersonalStepRequestV2
    from ..domains.d08.personal_plan_v1 import (QualifiedPersonalCandidateV1,select_personal_step_v2,
        decode_personal_plan_type_v1,DECISION_TYPE,PLAN_TYPE)
    legacy=SelectCurrentPersonalStepRequestV2(request.plan_ref,request.goal_ref,request.prepared_candidates_operation_id)
    base=stage_select_current_personal_step_in_transaction_v2(db,frame=read.frame,request=legacy,installed_readers=readers.personal)
    if not base.proposals:return waiting_stage_v1(read.frame,'d08','select_current_conditioned_personal_step_v1',request,
        MissingProductionOriginalV1(*base.missing_inputs))
    import json
    provenance=json.loads(base.original_payload_json)['provenance']
    candidates=decode_typed_production_value_v1(provenance['candidate_evidence'],tuple[QualifiedPersonalCandidateV1,...])
    old=decode_personal_plan_type_v1(DECISION_TYPE,provenance['decision'])
    plan=decode_personal_plan_type_v1(PLAN_TYPE,read.head(db,request.plan_ref,required=True).value)
    eligible={row.candidate_ref for row in candidates if row.hard_status=='eligible'}
    edges=set(old.preference_edges);matches=[]
    if len(request.condition_match_refs)>6 or len(set(request.condition_match_refs))!=len(request.condition_match_refs):
        raise ValueError('conditional choice keeps the existing six candidate bound')
    for ref in request.condition_match_refs:
        _,saved=_typed(db,read,ref,ConditionMatchProjectionV1)
        match_request=MatchCurrentConditionedStrategyRequestV1(saved.strategy_ref,saved.semantic_question_ref,request.goal_ref,plan.goal_revision,plan.method_candidates,saved.scope_project_ref)
        if saved.scope_project_ref is not None:_condition_project_scope_v1(db,read,saved.scope_project_ref,read.head(db,request.goal_ref,required=True),selected_plan_ref=request.plan_ref)
        current=read_current_conditioned_match_v1(db,read,match_request,readers)
        if replace(current,coverage_epoch=saved.coverage_epoch)!=saved:
            raise MissingProductionOriginalV1('current_same_exact_conditioned_method_match')
        matches.append(saved)
        if current.matching=='matched':edges.update((a,b)for a,b in current.preference_edges if a in eligible and b in eligible)
    from ..runtime_contracts import VersionedRef
    roots=tuple(sorted(set((*old.source_refs,*(ref for match in matches for ref in match.source_refs)))))
    versions=tuple(VersionedRef(v.key.token,v.revision)for v in read.frame.snapshot.versions if v.revision>0)
    record=select_personal_step_v2(decision_id=old.decision_id,candidates=candidates,preference_edges=tuple(sorted(edges)),
        source_refs=roots,read_versions=versions)
    write=base.proposals[0].typed_writes[0]
    provenance.update({'decision':record,'conditioned_matches':tuple(matches),'hard_eligibility_before_conditioned_preferences':True})
    return _stage(db,read,readers,'select_current_conditioned_personal_step_v1',request,(replace(write,value=plain_v1(record),dependencies=tuple(v.key for v in read.frame.snapshot.versions if v.revision>0 and v.key!=write.key)),),**provenance)


def _conditioned_life_projection_material_v1(db,read,request,readers):
    from ..domains.d10.production_operations_v1 import ConditionedLifeStrategyProjectionV1
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1,decode_project_checkpoint_type_v1,CHECKPOINT_TYPE
    from ..domains.d08.personal_plan_v1 import decode_personal_plan_type_v1,PLAN_TYPE
    project=read.head(db,request.project_ref,required=True);recipe=read.head(db,request.recipe_ref,required=True)
    if (project.key.type_name!='d10.life_project.v1'or recipe.key.type_name!='d10.activity_recipe.v1'
            or project.value['next_step']not in recipe.value['allowed_steps']):
        raise ValueError('conditioned Life projection changed actual project/recipe current step')
    checkpoint_atom=read.head(db,project_checkpoint_key_v1(read.frame.envelope.authority.namespace,request.project_ref),required=True)
    checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,checkpoint_atom.value)
    plan_atom=read.head(db,checkpoint.plan_ref,required=True);plan=decode_personal_plan_type_v1(PLAN_TYPE,plan_atom.value)
    if checkpoint.plan_revision!=plan.revision:raise MissingProductionOriginalV1('current_actual_Life_project_plan_revision')
    goal=read.head(db,plan.goal_ref,required=True)
    _,strategy=_typed(db,read,request.strategy_ref,ConditionedStrategyRevisionV1)
    matching=read_current_conditioned_match_v1(db,read,MatchCurrentConditionedStrategyRequestV1(request.strategy_ref,_condition_question_locator_v1(db,read,goal.key.token,plan.goal_revision),
        goal.key.token,plan.goal_revision,plan.method_candidates,request.project_ref),readers)
    identity=conditioned_life_projection_identity_v1(request,GraphVersion(project.key,project.revision),
        GraphVersion(recipe.key,recipe.revision),GraphVersion(plan_atom.key,plan_atom.revision),matching.match_id)
    value=ConditionedLifeStrategyProjectionV1(read.frame.envelope.authority.namespace,identity,
        GraphVersion(project.key,project.revision),GraphVersion(recipe.key,recipe.revision),GraphVersion(plan_atom.key,plan_atom.revision),
        GraphVersion(goal.key,goal.revision),request.strategy_ref,canonical_digest(plain_v1(strategy)),matching,
        strategy.preferred_method,strategy.alternative_method,strategy.support_families,strategy.exclusions,
        strategy.counterexamples,strategy.rollback_predicate_ref,matching.source_refs)
    return value


def _project_life(db,read,request,readers):
    from ..domains.d10.production_operations_v1 import ConditionedLifeStrategyProjectionV1
    value=_conditioned_life_projection_material_v1(db,read,request,readers)
    matching=value.condition_match
    key=conditioned_key_v1(value.namespace,'d10.conditioned_strategy_projection.v1',value.projection_id)
    prior=read.head(db,key)
    if prior.revision:
        saved=decode_typed_production_value_v1(prior.value,ConditionedLifeStrategyProjectionV1);_origin(db,read,prior,'project_current_conditioned_life_strategy_v1')
        if replace(value,condition_match=replace(matching,coverage_epoch=saved.condition_match.coverage_epoch))!=saved:
            raise ValueError('Life strategy projection replay changed its actual current semantic basis')
        value=saved;write=None
    else:write=GraphWrite(key,plain_v1(value),tuple(v.key for v in read.frame.snapshot.versions if v.revision>0 and v.key!=key))
    return _stage(db,read,readers,'project_current_conditioned_life_strategy_v1',request,(write,),conditioned_life_strategy=value)


def require_current_conditioned_life_projection_v1(db,read,projection_ref,projection_digest,*,project_ref,recipe_ref,issuer):
    from ..domains.d10.production_operations_v1 import ConditionedLifeStrategyProjectionV1
    from .current_conditioned_self_read_v3 import require_conditioned_life_projection_consumer_v3
    readers=require_conditioned_life_projection_consumer_v3(db,read,issuer)
    atom=read.head(db,projection_ref,required=True)
    if atom.key.type_name!='d10.conditioned_strategy_projection.v1'or canonical_digest(atom.value)!=projection_digest:
        raise ValueError('Life strategy consumer changed its actual original ref/digest')
    _origin(db,read,atom,'project_current_conditioned_life_strategy_v1')
    value=decode_typed_production_value_v1(atom.value,ConditionedLifeStrategyProjectionV1)
    if (value.project_head.key.token,value.recipe_head.key.token)!=(project_ref,recipe_ref):
        raise ValueError('Life strategy consumer crossed actual project/recipe')
    for version in (value.project_head,value.recipe_head,value.plan_head,value.goal_head):
        if read.head(db,version.key,required=True).revision!=version.revision:
            raise MissingProductionOriginalV1('current_Life_strategy_projection_basis')
    from ..domains.d08.personal_plan_v1 import decode_personal_plan_type_v1,PLAN_TYPE
    plan=decode_personal_plan_type_v1(PLAN_TYPE,read.head(db,value.plan_head.key,required=True).value)
    current=read_current_conditioned_match_v1(db,read,MatchCurrentConditionedStrategyRequestV1(value.strategy_ref,value.condition_match.semantic_question_ref,
        value.goal_head.key.token,plan.goal_revision,plan.method_candidates,project_ref),readers)
    if replace(current,coverage_epoch=value.condition_match.coverage_epoch)!=value.condition_match:
        raise MissingProductionOriginalV1('current_D07_complete_conditional_Life_match')
    return value


@dataclass(frozen=True,slots=True)
class _CalibrationReadoutV1:
    prediction_refs: tuple[str,...]
    resolution_refs: tuple[str,...]
    counterexamples: tuple[str,...]
    counts: tuple[tuple[str,int],...]
    unknown_count: int
    source_refs: tuple[str,...]
    support_families: tuple[str,...]
    observation_unit_count: int
    policy_ref: str
    policy_digest: str
    minimum_verified_outcomes: int
    coverage: float
    threshold_met: bool


def _current_prediction_calibration_v1(db,read,predicate_ref,predicate):
    policy_atom,policy=_calibration_policy(db,read,predicate)
    inventory=read.complete_inventory(db,PREDICTION_TYPE)
    actual_predictions=tuple(sorted(atom.key.token for atom in inventory if atom.valid
        and atom.value['condition_predicate_ref']==predicate_ref))
    resolution_inventory=read.complete_inventory(db,RESOLUTION_TYPE)
    resolutions=[];counterexamples=[];roots=set((*predicate.source_refs,*policy.source_refs));support=set();items=[]
    for ref in actual_predictions:
        atom,prediction=_typed(db,read,ref,PredictionRecordV1)
        if (prediction.task_class!=policy.task_class or prediction.target_observable!=policy.target_observable
                or prediction.resolution_rule!=policy.resolution_rule or prediction.target_head.key.token not in policy.population_scope_refs):
            raise ValueError('prediction calibration crossed its actual registered population, observable or rule')
        roots.update(prediction.source_refs)
        choices=[]
        for item in resolution_inventory:
            if not item.valid or item.value['prediction_ref']!=ref:continue
            _,value=_typed(db,read,item.key.token,PredictionResolutionV1)
            if value.prediction_digest!=canonical_digest(atom.value):raise ValueError('resolution substituted its frozen prediction')
            choices.append((value.resolved_at,item.key.token,value))
        observed=[item for item in choices if item[2].observation_unit_ref is not None]
        if len({(item[2].observation_unit_ref,item[2].outcome_ref,item[2].outcome_digest)for item in observed})>1:
            raise ValueError('one prediction cannot claim different independent actual outcomes')
        chosen=max(observed or choices,default=None)
        value=None if chosen is None else chosen[2]
        if chosen is not None:
            resolution_ref=chosen[1];resolutions.append(resolution_ref);roots.update(value.source_refs)
            if value.calibration_status=='counterexample':counterexamples.append(resolution_ref)
        items.append((prediction.resolution_target_ref,None if value is None else value.observation_unit_ref,value))
    target_units={}
    for target,unit,_ in items:
        if unit is None:continue
        if target in target_units and target_units[target]!=unit:raise ValueError('one frozen observer target claimed different physical observation units')
        target_units[target]=unit
    units={}
    for target,unit,value in items:
        key=unit or target_units.get(target)or('unobserved-target:'+target)
        units.setdefault(key,[]).append(value)
    counts={'matched':0,'counterexample':0};unknown=0
    for values in units.values():
        statuses={None if value is None else value.calibration_status for value in values}
        if len(statuses)!=1 or next(iter(statuses))not in counts:unknown+=1;continue
        status=next(iter(statuses));counts[status]+=1
        if status=='matched':
            for value in values:
                records=read.source_family(db,value.source_refs,purpose='consolidation')if value.source_refs else{}
                support.update(record.provenance_root for record in records.values())
    known=sum(counts.values());total=len(units)
    threshold=(known>=policy.minimum_verified_outcomes
        and(policy.missing_outcome_policy=='report_known_and_unknown'or unknown==0)
        and policy.valid_from<=read.frame.now_utc<policy.valid_until)
    return _CalibrationReadoutV1(actual_predictions,tuple(resolutions),tuple(counterexamples),tuple(counts.items()),unknown,
        tuple(sorted(roots)),tuple(sorted(support)),total,predicate.calibration_policy_ref,canonical_digest(policy_atom.value),
        policy.minimum_verified_outcomes,known/total if total else 0.0,threshold)


from weakref import WeakKeyDictionary
_CONDITIONED_ADOPTION_ISSUER_V1=object()
_CONDITIONED_ADOPTIONS_V1=WeakKeyDictionary()
_CONDITIONED_COMPILED_ADOPTIONS_V1=WeakKeyDictionary()

class _ConditionedGrowthQualificationV1:
    def __init__(self,issuer,frame,candidate_ref,candidate):
        if issuer is not _CONDITIONED_ADOPTION_ISSUER_V1:raise ValueError('actual conditional adopter issuer required')
        self.frame,self.candidate_ref,self.candidate=frame,candidate_ref,candidate
        _CONDITIONED_ADOPTIONS_V1[self]=(frame,candidate_ref,candidate,frame.envelope.identity.operation_id,frame.snapshot.versions)


def require_conditioned_growth_qualification_v1(qualification,*,plan,proposal,candidate):
    if (type(qualification)is not _ConditionedGrowthQualificationV1
            or _CONDITIONED_ADOPTIONS_V1.get(qualification)!=(qualification.frame,qualification.candidate_ref,qualification.candidate,
                qualification.frame.envelope.identity.operation_id,qualification.frame.snapshot.versions)
            or qualification.frame.envelope.identity.phase not in {'adopt_current_conditioned_self_v1','rollback_current_conditioned_strategy_v1'}
            or qualification.candidate!=candidate or proposal.base_head!=plan.head_id
            or proposal.replacement_claim!=canonical_serialize(plain_v1(candidate))):
        raise ValueError('conditional Self semantics require their actual explicit D01 adopter qualification')
    target=next((block for block in plan.blocks if block.block_id==proposal.target_block),None)
    kind='self_knowledge'if type(candidate)is ConditionedCapabilityRevisionV1 else'strategy'
    if target is None or target.kind!=kind:raise ValueError('conditional adopter cannot change another persona block kind')
    return qualification


@dataclass(frozen=True,slots=True)
class ConditionedSelfRecoveryObservationV1:
    producer_operation_id: str
    original_digest: str
    receipt_digest: str
    original_write_versions: tuple[GraphVersion,...]
    current_versions: tuple[GraphVersion,...]
    status: str
    waiting_for: tuple[str,...]
    schema: str='d01.conditioned-self-recovery-observation.v1'


def read_conditioned_self_recovery_v1(db,*,work,frame,producer_operation_id,issuer):
    from .current_conditioned_self_read_v3 import require_conditioned_recovery_observer_v3,conditioned_recovery_original_v3
    require_conditioned_recovery_observer_v3(db,work=work,frame=frame,producer_operation_id=producer_operation_id,issuer=issuer)
    original=conditioned_recovery_original_v3(db,frame.envelope.authority.namespace,producer_operation_id,work=work,issuer=issuer)
    if original is None or original['operation_kind']not in OPERATIONS:
        raise MissingProductionOriginalV1('actual_registered_conditioned_producer_original')
    receipt=original['receipt']
    if receipt.operation_id!=producer_operation_id or receipt.status not in {'committed','duplicate'}:
        raise ValueError('conditional recovery cannot substitute another actual producing COMMIT')
    read=CurrentDomainReadV1(frame);read.check(db)
    versions=[];waiting=[]
    for version in receipt.write_versions:
        atom=read.head(db,version.key)
        versions.append(GraphVersion(atom.key,atom.revision))
        if not atom.valid or atom.revision!=version.revision:
            waiting.append('superseded_or_invalid:'+version.key.token)
    payload=original['payload']['provenance']
    resolution=payload.get('prediction_resolution')
    if resolution is not None and resolution['calibration_status']in {'unknown','expired_unknown'}:
        waiting.append('actual_frozen_observer_result:'+resolution['prediction_ref'])
    if original['operation_kind']=='review_current_conditioned_self_v1':
        waiting.append('explicit_current_Owner_D01_adopter')
    return ConditionedSelfRecoveryObservationV1(producer_operation_id,original['original_digest'],canonical_digest(receipt),
        receipt.write_versions,tuple(versions),'waiting'if waiting else'observed_original',tuple(waiting))


def _register_forecast_plan(db,read,request,readers):
    value=request.value
    if type(value)is not SimulationForecastPlanV1:raise TypeError('exact explicit simulation forecast declaration required')
    prior=read.head(db,conditioned_key_v1(value.namespace,FORECAST_PLAN_TYPE,value.plan_id))
    if prior.revision:
        _,saved=_typed(db,read,prior.key.token,SimulationForecastPlanV1)
        replay=replace(value,declared_at=saved.declared_at,forecasts=tuple(replace(item,registered_at=saved.declared_at)for item in value.forecasts))
        if replay!=saved:raise ValueError('forecast plan replay changed its actual frozen declaration')
        return _stage(db,read,readers,'register_simulation_forecast_plan_v1',request,forecast_plan=saved)
    value=replace(value,declared_at=read.frame.now_utc,forecasts=tuple(replace(item,registered_at=read.frame.now_utc)for item in value.forecasts))
    from .d07_execution_v1 import read_registered_simulation_request_v1
    from ..domains.d07 import _stable_id
    from .current_conditioned_self_read_v3 import require_conditioned_forecast_preregistration_v3
    require_conditioned_forecast_preregistration_v3(db,read,value)
    registered=read_registered_simulation_request_v1(db,readers.issuer,value.namespace,value.simulation_request_ref)
    if (registered.activity_id!=value.simulation_activity_id or registered.baseline!=value.baseline_assumption_ref
            or registered.alternatives!=value.alternative_assumption_refs
            or set(value.source_refs)!=set(registered.snapshot_refs)
            or any(not set(prediction.source_refs)<=set(value.source_refs)for prediction in value.forecasts)
            or tuple(v.key.token for v in value.baseline_snapshot)!=registered.snapshot_refs):
        raise ValueError('forecast plan changed its actual registered simulation baseline and assumptions')
    for version in value.baseline_snapshot:
        if read.head(db,version.key,required=True).revision!=version.revision:
            raise MissingProductionOriginalV1('actual_preregistered_forecast_baseline_versions')
    branches={AtomKey(Owner('activity',*value.namespace.as_tuple,registered.activity_id),'d07.simulation_branch.v1',
        _stable_id('simulation',{'activity':registered.activity_id,'index':index,'assumption':assumption,'snapshot':registered.snapshot_refs})).token:assumption
        for index,assumption in enumerate((registered.baseline,*registered.alternatives))}
    for prediction in value.forecasts:
        if prediction.branch_ref not in branches:raise ValueError('declared forecast has another actual planned simulation branch')
        if prediction.assumption_refs!=(branches[prediction.branch_ref],)or prediction.condition_predicate_ref!=branches[prediction.branch_ref]:
            raise ValueError('forecast condition must be its actual registered branch assumption')
        _,predicate=_typed(db,read,prediction.condition_predicate_ref,ConditionPredicateV1)
        _,policy=_calibration_policy(db,read,predicate)
        if (prediction.target_observable,prediction.resolution_rule)!=(policy.target_observable,policy.resolution_rule):
            raise ValueError('forecast plan changed its actual immutable calibration observable')
        _prediction_assumptions_v1(db,read,prediction)
        target=read.head(db,prediction.target_head.key,required=True)
        if target.revision!=prediction.target_head.revision:raise MissingProductionOriginalV1('current_declared_forecast_target')
        from .current_conditioned_self_read_v3 import require_conditioned_prediction_before_outcome_v3
        require_conditioned_prediction_before_outcome_v3(db,read,prediction)
    write=_write(db,read,FORECAST_PLAN_TYPE,value.plan_id,value,refs=tuple(v.key.token for v in value.baseline_snapshot))
    return _stage(db,read,readers,'register_simulation_forecast_plan_v1',request,(write,),forecast_plan=value)


def _actual_forecast_parent(db,read,readers,plan_ref,simulation_operation_id):
    atom,plan=_typed(db,read,plan_ref,SimulationForecastPlanV1)
    original=read_adopted_domain_operation_v1(db,plan.namespace,simulation_operation_id)
    if original is None or(original['domain'],original['operation_kind'])!=('d07','run_simulation'):
        raise MissingProductionOriginalV1('actual_adopted_simulation_producer_COMMIT')
    provenance=original['payload']['provenance'];behavior=provenance['behavior'];execution=provenance['execution']
    if (provenance['status']not in {'staged','already_recorded'}or execution is None
            or(behavior['forecast_plan_ref'],behavior['forecast_plan_digest'],behavior['forecast_mode'])!=
                (plan_ref,canonical_digest(atom.value),'declared_forecast')
            or behavior['registered_request_ref']!=plan.simulation_request_ref
            or plan.declared_at>execution['started_at']or execution['work_kind']!='simulation'
            or behavior['content_reality']!='hypothetical'or behavior['external_evidence_eligibility']!='none'):
        raise ValueError('forecast plan was not durably bound before its actual simulation execution')
    from .current_conditioned_self_read_v3 import require_forecast_plan_before_execution_v3
    require_forecast_plan_before_execution_v3(db,read,plan_ref,original)
    return atom,plan,original,behavior['simulation_result']


def read_simulation_forecast_binding_v1(db,*,frame,registered,simulation_request_ref,execution):
    from .current_d07_simulation_source_read_v3 import (require_current_d07_simulation_source_frame_v3,read_current_d07_simulation_forecast_plan_v3)
    source_reader=require_current_d07_simulation_source_frame_v3(db,frame=frame,simulation_request_ref=simulation_request_ref)
    record=read_current_d07_simulation_forecast_plan_v3(source_reader,frame=frame,simulation_request_ref=simulation_request_ref)
    if record is None:return None
    atom,plan=record
    if (type(plan)is not SimulationForecastPlanV1 or plan.simulation_request_ref!=simulation_request_ref
            or plan.simulation_activity_id!=registered.activity_id or plan.baseline_assumption_ref!=registered.baseline
            or plan.alternative_assumption_refs!=registered.alternatives
            or tuple(v.key.token for v in plan.baseline_snapshot)!=registered.snapshot_refs):
        raise ValueError('simulation prepare changed its exact preregistered typed forecast binding')
    current={v.key:v.revision for v in frame.snapshot.versions}
    if current.get(atom.key)!=atom.revision or any(current.get(v.key)!=v.revision for v in plan.baseline_snapshot):
        raise MissingProductionOriginalV1('actual_simulation_forecast_plan_and_baseline_in_frozen_request_commit')
    read=CurrentDomainReadV1(frame);_origin(db,read,atom,'register_simulation_forecast_plan_v1')
    if execution is not None and plan.declared_at>execution.started_at:
        raise ValueError('simulation cannot retroactively add a declared forecast plan')
    return atom.key.token,canonical_digest(atom.value)


def read_conditioned_self_view_v4(db,*,work,frame,request,readers):
    from .current_conditioned_self_read_v3 import require_conditioned_self_view_observer_v3
    require_conditioned_self_view_observer_v3(db,work=work,frame=frame,request=request,readers=readers)
    if type(request)is not ProjectCurrentSelfViewRequestV4:raise TypeError('exact typed SelfView selector required')
    read=CurrentDomainReadV1(frame);read.check(db)
    return read_current_self_view_v4(db,read,request,readers)


def _condition_question_locator_v1(db,read,goal_ref,goal_revision):
    from ..domains.d07 import decode_method_condition_question_v1
    refs=[]
    for atom in read.complete_inventory(db,'d07.current_interpretation.v1'):
        if not atom.valid or atom.value.get('current')is not True:continue
        scope=decode_method_condition_question_v1(atom.value.get('question_key'))
        if scope is not None and(scope['goal_ref'],scope['goal_revision'])==(goal_ref,goal_revision):refs.append(atom.key.token)
    return min(refs)if refs else None


def require_conditioned_method_benefit_original_v1(db,read,review_ref,readers,*,candidate):
    from ..domains.d01.method_learning_v1 import (MethodOutcomeReviewV1,MethodScopedTrialV1,
        MethodEvaluationProtocolV1,MethodEvaluationV1,evaluate_method_benefit_v1)
    from .d01_method_learning_v1 import _typed_head,_milestone,_blind_reviews,_policy,OBSERVATION_KIND
    from .d11_life_preparation_v1 import _read
    review_atom,review=_typed_head(db,read,review_ref,MethodOutcomeReviewV1)
    _origin(db,read,review_atom,'review_current_method_growth_v1')
    trial_atom,trial=_typed_head(db,read,review.trial_ref,MethodScopedTrialV1)
    _origin(db,read,trial_atom)
    protocol_atom,protocol=_typed_head(db,read,review.protocol_ref,MethodEvaluationProtocolV1)
    _origin(db,read,protocol_atom,'register_method_evaluation_protocol_v1')
    if (review.qualification!='qualified'or review.protocol_digest!=canonical_digest(protocol_atom.value)
            or trial.protocol_digest!=review.protocol_digest or len(review.evaluation_refs)<protocol.required_project_trials):
        raise MissingProductionOriginalV1('actual_frozen_method_benefit_protocol_and_review')
    _policy(read,protocol)
    for ref in candidate.applicable_scope:
        scope=read.head(db,ref,required=True)
        if scope.key.type_name=='d08.goal.v1':goal=scope
        elif scope.key.type_name=='d10.life_project.v1':
            from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1,decode_project_checkpoint_type_v1,CHECKPOINT_TYPE
            from ..domains.d08.personal_plan_v1 import decode_personal_plan_type_v1,PLAN_TYPE
            checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,read.head(db,
                project_checkpoint_key_v1(review.namespace,scope.key.token),required=True).value)
            plan=decode_personal_plan_type_v1(PLAN_TYPE,read.head(db,checkpoint.plan_ref,required=True).value)
            goal=read.head(db,plan.goal_ref,required=True);_condition_project_scope_v1(db,read,scope.key.token,goal)
        else:raise ValueError('method benefit has no registered actual Goal/project scope')
        if goal.key.token not in trial.goal_refs:
            raise MissingProductionOriginalV1('actual_method_benefit_scope_cannot_expand_to_untried_Goal')
    inventory=read.complete_inventory(db,'d01.method_evaluation.v1')
    if {atom.key.token for atom in inventory if atom.valid and atom.value['trial_ref']==review.trial_ref}!=set(review.evaluation_refs):
        raise MissingProductionOriginalV1('complete_actual_method_benefit_evaluation_inventory')
    counter_scope='d01.method-counterevidence:'+canonical_digest((review.trial_ref,trial.protocol_digest))
    for atom in read.complete_inventory(db,'d07.current_interpretation.v1'):
        if not atom.valid or not atom.value['current']or atom.value['question_key']!=counter_scope:continue
        read.original(atom.key.token,digest=canonical_digest(atom.value))
        read.source_family(db,tuple(atom.value['source_refs']),purpose='consolidation')
        if(atom.value['stance']=='oppose'and atom.value['evidence_status']=='supported'or atom.value['meaningful_unknowns']
                or atom.value['evidence_status']in {'insufficient','conflicted'}):
            raise MissingProductionOriginalV1('actual_unresolved_or_supported_method_counterevidence')
    projects=set();families=set()
    for ref in review.evaluation_refs:
        atom,value=_typed_head(db,read,ref,MethodEvaluationV1);_origin(db,read,atom,'evaluate_current_method_outcome_v1')
        if value.trial_ref!=review.trial_ref or value.protocol_digest!=review.protocol_digest or value.source_scope!='PRODUCTION':
            raise ValueError('conditioned strategy substituted its actual comparison scope')
        actual,_=_milestone(db,read,value.milestone_ref,readers.issuer)
        baseline,_=_milestone(db,read,value.baseline_milestone_ref,readers.issuer)
        if (actual.digest,actual.readback.content_digest,baseline.digest,baseline.readback.content_digest)!=(
                value.milestone_digest,value.artifact_digest,value.baseline_milestone_digest,value.baseline_artifact_digest):
            raise MissingProductionOriginalV1('actual_conditioned_strategy_comparison_artifacts')
        measured=_read(db,issuer=readers.issuer,namespace=value.namespace,kind=OBSERVATION_KIND,ref=value.measurement_original_ref)
        if measured is None or canonical_digest(measured[0])!=value.measurement_original_digest:
            raise MissingProductionOriginalV1('actual_conditioned_strategy_measurement_original')
        read.original(value.measurement_original_ref,kind='d11.life_'+OBSERVATION_KIND,digest=value.measurement_original_digest)
        blind=_blind_reviews(db,read,tuple(row.response_interpretation_ref for row in value.blind_reviews),
            experiment_ref=value.experiment_original_ref,actual=actual,baseline=baseline)
        benefit,gaps=evaluate_method_benefit_v1(protocol,value.metrics,blind)
        if benefit!='supported'or gaps or blind!=value.blind_reviews or value.method_benefit!='supported':
            raise MissingProductionOriginalV1('actual_conditioned_strategy_method_benefit')
        read.source_family(db,value.source_refs,purpose='consolidation');projects.add(value.project_ref);families.add(value.evidence_family)
    if len(projects)!=len(review.evaluation_refs)or len(families)!=len(review.evaluation_refs):
        raise ValueError('conditioned method benefit cannot duplicate one project or evidence family')
    return review


_STAGE_RECORDS_V1={
 'register_calibration_policy_v1':(('calibration_policy',CALIBRATION_POLICY_TYPE,'policy_id'),),
 'register_condition_predicate_v1':(('condition_predicate',CONDITION_TYPE,'predicate_id'),),
 'register_simulation_forecast_plan_v1':(('forecast_plan',FORECAST_PLAN_TYPE,'plan_id'),),
 'register_current_prediction_v1':(('prediction',PREDICTION_TYPE,'prediction_id'),),
 'resolve_current_prediction_v1':(('prediction_resolution',RESOLUTION_TYPE,'resolution_id'),('self_discrepancy',DISCREPANCY_TYPE,'discrepancy_id')),
 'record_current_simulation_v1':(('simulation',SIMULATION_TYPE,'simulation_id'),),
 'review_current_conditioned_self_v1':(('conditioned_self_review',REVIEW_TYPE,'review_id'),),
 'match_current_conditioned_strategy_v1':(('condition_match',MATCH_TYPE,'match_id'),),
 'project_current_conditioned_life_strategy_v1':(('conditioned_life_strategy','d10.conditioned_strategy_projection.v1','projection_id'),)}



def _validate_conditioned_source_provenance_v1(raw,namespace,source_refs):
    from .domain_production_erasure_v1 import DomainProductionErasureHold
    import math
    roots=decode_typed_production_value_v1(raw['conditioned_source_roots'],tuple[str,...])
    deadline=decode_typed_production_value_v1(raw['conditioned_original_deadline_utc'],float)
    if (len(set(roots))!=len(roots) or deadline<=0 or not math.isfinite(deadline)
            or not set(source_refs)<=set(roots)):
        raise DomainProductionErasureHold('conditional original changed its complete Source roots or actual original deadline')
    for ref in roots:
        key=AtomKey.from_token(ref)
        if key.token!=ref or key.type_name!='memory.source' or NamespaceId.from_key(key)!=namespace:
            raise DomainProductionErasureHold('conditional original Source roots crossed their actual namespace')
    return roots


def validate_conditioned_business_provenance_v1(domain,kind,raw):
    """Decode the twelve fixed semantic originals; this grants no current authority."""
    from .domain_production_erasure_v1 import (DomainProductionErasureHold,_exact,_references,
        _validate_personal_candidate_provenance_v1,validate_domain_stage_provenance_v1)
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    from .d01_general_growth_v1 import GeneralGrowthIntentOriginalV1
    from ..domains.d10.production_operations_v1 import ConditionedLifeStrategyProjectionV1
    if kind not in OPERATIONS or domain!=OPERATIONS[kind][0] or type(raw)is not dict:
        raise DomainProductionErasureHold('unregistered conditional semantic original writer or exact shape')
    if raw=={}:return ()
    from ..authority_service.conditioned_child_contract_v1 import (CHILD_DOMAINS,ConditionedChildSelectorV1,
        conditioned_child_from_wire_v1,validate_conditioned_frozen_targets_v1)
    execution=raw.get('conditioned_child_execution_v1')
    if execution is not None:
        selector=conditioned_child_from_wire_v1(execution,ConditionedChildSelectorV1)
        if(kind not in CHILD_DOMAINS or selector.operation_kind!=kind or CHILD_DOMAINS[kind]!=domain
                or selector.parent_budget_lease_ref is None):
            raise DomainProductionErasureHold('conditioned reserved execution is outside its exact seven-child semantic recipe')
        if selector.phase=='child':
            frozen=validate_conditioned_frozen_targets_v1(raw.get('conditioned_frozen_targets'),namespace=selector.namespace)
            if canonical_serialize(frozen)!=selector.frozen_targets_json:
                raise DomainProductionErasureHold('conditioned reserved frozen targets differ from their actual selector')
            commitment={'schema':'d01.conditioned-followup-target-commitment.v1','dedupe_key':selector.dedupe_key,
                'targets_digest':selector.targets_digest,'target_census_digest':selector.target_census_digest,
                'producer_receipt_digest':selector.producer_receipt_digest,'child_id':selector.operation_id}
            if raw.get('conditioned_followup_target_commitment')!=commitment:
                raise DomainProductionErasureHold('conditioned reserved target commitment differs from its exact selector')
        elif 'conditioned_frozen_targets'in raw or 'conditioned_followup_target_commitment'in raw:
            raise DomainProductionErasureHold('conditioned inline choice cannot borrow a durable frozen target event')
        raw={key:value for key,value in raw.items()if key not in {'conditioned_child_execution_v1','conditioned_frozen_targets'}}
    elif kind in CHILD_DOMAINS or 'conditioned_frozen_targets'in raw:
        raise DomainProductionErasureHold('conditioned semantic child lacks its exact private Core execution provenance')
    common={'conditioned_source_roots','conditioned_original_deadline_utc'}
    reserved={'conditioned_followup_target_commitment'}&set(raw)
    shapes={
      'register_calibration_policy_v1':{'calibration_policy':CalibrationPolicyV1,'calibration_review_target':None},
      'register_condition_predicate_v1':{'condition_predicate':ConditionPredicateV1},
      'register_simulation_forecast_plan_v1':{'forecast_plan':SimulationForecastPlanV1},
      'register_current_prediction_v1':{'prediction':PredictionRecordV1},
      'resolve_current_prediction_v1':{'prediction_resolution':PredictionResolutionV1,'self_discrepancy':SelfDiscrepancyV1|None},
      'record_current_simulation_v1':{'simulation':SimulationRecordV1,'forecast_plan':SimulationForecastPlanV1},
      'review_current_conditioned_self_v1':{'conditioned_self_review':ConditionedSelfReviewV1,
        'conditioned_self_candidate':ConditionedCapabilityRevisionV1|ConditionedStrategyRevisionV1},
      'match_current_conditioned_strategy_v1':{'condition_match':ConditionMatchProjectionV1},
      'project_current_conditioned_life_strategy_v1':{'conditioned_life_strategy':ConditionedLifeStrategyProjectionV1},
      'adopt_current_conditioned_self_v1':{'general_growth_intent':GeneralGrowthIntentOriginalV1,
        'trial_start_originals':tuple[ProductionOriginalRefV1,...],'trial_originals':tuple[ProductionOriginalRefV1,...],
        'conditioned_candidate_ref':str,'conditioned_candidate_digest':str,'conditioned_review_ref':str,
        'growth':None,'rollback':bool,'conditioned_self_candidate':ConditionedCapabilityRevisionV1|ConditionedStrategyRevisionV1,
        'candidate_method_trials':tuple[str,...],'general_required_trials':tuple[str,...]},
    }
    shapes['rollback_current_conditioned_strategy_v1']=shapes['adopt_current_conditioned_self_v1']
    if kind=='select_current_conditioned_personal_step_v1':
        keys={'conditioned_matches','hard_eligibility_before_conditioned_preferences'}
        if not common|keys<=set(raw):
            raise DomainProductionErasureHold('conditional choice requires both actual metadata and hard preference fields')
        legacy={key:value for key,value in raw.items()if key not in common|reserved|keys}
        _validate_personal_candidate_provenance_v1('d08','select_personal_step_v2',legacy)
        matches=decode_typed_production_value_v1(raw['conditioned_matches'],tuple[ConditionMatchProjectionV1,...])
        from ..domains.d08.personal_plan_v1 import DecisionRecordV2
        decision=decode_typed_production_value_v1(legacy['decision'],DecisionRecordV2)
        if raw['hard_eligibility_before_conditioned_preferences']is not True or len(matches)>6:
            raise DomainProductionErasureHold('conditional preference cannot replace original bounded hard eligibility')
        namespace=NamespaceId.from_key(AtomKey.from_token(decision.source_refs[0]))
        if any(match.namespace!=namespace for match in matches):
            raise DomainProductionErasureHold('conditional selection has another current match namespace')
        sources=(*decision.source_refs,*(ref for match in matches for ref in match.source_refs))
    else:
        shape=shapes[kind]
        _exact(raw,set(shape)|common|reserved)
        values={name:decode_typed_production_value_v1(raw[name],cls)for name,cls in shape.items()if cls is not None}
        primary=next(iter(values.values()))
        if kind in {'adopt_current_conditioned_self_v1','rollback_current_conditioned_strategy_v1'}:
            candidate=values['conditioned_self_candidate'];namespace=candidate.runtime_identity.namespace
            review_ref=candidate.last_review_ref if type(candidate)is ConditionedCapabilityRevisionV1 else candidate.review_ref
            record_id=candidate.capability_id if type(candidate)is ConditionedCapabilityRevisionV1 else candidate.strategy_id
            type_name=CAPABILITY_TYPE if type(candidate)is ConditionedCapabilityRevisionV1 else STRATEGY_TYPE
            expected=conditioned_key_v1(namespace,type_name,conditioned_revision_record_name_v1(namespace=namespace,
                type_name=type_name,record_id=record_id,revision=candidate.revision,review_ref=review_ref)).token
            if (values['conditioned_candidate_ref']!=expected or values['conditioned_candidate_digest']!=canonical_digest(plain_v1(candidate))
                    or values['conditioned_review_ref']!=review_ref or values['rollback']!=(kind=='rollback_current_conditioned_strategy_v1')
                    or values['candidate_method_trials']!=(candidate.trial_refs if type(candidate)is ConditionedStrategyRevisionV1 else())
                    or values['general_required_trials']!=values['general_growth_intent'].required_trial_refs
                    or kind=='rollback_current_conditioned_strategy_v1'and(type(candidate)is not ConditionedStrategyRevisionV1 or candidate.qualification!='rolled_back')):
                raise DomainProductionErasureHold('conditional adopter changed its exact candidate or distinct actual trial chains')
            nested={name:raw[name]for name in('general_growth_intent','trial_start_originals','trial_originals','growth')}
            validate_domain_stage_provenance_v1('d01','adopt_general_growth_v1',nested)
            from ..domains.d01 import GrowthAdoptionCandidate
            growth=decode_typed_production_value_v1(raw['growth']['candidate'],GrowthAdoptionCandidate)
            expected_kind='self_knowledge'if type(candidate)is ConditionedCapabilityRevisionV1 else'strategy'
            if not any(block.kind==expected_kind and block.claim==canonical_serialize(plain_v1(candidate))for block in growth.revision.blocks):
                raise DomainProductionErasureHold('General adoption must preserve the actual exact conditional replacement claim')
            sources=candidate.source_refs
        else:
            namespace=primary.runtime_identity.namespace if type(primary)in{CalibrationPolicyV1,ConditionedSelfReviewV1}else primary.namespace
            sources=tuple(ref for value in values.values()if value is not None for ref in value.source_refs)
        if kind=='register_calibration_policy_v1':
            target=raw['calibration_review_target'];_exact(target,{'persona_head','block_id','kind'})
            head=decode_typed_production_value_v1(target['persona_head'],GraphVersion)
            if (target['block_id']!=primary.review_target_block or target['kind']not in{'self_knowledge','strategy'}
                    or head.revision<1 or head.key.type_name!='d01.persona_plan.v1' or NamespaceId.from_key(head.key)!=namespace):
                raise DomainProductionErasureHold('calibration policy changed its actual configured current persona target')
        if kind=='review_current_conditioned_self_v1':
            review=values['conditioned_self_review'];candidate=values['conditioned_self_candidate']
            type_name=CAPABILITY_TYPE if type(candidate)is ConditionedCapabilityRevisionV1 else STRATEGY_TYPE
            review_ref=candidate.last_review_ref if type(candidate)is ConditionedCapabilityRevisionV1 else candidate.review_ref
            name=conditioned_revision_record_name_v1(namespace=namespace,type_name=type_name,
                record_id=candidate.capability_id if type(candidate)is ConditionedCapabilityRevisionV1 else candidate.strategy_id,
                revision=candidate.revision,review_ref=review_ref)
            if (candidate.runtime_identity!=review.runtime_identity or review.predicate_ref!=candidate.condition_predicate_ref
                    or review_ref!=conditioned_key_v1(namespace,REVIEW_TYPE,review.review_id).token
                    or review.candidate_ref!=conditioned_key_v1(namespace,type_name,name).token):
                raise DomainProductionErasureHold('conditional review candidate differs from its actual independent immutable review branch')
        if kind=='resolve_current_prediction_v1'and values['self_discrepancy']is not None:
            resolution=values['prediction_resolution'];discrepancy=values['self_discrepancy']
            if (resolution.calibration_status!='counterexample' or discrepancy.namespace!=namespace
                    or discrepancy.prediction_ref!=resolution.prediction_ref
                    or discrepancy.resolution_ref!=conditioned_key_v1(namespace,RESOLUTION_TYPE,resolution.resolution_id).token):
                raise DomainProductionErasureHold('discrepancy must preserve its actual counterexample resolution')
        if kind=='record_current_simulation_v1'and(values['simulation'].namespace!=values['forecast_plan'].namespace
                or values['simulation'].baseline_snapshot!=values['forecast_plan'].baseline_snapshot):
            raise DomainProductionErasureHold('simulation record changed its actual registered baseline plan')
    _validate_conditioned_source_provenance_v1(raw,namespace,sources)
    if reserved:
        commitment=raw['conditioned_followup_target_commitment']
        _exact(commitment,{'schema','dedupe_key','targets_digest','target_census_digest','producer_receipt_digest','child_id'})
        if kind in OWNER_CONFIGURED_CONDITIONED_OPERATIONS_V1 or commitment['schema']!='d01.conditioned-followup-target-commitment.v1':
            raise DomainProductionErasureHold('only actual fixed business children carry a target commitment')
        from ..domains.d01.production_operations_v1 import require_locator_v1
        for key in('dedupe_key','child_id'):require_locator_v1(commitment[key],key)
        for key in('targets_digest','target_census_digest','producer_receipt_digest'):
            value=commitment[key]
            if type(value)is not str or len(value)!=64 or any(char not in'0123456789abcdef'for char in value):
                raise DomainProductionErasureHold('conditional child target commitment digest differs')
    return tuple(sorted(set(_references(raw))))

def verify_conditioned_self_stage_v1(stage):
    import json
    from .domain_production_contracts_v1 import StagedDomainOperationV1
    if type(stage)is not StagedDomainOperationV1 or stage.operation_kind not in OPERATIONS:
        raise TypeError('exact registered conditional semantic stage required')
    domain,request_type,_=OPERATIONS[stage.operation_kind]
    raw=json.loads(stage.original_payload_json)
    if (stage.domain!=domain or canonical_serialize(raw)!=stage.original_payload_json
            or canonical_digest(raw)!=stage.original_digest
            or raw['schema']!=domain+'.current-'+stage.operation_kind+'.v1'):
        raise ValueError('conditional stage changed its actual canonical original')
    request=decode_typed_production_value_v1(raw['request'],request_type)
    if raw['identity']['operation_id']!=stage.operation_id or raw['identity']['activity_id']!=stage.activity_id:
        raise ValueError('conditional original changed its actual producing identity')
    if stage.coverage=='waiting_for_original':
        if stage.proposals or not stage.missing_inputs or stage.jobs or stage.outbox:
            raise ValueError('conditional waiting stage cannot pretend to have semantic output')
        return stage
    provenance=raw['provenance'];expected={}
    validate_conditioned_business_provenance_v1(domain,stage.operation_kind,provenance)
    from ..authority_service.conditioned_child_contract_v1 import CHILD_DOMAINS
    if stage.operation_kind in CHILD_DOMAINS and 'conditioned_child_execution_v1'not in provenance:
        raise ValueError('conditional business child lacks its actual independently qualified execution original')
    if 'conditioned_child_execution_v1'in provenance:
        from ..authority_service.conditioned_child_contract_v1 import (ConditionedChildSelectorV1,conditioned_child_from_wire_v1)
        selector=conditioned_child_from_wire_v1(provenance['conditioned_child_execution_v1'],ConditionedChildSelectorV1)
        if(selector.namespace!=stage.namespace or selector.operation_id!=stage.operation_id
                or selector.operation_kind!=stage.operation_kind or selector.typed_request_json!=canonical_serialize(raw['request'])
                or selector.typed_request_digest!=canonical_digest(request)or selector.parent_budget_lease_ref!=raw['parent_budget']):
            raise ValueError('conditional stage changed its actual independently qualified child execution')
    if 'conditioned_followup_target_commitment'in provenance:
        commitment=provenance['conditioned_followup_target_commitment']
        if(type(commitment)is not dict or set(commitment)!={'schema','dedupe_key','targets_digest','target_census_digest','producer_receipt_digest','child_id'}
                or commitment['schema']!='d01.conditioned-followup-target-commitment.v1'
                or type(commitment['dedupe_key'])is not str or not commitment['dedupe_key']
                or commitment['child_id']!=stage.operation_id
                or any(type(commitment[key])is not str or len(commitment[key])!=64
                    or any(char not in '0123456789abcdef'for char in commitment[key])
                    for key in('targets_digest','target_census_digest','producer_receipt_digest'))):
            raise ValueError('conditional child changed its complete signed target commitment')
        from ..authority_service.conditioned_child_contract_v1 import validate_conditioned_frozen_targets_v1
        frozen=validate_conditioned_frozen_targets_v1(provenance['conditioned_frozen_targets'],namespace=stage.namespace)
        members=tuple(target for target in frozen['targets']if target['child_id']==stage.operation_id)
        if(len(members)!=1 or members[0]['operation_kind']!=stage.operation_kind
                or members[0]['request']!=raw['request']or frozen['targets_digest']!=commitment['targets_digest']
                or frozen['target_census_digest']!=commitment['target_census_digest']
                or frozen['producer_receipt_digest']!=commitment['producer_receipt_digest']
                or frozen['dedupe_key']!=commitment['dedupe_key']):
            raise ValueError('conditional first-child original changed its full actual frozen census or target membership')
    elif 'conditioned_frozen_targets'in provenance:
        raise ValueError('conditional frozen targets require their actual child commitment')
    types=dict(VALUE_TYPES)
    from ..domains.d10.production_operations_v1 import ConditionedLifeStrategyProjectionV1
    types['d10.conditioned_strategy_projection.v1']=ConditionedLifeStrategyProjectionV1
    for field,type_name,identity_field in _STAGE_RECORDS_V1.get(stage.operation_kind,()):
        value=provenance[field]
        if value is None:
            if field!='self_discrepancy':raise ValueError('conditional semantic output is absent')
            continue
        typed=decode_typed_production_value_v1(value,types[type_name])
        expected[conditioned_key_v1(stage.namespace,type_name,getattr(typed,identity_field))]=plain_v1(typed)
    if stage.operation_kind=='review_current_conditioned_self_v1':
        value=provenance['conditioned_self_candidate']
        type_name=CAPABILITY_TYPE if value['schema']=='d01.conditioned-capability-revision.v1'else STRATEGY_TYPE
        typed=decode_typed_production_value_v1(value,types[type_name])
        identity=conditioned_revision_record_name_v1(namespace=stage.namespace,type_name=type_name,
            record_id=typed.capability_id if type_name==CAPABILITY_TYPE else typed.strategy_id,revision=typed.revision,
            review_ref=typed.last_review_ref if type_name==CAPABILITY_TYPE else typed.review_ref)
        expected[conditioned_key_v1(stage.namespace,type_name,identity)]=plain_v1(typed)
    if stage.operation_kind=='select_current_conditioned_personal_step_v1':
        from ..domains.d08.personal_plan_v1 import DecisionRecordV2,DECISION_TYPE
        value=decode_typed_production_value_v1(provenance['decision'],DecisionRecordV2)
        writes=tuple(w for p in stage.proposals if p.domain=='d08'for w in p.typed_writes)
        if (len(writes)!=1 or writes[0].key.type_name!=DECISION_TYPE or writes[0].key.name!=value.decision_id
                or provenance['hard_eligibility_before_conditioned_preferences']is not True):
            raise ValueError('conditioned D08 selection changed its original hard-qualified Decision output')
        expected[writes[0].key]=plain_v1(value)
    if stage.operation_kind in {'adopt_current_conditioned_self_v1','rollback_current_conditioned_strategy_v1'}:
        from ..domains.d01 import GrowthAdoptionCandidate
        from ..domains.d01.production_operations_v1 import D01_PRODUCTION_WRITE_TYPES_V1
        actual=decode_typed_production_value_v1(provenance['growth']['candidate'],GrowthAdoptionCandidate)
        if actual.read_versions!=stage.read_versions or any(w.key.type_name not in D01_PRODUCTION_WRITE_TYPES_V1 for w in actual.typed_writes):
            raise ValueError('conditional adopter changed the original D01 General persona write family')
        expected={w.key:w.value for w in actual.typed_writes}
        if not expected:raise ValueError('conditional adopter lacks its real General candidate')
    semantic=tuple(w for p in stage.proposals if p.domain==domain for w in p.typed_writes)
    if (any(p.domain!=domain for p in stage.proposals)
            or len({w.key for w in semantic})!=len(semantic)
            or any(w.key not in expected or w.value!=expected[w.key]or NamespaceId.from_key(w.key)!=stage.namespace for w in semantic)):
        raise ValueError('conditional producer contains another output or omits its exact typed commitment')
    if stage.operation_kind in {'adopt_current_conditioned_self_v1','rollback_current_conditioned_strategy_v1'}and{w.key for w in semantic}!=set(expected):
        raise ValueError('conditional adopter must retain every original General write')
    return stage


def require_conditioned_rollback_predicate_v1(db,read,predicate_ref,scope_refs):
    _,predicate=_typed(db,read,predicate_ref,ConditionPredicateV1)
    if not predicate.valid_from<=read.frame.now_utc<predicate.valid_until or not set(scope_refs)<=set(predicate.scope_refs):
        raise MissingProductionOriginalV1('current_exact_conditional_rollback_predicate_scope')
    for ref in scope_refs:
        goal=read.head(db,ref,required=True)
        if goal.key.type_name=='d10.life_project.v1':
            from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1,decode_project_checkpoint_type_v1,CHECKPOINT_TYPE
            from ..domains.d08.personal_plan_v1 import decode_personal_plan_type_v1,PLAN_TYPE
            checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,read.head(db,
                project_checkpoint_key_v1(read.frame.envelope.authority.namespace,goal.key.token),required=True).value)
            plan=decode_personal_plan_type_v1(PLAN_TYPE,read.head(db,checkpoint.plan_ref,required=True).value)
            actual_goal=read.head(db,plan.goal_ref,required=True)
            _condition_project_scope_v1(db,read,goal.key.token,actual_goal)
            goal=actual_goal
        if goal.key.type_name!='d08.goal.v1':raise ValueError('strategy rollback predicate has no actual registered Goal scope')
        values,_,_,_=_condition_facts_v1(db,read,goal,predicate)
        if any(key not in values or values[key]is None or values[key]!=value for key,value in predicate.conditions):
            raise MissingProductionOriginalV1('actual_complete_current_rollback_condition_evidence')
    return predicate


def validate_conditioned_general_adoption_proposal_v1(db,read,request,proposal,*,readers,qualification,compiled):
    from .current_conditioned_self_read_v3 import require_conditioned_stage_readers_v3
    kind=read.frame.envelope.identity.phase
    require_conditioned_stage_readers_v3(db,read.frame,readers,kind,request)
    if (kind not in {'adopt_current_conditioned_self_v1','rollback_current_conditioned_strategy_v1'}
            or type(qualification)is not _ConditionedGrowthQualificationV1
            or _CONDITIONED_ADOPTIONS_V1.get(qualification)!=(read.frame,request.candidate_ref,qualification.candidate,
                read.frame.envelope.identity.operation_id,read.frame.snapshot.versions)
            or _CONDITIONED_COMPILED_ADOPTIONS_V1.get(qualification)is not compiled
            or compiled.domain!='d01'or compiled.operation_kind!='adopt_growth'
            or compiled.operation_id!=read.frame.envelope.identity.operation_id
            or compiled.read_versions!=read.frame.snapshot.versions or compiled.jobs or compiled.missing_inputs
            or len(compiled.proposals)!=1 or proposal!=compiled.proposals[0]):
        raise ValueError('D01 conditional write must equal its same live privately qualified actual General compilation')
    return proposal


def validate_conditioned_life_projection_proposal_v1(db,read,request,proposal,*,readers,value):
    from .current_conditioned_self_read_v3 import require_conditioned_stage_readers_v3
    from ..domains.d10 import LifeDomain
    from ..domains.d10.production_operations_v1 import ConditionedLifeStrategyProjectionV1
    from ..runtime_contracts import DependencySet
    kind='project_current_conditioned_life_strategy_v1'
    require_conditioned_stage_readers_v3(db,read.frame,readers,kind,request)
    if (type(request)is not ProjectCurrentConditionedLifeStrategyRequestV1 or type(value)is not ConditionedLifeStrategyProjectionV1
            or proposal.domain!='d10'or proposal.proposal_schema!='d10.proposal.v1'
            or proposal.proposal_schema_hash!=LifeDomain().descriptor.request_schema_hash
            or proposal.envelope!=read.frame.envelope or proposal.contribution_keys or proposal.required_bundle_parts
            or len(proposal.typed_writes)!=1):
        raise ValueError('only the actual Source-qualified single conditioned Life projection reaches this named validator')
    write=proposal.typed_writes[0]
    key=conditioned_key_v1(read.frame.envelope.authority.namespace,'d10.conditioned_strategy_projection.v1',value.projection_id)
    dependencies=tuple(v.key for v in read.frame.snapshot.versions if v.revision>0 and v.key!=key)
    expected=GraphWrite(key,plain_v1(value),dependencies)
    if (write!=expected or(value.project_head.key.token,value.recipe_head.key.token,value.strategy_ref)!=
            (request.project_ref,request.recipe_ref,request.strategy_ref)
            or value.namespace!=read.frame.envelope.authority.namespace
            or not set(value.source_refs)<=set(read.frame.envelope.source_qualification.source_refs)
            or proposal.dependencies!=DependencySet(current_invalidation=tuple(v for v in read.frame.snapshot.versions if v.key in dependencies),
                historical_provenance=tuple(v for v in read.frame.snapshot.versions if v.key.type_name=='memory.source'and v.revision>0))):
        raise ValueError('conditioned Life proposal changed its exact typed Source/current-head commitment')
    for version in(value.project_head,value.recipe_head,value.plan_head,value.goal_head):
        if read.head(db,version.key,required=True).revision!=version.revision:
            raise MissingProductionOriginalV1('actual_conditioned_Life_projection_current_four_heads')
    if value.source_refs:read.source_family(db,value.source_refs,purpose='consolidation')
    return proposal


def build_current_simulation_forecast_context_v1(frame,stage):
    if stage.work_kind!='simulation'or stage.provenance.get('forecast_mode')!='declared_forecast':
        raise ValueError('typed forecast context belongs only to its actual registered simulation phase')
    ref=stage.provenance['forecast_plan_ref'];key=AtomKey.from_token(ref)
    atom=frame.snapshot.get(key)
    if atom is None or not atom.valid or key.type_name!=FORECAST_PLAN_TYPE or canonical_digest(atom.value)!=stage.provenance['forecast_plan_digest']:
        raise MissingProductionOriginalV1('actual_Source_qualified_forecast_plan_in_model_prepare_snapshot')
    plan=decode_typed_production_value_v1(atom.value,SimulationForecastPlanV1)
    if plan.namespace!=frame.envelope.authority.namespace or plan.simulation_request_ref!=stage.request.simulation_request_ref:
        raise ValueError('simulation forecast context crossed its actual registered plan')
    conditions=[]
    for ref in(plan.baseline_assumption_ref,*plan.alternative_assumption_refs):
        condition=frame.snapshot.get(AtomKey.from_token(ref))
        if condition is None or not condition.valid or condition.key.type_name!=CONDITION_TYPE:
            raise MissingProductionOriginalV1('actual_Source_qualified_typed_simulation_assumption')
        value=decode_typed_production_value_v1(condition.value,ConditionPredicateV1)
        if value.namespace!=plan.namespace or not set(value.source_refs)<=set(frame.envelope.source_qualification.source_refs):
            raise ValueError('simulation assumption changed its exact qualified Source scope')
        conditions.append({'ref':ref,'revision':condition.revision,'digest':canonical_digest(condition.value),'value':plain_v1(value)})
    context={'schema':'d07.simulation-forecast-context.v1','plan_ref':key.token,'plan_revision':atom.revision,
        'plan_digest':canonical_digest(atom.value),'conditions':tuple(conditions),'forecast_mode':'declared_forecast',
        'forecasts':tuple({'prediction_id':p.prediction_id,'branch_ref':p.branch_ref,'target_head':p.target_head,
            'observable':p.target_observable,'range':p.predicted_range,'category':p.predicted_category,
            'resolution_rule':p.resolution_rule,'observer_kind':p.observer_kind,'expires_at':p.expires_at}for p in plan.forecasts),
        'valid_until':plan.valid_until,'output_schema':'d07.declared_forecast.v1'}
    wire=canonical_serialize(plain_v1(context))
    if len(wire.encode('utf-8'))>8192:raise MissingProductionOriginalV1('bounded_simulation_forecast_context_8192')
    return wire,canonical_digest(plain_v1(context))


CONDITIONED_PRODUCER_EVENTS_V1={
 'conditioned_simulation_committed_v1':frozenset({('d07','run_simulation')}),
 'conditioned_observed_outcome_committed_v1':frozenset({('d08','settle_observed_action'),('d08','register_artifact_task_milestone_v2'),('d10','advance_life')}),
 'conditioned_calibration_resolution_committed_v1':frozenset({('d07','resolve_current_prediction_v1')}),
 'conditioned_method_review_committed_v1':frozenset({('d01','review_current_method_growth_v1')}),
 'conditioned_conditions_committed_v1':frozenset({('d07','adopt_current_c1_method_conditions_v1')}),
 'conditioned_life_phase_committed_v1':frozenset({('d10','advance_life')})}


def _current_conditioned_strategies_v1(db,read,readers):
    from ..domains.d01.conditioned_self_v1 import decode_conditioned_self_claim_v1
    active=_active(read,readers);result=[]
    for block in active.plan.blocks:
        if block.kind!='strategy':continue
        value=decode_conditioned_self_claim_v1(block.claim)
        if type(value)is not ConditionedStrategyRevisionV1 or value.qualification=='rolled_back':continue
        ref=conditioned_key_v1(active.plan.namespace,STRATEGY_TYPE,conditioned_revision_record_name_v1(
            namespace=active.plan.namespace,type_name=STRATEGY_TYPE,record_id=value.strategy_id,revision=value.revision,review_ref=value.review_ref)).token
        _,actual=_typed(db,read,ref,ConditionedStrategyRevisionV1)
        if actual!=value:raise ValueError('current strategy claim lost its actual immutable revision')
        result.append((ref,value))
    return tuple(result)


def _review_request_from_actual_trigger_v1(db,read,readers,*,predicate_ref,trigger_ref,method_review_ref=None,origin_utc=None):
    from ..domains.d01.conditioned_self_v1 import decode_conditioned_self_claim_v1
    _,predicate=_typed(db,read,predicate_ref,ConditionPredicateV1);_,policy=_calibration_policy(db,read,predicate)
    active=_active(read,readers)
    block=next((b for b in active.plan.blocks if b.block_id==policy.review_target_block),None)
    if block is None or block.kind not in {'self_knowledge','strategy'}:
        raise MissingProductionOriginalV1('actual_Owner_configured_conditional_review_target')
    previous=decode_conditioned_self_claim_v1(block.claim)
    expected=ConditionedCapabilityRevisionV1 if block.kind=='self_knowledge'else ConditionedStrategyRevisionV1
    if previous is not None and type(previous)is not expected:raise ValueError('configured review target changed its semantic kind')
    ns=active.plan.namespace;identity=RuntimeIdentityRef.from_owner_guard(ns,readers.owner_guard)
    name=(previous.capability_id if expected is ConditionedCapabilityRevisionV1 else previous.strategy_id)if previous is not None else 'conditioned-self:'+canonical_digest((identity,block.block_id))[:40]
    revision=1 if previous is None else previous.revision+1
    previous_type=CAPABILITY_TYPE if expected is ConditionedCapabilityRevisionV1 else STRATEGY_TYPE
    previous_ref=None if previous is None else conditioned_key_v1(ns,previous_type,conditioned_revision_record_name_v1(
        namespace=ns,type_name=previous_type,record_id=name,revision=previous.revision,
        review_ref=previous.last_review_ref if previous_type==CAPABILITY_TYPE else previous.review_ref)).token
    calibration=_current_prediction_calibration_v1(db,read,predicate_ref,predicate)
    counterexamples=calibration.counterexamples;source_refs=calibration.source_refs
    trigger_atom=read.head(db,trigger_ref,required=True)
    if trigger_atom.key.type_name==RESOLUTION_TYPE:
        _,trigger_resolution=_typed(db,read,trigger_ref,PredictionResolutionV1)
        _,trigger_prediction=_typed(db,read,trigger_resolution.prediction_ref,PredictionRecordV1)
        if trigger_prediction.condition_predicate_ref!=predicate_ref:
            if(previous is None or expected is not ConditionedStrategyRevisionV1
                    or previous.condition_predicate_ref!=trigger_prediction.condition_predicate_ref
                    or trigger_resolution.calibration_status!='counterexample'):
                raise ValueError('narrow review changed its actual adopted strategy counterexample')
            counterexamples=tuple(dict.fromkeys((*counterexamples,trigger_ref)))
            source_refs=tuple(sorted(set((*source_refs,*trigger_resolution.source_refs))))
    strategy=None
    if expected is ConditionedStrategyRevisionV1:
        from ..domains.d01.method_learning_v1 import MethodOutcomeReviewV1,TRIAL_METHOD,BASELINE_METHOD
        from .d01_method_learning_v1 import _typed_head
        review_ref=method_review_ref or(None if previous is None else previous.method_outcome_review_ref)
        if review_ref is None:raise MissingProductionOriginalV1('actual_method_review_before_strategy_candidate')
        atom,method=_typed_head(db,read,review_ref,MethodOutcomeReviewV1);_origin(db,read,atom,'review_current_method_growth_v1')
        if method.qualification!='qualified'or method.target_block!=block.block_id:
            raise MissingProductionOriginalV1('actual_qualified_method_review_for_configured_strategy_target')
        head=next(v for v in active.read_versions if v.key.type_name=='d01.persona_plan.v1')
        review_id=_conditioned_review_id_v1(head,block.block_id,predicate_ref,name,revision,calibration.resolution_refs,trigger_ref,review_ref)
        rollback_ref=predicate.rollback_predicate_ref
        if rollback_ref is None:raise MissingProductionOriginalV1('actual_registered_strategy_rollback_predicate')
        strategy=ConditionedStrategyRevisionV1(identity,name,revision,previous_ref,predicate_ref,TRIAL_METHOD,BASELINE_METHOD,
            predicate.scope_refs,calibration.support_families,counterexamples,(method.trial_ref,),
            predicate.exclusions,rollback_ref,conditioned_key_v1(ns,REVIEW_TYPE,review_id).token,review_ref,
            max(predicate.valid_from,read.frame.now_utc if origin_utc is None else origin_utc),predicate.valid_until,'candidate',source_refs)
    return ReviewCurrentConditionedSelfRequestV1(trigger_ref,block.block_id,predicate_ref,calibration.prediction_refs,
        name,revision,previous_ref,strategy)



def _review_requests_for_actual_resolution_v1(db,read,readers,ref,resolution,prediction,*,origin_utc=None):
    _,predicate=_typed(db,read,prediction.condition_predicate_ref,ConditionPredicateV1)
    _,policy=_calibration_policy(db,read,predicate);active=_active(read,readers)
    block=next((b for b in active.plan.blocks if b.block_id==policy.review_target_block),None)
    if block is None or block.kind not in {'self_knowledge','strategy'}:
        raise MissingProductionOriginalV1('actual_configured_counterexample_review_target')
    if block.kind!='strategy'or resolution.calibration_status!='counterexample':
        return(_review_request_from_actual_trigger_v1(db,read,readers,predicate_ref=prediction.condition_predicate_ref,trigger_ref=ref,origin_utc=origin_utc),)
    from ..domains.d01.conditioned_self_v1 import decode_conditioned_self_claim_v1
    previous=decode_conditioned_self_claim_v1(block.claim)
    if(type(previous)is not ConditionedStrategyRevisionV1 or previous.condition_predicate_ref!=prediction.condition_predicate_ref):
        raise MissingProductionOriginalV1('actual_adopted_strategy_for_counterexample_narrowing')
    goal=_forecast_goal_v1(db,read,prediction);requests=[]
    for atom in read.complete_inventory(db,CONDITION_TYPE):
        if not atom.valid:continue
        _,narrow=_typed(db,read,atom.key.token,ConditionPredicateV1)
        if(narrow.calibration_policy_ref!=predicate.calibration_policy_ref
                or narrow.calibration_policy_digest!=predicate.calibration_policy_digest
                or not set(narrow.scope_refs)<=set(previous.applicable_scope)
                or not set(predicate.conditions)<set(narrow.conditions)
                or not set(previous.exclusions)<=set(narrow.exclusions)
                or narrow.rollback_predicate_ref is None
                or not narrow.valid_from<=read.frame.now_utc<narrow.valid_until):continue
        values,_,_,_=_condition_facts_v1(db,read,goal,narrow)
        if not all(values.get(key)is value for key,value in narrow.conditions):continue
        requests.append(_review_request_from_actual_trigger_v1(db,read,readers,predicate_ref=atom.key.token,trigger_ref=ref,origin_utc=origin_utc))
    if not requests:raise MissingProductionOriginalV1('actual_current_Owner_registered_strict_narrow_condition')
    return tuple(requests)

def resolve_current_conditioned_followup_command_v1(db,*,frame,event,producer_original,readers):
    from .current_conditioned_self_read_v3 import require_conditioned_followup_resolver_v3
    require_conditioned_followup_resolver_v3(db,frame,event,producer_original,readers)
    if(event.event_kind not in CONDITIONED_PRODUCER_EVENTS_V1 or producer_original is None
            or(producer_original['domain'],producer_original['operation_kind'])not in CONDITIONED_PRODUCER_EVENTS_V1[event.event_kind]
            or producer_original['receipt'].operation_id!=event.causal_operation_id):
        raise ValueError('conditional followup has another exact fully committed producer')
    read=CurrentDomainReadV1(frame);read.check(db);p=producer_original['payload']['provenance'];commands=[]
    if not set(p['conditioned_source_roots'])<=set(frame.envelope.source_qualification.source_refs):
        raise ValueError('conditional followup changed its actual signed producer Source roots')
    kind=event.event_kind
    if kind=='conditioned_simulation_committed_v1':
        ref=p['behavior']['forecast_plan_ref'];_,plan,_,actual=_actual_forecast_parent(db,read,readers,ref,event.causal_operation_id)
        from ..domains.d07.prediction_v1 import SimulationBranchV1
        branches=[]
        for index,row in enumerate(actual['branches']):
            members=tuple(v.key for v in producer_original['receipt'].write_versions if v.key.type_name=='d07.simulation_branch.v1'and v.key.name==row['branch_id'])
            if len(members)!=1:raise ValueError('simulation branch is not its real producer COMMIT member')
            branch_ref=members[0].token
            forecasts=tuple(conditioned_key_v1(plan.namespace,PREDICTION_TYPE,item.prediction_id).token for item in plan.forecasts if item.branch_ref==branch_ref)
            branches.append(SimulationBranchV1(branch_ref,()if index==0 else(plan.alternative_assumption_refs[index-1],),forecasts))
        record=SimulationRecordV1(plan.namespace,'simulation-record:'+canonical_digest((event.causal_operation_id,ref))[:40],
            plan.baseline_snapshot,branches[0],tuple(branches[1:]),(), 'frozen_baseline_two_alternatives_two_steps',plan.source_refs)
        commands.append(('record_current_simulation_v1',RecordCurrentSimulationRequestV1(record,ref,event.causal_operation_id)))
        commands.extend(('register_current_prediction_v1',RegisterCurrentPredictionRequestV1(value,ref,event.causal_operation_id,value.branch_ref,index))for index,value in enumerate(plan.forecasts))
    elif kind=='conditioned_observed_outcome_committed_v1':
        if producer_original['operation_kind']=='register_artifact_task_milestone_v2':
            outcomes=(p['artifact_task_milestone']['original_ref'],)
        else:outcomes=tuple(v.key.token for v in producer_original['receipt'].write_versions if v.key.type_name in {'d08.action_outcome.v1','d10.life_progress.v1'})
        for atom in read.complete_inventory(db,PREDICTION_TYPE):
            if atom.valid and atom.value['resolution_target_ref']in outcomes:
                _,prediction=_typed(db,read,atom.key.token,PredictionRecordV1)
                commands.append(('resolve_current_prediction_v1',ResolveCurrentPredictionRequestV1(atom.key.token,prediction.resolution_target_ref)))
    elif kind=='conditioned_calibration_resolution_committed_v1':
        refs=tuple(v.key.token for v in producer_original['receipt'].write_versions if v.key.type_name==RESOLUTION_TYPE)
        for ref in refs:
            _,resolution=_typed(db,read,ref,PredictionResolutionV1);_,prediction=_typed(db,read,resolution.prediction_ref,PredictionRecordV1)
            commands.extend(('review_current_conditioned_self_v1',request)for request in
                _review_requests_for_actual_resolution_v1(db,read,readers,ref,resolution,prediction,origin_utc=producer_original['payload']['now_utc']))
    elif kind=='conditioned_method_review_committed_v1':
        method_refs=tuple(v.key.token for v in producer_original['receipt'].write_versions if v.key.type_name=='d01.method_outcome_review.v1')
        for method_ref in method_refs:
            from ..domains.d01.method_learning_v1 import MethodOutcomeReviewV1
            from .d01_method_learning_v1 import _typed_head
            _,method=_typed_head(db,read,method_ref,MethodOutcomeReviewV1)
            for atom in read.complete_inventory(db,CONDITION_TYPE):
                if not atom.valid:continue
                _,predicate=_typed(db,read,atom.key.token,ConditionPredicateV1);_,policy=_calibration_policy(db,read,predicate)
                if policy.review_target_block!=method.target_block:continue
                calibration=_current_prediction_calibration_v1(db,read,atom.key.token,predicate)
                if not calibration.resolution_refs:raise MissingProductionOriginalV1('actual_calibration_resolution_before_method_strategy_review')
                commands.append(('review_current_conditioned_self_v1',_review_request_from_actual_trigger_v1(db,read,readers,
                    predicate_ref=atom.key.token,trigger_ref=calibration.resolution_refs[-1],method_review_ref=method_ref,origin_utc=producer_original['payload']['now_utc'])))
    elif kind=='conditioned_conditions_committed_v1':
        goal_ref=p['goal_ref'];goal=read.head(db,goal_ref,required=True)
        questions=tuple(v.key.token for v in producer_original['receipt'].write_versions if v.key.type_name=='d07.current_interpretation.v1')
        if not questions:return ()
        plans=tuple(atom for atom in read.complete_inventory(db,'d08.personal_plan.v1')if atom.valid and atom.value['goal_ref']==goal_ref)
        for plan in plans:
            for ref,strategy in _current_conditioned_strategies_v1(db,read,readers):
                commands.append(('match_current_conditioned_strategy_v1',MatchCurrentConditionedStrategyRequestV1(ref,questions[0],
                    goal_ref,goal.value['revision'],tuple(tuple(pair)for pair in plan.value['method_candidates']))))
    elif kind=='conditioned_life_phase_committed_v1':
        progress=p['actual_progress']
        for ref,strategy in _current_conditioned_strategies_v1(db,read,readers):
            commands.append(('project_current_conditioned_life_strategy_v1',ProjectCurrentConditionedLifeStrategyRequestV1(
                progress['project_ref'],progress['recipe_ref'],ref)))
    distinct={canonical_digest((operation,request)):(operation,request)for operation,request in commands}
    if len(distinct)>frame.limits.max_followup_jobs:
        raise MissingProductionOriginalV1('complete_conditioned_child_set_exceeds_original_followup_bound')
    return tuple(distinct[key]for key in sorted(distinct))

def plan_current_conditioned_output_keys_v3(db,*,frame,operation_kind,request,readers):
    from .current_conditioned_self_read_v3 import require_conditioned_output_plan_v3
    require_conditioned_output_plan_v3(db,frame,readers,operation_kind,request)
    if operation_kind not in OPERATIONS or type(request)is not OPERATIONS[operation_kind][1]:
        raise TypeError('registered conditional output plan requires its exact typed request')
    read=CurrentDomainReadV1(frame);read.check(db);ns=frame.envelope.authority.namespace
    declared={
        'register_calibration_policy_v1':(CALIBRATION_POLICY_TYPE,'policy_id'),
        'register_condition_predicate_v1':(CONDITION_TYPE,'predicate_id'),
        'register_simulation_forecast_plan_v1':(FORECAST_PLAN_TYPE,'plan_id'),
        'register_current_prediction_v1':(PREDICTION_TYPE,'prediction_id'),
        'record_current_simulation_v1':(SIMULATION_TYPE,'simulation_id')}
    if operation_kind in declared:
        type_name,field=declared[operation_kind]
        return(conditioned_key_v1(ns,type_name,getattr(request.value,field)),)
    if operation_kind=='resolve_current_prediction_v1':
        resolution,discrepancy=_prediction_resolution_material_v1(db,read,request,readers)
        return(conditioned_key_v1(ns,RESOLUTION_TYPE,resolution.resolution_id),
            *((conditioned_key_v1(ns,DISCREPANCY_TYPE,discrepancy.discrepancy_id),)if discrepancy is not None else()))
    if operation_kind=='review_current_conditioned_self_v1':
        review,_,candidate_type,candidate_id=_conditioned_review_material_v1(db,read,request,readers)
        return(conditioned_key_v1(ns,candidate_type,candidate_id),conditioned_key_v1(ns,REVIEW_TYPE,review.review_id))
    if operation_kind=='match_current_conditioned_strategy_v1':
        value=read_current_conditioned_match_v1(db,read,request,readers)
        return(conditioned_key_v1(ns,MATCH_TYPE,value.match_id),)
    if operation_kind=='project_current_conditioned_life_strategy_v1':
        value=_conditioned_life_projection_material_v1(db,read,request,readers)
        return(conditioned_key_v1(ns,'d10.conditioned_strategy_projection.v1',value.projection_id),)
    if operation_kind=='select_current_conditioned_personal_step_v1':
        from .d08_personal_plan_v1 import personal_decision_key_v1
        from .d08_personal_candidate_v1 import require_current_personal_candidates_v1
        prepared,_=require_current_personal_candidates_v1(db,frame=frame,
            preparation_operation_id=request.prepared_candidates_operation_id,installed_readers=readers.personal)
        key=personal_decision_key_v1(frame,request.plan_ref)
        if (key.token!=prepared.future_decision_ref or frame.envelope.identity.operation_id!=prepared.selection_operation_id
                or request.plan_ref!=prepared.plan_head.key.token or request.goal_ref!=prepared.goal_head.key.token):
            raise ValueError('conditional output plan changed its original prepared Decision identity')
        return(key,)
    if operation_kind in {'adopt_current_conditioned_self_v1','rollback_current_conditioned_strategy_v1'}:
        from .d01_general_growth_v1 import read_current_general_growth_v1
        from ..domains.d01 import PersonaDomain,_activation_key
        active=_active(read,readers);inputs,_=read_current_general_growth_v1(readers.base,db,frame,request.general_request)
        proposal=inputs.proposal
        return(PersonaDomain.plan_write(active.plan).key,
            AtomKey(Owner('persona',*ns.as_tuple),'d01.persona_revision.v1',proposal.proposal_id),_activation_key(ns),
            *(AtomKey(Owner('persona',*ns.as_tuple),'d01.growth_contribution.v1',
                PersonaDomain.contribution_key(proposal.target_block,family,proposal.change_kind))for family in proposal.source_families))
    raise ValueError('conditional output plan has no registered semantic recipe')

