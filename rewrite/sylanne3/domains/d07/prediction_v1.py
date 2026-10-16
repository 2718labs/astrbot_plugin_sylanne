"""D07 frozen forecasts and bounded simulation retain their evidence status."""
from dataclasses import dataclass, fields
import math
from ..d01.identity_v3 import _text, _refs, _digest, _time_window
from ...graph_types import GraphVersion, TypeSpec
from ...runtime_contracts import NamespaceId, schema_hash

PREDICTION_TYPE='d07.prediction_record.v1'
RESOLUTION_TYPE='d07.prediction_resolution.v1'
SIMULATION_TYPE='d07.simulation_record.v1'
MATCH_TYPE='d07.condition_match.v1'
DISCREPANCY_TYPE='d07.self_discrepancy.v1'
FORECAST_PLAN_TYPE='d07.simulation_forecast_plan.v1'
OBSERVABLE_RULES={
    'action_result_level':('d08.action_outcome.v1','exact_result_level'),
    'artifact_readback_digest':('artifact_task_milestone_v2','exact_verified_artifact_digest'),
    'artifact_content_length':('artifact_task_milestone_v2','verified_artifact_length_in_interval'),
    'life_postcondition':('d10.life_progress.v1','exact_registered_life_postcondition')}


@dataclass(frozen=True,slots=True)
class PredictionRecordV1:
    namespace: NamespaceId
    prediction_id: str
    task_class: str
    condition_predicate_ref: str
    branch_ref: str|None
    target_head: GraphVersion
    target_observable: str
    predicted_range: tuple[float,float]|None
    predicted_category: str|None
    assumption_refs: tuple[str,...]
    assumption_heads: tuple[GraphVersion,...]
    condition_goal_head: GraphVersion
    condition_goal_revision: int
    observer_kind: str
    resolution_rule: str
    resolution_target_ref: str
    expires_at: float
    registered_at: float
    source_refs: tuple[str,...]
    schema: str='d07.prediction-record.v1'
    content_reality: str='forecast'
    producer_kind: str='declared_forecast'
    def __post_init__(self):
        from ..d01.conditioned_self_v1 import TASK_CLASSES
        if (self.schema!='d07.prediction-record.v1' or type(self.namespace)is not NamespaceId
                or self.task_class not in TASK_CLASSES or type(self.target_head)is not GraphVersion
                or self.target_head.revision<1 or NamespaceId.from_key(self.target_head.key)!=self.namespace
                or self.target_observable not in OBSERVABLE_RULES
                or (self.observer_kind,self.resolution_rule)!=OBSERVABLE_RULES[self.target_observable]
                or self.content_reality!='forecast' or self.producer_kind!='declared_forecast'
                or (self.predicted_range is None)==(self.predicted_category is None)):
            raise ValueError('forecast freezes its exact observable, real observer and resolution rule')
        if (self.target_observable=='artifact_content_length')!=(self.predicted_range is not None):
            raise ValueError('registered numeric observable has its exact range shape')
        if self.target_observable=='artifact_readback_digest':_digest(self.predicted_category)
        if self.target_observable=='action_result_level'and self.predicted_category not in {'completed_verified','accepted','attempted','partially_observed','failed','cancelled','unknown'}:
            raise ValueError('action forecast category belongs to the registered result levels')
        if self.predicted_range is not None:
            if (type(self.predicted_range)is not tuple or len(self.predicted_range)!=2
                    or any(type(v)not in (int,float)or not math.isfinite(v)for v in self.predicted_range)
                    or self.predicted_range[0]>self.predicted_range[1]):
                raise ValueError('forecast range is finite and retains its uncertainty')
        if self.predicted_category is not None:_text(self.predicted_category)
        for ref in (self.prediction_id,self.condition_predicate_ref,self.resolution_target_ref):_text(ref)
        if self.branch_ref is not None:_text(self.branch_ref)
        _refs(self.assumption_refs)
        if (not self.assumption_refs or not self.assumption_heads or len(set(self.assumption_heads))!=len(self.assumption_heads)
                or type(self.condition_goal_head)is not GraphVersion or self.condition_goal_head.key.type_name!='d08.goal.v1'
                or self.condition_goal_head.revision<1 or NamespaceId.from_key(self.condition_goal_head.key)!=self.namespace
                or type(self.condition_goal_revision)is not int or self.condition_goal_revision<1
                or any(type(head)is not GraphVersion or head.key.type_name!='d07.current_interpretation.v1'
                    or head.revision<1 or NamespaceId.from_key(head.key)!=self.namespace for head in self.assumption_heads)):
            raise ValueError('declared conditional forecast requires its actual frozen D07 assumption heads')
        _refs(self.source_refs);_time_window(self.registered_at,self.expires_at)


@dataclass(frozen=True,slots=True)
class PredictionResolutionV1:
    namespace: NamespaceId
    resolution_id: str
    prediction_ref: str
    prediction_digest: str
    outcome_ref: str|None
    outcome_digest: str|None
    observation_unit_ref: str|None
    outcome_category: str|None
    outcome_range: tuple[float,float]|None
    observed_at: float|None
    resolved_at: float
    calibration_status: str
    source_refs: tuple[str,...]
    schema: str='d07.prediction-resolution.v1'
    def __post_init__(self):
        if (self.schema!='d07.prediction-resolution.v1' or type(self.namespace)is not NamespaceId
                or self.calibration_status not in {'matched','counterexample','unknown','expired_unknown'}
                or (self.outcome_ref is None)!=(self.outcome_digest is None)
                or (self.outcome_ref is None)!=(self.observation_unit_ref is None)
                or self.calibration_status in {'matched','counterexample'}and(self.outcome_ref is None or self.observed_at is None)):
            raise ValueError('resolution keeps real membership and never converts missing results into success/failure')
        _text(self.resolution_id);_text(self.prediction_ref);_digest(self.prediction_digest);_refs(self.source_refs)
        if self.outcome_ref is not None:_text(self.outcome_ref);_digest(self.outcome_digest);_text(self.observation_unit_ref)
        if type(self.resolved_at)not in (int,float)or not math.isfinite(self.resolved_at):raise ValueError('finite resolution clock required')


@dataclass(frozen=True,slots=True)
class SimulationBranchV1:
    branch_ref: str
    changed_assumption_refs: tuple[str,...]
    prediction_refs: tuple[str,...]
    content_reality: str='simulated'
    evidence_eligibility: str='none'
    def __post_init__(self):
        _text(self.branch_ref);_refs(self.changed_assumption_refs);_refs(self.prediction_refs)
        if len(self.prediction_refs)>2 or self.content_reality!='simulated'or self.evidence_eligibility!='none':
            raise ValueError('simulation permits at most two forecast steps and cannot create actual evidence')


@dataclass(frozen=True,slots=True)
class SimulationRecordV1:
    namespace: NamespaceId
    simulation_id: str
    baseline_snapshot: tuple[GraphVersion,...]
    baseline: SimulationBranchV1
    alternatives: tuple[SimulationBranchV1,...]
    unmodelled_refs: tuple[str,...]
    stopping_rule: str
    source_refs: tuple[str,...]
    schema: str='d07.simulation-record.v1'
    def __post_init__(self):
        if (self.schema!='d07.simulation-record.v1' or type(self.namespace)is not NamespaceId
                or not self.baseline_snapshot or type(self.baseline)is not SimulationBranchV1
                or self.baseline.changed_assumption_refs or type(self.alternatives)is not tuple or len(self.alternatives)>2
                or any(type(b)is not SimulationBranchV1 for b in self.alternatives)
                or len({b.branch_ref for b in (self.baseline,*self.alternatives)})!=1+len(self.alternatives)
                or self.stopping_rule!='frozen_baseline_two_alternatives_two_steps'
                or any(type(v)is not GraphVersion or NamespaceId.from_key(v.key)!=self.namespace for v in self.baseline_snapshot)):
            raise ValueError('simulation preserves its actual frozen baseline and fixed finite branches')
        _text(self.simulation_id);_refs(self.unmodelled_refs);_refs(self.source_refs)


@dataclass(frozen=True,slots=True)
class ConditionMatchProjectionV1:
    namespace: NamespaceId
    match_id: str
    strategy_ref: str
    strategy_digest: str
    predicate_ref: str
    scope_refs: tuple[str,...]
    semantic_question_ref: str|None
    scope_project_ref: str|None
    condition_heads: tuple[GraphVersion,...]
    coverage_epoch: int
    coverage_complete: bool
    matching: str
    preference_edges: tuple[tuple[str,str],...]
    source_refs: tuple[str,...]
    meaningful_unknowns: tuple[str,...]
    schema: str='d07.condition-match.v1'
    def __post_init__(self):
        if (self.schema!='d07.condition-match.v1' or type(self.namespace)is not NamespaceId
                or self.matching not in {'matched','excluded','unknown'}or type(self.coverage_complete)is not bool
                or type(self.coverage_epoch)is not int or self.coverage_epoch<0
                or self.preference_edges and (not self.coverage_complete or self.matching!='matched'or self.semantic_question_ref is None)):
            raise ValueError('conditional preference requires actual complete current matching coverage')
        if self.scope_project_ref is not None:_text(self.scope_project_ref)
        for ref in (self.match_id,self.strategy_ref,self.predicate_ref):_text(ref)
        _digest(self.strategy_digest)
        for refs in (self.scope_refs,self.source_refs,self.meaningful_unknowns):_refs(refs)


@dataclass(frozen=True,slots=True)
class SelfDiscrepancyV1:
    namespace: NamespaceId
    discrepancy_id: str
    prediction_ref: str
    resolution_ref: str
    condition_predicate_ref: str
    scope_refs: tuple[str,...]
    source_refs: tuple[str,...]
    disposition: str='candidate_condition_narrowing'
    schema: str='d07.self-discrepancy.v1'
    def __post_init__(self):
        if self.schema!='d07.self-discrepancy.v1'or self.disposition!='candidate_condition_narrowing':
            raise ValueError('self discrepancy proposes narrowing and grants no adopter permission')
        for ref in (self.discrepancy_id,self.prediction_ref,self.resolution_ref,self.condition_predicate_ref):_text(ref)
        _refs(self.scope_refs);_refs(self.source_refs)


@dataclass(frozen=True,slots=True)
class SimulationForecastPlanV1:
    namespace: NamespaceId
    plan_id: str
    simulation_request_ref: str
    simulation_activity_id: str
    baseline_snapshot: tuple[GraphVersion,...]
    baseline_assumption_ref: str
    alternative_assumption_refs: tuple[str,...]
    forecasts: tuple[PredictionRecordV1,...]
    declared_at: float
    valid_until: float
    source_refs: tuple[str,...]
    schema: str='d07.simulation-forecast-plan.v1'
    forecast_mode: str='declared_forecast'
    def __post_init__(self):
        if (self.schema!='d07.simulation-forecast-plan.v1'or self.forecast_mode!='declared_forecast'
                or type(self.namespace)is not NamespaceId or not self.baseline_snapshot
                or len(self.alternative_assumption_refs)>2 or not 1<=len(self.forecasts)<=6
                or any(type(value)is not PredictionRecordV1 or value.namespace!=self.namespace
                    or value.producer_kind!='declared_forecast'or value.registered_at!=self.declared_at
                    or value.expires_at>self.valid_until for value in self.forecasts)
                or len({value.prediction_id for value in self.forecasts})!=len(self.forecasts)):
            raise ValueError('simulation forecast plan is a finite explicit declaration before execution')
        for ref in (self.plan_id,self.simulation_request_ref,self.simulation_activity_id,self.baseline_assumption_ref):_text(ref)
        _refs(self.alternative_assumption_refs);_refs(self.source_refs);_time_window(self.declared_at,self.valid_until)
        branches={}
        for value in self.forecasts:
            if value.branch_ref is None:raise ValueError('planned forecast binds its exact simulated branch')
            branches[value.branch_ref]=branches.get(value.branch_ref,0)+1
        if len(branches)>3 or any(count>2 for count in branches.values()):raise ValueError('forecast plan exceeds baseline plus two two-step branches')


VALUE_TYPES={FORECAST_PLAN_TYPE:SimulationForecastPlanV1,PREDICTION_TYPE:PredictionRecordV1,RESOLUTION_TYPE:PredictionResolutionV1,
    SIMULATION_TYPE:SimulationRecordV1,MATCH_TYPE:ConditionMatchProjectionV1,DISCREPANCY_TYPE:SelfDiscrepancyV1}


def prediction_type_specs_v1():
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    return tuple(TypeSpec(name,('persona',),'state',lambda value,cls=cls:decode_typed_production_value_v1(value,cls),
        immutable=True,writer_domain='d07',schema_version=1,schema_hash=schema_hash({'type':name,
        'fields':tuple(field.name for field in fields(cls)),'semantic':'pre-registered forecast; actual resolution; unknown retained'}))
        for name,cls in VALUE_TYPES.items())
