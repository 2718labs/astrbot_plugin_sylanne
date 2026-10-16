"""D01 conditional knowledge and explicit revisions; no execution authority."""
from dataclasses import dataclass, fields
from .identity_v3 import RuntimeIdentityRef, SelfModelProjectionV3, _text, _refs, _digest, _time_window
from ...graph_types import GraphVersion, TypeSpec
from ...runtime_contracts import NamespaceId, canonical_digest, schema_hash

CALIBRATION_POLICY_TYPE='d01.calibration_policy.v1'
CONDITION_TYPE='d01.condition_predicate.v1'
CAPABILITY_TYPE='d01.conditioned_capability_revision.v1'
STRATEGY_TYPE='d01.conditioned_strategy_revision.v1'
REVIEW_TYPE='d01.conditioned_self_review.v1'
TASK_CLASSES=('artifact_draft','source_note','life_activity')
REGISTERED_METHODS=('CP-tone-order:full-draft-then-check','CP-tone-order:tone-sample-then-full-draft')


def _scope(namespace,refs):
    from ...graph_types import AtomKey
    _refs(refs)
    if not refs or any(NamespaceId.from_key(AtomKey.from_token(ref))!=namespace or AtomKey.from_token(ref).type_name not in
            {'d08.goal.v1','d08.action_intent.v1','d10.life_project.v1'}for ref in refs):
        raise ValueError('conditioned Self requires exact bounded namespace scope')


def _version(identity,revision,previous):
    _text(identity)
    if type(revision)is not int or revision<1 or (revision==1)!=(previous is None):
        raise ValueError('conditioned revision requires its exact predecessor')
    if previous is not None:_text(previous)


@dataclass(frozen=True,slots=True)
class CalibrationPolicyV1:
    runtime_identity: RuntimeIdentityRef
    policy_id: str
    review_target_block: str
    task_class: str
    target_observable: str
    resolution_rule: str
    population_scope_refs: tuple[str,...]
    minimum_verified_outcomes: int
    missing_outcome_policy: str
    valid_from: float
    valid_until: float
    source_refs: tuple[str,...]
    schema: str='d01.calibration-policy.v1'
    def __post_init__(self):
        from ..d07.prediction_v1 import OBSERVABLE_RULES
        if (self.schema!='d01.calibration-policy.v1' or type(self.runtime_identity)is not RuntimeIdentityRef
                or self.task_class not in TASK_CLASSES or self.target_observable not in OBSERVABLE_RULES
                or self.resolution_rule!=OBSERVABLE_RULES[self.target_observable][1]
                or type(self.minimum_verified_outcomes)is not int or self.minimum_verified_outcomes<1
                or self.missing_outcome_policy not in {'report_known_and_unknown','require_complete_for_threshold'}):
            raise ValueError('calibration policy requires an explicit registered observable, population and sample rule')
        _text(self.policy_id);_text(self.review_target_block);_scope(self.runtime_identity.namespace,self.population_scope_refs)
        _refs(self.source_refs);_time_window(self.valid_from,self.valid_until)


@dataclass(frozen=True,slots=True)
class ConditionPredicateV1:
    namespace: NamespaceId
    predicate_id: str
    calibration_policy_ref: str
    task_class: str
    scope_refs: tuple[str,...]
    conditions: tuple[tuple[str,bool],...]
    exclusions: tuple[str,...]
    source_refs: tuple[str,...]
    valid_from: float
    valid_until: float
    schema: str='d01.condition-predicate.v1'
    rule: str='all_registered_conditions'
    rollback_predicate_ref: str|None=None
    def __post_init__(self):
        from ..d07 import METHOD_CONDITION_IDS_V1
        if (self.schema!='d01.condition-predicate.v1' or self.rule!='all_registered_conditions'
                or self.task_class not in TASK_CLASSES or type(self.namespace)is not NamespaceId
                or not self.conditions or len(self.conditions)>len(METHOD_CONDITION_IDS_V1)
                or len({key for key,_ in self.conditions})!=len(self.conditions)
                or any(key not in METHOD_CONDITION_IDS_V1 or type(value)is not bool for key,value in self.conditions)):
            raise ValueError('condition predicate uses only its finite registered typed conditions')
        _text(self.predicate_id);_text(self.calibration_policy_ref);_scope(self.namespace,self.scope_refs);_refs(self.exclusions)
        _refs(self.source_refs);_time_window(self.valid_from,self.valid_until)
        if self.rollback_predicate_ref is not None:_text(self.rollback_predicate_ref)


@dataclass(frozen=True,slots=True)
class ConditionedCapabilityRevisionV1:
    runtime_identity: RuntimeIdentityRef
    capability_id: str
    revision: int
    previous_ref: str|None
    task_class: str
    condition_predicate_ref: str
    scope_refs: tuple[str,...]
    support_family_refs: tuple[str,...]
    counterexample_refs: tuple[str,...]
    prediction_refs: tuple[str,...]
    resolution_refs: tuple[str,...]
    verified_outcome_counts: tuple[tuple[str,int],...]
    unknown_count: int
    observation_unit_count: int
    calibration_policy_ref: str
    calibration_policy_digest: str
    minimum_verified_outcomes: int
    calibration_coverage: float
    last_review_ref: str
    valid_from: float
    valid_until: float
    qualification: str
    source_refs: tuple[str,...]
    schema: str='d01.conditioned-capability-revision.v1'
    def __post_init__(self):
        _version(self.capability_id,self.revision,self.previous_ref)
        if (self.schema!='d01.conditioned-capability-revision.v1' or type(self.runtime_identity)is not RuntimeIdentityRef
                or self.task_class not in TASK_CLASSES or self.qualification not in {'sample_threshold_met','limited','unknown','stale'}
                or type(self.unknown_count)is not int or self.unknown_count<0
                or tuple(key for key,_ in self.verified_outcome_counts)!=('matched','counterexample')
                or any(type(value)is not int or value<0 for _,value in self.verified_outcome_counts)
                or type(self.observation_unit_count)is not int or self.observation_unit_count<0
                or sum(value for _,value in self.verified_outcome_counts)+self.unknown_count!=self.observation_unit_count
                or self.observation_unit_count>len(self.prediction_refs)
                or type(self.minimum_verified_outcomes)is not int or self.minimum_verified_outcomes<1
                or self.calibration_coverage!=(sum(value for _,value in self.verified_outcome_counts)/self.observation_unit_count if self.observation_unit_count else 0.0)
                or not set(self.counterexample_refs)<=set(self.resolution_refs)):
            raise ValueError('capability calibration retains its complete actual prediction denominator')
        _scope(self.runtime_identity.namespace,self.scope_refs)
        for refs in (self.support_family_refs,self.counterexample_refs,self.prediction_refs,self.resolution_refs,self.source_refs):_refs(refs)
        _text(self.condition_predicate_ref);_text(self.calibration_policy_ref);_digest(self.calibration_policy_digest);_text(self.last_review_ref);_time_window(self.valid_from,self.valid_until)


@dataclass(frozen=True,slots=True)
class ConditionedStrategyRevisionV1:
    runtime_identity: RuntimeIdentityRef
    strategy_id: str
    revision: int
    previous_ref: str|None
    condition_predicate_ref: str
    preferred_method: str
    alternative_method: str
    applicable_scope: tuple[str,...]
    support_families: tuple[str,...]
    counterexamples: tuple[str,...]
    trial_refs: tuple[str,...]
    exclusions: tuple[str,...]
    rollback_predicate_ref: str
    review_ref: str
    method_outcome_review_ref: str
    valid_from: float
    valid_until: float
    qualification: str
    source_refs: tuple[str,...]
    schema: str='d01.conditioned-strategy-revision.v1'
    def __post_init__(self):
        _version(self.strategy_id,self.revision,self.previous_ref)
        if (self.schema!='d01.conditioned-strategy-revision.v1' or type(self.runtime_identity)is not RuntimeIdentityRef
                or self.preferred_method not in REGISTERED_METHODS or self.alternative_method not in REGISTERED_METHODS
                or self.preferred_method==self.alternative_method or self.qualification not in {'candidate','qualified','narrowed','rolled_back','unknown'}):
            raise ValueError('conditioned strategy has only registered methods and explicit revision status')
        _scope(self.runtime_identity.namespace,self.applicable_scope)
        from ...graph_types import AtomKey
        if any(AtomKey.from_token(ref).type_name not in {'d08.goal.v1','d10.life_project.v1'}for ref in self.applicable_scope):
            raise ValueError('conditional preference has only actual Goal or Project applicability')
        for refs in (self.support_families,self.counterexamples,self.trial_refs,self.exclusions,self.source_refs):_refs(refs)
        for ref in (self.condition_predicate_ref,self.rollback_predicate_ref,self.review_ref,self.method_outcome_review_ref):_text(ref)
        _time_window(self.valid_from,self.valid_until)


@dataclass(frozen=True,slots=True)
class ConditionedSelfReviewV1:
    runtime_identity: RuntimeIdentityRef
    review_id: str
    target_block: str
    expected_persona_head: GraphVersion
    predicate_ref: str
    prediction_refs: tuple[str,...]
    resolution_refs: tuple[str,...]
    candidate_ref: str
    source_refs: tuple[str,...]
    qualification: str
    meaningful_unknowns: tuple[str,...]
    schema: str='d01.conditioned-self-review.v1'
    def __post_init__(self):
        if (self.schema!='d01.conditioned-self-review.v1' or type(self.runtime_identity)is not RuntimeIdentityRef
                or type(self.expected_persona_head)is not GraphVersion
                or self.expected_persona_head.key.type_name!='d01.persona_plan.v1'
                or self.qualification not in {'qualified','limited','unknown','rollback_evidence_qualified'}):
            raise ValueError('conditioned Self review requires the actual current persona head')
        for ref in (self.review_id,self.target_block,self.predicate_ref,self.candidate_ref):_text(ref)
        for refs in (self.prediction_refs,self.resolution_refs,self.source_refs,self.meaningful_unknowns):_refs(refs)


@dataclass(frozen=True,slots=True)
class ConditionedCalibrationViewV1:
    capability_revision_ref: str
    prediction_refs: tuple[str,...]
    resolution_refs: tuple[str,...]
    counterexample_refs: tuple[str,...]
    verified_outcome_counts: tuple[tuple[str,int],...]
    unknown_count: int
    observation_unit_count: int
    calibration_policy_ref: str
    calibration_policy_digest: str
    minimum_verified_outcomes: int
    coverage: float
    configured_sample_threshold_met: bool
    source_refs: tuple[str,...]
    schema: str='d01.conditioned-calibration-view.v1'
    def __post_init__(self):
        if (self.schema!='d01.conditioned-calibration-view.v1'
                or tuple(key for key,_ in self.verified_outcome_counts)!=('matched','counterexample')
                or any(type(value)is not int or value<0 for _,value in self.verified_outcome_counts)
                or type(self.unknown_count)is not int or self.unknown_count<0
                or type(self.observation_unit_count)is not int or self.observation_unit_count<0
                or sum(value for _,value in self.verified_outcome_counts)+self.unknown_count!=self.observation_unit_count
                or self.observation_unit_count>len(self.prediction_refs)
                or self.coverage!=(sum(value for _,value in self.verified_outcome_counts)/self.observation_unit_count if self.observation_unit_count else 0.0)
                or type(self.minimum_verified_outcomes)is not int or self.minimum_verified_outcomes<1
                or type(self.configured_sample_threshold_met)is not bool):
            raise ValueError('current calibration view retains its distinct immutable revision and complete outcome denominator')
        for ref in(self.capability_revision_ref,self.calibration_policy_ref):_text(ref)
        _digest(self.calibration_policy_digest)
        for refs in(self.prediction_refs,self.resolution_refs,self.counterexample_refs,self.source_refs):_refs(refs)


@dataclass(frozen=True,slots=True)
class SelfViewV4:
    runtime_identity: RuntimeIdentityRef
    persona_head: GraphVersion
    semantic_projection: SelfModelProjectionV3
    capabilities: tuple[tuple[str,ConditionedCapabilityRevisionV1],...]
    strategies: tuple[tuple[str,ConditionedStrategyRevisionV1],...]
    current_limit_refs: tuple[str,...]
    commitment_refs: tuple[str,...]
    read_versions: tuple[GraphVersion,...]
    meaningful_unknowns: tuple[str,...]
    calibrations: tuple[tuple[str,ConditionedCalibrationViewV1],...]
    schema: str='d01.self-view.v4'
    def __post_init__(self):
        if (self.schema!='d01.self-view.v4' or type(self.runtime_identity)is not RuntimeIdentityRef
                or type(self.semantic_projection)is not SelfModelProjectionV3
                or self.semantic_projection.runtime_identity!=self.runtime_identity
                or type(self.persona_head)is not GraphVersion or self.persona_head.key.type_name!='d01.persona_plan.v1'
                or any(type(value)is not ConditionedCapabilityRevisionV1 or value.runtime_identity!=self.runtime_identity for _,value in self.capabilities)
                or any(type(value)is not ConditionedStrategyRevisionV1 or value.runtime_identity!=self.runtime_identity for _,value in self.strategies)
                or any(type(value)is not ConditionedCalibrationViewV1 or ref!=value.capability_revision_ref for ref,value in self.calibrations)
                or len({ref for ref,_ in self.capabilities})!=len(self.capabilities)
                or len({ref for ref,_ in self.calibrations})!=len(self.calibrations)
                or {ref for ref,_ in self.calibrations}!={ref for ref,_ in self.capabilities}):
            raise ValueError('SelfView uses only actual qualified stable identity and current revisions')
        for refs in (self.current_limit_refs,self.commitment_refs,self.meaningful_unknowns):_refs(refs)


VALUE_TYPES={CALIBRATION_POLICY_TYPE:CalibrationPolicyV1,CONDITION_TYPE:ConditionPredicateV1,CAPABILITY_TYPE:ConditionedCapabilityRevisionV1,
    STRATEGY_TYPE:ConditionedStrategyRevisionV1,REVIEW_TYPE:ConditionedSelfReviewV1}


def conditioned_self_type_specs_v1():
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    return tuple(TypeSpec(name,('persona',),'state',lambda value,cls=cls:decode_typed_production_value_v1(value,cls),
        immutable=True,writer_domain='d01',schema_version=1,schema_hash=schema_hash({'type':name,
        'fields':tuple(field.name for field in fields(cls)),'semantic':'conditional knowledge; no execution authority'}))
        for name,cls in VALUE_TYPES.items())


def decode_conditioned_self_claim_v1(claim):
    import json
    from ...runtime_contracts import canonical_serialize
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    names={cls.__dataclass_fields__['schema'].default:cls for cls in (ConditionedCapabilityRevisionV1,ConditionedStrategyRevisionV1)}
    try:raw=json.loads(claim)
    except ValueError:
        if any(schema in claim for schema in names):raise ValueError('declared conditional Self schema is malformed')from None
        return None
    if type(raw)is not dict or raw.get('schema')not in names:return None
    if canonical_serialize(raw)!=claim:raise ValueError('conditioned Self claim requires canonical registered revision')
    return decode_typed_production_value_v1(raw,names[raw['schema']])


SEMANTIC_SELF_LOCATOR_FIELDS_V1=frozenset({'schema','kind','runtime_identity','block_id','revision',
    'previous_revision','legacy_origin','continuity_anchor','plasticity_policy_ref','plasticity_policy_digest',
    'support_original_refs','counterevidence_original_ref','continuity_original_ref','trial_original_refs',
    'scope_refs','exclusion_refs','valid_from','valid_until','revision_kind','adopt_before'})


def retain_semantic_self_locator_path_v1(path):
    return not path or path[0]in SEMANTIC_SELF_LOCATOR_FIELDS_V1


def require_semantic_self_locator_v1(metadata,field_names,*,runtime_identity,outer_block_id):
    from .identity_v3 import SemanticIdentityRevision,SEMANTIC_SCHEMA_V3
    from .production_operations_v1 import plain_v1
    if (set(field_names)!=set(SemanticIdentityRevision.__dataclass_fields__)
            or metadata.get('schema')!=SEMANTIC_SCHEMA_V3 or metadata.get('kind')!='semantic_identity'
            or metadata.get('runtime_identity')!=plain_v1(runtime_identity)
            or metadata.get('block_id')!=outer_block_id
            or type(metadata.get('revision'))is not int or metadata['revision']<1):
        raise ValueError('semantic Self nested locator differs from actual fixed schema/runtime/block/revision')
    for name in ('support_original_refs','trial_original_refs','scope_refs','exclusion_refs'):
        _refs(tuple(metadata[name]))
    if len(metadata['trial_original_refs'])>3:raise ValueError('semantic Self locator changed the original trial bound')
    _time_window(metadata['valid_from'],metadata['valid_until'])
    if metadata['adopt_before']is not None:_time_window(metadata['valid_from'],metadata['adopt_before'])
    if metadata['revision_kind']not in {'legacy_migration','growth','administrative'}:
        raise ValueError('semantic Self locator has no registered revision kind')
    return metadata


def conditioned_record_locator_fields_v1(type_name):
    from ..d07.prediction_v1 import VALUE_TYPES as prediction_types
    types={**VALUE_TYPES,**prediction_types}
    if type_name=='d10.conditioned_strategy_projection.v1':
        from ..d10.production_operations_v1 import ConditionedLifeStrategyProjectionV1
        cls=ConditionedLifeStrategyProjectionV1
    else:cls=types[type_name]
    return frozenset(cls.__dataclass_fields__),cls.__dataclass_fields__['schema'].default



def conditioned_revision_record_name_v1(*,namespace,type_name,record_id,revision,review_ref):
    from ...graph_types import AtomKey
    from ...runtime_contracts import canonical_digest
    if(type(namespace)is not NamespaceId or type_name not in {CAPABILITY_TYPE,STRATEGY_TYPE}
            or type(revision)is not int or revision<1):
        raise ValueError('conditional candidate requires its stable identity and actual next revision')
    _text(record_id);key=AtomKey.from_token(review_ref)
    if key.type_name!=REVIEW_TYPE or NamespaceId.from_key(key)!=namespace:
        raise ValueError('conditional candidate branch requires its actual same-namespace review original')
    return record_id+':revision:'+str(revision)+':review:'+canonical_digest(review_ref)[:48]

def require_conditioned_record_locator_v1(metadata,field_names,*,namespace,type_name):
    fields,expected_schema=conditioned_record_locator_fields_v1(type_name)
    actual_namespace=metadata.get('namespace',metadata.get('runtime_identity',{}).get('namespace'))
    from .production_operations_v1 import plain_v1
    if set(field_names)!=set(fields)or metadata.get('schema')!=expected_schema or actual_namespace!=plain_v1(namespace):
        raise ValueError('conditioned record locator requires complete exact typed schema and namespace EOF')
    from ...graph_types import AtomKey
    from ...memory_types import source_key
    roots=tuple(metadata['source_refs']);_refs(roots)
    for ref in roots:
        key=AtomKey.from_token(ref)
        if key!=source_key(*namespace.as_tuple,key.owner.subject or''):
            raise ValueError('conditioned record locator Source is outside its canonical current namespace')
    return roots
