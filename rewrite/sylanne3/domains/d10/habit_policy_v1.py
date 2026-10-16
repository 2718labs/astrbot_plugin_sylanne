"""B3 Habit policy definitions and exact Graph mirrors; definitions grant no execution."""
from dataclasses import asdict,dataclass,fields
import math
from ...graph_types import AtomKey,Owner,TypeSpec
from ...runtime_contracts import NamespaceId,canonical_digest,schema_hash
from ..d08.execution import GoalPredicate

HABIT_POLICY_TYPE='d10.habit_policy.v1'
HABIT_OCCURRENCE_TYPE='d10.habit_occurrence.v1'
HABIT_DISPOSITION_TYPE='d10.habit_disposition.v1'
HABIT_OUTCOME_TYPE='d10.habit_outcome.v1'
HABIT_EXECUTORS=frozenset(('source_note','draft_file'))
HABIT_MISS_POLICIES=frozenset(('skipped','wait','reschedule-required'))
HABIT_POLICY_STATES=frozenset(('enabled','paused','stopped','superseded'))

def _sha(value):
    if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):
        raise ValueError('Habit requires its exact SHA256 commitment')

def _graph_ref(namespace,ref,kind):
    key=AtomKey.from_token(ref)
    if NamespaceId.from_key(key)!=namespace or key.type_name!=kind:
        raise ValueError('Habit reference differs from its exact namespace/type')

def _predicate_from_wire(raw):
    if type(raw)is not dict or set(raw)!=set(GoalPredicate.__dataclass_fields__):
        raise ValueError('Habit predicate fields differ')
    return GoalPredicate(**{**raw,'parameters':tuple(tuple(x)for x in raw['parameters'])})

@dataclass(frozen=True,slots=True)
class HabitSourceNoteInputV1:
    source_ref:str
    source_revision:int
    source_digest:str
    role_binding_ref:str
    role_binding_revision:int
    role_binding_digest:str
    instantiate_occurrence_context:bool
    recipe_version:str='d10.habit-source-note.v1'
    def __post_init__(self):
        if self.recipe_version!='d10.habit-source-note.v1'or self.instantiate_occurrence_context is not True or type(self.source_revision)is not int or self.source_revision<1 or type(self.role_binding_revision)is not int or self.role_binding_revision<1:raise ValueError('Habit SourceNote standing input requires explicit fixed occurrence context permission and pinned versions')
        if AtomKey.from_token(self.source_ref).type_name!='memory.source'or AtomKey.from_token(self.role_binding_ref).type_name!='d03.role_binding':raise ValueError('Habit SourceNote input requires its actual Source and role')
        _sha(self.source_digest);_sha(self.role_binding_digest)

@dataclass(frozen=True,slots=True)
class HabitPolicyDefinitionV1:
    namespace:NamespaceId
    policy_id:str
    revision:int
    project_ref:str
    recipe_ref:str
    recipe_revision:int
    executor_kind:str
    cue_predicate:GoalPredicate
    window_anchor_utc:float
    window_seconds:float
    execution_seconds:float
    minimum_interval_seconds:float
    maximum_occurrences_per_window:int
    parent_root_grant_ref:str
    parent_root_grant_id:str
    parent_root_grant_version:int
    parent_root_grant_digest:str
    original_valid_until_utc:float
    miss_policy:str
    stop_predicate:GoalPredicate
    state:str
    cancellation_generation:int
    purpose:str
    audience:tuple[str,...]
    target_ref:str
    source_refs:tuple[str,...]
    source_note_input:HabitSourceNoteInputV1|None=None
    schema:str='d10.habit-policy-definition.v1'
    def __post_init__(self):
        if (self.schema!='d10.habit-policy-definition.v1' or type(self.namespace)is not NamespaceId
                or type(self.policy_id)is not str or not self.policy_id.startswith('habit:')
                or type(self.revision)is not int or self.revision<1 or type(self.recipe_revision)is not int or self.recipe_revision<1
                or self.executor_kind not in HABIT_EXECUTORS or type(self.cue_predicate)is not GoalPredicate
                or type(self.stop_predicate)is not GoalPredicate or self.miss_policy not in HABIT_MISS_POLICIES
                or self.state not in HABIT_POLICY_STATES or type(self.maximum_occurrences_per_window)is not int
                or self.maximum_occurrences_per_window<1 or type(self.cancellation_generation)is not int or self.cancellation_generation<0
                or type(self.parent_root_grant_version)is not int or self.parent_root_grant_version<1
                or not self.parent_root_grant_ref or not self.parent_root_grant_id or self.purpose!='context' or not self.target_ref):
            raise ValueError('Habit definition requires its fixed policy/recipe/Owner/Root scope')
        for name in ('window_anchor_utc','window_seconds','execution_seconds','minimum_interval_seconds','original_valid_until_utc'):
            value=getattr(self,name)
            if type(value)not in(int,float)or not math.isfinite(value):raise ValueError('Habit original schedule times must be finite')
        if (self.window_seconds<=0 or self.execution_seconds<=0 or self.minimum_interval_seconds<0
                or self.execution_seconds>self.window_seconds or self.original_valid_until_utc<=self.window_anchor_utc):
            raise ValueError('Habit window/execution intervals exceed their original policy bounds')
        for name in ('audience','source_refs'):
            value=getattr(self,name)
            if type(value)is not tuple or not 1<=len(value)<=32 or len(set(value))!=len(value)or any(type(x)is not str or not x for x in value):
                raise ValueError('Habit purpose/audience/Source scope must remain bounded and exact')
        _graph_ref(self.namespace,self.project_ref,'d10.life_project.v1')
        _graph_ref(self.namespace,self.recipe_ref,'d10.activity_recipe.v1')
        if self.executor_kind=='source_note':
            _graph_ref(self.namespace,self.target_ref,'d03.entity_anchor')
            if type(self.source_note_input)is not HabitSourceNoteInputV1:raise ValueError('SourceNote standing policy requires its explicit pinned input and instantiation recipe')
            _graph_ref(self.namespace,self.source_note_input.source_ref,'memory.source');_graph_ref(self.namespace,self.source_note_input.role_binding_ref,'d03.role_binding')
            if self.source_note_input.source_ref not in self.source_refs:raise ValueError('Habit SourceNote input must belong to signed Source roots')
        elif self.source_note_input is not None:raise ValueError('Artifact selected-generation policy cannot borrow SourceNote standing input')
        else:_graph_ref(self.namespace,self.target_ref,'d08.decision_record.v2')
        for ref in self.source_refs:_graph_ref(self.namespace,ref,'memory.source')
        _sha(self.parent_root_grant_digest)
    @property
    def digest(self):return canonical_digest(habit_policy_definition_to_wire_v1(self))

@dataclass(frozen=True,slots=True)
class GraphAdoptedHabitPolicyV1:
    definition:HabitPolicyDefinitionV1
    core_namespace:str
    installation_id:str
    core_policy_revision:int
    core_original_ref:str
    core_original_digest:str
    adoption_operation_id:str
    schema:str='d10.graph-adopted-habit-policy.v1'
    def __post_init__(self):
        if (self.schema!='d10.graph-adopted-habit-policy.v1'or type(self.definition)is not HabitPolicyDefinitionV1
                or type(self.core_policy_revision)is not int or self.core_policy_revision!=self.definition.revision
                or any(type(x)is not str or not x for x in(self.core_namespace,self.installation_id,self.core_original_ref,self.adoption_operation_id))):
            raise ValueError('Habit Graph policy is only its exact Core standing original mirror')
        _sha(self.core_original_digest)
    @property
    def digest(self):return canonical_digest(graph_adopted_habit_policy_to_wire_v1(self))

def habit_policy_definition_to_wire_v1(value):
    if type(value)is not HabitPolicyDefinitionV1:raise TypeError('actual Habit policy definition required')
    raw=asdict(value);raw['audience']=list(value.audience);raw['source_refs']=list(value.source_refs)
    for name in ('cue_predicate','stop_predicate'):raw[name]['parameters']=[list(x)for x in raw[name]['parameters']]
    return raw

def habit_source_note_input_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitSourceNoteInputV1)}:raise ValueError('Habit SourceNote standing input fields differ')
    return HabitSourceNoteInputV1(**raw)

def habit_policy_definition_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitPolicyDefinitionV1)}:
        raise ValueError('Habit policy definition wire fields differ')
    return HabitPolicyDefinitionV1(**{**raw,'namespace':NamespaceId(**raw['namespace']),
        'cue_predicate':_predicate_from_wire(raw['cue_predicate']),'stop_predicate':_predicate_from_wire(raw['stop_predicate']),
        'audience':tuple(raw['audience']),'source_refs':tuple(raw['source_refs']),
        'source_note_input':None if raw['source_note_input']is None else habit_source_note_input_from_wire_v1(raw['source_note_input'])})

def graph_adopted_habit_policy_to_wire_v1(value):
    if type(value)is not GraphAdoptedHabitPolicyV1:raise TypeError('actual adopted Habit policy mirror required')
    return {**asdict(value),'definition':habit_policy_definition_to_wire_v1(value.definition)}

def graph_adopted_habit_policy_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(GraphAdoptedHabitPolicyV1)}:
        raise ValueError('Habit adopted policy wire fields differ')
    return GraphAdoptedHabitPolicyV1(**{**raw,'definition':habit_policy_definition_from_wire_v1(raw['definition'])})

def habit_policy_key_v1(namespace,policy_id):
    return AtomKey(Owner('persona',*namespace.as_tuple,namespace.persona_id),HABIT_POLICY_TYPE,policy_id)

def habit_policy_type_spec_v1():
    return TypeSpec(HABIT_POLICY_TYPE,('persona',),'state',graph_adopted_habit_policy_from_wire_v1,writer_domain='d10',schema_hash=schema_hash(HABIT_POLICY_TYPE))


def habit_policy_dependency_refs_v1(definition):
    """Declared Graph dependencies only; this is neither closure nor authority."""
    if type(definition)is not HabitPolicyDefinitionV1:raise TypeError('actual closed Habit policy definition required')
    cue=definition.cue_predicate;stop=definition.stop_predicate
    if cue.kind!='domain_state'or cue.observation_provider not in {'d11.habit-window-cue.v1','d07.habit-cue.v1'}or dict(cue.parameters)!={'policy_id':definition.policy_id}:raise ValueError('unknown Habit cue dependency protocol')
    refs=[definition.project_ref,definition.recipe_ref,definition.target_ref,*definition.source_refs]
    if definition.source_note_input is not None:refs.extend((definition.source_note_input.source_ref,definition.source_note_input.role_binding_ref))
    if stop.kind!='domain_state':raise ValueError('unknown Habit stop dependency protocol')
    parameters=dict(stop.parameters)
    if stop.observation_provider=='d10.habit-policy-stop.v1':
        if parameters!={'policy_id':definition.policy_id}:raise ValueError('Habit control predicate changed exact policy identity')
    elif stop.observation_provider=='d07.habit-stop.v1':
        if set(parameters)!={'policy_id','interpretation_ref'}or parameters['policy_id']!=definition.policy_id:raise ValueError('Habit semantic stop dependency fields differ')
        _graph_ref(definition.namespace,parameters['interpretation_ref'],'d07.current_interpretation.v1');refs.append(parameters['interpretation_ref'])
    else:raise ValueError('unknown Habit stop dependency protocol')
    return tuple(dict.fromkeys(refs))
