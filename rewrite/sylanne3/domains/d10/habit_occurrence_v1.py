"""Durable Habit occurrence identities, missed cues and verified Life outcomes."""
from dataclasses import asdict,dataclass,fields,replace
import math
from ...graph_types import AtomKey,Owner,TypeSpec
from ...runtime_contracts import NamespaceId,canonical_digest,schema_hash
from .habit_policy_v1 import HABIT_OCCURRENCE_TYPE,HABIT_DISPOSITION_TYPE,HABIT_OUTCOME_TYPE,HABIT_EXECUTORS,_graph_ref,_sha

OCCURRENCE_STATES=frozenset(('registered','waiting','qualified','active','completed_verified','failed_verified','cancelled','unknown'))
COUNTED_STATES=OCCURRENCE_STATES

def habit_window_v1(definition,occurred_at_utc):
    if type(occurred_at_utc)not in(int,float)or not math.isfinite(occurred_at_utc)or occurred_at_utc<definition.window_anchor_utc:raise ValueError('cue precedes its actual standing schedule')
    index=math.floor((occurred_at_utc-definition.window_anchor_utc)/definition.window_seconds)
    start=definition.window_anchor_utc+index*definition.window_seconds
    return ('habit-window:'+canonical_digest((definition.namespace,definition.policy_id,start,definition.window_seconds))[:48],start,start+definition.window_seconds)

def habit_occurrence_id_v1(namespace,policy_id,revision,window_id,cue_stable_key):
    return 'habit-occurrence:'+canonical_digest((namespace,policy_id,revision,window_id,cue_stable_key))[:48]

def habit_occurrence_key_v1(ns,identity):return AtomKey(Owner('persona',*ns.as_tuple,ns.persona_id),HABIT_OCCURRENCE_TYPE,identity)

@dataclass(frozen=True,slots=True)
class HabitOccurrenceV1:
    namespace:NamespaceId
    occurrence_id:str
    policy_ref:str
    policy_revision:int
    policy_digest:str
    window_id:str
    window_start_utc:float
    window_end_utc:float
    cue_original_ref:str
    cue_original_digest:str
    cue_stable_key:str
    occurrence_operation_id:str
    activity_id:str
    effect_id:str
    attempt_id:str
    recipe_ref:str
    recipe_revision:int
    executor_kind:str
    parent_root_grant_ref:str
    parent_root_grant_digest:str
    original_deadline_utc:float
    cancellation_generation:int
    state:str
    action_intent_ref:str|None
    life_plan_original_ref:str|None
    qualification_original_ref:str|None
    outcome_original_ref:str|None
    source_refs:tuple[str,...]
    admitted_at_utc:float|None=None
    actual_started_at_utc:float|None=None
    context_original_ref:str|None=None
    context_original_digest:str|None=None
    goal_ref:str|None=None
    plan_ref:str|None=None
    schema:str='d10.habit-occurrence.v1'
    def __post_init__(self):
        if self.schema!='d10.habit-occurrence.v1'or type(self.namespace)is not NamespaceId or self.state not in OCCURRENCE_STATES or self.executor_kind not in HABIT_EXECUTORS or any(type(x)is not int or x<1 for x in(self.policy_revision,self.recipe_revision))or type(self.cancellation_generation)is not int or self.cancellation_generation<0:raise ValueError('occurrence requires exact policy/recipe/cancellation identity')
        _graph_ref(self.namespace,self.policy_ref,'d10.habit_policy.v1');_graph_ref(self.namespace,self.recipe_ref,'d10.activity_recipe.v1')
        for digest in(self.policy_digest,self.cue_original_digest,self.parent_root_grant_digest):_sha(digest)
        if any(not x for x in(self.window_id,self.cue_original_ref,self.cue_stable_key,self.occurrence_operation_id,self.activity_id,self.effect_id,self.attempt_id,self.parent_root_grant_ref)):raise ValueError('occurrence retains its immutable cue and effect identities')
        if type(self.source_refs)is not tuple or not 1<=len(self.source_refs)<=32 or len(set(self.source_refs))!=len(self.source_refs):raise ValueError('occurrence Source roots must be exact')
        for ref in self.source_refs:_graph_ref(self.namespace,ref,'memory.source')
        if not self.window_start_utc<self.original_deadline_utc<=self.window_end_utc:raise ValueError('occurrence cannot extend its original window deadline')
        for value in(self.window_start_utc,self.window_end_utc,self.original_deadline_utc,self.admitted_at_utc,self.actual_started_at_utc):
            if value is not None and(type(value)not in(int,float)or not math.isfinite(value)):raise ValueError('occurrence times must be original finite facts')
        if (self.context_original_ref is None)!=(self.context_original_digest is None):raise ValueError('Habit context original and digest are paired')
        if self.context_original_digest is not None:_sha(self.context_original_digest)
        if self.goal_ref is not None:_graph_ref(self.namespace,self.goal_ref,'d08.goal.v1')
        if self.plan_ref is not None:_graph_ref(self.namespace,self.plan_ref,'d08.personal_plan.v1')
        if self.state in {'qualified','active','completed_verified','failed_verified'}and(not self.qualification_original_ref or self.admitted_at_utc is None):raise ValueError('execution state requires independent actual Core occurrence admission')
        if self.state=='active'and(not self.action_intent_ref or not self.life_plan_original_ref or self.actual_started_at_utc is None):raise ValueError('active occurrence needs actual registered Action/Life start')
        if self.state in {'completed_verified','failed_verified'}and not self.outcome_original_ref:raise ValueError('terminal occurrence needs its actual verified outcome')

@dataclass(frozen=True,slots=True)
class HabitOccurrenceCensusEntryV1:
    ref:str
    revision:int
    value_digest:str
    policy_ref:str
    policy_revision:int
    window_id:str
    state:str
    admitted_at_utc:float|None
    actual_started_at_utc:float|None
    effect_id:str
    def __post_init__(self):
        if AtomKey.from_token(self.ref).type_name!=HABIT_OCCURRENCE_TYPE or self.revision<1 or self.policy_revision<1 or self.state not in OCCURRENCE_STATES or not self.window_id or not self.effect_id:raise ValueError('Habit census retains exact current identity metadata')
        _sha(self.value_digest)

@dataclass(frozen=True,slots=True)
class HabitOccurrenceSelectorV1:
    namespace:NamespaceId
    policy_ref:str
    policy_revision:int
    policy_digest:str
    window_id:str
    window_start_utc:float
    window_end_utc:float
    cue_original_ref:str
    cue_original_digest:str
    cue_stable_key:str
    occurrence_original_ref:str
    occurrence_original_digest:str
    operation_id:str
    execution_operation_id:str
    activity_id:str
    effect_id:str
    attempt_id:str
    request_digest:str
    recipe_ref:str
    recipe_revision:int
    executor_kind:str
    standing_authorization_original_ref:str
    standing_authorization_original_digest:str
    parent_root_grant_ref:str
    parent_root_grant_digest:str
    original_deadline_utc:float
    purpose:str
    audience:tuple[str,...]
    target_ref:str
    cancellation_generation:int
    source_refs:tuple[str,...]
    schema:str='d10.habit-occurrence-selector.v1'
    def __post_init__(self):
        if self.schema!='d10.habit-occurrence-selector.v1'or self.purpose!='context'or type(self.namespace)is not NamespaceId or self.executor_kind not in HABIT_EXECUTORS:raise ValueError('fixed Habit selector purpose/recipe/namespace required')
        _graph_ref(self.namespace,self.policy_ref,'d10.habit_policy.v1');_graph_ref(self.namespace,self.recipe_ref,'d10.activity_recipe.v1')
        for name in('policy_digest','cue_original_digest','occurrence_original_digest','request_digest','standing_authorization_original_digest','parent_root_grant_digest'):_sha(getattr(self,name))
        if not all((self.occurrence_original_ref,self.standing_authorization_original_ref,self.operation_id,self.execution_operation_id,self.activity_id,self.effect_id,self.attempt_id,self.target_ref,self.cue_stable_key))or not self.audience or not self.source_refs:raise ValueError('Habit selector cannot invent missing actual original identities')

@dataclass(frozen=True,slots=True)
class HabitDispositionV1:
    namespace:NamespaceId
    disposition_id:str
    policy_ref:str
    policy_revision:int
    window_id:str
    cue_original_ref:str
    disposition:str
    reason_ref:str
    original_deadline_utc:float
    recorded_at_utc:float
    source_refs:tuple[str,...]
    schema:str='d10.habit-disposition.v1'
    def __post_init__(self):
        if self.schema!='d10.habit-disposition.v1'or self.disposition not in {'skipped','wait','reschedule-required'}or not self.reason_ref or not self.cue_original_ref or type(self.policy_revision)is not int or self.policy_revision<1:raise ValueError('miss disposition contains no execution or Experience result')
        _graph_ref(self.namespace,self.policy_ref,'d10.habit_policy.v1')
        if self.recorded_at_utc<self.original_deadline_utc:raise ValueError('miss must follow its original occurrence deadline')
        for ref in self.source_refs:_graph_ref(self.namespace,ref,'memory.source')

@dataclass(frozen=True,slots=True)
class HabitOutcomeV1:
    namespace:NamespaceId
    outcome_id:str
    occurrence_ref:str
    occurrence_revision:int
    life_progress_ref:str
    life_progress_revision:int
    life_outcome_original_ref:str
    actual_terminal_original_ref:str
    accounting_original_refs:tuple[str,...]
    encoding_trigger_ref:str
    growth_trigger_ref:str
    source_refs:tuple[str,...]
    schema:str='d10.habit-outcome.v1'
    def __post_init__(self):
        if self.schema!='d10.habit-outcome.v1'or any(type(x)is not int or x<1 for x in(self.occurrence_revision,self.life_progress_revision))or not all((self.life_outcome_original_ref,self.actual_terminal_original_ref,self.encoding_trigger_ref,self.growth_trigger_ref)):raise ValueError('Habit outcome references actual Life/terminal/encoding/growth originals')
        _graph_ref(self.namespace,self.occurrence_ref,HABIT_OCCURRENCE_TYPE);_graph_ref(self.namespace,self.life_progress_ref,'d10.life_progress.v1')
        if not self.accounting_original_refs:raise ValueError('Habit outcome requires actual accounting originals')
        for ref in self.source_refs:_graph_ref(self.namespace,ref,'memory.source')

_TYPES={HABIT_OCCURRENCE_TYPE:HabitOccurrenceV1,HABIT_DISPOSITION_TYPE:HabitDispositionV1,HABIT_OUTCOME_TYPE:HabitOutcomeV1}
def habit_value_to_wire_v1(value):
    if type(value)not in _TYPES.values()and type(value)is not HabitOccurrenceSelectorV1:raise TypeError('registered Habit value required')
    return asdict(value)
def habit_value_from_wire_v1(kind,raw):
    cls=HabitOccurrenceSelectorV1 if kind=='d10.habit-occurrence-selector.v1'else _TYPES[kind]
    if type(raw)is not dict or set(raw)!={f.name for f in fields(cls)}:raise ValueError('Habit closed value fields differ')
    values={**raw,'namespace':NamespaceId(**raw['namespace']),'source_refs':tuple(raw['source_refs'])}
    for name in('accounting_original_refs','audience'):
        if name in values:values[name]=tuple(values[name])
    return cls(**values)
def habit_occurrence_type_specs_v1():
    return tuple(TypeSpec(kind,('persona',),'state',lambda raw,k=kind:habit_value_from_wire_v1(k,raw),immutable=kind!=HABIT_OCCURRENCE_TYPE,writer_domain='d10',schema_hash=schema_hash(kind))for kind in _TYPES)


def validate_habit_graph_proposal_v1(proposal,snapshot):
    from .habit_policy_v1 import HABIT_POLICY_TYPE,habit_policy_key_v1,graph_adopted_habit_policy_from_wire_v1
    from ...runtime_contracts import NamespaceId,canonical_digest
    if proposal.envelope.identity.phase=='instantiate_current_habit_source_note_context_v1'and {w.key.type_name for w in proposal.typed_writes}=={HABIT_OCCURRENCE_TYPE,'d10.project_checkpoint.v1'}:
        from .project_checkpoint_v1 import decode_project_checkpoint_type_v1
        checkpoints=tuple(w for w in proposal.typed_writes if w.key.type_name=='d10.project_checkpoint.v1')
        if len(checkpoints)!=1 or len(proposal.typed_writes)!=2:raise ValueError('Habit context changes exactly one checkpoint and its occurrence')
        checkpoint=decode_project_checkpoint_type_v1('d10.project_checkpoint.v1',checkpoints[0].value)
        guarded={v.key:v.revision for v in proposal.envelope.version_guard.read_versions}
        if checkpoints[0].key not in guarded or checkpoint.revision!=guarded[checkpoints[0].key]+1:raise ValueError('Habit checkpoint transition needs its actual expected head')
        nested=replace(proposal,typed_writes=tuple(w for w in proposal.typed_writes if w.key.type_name==HABIT_OCCURRENCE_TYPE))
        return validate_habit_graph_proposal_v1(nested,snapshot)
    supported={HABIT_POLICY_TYPE,HABIT_OCCURRENCE_TYPE,HABIT_DISPOSITION_TYPE,HABIT_OUTCOME_TYPE}
    if not proposal.typed_writes or not all(w.key.type_name in supported for w in proposal.typed_writes):return False
    if proposal.contribution_keys or proposal.required_bundle_parts:raise ValueError('Habit bookkeeping cannot issue a contribution, execution bundle or permission')
    if len(proposal.typed_writes)>1 and {w.key.type_name for w in proposal.typed_writes}!={HABIT_OCCURRENCE_TYPE,HABIT_OUTCOME_TYPE}:raise ValueError('Habit compound writes only its occurrence and actual outcome')
    guarded={v.key:v.revision for v in proposal.envelope.version_guard.read_versions};ns=proposal.envelope.authority.namespace
    mutable={'state','action_intent_ref','life_plan_original_ref','qualification_original_ref','outcome_original_ref','source_refs','admitted_at_utc','actual_started_at_utc','context_original_ref','context_original_digest','goal_ref','plan_ref'}
    for write in proposal.typed_writes:
        if write.key not in guarded or NamespaceId.from_key(write.key)!=ns or write.key.owner.kind!='persona':raise ValueError('Habit value must use its exact namespace and current/absence CAS head')
        value=graph_adopted_habit_policy_from_wire_v1(write.value)if write.key.type_name==HABIT_POLICY_TYPE else habit_value_from_wire_v1(write.key.type_name,write.value)
        if write.key.type_name==HABIT_POLICY_TYPE:
            if write.key!=habit_policy_key_v1(ns,value.definition.policy_id)or value.definition.namespace!=ns:raise ValueError('Habit policy mirror has another actual key')
        elif write.key.type_name==HABIT_OCCURRENCE_TYPE:
            identity=habit_occurrence_id_v1(ns,AtomKey.from_token(value.policy_ref).name,value.policy_revision,value.window_id,value.cue_stable_key)
            if write.key!=habit_occurrence_key_v1(ns,identity)or value.occurrence_id!=identity:raise ValueError('Habit occurrence key must derive from the original policy revision/window/cue')
            if snapshot is not None:
                prior=snapshot.get(write.key)
                if prior is not None and prior.valid:
                    old=habit_value_from_wire_v1(HABIT_OCCURRENCE_TYPE,prior.value)
                    if any(getattr(old,f.name)!=getattr(value,f.name)for f in fields(HabitOccurrenceV1)if f.name not in mutable):raise ValueError('Habit transition cannot rewrite original effect, Root, policy, cue or TTL')
        else:
            identity=value.disposition_id if write.key.type_name==HABIT_DISPOSITION_TYPE else value.outcome_id
            if write.key.name!=identity or value.namespace!=ns:raise ValueError('Habit immutable record key differs')
    return True
