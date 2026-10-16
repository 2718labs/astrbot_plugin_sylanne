"""Closed SourceNote recipe phases; old qualification is evidence, never a fresh permit."""
from dataclasses import asdict,dataclass,fields
from .d10_habit_contract_v1 import _sha_v1
from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceSelectorV1,habit_value_from_wire_v1,habit_value_to_wire_v1
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId

HABIT_SOURCE_NOTE_EXECUTION_KINDS_V1=frozenset(('instantiate_current_habit_source_note_context_v1',
    'prepare_current_habit_source_note_action_v1','prepare_source_note_body',
    'register_current_habit_source_note_life_plan_v1','prepare_life'))

@dataclass(frozen=True,slots=True)
class HabitOccurrencePhaseCommandV1:
    occurrence_ref:str
    expected_revision:int
    schema:str='d10.habit-occurrence-phase-command.v1'
    def __post_init__(self):
        if(self.schema!='d10.habit-occurrence-phase-command.v1'or type(self.expected_revision)is not int
                or self.expected_revision<1 or AtomKey.from_token(self.occurrence_ref).type_name!='d10.habit_occurrence.v1'):
            raise ValueError('Habit phase command requires exact current occurrence identity')

@dataclass(frozen=True,slots=True)
class HabitSourceNoteBodyCommandV1:
    action_intent_ref:str
    body_policy_id:str
    body_policy_version:int
    effect_policy_ref:str
    cpu_ceiling_ms:int
    preparation:object
    schema:str='d10.habit-source-note-body-command.v1'
    def __post_init__(self):
        from .habit_body_preparation_v3 import HabitBodyCPUPreparationV3
        if(self.schema!='d10.habit-source-note-body-command.v1'or type(self.preparation)is not HabitBodyCPUPreparationV3
                or self.cpu_ceiling_ms!=self.preparation.cpu_ceiling_ms):raise ValueError('fixed Habit Body command requires actual CPU preparation')

@dataclass(frozen=True,slots=True)
class HabitSourceNoteLifeCommandV1:
    plan_original_ref:str
    prepare_operation_id:str
    schema:str='d10.habit-source-note-life-command.v1'
    def __post_init__(self):
        if self.schema!='d10.habit-source-note-life-command.v1':raise ValueError('fixed Habit Life command schema required')

_COMMAND_TYPES={kind:(HabitSourceNoteBodyCommandV1 if kind=='prepare_source_note_body'else
    HabitSourceNoteLifeCommandV1 if kind=='prepare_life'else HabitOccurrencePhaseCommandV1)for kind in HABIT_SOURCE_NOTE_EXECUTION_KINDS_V1}

@dataclass(frozen=True,slots=True)
class HabitOccurrenceExecutionSelectorV1:
    namespace:NamespaceId
    qualification_selector:HabitOccurrenceSelectorV1
    qualification_original_ref:str
    qualification_original_digest:str
    occurrence_ref:str
    expected_occurrence_revision:int
    operation_kind:str
    operation_id:str
    request_digest:str
    command:HabitOccurrencePhaseCommandV1|HabitSourceNoteBodyCommandV1|HabitSourceNoteLifeCommandV1
    schema:str='d10.habit-occurrence-execution-selector.v1'
    def __post_init__(self):
        if(self.schema!='d10.habit-occurrence-execution-selector.v1'or type(self.namespace)is not NamespaceId
                or type(self.qualification_selector)is not HabitOccurrenceSelectorV1
                or self.qualification_selector.namespace!=self.namespace or self.qualification_selector.executor_kind!='source_note'
                or self.operation_kind not in HABIT_SOURCE_NOTE_EXECUTION_KINDS_V1
                or type(self.expected_occurrence_revision)is not int or self.expected_occurrence_revision<1
                or self.operation_id==self.qualification_selector.operation_id
                or type(self.qualification_original_ref)is not str or not self.qualification_original_ref.startswith('habit-qualification:')):
            raise ValueError('Habit execution needs its fixed phase, exact prior qualification and a distinct fresh operation')
        key=AtomKey.from_token(self.occurrence_ref)
        if key.type_name!='d10.habit_occurrence.v1'or NamespaceId.from_key(key)!=self.namespace:
            raise ValueError('Habit execution occurrence crossed actual namespace/type')
        if type(self.command)is not _COMMAND_TYPES[self.operation_kind]:raise ValueError('Habit execution phase command type differs')
        if(type(self.command)is HabitOccurrencePhaseCommandV1 and
                (self.command.occurrence_ref,self.command.expected_revision)!=(self.occurrence_ref,self.expected_occurrence_revision)):
            raise ValueError('Habit execution changed its exact current occurrence command')
        for value in(self.qualification_original_digest,self.request_digest):_sha_v1(value)
    @property
    def original_deadline_utc(self):return self.qualification_selector.original_deadline_utc

def habit_occurrence_execution_to_wire_v1(value):
    if type(value)is not HabitOccurrenceExecutionSelectorV1:raise TypeError('exact registered Habit execution selector required')
    return {**asdict(value),'qualification_selector':habit_value_to_wire_v1(value.qualification_selector)}

def habit_occurrence_execution_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitOccurrenceExecutionSelectorV1)}:
        raise ValueError('Habit execution selector closed fields differ')
    cls=_COMMAND_TYPES[raw['operation_kind']];command=raw['command']
    if cls is HabitSourceNoteBodyCommandV1:
        from .habit_body_preparation_v3 import preparation_from_domain_plain_v3
        command={**command,'preparation':preparation_from_domain_plain_v3(command['preparation'])}
    if type(command)is not dict or set(command)!={f.name for f in fields(cls)}:raise ValueError('Habit execution command closed fields differ')
    return HabitOccurrenceExecutionSelectorV1(**{**raw,'namespace':NamespaceId(**raw['namespace']),
        'command':cls(**command),'qualification_selector':habit_value_from_wire_v1('d10.habit-occurrence-selector.v1',raw['qualification_selector'])})

def habit_execution_typed_request_v1(selector):
    from ..runtime.domain_production_registry_v1 import installed_operation_v1
    if type(selector)is not HabitOccurrenceExecutionSelectorV1:raise TypeError('actual fixed Habit phase selector required')
    operation=installed_operation_v1(selector.operation_kind)
    request=operation.request_type(**{name:value for name,value in asdict(selector.command).items()if name not in {'schema','preparation'}})
    return operation,request

def habit_execution_purpose_v1(selector):
    if type(selector)is not HabitOccurrenceExecutionSelectorV1:raise TypeError('actual fixed Habit phase selector required')
    return 'context'if selector.operation_kind=='instantiate_current_habit_source_note_context_v1'else 'consolidation'


def habit_execution_phase_identity_v1(selector):
    if type(selector)is not HabitOccurrenceExecutionSelectorV1:raise TypeError('actual fixed Habit phase selector required')
    original=selector.qualification_selector;kind=selector.operation_kind
    effect=None if kind in {'instantiate_current_habit_source_note_context_v1','register_current_habit_source_note_life_plan_v1'}else original.effect_id
    attempt=original.attempt_id if kind=='prepare_current_habit_source_note_action_v1'else selector.operation_id
    return original.activity_id,effect,attempt

def habit_execution_write_domains_v1(selector):
    if type(selector)is not HabitOccurrenceExecutionSelectorV1:raise TypeError('actual fixed Habit phase selector required')
    return {'instantiate_current_habit_source_note_context_v1':('d08','d10','d11'),
        'prepare_current_habit_source_note_action_v1':('d08','d10','d11'),
        'prepare_source_note_body':('d02',),'register_current_habit_source_note_life_plan_v1':('d10','d11'),
        'prepare_life':('d10','d11')}[selector.operation_kind]
