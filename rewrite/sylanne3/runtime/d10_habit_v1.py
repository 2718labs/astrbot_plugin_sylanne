"""B3 Habit Graph mirrors and durable occurrences; Core alone grants occurrence eligibility."""
from dataclasses import dataclass,replace
from ..domains.d01.production_operations_v1 import plain_v1,stage_result_v1
from ..domains.d10.habit_policy_v1 import HabitPolicyDefinitionV1,GraphAdoptedHabitPolicyV1,HABIT_POLICY_TYPE,HABIT_OCCURRENCE_TYPE,HABIT_DISPOSITION_TYPE,HABIT_OUTCOME_TYPE,habit_policy_key_v1,habit_policy_definition_from_wire_v1,graph_adopted_habit_policy_from_wire_v1,graph_adopted_habit_policy_to_wire_v1
from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceV1,HabitOccurrenceSelectorV1,HabitDispositionV1,HabitOutcomeV1,habit_occurrence_id_v1,habit_window_v1,habit_occurrence_key_v1,habit_value_from_wire_v1,habit_value_to_wire_v1
from ..graph_types import AtomKey,GraphWrite,GraphVersion,Owner,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest,schema_hash
from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1,production_read_plan_v1,waiting_stage_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1

POLICY_OPERATIONS=frozenset(('create_habit_policy_v1','revise_habit_policy_v1','pause_habit_policy_v1','resume_habit_policy_v1','stop_habit_policy_v1'))
SOURCE_NOTE_OPERATIONS=frozenset(('instantiate_current_habit_source_note_context_v1','prepare_current_habit_source_note_action_v1','register_current_habit_source_note_life_plan_v1'))
OPERATIONS=POLICY_OPERATIONS|SOURCE_NOTE_OPERATIONS|frozenset(('register_habit_occurrence_v1','qualify_habit_occurrence_v1','record_habit_miss_v1','adopt_habit_outcome_v1'))

@dataclass(frozen=True,slots=True)
class CreateHabitPolicyRequestV1:
    definition:HabitPolicyDefinitionV1
    def __post_init__(self):
        if type(self.definition)is not HabitPolicyDefinitionV1:raise ValueError('Habit policy management requires its exact definition')

@dataclass(frozen=True,slots=True)
class ReviseHabitPolicyRequestV1:
    policy_ref:str
    expected_revision:int
    definition:HabitPolicyDefinitionV1

@dataclass(frozen=True,slots=True)
class PauseHabitPolicyRequestV1(ReviseHabitPolicyRequestV1):pass
@dataclass(frozen=True,slots=True)
class ResumeHabitPolicyRequestV1(ReviseHabitPolicyRequestV1):pass
@dataclass(frozen=True,slots=True)
class StopHabitPolicyRequestV1(ReviseHabitPolicyRequestV1):pass

@dataclass(frozen=True,slots=True)
class RegisterHabitOccurrenceRequestV1:
    policy_ref:str
    expected_policy_revision:int
    cue_original_ref:str
    cue_original_digest:str

@dataclass(frozen=True,slots=True)
class QualifyHabitOccurrenceRequestV1:
    occurrence_ref:str
    expected_revision:int

@dataclass(frozen=True,slots=True)
class InstantiateCurrentHabitSourceNoteContextRequestV1:
    occurrence_ref:str
    expected_revision:int

@dataclass(frozen=True,slots=True)
class PrepareCurrentHabitSourceNoteActionRequestV1:
    occurrence_ref:str
    expected_revision:int

@dataclass(frozen=True,slots=True)
class RegisterCurrentHabitSourceNoteLifePlanRequestV1:
    occurrence_ref:str
    expected_revision:int

@dataclass(frozen=True,slots=True)
class InstalledHabitSourceNoteReadersV1:
    legacy_readers:object
    life_readers:object
    def __post_init__(self):
        from .d08_production_operations_v1 import InstalledD08ProductionReadersV1
        from .d10_production_operations_v1 import InstalledD10ProductionReadersV1
        if type(self.legacy_readers)is not InstalledD08ProductionReadersV1 or type(self.life_readers)is not InstalledD10ProductionReadersV1 or self.legacy_readers.issuer is not self.life_readers.issuer:raise TypeError('Habit SourceNote requires the actual installed D08 and Life readers from the same issuer')
    @property
    def issuer(self):return self.life_readers.issuer

@dataclass(frozen=True,slots=True)
class RecordHabitMissRequestV1:
    occurrence_ref:str
    expected_revision:int
    reason_ref:str

@dataclass(frozen=True,slots=True)
class AdoptHabitOutcomeRequestV1:
    occurrence_ref:str
    expected_revision:int
    life_progress_ref:str
    life_progress_revision:int
    life_outcome_original_ref:str
    actual_terminal_original_ref:str
    accounting_original_refs:tuple[str,...]
    encoding_trigger_ref:str
    growth_trigger_ref:str

@dataclass(frozen=True,slots=True)
class ObserveCurrentJointHabitRecoveryRequestV1:
    producer_operation_id:str
    def __post_init__(self):
        if type(self.producer_operation_id)is not str or not self.producer_operation_id:raise ValueError('cold recovery observes an exact existing COMMIT operation')

@dataclass(frozen=True,slots=True)
class HabitRecoveryObservationV1:
    namespace:NamespaceId
    producer_original:ProductionOriginalRefV1
    producer_operation_id:str
    producing_receipt_digest:str
    occurrence_ref:str|None
    occurrence_revision:int|None
    state:str
    activity_id:str|None
    effect_id:str|None
    attempt_id:str|None
    outcome_original_ref:str|None
    disposition_ref:str|None
    coverage:str
    missing_inputs:tuple[str,...]

@dataclass(frozen=True,slots=True)
class JointHabitRecoveryReadV1:
    domain:str
    observation:object
    coverage:str
    missing_inputs:tuple[str,...]

_REQUESTS={'register_current_habit_source_note_life_plan_v1':RegisterCurrentHabitSourceNoteLifePlanRequestV1,'instantiate_current_habit_source_note_context_v1':InstantiateCurrentHabitSourceNoteContextRequestV1,'prepare_current_habit_source_note_action_v1':PrepareCurrentHabitSourceNoteActionRequestV1,'create_habit_policy_v1':CreateHabitPolicyRequestV1,'revise_habit_policy_v1':ReviseHabitPolicyRequestV1,'pause_habit_policy_v1':PauseHabitPolicyRequestV1,'resume_habit_policy_v1':ResumeHabitPolicyRequestV1,'stop_habit_policy_v1':StopHabitPolicyRequestV1,'register_habit_occurrence_v1':RegisterHabitOccurrenceRequestV1,'qualify_habit_occurrence_v1':QualifyHabitOccurrenceRequestV1,'record_habit_miss_v1':RecordHabitMissRequestV1,'adopt_habit_outcome_v1':AdoptHabitOutcomeRequestV1}
def habit_request_from_wire_v1(kind,raw):
    from dataclasses import fields
    cls=_REQUESTS[kind]
    if type(raw)is not dict or set(raw)!={f.name for f in fields(cls)}:raise ValueError('Habit request closed fields differ')
    values=dict(raw)
    if 'definition'in values:values['definition']=habit_policy_definition_from_wire_v1(values['definition'])
    if 'accounting_original_refs'in values:values['accounting_original_refs']=tuple(values['accounting_original_refs'])
    return cls(**values)


@dataclass(frozen=True,slots=True)
class HabitSelectedExecutionV1:
    future_identity:object
    phase_selector:object|None
    prepared_candidates_operation_id:str
    prepared_candidates_digest:str
    decision_ref:str
    decision_digest:str


def read_current_habit_execution_target_v1(db,*,read,definition,issuer,require_unused):
    from ..domains.d08.personal_candidate_v1 import ConsumePersonalDecisionRequestV1,PreparedPersonalCandidateSetV1,ArtifactPhaseCandidateBindingV3
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_background_read_v3 import background_history_v3
    from .d08_personal_candidate_v1 import _selected_candidate_phase_selector_from_originals_v2
    if definition.executor_kind!='draft_file':raise TypeError('selected generation reader belongs only to the actual DraftFile recipe')
    decision=read.head(db,definition.target_ref,required=True)
    if decision.key.type_name!='d08.decision_record.v2':raise ValueError('Habit target is the actual adopted selected Decision, not a new task or free filename')
    history=background_history_v3(db,decision.key.token,decision.revision,columns=('event_id',))
    if history is None:raise MissingProductionOriginalV1('actual_habit_selected_Decision_W01')
    selection=read_adopted_domain_operation_v1(db,definition.namespace,history[0])
    if selection is None or selection['domain']!='d08' or selection['receipt'].status!='committed':raise MissingProductionOriginalV1('actual_habit_selected_Decision_COMMIT')
    read.committed_operation(db,history[0])
    preparation_id=selection['payload']['provenance']['prepared_candidates_operation_id']
    original=read_adopted_domain_operation_v1(db,definition.namespace,preparation_id)
    if original is None or(original['domain'],original['operation_kind'])!=('d08','prepare_personal_candidates_v1'):raise MissingProductionOriginalV1('actual_habit_selected_preparation')
    read.committed_operation(db,preparation_id)
    prepared=decode_typed_production_value_v1(original['payload']['provenance']['prepared_candidates'],PreparedPersonalCandidateSetV1)
    chosen=tuple(c for c in prepared.candidates if c.future_identity.action_ref==decision.value['chosen_action_ref'])
    if len(chosen)!=1 or chosen[0].eligibility.hard_status!='eligible' or prepared.future_decision_ref!=decision.key.token or prepared.selection_operation_id!=history[0] or not prepared.need.complete or prepared.need.new_c3_required or prepared.need.meaningful_gaps:raise MissingProductionOriginalV1('actual_eligible_selected_habit_execution_generation')
    candidate=chosen[0];future=candidate.future_identity;binding=candidate.binding
    selector=None
    if type(binding)is not ArtifactPhaseCandidateBindingV3:raise ValueError('Habit DraftFile requires the actual approved prospective phase generation')
    consume=ConsumePersonalDecisionRequestV1(decision.key.token,preparation_id)
    selector=_selected_candidate_phase_selector_from_originals_v2(db,namespace=definition.namespace,request=consume,issuer=issuer)
    from .d11_artifact_draft_model_v1 import _read_artifact_phase_selected_originals_v2,_current_artifact_phase_parameters_v2,read_artifact_draft_prepared_v2
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v2
    exact,selected,checked=_read_artifact_phase_selected_originals_v2(db,selector=selector,issuer=issuer)
    if exact!=prepared or selected!=candidate or checked!=original:raise ValueError('Habit phase selector changed the original selected generation')
    _current_artifact_phase_parameters_v2(db,selector=selector,chosen=candidate,issuer=issuer)
    actual=artifact_draft_file_ids_v2(selector)
    if(future.action_operation_id,future.activity_id,future.effect_id,future.attempt_id)!=(actual['action_operation'],AtomKey.from_token(binding.task.cycle_job_ref).owner.subject,actual['effect'],actual['attempt']):raise ValueError('Habit DraftFile identity differs from actual PhaseSelector')
    if require_unused and read_artifact_draft_prepared_v2(db,namespace=definition.namespace,issuer=issuer,selector=selector)is not None:raise MissingProductionOriginalV1('observe_original_started_or_unknown_artifact_generation_without_new_admission')
    if future.parent_budget_lease_ref!=definition.parent_root_grant_ref or read.frame.now_utc>=min(future.deadline_utc,definition.original_valid_until_utc):raise MissingProductionOriginalV1('actual_selected_habit_original_Root_and_absolute_deadline')
    if require_unused:
        from .d11_types import runtime_job_key
        from .d11_life_preparation_v1 import life_ids_v1
        from types import SimpleNamespace
        job=life_ids_v1(SimpleNamespace(activity_id=future.activity_id,effect_id=future.effect_id,attempt_id=future.attempt_id,operation_id=future.action_operation_id))['job']
        if read.head(db,runtime_job_key(*definition.namespace.as_tuple,future.activity_id,job)).revision or read_adopted_domain_operation_v1(db,definition.namespace,future.action_operation_id)is not None:raise MissingProductionOriginalV1('actual_unused_habit_selected_execution_once_identity')
    return HabitSelectedExecutionV1(future,selector,preparation_id,original['original_digest'],decision.key.token,canonical_digest(decision.value))

def habit_source_note_context_operation_id_v1(namespace,occurrence_id):
    return 'habit-source-note-context:'+canonical_digest(('d10.habit-source-note.v1',namespace,occurrence_id))[:48]

def habit_source_note_execution_identity_v1(namespace,occurrence_id,project_ref):
    from .d08_source_note_action_v1 import source_note_effect_id_v1,source_note_attempt_id_v1
    operation='habit-source-note-action:'+canonical_digest(('d10.habit-source-note.v1',namespace,occurrence_id))[:48]
    return operation,'habit-activity:'+canonical_digest((namespace,occurrence_id))[:48],source_note_effect_id_v1(namespace,project_ref,operation),source_note_attempt_id_v1(namespace,project_ref,operation)

def habit_registration_operation_id_v1(namespace,occurrence_id):return 'habit-register:'+canonical_digest((namespace,occurrence_id))[:48]

def habit_cue_question_scope_v1(definition):return 'd10.habit-cue:'+canonical_digest((definition.namespace,definition.policy_id,definition.revision,definition.cue_predicate))

def _entry(db,frame,kind,request,installed):
    from .current_habit_source_read_v3 import require_current_habit_source_frame_v3
    from .d10_production_operations_v1 import InstalledD10ProductionReadersV1
    require_current_habit_source_frame_v3(db,frame=frame,operation_kind=kind,request=request)
    if type(installed)is not InstalledD10ProductionReadersV1:raise TypeError('Habit uses the actual installed Life original reader')
    purpose='consolidation'if kind in {'adopt_habit_outcome_v1','prepare_current_habit_source_note_action_v1','register_current_habit_source_note_life_plan_v1'}else 'context'
    if frame.envelope.authority.purpose!=purpose:raise ValueError('Habit operation changed its fixed Source purpose')
    from .habit_maintenance_frame_v1 import CurrentHabitMaintenanceFrameV1,CurrentHabitMaintenanceReadV1
    read=CurrentHabitMaintenanceReadV1(frame)if type(frame)is CurrentHabitMaintenanceFrameV1 else CurrentDomainReadV1(frame)
    read.check(db);return read

def _policy(db,read,ref,revision=None,*,enabled=True):
    atom=read.head(db,ref,required=True)
    if atom.key.type_name!=HABIT_POLICY_TYPE or revision is not None and atom.revision!=revision:raise ValueError('Habit policy current head changed')
    policy=graph_adopted_habit_policy_from_wire_v1(atom.value);definition=policy.definition
    if definition.namespace!=read.frame.envelope.authority.namespace or enabled and definition.state!='enabled':raise MissingProductionOriginalV1('current_enabled_habit_policy')
    read.source_family(db,definition.source_refs,purpose=definition.purpose)
    from .habit_maintenance_frame_v1 import CurrentHabitMaintenanceFrameV1,require_habit_maintenance_frame_v1
    if type(read.frame)is CurrentHabitMaintenanceFrameV1:
        facts=require_habit_maintenance_frame_v1(read.frame)
        if (atom.key.token!=facts.request.policy_ref or definition!=facts.policy_original.definition
                or(policy.core_original_ref,policy.core_original_digest)!=(facts.policy_original.original_ref,facts.policy_original.digest)):
            raise ValueError('Habit maintenance current policy mirror differs from its independent Core head')
        policy=facts.standing_original;definition=policy.definition
        read.source_family(db,definition.source_refs,purpose=definition.purpose)
    if not set(read.frame.envelope.authority.audience)<=set(definition.audience)or read.frame.envelope.parent_budget_lease_ref!=definition.parent_root_grant_ref:raise ValueError('Habit changed signed audience or original Root lease')
    return atom,policy

def _occurrence(db,read,ref,revision=None):
    atom=read.head(db,ref,required=True)
    if atom.key.type_name!=HABIT_OCCURRENCE_TYPE or revision is not None and atom.revision!=revision:raise ValueError('Habit occurrence current head changed')
    value=habit_value_from_wire_v1(HABIT_OCCURRENCE_TYPE,atom.value)
    read.source_family(db,value.source_refs)
    return atom,value

def _write(frame,atom,value,*,policy=False):
    raw=graph_adopted_habit_policy_to_wire_v1(value)if policy else habit_value_to_wire_v1(value)
    return GraphWrite(atom.key,raw,dependencies=tuple(v.key for v in frame.snapshot.versions if v.key!=atom.key))

def _new(frame,key,value):
    atom=frame.snapshot.get(key)
    if atom is None or atom.revision!=0 or atom.valid:raise ValueError('Habit durable identity already exists')
    return _write(frame,atom,value,policy=type(value)is GraphAdoptedHabitPolicyV1)

def _core_inputs(db,frame,kind,request):
    from .current_habit_source_read_v3 import require_current_habit_core_inputs_v3
    return require_current_habit_core_inputs_v3(db,frame=frame,operation_kind=kind,request=request)

def _semantic_definition(definition):
    return {k:plain_v1(getattr(definition,k))for k in('policy_id','project_ref','recipe_ref','recipe_revision','executor_kind','cue_predicate','window_anchor_utc','window_seconds','execution_seconds','minimum_interval_seconds','maximum_occurrences_per_window','miss_policy','stop_predicate','state','purpose','audience','target_ref','source_note_input')}

def _emit(db,frame,kind,request,*,writes,provenance,causal,roots,semantic,cancellation_generation,original_deadline_utc,events=(),versions=(),predecessors=(),wait=None,subscription_jobs=None):
    from .domain_mesh_tick_v1 import MeshTickInputsV1,stage_joint_habit_mesh_companion_v1,combine_semantic_mesh_stage_v1
    inputs=MeshTickInputsV1(causal_original=causal,source_roots=roots,predecessors=predecessors,semantic_originals=(causal,),semantic_versions=versions,cancellation_generation=cancellation_generation,semantic_digest=canonical_digest(semantic),original_deadline_utc=original_deadline_utc,wait=wait)
    from .habit_maintenance_frame_v1 import CurrentHabitMaintenanceFrameV1,stage_habit_maintenance_result_v1
    if type(frame)is CurrentHabitMaintenanceFrameV1:
        from .domain_mesh_tick_v1 import stage_habit_original_maintenance_mesh_companion_v1
        companion=stage_habit_original_maintenance_mesh_companion_v1(db,frame=frame,operation_kind=kind,request=request,actual_inputs=inputs)
        base=stage_habit_maintenance_result_v1(frame,'d10',kind,request,writes=writes,provenance={**provenance,'semantic_mesh':companion.trace},receiver_events=events,proposal_schema='d10.proposal.v1',proposal_hash=schema_hash({'domain':'d10','proposal':1}))
    else:
        companion=stage_joint_habit_mesh_companion_v1(db,frame=frame,operation_kind=kind,request=request,actual_inputs=inputs)
        base=stage_result_v1(frame,'d10',kind,request,writes=writes,provenance={**provenance,'semantic_mesh':companion.trace},receiver_events=events,proposal_schema='d10.proposal.v1',proposal_hash=schema_hash({'domain':'d10','proposal':1}))
    if subscription_jobs is None:return combine_semantic_mesh_stage_v1(base,companion)
    from .habit_schedule_driver_v1 import attach_habit_schedule_stage_v1
    schedule=attach_habit_schedule_stage_v1(base,frame=frame,before_jobs=subscription_jobs[0],after_jobs=subscription_jobs[1],window_census=subscription_jobs[2])
    return replace(schedule,stage=combine_semantic_mesh_stage_v1(schedule.stage,companion))

def _mirror_policy(db,*,frame,request,installed,kind):
    from ..authority_service.d10_habit_contract_v1 import HabitStandingPolicyOriginalV1
    read=_entry(db,frame,kind,request,installed);original=installed.habit_policy_original_v1;definition=request.definition
    if type(original)is not HabitStandingPolicyOriginalV1 or original.definition!=definition or original.namespace!=frame.envelope.authority.namespace or original.owner_head_digest.removeprefix('sha256:')!=frame.owner_guard.owner_head_digest or original.root_lease_id!=frame.envelope.parent_budget_lease_ref:raise ValueError('Graph Habit mirror differs from actual currently issued Core policy')
    read.source_family(db,definition.source_refs,purpose='context')
    project=read.head(db,definition.project_ref,required=True);recipe=read.head(db,definition.recipe_ref,required=True)
    if project.value['reality']!='real_execution'or recipe.revision!=definition.recipe_revision or recipe.value['reality']!='real_execution':raise MissingProductionOriginalV1('actual_habit_real_project_and_recipe')
    key=habit_policy_key_v1(definition.namespace,definition.policy_id);old_atom=read.head(db,key);old=None
    if kind=='create_habit_policy_v1':
        if original.action!='issue'or definition.revision!=1 or old_atom.revision!=0:raise ValueError('Habit creation mirrors only actual first standing issue')
    else:
        if request.policy_ref!=key.token or old_atom.revision!=request.expected_revision:raise ValueError('Habit management changed its exact original policy head')
        old=graph_adopted_habit_policy_from_wire_v1(old_atom.value)
        if definition.revision!=old.definition.revision+1 or old.definition.state in {'stopped','superseded'}or definition.cancellation_generation<old.definition.cancellation_generation:raise ValueError('Habit revision cannot revive stopped policy or clear cancellation history')
        if kind=='pause_habit_policy_v1'and definition.state!='paused'or kind=='resume_habit_policy_v1'and(old.definition.state!='paused'or definition.state!='enabled')or kind=='stop_habit_policy_v1'and(definition.state!='stopped'or original.action!='revoke'):raise ValueError('Habit control differs from exact Core policy transition')
        if kind!='stop_habit_policy_v1'and original.action!='revise':raise ValueError('Habit management must mirror actual Core revise')
    managed_target=None
    if definition.executor_kind=='draft_file'and(kind=='create_habit_policy_v1'or old.definition.executor_kind!='draft_file'or old.definition.target_ref!=definition.target_ref):
        target=read_current_habit_execution_target_v1(db,read=read,definition=definition,issuer=installed.issuer,require_unused=True)
        managed_target={'selector_commitment':habit_draft_selector_commitment_v1(definition.namespace,decision_ref=target.decision_ref,decision_digest=target.decision_digest,phase_selector=target.phase_selector,future_identity=target.future_identity,issuer=installed.issuer),'decision_ref':target.decision_ref,'decision_digest':target.decision_digest,'phase_selector_digest':canonical_digest(target.phase_selector),'future_identity_digest':canonical_digest(target.future_identity)}
    mirror=GraphAdoptedHabitPolicyV1(definition,original.authority_namespace,original.installation_id,definition.revision,original.original_ref,original.digest,frame.envelope.identity.operation_id)
    causal=ProductionOriginalRefV1('d10.habit_standing_policy',original.original_ref,original.digest)
    from .habit_schedule_driver_v1 import policy_habit_subscription_jobs_v1
    subscription_jobs=policy_habit_subscription_jobs_v1(db,frame=frame,policy=mirror,before_policy=old)
    write=_new(frame,key,mirror)if old_atom.revision==0 else _write(frame,old_atom,mirror,policy=True)
    from .b3_managed_metadata_v1 import prepare_habit_managed_metadata_retirements_v1
    retirements=prepare_habit_managed_metadata_retirements_v1(db,namespace=definition.namespace,policy_ref=key.token,new_executor_kind=definition.executor_kind,new_target_ref=definition.target_ref,issuer=installed.issuer)
    return _emit(db,frame,kind,request,writes=(write,),provenance={'policy':mirror,'core_standing_original':original,'habit_draft_managed_target':managed_target,'managed_metadata_retirements_v1':retirements},causal=causal,roots=definition.source_refs,semantic={'policy':_semantic_definition(definition)},cancellation_generation=definition.cancellation_generation,original_deadline_utc=min(definition.original_valid_until_utc,frame.envelope.deadline_utc),events=(('d11','habit_schedule_changed_requires_subscription'),),subscription_jobs=subscription_jobs)

def stage_create_habit_policy_v1(db,*,frame,request,installed):return _mirror_policy(db,frame=frame,request=request,installed=installed,kind='create_habit_policy_v1')
def stage_revise_habit_policy_v1(db,*,frame,request,installed):return _mirror_policy(db,frame=frame,request=request,installed=installed,kind='revise_habit_policy_v1')
def stage_pause_habit_policy_v1(db,*,frame,request,installed):return _mirror_policy(db,frame=frame,request=request,installed=installed,kind='pause_habit_policy_v1')
def stage_resume_habit_policy_v1(db,*,frame,request,installed):return _mirror_policy(db,frame=frame,request=request,installed=installed,kind='resume_habit_policy_v1')
def stage_stop_habit_policy_v1(db,*,frame,request,installed):return _mirror_policy(db,frame=frame,request=request,installed=installed,kind='stop_habit_policy_v1')

def _cue(db,read,policy,request,issuer):
    definition=policy.definition;predicate=definition.cue_predicate
    if predicate.kind!='domain_state':raise MissingProductionOriginalV1('installed_habit_cue_predicate_provider')
    if predicate.observation_provider=='d11.habit-window-cue.v1':
        if dict(predicate.parameters)!={'policy_id':definition.policy_id}:raise ValueError('time cue changed its exact registered policy identity')
        from .habit_schedule_driver_v1 import read_actual_habit_cue_v1
        return read_actual_habit_cue_v1(db,frame=read.frame,policy=policy,original_ref=request.cue_original_ref,original_digest=request.cue_original_digest,issuer=issuer)
    if predicate.observation_provider!='d07.habit-cue.v1'or dict(predicate.parameters)!={'policy_id':definition.policy_id}:raise MissingProductionOriginalV1('installed_habit_semantic_cue_provider')
    atom,original,records=read.adopted_interpretation(db,request.cue_original_ref,question_scope=habit_cue_question_scope_v1(definition))
    if original.original_digest!=request.cue_original_digest or atom.value['proposition']!='cue_present':raise MissingProductionOriginalV1('actual_supported_habit_cue')
    from .habit_schedule_driver_v1 import SemanticHabitCueObservationV1
    sources=tuple(sorted(records))
    stable=canonical_digest(tuple((ref,records[ref].source_id,records[ref].recorded_at)for ref in sources))
    occurred=max(records[ref].recorded_at for ref in sources)
    if occurred>read.frame.now_utc or occurred<predicate.valid_from or predicate.valid_until is not None and occurred>predicate.valid_until:raise MissingProductionOriginalV1('actual_habit_cue_within_original_predicate_time')
    from .domain_background_read_v3 import background_history_v3
    history=background_history_v3(db,atom.key.token,atom.revision,columns=('event_id',))
    return SemanticHabitCueObservationV1(namespace=definition.namespace,policy_ref=habit_policy_key_v1(definition.namespace,definition.policy_id).token,policy_revision=definition.revision,cue_stable_key=stable,occurred_at_utc=occurred,predicate_digest=canonical_digest(predicate),source_refs=sources,producer_operation_id=history[0],cue_original_ref=original.original_ref,cue_original_digest=original.original_digest)

def _stop(db,read,definition):
    predicate=definition.stop_predicate
    if read.frame.now_utc<predicate.valid_from or predicate.valid_until is not None and read.frame.now_utc>=predicate.valid_until:raise MissingProductionOriginalV1('current_original_habit_stop_predicate_time')
    if predicate.kind=='domain_state'and predicate.observation_provider=='d10.habit-policy-stop.v1'and dict(predicate.parameters)=={'policy_id':definition.policy_id}:
        return definition.state!='enabled'
    if predicate.observation_provider!='d07.habit-stop.v1':raise MissingProductionOriginalV1('installed_habit_stop_predicate_provider')
    parameters=dict(predicate.parameters)
    if set(parameters)!={'policy_id','interpretation_ref'}or parameters['policy_id']!=definition.policy_id:raise ValueError('Habit stop predicate changed its exact policy scope')
    atom,_,_=read.adopted_interpretation(db,parameters['interpretation_ref'],question_scope='d10.habit-stop:'+canonical_digest((definition.namespace,definition.policy_id,definition.revision)))
    if atom.value['proposition']not in {'continue','stop'}:raise MissingProductionOriginalV1('actual_habit_stop_or_continue_observation')
    return atom.value['proposition']=='stop'

def current_habit_window_census_v1(db,*,read,policy_ref,window_id):
    from .current_habit_source_read_v3 import read_current_habit_occurrence_census_v3
    from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceCensusEntryV1
    entries=read_current_habit_occurrence_census_v3(db,frame=read.frame,policy_ref=policy_ref)
    if type(entries)is not tuple or any(type(e)is not HabitOccurrenceCensusEntryV1 or e.policy_ref!=policy_ref for e in entries):raise TypeError('Habit census requires the complete private Source metadata projection')
    if len({e.ref for e in entries})!=len(entries):raise ValueError('Habit census repeats a current occurrence head')
    counted=tuple(sorted(e.ref for e in entries if e.window_id==window_id))
    digest=canonical_digest(tuple(sorted((e.ref,e.revision,e.value_digest)for e in entries)))
    return entries,counted,digest

def stage_register_habit_occurrence_v1(db,*,frame,request,installed):
    kind='register_habit_occurrence_v1';read=_entry(db,frame,kind,request,installed)
    policy_atom,policy=_policy(db,read,request.policy_ref,request.expected_policy_revision);definition=policy.definition
    facts=_core_inputs(db,frame,kind,request)
    if facts.policy_original.original_ref!=policy.core_original_ref or facts.policy_original.digest!=policy.core_original_digest or facts.policy_original.definition!=definition:raise MissingProductionOriginalV1('actual_current_core_standing_policy_matches_graph_mirror')
    if _stop(db,read,definition):raise MissingProductionOriginalV1('habit_stop_predicate_or_owner_control')
    cue=_cue(db,read,policy,request,installed.issuer)
    if (cue.namespace,cue.policy_ref,cue.policy_revision,cue.predicate_digest)!=(definition.namespace,policy_atom.key.token,definition.revision,canonical_digest(definition.cue_predicate)):raise ValueError('actual cue belongs to another exact policy predicate')
    window_id,start,end=habit_window_v1(definition,cue.occurred_at_utc)
    identity=habit_occurrence_id_v1(definition.namespace,definition.policy_id,definition.revision,window_id,cue.cue_stable_key)
    key=habit_occurrence_key_v1(definition.namespace,identity)
    if frame.envelope.identity.operation_id!=habit_registration_operation_id_v1(definition.namespace,identity):raise ValueError('Habit cue registration requires its stable operation identity before any Action')
    prior=read.head(db,key)
    if prior.revision:
        original=habit_value_from_wire_v1(HABIT_OCCURRENCE_TYPE,prior.value)
        if (original.policy_ref,original.policy_revision,original.window_id,original.cue_stable_key)!=(policy_atom.key.token,definition.revision,window_id,cue.cue_stable_key):raise ValueError('duplicate Habit wake changed original occurrence identity')
        raise MissingProductionOriginalV1('observe_existing_habit_occurrence_without_new_registration')
    deadline=min(end,(start if definition.cue_predicate.observation_provider=='d11.habit-window-cue.v1'else cue.occurred_at_utc)+definition.execution_seconds,definition.original_valid_until_utc)
    roots=tuple(dict.fromkeys((*definition.source_refs,*cue.source_refs)))
    if frame.now_utc>=deadline or cue.execution_state!='due':
        return _miss(db,frame=frame,read=read,kind=kind,request=request,policy=policy,window_id=window_id,cue_ref=cue.cue_original_ref,deadline=deadline,roots=roots,reason_ref=cue.cue_original_ref)
    census,counted,census_digest=current_habit_window_census_v1(db,read=read,policy_ref=policy_atom.key.token,window_id=window_id)
    if len(counted)>=definition.maximum_occurrences_per_window:raise MissingProductionOriginalV1('habit_original_window_occurrence_limit')
    admitted=tuple(value.actual_started_at_utc if value.actual_started_at_utc is not None else value.admitted_at_utc for value in census if value.actual_started_at_utc is not None or value.admitted_at_utc is not None)
    if admitted and frame.now_utc-max(admitted)<definition.minimum_interval_seconds:raise MissingProductionOriginalV1('habit_original_minimum_interval')
    target=None
    if definition.executor_kind=='source_note':
        operation,activity,effect,attempt=habit_source_note_execution_identity_v1(definition.namespace,identity,definition.project_ref)
        source_note=definition.source_note_input
        for ref,revision,digest in((source_note.source_ref,source_note.source_revision,source_note.source_digest),(source_note.role_binding_ref,source_note.role_binding_revision,source_note.role_binding_digest)):
            selected=read.head(db,ref,required=True)
            if selected.revision!=revision or canonical_digest(selected.value)!=digest:raise MissingProductionOriginalV1('actual_pinned_habit_SourceNote_input')
    else:
        target=read_current_habit_execution_target_v1(db,read=read,definition=definition,issuer=installed.issuer,require_unused=True)
        future=target.future_identity
        operation,activity,effect,attempt=future.action_operation_id,future.activity_id,future.effect_id,future.attempt_id
        deadline=min(deadline,future.deadline_utc)
    value=HabitOccurrenceV1(definition.namespace,identity,policy_atom.key.token,definition.revision,policy.digest,window_id,start,end,cue.cue_original_ref,cue.cue_original_digest,cue.cue_stable_key,operation,activity,effect,attempt,definition.recipe_ref,definition.recipe_revision,definition.executor_kind,definition.parent_root_grant_ref,definition.parent_root_grant_digest,deadline,definition.cancellation_generation,'registered',None,None,None,None,roots)
    causal=ProductionOriginalRefV1('d10.actual_habit_cue',cue.cue_original_ref,cue.cue_original_digest)
    return _emit(db,frame,kind,request,writes=(_new(frame,key,value),),provenance={'occurrence':value,'actual_cue':cue,'selected_execution':target,'window_census_digest':census_digest,'counted_occurrence_refs':counted},causal=causal,roots=roots,semantic={'occurrence':{'policy':definition.policy_id,'window':window_id,'cue':cue.cue_stable_key,'state':'registered','recipe':definition.recipe_ref}},cancellation_generation=definition.cancellation_generation,original_deadline_utc=min(deadline,frame.envelope.deadline_utc),events=(('d11','habit_occurrence_registered_requires_qualification'),))


def _miss(db,*,frame,read,kind,request,policy,window_id,cue_ref,deadline,roots,reason_ref):
    from .domain_mesh_contract_v1 import MeshWaitV1
    definition=policy.definition
    if frame.now_utc<deadline:raise ValueError('miss bookkeeping cannot precede the original execution deadline')
    identity='habit-disposition:'+canonical_digest((definition.namespace,definition.policy_id,definition.revision,window_id,cue_ref,definition.miss_policy))[:48]
    value=HabitDispositionV1(definition.namespace,identity,habit_policy_key_v1(definition.namespace,definition.policy_id).token,definition.revision,window_id,cue_ref,definition.miss_policy,reason_ref,deadline,frame.now_utc,roots)
    key=AtomKey(Owner('persona',*definition.namespace.as_tuple,definition.namespace.persona_id),HABIT_DISPOSITION_TYPE,identity)
    prior=read.head(db,key)
    if prior.revision:raise MissingProductionOriginalV1('observe_existing_habit_disposition_without_new_occurrence')
    causal=read.original(cue_ref)
    wait=MeshWaitV1('original_deadline_expired','d10','habit_schedule_changed_requires_subscription',(value.policy_ref,cue_ref),frame.snapshot.versions,frame.query_coverage)
    return _emit(db,frame,kind,request,writes=(_new(frame,key,value),),provenance={'miss_disposition':value},causal=causal,roots=roots,semantic={'policy':definition.policy_id,'window':window_id,'cue':cue_ref,'disposition':definition.miss_policy},cancellation_generation=definition.cancellation_generation,original_deadline_utc=deadline,wait=wait)

def stage_qualify_habit_occurrence_v1(db,*,frame,request,installed):
    from ..authority_service.d10_habit_contract_v1 import HabitOccurrenceQualificationOriginalV1
    kind='qualify_habit_occurrence_v1';read=_entry(db,frame,kind,request,installed)
    atom,occurrence=_occurrence(db,read,request.occurrence_ref,request.expected_revision)
    _,policy=_policy(db,read,occurrence.policy_ref);definition=policy.definition
    if occurrence.state not in {'registered','waiting'}or occurrence.policy_revision!=definition.revision or occurrence.policy_digest!=policy.digest or occurrence.cancellation_generation!=definition.cancellation_generation or frame.now_utc>=occurrence.original_deadline_utc or _stop(db,read,definition):raise MissingProductionOriginalV1('current_habit_occurrence_original_scope_and_deadline')
    facts=_core_inputs(db,frame,kind,request);qualification=facts.occurrence_qualification
    if type(qualification)is not HabitOccurrenceQualificationOriginalV1 or qualification.namespace!=occurrence.namespace or qualification.occurrence_head!=GraphVersion(atom.key,atom.revision)or qualification.occurrence_digest!=canonical_digest(atom.value)or qualification.owner_head_digest.removeprefix('sha256:')!=frame.owner_guard.owner_head_digest:raise ValueError('Habit eligibility is not this actual independent current Core occurrence original')
    selector=qualification.selector
    if (selector.policy_ref,selector.policy_revision,selector.policy_digest,selector.window_id,selector.cue_original_ref,selector.cue_original_digest,selector.cue_stable_key,selector.execution_operation_id,selector.activity_id,selector.effect_id,selector.attempt_id,selector.recipe_ref,selector.recipe_revision,selector.executor_kind,selector.standing_authorization_original_ref,selector.standing_authorization_original_digest,selector.parent_root_grant_ref,selector.parent_root_grant_digest,selector.original_deadline_utc,selector.cancellation_generation)!=(occurrence.policy_ref,occurrence.policy_revision,occurrence.policy_digest,occurrence.window_id,occurrence.cue_original_ref,occurrence.cue_original_digest,occurrence.cue_stable_key,occurrence.occurrence_operation_id,occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id,occurrence.recipe_ref,occurrence.recipe_revision,occurrence.executor_kind,policy.core_original_ref,policy.core_original_digest,occurrence.parent_root_grant_ref,occurrence.parent_root_grant_digest,occurrence.original_deadline_utc,occurrence.cancellation_generation):raise ValueError('Core Habit selector changed the durable occurrence or original grant')
    from .domain_production_registry_v1 import installed_operation_v1
    from .habit_activity_issuance_v1 import habit_typed_command_digest_v1
    if selector.operation_id!=frame.envelope.identity.operation_id or selector.request_digest!=habit_typed_command_digest_v1(installed_operation_v1(kind),request):raise ValueError('Habit qualification changed its actual qualification W01 request')
    census,counted,digest=current_habit_window_census_v1(db,read=read,policy_ref=occurrence.policy_ref,window_id=occurrence.window_id)
    if qualification.window_census_digest!=digest or qualification.counted_occurrence_refs!=counted or len(counted)>definition.maximum_occurrences_per_window or atom.key.token not in counted:raise ValueError('Habit Core eligibility lost complete cross-revision occurrence census')
    prior_admissions=tuple(v.actual_started_at_utc if v.actual_started_at_utc is not None else v.admitted_at_utc for v in census if v.ref!=atom.key.token and(v.actual_started_at_utc is not None or v.admitted_at_utc is not None))
    if prior_admissions and qualification.issued_at_utc-max(prior_admissions)<definition.minimum_interval_seconds:raise MissingProductionOriginalV1('current_habit_minimum_interval_from_actual_admission')
    if not set(qualification.read_versions)<=set(frame.snapshot.versions)or qualification.original_deadline_utc!=occurrence.original_deadline_utc:raise ValueError('Habit current Source read/CAS or original deadline differs from Core qualification')
    updated=replace(occurrence,state='qualified',qualification_original_ref=qualification.original_ref,admitted_at_utc=qualification.issued_at_utc)
    causal=ProductionOriginalRefV1('d10.habit_occurrence_qualification',qualification.original_ref,qualification.digest)
    return _emit(db,frame,kind,request,writes=(_write(frame,atom,updated),),provenance={'occurrence':updated,'core_qualification':qualification},causal=causal,roots=updated.source_refs,semantic={'occurrence':updated.occurrence_id,'state':'qualified','window':updated.window_id,'recipe':updated.recipe_ref},cancellation_generation=updated.cancellation_generation,original_deadline_utc=updated.original_deadline_utc,events=(('d08','qualified_habit_occurrence_requires_recipe'),))

def stage_record_habit_miss_v1(db,*,frame,request,installed):
    kind='record_habit_miss_v1';read=_entry(db,frame,kind,request,installed)
    _,occurrence=_occurrence(db,read,request.occurrence_ref,request.expected_revision)
    _,policy=_policy(db,read,occurrence.policy_ref,enabled=False)
    if occurrence.state not in {'registered','waiting'}:raise MissingProductionOriginalV1('observe_original_active_or_unknown_habit_effect_without_clearing_it')
    if policy.definition.revision!=occurrence.policy_revision:raise MissingProductionOriginalV1('actual_original_habit_policy_revision_for_miss')
    return _miss(db,frame=frame,read=read,kind=kind,request=request,policy=policy,window_id=occurrence.window_id,cue_ref=occurrence.cue_original_ref,deadline=occurrence.original_deadline_utc,roots=occurrence.source_refs,reason_ref=request.reason_ref)

def _current_habit_outcome_inputs_v1(db,*,frame,request,installed):
    from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
    from .d10_life_progress_provenance_v1 import require_current_life_progress_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    kind='adopt_habit_outcome_v1';read=_entry(db,frame,kind,request,installed)
    atom,occurrence=_occurrence(db,read,request.occurrence_ref,request.expected_revision)
    _,policy=_policy(db,read,occurrence.policy_ref,enabled=False)
    if occurrence.state not in {'qualified','active','unknown'}or not occurrence.qualification_original_ref:raise MissingProductionOriginalV1('actual_previously_qualified_habit_effect')
    progress_atom=read.head(db,request.life_progress_ref,required=True)
    if progress_atom.revision!=request.life_progress_revision or progress_atom.key.type_name!='d10.life_progress.v1':raise ValueError('Habit outcome current progress revision differs')
    progress=decode_typed_production_value_v1(progress_atom.value,LifeProgressHeadV1)
    prepared,terminal,production=require_current_life_progress_v1(db,namespace=occurrence.namespace,progress=progress,issuer=installed.issuer,read=read)
    b=terminal.binding
    if progress.reality!='real_execution'or progress.actuality!='completed'or (progress.activity_id,progress.effect_id,progress.recipe_ref)!=(occurrence.activity_id,occurrence.effect_id,occurrence.recipe_ref)or (b.activity_id,b.effect_id,b.attempt_id,b.parent_budget_lease_ref)!=(occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id,occurrence.parent_root_grant_ref)or terminal.original_ref!=request.actual_terminal_original_ref or terminal.status!='completed':raise ValueError('Habit result must be its actual original Life execution and verified terminal')
    if prepared.plan.recipe.revision!=occurrence.recipe_revision:raise ValueError('Habit result changed original recipe revision')
    if production['payload']['request']['activity_outcome_ref']!=request.life_outcome_original_ref:raise ValueError('Habit outcome names another actual registered Life outcome')
    from .d11_life_preparation_v1 import _read
    from .d11_life_contract_v1 import RegisteredLifeOutcomeV2,life_from_wire_v1
    from .d10_life_outcome_v2 import _actual_outcome
    raw_outcome=_read(db,issuer=installed.issuer,namespace=occurrence.namespace,kind='outcome',ref=request.life_outcome_original_ref)
    if raw_outcome is None:raise MissingProductionOriginalV1('actual_registered_habit_life_outcome')
    actual_outcome=life_from_wire_v1(raw_outcome[0],RegisteredLifeOutcomeV2)
    _,_,checked_terminal,_,accounting=_actual_outcome(db,read,installed.issuer,actual_outcome)
    if checked_terminal!=terminal or tuple(ref.original_ref for ref in accounting)!=request.accounting_original_refs:raise ValueError('Habit result changed actual component accounting originals')
    outcome_original=ProductionOriginalRefV1('d10.current-advance_life','d10-current:'+production['original_digest'][:48],production['original_digest'])
    from .d10_life_outcome_v2 import life_experience_source_id_v1
    from ..memory_types import source_key
    experience=source_key(*occurrence.namespace.as_tuple,life_experience_source_id_v1(b)).token
    if request.encoding_trigger_ref!=experience or request.growth_trigger_ref!=outcome_original.original_ref:raise ValueError('Habit result references only actual existing Life encoding/growth triggers')
    read.head(db,experience,required=True)
    return read,atom,occurrence,policy,progress_atom,progress,terminal,accounting,outcome_original,experience

def stage_adopt_habit_outcome_v1(db,*,frame,request,installed):
    kind='adopt_habit_outcome_v1'
    read,atom,occurrence,policy,progress_atom,progress,terminal,accounting,outcome_original,experience=_current_habit_outcome_inputs_v1(db,frame=frame,request=request,installed=installed)
    roots=tuple(dict.fromkeys((*occurrence.source_refs,*progress.source_refs,experience)))
    for purpose in('context','consolidation'):read.source_family(db,roots,purpose=purpose)
    identity='habit-outcome:'+canonical_digest((occurrence.occurrence_id,terminal.original_ref,outcome_original.original_digest))[:48]
    result=HabitOutcomeV1(occurrence.namespace,identity,atom.key.token,atom.revision,progress_atom.key.token,progress_atom.revision,request.life_outcome_original_ref,terminal.original_ref,request.accounting_original_refs,experience,outcome_original.original_ref,roots)
    key=AtomKey(Owner('persona',*occurrence.namespace.as_tuple,occurrence.namespace.persona_id),HABIT_OUTCOME_TYPE,identity)
    updated=replace(occurrence,state='completed_verified',life_plan_original_ref=terminal.binding.plan_original_ref,outcome_original_ref=key.token,source_refs=roots)
    return _emit(db,frame,kind,request,writes=(_new(frame,key,result),_write(frame,atom,updated)),provenance={'habit_outcome':result,'actual_life_progress':progress,'actual_terminal':terminal,'actual_accounting':accounting},causal=outcome_original,roots=roots,semantic={'occurrence':occurrence.occurrence_id,'state':'completed_verified','result':terminal.payload.artifact_digest},cancellation_generation=occurrence.cancellation_generation,original_deadline_utc=occurrence.original_deadline_utc)


def read_plan_current_habit_operation_v1(db,*,namespace,activity_id,operation_kind,request):
    from .current_habit_source_read_v3 import current_habit_source_read_plan_v3
    if operation_kind not in OPERATIONS or type(request)is not _REQUESTS[operation_kind]:raise ValueError('unknown Habit operation/request')
    return current_habit_source_read_plan_v3(db,namespace=namespace,activity_id=activity_id,operation_kind=operation_kind,request=request)

def recover_habit_occurrence_v1(db,*,work,frame,producer_original,producer_operation_id,issuer):
    from .semantic_recovery_source_v3 import require_current_semantic_recovery_work_v3,read_committed_semantic_producer_v3
    namespace=frame.envelope.authority.namespace
    require_current_semantic_recovery_work_v3(work,db=db,namespace=namespace,producer_operation_id=producer_operation_id)
    actual=read_committed_semantic_producer_v3(work,db=db,namespace=namespace,producer_operation_id=producer_operation_id,issuer=issuer)
    operation=producer_operation_id
    domain=actual['domain'];kind=actual['operation_kind']
    if (domain=='d10'and kind not in OPERATIONS)or(domain=='d08'and kind not in {'instantiate_current_habit_source_note_context_v1','prepare_current_habit_source_note_action_v1'})or(domain=='d11'and kind!='record_habit_window_cue_v1')or domain not in {'d08','d10','d11'}or producer_original.original_digest!=actual['original_digest']or producer_original.original_ref!=domain+'-current:'+actual['original_digest'][:48]:raise ValueError('Habit recovery observes only the exact committed producer')
    read=CurrentDomainReadV1(frame);read.check(db);read.committed_operation(db,operation)
    versions=tuple(v for v in actual['receipt'].write_versions if v.key.type_name==HABIT_OCCURRENCE_TYPE)
    if len(versions)>1:raise ValueError('Habit operation cannot recover multiple occurrence identities')
    if versions:
        atom,value=_occurrence(db,read,versions[0].key)
        return HabitRecoveryObservationV1(value.namespace,producer_original,operation,canonical_digest(actual['receipt']),atom.key.token,atom.revision,value.state,value.activity_id,value.effect_id,value.attempt_id,value.outcome_original_ref,None,'complete',())
    disposition_versions=tuple(v for v in actual['receipt'].write_versions if v.key.type_name==HABIT_DISPOSITION_TYPE)
    if disposition_versions:
        if len(disposition_versions)!=1:raise ValueError('Habit miss has multiple original dispositions')
        atom=read.head(db,disposition_versions[0].key,required=True);value=habit_value_from_wire_v1(HABIT_DISPOSITION_TYPE,atom.value)
        return HabitRecoveryObservationV1(value.namespace,producer_original,operation,canonical_digest(actual['receipt']),None,None,value.disposition,None,None,None,None,atom.key.token,'complete',())
    if domain=='d11':
        from .joint_habit_provenance_v1 import habit_window_cue_from_domain_plain_v1
        core=habit_window_cue_from_domain_plain_v1(actual['payload']['provenance']['core_cue_original'])
        return HabitRecoveryObservationV1(core.selector.namespace,producer_original,operation,canonical_digest(actual['receipt']),None,None,core.execution_state,None,None,None,None,None,'complete',())
    policy_versions=tuple(v for v in actual['receipt'].write_versions if v.key.type_name==HABIT_POLICY_TYPE)
    if len(policy_versions)!=1:raise ValueError('Habit management recovery lacks its one actual policy mirror')
    _,policy=_policy(db,read,policy_versions[0].key,enabled=False)
    return HabitRecoveryObservationV1(policy.definition.namespace,producer_original,operation,canonical_digest(actual['receipt']),None,None,policy.definition.state,None,None,None,None,None,'complete',())

def observe_current_joint_habit_recovery_v1(db,*,work,frame,selector,producer_original,issuer):
    from .semantic_recovery_source_v3 import require_current_semantic_recovery_work_v3,read_committed_semantic_producer_v3
    if type(selector)is not ObserveCurrentJointHabitRecoveryRequestV1:raise TypeError('cold observer requires its exact existing producer locator')
    operation=selector.producer_operation_id;namespace=frame.envelope.authority.namespace
    require_current_semantic_recovery_work_v3(work,db=db,namespace=namespace,producer_operation_id=operation)
    actual=read_committed_semantic_producer_v3(work,db=db,namespace=namespace,producer_operation_id=operation,issuer=issuer)
    if producer_original.original_digest!=actual['original_digest']:raise ValueError('cold recovery changed the exact committed semantic producer')
    from .d08_long_term_plan_v1 import OPERATIONS as LONG_TERM_OPERATIONS
    if actual['domain']=='d08'and actual['operation_kind']in LONG_TERM_OPERATIONS:
        from .d08_long_term_plan_v1 import recover_long_term_window_v1
        value=recover_long_term_window_v1(db,work=work,frame=frame,producer_original=producer_original,producer_operation_id=operation,issuer=issuer)
    else:value=recover_habit_occurrence_v1(db,work=work,frame=frame,producer_original=producer_original,producer_operation_id=operation,issuer=issuer)
    return JointHabitRecoveryReadV1(actual['domain'],value,value.coverage,value.missing_inputs)


def joint_habit_recovery_request_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={'producer_operation_id'}:raise ValueError('recovery is an exact read-only producer locator')
    return ObserveCurrentJointHabitRecoveryRequestV1(**raw)


def stage_current_habit_operation_v1(db,*,frame,request,installed_readers,operation_kind):
    if operation_kind not in OPERATIONS or type(request)is not _REQUESTS[operation_kind]:raise ValueError('unknown B3 Habit request')
    return globals()['stage_'+operation_kind](db,frame=frame,request=request,installed=installed_readers)


def require_joint_habit_head_original_v1(db,*,read,atom,allowed_producers=None):
    from .domain_background_read_v3 import background_history_v3
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    history=background_history_v3(db,atom.key.token,atom.revision,columns=('event_id',))
    if history is None:raise MissingProductionOriginalV1('actual_joint_habit_current_head_history')
    actual=read_adopted_domain_operation_v1(db,read.frame.envelope.authority.namespace,history[0])
    if actual is None or allowed_producers is not None and(actual['domain'],actual['operation_kind'])not in allowed_producers or actual['receipt'].status!='committed'or GraphVersion(atom.key,atom.revision)not in actual['receipt'].write_versions:raise MissingProductionOriginalV1('actual_joint_habit_current_head_producer_COMMIT')
    read.committed_operation(db,history[0])
    matching=tuple(decode_typed_production_value_v1(w,GraphWrite)for w in actual['payload']['writes']if w['key']==plain_v1(atom.key))
    if len(matching)!=1 or matching[0].value!=atom.value:raise ValueError('maintenance current head differs from its actual original write commitment')
    ref=actual['domain']+'-current:'+actual['original_digest'][:48]
    read.original(ref,kind=actual['domain']+'.current-'+actual['operation_kind'],digest=actual['original_digest'])
    return ProductionOriginalRefV1(actual['domain']+'.current-'+actual['operation_kind'],ref,actual['original_digest'])


def joint_habit_original_maintenance_v1(db,*,frame,operation_kind,request,installed_readers):
    """Current Source-qualified original maintenance; this predicate issues no permission."""
    from .current_habit_source_read_v3 import require_current_habit_source_frame_v3
    require_current_habit_source_frame_v3(db,frame=frame,operation_kind=operation_kind,request=request)
    if operation_kind in {'pause_long_term_plan_v1','stop_long_term_plan_v1'}:
        from .d08_long_term_plan_v1 import current_long_term_original_maintenance_v1
        return current_long_term_original_maintenance_v1(db,frame=frame,operation_kind=operation_kind,request=request,installed=installed_readers)
    if operation_kind in {'pause_habit_policy_v1','stop_habit_policy_v1'}:
        if type(request)is not _REQUESTS[operation_kind]or request.expected_revision<1:return False
        read=_entry(db,frame,operation_kind,request,installed_readers)
        atom,policy=_policy(db,read,request.policy_ref,request.expected_revision,enabled=False);before=policy.definition;after=request.definition
        if before.state in {'stopped','superseded'}or after.revision!=before.revision+1 or after.state!=('paused'if operation_kind=='pause_habit_policy_v1'else 'stopped')or after.cancellation_generation!=before.cancellation_generation+1:return False
        mutable={'revision','state','cancellation_generation'}
        if any(getattr(before,name)!=getattr(after,name)for name in before.__dataclass_fields__ if name not in mutable):return False
        require_joint_habit_head_original_v1(db,read=read,atom=atom,allowed_producers={('d10',kind)for kind in POLICY_OPERATIONS})
        return True
    if operation_kind=='record_habit_miss_v1':
        if type(request)is not RecordHabitMissRequestV1 or request.expected_revision<1:return False
        read=_entry(db,frame,operation_kind,request,installed_readers);atom,occurrence=_occurrence(db,read,request.occurrence_ref,request.expected_revision)
        if occurrence.state not in {'registered','waiting'}or frame.now_utc<occurrence.original_deadline_utc or occurrence.action_intent_ref is not None or occurrence.life_plan_original_ref is not None:return False
        require_joint_habit_head_original_v1(db,read=read,atom=atom,allowed_producers={('d10','register_habit_occurrence_v1')})
        _,policy=_policy(db,read,occurrence.policy_ref,enabled=False)
        if policy.definition.revision!=occurrence.policy_revision:return False
        actual=_cue(db,read,policy,RegisterHabitOccurrenceRequestV1(occurrence.policy_ref,occurrence.policy_revision,occurrence.cue_original_ref,occurrence.cue_original_digest),installed_readers.issuer)
        return actual.cue_stable_key==occurrence.cue_stable_key and actual.cue_original_ref==request.reason_ref
    if operation_kind=='adopt_habit_outcome_v1':
        if type(request)is not AdoptHabitOutcomeRequestV1:return False
        _current_habit_outcome_inputs_v1(db,frame=frame,request=request,installed=installed_readers)
        return True
    return False


@dataclass(frozen=True,slots=True)
class HabitSourceNoteContextV1:
    namespace:NamespaceId
    occurrence_ref:str
    occurrence_before_revision:int
    policy_ref:str
    policy_revision:int
    standing_original_ref:str
    standing_original_digest:str
    qualification_original_ref:str
    qualification_original_digest:str
    project_head:GraphVersion
    checkpoint_before_head:GraphVersion
    parent_plan_head:GraphVersion
    parent_goal_head:GraphVersion
    input_source_head:GraphVersion
    input_source_digest:str
    role_binding_head:GraphVersion
    role_binding_digest:str
    target_entity_head:GraphVersion
    postcondition_build_digest:str
    goal_head:GraphVersion
    plan_head:GraphVersion
    node_id:str
    execution_operation_id:str
    effect_id:str
    parent_root_grant_ref:str
    parent_root_grant_digest:str
    original_deadline_utc:float
    schema:str='d10.habit-source-note-context.v1'
    def __post_init__(self):
        if self.schema!='d10.habit-source-note-context.v1'or self.occurrence_before_revision<1 or self.policy_revision<1 or any(type(v)is not GraphVersion for v in(self.project_head,self.checkpoint_before_head,self.parent_plan_head,self.parent_goal_head,self.input_source_head,self.role_binding_head,self.target_entity_head,self.goal_head,self.plan_head)):raise ValueError('Habit context binds actual prior heads and its own two new heads')
        if self.goal_head.revision!=1 or self.plan_head.revision!=1 or self.goal_head.key.type_name!='d08.goal.v1'or self.plan_head.key.type_name!='d08.personal_plan.v1':raise ValueError('Habit occurrence context never rewrites an old Goal/Plan')

def habit_source_note_context_from_wire_v1(raw):
    from dataclasses import fields
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitSourceNoteContextV1)}:raise ValueError('Habit context closed fields differ')
    value={**raw,'namespace':NamespaceId(**raw['namespace'])}
    for name in('project_head','checkpoint_before_head','parent_plan_head','parent_goal_head','input_source_head','role_binding_head','target_entity_head','goal_head','plan_head'):
        item=raw[name]
        if type(item)is not dict or set(item)!={'key','revision'}:raise ValueError('Habit context head fields differ')
        value[name]=GraphVersion(AtomKey.from_token(item['key']),item['revision'])
    return HabitSourceNoteContextV1(**value)

def habit_source_note_context_keys_v1(namespace,occurrence_id,activity_id):
    from ..graph_types import Owner
    marker=canonical_digest(('d10.habit-source-note.v1',namespace,occurrence_id))[:48];owner=Owner('activity',*namespace.as_tuple,activity_id)
    return {'goal':AtomKey(owner,'d08.goal.v1','goal:habit-source-note:'+marker),'plan':AtomKey(owner,'d08.personal_plan.v1','plan:habit-source-note:'+marker)}

def _qualified_habit_execution_v1(db,*,frame,request,installed,kind):
    from ..authority_service.current_habit_occurrence_v1 import HabitOccurrenceCurrentV1
    from ..authority_service.d10_habit_contract_v1 import HabitOccurrenceQualificationOriginalV1
    if type(installed)is not InstalledHabitSourceNoteReadersV1:raise TypeError('Habit SourceNote execution requires its actual paired domain readers')
    read=_entry(db,frame,kind,request,installed.life_readers);atom,occurrence=_occurrence(db,read,request.occurrence_ref,request.expected_revision)
    policy_atom,policy=_policy(db,read,occurrence.policy_ref);definition=policy.definition
    if occurrence.executor_kind!='source_note'or occurrence.state!='qualified'or occurrence.policy_revision!=definition.revision or occurrence.policy_digest!=policy.digest or occurrence.cancellation_generation!=definition.cancellation_generation or frame.now_utc>=occurrence.original_deadline_utc or _stop(db,read,definition):raise MissingProductionOriginalV1('current_qualified_Habit_SourceNote_original_window_and_policy')
    facts=_core_inputs(db,frame,kind,request);current=facts.execution_current;qualification=facts.occurrence_qualification
    if type(current)is not HabitOccurrenceCurrentV1 or type(qualification)is not HabitOccurrenceQualificationOriginalV1 or current.qualification_original!=qualification or current.policy_original!=facts.policy_original or current.owner_guard!=frame.owner_guard or qualification.original_ref!=occurrence.qualification_original_ref or (qualification.standing_original_ref,qualification.standing_original_digest)!=(policy.core_original_ref,policy.core_original_digest):raise ValueError('Habit execution lost its sameScope current independent Core standing and original occurrence qualification')
    read.original(qualification.original_ref,digest=qualification.digest)
    return read,atom,occurrence,policy_atom,policy,qualification,current

def _habit_source_note_input_v1(db,*,read,definition):
    pinned=definition.source_note_input
    for ref,revision,digest in((pinned.source_ref,pinned.source_revision,pinned.source_digest),(pinned.role_binding_ref,pinned.role_binding_revision,pinned.role_binding_digest)):
        atom=read.head(db,ref,required=True)
        if atom.revision!=revision or canonical_digest(atom.value)!=digest:raise MissingProductionOriginalV1('actual_pinned_habit_source_note_Source_and_role')
    phase=read.frame.envelope.identity.phase
    if phase not in {'instantiate_current_habit_source_note_context_v1','prepare_current_habit_source_note_action_v1'}:raise ValueError('Habit pinned input is consumed only by its fixed context/Action recipes')
    purposes=('context',)if phase=='instantiate_current_habit_source_note_context_v1'else('context','consolidation')
    for audience in definition.audience:
        for purpose in purposes:read.source_family(db,(pinned.source_ref,),purpose=purpose,audience=audience)
    return pinned

def _habit_multidomain_emit_v1(db,*,frame,kind,request,writes,provenance,causal,definition,occurrence,semantic,events):
    from ..runtime_contracts import DomainProposal
    from ..domains.d08.execution import GoalExecutionProvider
    from .domain_mesh_tick_v1 import MeshTickInputsV1,stage_joint_habit_mesh_companion_v1,combine_semantic_mesh_stage_v1
    companion=stage_joint_habit_mesh_companion_v1(db,frame=frame,operation_kind=kind,request=request,actual_inputs=MeshTickInputsV1(causal_original=causal,source_roots=occurrence.source_refs,predecessors=(causal,),semantic_originals=(causal,),semantic_versions=frame.snapshot.versions,cancellation_generation=occurrence.cancellation_generation,semantic_digest=canonical_digest(semantic),original_deadline_utc=occurrence.original_deadline_utc))
    from ..authority_service.current_habit_occurrence_v1 import habit_current_to_wire_v1
    provenance={**provenance,'habit_execution_current':habit_current_to_wire_v1(provenance['habit_execution_current'])}
    provider=GoalExecutionProvider();base=stage_result_v1(frame,'d08',kind,request,writes=writes,provenance={**provenance,'semantic_mesh':companion.trace},receiver_events=events,proposal_schema='d08.proposal.v1',proposal_hash=provider.descriptor.request_schema_hash)
    source=base.proposals[0];proposals=[]
    for domain in('d08','d10'):
        selected=tuple(w for w in writes if w.key.type_name.startswith(domain+'.'))
        if not selected:continue
        proposal=replace(source,domain=domain,proposal_schema=domain+'.proposal.v1',proposal_schema_hash=provider.descriptor.request_schema_hash if domain=='d08'else schema_hash({'domain':'d10','proposal':1}),typed_writes=selected)
        if domain=='d08':provider.validate(proposal,frame.snapshot)
        else:
            from ..domains.d10 import LifeDomain
            LifeDomain().validate(proposal,frame.snapshot)
        proposals.append(proposal)
    return combine_semantic_mesh_stage_v1(replace(base,proposals=tuple(proposals)),companion)

def stage_instantiate_current_habit_source_note_context_v1(db,*,frame,request,installed):
    from ..domains.d08.execution import Goal,GoalPredicate
    from ..domains.d08.personal_plan_v1 import PersonalPlanV1,PlanNodeV2,decode_personal_plan_type_v1
    from ..domains.d10.project_checkpoint_v1 import ProjectCheckpointV1,project_checkpoint_key_v1,decode_project_checkpoint_type_v1,CHECKPOINT_TYPE
    from ..runtime_contracts import VersionedRef
    from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
    from .d11_life_contract_v1 import life_artifact_ref_v1
    from .current_habit_source_read_v3 import read_current_habit_project_occurrence_census_v3,require_current_habit_project_context_transition_v3
    kind='instantiate_current_habit_source_note_context_v1';read,atom,occurrence,policy_atom,policy,qualification,current=_qualified_habit_execution_v1(db,frame=frame,request=request,installed=installed,kind=kind);d=policy.definition
    if frame.envelope.identity.operation_id!=habit_source_note_context_operation_id_v1(d.namespace,occurrence.occurrence_id)or occurrence.goal_ref is not None or occurrence.plan_ref is not None or occurrence.action_intent_ref is not None:raise MissingProductionOriginalV1('observe_actual_original_Habit_context_without_second_birth')
    census=read_current_habit_project_occurrence_census_v3(db,frame=frame,project_ref=d.project_ref)
    if any(e.ref!=atom.key.token and e.state in {'active','unknown','qualified'}for e in census):raise MissingProductionOriginalV1('other_actual_project_Habit_responsibility_must_remain_observed')
    project=read.head(db,d.project_ref,required=True);recipe=read.head(db,d.recipe_ref,required=True);pinned=_habit_source_note_input_v1(db,read=read,definition=d)
    checkpoint_atom=read.head(db,project_checkpoint_key_v1(d.namespace,d.project_ref),required=True);before=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,checkpoint_atom.value)
    parent_plan=read.head(db,before.plan_ref,required=True);parent=decode_personal_plan_type_v1(parent_plan.key.type_name,parent_plan.value);parent_goal=read.head(db,parent.goal_ref,required=True)
    if before.plan_revision!=parent_plan.revision or parent.goal_revision!=parent_goal.revision or before.state in {'paused','cancelled'}or parent.state in {'paused','abandoned','superseded'}or any(n.pending_original_effects for n in parent.nodes)or recipe.revision!=d.recipe_revision or project.value['reality']!='real_execution'or project.value['next_step']!='source_note':raise MissingProductionOriginalV1('actual_current_project_plan_goal_without_unknown_or_paused_responsibility')
    for prior in(project,recipe,checkpoint_atom,parent_plan,parent_goal):require_joint_habit_head_original_v1(db,read=read,atom=prior)
    require_current_habit_project_context_transition_v3(db,frame=frame,project_ref=d.project_ref,checkpoint=before,plan=parent)
    keys=habit_source_note_context_keys_v1(d.namespace,occurrence.occurrence_id,occurrence.activity_id)
    if any(read.head(db,key).revision for key in keys.values()):raise MissingProductionOriginalV1('actual_new_occurrence_Goal_and_Plan_absence')
    source=read.head(db,pinned.source_ref,required=True);role=read.head(db,pinned.role_binding_ref,required=True);entity=read.head(db,d.target_ref,required=True)
    build=read_installed_d11_life_build_v1(installed.legacy_readers.package_root,installed.legacy_readers.manifest_digest)
    from .d11_life_contract_v1 import POSTCONDITION_ID
    artifact=life_artifact_ref_v1(d.namespace,occurrence.effect_id);predicate=GoalPredicate('artifact_verified',POSTCONDITION_ID,(('artifact_ref',artifact),('input_digest',canonical_digest(source.value)),('build_digest',build['postcondition_build_digest'])),frame.now_utc,occurrence.original_deadline_utc)
    goal=Goal(keys['goal'].name,1,'active',(predicate),(parent_goal.key.token,policy.core_original_ref,qualification.original_ref),(atom.key.token,policy_atom.key.token),None,(policy_atom.key.token,),())
    node_id='task:habit-source-note:'+canonical_digest((d.namespace,occurrence.occurrence_id))[:48]
    node=PlanNodeV2(node_id,'persona:'+d.namespace.persona_id,(),'source_note',predicate,True,None,qualification.original_ref,(predicate,))
    facts=tuple(VersionedRef(a.key.token,a.revision)for a in(project,recipe,source,role,entity))
    plan=PersonalPlanV1(keys['plan'].name,1,keys['goal'].token,1,'active','persona:'+d.namespace.persona_id,(node,),(),parent.pause_conditions,parent.waiting_conditions,parent.cancel_conditions,d.source_refs,facts,None)
    checkpoint=replace(before,revision=before.revision+1,plan_ref=keys['plan'].token,plan_revision=1,next_step=node_id,state='active',wait_condition=None,last_fact_versions=facts)
    updated=replace(occurrence,goal_ref=keys['goal'].token,plan_ref=keys['plan'].token)
    context=HabitSourceNoteContextV1(d.namespace,atom.key.token,atom.revision,policy_atom.key.token,d.revision,policy.core_original_ref,policy.core_original_digest,qualification.original_ref,qualification.digest,GraphVersion(project.key,project.revision),GraphVersion(checkpoint_atom.key,checkpoint_atom.revision),GraphVersion(parent_plan.key,parent_plan.revision),GraphVersion(parent_goal.key,parent_goal.revision),GraphVersion(source.key,source.revision),canonical_digest(source.value),GraphVersion(role.key,role.revision),canonical_digest(role.value),GraphVersion(entity.key,entity.revision),build['postcondition_build_digest'],GraphVersion(keys['goal'],1),GraphVersion(keys['plan'],1),node_id,occurrence.occurrence_operation_id,occurrence.effect_id,occurrence.parent_root_grant_ref,occurrence.parent_root_grant_digest,occurrence.original_deadline_utc)
    writes=(GraphWrite(keys['goal'],plain_v1(goal)),GraphWrite(keys['plan'],plain_v1(plan)),GraphWrite(checkpoint_atom.key,plain_v1(checkpoint)),_write(frame,atom,updated))
    return _habit_multidomain_emit_v1(db,frame=frame,kind=kind,request=request,writes=writes,provenance={'habit_source_note_context':context,'before_checkpoint':before,'core_qualification':qualification,'habit_execution_current':current,'occurrence':updated},causal=ProductionOriginalRefV1('d10.habit_occurrence_qualification',qualification.original_ref,qualification.digest),definition=d,occurrence=updated,semantic={'occurrence':occurrence.occurrence_id,'phase':'context_ready','source':pinned.source_digest,'recipe':d.recipe_ref},events=(('d08','habit_source_note_context_ready_requires_action'),))


def read_current_habit_source_note_context_v1(db,*,read,occurrence,policy):
    operation=habit_source_note_context_operation_id_v1(occurrence.namespace,occurrence.occurrence_id)
    actual=read_adopted_domain_operation_v1(db,occurrence.namespace,operation)
    if actual is None or(actual['domain'],actual['operation_kind'])!=('d08','instantiate_current_habit_source_note_context_v1')or actual['receipt'].status!='committed':raise MissingProductionOriginalV1('actual_Habit_occurrence_context_COMMIT_before_Action')
    read.committed_operation(db,operation)
    context=habit_source_note_context_from_wire_v1(actual['payload']['provenance']['habit_source_note_context'])
    if(context.namespace,context.occurrence_ref,context.policy_ref,context.policy_revision,context.standing_original_ref,context.standing_original_digest,context.qualification_original_ref,context.execution_operation_id,context.effect_id,context.parent_root_grant_ref,context.parent_root_grant_digest,context.original_deadline_utc)!=(occurrence.namespace,habit_occurrence_key_v1(occurrence.namespace,occurrence.occurrence_id).token,occurrence.policy_ref,occurrence.policy_revision,policy.core_original_ref,policy.core_original_digest,occurrence.qualification_original_ref,occurrence.occurrence_operation_id,occurrence.effect_id,occurrence.parent_root_grant_ref,occurrence.parent_root_grant_digest,occurrence.original_deadline_utc):raise ValueError('Habit context is not this actual original occurrence and standing policy')
    if (occurrence.goal_ref,occurrence.plan_ref)!=(context.goal_head.key.token,context.plan_head.key.token):raise ValueError('Habit occurrence changed its actual context heads')
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1,decode_project_checkpoint_type_v1,CHECKPOINT_TYPE
    for version in(context.goal_head,context.plan_head,context.input_source_head,context.role_binding_head,context.target_entity_head):
        if read.head(db,version.key,required=True).revision!=version.revision:raise MissingProductionOriginalV1('current_exact_Habit_SourceNote_context_head')
    checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,read.head(db,project_checkpoint_key_v1(occurrence.namespace,policy.definition.project_ref),required=True).value)
    if(checkpoint.plan_ref,checkpoint.plan_revision,checkpoint.next_step,checkpoint.state)!=(context.plan_head.key.token,context.plan_head.revision,context.node_id,'active'):raise MissingProductionOriginalV1('actual_project_current_Habit_occurrence_context_pointer')
    ref=ProductionOriginalRefV1('d08.current-instantiate_current_habit_source_note_context_v1','d08-current:'+actual['original_digest'][:48],actual['original_digest'])
    read.original(ref.original_ref,kind=ref.kind,digest=ref.original_digest)
    return context,ref


def stage_prepare_current_habit_source_note_action_v1(db,*,frame,request,installed):
    from .d08_source_note_action_v1 import PrepareSourceNoteActionRequestV1,_build_source_note_action_in_transaction_v1,SourceNoteActionStageV1
    kind='prepare_current_habit_source_note_action_v1';read,atom,occurrence,policy_atom,policy,qualification,current=_qualified_habit_execution_v1(db,frame=frame,request=request,installed=installed,kind=kind);d=policy.definition
    if frame.envelope.identity.operation_id!=occurrence.occurrence_operation_id or occurrence.action_intent_ref is not None:raise MissingProductionOriginalV1('actual_once_Habit_SourceNote_Action_operation')
    if(frame.envelope.identity.activity_id,frame.envelope.identity.effect_id,frame.envelope.identity.attempt_id)!=(occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id)or frame.envelope.parent_budget_lease_ref!=occurrence.parent_root_grant_ref or frame.envelope.deadline_utc>occurrence.original_deadline_utc:raise ValueError('Habit Action changed original execution identity, Root or deadline')
    context,context_original=read_current_habit_source_note_context_v1(db,read=read,occurrence=occurrence,policy=policy);pinned=_habit_source_note_input_v1(db,read=read,definition=d)
    derived=PrepareSourceNoteActionRequestV1(d.project_ref,d.recipe_ref,pinned.source_ref,context.goal_head.key.token,d.target_ref,pinned.role_binding_ref)
    legacy=_build_source_note_action_in_transaction_v1(db,frame=frame,request=derived,installed_readers=installed.legacy_readers)
    import json
    legacy_proof=json.loads(legacy.stage.original_payload_json)['provenance']
    action_writes=legacy.stage.proposals[0].typed_writes;action=next(w for w in action_writes if w.key.type_name=='d08.action_intent.v1')
    updated=replace(occurrence,action_intent_ref=action.key.token,context_original_ref=context_original.original_ref,context_original_digest=context_original.original_digest)
    writes=(*action_writes,_write(frame,atom,updated))
    stage=_habit_multidomain_emit_v1(db,frame=frame,kind=kind,request=request,writes=writes,provenance={**legacy_proof,'derived_request':derived,'occurrence':updated,'core_standing_original':current.policy_original,'core_qualification':qualification,'habit_execution_current':current,'habit_context':context_original},causal=context_original,definition=d,occurrence=updated,semantic={'occurrence':occurrence.occurrence_id,'phase':'action_registered','source':pinned.source_digest,'recipe':d.recipe_ref},events=(('d11','habit_source_note_action_requires_original_life'),))
    return SourceNoteActionStageV1(stage)


from .d08_source_note_action_v1 import SourceNoteActionOriginalV1
@dataclass(frozen=True,slots=True,kw_only=True)
class HabitSourceNoteOriginalV1(SourceNoteActionOriginalV1):
    occurrence_ref:str
    occurrence_revision:int
    standing_original_ref:str
    standing_original_digest:str
    qualification_original_ref:str
    qualification_original_digest:str
    context_original_ref:str
    context_original_digest:str
    command_request_digest:str
    whole_write_commitments:tuple[tuple[str,int,str],...]
    schema:str='d08.habit-source-note-action-original.v1'
    def __post_init__(self):
        from dataclasses import fields
        values={f.name:getattr(self,f.name)for f in fields(SourceNoteActionOriginalV1)};values['schema']='d08.source-note-action-original.v2';SourceNoteActionOriginalV1(**values)
        if self.schema!='d08.habit-source-note-action-original.v1'or AtomKey.from_token(self.occurrence_ref).type_name!=HABIT_OCCURRENCE_TYPE or self.occurrence_revision<1 or not self.whole_write_commitments:raise ValueError('Habit SourceNote original binds actual occurrence and whole same-W01 receipt')

def habit_source_note_original_from_wire_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw,HabitSourceNoteOriginalV1)


def record_habit_source_note_action_after_cas_v1(db,*,frame,staged,receipt,issuer):
    import json
    from .d08_source_note_action_v1 import _adopted
    from .d04_root_original_store_v1 import _receipt
    from .d11_life_preparation_v1 import _record
    from ..runtime_contracts import CommitReceipt
    primary=staged.stage;proof=json.loads(primary.original_payload_json)['provenance'];request=proof['derived_request'];read=CurrentDomainReadV1(frame)
    if type(receipt)is not CommitReceipt or receipt.status!='committed'or receipt.operation_id!=frame.envelope.identity.operation_id or primary.operation_kind!='prepare_current_habit_source_note_action_v1'or _receipt(db,primary.namespace,receipt.operation_id)!=receipt:raise ValueError('Habit SourceNote requires its actual successful same-W01 receipt')
    writes=tuple(w for p in primary.proposals for w in p.typed_writes);versions={v.key:v.revision for v in receipt.write_versions}
    if set(versions)!={w.key for w in writes}:raise ValueError('Habit Action receipt lost its whole Action/occurrence/semantic members')
    action=next(w for w in writes if w.key.type_name=='d08.action_intent.v1');action_writes=tuple(w for w in writes if w.key.type_name in {'d08.action_intent.v1','d08.action_schema.v1','d08.action_cancellation.v1'})
    contexts=[]
    for ref in(request['target_entity_ref'],request['role_binding_ref'],request['project_ref']):
        atom=read.head(db,ref,required=True);operation=_adopted(db,read,atom);contexts.append((ref,atom.revision,canonical_digest(atom.value),operation,canonical_digest(_receipt(db,primary.namespace,operation))))
    occ=habit_value_from_wire_v1(HABIT_OCCURRENCE_TYPE,proof['occurrence'])
    from ..authority_service.d10_habit_contract_v1 import habit_occurrence_qualification_from_wire_v1
    qualification=habit_occurrence_qualification_from_wire_v1(proof['core_qualification'])
    base=SourceNoteActionOriginalV1(action.key.token,canonical_digest(action.value),receipt.operation_id,occ.activity_id,occ.effect_id,request['project_ref'],request['recipe_ref'],request['source_ref'],request['goal_ref'],frame.envelope.authority.audience,request['target_entity_ref'],request['role_binding_ref'],tuple(contexts),tuple((w.key.token,versions[w.key],canonical_digest(w.value))for w in action_writes),canonical_digest(receipt))
    from dataclasses import asdict
    original=HabitSourceNoteOriginalV1(**{**asdict(base),'audiences':base.audiences,'context_commitments':base.context_commitments,'write_commitments':base.write_commitments,'schema':'d08.habit-source-note-action-original.v1'},occurrence_ref=habit_occurrence_key_v1(occ.namespace,occ.occurrence_id).token,occurrence_revision=versions[habit_occurrence_key_v1(occ.namespace,occ.occurrence_id)],standing_original_ref=qualification.standing_original_ref,standing_original_digest=qualification.standing_original_digest,qualification_original_ref=qualification.original_ref,qualification_original_digest=qualification.digest,context_original_ref=occ.context_original_ref,context_original_digest=occ.context_original_digest,command_request_digest=_habit_installed_command_digest_v1(primary.operation_kind,habit_request_from_wire_v1(primary.operation_kind,json.loads(primary.original_payload_json)['request'])),whole_write_commitments=tuple((w.key.token,versions[w.key],canonical_digest(w.value))for w in writes))
    return _record(db,issuer=issuer,namespace=primary.namespace,kind='source_note_action',ref='life-root:'+receipt.operation_id,operation_id=receipt.operation_id,value=original)


def _habit_installed_command_digest_v1(kind,request):
    from .domain_production_registry_v1 import installed_operation_v1
    from .habit_activity_issuance_v1 import habit_typed_command_digest_v1
    return habit_typed_command_digest_v1(installed_operation_v1(kind),request)


def require_habit_source_note_original_v1(db,*,namespace,raw,operation,issuer,frame=None):
    from .domain_background_read_v3 import background_history_v3
    from .d04_root_original_store_v1 import _receipt
    original=habit_source_note_original_from_wire_v1(raw);receipt=_receipt(db,namespace,operation)
    if operation!=original.action_operation_id or canonical_digest(receipt)!=original.receipt_digest or receipt.status!='committed'or {(v.key.token,v.revision)for v in receipt.write_versions}!={(r,v)for r,v,_ in original.whole_write_commitments}:raise ValueError('Habit SourceNote original lost its whole actual successful W01 receipt')
    for ref,revision,digest in original.whole_write_commitments:
        row=background_history_v3(db,ref,revision,columns=('value','valid','event_id'))
        import json
        if row is None or row[1]!=1 or row[2]!=operation or canonical_digest(json.loads(row[0]))!=digest:raise ValueError('Habit SourceNote original lost an actual whole-CAS history member')
    actual=read_adopted_domain_operation_v1(db,namespace,operation)
    if actual is None or(actual['domain'],actual['operation_kind'])!=('d08','prepare_current_habit_source_note_action_v1')or actual['original_digest']!=canonical_digest(actual['payload']):raise ValueError('Habit SourceNote uses its named actual producer, not selected/Owner task originals')
    request=habit_request_from_wire_v1(actual['operation_kind'],actual['payload']['request'])
    if(request.occurrence_ref,request.expected_revision+1)!=(original.occurrence_ref,original.occurrence_revision)or _habit_installed_command_digest_v1(actual['operation_kind'],request)!=original.command_request_digest:raise ValueError('Habit SourceNote original changed its actual typed request')
    proof=actual['payload']['provenance']
    from ..authority_service.d10_habit_contract_v1 import habit_occurrence_qualification_from_wire_v1,habit_standing_policy_original_from_wire_v1
    qualification=habit_occurrence_qualification_from_wire_v1(proof['core_qualification']);standing=habit_standing_policy_original_from_wire_v1(proof['core_standing_original'])
    if(qualification.original_ref,qualification.digest,qualification.standing_original_ref,qualification.standing_original_digest)!=(original.qualification_original_ref,original.qualification_original_digest,original.standing_original_ref,original.standing_original_digest)or(standing.original_ref,standing.digest)!=(original.standing_original_ref,original.standing_original_digest):raise ValueError('Habit SourceNote original changed actual independent Core standing/occurrence originals')
    if frame is not None:
        from .current_habit_source_read_v3 import require_current_habit_executor_inputs_v3
        facts=require_current_habit_executor_inputs_v3(db,frame=frame,action_ref=original.action_intent_ref,issuer=issuer)
        current=facts.execution_current
        if current.qualification_original!=qualification or current.policy_original!=standing or current.owner_guard!=frame.owner_guard:raise MissingProductionOriginalV1('same_actual_current_Habit_execution_Source_Owner_Core_Root')
        read=CurrentDomainReadV1(frame);atom,occurrence=_occurrence(db,read,original.occurrence_ref)
        if occurrence.action_intent_ref!=original.action_intent_ref or occurrence.state not in {'qualified','active','unknown'}or frame.now_utc>=occurrence.original_deadline_utc:raise MissingProductionOriginalV1('actual_original_Habit_execution_identity_and_deadline')
        _,policy=_policy(db,read,occurrence.policy_ref)
        if policy.core_original_ref!=standing.original_ref or policy.core_original_digest!=standing.digest or occurrence.cancellation_generation!=policy.definition.cancellation_generation or _stop(db,read,policy.definition):raise MissingProductionOriginalV1('actual_current_Habit_policy_revision_or_stop')
        read_current_habit_source_note_context_v1(db,read=read,occurrence=occurrence,policy=policy)
        for ref,revision,digest in original.write_commitments:
            selected=read.head(db,ref,required=True)
            if selected.revision!=revision or canonical_digest(selected.value)!=digest:raise MissingProductionOriginalV1('current_Habit_Action_schema_and_cancellation')
    return original


def habit_source_note_life_ids_v1(namespace,occurrence_id,project_ref):
    operation,activity,effect,attempt=habit_source_note_execution_identity_v1(namespace,occurrence_id,project_ref)
    marker=canonical_digest(('d10.habit-source-note.v1',namespace,occurrence_id))[:48];plan='habit-source-note-life-plan:'+marker
    return {'action_operation_id':operation,'activity_id':activity,'effect_id':effect,'attempt_id':attempt,'action_original_ref':'life-root:'+operation,'body_operation_id':'d02-life-body:'+operation,'body_original_ref':'life-body:d02-life-body:'+operation,'plan_ref':plan,'plan_operation_id':plan+':register','prepare_operation_id':'d11-life-prepare:'+operation}


def stage_register_current_habit_source_note_life_plan_v1(db,*,frame,request,installed):
    from datetime import datetime,timezone
    from ..memory_types import SourceRecord,access_key
    from .d11_life_contract_v1 import RegisteredLifePlanV2,LifeInputRefV1,LifeBodyComponentContractV1,WORK_KIND
    from .d11_life_preparation_v1 import _read
    from .d02_life_body_preparation_v1 import life_body_preparation_original_from_wire_v1
    from ..runtime_contracts import canonical_serialize
    from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
    from .d08_source_note_action_v1 import require_source_note_action_original_v1
    kind='register_current_habit_source_note_life_plan_v1';read,atom,occurrence,policy_atom,policy,qualification,current=_qualified_habit_execution_v1(db,frame=frame,request=request,installed=installed,kind=kind);d=policy.definition;ids=habit_source_note_life_ids_v1(d.namespace,occurrence.occurrence_id,d.project_ref)
    if frame.envelope.identity.operation_id!=ids['plan_operation_id']or occurrence.life_plan_original_ref is not None or occurrence.action_intent_ref is None:raise MissingProductionOriginalV1('actual_Habit_Life_plan_once_registration_after_Action_and_Body')
    root=require_source_note_action_original_v1(db,namespace=d.namespace,action_intent_ref=occurrence.action_intent_ref,issuer=installed.issuer,frame=frame)
    if type(root)is not HabitSourceNoteOriginalV1 or root.occurrence_ref!=atom.key.token:raise ValueError('Habit final Life plan cannot borrow another Action variant or occurrence')
    material={}
    for name,ref in(('project',d.project_ref),('recipe',d.recipe_ref),('action_intent',occurrence.action_intent_ref),('input_source',d.source_note_input.source_ref)):
        selected=read.head(db,ref,required=True);material[name]=LifeInputRefV1(ref,selected.revision,canonical_digest(selected.value))
    source=SourceRecord.from_dict(read.head(db,material['input_source'].ref,required=True).value);access=read.head(db,access_key(*d.namespace.as_tuple,source.source_id),required=True)
    material['input_access']=LifeInputRefV1(access.key.token,access.revision,canonical_digest(access.value))
    saved=_read(db,issuer=installed.issuer,namespace=d.namespace,kind='life_body_preparation',ref=ids['body_original_ref'])
    if saved is None:raise MissingProductionOriginalV1('actual_Habit_Body_B_COMMIT_before_registered_Life_plan')
    body=life_body_preparation_original_from_wire_v1(saved[0]);actual=read_adopted_domain_operation_v1(db,d.namespace,saved[1]);read.committed_operation(db,saved[1])
    if actual is None or(actual['domain'],actual['operation_kind'])!=('d02','prepare_source_note_body')or saved[1]!=ids['body_operation_id']or actual['receipt'].status!='committed'or canonical_digest(actual['receipt'])!=body.receipt_digest or(body.action_intent_ref,body.action_intent_digest,body.action_operation_id,body.activity_id,body.effect_id)!=(root.action_intent_ref,root.action_intent_digest,root.action_operation_id,root.activity_id,root.effect_id):raise ValueError('Habit Life plan lost its exact original Body B and Action A')
    reservation=read.head(db,body.reservation_ref,required=True)
    if(reservation.revision,canonical_digest(reservation.value))!=(body.reservation_revision,body.reservation_digest)or actual['receipt'].write_versions!=(GraphVersion(reservation.key,reservation.revision),):raise ValueError('Habit Life Body reservation current head or producing receipt changed')
    quote=installed.issuer.resource_issuer.original_signed_quote(db,body.resource_quote_ref,body.resource_quote_version)
    if canonical_digest(quote)!=body.resource_quote_digest or quote.work_kind!=WORK_KIND or(quote.operation_id,quote.activity_id,quote.effect_id,quote.parent_budget_lease_ref)!=(ids['body_operation_id'],occurrence.activity_id,occurrence.effect_id,occurrence.parent_root_grant_ref):raise ValueError('Habit Life plan changed original signed Body resource quote')
    body_authority=installed.legacy_readers.body_readers.body_quote_authority
    body_quote=body_authority.original_body_quote(db,body.body_quote_ref,body.body_quote_version,quote,body.body_prepare_operation_id)
    if canonical_digest(body_quote)!=body.body_quote_digest:raise ValueError('Habit Life plan changed actual signed Body quote')
    cpu=min(60000,quote.ceiling.get('cpu_ms',0),current.policy_original.root_grant.max_ceiling.get('thread_cpu_ms',0))
    deadline=min(occurrence.original_deadline_utc,quote.valid_until_utc,body_quote.valid_until,current.valid_until_utc)
    if cpu<1 or frame.now_utc>=deadline:raise MissingProductionOriginalV1('actual_Habit_original_Root_Body_CPU_or_deadline')
    build=read_installed_d11_life_build_v1(installed.legacy_readers.package_root,installed.legacy_readers.manifest_digest)
    contract=LifeBodyComponentContractV1(*(getattr(body,n)for n in('body_quote_ref','body_quote_version','body_quote_digest','resource_quote_ref','resource_quote_version','resource_quote_digest','reservation_ref','settlement_ref','component_id','effect_policy_ref','body_prepare_operation_id')))
    plan=RegisteredLifePlanV2(material['project'],material['recipe'],material['action_intent'],material['input_source'],material['input_access'],occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id,occurrence.occurrence_operation_id,d.audience,occurrence.parent_root_grant_ref,cpu,datetime.fromtimestamp(deadline,timezone.utc).isoformat().replace('+00:00','Z'),build['algorithm_build_digest'],build['postcondition_build_digest'],canonical_serialize(plain_v1(contract)))
    updated=replace(occurrence,life_plan_original_ref=ids['plan_ref'])
    return _emit(db,frame,kind,request,writes=(_write(frame,atom,updated),),provenance={'life_plan':plan,'habit_occurrence_ref':atom.key.token,'occurrence':updated,'core_qualification':qualification,'action_original_ref':ids['action_original_ref'],'action_original_digest':canonical_digest(plain_v1(root)),'body_original_ref':ids['body_original_ref'],'body_original_digest':canonical_digest(saved[0])},causal=ProductionOriginalRefV1('d11.life_life_body_preparation',ids['body_original_ref'],canonical_digest(saved[0])),roots=updated.source_refs,semantic={'occurrence':updated.occurrence_id,'phase':'life_plan_registered','recipe':updated.recipe_ref,'source':material['input_source'].digest},cancellation_generation=updated.cancellation_generation,original_deadline_utc=updated.original_deadline_utc,events=(('d11','habit_life_plan_requires_original_preparation'),))


def record_habit_source_note_life_plan_after_cas_v1(db,*,frame,stage,receipt,installed):
    import json
    from .d11_life_preparation_v1 import record_registered_life_plan_v2
    from .d11_life_contract_v1 import RegisteredLifePlanV2,life_from_wire_v1
    from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
    if stage.operation_kind!='register_current_habit_source_note_life_plan_v1'or receipt.status!='committed'or receipt.operation_id!=stage.operation_id:raise ValueError('Habit final Life plan needs its exact same-W01 producer receipt')
    proof=json.loads(stage.original_payload_json)['provenance'];occurrence=habit_value_from_wire_v1(HABIT_OCCURRENCE_TYPE,proof['occurrence']);plan=life_from_wire_v1(proof['life_plan'],RegisteredLifePlanV2)
    if occurrence.life_plan_original_ref is None or(plan.activity_id,plan.effect_id,plan.attempt_id,plan.operation_id,plan.parent_budget_lease_ref)!=(occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id,occurrence.occurrence_operation_id,occurrence.parent_root_grant_ref):raise ValueError('Habit registered plan changes immutable original execution identity')
    build=read_installed_d11_life_build_v1(installed.legacy_readers.package_root,installed.legacy_readers.manifest_digest)
    return record_registered_life_plan_v2(db,frame=frame,issuer=installed.issuer,original_ref=occurrence.life_plan_original_ref,producing_operation_id=receipt.operation_id,plan=plan,installed_build=build,body_quote_authority=installed.legacy_readers.body_readers.body_quote_authority)


@dataclass(frozen=True,slots=True)
class HabitLifeOccurrenceTransitionV1:
    occurrence_ref:str
    occurrence_before_revision:int
    occurrence_before_digest:str
    action_head:GraphVersion
    action_digest:str
    job_id:str
    job_fence:int
    job_cancel_epoch:int
    job_holder:str
    qualification_original_ref:str
    qualification_original_digest:str
    execution_selector:object
    core_current_digest:str
    write:GraphWrite
    schema:str='d10.habit-life-occurrence-transition.v1'


def adopted_habit_occurrence_execution_v1(db,*,frame,prepared,job,issuer):
    from .current_habit_source_read_v3 import require_current_habit_executor_inputs_v3
    from .jobs import get_job
    from .d11_offline_originals_v1 import _utc
    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
    if type(prepared.plan)is RegisteredDraftFilePlanV3:
        from .artifact_borrowed_source_v3 import require_artifact_borrowed_life_facts_v3
        facts=require_artifact_borrowed_life_facts_v3(db,frame=frame,prepared=prepared,job=job,issuer=issuer)
        # Only the actual Artifact Source profile may prove a positive ordinary plan.
        if facts is None:return None
    else:
        facts=require_current_habit_executor_inputs_v3(db,frame=frame,action_ref=prepared.plan.action_intent.ref,issuer=issuer)
    from .ordinary_source_note_habit_classification_v3 import OrdinarySourceNoteHabitClassificationV3
    if type(facts)is OrdinarySourceNoteHabitClassificationV3:
        facts.require_current_v3(db,frame,prepared.plan.action_intent.ref,issuer)
        return None
    if facts is None:raise MissingProductionOriginalV1("actual_positive_execution_family_classification")
    current=facts.execution_current;qualification=facts.occurrence_qualification;read=CurrentDomainReadV1(frame)
    occurrence_ref=current.request.occurrence_ref;atom,occurrence=_occurrence(db,read,occurrence_ref)
    _,policy=_policy(db,read,occurrence.policy_ref);d=policy.definition;b=prepared.binding;p=prepared.plan
    if occurrence.state!='qualified'or occurrence.qualification_original_ref!=qualification.original_ref or current.qualification_original!=qualification or current.owner_guard!=frame.owner_guard or(current.policy_original.original_ref,current.policy_original.digest)!=(policy.core_original_ref,policy.core_original_digest)or occurrence.policy_revision!=d.revision or occurrence.cancellation_generation!=d.cancellation_generation or _stop(db,read,d):raise MissingProductionOriginalV1('actual_current_Habit_original_occurrence_Life_phase')
    if(b.operation_id,b.activity_id,b.effect_id,b.attempt_id,b.parent_budget_lease_ref)!=(occurrence.occurrence_operation_id,occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id,occurrence.parent_root_grant_ref)or current.request.operation_kind!='prepare_life'or current.request.operation_id!=b.prepare_operation_id or frame.envelope.identity.operation_id!=b.prepare_operation_id:raise ValueError('Habit Life phase changed its actual original Action/effect/Root/operation')
    if job.phase!='running'or get_job(db,job.job_id)!=job or(job.job_id,job.fence,job.cancel_epoch,job.lease_holder)!=(b.job_id,b.job_fence,b.job_cancel_epoch,b.job_holder)or _utc(b.deadline_utc).timestamp()>occurrence.original_deadline_utc or frame.now_utc>=occurrence.original_deadline_utc:raise MissingProductionOriginalV1('actual_same_running_Life_job_and_original_Habit_deadline')
    action=read.head(db,p.action_intent.ref,required=True)
    if(action.revision,canonical_digest(action.value))!=(p.action_intent.revision,p.action_intent.digest)or occurrence.action_intent_ref not in(None,action.key.token)or occurrence.life_plan_original_ref not in(None,b.plan_original_ref):raise ValueError('Habit Life phase changed its actual Action or signed registered plan')
    if occurrence.executor_kind=='source_note':
        from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
        if type(current.request)is not HabitOccurrenceExecutionSelectorV1 or b.prepare_operation_id!='d11-life-prepare:'+occurrence.occurrence_operation_id:raise ValueError('Habit SourceNote keeps its exact independently issued Life phase')
        if occurrence.action_intent_ref!=action.key.token or occurrence.life_plan_original_ref!=b.plan_original_ref:raise ValueError('Habit SourceNote Life needs its actual prior Action and plan COMMITs')
        read_current_habit_source_note_context_v1(db,read=read,occurrence=occurrence,policy=policy)
    else:
        selected=read_current_habit_execution_target_v1(db,read=read,definition=d,issuer=issuer,require_unused=False)
        from ..authority_service.current_habit_artifact_restriction_v1 import HabitArtifactAdditionalSelectorV1
        from ..model_broker.artifact_draft_v1 import artifact_draft_phase_original_ref_v2
        if type(current.request)is not HabitArtifactAdditionalSelectorV1 or current.request.artifact_phase_selector!=selected.phase_selector or current.request.foreground_request.operation_kind!='prepare_life'or current.request.foreground_request.operation_id!=b.prepare_operation_id or b.prepare_operation_id!=artifact_draft_phase_original_ref_v2(selected.phase_selector)+':file-prepare':raise ValueError('Habit Draft Life preserves its actual original Foreground phase scope and prepare operation')
        if(selected.future_identity.action_operation_id,selected.future_identity.effect_id)!=(b.operation_id,b.effect_id):raise ValueError('Habit DraftFile Life cannot create another generation')
    updated=replace(occurrence,state='active',action_intent_ref=action.key.token,life_plan_original_ref=b.plan_original_ref,actual_started_at_utc=frame.now_utc)
    return HabitLifeOccurrenceTransitionV1(atom.key.token,atom.revision,canonical_digest(atom.value),GraphVersion(action.key,action.revision),canonical_digest(action.value),job.job_id,job.fence,job.cancel_epoch,job.lease_holder,qualification.original_ref,qualification.digest,current.request,canonical_digest(current),_write(frame,atom,updated))


def attach_habit_life_occurrence_transition_v1(db,*,preparation,issuer):
    import json
    from ..runtime_contracts import canonical_serialize
    from .d11_life_preparation_v1 import LifePreparationStageV1
    if type(preparation)is not LifePreparationStageV1:raise TypeError('Habit transition decorates only the actual existing Life preparation stage')
    transition=adopted_habit_occurrence_execution_v1(db,frame=preparation.frame,prepared=preparation.prepared,job=preparation.job,issuer=issuer)
    if transition is None:return preparation
    raw=json.loads(preparation.stage.original_payload_json)
    raw['provenance']['habit_life_occurrence_transition']=plain_v1(transition)
    raw['writes']=plain_v1((*preparation.writes,transition.write))
    primary=replace(preparation.stage,original_payload_json=canonical_serialize(raw),original_digest=canonical_digest(raw))
    return replace(preparation,stage=primary,habit_occurrence_transition=transition)


def verify_habit_life_occurrence_transition_v1(db,*,preparation,issuer):
    transition=preparation.habit_occurrence_transition
    actual=adopted_habit_occurrence_execution_v1(db,frame=preparation.frame,prepared=preparation.prepared,job=preparation.job,issuer=issuer)
    if transition is None:
        if actual is not None:raise MissingProductionOriginalV1('Habit_managed_Life_cannot_fall_back_to_ordinary_job_only_CAS')
        return None
    if type(transition)is not HabitLifeOccurrenceTransitionV1 or actual!=transition:raise ValueError('Habit Life transition is not its actual current Core/Owner/Source/job/occurrence expected-head fact')
    return transition


def habit_occurrence_companion_matches_v1(stage,proposal):
    """Closed structural companion contract; current private Source/Core gates remain mandatory."""
    import json
    from ..authority_service.current_habit_occurrence_v1 import habit_current_from_wire_v1
    from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d10.project_checkpoint_v1 import decode_project_checkpoint_type_v1,project_checkpoint_key_v1,CHECKPOINT_TYPE
    allowed={'instantiate_current_habit_source_note_context_v1','prepare_current_habit_source_note_action_v1'}
    if stage.domain!='d08'or stage.operation_kind not in allowed or proposal.domain!='d10':return False
    raw=json.loads(stage.original_payload_json);request=habit_request_from_wire_v1(stage.operation_kind,raw['request']);proof=raw['provenance']
    current=habit_current_from_wire_v1(proof['habit_execution_current']);selector=current.request
    if type(selector)is not HabitOccurrenceExecutionSelectorV1 or selector.operation_kind!=stage.operation_kind or selector.operation_id!=stage.operation_id or selector.request_digest!=_habit_installed_command_digest_v1(stage.operation_kind,request)or selector.occurrence_ref!=request.occurrence_ref or selector.expected_occurrence_revision!=request.expected_revision:raise ValueError('Habit companion requires this exact current Core execution phase and typed command')
    if proposal.proposal_schema!='d10.proposal.v1'or proposal.proposal_schema_hash!=schema_hash({'domain':'d10','proposal':1}):raise ValueError('Habit companion requires its exact installed D10 schema')
    if proposal.envelope!=next(p.envelope for p in stage.proposals if p.domain=='d08'):raise ValueError('Habit companion cannot change the complete actual primary envelope')
    if proposal.envelope.authority.namespace!=stage.namespace or proposal.envelope.identity.operation_id!=stage.operation_id or proposal.envelope.identity.activity_id!=stage.activity_id or proposal.envelope.version_guard.read_versions!=stage.read_versions or proposal.contribution_keys or proposal.required_bundle_parts:raise ValueError('Habit companion cannot change the exact namespace/operation/readset or issue another bundle capability')
    written=tuple(decode_typed_production_value_v1(w,GraphWrite)for w in raw['writes']);by_key={w.key:w for w in written}
    if len(by_key)!=len(written)or any(by_key.get(w.key)!=w for w in proposal.typed_writes):raise ValueError('Habit companion differs from whole original write commitments')
    declared=tuple(w for w in written if w.key.type_name.startswith('d10.'))
    if proposal.typed_writes!=declared or len({p.domain for p in stage.proposals if p.domain in {'d08','d10'}})!=2 or sum(p.domain=='d10'for p in stage.proposals)!=1:raise ValueError('Habit companion must be the exact single D10 partition')
    if sum(p.domain=='d08'for p in stage.proposals)!=1:raise ValueError('Habit companion requires exactly one primary proposal')
    expected_events={('d08','habit_source_note_context_ready_requires_action')}if stage.operation_kind=='instantiate_current_habit_source_note_context_v1'else {('d11','habit_source_note_action_requires_original_life')}
    if {(o.receiver_domain,o.event_kind)for o in stage.outbox}!=expected_events or len(stage.outbox)!=1 or stage.jobs or stage.paid_cost_originals:raise ValueError('Habit companion cannot add another job, cost or outbox route')
    primary=tuple(w for p in stage.proposals if p.domain=='d08'for w in p.typed_writes)
    if primary!=tuple(w for w in written if w.key.type_name.startswith('d08.')):raise ValueError('Habit primary proposal loses exact Goal/Plan or Action members')
    occurrence_writes=tuple(w for w in declared if w.key.type_name==HABIT_OCCURRENCE_TYPE)
    if len(occurrence_writes)!=1 or occurrence_writes[0].key.token!=request.occurrence_ref:raise ValueError('Habit companion updates only its exact occurrence')
    occurrence=habit_value_from_wire_v1(HABIT_OCCURRENCE_TYPE,occurrence_writes[0].value);qualification=current.qualification_original;d=current.policy_original.definition
    if occurrence.state!='qualified'or occurrence.qualification_original_ref!=qualification.original_ref or occurrence.policy_ref!=habit_policy_key_v1(d.namespace,d.policy_id).token or occurrence.policy_revision!=d.revision or occurrence.cancellation_generation!=d.cancellation_generation or occurrence.occurrence_operation_id!=selector.qualification_selector.execution_operation_id:raise ValueError('Habit companion cannot change independent standing, qualification or execution identity')
    heads={v.key:v.revision for v in stage.read_versions}
    if heads.get(occurrence_writes[0].key)!=request.expected_revision or any(w.key not in heads or NamespaceId.from_key(w.key)!=stage.namespace for w in written):raise ValueError('Habit companion requires every actual expected head')
    if stage.operation_kind=='instantiate_current_habit_source_note_context_v1':
        context=habit_source_note_context_from_wire_v1(proof['habit_source_note_context']);keys=habit_source_note_context_keys_v1(stage.namespace,occurrence.occurrence_id,stage.activity_id)
        if len(primary)!=2 or {w.key for w in primary}!=set(keys.values())or any(heads[w.key]!=0 for w in primary)or occurrence.action_intent_ref is not None or occurrence.life_plan_original_ref is not None or(occurrence.goal_ref,occurrence.plan_ref)!=(keys['goal'].token,keys['plan'].token):raise ValueError('Habit context companion describes only this new occurrence Goal/Plan')
        checkpoints=tuple(w for w in declared if w.key.type_name==CHECKPOINT_TYPE)
        if len(declared)!=2 or len(checkpoints)!=1 or checkpoints[0].key!=project_checkpoint_key_v1(stage.namespace,d.project_ref):raise ValueError('Habit context companion changes exactly one actual project pointer')
        checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,checkpoints[0].value)
        if checkpoint.revision!=heads[checkpoints[0].key]+1 or(checkpoint.plan_ref,checkpoint.plan_revision,checkpoint.next_step,checkpoint.state)!=(keys['plan'].token,1,context.node_id,'active')or context.occurrence_before_revision!=request.expected_revision:raise ValueError('Habit context checkpoint lost its exact expected head or occurrence plan')
    else:
        if len(declared)!=1 or len(primary)!=3 or {w.key.type_name for w in primary}!={'d08.action_intent.v1','d08.action_schema.v1','d08.action_cancellation.v1'}or any(heads[w.key]!=0 for w in primary):raise ValueError('Habit Action companion preserves its exact three-member birth')
        action=next(w for w in primary if w.key.type_name=='d08.action_intent.v1')
        if occurrence.action_intent_ref!=action.key.token or not occurrence.context_original_ref or not occurrence.context_original_digest or stage.operation_id!=occurrence.occurrence_operation_id:raise ValueError('Habit Action companion requires the actual preceding context original and fixed Action identity')
    return True


def require_habit_life_input_own_delta_v1(db,*,prepared,frozen,actual,issuer):
    """Accept only the occurrence member of this exact real Life prepare CAS."""
    import json
    from .d11_types import job_graph_write
    from .domain_background_read_v3 import background_history_v3
    b=prepared.binding
    original=read_adopted_domain_operation_v1(db,b.namespace,b.prepare_operation_id)
    if original is None:return False
    raw=original['payload']['provenance'].get('habit_life_occurrence_transition')
    if raw is None:return False
    if raw.get('schema')!='d10.habit-life-occurrence-transition.v1'or(original['domain'],original['operation_kind'])!=('d10','prepare_life')or original['receipt'].status!='committed':raise ValueError('Habit Life own delta is not its actual named signed preparation original')
    if frozen.ref!=raw['occurrence_ref']:return False
    if actual is None or raw['occurrence_before_revision']!=frozen.revision or raw['occurrence_before_digest']!=canonical_digest(json.loads(frozen.value_json)):raise ValueError('Habit Life own delta changed its immutable captured input')
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    write=decode_typed_production_value_v1(raw['write'],GraphWrite);after=habit_value_from_wire_v1(HABIT_OCCURRENCE_TYPE,write.value)
    if write.key.token!=frozen.ref or(actual[0],actual[2])!=(frozen.revision+1,1)or canonical_digest(json.loads(actual[1]))!=canonical_digest(write.value)or after.state!='active'or(after.activity_id,after.effect_id,after.attempt_id,after.occurrence_operation_id,after.parent_root_grant_ref,after.life_plan_original_ref)!=(b.activity_id,b.effect_id,b.attempt_id,b.operation_id,b.parent_budget_lease_ref,b.plan_original_ref):raise ValueError('Habit Life own delta is not the exact active original occurrence member')
    from .jobs import get_job
    job=get_job(db,b.job_id)
    if job is None or(raw['job_id'],raw['job_fence'],raw['job_cancel_epoch'],raw['job_holder'])!=(b.job_id,b.job_fence,b.job_cancel_epoch,b.job_holder):raise ValueError('Habit Life own delta changed actual acquired job identity')
    receipt=original['receipt'];expected={GraphVersion(write.key,frozen.revision+1),GraphVersion(job_graph_write(job).key,prepared.job_projection_revision)}
    if set(receipt.write_versions)!=expected:raise ValueError('Habit Life own delta must be exactly the original job and occurrence same-CAS receipt')
    history=background_history_v3(db,write.key.token,frozen.revision+1,columns=('event_id','value','valid'))
    if history!=(b.prepare_operation_id,actual[1],1):raise ValueError('Habit Life own delta lost its actual immutable event member')
    selector_raw=raw['execution_selector']
    from ..authority_service.d10_habit_execution_contract_v1 import habit_occurrence_execution_from_wire_v1
    if selector_raw['schema']=='d10.habit-occurrence-execution-selector.v1':selector=habit_occurrence_execution_from_wire_v1(selector_raw)
    else:
        from ..authority_service.current_habit_artifact_restriction_v1 import habit_artifact_additional_from_wire_v1
        selector=habit_artifact_additional_from_wire_v1(selector_raw)
    if selector.operation_kind!='prepare_life'or selector.operation_id!=b.prepare_operation_id or selector.qualification_selector.execution_operation_id!=b.operation_id or selector.qualification_original_ref!=raw['qualification_original_ref']or selector.qualification_original_digest!=raw['qualification_original_digest']:raise ValueError('Habit Life own delta lost its original independent Core execution and qualification identity')
    return True


HABIT_MANAGED_TABLE='graph_habit_managed_execution_v1'
HABIT_MANAGED_SIGN='d11.habit-managed-execution-metadata.v1'
HABIT_MANAGED_COLUMNS=('selector_commitment','decision_ref','decision_digest','phase_selector_digest','future_identity_digest','policy_ref','policy_revision','core_original_ref','core_original_digest','current_state','producer_operation_id','producer_receipt_digest','retired','signature')

def install_habit_managed_execution_schema_v1(db):
    if db.in_transaction:raise ValueError('install managed metadata before runtime transactions')
    from .b3_managed_metadata_v1 import install_managed_metadata_table_v1
    install_managed_metadata_table_v1(db,HABIT_MANAGED_TABLE)

def habit_draft_selector_commitment_v1(namespace,*,decision_ref,decision_digest,phase_selector,future_identity,issuer):
    from ..runtime_contracts import canonical_serialize
    material=(namespace,'d10.habit-draft-selector.v1',decision_ref,decision_digest,canonical_digest(phase_selector),canonical_digest(future_identity))
    return canonical_digest(issuer._signer.sign(HABIT_MANAGED_SIGN,canonical_serialize(material)))

def _habit_managed_signed_row_v1(namespace,values,issuer):
    from ..runtime_contracts import canonical_serialize
    return (*values,issuer._signer.sign(HABIT_MANAGED_SIGN,canonical_serialize((namespace,values))))

def record_habit_managed_execution_after_cas_v1(db,*,witness,primary,receipt,issuer):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE,_members
    from ..runtime_contracts import canonical_serialize
    if primary.operation_kind not in POLICY_OPERATIONS:return ()
    if type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness or _members(witness.stage)[0]is not primary or db is not witness.graph._GraphCoordinator__store._db or not db.in_transaction or receipt.status!='committed'or receipt.operation_id!=primary.operation_id:raise ValueError('Habit metadata classification requires its actual same-W01 private witness')
    writes=tuple(w for p in primary.proposals for w in p.typed_writes if w.key.type_name==HABIT_POLICY_TYPE)
    if len(writes)!=1:raise ValueError('Habit classification is born only with the one real adopted policy')
    write=writes[0];policy=graph_adopted_habit_policy_from_wire_v1(write.value);d=policy.definition;ns=d.namespace;written=[]
    rows=db.execute('SELECT '+','.join(HABIT_MANAGED_COLUMNS)+' FROM '+HABIT_MANAGED_TABLE+' WHERE bot=? AND persona=? AND policy_ref=?',(*ns.as_tuple,write.key.token)).fetchall()
    for row in rows:
        issuer._signer.verify(HABIT_MANAGED_SIGN,canonical_serialize((ns,tuple(row[:-1]))),row[-1])
    from .b3_managed_metadata_v1 import apply_habit_managed_metadata_retirements_after_cas_v1
    retired=apply_habit_managed_metadata_retirements_after_cas_v1(db,witness=witness,primary=primary,receipt=receipt,issuer=issuer)
    reusable=tuple(r for r in rows if r[1]==d.target_ref and r[12]==0)
    if d.executor_kind!='draft_file':
        return retired
    if reusable:
        if len(reusable)!=1:raise ValueError('Habit Draft policy cannot own multiple current selected generations')
        row=reusable[0];values=(*row[:5],write.key.token,d.revision,policy.core_original_ref,policy.core_original_digest,d.state,receipt.operation_id,canonical_digest(receipt),0)
    else:
        if d.state!='enabled':raise MissingProductionOriginalV1('actual_original_Habit_Draft_selector_for_management')
        import json
        target=json.loads(primary.original_payload_json)['provenance']['habit_draft_managed_target']
        if type(target)is not dict or set(target)!={'selector_commitment','decision_ref','decision_digest','phase_selector_digest','future_identity_digest'}or target['decision_ref']!=d.target_ref:raise ValueError('Habit Draft classification lost its actual pre-CAS selected generation metadata')
        selected=witness.frame.snapshot.get(AtomKey.from_token(target['decision_ref']))
        if (selected is None or not selected.valid or canonical_digest(selected.value)!=target['decision_digest']
                or GraphVersion(selected.key,selected.revision)not in receipt.read_versions
                or any(v.key==selected.key for v in receipt.write_versions)):
            raise ValueError('Habit Draft original Decision is not its actual unchanged pre-CAS input member')
        commitment=target['selector_commitment']
        values=(commitment,target['decision_ref'],target['decision_digest'],target['phase_selector_digest'],target['future_identity_digest'],write.key.token,d.revision,policy.core_original_ref,policy.core_original_digest,d.state,receipt.operation_id,canonical_digest(receipt),0)
        prior=db.execute('SELECT retired FROM '+HABIT_MANAGED_TABLE+' WHERE bot=? AND persona=? AND selector_commitment=?',(*ns.as_tuple,commitment)).fetchone()
        if prior is not None:raise MissingProductionOriginalV1('Habit_Draft_selector_already_managed_or_retired_without_new_effect')
    signed=_habit_managed_signed_row_v1(ns,values,issuer);existing=db.execute('SELECT 1 FROM '+HABIT_MANAGED_TABLE+' WHERE bot=? AND persona=? AND selector_commitment=?',(*ns.as_tuple,values[0])).fetchone()
    if existing is None:db.execute('INSERT INTO '+HABIT_MANAGED_TABLE+' VALUES('+','.join('?'for _ in range(16))+')',(*ns.as_tuple,*signed))
    else:db.execute('UPDATE '+HABIT_MANAGED_TABLE+' SET '+','.join(c+'=?'for c in HABIT_MANAGED_COLUMNS[1:])+' WHERE bot=? AND persona=? AND selector_commitment=?',(*signed[1:],*ns.as_tuple,values[0]))
    return (values[0],)

def retire_habit_managed_execution_v1(db,*,namespace,selector_commitments,issuer):
    """Use the same authenticated opaque-row transformation as the real C09 writer."""
    if not db.in_transaction:raise ValueError('managed retirement belongs to the actual C09 transaction')
    from .b3_managed_metadata_v1 import metadata_columns_v1,retired_managed_metadata_row_v1
    columns=metadata_columns_v1(HABIT_MANAGED_TABLE)
    if columns!=('bot','persona',*HABIT_MANAGED_COLUMNS):raise ValueError('managed metadata exact installed columns differ')
    for selector in selector_commitments:
        row=db.execute('SELECT '+','.join(columns)+' FROM '+HABIT_MANAGED_TABLE+
            ' WHERE bot=? AND persona=? AND selector_commitment=?',(*namespace.as_tuple,selector)).fetchone()
        if row is None:raise ValueError('C09 cannot retire an unobserved managed classification')
        updated=retired_managed_metadata_row_v1(HABIT_MANAGED_TABLE,columns,tuple(row),issuer=issuer)
        assignments=','.join(name+'=?'for name in HABIT_MANAGED_COLUMNS[1:])
        db.execute('UPDATE '+HABIT_MANAGED_TABLE+' SET '+assignments+
            ' WHERE bot=? AND persona=? AND selector_commitment=?',(*updated[3:],*namespace.as_tuple,selector))

HABIT_MANAGED_STORAGE_V1={HABIT_MANAGED_TABLE:{'namespace_columns':('bot','persona'),'content_columns':(),'metadata_columns':HABIT_MANAGED_COLUMNS,'source_closure':'exact_current_adopted_policy_typed_dependencies_and_actual_selected_generation','retirement':'retain_only_namespace_keyed_selector_commitment_retired_state_signature','cold':'actual_policy_W01_receipt_history_and_complete_metadata_classification_before_ordinary'}}


def _require_habit_draft_current_facts_v1(db,*,facts,frame,selector,issuer):
    from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2,artifact_draft_file_ids_v2
    from ..authority_service.current_habit_occurrence_v1 import HabitOccurrenceCurrentV1
    current=facts.execution_current
    if type(current)is not HabitOccurrenceCurrentV1 or facts.artifact_phase_selector!=selector or type(selector)is not ArtifactDraftPhaseSelectorV2 or not selector.generation:raise ValueError('Habit Draft restriction requires its actual fixed Artifact generation and independent current facts')
    read=CurrentDomainReadV1(frame);read.check(db);atom,occurrence=_occurrence(db,read,current.request.occurrence_ref)
    _,policy=_policy(db,read,occurrence.policy_ref);d=policy.definition;qualification=current.qualification_original
    if occurrence.executor_kind!='draft_file'or occurrence.state!='qualified'or occurrence.policy_revision!=d.revision or occurrence.policy_digest!=policy.digest or occurrence.cancellation_generation!=d.cancellation_generation or qualification is None or qualification.original_ref!=occurrence.qualification_original_ref or(current.policy_original.original_ref,current.policy_original.digest)!=(policy.core_original_ref,policy.core_original_digest)or current.owner_guard!=frame.owner_guard or current.query_epoch.revision!=frame.snapshot.epochs[0].revision or frame.envelope.deadline_utc>min(current.valid_until_utc,occurrence.original_deadline_utc)or frame.now_utc>=min(current.valid_until_utc,occurrence.original_deadline_utc)or _stop(db,read,d):raise MissingProductionOriginalV1('actual_current_Habit_qualified_Draft_policy_cue_and_deadline')
    if selector.decision_ref!=d.target_ref or selector.task.namespace!=d.namespace or frame.envelope.parent_budget_lease_ref!=occurrence.parent_root_grant_ref:raise ValueError('Habit Draft cannot switch its actual selected input or original Root')
    identity=artifact_draft_file_ids_v2(selector)
    if(identity['action_operation'],identity['effect'],identity['attempt'])!=(occurrence.occurrence_operation_id,occurrence.effect_id,occurrence.attempt_id):raise MissingProductionOriginalV1('actual_unused_authorized_generation_bound_to_this_Habit_occurrence')
    from .domain_production_contracts_v1 import actual_frame_read_versions_v1
    if current.access_epoch!=frame.envelope.version_guard.access_epoch or current.delete_epoch!=frame.envelope.version_guard.delete_epoch or not set(current.read_versions)<=set(actual_frame_read_versions_v1(frame)):raise ValueError('Habit Draft extra observation lost the same current Source/Owner/read set')
    read.original(qualification.original_ref,digest=qualification.digest)
    return occurrence


def require_current_habit_artifact_generation_v1(db,*,frame,selector,issuer):
    from .current_habit_source_read_v3 import require_current_habit_artifact_frame_inputs_v3
    facts=require_current_habit_artifact_frame_inputs_v3(db,frame=frame,selector=selector,issuer=issuer)
    if facts is None:return None
    return _require_habit_draft_current_facts_v1(db,facts=facts,frame=frame,selector=selector,issuer=issuer)


def require_current_habit_prepared_artifact_v1(db,*,prepared,issuer):
    from .artifact_host_dispatch_source_v3 import require_artifact_host_prepared_restriction_v3
    return require_artifact_host_prepared_restriction_v3(db,prepared=prepared,issuer=issuer)


def current_habit_draft_plan_deadline_v1(db,*,frame,selector,deadline_utc,issuer):
    """Tighten only a newly derived actual managed plan; old originals remain immutable."""
    from .current_habit_source_read_v3 import require_current_habit_artifact_frame_inputs_v3
    from .d11_offline_originals_v1 import _utc
    from datetime import datetime,timezone
    facts=require_current_habit_artifact_frame_inputs_v3(db,frame=frame,selector=selector,issuer=issuer)
    if facts is None:return deadline_utc
    occurrence=_require_habit_draft_current_facts_v1(db,facts=facts,frame=frame,selector=selector,issuer=issuer)
    deadline=min(_utc(deadline_utc).timestamp(),occurrence.original_deadline_utc,frame.envelope.deadline_utc)
    if frame.now_utc>=deadline:raise MissingProductionOriginalV1('actual_original_Habit_Draft_new_plan_deadline')
    return datetime.fromtimestamp(deadline,timezone.utc).isoformat().replace('+00:00','Z')


def habit_operation_metadata_output_keys_v1(namespace,*,operation_kind,request,occurrence,definition,activity_id,cue=None,outcome_production_digest=None):
    """Pure fixed output locators; this does not select Source body or issue a permission."""
    from .habit_schedule_driver_v1 import habit_subscription_job_id_v1,habit_subscription_activity_id_v1
    from .d11_types import runtime_job_key
    from .d02_life_body_preparation_v1 import _refs as body_keys
    from .d11_life_preparation_v1 import life_ids_v1
    from types import SimpleNamespace
    if operation_kind in POLICY_OPERATIONS:
        if type(request)is not _REQUESTS[operation_kind]:raise TypeError('exact Habit policy command metadata required')
        d=request.definition;keys=[habit_policy_key_v1(namespace,d.policy_id)]
        if d.state=='enabled':keys.append(runtime_job_key(*namespace.as_tuple,habit_subscription_activity_id_v1(namespace,d.policy_id),habit_subscription_job_id_v1(namespace,d.policy_id,d.revision)))
        return tuple(keys)
    if operation_kind=='register_habit_occurrence_v1':
        identity=habit_occurrence_id_v1(namespace,definition.policy_id,definition.revision,cue.window_id,cue.cue_stable_key)
        miss='habit-disposition:'+canonical_digest((namespace,definition.policy_id,definition.revision,cue.window_id,cue.cue_original_ref,definition.miss_policy))[:48]
        return(habit_occurrence_key_v1(namespace,identity),AtomKey(Owner('persona',*namespace.as_tuple,namespace.persona_id),HABIT_DISPOSITION_TYPE,miss))
    if operation_kind=='record_habit_miss_v1':
        miss='habit-disposition:'+canonical_digest((namespace,definition.policy_id,definition.revision,occurrence.window_id,occurrence.cue_original_ref,definition.miss_policy))[:48]
        return(AtomKey(Owner('persona',*namespace.as_tuple,namespace.persona_id),HABIT_DISPOSITION_TYPE,miss),)
    if operation_kind=='qualify_habit_occurrence_v1':return(AtomKey.from_token(request.occurrence_ref),)
    if operation_kind=='instantiate_current_habit_source_note_context_v1':return tuple(habit_source_note_context_keys_v1(namespace,occurrence.occurrence_id,activity_id).values())
    if operation_kind=='prepare_current_habit_source_note_action_v1':
        from .d08_source_note_action_v1 import PrepareSourceNoteActionRequestV1,_keys
        pinned=definition.source_note_input
        derived=PrepareSourceNoteActionRequestV1(definition.project_ref,definition.recipe_ref,pinned.source_ref,occurrence.goal_ref,definition.target_ref,pinned.role_binding_ref)
        _,action,cancel=_keys(namespace,activity_id,occurrence.occurrence_operation_id,derived)
        return(action,cancel)
    if operation_kind=='prepare_source_note_body':return body_keys(namespace,activity_id,'d02-life-body:'+occurrence.occurrence_operation_id)
    if operation_kind=='register_current_habit_source_note_life_plan_v1':return(habit_occurrence_key_v1(namespace,occurrence.occurrence_id),)
    if operation_kind=='prepare_life':
        ids=life_ids_v1(SimpleNamespace(activity_id=occurrence.activity_id,effect_id=occurrence.effect_id,attempt_id=occurrence.attempt_id,operation_id=occurrence.occurrence_operation_id))
        return(runtime_job_key(*namespace.as_tuple,activity_id,ids['job']),habit_occurrence_key_v1(namespace,occurrence.occurrence_id))
    if operation_kind=='adopt_habit_outcome_v1':
        from ..domains.d10.habit_policy_v1 import _sha
        _sha(outcome_production_digest)
        identity='habit-outcome:'+canonical_digest((occurrence.occurrence_id,request.actual_terminal_original_ref,outcome_production_digest))[:48]
        return(AtomKey(Owner('persona',*namespace.as_tuple,namespace.persona_id),HABIT_OUTCOME_TYPE,identity),habit_occurrence_key_v1(namespace,occurrence.occurrence_id))
    if operation_kind=='record_habit_window_cue_v1':
        identity='habit-disposition:'+canonical_digest((namespace,definition.policy_id,definition.revision,cue.window_id,cue.cue_original_ref,definition.miss_policy))[:48]
        return(AtomKey.from_token(request.subscription_job_ref),AtomKey(Owner('persona',*namespace.as_tuple,namespace.persona_id),HABIT_DISPOSITION_TYPE,identity))
    raise ValueError('unknown fixed Habit metadata output recipe')


def habit_operation_metadata_original_refs_v1(namespace,*,operation_kind,occurrence,definition,request=None):
    from .d11_life_preparation_v1 import life_ids_v1
    from types import SimpleNamespace
    if operation_kind in SOURCE_NOTE_OPERATIONS or operation_kind in {'prepare_source_note_body','prepare_life'}:
        if definition.executor_kind=='source_note':
            ids=habit_source_note_life_ids_v1(namespace,occurrence.occurrence_id,definition.project_ref)
            refs=(ids['action_original_ref'],ids['body_original_ref'],ids['plan_ref'])
        else:
            from .d11_life_preparation_v1 import PrepareCurrentLifeRequestV1
            if operation_kind!='prepare_life'or type(request)is not PrepareCurrentLifeRequestV1:raise ValueError('Draft original locators come from its actual Foreground phase recipe')
            refs=(request.plan_original_ref,)
        if operation_kind=='prepare_life':
            life=life_ids_v1(SimpleNamespace(activity_id=occurrence.activity_id,effect_id=occurrence.effect_id,attempt_id=occurrence.attempt_id,operation_id=occurrence.occurrence_operation_id))
            refs=(*refs,life['prepared'],life['quote'],life['reservation'])
        return refs
    return ()
