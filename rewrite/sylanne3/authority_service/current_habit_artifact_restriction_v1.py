"""An additional Habit restriction on one actual existing Foreground Draft WRITE."""
from dataclasses import dataclass,fields
from .contract import AuthorityUnavailable
from .current_foreground_activity_v1 import (ForegroundActivityRequestV1,ForegroundActivityEvidenceV1,
    InstalledCurrentForegroundActivityV1,foreground_fence_operation_id_v1)
from .d10_habit_contract_v1 import _sha_v1
from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceSelectorV1,habit_value_from_wire_v1
from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId

HABIT_ARTIFACT_ADDITIONAL_KINDS_V1=frozenset(('propose_artifact_draft_phase_action_v2',
    'prepare_artifact_draft_body','input:register_artifact_phase_draft_plan_v2','prepare_life'))
_FOREGROUND_OBSERVATIONS={}

@dataclass(frozen=True,slots=True)
class HabitArtifactAdditionalSelectorV1:
    namespace:NamespaceId
    qualification_selector:HabitOccurrenceSelectorV1
    qualification_original_ref:str
    qualification_original_digest:str
    occurrence_ref:str
    expected_occurrence_revision:int
    foreground_request:ForegroundActivityRequestV1
    artifact_phase_selector:ArtifactDraftPhaseSelectorV2
    schema:str='d10.habit-artifact-additional-selector.v1'
    def __post_init__(self):
        _validate_artifact_restriction_selector_v3(self,schema='d10.habit-artifact-additional-selector.v1',
            kinds=HABIT_ARTIFACT_ADDITIONAL_KINDS_V1)
    @property
    def operation_id(self):return self.foreground_request.operation_id
    @property
    def operation_kind(self):return self.foreground_request.operation_kind
    @property
    def request_digest(self):return self.foreground_request.request_digest
    @property
    def original_deadline_utc(self):return self.qualification_selector.original_deadline_utc


def _validate_artifact_restriction_selector_v3(self,*,schema,kinds):
    foreground=self.foreground_request;phase=self.artifact_phase_selector
    if(self.schema!=schema or type(self.namespace)is not NamespaceId
            or type(self.qualification_selector)is not HabitOccurrenceSelectorV1 or self.qualification_selector.executor_kind!='draft_file'
            or type(foreground)is not ForegroundActivityRequestV1 or foreground.operation_kind not in kinds
            or foreground.namespace!=self.namespace or self.qualification_selector.namespace!=self.namespace
            or type(phase)is not ArtifactDraftPhaseSelectorV2 or not phase.generation or phase.task.namespace!=self.namespace
            or foreground.purpose!='consolidation' or foreground.plan_ref!=phase.plan_ref
            or(foreground.c02_operation_id,foreground.cycle_job_ref,foreground.draft_root_registration_ref)!=(
                phase.task.c02_operation_id,phase.task.cycle_job_ref,phase.task.root_registration_ref)
            or type(self.expected_occurrence_revision)is not int or self.expected_occurrence_revision<1):
        raise ValueError('Habit Draft restriction must retain its exact real Foreground request and approved generation')
    key=AtomKey.from_token(self.occurrence_ref)
    if key.type_name!='d10.habit_occurrence.v1'or NamespaceId.from_key(key)!=self.namespace:
        raise ValueError('Habit Draft extra occurrence crossed namespace/type')
    _sha_v1(self.qualification_original_digest)


HABIT_ARTIFACT_MODEL_READ_KINDS_V3=frozenset(('prepare_artifact_draft_model_v2','acquire_artifact_draft_model_v2'))

@dataclass(frozen=True,slots=True)
class HabitArtifactModelReadSelectorV3(HabitArtifactAdditionalSelectorV1):
    schema:str='d10.habit-artifact-model-read-selector.v3'
    def __post_init__(self):
        _validate_artifact_restriction_selector_v3(self,schema='d10.habit-artifact-model-read-selector.v3',
            kinds=HABIT_ARTIFACT_MODEL_READ_KINDS_V3)


def habit_artifact_model_read_to_wire_v3(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(value)is not HabitArtifactModelReadSelectorV3:raise TypeError('exact closed additional Draft selector required')
    return plain_v1(value)


def habit_artifact_model_read_from_wire_v3(raw):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitArtifactModelReadSelectorV3)}:
        raise ValueError('Habit Draft additional selector fields differ')
    value=HabitArtifactModelReadSelectorV3(**{**raw,'namespace':NamespaceId(**raw['namespace']),
        'qualification_selector':habit_value_from_wire_v1('d10.habit-occurrence-selector.v1',raw['qualification_selector']),
        'foreground_request':decode_typed_production_value_v1(raw['foreground_request'],ForegroundActivityRequestV1),
        'artifact_phase_selector':decode_typed_production_value_v1(raw['artifact_phase_selector'],ArtifactDraftPhaseSelectorV2)})
    if habit_artifact_model_read_to_wire_v3(value)!=raw:raise ValueError('Habit Draft extra selector canonical fields differ')
    return value


def habit_artifact_additional_to_wire_v1(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(value)is not HabitArtifactAdditionalSelectorV1:raise TypeError('exact closed additional Draft selector required')
    return plain_v1(value)


def habit_artifact_additional_from_wire_v1(raw):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitArtifactAdditionalSelectorV1)}:
        raise ValueError('Habit Draft additional selector fields differ')
    value=HabitArtifactAdditionalSelectorV1(**{**raw,'namespace':NamespaceId(**raw['namespace']),
        'qualification_selector':habit_value_from_wire_v1('d10.habit-occurrence-selector.v1',raw['qualification_selector']),
        'foreground_request':decode_typed_production_value_v1(raw['foreground_request'],ForegroundActivityRequestV1),
        'artifact_phase_selector':decode_typed_production_value_v1(raw['artifact_phase_selector'],ArtifactDraftPhaseSelectorV2)})
    if habit_artifact_additional_to_wire_v1(value)!=raw:raise ValueError('Habit Draft extra selector canonical fields differ')
    return value


def require_habit_foreground_observation_v1(service,permit,request):
    saved=_FOREGROUND_OBSERVATIONS.get(id(request))
    if(saved is None or saved[0]is not request or saved[1]is not service or saved[2]!=permit
            or type(saved[3])is not ForegroundActivityEvidenceV1 or saved[3].request!=request.foreground_request
            or saved[3].current_self.permit!=permit):
        raise AuthorityUnavailable('Habit Draft extra read lacks this actual same-call Foreground reconstruction')
    return saved[3]


def _current_habit_artifact_restriction_v3(service,*,foreground_service,credential,subject,permit,request,selector_type):
    from .current_habit_occurrence_v1 import InstalledCurrentHabitOccurrenceV1
    from .current_habit_execution_v1 import _old_qualification_v1,_producer_v1
    from .habit_authority_source_read_v3 import require_habit_no_other_obligation_v1
    from ..domains.d10.habit_occurrence_v1 import habit_occurrence_id_v1,habit_occurrence_key_v1,habit_value_from_wire_v1
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v2
    from ..runtime.foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from ..runtime.foreground_call_plan_v1 import ForegroundCallPlanV2
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..runtime.d11_offline_originals_v1 import _utc
    from ..runtime_contracts import canonical_digest
    if(selector_type not in {HabitArtifactAdditionalSelectorV1,HabitArtifactModelReadSelectorV3}
            or type(service)is not InstalledCurrentHabitOccurrenceV1 or type(request)is not selector_type
            or type(foreground_service)is not InstalledCurrentForegroundActivityV1
            or foreground_service.self_identity is not service.self_identity or foreground_service.issuer is not service.issuer
            or foreground_service.installed_bundle is not service.installed_bundle
            or permit.operation!='write'or permit.operation_id!=foreground_fence_operation_id_v1(request.foreground_request)):
        raise AuthorityUnavailable('Habit Draft extra observer needs the actual original Foreground installation and WRITE')
    foreground,observed=foreground_service.current(credential=credential,subject=subject,permit=permit,request=request.foreground_request)
    if type(foreground)is not ForegroundActivityEvidenceV1 or foreground.request!=request.foreground_request or observed!=permit:
        raise AuthorityUnavailable('Habit Draft actual Foreground reconstruction differs')
    if id(request)in _FOREGROUND_OBSERVATIONS:raise AuthorityUnavailable('Habit Draft extra call already has a live upstream observation')
    _FOREGROUND_OBSERVATIONS[id(request)]=(request,service,permit,foreground)
    inputs=None
    try:
        policy,inputs=service._prepare_v1(credential=credential,subject=subject,permit=permit,request=request,require_write=False)
        definition=policy.definition;selection=request.qualification_selector;phase=request.artifact_phase_selector;fg=request.foreground_request
        key=AtomKey.from_token(request.occurrence_ref);atom=inputs.bodies[key]
        occurrence=habit_value_from_wire_v1('d10.habit_occurrence.v1',atom.value)
        identity=habit_occurrence_id_v1(definition.namespace,definition.policy_id,definition.revision,selection.window_id,selection.cue_stable_key)
        ids=artifact_draft_file_ids_v2(phase)
        if(definition.executor_kind!='draft_file'or atom.revision!=request.expected_occurrence_revision
                or key!=habit_occurrence_key_v1(definition.namespace,identity)or occurrence.state!='qualified'
                or occurrence.actual_started_at_utc is not None or phase.decision_ref!=definition.target_ref
                or(occurrence.occurrence_operation_id,occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id)!=(
                    ids['action_operation'],ids['activity_id'],ids['effect'],ids['attempt'])
                or(selection.execution_operation_id,selection.activity_id,selection.effect_id,selection.attempt_id)!=(
                    occurrence.occurrence_operation_id,occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id)
                or fg.parent_budget_lease_ref!=occurrence.parent_root_grant_ref or fg.audiences!=definition.audience):
            raise AuthorityUnavailable('Habit Draft extra observation changed actual original generation/effect/Root/deadline')
        qualification=_old_qualification_v1(service,permit,subject,request,policy)
        if(qualification.original_ref!=occurrence.qualification_original_ref
                or(qualification.target_commitment,qualification.project_commitment)!=(policy.target_commitment,policy.project_commitment)):
            raise AuthorityUnavailable('Habit Draft extra observation lost the actual independent old qualification')
        _,original=_producer_v1(inputs,selection.operation_id,'qualify_habit_occurrence_v1')
        if original['provenance']['core_qualification']!=plain_v1(qualification):
            raise AuthorityUnavailable('Habit Draft original qualification has no actual positive Graph W01')
        actual_job=inputs.bodies[AtomKey.from_token(fg.cycle_job_ref)]
        from .habit_authority_source_read_v3 import _run_column_v3,_fixed_row_v3
        from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
        job_key=AtomKey.from_token(fg.cycle_job_ref)
        metadata=_fixed_row_v3(inputs.work,"runtime_jobs",("bot_id","persona_id"),"job_id=?",(job_key.name,))
        if metadata!=fg.namespace.as_tuple:raise AuthorityUnavailable("Habit extra Foreground durable job crossed namespace")
        column=DispatchOriginalJSONReadV3(inputs.work,table="runtime_jobs",column="continuation_json",key_columns=("job_id",),key=(job_key.name,))
        actual_continuation=_run_column_v3(inputs.work,column)
        if canonical_digest(actual_continuation)!=actual_job.value["continuation_digest"]:
            raise AuthorityUnavailable("Habit extra Foreground SQL continuation differs from actual current job mirror")
        continuation=foreground_cycle_from_wire_v1(actual_continuation)
        if(type(continuation.call_plan)is not ForegroundCallPlanV2 or continuation.call_plan.phase_group.selector!=phase):
            raise AuthorityUnavailable('Habit Draft extra selector differs from actual current Foreground cycle phase group')
        for ref,revision,digest in((phase.decision_ref,phase.decision_revision,phase.decision_digest),(phase.plan_ref,phase.plan_revision,phase.plan_digest)):
            current=inputs.bodies[AtomKey.from_token(ref)]
            if(current.revision,canonical_digest(current.value))!=(revision,digest):
                raise AuthorityUnavailable('Habit Draft adopted Decision/Plan changed before this actual phase')
        if(inputs.current_self!=foreground.current_self or inputs.owner_entry.head.guard.authorization_head!=foreground.current_self.owner_authorization_head
                or inputs.work.graph_stamp!=(foreground.query_epoch.revision,foreground.access_epoch,foreground.delete_epoch)):
            raise AuthorityUnavailable('Habit and Foreground extra observation lost same current Owner/Self/Graph/rights stamp')
        require_habit_no_other_obligation_v1(inputs,occurrence_key=key,context=False)
        reading=service.clock();now=reading.utc_seconds+reading.utc_error_seconds
        if now>=min(occurrence.original_deadline_utc,_utc(foreground.valid_until_utc).timestamp()):
            raise AuthorityUnavailable('Habit extra Draft original window or Foreground deadline expired')
        census=tuple((other,value)for other,(_,_,value)in inputs.census.items()if value["policy_ref"]==selection.policy_ref)
        counted=tuple(other for other,value in census if value["window_id"]==occurrence.window_id)
        if len(counted)>definition.maximum_occurrences_per_window or key not in counted:
            raise AuthorityUnavailable("Habit extra Draft lost complete cross-revision current window census")
        times=tuple(value["actual_started_at_utc"]if value["actual_started_at_utc"]is not None else value["admitted_at_utc"]
            for other,value in census if other!=key and(value["actual_started_at_utc"]is not None or value["admitted_at_utc"]is not None))
        if times and now-max(times)<definition.minimum_interval_seconds:
            raise AuthorityUnavailable("Habit extra Draft current minimum interval is not ready")
        service._require_cue_v1(inputs,policy,selection,now)
        inputs.require_for_v3(service=service,permit=permit)
        from dataclasses import replace
        evidence=service._evidence_v1(request,policy,inputs,qualification=qualification,now=now)
        return replace(evidence,valid_until_utc=min(evidence.valid_until_utc,_utc(foreground.valid_until_utc).timestamp())),permit
    finally:
        if inputs is not None:inputs.release_v3()
        _FOREGROUND_OBSERVATIONS.pop(id(request),None)

def current_habit_artifact_restriction_v1(service,*,foreground_service,credential,subject,permit,request):
    return _current_habit_artifact_restriction_v3(service,foreground_service=foreground_service,
        credential=credential,subject=subject,permit=permit,request=request,selector_type=HabitArtifactAdditionalSelectorV1)


def current_habit_artifact_model_read_restriction_v3(service,*,foreground_service,credential,subject,permit,request):
    return _current_habit_artifact_restriction_v3(service,foreground_service=foreground_service,
        credential=credential,subject=subject,permit=permit,request=request,selector_type=HabitArtifactModelReadSelectorV3)

