"""Private installed Habit activity issuance on a new exact current WRITE permit."""
from contextlib import contextmanager
from dataclasses import dataclass,replace
from ..runtime_contracts import FenceScope,canonical_digest
from ..authority_service.current_habit_occurrence_v1 import HabitOccurrenceCurrentV1,current_habit_fence_operation_id_v1
from ..authority_service.d10_habit_contract_v1 import HabitWindowCueSelectorV1,HabitOccurrenceBirthSelectorV1
from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceSelectorV1
from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1

_KEY=object()
_ACTIVE={}
def habit_activity_domains_v1(operation_kind):
    return {"record_habit_window_cue_v1":("d03","d05","d06","d07","d08","d10","d11"),
        "register_habit_occurrence_v1":("d03","d05","d06","d07","d08","d10","d11"),
        "qualify_habit_occurrence_v1":("d03","d05","d06","d07","d08","d10","d11"),
        "instantiate_current_habit_source_note_context_v1":("d03","d05","d06","d07","d08","d10","d11"),
        "prepare_current_habit_source_note_action_v1":("d02","d03","d05","d06","d07","d08","d10","d11"),
        "prepare_source_note_body":("d02","d03","d05","d06","d07","d08","d10","d11"),
        "register_current_habit_source_note_life_plan_v1":("d02","d03","d05","d06","d07","d08","d10","d11"),
        "prepare_life":("d02","d03","d05","d06","d07","d08","d10","d11")}[operation_kind]

def habit_activity_operation_kind_v1(selector):
    if type(selector)is HabitOccurrenceExecutionSelectorV1:return selector.operation_kind
    if type(selector)is HabitWindowCueSelectorV1:return"record_habit_window_cue_v1"
    if type(selector)is HabitOccurrenceBirthSelectorV1:return"register_habit_occurrence_v1"
    if type(selector)is HabitOccurrenceSelectorV1:return"qualify_habit_occurrence_v1"
    raise TypeError("one installed closed Habit activity selector required")

def habit_typed_command_digest_v1(operation,request):
    from .domain_production_registry_v1 import installed_operation_v1
    if(installed_operation_v1(operation.operation_kind)!=operation or type(request)is not operation.request_type
            or(operation.domain,operation.operation_kind)not in{("d11","record_habit_window_cue_v1"),
                ("d10","register_habit_occurrence_v1"),("d10","qualify_habit_occurrence_v1"),
                ("d08","instantiate_current_habit_source_note_context_v1"),("d08","prepare_current_habit_source_note_action_v1"),
                ("d02","prepare_source_note_body"),("d10","register_current_habit_source_note_life_plan_v1"),("d10","prepare_life")}):
        raise TypeError("Habit command must be one exact registered bookkeeping request")
    return canonical_digest(("sylanne.habit-typed-command.v1",operation.domain,operation.operation_kind,request))

@dataclass(frozen=True,slots=True,init=False)
class _IssuedHabitActivityV1:
    graph:object
    port:object
    scope:FenceScope
    evidence:HabitOccurrenceCurrentV1
    operation:object
    command:object
    digest:str
    def __init__(self,key,graph,port,scope,evidence,operation,command):
        if key is not _KEY:raise TypeError("Habit issuance requires its actual installed paired stage")
        for name,value in(("graph",graph),("port",port),("scope",scope),("evidence",evidence),
                ("operation",operation),("command",command),("digest",canonical_digest(evidence))):
            object.__setattr__(self,name,value)

@contextmanager
def habit_activity_for_fence_v1(graph,*,scope,request,operation,command):
    from ..graph_coordinator import GraphCoordinator
    from ..host.current_habit_occurrence_port_v1 import InstalledCurrentHabitOccurrencePortV1
    if(type(graph)is not GraphCoordinator or type(scope)is not FenceScope or scope.operation!="write"
            or scope.operation_id!=current_habit_fence_operation_id_v1(request)
            or operation.operation_kind!=habit_activity_operation_kind_v1(request)
            or request.request_digest!=habit_typed_command_digest_v1(operation,command)):
        raise ValueError("Habit activity requires exact installed Graph/new WRITE scope/typed command")
    port=graph._GraphCoordinator__habit_occurrence_port_v1
    if type(port)is not InstalledCurrentHabitOccurrencePortV1 or port.graph is not graph:
        raise ValueError("Habit activity actual installed port absent")
    if type(request)is HabitOccurrenceExecutionSelectorV1:
        evidence,permit=port.observe_current_habit_execution_for_fence_v1(scope=scope,request=request)
    elif type(request)is HabitWindowCueSelectorV1:
        evidence,permit=port.observe_habit_window_cue_for_fence_v1(scope=scope,request=request)
    elif type(request)is HabitOccurrenceBirthSelectorV1:
        evidence,permit=port.admit_habit_occurrence_registration_for_fence_v1(scope=scope,request=request)
    else:evidence,permit=port.qualify_habit_occurrence_for_fence_v1(scope=scope,request=request)
    if(type(evidence)is not HabitOccurrenceCurrentV1 or evidence.request!=request or permit!=scope.permit
            or evidence.current_self.permit!=permit or evidence.query_epoch.revision!=scope.graph_epoch.revision
            or evidence.current_self.graph_revision!=scope.graph_revision):
        raise ValueError("Habit paired result changed actual request/permit/Self/Graph stamp")
    issued=_IssuedHabitActivityV1(_KEY,graph,port,scope,evidence,operation,command)
    _ACTIVE[id(issued)]=issued
    try:yield issued
    finally:
        _ACTIVE.pop(id(issued),None);port.release_scope_v3(scope)

def require_habit_activity_issuance_v1(issued,graph,scope):
    if(type(issued)is not _IssuedHabitActivityV1 or _ACTIVE.get(id(issued))is not issued
            or issued.graph is not graph or issued.scope is not scope or issued.digest!=canonical_digest(issued.evidence)
            or issued.evidence.request.request_digest!=habit_typed_command_digest_v1(issued.operation,issued.command)
            or issued.operation.operation_kind!=habit_activity_operation_kind_v1(issued.evidence.request)):
        raise ValueError("Habit private sameScope issuance ended or changed its fixed command")
    return issued.port.require_issued_activity_v3(scope=scope,request=issued.evidence.request,evidence=issued.evidence)

def reobserve_habit_activity_v1(issued,graph,scope):
    evidence=require_habit_activity_issuance_v1(issued,graph,scope)
    if graph._GraphCoordinator__store._db.in_transaction:raise ValueError("Habit actual current observation must precede SQL")
    if type(evidence.request)is HabitOccurrenceExecutionSelectorV1:
        current,permit=issued.port.observe_current_habit_execution_for_fence_v1(scope=scope,request=evidence.request)
    elif type(evidence.request)is HabitWindowCueSelectorV1:
        current,permit=issued.port.read_current_habit_window_cue_for_fence_v1(scope=scope,original_request=evidence.request)
    elif type(evidence.request)is HabitOccurrenceSelectorV1:
        current,permit=issued.port.read_current_habit_occurrence_for_fence_v1(scope=scope,original_request=evidence.request)
    else:
        # Birth has no future ledger original; repeat its exact current empty-slot qualification.
        current,permit=issued.port.admit_habit_occurrence_registration_for_fence_v1(scope=scope,request=evidence.request)
    if permit!=scope.permit or replace(current,observed_at_utc=evidence.observed_at_utc)!=evidence:
        raise ValueError("Habit actual current Owner/Self/Source/Root/job facts changed")
    return current


def habit_activity_request_digest_v1(request):
    if type(request)not in{HabitWindowCueSelectorV1,HabitOccurrenceBirthSelectorV1,HabitOccurrenceSelectorV1,HabitOccurrenceExecutionSelectorV1}:
        raise TypeError('one exact closed Habit activity selector required')
    return canonical_digest(request)

def habit_activity_finish_digest_v1(issued,graph,scope):
    evidence=require_habit_activity_issuance_v1(issued,graph,scope)
    return 'sha256:'+canonical_digest({'schema':'w01.habit-domain-write.v1',
        'operation_id':evidence.request.operation_id,'request_digest':habit_activity_request_digest_v1(evidence.request),
        'permit_token':scope.permit.token})
