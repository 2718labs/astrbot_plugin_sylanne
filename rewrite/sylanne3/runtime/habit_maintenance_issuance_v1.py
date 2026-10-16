"""Private installed Habit maintenance observation; no execution grant is issued."""
from contextlib import contextmanager
from dataclasses import dataclass,replace
from ..runtime_contracts import FenceScope,canonical_digest
from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1,HabitOriginalMaintenanceCurrentV1

_KEY=object()
_ACTIVE={}

def habit_maintenance_typed_command_digest_v1(operation,command):
    from .domain_production_registry_v1 import installed_operation_v1
    if(installed_operation_v1(operation.operation_kind)!=operation or type(command)is not operation.request_type
            or(operation.domain,operation.operation_kind)not in{('d10','record_habit_miss_v1'),('d10','adopt_habit_outcome_v1')}):
        raise TypeError('Habit maintenance requires one of its two actual installed typed commands')
    return canonical_digest(('sylanne.habit-maintenance-typed-command.v1',operation.domain,operation.operation_kind,command))

@dataclass(frozen=True,slots=True,init=False)
class _IssuedHabitMaintenanceV1:
    graph:object
    port:object
    scope:FenceScope
    request:HabitOriginalMaintenanceSelectorV1
    evidence:HabitOriginalMaintenanceCurrentV1
    operation:object
    command:object
    digest:str
    def __init__(self,key,graph,port,scope,request,evidence,operation,command):
        if key is not _KEY:raise TypeError('Habit maintenance issuance requires its actual installed paired observation')
        for name,value in(('graph',graph),('port',port),('scope',scope),('request',request),('evidence',evidence),
                ('operation',operation),('command',command),('digest',canonical_digest(evidence))):object.__setattr__(self,name,value)

@contextmanager
def habit_maintenance_for_fence_v1(graph,*,scope,request,operation,command):
    from ..graph_coordinator import GraphCoordinator
    from ..host.current_habit_occurrence_port_v1 import InstalledCurrentHabitOccurrencePortV1
    if(type(graph)is not GraphCoordinator or type(scope)is not FenceScope or scope.operation!='write'
            or type(request)is not HabitOriginalMaintenanceSelectorV1 or scope.operation_id!=request.operation_id
            or operation.operation_kind!=request.operation_kind or command!=request.command
            or request.request_digest!=habit_maintenance_typed_command_digest_v1(operation,command)):
        raise ValueError('Habit maintenance requires its actual Graph/fresh control Scope and exact installed command')
    port=graph._GraphCoordinator__habit_occurrence_port_v1
    if type(port)is not InstalledCurrentHabitOccurrencePortV1 or port.graph is not graph:raise ValueError('Habit maintenance actual installed port absent')
    evidence,permit=port.observe_current_habit_maintenance_for_fence_v1(scope=scope,request=request)
    if(type(evidence)is not HabitOriginalMaintenanceCurrentV1 or evidence.request!=request or permit!=scope.permit
            or evidence.permit!=permit or evidence.query_epoch.revision!=scope.graph_epoch.revision
            or evidence.current_self.graph_revision!=scope.graph_revision):raise ValueError('Habit maintenance paired current facts differ from actual control Scope')
    issued=_IssuedHabitMaintenanceV1(_KEY,graph,port,scope,request,evidence,operation,command);_ACTIVE[id(issued)]=issued
    try:yield issued
    finally:_ACTIVE.pop(id(issued),None);port.release_scope_v3(scope)

def require_habit_maintenance_issuance_v1(issued,graph,scope):
    if(type(issued)is not _IssuedHabitMaintenanceV1 or _ACTIVE.get(id(issued))is not issued
            or issued.graph is not graph or issued.scope is not scope or issued.request!=issued.evidence.request
            or issued.digest!=canonical_digest(issued.evidence)or issued.command!=issued.request.command
            or issued.request.request_digest!=habit_maintenance_typed_command_digest_v1(issued.operation,issued.command)):
        raise ValueError('Habit maintenance private sameScope observation ended or changed')
    return issued.port.require_issued_maintenance_v1(scope=scope,request=issued.request,evidence=issued.evidence)

def reobserve_habit_maintenance_v1(issued,graph,scope):
    evidence=require_habit_maintenance_issuance_v1(issued,graph,scope)
    if graph._GraphCoordinator__store._db.in_transaction:raise ValueError('Habit maintenance current observation must precede Graph SQL')
    current,permit=issued.port.observe_current_habit_maintenance_for_fence_v1(scope=scope,request=issued.request)
    if permit!=scope.permit or replace(current,observed_at_utc=evidence.observed_at_utc)!=evidence:
        raise ValueError('Habit maintenance actual Owner/Self/Source/occurrence/terminal facts changed')
    return current

def habit_maintenance_request_digest_v1(request):
    if type(request)is not HabitOriginalMaintenanceSelectorV1:raise TypeError('exact Habit maintenance selector required')
    return canonical_digest(request)

def habit_maintenance_finish_digest_v1(issued,graph,scope):
    evidence=require_habit_maintenance_issuance_v1(issued,graph,scope)
    return 'sha256:'+canonical_digest({'schema':'w01.habit-maintenance-write.v1',
        'operation_id':evidence.request.operation_id,'request_digest':habit_maintenance_request_digest_v1(evidence.request),
        'permit_token':scope.permit.token})
