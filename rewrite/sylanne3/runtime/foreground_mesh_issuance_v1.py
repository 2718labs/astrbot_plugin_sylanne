"""Private paired Personal mesh issuance; original issuer handles stay distinct."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from ..runtime_contracts import FenceScope, canonical_digest
from ..authority_service.foreground_mesh_contract_v1 import (
    ForegroundMeshActivityRequestV1, OwnerTaskMeshActivityRequestV1,
    ForegroundMeshActivityEvidenceV1, OwnerTaskMeshActivityEvidenceV1,
    personal_mesh_fence_operation_id_v1)
from .domain_mesh_contract_v1 import PersonalMeshStageReadsetCompositionV1

_KEY = object()
_ACTIVE = {}
_BOUND = ContextVar("sylanne_personal_mesh_issued_v1", default=None)

@dataclass(frozen=True, slots=True, init=False, eq=False)
class _IssuedForegroundMeshActivityV1:
    graph: object
    port: object
    scope: FenceScope
    request: ForegroundMeshActivityRequestV1
    evidence: ForegroundMeshActivityEvidenceV1
    original_issued: object
    digest: str

    def __init__(self,key,graph,port,scope,request,evidence,original_issued):
        if key is not _KEY:
            raise TypeError("Personal Foreground mesh issuance requires its exact paired observer")
        for name,value in (("graph",graph),("port",port),("scope",scope),("request",request),
                ("evidence",evidence),("original_issued",original_issued),("digest",canonical_digest(evidence))):
            object.__setattr__(self,name,value)

@dataclass(frozen=True, slots=True, init=False, eq=False)
class _IssuedOwnerTaskMeshActivityV1:
    graph: object
    port: object
    scope: FenceScope
    request: OwnerTaskMeshActivityRequestV1
    evidence: OwnerTaskMeshActivityEvidenceV1
    original_issued: object
    digest: str

    def __init__(self,key,graph,port,scope,request,evidence,original_issued):
        if key is not _KEY:
            raise TypeError("Personal OwnerTask mesh issuance requires its exact paired observer")
        for name,value in (("graph",graph),("port",port),("scope",scope),("request",request),
                ("evidence",evidence),("original_issued",original_issued),("digest",canonical_digest(evidence))):
            object.__setattr__(self,name,value)

@contextmanager
def personal_mesh_activity_for_fence_v1(graph, *, scope, request):
    from ..graph_coordinator import GraphCoordinator
    from ..host.v2_fence_port import V2FencePort
    from . import foreground_activity_issuance_v1 as foreground
    from . import owner_source_note_task_issuance_v1 as owner_task
    if (type(graph) is not GraphCoordinator or type(scope) is not FenceScope
            or type(request) not in (ForegroundMeshActivityRequestV1,OwnerTaskMeshActivityRequestV1)
            or scope.operation != "write" or scope.operation_id != personal_mesh_fence_operation_id_v1(request)
            or graph._GraphCoordinator__store._db.in_transaction):
        raise TypeError("Personal mesh issuance requires its actual original WRITE outside Graph SQL")
    port = graph._GraphCoordinator__content_fence_v2
    if type(port) is not V2FencePort or _BOUND.get() is not None:
        raise ValueError("Personal mesh requires one original paired issuer lifetime")
    if type(request) is ForegroundMeshActivityRequestV1:
        evidence,permit = port.admit_foreground_mesh_activity_for_fence_v1(scope=scope,request=request)
        expected = ForegroundMeshActivityEvidenceV1
        module = foreground
    else:
        evidence,permit = port.admit_owner_task_mesh_activity_for_fence_v1(scope=scope,request=request)
        expected = OwnerTaskMeshActivityEvidenceV1
        module = owner_task
    if (type(evidence) is not expected or evidence.request != request or permit != scope.permit
            or evidence.original.current_self.permit != scope.permit
            or evidence.original.query_epoch.revision != scope.graph_epoch.revision
            or evidence.original.current_self.graph_revision != scope.graph_revision):
        raise ValueError("Personal mesh paired evidence changed its exact original request, scope or current snapshot")
    if len(module._ACTIVE) >= 8:
        raise ValueError("Personal mesh original issued-handle slots are occupied")
    if module is foreground:
        inner = foreground._IssuedForegroundActivityV1(foreground._KEY,graph,port,scope,request.original,evidence.original)
        outer = _IssuedForegroundMeshActivityV1(_KEY,graph,port,scope,request,evidence,inner)
    else:
        inner = owner_task._IssuedOwnerSourceNoteTaskV1(owner_task._KEY,graph,scope,evidence.original,None)
        outer = _IssuedOwnerTaskMeshActivityV1(_KEY,graph,port,scope,request,evidence,inner)
    module._ACTIVE[id(inner)] = inner
    _ACTIVE[id(inner)] = outer
    token = _BOUND.set(outer)
    try:
        yield inner
    finally:
        _BOUND.reset(token)
        _ACTIVE.pop(id(inner),None)
        module._ACTIVE.pop(id(inner),None)

def require_personal_mesh_issuance_v1(inner,graph,scope):
    from . import foreground_activity_issuance_v1 as foreground
    from . import owner_source_note_task_issuance_v1 as owner_task
    outer = _ACTIVE.get(id(inner))
    if (type(outer) not in (_IssuedForegroundMeshActivityV1,_IssuedOwnerTaskMeshActivityV1)
            or outer.original_issued is not inner or outer.graph is not graph or outer.scope != scope
            or outer.port is not graph._GraphCoordinator__content_fence_v2
            or outer.digest != canonical_digest(outer.evidence) or _BOUND.get() is not outer):
        raise ValueError("Personal mesh requires the active outer and original inner issued handles")
    if type(outer) is _IssuedForegroundMeshActivityV1:
        original = foreground.require_foreground_activity_issuance_v1(inner,graph,scope)
        if type(outer.request) is not ForegroundMeshActivityRequestV1:
            raise ValueError("Foreground mesh cannot borrow an OwnerTask selector")
    else:
        original = owner_task.require_owner_source_note_task_issuance_v1(inner,graph,scope)
        if type(outer.request) is not OwnerTaskMeshActivityRequestV1:
            raise ValueError("OwnerTask mesh cannot borrow a Foreground selector")
    if original != outer.evidence.original or original.request != outer.request.original:
        raise ValueError("Personal mesh original independently issued evidence changed")
    return outer

def reobserve_personal_mesh_activity_v1(inner,graph,scope):
    outer = require_personal_mesh_issuance_v1(inner,graph,scope)
    if graph._GraphCoordinator__store._db.in_transaction:
        raise ValueError("Personal mesh reobservation must precede Graph SQL")
    if type(outer) is _IssuedForegroundMeshActivityV1:
        current,permit = outer.port.read_current_foreground_mesh_activity_for_fence_v1(scope=scope,original_request=outer.request)
    else:
        current,permit = outer.port.read_current_owner_task_mesh_activity_for_fence_v1(scope=scope,original_request=outer.request)
        current = replace(current,original=replace(current.original,observed_at_utc=outer.evidence.original.observed_at_utc))
    if current != outer.evidence or permit != scope.permit:
        raise ValueError("Personal mesh current Core qualification or original current proof changed")
    return current.original

def personal_mesh_composition_for_frame_v1(frame):
    outer = _BOUND.get()
    if outer is None:
        return None
    require_personal_mesh_issuance_v1(outer.original_issued,outer.graph,outer.scope)
    facts = outer.evidence.mesh
    if facts is None:
        return None
    original = outer.evidence.original
    versions = dict((v.key,v.revision) for v in frame.snapshot.versions)
    coverage = {row.type_id:row for row in frame.query_coverage}
    if (frame.envelope.identity.operation_id != outer.request.original.operation_id
            or frame.envelope.identity.activity_id != facts.expected_tick.key.owner.subject
            or frame.envelope.parent_budget_lease_ref != facts.parent_budget_lease_ref
            or frame.envelope.deadline_utc > facts.original_deadline_utc
            or frame.owner_guard != original.owner_guard
            or frame.envelope.authority.purpose != "consolidation"
            or any(versions.get(v.key) != v.revision for v in facts.read_versions)
            or any(coverage.get(row.type_id) != row for row in facts.query_coverage)):
        raise ValueError("Personal mesh Core qualification is not an exact covered subset of the actual Host frame")
    return PersonalMeshStageReadsetCompositionV1(facts.selector_commitment,facts.core_qualification_readset_digest,
        canonical_digest((frame.snapshot.versions,frame.query_coverage)),facts.tick_keys,facts.expected_tick,
        facts.read_versions,facts.query_coverage,facts.source_closure)

def current_personal_mesh_facts_v1(frame):
    composition = personal_mesh_composition_for_frame_v1(frame)
    if composition is None:
        return None
    return _BOUND.get().evidence.mesh

def is_personal_mesh_issuance_v1(inner):
    return _ACTIVE.get(id(inner)) is not None

def augment_personal_mesh_plan_v1(graph, issued, plan):
    if not is_personal_mesh_issuance_v1(issued):
        return plan
    outer = require_personal_mesh_issuance_v1(issued,graph,issued.scope)
    from dataclasses import replace
    facts = outer.evidence.mesh
    if facts is None:
        return plan
    return replace(plan,exact_keys=tuple(sorted(set((*plan.exact_keys,*facts.tick_keys)),key=lambda key:key.token)),
        required_original_refs=tuple(sorted(set((*plan.required_original_refs,facts.causal_original.original_ref,
            *(original.original_ref for original in facts.predecessors))))))
