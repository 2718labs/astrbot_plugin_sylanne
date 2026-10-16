"""Private paired-Core issuance for one exact conditioned semantic child."""
from contextlib import contextmanager
from dataclasses import dataclass,replace

from ..runtime_contracts import FenceScope,AuthorityContext,canonical_digest
from ..authority_service.conditioned_child_contract_v1 import (ConditionedChildSelectorV1,
    ConditionedChildEvidenceV1,CHILD_DOMAINS,ROOT_WORK_KIND,conditioned_child_fence_operation_id_v1)

_KEY=object()
_ACTIVE={}
_PROCESSES={}


@dataclass(frozen=True,slots=True,init=False)
class _IssuedConditionedChildV1:
    graph:object
    scope:FenceScope
    selector:ConditionedChildSelectorV1
    evidence:ConditionedChildEvidenceV1
    port:object
    digest:str

    def __init__(self,key,graph,scope,selector,evidence,port):
        if key is not _KEY:raise TypeError('conditioned child issuance belongs to the actual paired Core observer')
        for name,value in(('graph',graph),('scope',scope),('selector',selector),('evidence',evidence),
                ('port',port),('digest',canonical_digest(evidence))):object.__setattr__(self,name,value)


@contextmanager
def conditioned_child_for_fence_v1(graph,*,scope,request):
    from ..graph_coordinator import GraphCoordinator
    from ..host.v2_fence_port import V2FencePort
    if(type(graph)is not GraphCoordinator or type(scope)is not FenceScope or type(request)is not ConditionedChildSelectorV1
            or scope.operation!='write'or scope.operation_id!=conditioned_child_fence_operation_id_v1(request)
            or scope.namespace!=request.namespace or graph._GraphCoordinator__store._db.in_transaction):
        raise ValueError('conditioned child qualification requires its original fresh scope before Graph SQL')
    port=graph._GraphCoordinator__content_fence_v2
    if type(port)is not V2FencePort:raise ValueError('conditioned child paired Core port is unavailable')
    evidence,observed=port.admit_conditioned_child_for_fence_v1(scope=scope,request=request)
    if(type(evidence)is not ConditionedChildEvidenceV1 or evidence.selector!=request or observed!=scope.permit
            or evidence.current_self.permit!=scope.permit or evidence.query_epoch.revision!=scope.graph_epoch.revision
            or evidence.current_self.graph_revision!=scope.graph_revision):
        raise ValueError('conditioned child paired qualification changed its exact command, permit or Graph stamp')
    issued=_IssuedConditionedChildV1(_KEY,graph,scope,request,evidence,port)
    _ACTIVE[id(issued)]=issued
    try:yield issued
    finally:_ACTIVE.pop(id(issued),None)


def require_conditioned_child_issuance_v1(issued,graph,scope):
    if(type(issued)is not _IssuedConditionedChildV1 or _ACTIVE.get(id(issued))is not issued
            or issued.graph is not graph or issued.scope!=scope
            or issued.port is not graph._GraphCoordinator__content_fence_v2
            or issued.digest!=canonical_digest(issued.evidence)
            or issued.evidence.selector!=issued.selector or issued.evidence.current_self.permit!=scope.permit):
        raise ValueError('conditioned child lost its actual private paired-Core issuance')
    return issued.evidence


def reobserve_conditioned_child_v1(issued,graph,scope):
    evidence=require_conditioned_child_issuance_v1(issued,graph,scope)
    if graph._GraphCoordinator__store._db.in_transaction:
        raise ValueError('conditioned child current qualification RPC must precede Graph SQL')
    current,observed=issued.port.read_current_conditioned_child_for_fence_v1(scope=scope,original_request=issued.selector)
    if observed!=scope.permit or replace(current,observed_at_utc=evidence.observed_at_utc)!=evidence:
        raise ValueError('conditioned child current Owner/Self/Source/Root or producer membership changed')
    return current


@contextmanager
def conditioned_child_process_for_fence_v1(issued,graph,scope):
    evidence=require_conditioned_child_issuance_v1(issued,graph,scope);selector=issued.selector
    domain=CHILD_DOMAINS[selector.operation_kind]
    lease,ref=graph._grant_registered(actor=evidence.current_self.self_entity_ref,issuer_domain=domain,
        namespace=selector.namespace,domains=evidence.allowed_write_domains,
        activation_generation=evidence.current_self.activation_generation,operation_id=selector.operation_id)
    actual_owners=graph._GraphCoordinator__leases[lease][5]
    owners=tuple(sorted(set(evidence.allowed_owner_kinds)&actual_owners))
    if owners!=evidence.allowed_owner_kinds:
        graph._GraphCoordinator__leases.pop(lease,None)
        raise ValueError('conditioned child owner kinds exceed its actual registered process lease')
    authority=AuthorityContext(evidence.current_self.self_entity_ref,domain,ref,selector.namespace,
        owners,selector.purpose,selector.audiences,evidence.provider_policy_ref,
        evidence.current_self.activation_generation)
    _PROCESSES[id(lease)]=(issued,graph,scope,authority,lease)
    try:yield authority,lease
    finally:
        _PROCESSES.pop(id(lease),None)
        graph._GraphCoordinator__leases.pop(lease,None)


def require_conditioned_child_process_v1(issued,graph,scope,authority,lease):
    evidence=require_conditioned_child_issuance_v1(issued,graph,scope)
    if _PROCESSES.get(id(lease))!=(issued,graph,scope,authority,lease):
        raise ValueError('conditioned child process lease was not issued from its actual Core qualification')
    graph._authorize(lease,authority,frozenset(evidence.allowed_write_domains))
    return evidence
