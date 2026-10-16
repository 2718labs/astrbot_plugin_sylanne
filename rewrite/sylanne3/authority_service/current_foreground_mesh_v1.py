"""Paired Core admission for the two actual Personal eligibility WRITE stages."""
from datetime import datetime
from .contract import AuthorityUnavailable
from .foreground_mesh_contract_v1 import (
    ForegroundMeshActivityRequestV1, OwnerTaskMeshActivityRequestV1,
    ForegroundMeshActivityEvidenceV1, OwnerTaskMeshActivityEvidenceV1,
    PersonalMeshQualifiedFactsV1, personal_mesh_fence_operation_id_v1, RECIPE)
from .foreground_mesh_source_read_v3 import (
    begin_foreground_mesh_source_read_v3, require_foreground_mesh_work_v3,
    foreground_mesh_self_phase_v3, _clock_upper_v3)
from .foreground_mesh_owner_location_v3 import prepare_foreground_mesh_owner_v3, _OWNERS
from .v2_self_identity_contract import SelfIdentityCurrentRequestV1
from ..runtime_contracts import canonical_digest, QueryEpoch
from ..graph_types import AtomKey, GraphVersion
from ..runtime.domain_production_contracts_v1 import ProductionOriginalRefV1, ProductionQueryCoverageV1

def _self_in_original_work_v3(work):
    """The original Self predicates consume the completed Owner in this Work."""
    from .current_authority_graph_read_v3 import read_authority_graph_current_v3
    identity = work.service.self_identity
    request = SelfIdentityCurrentRequestV1(work.permit.authority_id, identity._fences.namespace,
        work.namespace, identity._installation_id, identity._manifest_digest,
        work.request.original.operation_id, work.permit)
    identity._core._require(work.credential,"self_identity_read",request.authority_namespace,identity._holder)
    owner = _OWNERS[work]
    owner._check_permission_v3()
    with identity._fences._frozen() as (db,deletion,execution,history):
        before = identity._read_locked(db,deletion,execution,history,work.credential,
            work.subject,request,work.mesh_location,_mesh_work=work)
    if before is None or before[1] != owner.observed.guard:
        raise AuthorityUnavailable("Personal mesh current Self or current Owner is unavailable")
    head,guard,anchor,_ = before
    with foreground_mesh_self_phase_v3(work):
        current_graph = read_authority_graph_current_v3(work,lambda db: identity._graph._check(
            db,work.namespace,anchor,identity._installation_id,guard,
            location_observation=work.mesh_location,storage_admission=owner.observed.storage_admission,
            holder=identity._holder))
    if current_graph is None:
        raise AuthorityUnavailable("Personal mesh current D01 role is unavailable")
    owner._check_permission_v3()
    with identity._fences._frozen() as (db,deletion,execution,history):
        after = identity._read_locked(db,deletion,execution,history,work.credential,
            work.subject,request,work.mesh_location,_mesh_work=work)
    if before != after:
        raise AuthorityUnavailable("Personal mesh original current Self changed during its same Work")
    return identity._current_value(request,head,guard,anchor,current_graph,owner.observed.storage_admission)

def _current_facts_in_tx_v3(work, db, original):
    from ..runtime.domain_mesh_tick_v1 import semantic_tick_key_v1
    from ..runtime.personal_candidate_eligibility_v1 import PREPARE, ADOPT, personal_eligibility_request_id_v1
    from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    require_foreground_mesh_work_v3(work)
    selected = work.request.companion
    actual_cause = read_adopted_domain_operation_v1(db,work.namespace,work.mesh_causal_operation_id)
    if (actual_cause is None or actual_cause["original_digest"] != work.mesh_causal_original.original_digest
            or actual_cause["read_versions"] != work.mesh_causal_read_versions):
        raise AuthorityUnavailable("Personal mesh causal original changed its independently observed complete readset")
    actual_id = personal_eligibility_request_id_v1(db,work.namespace,selected.command.candidates,
        prepare=work.request.original.operation_kind == PREPARE)
    if actual_id != work.request.original.operation_id:
        raise AuthorityUnavailable("Personal mesh operation is not its actual independently rebuilt Need/candidate identity")
    if work.mesh_recipe_version == 'legacy.v1':
        return None
    key = semantic_tick_key_v1(work.namespace,work.mesh_activity_id,work.mesh_causal_original.original_ref,RECIPE)
    head = work.mesh_metadata.heads.get(key.token,(0,0,None))
    expected = GraphVersion(key,head[0])
    predecessors = ()
    previous = work.mesh_previous_tick
    if previous is not None:
        prior = read_adopted_domain_operation_v1(db,work.namespace,previous.producer_operation_id)
        from ..runtime.domain_mesh_tick_v1 import validate_semantic_mesh_trace_v1
        if (prior is None or validate_semantic_mesh_trace_v1(prior['payload']['provenance']['semantic_mesh']).after_tick != previous):
            raise AuthorityUnavailable('Personal feedback predecessor has no exact actual committed tick producer')
        producer = ProductionOriginalRefV1(prior['domain']+'.current-'+prior['operation_kind'],
            prior['domain']+'-current:'+prior['original_digest'][:48],prior['original_digest'])
        predecessors = tuple(dict.fromkeys((*previous.predecessors,producer)))
    if work.request.original.operation_kind == ADOPT:
        prepare_id = personal_eligibility_request_id_v1(db,work.namespace,selected.command.candidates,prepare=True)
        prepared = read_adopted_domain_operation_v1(db,work.namespace,prepare_id)
        if (prepared is None or prepared["operation_kind"] != PREPARE
                or prepared["payload"]["request"] != plain_v1(selected.command)
                or prepared["payload"]["parent_budget"] != work.mesh_parent_budget):
            raise AuthorityUnavailable("Personal mesh adoption lost its exact actual committed preparation")
        preparation = ProductionOriginalRefV1("d08.current-"+PREPARE,
            "d08-current:"+prepared["original_digest"][:48],prepared["original_digest"])
        predecessors = tuple(dict.fromkeys((*predecessors,preparation)))
    elif work.request.original.operation_kind != PREPARE:
        raise AuthorityUnavailable("unregistered Personal mesh producer")
    versions = {AtomKey.from_token(token):row[0] for token,row in work.mesh_metadata.heads.items()}
    versions.update(work.mesh_rights.versions)
    versions.update((version.key,version.revision) for version in original.read_versions)
    versions[key] = expected.revision
    coverage = tuple(ProductionQueryCoverageV1(
        QueryEpoch(work.namespace,"namespace",work.graph_stamp[0]),name,tuple(rows),True,None)
        for name,rows in sorted(work.mesh_metadata.families.items()))
    deadline = min(work.deadline_utc,datetime.fromisoformat(original.valid_until_utc.replace("Z","+00:00")).timestamp())
    if _clock_upper_v3(work) >= deadline:
        raise AuthorityUnavailable("Personal mesh cannot renew its actual original root deadline")
    if type(work.request) is ForegroundMeshActivityRequestV1:
        budget = work.request.original.parent_budget_lease_ref
    else:
        budget = original.authorization.cause.parent_budget_lease_ref
    if budget != work.mesh_parent_budget:
        raise AuthorityUnavailable("Personal mesh changed its actual original parent budget")
    return PersonalMeshQualifiedFactsV1(work.mesh_causal_original,(key,),expected,
        tuple(GraphVersion(k,v) for k,v in sorted(versions.items(),key=lambda row:row[0].token)),
        coverage,predecessors,
        tuple(GraphVersion(k,v) for k,v in sorted(work.mesh_rights.versions.items(),key=lambda row:row[0].token)),
        canonical_digest(work.request),budget,deadline,work.handle.context.storage_generation)

def _require_foreground_reply_barrier_v1(service, request, *, permit, after=False):
    stop = service._owner_stop_reply_service_v1
    if stop is None:
        raise AuthorityUnavailable("Personal mesh foreground admission lacks its installed reply barrier")
    if not after:
        stop.require_reply_cycle_not_retired_v1(c02_operation_id=request.c02_operation_id)
        return
    from .owner_stop_reply_v1 import require_reply_scope_not_stopped_in_tx_v1
    actual = stop.observe_actual_reply_scope_v1(c02_operation_id=request.c02_operation_id)
    with stop.core._tx() as db:
        require_reply_scope_not_stopped_in_tx_v1(db,authority_namespace=service.self_identity._fences.namespace,
            installation_id=service.self_identity._installation_id,
            activation_generation=permit.generation,
            actual_cycle_identity=actual,action="foreground")

def observe_current_personal_mesh_v1(service, *, credential, subject, permit, request):
    from .current_foreground_activity_v1 import InstalledCurrentForegroundActivityV1
    from .current_owner_source_note_task_v1 import InstalledCurrentOwnerSourceNoteTaskV1
    from .current_authority_graph_read_v3 import advance_authority_graph_read_work_v3, read_authority_graph_current_v3, finish_authority_graph_read_work_v3
    types = {InstalledCurrentForegroundActivityV1: ForegroundMeshActivityRequestV1,
        InstalledCurrentOwnerSourceNoteTaskV1: OwnerTaskMeshActivityRequestV1}
    if type(request) is not types.get(type(service)):
        raise AuthorityUnavailable("Personal mesh original issuer and exact selector type differ")
    identity = service.self_identity
    original_request = request.original
    if (permit.operation != "write" or permit.operation_id != personal_mesh_fence_operation_id_v1(request)
            or original_request.namespace != identity._namespace_id
            or original_request.installation_id != identity._installation_id or subject != identity._read_subject):
        raise AuthorityUnavailable("Personal mesh changed its original installed Host WRITE identity")
    identity._fences.validate_fence(credential=credential,subject=subject,permit=permit)
    if type(request) is ForegroundMeshActivityRequestV1:
        _require_foreground_reply_barrier_v1(service,original_request,permit=permit)
    location = identity._source_location.observe_business_for_fence_v1(credential=credential,subject=subject,permit=permit)
    work = begin_foreground_mesh_source_read_v3(service,credential=credential,subject=subject,permit=permit,request=request)
    work.mesh_location = location
    try:
        while work.phase == "mesh_metadata":
            advance_authority_graph_read_work_v3(work)
        prepare_foreground_mesh_owner_v3(identity._owner_storage,work)
        current_self = _self_in_original_work_v3(work)
        while work.phase != "validate":
            advance_authority_graph_read_work_v3(work)
        def current(db):
            original = service._read_current_graph_v3(db,credential=credential,subject=subject,permit=permit,
                request=original_request,current_self=current_self,current_owner=_OWNERS[work].observed,
                location=location,now=_clock_upper_v3(work))
            if type(request) is ForegroundMeshActivityRequestV1:
                original = original[0]
            facts = _current_facts_in_tx_v3(work,db,original)
            return original,facts
        original,facts = read_authority_graph_current_v3(work,current)
        from .foreground_mesh_contract_v1 import PersonalMeshJobMetadataV1
        job = work.mesh_metadata.job_key
        head = work.mesh_metadata.heads[job.token]
        job_metadata = PersonalMeshJobMetadataV1(work.namespace,job.token,head[0],work.mesh_job_work_kind,
            work.mesh_job_continuation_schema,work.mesh_recipe_version,work.mesh_operator_versions_digest)
        if identity._source_location._pointer(location.context) != location.control_operation_id:
            raise AuthorityUnavailable("Personal mesh current storage pointer changed before issuance")
        if _self_in_original_work_v3(work) != current_self:
            raise AuthorityUnavailable("Personal mesh current Self changed before issuing its paired evidence")
        identity._fences.validate_fence(credential=credential,subject=subject,permit=permit)
        if type(request) is ForegroundMeshActivityRequestV1:
            _require_foreground_reply_barrier_v1(service,original_request,permit=permit,after=True)
            return ForegroundMeshActivityEvidenceV1(request,original,facts,job_metadata),permit
        return OwnerTaskMeshActivityEvidenceV1(request,original,facts,job_metadata),permit
    finally:
        finish_authority_graph_read_work_v3(work)

_MESH_RPC_TYPES = {
    "foreground_mesh_activity_admit_v1": ForegroundMeshActivityRequestV1,
    "foreground_mesh_activity_current_v1": ForegroundMeshActivityRequestV1,
    "owner_task_mesh_activity_admit_v1": OwnerTaskMeshActivityRequestV1,
    "owner_task_mesh_activity_current_v1": OwnerTaskMeshActivityRequestV1,
}

def dispatch_personal_mesh_rpc_v1(server, method, command, *, credential, subject, profile_id, manifest_digest):
    from .v2_contract import FencePermitV2, from_wire, to_wire
    from .foreground_mesh_contract_v1 import personal_mesh_from_wire_v1, personal_mesh_to_wire_v1
    from .contract import identifier
    if method not in _MESH_RPC_TYPES or set(command) != {"namespace","permit","request"}:
        raise AuthorityUnavailable("Personal mesh RPC has no exact registered command")
    namespace = identifier(command["namespace"],"namespace")
    server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    expected = _MESH_RPC_TYPES[method]
    registry = server._v2_foreground_activity if expected is ForegroundMeshActivityRequestV1 else server._v2_owner_source_note_tasks
    service = registry.get(namespace)
    if service is None or server._self_identity_readers_v2.get(namespace) != (credential.certificate_sha256,profile_id):
        raise AuthorityUnavailable("Personal mesh actual installed Self reader differs")
    request = personal_mesh_from_wire_v1(command["request"],expected)
    permit = from_wire(command["permit"])
    if (type(permit) is not FencePermitV2 or permit.operation != "write"
            or permit.subject != subject or permit.namespace != namespace
            or server._namespace_bindings_v2.get((credential.certificate_sha256,profile_id,request.original.namespace)) != namespace):
        raise AuthorityUnavailable("Personal mesh actual paired Host namespace or original WRITE permit differs")
    evidence,observed = service.current_mesh_v1(credential=credential,subject=subject,permit=permit,request=request)
    return {"evidence":personal_mesh_to_wire_v1(evidence),"permit":to_wire(observed)}
