"""Paired Self derivation from an installed standing envelope and actual C1/C02 originals."""
from dataclasses import dataclass, field
from datetime import datetime,timezone
import json,math
from ..runtime_contracts import NamespaceId,canonical_digest
from ..graph_types import AtomKey,GraphWrite,owner_grant_key
from ..memory_types import SourceRecord
from ..domains.d01.production_operations_v1 import plain_v1,stage_result_v1
from ..domains.d08.execution import Goal,GoalPredicate,GoalExecutionProvider,_decode_goal
from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1,production_read_plan_v1
from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1,DraftFileIdentityV1
from .d11_life_preparation_v1 import _read,_record,TABLE
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .c1_artifact_task_intent_v1 import read_c1_task_intent_original_v1,c1_task_intent_ref_v1
from .ingress_observation import read_committed_ingress_identity
from .budget import require_budget_family_admissible,get_budget_lease
from .artifact_task_continuation_authorization_v2 import ArtifactTaskContinuationAuthorizationV2

OPERATION="derive_ingress_artifact_task_scope_v1"
SCOPE_KIND="artifact_task_scope"
OBJECTIVE_KIND="artifact_task_objective"
OBJECTIVE_PROVIDER="d08.artifact_task_objective.v1"


def standing_artifact_policy_v1(bundle):
    from ..host.authority_profile import AdminInstallationBundle,AdminArtifactDraftPolicyV2,AdminArtifactDraftPolicyV3
    from ..host.artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4
    if type(bundle) is not AdminInstallationBundle or type(bundle.artifact_draft) not in {AdminArtifactDraftPolicyV2,AdminArtifactDraftPolicyV3,AdminArtifactDraftPairedPolicyV4}:
        raise MissingProductionOriginalV1("explicit_installed_artifact_standing_scope_v1")
    return bundle.artifact_draft.standing_scope


@dataclass(frozen=True,slots=True)
class DeriveIngressArtifactTaskScopeRequestV1:
    c02_operation_id:str
    source_ref:str
    def __post_init__(self):
        if not self.c02_operation_id or AtomKey.from_token(self.source_ref).type_name!="memory.source":
            raise ValueError("actual ordinary C02/Source selectors required")


@dataclass(frozen=True,slots=True)
class ArtifactTaskObjectiveV1:
    namespace:NamespaceId
    installation_id:str
    manifest_digest:str
    initial_c02_operation_id:str
    source_ref:str
    source_revision:int
    source_digest:str
    standing_policy_ref:str
    standing_policy_version:int
    standing_policy_digest:str
    sender_ref:str
    platform_ref:str
    root_resource_id:str
    root_identity:DraftFileIdentityV1
    filename:str
    initial_root_registration_ref:str
    goal_ref:str
    plan_ref:str
    project_ref:str
    recipe_ref:str
    created_at_utc:float
    valid_until_utc:float
    completion_rule:str="draft_then_corrected_revision"
    schema:str="d08.artifact-task-objective.v1"
    def __post_init__(self):
        if (self.schema!="d08.artifact-task-objective.v1" or self.completion_rule!="draft_then_corrected_revision"
                or type(self.namespace) is not NamespaceId or type(self.root_identity) is not DraftFileIdentityV1
                or type(self.source_revision) is not int or self.source_revision<1
                or type(self.standing_policy_version) is not int or self.standing_policy_version<1
                or not all(type(t) in (int,float) and math.isfinite(t) for t in (self.created_at_utc,self.valid_until_utc))
                or not self.created_at_utc<self.valid_until_utc):
            raise ValueError("finite prospective two-milestone objective required")
        for ref,kind in ((self.source_ref,"memory.source"),(self.goal_ref,"d08.goal.v1"),
                (self.plan_ref,"d08.personal_plan.v1"),(self.project_ref,"d10.life_project.v1"),
                (self.recipe_ref,"d10.activity_recipe.v1")):
            key=AtomKey.from_token(ref)
            if key.type_name!=kind or NamespaceId.from_key(key)!=self.namespace:
                raise ValueError("task objective crossed actual stable controls/namespace")
        from .d11_artifact_draft_contract_v1 import _filename
        _filename(self.filename)
        for value in (self.manifest_digest,self.source_digest,self.standing_policy_digest):
            if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
                raise ValueError("task objective requires exact immutable digests")


def task_objective_ref_v1(objective):
    return "artifact-task-objective:"+canonical_digest((objective.namespace,
        objective.initial_c02_operation_id,objective.initial_root_registration_ref))[:48]


def task_objective_goal_v1(objective):
    predicate=GoalPredicate("domain_state",OBJECTIVE_PROVIDER,
        (("objective_ref",task_objective_ref_v1(objective)),("objective_digest",canonical_digest(plain_v1(objective)))),
        objective.created_at_utc,objective.valid_until_utc)
    return Goal(AtomKey.from_token(objective.goal_ref).name,1,"active",predicate,(objective.source_ref,),
        (objective.initial_root_registration_ref,),None,
        ("task_cancelled","source_or_owner_revoked","task_deadline_expired"),())


@dataclass(frozen=True,slots=True)
class IngressArtifactTaskScopeOriginalV1:
    namespace:NamespaceId
    c02_operation_id:str
    source_ref:str
    source_revision:int
    source_digest:str
    c1_intent_ref:str
    c1_intent_digest:str
    standing_policy_digest:str
    root:DraftRootCapabilityV1
    task_kind:str
    objective_ref:str|None
    objective_digest:str|None
    cause_frozen_at_utc:float
    schema:str="d11.ingress-artifact-task-scope.v1"
    def __post_init__(self):
        if self.schema != "d11.ingress-artifact-task-scope.v1":
            raise ValueError("unknown legacy task scope schema")
        _validate_task_scope_fields_v1(self)


def _validate_task_scope_fields_v1(self):
        if (type(self.namespace) is not NamespaceId
                or type(self.root) is not DraftRootCapabilityV1 or self.source_ref!=self.root.source_ref
                or self.task_kind not in {"save_once","draft_then_corrected_revision","continue"}
                or (self.objective_ref is None)!=(self.objective_digest is None)
                or self.task_kind!="save_once" and self.objective_ref is None
                or self.task_kind=="save_once" and self.objective_ref is not None
                or type(self.source_revision) is not int or self.source_revision<1
                or type(self.cause_frozen_at_utc) not in (int,float) or not math.isfinite(self.cause_frozen_at_utc)):
            raise ValueError("exact finite task-to-root original required")
        for digest in (self.source_digest,self.c1_intent_digest,self.standing_policy_digest):
            if type(digest) is not str or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError("task scope original requires exact digests")


@dataclass(frozen=True,slots=True)
class IngressArtifactTaskScopeOriginalV2(IngressArtifactTaskScopeOriginalV1):
    approval_original_ref: str = field(kw_only=True)
    approval_original_digest: str = field(kw_only=True)
    schema: str = "d11.ingress-artifact-task-scope.v2"

    def __post_init__(self):
        if self.schema != "d11.ingress-artifact-task-scope.v2":
            raise ValueError("unknown approved task scope schema")
        _validate_task_scope_fields_v1(self)
        if (type(self.approval_original_ref) is not str or not self.approval_original_ref
                or type(self.approval_original_digest) is not str or len(self.approval_original_digest) != 64
                or any(c not in '0123456789abcdef' for c in self.approval_original_digest)):
            raise ValueError("task scope requires its exact genuine Owner approval")


@dataclass(frozen=True,slots=True)
class IngressArtifactTaskScopeOriginalV3(IngressArtifactTaskScopeOriginalV2):
    continuation_authorization: ArtifactTaskContinuationAuthorizationV2 = field(kw_only=True)
    schema: str = "d11.ingress-artifact-task-scope.v3"

    def __post_init__(self):
        if self.schema != "d11.ingress-artifact-task-scope.v3" or self.task_kind != "continue":
            raise ValueError("continuation scope requires its explicit new authorization generation")
        _validate_task_scope_fields_v1(self)
        if type(self.continuation_authorization) is not ArtifactTaskContinuationAuthorizationV2:
            raise ValueError("exact typed continuation authorization required")
        if (self.continuation_authorization.fresh_root_registration_ref,self.continuation_authorization.fresh_c02_operation_id) != (self.root.registration_ref,self.c02_operation_id):
            raise ValueError("continuation scope crossed its bound new Root/C02")


def task_scope_ref_v1(root_registration_ref):
    return "artifact-task-scope:"+canonical_digest(root_registration_ref)[:48]


def _decode(raw,cls):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if cls in {IngressArtifactTaskScopeOriginalV1,IngressArtifactTaskScopeOriginalV2} and type(raw) is dict and raw.get('schema') == 'd11.ingress-artifact-task-scope.v3':
        cls = IngressArtifactTaskScopeOriginalV3
    if cls is IngressArtifactTaskScopeOriginalV1 and type(raw) is dict and raw.get('schema') == 'd11.ingress-artifact-task-scope.v2':
        cls = IngressArtifactTaskScopeOriginalV2
    return decode_typed_production_value_v1(raw,cls)


def active_task_objectives_v1(db,namespace,issuer):
    rows=db.execute("SELECT o.original_ref FROM "+TABLE+" AS o JOIN graph_atoms AS g "
        "ON g.token=json_extract(o.payload_json,'$.goal_ref') AND g.bot=o.bot AND g.persona=o.persona "
        "WHERE o.bot=? AND o.persona=? AND o.kind='artifact_task_objective' "
        "AND json_extract(g.value,'$.state')='active' ORDER BY o.original_ref LIMIT 129",namespace.as_tuple).fetchall()
    if len(rows)>128:raise MissingProductionOriginalV1("complete_active_artifact_task_inventory")
    values=[]
    for (ref,) in rows:
        raw=_read(db,issuer=issuer,namespace=namespace,kind=OBJECTIVE_KIND,ref=ref)
        value=_decode(raw[0],ArtifactTaskObjectiveV1)
        if task_objective_ref_v1(value)!=ref:raise ValueError("task objective original identity changed")
        values.append(value)
    return tuple(values)


def derive_task_scope_candidate_v1(db,*,bundle,issuer,request,owner_guard,root_identity,now_utc):
    """Pure current reconstruction; only paired Authority and W01 may adopt it."""
    from .foreground_cycle_v1 import _adopted_c02_v1
    from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    if type(request) is not DeriveIngressArtifactTaskScopeRequestV1 or type(owner_guard) is not ProductionOwnerGuardV1:
        raise TypeError("exact installed Self task request/upstream guard required")
    policy=standing_artifact_policy_v1(bundle);ns=bundle.installation_policy.namespace
    from ..host.authority_profile import AdminArtifactStandingScopeV2, AdminArtifactStandingScopeV3
    approval=None
    if type(policy) in {AdminArtifactStandingScopeV2, AdminArtifactStandingScopeV3}:
        from .artifact_phase_postconditions_v1 import read_current_artifact_standing_predecision_approval_v2
        approval=read_current_artifact_standing_predecision_approval_v2(db,namespace=ns,
            bundle=bundle,issuer=issuer,owner_guard=owner_guard,now_utc=now_utc)
    intent=read_c1_task_intent_original_v1(db,namespace=ns,c02_operation_id=request.c02_operation_id,issuer=issuer)
    if (intent is None or intent.source_ref!=request.source_ref
            or (intent.installation_id,intent.manifest_digest)!=(bundle.installation_policy.installation_id,
                bundle.installation_policy.manifest_digest)):
        raise MissingProductionOriginalV1("actual_qualified_C1_task_intent_original")
    row=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (request.source_ref,*ns.as_tuple)).fetchone()
    if row is None or row[2]!=1 or row[0]!=intent.source_revision or canonical_digest(json.loads(row[1]))!=intent.source_digest:
        raise MissingProductionOriginalV1("current_unmodified_task_source")
    source=SourceRecord.from_dict(json.loads(row[1]))
    ingress=read_committed_ingress_identity(db,ns,source.source_id)
    if (ingress is None or ingress.visibility!="private" or ingress.platform_ref!=policy.platform_ref
            or ingress.sender_ref not in policy.allowed_sender_refs):
        raise MissingProductionOriginalV1("standing_scope_exact_private_sender_account")
    tool=bundle.artifact_draft.tool_scope
    from ..host.artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4, select_paired_tool_scope_v3
    if type(bundle.artifact_draft) is AdminArtifactDraftPairedPolicyV4:
        tool=select_paired_tool_scope_v3(bundle.artifact_draft,intent.intent.filename)
    if intent.intent.filename is not None and intent.intent.filename!=tool.filename:
        raise ValueError("task names a file outside the initially installed target")
    grant=issuer.current_budget_grant(db,bundle.installation_policy.root_lease.lease_id)
    lease=get_budget_lease(db,grant.lease_id);require_budget_family_admissible(db,grant.lease_id)
    if grant!=bundle.installation_policy.root_grant or lease.state!="active":
        raise MissingProductionOriginalV1("actual_original_parent_task_budget_grant")
    seal=db.execute("SELECT seal_json FROM graph_first_ingress_c02_committed_seals_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,request.c02_operation_id)).fetchone()
    _adopted_c02_v1(db,ns,request.c02_operation_id)
    if seal is None:raise MissingProductionOriginalV1("actual_original_task_C02_deadline")
    deadline=min(source.recorded_at+policy.root_window_seconds,policy.valid_until_utc,
        grant.valid_until_utc,json.loads(seal[0])["business_deadline_utc"])
    policy_digest=canonical_digest(plain_v1(policy))
    registration="draft-root-task:"+canonical_digest((ns,request,policy_digest,root_identity,owner_guard))[:48]
    active=active_task_objectives_v1(db,ns,issuer)
    matching=[obj for obj in active if (obj.root_resource_id,obj.root_identity,obj.filename)==
        (tool.resource_id,root_identity,tool.filename)]
    objective=None;kind=intent.intent.kind
    if kind=="continue":
        if len(matching)!=1:raise MissingProductionOriginalV1("unique_actual_unfinished_task_for_target")
        objective=matching[0]
        if ((objective.installation_id,objective.manifest_digest)!=(bundle.installation_policy.installation_id,bundle.installation_policy.manifest_digest)
                or objective.sender_ref!=ingress.sender_ref
                or objective.platform_ref!=ingress.platform_ref):
            raise MissingProductionOriginalV1("current_original_unexpired_task_standing_scope")
        from ..domains.d10.project_checkpoint_v1 import (project_checkpoint_key_v1,decode_project_checkpoint_type_v1,
            CHECKPOINT_TYPE,ProjectTaskWaitConditionV1)
        checkpoint_key=project_checkpoint_key_v1(ns,objective.project_ref)
        row_cp=db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",(checkpoint_key.token,*ns.as_tuple)).fetchone()
        if row_cp is None or row_cp[1]!=1:raise MissingProductionOriginalV1("actual_waiting_task_checkpoint")
        checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,json.loads(row_cp[0]))
        from .artifact_task_observer_v1 import require_task_observer_checkpoint_member_v1
        from ..graph_types import GraphAtom
        history=db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?",(checkpoint_key.token,checkpoint.revision)).fetchone()
        if history is None:raise MissingProductionOriginalV1("actual_task_wait_producer")
        original=read_adopted_domain_operation_v1(db,ns,history[0])
        require_task_observer_checkpoint_member_v1(db,namespace=ns,original=original,
            atom=GraphAtom(checkpoint_key,checkpoint.revision,json.loads(row_cp[0]),True))
        wake=checkpoint.wait_condition
        c02=_adopted_c02_v1(db,ns,request.c02_operation_id)
        if (checkpoint.state!="waiting" or type(wake) is not ProjectTaskWaitConditionV1
                or (wake.objective_ref,wake.objective_digest)!=(task_objective_ref_v1(objective),canonical_digest(plain_v1(objective)))
                or c02.commit_seq<=wake.consume_cursor):
            raise MissingProductionOriginalV1("new_message_after_actual_unfinished_task_wait")
        from .artifact_task_wait_consumer_v1 import require_unconsumed_task_wait_v1
        require_unconsumed_task_wait_v1(db,namespace=ns,objective=objective)
        if approval is None:
            if objective.standing_policy_digest!=policy_digest or now_utc>=objective.valid_until_utc:
                raise MissingProductionOriginalV1("current_original_unexpired_task_standing_scope")
            deadline=min(deadline,objective.valid_until_utc)
    elif matching:
        raise MissingProductionOriginalV1("existing_unfinished_target_requires_continuation_not_new_goal")
    elif kind=="draft_then_corrected_revision":
        if len(active)>=policy.maximum_active_tasks:
            raise MissingProductionOriginalV1("installed_active_task_capacity")
        keys=artifact_goal_plan_keys_v1(ns,c02_operation_id=request.c02_operation_id,root_registration_ref=registration)
        objective=ArtifactTaskObjectiveV1(ns,bundle.installation_policy.installation_id,bundle.installation_policy.manifest_digest,
            request.c02_operation_id,request.source_ref,row[0],intent.source_digest,
            policy.policy_ref,policy.policy_version,policy_digest,ingress.sender_ref,ingress.platform_ref,
            tool.resource_id,root_identity,tool.filename,registration,*(key.token for key in keys),
            float(source.recorded_at),float(min(source.recorded_at+policy.task_lifetime_seconds,
                policy.valid_until_utc,grant.valid_until_utc)))
    if not now_utc<deadline:raise MissingProductionOriginalV1("original_task_scope_deadline_not_renewed")
    root=DraftRootCapabilityV1(bundle.installation_policy.installation_id,bundle.installation_policy.manifest_digest,
        tool.resource_id,registration,root_identity,(tool.filename,),tool.max_file_bytes,
        datetime.fromtimestamp(deadline,timezone.utc).isoformat().replace('+00:00','Z'),request.source_ref,
        owner_guard.grant_ref,owner_guard.grant_revision,owner_guard.grant_digest)
    scope=IngressArtifactTaskScopeOriginalV1(ns,request.c02_operation_id,request.source_ref,row[0],intent.source_digest,
        c1_task_intent_ref_v1(ns,request.c02_operation_id),canonical_digest(plain_v1(intent)),policy_digest,root,kind,
        task_objective_ref_v1(objective) if objective else None,
        canonical_digest(plain_v1(objective)) if objective else None,float(source.recorded_at))
    if approval is not None:
        approved=read_adopted_domain_operation_v1(db,ns,approval.registration_operation_id)
        event=db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=1",(request.source_ref,)).fetchone()
        source_op=None if event is None else db.execute(
            "SELECT commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
            (*ns.as_tuple,event[0])).fetchone()
        c02=_adopted_c02_v1(db,ns,request.c02_operation_id)
        if (approved is None or source_op is None
                or not approved['receipt'].commit_seq < source_op[0]
                or not approved['receipt'].commit_seq < c02.commit_seq):
            raise MissingProductionOriginalV1("new_Source_C1_C02_after_actual_Owner_approval")
        scope=IngressArtifactTaskScopeOriginalV2(**{name:getattr(scope,name) for name in scope.__dataclass_fields__ if name!='schema'},
            approval_original_ref=approval.original_ref,approval_original_digest=approval.digest)
    if kind=="continue" and approval is not None:
        from .artifact_task_continuation_authorization_v2 import continuation_authorization_candidate_v2
        authorization=continuation_authorization_candidate_v2(db,objective=objective,checkpoint=checkpoint,
            checkpoint_ref=checkpoint_key.token,checkpoint_digest=canonical_digest(json.loads(row_cp[0])),
            scope=scope,approval=approval,grant=grant,tool=tool,issuer=issuer,now_utc=now_utc)
        scope=IngressArtifactTaskScopeOriginalV3(**{name:getattr(scope,name) for name in scope.__dataclass_fields__ if name!='schema'},
            continuation_authorization=authorization)
    return scope,objective


@dataclass(frozen=True,slots=True)
class InstalledIngressTaskScopeReadersV1:
    graph:object
    issuer:object
    installed_bundle:object
    issued:object


def scope_candidate_for_readers_v1(db,readers,request,now_utc):
    from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
    e=require_foreground_activity_issuance_v1(readers.issued,readers.graph,readers.issued.scope)
    if (e.request.operation_kind!=OPERATION or e.root_capability is None
            or (request.c02_operation_id,request.source_ref)!=(e.request.c02_operation_id,e.request.cue_source_ref)):
        raise ValueError("Self task scope requires the exact privately issued C02/Source/root observation")
    scope,objective=derive_task_scope_candidate_v1(db,bundle=readers.installed_bundle,issuer=readers.issuer,
        request=request,owner_guard=e.owner_guard,root_identity=e.root_capability.root_identity,now_utc=now_utc)
    if scope.root!=e.root_capability:raise ValueError("Self task scope differs from independent Authority observation")
    return scope,objective


def read_plan_ingress_artifact_task_scope_v1(db,*,namespace,request,readers,now_utc):
    scope,objective=scope_candidate_for_readers_v1(db,readers,request,now_utc)
    active=active_task_objectives_v1(db,namespace,readers.issuer)
    keys=[owner_grant_key(*namespace.as_tuple)]
    refs=[scope.c1_intent_ref]
    if type(scope) in {IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3}:
        refs.append(scope.approval_original_ref)
    for item in active:
        keys.append(AtomKey.from_token(item.goal_ref));refs.append(task_objective_ref_v1(item))
    if objective is not None:
        keys.extend(AtomKey.from_token(ref) for ref in (objective.goal_ref,objective.plan_ref))
    if scope.task_kind=="continue":
        from .artifact_task_amendment_v1 import amendment_key_v1
        keys.append(amendment_key_v1(namespace,scope.root.registration_ref))
        from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
        keys.append(project_checkpoint_key_v1(namespace,objective.project_ref))
        if type(scope) is IngressArtifactTaskScopeOriginalV3:
            authorization=scope.continuation_authorization
            refs.append(authorization.predecessor_result_ref)
            if authorization.previous_authorization_ref is not None:refs.append(authorization.previous_authorization_ref)
            from ..domains.d10.project_checkpoint_v1 import decode_project_checkpoint_type_v1,CHECKPOINT_TYPE
            cp=db.execute("SELECT value FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                (authorization.waiting_checkpoint_ref,*namespace.as_tuple)).fetchone()
            keys.extend(AtomKey.from_token(ref) for ref in decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,json.loads(cp[0])).work_version_refs)
    return production_read_plan_v1((),tuple(dict.fromkeys(keys)),(request.source_ref,),tuple(dict.fromkeys(refs)))


@dataclass(frozen=True,slots=True)
class IngressArtifactTaskScopeStageV1:
    stage:object
    goal_stage:object
    amendment_stage:object|None=None


def stage_derive_ingress_artifact_task_scope_v1(db,*,frame,request,installed_readers):
    if type(installed_readers) is not InstalledIngressTaskScopeReadersV1:
        raise TypeError("actual installed Self scope readers required")
    read=CurrentDomainReadV1(frame);read.check(db)
    scope,objective=scope_candidate_for_readers_v1(db,installed_readers,request,frame.now_utc)
    read.source_family(db,(request.source_ref,))
    read.original(scope.c1_intent_ref,kind="d11.life_c1_task_intent",digest=scope.c1_intent_digest)
    if type(scope) in {IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3}:
        read.original(scope.approval_original_ref,kind="d11.life_artifact_standing_predecision_approval",digest=scope.approval_original_digest)
    writes=()
    if scope.task_kind=="draft_then_corrected_revision":
        key=AtomKey.from_token(objective.goal_ref)
        if read.head(db,key).revision or read.head(db,objective.plan_ref).revision:
            raise ValueError("initial task cannot replace a previously adopted Goal or Plan")
        writes=(GraphWrite(key,plain_v1(task_objective_goal_v1(objective)),(AtomKey.from_token(request.source_ref),)),)
    elif objective is not None:
        from .d08_personal_plan_v1 import require_artifact_task_objective_original_v1
        atom=read.head(db,objective.goal_ref,required=True)
        require_artifact_task_objective_original_v1(db,namespace=scope.namespace,goal_ref=objective.goal_ref,
            goal=_decode_goal(atom.value),issuer=installed_readers.issuer)
    clock=tuple(o for o in frame.observed_originals if o.kind=="d11.trusted_tick")
    if len(clock)!=1:raise ValueError("task scope needs its real paired clock original")
    provider=installed_readers.graph._GraphCoordinator__providers["d10"]
    primary=stage_result_v1(frame,"d10",OPERATION,request,provenance={
        "draft_root_capability":scope.root,"artifact_task_scope":scope,
        "artifact_task_objective":objective,"cause_frozen_at_utc":scope.cause_frozen_at_utc,
        "clock_sample_digest":clock[0].original_digest},proposal_schema=provider[1],proposal_hash=provider[2])
    goals=stage_result_v1(frame,"d08",OPERATION,request,writes=writes,
        proposal_schema="d08.proposal.v1",proposal_hash=GoalExecutionProvider().descriptor.request_schema_hash)
    amendment_stage=None
    if scope.task_kind=="continue":
        from .artifact_task_amendment_v1 import amendment_from_scope_v1,amendment_key_v1
        memory_provider=installed_readers.graph._GraphCoordinator__providers["d06"]
        amendment=amendment_from_scope_v1(scope,objective)
        key=amendment_key_v1(scope.namespace,scope.root.registration_ref)
        if read.head(db,key).revision:raise ValueError("task amendment cannot replace an existing message original")
        amendment_stage=stage_result_v1(frame,"d06",OPERATION,request,
            writes=(GraphWrite(key,plain_v1(amendment),(AtomKey.from_token(scope.source_ref),)),),
            proposal_schema=memory_provider[1],proposal_hash=memory_provider[2])
    return IngressArtifactTaskScopeStageV1(primary,goals,amendment_stage)


def record_task_scope_after_commit_v1(db,*,graph,issued,frame,receipt,issuer):
    from .domain_production_contracts_v1 import ProductionOutboxStageV1
    request=DeriveIngressArtifactTaskScopeRequestV1(issued.request.c02_operation_id,issued.request.cue_source_ref)
    # The initial Goal has now been committed. Reuse the exact before-CAS candidate
    # retained in the W01 original, never rerun current active-task selection after writing it.
    original=read_adopted_domain_operation_v1(db,frame.envelope.authority.namespace,receipt.operation_id)
    if original is None or (original["domain"],original["operation_kind"])!=("d10",OPERATION):
        raise ValueError("task scope lacks the actual same-transaction W01 producer")
    p=original["payload"]["provenance"]
    scope=_decode(p["artifact_task_scope"],IngressArtifactTaskScopeOriginalV1)
    objective=None if p["artifact_task_objective"] is None else _decode(p["artifact_task_objective"],ArtifactTaskObjectiveV1)
    if (scope.root!=issued.evidence.root_capability or scope.c02_operation_id!=request.c02_operation_id
            or scope.source_ref!=request.source_ref or scope.namespace!=frame.envelope.authority.namespace):
        raise ValueError("task producer differs from its actual private scope issuance")
    values=[("draft_root_capability",scope.root.registration_ref,scope.root),
        (SCOPE_KIND,task_scope_ref_v1(scope.root.registration_ref),scope)]
    if scope.task_kind=="draft_then_corrected_revision":
        values.append((OBJECTIVE_KIND,task_objective_ref_v1(objective),objective))
    if type(scope) is IngressArtifactTaskScopeOriginalV3:
        from .artifact_task_continuation_authorization_v2 import KIND as CONTINUATION_KIND
        values.append((CONTINUATION_KIND,scope.continuation_authorization.original_ref,scope.continuation_authorization))
    if scope.task_kind=="continue":
        from .artifact_task_amendment_v1 import amendment_from_scope_v1,amendment_original_ref_v1,require_amendment_history_v1,KIND
        amendment=amendment_from_scope_v1(scope,objective)
        require_amendment_history_v1(db,value=amendment,producer=original,scope=scope,objective=objective)
        values.append((KIND,amendment_original_ref_v1(amendment),amendment))
    result=tuple(_record(db,issuer=issuer,namespace=scope.namespace,kind=kind,ref=ref,
        operation_id=receipt.operation_id,value=value) for kind,ref,value in values)
    root=result[0]
    event=ProductionOutboxStageV1(scope.namespace,receipt.operation_id,"d11","artifact_draft_root_registered",root)
    db.execute("INSERT INTO graph_domain_production_outbox_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (*scope.namespace.as_tuple,event.dedupe_key,receipt.operation_id,"d11",event.event_kind,
            root.original_ref,root.original_digest,"pending",None,None))
    if scope.task_kind=="continue":
        from .artifact_task_wait_consumer_v1 import consume_task_wait_after_scope_cas_v1
        consume_task_wait_after_scope_cas_v1(db,scope=scope,objective=objective,receipt=receipt)
        amendment_original=result[-1]
        event=ProductionOutboxStageV1(scope.namespace,receipt.operation_id,"d10","artifact_task_amendment_adopted",amendment_original)
        db.execute("INSERT INTO graph_domain_production_outbox_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (*scope.namespace.as_tuple,event.dedupe_key,receipt.operation_id,"d10",event.event_kind,
                amendment_original.original_ref,amendment_original.original_digest,"pending",None,None))
    return result


def require_task_scope_archive_v1(db,*,namespace,root,producer):
    """Passive original joins used by C09 and live responsibility reconstruction."""
    from .c09_life_originals_v1 import _read_archive_life_original_v1
    from .c1_artifact_task_intent_v1 import C1ArtifactTaskIntentOriginalV1,require_c1_task_original_history_v1
    p=producer["payload"]["provenance"]
    if ((producer["domain"],producer["operation_kind"])!=("d10",OPERATION)
            or set(p)!={"draft_root_capability","artifact_task_scope","artifact_task_objective","cause_frozen_at_utc","clock_sample_digest"}
            or p["draft_root_capability"]!=plain_v1(root)):
        raise ValueError("task root lacks its exact Self W01 variant")
    scope=_decode(p["artifact_task_scope"],IngressArtifactTaskScopeOriginalV1)
    op=producer["receipt"].operation_id
    stored=_read_archive_life_original_v1(db,namespace,SCOPE_KIND,task_scope_ref_v1(root.registration_ref))
    c1row=_read_archive_life_original_v1(db,namespace,"c1_task_intent",scope.c1_intent_ref)
    if (stored is None or stored[:2]!=(plain_v1(scope),op) or c1row is None
            or canonical_digest(c1row[0])!=scope.c1_intent_digest or scope.root!=root
            or scope.namespace!=namespace or scope.cause_frozen_at_utc!=p["cause_frozen_at_utc"]):
        raise ValueError("Self task root lost actual signed C1/task joins")
    c1=_decode(c1row[0],C1ArtifactTaskIntentOriginalV1);require_c1_task_original_history_v1(db,c1)
    if (c1.c02_operation_id,c1.source_ref,c1.source_revision,c1.source_digest,c1.intent.kind)!=(
            scope.c02_operation_id,scope.source_ref,scope.source_revision,scope.source_digest,scope.task_kind):
        raise ValueError("Self task root changed its actual original model intent")
    if type(scope) in {IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3}:
        from .artifact_phase_postconditions_v1 import (APPROVAL_KIND_V2,
            decode_artifact_phase_postcondition_original_v1, require_artifact_phase_postcondition_history_v1)
        approval_row=_read_archive_life_original_v1(db,namespace,APPROVAL_KIND_V2,scope.approval_original_ref)
        if approval_row is None or canonical_digest(approval_row[0]) != scope.approval_original_digest:
            raise ValueError("task scope lost its exact original Owner approval")
        approval=decode_artifact_phase_postcondition_original_v1(APPROVAL_KIND_V2,approval_row[0])
        require_artifact_phase_postcondition_history_v1(db,namespace=namespace,kind=APPROVAL_KIND_V2,
            original_ref=scope.approval_original_ref,producing_operation_id=approval_row[1],raw=approval_row[0])
        approved=read_adopted_domain_operation_v1(db,namespace,approval.registration_operation_id)
        source_event=db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=1",(scope.source_ref,)).fetchone()
        source_op=None if source_event is None else db.execute(
            "SELECT commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
            (*namespace.as_tuple,source_event[0])).fetchone()
        if (approved is None or source_op is None or approval.scope_digest != scope.standing_policy_digest
                or (approval.installation_id,approval.manifest_digest) != (root.installation_id,root.manifest_digest)
                or (approval.owner_guard.grant_ref,approval.owner_guard.grant_revision,approval.owner_guard.grant_digest) !=
                    (root.owner_grant_ref,root.owner_grant_revision,root.owner_grant_digest)
                or not approved['receipt'].commit_seq < source_op[0]
                or not approved['receipt'].commit_seq < c1.c02_commit_seq < producer['receipt'].commit_seq
                or not approval.approved_at_utc <= scope.cause_frozen_at_utc < approval.original_deadline_utc):
            raise ValueError("task scope cannot upgrade an older Source or borrow another approved scope")
    if scope.objective_ref is not None:
        obj=_read_archive_life_original_v1(db,namespace,OBJECTIVE_KIND,scope.objective_ref)
        if obj is None or canonical_digest(obj[0])!=scope.objective_digest or obj[0]!=p["artifact_task_objective"]:
            raise ValueError("Self task scope lost the immutable prospective objective")
        objective=_decode(obj[0],ArtifactTaskObjectiveV1)
        initial=read_adopted_domain_operation_v1(db,namespace,obj[1])
        if (task_objective_ref_v1(objective)!=scope.objective_ref or initial is None
                or (initial["domain"],initial["operation_kind"])!=("d10",OPERATION)
                or initial["payload"]["provenance"]["artifact_task_scope"]["task_kind"]!="draft_then_corrected_revision"
                or initial["payload"]["provenance"]["artifact_task_objective"]!=obj[0]):
            raise ValueError("objective lost its initial non-resurrected task producer")
        goal=task_objective_goal_v1(objective)
        history=db.execute("SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1",
            (objective.goal_ref,)).fetchone()
        if history is None or history[1:]!=(1,obj[1]) or json.loads(history[0])!=plain_v1(goal):
            raise ValueError("objective was not prospectively committed with its fixed Goal")
    if type(scope) is IngressArtifactTaskScopeOriginalV3:
        from .artifact_task_continuation_authorization_v2 import KIND as CONTINUATION_KIND, require_continuation_authorization_history_v2
        value=scope.continuation_authorization
        saved=_read_archive_life_original_v1(db,namespace,CONTINUATION_KIND,value.original_ref)
        if saved is None or saved[:2]!=(plain_v1(value),op):
            raise ValueError("continuation scope lost its actual same-CAS authorization original")
        require_continuation_authorization_history_v2(db,namespace=namespace,original_ref=value.original_ref,
            producing_operation_id=op,raw=saved[0])
    return scope
