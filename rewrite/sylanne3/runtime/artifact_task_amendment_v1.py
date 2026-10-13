"""Ordinary message task amendment, distinct from a factual Source correction."""
from dataclasses import dataclass
import json
from ..graph_types import AtomKey,Owner,TypeSpec,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest,schema_hash
from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1,DraftFileReadbackV1
from .domain_production_contracts_v1 import ProductionOwnerGuardV1
from ..domains.d01.production_operations_v1 import plain_v1
from .d01_production_operations_v1 import MissingProductionOriginalV1

KIND="artifact_task_amendment"
TYPE="d06.artifact_task_amendment.v1"

@dataclass(frozen=True,slots=True)
class ArtifactTaskAmendmentV1:
    namespace:NamespaceId
    root_registration_ref:str
    task_scope_ref:str
    task_scope_digest:str
    objective_ref:str
    objective_digest:str
    c1_intent_ref:str
    c1_intent_digest:str
    c02_operation_id:str
    source_ref:str
    source_revision:int
    source_digest:str
    goal_ref:str
    project_ref:str
    filename:str
    schema:str=TYPE
    def __post_init__(self):
        if (self.schema!=TYPE or type(self.namespace) is not NamespaceId
                or type(self.source_revision) is not int or self.source_revision<1):
            raise ValueError("exact ordinary task amendment required")
        for ref,kind in ((self.source_ref,"memory.source"),(self.goal_ref,"d08.goal.v1"),
                (self.project_ref,"d10.life_project.v1")):
            key=AtomKey.from_token(ref)
            if key.type_name!=kind or NamespaceId.from_key(key)!=self.namespace:
                raise ValueError("task amendment crossed namespace or control type")
        for digest in (self.task_scope_digest,self.objective_digest,self.c1_intent_digest,self.source_digest):
            if type(digest) is not str or len(digest)!=64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("task amendment lost original digest")
        from .d11_artifact_draft_contract_v1 import _filename
        _filename(self.filename)

def amendment_key_v1(namespace,root_registration_ref):
    return AtomKey(Owner("activity",*namespace.as_tuple,"artifact-task:"+canonical_digest(root_registration_ref)[:40]),
        TYPE,"amendment")

def amendment_original_ref_v1(value):
    return "artifact-task-amendment:"+canonical_digest((value.namespace,value.root_registration_ref))[:48]

def amendment_from_scope_v1(scope,objective):
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1,task_objective_ref_v1
    if (scope.task_kind!="continue" or objective is None
            or scope.namespace!=objective.namespace or scope.objective_ref!=task_objective_ref_v1(objective)
            or scope.objective_digest!=canonical_digest(plain_v1(objective))
            or scope.source_ref==objective.source_ref):
        raise ValueError("amendment needs a new ordinary message for the exact unfinished objective")
    return ArtifactTaskAmendmentV1(scope.namespace,scope.root.registration_ref,
        task_scope_ref_v1(scope.root.registration_ref),canonical_digest(plain_v1(scope)),
        scope.objective_ref,scope.objective_digest,scope.c1_intent_ref,scope.c1_intent_digest,
        scope.c02_operation_id,scope.source_ref,scope.source_revision,scope.source_digest,
        objective.goal_ref,objective.project_ref,objective.filename)

def decode_amendment_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw,ArtifactTaskAmendmentV1)

def amendment_type_spec_v1():
    return TypeSpec(TYPE,("activity",),"state",decode_amendment_v1,immutable=True,writer_domain="d06",
        schema_hash=schema_hash({"type":TYPE,"fields":tuple(ArtifactTaskAmendmentV1.__dataclass_fields__)}))

def require_amendment_history_v1(db,*,value,producer,scope,objective):
    """Join the same actual CAS and immutable graph member; no execution grant."""
    if value!=amendment_from_scope_v1(scope,objective):
        raise ValueError("task amendment changed its original C1/C02/scope/objective")
    key=amendment_key_v1(value.namespace,value.root_registration_ref)
    row=db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=1",(key.token,)).fetchone()
    writes=tuple(w for w in producer["payload"]["writes"] if w["key"]==key.token)
    if (row is None or row[0]!=producer["receipt"].operation_id or row[2]!=1
            or json.loads(row[1])!=plain_v1(value) or len(writes)!=1 or writes[0]["value"]!=plain_v1(value)
            or GraphVersion(key,1) not in producer["receipt"].write_versions):
        raise ValueError("task amendment was not adopted in its actual Self task CAS")
    return value

def read_current_amendment_v1(db,*,namespace,root_registration_ref,issuer):
    from .d11_life_preparation_v1 import _read
    from .ingress_artifact_task_scope_v1 import (SCOPE_KIND,task_scope_ref_v1,IngressArtifactTaskScopeOriginalV1,
        ArtifactTaskObjectiveV1,require_task_scope_archive_v1,_decode)
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    scope_row=_read(db,issuer=issuer,namespace=namespace,kind=SCOPE_KIND,ref=task_scope_ref_v1(root_registration_ref))
    if scope_row is None:return None
    scope=_decode(scope_row[0],IngressArtifactTaskScopeOriginalV1)
    if scope.task_kind!="continue":return None
    producer=read_adopted_domain_operation_v1(db,namespace,scope_row[1])
    if producer is None:raise MissingProductionOriginalV1("actual_task_amendment_scope_producer")
    require_task_scope_archive_v1(db,namespace=namespace,root=scope.root,producer=producer)
    objective=_decode(producer["payload"]["provenance"]["artifact_task_objective"],ArtifactTaskObjectiveV1)
    value=amendment_from_scope_v1(scope,objective);ref=amendment_original_ref_v1(value)
    original=_read(db,issuer=issuer,namespace=namespace,kind=KIND,ref=ref)
    key=amendment_key_v1(namespace,root_registration_ref)
    head=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",(key.token,*namespace.as_tuple)).fetchone()
    if (original is None or original!=(plain_v1(value),scope_row[1]) or head is None
            or head[0]!=1 or head[2]!=1 or json.loads(head[1])!=plain_v1(value)):
        raise MissingProductionOriginalV1("current_original_task_amendment_head")
    require_amendment_history_v1(db,value=value,producer=producer,scope=scope,objective=objective)
    return value,ref,key


@dataclass(frozen=True,slots=True)
class ArtifactTaskAmendmentBasisV1:
    task:ArtifactDraftTaskSelectorV1
    objective_ref:str
    objective_digest:str
    initial_extent_ref:str
    initial_extent_digest:str
    amendment_original_ref:str
    amendment_original_digest:str
    amendment_head:GraphVersion
    task_scope_ref:str
    task_scope_digest:str
    c1_intent_ref:str
    c1_intent_digest:str
    amendment_source_head:GraphVersion
    amendment_source_digest:str
    previous_milestone_ref:str
    previous_milestone_digest:str
    previous_settlement_operation_id:str
    previous_settlement_original_digest:str
    previous_content_head:GraphVersion
    previous_content_digest:str
    previous_verified_original_ref:str
    previous_verified_original_digest:str
    previous_readback:DraftFileReadbackV1
    plan_revision_operation_id:str
    plan_revision_original_digest:str
    goal_head:GraphVersion
    goal_digest:str
    plan_head:GraphVersion
    plan_digest:str
    root:DraftRootCapabilityV1
    root_digest:str
    owner_guard:ProductionOwnerGuardV1
    original_deadline_utc:float
    schema:str='d08.artifact-task-amendment-basis.v1'

    @property
    def namespace(self):return self.task.namespace
    @property
    def digest(self):return canonical_digest(plain_v1(self))
    @property
    def original_ref(self):return 'artifact-task-amendment-basis:'+self.digest[:48]

    def __post_init__(self):
        import math
        if (self.schema!='d08.artifact-task-amendment-basis.v1' or type(self.task) is not ArtifactDraftTaskSelectorV1
                or type(self.root) is not DraftRootCapabilityV1 or type(self.previous_readback) is not DraftFileReadbackV1
                or type(self.owner_guard) is not ProductionOwnerGuardV1
                or type(self.original_deadline_utc) not in (int,float) or not math.isfinite(self.original_deadline_utc)):
            raise ValueError('exact closed ordinary amendment basis required')
        for name,kind in (('amendment_head',TYPE),('amendment_source_head','memory.source'),
                ('previous_content_head','memory.source'),('goal_head','d08.goal.v1'),('plan_head','d08.personal_plan.v1')):
            head=getattr(self,name)
            if type(head) is not GraphVersion or head.revision<1 or head.key.type_name!=kind or NamespaceId.from_key(head.key)!=self.namespace:
                raise ValueError('amendment basis crossed an exact positive source or control head')
        for name in self.__dataclass_fields__:
            if name.endswith('digest'):
                digest=getattr(self,name)
                if type(digest) is not str or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
                    raise ValueError('amendment basis lost a complete original digest')
        if (self.root.registration_ref!=self.task.root_registration_ref or self.root.source_ref!=self.amendment_source_head.key.token
                or canonical_digest(plain_v1(self.root))!=self.root_digest
                or (self.root.owner_grant_ref,self.root.owner_grant_revision,self.root.owner_grant_digest)!=
                    (self.owner_guard.grant_ref,self.owner_guard.grant_revision,self.owner_guard.grant_digest)):
            raise ValueError('amendment basis lost its actual new Root/Source/Owner')


def decode_artifact_task_amendment_basis_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw,ArtifactTaskAmendmentBasisV1)


def readonly_current_artifact_task_amendment_basis_v1(db,*,namespace,task,issuer,bundle,owner_guard,now_utc,
        parent_budget_lease_ref,actor_ref,purpose,audiences,access_epoch,delete_epoch):
    from .d08_personal_plan_v1 import artifact_task_plan_revision_operation_id_v2,require_artifact_task_plan_revision_original_v2
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .artifact_task_observer_v1 import read_current_artifact_task_milestone_v2
    from .d11_artifact_draft_content_v1 import require_artifact_method_settlement_history_v2,read_current_artifact_phase_verified_v2
    from .d11_artifact_draft_model_v1 import read_artifact_phase_selected_history_v2
    from .artifact_task_text_extent_v1 import KIND as EXTENT_KIND,ArtifactTaskTextExtentOriginalV1,require_artifact_task_text_extent_history_v1
    from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV2,ArtifactTaskObjectiveV1,_decode,task_scope_ref_v1
    from .d11_life_preparation_v1 import _read
    from .c1_artifact_task_intent_v1 import read_c1_task_intent_original_v1
    from .artifact_phase_postconditions_v1 import readonly_current_task_predecision_facts_v2,_standing_source_family_sql_v2
    from .d11_offline_originals_v1 import _utc
    from .d11_types import job_graph_write
    from .jobs import get_job
    from .budget import get_budget_lease,require_budget_family_admissible
    from .issuers import D11BudgetJobIssuer
    if not db.in_transaction or type(task) is not ArtifactDraftTaskSelectorV1 or task.namespace!=namespace or type(issuer) is not D11BudgetJobIssuer:
        raise TypeError('actual amended task basis requires its installed issuer and SQL snapshot')
    actual=read_current_amendment_v1(db,namespace=namespace,root_registration_ref=task.root_registration_ref,issuer=issuer)
    if actual is None:raise MissingProductionOriginalV1('actual_ordinary_user_amendment_before_second_extent')
    amendment,amendment_ref,amendment_key=actual
    if amendment.c02_operation_id!=task.c02_operation_id:raise ValueError('amendment basis changed current task C02')
    scope_row=_read(db,issuer=issuer,namespace=namespace,kind='artifact_task_scope',ref=task_scope_ref_v1(task.root_registration_ref))
    scope=_decode(scope_row[0],IngressArtifactTaskScopeOriginalV2)
    if scope.task_kind!='continue':raise ValueError('amended basis requires its actual continued TaskScope')
    approval=readonly_current_task_predecision_facts_v2(db,namespace=namespace,task=task,
        operation='input:register_artifact_task_text_extent',method_ref=None,actor_ref=actor_ref,bundle=bundle,
        issuer=issuer,owner_guard=owner_guard,now_utc=now_utc,purpose=purpose,audiences=audiences,
        access_epoch=access_epoch,delete_epoch=delete_epoch)
    revision=read_adopted_domain_operation_v1(db,namespace,artifact_task_plan_revision_operation_id_v2(task))
    plan,checkpoint=require_artifact_task_plan_revision_original_v2(db,namespace=namespace,original=revision)
    provenance=revision['payload']['provenance']
    if (provenance['amendment_original_ref'],provenance['amendment_original_digest'],provenance['task_scope_ref'],provenance['task_scope_digest'])!=(
            amendment_ref,canonical_digest(plain_v1(amendment)),amendment.task_scope_ref,amendment.task_scope_digest):
        raise ValueError('amended basis lost its exact same-W01 Plan revision')
    previous=read_current_artifact_task_milestone_v2(db,namespace=namespace,original_ref=provenance['previous_milestone_ref'],issuer=issuer)
    settled=read_adopted_domain_operation_v1(db,namespace,provenance['previous_settlement_operation_id'])
    completion=require_artifact_method_settlement_history_v2(db,namespace=namespace,original=settled,raw=settled['payload']['provenance']['artifact_method_completion'])
    objective_row=_read(db,issuer=issuer,namespace=namespace,kind='artifact_task_objective',ref=amendment.objective_ref)
    objective=_decode(objective_row[0],ArtifactTaskObjectiveV1)
    _,chosen,_=read_artifact_phase_selected_history_v2(db,selector=previous.selector,issuer=issuer)
    extent_row=_read(db,issuer=issuer,namespace=namespace,kind=EXTENT_KIND,ref=chosen.binding.extent_original_ref)
    initial_extent=require_artifact_task_text_extent_history_v1(db,namespace=namespace,original_ref=chosen.binding.extent_original_ref,
        producing_operation_id=extent_row[1],raw=extent_row[0])
    if (type(initial_extent) is not ArtifactTaskTextExtentOriginalV1 or initial_extent.objective_ref!=amendment.objective_ref
            or canonical_digest(extent_row[0])!=chosen.binding.extent_original_digest or previous.semantic_index!=1
            or completion.state!='partial' or completion.milestone_original_ref!=previous.original_ref
            or settled['original_digest']!=provenance['previous_settlement_original_digest']
            or previous.digest!=provenance['previous_milestone_digest']
            or (plan.goal_ref,objective.goal_ref,previous.goal_ref)!=(amendment.goal_ref,amendment.goal_ref,amendment.goal_ref)
            or checkpoint.project_ref!=objective.project_ref or objective.project_ref!=amendment.project_ref
            or (scope.root.resource_id,scope.root.root_identity,amendment.filename)!=(objective.root_resource_id,objective.root_identity,objective.filename)
            or previous.readback.filename!=objective.filename):
        raise ValueError('amendment basis crossed initial rule, partial milestone or stable file identity')
    def current(ref):
        key=AtomKey.from_token(ref);row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',(*namespace.as_tuple,ref)).fetchone()
        if row is None or row[2]!=1:raise MissingProductionOriginalV1('current_amended_basis_'+key.type_name)
        return GraphVersion(key,row[0]),json.loads(row[1])
    plan_head,plan_value=current(objective.plan_ref);goal_head,goal_value=current(objective.goal_ref)
    if plan_value!=plain_v1(plan) or plan_head.revision!=plan.revision or plan.goal_revision!=goal_head.revision or goal_value['state']!='active':
        raise MissingProductionOriginalV1('actual_current_fixed_revised_Plan_and_active_Goal')
    intent=read_c1_task_intent_original_v1(db,namespace=namespace,c02_operation_id=task.c02_operation_id,issuer=issuer)
    if (intent is None or intent.intent.kind!='continue' or (intent.source_ref,intent.source_revision,intent.source_digest)!=(
            amendment.source_ref,amendment.source_revision,amendment.source_digest)
            or canonical_digest(plain_v1(intent))!=amendment.c1_intent_digest):
        raise MissingProductionOriginalV1('actual_paid_new_C1_for_same_ordinary_amendment')
    for source_ref in dict.fromkeys((initial_extent.task_source_head.key.token,amendment.source_ref,previous.source_head.key.token)):
        _standing_source_family_sql_v2(db,namespace=namespace,source_ref=source_ref,purpose=purpose,audiences=audiences,
            access_epoch=access_epoch,delete_epoch=delete_epoch)
    new_head,new_value=current(amendment.source_ref);old_rule_head,old_rule_value=current(initial_extent.task_source_head.key.token)
    if ((new_head.revision,canonical_digest(new_value))!=(amendment.source_revision,amendment.source_digest)
            or (old_rule_head,canonical_digest(old_rule_value))!=(initial_extent.task_source_head,initial_extent.task_source_digest)):
        raise MissingProductionOriginalV1('actual_unchanged_initial_rule_and_new_amendment_Source')
    verified_ref,verified_digest=previous.ordered_phase_originals[-1]
    verified=read_current_artifact_phase_verified_v2(db,namespace=namespace,selector=previous.selector,issuer=issuer)
    if (verified.original_ref,verified.digest,verified.source_head,verified.source_value_digest,verified.readback)!=(
            verified_ref,verified_digest,previous.source_head,previous.source_value_digest,previous.readback):
        raise ValueError('amended basis lost exact previous full method verified file')
    cycle=get_job(db,AtomKey.from_token(task.cycle_job_ref).name);_,cycle_value=current(task.cycle_job_ref)
    if cycle.budget_ref!=parent_budget_lease_ref or cycle_value!=job_graph_write(cycle).value:
        raise ValueError('amended basis changed actual cycle or parent budget')
    require_budget_family_admissible(db,parent_budget_lease_ref);lease=get_budget_lease(db,parent_budget_lease_ref)
    # Completed predecessor effects remain passive history, not a new cycle execution window.
    from .artifact_task_continuation_authorization_v2 import resolve_artifact_task_authorization_deadline_v2
    authorization_deadline=resolve_artifact_task_authorization_deadline_v2(db,namespace=namespace,scope=scope,
        objective=objective,issuer=issuer,bundle=bundle,owner_guard=owner_guard,now_utc=now_utc,
        parent_budget_lease_ref=parent_budget_lease_ref)
    from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV3
    if type(scope) is not IngressArtifactTaskScopeOriginalV3 and previous.owner_guard!=owner_guard:
        raise MissingProductionOriginalV1("original_amendment_Owner_without_new_generation")
    deadlines=[authorization_deadline,approval.original_deadline_utc,
        _utc(scope.root.valid_until_utc).timestamp(),_utc(cycle.deadline_utc).timestamp()]
    ancestor=lease
    while True:
        deadlines.append(issuer.current_budget_grant(db,ancestor.lease_id).valid_until_utc)
        if ancestor.parent_id is None:break
        ancestor=get_budget_lease(db,ancestor.parent_id)
    limit=min(deadlines)
    if lease.state!='active' or now_utc>=limit:raise MissingProductionOriginalV1('remaining_original_amended_task_deadline_without_renewal')
    return ArtifactTaskAmendmentBasisV1(task,amendment.objective_ref,amendment.objective_digest,
        chosen.binding.extent_original_ref,chosen.binding.extent_original_digest,amendment_ref,canonical_digest(plain_v1(amendment)),
        GraphVersion(amendment_key,1),amendment.task_scope_ref,amendment.task_scope_digest,amendment.c1_intent_ref,
        amendment.c1_intent_digest,new_head,canonical_digest(new_value),previous.original_ref,previous.digest,
        settled['receipt'].operation_id,settled['original_digest'],previous.source_head,previous.source_value_digest,
        verified_ref,verified_digest,previous.readback,revision['receipt'].operation_id,revision['original_digest'],
        goal_head,canonical_digest(goal_value),plan_head,canonical_digest(plan_value),scope.root,canonical_digest(plain_v1(scope.root)),owner_guard,limit)
