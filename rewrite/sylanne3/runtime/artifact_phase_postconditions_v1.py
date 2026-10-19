"""Pre-committed, signed artifact policy/contract and independent actual assessment."""
from dataclasses import dataclass, fields, field
import hashlib
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..graph_types import AtomKey, GraphVersion, owner_grant_key
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1, ArtifactDraftPhaseSelectorV2, artifact_draft_phase_sequence_v2
from .domain_production_contracts_v1 import ProductionOwnerGuardV1
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d11_life_preparation_v1 import _read, _record
from .d11_artifact_draft_contract_v1 import DraftFileReadbackV1

POLICY_KIND='artifact_phase_postcondition_policy'
CONTRACT_KIND='artifact_phase_postcondition_contract'
ASSESSMENT_KIND='artifact_phase_assessment'
POLICY_OPERATION='input:register_artifact_phase_postcondition_policy_v1'
CONTRACT_OPERATION='register_artifact_phase_postcondition_contract_v1'
ASSESSMENT_OPERATION='observe_artifact_phase_postconditions_v1'
STATUSES=frozenset({'satisfied','violated','unknown','conflicting'})


def _digest(value):
    if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('postcondition requires a complete original digest')


def _text(value):
    if type(value) is not str or not value or len(value.encode())>4096:
        raise ValueError('postcondition requires a bounded selector or actual literal')








@dataclass(frozen=True,slots=True)
class ArtifactPhaseConditionV1:
    condition_id: str
    kind: str
    phase_kind: str
    minimum: int | None=None
    maximum: int | None=None
    literals: tuple[str,...]=()
    observer_id: str | None=None
    observer_version: int | None=None
    observer_asset_digest: str | None=None
    evidence_start: int | None=None
    evidence_end: int | None=None

    def __post_init__(self):
        _text(self.condition_id)
        if self.kind not in {'length','literal','sections','tone','task_semantics'} or self.phase_kind not in {'sample_check','check'}:
            raise ValueError('postcondition is outside the registered finite rule vocabulary')
        if self.kind=='length':
            if type(self.minimum) is not int or type(self.maximum) is not int or not 1<=self.minimum<=self.maximum<=65536:
                raise ValueError('postcondition length has no registered exact range')
        elif self.minimum is not None or self.maximum is not None:raise ValueError('semantic conditions cannot borrow a length threshold')
        if type(self.literals) is not tuple or len(self.literals)>16 or self.kind in {'literal','sections'} and not self.literals:
            raise ValueError('explicit literals and sections require actual bounded task evidence')
        for literal in self.literals:_text(literal)
        if (self.observer_id is None)!=(self.observer_version is None) or (self.observer_id is None)!=(self.observer_asset_digest is None):
            raise ValueError('observer identity/version/asset commitment must be one complete original')
        if self.observer_id is not None:
            _text(self.observer_id);_digest(self.observer_asset_digest)
            if type(self.observer_version) is not int or self.observer_version<1:raise ValueError('observer version differs')
        if (self.evidence_start is None)!=(self.evidence_end is None):raise ValueError('task evidence positions must be paired')


@dataclass(frozen=True,slots=True)
class RegisterArtifactPhasePostconditionPolicyRequestV1:
    task: ArtifactDraftTaskSelectorV1
    goal_ref: str
    plan_ref: str
    method_ref: str
    extent_original_ref: str
    observer_policy_ref: str | None=None

    def __post_init__(self):
        if type(self.task) is not ArtifactDraftTaskSelectorV1:raise TypeError('policy registration requires exact actual task selector')
        if AtomKey.from_token(self.goal_ref).type_name!='d08.goal.v1' or AtomKey.from_token(self.plan_ref).type_name!='d08.personal_plan.v1':
            raise ValueError('policy registration requires actual task Goal and Plan selectors')
        artifact_draft_phase_sequence_v2(self.method_ref);_text(self.extent_original_ref)
        if self.observer_policy_ref is not None:_text(self.observer_policy_ref)


@dataclass(frozen=True,slots=True)
class RegisterArtifactPhasePostconditionContractRequestV1:
    selector: ArtifactDraftPhaseSelectorV2
    policy_ref: str

    def __post_init__(self):
        if type(self.selector) is not ArtifactDraftPhaseSelectorV2 or self.selector.phase_index!=0 or not self.selector.generation:
            raise ValueError('contract registration binds the first actually selected whole-method generation')
        _text(self.policy_ref)


@dataclass(frozen=True,slots=True)
class ObserveArtifactPhasePostconditionsRequestV1:
    selector: ArtifactDraftPhaseSelectorV2
    file_result_ref: str
    contract_ref: str
    observer_original_refs: tuple[str,...]=()

    def __post_init__(self):
        if type(self.selector) is not ArtifactDraftPhaseSelectorV2 or self.selector.generation:raise ValueError('assessment requires its actual check phase selector')
        _text(self.file_result_ref);_text(self.contract_ref)
        if type(self.observer_original_refs) is not tuple or len(self.observer_original_refs)>8:raise ValueError('assessment accepts bounded original selectors only')
        for ref in self.observer_original_refs:_text(ref)


@dataclass(frozen=True,slots=True)
class ArtifactPhasePostconditionPolicyOriginalV1:
    request: RegisterArtifactPhasePostconditionPolicyRequestV1
    goal_head: GraphVersion
    goal_digest: str
    plan_head: GraphVersion
    plan_digest: str
    source_head: GraphVersion
    source_value_digest: str
    objective_ref: str
    objective_digest: str
    extent_original_digest: str
    owner_guard: ProductionOwnerGuardV1
    installation_id: str
    manifest_digest: str
    conditions: tuple[ArtifactPhaseConditionV1,...]
    original_deadline_utc: float
    registration_operation_id: str
    schema: str='d11.artifact-phase-postcondition-policy.v1'

    @property
    def namespace(self):return self.request.task.namespace
    @property
    def original_ref(self):return _artifact_phase_policy_original_ref_from_parts_v1(self.request,self.goal_head,self.goal_digest,self.plan_head,self.plan_digest,self.source_head,self.source_value_digest,self.objective_ref,self.objective_digest,self.extent_original_digest,self.owner_guard,self.installation_id,self.manifest_digest,self.conditions,self.original_deadline_utc)
    @property
    def digest(self):return canonical_digest(plain_v1(self))

    def __post_init__(self):
        if self.schema!='d11.artifact-phase-postcondition-policy.v1' or type(self.request) is not RegisterArtifactPhasePostconditionPolicyRequestV1:
            raise ValueError('exact postcondition policy original required')
        if type(self.conditions) is not tuple or not 1<=len(self.conditions)<=16 or any(type(c) is not ArtifactPhaseConditionV1 for c in self.conditions):
            raise ValueError('policy requires an actual finite set of mandatory conditions')
        if len({(c.phase_kind,c.condition_id) for c in self.conditions})!=len(self.conditions):raise ValueError('policy repeats a required condition')
        for value in (self.goal_digest,self.plan_digest,self.source_value_digest,self.objective_digest,self.extent_original_digest):_digest(value)



@dataclass(frozen=True,slots=True)
class ArtifactPhasePostconditionPolicyOriginalV2(ArtifactPhasePostconditionPolicyOriginalV1):
    task_basis_ref: str = field(kw_only=True)
    task_basis_digest: str = field(kw_only=True)
    amendment_original_ref: str = field(kw_only=True)
    amendment_original_digest: str = field(kw_only=True)
    rule_source_head: GraphVersion = field(kw_only=True)
    rule_source_digest: str = field(kw_only=True)
    schema: str = 'd11.artifact-phase-postcondition-policy.v2'

    def __post_init__(self):
        ArtifactPhasePostconditionPolicyOriginalV1(**{f.name:getattr(self,f.name)
            for f in fields(ArtifactPhasePostconditionPolicyOriginalV1) if f.name!='schema'})
        from ..runtime_contracts import NamespaceId
        if (self.schema!='d11.artifact-phase-postcondition-policy.v2'
                or type(self.rule_source_head) is not GraphVersion or self.rule_source_head.revision<1
                or self.rule_source_head.key.type_name!='memory.source'
                or NamespaceId.from_key(self.rule_source_head.key)!=self.namespace):
            raise ValueError('amended policy requires its closed V2 rule Source commitment')
        for digest in (self.task_basis_digest,self.amendment_original_digest,self.rule_source_digest):_digest(digest)
        _text(self.task_basis_ref);_text(self.amendment_original_ref)
        if not self.task_basis_ref.startswith('artifact-task-amendment-basis:') or not self.amendment_original_ref.startswith('artifact-task-amendment:'):
            raise ValueError('amended policy requires its actual basis and amendment selectors')

    @property
    def original_ref(self):
        material=plain_v1(self);del material['registration_operation_id']
        return 'artifact-phase-postcondition-policy:'+canonical_digest(material)[:48]


@dataclass(frozen=True,slots=True)
class ArtifactPhasePostconditionContractV1:
    selector: ArtifactDraftPhaseSelectorV2
    policy_ref: str
    policy_digest: str
    selected_preparation_ref: str
    selected_preparation_digest: str
    selected_binding_digest: str
    goal_head: GraphVersion
    goal_digest: str
    plan_head: GraphVersion
    plan_digest: str
    source_head: GraphVersion
    source_value_digest: str
    owner_guard: ProductionOwnerGuardV1
    conditions: tuple[ArtifactPhaseConditionV1,...]
    original_deadline_utc: float
    registration_operation_id: str
    registered_at_utc: float
    schema: str='d11.artifact-phase-postcondition-contract.v1'

    @property
    def namespace(self):return self.selector.task.namespace
    @property
    def original_ref(self):return artifact_phase_postcondition_contract_ref_v1(self.selector)
    @property
    def digest(self):return canonical_digest(plain_v1(self))

    def __post_init__(self):
        if self.schema!='d11.artifact-phase-postcondition-contract.v1' or type(self.selector) is not ArtifactDraftPhaseSelectorV2:
            raise ValueError('actual adopted Decision postcondition contract required')
        if self.selector.phase_index!=0 or not self.selector.generation:raise ValueError('contract must precede first generation')
        for value in (self.policy_digest,self.selected_preparation_digest,self.selected_binding_digest,self.goal_digest,self.plan_digest,self.source_value_digest):_digest(value)


@dataclass(frozen=True,slots=True)
class ArtifactPhaseConditionResultV1:
    condition_id: str
    status: str
    evidence_positions: tuple[tuple[int,int],...]
    observer_id: str
    observer_version: int
    observer_original_ref: str | None
    observer_original_digest: str | None
    detail: str

    def __post_init__(self):
        if self.status not in STATUSES or type(self.evidence_positions) is not tuple or len(self.evidence_positions)>32:
            raise ValueError('actual assessment result has another status or evidence scope')
        _text(self.condition_id);_text(self.observer_id);_text(self.detail)
        if type(self.observer_version) is not int or self.observer_version<1:raise ValueError('assessment observer requires its exact version')
        if (self.observer_original_ref is None)!=(self.observer_original_digest is None):raise ValueError('observer evidence commitment must be paired')
        if self.observer_original_digest is not None:_digest(self.observer_original_digest)
        for start,end in self.evidence_positions:
            if type(start) is not int or type(end) is not int or not 0<=start<=end:raise ValueError('assessment evidence positions differ')


@dataclass(frozen=True,slots=True)
class ArtifactPhaseAssessmentOriginalV1:
    request: ObserveArtifactPhasePostconditionsRequestV1
    content_selector: ArtifactDraftPhaseSelectorV2
    contract_digest: str
    source_head: GraphVersion
    source_value_digest: str
    file_result_digest: str
    readback: DraftFileReadbackV1
    owner_guard: ProductionOwnerGuardV1
    results: tuple[ArtifactPhaseConditionResultV1,...]
    assessed_at_utc: float
    original_deadline_utc: float
    registration_operation_id: str
    schema: str='d11.artifact-phase-assessment-original.v1'

    @property
    def namespace(self):return self.request.selector.task.namespace
    @property
    def original_ref(self):return artifact_phase_assessment_original_ref_v1(self.request.selector)
    @property
    def digest(self):return canonical_digest(plain_v1(self))

    def __post_init__(self):
        from .d11_artifact_draft_contract_v1 import DraftFileReadbackV1
        if self.schema!='d11.artifact-phase-assessment-original.v1' or type(self.request) is not ObserveArtifactPhasePostconditionsRequestV1 or type(self.readback) is not DraftFileReadbackV1:
            raise ValueError('assessment requires the real content and file witness')
        for value in (self.contract_digest,self.source_value_digest,self.file_result_digest):_digest(value)
        if type(self.results) is not tuple or any(type(row) is not ArtifactPhaseConditionResultV1 for row in self.results):raise ValueError('assessment requires typed individual observations')


_INSTALL_KEY=object()


class InstalledArtifactPhasePostconditionReadersV1:
    def __init__(self,key,*,graph,bootstrap,bundle,model_readers):
        if key is not _INSTALL_KEY:raise TypeError('postconditions require the actual installed Graph factory')
        self.graph,self.bootstrap,self.bundle,self.model_readers=graph,bootstrap,bundle,model_readers
        self.issuer=model_readers.issuer
        self.current()

    def current(self):
        from ..graph_coordinator import GraphCoordinator
        from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
        if (type(self.graph) is not GraphCoordinator or type(self.model_readers) is not InstalledArtifactDraftModelReadersV1
                or self.model_readers.installed_bundle is not self.bundle
                or self.model_readers.model_runtime is not self.graph._GraphCoordinator__artifact_draft_model_runtime_v1
                or self.issuer is not self.graph._GraphCoordinator__d11_issuer):
            raise TypeError('postcondition factory differs from actual installed Graph/model package')
        self.graph._admin(self.bootstrap)
        from .d08_personal_candidate_v1 import _readers
        personal=_readers(self.graph._GraphCoordinator__domain_production_runtime_v1._personal_candidate_readers_v1)
        if personal.bundle is not self.bundle or personal.current().graph is not self.graph:
            raise ValueError('postcondition factory lost actual current candidate producer')
        return personal

    def observer(self,ref):
        if ref is None:return None
        from ..host.artifact_phase_observer_policy_v2 import require_current_artifact_phase_observer_v2
        value=require_current_artifact_phase_observer_v2(self.bundle)
        if value.asset_ref!=ref:
            raise ValueError('policy observer selector differs from actual protected installed asset')
        return value


def install_artifact_phase_postcondition_readers_v1(*,graph,bootstrap,bundle,model_readers):
    return InstalledArtifactPhasePostconditionReadersV1(_INSTALL_KEY,graph=graph,bootstrap=bootstrap,bundle=bundle,model_readers=model_readers)


def _readers(installed_readers):
    if type(installed_readers) is InstalledArtifactPhasePostconditionReadersV1:
        installed_readers.current();return installed_readers
    from .d08_personal_candidate_v1 import _readers as personal_readers
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
    if type(installed_readers) is InstalledArtifactDraftModelReadersV1:
        runtime=installed_readers.model_runtime
        if runtime is None:raise MissingProductionOriginalV1('actual_installed_postcondition_model_runtime')
        return install_artifact_phase_postcondition_readers_v1(graph=runtime.graph,bootstrap=runtime.bootstrap,
            bundle=installed_readers.installed_bundle,model_readers=installed_readers)
    personal=personal_readers(installed_readers);graph=personal.current().graph
    return install_artifact_phase_postcondition_readers_v1(graph=graph,
        bootstrap=graph._GraphCoordinator__domain_production_runtime_v1._bootstrap,bundle=personal.bundle,
        model_readers=InstalledArtifactDraftModelReadersV1(personal.issuer,personal.bundle,graph._GraphCoordinator__artifact_draft_model_runtime_v1))


def _decode(raw,kind):
    if kind in {ArtifactPhasePostconditionPolicyOriginalV1,ArtifactPhasePostconditionPolicyOriginalV2}:
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        variants={'d11.artifact-phase-postcondition-policy.v1':ArtifactPhasePostconditionPolicyOriginalV1,
            'd11.artifact-phase-postcondition-policy.v2':ArtifactPhasePostconditionPolicyOriginalV2}
        cls=variants.get(raw.get('schema')) if type(raw) is dict else None
        if cls is None:raise ValueError('unregistered closed postcondition Policy schema')
        return decode_typed_production_value_v1(raw,cls)
    if kind is ArtifactCandidatePreparationParentOriginalV1:
        return _preparation_parent_from_wire_v1(raw)
    if kind is ArtifactStandingPredecisionApprovalOriginalV2:
        return _standing_approval_from_wire_v2(raw)
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw,kind)


def _original(db,*,namespace,kind,ref,issuer):
    row=_read(db,issuer=issuer,namespace=namespace,kind=kind,ref=ref)
    if row is None:raise MissingProductionOriginalV1('actual_registered_'+kind)
    cls={POLICY_KIND:ArtifactPhasePostconditionPolicyOriginalV1,CONTRACT_KIND:ArtifactPhasePostconditionContractV1,
        ASSESSMENT_KIND:ArtifactPhaseAssessmentOriginalV1, APPROVAL_KIND_V2:ArtifactStandingPredecisionApprovalOriginalV2,
        PREPARATION_PARENT_KIND_V1:ArtifactCandidatePreparationParentOriginalV1}[kind]
    value=_decode(row[0],cls)
    require_artifact_phase_postcondition_history_v1(db,namespace=namespace,kind=kind,original_ref=ref,
        producing_operation_id=row[1],raw=row[0], issuer=issuer)
    return value,row


def _require_before_first_generation_v1(db,task,*,before_operation_id=None):
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .d11_life_preparation_v1 import TABLE
    rows=_artifact_receipt_sql_v1(db,"SELECT producing_operation_id FROM "+TABLE+" WHERE bot=? AND persona=? "
        "AND kind IN ('c4_phase_prepared','c4_phase_frozen','c4_phase_paid','c4_prepared','c4_paid') "
        "AND (json_extract(payload_json,'$.selector.task.c02_operation_id')=? OR json_extract(payload_json,'$.selector.c02_operation_id')=?) LIMIT 1",
        (*task.namespace.as_tuple,task.c02_operation_id,task.c02_operation_id)).fetchall()
    if rows:raise MissingProductionOriginalV1('postcondition_contract_before_actual_first_prepare_reserve_paid')
    if before_operation_id is not None:
        prior=_artifact_receipt_sql_v1(db,"SELECT operation_id FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
            "AND operation_id=? AND phase='reserve' LIMIT 1",(*task.namespace.as_tuple,before_operation_id)).fetchone()
        if prior:raise MissingProductionOriginalV1('postcondition_contract_before_actual_first_reservation')


def _policy_basis_v1(db,*,frame,request,readers,registration_operation_id,deadline=None):
    from .artifact_task_text_extent_v1 import (_qualified_extent_v1,RegisterArtifactTaskTextExtentRequestV1,
        require_artifact_task_text_extent_history_v1,KIND as EXTENT_KIND)
    from ..domains.d08.execution import _decode_goal
    from ..domains.d08.personal_plan_v1 import decode_personal_plan_type_v1,PLAN_TYPE
    read=CurrentDomainReadV1(frame);read.check(db);ns=request.task.namespace
    if ns!=frame.envelope.authority.namespace:raise ValueError('policy task namespace differs')
    goal_atom=read.head(db,request.goal_ref,required=True);plan_atom=read.head(db,request.plan_ref,required=True)
    goal=_decode_goal(goal_atom.value);plan=decode_personal_plan_type_v1(PLAN_TYPE,plan_atom.value)
    if goal.state!='active' or plan.state!='active' or (plan.goal_ref,plan.goal_revision)!=(request.goal_ref,goal_atom.revision):
        raise MissingProductionOriginalV1('current_active_postcondition_task_Goal_Plan')
    row=_read(db,issuer=readers.issuer,namespace=ns,kind=EXTENT_KIND,ref=request.extent_original_ref)
    if row is None:raise MissingProductionOriginalV1('actual_registered_postcondition_task_extent')
    extent=require_artifact_task_text_extent_history_v1(db,namespace=ns,original_ref=request.extent_original_ref,
        producing_operation_id=row[1],raw=row[0])
    from .artifact_task_text_extent_v1 import ArtifactTaskTextExtentOriginalV2
    if type(extent) is ArtifactTaskTextExtentOriginalV2:
        return _policy_basis_v2(db,frame=frame,request=request,readers=readers,extent=extent,
            registration_operation_id=registration_operation_id,deadline=deadline)
    current=_qualified_extent_v1(db,frame=frame,request=RegisterArtifactTaskTextExtentRequestV1(request.goal_ref,goal_atom.revision),
        readers=readers.current(),registration_operation_id=extent.registration_operation_id)
    objective=_read(db,issuer=readers.issuer,namespace=ns,kind='artifact_task_objective',ref=extent.objective_ref)[0]
    if (extent!=current or extent.task_c02_operation_id!=request.task.c02_operation_id
            or objective['initial_root_registration_ref']!=request.task.root_registration_ref):
        raise ValueError('policy changed actual registered task/Source/root/extent')
    read.original(request.extent_original_ref,kind='d11.life_'+EXTENT_KIND,digest=canonical_digest(row[0]))
    from .budget import get_budget_lease,require_budget_family_admissible
    lease=get_budget_lease(db,frame.envelope.parent_budget_lease_ref)
    grant=readers.issuer.current_budget_grant(db,lease.lease_id)
    require_budget_family_admissible(db,lease.lease_id)
    from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1,draft_from_wire_v1
    from .d11_offline_originals_v1 import _utc
    root_row=_read(db,issuer=readers.issuer,namespace=ns,kind='draft_root_capability',ref=request.task.root_registration_ref)
    if root_row is None:raise MissingProductionOriginalV1('actual_postcondition_registered_Root_scope')
    root=draft_from_wire_v1(root_row[0],DraftRootCapabilityV1)
    if (root.source_ref,root.owner_grant_ref,root.owner_grant_revision,root.owner_grant_digest,root.installation_id,root.manifest_digest)!=(
            extent.task_source_head.key.token,frame.owner_guard.grant_ref,frame.owner_guard.grant_revision,frame.owner_guard.grant_digest,
            readers.bundle.installation_policy.installation_id,readers.bundle.installation_policy.manifest_digest):
        raise ValueError('postcondition policy crossed actual Root/Source/Owner/installed package')
    read.original(root.registration_ref,kind='d11.life_draft_root_capability',digest=canonical_digest(root_row[0]))
    from .jobs import get_job
    from .d11_types import job_graph_write
    cycle=get_job(db,AtomKey.from_token(request.task.cycle_job_ref).name)
    cycle_atom=read.head(db,request.task.cycle_job_ref,required=True)
    if (cycle_atom.value!=job_graph_write(cycle).value or cycle.budget_ref!=lease.lease_id
            or (cycle.bot_id,cycle.persona_id)!=ns.as_tuple):
        raise ValueError('policy deadline budget is not the actual registered task budget')
    grant_deadlines=[grant.valid_until_utc]
    ancestor=lease
    while ancestor.parent_id is not None:
        ancestor=get_budget_lease(db,ancestor.parent_id)
        grant_deadlines.append(readers.issuer.current_budget_grant(db,ancestor.lease_id).valid_until_utc)
    # The Owner write window guards this attempt. It cannot choose a policy
    # identity or renew the absolute lifetime of the registered task rubric.
    limit=min(objective['valid_until_utc'],_utc(root.valid_until_utc).timestamp(),
        _utc(cycle.deadline_utc).timestamp(),*grant_deadlines)
    original_deadline=limit if deadline is None else deadline
    if (not frame.now_utc<frame.envelope.deadline_utc or not frame.now_utc<original_deadline<=limit
            or lease.state!='active'):
        raise MissingProductionOriginalV1('current_original_postcondition_task_budget_deadline')
    observer=readers.observer(request.observer_policy_ref)
    value=_readonly_artifact_phase_policy_basis_core_v1(db,namespace=ns,request=request,issuer=readers.issuer,
        bundle=readers.bundle,owner_guard=frame.owner_guard,now_utc=frame.now_utc,
        parent_budget_lease_ref=frame.envelope.parent_budget_lease_ref,actor_ref=frame.envelope.authority.actor,
        purpose=frame.envelope.authority.purpose,audiences=frame.envelope.authority.audience,
        access_epoch=frame.envelope.version_guard.access_epoch,delete_epoch=frame.envelope.version_guard.delete_epoch,
        registration_operation_id=registration_operation_id,deadline=original_deadline)
    expected_observers=set() if observer is None else {(observer.observer_id,observer.observer_version,observer.asset_digest)}
    if ({(c.observer_id,c.observer_version,c.observer_asset_digest) for c in value.conditions if c.observer_id is not None}!=expected_observers
            or (value.goal_head,value.goal_digest,value.plan_head,value.plan_digest,value.source_head,value.source_value_digest,
                value.extent_original_digest)!=(GraphVersion(goal_atom.key,goal_atom.revision),canonical_digest(goal_atom.value),
                GraphVersion(plan_atom.key,plan_atom.revision),canonical_digest(plan_atom.value),extent.task_source_head,
                extent.task_source_digest,canonical_digest(row[0]))):
        raise ValueError('pure policy material differs from its actual qualified Frame originals')
    return value


def stage_register_artifact_phase_postcondition_policy_v1(db,*,frame,request,installed_readers):
    if type(request) is not RegisterArtifactPhasePostconditionPolicyRequestV1:raise TypeError('exact policy registration selectors required')
    readers=_readers(installed_readers)
    try:
        _require_before_first_generation_v1(db,request.task)
        from .domain_production_originals_v1 import TABLE as DOMAIN_TABLE
        existing=db.execute("SELECT operation_id FROM "+DOMAIN_TABLE+" WHERE bot=? AND persona=? AND domain='d08' "
            "AND operation_kind='prepare_personal_candidates_v1' AND EXISTS (SELECT 1 FROM json_each(original_payload_json,'$.request.bindings') "
            "WHERE json_extract(value,'$.task.c02_operation_id')=?) LIMIT 1",(*request.task.namespace.as_tuple,request.task.c02_operation_id)).fetchone()
        if existing is not None:raise MissingProductionOriginalV1('postcondition_policy_before_actual_candidate_preparation')
        value=_policy_basis_v1(db,frame=frame,request=request,readers=readers,registration_operation_id=frame.envelope.identity.operation_id)
        if frame.envelope.identity.operation_id!=artifact_phase_policy_registration_operation_id_v1(value):
            raise ValueError('policy registration changed its actual fixed original once ID')
    except MissingProductionOriginalV1 as missing:
        return stage_result_v1(frame,'d08',POLICY_OPERATION,request,coverage='waiting_for_original',missing=missing.missing_inputs)
    return _empty_postcondition_stage_v1(stage_result_v1(frame,'d08',POLICY_OPERATION,request,provenance={'postcondition_policy':value}),frame,readers)


def require_current_artifact_phase_postcondition_policy_v1(db,*,frame,binding,goal_ref,plan_ref,installed_readers):
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV3
    if type(binding) is not ArtifactPhaseCandidateBindingV3:raise MissingProductionOriginalV1('actual_precommitted_V3_postcondition_policy')
    readers=_readers(installed_readers);ns=frame.envelope.authority.namespace
    value,row=_original(db,namespace=ns,kind=POLICY_KIND,ref=binding.postcondition_policy_ref,issuer=readers.issuer)
    expected=_policy_basis_v1(db,frame=frame,request=value.request,readers=readers,
        registration_operation_id=value.registration_operation_id,deadline=value.original_deadline_utc)
    if (value!=expected or value.digest!=binding.postcondition_policy_digest
            or (value.request.goal_ref,value.request.plan_ref,value.request.task,value.request.method_ref,value.request.extent_original_ref)!=
                (goal_ref,plan_ref,binding.task,binding.method_ref,binding.extent_original_ref)
            or value.extent_original_digest!=binding.extent_original_digest):
        raise ValueError('candidate changed prospective rubric or current original task/Owner/Source/Goal/Plan')
    CurrentDomainReadV1(frame).original(value.original_ref,kind='d11.life_'+POLICY_KIND,digest=value.digest)
    return value


def stage_register_artifact_phase_postcondition_contract_v1(db,*,frame,request,installed_readers):
    from .d08_personal_candidate_v1 import read_selected_personal_adapter_v1
    from .d11_artifact_draft_model_v1 import _artifact_phase_selection_locator_v2
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV3
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2
    if type(request) is not RegisterArtifactPhasePostconditionContractRequestV1:raise TypeError('exact contract selectors required')
    readers=_readers(installed_readers)
    if frame.now_utc>=frame.envelope.deadline_utc:
        raise MissingProductionOriginalV1('fresh_current_contract_registration_write_window')
    if frame.envelope.identity.operation_id!=artifact_phase_contract_registration_operation_id_v1(request.selector):
        raise ValueError('contract registration changed the selected method fixed once ID')
    try:
        locator,_,_=_artifact_phase_selection_locator_v2(db,request.selector)
        candidates,chosen,original=read_selected_personal_adapter_v1(db,frame=frame,request=locator,installed_readers=readers.current())
        if type(chosen.binding) is not ArtifactPhaseCandidateBindingV3 or chosen.binding.postcondition_policy_ref!=request.policy_ref:
            raise MissingProductionOriginalV1('actual_selected_V3_postcondition_policy')
        if (chosen.binding.task,chosen.binding.method_ref,chosen.binding.phase_index,chosen.binding.phase_kind)!=(
                request.selector.task,request.selector.method_ref,request.selector.phase_index,request.selector.phase_kind):
            raise ValueError('contract caller redirected the actually selected whole method')
        policy=require_current_artifact_phase_postcondition_policy_v1(db,frame=frame,binding=chosen.binding,
            goal_ref=candidates.goal_head.key.token,plan_ref=candidates.plan_head.key.token,installed_readers=readers)
        _require_before_first_generation_v1(db,request.selector.task,before_operation_id=artifact_draft_model_ids_v2(request.selector)['prepare'])
        deadline=min(policy.original_deadline_utc,candidates.need.original_deadline_utc)
        if not frame.now_utc<deadline:
            raise MissingProductionOriginalV1('unexpired_registered_whole_method_contract_window')
        value=ArtifactPhasePostconditionContractV1(request.selector,policy.original_ref,policy.digest,
            'd08-current:'+original['original_digest'][:48],original['original_digest'],chosen.binding.digest,
            policy.goal_head,policy.goal_digest,policy.plan_head,policy.plan_digest,policy.source_head,policy.source_value_digest,
            frame.owner_guard,policy.conditions,deadline,frame.envelope.identity.operation_id,frame.now_utc)
        prior=_read(db,issuer=readers.issuer,namespace=value.namespace,kind=CONTRACT_KIND,ref=value.original_ref)
        if prior is not None and prior[0]!=plain_v1(value):raise ValueError('same Decision cannot change its registered success contract')
    except MissingProductionOriginalV1 as missing:
        return stage_result_v1(frame,'d08',CONTRACT_OPERATION,request,coverage='waiting_for_original',missing=missing.missing_inputs)
    return _empty_postcondition_stage_v1(stage_result_v1(frame,'d08',CONTRACT_OPERATION,request,provenance={'postcondition_contract':value}),frame,readers)


def _current_policy_sql_v1(db,*,policy,issuer,now_utc,owner_guard,installed_bundle):
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3
    if type(policy) is ArtifactPhasePostconditionPolicyOriginalV2:
        return _current_policy_sql_v2(db,policy=policy,issuer=issuer,now_utc=now_utc,
            owner_guard=owner_guard,installed_bundle=installed_bundle)
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    from ..memory_types import SourceRecord
    if not db.in_transaction or (policy.owner_guard,policy.installation_id,policy.manifest_digest)!=(
            owner_guard,installed_bundle.installation_policy.installation_id,installed_bundle.installation_policy.manifest_digest):
        raise ValueError('postcondition current policy lost actual Owner/installed package')
    if now_utc>=policy.original_deadline_utc:raise MissingProductionOriginalV1('current_original_postcondition_deadline')
    for head,digest in ((policy.goal_head,policy.goal_digest),(policy.plan_head,policy.plan_digest),
            (policy.source_head,policy.source_value_digest)):
        row=artifact_model_graph_point_v3(db,('revision', 'value', 'valid'),token=head.key.token)
        if row is None or (row[0],canonical_digest(json.loads(row[1])),row[2])!=(head.revision,digest,1):
            raise MissingProductionOriginalV1('current_postcondition_Goal_Plan_Source_original')
    owner=artifact_model_graph_point_v3(db,('revision', 'value', 'valid'),token=owner_guard.grant_ref)
    if owner is None or (owner[0],canonical_digest(json.loads(owner[1])),owner[2])!=(owner_guard.grant_revision,owner_guard.grant_digest,1):
        raise MissingProductionOriginalV1('current_postcondition_upstream_Owner')
    from .artifact_task_text_extent_v1 import KIND as EXTENT_KIND,require_artifact_task_text_extent_history_v1
    extent=_read(db,issuer=issuer,namespace=policy.namespace,kind=EXTENT_KIND,ref=policy.request.extent_original_ref)
    if extent is None or canonical_digest(extent[0])!=policy.extent_original_digest:raise ValueError('policy extent original changed')
    actual_extent=require_artifact_task_text_extent_history_v1(db,namespace=policy.namespace,original_ref=policy.request.extent_original_ref,
        producing_operation_id=extent[1],raw=extent[0])
    if (actual_extent.task_source_head,actual_extent.task_source_digest,actual_extent.objective_ref,actual_extent.objective_digest)!=(
            policy.source_head,policy.source_value_digest,policy.objective_ref,policy.objective_digest):
        raise ValueError('policy lost actual task extent/objective lineage')
    objective=_read(db,issuer=issuer,namespace=policy.namespace,kind='artifact_task_objective',ref=policy.objective_ref)
    if objective is None or canonical_digest(objective[0])!=policy.objective_digest or now_utc>=objective[0]['valid_until_utc']:
        raise ValueError('policy task objective changed or expired')
    from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1,draft_from_wire_v1
    from .d11_offline_originals_v1 import _utc
    root_row=_read(db,issuer=issuer,namespace=policy.namespace,kind='draft_root_capability',ref=policy.request.task.root_registration_ref)
    if root_row is None:raise MissingProductionOriginalV1('current_postcondition_registered_Root')
    root=draft_from_wire_v1(root_row[0],DraftRootCapabilityV1)
    if (root.source_ref,root.owner_grant_ref,root.owner_grant_revision,root.owner_grant_digest,root.installation_id,root.manifest_digest)!=(
            policy.source_head.key.token,owner_guard.grant_ref,owner_guard.grant_revision,owner_guard.grant_digest,policy.installation_id,policy.manifest_digest):
        raise ValueError('current postcondition Root/Source/Owner changed')
    from .jobs import get_job
    from .budget import get_budget_lease,require_budget_family_admissible
    cycle=get_job(db,AtomKey.from_token(policy.request.task.cycle_job_ref).name)
    if (cycle.bot_id,cycle.persona_id)!=policy.namespace.as_tuple:raise ValueError('current policy task budget namespace changed')
    lease=get_budget_lease(db,cycle.budget_ref)
    require_budget_family_admissible(db,lease.lease_id)
    grant_deadlines=[]
    ancestor=lease
    while True:
        grant_deadlines.append(issuer.current_budget_grant(db,ancestor.lease_id).valid_until_utc)
        if ancestor.parent_id is None:break
        ancestor=get_budget_lease(db,ancestor.parent_id)
    limit=min(objective[0]['valid_until_utc'],_utc(root.valid_until_utc).timestamp(),_utc(cycle.deadline_utc).timestamp(),*grant_deadlines)
    if lease.state!='active' or not now_utc<policy.original_deadline_utc<=limit:
        raise MissingProductionOriginalV1('current_fixed_registered_task_Root_budget_policy_deadline')
    record=SourceRecord.from_dict(json.loads(artifact_model_graph_point_v3(db,('value',),token=policy.source_head.key.token)[0]))
    _source_family_current_sql_v1(db,namespace=policy.namespace,roots=(policy.source_head.key.token,),purpose='context',audiences=record.audiences)
    if policy.request.observer_policy_ref is not None:
        from ..host.artifact_phase_observer_policy_v2 import require_current_artifact_phase_observer_v2
        observer=require_current_artifact_phase_observer_v2(installed_bundle)
        committed={(c.observer_id,c.observer_version,c.observer_asset_digest) for c in policy.conditions if c.observer_id is not None}
        if observer.asset_ref!=policy.request.observer_policy_ref or committed!={(observer.observer_id,observer.observer_version,observer.asset_digest)}:
            raise ValueError('current observer changed frozen rubric identity/version/asset')
    return policy


def readonly_current_artifact_phase_postcondition_contract_v1(db,*,namespace,selector,issuer,now_utc,owner_guard,installed_bundle):
    from .d11_artifact_draft_model_v1 import _read_artifact_phase_selected_originals_v2
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV3
    from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
    candidates,chosen,original=_read_artifact_phase_selected_originals_v2(db,selector=selector,issuer=issuer)
    binding=chosen.binding
    if type(binding) is not ArtifactPhaseCandidateBindingV3:raise MissingProductionOriginalV1('actual_precommitted_V3_postcondition_contract')
    policy,_=_original(db,namespace=namespace,kind=POLICY_KIND,ref=binding.postcondition_policy_ref,issuer=issuer)
    _current_policy_sql_v1(db,policy=policy,issuer=issuer,now_utc=now_utc,owner_guard=owner_guard,installed_bundle=installed_bundle)
    ref=artifact_phase_postcondition_contract_ref_v1(selector)
    contract,_=_original(db,namespace=namespace,kind=CONTRACT_KIND,ref=ref,issuer=issuer)
    if (foreground_artifact_phase_group_identity_v2(contract.selector)!=foreground_artifact_phase_group_identity_v2(selector)
            or (contract.policy_ref,contract.policy_digest,contract.selected_preparation_digest,contract.selected_binding_digest)!=
                (policy.original_ref,policy.digest,original['original_digest'],binding.digest)
            or (contract.goal_head,contract.plan_head,contract.source_head,contract.source_value_digest,contract.owner_guard,contract.conditions)!=
                (policy.goal_head,policy.plan_head,policy.source_head,policy.source_value_digest,owner_guard,policy.conditions)
            or policy.digest!=binding.postcondition_policy_digest or now_utc>=contract.original_deadline_utc
            or contract.original_deadline_utc!=min(policy.original_deadline_utc,candidates.need.original_deadline_utc)):
        raise ValueError('current same Decision contract changed its frozen task/method/rubric/Owner/deadline')
    return contract


def read_current_artifact_phase_postcondition_contract_v1(db,*,frame,selector,installed_readers):
    readers=_readers(installed_readers);read=CurrentDomainReadV1(frame);read.check(db)
    if frame.now_utc>=frame.envelope.deadline_utc:raise MissingProductionOriginalV1('fresh_current_postcondition_scope_window')
    contract=readonly_current_artifact_phase_postcondition_contract_v1(db,namespace=frame.envelope.authority.namespace,
        selector=selector,issuer=readers.issuer,now_utc=frame.now_utc,owner_guard=frame.owner_guard,installed_bundle=readers.bundle)
    read.original(contract.original_ref,kind='d11.life_'+CONTRACT_KIND,digest=contract.digest)
    read.original(contract.policy_ref,kind='d11.life_'+POLICY_KIND,digest=contract.policy_digest)
    for head,digest in ((contract.goal_head,contract.goal_digest),(contract.plan_head,contract.plan_digest),(contract.source_head,contract.source_value_digest)):
        atom=read.head(db,head.key,required=True)
        if (atom.revision,canonical_digest(atom.value))!=(head.revision,digest):raise ValueError('contract frame is not its actual current hard truth')
    read.source_family(db,(contract.source_head.key.token,))
    policy,_=_original(db,namespace=frame.envelope.authority.namespace,kind=POLICY_KIND,ref=contract.policy_ref,issuer=readers.issuer)
    if type(policy) is ArtifactPhasePostconditionPolicyOriginalV2:
        from .artifact_task_text_extent_v1 import (KIND as EXTENT_KIND,read_plan_artifact_task_text_extent_v1,
            RegisterArtifactTaskTextExtentRequestV1)
        extent=_read(db,issuer=readers.issuer,namespace=policy.namespace,kind=EXTENT_KIND,ref=policy.request.extent_original_ref)
        plan=read_plan_artifact_task_text_extent_v1(db,namespace=policy.namespace,
            request=RegisterArtifactTaskTextExtentRequestV1(policy.request.goal_ref,policy.goal_head.revision),installed_readers=readers.current())
        for key in plan.exact_keys:read.head(db,key)
        read.source_family(db,plan.source_roots)
        for ref in plan.required_original_refs:read.original(ref)
        read.original(policy.request.extent_original_ref,kind='d11.life_'+EXTENT_KIND,digest=policy.extent_original_digest)
        if extent is None or canonical_digest(extent[0])!=policy.extent_original_digest:
            raise ValueError('contract Frame lost its actual frozen amended extent')
    return contract


def _assessment_inputs_v1(db,*,request,contract,issuer):
    from .d11_artifact_draft_content_v1 import (ArtifactDraftPhaseVerifiedOriginalV2,artifact_draft_phase_verification_from_wire_v2,
        read_current_artifact_phase_verified_v2,_read_phase_content_adoption_original_v2,_read_actual_phase_file_v2)
    from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
    selector=request.selector;ns=selector.task.namespace
    previous=_read(db,issuer=issuer,namespace=ns,kind='c4_phase_verified',ref=selector.prev_phase_original_ref)
    if previous is None or canonical_digest(previous[0])!=selector.prev_phase_original_digest:
        raise MissingProductionOriginalV1('actual_independently_structurally_verified_generation_before_assessment')
    generation=artifact_draft_phase_verification_from_wire_v2(previous[0],ArtifactDraftPhaseVerifiedOriginalV2)
    if (not generation.selector.generation or generation.selector.phase_index!=selector.phase_index-1
            or foreground_artifact_phase_group_identity_v2(generation.selector)!=foreground_artifact_phase_group_identity_v2(selector)
            or foreground_artifact_phase_group_identity_v2(contract.selector)!=foreground_artifact_phase_group_identity_v2(selector)):
        raise ValueError('assessment crossed actual previous generation/Decision/method group')
    read_current_artifact_phase_verified_v2(db,namespace=ns,selector=generation.selector,issuer=issuer)
    adoption,_,record,_=_read_phase_content_adoption_original_v2(db,namespace=ns,selector=generation.selector,issuer=issuer)
    _,_,file_original,readback=_read_actual_phase_file_v2(db,namespace=ns,selector=generation.selector,
        adoption=adoption,result_ref=request.file_result_ref,issuer=issuer)
    from .d11_artifact_draft_model_v1 import read_artifact_draft_prepared_v2,read_artifact_draft_frozen_v2
    from ..model_broker.artifact_draft_v1 import ArtifactDraftInputV3
    prepared=read_artifact_draft_prepared_v2(db,namespace=ns,selector=generation.selector,issuer=issuer)
    frozen=read_artifact_draft_frozen_v2(db,prepared=prepared,issuer=issuer)
    if type(frozen) is not ArtifactDraftInputV3 or (frozen.postcondition_contract_ref,frozen.postcondition_contract_digest)!=(contract.original_ref,contract.digest):
        raise ValueError('actual paid generation did not freeze this preregistered success contract')
    return generation.selector,adoption,record,file_original,readback


def _evaluate_conditions_v1(*,policy,contract,selector,text,readback,observer,semantic_observations):
    results=[]
    content_digest=hashlib.sha256(text.encode()).hexdigest()
    for condition in contract.conditions:
        if condition.phase_kind!=selector.phase_kind:continue
        status='unknown';positions=();observer_id='d11.explicit-task-objective';observer_version=1
        original_ref=None;original_digest=None;detail='applicable registered semantic observer unavailable'
        if condition.kind=='length':
            count=sum(not ch.isspace() for ch in text)
            status='satisfied' if condition.minimum<=count<=condition.maximum else 'violated'
            positions=((0,len(text)),);detail='registered non-whitespace codepoint range: '+str(count)
        elif condition.kind in {'literal','sections'}:
            found=[]
            for literal in condition.literals:
                offset=text.find(literal)
                if offset<0:status='violated';break
                if condition.kind=='sections' and offset and text[offset-1]!='\n':status='violated';break
                found.append((offset,offset+len(literal)))
            else:status='satisfied'
            positions=tuple(found);detail='explicit registered task literals/section positions'
        elif observer is not None:
            if (condition.observer_id,condition.observer_version,condition.observer_asset_digest)!=(
                    observer.observer_id,observer.observer_version,observer.asset_digest):
                raise ValueError('actual observer changed preregistered policy identity/version/rules')
            actual=semantic_observations.get(condition.condition_id)
            if actual is None:raise MissingProductionOriginalV1('actual_independent_semantic_observation')
            observer_id,observer_version=observer.observer_id,observer.observer_version
            original_ref,original_digest=actual.terminal_ref,actual.terminal_digest
            status=actual.status
            detail='all actual independently paid D07 findings and adopted interpretation originals'
        if content_digest!=readback.content_digest:raise ValueError('assessment text differs from actual adopted file hash')
        results.append(ArtifactPhaseConditionResultV1(condition.condition_id,status,positions,observer_id,observer_version,original_ref,original_digest,detail))
    if not results:raise MissingProductionOriginalV1('registered_required_conditions_for_current_check_phase')
    return tuple(results)


def stage_observe_artifact_phase_postconditions_v1(db,*,frame,request,installed_readers):
    if type(request) is not ObserveArtifactPhasePostconditionsRequestV1:raise TypeError('assessment accepts exact original selectors only')
    readers=_readers(installed_readers)
    if frame.envelope.identity.operation_id!=artifact_phase_assessment_operation_id_v1(request.selector):
        raise ValueError('assessment changed the check phase fixed original once ID')
    try:
        contract=read_current_artifact_phase_postcondition_contract_v1(db,frame=frame,selector=request.selector,installed_readers=readers)
        if request.contract_ref!=contract.original_ref:raise ValueError('assessment caller changed actual registered contract locator')
        policy,_=_original(db,namespace=contract.namespace,kind=POLICY_KIND,ref=contract.policy_ref,issuer=readers.issuer)
        content_selector,adoption,record,file_original,readback=_assessment_inputs_v1(db,request=request,contract=contract,issuer=readers.issuer)
        observer=readers.observer(policy.request.observer_policy_ref)
        from .artifact_phase_observation_result_v1 import read_artifact_phase_semantic_observations_v1
        semantic=read_artifact_phase_semantic_observations_v1(db,namespace=contract.namespace,selector=request.selector,
            contract=contract,observer_original_refs=request.observer_original_refs,issuer=readers.issuer,
            frame=frame,installed_readers=readers) if observer is not None else {}
        if observer is None and request.observer_original_refs:
            raise ValueError('no undeclared independent observer original may substitute a registered condition')
        results=_evaluate_conditions_v1(policy=policy,contract=contract,selector=request.selector,text=record.text,
            readback=readback,observer=observer,semantic_observations=semantic)
        value=ArtifactPhaseAssessmentOriginalV1(request,content_selector,contract.digest,
            GraphVersion(AtomKey.from_token(adoption.content.content.ref),adoption.content.content.revision),adoption.content.content.digest,
            canonical_digest(file_original),readback,frame.owner_guard,results,frame.now_utc,contract.original_deadline_utc,frame.envelope.identity.operation_id)
    except MissingProductionOriginalV1 as missing:
        return stage_result_v1(frame,'d11',ASSESSMENT_OPERATION,request,coverage='waiting_for_original',missing=missing.missing_inputs)
    stage=stage_result_v1(frame,'d11',ASSESSMENT_OPERATION,request,provenance={'phase_assessment':value,'observer_asset':observer},
        receiver_events=(('d11','actual_artifact_phase_assessment_available'),))
    from dataclasses import replace
    from ..runtime_contracts import DomainProposal,DependencySet
    from .d11_types import D11RuntimeProvider,D11_PROPOSAL_SCHEMA
    return replace(stage,proposals=(DomainProposal('d11',D11_PROPOSAL_SCHEMA,D11RuntimeProvider().descriptor.request_schema_hash,
        frame.envelope,(),DependencySet(),(),()),))


def read_current_artifact_phase_assessment_v1(db,*,namespace,original_ref,issuer,now_utc,owner_guard,installed_bundle):
    value,_=_original(db,namespace=namespace,kind=ASSESSMENT_KIND,ref=original_ref,issuer=issuer)
    contract=readonly_current_artifact_phase_postcondition_contract_v1(db,namespace=namespace,selector=value.request.selector,
        issuer=issuer,now_utc=now_utc,owner_guard=owner_guard,installed_bundle=installed_bundle)
    _,adoption,record,file_original,readback=_assessment_inputs_v1(db,request=value.request,contract=contract,issuer=issuer)
    if (value.contract_digest,value.owner_guard,value.readback,value.file_result_digest,value.source_head.key.token,
            value.source_head.revision,value.source_value_digest)!=(contract.digest,owner_guard,readback,canonical_digest(file_original),
                adoption.content.content.ref,adoption.content.content.revision,adoption.content.content.digest):
        raise ValueError('assessment changed current content Source/file version/hash/contract/Owner')
    policy,_=_original(db,namespace=namespace,kind=POLICY_KIND,ref=contract.policy_ref,issuer=issuer)
    observer=None
    if policy.request.observer_policy_ref is not None:
        from ..host.artifact_phase_observer_policy_v2 import require_current_artifact_phase_observer_v2
        observer=require_current_artifact_phase_observer_v2(installed_bundle)
    from .artifact_phase_observation_result_v1 import read_artifact_phase_semantic_observations_v1
    semantic=read_artifact_phase_semantic_observations_v1(db,namespace=namespace,selector=value.request.selector,
        contract=contract,observer_original_refs=value.request.observer_original_refs,issuer=issuer,
        now_utc=now_utc,owner_guard=owner_guard,installed_bundle=installed_bundle) if observer is not None else {}
    expected=_evaluate_conditions_v1(policy=policy,contract=contract,selector=value.request.selector,text=record.text,
        readback=readback,observer=observer,semantic_observations=semantic)
    if expected!=value.results or now_utc>=value.original_deadline_utc or value.assessed_at_utc>now_utc:
        raise ValueError('assessment observer/current evidence/deadline changed')
    return value


def artifact_phase_assessment_original_ref_v1(selector):
    if type(selector) is not ArtifactDraftPhaseSelectorV2 or selector.generation:
        raise TypeError('assessment locator is fixed by the actual registered check phase')
    return 'artifact-phase-assessment:'+selector.identity_digest[:48]


def decode_artifact_phase_postcondition_original_v1(kind,raw):
    from .artifact_phase_observation_v1 import KIND as OBSERVATION_KIND,observation_basis_from_wire_v1
    if kind==OBSERVATION_KIND:return observation_basis_from_wire_v1(raw)
    if kind == PREPARATION_PARENT_KIND_V1:
        return _preparation_parent_from_wire_v1(raw)
    if kind == APPROVAL_KIND_V2:
        return _standing_approval_from_wire_v2(raw)
    classes={POLICY_KIND:ArtifactPhasePostconditionPolicyOriginalV1,CONTRACT_KIND:ArtifactPhasePostconditionContractV1,
        ASSESSMENT_KIND:ArtifactPhaseAssessmentOriginalV1}
    if kind not in classes:raise ValueError('unregistered artifact postcondition original')
    value=_decode(raw,classes[kind])
    if plain_v1(value)!=raw:raise ValueError('postcondition original is noncanonical')
    return value


def _history_life_payload_point_v2(db,columns,*,namespace,kind,ref,issuer=None,read_original=None):
    """Read through the actual issuer or the C09 caller's immutable join lookup.

    A historical join lookup supplies facts for validation, never current Source
    access or execution permission. Live paths retain their actual signed reader.
    """
    if issuer is not None:
        if read_original is not None:
            raise ValueError('historical lookup cannot replace the actual live issuer')
        from ..authority_service.artifact_model_source_read_v3 import artifact_model_life_payload_point_v3
        return artifact_model_life_payload_point_v3(db,columns,namespace=namespace,kind=kind,ref=ref,issuer=issuer)
    if read_original is None:
        raise MissingProductionOriginalV1('actual_signed_reader_or_C09_historical_join_lookup')
    saved=read_original((namespace,kind,ref))
    if saved is None:return None
    operation_id,_value,raw,digest=saved
    if canonical_digest(raw)!=digest:
        raise ValueError('historical join lookup changed its exact canonical original')
    from .domain_production_read_plans_v1 import _committed
    _committed(db,namespace,operation_id)
    data={'payload_json':canonical_serialize(raw),'payload_digest':digest,'producing_operation_id':operation_id}
    return tuple(data[name]for name in columns)


def require_artifact_phase_postcondition_history_v1(db,*,namespace,kind,original_ref,producing_operation_id,raw,issuer=None,read_original=None,read_d07_original=None):
    from .domain_background_read_v3 import background_json_loads_v3, background_json_digest_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .artifact_phase_observation_v1 import KIND as OBSERVATION_KIND,require_artifact_phase_observation_basis_history_v1
    if kind==OBSERVATION_KIND:
        return require_artifact_phase_observation_basis_history_v1(db,namespace=namespace,original_ref=original_ref,
            producing_operation_id=producing_operation_id,raw=raw)
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3,artifact_model_life_payload_point_v3,artifact_model_task_preparation_operations_v3
    if kind == PREPARATION_PARENT_KIND_V1:
        return _preparation_parent_history_v1(db, namespace=namespace, original_ref=original_ref,
            producing_operation_id=producing_operation_id, raw=raw)
    if kind == APPROVAL_KIND_V2:
        return _standing_approval_history_v2(db, namespace=namespace, original_ref=original_ref,
            producing_operation_id=producing_operation_id, raw=raw)
    value=decode_artifact_phase_postcondition_original_v1(kind,raw)
    operation={POLICY_KIND:POLICY_OPERATION,CONTRACT_KIND:CONTRACT_OPERATION,ASSESSMENT_KIND:ASSESSMENT_OPERATION}[kind]
    domain='d11' if kind==ASSESSMENT_KIND else 'd08'
    adopted=read_adopted_domain_operation_v1(db,namespace,producing_operation_id)
    field={POLICY_KIND:'postcondition_policy',CONTRACT_KIND:'postcondition_contract',ASSESSMENT_KIND:'phase_assessment'}[kind]
    if (value.namespace!=namespace or value.original_ref!=original_ref or value.registration_operation_id!=producing_operation_id
            or adopted is None or (adopted['domain'],adopted['operation_kind'])!=(domain,operation)
            or adopted['payload']['coverage']!='complete' or adopted['payload']['provenance'].get(field)!=raw
            or adopted['receipt'].write_versions):
        raise ValueError('postcondition original has no exact empty-member actual W01 producer')
    fixed_id=(artifact_phase_policy_registration_operation_id_v1(value) if kind==POLICY_KIND else
        artifact_phase_contract_registration_operation_id_v1(value.selector) if kind==CONTRACT_KIND else
        artifact_phase_assessment_operation_id_v1(value.request.selector))
    if producing_operation_id!=fixed_id:raise ValueError('postcondition history producer changed its original fixed once ID')
    if kind==POLICY_KIND:
        if type(value) is ArtifactPhasePostconditionPolicyOriginalV2:
            _require_amended_policy_history_v2(db,namespace=namespace,value=value,adopted=adopted, issuer=issuer, read_original=read_original)
        if adopted['payload']['request']!=plain_v1(value.request):raise ValueError('policy registered caller rules instead of exact selectors')
        if not adopted['payload']['now_utc']<value.original_deadline_utc:
            raise ValueError('policy was not actually registered within its fixed original lifetime')
        from .d11_life_preparation_v1 import TABLE
        root_row=_history_life_payload_point_v2(db,('payload_json', 'payload_digest'),namespace=namespace,kind='draft_root_capability',ref=value.request.task.root_registration_ref,issuer=issuer, read_original=read_original)
        objective_row=_history_life_payload_point_v2(db,('payload_json', 'payload_digest'),namespace=namespace,kind='artifact_task_objective',ref=value.objective_ref,issuer=issuer, read_original=read_original)
        if root_row is None or objective_row is None or objective_row[1]!=value.objective_digest:
            raise ValueError('policy history lost fixed registered task/Root originals')
        from .d11_offline_originals_v1 import _utc
        if value.original_deadline_utc>min(background_json_loads_v3(objective_row[0])['valid_until_utc'],_utc(background_json_loads_v3(root_row[0])['valid_until_utc']).timestamp()):
            raise ValueError('policy history exceeded fixed registered task/Root absolute lifetime')
    if kind==CONTRACT_KIND:
        if adopted['payload']['request']!=plain_v1(RegisterArtifactPhasePostconditionContractRequestV1(value.selector,value.policy_ref)):
            raise ValueError('contract actual registration request differs')
        from .d11_life_preparation_v1 import TABLE
        policy_raw=_history_life_payload_point_v2(db,('payload_json', 'payload_digest', 'producing_operation_id'),namespace=namespace,kind=POLICY_KIND,ref=value.policy_ref,issuer=issuer, read_original=read_original)
        if policy_raw is None or policy_raw[1]!=value.policy_digest:raise ValueError('contract has no original preDecision policy')
        policy=decode_artifact_phase_postcondition_original_v1(POLICY_KIND,background_json_loads_v3(policy_raw[0]))
        if ((value.conditions,value.owner_guard,value.goal_head,value.goal_digest,value.plan_head,value.plan_digest,value.source_head,value.source_value_digest)!=
                (policy.conditions,policy.owner_guard,policy.goal_head,policy.goal_digest,policy.plan_head,policy.plan_digest,policy.source_head,policy.source_value_digest)
                or (value.selector.task,value.selector.method_ref)!=(policy.request.task,policy.request.method_ref)
                or value.original_deadline_utc>policy.original_deadline_utc):
            raise ValueError('contract changed frozen required conditions/Owner/deadline')
        from .domain_production_originals_v1 import TABLE as DOMAIN_TABLE
        candidate_rows=_artifact_receipt_sql_v1(db,"SELECT operation_id FROM "+DOMAIN_TABLE+" WHERE bot=? AND persona=? AND domain='d08' "
            "AND operation_kind='prepare_personal_candidates_v1' AND original_digest=?",(*namespace.as_tuple,value.selected_preparation_digest)).fetchall()
        if len(candidate_rows)!=1:raise ValueError('contract lost actual selected preparation original')
        candidate=read_adopted_domain_operation_v1(db,namespace,candidate_rows[0][0])
        from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1,ArtifactPhaseCandidateBindingV3
        prepared=_decode(candidate['payload']['provenance']['prepared_candidates'],PreparedPersonalCandidateSetV1)
        if (value.original_deadline_utc!=min(policy.original_deadline_utc,prepared.need.original_deadline_utc)
                or not adopted['payload']['now_utc']==value.registered_at_utc<value.original_deadline_utc):
            raise ValueError('contract history changed registered whole-method absolute lifetime or original registration time')
        chosen=tuple(row for row in prepared.candidates if row.binding.digest==value.selected_binding_digest)
        if (len(chosen)!=1 or type(chosen[0].binding) is not ArtifactPhaseCandidateBindingV3
                or (chosen[0].binding.postcondition_policy_ref,chosen[0].binding.postcondition_policy_digest)!=(value.policy_ref,value.policy_digest)
                or (chosen[0].binding.task,chosen[0].binding.method_ref,chosen[0].binding.phase_index,chosen[0].binding.phase_kind)!=
                    (value.selector.task,value.selector.method_ref,value.selector.phase_index,value.selector.phase_kind)
                or value.selected_preparation_ref!='d08-current:'+value.selected_preparation_digest[:48]):
            raise ValueError('contract lost the policy committed by actual selected binding')
        decision=artifact_model_graph_point_v3(db,('event_id', 'value', 'valid'),token=value.selector.decision_ref,revision=value.selector.decision_revision)
        if decision is None or decision[2]!=1 or background_json_digest_v3(decision[1],background_json_loads_v3(decision[1]))!=value.selector.decision_digest:
            raise ValueError('contract actual adopted Decision history differs')
        selection=read_adopted_domain_operation_v1(db,namespace,decision[0])
        if selection is None or (selection['domain'],selection['operation_kind'])!=('d08','select_personal_step_v2') or (
                selection['payload']['provenance']['prepared_candidates_operation_id']!=prepared.preparation_operation_id
                or background_json_loads_v3(decision[1])['chosen_action_ref']!=chosen[0].future_identity.action_ref):
            raise ValueError('contract has no actually adopted selection of its binding')
        policy_seq=_artifact_receipt_sql_v1(db,'SELECT commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
            (*namespace.as_tuple,policy_raw[2])).fetchone()
        if policy_seq is None or not policy_seq[0]<candidate['receipt'].commit_seq<selection['receipt'].commit_seq<adopted['receipt'].commit_seq:
            raise ValueError('contract was not actually registered after preDecision policy and adopted Decision')
        model_rows=artifact_model_task_preparation_operations_v3(db,namespace,value.selector.task.c02_operation_id,legacy_reader=lambda:_artifact_receipt_sql_v1(db,"SELECT producing_operation_id FROM "+TABLE+" WHERE bot=? AND persona=? AND kind='c4_phase_prepared' "
            "AND json_extract(payload_json,'$.selector.task.c02_operation_id')=?",(*namespace.as_tuple,value.selector.task.c02_operation_id)).fetchall())
        for (op,) in model_rows:
            seq=_artifact_receipt_sql_v1(db,'SELECT commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,op)).fetchone()
            if seq is None or seq[0]<=adopted['receipt'].commit_seq:raise ValueError('contract was registered after generation preparation')
    if kind==ASSESSMENT_KIND:
        if adopted['payload']['request']!=plain_v1(value.request):raise ValueError('assessment actual selectors differ')
        from .d11_life_preparation_v1 import TABLE
        contract_row=_history_life_payload_point_v2(db,('payload_json', 'payload_digest', 'producing_operation_id'),namespace=namespace,kind=CONTRACT_KIND,ref=value.request.contract_ref,issuer=issuer, read_original=read_original)
        if contract_row is None or contract_row[1]!=value.contract_digest:raise ValueError('assessment lost frozen contract original')
        contract=decode_artifact_phase_postcondition_original_v1(CONTRACT_KIND,background_json_loads_v3(contract_row[0]))
        require_artifact_phase_postcondition_history_v1(db,namespace=namespace,kind=CONTRACT_KIND,original_ref=contract.original_ref,
            producing_operation_id=contract_row[2],raw=background_json_loads_v3(contract_row[0]), issuer=issuer, read_original=read_original)
        policy_row=_history_life_payload_point_v2(db,('payload_json',),namespace=namespace,kind=POLICY_KIND,ref=contract.policy_ref,issuer=issuer, read_original=read_original)
        policy=decode_artifact_phase_postcondition_original_v1(POLICY_KIND,background_json_loads_v3(policy_row[0]))
        from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
        if (foreground_artifact_phase_group_identity_v2(value.content_selector)!=foreground_artifact_phase_group_identity_v2(value.request.selector)
                or foreground_artifact_phase_group_identity_v2(contract.selector)!=foreground_artifact_phase_group_identity_v2(value.request.selector)
                or value.content_selector.phase_index!=value.request.selector.phase_index-1 or not value.content_selector.generation
                or value.owner_guard!=contract.owner_guard or value.original_deadline_utc!=contract.original_deadline_utc
                or not contract.registered_at_utc<=value.assessed_at_utc<value.original_deadline_utc):
            raise ValueError('assessment crossed actual content phase/contract/Owner/deadline')
        from .d11_life_contract_v1 import life_from_wire_v1,D11LifeTerminalV1
        from .d11_life_adoption_v1 import require_draft_terminal_readback_v1
        # This history seam verifies bytes and actual CAS joins. Installed
        # current readers and C09 authenticate the corresponding signatures.
        file_row=_history_life_payload_point_v2(db,('payload_json', 'payload_digest', 'producing_operation_id'),namespace=namespace,kind='adopted_life',ref=value.request.file_result_ref,issuer=issuer, read_original=read_original)
        if file_row is None:raise ValueError('assessment lost actual adopted file original')
        file_original=background_json_loads_v3(file_row[0])
        if canonical_digest(file_original)!=file_row[1] or canonical_serialize(file_original)!=file_row[0]:raise ValueError('assessment file original bytes changed')
        from .d11_life_terminal_v1 import validate_adopted_life_member_history_v1
        validate_adopted_life_member_history_v1(db,value=file_original,namespace=namespace,result_ref=value.request.file_result_ref,producing_operation_id=file_row[2])
        terminal=life_from_wire_v1(file_original['terminal'],D11LifeTerminalV1)
        from .d11_life_preparation_v1 import life_prepared_from_wire_v1
        prepared_row=_history_life_payload_point_v2(db,('payload_json', 'payload_digest'),namespace=namespace,kind='prepared',ref=terminal.binding.prepared_original_ref,issuer=issuer, read_original=read_original)
        if prepared_row is None:raise ValueError('assessment lost actual file preparation')
        file_prepared=life_prepared_from_wire_v1(background_json_loads_v3(prepared_row[0]))
        if file_prepared.digest!=prepared_row[1] or file_prepared.digest!=file_original['prepared_digest']:
            raise ValueError('assessment file preparation digest changed')
        readback=require_draft_terminal_readback_v1(prepared=file_prepared,terminal=terminal)
        from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v2
        ids=artifact_draft_file_ids_v2(value.content_selector)
        if (readback!=value.readback or canonical_digest(file_original)!=value.file_result_digest
                or (file_prepared.plan.operation_id,file_prepared.plan.attempt_id,file_prepared.plan.effect_id,file_prepared.plan.execution_call_id)!=
                    (ids['action_operation'],ids['attempt'],ids['effect'],ids['execution_call'])):
            raise ValueError('assessment changed independently adopted actual file readback/phase once IDs')
        source=artifact_model_graph_point_v3(db,('value', 'valid'),token=value.source_head.key.token,revision=value.source_head.revision)
        from ..memory_types import SourceRecord
        if source is None or source[1]!=1 or background_json_digest_v3(source[0],background_json_loads_v3(source[0]))!=value.source_value_digest:
            raise ValueError('assessment actual content Source historical bytes differ')
        text=SourceRecord.from_dict(background_json_loads_v3(source[0])).text
        from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2,artifact_draft_input_from_wire_v2,ArtifactDraftInputV3
        model_ids=artifact_draft_model_ids_v2(value.content_selector)
        frozen_row=_history_life_payload_point_v2(db,('payload_json', 'payload_digest'),namespace=namespace,kind='c4_phase_frozen',ref=model_ids['frozen'],issuer=issuer, read_original=read_original)
        if frozen_row is None:raise ValueError('assessment has no actual frozen generation contract commitment')
        frozen=artifact_draft_input_from_wire_v2(background_json_loads_v3(frozen_row[0]))
        if (type(frozen) is not ArtifactDraftInputV3 or frozen.digest!=frozen_row[1]
                or (frozen.selector,frozen.postcondition_contract_ref,frozen.postcondition_contract_digest)!=(value.content_selector,contract.original_ref,contract.digest)
                or (file_prepared.plan.content.content.ref,file_prepared.plan.content.content.revision,file_prepared.plan.content.content.digest)!=
                    (value.source_head.key.token,value.source_head.revision,value.source_value_digest)):
            raise ValueError('assessment changed actual frozen generation/file/Source contract lineage')
        asset=adopted['payload']['provenance'].get('observer_asset')
        from ..host.artifact_phase_observer_policy_v2 import ArtifactPhaseObserverPolicyV2
        observer=None if asset is None else _decode(asset,ArtifactPhaseObserverPolicyV2)
        from .artifact_phase_observation_result_v1 import read_artifact_phase_semantic_observations_v1
        semantic=read_artifact_phase_semantic_observations_v1(db,namespace=namespace,selector=value.request.selector,
            contract=contract,observer_original_refs=value.request.observer_original_refs,issuer=issuer,
            read_life_original=read_original,read_d07_original=read_d07_original) if observer is not None else {}
        if observer is None and value.request.observer_original_refs:
            raise ValueError('historical assessment has undeclared independent observer originals')
        expected=_evaluate_conditions_v1(policy=policy,contract=contract,selector=value.request.selector,text=text,
            readback=readback,observer=observer,semantic_observations=semantic)
        if expected!=value.results:raise ValueError('assessment did not actually observe each frozen required condition')
    return value


def require_artifact_phase_assessment_history_v1(db,*,namespace,original_ref,producing_operation_id,raw,issuer=None,read_original=None):
    return require_artifact_phase_postcondition_history_v1(db,namespace=namespace,kind=ASSESSMENT_KIND,
        original_ref=original_ref,producing_operation_id=producing_operation_id,raw=raw, issuer=issuer, read_original=read_original)


def record_artifact_phase_postcondition_after_cas_v1(db, *, frame, stage, receipt, issuer):
    from .foreground_command_writer_outputs_v3 import record_foreground_writer_life_v3
    from .artifact_phase_observation_v1 import OPERATION as OBSERVATION_OPERATION, record_artifact_phase_observation_after_cas_v1
    if stage.operation_kind == OBSERVATION_OPERATION:
        return record_artifact_phase_observation_after_cas_v1(db, frame=frame, stage=stage, receipt=receipt, issuer=issuer)
    operations = {PREPARATION_PARENT_OPERATION_V1: (PREPARATION_PARENT_KIND_V1, 'candidate_preparation_parent'), APPROVAL_OPERATION_V2: (APPROVAL_KIND_V2, 'standing_predecision_approval'), POLICY_OPERATION: (POLICY_KIND, 'postcondition_policy'), CONTRACT_OPERATION: (CONTRACT_KIND, 'postcondition_contract'), ASSESSMENT_OPERATION: (ASSESSMENT_KIND, 'phase_assessment')}
    if stage.operation_kind not in operations or stage.coverage != 'complete':
        return None
    kind, field = operations[stage.operation_kind]
    if receipt.status != 'committed' or receipt.operation_id != stage.operation_id:
        raise ValueError('postconditions require actual same-transaction W01 receipt')
    ns = frame.envelope.authority.namespace
    adopted = read_adopted_domain_operation_v1(db, ns, stage.operation_id)
    if adopted is None or adopted['original_digest'] != stage.original_digest or adopted['receipt'] != receipt:
        raise ValueError('postcondition producer was not adopted by actual W01 CAS')
    raw = adopted['payload']['provenance'][field]
    value = decode_artifact_phase_postcondition_original_v1(kind, raw)
    require_artifact_phase_postcondition_history_v1(db, namespace=ns, kind=kind, original_ref=value.original_ref, producing_operation_id=stage.operation_id, raw=raw, issuer=issuer)
    return record_foreground_writer_life_v3(db, issuer=issuer, namespace=ns, kind=kind, ref=value.original_ref, operation_id=stage.operation_id, value=value, recorder=record_artifact_phase_postcondition_after_cas_v1, frame=frame, actual_receipt=receipt)


def read_plan_artifact_phase_postconditions_v1(db,*,namespace,request,installed_readers):
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    if type(request)is PrepareArtifactPhaseObservationRequestV1:
        from .artifact_phase_observation_v1 import read_plan_prepare_artifact_phase_observation_v1
        return read_plan_prepare_artifact_phase_observation_v1(db,namespace=namespace,request=request,installed_readers=installed_readers)
    if type(request) is FreezeArtifactCandidatePreparationRequestV1:
        return read_plan_artifact_candidate_preparation_parent_v1(db, namespace=namespace,
            request=request, installed_readers=installed_readers)
    if type(request) is ApproveArtifactStandingPredecisionRequestV2:
        return read_plan_artifact_standing_predecision_approval_v2(db, namespace=namespace,
            request=request, installed_readers=installed_readers)
    readers=_readers(installed_readers)
    keys=[owner_grant_key(*namespace.as_tuple)];roots=[];originals=[];types=[]
    if type(request) is RegisterArtifactPhasePostconditionPolicyRequestV1:
        from .artifact_task_text_extent_v1 import read_plan_artifact_task_text_extent_v1,RegisterArtifactTaskTextExtentRequestV1
        goal=AtomKey.from_token(request.goal_ref)
        row=_artifact_receipt_sql_v1(db,'SELECT revision FROM graph_atoms WHERE token=? AND valid=1',(goal.token,)).fetchone()
        keys.extend((goal,AtomKey.from_token(request.plan_ref),AtomKey.from_token(request.task.cycle_job_ref)))
        originals.extend((request.extent_original_ref,request.task.root_registration_ref))
        if row:
            plan=read_plan_artifact_task_text_extent_v1(db,namespace=namespace,
                request=RegisterArtifactTaskTextExtentRequestV1(request.goal_ref,row[0]),installed_readers=readers.current())
            keys.extend(plan.exact_keys);roots.extend(plan.source_roots);originals.extend(plan.required_original_refs);types.extend(plan.fixed_type_ids)
    elif type(request) is RegisterArtifactPhasePostconditionContractRequestV1:
        from .d11_artifact_draft_model_v1 import _artifact_phase_selection_locator_v2
        from .d08_personal_candidate_v1 import read_plan_personal_candidates_v1
        locator,_,_=_artifact_phase_selection_locator_v2(db,request.selector)
        cycle_key=AtomKey.from_token(request.selector.task.cycle_job_ref)
        plan=read_plan_personal_candidates_v1(db,namespace=namespace,activity_id=cycle_key.owner.subject,request=locator,
            installed_readers=readers.current())
        keys.extend(plan.exact_keys);roots.extend(plan.source_roots);originals.extend(plan.required_original_refs);types.extend(plan.fixed_type_ids)
        originals.append(request.policy_ref)
    elif type(request) is ObserveArtifactPhasePostconditionsRequestV1:
        plan=read_plan_current_artifact_phase_postcondition_contract_v1(db,namespace=namespace,selector=request.selector,installed_readers=readers)
        keys.extend(plan.exact_keys);roots.extend(plan.source_roots);originals.extend(plan.required_original_refs);types.extend(plan.fixed_type_ids)
        originals.extend((request.file_result_ref,request.selector.prev_phase_original_ref))
        from .d11_artifact_draft_content_v1 import artifact_draft_phase_verification_from_wire_v2,ArtifactDraftPhaseVerifiedOriginalV2
        previous=_read(db,issuer=readers.issuer,namespace=namespace,kind='c4_phase_verified',ref=request.selector.prev_phase_original_ref)
        if previous is not None:
            generation=artifact_draft_phase_verification_from_wire_v2(previous[0],ArtifactDraftPhaseVerifiedOriginalV2)
            from .d08_personal_candidate_v1 import _read_plan_completed_phase_action_transition_v1
            phase_plan=_read_plan_completed_phase_action_transition_v1(db,namespace=namespace,
                phase_selector=generation.selector,installed_readers=readers.current())
            keys.extend(phase_plan.exact_keys);roots.extend(phase_plan.source_roots);originals.extend(phase_plan.required_original_refs)
            originals.extend(request.observer_original_refs)
        if request.observer_original_refs:
            from .artifact_phase_observation_result_v1 import read_artifact_phase_semantic_observations_v1
            from .artifact_phase_observation_v1 import read_artifact_phase_observation_basis_v1
            contract,_=_original(db,namespace=namespace,kind=CONTRACT_KIND,ref=request.contract_ref,issuer=readers.issuer)
            observed=read_artifact_phase_semantic_observations_v1(db,namespace=namespace,selector=request.selector,
                contract=contract,observer_original_refs=request.observer_original_refs,issuer=readers.issuer)
            for actual in observed.values():
                basis=read_artifact_phase_observation_basis_v1(db,namespace=namespace,original_ref=actual.basis_ref,issuer=readers.issuer)
                keys.extend(head.key for head,_ in basis.source_heads);roots.extend(basis.source_refs)
                keys.extend(AtomKey.from_token(ref)for ref in actual.interpretation_refs)
                originals.extend((basis.original_ref,basis.ids['question'],*actual.interpretation_refs))
    else:raise TypeError('postcondition read plan accepts only registered closed selector requests')
    # Policy/contract original lookup exposes only exact registered current keys.
    refs=[request.policy_ref] if type(request) is RegisterArtifactPhasePostconditionContractRequestV1 else []
    for ref in refs:
        row=_read(db,issuer=readers.issuer,namespace=namespace,kind=POLICY_KIND,ref=ref)
        if row:
            policy=decode_artifact_phase_postcondition_original_v1(POLICY_KIND,row[0])
            keys.extend((policy.goal_head.key,policy.plan_head.key,policy.source_head.key));roots.append(policy.source_head.key.token)
            originals.extend((policy.objective_ref,policy.request.extent_original_ref))
    return production_read_plan_v1(types,keys,roots,originals)


def read_plan_current_artifact_phase_postcondition_contract_v1(db,*,namespace,selector,installed_readers):
    readers=_readers(installed_readers)
    from .d11_artifact_draft_model_v1 import _read_artifact_phase_selected_originals_v2
    candidates,chosen,original=_read_artifact_phase_selected_originals_v2(db,selector=selector,issuer=readers.issuer)
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV3
    if type(chosen.binding) is not ArtifactPhaseCandidateBindingV3:raise MissingProductionOriginalV1('actual_V3_postcondition_read_plan')
    keys=[owner_grant_key(*namespace.as_tuple),AtomKey.from_token(selector.decision_ref),candidates.goal_head.key,candidates.plan_head.key]
    originals=[chosen.binding.postcondition_policy_ref,'d08-current:'+original['original_digest'][:48]]
    roots=[]
    policy=_read(db,issuer=readers.issuer,namespace=namespace,kind=POLICY_KIND,ref=chosen.binding.postcondition_policy_ref)
    if policy:
        value=decode_artifact_phase_postcondition_original_v1(POLICY_KIND,policy[0])
        keys.append(value.source_head.key);roots.append(value.source_head.key.token)
        originals.extend((value.objective_ref,value.request.extent_original_ref,value.request.task.root_registration_ref))
    ref=artifact_phase_postcondition_contract_ref_v1(selector)
    originals.append(ref)
    return production_read_plan_v1((),keys,roots,originals)


def read_plan_artifact_phase_assessment_v1(db,*,namespace,selector,installed_readers):
    readers=_readers(installed_readers)
    ref=artifact_phase_assessment_original_ref_v1(selector)
    current=read_plan_current_artifact_phase_postcondition_contract_v1(db,namespace=namespace,selector=selector,installed_readers=readers)
    row=_read(db,issuer=readers.issuer,namespace=namespace,kind=ASSESSMENT_KIND,ref=ref)
    if row is None:return production_read_plan_v1(current.fixed_type_ids,current.exact_keys,current.source_roots,(*current.required_original_refs,ref))
    value=decode_artifact_phase_postcondition_original_v1(ASSESSMENT_KIND,row[0])
    plan=read_plan_artifact_phase_postconditions_v1(db,namespace=namespace,request=value.request,installed_readers=readers)
    return production_read_plan_v1(plan.fixed_type_ids,plan.exact_keys,plan.source_roots,(*plan.required_original_refs,ref))


def read_current_artifact_phase_postcondition_original_ref_v1(db,*,namespace,original_ref,issuer):
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .d11_life_preparation_v1 import TABLE
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    rows=_artifact_receipt_sql_v1(db,"SELECT kind FROM "+TABLE+" WHERE bot=? AND persona=? AND original_ref=? AND kind IN (?,?,?,?,?,?)",
        (*namespace.as_tuple,original_ref,POLICY_KIND,CONTRACT_KIND,ASSESSMENT_KIND,APPROVAL_KIND_V2,PREPARATION_PARENT_KIND_V1,'artifact_phase_observation_basis_v1')).fetchall()
    if not rows:return None
    if len(rows)!=1:raise ValueError('postcondition original selector is ambiguous')
    value,_=_original(db,namespace=namespace,kind=rows[0][0],ref=original_ref,issuer=issuer)
    return ProductionOriginalRefV1('d11.life_'+rows[0][0],original_ref,value.digest)




def _empty_postcondition_stage_v1(stage,frame,readers):
    from dataclasses import replace
    from ..runtime_contracts import DomainProposal,DependencySet
    if stage.operation_kind not in {POLICY_OPERATION,CONTRACT_OPERATION,APPROVAL_OPERATION_V2,PREPARATION_PARENT_OPERATION_V1} or stage.domain!='d08' or stage.proposals:
        raise ValueError('postcondition empty W01 proposal has another producer/member scope')
    registration=readers.graph._GraphCoordinator__providers[stage.domain]
    return replace(stage,proposals=(DomainProposal(stage.domain,registration[1],registration[2],frame.envelope,
        (),DependencySet(),(),()),))


def artifact_phase_postcondition_contract_ref_v1(selector):
    if type(selector) is not ArtifactDraftPhaseSelectorV2:raise TypeError('contract reference requires actual whole-method selector')
    return 'artifact-phase-postcondition-contract:'+canonical_digest((selector.task,selector.decision_ref,selector.decision_digest,selector.method_ref))[:48]


def artifact_phase_contract_registration_operation_id_v1(selector):
    return artifact_phase_postcondition_contract_ref_v1(selector)+':register'


def artifact_phase_assessment_operation_id_v1(selector):
    return artifact_phase_assessment_original_ref_v1(selector)+':observe'


def artifact_phase_policy_registration_operation_id_v1(policy):
    if type(policy) not in {ArtifactPhasePostconditionPolicyOriginalV1,ArtifactPhasePostconditionPolicyOriginalV2}:raise TypeError('policy once ID requires actual policy original material')
    return policy.original_ref+':register'


def read_current_artifact_phase_postcondition_policy_basis_v1(db,*,frame,request,installed_readers):
    """Readonly prospective material from an existing genuine current scope.

    The returned material grants nothing. Registration recomputes this exact
    fixed basis and signs an original only after its actual W01 commit.
    """
    from dataclasses import replace
    if type(request) is not RegisterArtifactPhasePostconditionPolicyRequestV1:
        raise TypeError('policy precompute accepts only actual task selectors')
    readers=_readers(installed_readers);graph=readers.graph
    if (db is not graph._GraphCoordinator__store._db or not db.in_transaction
            or not graph._GraphCoordinator__store._lock._is_owned()):
        raise TypeError('policy precompute requires the existing actual Graph current read scope')
    value=_policy_basis_v1(db,frame=frame,request=request,readers=readers,
        registration_operation_id=frame.envelope.identity.operation_id)
    value=replace(value,registration_operation_id=artifact_phase_policy_registration_operation_id_v1(value))
    stored=_read(db,issuer=readers.issuer,namespace=value.namespace,kind=POLICY_KIND,ref=value.original_ref)
    if stored is not None:
        actual,_=_original(db,namespace=value.namespace,kind=POLICY_KIND,ref=value.original_ref,issuer=readers.issuer)
        if actual!=value:raise ValueError('same policy once ID cannot update original basis or expiry')
        return actual
    return value


def read_current_artifact_phase_policy_registration_operation_id_v1(db,*,frame,request,installed_readers):
    return artifact_phase_policy_registration_operation_id_v1(
        read_current_artifact_phase_postcondition_policy_basis_v1(db,frame=frame,request=request,installed_readers=installed_readers))


def pre_read_artifact_phase_postcondition_policy_v1(graph,bootstrap,*,authority,lease,request,installed_readers):
    """Read PolicyID under the ordinary live Owner read fence, before W01.

    The actual read permit creates the frozen frame. No execution lease, write
    intent, candidate, quote or signed Policy original is created here.
    """
    from ..graph_coordinator import GraphCoordinator,OwnerLeaseBindingV1
    from ..runtime_contracts import (AuthorityContext,CommandEnvelope,OperationIdentity,VersionGuard,QueryEpoch,
        SourceQualification,RUNTIME_SCHEMA)
    from .domain_production_frame_v1 import freeze_domain_production_frame_v1
    from .domain_production_read_plans_v1 import read_current_domain_original_refs_v1,read_current_domain_policy_refs_v1
    from .first_ingress_v2 import trusted_upper
    from .jobs import get_job
    from .d11_offline_originals_v1 import _utc
    import time
    if type(graph) is not GraphCoordinator or type(authority) is not AuthorityContext or type(request) is not RegisterArtifactPhasePostconditionPolicyRequestV1:
        raise TypeError('policy ID preread requires the actual Graph, Owner context and closed selectors')
    graph._admin(bootstrap)
    readers=_readers(installed_readers)
    if readers.graph is not graph or authority.namespace!=request.task.namespace:
        raise ValueError('policy preread changed actual installed Graph/task namespace')
    binding=graph._GraphCoordinator__owner_leases.get(lease)
    session=graph._GraphCoordinator__owner_session_proofs.get(lease)
    if (type(binding) is not OwnerLeaseBindingV1 or session is None or authority.issuer_domain!='d12'
            or not {'workbench.read','workbench.create'}<=binding.capabilities):
        raise ValueError('policy preread requires the existing independently authenticated Owner workbench channel')
    graph._authorize(lease,authority,frozenset({'d06','d08','d11','d12'}),owner_read=True)
    store=graph._GraphCoordinator__store;port=graph._GraphCoordinator__content_fence_v2
    context={}
    def observe(scope):
        if scope.operation!='read' or graph._GraphCoordinator__owner_leases.get(lease)!=binding or graph._GraphCoordinator__owner_session_proofs.get(lease)!=session:
            raise ValueError('policy preread lost its exact actual Owner read permit/session')
        now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
        if not context:
            context.update(scope=scope,now=now)
        elif context['scope']!=scope or now<context['now'] or now>=context['basis'].original_deadline_utc:
            raise ValueError('policy preread scope or fresh trusted clock expired while observing fixed basis')
        return scope
    def read():
        db=store._db
        if db.in_transaction:raise ValueError('policy preread requires its own readonly SQL snapshot')
        db.execute('BEGIN')
        try:
            scope,now=context['scope'],context['now']
            cycle=get_job(db,AtomKey.from_token(request.task.cycle_job_ref).name)
            if (cycle.bot_id,cycle.persona_id)!=request.task.namespace.as_tuple:
                raise ValueError('policy preread task budget namespace changed')
            plan=read_plan_artifact_phase_postconditions_v1(db,namespace=request.task.namespace,request=request,installed_readers=readers)
            for key in plan.exact_keys:
                if key.owner.kind not in authority.owner_scope:raise ValueError('policy preread key exceeds current Owner read scope')
            versions=dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
                "AND ref='current' AND kind IN ('scheme','operator','policy')",request.task.namespace.as_tuple).fetchall())
            if set(versions)!={'scheme','operator','policy'}:raise ValueError('policy preread current installed guard versions unavailable')
            originals=read_current_domain_original_refs_v1(db,namespace=request.task.namespace,plan=plan,installed_readers=readers)
            policies=read_current_domain_policy_refs_v1(db,namespace=request.task.namespace,plan=plan,installed_readers=readers)
            deadline=_utc(cycle.deadline_utc).timestamp()
            if now>=deadline:raise MissingProductionOriginalV1('unexpired_actual_task_for_policy_ID_preread')
            envelope=CommandEnvelope(RUNTIME_SCHEMA,
                OperationIdentity(cycle.activity_id,None,scope.operation_id,'read_artifact_phase_postcondition_policy_v1',scope.operation_id,
                    canonical_digest({'input_refs':[]})),authority,
                VersionGuard((),(QueryEpoch(request.task.namespace,'namespace',scope.graph_epoch.revision),),binding.access_epoch,binding.delete_epoch,
                    store._registry.catalogue_hash,versions['scheme'],versions['operator'],versions['policy'],(),(),()),
                SourceQualification((),'derived',None,now,'inference','ineligible',None,'not_applicable'),(),cycle.budget_ref,
                deadline,time.monotonic()+deadline-now,'policy-preread:'+scope.operation_id,())
            frame=freeze_domain_production_frame_v1(graph,db,envelope=envelope,current_owner=binding,scope=scope,plan=plan,now_utc=now,
                observed_originals=originals,installed_policy_refs=policies)
            value=read_current_artifact_phase_postcondition_policy_basis_v1(db,frame=frame,request=request,installed_readers=readers)
            context['basis']=value
            return value
        finally:
            db.rollback()
    return graph._read_v2(authority,read,owner_binding=binding,owner_session_proof=session,fence_observer=observe)


def register_current_artifact_phase_postcondition_policy_v1(graph,bootstrap,*,authority,lease,request,installed_readers):
    """Actual Owner entry: formal readonly ID discovery, then standard W01."""
    value=pre_read_artifact_phase_postcondition_policy_v1(graph,bootstrap,authority=authority,lease=lease,request=request,
        installed_readers=installed_readers)
    from .jobs import get_job
    store=graph._GraphCoordinator__store
    with store._lock:
        cycle=get_job(store._db,AtomKey.from_token(request.task.cycle_job_ref).name)
        activity_id,budget_ref=cycle.activity_id,cycle.budget_ref
    return graph.run_current_domain_operation_v1(authority,lease,operation_kind=POLICY_OPERATION,request=request,
        operation_id=artifact_phase_policy_registration_operation_id_v1(value),activity_id=activity_id,
        audience_ref=authority.audience[0],parent_budget_lease_ref=budget_ref)

APPROVAL_KIND_V2 = "artifact_standing_predecision_approval"
APPROVAL_OPERATION_V2 = "input:approve_artifact_standing_predecision_v2"
_APPROVAL_READERS_KEY_V2 = object()


@dataclass(frozen=True, slots=True)
class ApproveArtifactStandingPredecisionRequestV2:
    approval_original_ref: str

    def __post_init__(self):
        _text(self.approval_original_ref)
        if not self.approval_original_ref.startswith("artifact-standing-approval:"):
            raise ValueError("approval request selects its fixed standing declaration")


@dataclass(frozen=True, slots=True)
class ArtifactStandingPredecisionApprovalOriginalV2:
    request: ApproveArtifactStandingPredecisionRequestV2
    namespace: object
    scope: object
    scope_digest: str
    self_mapping_head: GraphVersion
    self_mapping_digest: str
    self_actor_ref: str
    approver_actor_ref: str
    owner_guard: ProductionOwnerGuardV1
    owner_authorization: object
    installation_id: str
    manifest_digest: str
    profile_id: str
    profile_digest: str
    catalogue_hash: str
    scheme_version: str
    operator_version: str
    policy_version: str
    root_budget_lease_ref: str
    root_budget_grant_digest: str
    root_budget_lease_bound_digest: str
    root_budget_lease_version: int
    observer_bindings: tuple[tuple[str, int, str], ...]
    original_deadline_utc: float
    approved_at_utc: float
    registration_operation_id: str
    schema: str = "d08.artifact-standing-predecision-approval.v2"

    def __post_init__(self):
        from ..runtime_contracts import NamespaceId
        from ..host.authority_profile import AdminArtifactStandingScopeV2, AdminArtifactStandingScopeV3
        from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
        import math
        scope_class = {ArtifactStandingPredecisionApprovalOriginalV2: AdminArtifactStandingScopeV2,
            ArtifactStandingPredecisionApprovalOriginalV3: AdminArtifactStandingScopeV3}.get(type(self))
        schema = {ArtifactStandingPredecisionApprovalOriginalV2: "d08.artifact-standing-predecision-approval.v2",
            ArtifactStandingPredecisionApprovalOriginalV3: "d08.artifact-standing-predecision-approval.v3"}.get(type(self))
        if (scope_class is None or self.schema != schema
                or type(self.request) is not ApproveArtifactStandingPredecisionRequestV2
                or type(self.namespace) is not NamespaceId
                or type(self.scope) is not scope_class
                or type(self.self_mapping_head) is not GraphVersion
                or type(self.owner_guard) is not ProductionOwnerGuardV1
                or type(self.owner_authorization) is not OwnerAuthorizationGuardV1
                or self.owner_authorization.namespace != self.namespace
                or self.scope.self_actor_ref != self.self_actor_ref
                or self.scope.approval_original_ref != self.request.approval_original_ref
                or self.scope_digest != canonical_digest(plain_v1(self.scope))
                or NamespaceId.from_key(self.self_mapping_head.key) != self.namespace
                or self.self_actor_ref == self.approver_actor_ref
                or type(self.root_budget_lease_version) is not int or self.root_budget_lease_version < 1
                or type(self.observer_bindings) is not tuple or len(self.observer_bindings) > 2
                or type(self.original_deadline_utc) not in (int, float)
                or type(self.approved_at_utc) not in (int, float)
                or not math.isfinite(self.original_deadline_utc) or not math.isfinite(self.approved_at_utc)
                or not self.approved_at_utc < self.original_deadline_utc):
            raise ValueError("exact signed standing approval original required")
        for name in ("scope_digest", "self_mapping_digest", "manifest_digest", "profile_digest",
                "catalogue_hash", "root_budget_grant_digest", "root_budget_lease_bound_digest"):
            _digest(getattr(self, name))
        for name in ("self_actor_ref", "approver_actor_ref", "installation_id", "profile_id",
                "scheme_version", "operator_version", "policy_version", "root_budget_lease_ref",
                "registration_operation_id"):
            _text(getattr(self, name))
        for ref, version, digest in self.observer_bindings:
            _text(ref); _digest(digest)
            if type(version) is not int or version < 1:
                raise ValueError("standing observer version is not fixed")

    @property
    def original_ref(self):
        return self.request.approval_original_ref

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))



@dataclass(frozen=True, slots=True)
class ArtifactStandingPredecisionApprovalOriginalV3(ArtifactStandingPredecisionApprovalOriginalV2):
    preparation_dependency_contract_ref: str = field(kw_only=True)
    preparation_dependency_contract_digest: str = field(kw_only=True)
    schema: str = "d08.artifact-standing-predecision-approval.v3"

    def __post_init__(self):
        ArtifactStandingPredecisionApprovalOriginalV2.__post_init__(self)
        from ..host.authority_profile import artifact_candidate_preparation_dependency_contract_v1
        contract = artifact_candidate_preparation_dependency_contract_v1()
        if ((self.preparation_dependency_contract_ref, self.preparation_dependency_contract_digest)
                != (contract.original_ref, contract.digest)
                or (self.scope.preparation_dependency_contract_ref, self.scope.preparation_dependency_contract_digest)
                != (contract.original_ref, contract.digest)):
            raise ValueError("actual Owner approval must explicitly sign the fresh preparation contract")


class InstalledArtifactStandingPredecisionApprovalReadersV2:
    def __init__(self, key, *, graph, issuer, bundle, owner_guard, owner_binding):
        from ..runtime.issuers import D11BudgetJobIssuer
        from ..host.authority_profile import AdminInstallationBundle
        from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
        from ..graph_coordinator import GraphCoordinator, OwnerLeaseBindingV1
        if (type(graph) is not GraphCoordinator or key is not _APPROVAL_READERS_KEY_V2 or type(issuer) is not D11BudgetJobIssuer
                or type(bundle) is not AdminInstallationBundle
                or type(owner_guard) is not OwnerAuthorizationGuardV1
                or type(owner_binding) is not OwnerLeaseBindingV1
                or owner_binding.namespace != owner_guard.namespace
                or owner_binding.authorization_head != owner_guard.authorization_head
                or owner_binding.authorization_revision != owner_guard.authorization_revision):
            raise TypeError("standing approval reader requires its live installed Owner factory")
        self.issuer, self.bundle, self.graph = issuer, bundle, graph
        self.owner_guard, self.owner_binding = owner_guard, owner_binding


def install_artifact_standing_predecision_approval_readers_v2(graph, *, scope, owner_guard, bundle):
    from ..graph_coordinator import GraphCoordinator, OwnerLeaseBindingV1
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from ..runtime_contracts import FenceScope
    if (type(graph) is not GraphCoordinator or type(scope) is not FenceScope
            or type(owner_guard) is not OwnerAuthorizationGuardV1
            or owner_guard.namespace != scope.namespace or owner_guard.authorization_head == "genesis"
            or owner_guard.pending_revoke_operation_id is not None):
        raise ValueError("standing approval requires the actual current Owner fence")
    matches = [binding for binding in graph._GraphCoordinator__owner_leases.values()
        if type(binding) is OwnerLeaseBindingV1 and binding.namespace == scope.namespace
        and binding.authorization_head == owner_guard.authorization_head
        and binding.authorization_revision == owner_guard.authorization_revision]
    if not matches or len({binding.actor for binding in matches}) != 1:
        raise MissingProductionOriginalV1("actual_unique_live_Owner_approval_actor")
    return InstalledArtifactStandingPredecisionApprovalReadersV2(_APPROVAL_READERS_KEY_V2,
        graph=graph, issuer=graph._GraphCoordinator__d11_issuer, bundle=bundle,
        owner_guard=owner_guard, owner_binding=matches[0])


def artifact_standing_predecision_approval_operation_id_v2(approval_original_ref):
    _text(approval_original_ref)
    return "artifact-standing-approve:" + canonical_digest(approval_original_ref)[:48]


def _standing_lease_bounds_v2(lease):
    return canonical_digest({"lease_id": lease.lease_id, "parent_id": lease.parent_id,
        "bot_id": lease.bot_id, "persona_id": lease.persona_id,
        "currency": lease.currency, "limits": dict(lease.limits)})


def _standing_profile_material_v2(bundle):
    from ..host.authority_profile import (AdminInstallationBundle, AdminArtifactDraftPolicyV3,
        AdminArtifactStandingScopeV2, AdminArtifactStandingScopeV3, artifact_standing_scope_approval_ref_v2,
        artifact_standing_scope_from_payload_v2, _read_profile_json, _read_fd_bounded)
    from ..authority_service.linux_installation_security_v1 import opened_installed_file_v1
    from pathlib import Path
    from ..host.artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4
    if type(bundle) is not AdminInstallationBundle or type(bundle.artifact_draft) not in {AdminArtifactDraftPolicyV3,AdminArtifactDraftPairedPolicyV4}:
        raise MissingProductionOriginalV1("actual_installed_standing_V2_phase_package")
    scope = bundle.artifact_draft.standing_scope
    if type(scope) not in {AdminArtifactStandingScopeV2, AdminArtifactStandingScopeV3}:
        raise MissingProductionOriginalV1("explicit_Owner_approved_standing_V2_no_V1_upgrade")
    installation = bundle.installation_policy
    ref = artifact_standing_scope_approval_ref_v2(scope, namespace=installation.namespace,
        installation_id=installation.installation_id, manifest_digest=installation.manifest_digest,
        profile_id=bundle.tls_profile.profile_id)
    if scope.approval_original_ref != ref:
        raise ValueError("standing approval reference changed its fixed declaration")
    directory = Path(bundle.tls_profile.client_private_key).parent
    with opened_installed_file_v1(directory / "profile.json") as descriptor:
        raw = _read_fd_bounded(descriptor, 65536)
    payload = json.loads(raw.decode("utf-8"))
    if artifact_standing_scope_from_payload_v2(payload["artifact_draft"]["standing_scope"]) != scope:
        raise ValueError("standing declaration differs from actual protected profile bytes")
    bindings = []
    for observer_ref in scope.observer_scope:
        if observer_ref == "d11.explicit-task-objective":
            continue
        from ..host.artifact_phase_observer_policy_v2 import require_current_artifact_phase_observer_v2
        spec=require_current_artifact_phase_observer_v2(bundle)
        pins=payload.get('artifact_phase_observer')
        if (type(pins)is not dict or pins.get('asset_ref')!=observer_ref
                or pins.get('asset_sha256')!=spec.asset_digest or spec.asset_ref!=observer_ref):
            raise ValueError('standing observer differs from actual protected production declaration')
        bindings.append((observer_ref, spec.observer_version, spec.asset_digest))
    return scope, hashlib.sha256(raw).hexdigest(), tuple(bindings)


def _standing_current_basis_v2(db, *, namespace, bundle, issuer, owner_guard, now_utc):
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3
    from ..domains.d03.self_perspective import self_mapping_key, SelfIdentityMapping
    from ..graph_types import validate_owner_grant_v1
    from .budget import get_budget_lease, require_budget_family_admissible
    scope, profile_digest, observers = _standing_profile_material_v2(bundle)
    installation = bundle.installation_policy
    if namespace != installation.namespace:
        raise ValueError("standing approval crossed installed namespace")
    def current(key):
        row = artifact_model_graph_point_v3(db,('revision', 'value', 'valid'),token=key.token)
        if row is None or row[2] != 1:
            raise MissingProductionOriginalV1("actual_current_standing_" + key.type_name)
        return GraphVersion(key, row[0]), json.loads(row[1])
    owner_head, owner_value = current(owner_grant_key(*namespace.as_tuple))
    validate_owner_grant_v1(owner_value)
    if (owner_value["state"] != "active" or owner_value["installation_id"] != installation.installation_id
            or owner_value["authority_id"] != installation.expected_authority_id):
        raise MissingProductionOriginalV1("actual_active_installed_standing_Owner_grant")
    if (owner_head.key.token, owner_head.revision, canonical_digest(owner_value)) != (
            owner_guard.grant_ref, owner_guard.grant_revision, owner_guard.grant_digest):
        raise MissingProductionOriginalV1("actual_current_standing_Owner_guard")
    mapping_head, mapping_value = current(self_mapping_key(namespace))
    mapping = SelfIdentityMapping(**mapping_value)
    if (mapping.status != "active" or mapping.self_entity_ref != scope.self_actor_ref
            or mapping.persona_ref != "persona:" + namespace.persona_id
            or mapping.graph_incarnation != owner_value["graph_incarnation"]):
        raise MissingProductionOriginalV1("actual_active_standing_Self_mapping")
    lease = get_budget_lease(db, installation.root_lease.lease_id)
    grant = issuer.current_budget_grant(db, lease.lease_id)
    require_budget_family_admissible(db, lease.lease_id)
    if (grant != installation.root_grant or lease.state != "active"
            or _standing_lease_bounds_v2(lease) != _standing_lease_bounds_v2(installation.root_lease)):
        raise MissingProductionOriginalV1("actual_original_standing_Root_budget")
    deadlines = [scope.valid_until_utc, grant.valid_until_utc]
    ancestor = lease
    while ancestor.parent_id is not None:
        ancestor = get_budget_lease(db, ancestor.parent_id)
        deadlines.append(issuer.current_budget_grant(db, ancestor.lease_id).valid_until_utc)
    deadline = min(deadlines)
    if now_utc >= deadline:
        raise MissingProductionOriginalV1("original_standing_approval_fixed_deadline")
    return scope, profile_digest, observers, mapping_head, canonical_digest(mapping_value), lease, grant, deadline


def _standing_approval_from_wire_v2(raw):
    from ..runtime_contracts import NamespaceId
    from ..host.authority_profile import artifact_standing_scope_from_payload_v2
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    value_class = {"d08.artifact-standing-predecision-approval.v2": ArtifactStandingPredecisionApprovalOriginalV2,
        "d08.artifact-standing-predecision-approval.v3": ArtifactStandingPredecisionApprovalOriginalV3}.get(
            raw.get("schema") if type(raw) is dict else None)
    if value_class is None or set(raw) != {f.name for f in fields(value_class)}:
        raise ValueError("standing approval has another closed wire")
    values = dict(raw)
    if type(values["request"]) is not dict or set(values["request"]) != {"approval_original_ref"}:
        raise ValueError("standing approval request is not its exact selector")
    values["request"] = ApproveArtifactStandingPredecisionRequestV2(**values["request"])
    values["namespace"] = NamespaceId(**values["namespace"])
    values["scope"] = artifact_standing_scope_from_payload_v2(values["scope"])
    head = values["self_mapping_head"]
    if type(head) is not dict or set(head) != {"key", "revision"}:
        raise ValueError("standing approval mapping version changed wire")
    values["self_mapping_head"] = GraphVersion(AtomKey.from_token(head["key"]), head["revision"])
    values["owner_guard"] = ProductionOwnerGuardV1(**values["owner_guard"])
    guard = dict(values["owner_authorization"])
    guard["namespace"] = NamespaceId(**guard["namespace"])
    values["owner_authorization"] = OwnerAuthorizationGuardV1(**guard)
    if type(values["observer_bindings"]) is not list:
        raise ValueError("standing observer identities require their exact array")
    values["observer_bindings"] = tuple(tuple(row) for row in values["observer_bindings"])
    value = value_class(**values)
    if plain_v1(value) != raw:
        raise ValueError("standing approval was not canonical")
    return value


def stage_approve_artifact_standing_predecision_v2(db, *, frame, request, installed_readers):
    if type(request) is not ApproveArtifactStandingPredecisionRequestV2 or type(installed_readers) is not InstalledArtifactStandingPredecisionApprovalReadersV2:
        raise TypeError("standing approval requires exact Owner selectors and installed readers")
    readers = installed_readers
    read = CurrentDomainReadV1(frame); read.check(db)
    binding, guard = readers.owner_binding, readers.owner_guard
    if (frame.envelope.authority.actor != binding.actor
            or frame.envelope.authority.namespace != guard.namespace
            or frame.owner_guard.owner_head_digest != guard.authorization_head.removeprefix("sha256:")
            or (frame.owner_guard.grant_revision, frame.owner_guard.grant_digest) != (binding.grant_revision, binding.grant_digest)
            or (binding.access_epoch, binding.delete_epoch) != (frame.envelope.version_guard.access_epoch, frame.envelope.version_guard.delete_epoch)
            or frame.envelope.authority.purpose not in binding.purposes
            or not set(frame.envelope.authority.audience) <= set(binding.audiences)):
        raise ValueError("standing approval changed its actual live Owner session/fence")
    scope, profile_digest, observers, mapping, mapping_digest, lease, grant, deadline = _standing_current_basis_v2(
        db, namespace=frame.envelope.authority.namespace, bundle=readers.bundle, issuer=readers.issuer,
        owner_guard=frame.owner_guard, now_utc=frame.now_utc)
    read.head(db, mapping.key, required=True)
    operation_id = artifact_standing_predecision_approval_operation_id_v2(scope.approval_original_ref)
    if request.approval_original_ref != scope.approval_original_ref or frame.envelope.identity.operation_id != operation_id:
        raise ValueError("standing approval changed its stable operation/declaration")
    installation = readers.bundle.installation_policy
    from ..host.authority_profile import AdminArtifactStandingScopeV3
    approval_class = ArtifactStandingPredecisionApprovalOriginalV3 if type(scope) is AdminArtifactStandingScopeV3 else ArtifactStandingPredecisionApprovalOriginalV2
    contract_fields = {} if approval_class is ArtifactStandingPredecisionApprovalOriginalV2 else {
        "preparation_dependency_contract_ref": scope.preparation_dependency_contract_ref,
        "preparation_dependency_contract_digest": scope.preparation_dependency_contract_digest}
    value = approval_class(request, installation.namespace, scope,
        canonical_digest(plain_v1(scope)), mapping, mapping_digest, scope.self_actor_ref, binding.actor,
        frame.owner_guard, guard, installation.installation_id, installation.manifest_digest,
        readers.bundle.tls_profile.profile_id, profile_digest, installation.catalogue_hash,
        installation.scheme_version, installation.operator_version, installation.policy_version,
        lease.lease_id, canonical_digest(grant), _standing_lease_bounds_v2(lease), lease.version, observers,
        deadline, frame.now_utc, operation_id, **contract_fields)
    stage = stage_result_v1(frame, "d08", APPROVAL_OPERATION_V2, request,
        provenance={"standing_predecision_approval": value})
    return _empty_postcondition_stage_v1(stage, frame, readers)


def _standing_approval_history_v2(db, *, namespace, original_ref, producing_operation_id, raw):
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3
    value = _standing_approval_from_wire_v2(raw)
    adopted = read_adopted_domain_operation_v1(db, namespace, producing_operation_id)
    if (value.namespace != namespace or value.original_ref != original_ref
            or value.registration_operation_id != producing_operation_id
            or producing_operation_id != artifact_standing_predecision_approval_operation_id_v2(original_ref)
            or adopted is None or (adopted["domain"], adopted["operation_kind"]) != ("d08", APPROVAL_OPERATION_V2)
            or adopted["receipt"].status != "committed" or adopted["receipt"].write_versions
            or adopted["payload"]["request"] != plain_v1(value.request)
            or adopted["payload"]["provenance"].get("standing_predecision_approval") != raw
            or adopted["payload"]["authority"]["actor"] != value.approver_actor_ref
            or adopted["payload"]["owner_guard"] != plain_v1(value.owner_guard)
            or adopted["payload"]["now_utc"] != value.approved_at_utc
            or GraphVersion(value.self_mapping_head.key, value.self_mapping_head.revision) not in adopted["read_versions"]):
        raise ValueError("standing approval has no exact actual Owner W01 producer")
    history = artifact_model_graph_point_v3(db,('value', 'valid'),token=value.self_mapping_head.key.token,revision=value.self_mapping_head.revision)
    if history is None or history[1] != 1 or canonical_digest(json.loads(history[0])) != value.self_mapping_digest:
        raise ValueError("standing approval lost actual certified mapping historical bytes")
    return value


def read_current_artifact_standing_predecision_approval_v2(db, *, namespace, bundle, issuer, owner_guard, now_utc):
    scope, profile_digest, observers, mapping, mapping_digest, lease, grant, deadline = _standing_current_basis_v2(
        db, namespace=namespace, bundle=bundle, issuer=issuer, owner_guard=owner_guard, now_utc=now_utc)
    row = _read(db, issuer=issuer, namespace=namespace, kind=APPROVAL_KIND_V2, ref=scope.approval_original_ref)
    if row is None:
        raise MissingProductionOriginalV1("actual_signed_Owner_standing_V2_approval")
    value = _standing_approval_history_v2(db, namespace=namespace, original_ref=scope.approval_original_ref,
        producing_operation_id=row[1], raw=row[0])
    policy = bundle.installation_policy
    if (value.scope != scope or value.profile_digest != profile_digest or value.observer_bindings != observers
            or value.self_mapping_head != mapping or value.self_mapping_digest != mapping_digest
            or value.owner_guard != owner_guard
            or value.owner_authorization.authorization_head.removeprefix("sha256:") != owner_guard.owner_head_digest
            or value.root_budget_grant_digest != canonical_digest(grant)
            or value.root_budget_lease_ref != lease.lease_id or lease.version < value.root_budget_lease_version
            or value.root_budget_lease_bound_digest != _standing_lease_bounds_v2(lease)
            or (value.installation_id, value.manifest_digest, value.profile_id, value.catalogue_hash,
                value.scheme_version, value.operator_version, value.policy_version) !=
               (policy.installation_id, policy.manifest_digest, bundle.tls_profile.profile_id,
                policy.catalogue_hash, policy.scheme_version, policy.operator_version, policy.policy_version)
            or not now_utc < value.original_deadline_utc <= deadline):
        raise MissingProductionOriginalV1("current_Owner_Self_scope_manifest_Root_budget_approval")
    return value


def read_plan_artifact_standing_predecision_approval_v2(db, *, namespace, request, installed_readers):
    from ..domains.d03.self_perspective import self_mapping_key
    if type(request) is not ApproveArtifactStandingPredecisionRequestV2 or type(installed_readers) is not InstalledArtifactStandingPredecisionApprovalReadersV2:
        raise TypeError("standing approval read plan requires exact Owner installed selectors")
    return production_read_plan_v1((), (owner_grant_key(*namespace.as_tuple), self_mapping_key(namespace)), (), ())


def authorize_current_task_predecision_v2(db, *, frame, task, operation, method_ref, installed_readers):
    readers = _readers(installed_readers)
    read = CurrentDomainReadV1(frame); read.check(db)
    from .jobs import get_job
    cycle = get_job(db, AtomKey.from_token(task.cycle_job_ref).name)
    if cycle.budget_ref != frame.envelope.parent_budget_lease_ref:
        raise ValueError("predecision frame changed its actual task budget")
    approval = readonly_current_task_predecision_facts_v2(db,
        namespace=frame.envelope.authority.namespace, task=task, operation=operation,
        method_ref=method_ref, actor_ref=frame.envelope.authority.actor,
        bundle=readers.bundle, issuer=readers.issuer, owner_guard=frame.owner_guard, now_utc=frame.now_utc,
        purpose=frame.envelope.authority.purpose, audiences=frame.envelope.authority.audience,
        access_epoch=frame.envelope.version_guard.access_epoch, delete_epoch=frame.envelope.version_guard.delete_epoch)
    from .ingress_artifact_task_scope_v1 import SCOPE_KIND, task_scope_ref_v1
    scope = _read(db, issuer=readers.issuer, namespace=task.namespace,
        kind=SCOPE_KIND, ref=task_scope_ref_v1(task.root_registration_ref))[0]
    read.source_family(db, (scope["source_ref"],))
    if approval.observer_bindings:
        from ..host.artifact_phase_observer_policy_v2 import require_current_artifact_phase_observer_v2
        observer = require_current_artifact_phase_observer_v2(readers.bundle)
        if (observer.asset_ref, observer.observer_version, observer.asset_digest) not in approval.observer_bindings:
            raise ValueError("Self cannot borrow an unapproved independent observer policy")
    read.original(approval.original_ref, kind="d11.life_" + APPROVAL_KIND_V2, digest=approval.digest)
    return approval


def _standing_source_family_sql_v2(db, *, namespace, source_ref, purpose, audiences, access_epoch, delete_epoch):
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3
    from ..runtime_contracts import NamespaceId
    from ..memory_types import SourceRecord, source_key, access_key, validate_access
    from ..domains.d06 import source_correction_head_key
    from .domain_production_contracts_v1 import ProductionOperationLimitsV1
    if (type(namespace) is not NamespaceId or type(audiences) is not tuple
            or db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
                namespace.as_tuple).fetchone() != (access_epoch, delete_epoch)):
        raise ValueError("predecision facts changed actual Source rights barriers")
    active, records = set(), {}
    def current(key):
        row = artifact_model_graph_point_v3(db,('revision', 'value', 'valid'),token=key.token)
        if row is None or row[2] != 1:
            raise MissingProductionOriginalV1("actual_current_predecision_" + key.type_name)
        return GraphVersion(key, row[0]), json.loads(row[1])
    def visit(ref):
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject or "") or ref in active:
            raise ValueError("predecision Source family changed canonical namespace or is cyclic")
        if ref in records:return
        if 3 * (len(active) + len(records) + 1) > ProductionOperationLimitsV1().max_graph_heads:
            raise MissingProductionOriginalV1("bounded_predecision_source_family_closure")
        head, value = current(key)
        _, access = current(access_key(*namespace.as_tuple, key.owner.subject))
        correction_key = source_correction_head_key(namespace, key.owner.subject)
        correction = artifact_model_graph_point_v3(db,('revision', 'valid'),token=correction_key.token)
        record = SourceRecord.from_dict(value);validate_access(access)
        if (record.source_id != key.owner.subject or access["source_id"] != record.source_id
                or access["status"] != "active" or purpose not in record.purposes or purpose not in access["purposes"]
                or not set(audiences) <= set(record.audiences) or not set(audiences) <= set(access["audiences"])
                or correction is not None and (correction[0] != 0 or correction[1] != 0)):
            raise MissingProductionOriginalV1("current_predecision_Source_family_permission:" + record.source_id)
        active.add(ref)
        for parent in record.parent_source_ids:visit(source_key(*namespace.as_tuple, parent).token)
        active.remove(ref);records[ref] = (head, value, record)
    visit(source_ref)
    return records


def readonly_current_task_predecision_facts_v2(db, *, namespace, task, operation, method_ref, actor_ref,
        bundle, issuer, owner_guard, now_utc, purpose, audiences, access_epoch, delete_epoch):
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3
    from .ingress_artifact_task_scope_v1 import (IngressArtifactTaskScopeOriginalV2,
        task_scope_ref_v1, SCOPE_KIND, OPERATION as TASK_SCOPE_OPERATION,
        _decode as task_decode, require_task_scope_archive_v1)
    from ..memory_types import SourceRecord
    from .ingress_observation import read_committed_ingress_identity
    from .foreground_cycle_v1 import _adopted_c02_v1
    from .jobs import get_job
    from .d11_offline_originals_v1 import _utc
    from .budget import get_budget_lease, require_budget_family_admissible
    if not db.in_transaction:
        raise ValueError("predecision facts require the actual current SQL transaction")
    approval = read_current_artifact_standing_predecision_approval_v2(db, namespace=namespace,
        bundle=bundle, issuer=issuer, owner_guard=owner_guard, now_utc=now_utc)
    if (type(task) is not ArtifactDraftTaskSelectorV1 or task.namespace != namespace
            or actor_ref != approval.self_actor_ref
            or operation not in approval.scope.predecision_operations
            or method_ref is not None and method_ref not in approval.scope.method_refs):
        raise ValueError("standing approval does not permit this exact current Self task operation/method")
    root_row = _read(db, issuer=issuer, namespace=namespace,
        kind="draft_root_capability", ref=task.root_registration_ref)
    scope_row = _read(db, issuer=issuer, namespace=namespace,
        kind=SCOPE_KIND, ref=task_scope_ref_v1(task.root_registration_ref))
    if root_row is None or scope_row is None:
        raise MissingProductionOriginalV1("actual_paid_C1_C02_signed_TaskScope_V2")
    scope = task_decode(scope_row[0], IngressArtifactTaskScopeOriginalV2)
    from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV3
    producer = read_adopted_domain_operation_v1(db, namespace, scope_row[1])
    if type(scope) not in {IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3} or producer is None:
        raise MissingProductionOriginalV1("actual_V2_task_no_legacy_scope_upgrade")
    root = scope.root
    tool = bundle.artifact_draft.tool_scope
    from ..host.artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4, select_paired_tool_scope_v3
    if type(bundle.artifact_draft) is AdminArtifactDraftPairedPolicyV4:
        if len(root.filenames) != 1: raise ValueError("paired task Root must contain its one actual registered filename")
        tool = select_paired_tool_scope_v3(bundle.artifact_draft,root.filenames[0])
    verified = require_task_scope_archive_v1(db, namespace=namespace, root=root, producer=producer)
    if (verified != scope or (producer["domain"], producer["operation_kind"]) != ("d10", TASK_SCOPE_OPERATION)
            or scope.approval_original_ref != approval.original_ref
            or scope.approval_original_digest != approval.digest
            or scope.standing_policy_digest != approval.scope_digest
            or (root.owner_grant_ref, root.owner_grant_revision, root.owner_grant_digest) !=
               (approval.owner_guard.grant_ref, approval.owner_guard.grant_revision, approval.owner_guard.grant_digest)
            or (root.installation_id, root.manifest_digest, root.resource_id) !=
               (approval.installation_id, approval.manifest_digest, tool.resource_id)
            or tool.filename not in root.filenames):
        raise MissingProductionOriginalV1("current_approved_TaskScope_Source_Owner_target_Root")
    family = _standing_source_family_sql_v2(db, namespace=namespace, source_ref=scope.source_ref,
        purpose=purpose, audiences=audiences, access_epoch=access_epoch, delete_epoch=delete_epoch)
    source, source_value, record = family[scope.source_ref]
    ingress = read_committed_ingress_identity(db, namespace, record.source_id)
    if (source.revision != scope.source_revision or canonical_digest(source_value) != scope.source_digest
            or ingress is None or ingress.visibility != "private"
            or ingress.platform_ref != approval.scope.platform_ref
            or ingress.sender_ref not in approval.scope.allowed_sender_refs
            or scope.c02_operation_id != task.c02_operation_id):
        raise MissingProductionOriginalV1("actual_current_approved_private_task_source_sender")
    approval_producer = read_adopted_domain_operation_v1(db, namespace, approval.registration_operation_id)
    source_event = artifact_model_graph_point_v3(db,('event_id',),token=scope.source_ref,revision=1)
    source_operation = None if source_event is None else db.execute(
        "SELECT commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, source_event[0])).fetchone()
    c02 = _adopted_c02_v1(db, namespace, scope.c02_operation_id)
    if (approval_producer is None or source_operation is None or c02 is None
            or not approval_producer["receipt"].commit_seq < source_operation[0]
            or not approval_producer["receipt"].commit_seq < c02.commit_seq < producer["receipt"].commit_seq):
        raise MissingProductionOriginalV1("actual_approval_before_ordinary_Source_C02_TaskScope_ordinals")
    cycle = get_job(db, AtomKey.from_token(task.cycle_job_ref).name)
    lease = get_budget_lease(db, cycle.budget_ref)
    grant = issuer.current_budget_grant(db, lease.lease_id)
    require_budget_family_admissible(db, lease.lease_id)
    chain = lease
    while chain.lease_id != approval.root_budget_lease_ref:
        if chain.parent_id is None:
            raise ValueError("task budget does not descend from the original approved Root")
        chain = get_budget_lease(db, chain.parent_id)
    if (lease.state != "active" or cycle.budget_ref != lease.lease_id
            or now_utc >= min(approval.original_deadline_utc, grant.valid_until_utc,
                _utc(root.valid_until_utc).timestamp(), _utc(cycle.deadline_utc).timestamp())):
        raise MissingProductionOriginalV1("current_original_task_Root_budget_deadline")
    if type(scope) is IngressArtifactTaskScopeOriginalV3:
        from .artifact_task_continuation_authorization_v2 import resolve_artifact_task_authorization_deadline_v2
        from .ingress_artifact_task_scope_v1 import ArtifactTaskObjectiveV1
        objective_row=_read(db,issuer=issuer,namespace=namespace,kind="artifact_task_objective",ref=scope.objective_ref)
        objective=task_decode(objective_row[0],ArtifactTaskObjectiveV1)
        resolve_artifact_task_authorization_deadline_v2(db,namespace=namespace,scope=scope,objective=objective,
            issuer=issuer,bundle=bundle,owner_guard=owner_guard,now_utc=now_utc,parent_budget_lease_ref=cycle.budget_ref)
    return approval


def _artifact_phase_policy_original_ref_from_parts_v1(request,goal_head,goal_digest,plan_head,plan_digest,
        source_head,source_value_digest,objective_ref,objective_digest,extent_original_digest,owner_guard,
        installation_id,manifest_digest,conditions,original_deadline_utc):
    return 'artifact-phase-postcondition-policy:'+canonical_digest((request,goal_head,goal_digest,plan_head,plan_digest,
        source_head,source_value_digest,objective_ref,objective_digest,extent_original_digest,owner_guard,
        installation_id,manifest_digest,conditions,original_deadline_utc))[:48]


def _readonly_artifact_phase_policy_basis_core_v1(db,*,namespace,request,issuer,bundle,owner_guard,now_utc,
        parent_budget_lease_ref,actor_ref,purpose,audiences,access_epoch,delete_epoch,
        registration_operation_id=None,deadline=None):
    from .artifact_task_text_extent_v1 import (KIND as EXTENT_KIND,ArtifactTaskTextExtentOriginalV1,
        require_artifact_task_text_extent_history_v1,_objective_basis_v1,_explicit_zh_extent_v1)
    from .c1_artifact_task_intent_v1 import read_c1_task_intent_original_v1,c1_task_intent_ref_v1
    from ..domains.d08.execution import _decode_goal
    from ..domains.d08.personal_plan_v1 import decode_personal_plan_type_v1,PLAN_TYPE
    from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1,draft_from_wire_v1
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
    from .d11_offline_originals_v1 import _utc
    from .d11_types import job_graph_write
    from .jobs import get_job
    from .budget import get_budget_lease,require_budget_family_admissible
    from .issuers import D11BudgetJobIssuer
    from ..host.artifact_phase_observer_policy_v2 import require_current_artifact_phase_observer_v2
    if (type(request) is not RegisterArtifactPhasePostconditionPolicyRequestV1 or request.task.namespace!=namespace
            or type(issuer) is not D11BudgetJobIssuer or type(owner_guard) is not ProductionOwnerGuardV1 or not db.in_transaction):
        raise TypeError('pure policy basis requires actual task, D11 issuer, Owner guard and SQL snapshot')
    def current(ref):
        key=AtomKey.from_token(ref)
        row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
            (*namespace.as_tuple,ref)).fetchone()
        if row is None or row[2]!=1:raise MissingProductionOriginalV1('current_policy_basis_'+key.type_name)
        return GraphVersion(key,row[0]),json.loads(row[1])
    goal_head,goal_value=current(request.goal_ref);plan_head,plan_value=current(request.plan_ref)
    goal=_decode_goal(goal_value);plan=decode_personal_plan_type_v1(PLAN_TYPE,plan_value)
    if goal.state!='active' or plan.state!='active' or (plan.goal_ref,plan.goal_revision)!=(request.goal_ref,goal_head.revision):
        raise MissingProductionOriginalV1('current_active_postcondition_task_Goal_Plan')
    row=_read(db,issuer=issuer,namespace=namespace,kind=EXTENT_KIND,ref=request.extent_original_ref)
    if row is None:raise MissingProductionOriginalV1('actual_registered_postcondition_task_extent')
    extent=require_artifact_task_text_extent_history_v1(db,namespace=namespace,original_ref=request.extent_original_ref,
        producing_operation_id=row[1],raw=row[0])
    from .artifact_task_text_extent_v1 import ArtifactTaskTextExtentOriginalV2
    if type(extent) is ArtifactTaskTextExtentOriginalV2:
        return _readonly_artifact_phase_policy_basis_core_v2(db,namespace=namespace,request=request,
            issuer=issuer,bundle=bundle,owner_guard=owner_guard,now_utc=now_utc,
            parent_budget_lease_ref=parent_budget_lease_ref,actor_ref=actor_ref,purpose=purpose,audiences=audiences,
            access_epoch=access_epoch,delete_epoch=delete_epoch,registration_operation_id=registration_operation_id,deadline=deadline)
    objective_ref,objective,producer=_objective_basis_v1(db,namespace,request.goal_ref,goal,issuer)
    installed=bundle.installation_policy
    if ((objective['installation_id'],objective['manifest_digest'])!=(installed.installation_id,installed.manifest_digest)
            or now_utc>=objective['valid_until_utc'] or objective['initial_root_registration_ref']!=request.task.root_registration_ref
            or objective['initial_c02_operation_id']!=request.task.c02_operation_id):
        raise MissingProductionOriginalV1('current_installed_unexpired_task_extent_objective')
    intent=read_c1_task_intent_original_v1(db,namespace=namespace,c02_operation_id=objective['initial_c02_operation_id'],issuer=issuer)
    if (intent is None or intent.intent.kind!='draft_then_corrected_revision'
            or (intent.source_ref,intent.source_revision,intent.source_digest)!=
                (objective['source_ref'],objective['source_revision'],objective['source_digest'])):
        raise MissingProductionOriginalV1('actual_paid_C1_for_exact_task_extent_objective')
    family=_standing_source_family_sql_v2(db,namespace=namespace,source_ref=intent.source_ref,purpose=purpose,
        audiences=audiences,access_epoch=access_epoch,delete_epoch=delete_epoch)
    source_head,source_value,record=family[intent.source_ref]
    if (source_head.revision,canonical_digest(source_value))!=(intent.source_revision,intent.source_digest):
        raise MissingProductionOriginalV1('current_unmodified_task_extent_source')
    full_extent,start,end,evidence=_explicit_zh_extent_v1(record.text,intent.intent.source_quote)
    actual_extent=ArtifactTaskTextExtentOriginalV1(namespace,goal_head,canonical_digest(goal_value),objective_ref,
        canonical_digest(objective),source_head,canonical_digest(source_value),intent.c02_operation_id,
        c1_task_intent_ref_v1(namespace,intent.c02_operation_id),canonical_digest(plain_v1(intent)),
        'd10-current:'+producer['original_digest'][:48],producer['original_digest'],extent.registration_operation_id,
        owner_guard,start,end,evidence,full_extent)
    if actual_extent!=extent:raise ValueError('pure policy basis changed qualified actual task extent')
    root_row=_read(db,issuer=issuer,namespace=namespace,kind='draft_root_capability',ref=request.task.root_registration_ref)
    if root_row is None:raise MissingProductionOriginalV1('actual_postcondition_registered_Root_scope')
    root=draft_from_wire_v1(root_row[0],DraftRootCapabilityV1)
    if (root.source_ref,root.owner_grant_ref,root.owner_grant_revision,root.owner_grant_digest,root.installation_id,root.manifest_digest)!=(
            extent.task_source_head.key.token,owner_guard.grant_ref,owner_guard.grant_revision,owner_guard.grant_digest,
            installed.installation_id,installed.manifest_digest):
        raise ValueError('postcondition policy crossed actual Root/Source/Owner/installed package')
    owner_head,owner_value=current(owner_guard.grant_ref)
    if (owner_head.revision,canonical_digest(owner_value))!=(owner_guard.grant_revision,owner_guard.grant_digest):
        raise MissingProductionOriginalV1('current_postcondition_upstream_Owner')
    cycle=get_job(db,AtomKey.from_token(request.task.cycle_job_ref).name)
    _,cycle_value=current(request.task.cycle_job_ref)
    lease=get_budget_lease(db,parent_budget_lease_ref)
    if (cycle_value!=job_graph_write(cycle).value or cycle.budget_ref!=lease.lease_id
            or (cycle.bot_id,cycle.persona_id)!=namespace.as_tuple):
        raise ValueError('policy deadline budget is not the actual registered task budget')
    require_budget_family_admissible(db,lease.lease_id)
    grant_deadlines=[];ancestor=lease
    while True:
        grant_deadlines.append(issuer.current_budget_grant(db,ancestor.lease_id).valid_until_utc)
        if ancestor.parent_id is None:break
        ancestor=get_budget_lease(db,ancestor.parent_id)
    scope_row=_read(db,issuer=issuer,namespace=namespace,kind='artifact_task_scope',ref=task_scope_ref_v1(root.registration_ref))
    approval=None
    if scope_row is not None and scope_row[0].get('schema')=='d11.ingress-artifact-task-scope.v2':
        approval=readonly_current_task_predecision_facts_v2(db,namespace=namespace,task=request.task,operation=POLICY_OPERATION,
            method_ref=request.method_ref,actor_ref=actor_ref,bundle=bundle,issuer=issuer,owner_guard=owner_guard,now_utc=now_utc,
            purpose=purpose,audiences=audiences,access_epoch=access_epoch,delete_epoch=delete_epoch)
    limit=min(objective['valid_until_utc'],_utc(root.valid_until_utc).timestamp(),_utc(cycle.deadline_utc).timestamp(),*grant_deadlines)
    if approval is not None and limit>approval.original_deadline_utc:
        raise ValueError('registered task policy lifetime exceeds its genuine standing approval')
    original_deadline=limit if deadline is None else deadline
    if lease.state!='active' or not now_utc<original_deadline<=limit:
        raise MissingProductionOriginalV1('current_original_postcondition_task_budget_deadline')
    observer=None
    if request.observer_policy_ref is not None:
        observer=require_current_artifact_phase_observer_v2(bundle)
        if observer.asset_ref!=request.observer_policy_ref:
            raise ValueError('policy observer selector differs from actual protected installed asset')
        if approval is not None and (observer.asset_ref,observer.observer_version,observer.asset_digest) not in approval.observer_bindings:
            raise ValueError('policy observer changed actual approved asset pin')
    def semantic(name,phase):
        return ArtifactPhaseConditionV1(name,name,phase,observer_id=None if observer is None else observer.observer_id,
            observer_version=None if observer is None else observer.observer_version,
            observer_asset_digest=None if observer is None else observer.asset_digest)
    conditions=[ArtifactPhaseConditionV1('full_length','length','check',extent.full_extent.minimum,extent.full_extent.maximum,
        evidence_start=extent.evidence_start,evidence_end=extent.evidence_end),semantic('task_semantics','check')]
    if 'sample_check' in artifact_draft_phase_sequence_v2(request.method_ref):
        conditions.extend((ArtifactPhaseConditionV1('sample_length','length','sample_check',120,180),semantic('tone','sample_check')))
    conditions=tuple(conditions)
    if approval is not None and not {c.kind for c in conditions}<=set(approval.scope.rubric_scope):
        raise ValueError('policy conditions exceed actual approved registered rubric vocabulary')
    parts=(request,goal_head,canonical_digest(goal_value),plan_head,canonical_digest(plan_value),extent.task_source_head,
        extent.task_source_digest,extent.objective_ref,extent.objective_digest,canonical_digest(row[0]),owner_guard,
        installed.installation_id,installed.manifest_digest,conditions,original_deadline)
    actual_ref=_artifact_phase_policy_original_ref_from_parts_v1(*parts)
    operation_id=actual_ref+':register' if registration_operation_id is None else registration_operation_id
    return ArtifactPhasePostconditionPolicyOriginalV1(*parts,operation_id)


def readonly_current_artifact_phase_policy_basis_v1(db,*,namespace,request,issuer,bundle,owner_guard,now_utc,
        parent_budget_lease_ref,actor_ref,purpose,audiences,access_epoch,delete_epoch):
    """Actual signed task material for fixed Policy ID discovery; no Frame or permit is created."""
    value=_readonly_artifact_phase_policy_basis_core_v1(db,namespace=namespace,request=request,issuer=issuer,bundle=bundle,
        owner_guard=owner_guard,now_utc=now_utc,parent_budget_lease_ref=parent_budget_lease_ref,actor_ref=actor_ref,
        purpose=purpose,audiences=audiences,access_epoch=access_epoch,delete_epoch=delete_epoch)
    saved=_read(db,issuer=issuer,namespace=namespace,kind=POLICY_KIND,ref=value.original_ref)
    if saved is not None:
        actual,_=_original(db,namespace=namespace,kind=POLICY_KIND,ref=value.original_ref,issuer=issuer)
        if actual!=value:raise ValueError('same policy once ID cannot update original basis or expiry')
        return actual
    return value


PREPARATION_PARENT_KIND_V1 = "artifact_candidate_preparation_parent"
PREPARATION_PARENT_OPERATION_V1 = "input:freeze_artifact_candidate_preparation_v1"
_PREPARATION_PARENT_KEY_V1 = object()
_ACTIVE_PREPARATION_PARENTS_V1 = {}


@dataclass(frozen=True, slots=True)
class FreezeArtifactCandidatePreparationRequestV1:
    task: ArtifactDraftTaskSelectorV1

    def __post_init__(self):
        if type(self.task) is not ArtifactDraftTaskSelectorV1:
            raise TypeError("preparation parent selects its actual current task")


@dataclass(frozen=True, slots=True)
class ArtifactPreparationChildSelectorV1:
    parent_original_ref: str
    child_slot: str

    def __post_init__(self):
        _text(self.parent_original_ref)
        if not self.parent_original_ref.startswith("artifact-candidate-preparation:") or self.child_slot not in {"freeze", "evaluate"}:
            raise ValueError("internal child selects one fixed actual preparation parent")


@dataclass(frozen=True, slots=True)
class ArtifactCandidatePreparationParentOriginalV1:
    request: FreezeArtifactCandidatePreparationRequestV1
    namespace: object
    approval_original_ref: str
    approval_original_digest: str
    dependency_contract_ref: str
    dependency_contract_digest: str
    task_scope_ref: str
    task_scope_digest: str
    material_digest: str
    candidates_digest: str
    goal_head: GraphVersion
    plan_head: GraphVersion
    source_head: GraphVersion
    source_digest: str
    parent_prepare_operation_id: str
    child_operations: tuple[tuple[str, str, str, str], ...]
    self_actor_ref: str
    owner_guard: ProductionOwnerGuardV1
    parent_budget_lease_ref: str
    budget_grant_digest: str
    budget_bounds_digest: str
    purpose: str
    audiences: tuple[str, ...]
    access_epoch: int
    delete_epoch: int
    original_deadline_utc: float
    frozen_at_utc: float
    registration_operation_id: str
    schema: str = "d08.artifact-candidate-preparation-parent.v1"

    def __post_init__(self):
        from ..runtime_contracts import NamespaceId
        from ..host.authority_profile import artifact_candidate_preparation_dependency_contract_v1
        import math
        contract = artifact_candidate_preparation_dependency_contract_v1()
        if (self.schema != "d08.artifact-candidate-preparation-parent.v1"
                or type(self.request) is not FreezeArtifactCandidatePreparationRequestV1
                or type(self.namespace) is not NamespaceId or self.request.task.namespace != self.namespace
                or type(self.owner_guard) is not ProductionOwnerGuardV1
                or any(type(v) is not GraphVersion or v.revision < 1 or NamespaceId.from_key(v.key) != self.namespace
                    for v in (self.goal_head, self.plan_head, self.source_head))
                or (self.dependency_contract_ref, self.dependency_contract_digest) != (contract.original_ref, contract.digest)
                or type(self.child_operations) is not tuple or len(self.child_operations) != 2
                or tuple((r[0],r[1]) for r in self.child_operations) != contract.internal_children
                or len({r[2] for r in self.child_operations}) != 2
                or type(self.audiences) is not tuple or not self.audiences
                or type(self.access_epoch) is not int or self.access_epoch < 0
                or type(self.delete_epoch) is not int or self.delete_epoch < 0
                or not math.isfinite(self.original_deadline_utc) or not math.isfinite(self.frozen_at_utc)
                or not self.frozen_at_utc < self.original_deadline_utc):
            raise ValueError("preparation parent must freeze exact task/Source/Plan and two internal children")
        for name in ("approval_original_digest", "dependency_contract_digest", "task_scope_digest",
                "material_digest", "candidates_digest", "source_digest", "budget_grant_digest", "budget_bounds_digest"):
            _digest(getattr(self,name))
        for name in ("approval_original_ref", "dependency_contract_ref", "task_scope_ref",
                "parent_prepare_operation_id", "self_actor_ref", "parent_budget_lease_ref", "purpose", "registration_operation_id"):
            _text(getattr(self,name))
        for _,_,operation_id,digest in self.child_operations:
            _text(operation_id); _digest(digest)
        if self.registration_operation_id != artifact_candidate_preparation_parent_operation_id_v1(self.request.task,self.plan_head):
            raise ValueError("preparation parent changed its fixed ID")

    @property
    def original_ref(self):
        return artifact_candidate_preparation_parent_ref_v1(self.request.task,self.plan_head)

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


def artifact_candidate_preparation_parent_ref_v1(task,plan_head):
    from .d08_personal_candidate_v1 import artifact_task_choice_ids_v2
    ids = artifact_task_choice_ids_v2(task,plan_head)
    return "artifact-candidate-preparation:" + canonical_digest((task,plan_head,ids["prepare"]))[:48]


def artifact_candidate_preparation_parent_operation_id_v1(task,plan_head):
    return artifact_candidate_preparation_parent_ref_v1(task,plan_head)+":freeze"


def _preparation_parent_from_wire_v1(raw):
    from ..runtime_contracts import NamespaceId
    if type(raw) is not dict or set(raw) != {f.name for f in fields(ArtifactCandidatePreparationParentOriginalV1)}:
        raise ValueError("preparation parent has another closed wire")
    values=dict(raw); request=values["request"]
    if type(request) is not dict or set(request)!={"task"}:
        raise ValueError("preparation parent request selects only its task")
    task=dict(request["task"]); task["namespace"]=NamespaceId(**task["namespace"])
    values["request"]=FreezeArtifactCandidatePreparationRequestV1(ArtifactDraftTaskSelectorV1(**task))
    values["namespace"]=NamespaceId(**values["namespace"])
    for name in ("goal_head","plan_head","source_head"):
        head=values[name]
        if type(head) is not dict or set(head)!={"key","revision"}:
            raise ValueError("preparation parent changed an actual Graph version wire")
        values[name]=GraphVersion(AtomKey.from_token(head["key"]),head["revision"])
    values["owner_guard"]=ProductionOwnerGuardV1(**values["owner_guard"])
    for name in ("child_operations","audiences"):
        if type(values[name]) is not list:raise ValueError("preparation parent arrays changed closed wire")
    values["child_operations"]=tuple(tuple(row) for row in values["child_operations"])
    values["audiences"]=tuple(values["audiences"])
    value=ArtifactCandidatePreparationParentOriginalV1(**values)
    if plain_v1(value)!=raw:raise ValueError("preparation parent is not canonical")
    return value


def _preparation_parent_history_v1(db,*,namespace,original_ref,producing_operation_id,raw):
    value=_preparation_parent_from_wire_v1(raw)
    adopted=read_adopted_domain_operation_v1(db,namespace,producing_operation_id)
    if (value.namespace!=namespace or value.original_ref!=original_ref
            or value.registration_operation_id!=producing_operation_id or adopted is None
            or (adopted["domain"],adopted["operation_kind"])!=("d08",PREPARATION_PARENT_OPERATION_V1)
            or adopted["receipt"].status!="committed" or adopted["receipt"].write_versions
            or adopted["payload"]["coverage"]!="complete"
            or adopted["payload"]["request"]!=plain_v1(value.request)
            or adopted["payload"]["provenance"].get("candidate_preparation_parent")!=raw
            or adopted["payload"]["authority"]["actor"]!=value.self_actor_ref
            or adopted["payload"]["owner_guard"]!=plain_v1(value.owner_guard)
            or adopted["payload"]["now_utc"]!=value.frozen_at_utc
            or any(head not in adopted["read_versions"] for head in (value.goal_head,value.plan_head,value.source_head))):
        raise ValueError("preparation parent has no exact actual Self W01 start receipt")
    return value


def _preparation_current_basis_v1(db,*,namespace,task,actor_ref,bundle,issuer,owner_guard,now_utc,
        purpose,audiences,access_epoch,delete_epoch):
    from .d08_personal_candidate_v1 import (CurrentArtifactTaskChoiceRequestV2,
        readonly_current_artifact_task_choice_material_v2)
    from .ingress_artifact_task_scope_v1 import SCOPE_KIND,task_scope_ref_v1
    from .jobs import get_job
    from .budget import get_budget_lease
    from .d11_offline_originals_v1 import _utc
    material=readonly_current_artifact_task_choice_material_v2(db,namespace=namespace,
        request=CurrentArtifactTaskChoiceRequestV2(task),issuer=issuer)
    approval=None
    for binding in material.prepare_request.bindings:
        approval=readonly_current_task_predecision_facts_v2(db,namespace=namespace,task=task,
            operation="prepare_personal_candidates_v1",method_ref=binding.method_ref,actor_ref=actor_ref,
            bundle=bundle,issuer=issuer,owner_guard=owner_guard,now_utc=now_utc,purpose=purpose,
            audiences=audiences,access_epoch=access_epoch,delete_epoch=delete_epoch)
    if type(approval) is not ArtifactStandingPredecisionApprovalOriginalV3:
        raise MissingProductionOriginalV1("fresh_actual_Owner_approval_preparation_dependency_contract")
    scope_ref=task_scope_ref_v1(task.root_registration_ref)
    raw_scope=_read(db,issuer=issuer,namespace=namespace,kind=SCOPE_KIND,ref=scope_ref)[0]
    source_head=GraphVersion(AtomKey.from_token(raw_scope["source_ref"]),raw_scope["source_revision"])
    cycle=get_job(db,AtomKey.from_token(task.cycle_job_ref).name)
    lease=get_budget_lease(db,cycle.budget_ref);grant=issuer.current_budget_grant(db,lease.lease_id)
    deadline=min(approval.original_deadline_utc,grant.valid_until_utc,
        _utc(raw_scope["root"]["valid_until_utc"]).timestamp(),_utc(cycle.deadline_utc).timestamp())
    ids=dict(material.ids)
    children=(("freeze","input:freeze_values",ids["freeze"],canonical_digest(plain_v1(material.freeze_request))),
        ("evaluate","evaluate_values",ids["evaluate"],canonical_digest(plain_v1(material.evaluate_request))))
    return material,approval,scope_ref,raw_scope,source_head,lease,grant,deadline,children


@dataclass(frozen=True,slots=True,init=False)
class _IssuedCandidatePreparationParentV1:
    graph: object
    material_digest: str
    task: ArtifactDraftTaskSelectorV1
    parent_prepare_operation_id: str
    goal_head: GraphVersion
    plan_head: GraphVersion
    candidates_digest: str

    def __init__(self,key,graph,material):
        if key is not _PREPARATION_PARENT_KEY_V1:
            raise TypeError("preparation handle belongs only to its actual installed parent pipeline")
        object.__setattr__(self,"graph",graph)
        object.__setattr__(self,"task",material.selector)
        object.__setattr__(self,"material_digest",canonical_digest(plain_v1(material)))
        object.__setattr__(self,"parent_prepare_operation_id",dict(material.ids)["prepare"])
        object.__setattr__(self,"goal_head",material.goal_head)
        object.__setattr__(self,"plan_head",material.plan_head)
        object.__setattr__(self,"candidates_digest",canonical_digest(plain_v1(material.prepare_request.bindings)))


def prepare_candidate_preparation_parent_for_graph_v3(graph,*,request,installed_readers):
    from .d08_personal_candidate_v1 import CurrentArtifactTaskChoiceRequestV2,readonly_current_artifact_task_choice_material_v2
    readers=_readers(installed_readers)
    if readers.graph is not graph or type(request) is not CurrentArtifactTaskChoiceRequestV2:
        raise TypeError("parent pipeline requires its actual installed graph and current task selector")
    store=graph._GraphCoordinator__store
    if not store._db.in_transaction or not store._lock._is_owned():
        raise ValueError("parent handle freezes material in the actual Graph readonly transaction")
    material=readonly_current_artifact_task_choice_material_v2(store._db,namespace=request.task.namespace,
        request=request,issuer=readers.issuer)
    return _IssuedCandidatePreparationParentV1(_PREPARATION_PARENT_KEY_V1,graph,material),material


def activate_candidate_preparation_parent_for_graph_v3(graph,*,handle):
    from contextlib import contextmanager
    if type(handle) is not _IssuedCandidatePreparationParentV1 or handle.graph is not graph:
        raise TypeError("actual preparation parent belongs to its installed Graph")
    @contextmanager
    def activate():
        runtime=graph._GraphCoordinator__domain_production_runtime_v1
        previous=getattr(runtime,"_active_candidate_preparation_parent_v1",None)
        if previous is not None:raise ValueError("one actual preparation parent pipeline is active")
        _ACTIVE_PREPARATION_PARENTS_V1[id(handle)]=handle
        runtime._active_candidate_preparation_parent_v1=handle
        try:yield handle
        finally:
            runtime._active_candidate_preparation_parent_v1=previous
            del _ACTIVE_PREPARATION_PARENTS_V1[id(handle)]
    return activate()


def candidate_preparation_parent_for_graph_v1(graph,*,request,installed_readers):
    handle,_=prepare_candidate_preparation_parent_for_graph_v3(graph,request=request,
        installed_readers=installed_readers)
    return activate_candidate_preparation_parent_for_graph_v3(graph,handle=handle)


def require_candidate_preparation_parent_handle_v1(graph,*,task=None,material_digest=None):
    handle=getattr(graph._GraphCoordinator__domain_production_runtime_v1,"_active_candidate_preparation_parent_v1",None)
    if (type(handle) is not _IssuedCandidatePreparationParentV1
            or _ACTIVE_PREPARATION_PARENTS_V1.get(id(handle)) is not handle or handle.graph is not graph
            or task is not None and handle.task!=task
            or material_digest is not None and handle.material_digest!=material_digest):
        raise ValueError("internal dependency requires its live actual parent pipeline")
    return handle


def stage_freeze_artifact_candidate_preparation_v1(db,*,frame,request,installed_readers):
    readers=_readers(installed_readers)
    if type(request) is not FreezeArtifactCandidatePreparationRequestV1:
        raise TypeError("preparation parent accepts only its exact task selector")
    read=CurrentDomainReadV1(frame);read.check(db)
    authority=frame.envelope.authority;guard=frame.envelope.version_guard
    basis=_preparation_current_basis_v1(db,namespace=authority.namespace,task=request.task,actor_ref=authority.actor,
        bundle=readers.bundle,issuer=readers.issuer,owner_guard=frame.owner_guard,now_utc=frame.now_utc,
        purpose=authority.purpose,audiences=authority.audience,access_epoch=guard.access_epoch,delete_epoch=guard.delete_epoch)
    material,approval,scope_ref,raw_scope,source_head,lease,grant,deadline,children=basis
    require_candidate_preparation_parent_handle_v1(readers.graph,task=request.task,
        material_digest=canonical_digest(plain_v1(material)))
    operation_id=artifact_candidate_preparation_parent_operation_id_v1(request.task,material.plan_head)
    if frame.envelope.identity.operation_id!=operation_id or frame.envelope.parent_budget_lease_ref!=lease.lease_id:
        raise ValueError("parent start changed its fixed identity or actual task budget")
    for head in (material.goal_head,material.plan_head,source_head):
        if read.head(db,head.key,required=True).revision!=head.revision:
            raise ValueError("parent start changed an actual task head")
    read.source_family(db,(source_head.key.token,))
    read.original(approval.original_ref,kind="d11.life_"+APPROVAL_KIND_V2,digest=approval.digest)
    value=ArtifactCandidatePreparationParentOriginalV1(request,authority.namespace,approval.original_ref,approval.digest,
        approval.preparation_dependency_contract_ref,approval.preparation_dependency_contract_digest,
        scope_ref,canonical_digest(raw_scope),canonical_digest(plain_v1(material)),
        canonical_digest(plain_v1(material.prepare_request.bindings)),material.goal_head,material.plan_head,
        source_head,raw_scope["source_digest"],dict(material.ids)["prepare"],children,authority.actor,
        frame.owner_guard,lease.lease_id,canonical_digest(grant),_standing_lease_bounds_v2(lease),
        authority.purpose,authority.audience,guard.access_epoch,guard.delete_epoch,deadline,frame.now_utc,operation_id)
    stage=stage_result_v1(frame,"d08",PREPARATION_PARENT_OPERATION_V1,request,
        provenance={"candidate_preparation_parent":value})
    return _empty_postcondition_stage_v1(stage,frame,readers)


def read_plan_artifact_candidate_preparation_parent_v1(db,*,namespace,request,installed_readers):
    from .d08_personal_candidate_v1 import CurrentArtifactTaskChoiceRequestV2,readonly_current_artifact_task_choice_material_v2
    from .ingress_artifact_task_scope_v1 import SCOPE_KIND,task_scope_ref_v1
    readers=_readers(installed_readers)
    if type(request) is not FreezeArtifactCandidatePreparationRequestV1 or request.task.namespace!=namespace:
        raise TypeError("preparation parent read plan selects only the current task")
    material=readonly_current_artifact_task_choice_material_v2(db,namespace=namespace,
        request=CurrentArtifactTaskChoiceRequestV2(request.task),issuer=readers.issuer)
    scope_ref=task_scope_ref_v1(request.task.root_registration_ref)
    raw_scope=_read(db,issuer=readers.issuer,namespace=namespace,kind=SCOPE_KIND,ref=scope_ref)[0]
    keys=(material.goal_head.key,material.plan_head.key,AtomKey.from_token(raw_scope["source_ref"]),
        AtomKey.from_token(request.task.cycle_job_ref),owner_grant_key(*namespace.as_tuple))
    return production_read_plan_v1((),keys,(raw_scope["source_ref"],),
        (scope_ref,raw_scope["approval_original_ref"],*(b.postcondition_policy_ref for b in material.prepare_request.bindings),
            *(b.extent_original_ref for b in material.prepare_request.bindings)))


@dataclass(frozen=True,slots=True)
class ArtifactPreparationChildFactsV1:
    parent: ArtifactCandidatePreparationParentOriginalV1
    child_slot: str
    operation_kind: str
    operation_id: str
    request: object


def readonly_current_artifact_preparation_child_facts_v1(db,*,namespace,request,actor_ref,bundle,issuer,
        owner_guard,now_utc,purpose,audiences,access_epoch,delete_epoch):
    if type(request) is not ArtifactPreparationChildSelectorV1:
        raise TypeError("internal child accepts its fixed parent selector")
    row=_read(db,issuer=issuer,namespace=namespace,kind=PREPARATION_PARENT_KIND_V1,ref=request.parent_original_ref)
    if row is None:raise MissingProductionOriginalV1("actual_signed_candidate_preparation_parent_start")
    parent=_preparation_parent_history_v1(db,namespace=namespace,original_ref=request.parent_original_ref,
        producing_operation_id=row[1],raw=row[0])
    basis=_preparation_current_basis_v1(db,namespace=namespace,task=parent.request.task,actor_ref=actor_ref,
        bundle=bundle,issuer=issuer,owner_guard=owner_guard,now_utc=now_utc,purpose=purpose,audiences=audiences,
        access_epoch=access_epoch,delete_epoch=delete_epoch)
    material,approval,scope_ref,scope,source_head,lease,grant,deadline,children=basis
    if ((parent.approval_original_ref,parent.approval_original_digest)!=(approval.original_ref,approval.digest)
            or (parent.task_scope_ref,parent.task_scope_digest)!=(scope_ref,canonical_digest(scope))
            or parent.material_digest!=canonical_digest(plain_v1(material))
            or parent.candidates_digest!=canonical_digest(plain_v1(material.prepare_request.bindings))
            or (parent.goal_head,parent.plan_head,parent.source_head,parent.source_digest)
                !=(material.goal_head,material.plan_head,source_head,scope["source_digest"])
            or parent.child_operations!=children or parent.parent_prepare_operation_id!=dict(material.ids)["prepare"]
            or parent.self_actor_ref!=actor_ref or parent.owner_guard!=owner_guard
            or parent.parent_budget_lease_ref!=lease.lease_id
            or parent.budget_grant_digest!=canonical_digest(grant)
            or parent.budget_bounds_digest!=_standing_lease_bounds_v2(lease)
            or (parent.purpose,parent.audiences,parent.access_epoch,parent.delete_epoch)
                !=(purpose,audiences,access_epoch,delete_epoch)
            or not now_utc<parent.original_deadline_utc<=deadline):
        raise MissingProductionOriginalV1("current_exact_preparation_parent_Task_Plan_Source_Owner_Root_deadline")
    child=next(row for row in children if row[0]==request.child_slot)
    actual_request=material.freeze_request if request.child_slot=="freeze" else material.evaluate_request
    return ArtifactPreparationChildFactsV1(parent,child[0],child[1],child[2],actual_request)


def readonly_current_artifact_preparation_completion_v1(db,*,namespace,request,actor_ref,bundle,issuer,
        owner_guard,now_utc,purpose,audiences,access_epoch,delete_epoch):
    if type(request) is not ArtifactPreparationChildSelectorV1 or request.child_slot!='evaluate':
        raise TypeError('parent completion selects its exact final internal evaluation')
    facts=[]
    for slot in ("freeze","evaluate"):
        facts.append(readonly_current_artifact_preparation_child_facts_v1(db,namespace=namespace,
            request=ArtifactPreparationChildSelectorV1(request.parent_original_ref,slot),actor_ref=actor_ref,
            bundle=bundle,issuer=issuer,owner_guard=owner_guard,now_utc=now_utc,purpose=purpose,
            audiences=audiences,access_epoch=access_epoch,delete_epoch=delete_epoch))
    parent=facts[0].parent
    parent_receipt=read_adopted_domain_operation_v1(db,namespace,parent.registration_operation_id)["receipt"]
    receipts=[]
    for fact in facts:
        adopted=read_adopted_domain_operation_v1(db,namespace,fact.operation_id)
        if (adopted is None or (adopted["domain"],adopted["operation_kind"])!=("d01",fact.operation_kind)
                or adopted["receipt"].status!="committed" or adopted["payload"]["coverage"]!="complete"
                or adopted["payload"]["request"]!=plain_v1(fact.request)
                or adopted["payload"]["authority"]["actor"]!=parent.self_actor_ref
                or adopted["payload"]["owner_guard"]!=plain_v1(parent.owner_guard)
                or adopted["payload"]["parent_budget"]!=parent.parent_budget_lease_ref
                or not parent_receipt.commit_seq<adopted["receipt"].commit_seq):
            raise MissingProductionOriginalV1("actual_same_parent_internal_"+fact.child_slot+"_W01_receipt")
        receipts.append(adopted["receipt"])
    if not receipts[0].commit_seq<receipts[1].commit_seq:
        raise ValueError("actual value evaluation must follow its fixed candidate/context freeze")
    return parent


def require_artifact_preparation_completion_v1(db,*,frame,request,installed_readers):
    readers=_readers(installed_readers)
    authority=frame.envelope.authority;guard=frame.envelope.version_guard
    parent=readonly_current_artifact_preparation_completion_v1(db,namespace=authority.namespace,request=request,
        actor_ref=authority.actor,bundle=readers.bundle,issuer=readers.issuer,owner_guard=frame.owner_guard,
        now_utc=frame.now_utc,purpose=authority.purpose,audiences=authority.audience,
        access_epoch=guard.access_epoch,delete_epoch=guard.delete_epoch)
    require_candidate_preparation_parent_handle_v1(readers.graph,task=parent.request.task,material_digest=parent.material_digest)
    if frame.envelope.identity.operation_id!=parent.parent_prepare_operation_id:
        raise ValueError("completion belongs only to its actual approved parent prepare")
    read=CurrentDomainReadV1(frame);read.check(db)
    read.original(parent.original_ref,kind="d11.life_"+PREPARATION_PARENT_KIND_V1,digest=parent.digest)
    return parent


def _amended_policy_conditions_v2(extent,method_ref,observer_identity):
    observer_id,observer_version,asset_digest=(None,None,None) if observer_identity is None else observer_identity
    def semantic(name,phase):
        return ArtifactPhaseConditionV1(name,name,phase,observer_id=observer_id,
            observer_version=observer_version,observer_asset_digest=asset_digest)
    conditions=[ArtifactPhaseConditionV1('full_length','length','check',extent.full_extent.minimum,extent.full_extent.maximum,
        evidence_start=extent.evidence_start,evidence_end=extent.evidence_end),semantic('task_semantics','check')]
    if 'sample_check' in artifact_draft_phase_sequence_v2(method_ref):
        conditions.extend((ArtifactPhaseConditionV1('sample_length','length','sample_check',120,180),semantic('tone','sample_check')))
    return tuple(conditions)


def _readonly_artifact_phase_policy_basis_core_v2(db,*,namespace,request,issuer,bundle,owner_guard,now_utc,
        parent_budget_lease_ref,actor_ref,purpose,audiences,access_epoch,delete_epoch,registration_operation_id=None,deadline=None):
    from dataclasses import replace
    from .artifact_task_text_extent_v1 import (ArtifactTaskTextExtentOriginalV2,KIND as EXTENT_KIND,
        RegisterArtifactTaskTextExtentRequestV1,readonly_current_artifact_task_text_extent_basis_v2,
        require_artifact_task_text_extent_history_v1)
    from ..host.artifact_phase_observer_policy_v2 import require_current_artifact_phase_observer_v2
    if type(request) is not RegisterArtifactPhasePostconditionPolicyRequestV1 or request.task.namespace!=namespace:
        raise TypeError('amended policy selects its exact current registered task')
    row=_read(db,issuer=issuer,namespace=namespace,kind=EXTENT_KIND,ref=request.extent_original_ref)
    if row is None:raise MissingProductionOriginalV1('actual_registered_amended_policy_extent')
    extent=require_artifact_task_text_extent_history_v1(db,namespace=namespace,original_ref=request.extent_original_ref,
        producing_operation_id=row[1],raw=row[0])
    if type(extent) is not ArtifactTaskTextExtentOriginalV2:
        raise ValueError('amended policy requires its exact new extent schema')
    current=readonly_current_artifact_task_text_extent_basis_v2(db,namespace=namespace,
        request=RegisterArtifactTaskTextExtentRequestV1(request.goal_ref,extent.goal_head.revision),issuer=issuer,bundle=bundle,
        owner_guard=owner_guard,now_utc=now_utc,parent_budget_lease_ref=parent_budget_lease_ref,actor_ref=actor_ref,
        purpose=purpose,audiences=audiences,access_epoch=access_epoch,delete_epoch=delete_epoch)
    basis=extent.basis
    if (current!=extent or request.task!=basis.task or request.plan_ref!=basis.plan_head.key.token
            or request.goal_ref!=basis.goal_head.key.token or basis.owner_guard!=owner_guard
            or (basis.root.installation_id,basis.root.manifest_digest)!=(bundle.installation_policy.installation_id,
                bundle.installation_policy.manifest_digest)):
        raise ValueError('amended policy changed actual Task/Plan/Source/Owner/Root/basis')
    approval=readonly_current_task_predecision_facts_v2(db,namespace=namespace,task=request.task,operation=POLICY_OPERATION,
        method_ref=request.method_ref,actor_ref=actor_ref,bundle=bundle,issuer=issuer,owner_guard=owner_guard,now_utc=now_utc,
        purpose=purpose,audiences=audiences,access_epoch=access_epoch,delete_epoch=delete_epoch)
    limit=min(basis.original_deadline_utc,approval.original_deadline_utc)
    original_deadline=limit if deadline is None else deadline
    if not now_utc<original_deadline<=limit:
        raise MissingProductionOriginalV1('original_amended_policy_deadline_without_renewal')
    observer_identity=None
    if request.observer_policy_ref is not None:
        observer=require_current_artifact_phase_observer_v2(bundle)
        if (observer.asset_ref!=request.observer_policy_ref
                or (observer.asset_ref,observer.observer_version,observer.asset_digest) not in approval.observer_bindings):
            raise ValueError('amended policy changed its actual approved observer asset')
        observer_identity=(observer.observer_id,observer.observer_version,observer.asset_digest)
    conditions=_amended_policy_conditions_v2(extent,request.method_ref,observer_identity)
    if not {c.kind for c in conditions}<=set(approval.scope.rubric_scope):
        raise ValueError('amended policy exceeded the original approved rubric vocabulary')
    value=ArtifactPhasePostconditionPolicyOriginalV2(request,basis.goal_head,basis.goal_digest,basis.plan_head,basis.plan_digest,
        basis.amendment_source_head,basis.amendment_source_digest,basis.objective_ref,basis.objective_digest,
        canonical_digest(row[0]),owner_guard,basis.root.installation_id,basis.root.manifest_digest,conditions,
        original_deadline,'prospective',task_basis_ref=basis.original_ref,task_basis_digest=basis.digest,
        amendment_original_ref=basis.amendment_original_ref,amendment_original_digest=basis.amendment_original_digest,
        rule_source_head=extent.rule_source_head,rule_source_digest=extent.rule_source_digest)
    return replace(value,registration_operation_id=value.original_ref+':register' if registration_operation_id is None else registration_operation_id)


def _policy_basis_v2(db,*,frame,request,readers,extent,registration_operation_id,deadline=None):
    from .artifact_task_text_extent_v1 import (RegisterArtifactTaskTextExtentRequestV1,
        _qualified_amended_artifact_task_text_extent_v2,KIND as EXTENT_KIND)
    read=CurrentDomainReadV1(frame);read.check(db)
    current=_qualified_amended_artifact_task_text_extent_v2(db,frame=frame,
        request=RegisterArtifactTaskTextExtentRequestV1(request.goal_ref,extent.goal_head.revision),
        readers=readers.current(),registration_operation_id=extent.registration_operation_id)
    if current!=extent:raise ValueError('amended policy Frame differs from actual qualified extent')
    read.original(request.extent_original_ref,kind='d11.life_'+EXTENT_KIND,digest=canonical_digest(plain_v1(extent)))
    if not frame.now_utc<frame.envelope.deadline_utc:
        raise MissingProductionOriginalV1('fresh_current_amended_policy_write_window')
    value=_readonly_artifact_phase_policy_basis_core_v2(db,namespace=frame.envelope.authority.namespace,request=request,
        issuer=readers.issuer,bundle=readers.bundle,owner_guard=frame.owner_guard,now_utc=frame.now_utc,
        parent_budget_lease_ref=frame.envelope.parent_budget_lease_ref,actor_ref=frame.envelope.authority.actor,
        purpose=frame.envelope.authority.purpose,audiences=frame.envelope.authority.audience,
        access_epoch=frame.envelope.version_guard.access_epoch,delete_epoch=frame.envelope.version_guard.delete_epoch,
        registration_operation_id=registration_operation_id,deadline=deadline)
    observer=readers.observer(request.observer_policy_ref)
    expected=set() if observer is None else {(observer.observer_id,observer.observer_version,observer.asset_digest)}
    if {(c.observer_id,c.observer_version,c.observer_asset_digest) for c in value.conditions if c.observer_id is not None}!=expected:
        raise ValueError('amended policy changed its actual installed observer qualification')
    return value


def _current_policy_sql_v2(db,*,policy,issuer,now_utc,owner_guard,installed_bundle):
    from .jobs import get_job
    if type(policy) is not ArtifactPhasePostconditionPolicyOriginalV2 or not db.in_transaction:
        raise TypeError('current amended policy requires its exact V2 and SQL snapshot')
    if (policy.owner_guard,policy.installation_id,policy.manifest_digest)!=(owner_guard,
            installed_bundle.installation_policy.installation_id,installed_bundle.installation_policy.manifest_digest):
        raise ValueError('current amended policy changed Owner or protected installed pins')
    original=read_adopted_domain_operation_v1(db,policy.namespace,policy.registration_operation_id)
    if original is None:raise MissingProductionOriginalV1('actual_adopted_amended_policy_registration')
    authority=original['payload']['authority']
    epochs=db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',policy.namespace.as_tuple).fetchone()
    cycle=get_job(db,AtomKey.from_token(policy.request.task.cycle_job_ref).name)
    current=_readonly_artifact_phase_policy_basis_core_v2(db,namespace=policy.namespace,request=policy.request,
        issuer=issuer,bundle=installed_bundle,owner_guard=owner_guard,now_utc=now_utc,parent_budget_lease_ref=cycle.budget_ref,
        actor_ref=authority['actor'],purpose=authority['purpose'],audiences=tuple(authority['audience']),
        access_epoch=epochs[0],delete_epoch=epochs[1],registration_operation_id=policy.registration_operation_id,
        deadline=policy.original_deadline_utc)
    if current!=policy:raise MissingProductionOriginalV1('current_exact_amended_Policy_Task_Plan_Source_Root')
    return policy


def _require_amended_policy_history_v2(db,*,namespace,value,adopted,issuer=None,read_original=None):
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3,artifact_model_life_payload_point_v3
    from .d11_life_preparation_v1 import TABLE
    from .artifact_task_text_extent_v1 import (KIND as EXTENT_KIND,ArtifactTaskTextExtentOriginalV2,
        require_artifact_task_text_extent_history_v1)
    row=_history_life_payload_point_v2(db,('payload_json', 'payload_digest', 'producing_operation_id'),namespace=namespace,kind=EXTENT_KIND,ref=value.request.extent_original_ref,issuer=issuer, read_original=read_original)
    if row is None or row[1]!=value.extent_original_digest:
        raise ValueError('amended policy history lost its actual signed new extent')
    extent=require_artifact_task_text_extent_history_v1(db,namespace=namespace,original_ref=value.request.extent_original_ref,
        producing_operation_id=row[2],raw=json.loads(row[0]))
    if type(extent) is not ArtifactTaskTextExtentOriginalV2:
        raise ValueError('amended policy history cannot reinterpret an initial V1 extent')
    basis=extent.basis
    extent_original=read_adopted_domain_operation_v1(db,namespace,row[2])
    if ((value.task_basis_ref,value.task_basis_digest)!=(basis.original_ref,basis.digest)
            or (value.amendment_original_ref,value.amendment_original_digest)!=(basis.amendment_original_ref,basis.amendment_original_digest)
            or (value.rule_source_head,value.rule_source_digest)!=(extent.rule_source_head,extent.rule_source_digest)
            or (value.request.task,value.request.goal_ref,value.request.plan_ref)!=(basis.task,basis.goal_head.key.token,basis.plan_head.key.token)
            or (value.goal_head,value.goal_digest,value.plan_head,value.plan_digest,value.source_head,value.source_value_digest,
                value.objective_ref,value.objective_digest,value.owner_guard,value.installation_id,value.manifest_digest)!=(
                basis.goal_head,basis.goal_digest,basis.plan_head,basis.plan_digest,basis.amendment_source_head,
                basis.amendment_source_digest,basis.objective_ref,basis.objective_digest,basis.owner_guard,
                basis.root.installation_id,basis.root.manifest_digest)
            or value.original_deadline_utc>basis.original_deadline_utc
            or extent_original is None or not extent_original['receipt'].commit_seq<adopted['receipt'].commit_seq):
        raise ValueError('amended policy history changed fixed basis/operative/rule Source or actual predecessor')
    for head,digest in ((value.source_head,value.source_value_digest),(value.rule_source_head,value.rule_source_digest)):
        source=artifact_model_graph_point_v3(db,('value', 'valid'),token=head.key.token,revision=head.revision)
        if source is None or source[1]!=1 or canonical_digest(json.loads(source[0]))!=digest:
            raise ValueError('amended policy history lost exact Source bytes')
    from ..memory_types import SourceRecord
    rule=SourceRecord.from_dict(json.loads(artifact_model_graph_point_v3(db,('value',),token=value.rule_source_head.key.token,revision=value.rule_source_head.revision)[0])).text
    if rule[extent.evidence_start:extent.evidence_end]!=extent.evidence_text:
        raise ValueError('amended policy evidence span belongs to another actual rule Source')
    semantic=[c for c in value.conditions if c.kind in {'tone','task_semantics'}]
    observer_identities={(c.observer_id,c.observer_version,c.observer_asset_digest) for c in semantic}
    if len(observer_identities)!=1:raise ValueError('amended policy changed its frozen observer identity')
    identity=next(iter(observer_identities))
    if value.request.observer_policy_ref is None:
        if identity!=(None,None,None):raise ValueError('amended policy invented an undeclared observer')
        identity=None
    elif identity[0] is None:raise ValueError('amended policy lost its declared observer identity')
    if value.conditions!=_amended_policy_conditions_v2(extent,value.request.method_ref,identity):
        raise ValueError('amended policy changed mandatory conditions derived from actual extent')
    return value


from .artifact_phase_observation_v1 import (PrepareArtifactPhaseObservationRequestV1,
    stage_prepare_artifact_phase_observation_v1)


def artifact_phase_expected_observer_refs_v1(contract,selector):
    """Deterministic complete observation selectors; existence is verified by the consumer."""
    if type(contract)is not ArtifactPhasePostconditionContractV1 or type(selector)is not ArtifactDraftPhaseSelectorV2 or selector.generation:
        raise TypeError('exact adopted phase contract and current check selector required')
    from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
    from .foreground_artifact_observation_plan_v3 import artifact_observation_ids_v1
    if foreground_artifact_phase_group_identity_v2(contract.selector)!=foreground_artifact_phase_group_identity_v2(selector):
        raise ValueError('observation reference derivation crossed actual adopted task/Decision/method')
    return tuple('d07-terminal:'+artifact_observation_ids_v1(selector,c.condition_id)['call']
        for c in contract.conditions if c.phase_kind==selector.phase_kind
        and c.kind in {'tone','task_semantics'} and c.observer_id is not None)
