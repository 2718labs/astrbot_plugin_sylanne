"""Independent fixed task objective observer over actual file originals and selected amendment."""
from dataclasses import dataclass,replace
import json
from ..graph_types import AtomKey,GraphWrite,GraphVersion
from ..runtime_contracts import NamespaceId,VersionedRef,QueryEpoch,canonical_digest
from ..domains.d01.production_operations_v1 import plain_v1,stage_result_v1
from ..domains.d10.project_checkpoint_v1 import (ProjectWorkVersionV1,ProjectTaskWaitConditionV1,
    CHECKPOINT_TYPE,WORK_TYPE,ProjectCheckpointV1,decode_project_checkpoint_type_v1,project_checkpoint_key_v1)
from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1

@dataclass(frozen=True,slots=True)
class ArtifactTaskObservationV1:
    objective_ref:str
    objective_digest:str
    goal_ref:str
    project_ref:str
    phase:str
    work_versions:tuple[ProjectWorkVersionV1,...]
    result_original_digests:tuple[str,...]
    amendment_ref:str|None
    amendment_digest:str|None
    checkpoint:ProjectCheckpointV1
    schema:str="d08.artifact-task-observation.v1"
    def __post_init__(self):
        if (self.schema!="d08.artifact-task-observation.v1" or self.phase not in {"partial","satisfied"}
                or len(self.work_versions)!=(1 if self.phase=="partial" else 2)
                or len(self.result_original_digests)!=len(self.work_versions)
                or (self.amendment_ref is None)!=(self.amendment_digest is None)
                or (self.phase=="partial")!=(self.amendment_ref is None)
                or tuple(w.version for w in self.work_versions)!=tuple(range(1,len(self.work_versions)+1))
                or len({w.work_ref for w in self.work_versions})!=1
                or any(w.project_ref!=self.project_ref for w in self.work_versions)
                or self.checkpoint.project_ref!=self.project_ref
                or self.checkpoint.state!=("waiting" if self.phase=="partial" else "completed")):
            raise ValueError("task observation requires exact first draft and same-work corrected version")
        for value in (self.objective_digest,*self.result_original_digests,*(() if self.amendment_digest is None else (self.amendment_digest,))):
            if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("task observation lost exact original digests")

@dataclass(frozen=True,slots=True)
class ArtifactTaskSettlementStageV1:
    stage:object
    checkpoint_stage:object


def artifact_task_observer_read_inputs_v1(db,namespace,goal_ref):
    """Finite selectors only; the stage reconstructs every original independently."""
    from .d11_life_preparation_v1 import TABLE
    from .d10_project_checkpoint_v1 import project_effect_read_inputs_v1
    from .domain_background_read_v3 import background_graph_head_v3,background_json_loads_v3
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    def original(kind,ref):
        return _producer_original_point_v3(db,table=TABLE,columns=("payload_json",),
            key_columns=("bot","persona","kind","original_ref"),key=(*namespace.as_tuple,kind,ref),
            legacy_reader=lambda:db.execute("SELECT payload_json FROM "+TABLE+
                " WHERE bot=? AND persona=? AND kind=? AND original_ref=?",(*namespace.as_tuple,kind,ref)).fetchone())
    row=background_graph_head_v3(db,namespace,goal_ref)
    if row is None:return (),(),()
    predicate=background_json_loads_v3(row[1])["satisfaction_predicate"]
    if (predicate["kind"],predicate["observation_provider"])!=("domain_state","d08.artifact_task_objective.v1"):
        return (),(),()
    ref=dict(predicate["parameters"])["objective_ref"]
    objective=original("artifact_task_objective",ref)
    if objective is None:return (),(),(ref,)
    obj=background_json_loads_v3(objective[0]);key=project_checkpoint_key_v1(namespace,obj["project_ref"])
    keys=[key];roots=[];originals=[ref]
    cp=background_graph_head_v3(db,namespace,key)
    if cp is not None:
        for work_ref in background_json_loads_v3(cp[1])["work_version_refs"]:
            keys.append(AtomKey.from_token(work_ref))
            row=background_graph_head_v3(db,namespace,work_ref)
            if row is None:continue
            work=background_json_loads_v3(row[1]);k,s,o=project_effect_read_inputs_v1(db,namespace,work["progress_ref"])
            keys.extend(k);roots.extend(s);originals.extend(o)
            terminal=original("adopted_life",work["artifact_ref"])
            if terminal is None:continue
            binding=background_json_loads_v3(terminal[0])["terminal"]["binding"]
            prepared=original("prepared",binding["prepared_original_ref"])
            if prepared is None:continue
            target=background_json_loads_v3(prepared[0])["plan"]["target"]
            from .artifact_task_amendment_v1 import amendment_key_v1,amendment_original_ref_v1,decode_amendment_v1
            amendment_key=amendment_key_v1(namespace,target["root_registration_ref"]);keys.append(amendment_key)
            amendment=background_graph_head_v3(db,namespace,amendment_key)
            if amendment is not None:originals.append(amendment_original_ref_v1(decode_amendment_v1(background_json_loads_v3(amendment[1]))))
    return tuple(dict.fromkeys(keys)),tuple(dict.fromkeys(roots)),tuple(dict.fromkeys(originals))


def stage_observe_artifact_task_v1(db,*,frame,request,readers,goal_atom,plan_atom,goal,plan,evidence):
    from .d08_personal_plan_v1 import require_artifact_task_objective_original_v1,_plan_stage
    from .artifact_continuation_originals_v1 import read_artifact_control_history_v1,read_completed_draft_predecessor_v1,read_selected_artifact_continuation_request_v1
    from .ingress_artifact_task_scope_v1 import ArtifactTaskObjectiveV1,_decode
    from .artifact_task_amendment_v1 import read_current_amendment_v1
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    from .d11_life_preparation_v1 import _read
    from .d11_artifact_draft_contract_v1 import DraftActivityScopeV1,draft_from_wire_v1
    read=CurrentDomainReadV1(frame);ns=frame.envelope.authority.namespace
    ref,raw=require_artifact_task_objective_original_v1(db,namespace=ns,goal_ref=request.goal_ref,goal=goal,issuer=readers.issuer)
    objective=_decode(raw,ArtifactTaskObjectiveV1);digest=canonical_digest(raw)
    read.original(ref,kind="d11.life_artifact_task_objective",digest=digest)
    if (goal.state!="active" or plan.state not in {"active","waiting"}
            or (objective.goal_ref,objective.plan_ref)!=(request.goal_ref,request.plan_ref)
            or frame.now_utc<objective.created_at_utc
            or not evidence.completed_verified):
        raise MissingProductionOriginalV1("current_unfinished_original_artifact_task")
    cp_key=project_checkpoint_key_v1(ns,objective.project_ref)
    cp_atom,_,cp_original=read_artifact_control_history_v1(db,frame=frame,ref=cp_key.token)
    checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,cp_atom.value)
    if (not cp_atom.valid or checkpoint.plan_ref!=request.plan_ref or checkpoint.plan_revision!=plan.revision
            or checkpoint.state!="completed" or checkpoint.next_step is not None
            or set(checkpoint.completed_node_refs)!={n.node_id for n in plan.nodes}
            or len(checkpoint.work_version_refs) not in {1,2}
            or request.progress_ref not in checkpoint.progress_refs):
        raise MissingProductionOriginalV1("actual_settled_artifact_milestone_checkpoint")
    observations=[]
    for work_ref in checkpoint.work_version_refs:
        atom,_,_=read_artifact_control_history_v1(db,frame=frame,ref=work_ref)
        work=decode_project_checkpoint_type_v1(WORK_TYPE,atom.value)
        previous,terminal,adopted,witness=read_completed_draft_predecessor_v1(db,frame=frame,result_ref=work.artifact_ref,issuer=readers.issuer)
        if (not atom.valid or work.project_ref!=objective.project_ref
                or (work.artifact_digest,work.artifact_length,work.version,work.terminal_ref,work.activity_id,work.effect_id,work.attempt_id)!=
                   (witness.content_digest,witness.content_length,witness.version,terminal.original_ref,terminal.binding.activity_id,terminal.binding.effect_id,terminal.binding.attempt_id)
                or work.progress_ref not in checkpoint.progress_refs or work.node_id not in checkpoint.completed_node_refs
                or (previous.plan.target.root_resource_id,previous.plan.target.root_identity,previous.plan.target.filename)!=
                   (objective.root_resource_id,objective.root_identity,objective.filename)):
            raise ValueError("task milestone changed its actual same-file original")
        observations.append((work,previous,terminal,adopted,witness))
    observations.sort(key=lambda row:row[0].version)
    first=observations[0];first_target=first[1].plan.target
    if (first[0].version!=1 or first_target.mode!="create" or first_target.root_registration_ref!=objective.initial_root_registration_ref
            or first[1].plan.input_source.ref!=objective.source_ref):
        raise ValueError("first milestone is not the initial task's actual newly created file")
    if observations[-1][0].progress_ref!=request.progress_ref or observations[-1][0].effect_id!=evidence.effect_id:
        raise ValueError("task observation must consume the actual latest effect")
    amendment_ref=amendment_digest=None
    if len(observations)==2:
        second=observations[1];target=second[1].plan.target
        if (second[0].version!=2 or second[0].work_ref!=first[0].work_ref or target.mode!="replace"
                or (target.expected_prior_version,target.expected_prior_digest,target.expected_prior_identity,target.expected_prior_effect_marker)!=
                   (1,first[4].content_digest,first[4].file_identity,first[4].effect_marker)):
            raise ValueError("second milestone did not replace the exact original first work version")
        actual=read_current_amendment_v1(db,namespace=ns,root_registration_ref=target.root_registration_ref,issuer=readers.issuer)
        if actual is None or (actual[0].objective_ref,actual[0].objective_digest,actual[0].goal_ref)!=(ref,digest,request.goal_ref):
            raise MissingProductionOriginalV1("actual_selected_ordinary_task_amendment")
        amendment,amendment_ref,amendment_key=actual
        head=read.head(db,amendment_key,required=True);amendment_digest=canonical_digest(plain_v1(amendment))
        read.original(amendment_ref,kind="d11.life_artifact_task_amendment",digest=amendment_digest)
        if head.value!=plain_v1(amendment):raise ValueError("task amendment head changed")
        scope_row=_read(db,issuer=readers.issuer,namespace=ns,kind="activity_scope",ref=second[1].plan.activity_scope_ref)
        if scope_row is None:raise MissingProductionOriginalV1("actual_replacement_activity_scope")
        scope=draft_from_wire_v1(scope_row[0],DraftActivityScopeV1)
        selector=artifact_draft_task_selector_v1(ns,c02_operation_id=scope.c02_original_ref,root_registration_ref=target.root_registration_ref)
        selected=read_selected_artifact_continuation_request_v1(db,namespace=ns,selector=selector)
        if (selected is None or selected[0].correction_head_ref!=amendment_key.token
                or selected[0].predecessor_result_ref!=first[0].artifact_ref
                or selected[0].goal_ref!=request.goal_ref or selected[0].project_ref!=objective.project_ref):
            raise ValueError("replacement did not adopt this amendment and exact predecessor")
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1,IngressArtifactTaskScopeOriginalV1
    from .artifact_task_continuation_authorization_v2 import resolve_artifact_task_authorization_deadline_v2
    latest_root=observations[-1][1].plan.target.root_registration_ref
    task_scope_row=_read(db,issuer=readers.issuer,namespace=ns,kind="artifact_task_scope",ref=task_scope_ref_v1(latest_root))
    if task_scope_row is None:raise MissingProductionOriginalV1("actual_latest_task_observer_scope")
    task_scope=_decode(task_scope_row[0],IngressArtifactTaskScopeOriginalV1)
    authorization_deadline=resolve_artifact_task_authorization_deadline_v2(db,namespace=ns,scope=task_scope,objective=objective,
        issuer=readers.issuer,bundle=readers.installed_bundle,owner_guard=frame.owner_guard,now_utc=frame.now_utc,
        parent_budget_lease_ref=frame.envelope.parent_budget_lease_ref)
    if not frame.now_utc<authorization_deadline:
        raise MissingProductionOriginalV1("current_task_observer_authorization_deadline")
    phase="partial" if len(observations)==1 else "satisfied"
    updated_goal=replace(goal,revision=goal_atom.revision+1,state="active" if phase=="partial" else "satisfied",
        progress_refs=tuple(dict.fromkeys((*goal.progress_refs,request.progress_ref))))
    updated_plan=replace(plan,revision=plan_atom.revision+1,goal_revision=updated_goal.revision,
        state="waiting" if phase=="partial" else "satisfied",candidate_refs=(),
        waiting_conditions=(ref,) if phase=="partial" else (),parent_plan_revision_ref=VersionedRef(request.plan_ref,plan_atom.revision))
    wake=(ProjectTaskWaitConditionV1(ref,digest,plan.fact_versions,
        QueryEpoch(ns,"namespace",frame.snapshot.epochs[0].revision),cp_original["receipt"].commit_seq)
        if phase=="partial" else None)
    updated_cp=replace(checkpoint,revision=cp_atom.revision+1,plan_revision=updated_plan.revision,
        state="waiting" if phase=="partial" else "completed",wait_condition=wake)
    observation=ArtifactTaskObservationV1(ref,digest,request.goal_ref,objective.project_ref,phase,
        tuple(row[0] for row in observations),tuple(canonical_digest(row[3]) for row in observations),
        amendment_ref,amendment_digest,updated_cp)
    primary=_plan_stage(frame,"settle_personal_goal",request,
        (GraphWrite(goal_atom.key,plain_v1(updated_goal)),GraphWrite(plan_atom.key,plain_v1(updated_plan))),
        actual_effect=evidence,task_observation=observation)
    from ..domains.d10 import LifeDomain
    checkpoint_stage=stage_result_v1(frame,"d10","settle_personal_goal",request,
        writes=(GraphWrite(cp_key,plain_v1(updated_cp)),),proposal_schema="d10.proposal.v1",
        proposal_hash=LifeDomain().descriptor.request_schema_hash)
    return ArtifactTaskSettlementStageV1(primary,checkpoint_stage)


def require_task_observer_checkpoint_member_v1(db,*,namespace,original,atom):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .artifact_wait_checkpoint_v1 import _require_history_member
    if (original is None or (original["domain"],original["operation_kind"])!=("d08","settle_personal_goal")
            or set(original["payload"]["provenance"])!={"actual_effect","task_observation"}):
        raise MissingProductionOriginalV1("actual_task_objective_observer_producer")
    observation=decode_typed_production_value_v1(original["payload"]["provenance"]["task_observation"],ArtifactTaskObservationV1)
    if (atom.key!=project_checkpoint_key_v1(namespace,observation.project_ref)
            or atom.revision!=observation.checkpoint.revision or atom.value!=plain_v1(observation.checkpoint)):
        raise ValueError("checkpoint changed its actual task objective observation")
    _require_history_member(db,namespace=namespace,original=original,key=atom.key,revision=atom.revision,value=atom.value)
    return observation


# V2 keeps task milestones distinct from method-internal physical file versions.
from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2, artifact_draft_phase_sequence_v2
from .d11_artifact_draft_contract_v1 import DraftFileReadbackV1
from .domain_production_contracts_v1 import ProductionOwnerGuardV1

ARTIFACT_TASK_MILESTONE_KIND_V2 = 'artifact_task_milestone_v2'
ARTIFACT_TASK_MILESTONE_OPERATION_V2 = 'register_artifact_task_milestone_v2'


def artifact_task_milestone_original_ref_v2(selector):
    from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
    return 'artifact-task-milestone:' + canonical_digest(foreground_artifact_phase_group_identity_v2(selector))[:48]


def artifact_task_milestone_registration_operation_id_v2(selector):
    return artifact_task_milestone_original_ref_v2(selector) + ':register'


@dataclass(frozen=True, slots=True)
class RegisterCurrentArtifactTaskMilestoneRequestV2:
    selector: ArtifactDraftPhaseSelectorV2

    def __post_init__(self):
        if (type(self.selector) is not ArtifactDraftPhaseSelectorV2 or self.selector.phase_kind != 'check'
                or self.selector.phase_index != len(artifact_draft_phase_sequence_v2(self.selector.method_ref)) - 1):
            raise TypeError('task milestone requires the actual final method check selector')


@dataclass(frozen=True, slots=True)
class ArtifactTaskMilestoneV2:
    selector: ArtifactDraftPhaseSelectorV2
    objective_ref: str
    objective_digest: str
    goal_ref: str
    project_ref: str
    semantic_index: int
    ordered_phase_originals: tuple[tuple[str, str], ...]
    full_check_original_ref: str
    full_check_original_digest: str
    file_result_ref: str
    file_result_digest: str
    source_head: GraphVersion
    source_value_digest: str
    readback: DraftFileReadbackV1
    owner_guard: ProductionOwnerGuardV1
    prev_milestone_ref: str | None
    prev_milestone_digest: str | None
    amendment_ref: str | None
    amendment_digest: str | None
    registered_at_utc: float
    original_deadline_utc: float
    registration_operation_id: str
    schema: str = 'd08.artifact-task-milestone.v2'

    @property
    def namespace(self): return self.selector.task.namespace

    @property
    def original_ref(self): return artifact_task_milestone_original_ref_v2(self.selector)

    @property
    def digest(self): return canonical_digest(plain_v1(self))

    @property
    def file_version(self): return self.readback.version

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import _digest, _text
        import math
        RegisterCurrentArtifactTaskMilestoneRequestV2(self.selector)
        if (self.schema != 'd08.artifact-task-milestone.v2' or self.semantic_index not in {1, 2}
                or type(self.readback) is not DraftFileReadbackV1 or type(self.owner_guard) is not ProductionOwnerGuardV1
                or type(self.source_head) is not GraphVersion or self.source_head.revision < 1
                or self.source_head.key.type_name != 'memory.source' or NamespaceId.from_key(self.source_head.key) != self.namespace
                or self.registration_operation_id != artifact_task_milestone_registration_operation_id_v2(self.selector)
                or type(self.registered_at_utc) not in {int, float} or not math.isfinite(self.registered_at_utc)
                or type(self.original_deadline_utc) not in {int, float} or not math.isfinite(self.original_deadline_utc)
                or not self.registered_at_utc < self.original_deadline_utc):
            raise ValueError('task milestone needs its real full-file method witness within the original scope')
        for ref in (self.objective_ref, self.goal_ref, self.project_ref, self.full_check_original_ref, self.file_result_ref): _text(ref, 'milestone original')
        for digest in (self.objective_digest, self.full_check_original_digest, self.file_result_digest, self.source_value_digest): _digest(digest)
        if (type(self.ordered_phase_originals) is not tuple
                or len(self.ordered_phase_originals) != len(artifact_draft_phase_sequence_v2(self.selector.method_ref))
                or self.ordered_phase_originals[-1] != (self.full_check_original_ref, self.full_check_original_digest)):
            raise ValueError('task milestone cannot omit or replace a method phase verification')
        for ref, digest in self.ordered_phase_originals: _text(ref, 'phase original'); _digest(digest)
        if self.semantic_index == 1:
            if any(value is not None for value in (self.prev_milestone_ref, self.prev_milestone_digest, self.amendment_ref, self.amendment_digest)):
                raise ValueError('first task milestone cannot claim an ordinary correction')
        else:
            for ref in (self.prev_milestone_ref, self.amendment_ref): _text(ref, 'actual correction predecessor')
            for digest in (self.prev_milestone_digest, self.amendment_digest): _digest(digest)


def decode_artifact_task_milestone_v2(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value = decode_typed_production_value_v1(raw, ArtifactTaskMilestoneV2)
    if plain_v1(value) != raw: raise ValueError('task milestone wire is not canonical')
    return value


def _artifact_task_milestone_basis_v2(db, *, selector, issuer):
    from .d08_personal_plan_v1 import _decode_goal, require_artifact_task_objective_original_v1
    from .ingress_artifact_task_scope_v1 import ArtifactTaskObjectiveV1, _decode
    ns = selector.task.namespace
    plan_row = db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?',
        (selector.plan_ref, selector.plan_revision)).fetchone()
    if plan_row is None or plan_row[1] != 1 or canonical_digest(json.loads(plan_row[0])) != selector.plan_digest:
        raise MissingProductionOriginalV1('actual_milestone_selected_plan_history')
    plan = json.loads(plan_row[0]); goal_ref = plan['goal_ref']
    goal_row = db.execute('SELECT value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
        (*ns.as_tuple, goal_ref)).fetchone()
    if goal_row is None or goal_row[1] != 1:
        raise MissingProductionOriginalV1('actual_current_milestone_goal')
    goal = _decode_goal(json.loads(goal_row[0]))
    ref, raw = require_artifact_task_objective_original_v1(db, namespace=ns, goal_ref=goal_ref, goal=goal, issuer=issuer)
    objective = _decode(raw, ArtifactTaskObjectiveV1)
    return objective, ref, canonical_digest(raw)


def _require_milestone_file_chain_v2(db, *, value, objective, previous, issuer):
    from .d11_artifact_draft_content_v1 import read_current_artifact_phase_verified_v2, _read_actual_phase_file_v2, _read_phase_content_adoption_original_v2
    expected_version = 0 if previous is None else previous.file_version
    phases = artifact_draft_phase_sequence_v2(value.selector.method_ref)
    latest = None
    for index, kind in enumerate(phases):
        if kind not in {'tone_sample', 'full'}: continue
        prior = value.ordered_phase_originals[index-1] if index else (None, None)
        selector = replace(value.selector, phase_index=index, phase_kind=kind,
            prev_phase_original_ref=prior[0], prev_phase_original_digest=prior[1])
        verified = read_current_artifact_phase_verified_v2(db, namespace=value.namespace, selector=selector, issuer=issuer)
        if (verified.original_ref, verified.digest) != value.ordered_phase_originals[index]:
            raise ValueError('milestone lost actual ordered generation file proof')
        adoption, _, _, _ = _read_phase_content_adoption_original_v2(db, namespace=value.namespace, selector=selector, issuer=issuer)
        prepared, _, _, witness = _read_actual_phase_file_v2(db, namespace=value.namespace, selector=selector,
            adoption=adoption, result_ref=verified.readback_original_ref, issuer=issuer)
        target = prepared.plan.target
        expected_version += 1
        if (witness.version != expected_version or witness.filename != objective.filename
                or (target.root_resource_id, target.root_identity) != (objective.root_resource_id, objective.root_identity)
                or target.mode != ('create' if expected_version == 1 else 'replace')
                or expected_version > 1 and target.expected_prior_version != expected_version - 1):
            raise ValueError('milestone physical file chain is not its exact same-file method predecessor')
        latest = witness
    if latest != value.readback:
        raise ValueError('milestone substituted a sample or another physical full-file witness')


def _derive_current_artifact_task_milestone_v2(db, *, frame, request, installed_readers):
    from .d11_artifact_draft_content_v1 import require_current_artifact_method_completion_v2
    from .foreground_cycle_v1 import foreground_cycle_ids_v1, foreground_cycle_from_wire_v1
    from .jobs import get_job
    from .artifact_phase_postconditions_v1 import _readers
    from .d11_life_preparation_v1 import _read, TABLE
    from .artifact_task_amendment_v1 import read_current_amendment_v1
    from .artifact_continuation_originals_v1 import read_selected_artifact_continuation_request_v1
    from .d11_offline_originals_v1 import _utc
    if type(request) is not RegisterCurrentArtifactTaskMilestoneRequestV2:
        raise TypeError('task milestone accepts only its final selected method selector')
    readers = _readers(installed_readers); selector = request.selector; ns = selector.task.namespace
    cycle = get_job(db, foreground_cycle_ids_v1(ns, selector.task.c02_operation_id)[1])
    if cycle is None: raise MissingProductionOriginalV1('actual_method_cycle_before_task_milestone')
    continuation = foreground_cycle_from_wire_v1(cycle.continuation)
    verified = require_current_artifact_method_completion_v2(db, namespace=ns, continuation=continuation,
        issuer=readers.issuer, now_utc=frame.now_utc, owner_guard=frame.owner_guard, installed_bundle=readers.bundle)
    if verified.selector != selector or frame.envelope.identity.operation_id != artifact_task_milestone_registration_operation_id_v2(selector):
        raise ValueError('task milestone changed its actual current final method and fixed operation')
    objective, objective_ref, objective_digest = _artifact_task_milestone_basis_v2(db, selector=selector, issuer=readers.issuer)
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1,IngressArtifactTaskScopeOriginalV1,_decode
    from .artifact_task_continuation_authorization_v2 import resolve_artifact_task_authorization_deadline_v2
    task_scope_row=_read(db,issuer=readers.issuer,namespace=ns,kind="artifact_task_scope",ref=task_scope_ref_v1(selector.task.root_registration_ref))
    if task_scope_row is None:raise MissingProductionOriginalV1("actual_task_milestone_scope")
    task_scope=_decode(task_scope_row[0],IngressArtifactTaskScopeOriginalV1)
    authorization_deadline=resolve_artifact_task_authorization_deadline_v2(db,namespace=ns,scope=task_scope,objective=objective,
        issuer=readers.issuer,bundle=readers.bundle,owner_guard=frame.owner_guard,now_utc=frame.now_utc,parent_budget_lease_ref=cycle.budget_ref)
    previous = None; amendment_ref = amendment_digest = None
    semantic_index = 1 if selector.task.c02_operation_id == objective.initial_c02_operation_id else 2
    if semantic_index == 2:
        rows = db.execute('SELECT original_ref FROM ' + TABLE + ' WHERE bot=? AND persona=? AND kind=? '
            "AND json_extract(payload_json,'$.objective_ref')=? AND json_extract(payload_json,'$.semantic_index')=1",
            (*ns.as_tuple, ARTIFACT_TASK_MILESTONE_KIND_V2, objective_ref)).fetchall()
        if len(rows) != 1: raise MissingProductionOriginalV1('actual_first_semantic_artifact_milestone')
        previous = read_current_artifact_task_milestone_v2(db, namespace=ns, original_ref=rows[0][0], issuer=readers.issuer)
        actual = read_current_amendment_v1(db, namespace=ns, root_registration_ref=selector.task.root_registration_ref, issuer=readers.issuer)
        selected = read_selected_artifact_continuation_request_v1(db, namespace=ns, selector=selector.task)
        if (actual is None or selected is None or (actual[0].objective_ref, actual[0].objective_digest, actual[0].goal_ref) !=
                (objective_ref, objective_digest, objective.goal_ref) or selected[0].correction_head_ref != actual[2].token
                or selected[0].predecessor_result_ref != previous.file_result_ref or selected[0].goal_ref != objective.goal_ref
                or selected[0].project_ref != objective.project_ref):
            raise MissingProductionOriginalV1('actual_ordinary_amendment_and_exact_previous_semantic_milestone')
        amendment_ref, amendment_digest = actual[1], canonical_digest(plain_v1(actual[0]))
    read = CurrentDomainReadV1(frame); read.check(db)
    for ref, kind, digest in ((objective_ref,'artifact_task_objective',objective_digest),
            (verified.original_ref,'c4_phase_verified',verified.digest)):
        read.original(ref,kind='d11.life_'+kind,digest=digest)
    value = ArtifactTaskMilestoneV2(selector, objective_ref, objective_digest, objective.goal_ref, objective.project_ref, semantic_index,
        continuation.call_plan.phase_group.completed_phase_originals, verified.original_ref, verified.digest,
        verified.readback_original_ref, verified.readback_original_digest, verified.source_head, verified.source_value_digest,
        verified.readback, frame.owner_guard, None if previous is None else previous.original_ref,
        None if previous is None else previous.digest, amendment_ref, amendment_digest, frame.now_utc,
        min(authorization_deadline,_utc(verified.original_deadline_utc).timestamp()), frame.envelope.identity.operation_id)
    _require_milestone_file_chain_v2(db, value=value, objective=objective, previous=previous, issuer=readers.issuer)
    return value


def stage_register_current_artifact_task_milestone_in_transaction_v2(db, *, frame, request, installed_readers):
    from .artifact_phase_postconditions_v1 import _readers, _empty_postcondition_stage_v1
    readers = _readers(installed_readers)
    try:
        value = _derive_current_artifact_task_milestone_v2(db, frame=frame, request=request, installed_readers=readers)
    except MissingProductionOriginalV1 as missing:
        return stage_result_v1(frame,'d08',ARTIFACT_TASK_MILESTONE_OPERATION_V2,request,coverage='waiting_for_original',missing=missing.missing_inputs)
    stage = stage_result_v1(frame,'d08',ARTIFACT_TASK_MILESTONE_OPERATION_V2,request,
        provenance={'artifact_task_milestone':value,'conditioned_source_roots':frame.envelope.source_qualification.source_refs,'conditioned_original_deadline_utc':frame.envelope.deadline_utc},
        receiver_events=(('d07','conditioned_observed_outcome_committed_v1'),))
    return _empty_postcondition_stage_v1(stage,frame,readers)


def require_artifact_task_milestone_history_v2(db, *, namespace, original_ref, producing_operation_id, raw):
    from .domain_background_read_v3 import background_json_loads_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d11_life_preparation_v1 import TABLE
    from .d11_artifact_draft_content_v1 import require_artifact_draft_phase_verified_history_v2
    value=decode_artifact_task_milestone_v2(raw)
    producer=read_adopted_domain_operation_v1(db,namespace,producing_operation_id)
    provenance=None if producer is None else producer['payload']['provenance']
    exact_provenance=provenance=={'artifact_task_milestone':raw}
    if type(provenance)is dict and set(provenance)=={'artifact_task_milestone','conditioned_source_roots','conditioned_original_deadline_utc'}:
        import math
        roots=provenance['conditioned_source_roots'];deadline=provenance['conditioned_original_deadline_utc']
        source_reads={row['key']for row in producer['payload']['read_versions']
            if row['revision']>0 and AtomKey.from_token(row['key']).type_name=='memory.source'}
        exact_provenance=(provenance['artifact_task_milestone']==raw and type(roots)is list
            and all(type(ref)is str for ref in roots)and len(set(roots))==len(roots)
            and value.source_head.key.token in roots and set(roots)<=source_reads
            and all(AtomKey.from_token(ref).token==ref and NamespaceId.from_key(AtomKey.from_token(ref))==namespace for ref in roots)
            and type(deadline)in {int,float}and math.isfinite(deadline)and deadline>producer['payload']['now_utc'])
    if (value.namespace!=namespace or value.original_ref!=original_ref or value.registration_operation_id!=producing_operation_id
            or producer is None or (producer['domain'],producer['operation_kind'])!=('d08',ARTIFACT_TASK_MILESTONE_OPERATION_V2)
            or producer['payload']['coverage']!='complete' or producer['receipt'].write_versions
            or producer['payload']['request']!=plain_v1(RegisterCurrentArtifactTaskMilestoneRequestV2(value.selector))
            or not exact_provenance
            or producer['payload']['now_utc']!=value.registered_at_utc):
        raise ValueError('task milestone has no exact empty-write actual signed W01 producer')
    def original(kind,ref,digest):
        row=_artifact_receipt_sql_v1(db,'SELECT payload_json,payload_digest,producing_operation_id FROM '+TABLE+
            ' WHERE bot=? AND persona=? AND kind=? AND original_ref=?',(*namespace.as_tuple,kind,ref)).fetchone()
        if row is None or row[1]!=digest: raise MissingProductionOriginalV1('actual_milestone_'+kind+'_original')
        return background_json_loads_v3(row[0]),row[2]
    objective_raw,_=original('artifact_task_objective',value.objective_ref,value.objective_digest)
    from .ingress_artifact_task_scope_v1 import ArtifactTaskObjectiveV1,_decode
    objective=_decode(objective_raw,ArtifactTaskObjectiveV1)
    if (objective.goal_ref,objective.project_ref,objective.filename)!=(value.goal_ref,value.project_ref,value.readback.filename):
        raise ValueError('milestone changed original same-file task objective')
    previous=None
    if value.semantic_index==1:
        if value.selector.task.c02_operation_id!=objective.initial_c02_operation_id:
            raise ValueError('first semantic milestone belongs to another task cause')
    else:
        prior,op=original(ARTIFACT_TASK_MILESTONE_KIND_V2,value.prev_milestone_ref,value.prev_milestone_digest)
        previous=require_artifact_task_milestone_history_v2(db,namespace=namespace,original_ref=value.prev_milestone_ref,producing_operation_id=op,raw=prior)
        if previous.semantic_index!=1 or (previous.objective_ref,previous.objective_digest)!=(value.objective_ref,value.objective_digest):
            raise ValueError('correction milestone lost its actual first task milestone')
        amendment,_=original('artifact_task_amendment',value.amendment_ref,value.amendment_digest)
        from .artifact_task_amendment_v1 import decode_amendment_v1
        amended=decode_amendment_v1(amendment)
        if (amended.objective_ref,amended.objective_digest,amended.goal_ref)!=(value.objective_ref,value.objective_digest,value.goal_ref):
            raise ValueError('correction milestone substituted another user task amendment')
        from .artifact_continuation_originals_v1 import read_selected_artifact_continuation_request_v1
        selected=read_selected_artifact_continuation_request_v1(db,namespace=namespace,selector=value.selector.task)
        if selected is None or selected[0].predecessor_result_ref!=previous.file_result_ref:
            raise ValueError('correction milestone lacks its actual same-file predecessor selection')
    phases=artifact_draft_phase_sequence_v2(value.selector.method_ref);generation=[]
    for index,(ref,digest) in enumerate(value.ordered_phase_originals):
        phase_raw,op=original('c4_phase_verified',ref,digest)
        verified=require_artifact_draft_phase_verified_history_v2(db,namespace=namespace,original_ref=ref,producing_operation_id=op,raw=phase_raw)
        prior=value.ordered_phase_originals[index-1] if index else (None,None)
        expected=replace(value.selector,phase_index=index,phase_kind=phases[index],prev_phase_original_ref=prior[0],prev_phase_original_digest=prior[1])
        if verified.selector!=expected: raise ValueError('milestone replaced its full ordered actual method phase prefix')
        if phases[index] in {'tone_sample','full'}: generation.append(verified)
    _require_milestone_file_history_v2(db,value=value,objective=objective,previous=previous,generation=tuple(generation),original=original)
    full_raw,full_op=original('c4_phase_verified',value.full_check_original_ref,value.full_check_original_digest)
    full=require_artifact_draft_phase_verified_history_v2(db,namespace=namespace,original_ref=value.full_check_original_ref,producing_operation_id=full_op,raw=full_raw)
    if full.method_qualified is not True or full.content_selector.phase_kind!='full' or full.readback!=value.readback:
        raise ValueError('milestone cannot claim sample or unqualified full content as a task milestone')
    return value


def _require_milestone_file_history_v2(db, *, value, objective, previous, generation, original):
    from .domain_background_read_v3 import background_json_loads_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .d11_life_preparation_v1 import TABLE,life_prepared_from_wire_v1
    from .d11_life_terminal_v1 import validate_adopted_life_member_history_v1
    from .d11_life_contract_v1 import D11LifeTerminalV1,life_from_wire_v1
    from .d11_life_adoption_v1 import require_draft_terminal_readback_v1
    version=0 if previous is None else previous.file_version;last=None
    for verified in generation:
        file_raw,file_op=original('adopted_life',verified.readback_original_ref,verified.readback_original_digest)
        validate_adopted_life_member_history_v1(db,value=file_raw,namespace=value.namespace,result_ref=verified.readback_original_ref,producing_operation_id=file_op)
        terminal=life_from_wire_v1(file_raw['terminal'],D11LifeTerminalV1)
        row=_artifact_receipt_sql_v1(db,'SELECT payload_json FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
            (*value.namespace.as_tuple,'prepared',terminal.binding.prepared_original_ref)).fetchone()
        if row is None: raise MissingProductionOriginalV1('actual_milestone_file_preparation')
        prepared=life_prepared_from_wire_v1(background_json_loads_v3(row[0]));witness=require_draft_terminal_readback_v1(prepared=prepared,terminal=terminal)
        version+=1;target=prepared.plan.target
        if (witness.version!=version or witness.filename!=objective.filename or witness!=verified.readback
                or (target.root_resource_id,target.root_identity)!=(objective.root_resource_id,objective.root_identity)
                or target.mode!=('create' if version==1 else 'replace') or version>1 and target.expected_prior_version!=version-1):
            raise ValueError('milestone changed actual physical same-file method continuity')
        last=verified
    if (last is None or (value.file_result_ref,value.file_result_digest,value.source_head,value.source_value_digest,value.readback)!=
            (last.readback_original_ref,last.readback_original_digest,last.source_head,last.source_value_digest,last.readback)):
        raise ValueError('milestone full file/source witness differs from its final generation')


def read_current_artifact_task_milestone_v2(db, *, namespace, original_ref, issuer):
    from .domain_background_read_v3 import background_json_loads_v3, background_json_digest_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .d11_life_preparation_v1 import _read
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    raw=_read(db,issuer=issuer,namespace=namespace,kind=ARTIFACT_TASK_MILESTONE_KIND_V2,ref=original_ref)
    if raw is None: raise MissingProductionOriginalV1('actual_signed_task_semantic_milestone')
    value=require_artifact_task_milestone_history_v2(db,namespace=namespace,original_ref=original_ref,producing_operation_id=raw[1],raw=raw[0])
    guard=value.owner_guard
    owner=_artifact_receipt_sql_v1(db,'SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
        (*namespace.as_tuple,guard.grant_ref)).fetchone()
    if owner is None or owner[2]!=1 or (owner[0],background_json_digest_v3(owner[1],background_json_loads_v3(owner[1])))!=(guard.grant_revision,guard.grant_digest):
        raise MissingProductionOriginalV1('current_owner_access_to_completed_task_milestone')
    source=_artifact_receipt_sql_v1(db,'SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
        (*namespace.as_tuple,value.source_head.key.token)).fetchone()
    if source is None or source[2]!=1 or (source[0],background_json_digest_v3(source[1],background_json_loads_v3(source[1])))!=(value.source_head.revision,value.source_value_digest):
        raise MissingProductionOriginalV1('current_source_access_to_completed_task_milestone')
    _source_family_current_sql_v1(db,namespace=namespace,roots=(value.source_head.key.token,),purpose='consolidation',audiences=tuple(background_json_loads_v3(source[1])['audiences']))
    return value


def read_plan_current_artifact_task_milestone_v2(db, *, namespace, request, installed_readers):
    from .domain_background_read_v3 import background_json_loads_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .artifact_phase_postconditions_v1 import _readers
    from .d11_artifact_draft_content_v1 import read_plan_artifact_draft_phase_verification_v2, VerifyArtifactDraftPhaseRequestV2
    from .d11_life_preparation_v1 import _read,TABLE
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..model_broker.artifact_draft_v1 import artifact_draft_phase_original_ref_v2
    from .artifact_phase_postconditions_v1 import artifact_phase_assessment_original_ref_v1
    readers=_readers(installed_readers)
    if type(request) is not RegisterCurrentArtifactTaskMilestoneRequestV2 or request.selector.task.namespace!=namespace:
        raise TypeError('same namespace final selected method milestone read recipe required')
    selector=request.selector;ref=artifact_draft_phase_original_ref_v2(selector)+':verified'
    row=_read(db,issuer=readers.issuer,namespace=namespace,kind='c4_phase_verified',ref=ref)
    if row is None: raise MissingProductionOriginalV1('actual_final_full_check_before_milestone')
    from .d11_artifact_draft_content_v1 import artifact_draft_phase_verification_from_wire_v2,ArtifactDraftPhaseVerifiedOriginalV2
    verified=artifact_draft_phase_verification_from_wire_v2(row[0],ArtifactDraftPhaseVerifiedOriginalV2)
    base=read_plan_artifact_draft_phase_verification_v2(db,namespace=namespace,
        request=VerifyArtifactDraftPhaseRequestV2(selector,verified.readback_original_ref,(artifact_phase_assessment_original_ref_v1(selector),)),
        installed_readers=readers.model_readers)
    objective,objective_ref,_=_artifact_task_milestone_basis_v2(db,selector=selector,issuer=readers.issuer)
    originals=[*base.required_original_refs,ref,objective_ref];keys=[*base.exact_keys,AtomKey.from_token(objective.goal_ref)]
    roots=[*base.source_roots,objective.source_ref,verified.source_head.key.token]
    prior=_artifact_receipt_sql_v1(db,'SELECT original_ref,payload_json FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? '
        "AND json_extract(payload_json,'$.objective_ref')=?",(*namespace.as_tuple,ARTIFACT_TASK_MILESTONE_KIND_V2,objective_ref)).fetchall()
    for prior_ref,raw in prior:
        value=decode_artifact_task_milestone_v2(background_json_loads_v3(raw));originals.append(prior_ref)
        originals.extend((value.full_check_original_ref,value.file_result_ref))
        keys.append(value.source_head.key);roots.append(value.source_head.key.token)
    if selector.task.c02_operation_id!=objective.initial_c02_operation_id:
        from .artifact_task_amendment_v1 import read_current_amendment_v1
        actual=read_current_amendment_v1(db,namespace=namespace,root_registration_ref=selector.task.root_registration_ref,issuer=readers.issuer)
        if actual is not None: originals.append(actual[1]);keys.append(actual[2])
    return production_read_plan_v1(base.fixed_type_ids,keys,roots,originals)


def record_artifact_task_milestone_after_cas_v2(db, *, frame, stage, receipt, issuer):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d11_life_preparation_v1 import _record
    if receipt.status!='committed' or receipt.operation_id!=frame.envelope.identity.operation_id:
        raise ValueError('task milestone signature requires its actual same-transaction CAS')
    actual=read_adopted_domain_operation_v1(db,frame.envelope.authority.namespace,receipt.operation_id)
    if actual is None or actual['receipt']!=receipt or actual['original_digest']!=stage.original_digest:
        raise ValueError('task milestone cannot be signed before its real W01 adoption')
    raw=actual['payload']['provenance']['artifact_task_milestone']
    decoded=decode_artifact_task_milestone_v2(raw)
    value=require_artifact_task_milestone_history_v2(db,namespace=frame.envelope.authority.namespace,
        original_ref=decoded.original_ref,
        producing_operation_id=receipt.operation_id,raw=raw)
    return _record(db,issuer=issuer,namespace=value.namespace,kind=ARTIFACT_TASK_MILESTONE_KIND_V2,
        ref=value.original_ref,operation_id=receipt.operation_id,value=value)


def read_current_artifact_task_milestone_original_ref_v2(db, *, namespace, original_ref, issuer):
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    from .d11_life_preparation_v1 import TABLE
    row=_artifact_receipt_sql_v1(db,'SELECT 1 FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
        (*namespace.as_tuple,ARTIFACT_TASK_MILESTONE_KIND_V2,original_ref)).fetchone()
    if row is None: return None
    value=read_current_artifact_task_milestone_v2(db,namespace=namespace,original_ref=original_ref,issuer=issuer)
    return ProductionOriginalRefV1('d11.life_'+ARTIFACT_TASK_MILESTONE_KIND_V2,value.original_ref,value.digest,(value.source_head,))


@dataclass(frozen=True,slots=True)
class ArtifactTaskObservationV2:
    objective_ref: str
    objective_digest: str
    goal_ref: str
    project_ref: str
    phase: str
    milestones: tuple[ArtifactTaskMilestoneV2,...]
    selected_node_id: str
    checkpoint: ProjectCheckpointV1
    schema: str='d08.artifact-task-observation.v2'

    def __post_init__(self):
        if (self.schema!='d08.artifact-task-observation.v2' or self.phase not in {'partial','satisfied'}
                or type(self.milestones) is not tuple or len(self.milestones)!=(1 if self.phase=='partial' else 2)
                or any(type(value) is not ArtifactTaskMilestoneV2 for value in self.milestones)
                or tuple(value.semantic_index for value in self.milestones)!=tuple(range(1,len(self.milestones)+1))
                or any((value.objective_ref,value.objective_digest,value.goal_ref,value.project_ref)!=(
                    self.objective_ref,self.objective_digest,self.goal_ref,self.project_ref) for value in self.milestones)
                or type(self.checkpoint) is not ProjectCheckpointV1
                or self.checkpoint.state!=('waiting' if self.phase=='partial' else 'completed')):
            raise ValueError('V2 task observation requires genuine ordered semantic milestones and its exact checkpoint')


def stage_observe_artifact_task_v2(db, *, frame, request, readers, goal_atom, plan_atom, goal, plan, evidence):
    from .d08_personal_plan_v1 import _plan_stage,require_artifact_task_objective_original_v1
    from .d10_project_checkpoint_v1 import _current_artifact_task_final_selector_v2
    from .artifact_continuation_originals_v1 import read_artifact_control_history_v1
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    from .d11_life_preparation_v1 import TABLE
    from .ingress_artifact_task_scope_v1 import ArtifactTaskObjectiveV1,_decode
    read=CurrentDomainReadV1(frame);read.check(db);ns=frame.envelope.authority.namespace
    selector=_current_artifact_task_final_selector_v2(db,namespace=ns,plan_ref=request.plan_ref)
    latest=read_current_artifact_task_milestone_v2(db,namespace=ns,original_ref=artifact_task_milestone_original_ref_v2(selector),issuer=readers.issuer)
    objective_ref,raw=require_artifact_task_objective_original_v1(db,namespace=ns,goal_ref=request.goal_ref,goal=goal,issuer=readers.issuer)
    objective=_decode(raw,ArtifactTaskObjectiveV1)
    if (latest.goal_ref!=request.goal_ref or latest.project_ref!=objective.project_ref or latest.objective_ref!=objective_ref
            or latest.owner_guard!=frame.owner_guard or frame.now_utc>=latest.original_deadline_utc
            or goal.state!='active' or plan.state not in {'active','waiting'}
            or (evidence.artifact_ref,evidence.artifact_digest,evidence.work_version,evidence.effect_id)!=(
                latest.file_result_ref,latest.readback.content_digest,latest.file_version,latest.readback.effect_id)
            or not evidence.completed_verified):
        raise MissingProductionOriginalV1('actual_current_full_method_semantic_milestone_before_goal_transition')
    milestones=(latest,) if latest.semantic_index==1 else (read_current_artifact_task_milestone_v2(db,namespace=ns,
        original_ref=latest.prev_milestone_ref,issuer=readers.issuer),latest)
    cp_key=project_checkpoint_key_v1(ns,objective.project_ref)
    cp_atom,_,cp_original=read_artifact_control_history_v1(db,frame=frame,ref=cp_key.token)
    checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,cp_atom.value)
    if (checkpoint.plan_ref!=request.plan_ref or checkpoint.plan_revision!=plan.revision
            or checkpoint.state!='completed' or checkpoint.next_step is not None
            or request.progress_ref not in checkpoint.progress_refs or len(checkpoint.work_version_refs)!=len(milestones)):
        raise MissingProductionOriginalV1('actual_selected_method_project_milestone_checkpoint')
    works=[]
    for work_ref in checkpoint.work_version_refs:
        atom,_,_=read_artifact_control_history_v1(db,frame=frame,ref=work_ref)
        if not atom.valid:raise ValueError('semantic milestone project work is invalid')
        works.append(decode_project_checkpoint_type_v1(WORK_TYPE,atom.value))
    works.sort(key=lambda value:value.version)
    for work,milestone in zip(works,milestones):
        if (work.project_ref,work.version,work.artifact_ref,work.artifact_digest,work.effect_id)!=(
                milestone.project_ref,milestone.file_version,milestone.file_result_ref,milestone.readback.content_digest,milestone.readback.effect_id):
            raise ValueError('semantic milestone does not match actual physical project work')
        read.original(milestone.original_ref,kind='d11.life_artifact_task_milestone_v2',digest=milestone.digest)
    selected=works[-1].node_id
    if selected not in checkpoint.completed_node_refs:raise ValueError('task observation has no actual selected completed method node')
    phase='partial' if latest.semantic_index==1 else 'satisfied'
    updated_goal=replace(goal,revision=goal_atom.revision+1,state='active' if phase=='partial' else 'satisfied',
        progress_refs=tuple(dict.fromkeys((*goal.progress_refs,request.progress_ref))))
    updated_plan=replace(plan,revision=plan_atom.revision+1,goal_revision=updated_goal.revision,
        state='waiting' if phase=='partial' else 'satisfied',candidate_refs=(),method_candidates=(),waiting_conditions=(objective_ref,) if phase=='partial' else (),
        parent_plan_revision_ref=VersionedRef(request.plan_ref,plan_atom.revision))
    wake=ProjectTaskWaitConditionV1(objective_ref,latest.objective_digest,plan.fact_versions,
        QueryEpoch(ns,'namespace',frame.snapshot.epochs[0].revision),cp_original['receipt'].commit_seq) if phase=='partial' else None
    updated_cp=replace(checkpoint,revision=cp_atom.revision+1,plan_revision=updated_plan.revision,
        state='waiting' if phase=='partial' else 'completed',wait_condition=wake)
    observation=ArtifactTaskObservationV2(objective_ref,latest.objective_digest,request.goal_ref,objective.project_ref,phase,
        milestones,selected,updated_cp)
    primary=_plan_stage(frame,'settle_personal_goal',request,(GraphWrite(goal_atom.key,plain_v1(updated_goal)),
        GraphWrite(plan_atom.key,plain_v1(updated_plan))),actual_effect=evidence,task_observation=observation)
    from ..domains.d10 import LifeDomain
    checkpoint_stage=stage_result_v1(frame,'d10','settle_personal_goal',request,writes=(GraphWrite(cp_key,plain_v1(updated_cp)),),
        proposal_schema='d10.proposal.v1',proposal_hash=LifeDomain().descriptor.request_schema_hash)
    return ArtifactTaskSettlementStageV1(primary,checkpoint_stage)
