"""Actual original joins for the finite existing-artifact revision path.

These helpers never reactivate old permission, read old file bytes, acquire an
execution, commit, or treat a typed proposal as authority. Caller is the private
W01 foreground stage and supplies its actual CurrentOperationFrameV1.
"""
from dataclasses import dataclass
import json

from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d08.execution import _decode_goal
from ..domains.d08.personal_plan_v1 import PLAN_TYPE, decode_personal_plan_type_v1
from ..domains.d10.project_checkpoint_v1 import (
    CHECKPOINT_TYPE, WORK_TYPE, decode_project_checkpoint_type_v1, project_checkpoint_key_v1,
)
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d11_life_preparation_v1 import _read, read_prepared_life_v1
from .d11_life_terminal_v1 import read_adopted_life_original_v1
from .d11_life_adoption_v1 import require_draft_terminal_readback_v1
from .d11_life_contract_v1 import D11LifeTerminalV1, D11DraftTerminalV1, life_from_wire_v1
from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
from .d11_offline_originals_v1 import _utc
from .artifact_continuation_v1 import ExistingArtifactRevisionBasisV1


@dataclass(frozen=True, slots=True)
class InstalledArtifactContinuationReadersV1:
    issuer: object
    resource_issuer: object
    model_readers: object

    def __post_init__(self):
        from .issuers import D11BudgetJobIssuer, D02ResourceIssuer
        from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
        if (type(self.issuer) is not D11BudgetJobIssuer
                or type(self.resource_issuer) is not D02ResourceIssuer
                or type(self.model_readers) is not InstalledArtifactDraftModelReadersV1
                or self.model_readers.issuer is not self.issuer):
            raise TypeError("actual installed artifact/Body original readers required")


def read_artifact_control_history_v1(db, *, frame, ref):
    """Read a current CAS head and its actual last valid producer independently."""
    read = CurrentDomainReadV1(frame)
    atom = read.head(db, ref)
    if atom.revision < 1:
        raise MissingProductionOriginalV1("existing_artifact_control_head")
    row = db.execute(
        "SELECT revision,event_id,value FROM graph_history WHERE token=? AND valid=1 "
        "AND revision<=? ORDER BY revision DESC LIMIT 1",
        (atom.key.token, atom.revision)).fetchone()
    if row is None or json.loads(row[2]) != atom.value:
        raise MissingProductionOriginalV1("exact_existing_artifact_control_history")
    original = read_adopted_domain_operation_v1(
        db, frame.envelope.authority.namespace, row[1])
    allowed = {
        "d08.goal.v1": {
            ("d10", "derive_ingress_artifact_task_scope_v1"),
            ("d08", "compose_artifact_goal_plan"), ("d08", "revise_personal_plan"),
            ("d08", "settle_personal_goal"), ("d08", "revise_existing_artifact_v1")},
        PLAN_TYPE: {
            ("d08", "compose_artifact_goal_plan"), ("d08", "revise_personal_plan"),
            ("d08", "settle_personal_goal"), ("d08", "revise_existing_artifact_v1")},
        "d10.life_project.v1": {
            ("d10", "create_artifact_project"), ("d08", "revise_existing_artifact_v1")},
        "d10.activity_recipe.v1": {
            ("d10", "create_artifact_project"), ("d08", "revise_existing_artifact_v1")},
        WORK_TYPE: {("d10", "settle_project_checkpoint")},
        CHECKPOINT_TYPE: {
            ("d10", "initialize_project_checkpoint"), ("d10", "refresh_project_checkpoint"),
            ("d10", "settle_project_checkpoint"), ("d08", "revise_existing_artifact_v1"),
            ("d10", "await_existing_artifact_revision_v1"), ("d08","settle_personal_goal")},
    }
    if (original is None
            or (original["domain"], original["operation_kind"]) not in allowed[atom.key.type_name]
            or GraphVersion(atom.key, row[0]) not in original["receipt"].write_versions):
        raise MissingProductionOriginalV1("actual_registered_artifact_control_producer")
    if atom.key.type_name == CHECKPOINT_TYPE and (original["domain"],original["operation_kind"])==("d08","settle_personal_goal"):
        from .artifact_task_observer_v1 import require_task_observer_checkpoint_member_v1
        from ..graph_types import GraphAtom
        require_task_observer_checkpoint_member_v1(db,namespace=frame.envelope.authority.namespace,
            original=original,atom=GraphAtom(atom.key,row[0],atom.value,True))
    if atom.key.type_name == CHECKPOINT_TYPE and original["operation_kind"] in {
            "await_existing_artifact_revision_v1", "revise_existing_artifact_v1"}:
        from .artifact_wait_checkpoint_v1 import require_finite_artifact_checkpoint_member_v1
        from ..graph_types import GraphAtom
        require_finite_artifact_checkpoint_member_v1(db,
            namespace=frame.envelope.authority.namespace, original=original,
            atom=GraphAtom(atom.key, row[0], atom.value, True))
    return atom, GraphVersion(atom.key, row[0]), original


def read_completed_draft_predecessor_v1(db, *, frame, result_ref, issuer):
    read = CurrentDomainReadV1(frame)
    ns = frame.envelope.authority.namespace
    adopted = read_adopted_life_original_v1(
        db, namespace=ns, result_ref=result_ref, issuer=issuer)
    if adopted is None:
        raise MissingProductionOriginalV1("actual_signed_old_draft_result")
    terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
    if type(terminal) is not D11DraftTerminalV1 or terminal.status != "completed":
        raise MissingProductionOriginalV1("query_original_draft_effect_without_new_attempt")
    prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=issuer)
    if prepared is None:
        raise MissingProductionOriginalV1("actual_signed_old_draft_prepared")
    witness = require_draft_terminal_readback_v1(prepared=prepared, terminal=terminal)
    if witness.root_registration_digest != prepared.plan.target.root_registration_digest:
        raise ValueError("old file witness must retain its own original root provenance")
    read.original(result_ref, kind="d11.life_adopted_life", digest=canonical_digest(adopted))
    read.original(terminal.binding.prepared_original_ref)
    return prepared, terminal, adopted, witness


def read_current_artifact_renewal_root_v1(
    db, *, frame, selector, installed_readers, predecessor,
):
    """Reuse current C4 task/Self/Owner/root checks; never extend an old root."""
    from .d11_artifact_draft_model_v1 import _current_task
    read, cycle, continuation, root, family, mapping_atom, mapping = _current_task(
        db, frame=frame, selector=selector, readers=installed_readers.model_readers)
    old = predecessor.plan.target
    if (root.resource_id != old.root_resource_id
            or root.root_identity != old.root_identity
            or root.filenames != (old.filename,)
            or root.source_ref != continuation.source_ref):
        raise ValueError("fresh actual Owner root must name the same unique physical file")
    from .ingress_artifact_task_scope_v1 import (SCOPE_KIND,task_scope_ref_v1,IngressArtifactTaskScopeOriginalV1,
        IngressArtifactTaskScopeOriginalV3,ArtifactTaskObjectiveV1,_decode)
    scope_row=_read(db,issuer=installed_readers.issuer,namespace=selector.namespace,kind=SCOPE_KIND,ref=task_scope_ref_v1(root.registration_ref))
    if scope_row is not None:
        scope=_decode(scope_row[0],IngressArtifactTaskScopeOriginalV1)
        if type(scope) is IngressArtifactTaskScopeOriginalV3:
            from .artifact_task_continuation_authorization_v2 import resolve_artifact_task_authorization_deadline_v2
            objective_row=_read(db,issuer=installed_readers.issuer,namespace=selector.namespace,kind="artifact_task_objective",ref=scope.objective_ref)
            objective=_decode(objective_row[0],ArtifactTaskObjectiveV1)
            resolve_artifact_task_authorization_deadline_v2(db,namespace=selector.namespace,scope=scope,objective=objective,
                issuer=installed_readers.issuer,bundle=installed_readers.model_readers.installed_bundle,
                owner_guard=frame.owner_guard,now_utc=frame.now_utc,parent_budget_lease_ref=cycle.budget_ref)
            authorization=scope.continuation_authorization
            if (authorization.predecessor_result_ref,authorization.predecessor_effect_id)!=(predecessor.binding.artifact_ref,predecessor.binding.effect_id):
                raise ValueError("fresh continuation Root changed its explicitly authorized predecessor")
    return read, cycle, continuation, root, family, mapping_atom, mapping


def read_existing_artifact_basis_v1(
    db, *, frame, project_ref, goal_ref, plan_ref, recipe_ref,
    predecessor_result_ref, correction_head_ref, installed_readers,
):
    """Rebuild selected existing-work metadata; selection itself is W01-bound.

    W01 must already have bound the unique selected project to the actual
    fresh Root filename and authenticated correction/C03 selection original.
    This reader does not choose a project by textual similarity.
    """
    from ..domains.d06 import validate_source_correction_head
    from .d08_personal_plan_v1 import InstalledD08PersonalPlanReadersV1
    from .d11_life_outcome_provenance_v1 import life_outcome_key_v1
    if type(installed_readers) is not InstalledArtifactContinuationReadersV1:
        raise TypeError("installed continuation readers required")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    checkpoint_ref = project_checkpoint_key_v1(ns, project_ref).token
    refs = (goal_ref, plan_ref, project_ref, recipe_ref, checkpoint_ref)
    controls = tuple(read_artifact_control_history_v1(db, frame=frame, ref=ref) for ref in refs)
    goal, plan = _decode_goal(controls[0][0].value), decode_personal_plan_type_v1(PLAN_TYPE, controls[1][0].value)
    from .d08_personal_plan_v1 import require_artifact_task_objective_original_v1
    objective_ref, _ = require_artifact_task_objective_original_v1(db, namespace=ns,
        goal_ref=goal_ref, goal=goal, issuer=installed_readers.issuer)
    read.original(objective_ref)
    checkpoint = decode_project_checkpoint_type_v1(CHECKPOINT_TYPE, controls[4][0].value)
    previous, terminal, adopted, witness = read_completed_draft_predecessor_v1(
        db, frame=frame, result_ref=predecessor_result_ref, issuer=installed_readers.issuer)
    if (previous.plan.project.ref != project_ref or previous.plan.recipe.ref != recipe_ref
            or plan.goal_ref != goal_ref or checkpoint.plan_ref != plan_ref
            or checkpoint.project_ref != project_ref or goal.state != "active"):
        raise ValueError("existing draft/goal/plan/checkpoint identity differs")
    correction = read.head(db, correction_head_ref, required=True)
    from .artifact_task_amendment_v1 import TYPE as AMENDMENT_TYPE,read_current_amendment_v1
    if correction.key.type_name==AMENDMENT_TYPE:
        actual=read_current_amendment_v1(db,namespace=ns,
            root_registration_ref=correction.value["root_registration_ref"],issuer=installed_readers.issuer)
        if (actual is None or actual[2]!=correction.key or plain_v1(actual[0])!=correction.value
                or (actual[0].goal_ref,actual[0].project_ref,actual[0].objective_ref)!=(goal_ref,project_ref,objective_ref)):
            raise ValueError("ordinary amendment differs from the exact unfinished task")
        read.original(actual[1],kind="d11.life_artifact_task_amendment",digest=canonical_digest(correction.value))
    else:
        validate_source_correction_head(correction.key, correction.value)
        if (correction.value["source_ref"] not in plan.source_refs
                or correction.value["state"] != "pending_reevaluation"):
            raise ValueError("actual pending correction must identify an old plan Source")
    # This is a metadata lineage proof only. We do not traverse its corrected
    # Source as semantic input or claim the global correction has been resolved.
    history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
        (correction_head_ref, correction.revision)).fetchone()
    if history is None or history[1:] != (canonical_serialize(correction.value), 1):
        raise ValueError("source correction lost its actual immutable producer")
    committed = read.committed_operation(db, history[0])
    personal = InstalledD08PersonalPlanReadersV1(
        issuer=installed_readers.issuer, resource_issuer=installed_readers.resource_issuer)
    actions, outcomes, commitments = personal.obligations(db, read, goal.goal_id)
    works = {}
    for ref in checkpoint.work_version_refs:
        atom, version, original = read_artifact_control_history_v1(db, frame=frame, ref=ref)
        work = decode_project_checkpoint_type_v1(WORK_TYPE, atom.value)
        if (work.project_ref != project_ref or work.progress_ref not in checkpoint.progress_refs
                or work.node_id not in checkpoint.completed_node_refs
                or work.effect_id in works):
            raise ValueError("checkpoint work metadata does not join its actual completed nodes")
        works[work.effect_id] = work
    by_action = {}
    for atom, outcome in outcomes:
        by_action.setdefault(outcome.action_id, []).append((atom, outcome))
    verified = {node.node_id: [] for node in plan.nodes}
    for atom, action in actions:
        found = by_action.get(action.action_id, ())
        if (len(found) != 1 or found[0][1].result_level != "completed_verified"
                or found[0][1].unknown_effects):
            raise MissingProductionOriginalV1("query_original_unresolved_artifact_action")
        outcome = found[0][1]
        result = dict(action.success_predicate.parameters).get("artifact_ref")
        if result is None:
            raise ValueError("existing non-artifact obligation cannot be silently continued")
        prep, term, original, file_readback = read_completed_draft_predecessor_v1(
            db, frame=frame, result_ref=result, issuer=installed_readers.issuer)
        work = works.get(term.binding.effect_id)
        if (work is None or (work.artifact_ref, work.artifact_digest, work.artifact_length,
                work.terminal_ref, work.activity_id, work.attempt_id) !=
                (term.binding.artifact_ref, file_readback.content_digest, file_readback.content_length,
                 term.original_ref, term.binding.activity_id, term.binding.attempt_id)):
            raise ValueError("old actual work version differs from the signed file result")
        outcome_key = life_outcome_key_v1(term.binding, prep.plan.action_intent.ref)
        actual = read.head(db, outcome_key)
        commitment = next((row for row in original["write_commitments"] if row["ref"] == outcome_key.token), None)
        if (commitment is None or commitment["digest"] != canonical_digest(actual.value)
                or actual != found[0][0] or outcome.effect_id != term.binding.effect_id
                or outcome.completed_effects != (term.binding.effect_id,)
                or outcome.observation_refs != (term.original_ref,)
                or prep.plan.action_intent.ref != atom.key.token
                or prep.plan.project.ref != project_ref):
            raise ValueError("old Action outcome does not join its signed actual file completion")
        matches = tuple(node for node in plan.nodes
            if node.action_kind == action.action_kind and node.success_predicate == action.success_predicate)
        if len(matches) != 1 or matches[0].node_id != work.node_id:
            raise ValueError("old completed effect must map to one existing node")
        verified[matches[0].node_id].append(term.binding.effect_id)
    return ExistingArtifactRevisionBasisV1(
        goal_ref, plan_ref, project_ref, recipe_ref, checkpoint_ref,
        tuple(GraphVersion(atom.key, atom.revision) for atom, _, _ in controls),
        tuple(version for _, version, _ in controls),
        tuple(original["original_digest"] for _, _, original in controls),
        goal, plan, checkpoint, controls[2][0].value, controls[3][0].value, controls[3][0].valid,
        predecessor_result_ref, previous.digest, canonical_digest(adopted),
        terminal.binding.effect_id, previous.plan.target, witness.version,
        witness.content_digest, witness.file_identity, witness.effect_marker,
        tuple((node.node_id, tuple(sorted(verified[node.node_id]))) for node in plan.nodes),
        correction_head_ref, correction.revision, committed[0])


def artifact_continuation_operation_id_v1(selector, *, revision=False):
    from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
    if type(selector) is not ArtifactDraftTaskSelectorV1:
        raise TypeError("actual current artifact selector required")
    phase = "revise" if revision else "select"
    return "artifact-continuation-" + phase + ":" + canonical_digest(
        ("d08.existing-artifact-continuation.v1", selector, phase))[:48]


def require_actual_renewed_predecessor_v1(
    db, *, frame, plan, previous, terminal, witness, issuer,
):
    """Finite cross-registration relation; never an alternative current Root check."""
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    from .d11_artifact_draft_contract_v1 import DraftActivityScopeV1
    ns, target = frame.envelope.authority.namespace, plan.target
    original = _read(db, issuer=issuer, namespace=ns, kind="activity_scope",
                     ref=plan.activity_scope_ref)
    if original is None:
        raise MissingProductionOriginalV1("actual_new_draft_activity_scope")
    scope = draft_from_wire_v1(original[0], DraftActivityScopeV1)
    selector = artifact_draft_task_selector_v1(ns,
        c02_operation_id=scope.c02_original_ref, root_registration_ref=target.root_registration_ref)
    selection = read_adopted_domain_operation_v1(
        db, ns, artifact_continuation_operation_id_v1(selector))
    if (selection is None or (selection["domain"], selection["operation_kind"]) !=
            ("d08", "select_existing_artifact_continuation_v1")):
        raise MissingProductionOriginalV1("actual_adopted_existing_artifact_selection")
    p = selection["payload"]["provenance"]
    if (set(p) != {"schema", "selector", "basis", "replacement_target"}
            or p["schema"] != "d08.existing-artifact-continuation-original.v1"
            or p["selector"] != plain_v1(selector) or p["replacement_target"] != plain_v1(target)
            or p["basis"]["predecessor_result_ref"] != terminal.binding.artifact_ref
            or p["basis"]["predecessor_prepared_digest"] != previous.digest
            or p["basis"]["predecessor_target"] != plain_v1(previous.plan.target)
            or p["basis"]["predecessor_effect_id"] != terminal.binding.effect_id
            or p["basis"]["prior_effect_marker"] != witness.effect_marker):
        raise ValueError("renewed root is not the actual selected existing file lineage")
    root_row = _read(db, issuer=issuer, namespace=ns, kind="draft_root_capability",
                     ref=target.root_registration_ref)
    if root_row is None:
        raise MissingProductionOriginalV1("actual_fresh_owner_draft_root")
    root = draft_from_wire_v1(root_row[0], DraftRootCapabilityV1)
    guard = frame.owner_guard
    if (canonical_digest(plain_v1(scope)) != plan.activity_scope_digest
            or scope.actor_ref != frame.envelope.authority.actor
            or scope.activity_id != plan.activity_id or scope.source.ref != plan.input_source.ref
            or scope.root_registration_ref != root.registration_ref
            or scope.root_registration_digest != canonical_digest(plain_v1(root))
            or (root.owner_grant_ref, root.owner_grant_revision, root.owner_grant_digest) !=
               (guard.grant_ref, guard.grant_revision, guard.grant_digest)
            or root.source_ref != plan.input_source.ref
            or root.resource_id != target.root_resource_id or root.root_identity != target.root_identity
            or root.filenames != (target.filename,) or target.max_bytes > root.max_bytes
            or canonical_digest(plain_v1(root)) != target.root_registration_digest
            or not frame.now_utc < min(_utc(root.valid_until_utc).timestamp(),
                                      _utc(scope.valid_until_utc).timestamp())):
        raise ValueError("current actual Owner root/activity authority changed")
    CurrentDomainReadV1(frame).source_family(db, (root.source_ref,), purpose="consolidation")
    return selection


@dataclass(frozen=True, slots=True)
class ExistingArtifactContinuationRequestV1:
    selector: ArtifactDraftTaskSelectorV1
    project_ref: str
    goal_ref: str
    plan_ref: str
    recipe_ref: str
    predecessor_result_ref: str
    correction_head_ref: str


@dataclass(frozen=True, slots=True)
class ExistingArtifactRevisionStageV1:
    frame: object
    request: ExistingArtifactContinuationRequestV1
    stage: object
    d10_stage: object
    candidate: object
    bundle: object


def require_unique_existing_artifact_project_v1(db, *, frame, basis, root):
    """Closed namespace inventory; no first-match or text-similarity selection."""
    read = CurrentDomainReadV1(frame)
    projects = read.complete_inventory(db, "d10.life_project.v1")
    goals = {atom.key.token: atom for atom in read.complete_inventory(db, "d08.goal.v1")}
    matches = []
    for project in projects:
        if project.value.get("topic") != root.filenames[0]:
            continue
        _, _, original = read_artifact_control_history_v1(db, frame=frame, ref=project.key.token)
        p = original["payload"]["provenance"]
        if original["operation_kind"] == "create_artifact_project":
            target, goal_ref = p["artifact_content_adoption"]["target"], p["artifact_goal_ref"]
        else:
            target, goal_ref = p["content_adoption"]["target"], p["basis"]["goal_ref"]
        goal = goals.get(goal_ref)
        if (goal is not None and goal.value.get("state") == "active"
                and target["root_resource_id"] == root.resource_id
                and target["root_identity"] == plain_v1(root.root_identity)
                and target["filename"] == root.filenames[0]):
            matches.append(project.key.token)
    if matches != [basis.project_ref]:
        raise MissingProductionOriginalV1("unique_existing_artifact_project_for_actual_owner_root")


def _request_basis(db, *, frame, request, installed_readers):
    if type(request) is not ExistingArtifactContinuationRequestV1:
        raise TypeError("closed existing artifact selector required")
    return read_existing_artifact_basis_v1(db, frame=frame,
        project_ref=request.project_ref, goal_ref=request.goal_ref, plan_ref=request.plan_ref,
        recipe_ref=request.recipe_ref, predecessor_result_ref=request.predecessor_result_ref,
        correction_head_ref=request.correction_head_ref, installed_readers=installed_readers)


def stage_select_existing_artifact_continuation_v1(db, *, frame, request, installed_readers):
    from .artifact_wait_checkpoint_v1 import require_current_artifact_wait_before_selection_v1
    require_current_artifact_wait_before_selection_v1(db, frame=frame, request=request)
    from ..domains.d08.execution import GoalExecutionProvider
    from .artifact_continuation_v1 import continuation_replace_target_v1
    basis = _request_basis(db, frame=frame, request=request, installed_readers=installed_readers)
    previous, _, _, _ = read_completed_draft_predecessor_v1(
        db, frame=frame, result_ref=request.predecessor_result_ref, issuer=installed_readers.issuer)
    _, _, _, root, _, _, _ = read_current_artifact_renewal_root_v1(
        db, frame=frame, selector=request.selector, installed_readers=installed_readers, predecessor=previous)
    if frame.envelope.identity.operation_id != artifact_continuation_operation_id_v1(request.selector):
        raise ValueError("artifact continuation selection changed its fixed once identity")
    require_unique_existing_artifact_project_v1(db, frame=frame, basis=basis, root=root)
    target = continuation_replace_target_v1(basis, root)
    return stage_result_v1(frame, "d08", "select_existing_artifact_continuation_v1", request,
        provenance={"schema": "d08.existing-artifact-continuation-original.v1",
                    "selector": request.selector, "basis": basis, "replacement_target": target},
        proposal_schema="d08.proposal.v1",
        proposal_hash=GoalExecutionProvider().descriptor.request_schema_hash)


def stage_revise_existing_artifact_v1(db, *, frame, request, installed_readers):
    from dataclasses import replace
    from ..domains.d08.execution import GoalExecutionProvider
    from ..domains.d10 import LifeDomain
    from ..runtime_contracts import DomainBundle, VersionedRef
    from .artifact_continuation_v1 import compose_existing_artifact_revision_v1
    from .d11_artifact_draft_content_v1 import read_current_adopted_artifact_draft_content_v1
    from .artifact_continuation_v1 import continuation_replace_target_v1
    basis = _request_basis(db, frame=frame, request=request, installed_readers=installed_readers)
    previous, _, _, _ = read_completed_draft_predecessor_v1(
        db, frame=frame, result_ref=request.predecessor_result_ref, issuer=installed_readers.issuer)
    read, _, _, root, _, _, _ = read_current_artifact_renewal_root_v1(
        db, frame=frame, selector=request.selector, installed_readers=installed_readers, predecessor=previous)
    require_unique_existing_artifact_project_v1(db, frame=frame, basis=basis, root=root)
    selected = read_adopted_domain_operation_v1(db, frame.envelope.authority.namespace,
        artifact_continuation_operation_id_v1(request.selector))
    if selected is None or selected["operation_kind"] != "select_existing_artifact_continuation_v1":
        raise MissingProductionOriginalV1("actual_adopted_artifact_continuation_selection")
    expected = plain_v1({"schema": "d08.existing-artifact-continuation-original.v1",
        "selector": request.selector, "basis": basis,
        "replacement_target": continuation_replace_target_v1(basis, root)})
    if (selected["payload"]["provenance"] != expected or frame.envelope.identity.operation_id !=
            artifact_continuation_operation_id_v1(request.selector, revision=True)):
        raise ValueError("selected existing artifact changed before its paid revision")
    adoption = read_current_adopted_artifact_draft_content_v1(db, frame=frame,
        c02_operation_id=request.selector.c02_operation_id,
        root_registration_ref=request.selector.root_registration_ref,
        installed_readers=installed_readers.model_readers)
    family = read.source_family(db, tuple(dict.fromkeys((adoption.task_source.ref, *adoption.content.source_refs))))
    facts = tuple(VersionedRef(ref, read.head(db, ref, required=True).revision) for ref in sorted(family))
    candidate = compose_existing_artifact_revision_v1(
        namespace=frame.envelope.authority.namespace, basis=basis, adoption=adoption,
        root=root, current_source_versions=facts, now_utc=frame.now_utc)
    primary = stage_result_v1(frame, "d08", "revise_existing_artifact_v1", request,
        writes=candidate.d08_writes,
        provenance={"schema": "d08.existing-artifact-revision-original.v1",
                    "selection_original_digest": selected["original_digest"],
                    "basis": basis, "content_adoption": adoption, "candidate": candidate},
        proposal_schema="d08.proposal.v1",
        proposal_hash=GoalExecutionProvider().descriptor.request_schema_hash)
    d10 = stage_result_v1(frame, "d10", "revise_existing_artifact_checkpoint_v1", request,
        writes=candidate.d10_writes, provenance={"candidate_digest": candidate.digest},
        proposal_schema="d10.proposal.v1", proposal_hash=LifeDomain().descriptor.request_schema_hash)
    # A separate wrapper keeps StagedDomainOperationV1's one-domain invariant.
    # The primary original includes every cross-domain member in its payload.
    payload = json.loads(primary.original_payload_json)
    payload["writes"] = plain_v1((*candidate.d08_writes, *candidate.d10_writes))
    primary = replace(primary, original_payload_json=canonical_serialize(payload),
                      original_digest=canonical_digest(payload))
    bundle = DomainBundle(frame.envelope, (*primary.proposals, *d10.proposals),
                          (), (), (), (), (frame.envelope.identity.operation_id,), (), ())
    return ExistingArtifactRevisionStageV1(frame, request, primary, d10, candidate, bundle)


def read_selected_artifact_continuation_request_v1(db, *, namespace, selector):
    """Locate the actual W01 selection; a missing selection means no amendment."""
    from ..model_broker.artifact_draft_v1 import artifact_draft_from_wire_v1
    original = read_adopted_domain_operation_v1(
        db, namespace, artifact_continuation_operation_id_v1(selector))
    if original is None:
        return None
    if (original["domain"], original["operation_kind"]) != (
            "d08", "select_existing_artifact_continuation_v1"):
        raise ValueError("artifact selection belongs to another registered operation")
    raw = original["payload"]["request"]
    from dataclasses import fields
    if set(raw) != {field.name for field in fields(ExistingArtifactContinuationRequestV1)}:
        raise ValueError("artifact selection request is not the exact registered variant")
    request = ExistingArtifactContinuationRequestV1(**{
        **raw, "selector": artifact_draft_from_wire_v1(raw["selector"], ArtifactDraftTaskSelectorV1)})
    if request.selector != selector or selector.namespace != namespace:
        raise ValueError("artifact selection belongs to another current task")
    return request, original


def require_selected_artifact_target_sql_v1(db, *, namespace, selector, root, target, issuer):
    """Independent Core join of a replacement to its actual committed lineage."""
    from .d11_artifact_draft_contract_v1 import DraftFileTargetV1
    selected = read_selected_artifact_continuation_request_v1(db, namespace=namespace, selector=selector)
    if selected is None:
        expected = DraftFileTargetV1(root.resource_id, root.registration_ref,
            canonical_digest(plain_v1(root)), root.root_identity, root.filenames[0],
            "create", 0, None, None, None, root.max_bytes)
        if target != expected:
            raise ValueError("C4 create target differs from actual registered Root")
        return None
    request, original = selected
    provenance = original["payload"]["provenance"]
    if (set(provenance) != {"schema", "selector", "basis", "replacement_target"}
            or provenance["schema"] != "d08.existing-artifact-continuation-original.v1"
            or provenance["selector"] != plain_v1(selector)):
        raise ValueError("artifact selection lost its actual closed provenance")
    expected = draft_from_wire_v1(provenance["replacement_target"], DraftFileTargetV1)
    if target != expected or target.mode != "replace":
        raise ValueError("C4 replacement target differs from actual adopted selection")
    basis = provenance["basis"]
    if (basis["project_ref"], basis["goal_ref"], basis["plan_ref"], basis["recipe_ref"],
            basis["predecessor_result_ref"], basis["correction_head_ref"]) != (
            request.project_ref, request.goal_ref, request.plan_ref, request.recipe_ref,
            request.predecessor_result_ref, request.correction_head_ref):
        raise ValueError("artifact selection request and original basis differ")
    adopted = read_adopted_life_original_v1(db, namespace=namespace,
        result_ref=request.predecessor_result_ref, issuer=issuer)
    if adopted is None:
        raise MissingProductionOriginalV1("actual_signed_replacement_predecessor")
    terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
    if type(terminal) is not D11DraftTerminalV1 or terminal.status != "completed":
        raise MissingProductionOriginalV1("query_original_draft_effect_without_new_attempt")
    prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=issuer)
    if prepared is None:
        raise MissingProductionOriginalV1("actual_signed_replacement_prepared")
    witness = require_draft_terminal_readback_v1(prepared=prepared, terminal=terminal)
    old = prepared.plan.target
    if (basis["predecessor_prepared_digest"] != prepared.digest
            or basis["predecessor_adopted_digest"] != canonical_digest(adopted)
            or basis["predecessor_effect_id"] != terminal.binding.effect_id
            or basis["predecessor_target"] != plain_v1(old)
            or (target.expected_prior_version, target.expected_prior_digest, target.expected_prior_identity,
                target.expected_prior_effect_marker) != (witness.version, witness.content_digest,
                witness.file_identity, witness.effect_marker)
            or witness.root_registration_digest != old.root_registration_digest
            or (target.root_resource_id, target.root_identity, target.filename) !=
                (old.root_resource_id, old.root_identity, old.filename)
            or (root.resource_id, root.root_identity, root.filenames) !=
                (target.root_resource_id, target.root_identity, (target.filename,))
            or (target.root_registration_ref, target.root_registration_digest) !=
                (root.registration_ref, canonical_digest(plain_v1(root)))
            or target.max_bytes > root.max_bytes):
        raise ValueError("C4 target crossed actual prior file or current registered Root")
    for version in basis["current_versions"]:
        key = AtomKey.from_token(version["key"])
        if key.owner.bot != namespace.bot_id or key.owner.persona != namespace.persona_id:
            raise ValueError("artifact selection control crossed namespace")
        row = db.execute("SELECT revision FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (key.token, *namespace.as_tuple)).fetchone()
        if row != (version["revision"],):
            raise ValueError("selected existing artifact control changed before C4")
    return request, original


def current_selected_artifact_target_v1(db, *, frame, selector, root, installed_readers):
    selected = read_selected_artifact_continuation_request_v1(
        db, namespace=selector.namespace, selector=selector)
    if selected is None:
        return None
    from .artifact_continuation_v1 import continuation_replace_target_v1
    readers = InstalledArtifactContinuationReadersV1(
        installed_readers.issuer, installed_readers.resource_issuer, installed_readers)
    request, original = selected
    basis = _request_basis(db, frame=frame, request=request, installed_readers=readers)
    require_unique_existing_artifact_project_v1(db, frame=frame, basis=basis, root=root)
    target = continuation_replace_target_v1(basis, root)
    expected = plain_v1({"schema": "d08.existing-artifact-continuation-original.v1",
        "selector": selector, "basis": basis, "replacement_target": target})
    if original["payload"]["provenance"] != expected:
        raise ValueError("actual selected artifact basis changed before C4")
    require_selected_artifact_target_sql_v1(db, namespace=selector.namespace,
        selector=selector, root=root, target=target, issuer=installed_readers.issuer)
    return basis, target


def discover_existing_artifact_continuation_request_v1(db, *, namespace, selector, issuer):
    """Select one actual previous project by fresh Owner Root and physical file."""
    root_row = _read(db, issuer=issuer, namespace=namespace,
        kind="draft_root_capability", ref=selector.root_registration_ref)
    if root_row is None:
        raise MissingProductionOriginalV1("actual_fresh_owner_draft_root")
    root = draft_from_wire_v1(root_row[0], DraftRootCapabilityV1)
    if len(root.filenames) != 1:
        raise ValueError("one registered filename required")
    rows = db.execute("SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name='d10.life_project.v1' ORDER BY token LIMIT 129", namespace.as_tuple).fetchall()
    if len(rows) > 128:
        raise MissingProductionOriginalV1("complete_existing_artifact_project_inventory")
    matches = []
    for ref, revision, encoded in rows:
        if json.loads(encoded).get("topic") != root.filenames[0]:
            continue
        history = db.execute("SELECT event_id,value FROM graph_history WHERE token=? AND valid=1 "
            "AND revision<=? ORDER BY revision DESC LIMIT 1", (ref, revision)).fetchone()
        if history is None or history[1] != encoded:
            raise MissingProductionOriginalV1("actual_existing_artifact_project_history")
        original = read_adopted_domain_operation_v1(db, namespace, history[0])
        if original is None:
            raise MissingProductionOriginalV1("actual_existing_artifact_project_producer")
        provenance = original["payload"]["provenance"]
        if (original["domain"], original["operation_kind"]) == ("d10", "create_artifact_project"):
            content = provenance["artifact_content_adoption"]
            goal_ref, plan_ref, recipe_ref = (provenance[name] for name in
                ("artifact_goal_ref", "artifact_plan_ref", "artifact_recipe_ref"))
        elif (original["domain"], original["operation_kind"]) == ("d08", "revise_existing_artifact_v1"):
            content = provenance["content_adoption"]
            goal_ref, plan_ref, recipe_ref = (provenance["basis"][name] for name in
                ("goal_ref", "plan_ref", "recipe_ref"))
        else:
            raise ValueError("existing artifact project has another producer")
        target = content["target"]
        if (target["root_resource_id"], target["root_identity"], target["filename"]) != (
                root.resource_id, plain_v1(root.root_identity), root.filenames[0]):
            continue
        goal_row = db.execute("SELECT value FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (goal_ref, *namespace.as_tuple)).fetchone()
        if goal_row is None or _decode_goal(json.loads(goal_row[0])).state != "active":
            raise MissingProductionOriginalV1("active_existing_artifact_goal_without_revival")
        from .d08_personal_plan_v1 import require_artifact_task_objective_original_v1
        require_artifact_task_objective_original_v1(db, namespace=namespace, goal_ref=goal_ref,
            goal=_decode_goal(json.loads(goal_row[0])), issuer=issuer)
        plan_row = db.execute("SELECT value FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (plan_ref, *namespace.as_tuple)).fetchone()
        checkpoint_row = db.execute("SELECT value FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (project_checkpoint_key_v1(namespace, ref).token, *namespace.as_tuple)).fetchone()
        if plan_row is None or checkpoint_row is None:
            raise MissingProductionOriginalV1("recover_original_existing_artifact_checkpoint")
        plan = decode_personal_plan_type_v1(PLAN_TYPE, json.loads(plan_row[0]))
        checkpoint = decode_project_checkpoint_type_v1(CHECKPOINT_TYPE, json.loads(checkpoint_row[0]))
        from ..domains.d06 import source_correction_head_key
        from .artifact_task_amendment_v1 import read_current_amendment_v1
        amendment=read_current_amendment_v1(db,namespace=namespace,
            root_registration_ref=selector.root_registration_ref,issuer=issuer)
        corrections=[]
        if amendment is not None:
            if (amendment[0].goal_ref,amendment[0].project_ref,amendment[0].source_ref)!=(goal_ref,ref,root.source_ref):
                raise ValueError("ordinary task amendment identifies another project or incoming Source")
            corrections.append(amendment[2].token)
        else:
            for source_ref in plan.source_refs:
                key = source_correction_head_key(namespace, AtomKey.from_token(source_ref).owner.subject)
                row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
                if row is not None and row[1] == 1 and json.loads(row[0])["state"] == "pending_reevaluation":
                    corrections.append(key.token)
        if len(corrections) != 1:
            raise MissingProductionOriginalV1("unique_actual_pending_artifact_correction")
        witnesses = []
        for work_ref in checkpoint.work_version_refs:
            row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                (work_ref, *namespace.as_tuple)).fetchone()
            if row is None or row[1] != 1:
                raise MissingProductionOriginalV1("actual_existing_artifact_work_version")
            work = decode_project_checkpoint_type_v1(WORK_TYPE, json.loads(row[0]))
            adopted = read_adopted_life_original_v1(db, namespace=namespace,
                result_ref=work.artifact_ref, issuer=issuer)
            if adopted is None:
                raise MissingProductionOriginalV1("query_original_draft_effect_without_new_attempt")
            terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
            if type(terminal) is not D11DraftTerminalV1 or terminal.status != "completed":
                raise MissingProductionOriginalV1("query_original_draft_effect_without_new_attempt")
            prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=issuer)
            if prepared is None:
                raise MissingProductionOriginalV1("actual_signed_old_draft_prepared")
            witness = require_draft_terminal_readback_v1(prepared=prepared, terminal=terminal)
            if (prepared.plan.project.ref, witness.filename) != (ref, root.filenames[0]):
                raise ValueError("existing work belongs to another artifact")
            witnesses.append((witness.version, work.artifact_ref))
        if not witnesses:
            raise MissingProductionOriginalV1("recover_original_existing_artifact_progress")
        latest = max(version for version, _ in witnesses)
        results = [result for version, result in witnesses if version == latest]
        if len(results) != 1:
            raise MissingProductionOriginalV1("unique_actual_latest_artifact_version")
        matches.append(ExistingArtifactContinuationRequestV1(selector, ref, goal_ref,
            plan_ref, recipe_ref, results[0], corrections[0]))
    if len(matches) > 1:
        raise MissingProductionOriginalV1("unique_existing_artifact_project_for_actual_owner_root")
    return matches[0] if matches else None


def read_plan_existing_artifact_continuation_v1(db, *, namespace, request, include_content=False):
    from .d01_production_operations_v1 import production_read_plan_v1
    from .d08_personal_plan_v1 import OBLIGATION_TYPES
    from ..domains.d03.self_perspective import self_mapping_key
    from ..graph_types import owner_grant_key
    from .jobs import get_job
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from .d11_life_preparation_v1 import TABLE
    keys = [AtomKey.from_token(ref) for ref in (request.project_ref, request.goal_ref,
        request.plan_ref, request.recipe_ref, request.correction_head_ref, request.selector.cycle_job_ref)]
    keys += [project_checkpoint_key_v1(namespace, request.project_ref), self_mapping_key(namespace),
        owner_grant_key(*namespace.as_tuple)]
    originals = [request.selector.c02_operation_id, request.selector.root_registration_ref, request.predecessor_result_ref]
    from .ingress_artifact_task_scope_v1 import (SCOPE_KIND,task_scope_ref_v1,IngressArtifactTaskScopeOriginalV1,IngressArtifactTaskScopeOriginalV3,_decode)
    raw_scope=db.execute("SELECT payload_json FROM "+TABLE+" WHERE bot=? AND persona=? AND kind=? AND original_ref=?",
        (*namespace.as_tuple,SCOPE_KIND,task_scope_ref_v1(request.selector.root_registration_ref))).fetchone()
    if raw_scope is not None:
        scope=_decode(json.loads(raw_scope[0]),IngressArtifactTaskScopeOriginalV1)
        if type(scope) is IngressArtifactTaskScopeOriginalV3:originals.append(scope.continuation_authorization.original_ref)
    from .artifact_task_amendment_v1 import TYPE as AMENDMENT_TYPE,decode_amendment_v1,amendment_original_ref_v1
    amendment_key=AtomKey.from_token(request.correction_head_ref)
    if amendment_key.type_name==AMENDMENT_TYPE:
        row=db.execute("SELECT value FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (amendment_key.token,*namespace.as_tuple)).fetchone()
        if row is None:raise MissingProductionOriginalV1("actual_task_amendment_read_plan")
        originals.append(amendment_original_ref_v1(decode_amendment_v1(json.loads(row[0]))))
    goal_row = db.execute("SELECT value FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (request.goal_ref, *namespace.as_tuple)).fetchone()
    if goal_row is not None:
        predicate = _decode_goal(json.loads(goal_row[0])).satisfaction_predicate
        if (predicate.kind, predicate.observation_provider) == ("domain_state", "d08.artifact_task_objective.v1"):
            parameters = dict(predicate.parameters)
            if set(parameters) != {"objective_ref", "objective_digest"}:
                raise ValueError("artifact objective predicate has another exact binding")
            originals.append(parameters["objective_ref"])
    cycle = get_job(db, AtomKey.from_token(request.selector.cycle_job_ref).name)
    continuation = foreground_cycle_from_wire_v1(cycle.continuation)
    roots = [continuation.source_ref]
    result_refs = [request.predecessor_result_ref]
    for token, encoded in db.execute("SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name=? ORDER BY token LIMIT 129", (*namespace.as_tuple, WORK_TYPE)).fetchall():
        work = json.loads(encoded)
        if work["project_ref"] == request.project_ref:
            keys.append(AtomKey.from_token(token)); result_refs.append(work["artifact_ref"])
    for ref in dict.fromkeys(result_refs):
        originals.append(ref)
        row = db.execute("SELECT payload_json FROM " + TABLE +
            " WHERE bot=? AND persona=? AND kind='adopted_life' AND original_ref=?", (*namespace.as_tuple, ref)).fetchone()
        if row:
            terminal = life_from_wire_v1(json.loads(row[0])["terminal"], D11LifeTerminalV1)
            originals.append(terminal.binding.prepared_original_ref)
    if include_content:
        from .d11_artifact_draft_content_v1 import read_plan_artifact_draft_content_v1
        extra_keys, extra_roots, extra_originals = read_plan_artifact_draft_content_v1(db,
            namespace=namespace, c02_operation_id=request.selector.c02_operation_id,
            root_registration_ref=request.selector.root_registration_ref)
        keys += list(extra_keys); roots += list(extra_roots); originals += list(extra_originals)
    return production_read_plan_v1((*OBLIGATION_TYPES, "d10.life_project.v1", "d08.goal.v1", WORK_TYPE),
        keys, roots, originals)


def artifact_control_keys_for_task_v1(db, *, namespace, c02_operation_id, root_registration_ref):
    """Selectors only: execution still rereads actual current members and origins."""
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1
    selector = artifact_draft_task_selector_v1(namespace, c02_operation_id=c02_operation_id,
        root_registration_ref=root_registration_ref)
    selected = read_selected_artifact_continuation_request_v1(db, namespace=namespace, selector=selector)
    if selected is None:
        return artifact_goal_plan_keys_v1(namespace, c02_operation_id=c02_operation_id,
            root_registration_ref=root_registration_ref)
    return tuple(AtomKey.from_token(getattr(selected[0], name)) for name in
        ("goal_ref", "plan_ref", "project_ref", "recipe_ref"))


def read_current_existing_artifact_composition_v1(db, *, frame, request, installed_readers):
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    from .d08_personal_plan_v1 import ArtifactGoalPlanCompositionV1
    from .d11_artifact_draft_content_v1 import read_current_adopted_artifact_draft_content_v1
    from ..domains.d10 import LifeProject, ActivityRecipe
    selector = artifact_draft_task_selector_v1(frame.envelope.authority.namespace,
        c02_operation_id=request.c02_operation_id, root_registration_ref=request.root_registration_ref)
    selected = read_selected_artifact_continuation_request_v1(db, namespace=selector.namespace, selector=selector)
    if selected is None:
        raise MissingProductionOriginalV1("actual_adopted_existing_artifact_selection")
    original = read_adopted_domain_operation_v1(db, selector.namespace,
        artifact_continuation_operation_id_v1(selector, revision=True))
    if original is None or (original["domain"], original["operation_kind"]) != (
            "d08", "revise_existing_artifact_v1"):
        raise MissingProductionOriginalV1("actual_adopted_existing_artifact_amendment")
    provenance = original["payload"]["provenance"]
    if provenance["selection_original_digest"] != selected[1]["original_digest"]:
        raise ValueError("artifact amendment lost its exact selected lineage")
    adoption = read_current_adopted_artifact_draft_content_v1(db, frame=frame,
        c02_operation_id=selector.c02_operation_id, root_registration_ref=selector.root_registration_ref,
        installed_readers=installed_readers)
    if provenance["content_adoption"] != plain_v1(adoption):
        raise ValueError("artifact amendment differs from actual paid authored content")
    read = CurrentDomainReadV1(frame)
    keys = artifact_control_keys_for_task_v1(db, namespace=selector.namespace,
        c02_operation_id=selector.c02_operation_id, root_registration_ref=selector.root_registration_ref)
    candidate = provenance["candidate"]
    heads = tuple(read.head(db, key, required=True) for key in keys)
    from .d08_life_admission_v1 import _adopted
    for atom in heads[:3]:
        if (_adopted(db, read, atom) != original["receipt"].operation_id
                or GraphVersion(atom.key, atom.revision) not in original["receipt"].write_versions):
            raise ValueError("artifact current control is not its actual amended member")
    if heads[0].value != candidate["goal"] or heads[1].value != candidate["plan"]:
        raise ValueError("artifact amended Goal/Plan changed")
    goal = _decode_goal(heads[0].value)
    plan = decode_personal_plan_type_v1(PLAN_TYPE, heads[1].value)
    if (goal.state, plan.state, plan.goal_ref, plan.goal_revision) != (
            "active", "active", keys[0].token, goal.revision):
        raise MissingProductionOriginalV1("actual_active_amended_artifact_plan")
    read.source_family(db, plan.source_refs, purpose="consolidation")
    project = LifeProject(namespace=selector.namespace, **heads[2].value)
    recipe = ActivityRecipe(**heads[3].value)
    return ArtifactGoalPlanCompositionV1(adoption, goal, plan, project, recipe, *keys)
