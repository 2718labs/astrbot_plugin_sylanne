"""Actual artifact history and the one current D10 continuation head."""
from dataclasses import dataclass, replace
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d08.execution import GoalPredicate, _decode_intent, _decode
from ..domains.d08.personal_plan_v1 import PLAN_TYPE, decode_personal_plan_type_v1
from ..domains.d10 import LifeDomain
from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
from ..domains.d10.project_checkpoint_v1 import (CHECKPOINT_TYPE, WORK_TYPE, ProjectCheckpointV1,
    ProjectWaitConditionV1, ProjectWorkVersionV1, project_checkpoint_key_v1,
    project_work_version_key_v1, decode_project_checkpoint_type_v1, project_checkpoint_type_specs_v1)
from ..graph_types import AtomKey, GraphWrite, owner_grant_key
from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1, ArtifactDraftPhaseSelectorV2
from ..runtime_contracts import NamespaceId, QueryEpoch, VersionedRef, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import (CurrentDomainReadV1, MissingProductionOriginalV1,
    production_read_plan_v1, raw_head_value_v1, waiting_stage_v1)
from .issuers import D11BudgetJobIssuer
from .d08_personal_plan_v1 import ComposeCurrentArtifactGoalPlanRequestV1


@dataclass(frozen=True, slots=True)
class CreateCurrentArtifactProjectRequestV1(ComposeCurrentArtifactGoalPlanRequestV1):
    pass


def project_capacity_locator_inputs_v3(checkpoints, jobs):
    """Compose current capacity locators; headers cannot admit an execution."""
    keys, originals = [], []
    for token, valid in checkpoints:
        keys.append(AtomKey.from_token(token))
        if valid:originals.append(token)
    for token, work_kind, job_id in jobs:
        if work_kind == "artifact_draft_v1":
            keys.append(AtomKey.from_token(token)); originals.append(job_id)
    return keys, originals


def read_plan_current_project_capacity_v1(db, *, namespace, selector=None):
    """Select existing metadata and signed C4 predecessors; grant no slot."""
    from .domain_background_read_v3 import background_inventory_v3
    checkpoints = background_inventory_v3(db, namespace, CHECKPOINT_TYPE, valid_only=False)
    jobs = background_inventory_v3(db, namespace, "runtime.job", valid_only=True)
    keys, originals = project_capacity_locator_inputs_v3(
        ((atom.key.token, atom.valid) for atom in checkpoints),
        ((atom.key.token, atom.value["work_kind"], atom.value["job_id"]) for atom in jobs))
    # The prospective selection is an adopted original. Its old controls are
    # metadata reads only; never add old Source roots to the capacity scope.
    if selector is not None:
        from .artifact_continuation_originals_v1 import read_selected_artifact_continuation_request_v1
        selected = read_selected_artifact_continuation_request_v1(db, namespace=namespace, selector=selector)
        if selected is not None:
            request = selected[0]
            keys.extend(AtomKey.from_token(getattr(request, name)) for name in
                ("goal_ref", "plan_ref", "project_ref", "recipe_ref"))
            keys.append(project_checkpoint_key_v1(namespace, request.project_ref))
    return production_read_plan_v1((CHECKPOINT_TYPE, "runtime.job"), keys, (), originals)


def _current_project_capacity_v1(db, *, frame, project_ref, issuer):
    """One namespace capacity invariant shared by preparation and initialization."""
    from .d08_life_admission_v1 import _adopted
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .jobs import get_job
    from .d11_types import job_graph_write
    from ..model_broker.artifact_draft_v1 import (ArtifactDraftTaskSelectorV1,
        artifact_draft_from_wire_v1, artifact_draft_model_ids_v1)
    from .d11_artifact_draft_model_v1 import read_artifact_draft_prepared_v1
    if type(issuer) is not D11BudgetJobIssuer:
        raise TypeError("project capacity requires the actual installed original issuer")
    read, ns = CurrentDomainReadV1(frame), frame.envelope.authority.namespace
    read.check(db)
    project_key = AtomKey.from_token(project_ref)
    if (project_key.type_name != "d10.life_project.v1" or project_key.owner.kind != "persona"
            or NamespaceId.from_key(project_key) != ns):
        raise ValueError("prospective project capacity crossed its actual namespace")
    occupied, terminal = set(), set()
    for atom in read.complete_inventory(db, CHECKPOINT_TYPE):
        if not atom.valid:
            raise MissingProductionOriginalV1("actual_current_project_capacity_checkpoint")
        checkpoint = decode_project_checkpoint_type_v1(CHECKPOINT_TYPE, atom.value)
        if (atom.key != project_checkpoint_key_v1(ns, checkpoint.project_ref)
                or atom.revision != checkpoint.revision):
            raise ValueError("project capacity checkpoint identity/revision differs")
        operation = _adopted(db, read, atom)
        original = read_adopted_domain_operation_v1(db, ns, operation)
        if original is not None and (original["domain"], original["operation_kind"]) in {
                ("d10", "await_existing_artifact_revision_v1"), ("d08", "revise_existing_artifact_v1")}:
            from .artifact_wait_checkpoint_v1 import require_finite_artifact_checkpoint_member_v1
            require_finite_artifact_checkpoint_member_v1(db, namespace=ns, original=original, atom=atom)
        elif original is not None and (original["domain"],original["operation_kind"])==("d08","settle_personal_goal"):
            from .artifact_task_observer_v1 import require_task_observer_checkpoint_member_v1
            require_task_observer_checkpoint_member_v1(db,namespace=ns,original=original,atom=atom)
        elif original is not None and original["domain"]=="d10" and original["operation_kind"] in {
                INIT_TASK_CHECKPOINT_OPERATION_V1,ACTIVATE_TASK_CHECKPOINT_OPERATION_V1}:
            require_artifact_task_checkpoint_original_v1(db,namespace=ns,original=original)
        elif (original is None or original["domain"] != "d10"
                or original["operation_kind"] not in {"initialize_project_checkpoint", "refresh_project_checkpoint", "settle_project_checkpoint", INIT_TASK_CHECKPOINT_OPERATION_V1, ACTIVATE_TASK_CHECKPOINT_OPERATION_V1}
                or original["payload"]["provenance"]["checkpoint"] != plain_v1(checkpoint)
                or not any(version.key == atom.key and version.revision == atom.revision
                    for version in original["receipt"].write_versions)):
            raise MissingProductionOriginalV1("actual_immutable_project_capacity_checkpoint_member")
        if checkpoint.state in {"active", "waiting", "paused"}:
            occupied.add(checkpoint.project_ref)
        else:
            terminal.add(checkpoint.project_ref)
    jobs = read.complete_inventory(db, "runtime.job")
    sql_jobs = db.execute("SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
        "AND work_kind='artifact_draft_v1' ORDER BY job_id LIMIT ?", (*ns.as_tuple, frame.limits.max_query_rows + 1)).fetchall()
    if (len(sql_jobs) > frame.limits.max_query_rows
            or {row[0] for row in sql_jobs} != {atom.key.name for atom in jobs if atom.value["work_kind"] == "artifact_draft_v1"}):
        raise MissingProductionOriginalV1("complete_current_sql_graph_pending_artifact_project_inventory")
    for atom in jobs:
        if atom.value["work_kind"] != "artifact_draft_v1":
            continue
        if not atom.valid:
            raise MissingProductionOriginalV1("actual_current_pending_artifact_project_job")
        job = get_job(db, atom.key.name)
        projection = job_graph_write(job)
        if (projection.key != atom.key or projection.value != atom.value
                or set(job.continuation) != {"schema", "selector", "prepared_digest"}
                or job.continuation["schema"] != "d11.artifact-draft-model-job.v1"):
            raise MissingProductionOriginalV1("actual_sql_graph_pending_artifact_project_job")
        selector = artifact_draft_from_wire_v1(job.continuation["selector"], ArtifactDraftTaskSelectorV1)
        if selector.namespace != ns:
            raise ValueError("pending artifact project job crossed namespace")
        prepared = read_artifact_draft_prepared_v1(db, namespace=ns, issuer=issuer, selector=selector)
        if prepared is None:
            raise MissingProductionOriginalV1("actual_signed_pending_artifact_project_prepared")
        ids = artifact_draft_model_ids_v1(selector)
        if ((job.job_id, job.operation_id, job.activity_id, job.effect_id, job.snapshot_ref,
                job.deadline_utc, job.budget_ref, job.operator_versions, job.continuation["prepared_digest"]) !=
                (prepared.job_id, prepared.operation_id, prepared.activity_id, None, ids["snapshot"],
                    prepared.deadline_utc, prepared.parent_budget_lease_ref, {"resource_quote": prepared.quote_id + ":1"}, prepared.digest)):
            raise ValueError("pending artifact project metadata changed its actual prepared predecessor")
        read.original(prepared.job_id, kind="d11.life_c4_prepared", digest=prepared.digest)
        from .artifact_wait_checkpoint_v1 import artifact_model_project_for_capacity_v1
        pending_ref = artifact_model_project_for_capacity_v1(db, prepared=prepared, issuer=issuer)
        # A model terminal/cancel/UNKNOWN alone never releases project capacity.
        # Only the adopted terminal checkpoint above closes this same project.
        if pending_ref not in terminal:
            occupied.add(pending_ref)
    if project_ref in terminal:
        raise MissingProductionOriginalV1("new_project_identity_after_actual_terminal_checkpoint")
    occupied.add(project_ref)
    if len(occupied) > 3:
        raise MissingProductionOriginalV1("available_project_slot_including_pending_artifact_models")
    return tuple(sorted(occupied))


def require_current_artifact_project_capacity_v1(db, *, frame, selector, installed_readers):
    from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
    if (type(selector) is not ArtifactDraftTaskSelectorV1
            or type(installed_readers) is not InstalledArtifactDraftModelReadersV1
            or selector.namespace != frame.envelope.authority.namespace):
        raise TypeError("project capacity requires the actual installed artifact task selector/readers")
    from .artifact_wait_checkpoint_v1 import prospective_artifact_project_for_capacity_v1
    project_ref = prospective_artifact_project_for_capacity_v1(db, frame=frame,
        selector=selector, issuer=installed_readers.issuer)
    return _current_project_capacity_v1(db, frame=frame, project_ref=project_ref, issuer=installed_readers.issuer)


def read_plan_create_current_artifact_project_v1(db, *, namespace, activity_id, request):
    if type(request) is not CreateCurrentArtifactProjectRequestV1:
        raise TypeError("closed artifact project selector required")
    from .d08_personal_plan_v1 import read_plan_current_personal_plan_operation_v1
    selector = ComposeCurrentArtifactGoalPlanRequestV1(request.c02_operation_id, request.root_registration_ref)
    return read_plan_current_personal_plan_operation_v1(db, namespace=namespace, activity_id=activity_id,
        operation_kind="compose_artifact_goal_plan", request=selector)


def stage_create_current_artifact_project_in_transaction_v1(db, *, frame, request, installed_readers):
    from .d08_personal_plan_v1 import compose_current_artifact_goal_plan_v1
    from .d08_life_admission_v1 import _adopted
    if type(request) is not CreateCurrentArtifactProjectRequestV1:
        raise TypeError("exact artifact project creation request required")
    try:
        selector = ComposeCurrentArtifactGoalPlanRequestV1(request.c02_operation_id, request.root_registration_ref)
        composition = compose_current_artifact_goal_plan_v1(db, frame=frame, request=selector,
            installed_readers=installed_readers)
        read = CurrentDomainReadV1(frame)
        for key, value in ((composition.goal_key, composition.goal), (composition.plan_key, composition.plan)):
            atom = read.head(db, key, required=True)
            _adopted(db, read, atom)
            if atom.value != plain_v1(value):
                raise MissingProductionOriginalV1("actual_adopted_artifact_goal_plan_for_project")
        if read.head(db, composition.project_key).revision:
            raise ValueError("artifact project cannot replace an existing definition or continuation")
        recipe = read.head(db, composition.recipe_key)
        if recipe.revision:
            if not recipe.valid or recipe.value != plain_v1(composition.recipe):
                raise ValueError("artifact recipe differs from its existing adopted definition")
            _adopted(db, read, recipe)
        dependencies = tuple(AtomKey.from_token(ref) for ref in composition.plan.source_refs)
        project_value = {name: value for name, value in plain_v1(composition.project).items() if name != "namespace"}
        writes = (GraphWrite(composition.project_key, project_value, dependencies),)
        if not recipe.revision:
            writes += (GraphWrite(composition.recipe_key, plain_v1(composition.recipe), dependencies),)
        stage = stage_result_v1(frame, "d10", "create_artifact_project", request, writes=writes,
            provenance={"artifact_goal_ref": composition.goal_key.token, "artifact_plan_ref": composition.plan_key.token,
                "artifact_project_ref": composition.project_key.token, "artifact_recipe_ref": composition.recipe_key.token,
                "draft_task_source_ref": composition.adoption.task_source.ref,
                "draft_content_ref": composition.adoption.content.content.ref,
                "artifact_content_adoption": composition.adoption},
            receiver_events=(("d03", "artifact_project_definition_available"),),
            proposal_schema="d10.proposal.v1", proposal_hash=LifeDomain().descriptor.request_schema_hash)
        return verify_d10_artifact_project_stage_v1(stage)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d10", "create_artifact_project", request, missing)


def verify_d10_artifact_project_stage_v1(stage):
    if stage.domain != "d10" or stage.operation_kind not in {"create_artifact_project", CREATE_TASK_PROJECT_OPERATION_V1}:
        raise ValueError("unregistered artifact project stage")
    specs = {spec.name: spec for spec in LifeDomain().type_specs()
        if spec.name in {"d10.life_project.v1", "d10.activity_recipe.v1"}}
    for proposal in stage.proposals:
        if (proposal.domain != "d10" or proposal.proposal_schema != "d10.proposal.v1"
                or proposal.proposal_schema_hash != LifeDomain().descriptor.request_schema_hash
                or not 1 <= len(proposal.typed_writes) <= 2):
            raise ValueError("artifact project requires its finite registered D10 proposal")
        for write in proposal.typed_writes:
            spec = specs[write.key.type_name]
            if write.key.owner.kind not in spec.owner_kinds:
                raise ValueError("artifact project contains another registered write owner")
            spec.validator(write.value)
    return stage


def _artifact_project_original_v1(db, *, namespace, project_ref):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    key = AtomKey.from_token(project_ref)
    if (key.type_name != "d10.life_project.v1" or key.owner.kind != "persona"
            or NamespaceId.from_key(key) != namespace):
        raise ValueError("artifact project requires its actual persona-owned definition")
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (project_ref, *namespace.as_tuple)).fetchone()
    if row is None or row[2] != 1:
        raise MissingProductionOriginalV1("actual_adopted_artifact_project_definition")
    history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
        (project_ref, row[0])).fetchone()
    if history is None or history[1:] != (row[1], 1):
        raise ValueError("artifact project lost its actual immutable producing history")
    original = read_adopted_domain_operation_v1(db, namespace, history[0])
    if original is None or (original["domain"], original["operation_kind"]) not in {
            ("d10", "create_artifact_project"), ("d10", CREATE_TASK_PROJECT_OPERATION_V1), ("d08", "revise_existing_artifact_v1")} or not any(
            version.key == key and version.revision == row[0] for version in original["receipt"].write_versions):
        raise MissingProductionOriginalV1("registered_artifact_project_producing_operation")
    if original["operation_kind"]==CREATE_TASK_PROJECT_OPERATION_V1:
        require_artifact_task_project_original_v1(db,namespace=namespace,original=original)
    return original


def read_current_artifact_project_definition_v1(db, *, frame, project_ref, recipe_ref, source_ref):
    from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1
    from .d08_life_admission_v1 import _adopted
    from .d11_artifact_draft_contract_v1 import RECIPE_ID
    read = CurrentDomainReadV1(frame)
    ns = frame.envelope.authority.namespace
    original = _artifact_project_original_v1(db, namespace=ns, project_ref=project_ref)
    if (original["domain"], original["operation_kind"]) == ("d08", "revise_existing_artifact_v1"):
        p = original["payload"]["provenance"]
        adoption, basis = p["content_adoption"], p["basis"]
        if (project_ref, recipe_ref, source_ref) != (basis["project_ref"], basis["recipe_ref"], adoption["task_source"]["ref"]):
            raise ValueError("amended artifact context changed its actual project/recipe/Source")
        project, recipe = read.head(db, project_ref, required=True), read.head(db, recipe_ref, required=True)
        if (_adopted(db, read, project) != original["receipt"].operation_id
                or project.value != basis["project_value"]
                or recipe.value != {"recipe_id": RECIPE_ID, "version": 1, "reality": "real_execution",
                    "allowed_steps": [RECIPE_ID], "preemptible": True}):
            raise ValueError("amended project lost its actual committed member or installed recipe")
        roots = (source_ref, adoption["content"]["content"]["ref"])
        for audience in frame.envelope.authority.audience:
            for purpose in ("context", "consolidation"):
                read.source_family(db, roots, audience=audience, purpose=purpose)
        return project, recipe
    if original['operation_kind']==CREATE_TASK_PROJECT_OPERATION_V1:
        require_artifact_task_project_original_v1(db,namespace=ns,original=original)
        basis=original['payload']['provenance']['task_project_basis']
        if (project_ref,recipe_ref,source_ref)!=(basis['project_ref'],basis['recipe_ref'],basis['source_head']['key']):
            raise ValueError('task project definition changed actual objective/project/recipe/Source')
        project,recipe=read.head(db,project_ref,required=True),read.head(db,recipe_ref,required=True)
        if project.value!=basis['project_value'] or recipe.value!=basis['recipe_value']:
            raise ValueError('task project definition changed actual immutable members')
        for atom in (project,recipe):_adopted(db,read,atom)
        for purpose in ('context','consolidation'):read.source_family(db,(source_ref,),purpose=purpose)
        return project,recipe
    request = CreateCurrentArtifactProjectRequestV1(**original["payload"]["request"])
    expected = artifact_goal_plan_keys_v1(ns, c02_operation_id=request.c02_operation_id,
        root_registration_ref=request.root_registration_ref)
    provenance = original["payload"]["provenance"]
    if (project_ref, recipe_ref, source_ref) != (expected[2].token, expected[3].token, provenance["draft_task_source_ref"]):
        raise ValueError("artifact context changed its adopted task/project/recipe binding")
    if (provenance["artifact_goal_ref"], provenance["artifact_plan_ref"], provenance["artifact_project_ref"],
            provenance["artifact_recipe_ref"]) != tuple(key.token for key in expected):
        raise ValueError("artifact project producing original changed its stable predecessors")
    project, recipe = read.head(db, project_ref, required=True), read.head(db, recipe_ref, required=True)
    for atom in (project, recipe):
        _adopted(db, read, atom)
    if (project.value["reality"] != "real_execution" or project.value["next_step"] != RECIPE_ID
            or recipe.value != {"recipe_id": RECIPE_ID, "version": 1, "reality": "real_execution",
                "allowed_steps": [RECIPE_ID], "preemptible": True}):
        raise ValueError("artifact context cannot reinterpret another project or recipe")
    roots = (source_ref, provenance["draft_content_ref"])
    for audience in frame.envelope.authority.audience:
        for purpose in ("context", "consolidation"):
            read.source_family(db, roots, audience=audience, purpose=purpose)
    return project, recipe


def artifact_project_context_read_inputs_v1(db, *, namespace, project_ref):
    original = _artifact_project_original_v1(db, namespace=namespace, project_ref=project_ref)
    provenance = original["payload"]["provenance"]
    if (original["domain"], original["operation_kind"]) == ("d08", "revise_existing_artifact_v1"):
        refs = tuple(provenance["basis"][name] for name in ("goal_ref", "plan_ref", "project_ref", "recipe_ref"))
        adoption = provenance["content_adoption"]
        roots = (adoption["task_source"]["ref"], adoption["content"]["content"]["ref"])
        return tuple(AtomKey.from_token(ref) for ref in refs), roots, refs
    if original['operation_kind']==CREATE_TASK_PROJECT_OPERATION_V1:
        require_artifact_task_project_original_v1(db,namespace=namespace,original=original)
        basis=provenance['task_project_basis']
        refs=(basis['goal_head']['key'],basis['plan_head']['key'],basis['project_ref'],basis['recipe_ref'])
        return tuple(AtomKey.from_token(ref) for ref in refs),(basis['source_head']['key'],),refs
    refs = tuple(provenance[name] for name in ("artifact_goal_ref", "artifact_plan_ref", "artifact_project_ref", "artifact_recipe_ref"))
    roots = (provenance["draft_task_source_ref"], provenance["draft_content_ref"])
    return tuple(AtomKey.from_token(ref) for ref in refs), roots, refs


@dataclass(frozen=True, slots=True)
class VerifiedProjectEffectV1:
    """Normalized installed-original read, never an operation request or permit."""
    project_ref: str
    progress_ref: str
    recipe_ref: str
    action_intent_ref: str
    action_revision: int
    goal_id: str
    action_kind: str
    success_predicate: GoalPredicate
    artifact_ref: str
    artifact_digest: str
    artifact_length: int
    work_ref: str
    work_version: int
    terminal_ref: str
    action_outcome_ref: str
    source_refs: tuple[str, ...]
    source_versions: tuple[VersionedRef, ...]
    activity_id: str
    effect_id: str
    attempt_id: str
    completed_verified: bool

    def __post_init__(self):
        if (type(self.success_predicate) is not GoalPredicate or type(self.completed_verified) is not bool
                or type(self.action_revision) is not int or self.action_revision < 1
                or not self.goal_id.startswith("goal:") or not self.action_kind
                or AtomKey.from_token(self.action_intent_ref).type_name != "d08.action_intent.v1"):
            raise ValueError("project effect requires the exact actual Action binding")
        # Reuse the immutable history schema; this validates metadata only.
        ProjectWorkVersionV1(self.project_ref, self.work_ref, self.work_version, self.progress_ref,
            self.artifact_ref, self.artifact_digest, self.artifact_length, self.terminal_ref,
            self.action_outcome_ref, self.source_refs, self.source_versions,
            self.activity_id, self.effect_id, self.attempt_id, "task:effect-read")


@dataclass(frozen=True, slots=True)
class InitializeCurrentProjectCheckpointRequestV1:
    project_ref: str
    plan_ref: str

    def __post_init__(self):
        _selectors(self.project_ref, self.plan_ref)


@dataclass(frozen=True, slots=True)
class RefreshCurrentProjectCheckpointRequestV1:
    project_ref: str
    plan_ref: str
    next_step: str | None
    expected_checkpoint_revision: int

    def __post_init__(self):
        _selectors(self.project_ref, self.plan_ref)
        if type(self.expected_checkpoint_revision) is not int or self.expected_checkpoint_revision < 1:
            raise ValueError("checkpoint refresh requires an existing exact CAS")


@dataclass(frozen=True, slots=True)
class SettleCurrentProjectCheckpointRequestV1:
    project_ref: str
    plan_ref: str
    progress_ref: str
    next_step: str | None
    expected_checkpoint_revision: int

    def __post_init__(self):
        _selectors(self.project_ref, self.plan_ref)
        if (AtomKey.from_token(self.progress_ref).type_name != "d10.life_progress.v1"
                or type(self.expected_checkpoint_revision) is not int or self.expected_checkpoint_revision < 1):
            raise ValueError("checkpoint progress requires its actual effect and predecessor CAS")


def _selectors(project_ref, plan_ref):
    if (AtomKey.from_token(project_ref).type_name != "d10.life_project.v1"
            or AtomKey.from_token(plan_ref).type_name != PLAN_TYPE):
        raise ValueError("continuation requires exact adopted project/plan selectors")


class InstalledD10ProjectReadersV1:
    def __init__(self, *, issuer, cycle_job_ref=None):
        if type(issuer) is not D11BudgetJobIssuer:
            raise TypeError("project history requires its installed original issuer")
        if cycle_job_ref is not None and AtomKey.from_token(cycle_job_ref).type_name != "runtime.job":
            raise ValueError("continuation wake needs the actual cycle job locator")
        self.issuer, self.cycle_job_ref = issuer, cycle_job_ref

    def read_effect(self, db, frame, progress_ref):
        read = CurrentDomainReadV1(frame)
        read.check(db)
        progress_atom = read.head(db, progress_ref, required=True)
        if progress_atom.key.type_name != "d10.life_progress.v1":
            raise ValueError("project progress has another Graph type")
        progress = LifeProgressHeadV1(**{**progress_atom.value,
            "receipt_refs": tuple(progress_atom.value["receipt_refs"]), "source_refs": tuple(progress_atom.value["source_refs"])})
        if progress.step == "artifact_draft_v1":
            from .d11_life_adoption_v1 import read_adopted_artifact_draft_for_project_v1
            evidence = read_adopted_artifact_draft_for_project_v1(db, frame=frame, progress=progress, issuer=self.issuer)
            if (type(evidence) is not VerifiedProjectEffectV1 or evidence.progress_ref != progress_ref
                    or evidence.project_ref != progress.project_ref or evidence.effect_id != progress.effect_id
                    or evidence.activity_id != progress.activity_id or evidence.artifact_ref != progress.artifact_ref):
                raise ValueError("draft installed-original reader returned another actual effect")
            read.source_family(db, evidence.source_refs)
            return evidence
        if progress.step != "source_note" or progress.reality != "real_execution" or progress.artifact_ref is None:
            raise MissingProductionOriginalV1("registered_actual_project_artifact_reader")
        from .d11_life_terminal_v1 import read_adopted_life_original_v1
        from .d11_life_contract_v1 import D11LifeTerminalV1, life_from_wire_v1, POSTCONDITION_ID
        from .d11_life_preparation_v1 import read_prepared_life_v1
        from .d11_life_source_note_v1 import verify_durable_life_artifact_v1
        from .d11_life_outcome_provenance_v1 import life_outcome_key_v1
        from .d10_life_progress_provenance_v1 import validate_life_progress_provenance_history_v1
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        adopted = read_adopted_life_original_v1(db, namespace=frame.envelope.authority.namespace,
            result_ref=progress.artifact_ref, issuer=self.issuer)
        if adopted is None:
            raise MissingProductionOriginalV1("signed_adopted_project_terminal")
        terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
        binding = terminal.binding
        prepared = read_prepared_life_v1(db, binding=binding, issuer=self.issuer)
        if prepared is None:
            raise MissingProductionOriginalV1("actual_prepared_project_original")
        if (terminal.status != "completed" or prepared.plan.project.ref != progress.project_ref
                or prepared.plan.recipe.ref != progress.recipe_ref
                or (binding.activity_id, binding.effect_id, binding.artifact_ref, terminal.original_ref) !=
                    (progress.activity_id, progress.effect_id, progress.artifact_ref, progress.terminal_ref)):
            raise MissingProductionOriginalV1("actual_complete_project_effect")
        history = db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?",
            (progress_ref, progress_atom.revision)).fetchone()
        if history is None:
            raise MissingProductionOriginalV1("actual_progress_adoption_history")
        production = read_adopted_domain_operation_v1(db, binding.namespace, history[0])
        if production is None:
            raise MissingProductionOriginalV1("actual_progress_operation_original")
        validate_life_progress_provenance_history_v1(db, prepared=prepared, terminal=terminal,
            progress=progress, production=production)
        _, digest, length = verify_durable_life_artifact_v1(db, prepared,
            digest=terminal.payload.artifact_digest, length=terminal.payload.artifact_length)
        action_row = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
            (prepared.plan.action_intent.ref, prepared.plan.action_intent.revision)).fetchone()
        if (action_row is None or action_row[1] != 1
                or canonical_digest(json.loads(action_row[0])) != prepared.plan.action_intent.digest):
            raise ValueError("project historical Action no longer has its exact committed bytes")
        action = _decode_intent(json.loads(action_row[0]))
        outcome_key = life_outcome_key_v1(binding, prepared.plan.action_intent.ref)
        outcome = _decode("d08.action_outcome.v1", read.head(db, outcome_key, required=True).value)
        predicate = action.success_predicate
        if (predicate.kind != "artifact_verified" or predicate.observation_provider != POSTCONDITION_ID
                or dict(predicate.parameters) != {"artifact_ref": binding.artifact_ref,
                    "input_digest": prepared.plan.input_source.digest, "build_digest": binding.postcondition_build_digest}
                or outcome.action_id != action.action_id or outcome.effect_id != binding.effect_id
                or outcome.attempt_id != binding.attempt_id or outcome.result_level != "completed_verified"
                or outcome.completed_effects != (binding.effect_id,) or outcome.unknown_effects
                or outcome.observation_refs != (terminal.original_ref,)
                or not predicate.valid_from <= outcome.observed_at
                or predicate.valid_until is not None and outcome.observed_at > predicate.valid_until):
            raise MissingProductionOriginalV1("registered_actual_project_postcondition")
        roots = (prepared.plan.input_source.ref,)
        read.source_family(db, roots)
        return VerifiedProjectEffectV1(progress.project_ref, progress_ref, progress.recipe_ref,
            prepared.plan.action_intent.ref, prepared.plan.action_intent.revision, action.goal_ref,
            action.action_kind, predicate, binding.artifact_ref, digest, length,
            binding.artifact_ref, 1, terminal.original_ref, outcome_key.token, roots,
            (VersionedRef(prepared.plan.input_source.ref, prepared.plan.input_source.revision),),
            binding.activity_id, binding.effect_id, binding.attempt_id, True)

    def wait_condition(self, db, read, plan, completed):
        if self.cycle_job_ref is None:
            raise MissingProductionOriginalV1("actual_cycle_job_for_checkpoint_wake_registration")
        from .jobs import get_job
        from .d11_types import job_graph_write
        key = AtomKey.from_token(self.cycle_job_ref)
        job = get_job(db, key.name)
        atom = read.head(db, key, required=True)
        if job_graph_write(job).key != key or job_graph_write(job).value != atom.value:
            raise ValueError("checkpoint wake job differs from its actual SQL/Graph projection")
        unknown = any(node.pending_original_effects for node in plan.nodes if node.node_id not in completed)
        epoch = read.frame.snapshot.epochs[0]
        return ProjectWaitConditionV1("d11" if unknown else "d08",
            "original_effect_observed" if unknown else "qualified_personal_step_available",
            plan.fact_versions, QueryEpoch(read.frame.envelope.authority.namespace, "namespace", epoch.revision),
            key.token, atom.revision)


def _reader(readers):
    if type(readers) is not InstalledD10ProjectReadersV1:
        raise TypeError("exact installed project readers required")
    return readers


def _current_plan(db, read, plan_ref):
    atom = read.head(db, plan_ref, required=True)
    plan = decode_personal_plan_type_v1(PLAN_TYPE, atom.value)
    goal = read.head(db, plan.goal_ref, required=True)
    if plan.goal_revision != goal.value["revision"]:
        raise MissingProductionOriginalV1("current_personal_plan_goal_revision")
    if plan.state == "active" and goal.value["state"] != "active":
        raise MissingProductionOriginalV1("active_goal_for_project_continuation")
    read.source_family(db, plan.source_refs)
    return atom, plan


def _ready_nodes(plan, completed):
    return tuple(node for node in plan.nodes if node.node_id not in completed
        and not node.pending_original_effects and not node.carried_forward_verified and set(node.depends_on) <= set(completed))


def _continuation(readers, db, read, plan, completed, requested):
    if plan.state == "satisfied":
        if requested is not None:
            raise ValueError("satisfied goal cannot expand another project step")
        return None, "completed", None
    if plan.state in {"paused", "abandoned", "superseded"}:
        if requested is not None:
            raise ValueError("paused or cancelled project cannot admit a next step")
        return None, "paused" if plan.state == "paused" else "cancelled", None
    ready = _ready_nodes(plan, completed)
    remaining = [node for node in plan.nodes if node.node_id not in completed]
    if not remaining:
        if requested is not None:
            raise ValueError("finished recipe cannot silently expand another work")
        return None, "completed", None
    if len(ready) == 1 and plan.state == "active":
        if requested != ready[0].node_id:
            raise ValueError("next-step selector differs from the unique adopted ready node")
        return requested, "active", None
    if requested is not None:
        raise MissingProductionOriginalV1("current_d08_decision_for_ambiguous_next_step")
    wake = readers.wait_condition(db, read, plan, completed)
    return None, "waiting", wake


def _stage(frame, kind, request, writes=(), **provenance):
    events = (("d08", "project_continuation_updated"), ("d07", "actual_project_result_available")) if writes else ()
    if provenance.get("checkpoint") is not None and provenance["checkpoint"].wait_condition is not None:
        events += (("d11", "project_checkpoint_wait_registered"),)
    return verify_d10_project_checkpoint_stage_v1(stage_result_v1(frame, "d10", kind, request,
        writes=writes, provenance=provenance, receiver_events=events,
        proposal_schema="d10.proposal.v1", proposal_hash=LifeDomain().descriptor.request_schema_hash))


def stage_initialize_current_project_checkpoint_in_transaction_v1(db, *, frame, request, installed_readers):
    readers = _reader(installed_readers)
    if type(request) is not InitializeCurrentProjectCheckpointRequestV1:
        raise TypeError("explicit checkpoint initialization request required")
    try:
        read = CurrentDomainReadV1(frame)
        read.check(db)
        project = read.head(db, request.project_ref, required=True)
        _, plan = _current_plan(db, read, request.plan_ref)
        key = project_checkpoint_key_v1(frame.envelope.authority.namespace, request.project_ref)
        if read.head(db, key).revision:
            raise ValueError("initial project definition cannot replace a current checkpoint")
        _current_project_capacity_v1(db, frame=frame, project_ref=request.project_ref, issuer=readers.issuer)
        ready = _ready_nodes(plan, ())
        candidates = [node for node in ready if node.action_kind == project.value["next_step"]]
        if len(candidates) != 1 or plan.state != "active":
            raise MissingProductionOriginalV1("unique_adopted_initial_project_step")
        checkpoint = ProjectCheckpointV1(request.project_ref, 1, request.plan_ref, plan.revision, (), (), (),
            candidates[0].node_id, "active", plan.fact_versions)
        return _stage(frame, "initialize_project_checkpoint", request,
            (GraphWrite(key, plain_v1(checkpoint)),), checkpoint=checkpoint)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d10", "initialize_project_checkpoint", request, missing)


def stage_refresh_current_project_checkpoint_in_transaction_v1(db, *, frame, request, installed_readers):
    readers = _reader(installed_readers)
    if type(request) is not RefreshCurrentProjectCheckpointRequestV1:
        raise TypeError("exact checkpoint refresh request required")
    try:
        read = CurrentDomainReadV1(frame)
        read.check(db)
        _, plan = _current_plan(db, read, request.plan_ref)
        key = project_checkpoint_key_v1(frame.envelope.authority.namespace, request.project_ref)
        atom = read.head(db, key, required=True)
        old = decode_project_checkpoint_type_v1(CHECKPOINT_TYPE, atom.value)
        if atom.revision != request.expected_checkpoint_revision or old.plan_ref != request.plan_ref:
            raise ValueError("checkpoint refresh CAS/plan identity is stale")
        if old.plan_revision == plan.revision:
            return _stage(frame, "refresh_project_checkpoint", request, duplicate=True)
        if plan.revision < old.plan_revision or not set(old.completed_node_refs) <= {node.node_id for node in plan.nodes}:
            raise ValueError("new plan cannot discard previously completed project nodes")
        next_step, state, wake = _continuation(readers, db, read, plan, old.completed_node_refs, request.next_step)
        updated = replace(old, revision=old.revision + 1, plan_revision=plan.revision,
            next_step=next_step, state=state, last_fact_versions=plan.fact_versions, wait_condition=wake)
        return _stage(frame, "refresh_project_checkpoint", request,
            (GraphWrite(key, plain_v1(updated)),), checkpoint=updated)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d10", "refresh_project_checkpoint", request, missing)


def stage_settle_current_project_checkpoint_in_transaction_v1(db, *, frame, request, installed_readers):
    readers = _reader(installed_readers)
    if type(request) is not SettleCurrentProjectCheckpointRequestV1:
        raise TypeError("exact verified checkpoint settlement required")
    try:
        read = CurrentDomainReadV1(frame)
        read.check(db)
        key = project_checkpoint_key_v1(frame.envelope.authority.namespace, request.project_ref)
        atom = read.head(db, key, required=True)
        checkpoint = decode_project_checkpoint_type_v1(CHECKPOINT_TYPE, atom.value)
        _, plan = _current_plan(db, read, request.plan_ref)
        evidence = readers.read_effect(db, frame, request.progress_ref)
        if (evidence.project_ref != request.project_ref or checkpoint.plan_ref != request.plan_ref
                or evidence.goal_id != AtomKey.from_token(plan.goal_ref).name or not evidence.completed_verified):
            raise ValueError("actual project outcome belongs to another adopted continuation")
        project_original=_artifact_project_original_v1(db,namespace=frame.envelope.authority.namespace,project_ref=request.project_ref)
        if project_original['operation_kind']==CREATE_TASK_PROJECT_OPERATION_V1:
            return _settle_current_artifact_task_checkpoint_v2(db,frame=frame,request=request,readers=readers,
                checkpoint_atom=atom,checkpoint=checkpoint,plan=plan,evidence=evidence)
        nodes = tuple(node for node in plan.nodes if node.action_kind == evidence.action_kind
            and node.success_predicate == evidence.success_predicate
            and evidence.success_predicate in node.observable_postconditions)
        if len(nodes) != 1:
            raise MissingProductionOriginalV1("exact_plan_node_for_actual_effect_postcondition")
        node = nodes[0]
        work = ProjectWorkVersionV1(request.project_ref, evidence.work_ref, evidence.work_version, request.progress_ref,
            evidence.artifact_ref, evidence.artifact_digest, evidence.artifact_length, evidence.terminal_ref,
            evidence.action_outcome_ref, evidence.source_refs, evidence.source_versions,
            evidence.activity_id, evidence.effect_id, evidence.attempt_id, node.node_id)
        work_key = project_work_version_key_v1(frame.envelope.authority.namespace, request.project_ref, evidence.effect_id)
        prior = read.head(db, work_key)
        if prior.revision:
            if (not prior.valid or prior.value != plain_v1(work) or work_key.token not in checkpoint.work_version_refs
                    or request.progress_ref not in checkpoint.progress_refs or node.node_id not in checkpoint.completed_node_refs):
                raise ValueError("same effect replay differs from its immutable work/checkpoint")
            return _stage(frame, "settle_project_checkpoint", request, duplicate=True, actual_effect=evidence)
        if atom.revision != request.expected_checkpoint_revision or checkpoint.revision != atom.revision:
            raise ValueError("project checkpoint CAS is stale")
        if node.node_id in checkpoint.completed_node_refs or not set(node.depends_on) <= set(checkpoint.completed_node_refs):
            raise ValueError("actual effect cannot replay a completed or unready project node")
        works = read.complete_inventory(db, WORK_TYPE)
        versions = [row.value["version"] for row in works if row.valid and row.value["project_ref"] == request.project_ref
            and row.value["work_ref"] == evidence.work_ref]
        if work.version != max(versions, default=0) + 1:
            raise ValueError("actual work version does not follow its exact same-work predecessor")
        completed = tuple(dict.fromkeys((*checkpoint.completed_node_refs, node.node_id)))
        next_step, state, wake = _continuation(readers, db, read, plan, completed, request.next_step)
        updated = replace(checkpoint, revision=checkpoint.revision + 1, plan_revision=plan.revision,
            completed_node_refs=completed, progress_refs=(*checkpoint.progress_refs, request.progress_ref),
            work_version_refs=(*checkpoint.work_version_refs, work_key.token), next_step=next_step,
            state=state, last_fact_versions=plan.fact_versions, wait_condition=wake)
        # No invalidating edge to mutable project/plan: real work remains
        # historical. Current consumers independently requalify its sources.
        return _stage(frame, "settle_project_checkpoint", request,
            (GraphWrite(work_key, plain_v1(work)), GraphWrite(key, plain_v1(updated))),
            checkpoint=updated, work_version=work, actual_effect=evidence)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d10", "settle_project_checkpoint", request, missing)


def read_current_project_continuation_v1(db, *, frame, project_ref):
    """One continuation authority; missing checkpoint never falls back to definition."""
    read = CurrentDomainReadV1(frame)
    read.check(db)
    key = project_checkpoint_key_v1(frame.envelope.authority.namespace, project_ref)
    checkpoint = decode_project_checkpoint_type_v1(CHECKPOINT_TYPE, read.head(db, key, required=True).value)
    _, plan = _current_plan(db, read, checkpoint.plan_ref)
    if checkpoint.plan_revision != plan.revision:
        raise MissingProductionOriginalV1("checkpoint_refresh_for_current_plan")
    if checkpoint.next_step is not None:
        ready = {node.node_id: node for node in _ready_nodes(plan, checkpoint.completed_node_refs)}
        if checkpoint.next_step not in ready:
            raise MissingProductionOriginalV1("current_executable_checkpoint_node")
        return checkpoint, ready[checkpoint.next_step]
    return checkpoint, None


def verify_d10_project_checkpoint_stage_v1(stage):
    if stage.domain != "d10" or stage.operation_kind not in {
            "initialize_project_checkpoint", "refresh_project_checkpoint", "settle_project_checkpoint", INIT_TASK_CHECKPOINT_OPERATION_V1, ACTIVATE_TASK_CHECKPOINT_OPERATION_V1, ACTIVATE_TASK_CHECKPOINT_OPERATION_V2}:
        raise ValueError("unregistered D10 continuation stage")
    if stage.operation_kind==ACTIVATE_TASK_CHECKPOINT_OPERATION_V2:
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        payload=json.loads(stage.original_payload_json)
        request=decode_typed_production_value_v1(payload['request'],ActivateCurrentArtifactTaskProjectCheckpointRequestV2)
        if stage.frame.envelope.identity.operation_id!=artifact_task_checkpoint_activation_operation_id_v2(request.selector):
            raise ValueError('amended activation stage changed its exact selector/fixed identity')
    specs = {spec.name: spec for spec in project_checkpoint_type_specs_v1()}
    for proposal in stage.proposals:
        if proposal.proposal_schema != "d10.proposal.v1" or proposal.proposal_schema_hash != LifeDomain().descriptor.request_schema_hash:
            raise ValueError("project stage has another registered proposal schema")
        for write in proposal.typed_writes:
            spec = specs[write.key.type_name]
            if write.key.owner.kind not in spec.owner_kinds:
                raise ValueError("project stage contains another write owner")
            spec.validator(write.value)
    return stage


def project_effect_read_inputs_v1(db, namespace, progress_ref):
    progress = raw_head_value_v1(db, namespace, AtomKey.from_token(progress_ref))
    if progress is None:
        return (AtomKey.from_token(progress_ref),), (), ()
    if progress["step"] == "artifact_draft_v1":
        from .d11_life_adoption_v1 import artifact_draft_project_effect_read_inputs_v1
        return artifact_draft_project_effect_read_inputs_v1(db, namespace=namespace, progress_ref=progress_ref)
    from .d10_life_progress_provenance_v1 import life_progress_current_read_inputs_v1
    return life_progress_current_read_inputs_v1(db, namespace, progress_ref)


def read_plan_current_project_checkpoint_operation_v1(db, *, namespace, activity_id, operation_kind, request, cycle_job_ref=None):
    if operation_kind not in {"initialize_project_checkpoint", "refresh_project_checkpoint", "settle_project_checkpoint"}:
        raise ValueError("unregistered current project operation")
    types = [CHECKPOINT_TYPE, WORK_TYPE]
    keys = [owner_grant_key(*namespace.as_tuple), AtomKey.from_token(request.project_ref), AtomKey.from_token(request.plan_ref),
        project_checkpoint_key_v1(namespace, request.project_ref)]
    roots, originals = [], []
    if operation_kind == "initialize_project_checkpoint":
        capacity = read_plan_current_project_capacity_v1(db, namespace=namespace)
        types.extend(capacity.fixed_type_ids)
        keys.extend(capacity.exact_keys)
        originals.extend(capacity.required_original_refs)
    plan = raw_head_value_v1(db, namespace, AtomKey.from_token(request.plan_ref))
    if plan:
        keys.append(AtomKey.from_token(plan["goal_ref"]))
        keys.extend(AtomKey.from_token(row["ref"]) for row in plan["fact_versions"])
        roots.extend(plan["source_refs"])
    if cycle_job_ref is not None:
        keys.append(AtomKey.from_token(cycle_job_ref))
    if operation_kind == "settle_project_checkpoint":
        if type(request) is not SettleCurrentProjectCheckpointRequestV1:
            raise TypeError("exact project settlement read recipe required")
        extra_keys, extra_roots, extra_originals = project_effect_read_inputs_v1(db, namespace, request.progress_ref)
        keys.extend(extra_keys)
        roots.extend(extra_roots)
        originals.extend(extra_originals)
        original=_artifact_project_original_v1(db,namespace=namespace,project_ref=request.project_ref)
        if original['operation_kind']==CREATE_TASK_PROJECT_OPERATION_V1:
            from .artifact_task_observer_v1 import artifact_task_milestone_original_ref_v2,decode_artifact_task_milestone_v2
            from .d11_life_preparation_v1 import TABLE
            selector=_current_artifact_task_final_selector_v2(db,namespace=namespace,plan_ref=request.plan_ref)
            milestone_ref=artifact_task_milestone_original_ref_v2(selector)
            originals.append(milestone_ref)
            milestone_row=db.execute('SELECT payload_json FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
                (*namespace.as_tuple,'artifact_task_milestone_v2',milestone_ref)).fetchone()
            if milestone_row is not None:
                milestone=decode_artifact_task_milestone_v2(json.loads(milestone_row[0]))
                originals.extend((milestone.objective_ref,milestone.full_check_original_ref,milestone.file_result_ref))
                originals.extend(ref for ref,_ in milestone.ordered_phase_originals)
                keys.append(milestone.source_head.key);roots.append(milestone.source_head.key.token)
                if milestone.prev_milestone_ref is not None: originals.append(milestone.prev_milestone_ref)
                if milestone.amendment_ref is not None: originals.append(milestone.amendment_ref)
        progress = raw_head_value_v1(db, namespace, AtomKey.from_token(request.progress_ref))
        if progress:
            keys.append(project_work_version_key_v1(namespace, request.project_ref, progress["effect_id"]))
    elif operation_kind == "initialize_project_checkpoint" and type(request) is not InitializeCurrentProjectCheckpointRequestV1:
        raise TypeError("exact explicit project initialization required")
    elif operation_kind == "refresh_project_checkpoint" and type(request) is not RefreshCurrentProjectCheckpointRequestV1:
        raise TypeError("exact project refresh required")
    return production_read_plan_v1(types, keys, roots, originals)


CREATE_TASK_PROJECT_OPERATION_V1='create_artifact_task_project_v1'
INIT_TASK_CHECKPOINT_OPERATION_V1='initialize_artifact_task_project_checkpoint_v1'
ACTIVATE_TASK_CHECKPOINT_OPERATION_V1='activate_artifact_task_project_checkpoint_v1'


@dataclass(frozen=True,slots=True)
class CreateCurrentArtifactTaskProjectRequestV1:
    task: 'ArtifactDraftTaskSelectorV1'

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
        if type(self.task) is not ArtifactDraftTaskSelectorV1:raise TypeError('task project requires the actual typed task selector')


@dataclass(frozen=True,slots=True)
class InitializeCurrentArtifactTaskProjectCheckpointRequestV1(CreateCurrentArtifactTaskProjectRequestV1):
    pass


@dataclass(frozen=True,slots=True)
class ActivateCurrentArtifactTaskProjectCheckpointRequestV1:
    selector: 'ArtifactDraftPhaseSelectorV2'

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
        if type(self.selector) is not ArtifactDraftPhaseSelectorV2 or self.selector.phase_index!=0 or not self.selector.generation:
            raise TypeError('checkpoint activation requires the actual first selected whole-method phase')


def artifact_task_project_operation_id_v1(task):
    CreateCurrentArtifactTaskProjectRequestV1(task)
    return 'artifact-task-project:'+task.digest[:48]


def artifact_task_checkpoint_initialization_operation_id_v1(task):
    CreateCurrentArtifactTaskProjectRequestV1(task)
    return 'artifact-task-checkpoint:'+task.digest[:48]+':initialize'


def artifact_task_checkpoint_activation_operation_id_v1(selector):
    ActivateCurrentArtifactTaskProjectCheckpointRequestV1(selector)
    return 'artifact-task-checkpoint:'+selector.task.digest[:48]+':activate:'+selector.decision_digest[:16]


def _task_project_basis_v1(db,*,namespace,task,issuer,read=None,installed_bundle=None):
    from .d08_personal_plan_v1 import (_initial_artifact_task_plan_basis_v1,CreateCurrentArtifactTaskPlanRequestV1,
        InstalledD08PersonalPlanReadersV1,ARTIFACT_TASK_PLAN_OPERATION_V1,artifact_task_initial_plan_candidates_v1)
    from ..domains.d03.self_perspective import self_mapping_key,SelfIdentityMapping
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d11_artifact_draft_contract_v1 import RECIPE_ID
    from .d11_types import job_graph_write
    from .jobs import get_job
    from ..graph_types import GraphVersion
    CreateCurrentArtifactTaskProjectRequestV1(task)
    actual_plan_readers=InstalledD08PersonalPlanReadersV1(issuer=issuer,resource_issuer=issuer.resource_issuer,installed_bundle=installed_bundle)
    keys,goal,objective_ref,objective,scope_ref,scope,root,producer=_initial_artifact_task_plan_basis_v1(db,namespace=namespace,
        request=CreateCurrentArtifactTaskPlanRequestV1(task),installed_readers=actual_plan_readers)
    def atom(key):
        if read is not None:return read.head(db,key,required=True)
        from ..graph_types import GraphAtom
        row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',(*namespace.as_tuple,key.token)).fetchone()
        if row is None or row[2]!=1:raise MissingProductionOriginalV1('actual_current_task_project_Goal_Plan_Source')
        return GraphAtom(key,row[0],json.loads(row[1]),True)
    goal_atom,plan_atom=atom(keys[0]),atom(keys[1])
    source=atom(AtomKey.from_token(objective.source_ref));mapping_atom=atom(self_mapping_key(namespace))
    mapping=SelfIdentityMapping(**mapping_atom.value)
    plan=decode_personal_plan_type_v1(PLAN_TYPE,plan_atom.value)
    candidates=artifact_task_initial_plan_candidates_v1(task)
    if (plan.goal_ref!=goal_atom.key.token or plan.goal_revision!=goal_atom.revision or plan.state!='active'
            or goal_atom.value!=plain_v1(goal) or plan.actor_ref!=mapping.persona_ref or mapping.status!='active'
            or tuple(plan.method_candidates)!=tuple((candidate,method) for method,candidate,_ in candidates)
            or set(plan.candidate_refs)!={candidate for _,candidate,_ in candidates}
            or (source.revision,canonical_digest(source.value))!=(objective.source_revision,objective.source_digest)
            or tuple(plan.source_refs)!=(source.key.token,)):
        raise ValueError('task project changed actual initial Goal/Plan/Source/method candidates')
    for method,candidate,node_id in candidates:
        node=next((n for n in plan.nodes if n.node_id==node_id),None)
        if (node is None or node.action_kind!=RECIPE_ID or node.owner_ref!=plan.actor_ref or node.depends_on
                or node.success_predicate!=goal.satisfaction_predicate or node.resource_ref!=root.registration_ref):
            raise ValueError('task project changed actual prospective method node')
    history=db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',(plan_atom.key.token,plan_atom.revision)).fetchone()
    original=read_adopted_domain_operation_v1(db,namespace,history[0]) if history else None
    if (history is None or history[1:]!=(canonical_serialize(plan_atom.value),1)
            or original is None or (original['domain'],original['operation_kind'])!=('d08',ARTIFACT_TASK_PLAN_OPERATION_V1)
            or original['payload']['request']!={'task':plain_v1(task)}
            or not any(v.key==plan_atom.key and v.revision==plan_atom.revision for v in original['receipt'].write_versions)):
        raise MissingProductionOriginalV1('actual_initial_task_plan_W01_project_predecessor')
    cycle=get_job(db,AtomKey.from_token(task.cycle_job_ref).name)
    cycle_atom=atom(AtomKey.from_token(task.cycle_job_ref))
    if cycle_atom.value!=job_graph_write(cycle).value or (cycle.bot_id,cycle.persona_id)!=namespace.as_tuple:
        raise ValueError('task project current SQL cycle does not match its actual Graph')
    project={'project_id':keys[2].name,'topic':'artifact-task:'+goal.goal_id,'reality':'real_execution','next_step':RECIPE_ID}
    recipe={'recipe_id':RECIPE_ID,'version':1,'reality':'real_execution','allowed_steps':[RECIPE_ID],'preemptible':True}
    return keys,goal_atom,plan_atom,plan,objective,scope,root,cycle,{
        'task':plain_v1(task),'objective_ref':objective_ref,'objective_digest':canonical_digest(plain_v1(objective)),
        'task_scope_ref':scope_ref,'task_scope_digest':canonical_digest(plain_v1(scope)),
        'task_scope_producer_ref':'d10-current:'+producer['original_digest'][:48],'task_scope_producer_digest':producer['original_digest'],
        'c1_intent_ref':scope.c1_intent_ref,'c1_intent_digest':scope.c1_intent_digest,
        'goal_head':plain_v1(GraphVersion(goal_atom.key,goal_atom.revision)),'goal_digest':canonical_digest(goal_atom.value),
        'plan_head':plain_v1(GraphVersion(plan_atom.key,plan_atom.revision)),'plan_digest':canonical_digest(plan_atom.value),
        'plan_producer_ref':'d08-current:'+original['original_digest'][:48],'plan_producer_digest':original['original_digest'],
        'source_head':plain_v1(GraphVersion(source.key,source.revision)),'source_digest':canonical_digest(source.value),
        'root_digest':canonical_digest(plain_v1(root)),'project_ref':keys[2].token,'project_value':project,
        'recipe_ref':keys[3].token,'recipe_value':recipe}


def _current_task_project_basis_v1(db,*,frame,task,issuer,installed_bundle=None):
    from .budget import require_budget_family_admissible
    from .d11_offline_originals_v1 import _utc
    read=CurrentDomainReadV1(frame);read.check(db)
    result=_task_project_basis_v1(db,namespace=frame.envelope.authority.namespace,task=task,issuer=issuer,read=read,installed_bundle=installed_bundle)
    keys,_,_,_,objective,scope,root,cycle,basis=result
    if (frame.envelope.identity.activity_id!=cycle.activity_id or frame.envelope.parent_budget_lease_ref!=cycle.budget_ref
            or frame.envelope.authority.purpose!='consolidation'
            or (root.owner_grant_ref,root.owner_grant_revision,root.owner_grant_digest)!=(
                frame.owner_guard.grant_ref,frame.owner_guard.grant_revision,frame.owner_guard.grant_digest)):
        raise ValueError('task project current activity/budget/Owner/source purpose changed')
    from ..domains.d03.self_perspective import self_mapping_key,SelfIdentityMapping
    mapping=SelfIdentityMapping(**read.head(db,self_mapping_key(frame.envelope.authority.namespace),required=True).value)
    if mapping.self_entity_ref!=frame.envelope.authority.actor:
        raise MissingProductionOriginalV1('actual_task_project_current_foreground_Self')
    require_budget_family_admissible(db,cycle.budget_ref)
    grant=issuer.current_budget_grant(db,cycle.budget_ref)
    if not frame.now_utc<min(frame.envelope.deadline_utc,objective.valid_until_utc,_utc(root.valid_until_utc).timestamp(),
            _utc(cycle.deadline_utc).timestamp(),grant.valid_until_utc):
        raise MissingProductionOriginalV1('unexpired_registered_task_project_lifetime')
    read.source_family(db,(objective.source_ref,),purpose='context');read.source_family(db,(objective.source_ref,),purpose='consolidation')
    for ref,kind,digest in ((basis['objective_ref'],'d11.life_artifact_task_objective',basis['objective_digest']),
            (basis['task_scope_ref'],'d11.life_artifact_task_scope',basis['task_scope_digest']),
            (root.registration_ref,'d11.life_draft_root_capability',basis['root_digest']),
            (scope.c1_intent_ref,'d11.life_c1_task_intent',scope.c1_intent_digest),
            (basis['task_scope_producer_ref'],'d10.current-derive_ingress_artifact_task_scope_v1',basis['task_scope_producer_digest']),
            (basis['plan_producer_ref'],'d08.current-create_artifact_task_plan_v1',basis['plan_producer_digest'])):
        read.original(ref,kind=kind,digest=digest)
    return result


def read_plan_create_current_artifact_task_project_v1(db,*,namespace,request,installed_readers):
    from .d08_personal_plan_v1 import InstalledD08PersonalPlanReadersV1,CreateCurrentArtifactTaskPlanRequestV1,read_plan_current_artifact_task_plan_v1
    from ..domains.d03.self_perspective import self_mapping_key
    if type(request) is not CreateCurrentArtifactTaskProjectRequestV1:raise TypeError('exact task project selectors required')
    issuer=installed_readers.issuer
    keys,_,_,plan,_,_,_,_,basis=_task_project_basis_v1(db,namespace=namespace,task=request.task,issuer=issuer,installed_bundle=installed_readers.installed_bundle)
    extra=read_plan_current_artifact_task_plan_v1(db,namespace=namespace,request=CreateCurrentArtifactTaskPlanRequestV1(request.task),
        installed_readers=InstalledD08PersonalPlanReadersV1(issuer=issuer,resource_issuer=issuer.resource_issuer,installed_bundle=installed_readers.installed_bundle))
    return production_read_plan_v1(extra.fixed_type_ids,(*extra.exact_keys,*keys,self_mapping_key(namespace),
        *(AtomKey.from_token(v.ref) for v in plan.fact_versions)),extra.source_roots,
        (*extra.required_original_refs,basis['plan_producer_ref']))


def stage_create_current_artifact_task_project_in_transaction_v1(db,*,frame,request,installed_readers):
    if type(request) is not CreateCurrentArtifactTaskProjectRequestV1:raise TypeError('exact task project creation selector required')
    _task_project_model_readers_v1(installed_readers)
    try:
        issuer=installed_readers.issuer
        keys,_,_,_,objective,_,_,_,basis=_current_task_project_basis_v1(db,frame=frame,task=request.task,issuer=issuer,installed_bundle=installed_readers.installed_bundle)
        if (objective.installation_id,objective.manifest_digest)!=(installed_readers.installed_bundle.installation_policy.installation_id,
                installed_readers.installed_bundle.installation_policy.manifest_digest):raise ValueError('task project crossed actual installed package')
        if frame.envelope.identity.operation_id!=artifact_task_project_operation_id_v1(request.task):raise ValueError('task project changed fixed once ID')
        read=CurrentDomainReadV1(frame)
        if read.head(db,keys[2]).revision:raise ValueError('task project cannot replace an existing definition')
        recipe=read.head(db,keys[3])
        dependencies=(AtomKey.from_token(basis['source_head']['key']),)
        writes=(GraphWrite(keys[2],basis['project_value'],dependencies),)
        if recipe.revision:
            if not recipe.valid or recipe.value!=basis['recipe_value']:raise ValueError('task project cannot change existing registered recipe')
            from .d08_life_admission_v1 import _adopted
            _adopted(db,read,recipe)
        else:writes+=(GraphWrite(keys[3],basis['recipe_value'],dependencies),)
        return verify_d10_artifact_project_stage_v1(stage_result_v1(frame,'d10',CREATE_TASK_PROJECT_OPERATION_V1,request,writes=writes,
            provenance={'task_project_basis':basis},receiver_events=(('d03','artifact_project_definition_available'),),
            proposal_schema='d10.proposal.v1',proposal_hash=LifeDomain().descriptor.request_schema_hash))
    except MissingProductionOriginalV1 as missing:return waiting_stage_v1(frame,'d10',CREATE_TASK_PROJECT_OPERATION_V1,request,missing)


def require_artifact_task_project_original_v1(db,*,namespace,original):
    from .d11_life_preparation_v1 import TABLE
    from .ingress_artifact_task_scope_v1 import ArtifactTaskObjectiveV1,IngressArtifactTaskScopeOriginalV1,_decode as decode_task,task_objective_goal_v1
    from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1,artifact_draft_from_wire_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d11_artifact_draft_contract_v1 import RECIPE_ID
    if original is None or (original['domain'],original['operation_kind'])!=('d10',CREATE_TASK_PROJECT_OPERATION_V1):
        raise ValueError('task project needs its exact actual D10 producer')
    p=original['payload']['provenance']
    if set(p)!={'task_project_basis'}:raise ValueError('task project provenance has foreign fields')
    basis=p['task_project_basis']
    fields={'task','objective_ref','objective_digest','task_scope_ref','task_scope_digest','task_scope_producer_ref','task_scope_producer_digest',
        'c1_intent_ref','c1_intent_digest','goal_head','goal_digest','plan_head','plan_digest','plan_producer_ref','plan_producer_digest',
        'source_head','source_digest','root_digest','project_ref','project_value','recipe_ref','recipe_value'}
    if set(basis)!=fields:raise ValueError('task project basis has another closed schema')
    task=artifact_draft_from_wire_v1(basis['task'],ArtifactDraftTaskSelectorV1)
    if task.namespace!=namespace or original['payload']['request']!={'task':plain_v1(task)} or original['receipt'].operation_id!=artifact_task_project_operation_id_v1(task):
        raise ValueError('task project selector/fixed producer identity changed')
    for kind,ref,digest in (('artifact_task_objective',basis['objective_ref'],basis['objective_digest']),
            ('artifact_task_scope',basis['task_scope_ref'],basis['task_scope_digest']),('draft_root_capability',task.root_registration_ref,basis['root_digest'])):
        row=db.execute('SELECT payload_json,payload_digest FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
            (*namespace.as_tuple,kind,ref)).fetchone()
        if row is None or row[1]!=digest or canonical_digest(json.loads(row[0]))!=digest:raise ValueError('task project lost actual registered predecessor bytes')
        if kind=='artifact_task_objective':objective=decode_task(json.loads(row[0]),ArtifactTaskObjectiveV1)
        if kind=='artifact_task_scope':scope=decode_task(json.loads(row[0]),IngressArtifactTaskScopeOriginalV1)
    if (objective.project_ref,objective.recipe_ref,objective.goal_ref,objective.plan_ref,objective.source_ref,
            objective.initial_c02_operation_id,objective.initial_root_registration_ref)!=(basis['project_ref'],basis['recipe_ref'],
            basis['goal_head']['key'],basis['plan_head']['key'],basis['source_head']['key'],task.c02_operation_id,task.root_registration_ref):
        raise ValueError('task project changed original objective control scope')
    if (scope.objective_ref,scope.objective_digest,scope.c1_intent_ref,scope.c1_intent_digest)!=(
            basis['objective_ref'],basis['objective_digest'],basis['c1_intent_ref'],basis['c1_intent_digest']):
        raise ValueError('task project changed actual paid C1/task scope lineage')
    for head,digest in ((basis['goal_head'],basis['goal_digest']),(basis['plan_head'],basis['plan_digest']),(basis['source_head'],basis['source_digest'])):
        history=db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?',(head['key'],head['revision'])).fetchone()
        if history is None or history[1]!=1 or canonical_digest(json.loads(history[0]))!=digest:raise ValueError('task project current-at-production original reads changed')
        if head==basis['goal_head'] and json.loads(history[0])!=plain_v1(task_objective_goal_v1(objective)):
            raise ValueError('task project fabricated another Goal')
    if basis['project_value']!={'project_id':AtomKey.from_token(objective.project_ref).name,'topic':'artifact-task:'+AtomKey.from_token(objective.goal_ref).name,
            'reality':'real_execution','next_step':RECIPE_ID} or basis['recipe_value']!={'recipe_id':RECIPE_ID,'version':1,'reality':'real_execution','allowed_steps':[RECIPE_ID],'preemptible':True}:
        raise ValueError('task project changed installed finite definition or recipe')
    writes=original['receipt'].write_versions
    members={v.key.token for v in writes}
    if objective.project_ref not in members or not members<={objective.project_ref,objective.recipe_ref}:raise ValueError('task project CAS has foreign members')
    expected={objective.project_ref:basis['project_value'],objective.recipe_ref:basis['recipe_value']}
    for version in writes:
        row=db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',(version.key.token,version.revision)).fetchone()
        if version.revision!=1 or row!=(original['receipt'].operation_id,canonical_serialize(expected[version.key.token]),1):
            raise ValueError('task project does not own exact immutable original CAS members')
    # Both actual producers are immutable W01 operations; these are facts, not grants.
    for domain,ref,digest in (('d10',basis['task_scope_producer_ref'],basis['task_scope_producer_digest']),
            ('d08',basis['plan_producer_ref'],basis['plan_producer_digest'])):
        from .domain_production_originals_v1 import TABLE as DOMAIN_TABLE
        row=db.execute('SELECT operation_id FROM '+DOMAIN_TABLE+' WHERE bot=? AND persona=? AND domain=? AND original_digest=?',
            (*namespace.as_tuple,domain,digest)).fetchall()
        if len(row)!=1 or ref!=domain+'-current:'+digest[:48]:raise ValueError('task project predecessor locator changed')
        predecessor=read_adopted_domain_operation_v1(db,namespace,row[0][0])
        if predecessor is None or predecessor['receipt'].commit_seq>=original['receipt'].commit_seq:raise ValueError('task project preceded its actual registered Goal/Plan/task facts')
    return basis


def _task_project_model_readers_v1(readers):
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
    if type(readers) is not InstalledArtifactDraftModelReadersV1 or readers.model_runtime is None:
        raise TypeError('task Project/Checkpoint needs the actual installed model/Graph readers')
    graph=readers.model_runtime.graph
    graph._admin(readers.model_runtime.bootstrap)
    if (readers.model_runtime is not graph._GraphCoordinator__artifact_draft_model_runtime_v1
            or readers.issuer is not graph._GraphCoordinator__d11_issuer or readers.installed_bundle is not readers.model_runtime.bundle):
        raise ValueError('task Project/Checkpoint factory differs from actual installed runtime')
    return graph


def stage_initialize_current_artifact_task_project_checkpoint_v1(db,*,frame,request,installed_readers):
    if type(request) is not InitializeCurrentArtifactTaskProjectCheckpointRequestV1:raise TypeError('exact initial task checkpoint selector required')
    _task_project_model_readers_v1(installed_readers)
    try:
        keys,_,plan_atom,plan,_,_,_,_,basis=_current_task_project_basis_v1(db,frame=frame,task=request.task,issuer=installed_readers.issuer,installed_bundle=installed_readers.installed_bundle)
        if frame.envelope.identity.operation_id!=artifact_task_checkpoint_initialization_operation_id_v1(request.task):raise ValueError('initial task checkpoint once ID changed')
        read=CurrentDomainReadV1(frame)
        read_current_artifact_project_definition_v1(db,frame=frame,project_ref=keys[2].token,recipe_ref=keys[3].token,source_ref=basis['source_head']['key'])
        checkpoint_key=project_checkpoint_key_v1(request.task.namespace,keys[2].token)
        if read.head(db,checkpoint_key).revision:raise ValueError('initial task checkpoint cannot replace an actual continuation')
        _current_project_capacity_v1(db,frame=frame,project_ref=keys[2].token,issuer=installed_readers.issuer)
        ready=_ready_nodes(plan,())
        if len(ready)!=len(plan.candidate_refs) or len(ready)!=2:raise ValueError('initial checkpoint did not retain both actual prospective methods')
        actual_reader=InstalledD10ProjectReadersV1(issuer=installed_readers.issuer,cycle_job_ref=request.task.cycle_job_ref)
        wait=actual_reader.wait_condition(db,read,plan,())
        checkpoint=ProjectCheckpointV1(keys[2].token,1,keys[1].token,plan_atom.revision,(),(),(),None,'waiting',plan.fact_versions,wait)
        return _stage(frame,INIT_TASK_CHECKPOINT_OPERATION_V1,request,(GraphWrite(checkpoint_key,plain_v1(checkpoint)),),
            checkpoint=checkpoint,task_project_basis=basis)
    except MissingProductionOriginalV1 as missing:return waiting_stage_v1(frame,'d10',INIT_TASK_CHECKPOINT_OPERATION_V1,request,missing)


def stage_activate_current_artifact_task_project_checkpoint_v1(db,*,frame,request,installed_readers):
    if type(request) is not ActivateCurrentArtifactTaskProjectCheckpointRequestV1:raise TypeError('exact actual selected phase checkpoint activation required')
    graph=_task_project_model_readers_v1(installed_readers)
    from .d11_artifact_draft_model_v1 import _artifact_phase_selection_locator_v2
    from .d08_personal_candidate_v1 import read_selected_personal_adapter_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    try:
        selector=request.selector
        keys,_,plan_atom,plan,_,_,_,_,basis=_current_task_project_basis_v1(db,frame=frame,task=selector.task,issuer=installed_readers.issuer,installed_bundle=installed_readers.installed_bundle)
        if frame.envelope.identity.operation_id!=artifact_task_checkpoint_activation_operation_id_v1(selector):raise ValueError('selected task checkpoint activation once ID changed')
        read=CurrentDomainReadV1(frame)
        read_current_artifact_project_definition_v1(db,frame=frame,project_ref=keys[2].token,recipe_ref=keys[3].token,source_ref=basis['source_head']['key'])
        locator,_,_=_artifact_phase_selection_locator_v2(db,selector)
        personal=graph._GraphCoordinator__domain_production_runtime_v1._personal_candidate_readers_v1
        prepared,chosen,original=read_selected_personal_adapter_v1(db,frame=frame,request=locator,installed_readers=personal)
        if (prepared.plan_head.key!=plan_atom.key or prepared.plan_head.revision!=plan_atom.revision or
                (chosen.binding.task,chosen.binding.method_ref,chosen.binding.phase_index,chosen.binding.phase_kind)!=
                (selector.task,selector.method_ref,selector.phase_index,selector.phase_kind)):
            raise ValueError('checkpoint activation changed actually selected method/Plan')
        checkpoint_key=project_checkpoint_key_v1(selector.task.namespace,keys[2].token)
        atom=read.head(db,checkpoint_key,required=True);old=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,atom.value)
        init=read_adopted_domain_operation_v1(db,selector.task.namespace,artifact_task_checkpoint_initialization_operation_id_v1(selector.task))
        if (old.revision!=1 or atom.revision!=1 or old.state!='waiting' or old.next_step is not None
                or old.plan_ref!=plan_atom.key.token or old.plan_revision!=plan_atom.revision or old.completed_node_refs
                or init is None or init['payload']['provenance']['checkpoint']!=plain_v1(old)):
            raise MissingProductionOriginalV1('actual_waiting_preDecision_task_checkpoint')
        require_artifact_task_checkpoint_original_v1(db,namespace=selector.task.namespace,original=init)
        ready={node.node_id:node for node in _ready_nodes(plan,old.completed_node_refs)}
        if chosen.binding.node_id not in ready:raise ValueError('actual adopted selection is not a ready task method')
        checkpoint=replace(old,revision=2,next_step=chosen.binding.node_id,state='active',wait_condition=None,last_fact_versions=plan.fact_versions)
        return _stage(frame,ACTIVATE_TASK_CHECKPOINT_OPERATION_V1,request,(GraphWrite(checkpoint_key,plain_v1(checkpoint)),),
            checkpoint=checkpoint,task_project_basis=basis,
            selected_candidates_original_ref='d08-current:'+original['original_digest'][:48],selected_candidates_original_digest=original['original_digest'],
            selected_binding_digest=chosen.binding.digest,decision_ref=selector.decision_ref,decision_digest=selector.decision_digest)
    except MissingProductionOriginalV1 as missing:return waiting_stage_v1(frame,'d10',ACTIVATE_TASK_CHECKPOINT_OPERATION_V1,request,missing)


def read_plan_current_artifact_task_checkpoint_v1(db,*,namespace,request,installed_readers):
    _task_project_model_readers_v1(installed_readers)
    task=request.selector.task if type(request) is ActivateCurrentArtifactTaskProjectCheckpointRequestV1 else request.task
    project=read_plan_create_current_artifact_task_project_v1(db,namespace=namespace,
        request=CreateCurrentArtifactTaskProjectRequestV1(task),installed_readers=installed_readers)
    keys,_,_,_,_,_,_,_,_=_task_project_basis_v1(db,namespace=namespace,task=task,issuer=installed_readers.issuer,installed_bundle=installed_readers.installed_bundle)
    capacity=read_plan_current_project_capacity_v1(db,namespace=namespace)
    originals=(*project.required_original_refs,*capacity.required_original_refs,artifact_task_project_operation_id_v1(task))
    exact=(*project.exact_keys,*capacity.exact_keys,project_checkpoint_key_v1(namespace,keys[2].token))
    types=(*project.fixed_type_ids,*capacity.fixed_type_ids,CHECKPOINT_TYPE,WORK_TYPE)
    if type(request) is ActivateCurrentArtifactTaskProjectCheckpointRequestV1:
        from .d11_artifact_draft_model_v1 import _artifact_phase_selection_locator_v2
        from .d08_personal_candidate_v1 import read_plan_personal_candidates_v1
        graph=installed_readers.model_runtime.graph
        locator,_,_=_artifact_phase_selection_locator_v2(db,request.selector)
        personal=graph._GraphCoordinator__domain_production_runtime_v1._personal_candidate_readers_v1
        selected=read_plan_personal_candidates_v1(db,namespace=namespace,activity_id=keys[0].owner.subject,request=locator,installed_readers=personal)
        exact+=selected.exact_keys;types+=selected.fixed_type_ids
        originals+=(*selected.required_original_refs,artifact_task_checkpoint_initialization_operation_id_v1(task))
    elif type(request) is not InitializeCurrentArtifactTaskProjectCheckpointRequestV1:
        raise TypeError('task checkpoint readplan accepts only exact init or adopted Decision selector')
    return production_read_plan_v1(types,exact,project.source_roots,originals)


def verify_d10_artifact_task_stage_v1(stage):
    if stage.operation_kind==CREATE_TASK_PROJECT_OPERATION_V1:return verify_d10_artifact_project_stage_v1(stage)
    if stage.operation_kind in {INIT_TASK_CHECKPOINT_OPERATION_V1,ACTIVATE_TASK_CHECKPOINT_OPERATION_V1}:
        return verify_d10_project_checkpoint_stage_v1(stage)
    raise ValueError('unregistered D10 actual task definition/checkpoint producer')


def require_artifact_task_checkpoint_original_v1(db,*,namespace,original):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1,TABLE as DOMAIN_TABLE
    from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1,ArtifactDraftPhaseSelectorV2,artifact_draft_from_wire_v1,artifact_draft_from_wire_v2
    from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if original is None or original['domain']!='d10' or original['operation_kind'] not in {INIT_TASK_CHECKPOINT_OPERATION_V1,ACTIVATE_TASK_CHECKPOINT_OPERATION_V1}:
        raise ValueError('task checkpoint requires exact actual registered D10 producer')
    kind=original['operation_kind'];p=original['payload']['provenance'];basis=p['task_project_basis']
    checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,p['checkpoint'])
    if kind==INIT_TASK_CHECKPOINT_OPERATION_V1:
        if set(p)!={'checkpoint','task_project_basis'}:raise ValueError('initial task checkpoint has foreign provenance')
        task=artifact_draft_from_wire_v1(original['payload']['request']['task'],ArtifactDraftTaskSelectorV1)
        expected_id=artifact_task_checkpoint_initialization_operation_id_v1(task)
        if (checkpoint.revision,checkpoint.state,checkpoint.next_step,checkpoint.completed_node_refs,checkpoint.progress_refs,checkpoint.work_version_refs)!=(1,'waiting',None,(),(),()):
            raise ValueError('initial task checkpoint pretended to select or finish a method')
        if checkpoint.wait_condition is None or (checkpoint.wait_condition.producer_domain,checkpoint.wait_condition.event_kind,
                checkpoint.wait_condition.resume_job_ref)!=('d08','qualified_personal_step_available',task.cycle_job_ref):
            raise ValueError('initial task checkpoint has no actual method-choice wait binding')
    else:
        expected_fields={'checkpoint','task_project_basis','selected_candidates_original_ref','selected_candidates_original_digest',
            'selected_binding_digest','decision_ref','decision_digest'}
        if set(p)!=expected_fields:raise ValueError('selected task checkpoint has foreign provenance')
        selector=artifact_draft_from_wire_v2(original['payload']['request']['selector'],ArtifactDraftPhaseSelectorV2)
        ActivateCurrentArtifactTaskProjectCheckpointRequestV1(selector)
        task=selector.task;expected_id=artifact_task_checkpoint_activation_operation_id_v1(selector)
        rows=db.execute('SELECT operation_id FROM '+DOMAIN_TABLE+" WHERE bot=? AND persona=? AND domain='d08' AND operation_kind='prepare_personal_candidates_v1' AND original_digest=?",
            (*namespace.as_tuple,p['selected_candidates_original_digest'])).fetchall()
        if len(rows)!=1 or p['selected_candidates_original_ref']!='d08-current:'+p['selected_candidates_original_digest'][:48]:
            raise ValueError('task activation lost actual selected preparation original')
        preparation=read_adopted_domain_operation_v1(db,namespace,rows[0][0])
        prepared=decode_typed_production_value_v1(preparation['payload']['provenance']['prepared_candidates'],PreparedPersonalCandidateSetV1)
        chosen=tuple(c for c in prepared.candidates if c.binding.digest==p['selected_binding_digest'])
        if len(chosen)!=1:raise ValueError('task activation selected another or copied binding')
        decision=db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',(selector.decision_ref,selector.decision_revision)).fetchone()
        selection=read_adopted_domain_operation_v1(db,namespace,decision[0]) if decision else None
        if (decision is None or decision[2]!=1 or canonical_digest(json.loads(decision[1]))!=selector.decision_digest
                or (p['decision_ref'],p['decision_digest'])!=(selector.decision_ref,selector.decision_digest)
                or selection is None or (selection['domain'],selection['operation_kind'])!=('d08','select_personal_step_v2')
                or selection['payload']['provenance']['prepared_candidates_operation_id']!=prepared.preparation_operation_id
                or json.loads(decision[1])['chosen_action_ref']!=chosen[0].future_identity.action_ref
                or (chosen[0].binding.task,chosen[0].binding.method_ref)!=(selector.task,selector.method_ref)
                or checkpoint.next_step!=chosen[0].binding.node_id or checkpoint.state!='active' or checkpoint.revision!=2):
            raise ValueError('task activation does not adopt its actual selected Decision node')
        prior=read_adopted_domain_operation_v1(db,namespace,artifact_task_checkpoint_initialization_operation_id_v1(task))
        require_artifact_task_checkpoint_original_v1(db,namespace=namespace,original=prior)
        old=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,prior['payload']['provenance']['checkpoint'])
        expected=replace(old,revision=2,next_step=chosen[0].binding.node_id,state='active',wait_condition=None,last_fact_versions=checkpoint.last_fact_versions)
        if checkpoint!=expected or selection['receipt'].commit_seq>=original['receipt'].commit_seq:
            raise ValueError('task activation changed actual checkpoint predecessor/control order')
    if task.namespace!=namespace or basis['task']!=plain_v1(task) or original['receipt'].operation_id!=expected_id:
        raise ValueError('task checkpoint changed task namespace/fixed operation identity')
    definition=read_adopted_domain_operation_v1(db,namespace,artifact_task_project_operation_id_v1(task))
    expected_basis=require_artifact_task_project_original_v1(db,namespace=namespace,original=definition)
    if basis!=expected_basis or (checkpoint.project_ref,checkpoint.plan_ref,checkpoint.plan_revision)!=(basis['project_ref'],basis['plan_head']['key'],basis['plan_head']['revision']):
        raise ValueError('task checkpoint changed actual Project/Plan/Source basis')
    key=project_checkpoint_key_v1(namespace,checkpoint.project_ref)
    versions=original['receipt'].write_versions
    if len(versions)!=1 or versions[0].key!=key or versions[0].revision!=checkpoint.revision:
        raise ValueError('task checkpoint contains foreign CAS members')
    before=tuple(v for v in original['receipt'].read_versions if v.key==key)
    if len(before)!=1 or before[0].revision!=checkpoint.revision-1:raise ValueError('task checkpoint has no exact CAS predecessor')
    history=db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',(key.token,checkpoint.revision)).fetchone()
    if history!=(expected_id,canonical_serialize(plain_v1(checkpoint)),1):raise ValueError('task checkpoint original lacks actual immutable CAS history')
    return checkpoint,basis


def readonly_current_artifact_task_checkpoint_activation_facts_v1(db,*,namespace,selector,issuer):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..graph_types import GraphVersion
    if not db.in_transaction or type(issuer) is not D11BudgetJobIssuer:raise TypeError('activation facts require the actual current SQL scope and installed issuer')
    original=read_adopted_domain_operation_v1(db,namespace,artifact_task_checkpoint_activation_operation_id_v1(selector))
    if original is None:raise MissingProductionOriginalV1('actual_signed_task_checkpoint_selected_activation')
    checkpoint,basis=require_artifact_task_checkpoint_original_v1(db,namespace=namespace,original=original)
    key=project_checkpoint_key_v1(namespace,checkpoint.project_ref)
    row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?',(key.token,*namespace.as_tuple)).fetchone()
    if row!=(2,canonical_serialize(plain_v1(checkpoint)),1):raise MissingProductionOriginalV1('current_exact_task_checkpoint_activation_without_foreign_successor')
    return GraphVersion(key,1),GraphVersion(key,2),canonical_digest(plain_v1(checkpoint)),original['receipt'].operation_id,original['original_digest'],checkpoint.next_step


def read_current_artifact_task_checkpoint_activation_v1(db, *, namespace, selector, issuer):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    activation=read_adopted_domain_operation_v1(db,namespace,artifact_task_checkpoint_activation_operation_id_v1(selector))
    if activation is not None:
        readonly_current_artifact_task_checkpoint_activation_facts_v1(db,namespace=namespace,selector=selector,issuer=issuer)
        return True
    task=selector.task
    original=read_adopted_domain_operation_v1(db,namespace,artifact_task_checkpoint_initialization_operation_id_v1(task))
    if original is None: raise MissingProductionOriginalV1('actual_signed_task_checkpoint_initialization')
    checkpoint,_=require_artifact_task_checkpoint_original_v1(db,namespace=namespace,original=original)
    key=project_checkpoint_key_v1(namespace,checkpoint.project_ref)
    row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',(*namespace.as_tuple,key.token)).fetchone()
    if (checkpoint.next_step is not None or checkpoint.state!='waiting'
            or row!=(1,canonical_serialize(plain_v1(checkpoint)),1)):
        raise MissingProductionOriginalV1('actual_current_waiting_task_checkpoint_before_selected_activation')
    return False


def _current_artifact_task_final_selector_v2(db, *, namespace, plan_ref):
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1,ForegroundCycleContinuationV2
    from .foreground_call_plan_v1 import ForegroundCallPlanV2
    from .jobs import get_job
    rows=db.execute("SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? AND work_kind='d11.foreground_cycle.v1' "
        "AND json_extract(continuation_json,'$.call_plan.phase_group.selector.plan_ref')=? AND phase='running'",(*namespace.as_tuple,plan_ref)).fetchall()
    if len(rows)!=1: raise MissingProductionOriginalV1('actual_unique_current_artifact_method_final_cycle')
    cycle=get_job(db,rows[0][0]);continuation=foreground_cycle_from_wire_v1(cycle.continuation)
    if type(continuation) is not ForegroundCycleContinuationV2 or type(continuation.call_plan) is not ForegroundCallPlanV2 or cycle.cancel_epoch:
        raise MissingProductionOriginalV1('actual_uncancelled_current_artifact_method_final_cycle')
    selector=continuation.call_plan.phase_group.selector
    if selector.phase_kind!='check': raise MissingProductionOriginalV1('actual_final_artifact_method_check_before_project_settlement')
    return selector


def _settle_current_artifact_task_checkpoint_v2(db, *, frame, request, readers, checkpoint_atom, checkpoint, plan, evidence):
    from .artifact_task_observer_v1 import (artifact_task_milestone_original_ref_v2,read_current_artifact_task_milestone_v2)
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2,artifact_draft_file_ids_v2
    ns=frame.envelope.authority.namespace
    selector=_current_artifact_task_final_selector_v2(db,namespace=ns,plan_ref=request.plan_ref)
    milestone=read_current_artifact_task_milestone_v2(db,namespace=ns,original_ref=artifact_task_milestone_original_ref_v2(selector),issuer=readers.issuer)
    first=replace(selector,phase_index=0,phase_kind=artifact_draft_phase_sequence_v2(selector.method_ref)[0],prev_phase_original_ref=None,prev_phase_original_digest=None)
    if milestone.semantic_index==2:
        activation=read_adopted_domain_operation_v1(db,ns,artifact_task_checkpoint_activation_operation_id_v2(first))
        activated,_,actual,_=require_artifact_task_checkpoint_activation_original_v2(db,namespace=ns,original=activation)
        if actual!=first:raise ValueError('second milestone changed its actual selected amended checkpoint')
    else:
        activation=read_adopted_domain_operation_v1(db,ns,artifact_task_checkpoint_activation_operation_id_v1(first))
        if activation is None: raise MissingProductionOriginalV1('actual_selected_task_checkpoint_activation_before_settlement')
        activated,_=require_artifact_task_checkpoint_original_v1(db,namespace=ns,original=activation)
    nodes=tuple(node for node in plan.nodes if node.node_id==activated.next_step)
    if len(nodes)!=1: raise MissingProductionOriginalV1('actual_selected_method_plan_node_before_settlement')
    node=nodes[0]
    generation_index=selector.phase_index-1
    previous=milestone.ordered_phase_originals[generation_index-1] if generation_index else (None,None)
    generation=replace(selector,phase_index=generation_index,phase_kind='full',prev_phase_original_ref=previous[0],prev_phase_original_digest=previous[1])
    file_ids=artifact_draft_file_ids_v2(generation)
    if (checkpoint_atom.revision!=request.expected_checkpoint_revision or checkpoint.revision!=checkpoint_atom.revision
            or checkpoint.next_step!=node.node_id or checkpoint.state!='active'
            or request.next_step is not None or node.node_id in checkpoint.completed_node_refs
            or (milestone.project_ref,milestone.goal_ref)!=(request.project_ref,plan.goal_ref)
            or milestone.owner_guard!=frame.owner_guard or frame.now_utc>=milestone.original_deadline_utc
            or (evidence.artifact_ref,evidence.artifact_digest,evidence.artifact_length,evidence.work_version,evidence.effect_id,evidence.attempt_id)!=
                (milestone.file_result_ref,milestone.readback.content_digest,milestone.readback.content_length,milestone.file_version,milestone.readback.effect_id,file_ids['attempt'])
            or not evidence.completed_verified or (node.action_kind,node.success_predicate)!=(evidence.action_kind,evidence.success_predicate)):
        raise MissingProductionOriginalV1('actual_selected_full_method_milestone_project_effect_and_original_scope')
    read=CurrentDomainReadV1(frame);read.check(db)
    read.original(milestone.original_ref,kind='d11.life_artifact_task_milestone_v2',digest=milestone.digest)
    if milestone.semantic_index==2:
        previous=read_current_artifact_task_milestone_v2(db,namespace=ns,original_ref=milestone.prev_milestone_ref,issuer=readers.issuer)
        works=read.complete_inventory(db,WORK_TYPE)
        same=tuple(atom for atom in works if atom.valid and atom.value['project_ref']==request.project_ref and atom.value['work_ref']==evidence.work_ref)
        if not same or max(atom.value['version'] for atom in same)!=previous.file_version:
            raise MissingProductionOriginalV1('actual_previous_semantic_milestone_project_work')
    elif checkpoint.work_version_refs:
        raise ValueError('first semantic milestone cannot replace existing project work')
    work=ProjectWorkVersionV1(request.project_ref,evidence.work_ref,evidence.work_version,request.progress_ref,
        evidence.artifact_ref,evidence.artifact_digest,evidence.artifact_length,evidence.terminal_ref,evidence.action_outcome_ref,
        evidence.source_refs,evidence.source_versions,evidence.activity_id,evidence.effect_id,evidence.attempt_id,node.node_id)
    work_key=project_work_version_key_v1(ns,request.project_ref,evidence.effect_id)
    if read.head(db,work_key).revision: raise ValueError('semantic milestone work already has its immutable settled version')
    updated=replace(checkpoint,revision=checkpoint.revision+1,plan_revision=plan.revision,
        completed_node_refs=tuple(dict.fromkeys((*checkpoint.completed_node_refs,node.node_id))),
        progress_refs=(*checkpoint.progress_refs,request.progress_ref),work_version_refs=(*checkpoint.work_version_refs,work_key.token),
        next_step=None,state='completed',last_fact_versions=plan.fact_versions,wait_condition=None)
    proof=ProductionOriginalRefV1('d11.life_artifact_task_milestone_v2',milestone.original_ref,milestone.digest,(milestone.source_head,))
    return _stage(frame,'settle_project_checkpoint',request,(GraphWrite(work_key,plain_v1(work)),GraphWrite(checkpoint_atom.key,plain_v1(updated))),
        checkpoint=updated,work_version=work,actual_effect=evidence,artifact_task_milestone=proof)


ACTIVATE_TASK_CHECKPOINT_OPERATION_V2='activate_artifact_task_project_checkpoint_v2'


@dataclass(frozen=True,slots=True)
class ActivateCurrentArtifactTaskProjectCheckpointRequestV2:
    selector: ArtifactDraftPhaseSelectorV2

    def __post_init__(self):
        ActivateCurrentArtifactTaskProjectCheckpointRequestV1(self.selector)


def artifact_task_checkpoint_activation_operation_id_v2(selector):
    ActivateCurrentArtifactTaskProjectCheckpointRequestV2(selector)
    return 'artifact-task-revision-checkpoint:'+selector.task.digest[:48]+':activate:'+selector.decision_digest[:16]


def stage_artifact_task_plan_revision_checkpoint_v2(db, *, frame, request, plan, checkpoint_atom, installed_readers):
    from .d08_personal_plan_v1 import ReviseCurrentArtifactTaskPlanRequestV2,ARTIFACT_TASK_PLAN_REVISION_OPERATION_V2
    if type(request) is not ReviseCurrentArtifactTaskPlanRequestV2:
        raise TypeError('revision checkpoint belongs to its exact same-W01 Plan request')
    read=CurrentDomainReadV1(frame);read.check(db)
    if read.head(db,checkpoint_atom.key,required=True)!=checkpoint_atom:raise ValueError('revision checkpoint before member changed')
    old=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,checkpoint_atom.value)
    if old.state!='waiting' or old.next_step is not None or len(old.work_version_refs)!=1 or not old.completed_node_refs:
        raise MissingProductionOriginalV1('actual_first_partial_task_wait_checkpoint')
    actual_reader=InstalledD10ProjectReadersV1(issuer=installed_readers.issuer,cycle_job_ref=request.task.cycle_job_ref)
    wait=actual_reader.wait_condition(db,read,plan,old.completed_node_refs)
    checkpoint=replace(old,revision=checkpoint_atom.revision+1,plan_revision=plan.revision,last_fact_versions=plan.fact_versions,wait_condition=wait)
    return _stage(frame,ARTIFACT_TASK_PLAN_REVISION_OPERATION_V2,request,(GraphWrite(checkpoint_atom.key,plain_v1(checkpoint)),))


def stage_activate_current_artifact_task_project_checkpoint_v2(db, *, frame, request, installed_readers):
    from .d08_personal_plan_v1 import (artifact_task_plan_revision_operation_id_v2,
        require_artifact_task_plan_revision_original_v2)
    from .d11_artifact_draft_model_v1 import _artifact_phase_selection_locator_v2
    from .d08_personal_candidate_v1 import read_selected_personal_adapter_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    if type(request) is not ActivateCurrentArtifactTaskProjectCheckpointRequestV2:
        raise TypeError('exact actual amended selected phase checkpoint request required')
    graph=_task_project_model_readers_v1(installed_readers)
    try:
        selector=request.selector;ns=selector.task.namespace
        read=CurrentDomainReadV1(frame);read.check(db)
        revision=read_adopted_domain_operation_v1(db,ns,artifact_task_plan_revision_operation_id_v2(selector.task))
        plan,old=require_artifact_task_plan_revision_original_v2(db,namespace=ns,original=revision)
        if frame.envelope.identity.operation_id!=artifact_task_checkpoint_activation_operation_id_v2(selector):
            raise ValueError('amended selected checkpoint activation changed its fixed operation')
        plan_atom=read.head(db,selector.plan_ref,required=True)
        checkpoint_key=project_checkpoint_key_v1(ns,old.project_ref);checkpoint_atom=read.head(db,checkpoint_key,required=True)
        if (plan_atom.value!=plain_v1(plan) or checkpoint_atom.value!=plain_v1(old)
                or plan_atom.revision!=selector.plan_revision or canonical_digest(plan_atom.value)!=selector.plan_digest):
            raise MissingProductionOriginalV1('current_exact_amended_Plan_waiting_checkpoint')
        locator,_,_=_artifact_phase_selection_locator_v2(db,selector)
        personal=graph._GraphCoordinator__domain_production_runtime_v1._personal_candidate_readers_v1
        prepared,chosen,original=read_selected_personal_adapter_v1(db,frame=frame,request=locator,installed_readers=personal)
        if ((chosen.binding.task,chosen.binding.method_ref,chosen.binding.phase_index,chosen.binding.phase_kind)!=
                (selector.task,selector.method_ref,selector.phase_index,selector.phase_kind)
                or prepared.plan_head.key!=plan_atom.key or prepared.plan_head.revision!=plan_atom.revision):
            raise ValueError('amended checkpoint activation changed the actual chosen Decision method')
        ready={node.node_id:node for node in _ready_nodes(plan,old.completed_node_refs)}
        if chosen.binding.node_id not in ready or chosen.binding.node_id not in {n.node_id for n in plan.nodes if n.node_id not in old.completed_node_refs}:
            raise ValueError('amended activation did not select its new actual ready method node')
        checkpoint=replace(old,revision=old.revision+1,next_step=chosen.binding.node_id,state='active',wait_condition=None)
        return _stage(frame,ACTIVATE_TASK_CHECKPOINT_OPERATION_V2,request,(GraphWrite(checkpoint_key,plain_v1(checkpoint)),),
            checkpoint=checkpoint,task_plan_revision_operation_id=revision['receipt'].operation_id,
            task_plan_revision_original_digest=revision['original_digest'],
            selected_candidates_original_ref='d08-current:'+original['original_digest'][:48],
            selected_candidates_original_digest=original['original_digest'],selected_binding_digest=chosen.binding.digest,
            decision_ref=selector.decision_ref,decision_digest=selector.decision_digest)
    except MissingProductionOriginalV1 as missing:return waiting_stage_v1(frame,'d10',ACTIVATE_TASK_CHECKPOINT_OPERATION_V2,request,missing)



def require_artifact_task_checkpoint_activation_original_v2(db, *, namespace, original):
    from ..graph_types import GraphVersion
    from .d08_personal_plan_v1 import require_artifact_task_plan_revision_original_v2,artifact_task_plan_revision_operation_id_v2
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1,TABLE as DOMAIN_TABLE
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1
    if original is None or (original['domain'],original['operation_kind'])!=('d10',ACTIVATE_TASK_CHECKPOINT_OPERATION_V2):
        raise MissingProductionOriginalV1('actual_amended_selected_checkpoint_activation_original')
    selector=decode_typed_production_value_v1(original['payload']['request']['selector'],ArtifactDraftPhaseSelectorV2)
    ActivateCurrentArtifactTaskProjectCheckpointRequestV2(selector)
    p=original['payload']['provenance']
    fields={'checkpoint','task_plan_revision_operation_id','task_plan_revision_original_digest',
        'selected_candidates_original_ref','selected_candidates_original_digest','selected_binding_digest','decision_ref','decision_digest'}
    if set(p)!=fields or selector.task.namespace!=namespace or original['receipt'].operation_id!=artifact_task_checkpoint_activation_operation_id_v2(selector):
        raise ValueError('amended activation changed actual namespace, provenance or fixed operation')
    revision=read_adopted_domain_operation_v1(db,namespace,artifact_task_plan_revision_operation_id_v2(selector.task))
    plan,old=require_artifact_task_plan_revision_original_v2(db,namespace=namespace,original=revision)
    if (p['task_plan_revision_operation_id'],p['task_plan_revision_original_digest'])!=(revision['receipt'].operation_id,revision['original_digest']):
        raise ValueError('amended activation lost actual same-W01 Plan checkpoint predecessor')
    rows=db.execute('SELECT operation_id FROM '+DOMAIN_TABLE+" WHERE bot=? AND persona=? AND domain='d08' AND operation_kind='prepare_personal_candidates_v1' AND original_digest=?",
        (*namespace.as_tuple,p['selected_candidates_original_digest'])).fetchall()
    if len(rows)!=1 or p['selected_candidates_original_ref']!='d08-current:'+p['selected_candidates_original_digest'][:48]:
        raise ValueError('amended activation lost immutable selected candidate preparation')
    preparation=read_adopted_domain_operation_v1(db,namespace,rows[0][0])
    prepared=decode_typed_production_value_v1(preparation['payload']['provenance']['prepared_candidates'],PreparedPersonalCandidateSetV1)
    chosen=tuple(c for c in prepared.candidates if c.binding.digest==p['selected_binding_digest'])
    decision=db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',(selector.decision_ref,selector.decision_revision)).fetchone()
    selection=read_adopted_domain_operation_v1(db,namespace,decision[0]) if decision else None
    if (len(chosen)!=1 or selection is None or (selection['domain'],selection['operation_kind'])!=('d08','select_personal_step_v2')
            or decision[2]!=1 or canonical_digest(json.loads(decision[1]))!=selector.decision_digest
            or (p['decision_ref'],p['decision_digest'])!=(selector.decision_ref,selector.decision_digest)
            or selection['payload']['provenance']['prepared_candidates_operation_id']!=prepared.preparation_operation_id
            or json.loads(decision[1])['chosen_action_ref']!=chosen[0].future_identity.action_ref
            or (chosen[0].binding.task,chosen[0].binding.method_ref)!=(selector.task,selector.method_ref)
            or (prepared.plan_head.key.token,prepared.plan_head.revision)!=(selector.plan_ref,selector.plan_revision)
            or selector.plan_revision!=plan.revision or selector.plan_digest!=canonical_digest(plain_v1(plan))):
        raise ValueError('amended checkpoint activation changed the actual selected Decision/Plan')
    checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,p['checkpoint'])
    expected=replace(old,revision=old.revision+1,next_step=chosen[0].binding.node_id,state='active',wait_condition=None)
    if checkpoint!=expected or not revision['receipt'].commit_seq<selection['receipt'].commit_seq<original['receipt'].commit_seq:
        raise ValueError('amended activation changed waiting predecessor, physical work or causal order')
    key=project_checkpoint_key_v1(namespace,checkpoint.project_ref)
    if (original['receipt'].write_versions!=(GraphVersion(key,checkpoint.revision),)
            or not any(v.key==key and v.revision==old.revision for v in original['read_versions'])):
        raise ValueError('amended activation must consume its exact one current checkpoint before member')
    actual=db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',(key.token,checkpoint.revision)).fetchone()
    if actual!=(original['receipt'].operation_id,canonical_serialize(plain_v1(checkpoint)),1):
        raise ValueError('amended checkpoint activation lost actual immutable CAS history')
    return checkpoint,plan,selector,chosen[0].binding.node_id


def read_plan_activate_current_artifact_task_project_checkpoint_v2(db, *, namespace, request, installed_readers):
    from .jobs import get_job
    from .d08_personal_plan_v1 import require_artifact_task_plan_revision_original_v2,artifact_task_plan_revision_operation_id_v2
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d11_artifact_draft_model_v1 import _artifact_phase_selection_locator_v2
    from .d08_personal_candidate_v1 import read_plan_personal_candidates_v1
    if type(request) is not ActivateCurrentArtifactTaskProjectCheckpointRequestV2:raise TypeError('exact amended checkpoint activation read selector required')
    graph=_task_project_model_readers_v1(installed_readers);selector=request.selector
    revision=read_adopted_domain_operation_v1(db,namespace,artifact_task_plan_revision_operation_id_v2(selector.task))
    plan,old=require_artifact_task_plan_revision_original_v2(db,namespace=namespace,original=revision)
    locator,_,_=_artifact_phase_selection_locator_v2(db,selector)
    personal=graph._GraphCoordinator__domain_production_runtime_v1._personal_candidate_readers_v1
    cycle=get_job(db,AtomKey.from_token(selector.task.cycle_job_ref).name)
    extra=read_plan_personal_candidates_v1(db,namespace=namespace,activity_id=cycle.activity_id,request=locator,installed_readers=personal)
    return production_read_plan_v1(extra.fixed_type_ids,(*extra.exact_keys,project_checkpoint_key_v1(namespace,old.project_ref),
        AtomKey.from_token(selector.plan_ref),AtomKey.from_token(selector.decision_ref)),extra.source_roots,
        (*extra.required_original_refs,'d08-current:'+revision['original_digest'][:48]))


def readonly_current_artifact_task_checkpoint_activation_facts_v2(db, *, namespace, selector, issuer):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..graph_types import GraphVersion
    original=read_adopted_domain_operation_v1(db,namespace,artifact_task_checkpoint_activation_operation_id_v2(selector))
    checkpoint,plan,actual,node=require_artifact_task_checkpoint_activation_original_v2(db,namespace=namespace,original=original)
    from .artifact_task_amendment_v1 import read_current_amendment_v1
    from .artifact_task_observer_v1 import read_current_artifact_task_milestone_v2
    revision=read_adopted_domain_operation_v1(db,namespace,original['payload']['provenance']['task_plan_revision_operation_id'])
    read_current_artifact_task_milestone_v2(db,namespace=namespace,
        original_ref=revision['payload']['provenance']['previous_milestone_ref'],issuer=issuer)
    if read_current_amendment_v1(db,namespace=namespace,root_registration_ref=actual.task.root_registration_ref,issuer=issuer) is None:
        raise MissingProductionOriginalV1('current_signed_ordinary_amendment_for_checkpoint_activation')
    if actual!=selector:raise ValueError('amended checkpoint reader changed the actual first phase selector')
    key=project_checkpoint_key_v1(namespace,checkpoint.project_ref)
    head=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',(*namespace.as_tuple,key.token)).fetchone()
    if head!=(checkpoint.revision,canonical_serialize(plain_v1(checkpoint)),1):
        raise MissingProductionOriginalV1('current_exact_amended_activation_without_foreign_successor')
    return GraphVersion(key,checkpoint.revision-1),GraphVersion(key,checkpoint.revision),canonical_digest(plain_v1(checkpoint)),original['receipt'].operation_id,original['original_digest'],node
