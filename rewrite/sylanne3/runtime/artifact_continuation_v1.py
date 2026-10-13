"""Bounded artifact revision candidates; no read, admission or write authority.

The installed W01 reader supplies authenticated original material. The W01
commit witness must reread it and rebuild this exact candidate before CAS.
A constructed instance is never evidence of adoption or permission.
"""
from dataclasses import dataclass, replace

from ..graph_types import AtomKey, GraphWrite, GraphVersion
from ..runtime_contracts import VersionedRef, canonical_digest
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d08.execution import Goal, GoalPredicate
from ..domains.d08.personal_plan_v1 import PersonalPlanV1, PlanNodeV2
from ..domains.d10.project_checkpoint_v1 import ProjectCheckpointV1
from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v1
from .d11_artifact_draft_content_v1 import ArtifactDraftContentAdoptionV1
from .d11_artifact_draft_contract_v1 import (
    DraftRootCapabilityV1, DraftFileTargetV1, DraftFileIdentityV1, RECIPE_ID, POSTCONDITION_ID,
)
from .d11_life_contract_v1 import draft_artifact_ref_v1
from .d11_offline_originals_v1 import _utc


@dataclass(frozen=True, slots=True)
class ExistingArtifactRevisionBasisV1:
    """Metadata of the actual current heads and their last valid originals."""
    goal_ref: str
    plan_ref: str
    project_ref: str
    recipe_ref: str
    checkpoint_ref: str
    current_versions: tuple[GraphVersion, ...]
    last_valid_versions: tuple[GraphVersion, ...]
    producer_digests: tuple[str, ...]
    goal: Goal
    plan: PersonalPlanV1
    checkpoint: ProjectCheckpointV1
    project_value: dict[str, str]
    recipe_value: dict[str, str | int | bool | list[str]]
    recipe_current_valid: bool
    predecessor_result_ref: str
    predecessor_prepared_digest: str
    predecessor_adopted_digest: str
    predecessor_effect_id: str
    predecessor_target: DraftFileTargetV1
    prior_version: int
    prior_content_digest: str
    prior_file_identity: DraftFileIdentityV1
    prior_effect_marker: str
    verified_effects_by_node: tuple[tuple[str, tuple[str, ...]], ...]
    correction_head_ref: str
    correction_head_revision: int
    correction_original_digest: str

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class ArtifactRevisionCandidateV1:
    basis_digest: str
    content_adoption_digest: str
    root_digest: str
    expected_versions: tuple[GraphVersion, ...]
    goal: Goal
    plan: PersonalPlanV1
    checkpoint: ProjectCheckpointV1
    d08_writes: tuple[GraphWrite, ...]
    d10_writes: tuple[GraphWrite, ...]
    old_effect_id: str
    new_effect_id: str
    new_action_ref: str
    schema: str = "d08.existing-artifact-revision-candidate.v1"

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


def continuation_replace_target_v1(basis, root):
    """Freeze an actual prior file under a separately authenticated fresh Root."""
    if type(basis) is not ExistingArtifactRevisionBasisV1 or type(root) is not DraftRootCapabilityV1:
        raise TypeError("exact actual artifact basis and current Root required")
    previous = basis.predecessor_target
    if (root.resource_id != previous.root_resource_id
            or root.root_identity != previous.root_identity
            or root.filenames != (previous.filename,)):
        raise ValueError("continued artifact changed physical root or unique filename")
    return DraftFileTargetV1(
        root.resource_id, root.registration_ref, canonical_digest(plain_v1(root)),
        root.root_identity, previous.filename, "replace", basis.prior_version,
        basis.prior_content_digest, basis.prior_file_identity,
        basis.prior_effect_marker, root.max_bytes,
    )


def compose_existing_artifact_revision_v1(
    *, namespace, basis, adoption, root, current_source_versions, now_utc,
):
    """Preserve stable work identity and historical effects; append one new node.

    This function is pure. The installed caller must authenticate basis/root/
    adoption and independently qualify the new Source family before calling.
    """
    if (type(basis) is not ExistingArtifactRevisionBasisV1
            or type(adoption) is not ArtifactDraftContentAdoptionV1
            or type(root) is not DraftRootCapabilityV1
            or adoption.selector.namespace != namespace):
        raise TypeError("finite artifact revision originals required")
    target = continuation_replace_target_v1(basis, root)
    if (adoption.target != target
            or adoption.selector.root_registration_ref != root.registration_ref
            or adoption.task_source.ref != root.source_ref):
        raise ValueError("new paid content changed the selected replacement target")
    deadline = min(_utc(adoption.original_deadline_utc).timestamp(),
                   _utc(root.valid_until_utc).timestamp())
    if not adoption.recorded_at_utc <= now_utc < deadline:
        raise ValueError("new actual artifact authorization expired")
    old_goal, old_plan, old_checkpoint = basis.goal, basis.plan, basis.checkpoint
    if (type(old_goal) is not Goal or type(old_plan) is not PersonalPlanV1
            or type(old_checkpoint) is not ProjectCheckpointV1
            or old_goal.state != "active"
            or (old_goal.satisfaction_predicate.kind, old_goal.satisfaction_predicate.observation_provider) !=
               ("domain_state", "d08.artifact_task_objective.v1")
            or old_plan.state not in {"active", "waiting"}
            or old_checkpoint.state == "cancelled"
            or old_plan.goal_ref != basis.goal_ref
            or old_checkpoint.plan_ref != basis.plan_ref
            or old_checkpoint.project_ref != basis.project_ref
            or old_plan.goal_revision != old_goal.revision):
        raise ValueError("only the actual unfinished existing work may continue")
    keys = tuple(AtomKey.from_token(ref) for ref in (
        basis.goal_ref, basis.plan_ref, basis.project_ref,
        basis.recipe_ref, basis.checkpoint_ref))
    if (tuple(key.type_name for key in keys) != (
            "d08.goal.v1", "d08.personal_plan.v1", "d10.life_project.v1",
            "d10.activity_recipe.v1", "d10.project_checkpoint.v1")
            or any((key.owner.bot, key.owner.persona) != namespace.as_tuple for key in keys)
            or keys[0].name != old_goal.goal_id or keys[1].name != old_plan.plan_id
            or basis.project_value.get("project_id") != keys[2].name
            or basis.project_value.get("reality") != "real_execution"
            or basis.project_value.get("next_step") != RECIPE_ID
            or basis.recipe_value != {"recipe_id": RECIPE_ID, "version": 1,
                "reality": "real_execution", "allowed_steps": [RECIPE_ID],
                "preemptible": True}):
        raise ValueError("artifact revision stable keys or installed recipe differ")
    versions = {row.key: row for row in basis.current_versions}
    historical = {row.key: row for row in basis.last_valid_versions}
    if (len(versions) != 5 or set(versions) != set(keys)
            or len(historical) != 5 or set(historical) != set(keys)
            or len(basis.producer_digests) != 5
            or any(not 1 <= historical[key].revision <= versions[key].revision for key in keys)):
        raise ValueError("current CAS and last valid producer versions must be separate")
    known = dict(basis.verified_effects_by_node)
    node_ids = {node.node_id for node in old_plan.nodes}
    if (len(known) != len(basis.verified_effects_by_node) or set(known) != node_ids
            or set(old_checkpoint.completed_node_refs) != node_ids
            or old_checkpoint.plan_revision != old_plan.revision
            or any(not effects for effects in known.values())
            or any(node.pending_original_effects for node in old_plan.nodes)
            or basis.predecessor_effect_id not in {effect for effects in known.values() for effect in effects}):
        raise ValueError("every existing node/effect must have actual settled progress before revision")
    if len(old_plan.nodes) >= 8:
        raise ValueError("artifact plan reached its existing bounded node window")
    roots = tuple(dict.fromkeys((adoption.task_source.ref, *adoption.content.source_refs)))
    facts = {row.ref: row for row in current_source_versions}
    if (len(facts) != len(current_source_versions)
            or any(type(row) is not VersionedRef for row in current_source_versions)
            or any(ref not in facts or facts[ref].version < 1 for ref in roots)):
        raise ValueError("new authored content requires its actual current Source closure")
    # Historical facts remain locators, never current semantic input. The actual
    # reader verifies their immutable original versions and disallows use as Sources.
    merged_facts = {row.ref: row for row in old_plan.fact_versions}
    merged_facts.update(facts)
    correction = VersionedRef(basis.correction_head_ref, basis.correction_head_revision)
    merged_facts[correction.ref] = correction
    ids = artifact_draft_file_ids_v1(namespace,
        c02_operation_id=adoption.selector.c02_operation_id,
        root_registration_ref=root.registration_ref)
    if ids["effect"] == basis.predecessor_effect_id or ids["node"] in node_ids:
        raise ValueError("new revision cannot reuse the prior effect or node")
    predicate = GoalPredicate("artifact_verified", POSTCONDITION_ID, (
        ("artifact_ref", draft_artifact_ref_v1(namespace, ids["effect"])),
        ("content_digest", adoption.content.content_digest),
        ("target_scope_digest", target.digest),
        ("build_digest", adoption.postcondition_build_digest)),
        adoption.recorded_at_utc, deadline)
    from .d08_personal_plan_v1 import artifact_draft_action_keys_v1
    action_ref = artifact_draft_action_keys_v1(namespace,
        c02_operation_id=adoption.selector.c02_operation_id,
        root_registration_ref=root.registration_ref)[0].token
    preserved_nodes = tuple(replace(node,
        carried_forward_verified=tuple(dict.fromkeys((*node.carried_forward_verified,
                                                     *known[node.node_id]))))
        for node in old_plan.nodes)
    new_node = PlanNodeV2(ids["node"], old_plan.actor_ref,
        tuple(old_checkpoint.completed_node_refs), RECIPE_ID, predicate, True,
        None, root.registration_ref, (predicate,))
    goal = replace(old_goal, revision=versions[keys[0]].revision + 1,
        reason_refs=roots,
        dependency_refs=(root.registration_ref, adoption.paid_original_ref, adoption.result_original_ref))
    plan = replace(old_plan, revision=versions[keys[1]].revision + 1,
        goal_revision=goal.revision, state="active",
        nodes=(*preserved_nodes, new_node), candidate_refs=(action_ref,),
        waiting_conditions=(), source_refs=roots,
        fact_versions=tuple(merged_facts[key] for key in sorted(merged_facts)),
        parent_plan_revision_ref=VersionedRef(basis.plan_ref, versions[keys[1]].revision))
    checkpoint = replace(old_checkpoint,
        revision=versions[keys[4]].revision + 1, plan_revision=plan.revision,
        next_step=new_node.node_id, state="active",
        last_fact_versions=plan.fact_versions, wait_condition=None)
    dependencies = tuple(AtomKey.from_token(ref) for ref in roots)
    d08 = (GraphWrite(keys[0], plain_v1(goal)),
           GraphWrite(keys[1], plain_v1(plan), dependencies))
    # Re-qualify the existing project against current Sources. The recipe is a
    # fixed installed declaration, so it must not retain task-specific Source edges.
    d10 = (GraphWrite(keys[2], basis.project_value, dependencies),
           *((GraphWrite(keys[3], basis.recipe_value),) if not basis.recipe_current_valid else ()),
           GraphWrite(keys[4], plain_v1(checkpoint)))
    return ArtifactRevisionCandidateV1(
        basis.digest, canonical_digest(plain_v1(adoption)),
        canonical_digest(plain_v1(root)), basis.current_versions,
        goal, plan, checkpoint, d08, d10, basis.predecessor_effect_id,
        ids["effect"], action_ref)
