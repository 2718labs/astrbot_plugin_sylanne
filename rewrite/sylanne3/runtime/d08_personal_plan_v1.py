"""Current D08 personal-plan CAS and finite choice over authenticated originals."""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from typing import TYPE_CHECKING

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d08.execution import (Goal, GoalExecutionProvider, ActionIntent, ActionSchema,
    ActionSchemaRecord, ActionCancellationState, RequiredCheckRegistry, _decode, _decode_goal)
from ..domains.d08.personal_candidate_v1 import SelectCurrentPersonalStepRequestV2, SELECT_OPERATION_V2
from ..domains.d08.personal_plan_v1 import (PLAN_TYPE, DECISION_TYPE, PersonalPlanV1,
    QualifiedPersonalCandidateV1, decode_personal_plan_type_v1, select_personal_step_v2)
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner, owner_grant_key
from ..runtime_contracts import CheckReceipt, VersionedRef, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import (CurrentDomainReadV1, MissingProductionOriginalV1,
    production_read_plan_v1, raw_head_value_v1, waiting_stage_v1)
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .issuers import D11BudgetJobIssuer, D02ResourceIssuer, IssuerAuthorityDenied
from .budget import get_budget_lease, require_budget_family_admissible, BudgetUnavailable

if TYPE_CHECKING:
    from .d11_artifact_draft_content_v1 import ArtifactDraftContentAdoptionV1
    from ..domains.d10 import LifeProject, ActivityRecipe

OBLIGATION_TYPES = ("d08.commitment.v1", "d08.action_intent.v1", "d08.action_outcome.v1")


@dataclass(frozen=True, slots=True)
class ComposeCurrentArtifactGoalPlanRequestV1:
    c02_operation_id: str
    root_registration_ref: str

    def __post_init__(self):
        if any(type(value) is not str or not value or len(value) > 4096
                for value in (self.c02_operation_id, self.root_registration_ref)):
            raise ValueError("artifact task needs the actual C02 and registered root selectors")


ARTIFACT_TASK_PLAN_OPERATION_V1 = "create_artifact_task_plan_v1"


@dataclass(frozen=True, slots=True)
class CreateCurrentArtifactTaskPlanRequestV1:
    task: "ArtifactDraftTaskSelectorV1"

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
        if type(self.task) is not ArtifactDraftTaskSelectorV1:
            raise TypeError("initial task plan accepts only the actual typed task selector")


def artifact_task_initial_plan_operation_id_v1(task):
    CreateCurrentArtifactTaskPlanRequestV1(task)
    return "artifact-initial-plan:" + task.digest[:48]


def artifact_task_initial_plan_candidates_v1(task):
    from ..domains.d01 import FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1
    from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2
    CreateCurrentArtifactTaskPlanRequestV1(task)
    result = []
    for method in (FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1):
        artifact_draft_phase_sequence_v2(method)
        identity = canonical_digest((task, method))[:48]
        result.append((method, "candidate:artifact-method:" + identity, "task:artifact-method:" + identity))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class ProposeCurrentArtifactActionRequestV1(ComposeCurrentArtifactGoalPlanRequestV1):
    pass


@dataclass(frozen=True, slots=True)
class ArtifactGoalPlanCompositionV1:
    """Deterministic candidates rebuilt from adopted C4, never execution authority."""
    adoption: ArtifactDraftContentAdoptionV1
    goal: Goal
    plan: PersonalPlanV1
    project: LifeProject
    recipe: ActivityRecipe
    goal_key: AtomKey
    plan_key: AtomKey
    project_key: AtomKey
    recipe_key: AtomKey


@dataclass(frozen=True, slots=True)
class CreateCurrentPersonalPlanRequestV1:
    source_ref: str
    goal: Goal
    plan: PersonalPlanV1

    def __post_init__(self):
        if (type(self.goal) is not Goal or type(self.plan) is not PersonalPlanV1
                or AtomKey.from_token(self.source_ref).type_name != "memory.source"):
            raise TypeError("personal-plan creation needs the exact typed source/goal/plan")


@dataclass(frozen=True, slots=True)
class ReviseCurrentPersonalPlanRequestV1:
    goal_ref: str
    plan_ref: str
    expected_goal_revision: int
    expected_plan_revision: int
    source_ref: str
    goal: Goal
    plan: PersonalPlanV1

    def __post_init__(self):
        if (type(self.goal) is not Goal or type(self.plan) is not PersonalPlanV1
                or AtomKey.from_token(self.goal_ref).type_name != "d08.goal.v1"
                or AtomKey.from_token(self.plan_ref).type_name != PLAN_TYPE
                or AtomKey.from_token(self.source_ref).type_name != "memory.source"
                or type(self.expected_goal_revision) is not int or self.expected_goal_revision < 1
                or type(self.expected_plan_revision) is not int or self.expected_plan_revision < 1):
            raise ValueError("plan revision requires exact predecessor CAS selectors")


@dataclass(frozen=True, slots=True)
class PersonalStepCandidateV1:
    candidate_ref: str
    node_id: str
    intent: ActionIntent
    action_schema: ActionSchema
    checks: tuple[CheckReceipt, ...]
    check_original_refs: tuple[str, ...]
    quote_version: VersionedRef | None

    def __post_init__(self):
        if (not self.candidate_ref or not self.node_id or type(self.intent) is not ActionIntent
                or type(self.action_schema) is not ActionSchema
                or type(self.checks) is not tuple or any(type(c) is not CheckReceipt for c in self.checks)
                or len(self.checks) != len(self.check_original_refs) or len(self.checks) > 16
                or len(set(self.check_original_refs)) != len(self.check_original_refs)
                or self.quote_version is not None and type(self.quote_version) is not VersionedRef):
            raise ValueError("candidate requires finite typed original-check and quote selectors")
        ActionSchemaRecord.bind(self.intent, self.action_schema)
        if len(canonical_serialize(self).encode("utf-8")) > 16384:
            raise ValueError("candidate exceeds the v3 encoded limit")


@dataclass(frozen=True, slots=True)
class SelectCurrentPersonalStepRequestV1:
    plan_ref: str
    goal_ref: str
    candidates: tuple[PersonalStepCandidateV1, ...]
    value_evaluation_operation_id: str

    def __post_init__(self):
        if (AtomKey.from_token(self.plan_ref).type_name != PLAN_TYPE
                or AtomKey.from_token(self.goal_ref).type_name != "d08.goal.v1"
                or type(self.candidates) is not tuple or not 1 <= len(self.candidates) <= 6
                or any(type(c) is not PersonalStepCandidateV1 for c in self.candidates)
                or len({c.candidate_ref for c in self.candidates}) != len(self.candidates)
                or not self.value_evaluation_operation_id):
            raise ValueError("personal choice requires bounded exact candidates and current value evaluation")
        if len(canonical_serialize(self).encode("utf-8")) > 131072:
            raise ValueError("decision request exceeds its encoded bound")


@dataclass(frozen=True, slots=True)
class SettleCurrentPersonalGoalRequestV1:
    goal_ref: str
    plan_ref: str
    progress_ref: str
    expected_goal_revision: int
    expected_plan_revision: int

    def __post_init__(self):
        for ref, kind in ((self.goal_ref, "d08.goal.v1"), (self.plan_ref, PLAN_TYPE),
                (self.progress_ref, "d10.life_progress.v1")):
            if AtomKey.from_token(ref).type_name != kind:
                raise ValueError("goal settlement requires original typed selectors")
        if any(type(n) is not int or n < 1 for n in (self.expected_goal_revision, self.expected_plan_revision)):
            raise ValueError("goal settlement requires exact expected revisions")


class InstalledD08PersonalPlanReadersV1:
    def __init__(self, *, issuer, resource_issuer, installed_bundle=None):
        if type(issuer) is not D11BudgetJobIssuer or type(resource_issuer) is not D02ResourceIssuer:
            raise TypeError("D08 personal planning requires its installed original issuers")
        self.issuer, self.resource_issuer = issuer, resource_issuer
        self.installed_bundle = installed_bundle

    def obligations(self, db, read, goal_id):
        inventories = {kind: read.complete_inventory(db, kind) for kind in OBLIGATION_TYPES}
        actions = tuple((atom, _decode("d08.action_intent.v1", atom.value))
            for atom in inventories["d08.action_intent.v1"] if atom.revision and atom.value["goal_ref"] == goal_id)
        action_ids = {action.action_id for _, action in actions}
        outcomes = tuple((atom, _decode("d08.action_outcome.v1", atom.value))
            for atom in inventories["d08.action_outcome.v1"] if atom.revision and atom.value["action_id"] in action_ids)
        commitments = tuple(atom for atom in inventories["d08.commitment.v1"] if atom.revision)
        return actions, outcomes, commitments


def _reader(installed_readers):
    if type(installed_readers) is not InstalledD08PersonalPlanReadersV1:
        raise TypeError("exact installed D08 personal-plan readers required")
    return installed_readers


def _plan_keys(frame, request):
    owner = Owner("activity", *frame.envelope.authority.namespace.as_tuple, frame.envelope.identity.activity_id)
    return AtomKey(owner, "d08.goal.v1", request.goal.goal_id), AtomKey(owner, PLAN_TYPE, request.plan.plan_id)


def _facts(db, read, plan):
    observed = []
    for version in plan.fact_versions:
        key = AtomKey.from_token(version.ref)
        if key.type_name in {PLAN_TYPE, "d08.goal.v1", DECISION_TYPE}:
            raise ValueError("control revisions cannot masquerade as new evidence")
        atom = read.head(db, key)
        if atom.revision != version.version:
            raise MissingProductionOriginalV1("current_plan_fact:" + version.ref)
        observed.append(version)
    source_versions = {row.ref: row.version for row in observed}
    if any(source_versions.get(ref, 0) < 1 for ref in plan.source_refs):
        raise ValueError("plan must freeze its actual source revisions")
    read.source_family(db, plan.source_refs)
    return tuple(observed)


def _plan_stage(frame, kind, request, writes=(), **provenance):
    provider = GoalExecutionProvider()
    events = (("d11", "artifact_action_proposal_available"),) if kind == "propose_artifact_draft_action" else (
        (("d10", "artifact_goal_plan_available"),) if kind == "compose_artifact_goal_plan" else
        (("d10", "personal_plan_revision_available"),))
    if kind=="settle_personal_goal" and "task_observation" in provenance and provenance["task_observation"].phase=="partial":
        events=(("d11","artifact_task_wait_registered"),)
    stage = stage_result_v1(frame, "d08", kind, request, writes=writes, provenance=provenance,
        receiver_events=events if writes else (),
        proposal_schema="d08.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
    return verify_d08_personal_plan_stage_v1(stage)


def _initial_artifact_task_plan_basis_v1(db, *, namespace, request, installed_readers):
    from .d11_life_preparation_v1 import _read
    from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
    from .ingress_artifact_task_scope_v1 import (
        ArtifactTaskObjectiveV1, IngressArtifactTaskScopeOriginalV1, _decode as decode_task,
        task_scope_ref_v1, task_objective_goal_v1, require_task_scope_archive_v1,
    )
    readers = _reader(installed_readers)
    if type(request) is not CreateCurrentArtifactTaskPlanRequestV1 or request.task.namespace != namespace:
        raise TypeError("same namespace initial typed task plan selector required")
    task = request.task
    keys = artifact_goal_plan_keys_v1(namespace, c02_operation_id=task.c02_operation_id,
        root_registration_ref=task.root_registration_ref)
    raw_goal = raw_head_value_v1(db, namespace, keys[0])
    if raw_goal is None:
        raise MissingProductionOriginalV1("actual_initial_task_objective_goal")
    goal = _decode_goal(raw_goal)
    objective_ref, raw_objective = require_artifact_task_objective_original_v1(db,
        namespace=namespace, goal_ref=keys[0].token, goal=goal, issuer=readers.issuer)
    objective = decode_task(raw_objective, ArtifactTaskObjectiveV1)
    root_row = _read(db, issuer=readers.issuer, namespace=namespace,
        kind="draft_root_capability", ref=task.root_registration_ref)
    scope_ref = task_scope_ref_v1(task.root_registration_ref)
    scope_row = _read(db, issuer=readers.issuer, namespace=namespace, kind="artifact_task_scope", ref=scope_ref)
    if root_row is None or scope_row is None:
        raise MissingProductionOriginalV1("actual_initial_task_root_scope_originals")
    root = draft_from_wire_v1(root_row[0], DraftRootCapabilityV1)
    scope = decode_task(scope_row[0], IngressArtifactTaskScopeOriginalV1)
    producer = read_adopted_domain_operation_v1(db, namespace, root_row[1])
    if producer is None:
        raise MissingProductionOriginalV1("actual_initial_task_scope_W01_producer")
    require_task_scope_archive_v1(db, namespace=namespace, root=root, producer=producer)
    if (root_row[1] != scope_row[1] or scope.root != root or scope.namespace != namespace
            or scope.task_kind != "draft_then_corrected_revision" or scope.objective_ref != objective_ref
            or scope.objective_digest != canonical_digest(raw_objective)
            or scope.c02_operation_id != task.c02_operation_id
            or objective.initial_c02_operation_id != task.c02_operation_id
            or objective.initial_root_registration_ref != task.root_registration_ref
            or (objective.goal_ref, objective.plan_ref, objective.project_ref, objective.recipe_ref) !=
               tuple(key.token for key in keys) or goal != task_objective_goal_v1(objective)):
        raise ValueError("initial task plan changed its actual Goal/objective/root/Scope producer")
    return keys, goal, objective_ref, objective, scope_ref, scope, root, producer


def read_plan_current_artifact_task_plan_v1(db, *, namespace, request, installed_readers):
    from ..domains.d03.self_perspective import self_mapping_key
    keys, _, objective_ref, objective, scope_ref, scope, _, producer = _initial_artifact_task_plan_basis_v1(
        db, namespace=namespace, request=request, installed_readers=installed_readers)
    return production_read_plan_v1((), (owner_grant_key(*namespace.as_tuple), keys[0], keys[1],
        AtomKey.from_token(objective.source_ref), self_mapping_key(namespace), AtomKey.from_token(request.task.cycle_job_ref)),
        (objective.source_ref,), (objective_ref, request.task.root_registration_ref, scope_ref,
            scope.c1_intent_ref, "d10-current:" + producer["original_digest"][:48]))


def stage_create_current_artifact_task_plan_in_transaction_v1(db, *, frame, request, installed_readers):
    from ..domains.d03.self_perspective import SelfIdentityMapping, self_mapping_key
    from .d11_artifact_draft_contract_v1 import RECIPE_ID
    from ..domains.d08.personal_plan_v1 import PlanNodeV2
    from .d11_offline_originals_v1 import _utc
    readers = _reader(installed_readers)
    if type(request) is not CreateCurrentArtifactTaskPlanRequestV1:
        raise TypeError("exact initial artifact TaskPlan request required")
    try:
        read = CurrentDomainReadV1(frame)
        read.check(db)
        ns = frame.envelope.authority.namespace
        keys, goal, objective_ref, objective, scope_ref, scope, root, producer = _initial_artifact_task_plan_basis_v1(
            db, namespace=ns, request=request, installed_readers=readers)
        if (frame.envelope.identity.operation_id != artifact_task_initial_plan_operation_id_v1(request.task)
                or frame.envelope.identity.activity_id != keys[0].owner.subject
                or frame.envelope.authority.purpose != "consolidation"):
            raise ValueError("initial task plan changed its formal operation/activity/purpose")
        atom = read.head(db, keys[0], required=True)
        if atom.revision != 1 or atom.value != plain_v1(goal) or read.head(db, keys[1]).revision:
            raise ValueError("initial task plan cannot replace an adopted Goal/Plan")
        source = read.head(db, objective.source_ref, required=True)
        if (source.revision, canonical_digest(source.value)) != (objective.source_revision, objective.source_digest):
            raise MissingProductionOriginalV1("current_unchanged_initial_task_plan_source")
        mapping_atom = read.head(db, self_mapping_key(ns), required=True)
        mapping = SelfIdentityMapping(**mapping_atom.value)
        if (mapping.status != "active" or mapping.persona_ref != "persona:" + ns.persona_id
                or mapping.self_entity_ref != frame.envelope.authority.actor):
            raise MissingProductionOriginalV1("actual_current_initial_task_plan_Self_mapping")
        guard = frame.owner_guard
        if (root.owner_grant_ref, root.owner_grant_revision, root.owner_grant_digest) != (
                guard.grant_ref, guard.grant_revision, guard.grant_digest):
            raise MissingProductionOriginalV1("actual_current_initial_task_plan_Owner")
        require_budget_family_admissible(db, frame.envelope.parent_budget_lease_ref)
        grant = readers.issuer.current_budget_grant(db, frame.envelope.parent_budget_lease_ref)
        deadline = min(objective.valid_until_utc, _utc(root.valid_until_utc).timestamp(), grant.valid_until_utc)
        if not frame.now_utc < deadline or frame.envelope.deadline_utc > deadline:
            raise MissingProductionOriginalV1("original_initial_task_plan_deadline_not_renewed")
        read.original(objective_ref, kind="d11.life_artifact_task_objective", digest=canonical_digest(plain_v1(objective)))
        read.original(scope_ref, kind="d11.life_artifact_task_scope", digest=canonical_digest(plain_v1(scope)))
        read.original(root.registration_ref, kind="d11.life_draft_root_capability", digest=canonical_digest(plain_v1(root)))
        read.original(scope.c1_intent_ref, kind="d11.life_c1_task_intent", digest=scope.c1_intent_digest)
        read.original("d10-current:" + producer["original_digest"][:48],
            kind="d10.current-derive_ingress_artifact_task_scope_v1", digest=producer["original_digest"])
        read.source_family(db, (objective.source_ref,))
        candidates = artifact_task_initial_plan_candidates_v1(request.task)
        nodes = tuple(PlanNodeV2(node_id=node_id, owner_ref=mapping.persona_ref, depends_on=(),
            action_kind=RECIPE_ID, success_predicate=goal.satisfaction_predicate,
            cancellation_point=True, compensation_ref=None, resource_ref=root.registration_ref,
            observable_postconditions=(goal.satisfaction_predicate,)) for _, _, node_id in candidates)
        facts = (VersionedRef(source.key.token, source.revision), VersionedRef(mapping_atom.key.token, mapping_atom.revision))
        plan = PersonalPlanV1(keys[1].name, 1, keys[0].token, atom.revision, "active", mapping.persona_ref,
            nodes, tuple(candidate for _, candidate, _ in candidates), ("current_final_admission_required",), (),
            goal.abandon_conditions, (objective.source_ref,), facts, None,
            method_candidates=tuple((candidate, method) for method, candidate, _ in candidates))
        _facts(db, read, plan)
        return _plan_stage(frame, ARTIFACT_TASK_PLAN_OPERATION_V1, request,
            (GraphWrite(keys[1], plain_v1(plan), (source.key, mapping_atom.key)),),
            actual_fact_versions=facts)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d08", ARTIFACT_TASK_PLAN_OPERATION_V1, request, missing)


def stage_create_current_personal_plan_in_transaction_v1(db, *, frame, request, installed_readers):
    _reader(installed_readers)
    if type(request) is not CreateCurrentPersonalPlanRequestV1:
        raise TypeError("exact personal-plan creation request required")
    try:
        read = CurrentDomainReadV1(frame)
        read.check(db)
        goal_key, plan_key = _plan_keys(frame, request)
        if (request.goal.revision != 1 or request.goal.state != "active" or request.goal.progress_refs
                or request.plan.revision != 1 or request.plan.state not in {"active", "waiting"}
                or request.plan.goal_ref != goal_key.token or request.plan.goal_revision != 1
                or request.plan.actor_ref != "persona:" + frame.envelope.authority.namespace.persona_id
                or request.source_ref not in request.goal.reason_refs or request.source_ref not in request.plan.source_refs
                or any(node.carried_forward_verified or node.pending_original_effects for node in request.plan.nodes)):
            raise ValueError("new goal/plan must begin as a genuine unexecuted source-bound proposal")
        if read.head(db, goal_key).revision or read.head(db, plan_key).revision:
            raise ValueError("new personal goal/plan requires absent heads")
        _facts(db, read, request.plan)
        dependencies = tuple(AtomKey.from_token(ref) for ref in request.plan.source_refs)
        return _plan_stage(frame, "create_personal_plan", request,
            (GraphWrite(goal_key, plain_v1(request.goal)), GraphWrite(plan_key, plain_v1(request.plan), dependencies)),
            actual_fact_versions=request.plan.fact_versions)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d08", "create_personal_plan", request, missing)


def stage_revise_current_personal_plan_in_transaction_v1(db, *, frame, request, installed_readers):
    readers = _reader(installed_readers)
    if type(request) is not ReviseCurrentPersonalPlanRequestV1:
        raise TypeError("exact personal-plan revision request required")
    try:
        read = CurrentDomainReadV1(frame)
        read.check(db)
        goal_atom, plan_atom = read.head(db, request.goal_ref), read.head(db, request.plan_ref)
        if (goal_atom.revision != request.expected_goal_revision
                or plan_atom.revision != request.expected_plan_revision):
            raise ValueError("personal goal/plan CAS is stale")
        old_goal = _decode_goal(goal_atom.value)
        old_plan = decode_personal_plan_type_v1(PLAN_TYPE, plan_atom.value)
        if (request.goal.goal_id != old_goal.goal_id or request.plan.plan_id != old_plan.plan_id
                or request.plan.goal_ref != request.goal_ref or old_plan.goal_ref != request.goal_ref
                or request.goal.revision != old_goal.revision + 1
                or request.plan.revision != old_plan.revision + 1
                or request.plan.goal_revision != request.goal.revision
                or request.plan.parent_plan_revision_ref != VersionedRef(request.plan_ref, plan_atom.revision)
                or request.plan.actor_ref != old_plan.actor_ref
                or request.source_ref not in request.plan.source_refs
                or request.source_ref not in request.goal.reason_refs
                or request.goal.progress_refs != old_goal.progress_refs
                or request.goal.state == "satisfied" and old_goal.state != "satisfied"
                or request.plan.state == "satisfied" and old_plan.state != "satisfied"
                or old_goal.state in {"satisfied", "abandoned", "superseded"} and request.goal.state not in {
                    old_goal.state, "abandoned", "superseded"}):
            raise ValueError("revision cannot replace identities, origins or already adopted progress")
        facts = _facts(db, read, request.plan)
        if not {row.ref for row in old_plan.fact_versions} <= {row.ref for row in facts}:
            raise ValueError("replanning cannot discard its previously observed fact identities")
        if {row.ref: row.version for row in facts} == {row.ref: row.version for row in old_plan.fact_versions}:
            return waiting_stage_v1(frame, "d08", "revise_personal_plan", request,
                MissingProductionOriginalV1("new_plan_fact_or_original_effect_observation"))
        actions, outcomes, commitments = readers.obligations(db, read, old_goal.goal_id)
        if request.goal.satisfaction_predicate != old_goal.satisfaction_predicate:
            raise ValueError("plan revision cannot replace the established success standard")
        old_nodes = {node.node_id: node for node in old_plan.nodes}
        new_nodes = {node.node_id: node for node in request.plan.nodes}
        for _, action in actions:
            touched = tuple(node for node in old_plan.nodes if node.action_kind == action.action_kind
                and node.success_predicate == action.success_predicate)
            for node in touched:
                successor = new_nodes.get(node.node_id)
                if (successor is None or successor.action_kind != node.action_kind
                        or successor.success_predicate != node.success_predicate
                        or successor.observable_postconditions != node.observable_postconditions):
                    raise ValueError("replanning must carry the original effect and its postconditions")
        known = {outcome.effect_id for _, outcome in outcomes
            if outcome.result_level == "completed_verified" and not outcome.unknown_effects}
        pending = {outcome.effect_id for _, outcome in outcomes
            if outcome.result_level in {"accepted", "running", "partially_observed", "unknown"} or outcome.unknown_effects}
        carried = {ref for node in request.plan.nodes for ref in node.carried_forward_verified}
        unresolved = {ref for node in request.plan.nodes for ref in node.pending_original_effects}
        if known != carried or pending != unresolved:
            raise ValueError("revision must retain exact verified and unresolved effects")
        actions_by_id = {action.action_id: action for _, action in actions}
        for node in request.plan.nodes:
            matching = {outcome.effect_id for _, outcome in outcomes
                if actions_by_id[outcome.action_id].action_kind == node.action_kind
                and actions_by_id[outcome.action_id].success_predicate == node.success_predicate}
            if not (set(node.carried_forward_verified) | set(node.pending_original_effects)) <= matching:
                raise ValueError("carried effect does not belong to this original plan node")
        for node in request.plan.nodes:
            previous = old_nodes.get(node.node_id)
            if previous is not None and not set(previous.carried_forward_verified) <= set(node.carried_forward_verified):
                raise ValueError("revision cannot discard a previous verified effect")
        writes = (GraphWrite(goal_atom.key, plain_v1(request.goal)), GraphWrite(plan_atom.key, plain_v1(request.plan),
            tuple(AtomKey.from_token(ref) for ref in request.plan.source_refs)))
        return _plan_stage(frame, "revise_personal_plan", request, writes,
            actual_fact_versions=facts, carried_effects=tuple(sorted(known)), pending_effects=tuple(sorted(pending)),
            retained_commitment_versions=tuple((atom.key.token, atom.revision) for atom in commitments))
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d08", "revise_personal_plan", request, missing)


def _candidate_keys(frame, candidate):
    owner = Owner("activity", *frame.envelope.authority.namespace.as_tuple, frame.envelope.identity.activity_id)
    binding = ActionSchemaRecord.bind(candidate.intent, candidate.action_schema)
    return (AtomKey(owner, "d08.action_intent.v1", candidate.intent.action_id),
        AtomKey(owner, "d08.action_schema.v1", binding.schema_ref),
        AtomKey(owner, "d08.action_cancellation.v1", candidate.intent.action_id))


def stage_select_current_personal_step_in_transaction_v1(db, *, frame, request, installed_readers):
    readers = _reader(installed_readers)
    if type(request) is not SelectCurrentPersonalStepRequestV1:
        raise TypeError("exact current choice request required")
    try:
        read = CurrentDomainReadV1(frame)
        read.check(db)
        plan_atom, goal_atom = read.head(db, request.plan_ref, required=True), read.head(db, request.goal_ref, required=True)
        plan, goal = decode_personal_plan_type_v1(PLAN_TYPE, plan_atom.value), _decode_goal(goal_atom.value)
        if (plan.goal_ref != request.goal_ref or plan.goal_revision != goal.revision
                or goal.state != "active" or plan.state != "active"):
            raise MissingProductionOriginalV1("current_active_personal_goal_and_plan")
        _facts(db, read, plan)
        actions, outcomes, commitments = readers.obligations(db, read, goal.goal_id)
        evaluation = read_adopted_domain_operation_v1(db, frame.envelope.authority.namespace, request.value_evaluation_operation_id)
        if evaluation is None or (evaluation["domain"], evaluation["operation_kind"]) != ("d01", "evaluate_values"):
            raise MissingProductionOriginalV1("actual_current_d01_value_evaluation")
        for version in evaluation["read_versions"]:
            if read.head(db, version.key).revision != version.revision:
                raise MissingProductionOriginalV1("current_d01_preference_revision")
        values = evaluation["payload"]["provenance"]["evaluation"]
        candidate_ids = {c.candidate_ref for c in request.candidates}
        classified = set(values["preferred"]) | set(values["rejected"]) | set(values["unresolved"])
        if classified != candidate_ids:
            raise ValueError("D01 evaluation must describe the exact current six-or-fewer candidates")
        edges = {(a, b) for a in values["preferred"]
            for b in (*values["unresolved"], *values["rejected"]) if a != b}
        # Retain each actually applicable value rule separately. Opposing
        # rules can produce a real SCC; a flattened support count cannot.
        for rule in evaluation["payload"]["provenance"]["persona_view"]["values"]:
            supported = {ref for ref in rule["supports_candidates"] if ref in candidate_ids
                and rule["label"] in values["reasons"][ref]}
            opposed = {ref for ref in rule["rejects_candidates"] if ref in candidate_ids
                and rule["label"] in values["reasons"][ref]}
            edges.update((a, b) for a in supported for b in opposed if a != b)
        edges = tuple(sorted(edges))
        nodes = {node.node_id: node for node in plan.nodes}
        completed = {node.node_id for node in plan.nodes if node.carried_forward_verified}
        qualified = []
        for candidate in request.candidates:
            intent, node = candidate.intent, nodes[candidate.node_id]
            if (intent.identity != frame.envelope.identity or intent.goal_ref != goal.goal_id
                    or intent.action_kind != node.action_kind or intent.success_predicate != node.success_predicate
                    or set(intent.source_refs) != set(frame.envelope.source_qualification.source_refs)
                    or candidate.candidate_ref not in plan.candidate_refs or not set(node.depends_on) <= completed):
                raise ValueError("candidate differs from the adopted ready plan node and actual operation")
            read.source_family(db, intent.source_refs, purpose=intent.purpose)
            for check, ref in zip(candidate.checks, candidate.check_original_refs, strict=True):
                read.original(ref, digest=canonical_digest(check))
                for version in check.input_versions:
                    try:
                        key = AtomKey.from_token(version.ref)
                    except ValueError:
                        read.original(version.ref)
                    else:
                        if read.head(db, key).revision != version.version:
                            raise MissingProductionOriginalV1("current_candidate_check_inputs")
            registry = RequiredCheckRegistry()
            registry.register(candidate.action_schema)
            decision = registry.qualify(intent, candidate.checks, now=frame.now_utc)
            status = "eligible" if decision.status == "qualified" else (
                "REJECTED" if decision.status == "rejected" else "REQUIRED_CHECK_UNRESOLVED")
            prior_actions = [action for _, action in actions if action.target_ref == intent.target_ref
                and action.action_kind == intent.action_kind]
            prior_ids = {action.action_id for action in prior_actions}
            pending = tuple(sorted({outcome.effect_id for _, outcome in outcomes if outcome.action_id in prior_ids
                and (outcome.result_level not in {"completed_verified", "failed_verified", "not_dispatched"} or outcome.unknown_effects)}))
            verified = tuple(sorted({outcome.effect_id for _, outcome in outcomes if outcome.action_id in prior_ids
                and outcome.result_level == "completed_verified" and not outcome.unknown_effects}))
            if pending:
                status = "WAIT_ORIGINAL_EFFECT"
            elif verified and node.carried_forward_verified:
                status = "REJECTED"
            quote = None
            if status == "eligible":
                if candidate.quote_version is None:
                    status = "WAIT_COST_EVIDENCE"
                else:
                    quote_envelope = replace(frame.envelope, version_guard=replace(frame.envelope.version_guard,
                        resource_lease_versions=(candidate.quote_version,)))
                    try:
                        quote = readers.resource_issuer.qualified_quote(quote_envelope, db, now_utc=frame.now_utc)
                        if quote.resource_ref != node.resource_ref:
                            raise ValueError("candidate quote names another registered plan resource")
                        ceilings = dict(node.cost_ceiling)
                        if any(amount > ceilings.get(dim, -1) for dim, amount in quote.ceiling.items()):
                            raise ValueError("candidate cost exceeds its frozen plan ceiling")
                        require_budget_family_admissible(db, quote.parent_budget_lease_ref)
                        lease = get_budget_lease(db, quote.parent_budget_lease_ref)
                        if any(lease.available(dim) < amount for dim, amount in quote.ceiling.items()):
                            status = "WAIT_BUDGET"
                    except IssuerAuthorityDenied:
                        status = "WAIT_COST_EVIDENCE"
                    except BudgetUnavailable:
                        status = "WAIT_BUDGET"
            if candidate.candidate_ref in values["rejected"]:
                status = "REJECTED"
            deadlines, established = [], False
            for atom in commitments:
                value = atom.value
                if (value["counterparty_ref"] == intent.target_ref and atom.valid
                        and value["establishment_state"] in {"communicated", "acknowledged"}
                        and value["fulfillment_state"] not in {"fulfilled", "withdrawn"}):
                    established = True
                    if value["deadline_ref"] is not None:
                        deadline = read.head(db, value["deadline_ref"], required=True)
                        if "deadline_utc" not in deadline.value:
                            raise MissingProductionOriginalV1("actual_established_deadline_time")
                        deadlines.append(deadline.value["deadline_utc"])
            semantic = (intent.target_ref, intent.action_kind, intent.purpose, intent.parameters_digest,
                intent.success_predicate, intent.effect_scope, intent.schema_id)
            qualified.append(QualifiedPersonalCandidateV1(candidate.candidate_ref, intent.action_id, node.node_id,
                canonical_digest(semantic), status, {"internal": 0, "reversible": 1, "limited": 2, "irreversible": 3}[intent.risk_class],
                intent.success_predicate in node.observable_postconditions, min(deadlines) if deadlines else None,
                quote.quote_id if quote is not None else None, pending, verified,
                numeric_discriminator_unresolved="NUMERIC_DISCRIMINATOR_UNRESOLVED" in values["reasons"].get(candidate.candidate_ref, ()),
                recovery_branch=intent.action_kind in {"ask", "narrow", "wait"}, established_commitment=established))
        method_strategy = evaluation["payload"]["provenance"].get("method_strategy")
        if plan.method_candidates:
            if method_strategy is None:
                raise MissingProductionOriginalV1("actual_current_d01_method_strategy")
            from ..domains.d01.production_operations_v1 import MethodStrategyProjectionV1
            from ..domains.d01 import PersonaPlan, _validate_persona_plan, _persona_block, _value_rule
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            from .d01_production_operations_v1 import current_method_strategy_projection_v1
            from ..runtime_contracts import NamespaceId
            prior = decode_typed_production_value_v1(method_strategy, MethodStrategyProjectionV1)
            if prior.plan_head != GraphVersion(plan_atom.key, plan_atom.revision):
                raise MissingProductionOriginalV1("current_exact_method_strategy_plan")
            persona_atom = read.head(db, prior.persona_head.key, required=True)
            _validate_persona_plan(persona_atom.value)
            raw = persona_atom.value
            current_persona = PersonaPlan(**{**raw, "namespace": NamespaceId(**raw["namespace"]),
                "blocks": tuple(_persona_block(row) for row in raw["blocks"]),
                "values": tuple(_value_rule(row) for row in raw["values"])})
            current = current_method_strategy_projection_v1(db, read, persona_plan=current_persona,
                persona_head=GraphVersion(persona_atom.key, persona_atom.revision), plan_head=prior.plan_head,
                candidate_refs=tuple(sorted(candidate_ids)), condition_heads=prior.condition_heads,
                condition_query_epoch=prior.condition_query_epoch)
            if current != prior:
                raise MissingProductionOriginalV1("current_complete_method_strategy_projection")
            eligible_refs = {candidate.candidate_ref for candidate in qualified if candidate.hard_status == "eligible"}
            edges = tuple(sorted(set(edges) | {(a, b) for a, b in current.preference_edges
                if a in eligible_refs and b in eligible_refs}))
        decision_key = personal_decision_key_v1(frame, request.plan_ref)
        decision_id = decision_key.name
        record = select_personal_step_v2(decision_id=decision_id, candidates=tuple(qualified), preference_edges=edges,
            source_refs=plan.source_refs, read_versions=tuple(VersionedRef(v.key.token, v.revision) for v in frame.snapshot.versions))
        if read.head(db, decision_key).revision:
            raise ValueError("one cycle cannot replace its immutable choice")
        writes = [GraphWrite(decision_key, plain_v1(record))]
        if record.chosen_action_ref is not None:
            candidate = next(c for c in request.candidates if c.intent.action_id == record.chosen_action_ref)
            action_key, schema_key, cancel_key = _candidate_keys(frame, candidate)
            if any(read.head(db, key).revision for key in (action_key, schema_key, cancel_key)):
                raise ValueError("a choice cannot replay an adopted action/effect")
            schema = ActionSchemaRecord.bind(candidate.intent, candidate.action_schema)
            cancel = ActionCancellationState.for_action(candidate.intent, state="active", actor=frame.envelope.authority.actor,
                source_refs=frame.envelope.source_qualification.source_refs, operation_id=frame.envelope.identity.operation_id)
            writes.extend((GraphWrite(action_key, plain_v1(candidate.intent)), GraphWrite(schema_key, plain_v1(schema)),
                GraphWrite(cancel_key, plain_v1(cancel))))
        provider = GoalExecutionProvider()
        provenance = {"decision": record, "candidate_evidence": tuple(qualified), "value_evaluation": evaluation["original_digest"]}
        if plan.method_candidates:
            provenance["method_strategy"] = current
        stage = stage_result_v1(frame, "d08", "select_personal_step", request, writes=tuple(writes),
            provenance=provenance,
            receiver_events=(("d11", "personal_step_requires_current_final_admission"),) if record.chosen_action_ref else
                (("d11", "personal_step_wait_condition_required"),),
            proposal_schema="d08.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
        provider.validate(stage.proposals[0], frame.snapshot)
        return verify_d08_personal_plan_stage_v1(stage)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d08", "select_personal_step", request, missing)


def stage_settle_current_personal_goal_in_transaction_v1(db, *, frame, request, installed_readers):
    readers = _reader(installed_readers)
    if type(request) is not SettleCurrentPersonalGoalRequestV1:
        raise TypeError("exact personal goal settlement required")
    from .d10_project_checkpoint_v1 import InstalledD10ProjectReadersV1
    try:
        read = CurrentDomainReadV1(frame)
        read.check(db)
        goal_atom, plan_atom = read.head(db, request.goal_ref, required=True), read.head(db, request.plan_ref, required=True)
        goal, plan = _decode_goal(goal_atom.value), decode_personal_plan_type_v1(PLAN_TYPE, plan_atom.value)
        if (goal_atom.revision, plan_atom.revision) != (request.expected_goal_revision, request.expected_plan_revision):
            raise ValueError("goal satisfaction CAS is stale")
        evidence = InstalledD10ProjectReadersV1(issuer=readers.issuer).read_effect(db, frame, request.progress_ref)
        if plan.goal_ref != request.goal_ref or evidence.goal_id != goal.goal_id:
            raise ValueError("actual effect belongs to another adopted goal")
        if request.progress_ref in goal.progress_refs and goal.state == "satisfied":
            return _plan_stage(frame, "settle_personal_goal", request, duplicate=True)
        if (goal.satisfaction_predicate.kind,goal.satisfaction_predicate.observation_provider)==("domain_state","d08.artifact_task_objective.v1"):
            from .d10_project_checkpoint_v1 import _artifact_project_original_v1,CREATE_TASK_PROJECT_OPERATION_V1
            project_original=_artifact_project_original_v1(db,namespace=frame.envelope.authority.namespace,project_ref=evidence.project_ref)
            if project_original['operation_kind']==CREATE_TASK_PROJECT_OPERATION_V1:
                from .artifact_task_observer_v1 import stage_observe_artifact_task_v2
                from .d11_artifact_draft_content_v1 import bind_artifact_method_settlement_stage_v2
                observed=stage_observe_artifact_task_v2(db,frame=frame,request=request,readers=readers,
                    goal_atom=goal_atom,plan_atom=plan_atom,goal=goal,plan=plan,evidence=evidence)
                return bind_artifact_method_settlement_stage_v2(db,frame=frame,request=request,stage=observed,issuer=readers.issuer)
            from .artifact_task_observer_v1 import stage_observe_artifact_task_v1
            return stage_observe_artifact_task_v1(db,frame=frame,request=request,readers=readers,
                goal_atom=goal_atom,plan_atom=plan_atom,goal=goal,plan=plan,evidence=evidence)
        if goal.satisfaction_predicate != evidence.success_predicate:
            raise MissingProductionOriginalV1("registered_goal_postcondition_for_actual_effect")
        if not evidence.completed_verified:
            raise MissingProductionOriginalV1("actual_complete_goal_effect_observation")
        updated_goal = replace(goal, revision=goal.revision + 1, state="satisfied",
            progress_refs=tuple(dict.fromkeys((*goal.progress_refs, request.progress_ref))))
        updated_plan = replace(plan, revision=plan.revision + 1, goal_revision=updated_goal.revision, state="satisfied",
            parent_plan_revision_ref=VersionedRef(request.plan_ref, plan_atom.revision))
        return _plan_stage(frame, "settle_personal_goal", request,
            (GraphWrite(goal_atom.key, plain_v1(updated_goal)), GraphWrite(plan_atom.key, plain_v1(updated_plan))),
            actual_effect=evidence)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d08", "settle_personal_goal", request, missing)


def require_artifact_task_objective_original_v1(db, *, namespace, goal_ref, goal, issuer):
    """An unfinished artifact Goal needs its real prospective registered producer."""
    from .d11_life_preparation_v1 import _read
    predicate = goal.satisfaction_predicate
    if (predicate.kind, predicate.observation_provider) != ("domain_state", "d08.artifact_task_objective.v1"):
        raise MissingProductionOriginalV1("registered_unfinished_artifact_objective_not_one_shot_revival")
    parameters = dict(predicate.parameters)
    if set(parameters) != {"objective_ref", "objective_digest"}:
        raise ValueError("artifact objective predicate has another closed binding")
    row = _read(db, issuer=issuer, namespace=namespace, kind="artifact_task_objective",
        ref=parameters["objective_ref"])
    if row is None:
        raise MissingProductionOriginalV1("actual_initial_artifact_task_objective")
    objective, producer = row
    original = read_adopted_domain_operation_v1(db, namespace, producer)
    if (canonical_digest(objective) != parameters["objective_digest"]
            or objective.get("schema") != "d08.artifact-task-objective.v1"
            or objective.get("goal_ref") != goal_ref
            or objective.get("completion_rule") != "draft_then_corrected_revision"
            or original is None or (original["domain"], original["operation_kind"]) !=
                ("d10", "derive_ingress_artifact_task_scope_v1")
            or original["payload"]["provenance"].get("artifact_task_objective") != objective):
        raise ValueError("artifact objective lacks its exact prospective installed producer")
    return parameters["objective_ref"], objective


def artifact_goal_plan_keys_v1(namespace, *, c02_operation_id, root_registration_ref):
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v1
    ids = artifact_draft_file_ids_v1(namespace, c02_operation_id=c02_operation_id,
        root_registration_ref=root_registration_ref)
    activity = Owner("activity", *namespace.as_tuple, ids["activity_id"])
    persona = Owner("persona", *namespace.as_tuple)
    return (AtomKey(activity, "d08.goal.v1", ids["goal"]), AtomKey(activity, PLAN_TYPE, ids["plan"]),
        AtomKey(persona, "d10.life_project.v1", ids["project"]), AtomKey.from_token(ids["recipe_ref"]))


def artifact_draft_action_keys_v1(namespace, *, c02_operation_id, root_registration_ref):
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v1
    ids = artifact_draft_file_ids_v1(namespace, c02_operation_id=c02_operation_id,
        root_registration_ref=root_registration_ref)
    owner = Owner("activity", *namespace.as_tuple, ids["activity_id"])
    action_id = ids["action"]
    return AtomKey(owner, "d08.action_intent.v1", action_id), AtomKey(owner, "d08.action_cancellation.v1", action_id)


def compose_current_artifact_goal_plan_v1(db, *, frame, request, installed_readers):
    """Freeze one explicit target after actual C4 adoption; no value-choice shortcut."""
    from ..domains.d03.self_perspective import SelfIdentityMapping, self_mapping_key
    from ..domains.d08.execution import GoalPredicate
    from ..domains.d08.personal_plan_v1 import PlanNodeV2
    from ..domains.d10 import LifeProject, ActivityRecipe
    from ..memory_types import SourceRecord
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v1, MAX_TEXT_BYTES
    from .d11_artifact_draft_content_v1 import (ArtifactDraftContentAdoptionV1,
        read_current_adopted_artifact_draft_content_v1)
    from .d11_artifact_draft_contract_v1 import (DraftActivityScopeV1, DraftRootCapabilityV1,
        RECIPE_ID, POSTCONDITION_ID, draft_from_wire_v1)
    from .d11_life_preparation_v1 import _read
    from .d11_offline_originals_v1 import _utc
    from .d11_life_contract_v1 import draft_artifact_ref_v1
    if type(request) not in {ComposeCurrentArtifactGoalPlanRequestV1, ProposeCurrentArtifactActionRequestV1}:
        raise TypeError("closed artifact composer selector required")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    adoption = read_current_adopted_artifact_draft_content_v1(db, frame=frame,
        c02_operation_id=request.c02_operation_id, root_registration_ref=request.root_registration_ref,
        installed_readers=installed_readers)
    if (type(adoption) is not ArtifactDraftContentAdoptionV1
            or adoption.selector.namespace != ns
            or adoption.selector.c02_operation_id != request.c02_operation_id
            or adoption.selector.root_registration_ref != request.root_registration_ref):
        raise ValueError("artifact composer lost its actual adopted task binding")
    ids = artifact_draft_file_ids_v1(ns, c02_operation_id=request.c02_operation_id,
        root_registration_ref=request.root_registration_ref)
    if (frame.envelope.identity.activity_id != ids["activity_id"]
            or frame.envelope.authority.purpose != "consolidation"):
        raise ValueError("artifact task belongs to another current activity")
    scope_original = _read(db, issuer=installed_readers.issuer, namespace=ns,
        kind="activity_scope", ref=adoption.activity_scope_ref)
    root_original = _read(db, issuer=installed_readers.issuer, namespace=ns,
        kind="draft_root_capability", ref=request.root_registration_ref)
    if scope_original is None or root_original is None:
        raise MissingProductionOriginalV1("actual_adopted_content_scope_and_registered_root")
    scope = draft_from_wire_v1(scope_original[0], DraftActivityScopeV1)
    root = draft_from_wire_v1(root_original[0], DraftRootCapabilityV1)
    read.original(adoption.activity_scope_ref, kind="d11.life_activity_scope", digest=adoption.activity_scope_digest)
    read.original(request.root_registration_ref, kind="d11.life_draft_root_capability", digest=canonical_digest(plain_v1(root)))
    if (canonical_digest(plain_v1(scope)) != adoption.activity_scope_digest
            or scope_original[1] != adoption.adoption_operation_id
            or scope.actor_ref != frame.envelope.authority.actor or scope.activity_id != ids["activity_id"]
            or scope.c02_original_ref != request.c02_operation_id or scope.source != adoption.task_source
            or scope.root_registration_ref != root.registration_ref
            or scope.root_registration_digest != canonical_digest(plain_v1(root))
            or scope.parent_budget_lease_ref != frame.envelope.parent_budget_lease_ref
            or (scope.owner_grant_ref, scope.owner_grant_revision, scope.owner_grant_digest) !=
               (frame.owner_guard.grant_ref, frame.owner_guard.grant_revision, frame.owner_guard.grant_digest)
            or root.filenames != (adoption.target.filename,) or adoption.target.mode != "create"
            or adoption.target.root_registration_ref != root.registration_ref
            or adoption.target.root_registration_digest != canonical_digest(plain_v1(root))
            or adoption.target.root_resource_id != root.resource_id
            or adoption.target.root_identity != root.root_identity or adoption.target.max_bytes > root.max_bytes):
        raise ValueError("artifact composer changed its signed scope, root or unique registered target")
    deadline = _utc(adoption.original_deadline_utc).timestamp()
    if not frame.now_utc < min(deadline, _utc(scope.valid_until_utc).timestamp(), _utc(root.valid_until_utc).timestamp()):
        raise MissingProductionOriginalV1("unexpired_original_artifact_task_scope")
    mapping_atom = read.head(db, self_mapping_key(ns), required=True)
    mapping = SelfIdentityMapping(**mapping_atom.value)
    if (mapping.status != "active" or mapping.self_entity_ref != scope.actor_ref
            or mapping.persona_ref != "persona:" + ns.persona_id):
        raise MissingProductionOriginalV1("actual_current_artifact_self_persona_mapping")
    roots = tuple(dict.fromkeys((adoption.task_source.ref, *adoption.content.source_refs)))
    task = read.head(db, adoption.task_source.ref, required=True)
    if (task.revision != adoption.task_source.revision or canonical_digest(task.value) != adoption.task_source.digest
            or root.source_ref != adoption.task_source.ref):
        raise ValueError("artifact goal changed its signed original task Source")
    if adoption.content.content.ref not in roots:
        raise ValueError("authored content must retain its own current Source qualification")
    for audience in frame.envelope.authority.audience:
        for purpose in ("context", "consolidation"):
            read.source_family(db, roots, audience=audience, purpose=purpose)
    source = read.head(db, adoption.content.content.ref, required=True)
    record = SourceRecord.from_dict(source.value)
    content_bytes = record.text.encode("utf-8")
    if (source.revision != adoption.content.content.revision
            or canonical_digest(source.value) != adoption.content.content.digest
            or record.source_kind != "authored" or record.assertion_status != "unknown"
            or record.speaker_id != mapping.persona_ref or record.recorded_at != adoption.recorded_at_utc
            or not 1 <= len(content_bytes) <= MAX_TEXT_BYTES
            or len(content_bytes) != adoption.content.content_length
            or hashlib.sha256(content_bytes).hexdigest() != adoption.content.content_digest):
        raise ValueError("artifact goal requires the exact adopted authored bytes and self provenance")
    read.original(adoption.paid_original_ref, digest=adoption.paid_original_digest)
    read.original(adoption.result_original_ref, digest=adoption.result_original_digest)
    goal_key, plan_key, project_key, recipe_key = artifact_goal_plan_keys_v1(ns,
        c02_operation_id=request.c02_operation_id, root_registration_ref=request.root_registration_ref)
    predicate = GoalPredicate("artifact_verified", POSTCONDITION_ID, (
        ("artifact_ref", draft_artifact_ref_v1(ns, ids["effect"])),
        ("content_digest", adoption.content.content_digest), ("target_scope_digest", adoption.target.digest),
        ("build_digest", adoption.postcondition_build_digest)), adoption.recorded_at_utc, deadline)
    facts = tuple(VersionedRef(ref, read.head(db, ref, required=True).revision) for ref in (*roots, mapping_atom.key.token))
    goal = Goal(ids["goal"], 1, "active", predicate, roots,
        (request.root_registration_ref, adoption.paid_original_ref, adoption.result_original_ref),
        None, ("task_cancelled", "source_or_owner_revoked", "original_deadline_expired"), ())
    prior=read.head(db,goal_key)
    if prior.revision:
        original_goal=_decode_goal(prior.value)
        objective_ref,objective=require_artifact_task_objective_original_v1(db,namespace=ns,
            goal_ref=goal_key.token,goal=original_goal,issuer=installed_readers.issuer)
        read.original(objective_ref,kind="d11.life_artifact_task_objective",digest=canonical_digest(objective))
        from .ingress_artifact_task_scope_v1 import ArtifactTaskObjectiveV1,task_objective_goal_v1,_decode as decode_task
        if (prior.revision!=1 or original_goal!=task_objective_goal_v1(decode_task(objective,ArtifactTaskObjectiveV1))
                or objective["initial_c02_operation_id"]!=request.c02_operation_id
                or objective["initial_root_registration_ref"]!=request.root_registration_ref):
            raise ValueError("artifact composer cannot change or revive an existing Goal")
        goal=original_goal
    node = PlanNodeV2(node_id=ids["node"], owner_ref=mapping.persona_ref, depends_on=(),
        action_kind=RECIPE_ID, success_predicate=predicate, cancellation_point=True, compensation_ref=None,
        resource_ref=request.root_registration_ref, observable_postconditions=(predicate,))
    plan = PersonalPlanV1(ids["plan"], 1, goal_key.token, 1, "active", mapping.persona_ref, (node,),
        (artifact_draft_action_keys_v1(ns, c02_operation_id=request.c02_operation_id,
            root_registration_ref=request.root_registration_ref)[0].token,),
        ("current_final_admission_required",), (), ("task_cancelled", "source_or_owner_revoked", "original_deadline_expired"),
        roots, facts, None)
    project = LifeProject(ids["project"], ns, adoption.target.filename, "real_execution", RECIPE_ID)
    recipe = ActivityRecipe(RECIPE_ID, 1, "real_execution", (RECIPE_ID,), True)
    return ArtifactGoalPlanCompositionV1(adoption, goal, plan, project, recipe,
        goal_key, plan_key, project_key, recipe_key)


def stage_compose_current_artifact_goal_plan_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(request) is not ComposeCurrentArtifactGoalPlanRequestV1:
        raise TypeError("exact artifact Goal/Plan composition request required")
    try:
        composition = compose_current_artifact_goal_plan_v1(db, frame=frame, request=request, installed_readers=installed_readers)
        read = CurrentDomainReadV1(frame)
        keys = (composition.goal_key, composition.plan_key, *artifact_draft_action_keys_v1(
            frame.envelope.authority.namespace, c02_operation_id=request.c02_operation_id,
            root_registration_ref=request.root_registration_ref))
        initial=read.head(db,composition.goal_key)
        if any(read.head(db,key).revision for key in keys[1:]):
            raise ValueError("artifact task cannot replace an adopted Plan or replay an unresolved effect")
        if initial.revision and initial.value!=plain_v1(composition.goal):
            raise ValueError("artifact composer must preserve the exact prospective Goal")
        _facts(db, read, composition.plan)
        goal_writes=() if initial.revision else (GraphWrite(composition.goal_key,plain_v1(composition.goal)),)
        return _plan_stage(frame, "compose_artifact_goal_plan", request,
            (*goal_writes,GraphWrite(composition.plan_key,plain_v1(composition.plan),
                tuple(AtomKey.from_token(ref) for ref in composition.plan.source_refs))),
            artifact_content_adoption=composition.adoption, actual_fact_versions=composition.plan.fact_versions,
            artifact_project_ref=composition.project_key.token, artifact_recipe_ref=composition.recipe_key.token)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d08", "compose_artifact_goal_plan", request, missing)


def _current_artifact_action_candidate_v1(db, *, frame, request, installed_readers):
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v1
    from .d08_life_admission_v1 import _adopted, _context_provider
    from .d03_life_project_context_v1 import life_project_context_keys_v1
    from ..domains.d03.context import EntityAnchor, RoleBinding, RoleBindingRequest, _tuple_payload
    from .d10_project_checkpoint_v1 import read_current_artifact_project_definition_v1
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    from .artifact_continuation_originals_v1 import (read_selected_artifact_continuation_request_v1,
        read_current_existing_artifact_composition_v1)
    selector = artifact_draft_task_selector_v1(frame.envelope.authority.namespace,
        c02_operation_id=request.c02_operation_id, root_registration_ref=request.root_registration_ref)
    selected = read_selected_artifact_continuation_request_v1(db, namespace=selector.namespace, selector=selector)
    composer = compose_current_artifact_goal_plan_v1 if selected is None else read_current_existing_artifact_composition_v1
    composition = composer(db, frame=frame, request=request, installed_readers=installed_readers)
    read, ns = CurrentDomainReadV1(frame), frame.envelope.authority.namespace
    ids = artifact_draft_file_ids_v1(ns, c02_operation_id=request.c02_operation_id,
        root_registration_ref=request.root_registration_ref)
    identity = frame.envelope.identity
    if (identity.operation_id, identity.attempt_id, identity.effect_id, identity.phase) != (
            ids["action_operation"], ids["attempt"], ids["effect"], "propose_artifact_draft_action"):
        raise ValueError("artifact Action changed the registered task's stable operation/attempt/effect")
    for key, value in ((composition.goal_key, composition.goal), (composition.plan_key, composition.plan)):
        atom = read.head(db, key, required=True)
        _adopted(db, read, atom)
        if atom.value != plain_v1(value):
            raise MissingProductionOriginalV1("actual_unexecuted_artifact_goal_plan")
    read_current_artifact_project_definition_v1(db, frame=frame,
        project_ref=composition.project_key.token, recipe_ref=composition.recipe_key.token,
        source_ref=composition.adoption.task_source.ref)
    entity_key, role_key = life_project_context_keys_v1(ns, composition.project_key.token)
    entity_atom, role_atom = (read.head(db, key, required=True) for key in (entity_key, role_key))
    for atom in (entity_atom, role_atom):
        _adopted(db, read, atom)
    entity = EntityAnchor(**_tuple_payload(entity_atom.value, "creation_evidence_refs"))
    role = RoleBinding(**_tuple_payload(role_atom.value, "norm_refs", "source_refs"))
    role_request = RoleBindingRequest(composition.plan.actor_ref, entity.entity_id, None, None,
        "artifact_draft_v1", "consolidation", frame.now_utc, True)
    if (entity.status != "active" or entity.kind != "activity" or entity.owner_scope != composition.plan.actor_ref
            or composition.project_key.token not in entity.creation_evidence_refs
            or role.target_entity_ref != entity.entity_id or role.subject_persona_ref != composition.plan.actor_ref
            or role.group_ref is not None or role.scene_ref is not None or not role.applies_to(role_request)
            or _context_provider(db, read).resolve_role_binding(role_request, (role,)).status != "complete"):
        raise MissingProductionOriginalV1("actual_registered_artifact_project_role_catalogue")
    action_key, cancel_key = artifact_draft_action_keys_v1(ns, c02_operation_id=request.c02_operation_id,
        root_registration_ref=request.root_registration_ref)
    from .current_method_learning_read_v3 import current_action_parameter_digest_v3
    parameter_values = (plain_v1(composition.adoption.target), plain_v1(composition.adoption.content))
    parameter_digest = current_action_parameter_digest_v3(db, ns, identity.operation_id, parameter_values)
    [node] = [node for node in composition.plan.nodes if node.node_id == ids["node"]]
    action, schema, keys = artifact_action_schema_parts_v1(namespace=ns, goal=composition.goal,
        plan=composition.plan, node=node, entity_ref=entity.entity_id, identity=identity,
        parameter_digest=parameter_digest, action_key=action_key, cancel_key=cancel_key,
        adoption=composition.adoption)
    return composition, action, schema, keys


def artifact_draft_action_schema_key_v1(db, *, frame, request, installed_readers):
    if type(request) is not ProposeCurrentArtifactActionRequestV1:
        raise TypeError("exact artifact Action proposal request required")
    key = _current_artifact_action_candidate_v1(db, frame=frame, request=request, installed_readers=installed_readers)[3][1]
    from .current_method_learning_read_v3 import verify_prepared_action_schema_key_v3
    return verify_prepared_action_schema_key_v3(db, frame.envelope.authority.namespace, frame.envelope.identity.operation_id, key)


def stage_propose_current_artifact_action_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(request) is not ProposeCurrentArtifactActionRequestV1:
        raise TypeError("exact artifact Action proposal request required")
    try:
        composition, action, schema, keys = _current_artifact_action_candidate_v1(db,
            frame=frame, request=request, installed_readers=installed_readers)
        read = CurrentDomainReadV1(frame)
        if any(read.head(db, key).revision for key in keys):
            raise ValueError("artifact Action cannot replace an existing action/schema/cancellation identity")
        cancel = ActionCancellationState.for_action(action, state="active", actor=frame.envelope.authority.actor,
            source_refs=action.source_refs, operation_id=action.identity.operation_id)
        return _plan_stage(frame, "propose_artifact_draft_action", request,
            tuple(GraphWrite(key, plain_v1(value)) for key, value in zip(keys, (action, schema, cancel), strict=True)),
            artifact_content_adoption=composition.adoption, artifact_goal_ref=composition.goal_key.token,
            artifact_plan_ref=composition.plan_key.token, artifact_project_ref=composition.project_key.token,
            artifact_recipe_ref=composition.recipe_key.token, final_admission=False)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d08", "propose_artifact_draft_action", request, missing)


def read_current_artifact_action_root_skeleton_v1(db, *, frame, request, installed_readers):
    """Read actual Action A members after CAS; it cannot register a final Plan."""
    from .d08_life_admission_v1 import DraftActionRootSkeletonV1, _adopted
    from .d11_life_contract_v1 import LifeInputRefV1
    from ..memory_types import access_key, SourceRecord
    if type(request) is not ProposeCurrentArtifactActionRequestV1:
        raise TypeError("exact committed artifact Action selector required")
    composition, action, schema, keys = _current_artifact_action_candidate_v1(db,
        frame=frame, request=request, installed_readers=installed_readers)
    read = CurrentDomainReadV1(frame)
    for key, value in zip(keys[:2], (action, schema), strict=True):
        atom = read.head(db, key, required=True)
        if atom.value != plain_v1(value) or _adopted(db, read, atom) != action.identity.operation_id:
            raise ValueError("artifact Action-only skeleton lost its actual adopted Action/schema")
    cancel = read.head(db, keys[2], required=True)
    if (_adopted(db, read, cancel) != action.identity.operation_id or
            cancel.value != plain_v1(ActionCancellationState.for_action(action, state="active",
                actor=frame.envelope.authority.actor, source_refs=action.source_refs,
                operation_id=action.identity.operation_id))):
        raise ValueError("artifact Action-only skeleton lost its current cancellation member")
    source = read.head(db, composition.adoption.task_source.ref, required=True)
    access = read.head(db, access_key(*frame.envelope.authority.namespace.as_tuple,
        SourceRecord.from_dict(source.value).source_id), required=True)
    def frozen(atom):
        from .current_method_learning_read_v3 import method_post_commit_atom_digest_v3
        return LifeInputRefV1(atom.key.token, atom.revision, method_post_commit_atom_digest_v3(db, atom))
    return DraftActionRootSkeletonV1(frozen(read.head(db, composition.project_key, required=True)),
        frozen(read.head(db, composition.recipe_key, required=True)), frozen(read.head(db, keys[0], required=True)),
        frozen(source), frozen(access), action.identity.activity_id, action.identity.effect_id,
        action.identity.attempt_id, action.identity.operation_id, frame.envelope.authority.audience,
        composition.adoption.target, composition.adoption.content, composition.adoption.postcondition_build_digest)


def verify_d08_personal_plan_stage_v1(stage):
    if stage.domain != "d08" or stage.operation_kind not in {"create_personal_plan", "revise_personal_plan", "select_personal_step", "settle_personal_goal",
            "compose_artifact_goal_plan", "propose_artifact_draft_action", ARTIFACT_TASK_PLAN_OPERATION_V1}:
        raise ValueError("unregistered personal-plan stage")
    provider = GoalExecutionProvider()
    for proposal in stage.proposals:
        provider.validate(proposal)
    return stage


def read_plan_current_personal_plan_operation_v1(db, *, namespace, activity_id, operation_kind, request, operation_id=None):
    keys, roots, originals = [owner_grant_key(*namespace.as_tuple)], [], []
    types = list(OBLIGATION_TYPES)
    from .d01_method_learning_v1 import method_trial_read_inputs_v1
    trial_types, trial_keys, trial_roots, trial_originals = method_trial_read_inputs_v1(db, namespace)
    types.extend(trial_types); keys.extend(trial_keys); roots.extend(trial_roots); originals.extend(trial_originals)
    if operation_kind in {"compose_artifact_goal_plan", "propose_artifact_draft_action"}:
        expected = ComposeCurrentArtifactGoalPlanRequestV1 if operation_kind == "compose_artifact_goal_plan" else ProposeCurrentArtifactActionRequestV1
        if type(request) is not expected:
            raise TypeError("exact installed artifact composer operation required")
        from .d11_artifact_draft_content_v1 import read_plan_artifact_draft_content_v1
        from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
        from ..domains.d03.self_perspective import self_mapping_key
        extra_keys, extra_roots, extra_originals = read_plan_artifact_draft_content_v1(db, namespace=namespace,
            c02_operation_id=request.c02_operation_id, root_registration_ref=request.root_registration_ref)
        keys.extend(extra_keys)
        keys.append(AtomKey.from_token(artifact_draft_task_selector_v1(namespace,
            c02_operation_id=request.c02_operation_id, root_registration_ref=request.root_registration_ref).cycle_job_ref))
        from .artifact_continuation_originals_v1 import artifact_control_keys_for_task_v1
        control_keys = artifact_control_keys_for_task_v1(db, namespace=namespace,
            c02_operation_id=request.c02_operation_id, root_registration_ref=request.root_registration_ref)
        keys.extend(control_keys)
        prior_goal=raw_head_value_v1(db,namespace,control_keys[0])
        if prior_goal is not None and prior_goal["satisfaction_predicate"]["observation_provider"]=="d08.artifact_task_objective.v1":
            originals.append(dict(prior_goal["satisfaction_predicate"]["parameters"])["objective_ref"])
        keys.extend(artifact_draft_action_keys_v1(namespace, c02_operation_id=request.c02_operation_id,
            root_registration_ref=request.root_registration_ref))
        keys.append(self_mapping_key(namespace))
        roots.extend(extra_roots)
        originals.extend(extra_originals)
        if operation_kind == "propose_artifact_draft_action":
            from .d03_life_project_context_v1 import life_project_context_keys_v1
            project_key = control_keys[2]
            keys.extend(life_project_context_keys_v1(namespace, project_key.token))
            types.extend(("d08.action_schema.v1", "d12.active_scheme_head.v1", "d03.entity_anchor", "d03.role_binding"))
            originals.extend(key.token for key in (*control_keys,
                *life_project_context_keys_v1(namespace, project_key.token)))
    elif operation_kind == "create_personal_plan" and type(request) is CreateCurrentPersonalPlanRequestV1:
        owner = Owner("activity", *namespace.as_tuple, activity_id)
        keys.extend((AtomKey(owner, "d08.goal.v1", request.goal.goal_id), AtomKey(owner, PLAN_TYPE, request.plan.plan_id)))
        keys.extend(AtomKey.from_token(row.ref) for row in request.plan.fact_versions)
        roots.extend(request.plan.source_refs)
    elif operation_kind == "revise_personal_plan" and type(request) is ReviseCurrentPersonalPlanRequestV1:
        keys.extend(AtomKey.from_token(ref) for ref in (request.goal_ref, request.plan_ref))
        keys.extend(AtomKey.from_token(row.ref) for row in request.plan.fact_versions)
        roots.extend(request.plan.source_refs)
    elif operation_kind == "select_personal_step" and type(request) is SelectCurrentPersonalStepRequestV1:
        keys.extend(AtomKey.from_token(ref) for ref in (request.goal_ref, request.plan_ref))
        plan = raw_head_value_v1(db, namespace, keys[-1])
        if plan:
            roots.extend(plan["source_refs"])
            keys.extend(AtomKey.from_token(row["ref"]) for row in plan["fact_versions"])
        owner = Owner("activity", *namespace.as_tuple, activity_id)
        if operation_id is None:
            raise ValueError("selection read planning requires its actual operation ID")
        keys.append(AtomKey(owner, DECISION_TYPE, "decision:" + canonical_digest(
            (namespace, activity_id, operation_id, request.plan_ref))[:48]))
        for candidate in request.candidates:
            schema = ActionSchemaRecord.bind(candidate.intent, candidate.action_schema)
            keys.extend((AtomKey(owner, "d08.action_intent.v1", candidate.intent.action_id),
                AtomKey(owner, "d08.action_schema.v1", schema.schema_ref),
                AtomKey(owner, "d08.action_cancellation.v1", candidate.intent.action_id)))
            roots.extend(candidate.intent.source_refs)
            originals.extend(candidate.check_original_refs)
            for check in candidate.checks:
                for version in check.input_versions:
                    try:
                        keys.append(AtomKey.from_token(version.ref))
                    except ValueError:
                        originals.append(version.ref)
        evaluation = read_adopted_domain_operation_v1(db, namespace, request.value_evaluation_operation_id)
        if evaluation is not None:
            keys.extend(v.key for v in evaluation["read_versions"])
            strategy = evaluation["payload"]["provenance"].get("method_strategy")
            if strategy is not None:
                from .d01_production_operations_v1 import method_condition_read_inputs_v1
                types.append("d07.current_interpretation.v1")
                extra_keys, extra_roots, extra_originals = method_condition_read_inputs_v1(db, namespace,
                    (AtomKey.from_token(request.goal_ref),))
                keys.extend(extra_keys)
                roots.extend(extra_roots)
                originals.extend(extra_originals)
        for (encoded,) in db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d08.commitment.v1' ORDER BY token LIMIT 129", namespace.as_tuple):
            value = json.loads(encoded)
            if value["deadline_ref"] is not None:
                keys.append(AtomKey.from_token(value["deadline_ref"]))
    elif operation_kind == "settle_personal_goal" and type(request) is SettleCurrentPersonalGoalRequestV1:
        keys.extend(AtomKey.from_token(ref) for ref in (request.goal_ref, request.plan_ref, request.progress_ref))
        from .d10_project_checkpoint_v1 import project_effect_read_inputs_v1
        extra_keys, extra_roots, extra_originals = project_effect_read_inputs_v1(db, namespace, request.progress_ref)
        keys.extend(extra_keys)
        roots.extend(extra_roots)
        originals.extend(extra_originals)
        from .artifact_task_observer_v1 import artifact_task_observer_read_inputs_v1
        extra_keys,extra_roots,extra_originals=artifact_task_observer_read_inputs_v1(db,namespace,request.goal_ref)
        keys.extend(extra_keys);roots.extend(extra_roots);originals.extend(extra_originals)
        from .d11_life_preparation_v1 import TABLE
        from .artifact_task_observer_v1 import decode_artifact_task_milestone_v2
        rows=db.execute('SELECT original_ref,payload_json FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? '
            "AND json_extract(payload_json,'$.goal_ref')=?",(*namespace.as_tuple,'artifact_task_milestone_v2',request.goal_ref)).fetchall()
        for milestone_ref,raw in rows:
            milestone=decode_artifact_task_milestone_v2(json.loads(raw));originals.extend((milestone_ref,milestone.objective_ref,milestone.file_result_ref,milestone.full_check_original_ref))
            originals.extend(ref for ref,_ in milestone.ordered_phase_originals)
            keys.append(milestone.source_head.key);roots.append(milestone.source_head.key.token)
            if milestone.prev_milestone_ref is not None:originals.append(milestone.prev_milestone_ref)
            if milestone.amendment_ref is not None:originals.append(milestone.amendment_ref)
    else:
        raise ValueError("unregistered exact personal-plan operation")
    return production_read_plan_v1(types, keys, roots, originals)


def personal_decision_key_v1(frame, plan_ref):
    owner = Owner("activity", *frame.envelope.authority.namespace.as_tuple, frame.envelope.identity.activity_id)
    return AtomKey(owner, DECISION_TYPE, "decision:" + canonical_digest((frame.envelope.authority.namespace,
        frame.envelope.identity.activity_id, frame.envelope.identity.operation_id, plan_ref))[:48])


def stage_select_current_personal_step_in_transaction_v2(db, *, frame, request, installed_readers):
    """Only an immutable Decision is written; selected tools have a later admission."""
    from .d08_personal_candidate_v1 import (require_current_personal_candidates_v1,
        read_current_personal_value_evaluation_v1, waiting_personal_candidate_stage_v1)
    from ..domains.d08.personal_candidate_v1 import PrepareCurrentPersonalCandidatesRequestV1
    if type(request) is not SelectCurrentPersonalStepRequestV2:
        raise TypeError("exact prepared-only personal selection request required")
    try:
        prepared, original = require_current_personal_candidates_v1(db, frame=frame,
            preparation_operation_id=request.prepared_candidates_operation_id, installed_readers=installed_readers)
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from .d08_personal_candidate_v1 import actual_personal_candidate_activity_v2
        prepared_request = decode_typed_production_value_v1(original["payload"]["request"], PrepareCurrentPersonalCandidatesRequestV1)
        actual_activity=actual_personal_candidate_activity_v2(db,namespace=frame.envelope.authority.namespace,
            request=prepared_request,issuer=installed_readers.issuer)
        if (request.plan_ref != prepared.plan_head.key.token or request.goal_ref != prepared.goal_head.key.token
                or frame.envelope.identity.operation_id != prepared.selection_operation_id
                or frame.envelope.identity.activity_id != actual_activity
                or frame.envelope.identity.effect_id is not None):
            raise ValueError("Decision-only selection changed its frozen current task/operation")
        read = CurrentDomainReadV1(frame)
        evaluation = read_current_personal_value_evaluation_v1(db, read, prepared_request,
            tuple(row.binding.candidate_ref for row in prepared.candidates))
        if evaluation["original_digest"] != prepared.value_evaluation_digest:
            raise MissingProductionOriginalV1("same_actual_prepared_d01_evaluation")
        values = evaluation["payload"]["provenance"]["evaluation"]
        candidate_refs = {row.binding.candidate_ref for row in prepared.candidates}
        edges = {(a, b) for a in values["preferred"] for b in (*values["unresolved"], *values["rejected"]) if a != b}
        for rule in evaluation["payload"]["provenance"]["persona_view"]["values"]:
            supported = {ref for ref in rule["supports_candidates"] if ref in candidate_refs and rule["label"] in values["reasons"][ref]}
            opposed = {ref for ref in rule["rejects_candidates"] if ref in candidate_refs and rule["label"] in values["reasons"][ref]}
            edges.update((a, b) for a in supported for b in opposed if a != b)
        from .d08_project_control_v1 import require_current_project_plan_for_new_work_v1
        require_current_project_plan_for_new_work_v1(db, namespace=frame.envelope.authority.namespace,
            plan_ref=prepared.plan_head.key.token, expected_plan_revision=prepared.plan_head.revision)
        plan = decode_personal_plan_type_v1(PLAN_TYPE, read.head(db, prepared.plan_head.key, required=True).value)
        nodes = {node.node_id: node for node in plan.nodes}
        qualified = []
        for row in prepared.candidates:
            evidence = row.eligibility
            node = nodes[row.binding.node_id]
            qualified.append(QualifiedPersonalCandidateV1(row.binding.candidate_ref, row.future_identity.action_ref,
                row.binding.node_id, row.binding.digest, evidence.hard_status, evidence.irreversible_exposure,
                node.success_predicate in node.observable_postconditions, evidence.established_deadline, row.quote_ref,
                tuple(sorted(set(node.pending_original_effects) | set(evidence.pending_original_effects))),
                tuple(sorted(set(node.carried_forward_verified) | set(evidence.carried_forward_verified))),
                numeric_discriminator_unresolved=evidence.numeric_discriminator_unresolved,
                recovery_branch=evidence.recovery_branch, established_commitment=evidence.established_commitment))
        strategy = evaluation["payload"]["provenance"].get("method_strategy")
        if plan.method_candidates:
            if strategy is None:
                raise MissingProductionOriginalV1("actual_current_prepared_method_projection")
            eligible = {row.candidate_ref for row in qualified if row.hard_status == "eligible"}
            edges.update((a, b) for a, b in strategy["preference_edges"] if a in eligible and b in eligible)
        from .d05_relationship_revision_v2 import read_current_relationship_preferences_v2
        relationship = read_current_relationship_preferences_v2(db, frame=frame, prepared=prepared, issuer=installed_readers.issuer)
        eligible = {row.candidate_ref for row in qualified if row.hard_status == "eligible"}
        edges.update((a, b) for a, b in relationship.preference_edges if a in eligible and b in eligible)
        decision_key = personal_decision_key_v1(frame, request.plan_ref)
        if decision_key.token != prepared.future_decision_ref or read.head(db, decision_key).revision != 0:
            raise ValueError("one prepared selection cannot replace its immutable Decision")
        record = select_personal_step_v2(decision_id=decision_key.name, candidates=tuple(qualified),
            preference_edges=tuple(sorted(edges)), source_refs=prepared.source_refs,
            read_versions=tuple(VersionedRef(v.key.token, v.revision) for v in frame.snapshot.versions))
        provenance = {"decision": record, "candidate_evidence": tuple(qualified),
            "prepared_candidates_operation_id": prepared.preparation_operation_id,
            "prepared_candidates_digest": original["original_digest"], "value_evaluation": evaluation["original_digest"],
            "relationship_preference": relationship}
        if strategy is not None:
            provenance["method_strategy"] = strategy
        provider = GoalExecutionProvider()
        stage = stage_result_v1(frame, "d08", SELECT_OPERATION_V2, request,
            writes=(GraphWrite(decision_key, plain_v1(record)),), provenance=provenance,
            proposal_schema="d08.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
        provider.validate(stage.proposals[0], frame.snapshot)
        return stage
    except MissingProductionOriginalV1 as missing:
        return waiting_personal_candidate_stage_v1(frame, SELECT_OPERATION_V2, request, missing)


from ..model_broker.artifact_draft_v1 import (ArtifactDraftTaskSelectorV1, ArtifactDraftPhaseSelectorV2, ArtifactDraftTextExtentV2,
    artifact_draft_file_ids_v2, artifact_draft_model_ids_v2)
from .d11_life_contract_v1 import LifeInputRefV1
from .d11_artifact_draft_contract_v1 import DraftFileTargetV1, FrozenDraftContentV1

_PHASE_ACTION_INSTALLED_V2 = object()
PHASE_ACTION_OPERATION_V2 = "propose_artifact_draft_phase_action_v2"


@dataclass(frozen=True, slots=True)
class ProposeCurrentArtifactPhaseActionRequestV2:
    selector: ArtifactDraftPhaseSelectorV2

    def __post_init__(self):
        if type(self.selector) is not ArtifactDraftPhaseSelectorV2 or not self.selector.generation:
            raise TypeError("phase Action accepts only its exact adopted generation selector")


class InstalledArtifactPhaseActionReadersV2:
    def __init__(self, token, *, graph, bootstrap, bundle, model_readers):
        if token is not _PHASE_ACTION_INSTALLED_V2:
            raise TypeError("phase Action readers require the actual installed Graph factory")
        self.graph, self.bootstrap, self.bundle, self.model_readers = graph, bootstrap, bundle, model_readers
        self.issuer = graph._GraphCoordinator__d11_issuer
        self.resource_issuer = graph._GraphCoordinator__d02_issuer

    def current(self):
        self.graph._admin(self.bootstrap)
        assembly = self.graph._GraphCoordinator__d04_installed_joint_assembly
        if (assembly is None or assembly.admin_bundle is not self.bundle
                or self.model_readers.installed_bundle is not self.bundle
                or self.model_readers.model_runtime is not self.graph._GraphCoordinator__artifact_draft_model_runtime_v1
                or self.model_readers.issuer is not self.issuer
                or self.issuer is not self.graph._GraphCoordinator__d11_issuer
                or self.resource_issuer is not self.graph._GraphCoordinator__d02_issuer):
            raise ValueError("phase Action Graph/package/model/issuer installation changed")
        return self

    def selected(self, db, *, frame, selector):
        from .d08_personal_candidate_v1 import (_completed_phase_action_transition_v1,
            _read_selected_after_phase_transition, InstalledPersonalCandidateReadersV1)
        from .d11_artifact_draft_model_v1 import _artifact_phase_selection_locator_v2
        runtime = self.graph._GraphCoordinator__domain_production_runtime_v1
        personal = getattr(runtime, "_personal_candidate_readers_v1", None)
        if type(personal) is not InstalledPersonalCandidateReadersV1:
            raise MissingProductionOriginalV1("actual_installed_phase_action_personal_readers")
        locator, _, _ = _artifact_phase_selection_locator_v2(db, selector)
        with _completed_phase_action_transition_v1(db, frame=frame, request=locator,
                phase_selector=selector, installed_readers=personal.current(), model_readers=self.model_readers) as transition:
            return _read_selected_after_phase_transition(db, frame=frame, request=locator,
                installed_readers=personal.current(), transition=transition)


def install_artifact_phase_action_readers_v2(*, graph, bootstrap, bundle, model_readers):
    from ..graph_coordinator import GraphCoordinator
    from ..host.authority_profile import AdminInstallationBundle
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
    if (type(graph) is not GraphCoordinator or type(bundle) is not AdminInstallationBundle
            or type(model_readers) is not InstalledArtifactDraftModelReadersV1 or model_readers.model_runtime is None
            or model_readers.model_runtime.graph is not graph):
        raise TypeError("phase Action factory requires actual Graph/bootstrap/bundle/model readers")
    return InstalledArtifactPhaseActionReadersV2(_PHASE_ACTION_INSTALLED_V2, graph=graph,
        bootstrap=bootstrap, bundle=bundle, model_readers=model_readers).current()


def _phase_action_readers_v2(value):
    if type(value) is not InstalledArtifactPhaseActionReadersV2:
        raise TypeError("exact installed phase Action readers required")
    return value.current()


@dataclass(frozen=True, slots=True)
class DraftActionRootSkeletonV2:
    project: LifeInputRefV1
    recipe: LifeInputRefV1
    action_intent: LifeInputRefV1
    input_source: LifeInputRefV1
    input_access: LifeInputRefV1
    activity_id: str
    effect_id: str
    attempt_id: str
    operation_id: str
    audiences: tuple[str, ...]
    target: DraftFileTargetV1
    content: FrozenDraftContentV1
    postcondition_build_digest: str
    selector: ArtifactDraftPhaseSelectorV2
    activity_scope_ref: str
    activity_scope_digest: str
    extent: ArtifactDraftTextExtentV2
    full_extent: ArtifactDraftTextExtentV2
    extent_original_ref: str
    extent_original_digest: str
    selected_preparation_original_ref: str
    selected_preparation_original_digest: str
    schema: str = "d08.artifact-phase-action-root-skeleton.v2"

    def __post_init__(self):
        from .d11_offline_originals_v1 import _digest, _text
        if (self.schema != "d08.artifact-phase-action-root-skeleton.v2"
                or any(type(getattr(self, name)) is not LifeInputRefV1 for name in
                    ("project", "recipe", "action_intent", "input_source", "input_access"))
                or type(self.selector) is not ArtifactDraftPhaseSelectorV2
                or type(self.target) is not DraftFileTargetV1 or type(self.content) is not FrozenDraftContentV1
                or type(self.extent) is not ArtifactDraftTextExtentV2 or type(self.full_extent) is not ArtifactDraftTextExtentV2
                or type(self.audiences) is not tuple or not self.audiences):
            raise TypeError("phase root skeleton requires actual typed Action/content/scope commitments")
        ids = artifact_draft_file_ids_v2(self.selector)
        if (self.activity_id, self.effect_id, self.attempt_id, self.operation_id) != (
                ids["activity_id"], ids["effect"], ids["attempt"], ids["action_operation"]):
            raise ValueError("phase root skeleton changed its original once file identities")
        for value in (self.postcondition_build_digest, self.activity_scope_digest,
                self.extent_original_digest, self.selected_preparation_original_digest):
            _digest(value)
        for value in (self.activity_scope_ref, self.extent_original_ref, self.selected_preparation_original_ref):
            _text(value)


def artifact_phase_action_keys_v2(selector):
    ids = artifact_draft_file_ids_v2(selector)
    owner = Owner("activity", *selector.task.namespace.as_tuple, ids["activity_id"])
    return AtomKey(owner, "d08.action_intent.v1", ids["action"]), AtomKey(owner, "d08.action_cancellation.v1", ids["action"])


@dataclass(frozen=True, slots=True)
class _CurrentArtifactPhaseActionV2:
    adoption: object
    prepared_candidates: object
    chosen: object
    selected_original: object
    goal: Goal
    plan: object
    project_key: AtomKey
    recipe_key: AtomKey
    action: ActionIntent
    action_schema: ActionSchemaRecord
    keys: tuple[AtomKey, ...]


def _current_artifact_phase_action_candidate_v2(db, *, frame, request, installed_readers):
    from .d11_artifact_draft_content_v1 import read_current_adopted_artifact_draft_content_v2
    from .d11_artifact_draft_model_v1 import _current_artifact_phase_parameters_v2
    from .artifact_task_text_extent_v1 import require_current_artifact_task_text_extent_v1
    from .d08_life_admission_v1 import _adopted, _context_provider
    from .d03_life_project_context_v1 import life_project_context_keys_v1
    from .d10_project_checkpoint_v1 import read_current_artifact_project_definition_v1
    from ..domains.d03.context import EntityAnchor, RoleBinding, RoleBindingRequest, _tuple_payload
    from .d11_artifact_draft_contract_v1 import DraftActivityScopeV1, DraftRootCapabilityV1, draft_from_wire_v1
    from .d11_life_preparation_v1 import _read
    from .d11_offline_originals_v1 import _utc
    from ..host.authority_profile import require_installed_artifact_target_v2
    from .d08_personal_candidate_v1 import InstalledPersonalCandidateReadersV1
    readers = _phase_action_readers_v2(installed_readers)
    if type(request) is not ProposeCurrentArtifactPhaseActionRequestV2:
        raise TypeError("exact phase Action selector required")
    selector, ns = request.selector, frame.envelope.authority.namespace
    read = CurrentDomainReadV1(frame); read.check(db)
    if selector.task.namespace != ns or frame.envelope.authority.purpose != "consolidation":
        raise ValueError("phase Action changed its actual Source purpose/namespace")
    prepared, chosen, original = readers.selected(db, frame=frame, selector=selector)
    personal = readers.graph._GraphCoordinator__domain_production_runtime_v1._personal_candidate_readers_v1
    if type(personal) is not InstalledPersonalCandidateReadersV1:
        raise MissingProductionOriginalV1("actual_installed_phase_action_personal_reader")
    require_current_artifact_task_text_extent_v1(db, frame=frame, binding=chosen.binding,
        goal_ref=prepared.goal_head.key.token, installed_readers=personal.current())
    adoption = read_current_adopted_artifact_draft_content_v2(db, frame=frame, selector=selector,
        installed_readers=readers.model_readers)
    extent, target, prior = _current_artifact_phase_parameters_v2(db, selector=selector, chosen=chosen, issuer=readers.issuer)
    if (adoption.target != target or adoption.extent != extent or adoption.full_extent != chosen.binding.full_extent
            or (adoption.extent_original_ref, adoption.extent_original_digest) !=
               (chosen.binding.extent_original_ref, chosen.binding.extent_original_digest)):
        raise ValueError("phase file Action changed its selected actual content/extent/target")
    if selector.phase_kind == "tone_sample":
        if selector.phase_index != 0:raise ValueError('tone sample must remain the first phase of its selected method')
        if target.mode=='create':
            if prior is not None:raise ValueError('initial tone sample cannot replace a claimed prior file')
        elif target.mode=='replace' and prior is not None:
            from .artifact_task_amendment_v1 import read_current_amendment_v1
            from .artifact_continuation_originals_v1 import read_selected_artifact_continuation_request_v1
            amendment=read_current_amendment_v1(db,namespace=ns,root_registration_ref=selector.task.root_registration_ref,issuer=readers.issuer)
            selected=read_selected_artifact_continuation_request_v1(db,namespace=ns,selector=selector.task)
            if (amendment is None or selected is None or selected[0].correction_head_ref!=amendment[2].token
                    or selected[0].goal_ref!=prepared.goal_head.key.token):
                raise MissingProductionOriginalV1('actual_ordinary_amendment_before_replacement_tone_sample')
            from .d11_artifact_draft_content_v1 import ArtifactDraftPhaseVerifiedOriginalV2,artifact_draft_phase_verification_from_wire_v2
            proof=_read(db,issuer=readers.issuer,namespace=ns,kind='c4_phase_verified',ref=prior.verified_original_ref)
            if proof is None:raise MissingProductionOriginalV1('actual_task_previous_full_check_before_replacement_sample')
            verified=artifact_draft_phase_verification_from_wire_v2(proof[0],ArtifactDraftPhaseVerifiedOriginalV2)
            if verified.readback!=prior.verified_readback or selected[0].predecessor_result_ref!=verified.readback_original_ref:
                raise ValueError('replacement sample changed the actually selected previous full-file result')
            from .d11_artifact_draft_model_v1 import require_artifact_method_physical_version_capacity_v2
            require_artifact_method_physical_version_capacity_v2(selector=selector,prior=prior,installed_bundle=readers.bundle)
        else:raise MissingProductionOriginalV1('actual_verified_task_predecessor_before_tone_sample')
    if selector.phase_kind == "full" and selector.phase_index > 0 and (target.mode != "replace" or prior is None):
        raise MissingProductionOriginalV1("actual_verified_sample_check_existing_file_before_full_action")
    scope_row = _read(db, issuer=readers.issuer, namespace=ns, kind="activity_scope", ref=adoption.activity_scope_ref)
    root_row = _read(db, issuer=readers.issuer, namespace=ns, kind="draft_root_capability", ref=selector.task.root_registration_ref)
    if scope_row is None or root_row is None:
        raise MissingProductionOriginalV1("actual_phase_action_scope_and_registered_file_root")
    scope = draft_from_wire_v1(scope_row[0], DraftActivityScopeV1)
    root = draft_from_wire_v1(root_row[0], DraftRootCapabilityV1)
    read.original(adoption.activity_scope_ref, kind="d11.life_activity_scope", digest=adoption.activity_scope_digest)
    read.original(root.registration_ref, kind="d11.life_draft_root_capability", digest=canonical_digest(plain_v1(root)))
    ids = artifact_draft_file_ids_v2(selector)
    if ((scope.activity_id, scope.actor_ref, scope.c02_original_ref, scope.source, scope.parent_budget_lease_ref) !=
            (ids["activity_id"], frame.envelope.authority.actor, selector.task.c02_operation_id,
                adoption.task_source, frame.envelope.parent_budget_lease_ref)
            or canonical_digest(scope_row[0]) != adoption.activity_scope_digest
            or scope_row[1] != adoption.adoption_operation_id or scope.root_registration_ref != root.registration_ref
            or scope.root_registration_digest != canonical_digest(plain_v1(root))
            or (scope.owner_grant_ref, scope.owner_grant_revision, scope.owner_grant_digest) !=
               (frame.owner_guard.grant_ref, frame.owner_guard.grant_revision, frame.owner_guard.grant_digest)
            or (root.owner_grant_ref, root.owner_grant_revision, root.owner_grant_digest) !=
               (frame.owner_guard.grant_ref, frame.owner_guard.grant_revision, frame.owner_guard.grant_digest)
            or not frame.now_utc < min(_utc(adoption.original_deadline_utc).timestamp(),
                _utc(scope.valid_until_utc).timestamp(), _utc(root.valid_until_utc).timestamp())):
        raise MissingProductionOriginalV1("current_exact_phase_action_owner_task_scope_deadline")
    require_installed_artifact_target_v2(readers.bundle.artifact_draft, root, target)
    goal_atom = read.head(db, prepared.goal_head.key, required=True)
    plan_atom = read.head(db, prepared.plan_head.key, required=True)
    for atom in (goal_atom, plan_atom):
        _adopted(db, read, atom)
    goal, plan = _decode_goal(goal_atom.value), decode_personal_plan_type_v1(PLAN_TYPE, plan_atom.value)
    if (goal_atom.revision != prepared.goal_head.revision or plan_atom.revision != prepared.plan_head.revision
            or goal.state != "active" or plan.state != "active" or plan.goal_ref != goal_atom.key.token):
        raise MissingProductionOriginalV1("current_same_phase_action_active_goal_plan")
    _facts(db, read, plan)
    objective_ref, objective = require_artifact_task_objective_original_v1(db, namespace=ns,
        goal_ref=goal_atom.key.token, goal=goal, issuer=readers.issuer)
    read.original(objective_ref, kind="d11.life_artifact_task_objective", digest=canonical_digest(objective))
    project_key, recipe_key = AtomKey.from_token(objective["project_ref"]), AtomKey.from_token(objective["recipe_ref"])
    read_current_artifact_project_definition_v1(db, frame=frame, project_ref=project_key.token,
        recipe_ref=recipe_key.token, source_ref=adoption.task_source.ref)
    entity_key, role_key = life_project_context_keys_v1(ns, project_key.token)
    entity_atom, role_atom = (read.head(db, key, required=True) for key in (entity_key, role_key))
    for atom in (entity_atom, role_atom):
        _adopted(db, read, atom)
    entity = EntityAnchor(**_tuple_payload(entity_atom.value, "creation_evidence_refs"))
    role = RoleBinding(**_tuple_payload(role_atom.value, "norm_refs", "source_refs"))
    role_request = RoleBindingRequest(plan.actor_ref, entity.entity_id, None, None, "artifact_draft_v1", "consolidation", frame.now_utc, True)
    if (entity.status != "active" or entity.kind != "activity" or entity.owner_scope != plan.actor_ref
            or project_key.token not in entity.creation_evidence_refs or role.target_entity_ref != entity.entity_id
            or role.subject_persona_ref != plan.actor_ref or role.group_ref is not None or role.scene_ref is not None
            or not role.applies_to(role_request)
            or _context_provider(db, read).resolve_role_binding(role_request, (role,)).status != "complete"):
        raise MissingProductionOriginalV1("actual_registered_phase_action_project_role")
    nodes = tuple(node for node in plan.nodes if node.node_id == chosen.binding.node_id)
    if (len(nodes) != 1 or nodes[0].owner_ref != plan.actor_ref or nodes[0].action_kind != "artifact_draft_v1"
            or nodes[0].pending_original_effects or nodes[0].carried_forward_verified):
        raise MissingProductionOriginalV1("actual_unexecuted_selected_phase_action_node")
    roots = tuple(dict.fromkeys((adoption.task_source.ref, *adoption.content.source_refs)))
    for audience in frame.envelope.authority.audience:
        for purpose in ("context", "consolidation"):
            read.source_family(db, roots, audience=audience, purpose=purpose)
    action_key, cancel_key = artifact_phase_action_keys_v2(selector)
    existing = read.head(db, action_key)
    if existing.revision:
        _adopted(db, read, existing)
        action_identity = _decode("d08.action_intent.v1", existing.value).identity
    else:
        action_identity = frame.envelope.identity
    if (action_identity.operation_id, action_identity.attempt_id, action_identity.effect_id, action_identity.activity_id, action_identity.phase) != (
            ids["action_operation"], ids["attempt"], ids["effect"], ids["activity_id"], PHASE_ACTION_OPERATION_V2):
        raise ValueError("phase Action must use its exact original V2 file once identities")
    from .current_method_learning_read_v3 import current_action_parameter_digest_v3
    parameter_values = (plain_v1(target), plain_v1(adoption.content))
    parameter_digest = current_action_parameter_digest_v3(db, ns, frame.envelope.identity.operation_id, parameter_values)
    action, schema, keys = artifact_phase_action_schema_parts_v2(namespace=ns, selector=selector,
        goal=goal, plan=plan, entity_ref=entity.entity_id, identity=action_identity,
        parameter_digest=parameter_digest, adoption=adoption, target=target, roots=roots)
    return _CurrentArtifactPhaseActionV2(adoption, prepared, chosen, original, goal, plan, project_key, recipe_key,
        action, schema, keys)


def artifact_phase_action_schema_key_v2(db, *, frame, request, installed_readers):
    key = _current_artifact_phase_action_candidate_v2(db, frame=frame, request=request, installed_readers=installed_readers).keys[1]
    from .current_method_learning_read_v3 import verify_prepared_action_schema_key_v3
    return verify_prepared_action_schema_key_v3(db, frame.envelope.authority.namespace, frame.envelope.identity.operation_id, key)


def stage_propose_current_artifact_phase_action_in_transaction_v2(db, *, frame, request, installed_readers):
    if type(request) is not ProposeCurrentArtifactPhaseActionRequestV2:
        raise TypeError("exact phase Action request required")
    try:
        value = _current_artifact_phase_action_candidate_v2(db, frame=frame, request=request, installed_readers=installed_readers)
        read = CurrentDomainReadV1(frame)
        if any(read.head(db, key).revision for key in value.keys):
            raise ValueError("phase Action cannot replace its original action/schema/cancellation")
        if value.action.identity != frame.envelope.identity:
            raise ValueError("phase Action A must be its actual current W01 operation")
        cancel = ActionCancellationState.for_action(value.action, state="active", actor=frame.envelope.authority.actor,
            source_refs=value.action.source_refs, operation_id=value.action.identity.operation_id)
        provider = GoalExecutionProvider()
        stage = stage_result_v1(frame, "d08", PHASE_ACTION_OPERATION_V2, request,
            writes=tuple(GraphWrite(key, plain_v1(item)) for key, item in zip(value.keys,
                (value.action, value.action_schema, cancel), strict=True)),
            provenance={"artifact_phase_content_adoption": value.adoption,
                "artifact_goal_ref": value.prepared_candidates.goal_head.key.token,
                "artifact_plan_ref": value.prepared_candidates.plan_head.key.token,
                "artifact_project_ref": value.project_key.token, "artifact_recipe_ref": value.recipe_key.token,
                "selected_preparation_original_ref": "d08-current:" + value.selected_original["original_digest"][:48],
                "selected_preparation_original_digest": value.selected_original["original_digest"], "final_admission": False},
            receiver_events=(("d11", "artifact_phase_action_proposal_available"),),
            proposal_schema="d08.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
        provider.validate(stage.proposals[0], frame.snapshot)
        return stage
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d08", PHASE_ACTION_OPERATION_V2, request, missing)


def read_current_artifact_phase_action_root_skeleton_v2(db, *, frame, request, installed_readers):
    from .d08_life_admission_v1 import _adopted
    from ..memory_types import SourceRecord, access_key
    value = _current_artifact_phase_action_candidate_v2(db, frame=frame, request=request, installed_readers=installed_readers)
    read = CurrentDomainReadV1(frame)
    for key, expected in zip(value.keys[:2], (value.action, value.action_schema), strict=True):
        atom = read.head(db, key, required=True)
        if atom.value != plain_v1(expected) or _adopted(db, read, atom) != value.action.identity.operation_id:
            raise ValueError("phase Action skeleton lost its actual A Action/schema")
    cancel = read.head(db, value.keys[2], required=True)
    expected_cancel = ActionCancellationState.for_action(value.action, state="active", actor=frame.envelope.authority.actor,
        source_refs=value.action.source_refs, operation_id=value.action.identity.operation_id)
    if cancel.value != plain_v1(expected_cancel) or _adopted(db, read, cancel) != value.action.identity.operation_id:
        raise MissingProductionOriginalV1("actual_current_active_phase_Action_cancellation")
    source = read.head(db, value.adoption.task_source.ref, required=True)
    access = read.head(db, access_key(*frame.envelope.authority.namespace.as_tuple,
        SourceRecord.from_dict(source.value).source_id), required=True)
    def frozen(atom):
        from .current_method_learning_read_v3 import method_post_commit_atom_digest_v3
        return LifeInputRefV1(atom.key.token, atom.revision, method_post_commit_atom_digest_v3(db, atom))
    return DraftActionRootSkeletonV2(frozen(read.head(db, value.project_key, required=True)),
        frozen(read.head(db, value.recipe_key, required=True)), frozen(read.head(db, value.keys[0], required=True)),
        frozen(source), frozen(access), value.action.identity.activity_id, value.action.identity.effect_id,
        value.action.identity.attempt_id, value.action.identity.operation_id, frame.envelope.authority.audience,
        value.adoption.target, value.adoption.content, value.adoption.postcondition_build_digest, request.selector,
        value.adoption.activity_scope_ref, value.adoption.activity_scope_digest, value.adoption.extent, value.adoption.full_extent,
        value.adoption.extent_original_ref, value.adoption.extent_original_digest,
        "d08-current:" + value.selected_original["original_digest"][:48], value.selected_original["original_digest"])


def read_plan_current_artifact_phase_action_v2(db, *, namespace, request, installed_readers):
    from .d11_artifact_draft_model_v1 import _artifact_phase_selection_locator_v2
    from .d11_artifact_draft_content_v1 import (read_plan_artifact_draft_content_adoption_v2,
        AdoptArtifactDraftContentRequestV2, artifact_draft_content_from_wire_v2, ArtifactDraftContentAdoptionV2)
    from .d08_personal_candidate_v1 import (read_plan_personal_candidates_v1,
        _read_plan_completed_phase_action_transition_v1, InstalledPersonalCandidateReadersV1)
    from .d03_life_project_context_v1 import life_project_context_keys_v1
    from .d11_life_preparation_v1 import _read
    from .artifact_task_text_extent_v1 import _objective_basis_v1
    from ..domains.d03.self_perspective import self_mapping_key
    readers = _phase_action_readers_v2(installed_readers)
    if type(request) is not ProposeCurrentArtifactPhaseActionRequestV2 or request.selector.task.namespace != namespace:
        raise TypeError("exact namespace phase Action read recipe required")
    selector = request.selector; ids = artifact_draft_file_ids_v2(selector); model_ids = artifact_draft_model_ids_v2(selector)
    locator, _, _ = _artifact_phase_selection_locator_v2(db, selector)
    personal = getattr(readers.graph._GraphCoordinator__domain_production_runtime_v1, "_personal_candidate_readers_v1", None)
    if type(personal) is not InstalledPersonalCandidateReadersV1:
        raise MissingProductionOriginalV1("actual_phase_action_read_plan_personal_reader")
    base = read_plan_personal_candidates_v1(db, namespace=namespace, activity_id=ids["activity_id"],
        request=locator, installed_readers=personal.current())
    content = read_plan_artifact_draft_content_adoption_v2(db, namespace=namespace,
        request=AdoptArtifactDraftContentRequestV2(selector), installed_readers=readers.model_readers)
    completed = _read_plan_completed_phase_action_transition_v1(db, namespace=namespace,
        phase_selector=selector, installed_readers=personal.current())
    keys = [*base.exact_keys, *content.exact_keys, *completed.exact_keys, self_mapping_key(namespace),
        *artifact_phase_action_keys_v2(selector)]
    roots = [*base.source_roots, *content.source_roots, *completed.source_roots]
    originals = [*base.required_original_refs, *content.required_original_refs, *completed.required_original_refs, model_ids["adopt"]]
    plan = raw_head_value_v1(db, namespace, AtomKey.from_token(selector.plan_ref))
    if plan is not None:
        goal = raw_head_value_v1(db, namespace, AtomKey.from_token(plan["goal_ref"]))
        if goal is not None:
            objective_ref, objective, _ = _objective_basis_v1(db, namespace, plan["goal_ref"], _decode_goal(goal), readers.issuer)
            project, recipe = AtomKey.from_token(objective["project_ref"]), AtomKey.from_token(objective["recipe_ref"])
            context = life_project_context_keys_v1(namespace, project.token)
            keys.extend((project, recipe, *context))
            originals.extend((objective_ref, project.token, recipe.token, *(key.token for key in context)))
    row = _read(db, issuer=readers.issuer, namespace=namespace, kind="c4_phase_adopted", ref=model_ids["adopt"])
    if row is not None:
        adoption = artifact_draft_content_from_wire_v2(row[0], ArtifactDraftContentAdoptionV2)
        keys.extend((AtomKey.from_token(adoption.task_source.ref), AtomKey.from_token(adoption.content.content.ref)))
        roots.extend(adoption.content.source_refs)
        originals.extend((adoption.activity_scope_ref, adoption.extent_original_ref))
    return production_read_plan_v1((*base.fixed_type_ids, *content.fixed_type_ids, *completed.fixed_type_ids,
        "d08.action_schema.v1", "d12.active_scheme_head.v1", "d03.entity_anchor", "d03.role_binding"), keys, roots, originals)


ARTIFACT_TASK_PLAN_REVISION_OPERATION_V2 = 'revise_artifact_task_plan_v2'


@dataclass(frozen=True, slots=True)
class ReviseCurrentArtifactTaskPlanRequestV2:
    task: ArtifactDraftTaskSelectorV1

    def __post_init__(self):
        CreateCurrentArtifactTaskPlanRequestV1(self.task)


@dataclass(frozen=True, slots=True)
class ArtifactTaskPlanRevisionStageV2:
    stage: object
    checkpoint_stage: object


def artifact_task_plan_revision_operation_id_v2(task):
    ReviseCurrentArtifactTaskPlanRequestV2(task)
    return 'artifact-task-plan-revision:' + task.digest[:48]


def artifact_task_plan_revision_basis_v2(db, *, namespace, request, issuer):
    from .artifact_task_amendment_v1 import read_current_amendment_v1
    from .artifact_task_observer_v1 import ARTIFACT_TASK_MILESTONE_KIND_V2, read_current_artifact_task_milestone_v2
    from .d11_life_preparation_v1 import _read, TABLE
    from .ingress_artifact_task_scope_v1 import (ArtifactTaskObjectiveV1, IngressArtifactTaskScopeOriginalV1,
        _decode as task_decode, task_scope_ref_v1, require_task_scope_archive_v1)
    from .d11_artifact_draft_content_v1 import artifact_method_settlement_operation_id_v2, require_artifact_method_settlement_history_v2
    from ..domains.d10.project_checkpoint_v1 import CHECKPOINT_TYPE, project_checkpoint_key_v1, decode_project_checkpoint_type_v1
    from ..graph_types import GraphAtom
    if type(request) is not ReviseCurrentArtifactTaskPlanRequestV2 or request.task.namespace != namespace:
        raise TypeError('revision Plan requires the exact ordinary amendment task')
    task=request.task
    actual=read_current_amendment_v1(db,namespace=namespace,root_registration_ref=task.root_registration_ref,issuer=issuer)
    if actual is None:raise MissingProductionOriginalV1('actual_ordinary_user_amendment_before_task_Plan_revision')
    amendment,amendment_ref,amendment_key=actual
    if amendment.c02_operation_id!=task.c02_operation_id:
        raise ValueError('revision task changed the actual ordinary user amendment C02')
    objective_row=_read(db,issuer=issuer,namespace=namespace,kind='artifact_task_objective',ref=amendment.objective_ref)
    scope_ref=task_scope_ref_v1(task.root_registration_ref)
    scope_row=_read(db,issuer=issuer,namespace=namespace,kind='artifact_task_scope',ref=scope_ref)
    if objective_row is None or scope_row is None:raise MissingProductionOriginalV1('actual_revision_task_objective_and_TaskScope')
    objective=task_decode(objective_row[0],ArtifactTaskObjectiveV1)
    scope=task_decode(scope_row[0],IngressArtifactTaskScopeOriginalV1)
    producer=read_adopted_domain_operation_v1(db,namespace,scope_row[1])
    require_task_scope_archive_v1(db,namespace=namespace,root=scope.root,producer=producer)
    if (scope.task_kind!='continue' or scope.c02_operation_id!=task.c02_operation_id
            or scope.objective_ref!=amendment.objective_ref or canonical_digest(objective_row[0])!=amendment.objective_digest
            or (amendment.goal_ref,amendment.project_ref,scope.source_ref)!=(objective.goal_ref,objective.project_ref,amendment.source_ref)):
        raise ValueError('revision changed the actual TaskScope/objective/amendment source')
    rows=db.execute('SELECT original_ref FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? '
        "AND json_extract(payload_json,'$.objective_ref')=? AND json_extract(payload_json,'$.semantic_index')=1",
        (*namespace.as_tuple,ARTIFACT_TASK_MILESTONE_KIND_V2,amendment.objective_ref)).fetchall()
    if len(rows)!=1:raise MissingProductionOriginalV1('unique_first_full_semantic_milestone_before_revision')
    previous=read_current_artifact_task_milestone_v2(db,namespace=namespace,original_ref=rows[0][0],issuer=issuer)
    from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1,draft_from_wire_v1
    previous_root_row=_read(db,issuer=issuer,namespace=namespace,kind='draft_root_capability',ref=previous.selector.task.root_registration_ref)
    if previous_root_row is None:raise MissingProductionOriginalV1('actual_original_first_milestone_file_Root')
    previous_root=draft_from_wire_v1(previous_root_row[0],DraftRootCapabilityV1)
    if (scope.root.root_identity,scope.root.resource_id,amendment.filename)!=(previous_root.root_identity,previous_root.resource_id,previous.readback.filename):
        raise ValueError('ordinary task revision changed the first physical file Root or target')
    settled=read_adopted_domain_operation_v1(db,namespace,artifact_method_settlement_operation_id_v2(previous.selector))
    if settled is None:raise MissingProductionOriginalV1('actual_first_method_partial_Goal_settlement_before_revision')
    completion=require_artifact_method_settlement_history_v2(db,namespace=namespace,original=settled,
        raw=settled['payload']['provenance']['artifact_method_completion'])
    if (completion.state!='partial' or completion.milestone_original_ref!=previous.original_ref
            or previous.goal_ref!=objective.goal_ref or previous.project_ref!=objective.project_ref
            or previous.selector.task.c02_operation_id==task.c02_operation_id):
        raise ValueError('revision cannot replace an initial, uncompleted or already satisfied task')
    atoms={}
    for member in completion.members:
        key=member.after.key
        row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
            (*namespace.as_tuple,key.token)).fetchone()
        if row is None or row[2]!=1 or (row[0],canonical_digest(json.loads(row[1])))!=(member.after.revision,member.after_value_digest):
            raise MissingProductionOriginalV1('actual_partial_task_after_heads_without_foreign_successor')
        atoms[key.token]=GraphAtom(key,row[0],json.loads(row[1]),True)
    goal_atom=atoms[objective.goal_ref];plan_atom=atoms[objective.plan_ref]
    checkpoint_atom=atoms[project_checkpoint_key_v1(namespace,objective.project_ref).token]
    goal=_decode_goal(goal_atom.value);plan=decode_personal_plan_type_v1(PLAN_TYPE,plan_atom.value)
    checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,checkpoint_atom.value)
    if (goal.state!='active' or plan.state!='waiting' or plan.candidate_refs or checkpoint.state!='waiting'
            or checkpoint.next_step is not None or len(checkpoint.work_version_refs)!=1
            or checkpoint.wait_condition is None or checkpoint.plan_revision!=plan_atom.revision):
        raise MissingProductionOriginalV1('actual_consumed_first_partial_task_wait_before_amendment')
    source=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
        (*namespace.as_tuple,amendment.source_ref)).fetchone()
    if source is None or source[2]!=1 or (source[0],canonical_digest(json.loads(source[1])))!=(amendment.source_revision,amendment.source_digest):
        raise MissingProductionOriginalV1('actual_current_ordinary_user_revision_Source')
    return objective,scope,producer,amendment,amendment_ref,amendment_key,previous,settled,completion,goal_atom,plan_atom,checkpoint_atom


def read_plan_current_artifact_task_plan_revision_v2(db, *, namespace, request, installed_readers):
    from ..domains.d03.self_perspective import self_mapping_key
    value=artifact_task_plan_revision_basis_v2(db,namespace=namespace,request=request,issuer=_reader(installed_readers).issuer)
    objective,scope,producer,amendment,amendment_ref,amendment_key,previous,settled,completion,goal,plan,checkpoint=value
    keys=(goal.key,plan.key,checkpoint.key,AtomKey.from_token(request.task.cycle_job_ref),amendment_key,
        self_mapping_key(namespace),owner_grant_key(*namespace.as_tuple),AtomKey.from_token(amendment.source_ref),previous.source_head.key)
    originals=(amendment.objective_ref,amendment.task_scope_ref,request.task.root_registration_ref,
        scope.c1_intent_ref,amendment_ref,previous.original_ref,previous.file_result_ref,
        'd10-current:'+producer['original_digest'][:48],'d08-current:'+settled['original_digest'][:48])
    from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV3
    if type(scope) is IngressArtifactTaskScopeOriginalV3:originals=(*originals,scope.continuation_authorization.original_ref)
    return production_read_plan_v1((),keys,(amendment.source_ref,previous.source_head.key.token),originals)



def stage_revise_current_artifact_task_plan_in_transaction_v2(db, *, frame, request, installed_readers):
    from ..domains.d03.self_perspective import SelfIdentityMapping, self_mapping_key
    from ..domains.d08.personal_plan_v1 import PlanNodeV2
    from .d11_offline_originals_v1 import _utc
    from .d11_types import job_graph_write
    from .jobs import get_job
    from .d10_project_checkpoint_v1 import stage_artifact_task_plan_revision_checkpoint_v2
    readers=_reader(installed_readers)
    if type(request) is not ReviseCurrentArtifactTaskPlanRequestV2:raise TypeError('exact ordinary amendment task Plan request required')
    try:
        read=CurrentDomainReadV1(frame);read.check(db);ns=frame.envelope.authority.namespace
        basis=artifact_task_plan_revision_basis_v2(db,namespace=ns,request=request,issuer=readers.issuer)
        objective,scope,producer,amendment,amendment_ref,amendment_key,previous,settled,completion,goal_atom,plan_atom,checkpoint_atom=basis
        from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV3
        root=scope.root;guard=frame.owner_guard
        if (frame.envelope.identity.operation_id!=artifact_task_plan_revision_operation_id_v2(request.task)
                or frame.envelope.authority.purpose!='consolidation'
                or (root.owner_grant_ref,root.owner_grant_revision,root.owner_grant_digest)!=(guard.grant_ref,guard.grant_revision,guard.grant_digest)
                or (type(scope) is not IngressArtifactTaskScopeOriginalV3 and previous.owner_guard!=guard)):
            raise ValueError('amendment Plan changed its actual Self/Owner/activity/fixed operation')
        for atom in (goal_atom,plan_atom,checkpoint_atom):
            if read.head(db,atom.key,required=True)!=atom:raise ValueError('revision Plan lost its exact partial before member')
        mapping_atom=read.head(db,self_mapping_key(ns),required=True);mapping=SelfIdentityMapping(**mapping_atom.value)
        if mapping.status!='active' or mapping.self_entity_ref!=frame.envelope.authority.actor or mapping.persona_ref!='persona:'+ns.persona_id:
            raise MissingProductionOriginalV1('actual_current_Self_for_task_amendment_Plan')
        cycle=get_job(db,AtomKey.from_token(request.task.cycle_job_ref).name)
        if (read.head(db,request.task.cycle_job_ref,required=True).value!=job_graph_write(cycle).value
                or cycle.budget_ref!=frame.envelope.parent_budget_lease_ref
                or frame.envelope.identity.activity_id!=cycle.activity_id):
            raise ValueError('revision Plan changed the actual amendment task cycle/budget')
        require_budget_family_admissible(db,cycle.budget_ref)
        grant=readers.issuer.current_budget_grant(db,cycle.budget_ref)
        from .artifact_task_continuation_authorization_v2 import resolve_artifact_task_authorization_deadline_v2
        authorization_deadline=resolve_artifact_task_authorization_deadline_v2(db,namespace=ns,scope=scope,
            objective=objective,issuer=readers.issuer,bundle=readers.installed_bundle,owner_guard=guard,
            now_utc=frame.now_utc,parent_budget_lease_ref=cycle.budget_ref)
        from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV3
        prior_deadline=authorization_deadline if type(scope) is IngressArtifactTaskScopeOriginalV3 else completion.original_deadline_utc
        limit=min(authorization_deadline,prior_deadline,_utc(root.valid_until_utc).timestamp(),
            _utc(cycle.deadline_utc).timestamp(),grant.valid_until_utc)
        if not frame.now_utc<limit or frame.envelope.deadline_utc>limit:
            raise MissingProductionOriginalV1('original_task_amendment_Plan_deadline_without_renewal')
        old=decode_personal_plan_type_v1(PLAN_TYPE,plan_atom.value)
        original_plan=db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?',
            (previous.selector.plan_ref,previous.selector.plan_revision)).fetchone()
        if original_plan is None or original_plan[1]!=1 or canonical_digest(json.loads(original_plan[0]))!=previous.selector.plan_digest:
            raise MissingProductionOriginalV1('actual_first_selected_Plan_method_cost_commitment')
        first_plan=decode_personal_plan_type_v1(PLAN_TYPE,json.loads(original_plan[0]))
        first_candidates=artifact_task_initial_plan_candidates_v1(previous.selector.task)
        costs={method:next(n for n in first_plan.nodes if n.node_id==node_id).cost_ceiling for method,_,node_id in first_candidates}
        current_candidates=artifact_task_initial_plan_candidates_v1(request.task)
        historical_nodes=tuple(node for node in old.nodes if node.node_id in checkpoint_atom.value['completed_node_refs'])
        if len(historical_nodes)!=1:raise ValueError('task revision lost the one actually completed first method node')
        fresh_nodes=tuple(PlanNodeV2(node_id=node_id,owner_ref=mapping.persona_ref,depends_on=(),
            action_kind=historical_nodes[0].action_kind,success_predicate=_decode_goal(goal_atom.value).satisfaction_predicate,
            cancellation_point=True,compensation_ref=None,resource_ref=root.registration_ref,
            observable_postconditions=(_decode_goal(goal_atom.value).satisfaction_predicate,),cost_ceiling=costs[method])
            for method,_,node_id in current_candidates)
        sources=tuple(dict.fromkeys((*old.source_refs,amendment.source_ref,previous.source_head.key.token)))
        read.source_family(db,sources)
        facts=tuple(VersionedRef(ref,read.head(db,ref,required=True).revision) for ref in sources)+(VersionedRef(mapping_atom.key.token,mapping_atom.revision),VersionedRef(amendment_key.token,read.head(db,amendment_key,required=True).revision))
        plan=replace(old,revision=plan_atom.revision+1,state='active',nodes=(*historical_nodes,*fresh_nodes),
            candidate_refs=tuple(candidate for _,candidate,_ in current_candidates),
            method_candidates=tuple((candidate,method) for method,candidate,_ in current_candidates),
            waiting_conditions=(),source_refs=sources,fact_versions=facts,parent_plan_revision_ref=VersionedRef(plan_atom.key.token,plan_atom.revision))
        for ref,kind,digest in ((amendment_ref,'artifact_task_amendment',canonical_digest(plain_v1(amendment))),
                (previous.original_ref,'artifact_task_milestone_v2',previous.digest),(scope.objective_ref,'artifact_task_objective',scope.objective_digest),
                (amendment.task_scope_ref,'artifact_task_scope',amendment.task_scope_digest),(root.registration_ref,'draft_root_capability',canonical_digest(plain_v1(root)))):
            read.original(ref,kind='d11.life_'+kind,digest=digest)
        if type(scope) is IngressArtifactTaskScopeOriginalV3:
            value=scope.continuation_authorization
            read.original(value.original_ref,kind='d11.life_artifact_task_continuation_authorization_v2',digest=value.digest)
        checkpoint_stage=stage_artifact_task_plan_revision_checkpoint_v2(db,frame=frame,request=request,
            plan=plan,checkpoint_atom=checkpoint_atom,installed_readers=readers)
        checkpoint=checkpoint_stage.original_payload_json
        checkpoint_value=json.loads(checkpoint)['writes'][0]['value']
        primary=_plan_stage(frame,ARTIFACT_TASK_PLAN_REVISION_OPERATION_V2,request,(GraphWrite(plan_atom.key,plain_v1(plan)),),
            actual_fact_versions=facts,amendment_original_ref=amendment_ref,amendment_original_digest=canonical_digest(plain_v1(amendment)),
            previous_milestone_ref=previous.original_ref,previous_milestone_digest=previous.digest,
            previous_settlement_operation_id=completion.settlement_operation_id,previous_settlement_original_digest=settled['original_digest'],
            task_scope_ref=amendment.task_scope_ref,task_scope_digest=amendment.task_scope_digest,checkpoint=checkpoint_value)
        payload=json.loads(primary.original_payload_json);payload['writes'].extend(json.loads(checkpoint_stage.original_payload_json)['writes'])
        primary=replace(primary,original_payload_json=canonical_serialize(payload),original_digest=canonical_digest(payload))
        return ArtifactTaskPlanRevisionStageV2(primary,checkpoint_stage)
    except MissingProductionOriginalV1 as missing:return waiting_stage_v1(frame,'d08',ARTIFACT_TASK_PLAN_REVISION_OPERATION_V2,request,missing)



def require_artifact_task_plan_revision_original_v2(db, *, namespace, original):
    from .d11_life_preparation_v1 import TABLE
    from .artifact_task_amendment_v1 import decode_amendment_v1, require_amendment_history_v1
    from .artifact_task_observer_v1 import require_artifact_task_milestone_history_v2
    from .ingress_artifact_task_scope_v1 import (IngressArtifactTaskScopeOriginalV1,ArtifactTaskObjectiveV1,_decode as task_decode)
    from .d11_artifact_draft_content_v1 import require_artifact_method_settlement_history_v2
    from ..domains.d10.project_checkpoint_v1 import CHECKPOINT_TYPE,project_checkpoint_key_v1,decode_project_checkpoint_type_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if original is None or (original['domain'],original['operation_kind'])!=('d08',ARTIFACT_TASK_PLAN_REVISION_OPERATION_V2):
        raise MissingProductionOriginalV1('actual_same_W01_amended_Plan_checkpoint_revision')
    task=decode_typed_production_value_v1(original['payload']['request']['task'],ArtifactDraftTaskSelectorV1)
    if task.namespace!=namespace or original['receipt'].operation_id!=artifact_task_plan_revision_operation_id_v2(task):
        raise ValueError('task Plan revision changed actual namespace/fixed identity')
    p=original['payload']['provenance']
    expected={'actual_fact_versions','amendment_original_ref','amendment_original_digest','previous_milestone_ref','previous_milestone_digest',
        'previous_settlement_operation_id','previous_settlement_original_digest','task_scope_ref','task_scope_digest','checkpoint'}
    if set(p)!=expected or original['payload']['coverage']!='complete':raise ValueError('task Plan revision has foreign or incomplete provenance')
    def saved(kind,ref,digest):
        row=db.execute('SELECT producing_operation_id,payload_json,payload_digest FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
            (*namespace.as_tuple,kind,ref)).fetchone()
        if row is None or row[2]!=digest or canonical_digest(json.loads(row[1]))!=digest:
            raise ValueError('task Plan revision lost actual original bytes')
        return row[0],json.loads(row[1])
    m_op,m_raw=saved('artifact_task_milestone_v2',p['previous_milestone_ref'],p['previous_milestone_digest'])
    milestone=require_artifact_task_milestone_history_v2(db,namespace=namespace,original_ref=p['previous_milestone_ref'],producing_operation_id=m_op,raw=m_raw)
    settled=read_adopted_domain_operation_v1(db,namespace,p['previous_settlement_operation_id'])
    if settled is None or settled['original_digest']!=p['previous_settlement_original_digest']:raise ValueError('revision lost actual first partial settlement producer')
    completion=require_artifact_method_settlement_history_v2(db,namespace=namespace,original=settled,raw=settled['payload']['provenance']['artifact_method_completion'])
    a_op,a_raw=saved('artifact_task_amendment',p['amendment_original_ref'],p['amendment_original_digest'])
    amendment=decode_amendment_v1(a_raw)
    scope_op,scope_raw=saved('artifact_task_scope',p['task_scope_ref'],p['task_scope_digest'])
    scope=task_decode(scope_raw,IngressArtifactTaskScopeOriginalV1)
    producer=read_adopted_domain_operation_v1(db,namespace,scope_op)
    objective=task_decode(producer['payload']['provenance']['artifact_task_objective'],ArtifactTaskObjectiveV1)
    from .ingress_artifact_task_scope_v1 import require_task_scope_archive_v1
    require_task_scope_archive_v1(db,namespace=namespace,root=scope.root,producer=producer)
    require_amendment_history_v1(db,value=amendment,producer=producer,scope=scope,objective=objective)
    from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1,draft_from_wire_v1
    old_root=db.execute('SELECT payload_json FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
        (*namespace.as_tuple,'draft_root_capability',milestone.selector.task.root_registration_ref)).fetchone()
    if old_root is None:raise ValueError('revision history lost actual first physical file Root')
    previous_root=draft_from_wire_v1(json.loads(old_root[0]),DraftRootCapabilityV1)
    if (scope.root.root_identity,scope.root.resource_id,amendment.filename)!=(previous_root.root_identity,previous_root.resource_id,milestone.readback.filename):
        raise ValueError('revision history changed actual first full physical file identity')
    from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV3
    if (a_op!=scope_op or completion.state!='partial' or milestone.semantic_index!=1
            or completion.milestone_original_ref!=milestone.original_ref or scope.task_kind!='continue'
            or (amendment.c02_operation_id,amendment.root_registration_ref)!=(task.c02_operation_id,task.root_registration_ref)
            or amendment.objective_ref!=milestone.objective_ref or amendment.goal_ref!=completion.goal_ref
            or amendment.project_ref!=completion.project_ref
            or (type(scope) is not IngressArtifactTaskScopeOriginalV3 and original['payload']['owner_guard']!=plain_v1(milestone.owner_guard))
            or not settled['receipt'].commit_seq<producer['receipt'].commit_seq<original['receipt'].commit_seq):
        raise ValueError('task Plan revision bypassed ordinary amendment after actual partial milestone')
    keys={AtomKey.from_token(completion.plan_ref),project_checkpoint_key_v1(namespace,completion.project_ref)}
    versions=original['receipt'].write_versions
    if len(versions)!=2 or {v.key for v in versions}!=keys:raise ValueError('amended Plan must have its exact two same-W01 members')
    members={m.after.key:m for m in completion.members}
    for v in versions:
        old=members[v.key]
        if v.revision!=old.after.revision+1 or old.after not in original['read_versions']:
            raise ValueError('amendment Plan checkpoint did not consume exact partial before heads')
        row=db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',(v.key.token,v.revision)).fetchone()
        if row is None or row[0]!=original['receipt'].operation_id or row[2]!=1:raise ValueError('amendment revision member lost actual W01 history')
    plan_version=next(v for v in versions if v.key.type_name==PLAN_TYPE)
    plan_raw=json.loads(db.execute('SELECT value FROM graph_history WHERE token=? AND revision=?',(plan_version.key.token,plan_version.revision)).fetchone()[0])
    plan=decode_personal_plan_type_v1(PLAN_TYPE,plan_raw)
    checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,p['checkpoint'])
    cp_version=next(v for v in versions if v.key.type_name==CHECKPOINT_TYPE)
    cp_raw=db.execute('SELECT value FROM graph_history WHERE token=? AND revision=?',(cp_version.key.token,cp_version.revision)).fetchone()[0]
    if canonical_serialize(plain_v1(checkpoint))!=cp_raw:raise ValueError('revision checkpoint differs from its actual same-W01 member')
    old_cp_raw=db.execute('SELECT value FROM graph_history WHERE token=? AND revision=?',(cp_version.key.token,cp_version.revision-1)).fetchone()[0]
    old_cp=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,json.loads(old_cp_raw))
    candidates=artifact_task_initial_plan_candidates_v1(task)
    fresh_ids={node for _,_,node in candidates}
    retained={node.node_id for node in plan.nodes}-fresh_ids
    if (plan.state!='active' or plan.goal_ref!=completion.goal_ref or plan.goal_revision!=next(m.after.revision for m in completion.members if m.after.key.token==completion.goal_ref)
            or set(plan.candidate_refs)!={candidate for _,candidate,_ in candidates}
            or set(plan.method_candidates)!={(candidate,method) for method,candidate,_ in candidates}
            or retained!=set(old_cp.completed_node_refs) or amendment.source_ref not in plan.source_refs
            or checkpoint.revision!=cp_version.revision or checkpoint.state!='waiting' or checkpoint.next_step is not None
            or (checkpoint.completed_node_refs,checkpoint.progress_refs,checkpoint.work_version_refs)!=(old_cp.completed_node_refs,old_cp.progress_refs,old_cp.work_version_refs)
            or (checkpoint.plan_ref,checkpoint.plan_revision)!=(plan_version.key.token,plan.revision)
            or checkpoint.wait_condition is None or checkpoint.wait_condition.resume_job_ref!=task.cycle_job_ref
            or checkpoint.last_fact_versions!=plan.fact_versions):
        raise ValueError('amendment Plan refreshed foreign nodes, progress or checkpoint state')
    return plan,checkpoint



def validate_artifact_task_control_joins_v2(db):
    from .domain_production_originals_v1 import TABLE
    from .d10_project_checkpoint_v1 import (require_artifact_task_project_original_v1,
        require_artifact_task_checkpoint_original_v1,require_artifact_task_checkpoint_activation_original_v2)
    from ..runtime_contracts import NamespaceId
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone() is None:return
    kinds={'revise_artifact_task_plan_v2':require_artifact_task_plan_revision_original_v2,
        'create_artifact_task_project_v1':require_artifact_task_project_original_v1,
        'initialize_artifact_task_project_checkpoint_v1':require_artifact_task_checkpoint_original_v1,
        'activate_artifact_task_project_checkpoint_v1':require_artifact_task_checkpoint_original_v1,
        'activate_artifact_task_project_checkpoint_v2':require_artifact_task_checkpoint_activation_original_v2}
    for bot,persona,operation_id,kind in db.execute('SELECT bot,persona,operation_id,operation_kind FROM '+TABLE):
        if kind in kinds:
            namespace=NamespaceId(bot,persona)
            original=read_adopted_domain_operation_v1(db,namespace,operation_id)
            if original['payload']['coverage']=='complete':kinds[kind](db,namespace=namespace,original=original)
            elif original['receipt'].write_versions:raise ValueError('incomplete task control original cannot contain adopted control members')


def artifact_action_schema_parts_v1(*, namespace, goal, plan, node, entity_ref, identity,
        parameter_digest, action_key, cancel_key, adoption):
    """Pure final Action/schema construction shared by current compiler and locator."""
    from ..domains.d08.execution import GoalPredicate, RequiredCheckSpec
    from .d08_life_admission_v1 import PAIRS, life_criterion_ref_v1
    from .d11_artifact_draft_contract_v1 import POSTCONDITION_ID
    from .d11_life_contract_v1 import draft_artifact_ref_v1
    from .d11_offline_originals_v1 import _utc
    checks = tuple(RequiredCheckSpec(kind, provider, plan.actor_ref, action_key.name, "consolidation",
        life_criterion_ref_v1(kind, recipe_id="artifact_draft_v1"),
        (VersionedRef(life_criterion_ref_v1(kind, recipe_id="artifact_draft_v1"), 1),)) for kind, provider in PAIRS)
    predicate = GoalPredicate("artifact_verified", POSTCONDITION_ID, (
        ("artifact_ref", draft_artifact_ref_v1(namespace, identity.effect_id)),
        ("content_digest", adoption.content.content_digest), ("target_scope_digest", adoption.target.digest),
        ("build_digest", adoption.postcondition_build_digest)), adoption.recorded_at_utc,
        _utc(adoption.original_deadline_utc).timestamp())
    if (node.action_kind != "artifact_draft_v1" or node.success_predicate != predicate
            or predicate not in node.observable_postconditions or node.carried_forward_verified or node.pending_original_effects):
        raise ValueError("artifact Action requires its exact current unexecuted node postcondition")
    action = ActionIntent(action_key.name, 1, goal.goal_id, (), entity_ref, "artifact_draft_v1",
        "consolidation", "limited", parameter_digest, identity, "d10.artifact-draft.action.v1",
        checks, node.success_predicate, (dict(node.success_predicate.parameters)["artifact_ref"],), None, plan.source_refs)
    schema = ActionSchemaRecord.bind(action, ActionSchema(action.schema_id, action.action_kind, False, checks))
    return action, schema, (action_key, AtomKey(action_key.owner, "d08.action_schema.v1", schema.schema_ref), cancel_key)


def artifact_phase_action_schema_parts_v2(*, namespace, selector, goal, plan, entity_ref, identity,
        parameter_digest, adoption, target, roots):
    from ..domains.d08.execution import GoalPredicate, RequiredCheckSpec
    from .d08_life_admission_v1 import PAIRS, life_criterion_ref_v1
    from .d11_artifact_draft_contract_v1 import POSTCONDITION_ID
    from .d11_life_contract_v1 import draft_artifact_ref_v1
    from .d11_offline_originals_v1 import _utc
    ids = artifact_draft_file_ids_v2(selector)
    action_key, cancel_key = artifact_phase_action_keys_v2(selector)
    checks = tuple(RequiredCheckSpec(kind, provider, plan.actor_ref, ids["action"], "consolidation",
        life_criterion_ref_v1(kind, recipe_id="artifact_draft_v1"),
        (VersionedRef(life_criterion_ref_v1(kind, recipe_id="artifact_draft_v1"), 1),)) for kind, provider in PAIRS)
    artifact_ref = draft_artifact_ref_v1(namespace, ids["effect"])
    predicate = GoalPredicate("artifact_verified", POSTCONDITION_ID,
        (("artifact_ref", artifact_ref), ("content_digest", adoption.content.content_digest),
            ("target_scope_digest", target.digest), ("build_digest", adoption.postcondition_build_digest)),
        adoption.recorded_at_utc, _utc(adoption.original_deadline_utc).timestamp())
    action = ActionIntent(ids["action"], 1, goal.goal_id, (), entity_ref, "artifact_draft_v1", "consolidation", "limited",
        parameter_digest, identity, "d10.artifact-draft.phase-action.v2", checks, predicate, (artifact_ref,), None, roots)
    schema = ActionSchemaRecord.bind(action, ActionSchema(action.schema_id, action.action_kind, False, checks))
    return action, schema, (action_key, AtomKey(action_key.owner, "d08.action_schema.v1", schema.schema_ref), cancel_key)
