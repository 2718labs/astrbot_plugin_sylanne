"""Prospective fixed Artifact executor: real C4 paid content produces Action."""
from __future__ import annotations

from dataclasses import dataclass
from ..runtime_contracts import NamespaceId, canonical_digest
from ..graph_types import AtomKey
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d08.execution import GoalPredicate, ActionSchema, ActionSchemaRecord, _decode_goal
from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .domain_background_read_v3 import background_history_v3

PROSPECTIVE_KIND = "joint_artifact_prospective_binding_v1"


def artifact_joint_schema_contract_digest_v1():
    from .d11_artifact_draft_contract_v1 import RegisteredArtifactDraftRecipeV1
    from .d08_life_admission_v1 import PAIRS
    from ..model_broker.artifact_draft_v1 import TEMPLATE_DIGEST, TEMPLATE_DIGEST_V2
    return canonical_digest(("d10.joint-artifact-fixed-successor.v1", RegisteredArtifactDraftRecipeV1(),
        PAIRS, TEMPLATE_DIGEST, TEMPLATE_DIGEST_V2,
        "d10.artifact-draft.action.v1", "d10.artifact-draft.phase-action.v2"))


@dataclass(frozen=True, slots=True)
class JointArtifactProspectiveBindingV1:
    namespace: NamespaceId
    node_id: str
    plan_ref: str
    plan_revision: int
    owner_ref: str
    action_kind: str
    objective_ref: str
    objective_digest: str
    task_scope_ref: str
    task_scope_digest: str
    project_ref: str
    recipe_ref: str
    goal_ref: str
    goal_id: str
    target_ref: str
    target_entity_ref: str
    role_ref: str
    source_refs: tuple[str, ...]
    success_predicate: GoalPredicate
    executor: ArtifactJointExecutorV1
    parent_budget_lease_ref: str
    parent_grant_id: str
    parent_grant_version: int
    parent_grant_digest: str
    original_deadline_utc: float
    purpose: str
    audience: tuple[str, ...]
    installation_id: str
    manifest_digest: str
    algorithm_build_digest: str
    postcondition_build_digest: str
    schema_contract_digest: str
    schema: str = "d10.joint-artifact-prospective-binding.v1"

    def __post_init__(self):
        if (self.schema != "d10.joint-artifact-prospective-binding.v1" or type(self.namespace) is not NamespaceId
                or type(self.executor) is not ArtifactJointExecutorV1 or not self.node_id.startswith("task:")
                or self.owner_ref != "persona:" + self.namespace.persona_id or self.plan_revision < 1
                or self.action_kind != "artifact_draft_v1" or self.purpose != "consolidation"
                or not self.source_refs or len(self.source_refs) > 32 or len(set(self.source_refs)) != len(self.source_refs)
                or not self.audience or len(self.audience) > 32 or self.parent_grant_version < 1
                or self.schema_contract_digest != artifact_joint_schema_contract_digest_v1()
                or (self.success_predicate.kind, self.success_predicate.observation_provider) !=
                    ("domain_state", "d08.artifact_task_objective.v1")
                or self.success_predicate.parameters != (("objective_ref", self.objective_ref), ("objective_digest", self.objective_digest))
                or self.success_predicate.valid_until != self.original_deadline_utc):
            raise ValueError("prospective Artifact binding exceeds its registered objective/executor contract")
        for ref, kind in ((self.plan_ref, "d08.joint_plan.v1"), (self.project_ref, "d10.life_project.v1"),
                (self.recipe_ref, "d10.activity_recipe.v1"), (self.goal_ref, "d08.goal.v1"),
                (self.target_entity_ref, "d03.entity_anchor"), (self.role_ref, "d03.role_binding"),
                *((ref, "memory.source") for ref in self.source_refs)):
            key = AtomKey.from_token(ref)
            if key.type_name != kind or NamespaceId.from_key(key) != self.namespace:
                raise ValueError("prospective Artifact binding crossed actual typed controls")
        for digest in (self.objective_digest, self.task_scope_digest, self.parent_grant_digest,
                self.manifest_digest, self.algorithm_build_digest, self.postcondition_build_digest):
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("prospective Artifact binding requires actual original digests")

    @property
    def digest(self): return canonical_digest(plain_v1(self))
    @property
    def original_ref(self): return BINDING_PREFIX + self.digest
    @property
    def action_ref(self): return None
    @property
    def action_schema_ref(self): return None
    @property
    def progress_ref(self): return None


def artifact_prospective_read_inputs_v1(db, *, binding):
    from .artifact_task_observer_v1 import artifact_task_observer_read_inputs_v1
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    task = artifact_draft_task_selector_v1(binding.namespace, c02_operation_id=binding.executor.c02_operation_id, root_registration_ref=binding.executor.root_registration_ref)
    keys = [AtomKey.from_token(ref) for ref in (binding.goal_ref, binding.project_ref, binding.recipe_ref,
        binding.target_entity_ref, binding.role_ref, task.cycle_job_ref)]
    roots = list(binding.source_refs)
    originals = [binding.objective_ref, binding.task_scope_ref, binding.executor.root_registration_ref, binding.executor.c02_operation_id]
    phase = binding.executor.phase_selector
    if phase is not None:
        keys.extend((AtomKey.from_token(phase.decision_ref), AtomKey.from_token(phase.plan_ref)))
        if phase.prev_phase_original_ref is not None: originals.append(phase.prev_phase_original_ref)
    extra_keys, extra_roots, extra_originals = artifact_task_observer_read_inputs_v1(db, binding.namespace, binding.goal_ref)
    keys.extend(extra_keys); roots.extend(extra_roots); originals.extend(extra_originals)
    return tuple(dict.fromkeys(keys)), tuple(dict.fromkeys(roots)), tuple(dict.fromkeys(originals))


def qualify_artifact_prospective_binding_v1(db, *, frame, binding, issuer):
    from .d11_life_preparation_v1 import _read
    from .ingress_artifact_task_scope_v1 import ArtifactTaskObjectiveV1, IngressArtifactTaskScopeOriginalV1, _decode as task_decode, task_objective_goal_v1
    from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
    from .d11_offline_originals_v1 import _utc
    read = CurrentDomainReadV1(frame); read.check(db)
    if binding.namespace != frame.envelope.authority.namespace:
        raise ValueError("prospective Artifact binding belongs to another installed namespace")
    objective_row = _read(db, issuer=issuer, namespace=binding.namespace, kind="artifact_task_objective", ref=binding.objective_ref)
    scope_row = _read(db, issuer=issuer, namespace=binding.namespace, kind="artifact_task_scope", ref=binding.task_scope_ref)
    root_row = _read(db, issuer=issuer, namespace=binding.namespace, kind="draft_root_capability", ref=binding.executor.root_registration_ref)
    if objective_row is None or scope_row is None or root_row is None:
        raise MissingProductionOriginalV1("actual_registered_joint_artifact_objective_scope_root")
    objective = task_decode(objective_row[0], ArtifactTaskObjectiveV1)
    scope = task_decode(scope_row[0], IngressArtifactTaskScopeOriginalV1)
    root = draft_from_wire_v1(root_row[0], DraftRootCapabilityV1)
    if ((canonical_digest(objective_row[0]), canonical_digest(scope_row[0])) != (binding.objective_digest, binding.task_scope_digest)
            or (scope.objective_ref, scope.objective_digest, scope.c02_operation_id, scope.source_ref, scope.root.registration_ref) !=
               (binding.objective_ref, binding.objective_digest, binding.executor.c02_operation_id,
                binding.executor.source_ref, binding.executor.root_registration_ref)
            or scope.root != root or root.source_ref not in binding.source_refs
            or (objective.goal_ref, objective.project_ref, objective.recipe_ref, objective.installation_id, objective.manifest_digest) !=
               (binding.goal_ref, binding.project_ref, binding.recipe_ref, binding.installation_id, binding.manifest_digest)
            or task_objective_goal_v1(objective).satisfaction_predicate != binding.success_predicate
            or (root.owner_grant_ref, root.owner_grant_revision, root.owner_grant_digest) !=
               (frame.owner_guard.grant_ref, frame.owner_guard.grant_revision, frame.owner_guard.grant_digest)
            or binding.original_deadline_utc > min(objective.valid_until_utc, _utc(root.valid_until_utc).timestamp())):
        raise ValueError("prospective Artifact contract changed its admitted objective/root/Owner/deadline")
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    from .jobs import get_job
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    task = artifact_draft_task_selector_v1(binding.namespace, c02_operation_id=binding.executor.c02_operation_id, root_registration_ref=binding.executor.root_registration_ref)
    cycle = get_job(db, AtomKey.from_token(task.cycle_job_ref).name)
    if cycle is None: raise MissingProductionOriginalV1("actual_joint_artifact_causal_cycle")
    continuation = foreground_cycle_from_wire_v1(cycle.continuation)
    read.head(db, task.cycle_job_ref, required=True)
    if (continuation.c02_operation_id, continuation.source_ref, continuation.call_plan.parent_budget_lease_ref) != (binding.executor.c02_operation_id, binding.executor.source_ref, binding.parent_budget_lease_ref):
        raise ValueError("prospective Artifact contract changed actual causal Source/parent budget")
    grant = issuer.current_budget_grant(db, binding.parent_budget_lease_ref)
    if (grant.grant_id, grant.version, canonical_digest(grant)) != (binding.parent_grant_id, binding.parent_grant_version, binding.parent_grant_digest):
        raise MissingProductionOriginalV1("actual_joint_artifact_original_parent_grant")
    read.original(binding.objective_ref, digest=binding.objective_digest)
    read.original(binding.task_scope_ref, digest=binding.task_scope_digest)
    read.original(binding.executor.root_registration_ref, digest=canonical_digest(root_row[0]))
    read.original(binding.executor.c02_operation_id)
    for audience in binding.audience: read.source_family(db, binding.source_refs, purpose=binding.purpose, audience=audience)
    goal = _decode_goal(read.head(db, binding.goal_ref, required=True).value)
    if (goal.goal_id, goal.satisfaction_predicate) != (binding.goal_id, binding.success_predicate):
        raise ValueError("prospective Artifact goal changed its exact original objective")
    for ref in (binding.project_ref, binding.recipe_ref): read.head(db, ref, required=True)
    from ..domains.d03.context import EntityAnchor, RoleBinding, RoleBindingRequest, _tuple_payload
    from .d08_life_admission_v1 import _context_provider
    entity_atom = read.head(db, binding.target_entity_ref, required=True)
    role_atom = read.head(db, binding.role_ref, required=True)
    entity = EntityAnchor(**_tuple_payload(entity_atom.value, "creation_evidence_refs"))
    role = RoleBinding(**_tuple_payload(role_atom.value, "norm_refs", "source_refs"))
    role_request = RoleBindingRequest(binding.owner_ref, entity.entity_id, None, None, binding.action_kind, binding.purpose, frame.now_utc, True)
    if (entity.status != "active" or entity.entity_id != binding.target_ref or entity.kind != "activity"
            or binding.project_ref not in entity.creation_evidence_refs or entity.owner_scope != binding.owner_ref
            or role.target_entity_ref != binding.target_ref or role.subject_persona_ref != binding.owner_ref
            or not role.applies_to(role_request) or _context_provider(db, read).resolve_role_binding(role_request, (role,)).status != "complete"):
        raise MissingProductionOriginalV1("actual_current_joint_artifact_role")
    if goal.state == "abandoned" or frame.now_utc >= binding.original_deadline_utc: return None, "cancelled"
    if binding.executor.phase_selector is not None:
        require_artifact_joint_phase_successor_v1(db, binding=binding, selector=binding.executor.phase_selector, issuer=issuer)
    return None, "current"


def require_artifact_joint_phase_successor_v1(db, *, binding, selector, issuer):
    from .d11_artifact_draft_model_v1 import _read_artifact_phase_selected_originals_v2
    first = binding.executor.phase_selector
    if type(selector) is not ArtifactDraftPhaseSelectorV2 or first is None:
        raise ValueError("prospective Artifact phase requires its actual registered method")
    if (selector.task, selector.decision_ref, selector.decision_revision, selector.decision_digest,
            selector.plan_ref, selector.plan_revision, selector.plan_digest, selector.method_ref) != (
            first.task, first.decision_ref, first.decision_revision, first.decision_digest,
            first.plan_ref, first.plan_revision, first.plan_digest, first.method_ref):
        raise ValueError("Artifact successor changed its exact selected task/method")
    if selector.phase_index < first.phase_index: raise ValueError("Artifact successor precedes the consented phase")
    _read_artifact_phase_selected_originals_v2(db, selector=selector, issuer=issuer)
    if selector.prev_phase_original_ref is not None:
        from .d11_life_preparation_v1 import _read
        from .d11_artifact_draft_content_v1 import ArtifactDraftPhaseVerifiedOriginalV2, artifact_draft_phase_verification_from_wire_v2
        saved = _read(db, issuer=issuer, namespace=binding.namespace, kind="c4_phase_verified", ref=selector.prev_phase_original_ref)
        if saved is None or canonical_digest(saved[0]) != selector.prev_phase_original_digest:
            raise MissingProductionOriginalV1("actual_joint_artifact_preceding_phase_verification")
        verified = artifact_draft_phase_verification_from_wire_v2(saved[0], ArtifactDraftPhaseVerifiedOriginalV2)
        if (verified.selector.task, verified.selector.method_ref, verified.selector.phase_index) != (selector.task, selector.method_ref, selector.phase_index - 1):
            raise ValueError("Artifact successor changed its verified immediate preceding phase")


def require_artifact_joint_action_successor_v1(db, *, frame, binding, selector, candidate, issuer):
    from .joint_node_execution_v1 import require_current_joint_binding_gate_v1
    from .d08_personal_plan_v1 import artifact_phase_action_keys_v2, artifact_draft_action_keys_v1
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v2, artifact_draft_file_ids_v1
    from .d11_artifact_draft_contract_v1 import POSTCONDITION_ID, DraftActivityScopeV1, draft_from_wire_v1
    from .d11_life_contract_v1 import draft_artifact_ref_v1
    from .d11_offline_originals_v1 import _utc
    from .d11_life_preparation_v1 import _read
    require_current_joint_binding_gate_v1(db, frame=frame, binding=binding, issuer=issuer)
    if type(selector) is ArtifactDraftPhaseSelectorV2:
        require_artifact_joint_phase_successor_v1(db, binding=binding, selector=selector, issuer=issuer)
        ids = artifact_draft_file_ids_v2(selector); expected_key = artifact_phase_action_keys_v2(selector)[0]
    else:
        if binding.executor.phase_selector is not None: raise ValueError("Artifact V1 writer cannot consume a phase contract")
        ids = artifact_draft_file_ids_v1(binding.namespace, c02_operation_id=selector.c02_operation_id, root_registration_ref=selector.root_registration_ref)
        expected_key = artifact_draft_action_keys_v1(binding.namespace, c02_operation_id=selector.c02_operation_id, root_registration_ref=selector.root_registration_ref)[0]
    action, schema, adoption = candidate.action, candidate.action_schema, candidate.adoption
    target = adoption.target
    if (candidate.keys[0] != expected_key or action.identity.effect_id != ids["effect"]
            or action.identity.operation_id != ids["action_operation"] or action.identity.attempt_id != ids["attempt"]
            or action.goal_ref != binding.goal_id or action.target_ref != binding.target_ref
            or action.action_kind != binding.action_kind or action.purpose != binding.purpose
            or (candidate.project_key.token, candidate.recipe_key.token) != (binding.project_ref, binding.recipe_ref)
            or target.root_registration_ref != binding.executor.root_registration_ref or adoption.task_source.ref != binding.executor.source_ref
            or adoption.algorithm_build_digest != binding.algorithm_build_digest or adoption.postcondition_build_digest != binding.postcondition_build_digest
            or _utc(adoption.original_deadline_utc).timestamp() > binding.original_deadline_utc
            or schema != ActionSchemaRecord.bind(action, ActionSchema(schema.schema_id, schema.action_kind, schema.proactive, schema.required_checks))
            or (action.success_predicate.kind, action.success_predicate.observation_provider) != ("artifact_verified", POSTCONDITION_ID)
            or dict(action.success_predicate.parameters) != {"artifact_ref": draft_artifact_ref_v1(binding.namespace, ids["effect"]),
                "content_digest": adoption.content.content_digest, "target_scope_digest": target.digest, "build_digest": binding.postcondition_build_digest}):
        raise ValueError("actual Artifact Action escaped its consented prospective executor contract")
    scope_row = _read(db, issuer=issuer, namespace=binding.namespace, kind="activity_scope", ref=adoption.activity_scope_ref)
    scope = draft_from_wire_v1(scope_row[0], DraftActivityScopeV1)
    if scope.parent_budget_lease_ref != binding.parent_budget_lease_ref: raise ValueError("Artifact successor changed its original parent budget")
    return binding


def completed_artifact_joint_objective_v1(db, *, frame, binding, issuer):
    from .artifact_task_observer_v1 import ArtifactTaskObservationV1, ArtifactTaskObservationV2, read_current_artifact_task_milestone_v2
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1, CHECKPOINT_TYPE, decode_project_checkpoint_type_v1
    from .d10_project_checkpoint_v1 import InstalledD10ProjectReadersV1
    read = CurrentDomainReadV1(frame)
    goal_atom = read.head(db, binding.goal_ref, required=True); goal = _decode_goal(goal_atom.value)
    if goal.state != "satisfied": return None
    history = background_history_v3(db, goal_atom.key.token, goal_atom.revision, columns=("event_id",))
    producer = None if history is None else read_adopted_domain_operation_v1(db, binding.namespace, history[0])
    if producer is None or (producer["domain"], producer["operation_kind"]) != ("d08", "settle_personal_goal"):
        raise MissingProductionOriginalV1("actual_joint_artifact_objective_settlement_writer")
    raw = producer["payload"]["provenance"]["task_observation"]
    kind = ArtifactTaskObservationV2 if raw["schema"] == "d08.artifact-task-observation.v2" else ArtifactTaskObservationV1
    observation = decode_typed_production_value_v1(raw, kind)
    cp = read.head(db, project_checkpoint_key_v1(binding.namespace, binding.project_ref), required=True)
    checkpoint = decode_project_checkpoint_type_v1(CHECKPOINT_TYPE, cp.value)
    if ((observation.objective_ref, observation.objective_digest, observation.goal_ref, observation.project_ref,
            observation.phase, observation.checkpoint) != (binding.objective_ref, binding.objective_digest,
            binding.goal_ref, binding.project_ref, "satisfied", checkpoint)
            or checkpoint.state != "completed" or checkpoint.next_step is not None or not checkpoint.progress_refs
            or goal.satisfaction_predicate != binding.success_predicate):
        raise ValueError("Joint Artifact objective lacks its current satisfied same-project proof")
    effects = InstalledD10ProjectReadersV1(issuer=issuer)
    for progress_ref in checkpoint.progress_refs:
        proof = effects.read_effect(db, frame, progress_ref)
        if not proof.completed_verified or (proof.project_ref, proof.recipe_ref) != (binding.project_ref, binding.recipe_ref):
            raise ValueError("Joint Artifact objective lacks actual verified project effects")
    if kind is ArtifactTaskObservationV2:
        for milestone in observation.milestones:
            if read_current_artifact_task_milestone_v2(db, namespace=binding.namespace, original_ref=milestone.original_ref, issuer=issuer) != milestone:
                raise ValueError("Joint Artifact objective milestone changed its real file proof")
    return goal_atom.key.token


from .joint_node_execution_v1 import ArtifactJointExecutorV1, BINDING_PREFIX


@dataclass(frozen=True, slots=True)
class JointArtifactActualActionV1:
    action: object
    action_schema: object
    adoption: object
    keys: tuple[AtomKey, ...]
    project_key: AtomKey
    recipe_key: AtomKey


def require_installed_artifact_joint_contract_v1(binding, *, readers):
    from ..authority_service.named_joint_binding_body_v1 import require_named_joint_installed_artifact_v1
    if require_named_joint_installed_artifact_v1(binding,readers):return
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelRuntimeV1
    from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
    graph = readers.role_clock_reader.graph
    runtime = graph._GraphCoordinator__artifact_draft_model_runtime_v1
    if type(runtime) is not InstalledArtifactDraftModelRuntimeV1:
        raise MissingProductionOriginalV1("actual_installed_joint_artifact_runtime")
    policy = runtime.bundle.installation_policy
    build = read_installed_d11_life_build_v1(runtime.authority_client._package_root, policy.manifest_digest, recipe_id="artifact_draft_v1")
    if ((policy.namespace, policy.installation_id, policy.manifest_digest) != (binding.namespace, binding.installation_id, binding.manifest_digest)
            or (build["algorithm_build_digest"], build["postcondition_build_digest"]) != (binding.algorithm_build_digest, binding.postcondition_build_digest)):
        raise ValueError("prospective Artifact binding changed actual installed build")


def joint_artifact_binding_for_adopted_action_v1(db, *, namespace, action_ref, issuer):
    from .joint_node_execution_v1 import _joint_head_v1, joint_artifact_binding_for_selector_v1
    from .domain_background_read_v3 import background_json_loads_v3
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d11_artifact_draft_content_v1 import ArtifactDraftContentAdoptionV1, ArtifactDraftContentAdoptionV2
    atom = _joint_head_v1(db, namespace, action_ref)
    if atom is None or not atom[2]: return None
    history = background_history_v3(db, action_ref, atom[0], columns=("event_id",))
    producer = None if history is None else read_adopted_domain_operation_v1(db, namespace, history[0])
    if producer is None or producer["domain"] != "d08": return None
    provenance = producer["payload"]["provenance"]
    if producer["operation_kind"] == "propose_artifact_draft_phase_action_v2":
        raw = provenance["artifact_phase_content_adoption"]; kind = ArtifactDraftContentAdoptionV2
    elif producer["operation_kind"] == "propose_artifact_draft_action":
        raw = provenance["artifact_content_adoption"]; kind = ArtifactDraftContentAdoptionV1
    else: return None
    adoption = decode_typed_production_value_v1(raw, kind)
    binding = joint_artifact_binding_for_selector_v1(db, selector=adoption.selector, issuer=issuer)
    if type(binding) is not JointArtifactProspectiveBindingV1: return None
    from ..domains.d08.execution import _decode_intent
    action = _decode_intent(background_json_loads_v3(atom[1]))
    if (action.goal_ref, action.target_ref, action.action_kind, action.purpose, adoption.task_source.ref,
            provenance["artifact_project_ref"], provenance["artifact_recipe_ref"], adoption.target.root_registration_ref) != (
            binding.goal_id, binding.target_ref, binding.action_kind, binding.purpose, binding.executor.source_ref,
            binding.project_ref, binding.recipe_ref, binding.executor.root_registration_ref):
        raise ValueError("actual adopted Artifact Action differs from its prospective contract")
    return binding
