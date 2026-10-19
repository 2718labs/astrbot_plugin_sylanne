"""Installed prospective D08 qualification through immutable D02/D03/D05 inputs."""
from __future__ import annotations
from contextlib import contextmanager
from dataclasses import dataclass
import json
from contextvars import ContextVar
from weakref import WeakKeyDictionary
from ..domains.d02 import BodyDomain, BodyState, BodyProfile, BodyReservation, WorkComponent
from ..domains.d02.body_quote_original import FixedBodyPolicyV1
from ..domains.d03.context import RoleBinding, RoleBindingRequest, ContextProvider, _tuple_payload
from ..domains.d05.relationship import BoundaryRule, RelationshipProvider, _tuple_payload as boundary_payload
from ..domains.d08.personal_candidate_v1 import (
    PrepareCurrentPersonalCandidatesRequestV1, CurrentPersonalCandidateEligibilityV1,
    SourceNoteCandidateBindingV1, ArtifactPhaseCandidateBindingV1,
    ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3)
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .domain_production_contracts_v1 import (
    ProductionOriginalRefV1, ProductionOwnerGuardV1, ProductionQueryCoverageV1, ProductionPolicyRefV1)
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d02_production_operations_v1 import SettledBodyEffectPolicyV1
PREPARE = "prepare_personal_candidate_eligibility_v1"
ADOPT = "adopt_personal_candidate_eligibility_v1"
_ISSUER = object()
_ACTIVE_RESULTS = {}
_PINNED_CANDIDATE_REQUEST = ContextVar("sylanne_personal_eligibility_request", default=None)
def personal_eligibility_operation_id_v1(namespace, request, *, need_digest, prepare=False):
    return ("personal-eligibility-prepare:" if prepare else "personal-eligibility-adopt:") + canonical_digest(
        (namespace, request.selection_operation_id, request.plan_ref, request.expected_plan_revision,
         request.goal_ref, request.expected_goal_revision, request.need_qualification_original_ref, need_digest,
         request.value_evaluation_operation_id, tuple(binding.digest for binding in request.bindings)))[:48]

def read_personal_need_digest_v1(db, namespace, request):
    from .owner_source_note_need_v1 import read_owner_source_note_need_original_v2
    from .d08_personal_candidate_v1 import _personal_ingress_need_locator_v1
    owner = read_owner_source_note_need_original_v2(db, namespace=namespace,
        original_ref=request.need_qualification_original_ref)
    if owner is not None: return owner[1]["original_digest"]
    actual = _personal_ingress_need_locator_v1(db, namespace, request)
    if actual is None: raise MissingProductionOriginalV1("actual_original_personal_need_digest")
    return actual[1]["original_digest"]
def personal_eligibility_request_id_v1(db, namespace, request, *, prepare=False):
    return personal_eligibility_operation_id_v1(namespace, request,
        need_digest=read_personal_need_digest_v1(db, namespace, request), prepare=prepare)

@dataclass(frozen=True, slots=True)
class PersonalEligibilityRequestV1:
    candidates: PrepareCurrentPersonalCandidatesRequestV1
    def __post_init__(self):
        if type(self.candidates) is not PrepareCurrentPersonalCandidatesRequestV1:
            raise TypeError("eligibility consumes the exact actual prospective candidate recipe")

@dataclass(frozen=True, slots=True)
class PersonalBodyStateV1:
    profile_id: str
    version: int
    energy: float
    fatigue: tuple[tuple[str,float], ...]
    load: float
    cursor: float


@dataclass(frozen=True, slots=True)
class PersonalFixedBodyPolicyV1:
    policy_id: str
    version: int
    profile: BodyProfile
    initial_state: PersonalBodyStateV1
    work_kind: str
    component: WorkComponent
    valid_until: float


def immutable_body_state_v1(state):
    return PersonalBodyStateV1(state.profile_id,state.version,state.energy,tuple(sorted(state.fatigue.items())),
        state.load,state.cursor)


def immutable_fixed_body_policy_v1(policy):
    return None if policy is None else PersonalFixedBodyPolicyV1(policy.policy_id,policy.version,policy.profile,
        immutable_body_state_v1(policy.initial_state),policy.work_kind,policy.component,policy.valid_until)


def personal_body_state_for_calculation_v1(state):
    return BodyState(state.profile_id,state.version,state.energy,dict(state.fatigue),state.load,state.cursor)


@dataclass(frozen=True, slots=True)
class PersonalBodyInputV1:
    profile: BodyProfile
    state: PersonalBodyStateV1
    reservations: tuple[BodyReservation, ...]
    policy: PersonalFixedBodyPolicyV1 | None
    effect_policy: SettledBodyEffectPolicyV1 | None
@dataclass(frozen=True, slots=True)
class PersonalRoleInputV1:
    request: RoleBindingRequest
    bindings: tuple[RoleBinding, ...]
    roles: tuple[str, ...]
    norms: tuple[str, ...]
@dataclass(frozen=True, slots=True)
class PersonalBoundaryInputV1:
    subject_persona_ref: str
    target_entity_ref: str
    action_kind: str
    audiences: tuple[str, ...]
    at_time: float
    rules: tuple[BoundaryRule, ...]

@dataclass(frozen=True, slots=True)
class PersonalCandidateDiscriminatorContractV1:
    recipe_id: str
    recipe_version: int
    selection_semantics_digest: str
    numeric_discriminator: str = "not_required"
    schema: str = "d08.personal-candidate-discriminator.v1"

    def __post_init__(self):
        if self.schema != "d08.personal-candidate-discriminator.v1" or self.numeric_discriminator != "not_required":
            raise ValueError("unregistered actual candidate discriminator contract")
        _require_immutable_v1(self)


def read_personal_candidate_discriminator_contract_v1(db, *, read, binding, plan, node):
    from .d08_life_admission_v1 import _adopted
    if type(binding) is SourceNoteCandidateBindingV1:
        from .d11_life_contract_v1 import RECIPE_ID
        recipe = read.head(db,binding.recipe_ref,required=True); _adopted(db,read,recipe)
        if (recipe.value["recipe_id"],recipe.value["version"],recipe.value["reality"],tuple(recipe.value["allowed_steps"])) != (
                RECIPE_ID,1,"real_execution",("source_note",)):
            raise MissingProductionOriginalV1("actual_registered_SourceNote_selection_discriminator_contract")
        recipe_id,version,sequence = RECIPE_ID,1,("source_note",)
    elif type(binding) in {ArtifactPhaseCandidateBindingV1,ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3}:
        from ..domains.d01 import FULL_DRAFT_METHOD_V1,TONE_SAMPLE_METHOD_V1
        from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2
        if binding.method_ref not in {FULL_DRAFT_METHOD_V1,TONE_SAMPLE_METHOD_V1} or dict(plan.method_candidates).get(binding.candidate_ref) != binding.method_ref:
            raise MissingProductionOriginalV1("actual_registered_Artifact_selection_discriminator_contract")
        recipe_id,version,sequence = binding.method_ref,1,artifact_draft_phase_sequence_v2(binding.method_ref)
        if sequence[binding.phase_index] != binding.phase_kind:
            raise ValueError("candidate discriminator contract selected another registered phase")
    else:
        raise MissingProductionOriginalV1("actual_registered_personal_selection_discriminator_contract")
    semantic = canonical_digest(("hard_feasibility_then_current_evidence_preference.v1",recipe_id,version,sequence,
        plan.plan_id,plan.revision,binding.digest,node.node_id,node.action_kind))
    return PersonalCandidateDiscriminatorContractV1(recipe_id,version,semantic)


@dataclass(frozen=True, slots=True)
class PersonalCandidateInputV1:
    candidate_ref: str
    node_id: str
    parameter_digest: str
    body: PersonalBodyInputV1
    role: PersonalRoleInputV1
    boundary: PersonalBoundaryInputV1
    irreversible_exposure: int
    established_deadline: float | None
    established_commitment: bool
    pending_original_effects: tuple[str, ...]
    carried_forward_verified: tuple[str, ...]
    numeric_discriminator_unresolved: bool
    recovery_branch: bool
    discriminator_contract: PersonalCandidateDiscriminatorContractV1
@dataclass(frozen=True, slots=True)
class PreparedPersonalEligibilityWaveV1:
    namespace: NamespaceId
    request_digest: str
    selection_operation_id: str
    plan_head: GraphVersion
    goal_head: GraphVersion
    need_original: ProductionOriginalRefV1
    source_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    policies: tuple[ProductionPolicyRefV1, ...]
    owner_guard: ProductionOwnerGuardV1
    activation_generation: int
    access_epoch: int
    delete_epoch: int
    parent_budget_lease_ref: str
    storage_selection_digest: str
    storage_instance_id: str
    cancel_generations: tuple[tuple[str, int], ...]
    original_deadline_utc: float
    candidates: tuple[PersonalCandidateInputV1, ...]
    schema: str = "d08.personal-eligibility-wave.v1"
    def __post_init__(self):
        if (self.schema != "d08.personal-eligibility-wave.v1" or type(self.candidates) is not tuple
                or not 1 <= len(self.candidates) <= 6 or any(type(row) is not PersonalCandidateInputV1 for row in self.candidates)
                or len({row.candidate_ref for row in self.candidates}) != len(self.candidates)
                or any(not page.complete for page in self.query_coverage)):
            raise ValueError("eligibility wave requires exact finite candidates and complete negative scopes")
        _require_immutable_v1(self)
def _require_immutable_v1(value):
    from dataclasses import fields, is_dataclass
    if value is None or type(value) in {str, int, float, bool}:
        return
    if type(value) is tuple:
        for item in value: _require_immutable_v1(item)
        return
    if is_dataclass(value) and type(value).__dataclass_params__.frozen:
        for field in fields(value): _require_immutable_v1(getattr(value, field.name))
        return
    raise TypeError("eligibility executor input contains mutable or untyped material")

@dataclass(frozen=True, slots=True)
class PersonalProjectionCPUObservationV1:
    domain: str
    input_digest: str
    scope: str
    thread_cpu_ns: int
    elapsed_ns: int
    accounting_basis: str = "unbilled_qualification_overhead"
    schema: str = "d08.personal-projection-cpu-observation.v1"
    def __post_init__(self):
        if (self.schema!="d08.personal-projection-cpu-observation.v1" or self.domain not in {"d02","d03","d05"}
                or self.scope != "projection" or self.accounting_basis != "unbilled_qualification_overhead"
                or type(self.thread_cpu_ns) is not int or self.thread_cpu_ns<0
                or type(self.elapsed_ns) is not int or self.elapsed_ns<0):
            raise ValueError("actual domain computation CPU observation fields differ")
        _require_immutable_v1(self)

@dataclass(frozen=True, slots=True)
class PersonalProjectionResultV1:
    domain: str
    input_digest: str
    statuses: tuple[tuple[str, str], ...]
    cpu_observation: PersonalProjectionCPUObservationV1
    def __post_init__(self):
        if (self.domain not in {"d02", "d03", "d05"} or type(self.cpu_observation) is not PersonalProjectionCPUObservationV1
                or (self.cpu_observation.domain,self.cpu_observation.input_digest)!=(self.domain,self.input_digest)):
            raise ValueError("unregistered prospective eligibility domain/CPU input commitment")
        _require_immutable_v1(self)
@dataclass(frozen=True, slots=True)
class PersonalProjectionExecutionLimitV1:
    original_deadline_utc: float
    monotonic_deadline: float

    def __post_init__(self):
        import math
        if not all(type(value) in (int, float) and math.isfinite(value)
                for value in (self.original_deadline_utc, self.monotonic_deadline)):
            raise ValueError("projection requires its actual original finite time bounds")

    def require_current_v1(self):
        from time import monotonic
        if monotonic() >= self.monotonic_deadline:
            raise MissingProductionOriginalV1("original_personal_projection_deadline_expired")


def _compute_personal_projection_semantics_v1(domain, inputs, *, execution_limit=None):
    """Finite CPU computation; no Graph, reader, SQL, callback, claim or model."""
    rows = []
    for candidate_ref, packet in inputs:
        if execution_limit is not None:
            execution_limit.require_current_v1()
        if domain == "d02":
            if packet.policy is None or packet.policy.component.duration_rate != 0:
                status = "WAIT_COST_EVIDENCE"
            else:
                admission = BodyDomain.check_work_start(personal_body_state_for_calculation_v1(packet.state), packet.reservations,
                    additional_cost=packet.policy.component.fixed_cost)
                status = "eligible" if admission.status == "clear" else (
                    "WAIT_ORIGINAL_EFFECT" if admission.status == "pending_confirmation" else "WAIT_BUDGET")
        elif domain == "d03":
            provider = ContextProvider()
            provider.compile_scheme({"schema": "d03.context.scheme.v1", "roles": packet.roles, "norms": packet.norms}, None)
            resolution = provider.resolve_role_binding(packet.request, packet.bindings)
            status = "eligible" if resolution.status == "complete" else "REQUIRED_CHECK_UNRESOLVED"
        elif domain == "d05":
            checks = tuple(RelationshipProvider().provide_required_check(
                subject_persona_ref=packet.subject_persona_ref, target_entity_ref=packet.target_entity_ref,
                action_kind=packet.action_kind, audience_scope=audience, scene_ref=None,
                at_time=packet.at_time, rules=packet.rules, coverage_complete=True) for audience in packet.audiences)
            status = "REJECTED" if any(check.result == "deny" for check in checks) else (
                "eligible" if all(check.result == "pass" for check in checks) else "REQUIRED_CHECK_UNRESOLVED")
        else:
            raise ValueError("unregistered pure projection route")
        rows.append((candidate_ref, status))
    return domain,canonical_digest(inputs),tuple(rows)


def compute_personal_projection_v1(domain, inputs, *, execution_limit):
    """Observe the actual worker computation; observation is never a paid receipt."""
    from time import thread_time_ns,perf_counter_ns
    execution_limit.require_current_v1()
    started_cpu,started_elapsed=thread_time_ns(),perf_counter_ns()
    domain,input_digest,rows=_compute_personal_projection_semantics_v1(
        domain, inputs, execution_limit=execution_limit)
    execution_limit.require_current_v1()
    observation=PersonalProjectionCPUObservationV1(domain,input_digest,"projection",
        thread_time_ns()-started_cpu,perf_counter_ns()-started_elapsed)
    return PersonalProjectionResultV1(domain,input_digest,rows,observation)

def personal_projection_inputs_v1(wave, domain):
    field = {"d02": "body", "d03": "role", "d05": "boundary"}[domain]
    return tuple((candidate.candidate_ref, getattr(candidate, field)) for candidate in wave.candidates)
def _candidate_target_v1(namespace, binding):
    if type(binding) is SourceNoteCandidateBindingV1:
        return binding.project_ref, binding.target_entity_ref, binding.role_binding_ref, "source_note", "d10.life.source_note.v1", 0
    from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1
    from .d03_life_project_context_v1 import life_project_context_keys_v1
    project = artifact_goal_plan_keys_v1(namespace, c02_operation_id=binding.task.c02_operation_id,
        root_registration_ref=binding.task.root_registration_ref)[2]
    entity, role = life_project_context_keys_v1(namespace, project.token)
    from .d11_artifact_draft_contract_v1 import WORK_KIND
    return project.token, entity.token, role.token, "artifact_draft_v1", WORK_KIND, 2
def freeze_personal_eligibility_wave_v1(db, *, frame, request, readers):
    """Run only under the actual W01 current transaction and installed issuer."""
    from .d08_personal_candidate_v1 import _plan_goal, _need, read_current_personal_value_evaluation_v1, _artifact_scope, prospective_personal_decision_key_v1
    from .d08_life_admission_v1 import _adopted, _context_provider, _source_rights
    from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
    from ..domains.d03.context import EntityAnchor
    from .budget import require_budget_family_admissible
    readers.current()
    read = CurrentDomainReadV1(frame); read.check(db)
    base = request.candidates
    plan_atom, goal_atom, plan, goal, nodes = _plan_goal(db, read, base, installed_readers=readers)
    need = _need(db, read, readers, base, plan_atom, goal_atom)
    evaluation = read_current_personal_value_evaluation_v1(db, read, base, plan.candidate_refs, installed_readers=readers)
    ns = frame.envelope.authority.namespace
    require_budget_family_admissible(db, frame.envelope.parent_budget_lease_ref)
    grant = readers.issuer.current_budget_grant(db, frame.envelope.parent_budget_lease_ref)
    deadline = min(frame.envelope.deadline_utc, need.original_deadline_utc, grant.valid_until_utc)
    body_reader = InstalledD02ProductionReadersV1(issuer=readers.issuer,
        body_quote_authority=readers.graph._GraphCoordinator__body_quote_authority,
        role_clock_reader=readers.graph._GraphCoordinator__d04_semantic_mapping_reader)
    profile, state, reservations = body_reader._current_body(db, read)
    context = _context_provider(db, read)
    inventories = {name: read.complete_inventory(db, name) for name in (
        "d03.role_binding", "d05.boundary_rule", "d08.commitment.v1", "d08.action_intent.v1", "d08.action_outcome.v1")}
    roles = tuple(RoleBinding(**_tuple_payload(atom.value, "norm_refs", "source_refs"))
        for atom in inventories["d03.role_binding"] if atom.valid)
    rules = tuple(BoundaryRule(**boundary_payload(atom.value, "source_refs", "communicated_refs",
        "acknowledged_refs", "exception_refs")) for atom in inventories["d05.boundary_rule"] if atom.valid)
    for atom in tuple(atom for rows in inventories.values() for atom in rows if atom.valid):
        _adopted(db, read, atom)
    packets = []
    for binding in base.bindings:
        node = nodes[binding.node_id]
        project_ref, entity_ref, role_ref, kind, work_kind, risk = _candidate_target_v1(ns, binding)
        if type(binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}:
            _artifact_scope(db, read, readers, binding, plan)
        entity_atom = read.head(db, entity_ref, required=True); _adopted(db, read, entity_atom)
        entity = EntityAnchor(**_tuple_payload(entity_atom.value, "creation_evidence_refs"))
        role_atom = read.head(db, role_ref, required=True); _adopted(db, read, role_atom)
        selected_role = RoleBinding(**_tuple_payload(role_atom.value, "norm_refs", "source_refs"))
        if (entity.status != "active" or entity.owner_scope != plan.actor_ref
                or project_ref not in entity.creation_evidence_refs or selected_role.target_entity_ref != entity.entity_id
                or selected_role.subject_persona_ref != plan.actor_ref or selected_role.group_ref is not None
                or selected_role.scene_ref is not None):
            raise MissingProductionOriginalV1("actual_exact_candidate_target_and_role")
        role_request = RoleBindingRequest(plan.actor_ref, entity.entity_id, None, None, kind,
            "consolidation", frame.now_utc, True)
        from dataclasses import replace
        relevant_roles = tuple(role for role in roles if role.applies_to(replace(role_request,at_time=max(frame.now_utc,role.effective_from))))
        for role in relevant_roles:
            _source_rights(db, read, role.source_refs, frame.envelope.authority.audience)
            if role.effective_until is not None: deadline = min(deadline, role.effective_until)
        relevant_rules = tuple(rule for rule in rules if any(rule.applies_to(
            subject_persona_ref=plan.actor_ref, target_entity_ref=entity.entity_id, action_kind=kind,
            audience_scope=audience, scene_ref=None, at_time=max(frame.now_utc,rule.valid_from)) for audience in frame.envelope.authority.audience))
        for rule in relevant_rules:
            _source_rights(db, read, rule.source_refs, frame.envelope.authority.audience)
            if rule.valid_until is not None: deadline = min(deadline, rule.valid_until)
        _source_rights(db, read, plan.source_refs, frame.envelope.authority.audience)
        if type(binding) is SourceNoteCandidateBindingV1:
            from .owner_source_note_need_v1 import read_owner_source_note_need_original_v2
            from .owner_source_note_task_v1 import read_owner_source_note_task_authorization_v2
            selected_need = read_owner_source_note_need_original_v2(db, namespace=ns,
                original_ref=base.need_qualification_original_ref)
            if selected_need is None:
                read_legacy_source_note_authorization_for_candidates_v1(db,frame=frame,request=base,readers=readers)
                selected_policy = None  # No V1 signed CPU/Body binding exists; compute emits WAIT_COST_EVIDENCE.
            else:
                authorization = read_owner_source_note_task_authorization_v2(db, namespace=ns,
                    original_ref=selected_need[0].authorization_original_ref, issuer=readers.issuer)
                if authorization is None:
                    raise MissingProductionOriginalV1("actual_signed_source_note_body_policy_selection")
                selected_policy = authorization[0].body_policy
                policy_id, policy_version = selected_policy.body_policy_id, selected_policy.body_policy_version
                effect_ref, effect_revision = selected_policy.effect_policy_ref, selected_policy.effect_policy_revision
        else:
            selected_policy = readers.bundle.artifact_draft.body_policy
            if selected_policy is not None:
                policy_id, policy_version = selected_policy.policy_ref, selected_policy.policy_version
                effect_ref, effect_revision = selected_policy.effect_component_policy_ref, selected_policy.effect_component_policy_version
        policy, effect_policy = None, None
        if selected_policy is not None:
            policy = body_reader.body_quote_authority.policy(db, ns,
                policy_id, policy_version)
            if policy.profile != profile or policy.work_kind != work_kind:
                raise ValueError("prospective Body policy is not its actual recipe/profile component")

        if policy is not None:
            if state.cursor >= policy.valid_until:
                raise MissingProductionOriginalV1("unexpired_current_body_role_cursor_policy")
            effect_row = db.execute("SELECT payload_json,payload_digest,signature FROM graph_d02_production_policies_v1 "
                "WHERE bot=? AND persona=? AND policy_ref=? AND revision=? AND kind='effect'",
                (*ns.as_tuple, effect_ref, effect_revision)).fetchone()
            if effect_row is None: raise MissingProductionOriginalV1("actual_pinned_body_effect_component_policy")
            readers.issuer._signer.verify("d11.d02-production-policy.v1", effect_row[0], effect_row[2])
            raw_effect = json.loads(effect_row[0])
            if canonical_digest(raw_effect) != effect_row[1]:
                raise ValueError("actual prospective effect policy changed its signed original")
            raw_effect["namespace"] = NamespaceId(**raw_effect["namespace"])
            effect_policy = SettledBodyEffectPolicyV1(**raw_effect)
            if (effect_policy.profile_id, effect_policy.work_kind, effect_policy.component_id) != (
                    profile.profile_id, work_kind, policy.component.component_id):
                raise ValueError("prospective Body execution component changed its exact recipe association")
        actions = tuple(atom for atom in inventories["d08.action_intent.v1"] if atom.valid
            and atom.value["goal_ref"] == goal.goal_id and atom.value["target_ref"] == entity.entity_id
            and atom.value["action_kind"] == kind)
        action_ids = {atom.value["action_id"] for atom in actions}
        outcomes = tuple(atom for atom in inventories["d08.action_outcome.v1"] if atom.valid and atom.value["action_id"] in action_ids)
        pending = {atom.value["identity"]["effect_id"] for atom in actions
            if not any(outcome.value["action_id"] == atom.value["action_id"] for outcome in outcomes)}
        pending.update(outcome.value["effect_id"] for outcome in outcomes if outcome.value["unknown_effects"]
            or outcome.value["result_level"] not in {"completed_verified", "failed_verified", "not_dispatched"})
        verified = {outcome.value["effect_id"] for outcome in outcomes
            if outcome.value["result_level"] == "completed_verified" and not outcome.value["unknown_effects"]}
        if not set(node.carried_forward_verified) <= verified or not set(node.pending_original_effects) <= pending:
            raise MissingProductionOriginalV1("actual_bound_candidate_carried_and_unknown_effects")
        bound_commitment_refs = {ref for action in actions for ref in action.value["commitment_refs"]}
        bound_commitment_refs.update(version.ref for version in plan.fact_versions if AtomKey.from_token(version.ref).type_name == "d08.commitment.v1")
        commitments = tuple(atom for atom in inventories["d08.commitment.v1"] if atom.valid
            and atom.key.token in bound_commitment_refs and atom.value["subject_ref"] == plan.actor_ref
            and atom.value["counterparty_ref"] == entity.entity_id
            and atom.value["establishment_state"] in {"communicated", "acknowledged"}
            and atom.value["fulfillment_state"] not in {"fulfilled", "withdrawn"})
        established_deadlines = []
        if goal.deadline_ref is not None:
            deadline_atom = read.head(db,goal.deadline_ref,required=True)
            _adopted(db,read,deadline_atom)
            value = deadline_atom.value["deadline_utc"]
            if type(value) is str:
                from .d11_offline_originals_v1 import _utc
                value = _utc(value).timestamp()
            established_deadlines.append(value)
        for atom in commitments:
            _source_rights(db, read, tuple(atom.value["source_refs"]), frame.envelope.authority.audience)
            if atom.value["deadline_ref"] is not None:
                value = read.head(db, atom.value["deadline_ref"], required=True).value["deadline_utc"]
                if type(value) is str:
                    from .d11_offline_originals_v1 import _utc
                    value = _utc(value).timestamp()
                established_deadlines.append(value)
        packets.append(PersonalCandidateInputV1(binding.candidate_ref, binding.node_id, binding.digest,
            PersonalBodyInputV1(profile, immutable_body_state_v1(state), tuple(reservations), immutable_fixed_body_policy_v1(policy), effect_policy),
            PersonalRoleInputV1(role_request, relevant_roles, tuple(sorted(context._roles)), tuple(sorted(context._norms))),
            PersonalBoundaryInputV1(plan.actor_ref, entity.entity_id, kind, frame.envelope.authority.audience,
                frame.now_utc, relevant_rules), risk, min(established_deadlines) if established_deadlines else None,
            bool(commitments), tuple(sorted(pending)), tuple(sorted(verified)),
            False, node.action_kind in {"ask", "narrow", "wait"},
            read_personal_candidate_discriminator_contract_v1(db,read=read,binding=binding,plan=plan,node=node)))
    if frame.now_utc >= deadline: raise MissingProductionOriginalV1("unexpired_original_personal_eligibility_deadline")
    return PreparedPersonalEligibilityWaveV1(ns, canonical_digest(base), base.selection_operation_id,
        GraphVersion(plan_atom.key, plan_atom.revision), GraphVersion(goal_atom.key, goal_atom.revision),
        need.original, plan.source_refs, tuple(version for version in frame.snapshot.versions
            if version.key.type_name not in ("runtime.job", "d11.semantic_tick.v1") and version.key != prospective_personal_decision_key_v1(ns, frame.envelope.identity.activity_id,
                    base.selection_operation_id, base.plan_ref)),
        frame.query_coverage, frame.installed_policy_refs,
        frame.owner_guard, frame.activation_generation, frame.envelope.version_guard.access_epoch,
        frame.envelope.version_guard.delete_epoch, frame.envelope.parent_budget_lease_ref,
        _actual_storage_selection_v1(db)[0],
        _actual_storage_selection_v1(db)[1],
        tuple((atom.key.token, atom.value["cancel_epoch"]) for atom in frame.snapshot.atoms if atom.key.type_name == "runtime.job" and atom.valid),
        deadline, tuple(packets))

def _actual_storage_selection_v1(db):
    from ..runtime_storage_v3 import runtime_storage_v3
    actual = runtime_storage_v3(db)
    if actual is None: raise ValueError("personal eligibility requires its actual selected ordinary storage")
    return actual.selection_digest, actual.instance

def _personal_input_heap_v1(value, seen=None):
    from dataclasses import fields, is_dataclass
    import sys
    if seen is None: seen = set()
    if id(value) in seen: return 0
    seen.add(id(value))
    size = sys.getsizeof(value)
    if type(value) in (tuple,list):
        return size + sum(_personal_input_heap_v1(item, seen) for item in value)
    if type(value) is dict:
        return size + sum(_personal_input_heap_v1(key,seen)+_personal_input_heap_v1(item,seen) for key,item in value.items())
    if is_dataclass(value):
        storage = getattr(value, "__dict__", None)
        return size + (0 if storage is None else sys.getsizeof(storage)) + sum(
            _personal_input_heap_v1(getattr(value, field.name), seen) for field in fields(value))
    return size

def stage_prepare_personal_candidate_eligibility_v1(db, *, frame, request, installed_readers):
    wave = freeze_personal_eligibility_wave_v1(db, frame=frame, request=request, readers=installed_readers)
    if frame.envelope.identity.operation_id != personal_eligibility_operation_id_v1(wave.namespace, request.candidates, need_digest=wave.need_original.original_digest, prepare=True):
        raise ValueError("eligibility preparation changed its original deterministic identity")
    from .current_method_learning_read_v3 import _method_active
    owner = _method_active(db)
    if owner is None: raise ValueError("eligibility preparation requires its actual retained method Work")
    owner.operation.retain(_personal_input_heap_v1(wave) * 3 + 4096)
    owner.personal_eligibility_wave_v1 = wave
    return _stage_personal_mesh_result_v1(db,frame,PREPARE,request,wave,{"personal_eligibility_inputs":wave})
@dataclass(frozen=True, slots=True)
class CompletedPersonalEligibilityWaveV1:
    input_digest: str
    projections: tuple[PersonalProjectionResultV1, ...]
    def __post_init__(self):
        if (type(self.projections) is not tuple or tuple(row.domain for row in self.projections) != ("d02", "d03", "d05")
                or any(row.cpu_observation.scope!="projection" for row in self.projections)):
            raise ValueError("actual eligibility wave needs its three exact finite domains")
        _require_immutable_v1(self)
@contextmanager
def bind_completed_personal_eligibility_v1(graph, wave, results):
    if type(wave) is not PreparedPersonalEligibilityWaveV1 or results.input_digest != canonical_digest(wave):
        raise ValueError("actual pure results changed their original qualified immutable input")
    runtime = graph._GraphCoordinator__domain_production_runtime_v1
    if runtime in _ACTIVE_RESULTS: raise ValueError("one actual serial eligibility adoption at a time")
    _ACTIVE_RESULTS[runtime] = (wave, results)
    try: yield
    finally: _ACTIVE_RESULTS.pop(runtime)
def _read_prepared_wave_v1(db, namespace, request):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    ref = personal_eligibility_request_id_v1(db, namespace, request.candidates, prepare=True)
    original = read_adopted_domain_operation_v1(db, namespace, ref)
    if original is None or (original["domain"], original["operation_kind"]) != ("d08", PREPARE):
        raise MissingProductionOriginalV1("actual_adopted_personal_eligibility_preparation")
    if original["payload"]["request"] != plain_v1(request):
        raise ValueError("eligibility preparation changed its exact candidate recipe")
    wave = decode_typed_production_value_v1(original["payload"]["provenance"]["personal_eligibility_inputs"],
        PreparedPersonalEligibilityWaveV1)
    return wave, original
def _current_wave_v1(db, *, frame, request, readers, wave, original):
    from .d08_personal_candidate_v1 import _current_evidence
    read = CurrentDomainReadV1(frame); read.check(db)
    ns = frame.envelope.authority.namespace
    guard = frame.envelope.version_guard
    if (wave.namespace != ns or wave.request_digest != canonical_digest(request.candidates)
            or wave.selection_operation_id != request.candidates.selection_operation_id
            or wave.owner_guard != frame.owner_guard or wave.activation_generation != frame.activation_generation
            or (wave.access_epoch, wave.delete_epoch) != (guard.access_epoch, guard.delete_epoch)
            or wave.parent_budget_lease_ref != frame.envelope.parent_budget_lease_ref
            or frame.now_utc >= wave.original_deadline_utc):
        raise MissingProductionOriginalV1("current_same_personal_eligibility_root_owner_budget_deadline")
    current_need = readers.need_qualification_reader(db=db, frame=frame, request=request.candidates)
    if (current_need.original.kind,current_need.original.original_ref,current_need.original.original_digest) != (
            wave.need_original.kind,wave.need_original.original_ref,wave.need_original.original_digest):
        raise MissingProductionOriginalV1("same_actual_current_personal_need_original")
    _current_evidence(db, read, (current_need.original,), wave.read_versions, wave.query_coverage)
    for policy in wave.policies:
        if policy not in frame.installed_policy_refs:
            raise MissingProductionOriginalV1("current_exact_personal_eligibility_policy")
    if (wave.storage_selection_digest, wave.storage_instance_id) != _actual_storage_selection_v1(db):
        raise MissingProductionOriginalV1("same_selected_personal_eligibility_storage")
    for ref, generation in wave.cancel_generations:
        if read.head(db, ref, required=True).value["cancel_epoch"] != generation:
            raise MissingProductionOriginalV1("same_actual_personal_eligibility_cancel_generation")
    current_need = readers.need_qualification_reader(db=db, frame=frame, request=request.candidates)
    if (not current_need.complete
            or current_need.new_c3_required or current_need.meaningful_gaps):
        raise MissingProductionOriginalV1("same_actual_current_personal_need_without_new_model")
    read.source_family(db, wave.source_refs, purpose="consolidation")
    from .budget import require_budget_family_admissible
    require_budget_family_admissible(db, wave.parent_budget_lease_ref)
    grant = readers.issuer.current_budget_grant(db, wave.parent_budget_lease_ref)
    if frame.now_utc >= grant.valid_until_utc:
        raise MissingProductionOriginalV1("original_personal_eligibility_parent_grant_expired")
    authority = readers.graph._GraphCoordinator__body_quote_authority
    for packet in wave.candidates:
        policy = packet.body.policy
        if policy is not None:
            if immutable_fixed_body_policy_v1(authority.policy(db, ns, policy.policy_id, policy.version)) != policy:
                raise MissingProductionOriginalV1("same_actual_signed_personal_body_policy")
            effect = packet.body.effect_policy
            row = db.execute("SELECT payload_json,payload_digest,signature FROM graph_d02_production_policies_v1 "
                "WHERE bot=? AND persona=? AND policy_ref=? AND revision=? AND kind='effect'",
                (*ns.as_tuple, effect.policy_ref, effect.revision)).fetchone()
            if row is None or canonical_digest(plain_v1(effect)) != row[1]:
                raise MissingProductionOriginalV1("same_actual_body_effect_component_policy")
            readers.issuer._signer.verify("d11.d02-production-policy.v1", row[0], row[2])
            if json.loads(row[0]) != plain_v1(effect):
                raise ValueError("actual signed prospective body effect changed")
        from dataclasses import replace
        current_role_request = replace(packet.role.request,at_time=frame.now_utc)
        for role in packet.role.bindings:
            if role.applies_to(packet.role.request) != role.applies_to(current_role_request):
                raise MissingProductionOriginalV1("original_personal_role_time_window_changed")
            if role.applies_to(packet.role.request) and role.source_refs:
                read.source_family(db, role.source_refs, purpose="consolidation")
        for rule in packet.boundary.rules:
            for audience in packet.boundary.audiences:
                arguments = dict(subject_persona_ref=packet.boundary.subject_persona_ref, target_entity_ref=packet.boundary.target_entity_ref, action_kind=packet.boundary.action_kind, audience_scope=audience, scene_ref=None)
                if rule.applies_to(**arguments,at_time=packet.boundary.at_time) != rule.applies_to(**arguments,at_time=frame.now_utc):
                    raise MissingProductionOriginalV1("original_personal_boundary_time_window_changed")
            if any(rule.applies_to(subject_persona_ref=packet.boundary.subject_persona_ref,
                    target_entity_ref=packet.boundary.target_entity_ref, action_kind=packet.boundary.action_kind,
                    audience_scope=audience, scene_ref=None, at_time=packet.boundary.at_time)
                    for audience in packet.boundary.audiences) and rule.source_refs:
                read.source_family(db, rule.source_refs, purpose="consolidation")
def stage_adopt_personal_candidate_eligibility_v1(db, *, frame, request, installed_readers):
    readers = installed_readers.current()
    wave, original = _read_prepared_wave_v1(db, frame.envelope.authority.namespace, request)
    runtime = readers.graph._GraphCoordinator__domain_production_runtime_v1
    active = _ACTIVE_RESULTS.get(runtime)
    if active is None or active[0] != wave:
        raise MissingProductionOriginalV1("actual_installed_terminal_personal_projection_wave")
    results = active[1]
    _current_wave_v1(db, frame=frame, request=request, readers=readers, wave=wave, original=original)
    if frame.envelope.identity.operation_id != personal_eligibility_operation_id_v1(wave.namespace, request.candidates, need_digest=wave.need_original.original_digest):
        raise ValueError("eligibility adoption changed its original deterministic identity")
    expected = tuple(_compute_personal_projection_semantics_v1(domain, personal_projection_inputs_v1(wave, domain)) for domain in ("d02", "d03", "d05"))
    if (results.input_digest != canonical_digest(wave) or
            tuple((p.domain,p.input_digest,p.statuses) for p in results.projections) !=
            expected):
        raise ValueError("eligibility output differs from its exact registered pure domain operators")
    prepared_original = ProductionOriginalRefV1("d08.current-" + PREPARE,
        "d08-current:" + original["original_digest"][:48], original["original_digest"])
    rows = []
    for packet in wave.candidates:
        statuses = tuple(dict(projection.statuses)[packet.candidate_ref] for projection in results.projections)
        priority = ("REJECTED", "WAIT_ORIGINAL_EFFECT", "WAIT_COST_EVIDENCE", "WAIT_BUDGET", "REQUIRED_CHECK_UNRESOLVED")
        status = next((status for status in priority if status in statuses), "eligible")
        if packet.pending_original_effects: status = "WAIT_ORIGINAL_EFFECT"
        rows.append(CurrentPersonalCandidateEligibilityV1(packet.candidate_ref, packet.node_id,
            packet.parameter_digest, status, (wave.need_original, prepared_original), wave.read_versions,
            wave.query_coverage, packet.irreversible_exposure, packet.established_deadline,
            packet.established_commitment, packet.pending_original_effects, packet.carried_forward_verified,
            packet.numeric_discriminator_unresolved, packet.recovery_branch))
    return _stage_personal_mesh_result_v1(db,frame,ADOPT,request,wave,
        {"prepared_eligibility_digest":original["original_digest"],"projection_wave":results,"eligibilities":tuple(rows)},results=results)
class InstalledCurrentPersonalEligibilityReaderV1:
    def __init__(self, issuer, readers):
        if issuer is not _ISSUER: raise TypeError("eligibility requires its actual installed personal-reader factory")
        self.readers = readers
    def __call__(self, *, db, frame, binding, plan, goal, need):
        self.readers.current()
        original_ref = self._request_for_frame_v1(db, frame, binding, plan, goal, need)
        original, request = original_ref
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        wave, prepared = _read_prepared_wave_v1(db, frame.envelope.authority.namespace, request)
        _current_wave_v1(db, frame=frame, request=request, readers=self.readers, wave=wave, original=prepared)
        read = CurrentDomainReadV1(frame)
        read.original("d08-current:" + original["original_digest"][:48],
            kind="d08.current-" + ADOPT, digest=original["original_digest"])
        rows = tuple(decode_typed_production_value_v1(raw, CurrentPersonalCandidateEligibilityV1)
            for raw in original["payload"]["provenance"]["eligibilities"])
        outcome = PersonalMeshOutcomeV1(PERSONAL_MESH_ROUTES_V1[-1],
            ProductionOriginalRefV1("d08.current-" + ADOPT,"d08-current:" + original["original_digest"][:48],original["original_digest"]),canonical_digest(wave),rows)
        found = tuple(row for row in outcome.eligibilities if (row.candidate_ref, row.node_id, row.parameter_digest) ==
            (binding.candidate_ref, binding.node_id, binding.digest))
        if len(found) != 1: raise MissingProductionOriginalV1("exact_actual_adopted_personal_eligibility")
        from dataclasses import replace
        row = found[0]
        # A legal carrier update changes only this comparison view of the
        # authenticated Need original; the saved eligibility remains immutable.
        return replace(row, originals=tuple(need.original if (
            original.kind,original.original_ref,original.original_digest) == (
                need.original.kind,need.original.original_ref,need.original.original_digest) else original
            for original in row.originals))
    def _request_for_frame_v1(self, db, frame, binding, plan, goal, need):
        active = _PINNED_CANDIDATE_REQUEST.get()
        if active is None or active[0] is not self.readers or active[2] is not frame:
            raise ValueError("eligibility requires its exact actual current W01 candidate compiler")
        base = active[1]
        if (base.plan_ref, base.expected_plan_revision, base.goal_ref, base.expected_goal_revision,
                base.need_qualification_original_ref) != (
                need.plan_head.key.token, need.plan_head.revision, need.goal_head.key.token,
                need.goal_head.revision, need.original.original_ref):
            raise ValueError("eligibility reader changed the actual pinned Plan/Goal/Need request")
        if not any(row.digest == binding.digest for row in base.bindings):
            raise ValueError("candidate is outside the exact pinned eligibility request")
        operation = personal_eligibility_request_id_v1(db, frame.envelope.authority.namespace, base)
        original = read_adopted_domain_operation_v1(db, frame.envelope.authority.namespace, operation)
        if original is None or (original["domain"], original["operation_kind"]) != ("d08", ADOPT):
            raise MissingProductionOriginalV1("actual_exact_adopted_personal_eligibility")
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        request = decode_typed_production_value_v1(original["payload"]["request"], PersonalEligibilityRequestV1)
        if request.candidates != base:
            raise ValueError("adopted eligibility changed its exact full pinned request")
        return original, request
    def read_plan_inputs_v1(self, *, db, namespace, activity_id, request):
        operation = personal_eligibility_request_id_v1(db, namespace, request)
        original = read_adopted_domain_operation_v1(db, namespace, operation)
        extra = personal_eligibility_input_plan_v1(db, namespace=namespace, request=request)
        if original is None: return extra
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        typed = decode_typed_production_value_v1(original["payload"]["request"], PersonalEligibilityRequestV1)
        if typed.candidates != request: raise ValueError("pinned eligibility changed its exact actual candidate request")

        wave, preparation = _read_prepared_wave_v1(db, namespace, typed)
        return production_read_plan_v1(tuple(sorted(set((*extra.fixed_type_ids, *(p.type_id for p in wave.query_coverage))))),
            tuple(sorted(set((*extra.exact_keys, *(v.key for v in wave.read_versions))), key=lambda key: key.token)),
            tuple(sorted(set((*extra.source_roots, *wave.source_refs)))),
            tuple(sorted(set((*extra.required_original_refs, operation,
                personal_eligibility_request_id_v1(db, namespace, request, prepare=True))))))
@contextmanager
def bind_actual_personal_candidate_request_v1(readers, request, frame):
    if type(request) is not PrepareCurrentPersonalCandidatesRequestV1:
        raise TypeError("actual personal candidate compiler request required")
    token = _PINNED_CANDIDATE_REQUEST.set((readers, request, frame))
    try: yield
    finally: _PINNED_CANDIDATE_REQUEST.reset(token)
def install_current_personal_eligibility_reader_v1(readers):
    return InstalledCurrentPersonalEligibilityReaderV1(_ISSUER, readers)
def personal_eligibility_input_plan_v1(db, *, namespace, request):
    from .d12_current_domain_selection_v1 import read_current_domain_selection_v1
    from .d12_domain_scheme_compile_v1 import CONTEXT_SCHEME_FIELD
    keys, roots = [], []
    goal_row = db.execute("SELECT value FROM graph_atoms WHERE token=? AND valid=1",(request.goal_ref,)).fetchone()
    if goal_row is not None:
        goal = json.loads(goal_row[0])
        if goal["deadline_ref"] is not None: keys.append(AtomKey.from_token(goal["deadline_ref"]))
    for binding in request.bindings:
        project, entity, role, kind, work, risk = _candidate_target_v1(namespace, binding)
        keys.extend((AtomKey.from_token(entity), AtomKey.from_token(role), AtomKey.from_token(project)))
        if type(binding) is SourceNoteCandidateBindingV1: keys.append(AtomKey.from_token(binding.recipe_ref))
        if type(binding) is SourceNoteCandidateBindingV1: roots.append(binding.source_ref)
    version, _, _ = read_current_domain_selection_v1(db, namespace, domain="d03", field_name=CONTEXT_SCHEME_FIELD)
    keys.append(version.key)
    types = ("d02.body_state.v1", "d02.body_profile.v1", "d02.reservation.v1", "d03.role_binding",
        "d05.boundary_rule", "d08.commitment.v1", "d08.action_intent.v1", "d08.action_outcome.v1")
    for name in ("d03.role_binding", "d05.boundary_rule", "d08.commitment.v1"):
        rows = db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? AND valid=1 "
            "ORDER BY token LIMIT 129", (*namespace.as_tuple, name)).fetchall()
        if len(rows) > 128: raise MissingProductionOriginalV1("complete_personal_eligibility_input_inventory")
        target_ids = set()
        for binding in request.bindings:
            entity_ref = _candidate_target_v1(namespace, binding)[1]
            found = db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND token=? AND valid=1",
                (*namespace.as_tuple, entity_ref)).fetchone()
            if found is not None: target_ids.add(json.loads(found[0])["entity_id"])
        for encoded, in rows:
            value = json.loads(encoded)
            target = value.get("target_entity_ref") if name != "d08.commitment.v1" else value["counterparty_ref"]
            if target not in target_ids and not (name == "d03.role_binding" and target is None): continue
            roots.extend(value.get("source_refs", ()))
            if name == "d08.commitment.v1" and value["deadline_ref"] is not None:
                keys.append(AtomKey.from_token(value["deadline_ref"]))
    return production_read_plan_v1(types, keys, tuple(sorted(set(roots))))
def read_plan_personal_eligibility_v1(db, *, namespace, activity_id, operation_kind, request, readers):
    from .d08_personal_candidate_v1 import read_plan_personal_candidates_v1
    plan = read_plan_personal_candidates_v1(db, namespace=namespace, activity_id=activity_id,
        request=request.candidates, operation_id=personal_eligibility_request_id_v1(db, namespace, request.candidates, prepare=True),
        installed_readers=readers, include_eligibility=False)
    extra = personal_eligibility_input_plan_v1(db, namespace=namespace, request=request.candidates)
    originals = tuple(plan.required_original_refs)
    if operation_kind == ADOPT:
        originals += (personal_eligibility_request_id_v1(db, namespace, request.candidates, prepare=True),)
    return production_read_plan_v1(tuple(sorted(set((*plan.fixed_type_ids, *extra.fixed_type_ids)))),
        tuple(sorted(set((*plan.exact_keys, *extra.exact_keys)), key=lambda key: key.token)),
        tuple(sorted(set((*plan.source_roots, *extra.source_roots)))), tuple(sorted(set(originals))))

from weakref import WeakSet
_ISSUED_WAVES = WeakSet()


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False)
class IssuedPersonalEligibilityWaveV1:
    wave: PreparedPersonalEligibilityWaveV1
    prepare_receipt: object
    graph: object
    installation_bundle: object
    authorization_original_ref: str | None
    execution_limit: PersonalProjectionExecutionLimitV1
    already_adopted_original: ProductionOriginalRefV1 | None = None
    prepare_original: ProductionOriginalRefV1 | None = None
    retention_operation: object = None
    mesh_audience: tuple[str, ...] = ()
    storage_generation: int = 0


def issue_prepared_personal_eligibility_result_v1(graph, bundle, work, result, authorization_original_ref=None):
    from .domain_production_originals_v1 import _receipt
    wave = work.state.personal_eligibility_wave_v1
    expected = personal_eligibility_operation_id_v1(wave.namespace,
        work.state.request.candidates, need_digest=wave.need_original.original_digest, prepare=True)
    require_personal_mesh_route_v1(PERSONAL_MESH_ROUTES_V1[-2])
    receipt = _receipt(result["receipt"])
    if (result.get("coverage") != "complete" or receipt.status != "committed"
            or receipt.operation_id != expected or result["operation_kind"] != PREPARE
            or work.operation is not work.state.operation or work.operation.closed):
        raise ValueError("eligibility output requires its actual original prepared adoption and same retained Work")
    notice = PersonalMeshEvidenceNoticeV1(PERSONAL_MESH_ROUTES_V1[-2],expected,
        ProductionOriginalRefV1("d08.current-" + PREPARE,"d08-current:" + result["original_digest"][:48],result["original_digest"]),canonical_digest(wave))
    if notice.operation_id != receipt.operation_id: raise ValueError("mesh notice and actual same Work receipt differ")
    from .current_method_learning_read_v3 import (
        BorrowedMethodLearningReadV3, PreparedPersonalEligibilityRecoveryReadV1)
    state = work.state
    if type(state) is BorrowedMethodLearningReadV3:
        envelope = state.selected_envelope
        if wave.original_deadline_utc > envelope.deadline_utc:
            raise ValueError("projection cannot extend its original prepared envelope")
        monotonic_deadline = envelope.monotonic_deadline - (envelope.deadline_utc - wave.original_deadline_utc)
    elif type(state) is PreparedPersonalEligibilityRecoveryReadV1:
        monotonic_deadline = state.initial_monotonic_deadline
    else:
        raise ValueError("projection has no actual hot or cold prepared Work")
    execution_limit = PersonalProjectionExecutionLimitV1(wave.original_deadline_utc, monotonic_deadline)
    execution_limit.require_current_v1()
    issued = IssuedPersonalEligibilityWaveV1(wave, receipt, graph, bundle, authorization_original_ref,
        execution_limit,result.get("eligibility_recovery_outcome"),notice.original,work.operation,
        tuple(state.audiences) if type(state) is BorrowedMethodLearningReadV3 else tuple(state.issued.audiences),
        work.operation.handle.context.storage_generation)
    _ISSUED_WAVES.add(issued)
    return issued


def require_issued_personal_eligibility_v1(graph, bundle, issued):
    if (type(issued) is not IssuedPersonalEligibilityWaveV1 or issued not in _ISSUED_WAVES
            or issued.graph is not graph or issued.installation_bundle is not bundle
            or graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not bundle):
        raise ValueError("actual immutable eligibility handoff changed its installed producer")
    return issued.wave


def consume_completed_personal_eligibility_v1(graph, bootstrap, bundle, *, issued, results, candidates,
        c02_operation_id=None, source_ref=None, selector=None):
    from ..graph_worker import GraphStorageWorkV3
    require_personal_mesh_route_v1(PERSONAL_MESH_ROUTES_V1[-1])
    wave = require_issued_personal_eligibility_v1(graph, bundle, issued)
    if (wave.request_digest != canonical_digest(candidates) or candidates.selection_operation_id != wave.selection_operation_id
            or results.input_digest != canonical_digest(wave)):
        raise ValueError("eligibility adoption changed its original candidate request")
    request = PersonalEligibilityRequestV1(candidates)
    if issued.authorization_original_ref is None:
        _require_personal_foreground_selector_v3(selector,bundle,ADOPT,request,
            c02_operation_id=c02_operation_id,source_ref=source_ref)
        if selector.operation_id!=personal_eligibility_operation_id_v1(wave.namespace,candidates,
                need_digest=wave.need_original.original_digest):
            raise ValueError("eligibility adoption selector changed its original fixed operation")
    else:
        if selector is not None:raise ValueError("Owner SourceNote eligibility retains its actual Owner selector factory")
        selector = graph._owner_source_note_task_selector_v1(bootstrap, bundle,
            authorization_original_ref=issued.authorization_original_ref, operation_kind=ADOPT, request=request,
            operation_id=personal_eligibility_operation_id_v1(wave.namespace, candidates,
                need_digest=wave.need_original.original_digest))
    runtime = graph._GraphCoordinator__domain_production_runtime_v1
    with bind_completed_personal_eligibility_v1(graph,wave,results):
        result=runtime.run_personal_mesh_current_v1(selector=personal_mesh_request_v1(selector,request),
            operation_kind=ADOPT,request=request)
        if type(result)is GraphStorageWorkV3 and not has_borrowed_personal_eligibility_results_v3(result.state):
            raise ValueError("actual borrowed adoption did not retain its completed projection materials")
    return result


async def run_installed_personal_eligibility_wave_v1(runtime, installation, *, candidates,
        c02_operation_id=None, source_ref=None, authorization_original_ref=None):
    """One finite ready wave; its original eight-MiB lease spans every future."""
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    from ..graph_worker import OwnedGraphStorageResultV3
    worker, bootstrap, bundle = runtime._worker, runtime._v2_bootstrap, installation.admin_bundle
    request = PersonalEligibilityRequestV1(candidates)

    async def foreground_selector(kind):
        from .artifact_host_control_metadata_v3 import (ArtifactForegroundMetadataSelectorV3,
            prepare_current_artifact_foreground_metadata_v3)
        policy=bundle.installation_policy
        locator=ArtifactForegroundMetadataSelectorV3(policy.namespace,policy.installation_id,
            c02_operation_id,source_ref,kind,request)
        raw=await worker.call(lambda graph:prepare_current_artifact_foreground_metadata_v3(
            graph,bootstrap,bundle,selector=locator))
        selector=runtime._consume_background_graph_result_v3(raw)
        _require_personal_foreground_selector_v3(selector,bundle,kind,request,
            c02_operation_id=c02_operation_id,source_ref=source_ref)
        return selector

    prepare_selector=await foreground_selector(PREPARE)if authorization_original_ref is None else None
    def prepare(graph):
        from ..graph_worker import GraphStorageWorkV3
        actual = graph._GraphCoordinator__domain_production_runtime_v1
        if authorization_original_ref is None:
            selector=prepare_selector
            _require_personal_foreground_selector_v3(selector,bundle,PREPARE,request,
                c02_operation_id=c02_operation_id,source_ref=source_ref)
            work = actual.run_personal_mesh_current_v1(selector=personal_mesh_request_v1(selector,request), operation_kind=PREPARE, request=request)
        else:
            store = graph._GraphCoordinator__store
            with store._lock:
                db = store._db; db.execute("BEGIN")
                try: operation = personal_eligibility_request_id_v1(db, bundle.installation_policy.namespace, candidates, prepare=True)
                finally: db.rollback()
            selector = graph._owner_source_note_task_selector_v1(bootstrap, bundle,
                authorization_original_ref=authorization_original_ref, operation_kind=PREPARE, request=request, operation_id=operation)
            work = actual.run_personal_mesh_current_v1(selector=personal_mesh_request_v1(selector,request), operation_kind=PREPARE, request=request)
        if type(work) is not GraphStorageWorkV3:
            raise MissingProductionOriginalV1("actual_retained_personal_eligibility_prepare_work")
        work.map_terminal_v3("issuer",
            lambda result: issue_prepared_personal_eligibility_result_v1(graph, bundle, work, result, authorization_original_ref),
            lambda error: (_ for _ in ()).throw(error))
        return work
    raw = await worker.call(prepare)
    if type(raw) is not OwnedGraphStorageResultV3:
        raise TypeError("actual eligibility wave input requires its same owned Graph retention lease")
    issued, retention = raw.take_value_v3()
    raw = None
    futures, results, wave = (), None, None
    try:
        wave = issued.wave
        if issued.already_adopted_original is not None:
            runtime._personal_domain_mesh_catalog_v1 = installed_personal_mesh_catalog_v1(wave)
            return {"status":"eligibility_adopted","operation_id":personal_eligibility_operation_id_v1(wave.namespace,candidates,need_digest=wave.need_original.original_digest),"recovery":"existing_actual_adoption"}
        issued.execution_limit.require_current_v1()
        pool = runtime._personal_eligibility_executor_v1
        if pool is None:
            pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="sylanne-domain-projection")
            runtime._personal_eligibility_executor_v1 = pool
        submitted = []
        try:
            for domain in ("d02", "d03", "d05"):
                issued.execution_limit.require_current_v1()
                route = next(route for route in PERSONAL_MESH_ROUTES_V1 if route.receiver == domain and route.kind == "projectionRequest")
                message = PersonalProjectionRequestMessageV1(route, canonical_digest(wave),
                    personal_projection_inputs_v1(wave,domain), issued.execution_limit)
                from .domain_mesh_messages_v1 import issue_personal_mesh_projection_v1,compute_registered_mesh_personal_projection_v1
                packet = issue_personal_mesh_projection_v1(issued,message)
                submitted.append(asyncio.wrap_future(pool.submit(compute_registered_mesh_personal_projection_v1,packet)))
                packet = None
                message = None
        finally:
            futures = tuple(submitted)
            submitted.clear()
        # Cancellation never detaches in-flight inputs from their physical lease.
        completed = asyncio.gather(*futures, return_exceptions=True)
        try:
            projected = await asyncio.shield(completed)
        except asyncio.CancelledError:
            await asyncio.shield(completed)
            raise
        failure = next((item for item in projected if isinstance(item, BaseException)), None)
        if failure is not None: raise failure
        from .domain_mesh_messages_v1 import consume_registered_mesh_personal_projection_v1
        projected = tuple(consume_registered_mesh_personal_projection_v1(packet,wave) for packet in projected)
        if any(message.wave_digest != canonical_digest(wave) for message in projected):
            raise ValueError("domain mesh result changed its exact original retained wave")
        issued.execution_limit.require_current_v1()
        results = CompletedPersonalEligibilityWaveV1(canonical_digest(wave), tuple(message.result for message in projected))
        projected = None
        adopt_selector=await foreground_selector(ADOPT)if authorization_original_ref is None else None
        adoption = asyncio.create_task(worker.call(lambda graph: consume_completed_personal_eligibility_v1(
            graph, bootstrap, bundle, issued=issued, results=results, candidates=candidates,
            c02_operation_id=c02_operation_id, source_ref=source_ref, selector=adopt_selector)))
        try:
            adopted = await asyncio.shield(adoption)
        except asyncio.CancelledError:
            adopted = await asyncio.shield(adoption)
            runtime._consume_background_graph_result_v3(adopted)
            adopted = None
            raise
        # Adoption results contain only the ordinary actual receipt. They remain
        # subject to the original prepared candidate stage's current reader.
        result = runtime._consume_background_graph_result_v3(adopted)
        adopted = None
        if result.get("coverage") != "complete" or result.get("receipt",{}).get("status") not in {"committed","duplicate"}:
            raise MissingProductionOriginalV1("actual_completed_personal_eligibility_adoption")
        from .domain_mesh_messages_v1 import consume_actual_personal_mesh_outcome_v1
        consume_actual_personal_mesh_outcome_v1(issued,result)
        runtime._personal_domain_mesh_catalog_v1 = installed_personal_mesh_catalog_v1(wave)
        result = None
        return {"status": "eligibility_adopted", "operation_id":
            personal_eligibility_operation_id_v1(wave.namespace, candidates, need_digest=wave.need_original.original_digest)}
    finally:
        if futures:
            terminal = await asyncio.shield(asyncio.gather(*futures, return_exceptions=True))
            import traceback
            for item in terminal:
                if isinstance(item, BaseException):
                    traceback.clear_frames(item.__traceback__)
            terminal = None
        futures, results, wave = (), None, None
        adoption = completed = failure = result = None
        projected = None
        _ISSUED_WAVES.discard(issued)
        issued = None
        retention.release()

async def run_installed_artifact_predecision_mesh_v1(runtime, installation, *, c02_operation_id, source_ref):
    """Follow the actual finite dependency order; only qualified projections fan out."""
    from contextlib import asynccontextmanager
    from ..graph_worker import OwnedGraphStorageResultV3
    worker, bootstrap, bundle = runtime._worker, runtime._v2_bootstrap, installation.admin_bundle
    args = {"c02_operation_id": c02_operation_id, "source_ref": source_ref}

    @asynccontextmanager
    async def read(callback):
        result = await worker.call(callback)
        if type(result) is not OwnedGraphStorageResultV3:
            yield result
            return
        value, retention = result.take_value_v3()
        try:
            yield value
        finally:
            value = None
            retention.release()

    async def commit(kind, request):
        raw = await worker.call(lambda graph: graph.run_current_post_c02_artifact_preparation_step_v1(
            bootstrap, bundle, operation_kind=kind, request=request, **args))
        result = runtime._consume_background_graph_result_v3(raw)
        if result.get("coverage") != "complete" or result.get("receipt", {}).get("status") not in {"committed", "duplicate"}:
            raise MissingProductionOriginalV1("actual_complete_artifact_preparation:" + kind)
        return result

    async with read(lambda graph: graph.read_current_post_c02_artifact_task_choice_material_v3(
            bootstrap, bundle, **args)) as pre:
        await commit("input:register_artifact_task_text_extent", pre.extent_request)
        pre = None
    async with read(lambda graph: graph.read_current_post_c02_artifact_task_choice_material_v3(
            bootstrap, bundle, **args)) as pre:
        for request in pre.policy_requests:
            await commit("input:register_artifact_phase_postcondition_policy_v1", request)
        pre = request = None
    async with read(lambda graph: graph.read_current_post_c02_artifact_task_choice_material_v3(
            bootstrap, bundle, complete=True, **args)) as material:
        async with read(lambda graph: graph.read_current_post_c02_artifact_method_prerequisites_v1(
                bootstrap, bundle, material=material, **args)) as methods:
            for kind, request in methods:
                await commit(kind, request)
            methods = kind = request = None
        from .artifact_phase_postconditions_v1 import FreezeArtifactCandidatePreparationRequestV1
        await commit("input:freeze_artifact_candidate_preparation_v1", FreezeArtifactCandidatePreparationRequestV1(material.selector))
        await commit("input:freeze_values", material.freeze_request)
        await commit("evaluate_values", material.evaluate_request)
        await runtime.run_personal_candidate_eligibility_wave_v1(installation,
            candidates=material.prepare_request, **args)
        prepared = await commit("prepare_personal_candidates_v1", material.prepare_request)
        from .current_conditioned_personal_choice_v3 import prepare_current_conditioned_personal_choice_v3
        choice=await worker.call(lambda graph:prepare_current_conditioned_personal_choice_v3(graph,bootstrap,bundle,
            c02_operation_id=c02_operation_id,source_ref=source_ref,
            prepared_candidates_operation_id=dict(material.ids)['prepare'],plan_ref=material.plan_head.key.token,
            goal_ref=material.goal_head.key.token))
        selected=runtime._consume_background_graph_result_v3(choice)
        if selected.get('coverage')!='complete'or selected.get('receipt',{}).get('status')not in {'committed','duplicate'}:
            raise MissingProductionOriginalV1('actual_complete_conditional_personal_choice')
        if bundle.artifact_phase_observer is not None:
            begun=await worker.call(lambda graph:graph.begin_current_artifact_method_group_v3(bootstrap,bundle,
                prepared_candidates_operation_id=dict(material.ids)['prepare'],**args))
            begun=runtime._consume_background_graph_result_v3(begun)
            if begun.get('status')!='existing_original_method_group' and begun.get('receipt',{}).get('status')not in {'committed','duplicate'}:
                raise MissingProductionOriginalV1('actual_initial_selected_method_group_checkpoint')
        async with read(lambda graph: graph.read_current_post_c02_artifact_phase_resume_v2(
                bootstrap, bundle, **args)) as phase:
            if phase is None: raise MissingProductionOriginalV1("actual_adopted_immutable_artifact_decision_phase_group")
            return {"status": "selected", "selector": phase["selector"], "preparation": prepared, "selection": selected}



def actual_owner_personal_candidates_v1(db, *, namespace, authorization, job, issuer):
    from .owner_source_note_task_contract_v1 import owner_source_note_task_ids_v1
    from .owner_source_note_values_v1 import FreezeOwnerSourceNoteValuesParentRequestV1, owner_source_note_values_ids_v1
    from .d11_types import runtime_job_key
    auth = authorization
    ids = owner_source_note_task_ids_v1(namespace, auth.cause.owner_operation_id)
    need_op = "owner-note-need:" + canonical_digest((namespace, auth.original_ref))[:40]
    original = read_adopted_domain_operation_v1(db, namespace, need_op)
    if original is None or (original["domain"], original["operation_kind"]) != ("d07", "prepare_owner_source_note_need_v1"):
        raise MissingProductionOriginalV1("actual_original_owner_task_need")
    need_ref = "d07-current:" + original["original_digest"][:48]
    key = runtime_job_key(*namespace.as_tuple, ids["activity_id"], job.job_id)
    values_ids = owner_source_note_values_ids_v1(namespace,
        FreezeOwnerSourceNoteValuesParentRequestV1(auth.original_ref, key.token, need_ref))
    binding = SourceNoteCandidateBindingV1(ids["candidate_ref"], ids["node_id"], auth.request.project_ref,
        auth.request.recipe_ref, auth.request.body_source_ref, ids["goal_key"].token,
        auth.request.target_entity_ref, auth.request.role_binding_ref)
    return PrepareCurrentPersonalCandidatesRequestV1(ids["plan_key"].token, ids["goal_key"].token, 1, 1,
        ids["selection_operation_id"], values_ids["evaluate_operation_id"], need_ref, (binding,))


class InstalledCurrentSourceNotePriceReaderV1:
    """Actual signed CPU resource ceiling for the no-model SourceNote recipe."""
    def __init__(self, readers):
        self.readers = readers

    def _authorization_v1(self, db, namespace, need_ref):
        from .owner_source_note_need_v1 import read_owner_source_note_need_original_v2
        from .owner_source_note_task_v1 import read_owner_source_note_task_authorization_v2
        need = read_owner_source_note_need_original_v2(db, namespace=namespace, original_ref=need_ref)
        if need is None: raise MissingProductionOriginalV1("actual_signed_owner_source_note_cpu_price_need")
        saved = read_owner_source_note_task_authorization_v2(db, namespace=namespace,
            original_ref=need[0].authorization_original_ref, issuer=self.readers.issuer)
        if saved is None: raise MissingProductionOriginalV1("actual_signed_owner_source_note_cpu_price_authorization")
        return saved[0]

    def __call__(self, *, db, frame, binding, plan, goal, need,
            prospective_input_json, prospective_input_digest, future_identity):
        self.readers.current()
        if type(binding) is not SourceNoteCandidateBindingV1:
            raise MissingProductionOriginalV1("actual_installed_artifact_phase_counter_material")
        from ..domains.d08.personal_candidate_v1 import CurrentPersonalCandidatePriceV1
        from .owner_source_note_task_v1 import require_current_owner_source_note_task_authorization_v2
        active = _PINNED_CANDIDATE_REQUEST.get()
        if active is None or active[0] is not self.readers or active[2] is not frame:
            raise ValueError("SourceNote price requires the exact active current candidate compiler")
        request = active[1]
        auth = self._authorization_v1(db, frame.envelope.authority.namespace, request.need_qualification_original_ref)
        require_current_owner_source_note_task_authorization_v2(db, frame=frame, authorization=auth,
            issuer=self.readers.issuer, installed_bundle=self.readers.bundle, body_quote_authority=self.readers.graph._GraphCoordinator__body_quote_authority)
        if (binding.project_ref, binding.recipe_ref, binding.source_ref, binding.target_entity_ref, binding.role_binding_ref) != (
                auth.request.project_ref, auth.request.recipe_ref, auth.request.body_source_ref,
                auth.request.target_entity_ref, auth.request.role_binding_ref):
            raise ValueError("SourceNote CPU price changed the actual signed no-model recipe")
        pin = ProductionPolicyRefV1(auth.body_policy.effect_policy_ref, auth.body_policy.effect_policy_revision,
            auth.body_policy.effect_policy_digest)
        if pin not in frame.installed_policy_refs:
            raise MissingProductionOriginalV1("actual_pinned_source_note_execution_component")
        node = next(node for node in plan.nodes if node.node_id == binding.node_id)
        if node.resource_ref != auth.cause.parent_budget_lease_ref or future_identity.parent_budget_lease_ref != auth.cause.parent_budget_lease_ref:
            raise ValueError("SourceNote CPU price cannot choose a new parent resource or budget")
        from .owner_source_note_task_contract_v1 import NOTE_WORK_KIND
        if future_identity.model_call_id is not None or future_identity.execution_call_id is not None:
            raise ValueError("SourceNote prospective CPU price cannot become a model price")
        read = CurrentDomainReadV1(frame)
        original = read.original(auth.original_ref, kind="d11.owner_source_note_task_authorization.v2", digest=auth.digest)
        cpu = auth.body_policy.cpu_ceiling_ms
        return CurrentPersonalCandidatePriceV1(original, binding.candidate_ref, binding.digest, pin,
            (), (), NOTE_WORK_KIND,
            "d10.source-note.prospective-cpu-price.v1", node.resource_ref,
            (("cpu_ms", cpu), ("thread_cpu_ms", cpu)), prospective_input_digest, 0,
            auth.original_ref, "d11.owner-source-note-task-authorization.v2")

    def read_plan_inputs_v1(self, *, db, namespace, activity_id, request):
        if not any(type(binding) is SourceNoteCandidateBindingV1 for binding in request.bindings):
            return production_read_plan_v1((), ())
        auth = self._authorization_v1(db, namespace, request.need_qualification_original_ref)
        return production_read_plan_v1((), (), auth.source_refs,
            (auth.original_ref, auth.body_policy.effect_policy_ref))

def require_actual_owner_candidate_carrier_v1(db, *, frame, request, prepared, readers):
    from .owner_source_note_need_v1 import read_owner_source_note_need_original_v2, require_owner_note_legal_task_job_progress_v1
    original = read_owner_source_note_need_original_v2(db, namespace=frame.envelope.authority.namespace,
        original_ref=request.need_qualification_original_ref)
    if original is None: return None
    need = original[0]
    key = need.task_job_head.key
    previous = tuple(version for version in prepared.read_versions if version.key == key)
    if len(previous) != 1: raise ValueError("Owner candidate preparation lost its actual single task carrier")
    current = CurrentDomainReadV1(frame).head(db, key, required=True)
    row = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
        (key.token, previous[0].revision)).fetchone()
    if row is None or row[1] != 1:
        raise MissingProductionOriginalV1("actual_prepared_owner_candidate_carrier_history")
    previous_digest = canonical_digest(json.loads(row[0]))
    require_owner_note_legal_task_job_progress_v1(db, namespace=frame.envelope.authority.namespace,
        previous_head=previous[0], previous_digest=previous_digest,
        current_head=GraphVersion(key, current.revision), current_digest=canonical_digest(current.value),
        authorization_original_ref=need.authorization_original_ref,
        responsibility_digest=need.responsibility_digest, max_rows=frame.limits.max_query_rows)
    return key, previous[0], GraphVersion(key, current.revision)


def normalize_actual_owner_candidate_need_v1(current, previous, carrier):
    from dataclasses import replace
    key, old_carrier, actual_carrier = carrier
    old = {version.key: version for version in previous.read_versions}
    now = {version.key: version for version in current.read_versions}
    if set(old) != set(now):
        raise MissingProductionOriginalV1("same_complete_owner_candidate_need_scope")
    for member, value in now.items():
        if member == key:
            if value != actual_carrier or old[member] != old_carrier:
                raise ValueError("Owner candidate comparison changed its authenticated carrier")
        elif value != old[member]:
            raise MissingProductionOriginalV1("same_owner_candidate_need_semantic_head")
    prior = {(page.type_id, page.epoch.namespace): page for page in previous.query_coverage}
    observed = {(page.type_id, page.epoch.namespace): page for page in current.query_coverage}
    if (len(prior) != len(previous.query_coverage) or len(observed) != len(current.query_coverage)
            or set(prior) != set(observed)):
        raise MissingProductionOriginalV1("same_complete_owner_candidate_negative_scopes")
    for scope, page in observed.items():
        old_page = prior[scope]
        if (not page.complete or not old_page.complete or page.row_versions != old_page.row_versions
                or page.continuation_ref != old_page.continuation_ref or old_page.epoch.revision > page.epoch.revision):
            raise MissingProductionOriginalV1("same_actual_owner_candidate_negative_rows")
    prior_original = {version.key:version for version in previous.original.read_versions}
    observed_original = {version.key:version for version in current.original.read_versions}
    if set(prior_original) != set(observed_original):
        raise MissingProductionOriginalV1("same_owner_need_original_dependency_scope")
    for member,version in observed_original.items():
        if member == key:
            if version != actual_carrier or prior_original[member] != old_carrier:
                raise ValueError("Owner need original changed its authenticated carrier")
        elif version != prior_original[member]:
            raise MissingProductionOriginalV1("same_owner_need_original_semantic_dependency")
    return replace(current, original=replace(current.original,read_versions=previous.original.read_versions),
        read_versions=previous.read_versions, query_coverage=previous.query_coverage)

@dataclass(frozen=True, slots=True)
class PersonalMeshRouteV1:
    sender: str
    receiver: str
    kind: str
    schema: str
    purpose: str
    recipe_version: str


PERSONAL_MESH_ROUTES_V1 = tuple(
    PersonalMeshRouteV1("d08", domain, "projectionRequest", "d08.personal-eligibility-" + domain + "-input.v1",
        "consolidation", "d08.personal-eligibility-wave.v1") for domain in ("d02","d03","d05")
) + tuple(
    PersonalMeshRouteV1(domain, "d08", "projectionResult", "d08.personal-eligibility-" + domain + "-result.v1",
        "consolidation", "d08.personal-eligibility-wave.v1") for domain in ("d02","d03","d05")
) + (
    PersonalMeshRouteV1("d08","d08","evidenceNotice","d08.current-prepare_personal_candidate_eligibility_v1.v1",
        "consolidation","d08.personal-eligibility-wave.v1"),
    PersonalMeshRouteV1("d08","d08","outcome","d08.current-adopt_personal_candidate_eligibility_v1.v1",
        "consolidation","d08.personal-eligibility-wave.v1"),
)

@dataclass(frozen=True, slots=True)
class PersonalMeshAdapterStatusV1:
    domain: str
    adapter: str
    mode: str
    parallel_qualified: bool


def installed_personal_mesh_catalog_v1(wave):
    _require_immutable_v1(wave)
    # Qualification is for the three actual immutable projection adapters.
    # Other installed domains keep their existing real serial/dedicated drivers.
    names = (
        ("d01","evaluate_values","serial",False),
        ("d02","BodyDomain.check_work_start","finite_projection",True),
        ("d03","ContextProvider.resolve_role_binding","finite_projection",True),
        ("d04","installed_numeric_driver_v3","dedicated_numeric",False),
        ("d05","RelationshipProvider.provide_required_check","finite_projection",True),
        ("d06","installed_ingress_recall","serial",False),
        ("d07","installed_current_need","serial",False),
        ("d08","current_personal_candidates","serial_adoption",False),
        ("d09","D09ExpressionProvider","serial",False),
        ("d10","installed_life_project","serial",False),
        ("d11","original_budget_job_issuer","serial",False),
        ("d12","current_domain_scheme_selection","serial",False),
        ("d13","D13ShortContextProvider","serial",False),
    )
    return tuple(PersonalMeshAdapterStatusV1(*row) for row in names)


def require_personal_mesh_route_v1(route):
    if type(route) is not PersonalMeshRouteV1 or route not in PERSONAL_MESH_ROUTES_V1:
        raise ValueError("unregistered exact domain mesh sender/receiver/kind/schema/purpose/recipe")


@dataclass(frozen=True, slots=True)
class PersonalProjectionRequestMessageV1:
    route: PersonalMeshRouteV1
    wave_digest: str
    inputs: tuple
    execution_limit: PersonalProjectionExecutionLimitV1

    def __post_init__(self):
        require_personal_mesh_route_v1(self.route)
        if (self.route.kind != "projectionRequest"
                or type(self.execution_limit) is not PersonalProjectionExecutionLimitV1):
            raise ValueError("projection input used another closed mesh kind")
        _require_immutable_v1(self)


@dataclass(frozen=True, slots=True)
class PersonalProjectionResultMessageV1:
    route: PersonalMeshRouteV1
    wave_digest: str
    result: PersonalProjectionResultV1

    def __post_init__(self):
        require_personal_mesh_route_v1(self.route)
        if self.route.kind != "projectionResult" or self.result.domain != self.route.sender:
            raise ValueError("projection output used another closed mesh result")
        _require_immutable_v1(self)


def compute_registered_personal_projection_v1(message):
    require_personal_mesh_route_v1(message.route)
    domain = message.route.receiver
    result = compute_personal_projection_v1(domain, message.inputs, execution_limit=message.execution_limit)
    route = next(route for route in PERSONAL_MESH_ROUTES_V1 if route.sender == domain and route.kind == "projectionResult")
    return PersonalProjectionResultMessageV1(route, message.wave_digest, result)


def normalize_actual_owner_candidate_set_v1(current, previous, carrier):
    """Only authenticated task-carrier dependency views may differ on replay."""
    from dataclasses import replace
    key, old_carrier, actual_carrier = carrier
    needed = normalize_actual_owner_candidate_need_v1(current.need,previous.need,carrier)
    prior_rows = {row.binding.candidate_ref:row for row in previous.candidates}
    rows=[]
    for row in current.candidates:
        old=prior_rows[row.binding.candidate_ref]
        left,right=row.eligibility.originals,old.eligibility.originals
        if len(left)!=len(right):
            raise MissingProductionOriginalV1("same_owner_candidate_eligibility_original_scope")
        for observed,retained in zip(left,right,strict=True):
            if (observed.kind,observed.original_ref,observed.original_digest) != (
                    retained.kind,retained.original_ref,retained.original_digest):
                raise MissingProductionOriginalV1("same_owner_candidate_eligibility_original")
            before={version.key:version for version in retained.read_versions}
            after={version.key:version for version in observed.read_versions}
            if set(before)!=set(after):
                raise MissingProductionOriginalV1("same_owner_candidate_eligibility_dependency_scope")
            for member,version in after.items():
                if member==key:
                    if version!=actual_carrier or before[member]!=old_carrier:
                        raise ValueError("Owner eligibility original changed its authenticated job carrier")
                elif before[member]!=version:
                    raise MissingProductionOriginalV1("same_owner_candidate_eligibility_semantic_dependency")
        rows.append(replace(row,eligibility=replace(row.eligibility,originals=old.eligibility.originals)))
    return replace(current,need=needed,candidates=tuple(rows))

@dataclass(frozen=True, slots=True)
class PersonalMeshEvidenceNoticeV1:
    route: PersonalMeshRouteV1
    operation_id: str
    original: ProductionOriginalRefV1
    wave_digest: str

    def __post_init__(self):
        require_personal_mesh_route_v1(self.route)
        if self.route.kind != "evidenceNotice" or self.original.kind != "d08.current-" + PREPARE:
            raise ValueError("mesh evidence notice names another actual producer")
        _require_immutable_v1(self)


@dataclass(frozen=True, slots=True)
class PersonalMeshOutcomeV1:
    route: PersonalMeshRouteV1
    original: ProductionOriginalRefV1
    wave_digest: str
    eligibilities: tuple[CurrentPersonalCandidateEligibilityV1, ...]

    def __post_init__(self):
        require_personal_mesh_route_v1(self.route)
        if self.route.kind != "outcome" or self.original.kind != "d08.current-" + ADOPT:
            raise ValueError("mesh outcome names another actual adoption")
        _require_immutable_v1(self)

def read_legacy_source_note_authorization_for_candidates_v1(db, *, frame, request, readers):
    from .d08_personal_candidate_v1 import _personal_ingress_need_locator_v1
    from .source_note_foreground_v1 import ForegroundSourceNoteContinuationV1
    from .source_note_task_authorization_v1 import read_source_note_task_authorization_v1
    from .jobs import get_job
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    located = _personal_ingress_need_locator_v1(db,frame.envelope.authority.namespace,request)
    if located is None:raise MissingProductionOriginalV1("actual_legacy_SourceNote_current_Need")
    need=located[0]
    job=get_job(db,AtomKey.from_token(need.cycle_job_ref).name)
    continuation=decode_typed_production_value_v1(dict(job.continuation),ForegroundSourceNoteContinuationV1)
    saved=read_source_note_task_authorization_v1(db,namespace=frame.envelope.authority.namespace,
        original_ref=continuation.authorization_original_ref,issuer=readers.issuer)
    if saved is None or saved[0].digest!=continuation.authorization_original_digest:
        raise MissingProductionOriginalV1("actual_signed_legacy_SourceNote_task_authorization")
    auth,actual=saved
    if (auth.request.plan_ref,auth.request.goal_ref) != (request.plan_ref,request.goal_ref):
        raise ValueError("legacy SourceNote adapter changed its actual authorized Plan and Goal")
    read=CurrentDomainReadV1(frame)
    read.original(auth.original_ref,kind="d11.life_source_note_task_authorization",digest=auth.digest)
    # AuthV1 binds its actual Root/Source/heads/deadline, but has no signed
    # prospective CPU ceiling or selected Body component. It grants no price.
    return auth,actual


def begin_personal_eligibility_recovery_read_v1(graph, runtime, *, selector, request, original):
    """Finish has already confirmed the old WRITE; this is a separate exact READ."""
    import secrets,time
    from contextlib import ExitStack
    from dataclasses import replace
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from ..runtime_storage_v3 import begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,finish_runtime_storage_operation_v3
    from .current_method_learning_read_v3 import PreparedPersonalEligibilityRecoveryReadV1,attach_current_method_learning_work_v3,_ISSUER as READ_ISSUER
    from .foreground_activity_issuance_v1 import foreground_receipt_read_for_fence_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .first_ingress_v2 import trusted_upper
    from ..runtime_contracts import AuthorityContext
    require_graph_storage_work_admission_v3(graph)
    locator=original
    if locator[:2]!=("d08",PREPARE):raise ValueError("saved eligibility recovery changed its exact original recipe")
    bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    ns=selector.namespace; store=graph._GraphCoordinator__store
    if hasattr(selector,"authorization_original_ref"):
        from .owner_source_note_task_v1 import read_owner_source_note_task_authorization_v2
        with store._lock:
            db=store._db;db.execute("BEGIN")
            try:
                saved=read_owner_source_note_task_authorization_v2(db,namespace=ns,
                    original_ref=selector.authorization_original_ref,issuer=graph._GraphCoordinator__d11_issuer)
                if saved is None or saved[0].digest!=selector.authorization_original_digest:
                    raise MissingProductionOriginalV1("actual_saved_Owner_task_recovery_authorization")
                source_ref=saved[0].request.body_source_ref
                audiences=saved[0].cause.audiences
            finally:db.rollback()
    else:
        source_ref=selector.plan_source_ref; audiences=selector.audiences
    clock=graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    now=trusted_upper(clock)
    read_attempt_id="personal-eligibility-read:"+secrets.token_hex(16)
    deadline=saved[0].cause.original_deadline_utc if hasattr(selector,"authorization_original_ref") else selector.requested_deadline_utc
    if now>=deadline:raise MissingProductionOriginalV1("original_personal_recovery_deadline_expired")
    operation=begin_runtime_storage_operation_v3(store._db,read_attempt_id,deadline)
    metadata_reader=_PersonalRecoveryOriginalMetadataV1(store._db,operation,ns,selector.operation_id,locator)
    try:
        with bind_runtime_storage_operation_v3(operation,store._db):
            from ..runtime_storage_v3 import runtime_storage_quantum_v3
            while not metadata_reader.complete:
                with store._lock,runtime_storage_quantum_v3(store._db) as meter:metadata_reader.advance(meter)
        metadata=metadata_reader.metadata
        authority=decode_typed_production_value_v1(metadata_reader.authority_data,AuthorityContext)
        saved_deadline=metadata[("provenance","personal_eligibility_inputs","original_deadline_utc")]
        parent_budget=metadata[("provenance","personal_eligibility_inputs","parent_budget_lease_ref")]
        if saved_deadline>deadline or now>=saved_deadline or authority.namespace!=ns:
            raise MissingProductionOriginalV1("actual_original_recovery_authority_deadline")
        operation.deadline_utc=saved_deadline
    except BaseException:
        finish_runtime_storage_operation_v3(operation);raise
    lifetime=ExitStack(); fence=entry=None
    def observe(scope):
        with foreground_receipt_read_for_fence_v1(graph,scope=scope,operation_id=selector.operation_id,
                source_ref=source_ref,purpose="consolidation",audiences=audiences) as issued:
            if issued.current_self.self_entity_ref != authority.actor:
                raise ValueError("eligibility recovery belongs to another actual current Self")
            return issued.current_self,issued.current_owner
    try:
        with bind_runtime_storage_operation_v3(operation,store._db):
            fence=graph._begin_read_fence_v3(authority,operation_id=read_attempt_id,
                fence_observer=observe)
            issued=lifetime.enter_context(foreground_receipt_read_for_fence_v1(graph,scope=fence.scope,
                operation_id=selector.operation_id,source_ref=source_ref,purpose="consolidation",audiences=audiences))
            from ..authority_service.owner_location_read_v3 import prepare_current_host_foreground_read_owner_entry_v3
            entry=prepare_current_host_foreground_read_owner_entry_v3(graph,issued=issued,bundle=bundle,operation=operation)
            with store._lock:
                db=store._db;db.execute("BEGIN")
                try:owner=entry.require_for_v3(graph,issued,operation)
                finally:db.rollback()
            with store._lock:
                read_versions=_personal_recovery_read_versions_v1(store._db,operation,ns,selector.operation_id,
                    graph=graph,fence=fence,issued=issued,entry=entry)
            roots=tuple(v.key.token for v in read_versions if v.key.type_name=="memory.source")
            if source_ref not in roots:raise ValueError("saved eligibility is not bound to its actual selected Source")
            from .source_correction_read_v3 import PersonalEligibilityRecoverySourcesV1
            source_gate=PersonalEligibilityRecoverySourcesV1(store._db,roots=roots,namespace=ns,
                storage_lease=operation,read_scope=fence.scope,graph_stamp=graph._v2_graph_stamp(ns),
                purpose=issued.purpose,audiences=issued.audiences)
            while not source_gate.complete:
                graph._validate_read_fence_v3(fence)
                with store._lock:
                    store._db.execute("BEGIN")
                    try:entry.require_for_v3(graph,issued,operation)
                    finally:store._db.rollback()
                    source_gate.advance()
                graph._validate_read_fence_v3(fence)
            with store._lock:
                original=_personal_recovery_original_v1(store._db,operation,ns,selector.operation_id,locator,
                    read_versions,graph=graph,fence=fence,issued=issued,entry=entry,source_gate=source_gate)
            if original["payload"]["request"]!=plain_v1(request) or locator[2]!=canonical_digest(request):
                raise ValueError("qualified saved preparation differs from its exact current typed request")
            wave=decode_typed_production_value_v1(original["payload"]["provenance"]["personal_eligibility_inputs"],PreparedPersonalEligibilityWaveV1)
            if wave.original_deadline_utc!=saved_deadline or wave.parent_budget_lease_ref!=parent_budget:
                raise ValueError("qualified saved wave changed its actual metadata deadline/budget")
            operation.retain(_personal_input_heap_v1((wave,original,request))*3+4096)
            reader=PreparedPersonalEligibilityRecoveryReadV1(READ_ISSUER,graph,operation,fence,
                runtime=runtime,authority=authority,owner_binding=owner,owner_guard=issued.current_owner.guard,
                issued=issued,selector=selector,request=request,initial_now_utc=now,saved_wave=wave,
                saved_original=original,saved_receipt=None)
            reader.owner_read_entry=entry;reader.read_issuance_lifetime=lifetime;reader.source_gate=source_gate
            reader.initial_clock=clock;reader.initial_monotonic_deadline=time.monotonic()+wave.original_deadline_utc-now
        work=create_graph_storage_work_v3(graph,kind="current_method_learning_read_v3",operation_id=read_attempt_id,
            selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=reader,operation=operation)
        attach_current_method_learning_work_v3(reader,work)
        return work
    except BaseException:
        try:
            if entry is not None:entry.release_v3()
            lifetime.close()
        finally:
            try:
                if fence is not None:graph._finish_read_fence_v3(fence)
            finally:finish_runtime_storage_operation_v3(operation)
        raise


def prepare_personal_eligibility_recovery_inputs_v1(reader):
    """Prepare only the registered current READ recipe, using its retained Binder."""
    from dataclasses import replace
    import time
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3,_ISSUER as READ_ISSUER
    from .domain_production_frame_v1 import _materialize_current_domain_frame_fields_v1
    from .domain_production_contracts_v1 import ProductionOperationLimitsV1
    from .domain_production_read_plans_v1 import read_current_domain_policy_refs_v1,read_current_domain_original_refs_v1
    from .foreground_activity_issuance_v1 import read_foreground_receipt_in_transaction_v1
    from ..runtime_contracts import CommandEnvelope,OperationIdentity,QueryEpoch,RUNTIME_SCHEMA,SourceQualification,VersionGuard
    from .first_ingress_v2 import trusted_upper
    from .d08_personal_candidate_v1 import install_personal_candidate_readers_v1
    graph=reader.graph;bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    if now>=reader.operation.deadline_utc:raise MissingProductionOriginalV1("original_saved_personal_eligibility_deadline")
    readers=getattr(reader.runtime,"_personal_candidate_readers_v1",None)
    if readers is None:
        readers=install_personal_candidate_readers_v1(graph=graph,bootstrap=reader.runtime._bootstrap,bundle=bundle)
        reader.runtime._personal_candidate_readers_v1=readers
    with reader.store._lock:
        db=reader.db;db.execute("BEGIN")
        try:
            reader.owner_read_entry.require_for_v3(graph,reader.issued,reader.operation)
            receipt=read_foreground_receipt_in_transaction_v1(db,graph=graph,issued=reader.issued,
                streaming_source_qualification=reader.source_gate.qualification,streaming_graph_stamp=reader.graph_stamp)
            if receipt["original_digest"]!=reader.saved_original["original_digest"]:
                raise ValueError("personal recovery historical receipt and immutable input original differ")
            versions=dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? AND ref='current' "
                "AND kind IN ('scheme','operator','policy')",reader.namespace.as_tuple).fetchall())
            if set(versions)!={"scheme","operator","policy"}:raise MissingProductionOriginalV1("actual_recovery_current_guard_versions")
            authority=reader.authority
            if hasattr(reader.selector,"task_job_ref"):
                from .jobs import get_job
                from .owner_source_note_task_contract_v1 import OwnerSourceNoteTaskContinuationV2
                from .domain_production_erasure_v1 import decode_typed_production_value_v1
                from datetime import datetime
                job=get_job(db,AtomKey.from_token(reader.selector.task_job_ref).name)
                continuation=decode_typed_production_value_v1(dict(job.continuation),OwnerSourceNoteTaskContinuationV2)
                if (job.phase!="running" or job.lease_holder!=reader.issued.current_self.self_entity_ref or job.cancel_epoch
                        or continuation.step!="select" or continuation.pending_effect_refs
                        or continuation.authorization_original_ref!=reader.selector.authorization_original_ref
                        or job.lease_expires_utc is None
                        or now>=datetime.fromisoformat(job.lease_expires_utc.replace("Z","+00:00")).timestamp()):
                    raise MissingProductionOriginalV1("actual_live_same_Owner_task_personal_recovery_worker")
                authority=replace(authority,worker_fence=job.fence)
            envelope=CommandEnvelope(RUNTIME_SCHEMA,OperationIdentity(reader.activity_id,None,reader.business_operation_id,PREPARE,
                reader.business_operation_id,canonical_digest({"input_refs":[]})),authority,
                VersionGuard((),(QueryEpoch(reader.namespace,"namespace",reader.fence.epoch.revision),),
                    reader.owner_binding.access_epoch,reader.owner_binding.delete_epoch,reader.catalogue_hash,
                    versions["scheme"],versions["operator"],versions["policy"],(),(),()),
                SourceQualification((),"derived",None,now,"inference","ineligible",None,"not_applicable"),(),
                reader.parent_budget_lease_ref,reader.operation.deadline_utc,
                time.monotonic()+reader.operation.deadline_utc-now,"personal-eligibility-recovery:"+reader.operation_id,())
            plan=read_plan_personal_eligibility_v1(db,namespace=reader.namespace,activity_id=reader.activity_id,
                operation_kind=PREPARE,request=reader.request,readers=readers)
            prepare_id=personal_eligibility_request_id_v1(db,reader.namespace,reader.request.candidates,prepare=True)
            adopt_id=personal_eligibility_request_id_v1(db,reader.namespace,reader.request.candidates)
            if prepare_id!=reader.business_operation_id:raise ValueError("recovery changed its exact current Need digest/Plan/candidates")
            refs=tuple(sorted(set((*plan.required_original_refs,prepare_id,adopt_id))))
            plan=production_read_plan_v1(plan.fixed_type_ids,plan.exact_keys,plan.source_roots,refs)
            if not set(plan.source_roots)<=reader.selection_source_refs:
                raise MissingProductionOriginalV1("same_original_personal_recovery_Source_closure")
            policies=read_current_domain_policy_refs_v1(db,namespace=reader.namespace,plan=plan,installed_readers=readers)
            originals=read_current_domain_original_refs_v1(db,namespace=reader.namespace,plan=plan,installed_readers=readers)
            reader.seal_plan_v3(plan,envelope=envelope,installed_readers=readers,observed_originals=originals,installed_policy_refs=policies)
            reader.saved_receipt=receipt
            reader.frame_fields=_materialize_current_domain_frame_fields_v1(graph,db,envelope=envelope,scope=reader.fence.scope,
                plan=plan,now_utc=now,expected_owner_guard=reader.material_owner_guard,
                expected_rights=(reader.owner_binding.access_epoch,reader.owner_binding.delete_epoch),
                observed_originals=originals,installed_policy_refs=policies,limits=ProductionOperationLimitsV1(),
                prepared_inputs=PreparedMethodDomainInputsV3(READ_ISSUER,reader,plan,envelope))
        finally:db.rollback()
    reader.inputs_sealed=reader.complete=True
    reader.result=PreparedMethodDomainInputsV3(READ_ISSUER,reader,reader.selected_plan,reader.selected_envelope)
    reader.work.phase="eligibility_recovery_inputs_sealed"


def complete_personal_eligibility_recovery_read_v1(reader):
    """Fresh READ qualification returns the original immutable wave and receipt."""
    from .domain_production_contracts_v1 import CurrentOperationFrameV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if reader.issued.scope.operation!="read" or not reader.inputs_sealed or not reader.business_started:
        raise ValueError("actual sealed same-operation eligibility READ completion required")
    with reader.store._lock:
        db=reader.db;db.execute("BEGIN")
        try:
            reader.owner_read_entry.require_for_v3(reader.graph,reader.issued,reader.operation)
            frame=CurrentOperationFrameV1(*reader.frame_fields)
            wave,original=reader.saved_wave,reader.saved_original
            _current_wave_v1(db,frame=frame,request=reader.request,readers=reader.installed_readers,wave=wave,original=original)
            actual=_read_prepared_wave_v1(db,reader.namespace,reader.request)
            if actual[0]!=wave or actual[1]["original_digest"]!=original["original_digest"]:
                raise ValueError("saved recovery changed its actual immutable prepared input original")
            adoption=read_adopted_domain_operation_v1(db,reader.namespace,
                personal_eligibility_request_id_v1(db,reader.namespace,reader.request.candidates))
            result=dict(reader.saved_receipt)
            if adoption is not None:
                if adoption["operation_kind"]!=ADOPT or adoption["payload"]["request"]!=plain_v1(reader.request):
                    raise ValueError("personal recovery found another actual adopted recipe")
                if adoption["payload"]["provenance"]["prepared_eligibility_digest"]!=original["original_digest"]:
                    raise ValueError("personal recovery adoption belongs to another actual prepared wave")
                result["eligibility_recovery_outcome"]=ProductionOriginalRefV1("d08.current-"+ADOPT,
                    "d08-current:"+adoption["original_digest"][:48],adoption["original_digest"])
            reader.personal_eligibility_wave_v1=wave
        finally:db.rollback()
    reader.owner_read_entry.release_v3()
    return result


class _PersonalRecoveryOriginalMetadataV1:
    """Canonical EOF projection; candidate/body packets are never retained here."""
    def __init__(self,db,operation,namespace,operation_id,locator):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.db,self.operation,self.namespace,self.operation_id=db,operation,namespace,operation_id
        self.locator=locator;self.parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.offset=0;self.total=None;self.metadata={};self.authority_data={};self.authority_nodes={("authority",):self.authority_data};self.scalar=bytearray();self.complete=False
        operation.retain(262144)
    def _wanted(self,path):
        return (path[:1]==("authority",) or path==("identity","activity_id")
            or path[:2]==("provenance","personal_eligibility_inputs") and path[-1:] in
            (("original_deadline_utc",),("parent_budget_lease_ref",)))
    def _emit(self,event):
        import json
        if not self._wanted(event.path):return
        if event.path[:1]==("authority",) and event.kind in ("object_start","array_start"):
            if event.path==("authority",):return
            value={} if event.kind=="object_start" else []
            parent=self.authority_nodes[event.path[:-1]]
            if type(parent) is list:parent.append(value)
            else:parent[event.path[-1]]=value
            self.authority_nodes[event.path]=value
        elif event.kind=="scalar_start":self.scalar=bytearray()
        elif event.kind=="scalar_chunk":
            if len(self.scalar)+len(event.raw)>8192:raise ValueError("recovery metadata scalar exceeds registered bound")
            self.scalar.extend(event.raw)
        elif event.kind=="scalar_end":
            value=json.loads(self.scalar);self.scalar=bytearray()
            if event.path[:1]==("authority",):
                parent=self.authority_nodes[event.path[:-1]]
                if type(parent) is list:parent.append(value)
                else:parent[event.path[-1]]=value
            else:self.metadata[event.path]=value
    def advance(self,meter):
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        key=(*self.namespace.as_tuple,self.operation_id)
        actual=meter.read_fixed_row(self.db,"graph_domain_production_originals_v1",
            ("domain","operation_kind","request_digest","original_digest","bundle_digest","receipt_digest"),
            "bot=? AND persona=? AND operation_id=?",key)
        if actual!=self.locator:raise ValueError("saved eligibility metadata commitment changed")
        with legacy_cell_read_transaction_v2(self.db):
            if self.total is None:
                row=self.db.execute("SELECT typeof(original_payload_json),length(CAST(original_payload_json AS BLOB)) "
                    "FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND operation_id=?",key).fetchone()
                meter.charge_read(16)
                if row is None or row[0]!="text":raise ValueError("saved eligibility canonical original missing")
                self.total=row[1]
            if self.offset<self.total:
                chunk,total,kind=read_legacy_sql_cell_fragment_v2(self.db,table="graph_domain_production_originals_v1",
                    column="original_payload_json",where="bot=? AND persona=? AND operation_id=?",parameters=key,
                    start=self.offset,length=min(16384,self.total-self.offset),meter=meter)
                if (total,kind)!=(self.total,"text"):raise ValueError("saved eligibility metadata EOF changed")
                self.parser.feed(chunk,self._emit);self.offset+=len(chunk);return
        result=self.parser.finish()
        if (result.byte_count,result.sha256)!=(self.total,self.locator[3]):
            raise ValueError("saved eligibility canonical metadata digest differs")
        self.complete=True

def _personal_recovery_original_v1(db,operation,namespace,operation_id,locator,read_versions,*,graph,fence,issued,entry,source_gate):
    """Body release occurs only after the caller's completed actual Source front door."""
    from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    from .domain_production_originals_v1 import _receipt
    import json
    key=(*namespace.as_tuple,operation_id);parts=[];offset=0
    with legacy_cell_read_transaction_v2(db):
        total=db.execute("SELECT length(CAST(original_payload_json AS BLOB)) FROM graph_domain_production_originals_v1 "
            "WHERE bot=? AND persona=? AND operation_id=?",key).fetchone()[0]
    operation.retain(total*8+131072)
    while offset<total:
        graph._validate_read_fence_v3(fence)
        db.execute("BEGIN")
        try:
            entry.require_for_v3(graph,issued,operation)
            source_gate.qualification.require_for(db,namespace=namespace,roots=source_gate.saved_roots,
                purpose=issued.purpose,audiences=issued.audiences,read_scope=issued.scope,
                graph_stamp=graph._v2_graph_stamp(namespace))
        finally:db.rollback()
        with runtime_storage_quantum_v3(db) as meter,legacy_cell_read_transaction_v2(db):
            chunk,size,kind=read_legacy_sql_cell_fragment_v2(db,table="graph_domain_production_originals_v1",
                column="original_payload_json",where="bot=? AND persona=? AND operation_id=?",parameters=key,
                start=offset,length=min(16384,total-offset),meter=meter)
            if (size,kind)!=(total,"text"):raise ValueError("qualified saved original body changed")
        parts.append(chunk);offset+=len(chunk)
    payload=json.loads(b"".join(parts))
    if canonical_digest(payload)!=locator[3]:raise ValueError("qualified saved original canonical digest changed")
    row=db.execute("SELECT receipt_json FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND operation_id=?",key).fetchone()
    receipt=_receipt(json.loads(row[0]))
    bundle=db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",key).fetchone()
    if (canonical_digest(receipt)!=locator[5] or bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)
            or receipt.operation_id!=operation_id or receipt.operation_digest!=locator[4]):
        raise ValueError("qualified saved original lost its exact actual W01 receipt")
    return dict(domain=locator[0],operation_kind=locator[1],request_digest=locator[2],original_digest=locator[3],
        payload=payload,read_versions=read_versions,receipt=receipt)


def _personal_recovery_read_versions_v1(db,operation,namespace,operation_id,*,graph,fence,issued,entry):
    from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    import json
    from hashlib import sha256
    key=(*namespace.as_tuple,operation_id);offset=0;parts=[]
    with runtime_storage_quantum_v3(db) as meter,legacy_cell_read_transaction_v2(db):
        row=db.execute("SELECT typeof(read_versions_json),length(CAST(read_versions_json AS BLOB)) "
            "FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND operation_id=?",key).fetchone()
        meter.charge_read(16)
        if row is None or row[0]!="text":raise ValueError("saved eligibility metadata readset missing")
        total=row[1]
    operation.retain(total*8+32768)
    while offset<total:
        graph._validate_read_fence_v3(fence)
        db.execute("BEGIN")
        try:entry.require_for_v3(graph,issued,operation)
        finally:db.rollback()
        with runtime_storage_quantum_v3(db) as meter,legacy_cell_read_transaction_v2(db):
            chunk,size,kind=read_legacy_sql_cell_fragment_v2(db,table="graph_domain_production_originals_v1",
                column="read_versions_json",where="bot=? AND persona=? AND operation_id=?",parameters=key,
                start=offset,length=min(16384,total-offset),meter=meter)
            if (size,kind)!=(total,"text"):raise ValueError("saved eligibility metadata readset EOF changed")
        parts.append(chunk);offset+=len(chunk)
    raw=b"".join(parts).decode("ascii");rows=json.loads(raw)
    if canonical_digest(rows)!=sha256(raw.encode()).hexdigest():
        raise ValueError("saved eligibility metadata readset is not canonical")
    versions=tuple(GraphVersion(AtomKey.from_token(ref),revision) for ref,revision in rows)
    if len(versions)>1024 or any(NamespaceId.from_key(v.key)!=namespace for v in versions):
        raise ValueError("saved eligibility metadata readset namespace/bound differs")
    return versions

def personal_mesh_input_semantics_v1(wave):
    """Fixed D02/D03/D05 predicate inputs; Graph versions and CPU accounting stay in their own trace."""
    rows = []
    for item in wave.candidates:
        body,role,boundary = item.body,item.role,item.boundary
        policy = body.policy
        body_semantic = (body.state.energy,body.state.fatigue,body.state.load,body.state.cursor,
            tuple(sorted((r.remaining_cost,r.status) for r in body.reservations)),
            None if policy is None else (policy.work_kind,policy.component.cost_category,
                policy.component.fixed_cost,policy.component.duration_rate))
        request = role.request
        role_semantic = (request.subject_persona_ref,request.target_entity_ref,request.group_ref,
            request.scene_ref,request.requested_action_kind,request.purpose,request.scope_complete,
            role.roles,role.norms,tuple((binding.social_role,binding.target_entity_ref,binding.group_ref,
                binding.scene_ref,binding.scope_selector,binding.visibility_scope,binding.norm_refs,
                binding.precedence,binding.status,binding.applies_to(request)) for binding in role.bindings))
        boundary_semantic = (boundary.subject_persona_ref,boundary.target_entity_ref,boundary.action_kind,
            boundary.audiences,tuple((rule.subject_persona_ref,rule.target_entity_ref,rule.action_kind,
                rule.audience_scope,rule.scene_ref,rule.effect,rule.basis,bool(rule.communicated_refs),
                bool(rule.acknowledged_refs),bool(rule.exception_refs),rule.status,
                rule.valid_from <= boundary.at_time and (rule.valid_until is None or boundary.at_time < rule.valid_until))
                for rule in boundary.rules))
        rows.append((item.discriminator_contract.recipe_id,body_semantic,role_semantic,
            boundary_semantic,item.irreversible_exposure,item.established_deadline,item.established_commitment,
            bool(item.pending_original_effects),bool(item.carried_forward_verified),
            item.numeric_discriminator_unresolved,item.recovery_branch))
    return ('d08.personal-input-semantics.v1',tuple(rows))

def _stage_personal_mesh_result_v1(db,frame,operation,request,wave,provenance,*,results=None):
    from .foreground_mesh_issuance_v1 import current_personal_mesh_facts_v1
    facts = current_personal_mesh_facts_v1(frame)
    if facts is None:
        return stage_result_v1(frame,'d08',operation,request,provenance=provenance)
    from .domain_mesh_contract_v1 import MeshTickInputsV1,MeshPendingIdentityV1
    from .domain_mesh_tick_v1 import stage_personal_mesh_companion_v1,combine_semantic_mesh_stage_v1,decode_semantic_tick_v1
    input_schema,input_rows = personal_mesh_input_semantics_v1(wave)
    by_candidate = {item.candidate_ref:semantic for item,semantic in zip(wave.candidates,input_rows,strict=True)}
    semantic = ((input_schema,tuple(sorted(input_rows,key=canonical_serialize))),None if results is None else
        tuple((row.domain,tuple(sorted(((by_candidate[ref],status) for ref,status in row.statuses),
            key=canonical_serialize))) for row in results.projections))
    before = frame.snapshot.get(facts.expected_tick.key)
    previous = () if not before.valid else decode_semantic_tick_v1(before.value).pending
    effects = {ref for item in wave.candidates for ref in item.pending_original_effects}
    actions = tuple(atom for atom in frame.snapshot.atoms if atom.valid and atom.key.type_name == 'd08.action_intent.v1'
        and (atom.value['identity']['effect_id'] in effects or any(old.original_ref == atom.key.token for old in previous)))
    outcomes = tuple(atom for atom in frame.snapshot.atoms if atom.valid and atom.key.type_name == 'd08.action_outcome.v1')
    pending = list(previous)
    semantic_versions = [wave.plan_head,wave.goal_head]
    for action in actions:
        effect = action.value['identity']['effect_id']
        observed = tuple(atom for atom in outcomes if atom.value['effect_id'] == effect)
        settled = any(not atom.value['unknown_effects'] and atom.value['result_level'] in
            ('completed_verified','failed_verified','not_dispatched') for atom in observed)
        prior = next((item for item in pending if item.original_ref == action.key.token),None)
        entry = MeshPendingIdentityV1('effect',action.key.token,
            canonical_digest(action.value) if prior is None else prior.original_digest,
            'observed' if settled else 'unknown')
        if prior is not None:
            pending[pending.index(prior)] = entry
        else:
            pending.append(entry)
        semantic_versions.extend((GraphVersion(action.key,action.revision),
            *(GraphVersion(atom.key,atom.revision) for atom in observed)))
    inputs = MeshTickInputsV1(causal_original=facts.causal_original,source_roots=frame.envelope.source_qualification.source_refs,
        predecessors=facts.predecessors,semantic_originals=(facts.causal_original,*facts.predecessors),
        semantic_versions=tuple(dict.fromkeys(semantic_versions)),pending=tuple(pending),original_deadline_utc=wave.original_deadline_utc,
        semantic_digest=canonical_digest(semantic),cancellation_generation=max((value for _,value in wave.cancel_generations),default=0))
    companion = stage_personal_mesh_companion_v1(db,frame=frame,operation_kind=operation,request=request,actual_inputs=inputs)
    stage = stage_result_v1(frame,'d08',operation,request,provenance={**provenance,'semantic_mesh':companion.trace})
    return combine_semantic_mesh_stage_v1(stage,companion)

def personal_mesh_request_v1(original,command):
    from ..authority_service.current_foreground_activity_v1 import ForegroundActivityRequestV1
    from ..authority_service.current_owner_source_note_task_v1 import OwnerTaskActivityRequestV1
    from ..authority_service.foreground_mesh_contract_v1 import (
        PersonalMeshCompanionSelectorV1,ForegroundMeshActivityRequestV1,OwnerTaskMeshActivityRequestV1)
    companion = PersonalMeshCompanionSelectorV1(command,command.candidates.need_qualification_original_ref)
    if type(original) is ForegroundActivityRequestV1:
        return ForegroundMeshActivityRequestV1(original,companion)
    if type(original) is OwnerTaskActivityRequestV1:
        return OwnerTaskMeshActivityRequestV1(original,companion)
    raise TypeError('Personal mesh requires its exact registered original selector version')

def _require_personal_foreground_selector_v3(selector,bundle,kind,request,*,c02_operation_id,source_ref):
    from ..authority_service.current_foreground_activity_v1 import (ForegroundActivityRequestV1,
        foreground_typed_command_digest_v1)
    from .domain_production_registry_v1 import installed_operation_v1
    policy=bundle.installation_policy
    if(type(selector)is not ForegroundActivityRequestV1 or kind not in{PREPARE,ADOPT}
            or type(request)is not PersonalEligibilityRequestV1
            or selector.namespace!=policy.namespace or selector.installation_id!=policy.installation_id
            or selector.c02_operation_id!=c02_operation_id or selector.cue_source_ref!=source_ref
            or selector.operation_kind!=kind
            or selector.request_digest!=foreground_typed_command_digest_v1(installed_operation_v1(kind),request)):
        raise ValueError("personal eligibility requires this exact Source-prepared foreground selector")
    return selector


_BORROWED_RESULTS_V3=WeakKeyDictionary()


class _BorrowedPersonalEligibilityResultsV3:
    def __init__(self,reader,wave,results):
        from weakref import ref
        self.reader=ref(reader)
        self.identity=_borrowed_personal_results_identity_v3(reader)
        self.wave,self.results=wave,results
        self.digest=canonical_digest((wave,results))
        self.operation=reader.operation

    def _runtime_retained_heap_bytes_v3(self):
        import sys
        return sys.getsizeof(self)+sys.getsizeof(self.__dict__)+_personal_input_heap_v1((
            self.identity,self.wave,self.results,self.digest))

    def require_v3(self,reader):
        if(self.reader()is not reader or self.identity!=_borrowed_personal_results_identity_v3(reader)
                or self.operation is not reader.operation or self.wave is None or self.results is None
                or canonical_digest((self.wave,self.results))!=self.digest):
            raise ValueError("personal projection results changed their actual borrowed Work/scope/material")
        return self


def _borrowed_personal_results_identity_v3(reader):
    return(id(reader.work),id(reader.runtime),id(reader.issued),id(reader.issued.scope),reader.selector,
        reader.operation,reader.selection_digest,reader.request_digest,reader.graph_stamp)


def capture_borrowed_personal_eligibility_results_v3(reader):
    """Copy only factory-local handoff ownership into this actual retained Work."""
    from weakref import ref
    from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3,_READERS
    if reader.operation_kind!=ADOPT:return
    if(type(reader)is not BorrowedMethodLearningReadV3 or reader not in _READERS
            or reader.work is None or reader.work.state is not reader or reader.work.operation is not reader.operation
            or reader.work.coordinator is not reader.graph or reader.operation.closed
            or reader.runtime is not reader.graph._GraphCoordinator__domain_production_runtime_v1
            or reader in _BORROWED_RESULTS_V3):
        raise ValueError("actual fresh borrowed eligibility Work required for its synchronous handoff")
    active=_ACTIVE_RESULTS.get(reader.runtime)
    if active is None:raise MissingProductionOriginalV1("actual_installed_terminal_personal_projection_wave")
    wave,results=active
    if(type(wave)is not PreparedPersonalEligibilityWaveV1 or type(results)is not CompletedPersonalEligibilityWaveV1
            or wave.namespace!=reader.namespace or wave.request_digest!=canonical_digest(reader.request.candidates)
            or results.input_digest!=canonical_digest(wave)or reader.initial_now_utc>=wave.original_deadline_utc):
        raise ValueError("borrowed personal results changed their actual wave/request/original deadline")
    retained=_BorrowedPersonalEligibilityResultsV3(reader,wave,results)
    reader.operation.register_retained_state_v3(retained)
    _BORROWED_RESULTS_V3[reader]=ref(retained)


def has_borrowed_personal_eligibility_results_v3(reader):
    pending_ref=_BORROWED_RESULTS_V3.get(reader)
    pending=None if pending_ref is None else pending_ref()
    if pending is None:return False
    pending.require_v3(reader)
    return True


@contextmanager
def activate_borrowed_personal_eligibility_results_v3(reader):
    from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3,_READERS,_BOUND
    if reader.operation_kind!=ADOPT:yield;return
    if(type(reader)is not BorrowedMethodLearningReadV3 or reader not in _READERS
            or not reader.inputs_sealed or not reader.business_started or reader.business_completed
            or reader.work.state is not reader or reader.work.operation is not reader.operation
            or reader.operation.closed or _BOUND.get()!=(reader.inventory,reader.graph,reader.db)):
        raise ValueError("personal projection results activate only in their actual sealed borrowed compiler")
    reader.inventory._actual()
    pending_ref=_BORROWED_RESULTS_V3.get(reader)
    pending=None if pending_ref is None else pending_ref()
    if pending is None:raise MissingProductionOriginalV1("actual_borrowed_terminal_personal_projection_wave")
    pending.require_v3(reader)
    with bind_completed_personal_eligibility_v1(reader.graph,pending.wave,pending.results):
        yield


def release_borrowed_personal_eligibility_results_v3(reader):
    pending_ref=_BORROWED_RESULTS_V3.pop(reader,None)
    pending=None if pending_ref is None else pending_ref()
    if pending is not None:
        pending.operation.unregister_retained_state_v3(pending)
        pending.wave=pending.results=None
