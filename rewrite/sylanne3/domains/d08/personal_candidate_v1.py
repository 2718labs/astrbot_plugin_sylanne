"""Closed prospective personal candidates; no Action, final check or execution authority."""
from dataclasses import dataclass
import math

from ...graph_types import AtomKey, GraphVersion
from ...runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ...runtime.domain_production_contracts_v1 import ProductionOriginalRefV1, ProductionPolicyRefV1, ProductionQueryCoverageV1
from ...model_broker.artifact_draft_v1 import (ArtifactDraftTaskSelectorV1, ArtifactDraftTextExtentV2,
    ArtifactDraftPriorContentCommitmentV2, artifact_draft_phase_sequence_v2)
from ...runtime.d11_artifact_draft_contract_v1 import DraftFileTargetV1

PREPARE_OPERATION_V1 = "prepare_personal_candidates_v1"
SELECT_OPERATION_V2 = "select_personal_step_v2"
HARD_STATES_V1 = frozenset({"eligible", "REQUIRED_CHECK_UNRESOLVED", "REJECTED", "WAIT_COST_EVIDENCE", "WAIT_ORIGINAL_EFFECT", "WAIT_BUDGET"})


def _text(value):
    if type(value) is not str or not value or len(value.encode("utf-8")) > 4096:
        raise ValueError("personal candidate requires a bounded locator")


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("personal candidate requires an exact digest")


def _head(value, kind=None):
    if type(value) is not GraphVersion or value.revision < 1 or kind is not None and value.key.type_name != kind:
        raise ValueError("personal candidate requires an actual positive head")


def _evidence(originals, versions, coverage):
    if (type(originals) is not tuple or not originals or len(originals) > 32
            or any(type(row) is not ProductionOriginalRefV1 for row in originals)
            or len({row.original_ref for row in originals}) != len(originals)
            or type(versions) is not tuple or len(versions) > 1024
            or any(type(row) is not GraphVersion for row in versions)
            or len({row.key for row in versions}) != len(versions)
            or type(coverage) is not tuple or len(coverage) > 64
            or any(type(row) is not ProductionQueryCoverageV1 for row in coverage)):
        raise ValueError("personal eligibility requires bounded exact current original evidence")


@dataclass(frozen=True, slots=True)
class ArtifactPhaseCandidateBindingV1:
    candidate_ref: str
    node_id: str
    task: ArtifactDraftTaskSelectorV1
    method_ref: str
    phase_index: int
    phase_kind: str
    extent: ArtifactDraftTextExtentV2
    target: DraftFileTargetV1
    prior_content: ArtifactDraftPriorContentCommitmentV2 | None
    activity_scope_ref: str
    prev_phase_original_ref: str | None = None
    prev_phase_original_digest: str | None = None
    schema: str = "d08.artifact-phase-candidate-binding.v1"

    def __post_init__(self):
        for value in (self.candidate_ref, self.node_id, self.activity_scope_ref):
            _text(value)
        phases = artifact_draft_phase_sequence_v2(self.method_ref)
        if (self.schema != "d08.artifact-phase-candidate-binding.v1" or type(self.task) is not ArtifactDraftTaskSelectorV1
                or type(self.extent) is not ArtifactDraftTextExtentV2 or type(self.target) is not DraftFileTargetV1
                or type(self.phase_index) is not int or not 0 <= self.phase_index < len(phases)
                or self.phase_kind != phases[self.phase_index] or self.phase_kind not in {"full", "tone_sample"}
                or self.prior_content is not None and type(self.prior_content) is not ArtifactDraftPriorContentCommitmentV2):
            raise ValueError("candidate binds one exact registered future generation phase")
        if self.phase_kind == "tone_sample" and (self.extent.minimum, self.extent.maximum) != (120, 180):
            raise ValueError("candidate cannot expand the registered tone sample")
        if self.phase_index == 0:
            if self.prev_phase_original_ref is not None or self.prev_phase_original_digest is not None:
                raise ValueError("first candidate phase has no previous phase")
        else:
            _text(self.prev_phase_original_ref)
            _digest(self.prev_phase_original_digest)
            if self.prior_content is None:
                raise ValueError("later candidate requires independently verified previous content")
        if self.target.mode == "replace" and self.prior_content is None:
            raise ValueError("replacement candidate requires its actual verified predecessor")

    @property
    def digest(self):
        return canonical_digest(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class ArtifactPhaseCandidateBindingV2(ArtifactPhaseCandidateBindingV1):
    full_extent: ArtifactDraftTextExtentV2
    extent_original_ref: str
    extent_original_digest: str
    schema: str = "d08.artifact-phase-candidate-binding.v2"

    def __post_init__(self):
        # Preserve V1 unchanged; its constructor validates the shared phase fields.
        ArtifactPhaseCandidateBindingV1(self.candidate_ref, self.node_id, self.task,
            self.method_ref, self.phase_index, self.phase_kind, self.extent, self.target,
            self.prior_content, self.activity_scope_ref, self.prev_phase_original_ref,
            self.prev_phase_original_digest)
        if (self.schema != "d08.artifact-phase-candidate-binding.v2"
                or type(self.full_extent) is not ArtifactDraftTextExtentV2
                or self.phase_kind == "full" and self.extent != self.full_extent):
            raise ValueError("phase must retain its original whole-method full extent")
        _text(self.extent_original_ref); _digest(self.extent_original_digest)


@dataclass(frozen=True, slots=True, kw_only=True)
class ArtifactPhaseCandidateBindingV3(ArtifactPhaseCandidateBindingV2):
    postcondition_policy_ref: str
    postcondition_policy_digest: str
    schema: str = "d08.artifact-phase-candidate-binding.v3"

    def __post_init__(self):
        ArtifactPhaseCandidateBindingV2(candidate_ref=self.candidate_ref, node_id=self.node_id,
            task=self.task, method_ref=self.method_ref, phase_index=self.phase_index,
            phase_kind=self.phase_kind, extent=self.extent, target=self.target,
            prior_content=self.prior_content, activity_scope_ref=self.activity_scope_ref,
            prev_phase_original_ref=self.prev_phase_original_ref,
            prev_phase_original_digest=self.prev_phase_original_digest,
            full_extent=self.full_extent, extent_original_ref=self.extent_original_ref,
            extent_original_digest=self.extent_original_digest)
        if self.schema != "d08.artifact-phase-candidate-binding.v3":
            raise ValueError("postcondition policy commitment requires the explicit V3 binding")
        _text(self.postcondition_policy_ref); _digest(self.postcondition_policy_digest)


@dataclass(frozen=True, slots=True)
class SourceNoteCandidateBindingV1:
    candidate_ref: str
    node_id: str
    project_ref: str
    recipe_ref: str
    source_ref: str
    goal_ref: str
    target_entity_ref: str
    role_binding_ref: str
    schema: str = "d08.source-note-candidate-binding.v1"

    def __post_init__(self):
        if self.schema != "d08.source-note-candidate-binding.v1":
            raise ValueError("source-note candidate schema differs")
        _text(self.candidate_ref); _text(self.node_id)
        for ref, kind in ((self.project_ref, "d10.life_project.v1"), (self.recipe_ref, "d10.activity_recipe.v1"),
                (self.source_ref, "memory.source"), (self.goal_ref, "d08.goal.v1"),
                (self.target_entity_ref, "d03.entity_anchor"), (self.role_binding_ref, "d03.role_binding")):
            if AtomKey.from_token(ref).type_name != kind:
                raise ValueError("source-note candidate requires real tool locators")

    @property
    def digest(self):
        return canonical_digest(self)


CandidateBindingV1 = ArtifactPhaseCandidateBindingV1 | ArtifactPhaseCandidateBindingV2 | ArtifactPhaseCandidateBindingV3 | SourceNoteCandidateBindingV1


@dataclass(frozen=True, slots=True)
class PrepareCurrentPersonalCandidatesRequestV1:
    plan_ref: str
    goal_ref: str
    expected_plan_revision: int
    expected_goal_revision: int
    selection_operation_id: str
    value_evaluation_operation_id: str
    need_qualification_original_ref: str
    bindings: tuple[CandidateBindingV1, ...]

    def __post_init__(self):
        if (AtomKey.from_token(self.plan_ref).type_name != "d08.personal_plan.v1"
                or AtomKey.from_token(self.goal_ref).type_name != "d08.goal.v1"
                or any(type(value) is not int or value < 1 for value in (self.expected_plan_revision, self.expected_goal_revision))
                or type(self.bindings) is not tuple or not 1 <= len(self.bindings) <= 6
                or any(type(row) not in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3, SourceNoteCandidateBindingV1} for row in self.bindings)
                or len({row.candidate_ref for row in self.bindings}) != len(self.bindings)):
            raise ValueError("candidate preparation requires one exact bounded current Plan/Goal")
        for value in (self.selection_operation_id, self.value_evaluation_operation_id, self.need_qualification_original_ref):
            _text(value)
        if len(canonical_serialize(self).encode()) > 131072:
            raise ValueError("candidate preparation exceeds its finite encoded bound")


@dataclass(frozen=True, slots=True)
class SelectCurrentPersonalStepRequestV2:
    plan_ref: str
    goal_ref: str
    prepared_candidates_operation_id: str

    def __post_init__(self):
        if AtomKey.from_token(self.plan_ref).type_name != "d08.personal_plan.v1" or AtomKey.from_token(self.goal_ref).type_name != "d08.goal.v1":
            raise ValueError("prepared selection requires exact Plan/Goal locators")
        _text(self.prepared_candidates_operation_id)


@dataclass(frozen=True, slots=True)
class CurrentPersonalNeedQualificationV1:
    original: ProductionOriginalRefV1
    plan_head: GraphVersion
    goal_head: GraphVersion
    read_versions: tuple[GraphVersion, ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    complete: bool
    new_c3_required: bool
    meaningful_gaps: tuple[str, ...]
    original_deadline_utc: float

    def __post_init__(self):
        _head(self.plan_head, "d08.personal_plan.v1"); _head(self.goal_head, "d08.goal.v1")
        _evidence((self.original,), self.read_versions, self.query_coverage)
        if (type(self.complete) is not bool or type(self.new_c3_required) is not bool
                or type(self.meaningful_gaps) is not tuple or len(self.meaningful_gaps) > 16
                or any(type(value) is not str or not value for value in self.meaningful_gaps)
                or type(self.original_deadline_utc) not in {int, float} or not math.isfinite(self.original_deadline_utc)):
            raise ValueError("Need qualification requires actual bounded scope/deadline results")


@dataclass(frozen=True, slots=True)
class CurrentPersonalCandidateEligibilityV1:
    candidate_ref: str
    node_id: str
    parameter_digest: str
    hard_status: str
    originals: tuple[ProductionOriginalRefV1, ...]
    read_versions: tuple[GraphVersion, ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    irreversible_exposure: int
    established_deadline: float | None
    established_commitment: bool = False
    pending_original_effects: tuple[str, ...] = ()
    carried_forward_verified: tuple[str, ...] = ()
    numeric_discriminator_unresolved: bool = False
    recovery_branch: bool = False

    def __post_init__(self):
        _text(self.candidate_ref); _text(self.node_id); _digest(self.parameter_digest)
        _evidence(self.originals, self.read_versions, self.query_coverage)
        if (self.hard_status not in HARD_STATES_V1 or type(self.irreversible_exposure) is not int
                or not 0 <= self.irreversible_exposure <= 3
                or any(type(value) is not bool for value in (self.established_commitment, self.numeric_discriminator_unresolved, self.recovery_branch))
                or self.established_deadline is not None and (type(self.established_deadline) not in {int, float} or not math.isfinite(self.established_deadline))):
            raise ValueError("candidate eligibility is a scoped result, never a final CheckReceipt")
        for values in (self.pending_original_effects, self.carried_forward_verified):
            if type(values) is not tuple or len(values) > 32 or len(set(values)) != len(values):
                raise ValueError("candidate retains bounded original effect facts")
            for value in values: _text(value)


@dataclass(frozen=True, slots=True)
class CurrentPersonalCandidatePriceV1:
    original: ProductionOriginalRefV1
    candidate_ref: str
    parameter_digest: str
    installed_policy: ProductionPolicyRefV1
    read_versions: tuple[GraphVersion, ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    work_kind: str
    template_version: str
    resource_ref: str
    quote_ceiling: tuple[tuple[str, int], ...]
    serialized_input_digest: str
    input_token_count: int
    counting_policy_ref: str
    counting_policy_version: str

    def __post_init__(self):
        _evidence((self.original,), self.read_versions, self.query_coverage)
        for value in (self.candidate_ref, self.work_kind, self.template_version, self.resource_ref, self.counting_policy_ref, self.counting_policy_version): _text(value)
        _digest(self.parameter_digest); _digest(self.serialized_input_digest)
        if (type(self.installed_policy) is not ProductionPolicyRefV1 or type(self.input_token_count) is not int or self.input_token_count < 0
                or type(self.quote_ceiling) is not tuple or not self.quote_ceiling or len(self.quote_ceiling) > 32
                or len({dim for dim, _ in self.quote_ceiling}) != len(self.quote_ceiling)
                or any(type(dim) is not str or not dim or type(amount) is not int or amount < 0 for dim, amount in self.quote_ceiling)):
            raise ValueError("candidate price requires actual serialized prospective input and installed policy proof")


@dataclass(frozen=True, slots=True)
class PersonalCandidateFutureIdentityV1:
    action_ref: str
    activity_id: str
    action_operation_id: str
    attempt_id: str
    effect_id: str
    execution_call_id: str | None
    model_prepare_operation_id: str | None
    model_acquire_operation_id: str | None
    model_call_id: str | None
    deadline_utc: float
    parent_budget_lease_ref: str

    def __post_init__(self):
        for name in ("action_ref", "activity_id", "action_operation_id", "attempt_id", "effect_id", "parent_budget_lease_ref"):
            _text(getattr(self, name))
        if type(self.deadline_utc) not in {int, float} or not math.isfinite(self.deadline_utc):
            raise ValueError("candidate must preserve an actual absolute deadline")
        for value in (self.execution_call_id, self.model_prepare_operation_id, self.model_acquire_operation_id, self.model_call_id):
            if value is not None: _text(value)


@dataclass(frozen=True, slots=True)
class PreparedPersonalCandidateV1:
    binding: CandidateBindingV1
    eligibility: CurrentPersonalCandidateEligibilityV1
    price: CurrentPersonalCandidatePriceV1 | None
    quote_ref: str | None
    quote_digest: str | None
    quote_ceiling: tuple[tuple[str, int], ...]
    prospective_input_digest: str
    future_identity: PersonalCandidateFutureIdentityV1

    def __post_init__(self):
        if type(self.binding) not in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3, SourceNoteCandidateBindingV1} or type(self.eligibility) is not CurrentPersonalCandidateEligibilityV1 or type(self.future_identity) is not PersonalCandidateFutureIdentityV1:
            raise TypeError("prepared candidate requires its exact binding/current eligibility/future identity")
        _digest(self.prospective_input_digest)
        if (self.eligibility.candidate_ref, self.eligibility.node_id, self.eligibility.parameter_digest) != (self.binding.candidate_ref, self.binding.node_id, self.binding.digest):
            raise ValueError("candidate eligibility belongs to different parameters")
        if self.price is None:
            if self.quote_ref is not None or self.quote_digest is not None or self.quote_ceiling:
                raise ValueError("unknown price cannot manufacture a quote")
        else:
            if type(self.price) is not CurrentPersonalCandidatePriceV1 or self.price.serialized_input_digest != self.prospective_input_digest:
                raise ValueError("candidate price belongs to different prospective bytes")
            _text(self.quote_ref); _digest(self.quote_digest)


@dataclass(frozen=True, slots=True)
class PreparedPersonalCandidateSetV1:
    namespace: NamespaceId
    actor_ref: str
    preparation_operation_id: str
    selection_operation_id: str
    future_decision_ref: str
    plan_head: GraphVersion
    goal_head: GraphVersion
    source_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    value_evaluation_operation_id: str
    value_evaluation_digest: str
    need: CurrentPersonalNeedQualificationV1
    candidates: tuple[PreparedPersonalCandidateV1, ...]
    parent_budget_lease_ref: str
    owner_grant_ref: str
    owner_grant_revision: int
    owner_grant_digest: str
    access_epoch: int
    delete_epoch: int
    schema: str = "d08.prepared-personal-candidates.v1"

    def __post_init__(self):
        if (self.schema != "d08.prepared-personal-candidates.v1" or type(self.namespace) is not NamespaceId
                or self.actor_ref != "persona:" + self.namespace.persona_id or type(self.need) is not CurrentPersonalNeedQualificationV1
                or type(self.candidates) is not tuple or not 1 <= len(self.candidates) <= 6
                or any(type(row) is not PreparedPersonalCandidateV1 for row in self.candidates)
                or len({row.binding.candidate_ref for row in self.candidates}) != len(self.candidates)
                or self.candidates != tuple(sorted(self.candidates, key=lambda row: row.binding.candidate_ref))):
            raise ValueError("prepared candidates require one exact current subject and canonical finite set")
        _head(self.plan_head, "d08.personal_plan.v1"); _head(self.goal_head, "d08.goal.v1")
        for value in (self.preparation_operation_id, self.selection_operation_id, self.future_decision_ref, self.value_evaluation_operation_id, self.parent_budget_lease_ref, self.owner_grant_ref): _text(value)
        _digest(self.value_evaluation_digest); _digest(self.owner_grant_digest)
        if any(type(value) is not int or value < 0 for value in (self.owner_grant_revision, self.access_epoch, self.delete_epoch)):
            raise ValueError("candidate ownership generations differ")
        if (not self.source_refs or type(self.source_refs) is not tuple or len(self.source_refs) > 32
                or len(set(self.source_refs)) != len(self.source_refs)
                or any(AtomKey.from_token(ref).type_name != "memory.source" for ref in self.source_refs)):
            raise ValueError("candidate sources must be actual bounded D06 roots")


@dataclass(frozen=True, slots=True)
class ConsumePersonalDecisionRequestV1:
    decision_ref: str
    prepared_candidates_operation_id: str

    def __post_init__(self):
        if AtomKey.from_token(self.decision_ref).type_name != "d08.decision_record.v2":
            raise ValueError("adapter only consumes an actual immutable decision")
        _text(self.prepared_candidates_operation_id)
