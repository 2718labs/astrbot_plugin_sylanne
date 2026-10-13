"""Finite prospective method readiness facts; no resource reservation or action permit."""
from dataclasses import dataclass
import math
from ...graph_types import GraphVersion
from ...runtime_contracts import NamespaceId
from ...model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
from ..d08.personal_candidate_v1 import CurrentPersonalCandidatePriceV1

OPERATION = "quote_current_method_choices_v1"
FULL_METHOD = "CP-tone-order:full-draft-then-check"
SAMPLE_METHOD = "CP-tone-order:tone-sample-then-full-draft"
METHODS = frozenset({FULL_METHOD, SAMPLE_METHOD})
HARD_CONDITIONS = frozenset({"local_sample_permitted", "budget_deadline_feasible", "fact_permission_gap"})
DIMENSIONS = frozenset({"input_tokens", "output_tokens", "model_tokens", "model_microusd"})


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("method readiness requires exact SHA256 commitments")


def _amounts(values):
    if (type(values) is not tuple or values != tuple(sorted(values)) or len(values) != 4
            or set(dict(values)) != DIMENSIONS or any(type(n) is not int or n < 0 for _, n in values)):
        raise ValueError("method readiness retains all four actual installed quote dimensions")


@dataclass(frozen=True, slots=True)
class QuoteCurrentMethodChoicesRequestV1:
    task: ArtifactDraftTaskSelectorV1

    def __post_init__(self):
        if type(self.task) is not ArtifactDraftTaskSelectorV1:
            raise TypeError("method readiness selects one actual ordinary task")


@dataclass(frozen=True, slots=True)
class MethodReadinessOriginalV1:
    c02_operation_id: str
    task_scope_ref: str
    task_scope_digest: str
    goal_ref: str
    goal_revision: int
    parent_budget_lease_ref: str
    valid_until_utc: float
    candidate_method_refs: tuple[str, ...]
    condition_values: dict[str, bool]
    quote_original_refs: tuple[str, ...]
    schema: str = "d02.method-readiness.v1"

    def __post_init__(self):
        if (self.schema != "d02.method-readiness.v1" or set(self.candidate_method_refs) != METHODS
                or len(self.candidate_method_refs) != 2 or set(self.condition_values) != HARD_CONDITIONS
                or any(type(value) is not bool for value in self.condition_values.values())
                or type(self.quote_original_refs) is not tuple or len(set(self.quote_original_refs)) != 2
                or type(self.goal_revision) is not int or self.goal_revision < 1
                or type(self.valid_until_utc) not in {int, float} or not math.isfinite(self.valid_until_utc)):
            raise ValueError("closed two-method readiness summary required")
        _digest(self.task_scope_digest)


@dataclass(frozen=True, slots=True)
class MethodPhasePriceBoundV1:
    phase_kind: str
    ceiling: tuple[tuple[str, int], ...]

    def __post_init__(self):
        if self.phase_kind not in {"tone_sample", "full"}: raise ValueError("only actual generation phases have prices")
        _amounts(self.ceiling)


@dataclass(frozen=True, slots=True)
class MethodChoiceQuoteEvidenceV1:
    method_ref: str
    binding_digest: str
    quote_original_ref: str
    quote_digest: str
    first_phase_price: CurrentPersonalCandidatePriceV1
    phase_bounds: tuple[MethodPhasePriceBoundV1, ...]
    whole_method_ceiling: tuple[tuple[str, int], ...]
    planned_physical_calls: int
    planned_auxiliary_calls: int
    planned_input_ceiling: int
    planned_output_ceiling: int
    budget_fits: bool
    slots_fit: bool

    def __post_init__(self):
        if (self.method_ref not in METHODS or type(self.first_phase_price) is not CurrentPersonalCandidatePriceV1
                or type(self.phase_bounds) is not tuple or tuple(p.phase_kind for p in self.phase_bounds) !=
                    (("full",) if self.method_ref == FULL_METHOD else ("tone_sample", "full"))
                or any(type(n) is not int or n < 0 for n in (self.planned_physical_calls, self.planned_auxiliary_calls,
                    self.planned_input_ceiling, self.planned_output_ceiling))
                or type(self.budget_fits) is not bool or type(self.slots_fit) is not bool):
            raise ValueError("method quote evidence retains actual first-price and conservative complete phase bounds")
        _digest(self.binding_digest); _digest(self.quote_digest); _amounts(self.whole_method_ceiling)


@dataclass(frozen=True, slots=True)
class MethodReadinessEvidenceV1:
    namespace: NamespaceId
    task: ArtifactDraftTaskSelectorV1
    plan_head: GraphVersion
    need_original_ref: str
    need_original_digest: str
    call_plan_digest: str
    parent_budget_scope_digest: str
    counter_source_scope: str
    choices: tuple[MethodChoiceQuoteEvidenceV1, ...]
    schema: str = "d02.method-readiness-evidence.v1"

    def __post_init__(self):
        if (self.schema != "d02.method-readiness-evidence.v1" or type(self.namespace) is not NamespaceId
                or type(self.task) is not ArtifactDraftTaskSelectorV1 or self.task.namespace != self.namespace
                or self.plan_head.key.type_name != "d08.personal_plan.v1"
                or self.counter_source_scope not in {"PRODUCTION", "LOCAL_FIXTURE"}
                or type(self.choices) is not tuple or len(self.choices) != 2
                or {choice.method_ref for choice in self.choices} != METHODS):
            raise ValueError("actual task/Plan/Need/two-method evidence required")
        for digest in (self.need_original_digest, self.call_plan_digest, self.parent_budget_scope_digest): _digest(digest)
