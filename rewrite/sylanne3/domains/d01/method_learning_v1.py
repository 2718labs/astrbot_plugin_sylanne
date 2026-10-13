"""D01 scoped method trials and measured outcome gates on the shared Graph."""
from dataclasses import dataclass, fields
import math

from ...graph_types import AtomKey, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, canonical_digest, schema_hash

PROTOCOL_TYPE = "d01.method_evaluation_protocol.v1"
TRIAL_TYPE = "d01.method_scoped_trial.v1"
EVALUATION_TYPE = "d01.method_evaluation.v1"
REVIEW_TYPE = "d01.method_outcome_review.v1"
POLICY_ID = "CP-tone-order"
BASELINE_METHOD = "CP-tone-order:full-draft-then-check"
TRIAL_METHOD = "CP-tone-order:tone-sample-then-full-draft"


def _text(value):
    if type(value) is not str or not 1 <= len(value) <= 4096:
        raise ValueError("bounded method-learning reference required")


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("method-learning commitment must be SHA256")


def _refs(value, *, nonempty=False, limit=32):
    if type(value) is not tuple or len(value) > limit or len(set(value)) != len(value) or nonempty and not value:
        raise ValueError("method-learning references must be bounded and unique")
    for ref in value:
        _text(ref)


def _time(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("method-learning time must be finite")


def _ref_type(ref, namespace, kind):
    key = AtomKey.from_token(ref)
    if NamespaceId.from_key(key) != namespace or key.type_name != kind:
        raise ValueError("method-learning reference crossed its namespace/type")
    return key


@dataclass(frozen=True, slots=True)
class MethodEvaluationProtocolV1:
    namespace: NamespaceId
    protocol_id: str
    policy_id: str
    required_project_trials: int
    minimum_blind_reviewers: int
    minimum_rework_reduction_ppm: int
    maximum_time_regression_ppm: int
    observer_policy_ref: str
    observer_policy_digest: str
    source_refs: tuple[str, ...]
    valid_from: float
    valid_until: float
    schema: str = PROTOCOL_TYPE

    def __post_init__(self):
        if self.schema != PROTOCOL_TYPE or type(self.namespace) is not NamespaceId or self.policy_id != POLICY_ID:
            raise ValueError("registered scoped method evaluation protocol required")
        _text(self.protocol_id); _text(self.observer_policy_ref); _digest(self.observer_policy_digest)
        if (type(self.required_project_trials) is not int or not 2 <= self.required_project_trials <= 16
                or type(self.minimum_blind_reviewers) is not int or not 2 <= self.minimum_blind_reviewers <= 8):
            raise ValueError("method protocol requires independent projects and real plural reviewers")
        for value in (self.minimum_rework_reduction_ppm, self.maximum_time_regression_ppm):
            if type(value) is not int or not 0 <= value <= 1_000_000:
                raise ValueError("method metric thresholds must be frozen integer ratios")
        _refs(self.source_refs, nonempty=True)
        for ref in self.source_refs: _ref_type(ref, self.namespace, "memory.source")
        _time(self.valid_from); _time(self.valid_until)
        if self.valid_until <= self.valid_from:
            raise ValueError("method protocol has no finite valid interval")


@dataclass(frozen=True, slots=True)
class MethodScopedTrialV1:
    namespace: NamespaceId
    trial_id: str
    gp1_interpretation_ref: str
    growth_proposal_ref: str
    base_persona_head: str
    target_block: str
    protocol_ref: str
    protocol_digest: str
    goal_refs: tuple[str, ...]
    source_refs: tuple[str, ...]
    valid_from: float
    valid_until: float
    status: str
    schema: str = TRIAL_TYPE

    def __post_init__(self):
        if self.schema != TRIAL_TYPE or type(self.namespace) is not NamespaceId or self.status not in {"scoped_trial", "paused", "ended", "adopted"}:
            raise ValueError("ST1 is a scoped trial, never an already learned strategy")
        for value in (self.trial_id, self.growth_proposal_ref, self.base_persona_head, self.target_block): _text(value)
        _ref_type(self.gp1_interpretation_ref, self.namespace, "d07.current_interpretation.v1")
        _ref_type(self.protocol_ref, self.namespace, PROTOCOL_TYPE); _digest(self.protocol_digest)
        _refs(self.goal_refs, nonempty=True, limit=16); _refs(self.source_refs, nonempty=True)
        for ref in self.goal_refs: _ref_type(ref, self.namespace, "d08.goal.v1")
        for ref in self.source_refs: _ref_type(ref, self.namespace, "memory.source")
        _time(self.valid_from); _time(self.valid_until)
        if self.valid_until <= self.valid_from: raise ValueError("trial needs its original finite interval")


@dataclass(frozen=True, slots=True)
class MethodMetricsV1:
    rework_units: int | None
    baseline_rework_units: int | None
    first_full_elapsed_ms: int | None
    baseline_first_full_elapsed_ms: int | None
    discarded_generated_units: int | None
    baseline_discarded_generated_units: int | None
    model_input_tokens: int | None
    model_output_tokens: int | None
    network_wait_ms: int | None
    user_wait_ms: int | None

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if value is not None and (type(value) is not int or not 0 <= value <= 9_000_000_000_000_000):
                raise ValueError("actual method metrics must be finite nonnegative integer measurements or unknown")


@dataclass(frozen=True, slots=True)
class MethodBlindReviewV1:
    reviewer_entity_ref: str
    response_interpretation_ref: str
    source_ref: str
    quality_delta: int | None
    blind: bool

    def __post_init__(self):
        if not self.reviewer_entity_ref.startswith("entity:") or type(self.blind) is not bool:
            raise ValueError("method review needs an actual independent reviewer identity")
        _text(self.response_interpretation_ref); _text(self.source_ref)
        if self.quality_delta is not None and (type(self.quality_delta) is not int or not -100 <= self.quality_delta <= 100):
            raise ValueError("review quality difference is a bounded reported score or unknown")


@dataclass(frozen=True, slots=True)
class MethodEvaluationV1:
    namespace: NamespaceId
    evaluation_id: str
    trial_ref: str
    protocol_ref: str
    protocol_digest: str
    project_ref: str
    milestone_ref: str
    milestone_digest: str
    artifact_ref: str
    artifact_version: int
    artifact_digest: str
    baseline_milestone_ref: str
    baseline_milestone_digest: str
    baseline_artifact_ref: str
    baseline_artifact_version: int
    baseline_artifact_digest: str
    experiment_original_ref: str
    experiment_original_digest: str
    measurement_original_ref: str
    measurement_original_digest: str
    observer_policy_ref: str
    observer_policy_digest: str
    metrics: MethodMetricsV1
    blind_reviews: tuple[MethodBlindReviewV1, ...]
    source_refs: tuple[str, ...]
    evidence_family: str
    artifact_validity: str
    method_used: str
    attribution: str
    method_benefit: str
    missing_items: tuple[str, ...]
    source_scope: str
    schema: str = EVALUATION_TYPE

    def __post_init__(self):
        if self.schema != EVALUATION_TYPE or type(self.namespace) is not NamespaceId or type(self.metrics) is not MethodMetricsV1:
            raise ValueError("typed method evaluation required")
        for value in (self.evaluation_id, self.milestone_ref, self.baseline_milestone_ref,
                self.experiment_original_ref, self.measurement_original_ref, self.observer_policy_ref, self.evidence_family): _text(value)
        for value in (self.protocol_digest, self.milestone_digest, self.artifact_digest, self.baseline_milestone_digest,
                self.baseline_artifact_digest, self.experiment_original_digest, self.measurement_original_digest, self.observer_policy_digest): _digest(value)
        _ref_type(self.trial_ref, self.namespace, TRIAL_TYPE); _ref_type(self.protocol_ref, self.namespace, PROTOCOL_TYPE)
        _ref_type(self.project_ref, self.namespace, "d10.life_project.v1")
        for ref in (self.artifact_ref, self.baseline_artifact_ref):
            if NamespaceId.from_key(AtomKey.from_token(ref)) != self.namespace:
                raise ValueError("method comparison requires actual qualified same-namespace imported results")
        if any(type(v) is not int or v < 1 for v in (self.artifact_version, self.baseline_artifact_version)):
            raise ValueError("method comparison requires actual artifact versions")
        if (type(self.blind_reviews) is not tuple or len(self.blind_reviews) > 8
                or any(type(row) is not MethodBlindReviewV1 for row in self.blind_reviews)
                or len({row.reviewer_entity_ref for row in self.blind_reviews}) != len(self.blind_reviews)):
            raise ValueError("method blind reviews must be bounded distinct actual reviewers")
        if (self.artifact_validity not in {"verified", "unknown", "failed"}
                or self.method_used not in {"verified", "unknown", "mismatch"}
                or self.attribution not in {"matched", "unknown", "mismatch"}
                or self.method_benefit not in {"supported", "unknown", "not_supported", "no_improvable_baseline"}
                or self.source_scope not in {"PRODUCTION", "LOCAL_FIXTURE"}):
            raise ValueError("method outcome axes must remain separate")
        _refs(self.source_refs, nonempty=True); _refs(self.missing_items)
        if self.method_benefit == "supported" and (self.missing_items or self.artifact_validity != "verified"
                or self.method_used != "verified" or self.attribution != "matched"):
            raise ValueError("method benefit cannot hide missing validity, method or attribution")


@dataclass(frozen=True, slots=True)
class MethodOutcomeReviewV1:
    namespace: NamespaceId
    review_id: str
    trial_ref: str
    growth_proposal_ref: str
    protocol_ref: str
    protocol_digest: str
    evaluation_refs: tuple[str, ...]
    counter_interpretation_refs: tuple[str, ...]
    continuity_interpretation_ref: str
    base_persona_head: str
    target_block: str
    evidence_families: tuple[str, ...]
    source_refs: tuple[str, ...]
    qualification: str
    missing_items: tuple[str, ...]
    schema: str = REVIEW_TYPE

    def __post_init__(self):
        if self.schema != REVIEW_TYPE or type(self.namespace) is not NamespaceId or self.qualification not in {"qualified", "held", "rejected"}:
            raise ValueError("method outcome review is a current qualification, not a new strategy")
        for value in (self.review_id, self.growth_proposal_ref, self.base_persona_head, self.target_block): _text(value)
        _digest(self.protocol_digest); _ref_type(self.trial_ref, self.namespace, TRIAL_TYPE)
        _ref_type(self.protocol_ref, self.namespace, PROTOCOL_TYPE)
        _refs(self.evaluation_refs, limit=16); _refs(self.counter_interpretation_refs, limit=32)
        _refs(self.evidence_families, limit=16); _refs(self.source_refs, nonempty=True); _refs(self.missing_items)
        _ref_type(self.continuity_interpretation_ref, self.namespace, "d07.current_interpretation.v1")
        if self.qualification == "qualified" and (self.missing_items or len(self.evidence_families) < 2):
            raise ValueError("method review cannot qualify missing or nonindependent evidence")


def evaluate_method_benefit_v1(protocol, metrics, reviews):
    """Frozen integer-ratio comparison; no baseline or no blind evidence is not success."""
    if type(protocol) is not MethodEvaluationProtocolV1 or type(metrics) is not MethodMetricsV1:
        raise TypeError("actual typed protocol and measurements required")
    missing = []
    if any(getattr(metrics, name) is None for name in ("rework_units", "baseline_rework_units", "first_full_elapsed_ms", "baseline_first_full_elapsed_ms")):
        missing.append("actual_paired_method_measurements")
    if len(reviews) < protocol.minimum_blind_reviewers or any(not row.blind or row.quality_delta is None for row in reviews):
        missing.append("actual_complete_independent_blind_reviews")
    if missing: return "unknown", tuple(missing)
    if metrics.baseline_rework_units == 0:
        return "no_improvable_baseline", ("no_improvable_rework_baseline",)
    if metrics.baseline_first_full_elapsed_ms == 0:
        return "unknown", ("positive_actual_full_draft_time_baseline",)
    rework = (metrics.baseline_rework_units - metrics.rework_units) * 1_000_000 >= protocol.minimum_rework_reduction_ppm * metrics.baseline_rework_units
    timing = metrics.first_full_elapsed_ms * 1_000_000 <= metrics.baseline_first_full_elapsed_ms * (1_000_000 + protocol.maximum_time_regression_ppm)
    quality = all(row.quality_delta >= 0 for row in reviews)
    return ("supported" if rework and timing and quality else "not_supported"), ()


def method_learning_key_v1(namespace, type_name, identity):
    return AtomKey(Owner("persona", *namespace.as_tuple), type_name, "method-learning:" + canonical_digest((namespace, type_name, identity)))


@dataclass(frozen=True, slots=True)
class MethodExperimentPlanV1:
    namespace: NamespaceId
    experiment_id: str
    trial_ref: str
    protocol_ref: str
    protocol_digest: str
    treatment_goal_ref: str
    baseline_goal_ref: str
    treatment_method_ref: str
    baseline_method_ref: str
    common_task_source_ref: str
    parent_budget_lease_ref: str
    source_refs: tuple[str, ...]
    valid_until: float
    schema: str = "d01.method_experiment_plan.v1"

    def __post_init__(self):
        if self.schema != "d01.method_experiment_plan.v1" or type(self.namespace) is not NamespaceId:
            raise ValueError("exact prospective paired method experiment required")
        for value in (self.experiment_id, self.parent_budget_lease_ref): _text(value)
        for ref, kind in ((self.trial_ref, TRIAL_TYPE), (self.protocol_ref, PROTOCOL_TYPE),
                (self.treatment_goal_ref, "d08.goal.v1"), (self.baseline_goal_ref, "d08.goal.v1"),
                (self.common_task_source_ref, "memory.source")):
            _ref_type(ref, self.namespace, kind)
        if (self.treatment_goal_ref == self.baseline_goal_ref or self.treatment_method_ref != TRIAL_METHOD
                or self.baseline_method_ref != BASELINE_METHOD):
            raise ValueError("paired experiment requires distinct actual tasks and the two registered legal methods")
        _digest(self.protocol_digest); _refs(self.source_refs, nonempty=True); _time(self.valid_until)
        if self.common_task_source_ref not in self.source_refs:
            raise ValueError("paired experiment retains its common input provenance")


@dataclass(frozen=True, slots=True)
class MethodComparisonObservationV1:
    namespace: NamespaceId
    experiment_ref: str
    experiment_digest: str
    treatment_milestone_ref: str
    treatment_milestone_digest: str
    baseline_milestone_ref: str
    baseline_milestone_digest: str
    treatment_artifact_digest: str
    baseline_artifact_digest: str
    observer_policy_ref: str
    observer_policy_digest: str
    metrics: MethodMetricsV1
    source_refs: tuple[str, ...]
    source_scope: str
    schema: str = "d11.method_comparison_observation.v1"

    def __post_init__(self):
        if (self.schema != "d11.method_comparison_observation.v1" or type(self.namespace) is not NamespaceId
                or type(self.metrics) is not MethodMetricsV1 or self.source_scope not in {"PRODUCTION", "LOCAL_FIXTURE"}):
            raise ValueError("actual typed method observer output required")
        _ref_type(self.experiment_ref, self.namespace, "d01.method_experiment_plan.v1")
        for value in (self.treatment_milestone_ref, self.baseline_milestone_ref, self.observer_policy_ref): _text(value)
        for value in (self.experiment_digest, self.treatment_milestone_digest, self.baseline_milestone_digest,
                self.treatment_artifact_digest, self.baseline_artifact_digest, self.observer_policy_digest): _digest(value)
        _refs(self.source_refs, nonempty=True)


@dataclass(frozen=True, slots=True, kw_only=True)
class MethodComparisonObservationV2(MethodComparisonObservationV1):
    measurement_family_ref: str
    treatment_call_refs: tuple[str, ...]
    baseline_call_refs: tuple[str, ...]
    support_original_refs: tuple[str, ...]
    measurement_kind: str = "derived_phase_billing.v1"
    schema: str = "d11.method_comparison_observation.v2"

    def __post_init__(self):
        MethodComparisonObservationV1(**{field.name: getattr(self, field.name)
            for field in fields(MethodComparisonObservationV1) if field.name != "schema"})
        if self.schema != "d11.method_comparison_observation.v2" or self.measurement_kind != "derived_phase_billing.v1":
            raise ValueError("derived billing observation requires its explicit V2 contract")
        for refs in (self.treatment_call_refs, self.baseline_call_refs, self.support_original_refs):
            _refs(refs, nonempty=True, limit=32)
        if (self.treatment_call_refs != tuple(sorted(self.treatment_call_refs))
                or self.baseline_call_refs != tuple(sorted(self.baseline_call_refs))
                or set(self.treatment_call_refs) & set(self.baseline_call_refs)
                or self.measurement_family_ref != "method-billing-family:" + canonical_digest(self.treatment_call_refs)
                or len(self.source_refs) != 1
                or all(getattr(self.metrics, name) is None for name in ("model_input_tokens", "model_output_tokens"))
                or any(getattr(self.metrics, field.name) is not None for field in fields(MethodMetricsV1)
                    if field.name not in {"model_input_tokens", "model_output_tokens"})):
            raise ValueError("billing-only measurements cannot invent timing, rework, quality or independent experiences")


TRIAL_PROPOSAL_TYPE_V2 = "d01.method_trial_proposal.v2"
BLIND_REQUEST_TYPE_V2 = "d01.method_blind_review_request.v2"


@dataclass(frozen=True, slots=True)
class MethodTrialProposalV2:
    namespace: NamespaceId
    trial_id: str
    growth_proposal_ref: str
    base_persona_head: str
    target_block: str
    protocol_ref: str
    protocol_digest: str
    goal_refs: tuple[str, ...]
    source_refs: tuple[str, ...]
    valid_from: float
    valid_until: float
    schema: str = TRIAL_PROPOSAL_TYPE_V2

    def __post_init__(self):
        if self.schema != TRIAL_PROPOSAL_TYPE_V2 or type(self.namespace) is not NamespaceId:
            raise ValueError("independently registered method trial proposal required")
        for value in (self.trial_id, self.growth_proposal_ref, self.base_persona_head, self.target_block): _text(value)
        _ref_type(self.protocol_ref, self.namespace, PROTOCOL_TYPE); _digest(self.protocol_digest)
        _refs(self.goal_refs, nonempty=True, limit=16); _refs(self.source_refs, nonempty=True)
        for ref in self.goal_refs: _ref_type(ref, self.namespace, "d08.goal.v1")
        for ref in self.source_refs: _ref_type(ref, self.namespace, "memory.source")
        _time(self.valid_from); _time(self.valid_until)
        if self.valid_until <= self.valid_from: raise ValueError("trial proposal requires its finite original interval")


@dataclass(frozen=True, slots=True)
class MethodBlindReviewRequestV2:
    namespace: NamespaceId
    request_id: str
    experiment_ref: str
    experiment_digest: str
    treatment_milestone_ref: str
    treatment_milestone_digest: str
    baseline_milestone_ref: str
    baseline_milestone_digest: str
    treatment_artifact_digest: str
    baseline_artifact_digest: str
    reviewer_entity_ref: str
    source_refs: tuple[str, ...]
    valid_until: float
    schema: str = BLIND_REQUEST_TYPE_V2

    def __post_init__(self):
        if self.schema != BLIND_REQUEST_TYPE_V2 or type(self.namespace) is not NamespaceId:
            raise ValueError("independently registered blind review request required")
        for value in (self.request_id, self.treatment_milestone_ref, self.baseline_milestone_ref): _text(value)
        _ref_type(self.experiment_ref, self.namespace, "d01.method_experiment_plan.v1")
        for value in (self.experiment_digest, self.treatment_milestone_digest, self.baseline_milestone_digest,
                self.treatment_artifact_digest, self.baseline_artifact_digest): _digest(value)
        if not self.reviewer_entity_ref.startswith("entity:"): raise ValueError("actual reviewer entity required")
        _refs(self.source_refs, nonempty=True)
        for ref in self.source_refs: _ref_type(ref, self.namespace, "memory.source")
        _time(self.valid_until)


@dataclass(frozen=True, slots=True)
class MethodBlindResponseV2:
    request_ref: str
    request_digest: str
    source_ref: str
    quality_delta: int | None
    blind: bool
    schema: str = "d01.method_blind_response.v2"

    def __post_init__(self):
        if self.schema != "d01.method_blind_response.v2" or AtomKey.from_token(self.request_ref).type_name != BLIND_REQUEST_TYPE_V2:
            raise ValueError("blind response must name its prior independent request")
        _digest(self.request_digest); _text(self.source_ref)
        if type(self.blind) is not bool or self.quality_delta is not None and (
                type(self.quality_delta) is not int or not -100 <= self.quality_delta <= 100):
            raise ValueError("bounded reported blind review score required")


EXPERIMENT_TYPE = "d01.method_experiment_plan.v1"
VALUE_TYPES = {PROTOCOL_TYPE: MethodEvaluationProtocolV1, TRIAL_TYPE: MethodScopedTrialV1,
    EVALUATION_TYPE: MethodEvaluationV1, REVIEW_TYPE: MethodOutcomeReviewV1, EXPERIMENT_TYPE: MethodExperimentPlanV1,
    TRIAL_PROPOSAL_TYPE_V2: MethodTrialProposalV2, BLIND_REQUEST_TYPE_V2: MethodBlindReviewRequestV2}


def method_learning_type_specs_v1():
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    return tuple(TypeSpec(name, ("persona",), "state", lambda value, cls=cls: decode_typed_production_value_v1(value, cls),
        immutable=name != TRIAL_TYPE, writer_domain="d01", schema_version=2 if name.endswith(".v2") else 1,
        schema_hash=schema_hash({"type": name, "fields": tuple(field.name for field in fields(cls)),
            "metrics": tuple(field.name for field in fields(MethodMetricsV1)), "blind_review": tuple(field.name for field in fields(MethodBlindReviewV1)),
            "semantic": "ST1 scoped trial; artifact/method/benefit/attribution separate; no permission"}))
        for name, cls in VALUE_TYPES.items())