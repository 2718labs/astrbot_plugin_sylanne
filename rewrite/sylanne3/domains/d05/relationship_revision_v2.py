"""Source-bearing, directed relationship revisions; all durable state is shared Graph."""
from __future__ import annotations

from dataclasses import dataclass, fields, replace
import math

from ...graph_types import AtomKey, GraphVersion, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, canonical_digest, schema_hash

PROFILE_TYPE = "d05.relationship_profile.v2"
ESTIMATE_TYPE = "d05.dimension_estimate.v2"
CONTRIBUTION_TYPE = "d05.interaction_contribution.v3"
CHECKPOINT_TYPE = "d05.relationship_checkpoint.v2"
EXPECTATION_TYPE = "d05.relationship_expectation.v2"
RECIPROCITY_TYPE = "d05.reciprocity_pattern.v2"
REPAIR_TYPE = "d05.repair_process.v2"
REVISION_OPERATION = "adopt_relationship_revision_v2"
KINDS = ("external_interaction", "internal_recollection", "simulated_trial", "administrative_edit")


def _text(value):
    if type(value) is not str or not value or len(value) > 1024:
        raise ValueError("relationship locator must be a bounded nonempty string")


def _number(value, low, high):
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise ValueError("relationship number is outside its explicit finite domain")


def _refs(value, *, nonempty=False, bound=32):
    if type(value) is not tuple or len(value) > bound or len(set(value)) != len(value) or (nonempty and not value):
        raise ValueError("relationship references must be bounded and unique")
    for ref in value:
        _text(ref)


@dataclass(frozen=True, slots=True)
class RelationshipScopeV2:
    namespace: NamespaceId
    subject_head: GraphVersion
    context_head: GraphVersion | None
    relationship_domain: str
    context_ref: str
    dimension: str
    dimension_schema_version: str

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or type(self.subject_head) is not GraphVersion
                or self.subject_head.key.type_name != "d03.entity_anchor" or self.subject_head.revision < 1
                or NamespaceId.from_key(self.subject_head.key) != self.namespace
                or self.context_head is not None and (type(self.context_head) is not GraphVersion
                    or self.context_head.key.type_name not in {"d03.role_binding", "d03.world_event", "memory.source"}
                    or self.context_head.revision < 1 or NamespaceId.from_key(self.context_head.key) != self.namespace)):
            raise ValueError("relationship scope needs its actual current D03 subject version")
        for value in (self.relationship_domain, self.context_ref, self.dimension, self.dimension_schema_version):
            _text(value)

    @property
    def subject_entity_ref(self):
        return self.subject_head.key.name

    @property
    def owner(self):
        return Owner("relation", *self.namespace.as_tuple, self.subject_entity_ref)

    @property
    def scope_id(self):
        # Subject revisions fence reads; identity remains stable across revisions.
        return canonical_digest((self.namespace, self.subject_entity_ref, self.relationship_domain,
            self.context_ref, self.dimension, self.dimension_schema_version))

    def key(self, type_name, suffix=""):
        identity = (self.scope_id, suffix)
        if type_name == PROFILE_TYPE:
            identity = (self.namespace, self.subject_entity_ref, self.relationship_domain, self.context_ref, self.dimension_schema_version)
        elif type_name == REPAIR_TYPE:
            identity = (self.namespace, self.subject_entity_ref, suffix)
        return AtomKey(self.owner, type_name, "relationship:" + canonical_digest(identity))


@dataclass(frozen=True, slots=True)
class RelationshipDimensionRuleV2:
    dimension: str
    meaning: str
    relationship_domain: str
    context_ref: str
    dimension_schema_version: str
    context_kind: str
    kind_bounds: tuple[tuple[str, float], ...]
    family_net_cap: float
    checkpoint_total_variation_cap: float
    applicable_effects: tuple[str, ...]
    higher_preferred_effects: tuple[str, ...]
    lower_preferred_effects: tuple[str, ...]
    allow_evidence_initialization: bool
    authored_prior_source_ref: str | None
    authored_prior_estimate: float | None
    allow_reassessment_checkpoint: bool
    preference_pivot: float

    def __post_init__(self):
        for value in (self.dimension, self.meaning, self.relationship_domain, self.context_ref, self.dimension_schema_version):
            _text(value)
        if self.context_kind not in {"installed", "role", "event", "source"}:
            raise ValueError("relationship context uses an explicitly installed definition or actual typed context")
        if (type(self.kind_bounds) is not tuple or not self.kind_bounds
                or len({row[0] for row in self.kind_bounds}) != len(self.kind_bounds)
                or any(type(row) is not tuple or len(row) != 2 or row[0] not in KINDS for row in self.kind_bounds)):
            raise ValueError("each relationship kind needs an explicit installed bound")
        for _, limit in self.kind_bounds:
            _number(limit, 0, 2)
        _number(self.family_net_cap, 0, 2)
        _number(self.preference_pivot, -1, 1)
        _number(self.checkpoint_total_variation_cap, 0, 64)
        for refs in (self.applicable_effects, self.higher_preferred_effects, self.lower_preferred_effects):
            _refs(refs, bound=16)
        if (set(self.higher_preferred_effects) & set(self.lower_preferred_effects)
                or not set((*self.higher_preferred_effects, *self.lower_preferred_effects)) <= set(self.applicable_effects)
                or type(self.allow_evidence_initialization) is not bool or type(self.allow_reassessment_checkpoint) is not bool):
            raise ValueError("relationship preference effects must belong to their installed dimension")
        if (self.authored_prior_source_ref is None) != (self.authored_prior_estimate is None):
            raise ValueError("an authored prior requires both its actual source and value")
        if self.authored_prior_source_ref is not None:
            if AtomKey.from_token(self.authored_prior_source_ref).type_name != "memory.source":
                raise ValueError("authored prior must reference its independent source")
            _number(self.authored_prior_estimate, -1, 1)

    def matches(self, scope):
        return (self.dimension, self.relationship_domain, self.context_ref, self.dimension_schema_version) == (
            scope.dimension, scope.relationship_domain, scope.context_ref, scope.dimension_schema_version)


@dataclass(frozen=True, slots=True)
class InstalledRelationshipPolicyV2:
    policy_ref: str
    revision: int
    namespace: NamespaceId
    dimensions: tuple[str, ...]
    semantics: tuple[str, ...]
    boundary_bases: tuple[str, ...]
    dimension_rules: tuple[RelationshipDimensionRuleV2, ...]
    policy_source_refs: tuple[str, ...]
    policy_origin: str
    max_dimensions: int
    max_families: int
    max_auxiliary_calls: int
    schema_version: int = 2

    def __post_init__(self):
        _text(self.policy_ref)
        if type(self.namespace) is not NamespaceId or type(self.revision) is not int or self.revision < 1 or self.schema_version != 2:
            raise ValueError("exact installed relationship policy v2 required")
        _refs(self.dimensions, nonempty=True, bound=8)
        _refs(self.semantics, nonempty=True, bound=3)
        _refs(self.boundary_bases, nonempty=True, bound=5)
        _refs(self.policy_source_refs, nonempty=True)
        if (not set(self.semantics) <= {"external_observation", "recollection", "simulation"}
                or not set(self.boundary_bases) <= {"runtime_policy", "counterparty_explicit", "self_internal", "mutual_agreement", "inferred_preference"}
                or self.policy_origin not in {"authored", "evidence_supported"}
                or type(self.dimension_rules) is not tuple or not 1 <= len(self.dimension_rules) <= 8
                or any(type(rule) is not RelationshipDimensionRuleV2 for rule in self.dimension_rules)
                or len({(r.dimension, r.relationship_domain, r.context_ref, r.dimension_schema_version) for r in self.dimension_rules}) != len(self.dimension_rules)
                or {rule.dimension for rule in self.dimension_rules} != set(self.dimensions)
                or type(self.max_dimensions) is not int or not 1 <= self.max_dimensions <= 8
                or type(self.max_families) is not int or not 1 <= self.max_families <= 16
                or type(self.max_auxiliary_calls) is not int or not 0 <= self.max_auxiliary_calls <= 2):
            raise ValueError("relationship policy has no complete bounded installed semantics")

    def rule(self, scope):
        matches = tuple(rule for rule in self.dimension_rules if rule.matches(scope))
        if scope.namespace != self.namespace or len(matches) != 1:
            raise ValueError("relationship scope is not in its installed dimension policy")
        return matches[0]


@dataclass(frozen=True, slots=True)
class RelationshipExpectationV2:
    scope: RelationshipScopeV2
    expectation_ref: str
    expectation: str
    intensity: float
    source_refs: tuple[str, ...]
    negotiated_interpretation_refs: tuple[str, ...]
    commitment_ref: str | None

    def __post_init__(self):
        _text(self.expectation_ref); _text(self.expectation)
        _number(self.intensity, 0, 1); _refs(self.source_refs, nonempty=True)
        _refs(self.negotiated_interpretation_refs)
        if self.commitment_ref is not None and AtomKey.from_token(self.commitment_ref).type_name != "d08.commitment.v1":
            raise ValueError("expectation is not an obligation without an actual D08 commitment")


@dataclass(frozen=True, slots=True)
class ReciprocityPatternV2:
    scope: RelationshipScopeV2
    pattern_ref: str
    visible_sample_refs: tuple[str, ...]
    opportunity_source_refs: tuple[str, ...]
    capability_source_refs: tuple[str, ...]
    preference_source_refs: tuple[str, ...]
    unknown_contexts: tuple[str, ...]
    source_refs: tuple[str, ...]

    def __post_init__(self):
        _text(self.pattern_ref)
        _refs(self.visible_sample_refs, nonempty=True, bound=16)
        for refs in (self.opportunity_source_refs, self.capability_source_refs, self.preference_source_refs,
                self.unknown_contexts, self.source_refs):
            _refs(refs)
        if not self.source_refs:
            raise ValueError("reciprocity needs visible sourced samples; silence is not a sample")


@dataclass(frozen=True, slots=True)
class RepairProcessV2:
    scope: RelationshipScopeV2
    dispute_ref: str
    action_kind: str
    status: str
    source_refs: tuple[str, ...]
    proposal_interpretation_refs: tuple[str, ...]
    communication_original_ref: str | None
    communication_action_ref: str | None
    communication_effect_id: str | None
    communication_state: str
    response_interpretation_refs: tuple[str, ...]
    practice_progress_refs: tuple[str, ...]
    reevaluated_estimate_refs: tuple[str, ...]
    contact_basis_refs: tuple[str, ...]
    unresolved_items: tuple[str, ...]

    def __post_init__(self):
        _text(self.dispute_ref); _text(self.action_kind)
        if self.status not in {"proposed", "waiting", "practicing", "partial", "paused", "ended"}:
            raise ValueError("repair has no registered independent process state")
        if self.communication_state not in {"not_sent", "unknown", "accepted", "delivered", "failed"}:
            raise ValueError("repair communication outcome is not registered")
        if (self.communication_original_ref is None) != (self.communication_effect_id is None):
            raise ValueError("repair communication retains its actual original effect identity")
        if self.communication_state == "not_sent" and (self.communication_original_ref is not None or self.communication_action_ref is not None):
            raise ValueError("unsent repair cannot erase an actual pending communication identity")
        if self.communication_action_ref is not None and AtomKey.from_token(self.communication_action_ref).type_name != "d08.action_intent.v1":
            raise ValueError("repair communication requires its actual D08 action intent")
        if self.communication_state != "not_sent" and (self.communication_original_ref is None or self.communication_action_ref is None):
            raise ValueError("repair communication requires an actual original")
        for refs in (self.source_refs, self.proposal_interpretation_refs, self.response_interpretation_refs,
                self.practice_progress_refs, self.reevaluated_estimate_refs, self.contact_basis_refs, self.unresolved_items):
            _refs(refs)
        if not self.source_refs:
            raise ValueError("repair is a sourced matter, not a global reconciled flag")

    @property
    def invitation_pending(self):
        return self.communication_state in {"unknown", "accepted", "delivered"} and not self.response_interpretation_refs


@dataclass(frozen=True, slots=True)
class RelationshipEvaluationCandidateV2:
    scope: RelationshipScopeV2
    trigger_original_ref: str
    contribution_kind: str
    requested_delta: float | None
    initial_estimate: float | None
    initial_origin_ref: str | None
    reassessment_interpretation_ref: str | None
    reassessment_basis_versions: tuple[GraphVersion, ...]
    subjective_confidence: float
    evidence_coverage: str
    support_refs: tuple[str, ...]
    counter_refs: tuple[str, ...]
    interpretation_refs: tuple[str, ...]
    affect_refs: tuple[str, ...]
    source_refs: tuple[str, ...]
    applicable_effects: tuple[str, ...]
    valid_from: float
    valid_until: float | None
    expectation: RelationshipExpectationV2 | None
    reciprocity: ReciprocityPatternV2 | None
    repair: RepairProcessV2 | None
    schema: str = "d05.relationship-evaluation-candidate.v2"

    def __post_init__(self):
        if type(self.scope) is not RelationshipScopeV2 or self.schema != "d05.relationship-evaluation-candidate.v2" or self.contribution_kind not in KINDS:
            raise ValueError("exact directed relationship evaluation candidate required")
        _text(self.trigger_original_ref)
        if (type(self.reassessment_basis_versions) is not tuple or len(self.reassessment_basis_versions) > 32
                or any(type(row) is not GraphVersion for row in self.reassessment_basis_versions)
                or (self.reassessment_interpretation_ref is None) != (not self.reassessment_basis_versions)):
            raise ValueError("relationship reassessment binds its actual previous state and invalidation versions")
        _number(self.subjective_confidence, 0, 1)
        if self.evidence_coverage not in {"complete", "partial", "unknown"}:
            raise ValueError("relationship evidence coverage is not registered")
        for refs in (self.support_refs, self.counter_refs, self.interpretation_refs, self.affect_refs,
                self.source_refs, self.applicable_effects):
            _refs(refs)
        if not self.source_refs or not self.support_refs:
            raise ValueError("relationship candidate requires actual support and source closure")
        _number(self.valid_from, 0, float("inf"))
        if self.valid_until is not None:
            _number(self.valid_until, self.valid_from, float("inf"))
        if self.requested_delta is not None:
            _number(self.requested_delta, -2, 2)
        if (self.initial_estimate is None) != (self.initial_origin_ref is None):
            raise ValueError("unknown initialization requires an independently sourced initial value")
        if self.initial_estimate is not None:
            _number(self.initial_estimate, -1, 1)
            if self.initial_origin_ref not in self.source_refs or self.requested_delta is not None:
                raise ValueError("initialization cannot add a delta or omit its source")
        for extra, cls in ((self.expectation, RelationshipExpectationV2), (self.reciprocity, ReciprocityPatternV2), (self.repair, RepairProcessV2)):
            if extra is not None and (type(extra) is not cls or extra.scope != self.scope or not set(extra.source_refs) <= set(self.source_refs)):
                raise ValueError("relationship ancillary state changed its sourced directional scope")


@dataclass(frozen=True, slots=True)
class RelationshipCheckpointV2:
    scope: RelationshipScopeV2
    initial_estimate: float
    initial_origin_ref: str
    initialization_original_ref: str
    initialization_kind: str
    initial_origin_head: GraphVersion
    initial_origin_digest: str
    policy_ref: str
    policy_digest: str
    source_refs: tuple[str, ...]
    checkpoint_ref: str

    def __post_init__(self):
        _number(self.initial_estimate, -1, 1)
        for value in (self.initial_origin_ref, self.initialization_original_ref, self.initial_origin_digest, self.policy_ref, self.policy_digest, self.checkpoint_ref): _text(value)
        _refs(self.source_refs, nonempty=True)
        if (self.initialization_kind not in {"authored_prior", "evaluation_prior", "reassessment"}
                or type(self.initial_origin_head) is not GraphVersion or self.initial_origin_head.revision < 1
                or self.initial_origin_head.key.token != self.initial_origin_ref
                or NamespaceId.from_key(self.initial_origin_head.key) != self.scope.namespace
                or len(self.initial_origin_digest) != 64):
            raise ValueError("relationship initialization retains its exact independently sourced original")
        if self.initial_origin_ref not in self.source_refs:
            raise ValueError("relationship checkpoint retains its actual initialization source")


@dataclass(frozen=True, slots=True)
class InteractionContributionV3:
    scope: RelationshipScopeV2
    canonical_trigger_identity: str
    kind: str
    content_families: tuple[str, ...]
    source_refs: tuple[str, ...]
    evaluation_interpretation_ref: str
    trigger_original_ref: str
    original_sequence: int
    checkpoint_ref: str
    frozen_kind_bound: float
    support_refs: tuple[str, ...]
    counter_refs: tuple[str, ...]
    interpretation_refs: tuple[str, ...]
    affect_refs: tuple[str, ...]
    requested_delta: float
    applied_delta: float
    legacy_alias_refs: tuple[str, ...]
    policy_ref: str
    policy_digest: str

    def __post_init__(self):
        if type(self.scope) is not RelationshipScopeV2 or self.kind not in KINDS or type(self.original_sequence) is not int or self.original_sequence < 1:
            raise ValueError("interaction contribution requires actual committed identity/order")
        _text(self.canonical_trigger_identity)
        _refs(self.content_families, nonempty=True, bound=16); _refs(self.source_refs, nonempty=True)
        for value in (self.evaluation_interpretation_ref, self.trigger_original_ref, self.policy_ref, self.policy_digest): _text(value)
        _text(self.checkpoint_ref); _number(self.frozen_kind_bound, 0, 2)
        for refs in (self.support_refs, self.counter_refs, self.interpretation_refs, self.affect_refs): _refs(refs)
        _number(self.requested_delta, -2, 2); _number(self.applied_delta, -2, 2)
        _refs(self.legacy_alias_refs)

    @property
    def key(self):
        return self.scope.key(CONTRIBUTION_TYPE, (self.kind, self.canonical_trigger_identity))


@dataclass(frozen=True, slots=True)
class DimensionEstimateV2:
    scope: RelationshipScopeV2
    estimate: float
    subjective_confidence: float
    evidence_coverage: str
    support_refs: tuple[str, ...]
    counter_refs: tuple[str, ...]
    independent_families: tuple[str, ...]
    external_event_identities: tuple[str, ...]
    interpretation_refs: tuple[str, ...]
    checkpoint_ref: str
    contribution_refs: tuple[str, ...]
    family_net_influence: tuple[tuple[str, float], ...]
    checkpoint_total_variation: float
    policy_ref: str
    policy_digest: str
    applicable_effects: tuple[str, ...]
    valid_from: float
    valid_until: float | None
    source_refs: tuple[str, ...]
    status: str

    def __post_init__(self):
        _number(self.estimate, -1, 1); _number(self.subjective_confidence, 0, 1)
        _number(self.checkpoint_total_variation, 0, 64)
        if self.status not in {"current", "held_reevaluation"} or self.evidence_coverage not in {"complete", "partial", "unknown"}:
            raise ValueError("relationship estimate status/coverage is not registered")
        for refs in (self.support_refs, self.counter_refs, self.interpretation_refs, self.contribution_refs,
                self.applicable_effects, self.source_refs): _refs(refs)
        _refs(self.independent_families, bound=16); _refs(self.external_event_identities, bound=32)
        if (type(self.family_net_influence) is not tuple or len(self.family_net_influence) > 16
                or len({family for family, _ in self.family_net_influence}) != len(self.family_net_influence)):
            raise ValueError("relationship family influence must be bounded and unique")
        for _, influence in self.family_net_influence: _number(influence, -2, 2)
        _number(self.valid_from, 0, float("inf"))
        if self.valid_until is not None: _number(self.valid_until, self.valid_from, float("inf"))
        for value in (self.checkpoint_ref, self.policy_ref, self.policy_digest): _text(value)


@dataclass(frozen=True, slots=True)
class RelationshipProfileV2:
    scope: RelationshipScopeV2
    estimate_refs: tuple[str, ...]
    expectation_refs: tuple[str, ...]
    reciprocity_refs: tuple[str, ...]
    repair_refs: tuple[str, ...]
    source_refs: tuple[str, ...]

    def __post_init__(self):
        _refs(self.estimate_refs, nonempty=True, bound=8)
        for refs in (self.expectation_refs, self.reciprocity_refs, self.repair_refs, self.source_refs): _refs(refs)
        if any(AtomKey.from_token(ref).type_name != ESTIMATE_TYPE for ref in self.estimate_refs):
            raise ValueError("relationship profile aggregates estimate references, not another score")


@dataclass(frozen=True, slots=True)
class RelationshipRebuildV2:
    estimate: DimensionEstimateV2
    contributions: tuple[InteractionContributionV3, ...]
    held_reason: str | None


def rebuild_relationship_dimension_v2(*, checkpoint, contributions, candidate, policy, policy_digest, previous_estimate):
    """Recompute latest contribution revisions once; never subtract an old delta."""
    rule = policy.rule(candidate.scope)
    if type(checkpoint) is not RelationshipCheckpointV2 or checkpoint.scope.scope_id != candidate.scope.scope_id:
        raise ValueError("relationship rebuild requires its original sourced checkpoint")
    if len(contributions) > 32 or len({row.key for row in contributions}) != len(contributions):
        raise ValueError("relationship rebuild has repeated or unbounded current contributions")
    families = {family for row in contributions for family in row.content_families}
    if len(families) > policy.max_families:
        raise ValueError("relationship rebuild cannot drop a mandatory family/counterexample")
    value, net, revised, held = checkpoint.initial_estimate, {}, [], None
    limits = dict(rule.kind_bounds)
    for row in sorted(contributions, key=lambda item: (item.original_sequence, item.key.token)):
        if row.scope.scope_id != candidate.scope.scope_id or row.kind not in limits or row.checkpoint_ref != checkpoint.checkpoint_ref:
            raise ValueError("relationship contribution is outside the exact installed kind/scope")
        delta = max(-row.frozen_kind_bound, min(row.frozen_kind_bound, row.requested_delta))
        next_value = max(-1.0, min(1.0, value + delta))
        applied = next_value - value
        prospective = {family: net.get(family, 0.0) + applied for family in row.content_families}
        if held or any(abs(amount) > rule.family_net_cap for amount in prospective.values()):
            held = "source_family_or_checkpoint_drift_requires_reevaluation"
            applied = 0.0
        else:
            value = next_value
            net.update(prospective)
        revised.append(replace(row, applied_delta=applied))
    if previous_estimate is None:
        variation = abs(value - checkpoint.initial_estimate)
    else:
        if previous_estimate.scope.scope_id != candidate.scope.scope_id or previous_estimate.checkpoint_ref != checkpoint.checkpoint_ref:
            raise ValueError("relationship rebuild cannot reset its actual checkpoint through a revision/policy change")
        variation = previous_estimate.checkpoint_total_variation + abs(value - previous_estimate.estimate)
    if variation > rule.checkpoint_total_variation_cap:
        held = "checkpoint_total_variation_requires_reevaluation"
    if held and previous_estimate is not None:
        return RelationshipRebuildV2(replace(previous_estimate, status="held_reevaluation"), (), held)
    sources = tuple(dict.fromkeys((*checkpoint.source_refs, *(ref for row in contributions for ref in row.source_refs), *candidate.source_refs)))
    if len(sources) > 32:
        raise ValueError("relationship rebuild source closure exceeds its actual read bound")
    estimate = DimensionEstimateV2(candidate.scope, value, candidate.subjective_confidence, candidate.evidence_coverage,
        tuple(dict.fromkeys(ref for row in revised for ref in row.support_refs)),
        tuple(dict.fromkeys(ref for row in revised for ref in row.counter_refs)),
        tuple(sorted({family for row in revised if row.kind == "external_interaction" for family in row.content_families})),
        tuple(sorted({row.canonical_trigger_identity for row in contributions if row.kind == "external_interaction"})),
        tuple(dict.fromkeys((*((checkpoint.initialization_original_ref,) if checkpoint.initialization_kind != "authored_prior" else ()), *(row.evaluation_interpretation_ref for row in revised)))),
        checkpoint.checkpoint_ref, tuple(row.key.token for row in revised), tuple(sorted(net.items())), variation,
        policy.policy_ref, policy_digest, candidate.applicable_effects, candidate.valid_from, candidate.valid_until,
        sources, "held_reevaluation" if held else "current")
    return RelationshipRebuildV2(estimate, tuple(revised), held)


_VALUE_TYPES = {PROFILE_TYPE: RelationshipProfileV2, ESTIMATE_TYPE: DimensionEstimateV2,
    CONTRIBUTION_TYPE: InteractionContributionV3, CHECKPOINT_TYPE: RelationshipCheckpointV2,
    EXPECTATION_TYPE: RelationshipExpectationV2, RECIPROCITY_TYPE: ReciprocityPatternV2, REPAIR_TYPE: RepairProcessV2}


def relationship_revision_type_specs_v2():
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    def validate(value, cls):
        decode_typed_production_value_v1(value, cls)
    return tuple(TypeSpec(name, ("relation",), "state", lambda value, cls=cls: validate(value, cls),
        immutable=name == CHECKPOINT_TYPE, writer_domain="d05", schema_version=3 if name == CONTRIBUTION_TYPE else 2,
        schema_hash=schema_hash({"type": name, "version": 3 if name == CONTRIBUTION_TYPE else 2,
            "fields": tuple((field.name, str(field.type)) for field in fields(cls)),
            "scope_schema": tuple((field.name, str(field.type)) for field in fields(RelationshipScopeV2)),
            "contribution_kinds": KINDS, "numeric_range": (-1, 1), "unknown_initialization": "sourced_original_required"}))
        for name, cls in _VALUE_TYPES.items())


@dataclass(frozen=True, slots=True)
class RelationshipPreferenceInputV2:
    candidate_ref: str
    scope: RelationshipScopeV2
    estimate_head: GraphVersion
    effect_kind: str
    preference: str
    policy_ref: str
    policy_revision: int
    policy_digest: str

    def __post_init__(self):
        _text(self.candidate_ref); _text(self.effect_kind); _text(self.policy_ref); _text(self.policy_digest)
        if (self.preference not in {"favored", "disfavored", "neutral"} or self.estimate_head.key.type_name != ESTIMATE_TYPE
                or self.estimate_head.revision < 1 or type(self.policy_revision) is not int or self.policy_revision < 1):
            raise ValueError("relationship preference requires its actual current estimate and signed policy")


@dataclass(frozen=True, slots=True)
class RelationshipPreferenceProjectionV2:
    namespace: NamespaceId
    candidate_refs: tuple[str, ...]
    preference_edges: tuple[tuple[str, str], ...]
    inputs: tuple[RelationshipPreferenceInputV2, ...]
    candidate_statuses: tuple[tuple[str, str], ...]
    source_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]

    def __post_init__(self):
        _refs(self.candidate_refs, nonempty=True, bound=6); _refs(self.source_refs)
        if (type(self.namespace) is not NamespaceId or type(self.inputs) is not tuple or len(self.inputs) > 48
                or any(type(row) is not RelationshipPreferenceInputV2 or row.scope.namespace != self.namespace for row in self.inputs)
                or type(self.preference_edges) is not tuple or len(self.preference_edges) > 30
                or len(set(self.preference_edges)) != len(self.preference_edges)
                or any(a == b or a not in self.candidate_refs or b not in self.candidate_refs for a, b in self.preference_edges)
                or {ref for ref, _ in self.candidate_statuses} != set(self.candidate_refs)
                or any(status not in {"unscoped", "unknown", "current", "held"} for _, status in self.candidate_statuses)):
            raise ValueError("relationship preference is an exact bounded candidate partial order")
