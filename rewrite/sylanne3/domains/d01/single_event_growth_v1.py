"""Explicit single-event exception; existing V3 and General defaults stay unchanged."""
from dataclasses import dataclass, fields
import math

from ...graph_types import AtomKey, GraphVersion, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, canonical_digest, schema_hash
from .identity_v3 import RuntimeIdentityRef, _text, _digest, _refs
from ...runtime.domain_production_contracts_v1 import ProductionOriginalRefV1

POLICY_KIND = "single_event_growth_policy_v1"
INPUT_KIND = "single_event_growth_input_v1"
ADOPTION_TYPE = "d01.single_event_growth_adoption.v1"
REVIEW_TYPE = "d01.single_event_growth_review.v1"
REVIEW_EVENT = "single_event_growth_review_required_v1"
REVIEW_TYPE_V2 = "d01.single_event_growth_review.v2"
SCOPE_TYPES = frozenset({"d08.goal.v1", "d08.personal_plan.v1", "d08.action_intent.v1", "d10.life_project.v1"})
OUTCOME_TYPES = frozenset({"d08.action_outcome.v1", "d10.life_progress.v1"})


def _version(value, namespace, allowed):
    if (type(value) is not GraphVersion or value.revision < 1
            or NamespaceId.from_key(value.key) != namespace or value.key.type_name not in allowed):
        raise ValueError("single-event selector requires its exact namespace, type and positive revision")


def _versions(values, namespace, allowed, *, nonempty=False):
    if (type(values) is not tuple or len(values) > 128 or len({v.key for v in values}) != len(values)
            or nonempty and not values):
        raise ValueError("single-event selectors require a finite unique tuple")
    for value in values:
        _version(value, namespace, allowed)


def _time(value):
    if type(value) not in {int, float} or not math.isfinite(value):
        raise ValueError("single-event windows require finite original UTC times")


@dataclass(frozen=True, slots=True)
class SingleEventGrowthTermsV1:
    namespace: NamespaceId
    policy_ref: str
    revision: int
    expected_persona_head: GraphVersion
    persona_head_id: str
    target_block: str
    target_kind: str
    base_claim_digest: str
    event_source: GraphVersion
    event_source_digest: str
    event_provenance_root: str
    event_interpretation: GraphVersion
    event_interpretation_digest: str
    context_source_refs: tuple[str, ...]
    scope_versions: tuple[GraphVersion, ...]
    exclusion_versions: tuple[GraphVersion, ...]
    plasticity_policy_ref: str | None
    plasticity_policy_digest: str | None
    observer_policy_ref: str
    observer_policy_digest: str
    valid_from_utc: float
    adopt_before_utc: float
    review_not_before_utc: float
    review_due_utc: float
    readout_valid_until_utc: float
    required_outcome_versions: tuple[GraphVersion, ...] = ()

    def __post_init__(self):
        if type(self.namespace) is not NamespaceId or type(self.revision) is not int or self.revision < 1:
            raise ValueError("single-event policy requires an actual namespace and positive revision")
        for value in (self.policy_ref, self.persona_head_id, self.target_block, self.target_kind,
                      self.event_provenance_root, self.observer_policy_ref):
            _text(value)
        for value in (self.base_claim_digest, self.event_source_digest, self.event_interpretation_digest,
                      self.observer_policy_digest):
            _digest(value)
        if self.target_kind not in {"semantic_identity", "value", "trait"}:
            raise ValueError("single-event growth is restricted to an explicit core value, trait or semantic identity block")
        _version(self.expected_persona_head, self.namespace, {"d01.persona_plan.v1"})
        _version(self.event_source, self.namespace, {"memory.source"})
        _version(self.event_interpretation, self.namespace, {"d07.current_interpretation.v1"})
        _refs(self.context_source_refs)
        for ref in self.context_source_refs:
            key = AtomKey.from_token(ref)
            if NamespaceId.from_key(key) != self.namespace or key.type_name != "memory.source" or key == self.event_source.key:
                raise ValueError("single-event context cannot become its one supporting event")
        _versions(self.scope_versions, self.namespace, SCOPE_TYPES, nonempty=True)
        _versions(self.exclusion_versions, self.namespace, SCOPE_TYPES)
        if {v.key for v in self.scope_versions} & {v.key for v in self.exclusion_versions}:
            raise ValueError("single-event scope and exclusions overlap")
        _versions(self.required_outcome_versions, self.namespace, OUTCOME_TYPES)
        if (self.plasticity_policy_ref is None) != (self.plasticity_policy_digest is None):
            raise ValueError("single-event deep plasticity binding is incomplete")
        if self.plasticity_policy_ref is not None:
            _text(self.plasticity_policy_ref); _digest(self.plasticity_policy_digest)
        if self.target_kind == "semantic_identity" and self.plasticity_policy_ref is None:
            raise ValueError("semantic single-event policy retains its actual V3 plasticity policy")
        for value in (self.valid_from_utc, self.adopt_before_utc, self.review_not_before_utc,
                      self.review_due_utc, self.readout_valid_until_utc):
            _time(value)
        if not (self.valid_from_utc < self.adopt_before_utc <= self.review_due_utc <= self.readout_valid_until_utc
                and self.valid_from_utc <= self.review_not_before_utc < self.review_due_utc):
            raise ValueError("single-event original adoption, review and readout windows differ")


@dataclass(frozen=True, slots=True)
class SingleEventScopeCommitmentV1:
    version: GraphVersion
    cell_id: str
    codec_id: str
    payload_sha256: str
    semantic_digest: str
    total_bytes: int
    producer_operation_id: str
    def __post_init__(self):
        if type(self.version) is not GraphVersion or self.version.revision < 1 or self.version.key.type_name not in SCOPE_TYPES:
            raise ValueError("single-event scope commitment requires its exact actual target version")
        _text(self.cell_id); _text(self.producer_operation_id); _digest(self.payload_sha256); _digest(self.semantic_digest)
        if self.codec_id not in {"canonical-json.ascii.v1", "canonical-json.utf8.v1"} or type(self.total_bytes) is not int or self.total_bytes < 1:
            raise ValueError("single-event scope commitment requires the actual sealed physical codec/hash/bytes")


@dataclass(frozen=True, slots=True)
class SingleEventGrowthPolicyV1:
    terms: SingleEventGrowthTermsV1
    runtime_identity: RuntimeIdentityRef
    owner_grant: GraphVersion
    owner_grant_digest: str
    owner_binding_digest: str
    registered_at_utc: float
    registration_operation_id: str
    scope_commitments: tuple[SingleEventScopeCommitmentV1, ...]
    source_refs: tuple[str, ...]
    schema: str = "d01.single-event-growth-policy.v1"

    def __post_init__(self):
        if (self.schema != "d01.single-event-growth-policy.v1" or type(self.terms) is not SingleEventGrowthTermsV1
                or type(self.runtime_identity) is not RuntimeIdentityRef
                or self.runtime_identity.namespace != self.terms.namespace):
            raise ValueError("single-event policy requires its actual runtime and closed terms")
        _version(self.owner_grant, self.terms.namespace, {"d11.owner_grant.v1"})
        _digest(self.owner_grant_digest); _digest(self.owner_binding_digest)
        _text(self.registration_operation_id); _time(self.registered_at_utc); _refs(self.source_refs)
        if not self.source_refs:
            raise ValueError("single-event policy retains its actual Source read-plan roots")
        if (type(self.scope_commitments) is not tuple or any(type(v) is not SingleEventScopeCommitmentV1 for v in self.scope_commitments)
                or tuple(v.version for v in self.scope_commitments) != (*self.terms.scope_versions, *self.terms.exclusion_versions)):
            raise ValueError("single-event policy must bind every actual scope/exclusion sealed header")
        if not self.terms.valid_from_utc <= self.registered_at_utc < self.terms.adopt_before_utc:
            raise ValueError("single-event registration is outside its original adoption window")


@dataclass(frozen=True, slots=True)
class SingleEventGrowthInputV1:
    input_ref: str
    policy_ref: str
    policy_digest: str
    registration_operation_id: str
    growth_proposal_ref: str
    trigger_original_ref: str
    trial_original_refs: tuple[str, ...]
    counterevidence_query_ref: str
    general_growth_intent_ref: str | None
    continuity_interpretation_ref: str
    replacement_claim_digest: str
    event_provenance_root: str
    source_refs: tuple[str, ...]
    source_versions: tuple[GraphVersion, ...]
    prepared_at_utc: float
    schema: str = "d01.single-event-growth-input.v1"

    def __post_init__(self):
        if self.schema != "d01.single-event-growth-input.v1":
            raise ValueError("single-event input schema differs")
        for value in (self.input_ref, self.policy_ref, self.registration_operation_id, self.growth_proposal_ref,
                      self.trigger_original_ref, self.counterevidence_query_ref, self.continuity_interpretation_ref,
                      self.event_provenance_root):
            _text(value)
        for value in (self.policy_digest, self.replacement_claim_digest):
            _digest(value)
        _refs(self.trial_original_refs); _refs(self.source_refs); _time(self.prepared_at_utc)
        if not 1 <= len(self.trial_original_refs) <= 16 or not self.source_refs:
            raise ValueError("single-event growth retains its original nonempty completed trial and Source scope")
        if self.general_growth_intent_ref is not None:
            _text(self.general_growth_intent_ref)
        if (type(self.source_versions) is not tuple or not self.source_versions
                or len({v.key for v in self.source_versions}) != len(self.source_versions)
                or any(type(v) is not GraphVersion for v in self.source_versions)):
            raise ValueError("single-event input retains actual complete Source qualification versions")


@dataclass(frozen=True, slots=True)
class SingleEventGrowthAdoptionV1:
    namespace: NamespaceId
    policy_ref: str
    policy_digest: str
    input_ref: str
    input_digest: str
    adoption_operation_id: str
    target_block: str
    previous_head: str
    adopted_head: str
    adopted_claim_digest: str
    event_provenance_root: str
    review_ref: str
    adopted_at_utc: float
    review_not_before_utc: float
    review_due_utc: float
    readout_valid_until_utc: float
    source_refs: tuple[str, ...]
    schema: str = "d01.single-event-growth-adoption.v1"

    def __post_init__(self):
        if self.schema != "d01.single-event-growth-adoption.v1" or type(self.namespace) is not NamespaceId:
            raise ValueError("single-event adoption namespace/schema differs")
        for name in ("policy_ref", "input_ref", "adoption_operation_id", "target_block", "previous_head",
                     "adopted_head", "event_provenance_root", "review_ref"):
            _text(getattr(self, name))
        for name in ("policy_digest", "input_digest", "adopted_claim_digest"):
            _digest(getattr(self, name))
        _refs(self.source_refs)
        for value in (self.adopted_at_utc, self.review_not_before_utc, self.review_due_utc, self.readout_valid_until_utc):
            _time(value)
        if not (self.adopted_at_utc < self.review_due_utc <= self.readout_valid_until_utc
                and self.review_not_before_utc < self.review_due_utc):
            raise ValueError("single-event adoption cannot reset its original review window")


@dataclass(frozen=True, slots=True)
class SingleEventGrowthReviewV1:
    namespace: NamespaceId
    adoption_ref: str
    adoption_operation_id: str
    adopted_head: str
    target_block: str
    adopted_claim_digest: str
    review_not_before_utc: float
    review_due_utc: float
    readout_valid_until_utc: float
    disposition: str
    reviewed_at_utc: float | None
    continuity_interpretation_ref: str | None
    observed_original_refs: tuple[str, ...]
    missing_conditions: tuple[str, ...]
    source_refs: tuple[str, ...]
    schema: str = "d01.single-event-growth-review.v1"

    def __post_init__(self):
        if self.schema != "d01.single-event-growth-review.v1" or type(self.namespace) is not NamespaceId:
            raise ValueError("single-event review namespace/schema differs")
        for name in ("adoption_ref", "adoption_operation_id", "adopted_head", "target_block"):
            _text(getattr(self, name))
        _digest(self.adopted_claim_digest)
        for refs in (self.observed_original_refs, self.missing_conditions, self.source_refs):
            _refs(refs)
        for value in (self.review_not_before_utc, self.review_due_utc, self.readout_valid_until_utc):
            _time(value)
        if not self.review_not_before_utc < self.review_due_utc <= self.readout_valid_until_utc:
            raise ValueError("single-event review immutable window differs")
        if self.disposition not in {"pending", "qualified", "opposed", "unknown", "expired"}:
            raise ValueError("single-event review has another disposition")
        if self.disposition == "pending":
            if self.reviewed_at_utc is not None or self.continuity_interpretation_ref is not None or self.observed_original_refs:
                raise ValueError("a new same-CAS obligation is not a performed review")
        else:
            _time(self.reviewed_at_utc)
        if self.continuity_interpretation_ref is not None:
            _text(self.continuity_interpretation_ref)
        if self.disposition == "qualified" and (self.missing_conditions or self.continuity_interpretation_ref is None
                or not self.review_not_before_utc <= self.reviewed_at_utc < self.review_due_utc):
            raise ValueError("qualified review requires complete actual post-adoption continuity within the original window")


@dataclass(frozen=True, slots=True)
class SingleEventGrowthReviewV2:
    namespace: NamespaceId
    adoption_ref: str
    adoption_operation_id: str
    adopted_head: str
    target_block: str
    adopted_claim_digest: str
    review_not_before_utc: float
    review_due_utc: float
    readout_valid_until_utc: float
    disposition: str
    reviewed_at_utc: float | None
    continuity_interpretation_ref: str | None
    observed_original_refs: tuple[str, ...]
    missing_conditions: tuple[str, ...]
    source_refs: tuple[str, ...]
    review_case_original: ProductionOriginalRefV1 | None
    schema: str = "d01.single-event-growth-review.v2"

    def __post_init__(self):
        if self.schema != "d01.single-event-growth-review.v2" or type(self.namespace) is not NamespaceId:
            raise ValueError("single-event review namespace/schema differs")
        for name in ("adoption_ref", "adoption_operation_id", "adopted_head", "target_block"):
            _text(getattr(self, name))
        _digest(self.adopted_claim_digest)
        for refs in (self.observed_original_refs, self.missing_conditions, self.source_refs):
            _refs(refs)
        for value in (self.review_not_before_utc, self.review_due_utc, self.readout_valid_until_utc):
            _time(value)
        if not self.review_not_before_utc < self.review_due_utc <= self.readout_valid_until_utc:
            raise ValueError("single-event review immutable window differs")
        if self.disposition not in {"pending", "qualified", "opposed", "unknown", "expired"}:
            raise ValueError("single-event review has another disposition")
        from ...runtime.domain_production_contracts_v1 import ProductionOriginalRefV1
        original=self.review_case_original
        if original is not None and (type(original) is not ProductionOriginalRefV1
                or original.kind!='d01.single_event_review_case_v1'):
            raise TypeError('Review V2 locator requires its actual registered signed Case original')
        if self.disposition=='qualified' and original is None:
            raise ValueError('qualified Review V2 requires the actual consumed Case original')
        if self.disposition == "pending":
            if original is not None:raise ValueError('pending Review V2 has not consumed a Case')
            if self.reviewed_at_utc is not None or self.continuity_interpretation_ref is not None or self.observed_original_refs:
                raise ValueError("a new same-CAS obligation is not a performed review")
        else:
            _time(self.reviewed_at_utc)
        if self.continuity_interpretation_ref is not None:
            _text(self.continuity_interpretation_ref)
        if self.disposition == "qualified" and (self.missing_conditions or self.continuity_interpretation_ref is None
                or not self.review_not_before_utc <= self.reviewed_at_utc < self.review_due_utc):
            raise ValueError("qualified review requires complete actual post-adoption continuity within the original window")


def single_event_adoption_key_v1(namespace, policy_ref):
    return AtomKey(Owner("persona", *namespace.as_tuple), ADOPTION_TYPE,
                   "single-event:" + canonical_digest((namespace, policy_ref))[:48])


def single_event_review_key_v1(namespace, policy_ref):
    return AtomKey(Owner("persona", *namespace.as_tuple), REVIEW_TYPE,
                   "single-event-review:" + canonical_digest((namespace, policy_ref))[:48])


def single_event_type_specs_v1():
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    def validate_adoption(value):
        decode_typed_production_value_v1(value, SingleEventGrowthAdoptionV1)
    def validate_review(value):
        decode_typed_production_value_v1(value, SingleEventGrowthReviewV1)
    return tuple(TypeSpec(name, ("persona",), "state", validator, writer_domain="d01",
        schema_hash=schema_hash({"type": name, "schema_version": 1,
            "fields": [field.name for field in fields(cls)]}))
        for name, cls, validator in ((ADOPTION_TYPE, SingleEventGrowthAdoptionV1, validate_adoption),
                                     (REVIEW_TYPE, SingleEventGrowthReviewV1, validate_review)))

SINGLE_EVENT_OPERATION_KINDS_V1 = frozenset({
    "register_single_event_growth_policy_v1", "prepare_single_event_growth_v1", "adopt_single_event_growth_v1",
    "review_single_event_growth_v1", "read_single_event_growth_v1"})
SINGLE_EVENT_ORIGINAL_TYPES_V1 = {POLICY_KIND: SingleEventGrowthPolicyV1, INPUT_KIND: SingleEventGrowthInputV1}


def single_event_review_key_v2(namespace,policy_ref):
    return AtomKey(Owner('persona',*namespace.as_tuple),REVIEW_TYPE_V2,
        'single-event-review:'+canonical_digest((namespace,policy_ref))[:48])


def single_event_review_type_specs_v2():
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    def validate_review_v2(value):
        decode_typed_production_value_v1(value,SingleEventGrowthReviewV2)
    return (TypeSpec(REVIEW_TYPE_V2,('persona',),'state',validate_review_v2,writer_domain='d01',
        schema_hash=schema_hash({'type':REVIEW_TYPE_V2,'schema_version':2,
            'fields':[field.name for field in fields(SingleEventGrowthReviewV2)]})),)
