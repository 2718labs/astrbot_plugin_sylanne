"""Pure ordinary cumulative-growth contracts; these values issue no authority."""
from dataclasses import dataclass
import math

from ...graph_types import GraphVersion, NamespaceEpoch
from ...runtime_contracts import CommitReceipt, canonical_digest, NamespaceId
from ...runtime.domain_production_contracts_v1 import ProductionOriginalRefV1
from ...runtime.d01_ordinary_origin_v3 import OrdinaryHeadCommitmentV3, OrdinaryBlockCommitmentV3
from .identity_v3 import _text, _digest

POLICY_KIND = "ordinary_cumulative_growth_policy_v1"
ASSESSMENT_KIND = "ordinary_continuity_assessment_v1"
DEEP_ADOPTION_KIND = "ordinary_deep_growth_adoption_v1"
ANCHOR_TYPE = "d01.ordinary_deep_growth_anchor.v1"
SCREEN_PROFILE = "d01.ordinary-continuity-screen.v1"
DEEP_PROFILE = "d01.ordinary-deep-continuity.v1"
SCREEN_PREFIX = "d01.ordinary-continuity-screen.v1:"
DEEP_PREFIX = "d01.ordinary-deep-continuity.v1:"


def _time(value):
    if type(value) not in {int, float} or not math.isfinite(value):
        raise ValueError("ordinary cumulative policy requires a finite original UTC deadline")


def _original(value):
    if type(value) is not ProductionOriginalRefV1:
        raise TypeError("ordinary continuity retains its exact production original")


def _originals(values):
    if type(values) is not tuple or len(set(values)) != len(values):
        raise ValueError("ordinary continuity original membership repeats")
    for value in values:
        _original(value)


def _blocks(values):
    if (type(values) is not tuple or not values or any(type(v) is not OrdinaryBlockCommitmentV3 for v in values)
            or len({v.block_id for v in values}) != len(values)):
        raise ValueError("ordinary continuity requires every exact block commitment")


def _head(value):
    if type(value) is not OrdinaryHeadCommitmentV3:
        raise TypeError("ordinary continuity requires its measured complete head")
    _blocks(value.blocks)
    if (value.version < 1 or value.plan_ref.revision < 1 or value.activation_ref.revision < 1
            or value.plan_ref.key.type_name != "d01.persona_plan.v1"
            or value.activation_ref.key.type_name != "d01.persona_activation.v1"):
        raise ValueError("ordinary continuity has another current head binding")


def ordinary_block_v1(value):
    return value.kind != "semantic_identity" and value.plasticity == "growth" and value.claim_protocol is None



def ordinary_growth_block_v1(block):
    """Classify an already Source-qualified actual PersonaBlock, not a selector."""
    from . import PersonaBlock
    import re
    if type(block) is not PersonaBlock:
        raise TypeError("ordinary target classification requires its actual typed PersonaBlock")
    protocols = {"d01.semantic-identity-revision.v3", "d01.conditioned-capability-revision.v1",
        "d01.conditioned-strategy-revision.v1", "d01.method-policy.v1"}
    schemas = tuple(re.finditer(r'"schema"\s*:\s*"([^"\\]+)"', block.claim))
    if any(match.group(1) not in protocols for match in schemas):
        raise ValueError("unknown embedded claim schema cannot be classified as ordinary")
    protocol = next((name for name in protocols if name in block.claim), None)
    return block.kind != "semantic_identity" and block.plasticity == "growth" and protocol is None


@dataclass(frozen=True, slots=True)
class OrdinaryCumulativeGrowthPolicyV1:
    policy_id: str
    policy_version: int
    escalate_at_change_count: int
    valid_until_utc: float
    screen_profile: str = SCREEN_PROFILE
    deep_profile: str = DEEP_PROFILE
    schema: str = "d01.ordinary-cumulative-growth-policy.v1"

    def __post_init__(self):
        _text(self.policy_id)
        if (self.schema != "d01.ordinary-cumulative-growth-policy.v1"
                or type(self.policy_version) is not int or self.policy_version < 1
                or type(self.escalate_at_change_count) is not int or self.escalate_at_change_count < 1
                or self.screen_profile != SCREEN_PROFILE or self.deep_profile != DEEP_PROFILE):
            raise ValueError("Owner must explicitly choose the ordinary cumulative change threshold")
        _time(self.valid_until_utc)


@dataclass(frozen=True, slots=True)
class OrdinaryContinuityAnchorV1:
    kind: str
    original: ProductionOriginalRefV1
    head: OrdinaryHeadCommitmentV3
    receipt_digest: str

    def __post_init__(self):
        if self.kind not in {"initial", "deep"}:
            raise ValueError("only actual initialization or committed deep adoption can anchor continuity")
        _original(self.original); _head(self.head); _digest(self.receipt_digest)


@dataclass(frozen=True, slots=True)
class OrdinaryHistoryCoverageV1:
    anchor_head: str
    current_head: str
    transition_count: int
    ordinary_change_count: int
    chain_digest: str
    inventory_versions: tuple[GraphVersion, ...]
    query_epochs: tuple[NamespaceEpoch, ...]

    def __post_init__(self):
        _text(self.anchor_head); _text(self.current_head); _digest(self.chain_digest)
        if (type(self.transition_count) is not int or type(self.ordinary_change_count) is not int
                or not 0 <= self.ordinary_change_count <= self.transition_count
                or type(self.inventory_versions) is not tuple
                or any(type(v) is not GraphVersion for v in self.inventory_versions)
                or len({v.key for v in self.inventory_versions}) != len(self.inventory_versions)
                or type(self.query_epochs) is not tuple
                or any(type(v) is not NamespaceEpoch for v in self.query_epochs)):
            raise ValueError("ordinary history requires its actual complete versions and counts")


@dataclass(frozen=True, slots=True)
class OrdinaryContinuityAssessmentV1:
    policy_original: ProductionOriginalRefV1
    anchor: OrdinaryContinuityAnchorV1
    history: OrdinaryHistoryCoverageV1
    base_head: OrdinaryHeadCommitmentV3
    candidate_proposal_original: ProductionOriginalRefV1
    candidate_blocks: tuple[OrdinaryBlockCommitmentV3, ...]
    candidate_ordinary_change_count: int
    phase: str
    question_key: str
    cognition_originals: tuple[ProductionOriginalRefV1, ...]
    support_source_refs: tuple[str, ...]
    context_source_refs: tuple[str, ...]
    counter_query_original: ProductionOriginalRefV1
    counter_versions: tuple[GraphVersion, ...]
    trial_originals: tuple[ProductionOriginalRefV1, ...]
    decision: str
    reason: str
    valid_until_utc: float
    schema: str = "d01.ordinary-continuity-assessment.v1"

    def __post_init__(self):
        _original(self.policy_original); _original(self.candidate_proposal_original); _original(self.counter_query_original)
        if type(self.anchor) is not OrdinaryContinuityAnchorV1 or type(self.history) is not OrdinaryHistoryCoverageV1:
            raise TypeError("ordinary assessment requires its exact anchor and full coverage")
        _head(self.base_head); _blocks(self.candidate_blocks); _originals(self.cognition_originals); _originals(self.trial_originals)
        if (type(self.candidate_ordinary_change_count) is not int or self.candidate_ordinary_change_count < 0
                or self.schema != "d01.ordinary-continuity-assessment.v1"
                or self.phase not in {"ordinary_screen", "deep_review"}
                or not self.question_key.startswith(SCREEN_PREFIX if self.phase == "ordinary_screen" else DEEP_PREFIX)
                or type(self.counter_versions) is not tuple or any(type(v) is not GraphVersion for v in self.counter_versions)):
            raise ValueError("ordinary assessment changed its closed phase or complete candidate")
        choices = {("ordinary_allowed", "preserved"), ("deep_required", "count_threshold"),
            ("deep_required", "core_shift"), ("rejected", "opposition"), ("unknown", "incomplete")} if self.phase == "ordinary_screen" else {
            ("deep_accepted", "preserved"), ("rejected", "opposition"), ("unknown", "incomplete")}
        if (self.decision, self.reason) not in choices:
            raise ValueError("ordinary continuity decision has another phase meaning")
        if self.decision not in {"unknown"} and self.reason != "count_threshold" and not self.cognition_originals:
            raise ValueError("semantic continuity decisions require actual cognition originals")
        for refs in (self.support_source_refs, self.context_source_refs):
            if type(refs) is not tuple or len(set(refs)) != len(refs):
                raise ValueError("ordinary continuity source membership repeats")
            for value in refs: _text(value)
        _time(self.valid_until_utc)



@dataclass(frozen=True, slots=True)
class OrdinaryDeepGrowthPreparationV1:
    """Pre-CAS data only; it contains no future receipt and cannot establish an anchor."""
    policy_original: ProductionOriginalRefV1
    prior_anchor: OrdinaryContinuityAnchorV1
    history: OrdinaryHistoryCoverageV1
    proposal_original: ProductionOriginalRefV1
    assessment_original: ProductionOriginalRefV1
    base_head: OrdinaryHeadCommitmentV3
    successor_head: OrdinaryHeadCommitmentV3
    changed_block_ids: tuple[str, ...]
    support_source_refs: tuple[str, ...]
    trial_originals: tuple[ProductionOriginalRefV1, ...]
    counter_query_original: ProductionOriginalRefV1
    activation_operation_id: str

    def __post_init__(self):
        for value in (self.policy_original, self.proposal_original, self.assessment_original, self.counter_query_original): _original(value)
        _head(self.base_head); _head(self.successor_head); _originals(self.trial_originals)
        changed = changed_ordinary_blocks_v1(self.base_head.blocks, self.successor_head.blocks)
        if (len(changed) != 1 or self.changed_block_ids != changed
                or self.successor_head.version != self.base_head.version + 1
                or self.successor_head.namespace != self.base_head.namespace
                or self.successor_head.plan_id != self.base_head.plan_id):
            raise ValueError("deep preparation must retain its exact one-target mechanical transition")
        _text(self.activation_operation_id)


@dataclass(frozen=True, slots=True)
class OrdinaryDeepGrowthAdoptionV1:
    policy_original: ProductionOriginalRefV1
    prior_anchor: OrdinaryContinuityAnchorV1
    history: OrdinaryHistoryCoverageV1
    proposal_original: ProductionOriginalRefV1
    assessment_original: ProductionOriginalRefV1
    base_head: OrdinaryHeadCommitmentV3
    successor_head: OrdinaryHeadCommitmentV3
    changed_block_ids: tuple[str, ...]
    support_source_refs: tuple[str, ...]
    trial_originals: tuple[ProductionOriginalRefV1, ...]
    counter_query_original: ProductionOriginalRefV1
    activation_operation_id: str
    activation_receipt: CommitReceipt
    activation_event_digest: str
    schema: str = "d01.ordinary-deep-growth-adoption.v1"

    def __post_init__(self):
        for value in (self.policy_original, self.proposal_original, self.assessment_original, self.counter_query_original): _original(value)
        if type(self.prior_anchor) is not OrdinaryContinuityAnchorV1 or type(self.history) is not OrdinaryHistoryCoverageV1:
            raise TypeError("deep adoption requires its actual preceding anchor and history")
        _head(self.base_head); _head(self.successor_head); _originals(self.trial_originals)
        changed = changed_ordinary_blocks_v1(self.base_head.blocks, self.successor_head.blocks)
        if (self.schema != "d01.ordinary-deep-growth-adoption.v1" or len(changed) != 1 or self.changed_block_ids != changed
                or self.successor_head.namespace != self.base_head.namespace
                or self.successor_head.version != self.base_head.version + 1
                or self.successor_head.plan_id != self.base_head.plan_id
                or type(self.activation_receipt) is not CommitReceipt
                or self.activation_receipt.status != "committed"
                or self.activation_receipt.operation_id != self.activation_operation_id):
            raise ValueError("deep adoption must reconstruct its one actual committed ordinary transition")
        refs = set(self.activation_receipt.write_versions)
        if self.successor_head.plan_ref not in refs or self.successor_head.activation_ref not in refs:
            raise ValueError("deep adoption receipt lacks its actual successor control heads")
        _digest(self.activation_event_digest)


def changed_ordinary_blocks_v1(before, after):
    """Count changes without interpreting text or granting any growth authority."""
    _blocks(before); _blocks(after)
    if tuple(v.block_id for v in before) != tuple(v.block_id for v in after):
        raise ValueError("ordinary continuity cannot skip added, removed or reordered blocks")
    changed = []
    for old, new in zip(before, after, strict=True):
        if (old.kind, old.plasticity, old.claim_protocol) != (new.kind, new.plasticity, new.claim_protocol):
            raise ValueError("ordinary continuity cannot reinterpret a block classification change")
        if ordinary_block_v1(old) and old.claim_digest != new.claim_digest:
            changed.append(old.block_id)
    return tuple(changed)


def ordinary_history_metrics_v1(anchor, current, transitions):
    """Fold actual metadata rows (before,after,kind,original,receipt,event digests)."""
    _head(anchor); _head(current)
    previous, count, chain = anchor, 0, []
    for before, after, kind, original_digest, receipt_digest, event_digest in transitions:
        _head(before); _head(after); _text(kind)
        for value in (original_digest, receipt_digest, event_digest): _digest(value)
        if (before != previous or after.namespace != before.namespace or after.plan_id != before.plan_id
                or after.version != before.version + 1 or after.values_digest != before.values_digest
                or after.plan_ref != GraphVersion(before.plan_ref.key, before.plan_ref.revision + 1)
                or after.activation_ref != GraphVersion(before.activation_ref.key, before.activation_ref.revision + 1)):
            raise ValueError("ordinary cumulative history is not a gap-free actual head chain")
        count += bool(changed_ordinary_blocks_v1(before.blocks, after.blocks))
        chain.append((before.head_id, after.head_id, kind, original_digest, receipt_digest, event_digest,
            before.blocks, after.blocks))
        previous = after
    if previous != current:
        raise ValueError("ordinary cumulative history does not reach the protected current head")
    return len(chain), count, canonical_digest(tuple(chain))


def evaluate_ordinary_continuity_v1(policy, assessment, *, transitions):
    """Recompute counts and closed decisions; actual runtime must authenticate inputs."""
    if type(policy) is not OrdinaryCumulativeGrowthPolicyV1 or type(assessment) is not OrdinaryContinuityAssessmentV1:
        raise TypeError("exact ordinary cumulative policy and assessment required")
    total, count, digest = ordinary_history_metrics_v1(assessment.anchor.head, assessment.base_head, transitions)
    h = assessment.history
    candidate_count = count + bool(changed_ordinary_blocks_v1(assessment.base_head.blocks, assessment.candidate_blocks))
    if ((h.anchor_head, h.current_head, h.transition_count, h.ordinary_change_count, h.chain_digest)
            != (assessment.anchor.head.head_id, assessment.base_head.head_id, total, count, digest)
            or candidate_count != assessment.candidate_ordinary_change_count):
        raise ValueError("ordinary assessment counts differ from its actual complete commitments")
    if assessment.phase == "ordinary_screen":
        if candidate_count >= policy.escalate_at_change_count:
            if (assessment.decision, assessment.reason) != ("deep_required", "count_threshold"):
                raise ValueError("ordinary candidate reached its explicit cumulative deep threshold")
        elif assessment.reason == "count_threshold":
            raise ValueError("ordinary cumulative threshold was not reached")
    if assessment.valid_until_utc > policy.valid_until_utc:
        raise ValueError("ordinary assessment cannot extend its original installed policy deadline")
    return assessment.decision


BASIS_KIND = "ordinary_continuity_basis_v1"


@dataclass(frozen=True, slots=True)
class OrdinaryCounterScopeBindingV1:
    query_type: str
    question_key: str
    query_epoch: NamespaceEpoch
    coverage_complete: bool
    members: tuple[tuple[GraphVersion, str, bool, str, str, tuple[str, ...]], ...]
    counter_query_original: ProductionOriginalRefV1
    qualification: str

    def __post_init__(self):
        if (self.query_type != "d07.current_interpretation.v1" or type(self.query_epoch) is not NamespaceEpoch
                or type(self.coverage_complete) is not bool or type(self.members) is not tuple
                or self.qualification not in {"qualified", "opposition", "unknown"}):
            raise ValueError("ordinary counter scope requires its actual complete query domain")
        _text(self.question_key); _original(self.counter_query_original)
        keys = []
        for version, digest, current, stance, evidence_status, unknowns in self.members:
            if (type(version) is not GraphVersion or version.key.type_name != self.query_type
                    or version.revision < 1 or type(current) is not bool or type(unknowns) is not tuple
                    or any(type(value) is not str for value in unknowns)):
                raise ValueError("ordinary counter member changed its exact current metadata types")
            _digest(digest); _text(stance); _text(evidence_status); keys.append(version.key.token)
        if keys != sorted(set(keys)):
            raise ValueError("ordinary counter domain must retain every distinct member in key order")
        if not self.coverage_complete and self.qualification != "unknown":
            raise ValueError("incomplete ordinary counter coverage cannot qualify continuity")


@dataclass(frozen=True, slots=True)
class OrdinaryModelContentLocatorV1:
    role: str
    original_ref: str
    original_digest: str
    field_path: tuple[str | int, ...]
    sha256: str
    byte_count: int

    def __post_init__(self):
        _text(self.role); _text(self.original_ref); _digest(self.original_digest); _digest(self.sha256)
        if (type(self.field_path) is not tuple or any(type(v) not in {str, int} for v in self.field_path)
                or any(type(v) is int and v < 0 for v in self.field_path)
                or type(self.byte_count) is not int or self.byte_count < 0):
            raise ValueError("ordinary model content requires an exact canonical field locator")


@dataclass(frozen=True, slots=True)
class OrdinaryContinuityBasisOriginalV1:
    namespace: NamespaceId
    policy_original: ProductionOriginalRefV1
    anchor: OrdinaryContinuityAnchorV1
    history: OrdinaryHistoryCoverageV1
    base_head: OrdinaryHeadCommitmentV3
    candidate_proposal_original: ProductionOriginalRefV1
    candidate_blocks: tuple[OrdinaryBlockCommitmentV3, ...]
    candidate_write_digest: str
    candidate_ordinary_change_count: int
    source_versions: tuple[GraphVersion, ...]
    support_source_refs: tuple[str, ...]
    context_source_refs: tuple[str, ...]
    context_original_refs: tuple[ProductionOriginalRefV1, ...]
    counter_scope: OrdinaryCounterScopeBindingV1
    trial_originals: tuple[ProductionOriginalRefV1, ...]
    prior_cognition_originals: tuple[ProductionOriginalRefV1, ...]
    causal_original: ProductionOriginalRefV1
    causal_operation_id: str
    causal_receipt_digest: str
    original_parent_budget_lease_ref: str
    original_parent_grant_digest: str
    original_deadline_utc: float
    model_content_manifest: tuple[OrdinaryModelContentLocatorV1, ...]
    model_content_manifest_digest: str
    schema: str = "d01.ordinary-continuity-basis.v1"

    def __post_init__(self):
        if (self.schema != "d01.ordinary-continuity-basis.v1" or type(self.namespace) is not NamespaceId
                or type(self.anchor) is not OrdinaryContinuityAnchorV1
                or type(self.history) is not OrdinaryHistoryCoverageV1
                or type(self.counter_scope) is not OrdinaryCounterScopeBindingV1):
            raise TypeError("ordinary continuity basis requires its exact actual mechanical commitments")
        _head(self.base_head); _blocks(self.candidate_blocks)
        if self.anchor.head.namespace != self.namespace or self.base_head.namespace != self.namespace:
            raise ValueError("ordinary continuity basis crosses its actual namespace")
        for value in (self.policy_original, self.candidate_proposal_original, self.causal_original): _original(value)
        for values in (self.context_original_refs, self.trial_originals, self.prior_cognition_originals): _originals(values)
        for value in (self.candidate_write_digest, self.causal_receipt_digest, self.original_parent_grant_digest,
                      self.model_content_manifest_digest): _digest(value)
        for value in (self.causal_operation_id, self.original_parent_budget_lease_ref): _text(value)
        if (type(self.candidate_ordinary_change_count) is not int or self.candidate_ordinary_change_count < 0
                or type(self.source_versions) is not tuple
                or len({v.key for v in self.source_versions}) != len(self.source_versions)
                or any(type(v) is not GraphVersion or v.key.type_name not in {
                    "memory.source", "memory.access", "d06.source_correction_head.v1"}
                    or NamespaceId.from_key(v.key) != self.namespace for v in self.source_versions)
                or type(self.model_content_manifest) is not tuple or not self.model_content_manifest
                or any(type(v) is not OrdinaryModelContentLocatorV1 for v in self.model_content_manifest)
                or canonical_digest(self.model_content_manifest) != self.model_content_manifest_digest):
            raise ValueError("ordinary basis Source versions or complete model manifest differ")
        _time(self.original_deadline_utc)


def _ordinary_continuity_question_key_fields_v1(basis_original, basis_content_digest, phase, trigger_assessment_original):
    """Shared pure hash recipe; a caller must independently authenticate metadata."""
    _original(basis_original); _digest(basis_content_digest)
    if basis_original.kind != "d01." + BASIS_KIND or basis_original.original_digest != basis_content_digest:
        raise ValueError("ordinary question metadata differs from its immutable basis locator")
    if phase not in {"ordinary_screen", "deep_review"}:
        raise ValueError("ordinary question has another closed phase")
    if phase == "ordinary_screen":
        if trigger_assessment_original is not None:
            raise ValueError("ordinary screen cannot borrow a deep trigger assessment")
    else:
        _original(trigger_assessment_original)
        if trigger_assessment_original.kind != "d01." + ASSESSMENT_KIND:
            raise ValueError("ordinary deep review requires its real committed deep-required assessment")
    def locator(original):
        return None if original is None else {"kind": original.kind, "original_ref": original.original_ref,
            "original_digest": original.original_digest}
    return (SCREEN_PREFIX if phase == "ordinary_screen" else DEEP_PREFIX) + canonical_digest({
        "basis_original": locator(basis_original), "basis_content_digest": basis_content_digest,
        "phase": phase, "trigger_assessment_original": locator(trigger_assessment_original)})


def ordinary_continuity_question_key_v1(basis_original, basis, phase, trigger_assessment_original):
    """One shared key from the actual committed typed basis."""
    if type(basis) is not OrdinaryContinuityBasisOriginalV1:
        raise TypeError("exact ordinary continuity basis required")
    return _ordinary_continuity_question_key_fields_v1(basis_original, ordinary_cumulative_payload_digest_v1(basis), phase, trigger_assessment_original)


def ordinary_basis_semantics_v1(basis):
    """Exclude observation epochs only; this result is data, never freshness proof."""
    if type(basis) is not OrdinaryContinuityBasisOriginalV1:
        raise TypeError("exact ordinary continuity basis required")
    from .production_operations_v1 import plain_v1
    value = plain_v1(basis)
    value["history"].pop("query_epochs")
    value["counter_scope"].pop("query_epoch")
    return value


@dataclass(frozen=True, slots=True)
class OrdinaryDeepGrowthAnchorV1:
    namespace: NamespaceId
    operation_id: str
    basis_original: ProductionOriginalRefV1
    assessment_original: ProductionOriginalRefV1
    policy_original: ProductionOriginalRefV1
    base_head: str
    successor_head: str
    source_refs: tuple[str, ...]
    schema: str = ANCHOR_TYPE

    def __post_init__(self):
        if type(self.namespace) is not NamespaceId or self.schema != ANCHOR_TYPE:
            raise TypeError("ordinary deep marker requires its exact namespace and schema")
        for value in (self.operation_id, self.base_head, self.successor_head): _text(value)
        for value, kind in ((self.basis_original, BASIS_KIND), (self.assessment_original, ASSESSMENT_KIND), (self.policy_original, POLICY_KIND)):
            _original(value)
            if value.kind != "d01." + kind: raise ValueError("ordinary deep marker changed its actual original family")
        if self.base_head == self.successor_head or type(self.source_refs) is not tuple or len(set(self.source_refs)) != len(self.source_refs):
            raise ValueError("ordinary deep marker requires its actual successor and complete unique Sources")


def ordinary_cumulative_type_specs_v1():
    from dataclasses import fields
    from ...graph_types import TypeSpec
    from ...runtime_contracts import schema_hash
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    def validate(value):
        decode_typed_production_value_v1(value, OrdinaryDeepGrowthAnchorV1)
    return (TypeSpec(ANCHOR_TYPE, ("persona",), "state", validate, writer_domain="d01",
        schema_hash=schema_hash({"type": ANCHOR_TYPE, "schema_version": 1,
            "fields": [field.name for field in fields(OrdinaryDeepGrowthAnchorV1)]})),)


ORDINARY_CUMULATIVE_ORIGINAL_TYPES_V1 = {POLICY_KIND: OrdinaryCumulativeGrowthPolicyV1,
    BASIS_KIND: OrdinaryContinuityBasisOriginalV1, ASSESSMENT_KIND: OrdinaryContinuityAssessmentV1,
    DEEP_ADOPTION_KIND: OrdinaryDeepGrowthAdoptionV1}



def ordinary_cumulative_payload_digest_v1(value):
    """The one digest of the actual existing D01 signed plain payload bytes."""
    if type(value) not in {OrdinaryCumulativeGrowthPolicyV1, OrdinaryContinuityBasisOriginalV1,
            OrdinaryContinuityAssessmentV1, OrdinaryDeepGrowthAdoptionV1}:
        raise TypeError("exact registered ordinary cumulative signed payload required")
    from .production_operations_v1 import plain_v1
    return canonical_digest(plain_v1(value))
