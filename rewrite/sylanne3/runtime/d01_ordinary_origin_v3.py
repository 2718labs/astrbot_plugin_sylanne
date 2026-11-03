"""Pure commitments for the existing D01 initial/ordinary-growth lineage.

Inputs are projections measured from actual canonical originals to EOF by the
consumer's registered Work. This module performs no IO, signature verification,
Owner/Source authorization, issuance or claim disclosure. Its DTOs are freely
constructible data; none is a capability. Full-original canonical commitments,
signed bytes, producer signatures, receipts, fences and current rights remain
the actual Work's obligations.

All *_digest fields below are bare SHA256 of the actual canonical JSON value
(or canonical JSON string for claim_digest), measured by that Work. They are
not canonical_digest(dataclass), hashes of reduced projections, or Source grants.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from ..contracts import Event, Scope
from ..graph_types import AtomKey, GraphVersion, NamespaceEpoch, Owner, owner_grant_key
from ..memory_types import access_key, source_key
from ..runtime_contracts import CommitReceipt, NamespaceId
from ..domains.d01 import PersonaActivation
from ..domains.d06 import source_correction_head_key


class OrdinaryOriginUnavailableV3(ValueError):
    """The supplied actual-original structure cannot support this lineage."""


def _need(condition, reason):
    if not condition:
        raise OrdinaryOriginUnavailableV3(reason)


def _versions(values):
    _need(type(values) is tuple and all(type(v) is GraphVersion for v in values),
          "exact original version tuple required")
    result = {v.key: v.revision for v in values}
    _need(len(result) == len(values), "original read/write versions repeat a key")
    return result


@dataclass(frozen=True, slots=True)
class OrdinaryBlockCommitmentV3:
    block_id: str
    kind: str
    plasticity: str
    claim_digest: str
    # Actual EOF classification of registered embedded claims. None means
    # ordinary; semantic/conditioned/method protocols must never be set to None.
    claim_protocol: str | None


@dataclass(frozen=True, slots=True)
class OrdinaryHeadCommitmentV3:
    namespace: NamespaceId
    plan_id: str
    version: int
    authored: bool
    plan_ref: GraphVersion
    plan_value_digest: str
    activation_ref: GraphVersion
    activation_value_digest: str
    activation: PersonaActivation
    blocks: tuple[OrdinaryBlockCommitmentV3, ...]
    values_digest: str

    @property
    def head_id(self):
        return self.plan_id + "@" + str(self.version)


@dataclass(frozen=True, slots=True)
class OrdinaryHistoryMemberV3:
    ref: GraphVersion
    value_digest: str
    valid: bool
    event_scope: Scope
    event_id: str


@dataclass(frozen=True, slots=True)
class OrdinaryEventCommitmentV3:
    event: Event
    recorded_digest: str
    reads: tuple[GraphVersion, ...]
    epoch_reads: tuple[NamespaceEpoch, ...]
    revisions: tuple[GraphVersion, ...]
    invalidated: tuple[AtomKey, ...]
    epoch_revision: int


@dataclass(frozen=True, slots=True)
class OrdinaryInitialCommitmentV3:
    head: OrdinaryHeadCommitmentV3
    # Exact decoded RoleInitializationReceiptV1 scalar fields, not a new receipt.
    receipt: dict
    receipt_digest: str
    owner_grant_ref: GraphVersion
    owner_authorization_head: str
    resources_ref: GraphVersion
    resources_value_digest: str
    resources_namespace: NamespaceId
    resources_operation_id: str
    resources_plan_id: str
    resources_head_id: str
    event: OrdinaryEventCommitmentV3
    members: tuple[OrdinaryHistoryMemberV3, ...]


@dataclass(frozen=True, slots=True)
class OrdinaryRevisionCommitmentV3:
    ref: GraphVersion
    value_digest: str
    revision_id: str
    previous_head: str
    new_head: str
    blocks: tuple[OrdinaryBlockCommitmentV3, ...]
    retained_blocks: tuple[str, ...]
    changed_block: str
    source_families: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OrdinaryWriteCommitmentV3:
    key: AtomKey
    value_digest: str
    dependencies: tuple[AtomKey, ...]


@dataclass(frozen=True, slots=True)
class OrdinaryGrowthProposalCommitmentV3:
    original_ref: str
    kind: str
    producing_operation_id: str
    payload_digest: str
    signature_digest: str
    source_refs_json: tuple[str, ...]
    proposal_id: str
    base_head: str
    target_block: str
    replacement_claim_digest: str
    change_kind: str
    evidence_source_refs: tuple[str, ...]
    trigger_original_ref: str
    required_trial_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OrdinaryGrowthRequestCommitmentV3:
    growth_proposal_ref: str
    trigger_original_ref: str
    trial_original_refs: tuple[str, ...]
    counterevidence_query_ref: str
    general_growth_intent_ref: str | None = None


@dataclass(frozen=True, slots=True)
class OrdinaryOriginalReferenceV3:
    kind: str
    original_ref: str
    original_digest: str


@dataclass(frozen=True, slots=True)
class OrdinaryTrialCommitmentV3:
    original: OrdinaryOriginalReferenceV3
    growth_proposal_ref: str
    evidence_source_refs: tuple[str, ...]
    settled_outcome_refs: tuple[str, ...]
    completed: bool
    trial_start_ref: str | None


@dataclass(frozen=True, slots=True)
class OrdinaryCounterCommitmentV3:
    original: OrdinaryOriginalReferenceV3
    growth_proposal_ref: str
    evidence_source_refs: tuple[str, ...]
    counterevidence_source_refs: tuple[str, ...]
    query_scope_ref: str
    coverage_complete: bool


@dataclass(frozen=True, slots=True)
class OrdinaryGeneralStartCommitmentV3:
    original: OrdinaryOriginalReferenceV3
    proposal_ref: str
    proposal_digest: str
    base_persona_head: str
    base_persona_version: GraphVersion
    target_block: str
    completed_trial_ref: str


@dataclass(frozen=True, slots=True)
class OrdinaryGeneralIntentCommitmentV3:
    original: OrdinaryOriginalReferenceV3
    schema: str
    provenance_intent_digest: str
    proposal_ref: str
    proposal_digest: str
    required_trial_refs: tuple[str, ...]
    trial_start_refs: tuple[str, ...]
    support_source_refs: tuple[str, ...]
    context_source_refs: tuple[str, ...]
    starts: tuple[OrdinaryGeneralStartCommitmentV3, ...]
    outer_start_originals: tuple[OrdinaryOriginalReferenceV3, ...]
    outer_trial_originals: tuple[OrdinaryOriginalReferenceV3, ...]


@dataclass(frozen=True, slots=True)
class OrdinaryGrowthValueCommitmentV3:
    # Projection of the actual typed GrowthProposal stored in each contribution.
    value_digest: str
    proposal_id: str
    base_head: str
    target_block: str
    replacement_claim_digest: str
    source_families: tuple[str, ...]
    counterevidence_checked: bool
    change_kind: str
    evidence_reality: str


@dataclass(frozen=True, slots=True)
class OrdinarySingleEventCommitmentV1:
    policy: object
    policy_original: OrdinaryOriginalReferenceV3
    policy_producer: str
    input: object
    input_original: OrdinaryOriginalReferenceV3
    adoption: object
    review: object
    adoption_version: GraphVersion
    review_version: GraphVersion
    candidate_writes: tuple[OrdinaryWriteCommitmentV3, ...]


@dataclass(frozen=True, slots=True)
class OrdinaryAdoptionCommitmentV3:
    namespace: NamespaceId
    domain: str
    operation_kind: str
    payload_schema: str
    operation_id: str
    activity_id: str
    effect_id: str | None
    now_utc: float
    original_digest: str
    bundle_digest: str
    coverage: str
    missing_inputs: tuple[str, ...]
    continuation_ref: str | None
    request: OrdinaryGrowthRequestCommitmentV3
    proposal: OrdinaryGrowthProposalCommitmentV3
    trials: tuple[OrdinaryTrialCommitmentV3, ...]
    counter: OrdinaryCounterCommitmentV3
    general: OrdinaryGeneralIntentCommitmentV3 | None
    observed_originals: tuple[OrdinaryOriginalReferenceV3, ...]
    # Top-level provenance.originals for adopt_growth, or the exact nested
    # provenance.growth.originals for adopt_general_growth_v1.
    provenance_originals: tuple[OrdinaryOriginalReferenceV3, ...]
    candidate_path: str
    growth: OrdinaryGrowthValueCommitmentV3
    successor: OrdinaryHeadCommitmentV3
    revision: OrdinaryRevisionCommitmentV3
    # Actual canonical commitments measured independently at these payload paths:
    # provenance.candidate.revision and provenance.candidate.typed_writes.
    candidate_revision_digest: str
    candidate_writes_digest: str
    payload_writes_digest: str
    candidate_head_id: str
    candidate_read_versions: tuple[GraphVersion, ...]
    payload_read_versions: tuple[GraphVersion, ...]
    row_read_versions: tuple[GraphVersion, ...]
    writes: tuple[OrdinaryWriteCommitmentV3, ...]
    members: tuple[OrdinaryHistoryMemberV3, ...]
    receipt: CommitReceipt
    # Actual graph_bundle_operations fixed header, in its real column order.
    bundle_header: tuple[str, str, str | None, int]
    event: OrdinaryEventCommitmentV3
    single_event: OrdinarySingleEventCommitmentV1 | None = None


@dataclass(frozen=True, slots=True)
class OrdinarySourceSelectionV3:
    source: GraphVersion
    access: GraphVersion
    correction: GraphVersion


@dataclass(frozen=True, slots=True)
class OrdinaryBlockOriginV3:
    namespace: NamespaceId
    active_head: str
    active_plan_ref: GraphVersion
    active_activation_ref: GraphVersion
    block: OrdinaryBlockCommitmentV3
    origin_kind: str
    initial_head: str
    initial_receipt_digest: str
    changed_head: str
    change_revision: GraphVersion | None
    producing_operation_id: str
    adopted_original_digest: str | None
    proposal_ref: str | None
    proposal_digest: str | None
    trial_refs: tuple[str, ...]
    counter_ref: str | None
    support: tuple[OrdinarySourceSelectionV3, ...]
    related_originals: tuple[OrdinaryOriginalReferenceV3, ...]


_INITIAL_RECEIPT_FIELDS = frozenset((
    "namespace", "operation_id", "request_digest", "input_digest", "plan_id",
    "head_id", "owner_grant_id", "owner_grant_revision",
    "owner_authorization_head", "graph_incarnation", "graph_revision",
    "graph_epoch", "fence_attempt_id", "finish_request_id",
    "finish_request_digest",
))


def _head(head):
    _need(type(head) is OrdinaryHeadCommitmentV3
          and type(head.namespace) is NamespaceId
          and type(head.activation) is PersonaActivation
          and type(head.version) is int and head.version > 0
          and type(head.authored) is bool,
          "exact actual head metadata required")
    ns, activation = head.namespace, head.activation
    owner = Owner("persona", *ns.as_tuple)
    _need(head.plan_ref.key == AtomKey(owner, "d01.persona_plan.v1", head.plan_id)
          and head.activation_ref.key == AtomKey(owner, "d01.persona_activation.v1", "current")
          and head.plan_ref.revision > 0 and head.activation_ref.revision > 0
          and (activation.namespace, activation.plan_id, activation.plan_version,
               activation.head_id) == (ns, head.plan_id, head.version, head.head_id),
          "actual activation and plan metadata differ")
    _need(type(head.blocks) is tuple and head.blocks
          and all(type(b) is OrdinaryBlockCommitmentV3 for b in head.blocks),
          "actual complete block commitments required")
    blocks = {b.block_id: b for b in head.blocks}
    _need(len(blocks) == len(head.blocks), "block commitment identity repeats")
    return blocks


def _ordinary(block):
    return block.kind != "semantic_identity" and block.claim_protocol is None


def _same_owner(first, second):
    a, b = first.activation, second.activation
    _need((a.namespace, a.owner_grant_id, a.owner_grant_revision,
           a.graph_incarnation, a.activation_generation,
           a.authorization_revision, a.state)
          == (b.namespace, b.owner_grant_id, b.owner_grant_revision,
              b.graph_incarnation, b.activation_generation,
              b.authorization_revision, b.state),
          "lineage crosses the actual activation Owner root")


def _member_map(members, *, event, refs):
    _need(type(members) is tuple
          and all(type(m) is OrdinaryHistoryMemberV3 for m in members),
          "exact actual history members required")
    result = {m.ref.key: m for m in members}
    expected = _versions(refs)
    _need(len(result) == len(members) and set(result) == set(expected),
          "actual event history member set differs")
    for key, member in result.items():
        _need(member.valid is True and member.ref.revision == expected[key]
              and member.event_scope == event.scope
              and member.event_id == event.event_id,
              "history version or actual producer event differs")
    return result


def validate_ordinary_initial_v3(initial):
    """Check the actual dedicated initialization structure; confer no rights."""
    _need(type(initial) is OrdinaryInitialCommitmentV3,
          "exact initial original metadata required")
    head = initial.head
    _head(head)
    receipt = initial.receipt
    _need(type(receipt) is dict and set(receipt) == _INITIAL_RECEIPT_FIELDS,
          "actual initialization receipt fields differ")
    ns, activation = head.namespace, head.activation
    _need(receipt["namespace"] == {"bot_id": ns.bot_id, "persona_id": ns.persona_id}
          and (receipt["plan_id"], receipt["head_id"]) == (head.plan_id, head.head_id)
          and (receipt["owner_grant_id"], receipt["owner_grant_revision"],
               receipt["graph_incarnation"], receipt["owner_authorization_head"])
          == (activation.owner_grant_id, initial.owner_grant_ref.revision,
              activation.graph_incarnation, initial.owner_authorization_head)
          and activation.owner_grant_revision == initial.owner_grant_ref.revision
          and initial.owner_grant_ref.key == owner_grant_key(*ns.as_tuple)
          and head.version == 1 and head.authored is True
          and head.plan_ref.revision == head.activation_ref.revision == initial.resources_ref.revision == 1,
          "actual authored initialization root differs")
    resources_key = AtomKey(Owner("persona", *ns.as_tuple),
                           "runtime.role_resources.v1", head.plan_id)
    _need(initial.resources_ref.key == resources_key
          and (initial.resources_namespace, initial.resources_operation_id,
               initial.resources_plan_id, initial.resources_head_id)
          == (ns, receipt["operation_id"], head.plan_id, head.head_id)
          and receipt["finish_request_id"] == "finish:" + receipt["fence_attempt_id"],
          "actual role-resource root or finish identity differs")
    event = Event(Scope(*ns.as_tuple, "d01-role-initialization"),
                  receipt["operation_id"], 0, "role_initialized",
                  {"input_digest": receipt["input_digest"],
                   "owner_grant_id": receipt["owner_grant_id"],
                   "authorization_head": receipt["owner_authorization_head"]})
    actual = initial.event
    refs = (head.plan_ref, head.activation_ref, initial.resources_ref)
    expected_reads = (initial.owner_grant_ref,
                      *(GraphVersion(ref.key, 0) for ref in refs))
    _need(actual.event == event and actual.recorded_digest == event.digest
          and actual.reads == expected_reads
          and actual.revisions == refs and not actual.invalidated
          and actual.epoch_revision == receipt["graph_epoch"]
          and len(actual.epoch_reads) == 1
          and (actual.epoch_reads[0].bot, actual.epoch_reads[0].persona,
               actual.epoch_reads[0].revision + 1)
          == (*ns.as_tuple, receipt["graph_epoch"]),
          "actual initialization event or read/CAS versions differ")
    members = _member_map(initial.members, event=event, refs=refs)
    _need(members[head.plan_ref.key].value_digest == head.plan_value_digest
          and members[head.activation_ref.key].value_digest == head.activation_value_digest
          and members[initial.resources_ref.key].value_digest == initial.resources_value_digest,
          "initial actual member commitments differ")
    return head


def validate_ordinary_adoption_v3(previous, adoption):
    """Validate one real ordinary adopt_growth transition, returning selectors.

    The Work must already have measured the original/candidate/write commitments
    and verified the D11 proposal signature and its producing committed original.
    No root may be supplied independently of adoption.proposal.
    """
    before = _head(previous)
    _need(type(adoption) is OrdinaryAdoptionCommitmentV3,
          "exact adopted original metadata required")
    after = adoption.successor
    following = _head(after)
    _same_owner(previous, after)
    ns = previous.namespace
    variants = {
        "adopt_growth": ("d01.current-adopt_growth.v1", "provenance.candidate"),
        "adopt_single_event_growth_v1": ("d01.current-adopt_single_event_growth_v1.v1", "provenance.growth.candidate"),
        "adopt_general_growth_v1": (
            "d01.current-adopt_general_growth_v1.v1", "provenance.growth.candidate"),
    }
    expected = variants.get(adoption.operation_kind)
    _need(expected is not None
          and (adoption.namespace, adoption.domain, adoption.payload_schema,
               adoption.candidate_path, adoption.coverage, adoption.missing_inputs,
               adoption.continuation_ref)
          == (ns, "d01", expected[0], expected[1], "complete", (), None),
          "unsupported or incomplete actual persona transition")
    _need(after.plan_id == previous.plan_id
          and after.version == previous.version + 1
          and after.plan_ref == GraphVersion(previous.plan_ref.key, previous.plan_ref.revision + 1)
          and after.activation_ref == GraphVersion(previous.activation_ref.key, previous.activation_ref.revision + 1)
          and after.authored is False and after.values_digest == previous.values_digest
          and tuple(before) == tuple(following),
          "actual successor head or unchanged plan structure differs")
    revision, proposal, request, growth = (
        adoption.revision, adoption.proposal, adoption.request, adoption.growth)
    _need(type(revision) is OrdinaryRevisionCommitmentV3
          and type(proposal) is OrdinaryGrowthProposalCommitmentV3
          and type(request) is OrdinaryGrowthRequestCommitmentV3
          and type(growth) is OrdinaryGrowthValueCommitmentV3,
          "exact selected revision/proposal/request metadata required")
    target = revision.changed_block
    _need(target in before and _ordinary(before[target]) and _ordinary(following[target])
          and before[target].kind == following[target].kind
          and before[target].plasticity == following[target].plasticity == "growth",
          "ordinary transition cannot replace a dedicated or nonplastic block")
    _need(revision.ref.key == AtomKey(Owner("persona", *ns.as_tuple),
              "d01.persona_revision.v1", revision.revision_id)
          and revision.previous_head == previous.head_id
          and revision.new_head == after.head_id
          and revision.blocks == after.blocks
          and revision.retained_blocks == tuple(b.block_id for b in previous.blocks if b.block_id != target)
          and all(before[key] == following[key] for key in before if key != target),
          "actual revision retained/changed block lineage differs")
    _need(proposal.kind == "growth_proposal"
          and (proposal.proposal_id, proposal.base_head, proposal.target_block,
               proposal.replacement_claim_digest)
          == (revision.revision_id, previous.head_id, target, following[target].claim_digest)
          and proposal.original_ref == request.growth_proposal_ref
          and proposal.trigger_original_ref == request.trigger_original_ref
          and set(proposal.required_trial_refs) == set(request.trial_original_refs)
          and len(set(request.trial_original_refs)) == len(request.trial_original_refs)
          and proposal.source_refs_json == (
              tuple(sorted(proposal.evidence_source_refs))
              if adoption.operation_kind in {"adopt_general_growth_v1", "adopt_single_event_growth_v1"}
              else proposal.evidence_source_refs)
          and proposal.evidence_source_refs
          and len(set(proposal.evidence_source_refs)) == len(proposal.evidence_source_refs),
          "signed ordinary proposal/request/support membership differs")
    _need((growth.proposal_id, growth.base_head, growth.target_block,
           growth.replacement_claim_digest, growth.change_kind,
           growth.evidence_reality, growth.counterevidence_checked,
           growth.source_families)
          == (proposal.proposal_id, proposal.base_head, target,
              proposal.replacement_claim_digest, proposal.change_kind,
              "external", True, revision.source_families)
          and len(growth.source_families) == len(proposal.evidence_source_refs)
          and len(set(growth.source_families)) == len(growth.source_families),
          "actual adopted GrowthProposal contribution differs")
    _validate_original_members_v3(previous, adoption)
    _need(adoption.candidate_head_id == after.head_id
          and adoption.candidate_revision_digest == revision.value_digest
          and (adoption.candidate_writes_digest == adoption.payload_writes_digest
               if adoption.single_event is None else adoption.operation_kind == "adopt_single_event_growth_v1"),
          "actual candidate revision/full write commitments differ")
    receipt = adoption.receipt
    _need(type(receipt) is CommitReceipt
          and (receipt.status, receipt.operation_id, receipt.activity_id,
               receipt.effect_id, receipt.operation_digest)
          == ("committed", adoption.operation_id, adoption.activity_id,
              adoption.effect_id, adoption.bundle_digest)
          and adoption.bundle_header == (receipt.operation_digest, receipt.activity_id,
                                         receipt.effect_id, receipt.commit_seq)
          and adoption.row_read_versions == adoption.payload_read_versions == receipt.read_versions,
          "actual adopted receipt/bundle/readset identity differs")
    reads, candidate_reads = (_versions(adoption.payload_read_versions),
                              _versions(adoption.candidate_read_versions))
    _need(all(reads.get(key) == revision for key, revision in candidate_reads.items())
          and reads.get(previous.plan_ref.key) == previous.plan_ref.revision
          and reads.get(previous.activation_ref.key) == previous.activation_ref.revision
          and reads.get(revision.ref.key) == revision.ref.revision - 1
          and candidate_reads.get(owner_grant_key(*ns.as_tuple)) == previous.activation.owner_grant_revision,
          "actual candidate/predecessor CAS reads differ")
    _need(type(adoption.writes) is tuple
          and all(type(w) is OrdinaryWriteCommitmentV3 for w in adoption.writes),
          "exact actual typed-write commitments required")
    writes = {w.key: w for w in adoption.writes}
    refs = _versions(receipt.write_versions)
    _need(len(writes) == len(adoption.writes) and set(writes) == set(refs),
          "actual receipt and typed member set differ")
    event = Event(Scope(*ns.as_tuple, adoption.activity_id),
                  adoption.operation_id, adoption.now_utc, "domain_bundle",
                  {"bundle_digest": adoption.bundle_digest})
    actual_event = adoption.event
    _need(actual_event.event == event and actual_event.recorded_digest == event.digest
          and actual_event.reads == receipt.read_versions
          and actual_event.revisions == receipt.write_versions
          and len(receipt.invalidated_epochs) == 1
          and actual_event.epoch_revision == receipt.invalidated_epochs[0].revision
          and (receipt.invalidated_epochs[0].bot, receipt.invalidated_epochs[0].persona)
              == ns.as_tuple
          and actual_event.epoch_reads == (
              NamespaceEpoch(*ns.as_tuple, actual_event.epoch_revision - 1),),
          "actual adoption Graph event differs")
    members = _member_map(adoption.members, event=event, refs=receipt.write_versions)
    _need(all(members[key].value_digest == write.value_digest for key, write in writes.items()),
          "actual event member and typed-write commitments differ")
    required = {after.plan_ref.key: (after.plan_ref.revision, after.plan_value_digest),
                after.activation_ref.key: (after.activation_ref.revision, after.activation_value_digest),
                revision.ref.key: (revision.ref.revision, revision.value_digest)}
    _need(all(refs.get(key) == value[0] and key in writes
              and writes[key].value_digest == value[1] for key, value in required.items()),
          "actual plan/activation/revision member binding differs")
    _need(writes[after.activation_ref.key].dependencies == (
              owner_grant_key(*ns.as_tuple), after.plan_ref.key),
          "actual activation write dependencies differ")
    contributions = {
        AtomKey(Owner("persona", *ns.as_tuple), "d01.growth_contribution.v1",
                target + "|" + family + "|" + growth.change_kind)
        for family in growth.source_families}
    extras = _validate_single_event_adoption_v1(previous, adoption, writes, reads, refs)
    _need(set(writes) == set(required) | contributions | extras
          and all(writes[key].value_digest == growth.value_digest
                  and reads.get(key) == 0 and refs[key] == 1
                  for key in contributions),
          "actual unique growth contribution members differ")
    return (
        _source_selections_v3(ns, proposal.evidence_source_refs, candidate_reads),
        _selected_originals_v3(adoption),
    )


def _source_selections_v3(ns, roots, reads):
    support = []
    for ref in roots:
        key = AtomKey.from_token(ref)
        _need(key == source_key(*ns.as_tuple, key.owner.subject or ""),
              "signed proposal Source locator crosses namespace/type")
        access, correction = (access_key(*ns.as_tuple, key.owner.subject),
                              source_correction_head_key(ns, key.owner.subject))
        _need(reads.get(key, 0) > 0
              and reads.get(access, 0) > 0
              and reads.get(correction) == 0,
              "actual candidate lacks original Source/access/correction reads")
        support.append(OrdinarySourceSelectionV3(
            GraphVersion(key, reads[key]),
            GraphVersion(access, reads[access]),
            GraphVersion(correction, 0)))
    return tuple(support)


def _original_map_v3(values):
    result = {}
    for value in values:
        _need(type(value) is OrdinaryOriginalReferenceV3,
              "exact original reference commitment required")
        previous = result.get(value.original_ref)
        _need(previous is None or previous == value,
              "one original reference has conflicting kind/digest")
        result[value.original_ref] = value
    return result


def _validate_original_members_v3(previous, adoption):
    proposal, request = adoption.proposal, adoption.request
    observed = _original_map_v3(adoption.observed_originals)
    originals = _original_map_v3(adoption.provenance_originals)

    def member(value):
        _need(observed.get(value.original_ref) == value
              and originals.get(value.original_ref) == value,
              "signed original is not an exact actual adopted/observed member")

    member(OrdinaryOriginalReferenceV3(
        "d01.growth_proposal", proposal.original_ref, proposal.payload_digest))
    _need(type(adoption.trials) is tuple
          and all(type(t) is OrdinaryTrialCommitmentV3 for t in adoption.trials)
          and tuple(t.original.original_ref for t in adoption.trials)
              == request.trial_original_refs,
          "selected trial originals differ from the exact request order")
    for trial in adoption.trials:
        member(trial.original)
        _need(trial.growth_proposal_ref == proposal.original_ref
              and trial.completed is True and trial.settled_outcome_refs,
              "actual completed trial/proposal membership differs")
    counter = adoption.counter
    _need(type(counter) is OrdinaryCounterCommitmentV3
          and counter.original.kind == "d01.growth_counterevidence"
          and counter.original.original_ref == request.counterevidence_query_ref
          and counter.growth_proposal_ref == proposal.original_ref
          and counter.evidence_source_refs == proposal.evidence_source_refs
          and counter.query_scope_ref == "d07.current_interpretation.v1"
          and counter.coverage_complete is True,
          "actual counter original/proposal/support differs")
    member(counter.original)
    if adoption.operation_kind == "adopt_growth":
        _need(adoption.general is None and request.general_growth_intent_ref is None
              and all(t.original.kind in {"d01.growth_trial", "d01.growth_trial_v2"}
                      for t in adoption.trials),
              "ordinary legacy adopter cannot borrow a General original shape")
        return
    general = adoption.general
    _need(type(general) is OrdinaryGeneralIntentCommitmentV3
          and general.original.kind == "d01.general_growth_intent_v1"
          and general.original.original_ref == request.general_growth_intent_ref
          and general.schema == "d01.general-growth-intent.v1"
          and general.provenance_intent_digest == general.original.original_digest
          and (general.proposal_ref, general.proposal_digest,
               general.required_trial_refs, general.support_source_refs)
          == (proposal.original_ref, proposal.payload_digest,
              request.trial_original_refs, proposal.evidence_source_refs)
          and general.required_trial_refs
          and len(general.trial_start_refs) == len(general.required_trial_refs)
          and len(set(general.trial_start_refs)) == len(general.trial_start_refs)
          and general.context_source_refs,
          "exact installed General request/intent/proposal join differs")
    member(general.original)
    _need(type(general.starts) is tuple
          and all(type(s) is OrdinaryGeneralStartCommitmentV3 for s in general.starts)
          and tuple(s.original.original_ref for s in general.starts) == general.trial_start_refs
          and tuple(s.original for s in general.starts) == general.outer_start_originals
          and tuple(t.original for t in adoption.trials) == general.outer_trial_originals,
          "actual General outer trial/start provenance differs")
    for start, trial in zip(general.starts, adoption.trials, strict=True):
        member(start.original)
        _need(start.original.kind == "d01.general_growth_trial_start_v1"
              and trial.original.kind == "d01.general_growth_trial_v1"
              and (start.proposal_ref, start.proposal_digest,
                   start.base_persona_head, start.base_persona_version,
                   start.target_block, start.completed_trial_ref)
              == (proposal.original_ref, proposal.payload_digest,
                  previous.head_id, previous.plan_ref, proposal.target_block,
                  trial.original.original_ref)
              and trial.trial_start_ref == start.original.original_ref,
              "actual General completed-trial/start/base binding differs")


def _selected_originals_v3(adoption):
    # These are signed/original selectors, not additional prompt Source roots.
    # Counter sources are not inferred from obsolete birth-counter prose: the
    # actual adopter can replace that scope with its current D07 counter scope.
    values = [OrdinaryOriginalReferenceV3(
        "d01.growth_proposal", adoption.proposal.original_ref,
        adoption.proposal.payload_digest)]
    values.extend(trial.original for trial in adoption.trials)
    values.append(adoption.counter.original)
    if adoption.general is not None:
        values.append(adoption.general.original)
        values.extend(start.original for start in adoption.general.starts)
    if adoption.single_event is not None:
        values.extend((adoption.single_event.policy_original, adoption.single_event.input_original))
    return tuple(values)


class OrdinaryOriginLineageV3:
    """Pure one-transition-at-a-time fold; no DB lookup and no issued proof.

    The Work supplies the actual unique chronological chain. A repeated, missing,
    branching, unsupported or foreign transition cannot advance this fold. Call
    finish_v3 against the actual protected current head, never a guessed target.
    """
    def __init__(self, initial):
        self.head = validate_ordinary_initial_v3(initial)
        self.initial_head = self.head.head_id
        self.initial_receipt_digest = initial.receipt_digest
        self.origins = {}
        for block in self.head.blocks:
            if _ordinary(block):
                self.origins[block.block_id] = OrdinaryBlockOriginV3(
                    self.head.namespace, self.head.head_id, self.head.plan_ref,
                    self.head.activation_ref, block, "authored_initial",
                    self.head.head_id, initial.receipt_digest, self.head.head_id,
                    None, initial.receipt["operation_id"], None, None, None,
                    (), None, (), ())

    def advance_v3(self, adoption):
        support, originals = validate_ordinary_adoption_v3(self.head, adoption)
        after, target = adoption.successor, adoption.revision.changed_block
        block = next(b for b in after.blocks if b.block_id == target)
        self.origins[target] = OrdinaryBlockOriginV3(
            after.namespace, after.head_id, after.plan_ref, after.activation_ref,
            block, ("ordinary_single_event_growth_v1" if adoption.single_event is not None else
                    "ordinary_general_growth" if adoption.operation_kind == "adopt_general_growth_v1"
                    else "ordinary_growth"), self.initial_head,
            self.initial_receipt_digest, after.head_id, adoption.revision.ref,
            adoption.operation_id, adoption.original_digest,
            adoption.proposal.original_ref, adoption.proposal.payload_digest,
            adoption.request.trial_original_refs,
            adoption.request.counterevidence_query_ref, support, originals)
        self.head = after

    def finish_v3(self, current, selections):
        """Return metadata selectors only; SourceALL/readout issuance is external."""
        actual = _head(current)
        _need(current == self.head, "lineage does not reach the exact actual current head")
        _need(type(selections) is tuple
              and len({block_id for block_id, _ in selections}) == len(selections),
              "selected actual block commitments repeat")
        result = []
        for block_id, digest in selections:
            _need(block_id in actual and _ordinary(actual[block_id])
                  and actual[block_id].claim_digest == digest
                  and block_id in self.origins,
                  "selected ordinary block has no exact actual origin")
            origin = self.origins[block_id]
            _need(origin.block == actual[block_id],
                  "retained ordinary block differs from its last actual change")
            result.append(replace(origin, active_head=current.head_id,
                                  active_plan_ref=current.plan_ref,
                                  active_activation_ref=current.activation_ref))
        return tuple(result)


def _validate_single_event_adoption_v1(previous, actual, writes, reads, refs):
    if actual.operation_kind != "adopt_single_event_growth_v1":
        _need(actual.single_event is None, "ordinary adopter cannot borrow a single-event exception")
        return set()
    from ..domains.d01.single_event_growth_v1 import (SingleEventGrowthPolicyV1, SingleEventGrowthInputV1,
        SingleEventGrowthAdoptionV1, SingleEventGrowthReviewV1, SingleEventGrowthReviewV2,
        single_event_adoption_key_v1, single_event_review_key_v1, single_event_review_key_v2)
    from ..domains.d01.production_operations_v1 import plain_v1
    selected = actual.single_event
    _need(type(selected) is OrdinarySingleEventCommitmentV1, "actual selected single-event metadata commitment required")
    policy, value, adoption, review = selected.policy, selected.input, selected.adoption, selected.review
    _need(type(policy) is SingleEventGrowthPolicyV1 and type(value) is SingleEventGrowthInputV1
          and type(adoption) is SingleEventGrowthAdoptionV1 and type(review) in (SingleEventGrowthReviewV1,SingleEventGrowthReviewV2),
          "single-event origin has another exact contract")
    terms = policy.terms
    target = next(b for b in previous.blocks if b.block_id == actual.revision.changed_block)
    observed = _original_map_v3(actual.observed_originals)
    originals = _original_map_v3(actual.provenance_originals)
    for original in (selected.policy_original, selected.input_original):
        _need(observed.get(original.original_ref) == original and originals.get(original.original_ref) == original,
              "signed single-event policy/input is not an actual adopted observed member")
    _need((terms.namespace, terms.expected_persona_head, terms.persona_head_id, terms.target_block,
           terms.target_kind, terms.base_claim_digest) == (previous.namespace, previous.plan_ref,
           previous.head_id, target.block_id, target.kind, target.claim_digest)
          and policy.registration_operation_id == selected.policy_producer
          and canonical_digest(plain_v1(policy)) == selected.policy_original.original_digest
          and value.policy_ref == terms.policy_ref and value.policy_digest == selected.policy_original.original_digest
          and value.input_ref == selected.input_original.original_ref
          and canonical_digest(plain_v1(value)) == selected.input_original.original_digest
          and value.registration_operation_id == selected.policy_producer
          and value.replacement_claim_digest == actual.proposal.replacement_claim_digest
          and value.event_provenance_root == terms.event_provenance_root
          and actual.growth.source_families == (terms.event_provenance_root,)
          and actual.proposal.evidence_source_refs == (terms.event_source.key.token,)
          and policy.registered_at_utc <= value.prepared_at_utc <= adoption.adopted_at_utc < terms.adopt_before_utc
          and actual.now_utc <= adoption.adopted_at_utc,
          "single-event actual policy, one event, frozen input or exact base differs")
    ak = single_event_adoption_key_v1(previous.namespace, terms.policy_ref)
    rk = (single_event_review_key_v1(previous.namespace, terms.policy_ref)
          if type(review) is SingleEventGrowthReviewV1 else single_event_review_key_v2(previous.namespace, terms.policy_ref))
    _need(selected.adoption_version == GraphVersion(ak, 1) and selected.review_version == GraphVersion(rk, 1)
          and reads.get(ak) == reads.get(rk) == 0 and refs.get(ak) == refs.get(rk) == 1
          and adoption.adoption_operation_id == actual.operation_id and adoption.previous_head == previous.head_id
          and adoption.adopted_head == actual.successor.head_id and adoption.target_block == target.block_id
          and adoption.adopted_claim_digest == actual.proposal.replacement_claim_digest
          and adoption.policy_digest == selected.policy_original.original_digest
          and adoption.input_digest == selected.input_original.original_digest and adoption.review_ref == rk.token
          and (adoption.review_not_before_utc, adoption.review_due_utc, adoption.readout_valid_until_utc) == (
              terms.review_not_before_utc, terms.review_due_utc, terms.readout_valid_until_utc)
          and (review.adoption_ref, review.adoption_operation_id, review.target_block, review.adopted_claim_digest,
               review.review_not_before_utc, review.review_due_utc, review.readout_valid_until_utc) == (
              ak.token, actual.operation_id, target.block_id, actual.proposal.replacement_claim_digest,
              terms.review_not_before_utc, terms.review_due_utc, terms.readout_valid_until_utc)
          and review.disposition == "pending" and review.reviewed_at_utc is None
          and writes[ak].value_digest == canonical_digest(plain_v1(adoption))
          and writes[rk].value_digest == canonical_digest(plain_v1(review)),
          "single-event actual adoption/review obligation is not the same original W01 event")
    ordinary = tuple(write for write in actual.writes if write.key not in {ak, rk})
    _need(selected.candidate_writes == ordinary,
          "actual single-event growth candidate differs from its ordinary typed writes")
    return {ak, rk}
