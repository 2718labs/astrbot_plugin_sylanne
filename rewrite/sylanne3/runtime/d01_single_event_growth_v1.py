"""Installed D01 single-event registration, independent adoption and finite review.

The exception is a private binding to one existing, fully qualified growth input.
It grants neither Source access nor a shorter trial/continuity/counter pathway.
"""
from dataclasses import dataclass, replace
from weakref import WeakKeyDictionary, ref

from ..domains.d01 import PersonaDomain
from ..domains.d01.identity_v3 import RuntimeIdentityRef, decode_semantic_identity_v3, encode_semantic_identity_v3
from ..domains.d01.production_operations_v1 import (AdoptCurrentGrowthRequestV1, CurrentGrowthInputsV1,
    plain_v1, stage_result_v1, compile_adopt_current_growth_v1, require_locator_v1)
from ..domains.d01.single_event_growth_v1 import (SingleEventGrowthTermsV1, SingleEventGrowthPolicyV1,
    SingleEventGrowthInputV1, SingleEventGrowthAdoptionV1, SingleEventGrowthReviewV1,
    POLICY_KIND, INPUT_KIND, ADOPTION_TYPE, REVIEW_TYPE, REVIEW_EVENT,
    single_event_adoption_key_v1, single_event_review_key_v1, SingleEventScopeCommitmentV1,
    REVIEW_TYPE_V2,SingleEventGrowthReviewV2,single_event_review_key_v2)
from ..graph_types import AtomKey, GraphAtom, GraphVersion, GraphWrite, GraphSnapshot, owner_grant_key
from ..runtime_contracts import canonical_digest, NamespaceId
from .d01_production_operations_v1 import (CurrentDomainReadV1, InstalledD01ProductionReadersV1,
    MissingProductionOriginalV1, waiting_stage_v1)
from .domain_production_erasure_v1 import decode_typed_production_value_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1


@dataclass(frozen=True, slots=True)
class RegisterSingleEventGrowthPolicyRequestV1:
    terms: SingleEventGrowthTermsV1
    def __post_init__(self):
        if type(self.terms) is not SingleEventGrowthTermsV1:
            raise TypeError("single-event policy registration requires its exact explicit terms")


@dataclass(frozen=True, slots=True)
class PrepareSingleEventGrowthRequestV1:
    input_ref: str
    policy_ref: str
    growth_request: AdoptCurrentGrowthRequestV1
    general_growth_intent_ref: str | None
    continuity_interpretation_ref: str
    def __post_init__(self):
        for value in (self.input_ref, self.policy_ref, self.continuity_interpretation_ref):
            require_locator_v1(value, "single-event input locator")
        if type(self.growth_request) is not AdoptCurrentGrowthRequestV1:
            raise TypeError("single-event input retains the exact existing growth/trial/counter request")
        if self.general_growth_intent_ref is not None:
            require_locator_v1(self.general_growth_intent_ref, "General FULL wrapper")


@dataclass(frozen=True, slots=True)
class AdoptSingleEventGrowthRequestV1:
    input_ref: str
    def __post_init__(self):
        require_locator_v1(self.input_ref, "single-event input")


@dataclass(frozen=True, slots=True)
class ReviewSingleEventGrowthRequestV1:
    adoption_ref: str
    expected_review_revision: int
    continuity_interpretation_ref: str | None
    def __post_init__(self):
        require_locator_v1(self.adoption_ref, "single-event adoption")
        if type(self.expected_review_revision) is not int or self.expected_review_revision < 1:
            raise ValueError("single-event review requires its exact current obligation revision")
        if self.continuity_interpretation_ref is not None:
            require_locator_v1(self.continuity_interpretation_ref, "post-adoption continuity")


@dataclass(frozen=True, slots=True)
class ReadSingleEventGrowthRequestV1:
    adoption_ref: str
    def __post_init__(self):
        require_locator_v1(self.adoption_ref, "single-event adoption")


OPERATIONS = {
    "register_single_event_growth_policy_v1": (RegisterSingleEventGrowthPolicyRequestV1, "workbench.activate"),
    "prepare_single_event_growth_v1": (PrepareSingleEventGrowthRequestV1, "workbench.activate"),
    "adopt_single_event_growth_v1": (AdoptSingleEventGrowthRequestV1, "workbench.activate"),
    "review_single_event_growth_v1": (ReviewSingleEventGrowthRequestV1, "workbench.activate"),
    "read_single_event_growth_v1": (ReadSingleEventGrowthRequestV1, "workbench.read"),
}
from ..domains.d01.single_event_review_case_v1 import (CASE_KIND,CASE_EVENT,RegisteredSingleEventReviewCaseV1)
ORIGINAL_TYPES = {POLICY_KIND: SingleEventGrowthPolicyV1, INPUT_KIND: SingleEventGrowthInputV1,
    CASE_KIND:RegisteredSingleEventReviewCaseV1}
_ISSUER = object()
_QUALIFICATIONS = WeakKeyDictionary()


class _SingleEventQualificationV1:
    __slots__ = ("__weakref__",)
    def __init__(self, issuer):
        if issuer is not _ISSUER:
            raise TypeError("single-event exception is issued only by the actual installed D01 reader")


def _actual(db, frame, readers, request):
    if type(readers) is not InstalledD01ProductionReadersV1 or frame.envelope.authority.purpose != "consolidation":
        raise TypeError("single-event growth requires the actual D01 consolidation reader")
    from .current_method_learning_read_v3 import _method_active, require_actual_method_learning_attachment_owner_v3
    owner = _method_active(db)
    if owner is None:
        from .domain_background_read_v3 import (_active_v3, require_actual_background_attachment_owner_v3,
            require_background_followup_handoff_v3)
        owner = _active_v3(db)
        if owner is None or owner.kind != "followup_child":
            raise ValueError("single-event growth requires its independently installed exact Source Work")
        require_actual_background_attachment_owner_v3(owner, db=db)
        handoff = require_background_followup_handoff_v3(owner.handoff, owner.graph, owner.bundle)
        if handoff.command.operation_kind != "review_single_event_growth_v1" or handoff.command.request != request:
            raise ValueError("single-event background review changed its exact current outbox command")
    else:
        if owner.operation_kind not in OPERATIONS or owner.request != request:
            raise ValueError("single-event growth requires its exact current Owner command")
        require_actual_method_learning_attachment_owner_v3(owner, db=db)
    read = CurrentDomainReadV1(frame); read.check(db)
    return read, owner


def _policy(db, read, readers, policy_ref, *, require_current_base):
    raw, original = readers._read(db, read, policy_ref, POLICY_KIND)
    policy = decode_typed_production_value_v1(raw, SingleEventGrowthPolicyV1)
    terms = policy.terms
    ns = read.frame.envelope.authority.namespace
    pins = tuple(pin for pin in read.frame.installed_policy_refs if pin.policy_ref == policy_ref)
    grant = read.head(db, owner_grant_key(*ns.as_tuple), required=True)
    if (terms.namespace != ns or terms.policy_ref != policy_ref
            or policy.runtime_identity != RuntimeIdentityRef.from_owner_guard(ns, readers.owner_guard)
            or policy.owner_grant != GraphVersion(grant.key, grant.revision)
            or policy.owner_grant_digest != canonical_digest(grant.value)
            or policy.owner_binding_digest != canonical_digest(read.frame.owner_guard)
            or len(pins) != 1 or pins[0].revision != terms.revision or pins[0].policy_digest != original.original_digest):
        raise MissingProductionOriginalV1("actual_installed_single_event_policy_current_Owner_and_incarnation")
    if require_current_base and not terms.valid_from_utc <= actual_current_single_event_upper_utc_v1(db, read.frame) < terms.readout_valid_until_utc:
        raise MissingProductionOriginalV1("single_event_original_fixed_validity")
    observer_raw, observer = readers._read(db, read, terms.observer_policy_ref, "identity_trial_observation_policy_v3")
    from ..domains.d01.identity_v3 import IdentityTrialObservationPolicyV3
    observed = decode_typed_production_value_v1(observer_raw, IdentityTrialObservationPolicyV3)
    observer_pins = tuple(pin for pin in read.frame.installed_policy_refs if pin.policy_ref == terms.observer_policy_ref)
    scope = tuple(v.key.token for v in terms.scope_versions)
    exclusions = tuple(v.key.token for v in terms.exclusion_versions)
    if (observer.original_digest != terms.observer_policy_digest or len(observer_pins) != 1
            or observer_pins[0].policy_digest != observer.original_digest
            or observed.runtime_identity != policy.runtime_identity or observed.scope_refs != scope
            or observed.exclusion_refs != exclusions
            or not observed.valid_from_utc <= terms.valid_from_utc < terms.readout_valid_until_utc <= observed.valid_until_utc):
        raise MissingProductionOriginalV1("single_event_actual_installed_observer_and_finite_scope")
    for version in (*terms.scope_versions, *terms.exclusion_versions, *terms.required_outcome_versions):
        atom = read.head(db, version.key, required=True)
        if atom.revision != version.revision:
            raise MissingProductionOriginalV1("single_event_exact_scope_or_outcome_version_changed")
    if tuple(_scope_commitment_v1(db, read, v.version) for v in policy.scope_commitments) != policy.scope_commitments:
        raise MissingProductionOriginalV1("single_event_scope_sealed_header_changed")
    from .domain_background_read_v3 import _active_v3
    background=_active_v3(db)
    if background is not None:
        from .single_event_review_target_v1 import prepare_current_single_event_review_target_metadata_v1
        selected=prepare_current_single_event_review_target_metadata_v1(background)
        active,target=selected.control,selected.target
    elif read.frame.envelope.identity.phase=='read_single_event_growth_v1':
        active=current_single_event_policy_head_metadata_v1(db,ns)
        target=next((b for b in active.blocks if b.block_id==terms.target_block),None)
    else:
        from .current_method_learning_read_v3 import _method_active
        from .role_control_lineage_metadata_v4 import require_current_qualified_single_event_review_metadata_v4
        owner=_method_active(db)
        qualified=(require_current_qualified_single_event_review_metadata_v4(owner)
            if owner is not None and read.frame.envelope.identity.phase=='review_single_event_growth_v1' else None)
        if qualified is not None:
            active=qualified.current
            target=next((b for b in active.blocks if b.block_id==terms.target_block),None)
        else:
            active = PersonaDomain().resolve_active_role(read.frame.snapshot, namespace=ns, current_guard=readers.owner_guard)
            target = next((b for b in active.plan.blocks if b.block_id == terms.target_block), None)
    if target is None or target.kind != terms.target_kind or target.plasticity != "growth":
        raise MissingProductionOriginalV1("single_event_actual_growth_target")
    if require_current_base:
        head = read.head(db, terms.expected_persona_head.key, required=True)
        if (head.revision != terms.expected_persona_head.revision or active.head_id != terms.persona_head_id
                or _single_event_target_digest_v1(target) != terms.base_claim_digest
                or not policy.registered_at_utc <= actual_current_single_event_upper_utc_v1(db, read.frame) < terms.adopt_before_utc):
            raise MissingProductionOriginalV1("single_event_original_exact_base_and_adoption_window")
    records = read.source_family(db, (terms.event_source.key.token,), purpose="consolidation")
    source = read.head(db, terms.event_source.key, required=True)
    record = records[terms.event_source.key.token]
    if (source.revision != terms.event_source.revision or canonical_digest(source.value) != terms.event_source_digest
            or record.provenance_root != terms.event_provenance_root or record.parent_source_ids
            or record.source_kind != "observed" or record.assertion_status != "confirmed" or record.independence != "independent"):
        raise MissingProductionOriginalV1("single_event_one_exact_qualified_external_event")
    if terms.context_source_refs:
        read.source_family(db, terms.context_source_refs, purpose="consolidation")
    return policy, original, active, target


def _bind_exception(db, read, owner, policy, policy_original, request):
    value = _SingleEventQualificationV1(_ISSUER)
    _QUALIFICATIONS[value] = (db, read.frame, ref(owner), policy, policy_original, owner.request, False, None)
    return value


def require_single_event_qualification_v1(value, *, plan, proposal, completed=True):
    entry = _QUALIFICATIONS.get(value)
    if entry is None:
        raise ValueError("one actual private single-event qualification is required")
    db, frame, owner_ref, policy, original, request, ready, qualified = entry
    owner = owner_ref()
    from .current_method_learning_read_v3 import require_actual_method_learning_attachment_owner_v3
    if owner is None:
        raise ValueError("single-event issuing Source Work has ended")
    require_actual_method_learning_attachment_owner_v3(owner, db=db)
    terms = policy.terms
    if (not db.in_transaction or owner.request != request or owner.operation_kind not in OPERATIONS
            or plan.head_id != terms.persona_head_id or proposal.base_head != plan.head_id
            or proposal.target_block != terms.target_block or proposal.change_kind != "core"
            or proposal.source_families != (terms.event_provenance_root,)
            or completed and (not ready or qualified != proposal)):
        raise ValueError("single-event exception changed its actual policy, base, one event or completed input")
    return policy


def _growth_inputs(db, read, owner, readers, policy, policy_original, request):
    from .d01_general_growth_v1 import AdoptCurrentGeneralGrowthRequestV1, read_current_general_growth_v1
    cap = _bind_exception(db, read, owner, policy, policy_original, request)
    try:
        growth = request.growth_request
        if policy.terms.target_kind == "semantic_identity":
            inputs = readers.read_growth(db, read.frame, growth, single_event_qualification=cap)
            raw, _ = readers._read(db, read, growth.growth_proposal_ref, "growth_proposal")
            if (raw["plasticity_policy_ref"], raw["plasticity_policy_digest"]) != (
                    policy.terms.plasticity_policy_ref, policy.terms.plasticity_policy_digest):
                raise ValueError("single-event semantic input changed its existing V3 plasticity policy")
            semantic = decode_semantic_identity_v3(inputs.proposal.replacement_claim)
            semantic = replace(semantic, valid_until=min(semantic.valid_until or policy.terms.readout_valid_until_utc,
                policy.terms.readout_valid_until_utc))
            encoded = encode_semantic_identity_v3(semantic)
            proposal = replace(inputs.proposal, replacement_claim=encoded)
            inputs = replace(inputs, proposal=proposal,
                semantic_qualification=replace(inputs.semantic_qualification, replacement_claim=encoded))
            general_provenance = None
        else:
            if request.general_growth_intent_ref is None:
                raise MissingProductionOriginalV1("single_event_ordinary_requires_existing_General_FULL_trials")
            ordinary = AdoptCurrentGeneralGrowthRequestV1(request.general_growth_intent_ref, growth.growth_proposal_ref,
                growth.trigger_original_ref, growth.trial_original_refs, growth.counterevidence_query_ref)
            inputs, general_provenance = read_current_general_growth_v1(readers, db, read.frame, ordinary,single_event_qualification=cap)
        if (not inputs.trials_complete or not inputs.counterevidence_complete or inputs.counterevidence_conflict
                or inputs.proposal.source_families != (policy.terms.event_provenance_root,)):
            raise MissingProductionOriginalV1("single_event_complete_original_trials_current_counter_and_one_event")
        terms = policy.terms
        event, event_original, records = read.adopted_interpretation(db, terms.event_interpretation.key.token,
            question_scope="d01.growth:" + terms.target_block + ":core")
        if (event.revision != terms.event_interpretation.revision or canonical_digest(event.value) != terms.event_interpretation_digest
                or tuple(event.value["source_refs"]) != (terms.event_source.key.token,)
                or event.value["proposition"] != (decode_semantic_identity_v3(inputs.proposal.replacement_claim).claim
                    if terms.target_kind == "semantic_identity" else inputs.proposal.replacement_claim)
                or event.value["stance"] != "support" or event.value["evidence_status"] != "supported"):
            raise MissingProductionOriginalV1("single_event_actual_adopted_event_and_proposed_claim")
        question = single_event_continuity_question_v1(policy_original.original_digest, terms.base_claim_digest,
            canonical_digest(decode_semantic_identity_v3(inputs.proposal.replacement_claim).claim
                if terms.target_kind == "semantic_identity" else inputs.proposal.replacement_claim),
            inputs.originals, growth.counterevidence_query_ref)
        continuity, continuity_original, _ = read.adopted_interpretation(db, request.continuity_interpretation_ref,
            question_scope=question)
        if continuity.value["proposition"] != "accepted":
            raise MissingProductionOriginalV1("single_event_explicit_adopted_before_after_continuity")
        originals = tuple(dict.fromkeys((*inputs.originals, policy_original, event_original, continuity_original)))
        inputs = replace(inputs, originals=originals, single_event_qualification=cap)
        entry = _QUALIFICATIONS[cap]
        _QUALIFICATIONS[cap] = (*entry[:6], True, inputs.proposal)
        return inputs, general_provenance
    except BaseException:
        _QUALIFICATIONS.pop(cap, None)
        raise


def single_event_continuity_question_v1(policy_digest, base_digest, new_digest, originals, counter_ref):
    return "d01.single-event-continuity.v1:" + canonical_digest((policy_digest, base_digest, new_digest,
        tuple(sorted((v.original_ref, v.original_digest) for v in originals)), counter_ref))


def single_event_review_question_v1(adoption, input_digest):
    return "d01.single-event-review.v1:" + canonical_digest((adoption.adoption_operation_id,
        adoption.policy_digest, input_digest, adoption.target_block, adoption.adopted_claim_digest,
        adoption.review_not_before_utc, adoption.review_due_utc, adoption.readout_valid_until_utc))


def request_from_wire_v1(kind, raw):
    if kind not in OPERATIONS:
        raise ValueError("unregistered single-event operation")
    return decode_typed_production_value_v1(raw, OPERATIONS[kind][0])


def _single_event_target_digest_v1(target):
    from .d01_ordinary_origin_v3 import OrdinaryBlockCommitmentV3
    from ..domains.d01 import PersonaBlock
    if type(target) is OrdinaryBlockCommitmentV3:return target.claim_digest
    if type(target) is PersonaBlock:return canonical_digest(target.claim)
    raise TypeError('single-event target requires actual committed metadata or qualified complete block')



def read_current_qualified_single_event_review_selection_v1(reader):
    """Actual metadata locators only; this does not issue a Body or ACK proof."""
    from .current_method_learning_read_v3 import (_MethodLearningReadV3,
        require_actual_method_learning_attachment_owner_v3)
    from .d01_general_growth_v1 import _general_plan_head_metadata_v1
    if (type(reader)is not _MethodLearningReadV3
            or reader.operation_kind!='review_single_event_growth_v1'
            or type(reader.request)is not ReviewSingleEventGrowthRequestV1):
        raise ValueError('qualified review metadata selector requires its actual typed Method command')
    require_actual_method_learning_attachment_owner_v3(reader,db=reader.db)
    reader.general_owner_entry.require_for_v3(reader)
    adopted=_general_plan_head_metadata_v1(reader.db,reader.namespace,
        AtomKey.from_token(reader.request.adoption_ref),'single_event_adoption',[])
    adopted.require_for_v1(reader)
    adoption=decode_typed_production_value_v1(adopted.value,SingleEventGrowthAdoptionV1)
    key=AtomKey.from_token(adoption.review_ref)
    metadata=_general_plan_head_metadata_v1(reader.db,reader.namespace,key,_review_metadata_kind_v1(key),[])
    metadata.require_for_v1(reader)
    review=decode_typed_production_value_v1(metadata.value,_review_type_v1(key))
    if type(review)is not SingleEventGrowthReviewV2 or review.disposition!='qualified':return None
    if (adopted.revision!=1 or adopted.key!=single_event_adoption_key_v1(reader.namespace,adoption.policy_ref)
            or key!=single_event_review_key_v2(reader.namespace,adoption.policy_ref)or metadata.revision!=2
            or review.adoption_ref!=adopted.key.token or review.adoption_operation_id!=adoption.adoption_operation_id
            or review.target_block!=adoption.target_block or review.adopted_claim_digest!=adoption.adopted_claim_digest
            or review.review_case_original is None):
        raise MissingProductionOriginalV1('actual_first_qualified_single_event_review_v2_metadata')
    return adopted,metadata


def current_single_event_policy_head_metadata_v1(db,namespace):
    from .current_method_learning_read_v3 import _method_active,_MethodLearningReadV3,require_actual_method_learning_attachment_owner_v3
    from .persona_growth_birth_v1 import current_persona_birth_control_v1
    from .role_control_lineage_metadata_v4 import require_role_control_lineage_metadata_v4
    from ..domains.d01 import ActiveRoleHeadControlV3
    owner=_method_active(db)
    if (type(owner)is not _MethodLearningReadV3 or owner.namespace!=namespace
            or (owner.operation_kind,type(owner.request))not in {
                ('register_single_event_growth_policy_v1',RegisterSingleEventGrowthPolicyRequestV1),
                ('read_single_event_growth_v1',ReadSingleEventGrowthRequestV1)}):
        raise ValueError('single-event head metadata requires its actual typed policy/read Method')
    require_actual_method_learning_attachment_owner_v3(owner,db=db)
    birth=current_persona_birth_control_v1(db,namespace=namespace)
    control=ActiveRoleHeadControlV3(namespace,birth.head_id,birth.persona_head_version.key,birth.semantic_version,
        (birth.activation_version,birth.persona_head_version,birth.owner_grant_version),
        owner.graph_stamp[1].revision,owner.owner_guard.authorization_revision)
    lineage=require_role_control_lineage_metadata_v4(owner,control)
    head=lineage.current
    if head.plan_ref!=birth.persona_head_version or head.head_id!=birth.head_id:
        raise ValueError('single-event policy metadata lost its actual current control/head join')
    return head

def _register_policy(db, frame, readers, request, read):
    terms = request.terms
    ns = frame.envelope.authority.namespace
    if terms.namespace != ns or not terms.valid_from_utc <= actual_current_single_event_upper_utc_v1(db, frame) < terms.adopt_before_utc:
        raise ValueError("explicit single-event registration crossed its namespace or original window")
    head = current_single_event_policy_head_metadata_v1(db, ns)
    target = next((b for b in head.blocks if b.block_id == terms.target_block), None)
    if (head.plan_ref != terms.expected_persona_head or head.head_id != terms.persona_head_id
            or target is None or target.kind != terms.target_kind or target.plasticity != "growth"
            or target.claim_digest != terms.base_claim_digest):
        raise MissingProductionOriginalV1("single_event_registration_exact_current_base")
    grant = read.head(db, owner_grant_key(*ns.as_tuple), required=True)
    for version in (*terms.scope_versions, *terms.exclusion_versions, *terms.required_outcome_versions):
        if read.head(db, version.key, required=True).revision != version.revision:
            raise MissingProductionOriginalV1("single_event_registration_exact_current_scope")
    records = read.source_family(db, (terms.event_source.key.token,), purpose="consolidation")
    source = read.head(db, terms.event_source.key, required=True)
    event, _, _ = read.adopted_interpretation(db, terms.event_interpretation.key.token,
        question_scope="d01.growth:" + terms.target_block + ":core")
    record = records[terms.event_source.key.token]
    if (source.revision != terms.event_source.revision or canonical_digest(source.value) != terms.event_source_digest
            or record.provenance_root != terms.event_provenance_root or record.parent_source_ids
            or record.source_kind != "observed" or record.assertion_status != "confirmed" or record.independence != "independent"
            or event.revision != terms.event_interpretation.revision or canonical_digest(event.value) != terms.event_interpretation_digest
            or tuple(event.value["source_refs"]) != (terms.event_source.key.token,)
            or event.value["stance"] != "support" or event.value["evidence_status"] != "supported"):
        raise MissingProductionOriginalV1("single_event_registration_actual_one_event_adoption")
    if terms.context_source_refs:
        read.source_family(db, terms.context_source_refs, purpose="consolidation")
    observer_raw, observer_original = readers._read(db, read, terms.observer_policy_ref, "identity_trial_observation_policy_v3")
    from ..domains.d01.identity_v3 import IdentityTrialObservationPolicyV3
    observer = decode_typed_production_value_v1(observer_raw, IdentityTrialObservationPolicyV3)
    runtime = RuntimeIdentityRef.from_owner_guard(ns, readers.owner_guard)
    pins = tuple(v for v in frame.installed_policy_refs if v.policy_ref == terms.observer_policy_ref)
    if (observer_original.original_digest != terms.observer_policy_digest or observer.runtime_identity != runtime
            or len(pins) != 1 or pins[0].policy_digest != observer_original.original_digest
            or observer.scope_refs != tuple(v.key.token for v in terms.scope_versions)
            or observer.exclusion_refs != tuple(v.key.token for v in terms.exclusion_versions)
            or not observer.valid_from_utc <= terms.valid_from_utc < terms.readout_valid_until_utc <= observer.valid_until_utc):
        raise MissingProductionOriginalV1("single_event_registration_actual_installed_observer")
    if terms.target_kind == "semantic_identity":
        policy, original = readers._identity_policy_v3(db, read, terms.plasticity_policy_ref, require_growth=True)
        if (original.original_digest != terms.plasticity_policy_digest or terms.target_block not in policy.target_block_ids
                or policy.observer_policy_ref != terms.observer_policy_ref or policy.observer_policy_digest != terms.observer_policy_digest
                or not policy.valid_from_utc <= terms.valid_from_utc < terms.adopt_before_utc <= policy.valid_until_utc
                or policy.readout_valid_until_utc is not None and terms.readout_valid_until_utc > policy.readout_valid_until_utc):
            raise MissingProductionOriginalV1("single_event_registration_preserves_existing_deep_V3_bounds")
    for key in (single_event_adoption_key_v1(ns, terms.policy_ref), single_event_review_key_v2(ns, terms.policy_ref)):
        if read.head(db, key).revision != 0:
            raise ValueError("a consumed single-event policy cannot be re-registered")
    return SingleEventGrowthPolicyV1(terms, runtime, GraphVersion(grant.key, grant.revision),
        canonical_digest(grant.value), canonical_digest(frame.owner_guard), actual_current_single_event_upper_utc_v1(db, frame), frame.envelope.identity.operation_id,
        tuple(_scope_commitment_v1(db, read, version) for version in (*terms.scope_versions, *terms.exclusion_versions)),
        _actual_source_plan_roots_v1(db))


def _prepare_input(db, read, owner, readers, request, policy, policy_original):
    inputs, general = _growth_inputs(db, read, owner, readers, policy, policy_original, request)
    roots = _actual_source_plan_roots_v1(db)
    value = SingleEventGrowthInputV1(request.input_ref, policy.terms.policy_ref, policy_original.original_digest,
        policy.registration_operation_id, request.growth_request.growth_proposal_ref, request.growth_request.trigger_original_ref,
        request.growth_request.trial_original_refs, request.growth_request.counterevidence_query_ref,
        request.general_growth_intent_ref, request.continuity_interpretation_ref,
        canonical_digest(decode_semantic_identity_v3(inputs.proposal.replacement_claim).claim
            if policy.terms.target_kind == "semantic_identity" else inputs.proposal.replacement_claim),
        policy.terms.event_provenance_root, roots,
        tuple(v for v in read.frame.snapshot.versions if v.key.type_name in {
            "memory.source", "memory.access", "d06.source_correction_head.v1"}), actual_current_single_event_upper_utc_v1(db, read.frame))
    if value.prepared_at_utc>=policy.terms.adopt_before_utc:
        raise MissingProductionOriginalV1("single_event_original_preparation_deadline_elapsed")
    return value, inputs, general


def _registered_input(db, read, readers, ref):
    raw, original = readers._read(db, read, ref, INPUT_KIND)
    value = decode_typed_production_value_v1(raw, SingleEventGrowthInputV1)
    policy, policy_original, active, target = _policy(db, read, readers, value.policy_ref, require_current_base=True)
    if (value.policy_digest != policy_original.original_digest or value.registration_operation_id != policy.registration_operation_id
            or not policy.registered_at_utc <= value.prepared_at_utc <= actual_current_single_event_upper_utc_v1(db, read.frame) < policy.terms.adopt_before_utc):
        raise MissingProductionOriginalV1("single_event_input_actual_registration_and_original_window")
    request = PrepareSingleEventGrowthRequestV1(value.input_ref, value.policy_ref,
        AdoptCurrentGrowthRequestV1(value.growth_proposal_ref, value.trigger_original_ref,
            value.trial_original_refs, value.counterevidence_query_ref), value.general_growth_intent_ref,
        value.continuity_interpretation_ref)
    return value, original, policy, policy_original, request


def _record_origin(db, read, atom, *, kind):
    if read.frame.envelope.identity.phase=='review_single_event_growth_v1':
        from .current_method_learning_read_v3 import _method_active
        from .role_control_lineage_metadata_v4 import require_current_qualified_single_event_review_metadata_v4
        owner=_method_active(db)
        qualified=require_current_qualified_single_event_review_metadata_v4(owner)if owner is not None else None
        if qualified is not None:
            return qualified.require_recorded_origin_v4(owner,version=GraphVersion(atom.key,atom.revision),
                value=atom.value,operation_kind=kind)
    from ..runtime_storage_v3 import read_graph_row_v3
    history = read_graph_row_v3(db, ("event_id", "value", "valid"), where="token=? AND revision=?",
        parameters=(atom.key.token, atom.revision), history=True)
    from ..runtime_contracts import canonical_serialize
    if history is None or history[2] != 1 or __import__("json").loads(history[1]) != atom.value:
        raise MissingProductionOriginalV1("single_event_actual_original_history")
    from .domain_background_read_v3 import _active_v3
    background=_active_v3(db)
    if background is not None and kind=='adopt_single_event_growth_v1':
        from .single_event_review_target_v1 import read_current_single_event_review_adoption_metadata_v1
        adopted=decode_typed_production_value_v1(atom.value,SingleEventGrowthAdoptionV1)
        original=read_current_single_event_review_adoption_metadata_v1(background,adopted)
    else:
        original = read_adopted_domain_operation_v1(db, read.frame.envelope.authority.namespace, history[0])
    if (original is None or (original["domain"], original["operation_kind"]) != ("d01", kind)
            or GraphVersion(atom.key, atom.revision) not in original["receipt"].write_versions):
        raise MissingProductionOriginalV1("single_event_same_W01_typed_original_and_receipt")
    read.committed_operation(db, history[0])
    return original


def _review_type_v1(key):
    if key.type_name==REVIEW_TYPE:return SingleEventGrowthReviewV1
    if key.type_name==REVIEW_TYPE_V2:return SingleEventGrowthReviewV2
    raise ValueError('single-event review requires its explicit registered Graph type')


def _review_metadata_kind_v1(key):
    _review_type_v1(key)
    return 'single_event_review_v2' if key.type_name==REVIEW_TYPE_V2 else 'single_event_review'


def _adoption_and_review(db, read, readers, adoption_ref):
    atom = read.head(db, adoption_ref, required=True)
    if atom.key.type_name != ADOPTION_TYPE or atom.revision != 1:
        raise ValueError("single-event review selects its immutable actual first adoption")
    adoption = decode_typed_production_value_v1(atom.value, SingleEventGrowthAdoptionV1)
    original = _record_origin(db, read, atom, kind="adopt_single_event_growth_v1")
    policy, policy_original, active, target = _policy(db, read, readers, adoption.policy_ref, require_current_base=False)
    input_raw, input_original = readers._read(db, read, adoption.input_ref, INPUT_KIND)
    value = decode_typed_production_value_v1(input_raw, SingleEventGrowthInputV1)
    review_key=AtomKey.from_token(adoption.review_ref)
    expected_keys={REVIEW_TYPE:single_event_review_key_v1(adoption.namespace,adoption.policy_ref),
        REVIEW_TYPE_V2:single_event_review_key_v2(adoption.namespace,adoption.policy_ref)}
    if review_key.type_name not in expected_keys or review_key!=expected_keys[review_key.type_name]:
        raise ValueError('single-event adoption has another exact versioned review selector')
    review_atom = read.head(db, review_key, required=True)
    review=decode_typed_production_value_v1(review_atom.value,
        SingleEventGrowthReviewV2 if review_key.type_name==REVIEW_TYPE_V2 else SingleEventGrowthReviewV1)
    terms = policy.terms
    if (atom.key != single_event_adoption_key_v1(adoption.namespace, terms.policy_ref)
            or original["receipt"].operation_id != adoption.adoption_operation_id
            or original["payload"]["provenance"]["single_event_adoption"] != atom.value
            or adoption.policy_digest != policy_original.original_digest or adoption.input_digest != input_original.original_digest
            or value.policy_digest != policy_original.original_digest or adoption.target_block != terms.target_block
            or _single_event_target_digest_v1(target) != adoption.adopted_claim_digest
            or adoption.review_ref != review_key.token
            or (adoption.review_not_before_utc, adoption.review_due_utc, adoption.readout_valid_until_utc) != (
                terms.review_not_before_utc, terms.review_due_utc, terms.readout_valid_until_utc)
            or (review.adoption_ref, review.adoption_operation_id, review.target_block, review.adopted_claim_digest,
                review.review_not_before_utc, review.review_due_utc, review.readout_valid_until_utc) != (
                atom.key.token, adoption.adoption_operation_id, terms.target_block, adoption.adopted_claim_digest,
                terms.review_not_before_utc, terms.review_due_utc, terms.readout_valid_until_utc)):
        raise MissingProductionOriginalV1("single_event_exact_adoption_input_review_current_claim_binding")
    born = GraphVersion(review_key, 1)
    if born not in original["receipt"].write_versions or GraphVersion(review_key, 0) not in original["receipt"].read_versions:
        raise MissingProductionOriginalV1("single_event_review_obligation_was_not_same_CAS")
    if review_atom.revision == 1:
        if review.disposition != "pending":
            raise ValueError("single-event birth obligation cannot claim a performed review")
    else:
        _record_origin(db, read, review_atom, kind="review_single_event_growth_v1")
    return adoption, original, policy, value, review_atom, review




def prepare_current_single_event_review_read_dependencies_v1(owner,*,frame=None):
    from .current_method_learning_read_v3 import _MethodLearningReadV3,require_actual_method_learning_attachment_owner_v3
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_background_followup_handoff_v3
    if type(owner)is _MethodLearningReadV3:
        if owner.operation_kind!='review_single_event_growth_v1':return
        require_actual_method_learning_attachment_owner_v3(owner,db=owner.db)
        if type(owner.request)is not ReviewSingleEventGrowthRequestV1:
            raise TypeError('review dependencies need the actual typed Owner request')
        adoption=_single_graph_metadata_v1(owner.db,owner.namespace,AtomKey.from_token(owner.request.adoption_ref),
            'single_event_adoption',[])
        if _single_event_qualified_review_metadata_v1(owner.db,owner.namespace,adoption):return
        if owner.request.continuity_interpretation_ref is None:
            from .d07_single_event_review_v1 import prepare_current_single_event_review_cause_history_v1
            prepare_current_single_event_review_cause_history_v1(owner)
            return
        from .d07_single_event_review_v1 import read_actual_single_event_review_interpretation_case_original_v1
        case_original=read_actual_single_event_review_interpretation_case_original_v1(owner.db,read=owner,
            interpretation_ref=owner.request.continuity_interpretation_ref)
    elif type(owner)is BackgroundReadWorkV3:
        require_single_event_review_target_metadata_work_v1(owner)
        command=require_background_followup_handoff_v3(owner.handoff,owner.graph,owner.bundle).command
        if command.request.continuity_interpretation_ref is None:
            from .d07_single_event_review_v1 import prepare_current_single_event_review_cause_history_v1
            prepare_current_single_event_review_cause_history_v1(owner)
            if frame is not None:prepare_current_single_event_review_registration_v1(owner,frame)
            return
        fact=_require_single_event_completion_source_cause_v1(owner)
        if fact is None:raise ValueError('final review dependencies have no actual paid completion cause')
        if command.request.continuity_interpretation_ref!=fact.value.interpretation_version.key.token:
            raise ValueError('review dependencies changed their actual paid interpretation')
        case_original=fact.value.case_original
    else:raise TypeError('review dependencies need their actual registered Method or Background child')
    from .d01_single_event_review_case_v1 import prepare_current_single_event_review_case_body_v1
    prepare_current_single_event_review_case_body_v1(owner,case_original)
    from .d07_single_event_review_v1 import prepare_single_event_review_interpretation_dependencies_v1
    prepare_single_event_review_interpretation_dependencies_v1(owner,case_original)


def prepare_current_single_event_review_registration_v1(owner,frame):
    """Derive/locate a Case in the actual READ; no proposal or W01 is produced."""
    from .current_method_learning_read_v3 import _MethodLearningReadV3,require_actual_method_learning_attachment_owner_v3
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_background_followup_handoff_v3
    if type(owner)is _MethodLearningReadV3:
        require_actual_method_learning_attachment_owner_v3(owner,db=owner.db)
        if owner.operation_kind!='review_single_event_growth_v1' or type(owner.request)is not ReviewSingleEventGrowthRequestV1:
            raise ValueError('Case READ registration has another actual Method command')
        request=owner.request
    elif type(owner)is BackgroundReadWorkV3:
        require_single_event_review_target_metadata_work_v1(owner)
        request=require_background_followup_handoff_v3(owner.handoff,owner.graph,owner.bundle).command.request
    else:raise TypeError('Case READ registration needs its actual Method or Background child')
    if request.continuity_interpretation_ref is not None:return
    read=CurrentDomainReadV1(frame);read.check(owner.db)
    readers=InstalledD01ProductionReadersV1(issuer=owner.graph._GraphCoordinator__d11_issuer,
        owner_guard=owner.owner_guard,role_clock_reader=owner.graph._GraphCoordinator__d04_semantic_mapping_reader)
    adoption,original,policy,value,atom,review=_adoption_and_review(owner.db,read,readers,request.adoption_ref)
    now=actual_current_single_event_upper_utc_v1(owner.db,frame)
    if (type(review)is not SingleEventGrowthReviewV2 or atom.revision!=1 or review.disposition!='pending'
            or not adoption.review_not_before_utc<=now<adoption.review_due_utc):return
    from .d01_single_event_review_case_v1 import prepare_current_single_event_case_registration_v1
    prepare_current_single_event_case_registration_v1(owner,frame,adoption=adoption,adoption_original=original,
        policy=policy,value=value,review_atom=atom,review=review,readers=readers)

def _single_event_first_review_interpretation_v1(db,read,readers,adoption,policy,value,interpretation_ref):
    from .domain_background_read_v3 import _active_v3
    from .d01_single_event_review_case_v1 import require_registered_single_event_review_case_fact_v1
    from .d07_single_event_review_v1 import require_actual_single_event_review_interpretation_v1
    owner=_active_v3(db)
    completion=None if owner is None else _require_single_event_completion_source_cause_v1(owner)
    if owner is not None:
        if completion is None:raise MissingProductionOriginalV1('actual_single_event_review_paid_completion')
        selected=completion.value;case_original=selected.case_original
        if (selected.adoption_version.key.token!=single_event_adoption_key_v1(adoption.namespace,adoption.policy_ref).token
                or selected.interpretation_version.key.token!=interpretation_ref):
            raise ValueError('review continuity changed its actual paid completion adoption or interpretation')
    else:
        from .d07_single_event_review_v1 import read_actual_single_event_review_interpretation_case_original_v1
        case_original=read_actual_single_event_review_interpretation_case_original_v1(db,read=read,
            interpretation_ref=interpretation_ref)
    case_fact=require_registered_single_event_review_case_fact_v1(db,frame=read.frame,
        case_original=case_original,issuer=readers.issuer)
    case=case_fact.case
    if (case.policy_original.original_ref!=policy.terms.policy_ref or case.policy_original.original_digest!=adoption.policy_digest
            or case.input_original.original_ref!=value.input_ref or case.input_original.original_digest!=adoption.input_digest
            or case.target_block!=adoption.target_block or case.adopted_claim_digest!=adoption.adopted_claim_digest
            or case.adoption_version!=GraphVersion(single_event_adoption_key_v1(adoption.namespace,adoption.policy_ref),1)
            or completion is not None and (case.adoption_version!=completion.value.adoption_version
                or case.review_version!=completion.value.review_version)):
        raise ValueError('review continuity differs from the exact actual adoption/Case/pending obligation')
    return require_actual_single_event_review_interpretation_v1(readers,db,read,
        case_original=case_original,interpretation_ref=interpretation_ref,case_fact=case_fact)

def _review_current_counter_v1(db,read,readers,policy,value):
    missing = []
    originals = []
    raw, proposal_original = readers._read(db, read, value.growth_proposal_ref, "growth_proposal")
    proof=_issue_single_event_fact_read_v1(db,read,readers,policy,value)
    if policy.terms.target_kind == "semantic_identity":
        counter = single_event_current_counter_scope_v1(db,read,raw,proof,semantic=True)
        if not counter.complete:
            missing.append("complete_current_counter_scope:" + counter.qualification)
        conflict = counter.qualification == "opposition"
    else:
        complete, conflict, counter_originals = single_event_current_counter_scope_v1(db,read,raw,proof,semantic=False)
        originals.extend(counter_originals)
        if not complete:
            missing.append("complete_current_counter_scope")
    for version in policy.terms.required_outcome_versions:
        atom = read.head(db, version.key, required=True)
        if atom.revision != version.revision:
            missing.append("exact_registered_actual_outcome")
        else:
            originals.append(read.original(atom.key.token))
    return conflict,tuple(dict.fromkeys(missing)),tuple(dict.fromkeys(originals))


def _review_conditions(db, read, readers, adoption, policy, value, continuity_ref):
    _requalify_trials(db, read, readers, policy, value, adoption.adopted_at_utc)
    conflict,current_missing,current_originals=_review_current_counter_v1(db,read,readers,policy,value)
    missing=list(current_missing);originals=list(current_originals)
    case_original=None;case_roots=()
    if continuity_ref is None:
        missing.append("actual_post_adoption_continuity")
    else:
        fact=_single_event_first_review_interpretation_v1(db,read,readers,adoption,policy,value,continuity_ref)
        fact.require_current_v1(readers,read);case_original=fact.case_original
        case_roots=tuple(dict.fromkeys((*fact.case.support_source_refs,*fact.case.context_source_refs)))
        originals.extend((*fact.originals,case_original))
        current=fact.semantic.value
        if current['stance']=='oppose'and current['evidence_status']=='supported':conflict=True
        elif (current['stance']!='support'or current['evidence_status']!='supported'
                or current['meaningful_unknowns']or not current['source_refs']):
            missing.append('actual_single_event_review_continuity_support')
    return conflict, tuple(dict.fromkeys(missing)), tuple(dict.fromkeys(originals)),case_original,case_roots


def _interpretation_operation_v1(db, atom):
    from ..runtime_storage_v3 import read_graph_row_v3
    row = read_graph_row_v3(db, ("event_id",), where="token=? AND revision=?",
        parameters=(atom.key.token, atom.revision), history=True)
    if row is None:
        raise MissingProductionOriginalV1("actual_single_event_continuity_history")
    return row[0]


def stage_single_event_growth_v1(db, *, frame, request, installed_readers):
    read, owner = _actual(db, frame, installed_readers, request)
    kind = next(k for k, (cls, _) in OPERATIONS.items() if type(request) is cls)
    ns = frame.envelope.authority.namespace
    if type(request) is not OPERATIONS[kind][0]:
        raise TypeError("single-event operation requires its exact closed request")
    try:
        if kind == "register_single_event_growth_policy_v1":
            value = _register_policy(db, frame, installed_readers, request, read)
            return stage_result_v1(frame, "d01", kind, request, provenance={"single_event_policy": value})
        if kind == "prepare_single_event_growth_v1":
            policy, original, _, _ = _policy(db, read, installed_readers, request.policy_ref, require_current_base=True)
            value, inputs, general = _prepare_input(db, read, owner, installed_readers, request, policy, original)
            return stage_result_v1(frame, "d01", kind, request, provenance={"single_event_input": value},
                costs=inputs.paid_cost_originals)
        if kind == "adopt_single_event_growth_v1":
            value, input_original, policy, policy_original, prepared = _registered_input(db, read, installed_readers, request.input_ref)
            current, inputs, general = _prepare_input(db, read, owner, installed_readers, prepared, policy, policy_original)
            if (current.replacement_claim_digest != value.replacement_claim_digest
                    or current.source_versions != value.source_versions or current.source_refs != value.source_refs):
                raise MissingProductionOriginalV1("single_event_frozen_input_Source_versions_or_claim_changed")
            inputs = replace(inputs, originals=tuple(dict.fromkeys((*inputs.originals, input_original))))
            from .current_full_persona_writer_v1 import (require_bound_current_full_persona_writer_v1,
                require_full_persona_writer_stage_v1)
            writer, _ = require_bound_current_full_persona_writer_v1(db, frame=frame, request=request)
            old_stage = compile_adopt_current_growth_v1(frame, prepared.growth_request, inputs,
                writer_qualification=writer, writer_request=request)
            old_stage = require_full_persona_writer_stage_v1(db, frame=frame, request=request, stage=old_stage)
            writes = tuple(w for p in old_stage.proposals for w in p.typed_writes)
            candidate = __import__("json").loads(old_stage.original_payload_json)["provenance"]
            adoption_key = single_event_adoption_key_v1(ns, policy.terms.policy_ref)
            review_key = single_event_review_key_v2(ns, policy.terms.policy_ref)
            if any(read.head(db, key).revision != 0 for key in (adoption_key, review_key)):
                raise ValueError("single-event policy was already consumed by an actual adoption")
            if actual_current_single_event_upper_utc_v1(db,frame)>=policy.terms.adopt_before_utc:
                raise MissingProductionOriginalV1("single_event_original_adoption_deadline_elapsed")
            adoption = SingleEventGrowthAdoptionV1(ns, policy.terms.policy_ref, policy_original.original_digest,
                value.input_ref, input_original.original_digest, frame.envelope.identity.operation_id,
                policy.terms.target_block, policy.terms.persona_head_id, candidate["candidate"]["head_id"],
                canonical_digest(inputs.proposal.replacement_claim), policy.terms.event_provenance_root, review_key.token, (decode_semantic_identity_v3(inputs.proposal.replacement_claim).valid_from
                    if policy.terms.target_kind == "semantic_identity" else actual_current_single_event_upper_utc_v1(db, frame)),
                policy.terms.review_not_before_utc, policy.terms.review_due_utc, policy.terms.readout_valid_until_utc, value.source_refs)
            obligation = SingleEventGrowthReviewV2(ns, adoption_key.token, adoption.adoption_operation_id,
                adoption.adopted_head, adoption.target_block, adoption.adopted_claim_digest, adoption.review_not_before_utc,
                adoption.review_due_utc, adoption.readout_valid_until_utc, "pending", None, None, (), (), value.source_refs, None)
            writes += (GraphWrite(adoption_key, plain_v1(adoption)), GraphWrite(review_key, plain_v1(obligation)))
            return stage_result_v1(frame, "d01", kind, request, writes=writes,
                provenance={"single_event_adoption": adoption, "single_event_review": obligation,
                    "growth": candidate, "general_growth": general},
                contribution_keys=tuple(k for p in old_stage.proposals for k in p.contribution_keys),
                receiver_events=(("d01", REVIEW_EVENT), ("d08", "persona_growth_requires_commitment_reevaluation"),
                    ("d10", "persona_growth_requires_life_reevaluation")), costs=old_stage.paid_cost_originals,
                proposal_schema="d01.proposal.v1", proposal_hash=PersonaDomain().descriptor.request_schema_hash)
        adoption, original, policy, value, atom, previous = _adoption_and_review(db, read, installed_readers, request.adoption_ref)
        if kind == "read_single_event_growth_v1":
            return stage_result_v1(frame, "d01", kind, request, provenance={"single_event_adoption": adoption,
                "single_event_review": previous})
        if type(previous) is not SingleEventGrowthReviewV2:
            raise MissingProductionOriginalV1('legacy_single_event_review_v1_has_no_v2_case_qualification')
        case_original=previous.review_case_original;case_roots=()
        if atom.revision != request.expected_review_revision:
            raise MissingProductionOriginalV1("single_event_actual_review_revision_changed")
        if previous.disposition == "qualified" and actual_current_single_event_upper_utc_v1(db, frame) < adoption.readout_valid_until_utc:
            conflict,missing,originals=_review_current_counter_v1(db,read,installed_readers,policy,value)
            if not conflict and not missing:
                return stage_result_v1(frame, "d01", kind, request,
                    provenance={"single_event_adoption": adoption, "single_event_review": previous,
                        "single_event_review_case":None})
            disposition = "opposed" if conflict else "unknown"
        elif actual_current_single_event_upper_utc_v1(db, frame) >= adoption.readout_valid_until_utc or actual_current_single_event_upper_utc_v1(db, frame) >= adoption.review_due_utc:
            disposition, missing, originals = "expired", ("original_single_event_review_or_readout_window_elapsed",), ()
        elif actual_current_single_event_upper_utc_v1(db, frame) < adoption.review_not_before_utc:
            raise MissingProductionOriginalV1("single_event_original_review_not_before")
        else:
            conflict, missing, originals, case_original, case_roots = _review_conditions(db, read, installed_readers, adoption, policy, value,
                request.continuity_interpretation_ref)
            if not conflict and request.continuity_interpretation_ref is None:
                from .d01_single_event_review_case_v1 import require_current_single_event_case_registration_v1
                case,reused=require_current_single_event_case_registration_v1(owner,frame)
                return stage_result_v1(frame,'d01',kind,request,
                    provenance={'single_event_adoption':adoption,'single_event_review':previous,'single_event_review_case':case},
                    receiver_events=(('d07',CASE_EVENT),)if reused is None else ())
            disposition = "opposed" if conflict else "unknown" if missing else "qualified"
        review = replace(previous, disposition=disposition, reviewed_at_utc=actual_current_single_event_upper_utc_v1(db, frame),
            continuity_interpretation_ref=request.continuity_interpretation_ref,
            observed_original_refs=tuple(o.original_ref for o in originals), missing_conditions=missing,
            review_case_original=case_original,
            source_refs=tuple(dict.fromkeys((*previous.source_refs,*case_roots))))
        return stage_result_v1(frame, "d01", kind, request,
            writes=(GraphWrite(atom.key, plain_v1(review),dependencies=(AtomKey.from_token(review.adoption_ref),
                *(AtomKey.from_token(ref)for ref in review.source_refs))),),
            provenance={"single_event_adoption": adoption, "single_event_review": review,
                "single_event_review_case":None},
            proposal_schema="d01.proposal.v1", proposal_hash=PersonaDomain().descriptor.request_schema_hash)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d01", kind, request, missing)


def provenance_types_single_event_v1(kind):
    if kind == "register_single_event_growth_policy_v1":
        return {"single_event_policy": SingleEventGrowthPolicyV1}
    if kind == "prepare_single_event_growth_v1":
        return {"single_event_input": SingleEventGrowthInputV1}
    if kind == "adopt_single_event_growth_v1":
        return {"single_event_adoption": SingleEventGrowthAdoptionV1, "single_event_review": SingleEventGrowthReviewV1|SingleEventGrowthReviewV2,
                "growth": None, "general_growth": None}
    if kind=='review_single_event_growth_v1':
        return {'single_event_adoption':SingleEventGrowthAdoptionV1,'single_event_review':SingleEventGrowthReviewV2,
            'single_event_review_case':RegisteredSingleEventReviewCaseV1|None}
    if kind=='read_single_event_growth_v1':
        return {'single_event_adoption':SingleEventGrowthAdoptionV1,'single_event_review':SingleEventGrowthReviewV1|SingleEventGrowthReviewV2}
    raise ValueError("unregistered single-event provenance shape")


def legacy_single_event_review_provenance_types_v1():
    """Exact old signed two-field data; this decoder issues no Case qualification."""
    return {'single_event_adoption':SingleEventGrowthAdoptionV1,'single_event_review':SingleEventGrowthReviewV1}


def verify_single_event_stage_v1(stage):
    import json
    if stage.domain != "d01" or stage.operation_kind not in OPERATIONS:
        raise ValueError("single-event verifier received another installed operation")
    payload = json.loads(stage.original_payload_json)
    provenance = payload["provenance"]
    if stage.coverage != "complete":
        if stage.proposals:
            raise ValueError("incomplete single-event evidence cannot write persona or review state")
        return stage
    shape = provenance_types_single_event_v1(stage.operation_kind)
    if set(provenance) != set(shape):
        raise ValueError("single-event actual original has another closed provenance shape")
    for name, cls in shape.items():
        if cls is not None:
            decode_typed_production_value_v1(provenance[name], cls)
    if stage.operation_kind=='adopt_single_event_growth_v1' and provenance['single_event_review']['schema']!='d01.single-event-growth-review.v2':
        raise ValueError('new single-event adopter requires its explicit same-CAS Review V2 obligation')
    allowed = {"d01.persona_plan.v1", "d01.persona_revision.v1", "d01.persona_activation.v1",
               "d01.growth_contribution.v1", ADOPTION_TYPE, REVIEW_TYPE_V2} if stage.operation_kind == "adopt_single_event_growth_v1" else {
                   REVIEW_TYPE,REVIEW_TYPE_V2} if stage.operation_kind == "review_single_event_growth_v1" else set()
    specs = {s.name: s for s in PersonaDomain().type_specs()}
    for proposal in stage.proposals:
        if proposal.proposal_schema != "d01.proposal.v1":
            raise ValueError("single-event proposal changed its actual D01 schema")
        for write in proposal.typed_writes:
            if write.key.type_name not in allowed or write.key.owner.kind != "persona":
                raise ValueError("single-event operation contains an unrelated write")
            specs[write.key.type_name].validator(write.value)
    return stage


def _requalify_trials(db, read, readers, policy, value, adopted_at):
    from .d01_general_growth_v1 import (GeneralGrowthIntentOriginalV1, GeneralGrowthTrialStartV1,
        GeneralGrowthTrialOriginalV1, validate_current_general_growth_completed_trial_v1)
    if policy.terms.target_kind == "semantic_identity":
        fact_read = _issue_single_event_fact_read_v1(db, read, readers, policy, value)
        for trial_ref in value.trial_original_refs:
            trial, _ = readers._read(db, read, trial_ref, "growth_trial")
            if trial.get("schema") != "d01.growth-trial.v2":
                raise MissingProductionOriginalV1("single_event_actual_semantic_V2_trial")
            start, _ = readers._read(db, read, trial["trial_start_ref"], "identity_trial_start_v3")
            readers.validate_semantic_trial_plan_history_v3(db, read, start)
            for outcome in trial["settled_outcome_refs"]:
                current = readers.derive_current_growth_trial_from_adopted_progress_v1(db, frame=read.frame,
                    producing_operation_id=None, original_ref=trial_ref, growth_proposal_ref=value.growth_proposal_ref,
                    settled_progress_ref=outcome, validate_only=True, adopted_at_utc=adopted_at,
                    single_event_qualification=fact_read)
                if plain_v1(current) != trial:
                    raise MissingProductionOriginalV1("single_event_current_actual_semantic_trial_effect_Source_cost")
    else:
        raw, _ = readers._read(db, read, value.general_growth_intent_ref, "general_growth_intent_v1")
        wrapper = decode_typed_production_value_v1(raw, GeneralGrowthIntentOriginalV1)
        if wrapper.required_trial_refs != value.trial_original_refs:
            raise ValueError("single-event ordinary readout changed its exact General trial membership")
        for trial_ref, start_ref in zip(value.trial_original_refs, wrapper.trial_start_refs, strict=True):
            raw, _ = readers._read(db, read, start_ref, "general_growth_trial_start_v1")
            start = decode_typed_production_value_v1(raw, GeneralGrowthTrialStartV1)
            raw, _ = readers._read(db, read, trial_ref, "general_growth_trial_v1")
            trial = decode_typed_production_value_v1(raw, GeneralGrowthTrialOriginalV1)
            validate_current_general_growth_completed_trial_v1(readers, db, read, start, trial)


def record_single_event_after_cas_v1(readers, db, *, witness, frame, primary, request, receipt):
    """The shared committer supplies the actual prevalidated same-CAS witness."""
    from .domain_production_commit_v1 import require_single_event_after_cas_witness_v1
    provenance = require_single_event_after_cas_witness_v1(witness, db=db, frame=frame,
        producing_operation_id=primary.operation_id, request=request, receipt=receipt,
        operation_kind=primary.operation_kind)
    if primary.operation_kind == "register_single_event_growth_policy_v1":
        value = provenance["single_event_policy"]
        kind, original_ref = POLICY_KIND, value.terms.policy_ref
        roots = value.source_refs
    elif primary.operation_kind == "prepare_single_event_growth_v1":
        value = provenance["single_event_input"]
        kind, original_ref, roots = INPUT_KIND, value.input_ref, value.source_refs
    elif primary.operation_kind=='review_single_event_growth_v1' and provenance['single_event_review_case'] is not None:
        value=provenance['single_event_review_case']
        if receipt.write_versions:
            raise ValueError('review case registration cannot change its pending obligation')
        if value.registration_operation_id!=primary.operation_id:
            from .d01_single_event_review_case_v1 import require_reused_single_event_case_after_cas_v1
            original=require_reused_single_event_case_after_cas_v1(db,value,frame=frame,receipt=receipt)
            from .d01_production_operations_v1 import TABLE,SIGN_KIND
            from ..runtime_contracts import canonical_serialize
            encoded=canonical_serialize(plain_v1(value))
            row=db.execute('SELECT producing_operation_id,payload_json,payload_digest,signature FROM '+TABLE
                +' WHERE bot=? AND persona=? AND original_ref=? AND kind=?',
                (*primary.namespace.as_tuple,value.case_ref,CASE_KIND)).fetchone()
            if row is None or row[:3]!=(value.registration_operation_id,encoded,original.original_digest):
                raise ValueError('reused Case differs from its actual first immutable signed original')
            readers.issuer._signer.verify(SIGN_KIND,encoded,row[3])
            return (original,)
        kind,original_ref,roots=CASE_KIND,value.case_ref,(*value.support_source_refs,*value.context_source_refs)
    else:
        return ()
    if type(value) is not ORIGINAL_TYPES[kind]:
        raise TypeError("single-event after-CAS recorder needs its actual typed verified provenance")
    from .d01_production_operations_v1 import TABLE, SIGN_KIND
    from ..runtime_contracts import canonical_serialize
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    encoded = canonical_serialize(plain_v1(value)); digest = canonical_digest(plain_v1(value))
    expected = (kind, primary.operation_id, encoded, digest, readers.issuer._signer.sign(SIGN_KIND, encoded),
        canonical_serialize(tuple(sorted(set(roots)))))
    row = db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature,source_refs_json FROM " + TABLE
        + " WHERE bot=? AND persona=? AND original_ref=?", (*primary.namespace.as_tuple, original_ref)).fetchone()
    if row is not None and tuple(row) != expected:
        raise ValueError("single-event policy/input original replay conflicts with its actual first producer")
    if row is None:
        db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?,?)", (*primary.namespace.as_tuple, original_ref, *expected))
    return (ProductionOriginalRefV1("d01." + kind, original_ref, digest, receipt.read_versions),)


def single_event_followup_plan_v1(db, *, namespace, event):
    from .domain_background_read_v3 import _active_v3
    owner=_active_v3(db)
    original = read_single_event_followup_cause_v1(db,namespace=namespace,event_kind=event.event_kind,
        causal_operation_id=event.causal_operation_id,original_ref=event.trigger_original.original_ref,
        issuer=owner.graph._GraphCoordinator__d11_issuer)
    if (original is None or event.event_kind != REVIEW_EVENT or event.receiver_domain != "d01"
            or (original["domain"], original["operation_kind"]) != ("d01", "adopt_single_event_growth_v1")
            or original["original_digest"] != event.trigger_original.original_digest):
        raise ValueError("single-event review event is not its exact actual same-CAS D01 adoption")
    adoption = decode_typed_production_value_v1(original["payload"]["provenance"]["single_event_adoption"], SingleEventGrowthAdoptionV1)
    return read_plan_single_event_growth_v1(db, namespace=namespace,
        operation_kind="read_single_event_growth_v1", request=ReadSingleEventGrowthRequestV1(
            single_event_adoption_key_v1(namespace, adoption.policy_ref).token))


def resolve_single_event_followup_v1(db, *, frame, event, original):
    from .domain_production_followups_v1 import DomainFollowupResolutionV1, DomainFollowupCommandV1
    read = CurrentDomainReadV1(frame); read.check(db)
    if (event.event_kind != REVIEW_EVENT or event.receiver_domain != "d01"
            or (original["domain"], original["operation_kind"]) != ("d01", "adopt_single_event_growth_v1")):
        raise ValueError("single-event consumer requires its original actual adoption event")
    adoption = decode_typed_production_value_v1(original["payload"]["provenance"]["single_event_adoption"], SingleEventGrowthAdoptionV1)
    key = AtomKey.from_token(adoption.review_ref)
    atom = read.head(db, key, required=True)
    review = decode_typed_production_value_v1(atom.value, _review_type_v1(key))
    if review.adoption_operation_id != event.causal_operation_id:
        raise ValueError("single-event review obligation belongs to another producer")
    continuation = "single-event-review:" + canonical_digest((event.dedupe_key, key.token))[:48]
    if actual_current_single_event_upper_utc_v1(db, frame) < adoption.review_not_before_utc:
        return DomainFollowupResolutionV1("waiting_for_original", (), (key.token,),
            ("single_event_original_review_not_before",), continuation)
    if review.disposition in {"qualified","opposed","expired"}:
        return DomainFollowupResolutionV1("growth_review_observed", (), (key.token,), ())
    if type(review)is not SingleEventGrowthReviewV2 or atom.revision!=1 or review.disposition!='pending':
        return DomainFollowupResolutionV1("waiting_for_original",(),(key.token,),
            ("actual_first_pending_single_event_review_v2",),continuation)
    owner=_actual_single_event_owner_v1(db,frame)
    require_single_event_background_source_permission_v1(owner)
    request = ReviewSingleEventGrowthRequestV1(single_event_adoption_key_v1(adoption.namespace, adoption.policy_ref).token,
        atom.revision,None)
    command = DomainFollowupCommandV1("d01", "review_single_event_growth_v1", request,
        original["receipt"].activity_id, frame.envelope.authority.audience[0], frame.envelope.authority.audience)
    return DomainFollowupResolutionV1("ready", (command,), (key.token,), ())


def read_plan_single_event_growth_v1(db, *, namespace, operation_kind, request, activity_id=None, issuer=None):
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..graph_types import AtomKey
    from .d01_general_growth_v1 import read_plan_adopt_current_general_growth_v1, AdoptCurrentGeneralGrowthRequestV1
    if operation_kind not in OPERATIONS or type(request) is not OPERATIONS[operation_kind][0] or not db.in_transaction:
        raise ValueError("single-event fixed read planner requires the registered exact operation and current Work")
    keys = [owner_grant_key(*namespace.as_tuple)]
    types = ["d01.persona_plan.v1", "d01.persona_activation.v1", "d01.persona_revision.v1",
        "d01.growth_contribution.v1", "d07.current_interpretation.v1"]
    roots, originals = [], []
    if issuer is None:
        from .current_method_learning_read_v3 import _method_active
        from .domain_background_read_v3 import _active_v3
        actual_owner = _method_active(db) or _active_v3(db)
        if actual_owner is None:
            raise ValueError("single-event metadata plan requires its actual installed Work")
        issuer = actual_owner.graph._GraphCoordinator__d11_issuer
    policy_raw = None
    input_raw = None
    growth = None
    general_ref = None
    qualified_ack=False
    if operation_kind == "register_single_event_growth_policy_v1":
        terms = request.terms
    else:
        if operation_kind == "prepare_single_event_growth_v1":
            policy_ref = request.policy_ref
            growth, general_ref = request.growth_request, request.general_growth_intent_ref
            keys.append(AtomKey.from_token(request.continuity_interpretation_ref))
            originals.append(request.continuity_interpretation_ref)
        elif operation_kind == "adopt_single_event_growth_v1":
            originals.append(request.input_ref)
            input_raw = _single_signed_metadata_v1(db, namespace, issuer, request.input_ref, INPUT_KIND, originals)
            if input_raw is None:
                raise MissingProductionOriginalV1("actual_single_event_input_for_read_plan")
            policy_ref = input_raw["policy_ref"]
            growth = AdoptCurrentGrowthRequestV1(input_raw["growth_proposal_ref"], input_raw["trigger_original_ref"],
                tuple(input_raw["trial_original_refs"]), input_raw["counterevidence_query_ref"])
            general_ref = input_raw["general_growth_intent_ref"]
            keys.append(AtomKey.from_token(input_raw["continuity_interpretation_ref"]))
            originals.append(input_raw["continuity_interpretation_ref"])
        else:
            key = AtomKey.from_token(request.adoption_ref)
            if key.type_name != ADOPTION_TYPE:
                raise ValueError("single-event read plan requires an actual adoption selector")
            keys.append(key)
            adoption = _single_graph_metadata_v1(db, namespace, key, "single_event_adoption", keys)
            if adoption is None:
                raise MissingProductionOriginalV1("actual_single_event_adoption_for_read_plan")
            review_key=AtomKey.from_token(adoption['review_ref'])
            keys.append(review_key)
            review_metadata=_single_graph_metadata_v1(db,namespace,review_key,_review_metadata_kind_v1(review_key),keys)
            roots.extend(review_metadata['source_refs'])
            policy_ref = adoption["policy_ref"]
            originals.append(adoption["input_ref"])
            input_raw = _single_signed_metadata_v1(db, namespace, issuer, adoption["input_ref"], INPUT_KIND, originals)
            if input_raw is None:
                raise MissingProductionOriginalV1("actual_single_event_adopted_input_for_read_plan")
            growth = AdoptCurrentGrowthRequestV1(input_raw["growth_proposal_ref"], input_raw["trigger_original_ref"],
                tuple(input_raw["trial_original_refs"]), input_raw["counterevidence_query_ref"])
            general_ref = input_raw["general_growth_intent_ref"]
            qualified_ack=(type(request)is ReviewSingleEventGrowthRequestV1
                and _single_event_qualified_review_metadata_v1(db,namespace,adoption))
            continuity_ref = request.continuity_interpretation_ref if type(request) is ReviewSingleEventGrowthRequestV1 else None
            if continuity_ref is not None and not qualified_ack:
                keys.append(AtomKey.from_token(continuity_ref)); originals.append(continuity_ref)
            roots.extend(input_raw["source_refs"])
            _single_review_metadata_plan_v1(db,namespace,adoption,input_raw,keys,roots,originals)
        originals.append(policy_ref)
        policy_raw = _single_signed_metadata_v1(db, namespace, issuer, policy_ref, POLICY_KIND, originals)
        if policy_raw is None:
            raise MissingProductionOriginalV1("actual_single_event_policy_for_read_plan")
        policy = decode_typed_production_value_v1(policy_raw, SingleEventGrowthPolicyV1)
        terms = policy.terms
    if terms.namespace != namespace:
        raise ValueError("single-event read selectors crossed namespace")
    keys.extend((terms.expected_persona_head.key, terms.event_source.key, terms.event_interpretation.key,
        single_event_adoption_key_v1(namespace, terms.policy_ref), single_event_review_key_v2(namespace, terms.policy_ref)))
    keys.extend(v.key for v in (*terms.scope_versions, *terms.exclusion_versions, *terms.required_outcome_versions))
    originals.extend(v.key.token for v in terms.required_outcome_versions)
    _scope_plan_source_roots_v1(db, namespace, (*terms.scope_versions, *terms.exclusion_versions,
        *terms.required_outcome_versions), keys, roots, originals)
    if operation_kind=='review_single_event_growth_v1' and not qualified_ack:
        from .d01_single_event_review_case_v1 import append_single_event_review_case_plan_v1
        append_single_event_review_case_plan_v1(db,namespace,terms,keys,roots,originals)
    roots.extend((terms.event_source.key.token, *terms.context_source_refs))
    originals.extend((terms.observer_policy_ref, terms.event_interpretation.key.token))
    if terms.plasticity_policy_ref is not None:
        originals.append(terms.plasticity_policy_ref)
    if growth is not None:
        if general_ref is not None:
            if issuer is None:
                from .current_method_learning_read_v3 import _method_active
                from .domain_background_read_v3 import _active_v3
                owner = _method_active(db) or _active_v3(db)
                if owner is None:
                    raise ValueError("single-event planner requires its actual installed signer")
                issuer = owner.graph._GraphCoordinator__d11_issuer
            nested = read_plan_adopt_current_general_growth_v1(db, namespace=namespace,
                request=AdoptCurrentGeneralGrowthRequestV1(general_ref, growth.growth_proposal_ref,
                    growth.trigger_original_ref, growth.trial_original_refs, growth.counterevidence_query_ref), issuer=issuer)
        else:
            _single_semantic_trial_read_plan_v1(db, namespace, issuer, growth, roots, keys, originals)
            nested = production_read_plan_v1((), (), (), ())
        keys.extend(nested.exact_keys); types.extend(nested.fixed_type_ids)
        roots.extend(nested.source_roots); originals.extend(nested.required_original_refs)
    from .domain_background_read_v3 import _active_v3
    background=_active_v3(db)
    qualified_metadata=None
    if background is None and qualified_ack:
        from .current_method_learning_read_v3 import _method_active
        from .role_control_lineage_metadata_v4 import prepare_current_qualified_single_event_review_metadata_v4
        qualified_metadata=prepare_current_qualified_single_event_review_metadata_v4(_method_active(db))
        if qualified_metadata is None:
            raise MissingProductionOriginalV1('actual_qualified_review_metadata_lineage')
    if (background is not None and single_event_metadata_work_v1(background)
            or qualified_metadata is not None
            or operation_kind in {'register_single_event_growth_policy_v1','read_single_event_growth_v1'}):
        if background is None and operation_kind in {'register_single_event_growth_policy_v1','read_single_event_growth_v1'}:
            current_single_event_policy_head_metadata_v1(db,namespace)
        from .persona_growth_review_metadata_v1 import growth_metadata_head_v1
        metadata_types=frozenset({'d01.persona_plan.v1','d01.persona_revision.v1','d01.growth_contribution.v1'})
        for key in keys:
            if key.type_name in metadata_types:growth_metadata_head_v1(db,namespace,key)
        keys=[key for key in keys if key.type_name not in metadata_types]
        types=[kind for kind in types if kind not in metadata_types]
    if (background is not None and operation_kind=='review_single_event_growth_v1'
            and background.entry is not None and background.entry[1:3]==('d01','single_event_review_cognition_adopted_v1')):
        case_plan=_single_event_background_source_plan_v1(background)
        keys.extend(case_plan.exact_keys);types.extend(case_plan.fixed_type_ids)
        roots.extend(case_plan.source_roots);originals.extend(case_plan.required_original_refs)
    if (background is None and operation_kind=='review_single_event_growth_v1'
            and request.continuity_interpretation_ref is not None and not qualified_ack):
        from .current_method_learning_read_v3 import _method_active
        from .d07_single_event_review_v1 import read_actual_single_event_review_interpretation_case_original_v1
        from .d01_single_event_review_case_v1 import read_plan_registered_single_event_review_case_v1
        case_original=read_actual_single_event_review_interpretation_case_original_v1(db,read=_method_active(db),
            interpretation_ref=request.continuity_interpretation_ref)
        case_plan=read_plan_registered_single_event_review_case_v1(db,namespace=namespace,case_original=case_original,issuer=issuer)
        keys.extend(case_plan.exact_keys);types.extend(case_plan.fixed_type_ids)
        roots.extend(case_plan.source_roots);originals.extend(case_plan.required_original_refs)
    return production_read_plan_v1(types, keys, roots, originals)


def single_event_metadata_type_v1(table, kind):
    from .d01_production_operations_v1 import GrowthIntentOriginalV2, GrowthTrialOriginalV2, IdentityTrialStartV3
    from ..domains.d01.identity_v3 import IdentityPlasticityPolicyV3, IdentityTrialObservationPolicyV3
    if table == "graph_d01_production_inputs_v1":
        return {**ORIGINAL_TYPES, "growth_proposal_v2": GrowthIntentOriginalV2,
            "growth_trial_v2": GrowthTrialOriginalV2, "identity_trial_start_v3": IdentityTrialStartV3,
            "identity_plasticity_policy_v3": IdentityPlasticityPolicyV3,
            "identity_trial_observation_policy_v3": IdentityTrialObservationPolicyV3}.get(kind)
    if table in {"graph_atoms", "graph_history"}:
        return {"single_event_adoption": SingleEventGrowthAdoptionV1,
            "single_event_review": SingleEventGrowthReviewV1,
            "single_event_review_v2":SingleEventGrowthReviewV2}.get(kind)
    return None


def single_event_metadata_paths_v1(table, kind, path):
    cls = single_event_metadata_type_v1(table, kind)
    if cls is None:
        return None
    if not path:
        return True
    from dataclasses import fields
    return path[0] in {f.name for f in fields(cls)} and path[0] not in {
        'replacement_claim','adopted_claim','post_adoption_evidence_values'}


def _single_signed_metadata_v1(db, namespace, issuer, original_ref, kind, originals):
    from .d01_general_growth_v1 import _general_plan_signed_metadata_v1
    from .d01_production_operations_v1 import TABLE
    value, original = _general_plan_signed_metadata_v1(db, namespace, issuer, TABLE, original_ref, kind, originals)
    return value


def _single_event_qualified_review_metadata_v1(db,namespace,adoption):
    key=AtomKey.from_token(adoption['review_ref'])
    metadata=_single_graph_metadata_v1(db,namespace,key,_review_metadata_kind_v1(key),[])
    value=decode_typed_production_value_v1(metadata,_review_type_v1(key))
    if value.adoption_operation_id!=adoption['adoption_operation_id']:
        raise ValueError('review metadata changed its actual same-CAS adoption')
    return type(value)is SingleEventGrowthReviewV2 and value.disposition=='qualified'


def _single_graph_metadata_v1(db, namespace, key, kind, keys):
    from .d01_general_growth_v1 import _general_plan_head_metadata_v1
    return _general_plan_head_metadata_v1(db, namespace, key, kind, keys).value


def _single_semantic_trial_read_plan_v1(db, namespace, issuer, growth, roots, keys, originals):
    from .d01_production_operations_v1 import TABLE
    from .d01_general_growth_v1 import (_general_plan_counter_metadata_v1, _general_plan_head_metadata_v1,
        _general_plan_life_readset_v1)
    from ..graph_types import AtomKey
    from .current_method_learning_read_v3 import read_bound_current_general_owner_type_metadata_v1
    from .persona_growth_review_metadata_v1 import growth_metadata_head_v1
    inventories = {}
    for type_id in ("d08.goal.v1", "d08.personal_plan.v1", "d08.action_intent.v1", "runtime.cost_settlement"):
        rows, complete = _single_type_metadata_v1(db, namespace, type_id)
        if not complete or len(rows) > 128:
            raise MissingProductionOriginalV1("single_event_complete_trial_metadata_inventory:" + type_id)
        inventories[type_id] = rows
        for row in rows:
            actual, valid = growth_metadata_head_v1(db, namespace, row.key)
            if actual.revision != row.revision or valid != bool(row.valid):
                raise MissingProductionOriginalV1("single_event_trial_metadata_head_changed")
    intent = _single_signed_metadata_v1(db, namespace, issuer, growth.growth_proposal_ref, "growth_proposal_v2", originals)
    counter = _single_signed_metadata_v1(db, namespace, issuer, growth.counterevidence_query_ref, "growth_counterevidence", originals)
    roots.extend((*intent["evidence_source_refs"], *counter["counterevidence_source_refs"]))
    originals.extend((intent["plasticity_policy_ref"], intent["observer_policy_ref"], intent["continuity_interpretation_ref"],
        growth.trigger_original_ref))
    keys.append(AtomKey.from_token(intent["continuity_interpretation_ref"]))
    for trial_ref in growth.trial_original_refs:
        trial = _single_signed_metadata_v1(db, namespace, issuer, trial_ref, "growth_trial_v2", originals)
        start = _single_signed_metadata_v1(db, namespace, issuer, trial["trial_start_ref"], "identity_trial_start_v3", originals)
        planned = AtomKey.from_token(start["planned_progress_ref"])
        keys.append(planned); roots.extend(trial["evidence_source_refs"])
        if planned.type_name == "d08.action_intent.v1":
            _scope_plan_source_roots_v1(db, namespace, (decode_typed_production_value_v1(
                start["planned_progress_head"], GraphVersion),), keys, roots, originals)
            selected = next((a for a in inventories["d08.action_intent.v1"] if a.key == planned and a.valid), None)
            if selected is None:raise MissingProductionOriginalV1("single_event_actual_planned_action_metadata")
            identity = selected.value["identity"]
            for cost in inventories["runtime.cost_settlement"]:
                if cost.valid and (cost.value["activity_id"], cost.value["effect_id"]) == (identity["activity_id"], identity["effect_id"]):
                    keys.append(cost.key); originals.append(cost.key.token)
        for outcome_ref in trial["settled_outcome_refs"]:
            kind = "life_progress" if AtomKey.from_token(outcome_ref).type_name == "d10.life_progress.v1" else "outcome"
            outcome = _general_plan_head_metadata_v1(db, namespace, outcome_ref, kind, keys)
            originals.append(outcome.key.token)
            roots.extend(outcome.value["source_refs"])
            if kind == "life_progress":
                _general_plan_life_readset_v1(db, namespace, outcome.key.token, planned.token, roots, keys, originals)
            else:
                originals.extend((*outcome.value["observation_refs"], *outcome.value["cost_refs"]))
    _general_plan_counter_metadata_v1(db, namespace, "d01.growth:" + intent["target_block"] + ":core", roots, keys, originals)


def committed_single_event_growth_view_v1(stage, receipt):
    """Metadata projection of this actual stage/receipt; no claim or Source Body."""
    import json
    if (stage.domain != "d01" or stage.operation_kind not in OPERATIONS or stage.coverage != "complete"
            or receipt.status != "committed" or receipt.operation_id != stage.operation_id):
        return None
    raw = json.loads(stage.original_payload_json)["provenance"]
    policy = decode_typed_production_value_v1(raw["single_event_policy"], SingleEventGrowthPolicyV1) if "single_event_policy" in raw else None
    value = decode_typed_production_value_v1(raw["single_event_input"], SingleEventGrowthInputV1) if "single_event_input" in raw else None
    adoption = decode_typed_production_value_v1(raw["single_event_adoption"], SingleEventGrowthAdoptionV1) if "single_event_adoption" in raw else None
    review_raw=raw.get('single_event_review')
    review_cls=SingleEventGrowthReviewV2 if review_raw is not None and review_raw['schema']=='d01.single-event-growth-review.v2' else SingleEventGrowthReviewV1
    review=decode_typed_production_value_v1(review_raw,review_cls) if review_raw is not None else None
    policy_ref = policy.terms.policy_ref if policy is not None else value.policy_ref if value is not None else adoption.policy_ref
    adoption_key = single_event_adoption_key_v1(stage.namespace, policy_ref)
    review_key = AtomKey.from_token(adoption.review_ref) if adoption is not None else single_event_review_key_v2(stage.namespace,policy_ref)
    versions = {v.key: v.revision for v in (*receipt.read_versions, *receipt.write_versions)}
    if adoption is not None and (adoption_key not in versions or review_key not in versions):
        raise ValueError("single-event metadata view lacks its actual target/obligation receipt versions")
    return {"schema": "d01.single-event-growth-view.v1", "operation_kind": stage.operation_kind,
        "operation_id": receipt.operation_id, "policy_ref": policy_ref,
        "policy_digest": canonical_digest(plain_v1(policy)) if policy is not None else value.policy_digest if value is not None else adoption.policy_digest,
        "input_ref": value.input_ref if value is not None else adoption.input_ref if adoption is not None else None,
        "input_digest": canonical_digest(plain_v1(value)) if value is not None else adoption.input_digest if adoption is not None else None,
        "adoption_ref": adoption_key.token if adoption is not None else None,
        "adoption_revision": versions.get(adoption_key) if adoption is not None else None,
        "review_ref": review_key.token if review is not None else None,
        "review_revision": versions.get(review_key) if review is not None else None,
        "disposition": review.disposition if review is not None else None,
        "target_block": policy.terms.target_block if policy is not None else adoption.target_block if adoption is not None else None,
        "adopted_claim_digest": adoption.adopted_claim_digest if adoption is not None else None,
        "review_not_before_utc": policy.terms.review_not_before_utc if policy is not None else adoption.review_not_before_utc if adoption is not None else None,
        "review_due_utc": policy.terms.review_due_utc if policy is not None else adoption.review_due_utc if adoption is not None else None,
        "readout_valid_until_utc": policy.terms.readout_valid_until_utc if policy is not None else adoption.readout_valid_until_utc if adoption is not None else None,
        "missing_conditions": list(review.missing_conditions) if review is not None else []}


def _scope_commitment_v1(db, read, version):
    """Bind the sealed header and exact target value after this Work has Source ALL."""
    from .persona_growth_review_metadata_v1 import growth_target_control_v1
    from ..runtime_storage_v3 import runtime_storage_quantum_v3, begin_runtime_cell_read_v3
    ns = read.frame.envelope.authority.namespace
    control = growth_target_control_v1(db, version)
    with runtime_storage_quantum_v3(db) as meter:
        row = meter.read_fixed_row(db, "graph_atoms", ("revision", "valid", "value_cell_id"),
            "token=? AND bot=? AND persona=?", (version.key.token, *ns.as_tuple))
        if row is None or row[:2] != (version.revision, 1) or row[2] is None:
            raise MissingProductionOriginalV1("single_event_actual_scope_sealed_origin_metadata")
        cell = begin_runtime_cell_read_v3(db, row[2], erasure_owner_ref=version.key.token)
        header = cell.header
    if header[2] != control["receipt"].operation_id:
        raise MissingProductionOriginalV1("single_event_scope_header_same_producer_receipt")
    return SingleEventScopeCommitmentV1(version, row[2], header[0], header[5],
        canonical_digest(read.head(db,version.key,required=True).value),header[3],header[2])


def _scope_plan_source_roots_v1(db, namespace, versions, keys, roots, originals):
    from .persona_growth_review_metadata_v1 import growth_metadata_head_v1, growth_target_control_v1
    for version in versions:
        current, valid = growth_metadata_head_v1(db, namespace, version.key)
        if not valid or current != version:
            raise MissingProductionOriginalV1("single_event_exact_scope_or_outcome_metadata_head")
        original = growth_target_control_v1(db, version)
        keys.append(version.key)
        roots.extend(v.key.token for v in original["read_versions"] if v.key.type_name == "memory.source" and v.revision > 0)
        originals.append(original["receipt"].operation_id)


def _actual_source_plan_roots_v1(db):
    from .current_method_learning_read_v3 import _method_active, require_actual_method_learning_attachment_owner_v3
    owner = _method_active(db)
    require_actual_method_learning_attachment_owner_v3(owner, db=db)
    if owner.operation_kind not in OPERATIONS or owner.selected_plan is None or owner.general_source_permission is None:
        raise ValueError("single-event signed policy requires its actual completed Source plan")
    from .current_full_persona_writer_v1 import current_full_persona_writer_base_source_roots_v1
    roots=current_full_persona_writer_base_source_roots_v1(owner)
    if roots is None:roots=tuple(owner.selected_plan.source_roots)
    owner.general_source_permission.require_for_v1(owner,roots)
    return roots


_FACT_READS = WeakKeyDictionary()


class _SingleEventFactReadV1:
    pass


def _issue_single_event_fact_read_v1(db, read, readers, policy, value):
    raw, original = readers._read(db, read, value.input_ref, INPUT_KIND)
    if decode_typed_production_value_v1(raw, SingleEventGrowthInputV1) != value:
        raise ValueError("single-event trial fact reader changed its actual signed input")
    raw, original = readers._read(db, read, value.policy_ref, POLICY_KIND)
    if (decode_typed_production_value_v1(raw, SingleEventGrowthPolicyV1) != policy
            or original.original_digest != value.policy_digest):
        raise ValueError("single-event trial fact reader changed its actual signed policy")
    owner = _actual_single_event_owner_v1(db, read.frame)
    from .current_method_learning_read_v3 import _MethodLearningReadV3
    if type(owner) is _MethodLearningReadV3:
        _actual_source_plan_roots_v1(db)
    else:
        from .domain_background_read_v3 import require_current_general_growth_trial_metadata_reader_v1
        require_current_general_growth_trial_metadata_reader_v1(owner)
        require_single_event_background_source_permission_v1(owner)
    proof = _SingleEventFactReadV1()
    _FACT_READS[proof] = (db, read.frame, ref(owner))
    return proof


def require_single_event_metadata_read_v1(proof, *, db, frame):
    entry = _QUALIFICATIONS.get(proof)
    issued = _FACT_READS.get(proof) if entry is None else entry[:3]
    if issued is None or issued[0] is not db or issued[1] is not frame:
        raise ValueError("single-event trial metadata requires its actual same-frame private read")
    owner = issued[2]()
    if _actual_single_event_owner_v1(db, frame) is not owner:
        raise ValueError("single-event trial metadata left its actual operation")
    return owner


def single_event_trial_metadata_rows_v1(db, read, proof, type_id):
    require_single_event_metadata_read_v1(proof, db=db, frame=read.frame)
    from .current_method_learning_read_v3 import read_bound_current_general_owner_type_metadata_v1
    rows, complete = _single_type_metadata_v1(db, read.frame.envelope.authority.namespace, type_id)
    if not complete or len(rows) > read.frame.limits.max_query_rows:
        raise MissingProductionOriginalV1("single_event_complete_trial_metadata_inventory:" + type_id)
    return rows


def single_event_trial_scope_v1(db, read, planned, policy, proof):
    lineage = {planned.key.token}
    if planned.key.type_name == "d08.action_intent.v1":
        goals = tuple(a for a in single_event_trial_metadata_rows_v1(db, read, proof, "d08.goal.v1")
            if a.valid and a.key.name == planned.value["goal_ref"])
        if len(goals) != 1:
            raise MissingProductionOriginalV1("single_event_exact_trial_goal_metadata_lineage")
        lineage.add(goals[0].key.token)
        plans = single_event_trial_metadata_rows_v1(db, read, proof, "d08.personal_plan.v1")
        lineage.update(a.key.token for a in plans if a.valid and a.value["goal_ref"] == goals[0].key.token)
    if not lineage.intersection(policy.scope_refs) or lineage.intersection(policy.exclusion_refs):
        raise ValueError("actual single-event trial lies outside the unchanged installed semantic policy")
    return lineage


def single_event_trial_actions_v1(db, read, outcome, proof):
    rows = single_event_trial_metadata_rows_v1(db, read, proof, "d08.action_intent.v1")
    selected = tuple(a for a in rows if a.valid and a.value["action_id"] == outcome.action_id
        and a.value["identity"]["effect_id"] == outcome.effect_id
        and a.value["identity"]["attempt_id"] == outcome.attempt_id)
    return tuple(read.head(db, a.key, required=True) for a in selected) if len(selected) == 1 else ()


def single_event_trial_costs_v1(db, read, action, outcome, proof):
    rows = single_event_trial_metadata_rows_v1(db, read, proof, "runtime.cost_settlement")
    return tuple(read.head(db, a.key, required=True) for a in rows if a.valid
        and a.value["activity_id"] == action.identity.activity_id and a.value["effect_id"] == outcome.effect_id)


def single_event_metadata_work_v1(owner):
    from .current_method_learning_read_v3 import _MethodLearningReadV3, require_actual_method_learning_attachment_owner_v3
    if type(owner) is _MethodLearningReadV3:
        require_actual_method_learning_attachment_owner_v3(owner, db=owner.db)
        return owner.operation_kind in OPERATIONS
    from .domain_background_read_v3 import (BackgroundReadWorkV3, require_actual_background_attachment_owner_v3,
        require_background_followup_handoff_v3)
    if type(owner) is BackgroundReadWorkV3:
        require_actual_background_attachment_owner_v3(owner, db=owner.db)
        if owner.kind == "followup":
            return owner.entry is not None and owner.entry[1:3] == ("d01", REVIEW_EVENT)
        if owner.kind != "followup_child":return False
        handoff = require_background_followup_handoff_v3(owner.handoff, owner.graph, owner.bundle)
        return handoff.command.operation_kind == "review_single_event_growth_v1"
    return False


def require_single_event_review_target_metadata_work_v1(owner):
    from .domain_background_read_v3 import (BackgroundReadWorkV3,
        require_actual_background_attachment_owner_v3,require_background_followup_handoff_v3)
    if type(owner) is not BackgroundReadWorkV3:
        raise TypeError('review target metadata needs its actual Background child Work')
    require_actual_background_attachment_owner_v3(owner,db=owner.db)
    if owner.kind!='followup_child':
        raise ValueError('review target metadata is not an actual retained followup child')
    handoff=require_background_followup_handoff_v3(owner.handoff,owner.graph,owner.bundle)
    command=handoff.command
    if (command.operation_kind!='review_single_event_growth_v1'
            or type(command.request) is not ReviewSingleEventGrowthRequestV1
            or owner.read_scope is None or owner.read_scope.operation!='read'
            or owner.read_scope.namespace!=owner.namespace or owner.authority.purpose!='consolidation'):
        raise ValueError('review target metadata left its exact typed reviewer, original READ or actual scope')
    return owner


def _single_type_metadata_v1(db, namespace, type_id):
    from .domain_background_read_v3 import _active_v3, read_bound_background_general_growth_type_metadata_v1
    owner = _active_v3(db)
    if owner is not None:
        if not single_event_metadata_work_v1(owner):
            raise ValueError("single-event background metadata has another actual consumer")
        handled, result = read_bound_background_general_growth_type_metadata_v1(db,
            namespace=namespace, type_id=type_id, limit=129)
        if not handled:raise ValueError("single-event background metadata binding is unavailable")
        return result
    from .current_method_learning_read_v3 import read_bound_current_general_owner_type_metadata_v1
    return read_bound_current_general_owner_type_metadata_v1(db, namespace=namespace, type_id=type_id, limit=129)


def single_event_semantic_trial_start_v1(readers, db, read, proposal_ref, completed_ref, proof):
    require_single_event_metadata_read_v1(proof, db=db, frame=read.frame)
    trial, _ = readers._read(db, read, completed_ref, "growth_trial")
    start_ref = trial["trial_start_ref"]
    start, original = readers._read(db, read, start_ref, "identity_trial_start_v3")
    if start["growth_proposal_ref"] != proposal_ref or start["completed_trial_ref"] != completed_ref:
        raise ValueError("single-event trial has another exact registered start/proposal")
    return start_ref, start, original


def _actual_single_event_owner_v1(db, frame):
    from .current_method_learning_read_v3 import _method_active, require_actual_method_learning_attachment_owner_v3
    owner = _method_active(db)
    if owner is not None:
        require_actual_method_learning_attachment_owner_v3(owner, db=db)
        if owner.operation_kind not in OPERATIONS:
            raise ValueError("single-event metadata has another actual Method command")
    else:
        from .domain_background_read_v3 import _active_v3, require_actual_background_attachment_owner_v3
        owner = _active_v3(db)
        require_actual_background_attachment_owner_v3(owner, db=db)
        if not single_event_metadata_work_v1(owner):
            raise ValueError("single-event metadata has another actual background command")
    from .current_method_learning_read_v3 import _MethodLearningReadV3
    if type(owner) is _MethodLearningReadV3 and owner.operation.operation_id != frame.envelope.identity.operation_id:
        raise ValueError("single-event metadata left its actual frame operation")
    if owner.namespace != frame.envelope.authority.namespace or owner.authority != frame.envelope.authority:
        raise ValueError("single-event metadata changed its actual namespace/authority")
    owner.work._require_invocation(owner.graph)
    return owner


def actual_current_single_event_upper_utc_v1(db, frame):
    owner = _actual_single_event_owner_v1(db, frame)
    from .current_method_learning_read_v3 import _MethodLearningReadV3, actual_current_method_upper_utc_v1
    if type(owner) is _MethodLearningReadV3:
        return actual_current_method_upper_utc_v1(owner)
    from ..host.v2_fence_port import VerifiedIngressClockV2
    from .first_ingress_v2 import trusted_upper
    if type(owner.initial_clock) is not VerifiedIngressClockV2:
        raise ValueError("actual background paired ClockReading is required")
    now = trusted_upper(owner.initial_clock)
    if now >= owner.operation.deadline_utc:
        raise ValueError("single-event background exceeded its original deadline")
    return now


def single_event_qualification_now_v1(proof, *, db, frame):
    require_single_event_metadata_read_v1(proof, db=db, frame=frame)
    return actual_current_single_event_upper_utc_v1(db, frame)


_SINGLE_EVENT_CAUSES_V1 = WeakKeyDictionary()


def single_event_cause_locator_path_v1(owner, column, path):
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    if type(owner) is not BackgroundReadWorkV3:return None
    require_actual_background_attachment_owner_v3(owner, db=owner.db)
    task=owner.entry_column
    if (task is None or task.column is not column or task.entry is None
            or task.entry[1:3] != ("d01", REVIEW_EVENT)):
        return None
    if task.metadata[:2] != ("d01", "adopt_single_event_growth_v1"):
        raise ValueError("single-event review locator has another actual producer")
    if not path:return True
    if path[0] in {"schema","namespace","identity","authority","parent_budget","now_utc"}:return True
    return path[0]=="provenance" and (len(path)==1 or path[1] in {"single_event_adoption","single_event_review"})


def read_single_event_followup_cause_v1(db, *, namespace, event_kind, causal_operation_id, original_ref, issuer):
    if event_kind != REVIEW_EVENT:return None
    from .domain_background_read_v3 import (_active_v3,require_actual_background_attachment_owner_v3,
        background_point_v3,background_json_loads_v3,background_json_matches_v3,background_typed_original_digest_v3)
    from .domain_production_originals_v1 import TABLE,_receipt
    from ..runtime_contracts import canonical_serialize
    owner=_active_v3(db)
    require_actual_background_attachment_owner_v3(owner,db=db)
    if (namespace!=owner.namespace or issuer is not owner.graph._GraphCoordinator__d11_issuer
            or owner.entry is None or owner.entry[:3]!=(causal_operation_id,"d01",REVIEW_EVENT)):
        raise ValueError("single-event causal metadata requires its actual outbox Work")
    task=owner.entry_column
    if task is None or not task.complete or task.column.sha256!=task.metadata[2]:
        raise ValueError("single-event causal metadata lacks its own complete raw canonical EOF")
    metadata,payload=owner.entry_metadata
    if (metadata[:2]!=("d01","adopt_single_event_growth_v1")
            or payload.get("schema")!="d01.current-adopt_single_event_growth_v1.v1"
            or payload["identity"]["operation_id"]!=causal_operation_id
            or original_ref!="d01-current:"+metadata[2][:48]
            or owner.entry[4]!=metadata[2]):
        raise ValueError("single-event causal metadata changed its exact producer/ref/digest")
    row=background_point_v3(db,table=TABLE,
        columns=("domain","operation_kind","request_digest","original_digest","read_versions_json","bundle_digest","receipt_json","receipt_digest"),
        key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple,causal_operation_id),
        legacy_reader=lambda:None)
    if row is None or row[:2]!=metadata[:2] or row[3]!=metadata[2]:
        raise ValueError("single-event causal original metadata changed")
    reads_raw,receipt_raw=background_json_loads_v3(row[4]),background_json_loads_v3(row[6])
    reads=tuple(GraphVersion(AtomKey.from_token(token),revision)for token,revision in reads_raw)
    receipt=_receipt(receipt_raw)
    actual=background_point_v3(db,table="graph_bundle_operations",columns=("digest","activity_id","effect_id","commit_seq"),
        key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple,causal_operation_id),legacy_reader=lambda:None)
    if (not background_json_matches_v3(row[4],reads_raw) or not background_json_matches_v3(row[6],receipt_raw)
            or background_typed_original_digest_v3(db,row[6],receipt)!=row[7]
            or receipt.operation_id!=causal_operation_id or receipt.operation_digest!=row[5]
            or actual!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)
            or len(reads)>1024 or any(NamespaceId.from_key(v.key)!=namespace for v in reads)
            or tuple(receipt.read_versions)!=reads):
        raise ValueError("single-event causal metadata lost its actual complete W01 receipt/readset")
    adoption=decode_typed_production_value_v1(payload["provenance"]["single_event_adoption"],SingleEventGrowthAdoptionV1)
    obligation=decode_typed_production_value_v1(payload["provenance"]["single_event_review"],_review_type_v1(AtomKey.from_token(adoption.review_ref)))
    adoption_key=single_event_adoption_key_v1(namespace,adoption.policy_ref)
    review_key=AtomKey.from_token(adoption.review_ref)
    if (adoption.adoption_operation_id!=causal_operation_id or adoption.review_ref!=review_key.token
            or obligation.adoption_ref!=adoption_key.token or obligation.adoption_operation_id!=causal_operation_id
            or obligation.disposition!="pending" or obligation.reviewed_at_utc is not None
            or any(GraphVersion(key,0) not in reads or GraphVersion(key,1) not in receipt.write_versions
                for key in (adoption_key,review_key))):
        raise ValueError("single-event obligation is not the exact same-CAS birth of its actual adoption")
    original={"domain":row[0],"operation_kind":row[1],"request_digest":row[2],"original_digest":row[3],
        "read_versions":reads,"receipt":receipt,"payload":payload}
    _SINGLE_EVENT_CAUSES_V1[owner]=(original,task,owner.operation,owner.graph_stamp)
    return original



_SINGLE_EVENT_COMPLETION_SOURCE_CAUSES_V1=WeakKeyDictionary()


def _require_single_event_completion_source_cause_v1(owner):
    saved=_SINGLE_EVENT_COMPLETION_SOURCE_CAUSES_V1.get(owner)
    if saved is None:return None
    fact,column,operation,stamp,handoff,case_original=saved
    if (column is not owner.entry_column or operation is not owner.operation or stamp!=owner.graph_stamp
            or handoff is not owner.handoff or fact.value.case_original!=case_original):
        raise ValueError('single-event final Source cause changed its actual Background child identity')
    fact.require_current_v1(owner)
    return fact


def _single_event_background_source_plan_v1(owner):
    cause=_SINGLE_EVENT_CAUSES_V1.get(owner)
    if cause is not None:
        if cause[1]is not owner.entry_column or cause[2:]!=(owner.operation,owner.graph_stamp):
            raise ValueError('single-event Source plan changed its actual adoption metadata cause')
        adoption=decode_typed_production_value_v1(cause[0]['payload']['provenance']['single_event_adoption'],SingleEventGrowthAdoptionV1)
        if owner.kind=='followup_child':
            from .domain_background_read_v3 import require_background_followup_handoff_v3
            command=require_background_followup_handoff_v3(owner.handoff,owner.graph,owner.bundle).command
            if command.operation_kind!='review_single_event_growth_v1' or type(command.request)is not ReviewSingleEventGrowthRequestV1:
                raise ValueError('single-event Case Source plan changed its actual typed review child')
            return read_plan_single_event_growth_v1(owner.db,namespace=owner.namespace,
                operation_kind=command.operation_kind,request=command.request,issuer=owner.graph._GraphCoordinator__d11_issuer)
        return read_plan_single_event_growth_v1(owner.db,namespace=owner.namespace,
            operation_kind='read_single_event_growth_v1',request=ReadSingleEventGrowthRequestV1(
                single_event_adoption_key_v1(owner.namespace,adoption.policy_ref).token),
            issuer=owner.graph._GraphCoordinator__d11_issuer)
    from .d07_single_event_review_v1 import read_single_event_review_completion_followup_cause_v1
    from .domain_background_read_v3 import require_background_followup_handoff_v3
    from .single_event_review_target_v1 import prepare_current_single_event_review_target_metadata_v1
    from .d01_single_event_review_case_v1 import (read_registered_single_event_review_case_metadata_v1,
        read_plan_registered_single_event_review_case_v1)
    if (owner.kind!='followup_child' or owner.entry is None
            or owner.entry[1:3]!=('d01','single_event_review_cognition_adopted_v1')):
        raise ValueError('single-event Source plan lacks its actual adoption or paid completion metadata')
    command=require_background_followup_handoff_v3(owner.handoff,owner.graph,owner.bundle).command
    if command.operation_kind!='review_single_event_growth_v1' or type(command.request)is not ReviewSingleEventGrowthRequestV1:
        raise ValueError('single-event final Source cause has another actual typed child')
    cause=read_single_event_review_completion_followup_cause_v1(owner.db,namespace=owner.namespace,
        event_kind=owner.entry[2],causal_operation_id=owner.entry[0],original_ref=owner.entry[3],
        issuer=owner.graph._GraphCoordinator__d11_issuer)
    if cause is None:raise ValueError('single-event final Source cause has no authenticated paid completion')
    fact=cause['single_event_review_completion'];fact.require_current_v1(owner);value=fact.value
    target=prepare_current_single_event_review_target_metadata_v1(owner)
    request=command.request
    if (value.adoption_version!=target.adoption_version or value.review_version.key.token!=target.adoption.review_ref
            or request.adoption_ref!=value.adoption_version.key.token
            or request.expected_review_revision!=value.review_version.revision
            or request.continuity_interpretation_ref!=value.interpretation_version.key.token):
        raise ValueError('single-event final Source cause changed its actual adoption/review/interpretation selection')
    from .d07_single_event_review_v1 import prepare_current_single_event_review_interpretation_metadata_v1
    dependency=prepare_current_single_event_review_interpretation_metadata_v1(owner.db,reader=owner,
        interpretation_ref=value.interpretation_version.key.token)
    if dependency.result!=value.case_original:
        raise ValueError('final review immutable receipt metadata selected another signed Case')
    metadata,original=read_registered_single_event_review_case_metadata_v1(owner.db,namespace=owner.namespace,
        case_original=value.case_original,issuer=owner.graph._GraphCoordinator__d11_issuer)
    if (original!=value.case_original
            or decode_typed_production_value_v1(metadata['adoption_version'],GraphVersion)!=value.adoption_version
            or decode_typed_production_value_v1(metadata['review_version'],GraphVersion)!=value.review_version):
        raise ValueError('single-event final Source cause differs from the independent signed Case metadata')
    _SINGLE_EVENT_COMPLETION_SOURCE_CAUSES_V1[owner]=(fact,owner.entry_column,owner.operation,owner.graph_stamp,
        owner.handoff,original)
    return read_plan_registered_single_event_review_case_v1(owner.db,namespace=owner.namespace,
        case_original=original,issuer=owner.graph._GraphCoordinator__d11_issuer)

_SINGLE_EVENT_SOURCE_TASKS_V1=WeakKeyDictionary()
_SINGLE_EVENT_SOURCE_PERMISSIONS_V1=WeakKeyDictionary()


class _SingleEventBackgroundSourceMetadataV1:
    def __init__(self,owner,token):
        from .domain_background_read_v3 import require_current_general_growth_trial_metadata_reader_v1
        from .source_inspection_metadata_read_v3 import InspectionMetadataReadV3
        require_current_general_growth_trial_metadata_reader_v1(owner)
        if not single_event_metadata_work_v1(owner):raise ValueError("single-event Source task has another actual consumer")
        self.owner=ref(owner);self.key=AtomKey.from_token(token)
        self.inspection=InspectionMetadataReadV3(owner,self.key)
        self.complete=False;self.metadata=self.header=None
    def advance(self,meter):
        owner=self.owner();owner.require_data_current_v3(meter)
        if not self.inspection.advance(meter):return False
        original=self.inspection.result.require_v3(owner,meter)
        self.metadata=original.metadata;self.header=(original.revision,int(original.valid),original.cell_id)
        self.complete=True;return True
    def require_v1(self,owner,meter):
        if self.owner() is not owner or _SINGLE_EVENT_SOURCE_TASKS_V1.get(owner,{}).get(self.key.token)is not self or not self.complete:
            raise ValueError("single-event Source metadata is not the actual Work's EOF")
        owner.require_data_current_v3(meter);self.inspection.result.require_v3(owner,meter)
        return self
    @property
    def revision(self):return self.header[0]
    @property
    def valid(self):return bool(self.header[1])


def start_single_event_background_source_metadata_v1(owner,token):
    from .domain_background_read_v3 import require_current_general_growth_trial_metadata_reader_v1
    require_current_general_growth_trial_metadata_reader_v1(owner)
    tasks=_SINGLE_EVENT_SOURCE_TASKS_V1.setdefault(owner,{})
    task=tasks.get(token)
    if task is None:task=_SingleEventBackgroundSourceMetadataV1(owner,token);tasks[token]=task
    return task


class _SingleEventBackgroundSourcePermissionV1:
    def __init__(self,owner,plan,records,versions):
        self.owner=ref(owner);self.plan=plan;self.refs=tuple(sorted(records));self.versions=tuple(versions)
        self.operation,self.stamp,self.scope,self.guard=owner.operation,owner.graph_stamp,owner.read_scope,owner.owner_guard
        _SINGLE_EVENT_SOURCE_PERMISSIONS_V1[owner]=self
    def require_v1(self,owner):
        from .domain_background_read_v3 import require_current_general_growth_trial_metadata_reader_v1
        from ..runtime_storage_v3 import runtime_storage_quantum_v3
        require_current_general_growth_trial_metadata_reader_v1(owner)
        _require_single_event_completion_source_cause_v1(owner)
        if (_SINGLE_EVENT_SOURCE_PERMISSIONS_V1.get(owner)is not self or self.owner()is not owner
                or (self.operation,self.stamp,self.scope,self.guard)!=(owner.operation,owner.graph_stamp,owner.read_scope,owner.owner_guard)):
            raise ValueError("single-event Source ALL proof left its actual Owner/read scope/stamp")
        with runtime_storage_quantum_v3(owner.db)as meter:
            owner.require_data_current_v3(meter)
            for token in self.refs:_SINGLE_EVENT_SOURCE_TASKS_V1[owner][token].require_v1(owner,meter)
            for version in self.versions:
                row=meter.read_fixed_row(owner.db,"graph_atoms",("revision",),
                    "token=? AND bot=? AND persona=?",(version.key.token,*owner.namespace.as_tuple))
                if (0 if row is None else row[0])!=version.revision:
                    raise ValueError("single-event Source/Access/correction current version changed")
        return self


def require_single_event_background_source_permission_v1(owner):
    from .domain_background_read_v3 import (require_current_general_growth_trial_metadata_reader_v1,
        BackgroundReadNeededV3,background_graph_head_v3,background_json_loads_v3)
    from .current_method_learning_read_v3 import _traverse_current_source_metadata_roots_v1
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    require_current_general_growth_trial_metadata_reader_v1(owner)
    if not single_event_metadata_work_v1(owner) or owner.authority.purpose!="consolidation":
        raise ValueError("single-event Source ALL requires its independent actual consolidation review")
    proof=_SINGLE_EVENT_SOURCE_PERMISSIONS_V1.get(owner)
    if proof is not None:return proof.require_v1(owner)
    plan=_single_event_background_source_plan_v1(owner)
    def leaf(token):
        task=_SINGLE_EVENT_SOURCE_TASKS_V1.get(owner,{}).get(token)
        if task is None or not task.complete:
            if owner.sealed:raise ValueError("single-event Source EOF was not prepared before actual WRITE")
            raise BackgroundReadNeededV3(("single_event_source_metadata",token))
        with runtime_storage_quantum_v3(owner.db)as meter:task.require_v1(owner,meter)
        return task
    def head(key):
        row=background_graph_head_v3(owner.db,owner.namespace,key)
        return GraphAtom(key,0,None,False)if row is None else GraphAtom(key,row[0],background_json_loads_v3(row[1]),bool(row[2]))
    records,versions=_traverse_current_source_metadata_roots_v1(owner,plan.source_roots,("consolidation",),
        metadata_leaf=leaf,graph_head=head)
    proof=_SingleEventBackgroundSourcePermissionV1(owner,plan,records,
        tuple(sorted(versions.values(),key=lambda v:v.key.token)))
    return proof.require_v1(owner)


def require_single_event_background_body_v1(owner,table,key,*,column):
    from .d01_single_event_review_case_v1 import case_original_metadata_column_allowed_v1
    if case_original_metadata_column_allowed_v1(owner,table,key,column):return
    if not single_event_metadata_work_v1(owner):return
    if table in {'graph_atoms','graph_history'} and column=='value' and AtomKey.from_token(key[0]).type_name=='d01.persona_plan.v1':
        raise ValueError('actual single-event reviewer must use its selected target claim, not whole PersonaPlan Body')
    # Immutable causal receipts/readsets and current Access are fixed metadata.
    if column in {"read_versions_json","receipt_json"}:return
    if table=="graph_atoms" and column=="value" and AtomKey.from_token(key[0]).type_name in {"memory.access","d06.source_correction_head.v1"}:return
    proof=require_single_event_background_source_permission_v1(owner)
    if table in {"graph_atoms","graph_history"} and column=="value":
        token=key[0]
        if AtomKey.from_token(token).type_name=="memory.source" and token not in proof.refs:
            raise ValueError("single-event Source Body is outside the actual ALL closure")


def single_event_background_source_original_v1(owner,token,meter):
    proof=_SINGLE_EVENT_SOURCE_PERMISSIONS_V1.get(owner)
    if proof is None or token not in proof.require_v1(owner).refs:
        raise ValueError("single-event Source Body lacks its independent actual ALL proof")
    leaf=_SINGLE_EVENT_SOURCE_TASKS_V1[owner][token].require_v1(owner,meter)
    return leaf.inspection.result


def release_single_event_background_metadata_v1(owner):
    from .d01_single_event_review_case_v1 import release_current_single_event_review_case_v1
    release_current_single_event_review_case_v1(owner)
    _SINGLE_EVENT_COMPLETION_SOURCE_CAUSES_V1.pop(owner,None)
    _SINGLE_EVENT_SOURCE_PERMISSIONS_V1.pop(owner,None);_SINGLE_EVENT_CAUSES_V1.pop(owner,None)
    _SINGLE_EVENT_SOURCE_TASKS_V1.pop(owner,None)



def _single_review_metadata_plan_v1(db,namespace,adoption,input_value,keys,roots,originals):
    from .persona_growth_review_metadata_v1 import growth_metadata_head_v1
    rows,complete=_single_type_metadata_v1(db,namespace,"d07.current_interpretation.v1")
    if not complete or len(rows)>128:
        raise MissingProductionOriginalV1("single_event_complete_review_continuity_inventory")
    actual=decode_typed_production_value_v1(adoption,SingleEventGrowthAdoptionV1)
    question=single_event_review_question_v1(actual,actual.input_digest)
    for metadata in rows:
        version,valid=growth_metadata_head_v1(db,namespace,metadata.key)
        if version.revision!=metadata.revision or valid!=metadata.valid:
            raise MissingProductionOriginalV1("single_event_review_continuity_metadata_head_changed")
        if metadata.valid and metadata.value["question_key"]==question and metadata.value["current"] is True:
            keys.append(metadata.key);roots.extend(metadata.value["source_refs"]);originals.append(metadata.key.token)


def current_single_event_followup_wake_v1(db,*,namespace,event):
    """A timer selector from this actual metadata Work; it never extends authorization."""
    from .domain_background_read_v3 import _active_v3,require_current_general_growth_trial_metadata_reader_v1
    from ..host.v2_fence_port import VerifiedIngressClockV2
    from .first_ingress_v2 import trusted_upper
    owner=_active_v3(db);require_current_general_growth_trial_metadata_reader_v1(owner)
    cause=read_single_event_followup_cause_v1(db,namespace=namespace,event_kind=event.event_kind,
        causal_operation_id=event.causal_operation_id,original_ref=event.trigger_original.original_ref,
        issuer=owner.graph._GraphCoordinator__d11_issuer)
    adoption=decode_typed_production_value_v1(cause["payload"]["provenance"]["single_event_adoption"],SingleEventGrowthAdoptionV1)
    key=AtomKey.from_token(adoption.review_ref)
    metadata=_single_graph_metadata_v1(db,namespace,key,_review_metadata_kind_v1(key),[])
    review=decode_typed_production_value_v1(metadata,_review_type_v1(key))
    if review.adoption_operation_id!=adoption.adoption_operation_id:
        raise ValueError("single-event timer changed its exact same-CAS obligation")
    if type(owner.initial_clock)is not VerifiedIngressClockV2:raise ValueError("actual paired review ClockReading is required")
    now=trusted_upper(owner.initial_clock)
    due=(adoption.review_not_before_utc if now<adoption.review_not_before_utc else
        adoption.review_due_utc if now<adoption.review_due_utc else None)
    if review.disposition in {"qualified","opposed","expired"}:due=None
    return {"next_wake_utc":due,"adoption_operation_id":adoption.adoption_operation_id,
        "adoption_digest":canonical_digest(plain_v1(adoption)),"review_ref":key.token,
        "review_digest":canonical_digest(plain_v1(review)),"readout_valid_until_utc":adoption.readout_valid_until_utc}



def single_event_current_counter_scope_v1(db,read,intent,proof,*,semantic):
    from ..domains.d01.production_operations_v1 import SemanticCounterScopeV3
    from ..domains.d07 import D07DomainProvider
    from ..runtime_storage_v3 import read_graph_row_v3
    from .domain_background_read_v3 import background_json_loads_v3
    require_single_event_metadata_read_v1(proof,db=db,frame=read.frame)
    rows=single_event_trial_metadata_rows_v1(db,read,proof,"d07.current_interpretation.v1")
    pages=tuple(page for page in read.frame.query_coverage if page.type_id=="d07.current_interpretation.v1")
    if (len(pages)!=1 or not pages[0].complete
            or pages[0].row_versions!=tuple(GraphVersion(a.key,a.revision)for a in rows)):
        raise MissingProductionOriginalV1("single_event_complete_current_counter_query_coverage")
    scope="d01.growth:"+intent["target_block"]+":"+intent["change_kind"]
    single_event_qualification_now_v1(proof,db=db,frame=read.frame)
    selected=tuple(a for a in rows if a.valid and a.value["question_key"]==scope and a.value["current"]is True)
    qualification="qualified"if semantic or selected else"unknown"
    originals=[];versions=[];digests=[];source_digests={}
    spec=next(s for s in D07DomainProvider.type_specs()if s.name=="d07.current_interpretation.v1")
    for metadata in selected:
        atom=read.head(db,metadata.key,required=True);spec.validator(atom.value)
        if any(atom.value[name]!=metadata.value[name]for name in metadata.value):
            raise ValueError("single-event counter Body differs from its qualified fixed metadata")
        history=read_graph_row_v3(db,("event_id","value","valid"),where="token=? AND revision=?",
            parameters=(atom.key.token,atom.revision),history=True)
        if history is None or history[2]!=1 or background_json_loads_v3(history[1])!=atom.value:
            raise MissingProductionOriginalV1("single_event_actual_current_counter_adoption")
        read.committed_operation(db,history[0]);originals.append(read.original(atom.key.token,digest=canonical_digest(atom.value)))
        refs=tuple(atom.value["source_refs"])
        if refs:read.source_family(db,refs,purpose="consolidation")
        for token in refs:source_digests[token]=canonical_digest(read.head(db,token,required=True).value)
        if atom.value["stance"]=="oppose"and atom.value["evidence_status"]=="supported":qualification="opposition"
        elif qualification!="opposition"and (not refs or atom.value["stance"]!="support"
                or atom.value["evidence_status"]!="supported"or atom.value["meaningful_unknowns"]):qualification="unknown"
        versions.append(GraphVersion(atom.key,atom.revision));digests.append((atom.key.token,canonical_digest(atom.value)))
    if semantic:
        return SemanticCounterScopeV3(scope,pages[0],tuple(versions),tuple(digests),tuple(sorted(source_digests.items())),qualification)
    return qualification=="qualified",qualification=="opposition",tuple(originals)






def require_current_single_event_background_source_v1(reader):
    from .domain_background_read_v3 import require_actual_background_attachment_owner_v3,require_background_followup_handoff_v3
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    require_actual_background_attachment_owner_v3(reader,db=reader.db)
    if reader.kind!="followup_child"or not reader.sealed or not reader.complete:
        raise ValueError("single-event review requires its actual completed independent child Source Work")
    handoff=require_background_followup_handoff_v3(reader.handoff,reader.graph,reader.bundle)
    if handoff.command.operation_kind!="review_single_event_growth_v1":
        raise ValueError("single-event background WRITE has another actual registered command")
    proof=_SINGLE_EVENT_SOURCE_PERMISSIONS_V1.get(reader)
    _require_single_event_completion_source_cause_v1(reader)
    if (proof is None or proof.owner()is not reader or proof.operation is not reader.operation
            or proof.stamp!=reader.graph_stamp or proof.guard!=reader.owner_guard or proof.scope is not reader.read_scope):
        raise ValueError("single-event independent child never completed its actual current Source ALL")
    with runtime_storage_quantum_v3(reader.db)as meter:
        reader.require_data_current_v3(meter)
        for token in proof.refs:_SINGLE_EVENT_SOURCE_TASKS_V1[reader][token].require_v1(reader,meter)
    return proof



def require_current_single_event_disposition_source_v1(reader):
    from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    require_actual_background_attachment_owner_v3(reader,db=reader.db)
    if (reader.kind!="followup"or not reader.sealed or not reader.complete
            or reader.entry is None or reader.entry[1:3]!=("d01",REVIEW_EVENT)):
        raise ValueError("single-event waiting disposition requires its actual completed parent Work")
    proof=_SINGLE_EVENT_SOURCE_PERMISSIONS_V1.get(reader)
    cause=_SINGLE_EVENT_CAUSES_V1.get(reader)
    if (proof is None or cause is None or proof.owner()is not reader or proof.operation is not reader.operation
            or proof.stamp!=reader.graph_stamp or proof.guard!=reader.owner_guard or proof.scope is not reader.read_scope
            or cause[1]is not reader.entry_column or cause[2:]!=(reader.operation,reader.graph_stamp)):
        raise ValueError("single-event parent disposition lacks actual causal metadata and complete Source ALL")
    with runtime_storage_quantum_v3(reader.db)as meter:
        reader.require_data_current_v3(meter)
        for token in proof.refs:_SINGLE_EVENT_SOURCE_TASKS_V1[reader][token].require_v1(reader,meter)
    return proof
