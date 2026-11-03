"""Closed material for a real post-adoption single-event review.

These values carry data. Only the installed D01 Source-qualified producer may
register their signed original; a caller-created value grants no use.
"""
from dataclasses import dataclass
import json

from ...graph_types import GraphVersion, NamespaceEpoch
from ...runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ...runtime.domain_production_contracts_v1 import ProductionOriginalRefV1
from .identity_v3 import _text, _digest, _refs
from .single_event_growth_v1 import _time, _versions, SCOPE_TYPES

CASE_KIND = 'single_event_review_case_v1'
CASE_EVENT = 'd01.single_event_review_case_registered_v1'
CASE_SCHEMA = 'd01.registered-single-event-review-case.v1'


def _original(value):
    if type(value) is not ProductionOriginalRefV1:
        raise TypeError('single-event review requires actual typed original commitments')


@dataclass(frozen=True, slots=True)
class SingleEventReviewCounterBindingV1:
    question_key: str
    epoch: NamespaceEpoch
    inventory_versions: tuple[GraphVersion,...]
    selected_members: tuple[tuple[GraphVersion,str],...]
    qualification: str

    def __post_init__(self):
        _text(self.question_key)
        if (type(self.epoch) is not NamespaceEpoch or type(self.inventory_versions) is not tuple
                or len(self.inventory_versions)>128
                or len({v.key for v in self.inventory_versions})!=len(self.inventory_versions)
                or any(type(v) is not GraphVersion or v.key.type_name!='d07.current_interpretation.v1'
                    or v.revision<1 for v in self.inventory_versions)
                or self.qualification not in {'qualified','unknown','opposition'}):
            raise ValueError('review counter requires its complete actual bounded current domain')
        inventory=set(self.inventory_versions)
        if len({v.key for v,_ in self.selected_members})!=len(self.selected_members):
            raise ValueError('review counter member repeats')
        for version,digest in self.selected_members:
            if version not in inventory:raise ValueError('review counter member is outside actual census')
            _digest(digest)


@dataclass(frozen=True, slots=True)
class SingleEventPostAdoptionScopeBindingV1:
    evidence_kind: str
    evidence_source_version: GraphVersion | None
    outcome_version: GraphVersion
    planned_version: GraphVersion
    scope_version: GraphVersion
    producer_original: ProductionOriginalRefV1
    observer_originals: tuple[ProductionOriginalRefV1,...]
    occurred_at_utc: float

    def __post_init__(self):
        if self.evidence_kind not in {'source_observation','typed_outcome'}:
            raise ValueError('review evidence has another registered kind')
        if self.evidence_kind=='source_observation' and self.evidence_source_version is None:
            raise ValueError('an observed Source needs its actual current version')
        for value in (self.outcome_version,self.planned_version,self.scope_version):
            if type(value) is not GraphVersion or value.revision<1:
                raise TypeError('review evidence requires actual typed outcome/planned/scope versions')
        if self.outcome_version.key.type_name not in {'d08.action_outcome.v1','d10.life_progress.v1'}:
            raise ValueError('review evidence lacks a registered actual outcome')
        if self.scope_version.key.type_name not in SCOPE_TYPES:
            raise ValueError('review evidence scope is outside its registered finite kinds')
        expected='d08.action_intent.v1' if self.outcome_version.key.type_name=='d08.action_outcome.v1' else 'd10.life_project.v1'
        if self.planned_version.key.type_name!=expected:
            raise ValueError('review planned anchor differs from its exact outcome kind')
        _original(self.producer_original)
        if type(self.observer_originals) is not tuple or not self.observer_originals:
            raise ValueError('review evidence needs its actual independent observer originals')
        for original in self.observer_originals:_original(original)
        _time(self.occurred_at_utc)


@dataclass(frozen=True, slots=True)
class RegisteredSingleEventReviewCaseV1:
    namespace: NamespaceId
    case_revision: int
    policy_original: ProductionOriginalRefV1
    input_original: ProductionOriginalRefV1
    adoption_version: GraphVersion
    adoption_value_digest: str
    adoption_original: ProductionOriginalRefV1
    adoption_receipt_digest: str
    adoption_recorded_at_utc: float
    review_version: GraphVersion
    review_value_digest: str
    current_persona_head: GraphVersion
    current_persona_head_id: str
    target_block: str
    adopted_claim: str
    adopted_claim_digest: str
    scope_versions: tuple[GraphVersion,...]
    exclusion_versions: tuple[GraphVersion,...]
    review_not_before_utc: float
    review_due_utc: float
    readout_valid_until_utc: float
    post_adoption_evidence_originals: tuple[ProductionOriginalRefV1,...]
    post_adoption_evidence_versions: tuple[GraphVersion,...]
    post_adoption_evidence_values: tuple[tuple[GraphVersion,str],...]
    post_adoption_scope_bindings: tuple[SingleEventPostAdoptionScopeBindingV1,...]
    support_source_refs: tuple[str,...]
    context_source_refs: tuple[str,...]
    source_versions: tuple[GraphVersion,...]
    counter_scope_binding: SingleEventReviewCounterBindingV1
    trial_originals: tuple[ProductionOriginalRefV1,...]
    clock_original: ProductionOriginalRefV1
    clock_mapping_id: str
    clock_mapping_version: int
    registered_at_utc: float
    registration_operation_id: str
    causal_original: ProductionOriginalRefV1
    causal_operation_id: str
    causal_receipt_digest: str
    original_parent_budget_lease_ref: str
    original_parent_grant_digest: str
    original_deadline_utc: float
    schema: str = CASE_SCHEMA

    def __post_init__(self):
        if self.schema!=CASE_SCHEMA or type(self.namespace) is not NamespaceId or self.case_revision!=1:
            raise ValueError('single-event review case has another closed schema/namespace/revision')
        for value in (self.policy_original,self.input_original,self.adoption_original,self.clock_original,self.causal_original,
                *self.post_adoption_evidence_originals,*self.trial_originals):_original(value)
        for value in (self.adoption_version,self.review_version,self.current_persona_head,
                *self.post_adoption_evidence_versions,*self.source_versions):
            if type(value) is not GraphVersion or NamespaceId.from_key(value.key)!=self.namespace or value.revision<0:
                raise ValueError('single-event review case has a foreign current version')
        if (self.adoption_version.key.type_name!='d01.single_event_growth_adoption.v1'
                or self.adoption_version.revision!=1 or self.review_version.revision<1
                or self.review_version.key.type_name!='d01.single_event_growth_review.v2'
                or self.current_persona_head.key.type_name!='d01.persona_plan.v1'
                or self.current_persona_head.revision<1):
            raise ValueError('single-event case does not bind its actual adoption/review/current persona')
        for value in (self.adoption_value_digest,self.adoption_receipt_digest,self.review_value_digest,
                self.adopted_claim_digest,self.causal_receipt_digest,self.original_parent_grant_digest):_digest(value)
        for value in (self.current_persona_head_id,self.target_block,self.adopted_claim,self.clock_mapping_id,
                self.registration_operation_id,self.causal_operation_id,self.original_parent_budget_lease_ref):_text(value)
        if canonical_digest(self.adopted_claim)!=self.adopted_claim_digest:
            raise ValueError('single-event case changed the exact adopted claim')
        if self.clock_original.kind!='d11.owner_role_clock_installation.v1' or type(self.clock_mapping_version) is not int or self.clock_mapping_version<1:
            raise ValueError('single-event case needs the actual versioned signed D11 mapping original')
        _versions(self.scope_versions,self.namespace,SCOPE_TYPES,nonempty=True)
        _versions(self.exclusion_versions,self.namespace,SCOPE_TYPES)
        if not self.post_adoption_scope_bindings or not self.post_adoption_evidence_originals or not self.post_adoption_evidence_versions:
            raise ValueError('single-event review requires actual new applicable evidence')
        if type(self.counter_scope_binding) is not SingleEventReviewCounterBindingV1:
            raise TypeError('single-event review needs its complete current counter commitment')
        if self.counter_scope_binding.qualification=='opposition':
            raise ValueError('actual opposition is settled by D01 without a forced review case')
        for value in (self.adoption_recorded_at_utc,self.review_not_before_utc,self.review_due_utc,
                self.readout_valid_until_utc,self.registered_at_utc,self.original_deadline_utc):_time(value)
        if not self.review_not_before_utc<=self.registered_at_utc<min(self.review_due_utc,self.original_deadline_utc)<=self.readout_valid_until_utc:
            raise ValueError('single-event case cannot renew its original review or grant window')
        roots=(*self.support_source_refs,*self.context_source_refs)
        _refs(self.support_source_refs);_refs(self.context_source_refs)
        if not roots or len(roots)>16 or len(set(roots))!=len(roots):
            raise ValueError('single-event review retains separate bounded support/context Source roots')
        for row in self.post_adoption_scope_bindings:
            if (type(row) is not SingleEventPostAdoptionScopeBindingV1
                    or row.scope_version not in self.scope_versions
                    or row.outcome_version not in self.post_adoption_evidence_versions
                    or not self.adoption_recorded_at_utc<row.occurred_at_utc<=self.registered_at_utc):
                raise ValueError('review evidence is not actually after adoption in the exact original finite scope')
        if tuple(version for version,_ in self.post_adoption_evidence_values)!=self.post_adoption_evidence_versions:
            raise ValueError('review target must contain exactly its authenticated typed evidence values')
        for version,encoded in self.post_adoption_evidence_values:
            raw=json.loads(encoded)
            if canonical_serialize(raw)!=encoded:raise ValueError('review evidence is not canonical original content')
            from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
            if version.key.type_name=='d08.action_outcome.v1':
                from ..d08.execution import _decode
                _decode(version.key.type_name,raw)
            elif version.key.type_name=='d10.life_progress.v1':
                from ..d10.production_operations_v1 import LifeProgressHeadV1
                decode_typed_production_value_v1(raw,LifeProgressHeadV1)
            else:raise ValueError('review evidence has an unregistered outcome Body')
        if len(canonical_serialize(self).encode('utf8'))>8192:
            raise ValueError('single-event review case exceeds the original generic model target bound')

    @property
    def case_ref(self):
        basis=(self.namespace,self.adoption_version,self.adoption_value_digest,self.policy_original,
            self.input_original,self.adopted_claim_digest,self.post_adoption_evidence_originals,
            self.post_adoption_evidence_versions,self.post_adoption_evidence_values,
            self.post_adoption_scope_bindings,self.scope_versions,self.exclusion_versions,self.source_versions,
            (self.counter_scope_binding.question_key,self.counter_scope_binding.selected_members,
             self.counter_scope_binding.qualification))
        return 'single-event-review-case:'+canonical_digest(basis)[:48]
