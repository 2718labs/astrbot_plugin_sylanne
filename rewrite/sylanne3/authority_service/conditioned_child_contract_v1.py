"""Closed locators and evidence for independently qualified conditioned children.

These wire values grant no authority. Only the paired Core observer and its
private Host issuance bind them to one actual fresh WRITE scope.
"""
from dataclasses import dataclass
import json
import math

from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,QueryEpoch,canonical_digest,canonical_serialize
from ..runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1
from .v2_self_identity_contract import AuthorityCurrentSelfIdentityV1

ROOT_WORK_KIND='d01.conditioned_self_child.v1'
CHILD_DOMAINS={
    'register_current_prediction_v1':'d07','record_current_simulation_v1':'d07',
    'resolve_current_prediction_v1':'d07','review_current_conditioned_self_v1':'d01',
    'match_current_conditioned_strategy_v1':'d07','select_current_conditioned_personal_step_v1':'d08',
    'project_current_conditioned_life_strategy_v1':'d10'}
CHILD_OUTPUT_TYPES={
    'register_current_prediction_v1':frozenset({'d07.prediction_record.v1'}),
    'record_current_simulation_v1':frozenset({'d07.simulation_record.v1'}),
    'resolve_current_prediction_v1':frozenset({'d07.prediction_resolution.v1','d07.self_discrepancy.v1'}),
    'review_current_conditioned_self_v1':frozenset({'d01.conditioned_capability_revision.v1','d01.conditioned_strategy_revision.v1','d01.conditioned_self_review.v1'}),
    'match_current_conditioned_strategy_v1':frozenset({'d07.condition_match.v1'}),
    'select_current_conditioned_personal_step_v1':frozenset({'d08.decision_record.v2'}),
    'project_current_conditioned_life_strategy_v1':frozenset({'d10.conditioned_strategy_projection.v1'})}


def _digest(value):
    if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):
        raise ValueError('conditioned child requires an exact lowercase SHA256 commitment')


def _text(value):
    if type(value)is not str or not value or len(value)>4096:
        raise ValueError('conditioned child locator is invalid')


@dataclass(frozen=True,slots=True)
class ConditionedChildSelectorV1:
    namespace:NamespaceId
    installation_id:str
    phase:str
    operation_id:str
    activity_id:str
    operation_kind:str
    typed_request_json:str
    typed_request_digest:str
    producer_domain:str
    producer_kind:str
    producer_operation_id:str
    producer_original_ref:str
    producer_original_digest:str
    producer_receipt_digest:str
    dedupe_key:str|None
    event_kind:str|None
    targets_digest:str
    target_census_digest:str
    frozen_targets_original_ref:str|None
    frozen_targets_original_digest:str|None
    frozen_targets_json:str|None
    parent_budget_lease_ref:str
    root_budget_lease_ref:str
    root_grant_id:str
    root_grant_version:int
    root_grant_digest:str
    original_deadline_utc:float
    purpose:str
    audiences:tuple[str,...]
    source_refs:tuple[str,...]
    allowed_write_keys:tuple[AtomKey,...]
    schema:str='d01.conditioned-child-selector.v1'

    def __post_init__(self):
        if(self.schema!='d01.conditioned-child-selector.v1'or type(self.namespace)is not NamespaceId
                or self.phase not in {'child','personal_choice'}or self.operation_kind not in CHILD_DOMAINS
                or(self.phase=='personal_choice')!=(self.operation_kind=='select_current_conditioned_personal_step_v1')
                or self.producer_domain not in {'d01','d07','d08','d10'}or self.purpose!='consolidation'
                or type(self.root_grant_version)is not int or self.root_grant_version<1
                or type(self.original_deadline_utc)not in(int,float)or not math.isfinite(self.original_deadline_utc)):
            raise ValueError('conditioned selector changed its registered phase, semantic kind or original Root')
        for value in(self.installation_id,self.operation_id,self.activity_id,self.producer_kind,self.producer_operation_id,
                self.producer_original_ref,self.parent_budget_lease_ref,self.root_budget_lease_ref,self.root_grant_id):_text(value)
        for value in(self.typed_request_digest,self.producer_original_digest,self.producer_receipt_digest,
                self.targets_digest,self.target_census_digest,self.root_grant_digest):_digest(value)
        if(self.frozen_targets_original_ref is None)!=(self.frozen_targets_original_digest is None):
            raise ValueError('conditioned frozen targets require their actual COMMIT original and digest together')
        if self.frozen_targets_original_ref is not None:
            _text(self.frozen_targets_original_ref);_digest(self.frozen_targets_original_digest)
        if self.phase=='child':
            if self.activity_id!=self.operation_id:raise ValueError('conditioned semantic child must retain its actual stable child Work activity')
            from ..runtime.conditioned_self_operations_v1 import CONDITIONED_PRODUCER_EVENTS_V1
            if(self.event_kind not in CONDITIONED_PRODUCER_EVENTS_V1 or self.dedupe_key is None
                    or(self.producer_domain,self.producer_kind)not in CONDITIONED_PRODUCER_EVENTS_V1[self.event_kind]):
                raise ValueError('conditioned child requires its fixed actual producer/event pair')
            _text(self.dedupe_key)
            if type(self.frozen_targets_json)is not str:raise ValueError('conditioned child requires its full exact frozen target census')
            frozen=json.loads(self.frozen_targets_json)
            validate_conditioned_frozen_targets_v1(frozen,namespace=self.namespace)
            if(canonical_serialize(frozen)!=self.frozen_targets_json or frozen['targets_digest']!=self.targets_digest
                    or frozen['target_census_digest']!=self.target_census_digest
                    or frozen['dedupe_key']!=self.dedupe_key or frozen['causal_operation_id']!=self.producer_operation_id
                    or frozen['producer_original_digest']!=self.producer_original_digest
                    or frozen['producer_receipt_digest']!=self.producer_receipt_digest
                    or frozen['parent_budget_lease_ref']!=self.parent_budget_lease_ref
                    or frozen['original_deadline_utc']!=self.original_deadline_utc):
                raise ValueError('conditioned selector changed its actual frozen producer or target census')
            members=tuple(target for target in frozen['targets']if target['child_id']==self.operation_id)
            if(len(members)!=1 or members[0]['operation_kind']!=self.operation_kind
                    or canonical_serialize(members[0]['request'])!=self.typed_request_json):
                raise ValueError('conditioned selector is not one exact member of its complete frozen target set')
        elif(self.dedupe_key is not None or self.event_kind is not None or self.frozen_targets_json is not None
                or self.frozen_targets_original_ref is not None
                or(self.producer_domain,self.producer_kind)!=('d08','prepare_personal_candidates_v1')):
            raise ValueError('inline conditioned choice belongs to its actual prepared-candidate W01')
        from ..runtime.conditioned_self_operations_v1 import conditioned_request_from_wire_v1
        if type(self.typed_request_json)is not str or len(self.typed_request_json.encode('utf-8'))>65536:
            raise ValueError('conditioned child request exceeds its existing bounded typed request envelope')
        raw=json.loads(self.typed_request_json)
        request=conditioned_request_from_wire_v1(self.operation_kind,raw)
        if canonical_serialize(raw)!=self.typed_request_json or canonical_digest(request)!=self.typed_request_digest:
            raise ValueError('conditioned child request does not match its exact registered canonical typed command')
        if(type(self.audiences)is not tuple or not self.audiences or len(set(self.audiences))!=len(self.audiences)
                or type(self.source_refs)is not tuple or len(set(self.source_refs))!=len(self.source_refs)
                or type(self.allowed_write_keys)is not tuple or len(set(self.allowed_write_keys))!=len(self.allowed_write_keys)):
            raise ValueError('conditioned child metadata must retain unique exact selectors')
        for value in self.audiences:_text(value)
        from ..memory_types import source_key
        for ref in self.source_refs:
            key=AtomKey.from_token(ref)
            if key!=source_key(*self.namespace.as_tuple,key.owner.subject):
                raise ValueError('conditioned child Source locator crossed its actual namespace or canonical key')
        if(any(type(key)is not AtomKey or NamespaceId.from_key(key)!=self.namespace
                or key.type_name not in CHILD_OUTPUT_TYPES[self.operation_kind]for key in self.allowed_write_keys)):
            raise ValueError('conditioned child contains another semantic write domain')


def validate_conditioned_frozen_targets_v1(raw,*,namespace):
    from ..runtime.conditioned_self_operations_v1 import CONDITIONED_PRODUCER_EVENTS_V1,conditioned_request_from_wire_v1
    if(type(raw)is not dict or set(raw)!={'schema','namespace','dedupe_key','causal_operation_id','event_kind',
            'producer_original_digest','producer_receipt_digest','parent_budget_lease_ref','original_deadline_utc',
            'target_census','target_census_digest','targets','targets_digest'}
            or raw['schema']!='d01.conditioned-frozen-targets.v1'
            or raw['namespace']!={'bot_id':namespace.bot_id,'persona_id':namespace.persona_id}
            or raw['event_kind']not in CONDITIONED_PRODUCER_EVENTS_V1):
        raise ValueError('conditioned frozen targets changed their fixed complete producer schema')
    for name in('dedupe_key','causal_operation_id','parent_budget_lease_ref'):_text(raw[name])
    for name in('producer_original_digest','producer_receipt_digest','target_census_digest','targets_digest'):_digest(raw[name])
    census=raw['target_census'];targets=raw['targets']
    if(type(census)is not dict or set(census)!={'read_versions','query_coverage','source_roots'}
            or canonical_digest(census)!=raw['target_census_digest']
            or type(targets)not in(tuple,list)or not 1<=len(targets)<=16
            or canonical_digest(targets)!=raw['targets_digest']):
        raise ValueError('conditioned frozen targets lost their full census or bounded complete target tuple')
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..runtime.domain_production_contracts_v1 import ProductionQueryCoverageV1
    versions=decode_typed_production_value_v1(census['read_versions'],tuple[GraphVersion,...])
    pages=decode_typed_production_value_v1(census['query_coverage'],tuple[ProductionQueryCoverageV1,...])
    if(len({value.key for value in versions})!=len(versions)
            or any(NamespaceId.from_key(value.key)!=namespace for value in versions)
            or any(page.epoch.namespace!=namespace or not page.complete for page in pages)
            or type(census['source_roots'])not in(tuple,list)
            or len(set(census['source_roots']))!=len(census['source_roots'])
            or type(raw['original_deadline_utc'])not in(int,float)or not math.isfinite(raw['original_deadline_utc'])):
        raise ValueError('conditioned target census changed its exact complete namespace, Source or query coverage')
    from ..memory_types import source_key
    for ref in census['source_roots']:
        key=AtomKey.from_token(ref)
        if key!=source_key(*namespace.as_tuple,key.owner.subject):raise ValueError('conditioned census Source token differs')
    seen=set()
    for target in targets:
        if(type(target)is not dict or set(target)!={'child_id','operation_kind','request'}
                or target['operation_kind']not in CHILD_DOMAINS
                or target['operation_kind']=='select_current_conditioned_personal_step_v1'):
            raise ValueError('frozen conditioned target is outside its actual durable semantic child recipe')
        request=conditioned_request_from_wire_v1(target['operation_kind'],target['request'])
        child_id='conditioned-child:'+canonical_digest((namespace,raw['dedupe_key'],target['operation_kind'],request))[:48]
        if target['child_id']!=child_id or child_id in seen:
            raise ValueError('conditioned target set repeats or changes its stable actual child identity')
        seen.add(child_id)
    return raw


def conditioned_child_fence_operation_id_v1(selector):
    if type(selector)is not ConditionedChildSelectorV1:raise TypeError('actual conditioned child selector required')
    return 'conditioned-child-'+canonical_digest(selector)[:48]


def conditioned_child_finish_digest_v1(selector,permit):
    from .v2_contract import FencePermitV2
    if(type(selector)is not ConditionedChildSelectorV1 or type(permit)is not FencePermitV2
            or permit.operation!='write'or permit.operation_id!=conditioned_child_fence_operation_id_v1(selector)):
        raise ValueError('conditioned finish requires its exact original child selector and WRITE permit')
    return 'sha256:'+canonical_digest({'schema':'w01.conditioned-child-domain-write.v1',
        'operation_id':selector.operation_id,'request_digest':canonical_digest(selector),'permit_token':permit.token})


@dataclass(frozen=True,slots=True)
class ConditionedChildEvidenceV1:
    selector:ConditionedChildSelectorV1
    current_self:AuthorityCurrentSelfIdentityV1
    owner_guard:ProductionOwnerGuardV1
    read_versions:tuple[GraphVersion,...]
    query_epoch:QueryEpoch
    access_epoch:int
    delete_epoch:int
    allowed_write_domains:tuple[str,...]
    allowed_owner_kinds:tuple[str,...]
    provider_policy_ref:str
    root_grant_digest:str
    valid_until_utc:float
    source_commitment:str
    target_membership_digest:str
    observed_at_utc:float
    schema:str='d01.conditioned-child-evidence.v1'

    def __post_init__(self):
        if(self.schema!='d01.conditioned-child-evidence.v1'or type(self.selector)is not ConditionedChildSelectorV1
                or type(self.current_self)is not AuthorityCurrentSelfIdentityV1 or type(self.owner_guard)is not ProductionOwnerGuardV1
                or type(self.query_epoch)is not QueryEpoch or type(self.read_versions)is not tuple
                or any(type(value)is not GraphVersion or NamespaceId.from_key(value.key)!=self.selector.namespace for value in self.read_versions)
                or len({value.key for value in self.read_versions})!=len(self.read_versions)
                or self.current_self.namespace!=self.selector.namespace or self.current_self.permit.operation!='write'
                or self.current_self.permit.operation_id!=conditioned_child_fence_operation_id_v1(self.selector)
                or self.allowed_write_domains!=(CHILD_DOMAINS[self.selector.operation_kind],)
                or self.allowed_owner_kinds!=tuple(sorted({key.owner.kind for key in self.selector.allowed_write_keys}))
                or self.root_grant_digest!=self.selector.root_grant_digest
                or type(self.valid_until_utc)not in(int,float)or not math.isfinite(self.valid_until_utc)
                or type(self.observed_at_utc)not in(int,float)or not math.isfinite(self.observed_at_utc)
                or not self.observed_at_utc<self.valid_until_utc<=self.selector.original_deadline_utc):
            raise ValueError('conditioned evidence changed its actual fresh WRITE, current Self or original deadline')
        _text(self.provider_policy_ref)
        for value in(self.root_grant_digest,self.source_commitment,self.target_membership_digest):_digest(value)
        if any(type(value)is not int or value<0 for value in(self.access_epoch,self.delete_epoch)):
            raise ValueError('conditioned evidence requires actual current rights epochs')


def conditioned_child_to_wire_v1(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    kinds={ConditionedChildSelectorV1:'selector',ConditionedChildEvidenceV1:'evidence'}
    if type(value)not in kinds:raise TypeError('closed conditioned child wire type required')
    return {'schema':'d01.conditioned-child-wire.v1','kind':kinds[type(value)],'payload':plain_v1(value)}


def conditioned_child_from_wire_v1(raw,expected_type):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    kinds={ConditionedChildSelectorV1:'selector',ConditionedChildEvidenceV1:'evidence'}
    if(expected_type not in kinds or type(raw)is not dict or set(raw)!={'schema','kind','payload'}
            or raw['schema']!='d01.conditioned-child-wire.v1'or raw['kind']!=kinds[expected_type]):
        raise ValueError('conditioned child wire changed its exact registered shape')
    return decode_typed_production_value_v1(raw['payload'],expected_type)
