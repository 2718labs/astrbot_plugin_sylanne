"""Independent normal Habit Body CPU preparation. This is neither a quote nor a grant."""
from dataclasses import dataclass,asdict,fields
import hashlib,hmac,math
from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2,to_wire,from_wire
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceSelectorV1,habit_value_from_wire_v1
from ..graph_types import AtomKey

BODY_PREPARATION_PROVENANCE_V3='habit_body_cpu_preparation_v3'
CPU_RULE_V3='habit-source-note-original-parent-cpu-intersection.v1'
_BASIS_FIELDS=frozenset({'schema','namespace','installation_id','occurrence_head','occurrence_digest',
    'qualification_original_ref','qualification_original_digest','action_head','action_digest',
    'action_producer_digest','action_receipt_digest','body_policy','body_policy_digest','effect_policy',
    'effect_policy_digest','parent_lease','parent_lease_digest','root_grant_id','root_grant_version',
    'root_grant_digest','owner_guard','self_identity','source_versions','source_versions_digest','body_heads','body_state_digest',
    'graph_revision','graph_epoch','access_epoch','delete_epoch','cpu_rule','cpu_ceiling_ms','valid_until_utc'})

@dataclass(frozen=True,slots=True)
class HabitBodyPreparationSelectorV3:
    namespace:NamespaceId
    installation_id:str
    qualification_selector:HabitOccurrenceSelectorV1
    qualification_original_ref:str
    qualification_original_digest:str
    occurrence_ref:str
    expected_occurrence_revision:int
    action_intent_ref:str
    body_policy_id:str
    body_policy_version:int
    effect_policy_ref:str
    schema:str='d10.habit-body-cpu-preparation-selector.v1'
    def __post_init__(self):
        if(self.schema!='d10.habit-body-cpu-preparation-selector.v1'or type(self.namespace)is not NamespaceId
                or type(self.qualification_selector)is not HabitOccurrenceSelectorV1
                or self.qualification_selector.namespace!=self.namespace or self.qualification_selector.executor_kind!='source_note'
                or type(self.expected_occurrence_revision)is not int or self.expected_occurrence_revision<1
                or type(self.body_policy_version)is not int or self.body_policy_version<1):
            raise ValueError('Habit Body preparation requires its exact installed qualified occurrence')
        for ref,kind in ((self.occurrence_ref,'d10.habit_occurrence.v1'),(self.action_intent_ref,'d08.action_intent.v1')):
            key=AtomKey.from_token(ref)
            if NamespaceId.from_key(key)!=self.namespace or key.type_name!=kind:raise ValueError('Habit Body preparation crossed namespace/type')
        if not all(type(v)is str and v for v in(self.installation_id,self.qualification_original_ref,self.body_policy_id,self.effect_policy_ref)):
            raise ValueError('Habit Body preparation lacks actual immutable selectors')
        if len(self.qualification_original_digest)!=64:raise ValueError('Habit Body preparation qualification digest differs')
    @property
    def operation_kind(self):return 'prepare_source_note_body'
    @property
    def operation_id(self):return 'd02-life-body:'+self.qualification_selector.execution_operation_id
    @property
    def original_deadline_utc(self):return self.qualification_selector.original_deadline_utc

def preparation_selector_from_wire_v3(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitBodyPreparationSelectorV3)}:raise ValueError('Habit Body preparation closed selector fields differ')
    return HabitBodyPreparationSelectorV3(**{**raw,'namespace':NamespaceId(**raw['namespace']),
        'qualification_selector':habit_value_from_wire_v1('d10.habit-occurrence-selector.v1',raw['qualification_selector'])})

@dataclass(frozen=True,slots=True)
class HabitBodyCPUPreparationV3:
    selector:HabitBodyPreparationSelectorV3
    basis:dict
    read_permit:FencePermitV2
    signature:str
    schema:str='d10.habit-body-cpu-preparation.v1'
    def __post_init__(self):
        if(self.schema!='d10.habit-body-cpu-preparation.v1'or type(self.selector)is not HabitBodyPreparationSelectorV3
                or type(self.read_permit)is not FencePermitV2 or self.read_permit.operation!='read'
                or type(self.basis)is not dict or set(self.basis)!=_BASIS_FIELDS
                or self.basis['schema']!='d10.habit-body-cpu-basis.v1'or self.basis['cpu_rule']!=CPU_RULE_V3
                or type(self.basis['cpu_ceiling_ms'])is not int or not 1<=self.basis['cpu_ceiling_ms']<=60000
                or type(self.basis['valid_until_utc'])not in {int,float}or not math.isfinite(self.basis['valid_until_utc'])
                or self.basis['valid_until_utc']>self.selector.original_deadline_utc
                or self.basis['namespace']!=asdict(self.selector.namespace)
                or self.basis['installation_id']!=self.selector.installation_id):
            raise ValueError('Habit Body preparation lost its exact actual READ and complete basis')
        if type(self.signature)is not str or len(self.signature)!=64 or any(c not in '0123456789abcdef'for c in self.signature):
            raise ValueError('Habit Body preparation requires its exact Core-issued signature')
        for name in ('body_policy_digest','effect_policy_digest','parent_lease_digest','source_versions_digest'):
            field={'body_policy_digest':'body_policy','effect_policy_digest':'effect_policy','parent_lease_digest':'parent_lease','source_versions_digest':'source_versions'}[name]
            if self.basis[name]!=canonical_digest(self.basis[field]):raise ValueError('Habit Body preparation basis commitment changed')
    @property
    def digest(self):return canonical_digest(self)
    @property
    def cpu_ceiling_ms(self):return self.basis['cpu_ceiling_ms']
    @property
    def valid_until_utc(self):return self.basis['valid_until_utc']

def preparation_to_wire_v3(value):
    if type(value)is not HabitBodyCPUPreparationV3:raise TypeError('exact Habit Body preparation required')
    return {**asdict(value),'read_permit':to_wire(value.read_permit)}

def preparation_from_wire_v3(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitBodyCPUPreparationV3)}:raise ValueError('Habit Body preparation closed evidence fields differ')
    return HabitBodyCPUPreparationV3(**{**raw,'selector':preparation_selector_from_wire_v3(raw['selector']),'read_permit':from_wire(raw['read_permit'])})

def preparation_signature_material_v3(selector,basis,permit):
    return canonical_serialize(('d10.habit-body-cpu-preparation.v1',selector,basis,to_wire(permit))).encode('utf8')

def body_cpu_intersection_v3(parent,grant):
    for dimension in ('cpu_ms','thread_cpu_ms'):
        if(type(parent.limits.get(dimension))is not int or type(grant.max_ceiling.get(dimension))is not int
                or parent.limits[dimension]<1 or grant.max_ceiling[dimension]<1):
            raise AuthorityUnavailable('Habit original parent lacks exact positive signed CPU dimensions')
    cpu=min(60000,grant.max_ceiling['cpu_ms'],parent.available('cpu_ms'),grant.max_ceiling['thread_cpu_ms'],parent.available('thread_cpu_ms'))
    if cpu<1:raise AuthorityUnavailable('Habit original parent has no available Body CPU allowance')
    return cpu

def stable_self_v3(value):
    return tuple(getattr(value,name)for name in('namespace','authority_namespace','authority_id','installation_id',
        'manifest_digest','activation_generation','graph_incarnation','role_head_id','graph_revision','graph_epoch',
        'origin_graph_incarnation','storage_admission_digest','persona_ref','self_entity_ref','mapping_id','mapping_revision',
        'mapping_revocation_epoch','registration_operation_id','registration_digest','owner_authorization_revision',
        'owner_authorization_head','owner_minimum_revocation_revision','owner_revocation_epoch'))

def body_basis_v3(*,selector,occurrence_head,occurrence_digest,action_head,action_digest,action_producer_digest,
        action_receipt_digest,body_policy,effect_policy,parent,grant,owner_guard,current_self,source_versions,
        graph_revision,graph_epoch,access_epoch,delete_epoch,body_heads,body_state_digest):
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..runtime.d11_life_contract_v1 import WORK_KIND
    if(parent.state!='active'or parent.lease_id!=grant.lease_id or parent.parent_id is not None
            or(parent.bot_id,parent.persona_id)!=selector.namespace.as_tuple
            or WORK_KIND not in grant.allowed_work_kinds):
        raise AuthorityUnavailable('Habit Body preparation lost original active same-namespace execution parent')
    if(body_policy.policy_id,body_policy.version,effect_policy.policy_ref)!=(selector.body_policy_id,selector.body_policy_version,selector.effect_policy_ref):
        raise AuthorityUnavailable('Habit Body preparation changed actual fixed policy selectors')
    if(body_policy.work_kind,effect_policy.work_kind,body_policy.profile.profile_id,effect_policy.profile_id,
            body_policy.component.component_id)!=(WORK_KIND,WORK_KIND,effect_policy.profile_id,
                body_policy.profile.profile_id,effect_policy.component_id):
        raise AuthorityUnavailable('Habit Body preparation changed actual SourceNote profile/component')
    cpu=body_cpu_intersection_v3(parent,grant)
    deadline=min(selector.original_deadline_utc,grant.valid_until_utc,body_policy.valid_until)
    body=plain_v1(body_policy);effect=plain_v1(effect_policy);lease=plain_v1(parent)
    source=plain_v1(tuple(sorted(source_versions,key=lambda v:v.key.token)))
    return plain_v1({'schema':'d10.habit-body-cpu-basis.v1','namespace':selector.namespace,'installation_id':selector.installation_id,
        'occurrence_head':occurrence_head,'occurrence_digest':occurrence_digest,
        'qualification_original_ref':selector.qualification_original_ref,'qualification_original_digest':selector.qualification_original_digest,
        'action_head':action_head,'action_digest':action_digest,'action_producer_digest':action_producer_digest,
        'action_receipt_digest':action_receipt_digest,'body_policy':body,'body_policy_digest':canonical_digest(body),
        'effect_policy':effect,'effect_policy_digest':canonical_digest(effect),'parent_lease':lease,
        'parent_lease_digest':canonical_digest(lease),'root_grant_id':grant.grant_id,'root_grant_version':grant.version,
        'root_grant_digest':canonical_digest(grant),'owner_guard':owner_guard,'self_identity':stable_self_v3(current_self),
        'source_versions':source,'source_versions_digest':canonical_digest(source),'body_heads':body_heads,
        'body_state_digest':body_state_digest,'graph_revision':graph_revision,
        'graph_epoch':graph_epoch,'access_epoch':access_epoch,'delete_epoch':delete_epoch,'cpu_rule':CPU_RULE_V3,
        'cpu_ceiling_ms':cpu,'valid_until_utc':deadline})

def observe_current_body_cpu_v3(service,*,credential,subject,permit,request):
    from .current_habit_execution_v1 import current_habit_execution_v1
    if type(request)is not HabitBodyPreparationSelectorV3 or permit.operation!='read':
        raise AuthorityUnavailable('Habit Body CPU preparation needs its exact fixed current READ')
    return current_habit_execution_v1(service,credential=credential,subject=subject,permit=permit,request=request)

def require_body_preparation_v3(service,preparation,selector,basis,permit,inputs):
    if(type(preparation)is not HabitBodyCPUPreparationV3 or preparation.selector!=selector or preparation.basis!=basis
            or(preparation.read_permit.authority_id,preparation.read_permit.namespace,preparation.read_permit.subject,preparation.read_permit.holder,preparation.read_permit.pinned_anchor)!=(
                permit.authority_id,permit.namespace,permit.subject,permit.holder,permit.pinned_anchor)):

        raise AuthorityUnavailable('Habit Body WRITE changed its independently prepared actual basis')
    expected=hmac.new(service._key,preparation_signature_material_v3(selector,basis,preparation.read_permit),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,preparation.signature):raise AuthorityUnavailable('Habit Body CPU preparation is not actual Core-issued evidence')
    from .habit_finished_producer_v3 import require_habit_preparation_read_finished_v3
    require_habit_preparation_read_finished_v3(inputs,preparation)


def preparation_from_domain_plain_v3(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitBodyCPUPreparationV3)}:
        raise ValueError('Habit Body domain preparation closed fields differ')
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    permit=decode_typed_production_value_v1(raw['read_permit'],FencePermitV2)
    return HabitBodyCPUPreparationV3(**{**raw,'selector':preparation_selector_from_wire_v3(raw['selector']),'read_permit':permit})

def preparation_domain_plain_v3(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(value)is not HabitBodyCPUPreparationV3:raise TypeError('exact actual Habit Body CPU preparation required')
    return plain_v1(value)
