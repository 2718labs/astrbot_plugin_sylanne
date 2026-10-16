"""Independent five-write continuation P2 capsule; the first eleven-write carrier remains distinct."""
from dataclasses import dataclass,fields,asdict
import math
from .d10_contact_policy_service_v1 import D10ContactPolicyOriginalV1,contact_policy_original_to_wire_v1,contact_policy_original_from_wire_v1
from .contact_continuation_contract_v1 import (ContactContinuationObservationV1,ContactContinuationPrefixFactV1,
    contact_continuation_to_wire_v1,contact_continuation_from_wire_v1,_digest,_text)
from .v2_contract import canonical_digest as authority_digest
from ..runtime_contracts import NamespaceId,canonical_digest

@dataclass(frozen=True,slots=True)
class ContactContinuationP2PolicyCapsuleV1:
    installation_id:str
    namespace:NamespaceId
    graph_incarnation:str
    storage_commitment:str
    admission_ref:str
    batch_ref:str
    plan_ref:str
    context_digest:str
    binding_digest:str
    claimed_receipt_digest:str
    owner_witness_digest:str
    authority_snapshot_digest:str
    policy_original:D10ContactPolicyOriginalV1
    continuation:ContactContinuationObservationV1
    prefix:tuple[ContactContinuationPrefixFactV1,...]
    same_object_gate:str
    communication_action:str
    quote_id:str
    quote_version:int
    quote_digest:str
    reservation_digest:str
    root_grant_id:str
    root_grant_version:int
    root_grant_digest:str
    root_lease_ref:str
    quota_occupancies:tuple[str,...]
    observed_at_utc:float
    deadline_utc:float
    schema:str='sylanne.contact-continuation-p2-current-policy-capsule.v1'
    def __post_init__(self):
        if (self.schema!='sylanne.contact-continuation-p2-current-policy-capsule.v1' or type(self.namespace)is not NamespaceId
                or type(self.policy_original)is not D10ContactPolicyOriginalV1 or type(self.continuation)is not ContactContinuationObservationV1
                or self.policy_original.namespace!=self.namespace or self.policy_original.installation_id!=self.installation_id
                or self.policy_original.action!='issue' or self.continuation.selector.namespace!=self.namespace
                or self.continuation.installation_id!=self.installation_id or self.prefix!=self.continuation.prefix
                or type(self.quota_occupancies)is not tuple or self.quota_occupancies!=()
                or type(self.quote_version)is not int or self.quote_version<1 or type(self.root_grant_version)is not int or self.root_grant_version<1
                or any(type(v)not in(int,float)or not math.isfinite(v)for v in(self.observed_at_utc,self.deadline_utc))
                or not self.observed_at_utc<self.deadline_utc<=self.continuation.deadline_utc
                or not self.policy_original.policy.window_start<=self.observed_at_utc<self.policy_original.policy.window_end):
            raise ValueError('Contact continuation P2 requires original permission, empty continuation quota and full settled prefix')
        for name in ('installation_id','graph_incarnation','admission_ref','batch_ref','plan_ref','same_object_gate',
                'communication_action','quote_id','root_grant_id','root_lease_ref'):_text(getattr(self,name))
        for name in ('storage_commitment','quote_digest','reservation_digest','root_grant_digest'):_digest(getattr(self,name))
        for name in ('context_digest','binding_digest','claimed_receipt_digest','owner_witness_digest','authority_snapshot_digest'):
            value=getattr(self,name)
            if not value.startswith('sha256:'):raise ValueError('Contact continuation P2 lacks exact Authority commitment')
            _digest(value[7:])
    @property
    def digest(self):return canonical_digest(contact_continuation_p2_capsule_to_wire_v1(self))
    @property
    def segment_index(self):return self.continuation.selector.segment_index
    @property
    def segment_count(self):return self.continuation.segment_count
    @property
    def first_admission_ref(self):return self.continuation.first_admission_ref
    @property
    def whole_manifest_digest(self):return self.continuation.whole_manifest_digest
    @property
    def old_cause_ref(self):return self.continuation.old_cause_ref
    @property
    def old_cause_digest(self):return self.continuation.old_cause_digest
    @property
    def same_claim_ref(self):return self.continuation.same_claim_ref
    @property
    def same_goal_ref(self):return self.continuation.same_goal_ref

def contact_continuation_p2_capsule_to_wire_v1(value):
    if type(value)is not ContactContinuationP2PolicyCapsuleV1:raise TypeError('Independent Contact continuation P2 capsule required')
    result={f.name:getattr(value,f.name)for f in fields(value)}
    result['namespace']=asdict(value.namespace);result['policy_original']=contact_policy_original_to_wire_v1(value.policy_original)
    result['continuation']=contact_continuation_to_wire_v1(value.continuation)
    result['prefix']=[contact_continuation_to_wire_v1(f)for f in value.prefix];result['quota_occupancies']=[]
    return result

def contact_continuation_p2_capsule_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(ContactContinuationP2PolicyCapsuleV1)}:
        raise ValueError('Contact continuation P2 closed fields differ')
    value=dict(raw);value['namespace']=NamespaceId(**value['namespace'])
    value['policy_original']=contact_policy_original_from_wire_v1(value['policy_original'])
    value['continuation']=contact_continuation_from_wire_v1(value['continuation'],ContactContinuationObservationV1)
    if type(value['prefix'])is not list or value['quota_occupancies']!=[]:raise ValueError('Contact continuation P2 prefix/quota shape differs')
    value['prefix']=tuple(contact_continuation_from_wire_v1(f,ContactContinuationPrefixFactV1)for f in value['prefix'])
    value['quota_occupancies']=()
    result=ContactContinuationP2PolicyCapsuleV1(**value)
    if contact_continuation_p2_capsule_to_wire_v1(result)!=raw:raise ValueError('Contact continuation P2 canonical wire differs')
    return result

def require_exact_contact_continuation_p2_capsule_v1(context,binding,claimed,witness,snapshot,capsule):
    if (type(capsule)is not ContactContinuationP2PolicyCapsuleV1 or binding.origin.proactive_contact is not True
            or not 1<=binding.origin.segment_index<binding.origin.segment_count<=3
            or (capsule.segment_index,capsule.segment_count)!=(binding.origin.segment_index,binding.origin.segment_count)
            or 'sha256:'+capsule.whole_manifest_digest!=binding.origin.segment_manifest_digest
            or capsule.continuation.selector.operation_id!=binding.operation_id
            or capsule.continuation.current_effect.effect_id!=binding.origin.effect_id
            or capsule.installation_id!=witness.guard.installation_id or capsule.namespace!=witness.guard.namespace
            or capsule.graph_incarnation!=binding.graph_incarnation or capsule.admission_ref!=binding.origin.admission_ref
            or (capsule.context_digest,capsule.binding_digest,capsule.claimed_receipt_digest,capsule.owner_witness_digest,capsule.authority_snapshot_digest)!=
                tuple(authority_digest(v)for v in(context,binding,claimed,witness,snapshot))):
        raise ValueError('Contact continuation exact five-write reverse binding differs')
    return capsule
