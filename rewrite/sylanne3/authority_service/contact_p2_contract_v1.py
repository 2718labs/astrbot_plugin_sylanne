"""Exact Contact-only reverse capsule; generic reverse handoff wire is unchanged.

This carrier is not a send grant. Its only producer is the installed Core's
current D10/Owner/C09 read, and the reverse channel carries it with the existing
actual context, claimed receipt, Owner witness and Authority snapshot.
"""
from dataclasses import asdict, dataclass
import math

from ..runtime_contracts import NamespaceId, canonical_digest
from .v2_contract import MutationReceiptV2, FencePermitV2
from .d10_contact_policy_service_v1 import (
    D10ContactPolicyOriginalV1, contact_policy_original_from_wire_v1,
    contact_policy_original_to_wire_v1,
)


@dataclass(frozen=True, slots=True)
class ContactP2PolicyCapsuleV1:
    installation_id: str
    namespace: NamespaceId
    graph_incarnation: str
    storage_commitment: str
    admission_ref: str
    batch_ref: str
    plan_ref: str
    context_digest: str
    binding_digest: str
    claimed_receipt_digest: str
    owner_witness_digest: str
    authority_snapshot_digest: str
    policy_original: D10ContactPolicyOriginalV1
    observed_at_utc: float
    schema: str = "sylanne.contact-p2-current-policy-capsule.v1"

    def __post_init__(self):
        if (self.schema!="sylanne.contact-p2-current-policy-capsule.v1" or type(self.namespace) is not NamespaceId
                or type(self.policy_original) is not D10ContactPolicyOriginalV1
                or self.policy_original.namespace!=self.namespace
                or self.policy_original.installation_id!=self.installation_id
                or self.policy_original.action!="issue"
                or type(self.observed_at_utc) not in (float,int) or not math.isfinite(self.observed_at_utc)
                or not self.policy_original.policy.window_start<=self.observed_at_utc<self.policy_original.policy.window_end):
            raise ValueError("Contact P2 actual installed policy capsule differs")
        for value in (self.installation_id,self.graph_incarnation,self.admission_ref,self.batch_ref,self.plan_ref):
            if type(value) is not str or not 1<=len(value)<=4096:
                raise ValueError("Contact P2 capsule actual original locator differs")
        if (type(self.storage_commitment) is not str or len(self.storage_commitment)!=64
                or any(c not in "0123456789abcdef" for c in self.storage_commitment)):
            raise ValueError("Contact P2 actual storage commitment differs")
        for value in (self.context_digest,self.binding_digest,self.claimed_receipt_digest,
                self.owner_witness_digest,self.authority_snapshot_digest):
            if (type(value) is not str or not value.startswith('sha256:') or len(value)!=71
                    or any(c not in "0123456789abcdef" for c in value[7:])):
                raise ValueError("Contact P2 exact Authority current commitment differs")

    @property
    def digest(self):
        return canonical_digest(contact_p2_policy_capsule_to_wire_v1(self))


def contact_p2_policy_capsule_to_wire_v1(value):
    from .contact_continuation_p2_contract_v1 import ContactContinuationP2PolicyCapsuleV1,contact_continuation_p2_capsule_to_wire_v1
    if type(value)is ContactContinuationP2PolicyCapsuleV1:return contact_continuation_p2_capsule_to_wire_v1(value)
    if type(value) is not ContactP2PolicyCapsuleV1:
        raise TypeError("actual Contact P2 policy capsule required")
    raw=asdict(value)
    raw["policy_original"]=contact_policy_original_to_wire_v1(value.policy_original)
    return raw


def contact_p2_policy_capsule_from_wire_v1(raw):
    if type(raw)is dict and raw.get('schema')=='sylanne.contact-continuation-p2-current-policy-capsule.v1':
        from .contact_continuation_p2_contract_v1 import contact_continuation_p2_capsule_from_wire_v1
        return contact_continuation_p2_capsule_from_wire_v1(raw)
    if type(raw) is not dict or set(raw)!=set(ContactP2PolicyCapsuleV1.__dataclass_fields__):
        raise ValueError("exact Contact P2 policy capsule wire required")
    data=dict(raw);data["namespace"]=NamespaceId(**data["namespace"])
    data["policy_original"]=contact_policy_original_from_wire_v1(data["policy_original"])
    value=ContactP2PolicyCapsuleV1(**data)
    if contact_p2_policy_capsule_to_wire_v1(value)!=raw:
        raise ValueError("Contact P2 capsule canonical wire differs")
    return value


def require_exact_contact_p2_policy_capsule_v1(context,binding,claimed,witness,snapshot,capsule):
    from .contact_continuation_p2_contract_v1 import ContactContinuationP2PolicyCapsuleV1,require_exact_contact_continuation_p2_capsule_v1
    if type(capsule)is ContactContinuationP2PolicyCapsuleV1:
        return require_exact_contact_continuation_p2_capsule_v1(context,binding,claimed,witness,snapshot,capsule)
    from .v2_contract import canonical_digest as authority_digest
    if (type(capsule) is not ContactP2PolicyCapsuleV1 or binding.origin.proactive_contact is not True
            or binding.origin.segment_index != 0
            or capsule.installation_id!=witness.guard.installation_id
            or capsule.namespace!=witness.guard.namespace
            or capsule.graph_incarnation!=binding.graph_incarnation
            or capsule.admission_ref!=binding.origin.admission_ref
            or (capsule.context_digest,capsule.binding_digest,capsule.claimed_receipt_digest,
                capsule.owner_witness_digest,capsule.authority_snapshot_digest)!=
               tuple(authority_digest(v) for v in (context,binding,claimed,witness,snapshot))):
        raise ValueError('Contact-only reverse current policy capsule identity differs')
    return capsule


@dataclass(frozen=True, slots=True)
class ContactObservationProjectionReadV1:
    namespace: NamespaceId
    installation_id: str
    graph_path: str
    graph_device: int
    graph_file_id: int
    graph_incarnation: str
    storage_commitment: str
    observed_receipt: 'MutationReceiptV2'
    observed_permit: 'FencePermitV2'
    fence_state: str
    schema: str = 'sylanne.contact-observation-projection-read.v1'

    def __post_init__(self):
        from dataclasses import replace
        from .v2_contract import MutationReceiptV2, FencePermitV2
        from ..graph_coordinator import namespace_ref
        r,p=self.observed_receipt,self.observed_permit
        if (self.schema!='sylanne.contact-observation-projection-read.v1'
                or type(self.namespace) is not NamespaceId or type(r) is not MutationReceiptV2
                or type(p) is not FencePermitV2 or r.durable_state!='committed' or r.pending.phase!='observed'
                or r.pending.binding.origin.proactive_contact is not True
                or r.pending.platform_observation.outcome not in {'accepted','unknown'}
                or p!=replace(r.pending.permit,revision=r.updated_revision,pinned_anchor=r.after_anchor)
                or p.namespace!=namespace_ref(self.namespace) or p.operation!='dispatch'
                or r.pending.binding.graph_incarnation!=self.graph_incarnation
                or self.fence_state not in {'active','finished'}):
            raise ValueError('Contact observation projection needs its actual same-original observed dispatch scope')


def contact_observation_projection_to_wire_v1(value):
    from .v2_contract import to_wire
    if type(value) is not ContactObservationProjectionReadV1:
        raise ValueError('actual Contact observation projection read required')
    raw=asdict(value);raw['observed_receipt']=to_wire(value.observed_receipt);raw['observed_permit']=to_wire(value.observed_permit)
    return raw


def contact_observation_projection_from_wire_v1(raw):
    from .v2_contract import from_wire
    if type(raw) is not dict or set(raw)!=set(ContactObservationProjectionReadV1.__dataclass_fields__):
        raise ValueError('Contact observation projection exact fields differ')
    data=dict(raw);data['namespace']=NamespaceId(**data['namespace'])
    data['observed_receipt']=from_wire(data['observed_receipt']);data['observed_permit']=from_wire(data['observed_permit'])
    value=ContactObservationProjectionReadV1(**data)
    if contact_observation_projection_to_wire_v1(value)!=raw:
        raise ValueError('Contact observation projection canonical wire differs')
    return value
