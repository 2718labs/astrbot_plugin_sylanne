"""Closed Contact continuation observations: later segments, no new dispatch authority."""
from dataclasses import dataclass,fields,asdict,replace
import json
import math
from .contract import identifier
from .v2_contract import CurrentEffectReadV2,AuthorityCurrentEffectSnapshotV2,MutationReceiptV2,FencePermitV2,to_wire,from_wire
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize

MAX_INPUT_BYTES=65536
MAX_OBSERVATION_BYTES=131072

def _digest(value):
    if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):
        raise ValueError('Contact continuation exact digest required')

def _text(value):
    identifier(value,'Contact continuation reference')
    if len(value.encode())>4096:raise ValueError('Contact continuation reference exceeds its original bound')

@dataclass(frozen=True,slots=True)
class ContactContinuationSelectorV1:
    namespace:NamespaceId
    contact_id:str
    segment_index:int
    operation_id:str
    request_digest:str
    policy_id:str
    causal_dedupe_key:str
    def __post_init__(self):
        if type(self.namespace)is not NamespaceId or type(self.segment_index)is not int or not 1<=self.segment_index<=2:
            raise ValueError('Contact continuation requires an exact later-segment selector')
        for name in ('contact_id','operation_id','policy_id'):_text(getattr(self,name))
        if not self.contact_id.startswith('contact:'):raise ValueError('Contact continuation identity differs')
        _digest(self.request_digest);_digest(self.causal_dedupe_key)

@dataclass(frozen=True,slots=True)
class ContactContinuationPrefixFactV1:
    segment_index:int
    operation_id:str
    effect_id:str
    admission_ref:str
    admission_receipt_digest:str
    request_digest:str
    payload_digest:str
    observed_receipt_digest:str
    observed_mutation_id:str
    binding_digest:str
    origin_digest:str
    settlement_digest:str
    fact_digest:str
    accounting_operation_id:str
    accounting_request_digest:str
    finish_request_id:str
    finish_request_digest:str
    observation_outcome:str='accepted'
    budget_status:str='settled'
    accounting_finished:bool=True
    schema:str='authority.contact-continuation-prefix-fact.v1'
    def __post_init__(self):
        if (self.schema!='authority.contact-continuation-prefix-fact.v1' or type(self.segment_index)is not int
                or not 0<=self.segment_index<=1 or self.observation_outcome!='accepted'
                or self.budget_status!='settled' or self.accounting_finished is not True):
            raise ValueError('Contact continuation prefix needs actual accepted/settled/finished accounting')
        for name in ('operation_id','effect_id','admission_ref','observed_mutation_id','accounting_operation_id','finish_request_id'):
            _text(getattr(self,name))
        for name in ('admission_receipt_digest','request_digest','payload_digest','observed_receipt_digest','binding_digest',
                'origin_digest','settlement_digest','fact_digest','accounting_request_digest'):_digest(getattr(self,name))
        if not self.finish_request_digest.startswith('sha256:'):raise ValueError('Contact accounting finish digest lacks its actual encoding')
        _digest(self.finish_request_digest[7:])

@dataclass(frozen=True,slots=True)
class ContactContinuationObservationV1:
    selector:ContactContinuationSelectorV1
    authority_id:str
    authority_namespace:str
    installation_id:str
    subject:str
    attempt_id:str
    permit_digest:str
    anchor_digest:str
    selection_digest:str
    owner_authority_digest:str
    owner_actor:str
    owner_head_digest:str
    owner_revision:int
    principal_epoch:int
    policy_original_ref:str
    policy_original_digest:str
    policy_window_id:str
    policy_version:int
    first_admission_ref:str
    whole_manifest_digest:str
    old_cause_ref:str
    old_cause_digest:str
    same_claim_ref:str
    same_goal_ref:str
    segment_count:int
    inputs_json:str
    prefix:tuple[ContactContinuationPrefixFactV1,...]
    current_effect:CurrentEffectReadV2
    effect_snapshot:AuthorityCurrentEffectSnapshotV2
    observed_at_utc:float
    deadline_utc:float
    observation_ref:str
    signature:str
    schema:str='authority.contact-continuation-observation.v1'
    def __post_init__(self):
        if (self.schema!='authority.contact-continuation-observation.v1' or type(self.selector)is not ContactContinuationSelectorV1
                or type(self.current_effect)is not CurrentEffectReadV2 or type(self.effect_snapshot)is not AuthorityCurrentEffectSnapshotV2):
            raise ValueError('Contact continuation requires its independent exact observation types')
        for name in ('authority_id','authority_namespace','installation_id','subject','attempt_id','owner_actor','owner_head_digest',
                'policy_original_ref','policy_window_id','first_admission_ref','old_cause_ref','same_claim_ref','same_goal_ref'):_text(getattr(self,name))
        for name in ('permit_digest','anchor_digest','selection_digest','owner_authority_digest','policy_original_digest',
                'whole_manifest_digest','old_cause_digest','signature'):_digest(getattr(self,name))
        if (type(self.segment_count)is not int or not self.selector.segment_index<self.segment_count<=3
                or type(self.prefix)is not tuple or len(self.prefix)!=self.selector.segment_index
                or any(type(p)is not ContactContinuationPrefixFactV1 or p.segment_index!=i for i,p in enumerate(self.prefix))
                or self.prefix[0].admission_ref!=self.first_admission_ref
                or type(self.owner_revision)is not int or self.owner_revision<1
                or type(self.principal_epoch)is not int or self.principal_epoch<0
                or type(self.policy_version)is not int or self.policy_version<1
                or any(type(v)not in(int,float)or not math.isfinite(v)for v in(self.observed_at_utc,self.deadline_utc))
                or not self.observed_at_utc<self.deadline_utc):
            raise ValueError('Contact continuation whole manifest, full prefix or original expiry differs')
        if type(self.inputs_json)is not str or len(self.inputs_json.encode())>MAX_INPUT_BYTES:
            raise ValueError('Contact continuation metadata exceeds its fixed bound')
        values=json.loads(self.inputs_json);selected=self.selector
        exact={'namespace':asdict(selected.namespace),'contact_id':selected.contact_id,'segment_index':selected.segment_index,
            'operation_id':selected.operation_id,'request_digest':selected.request_digest,'old_causal_dedupe_key':selected.causal_dedupe_key,
            'attempt_id':self.attempt_id,'permit_digest':self.permit_digest,'segment_count':self.segment_count,
            'first_admission_ref':self.first_admission_ref,'whole_manifest_digest':self.whole_manifest_digest,
            'old_cause_ref':self.old_cause_ref,'old_cause_digest':self.old_cause_digest,
            'same_claim_ref':self.same_claim_ref,'same_goal_ref':self.same_goal_ref}
        if canonical_serialize(values)!=self.inputs_json or any(values[k]!=v for k,v in exact.items())or self.deadline_utc>values['deadline_utc']:
            raise ValueError('Contact continuation metadata changed its actual Source/attempt tuple')
        effect,snapshot=self.current_effect,self.effect_snapshot
        if (effect.effect_id!=values['effect_id'] or effect.state!='absent' or effect.authority_id!=self.authority_id
                or effect.namespace!=self.authority_namespace or snapshot.authority_id!=self.authority_id
                or snapshot.namespace!=self.authority_namespace or snapshot.coverage!='complete'
                or snapshot.permit_digest!='sha256:'+self.permit_digest
                or snapshot.anchor.activation_generation!=effect.activation_generation
                or (effect.execution_head_seq,effect.execution_head_digest)!=(snapshot.execution_head_seq,snapshot.execution_head_digest)):
            raise ValueError('Contact continuation new effect is not independently absent under its actual WRITE')
        if self.observation_ref!='contact-continuation-observation:'+canonical_digest(self.material()):
            raise ValueError('Contact continuation observation reference differs')
    def material(self):return {k:v for k,v in contact_continuation_to_wire_v1(self).items()if k not in {'observation_ref','signature'}}
    @property
    def digest(self):return canonical_digest(contact_continuation_to_wire_v1(self))

@dataclass(frozen=True,slots=True)
class ContactContinuationObservationProjectionReadV1:
    namespace:NamespaceId
    installation_id:str
    graph_path:str
    graph_device:int
    graph_file_id:int
    graph_incarnation:str
    storage_commitment:str
    observed_receipt:MutationReceiptV2
    observed_permit:FencePermitV2
    fence_state:str
    continuation:ContactContinuationObservationV1
    prefix:tuple[ContactContinuationPrefixFactV1,...]
    schema:str='sylanne.contact-continuation-observation-projection-read.v1'
    def __post_init__(self):
        r,p,o=self.observed_receipt,self.observed_permit,self.continuation
        if (self.schema!='sylanne.contact-continuation-observation-projection-read.v1' or type(self.namespace)is not NamespaceId
                or type(r)is not MutationReceiptV2 or type(p)is not FencePermitV2 or type(o)is not ContactContinuationObservationV1
                or r.durable_state!='committed' or r.pending.phase!='observed' or p.operation!='dispatch'
                or p!=replace(r.pending.permit,revision=r.updated_revision,pinned_anchor=r.after_anchor)
                or self.fence_state not in {'active','finished'} or r.pending.binding.origin.proactive_contact is not True
                or r.pending.platform_observation.outcome not in {'accepted','unknown'}
                or (r.pending.binding.origin.footprint.contact_id,r.pending.binding.operation_id,r.pending.binding.origin.segment_index,
                    r.pending.binding.origin.segment_count,r.pending.binding.origin.segment_manifest_digest)!=(
                    o.selector.contact_id,o.selector.operation_id,o.selector.segment_index,o.segment_count,'sha256:'+o.whole_manifest_digest)
                or p.effect_id!=o.current_effect.effect_id or o.selector.namespace!=self.namespace
                or o.installation_id!=self.installation_id or p.namespace!='/'.join(self.namespace.as_tuple)
                or r.pending.binding.graph_incarnation!=self.graph_incarnation or self.prefix!=o.prefix):
            raise ValueError('Contact continuation projection changed its actual later-segment dispatch original')
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

_TYPES={ContactContinuationSelectorV1,ContactContinuationPrefixFactV1,ContactContinuationObservationV1,ContactContinuationObservationProjectionReadV1}

def contact_continuation_to_wire_v1(value):
    if type(value)not in _TYPES:raise TypeError('Unregistered Contact continuation wire type')
    result={f.name:getattr(value,f.name)for f in fields(value)}
    if 'namespace'in result:result['namespace']=asdict(value.namespace)
    for name in ('selector','continuation'):
        if name in result:result[name]=contact_continuation_to_wire_v1(result[name])
    if 'prefix'in result:result['prefix']=[contact_continuation_to_wire_v1(p)for p in result['prefix']]
    for name in ('current_effect','effect_snapshot','observed_receipt','observed_permit'):
        if name in result:result[name]=to_wire(result[name])
    return result

def contact_continuation_from_wire_v1(raw,kind):
    if kind not in _TYPES or type(raw)is not dict or set(raw)!={f.name for f in fields(kind)}:
        raise ValueError('Contact continuation exact closed wire fields differ')
    value=dict(raw)
    if 'namespace'in value:value['namespace']=NamespaceId(**value['namespace'])
    for name,cls in (('selector',ContactContinuationSelectorV1),('continuation',ContactContinuationObservationV1)):
        if name in value:value[name]=contact_continuation_from_wire_v1(value[name],cls)
    if 'prefix'in value:
        if type(value['prefix'])is not list:raise ValueError('Contact continuation requires its canonical full prefix array')
        value['prefix']=tuple(contact_continuation_from_wire_v1(p,ContactContinuationPrefixFactV1)for p in value['prefix'])
    for name in ('current_effect','effect_snapshot','observed_receipt','observed_permit'):
        if name in value:value[name]=from_wire(value[name])
    result=kind(**value)
    if contact_continuation_to_wire_v1(result)!=raw:raise ValueError('Contact continuation wire is not canonical')
    return result
