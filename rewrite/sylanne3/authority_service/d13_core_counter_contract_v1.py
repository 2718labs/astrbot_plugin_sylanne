"""Closed V7 frame intent and independently measured Core full-HTTP evidence.

DTO construction carries no current-source, CPU or model-admission authority.
Only the installed service reconstructs, measures and signs these originals.
"""
from __future__ import annotations
from dataclasses import asdict,dataclass,fields
import base64
import json
import math
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from ..runtime_contracts import NamespaceId,VersionedRef,canonical_digest,canonical_serialize
from ..model_broker.natural_reply import NaturalReplyInstallationV2
from ..model_broker.natural_reply_history_v7 import TEMPLATE_DIGEST

SELECTOR_SCHEMA='sylanne3.d13.current-wire-count-selector.v1'
PREPARE_SCHEMA='sylanne3.d13.current-frame-prepare-selector.v7'
FRAME_SCHEMA='sylanne3.d13.core-frame-intent-header.v7'
EVIDENCE_SCHEMA='sylanne3.d13.core-full-wire-evidence.v1'
ENVELOPE_SCHEMA='sylanne3.d13.core-full-wire-envelope.v1'
POLICY_SCHEMA='sylanne3.d13.installed-core-wire-policy.v7'
SIGNING_DOMAIN=(EVIDENCE_SCHEMA+chr(0)).encode('utf-8')
MAX_RPC_BYTES=65536
MAX_COUNTER_INPUT_BYTES=16*1024*1024
HTTP_BINDING_SCHEMA='sylanne3.d13.late-model-request-digest-http.v1'
HTTP_TEMPLATE_SCHEMA='sylanne3.d13.provider-http-template.v1'
HTTP_BINDING_CONTRACT={
    'schema':HTTP_BINDING_SCHEMA,
    'late_path':['metadata','sylanne_request_digest'],
    'late_value':'actual ModelCallRequest.digest',
    'alphabet':'0123456789abcdef','characters':64,
    'fixed_metadata':['sylanne_call_id','sylanne_billing_contract'],
    'provider_fields':['model','messages','stream','max_completion_tokens','metadata'],
    'admission':'exact actual SDK wire and same current model reservation before first send',
}
HTTP_BINDING_CONTRACT_DIGEST=canonical_digest(HTTP_BINDING_CONTRACT)


def _text(value,name):
    if type(value) is not str or not value:raise ValueError('nonempty '+name+' required')

def _sha(value,name):
    if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('exact SHA-256 '+name+' required')

def _uint(value,name,minimum=0):
    if type(value) is not int or value<minimum:raise ValueError('integer '+name+' differs')

def _time(value,name):
    if type(value) not in (int,float) or not math.isfinite(value):raise ValueError('finite '+name+' required')

def _bounded(value):
    if len(canonical_serialize(asdict(value)).encode('utf-8'))>MAX_RPC_BYTES:
        raise ValueError('closed counter descriptor exceeds existing RPC limit')


@dataclass(frozen=True,slots=True)
class D13CurrentFramePrepareSelectorV7:
    install_id:str
    authority_namespace:str
    namespace:NamespaceId
    c02_operation_id:str
    plan_ref:VersionedRef
    counter_operation_id:str
    schema:str=PREPARE_SCHEMA
    def __post_init__(self):
        if self.schema!=PREPARE_SCHEMA or type(self.namespace) is not NamespaceId or type(self.plan_ref) is not VersionedRef:
            raise ValueError('exact V7 current-frame prepare selector required')
        for name in ('install_id','authority_namespace','c02_operation_id','counter_operation_id'):_text(getattr(self,name),name)
        from ..graph_types import AtomKey
        key=AtomKey.from_token(self.plan_ref.ref)
        if key.type_name!='d08.natural_expression_plan.v2' or NamespaceId.from_key(key)!=self.namespace or self.plan_ref.version<1:
            raise ValueError('prepare selector names another actual plan namespace or type')
        _bounded(self)


@dataclass(frozen=True,slots=True)
class D13CurrentWireCountSelectorV1:
    install_id:str
    authority_namespace:str
    frame_intent_id:str
    frame_intent_digest:str
    counter_operation_id:str
    expected_raw_authority_digest:str
    expected_compressed_authority_digest:str|None
    expected_raw_http_template_digest:str
    expected_compressed_http_template_digest:str|None
    schema:str=SELECTOR_SCHEMA
    def __post_init__(self):
        if self.schema!=SELECTOR_SCHEMA:raise ValueError('exact current-wire selector schema required')
        for name in ('install_id','authority_namespace','frame_intent_id','counter_operation_id'):_text(getattr(self,name),name)
        for name in ('frame_intent_digest','expected_raw_authority_digest','expected_raw_http_template_digest'):_sha(getattr(self,name),name)
        pair=(self.expected_compressed_authority_digest,self.expected_compressed_http_template_digest)
        if (pair[0] is None)!=(pair[1] is None):raise ValueError('absent compressed variant must have no partial commitments')
        if pair[0] is not None:
            _sha(pair[0],'expected_compressed_authority_digest');_sha(pair[1],'expected_compressed_http_template_digest')
        _bounded(self)
    @property
    def selector_digest(self):return canonical_digest(self)


@dataclass(frozen=True,slots=True)
class InstalledD13WirePolicyV7:
    installation:NaturalReplyInstallationV2
    counter_public_key_hex:str
    counter_key_id:str
    counter_policy_id:str
    counter_policy_version:int
    counter_policy_fingerprint:str
    tokenizer_fingerprint:str
    wire_policy_fingerprint:str
    serializer_fingerprint:str
    applicability_fingerprint:str
    context_limit_tokens:int
    tool_reserve_tokens:int
    uncached_input_microusd_per_million:int
    cache_write_input_microusd_per_million:int
    output_microusd_per_million:int
    storage_microusd_upper:int
    allow_conservative_switch:bool=False
    max_input_tokens:int=6000
    max_slots:int=256
    max_blocks:int=4
    wire_policy_id:str='natural.v7.core-complete-no-tools'
    template_digest:str=TEMPLATE_DIGEST
    http_binding_contract_digest:str=HTTP_BINDING_CONTRACT_DIGEST
    schema:str=POLICY_SCHEMA
    def __post_init__(self):
        if (type(self.installation) is not NaturalReplyInstallationV2 or self.schema!=POLICY_SCHEMA
                or self.wire_policy_id!='natural.v7.core-complete-no-tools' or self.template_digest!=TEMPLATE_DIGEST
                or self.http_binding_contract_digest!=HTTP_BINDING_CONTRACT_DIGEST
                or type(self.allow_conservative_switch) is not bool):raise ValueError('exact installed V7 wire policy required')
        for name in ('counter_public_key_hex','counter_policy_fingerprint','tokenizer_fingerprint','wire_policy_fingerprint','serializer_fingerprint','applicability_fingerprint'):_sha(getattr(self,name),name)
        for name in ('counter_key_id','counter_policy_id'):_text(getattr(self,name),name)
        _uint(self.counter_policy_version,'counter_policy_version',1)
        for name in ('context_limit_tokens','max_input_tokens','max_slots','max_blocks'):_uint(getattr(self,name),name,1)
        for name in ('tool_reserve_tokens','uncached_input_microusd_per_million','cache_write_input_microusd_per_million','output_microusd_per_million','storage_microusd_upper'):_uint(getattr(self,name),name)
        if (self.max_input_tokens>6000 or self.context_limit_tokens>7024 or self.installation.max_output_tokens>1024
                or self.max_slots>256 or self.max_blocks>4
                or self.context_limit_tokens<=self.installation.max_output_tokens+self.tool_reserve_tokens):
            raise ValueError('V7 policy cannot enlarge the installed model or collection ceilings')
        _bounded(self)
    @property
    def policy_digest(self):return canonical_digest(self)


@dataclass(frozen=True,slots=True)
class D13CorePaidBlockBindingV1:
    metadata_ref: str
    metadata_revision: int
    metadata_digest: str
    payload_digest: str
    plan_ref: str
    plan_digest: str
    paid_original_ref: str
    paid_original_digest: str
    expires_at_utc: float
    turn_first: int
    turn_last: int

    def __post_init__(self):
        for name in ('metadata_ref','plan_ref','paid_original_ref'):_text(getattr(self,name),name)
        for name in ('metadata_digest','payload_digest','plan_digest','paid_original_digest'):_sha(getattr(self,name),name)
        _uint(self.metadata_revision,'metadata_revision',1)
        _uint(self.turn_first,'turn_first');_uint(self.turn_last,'turn_last')
        _time(self.expires_at_utc,'expires_at_utc')
        if self.turn_first>self.turn_last:raise ValueError('counter paid block range differs')


@dataclass(frozen=True,slots=True)
class D13CoreFrameIntentHeaderV7:
    install_id:str
    authority_id:str
    authority_namespace:str
    namespace:NamespaceId
    frame_intent_id:str
    frame_intent_digest:str
    counter_operation_id:str
    counter_nonce:str
    c02_operation_id:str
    plan_ref:VersionedRef
    job_id:str
    step_index:int
    generation_call_id:str
    activation_generation:int
    storage_generation:int
    selected_manifest_digest:str
    selected_pointer_version:int
    owner_responsibility_digest:str
    owner_grant_digest:str
    source_scope_digest:str
    parent_budget_lease_ref:str
    budget_grant_digest:str
    cpu_reservation_ref:str
    cpu_reservation_digest:str
    policy_digest:str
    template_digest:str
    collection_digest:str
    collection_snapshot_commitment:str
    blockset_digest:str
    billing_contract_digest:str
    frozen_at_utc:float
    expires_at_utc:float
    prospective_plan_deadline_utc:float
    raw_authority_digest:str
    compressed_authority_digest:str|None
    raw_http_template_digest:str
    compressed_http_template_digest:str|None
    block_bindings:tuple[D13CorePaidBlockBindingV1,...]=()
    schema:str=FRAME_SCHEMA
    def __post_init__(self):
        if self.schema!=FRAME_SCHEMA or type(self.namespace) is not NamespaceId or type(self.plan_ref) is not VersionedRef:
            raise ValueError('exact Core V7 frame intent header required')
        for name in ('install_id','authority_id','authority_namespace','frame_intent_id','counter_operation_id','counter_nonce','c02_operation_id','job_id','generation_call_id','parent_budget_lease_ref','cpu_reservation_ref'):_text(getattr(self,name),name)
        for field in fields(self):
            value=getattr(self,field.name)
            if field.name.endswith('_digest') and not (field.name in {'compressed_authority_digest','compressed_http_template_digest'} and value is None):
                _sha(value,field.name)
        for name in ('step_index','storage_generation','selected_pointer_version'):_uint(getattr(self,name),name)
        _sha(self.collection_snapshot_commitment,'collection_snapshot_commitment')
        _uint(self.activation_generation,'activation_generation',1)
        _time(self.frozen_at_utc,'frozen_at_utc');_time(self.expires_at_utc,'expires_at_utc')
        _time(self.prospective_plan_deadline_utc,'prospective_plan_deadline_utc')
        if self.expires_at_utc>self.prospective_plan_deadline_utc:
            raise ValueError('counter frame exceeds its original prospective plan lifetime')
        if self.template_digest!=TEMPLATE_DIGEST or not self.frozen_at_utc<self.expires_at_utc:
            raise ValueError('Core V7 frame template or unchanged absolute lifetime differs')
        if (type(self.block_bindings) is not tuple or len(self.block_bindings)>4
                or any(type(v) is not D13CorePaidBlockBindingV1 for v in self.block_bindings)
                or self.blockset_digest!=canonical_digest({'schema':'sylanne3.d13.core-paid-blockset.v7',
                    'bindings':[asdict(v) for v in self.block_bindings]})):
            raise ValueError('counter header exact bounded paid block bindings differ')
        if (self.compressed_authority_digest is None)!=(self.compressed_http_template_digest is None):
            raise ValueError('counter header compressed commitments must be wholly absent or present')
        _bounded(self)


@dataclass(frozen=True,slots=True)
class D13CoreFullWireEvidenceV1:
    frame:D13CoreFrameIntentHeaderV7
    selector_digest:str
    raw_authority_digest:str
    compressed_authority_digest:str|None
    raw_request_digest:str
    compressed_request_digest:str|None
    raw_http_template_digest:str
    compressed_http_template_digest:str|None
    raw_http_bytes:int
    compressed_http_bytes:int|None
    token_evidence:str
    raw_lower_tokens:int
    raw_upper_tokens:int
    compressed_lower_tokens:int|None
    compressed_upper_tokens:int|None
    counter_policy_fingerprint:str
    tokenizer_fingerprint:str
    wire_policy_fingerprint:str
    serializer_fingerprint:str
    applicability_fingerprint:str
    cpu_execution_id:str
    cpu_worker_binding_digest:str
    cpu_claim_digest:str
    cpu_input_digest:str
    cpu_terminal_digest:str
    actual_cpu_ns:int
    cpu_settlement_ref:str
    cpu_settlement_digest:str
    d02_accounting_digest:str
    d11_accounting_digest:str
    http_binding_contract_digest:str=HTTP_BINDING_CONTRACT_DIGEST
    schema:str=EVIDENCE_SCHEMA
    def __post_init__(self):
        if (self.schema!=EVIDENCE_SCHEMA or type(self.frame) is not D13CoreFrameIntentHeaderV7
                or self.http_binding_contract_digest!=HTTP_BINDING_CONTRACT_DIGEST):
            raise ValueError('exact new Core full-wire evidence required')
        for field in fields(self):
            value=getattr(self,field.name)
            if field.name.endswith(('_digest','_fingerprint')) and value is not None:_sha(value,field.name)
        for name in ('cpu_execution_id','cpu_settlement_ref'):_text(getattr(self,name),name)
        _uint(self.raw_http_bytes,'raw_http_bytes',1);_uint(self.raw_lower_tokens,'raw_lower_tokens')
        _uint(self.raw_upper_tokens,'raw_upper_tokens',1);_uint(self.actual_cpu_ns,'actual_cpu_ns')
        if self.raw_http_bytes>MAX_COUNTER_INPUT_BYTES or self.raw_lower_tokens>self.raw_upper_tokens:
            raise ValueError('raw full-HTTP size or count interval differs')
        optional=(self.compressed_authority_digest,self.compressed_request_digest,self.compressed_http_template_digest,
                  self.compressed_http_bytes,self.compressed_lower_tokens,self.compressed_upper_tokens)
        if any(v is None for v in optional) and not all(v is None for v in optional):
            raise ValueError('compressed variant evidence must be completely present or absent')
        if optional[0] is not None:
            _uint(self.compressed_http_bytes,'compressed_http_bytes',1)
            _uint(self.compressed_lower_tokens,'compressed_lower_tokens');_uint(self.compressed_upper_tokens,'compressed_upper_tokens',1)
            if self.compressed_http_bytes>MAX_COUNTER_INPUT_BYTES or self.compressed_lower_tokens>self.compressed_upper_tokens:
                raise ValueError('compressed full-HTTP size or count interval differs')
        if self.token_evidence!='bounded_full_wire':
            raise ValueError('whole-request count evidence kind differs')
        _bounded(self)


@dataclass(frozen=True,slots=True)
class D13CoreFullWireEnvelopeV1:
    payload:D13CoreFullWireEvidenceV1
    key_id:str
    signature:str
    schema:str=ENVELOPE_SCHEMA
    def __post_init__(self):
        if self.schema!=ENVELOPE_SCHEMA or type(self.payload) is not D13CoreFullWireEvidenceV1:
            raise ValueError('exact Core full-wire signature envelope required')
        _text(self.key_id,'key_id')
        if type(self.signature) is not str or len(base64.b64decode(self.signature,validate=True))!=64:
            raise ValueError('exact Ed25519 full-wire signature required')
        _bounded(self)
    @property
    def evidence_digest(self):return canonical_digest(self)


@dataclass(frozen=True,slots=True)
class D13CoreHTTPLateBindingV1:
    namespace:NamespaceId
    frame_intent_id:str
    frame_intent_digest:str
    counter_operation_id:str
    counter_evidence_digest:str
    variant:str
    call_id:str
    model_request_digest:str
    http_template_digest:str
    actual_http_digest:str
    actual_http_bytes:int
    parent_budget_lease_ref:str
    model_reservation_digest:str
    model_job_id:str
    expires_at_utc:float
    http_binding_contract_digest:str=HTTP_BINDING_CONTRACT_DIGEST
    schema:str='sylanne3.d13.actual-http-late-binding.v1'
    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or self.variant not in {'raw','compressed'}
                or self.schema!='sylanne3.d13.actual-http-late-binding.v1'
                or self.http_binding_contract_digest!=HTTP_BINDING_CONTRACT_DIGEST):
            raise ValueError('exact current HTTP late-binding original required')
        for name in ('frame_intent_id','counter_operation_id','call_id','parent_budget_lease_ref','model_job_id'):_text(getattr(self,name),name)
        for f in fields(self):
            if f.name.endswith('_digest'):_sha(getattr(self,f.name),f.name)
        _uint(self.actual_http_bytes,'actual_http_bytes',1);_time(self.expires_at_utc,'expires_at_utc')
        _bounded(self)
    @property
    def late_binding_digest(self):return canonical_digest(self)


_CONTRACTS=(D13CurrentFramePrepareSelectorV7,D13CurrentWireCountSelectorV1,InstalledD13WirePolicyV7,
            D13CoreFrameIntentHeaderV7,D13CoreFullWireEvidenceV1,D13CoreFullWireEnvelopeV1,D13CoreHTTPLateBindingV1)


def d13_core_counter_from_wire_v1(value,cls):
    if cls not in _CONTRACTS or type(value) is not dict or set(value)!={f.name for f in fields(cls)}:
        raise ValueError('Core counter exact closed wire fields required')
    raw=dict(value)
    if 'namespace' in raw:raw['namespace']=NamespaceId(**raw['namespace'])
    if 'plan_ref' in raw:raw['plan_ref']=VersionedRef(**raw['plan_ref'])
    if 'source_ref' in raw:raw['source_ref']=VersionedRef(**raw['source_ref'])
    if cls is D13CoreFrameIntentHeaderV7:
        raw['block_bindings']=tuple(D13CorePaidBlockBindingV1(**v) for v in raw['block_bindings'])
    if cls is InstalledD13WirePolicyV7:raw['installation']=NaturalReplyInstallationV2(**raw['installation'])
    if cls is D13CoreFullWireEvidenceV1:raw['frame']=d13_core_counter_from_wire_v1(raw['frame'],D13CoreFrameIntentHeaderV7)
    if cls is D13CoreFullWireEnvelopeV1:raw['payload']=d13_core_counter_from_wire_v1(raw['payload'],D13CoreFullWireEvidenceV1)
    return cls(**raw)


def installed_d13_wire_policy_from_payload_v7(value):
    return d13_core_counter_from_wire_v1(value,InstalledD13WirePolicyV7)


def _verify_signed_d13_core_wire_origin_v1(policy,envelope,*,selector,frame):
    """Exact signature and original scope binding, with no current admission."""
    if (type(policy) is not InstalledD13WirePolicyV7 or type(selector) is not D13CurrentWireCountSelectorV1
            or type(frame) is not D13CoreFrameIntentHeaderV7):raise ValueError('actual exact V7 counter policy/selector/frame required')
    if type(envelope) is dict:envelope=d13_core_counter_from_wire_v1(envelope,D13CoreFullWireEnvelopeV1)
    if type(envelope) is not D13CoreFullWireEnvelopeV1:raise ValueError('exact Core counter envelope required')
    p=envelope.payload
    if (envelope.key_id!=policy.counter_key_id or p.frame!=frame or p.selector_digest!=selector.selector_digest
            or frame.install_id!=policy.installation.installation_id or frame.policy_digest!=policy.policy_digest
            or frame.template_digest!=policy.template_digest or p.http_binding_contract_digest!=policy.http_binding_contract_digest
            or (selector.install_id,selector.authority_namespace,selector.frame_intent_id,selector.frame_intent_digest,selector.counter_operation_id)
                !=(frame.install_id,frame.authority_namespace,frame.frame_intent_id,frame.frame_intent_digest,frame.counter_operation_id)
            or (p.raw_authority_digest,p.compressed_authority_digest,p.raw_http_template_digest,p.compressed_http_template_digest)
                !=(selector.expected_raw_authority_digest,selector.expected_compressed_authority_digest,
                   selector.expected_raw_http_template_digest,selector.expected_compressed_http_template_digest)):
        raise ValueError('signed Core count belongs to another scope, pair, operation or original lifetime')
    for name in ('counter_policy_fingerprint','tokenizer_fingerprint','wire_policy_fingerprint','serializer_fingerprint','applicability_fingerprint'):
        if getattr(p,name)!=getattr(policy,name):raise ValueError('signed Core counter applicability or installed asset differs')
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(policy.counter_public_key_hex)).verify(
        base64.b64decode(envelope.signature,validate=True),SIGNING_DOMAIN+canonical_serialize(asdict(p)).encode('utf-8'))
    return p


def verify_signed_d13_core_wire_evidence_v1(policy,envelope,*,selector,frame,now_utc):
    """Verify currently usable evidence; Source/job/admission remain independent."""
    _time(now_utc,'now_utc')
    payload=_verify_signed_d13_core_wire_origin_v1(policy,envelope,selector=selector,frame=frame)
    if not frame.frozen_at_utc<=now_utc<frame.expires_at_utc:
        raise ValueError('signed Core count belongs to another scope, pair, operation or original lifetime')
    return payload


def verify_historical_d13_core_wire_origin_v1(policy,envelope,*,selector,frame):
    """Authenticate recorded counter bytes. Grants no present execution permission.

    Historical event times are checked by the named original-chain consumer;
    this entry never accepts a substituted wall-clock time or issues admission.
    """
    return _verify_signed_d13_core_wire_origin_v1(policy,envelope,selector=selector,frame=frame)


class ClaimedD13CounterInputV1:
    """Process-local mechanical input issued after Core's durable claim.

    This object is deliberately absent from the wire codec. Possession is not
    authorization: every use rereads the issuing Core service's current claim.
    Program, manifest and cgroup roots belong to the installed worker constructor.
    """
    __slots__ = ('binding', 'claim', 'input_bytes', 'input_digest',
                 'expires_at_utc', 'cpu_ms_ceiling', 'installation_id',
                 'authority_namespace', '_registry', '_sealed')

    def __new__(cls, *args, **kwargs):
        raise TypeError('counter inputs are issued by the installed Core service')

    def __setattr__(self, name, value):
        raise AttributeError('claimed counter input is immutable')

    def require_current(self):
        self._registry.require_current(self)

    def require_recorded_execution_origin(self):
        self._registry.require_recorded_execution_origin(self)


class _D13CounterClaimRegistryV1:
    """Private live handles; its validator is bound by Core composition only."""
    def __init__(self, current_claim_validator, recorded_execution_validator):
        self._current_claim_validator = current_claim_validator
        self._recorded_execution_validator = recorded_execution_validator
        self._live = {}

    def issue(self, *, binding, claim, input_bytes, expires_at_utc,
              installation_id, authority_namespace, cpu_ms_ceiling=1000):
        import hashlib
        from .internal_work_contract import InternalWorkBindingV1, InternalWorkClaimV1
        if (type(binding) is not InternalWorkBindingV1
                or type(claim) is not InternalWorkClaimV1
                or claim.binding_digest != binding.binding_digest
                or authority_namespace != binding.namespace
                or type(input_bytes) is not bytes
                or not 0 < len(input_bytes) <= MAX_COUNTER_INPUT_BYTES
                or type(cpu_ms_ceiling) is not int or cpu_ms_ceiling != 1000):
            raise ValueError('actual D13 claim, bounded input and fixed CPU ceiling required')
        digest = hashlib.sha256(input_bytes).hexdigest()
        if binding.input_digest != digest:
            raise ValueError('counter input differs from the durable work binding')
        self._current_claim_validator(binding, claim, digest, expires_at_utc)
        result = object.__new__(ClaimedD13CounterInputV1)
        for name, value in (
            ('binding', binding), ('claim', claim), ('input_bytes', input_bytes),
            ('input_digest', digest), ('expires_at_utc', expires_at_utc),
            ('cpu_ms_ceiling', cpu_ms_ceiling), ('installation_id', installation_id),
            ('authority_namespace', authority_namespace), ('_registry', self),
            ('_sealed', True),
        ):
            object.__setattr__(result, name, value)
        self._live[id(result)] = result
        return result

    def require_current(self, claimed):
        if (type(claimed) is not ClaimedD13CounterInputV1
                or self._live.get(id(claimed)) is not claimed
                or claimed._registry is not self):
            raise ValueError('counter capsule is not a live installed Core original')
        self._current_claim_validator(claimed.binding, claimed.claim,
                                      claimed.input_digest, claimed.expires_at_utc)

    def require_recorded_execution_origin(self, claimed):
        if (type(claimed) is not ClaimedD13CounterInputV1
                or self._live.get(id(claimed)) is not claimed or claimed._registry is not self):
            raise ValueError('counter cost observation is detached from its original installed capsule')
        self._recorded_execution_validator(claimed.binding, claimed.claim, claimed.input_digest,
                                           claimed.installation_id, claimed.authority_namespace)

    def retire(self, claimed):
        if self._live.get(id(claimed)) is claimed:
            del self._live[id(claimed)]


@dataclass(frozen=True, slots=True)
class D13CounterCPUPrepareInstructionV1:
    """Bounded Core draft locator for W01's independent CPU preparation fence."""
    namespace: NamespaceId
    install_id: str
    authority_namespace: str
    frame_intent_id: str
    frame_intent_digest: str
    counter_operation_id: str
    c02_operation_id: str
    plan_ref: VersionedRef
    source_ref: VersionedRef
    prospective_plan_digest: str
    prospective_plan_deadline_utc: float
    input_digest: str
    source_scope_digest: str
    owner_responsibility_digest: str
    owner_grant_digest: str
    parent_budget_lease_ref: str
    budget_grant_digest: str
    activity_id: str
    job_id: str
    execution_id: str
    algorithm_id: str
    algorithm_build_digest: str
    policy_ref: str
    cpu_policy_id: str
    cpu_policy_version: int
    body_policy_id: str
    body_policy_version: int
    generation_call_id: str
    activation_generation: int
    frozen_at_utc: float
    expires_at_utc: float
    cpu_ms_ceiling: int = 1000
    schema: str = 'sylanne3.d13.counter-cpu-prepare-instruction.v1'

    def __post_init__(self):
        if (self.schema != 'sylanne3.d13.counter-cpu-prepare-instruction.v1'
                or type(self.namespace) is not NamespaceId
                or type(self.plan_ref) is not VersionedRef
                or type(self.source_ref) is not VersionedRef
                or self.algorithm_id != 'd13.full_http_counter.v1'
                or type(self.cpu_ms_ceiling) is not int or self.cpu_ms_ceiling != 1000):
            raise ValueError('exact independent D13 CPU preparation instruction required')
        for field in fields(self):
            if field.name.endswith('_digest'):
                _sha(getattr(self, field.name), field.name)
        _uint(self.cpu_policy_version, 'cpu_policy_version', 1)
        _uint(self.body_policy_version, 'body_policy_version', 1)
        _uint(self.activation_generation, 'activation_generation', 1)
        _time(self.frozen_at_utc, 'frozen_at_utc'); _time(self.expires_at_utc, 'expires_at_utc')
        _time(self.prospective_plan_deadline_utc, 'prospective_plan_deadline_utc')
        if not self.frozen_at_utc < self.expires_at_utc <= self.prospective_plan_deadline_utc:
            raise ValueError('counter instruction lost its original absolute lifetime')
        _bounded(self)


@dataclass(frozen=True, slots=True)
class D13CounterAwaitingAccountingV1:
    namespace: NamespaceId
    frame_intent_id: str
    frame_intent_digest: str
    counter_operation_id: str
    binding_digest: str
    terminal_digest: str
    terminal_receipt_digest: str
    status: str
    schema: str = 'sylanne3.d13.counter-awaiting-accounting.v1'

    def __post_init__(self):
        if (self.schema != 'sylanne3.d13.counter-awaiting-accounting.v1'
                or type(self.namespace) is not NamespaceId
                or self.status not in {'completed', 'failed', 'unknown'}):
            raise ValueError('exact actual counter terminal accounting locator required')
        for field in fields(self):
            if field.name.endswith('_digest'):
                _sha(getattr(self, field.name), field.name)
        _bounded(self)


_CONTRACTS += (D13CounterCPUPrepareInstructionV1, D13CounterAwaitingAccountingV1)
