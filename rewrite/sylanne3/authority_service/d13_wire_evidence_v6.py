"""Independent v6 complete-wire evidence; old v1 signatures/contracts stay exact."""
from dataclasses import asdict, dataclass, fields, replace
import base64
import json
import math
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from ..model_broker.natural_reply import NaturalReplyInstallationV2
from ..model_broker.natural_reply_history_v6 import (FrozenNaturalReplyRequestV6,freeze_natural_reply_request_v6,TEMPLATE_DIGEST)
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime.d13_current_collection_v6 import read_current_d13_collection_v6
from ..runtime.installed_d13_natural_frame_v6 import NaturalHistoryPairV6,read_current_derived_blocks_v6
from .d13_derived_paid_block_verifier_v2 import InstalledD13DerivedPaidBlockVerifierV2
from .d13_wire_evidence_v1 import (D13ForegroundBudgetBindingV1,D13ForegroundBudgetPreparationV1,
    _verify_foreground_budget,_integer,_digest)

WIRE_POLICY='natural.v6.complete-no-tools'
EVIDENCE_SCHEMA='sylanne3.d13.signed-full-wire-evidence.v6'
SIGNING_DOMAIN=(EVIDENCE_SCHEMA+'\0').encode()
TABLE='graph_d13_wire_evidence_v6'

@dataclass(frozen=True, slots=True)
class InstalledD13WirePolicyV6:
    """Only load from the administrator-protected installation profile.

    The counter key authenticates complete-wire count/bound responses, including
    provider serialization overhead. An arbitrary integer count is insufficient.
    Pricing is the verified maximum of uncached input or cache-write input, plus
    explicit storage and output bounds. All rates are integer micro-USD/million.
    """
    installation: NaturalReplyInstallationV2
    counter_public_key_hex: str
    counter_policy_id: str
    counter_policy_version: int
    counter_policy_fingerprint: str
    tokenizer_fingerprint: str
    wire_policy_fingerprint: str
    context_limit_tokens: int
    tool_reserve_tokens: int
    uncached_input_microusd_per_million: int
    cache_write_input_microusd_per_million: int
    output_microusd_per_million: int
    storage_microusd_upper: int
    allow_conservative_switch: bool = False
    max_slots: int = 256
    max_blocks: int = 4
    wire_policy_id: str = WIRE_POLICY
    template_digest: str = TEMPLATE_DIGEST
    schema: str = "sylanne3.d13.installed-wire-policy.v6"

    def __post_init__(self):
        if (type(self.installation) is not NaturalReplyInstallationV2
                or self.schema != "sylanne3.d13.installed-wire-policy.v6"
                or self.wire_policy_id != WIRE_POLICY or self.template_digest != TEMPLATE_DIGEST
                or not _digest(self.counter_public_key_hex)
                or not self.counter_policy_id or type(self.counter_policy_id) is not str
                or not _integer(self.counter_policy_version, 1)
                or not _integer(self.context_limit_tokens, 1)
                or self.context_limit_tokens <= self.installation.max_output_tokens + self.tool_reserve_tokens
                or type(self.max_slots) is not int or not 1 <= self.max_slots <= 256
                or type(self.max_blocks) is not int or not 1 <= self.max_blocks <= 4
                or type(self.allow_conservative_switch) is not bool):
            raise ValueError("installed D13 full-wire policy identity/capacity differs")
        for name in ("counter_policy_fingerprint", "tokenizer_fingerprint", "wire_policy_fingerprint"):
            if not _digest(getattr(self, name)):
                raise ValueError("installed D13 policy assets require SHA-256 pins")
        for name in ("tool_reserve_tokens", "uncached_input_microusd_per_million",
                     "cache_write_input_microusd_per_million", "output_microusd_per_million",
                     "storage_microusd_upper"):
            if not _integer(getattr(self, name)):
                raise ValueError("installed D13 reserves and prices require integer bounds")

    @property
    def policy_digest(self):
        return canonical_digest(self)


@dataclass(frozen=True,slots=True)
class D13NaturalWireDecisionV6:
    selected: str
    token_evidence: str
    proof_digest: str
    wire_digest: str
    collection_digest: str
    blockset_digest: str
    policy_digest: str
    template_digest: str
    expires_at_utc: float
    budget_state: str

@dataclass(frozen=True,slots=True)
class D13NaturalReservedSelectionV6:
    wire_digest: str
    proof_digest: str
    reservation_digest: str
    token_evidence: str
    collection_digest: str
    blockset_digest: str
    policy_digest: str
    template_digest: str
    budget_state: str='reserved_original'


def installed_d13_wire_policy_from_payload_v6(payload):
    if type(payload) is not dict or set(payload)!={field.name for field in fields(InstalledD13WirePolicyV6)}:
        raise ValueError('v6 installed wire policy has another closed schema')
    raw=dict(payload);raw['installation']=NaturalReplyInstallationV2(**raw['installation'])
    return InstalledD13WirePolicyV6(**raw)


def install_d13_wire_evidence_schema_v6(db):
    db.execute(f"""CREATE TABLE IF NOT EXISTS {TABLE} (
        bot TEXT NOT NULL,persona TEXT NOT NULL,evidence_digest TEXT NOT NULL,policy_digest TEXT NOT NULL,
        raw_request_digest TEXT NOT NULL,compressed_request_digest TEXT NOT NULL,envelope_json TEXT NOT NULL,
        PRIMARY KEY(bot,persona,evidence_digest))""")
    db.execute(f'CREATE INDEX IF NOT EXISTS graph_d13_wire_evidence_pair_v6 ON {TABLE}(bot,persona,policy_digest,raw_request_digest,compressed_request_digest)')
    for action in ('UPDATE','DELETE'):
        db.execute(f"CREATE TRIGGER IF NOT EXISTS graph_d13_wire_evidence_v6_no_{action.lower()} BEFORE {action} ON {TABLE} BEGIN SELECT RAISE(ABORT,'v6 signed full-wire evidence is immutable'); END")


def _block_bindings(pair):
    result=[]
    for item in pair.projected_blocks:
        metadata=item.metadata
        result.append({'metadata_ref':item.ref.ref,'metadata_revision':item.ref.version,
            'metadata_digest':canonical_digest(metadata),'payload_digest':metadata.payload_digest,
            'plan_ref':item.compression_plan.job_ref,'plan_digest':canonical_digest(item.compression_plan),
            'paid_original_ref':metadata.paid_original_operation_id,'paid_original_digest':metadata.paid_original_digest,
            'expires_at_utc':metadata.expires_at_utc,'turn_first':item.block.turns[0].sequence,'turn_last':item.block.turns[-1].sequence})
    return result


def _pair_original_fields_v6(policy,pair):
    if (type(policy) is not InstalledD13WirePolicyV6 or type(pair) is not NaturalHistoryPairV6 or pair.compressed is None
            or type(pair.raw) is not FrozenNaturalReplyRequestV6 or type(pair.compressed) is not FrozenNaturalReplyRequestV6
            or pair.raw!=freeze_natural_reply_request_v6(pair.raw.input,pair.raw.installation)
            or pair.compressed!=freeze_natural_reply_request_v6(pair.compressed.input,pair.compressed.installation)
            or pair.raw.installation!=policy.installation or pair.compressed.installation!=policy.installation
            or pair.raw.input.stable_history or not pair.compressed.input.stable_history
            or pair.raw.input.question!=pair.compressed.input.question or pair.raw.input.plan!=pair.compressed.input.plan
            or pair.raw.input.frozen_at_utc!=pair.compressed.input.frozen_at_utc
            or pair.raw.input.expires_at_utc!=pair.compressed.input.expires_at_utc
            or pair.collection.max_slots!=policy.max_slots or not 1<=len(pair.projected_blocks)<=policy.max_blocks):
        raise ValueError('v6 complete exact same-model wire pair and installed collection policy required')
    bindings=_block_bindings(pair)
    return {'namespace':asdict(pair.raw.input.plan.namespace),'policy_digest':policy.policy_digest,
        'raw_request_digest':pair.raw.model_request_digest,'compressed_request_digest':pair.compressed.model_request_digest,
        'raw_frozen_digest':pair.raw.frozen_input_digest,'compressed_frozen_digest':pair.compressed.frozen_input_digest,
        'collection_digest':canonical_digest({'snapshot':pair.collection.snapshot_commitment,'window':pair.collection.window,
            'pages':tuple((page.before_sequence,page.max_slots,page.first_sequence,page.last_sequence,page.page_status,
                page.expired_sequences,page.unclosed_sequences) for page in pair.collection.pages)}),
        'block_bindings':bindings,'blockset_digest':canonical_digest(bindings),
        'frozen_at_utc':pair.raw.input.frozen_at_utc,'expires_at_utc':pair.raw.input.expires_at_utc}


def d13_full_wire_count_request_v6(*,policy,pair):
    request={'schema':'sylanne3.d13.full-wire-count-request.v6','original':_pair_original_fields_v6(policy,pair),
        'policy':asdict(policy),'raw_wire':pair.raw.canonical_wire,'compressed_wire':pair.compressed.canonical_wire}
    if len(canonical_serialize(request).encode('utf-8'))>16*1024*1024:
        raise ValueError('v6 full count request exceeds the actual existing protected-program stdin cap; no prefix fallback')
    return request

_FIELDS=frozenset({'schema','namespace','policy_digest','raw_request_digest','compressed_request_digest','raw_frozen_digest',
    'compressed_frozen_digest','collection_digest','block_bindings','blockset_digest','frozen_at_utc','expires_at_utc',
    'token_evidence','raw_lower_tokens','raw_upper_tokens','compressed_lower_tokens','compressed_upper_tokens'})
_BINDING_FIELDS=frozenset({'metadata_ref','metadata_revision','metadata_digest','payload_digest','plan_ref','plan_digest',
    'paid_original_ref','paid_original_digest','expires_at_utc','turn_first','turn_last'})

def verify_signed_d13_wire_envelope_v6(policy,envelope):
    if type(policy) is not InstalledD13WirePolicyV6 or type(envelope) is not dict or set(envelope)!={'payload','signature'}:
        raise ValueError('v6 signed installed counter envelope required')
    payload=envelope['payload']
    if (type(payload) is not dict or set(payload)!=_FIELDS or payload['schema']!=EVIDENCE_SCHEMA
            or payload['policy_digest']!=policy.policy_digest or payload['token_evidence'] not in {'exact_full_wire','bounded_full_wire'}):
        raise ValueError('v6 signature/policy/whole-wire schema differs')
    if type(payload['namespace']) is not dict or set(payload['namespace'])!={'bot_id','persona_id'}:
        raise ValueError('v6 signed namespace differs')
    NamespaceId(**payload['namespace'])
    for name in ('raw_request_digest','compressed_request_digest','raw_frozen_digest','compressed_frozen_digest','collection_digest','blockset_digest'):
        if not _digest(payload[name]):
            raise ValueError('v6 whole original digest binding differs')
    bindings=payload['block_bindings']
    if (type(bindings) is not list or not 1<=len(bindings)<=policy.max_blocks
            or any(type(row) is not dict or set(row)!=_BINDING_FIELDS for row in bindings)
            or payload['blockset_digest']!=canonical_digest(bindings)):
        raise ValueError('v6 ordered signed block set differs')
    for row in bindings:
        key=AtomKey.from_token(row['metadata_ref'])
        if key.type_name not in('d13.derived_block_metadata.v1','d13.derived_block_metadata.v2') or key.owner.kind!='persona' or NamespaceId.from_key(key)!=NamespaceId(**payload['namespace']):
            raise ValueError('v6 signed metadata belongs to another namespace/type')
        if (any(not _digest(row[name]) for name in ('metadata_digest','payload_digest','plan_digest','paid_original_digest'))
                or any(type(row[name]) is not str or not row[name] for name in ('metadata_ref','plan_ref','paid_original_ref'))
                or not _integer(row['metadata_revision'],1) or not _integer(row['turn_first'],0) or not _integer(row['turn_last'],0)
                or not 1<=row['turn_last']-row['turn_first']+1<=64
                or type(row['expires_at_utc']) not in (int,float) or not math.isfinite(row['expires_at_utc'])):
            raise ValueError('v6 block original/source/expiry commitment differs')
    if (any(a['turn_last']>=b['turn_first'] for a,b in zip(bindings,bindings[1:]))
            or sum(row['turn_last']-row['turn_first']+1 for row in bindings)>256
            or len({row['metadata_ref'] for row in bindings})!=len(bindings)):
        raise ValueError('v6 blocks overlap or exceed the bounded actual window')
    for name in ('raw_lower_tokens','raw_upper_tokens','compressed_lower_tokens','compressed_upper_tokens'):
        if not _integer(payload[name],0 if 'lower' in name else 1):
            raise ValueError('v6 complete nonempty wire count invalid')
    if (payload['raw_lower_tokens']>payload['raw_upper_tokens'] or payload['compressed_lower_tokens']>payload['compressed_upper_tokens']
            or payload['raw_request_digest']==payload['compressed_request_digest']
            or payload['token_evidence']=='exact_full_wire' and (payload['raw_lower_tokens']!=payload['raw_upper_tokens']
                or payload['compressed_lower_tokens']!=payload['compressed_upper_tokens'])):
        raise ValueError('v6 exact count/conservative interval invalid')
    if (any(type(payload[name]) not in (int,float) or not math.isfinite(payload[name]) for name in ('frozen_at_utc','expires_at_utc'))
            or not payload['frozen_at_utc']<payload['expires_at_utc']<=min(row['expires_at_utc'] for row in bindings)):
        raise ValueError('v6 evidence absolute original lifetime differs')
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(policy.counter_public_key_hex)).verify(
        base64.b64decode(envelope['signature'],validate=True),SIGNING_DOMAIN+canonical_serialize(payload).encode())
    return payload


def record_signed_d13_wire_evidence_v6(db,*,policy,envelope):
    if not db.in_transaction:
        raise ValueError('v6 signed evidence belongs to the existing fenced transaction')
    payload=verify_signed_d13_wire_envelope_v6(policy,envelope)
    encoded,digest=canonical_serialize(envelope),canonical_digest(envelope)
    ns=NamespaceId(**payload['namespace']).as_tuple
    prior=db.execute(f'SELECT envelope_json FROM {TABLE} WHERE bot=? AND persona=? AND evidence_digest=?',(*ns,digest)).fetchone()
    if prior is not None:
        if prior!=(encoded,):
            raise ValueError('v6 signed original evidence identity changed')
        return digest
    db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)',(*ns,digest,policy.policy_digest,
        payload['raw_request_digest'],payload['compressed_request_digest'],encoded))
    return digest


def require_current_v6_collection_for_original_pair(db,policy,pair,now_utc):
    current=read_current_d13_collection_v6(db,pair.raw.input.plan.namespace,pair.raw.input.plan.scene_id,
        pair.raw.input.plan.audience_id,now_utc,expected_activation_generation=pair.collection.window.activation_epoch,
        max_slots=policy.max_slots)
    original=pair.collection
    if (replace(current.window,trusted_utc=0)!=replace(original.window,trusted_utc=0)
            or current.max_slots!=original.max_slots or len(current.pages)!=len(original.pages)
            or any(replace(a,window=replace(a.window,trusted_utc=0))!=replace(b,window=replace(b.window,trusted_utc=0))
                for a,b in zip(current.pages,original.pages))):
        raise ValueError('v6 original semantic Source/turn/gap/readset projection changed')
    if not now_utc<min(pair.raw.input.expires_at_utc,pair.compressed.input.expires_at_utc,
            *(item.metadata.expires_at_utc for item in pair.projected_blocks)):
        raise ValueError('v6 original counted wire or effective paid/source lifetime expired')
    return current


class InstalledD13WireEvidencePortV6:
    def __init__(self,db,*,policy,foreground_budget,resource_issuer,budget_issuer,paid_verifier):
        if (type(db) is not sqlite3.Connection or type(policy) is not InstalledD13WirePolicyV6
                or type(paid_verifier) is not InstalledD13DerivedPaidBlockVerifierV2):
            raise ValueError('new installed v6 current paid/wire authorities required')
        self._db,self._policy,self._budget,self._resource,self._issuer,self._paid=db,policy,foreground_budget,resource_issuer,budget_issuer,paid_verifier
        self.policy_digest=policy.policy_digest
        self.pending_count_request=None
        self._last_pair=None
        self._quote_read_versions=None

    def evaluate_natural_pair_v6(self,*,pair,now_utc):
        policy,db=self._policy,self._db
        if not db.in_transaction:
            raise ValueError('v6 actual current count selection needs its held transaction')
        current=require_current_v6_collection_for_original_pair(db,policy,pair,now_utc)
        paid=self._paid.for_current_read_v2(now_utc)
        blocks=read_current_derived_blocks_v6(db,collection=current,question=pair.raw.input.question,paid_verifier=paid)
        from ..runtime.d11_derived_cache_payload_v1 import require_actual_derived_activation_v6
        for expected_block in pair.projected_blocks:
            actual=next((item for item in blocks if item.ref.ref==expected_block.ref.ref),None)
            if actual is None:
                raise ValueError('v6 current paid/source block is no longer qualified')
            if actual!=expected_block:
                require_actual_derived_activation_v6(db,expected_block,actual)
        expected=_pair_original_fields_v6(policy,pair)
        self.pending_count_request=d13_full_wire_count_request_v6(policy=policy,pair=pair)
        rows=db.execute(f'SELECT evidence_digest,envelope_json FROM {TABLE} WHERE bot=? AND persona=? AND policy_digest=? '
            'AND raw_request_digest=? AND compressed_request_digest=? ORDER BY evidence_digest LIMIT 17',
            (*pair.raw.input.plan.namespace.as_tuple,policy.policy_digest,pair.raw.model_request_digest,pair.compressed.model_request_digest)).fetchall()
        if len(rows)>16:
            raise ValueError('v6 counter evidence window incomplete')
        for digest,encoded in rows:
            envelope=json.loads(encoded)
            if canonical_serialize(envelope)!=encoded or canonical_digest(envelope)!=digest:
                raise ValueError('v6 immutable evidence bytes changed')
            payload=verify_signed_d13_wire_envelope_v6(policy,envelope)
            if any(payload[name]!=value for name,value in expected.items()):
                continue
            if not now_utc<payload['expires_at_utc'] or now_utc<payload['frozen_at_utc']:
                continue
            capacity=policy.context_limit_tokens-policy.installation.max_output_tokens-policy.tool_reserve_tokens
            selected='raw' if payload['raw_upper_tokens']<=capacity else 'compressed' if payload['compressed_upper_tokens']<=capacity and (
                payload['raw_lower_tokens']>capacity or policy.allow_conservative_switch) else 'hold'
            if selected=='hold':
                self.pending_count_request=None
                return D13NaturalWireDecisionV6('hold',payload['token_evidence'],digest,pair.raw.model_request_digest,
                    expected['collection_digest'],expected['blockset_digest'],policy.policy_digest,TEMPLATE_DIGEST,payload['expires_at_utc'],'unverified')
            frozen=pair.raw if selected=='raw' else pair.compressed
            budget_digest=_verify_foreground_budget(db,policy,self._budget,self._resource,self._issuer,frozen,
                payload['raw_upper_tokens'] if selected=='raw' else payload['compressed_upper_tokens'],now_utc,
                quote_read_versions=self._quote_read_versions)
            result=D13NaturalWireDecisionV6(selected,payload['token_evidence'],canonical_digest({'signed_evidence':digest,'foreground_budget':budget_digest}),
                frozen.model_request_digest,expected['collection_digest'],expected['blockset_digest'],policy.policy_digest,TEMPLATE_DIGEST,
                payload['expires_at_utc'],'preparation_only' if type(self._budget) is D13ForegroundBudgetPreparationV1 else 'reserved_original')
            self._last_pair=pair,result;self.pending_count_request=None
            return result
        return None

    def verify_reserved_original_v6(self,*,original,current_collection,now_utc):
        if type(self._budget) is not D13ForegroundBudgetBindingV1 or original!=freeze_natural_reply_request_v6(original.input,original.installation):
            raise ValueError('v6 historical consumption requires its exact reserved original')
        selection=original.input.history_selection
        if canonical_digest(replace(current_collection.window,trusted_utc=original.input.frozen_at_utc))!=selection.window_digest:
            raise ValueError('v6 original Source/order/readset/body projection changed')
        current_cursors=tuple((page.before_sequence,page.max_slots,page.first_sequence,page.last_sequence) for page in current_collection.pages)
        if current_cursors!=selection.page_cursors:
            raise ValueError('v6 original strict page cursors changed')
        original_collection_digest=canonical_digest({'snapshot':selection.collection_snapshot_commitment,
            'window':replace(current_collection.window,trusted_utc=original.input.frozen_at_utc),
            'pages':tuple((page.before_sequence,page.max_slots,page.first_sequence,page.last_sequence,page.page_status,
                page.expired_sequences,page.unclosed_sequences) for page in current_collection.pages)})
        current_blocks=()
        if selection.block_refs:
            paid=self._paid.for_current_read_v2(now_utc)
            current_blocks=read_current_derived_blocks_v6(self._db,collection=current_collection,question=original.input.question,paid_verifier=paid)
        by_ref={item.ref.ref:item for item in current_blocks}
        for ref in selection.block_refs:
            item=by_ref.get(ref.ref)
            if item is None or item.ref!=ref or now_utc>=item.metadata.expires_at_utc:
                raise ValueError('v6 original current paid block head/expiry changed')
            part=next((part for part in original.input.stable_history if part.ref==ref),None)
            text='\n'.join(f'[{turn.sequence} {turn.speaker_ref}] {turn.text}' for turn in item.block.timeline)
            if part is None or part.text!=text or part.dependencies!=item.block.source_dependencies:
                raise ValueError('v6 original stable bytes differ from its actual paid payload')
        rows=self._db.execute(f'SELECT evidence_digest,envelope_json FROM {TABLE} WHERE bot=? AND persona=? AND policy_digest=? '
            'AND (raw_request_digest=? OR compressed_request_digest=?) ORDER BY evidence_digest LIMIT 17',
            (*original.input.plan.namespace.as_tuple,self._policy.policy_digest,original.model_request_digest,original.model_request_digest)).fetchall()
        if len(rows)>16:
            raise ValueError('v6 original signed count window incomplete')
        for digest,encoded in rows:
            envelope=json.loads(encoded)
            if canonical_serialize(envelope)!=encoded or canonical_digest(envelope)!=digest:
                raise ValueError('v6 immutable original count bytes changed')
            payload=verify_signed_d13_wire_envelope_v6(self._policy,envelope)
            if payload['namespace']!=asdict(original.input.plan.namespace) or now_utc>=payload['expires_at_utc']:
                continue
            selected_raw=payload['raw_request_digest']==original.model_request_digest
            frozen_digest=payload['raw_frozen_digest'] if selected_raw else payload['compressed_frozen_digest']
            if frozen_digest!=original.frozen_input_digest:
                continue
            if payload['collection_digest']!=original_collection_digest:
                raise ValueError('v6 signed original collection commitment changed')
            if not selected_raw:
                from ..domains.d13.derived_block_metadata_v2 import decode_derived_block_metadata_history_v2
                from ..runtime.d11_derived_cache_payload_v1 import require_actual_derived_metadata_activation_v6
                from ..runtime_contracts import VersionedRef
                bindings=payload['block_bindings']
                if tuple(row['metadata_ref'] for row in bindings)!=tuple(ref.ref for ref in selection.block_refs):
                    raise ValueError('v6 signed ordered block set differs from the original selected blocks')
                for bound,ref in zip(bindings,selection.block_refs):
                    item=by_ref[ref.ref]
                    historical=self._db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?',
                        (bound['metadata_ref'],bound['metadata_revision'])).fetchone()
                    if historical is None or historical[1]!=1:
                        raise ValueError('v6 signed block historical metadata unavailable')
                    before=decode_derived_block_metadata_history_v2(AtomKey.from_token(bound['metadata_ref']),json.loads(historical[0]))
                    before_ref=VersionedRef(bound['metadata_ref'],bound['metadata_revision'])
                    actual={'metadata_ref':before_ref.ref,'metadata_revision':before_ref.version,
                        'metadata_digest':canonical_digest(before),'payload_digest':before.payload_digest,
                        'plan_ref':item.compression_plan.job_ref,'plan_digest':canonical_digest(item.compression_plan),
                        'paid_original_ref':before.paid_original_operation_id,'paid_original_digest':before.paid_original_digest,
                        'expires_at_utc':before.expires_at_utc,'turn_first':item.block.turns[0].sequence,
                        'turn_last':item.block.turns[-1].sequence}
                    if actual!=bound:
                        raise ValueError('v6 signed block paid/payload/plan/expiry binding changed')
                    if before_ref!=item.ref or before!=item.metadata:
                        require_actual_derived_metadata_activation_v6(self._db,before,before_ref,item.metadata,item.ref)
            upper=payload['raw_upper_tokens'] if selected_raw else payload['compressed_upper_tokens']
            if upper>self._policy.context_limit_tokens-self._policy.installation.max_output_tokens-self._policy.tool_reserve_tokens:
                raise ValueError('v6 original complete wire exceeds its unchanged installed model capacity')
            budget=_verify_foreground_budget(self._db,self._policy,self._budget,self._resource,self._issuer,original,upper,now_utc)
            return D13NaturalWireDecisionV6('raw' if selected_raw else 'compressed',payload['token_evidence'],
                canonical_digest({'signed_evidence':digest,'foreground_budget':budget}),original.model_request_digest,
                payload['collection_digest'],payload['blockset_digest'],self._policy.policy_digest,TEMPLATE_DIGEST,
                payload['expires_at_utc'],'reserved_original')
        raise ValueError('v6 original current reserved whole-wire proof unavailable')

    def validate_reserved_selection_v6(self,*,selected,decision,binding,read_versions,now_utc):
        from ..runtime.installed_d13_natural_frame_v6 import NaturalHistoryDecisionV6
        if (not self._db.in_transaction or type(self._budget) is not D13ForegroundBudgetPreparationV1
                or type(binding) is not D13ForegroundBudgetBindingV1 or type(decision) is not NaturalHistoryDecisionV6
                or decision.budget_state!='preparation_only' or self._last_pair is None):
            raise ValueError('v6 reserved second gate requires its actual prior preparation')
        pair,first=self._last_pair
        if ((decision.selected,decision.proof_digest,decision.wire_digest,decision.policy_digest)!=(first.selected,first.proof_digest,first.wire_digest,first.policy_digest)
                or selected!=(pair.raw if first.selected=='raw' else pair.compressed)):
            raise ValueError('v6 reserved selection differs from the counted original')
        if (binding.lease_id,binding.reservation_operation_id)!=(self._budget.lease_id,self._budget.reservation_operation_id):
            raise ValueError('v6 reserved operation differs')
        quote=self._resource.original_signed_quote(self._db,binding.quote_id,binding.quote_version)
        if quote.activity_id!=self._budget.activity_id or dict(quote.ceiling)!=dict(self._budget.quote_ceiling):
            raise ValueError('v6 exact original foreground quote differs')
        admitted=InstalledD13WireEvidencePortV6(self._db,policy=self._policy,foreground_budget=binding,
            resource_issuer=self._resource,budget_issuer=self._issuer,paid_verifier=self._paid)
        admitted._quote_read_versions=read_versions
        proof=admitted.evaluate_natural_pair_v6(pair=pair,now_utc=now_utc)
        if proof is None or proof.selected!=first.selected or proof.budget_state!='reserved_original':
            raise ValueError('v6 actual reserved second gate unavailable')
        return D13NaturalReservedSelectionV6(selected.model_request_digest,proof.proof_digest,binding.reservation_digest,
            proof.token_evidence,proof.collection_digest,proof.blockset_digest,proof.policy_digest,proof.template_digest)


def validate_reserved_d13_natural_selection_v6(port,**kwargs):
    if type(port) is not InstalledD13WireEvidencePortV6:
        raise ValueError('actual installed v6 wire port required')
    return port.validate_reserved_selection_v6(**kwargs)
