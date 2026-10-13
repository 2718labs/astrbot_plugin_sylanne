"""V7 semantic wire with complete authority provenance retained in the input.

The model projection is deterministic data, never qualification or permission.
Core must independently reconstruct and verify the complete original input and
count both actual complete HTTP requests under the installed counter policy.
V6 template, wire, digests and decoders remain unchanged.
"""
from dataclasses import asdict,dataclass,fields,field
from hashlib import sha256

from ..runtime_contracts import canonical_digest,canonical_serialize
from .natural_reply import NaturalReplyInstallationV2,NaturalReplyMessageV2
from .natural_reply_history_v6 import NaturalReplyInputV6
from .natural_reply_history_v4 import OUTPUT_SCHEMA_V3,SYSTEM_MESSAGE_V5

TEMPLATE_VERSION='sylanne.d09.context_reply_input.v7'
INPUT_SCHEMA=TEMPLATE_VERSION
OUTPUT_SCHEMA=OUTPUT_SCHEMA_V3
SYSTEM_MESSAGE=SYSTEM_MESSAGE_V5+(
    ' The V7 request contains only qualified semantic material and a commitment to the full authority input. '
    'A commitment never grants access, proves delivery, or creates a promise. '
    'Use the speaker dictionary exactly; speaker keys are aliases of the supplied original identities. '
    'Keep chronological coverage, gaps, source attribution, evidence excerpts, polarity and uncertainty. '
    'Never infer omitted history or treat a gap as a denial. Return the exact declared response schema.')
UNIT_SEMANTIC_FIELDS_V7=(
    'basis_id','kind','qualified_text','direct_quote','speaker_id','content_reality','stance','uncertainty',
    'self_description_hypotheses','semantic_constraints','occurred_at','learned_at','source_kind','assertion_status',
    'd06_claim_kind','attribution_required','polarity_status','source_excerpt','evidence_span','direct_quote_span','negation_cue_span')
PROJECTION_SCHEMA='sylanne.d09.semantic_model_projection.v7'
PROJECTION_DIGEST=canonical_digest({'schema':PROJECTION_SCHEMA,'question':('kind','text'),
    'plan':('required_slots','allowed_speech_acts','promise_grants','scene_id','audience_id'),
    'units':UNIT_SEMANTIC_FIELDS_V7,'speaker_order':'first-occurrence-stable-recent-detail',
    'stable':('block_index','sequence','speaker_key','text'),'history':('order_watermark','coverage','gaps'),'authority_commitment':'full-typed-input-digest'})
TEMPLATE_DIGEST=canonical_digest({'version':TEMPLATE_VERSION,'input_schema':INPUT_SCHEMA,'output_schema':OUTPUT_SCHEMA,
    'layout':'system/stable_user/dynamic_user','system_message':SYSTEM_MESSAGE,'projection_digest':PROJECTION_DIGEST})

@dataclass(frozen=True,slots=True)
class D13NaturalStableTurnV7:
    block_index:int
    sequence:int
    speaker_ref:str
    text:str
    def __post_init__(self):
        if (type(self.block_index) is not int or not 0<=self.block_index<4
                or type(self.sequence) is not int or self.sequence<0
                or type(self.speaker_ref) is not str or not self.speaker_ref
                or type(self.text) is not str or not self.text):
            raise ValueError('V7 stable turn retains exact original sequence speaker and text')

@dataclass(frozen=True,slots=True)
class NaturalReplyInputV7(NaturalReplyInputV6):
    schema:str=INPUT_SCHEMA
    stable_turns:tuple[D13NaturalStableTurnV7,...]=field(default=(),kw_only=True)
    def __post_init__(self,_prepared_history_eof_v3=None):
        if self.schema!=INPUT_SCHEMA:raise ValueError('explicit Natural V7 input schema required')
        # Validate the full immutable data through existing pure provenance rules.
        # This structural view is never stored or used as an actual V6 original.
        values={field.name:getattr(self,field.name) for field in fields(NaturalReplyInputV6)}
        values['schema']='sylanne.d09.context_reply_input.v6'
        NaturalReplyInputV6(**values,_prepared_history_eof_v3=_prepared_history_eof_v3)
        if (type(self.stable_turns) is not tuple or len(self.stable_turns)>256
                or any(type(turn) is not D13NaturalStableTurnV7 for turn in self.stable_turns)):
            raise ValueError('V7 stable projection needs complete typed actual block timeline')
        if any(a.block_index>b.block_index or a.block_index==b.block_index and a.sequence>=b.sequence
                for a,b in zip(self.stable_turns,self.stable_turns[1:])):
            raise ValueError('V7 actual stable timeline order differs')
        if any(turn.block_index>=len(self.stable_history) for turn in self.stable_turns):
            raise ValueError('V7 stable turn points outside selected original blocks')
        if _prepared_history_eof_v3 is not None:
            from ..runtime.natural_frozen_original_read_v3 import require_prepared_stable_timeline_v3
            require_prepared_stable_timeline_v3(_prepared_history_eof_v3,self)
        else:
            for index,part in enumerate(self.stable_history):
                rows=tuple(turn for turn in self.stable_turns if turn.block_index==index)
                if not rows or '\n'.join(f'[{turn.sequence} {turn.speaker_ref}] {turn.text}' for turn in rows)!=part.text:
                    raise ValueError('V7 stable semantic timeline differs from exact qualified original body')

@dataclass(frozen=True,slots=True)
class FrozenNaturalReplyRequestV7:
    input:NaturalReplyInputV7
    installation:NaturalReplyInstallationV2
    messages:tuple[NaturalReplyMessageV2,...]
    canonical_wire:str
    stable_prefix_wire:str
    stable_prefix_digest:str
    frozen_input_digest:str
    qualified_units_digest:str
    model_request_digest:str
    semantic_projection_digest:str
    schema:str='sylanne.d09.frozen_natural_request.v7'


def semantic_model_projection_v7(input,*,prepared_eof=None):
    if type(input) is not NaturalReplyInputV7:raise TypeError('actual typed full V7 input required')
    plan=input.plan;selection=input.history_selection
    speakers=[];speaker_keys={}
    def speaker(ref):
        if ref not in speaker_keys:
            key='s'+str(len(speakers));speaker_keys[ref]=key
            speakers.append({'speaker_key':key,'speaker_ref':ref})
        return speaker_keys[ref]
    # Stable history text retains its exact chronological/speaker annotations.
    # Its corresponding refs map to the unchanged complete selected block set.
    stable=[{'block_index':turn.block_index,'sequence':turn.sequence,'speaker_key':speaker(turn.speaker_ref),'text':turn.text}
        for turn in input.stable_turns]
    recent=[{'sequence':part.turn.sequence,'text':part.turn.text,'trusted_utc':part.turn.trusted_utc,
        'speaker_key':speaker(part.turn.speaker_ref),'delivery_state':part.turn.delivery_state,'tool_state':part.turn.tool_state}
        for part in input.recent_history]
    detail=[{'sequence':part.sequence,'text':part.text,'speaker_key':speaker(part.speaker_ref)} for part in input.detail_history]
    if prepared_eof is not None:
        from ..runtime.natural_frozen_original_read_v3 import require_prepared_semantic_input_digest_v3
    return {'schema':PROJECTION_SCHEMA,'authority_input_digest':(canonical_digest(input)if prepared_eof is None else require_prepared_semantic_input_digest_v3(prepared_eof,input)),
        'frozen_at_utc':input.frozen_at_utc,'expires_at_utc':input.expires_at_utc,
        'question':{'kind':input.question.kind,'text':input.question.text},
        'expression_plan':{'required_slots':plan.required_slots,'allowed_speech_acts':plan.allowed_speech_acts,
            'promise_grants':[asdict(ref) for ref in plan.promise_grants],'scene_id':plan.scene_id,'audience_id':plan.audience_id},
        'qualified_units':[{name:getattr(unit,name) for name in UNIT_SEMANTIC_FIELDS_V7} for unit in plan.units],
        'speaker_dictionary':speakers,'stable_history':stable,'recent_history':recent,'detail_history':detail,
        'history_selection':{'order_watermark':selection.order_watermark,'coverage':selection.coverage,'gaps':selection.gaps}}


def _natural_message_values_v7(projection):
    return ({'schema':INPUT_SCHEMA,'stable_history':projection['stable_history']},
        {'schema':INPUT_SCHEMA,**{key:value for key,value in projection.items() if key not in {'schema','stable_history'}}})


def _natural_wire_value_v7(installation,messages):
    return {'provider_id':installation.provider_id,'model':installation.model_id,
        'messages':[asdict(message) for message in messages],'max_output_tokens':installation.max_output_tokens}


def _natural_prefix_parts_v7(installation,system_wire,stable_wire):
    return ('{"max_output_tokens":'+str(installation.max_output_tokens)+',"messages":[',system_wire,',',stable_wire,',{"content":')


def freeze_natural_reply_request_v7(input,installation):
    if type(input) is not NaturalReplyInputV7 or type(installation) is not NaturalReplyInstallationV2:
        raise TypeError('typed V7 input and actual installed model required')
    projection=semantic_model_projection_v7(input)
    stable_value,dynamic_value=_natural_message_values_v7(projection)
    stable=canonical_serialize(stable_value);dynamic=canonical_serialize(dynamic_value)
    messages=(NaturalReplyMessageV2('system',SYSTEM_MESSAGE),NaturalReplyMessageV2('user',stable),NaturalReplyMessageV2('user',dynamic))
    wire=canonical_serialize(_natural_wire_value_v7(installation,messages))
    prefix=''.join(_natural_prefix_parts_v7(installation,canonical_serialize(asdict(messages[0])),canonical_serialize(asdict(messages[1]))))
    if not wire.startswith(prefix):raise ValueError('V7 stable prefix differs from actual canonical wire')
    return FrozenNaturalReplyRequestV7(input,installation,messages,wire,prefix,
        canonical_digest({'template_digest':TEMPLATE_DIGEST,'installation':installation,'stable_prefix_sha256':sha256(prefix.encode()).hexdigest()}),
        canonical_digest(input),canonical_digest(input.plan.units),sha256(wire.encode()).hexdigest(),canonical_digest(projection))


def thaw_natural_reply_request_v7(raw,*,prepared_eof=None):
    """Decode complete authority input separately from the semantic model wire."""
    if prepared_eof is not None:
        from ..runtime.natural_frozen_original_read_v3 import require_prepared_natural_frozen_v3
        return require_prepared_natural_frozen_v3(prepared_eof,raw,version=7)
    from ..runtime.natural_reply_job_v2 import _part,_unit
    from ..runtime_contracts import NamespaceId,VersionedRef,CompletedTurnV1
    from ..domains.d09.natural_reply import NaturalExpressionPlanV2
    from .natural_reply_history_v3 import D13NaturalRawTurnV1
    from .natural_reply_history_v4 import D13NaturalDetailPartV1
    from .natural_reply_history_v6 import D13NaturalHistorySelectionV2
    if type(raw) is not dict or set(raw)!={field.name for field in fields(FrozenNaturalReplyRequestV7)}:
        raise ValueError('V7 frozen fields differ')
    data=raw['input']
    if type(data) is not dict or set(data)!={field.name for field in fields(NaturalReplyInputV7)}:
        raise ValueError('V7 authority input fields differ')
    plan=dict(data['plan']);plan['namespace']=NamespaceId(**plan['namespace'])
    for name in ('plan_ref','scene_ref','audience_ref'):plan[name]=VersionedRef(**plan[name])
    for name in ('required_slots','allowed_speech_acts'):plan[name]=tuple(plan[name])
    plan['promise_grants']=tuple(VersionedRef(**v) for v in plan['promise_grants']);plan['units']=tuple(_unit(v) for v in plan['units'])
    selection=dict(data['history_selection'])
    for name in ('scene_ref','audience_ref'):selection[name]=VersionedRef(**selection[name])
    for name in ('source_dependencies','read_set','raw_turn_refs','block_refs'):selection[name]=tuple(VersionedRef(**v) for v in selection[name])
    for name in ('coverage','gaps','page_cursors'):selection[name]=tuple(tuple(v) for v in selection[name])
    recent=[]
    for part in data['recent_history']:
        if type(part) is not dict or set(part)!={'turn','completion_ref'}:raise ValueError('V7 actual raw turn fields differ')
        turn=dict(part['turn'])
        for name in ('audience_ref','raw_ref','source_ref','access_ref'):turn[name]=VersionedRef(**turn[name])
        recent.append(D13NaturalRawTurnV1(CompletedTurnV1(**turn),VersionedRef(**part['completion_ref'])))
    expected=freeze_natural_reply_request_v7(NaturalReplyInputV7(_part(data['question']),NaturalExpressionPlanV2(**plan),
        tuple(_part(v) for v in data['stable_history']),tuple(recent),D13NaturalHistorySelectionV2(**selection),
        tuple(D13NaturalDetailPartV1(v['sequence'],VersionedRef(**v['source_ref']),v['speaker_ref'],v['text'],v['expires_at_utc']) for v in data['detail_history']),
        data['frozen_at_utc'],data['expires_at_utc'],data['schema'],
        stable_turns=tuple(D13NaturalStableTurnV7(**turn) for turn in data['stable_turns'])),NaturalReplyInstallationV2(**raw['installation']))
    if canonical_serialize(asdict(expected))!=canonical_serialize(raw):raise ValueError('V7 full authority input or semantic wire changed')
    return expected


def parse_natural_reply_output_v7(text,frozen):
    from .natural_reply import _parse_natural_reply_output_payload
    if type(frozen) is not FrozenNaturalReplyRequestV7 or freeze_natural_reply_request_v7(frozen.input,frozen.installation)!=frozen:
        raise ValueError('V7 frozen original differs')
    return _parse_natural_reply_output_payload(text,frozen)
