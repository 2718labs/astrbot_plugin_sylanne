"""Pinned complete SDK HTTP template with one explicitly typed late digest slot.

The exemplar is used only for byte counting. It is never an actual HTTP hash.
The actual request is checked at the SDK transport boundary before network I/O.
"""
from dataclasses import dataclass,asdict
from hashlib import sha256
import json
from ..runtime_contracts import canonical_digest
from .natural_reply_history_v7 import FrozenNaturalReplyRequestV7,freeze_natural_reply_request_v7

HTTP_TEMPLATE_SCHEMA='sylanne3.d13.provider-http-template.v1'
SERIALIZER_RULE={'schema':'sylanne3.d13.openai-httpx-json-serializer.v1',
    'provider_order':('model','stream','messages','max_completion_tokens','metadata'),
    'metadata_order':('sylanne_call_id','sylanne_request_digest','sylanne_billing_contract'),
    'ensure_ascii':False,'separators':(',',':'),'allow_nan':False,'encoding':'utf-8'}
SERIALIZER_FINGERPRINT=canonical_digest(SERIALIZER_RULE)


def _digest(value):
    if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('actual 64 lowercase hexadecimal request commitment required')


@dataclass(frozen=True,slots=True)
class D13ProviderHTTPTemplateV1:
    model:str
    messages:tuple[tuple[str,str],...]
    max_completion_tokens:int
    generation_call_id:str
    billing_contract_digest:str
    serializer_pin:str
    late_path:tuple[str,str]=('metadata','sylanne_request_digest')
    late_kind:str='actual-model-call-request-digest-64lowerhex'
    schema:str=HTTP_TEMPLATE_SCHEMA
    def __post_init__(self):
        if (self.schema!=HTTP_TEMPLATE_SCHEMA or self.serializer_pin!=SERIALIZER_FINGERPRINT
                or self.late_path!=('metadata','sylanne_request_digest')
                or self.late_kind!='actual-model-call-request-digest-64lowerhex'
                or type(self.model) is not str or not self.model
                or type(self.generation_call_id) is not str or not self.generation_call_id
                or type(self.max_completion_tokens) is not int or self.max_completion_tokens<1
                or type(self.messages) is not tuple or len(self.messages)!=3
                or tuple(row[0] for row in self.messages)!=('system','user','user')
                or any(type(row) is not tuple or len(row)!=2 or type(row[1]) is not str for row in self.messages)):
            raise ValueError('closed actual V7 SDK HTTP template required')
        _digest(self.billing_contract_digest)
    @property
    def template_digest(self):return canonical_digest(asdict(self))
    @property
    def byte_count(self):return len(serialize_provider_http_v1(self,request_digest='0'*64))


def provider_http_template_v1(frozen,*,generation_call_id,billing_contract_digest,serializer_pin):
    if (type(frozen) is not FrozenNaturalReplyRequestV7
            or freeze_natural_reply_request_v7(frozen.input,frozen.installation)!=frozen):
        raise ValueError('exact frozen actual V7 semantic request required')
    return D13ProviderHTTPTemplateV1(frozen.installation.model_id,
        tuple((message.role,message.content) for message in frozen.messages),frozen.installation.max_output_tokens,
        generation_call_id,billing_contract_digest,serializer_pin)


def provider_http_body_v1(template,*,request_digest):
    if type(template) is not D13ProviderHTTPTemplateV1:raise TypeError('registered HTTP template required')
    _digest(request_digest)
    # Matches the actual OpenAI AsyncCompletions.create body order after omitted fields are removed.
    return {'model':template.model,'stream':False,
        'messages':[{'role':role,'content':content} for role,content in template.messages],
        'max_completion_tokens':template.max_completion_tokens,
        'metadata':{'sylanne_call_id':template.generation_call_id,'sylanne_request_digest':request_digest,
            'sylanne_billing_contract':template.billing_contract_digest}}


def serialize_provider_http_v1(template,*,request_digest):
    return json.dumps(provider_http_body_v1(template,request_digest=request_digest),
        ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')


def require_actual_provider_http_v1(template,*,request,content):
    """Check bytes captured from actual httpx.Request.content, never internal model wire."""
    from .broker import ModelCallRequest
    if (type(request) is not ModelCallRequest or request.call_id!=template.generation_call_id
            or request.model_id!=template.model or request.max_output_tokens!=template.max_completion_tokens
            or request.payload.get('messages')!=[{'role':role,'content':text} for role,text in template.messages]):
        raise ValueError('actual SDK HTTP late binding crossed its original model request')
    expected=serialize_provider_http_v1(template,request_digest=request.digest)
    if type(content) is not bytes or content!=expected or len(content)!=template.byte_count:
        raise ValueError('actual complete SDK HTTP bytes differ from signed fixed template')
    return sha256(content).hexdigest()
