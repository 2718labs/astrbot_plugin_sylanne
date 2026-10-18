#!/usr/bin/python3
"""Fixed isolated local-SDK-Mock whole-HTTP UTF-8 byte counter.

This executable implements only the installed Mock's ceil(bytes/4) metric.
It reads one bounded canonical JSON value from stdin and writes one bounded
canonical JSON result. It reads no file, environment configuration or network.
The installed worker independently pins its program/interpreter/profile.
"""
import hashlib
import json
import sys

METRIC_ID = 'sylanne3.local-sdk-mock.full-http-utf8-ceil4.v1'
INPUT_SCHEMA = 'sylanne3.d13.counter-kernel-input.v1'
OUTPUT_SCHEMA = 'sylanne3.d13.counter-kernel-output.v1'
MAX_INPUT_BYTES = 16 * 1024 * 1024


def canonical(value):
    return json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')


def local_mock_applicability_descriptor_v2(*,metric_source_sha256,program_sha256,interpreter_sha256,
        provider_id,model_id,provider_config_digest,template_digest,serializer_fingerprint,tokenizer_fingerprint,wire_policy_fingerprint):
    """Exact isolated Mock binding, never a production tokenizer qualification."""
    return {'schema':'sylanne3.d13.counter-applicability.v2','execution_abi':'python-isolated-self-contained.v1',
        'measurement':'provider-metered-input-for-complete-http-request','metric_id':METRIC_ID,
        'metric_source_sha256':metric_source_sha256,'program_sha256':program_sha256,
        'interpreter_sha256':interpreter_sha256,'provider_id':provider_id,'model_id':model_id,
        'provider_config_digest':provider_config_digest,'template_digest':template_digest,
        'serializer_fingerprint':serializer_fingerprint,'tokenizer_fingerprint':tokenizer_fingerprint,
        'wire_policy_fingerprint':wire_policy_fingerprint,
        'late_slot':{'path':['metadata','sylanne_request_digest'],'alphabet':'0123456789abcdef','characters':64,
            'coverage':'all-allowed-values','bound_evidence_sha256':metric_source_sha256}}


def unique_object(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise ValueError('duplicate JSON field')
        value[key]=item
    return value


def no_constant(value):
    raise ValueError('nonfinite JSON number')


def sha(value):
    if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('invalid digest')


def count_template(text,expected_digest,serializer_pin):
    if type(text) is not str or not text:
        raise ValueError('complete HTTP exemplar required')
    encoded=text.encode('utf-8')
    body=json.loads(text,object_pairs_hook=unique_object,parse_constant=no_constant)
    if (type(body) is not dict or tuple(body)!=('model','stream','messages','max_completion_tokens','metadata')
            or type(body['model']) is not str or not body['model'] or body['stream'] is not False
            or type(body['max_completion_tokens']) is not int or not 1<=body['max_completion_tokens']<=1024
            or type(body['messages']) is not list or len(body['messages'])!=3
            or any(type(m) is not dict or tuple(m)!=('role','content') or type(m['content']) is not str for m in body['messages'])
            or [m['role'] for m in body['messages']]!=['system','user','user']
            or type(body['metadata']) is not dict
            or tuple(body['metadata'])!=('sylanne_call_id','sylanne_request_digest','sylanne_billing_contract')):
        raise ValueError('complete actual provider HTTP shape differs')
    metadata=body['metadata']
    if (type(metadata['sylanne_call_id']) is not str or not metadata['sylanne_call_id']
            or metadata['sylanne_request_digest']!='0'*64):
        raise ValueError('closed call or count-only late digest exemplar differs')
    sha(metadata['sylanne_billing_contract']);sha(expected_digest)
    if json.dumps(body,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')!=encoded:
        raise ValueError('actual installed HTTP serialization differs')
    template={'model':body['model'],'messages':[[m['role'],m['content']] for m in body['messages']],
        'max_completion_tokens':body['max_completion_tokens'],'generation_call_id':metadata['sylanne_call_id'],
        'billing_contract_digest':metadata['sylanne_billing_contract'],'serializer_pin':serializer_pin,
        'late_path':['metadata','sylanne_request_digest'],'late_kind':'actual-model-call-request-digest-64lowerhex',
        'schema':'sylanne3.d13.provider-http-template.v1'}
    if hashlib.sha256(canonical(template)).hexdigest()!=expected_digest:
        raise ValueError('HTTP template commitment does not bind complete counted bytes')
    return len(encoded),max(1,(len(encoded)+3)//4)


def main():
    raw=sys.stdin.buffer.read(MAX_INPUT_BYTES+1)
    if not raw or len(raw)>MAX_INPUT_BYTES:
        raise ValueError('counter input size exceeds fixed bound')
    value=json.loads(raw,object_pairs_hook=unique_object,parse_constant=no_constant)
    required={'schema','raw_http_template_digest','compressed_http_template_digest','raw_http_utf8',
        'compressed_http_utf8','serializer_fingerprint','applicability_fingerprint','counter_policy_fingerprint'}
    if type(value) is not dict or set(value)!=required or value['schema']!=INPUT_SCHEMA or canonical(value)!=raw:
        raise ValueError('counter input is not the closed canonical original')
    for name in ('serializer_fingerprint','applicability_fingerprint','counter_policy_fingerprint'):
        sha(value[name])
    raw_size,raw_tokens=count_template(value['raw_http_utf8'],value['raw_http_template_digest'],value['serializer_fingerprint'])
    compressed_size=compressed_tokens=None
    if (value['compressed_http_utf8'] is None)!=(value['compressed_http_template_digest'] is None):
        raise ValueError('partial compressed variant')
    if value['compressed_http_utf8'] is not None:
        compressed_size,compressed_tokens=count_template(value['compressed_http_utf8'],
            value['compressed_http_template_digest'],value['serializer_fingerprint'])
    output={'schema':OUTPUT_SCHEMA,'input_digest':hashlib.sha256(raw).hexdigest(),
        'raw_http_template_digest':value['raw_http_template_digest'],
        'compressed_http_template_digest':value['compressed_http_template_digest'],
        'raw_http_bytes':raw_size,'compressed_http_bytes':compressed_size,
        'raw_lower_tokens':raw_tokens,'raw_upper_tokens':raw_tokens,
        'compressed_lower_tokens':compressed_tokens,'compressed_upper_tokens':compressed_tokens,
        'token_evidence':'bounded_full_wire',
        **{name:value[name] for name in ('serializer_fingerprint','applicability_fingerprint','counter_policy_fingerprint')}}
    sys.stdout.buffer.write(canonical(output));sys.stdout.buffer.flush()


if __name__=='__main__':
    try:
        main()
    except (ValueError,TypeError,KeyError,UnicodeError):
        sys.stderr.write('fixed local Mock counter rejected its bounded input\n')
        raise SystemExit(2)
