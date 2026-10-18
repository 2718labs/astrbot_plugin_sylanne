"""Closed applicability of an administrator-reviewed, self-contained D13 counter.

The installed program and provider metric evidence are external protected
assets. This contract validates their binding; it does not prove a tokenizer
correct or issue any model, Source or budget authorization.
"""
import json
from ..runtime_contracts import canonical_digest,canonical_serialize
from .contract import AuthorityUnavailable

SCHEMA='sylanne3.d13.counter-applicability.v2'
EXECUTION_ABI='python-isolated-self-contained.v1'
MEASUREMENT='provider-metered-input-for-complete-http-request'


def require_d13_counter_applicability_v2(raw,*,policy,metric_id,metric_source_sha256,
        program_sha256,interpreter_sha256):
    value=json.loads(raw)
    pins={'metric_id':metric_id,'metric_source_sha256':metric_source_sha256,
        'program_sha256':program_sha256,'interpreter_sha256':interpreter_sha256,
        'provider_id':policy.installation.provider_id,'model_id':policy.installation.model_id,
        'provider_config_digest':policy.installation.provider_config_digest,
        'template_digest':policy.template_digest,'serializer_fingerprint':policy.serializer_fingerprint,
        'tokenizer_fingerprint':policy.tokenizer_fingerprint,'wire_policy_fingerprint':policy.wire_policy_fingerprint}
    if (type(value)is not dict or set(value)!={'schema','execution_abi','measurement','late_slot',*pins}
            or canonical_serialize(value).encode('utf-8')!=raw
            or value['schema']!=SCHEMA or value['execution_abi']!=EXECUTION_ABI
            or value['measurement']!=MEASUREMENT or any(value[name]!=pin for name,pin in pins.items())
            or canonical_digest(value)!=policy.applicability_fingerprint):
        raise AuthorityUnavailable('counter applicability differs from its exact installed provider/program/evidence')
    late={'path':['metadata','sylanne_request_digest'],'alphabet':'0123456789abcdef','characters':64,
        'coverage':'all-allowed-values','bound_evidence_sha256':metric_source_sha256}
    if value['late_slot']!=late:
        raise AuthorityUnavailable('counter bounds must cover every allowed final request-digest value')
    return value
