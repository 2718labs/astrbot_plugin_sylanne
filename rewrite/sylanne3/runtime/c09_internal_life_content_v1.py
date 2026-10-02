"""Closed Life-content preparation inventory; deletion is not yet issued.

Schema/row decoding never supplies authentication. A populated preparation
inventory remains HOLD until its worker/accounting/erasure chain is closed.
"""
import json

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .internal_life_content_preparation_v1 import (
    TABLE, require_internal_life_content_schema_v1, decode_internal_life_prepared_v1,
)
from .domain_production_originals_v1 import _receipt, _receipt_wire
from .d06_internal_life_episode_v2 import _sha

COLUMNS = ('bot', 'persona', 'kind', 'original_ref', 'payload_json', 'payload_digest', 'signature')


def validate_internal_life_content_inventory_row_v1(columns, row):
    if tuple(columns) != COLUMNS or len(row) != len(COLUMNS):
        raise ValueError('Life content installed inventory columns differ')
    bot, persona, kind, ref, encoded, digest, signature = row
    namespace = NamespaceId(bot, persona)
    _sha(digest); _sha(signature)
    raw = json.loads(encoded)
    if (type(ref) is not str or not ref.startswith('life-content-job:')
            or canonical_serialize(raw) != encoded or canonical_digest(raw) != digest):
        raise ValueError('Life content inventory exact bytes/selector differ')
    if kind == 'prepared':
        prepared = decode_internal_life_prepared_v1(raw)
        if prepared.namespace != namespace or prepared.job_id != ref:
            raise ValueError('Life content preparation inventory crossed scope')
    elif kind == 'prepare_commit':
        if type(raw) is not dict or set(raw) != {
                'schema', 'prepared_digest', 'operation_id', 'receipt', 'receipt_digest'}:
            raise ValueError('Life content commit inventory fields differ')
        if raw['schema'] != 'd06.internal-life-content-prepare-commit.v1':
            raise ValueError('Life content commit inventory version differs')
        _sha(raw['prepared_digest']); _sha(raw['receipt_digest'])
        receipt = _receipt(raw['receipt'])
        if (canonical_serialize(_receipt_wire(receipt)) != canonical_serialize(raw['receipt'])
                or receipt.status != 'committed' or receipt.operation_id != raw['operation_id']
                or canonical_digest(receipt) != raw['receipt_digest']
                or len(receipt.write_versions) != 1
                or receipt.write_versions[0].key.type_name != 'runtime.job'
                or receipt.write_versions[0].key.name != ref
                or NamespaceId.from_key(receipt.write_versions[0].key) != namespace):
            raise ValueError('Life content commit inventory receipt member differs')
    elif kind == 'request':
        from .natural_reply_job_v2 import _request_from_wire
        from .reply_model_job import reply_request_wire_v1
        from ..model_broker.internal_life_content_v1 import TEMPLATE_DIGEST
        if type(raw) is not dict or set(raw) != {'schema','prepared_digest','request_digest','worker_fence','wire'}:
            raise ValueError('Life acquired input inventory fields differ')
        if (raw['schema'] != 'd06.internal-life-content-request.v1'
                or type(raw['worker_fence']) is not int or raw['worker_fence'] < 1):
            raise ValueError('Life acquired input inventory version/fence differs')
        _sha(raw['prepared_digest']); _sha(raw['request_digest'])
        model = _request_from_wire(raw['wire'])
        if (model.envelope.authority.namespace != namespace or model.identity.phase != 'internal_life_content'
                or model.envelope.authority.purpose != 'consolidation'
                or model.envelope.authority.worker_fence != raw['worker_fence']
                or model.prompt_template_digest != TEMPLATE_DIGEST or model.digest != raw['request_digest']
                or canonical_serialize(reply_request_wire_v1(model.envelope, model)) != raw['wire']):
            raise ValueError('Life acquired input is not its exact canonical closed model request')
    elif kind == 'acquire_commit':
        if type(raw) is not dict or set(raw) != {
                'schema','prepared_digest','request_digest','operation_id','receipt','receipt_digest'}:
            raise ValueError('Life acquisition commit inventory fields differ')
        if raw['schema'] != 'd06.internal-life-content-acquire-commit.v1':
            raise ValueError('Life acquisition commit version differs')
        for name in ('prepared_digest','request_digest','receipt_digest'):
            _sha(raw[name])
        receipt = _receipt(raw['receipt'])
        if (canonical_serialize(_receipt_wire(receipt)) != canonical_serialize(raw['receipt'])
                or receipt.status != 'committed' or receipt.operation_id != raw['operation_id']
                or canonical_digest(receipt) != raw['receipt_digest']
                or len(receipt.write_versions) != 1 or receipt.write_versions[0].revision != 2
                or receipt.write_versions[0].key.type_name != 'runtime.job'
                or receipt.write_versions[0].key.name != ref
                or NamespaceId.from_key(receipt.write_versions[0].key) != namespace):
            raise ValueError('Life acquisition commit actual job member differs')
    else:
        raise ValueError('unregistered Life content original kind')
    return raw
