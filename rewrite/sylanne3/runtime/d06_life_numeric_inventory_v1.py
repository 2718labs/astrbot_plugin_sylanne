"""Closed numeric-Life original codecs for C09 inventory, not authorization.

The existing signed Life table is shared with other finite original families.
These kinds remain a distinct nonempty C09 closure until their actual content
disposition and embedded cost/terminal fact preservation are implemented.
"""
import json
from dataclasses import fields

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d06_internal_life_episode_v2 import _sha

COLUMNS = ('bot', 'persona', 'kind', 'original_ref', 'producing_operation_id',
           'payload_json', 'payload_digest', 'signature')
KINDS = frozenset({'numeric_prepared_v1', 'numeric_binding_v1', 'numeric_request_v1',
    'numeric_acquire_commit_v1', 'numeric_call_v1', 'numeric_paid_v1', 'numeric_appraisal_acceptance_v1',
    'numeric_read_attempt_v1'})
MIXED_CONTENT_AND_FACT_KINDS = frozenset({'numeric_call_v1', 'numeric_paid_v1'})
MAX_PAYLOAD_BYTES = 2097152


def _fields(raw, names, schema):
    if type(raw) is not dict or set(raw) != set(names) or raw.get('schema') != schema:
        raise ValueError('Life numeric inventory closed original schema differs')


def validate_life_numeric_inventory_row_v1(columns, row):
    if tuple(columns) != COLUMNS or type(row) is not tuple or len(row) != 8:
        raise ValueError('Life numeric inventory exact table columns differ')
    bot, persona, kind, ref, operation, encoded, digest, signature = row
    ns = NamespaceId(bot, persona)
    _sha(digest); _sha(signature)
    if (kind not in KINDS or type(encoded) is not str or len(encoded.encode('utf-8')) > MAX_PAYLOAD_BYTES
            or any(type(v) is not str or not 1 <= len(v) <= 4096 for v in (ref, operation))):
        raise ValueError('Life numeric inventory exceeds its finite family')
    raw = json.loads(encoded)
    if canonical_serialize(raw) != encoded or canonical_digest(raw) != digest:
        raise ValueError('Life numeric inventory payload commitment differs')
    if kind == 'numeric_prepared_v1':
        from .d06_life_numeric_task_v1 import decode_life_numeric_prepared_v1
        value = decode_life_numeric_prepared_v1(raw)
        if (value.namespace, value.job_id, value.operation_id) != (ns, ref, operation):
            raise ValueError('Life numeric prepared inventory crossed scope')
    elif kind == 'numeric_binding_v1':
        from .d06_life_numeric_worker_v1 import decode_life_numeric_worker_binding_v1
        value = decode_life_numeric_worker_binding_v1(raw)
        if (value.namespace, value.job_id, value.acquire_operation_id) != (ns, ref, operation):
            raise ValueError('Life numeric worker inventory crossed scope')
    elif kind == 'numeric_read_attempt_v1':
        from ..authority_service.current_life_numeric_v1 import (LifeNumericModelResultReadRequestV1,
            life_numeric_result_from_wire_v1)
        value = life_numeric_result_from_wire_v1(raw, LifeNumericModelResultReadRequestV1)
        if (value.namespace, value.read_attempt_id, value.acquire_operation_id) != (ns, ref, operation):
            raise ValueError('Life numeric result selector inventory crossed scope')
    elif kind == 'numeric_appraisal_acceptance_v1':
        from .d06_life_numeric_task_v1 import decode_life_numeric_appraisal_acceptance_v1
        value = decode_life_numeric_appraisal_acceptance_v1(raw)
        if (value.namespace, value.appraisal_ref, value.operation_id) != (ns, ref, operation):
            raise ValueError('Life numeric adoption inventory crossed scope')
    else:
        suffix = ref.removeprefix('life-numeric-job:')
        if len(suffix) != 48 or any(c not in '0123456789abcdef' for c in suffix) or ref != 'life-numeric-job:' + suffix:
            raise ValueError('Life numeric worker inventory has another once family')
        acquire, call = 'life-numeric-acquire:' + suffix, 'life-numeric-call:' + suffix
        if kind != 'numeric_paid_v1' and operation != acquire:
            raise ValueError('Life numeric worker original has another producer')
        if kind == 'numeric_request_v1':
            from .natural_reply_job_v2 import _request_from_wire
            from ..model_broker.internal_life_numeric_v1 import TEMPLATE_DIGEST
            _fields(raw, ('schema', 'prepared_digest', 'binding_digest', 'request_digest', 'wire'),
                    'd06.internal-life-numeric-request.v1')
            model = _request_from_wire(raw['wire'])
            if (model.envelope.authority.namespace != ns or model.identity.operation_id != acquire
                    or model.identity.phase != 'internal_life_numeric_v1' or model.call_id != call
                    or model.envelope.authority.purpose != 'consolidation' or model.envelope.authority.worker_fence != 1
                    or model.prompt_template_digest != TEMPLATE_DIGEST or model.digest != raw['request_digest']):
                raise ValueError('Life numeric model inventory changed its actual call family')
        elif kind == 'numeric_acquire_commit_v1':
            from .domain_production_originals_v1 import _receipt
            _fields(raw, ('schema', 'prepared_digest', 'binding_digest', 'receipt', 'request_digest', 'receipt_digest'),
                    'd06.internal-life-numeric-acquire-commit.v1')
            receipt = _receipt(raw['receipt'])
            if (receipt.status != 'committed' or receipt.operation_id != acquire
                    or canonical_digest(receipt) != raw['receipt_digest'] or len(receipt.write_versions) != 1
                    or receipt.write_versions[0].key.type_name != 'runtime.job'
                    or receipt.write_versions[0].key.name != ref or receipt.write_versions[0].revision != 2
                    or NamespaceId.from_key(receipt.write_versions[0].key) != ns):
                raise ValueError('Life numeric acquisition inventory receipt differs')
        elif kind == 'numeric_call_v1':
            from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
            from ..authority_service.v2_model_egress_wire import from_wire
            from ..authority_service.v2_contract import FencePermitV2, from_wire as permit_from_wire
            _fields(raw, ('schema', 'prepared_digest', 'binding_digest', 'request_digest', 'intent', 'permit'),
                    'd06.internal-life-numeric-call.v1')
            intent = from_wire(raw['intent'], ModelEgressIntentV1)
            permit = permit_from_wire(raw['permit'])
            if (type(permit) is not FencePermitV2 or intent.job_id != ref or intent.call_id != call
                    or intent.operation_id != acquire or intent.binding_digest != raw['binding_digest']
                    or intent.request_digest != raw['request_digest'] or permit.operation != 'model_egress'
                    or (permit.subject, permit.operation_id, permit.token, permit.fence_epoch, permit.revision) !=
                       (intent.subject, intent.operation_id, intent.fence_token, intent.fence_epoch, intent.fence_revision)):
                raise ValueError('Life numeric call inventory lacks its exact intent/permit family')
        else:
            from ..authority_service.current_life_numeric_v1 import LifeNumericModelResultReadV1, life_numeric_result_from_wire_v1
            from .model_cost_settlement import OriginalModelCostCommitV1, original_model_cost_operation_id_v1
            _fields(raw, ('schema', 'prepared_digest', 'binding_digest', 'result', 'cost', 'cost_digest', 'paid'),
                    'd06.internal-life-numeric-paid-result.v1')
            result = life_numeric_result_from_wire_v1(raw['result'], LifeNumericModelResultReadV1)
            if type(raw['cost']) is not dict or set(raw['cost']) != {f.name for f in fields(OriginalModelCostCommitV1)}:
                raise ValueError('Life numeric cost inventory fields differ')
            cost = OriginalModelCostCommitV1(**raw['cost'])
            if (raw['paid'] is not True or result.request.namespace != ns or result.request.job_id != ref
                    or result.request.call_id != call or result.request.binding_digest != raw['binding_digest']
                    or result.request.prepared_digest != raw['prepared_digest'] or cost.call_id != call
                    or operation != original_model_cost_operation_id_v1(ns, call) or cost.operation_id != operation
                    or cost.status != 'committed' or canonical_digest(cost) != raw['cost_digest']):
                raise ValueError('Life numeric paid inventory mixed content/fact linkage differs')
        for name in ('prepared_digest', 'binding_digest'):
            _sha(raw[name])
        for name in ('request_digest', 'receipt_digest', 'cost_digest'):
            if name in raw: _sha(raw[name])
    return raw
