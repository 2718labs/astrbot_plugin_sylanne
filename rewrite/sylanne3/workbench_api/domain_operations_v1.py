"""Finite Owner-scoped W09 domain commands; JSON carries intent and locators only."""
from dataclasses import fields
from ..runtime.domain_production_registry_v1 import installed_operation_v1, _OPERATIONS
from ..runtime_contracts import canonical_digest
from ..graph_worker import GraphStorageWorkV3, GraphStorageContinuationRequiredV3

ACTIONS = {'domain_' + key: installed_operation_v1(key) for key in _OPERATIONS
    if key not in {'prepare_offline_tick', 'record_host_lifecycle'}}
from ..runtime.domain_production_inputs_v1 import _PRODUCERS
ACTIONS.update({'domain_input_' + key: installed_operation_v1('input:' + key) for key in _PRODUCERS})
ACTIONS['domain_adopt_owner_artifact_project_context_v1'] = installed_operation_v1('adopt_owner_artifact_project_context_v1')
ACTIONS['domain_submit_owner_source_note_task_v1'] = installed_operation_v1('submit_owner_source_note_task_v1')
ACTIONS['domain_admit_owner_material_source_v1'] = installed_operation_v1('admit_owner_material_source_v1')
INPUT_FIELDS = frozenset({'activity_id', 'audience_ref', 'parent_budget_lease_ref', 'request'})

def input_fields_for_action_v1(action):
    return frozenset({'request'}) if action in {'domain_submit_owner_source_note_task_v1','domain_admit_owner_material_source_v1'} else INPUT_FIELDS

_TUPLE_FIELDS = {'adopt_growth': {'trial_original_refs'}, 'adopt_joint_plan': {'party_consent_original_refs'},
    'prepare_life_project_context': {'norm_refs'}, 'adopt_owner_artifact_project_context_v1': {'norm_refs'}}


def decode_request_v1(kind, raw):
    operation = installed_operation_v1(kind)
    if kind.startswith("input:"):
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        return decode_typed_production_value_v1(raw, operation.request_type)
    names = {field.name for field in fields(operation.request_type)}
    if type(raw) is not dict or set(raw) != names:
        raise ValueError('domain command requires the exact registered intent fields')
    value = dict(raw)
    for name in _TUPLE_FIELDS.get(kind, ()):
        if type(value[name]) is not list or len(value[name]) > 16:
            raise ValueError('domain command original list is not bounded')
        value[name] = tuple(value[name])
    # All other fields in the fixed request catalogue are scalars or nullable
    # locators. Nested objects cannot smuggle authority receipts or policies.
    for name, item in value.items():
        if name not in _TUPLE_FIELDS.get(kind, ()) and type(item) not in (str, int, float, type(None)):
            raise ValueError('domain request field is not a registered scalar')
    return operation.request_type(**value)


def validate_input_v1(action, data):
    if action not in ACTIONS or type(data) is not dict or set(data) != input_fields_for_action_v1(action):
        raise ValueError('domain command input schema differs')
    for name in input_fields_for_action_v1(action) - {'request'}:
        if type(data[name]) is not str or not 1 <= len(data[name]) <= 4096:
            raise ValueError('domain command requires bounded actual identity locators')
    return decode_request_v1(ACTIONS[action].operation_kind, data['request'])


def _domain_operation_receipt_v1(*, action, operation_id, result, input_digest):
    if type(result) is not dict or result.get('operation_id') != operation_id:
        raise ValueError('domain operation returned no matching durable original')
    return {'status':'ready','receipt':{'schema':'d12.domain-operation-receipt.v1',
        'operation_id':operation_id,'action':action,'input_digest':input_digest,
        'original_digest':canonical_digest(result),'original':result}}


def _owner_material_terminal_receipt_v3(*, action, operation_id, input_data, state, result):
    from ..runtime.owner_material_source_storage_v3 import require_owner_material_input_witness_v3
    digest = require_owner_material_input_witness_v3(state.input_witness,
        request=input_data, operation_id=operation_id)
    return _domain_operation_receipt_v1(action=action, operation_id=operation_id,
        result=result, input_digest=digest)


def _raise_domain_operation_error_v3(error):
    raise error


def execute_domain_operation_v1(issuer, *, session, action, scope, purpose, audience, operation_id, input_data):
    from .issuer import _unavailable
    from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
    operation = ACTIONS[action]
    if (audience != 'owner' or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
            or not session.owner_session_token or not session.allows(scope, operation.capability, purpose, audience)):
        return _unavailable('signed_owner_session_unavailable')
    request = validate_input_v1(action, dict(input_data))
    domains = ('d02','d03','d06','d07','d08','d10','d11','d12') if operation.operation_kind=='submit_owner_source_note_task_v1' else ('d03','d08','d10','d11','d12') if operation.operation_kind == 'adopt_owner_artifact_project_context_v1' else (
        ('d08','d11') if operation.operation_kind == 'prepare_source_note_action' else (
        ('d03','d06','d11') if operation.domain == 'd06' else ('d02','d06','d10','d11') if operation.domain == 'd10' else (
        ('d02','d07','d11') if operation.domain == 'd07' else (operation.domain,'d11'))
    ))
    grant = issuer._resolve(session, scope, purpose, audience, domains=domains)
    if grant is None or operation.capability not in grant.capabilities:
        return _unavailable('domain_operation_authority_unavailable')
    if operation.operation_kind in {'submit_owner_source_note_task_v1','admit_owner_material_source_v1'}:
        from ..runtime.owner_source_note_task_contract_v1 import owner_source_note_task_ids_v1
        assembly = issuer._coordinator._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None or assembly.admin_bundle.installation_policy.namespace != grant.authority.namespace:
            return _unavailable('owner_source_note_actual_installation_unavailable')
        ids = owner_source_note_task_ids_v1(grant.authority.namespace, operation_id)
        activity_id = (ids['activity_id'] if operation.operation_kind=='submit_owner_source_note_task_v1'
            else 'owner-material:'+canonical_digest((grant.authority.namespace,operation_id))[:40])
        audience_ref, parent = 'owner', assembly.admin_bundle.installation_policy.root_lease.lease_id
    else:
        activity_id, audience_ref, parent = (input_data['activity_id'], input_data['audience_ref'],
            input_data['parent_budget_lease_ref'])
    if operation.operation_kind=='submit_owner_source_note_task_v1':
        result=issuer._coordinator.submit_owner_source_note_task_v1(grant.authority,grant.lease,
            request=request,operation_id=operation_id)
        if result.get('status') in {'owner_focus_held','focus_saved_task_not_saved'}:
            return {'status':'unavailable','problem':{'code':result['status'],'retryable':False,
                'operation_id':operation_id,'focus_operation_id':result['focus_operation_id'],
                'message':'任务前置 Focus 尚未闭合；未保存任务授权。'}}
    else:
        try:
            result = issuer._coordinator.run_current_domain_operation_v1(grant.authority, grant.lease,
                operation_kind=operation.operation_kind, request=request, operation_id=operation_id,
                activity_id=activity_id, audience_ref=audience_ref, parent_budget_lease_ref=parent)
        except GraphStorageContinuationRequiredV3:
            if operation.operation_kind == 'admit_owner_material_source_v1':
                return {'status':'unavailable','problem':{'code':'async_graph_worker_required','retryable':False}}
            raise
    if type(result) is GraphStorageWorkV3:
        if result.kind == 'current_method_learning_read_v3':
            from ..runtime.current_method_learning_read_v3 import (
                METHOD_INPUT_OPERATIONS_V3, _MethodLearningReadV3)
            state = result.state
            if (operation.operation_kind not in METHOD_INPUT_OPERATIONS_V3
                    or type(state) is not _MethodLearningReadV3
                    or state.work is not result or result.coordinator is not issuer._coordinator
                    or result.operation_id != operation_id or state.operation_kind != operation.operation_kind
                    or state.authority is not grant.authority or state.lease is not grant.lease
                    or state.request != request or state.activity_id != activity_id
                    or state.audience_ref != audience_ref or state.parent_budget_lease_ref != parent):
                raise ValueError('method continuation differs from its actual Owner command')
            input_digest = canonical_digest(dict(input_data))
            return result.map_terminal_v3('issuer',
                lambda original: _domain_operation_receipt_v1(action=action, operation_id=operation_id,
                    result=original, input_digest=input_digest), _raise_domain_operation_error_v3)
        if (operation.operation_kind != 'admit_owner_material_source_v1'
                or result.kind != 'owner_material_source_write_v3'
                or result.coordinator is not issuer._coordinator or result.operation_id != operation_id):
            raise ValueError('domain continuation differs from the actual Owner Source operation')
        state = result.state
        return result.map_terminal_v3('issuer',
            lambda original: _owner_material_terminal_receipt_v3(action=action, operation_id=operation_id,
                input_data=input_data, state=state, result=original), _raise_domain_operation_error_v3)
    return _domain_operation_receipt_v1(action=action, operation_id=operation_id,
        result=result, input_digest=canonical_digest(dict(input_data)))
