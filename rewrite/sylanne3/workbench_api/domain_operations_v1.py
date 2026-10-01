"""Finite Owner-scoped W09 domain commands; JSON carries intent and locators only."""
from dataclasses import fields
from ..runtime.domain_production_registry_v1 import installed_operation_v1, _OPERATIONS
from ..runtime_contracts import canonical_digest

ACTIONS = {'domain_' + key: installed_operation_v1(key) for key in _OPERATIONS
    if key not in {'prepare_offline_tick', 'record_host_lifecycle'}}
from ..runtime.domain_production_inputs_v1 import _PRODUCERS
ACTIONS.update({'domain_input_' + key: installed_operation_v1('input:' + key) for key in _PRODUCERS})
INPUT_FIELDS = frozenset({'activity_id', 'audience_ref', 'parent_budget_lease_ref', 'request'})
_TUPLE_FIELDS = {'adopt_growth': {'trial_original_refs'}, 'adopt_joint_plan': {'party_consent_original_refs'},
    'prepare_life_project_context': {'norm_refs'}}


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
    if action not in ACTIONS or type(data) is not dict or set(data) != INPUT_FIELDS:
        raise ValueError('domain command input schema differs')
    for name in INPUT_FIELDS - {'request'}:
        if type(data[name]) is not str or not 1 <= len(data[name]) <= 4096:
            raise ValueError('domain command requires bounded actual identity locators')
    return decode_request_v1(ACTIONS[action].operation_kind, data['request'])


def execute_domain_operation_v1(issuer, *, session, action, scope, purpose, audience, operation_id, input_data):
    from .issuer import _unavailable
    from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
    operation = ACTIONS[action]
    if (audience != 'owner' or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
            or not session.owner_session_token or not session.allows(scope, operation.capability, purpose, audience)):
        return _unavailable('signed_owner_session_unavailable')
    request = validate_input_v1(action, dict(input_data))
    domains = ('d08','d11') if operation.operation_kind == 'prepare_source_note_action' else (
        ('d03','d06','d11') if operation.domain == 'd06' else ('d02','d06','d10','d11') if operation.domain == 'd10' else (
        ('d02','d07','d11') if operation.domain == 'd07' else (operation.domain,'d11'))
    )
    grant = issuer._resolve(session, scope, purpose, audience, domains=domains)
    if grant is None or operation.capability not in grant.capabilities:
        return _unavailable('domain_operation_authority_unavailable')
    result = issuer._coordinator.run_current_domain_operation_v1(grant.authority, grant.lease,
        operation_kind=operation.operation_kind, request=request, operation_id=operation_id,
        activity_id=input_data['activity_id'], audience_ref=input_data['audience_ref'],
        parent_budget_lease_ref=input_data['parent_budget_lease_ref'])
    if type(result) is not dict or result.get('operation_id') != operation_id:
        raise ValueError('domain operation returned no matching durable original')
    return {'status':'ready','receipt':{'schema':'d12.domain-operation-receipt.v1',
        'operation_id':operation_id,'action':action,'input_digest':canonical_digest(dict(input_data)),
        'original_digest':canonical_digest(result),'original':result}}
