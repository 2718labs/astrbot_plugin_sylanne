"""Finite Owner-scoped W09 domain commands; JSON carries intent and locators only."""
from dataclasses import fields
from ..runtime.domain_production_registry_v1 import installed_operation_v1, _OPERATIONS
from ..runtime_contracts import canonical_digest
from ..graph_worker import GraphStorageWorkV3, GraphStorageContinuationRequiredV3
from ..runtime.conditioned_self_operations_v1 import (OPERATIONS as _CONDITIONED_OPERATIONS_V1,
    OWNER_CONFIGURED_CONDITIONED_OPERATIONS_V1, conditioned_request_from_wire_v1)

ACTIONS = {'domain_' + key: installed_operation_v1(key) for key in _OPERATIONS
    if key not in {'prepare_offline_tick', 'record_host_lifecycle'}
    and (key not in _CONDITIONED_OPERATIONS_V1 or key in OWNER_CONFIGURED_CONDITIONED_OPERATIONS_V1)}
from ..runtime.domain_production_inputs_v1 import _PRODUCERS
ACTIONS.update({'domain_input_' + key: installed_operation_v1('input:' + key) for key in _PRODUCERS
    if key!='freeze_joint_window_node_command_v1'})
ACTIONS['domain_adopt_owner_artifact_project_context_v1'] = installed_operation_v1('adopt_owner_artifact_project_context_v1')
ACTIONS['domain_submit_owner_source_note_task_v1'] = installed_operation_v1('submit_owner_source_note_task_v1')
ACTIONS['domain_admit_owner_material_source_v1'] = installed_operation_v1('admit_owner_material_source_v1')
_GENERAL_OWNER_OPERATIONS = frozenset(('freeze_general_growth_intent_v1','register_general_growth_trial_start_v1',
    'derive_general_growth_trial_v1','adopt_general_growth_v1'))
ACTIONS.update({'domain_'+kind:installed_operation_v1(kind) for kind in _GENERAL_OWNER_OPERATIONS})
_GENERAL_OWNER_DOMAINS_V1 = {
    "freeze_general_growth_intent_v1": ("d01", "d06", "d07", "d11"),
    "register_general_growth_trial_start_v1": ("d01", "d06", "d07", "d08", "d10", "d11"),
    "derive_general_growth_trial_v1": ("d01", "d06", "d07", "d08", "d10", "d11"),
    "adopt_general_growth_v1": ("d01", "d06", "d07", "d08", "d10", "d11"),
}
from ..domains.d03.world_history_v1 import WORLD_OPERATIONS
ACTIONS.update({'domain_'+kind:installed_operation_v1(kind) for kind in WORLD_OPERATIONS})

_CONDITIONED_OWNER_DOMAINS_V1 = {
    "register_calibration_policy_v1": ("d01", "d06", "d08", "d10", "d11"),
    "register_condition_predicate_v1": ("d01", "d06", "d08", "d10", "d11"),
    "register_simulation_forecast_plan_v1": ("d01", "d06", "d07", "d08", "d10", "d11"),
    "adopt_current_conditioned_self_v1": ("d01", "d02", "d06", "d07", "d08", "d10", "d11"),
    "rollback_current_conditioned_strategy_v1": ("d01", "d02", "d06", "d07", "d08", "d10", "d11"),
}

INPUT_FIELDS = frozenset({'activity_id', 'audience_ref', 'parent_budget_lease_ref', 'request'})

def input_fields_for_action_v1(action):
    return frozenset({'request'}) if action in {'domain_submit_owner_source_note_task_v1','domain_admit_owner_material_source_v1'} else INPUT_FIELDS

_TUPLE_FIELDS = {'adopt_growth': {'trial_original_refs'}, 'adopt_joint_plan': {'party_consent_original_refs'},
    'prepare_life_project_context': {'norm_refs'}, 'adopt_owner_artifact_project_context_v1': {'norm_refs'}}


_BETA1_LONG_TERM_OPERATIONS = frozenset(["adopt_long_term_plan_v1","prepare_joint_window_v1","enter_current_joint_window_v1","finalize_current_joint_window_v1","advance_long_term_window_v1","pause_long_term_plan_v1","resume_long_term_plan_v1","stop_long_term_plan_v1"])
_BETA1_HABIT_OPERATIONS = frozenset(["create_habit_policy_v1","revise_habit_policy_v1","pause_habit_policy_v1","resume_habit_policy_v1","stop_habit_policy_v1","register_habit_occurrence_v1","qualify_habit_occurrence_v1","record_habit_miss_v1","adopt_habit_outcome_v1"])

_BETA1_OWNER_DOMAINS = {
    "adopt_world_assertion_v1": ("d03", "d06", "d11"),
    "relearn_world_assertion_v1": ("d03", "d06", "d11"),
    "query_world_view_v1": ("d03", "d06", "d11"),
    "project_world_perspective_v1": ("d03", "d06", "d08", "d09", "d11"),
    "adopt_long_term_plan_v1": ("d06", "d08", "d10", "d11"),
    "prepare_joint_window_v1": ("d06", "d08", "d10", "d11"),
    "enter_current_joint_window_v1": ("d03", "d05", "d06", "d07", "d08", "d10", "d11"),
    "finalize_current_joint_window_v1": ("d03", "d05", "d06", "d07", "d08", "d10", "d11"),
    "advance_long_term_window_v1": ("d03", "d05", "d06", "d07", "d08", "d10", "d11"),
    "pause_long_term_plan_v1": ("d06", "d08", "d11"),
    "resume_long_term_plan_v1": ("d06", "d08", "d11"),
    "stop_long_term_plan_v1": ("d06", "d08", "d11"),
    "create_habit_policy_v1": ("d06", "d08", "d10", "d11"),
    "revise_habit_policy_v1": ("d06", "d08", "d10", "d11"),
    "pause_habit_policy_v1": ("d06", "d08", "d10", "d11"),
    "resume_habit_policy_v1": ("d06", "d08", "d10", "d11"),
    "stop_habit_policy_v1": ("d06", "d08", "d10", "d11"),
    "register_habit_occurrence_v1": ("d06", "d07", "d08", "d10", "d11"),
    "qualify_habit_occurrence_v1": ("d06", "d07", "d08", "d10", "d11"),
    "record_habit_miss_v1": ("d06", "d10", "d11"),
    "adopt_habit_outcome_v1": ("d02", "d06", "d08", "d10", "d11"),
    "serve_concern": ("d02", "d03", "d06", "d07", "d11"),
}

def decode_request_v1(kind, raw):
    operation = installed_operation_v1(kind)
    if kind in OWNER_CONFIGURED_CONDITIONED_OPERATIONS_V1:
        return conditioned_request_from_wire_v1(kind, raw)
    if kind in _BETA1_LONG_TERM_OPERATIONS:
        from ..runtime.d08_long_term_plan_v1 import long_term_request_from_wire_v1
        return long_term_request_from_wire_v1(kind, raw)
    if kind in _BETA1_HABIT_OPERATIONS:
        from ..runtime.d10_habit_v1 import habit_request_from_wire_v1
        return habit_request_from_wire_v1(kind, raw)
    if kind.startswith("input:") or kind in _GENERAL_OWNER_OPERATIONS or kind in WORLD_OPERATIONS:
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
    if operation.operation_kind in _BETA1_OWNER_DOMAINS:
        domains = _BETA1_OWNER_DOMAINS[operation.operation_kind]
    if operation.operation_kind in _GENERAL_OWNER_DOMAINS_V1:
        domains = _GENERAL_OWNER_DOMAINS_V1[operation.operation_kind]
    if operation.operation_kind=="run_simulation":
        domains=("d01","d02","d06","d07","d08","d10","d11")
    if operation.operation_kind in _CONDITIONED_OWNER_DOMAINS_V1:
        domains = _CONDITIONED_OWNER_DOMAINS_V1[operation.operation_kind]
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
        if result.kind == 'contact_host_stage_read_v3':
            from ..runtime.contact_host_stage_work_v3 import ContactHostStageReadWorkV3
            from ..runtime.contact_host_source_v3 import require_contact_host_work_v3
            from ..runtime.contact_owner_command_source_v3 import require_contact_owner_command_source_v3
            state=require_contact_host_work_v3(result.state)
            command=require_contact_owner_command_source_v3(state.owner_command,state=state)
            if (operation.operation_kind!='input:register_joint_contact_preparation_v1'
                    or type(state)is not ContactHostStageReadWorkV3 or state.work is not result
                    or result.coordinator is not issuer._coordinator or result.operation is not state.operation
                    or state.selector.stage!='joint_contact_preparation'
                    or command.operation_id!=operation_id or command.authority is not grant.authority
                    or command.lease is not grant.lease or command.request!=request):
                raise ValueError('Contact Source Work differs from its actual native Owner command')
            input_digest=canonical_digest(dict(input_data))
            return result.map_terminal_v3('issuer',
                lambda original:_domain_operation_receipt_v1(action=action,operation_id=operation_id,
                    result=original,input_digest=input_digest),_raise_domain_operation_error_v3)
        if result.kind in {'current_world_source_read_v3','current_d07_source_read_v3','current_d07_simulation_source_read_v3','current_d07_dispatch_read_v3'}:
            from ..runtime.current_beta1_source_read_v3 import require_beta1_source_w09_command_v3
            require_beta1_source_w09_command_v3(result,graph=issuer._coordinator,
                operation_kind=operation.operation_kind,request=request,authority=grant.authority,lease=grant.lease,
                operation_id=operation_id,activity_id=activity_id,audience_ref=audience_ref,parent_budget_lease_ref=parent)
            input_digest=canonical_digest(dict(input_data))
            return result.map_terminal_v3('issuer',lambda original:_domain_operation_receipt_v1(
                action=action,operation_id=operation_id,result=original,input_digest=input_digest),_raise_domain_operation_error_v3)
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
