"""Owner policy issuance inside the same qualified W01 scope as its Graph mirror."""
from contextlib import contextmanager

from ..authority_service.d10_habit_contract_v1 import HabitStandingPolicyOriginalV1
from ..host.current_habit_occurrence_port_v1 import InstalledCurrentHabitOccurrencePortV1
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .d10_habit_v1 import POLICY_OPERATIONS


@contextmanager
def observe_habit_owner_policy_write_v1(graph, *, authority, lease, scope,
        operation_kind, request, operation_id):
    from .current_habit_source_read_v3 import (
        require_habit_owner_policy_write_v3, bind_habit_policy_core_original_v3)
    if operation_kind not in POLICY_OPERATIONS:
        raise ValueError('Habit policy observer requires its exact registered Owner command')
    require_habit_owner_policy_write_v3(graph, scope, authority, lease, operation_kind, request)
    port = graph._GraphCoordinator__habit_occurrence_port_v1
    if type(port) is not InstalledCurrentHabitOccurrencePortV1:
        raise TypeError('Habit policy requires its actual installed independent Core port')
    session_token, session_request = graph._GraphCoordinator__owner_session_proofs[lease]
    action = ('issue' if operation_kind == 'create_habit_policy_v1' else
        'revoke' if operation_kind == 'stop_habit_policy_v1' else 'revise')
    core_operation_id = 'habit-policy:' + operation_id
    try:
        original = port.change_current_habit_policy_v1(scope=scope, owner_actor_id=authority.actor,
            owner_session_token=session_token, owner_session_request=session_request,
            operation_id=core_operation_id, action=action, definition=request.definition)
        if (type(original) is not HabitStandingPolicyOriginalV1
                or original.namespace != authority.namespace or original.definition != request.definition
                or original.owner_actor_id != authority.actor
                or (original.operation_id, original.action) != (core_operation_id, action)):
            raise ValueError('Habit policy Core original differs from its actual Owner command')
        port.require_issued_policy_v3(scope=scope, definition=request.definition,
            operation_id=core_operation_id, action=action, original=original)
        bind_habit_policy_core_original_v3(graph, scope, operation_kind, request, original)
        yield ProductionOriginalRefV1(original.schema, original.original_ref, original.digest)
    finally:
        port.release_scope_v3(scope)
