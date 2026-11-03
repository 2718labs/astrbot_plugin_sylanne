"""Closed dispatch for private installed background Owner observations."""


def require_background_issuance_v1(value, graph, authority, operation_id):
    from .d13_counter_prepare_owner_v1 import (
        D13CounterOwnerIssuanceV1,require_actual_d13_counter_owner_issuance_v1)
    from .domain_followup_consumer_v1 import _BackgroundFollowupV1, require_background_followup_v1
    from .d11_host_lifecycle_driver_v1 import _BackgroundHostLifecycleV1, require_background_host_lifecycle_v1
    from .d10_offline_recovery_driver_v1 import _BackgroundOfflineCommandV1, require_background_offline_command_v1
    from .contact_background_invocation_v1 import _BackgroundContactRecoveryV1, require_background_contact_recovery_v1
    if type(value) is _BackgroundContactRecoveryV1:
        return require_background_contact_recovery_v1(value, graph, authority, operation_id)
    if type(value) is _BackgroundFollowupV1:
        return require_background_followup_v1(value, graph, authority, operation_id)
    if type(value) is _BackgroundHostLifecycleV1:
        return require_background_host_lifecycle_v1(value, graph, authority, operation_id)
    if type(value) is _BackgroundOfflineCommandV1:
        return require_background_offline_command_v1(value, graph, authority, operation_id)
    if type(value)is D13CounterOwnerIssuanceV1:
        return require_actual_d13_counter_owner_issuance_v1(value,graph,authority,operation_id)
    raise TypeError("unregistered installed background issuance")


def observe_background_owner_v1(value, graph, authority, scope):
    require_background_issuance_v1(value, graph, authority, value.operation_id)
    from .d13_counter_prepare_owner_v1 import D13CounterOwnerIssuanceV1,observe_current_d13_counter_owner_write_v1
    if type(value)is D13CounterOwnerIssuanceV1:
        return observe_current_d13_counter_owner_write_v1(value,graph,scope)
    from .domain_followup_consumer_v1 import _observe_owner
    return _observe_owner(graph, authority, scope)
