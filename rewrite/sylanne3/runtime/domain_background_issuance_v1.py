"""Closed dispatch for private installed background Owner observations."""


def require_background_issuance_v1(value, graph, authority, operation_id):
    from .domain_followup_consumer_v1 import _BackgroundFollowupV1, require_background_followup_v1
    from .d11_host_lifecycle_driver_v1 import _BackgroundHostLifecycleV1, require_background_host_lifecycle_v1
    from .d10_offline_recovery_driver_v1 import _BackgroundOfflineCommandV1, require_background_offline_command_v1
    if type(value) is _BackgroundFollowupV1:
        return require_background_followup_v1(value, graph, authority, operation_id)
    if type(value) is _BackgroundHostLifecycleV1:
        return require_background_host_lifecycle_v1(value, graph, authority, operation_id)
    if type(value) is _BackgroundOfflineCommandV1:
        return require_background_offline_command_v1(value, graph, authority, operation_id)
    raise TypeError("unregistered installed background issuance")


def observe_background_owner_v1(value, graph, authority, scope):
    require_background_issuance_v1(value, graph, authority, value.operation_id)
    from .domain_followup_consumer_v1 import _observe_owner
    return _observe_owner(graph, authority, scope)
