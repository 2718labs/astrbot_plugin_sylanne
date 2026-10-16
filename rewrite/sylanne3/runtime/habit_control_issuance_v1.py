"""Closed internal control composition; normal execution and maintenance issuers stay distinct."""
from .habit_maintenance_issuance_v1 import _IssuedHabitMaintenanceV1


def require_habit_control_issuance_v1(issued,graph,scope):
    if type(issued)is _IssuedHabitMaintenanceV1:
        from .habit_maintenance_issuance_v1 import require_habit_maintenance_issuance_v1
        return require_habit_maintenance_issuance_v1(issued,graph,scope)
    from .habit_activity_issuance_v1 import require_habit_activity_issuance_v1
    return require_habit_activity_issuance_v1(issued,graph,scope)


def habit_control_deadline_v1(issued,reader):
    evidence=require_habit_control_issuance_v1(issued,reader.graph,issued.scope)
    if type(issued)is _IssuedHabitMaintenanceV1:
        from .habit_maintenance_source_v3 import habit_maintenance_source_reader_v3
        if habit_maintenance_source_reader_v3(reader)is None:
            raise ValueError('maintenance control deadline needs the actual private Source profile')
        return reader.operation.deadline_utc
    return min(reader.operation.deadline_utc,evidence.valid_until_utc)


def habit_control_request_digest_v1(selector):
    from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1
    if type(selector)is HabitOriginalMaintenanceSelectorV1:
        from .habit_maintenance_issuance_v1 import habit_maintenance_request_digest_v1
        return habit_maintenance_request_digest_v1(selector)
    from .habit_activity_issuance_v1 import habit_activity_request_digest_v1
    return habit_activity_request_digest_v1(selector)


def habit_control_finish_digest_v1(issued,graph,scope):
    from .habit_maintenance_issuance_v1 import _IssuedHabitMaintenanceV1,habit_maintenance_finish_digest_v1
    if type(issued)is _IssuedHabitMaintenanceV1:return habit_maintenance_finish_digest_v1(issued,graph,scope)
    from .habit_activity_issuance_v1 import habit_activity_finish_digest_v1
    return habit_activity_finish_digest_v1(issued,graph,scope)
