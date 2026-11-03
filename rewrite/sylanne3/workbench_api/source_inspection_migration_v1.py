"""Named signed Owner ACCEPT/READ lane for the Authority inspection workflow."""
import math
from uuid import UUID

ACCEPT = 'accept_source_inspection_migration_v1'
READ = 'read_source_inspection_migration_v1'
ACTIONS = frozenset({ACCEPT, READ})
WORKFLOW_INPUT_FIELDS = frozenset({'pause_operation_id', 'resume_operation_id', 'resume_on_complete',
    'scope_kind', 'target_refs', 'deadline_utc', 'interpretation_status_discovery'})
INPUT_FIELDS = {ACCEPT: WORKFLOW_INPUT_FIELDS, READ: frozenset({'operation_id'})}
VIEW_SCHEMA = 'd12.source-inspection-workflow-view.v1'
VIEW_FIELDS = frozenset({'schema', 'scope', 'installation_id', 'operation_id', 'request_digest', 'state',
    'phase', 'hold_code', 'effective_deadline_utc', 'progress'}) | WORKFLOW_INPUT_FIELDS


def _uuid(value):
    parsed = UUID(value)
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError('inspection workflow requires a canonical UUID4 original')


def _workflow_input(value, *, scope, operation_id):
    from ..graph_types import AtomKey
    from ..authority_service.source_inspection_workflow_v1 import validate_workflow_input_v1
    validate_workflow_input_v1(operation_id, value)
    refs = value['target_refs']
    if (value['scope_kind'] not in {'exact_parent_closed_targets', 'namespace_source_family'}
            or type(refs) is not list or refs != sorted(set(refs)) or len(refs) > 32
            or (value['scope_kind'] == 'namespace_source_family') != (not refs)
            or type(value['deadline_utc']) not in (int, float) or not math.isfinite(value['deadline_utc'])
            or value['deadline_utc'] <= 0 or type(value['interpretation_status_discovery']) is not bool):
        raise ValueError('inspection workflow exact closure/deadline/status-discovery fields differ')
    for ref in refs:
        key = AtomKey.from_token(ref)
        if (key.token != ref or (key.owner.bot, key.owner.persona) != tuple(scope.split('/'))
                or key.type_name not in {'memory.source', 'memory.interpretation'}):
            raise ValueError('inspection target leaves its exact Owner namespace')


def validate_inspection_input_v1(action, value, *, scope, purpose, audience, operation_id):
    if (action not in ACTIONS or type(value) is not dict or set(value) != INPUT_FIELDS[action]
            or len(scope.split('/')) != 2 or audience != 'owner'
            or purpose != ('workbench_user_action' if action == ACCEPT else 'workbench_view')):
        raise ValueError('inspection workflow requires its exact signed Owner action/purpose')
    _uuid(operation_id)
    if action == READ:
        _uuid(value['operation_id'])
    else:
        _workflow_input(value, scope=scope, operation_id=operation_id)


def decode_inspection_view_v1(value, *, scope, operation_id):
    from ..authority_service.source_inspection_migration_v1 import decode_source_inspection_migration_progress_v1, _sha_v1
    from ..contracts import canonical_json
    from ..runtime_contracts import canonical_digest
    if (type(value) is not dict or set(value) != VIEW_FIELDS or value['schema'] != VIEW_SCHEMA
            or value['scope'] != scope or value['operation_id'] != operation_id
            or value['state'] not in {'accepted', 'running', 'completed', 'held'}
            or value['phase'] not in {'accepted', 'pausing', 'paused', 'migrating', 'migration_complete', 'resuming', 'active', 'held'}
            or type(value['installation_id']) is not str or not value['installation_id']):
        raise ValueError('inspection workflow view differs from its actual operation/namespace')
    _sha_v1(value['request_digest'])
    actual_input = {field: value[field] for field in WORKFLOW_INPUT_FIELDS}
    _workflow_input(actual_input, scope=scope, operation_id=operation_id)
    if (value['request_digest'] != canonical_digest(actual_input)
            or type(value['effective_deadline_utc']) not in (int, float)
            or not math.isfinite(value['effective_deadline_utc'])
            or not 0 < value['effective_deadline_utc'] <= value['deadline_utc']
            or (value['state'] == 'held') != (value['phase'] == 'held')
            or (value['state'] == 'held') != (value['hold_code'] is not None)
            or value['hold_code'] is not None and (type(value['hold_code']) is not str or not value['hold_code'])):
        raise ValueError('inspection workflow request/hold/deadline is not its accepted original')
    progress = value['progress']
    if progress is not None:
        _sha_v1(progress['request_digest'])
        decode_source_inspection_migration_progress_v1(canonical_json(progress),
            operation_id=operation_id, request_digest=progress['request_digest'])
    if value['state'] == 'completed' and (progress is None or progress['phase'] != 'completed'
            or value['phase'] != ('active' if value['resume_on_complete'] else 'paused')):
        raise ValueError('inspection workflow completion lacks its actual migration/resume receipt')
    return value


def execute_inspection_maintenance_v1(issuer, *, session, action, scope, purpose, audience, operation_id, input_data):
    from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
    port = issuer._package_maintenance_port
    if port is None:
        return {'status': 'unavailable', 'problem': {'code': 'inspection_maintenance_unavailable'}}
    original = input_data['operation_id'] if action == READ else operation_id
    required = {'workbench.read'} if action == READ else {'workbench.read', 'workbench.maintain', 'workbench.control'}
    if (audience != 'owner' or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
            or not session.owner_session_token or session.inspection_operation_id != original
            or not all(session.allows(scope, cap, purpose, audience) for cap in required)):
        raise PermissionError('inspection workflow requires actual current Owner operation/capabilities')
    try:
        if action == ACCEPT:
            value = port.accept_session_source_inspection_migration_v1(session=session, scope=scope,
                operation_id=operation_id, input_data=input_data)
        else:
            value = port.read_session_source_inspection_migration_v1(session=session, scope=scope, operation_id=original)
        value = decode_inspection_view_v1(value, scope=scope, operation_id=original)
        if action == ACCEPT and {name: value[name] for name in WORKFLOW_INPUT_FIELDS} != input_data:
            raise ValueError('inspection workflow acceptance returned another submitted request')
    except PermissionError:
        raise
    except (RuntimeError, OSError, ValueError, TypeError, KeyError):
        if action == READ:
            raise
        return {'status': 'pending_confirmation', 'problem': {'code': 'inspection_migration_unconfirmed',
            'operation_id': original, 'recovery_action': READ}}
    return {'status': 'ready' if action == READ or value['state'] == 'completed' else 'accepted',
        'projection' if action == READ else 'receipt': value}
