"""Two exact signed Owner Source READ commands; metadata never grants Body."""
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..graph_worker import GraphStorageWorkV3
from ..runtime_contracts import NamespaceId
from ..runtime.source_inspection_metadata_read_v3 import LegacyInspectionMetadataUnavailableV3
from ..runtime.source_owner_read_v3 import (
    PAGE_ACTION, DETAIL_ACTION, decode_source_owner_request_v1,
    require_source_owner_work_v3, SourceOwnerCursorStaleV3, SourceOwnerReadIncompleteV3)

ACTIONS = frozenset({PAGE_ACTION, DETAIL_ACTION})
INPUT_FIELDS = {PAGE_ACTION: frozenset({'cursor', 'page_size'}),
    DETAIL_ACTION: frozenset({'source_id', 'expected_revision'})}


def validate_source_owner_input_v1(action, data):
    return decode_source_owner_request_v1(action, data)


def require_source_owner_command_work_v1(issuer, work, *, action, scope, input_data):
    request = validate_source_owner_input_v1(action, input_data)
    state = require_source_owner_work_v3(work, issuer._coordinator, action=action, request=request)
    if state.namespace != NamespaceId(*scope.split('/')):
        raise ValueError('Source READ Work crossed the exact current Owner scope')
    return state


def source_owner_error_v1(error):
    if type(error) is LegacyInspectionMetadataUnavailableV3:
        return {'status': 'unavailable', 'problem': {'code': 'legacy_metadata_unavailable', 'retryable': False}}
    if type(error) is SourceOwnerReadIncompleteV3:
        return {'status': 'partial', 'problem': {'code': 'source_read_incomplete', 'retryable': True}}
    if type(error) is SourceOwnerCursorStaleV3:
        return {'status': 'stale', 'problem': {'code': 'source_cursor_stale', 'retryable': False}}
    return {'status': 'unavailable', 'problem': {'code': 'source_read_unavailable', 'retryable': False}}


def execute_source_owner_read_v1(issuer, *, session, action, scope, purpose, audience, operation_id, input_data):
    if (purpose != 'context' or audience != 'owner'
            or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
            or not session.owner_session_token
            or not session.allows(scope, 'workbench.read', purpose, audience)):
        return source_owner_error_v1(None)
    request = validate_source_owner_input_v1(action, input_data)
    grant = issuer._resolve(session, scope, purpose, audience, domains=('d06', 'd11'))
    if grant is None or 'workbench.read' not in grant.capabilities:
        return source_owner_error_v1(None)
    try:
        work = getattr(issuer._coordinator, action)(grant.authority, grant.lease, request=request)
    except SourceOwnerCursorStaleV3 as error:
        return source_owner_error_v1(error)
    if type(work) is not GraphStorageWorkV3:
        raise TypeError('Source READ requires its actual installed serial Work')
    require_source_owner_command_work_v1(issuer, work, action=action, scope=scope, input_data=input_data)
    return work.map_terminal_v3('issuer', lambda value: {'status': 'ready',
        'projection': {'scope': scope, 'operation_id': operation_id, **value}}, source_owner_error_v1)
