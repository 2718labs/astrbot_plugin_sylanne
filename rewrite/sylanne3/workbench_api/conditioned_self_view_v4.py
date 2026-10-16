"""Explicit Owner SelfView reads through the installed Source-qualified READ Work."""
from ..runtime_contracts import NamespaceId, canonical_digest
from ..graph_worker import GraphStorageWorkV3

ACTION = 'read_current_self_view_v4'
INPUT_FIELDS = frozenset({'request'})


def validate_self_view_input_v4(input_data):
    from ..runtime.conditioned_self_operations_v1 import self_view_request_from_wire_v4
    if type(input_data) is not dict or set(input_data) != INPUT_FIELDS:
        raise ValueError('SelfView requires its exact typed read request')
    return self_view_request_from_wire_v4(input_data['request'])


def require_self_view_command_work_v4(issuer, work, *, scope, input_data):
    from ..runtime.current_conditioned_self_read_v3 import require_current_self_view_work_v4
    request = validate_self_view_input_v4(input_data)
    state = work.state
    require_current_self_view_work_v4(work, issuer._coordinator, state.authority, state.lease, request)
    if (state.authority.namespace != NamespaceId(*scope.split('/'))
            or state.authority.purpose != 'consolidation'
            or state.authority.audience != ('owner',)):
        raise ValueError('SelfView Work crossed its exact Owner read command')
    return work


def _projection_v4(view, *, scope, request_digest, operation_id, read_operation_id):
    from ..runtime.conditioned_self_operations_v1 import self_view_to_wire_v4
    wire = self_view_to_wire_v4(view)
    return {'status': 'ready', 'projection': {
        'schema': 'd12.self-view-projection.v4', 'scope': scope,
        'operation_id': operation_id, 'read_operation_id': read_operation_id,
        'request_digest': request_digest, 'view_digest': canonical_digest(wire), 'view': wire}}


def _raise(error):
    raise error


def execute_self_view_read_v4(issuer, *, session, scope, purpose, audience, operation_id, input_data):
    from .issuer import _unavailable
    from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
    if (purpose != 'consolidation' or audience != 'owner'
            or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
            or not session.owner_session_token
            or not session.allows(scope, 'workbench.read', purpose, audience)):
        return _unavailable('self_view_current_owner_read_unavailable')
    request = validate_self_view_input_v4(input_data)
    grant = issuer._resolve(session, scope, purpose, audience, domains=('d01', 'd02', 'd06', 'd07', 'd08', 'd11'))
    if grant is None or 'workbench.read' not in grant.capabilities:
        return _unavailable('self_view_current_owner_authority_unavailable')
    work = issuer._coordinator.read_current_self_view_v4(grant.authority, grant.lease, request=request)
    if type(work) is not GraphStorageWorkV3:
        raise TypeError('SelfView requires its actual installed Source READ Work')
    require_self_view_command_work_v4(issuer, work, scope=scope, input_data=input_data)
    request_digest = canonical_digest(input_data)
    read_operation_id = work.operation_id
    return work.map_terminal_v3('issuer',
        lambda view: _projection_v4(view, scope=scope, request_digest=request_digest,
            operation_id=operation_id, read_operation_id=read_operation_id), _raise)
