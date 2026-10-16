"""Signed Owner-only current metadata; completion retains the actual Source READ."""
from ..graph_worker import GraphStorageWorkV3
from ..runtime_contracts import NamespaceId
from ..runtime.beta1_owner_state_read_v3 import (
    READ_KIND as ACTION, decode_owner_state_request_v1, owner_state_required_domains_v3,
    prepare_owner_state_read_v3, require_owner_state_work_v3)

INPUT_FIELDS = frozenset({'domain', 'refs'})


def validate_owner_state_input_v1(data):
    return decode_owner_state_request_v1(data)


def require_owner_state_command_work_v1(issuer, work, *, scope, input_data):
    request = validate_owner_state_input_v1(input_data)
    state = work.state
    require_owner_state_work_v3(work, issuer._coordinator, state.authority, state.lease, request)
    if state.authority.namespace != NamespaceId(*scope.split('/')):
        raise ValueError('Owner state Work crossed its exact current scope')
    return work


def _projection(value, *, scope, operation_id):
    if type(value) is not dict or set(value) != {'domain', 'items', 'coverage', 'missing_inputs'}:
        raise ValueError('Owner state requires its actual finite Source READ result')
    return {'status': 'ready', 'projection': {'schema': 'd12.beta1-owner-state.v1',
        'scope': scope, 'operation_id': operation_id, **value}}


def _raise(error):
    raise error


def execute_owner_state_read_v1(issuer, *, session, scope, purpose, audience, operation_id, input_data):
    from .issuer import _unavailable
    from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
    if (purpose != 'context' or audience != 'owner'
            or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
            or not session.owner_session_token
            or not session.allows(scope, 'workbench.read', purpose, audience)):
        return _unavailable('owner_state_current_signed_owner_unavailable')
    request = validate_owner_state_input_v1(input_data)
    grant = issuer._resolve(session, scope, purpose, audience, domains=tuple(sorted(owner_state_required_domains_v3(request))))
    if grant is None or 'workbench.read' not in grant.capabilities:
        return _unavailable('owner_state_current_read_authority_unavailable')
    work = prepare_owner_state_read_v3(issuer._coordinator, grant.authority, grant.lease, request=request)
    if type(work) is not GraphStorageWorkV3:
        raise TypeError('Owner state requires its actual installed serial Source READ Work')
    require_owner_state_command_work_v1(issuer, work, scope=scope, input_data=input_data)
    return work.map_terminal_v3('issuer', lambda value: _projection(value, scope=scope, operation_id=operation_id), _raise)
