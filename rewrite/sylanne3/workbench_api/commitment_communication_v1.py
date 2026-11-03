"""Signed Owner W09 command for one approved exact-literal communication."""
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..graph_types import AtomKey
from ..graph_worker import GraphStorageWorkV3
from ..runtime_contracts import CommitReceipt, NamespaceId, canonical_digest
from ..runtime.d08_commitment_dispatch_v1 import PrepareCurrentCommitmentCommunicationRequestV1

ACTION = 'prepare_current_commitment_communication_v1'
INPUT_FIELDS = frozenset({'scope_ref', 'c02_operation_id', 'source_ref', 'deadline_utc'})
_DOMAINS = ('d01', 'd03', 'd05', 'd06', 'd07', 'd08', 'd09', 'd11')
_COMMANDS = WeakKeyDictionary()


def validate_commitment_communication_input_v1(data):
    if type(data) is not dict or set(data) != INPUT_FIELDS:
        raise ValueError('communication command requires its exact approved Scope selectors')
    return PrepareCurrentCommitmentCommunicationRequestV1(**data)


def execute_commitment_communication_v1(issuer, *, session, scope, purpose, audience, operation_id, input_data):
    from ..runtime_context import RuntimeContext
    from .issuer import _unavailable
    request = validate_commitment_communication_input_v1(dict(input_data))
    context, graph = issuer._runtime_context, issuer._coordinator
    if (type(context) is not RuntimeContext or context._v2_coordinator is not graph
            or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
            or not session.owner_session_token or purpose != 'context' or audience != 'owner'
            or any(not session.allows(scope, capability, purpose, audience)
                   for capability in ('workbench.read', 'workbench.activate'))):
        return _unavailable('signed_commitment_owner_session_unavailable')
    grant = issuer._resolve(session, scope, purpose, audience, domains=_DOMAINS)
    if grant is None or not {'workbench.read', 'workbench.activate'} <= set(grant.capabilities):
        return _unavailable('commitment_communication_owner_authority_unavailable')
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    bundle = context._v2_model_bundle
    if (assembly is None or bundle is not assembly.admin_bundle or context._v2_bootstrap is None
            or bundle.installation_policy.namespace != grant.authority.namespace
            or any(NamespaceId.from_key(AtomKey.from_token(ref)) != grant.authority.namespace
                   for ref in (request.scope_ref, request.source_ref))):
        return _unavailable('commitment_communication_actual_installation_unavailable')
    # The browser submits selectors only. Source ALL, current Owner/Self, exact
    # approved text, final checks and the actual W01 dispatch seal stay in Graph.
    work = graph.prepare_current_commitment_communication_v1(context._v2_bootstrap, bundle,
        scope_ref=request.scope_ref, c02_operation_id=request.c02_operation_id,
        source_ref=request.source_ref, deadline_utc=request.deadline_utc)
    _COMMANDS[work] = (graph, context, grant.authority.namespace, request,
                       operation_id, scope, purpose, canonical_digest(dict(input_data)))
    require_commitment_communication_work_v1(issuer, work, scope=scope, purpose=purpose,
        audience=audience, operation_id=operation_id, input_data=input_data)
    # Graph already owns its issuer mapper. W09 uses only the service mapper,
    # retaining the current Owner resolver scope through the existing worker.
    return work


def require_commitment_communication_work_v1(issuer, work, *, scope, purpose, audience, operation_id, input_data):
    from ..runtime.current_graph_full_read_v3 import _OrdinaryFullReadV3, COMMITMENT_COMMUNICATION_FULL_READ_V1
    request = validate_commitment_communication_input_v1(dict(input_data))
    expected = (issuer._coordinator, issuer._runtime_context,
                issuer._runtime_context._v2_model_bundle.installation_policy.namespace,
                request, operation_id, scope, purpose, canonical_digest(dict(input_data)))
    if (type(work) is not GraphStorageWorkV3 or _COMMANDS.get(work) != expected
            or audience != 'owner' or purpose != 'context'
            or work.coordinator is not issuer._coordinator
            or type(work.state) is not _OrdinaryFullReadV3
            or work.kind != 'current_graph_full_read_v3' or work.state.work is not work
            or work.operation is not work.state.operation
            or work.state.contract is not COMMITMENT_COMMUNICATION_FULL_READ_V1
            or work.state.commitment_scope_ref != request.scope_ref
            or work.state.source_locator.c02_operation_id != request.c02_operation_id
            or work.state.source_locator.source_ref != request.source_ref):
        raise AuthorityUnavailable('communication continuation differs from its actual signed Owner command')
    work._require_invocation(issuer._coordinator, initial=True)
    return request


def commitment_communication_result_v1(operation_id, input_data, result):
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..host.post_c02_reply_driver import post_c02_reply_operation_id
    request = validate_commitment_communication_input_v1(dict(input_data))
    actual_operation = post_c02_reply_operation_id(request.c02_operation_id, request.source_ref)
    if (type(result) is not dict or set(result) != {
            'status', 'operation_id', 'scope_ref', 'commit_receipt', 'job_ref', 'outbox_ref'}
            or result['status'] != 'commitment_communication_dispatch_committed'
            or result['operation_id'] != actual_operation or result['scope_ref'] != request.scope_ref
            or type(result['commit_receipt']) is not CommitReceipt
            or result['commit_receipt'].status != 'committed'
            or result['commit_receipt'].operation_id != actual_operation
            or any(type(result[name]) is not str or not result[name] for name in ('job_ref', 'outbox_ref'))):
        raise AuthorityUnavailable('communication has no exact actual dispatch commit original')
    original = plain_v1(result)
    return {'status': 'ready', 'receipt': {
        'schema': 'd12.commitment-communication-receipt.v1', 'action': ACTION,
        'operation_id': operation_id, 'input_digest': canonical_digest(dict(input_data)),
        'original_digest': canonical_digest(original), 'original': original}}


def valid_commitment_communication_receipt_v1(receipt, operation_id, input_data):
    from ..host.post_c02_reply_driver import post_c02_reply_operation_id
    request = validate_commitment_communication_input_v1(dict(input_data))
    original = receipt.get('original')
    return (set(receipt) == {'schema', 'action', 'operation_id', 'input_digest', 'original_digest', 'original'}
        and receipt['schema'] == 'd12.commitment-communication-receipt.v1'
        and receipt['action'] == ACTION and receipt['operation_id'] == operation_id
        and receipt['input_digest'] == canonical_digest(dict(input_data))
        and type(original) is dict and receipt['original_digest'] == canonical_digest(original)
        and original.get('status') == 'commitment_communication_dispatch_committed'
        and original.get('scope_ref') == request.scope_ref
        and original.get('operation_id') == post_c02_reply_operation_id(request.c02_operation_id, request.source_ref))
