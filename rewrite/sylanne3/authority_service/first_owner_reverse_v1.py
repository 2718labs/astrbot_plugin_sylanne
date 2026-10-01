"""First-Owner orchestration through the fixed, actually admitted Host.

The console bearer stays at Authority. The Host receives only original claim
material and performs the existing pending-grant Graph transaction.
"""
from dataclasses import asdict
from contextlib import ExitStack
from .contract import AuthorityUnavailable
from .v2_owner_contract import OwnerAuthorizationOperationV1,OwnerAuthorizationReceiptV1,OwnerClaimTicketV1,OwnerGraphCommitProofV1,from_wire,to_wire
from .v2_owner_session import OwnerSessionLoginRequestV1
from ..graph_coordinator import namespace_ref
from ..graph_types import validate_owner_grant_v1,owner_grant_policy_digest_v1
from ..runtime_contracts import canonical_digest

METHOD='first_owner_issue_v1'
SCHEMA='sylanne3.first-owner-graph-commit.v1'


def validate_first_owner_material_v1(ticket,operation,value):
    if (type(ticket) is not OwnerClaimTicketV1 or type(operation) is not OwnerAuthorizationOperationV1
            or operation.action!='issue' or operation.ticket!=ticket):
        raise AuthorityUnavailable('exact original first Owner ticket and operation required')
    validate_owner_grant_v1(value)
    if (value['authority_id']!=operation.authority_id or value['installation_id']!=operation.installation_id
            or value['grant_id']!=operation.grant_id or value['ticket_id']!=ticket.ticket_id
            or value['creation_operation_id']!=ticket.creation_operation_id or value['creation_digest']!=ticket.creation_digest
            or value['issue_operation_id']!=operation.operation_id or value['principal']!=asdict(ticket.principal)
            or operation.grant_digest!='sha256:'+canonical_digest(value)
            or ticket.policy_digest!=owner_grant_policy_digest_v1(value,bot=ticket.namespace.bot_id,persona=ticket.namespace.persona_id)):
        raise AuthorityUnavailable('first Owner policy differs from original paired creation')


def dispatch_first_owner_issue_v1(server,method,credential,profile_id,manifest_digest,command):
    if method!=METHOD:return None
    expected={'namespace','ticket','operation','grant_value','owner_session_token','owner_session_request'}
    if type(command) is not dict or set(command)!=expected:raise AuthorityUnavailable('closed first Owner console command required')
    namespace=command['namespace'];server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    peer=(credential.certificate_sha256,profile_id)
    installed=server._installations_v2[peer]
    ticket,operation=from_wire(command['ticket']),from_wire(command['operation'])
    if to_wire(ticket)!=command['ticket'] or to_wire(operation)!=command['operation']:
        raise AuthorityUnavailable('canonical first Owner originals required')
    validate_first_owner_material_v1(ticket,operation,command['grant_value'])
    if (ticket.authority_id!=server._authority_id() or ticket.installation_id!=installed.installation_id
            or namespace_ref(ticket.namespace)!=namespace or server._namespace_bindings_v2.get((*peer,ticket.namespace))!=namespace):
        raise AuthorityUnavailable('first Owner installed namespace differs')
    session=server._owner_session_kwargs(command,namespace,installed.installation_id)
    request=session.get('session_request')
    if (type(request) is not OwnerSessionLoginRequestV1 or request.audience!='sylanne-owner-console'
            or request.principal!=ticket.principal or server._v2_owner_sessions is None):
        raise AuthorityUnavailable('current independently signed console session required')
    def current_session():
        server._v2_owner_sessions.require_current(transport_credential=credential,
            token=session['session_token'],request=request)
    current_session()
    tickets=server._v2_owner_tickets
    if tickets is None:raise AuthorityUnavailable('installed Owner ticket store unavailable')
    committed=tickets.read_committed_issue(credential=credential,authority_namespace=namespace,operation=operation,**session)
    if committed is not None:
        current_session()
        return {'receipt':to_wire(committed)}
    maintenance=getattr(server,'_c09_maintenance_v1',None)
    reverse=server._final_handoff_reverse_v2.get(namespace)
    from .reverse_handoff import ReverseGraphClaimClient
    if maintenance is None or type(reverse) is not ReverseGraphClaimClient:
        raise AuthorityUnavailable('actual current Host and fixed reverse pairing required')
    selection=getattr(server,'_package_selection_v2',None)
    lifetime=ExitStack()
    try:
        admission=lifetime.enter_context(maintenance.gate.admit_peer_v1(peer=peer))
        for service in getattr(server,'_d12_installation_lifecycle_services_v1',{}).values():
            if service.peer==peer and service.namespace==namespace:
                lifetime.enter_context(service.rpc_activity_v1())
        context=maintenance.gate.control.read_verified_current_storage_v1();context.require_current('business')
        if admission[:2]!=(context.pointer_version,context.storage_generation):
            raise AuthorityUnavailable('first Owner Host storage admission changed')
        tickets=server._v2_owner_tickets
        if tickets is None:raise AuthorityUnavailable('installed Owner ticket store unavailable')
        current_session()
        if tickets.register_ticket(credential=credential,authority_namespace=namespace,ticket=ticket)!=ticket:
            raise AuthorityUnavailable('registered ticket differs')
        pending=tickets.reserve_issue(credential=credential,authority_namespace=namespace,operation=operation,**session)
        if type(pending) is not OwnerAuthorizationReceiptV1 or pending.operation!=operation or pending.phase!='pending':
            raise AuthorityUnavailable('exact pending first Owner issue unavailable')
        message=dict(schema=SCHEMA,profile_id=profile_id,installation_id=installed.installation_id,
            namespace=namespace,manifest_digest=manifest_digest,process_original=admission[4],
            pointer_version=admission[0],storage_generation=admission[1],storage_manifest_digest=context.manifest_digest,
            package_selection=None if selection is None else asdict(selection),
            ticket=command['ticket'],operation=command['operation'],grant_value=command['grant_value'])
        return _PreparedFirstOwnerIssueV1(server,credential,peer,namespace,operation,session,
            current_session,maintenance,admission,context,selection,reverse,message,lifetime)
    except BaseException:
        lifetime.close()
        raise


class _PreparedFirstOwnerIssueV1:
    """Private worker continuation; never serializable or accepted from a caller."""
    def __init__(self,server,credential,peer,namespace,operation,session,current_session,
                 maintenance,admission,context,selection,reverse,message,lifetime):
        self.server,self.credential,self.peer,self.namespace=server,credential,peer,namespace
        self.operation,self.session,self.current_session=operation,session,current_session
        self.maintenance,self.admission,self.context,self.selection=maintenance,admission,context,selection
        self.reverse,self.message=reverse,message
        self.channel_binding=None
        self._finished=False
        self._lifetime=lifetime

    def close(self):
        lifetime,self._lifetime=self._lifetime,None
        if lifetime is not None:lifetime.close()

    def reverse_call(self):
        # Called only outside the single Authority worker. Host is now free to
        # make its independently authenticated pending/fence/finish RPCs.
        return self.reverse.commit_first_owner_v1(self.message)

    def finalize(self,proof):
        if self._finished:raise AuthorityUnavailable('first Owner continuation already consumed')
        self._finished=True
        operation=self.operation
        if (type(proof) is not OwnerGraphCommitProofV1 or proof.namespace!=operation.namespace
                or proof.operation_id!=operation.operation_id or proof.request_digest!=operation.request_digest
                or proof.grant_digest!=operation.grant_digest):raise AuthorityUnavailable('first Owner graph proof differs')
        self.current_session()
        with self.maintenance.gate.admit_peer_v1(peer=self.peer) as current:
            if current!=self.admission:raise AuthorityUnavailable('first Owner Host process admission changed')
            self.context.require_current('business')
            if getattr(self.server,'_package_selection_v2',None)!=self.selection:
                raise AuthorityUnavailable('first Owner selected package changed')
            if self.selection is not None:
                from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
                actual,cohort,_=InstalledPackageSelectionFilesV2(control_directory='/etc/sylanne/maintenance').read_selected_configuration_cohort_v2()
                if actual!=self.selection or cohort.cohort_digest!=self.selection.cohort_digest:
                    raise AuthorityUnavailable('first Owner actual protected package selection changed')
            receipt=self.server._v2_owner_tickets.finalize_issue(credential=self.credential,
                authority_namespace=self.namespace,operation=operation,proof=proof,**self.session)
            self.current_session()
            if receipt.phase!='committed' or receipt.operation!=operation:
                raise AuthorityUnavailable('first Owner final original differs')
            result={'receipt':to_wire(receipt)}
            if self.channel_binding is not None:result['channel_binding_sha256']=self.channel_binding
            return result


async def _await_actual_completion_v1(future):
    """A cancelled waiter cannot release admission while its real work runs."""
    import asyncio
    cancelled=False
    while not future.done():
        try:
            await asyncio.shield(future)
        except asyncio.CancelledError:
            cancelled=True
        except BaseException:
            break
    if cancelled:
        if not future.cancelled():future.exception()
        raise asyncio.CancelledError
    return future.result()
