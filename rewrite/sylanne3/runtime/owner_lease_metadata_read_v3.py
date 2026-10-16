"""Selected V3 Owner lease/view metadata over the actual signed session.

A provisional D12 capability remains unusable by business authorization until
the original grant caller registers the complete fixed-EOF binding.
"""
from dataclasses import dataclass
from threading import get_ident
import secrets
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.v2_owner_contract import OwnerPrincipalV1
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..runtime_storage_v3 import runtime_storage_v3,runtime_storage_operation_v3
from ..runtime_contracts import AuthorityContext

_READERS = WeakKeyDictionary()


@dataclass(eq=False,slots=True,weakref_slot=True)
class _OwnerLeaseReadV3:
    graph:object
    bootstrap:object
    authority:object
    owner_principal:object
    owner_session_proof:object
    provisional_lease:object
    mode:str
    operation:object
    fence:object
    bundle:object
    thread:int
    owner_entry:object = None
    closed:bool = False
    @property
    def store(self):return self.graph._GraphCoordinator__store
    @property
    def db(self):return self.store._db
    @property
    def read_scope(self):return self.fence.scope
    @property
    def namespace(self):return self.authority.namespace
    @property
    def graph_stamp(self):return self.fence.metadata,self.fence.epoch
    def _identity_v3(self):
        return (self.graph,self.bootstrap,self.authority,self.owner_principal,self.owner_session_proof,
            self.provisional_lease,self.mode,self.operation,self.fence,self.bundle,self.thread)


def require_current_owner_lease_reader_v3(reader):
    from ..host.authority_profile import AdminInstallationBundle
    from ..graph_coordinator import ProductionGraphStore
    if (type(reader)is not _OwnerLeaseReadV3 or _READERS.get(reader)!=reader._identity_v3()
            or reader.closed or reader.thread!=get_ident()):
        raise AuthorityUnavailable('Owner lease metadata requires its exact private preparation caller')
    graph=reader.graph
    graph._admin(reader.bootstrap)
    from ..host.authority_profile import current_owner_metadata_installation_v3
    actual_bundle,package_root,verified=current_owner_metadata_installation_v3(graph,expected_bundle=reader.bundle)
    token,request=reader.owner_session_proof
    scope=reader.read_scope;authority=reader.authority;port=graph._GraphCoordinator__content_fence_v2
    if (not isinstance(reader.store,ProductionGraphStore)
            or type(reader.bundle)is not AdminInstallationBundle or actual_bundle is not reader.bundle
            or reader.namespace!=reader.bundle.installation_policy.namespace
            or type(request)is not OwnerSessionLoginRequestV1 or not token
            or type(reader.owner_principal)is not OwnerPrincipalV1 or request.principal!=reader.owner_principal
            or type(authority)is not AuthorityContext or authority.issuer_domain!='d12'
            or scope.operation!='read' or scope.namespace!=reader.namespace
            or scope.generation!=authority.activation_generation or reader.fence.authority is not authority
            or reader.fence.owner_binding is not None or reader.fence.owner_principal is not None
            or reader.fence.fence_observer is not None
            or reader.fence.owner_session_proof is not reader.owner_session_proof
            or scope.authority_namespace!=reader.bundle.installation_policy.authority_namespace
            or scope.permit.holder!=reader.bundle.installation_policy.administrator_holder
            or port.installation_grant.installation_id!=reader.bundle.installation_policy.installation_id
            or reader.operation.closed or reader.operation.handle is not runtime_storage_v3(reader.db)
            or reader.operation.selection_digest!=reader.operation.handle.selection_digest):
        raise AuthorityUnavailable('Owner lease metadata left its real session/READ/selected installation')
    if reader.mode=='grant':
        record=graph._GraphCoordinator__leases.get(reader.provisional_lease)
        if (record is None or record[:4]!=(authority.capability_ref,authority.actor,'d12',reader.namespace)
                or record[6]!=authority.activation_generation or tuple(sorted(record[5]))!=authority.owner_scope
                or reader.provisional_lease in graph._GraphCoordinator__owner_leases
                or reader.provisional_lease in graph._GraphCoordinator__owner_session_proofs
                or authority.provider_policy_ref!='owner-grant-v1'):
            raise AuthorityUnavailable('Owner provisional capability changed or escaped before fixed EOF')
    elif reader.mode=='view':
        if (reader.provisional_lease is not None or authority.provider_policy_ref!='owner-view-v1'
                or authority.owner_scope!=('persona',) or not authority.capability_ref.startswith('owner-view:')):
            raise AuthorityUnavailable('Owner metadata view cannot mint a process lease')
    else:
        raise AuthorityUnavailable('Owner lease metadata has another preparation mode')
    return reader


def read_current_owner_lease_metadata_v3(issuer,graph,bootstrap,*,authority,owner_principal,
        owner_session_proof,provisional_lease=None):
    from ..graph_coordinator import _OWNER_LEASE_METADATA_READ_ISSUER_V3,CurrentOwnerViewV1
    from ..host.authority_profile import AdminInstallationBundle,current_owner_metadata_installation_v3
    from ..authority_service.owner_location_read_v3 import prepare_current_host_owner_lease_read_entry_v3
    if issuer is not _OWNER_LEASE_METADATA_READ_ISSUER_V3:
        raise AuthorityUnavailable('Owner lease EOF must originate in the actual Graph grant/view entry')
    graph._admin(bootstrap)
    bundle,package_root,verified=current_owner_metadata_installation_v3(graph)
    if type(bundle)is not AdminInstallationBundle or owner_session_proof is None:
        raise AuthorityUnavailable('Selected V3 Owner metadata requires its actual installation and signed session')
    operation_id='owner-lease-read:'+secrets.token_hex(24)
    state=None;fence=None
    with runtime_storage_operation_v3(graph._GraphCoordinator__store._db,operation_id=operation_id)as operation:
        try:
            fence=graph._begin_read_fence_v3(authority,operation_id=operation_id,
                owner_session_proof=owner_session_proof)
            state=_OwnerLeaseReadV3(graph,bootstrap,authority,owner_principal,owner_session_proof,provisional_lease,
                'grant' if provisional_lease is not None else 'view',operation,fence,bundle,get_ident())
            _READERS[state]=state._identity_v3()
            require_current_owner_lease_reader_v3(state)
            state.owner_entry=prepare_current_host_owner_lease_read_entry_v3(state)
            binding=state.owner_entry.require_for_v3(state)
            guard=state.owner_entry.require_permission_v3(state)
            return CurrentOwnerViewV1(guard,binding)
        finally:
            try:
                if fence is not None:graph._finish_read_fence_v3(fence)
            finally:
                if state is not None:
                    try:
                        if state.owner_entry is not None:state.owner_entry.release_v3()
                    finally:
                        state.closed=True
                        _READERS.pop(state,None)
