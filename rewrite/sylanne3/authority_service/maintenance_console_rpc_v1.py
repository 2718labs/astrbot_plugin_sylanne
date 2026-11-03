"""Finite mTLS dispatcher for a separately installed Owner maintenance console."""
from dataclasses import dataclass

from .contract import AuthorityUnavailable,identifier
from .maintenance_console_contract_v1 import (
    MaintenanceConsoleBindingV1,MAINTENANCE_CONSOLE_PROTOCOL_V1,MAINTENANCE_CONSOLE_METHOD_V1)
from .v2_owner_contract import OwnerActorBindingV1
from .v2_owner_session import (
    AuthorityV2OwnerSessionStore,OwnerSessionLoginRequestV1,OwnerSessionLoginChallengeV1,
    from_wire as session_from_wire,to_wire as session_to_wire)

PROTOCOL=MAINTENANCE_CONSOLE_PROTOCOL_V1
METHOD=MAINTENANCE_CONSOLE_METHOD_V1
_ACTION_FIELDS={
    "describe":frozenset(),
    "begin_owner_session_v1":frozenset({"request"}),
    "accept_owner_session_v1":frozenset({"challenge","signature"}),
    "describe_owner_session_v1":frozenset({"token"}),
    "current_owner_session_v1":frozenset({"request","token"}),
    "logout_owner_session_v1":frozenset({"request","token"}),
    "inspection_workflow_accept":frozenset({"operation_id","input_data"}),
    "inspection_workflow_status":frozenset({"operation_id"}),
    "resume_completed_inspection_v1":frozenset({"operation_id","input_data"}),
    "inspection_recovery_status":frozenset({"operation_id"}),
    "reconcile_held_inspection_v1":frozenset({"operation_id","input_data"}),
    "inspection_reconciliation_status":frozenset({"operation_id"}),
    "read_inspection_recovery_options_v1":frozenset({"parent_workflow_operation_id"}),
}
_SESSION_ACTIONS=frozenset({"describe","begin_owner_session_v1","accept_owner_session_v1",
    "describe_owner_session_v1","current_owner_session_v1","logout_owner_session_v1"})
_OWNER_FIELDS=frozenset({"owner_actor_id","owner_session_token","owner_session_request"})


@dataclass(frozen=True)
class _InstalledConsoleBindingV1:
    binding: MaintenanceConsoleBindingV1
    role_proof: object
    migration: object


def _source_v1(server,binding):
    from .source_inspection_migration_v1 import InstalledSourceInspectionMigrationV1
    source=getattr(server,"_d12_source_inspection_migration_services_v1",{}).get(
        (binding.authority_namespace,binding.installation_id))
    if (type(source) is not InstalledSourceInspectionMigrationV1 or source.lifecycle.core is not server._core
            or source.lifecycle.control.authority_id!=binding.authority_id
            or source.lifecycle.installation_id!=binding.installation_id
            or source.lifecycle.namespace!=binding.authority_namespace or source.lifecycle.namespace_id!=binding.namespace
            or source.lifecycle.expected_manifest_digest!=binding.package_manifest_digest
            or source.lifecycle.peer==(binding.console_cert_sha256,binding.console_profile_id)
            or server._v2_fences.get(binding.authority_namespace) is not source.lifecycle.fences):
        raise AuthorityUnavailable("console has no exact registered Source maintenance Authority")
    return source


def install_maintenance_console_binding_v1(server,*,binding,administrator_credential,role_proof):
    from .mtls_server import AuthorityRpcServer
    from .maintenance_console_role_v1 import VerifiedMaintenanceConsoleRoleV1
    if (type(server) is not AuthorityRpcServer or type(binding) is not MaintenanceConsoleBindingV1
            or type(role_proof) is not VerifiedMaintenanceConsoleRoleV1):
        raise AuthorityUnavailable("actual installed console server/binding/private Root role required")
    server._core._require(administrator_credential,"d12_lifecycle_install",binding.authority_namespace)
    role_proof.require_installed_v1(binding=binding,server=server)
    source=_source_v1(server,binding)
    if any(certificate==binding.console_cert_sha256 for certificate,_ in server._installations_v2):
        raise AuthorityUnavailable("console certificate cannot also be an installed Host peer")
    sessions=server._v2_owner_sessions
    if type(sessions) is not AuthorityV2OwnerSessionStore or sessions._core is not server._core:
        raise AuthorityUnavailable("console requires the actual same Core Owner session store")
    from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource
    pairing=sessions._current_pairing_source
    if type(pairing) is not AuthorityOwnerPairingSource or pairing._core is not server._core:
        raise AuthorityUnavailable("console requires the actual Authority-owned actor resolver")
    installed=_InstalledConsoleBindingV1(binding,role_proof,source)
    registry=getattr(server,"_maintenance_console_bindings_v1",None)
    if registry is None:
        registry={};server._maintenance_console_bindings_v1=registry
    key=(binding.console_cert_sha256,binding.console_profile_id)
    prior=registry.get(key)
    if prior is not None:
        if prior.binding!=binding or prior.role_proof is not role_proof or prior.migration is not source:
            raise AuthorityUnavailable("installed console binding cannot be substituted")
        return
    if any(item.binding.console_cert_sha256==binding.console_cert_sha256 for item in registry.values()):
        raise AuthorityUnavailable("console certificate already has its fixed installed profile")
    registry[key]=installed


def is_maintenance_console_peer_v1(server,certificate_sha256):
    return any(certificate==certificate_sha256 for certificate,_ in getattr(server,"_maintenance_console_bindings_v1",{}))


def _installed_v1(server,credential,profile_id,request):
    from .mtls_server import MtlsPeerCredential
    if type(credential) is not MtlsPeerCredential:
        raise AuthorityUnavailable("actual TLS console peer credential required")
    key=(credential.certificate_sha256,profile_id)
    installed=getattr(server,"_maintenance_console_bindings_v1",{}).get(key)
    if type(installed) is not _InstalledConsoleBindingV1:
        raise AuthorityUnavailable("console peer has no installed Root role binding")
    binding=installed.binding
    if type(request) is not dict or request!=binding.request_v1() or set(request)!=set(binding.request_v1()):
        raise AuthorityUnavailable("console request differs from its fixed installed locator")
    installed.role_proof.require_current_v1(binding=binding,server=server)
    if _source_v1(server,binding) is not installed.migration:
        raise AuthorityUnavailable("console maintenance service instance changed")
    return installed


def _login_request_v1(raw,binding,*,challenge=False):
    value=session_from_wire(raw)
    expected=OwnerSessionLoginChallengeV1 if challenge else OwnerSessionLoginRequestV1
    if type(value) is not expected or session_to_wire(value)!=raw:
        raise AuthorityUnavailable("console Owner login value is not its canonical registered DTO")
    request=value.request if challenge else value
    if (request.authority_id!=binding.authority_id or request.authority_namespace!=binding.authority_namespace
            or request.installation_id!=binding.installation_id or request.dashboard_origin!=binding.origin
            or request.audience!="owner"):
        raise AuthorityUnavailable("console Owner request crosses its exact installation/Origin")
    return value


def _actual_actor_in_tx_v1(server,db,binding,request):
    from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource
    pairing=server._v2_owner_sessions._current_pairing_source
    if type(pairing) is not AuthorityOwnerPairingSource or pairing._core is not server._core:
        raise AuthorityUnavailable("console actual Owner actor resolver is unavailable")
    actor=pairing.current_principal_binding(authority_namespace=binding.authority_namespace,
        installation_id=binding.installation_id,principal=request.principal)
    if (type(actor) is not OwnerActorBindingV1 or actor.authority_id!=binding.authority_id
            or actor.installation_id!=binding.installation_id or actor.namespace!=binding.namespace
            or actor.principal!=request.principal):
        raise AuthorityUnavailable("console Owner has no actual current paired actor")
    pairing.require_current_actor_in_tx(db,authority_namespace=binding.authority_namespace,
        installation_id=binding.installation_id,actor_id=actor.actor_id,principal=request.principal)
    return actor.actor_id


def _current_v1(server,credential,binding,*,token,request=None):
    sessions=server._v2_owner_sessions
    server._core._require(credential,"owner_session",binding.authority_namespace)
    with server._core._tx() as db:
        if request is None:
            request=sessions.describe_current_in_tx(db,token=token,namespace=binding.authority_namespace,
                installation_id=binding.installation_id)
            _login_request_v1(session_to_wire(request),binding)
        else:
            sessions.require_current_in_tx(db,token=token,request=request)
        actor=_actual_actor_in_tx_v1(server,db,binding,request)
        return request,actor


def dispatch_maintenance_console_v1(server,method,credential,profile_id,request,command):
    if method!=METHOD:raise AuthorityUnavailable("console peer may call only its finite management method")
    installed=_installed_v1(server,credential,profile_id,request)
    binding=installed.binding
    if type(command) is not dict or type(command.get("action")) is not str:
        raise AuthorityUnavailable("console requires one exact finite command")
    action=command["action"];fields=_ACTION_FIELDS.get(action)
    if fields is None:raise AuthorityUnavailable("console action is not registered")
    expected={"action"}|fields|(_OWNER_FIELDS if action not in _SESSION_ACTIONS else frozenset())
    if set(command)!=expected:raise AuthorityUnavailable("console action fields differ from its closed command")
    sessions=server._v2_owner_sessions
    if action=="describe":
        server._core._require(credential,"owner_guard_read",binding.authority_namespace)
        return {"binding":binding.request_v1()}
    if action=="begin_owner_session_v1":
        login=_login_request_v1(command["request"],binding)
        challenge=sessions.begin_login(transport_credential=credential,request=login)
        return {"challenge":session_to_wire(challenge)}
    if action=="accept_owner_session_v1":
        challenge=_login_request_v1(command["challenge"],binding,challenge=True)
        signature=server._owner_proof_signature(command["signature"])
        token=sessions.accept_login(transport_credential=credential,challenge=challenge,signature=signature)
        return {"token":token}
    if action=="describe_owner_session_v1":
        described,actor=_current_v1(server,credential,binding,token=command["token"])
        return {"request":session_to_wire(described),"actualactor_id":actor}
    if action in {"current_owner_session_v1","logout_owner_session_v1"}:
        login=_login_request_v1(command["request"],binding)
        _,actor=_current_v1(server,credential,binding,token=command["token"],request=login)
        if action=="current_owner_session_v1":return {"current":True,"actualactor_id":actor}
        sessions.logout(transport_credential=credential,token=command["token"],request=login)
        return {"revoked":True}
    login=_login_request_v1(command["owner_session_request"],binding)
    _,actor=_current_v1(server,credential,binding,token=command["owner_session_token"],request=login)
    if identifier(command["owner_actor_id"],"owner_actor_id")!=actor:
        raise AuthorityUnavailable("console caller actor differs from the actual paired Owner")
    source=installed.migration
    kwargs=dict(credential=credential,actor=actor,session_token=command["owner_session_token"],session_request=login)
    if action=="inspection_workflow_accept":
        return {"inspection_workflow":source.workflow.accept_current_v1(operation_id=command["operation_id"],input_data=command["input_data"],**kwargs)}
    if action=="inspection_workflow_status":
        value=source.workflow.read_current_v1(operation_id=command["operation_id"],**kwargs)
        if value["schema"]!="d12.source-inspection-workflow-view.v1":
            raise AuthorityUnavailable("requested operation is not a normal inspection workflow")
        return {"inspection_workflow":value}
    if action=="resume_completed_inspection_v1":
        return {"inspection_recovery":source.workflow.recovery.accept_completed_v1(operation_id=command["operation_id"],input_data=command["input_data"],**kwargs)}
    if action=="inspection_recovery_status":
        value=source.workflow.read_current_v1(operation_id=command["operation_id"],**kwargs)
        if value["schema"]!="d12.source-inspection-recovery-view.v1":
            raise AuthorityUnavailable("requested operation is not a fresh completed inspection resume")
        return {"inspection_recovery":value}
    if action=="reconcile_held_inspection_v1":
        return {"inspection_reconciliation":source.workflow.held_reconciliation.accept_v1(operation_id=command["operation_id"],input_data=command["input_data"],**kwargs)}
    if action=="inspection_reconciliation_status":
        value=source.workflow.read_current_v1(operation_id=command["operation_id"],**kwargs)
        if value["schema"]!="d12.source-inspection-held-reconciliation-view.v1":
            raise AuthorityUnavailable("requested operation is not a held inspection reconciliation")
        return {"inspection_reconciliation":value}
    return {"inspection_recovery_options":source.workflow.recovery.read_options_current_v1(
        parent_workflow_operation_id=command["parent_workflow_operation_id"],**kwargs)}


__all__=("MaintenanceConsoleBindingV1","PROTOCOL","METHOD","install_maintenance_console_binding_v1",
    "is_maintenance_console_peer_v1","dispatch_maintenance_console_v1")

