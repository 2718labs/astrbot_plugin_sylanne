"""Fixed paired C11 acceptance/status routes; no OS mutation RPC exists here."""
from .contract import AuthorityUnavailable,identifier
from .d12_package_maintenance_authority_v2 import InstalledD12PackageMaintenanceAuthorityV2
from .d12_package_maintenance_contract_v2 import package_intent_to_wire_v2
from .v2_owner_session import OwnerSessionLoginRequestV1,from_wire as session_from_wire

METHOD='d12_package_maintenance_v2'


def install_d12_package_maintenance_authority_v2(server,service):
    if type(service) is not InstalledD12PackageMaintenanceAuthorityV2 or service.core is not server._core:raise TypeError('actual package Authority service required')
    if not hasattr(server,'_d12_package_services_v2'):server._d12_package_services_v2={}
    if service.namespace in server._d12_package_services_v2:raise AuthorityUnavailable('package Authority already installed')
    server._d12_package_services_v2[service.namespace]=service


def dispatch_d12_package_maintenance_v2(server,method,credential,profile_id,manifest_digest,command):
    if method!=METHOD:return None
    if type(command) is not dict:raise AuthorityUnavailable('package maintenance command differs')
    action=command.get('action');expected={'namespace','action'} if action=='profile' else {'namespace','action','operation_id'}
    if action in {'accept','status','profile'}:expected.update({'owner_actor_id','owner_session_token','owner_session_request'})
    if action=='register_host_ready':expected.update({'process_id','invocation_id','selection_revision','cohort_digest','catalogue_hash','ready_domains'})
    if action=='accept':expected.update({'candidate_cohort_ref','expected_selection_digest','expected_lifecycle_epoch'})
    if action not in {'accept','status','profile','read_supervisor_intent','read_supervisor_backup_source','read_supervisor_rollback_source','read_authority_bootstrap','read_host_bootstrap','register_host_ready','finish_activation'} or set(command)!=expected:raise AuthorityUnavailable('closed package maintenance action fields required')
    namespace=identifier(command['namespace'],'namespace')
    server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    installed=server._installations_v2[(credential.certificate_sha256,profile_id)]
    service=getattr(server,'_d12_package_services_v2',{}).get(namespace)
    if type(service) is not InstalledD12PackageMaintenanceAuthorityV2 or installed.installation_id!=service.installation_id:raise AuthorityUnavailable('package actual paired installation differs')
    if action=='read_host_bootstrap':return service.read_current_package_host_bootstrap_v2(credential=credential,operation_id=command['operation_id'])
    if action=='read_authority_bootstrap':return {'bootstrap_original':service.read_current_authority_package_bootstrap_v2(credential=credential,operation_id=command['operation_id'])}
    if action=='finish_activation':return {'activation_original':service.finish_current_package_activation_v2(credential=credential,operation_id=command['operation_id'])}
    if action=='register_host_ready':
        if type(command['ready_domains']) is not list:raise AuthorityUnavailable('exact Host domain readiness list required')
        return service.register_current_package_host_ready_v2(credential=credential,peer_certificate_sha256=credential.certificate_sha256,
            peer_profile_id=profile_id,operation_id=command['operation_id'],process_id=command['process_id'],invocation_id=command['invocation_id'],
            selection_revision=command['selection_revision'],cohort_digest=command['cohort_digest'],catalogue_hash=command['catalogue_hash'],ready_domains=tuple(command['ready_domains']))
    if action=='read_supervisor_rollback_source':return service.read_supervisor_rollback_source_v2(credential=credential,operation_id=command['operation_id'])
    if action=='read_supervisor_backup_source':return service.read_supervisor_backup_source_v2(credential=credential,operation_id=command['operation_id'])
    if action=='read_supervisor_intent':return service.read_supervisor_intent_v2(credential=credential,operation_id=command['operation_id'])
    request=session_from_wire(command['owner_session_request'])
    if type(request) is not OwnerSessionLoginRequestV1 or request.authority_namespace!=namespace or request.installation_id!=installed.installation_id:raise AuthorityUnavailable('package Owner session scope differs')
    if action=='profile':return {'profile':service.read_current_package_maintenance_v2(credential=credential,actor=command['owner_actor_id'],session_token=command['owner_session_token'],session_request=request)}
    owner=dict(credential=credential,actor=command['owner_actor_id'],session_token=command['owner_session_token'],session_request=request,operation_id=command['operation_id'])
    if action=='accept':
        result=service.accept_current_package_switch_v2(**owner,candidate_cohort_ref=command['candidate_cohort_ref'],expected_selection_digest=command['expected_selection_digest'],expected_lifecycle_epoch=command['expected_lifecycle_epoch'])
        return service.read_current_package_operation_v2(**owner)
    return service.read_current_package_operation_v2(**owner)
