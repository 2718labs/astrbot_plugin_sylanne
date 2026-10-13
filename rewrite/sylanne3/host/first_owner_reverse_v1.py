"""Actual Host half of independent-console first Owner issuance."""
from copy import deepcopy
from dataclasses import asdict
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.first_owner_reverse_v1 import SCHEMA,validate_first_owner_material_v1
from ..authority_service.v2_owner_contract import from_wire,to_wire,OwnerGraphCommitProofV1
from ..runtime_contracts import namespace_ref
from ..graph_worker import GraphWorker
from ..runtime_contracts import NamespaceId
from .v2_installation import V2InstallationAssembly
from .c09_storage_admission_v1 import InstalledHostStorageAdmissionV1


class InstalledFirstOwnerGraphCommitV1:
    def __init__(self,*,namespace,worker,bootstrap,installation):
        if (type(namespace) is not NamespaceId or type(worker) is not GraphWorker
                or type(installation) is not V2InstallationAssembly or bootstrap is None
                or type(installation.storage_admission) is not InstalledHostStorageAdmissionV1
                or installation.installation_policy.namespace!=namespace):
            raise TypeError('actual installed Host Graph worker and storage admission required')
        installation.storage_admission.require_current_process_v1()
        self.namespace,self.worker,self.bootstrap,self.installation=namespace,worker,bootstrap,installation

    async def commit(self,message):
        expected={'schema','profile_id','installation_id','namespace','manifest_digest','process_original',
            'pointer_version','storage_generation','storage_manifest_digest','package_selection','ticket','operation','grant_value'}
        if type(message) is not dict or set(message)!=expected or message['schema']!=SCHEMA:
            raise AuthorityUnavailable('closed first Owner Host request required')
        installation=self.installation;policy=installation.installation_policy;admission=installation.storage_admission
        admission.require_current_process_v1()
        bundle=installation.admin_bundle
        if bundle is None:raise AuthorityUnavailable('actual installed Host profile required')
        from .selected_profile_cohort_v2 import require_current_bundle_selection_v2
        require_current_bundle_selection_v2(bundle,installation.package_root,require_selected_python=True)
        selection=admission.package_selection
        if (message['profile_id']!=bundle.tls_profile.profile_id or message['installation_id']!=policy.installation_id
                or message['namespace']!=namespace_ref(self.namespace) or message['manifest_digest']!=policy.manifest_digest
                or message['process_original']!=admission.process_original or message['pointer_version']!=admission.pointer_version
                or message['storage_generation']!=admission.storage_generation or message['storage_manifest_digest']!=admission.manifest_digest
                or message['package_selection']!=(None if selection is None else asdict(selection))):
            raise AuthorityUnavailable('first Owner callback actual Host incarnation/cohort differs')
        ticket,operation=from_wire(message['ticket']),from_wire(message['operation'])
        if to_wire(ticket)!=message['ticket'] or to_wire(operation)!=message['operation']:
            raise AuthorityUnavailable('canonical first Owner originals required')
        validate_first_owner_material_v1(ticket,operation,message['grant_value'])
        if ticket.namespace!=self.namespace or ticket.installation_id!=policy.installation_id or ticket.authority_id!=policy.expected_authority_id:
            raise AuthorityUnavailable('first Owner callback namespace differs')
        value=deepcopy(message['grant_value'])
        proof=await self.worker.call(lambda graph:graph.commit_first_owner_grant_v2(self.bootstrap,
            namespace=self.namespace,operation_id=operation.operation_id,grant_value=value))
        admission.require_current_process_v1()
        require_current_bundle_selection_v2(bundle,installation.package_root,require_selected_python=True)
        if type(proof) is not OwnerGraphCommitProofV1 or proof.operation_id!=operation.operation_id or proof.grant_digest!=operation.grant_digest:
            raise AuthorityUnavailable('actual first Owner graph proof differs')
        return proof
