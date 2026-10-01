"""Fixed read-only mTLS pre-stop client for the privileged external supervisor.

It reuses the exact installed peer only for the scoped read_supervisor_intent
route. It cannot submit Owner controls, stop processes or issue content work.
"""
from __future__ import annotations
import asyncio
from pathlib import Path
from uuid import UUID
from .contract import AuthorityUnavailable
from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
from .d12_package_maintenance_contract_v2 import package_intent_from_wire_v2
from .linux_installation_security_v1 import require_linux_administrator_v1
from ..runtime_contracts import canonical_digest


class InstalledPackageSupervisorAuthorityClientV2:
    def __init__(self,*,profile_id,package_files,supervisor_policy_digest):
        if type(package_files) is not InstalledPackageSelectionFilesV2:
            raise TypeError('actual protected package selector required')
        from ..host.authority_profile import _check_profile_id
        _check_profile_id(profile_id)
        if package_files.read_maintenance_policy_v2()['supervisor_policy_digest']!=supervisor_policy_digest:
            raise AuthorityUnavailable('fixed supervisor policy differs')
        self.profile_id,self.files,self.policy=profile_id,package_files,supervisor_policy_digest

    async def _paired_rpc_v2(self,operation_id,action):
        require_linux_administrator_v1()
        if action not in {'read_supervisor_intent','read_supervisor_backup_source','read_supervisor_rollback_source',
                'read_authority_bootstrap','read_host_bootstrap','finish_activation'}:
            raise ValueError('fixed package supervisor action required')
        operation=UUID(operation_id)
        if operation.version!=4 or str(operation)!=operation_id:raise ValueError('exact accepted operation UUID4 required')
        from ..host.authority_profile import _load_installation_bundle_from_root
        from ..host.authority_client import AuthorityProvisioningRequest,PublisherPackageIdentity,AUTHORITY_PROTOCOL,AUTHORITY_V2_PROTOCOL
        from ..host.mtls_transport import MtlsAuthorityTransport
        selection,cohort,_=await asyncio.to_thread(self.files.read_selected_configuration_cohort_v2)
        bundle=await asyncio.to_thread(_load_installation_bundle_from_root,self.profile_id,Path('/etc/sylanne/client/profiles'),'Linux')
        policy=bundle.installation_policy
        if (bundle.package_selection!=selection or policy.installation_id!=cohort.installation_id
                or policy.manifest_digest!=cohort.package.manifest_sha256):
            raise AuthorityUnavailable('supervisor client configuration is not the actual selected cohort')
        root=Path(cohort.package.package_root)
        request=AuthorityProvisioningRequest(AUTHORITY_PROTOCOL,self.profile_id,'astrbot_plugin_sylanne','4.28.1',
            root,root,PublisherPackageIdentity(policy.manifest_digest))
        transport=MtlsAuthorityTransport({self.profile_id:bundle.tls_profile})
        try:
            handshake=await transport.handshake(request,protocol=AUTHORITY_V2_PROTOCOL)
            grant=await transport.installation_grant_v2(request,handshake)
            if (not handshake.valid_pairing() or grant.authority_id!=policy.expected_authority_id
                    or grant.installation_id!=policy.installation_id or grant.manifest_digest!=policy.manifest_digest):
                raise AuthorityUnavailable('supervisor actual paired Authority identity differs')
            result=await transport._content_rpc(request,handshake,'d12_package_maintenance_v2',
                {'namespace':policy.authority_namespace,'action':action,'operation_id':operation_id},protocol=AUTHORITY_V2_PROTOCOL)
        finally:
            await transport.close()
        current,_,_=await asyncio.to_thread(self.files.read_selected_configuration_cohort_v2)
        if current!=selection:raise AuthorityUnavailable('selection changed during authenticated supervisor RPC')
        return result,selection,policy

    async def _read_v2(self,operation_id,action):
        result,selection,policy=await self._paired_rpc_v2(operation_id,action)
        intent=package_intent_from_wire_v2(result['intent'])
        if (intent.operation_id!=operation_id or intent.authority_id!=policy.expected_authority_id
                or intent.installation_id!=policy.installation_id or intent.namespace_cohort!=(policy.authority_namespace,)
                or intent.supervisor_policy_digest!=self.policy):
            raise AuthorityUnavailable('actual supervisor intent scope differs')
        if action=='read_supervisor_rollback_source':
            if (selection.revision!=intent.expected_selection_revision+1
                    or selection.package_epoch!=intent.expected_package_epoch+1
                    or selection.prior_selection_digest!=intent.expected_selection_digest
                    or selection.operation_id!=operation_id
                    or selection.cohort_ref!=intent.candidate_cohort_ref
                    or selection.cohort_digest!=intent.candidate_cohort_digest
                    or selection.manifest_sha256!=intent.candidate_manifest_sha256):
                raise AuthorityUnavailable('rollback source must be actual selected candidate of this operation')
        elif intent.expected_selection_digest!=selection.selection_digest:
            raise AuthorityUnavailable('forward supervisor read is no longer on its accepted source selection')
        current,_,_=await asyncio.to_thread(self.files.read_selected_configuration_cohort_v2)
        if current!=selection:raise AuthorityUnavailable('selection changed during supervisor read')
        return result,intent,selection

    async def read_backup_source_v2(self,operation_id):
        return await self._read_backup_source_v2(operation_id,'read_supervisor_backup_source','forward')

    async def read_rollback_source_v2(self,operation_id):
        return await self._read_backup_source_v2(operation_id,'read_supervisor_rollback_source','rollback')

    async def _read_backup_source_v2(self,operation_id,action,phase):
        from .d12_managed_backup_v2 import decode_backup_source_v2
        result,intent,selection=await self._read_v2(operation_id,action)
        if set(result)!={'intent','backup_source','channel_binding_sha256'}:
            raise AuthorityUnavailable('supervisor backup source response fields differ')
        source=decode_backup_source_v2(result['backup_source'])
        if (source['backup_phase']!=phase or source['operation_id']!=operation_id or source['accepted_original_digest']!=intent.digest
                or source['installation_id']!=intent.installation_id or source['namespace']!=intent.namespace_cohort[0]
                or source['selection_digest']!=selection.selection_digest or source['lifecycle_epoch']!=intent.lifecycle_epoch
                or canonical_digest(source['storage_identity'])!=intent.current_storage_identity_digest):
            raise AuthorityUnavailable('supervisor backup source scope differs')
        return intent,source

    async def read_accepted_intent_v2(self,operation_id):
        result,intent,selection=await self._read_v2(operation_id,'read_supervisor_intent')
        if set(result)!={'intent','admission_observation','channel_binding_sha256'}:
            raise AuthorityUnavailable('supervisor authenticated response fields differ')
        intent=package_intent_from_wire_v2(result['intent'])
        observation=result['admission_observation']
        fields={'schema','operation_id','accepted_original_digest','lifecycle_epoch','lifecycle_state',
            'current_storage_identity_digest','current_anchor_digest','live_fence_count','pending_mutation_count',
            'active_rpc_count','selection_digest','supervisor_policy_digest','observation_digest'}
        if type(observation) is not dict or set(observation)!=fields:
            raise AuthorityUnavailable('actual supervisor admission observation fields differ')
        material=dict(observation);commitment=material.pop('observation_digest')
        if (canonical_digest(material)!=commitment or observation['schema']!='d12.package-supervisor-admission.v2'
                or intent.operation_id!=operation_id or observation['supervisor_policy_digest']!=self.policy
                or intent.expected_selection_digest!=selection.selection_digest
                or observation['selection_digest']!=selection.selection_digest
                or observation['operation_id']!=operation_id or observation['accepted_original_digest']!=intent.digest
                or observation['lifecycle_epoch']!=intent.lifecycle_epoch
                or observation['current_storage_identity_digest']!=intent.current_storage_identity_digest
                or observation['lifecycle_state'] not in {'quiescing','drained','resuming'}
                or any(type(observation[name]) is not int or observation[name]<0
                    for name in ('live_fence_count','pending_mutation_count','active_rpc_count'))):
            raise AuthorityUnavailable('actual supervisor acceptance/admission scope differs')
        current,_,_=await asyncio.to_thread(self.files.read_selected_configuration_cohort_v2)
        if current!=selection:raise AuthorityUnavailable('selection changed during supervisor admission read')
        return intent,observation

    async def _read_bootstrap_or_activation_v2(self,operation_id,action):
        from .d12_package_bootstrap_v2 import decode_package_bootstrap_original_v2,decode_package_activation_original_v2
        from .d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2
        result,selection,policy=await self._paired_rpc_v2(operation_id,action)
        journal=InstalledPackageSupervisorJournalV2(control_directory=self.files.control_directory,supervisor_policy_digest=self.policy)
        intent=journal.read_verified_intent_v2(operation_id)
        if intent is None:raise AuthorityUnavailable('independent accepted operation original absent')
        forward=(selection.revision==intent.expected_selection_revision+1 and selection.package_epoch==intent.expected_package_epoch+1
            and selection.prior_selection_digest==intent.expected_selection_digest and selection.cohort_digest==intent.candidate_cohort_digest
            and selection.manifest_sha256==intent.candidate_manifest_sha256)
        rollback=(selection.revision==intent.expected_selection_revision+2 and selection.package_epoch==intent.expected_package_epoch+2
            and selection.cohort_digest==intent.old_cohort_digest and selection.manifest_sha256==intent.old_manifest_sha256)
        receipts=journal.read_verified_receipts_v2(operation_id)
        pending=journal.read_verified_pending_stage_v2(operation_id)
        abort=(selection.selection_digest==intent.expected_selection_digest
            and (any(r.stage=='abort_intent' for r in receipts) or pending is not None and pending['stage']=='abort_intent'))
        if not abort and (selection.operation_id!=operation_id or not (forward or rollback)):
            raise AuthorityUnavailable('actual bootstrap selection differs from original package operation')
        phase='abort_before_switch' if abort else 'rollback' if rollback else 'forward'
        key='activation_original' if action=='finish_activation' else 'bootstrap_original'
        fields={key,'channel_binding_sha256'}
        if action=='read_host_bootstrap':fields.update({'lifecycle_state','lifecycle_epoch'})
        if set(result)!=fields:raise AuthorityUnavailable('package supervisor bootstrap response fields differ')
        if action=='read_host_bootstrap' and (result['lifecycle_epoch']!=intent.lifecycle_epoch or result['lifecycle_state'] not in {'resuming','active'}):
            raise AuthorityUnavailable('Host bootstrap lifecycle scope differs')
        value=result[key]
        if value is None:
            if action!='read_host_bootstrap':raise AuthorityUnavailable('actual process bootstrap original absent')
            return None
        value=(decode_package_activation_original_v2(value) if action=='finish_activation' else decode_package_bootstrap_original_v2(value))
        if (value['maintenance_phase']!=phase or value['operation_id']!=operation_id or value['accepted_original_digest']!=intent.digest
                or value['namespace']!=policy.authority_namespace or value['installation_id']!=policy.installation_id
                or value['selection_digest']!=selection.selection_digest or value['package_epoch']!=selection.package_epoch
                or value['cohort_digest']!=selection.cohort_digest or value['manifest_sha256']!=selection.manifest_sha256
                or value['lifecycle_epoch']!=intent.lifecycle_epoch
                or action!='finish_activation' and value['service_role']!=('authority' if action=='read_authority_bootstrap' else 'host')):
            raise AuthorityUnavailable('actual package readiness original differs from selected operation')
        return value

    async def read_authority_bootstrap_v2(self,operation_id):
        return await self._read_bootstrap_or_activation_v2(operation_id,'read_authority_bootstrap')

    async def read_host_bootstrap_v2(self,operation_id):
        return await self._read_bootstrap_or_activation_v2(operation_id,'read_host_bootstrap')

    async def finish_activation_v2(self,operation_id):
        return await self._read_bootstrap_or_activation_v2(operation_id,'finish_activation')
