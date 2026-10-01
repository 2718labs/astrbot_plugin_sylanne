"""Fixed root one-shot compatible-package executor.

Only an existing signed Owner-accepted operation UUID is an input. Every side
effect has a prior immutable intent, exact process/path identity and recovery
from real originals. No old Core or journal is restored during rollback.
"""
from dataclasses import asdict
import asyncio
from contextlib import contextmanager
import json
import time
from uuid import UUID
from .contract import AuthorityUnavailable
from .d12_package_supervisor_writer_v2 import _InstalledPackageSupervisorWriterV2
from .d12_package_supervisor_client_v2 import InstalledPackageSupervisorAuthorityClientV2
from .d12_installed_supervisor_v1 import InstalledD12SystemdSupervisorV1
from .c09_process_identity_v1 import read_process_identity_v1,require_process_retired_v1
from .d12_package_files_v2 import next_package_selection_v2,decode_package_selection_v2
from ..runtime_contracts import canonical_serialize


def _wire(value):return json.loads(canonical_serialize(value))


class InstalledD12PackageSupervisorV2:
    def __init__(self):
        self.writer=_InstalledPackageSupervisorWriterV2()
        self.files,self.journal=self.writer.files,self.writer.reader
        self.policy=self.writer.policy
        self._fresh_start_permissions=set()
        self.host=InstalledD12SystemdSupervisorV1(config=self.writer.host_config)
        self.authority=InstalledD12SystemdSupervisorV1(config=self.writer.authority_config)
        self.client=InstalledPackageSupervisorAuthorityClientV2(profile_id=self.policy['profile_id'],
            package_files=self.files,supervisor_policy_digest=self.journal.policy)

    def close(self):self.writer.close()

    def _observe(self,op,kind,body):return self.writer.observe(op,kind,_wire(body))

    def _process(self,op,role):
        service=self.host if role=='host' else self.authority
        actual=service.read_current_host_state_v1()
        identity=read_process_identity_v1(actual.main_pid) if actual.main_pid else None
        if actual.main_pid and identity is None:raise AuthorityUnavailable('observed service exited during process read')
        return self._observe(op,'process',dict(service_role=role,systemd=asdict(actual),process_original=identity))

    def _stage_observations(self,op,stage):
        rows=[r for r in self.journal.read_verified_receipts_v2(op) if r.stage==stage]
        if len(rows)!=1:raise AuthorityUnavailable('one exact original supervisor stage required: '+stage)
        intent=self.journal.read_verified_intent_v2(op)
        return tuple(self.journal.read_verified_observation_v2(op,ref) for ref,_ in rows[0].observation_refs if ref!=intent.accepted_original_ref)

    def _one(self,values,kind,role=None):
        found=[v for v in values if v.kind==kind and (role is None or v.body.get('service_role')==role)]
        if len(found)!=1:raise AuthorityUnavailable('unique actual stage observation required: '+kind)
        return found[0]

    @contextmanager
    def _retired_storage(self):
        from .c09_storage_control_v1 import InstalledC09InstanceLeaseV1,C09StorageControlV1
        from .linux_installation_security_v1 import read_installed_json_v1
        from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2
        selected,cohort,values=self.files.read_selected_configuration_cohort_v2()
        if any(not service.read_current_host_state_v1().stopped_and_drained for service in (self.host,self.authority)):
            raise AuthorityUnavailable('both actual units must be stopped before exclusive storage maintenance')
        with InstalledC09InstanceLeaseV1(self.policy['instance_lock']) as lease:
            control=C09StorageControlV1(**values['assets']['c09_storage_v1'],lease=lease)
            raw=read_installed_json_v1(values['deployment']['inventory_path'])
            from ..runtime.c09_installation_inventory_v2 import InstalledResourceV2
            raw=dict(raw);raw['resources']=tuple(InstalledResourceV2(**{**item,
                'content_coverage':tuple(item['content_coverage'])}) for item in raw['resources'])
            inventory=InstallationFilesystemManifestV2(**raw)
            yield control,inventory
            lease.require_held()

    def _backup_component(self,control,inventory):
        from .d12_managed_backup_v2 import InstalledD12ManagedBackupV2
        return InstalledD12ManagedBackupV2(package_files=self.files,supervisor_journal=self.journal,
            host_supervisor=self.host,authority_supervisor=self.authority,storage_reader=control,
            inventory_manifest=inventory,maximum_file_bytes=8*1024**3)

    def _require_unchanged_snapshot(self,op,control,inventory,phase='forward'):
        from .d12_managed_backup_v2 import reread_sqlite_backup_v2
        backup=self._backup_component(control,inventory).read_managed_backup_v2(op,backup_phase=phase)
        context=control.read_verified_current_storage_v1();context.require_current('maintenance')
        for member in context.manifest['members']:
            copy=backup['copies'][member['role']]
            if copy['source_observation']['resolved_path']!=member['resolved_path']:
                raise AuthorityUnavailable('current selected store differs from qualified snapshot')
            reread_sqlite_backup_v2(member['resolved_path'],copy['backup_observation']['resolved_path'],
                copy['logical_inventory'],maximum_file_bytes=8*1024**3,instance_lease=control.lease)
        return backup

    async def _wait_call(self,call,timeout=90):
        deadline=time.monotonic()+timeout
        last=None
        while time.monotonic()<deadline:
            try:
                value=await call()
                if value is not None:return value
            except (AuthorityUnavailable,RuntimeError,ConnectionError,TimeoutError) as exc:last=exc
            await asyncio.sleep(0.5)
        raise AuthorityUnavailable('same original process readiness remains unresolved') from last

    async def _os_call(self,method,**arguments):
        from .first_owner_reverse_v1 import _await_actual_completion_v1
        return await _await_actual_completion_v1(asyncio.create_task(asyncio.to_thread(method,**arguments)))

    def _begin(self,op,stage):
        prior=self.journal.read_verified_pending_stage_v2(op)
        original=self.writer.prepare(op,stage)
        if prior is None and stage in {'authority_start_intent','host_start_intent',
                'rollback_authority_start_intent','rollback_host_start_intent','abort_authority_start_intent','abort_host_start_intent'}:
            self._fresh_start_permissions.add((op,stage))
        return original
    def _finish(self,op,stage,values=()):return self.writer.finish(op,stage,values)

    async def run(self,operation_id):
        operation=UUID(operation_id)
        if operation.version!=4 or str(operation)!=operation_id:raise ValueError('exact accepted operation UUID4 required')
        op=operation_id
        intent=self.journal.read_verified_intent_v2(op)
        if intent is None:
            intent,_=await self.client.read_accepted_intent_v2(op)
            self.writer.kernel._register_observed_acceptance(intent)
        if intent.installation_id!=self.policy['installation_id'] or intent.namespace_cohort!=tuple(self.policy['namespace_cohort']):
            raise AuthorityUnavailable('accepted operation differs from fixed supervisor installation')
        while True:
            receipts=self.journal.read_verified_receipts_v2(op)
            pending=self.journal.read_verified_pending_stage_v2(op)
            last=receipts[-1].stage if receipts else None
            if last in {'active','rollback_complete','abort_complete'} and pending is None:
                return {'operation_id':op,'stage':last,'receipt_digest':receipts[-1].receipt_digest}
            if last=='unknown':raise AuthorityUnavailable('unknown original side effect requires exact recovery, not a new action')
            from .d12_package_supervisor_journal_v2 import _FORWARD,_ROLLBACK,_ABORT
            if pending is not None:stage=pending['stage']
            elif last=='failed':stage=self._recovery_stage(op,intent,receipts)
            elif last is None:stage='accepted'
            else:
                order=next((order for order in (_FORWARD,_ROLLBACK,_ABORT) if last in order),None)
                if order is None:raise AuthorityUnavailable('unknown original maintenance sequence')
                stage=order[order.index(last)+1]
            try:
                await self._advance(op,intent,stage)
            except (AuthorityUnavailable,RuntimeError):
                if stage not in _FORWARD or stage in {'active','switch_intent','package_switched'}:
                    raise
                self._resolve_failed_forward(op,intent,stage)

    def _recovery_stage(self,op,intent,receipts):
        if any(r.stage.startswith(('abort_','rollback_')) for r in receipts):
            raise AuthorityUnavailable('original recovery itself failed; another start is not authorized')
        selected,_,_=self.files.read_selected_configuration_cohort_v2()
        if (selected.selection_digest==intent.expected_selection_digest
                and not any(r.stage in {'switch_intent','package_switched'} for r in receipts)):
            return 'abort_intent'
        if (selected.operation_id==op and selected.revision==intent.expected_selection_revision+1
                and selected.package_epoch==intent.expected_package_epoch+1 and selected.cohort_digest==intent.candidate_cohort_digest
                and any(r.stage=='package_switched' for r in receipts) and not any(r.stage=='active' for r in receipts)):
            return 'rollback_retire_intent'
        raise AuthorityUnavailable('actual pointer/activation does not permit original recovery')

    def _resolve_failed_forward(self,op,intent,stage):
        pending=self.journal.read_verified_pending_stage_v2(op)
        if pending is None or pending['stage']!=stage:raise AuthorityUnavailable('failure has no exact pending stage')
        receipts=self.journal.read_verified_receipts_v2(op)
        recovery=self._recovery_stage(op,intent,receipts)
        selected,_,_=self.files.read_selected_configuration_cohort_v2()
        pointer=self._observe(op,'package_selection',asdict(selected))
        processes=(self._process(op,'host'),self._process(op,'authority'))
        body=dict(requested_stage=stage,pending_intent_digest=pending['intent_digest'],failure_code='qualification_unavailable',
            side_effect_state='no_package_switch' if recovery=='abort_intent' else 'candidate_selected_not_activated',
            selection_observation_ref=pointer.observation_ref,selection_observation_digest=pointer.observation_digest,
            process_observation_refs=sorted((o.observation_ref,o.observation_digest) for o in processes))
        resolution=self._observe(op,'stage_failure_resolution',body)
        self._finish(op,'failed',(*processes,pointer,resolution))

    async def _advance(self,op,intent,stage):
        if stage in {'authority_start_intent','rollback_authority_start_intent'}:
            from .d12_public_history_eligibility_v1 import publish_actual_historical_eligibility_v1
            publish_actual_historical_eligibility_v1(package_files=self.files,supervisor_journal=self.journal,
                supervisor_writer=self.writer.kernel,authority_namespace=intent.namespace_cohort[0])
        self._begin(op,stage)
        if stage=='accepted':
            self._finish(op,stage);return
        if stage=='packages_verified':
            from .d12_configuration_cohort_v2 import read_verified_configuration_cohort_v2
            selected,source,_=self.files.read_selected_configuration_cohort_v2()
            _,candidate=self.files.read_registered_cohort_v2(intent.candidate_cohort_ref)
            read_verified_configuration_cohort_v2(candidate)
            if selected.selection_digest!=intent.expected_selection_digest or candidate.cohort_digest!=intent.candidate_cohort_digest:
                raise AuthorityUnavailable('accepted source/candidate package registration changed')
            observed=self._observe(op,'registered_packages',dict(selection=asdict(selected),source=asdict(source),candidate=asdict(candidate)))
            self._finish(op,stage,(observed,));return
        if stage=='quiescing':
            _,admission=await self.client.read_accepted_intent_v2(op)
            async def source_read():return (await self.client.read_backup_source_v2(op))[1]
            _,_,values=self.files.read_selected_configuration_cohort_v2()
            source=await self._wait_call(source_read,values['deployment']['host_lifecycle']['drain_timeout_seconds'])
            self._finish(op,stage,(self._observe(op,'authority_admission',admission),self._observe(op,'backup_source',source)));return
        if stage=='retire_intent':
            source=self._one(self._stage_observations(op,'quiescing'),'backup_source')
            self._finish(op,stage,(self._process(op,'host'),self._process(op,'authority'),source));return
        if stage=='retired':
            before=self._stage_observations(op,'retire_intent')
            for role,service in (('host',self.host),('authority',self.authority)):
                original=self._one(before,'process',role)
                await self._os_call(service.stop_original_host_v1,expected_invocation_id=original.body['systemd']['invocation_id'])
                if original.body['process_original'] is not None:require_process_retired_v1(original.body['process_original'])
            self._finish(op,stage,(self._process(op,'host'),self._process(op,'authority'),self._one(before,'backup_source')));return
        if stage=='backup_ready':
            with self._retired_storage() as (control,inventory):
                body=self._backup_component(control,inventory).create_managed_backup_v2(op)
                original=self._observe(op,'managed_backup',body)
            self._finish(op,stage,(original,));return
        if stage=='compatible_no_data_migration':
            from .d12_candidate_compatibility_v2 import InstalledD12CandidateCompatibilityV2
            with self._retired_storage() as (control,inventory):
                backup=self._backup_component(control,inventory)
                reader=InstalledD12CandidateCompatibilityV2(package_files=self.files,supervisor_journal=self.journal,
                    storage_reader=control,managed_backup=backup)
                body=reader.verify_current_candidate_v2(op)
                original=self._observe(op,'package_compatibility',body)
            self._finish(op,stage,(original,));return
        if stage=='switch_intent':
            selected,_,_=self.files.read_selected_configuration_cohort_v2()
            if selected.selection_digest!=intent.expected_selection_digest:raise AuthorityUnavailable('switch predecessor changed')
            self._finish(op,stage,(self._observe(op,'package_selection',asdict(selected)),
                self._one(self._stage_observations(op,'compatible_no_data_migration'),'package_compatibility')));return
        if stage=='package_switched':
            before=self._one(self._stage_observations(op,'switch_intent'),'package_selection')
            expected=decode_package_selection_v2(before.body)
            _,candidate=self.files.read_registered_cohort_v2(intent.candidate_cohort_ref)
            desired=next_package_selection_v2(expected,operation_id=op,package=candidate.package,
                cohort_ref=candidate.cohort_ref,cohort_digest=candidate.cohort_digest)
            with self._retired_storage() as (control,inventory):
                self._require_unchanged_snapshot(op,control,inventory)
                actual=self.files._switch_after_supervisor_authorization_v2(expected=expected,desired=desired)
                if actual!=desired:raise AuthorityUnavailable('actual selection CAS returned another pointer')
                original=self._observe(op,'package_selection',asdict(actual))
            self._finish(op,stage,(original,));return
        if stage=='authority_start_intent':
            original=self._one(self._stage_observations(op,'retire_intent'),'process','authority')
            await self._start_or_recover(op,self.authority,original,stage,'authority')
            return
        if stage=='authority_bootstrap_ready':
            body=await self._wait_call(lambda:self.client.read_authority_bootstrap_v2(op))
            self._finish(op,stage,(self._observe(op,'package_bootstrap',body),));return
        if stage=='host_start_intent':
            original=self._one(self._stage_observations(op,'retire_intent'),'process','host')
            await self._start_or_recover(op,self.host,original,stage,'host');return
        if stage=='bootstrap_ready':
            host=await self._wait_call(lambda:self.client.read_host_bootstrap_v2(op))
            authority=await self.client.read_authority_bootstrap_v2(op)
            self._finish(op,stage,(self._observe(op,'package_bootstrap',authority),self._observe(op,'package_bootstrap',host)));return
        if stage=='abort_intent':
            selected,_,_=self.files.read_selected_configuration_cohort_v2()
            if selected.selection_digest!=intent.expected_selection_digest:
                raise AuthorityUnavailable('pre-switch abort cannot change the original selection')
            sources={}
            for receipt in self.journal.read_verified_receipts_v2(op):
                for ref,_ in receipt.observation_refs:
                    if ref==intent.accepted_original_ref:continue
                    observed=self.journal.read_verified_observation_v2(op,ref)
                    if observed.kind=='backup_source' and observed.body['backup_phase']=='forward':sources[ref]=observed
            if not sources:
                _,body=await self.client.read_backup_source_v2(op)
                source=self._observe(op,'backup_source',body)
            elif len(sources)==1:source=next(iter(sources.values()))
            else:raise AuthorityUnavailable('abort source qualification is ambiguous')
            self._finish(op,stage,(self._process(op,'host'),self._process(op,'authority'),source));return
        if stage=='abort_retired':
            before=self._stage_observations(op,'abort_intent')
            for role,service in (('host',self.host),('authority',self.authority)):
                original=self._one(before,'process',role)
                await self._os_call(service.stop_original_host_v1,expected_invocation_id=original.body['systemd']['invocation_id'])
                if original.body['process_original'] is not None:require_process_retired_v1(original.body['process_original'])
            with self._retired_storage() as (control,inventory):
                body=self._backup_component(control,inventory).read_retired_abort_source_v2(op)
                source=self._observe(op,'backup_source',body)
            self._finish(op,stage,(self._process(op,'host'),self._process(op,'authority'),source));return
        if stage=='abort_authority_start_intent':
            original=self._one(self._stage_observations(op,'abort_intent'),'process','authority')
            await self._start_or_recover(op,self.authority,original,stage,'authority');return
        if stage=='abort_authority_bootstrap_ready':
            body=await self._wait_call(lambda:self.client.read_authority_bootstrap_v2(op))
            self._finish(op,stage,(self._observe(op,'package_bootstrap',body),));return
        if stage=='abort_host_start_intent':
            original=self._one(self._stage_observations(op,'abort_intent'),'process','host')
            await self._start_or_recover(op,self.host,original,stage,'host');return
        if stage=='abort_bootstrap_ready':
            host=await self._wait_call(lambda:self.client.read_host_bootstrap_v2(op))
            authority=await self.client.read_authority_bootstrap_v2(op)
            self._finish(op,stage,(self._observe(op,'package_bootstrap',authority),self._observe(op,'package_bootstrap',host)));return
        if stage=='rollback_retire_intent':
            source=None
            try:_,source=await self.client.read_rollback_source_v2(op)
            except (AuthorityUnavailable,RuntimeError,ConnectionError,TimeoutError):pass
            observations=[self._process(op,'host'),self._process(op,'authority')]
            if source is not None:observations.append(self._observe(op,'backup_source',source))
            self._finish(op,stage,observations);return
        if stage=='rollback_retired':
            before=self._stage_observations(op,'rollback_retire_intent')
            for role,service in (('host',self.host),('authority',self.authority)):
                original=self._one(before,'process',role)
                await self._os_call(service.stop_original_host_v1,expected_invocation_id=original.body['systemd']['invocation_id'])
                if original.body['process_original'] is not None:require_process_retired_v1(original.body['process_original'])
            sources=[o for o in before if o.kind=='backup_source']
            if len(sources)>1:raise AuthorityUnavailable('ambiguous rollback current source')
            if sources:source=sources[0]
            else:
                with self._retired_storage() as (control,inventory):
                    body=self._backup_component(control,inventory).read_retired_rollback_source_v2(op)
                    source=self._observe(op,'backup_source',body)
            self._finish(op,stage,(self._process(op,'host'),self._process(op,'authority'),source));return
        if stage=='rollback_backup_ready':
            with self._retired_storage() as (control,inventory):
                body=self._backup_component(control,inventory).create_managed_backup_v2(op)
                original=self._observe(op,'managed_backup',body)
            self._finish(op,stage,(original,));return
        if stage=='rollback_compatible_current_data':
            from .d12_candidate_compatibility_v2 import InstalledD12CandidateCompatibilityV2
            with self._retired_storage() as (control,inventory):
                reader=InstalledD12CandidateCompatibilityV2(package_files=self.files,supervisor_journal=self.journal,
                    storage_reader=control,managed_backup=self._backup_component(control,inventory))
                original=self._observe(op,'package_compatibility',reader.verify_current_candidate_v2(op))
            self._finish(op,stage,(original,));return
        if stage=='rollback_switch_intent':
            selected,_,_=self.files.read_selected_configuration_cohort_v2()
            if selected.operation_id!=op or selected.cohort_digest!=intent.candidate_cohort_digest or selected.revision!=intent.expected_selection_revision+1:
                raise AuthorityUnavailable('rollback must use exact current candidate')
            self._finish(op,stage,(self._observe(op,'package_selection',asdict(selected)),
                self._one(self._stage_observations(op,'rollback_compatible_current_data'),'package_compatibility')));return
        if stage=='rollback_package_switched':
            before=self._one(self._stage_observations(op,'rollback_switch_intent'),'package_selection')
            expected=decode_package_selection_v2(before.body)
            _,old=self.files.read_registered_cohort_v2(intent.old_cohort_ref)
            desired=next_package_selection_v2(expected,operation_id=op,package=old.package,cohort_ref=old.cohort_ref,cohort_digest=old.cohort_digest)
            with self._retired_storage() as (control,inventory):
                self._require_unchanged_snapshot(op,control,inventory,'rollback')
                actual=self.files._switch_after_supervisor_authorization_v2(expected=expected,desired=desired)
                if actual!=desired:raise AuthorityUnavailable('rollback selection CAS differs')
                original=self._observe(op,'package_selection',asdict(actual))
            self._finish(op,stage,(original,));return
        if stage=='rollback_authority_start_intent':
            original=self._one(self._stage_observations(op,'rollback_retire_intent'),'process','authority')
            await self._start_or_recover(op,self.authority,original,stage,'authority');return
        if stage=='rollback_authority_bootstrap_ready':
            body=await self._wait_call(lambda:self.client.read_authority_bootstrap_v2(op))
            self._finish(op,stage,(self._observe(op,'package_bootstrap',body),));return
        if stage=='rollback_host_start_intent':
            original=self._one(self._stage_observations(op,'rollback_retire_intent'),'process','host')
            await self._start_or_recover(op,self.host,original,stage,'host');return
        if stage=='rollback_bootstrap_ready':
            host=await self._wait_call(lambda:self.client.read_host_bootstrap_v2(op))
            authority=await self.client.read_authority_bootstrap_v2(op)
            self._finish(op,stage,(self._observe(op,'package_bootstrap',authority),self._observe(op,'package_bootstrap',host)));return
        if stage in {'active','rollback_complete','abort_complete'}:
            original=await self.client.finish_activation_v2(op)
            self._finish(op,stage,(self._observe(op,'package_activation',original),));return
        raise AuthorityUnavailable('unimplemented original maintenance stage remains HOLD')

    async def _start_or_recover(self,op,service,prior,stage,role):
        current=service.read_current_host_state_v1()
        if current.stopped_and_drained:
            if (op,stage) not in self._fresh_start_permissions:
                raise AuthorityUnavailable('original start outcome unknown; stopped state does not permit a second start')
            self._fresh_start_permissions.remove((op,stage))
            await self._os_call(service.start_stopped_host_v1,expected_prior_invocation_id=prior.body['systemd']['invocation_id'])
        elif (current.active_state!='active' or current.main_pid<1 or not current.invocation_id
                or current.invocation_id==prior.body['systemd']['invocation_id']):
            raise AuthorityUnavailable('original start is unresolved; no second process start allowed')
        # An observed new process is not native/data readiness. The following
        # independent bootstrap stage must prove that exact actual incarnation.
        self._finish(op,stage,(self._process(op,role),))
