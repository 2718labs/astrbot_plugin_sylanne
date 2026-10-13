"""Installed Owner acceptance and lifecycle exclusion for compatible packages.

All package/proc/supervisor reads precede short Core stage transactions. This
service never stops a process, copies a database or switches a filesystem path.
The separate protected supervisor owns those effects and its durable journal.
"""
from dataclasses import asdict
import json
from uuid import UUID
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..runtime.lifecycle_operations_v1 import digest as lifecycle_digest
from .contract import AuthorityUnavailable
from .d12_installation_lifecycle_v1 import InstalledD12InstallationLifecycleV1
from .d12_lifecycle_gate_v1 import read_lifecycle_head_in_tx_v1
from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
from .d12_package_maintenance_contract_v2 import build_d12_package_intent_v2,package_intent_from_wire_v2,package_intent_to_wire_v2
from .d12_package_owner_observation_v2 import observe_current_package_owner_v2
from .d12_package_bootstrap_v2 import BOOTSTRAPS,BOOT_DDL
from .v2_owner_session import from_wire as session_from_wire,_canonical
from .graph_catalogue_upgrade_v1 import require_selected_catalogue_target_in_tx_v1

ACCEPTANCES='authority_d12_package_acceptances_v2'
HEADS='authority_d12_package_heads_v2'
ACTIVATIONS='authority_d12_package_activations_v2'
DDL={
BOOTSTRAPS:BOOT_DDL,
ACCEPTANCES:f'CREATE TABLE {ACCEPTANCES}(namespace TEXT NOT NULL,operation_id TEXT NOT NULL,request_digest TEXT NOT NULL,intent_json TEXT NOT NULL,intent_digest TEXT NOT NULL,actor TEXT NOT NULL,session_request_json BLOB NOT NULL,owner_head TEXT NOT NULL,owner_observation_json TEXT NOT NULL,storage_identity_json TEXT NOT NULL,selection_json TEXT NOT NULL,acceptance_anchor_json TEXT NOT NULL,PRIMARY KEY(namespace,operation_id))',
HEADS:f'CREATE TABLE {HEADS}(namespace TEXT PRIMARY KEY,operation_id TEXT NOT NULL,intent_digest TEXT NOT NULL,lifecycle_epoch INTEGER NOT NULL,stage TEXT NOT NULL,supervisor_receipt_digest TEXT,hold_code TEXT)',
ACTIVATIONS:f'CREATE TABLE {ACTIVATIONS}(namespace TEXT NOT NULL,operation_id TEXT NOT NULL,original_ref TEXT NOT NULL,original_digest TEXT NOT NULL,original_json TEXT NOT NULL,PRIMARY KEY(namespace,operation_id))',
}


def immutable_package_trigger_ddl_v2(table,action):
    if table not in {ACCEPTANCES,ACTIVATIONS,BOOTSTRAPS} or action not in {"UPDATE","DELETE"}:raise ValueError("closed package immutable trigger required")
    return f"CREATE TRIGGER {table}_no_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'package maintenance original immutable'); END"


def validate_package_authority_schema_v2(db):
    for name,sql in DDL.items():
        if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()!=(sql,):raise AuthorityUnavailable("package Authority schema differs")
        if name!=HEADS:
            for action in ("UPDATE","DELETE"):
                if db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",(name+'_no_'+action.lower(),)).fetchone()!=(immutable_package_trigger_ddl_v2(name,action),):raise AuthorityUnavailable("package Authority immutable trigger differs")


class InstalledD12PackageMaintenanceAuthorityV2:
    def __init__(self,*,lifecycle,package_files,supervisor_journal=None,authority_supervisor=None):
        if type(lifecycle) is not InstalledD12InstallationLifecycleV1 or type(package_files) is not InstalledPackageSelectionFilesV2:raise TypeError('actual installed lifecycle and protected package registry required')
        policy=package_files.read_maintenance_policy_v2()
        if supervisor_journal is not None:
            from .d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2
            if type(supervisor_journal) is not InstalledPackageSupervisorJournalV2 or supervisor_journal.policy!=policy['supervisor_policy_digest']:raise TypeError('actual independently verified supervisor journal required')
        from .d12_installed_supervisor_v1 import is_installed_supervisor_v1,supervisor_identity_v1
        if authority_supervisor is not None and (not is_installed_supervisor_v1(authority_supervisor) or supervisor_identity_v1(authority_supervisor.config)==supervisor_identity_v1(lifecycle.supervisor.config)):raise TypeError('distinct actual fixed Authority supervisor required')
        self.authority_supervisor=authority_supervisor
        self.lifecycle=lifecycle;self.files=package_files;self.journal=supervisor_journal;self.policy=policy
        self.status=lifecycle.status_service;self.core=lifecycle.core;self.fences=lifecycle.fences
        self.namespace=lifecycle.namespace;self.installation_id=lifecycle.installation_id
        self._subject='d12-package:'+self.installation_id

    def install_schema_v2(self,administrator_credential):
        self.core._require(administrator_credential,'d12_package_install',self.namespace)
        with self.core._tx() as db:
            for name,sql in DDL.items():
                row=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()
                if row is None:db.execute(sql)
                elif row!=(sql,):raise AuthorityUnavailable('package Authority schema differs')
                if name!=HEADS:
                    for action in ('UPDATE','DELETE'):
                        trigger=immutable_package_trigger_ddl_v2(name,action)
                        old=db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",(name+'_no_'+action.lower(),)).fetchone()
                        if old is None:db.execute(trigger)
                        elif old!=(trigger,):raise AuthorityUnavailable('package Authority original trigger differs')

    def _row(self,db,operation_id):
        row=db.execute(f'SELECT * FROM {ACCEPTANCES} WHERE namespace=? AND operation_id=?',(self.namespace,operation_id)).fetchone()
        if row is None:raise AuthorityUnavailable('exact accepted package operation absent')
        from .d12_package_core_rows_v2 import validate_d12_package_core_row_v2,COLUMNS
        intent=validate_d12_package_core_row_v2(ACCEPTANCES,COLUMNS[ACCEPTANCES],row)
        if (intent.operation_id!=operation_id or intent.request_digest!=row[2] or intent.accepted_original_digest!=row[4]
                or intent.installation_id!=self.installation_id or intent.namespace_cohort!=(self.namespace,)
                or intent.current_storage_identity_digest!=canonical_digest(json.loads(row[9]))):raise AuthorityUnavailable('package accepted original differs')
        return row,intent

    def _current_accepted_owner(self,db,row):
        require_selected_catalogue_target_in_tx_v1(db,self.lifecycle)
        request=session_from_wire({'kind':'owner_session_login_request_v1',**json.loads(row[6])})
        sessions=self.status.sessions
        sessions._current_key(db,request)
        sessions._current_pairing_source.require_current_actor_in_tx(db,authority_namespace=self.namespace,
            installation_id=self.installation_id,actor_id=row[5],principal=request.principal)
        guard=self.status.tickets._checked_current_head(db,self.namespace)
        if guard is None or guard.authorization_head!=row[7] or guard.pending_revoke_operation_id is not None or guard.minimum_revocation_epoch or guard.minimum_revocation_revision:raise AuthorityUnavailable('package accepted Owner was revoked or changed')
        return guard

    def _current_status_owner(self,db,row,*,actor,token,request):
        old=session_from_wire({'kind':'owner_session_login_request_v1',**json.loads(row[6])})
        if (actor!=row[5] or any(getattr(old,k)!=getattr(request,k) for k in ('authority_id','authority_namespace','installation_id','principal','audience'))):raise AuthorityUnavailable('package status exact initiating principal/scope differs')
        return self.status._current_session_in_tx(db,actor=actor,token=token,request=request,expected_head=row[7])

    def accept_current_package_switch_v2(self,*,credential,actor,session_token,session_request,
            operation_id,candidate_cohort_ref,expected_selection_digest,expected_lifecycle_epoch):
        self.core._require(credential,'d12_package_control',self.namespace)
        parsed=UUID(operation_id)
        if parsed.version!=4 or str(parsed)!=operation_id:raise ValueError('package operation must be canonical UUID4')
        requested={'schema':'d12.compatible-package-request.v2','operation_id':operation_id,
            'candidate_cohort_ref':candidate_cohort_ref,'expected_selection_digest':expected_selection_digest,
            'expected_lifecycle_epoch':expected_lifecycle_epoch}
        request_digest=canonical_digest(requested)
        with self.core._tx() as db:
            require_selected_catalogue_target_in_tx_v1(db,self.lifecycle)
            prior=db.execute(f'SELECT 1 FROM {ACCEPTANCES} WHERE namespace=? AND operation_id=?',(self.namespace,operation_id)).fetchone()
            if prior:
                row,intent=self._row(db,operation_id)
                self._current_status_owner(db,row,actor=actor,token=session_token,request=session_request)
                if intent.request_digest!=request_digest:raise AuthorityUnavailable('package retry changes accepted intent')
                return intent
        # Closing admission is consequential even before an OS action. An
        # optional journal reader alone is not proof that an independent live
        # executor, managed backup and compatibility producers are available.
        if self.journal is None:
            raise AuthorityUnavailable('installed external package supervisor is unavailable')
        readiness=getattr(self.journal,'require_installed_executor_ready_v2',None)
        if not callable(readiness):
            raise AuthorityUnavailable('installed package executor/backup/compatibility readiness is unavailable')
        readiness(operation_id=operation_id,candidate_cohort_ref=candidate_cohort_ref,
            expected_selection_digest=expected_selection_digest)
        # Actual protected registry/config/package reads are outside Core SQL.
        selected,old_cohort,_=self.files.read_selected_configuration_cohort_v2()
        installation,candidate=self.files.read_registered_cohort_v2(candidate_cohort_ref)
        from .d12_configuration_cohort_v2 import read_verified_configuration_cohort_v2
        read_verified_configuration_cohort_v2(candidate)
        policy=self.files.read_maintenance_policy_v2()
        if (policy!=self.policy or installation!=self.installation_id or selected.installation_id!=self.installation_id
                or selected.selection_digest!=expected_selection_digest
                or old_cohort.package.manifest_sha256!=self.lifecycle.expected_manifest_digest
                or candidate.identity_commitment!=old_cohort.identity_commitment
                or candidate.compatibility_plan_ref!=policy['compatibility_plan_ref']
                or old_cohort.compatibility_plan_ref!=policy['compatibility_plan_ref']
                or candidate.supervisor_policy_digest!=policy['supervisor_policy_digest']
                or old_cohort.supervisor_policy_digest!=policy['supervisor_policy_digest']):raise AuthorityUnavailable('package registered candidate changes current installed identities/policies')
        context,storage=self.lifecycle._storage()
        with self.fences._frozen() as (db,deletion,execution,_):
            head=read_lifecycle_head_in_tx_v1(db,self.namespace)
            if head is None or head.state!='active' or head.epoch!=expected_lifecycle_epoch:raise AuthorityUnavailable('package lifecycle state/epoch differs')
            anchor=self.fences._current_locked(db,deletion,execution)
            holder=self.core._row(db,self.namespace)[0]
            permit=self.fences.fences.begin_fence_locked(db,subject=self._subject,holder=holder,operation='write',current_anchor=anchor,
                operation_id='d12-package-accept:'+operation_id)
        committed=False
        try:
            owner=observe_current_package_owner_v2(self.status,credential=credential,subject=self._subject,permit=permit,
                actor=actor,session_token=session_token,session_request=session_request)
            plan={'schema':'d12.registered-compatible-plan.v2','plan_ref':policy['compatibility_plan_ref'],
                'source_cohort_digest':old_cohort.cohort_digest,'candidate_cohort_digest':candidate.cohort_digest,
                'identity_commitment':candidate.identity_commitment,'mode':'compatible_package_switch'}
            intent=build_d12_package_intent_v2(operation_id=operation_id,request_digest=request_digest,
                authority_id=anchor.authority_id,installation_id=self.installation_id,namespace_cohort=(self.namespace,),
                current_storage_identity_digest=canonical_digest(storage),current_owner_heads_digest=owner.observation_digest,
                lifecycle_operation_id=operation_id,lifecycle_epoch=expected_lifecycle_epoch+1,
                old_package_id=old_cohort.package.release_ref,old_manifest_sha256=old_cohort.package.manifest_sha256,
                old_cohort_ref=old_cohort.cohort_ref,old_cohort_digest=old_cohort.cohort_digest,
                expected_selection_revision=selected.revision,expected_selection_digest=selected.selection_digest,
                expected_package_epoch=selected.package_epoch,candidate_package_id=candidate.package.release_ref,
                candidate_manifest_sha256=candidate.package.manifest_sha256,candidate_cohort_ref=candidate.cohort_ref,
                candidate_cohort_digest=candidate.cohort_digest,compatibility_plan_digest=canonical_digest(plan),
                managed_backup_ref='d12-managed-backup:'+operation_id,supervisor_policy_digest=policy['supervisor_policy_digest'])
            context,current_storage=self.lifecycle._storage()
            if current_storage!=storage:raise AuthorityUnavailable('package accepted current storage changed during observation')
            with self.fences._frozen() as (db,deletion,execution,_):
                current=self.fences._current_locked(db,deletion,execution,require_no_pending=False)
                self.fences.fences.validate_fence_locked(db,permit,subject=self._subject,current_anchor=current)
                self.status._current_session_in_tx(db,actor=actor,token=session_token,request=session_request,expected_head=owner.authority.guard.authorization_head)
                head=read_lifecycle_head_in_tx_v1(db,self.namespace)
                if head.state!='active' or head.epoch!=expected_lifecycle_epoch or current!=anchor:raise AuthorityUnavailable('package accepted lifecycle/current head changed')
                values=(self.namespace,operation_id,request_digest,canonical_serialize(package_intent_to_wire_v2(intent)),intent.digest,
                    actor,_canonical(session_request),owner.authority.guard.authorization_head,canonical_serialize(asdict(owner)),
                    canonical_serialize(storage),canonical_serialize(asdict(selected)),canonical_serialize(asdict(anchor)))
                db.execute(f'INSERT INTO {ACCEPTANCES} VALUES({",".join("?" for _ in values)})',values)
                self.fences.fences.finish_fence_locked(db,permit,subject=self._subject,current_anchor=current,
                    request_id=permit.operation_id+':accepted',request_digest='sha256:'+intent.digest)
                state=(self.namespace,self.installation_id,'quiescing',intent.lifecycle_epoch,operation_id,intent.accepted_original_ref)
                changed=db.execute('UPDATE authority_d12_lifecycle_heads_v1 SET state=?,epoch=?,operation_id=?,head_digest=?,current_receipt_ref=? WHERE namespace=? AND epoch=? AND head_digest=?',
                    ('quiescing',intent.lifecycle_epoch,operation_id,lifecycle_digest(state),intent.accepted_original_ref,self.namespace,head.epoch,head.head_digest)).rowcount
                if changed!=1:raise AuthorityUnavailable('package lifecycle exclusion CAS changed')
                db.execute(f'INSERT INTO {HEADS} VALUES(?,?,?,?,?,?,?) ON CONFLICT(namespace) DO UPDATE SET operation_id=excluded.operation_id,intent_digest=excluded.intent_digest,lifecycle_epoch=excluded.lifecycle_epoch,stage=excluded.stage,supervisor_receipt_digest=NULL,hold_code=NULL',
                    (self.namespace,operation_id,intent.digest,intent.lifecycle_epoch,'accepted',None,None))
                self.core._event(db,self.namespace,'d12_package_accepted',current.activation_generation,(operation_id,intent.digest,owner.observation_digest))
                committed=True
            return intent
        finally:
            if not committed:
                with self.fences._frozen() as (db,deletion,execution,_):
                    current=self.fences._current_locked(db,deletion,execution,require_no_pending=False)
                    self.fences.fences.finish_fence_locked(db,permit,subject=self._subject,current_anchor=current,
                        request_id=permit.operation_id+':rejected',request_digest='sha256:'+canonical_digest((operation_id,request_digest,'not_accepted')))

    def read_current_package_operation_v2(self,*,credential,actor,session_token,session_request,operation_id):
        self.core._require(credential,'d12_package_control',self.namespace)
        with self.core._tx() as db:
            row,intent=self._row(db,operation_id)
            self._current_status_owner(db,row,actor=actor,token=session_token,request=session_request)
            head=db.execute(f'SELECT stage,supervisor_receipt_digest,hold_code FROM {HEADS} WHERE namespace=? AND operation_id=?',(self.namespace,operation_id)).fetchone()
            if head is None:raise AuthorityUnavailable('package original head absent')
            lifecycle_head=read_lifecycle_head_in_tx_v1(db,self.namespace)
            result={'intent':package_intent_to_wire_v2(intent),'stage':head[0], 'supervisor_receipt_digest':head[1],'hold_code':head[2],
                'lifecycle_state':lifecycle_head.state,'executor_state':'awaiting_privileged_executor' if head[0]=='accepted' else 'original_stage_recorded'}
        if self.journal is not None:
            observed=self.journal.read_verified_intent_v2(operation_id)
            if observed is not None:
                if observed!=intent:raise AuthorityUnavailable('package status supervisor original differs')
                stages=self.journal.read_verified_receipts_v2(operation_id)
                pending=self.journal.read_verified_pending_stage_v2(operation_id)
                if stages:
                    result.update(stage=stages[-1].stage,supervisor_receipt_digest=stages[-1].receipt_digest,executor_state='original_stage_recorded')
                if pending is not None:result.update(pending_stage=pending['stage'],executor_state='original_stage_pending')
                if lifecycle_head.state=='active' and head[0] in {'active','rollback_complete','abort_complete'}:result['stage']=head[0]
        return result


    def read_supervisor_intent_v2(self,*,credential,operation_id):
        """Read accepted facts through an independently installed supervisor peer."""
        self.core._require(credential,'d12_package_supervisor',self.namespace)
        context,storage=self.lifecycle._storage()
        selected,cohort,_=self.files.read_selected_configuration_cohort_v2()
        with self.fences._frozen() as (db,deletion,execution,_):
            row,intent=self._row(db,operation_id);self._current_accepted_owner(db,row)
            head=read_lifecycle_head_in_tx_v1(db,self.namespace)
            if (head.operation_id!=operation_id or head.epoch!=intent.lifecycle_epoch or head.state not in {'quiescing','drained','resuming'}
                    or canonical_digest(storage)!=intent.current_storage_identity_digest
                    or selected.selection_digest!=intent.expected_selection_digest
                    or cohort.cohort_digest!=intent.old_cohort_digest):raise AuthorityUnavailable('package supervisor intent no longer owns current lifecycle/storage/selection')
            live,pending,rpc=self.lifecycle._counts(db)
            anchor=self.fences._current_locked(db,deletion,execution,require_no_pending=False)
            observation={'schema':'d12.package-supervisor-admission.v2','operation_id':operation_id,
                'accepted_original_digest':intent.digest,'lifecycle_epoch':head.epoch,'lifecycle_state':head.state,
                'current_storage_identity_digest':canonical_digest(storage),'current_anchor_digest':canonical_digest(anchor),
                'live_fence_count':live,'pending_mutation_count':pending,'active_rpc_count':rpc,
                'selection_digest':selected.selection_digest,'supervisor_policy_digest':self.policy['supervisor_policy_digest']}
            observation['observation_digest']=canonical_digest(observation)
            return {'intent':package_intent_to_wire_v2(intent),'admission_observation':observation}

    def read_supervisor_backup_source_v2(self,*,credential,operation_id):
        from .d12_managed_backup_v2 import read_actual_backup_source_v2
        return read_actual_backup_source_v2(self,credential=credential,operation_id=operation_id)

    def read_supervisor_rollback_source_v2(self,*,credential,operation_id):
        self.core._require(credential,'d12_package_supervisor',self.namespace)
        from .d12_managed_backup_v2 import read_actual_backup_source_v2
        from .d12_package_bootstrap_v2 import require_package_supervisor_scope_v2
        require_package_supervisor_scope_v2(self,operation_id=operation_id,role='rollback_source')
        return read_actual_backup_source_v2(self,credential=credential,operation_id=operation_id,_selection_purpose='rollback_source')

    def read_current_authority_package_bootstrap_v2(self,**request):
        from .d12_package_bootstrap_v2 import read_current_authority_package_bootstrap_v2
        return read_current_authority_package_bootstrap_v2(self,**request)

    def read_current_maintenance_bootstrap_v2(self,**request):
        from .d12_package_bootstrap_v2 import read_current_maintenance_bootstrap_v2
        return read_current_maintenance_bootstrap_v2(self,**request)

    def register_current_package_host_ready_v2(self,**request):
        from .d12_package_bootstrap_v2 import register_current_package_host_ready_v2
        return register_current_package_host_ready_v2(self,**request)

    def finish_current_package_activation_v2(self,**request):
        from .d12_package_bootstrap_v2 import finish_current_package_activation_v2
        return finish_current_package_activation_v2(self,**request)

    def read_current_package_host_bootstrap_v2(self,**request):
        from .d12_package_bootstrap_v2 import read_current_package_host_bootstrap_v2
        return read_current_package_host_bootstrap_v2(self,**request)

    def read_current_package_maintenance_v2(self,*,credential,actor,session_token,session_request):
        """Current signed Owner view of fixed registered choices, never readiness."""
        from uuid import uuid4
        self.core._require(credential,'d12_package_control',self.namespace)
        selected,current,_=self.files.read_selected_configuration_cohort_v2()
        installation,registered=self.files.read_registered_cohorts_v2()
        context,storage=self.lifecycle._storage()
        with self.fences._frozen() as (db,deletion,execution,_):
            head=read_lifecycle_head_in_tx_v1(db,self.namespace)
            if head is None or head.state!='active' or installation!=self.installation_id:raise AuthorityUnavailable('current package maintenance selection is unavailable')
            anchor=self.fences._current_locked(db,deletion,execution)
            holder=self.core._row(db,self.namespace)[0]
            permit=self.fences.fences.begin_fence_locked(db,subject=self._subject,holder=holder,operation='read',current_anchor=anchor,
                operation_id='d12-package-profile:'+str(uuid4()))
        try:
            owner=observe_current_package_owner_v2(self.status,credential=credential,subject=self._subject,permit=permit,
                actor=actor,session_token=session_token,session_request=session_request)
            def public(cohort):
                return {'cohort_ref':cohort.cohort_ref,'cohort_digest':cohort.cohort_digest,'release_ref':cohort.package.release_ref,
                    'manifest_sha256':cohort.package.manifest_sha256,'package_version':cohort.package.package_version}
            with self.core._tx() as db:
                if read_lifecycle_head_in_tx_v1(db,self.namespace)!=head:raise AuthorityUnavailable('package profile lifecycle changed')
                self.status._current_session_in_tx(db,actor=actor,token=session_token,request=session_request,expected_head=owner.authority.guard.authorization_head)
            context.require_current('business')
            if self.files.read_selected_package_v2()[0]!=selected:raise AuthorityUnavailable('package profile selection changed')
            return {'schema':'d12.package-maintenance-view.v2','installation_id':self.installation_id,'namespace':asdict(self.lifecycle.namespace_id),
                'current':{**public(current),'selection_digest':selected.selection_digest,'selection_revision':selected.revision,'package_epoch':selected.package_epoch},
                'lifecycle_epoch':head.epoch,'lifecycle_state':head.state,
                'candidates':[public(c) for c in registered if c.identity_commitment==current.identity_commitment and c.package.manifest_sha256!=current.package.manifest_sha256],
                'execution_mode':'privileged_operator_required'}
        finally:
            self.fences.finish_fence(credential=credential,subject=self._subject,permit=permit,
                request_id=permit.operation_id+':read',request_digest='sha256:'+canonical_digest((permit.operation_id,'package_profile')))
