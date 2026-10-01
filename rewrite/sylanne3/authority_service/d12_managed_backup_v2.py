"""Qualified, protected four-store snapshots for compatible package switches.

The authenticated source observation comes from the running actual Authority.
After both fixed units retire, an actual installation OS lease and exact logical
row/DDL equality bridge that observation to SQLite-native snapshots. These
artifacts never authorize restoring old journals or rewinding current data.
"""
from __future__ import annotations
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
from .contract import AuthorityUnavailable
from .d12_package_files_v2 import _sha
from ..runtime_contracts import canonical_digest,canonical_serialize,NamespaceId
from ..runtime.lifecycle_operations_v1 import digest
from .installed_migration_reconciliation_v1 import NamespaceExecutionReconciliationV1
from .c09_storage_control_v1 import InstalledC09StorageReaderV1,InstalledC09InstanceLeaseV1,file_observation_v1
from .d12_sqlite_backup_v2 import sqlite_logical_inventory_v2,snapshot_sqlite_file_v2

SOURCE_SCHEMA='sylanne3.d12.managed-backup-source.v2'
BACKUP_SCHEMA='sylanne3.d12.managed-backup.v2'
ROLES=('core','deletion','execution','graph')
_SOURCE_FIELDS=frozenset('schema operation_id accepted_original_digest backup_phase source_kind continuation_proof installation_id namespace lifecycle_epoch selection_digest storage_identity current_anchor owner_head graph_metadata_digest reconciliation history_inventory logical_inventories source_digest'.split())
_BACKUP_FIELDS=frozenset('schema operation_id accepted_original_digest backup_phase installation_id namespace managed_backup_ref inventory_manifest_digest source_observation_ref source_observation_digest source_digest storage_identity current_anchor owner_head graph_metadata_digest reconciliation history_inventory copies retired_observation_refs restore_authorized disposition manifest_digest'.split())
_LOGICAL_FIELDS=frozenset('inventory_digest table_count row_count schema_object_count user_version application_id'.split())
_FILE_FIELDS=frozenset('resolved_path device file_id prepared_size prepared_mtime_ns prepared_sha256'.split())


def _file(raw):
    if (type(raw) is not dict or set(raw)!=_FILE_FIELDS or not _sha(raw['prepared_sha256'])
            or type(raw['resolved_path']) is not str or not Path(raw['resolved_path']).is_absolute()
            or any(type(raw[k]) is not int or raw[k]<0 for k in _FILE_FIELDS-{'resolved_path','prepared_sha256'})):
        raise AuthorityUnavailable('managed backup exact file observation differs')


def _logical(raw):
    if (type(raw) is not dict or set(raw)!=_LOGICAL_FIELDS or not _sha(raw['inventory_digest'])
            or any(type(raw[k]) is not int or raw[k]<0 for k in _LOGICAL_FIELDS-{'inventory_digest'})):
        raise AuthorityUnavailable('managed backup exact logical inventory differs')


def _reconciliation(raw,namespace):
    if type(raw) is not dict or set(raw)!=set(NamespaceExecutionReconciliationV1.__dataclass_fields__):
        raise AuthorityUnavailable('actual namespace recovery reconciliation required')
    fields=dict(raw);fields['namespace']=NamespaceId(**fields['namespace']);fields['constraints']=tuple(tuple(row) for row in fields['constraints'])
    result=NamespaceExecutionReconciliationV1(**fields)
    material=asdict(result);material.pop('original_digest')
    # The original producer commits the typed NamespaceId, including its
    # canonical type discriminator. Preserve that exact material on decode.
    material['namespace']=result.namespace
    if (result.authority_namespace!=namespace or digest(material)!=result.original_digest
            or result.constraints!=tuple(sorted(set(result.constraints)))
            or any(len(row)!=4 or any(type(v) is not str or not v for v in row) for row in result.constraints)):
        raise AuthorityUnavailable('namespace recovery projection commitment differs')
    return result


def decode_backup_source_v2(raw):
    if type(raw) is not dict or set(raw)!=_SOURCE_FIELDS or raw['schema']!=SOURCE_SCHEMA:
        raise AuthorityUnavailable('closed managed backup source fields required')
    from uuid import UUID
    op=UUID(raw['operation_id'])
    if str(op)!=raw['operation_id'] or op.version!=4:raise AuthorityUnavailable('backup exact operation required')
    for k in ('accepted_original_digest','selection_digest','source_digest'):
        if not _sha(raw[k]):raise AuthorityUnavailable('backup source digest differs')
    if raw['backup_phase'] not in {'forward','rollback','abort'}:raise AuthorityUnavailable('fixed source phase required')
    if raw['source_kind']=='paired_authority':
        if raw['continuation_proof'] is not None:raise AuthorityUnavailable('paired source cannot claim offline continuation')
    elif raw['source_kind']=='retired_current_core':
        proof=raw['continuation_proof']
        fields={'schema','forward_source_observation_ref','forward_source_observation_digest','forward_source_digest','before_core_inventory_digest','current_core_inventory_digest','changes','continuation_digest'}
        if type(proof) is not dict or set(proof)!=fields or proof['schema']!='d12.offline-current-core-continuation.v2' or raw['backup_phase'] not in {'rollback','abort'}:raise AuthorityUnavailable('closed offline current Core continuation required')
        material=dict(proof);material.pop('continuation_digest')
        if (canonical_digest(material)!=proof['continuation_digest'] or proof['current_core_inventory_digest']!=raw['logical_inventories']['core']['inventory_digest']
                or any(not _sha(proof[k]) for k in fields-{'schema','forward_source_observation_ref','changes'})
                or type(proof['changes']) not in (list,tuple) or any(len(row)!=3 or row[0] not in {'retired_bootstrap','owner_session_boot_id','lifecycle_resuming'} for row in proof['changes'])):
            raise AuthorityUnavailable('offline current Core continuation commitment differs')
    else:raise AuthorityUnavailable('unknown managed backup source authority')
    if type(raw['lifecycle_epoch']) is not int or raw['lifecycle_epoch']<1:raise AuthorityUnavailable('backup lifecycle epoch absent')
    if type(raw['logical_inventories']) is not dict or set(raw['logical_inventories'])!=set(ROLES):raise AuthorityUnavailable('all four backup source inventories required')
    for value in raw['logical_inventories'].values():_logical(value)
    _reconciliation(raw['reconciliation'],raw['namespace'])
    from .d12_historical_manifest_inventory_v1 import decode_historical_manifest_inventory_v1
    history=decode_historical_manifest_inventory_v1(raw['history_inventory'])
    if (history['authority_namespace']!=raw['namespace'] or history['installation_id']!=raw['installation_id']
            or history['namespace']!=raw['reconciliation']['namespace']
            or any(history['execution_head'][key]!=raw['current_anchor']['execution_'+key] for key in ('journal_id','seq','digest'))):raise AuthorityUnavailable('backup historical inventory namespace/head differs')
    from ..runtime.restore_anchor import RestoreAnchor
    anchor=RestoreAnchor(**raw['current_anchor'])
    if anchor.namespace!=raw['namespace']:raise AuthorityUnavailable('backup anchor namespace differs')
    storage=raw['storage_identity']
    if (type(storage) is not dict or set(storage)!={'pointer_version','manifest_digest','storage_generation','members'}
            or tuple(sorted(m['role'] for m in storage['members']))!=ROLES):raise AuthorityUnavailable('exact selected four-file storage required')
    body=dict(raw);body.pop('source_digest')
    if canonical_digest(body)!=raw['source_digest'] or len(canonical_serialize(raw).encode())>48*1024:
        raise AuthorityUnavailable('backup source commitment or bounded RPC size differs')
    return raw


def decode_managed_backup_v2(raw):
    if type(raw) is not dict or set(raw)!=_BACKUP_FIELDS or raw['schema']!=BACKUP_SCHEMA:
        raise AuthorityUnavailable('closed managed four-store backup fields required')
    if raw['restore_authorized'] is not False or raw['disposition']!='protected_nonrestorable':
        raise AuthorityUnavailable('managed snapshot cannot authorize journal restore')
    if raw['backup_phase'] not in {'forward','rollback'}:raise AuthorityUnavailable('fixed backup phase required')
    if raw['managed_backup_ref']!='d12-managed-backup:'+raw['operation_id']+('' if raw['backup_phase']=='forward' else ':rollback'):
        raise AuthorityUnavailable('exact accepted managed backup reference required')
    for k in ('accepted_original_digest','inventory_manifest_digest','source_observation_digest','source_digest','manifest_digest'):
        if not _sha(raw[k]):raise AuthorityUnavailable('managed backup commitment differs')
    _reconciliation(raw['reconciliation'],raw['namespace'])
    from .d12_historical_manifest_inventory_v1 import decode_historical_manifest_inventory_v1
    history=decode_historical_manifest_inventory_v1(raw['history_inventory'])
    if (history['authority_namespace']!=raw['namespace'] or history['installation_id']!=raw['installation_id']
            or history['namespace']!=raw['reconciliation']['namespace']
            or any(history['execution_head'][key]!=raw['current_anchor']['execution_'+key] for key in ('journal_id','seq','digest'))):raise AuthorityUnavailable('backup historical inventory namespace/head differs')
    if type(raw['copies']) is not dict or set(raw['copies'])!=set(ROLES):raise AuthorityUnavailable('four real SQLite backups required')
    for copy in raw['copies'].values():
        if (type(copy) is not dict or set(copy)!={'schema','source_observation','source_wal_observation','backup_observation','logical_inventory','source_write_performed','restore_authorized'}
                or copy['schema']!='sylanne3.d12.sqlite-backup-file.v2' or copy['source_write_performed'] is not False or copy['restore_authorized'] is not False):raise AuthorityUnavailable('real SQLite snapshot observation differs')
        _file(copy['source_observation']);_file(copy['backup_observation']);_logical(copy['logical_inventory'])
        if copy['source_wal_observation'] is not None:_file(copy['source_wal_observation'])
    if type(raw['retired_observation_refs']) not in (tuple,list) or len(raw['retired_observation_refs'])!=2:raise AuthorityUnavailable('both actual retired units required')
    body=dict(raw);body.pop('manifest_digest')
    if canonical_digest(body)!=raw['manifest_digest']:raise AuthorityUnavailable('managed backup manifest commitment differs')
    return raw


def read_actual_backup_source_v2(service,*,credential,operation_id,_selection_purpose="source"):
    from .d12_package_maintenance_authority_v2 import InstalledD12PackageMaintenanceAuthorityV2
    from .d12_lifecycle_gate_v1 import read_lifecycle_head_in_tx_v1
    if type(service) is not InstalledD12PackageMaintenanceAuthorityV2:raise TypeError('actual package Authority required')
    service.core._require(credential,'d12_package_supervisor',service.namespace)
    context,storage=service.lifecycle._storage()
    selection,cohort,_=service.files.read_selected_configuration_cohort_v2()
    from .d12_package_selection_admission_v2 import require_actual_package_selection_v2
    with service.core._tx() as db:accepted_row,accepted_intent=service._row(db,operation_id)
    require_actual_package_selection_v2(service,intent=accepted_intent,accepted_row=accepted_row,selected=selection,purpose=_selection_purpose)
    deadline=time.monotonic()+30
    from contextlib import ExitStack
    from ..graph_store import GraphStore
    from .d12_historical_manifest_inventory_v1 import read_authenticated_package_history_inputs_v1,collect_package_history_inventory_in_graph_v1
    with ExitStack() as locks:
        for lock in (service.fences.deletion._lock,service.fences.execution._lock,service.core._lock):locks.enter_context(lock)
        if any(store._db.in_transaction for store in (service.fences.deletion,service.fences.execution,service.core)):
            raise AuthorityUnavailable('backup observation requires no outstanding store SQL')
        with service.fences.deletion.freeze_writes():deletion=service.fences.deletion.verified_head()
        execution,execution_rows=service.fences.execution._scan_locked()
        with service.core._tx() as db:
            row,intent=service._row(db,operation_id);owner=service._current_accepted_owner(db,row)
            head=read_lifecycle_head_in_tx_v1(db,service.namespace)
            live,pending,rpc=service.lifecycle._counts(db)
            if (head.state not in {'quiescing','drained','resuming'} or head.operation_id!=operation_id or head.epoch!=intent.lifecycle_epoch
                    or live or pending or rpc>1 or intent!=accepted_intent or row!=accepted_row
                    or canonical_digest(storage)!=intent.current_storage_identity_digest
                    or service.core._row(db,service.namespace)[9]!='clear'):
                raise AuthorityUnavailable('backup source admission/operation has not actually drained')
            # Current C09 applied proof was read above, outside Core SQL. This
            # short comparison does not recursively open Graph through it.
            anchor=service.fences._current_locked(db,deletion,execution,require_clear=False)
        authenticated=service.lifecycle.constraints.authenticate_execution_rows_under_writer_locks_v1()
        numeric=service.core._execution_redaction_d04_numeric_services_v3.get(service.namespace)
        root=service.core._execution_redaction_d04_root_services_v3.get(service.namespace)
        inputs=read_authenticated_package_history_inputs_v1(numeric_service=numeric,root_service=root,model_store=service.lifecycle.constraints.models)
        inventories={};projection=None;metadata_digest=None
        for member in storage['members']:
            graph=sqlite3.connect(Path(member['resolved_path']).as_uri()+'?mode=ro',uri=True,isolation_level=None)
            try:
                graph.execute('PRAGMA query_only=ON');graph.execute('BEGIN')
                if member['role']=='graph':
                    metadata=GraphStore._decode_recovery(graph.execute('SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',service.lifecycle.namespace_id.as_tuple).fetchone(),service.lifecycle.namespace_id)
                    if metadata is None:raise AuthorityUnavailable('current backup Graph metadata absent')
                    req=metadata.requirements
                    if (req.authority_id!=anchor.authority_id or req.authority_namespace!=anchor.namespace
                            or any(getattr(req,k)!=getattr(anchor,k) for k in ('activation_generation','revocation_epoch','deletion_journal_id','deletion_seq','deletion_digest','execution_journal_id'))
                            or req.execution_seq>anchor.execution_seq
                            or req.execution_digest!=('genesis' if req.execution_seq==0 else next((r[6] for r in execution_rows if r[0]==req.execution_seq),None))):raise AuthorityUnavailable('backup Graph has no actual independent recovery prefix')
                    projection=service.lifecycle.constraints.read_namespace_constraints_under_writer_locks_v1(db=service.core._db,target_db=graph,
                        namespace_id=service.lifecycle.namespace_id,deletion_head=deletion,execution_head=execution,authenticated_rows=authenticated)
                    history=collect_package_history_inventory_in_graph_v1(graph,inputs,resource_issuer=numeric.resource_issuer,
                        budget_issuer=numeric.budget_issuer,namespace=service.lifecycle.namespace_id,installation_id=service.installation_id)
                    metadata_digest=digest(metadata)
                inventories[member['role']]=sqlite_logical_inventory_v2(graph,maximum_rows=100000,deadline=deadline)
            finally:graph.close()
        with service.core._tx() as db:
            current_row,current_intent=service._row(db,operation_id)
            if (current_intent!=intent or service._current_accepted_owner(db,current_row)!=owner
                    or read_lifecycle_head_in_tx_v1(db,service.namespace)!=head
                    or service.lifecycle._counts(db)[:2]!=(0,0) or service.lifecycle._counts(db)[2]>1
                    or service.fences._current_locked(db,deletion,execution,require_clear=False)!=anchor):raise AuthorityUnavailable('backup original admission changed during observation')
        # One actual SQL snapshot at a time. No external writer can cross these
        # held process locks or the drained lifecycle gate; every root is read
        # again to reject an uncoordinated Graph/storage mutation.
        for member in storage['members']:
            graph=sqlite3.connect(Path(member['resolved_path']).as_uri()+'?mode=ro',uri=True,isolation_level=None)
            try:
                graph.execute('PRAGMA query_only=ON');graph.execute('BEGIN')
                if sqlite_logical_inventory_v2(graph,maximum_rows=100000,deadline=deadline)!=inventories[member['role']]:raise AuthorityUnavailable('backup original rows changed during qualification')
            finally:graph.close()
        value=dict(schema=SOURCE_SCHEMA,operation_id=operation_id,accepted_original_digest=intent.digest,
            backup_phase='abort' if _selection_purpose in {'abort_source','abort_bootstrap'} else 'rollback' if _selection_purpose in {'rollback_source','rollback_bootstrap'} else 'forward',source_kind='paired_authority',continuation_proof=None,
            installation_id=service.installation_id,namespace=service.namespace,lifecycle_epoch=head.epoch,
            selection_digest=selection.selection_digest,storage_identity=storage,current_anchor=asdict(anchor),
            owner_head=owner.authorization_head,graph_metadata_digest=metadata_digest,
            reconciliation=json.loads(canonical_serialize(asdict(projection))),history_inventory=history,logical_inventories=inventories)
    context.require_current('business')
    if service.files.read_selected_package_v2()[0]!=selection:raise AuthorityUnavailable('backup selection changed during source qualification')
    value['source_digest']=canonical_digest(value)
    return {'intent':asdict(intent),'backup_source':decode_backup_source_v2(value)}


def reread_sqlite_backup_v2(source,destination,expected,*,maximum_file_bytes,instance_lease=None):
    # ACK loss may leave a complete SQLite-native copy before its signed
    # observation was published. Requalify that exact file; never overwrite
    # or retry a partially written file under a new identity.
    for suffix in ('-wal','-shm','-journal'):
        if Path(str(destination)+suffix).exists():raise AuthorityUnavailable('interrupted backup companion requires exact-stage repair')
    before=file_observation_v1(source);wal=Path(str(source)+'-wal')
    wal_before=file_observation_v1(wal) if wal.exists() else None
    observed=file_observation_v1(destination)
    if observed['prepared_size']>maximum_file_bytes:raise AuthorityUnavailable('existing backup exceeds installed bound')
    for path in (source,destination):
        from .d12_sqlite_backup_v2 import leased_sqlite_read_uri_v2
        uri,immutable=leased_sqlite_read_uri_v2(path,instance_lease)
        db=sqlite3.connect(uri,uri=True,isolation_level=None)
        try:
            db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            if db.execute('PRAGMA quick_check').fetchone()!=('ok',) or sqlite_logical_inventory_v2(db,maximum_rows=100000,deadline=time.monotonic()+30)!=expected:
                raise AuthorityUnavailable('same-operation backup is incomplete or originals changed')
        finally:db.close()
        if immutable and any(Path(str(path)+suffix).exists() for suffix in ('-wal','-shm','-journal')):
            raise AuthorityUnavailable('closed snapshot source acquired a companion')
    if instance_lease is not None:instance_lease.require_held()
    if (file_observation_v1(source)!=before or file_observation_v1(destination)!=observed
            or (file_observation_v1(wal) if wal.exists() else None)!=wal_before):raise AuthorityUnavailable('backup recovery file changed during read')
    return dict(schema='sylanne3.d12.sqlite-backup-file.v2',source_observation=before,source_wal_observation=wal_before,
        backup_observation=observed,logical_inventory=expected,source_write_performed=False,restore_authorized=False)


class InstalledD12ManagedBackupV2:
    """Private supervisor component; no paths or evidence DTOs in its API."""
    def __init__(self,*,package_files,supervisor_journal,host_supervisor,authority_supervisor,storage_reader,inventory_manifest,maximum_file_bytes):
        from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
        from .d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2
        from .d12_installed_supervisor_v1 import InstalledD12SystemdSupervisorV1
        from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2
        if (type(package_files) is not InstalledPackageSelectionFilesV2 or type(supervisor_journal) is not InstalledPackageSupervisorJournalV2
                or any(type(s) is not InstalledD12SystemdSupervisorV1 for s in (host_supervisor,authority_supervisor))
                or not isinstance(storage_reader,InstalledC09StorageReaderV1) or type(inventory_manifest) is not InstallationFilesystemManifestV2
                or type(maximum_file_bytes) is not int or not 1<=maximum_file_bytes<=8*1024**3):raise TypeError('actual protected supervisor/storage/backup composition required')
        if host_supervisor.config.unit_name==authority_supervisor.config.unit_name:raise AuthorityUnavailable('independent Host and Authority units required')
        self.files=package_files;self.journal=supervisor_journal;self.host=host_supervisor;self.authority=authority_supervisor
        self.reader=storage_reader;self.inventory=inventory_manifest;self.maximum_file_bytes=maximum_file_bytes
        roots=[r for r in inventory_manifest.resources if r.kind=='controlled_backup' and 'controlled_backups' in r.content_coverage]
        if len(roots)!=1 or roots[0].namespace!=inventory_manifest.namespace:raise AuthorityUnavailable('one exact C09 managed backup registration required')
        from .c09_storage_control_v1 import _directory_path
        self.root=_directory_path(roots[0].path)
        self._require_composition()

    def _require_composition(self):
        from .linux_installation_security_v1 import read_installed_bytes_v1
        selected,cohort,config=self.files.read_selected_configuration_cohort_v2()
        installed=config['assets']['c09_storage_v1'];launch=config['deployment']
        raw=read_installed_bytes_v1(launch['inventory_path'],limit=1048576)
        if (hashlib.sha256(raw).hexdigest()!=launch['inventory_sha256']
                or json.loads(raw)!=json.loads(canonical_serialize(asdict(self.inventory)))
                or str(self.reader.lease.path)!=config['assets']['instance_lock']
                or any(str(getattr(self.reader,name))!=str(installed[field]) for name,field in
                    (('path','control_path'),('key_path','key_path'),('installation_id','installation_id'),
                     ('authority_id','authority_id'),('control_store_id','control_store_id'),('key_id','key_id')))
                or tuple(str(p) for p in self.reader._roots)!=tuple(installed['resource_roots'])
                or cohort.installation_id!=self.reader.installation_id):
            raise AuthorityUnavailable('backup composition differs from protected selected cohort')
        self.reader.lease.require_held()
        return selected

    def read_retired_rollback_source_v2(self,operation_id):
        from .d12_offline_package_source_v2 import read_retired_rollback_source_v2
        return read_retired_rollback_source_v2(self,operation_id)

    def read_retired_abort_source_v2(self,operation_id):
        from .d12_offline_package_source_v2 import read_retired_abort_source_v2
        return read_retired_abort_source_v2(self,operation_id)

    def read_managed_backup_v2(self,operation_id,*,backup_phase="forward"):
        intent=self.journal.read_verified_intent_v2(operation_id)
        found={}
        for receipt in self.journal.read_verified_receipts_v2(operation_id):
            for ref,_ in receipt.observation_refs:
                if ref==intent.accepted_original_ref:continue
                observed=self.journal.read_verified_observation_v2(operation_id,ref)
                if observed.kind=='managed_backup' and observed.body['backup_phase']==backup_phase:found[ref]=observed
        if len(found)!=1:raise AuthorityUnavailable('unique protected managed backup original absent')
        observed=next(iter(found.values()));value=decode_managed_backup_v2(observed.body)
        if value['accepted_original_digest']!=intent.digest or value['managed_backup_ref']!=intent.managed_backup_ref+('' if backup_phase=='forward' else ':rollback'):
            raise AuthorityUnavailable('registered backup original intent differs')
        for copy in value['copies'].values():
            before=copy['backup_observation'];path=Path(before['resolved_path'])
            if path.parent!=(self.root/operation_id if backup_phase=='forward' else self.root/operation_id/'rollback') or file_observation_v1(path)!=before:raise AuthorityUnavailable('registered backup bytes changed')
        return value

    def create_managed_backup_v2(self,operation_id):
        from .d12_package_observation_v2 import PackageSupervisorObservationV2
        from .c09_process_identity_v1 import require_process_retired_v1
        intent=self.journal.read_verified_intent_v2(operation_id)
        receipts=self.journal.read_verified_receipts_v2(operation_id)
        rollback=bool(receipts and any(r.stage=='rollback_retire_intent' for r in receipts))
        phase='rollback' if rollback else 'forward';retired_stage='rollback_retired' if rollback else 'retired'
        if not receipts:raise AuthorityUnavailable('actual both-unit retired receipt required before backup')
        if any(r.stage==('rollback_backup_ready' if rollback else 'backup_ready') for r in receipts):return self.read_managed_backup_v2(operation_id,backup_phase=phase)
        if receipts[-1].stage!=retired_stage:raise AuthorityUnavailable('actual both-unit retired receipt required before backup')
        observations={}
        for receipt in receipts:
            for ref,_ in receipt.observation_refs:
                if ref==intent.accepted_original_ref:continue
                original=self.journal.read_verified_observation_v2(operation_id,ref)
                if type(original) is not PackageSupervisorObservationV2:raise AuthorityUnavailable('actual signed supervisor observation required')
                observations[ref]=original
        retired_refs={ref for ref,_ in receipts[-1].observation_refs}
        sources=[o for ref,o in observations.items() if ref in retired_refs and o.kind=='backup_source' and o.body['backup_phase']==phase]
        if len(sources)!=1:raise AuthorityUnavailable('unique authenticated Authority backup source observation absent')
        source_observation=sources[0];source=decode_backup_source_v2(source_observation.body)
        if source['accepted_original_digest']!=intent.digest or source['operation_id']!=operation_id:raise AuthorityUnavailable('backup source exact intent differs')
        selected=self._require_composition()
        if selected.selection_digest!=source['selection_digest']:raise AuthorityUnavailable('package selection changed before backup')
        retire_intents=[r for r in receipts if r.stage==('rollback_retire_intent' if rollback else 'retire_intent')]
        if not retire_intents:raise AuthorityUnavailable('actual registered retirement intent absent')
        before_refs={ref for ref,_ in retire_intents[-1].observation_refs}
        retired=[]
        for role,supervisor in (('host',self.host),('authority',self.authority)):
            current=supervisor.read_current_host_state_v1()
            before=[o for ref,o in observations.items() if ref in before_refs and o.kind=='process' and o.body['service_role']==role]
            stopped=[o for ref,o in observations.items() if ref in retired_refs and o.kind=='process' and o.body['service_role']==role and o.body['process_original'] is None]
            if len(before)!=1 or len(stopped)!=1 or not current.stopped_and_drained:raise AuthorityUnavailable('actual original unit retirement differs')
            original=before[0].body['systemd'];observed=stopped[0].body['systemd']
            if any(original[k]!=asdict(current)[k] for k in ('unit_name','control_group','unit_fragment_sha256')) or observed!=json.loads(canonical_serialize(asdict(current))):raise AuthorityUnavailable('actual retired systemd identity differs')
            prior_process=before[0].body['process_original']
            if prior_process is not None:require_process_retired_v1(prior_process)
            elif (original['active_state'] not in {'inactive','failed'} or original['main_pid']!=0 or original['process_ids']):
                raise AuthorityUnavailable('initially absent process was not actually stopped and drained')
            retired.append(stopped[0].observation_ref)
        self.reader.lease.require_held()
        context=self.reader.read_verified_current_storage_v1();context.require_current('maintenance')
        storage={'pointer_version':context.pointer_version,'manifest_digest':context.manifest_digest,'storage_generation':context.storage_generation,
            'members':[{key:m[key] for key in ('role','resolved_path','device','file_id','incarnation_or_journal_id')} for m in context.manifest['members']]}
        if (storage!=source['storage_identity'] or context.stage not in {'READY','RELEASED'}
                or context.manifest['inventory_manifest_digest']!=self.inventory.manifest_digest
                or self.inventory.installation_id!=intent.installation_id or self.inventory.namespace!=source['namespace']):raise AuthorityUnavailable('backup actual selected C09 cohort differs')
        directory=self.root/operation_id if phase=='forward' else self.root/operation_id/'rollback'
        from .c09_storage_control_v1 import _directory_path
        if directory.exists():
            _directory_path(directory)
            if any(p.name not in {role+'.sqlite3' for role in ROLES} or not p.is_file() or p.is_symlink() for p in directory.iterdir()):raise AuthorityUnavailable('unregistered file in exact managed backup directory')
        else:
            directory.mkdir(mode=0o700)
            fd=os.open(directory.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
        copies={}
        for member in context.manifest['members']:
            role=member['role'];destination=directory/(role+'.sqlite3')
            copy=(reread_sqlite_backup_v2(Path(member['resolved_path']),destination,source['logical_inventories'][role],maximum_file_bytes=self.maximum_file_bytes,instance_lease=self.reader.lease) if destination.exists() else
                snapshot_sqlite_file_v2(member['resolved_path'],destination,maximum_bytes=self.maximum_file_bytes,maximum_rows=100000,instance_lease=self.reader.lease))
            if copy['logical_inventory']!=source['logical_inventories'][role]:raise AuthorityUnavailable('post-qualification original changed before snapshot: '+role)
            copies[role]=copy
        context.require_current('maintenance');self.reader.lease.require_held()
        if self.files.read_selected_package_v2()[0]!=selected:raise AuthorityUnavailable('package selection changed while copying')
        value=dict(schema=BACKUP_SCHEMA,operation_id=operation_id,accepted_original_digest=intent.digest,backup_phase=phase,
            installation_id=intent.installation_id,namespace=source['namespace'],managed_backup_ref=intent.managed_backup_ref+('' if phase=='forward' else ':rollback'),
            inventory_manifest_digest=self.inventory.manifest_digest,source_observation_ref=source_observation.observation_ref,
            source_observation_digest=source_observation.observation_digest,source_digest=source['source_digest'],storage_identity=storage,
            current_anchor=source['current_anchor'],owner_head=source['owner_head'],graph_metadata_digest=source['graph_metadata_digest'],
            reconciliation=source['reconciliation'],history_inventory=source['history_inventory'],copies=copies,retired_observation_refs=sorted(retired),
            restore_authorized=False,disposition='protected_nonrestorable')
        value['manifest_digest']=canonical_digest(value)
        return decode_managed_backup_v2(value)
