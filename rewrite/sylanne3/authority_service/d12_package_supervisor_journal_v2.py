"""Independent protected maintenance journal; records are not process readiness.

The concrete reader authenticates persisted originals in a fixed root-owned
journal with the pinned supervisor policy and protected signing key. Private
writers are used only by the external supervisor after actual Authority acceptance.
No method accepts process commands, package paths or an authorization boolean.
"""
from __future__ import annotations
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sqlite3

from .contract import AuthorityUnavailable
from .d12_package_maintenance_contract_v2 import (
    D12PackageMaintenanceIntentV2, D12PackageStageReceiptV2,
    package_intent_from_wire_v2, package_intent_to_wire_v2,
)
from .d12_package_files_v2 import _canonical, _sha, _protected_directory
from .linux_installation_security_v1 import read_installed_bytes_v1, opened_installed_file_v1

DDL = {
    'package_operations_v2':'CREATE TABLE package_operations_v2(operation_id TEXT PRIMARY KEY,intent_json TEXT NOT NULL,intent_digest TEXT NOT NULL,signature TEXT NOT NULL) STRICT',
    'package_stage_intents_v2':'CREATE TABLE package_stage_intents_v2(operation_id TEXT NOT NULL,stage_sequence INTEGER NOT NULL,stage TEXT NOT NULL,prior_receipt_digest TEXT,intent_json TEXT NOT NULL,intent_digest TEXT NOT NULL,signature TEXT NOT NULL,PRIMARY KEY(operation_id,stage_sequence)) STRICT',
    'package_stage_receipts_v2':'CREATE TABLE package_stage_receipts_v2(operation_id TEXT NOT NULL,stage_sequence INTEGER NOT NULL,stage_intent_digest TEXT NOT NULL,receipt_json TEXT NOT NULL,receipt_digest TEXT NOT NULL,signature TEXT NOT NULL,PRIMARY KEY(operation_id,stage_sequence)) STRICT',
    'package_observations_v2':'CREATE TABLE package_observations_v2(operation_id TEXT NOT NULL,observation_ref TEXT NOT NULL,original_json TEXT NOT NULL,original_digest TEXT NOT NULL,signature TEXT NOT NULL,PRIMARY KEY(operation_id,observation_ref)) STRICT',
}
PREFIX=b'sylanne3.d12.supervisor-journal.v2\0'
_FORWARD=('accepted','packages_verified','quiescing','retire_intent','retired','backup_ready',
    'compatible_no_data_migration','switch_intent','package_switched','authority_start_intent',
    'authority_bootstrap_ready','host_start_intent','bootstrap_ready','active')
_ROLLBACK=('rollback_retire_intent','rollback_retired','rollback_backup_ready','rollback_compatible_current_data','rollback_switch_intent',
    'rollback_package_switched','rollback_authority_start_intent','rollback_authority_bootstrap_ready','rollback_host_start_intent',
    'rollback_bootstrap_ready','rollback_complete')

_ABORT=('abort_intent','abort_retired','abort_authority_start_intent','abort_authority_bootstrap_ready',
    'abort_host_start_intent','abort_bootstrap_ready','abort_complete')

def _allowed_after(stage):
    if stage is None:return {'accepted'}
    if stage=='failed':return {'abort_intent','rollback_retire_intent'}
    allowed=set()
    for order in (_FORWARD,_ROLLBACK,_ABORT):
        if stage in order and order.index(stage)+1<len(order):allowed.add(order[order.index(stage)+1])
    if stage in _FORWARD[_FORWARD.index('package_switched'):-1]:allowed.add('rollback_retire_intent')
    if stage in _FORWARD[:_FORWARD.index('switch_intent')]:allowed.add('abort_intent')
    return allowed


def _signature(key, kind, raw):
    if key is None: raise AuthorityUnavailable('read-only supervisor verifier cannot sign originals')
    return key.sign(PREFIX+kind.encode()+b'\0'+raw).hex()


def _decode_receipt(raw):
    value=json.loads(raw)
    if type(value) is not dict or set(value)!=set(D12PackageStageReceiptV2.__dataclass_fields__):
        raise AuthorityUnavailable('supervisor receipt fields differ')
    if type(value['observation_refs']) is not list:
        raise AuthorityUnavailable('supervisor receipt observations differ')
    value['observation_refs']=tuple(tuple(row) for row in value['observation_refs'])
    receipt=D12PackageStageReceiptV2(**value)
    if _canonical(asdict(receipt)).decode()!=raw:
        raise AuthorityUnavailable('supervisor receipt bytes are not canonical')
    return receipt


def _install_schema(db):
    if db.in_transaction: raise AuthorityUnavailable('supervisor schema needs its independent transaction')
    db.execute('BEGIN IMMEDIATE')
    try:
        for name,ddl in DDL.items():
            prior=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()
            if prior is None:
                db.execute(ddl)
                for action in ('UPDATE','DELETE'):
                    db.execute(f"CREATE TRIGGER {name}_no_{action.lower()} BEFORE {action} ON {name} BEGIN SELECT RAISE(ABORT,'supervisor original immutable'); END")
            elif prior!=(ddl,): raise AuthorityUnavailable('supervisor journal schema differs')
        db.commit()
    except BaseException:
        db.rollback(); raise


class _SupervisorJournalKernelV2:
    """Internal data layer, not an externally callable accepted-intent issuer."""
    def __init__(self,db,key,policy_digest,*,verification_key=None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        if (not _sha(policy_digest) or key is not None and (type(key) is not bytes or len(key)!=32)
                or key is None and (type(verification_key) is not bytes or len(verification_key)!=32)):
            raise AuthorityUnavailable('supervisor protected key and policy required')
        self.key=Ed25519PrivateKey.from_private_bytes(key) if key is not None else None
        self.verifier=self.key.public_key() if self.key is not None else Ed25519PublicKey.from_public_bytes(verification_key)
        self.db,self.policy_digest=db,policy_digest
        self._schema()

    def _schema(self):
        tables={row[0]:row[1] for row in self.db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        if tables!=DDL: raise AuthorityUnavailable('closed supervisor journal schema differs')

    def _verify(self,kind,raw,signature):
        try:
            self.verifier.verify(bytes.fromhex(signature),PREFIX+kind.encode()+b'\0'+raw.encode())
        except Exception as exc:
            raise AuthorityUnavailable('supervisor original signature differs') from exc

    def read_intent(self,operation_id):
        self._schema()
        row=self.db.execute('SELECT intent_json,intent_digest,signature FROM package_operations_v2 WHERE operation_id=?',(operation_id,)).fetchone()
        if row is None: return None
        self._verify('acceptance',row[0],row[2])
        intent=package_intent_from_wire_v2(json.loads(row[0]))
        if (intent.operation_id!=operation_id or intent.accepted_original_digest!=row[1]
                or intent.supervisor_policy_digest!=self.policy_digest
                or _canonical(package_intent_to_wire_v2(intent)).decode()!=row[0]):
            raise AuthorityUnavailable('supervisor accepted identity or policy differs')
        return intent

    def _register_observed_acceptance(self,intent):
        if type(intent) is not D12PackageMaintenanceIntentV2 or intent.supervisor_policy_digest!=self.policy_digest:
            raise AuthorityUnavailable('actual accepted supervisor policy differs')
        raw=_canonical(package_intent_to_wire_v2(intent)).decode()
        with self.db:
            prior=self.read_intent(intent.operation_id)
            if prior is not None:
                if prior!=intent: raise AuthorityUnavailable('supervisor operation replay differs')
                return prior
            self.db.execute('INSERT INTO package_operations_v2 VALUES(?,?,?,?)',
                (intent.operation_id,raw,intent.accepted_original_digest,_signature(self.key,'acceptance',raw.encode())))
        return intent

    def read_observation(self,operation_id,reference):
        from .d12_package_observation_v2 import decode_supervisor_observation_v2
        if self.read_intent(operation_id) is None:raise AuthorityUnavailable('supervisor accepted operation absent')
        row=self.db.execute('SELECT original_json,original_digest,signature FROM package_observations_v2 WHERE operation_id=? AND observation_ref=?',(operation_id,reference)).fetchone()
        if row is None:raise AuthorityUnavailable('actual supervisor observation absent')
        self._verify('observation',row[0],row[2])
        value=decode_supervisor_observation_v2(json.loads(row[0]))
        if (value.operation_id!=operation_id or value.observation_ref!=reference or value.observation_digest!=row[1]
                or _canonical(asdict(value)).decode()!=row[0]):
            raise AuthorityUnavailable('supervisor observation identity differs')
        return value

    def _record_observation(self,value):
        from .d12_package_observation_v2 import PackageSupervisorObservationV2
        if type(value) is not PackageSupervisorObservationV2:raise TypeError('actual typed supervisor observation required')
        if self.read_intent(value.operation_id) is None:raise AuthorityUnavailable('supervisor accepted operation absent')
        with self.db:
            found=self.db.execute('SELECT 1 FROM package_observations_v2 WHERE operation_id=? AND observation_ref=?',(value.operation_id,value.observation_ref)).fetchone()
            if found:
                prior=self.read_observation(value.operation_id,value.observation_ref)
                if prior!=value:raise AuthorityUnavailable('supervisor observation replay differs')
                return prior
            raw=_canonical(asdict(value)).decode()
            self.db.execute('INSERT INTO package_observations_v2 VALUES(?,?,?,?,?)',
                (value.operation_id,value.observation_ref,raw,value.observation_digest,_signature(self.key,'observation',raw.encode())))
        return value

    def read_receipts(self,operation_id):
        intent=self.read_intent(operation_id)
        if intent is None: raise AuthorityUnavailable('supervisor operation not registered')
        result=[]; prior=None
        for row in self.db.execute('SELECT stage_sequence,stage_intent_digest,receipt_json,receipt_digest,signature FROM package_stage_receipts_v2 WHERE operation_id=? ORDER BY stage_sequence',(operation_id,)):
            sequence,stage_intent,raw,commitment,signature=row
            self._verify('receipt',raw,signature)
            receipt=_decode_receipt(raw)
            pending=self._read_stage_intent(operation_id,sequence)
            if (pending is None or pending['intent_digest']!=stage_intent
                    or receipt.stage not in {pending['stage'],'unknown','failed'}
                    or pending['accepted_original_digest']!=intent.accepted_original_digest
                    or pending['prior_receipt_digest']!=prior
                    or sequence!=len(result)+1 or receipt.stage_sequence!=sequence
                    or receipt.operation_id!=operation_id or receipt.accepted_original_digest!=intent.accepted_original_digest
                    or receipt.receipt_digest!=commitment or receipt.prior_receipt_digest!=prior):
                raise AuthorityUnavailable('supervisor receipt chain differs')
            if pending['stage'] not in _allowed_after(result[-1].stage if result else None):
                raise AuthorityUnavailable('supervisor receipt stage transition differs')
            self._verify_observation_refs(intent,receipt.observation_refs)
            if receipt.stage=='failed':self._verify_failed_resolution(intent,pending,receipt)
            result.append(receipt); prior=commitment
        return tuple(result)

    def _verify_observation_refs(self,intent,references):
        for reference,commitment in references:
            if (reference,commitment)==(intent.accepted_original_ref,intent.accepted_original_digest):
                continue
            observed=self.read_observation(intent.operation_id,reference)
            if observed.observation_digest!=commitment:
                raise AuthorityUnavailable('receipt observation commitment differs')

    def _verify_failed_resolution(self,intent,pending,receipt):
        excluded={'active','rollback_complete','abort_complete','switch_intent','package_switched','rollback_switch_intent','rollback_package_switched'}
        if pending['stage'] in excluded:raise AuthorityUnavailable('activation or pointer ambiguity cannot become a failed qualification')
        originals=[self.read_observation(intent.operation_id,ref) for ref,_ in receipt.observation_refs if ref!=intent.accepted_original_ref]
        resolutions=[o for o in originals if o.kind=='stage_failure_resolution']
        if len(resolutions)!=1:raise AuthorityUnavailable('failed stage needs one actual closed resolution')
        body=resolutions[0].body
        if body['requested_stage']!=pending['stage'] or body['pending_intent_digest']!=pending['intent_digest']:
            raise AuthorityUnavailable('failure resolution differs from exact pending intent')
        observed={o.observation_ref:o for o in originals}
        from .d12_package_files_v2 import decode_package_selection_v2
        selected=observed.get(body['selection_observation_ref'])
        if selected is None or selected.kind!='package_selection' or selected.observation_digest!=body['selection_observation_digest']:
            raise AuthorityUnavailable('failure selection observation absent')
        value=decode_package_selection_v2(selected.body)
        if body['side_effect_state']=='no_package_switch':
            if value.selection_digest!=intent.expected_selection_digest:raise AuthorityUnavailable('failed unswitched selection differs')
        elif (value.operation_id!=intent.operation_id or value.revision!=intent.expected_selection_revision+1
                or value.package_epoch!=intent.expected_package_epoch+1 or value.prior_selection_digest!=intent.expected_selection_digest
                or value.cohort_digest!=intent.candidate_cohort_digest):
            raise AuthorityUnavailable('failed candidate selection differs')
        roles=[]
        for ref,digest in body['process_observation_refs']:
            process=observed.get(ref)
            if process is None or process.kind!='process' or process.observation_digest!=digest:
                raise AuthorityUnavailable('failure actual process observation absent')
            roles.append(process.body['service_role'])
        if sorted(roles)!=['authority','host']:raise AuthorityUnavailable('failure both-unit observations required')

    def _read_stage_intent(self,operation_id,sequence):
        row=self.db.execute('SELECT stage,prior_receipt_digest,intent_json,intent_digest,signature FROM package_stage_intents_v2 WHERE operation_id=? AND stage_sequence=?',(operation_id,sequence)).fetchone()
        if row is None:return None
        self._verify('stage-intent',row[2],row[4])
        value=json.loads(row[2]); commitment=value.pop('intent_digest',None)
        if (set(value)!={'operation_id','stage_sequence','stage','prior_receipt_digest','accepted_original_digest','schema'}
                or value['schema']!='sylanne3.d12.supervisor-stage-intent.v2'
                or value['operation_id']!=operation_id or value['stage_sequence']!=sequence
                or value['stage']!=row[0] or value['prior_receipt_digest']!=row[1]
                or hashlib.sha256(_canonical(value)).hexdigest()!=commitment or commitment!=row[3]
                or _canonical({**value,'intent_digest':commitment}).decode()!=row[2]):
            raise AuthorityUnavailable('supervisor stage intent differs')
        return {**value,'intent_digest':commitment}

    def _prepare_stage(self,operation_id,stage):
        from .d12_package_maintenance_contract_v2 import STAGES
        if stage not in STAGES:raise AuthorityUnavailable('unknown supervisor stage')
        with self.db:
            intent=self.read_intent(operation_id)
            if intent is None:raise AuthorityUnavailable('accepted operation absent')
            receipts=self.read_receipts(operation_id)
            if receipts and receipts[-1].stage=='unknown':
                raise AuthorityUnavailable('unknown side effect requires original resolution, not another action')
            if stage not in _allowed_after(receipts[-1].stage if receipts else None):
                raise AuthorityUnavailable('supervisor stage skips required actual observations')
            sequence=len(receipts)+1; prior=receipts[-1].receipt_digest if receipts else None
            value=dict(schema='sylanne3.d12.supervisor-stage-intent.v2',operation_id=operation_id,
                stage_sequence=sequence,stage=stage,prior_receipt_digest=prior,accepted_original_digest=intent.accepted_original_digest)
            value['intent_digest']=hashlib.sha256(_canonical(value)).hexdigest()
            existing=self._read_stage_intent(operation_id,sequence)
            if existing is not None:
                if existing!=value:raise AuthorityUnavailable('pending original stage cannot be replaced')
                return existing
            raw=_canonical(value).decode()
            self.db.execute('INSERT INTO package_stage_intents_v2 VALUES(?,?,?,?,?,?,?)',
                (operation_id,sequence,stage,prior,raw,value['intent_digest'],_signature(self.key,'stage-intent',raw.encode())))
            return value

    def _record_observed_stage(self,receipt):
        if type(receipt) is not D12PackageStageReceiptV2:raise TypeError('actual typed observation receipt required')
        with self.db:
            receipts=self.read_receipts(receipt.operation_id)
            if receipt.stage_sequence<=len(receipts):
                if receipts[receipt.stage_sequence-1]!=receipt:raise AuthorityUnavailable('observed receipt replay differs')
                return receipt
            pending=self._read_stage_intent(receipt.operation_id,receipt.stage_sequence)
            intent=self.read_intent(receipt.operation_id)
            if (receipt.stage_sequence!=len(receipts)+1 or pending is None or receipt.stage not in {pending['stage'],'unknown','failed'}
                    or pending['prior_receipt_digest']!=receipt.prior_receipt_digest
                    or receipt.accepted_original_digest!=intent.accepted_original_digest):
                raise AuthorityUnavailable('observation has no exact durable original stage intent')
            self._verify_observation_refs(intent,receipt.observation_refs)
            if receipt.stage=='failed':self._verify_failed_resolution(intent,pending,receipt)
            raw=_canonical(asdict(receipt)).decode()
            self.db.execute('INSERT INTO package_stage_receipts_v2 VALUES(?,?,?,?,?,?)',
                (receipt.operation_id,receipt.stage_sequence,pending['intent_digest'],raw,receipt.receipt_digest,
                 _signature(self.key,'receipt',raw.encode())))
            return receipt


class InstalledPackageSupervisorJournalV2:
    """Concrete read-only root-protected original reader for Authority admission."""
    def __init__(self,*,control_directory,supervisor_policy_digest):
        self.directory=Path(control_directory)
        fd=_protected_directory(self.directory)
        import os
        os.close(fd)
        self.public_key=read_installed_bytes_v1(self.directory/'journal-public.key',limit=32)
        self.policy=supervisor_policy_digest

    def _read(self,operation_id,receipts,observation_ref=None,managed_namespace=None,pending_stage=False):
        path=self.directory/'supervisor.sqlite3'
        with opened_installed_file_v1(path,private=True,allowed_gid=0) as fd:
            import os
            before=os.fstat(fd)
            db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=5)
            try:
                after=path.stat(follow_symlinks=False)
                if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):
                    raise AuthorityUnavailable('supervisor journal selection changed')
                db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
                kernel=_SupervisorJournalKernelV2(db,None,self.policy,verification_key=self.public_key)
                if pending_stage:
                    intent=kernel.read_intent(operation_id)
                    if intent is None:raise AuthorityUnavailable('accepted original absent')
                    chain=kernel.read_receipts(operation_id)
                    sequences=tuple(row[0] for row in db.execute('SELECT stage_sequence FROM package_stage_intents_v2 WHERE operation_id=? ORDER BY stage_sequence',(operation_id,)))
                    completed=tuple(range(1,len(chain)+1))
                    if sequences==completed:return None
                    if sequences!=completed+(len(chain)+1,):raise AuthorityUnavailable('pending supervisor sequence has a gap or hidden stage')
                    pending=kernel._read_stage_intent(operation_id,len(chain)+1)
                    prior=chain[-1] if chain else None
                    if (pending['accepted_original_digest']!=intent.accepted_original_digest
                            or pending['prior_receipt_digest']!=(prior.receipt_digest if prior else None)
                            or pending['stage'] not in _allowed_after(prior.stage if prior else None)):
                        raise AuthorityUnavailable('pending supervisor stage original differs from verified chain')
                    return pending
                if managed_namespace is not None:
                    result=[]
                    operations=tuple(row[0] for row in db.execute('SELECT operation_id FROM package_operations_v2 ORDER BY operation_id'))
                    # Authenticate every observation before selecting by kind; a
                    # malformed or unrecognized registration cannot disappear.
                    for op in operations:
                        intent=kernel.read_intent(op)
                        kernel.read_receipts(op)
                        for reference, in db.execute('SELECT observation_ref FROM package_observations_v2 WHERE operation_id=? ORDER BY observation_ref',(op,)):
                            original=kernel.read_observation(op,reference)
                            if original.kind=='managed_backup':
                                if original.body['namespace'] not in intent.namespace_cohort:
                                    raise AuthorityUnavailable('backup registration namespace differs from accepted intent')
                                if (original.body['operation_id']!=op or original.body['accepted_original_digest']!=intent.digest
                                        or original.body['managed_backup_ref']!=intent.managed_backup_ref+(':rollback' if original.body['backup_phase']=='rollback' else '')):
                                    raise AuthorityUnavailable('backup registration differs from accepted operation')
                                if original.body['namespace']==managed_namespace:result.append((intent,original))
                    orphan=db.execute('SELECT 1 FROM package_observations_v2 o LEFT JOIN package_operations_v2 p USING(operation_id) WHERE p.operation_id IS NULL LIMIT 1').fetchone()
                    if orphan is not None:raise AuthorityUnavailable('orphan managed observation registration')
                    return tuple(result)
                if observation_ref is not None:return kernel.read_observation(operation_id,observation_ref)
                return kernel.read_receipts(operation_id) if receipts else kernel.read_intent(operation_id)
            finally:db.close()

    def read_verified_intent_v2(self,operation_id):return self._read(operation_id,False)
    def read_verified_receipts_v2(self,operation_id):return self._read(operation_id,True)
    def read_verified_observation_v2(self,operation_id,reference):return self._read(operation_id,False,reference)

    def read_verified_managed_backups_v2(self,namespace):
        from .contract import identifier
        identifier(namespace,'namespace')
        return self._read(None,False,managed_namespace=namespace)

    def read_verified_pending_stage_v2(self,operation_id):
        return self._read(operation_id,False,pending_stage=True)

    def require_installed_executor_ready_v2(self,operation_id,candidate_cohort,expected_selection_digest):
        """Static installation qualification, never a live executor receipt."""
        from uuid import UUID
        from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
        from .d12_fixed_supervisor_policy_v2 import read_fixed_supervisor_policy_v2
        from .d12_installed_supervisor_v1 import InstalledD12SystemdSupervisorV1
        from .d12_initial_selection_original_v1 import read_initial_selection_original_v1
        from .d12_configuration_cohort_v2 import read_verified_configuration_cohort_v2
        operation=UUID(operation_id)
        if operation.version!=4 or str(operation)!=operation_id:raise AuthorityUnavailable('exact maintenance operation required')
        files=InstalledPackageSelectionFilesV2(control_directory=self.directory)
        policy,host,authority=read_fixed_supervisor_policy_v2(files)
        if _digest_policy(policy)!=self.policy:raise AuthorityUnavailable('fixed journal policy differs')
        actual,cohort,_=files.read_selected_configuration_cohort_v2()
        installation,candidate=files.read_registered_cohort_v2(candidate_cohort.cohort_ref)
        if (actual.selection_digest!=expected_selection_digest or candidate!=candidate_cohort
                or installation!=actual.installation_id or candidate.identity_commitment!=cohort.identity_commitment):
            raise AuthorityUnavailable('static executor candidate registration differs')
        read_verified_configuration_cohort_v2(candidate)
        read_initial_selection_original_v1(package_files=files,supervisor_journal=self)
        # Authority inspects protected key availability but does not import the
        # independent supervisor's private signing material into its process.
        with opened_installed_file_v1(self.directory/'journal-signing.key',private=True,allowed_gid=0) as key_fd:
            import os
            if os.fstat(key_fd).st_size!=32:raise AuthorityUnavailable('installed supervisor signing key size differs')
        InstalledD12SystemdSupervisorV1(config=host)
        InstalledD12SystemdSupervisorV1(config=authority)
        return None


def _digest_policy(policy):
    return hashlib.sha256(_canonical(policy)).hexdigest()
