"""Actual installed peer admission and complete OS retirement in protected Control."""
from __future__ import annotations
import json
import os
from .contract import AuthorityUnavailable
from .c09_process_identity_v1 import read_process_identity_v1, require_process_retired_v1
from .c09_selected_history_v3 import _bounded, _read_one
from ..runtime_contracts import canonical_digest
from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2

_ADMISSION = 'sylanne3.c09.writer-peer-admission.v3'
_RETIREMENT = 'sylanne3.c09.writer-peer-retirement.v3'
_COMPLETION = 'sylanne3.c09.writer-peer-retirement-complete.v3'
_ACTIVATION = 'sylanne3.c09.writer-peer-registry-activation.v3'
_SDK_ACTIVATION = 'sylanne3.c09.writer-peer-registry-activation.controlled-sdk.v3'
_PENDING_START = 'sylanne3.c09.writer-peer-pending-start.v3'
_PENDING_COMPLETE = 'sylanne3.c09.writer-peer-pending-start-complete.v3'
_PENDING_COVERAGE = 'sylanne3.c09.writer-peer-pending-start-coverage.v3'
_PENDING_OLD_COHORT_COMPLETE='sylanne3.c09.writer-peer-pending-start-old-cohort-complete.v3'
_OLD_ROOT_PHYSICAL='sylanne3.c09.writer-peer-old-root-physical-retirement.v3'
_ROOT_PEER_RETIREMENT='sylanne3.c09.writer-peer-root-cohort-retirement.v3'
_VERIFY = object()
_PENDING_INDEX='CREATE INDEX c09_writer_peer_pending_generation_v3 ON c09_writer_peer_pending_starts_v3(manifest_digest,pointer_version,storage_generation,pending_start_digest)'
_ADMISSION_INDEX = 'CREATE INDEX c09_writer_peer_admissions_generation_v3 ON c09_writer_peer_admissions_v3(manifest_digest,pointer_version,storage_generation,admission_digest)'
DDLS_V3 = {
 'c09_writer_peer_old_root_retirements_v3':'CREATE TABLE c09_writer_peer_old_root_retirements_v3 (pending_start_digest TEXT PRIMARY KEY,retirement_json TEXT NOT NULL,retirement_digest TEXT NOT NULL UNIQUE,key_id TEXT NOT NULL,signature TEXT NOT NULL) STRICT',
 'c09_writer_peer_pending_starts_v3':'CREATE TABLE c09_writer_peer_pending_starts_v3 (pending_start_digest TEXT PRIMARY KEY,manifest_digest TEXT NOT NULL,pointer_version INTEGER NOT NULL,storage_generation INTEGER NOT NULL,peer_digest TEXT NOT NULL,start_sequence INTEGER NOT NULL CHECK(start_sequence>0),previous_pending_start_digest TEXT,pending_json TEXT NOT NULL,key_id TEXT NOT NULL,signature TEXT NOT NULL,UNIQUE(manifest_digest,pointer_version,storage_generation,peer_digest,start_sequence)) STRICT',
 'c09_writer_peer_pending_start_completions_v3':'CREATE TABLE c09_writer_peer_pending_start_completions_v3 (pending_start_digest TEXT PRIMARY KEY,manifest_digest TEXT NOT NULL,pointer_version INTEGER NOT NULL,storage_generation INTEGER NOT NULL,completion_json TEXT NOT NULL,completion_digest TEXT NOT NULL UNIQUE,key_id TEXT NOT NULL,signature TEXT NOT NULL) STRICT',
 'c09_writer_peer_pending_start_coverages_v3':'CREATE TABLE c09_writer_peer_pending_start_coverages_v3 (operation_id TEXT,manifest_digest TEXT NOT NULL,pointer_version INTEGER NOT NULL,storage_generation INTEGER NOT NULL,coverage_json TEXT NOT NULL,coverage_digest TEXT PRIMARY KEY,key_id TEXT NOT NULL,signature TEXT NOT NULL) STRICT',
 'c09_writer_peer_registry_activation_v3': 'CREATE TABLE c09_writer_peer_registry_activation_v3 (installation_id TEXT PRIMARY KEY,activation_json TEXT NOT NULL,activation_digest TEXT NOT NULL UNIQUE,key_id TEXT NOT NULL,signature TEXT NOT NULL) STRICT',
 'c09_writer_peer_admissions_v3': 'CREATE TABLE c09_writer_peer_admissions_v3 (admission_digest TEXT PRIMARY KEY,manifest_digest TEXT NOT NULL,pointer_version INTEGER NOT NULL,storage_generation INTEGER NOT NULL,admission_json TEXT NOT NULL,key_id TEXT NOT NULL,signature TEXT NOT NULL) STRICT',
 'c09_writer_peer_retirements_v3': 'CREATE TABLE c09_writer_peer_retirements_v3 (operation_id TEXT NOT NULL,admission_digest TEXT NOT NULL,retirement_json TEXT NOT NULL,retirement_digest TEXT NOT NULL UNIQUE,key_id TEXT NOT NULL,signature TEXT NOT NULL,PRIMARY KEY(operation_id,admission_digest)) STRICT',
 'c09_writer_peer_retirement_completions_v3': 'CREATE TABLE c09_writer_peer_retirement_completions_v3 (operation_id TEXT NOT NULL,manifest_digest TEXT NOT NULL,pointer_version INTEGER NOT NULL,storage_generation INTEGER NOT NULL,completion_json TEXT NOT NULL,completion_digest TEXT NOT NULL UNIQUE,key_id TEXT NOT NULL,signature TEXT NOT NULL,PRIMARY KEY(operation_id,manifest_digest,pointer_version,storage_generation)) STRICT',
}


def require_writer_peer_schema_v3(control, db):
    index = db.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name='c09_writer_peer_admissions_generation_v3'").fetchone()
    if index is None or index[0] != _ADMISSION_INDEX:
        raise AuthorityUnavailable('actual durable admission generation index differs')
    for table, ddl in DDLS_V3.items():
        row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        if row is None or row[0] != ddl:
            raise AuthorityUnavailable('actual writer peer protected schema differs')
        for action in ('UPDATE', 'DELETE'):
            row = db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (table + '_no_' + action.lower(),)).fetchone()
            if row is None or row[0] != control._immutable_ddl(table, action):
                raise AuthorityUnavailable('actual writer peer immutable trigger differs')


def install_writer_peer_gate_v3(control, gate):
    from .c09_storage_maintenance_v1 import InstalledC09WriterGateV1
    from .deployment_config import AuthorityDeploymentConfig
    if (type(gate) is not InstalledC09WriterGateV1 or gate.control is not control
            or type(gate._installed_config_v3) is not AuthorityDeploymentConfig
            or getattr(control, '_final_gate_v3', gate) is not gate):
        raise AuthorityUnavailable('actual installed config and writer gate required')
    previous = getattr(control, '_writer_peer_gate_v3', None)
    if previous is not None and previous is not gate:
        raise AuthorityUnavailable('actual durable writer gate is already registered')
    with control._resource_sql_quantum_v3() as meter:
        with control._db(write=True) as db:
            control._current(db)
            activation_original=require_writer_peer_registry_activation_v3(control, gate, db, meter)
            for table, ddl in DDLS_V3.items():
                present = _read_one(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,), meter)
                if present is None:
                    meter.write(db, ddl)
                    for action in ('UPDATE', 'DELETE'):
                        meter.write(db, control._immutable_ddl(table, action))
            if _read_one(db, "SELECT 1 FROM sqlite_master WHERE type='index' AND name='c09_writer_peer_admissions_generation_v3'", (), meter) is None:
                meter.write(db, _ADMISSION_INDEX)
            if _read_one(db,"SELECT 1 FROM sqlite_master WHERE type='index' AND name='c09_writer_peer_pending_generation_v3'",(),meter) is None:
                meter.write(db,_PENDING_INDEX)
            require_writer_peer_schema_v3(control, db)
    control._writer_peer_gate_v3 = gate
    control._writer_peer_activation_v3 = activation_original


def _require_gate(control, gate):
    from .c09_storage_maintenance_v1 import InstalledC09WriterGateV1
    if type(gate) is not InstalledC09WriterGateV1 or gate.control is not control or control._writer_peer_gate_v3 is not gate:
        raise AuthorityUnavailable('actual registered durable writer gate required')
    control.lease.require_held()


def retain_writer_peer_admission_v3(control, gate, *, peer, process_incarnation, process_original, context):
    _require_gate(control, gate)
    config = gate._installed_config_v3
    if (type(peer) is not tuple or len(peer) != 2 or peer not in config.installations_v2
            or config.installations_v2[peer].installation_id != control.installation_id
            or type(process_incarnation) is not str or not process_incarnation
            or read_process_identity_v1(process_original['pid']) != process_original):
        raise AuthorityUnavailable('actual installed peer profile or OS process identity differs')
    activation=control._writer_peer_activation_v3
    if activation['schema']==_SDK_ACTIVATION:
        if (list(peer)!=activation['activation_basis']['sdk_peer_descriptor']
                or process_original!=read_process_identity_v1(os.getpid())):
            raise AuthorityUnavailable('controlled SDK admission requires its sole actual Authority process and fixed peer role')
    namespace = context.manifest['cohort_namespaces'][0]
    if not any(key[:2] == peer and value == namespace for key, value in config.namespace_bindings_v2.items()):
        raise AuthorityUnavailable('actual peer profile has no installed selected namespace binding')
    with control._resource_sql_quantum_v3() as meter:
        if activation['schema']==_SDK_ACTIVATION:gate.require_registry_activation_domain_v3(activation,meter=meter)
        context.require_current('business')
        with gate._condition:
            if gate._operation is not None:
                raise AuthorityUnavailable('actual peer admission is revoked for maintenance')
            authority = read_process_identity_v1(os.getpid())
            if (authority is None or read_process_identity_v1(process_original['pid']) != process_original
                    or activation['schema']==_SDK_ACTIVATION and process_original!=authority):
                raise AuthorityUnavailable('actual peer or Authority process changed during admission')
            original = control.sign_original_v1(_ADMISSION, dict(schema=_ADMISSION,
                authority_id=control.authority_id, installation_id=control.installation_id, namespace=namespace,
                peer=list(peer), process_incarnation=process_incarnation, process_original=process_original,
                authority_process_original=authority, manifest_digest=context.manifest_digest,
                pointer_version=context.pointer_version, storage_generation=context.storage_generation), 'admission_digest')
            with control._db(write=True) as db:
                current = control._current(db)
                if (current['stage'] not in {'READY', 'RELEASED'} or current['pointer_version'] != context.pointer_version
                        or current['current_manifest_digest'] != context.manifest_digest):
                    raise AuthorityUnavailable('actual selected peer admission pointer CAS changed')
                require_writer_peer_schema_v3(control, db)
                row = _bounded(db, meter).execute('SELECT admission_json FROM c09_writer_peer_admissions_v3 WHERE admission_digest=?',
                    (original['admission_digest'],)).fetchone()
                from .c09_storage_control_v1 import canonical
                wire = canonical(original)
                if row is not None:
                    if row[0] != wire:
                        raise AuthorityUnavailable('actual durable peer admission identity changed')
                    return original
                meter.write_row(db, 'c09_writer_peer_admissions_v3', ('admission_digest', 'manifest_digest', 'pointer_version',
                    'storage_generation', 'admission_json', 'key_id', 'signature'),
                    (original['admission_digest'], context.manifest_digest, context.pointer_version, context.storage_generation,
                     wire, control.key_id, original['signature']))
            return original


class VerifiedPeerRetirementCoverageV3:
    def __init__(self, token, progress, original):
        if token is not _VERIFY or not progress.complete:
            raise AuthorityUnavailable('actual complete durable peer retirement issuer required')
        self._issuer, self.progress, self.original = token, progress, original
        self.operation_id = progress.operation_id
    def require_current(self, *, meter):
        if self._issuer is not _VERIFY:
            raise AuthorityUnavailable('actual peer retirement issuer differs')
        self.progress.require_current(meter)
        return self


class InstalledPeerRetirementCoverageV3:
    def __init__(self, control, gate, operation_id, context):
        self.control, self.gate, self.operation_id, self.context = control, gate, operation_id, context
        self.after, self.count, self.root = '', 0, canonical_digest((_COMPLETION, operation_id, context.manifest_digest, context.pointer_version))
        self.complete, self.result, self.failed = False, None, None
        self.pending_start_reader=self.pending_start_proof=None
    def require_current(self, meter):
        _require_gate(self.control, self.gate)
        m = self.gate._installed_maintenance_v3
        if m.gate is not self.gate or m.control is not self.control or self.gate._operation != self.operation_id:
            raise AuthorityUnavailable('actual current accepted maintenance gate required for peer retirement')
        m.core._require(m.credential, 'delete', m.closure.namespace)
        with self.control._db() as db:
            current = self.control._current(db)
        if (current['pointer_version'], current['current_manifest_digest']) != (self.context.pointer_version, self.context.manifest_digest):
            raise AuthorityUnavailable('actual peer retirement selected generation changed')
        if current['stage'] in {'READY', 'RELEASED'}:
            from .erasure_closure_inventory import CleanupRunV2, _TABLES
            with m.core._tx() as db:
                run = m.closure._read_record(_bounded(db, meter), _TABLES[1], self.operation_id, CleanupRunV2)
                if run is None:
                    raise AuthorityUnavailable('actual accepted run absent before INTENT peer retirement')
                m.closure._accepted_locked(db, run, m.subject)
        elif current['active_operation_id'] != self.operation_id or current['stage'] not in {'INTENT', 'PREPARED'}:
            raise AuthorityUnavailable('actual old selected maintenance operation differs for peer retirement')
    def advance(self, meter):
        if self.failed is not None:
            raise AuthorityUnavailable(self.failed)
        try:
            return self._advance(meter)
        except BaseException as exc:
            self.failed = str(exc)
            raise
    def _advance(self, meter):
        control, context = self.control, self.context
        self.require_current(meter)
        if self.result is not None:
            return self.result.require_current(meter=meter)
        if self.pending_start_proof is None:
            if self.pending_start_reader is None:
                self.pending_start_reader=InstalledWriterPeerPendingStartReadV3(control,self.gate,self.operation_id,context)
            result=self.pending_start_reader.advance(meter)
            if type(result) is VerifiedWriterPeerPendingStartCoverageV3:
                self.pending_start_proof=result.require_current(meter=meter)
                return dict(status='progress',phase='writer_peer_pending_start_complete')
            return result
        with control._db() as db:
            require_writer_peer_schema_v3(control, db)
            row = _bounded(db, meter).execute('SELECT admission_digest,admission_json FROM c09_writer_peer_admissions_v3 '
                'WHERE manifest_digest=? AND pointer_version=? AND storage_generation=? AND admission_digest>? '
                'ORDER BY admission_digest COLLATE BINARY LIMIT 1',
                (context.manifest_digest, context.pointer_version, context.storage_generation, self.after)).fetchone()
        if row is not None:
            admission = json.loads(row[1]);control.verify_original_v1(admission, 'admission_digest')
            if (admission['admission_digest'] != row[0] or admission['manifest_digest'] != context.manifest_digest
                    or admission['pointer_version'] != context.pointer_version or admission['storage_generation'] != context.storage_generation
                    or admission['installation_id'] != control.installation_id or admission['authority_id'] != control.authority_id):
                raise AuthorityUnavailable('actual peer retirement admission original scope differs')
            with control._db() as db:
                stored_retirement=_bounded(db,meter).execute('SELECT retirement_json FROM c09_writer_peer_retirements_v3 WHERE operation_id=? AND admission_digest=?',
                    (self.operation_id,row[0])).fetchone()
            if stored_retirement is not None:
                retained=json.loads(stored_retirement[0])
                if retained.get('schema')==_ROOT_PEER_RETIREMENT:
                    _verify_root_cohort_peer_retirement_v3(control,self.operation_id,admission,retained,meter)
                    self.after,self.count=row[0],self.count+1
                    self.root=canonical_digest((self.root,self.count,row[0],retained['retirement_digest']))
                    return dict(status='progress',phase='writer_peer_old_root_retirement',peer_count=self.count)
            if read_process_identity_v1(admission['process_original']['pid']) == admission['process_original']:
                return dict(status='progress', phase='writer_peer_waiting_retirement',
                    admission_digest=row[0], process_original=admission['process_original'])
            observation = require_process_retired_v1(admission['process_original'])
            retirement = control.sign_original_v1(_RETIREMENT, dict(schema=_RETIREMENT, authority_id=control.authority_id,
                installation_id=control.installation_id, namespace=admission['namespace'], maintenance_operation_id=self.operation_id,
                admission_digest=row[0], manifest_digest=context.manifest_digest, pointer_version=context.pointer_version,
                storage_generation=context.storage_generation, original_process=admission['process_original'], observation=observation,
                observer_process_original=read_process_identity_v1(os.getpid())), 'retirement_digest')
            with control._db(write=True) as db:
                self.require_current(meter)
                prior = _bounded(db, meter).execute('SELECT retirement_json FROM c09_writer_peer_retirements_v3 WHERE operation_id=? AND admission_digest=?',
                    (self.operation_id, row[0])).fetchone()
                from .c09_storage_control_v1 import canonical
                if prior is None:
                    meter.write_row(db, 'c09_writer_peer_retirements_v3', ('operation_id', 'admission_digest', 'retirement_json', 'retirement_digest', 'key_id', 'signature'),
                        (self.operation_id, row[0], canonical(retirement), retirement['retirement_digest'], control.key_id, retirement['signature']))
                else:
                    retained = json.loads(prior[0]);control.verify_original_v1(retained, 'retirement_digest')
                    if (retained['admission_digest'] != row[0] or retained['original_process'] != admission['process_original']
                            or retained['maintenance_operation_id'] != self.operation_id):
                        raise AuthorityUnavailable('actual durable peer retirement changed')
                    retirement = retained
            self.after, self.count = row[0], self.count + 1
            self.root = canonical_digest((self.root, self.count, row[0], retirement['retirement_digest']))
            return dict(status='progress', phase='writer_peer_retirement', peer_count=self.count)
        original = control.sign_original_v1(_COMPLETION, dict(schema=_COMPLETION,
            authority_id=control.authority_id, installation_id=control.installation_id,
            namespace=context.manifest['cohort_namespaces'][0], maintenance_operation_id=self.operation_id,
            manifest_digest=context.manifest_digest, pointer_version=context.pointer_version, storage_generation=context.storage_generation,
            admission_count=self.count, retirement_root=self.root, last_admission_digest=self.after, complete=True,
            pending_start_coverage_original_digest=self.pending_start_proof.original['coverage_digest'],
            pending_start_count=self.pending_start_proof.original['pending_start_count'],
            pending_start_root=self.pending_start_proof.original['coverage_root'],
            pending_start_eof_digest=self.pending_start_proof.original['eof_digest'],
            eof_digest=canonical_digest((_COMPLETION, context.manifest_digest, context.pointer_version, context.storage_generation, self.count, self.after, self.root))),
            'completion_digest')
        with control._db(write=True) as db:
            self.require_current(meter)
            prior = _bounded(db, meter).execute('SELECT completion_json FROM c09_writer_peer_retirement_completions_v3 '
                'WHERE operation_id=? AND manifest_digest=? AND pointer_version=? AND storage_generation=?',
                (self.operation_id, context.manifest_digest, context.pointer_version, context.storage_generation)).fetchone()
            from .c09_storage_control_v1 import canonical
            if prior is None:
                meter.write_row(db, 'c09_writer_peer_retirement_completions_v3', ('operation_id', 'manifest_digest', 'pointer_version',
                    'storage_generation', 'completion_json', 'completion_digest', 'key_id', 'signature'),
                    (self.operation_id, context.manifest_digest, context.pointer_version, context.storage_generation,
                     canonical(original), original['completion_digest'], control.key_id, original['signature']))
            elif prior[0] != canonical(original):
                raise AuthorityUnavailable('actual complete peer retirement EOF changed')
        self.complete = True
        self.result = VerifiedPeerRetirementCoverageV3(_VERIFY, self, original)
        return self.result


def advance_writer_peer_retirement_coverage_v3(control, gate, *, operation_id):
    _require_gate(control, gate)
    with control._resource_sql_quantum_v3() as meter:
        context = gate._current_context_v3(action='maintenance',verify_files=False)
        progress = getattr(gate, '_durable_peer_retirement_progress_v3', None)
        if progress is None:
            progress = InstalledPeerRetirementCoverageV3(control, gate, operation_id, context)
            gate._durable_peer_retirement_progress_v3 = progress
        elif progress.operation_id != operation_id:
            raise AuthorityUnavailable('actual durable peer retirement already belongs to another operation')
        return progress.advance(meter)


class VerifiedPreparedPeerRetirementCoverageV3:
    """Cold use of a signed old-selection EOF; it never reconstructs live peers."""
    def __init__(self, token, control, context, original):
        if token is not _VERIFY:
            raise AuthorityUnavailable('actual cold prepared peer retirement issuer required')
        self._issuer, self.control, self.context, self.original = token, control, context, original
        self.operation_id = original['maintenance_operation_id']
    def require_current(self, *, meter):
        current = self.control.read_verified_current_storage_v3(meter=meter)
        if (current.pointer_version, current.manifest_digest, current.prepared_original['operation_id']) != (
                self.context.pointer_version, self.context.manifest_digest, self.operation_id):
            raise AuthorityUnavailable('actual cold peer retirement selected context expired')
        self.control.verify_original_v1(self.original, 'completion_digest')
        require_peer_completion_pending_coverage_v3(self.control,self.original,meter=meter)
        return self


def read_writer_peer_retirement_coverage_for_prepared_v3(control, gate, *, operation_id, context):
    _require_gate(control, gate)
    with control._resource_sql_quantum_v3() as meter:
        current = control._c09_control_chain_proof_v2
        with control._db() as db:
            selected = current.require_current(db, meter)
            intent = current.state.get('maintenance_intent')
            prepared = context.prepared_original
            if (selected['stage'] not in {'SWITCHED', 'CLEANED'} or selected['active_operation_id'] != operation_id
                    or prepared['operation_id'] != operation_id or intent is None
                    or intent['old_manifest_digest'] != prepared['old_manifest_digest']
                    or intent['expected_pointer_version'] != prepared['expected_pointer_version']
                    or intent.get('quiescence_digest') != prepared['writer_freeze_digest']
                    or intent.get('schema') != 'sylanne3.c09.writer_quiescence.v3'
                    or 'writer_peer_retirement_complete_original_digest' not in intent):
                raise AuthorityUnavailable('actual new selected PREPARED lacks its signed old peer retirement basis')
            row = _bounded(db, meter).execute('SELECT completion_json FROM c09_writer_peer_retirement_completions_v3 '
                'WHERE operation_id=? AND completion_digest=?',
                (operation_id, intent['writer_peer_retirement_complete_original_digest'])).fetchone()
            if row is None:
                raise AuthorityUnavailable('actual prepared old peer retirement EOF original absent')
            original = json.loads(row[0]);control.verify_original_v1(original, 'completion_digest')
            old = control._read_manifest(_bounded(db, meter), prepared['old_manifest_digest'])
            if (original['maintenance_operation_id'] != operation_id or original['manifest_digest'] != old['manifest_digest']
                    or original['pointer_version'] != prepared['expected_pointer_version']
                    or original['storage_generation'] != old['generation'] or original['complete'] is not True
                    or original['installation_id'] != control.installation_id or original['authority_id'] != control.authority_id
                    or original['admission_count'] != intent['writer_peer_retirement_count']
                    or original['retirement_root'] != intent['writer_peer_retirement_root']):
                raise AuthorityUnavailable('actual prepared peer retirement old-generation signature or EOF scope differs')
            require_peer_completion_pending_coverage_v3(control,original,meter=meter)
        proof = VerifiedPreparedPeerRetirementCoverageV3(_VERIFY, control, context, original)
        proof.require_current(meter=meter)
        return proof


def require_writer_quiescence_original_v3(control, original, *, meter, operation_id=None):
    """The compact V3 domain binds the complete old-generation durable census."""
    expected = {'schema','installation_id','operation_id','pointer_version','storage_generation',
        'revoked_admission_epoch','active_writers','exited_workers','retired_worker_originals','retired_peer_originals',
        'writer_peer_retirement_complete_original_digest','writer_peer_retirement_count','writer_peer_retirement_root',
        'authority_process_original','lock_path','lock_process_id','quiescence_digest','key_id','signature'}
    if (set(original) != expected or original['schema'] != 'sylanne3.c09.writer_quiescence.v3'
            or original['installation_id'] != control.installation_id or original['active_writers'] != 0
            or operation_id is not None and original['operation_id'] != operation_id):
        raise AuthorityUnavailable('actual exact V3 writer quiescence original required')
    control.verify_original_v1(original,'quiescence_digest')
    with control._db() as db:
        row = _bounded(db,meter).execute('SELECT completion_json FROM c09_writer_peer_retirement_completions_v3 '
            'WHERE operation_id=? AND completion_digest=?',
            (original['operation_id'],original['writer_peer_retirement_complete_original_digest'])).fetchone()
    if row is None:raise AuthorityUnavailable('actual compact V3 quiescence has no complete durable peer original')
    completion=json.loads(row[0]);control.verify_original_v1(completion,'completion_digest')
    if (completion['schema'] != _COMPLETION or completion['complete'] is not True
            or completion['authority_id'] != control.authority_id or completion['installation_id'] != control.installation_id
            or completion['maintenance_operation_id'] != original['operation_id']
            or completion['pointer_version'] != original['pointer_version'] or completion['storage_generation'] != original['storage_generation']
            or completion['admission_count'] != original['writer_peer_retirement_count']
            or completion['retirement_root'] != original['writer_peer_retirement_root']):
        raise AuthorityUnavailable('actual V3 quiescence differs from its signed complete durable coverage')
    require_peer_completion_pending_coverage_v3(control,completion,meter=meter)
    return completion


def retain_writer_peer_registry_activation_v3(control, gate, *, activation):
    from .c09_storage_maintenance_v1 import VerifiedInstalledPeerRegistryActivationV3,InstalledC09WriterGateV1
    from .deployment_config import AuthorityDeploymentConfig
    if (type(activation) is not VerifiedInstalledPeerRegistryActivationV3
            or type(gate) is not InstalledC09WriterGateV1 or gate.control is not control
            or type(gate._installed_config_v3) is not AuthorityDeploymentConfig):
        raise AuthorityUnavailable('actual completed installed peer process census activation required')
    with control._resource_sql_quantum_v3() as meter:
        activation.require_current(control=control,gate=gate,meter=meter)
        summary=activation.summary
        expected={'schema','mode','installation_inventory_digest','process_count','process_root','process_eof_digest',
            'legacy_quiescence_count','legacy_quiescence_root','legacy_quiescence_eof_digest'}
        if summary['mode']=='controlled_sdk_genesis':
            expected|={'controlled_sdk_original_digest','sdk_peer_descriptor','authority_process_original','closed_service_original_root','closed_service_original_count',
                'controlled_sdk_root_census_original','controlled_sdk_root_census_original_digest'}
        else:expected|={'root_channel_nonce','supervisor_spec_digest','root_process_original'}
        if set(summary)!=expected or summary['schema']!='sylanne3.c09.writer-peer-registry-activation-input.v3':
            raise AuthorityUnavailable('actual peer registry activation producer schema differs')
        with control._db(write=True) as db:
            current=control._c09_control_chain_proof_v2.require_current(db,meter)
            manifest=control._read_manifest(_bounded(db,meter),current['current_manifest_digest'])
            if summary['installation_inventory_digest']!=manifest['inventory_manifest_digest']:
                raise AuthorityUnavailable('actual activation process census belongs to another installation inventory')
            if summary['mode']=='genesis':
                if (manifest['generation']!=0 or current['pointer_version']!=0 or current['last_event_seq']!=0
                        or current['stage']!='READY' or summary['process_count']!=0 or summary['legacy_quiescence_count']!=0):
                    raise AuthorityUnavailable('actual registry genesis requires the installed prehost genesis census')
            elif summary['mode']=='controlled_sdk_genesis':
                if (manifest['generation']!=0 or current['pointer_version']!=0 or current['last_event_seq']!=0
                        or current['stage']!='READY' or summary['process_count']!=1 or summary['legacy_quiescence_count']!=0
                        or summary['authority_process_original']!=read_process_identity_v1(os.getpid())
                        or summary['closed_service_original_count']<1 or len(summary['sdk_peer_descriptor'])!=2):
                    raise AuthorityUnavailable('controlled SDK registry requires the sole actual Authority and closed service originals')
            elif summary['mode']=='legacy_migration':
                if current['stage']!='RELEASED' or summary['legacy_quiescence_count']==0:
                    raise AuthorityUnavailable('actual existing peer registry migration requires complete signed retirement history')
            else:raise AuthorityUnavailable('actual peer registry activation mode is unregistered')
            if summary['mode']=='controlled_sdk_genesis':
                _require_controlled_sdk_root_census_v3(summary,control,manifest,current,gate=gate,activation=activation)
            domain=_SDK_ACTIVATION if summary['mode']=='controlled_sdk_genesis' else _ACTIVATION
            original=control.sign_original_v1(domain,dict(schema=domain,
                authority_id=control.authority_id,installation_id=control.installation_id,control_store_id=control.control_store_id,
                namespace=manifest['cohort_namespaces'][0],manifest_digest=manifest['manifest_digest'],pointer_version=current['pointer_version'],
                storage_generation=manifest['generation'],authority_process_original=read_process_identity_v1(os.getpid()),
                activation_basis=summary,pending_start_protocol=_PENDING_START),'activation_digest')
            table='c09_writer_peer_registry_activation_v3'
            present=_read_one(db,"SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,),meter)
            if present is None:
                meter.write(db,DDLS_V3[table])
                for action in ('UPDATE','DELETE'):meter.write(db,control._immutable_ddl(table,action))
            elif present!=(DDLS_V3[table],):raise AuthorityUnavailable('actual activation protected schema differs')
            row=_bounded(db,meter).execute('SELECT activation_json FROM '+table+' WHERE installation_id=?',(control.installation_id,)).fetchone()
            from .c09_storage_control_v1 import canonical
            wire=canonical(original)
            if row is not None:
                if row!=(wire,):raise AuthorityUnavailable('actual peer registry activation is already sealed by another original')
            else:
                meter.write_row(db,table,('installation_id','activation_json','activation_digest','key_id','signature'),
                    (control.installation_id,wire,original['activation_digest'],control.key_id,original['signature']))
            return original


def require_writer_peer_registry_activation_v3(control, gate, db, meter):
    present=_read_one(db,"SELECT sql FROM sqlite_master WHERE type='table' AND name='c09_writer_peer_registry_activation_v3'",(),meter)
    if present != (DDLS_V3['c09_writer_peer_registry_activation_v3'],):
        raise AuthorityUnavailable('actual peer registry lacks an installed complete process census activation')
    for action in ('UPDATE','DELETE'):
        row=_read_one(db,"SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",('c09_writer_peer_registry_activation_v3_no_'+action.lower(),),meter)
        if row!=(control._immutable_ddl('c09_writer_peer_registry_activation_v3',action),):
            raise AuthorityUnavailable('actual peer registry activation is not immutable')
    row=_bounded(db,meter).execute('SELECT activation_json FROM c09_writer_peer_registry_activation_v3 WHERE installation_id=?',
        (control.installation_id,)).fetchone()
    if row is None:raise AuthorityUnavailable('actual complete peer registry activation original is absent')
    original=json.loads(row[0]);control.verify_original_v1(original,'activation_digest')
    if (original['schema'] not in {_ACTIVATION,_SDK_ACTIVATION} or original['authority_id']!=control.authority_id
            or original['installation_id']!=control.installation_id or original['control_store_id']!=control.control_store_id
            or original.get('pending_start_protocol')!=_PENDING_START):
        raise AuthorityUnavailable('actual peer registry activation belongs to another installed Control')
    if original['schema']==_SDK_ACTIVATION and gate is not None:
        gate.require_registry_activation_domain_v3(original,meter=meter)
    current=control._c09_control_chain_proof_v2.require_current(db,meter)
    manifest=control._read_manifest(_bounded(db,meter),original['manifest_digest'])
    if (current['pointer_version']<original['pointer_version'] or manifest['generation']!=original['storage_generation']
            or manifest['cohort_namespaces']!=[original['namespace']]
            or manifest['inventory_manifest_digest']!=original['activation_basis']['installation_inventory_digest']):
        raise AuthorityUnavailable('actual peer registry activation source cut or installation inventory differs')
    return original


class VerifiedWriterPeerRegistryActivationReadV3:
    """Protected signed registry admission metadata, without a new activation grant."""
    def __init__(self, token, control, original):
        if token is not _VERIFY:raise AuthorityUnavailable('actual protected registry activation read issuer required')
        self._issuer,self.control,self.original=token,control,original
    def require_current(self, *, meter):
        if self._issuer is not _VERIFY:raise AuthorityUnavailable('actual protected registry activation read issuer differs')
        with self.control._db() as db:
            original=require_writer_peer_registry_activation_v3(self.control,None,db,meter)
        if original!=self.original:raise AuthorityUnavailable('actual immutable registry activation changed')
        return self


def read_writer_peer_registry_activation_v3(control):
    with control._resource_sql_quantum_v3() as meter:
        with control._db() as db:
            control._c09_control_chain_proof_v2.require_current(db,meter)
            present=_read_one(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='c09_writer_peer_registry_activation_v3'",(),meter)
            if present is None:
                if _read_one(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='c09_writer_peer_admissions_v3'",(),meter) is not None:
                    raise AuthorityUnavailable('actual legacy peer registry has no qualified activation original')
                return None
            original=require_writer_peer_registry_activation_v3(control,None,db,meter)
        return VerifiedWriterPeerRegistryActivationReadV3(_VERIFY,control,original)


def verify_writer_peer_registry_activation_for_host_start_v3(original,*,authority_id,installation_id,namespace,
        supervisor_spec_digest,key_id,key_bytes):
    """Root launcher pure signature/scope check; current admission remains its actual Authority guard."""
    import hmac
    from .c09_storage_control_v1 import digest
    fields={'schema','authority_id','installation_id','control_store_id','namespace','manifest_digest','pointer_version',
        'storage_generation','authority_process_original','activation_basis','pending_start_protocol','activation_digest','key_id','signature'}
    if (set(original)!=fields or original['schema']!=_ACTIVATION or original['authority_id']!=authority_id
            or original['installation_id']!=installation_id or original['namespace']!=namespace or original['key_id']!=key_id
            or original['pending_start_protocol']!=_PENDING_START):
        raise AuthorityUnavailable('production Host requires its exact installed peer registry activation domain')
    basis=original['activation_basis']
    if (basis['mode'] not in ('genesis','legacy_migration') or basis['supervisor_spec_digest']!=supervisor_spec_digest
            or type(basis['root_channel_nonce']) is not str or not basis['root_channel_nonce']
            or type(basis['root_process_original']) is not dict or basis['root_process_original'].get('pid')!=1):
        raise AuthorityUnavailable('production Host activation differs from its actual Root supervisor scope')
    actual=digest({name:value for name,value in original.items() if name not in {'activation_digest','signature'}})
    signature=hmac.new(key_bytes,(_ACTIVATION+'\n'+actual).encode(),'sha256').hexdigest()
    if actual!=original['activation_digest'] or not hmac.compare_digest(signature,original['signature']):
        raise AuthorityUnavailable('production Host peer registry activation HMAC differs')
    return original


def read_writer_peer_registry_host_start_original_v3(control,gate,*,supervisor_spec_digest):
    _require_gate(control,gate)
    with control._resource_sql_quantum_v3() as meter:
        with gate._condition:
            if gate._operation is not None:
                raise AuthorityUnavailable('actual Host start is revoked during maintenance')
            with control._db() as db:
                activation=require_writer_peer_registry_activation_v3(control,gate,db,meter)
            if (activation['schema']!=_ACTIVATION
                    or activation['activation_basis']['supervisor_spec_digest']!=supervisor_spec_digest):
                raise AuthorityUnavailable('production Host start requires its actual Root supervisor activation scope')
            context=gate._current_context_v3(action='business',verify_files=False)
            context.require_current('business')
            if context.stage!='RELEASED' and not (context.stage=='READY' and context.storage_generation==0 and context.pointer_version==0):
                raise AuthorityUnavailable('actual selected Host start business stage is unavailable')
            identity=read_process_identity_v1(os.getpid())
            return control.sign_original_v1('sylanne3.c09.writer-peer-host-start.v3',dict(schema='sylanne3.c09.writer-peer-host-start.v3',
                authority_id=control.authority_id,installation_id=control.installation_id,control_store_id=control.control_store_id,
                namespace=context.manifest['cohort_namespaces'][0],activation_digest=activation['activation_digest'],
                manifest_digest=context.manifest_digest,pointer_version=context.pointer_version,storage_generation=context.storage_generation,
                stage=context.stage,authority_process_original=identity,supervisor_spec_digest=supervisor_spec_digest,
                root_channel_nonce=activation['activation_basis']['root_channel_nonce']),'host_start_digest')


def verify_writer_peer_registry_host_start_original_v3(original,*,activation_original,authority_id,installation_id,namespace,
        supervisor_spec_digest,authority_process_original,key_id,key_bytes):
    import hmac
    from .c09_storage_control_v1 import digest
    verify_writer_peer_registry_activation_for_host_start_v3(activation_original,authority_id=authority_id,
        installation_id=installation_id,namespace=namespace,supervisor_spec_digest=supervisor_spec_digest,key_id=key_id,key_bytes=key_bytes)
    fields={'schema','authority_id','installation_id','control_store_id','namespace','activation_digest','manifest_digest',
        'pointer_version','storage_generation','stage','authority_process_original','supervisor_spec_digest','root_channel_nonce',
        'host_start_digest','key_id','signature'}
    if (set(original)!=fields or original['schema']!='sylanne3.c09.writer-peer-host-start.v3'
            or original['authority_id']!=authority_id or original['installation_id']!=installation_id or original['namespace']!=namespace
            or original['supervisor_spec_digest']!=supervisor_spec_digest or original['authority_process_original']!=authority_process_original
            or original['activation_digest']!=activation_original['activation_digest'] or original['key_id']!=key_id
            or original['control_store_id']!=activation_original['control_store_id']
            or original['root_channel_nonce']!=activation_original['activation_basis']['root_channel_nonce']
            or original['pointer_version']<activation_original['pointer_version']
            or original['stage']!='RELEASED' and not (original['stage']=='READY' and original['pointer_version']==0 and original['storage_generation']==0)):
        raise AuthorityUnavailable('actual fresh Host start original differs from the installed Authority channel and business scope')
    committed=digest({name:value for name,value in original.items() if name not in {'host_start_digest','signature'}})
    signature=hmac.new(key_bytes,(original['schema']+'\n'+committed).encode(),'sha256').hexdigest()
    if committed!=original['host_start_digest'] or not hmac.compare_digest(signature,original['signature']):
        raise AuthorityUnavailable('actual fresh Host start HMAC differs')
    return original


_PENDING_FIELDS=frozenset(('schema','authority_id','installation_id','control_store_id','namespace',
    'activation_digest','manifest_digest','pointer_version','storage_generation','supervisor_spec_digest',
    'peer','start_sequence','previous_pending_start_digest','host_start_digest','expected_prior_invocation_id','authority_process_original','root_process_original',
    'start_channel_nonce','baseline_observation','pending_start_digest','key_id','signature'))
_PENDING_COMPLETE_FIELDS=frozenset(('schema','authority_id','installation_id','control_store_id','namespace',
    'pending_start_digest','manifest_digest','pointer_version','storage_generation','supervisor_spec_digest',
    'peer','disposition','observation','admission_digest','observer_authority_process_original',
    'completion_digest','key_id','signature'))


def _require_pending_schema_v3(control,db,meter):
    activation=require_writer_peer_registry_activation_v3(control,None,db,meter)
    if activation.get('pending_start_protocol')!=_PENDING_START:
        raise AuthorityUnavailable('peer registry lacks an authenticated pending-start protocol activation')
    for name in ('c09_writer_peer_pending_starts_v3','c09_writer_peer_pending_start_completions_v3','c09_writer_peer_pending_start_coverages_v3','c09_writer_peer_old_root_retirements_v3'):
        if _read_one(db,"SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,),meter)!=(DDLS_V3[name],):
            raise AuthorityUnavailable('actual pending-start protected table schema differs')
        for action in ('UPDATE','DELETE'):
            trigger=name+'_no_'+action.lower()
            if _read_one(db,"SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",(trigger,),meter)!=(control._immutable_ddl(name,action),):
                raise AuthorityUnavailable('actual pending-start protected original is not immutable')
    if _read_one(db,"SELECT sql FROM sqlite_master WHERE type='index' AND name='c09_writer_peer_pending_generation_v3'",(),meter)!=(_PENDING_INDEX,):
        raise AuthorityUnavailable('actual pending-start generation keyset index differs')
    return activation


def _verify_pending_original_v3(control,original):
    from .installed_process_supervisor_v1 import decode_process_supervisor_observation_v2
    if type(original) is not dict or set(original)!=_PENDING_FIELDS or original['schema']!=_PENDING_START:
        raise AuthorityUnavailable('exact pending Host start original required')
    control.verify_original_v1(original,'pending_start_digest')
    baseline=decode_process_supervisor_observation_v2(original['baseline_observation'])
    if (original['authority_id']!=control.authority_id or original['installation_id']!=control.installation_id
            or original['control_store_id']!=control.control_store_id or len(original['peer'])!=2
            or baseline.spec_digest!=original['supervisor_spec_digest'] or baseline.service_role!='host'
            or baseline.invocation_id!=original['expected_prior_invocation_id']
            or baseline.launcher_process_original!=original['root_process_original']
            or not baseline.stopped_and_drained or not original['start_channel_nonce']
            or type(original['start_sequence']) is not int or original['start_sequence']<1
            or (original['start_sequence']==1)!=(original['previous_pending_start_digest'] is None)):
        raise AuthorityUnavailable('pending Host start differs from actual full Root baseline and installed scope')
    return baseline


def retain_writer_peer_pending_start_v3(control,gate,*,supervisor,host_start_original,baseline,expected_prior_invocation_id):
    from dataclasses import asdict
    from .installed_process_supervisor_v1 import InstalledRootProcessSupervisorV1,RootPeerStartBaselineV3
    _require_gate(control,gate)
    if (type(supervisor) is not InstalledRootProcessSupervisorV1 or type(baseline) is not RootPeerStartBaselineV3
            or baseline.supervisor is not supervisor or baseline.gate is not gate or baseline.control is not control
            or supervisor._peer_registry_gate_v3 is not gate or supervisor._peer_registry_control_v3 is not control):
        raise AuthorityUnavailable('actual installed Root start hold and registered supervisor required')
    with control._resource_sql_quantum_v3() as meter:
        baseline.require_current(control=control,gate=gate,meter=meter)
        if baseline.observation.invocation_id!=expected_prior_invocation_id or not baseline.observation.stopped_and_drained:
            raise AuthorityUnavailable('expected prior invocation must be the actual complete stopped Root baseline')
        spec=supervisor.config
        peer=tuple(baseline.peer)
        config=gate._installed_config_v3
        if (peer not in config.installations_v2 or peer[1]!=spec.profile_id
                or config.installations_v2[peer].installation_id!=control.installation_id
                or spec.installation_id!=control.installation_id or spec.authority_id!=control.authority_id):
            raise AuthorityUnavailable('actual Root start peer and installed supervisor scope differ')
        with gate._condition:
            if gate._operation is not None:raise AuthorityUnavailable('actual Host start is revoked for maintenance')
            context=gate._current_context_v3(action='business',verify_files=False)
            context.require_current('business')
            control.verify_original_v1(host_start_original,'host_start_digest')
            if (host_start_original['schema']!='sylanne3.c09.writer-peer-host-start.v3'
                    or host_start_original['manifest_digest']!=context.manifest_digest
                    or host_start_original['pointer_version']!=context.pointer_version
                    or host_start_original['storage_generation']!=context.storage_generation
                    or host_start_original['supervisor_spec_digest']!=spec.spec_digest
                    or host_start_original['authority_process_original']!=baseline.authority_process_original
                    or baseline.authority_process_original!=read_process_identity_v1(os.getpid())
                    or context.manifest['cohort_namespaces']!=list(spec.namespace_cohort)):
                raise AuthorityUnavailable('pending Host start does not match actual selected business and Authority scope')
            with control._db(write=True) as db:
                activation=_require_pending_schema_v3(control,db,meter)
                if host_start_original['activation_digest']!=activation['activation_digest']:
                    raise AuthorityUnavailable('pending Host start registry activation differs')
                from .c09_storage_control_v1 import canonical
                peer_digest=canonical_digest(peer)
                prior=_bounded(db,meter).execute('SELECT pending_start_digest,start_sequence,pending_json FROM c09_writer_peer_pending_starts_v3 '
                    'WHERE manifest_digest=? AND pointer_version=? AND storage_generation=? AND peer_digest=? '
                    'ORDER BY start_sequence DESC LIMIT 1',
                    (context.manifest_digest,context.pointer_version,context.storage_generation,peer_digest)).fetchone()
                previous=None;sequence=1
                if prior is not None:
                    previous=json.loads(prior[2]);_verify_pending_original_v3(control,previous)
                    if (previous['pending_start_digest']!=prior[0] or previous['start_sequence']!=prior[1]
                            or previous['peer']!=list(peer) or previous['manifest_digest']!=context.manifest_digest
                            or previous['pointer_version']!=context.pointer_version or previous['storage_generation']!=context.storage_generation):
                        raise AuthorityUnavailable('actual pending Host signed peer tail differs')
                    same_hold=(previous['host_start_digest']==host_start_original['host_start_digest']
                        and previous['start_channel_nonce']==baseline.channel_nonce)
                    if same_hold:return previous
                    done=_bounded(db,meter).execute('SELECT completion_json FROM c09_writer_peer_pending_start_completions_v3 WHERE pending_start_digest=?',(prior[0],)).fetchone()
                    if done is None:raise AuthorityUnavailable('original pending Host start remains unresolved')
                    _verify_pending_completion_v3(control,previous,json.loads(done[0]))
                    sequence=prior[1]+1
                original=control.sign_original_v1(_PENDING_START,dict(schema=_PENDING_START,
                    authority_id=control.authority_id,installation_id=control.installation_id,control_store_id=control.control_store_id,
                    namespace=context.manifest['cohort_namespaces'][0],activation_digest=activation['activation_digest'],
                    manifest_digest=context.manifest_digest,pointer_version=context.pointer_version,storage_generation=context.storage_generation,
                    supervisor_spec_digest=spec.spec_digest,peer=list(peer),start_sequence=sequence,
                    previous_pending_start_digest=None if previous is None else previous['pending_start_digest'],host_start_digest=host_start_original['host_start_digest'],
                    expected_prior_invocation_id=baseline.observation.invocation_id,authority_process_original=baseline.authority_process_original,
                    root_process_original=baseline.root_process_original,start_channel_nonce=baseline.channel_nonce,
                    baseline_observation=asdict(baseline.observation)),'pending_start_digest')
                _verify_pending_original_v3(control,original)
                current=control._c09_control_chain_proof_v2.require_current(db,meter)
                if (current['current_manifest_digest'],current['pointer_version'])!=(context.manifest_digest,context.pointer_version):
                    raise AuthorityUnavailable('pending Host start actual selected CAS changed')
                meter.write_row(db,'c09_writer_peer_pending_starts_v3',('pending_start_digest','manifest_digest','pointer_version',
                    'storage_generation','peer_digest','start_sequence','previous_pending_start_digest','pending_json','key_id','signature'),
                    (original['pending_start_digest'],context.manifest_digest,context.pointer_version,context.storage_generation,
                        peer_digest,sequence,original['previous_pending_start_digest'],canonical(original),control.key_id,original['signature']))
                baseline.require_current(control=control,gate=gate,meter=meter)
                return original


def _verify_pending_completion_v3(control,pending,original):
    if type(original) is dict and original.get('schema')==_PENDING_OLD_COHORT_COMPLETE:
        return _verify_old_cohort_completion_v3(control,pending,original)
    from .installed_process_supervisor_v1 import decode_process_supervisor_observation_v2
    if type(original) is not dict or set(original)!=_PENDING_COMPLETE_FIELDS or original['schema']!=_PENDING_COMPLETE:
        raise AuthorityUnavailable('exact pending Host completion original required')
    control.verify_original_v1(original,'completion_digest')
    for name in ('authority_id','installation_id','control_store_id','namespace','pending_start_digest','manifest_digest',
            'pointer_version','storage_generation','supervisor_spec_digest','peer'):
        if original[name]!=pending[name]:raise AuthorityUnavailable('pending Host completion original crosses its request scope')
    observed=decode_process_supervisor_observation_v2(original['observation'])
    baseline=_verify_pending_original_v3(control,pending)
    if (observed.service_role!='host' or observed.spec_digest!=pending['supervisor_spec_digest']
            or observed.launcher_process_original!=pending['root_process_original']
            or observed.pid_namespace_identity!=baseline.pid_namespace_identity
            or observed.mount_namespace_identity!=baseline.mount_namespace_identity
            or observed.observation_sequence<baseline.observation_sequence):
        raise AuthorityUnavailable('pending Host completion does not describe the original Root/cohort namespace')
    if original['disposition']=='retired':
        if not observed.stopped_and_drained or original['admission_digest'] is not None:
            raise AuthorityUnavailable('pending Host retirement requires actual complete stopped Root census')
    elif original['disposition']=='admitted':
        if observed.main_process_original is None or observed.state!='active' or observed.invocation_id==pending['expected_prior_invocation_id']:
            raise AuthorityUnavailable('pending Host admission lacks an actual distinct active invocation')
    else:raise AuthorityUnavailable('pending Host completion disposition is unregistered')
    return observed


def complete_writer_peer_pending_start_v3(control,gate,*,observed_start):
    from dataclasses import asdict
    from .installed_process_supervisor_v1 import RootObservedPeerStartV3
    _require_gate(control,gate)
    if type(observed_start) is not RootObservedPeerStartV3:
        raise AuthorityUnavailable('actual Root observed pending Host start issuer required')
    with control._resource_sql_quantum_v3() as meter:
        observed_start.require_current(control=control,gate=gate,meter=meter)
        pending=observed_start.pending_original;_verify_pending_original_v3(control,pending)
        observed=observed_start.observation;admission=observed_start.admission_original
        disposition='retired' if observed.stopped_and_drained else 'admitted'
        with control._db(write=True) as db:
            _require_pending_schema_v3(control,db,meter)
            saved=_bounded(db,meter).execute('SELECT pending_json FROM c09_writer_peer_pending_starts_v3 WHERE pending_start_digest=?',
                (pending['pending_start_digest'],)).fetchone()
            from .c09_storage_control_v1 import canonical
            if saved!=(canonical(pending),):raise AuthorityUnavailable('Root observation has no exact durable pending Host original')
            if disposition=='admitted':
                if type(admission) is not dict:raise AuthorityUnavailable('pending Host completion requires a durable peer admission')
                control.verify_original_v1(admission,'admission_digest')
                if (admission['peer']!=pending['peer'] or admission['manifest_digest']!=pending['manifest_digest']
                        or admission['pointer_version']!=pending['pointer_version'] or admission['storage_generation']!=pending['storage_generation']
                        or admission['process_original']!=observed.main_process_original
                        or admission['namespace']!=pending['namespace']):
                    raise AuthorityUnavailable('actual durable admission differs from the pending Root-born Host')
                retained=_bounded(db,meter).execute('SELECT admission_json FROM c09_writer_peer_admissions_v3 WHERE admission_digest=?',
                    (admission['admission_digest'],)).fetchone()
                if retained!=(canonical(admission),):raise AuthorityUnavailable('pending Host completion admission was not durably registered')
            elif admission is not None:raise AuthorityUnavailable('retired pending Host cannot borrow a live admission')
            original=control.sign_original_v1(_PENDING_COMPLETE,dict(schema=_PENDING_COMPLETE,
                **{name:pending[name] for name in ('authority_id','installation_id','control_store_id','namespace','pending_start_digest',
                    'manifest_digest','pointer_version','storage_generation','supervisor_spec_digest','peer')},
                disposition=disposition,observation=asdict(observed),admission_digest=None if admission is None else admission['admission_digest'],
                observer_authority_process_original=read_process_identity_v1(os.getpid())),'completion_digest')
            _verify_pending_completion_v3(control,pending,original)
            prior=_bounded(db,meter).execute('SELECT completion_json FROM c09_writer_peer_pending_start_completions_v3 '
                'WHERE pending_start_digest=?',(pending['pending_start_digest'],)).fetchone()
            if prior is not None:
                retained=json.loads(prior[0]);_verify_pending_completion_v3(control,pending,retained)
                if retained['disposition']!=disposition or retained['admission_digest']!=original['admission_digest']:
                    raise AuthorityUnavailable('durable pending Host completion cannot be replaced')
                return retained
            meter.write_row(db,'c09_writer_peer_pending_start_completions_v3',('pending_start_digest','manifest_digest',
                'pointer_version','storage_generation','completion_json','completion_digest','key_id','signature'),
                (pending['pending_start_digest'],pending['manifest_digest'],pending['pointer_version'],pending['storage_generation'],
                    canonical(original),original['completion_digest'],control.key_id,original['signature']))
            observed_start.require_current(control=control,gate=gate,meter=meter)
            return original


class VerifiedWriterPeerPendingStartCoverageV3:
    def __init__(self,token,reader,original):
        if token is not _VERIFY or not reader.complete:raise AuthorityUnavailable('complete pending Host start EOF issuer required')
        self.reader,self.original,self.control,self.gate=reader,original,reader.control,reader.gate
    def require_current(self,*,meter):
        self.reader.require_current(meter)
        return self


class InstalledWriterPeerPendingStartReadV3:
    def __init__(self,control,gate,operation_id,context):
        self.control,self.gate,self.operation_id,self.context=control,gate,operation_id,context
        self.after='';self.phase='pending';self.count=self.completion_count=0
        self.root=canonical_digest((_PENDING_COVERAGE,operation_id,context.manifest_digest,context.pointer_version,context.storage_generation))
        self.complete=False;self.proof=None;self.failed=None;self.physical_count=0
        self.current_root_process_original=None
        control.register_c09_retained_state_v3(self)
    def _c09_retained_heap_bytes_v3(self):return 4096
    def require_current(self,meter):
        _require_gate(self.control,self.gate)
        if self.operation_id is None:
            hold=self.gate.require_pending_start_bootstrap_scope_v3(meter=meter)
            from .installed_process_supervisor_v1 import RootPeerStartCoverageHoldV3
            if type(hold) is RootPeerStartCoverageHoldV3:self.current_root_process_original=hold.root_process_original
        elif self.gate._operation!=self.operation_id:
            raise AuthorityUnavailable('actual revoked maintenance Gate required for pending Host EOF')
        with self.control._db() as db:
            current=self.control._c09_control_chain_proof_v2.require_current(db,meter)
        if (current['current_manifest_digest'],current['pointer_version'])!=(self.context.manifest_digest,self.context.pointer_version):
            raise AuthorityUnavailable('actual pending Host EOF selected generation changed')
    def advance(self,meter):
        if self.failed is not None:raise AuthorityUnavailable(self.failed)
        try:return self._advance(meter)
        except BaseException as exc:self.failed=str(exc);raise
    def _advance(self,meter):
        self.require_current(meter)
        if self.complete:return self.proof.require_current(meter=meter)
        control=self.control;context=self.context
        with control._db() as db:
            _require_pending_schema_v3(control,db,meter)
            family={'pending':'c09_writer_peer_pending_starts_v3','completions':'c09_writer_peer_pending_start_completions_v3','physical':'c09_writer_peer_old_root_retirements_v3'}[self.phase]
            column={'pending':'pending_json','completions':'completion_json','physical':'retirement_json'}[self.phase]
            row=_bounded(db,meter).execute('SELECT pending_start_digest,'+column+' FROM '+family+
                ' WHERE pending_start_digest>? ORDER BY pending_start_digest COLLATE BINARY LIMIT 1',(self.after,)).fetchone()
            if row is not None:
                pending_row=row if self.phase=='pending' else _bounded(db,meter).execute(
                    'SELECT pending_start_digest,pending_json FROM c09_writer_peer_pending_starts_v3 WHERE pending_start_digest=?',(row[0],)).fetchone()
                if pending_row is None:raise AuthorityUnavailable('pending Host completion has no original request')
                pending=json.loads(pending_row[1]);_verify_pending_original_v3(control,pending)
                stored=_read_one(db,'SELECT manifest_digest,pointer_version,storage_generation,peer_digest,start_sequence,previous_pending_start_digest '
                    'FROM c09_writer_peer_pending_starts_v3 WHERE pending_start_digest=?',(row[0],),meter)
                expected=(pending['manifest_digest'],pending['pointer_version'],pending['storage_generation'],canonical_digest(tuple(pending['peer'])),
                    pending['start_sequence'],pending['previous_pending_start_digest'])
                if (pending['pending_start_digest']!=row[0] or stored!=expected or pending['pointer_version']>context.pointer_version
                        or pending['storage_generation']>context.storage_generation or pending['namespace']!=context.manifest['cohort_namespaces'][0]):
                    raise AuthorityUnavailable('pending Host EOF request family scope differs')
                if pending['start_sequence']>1:
                    predecessor=_bounded(db,meter).execute('SELECT pending_json FROM c09_writer_peer_pending_starts_v3 WHERE '
                        'manifest_digest=? AND pointer_version=? AND storage_generation=? AND peer_digest=? AND start_sequence=?',
                        (pending['manifest_digest'],pending['pointer_version'],pending['storage_generation'],canonical_digest(tuple(pending['peer'])),pending['start_sequence']-1)).fetchone()
                    if predecessor is None:raise AuthorityUnavailable('pending Host immutable sequence has a missing predecessor')
                    predecessor_original=json.loads(predecessor[0]);_verify_pending_original_v3(control,predecessor_original)
                    if predecessor_original['pending_start_digest']!=pending['previous_pending_start_digest']:
                        raise AuthorityUnavailable('pending Host signed predecessor chain differs')
                completed=_bounded(db,meter).execute('SELECT completion_json FROM c09_writer_peer_pending_start_completions_v3 '
                    'WHERE pending_start_digest=?',(row[0],)).fetchone()
                if completed is None:
                    return dict(status='progress',phase='writer_peer_pending_start',pending_start_original=pending)
                original=json.loads(completed[0]);_verify_pending_completion_v3(control,pending,original)
                completion_scope=_read_one(db,'SELECT manifest_digest,pointer_version,storage_generation FROM c09_writer_peer_pending_start_completions_v3 WHERE pending_start_digest=?',(row[0],),meter)
                if completion_scope!=(pending['manifest_digest'],pending['pointer_version'],pending['storage_generation']):
                    raise AuthorityUnavailable('pending Host completion physical family scope differs from its signed original')
                physical_row=_bounded(db,meter).execute('SELECT retirement_json FROM c09_writer_peer_old_root_retirements_v3 WHERE pending_start_digest=?',(row[0],)).fetchone()
                physical=None
                if physical_row is not None:
                    physical=json.loads(physical_row[0]);_verify_old_root_physical_retirement_v3(control,pending,physical)
                if (self.phase=='pending' and self.current_root_process_original is not None
                        and pending['root_process_original']!=self.current_root_process_original and physical is None):
                    return dict(status='progress',phase='writer_peer_pending_start',pending_start_original=pending,
                        prior_completion_original=original)
                if self.phase=='physical':
                    if physical is None:raise AuthorityUnavailable('old Root physical family row disappeared')
                    self.physical_count+=1
                if self.phase=='pending':
                    if original['disposition']=='admitted':
                        saved=_bounded(db,meter).execute('SELECT admission_json FROM c09_writer_peer_admissions_v3 WHERE admission_digest=?',
                            (original['admission_digest'],)).fetchone()
                        if saved is None:raise AuthorityUnavailable('completed pending Host lost its durable admission')
                        admission=json.loads(saved[0]);control.verify_original_v1(admission,'admission_digest')
                        observed=json.loads(completed[0])['observation']
                        if (admission['peer']!=pending['peer'] or admission['process_original']!=observed['main_process_original']
                                or admission['manifest_digest']!=pending['manifest_digest'] or admission['pointer_version']!=pending['pointer_version']
                                or admission['storage_generation']!=pending['storage_generation']):
                            raise AuthorityUnavailable('pending Host admission EOF binding differs')
                    if physical is not None and original['disposition']=='admitted' and self.operation_id is not None:
                        _retain_root_cohort_peer_retirement_v3(control,self.operation_id,pending,physical,original,meter)
                    self.count+=1;self.root=canonical_digest((self.root,self.count,row[0],original['completion_digest'],
                        None if physical is None else physical['retirement_digest']))
                elif self.phase=='completions':self.completion_count+=1
                self.after=row[0];return dict(status='progress',phase='writer_peer_pending_start_eof',pending_start_count=self.count)
        if self.phase=='pending':self.phase='completions';self.after='';return dict(status='progress',phase='writer_peer_pending_completion_eof')
        if self.phase=='completions':self.phase='physical';self.after='';return dict(status='progress',phase='writer_peer_old_root_retirement_eof')
        if self.completion_count!=self.count:raise AuthorityUnavailable('pending Host request/completion full EOF counts differ')
        bootstrap_nonce=bootstrap_root=bootstrap_authority=None
        if self.operation_id is None:
            hold=self.gate.require_pending_start_bootstrap_scope_v3(meter=meter)
            from .installed_process_supervisor_v1 import RootPeerStartCoverageHoldV3
            if type(hold) is RootPeerStartCoverageHoldV3:
                bootstrap_nonce=hold.channel_nonce;bootstrap_root=hold.root_process_original;bootstrap_authority=hold.authority_process_original
            else:
                bootstrap_nonce=hold.original['channel_nonce'];bootstrap_root=hold.original['root_process'];bootstrap_authority=hold.original['authority_process']
        original=control.sign_original_v1(_PENDING_COVERAGE,dict(schema=_PENDING_COVERAGE,
            authority_id=control.authority_id,installation_id=control.installation_id,control_store_id=control.control_store_id,
            namespace=context.manifest['cohort_namespaces'][0],maintenance_operation_id=self.operation_id,
            manifest_digest=context.manifest_digest,pointer_version=context.pointer_version,storage_generation=context.storage_generation,
            pending_start_count=self.count,completion_count=self.completion_count,physical_retirement_count=self.physical_count,coverage_root=self.root,complete=True,
            bootstrap_channel_nonce=bootstrap_nonce,bootstrap_root_process_original=bootstrap_root,bootstrap_authority_process_original=bootstrap_authority,
            eof_digest=canonical_digest((_PENDING_COVERAGE,self.count,self.completion_count,self.root,self.after))),'coverage_digest')
        with control._db(write=True) as db:
            self.require_current(meter)
            prior=_bounded(db,meter).execute('SELECT coverage_json FROM c09_writer_peer_pending_start_coverages_v3 WHERE coverage_digest=?',
                (original['coverage_digest'],)).fetchone()
            from .c09_storage_control_v1 import canonical
            if prior is not None:
                if prior!=(canonical(original),):raise AuthorityUnavailable('pending Host complete EOF replay differs')
            else:meter.write_row(db,'c09_writer_peer_pending_start_coverages_v3',('operation_id','manifest_digest','pointer_version',
                'storage_generation','coverage_json','coverage_digest','key_id','signature'),
                (self.operation_id,context.manifest_digest,context.pointer_version,context.storage_generation,
                    canonical(original),original['coverage_digest'],control.key_id,original['signature']))
        self.complete=True;self.proof=VerifiedWriterPeerPendingStartCoverageV3(_VERIFY,self,original)
        return self.proof


def advance_writer_peer_pending_start_coverage_v3(control,gate,*,operation_id,context):
    _require_gate(control,gate)
    with control._resource_sql_quantum_v3() as meter:
        reader=getattr(gate,'_pending_peer_start_coverage_v3',None)
        if reader is None or reader.complete and reader.operation_id!=operation_id:
            reader=InstalledWriterPeerPendingStartReadV3(control,gate,operation_id,context)
            gate._pending_peer_start_coverage_v3=reader
        if reader.operation_id!=operation_id:raise AuthorityUnavailable('another pending Host EOF operation is already retained')
        return reader.advance(meter)


def verify_writer_peer_pending_start_for_root_v3(original,*,host_start_original,activation_original,
        authority_id,installation_id,namespace,supervisor_spec_digest,authority_process_original,
        root_process_original,start_channel_nonce,expected_prior_invocation_id,key_id,key_bytes):
    import hmac
    from .c09_storage_control_v1 import digest
    from .installed_process_supervisor_v1 import decode_process_supervisor_observation_v2
    verify_writer_peer_registry_host_start_original_v3(host_start_original,activation_original=activation_original,
        authority_id=authority_id,installation_id=installation_id,namespace=namespace,supervisor_spec_digest=supervisor_spec_digest,
        authority_process_original=authority_process_original,key_id=key_id,key_bytes=key_bytes)
    if type(original) is not dict or set(original)!=_PENDING_FIELDS or original['schema']!=_PENDING_START:
        raise AuthorityUnavailable('Root requires the actual signed pending Host original')
    for name,value in (('authority_id',authority_id),('installation_id',installation_id),('namespace',namespace),
            ('supervisor_spec_digest',supervisor_spec_digest),('authority_process_original',authority_process_original),
            ('root_process_original',root_process_original),('start_channel_nonce',start_channel_nonce),
            ('expected_prior_invocation_id',expected_prior_invocation_id),('key_id',key_id),
            ('host_start_digest',host_start_original['host_start_digest']),('activation_digest',activation_original['activation_digest'])):
        if original[name]!=value:raise AuthorityUnavailable('Root pending Host original scope differs')
    for name in ('manifest_digest','pointer_version','storage_generation','control_store_id'):
        if original[name]!=host_start_original[name]:raise AuthorityUnavailable('Root pending Host original selected scope differs')
    baseline=decode_process_supervisor_observation_v2(original['baseline_observation'])
    if (not baseline.stopped_and_drained or baseline.invocation_id!=expected_prior_invocation_id
            or baseline.launcher_process_original!=root_process_original or baseline.spec_digest!=supervisor_spec_digest):
        raise AuthorityUnavailable('Root pending Host baseline differs from its held complete cohort')
    committed=digest({name:value for name,value in original.items() if name not in {'pending_start_digest','signature'}})
    signature=hmac.new(key_bytes,(original['schema']+'\n'+committed).encode(),'sha256').hexdigest()
    if committed!=original['pending_start_digest'] or not hmac.compare_digest(signature,original['signature']):
        raise AuthorityUnavailable('Root pending Host start HMAC differs')
    return original



def verify_writer_peer_pending_start_original_v3(original,*,activation_original,host_start_original,
        supervisor_spec_digest,root_process_original,authority_process_original,channel_nonce,key_id,key_bytes):
    return verify_writer_peer_pending_start_for_root_v3(original,host_start_original=host_start_original,
        activation_original=activation_original,authority_id=host_start_original['authority_id'],
        installation_id=host_start_original['installation_id'],namespace=host_start_original['namespace'],
        supervisor_spec_digest=supervisor_spec_digest,authority_process_original=authority_process_original,
        root_process_original=root_process_original,start_channel_nonce=channel_nonce,
        expected_prior_invocation_id=original['expected_prior_invocation_id'],key_id=key_id,key_bytes=key_bytes)


def verify_writer_peer_pending_start_completion_original_v3(original,*,pending_start_original,key_id,key_bytes):
    if type(original) is dict and original.get('schema')==_PENDING_OLD_COHORT_COMPLETE:
        return verify_writer_peer_pending_start_old_cohort_completion_original_v3(original,
            pending_start_original=pending_start_original,key_id=key_id,key_bytes=key_bytes)
    import hmac
    from .c09_storage_control_v1 import digest
    from .installed_process_supervisor_v1 import decode_process_supervisor_observation_v2
    if type(original) is not dict or set(original)!=_PENDING_COMPLETE_FIELDS or original['schema']!=_PENDING_COMPLETE:
        raise AuthorityUnavailable('Root requires an exact signed pending Host completion')
    for field in ('authority_id','installation_id','control_store_id','namespace','pending_start_digest','manifest_digest',
            'pointer_version','storage_generation','supervisor_spec_digest','peer'):
        if original[field]!=pending_start_original[field]:raise AuthorityUnavailable('Root pending Host completion scope differs')
    if original['key_id']!=key_id:raise AuthorityUnavailable('Root pending Host completion key differs')
    committed=digest({name:value for name,value in original.items() if name not in {'completion_digest','signature'}})
    signature=hmac.new(key_bytes,(original['schema']+'\n'+committed).encode(),'sha256').hexdigest()
    if committed!=original['completion_digest'] or not hmac.compare_digest(signature,original['signature']):
        raise AuthorityUnavailable('Root pending Host completion HMAC differs')
    baseline=decode_process_supervisor_observation_v2(pending_start_original['baseline_observation'])
    observed=decode_process_supervisor_observation_v2(original['observation'])
    if (observed.launcher_process_original!=pending_start_original['root_process_original']
            or observed.spec_digest!=pending_start_original['supervisor_spec_digest'] or observed.service_role!='host'
            or observed.pid_namespace_identity!=baseline.pid_namespace_identity or observed.mount_namespace_identity!=baseline.mount_namespace_identity
            or observed.observation_sequence<baseline.observation_sequence):
        raise AuthorityUnavailable('Root pending Host completion observation differs from its actual held cohort')
    if original['disposition']=='retired':
        if not observed.stopped_and_drained or original['admission_digest'] is not None:
            raise AuthorityUnavailable('Root retired pending Host completion lacks full stopped census')
    elif original['disposition']=='admitted':
        if observed.main_process_original is None or observed.state!='active' or original['admission_digest'] is None:
            raise AuthorityUnavailable('Root admitted pending Host completion lacks actual durable admission')
    else:raise AuthorityUnavailable('Root pending Host completion disposition is unknown')
    return original


def _require_controlled_sdk_root_census_v3(summary,control,manifest,current,*,gate,activation):
    reply=summary['controlled_sdk_root_census_original']
    fields={'schema','command','phase','resource_operation_id','root_process','authority_process','app_cgroup','processes',
        'cohort_eof','continuous_start_exclusion','descriptor_sha256','node','node_sha256','package_sha256','manifest_sha256',
        'dependency_sha256','setup_sha256','selection_scope','request_digest','observed_monotonic_ns','root_uid','authority_uid',
        'socket','run_cgroup','cohort_count','cohort_root','channel_nonce','hold_token','profile_digest','run_deadline_monotonic_ns'}
    if (type(reply) is not dict or set(reply)!=fields or reply['schema']!='sylanne.root-controlled-sdk-census.v3'
            or canonical_digest(reply)!=summary['controlled_sdk_root_census_original_digest']
            or reply['cohort_count']!=1 or reply['processes']!=[reply['authority_process']]
            or reply['root_uid']!=0 or reply['authority_process']['pid']!=summary['authority_process_original']['pid']
            or reply['authority_process']['birth']!=summary['authority_process_original']['birth']
            or reply['cohort_eof'] is not True or reply['continuous_start_exclusion'] is not True
            or not reply['hold_token'] or not reply['channel_nonce']):
        raise AuthorityUnavailable('actual controlled SDK Root full census original differs')
    scope=reply['selection_scope'];peer=tuple(summary['sdk_peer_descriptor'])
    expected={'authority_id','installation_id','control_store_id','namespace','sdk_peer_descriptor',
        'manifest_digest','inventory_manifest_digest','descriptor_digest'}
    descriptor=activation.qualification.descriptor
    if (type(scope) is not dict or set(scope)!=expected or scope['authority_id']!=control.authority_id
            or scope['installation_id']!=control.installation_id or scope['control_store_id']!=control.control_store_id
            or scope['namespace']!=manifest['cohort_namespaces'][0] or scope['sdk_peer_descriptor']!=list(peer)
            or scope['manifest_digest']!=gate._installed_config_v3.installations_v2[peer].manifest_digest
            or scope['inventory_manifest_digest']!=gate._installed_config_v3.c09_maintenance_factory.inventory.manifest_digest
            or scope['descriptor_digest']!=descriptor.payload['descriptor_digest']
            or reply['descriptor_sha256']!=descriptor.source_digest):
        raise AuthorityUnavailable('controlled SDK Root full census belongs to another actual installed finite descriptor')



def require_peer_completion_pending_coverage_v3(control,completion,*,meter):
    required={'pending_start_coverage_original_digest','pending_start_count','pending_start_root','pending_start_eof_digest'}
    if not required<=set(completion):
        raise AuthorityUnavailable('writer retirement lacks complete durable pending Host start coverage')
    with control._db() as db:
        _require_pending_schema_v3(control,db,meter)
        row=_bounded(db,meter).execute('SELECT coverage_json FROM c09_writer_peer_pending_start_coverages_v3 '
            'WHERE operation_id=? AND manifest_digest=? AND pointer_version=? AND storage_generation=? AND coverage_digest=?',
            (completion['maintenance_operation_id'],completion['manifest_digest'],completion['pointer_version'],
                completion['storage_generation'],completion['pending_start_coverage_original_digest'])).fetchone()
    if row is None:raise AuthorityUnavailable('writer retirement pending Host signed EOF original is absent')
    original=json.loads(row[0]);control.verify_original_v1(original,'coverage_digest')
    if (original['schema']!=_PENDING_COVERAGE or original['complete'] is not True
            or original['maintenance_operation_id']!=completion['maintenance_operation_id']
            or original['authority_id']!=control.authority_id or original['installation_id']!=control.installation_id
            or original['control_store_id']!=control.control_store_id or original['namespace']!=completion['namespace']
            or original['pending_start_count']!=original['completion_count']
            or original['pending_start_count']!=completion['pending_start_count']
            or original['coverage_root']!=completion['pending_start_root'] or original['eof_digest']!=completion['pending_start_eof_digest']):
        raise AuthorityUnavailable('writer retirement pending Host original scope/root/count/EOF differ')
    return original



def read_writer_peer_pending_start_completion_v3(control,gate,*,pending_start_original):
    _require_gate(control,gate)
    with control._resource_sql_quantum_v3() as meter:
        pending=pending_start_original;_verify_pending_original_v3(control,pending)
        with control._db() as db:
            _require_pending_schema_v3(control,db,meter)
            from .c09_storage_control_v1 import canonical
            request=_bounded(db,meter).execute('SELECT pending_json FROM c09_writer_peer_pending_starts_v3 WHERE pending_start_digest=?',
                (pending['pending_start_digest'],)).fetchone()
            if request!=(canonical(pending),):raise AuthorityUnavailable('pending Host completion point has no exact retained original request')
            row=_bounded(db,meter).execute('SELECT completion_json FROM c09_writer_peer_pending_start_completions_v3 WHERE pending_start_digest=?',
                (pending['pending_start_digest'],)).fetchone()
            if row is None:return None
            original=json.loads(row[0]);_verify_pending_completion_v3(control,pending,original)
            if original['disposition']=='admitted':
                admission=_bounded(db,meter).execute('SELECT admission_json FROM c09_writer_peer_admissions_v3 WHERE admission_digest=?',
                    (original['admission_digest'],)).fetchone()
                if admission is None:raise AuthorityUnavailable('prior pending Host completion lost its durable admission')
                retained=json.loads(admission[0]);control.verify_original_v1(retained,'admission_digest')
                if (retained['peer']!=pending['peer'] or retained['process_original']!=original['observation']['main_process_original']
                        or retained['manifest_digest']!=pending['manifest_digest'] or retained['pointer_version']!=pending['pointer_version']
                        or retained['storage_generation']!=pending['storage_generation'] or retained['namespace']!=pending['namespace']):
                    raise AuthorityUnavailable('prior pending Host completion durable admission identity differs')
            return original



def verify_writer_peer_pending_start_resolve_original_v3(original,*,authority_id,installation_id,namespace,
        supervisor_spec_digest,root_process_original,key_id,key_bytes):
    import hmac
    from .c09_storage_control_v1 import digest
    from .installed_process_supervisor_v1 import decode_process_supervisor_observation_v2
    if type(original) is not dict or set(original)!=_PENDING_FIELDS or original['schema']!=_PENDING_START:
        raise AuthorityUnavailable('Root resolver requires the original signed pending Host request')
    for field,value in (('authority_id',authority_id),('installation_id',installation_id),('namespace',namespace),
            ('supervisor_spec_digest',supervisor_spec_digest),('root_process_original',root_process_original),('key_id',key_id)):
        if original[field]!=value:raise AuthorityUnavailable('Root pending Host resolver changes its original installed cohort')
    committed=digest({name:value for name,value in original.items() if name not in {'pending_start_digest','signature'}})
    signature=hmac.new(key_bytes,(original['schema']+'\n'+committed).encode(),'sha256').hexdigest()
    if committed!=original['pending_start_digest'] or not hmac.compare_digest(signature,original['signature']):
        raise AuthorityUnavailable('Root pending Host resolver original HMAC differs')
    baseline=decode_process_supervisor_observation_v2(original['baseline_observation'])
    if (baseline.launcher_process_original!=root_process_original or baseline.service_role!='host'
            or baseline.spec_digest!=supervisor_spec_digest or not baseline.stopped_and_drained
            or baseline.invocation_id!=original['expected_prior_invocation_id']):
        raise AuthorityUnavailable('Root pending Host resolver lacks its original complete baseline')
    return original


def verify_writer_peer_pending_start_coverage_original_v3(original,*,authority_id,installation_id,namespace,key_id,key_bytes):
    import hmac
    from .c09_storage_control_v1 import digest
    fields={'schema','authority_id','installation_id','control_store_id','namespace','maintenance_operation_id','manifest_digest',
        'pointer_version','storage_generation','pending_start_count','completion_count','physical_retirement_count','coverage_root','complete','eof_digest',
        'bootstrap_channel_nonce','bootstrap_root_process_original','bootstrap_authority_process_original','coverage_digest','key_id','signature'}
    if (type(original) is not dict or set(original)!=fields or original['schema']!=_PENDING_COVERAGE
            or original['authority_id']!=authority_id or original['installation_id']!=installation_id or original['namespace']!=namespace
            or original['key_id']!=key_id or original['complete'] is not True or type(original['pending_start_count']) is not int
            or original['pending_start_count']<0 or original['completion_count']!=original['pending_start_count']
            or original['maintenance_operation_id'] is not None or not original['bootstrap_channel_nonce']
            or type(original['bootstrap_root_process_original']) is not dict or type(original['bootstrap_authority_process_original']) is not dict):
        raise AuthorityUnavailable('Root pending Host coverage lacks exact complete bootstrap EOF scope')
    committed=digest({name:value for name,value in original.items() if name not in {'coverage_digest','signature'}})
    signature=hmac.new(key_bytes,(original['schema']+'\n'+committed).encode(),'sha256').hexdigest()
    if committed!=original['coverage_digest'] or not hmac.compare_digest(signature,original['signature']):
        raise AuthorityUnavailable('Root pending Host full coverage HMAC differs')
    return original


_OLD_COHORT_FIELDS=frozenset(('schema','pending_start_digest','old_baseline_digest','authority_id','installation_id',
    'control_store_id','namespace','peer','manifest_digest','pointer_version','storage_generation','supervisor_spec_digest',
    'old_root_process_original','old_ancestor_root_process_original','old_pid_namespace_identity','old_mount_namespace_identity',
    'old_procfs_identity','observer_process_original','kernel_boot_id','observer_spec_digest','lifetime_id','launch_id',
    'observer_hold_nonce','cohort_source_root','root_pidfd_exit','census_count','census_root','eof_digest','complete','resource_scope_original_digest'))
_OLD_COMPLETE_FIELDS=frozenset(('schema','authority_id','installation_id','control_store_id','namespace','pending_start_digest',
    'manifest_digest','pointer_version','storage_generation','supervisor_spec_digest','peer','disposition','retirement_original',
    'retirement_original_digest','observer_authority_process_original','completion_digest','key_id','signature'))


def _require_old_cohort_material_v3(pending,material):
    from .installed_process_supervisor_v1 import decode_process_supervisor_observation_v2
    if type(material) is not dict or set(material)!=_OLD_COHORT_FIELDS or material['schema']!='sylanne3.installed-root-cohort-retirement.v3':
        raise AuthorityUnavailable('exact installed old Root cohort retirement material required')
    for field in ('authority_id','installation_id','control_store_id','namespace','pending_start_digest','manifest_digest',
            'pointer_version','storage_generation','supervisor_spec_digest','peer'):
        if material[field]!=pending[field]:raise AuthorityUnavailable('old Root cohort retirement changes its actual pending installation scope')
    baseline=decode_process_supervisor_observation_v2(pending['baseline_observation'])
    old=material['old_root_process_original'];ancestor=material['old_ancestor_root_process_original']
    if (material['old_baseline_digest']!=canonical_digest(pending['baseline_observation'])
            or old!=pending['root_process_original'] or old!=baseline.launcher_process_original
            or type(ancestor) is not dict or ancestor.get('birth')!=old['birth'] or ancestor.get('pid',0)<1
            or material['old_pid_namespace_identity']!=baseline.pid_namespace_identity
            or material['old_mount_namespace_identity']!=baseline.mount_namespace_identity
            or type(material['old_procfs_identity']) is not dict or set(material['old_procfs_identity'])!={'device','inode'}
            or material['kernel_boot_id']!=old['birth'].split(':',1)[0]
            or material['root_pidfd_exit'] is not True or material['complete'] is not True
            or type(material['census_count']) is not int or material['census_count']!=0
            or not material['lifetime_id'] or not material['launch_id'] or not material['observer_hold_nonce']):
        raise AuthorityUnavailable('old Root cohort retirement lacks its original pinned namespace, same kernel and complete exit EOF')
    for field in ('observer_spec_digest','cohort_source_root','census_root','eof_digest','resource_scope_original_digest'):
        digest=material[field]
        if type(digest) is not str or len(digest)!=64 or any(char not in '0123456789abcdef' for char in digest):
            raise AuthorityUnavailable('old Root cohort actual lifetime/resource/EOF commitment differs')
    return material


def _verify_old_cohort_completion_v3(control,pending,original):
    if type(original) is not dict or set(original)!=_OLD_COMPLETE_FIELDS or original['schema']!=_PENDING_OLD_COHORT_COMPLETE:
        raise AuthorityUnavailable('exact signed old Root cohort completion required')
    control.verify_original_v1(original,'completion_digest')
    for field in ('authority_id','installation_id','control_store_id','namespace','pending_start_digest','manifest_digest',
            'pointer_version','storage_generation','supervisor_spec_digest','peer'):
        if original[field]!=pending[field]:raise AuthorityUnavailable('old Root cohort completion crosses its original pending scope')
    if (original['disposition']!='root_cohort_retired'
            or canonical_digest(original['retirement_original'])!=original['retirement_original_digest']):
        raise AuthorityUnavailable('old Root cohort completion material commitment differs')
    return _require_old_cohort_material_v3(pending,original['retirement_original'])


def complete_writer_peer_pending_start_old_cohort_v3(control,gate,*,retirement):
    from .installed_root_lifetime_observer_v3 import VerifiedInstalledRootCohortRetirementV3
    _require_gate(control,gate)
    if (type(retirement) is not VerifiedInstalledRootCohortRetirementV3 or retirement.control is not control or retirement.gate is not gate):
        raise AuthorityUnavailable('actual installed lifetime observer old-cohort retirement issuer required')
    with control._resource_sql_quantum_v3() as meter:
        retirement.require_current(control=control,gate=gate,meter=meter)
        pending=retirement.pending_original;_verify_pending_original_v3(control,pending)
        material=_require_old_cohort_material_v3(pending,retirement.original)
        retain_writer_peer_old_root_retirement_v3(control,gate,retirement=retirement)
        with control._db(write=True) as db:
            _require_pending_schema_v3(control,db,meter)
            from .c09_storage_control_v1 import canonical
            saved=_bounded(db,meter).execute('SELECT pending_json FROM c09_writer_peer_pending_starts_v3 WHERE pending_start_digest=?',
                (pending['pending_start_digest'],)).fetchone()
            if saved!=(canonical(pending),):raise AuthorityUnavailable('old Root cohort proof lacks its exact durable pending request')
            prior=_bounded(db,meter).execute('SELECT completion_json FROM c09_writer_peer_pending_start_completions_v3 '
                'WHERE pending_start_digest=?',(pending['pending_start_digest'],)).fetchone()
            if prior is not None:
                original=json.loads(prior[0]);_verify_pending_completion_v3(control,pending,original)
                return original
            original=control.sign_original_v1(_PENDING_OLD_COHORT_COMPLETE,dict(schema=_PENDING_OLD_COHORT_COMPLETE,
                **{field:pending[field] for field in ('authority_id','installation_id','control_store_id','namespace','pending_start_digest',
                    'manifest_digest','pointer_version','storage_generation','supervisor_spec_digest','peer')},
                disposition='root_cohort_retired',retirement_original=material,retirement_original_digest=canonical_digest(material),
                observer_authority_process_original=read_process_identity_v1(os.getpid())),'completion_digest')
            _verify_old_cohort_completion_v3(control,pending,original)
            meter.write_row(db,'c09_writer_peer_pending_start_completions_v3',('pending_start_digest','manifest_digest',
                'pointer_version','storage_generation','completion_json','completion_digest','key_id','signature'),
                (pending['pending_start_digest'],pending['manifest_digest'],pending['pointer_version'],pending['storage_generation'],
                    canonical(original),original['completion_digest'],control.key_id,original['signature']))
            retirement.require_current(control=control,gate=gate,meter=meter)
            return original


def verify_writer_peer_pending_start_old_cohort_completion_original_v3(original,*,pending_start_original,key_id,key_bytes):
    import hmac
    from .c09_storage_control_v1 import digest
    if (type(original) is not dict or set(original)!=_OLD_COMPLETE_FIELDS or original['schema']!=_PENDING_OLD_COHORT_COMPLETE
            or original['key_id']!=key_id or original['disposition']!='root_cohort_retired'
            or canonical_digest(original['retirement_original'])!=original['retirement_original_digest']):
        raise AuthorityUnavailable('Root requires the exact signed old-cohort retirement completion domain')
    for field in ('authority_id','installation_id','control_store_id','namespace','pending_start_digest','manifest_digest',
            'pointer_version','storage_generation','supervisor_spec_digest','peer'):
        if original[field]!=pending_start_original[field]:raise AuthorityUnavailable('Root old-cohort completion original pending scope differs')
    committed=digest({field:value for field,value in original.items() if field not in {'completion_digest','signature'}})
    signature=hmac.new(key_bytes,(original['schema']+'\n'+committed).encode(),'sha256').hexdigest()
    if committed!=original['completion_digest'] or not hmac.compare_digest(signature,original['signature']):
        raise AuthorityUnavailable('Root old-cohort completion HMAC differs')
    _require_old_cohort_material_v3(pending_start_original,original['retirement_original'])
    return original


_OLD_PHYSICAL_FIELDS=frozenset(('schema','authority_id','installation_id','control_store_id','namespace','pending_start_digest',
    'manifest_digest','pointer_version','storage_generation','supervisor_spec_digest','peer','retirement_original',
    'retirement_original_digest','observer_authority_process_original','retirement_digest','key_id','signature'))


def _verify_old_root_physical_retirement_v3(control,pending,original):
    if type(original) is not dict or set(original)!=_OLD_PHYSICAL_FIELDS or original['schema']!=_OLD_ROOT_PHYSICAL:
        raise AuthorityUnavailable('exact signed physical old Root retirement original required')
    control.verify_original_v1(original,'retirement_digest')
    for field in ('authority_id','installation_id','control_store_id','namespace','pending_start_digest','manifest_digest',
            'pointer_version','storage_generation','supervisor_spec_digest','peer'):
        if original[field]!=pending[field]:raise AuthorityUnavailable('physical old Root retirement changes its pending scope')
    if canonical_digest(original['retirement_original'])!=original['retirement_original_digest']:
        raise AuthorityUnavailable('physical old Root retirement material digest differs')
    return _require_old_cohort_material_v3(pending,original['retirement_original'])


def retain_writer_peer_old_root_retirement_v3(control,gate,*,retirement):
    from .installed_root_lifetime_observer_v3 import VerifiedInstalledRootCohortRetirementV3
    _require_gate(control,gate)
    if type(retirement) is not VerifiedInstalledRootCohortRetirementV3 or retirement.control is not control or retirement.gate is not gate:
        raise AuthorityUnavailable('actual installed continuous old Root lifetime observer required')
    with control._resource_sql_quantum_v3() as meter:
        retirement.require_current(control=control,gate=gate,meter=meter)
        pending=retirement.pending_original;_verify_pending_original_v3(control,pending)
        material=_require_old_cohort_material_v3(pending,retirement.original)
        with control._db(write=True) as db:
            _require_pending_schema_v3(control,db,meter)
            from .c09_storage_control_v1 import canonical
            saved=_bounded(db,meter).execute('SELECT pending_json FROM c09_writer_peer_pending_starts_v3 WHERE pending_start_digest=?',
                (pending['pending_start_digest'],)).fetchone()
            if saved!=(canonical(pending),):raise AuthorityUnavailable('physical old Root proof has no exact durable pending request')
            prior=_bounded(db,meter).execute('SELECT retirement_json FROM c09_writer_peer_old_root_retirements_v3 WHERE pending_start_digest=?',
                (pending['pending_start_digest'],)).fetchone()
            if prior is not None:
                retained=json.loads(prior[0]);_verify_old_root_physical_retirement_v3(control,pending,retained)
                return retained
            original=control.sign_original_v1(_OLD_ROOT_PHYSICAL,dict(schema=_OLD_ROOT_PHYSICAL,
                **{field:pending[field] for field in ('authority_id','installation_id','control_store_id','namespace','pending_start_digest',
                    'manifest_digest','pointer_version','storage_generation','supervisor_spec_digest','peer')},
                retirement_original=material,retirement_original_digest=canonical_digest(material),
                observer_authority_process_original=read_process_identity_v1(os.getpid())),'retirement_digest')
            _verify_old_root_physical_retirement_v3(control,pending,original)
            meter.write_row(db,'c09_writer_peer_old_root_retirements_v3',('pending_start_digest','retirement_json','retirement_digest','key_id','signature'),
                (pending['pending_start_digest'],canonical(original),original['retirement_digest'],control.key_id,original['signature']))
            retirement.require_current(control=control,gate=gate,meter=meter)
            return original


def read_writer_peer_old_root_retirement_v3(control,gate,*,pending_start_original):
    _require_gate(control,gate)
    with control._resource_sql_quantum_v3() as meter:
        pending=pending_start_original;_verify_pending_original_v3(control,pending)
        with control._db() as db:
            _require_pending_schema_v3(control,db,meter)
            row=_bounded(db,meter).execute('SELECT retirement_json FROM c09_writer_peer_old_root_retirements_v3 WHERE pending_start_digest=?',
                (pending['pending_start_digest'],)).fetchone()
            if row is None:return None
            original=json.loads(row[0]);_verify_old_root_physical_retirement_v3(control,pending,original)
            return original


def verify_writer_peer_old_root_retirement_original_v3(original,*,pending_start_original,key_id,key_bytes):
    import hmac
    from .c09_storage_control_v1 import digest
    if type(original) is not dict or set(original)!=_OLD_PHYSICAL_FIELDS or original['schema']!=_OLD_ROOT_PHYSICAL or original['key_id']!=key_id:
        raise AuthorityUnavailable('Root requires the exact signed physical old-cohort retirement domain')
    for field in ('authority_id','installation_id','control_store_id','namespace','pending_start_digest','manifest_digest',
            'pointer_version','storage_generation','supervisor_spec_digest','peer'):
        if original[field]!=pending_start_original[field]:raise AuthorityUnavailable('Root physical retirement original pending scope differs')
    committed=digest({field:value for field,value in original.items() if field not in {'retirement_digest','signature'}})
    signature=hmac.new(key_bytes,(original['schema']+'\n'+committed).encode(),'sha256').hexdigest()
    if committed!=original['retirement_digest'] or not hmac.compare_digest(signature,original['signature']):
        raise AuthorityUnavailable('Root physical old-cohort retirement HMAC differs')
    if canonical_digest(original['retirement_original'])!=original['retirement_original_digest']:
        raise AuthorityUnavailable('Root physical retirement material digest differs')
    _require_old_cohort_material_v3(pending_start_original,original['retirement_original'])
    return original



def _retain_root_cohort_peer_retirement_v3(control,operation_id,pending,physical,completion,meter):
    with control._db(write=True) as db:
        row=_bounded(db,meter).execute('SELECT admission_json FROM c09_writer_peer_admissions_v3 WHERE admission_digest=?',
            (completion['admission_digest'],)).fetchone()
        if row is None:raise AuthorityUnavailable('physical old-cohort peer retirement has no durable original admission')
        admission=json.loads(row[0]);control.verify_original_v1(admission,'admission_digest')
        if (admission['peer']!=pending['peer'] or admission['process_original']!=completion['observation']['main_process_original']):
            raise AuthorityUnavailable('physical old-cohort peer retirement changes its actual admitted process')
        prior=_bounded(db,meter).execute('SELECT retirement_json FROM c09_writer_peer_retirements_v3 WHERE operation_id=? AND admission_digest=?',
            (operation_id,admission['admission_digest'])).fetchone()
        if prior is not None:
            existing=json.loads(prior[0]);control.verify_original_v1(existing,'retirement_digest')
            if existing['schema']!=_ROOT_PEER_RETIREMENT:
                raise AuthorityUnavailable('old Root peer already has another immutable retirement observation domain')
            _verify_root_cohort_peer_retirement_v3(control,operation_id,admission,existing,meter)
            return existing
        original=control.sign_original_v1(_ROOT_PEER_RETIREMENT,dict(schema=_ROOT_PEER_RETIREMENT,
            authority_id=control.authority_id,installation_id=control.installation_id,namespace=pending['namespace'],
            maintenance_operation_id=operation_id,admission_digest=admission['admission_digest'],
            manifest_digest=admission['manifest_digest'],pointer_version=admission['pointer_version'],storage_generation=admission['storage_generation'],
            original_process=admission['process_original'],pending_start_digest=pending['pending_start_digest'],
            physical_retirement_digest=physical['retirement_digest'],observer_process_original=read_process_identity_v1(os.getpid())),'retirement_digest')
        from .c09_storage_control_v1 import canonical
        meter.write_row(db,'c09_writer_peer_retirements_v3',('operation_id','admission_digest','retirement_json','retirement_digest','key_id','signature'),
            (operation_id,admission['admission_digest'],canonical(original),original['retirement_digest'],control.key_id,original['signature']))
        return original


def _verify_root_cohort_peer_retirement_v3(control,operation_id,admission,original,meter):
    control.verify_original_v1(original,'retirement_digest')
    if (original['schema']!=_ROOT_PEER_RETIREMENT or original['maintenance_operation_id']!=operation_id
            or original['admission_digest']!=admission['admission_digest'] or original['original_process']!=admission['process_original']
            or original['authority_id']!=control.authority_id or original['installation_id']!=control.installation_id
            or original['namespace']!=admission['namespace'] or original['manifest_digest']!=admission['manifest_digest']
            or original['pointer_version']!=admission['pointer_version'] or original['storage_generation']!=admission['storage_generation']):
        raise AuthorityUnavailable('old-cohort peer retirement exact admission scope differs')
    with control._db() as db:
        request=_bounded(db,meter).execute('SELECT pending_json FROM c09_writer_peer_pending_starts_v3 WHERE pending_start_digest=?',
            (original['pending_start_digest'],)).fetchone()
        physical=_bounded(db,meter).execute('SELECT retirement_json FROM c09_writer_peer_old_root_retirements_v3 WHERE pending_start_digest=?',
            (original['pending_start_digest'],)).fetchone()
        completion=_bounded(db,meter).execute('SELECT completion_json FROM c09_writer_peer_pending_start_completions_v3 WHERE pending_start_digest=?',
            (original['pending_start_digest'],)).fetchone()
    if request is None or physical is None or completion is None:raise AuthorityUnavailable('old-cohort peer retirement lost its pending/physical/completion chain')
    pending=json.loads(request[0]);_verify_pending_original_v3(control,pending)
    material=json.loads(physical[0]);_verify_old_root_physical_retirement_v3(control,pending,material)
    completed=json.loads(completion[0]);_verify_pending_completion_v3(control,pending,completed)
    if material['retirement_digest']!=original['physical_retirement_digest'] or completed['admission_digest']!=admission['admission_digest']:
        raise AuthorityUnavailable('old-cohort peer retirement physical and completion commitments differ')
    return original
