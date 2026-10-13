"""Current stopped-storage rollback qualification after a failed candidate boot.

This is not a reconstructed live Authority. Exact current file/row observations
prove that business/journal/security originals stayed unchanged and that the
only new Core facts are bounded candidate bootstrap/session-incarnation facts.
Anything else remains stopped for qualified repair, preserving CURRENT files.
"""
from contextlib import closing
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time
from .contract import AuthorityUnavailable
from .c09_process_identity_v1 import require_process_retired_v1
from .c09_storage_control_v1 import file_observation_v1
from .d12_sqlite_backup_v2 import sqlite_logical_inventory_v2,_quote,_encoded_cell
from .d12_package_files_v2 import decode_package_selection_v2,next_package_selection_v2
from .d12_package_bootstrap_v2 import BOOTSTRAPS,decode_package_bootstrap_original_v2
from .d12_package_core_rows_v2 import COLUMNS,validate_d12_package_core_row_v2
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..runtime.lifecycle_operations_v1 import digest


def _open(path):
    path=Path(path)
    sidecars=tuple(Path(str(path)+suffix) for suffix in ('-wal','-shm','-journal'))
    # Caller already owns the genuine installation lease and has observed both
    # units retired. Immutable is legal only when no real companion exists.
    uri=path.as_uri()+('?mode=ro&immutable=1' if not any(p.exists() for p in sidecars) else '?mode=ro')
    db=sqlite3.connect(uri,uri=True,isolation_level=None)
    db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
    if db.execute('PRAGMA quick_check').fetchone()!=('ok',):raise AuthorityUnavailable('offline rollback actual SQLite integrity differs')
    return db


def _rows(db,table):
    rows=list(db.execute('SELECT * FROM '+_quote(table)))
    if len(rows)>100000:raise AuthorityUnavailable('offline rollback current row inventory exceeds bound')
    values={canonical_serialize(tuple(_encoded_cell(v) for v in row)):row for row in rows}
    if len(values)!=len(rows):raise AuthorityUnavailable('offline Core row identities are not unique')
    return values


def _verify_core_continuation(old,current,*,intent,source,selection):
    objects=lambda db:tuple(db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'))
    if objects(old)!=objects(current):raise AuthorityUnavailable('candidate changed Core schema; compatible rollback lane unavailable')
    changes=[];boots={}
    for table, in current.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        before,after=_rows(old,table),_rows(current,table)
        if before==after:continue
        if table==BOOTSTRAPS:
            if not set(before)<=set(after):raise AuthorityUnavailable('candidate removed or rewrote prior bootstrap originals')
            for encoded in sorted(set(after)-set(before)):
                row=after[encoded];value=validate_d12_package_core_row_v2(table,COLUMNS[table],row)
                if (value['operation_id']!=intent.operation_id or value['namespace']!=source['namespace']
                        or value['installation_id']!=intent.installation_id or value['accepted_original_digest']!=intent.digest
                        or value['package_epoch']!=selection.package_epoch or value['selection_digest']!=selection.selection_digest
                        or value['cohort_digest']!=selection.cohort_digest or value['manifest_sha256']!=selection.manifest_sha256
                        or value['lifecycle_epoch']!=intent.lifecycle_epoch or value['current_anchor']!=source['current_anchor']
                        or value['owner_head']!=source['owner_head'] or value['graph_metadata_digest']!=source['graph_metadata_digest']
                        or value['reconciliation_digest']!=source['reconciliation']['original_digest']
                        or value['history_inventory_digest']!=source['history_inventory']['inventory_digest']):
                    raise AuthorityUnavailable('candidate bootstrap does not bind exact unchanged current data')
                require_process_retired_v1(value['process_original'])
                boots[value['service_role']]=value
                changes.append(('retired_bootstrap',value['original_ref'],value['original_digest']))
        elif table=='authority_meta':
            b,a=dict(before.values()),dict(after.values())
            if set(b)!=set(a) or any(b[k]!=a[k] for k in b if k!='owner_session_boot_id'):
                raise AuthorityUnavailable('candidate changed Core authority/key/schema metadata')
            if any(type(values.get('owner_session_boot_id')) is not str or re.fullmatch(r'[A-Za-z0-9_-]{43}',values['owner_session_boot_id']) is None for values in (b,a)):
                raise AuthorityUnavailable('candidate Owner session boot identity is malformed')
            changes.append(('owner_session_boot_id',canonical_digest(b['owner_session_boot_id']),canonical_digest(a['owner_session_boot_id'])))
        elif table=='authority_d12_lifecycle_heads_v1':
            b={r[0]:r for r in before.values()};a={r[0]:r for r in after.values()};namespace=source['namespace']
            if set(b)!=set(a) or any(b[k]!=a[k] for k in b if k!=namespace):raise AuthorityUnavailable('candidate changed another lifecycle namespace')
            prior,actual=b[namespace],a[namespace]
            if (prior[1:5]!=(intent.installation_id,'quiescing',intent.lifecycle_epoch,intent.operation_id)
                    or actual[1:5]!=(intent.installation_id,'resuming',intent.lifecycle_epoch,intent.operation_id)):
                raise AuthorityUnavailable('candidate activation or unrelated lifecycle change denies offline rollback')
            changes.append(('lifecycle_resuming',actual[6],actual[5]))
        else:
            raise AuthorityUnavailable('current Core has additional original changes requiring live qualification: '+table)
    head=current.execute('SELECT installation_id,state,epoch,operation_id,head_digest,current_receipt_ref FROM authority_d12_lifecycle_heads_v1 WHERE namespace=?',(source['namespace'],)).fetchone()
    if head is None or head[:4] not in ((intent.installation_id,'quiescing',intent.lifecycle_epoch,intent.operation_id),(intent.installation_id,'resuming',intent.lifecycle_epoch,intent.operation_id)):
        raise AuthorityUnavailable('offline rollback is only for the original never-activated candidate')
    if head[1]=='resuming':
        authority=boots.get('authority')
        if authority is None or head[5]!=authority['original_ref'] or head[4]!=digest((source['namespace'],intent.installation_id,'resuming',intent.lifecycle_epoch,intent.operation_id,head[5])):
            raise AuthorityUnavailable('candidate resuming head lacks its actual retained Authority bootstrap')
    return tuple(sorted(changes))


def _read_retired_source_v2(component,operation_id,*,phase):
    from .d12_managed_backup_v2 import InstalledD12ManagedBackupV2,decode_backup_source_v2
    if type(component) is not InstalledD12ManagedBackupV2:raise TypeError('actual protected managed backup component required')
    selected=component._require_composition();intent=component.journal.read_verified_intent_v2(operation_id)
    receipts=component.journal.read_verified_receipts_v2(operation_id);pending=component.journal.read_verified_pending_stage_v2(operation_id)
    abort=phase=='abort'
    if phase not in {'rollback','abort'}:raise AuthorityUnavailable('fixed offline maintenance phase required')
    if (pending is None or pending['stage']!=('abort_retired' if abort else 'rollback_retired') or not receipts or receipts[-1].stage!=('abort_intent' if abort else 'rollback_retire_intent')
            or any(r.stage in {'active','rollback_complete'} for r in receipts)):
        raise AuthorityUnavailable('offline rollback source requires exact uncompleted retirement intent')
    if abort and any(r.stage in {'switch_intent','package_switched','rollback_retire_intent','rollback_package_switched'} for r in receipts):
        raise AuthorityUnavailable('a switched or unresolved pointer operation cannot abort as pre-switch')
    if any(not s.read_current_host_state_v1().stopped_and_drained for s in (component.host,component.authority)):
        raise AuthorityUnavailable('actual units must retire before any offline storage reads')
    component.reader.lease.require_held()
    forward=None;abort_source=None
    if abort:
        for ref,_ in receipts[-1].observation_refs:
            if ref==intent.accepted_original_ref:continue
            value=component.journal.read_verified_observation_v2(operation_id,ref)
            if value.kind=='backup_source' and value.body['backup_phase']=='forward':
                if abort_source is not None and abort_source!=value:raise AuthorityUnavailable('abort intent has ambiguous current source observations')
                abort_source=value
    if abort_source is not None:
        original=abort_source
        # A fresh paired source can include legitimate completed old work. It
        # qualifies CURRENT rows directly, with no reuse of an older backup.
    elif any(r.stage=='backup_ready' for r in receipts):
        forward=component.read_managed_backup_v2(operation_id)
        original=component.journal.read_verified_observation_v2(operation_id,forward['source_observation_ref'])
    else:
        if not abort:raise AuthorityUnavailable('offline rollback requires actual forward qualified backup')
        candidates={}
        for receipt in receipts:
            if receipt.stage not in {'quiescing','retire_intent','retired','abort_intent'}:continue
            for ref,_ in receipt.observation_refs:
                if ref==intent.accepted_original_ref:continue
                value=component.journal.read_verified_observation_v2(operation_id,ref)
                if value.kind=='backup_source' and value.body['backup_phase']=='forward':candidates[ref]=value
        if len(candidates)!=1:raise AuthorityUnavailable('pre-switch abort requires actual authenticated drained source')
        original=next(iter(candidates.values()))
    source=decode_backup_source_v2(original.body)
    if (forward is not None and (original.observation_digest!=forward['source_observation_digest'] or source['source_digest']!=forward['source_digest'])) or source['source_kind']!='paired_authority':
        raise AuthorityUnavailable('offline source has no actual authenticated forward Authority predecessor')
    # The old selection comes from the actual immutable accepted Core original
    # inside its qualified four-store snapshot, never caller recovery JSON.
    current_context=component.reader.read_verified_current_storage_v1();current_context.require_current('maintenance')
    current_core=Path(next(m['resolved_path'] for m in current_context.manifest['members'] if m['role']=='core'))
    core_copy=Path(forward['copies']['core']['backup_observation']['resolved_path']) if forward is not None else current_core
    with closing(_open(core_copy)) as db:
        if forward is None and sqlite_logical_inventory_v2(db,maximum_rows=100000,deadline=time.monotonic()+30)!=source['logical_inventories']['core']:
            raise AuthorityUnavailable('abort has no qualified prior Core snapshot for changed originals')
        table='authority_d12_package_acceptances_v2'
        row=db.execute(f'SELECT * FROM {table} WHERE namespace=? AND operation_id=?',(source['namespace'],operation_id)).fetchone()
        if row is None or validate_d12_package_core_row_v2(table,COLUMNS[table],row)!=intent:raise AuthorityUnavailable('backup actual accepted Core original absent')
        before=decode_package_selection_v2(json.loads(row[10]))
    _,candidate=component.files.read_registered_cohort_v2(intent.candidate_cohort_ref)
    desired=next_package_selection_v2(before,operation_id=operation_id,package=candidate.package,cohort_ref=candidate.cohort_ref,cohort_digest=candidate.cohort_digest)
    if selected!=(before if abort else desired):raise AuthorityUnavailable('offline maintenance source selected another package epoch')
    observed={}
    for ref,_ in receipts[-1].observation_refs:
        if ref!=intent.accepted_original_ref:
            value=component.journal.read_verified_observation_v2(operation_id,ref)
            if value.kind=='process':observed[value.body['service_role']]=value
    if set(observed)!={'host','authority'}:raise AuthorityUnavailable('offline rollback needs both original retirement identities')
    for role,supervisor in (('host',component.host),('authority',component.authority)):
        actual=supervisor.read_current_host_state_v1();prior=observed[role].body
        from .d12_installed_supervisor_v1 import process_observation_state_v1,D12SupervisorObservationV1
        state=process_observation_state_v1(prior)
        fixed=('unit_name','control_group','unit_fragment_sha256') if type(actual) is D12SupervisorObservationV1 else (
            'provider_kind','supervisor_id','spec_digest','service_role','installed_code_digest',
            'invocation_id','launcher_process_original','pid_namespace_identity','mount_namespace_identity')
        if (not actual.stopped_and_drained or any(state[k]!=asdict(actual)[k] for k in fixed)):raise AuthorityUnavailable('offline rollback actual supervisor retirement differs')
        if prior['process_original'] is not None:require_process_retired_v1(prior['process_original'])
        elif state['main_pid']!=0 or state['process_ids'] or state.get('active_state',state.get('state')) not in {'inactive','stopped','failed'}:
            raise AuthorityUnavailable('offline rollback prior absent process was not actually drained')
    component.reader.lease.require_held();context=component.reader.read_verified_current_storage_v1();context.require_current('maintenance')
    storage={'pointer_version':context.pointer_version,'manifest_digest':context.manifest_digest,'storage_generation':context.storage_generation,
        'members':[{k:m[k] for k in ('role','resolved_path','device','file_id','incarnation_or_journal_id')} for m in context.manifest['members']]}
    if context.stage not in {'READY','RELEASED'} or storage!=source['storage_identity']:raise AuthorityUnavailable('offline rollback current selected four-file identity changed')
    paths={m['role']:Path(m['resolved_path']) for m in context.manifest['members']};inventories={}
    with closing(_open(core_copy)) as old,closing(_open(paths['core'])) as current:
        changes=_verify_core_continuation(old,current,intent=intent,source=source,selection=selected)
    for role,path in paths.items():
        with closing(_open(path)) as db:inventories[role]=sqlite_logical_inventory_v2(db,maximum_rows=100000,deadline=time.monotonic()+30)
        if role!='core' and inventories[role]!=source['logical_inventories'][role]:raise AuthorityUnavailable('offline rollback current business/journal original advanced; live reconciliation required')
    proof={'schema':'d12.offline-current-core-continuation.v2','forward_source_observation_ref':original.observation_ref,
        'forward_source_observation_digest':original.observation_digest,'forward_source_digest':source['source_digest'],
        'before_core_inventory_digest':source['logical_inventories']['core']['inventory_digest'],
        'current_core_inventory_digest':inventories['core']['inventory_digest'],'changes':list(changes)}
    proof['continuation_digest']=canonical_digest(proof)
    value=dict(source,backup_phase=phase,selection_digest=selected.selection_digest,logical_inventories=inventories,
        source_kind='retired_current_core',continuation_proof=proof)
    value.pop('source_digest');value['source_digest']=canonical_digest(value)
    context.require_current('maintenance');component.reader.lease.require_held()
    if (component.files.read_selected_package_v2()[0]!=selected
            or component.journal.read_verified_receipts_v2(operation_id)!=receipts
            or component.journal.read_verified_pending_stage_v2(operation_id)!=pending
            or any(not s.read_current_host_state_v1().stopped_and_drained for s in (component.host,component.authority))):
        raise AuthorityUnavailable('offline maintenance pointer/process/original stage changed during current reads')
    return decode_backup_source_v2(value)


def read_retired_rollback_source_v2(component,operation_id):
    return _read_retired_source_v2(component,operation_id,phase='rollback')


def read_retired_abort_source_v2(component,operation_id):
    return _read_retired_source_v2(component,operation_id,phase='abort')
