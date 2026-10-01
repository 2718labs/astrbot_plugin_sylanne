"""Current selected package bootstrap and actual closed-to-active admission.

Only original supervisor stages, exact selected cohorts, actual process births,
loaded package bytes/native mappings, current Owner and actual four-store
reconciliation qualify these originals. No process start or selection mutation
is performed here. Business generation and immutable Owner grants stay intact.
"""
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys
from .contract import AuthorityUnavailable
from .c09_process_identity_v1 import read_process_identity_v1
from .d12_lifecycle_gate_v1 import read_lifecycle_head_in_tx_v1
from .d12_package_files_v2 import _sha,decode_package_selection_v2
from .d12_package_history_eligibility_v1 import decode_package_compatibility_original_v2
from .d12_package_selection_admission_v2 import require_actual_package_selection_v2
from .d12_managed_backup_v2 import decode_managed_backup_v2,decode_backup_source_v2,read_actual_backup_source_v2
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..runtime.lifecycle_operations_v1 import digest

BOOTSTRAPS='authority_d12_package_bootstraps_v2'
BOOT_DDL=f'CREATE TABLE {BOOTSTRAPS}(namespace TEXT NOT NULL,operation_id TEXT NOT NULL,service_role TEXT NOT NULL,package_epoch INTEGER NOT NULL,original_ref TEXT NOT NULL,original_digest TEXT NOT NULL,original_json TEXT NOT NULL,PRIMARY KEY(namespace,operation_id,service_role,package_epoch))'
BOOT_SCHEMA='d12.package-bootstrap-original.v2'
ACTIVE_SCHEMA='d12.package-activation-original.v2'
_BOOT_FIELDS=frozenset('schema namespace installation_id operation_id accepted_original_digest maintenance_phase lifecycle_epoch package_epoch selection_revision selection_digest cohort_digest manifest_sha256 service_role process_original invocation_id current_storage_identity_digest current_anchor owner_head graph_metadata_digest reconciliation_digest history_inventory_digest loaded_package_digest catalogue_hash ready_domains supervisor_intent_digest compatibility_observation_ref compatibility_observation_digest abort_source_observation_ref abort_source_observation_digest current_source_digest backup_manifest_digest original_ref original_digest'.split())
_ACTIVE_FIELDS=frozenset('schema namespace installation_id operation_id accepted_original_digest maintenance_phase lifecycle_epoch package_epoch selection_digest cohort_digest manifest_sha256 state authority_bootstrap_ref authority_bootstrap_digest host_bootstrap_ref host_bootstrap_digest current_storage_identity_digest current_anchor owner_head graph_metadata_digest reconciliation_digest history_inventory_digest supervisor_intent_digest compatibility_observation_ref compatibility_observation_digest abort_source_observation_ref abort_source_observation_digest current_source_digest original_ref original_digest'.split())


def _decode_original(raw,fields,schema,prefix):
    if type(raw) is not dict or set(raw)!=fields or raw['schema']!=schema:raise AuthorityUnavailable('closed package admission original required')
    body=dict(raw);commitment=body.pop('original_digest');ref=body.pop('original_ref')
    if not _sha(commitment) or canonical_digest(body)!=commitment or ref!=prefix+commitment:raise AuthorityUnavailable('package admission original commitment differs')
    phase=raw['maintenance_phase']
    if phase not in {'forward','rollback','abort_before_switch'}:raise AuthorityUnavailable('fixed package maintenance phase required')
    for name in ('lifecycle_epoch','package_epoch'):
        minimum=0 if name=='package_epoch' and phase=='abort_before_switch' else 1
        if type(raw[name]) is not int or raw[name]<minimum:raise AuthorityUnavailable('package admission epoch differs')
    absent={'compatibility_observation_digest','backup_manifest_digest'} if phase=='abort_before_switch' else {'abort_source_observation_digest'}
    if phase=='abort_before_switch':
        if raw['compatibility_observation_ref'] is not None or not raw['abort_source_observation_ref']:raise AuthorityUnavailable('abort requires its actual source proof, not candidate compatibility')
    elif raw['abort_source_observation_ref'] is not None or not raw['compatibility_observation_ref']:raise AuthorityUnavailable('candidate bootstrap requires actual compatibility')
    from ..runtime.restore_anchor import RestoreAnchor
    anchor=RestoreAnchor(**raw['current_anchor'])
    if anchor.namespace!=raw['namespace']:raise AuthorityUnavailable('package current admission namespace differs')
    for name in fields:
        if name.endswith('_digest') or name.endswith('_sha256'):
            if name in absent:
                if raw[name] is not None:raise AuthorityUnavailable('inapplicable package phase proof must be absent')
                continue
            if name=='reconciliation_digest' or name=='graph_metadata_digest':
                if type(raw[name]) is not str or not raw[name].startswith('sha256:') or not _sha(raw[name][7:]):raise AuthorityUnavailable('package graph/reconciliation commitment differs')
            elif not _sha(raw[name]):raise AuthorityUnavailable('package admission digest differs')
    return raw


def decode_package_bootstrap_original_v2(raw):
    _decode_original(raw,_BOOT_FIELDS,BOOT_SCHEMA,'d12-package-bootstrap:')
    role=raw['service_role'];process=raw['process_original']
    if (role not in {'authority','host'} or type(raw['selection_revision']) is not int or raw['selection_revision']<(0 if raw['maintenance_phase']=='abort_before_switch' else 1)
            or type(process) is not dict or set(process)!={'pid','platform','birth'} or process['platform']!='linux'
            or type(process['pid']) is not int or process['pid']<1 or type(process['birth']) is not str or not process['birth']
            or not raw['invocation_id'] or raw['ready_domains']!=([] if role=='authority' else [f'd{i:02}' for i in range(1,14)])):
        raise AuthorityUnavailable('package bootstrap actual role/birth/catalogue differs')
    return raw


def decode_package_activation_original_v2(raw):
    _decode_original(raw,_ACTIVE_FIELDS,ACTIVE_SCHEMA,'d12-package-activation:')
    if raw['state']!={'forward':'active','rollback':'rollback_complete','abort_before_switch':'abort_complete'}[raw['maintenance_phase']]:raise AuthorityUnavailable('package activation state differs')
    return raw


def _original(body,prefix):
    commitment=canonical_digest(body)
    return dict(body,original_ref=prefix+commitment,original_digest=commitment)


def _observations(service,intent,receipts):
    result={}
    for receipt in receipts:
        for ref,commitment in receipt.observation_refs:
            if ref==intent.accepted_original_ref:continue
            observed=service.journal.read_verified_observation_v2(intent.operation_id,ref)
            if observed.observation_digest!=commitment:raise AuthorityUnavailable('actual supervisor observation commitment differs')
            result[ref]=observed
    return result


def require_package_supervisor_scope_v2(service,*,operation_id,role):
    from .d12_package_maintenance_authority_v2 import InstalledD12PackageMaintenanceAuthorityV2
    if type(service) is not InstalledD12PackageMaintenanceAuthorityV2 or service.journal is None:raise AuthorityUnavailable('actual installed package supervisor required')
    with service.core._tx() as db:
        row,intent=service._row(db,operation_id);service._current_accepted_owner(db,row)
        head=read_lifecycle_head_in_tx_v1(db,service.namespace)
    if head.operation_id!=operation_id or head.epoch!=intent.lifecycle_epoch or head.state not in {'quiescing','drained','resuming','active'}:raise AuthorityUnavailable('package operation no longer owns actual lifecycle')
    actual=service.journal.read_verified_intent_v2(operation_id)
    receipts=service.journal.read_verified_receipts_v2(operation_id)
    pending=service.journal.read_verified_pending_stage_v2(operation_id)
    if actual!=intent or not receipts or any(r.stage=='unknown' for r in receipts):raise AuthorityUnavailable('package original supervisor state is unknown or differs')
    abort=any(r.stage=='abort_intent' for r in receipts) or pending is not None and pending['stage']=='abort_intent'
    rollback=any(r.stage=='rollback_retire_intent' for r in receipts) or pending is not None and pending['stage']=='rollback_retire_intent'
    selected,cohort,_=service.files.read_selected_configuration_cohort_v2()
    purpose='abort_bootstrap' if abort else 'rollback_source' if role=='rollback_source' else 'rollback_bootstrap' if rollback else 'candidate_bootstrap'
    before,candidate,rolled=require_actual_package_selection_v2(service,intent=intent,accepted_row=row,selected=selected,purpose=purpose)
    if role=='rollback_source':
        if head.state=='active' or not rollback:raise AuthorityUnavailable('completed operation cannot restart rollback maintenance')
        allowed={'rollback_retire_intent'}
    elif role=='authority':allowed={'abort_authority_start_intent','abort_authority_bootstrap_ready'} if abort else {'rollback_authority_start_intent','rollback_authority_bootstrap_ready'} if rollback else {'authority_start_intent','authority_bootstrap_ready'}
    elif role=='host':allowed={'abort_host_start_intent','abort_bootstrap_ready','abort_complete'} if abort else {'rollback_host_start_intent','rollback_bootstrap_ready','rollback_complete'} if rollback else {'host_start_intent','bootstrap_ready','active'}
    elif role=='activate':allowed={'abort_bootstrap_ready','abort_complete'} if abort else {'rollback_bootstrap_ready','rollback_complete'} if rollback else {'bootstrap_ready','active'}
    else:raise AuthorityUnavailable('fixed package bootstrap role required')
    stage=pending['stage'] if pending is not None else receipts[-1].stage
    if stage not in allowed:
        replay_stages={'host_start_intent','bootstrap_ready','active','rollback_host_start_intent','rollback_bootstrap_ready','rollback_complete','abort_host_start_intent','abort_bootstrap_ready','abort_complete'}
        with service.core._tx() as db:
            saved=db.execute(f'SELECT 1 FROM {BOOTSTRAPS} WHERE namespace=? AND operation_id=? AND service_role=? AND package_epoch=?',(service.namespace,operation_id,role,selected.package_epoch)).fetchone()
        if saved is None or stage not in replay_stages:raise AuthorityUnavailable('no actual original supervisor start/activation intent for this process')
    if pending is None:
        # A completed start may be replayed, but a new activation still needs
        # its separately durable external intent before the Core CAS.
        stage_original_digest=receipts[-1].receipt_digest
    else:stage_original_digest=pending['intent_digest']
    if role=='rollback_source':return dict(intent=intent,row=row,head=head,selected=selected,cohort=cohort,rollback=True,pending=pending,receipts=receipts)
    observations=_observations(service,intent,receipts)
    if abort:
        if any(r.stage in {'switch_intent','package_switched','rollback_retire_intent','rollback_package_switched'} for r in receipts):raise AuthorityUnavailable('pre-switch abort cannot cover a switched/ambiguous pointer')
        retired=[r for r in receipts if r.stage=='abort_retired']
        if len(retired)!=1:raise AuthorityUnavailable('actual abort process retirement/source qualification absent')
        sources=[observations[ref] for ref,_ in retired[0].observation_refs if ref in observations and observations[ref].kind=='backup_source' and observations[ref].body['backup_phase']=='abort']
        if len(sources)!=1:raise AuthorityUnavailable('one exact current-data abort source observation required')
        source_observation=sources[0];source=decode_backup_source_v2(source_observation.body)
        if (source['source_kind']!='retired_current_core' or source['accepted_original_digest']!=intent.digest
                or source['selection_digest']!=before.selection_digest):raise AuthorityUnavailable('abort source does not qualify original current package/data')
        continuation=source['continuation_proof'];prior=observations.get(continuation['forward_source_observation_ref'])
        if prior is None or prior.kind!='backup_source' or prior.observation_digest!=continuation['forward_source_observation_digest']:raise AuthorityUnavailable('abort source authenticated predecessor absent')
        previous=decode_backup_source_v2(prior.body)
        if (previous['source_kind']!='paired_authority' or previous['backup_phase']!='forward'
                or previous['source_digest']!=continuation['forward_source_digest']
                or any(source[k]!=previous[k] for k in ('storage_identity','current_anchor','owner_head','graph_metadata_digest','reconciliation','history_inventory'))
                or any(source['logical_inventories'][r]!=previous['logical_inventories'][r] for r in ('graph','deletion','execution'))):raise AuthorityUnavailable('abort source preserved current obligations differ')
        return dict(intent=intent,row=row,head=head,selected=selected,cohort=cohort,rollback=False,abort=True,pending=pending,
            receipts=receipts,observations=observations,compatibility=None,abort_source=source_observation,backup=None,source=source,stage_original_digest=stage_original_digest)
    switched_stage='rollback_package_switched' if rollback else 'package_switched'
    switched=[r for r in receipts if r.stage==switched_stage]
    if not switched:raise AuthorityUnavailable('actual selected package switch receipt absent')
    pointer=[observations[ref] for ref,_ in switched[-1].observation_refs if ref in observations and observations[ref].kind=='package_selection']
    if len(pointer)!=1 or decode_package_selection_v2(pointer[0].body)!=selected:raise AuthorityUnavailable('actual current package selection observation differs')
    compatibility_stage='rollback_compatible_current_data' if rollback else 'compatible_no_data_migration'
    stages=[r for r in receipts if r.stage==compatibility_stage and r.stage_sequence<switched[-1].stage_sequence]
    if not stages:raise AuthorityUnavailable('actual compatibility original absent before switch')
    compats=[observations[ref] for ref,_ in stages[-1].observation_refs if ref in observations and observations[ref].kind=='package_compatibility']
    if len(compats)!=1:raise AuthorityUnavailable('exact actual candidate compatibility observation required')
    comp=compats[0];body=decode_package_compatibility_original_v2(comp.body)
    predecessor=candidate if rollback else before
    if (body['operation_id']!=operation_id or body['accepted_original_digest']!=intent.digest
            or body['before_selection_digest']!=predecessor.selection_digest or body['candidate_manifest_sha256']!=selected.manifest_sha256
            or body['candidate_cohort_ref']!=selected.cohort_ref or body['candidate_cohort_digest']!=selected.cohort_digest
            or body['compatibility_plan_digest']!=intent.compatibility_plan_digest):raise AuthorityUnavailable('compatibility belongs to another package/data predecessor')
    backup_observation=observations.get(body['backup_observation_ref'])
    if backup_observation is None or backup_observation.kind!='managed_backup' or backup_observation.observation_digest!=body['backup_observation_digest']:raise AuthorityUnavailable('compatibility actual managed backup original absent')
    backup=decode_managed_backup_v2(backup_observation.body)
    source_observation=observations.get(backup['source_observation_ref'])
    if source_observation is None or source_observation.kind!='backup_source' or source_observation.observation_digest!=backup['source_observation_digest']:raise AuthorityUnavailable('backup actual source qualification absent')
    source=decode_backup_source_v2(source_observation.body)
    phase='rollback' if rollback else 'forward'
    if (backup['backup_phase']!=phase or source['backup_phase']!=phase or source['selection_digest']!=predecessor.selection_digest
            or backup['accepted_original_digest']!=intent.digest or source['accepted_original_digest']!=intent.digest
            or source['source_digest']!=backup['source_digest'] or source['history_inventory']!=backup['history_inventory']
            or source['logical_inventories']!={r:c['logical_inventory'] for r,c in backup['copies'].items()}
            or canonical_digest(backup['storage_identity'])!=body['storage_identity_digest']
            or backup['history_inventory']['inventory_digest']!=body['history_inventory_digest']
            or canonical_digest(source['logical_inventories'])!=body['logical_inventory_digest']):raise AuthorityUnavailable('compatibility actual current backup obligations differ')
    return dict(intent=intent,row=row,head=head,selected=selected,cohort=cohort,rollback=rollback,abort=False,pending=pending,
        receipts=receipts,observations=observations,compatibility=comp,backup=backup,source=source,stage_original_digest=stage_original_digest)


def _runtime(service,scope,credential):
    observed=read_actual_backup_source_v2(service,credential=credential,operation_id=scope['intent'].operation_id,
        _selection_purpose='abort_bootstrap' if scope.get('abort') else 'rollback_bootstrap' if scope['rollback'] else 'candidate_bootstrap')['backup_source']
    source=scope['source']
    for key in ('storage_identity','current_anchor','owner_head','graph_metadata_digest','reconciliation','history_inventory'):
        if observed[key]!=source[key]:raise AuthorityUnavailable('current package bootstrap changed retained original '+key)
    for role in ('graph','deletion','execution'):
        if observed['logical_inventories'][role]!=source['logical_inventories'][role]:raise AuthorityUnavailable('compatible bootstrap changed current business/journal originals')
    return observed


def _loaded_authority_package(service,selected,cohort):
    root=Path(cohort.package.package_root).resolve(strict=True)
    if service.lifecycle.package_root!=root or service.lifecycle.expected_manifest_digest!=selected.manifest_sha256:
        raise AuthorityUnavailable('Authority composition does not use actual current selected package')
    modules=[]
    for name,module in tuple(sys.modules.items()):
        path=getattr(module,'__file__',None)
        if name=='sylanne3' or name.startswith('sylanne3.'):
            if path is None:continue
            file=Path(path).resolve(strict=True)
            if not file.is_relative_to(root/'rewrite'/'sylanne3'):raise AuthorityUnavailable('Authority loaded code belongs to another package')
            modules.append((name,str(file.relative_to(root))))
    if not modules:raise AuthorityUnavailable('actual loaded Authority modules absent')
    verified=service.files.verify_registered_package_v2(cohort.package)
    return canonical_digest((selected.selection_digest,tuple(sorted(modules)),verified.catalogue_hash)),verified.catalogue_hash


def _process(service,role,process_id=None,invocation_id=None):
    supervisor=service.authority_supervisor if role=='authority' else service.lifecycle.supervisor
    if supervisor is None:raise AuthorityUnavailable('fixed actual Authority supervisor absent')
    observed=supervisor.read_current_host_state_v1()
    expected=os.getpid() if role=='authority' else process_id
    identity=read_process_identity_v1(expected)
    if (identity is None or observed.active_state!='active' or observed.main_pid!=expected or expected not in observed.process_ids
            or invocation_id is not None and observed.invocation_id!=invocation_id):raise AuthorityUnavailable('package bootstrap is not the exact actual supervised process')
    return observed,identity


def _save_bootstrap(service,scope,observed,identity,runtime,role,loaded,catalogue,domains):
    selected=scope['selected'];intent=scope['intent'];comp=scope['compatibility']
    body=dict(schema=BOOT_SCHEMA,namespace=service.namespace,installation_id=service.installation_id,
        operation_id=intent.operation_id,accepted_original_digest=intent.digest,maintenance_phase='abort_before_switch' if scope.get('abort') else 'rollback' if scope['rollback'] else 'forward',lifecycle_epoch=intent.lifecycle_epoch,
        package_epoch=selected.package_epoch,selection_revision=selected.revision,selection_digest=selected.selection_digest,
        cohort_digest=selected.cohort_digest,manifest_sha256=selected.manifest_sha256,service_role=role,process_original=identity,
        invocation_id=observed.invocation_id,current_storage_identity_digest=canonical_digest(runtime['storage_identity']),
        current_anchor=runtime['current_anchor'],owner_head=runtime['owner_head'],graph_metadata_digest=runtime['graph_metadata_digest'],
        reconciliation_digest=runtime['reconciliation']['original_digest'],history_inventory_digest=runtime['history_inventory']['inventory_digest'],
        loaded_package_digest=loaded,catalogue_hash=catalogue,ready_domains=list(domains),supervisor_intent_digest=scope['stage_original_digest'],
        compatibility_observation_ref=None if comp is None else comp.observation_ref,compatibility_observation_digest=None if comp is None else comp.observation_digest,
        abort_source_observation_ref=scope['abort_source'].observation_ref if scope.get('abort') else None,
        abort_source_observation_digest=scope['abort_source'].observation_digest if scope.get('abort') else None,current_source_digest=scope['source']['source_digest'],
        backup_manifest_digest=None if scope['backup'] is None else scope['backup']['manifest_digest'])
    original=decode_package_bootstrap_original_v2(_original(body,'d12-package-bootstrap:'))
    with service.fences._frozen() as (db,deletion,execution,_):
        row,current_intent=service._row(db,intent.operation_id);owner=service._current_accepted_owner(db,row)
        head=read_lifecycle_head_in_tx_v1(db,service.namespace)
        if (current_intent!=intent or owner.authorization_head!=runtime['owner_head'] or head.operation_id!=intent.operation_id
                or head.epoch!=intent.lifecycle_epoch or head.state not in {'quiescing','drained','resuming','active'}
                or asdict(service.fences._current_locked(db,deletion,execution,require_clear=False))!=runtime['current_anchor']
                or service.core._row(db,service.namespace)[9]!='clear' or service.lifecycle._counts(db)[:2]!=(0,0)):
            raise AuthorityUnavailable('package bootstrap original Owner/lifecycle/head changed')
        prior=db.execute(f'SELECT original_json FROM {BOOTSTRAPS} WHERE namespace=? AND operation_id=? AND service_role=? AND package_epoch=?',(service.namespace,intent.operation_id,role,selected.package_epoch)).fetchone()
        if prior is not None:
            saved=decode_package_bootstrap_original_v2(json.loads(prior[0]))
            # The same actual birth may replay after its start receipt advanced.
            compare=dict(original);compare['supervisor_intent_digest']=saved['supervisor_intent_digest'];compare.pop('original_ref');compare.pop('original_digest')
            if _original(compare,'d12-package-bootstrap:')!=saved:raise AuthorityUnavailable('package bootstrap replay changes original process/data')
            return saved
        if head.state=='active':raise AuthorityUnavailable('active package has no original bootstrap for this birth')
        db.execute(f'INSERT INTO {BOOTSTRAPS} VALUES(?,?,?,?,?,?,?)',(service.namespace,intent.operation_id,role,selected.package_epoch,original['original_ref'],original['original_digest'],canonical_serialize(original)))
        if role=='authority':
            state=(service.namespace,service.installation_id,'resuming',head.epoch,intent.operation_id,original['original_ref'])
            changed=db.execute('UPDATE authority_d12_lifecycle_heads_v1 SET state=?,head_digest=?,current_receipt_ref=? WHERE namespace=? AND epoch=? AND head_digest=?',('resuming',digest(state),original['original_ref'],service.namespace,head.epoch,head.head_digest)).rowcount
            if changed!=1:raise AuthorityUnavailable('package bootstrap lifecycle CAS changed')
    return original


def read_current_authority_package_bootstrap_v2(service,*,credential,operation_id):
    service.core._require(credential,'d12_package_bootstrap',service.namespace)
    scope=require_package_supervisor_scope_v2(service,operation_id=operation_id,role='authority')
    observed,identity=_process(service,'authority')
    loaded,catalogue=_loaded_authority_package(service,scope['selected'],scope['cohort'])
    saved=_read_same_bootstrap(service,scope,'authority',observed,identity)
    if saved is not None:return saved
    runtime=_runtime(service,scope,credential)
    if read_process_identity_v1(identity['pid'])!=identity:raise AuthorityUnavailable('Authority process birth changed during bootstrap')
    return _save_bootstrap(service,scope,observed,identity,runtime,'authority',loaded,catalogue,())


def read_current_maintenance_bootstrap_v2(service,*,credential,process_id,invocation_id,selection_revision,cohort_digest):
    service.core._require(credential,'d12_package_supervisor',service.namespace)
    selected,_,_=service.files.read_selected_configuration_cohort_v2()
    with service.core._tx() as db:current_head=read_lifecycle_head_in_tx_v1(db,service.namespace)
    if current_head is None or current_head.operation_id is None:raise AuthorityUnavailable('actual package lifecycle operation absent')
    operation_id=current_head.operation_id
    scope=require_package_supervisor_scope_v2(service,operation_id=operation_id,role='host')
    if selected.revision!=selection_revision or selected.cohort_digest!=cohort_digest:raise AuthorityUnavailable('Host selected bootstrap revision/cohort differs')
    observed,identity=_process(service,'host',process_id,invocation_id)
    authority_identity=read_process_identity_v1(os.getpid())
    with service.core._tx() as db:
        row=db.execute(f'SELECT original_json FROM {BOOTSTRAPS} WHERE namespace=? AND operation_id=? AND service_role=? AND package_epoch=?',(service.namespace,operation_id,'authority',selected.package_epoch)).fetchone()
        if row is None:raise AuthorityUnavailable('actual current Authority bootstrap original absent')
        authority=decode_package_bootstrap_original_v2(json.loads(row[0]))
        if authority['process_original']!=authority_identity:raise AuthorityUnavailable('Authority restarted outside the original package bootstrap')
    return dict(operation_id=operation_id,maintenance_phase='abort_before_switch' if scope.get('abort') else 'rollback' if scope['rollback'] else 'forward',lifecycle_epoch=scope['intent'].lifecycle_epoch,package_epoch=selected.package_epoch,
        selection_revision=selected.revision,cohort_digest=selected.cohort_digest,selection_digest=selected.selection_digest,
        process_original=identity,invocation_id=observed.invocation_id,state='bootstrap_only')


def register_current_package_host_ready_v2(service,*,credential,peer_certificate_sha256,peer_profile_id,
        operation_id,process_id,invocation_id,selection_revision,cohort_digest,catalogue_hash,ready_domains):
    service.core._require(credential,'d12_package_bootstrap',service.namespace)
    if (peer_certificate_sha256,peer_profile_id)!=service.lifecycle.peer:raise AuthorityUnavailable('actual package Host peer differs')
    admitted=read_current_maintenance_bootstrap_v2(service,credential=credential,process_id=process_id,invocation_id=invocation_id,
        selection_revision=selection_revision,cohort_digest=cohort_digest)
    if admitted['operation_id']!=operation_id:raise AuthorityUnavailable('Host ready operation differs from actual selected start')
    scope=require_package_supervisor_scope_v2(service,operation_id=operation_id,role='host')
    observed,identity=_process(service,'host',process_id,invocation_id)
    verified=service.lifecycle._verify_package_in_host(observed)
    if catalogue_hash!=verified.catalogue_hash or ready_domains!=tuple(f'd{i:02}' for i in range(1,14)):
        raise AuthorityUnavailable('actual package native/thirteen-domain readiness differs')
    saved=_read_same_bootstrap(service,scope,'host',observed,identity)
    if saved is not None:
        with service.core._tx() as db:head=read_lifecycle_head_in_tx_v1(db,service.namespace)
        return {'bootstrap_original':saved,'lifecycle_state':head.state,'lifecycle_epoch':head.epoch}
    runtime=_runtime(service,scope,credential)
    loaded=canonical_digest((scope['selected'].selection_digest,identity,observed.observation_digest,catalogue_hash,ready_domains))
    original=_save_bootstrap(service,scope,observed,identity,runtime,'host',loaded,catalogue_hash,ready_domains)
    with service.core._tx() as db:head=read_lifecycle_head_in_tx_v1(db,service.namespace)
    return {'bootstrap_original':original,'lifecycle_state':head.state,'lifecycle_epoch':head.epoch}


def _read_same_bootstrap(service,scope,role,observed,identity):
    with service.core._tx() as db:
        raw=db.execute(f'SELECT original_json FROM {BOOTSTRAPS} WHERE namespace=? AND operation_id=? AND service_role=? AND package_epoch=?',
            (service.namespace,scope['intent'].operation_id,role,scope['selected'].package_epoch)).fetchone()
        if raw is None:return None
        value=decode_package_bootstrap_original_v2(json.loads(raw[0]));row,intent=service._row(db,scope['intent'].operation_id)
        service._current_accepted_owner(db,row);head=read_lifecycle_head_in_tx_v1(db,service.namespace)
        if (value['process_original']!=identity or value['invocation_id']!=observed.invocation_id
                or value['selection_digest']!=scope['selected'].selection_digest or value['accepted_original_digest']!=intent.digest
                or head.operation_id!=intent.operation_id or head.epoch!=intent.lifecycle_epoch):raise AuthorityUnavailable('same original package bootstrap replay differs')
    return value


def finish_current_package_activation_v2(service,*,credential,operation_id):
    from .d12_package_maintenance_authority_v2 import ACTIVATIONS,HEADS
    service.core._require(credential,'d12_package_activate',service.namespace)
    scope=require_package_supervisor_scope_v2(service,operation_id=operation_id,role='activate')
    selected=scope['selected'];intent=scope['intent'];terminal='abort_complete' if scope.get('abort') else 'rollback_complete' if scope['rollback'] else 'active'
    authority_observation,authority_identity=_process(service,'authority')
    host_observation=service.lifecycle.supervisor.read_current_host_state_v1()
    host_observation,host_identity=_process(service,'host',host_observation.main_pid,host_observation.invocation_id)
    authority=_read_same_bootstrap(service,scope,'authority',authority_observation,authority_identity)
    host=_read_same_bootstrap(service,scope,'host',host_observation,host_identity)
    if authority is None or host is None:raise AuthorityUnavailable('both current actual package bootstraps required before activation')
    service.lifecycle._verify_package_in_host(host_observation)
    _loaded_authority_package(service,selected,scope['cohort'])
    with service.core._tx() as db:
        prior=db.execute(f'SELECT original_json FROM {ACTIVATIONS} WHERE namespace=? AND operation_id=?',(service.namespace,operation_id)).fetchone()
        if prior is not None:
            original=decode_package_activation_original_v2(json.loads(prior[0]));head=read_lifecycle_head_in_tx_v1(db,service.namespace)
            if (original['selection_digest']!=selected.selection_digest or original['authority_bootstrap_ref']!=authority['original_ref']
                    or original['host_bootstrap_ref']!=host['original_ref'] or head.state!='active'
                    or head.operation_id!=operation_id or head.epoch!=intent.lifecycle_epoch):raise AuthorityUnavailable('package activation replay differs from actual current admitted process')
            return original
    pending=scope['pending']
    if pending is None or pending['stage']!=terminal:raise AuthorityUnavailable('durable original external activation intent required')
    observations=scope['observations']
    stage='abort_bootstrap_ready' if scope.get('abort') else 'rollback_bootstrap_ready' if scope['rollback'] else 'bootstrap_ready'
    ready=[r for r in scope['receipts'] if r.stage==stage]
    if not ready:raise AuthorityUnavailable('independent actual bootstrap-ready stage absent')
    originals=[observations[ref] for ref,_ in ready[-1].observation_refs if ref in observations and observations[ref].kind=='package_bootstrap']
    if {v.body['original_ref'] for v in originals}!={authority['original_ref'],host['original_ref']}:
        raise AuthorityUnavailable('independent supervisor readiness does not name both actual Core bootstrap originals')
    for observed in originals:
        expected=authority if observed.body['service_role']=='authority' else host
        if decode_package_bootstrap_original_v2(observed.body)!=expected:raise AuthorityUnavailable('supervisor bootstrap original differs from actual Core')
    runtime=_runtime(service,scope,credential)
    comp=scope['compatibility']
    body=dict(schema=ACTIVE_SCHEMA,namespace=service.namespace,installation_id=service.installation_id,operation_id=operation_id,
        accepted_original_digest=intent.digest,maintenance_phase='abort_before_switch' if scope.get('abort') else 'rollback' if scope['rollback'] else 'forward',lifecycle_epoch=intent.lifecycle_epoch,package_epoch=selected.package_epoch,
        selection_digest=selected.selection_digest,cohort_digest=selected.cohort_digest,manifest_sha256=selected.manifest_sha256,state=terminal,
        authority_bootstrap_ref=authority['original_ref'],authority_bootstrap_digest=authority['original_digest'],
        host_bootstrap_ref=host['original_ref'],host_bootstrap_digest=host['original_digest'],
        current_storage_identity_digest=canonical_digest(runtime['storage_identity']),current_anchor=runtime['current_anchor'],
        owner_head=runtime['owner_head'],graph_metadata_digest=runtime['graph_metadata_digest'],
        reconciliation_digest=runtime['reconciliation']['original_digest'],history_inventory_digest=runtime['history_inventory']['inventory_digest'],
        supervisor_intent_digest=pending['intent_digest'],compatibility_observation_ref=None if comp is None else comp.observation_ref,compatibility_observation_digest=None if comp is None else comp.observation_digest,
        abort_source_observation_ref=scope['abort_source'].observation_ref if scope.get('abort') else None,
        abort_source_observation_digest=scope['abort_source'].observation_digest if scope.get('abort') else None,current_source_digest=scope['source']['source_digest'])
    original=decode_package_activation_original_v2(_original(body,'d12-package-activation:'))
    # All OS/package/journal-observation reads above are outside the short Core
    # admission CAS. The original current independent heads remain exact here.
    if service.files.read_selected_package_v2()[0]!=selected:raise AuthorityUnavailable('selection changed before package activation')
    with service.fences._frozen() as (db,deletion,execution,_):
        with service.lifecycle._condition:
            row,actual=service._row(db,operation_id);owner=service._current_accepted_owner(db,row)
            head=read_lifecycle_head_in_tx_v1(db,service.namespace);live,pending_count,rpcs=service.lifecycle._counts(db)
            anchor=service.fences._current_locked(db,deletion,execution,require_clear=False)
            if (actual!=intent or owner.authorization_head!=runtime['owner_head'] or head.operation_id!=operation_id
                    or head.epoch!=intent.lifecycle_epoch or head.state!='resuming' or live or pending_count or rpcs>1
                    or service.core._row(db,service.namespace)[9]!='clear' or asdict(anchor)!=runtime['current_anchor']):raise AuthorityUnavailable('package current Owner/lifecycle/ledger admission changed')
            for boot in (authority,host):
                stored=db.execute(f'SELECT original_json FROM {BOOTSTRAPS} WHERE namespace=? AND operation_id=? AND service_role=? AND package_epoch=?',
                    (service.namespace,operation_id,boot['service_role'],selected.package_epoch)).fetchone()
                if stored!=(canonical_serialize(boot),):raise AuthorityUnavailable('actual package bootstrap original changed')
            db.execute(f'INSERT INTO {ACTIVATIONS} VALUES(?,?,?,?,?)',(service.namespace,operation_id,original['original_ref'],original['original_digest'],canonical_serialize(original)))
            state=(service.namespace,service.installation_id,'active',head.epoch,operation_id,original['original_ref'])
            changed=db.execute('UPDATE authority_d12_lifecycle_heads_v1 SET state=?,head_digest=?,current_receipt_ref=? WHERE namespace=? AND epoch=? AND head_digest=?',
                ('active',digest(state),original['original_ref'],service.namespace,head.epoch,head.head_digest)).rowcount
            if changed!=1:raise AuthorityUnavailable('package activation lifecycle CAS changed')
            db.execute(f'UPDATE {HEADS} SET stage=?,supervisor_receipt_digest=?,hold_code=NULL WHERE namespace=? AND operation_id=?',
                (terminal,scope['receipts'][-1].receipt_digest,service.namespace,operation_id))
            service.core._event(db,service.namespace,'d12_package_activated',anchor.activation_generation,(operation_id,original['original_digest'],selected.selection_digest))
    return original


def read_current_package_host_bootstrap_v2(service,*,credential,operation_id):
    """Supervisor inspection of the Host's original; never a registration."""
    service.core._require(credential,'d12_package_supervisor',service.namespace)
    scope=require_package_supervisor_scope_v2(service,operation_id=operation_id,role='host')
    observed=service.lifecycle.supervisor.read_current_host_state_v1()
    observed,identity=_process(service,'host',observed.main_pid,observed.invocation_id)
    _,storage=service.lifecycle._storage()
    original=_read_same_bootstrap(service,scope,'host',observed,identity)
    if original is not None and original['current_storage_identity_digest']!=canonical_digest(storage):
        raise AuthorityUnavailable('saved Host bootstrap current storage changed')
    with service.core._tx() as db:head=read_lifecycle_head_in_tx_v1(db,service.namespace)
    return {'bootstrap_original':original,'lifecycle_state':head.state,'lifecycle_epoch':head.epoch}
