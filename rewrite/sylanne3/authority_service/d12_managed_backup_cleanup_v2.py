"""Versioned revoke-then-destroy disposition for registered nonrestorable backups.

Current signed C09 recovery facts, each historical execution-row commitment,
model unit obligation and immutable budget receipt must remain independently
readable before old backup bytes are removed. Unknown files or incomplete
coverage keep the exact operation held. No snapshot is restored or replaced.
"""
from __future__ import annotations
from contextlib import closing
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from .contract import AuthorityUnavailable
from .c09_surface_cleanup_v1 import InstalledC09SurfaceCleanupV1,_directory_files
from .c09_storage_control_v1 import file_observation_v1
from .c09_recovery_resolver_v4 import InstalledSanitizedRecoveryResolverV4
from .d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2
from .d12_managed_backup_v2 import decode_managed_backup_v2
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize

DISPOSITION_SCHEMA='sylanne3.d12.backup-revoked-destruction.v2'
COVERAGE_SCHEMA='sylanne3.d12.backup-recovery-coverage.v2'


def _open(path):
    db=sqlite3.connect(Path(path).as_uri()+'?mode=ro',uri=True,isolation_level=None)
    db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
    return db


def _row_commitment(row):
    return canonical_digest((row[0],row[1],row[2],row[3],row[5],row[6],hashlib.sha256(row[4]).hexdigest()))


def _facts(resolver):
    context,frames=resolver.read_verified_frames_v4()
    if not frames:raise AuthorityUnavailable('actual sanitized recovery frames absent')
    executions={};bindings={};d11={};unknown={}
    for original,facts,mapping in frames:
        for fact in facts.executions:
            if fact.execution_id in executions and executions[fact.execution_id]!=fact:raise AuthorityUnavailable('current execution recovery conflict')
            executions[fact.execution_id]=fact
        for binding in mapping.execution_bindings:
            if binding.execution_id in bindings and bindings[binding.execution_id]!=binding:raise AuthorityUnavailable('current recovery binding conflict')
            bindings[binding.execution_id]=binding
        for fact in facts.d11_facts:
            key=(fact.parent_budget_id,fact.idempotency_id,fact.cost_unit)
            if key in d11 and d11[key]!=fact:raise AuthorityUnavailable('current per-unit budget recovery conflict')
            d11[key]=fact
        for fact in facts.unknown_facts:
            if fact.execution_id in unknown and unknown[fact.execution_id]!=fact:raise AuthorityUnavailable('current unknown recovery conflict')
            unknown[fact.execution_id]=fact
    return context,frames,executions,bindings,d11,unknown


def _budget_coverage(old,current,namespace,d11):
    from ..runtime.budget import get_budget_lease,BudgetReceipt
    coverage=[]
    exists=old.execute("SELECT 1 FROM sqlite_master WHERE name='runtime_budget_leases'").fetchone()
    if not exists:return coverage
    for (lease_id,) in old.execute('SELECT lease_id FROM runtime_budget_leases WHERE bot_id=? AND persona_id=? ORDER BY lease_id',namespace.as_tuple):
        prior=get_budget_lease(old,lease_id);now=get_budget_lease(current,lease_id)
        if ((now.bot_id,now.persona_id,now.parent_id,now.currency)!=(prior.bot_id,prior.persona_id,prior.parent_id,prior.currency)
                or now.version<prior.version or any(now.used.get(unit,0)<amount for unit,amount in prior.used.items())):
            raise AuthorityUnavailable('current budget identity or actual spent dimensions lost')
        coverage.append(('budget_lease',lease_id,lease_id,canonical_digest(prior),canonical_digest(now)))
        reserved={};unknown={};used={}
        for row in current.execute('SELECT operation_id,digest,ceiling_json,state,actual_json FROM runtime_budget_reservations WHERE lease_id=? ORDER BY operation_id',(lease_id,)):
            op,commitment,ceiling,state,actual=row;ceiling=json.loads(ceiling);actual=None if actual is None else json.loads(actual)
            if state=='reserved':target=reserved;amounts=ceiling
            elif state=='unknown':target=unknown;amounts=ceiling
            elif state in {'partial_unknown','partial_overrun'}:
                if actual is None:raise AuthorityUnavailable('partial backup budget lost measured dimensions')
                target=unknown;amounts={k:v for k,v in ceiling.items() if k not in actual}
            elif state in {'settled','overrun'}:
                if actual is None:raise AuthorityUnavailable('settled backup budget lost actual vector')
                target=used;amounts=actual
            else:raise AuthorityUnavailable('unsupported current backup budget reservation state')
            if state in {'reserved','unknown'} and actual is not None:raise AuthorityUnavailable('unobserved backup budget has fabricated actual')
            for unit,amount in amounts.items():
                if type(amount) is not int or amount<0:raise AuthorityUnavailable('invalid current obligation amount')
                target[unit]=target.get(unit,0)+amount
            if state in {'partial_unknown','partial_overrun'}:
                for unit,amount in actual.items():used[unit]=used.get(unit,0)+amount
        for observed,lower in ((now.reserved,reserved),(now.unconfirmed,unknown),(now.used,used)):
            if any(observed.get(unit,0)<amount for unit,amount in lower.items()):raise AuthorityUnavailable('current aggregate lost a per-unit budget obligation')
        for oldrow in old.execute('SELECT operation_id,digest,ceiling_json,state,actual_json FROM runtime_budget_reservations WHERE lease_id=? ORDER BY operation_id',(lease_id,)):
            currentrow=current.execute('SELECT operation_id,digest,ceiling_json,state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',(lease_id,oldrow[0])).fetchone()
            if currentrow is None or currentrow[:3]!=oldrow[:3]:raise AuthorityUnavailable('registered backup reservation identity disappeared')
            before=None if oldrow[4] is None else json.loads(oldrow[4]);after=None if currentrow[4] is None else json.loads(currentrow[4])
            if before is not None and (after is None or any(after.get(k)!=v for k,v in before.items())):raise AuthorityUnavailable('registered backup measured cost was changed')
            if oldrow[3] in {'unknown','partial_unknown','partial_overrun'} and currentrow!=oldrow:
                if after is None:raise AuthorityUnavailable('unknown backup reservation lost occupancy without actual settlement')
                for unit,amount in after.items():
                    fact=d11.get((lease_id,oldrow[0],unit))
                    if fact is None or fact.actual_cost!=amount:raise AuthorityUnavailable('unknown backup unit lacks actual current recovery settlement')
            coverage.append(('budget_reservation',lease_id,oldrow[0],canonical_digest(oldrow),canonical_digest(currentrow)))
        for row in old.execute('SELECT * FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND lease_id=? ORDER BY operation_id,phase',(*namespace.as_tuple,lease_id)):
            currentrow=current.execute('SELECT * FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase=?',row[:4]).fetchone()
            if currentrow!=row:raise AuthorityUnavailable('immutable registered backup budget receipt absent/changed')
            receipt=BudgetReceipt(**json.loads(row[6]))
            if (receipt.operation_id,receipt.digest,receipt.lease_id)!=(row[2],row[4],row[5]):raise AuthorityUnavailable('actual retained budget receipt identity differs')
            coverage.append(('budget_receipt',lease_id,row[2]+':'+row[3],canonical_digest(row),canonical_digest(row)))
    return coverage


class InstalledD12ManagedBackupCleanupV2(InstalledC09SurfaceCleanupV1):
    def __init__(self,*,control,gate,inventory_manifest,supervisor_journal):
        super().__init__(control=control,gate=gate,inventory_manifest=inventory_manifest,surface='controlled_backups')
        if type(supervisor_journal) is not InstalledPackageSupervisorJournalV2:raise TypeError('actual independently signed backup registry required')
        self.journal=supervisor_journal

    def _registered(self,operation_id=None):
        registered=self.journal.read_verified_managed_backups_v2(self.inventory.namespace)
        result=[];paths=set();destroyed={}
        # Completed disposition originals stay outside the erased backup files.
        # A later C09 operation may rely on their exact registered absence, but
        # cannot infer a prior cleanup merely because a directory is empty.
        with self.control._db() as db:
            saved=tuple(db.execute("SELECT operation_id,evidence_json FROM c09_storage_surface_evidence_v1 WHERE surface='controlled_backups' ORDER BY operation_id"))
        for old_operation,encoded in saved:
            if old_operation==operation_id:continue
            receipt=json.loads(encoded);self.control.verify_original_v1(receipt,'evidence_digest')
            if receipt.get('disposition_schema')!=DISPOSITION_SCHEMA:continue
            if receipt.get('operation_id')!=old_operation or receipt.get('installation_id')!=self.control.installation_id:raise AuthorityUnavailable('prior backup destruction scope differs')
            prior=self.control.read_build_original_v1(operation_id=old_operation,kind='purge_controlled_backups')
            if prior is None or receipt.get('plan_digest')!=prior['original_digest'] or receipt.get('disposition')!='revoked_destroyed' or receipt.get('restore_authorized') is not False:
                raise AuthorityUnavailable('prior registered backup disposition differs')
            for registered in prior['details']['registrations']:
                value=decode_managed_backup_v2(registered['backup'])
                if any(Path(copy['backup_observation']['resolved_path']).exists() for copy in value['copies'].values()):raise AuthorityUnavailable('previously destroyed backup bytes reappeared')
                if value['manifest_digest'] in destroyed and destroyed[value['manifest_digest']]!=registered:raise AuthorityUnavailable('backup has conflicting destruction originals')
                destroyed[value['manifest_digest']]=registered
        for intent,observation in registered:
            value=decode_managed_backup_v2(observation.body)
            if (value['installation_id']!=self.control.installation_id or value['namespace']!=self.inventory.namespace
                    or value['inventory_manifest_digest']!=self.inventory.manifest_digest
                    or value['accepted_original_digest']!=intent.digest or value['managed_backup_ref']!=intent.managed_backup_ref+('' if value['backup_phase']=='forward' else ':rollback')):raise AuthorityUnavailable('registered backup installation/namespace differs')
            previous=destroyed.get(value['manifest_digest'])
            if previous is not None:
                if previous!={'observation_ref':observation.observation_ref,'observation_digest':observation.observation_digest,'backup':value}:raise AuthorityUnavailable('destroyed backup registration changed')
                continue
            files=[]
            for role,copy in sorted(value['copies'].items()):
                file=copy['backup_observation'];path=Path(file['resolved_path'])
                operation_dir=path.parent if value['backup_phase']=='forward' else path.parent.parent
                if (path.name!=role+'.sqlite3' or operation_dir.name!=intent.operation_id
                        or value['backup_phase']=='rollback' and path.parent.name!='rollback'
                        or operation_dir.parent not in self._roots() or str(path) in paths):raise AuthorityUnavailable('backup path is not its exact registered managed artifact')
                paths.add(str(path));files.append(file)
            result.append((observation,value,files))
        return tuple(result)

    def _coverage(self,context,operation_id,registered):
        resolver=InstalledSanitizedRecoveryResolverV4(storage_reader=self.control)
        observed,frames,facts,bindings,d11,unknown=_facts(resolver)
        if observed.manifest_digest!=context.manifest_digest or frames[-1][0]['operation_id']!=operation_id:raise AuthorityUnavailable('backup coverage is not current C09 sanitized inventory')
        commitments={}
        for binding in bindings.values():
            for commitment in binding.source_row_commitments:
                previous=commitments.get(commitment)
                if previous is not None and previous!=binding:raise AuthorityUnavailable('ambiguous current recovery row ownership')
                commitments[commitment]=binding
        current_paths={m['role']:Path(m['resolved_path']) for m in context.manifest['members']}
        namespace=NamespaceId(**registered[0][1]['reconciliation']['namespace']) if registered else None
        obligations=[]
        for observation,backup,files in registered:
            if any(file_observation_v1(file['resolved_path'],exclusive=True)!=file for file in files):raise AuthorityUnavailable('registered backup bytes differ before destruction qualification')
            copies={role:Path(copy['backup_observation']['resolved_path']) for role,copy in backup['copies'].items()}
            with closing(_open(copies['execution'])) as old:
                rows=old.execute('SELECT seq,mutation_id,request_digest,append_id,pending,previous_digest,chain_digest FROM authority_v2_execution_entries ORDER BY seq').fetchall()
                if len(rows)>100000:raise AuthorityUnavailable('registered backup execution coverage exceeds bound')
                for row in rows:
                    commitment=_row_commitment(row);binding=commitments.get(commitment)
                    if binding is None or binding.originating_journal_id!=backup['current_anchor']['execution_journal_id']:raise AuthorityUnavailable('backup execution row lacks actual current typed recovery coverage')
                    actual=resolver.read_sanitized_execution_v4(namespace=self.inventory.namespace,execution_id=binding.execution_id)
                    if actual is None or actual.input_commitment!=binding.input_commitment:raise AuthorityUnavailable('registered backup execution cannot independently recover')
                    obligations.append(('execution_row',binding.execution_id,commitment,canonical_digest(actual)))
            with closing(_open(copies['core'])) as old,closing(_open(current_paths['core'])) as current:
                # A backup taken after an earlier C09 cut contains a redacted
                # execution prefix. Its exact signed fact frames must survive
                # too; enumerating only the new journal suffix is incomplete.
                if backup['storage_identity']['storage_generation']:
                    from .erasure_recovery_pin_v4 import read_execution_recovery_facts_v4_locked
                    from .c09_recovery_resolver_v4 import read_recovery_bindings_v1_locked
                    found=False
                    for frame,frame_facts,frame_bindings in frames:
                        if frame['maintenance_generation']>backup['storage_identity']['storage_generation']:continue
                        retained=read_execution_recovery_facts_v4_locked(old,self.inventory.namespace,operation_id=frame['operation_id'])
                        retained_binding=read_recovery_bindings_v1_locked(old,namespace=self.inventory.namespace,operation_id=frame['operation_id'])
                        if retained!=frame_facts or retained_binding!=frame_bindings:raise AuthorityUnavailable('backup historical redacted prefix is not exactly retained')
                        obligations.append(('prior_recovery_frame',frame['operation_id'],frame_facts.facts_digest,frame_bindings.bindings_digest))
                        if frame['new_manifest_digest']==backup['storage_identity']['manifest_digest']:found=True
                    if not found:raise AuthorityUnavailable('backup current storage is not an ancestor of actual sanitized recovery')
                from .c09_model_budget_original_v1 import TABLE,read_model_budget_originals_v1
                from .c09_model_budget_original_v1 import read_model_audit_metadata_v1
                originals={}
                for frame,_,_ in frames:
                    if current.execute("SELECT 1 FROM sqlite_master WHERE name=?",(TABLE,)).fetchone():
                        for original in read_model_budget_originals_v1(current,namespace=self.inventory.namespace,operation_id=frame['operation_id']):
                            previous=originals.get(original.call_id)
                            if previous is not None and previous!=original:raise AuthorityUnavailable('current model recovery original conflict')
                            originals[original.call_id]=original
                present=old.execute("SELECT 1 FROM sqlite_master WHERE name='authority_model_egress_v1'").fetchone()
                calls=[] if present is None else old.execute('SELECT call_id FROM authority_model_egress_v1 WHERE namespace=? ORDER BY call_id',(self.inventory.namespace,)).fetchall()
                for (call_id,) in calls:
                    original=originals.get(call_id);fact=facts.get(call_id);binding=bindings.get(call_id)
                    if (original is None or fact is None or binding is None or binding.execution_kind!='model'
                            or fact.signature_commitment!=original.original_digest
                            or original.original_digest not in binding.source_row_commitments):raise AuthorityUnavailable('model backup lacks actual pinned per-unit recovery original')
                    prior=read_model_audit_metadata_v1(old,call_id)
                    if prior is None:raise AuthorityUnavailable("actual backup model audit identity absent")
                    intent=prior.intent
                    if ((original.model_operation_id,original.request_digest,original.binding_digest,original.parent_budget_id,
                         original.reservation_operation_id,original.reservation_digest,original.provider_id,original.dispatch_generation)!=
                        (intent.operation_id,intent.request_digest,intent.binding_digest,intent.budget_lease_id,
                         intent.budget_reservation_operation_id,intent.budget_reservation_digest,intent.provider_id,intent.authority_activation_generation)
                            or dict(intent.budget_ceiling)!={u.unit:u.ceiling for u in original.units}
                            or prior.state=='observed' and original.observation_digest_or_none!=prior.observation_digest):raise AuthorityUnavailable('model backup input/known terminal/unit identity changed')
                    actual=resolver.read_sanitized_execution_v4(namespace=self.inventory.namespace,execution_id=call_id)
                    if actual is None:raise AuthorityUnavailable('model backup recovery unavailable')
                    for unit in original.units:
                        if unit.actual_or_none is not None:
                            matched=[f for f in actual.d11_facts if f.cost_unit==unit.unit]
                            if len(matched)!=1 or (matched[0].actual_cost,matched[0].settled,matched[0].pending,matched[0].debt)!=(unit.actual_or_none,unit.settled,unit.pending_known,unit.debt):raise AuthorityUnavailable('model backup unit is not exactly covered by actual recovery')
                        elif original.provider_state=='observed':raise AuthorityUnavailable('completed model still needs actual unresolved-unit settlement continuation')
                        elif call_id not in unknown:raise AuthorityUnavailable('unobserved model backup unit lost unknown footprint')
                    obligations.append(('model_units',call_id,original.original_digest,canonical_digest(actual)))
            with closing(_open(copies['graph'])) as old,closing(_open(current_paths['graph'])) as current:
                obligations.extend(_budget_coverage(old,current,namespace,d11))
            for file in files:
                if file_observation_v1(file['resolved_path'],exclusive=True)!=file:raise AuthorityUnavailable('backup changed during coverage qualification')
        material=dict(schema=COVERAGE_SCHEMA,operation_id=operation_id,namespace=self.inventory.namespace,
            manifest_digest=context.manifest_digest,current_storage_generation=context.storage_generation,
            frame_digests=[p['prepared_digest'] for p,_,_ in frames],
            registered_backup_digests=sorted(value['manifest_digest'] for _,value,_ in registered),
            obligations=sorted(set(obligations)))
        material['coverage_digest']=canonical_digest(material)
        return material

    def clean_installed_surface_v1(self,*,operation_id,storage_reader):
        context=self._context(operation_id,storage_reader);registered=self._registered(operation_id)
        plan=self.control.read_build_original_v1(operation_id=operation_id,kind='purge_controlled_backups')
        if plan is None:
            files=sorted((f for _,_,rows in registered for f in rows),key=lambda f:f['resolved_path'])
            if tuple(files)!=self._before_files(context):raise AuthorityUnavailable('unregistered backup bytes or missing managed artifact')
            coverage=self._coverage(context,operation_id,registered)
            details=dict(schema=DISPOSITION_SCHEMA,disposition='revoked_pending_destruction',restore_authorized=False,
                inventory_manifest_digest=self.inventory.manifest_digest,
                registrations=[{'observation_ref':obs.observation_ref,'observation_digest':obs.observation_digest,'backup':value} for obs,value,_ in registered],
                files=files,roots=[str(p) for p in self._roots()],recovery_coverage=coverage)
            plan=self.control.record_cleanup_plan_v1(operation_id=operation_id,surface=self.surface,details=details)
        self._require_plan(context,operation_id,plan,registered)
        from .c09_durable_unlink_v2 import unlink_inventory_member_durably_v2
        for before in plan['details']['files']:
            self.control.lease.require_held()
            unlink_inventory_member_durably_v2(before)
        after=self._after(context,operation_id,plan)
        return self.control.sign_original_v1('sylanne3.c09.surface-evidence.v1',dict(schema='sylanne3.c09.surface-evidence.v1',
            installation_id=self.control.installation_id,issuer_id=self.control.authority_id,operation_id=operation_id,
            surface=self.surface,manifest_digest=context.manifest_digest,action='purged',plan_digest=plan['original_digest'],
            disposition_schema=DISPOSITION_SCHEMA,disposition='revoked_destroyed',restore_authorized=False,
            recovery_coverage_digest=plan['details']['recovery_coverage']['coverage_digest'],
            before_observations=plan['details']['files'],after_observations=after),'evidence_digest')

    def _require_plan(self,context,operation_id,plan,registered):
        details=plan['details']
        if (plan['manifest_digest']!=context.manifest_digest or details.get('schema')!=DISPOSITION_SCHEMA
                or details.get('disposition')!='revoked_pending_destruction' or details.get('restore_authorized') is not False
                or details.get('inventory_manifest_digest')!=self.inventory.manifest_digest
                or details['registrations']!=[{'observation_ref':o.observation_ref,'observation_digest':o.observation_digest,'backup':v} for o,v,_ in registered]):raise AuthorityUnavailable('exact backup destruction registration/intent differs')
        coverage=details['recovery_coverage'];material=dict(coverage);material.pop('coverage_digest',None)
        if coverage['coverage_digest']!=canonical_digest(material) or coverage['operation_id']!=operation_id:raise AuthorityUnavailable('backup recovery coverage commitment differs')
        # After an ACK loss, all retained typed facts must still be independently
        # readable even when some old files have already been removed.
        resolver=InstalledSanitizedRecoveryResolverV4(storage_reader=self.control)
        current,frames=resolver.read_verified_frames_v4()
        if current.manifest_digest!=context.manifest_digest or [p['prepared_digest'] for p,_,_ in frames]!=coverage['frame_digests']:raise AuthorityUnavailable('backup destruction recovery frame changed')
        for row in coverage['obligations']:
            if row[0] in {'execution_row','model_units'}:
                actual=resolver.read_sanitized_execution_v4(namespace=self.inventory.namespace,execution_id=row[1])
                if actual is None or canonical_digest(actual)!=row[3]:raise AuthorityUnavailable('backup destruction actual recovery obligation no longer holds')
        graph_path=next(m['resolved_path'] for m in context.manifest['members'] if m['role']=='graph')
        from ..runtime.budget import get_budget_lease
        with closing(_open(graph_path)) as graph:
            for row in coverage['obligations']:
                if row[0]=='budget_lease':
                    current=canonical_digest(get_budget_lease(graph,row[1]))
                elif row[0]=='budget_reservation':
                    value=graph.execute('SELECT operation_id,digest,ceiling_json,state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',(row[1],row[2])).fetchone()
                    current=canonical_digest(value)
                elif row[0]=='budget_receipt':
                    operation,phase=row[2].rsplit(':',1)
                    role=NamespaceId(**registered[0][1]['reconciliation']['namespace']) if registered else None
                    if role is None:raise AuthorityUnavailable('backup budget namespace absent')
                    value=graph.execute('SELECT * FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase=?',(*role.as_tuple,operation,phase)).fetchone()
                    current=canonical_digest(value)
                else:continue
                if current!=row[4]:raise AuthorityUnavailable('backup current per-unit budget coverage changed')
        expected={item['resolved_path']:item for item in details['files']}
        for root in self._roots():
            for item in _directory_files(root,protected=self._protected(context)):
                if expected.get(item['resolved_path'])!=item:raise AuthorityUnavailable('unknown/changed managed backup blocks destruction')

    def reread_installed_surface_v1(self,*,operation_id,storage_reader,original):
        context=self._context(operation_id,storage_reader);self.control.verify_original_v1(original,'evidence_digest')
        plan=self.control.read_build_original_v1(operation_id=operation_id,kind='purge_controlled_backups')
        if (plan is None or original.get('disposition_schema')!=DISPOSITION_SCHEMA or original.get('disposition')!='revoked_destroyed'
                or original.get('restore_authorized') is not False or original['plan_digest']!=plan['original_digest']):raise AuthorityUnavailable('actual versioned backup destruction receipt required')
        self._require_plan(context,operation_id,plan,self._registered(operation_id))
        after=self._after(context,operation_id,plan)
        if after!=original['after_observations']:raise AuthorityUnavailable('actual backup absence changed')
        return {'evidence_digest':original['evidence_digest'],'after_observations':after}
