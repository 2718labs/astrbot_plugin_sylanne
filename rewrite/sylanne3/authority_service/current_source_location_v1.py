"""Issued current storage/location observations; never an Owner/work grant.

The fixed installation observes outside Core/Graph SQL. Consumers retain their
own real fence or accepted-erasure exclusion and their domain-specific checks.
Only this exact instance can consume its observations; no wire DTO is accepted.
"""
from __future__ import annotations
from dataclasses import dataclass,asdict
import json
from pathlib import Path
import sqlite3
import threading
import weakref

from .contract import AuthorityUnavailable,CONTENT_OPERATIONS
from .v2_fence_service import AuthorityV2FenceService
from .v2_scoped_erasure_store import AuthorityV2ScopedErasureStore
from .v2_contract import FencePermitV2,DeletionMutationReceiptV1
from .c09_storage_control_v1 import C09StorageControlV1,_PREPARED_FIELDS
from ..graph_store import GraphStore
from ..graph_types import NamespaceEpoch
from ..runtime.c09_graph_originals_read_v4 import read_graph_rebase_certificate_v1
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime.restore_anchor import RestoreAnchor


@dataclass(frozen=True,slots=True,weakref_slot=True)
class _IssuedCurrentSourceLocationV1:
    purpose: str
    namespace_id: NamespaceId
    authority_namespace: str
    installation_id: str
    graph_db_path: str
    current_graph_metadata: object
    graph_epoch: NamespaceEpoch
    core_anchor: RestoreAnchor
    holder: str
    graph_incarnations: tuple[str,...]
    execution_locations: tuple[tuple[str,str],...]
    selected_files: tuple[tuple[str,str,int,int,str],...]
    storage_ancestors: tuple[tuple[int,str,str,str,str,str,str,int,int],...]
    lineage_commitments: tuple[tuple[str,str,str],...]
    pointer_version: int
    manifest_digest: str
    storage_generation: int
    stage: str
    control_operation_id: str | None
    subject: str
    permit: FencePermitV2 | None
    accepted_receipt: DeletionMutationReceiptV1 | None
    context: object


def _material(value):
    result={name:getattr(value,name) for name in value.__dataclass_fields__ if name!='context'}
    context=value.context
    result['context_commitment']=(context.control_path,context.pointer_version,context.manifest_digest,
        context.storage_generation,context.stage,canonical_digest(context.manifest),canonical_digest(context.prepared_original))
    return result


class InstalledCurrentSourceLocationQualifierV1:
    def __init__(self,*,fences,scoped,control,graph_db_path,namespace_id,installation_id):
        if (type(fences) is not AuthorityV2FenceService or type(scoped) is not AuthorityV2ScopedErasureStore
                or type(control) is not C09StorageControlV1 or type(namespace_id) is not NamespaceId
                or scoped.core is not fences.core or scoped.fences is not fences.fences
                or scoped.deletion is not fences.deletion or scoped.execution is not fences.execution
                or scoped.namespace!=fences.namespace or control.installation_id!=installation_id
                or getattr(fences.core,'_c09_storage_reader_v1',None) is not control):
            raise TypeError('one actual installed Core/fence/scoped/journal/storage composition required')
        self._fences=fences;self._scoped=scoped;self._control=control;self.core=fences.core
        self._graph_db_path=Path(graph_db_path).resolve(strict=True)
        self.namespace_id=namespace_id;self.namespace=fences.namespace;self.installation_id=installation_id
        self._issued={};self._issued_lock=threading.RLock();self._inventory_views={}

    def _outside_sql(self):
        if any(getattr(store,'_db',None) is None or store._db.in_transaction
                for store in (self.core,self._fences.deletion,self._fences.execution)):
            raise AuthorityUnavailable('current location observation must precede caller SQL/freezes')

    def _issue(self,**fields):
        value=_IssuedCurrentSourceLocationV1(**fields);key=id(value);commitment=canonical_digest(_material(value))
        def retire(_):
            with self._issued_lock:self._issued.pop(key,None)
        with self._issued_lock:self._issued[key]=(weakref.ref(value,retire),commitment,value.context)
        return value

    def _require_issued(self,value,purpose=None):
        if type(value) is not _IssuedCurrentSourceLocationV1:raise AuthorityUnavailable('actual issued current location required')
        with self._issued_lock:original=self._issued.get(id(value))
        if (original is None or original[0]() is not value or original[2] is not value.context or original[1]!=canonical_digest(_material(value))
                or purpose is not None and value.purpose!=purpose
                or value.namespace_id!=self.namespace_id or value.authority_namespace!=self.namespace
                or value.installation_id!=self.installation_id or value.graph_db_path!=str(self._graph_db_path)
                or value.context._reader is not self._control
                or value.context._capability is not self._control._capability):
            raise AuthorityUnavailable('altered, stale, cross-instance or wrong-purpose location observation')
        return value

    def _pointer(self,context):
        with self._control._db() as db:
            current=self._control._current(db)
            if (current['pointer_version'],current['current_manifest_digest'],current['stage'])!=(context.pointer_version,context.manifest_digest,context.stage):
                raise AuthorityUnavailable('current location storage observation expired')
            return current['active_operation_id']

    def _lineage(self,context):
        return read_current_storage_lineage_v1(self._control, context, namespace=self.namespace, installation_id=self.installation_id)

    def _graph_snapshot(self,db):
        return read_current_graph_snapshot_in_tx_v1(db, self.namespace_id)

    def _accepted_in_tx(self,db,receipt,subject):
        state=self._scoped.state_locked(db);current=self.core._row(db,self.namespace)
        saved=self._fences.fences.mutation_locked(db,receipt.pending.mutation_id)
        decoded=None if saved is None else self._fences.fences._decode_mutation_row(saved)
        if (decoded is None or decoded[2]!=receipt or saved[1:3]!=(self.namespace,subject)
                or receipt.pending.source_phase!='pending' or receipt.pending.target_phase!='accepted'
                or receipt.pending.evidence.issuer_id!='authority-pinned-graph-barrier-v1'
                or state.aggregate_phase!='accepted' or state.active_operation_id!=receipt.pending.deletion_operation_id
                or state.closed_seq is not None or current[9]!='accepted'):
            raise AuthorityUnavailable('location needs the actual current accepted erasure original')
        anchor=self.core._anchor(db,self.namespace,current)
        fence=self._fences.fences._row(db,receipt.pending.permit.operation_id)
        if fence is None or fence[6]!='active':raise AuthorityUnavailable('accepted location has no actual live deletion fence')
        permit=self._fences.fences._permit(fence)
        if anchor!=receipt.after_anchor:
            self._fences.fences.verify_current_deletion_bridge_locked(db,core=self.core,receipt=receipt,
                original_permit=decoded[3],current_anchor=anchor,current_permit=permit)
        self._fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
        return anchor,current[0]

    def _observe(self,*,purpose,credential,subject,permit=None,accepted_receipt=None):
        self._outside_sql();context=self._control.read_verified_current_storage_v1()
        context.require_current('business' if purpose=='business' else 'maintenance')
        control_operation=self._pointer(context);manifests,prepared,locations,commitments=self._lineage(context)
        current_members={m['role']:m for m in context.manifest['members']}
        if (Path(current_members['core']['resolved_path'])!=self.core.path.resolve()
                or Path(current_members['graph']['resolved_path'])!=self._graph_db_path
                or Path(current_members['deletion']['resolved_path'])!=self._fences.deletion.path.resolve()
                or Path(current_members['execution']['resolved_path'])!=self._fences.execution.path.resolve()
                or current_members['execution']['incarnation_or_journal_id']!=self._fences.execution.journal_id):
            raise AuthorityUnavailable('selected current Core/Graph/journal handles differ')
        with self._fences._frozen() as (db,deletion,execution,_):
            anchor=self._fences._current_locked(db,deletion,execution,require_clear=False)
            if current_members['deletion']['incarnation_or_journal_id']!=anchor.deletion_journal_id or deletion.journal_id!=anchor.deletion_journal_id:
                raise AuthorityUnavailable('selected deletion journal differs from actual current anchor')
            if purpose=='business':
                if self.core._row(db,self.namespace)[9]!='clear':raise AuthorityUnavailable('business namespace is not clear')
                self._fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
                holder=self.core._row(db,self.namespace)[0]
            else:anchor,holder=self._accepted_in_tx(db,accepted_receipt,subject)
        graph_uri=self._graph_db_path.as_uri()+'?mode=ro'
        immutable=False
        if purpose=='accepted_erasure' and context.stage in {'INTENT','PREPARED'}:
            from .d12_sqlite_backup_v2 import leased_sqlite_read_uri_v2
            graph_uri,immutable=leased_sqlite_read_uri_v2(self._graph_db_path,self._control.lease)
        graph=sqlite3.connect(graph_uri,uri=True,isolation_level=None)
        try:
            graph.execute('PRAGMA query_only=ON');graph.execute('BEGIN')
            metadata, epoch, incarnations = read_graph_location_in_tx_v1(graph,
                namespace_id=self.namespace_id, namespace=self.namespace, purpose=purpose, anchor=anchor,
                accepted_receipt=accepted_receipt, manifests=manifests, prepared=prepared)
        finally:graph.close()
        if immutable and any(Path(str(self._graph_db_path)+suffix).exists() for suffix in ('-wal','-shm','-journal')):
            raise AuthorityUnavailable('closed Graph acquired a companion during location observation')
        for member in context.manifest['members']:self._control.verify_member_v1(member,prepared=False)
        context.require_current('business' if purpose=='business' else 'maintenance')
        if self._pointer(context)!=control_operation:raise AuthorityUnavailable('current location control operation changed')
        value=self._issue(purpose=purpose,namespace_id=self.namespace_id,authority_namespace=self.namespace,installation_id=self.installation_id,
            graph_db_path=str(self._graph_db_path),current_graph_metadata=metadata,graph_epoch=epoch,core_anchor=anchor,holder=holder,
            graph_incarnations=tuple(incarnations),execution_locations=locations,
            selected_files=tuple((m['role'],m['resolved_path'],m['device'],m['file_id'],m['incarnation_or_journal_id']) for m in context.manifest['members']),
            storage_ancestors=tuple((m['generation'],v['role'],v['resolved_path'],v['store_id'],v['namespace'],m['installation_id'],v['incarnation_or_journal_id'],v['device'],v['file_id']) for m in manifests for v in m['members']),
            lineage_commitments=commitments,pointer_version=context.pointer_version,manifest_digest=context.manifest_digest,
            storage_generation=context.storage_generation,stage=context.stage,control_operation_id=control_operation,subject=subject,
            permit=permit,accepted_receipt=accepted_receipt,context=context)
        with self._fences._frozen() as (db,deletion,execution,_):
            if self._fences._current_locked(db,deletion,execution,require_clear=False)!=anchor:
                raise AuthorityUnavailable('current location anchor changed during observation')
            self.require_current_in_tx_v1(db,value)
        return value

    def observe_business_for_fence_v1(self,*,credential,subject,permit):
        if type(permit) is not FencePermitV2 or permit.operation not in CONTENT_OPERATIONS:
            raise AuthorityUnavailable('actual business fence required for location observation')
        self._fences._require_permit(credential=credential,subject=subject,permit=permit)
        return self._observe(purpose='business',credential=credential,subject=subject,permit=permit)

    def observe_accepted_erasure_location_v1(self,*,credential,subject,accepted_mutation_id):
        self._outside_sql()
        receipt=self._scoped.read_ancestor_receipt(credential=credential,subject=subject,mutation_id=accepted_mutation_id)
        return self._observe(purpose='accepted_erasure',credential=credential,subject=subject,accepted_receipt=receipt)

    def require_current_in_tx_v1(self,db,observation):
        value=self._require_issued(observation)
        if db is not self.core._db or not db.in_transaction:raise AuthorityUnavailable('current location requires this actual Core transaction')
        if getattr(self.core,'_c09_storage_reader_v1',None) is not self._control:raise AuthorityUnavailable('current storage reader changed')
        if self._pointer(value.context)!=value.control_operation_id:raise AuthorityUnavailable('location control operation expired')
        current, anchor = require_current_source_anchor_in_tx_v1(db, namespace=self.namespace,
            expected_anchor=value.core_anchor, holder=value.holder)
        if value.purpose=='business':
            if current[9]!='clear':raise AuthorityUnavailable('location observation cannot open business during erasure')
            from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
            require_lifecycle_admission_in_tx_v1(db,self.namespace,action='graph_read')
            self._fences.fences.validate_fence_locked(db,value.permit,subject=value.subject,current_anchor=anchor)
        elif value.purpose=='accepted_erasure':self._accepted_in_tx(db,value.accepted_receipt,value.subject)
        else:raise AuthorityUnavailable('unknown current location purpose')
        return value

    def require_graph_snapshot_v1(self,db,observation,*,graph_db_path=None):
        value=self._require_issued(observation,'business')
        if type(db) is not sqlite3.Connection or not db.in_transaction:raise AuthorityUnavailable('location binding requires the actual Graph read transaction')
        actual=Path(db.execute('PRAGMA database_list').fetchone()[2]).resolve(strict=True)
        if actual!=self._graph_db_path or graph_db_path is not None and Path(graph_db_path).resolve(strict=True)!=actual:
            raise AuthorityUnavailable('location proof belongs to another Graph file')
        require_graph_source_snapshot_in_tx_v1(db, namespace_id=self.namespace_id,
            expected_metadata=value.current_graph_metadata, expected_epoch=value.graph_epoch)
        return value

    def require_accepted_graph_snapshot_v1(self,db,observation,*,graph_db_path=None):
        value=self._require_issued(observation,'accepted_erasure')
        if type(db) is not sqlite3.Connection or not db.in_transaction:
            raise AuthorityUnavailable('accepted location requires the actual Graph transaction')
        actual=Path(db.execute('PRAGMA database_list').fetchone()[2]).resolve(strict=True)
        if actual!=self._graph_db_path or graph_db_path is not None and Path(graph_db_path).resolve(strict=True)!=actual:
            raise AuthorityUnavailable('accepted location belongs to another Graph')
        require_graph_source_snapshot_in_tx_v1(db, namespace_id=self.namespace_id,
            expected_metadata=value.current_graph_metadata, expected_epoch=value.graph_epoch)
        return value

    def observe_installation_inventory_v1(self,manifest,*,credential,subject,accepted_mutation_id):
        from .current_filesystem_inventory_v3 import issue_current_inventory_v3
        location=self.observe_accepted_erasure_location_v1(credential=credential,subject=subject,
            accepted_mutation_id=accepted_mutation_id)
        return issue_current_inventory_v3(self,manifest,location)

    def scan_installation_inventory_v1(self,view):
        from .current_filesystem_inventory_v3 import scan_current_inventory_v3
        return scan_current_inventory_v3(self,view)

    def require_inventory_graph_source_v1(self,view,source_path):
        from .current_filesystem_inventory_v3 import require_inventory_graph_source_v3
        return require_inventory_graph_source_v3(self,view,source_path)

    def require_registry_target_in_tx_v1(self,db,observation,*,target_ref,generation_ref):
        value=self._require_issued(observation,'accepted_erasure');self.require_current_in_tx_v1(db,value)
        if (target_ref,generation_ref) not in value.execution_locations or value.execution_locations[-1]!=(str(self._fences.execution.path.resolve()),self._fences.execution.journal_id):
            raise AuthorityUnavailable('registry is not an exact authenticated journal ancestor')
        return value


def read_current_storage_lineage_v1(control, context, *, namespace, installation_id):
    manifests=[];prepared=[];commitments=[];seen=set()
    with control._db() as db:
        current=control._current(db)
        if (current['pointer_version'],current['current_manifest_digest'],current['stage'])!=(context.pointer_version,context.manifest_digest,context.stage):
            raise AuthorityUnavailable('current location selected pointer changed')
        selected=context.manifest_digest
        while selected is not None:
            if selected in seen or len(seen)>=1024:raise AuthorityUnavailable('current location ancestry cycles or exceeds bound')
            seen.add(selected);manifest=control._read_manifest(db,selected)
            if manifest['cohort_namespaces']!=[namespace]:raise AuthorityUnavailable('location crosses installed storage namespace')
            manifests.append(manifest)
            if manifest['generation']==0:
                if manifest['prior_manifest_digest'] is not None:raise AuthorityUnavailable('location genesis ancestry differs')
                break
            rows=db.execute('SELECT operation_id,prepared_original_json,prepared_digest,signature FROM c09_storage_operations_v1 WHERE new_manifest_digest=?',(selected,)).fetchmany(2)
            if len(rows)!=1:raise AuthorityUnavailable('one signed selected PREPARED original required')
            operation,raw,commitment,signature=rows[0];original=json.loads(raw)
            control.verify_original_v1(original,'prepared_digest')
            if (set(original)!=_PREPARED_FIELDS or original['operation_id']!=operation or original['namespace']!=namespace
                    or original['installation_id']!=installation_id or original['authority_id']!=control.authority_id
                    or original['prepared_digest']!=commitment or original['signature']!=signature
                    or original['new_manifest_digest']!=selected or original['maintenance_generation']!=manifest['generation']
                    or original['old_manifest_digest']!=manifest['prior_manifest_digest']):
                raise AuthorityUnavailable('signed current location PREPARED identity differs')
            events=db.execute("SELECT event_json FROM c09_storage_events_v1 WHERE operation_id=? AND stage='SWITCHED'",(operation,)).fetchmany(2)
            if len(events)!=1:raise AuthorityUnavailable('registered candidate was never actually selected')
            switched=json.loads(events[0][0]);control.verify_original_v1(switched,'event_digest')
            if (switched['operation_id']!=operation or switched['current_manifest_digest']!=selected
                    or switched['pointer_version']!=original['expected_pointer_version']+1
                    or switched['details']['prepared_digest']!=commitment):
                raise AuthorityUnavailable('actual selected location transition differs')
            if selected!=context.manifest_digest or context.stage in {'RELEASED','INTENT','PREPARED'}:
                events=db.execute("SELECT event_json FROM c09_storage_events_v1 WHERE operation_id=? AND stage='RELEASED'",(operation,)).fetchmany(2)
                if len(events)!=1:raise AuthorityUnavailable('previous storage successor was not actually released')
                released=json.loads(events[0][0]);control.verify_original_v1(released,'event_digest')
                release=released['details']['release_original'];control.verify_original_v1(release,'release_digest')
                if release['manifest_digest']!=selected or release['operation_id']!=operation or release['state']!='applied':
                    raise AuthorityUnavailable('actual location release ancestry differs')
            prepared.append(original);commitments.append((selected,commitment,switched['event_digest']))
            selected=manifest['prior_manifest_digest']
    manifests.reverse();prepared.reverse();commitments.reverse()
    if len(manifests)!=context.storage_generation+1:raise AuthorityUnavailable('storage generations are not contiguous')
    locations=[]
    for index,manifest in enumerate(manifests):
        if manifest['generation']!=index:raise AuthorityUnavailable('storage generation ancestry differs')
        execution=next(m for m in manifest['members'] if m['role']=='execution')
        locations.append((execution['resolved_path'],execution['incarnation_or_journal_id']))
        if index:
            value=prepared[index-1];before=RestoreAnchor(**value['old_core_anchor_original']);after=RestoreAnchor(**value['new_core_anchor_original'])
            if (before.authority_id!=control.authority_id or after.authority_id!=before.authority_id
                    or before.namespace!=namespace or after.namespace!=namespace
                    or before.activation_generation!=after.activation_generation or after.revocation_epoch!=before.revocation_epoch+1
                    or before.execution_journal_id!=locations[index-1][1] or after.execution_journal_id!=locations[index][1]):
                raise AuthorityUnavailable('exact journal location transition differs')
    return tuple(manifests),tuple(prepared),tuple(locations),tuple(commitments)


def read_current_graph_snapshot_in_tx_v1(db, namespace_id):
    metadata=GraphStore._decode_recovery(db.execute('SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',namespace_id.as_tuple).fetchone(),namespace_id)
    row=db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?',namespace_id.as_tuple).fetchone()
    if metadata is None:raise AuthorityUnavailable('actual current Graph recovery metadata absent')
    return metadata,NamespaceEpoch(*namespace_id.as_tuple,0 if row is None else row[0])


def require_current_source_anchor_in_tx_v1(db, *, namespace, expected_anchor, holder):
    from .c09_connection_state_v1 import namespace_row_in_tx_v1, anchor_in_tx_v1
    row = namespace_row_in_tx_v1(db, namespace)
    anchor = anchor_in_tx_v1(db, namespace, row)
    if anchor != expected_anchor or row[0] != holder or row[2] != "active" or row[3:5] != (None, None):
        raise AuthorityUnavailable("current source Core/Owner activation changed")
    return row, anchor


def require_graph_source_snapshot_in_tx_v1(db, *, namespace_id, expected_metadata, expected_epoch):
    if not db.in_transaction or read_current_graph_snapshot_in_tx_v1(db, namespace_id) != (expected_metadata, expected_epoch):
        raise AuthorityUnavailable("actual source Graph metadata/stamps changed")


def read_graph_location_in_tx_v1(db, *, namespace_id, namespace, purpose, anchor,
        accepted_receipt, manifests, prepared):
    if not db.in_transaction:
        raise AuthorityUnavailable("Graph location requires pinned actual SQL")
    metadata,epoch=read_current_graph_snapshot_in_tx_v1(db, namespace_id);req=metadata.requirements
    if (req.authority_id!=anchor.authority_id or req.authority_namespace!=namespace
            or req.activation_generation!=anchor.activation_generation):raise AuthorityUnavailable('current Graph namespace/generation differs')
    incarnations=[]
    for index,original in enumerate(prepared):
        certificate=read_graph_rebase_certificate_v1(db,namespace_id,original['operation_id'])
        member=next(m for m in manifests[index+1]['members'] if m['role']=='graph')
        if (certificate is None or canonical_serialize(asdict(certificate))!=canonical_serialize(original['graph_certificate_original'])
                or certificate.old_incarnation!=original['old_graph_head_original']['incarnation']
                or certificate.new_incarnation!=member['incarnation_or_journal_id']
                or certificate.certificate_digest!=manifests[index+1]['certificate_digest']
                or certificate.maintenance_generation!=index+1
                or original['prior_prepared_digest']!=(None if index==0 else prepared[index-1]['prepared_digest'])
                or certificate.prior_certificate_digest!=(None if index==0 else prepared[index-1]['graph_certificate_original']['certificate_digest'])
                or index and certificate.old_incarnation!=incarnations[-1]):
            raise AuthorityUnavailable('actual certified Graph location ancestry differs')
        if not incarnations:incarnations.append(certificate.old_incarnation)
        incarnations.append(certificate.new_incarnation)
    if not incarnations:incarnations.append(req.graph_incarnation)
    if incarnations[-1]!=req.graph_incarnation:raise AuthorityUnavailable('selected Graph does not descend from signed location chain')
    if purpose=='business' and any(getattr(req,n)!=getattr(anchor,n) for n in ('activation_generation','revocation_epoch','deletion_journal_id','deletion_seq','deletion_digest','execution_journal_id','execution_seq','execution_digest')):
        raise AuthorityUnavailable('business Graph and Core recovery heads differ')
    if purpose=='accepted_erasure':
        from ..runtime.c09_erasure_barrier_store_v1 import read_c09_erasure_barrier_v1
        barrier=read_c09_erasure_barrier_v1(db,namespace_id,accepted_receipt.pending.deletion_operation_id)
        before=accepted_receipt.pending.before_anchor
        if (barrier is None or canonical_digest(barrier)!=accepted_receipt.pending.evidence.proof_digest.removeprefix('sha256:')
                or barrier.closure_digest!=accepted_receipt.pending.evidence.barrier_scope_digest.removeprefix('sha256:')
                or barrier.request_digest!=accepted_receipt.pending.request_digest.removeprefix('sha256:')
                or barrier.delete_epoch_after!=accepted_receipt.pending.deletion_epoch
                or epoch.revision!=barrier.graph_epoch_after
                or any(getattr(req,n)!=getattr(before,n) for n in ('activation_generation','revocation_epoch','deletion_journal_id','deletion_seq','deletion_digest','execution_journal_id','execution_seq','execution_digest'))):
            raise AuthorityUnavailable('maintenance Graph is not the exact accepted/barrier recovery relation')
        if req.graph_incarnation!=barrier.graph_incarnation:
            latest=prepared[-1] if prepared else None
            if (latest is None or latest['operation_id']!=barrier.operation_id
                    or latest['graph_certificate_original']['old_incarnation']!=barrier.graph_incarnation
                    or latest['graph_certificate_original']['new_incarnation']!=req.graph_incarnation
                    or latest['graph_certificate_original']['old_revision']!=metadata.graph_revision):
                raise AuthorityUnavailable('maintenance Graph rebase lacks exact current transition')
    return metadata, epoch, tuple(incarnations)
