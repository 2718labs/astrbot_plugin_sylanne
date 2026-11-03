"""Exact retired Owner WRITE protocol metadata; grants no Body or execution use."""
from contextlib import contextmanager,closing
from dataclasses import dataclass,asdict
import json
from pathlib import Path
from time import monotonic_ns
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
from .source_correction_read_v3 import _heap

_KEY=object()
_PROOFS=WeakKeyDictionary()


@dataclass(frozen=True,slots=True)
class RetiredOwnerWriteTerminalMetadataV3:
    owner_operation_id:str
    attempt_id:str
    request_digest:str
    original_ref:str
    original_digest:str
    receipt:object
    receipt_digest:str
    formal_finish_request_id:str
    formal_finish_request_digest:str
    event_digest:str
    graph_epoch:int


def _require_gate_v3(maintenance,coverage,quiescence,gate_identity):
    from ..authority_service.c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
    from ..authority_service.c09_writer_peer_originals_v3 import _require_gate,VerifiedPeerRetirementCoverageV3
    if (type(maintenance)is not InstalledC09MaintenanceV1
            or maintenance.gate._installed_maintenance_v3 is not maintenance):
        raise AuthorityUnavailable('retired WRITE metadata requires actual installed maintenance')
    gate=maintenance.gate
    _require_gate(maintenance.control,gate)
    if (gate._operation,gate._epoch,gate._closing_continuation)!=gate_identity or gate._active!=0:
        raise AuthorityUnavailable('retired WRITE metadata lost continuous drained Gate exclusion')
    if gate._operation!=coverage.operation_id:
        raise AuthorityUnavailable('retired WRITE metadata crossed its actual retirement operation')
    if type(coverage)is VerifiedPeerRetirementCoverageV3 and gate._epoch!=quiescence['revoked_admission_epoch']:
        raise AuthorityUnavailable('retired WRITE live metadata crossed its actual quiescence admission epoch')
    if gate._closing_continuation is not None:
        gate.require_final_continuation_v3(gate._closing_continuation,operation_id=coverage.operation_id,observe=False)
    maintenance.core._require(maintenance.credential,'delete',maintenance.closure.namespace)


class _RetiredWriteMetadataLeaseV3:
    def __init__(self,maintenance,coverage,quiescence,context,basis,layout_kind='selected_segmented'):
        self.maintenance,self.coverage,self.quiescence=maintenance,coverage,dict(quiescence)
        self.context,self.basis,self.layout_kind=context,basis,layout_kind
        gate=maintenance.gate
        self.gate_identity=(gate._operation,gate._epoch,gate._closing_continuation)
        self.headers,self.values,self.commitments=[],{},[]
        self.buffer=bytearray();self.metadata=None;self.closed=False
        maintenance.control.register_c09_retained_state_v3(self)
    def _c09_retained_heap_bytes_v3(self):
        return _heap((self.headers,self.values,self.commitments,self.buffer,self.metadata,self.quiescence))+65536
    def require_graph_scope_v3(self):
        if self.closed:raise AuthorityUnavailable('retired WRITE metadata lease was released')
        _require_gate_v3(self.maintenance,self.coverage,self.quiescence,self.gate_identity)
        self.context.require_current('maintenance')
    def require_v3(self):
        self.require_graph_scope_v3()
        if self.layout_kind=='initial_segmented_retirement_v4':
            with self.maintenance.control._resource_sql_quantum_v3()as meter:
                self.basis.require_current(meter=meter)
    def require_storage_v3(self,db,meter):
        self.basis.require_current(meter=meter)
    @contextmanager
    def sql_v3(self,db):
        retirement=self.layout_kind=='initial_segmented_retirement_v4'
        if retirement:self.require_graph_scope_v3()
        else:self.require_v3()
        with self.maintenance.control._resource_sql_quantum_v3()as meter:
            if not retirement:self.require_storage_v3(db,meter)
            self.maintenance.control.require_c09_retained_arena_v3(meter=meter)
            if db.in_transaction:raise AuthorityUnavailable('retired WRITE metadata cannot inherit Graph SQL')
            started=monotonic_ns();db.execute('BEGIN')
            try:
                if retirement:self.basis.require_graph(db,meter=meter)
                yield meter
            finally:db.rollback()
            if monotonic_ns()-started>meter.budget.max_read_ns:
                raise AuthorityUnavailable('retired WRITE metadata exceeded its actual C09 read deadline')
    def fixed_v3(self,db,table,columns,where,args):
        with self.sql_v3(db)as meter:
            row=meter.read_fixed_row(db,table,columns,where,args)
            self.maintenance.control.require_c09_retained_arena_v3(meter=meter,additional_bytes=_heap(row)*2+4096)
            self.headers.append((table,columns,where,args,row))
            return row
    def json_v3(self,db,table,column,keys,key):
        where=' AND '.join(name+'=?'for name in keys)
        with self.sql_v3(db)as meter:
            meter.require_available(32)
            row=db.execute('SELECT typeof('+column+'),length(CAST('+column+' AS BLOB)) FROM '+table+' WHERE '+where,key).fetchone()
            meter.charge_read(32)
        if row is None or row[0]!='text':raise AuthorityUnavailable('retired WRITE formal metadata original is absent')
        total=row[1];offset=0;parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.buffer=bytearray()
        while offset<total:
            with self.sql_v3(db)as meter:
                chunk,size,kind=read_legacy_sql_cell_fragment_v2(db,table=table,column=column,where=where,
                    parameters=key,start=offset,length=min(16384,total-offset),meter=meter)
                if(size,kind)!=(total,'text'):raise AuthorityUnavailable('retired WRITE metadata changed during complete EOF')
                self.maintenance.control.require_c09_retained_arena_v3(meter=meter,additional_bytes=len(chunk)*10+65536)
                parser.feed(chunk,lambda event:None);self.buffer.extend(chunk);offset+=len(chunk)
        result=parser.finish()
        if result.byte_count!=total:raise AuthorityUnavailable('retired WRITE canonical metadata EOF differs')
        with self.maintenance.control._resource_sql_quantum_v3()as meter:
            self.maintenance.control.require_c09_retained_arena_v3(meter=meter,additional_bytes=total*10+65536)
            meter.require_available(total)
            value=json.loads(self.buffer)
            name=(table,column,tuple(key))
            self.values[name]=value;self.commitments.append((name,result.sha256,result.byte_count))
            self.buffer.clear()
        return value
    def release_v3(self):
        if self.closed:return
        self.closed=True
        if self.layout_kind=='initial_segmented_retirement_v4':self.basis.release_v4()
        self.maintenance.control._c09_retained_states_v3.discard(self)
        self.headers.clear();self.values.clear();self.commitments.clear();self.buffer.clear()
        self.metadata=None


class _RetiredOwnerWriteTerminalProofV3:
    def __init__(self,key,lease,registration,permit,metadata):
        if key is not _KEY:raise TypeError('actual retired WRITE producer required')
        self.lease,self.registration,self.permit,self.metadata=lease,registration,permit,metadata
        lease.metadata=metadata
        _PROOFS[self]=(lease,registration,permit,metadata,canonical_digest(metadata),_retired_write_proof_scope_v3(lease))
    def release_v3(self):
        if _PROOFS.pop(self,None)is not None:
            self.lease.release_v3()
            self.lease=self.registration=self.permit=self.metadata=None


def _finish_v3(namespace,owner,request,attempt,permit):
    if attempt=='owner-stop-projection:'+owner:schema='w01.owner-domain-write.v3'
    elif attempt=='owner-domain-'+canonical_digest((namespace,owner,request))[:48]:schema='w01.owner-domain-write.v3'
    elif attempt=='owner-task-domain-'+request[:48]:schema='w01.owner-task-domain-write.v1'
    elif attempt in('foreground-domain-'+request[:48],'foreground-domain-v2-'+request[:48]):schema='w01.foreground-domain-write.v1'
    else:raise AuthorityUnavailable('retired WRITE has no supported actual Owner protocol terminal')
    return 'finish:'+attempt,'sha256:'+canonical_digest(dict(schema=schema,operation_id=owner,request_digest=request,permit_token=permit.token))


def _read_terminal_v3(lease,db,registration):
    from ..authority_service.v2_contract import FencePermitV2,from_wire
    from ..runtime_storage_v3 import read_selected_runtime_cell_origin_v3
    from .domain_production_originals_v1 import _receipt
    ns=lease.maintenance.namespace_id
    with lease.sql_v3(db)as meter:
        meter.require_available(4096)
        rows=db.execute('SELECT operation_id FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND attempt_id=? LIMIT 2',
            (*ns.as_tuple,registration.original_operation_id)).fetchall()
        meter.charge_read(sum(len(row[0].encode('utf8'))+64 for row in rows))
    if len(rows)!=1:raise AuthorityUnavailable('retired WRITE has no unique actual saved Owner attempt')
    owner=rows[0][0];key=(*ns.as_tuple,owner)
    attempt=lease.fixed_v3(db,'graph_owner_domain_attempts_v3',('request_digest','attempt_id','graph_revision','graph_epoch'),
        'bot=? AND persona=? AND operation_id=?',key)
    permit=from_wire(lease.json_v3(db,'graph_owner_domain_attempts_v3','permit_json',('bot','persona','operation_id'),key))
    if(type(permit)is not FencePermitV2 or permit.operation!='write' or permit.operation_id!=attempt[1]
            or permit.operation_id!=registration.original_operation_id or permit.namespace!=registration.authority_namespace
            or permit.subject!=registration.subject or permit.token!=registration.permit_token
            or canonical_digest(permit)!=registration.permit_digest):
        raise AuthorityUnavailable('retired WRITE actual saved permit differs from its registered receiver')
    anchor=lease.json_v3(db,'graph_owner_domain_attempts_v3','anchor_json',('bot','persona','operation_id'),key)
    if anchor!=asdict(permit.pinned_anchor):raise AuthorityUnavailable('retired WRITE saved anchor differs from its original permit')
    finish_id,finish_digest=_finish_v3(ns,owner,attempt[0],attempt[1],permit)
    raw=lease.json_v3(db,'graph_owner_domain_attempts_v3','receipt_json',('bot','persona','operation_id'),key)
    if(raw['schema']!='sylanne.domain-production-receipt.v1' or raw['operation_id']!=owner):
        raise AuthorityUnavailable('retired WRITE has no supported actual committed domain original')
    receipt=_receipt(raw['receipt']);receipt_digest=canonical_digest(receipt)
    if(receipt.status not in('committed','duplicate')or receipt.operation_id!=owner
            or receipt.activity_id!=raw['activity_id'] or receipt_digest!=raw['receipt_digest']):
        raise AuthorityUnavailable('retired WRITE complete receipt differs from its actual attempt')
    original=lease.fixed_v3(db,'graph_domain_production_originals_v1',
        ('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest'),
        'bot=? AND persona=? AND operation_id=?',key)
    if(original is None or original[0:2]!=(raw['domain'],raw['operation_kind'])
            or original[3:]!=(raw['original_digest'],receipt.operation_digest,receipt_digest)
            or raw['original_ref']!=raw['domain']+'-current:'+original[3][:48]):
        raise AuthorityUnavailable('retired WRITE committed original header/reference differs')
    original_receipt=lease.json_v3(db,'graph_domain_production_originals_v1','receipt_json',('bot','persona','operation_id'),key)
    if _receipt(original_receipt)!=receipt:raise AuthorityUnavailable('retired WRITE adopted original receipt differs')
    reads=lease.json_v3(db,'graph_domain_production_originals_v1','read_versions_json',('bot','persona','operation_id'),key)
    if not set(tuple(value)for value in reads)<=set((v.key.token,v.revision)for v in receipt.read_versions):
        raise AuthorityUnavailable('retired WRITE original readset exceeds its actual receipt')
    bundle=lease.fixed_v3(db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',key)
    if bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
        raise AuthorityUnavailable('retired WRITE actual Graph bundle receipt differs')
    bundle_receipt=lease.json_v3(db,'graph_bundle_operations','receipt_json',('bot','persona','operation_id'),key)
    if (bundle_receipt['commit_seq']!=receipt.commit_seq or tuple(bundle_receipt['ledger_refs'])!=receipt.ledger_refs
            or tuple(bundle_receipt['outbox_refs'])!=receipt.outbox_refs):
        raise AuthorityUnavailable('retired WRITE Graph complete receipt metadata differs')
    fence=lease.fixed_v3(db,'graph_bundle_fences_v2',('digest','pre_graph_revision','pre_graph_epoch',
        'post_graph_revision','post_graph_epoch','finish_request_id','finish_request_digest'),
        'bot=? AND persona=? AND operation_id=?',key)
    fence_permit=lease.json_v3(db,'graph_bundle_fences_v2','permit_json',('bot','persona','operation_id'),key)
    if(fence is None or fence!=(receipt.operation_digest,attempt[2],attempt[3],attempt[2]+1,attempt[3]+1,finish_id,finish_digest)
            or from_wire(fence_permit)!=permit):
        raise AuthorityUnavailable('retired WRITE lacks its exact Graph E+1/formal finish/permit original')
    event_key=(*ns.as_tuple,receipt.activity_id,owner)
    event=lease.fixed_v3(db,'graph_events',('digest','epoch_revision'),'bot=? AND persona=? AND session=? AND event_id=?',event_key)
    if event is None or event[1]!=fence[4]:raise AuthorityUnavailable('retired WRITE actual Graph event/E+1 differs')
    event_reads=lease.json_v3(db,'graph_events','reads',('bot','persona','session','event_id'),event_key)
    revisions=lease.json_v3(db,'graph_events','revisions',('bot','persona','session','event_id'),event_key)
    epochs=lease.json_v3(db,'graph_events','epoch_reads',('bot','persona','session','event_id'),event_key)
    if(event_reads!=sorted([[v.key.token,v.revision]for v in receipt.read_versions])
            or revisions!=[[v.key.token,v.revision]for v in receipt.write_versions]
            or epochs!=[[*ns.as_tuple,attempt[3]]]):
        raise AuthorityUnavailable('retired WRITE event complete reads/revisions/epoch differ from actual receipt')
    if (not receipt.invalidated_epochs or any((e.bot,e.persona,e.revision)!=(*ns.as_tuple,event[1])for e in receipt.invalidated_epochs)):
        raise AuthorityUnavailable('retired WRITE actual event E+1 receipt differs')
    for version in receipt.write_versions:
        if(version.key.owner.bot,version.key.owner.persona)!=ns.as_tuple:
            raise AuthorityUnavailable('retired WRITE receipt crosses its selected namespace')
        if type(lease)is _CurrentCoreWriteMetadataLeaseV4 and lease.layout_kind=='initial_inline':
            history=lease.fixed_v3(db,'graph_history',('event_bot','event_persona','event_session','event_id','valid'),
                'token=? AND revision=?',(version.key.token,version.revision))
            if history!=(*event_key,1):
                raise AuthorityUnavailable('initial WRITE history lacks its exact valid committed event')
            dependencies=lease.json_v3(db,'graph_history','dependencies',('token','revision'),
                (version.key.token,version.revision))
            from ..graph_types import AtomKey,GraphVersion
            actual_dependencies=tuple(GraphVersion(AtomKey.from_token(token),revision)for token,revision in dependencies)
            post_revisions={v.key.token:v.revision for v in receipt.read_versions+receipt.write_versions}
            if any((v.key.owner.bot,v.key.owner.persona)!=ns.as_tuple
                    or post_revisions.get(v.key.token)!=v.revision for v in actual_dependencies):
                raise AuthorityUnavailable('initial WRITE history dependencies differ from its actual read/write versions')
            continue
        history=lease.fixed_v3(db,'graph_history',('event_bot','event_persona','event_session','event_id','value_cell_id'),
            'token=? AND revision=?',(version.key.token,version.revision))
        if history is None or history[:4]!=event_key or history[4]is None:
            raise AuthorityUnavailable('retired WRITE immutable history lacks its actual matching event')
        header=lease.fixed_v3(db,'segmented_cells_v1',('codec_id','erasure_owner_ref','producer_operation_id','total_bytes',
            'segment_count','payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(history[4],))
        if header is None or header[1]!=version.key.token:
            raise AuthorityUnavailable('retired WRITE actual history cell header differs')
        with lease.sql_v3(db)as meter:
            if (type(lease)is _CurrentCoreWriteMetadataLeaseV4 and lease.layout_kind=='initial_segmented_v4'
                    or type(lease)is _RetiredWriteMetadataLeaseV3 and lease.layout_kind=='initial_segmented_retirement_v4'):
                from ..runtime_storage_v3 import read_initial_runtime_cell_origin_v4
                origin=read_initial_runtime_cell_origin_v4(db,initial=lease.basis,role='graph',
                    cell_id=history[4],header=header,meter=meter)
            else:
                origin=read_selected_runtime_cell_origin_v3(db,selected_basis=lease.basis,role='graph',cell_id=history[4],header=header,meter=meter)
        if origin is not None and origin['operation_id']!=owner:
            raise AuthorityUnavailable('retired WRITE history has another actual original producer')
    if type(lease)is _CurrentCoreWriteMetadataLeaseV4 and lease.layout_kind=='initial_inline':
        if lease.stamp[0]<fence[3]or lease.stamp[1]<event[1]:
            raise AuthorityUnavailable('initial WRITE terminal lies beyond its actual current Graph revision/epoch')
    return permit,RetiredOwnerWriteTerminalMetadataV3(owner,attempt[1],attempt[0],raw['original_ref'],raw['original_digest'],
        receipt,receipt_digest,finish_id,finish_digest,event[0],event[1])



def _coverage_v3(maintenance,coverage,quiescence):
    from ..authority_service.c09_writer_peer_originals_v3 import (VerifiedPeerRetirementCoverageV3,
        VerifiedPreparedPeerRetirementCoverageV3,require_writer_quiescence_original_v3,
        read_writer_peer_retirement_coverage_for_prepared_v3)
    with maintenance.control._resource_sql_quantum_v3()as meter:
        if type(coverage)is VerifiedPeerRetirementCoverageV3:
            if coverage.progress.control is not maintenance.control or coverage.progress.gate is not maintenance.gate:
                raise AuthorityUnavailable('retired WRITE coverage belongs to another installed Gate')
        elif type(coverage)is VerifiedPreparedPeerRetirementCoverageV3:
            if coverage.control is not maintenance.control:
                raise AuthorityUnavailable('retired WRITE cold coverage belongs to another Control')
            actual=read_writer_peer_retirement_coverage_for_prepared_v3(maintenance.control,maintenance.gate,
                operation_id=coverage.operation_id,context=coverage.context)
            if actual.original!=coverage.original:
                raise AuthorityUnavailable('retired WRITE lost its actual old-to-current PREPARED mapping')
        else:raise AuthorityUnavailable('retired WRITE requires an actual complete retirement census')
        coverage.require_current(meter=meter)
        if require_writer_quiescence_original_v3(maintenance.control,quiescence,meter=meter,
                operation_id=coverage.operation_id)!=coverage.original:
            raise AuthorityUnavailable('retired WRITE quiescence differs from the complete signed retirement EOF')


def prepare_actual_d13_retired_write_terminal_v3(maintenance,registration,*,retirement_coverage,quiescence_original):
    """Prepare complete protocol metadata outside Core; never open historical paths."""
    import sqlite3
    from ..authority_service.c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
    from ..authority_service.d13_cache_use_contract_v2 import D13OwnerRegistrationReceiptV3
    from ..authority_service.c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
    if(type(maintenance)is not InstalledC09MaintenanceV1 or type(registration)is not D13OwnerRegistrationReceiptV3
            or maintenance.core._db.in_transaction or registration.namespace!=maintenance.namespace_id
            or registration.authority_namespace!=maintenance.closure.namespace
            or registration.installation_id!=maintenance.control.installation_id
            or registration.owner_kind not in('graph_source_receiver','host_frame_receiver')):
        raise AuthorityUnavailable('actual installed retired WRITE preparation outside Core SQL required')
    gate=maintenance.gate
    gate_identity=(gate._operation,gate._epoch,gate._closing_continuation)
    _require_gate_v3(maintenance,retirement_coverage,quiescence_original,gate_identity)
    _coverage_v3(maintenance,retirement_coverage,quiescence_original)
    with maintenance.control._resource_sql_quantum_v3()as meter:
        selected=maintenance.control._selected_history_read_v3
        if selected is None:
            from ..authority_service.c09_initial_segmented_genesis_v4 import read_initial_segmented_context_v4
            context=read_initial_segmented_context_v4(maintenance.control,meter=meter)
            if (context.stage,context.pointer_version,context.storage_generation)!=('INTENT',0,0):
                raise AuthorityUnavailable('initial retired WRITE metadata requires its actual first capture INTENT')
            basis=None;layout_kind='initial_segmented_retirement_v4'
            member=next(item for item in context.manifest['members']if item['role']=='graph')
        else:
            context=maintenance.control.read_verified_current_storage_v3(meter=meter)
            if(type(selected)is not VerifiedSelectedHistoryReadV3 or selected.basis.control is not maintenance.control
                    or selected.basis.manifest['manifest_digest']!=context.manifest_digest
                    or selected.basis.manifest['generation']!=context.storage_generation):
                raise AuthorityUnavailable('retired WRITE requires the actual current selected Graph metadata mapping')
            basis=selected.basis;member=basis.member('graph');layout_kind='selected_segmented'
        context.require_current('maintenance')
        maintenance.control.verify_member_v1(member,prepared=False)
    lease=None
    try:
        with closing(sqlite3.connect(Path(member['resolved_path']).as_uri()+'?mode=ro',uri=True,isolation_level=None))as db:
            db.execute('PRAGMA query_only=ON')
            if layout_kind=='initial_segmented_retirement_v4':
                from ..authority_service.c09_initial_segmented_genesis_v4 import require_initial_segmented_retirement_metadata_v4
                with maintenance.control._resource_sql_quantum_v3()as meter:
                    db.execute('BEGIN')
                    try:
                        basis=require_initial_segmented_retirement_metadata_v4(maintenance,
                            retirement_coverage=retirement_coverage,quiescence_original=quiescence_original,db=db,meter=meter)
                    finally:db.rollback()
            lease=_RetiredWriteMetadataLeaseV3(maintenance,retirement_coverage,quiescence_original,context,basis,layout_kind)
            if layout_kind=='selected_segmented':
                with lease.sql_v3(db)as meter:basis.require_layout(db,'graph',meter=meter)
            permit,metadata=_read_terminal_v3(lease,db,registration)
            for table,columns,where,args,expected in tuple(lease.headers):
                with lease.sql_v3(db)as meter:
                    if meter.read_fixed_row(db,table,columns,where,args)!=expected:
                        raise AuthorityUnavailable('retired WRITE actual fixed protocol metadata changed before publication')
            if layout_kind=='initial_segmented_retirement_v4':
                with lease.sql_v3(db)as meter:basis.seal_graph_eof_v4(db,meter=meter)
        lease.require_v3()
        _coverage_v3(maintenance,retirement_coverage,quiescence_original)
        proof=_RetiredOwnerWriteTerminalProofV3(_KEY,lease,registration,permit,metadata)
        with maintenance.control._resource_sql_quantum_v3()as meter:
            maintenance.control.require_c09_retained_arena_v3(meter=meter)
        return proof
    except BaseException:
        if lease is not None:lease.release_v3()
        elif layout_kind=='initial_segmented_retirement_v4' and basis is not None:basis.release_v4()
        raise


def require_actual_d13_retired_write_terminal_v3(proof,*,maintenance,registration):
    """Consume only the private EOF proof; no Graph or Core business SQL is opened."""
    if type(proof)is not _RetiredOwnerWriteTerminalProofV3:
        raise AuthorityUnavailable('actual retired WRITE private metadata proof required')
    saved=_PROOFS.get(proof)
    if(saved is None or saved!=(proof.lease,registration,proof.permit,proof.metadata,
            canonical_digest(proof.metadata),_retired_write_proof_scope_v3(proof.lease))
            or proof.registration is not registration or proof.lease.maintenance is not maintenance):
        raise AuthorityUnavailable('retired WRITE proof crossed its actual original/metadata retention')
    proof.lease.require_v3()
    if type(proof.lease)is _RetiredWriteMetadataLeaseV3:
        _coverage_v3(maintenance,proof.lease.coverage,proof.lease.quiescence)
    elif type(proof.lease)is not _CurrentCoreWriteMetadataLeaseV4:
        raise AuthorityUnavailable('retired WRITE proof has no actual installed lifetime boundary')
    with maintenance.control._resource_sql_quantum_v3()as meter:
        maintenance.control.require_c09_retained_arena_v3(meter=meter)
    return proof.permit,'owner_write_committed',proof.metadata,proof.lease.context


class _CurrentCoreWriteMetadataLeaseV4(_RetiredWriteMetadataLeaseV3):
    def __init__(self,key,maintenance,qualification,retirement_cap,birth,context,basis,layout_kind):
        if key is not _KEY:raise TypeError('actual current-bootstrap WRITE metadata issuer required')
        self.maintenance,self.qualification,self.retirement_cap=maintenance,qualification,retirement_cap
        self.birth,self.context,self.basis=birth,context,basis
        self.member=next(member for member in context.manifest['members']if member['role']=='graph')
        self.store=maintenance.graph
        self.layout_kind=layout_kind
        self.stamp=None
        self.hold=qualification.hold
        self.headers,self.values,self.commitments=[],{},[]
        self.buffer=bytearray();self.metadata=None;self.closed=False
        maintenance.control.register_c09_retained_state_v3(self)
    def _c09_retained_heap_bytes_v3(self):
        return _heap((self.headers,self.values,self.commitments,self.buffer,self.metadata,self.birth))+65536
    def require_v3(self):
        if self.closed:raise AuthorityUnavailable('current Core WRITE metadata lease was released')
        from .d13_consumer_manifest_v3 import require_actual_d13_current_core_receiver_cleanup_v4
        db=self.maintenance.core._db
        with self.maintenance.control._resource_sql_quantum_v3()as meter:
            require_actual_d13_current_core_receiver_cleanup_v4(self.qualification,
                self.qualification.daemon,self.hold,meter,db=db if db.in_transaction else None)
        self.retirement_cap.require_current(control=self.maintenance.control,gate=self.maintenance.gate,
            birth=self.birth,qualification=self.qualification)
        self.context.require_current('maintenance')

    def require_storage_v3(self,db,meter):
        if self.layout_kind=='selected_segmented':
            return super().require_storage_v3(db,meter)
        if self.layout_kind=='initial_segmented_v4':
            from ..runtime_storage_v3 import runtime_storage_basis_identity_v4,runtime_storage_v3
            identity=runtime_storage_basis_identity_v4(self.basis,role='graph',meter=meter)
            handle=runtime_storage_v3(self.store._db)
            if (identity.origin_kind!='initial_segmented_v4' or identity.namespace!=self.maintenance.namespace_id
                    or identity.control is not self.maintenance.control or identity.member!=self.member
                    or handle is None or handle.initial is not self.basis
                    or self.context is not self.qualification.context
                    or self.basis.manifest['manifest_digest']!=self.context.manifest_digest):
                raise AuthorityUnavailable('current Core WRITE lost its actual initial-segmented Graph origin')
            rows=db.execute('PRAGMA database_list').fetchall()
            if len(rows)!=1 or Path(rows[0][2]).resolve(strict=True)!=Path(self.member['resolved_path']).resolve(strict=True):
                raise AuthorityUnavailable('initial-segmented WRITE metadata crossed its actual Graph source file')
            return
        if self.layout_kind!='initial_inline' or self.basis is not None:
            raise AuthorityUnavailable('current Core WRITE metadata changed its actual layout kind')
        from ..graph_store import ProductionGraphStore
        from ..runtime_storage_v3 import runtime_storage_v3
        context=self.context;store=self.store
        if (context is not self.qualification.context or context._reader is not self.maintenance.control
                or (context.stage,context.pointer_version,context.storage_generation)!=('READY',0,0)
                or context.manifest['schema']=='sylanne3.c09.storage_manifest.v3'
                or context.manifest['prior_manifest_digest']is not None or context.prepared_original is not None
                or self.maintenance.control._selected_history_read_v3 is not None
                or not isinstance(store,ProductionGraphStore)or store is not self.maintenance.graph
                or store._runtime_storage_v3 is not None):
            raise AuthorityUnavailable('actual initial READY Graph metadata lifetime required')
        self.maintenance.control.verify_member_v1(self.member,prepared=False)
        with store._lock:
            store._ensure_open()
            if store._db.in_transaction or runtime_storage_v3(store._db)is not None:
                raise AuthorityUnavailable('initial Graph metadata crossed its actual ordinary storage handle')
            rows=store._db.execute('PRAGMA database_list').fetchall()
        databases=db.execute('PRAGMA database_list').fetchall()
        for actual in (rows,databases):
            if (len(actual)!=1 or actual[0][1]!='main'
                    or Path(actual[0][2]).resolve(strict=True)!=Path(self.member['resolved_path']).resolve(strict=True)):
                raise AuthorityUnavailable('initial Graph metadata differs from its actual installed member')
        meter.require_available(8192)
        segmented=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='segmented_storage_layout_v1'").fetchone()
        columns=tuple(tuple(db.execute('PRAGMA table_info('+table+')'))for table in ('graph_atoms','graph_history'))
        meter.charge_read(_heap((segmented,columns)))
        expected=(('token','bot','persona','owner_kind','subject','type_name','name','revision','value','valid'),
            ('token','revision','value','valid','dependencies','event_bot','event_persona','event_session','event_id'))
        if segmented is not None or tuple(tuple(row[1]for row in table)for table in columns)!=expected:
            raise AuthorityUnavailable('initial Graph metadata requires its actual original inline schema')
    def prepare_initial_catalogue_v4(self,db):
        ns=self.maintenance.namespace_id
        revision=self.fixed_v3(db,'graph_recovery_metadata_v2',('graph_revision',),'bot=? AND persona=?',ns.as_tuple)
        epoch=self.fixed_v3(db,'graph_epochs',('revision',),'bot=? AND persona=?',ns.as_tuple)
        if revision is None or epoch is None:
            raise AuthorityUnavailable('initial WRITE metadata has no actual Graph revision/epoch')
        self.stamp=(revision[0],epoch[0])
        for table,columns,expected in (
                ('graph_type_catalog',('name','owner_kinds','storage_role','immutable','schema_version'),
                    tuple(self.store._catalog_row(spec)for spec in self.store._registry.specs)),
                ('graph_type_authority',('name','writer_domain','schema_hash'),
                    tuple((spec.name,spec.writer_domain or'',spec.schema_hash or'')for spec in self.store._registry.specs))):
            after=''
            for item in expected:
                row=self.fixed_v3(db,table,columns,'name>? ORDER BY name',(after,))
                if row!=item:
                    raise AuthorityUnavailable('initial WRITE metadata catalogue differs from its actual installed producer registry')
                after=item[0]
            if self.fixed_v3(db,table,columns,'name>? ORDER BY name',(after,))is not None:
                raise AuthorityUnavailable('initial WRITE metadata catalogue has an unclassified producer')



def _retired_write_proof_scope_v3(lease):
    if type(lease)is _CurrentCoreWriteMetadataLeaseV4:
        return ('current_core_v4',lease.qualification,lease.retirement_cap,lease.birth.birth_digest,lease.hold,
            lease.context,lease.basis,lease.store,canonical_digest(lease.member),lease.layout_kind,lease.stamp)
    if type(lease)is _RetiredWriteMetadataLeaseV3:
        return ('peer_v3',canonical_digest(lease.quiescence),lease.context,lease.basis,lease.layout_kind)
    raise AuthorityUnavailable('retired WRITE proof has no actual closed lifetime boundary')


def prepare_actual_d13_current_core_write_terminal_v4(maintenance,registration,*,qualification,retirement_cap):
    """Actual Owner WRITE protocol EOF under the independent current Root hold."""
    import sqlite3
    from ..authority_service.c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
    from ..authority_service.d13_cache_use_control_v2 import InstalledD13CacheUseControlServiceV2
    from ..authority_service.d13_cache_use_contract_v2 import (D13OwnerRegistrationReceiptV3,
        D13AuthoritySourceReceiverOwnerLocatorV4,D13AuthorityCoreBirthReceiptV4)
    from ..authority_service.d13_core_authority_retirement_v4 import VerifiedInstalledCoreAuthorityRetirementV4
    from ..authority_service.c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
    from ..runtime_storage_v3 import runtime_storage_operation_v3,runtime_storage_quantum_v3
    from .d13_consumer_manifest_v3 import require_actual_d13_current_core_receiver_cleanup_v4
    if(type(maintenance)is not InstalledC09MaintenanceV1 or type(registration)is not D13OwnerRegistrationReceiptV3
            or type(registration.original_locator)is not D13AuthoritySourceReceiverOwnerLocatorV4
            or type(retirement_cap)is not VerifiedInstalledCoreAuthorityRetirementV4
            or maintenance.core._db.in_transaction or registration.owner_kind!='authority_source_receiver'
            or registration.namespace!=maintenance.namespace_id
            or registration.authority_namespace!=maintenance.closure.namespace
            or registration.installation_id!=maintenance.control.installation_id):
        raise AuthorityUnavailable('actual current Core WRITE metadata preparation outside Core SQL required')
    service=maintenance.core._d13_cache_use_controls_v2.get(maintenance.closure.namespace)
    if type(service)is not InstalledD13CacheUseControlServiceV2 or service.core is not maintenance.core:
        raise AuthorityUnavailable('current Core WRITE metadata lost its actual installed selected Core service')
    with maintenance.control._resource_sql_quantum_v3()as meter:
        require_actual_d13_current_core_receiver_cleanup_v4(qualification,qualification.daemon,qualification.hold,meter)
    with runtime_storage_operation_v3(maintenance.core._db,operation_id='d13-current-core-write-original'):
        with maintenance.core._tx()as db,runtime_storage_quantum_v3(db):
            locator=registration.original_locator
            actual=service._owner_operation_v3(db,registration.owner_ref,'owner_register')
            birth=service._owner_operation_v3(db,locator.core_incarnation_id,'owner_core_birth')
            if(actual!=registration or type(birth)is not D13AuthorityCoreBirthReceiptV4
                    or birth.operation_id!=locator.core_birth_original_ref
                    or birth.birth_digest!=locator.core_birth_original_digest):
                raise AuthorityUnavailable('current Core WRITE metadata differs from its actual immutable receiver/birth')
            maintenance.control.verify_original_v1(asdict(birth),'birth_digest')
            retirement_cap.require_current(control=maintenance.control,gate=maintenance.gate,birth=birth,qualification=qualification)
    with maintenance.control._resource_sql_quantum_v3()as meter:
        context=qualification.context
        context.require_current('maintenance')
        selected=maintenance.control._selected_history_read_v3
        if selected is None:
            from ..runtime_storage_v3 import runtime_storage_v3,runtime_source_identity_v4
            handle=runtime_storage_v3(maintenance.graph._db)
            if handle is not None:
                identity=runtime_source_identity_v4(handle,meter=meter)
                if (identity.origin_kind!='initial_segmented_v4' or identity.role!='graph'
                        or identity.namespace!=maintenance.namespace_id
                        or identity.control is not maintenance.control
                        or handle.initial.manifest['manifest_digest']!=context.manifest_digest):
                    raise AuthorityUnavailable('current Core WRITE has no actual initial-segmented Graph proof')
                basis=handle.initial;member=identity.member;layout_kind='initial_segmented_v4'
            else:
                if ((context.stage,context.pointer_version,context.storage_generation)!=('READY',0,0)
                        or context.manifest['schema']=='sylanne3.c09.storage_manifest.v3'
                        or context.manifest['prior_manifest_digest']is not None or context.prepared_original is not None):
                    raise AuthorityUnavailable('current Core WRITE has no actual initial or selected Graph provenance')
                basis=None;layout_kind='initial_inline'
                member=next(member for member in context.manifest['members']if member['role']=='graph')
        else:
            if(type(selected)is not VerifiedSelectedHistoryReadV3 or selected.basis.control is not maintenance.control
                    or selected.basis.manifest['manifest_digest']!=context.manifest_digest
                    or selected.basis.manifest['generation']!=context.storage_generation):
                raise AuthorityUnavailable('current Core WRITE requires the actual selected Graph metadata mapping')
            basis=selected.basis;member=basis.member('graph');layout_kind='selected_segmented'
        maintenance.control.verify_member_v1(member,prepared=False)
    lease=_CurrentCoreWriteMetadataLeaseV4(_KEY,maintenance,qualification,retirement_cap,birth,context,basis,layout_kind)
    try:
        with closing(sqlite3.connect(Path(member['resolved_path']).as_uri()+'?mode=ro',uri=True,isolation_level=None))as db:
            db.execute('PRAGMA query_only=ON')
            with lease.sql_v3(db)as meter:
                if basis is not None:basis.require_layout(db,'graph',meter=meter)
            if lease.layout_kind=='initial_inline':lease.prepare_initial_catalogue_v4(db)
            permit,metadata=_read_terminal_v3(lease,db,registration)
            for table,columns,where,args,expected in tuple(lease.headers):
                with lease.sql_v3(db)as meter:
                    if meter.read_fixed_row(db,table,columns,where,args)!=expected:
                        raise AuthorityUnavailable('current Core WRITE actual fixed protocol metadata changed before publication')
        lease.require_v3()
        proof=_RetiredOwnerWriteTerminalProofV3(_KEY,lease,registration,permit,metadata)
        with maintenance.control._resource_sql_quantum_v3()as meter:
            maintenance.control.require_c09_retained_arena_v3(meter=meter)
        return proof
    except BaseException:
        lease.release_v3()
        raise
